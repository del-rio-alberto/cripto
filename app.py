from flask import Flask, jsonify, request
import logging
import base64
from datetime import datetime
from flasgger import Swagger
from dotenv import load_dotenv
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from utils import (
    hash_password,
    verify_password,
    generate_jwt,
    verify_jwt,
    generate_salt,
    derive_key_from_password,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    generate_hmac, 
    verify_hmac
)
from data_access import (
    init_database,
    create_user,
    get_user_password_hash,
    get_user_encryption_key,
    user_exists,
    get_user_hmac_key,
    get_message_by_id,
    get_user_messages,
    mark_message_as_read,
    store_message,
    reset_database,
    store_user_keypair,
    get_user_encrypted_private_key
)
from pki_helper import verify_signature, verify_certificate_chain
from user_keys import (
    generate_user_keypair,
    encrypt_private_key,
    decrypt_private_key,
    get_public_key_pem
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env.local
load_dotenv('.env.local')

app = Flask(__name__)
swagger = Swagger(app)



@app.route('/register', methods=['POST'])
def register():
  """
  Registra un nuevo usuario en el sistema.

  Body JSON:
      {
          "username": "nombre_usuario",
          "password": "contraseña_segura"
      }

  Proceso:
      1. Valida los datos de entrada
      2. Hashea la contraseña con bcrypt (12 rounds)
      3. Genera un salt aleatorio para la derivación de clave
      4. Deriva una clave de cifrado AES-256 usando PBKDF2
      5. Almacena todo en la base de datos

  Respuesta exitosa (201):
      {
          "success": true,
          "message": "Usuario registrado correctamente",
          "username": "nombre_usuario"
      }

  Errores:
      - 400: Datos faltantes o inválidos
      - 409: Usuario ya existe
      - 500: Error interno del servidor
  """
  try:
    # Obtener datos del request
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Validar datos de entrada
    if not username or not password:
      return jsonify({'error': 'Usuario y contraseña requeridos'}), 400

    if len(password) < 8:
      return jsonify({
          'error': 'Contraseña debe tener al menos 8 caracteres'
      }), 400

    # Verificar si el usuario ya existe
    if user_exists(username):
      return jsonify({'error': 'Usuario ya existe'}), 409

    # 1. Hashear contraseña con bcrypt
    password_hash = hash_password(password)

    # 2. Generar salt para derivación de clave
    salt = generate_salt()

    # 3. Derivar clave de cifrado del usuario
    encryption_key = derive_key_from_password(password, salt)

    # 4. Guardar en base de datos
    create_user(username, password_hash, salt, encryption_key)

    # 5. Generar par de claves EC P-256
    private_key, public_key = generate_user_keypair()
    
    # 6. Cifrar clave privada con la contraseña del usuario
    encrypted_private_key = encrypt_private_key(private_key, password)
    
    # 7. Obtener clave pública en formato PEM
    public_key_pem = get_public_key_pem(private_key)
    
    # 8. Guardar claves en la base de datos
    store_user_keypair(username, encrypted_private_key, public_key_pem)

    logger.info(f"Usuario '{username}' registrado exitosamente con keypair EC P-256")

    return jsonify({
        'success': True,
        'message': 'Usuario registrado correctamente',
        'username': username
    }), 201

  except Exception as e:
    logger.error(f"Error en registro: {str(e)}")
    return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/login', methods=['POST'])
def login():
  """
  Autentica a un usuario y genera un token JWT.

  Body JSON:
      {
          "username": "nombre_usuario",
          "password": "contraseña"
      }

  Proceso:
      1. Verifica las credenciales con bcrypt
      2. Genera un token JWT firmado con HS256
      3. El token es válido por 24 horas

  Respuesta exitosa (200):
      {
          "success": true,
          "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
          "username": "nombre_usuario",
          "expires_in": 86400
      }

  Errores:
      - 400: Datos faltantes
      - 401: Credenciales inválidas
      - 500: Error interno del servidor
  """
  try:
    # Obtener datos del request
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Validar datos de entrada
    if not username or not password:
      return jsonify({'error': 'Usuario y contraseña requeridos'}), 400

    # Obtener hash de contraseña de la BD
    stored_hash = get_user_password_hash(username)

    if not stored_hash:
      logger.warning(f"Intento de login con usuario inexistente: '{username}'")
      return jsonify({'error': 'Credenciales inválidas'}), 401

    # Verificar contraseña con bcrypt
    if not verify_password(password, stored_hash):
      logger.warning(f"Intento de login fallido para usuario '{username}'")
      return jsonify({'error': 'Credenciales inválidas'}), 401

    # Generar token JWT
    token = generate_jwt(username)
    
    # Obtener y descifrar clave privada del usuario
    encrypted_private_key_blob = get_user_encrypted_private_key(username)
    
    if encrypted_private_key_blob:
        try:
            # Descifrar la clave privada con la contraseña
            private_key = decrypt_private_key(encrypted_private_key_blob, password)
            logger.info(f"Clave privada descifrada exitosamente para '{username}'")
        except ValueError as e:
            logger.error(f"Error al descifrar clave privada para '{username}': {str(e)}")
            # Continuar con el login aunque falle el descifrado de la clave

    logger.info(f"Login exitoso para usuario '{username}'")

    return jsonify({
        'success': True,
        'token': token,
        'username': username,
        'expires_in': 86400  # 24 horas en segundos
    }), 200

  except Exception as e:
    logger.error(f"Error en login: {str(e)}")
    return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/encrypt', methods=['POST'])
def encrypt():
    """
    Cifra un mensaje usando AES-256-GCM con la clave del usuario autenticado.
    
    Headers:
        Authorization: Bearer <token_jwt>
    
    Body JSON:
        {
            "plaintext": "texto a cifrar"
        }
    
    Proceso:
        1. Verifica el token JWT
        2. Obtiene la clave de cifrado del usuario
        3. Cifra el mensaje con AES-256-GCM
        4. Genera nonce aleatorio y tag de autenticación
    
    Respuesta exitosa (200):
        {
            "success": true,
            "ciphertext": "base64_del_texto_cifrado",
            "nonce": "base64_del_nonce",
            "tag": "base64_del_tag",
            "algorithm": "AES-256-GCM",
            "key_size": 256
        }
    
    Errores:
        - 400: Datos faltantes
        - 401: Token inválido o ausente
        - 500: Error interno del servidor
    """
    try:
        # Verificar token JWT
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token no proporcionado'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_jwt(token)
        username = payload['username']
        
        # Obtener datos del request
        data = request.get_json()
        plaintext = data.get('plaintext')
        
        if not plaintext:
            return jsonify({'error': 'Texto plano requerido'}), 400
        
        # Obtener clave de cifrado del usuario
        encryption_key = get_user_encryption_key(username)
        
        if not encryption_key:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Cifrar con AES-256-GCM
        encrypted_data = encrypt_aes_gcm(plaintext, encryption_key)
        
        return jsonify({
            'success': True,
            'ciphertext': encrypted_data['ciphertext'],
            'nonce': encrypted_data['nonce'],
            'tag': encrypted_data['tag'],
            'algorithm': 'AES-256-GCM',
            'key_size': 256
        }), 200
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        logger.error(f"Error en cifrado: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

      
@app.route('/decrypt', methods=['POST'])
def decrypt():
  """
  Descifra un mensaje usando AES-256-GCM con la clave del usuario autenticado.

  Headers:
      Authorization: Bearer <token_jwt>

  Body JSON:
      {
          "ciphertext": "base64_del_texto_cifrado",
          "nonce": "base64_del_nonce",
          "tag": "base64_del_tag"
      }

  Proceso:
      1. Verifica el token JWT
      2. Obtiene la clave de cifrado del usuario
      3. Verifica el tag de autenticación (integridad)
      4. Descifra el mensaje

  Respuesta exitosa (200):
      {
          "success": true,
          "plaintext": "texto descifrado"
      }

  Errores:
      - 400: Datos faltantes
      - 401: Token inválido o ausente
      - 400: Tag inválido (mensaje corrupto o manipulado)
      - 500: Error interno del servidor
  """
  try:
    # Verificar token JWT
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
      return jsonify({'error': 'Token no proporcionado'}), 401

    token = auth_header.split(' ')[1]
    payload = verify_jwt(token)
    username = payload['username']

    # Obtener datos del request
    data = request.get_json()
    ciphertext = data.get('ciphertext')
    nonce = data.get('nonce')
    tag = data.get('tag')

    if not all([ciphertext, nonce, tag]):
      return jsonify({
          'error': 'ciphertext, nonce y tag son requeridos'
      }), 400

    # Obtener clave de cifrado del usuario
    encryption_key = get_user_encryption_key(username)

    if not encryption_key:
      return jsonify({'error': 'Usuario no encontrado'}), 404

    # Descifrar con AES-256-GCM (verifica tag automáticamente)
    plaintext = decrypt_aes_gcm(ciphertext, nonce, tag, encryption_key)

    return jsonify({
        'success': True,
        'plaintext': plaintext
    }), 200

  except ValueError as e:
    # Puede ser token inválido o tag inválido (mensaje corrupto)
    return jsonify({'error': str(e)}), 400
  except Exception as e:
    logger.error(f"Error en descifrado: {str(e)}")
    return jsonify({'error': 'Error interno del servidor'}), 500



@app.route('/messages', methods=['POST'])
def send_message():
    """
    Envía un mensaje cifrado a otro usuario.
    
    Headers:
        Authorization: Bearer <token_jwt>
    
    Body JSON:
        {
            "to": "username_destinatario",
            "message": "texto del mensaje"
        }
    
    Proceso:
        1. Verifica el token JWT del remitente
        2. Verifica que el destinatario existe
        3. Cifra el mensaje con AES-256-GCM usando la clave del REMITENTE
        4. Almacena el mensaje cifrado en la BD
        5. Genera un HMAC del mensaje para integridad adicional
    
    Respuesta exitosa (201):
        {
            "success": true,
            "message_id": 123,
            "from": "username_remitente",
            "to": "username_destinatario",
            "timestamp": "2025-10-28T10:30:00",
            "encryption_info": {
                "algorithm": "AES-256-GCM",
                "key_size": 256,
                "authenticated": true
            }
        }
    
    Errores:
        - 400: Datos faltantes o inválidos
        - 401: Token inválido o ausente
        - 404: Usuario destinatario no encontrado
        - 500: Error interno del servidor
    """
    try:
        # Verificar token JWT
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token no proporcionado'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_jwt(token)
        username_from = payload['username']
        
        # Obtener datos del request
        data = request.get_json()
        username_to = data.get('to')
        message_text = data.get('message')
        
        # Validar datos de entrada
        if not username_to or not message_text:
            return jsonify({'error': 'Destinatario y mensaje requeridos'}), 400
        
        if not user_exists(username_to):
            return jsonify({'error': 'Usuario destinatario no encontrado'}), 404
        
        # Obtener clave de cifrado del remitente
        encryption_key = get_user_encryption_key(username_from)
        
        # Cifrar mensaje con AES-256-GCM (incluye autenticación)
        encrypted_data = encrypt_aes_gcm(message_text, encryption_key)
        
        # Generar HMAC adicional para demostrar conocimiento
        # (aunque GCM ya autentica, esto es para mostrar HMAC explícitamente)
        hmac_key = get_user_hmac_key(username_from)
        message_hmac = generate_hmac(message_text, hmac_key)
        
        # Guardar mensaje en BD
        timestamp = datetime.now().isoformat()
        message_id = store_message(
            username_from=username_from,
            username_to=username_to,
            ciphertext=encrypted_data['ciphertext'],
            nonce=encrypted_data['nonce'],
            tag=encrypted_data['tag'],
            hmac=message_hmac,
            timestamp=timestamp
        )
        
        timestamp = datetime.now().isoformat()
        
        logger.info(
            f"Mensaje enviado: {username_from} -> {username_to} "
            f"(ID: {message_id}, Algoritmo: AES-256-GCM, "
            f"Tag autenticación: {encrypted_data['tag'][:16]}...)"
        )
        
        return jsonify({
            'success': True,
            'message_id': message_id,
            'from': username_from,
            'to': username_to,
            'timestamp': timestamp,
            'encryption_info': {
                'algorithm': 'AES-256-GCM',
                'key_size': 256,
                'authenticated': True,
                'hmac_algorithm': 'HMAC-SHA256'
            }
        }), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        logger.error(f"Error al enviar mensaje: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/messages', methods=['GET'])
def get_messages():
    """
    Obtiene los mensajes recibidos por el usuario autenticado.
    
    Headers:
        Authorization: Bearer <token_jwt>
    
    Query params (opcional):
        - unread_only: "true" para solo mensajes no leídos
    
    Proceso:
        1. Verifica el token JWT
        2. Obtiene mensajes cifrados de la BD
        3. NO los descifra automáticamente (privacidad)
        4. Devuelve lista con metadata
    
    Respuesta exitosa (200):
        {
            "success": true,
            "messages": [
                {
                    "message_id": 123,
                    "from": "username_remitente",
                    "timestamp": "2025-10-28T10:30:00",
                    "read": false
                },
                ...
            ]
        }
    
    Errores:
        - 401: Token inválido o ausente
        - 500: Error interno del servidor
    """
    try:
        # Verificar token JWT
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token no proporcionado'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_jwt(token)
        username = payload['username']
        
        # Obtener parámetros opcionales
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        
        # Obtener mensajes de la BD (sin descifrar)
        messages = get_user_messages(username, unread_only)
        
        logger.info(f"Usuario '{username}' consultó sus mensajes ({len(messages)} encontrados)")
        
        return jsonify({
            'success': True,
            'messages': messages
        }), 200
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        logger.error(f"Error al obtener mensajes: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/messages/<int:message_id>', methods=['GET'])
def read_message(message_id):
    """
    Lee y descifra un mensaje específico.
    
    Headers:
        Authorization: Bearer <token_jwt>
    
    Proceso:
        1. Verifica el token JWT
        2. Verifica que el mensaje pertenece al usuario
        3. Obtiene el mensaje cifrado de la BD
        4. Para descifrarlo, necesita la clave del REMITENTE
           (simplificación: usamos clave del destinatario)
        5. Verifica HMAC y tag GCM
        6. Descifra el mensaje
        7. Marca como leído
    
    Respuesta exitosa (200):
        {
            "success": true,
            "message_id": 123,
            "from": "username_remitente",
            "to": "username_destinatario",
            "message": "texto descifrado",
            "timestamp": "2025-10-28T10:30:00",
            "verification": {
                "gcm_tag_valid": true,
                "hmac_valid": true
            }
        }
    
    Errores:
        - 401: Token inválido o ausente
        - 403: Mensaje no pertenece al usuario
        - 404: Mensaje no encontrado
        - 400: Verificación de integridad falló
        - 500: Error interno del servidor
    """
    try:
        # Verificar token JWT
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token no proporcionado'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_jwt(token)
        username = payload['username']
        
        # Obtener mensaje de la BD
        message_data = get_message_by_id(message_id)
        
        if not message_data:
            return jsonify({'error': 'Mensaje no encontrado'}), 404
        
        # Verificar que el mensaje es para este usuario
        logger.info(f"Usuario '{username}' intentando leer mensaje ID {message_id}")
        logger.info(f"Mensaje pertenece a: '{message_data['username_to']}'")
        if message_data['username_to'] != username:
            logger.warning(
                f"Usuario '{username}' intentó leer mensaje de '{message_data['username_to']}'"
            )
            return jsonify({'error': 'No autorizado para leer este mensaje'}), 403
        logger.info(f"Acceso autorizado para '{username}' leer mensaje ID {message_id}")
        
        # Obtener clave del remitente para descifrar
        encryption_key = get_user_encryption_key(message_data['username_from'])

        if not encryption_key:
            return jsonify({'error': 'Usuario remitente no encontrado'}), 404
        
        # Descifrar con AES-256-GCM (verifica tag automáticamente)
        try:
            plaintext = decrypt_aes_gcm(
                message_data['ciphertext'],
                message_data['nonce'],
                message_data['tag'],
                encryption_key
            )
            gcm_valid = True
        except ValueError:
            logger.error(f"Tag GCM inválido para mensaje {message_id}")
            return jsonify({'error': 'Mensaje corrupto o manipulado (GCM tag inválido)'}), 400
        
        # Verificar HMAC adicional
        hmac_key = get_user_hmac_key(message_data['username_from'])
        hmac_valid = verify_hmac(plaintext, message_data['hmac'], hmac_key)
        
        if not hmac_valid:
            logger.warning(f"HMAC inválido para mensaje {message_id}")
            return jsonify({'error': 'Mensaje corrupto o manipulado (HMAC inválido)'}), 400
        
        # Marcar como leído
        mark_message_as_read(message_id)
        
        logger.info(
            f"Mensaje {message_id} leído por '{username}' "
            f"(GCM válido: {gcm_valid}, HMAC válido: {hmac_valid})"
        )
        
        return jsonify({
            'success': True,
            'message_id': message_id,
            'from': message_data['username_from'],
            'to': message_data['username_to'],
            'message': plaintext,
            'timestamp': message_data['timestamp'],
            'verification': {
                'gcm_tag_valid': gcm_valid,
                'hmac_valid': hmac_valid
            }
        }), 200
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        logger.error(f"Error al leer mensaje: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/hmac/generate', methods=['POST'])
def hmac_generate():
    """
    Genera un HMAC de un mensaje (demostración educativa).
    
    Headers:
        Authorization: Bearer <token_jwt>
    
    Body JSON:
        {
            "message": "texto a autenticar"
        }
    
    Proceso:
        1. Verifica el token JWT
        2. Obtiene la clave HMAC del usuario
        3. Genera HMAC-SHA256
    
    Respuesta exitosa (200):
        {
            "success": true,
            "message": "texto original",
            "hmac": "hex_string_del_hmac",
            "algorithm": "HMAC-SHA256",
            "key_size": 256
        }
    """
    try:
        # Verificar token JWT
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token no proporcionado'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_jwt(token)
        username = payload['username']
        
        # Obtener datos del request
        data = request.get_json()
        message = data.get('message')
        
        if not message:
            return jsonify({'error': 'Mensaje requerido'}), 400
        
        # Obtener clave HMAC del usuario
        hmac_key = get_user_hmac_key(username)
        
        # Generar HMAC
        hmac_value = generate_hmac(message, hmac_key)
        
        logger.info(f"HMAC generado para usuario '{username}' (HMAC-SHA256, 256 bits)")
        
        return jsonify({
            'success': True,
            'message': message,
            'hmac': hmac_value,
            'algorithm': 'HMAC-SHA256',
            'key_size': 256
        }), 200
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        logger.error(f"Error al generar HMAC: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/hmac/verify', methods=['POST'])
def hmac_verify():
    """
    Verifica un HMAC (demostración educativa).

    Headers:
        Authorization: Bearer <token_jwt>

    Body JSON:
        {
            "message": "texto original",
            "hmac": "hex_string_del_hmac_a_verificar"
        }

    Respuesta exitosa (200):
        {
            "success": true,
            "valid": true/false,
            "message": "HMAC válido" o "HMAC inválido"
        }
    """
    try:
        # Verificar token JWT
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token no proporcionado'}), 401

        token = auth_header.split(' ')[1]
        payload = verify_jwt(token)
        username = payload['username']

        # Obtener datos del request
        data = request.get_json()
        message = data.get('message')
        hmac_to_verify = data.get('hmac')

        if not message or not hmac_to_verify:
            return jsonify({'error': 'Mensaje y HMAC requeridos'}), 400

        # Obtener clave HMAC del usuario
        hmac_key = get_user_hmac_key(username)

        # Verificar HMAC
        is_valid = verify_hmac(message, hmac_to_verify, hmac_key)

        logger.info(f"HMAC verificado para usuario '{username}': {'válido' if is_valid else 'inválido'}")

        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': 'HMAC válido' if is_valid else 'HMAC inválido'
        }), 200

    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        logger.error(f"Error al verificar HMAC: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/reset_db', methods=['POST'])
def reset_db():
    """
    Resetea la base de datos eliminando todos los datos.
    Útil para limpiar el estado entre ejecuciones de tests.

    Respuesta exitosa (200):
        {
            "success": true,
            "message": "Base de datos reseteada correctamente"
        }

    Errores:
        - 500: Error interno del servidor
    """
    try:
        reset_database()
        logger.info("Base de datos reseteada vía endpoint")
        return jsonify({
            'success': True,
            'message': 'Base de datos reseteada correctamente'
        }), 200

    except Exception as e:
        logger.error(f"Error al resetear base de datos: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/pki/verify-signature', methods=['POST'])
def pki_verify_signature():
    """
    Verifica una firma digital usando la clave pública de un certificado.
    
    Body JSON:
        {
            "certificate_pem": "base64_del_certificado_pem",
            "signature": "base64_de_la_firma",
            "data": "datos_originales"
        }
    
    Respuesta exitosa (200):
        {
            "success": true,
            "valid": true/false,
            "message": "Firma válida" o "Firma inválida"
        }
    
    Errores:
        - 400: Datos faltantes o inválidos
        - 500: Error interno del servidor
    """
    try:
        data = request.get_json()
        cert_pem_b64 = data.get('certificate_pem')
        signature_b64 = data.get('signature')
        message_data = data.get('data')
        
        if not all([cert_pem_b64, signature_b64, message_data]):
            return jsonify({'error': 'certificate_pem, signature y data son requeridos'}), 400
        
        # Decodificar base64
        cert_pem = base64.b64decode(cert_pem_b64)
        signature = base64.b64decode(signature_b64)
        data_bytes = message_data.encode('utf-8')
        
        # Cargar certificado y extraer clave pública
        cert = x509.load_pem_x509_certificate(cert_pem)
        public_key = cert.public_key()
        
        # Verificar firma
        is_valid = verify_signature(public_key, signature, data_bytes)
        
        logger.info(f"Verificación de firma: {'válida' if is_valid else 'inválida'}")
        
        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': 'Firma válida' if is_valid else 'Firma inválida'
        }), 200
        
    except Exception as e:
        logger.error(f"Error al verificar firma: {str(e)}")
        return jsonify({'error': f'Error al verificar firma: {str(e)}'}), 500


@app.route('/pki/verify-chain', methods=['POST'])
def pki_verify_chain():
    """
    Verifica la cadena completa de certificados y CRL.
    
    Body JSON:
        {
            "user_cert_pem": "base64_del_certificado_usuario",
            "intermediate_cert_pem": "base64_del_certificado_intermedio",
            "root_cert_pem": "base64_del_certificado_raiz",
            "crl_pem": "base64_de_la_crl"
        }
    
    Respuesta exitosa (200):
        {
            "success": true,
            "valid": true/false,
            "message": "Cadena válida" o "Cadena inválida"
        }
    
    Errores:
        - 400: Datos faltantes o inválidos
        - 500: Error interno del servidor
    """
    try:
        data = request.get_json()
        user_cert_b64 = data.get('user_cert_pem')
        inter_cert_b64 = data.get('intermediate_cert_pem')
        root_cert_b64 = data.get('root_cert_pem')
        crl_b64 = data.get('crl_pem')
        
        if not all([user_cert_b64, inter_cert_b64, root_cert_b64, crl_b64]):
            return jsonify({
                'error': 'user_cert_pem, intermediate_cert_pem, root_cert_pem y crl_pem son requeridos'
            }), 400
        
        # Decodificar base64
        user_cert_pem = base64.b64decode(user_cert_b64)
        inter_cert_pem = base64.b64decode(inter_cert_b64)
        root_cert_pem = base64.b64decode(root_cert_b64)
        crl_pem = base64.b64decode(crl_b64)
        
        # Verificar cadena
        is_valid = verify_certificate_chain(
            user_cert_pem,
            inter_cert_pem,
            root_cert_pem,
            crl_pem
        )
        
        logger.info(f"Verificación de cadena: {'válida' if is_valid else 'inválida'}")
        
        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': 'Cadena válida' if is_valid else 'Cadena inválida'
        }), 200
        
    except Exception as e:
        logger.error(f"Error al verificar cadena: {str(e)}")
        return jsonify({'error': f'Error al verificar cadena: {str(e)}'}), 500


if __name__ == '__main__':
  # Inicializar base de datos
  init_database()
  
  # Iniciar servidor Flask
  app.run(host="0.0.0.0", port=5000)
