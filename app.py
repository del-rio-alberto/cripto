from flask import Flask, jsonify, request
import logging
import base64
import os
from datetime import datetime
from flasgger import Swagger
from dotenv import load_dotenv
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pki_helper import (
    verify_signature,
    verify_certificate_chain
)

from pki import (
    issue_certificate,
    revoke_certificate,
    load_certificate
)

from data_access import (
    init_database,
    reset_database,
    create_user,
    user_exists,
    get_user_password_hash,
    store_message,
    get_user_messages,
    get_message_by_id,
    mark_message_as_read,
    get_user_encrypted_private_key,
    get_user_private_key_salt,
    get_user_certificate,
    update_user_certificate
)

from utils import (
    hash_password,
    verify_password,
    generate_jwt,
    verify_jwt,
    generate_salt,
    derive_key_from_password
)

from user_keys import (
    generate_user_keypair,
    encrypt_private_key,
    decrypt_private_key,
    get_public_key_pem
)

from secure_messaging import (
    send_secure_message,
    receive_secure_message
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

    # 3. Generar par de claves EC P-256
    private_key, public_key = generate_user_keypair()
    
    # 4. Cifrar clave privada con la contraseña del usuario
    encrypted_private_key = encrypt_private_key(private_key, password)
    
    # 5. Obtener clave pública en formato PEM
    public_key_pem = get_public_key_pem(private_key)

    # 6. Guardar en base de datos (certificado vacío inicialmente)
    # El salt de la clave privada se genera dentro de encrypt_private_key
    # Necesitamos extraerlo del JSON
    import json
    encrypted_data = json.loads(encrypted_private_key)
    private_key_salt = base64.b64decode(encrypted_data['salt'])
    
    create_user(username, password_hash, salt, encrypted_private_key, private_key_salt, public_key_pem, "")

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
    Envía un mensaje cifrado y firmado a otro usuario usando certificados X.509.
    
    Headers:
        Authorization: Bearer <token_jwt>
    
    Body JSON:
        {
            "to": "username_destinatario",
            "message": "texto del mensaje",
            "password": "contraseña_del_remitente"  # Necesaria para descifrar clave privada
        }
    
    Proceso:
        1. Verifica el token JWT del remitente
        2. Verifica que el destinatario existe y tiene certificado
        3. Descifra la clave privada del remitente con su contraseña
        4. Obtiene certificados del remitente y destinatario
        5. Llama a send_secure_message() que:
           - Genera par de claves efímero
           - Deriva clave compartida con ECDH
           - Cifra con AES-256-GCM
           - Firma con clave privada del remitente
        6. Almacena el payload completo en la BD
    
    Respuesta exitosa (201):
        {
            "success": true,
            "message_id": 123,
            "from": "username_remitente",
            "to": "username_destinatario",
            "timestamp": "2025-12-01T10:30:00",
            "encryption_info": {
                "algorithm": "ECDH + AES-256-GCM",
                "signature_algorithm": "ECDSA-SHA256",
                "certificate_verified": true
            }
        }
    
    Errores:
        - 400: Datos faltantes o inválidos
        - 401: Token inválido o contraseña incorrecta
        - 404: Usuario destinatario no encontrado o sin certificado
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
        password = data.get('password')
        
        # Validar datos de entrada
        if not username_to or not message_text:
            return jsonify({'error': 'Destinatario y mensaje requeridos'}), 400
            
        if not password:
            return jsonify({'error': 'Contraseña requerida para descifrar clave privada'}), 400
        
        if not user_exists(username_to):
            return jsonify({'error': 'Usuario destinatario no encontrado'}), 404
        
        # Obtener certificado del remitente
        sender_cert_pem = get_user_certificate(username_from)
        if not sender_cert_pem:
            return jsonify({
                'error': 'El remitente no tiene certificado emitido. Use POST /cert/issue primero.'
            }), 400
        
        # Obtener certificado del destinatario
        receiver_cert_pem = get_user_certificate(username_to)
        if not receiver_cert_pem:
            return jsonify({
                'error': f'El destinatario {username_to} no tiene certificado emitido.'
            }), 404
        
        # Descifrar clave privada del remitente
        encrypted_private_key_blob = get_user_encrypted_private_key(username_from)
        if not encrypted_private_key_blob:
            return jsonify({'error': 'No se encontró clave privada del remitente'}), 500
        
        try:
            sender_private_key = decrypt_private_key(encrypted_private_key_blob, password)
        except ValueError as e:
            logger.warning(f"Contraseña incorrecta para usuario '{username_from}'")
            return jsonify({'error': 'Contraseña incorrecta'}), 401
        
        # Preparar sender y receiver para send_secure_message
        sender = {
            'private_key': sender_private_key,
            'cert': sender_cert_pem
        }
        
        receiver = {
            'cert': receiver_cert_pem
        }
        
        # Enviar mensaje seguro
        secure_payload = send_secure_message(sender, receiver, message_text)
        
        # Guardar en base de datos
        timestamp = datetime.now().isoformat()
        message_id = store_message(
            username_from=username_from,
            username_to=username_to,
            ciphertext=secure_payload['ciphertext'],
            nonce=secure_payload['nonce'],
            signature=secure_payload['signature'],
            cert_emisor=secure_payload['cert_emisor'],
            ephemeral_pubkey=secure_payload['pubkey_efimera'],  # Mapear pubkey_efimera -> ephemeral_pubkey
            timestamp=timestamp
        )
        
        logger.info(
            f"Mensaje seguro enviado: {username_from} -> {username_to} "
            f"(ID: {message_id}, ECDH + AES-256-GCM + ECDSA)"
        )
        
        return jsonify({
            'success': True,
            'message_id': message_id,
            'from': username_from,
            'to': username_to,
            'timestamp': timestamp,
            'encryption_info': {
                'algorithm': 'ECDH + AES-256-GCM',
                'signature_algorithm': 'ECDSA-SHA256',
                'certificate_verified': True
            }
        }), 201
        
    except ValueError as e:
        logger.error(f"Error de validación: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error al enviar mensaje: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/messages/secure', methods=['POST'])
def send_secure_message_endpoint():
    """
    Envía un mensaje PRE-CIFRADO (Client-Side) a otro usuario.
    
    Headers:
        Authorization: Bearer <token_jwt>
    
    Body JSON:
        {
            "to": "username_destinatario",
            "ciphertext": "base64...",
            "nonce": "base64...",
            "signature": "base64...",
            "cert_emisor": "pem_string...",
            "ephemeral_pubkey": "pem_string..."
        }
    """
    try:
        # Verificar token JWT
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token no proporcionado'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_jwt(token)
        username_from = payload['username']
        
        # Obtener datos
        data = request.get_json()
        username_to = data.get('to')
        ciphertext = data.get('ciphertext')
        nonce = data.get('nonce')
        signature = data.get('signature')
        cert_emisor = data.get('cert_emisor')
        ephemeral_pubkey = data.get('ephemeral_pubkey')
        
        if not all([username_to, ciphertext, nonce, signature, cert_emisor, ephemeral_pubkey]):
            return jsonify({'error': 'Faltan campos obligatorios para mensaje seguro'}), 400
            
        if not user_exists(username_to):
            return jsonify({'error': 'Usuario destinatario no encontrado'}), 404
            
        # Guardar en base de datos
        timestamp = datetime.now().isoformat()
        message_id = store_message(
            username_from=username_from,
            username_to=username_to,
            ciphertext=ciphertext,
            nonce=nonce,
            signature=signature,
            cert_emisor=cert_emisor,
            ephemeral_pubkey=ephemeral_pubkey,
            timestamp=timestamp
        )
        
        logger.info(f"Mensaje seguro (Client-Side) enviado: {username_from} -> {username_to} (ID: {message_id})")
        
        return jsonify({
            'success': True,
            'message_id': message_id,
            'timestamp': timestamp
        }), 201
        
    except Exception as e:
        logger.error(f"Error al enviar mensaje seguro: {str(e)}")
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
    Lee y descifra un mensaje específico usando certificados X.509.
    
    Headers:
        Authorization: Bearer <token_jwt>
    
    Query params:
        password: Contraseña del usuario para descifrar su clave privada
    
    Proceso:
        1. Verifica el token JWT
        2. Verifica que el mensaje pertenece al usuario
        3. Obtiene el mensaje cifrado de la BD
        4. Reconstruye el payload con todos los campos
        5. Descifra la clave privada del receptor
        6. Llama a receive_secure_message() que:
           - Verifica certificado del emisor (cadena + CRL)
           - Verifica firma digital
           - Deriva clave compartida con ECDH
           - Descifra con AES-256-GCM
        7. Marca como leído
    
    Respuesta exitosa (200):
        {
            "success": true,
            "message_id": 123,
            "from": "username_remitente",
            "to": "username_destinatario",
            "message": "texto descifrado",
            "timestamp": "2025-12-01T10:30:00",
            "verification": {
                "certificate_valid": true,
                "signature_valid": true,
                "chain_verified": true
            }
        }
    
    Errores:
        - 401: Token inválido o ausente
        - 403: Mensaje no pertenece al usuario
        - 404: Mensaje no encontrado
        - 400: Verificación de certificado o firma falló
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
        
        # Obtener contraseña del query param
        password = request.args.get('password')
        if not password:
            return jsonify({'error': 'Contraseña requerida para descifrar clave privada'}), 400
        
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
        
        # Descifrar clave privada del receptor
        encrypted_private_key_blob = get_user_encrypted_private_key(username)
        if not encrypted_private_key_blob:
            return jsonify({'error': 'No se encontró clave privada del receptor'}), 500
        
        try:
            receiver_private_key = decrypt_private_key(encrypted_private_key_blob, password)
        except ValueError as e:
            logger.warning(f"Contraseña incorrecta para usuario '{username}'")
            return jsonify({'error': 'Contraseña incorrecta'}), 401
        
        # Reconstruir payload para receive_secure_message
        payload_dict = {
            'ciphertext': message_data['ciphertext'],
            'nonce': message_data['nonce'],
            'signature': message_data['signature'],
            'cert_emisor': message_data['cert_emisor'],
            'pubkey_efimera': message_data['ephemeral_pubkey']  # Mapear ephemeral_pubkey -> pubkey_efimera
        }
        
        # Preparar receiver
        receiver = {
            'private_key': receiver_private_key
        }
        
        # Recibir y descifrar mensaje seguro
        try:
            plaintext = receive_secure_message(receiver, payload_dict)
            certificate_valid = True
            signature_valid = True
            chain_verified = True
        except ValueError as e:
            error_msg = str(e)
            logger.error(f"Error al verificar/descifrar mensaje {message_id}: {error_msg}")
            
            # Determinar tipo de error
            if 'certificado' in error_msg.lower() or 'cadena' in error_msg.lower():
                return jsonify({
                    'error': 'Verificación de certificado falló',
                    'details': error_msg
                }), 400
            elif 'firma' in error_msg.lower():
                return jsonify({
                    'error': 'Verificación de firma falló',
                    'details': error_msg
                }), 400
            else:
                return jsonify({
                    'error': 'Error al descifrar mensaje',
                    'details': error_msg
                }), 400
        
        # Marcar como leído
        mark_message_as_read(message_id)
        
        logger.info(
            f"Mensaje {message_id} leído por '{username}' "
            f"(Certificado válido, Firma válida, Cadena verificada)"
        )
        
        return jsonify({
            'success': True,
            'message_id': message_id,
            'from': message_data['username_from'],
            'to': message_data['username_to'],
            'message': plaintext,
            'timestamp': message_data['timestamp'],
            'verification': {
                'certificate_valid': certificate_valid,
                'signature_valid': signature_valid,
                'chain_verified': chain_verified
            }
        }), 200
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        logger.error(f"Error al leer mensaje: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/messages/<int:message_id>/raw', methods=['GET'])
def get_message_raw(message_id):
    """
    Obtiene el mensaje cifrado RAW para descifrado en cliente.
    """
    try:
        # Verificar token JWT
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token no proporcionado'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_jwt(token)
        username = payload['username']
        
        # Obtener mensaje
        message_data = get_message_by_id(message_id)
        if not message_data:
            return jsonify({'error': 'Mensaje no encontrado'}), 404
            
        # Verificar propiedad (to o from)
        if message_data['username_to'] != username and message_data['username_from'] != username:
            return jsonify({'error': 'No autorizado'}), 403
            
        # Marcar como leído si es el destinatario
        if message_data['username_to'] == username:
            mark_message_as_read(message_id)
            
        return jsonify({
            'success': True,
            'message': message_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error al obtener mensaje raw: {str(e)}")
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


@app.route('/cert/issue', methods=['POST'])
def cert_issue():
    """
    Emite un certificado de usuario basado en un CSR.
    
    Body JSON:
        {
            "username": "nombre_usuario",
            "csr_pem": "base64_del_csr_pem"
        }
    
    Proceso:
        1. Valida los datos de entrada
        2. Decodifica el CSR de base64
        3. Llama a issue_certificate() del módulo pki
        4. Devuelve el certificado emitido en base64
    
    Respuesta exitosa (200):
        {
            "success": true,
            "certificate_pem": "base64_del_certificado",
            "username": "nombre_usuario",
            "message": "Certificado emitido exitosamente"
        }
    
    Errores:
        - 400: Datos faltantes o CSR inválido
        - 500: Error interno del servidor
    """
    try:
        data = request.get_json()
        username = data.get('username')
        csr_pem_b64 = data.get('csr_pem')
        
        # Validar datos de entrada
        if not username or not csr_pem_b64:
            return jsonify({'error': 'username y csr_pem son requeridos'}), 400
        
        # Decodificar CSR de base64
        try:
            csr_pem = base64.b64decode(csr_pem_b64)
        except Exception as e:
            return jsonify({'error': f'CSR base64 inválido: {str(e)}'}), 400
        
        # Emitir certificado
        cert_pem = issue_certificate(username, csr_pem)
        
        # Codificar certificado a base64
        cert_pem_b64 = base64.b64encode(cert_pem).decode('utf-8')
        
        logger.info(f"Certificado emitido para usuario '{username}'")
        
        return jsonify({
            'success': True,
            'certificate_pem': cert_pem_b64,
            'username': username,
            'message': 'Certificado emitido exitosamente'
        }), 200
        
    except ValueError as e:
        logger.error(f"Error de validación al emitir certificado: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error al emitir certificado: {str(e)}")
        return jsonify({'error': f'Error al emitir certificado: {str(e)}'}), 500


@app.route('/cert/revoke', methods=['POST'])
def cert_revoke():
    """
    Revoca un certificado añadiéndolo a la CRL.
    
    Body JSON (opción 1 - por serial):
        {
            "serial": 123456789
        }
    
    Body JSON (opción 2 - por username):
        {
            "username": "nombre_usuario"
        }
    
    Proceso:
        1. Valida que se proporcione serial o username
        2. Si es username, busca el certificado y extrae el serial
        3. Llama a revoke_certificate() del módulo pki
        4. Devuelve confirmación de revocación
    
    Respuesta exitosa (200):
        {
            "success": true,
            "serial": 123456789,
            "message": "Certificado revocado exitosamente"
        }
    
    Errores:
        - 400: Datos faltantes o inválidos
        - 404: Certificado no encontrado (cuando se usa username)
        - 500: Error interno del servidor
    """
    try:
        data = request.get_json()
        serial = data.get('serial')
        username = data.get('username')
        
        # Validar que se proporcione al menos uno
        if not serial and not username:
            return jsonify({'error': 'Se requiere serial o username'}), 400
        
        # Si se proporciona username, buscar el certificado
        if username and not serial:
            cert_path = f"certs/{username}.crt"
            if not os.path.exists(cert_path):
                return jsonify({'error': f'Certificado no encontrado para usuario {username}'}), 404
            
            try:
                cert = load_certificate(cert_path)
                serial = cert.serial_number
                logger.info(f"Certificado encontrado para '{username}' con serial {serial}")
            except Exception as e:
                return jsonify({'error': f'Error al cargar certificado: {str(e)}'}), 500
        
        # Revocar certificado
        revoke_certificate(serial)
        
        logger.info(f"Certificado con serial {serial} revocado exitosamente")
        
        return jsonify({
            'success': True,
            'serial': serial,
            'message': 'Certificado revocado exitosamente'
        }), 200
        
    except Exception as e:
        logger.error(f"Error al revocar certificado: {str(e)}")
        return jsonify({'error': f'Error al revocar certificado: {str(e)}'}), 500


@app.route('/cert/<username>', methods=['GET'])
def get_user_cert(username):
    """
    Obtiene el certificado público de un usuario.
    
    Respuesta exitosa (200):
        {
            "success": true,
            "username": "nombre_usuario",
            "certificate_pem": "base64_del_certificado"
        }
    
    Errores:
        - 404: Certificado no encontrado
        - 500: Error interno
    """
    try:
        cert_pem = get_user_certificate(username)
        if not cert_pem:
            return jsonify({'error': f'Certificado no encontrado para {username}'}), 404
            
        # Si get_user_certificate devuelve bytes, decodificar
        if isinstance(cert_pem, bytes):
            cert_pem = cert_pem.decode('utf-8')
            
        # Codificar a base64 para transporte seguro en JSON
        cert_pem_b64 = base64.b64encode(cert_pem.encode('utf-8')).decode('utf-8')
        
        return jsonify({
            'success': True,
            'username': username,
            'certificate_pem': cert_pem_b64
        }), 200
        
    except Exception as e:
        logger.error(f"Error al obtener certificado de {username}: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/cert/crl', methods=['GET'])
def cert_get_crl():
    """
    Devuelve la CRL (Certificate Revocation List) actual.
    
    Proceso:
        1. Lee el archivo intermediate_ca.crl del disco
        2. Codifica el contenido en base64
        3. Devuelve la CRL
    
    Respuesta exitosa (200):
        {
            "success": true,
            "crl_pem": "base64_de_la_crl",
            "message": "CRL obtenida exitosamente"
        }
    
    Errores:
        - 404: CRL no encontrada
        - 500: Error interno del servidor
    """
    try:
        crl_path = "intermediate_ca.crl"
        
        # Verificar que existe el archivo CRL
        if not os.path.exists(crl_path):
            return jsonify({'error': 'CRL no encontrada'}), 404
        
        # Leer CRL del disco
        with open(crl_path, "rb") as f:
            crl_pem = f.read()
        
        # Codificar a base64
        crl_pem_b64 = base64.b64encode(crl_pem).decode('utf-8')
        
        logger.info("CRL obtenida exitosamente")
        
        return jsonify({
            'success': True,
            'crl_pem': crl_pem_b64,
            'message': 'CRL obtenida exitosamente'
        }), 200
        
    except Exception as e:
        logger.error(f"Error al obtener CRL: {str(e)}")
        return jsonify({'error': f'Error al obtener CRL: {str(e)}'}), 500


if __name__ == '__main__':
  # Inicializar base de datos
  init_database()
  
  # Iniciar servidor Flask
  app.run(host="0.0.0.0", port=5000)
