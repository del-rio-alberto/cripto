from flask import Flask, jsonify, request
import logging
from flasgger import Swagger
from utils import (
    hash_password,
    verify_password,
    generate_jwt,
    verify_jwt,
    generate_salt,
    derive_key_from_password,
    encrypt_aes_gcm,
    decrypt_aes_gcm
)
from data_access import (
    init_database,
    create_user,
    get_user_password_hash,
    get_user_encryption_key,
    user_exists
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

    logger.info(f"Usuario '{username}' registrado exitosamente")

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


@app.route("/hmac", methods=["POST"])
def hmac_generate():
  """
  Genera/verifica un HMAC.
  - Recibe: message
  - Devuelve: hmac generado
  (en versión extendida: validar el hmac que envía el cliente).
  """
  return jsonify({"success": True, "hmac": ""}), 200


@app.route("/messages", methods=["POST"])
def create_message():
  """
  Crea un mensaje
  - Recibe: message, from, to
  - Devuelve: 
  """
  return jsonify({"success": True}), 200


@app.route("/messages", methods=["GET"])
def list_messages():
  """
  Devuelve los mensajes de un usuario
  - Recibe: from
  - Devuelve: messages[]
  """
  return jsonify({"success": True, "messages": []}), 200


if __name__ == '__main__':
  # Inicializar base de datos
  init_database()
  
  # Iniciar servidor Flask
  app.run(host="0.0.0.0", port=5000)
