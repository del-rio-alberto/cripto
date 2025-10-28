import bcrypt
import jwt
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets
import logging
import os
import hmac
import hashlib

logger = logging.getLogger(__name__)

# Configuración JWT
JWT_SECRET = os.getenv('JWT_SECRET', 'test-cnslf9374nd9cm3sdh5-d83nfkslemv00-d09amcha196c')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24


def hash_password(password: str) -> str:
    """
    Hashea una contraseña usando bcrypt con 12 rounds.
    
    Args:
        password: Contraseña en texto plano
        
    Returns:
        Hash bcrypt en formato string
    """
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    logger.info("Contraseña hasheada con bcrypt (12 rounds)")
    return password_hash.decode()


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verifica una contraseña contra su hash bcrypt.
    
    Args:
        password: Contraseña en texto plano
        password_hash: Hash bcrypt almacenado
        
    Returns:
        True si la contraseña es correcta, False en caso contrario
    """
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def generate_jwt(username: str) -> str:
    """
    Genera un token JWT firmado con HS256.
    
    Args:
        username: Nombre del usuario
        
    Returns:
        Token JWT como string
    """
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    logger.info(f"JWT generado con {JWT_ALGORITHM} para usuario '{username}'")
    return token


def verify_jwt(token: str) -> dict:
    """
    Verifica y decodifica un token JWT.
    
    Args:
        token: Token JWT
        
    Returns:
        Payload decodificado del token
        
    Raises:
        ValueError: Si el token es inválido o ha expirado
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expirado")
    except jwt.InvalidTokenError:
        raise ValueError("Token inválido")


def generate_salt() -> bytes:
    """
    Genera un salt aleatorio de 128 bits.
    
    Returns:
        Salt de 16 bytes
    """
    return secrets.token_bytes(16)

# Derivación de clave con PBKDF2-HMAC-SHA256
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Deriva una clave de 256 bits a partir de una contraseña usando PBKDF2.
    
    Parámetros:
        - Algoritmo: PBKDF2-HMAC-SHA256
        - Iteraciones: 480000 (recomendación OWASP 2023)
        - Longitud de clave: 256 bits (32 bytes)
    
    Args:
        password: Contraseña del usuario
        salt: Salt de 16 bytes
        
    Returns:
        Clave derivada de 32 bytes
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=480000,  # Recomendación OWASP 2023
    )
    key = kdf.derive(password.encode())
    logger.info("Clave derivada con PBKDF2-HMAC-SHA256 (480k iteraciones, 256 bits)")
    return key


# Cifrado simétrico con AES-GCM
def encrypt_aes_gcm(plaintext: str, key: bytes) -> dict:
    """
    Cifra un mensaje usando AES-256-GCM.
    
    AES-GCM proporciona:
        - Confidencialidad (cifrado)
        - Autenticidad (verificación de integridad)
        - Protección contra manipulación
    
    Args:
        plaintext: Texto a cifrar
        key: Clave de 256 bits (32 bytes)
        
    Returns:
        Diccionario con:
            - ciphertext: Texto cifrado en base64
            - nonce: Nonce de 96 bits en base64
            - tag: Tag de autenticación de 128 bits en base64
    """
    if len(key) != 32:
        raise ValueError("La clave debe tener 256 bits (32 bytes)")
    
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96 bits para GCM (recomendado)
    
    # Cifrar (GCM incluye el tag en los últimos 16 bytes)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    
    # Separar ciphertext y tag
    tag = ciphertext[-16:]
    ciphertext_only = ciphertext[:-16]
    
    logger.info("Mensaje cifrado con AES-256-GCM (clave 256 bits, nonce 96 bits)")
    
    return {
        'ciphertext': base64.b64encode(ciphertext_only).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'tag': base64.b64encode(tag).decode()
    }

# Descifrado simétrico con AES-GCM
def decrypt_aes_gcm(ciphertext_b64: str, nonce_b64: str, tag_b64: str, key: bytes) -> str:
    """
    Descifra un mensaje usando AES-256-GCM.
    
    Verifica automáticamente la autenticidad del mensaje con el tag.
    Si el tag no coincide, el mensaje ha sido manipulado.
    
    Args:
        ciphertext_b64: Texto cifrado en base64
        nonce_b64: Nonce en base64
        tag_b64: Tag de autenticación en base64
        key: Clave de 256 bits (32 bytes)
        
    Returns:
        Texto descifrado
        
    Raises:
        ValueError: Si el descifrado falla o el tag no es válido
    """
    if len(key) != 32:
        raise ValueError("La clave debe tener 256 bits (32 bytes)")
    
    aesgcm = AESGCM(key)
    
    # Decodificar de base64
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    
    # Reconstruir ciphertext completo con tag
    full_ciphertext = ciphertext + tag
    
    try:
        plaintext = aesgcm.decrypt(nonce, full_ciphertext, None)
        logger.info("Mensaje descifrado con AES-256-GCM (verificación de tag exitosa)")
        return plaintext.decode()
    except Exception as e:
        logger.error(f"Error en descifrado o verificación de tag: {str(e)}")
        raise ValueError("Descifrado falló: mensaje corrupto o clave incorrecta")


def generate_hmac(message: str, key: bytes) -> str:
    """
    Genera un HMAC-SHA256 de un mensaje.
    
    Args:
        message: Texto a autenticar
        key: Clave secreta para HMAC (debe ser bytes)
    
    Returns:
        HMAC en formato hexadecimal
    
    Ejemplo:
        >>> key = secrets.token_bytes(32)
        >>> hmac_value = generate_hmac("Hola mundo", key)
        >>> print(f"HMAC: {hmac_value}")
    """
    # Convertir mensaje a bytes si es string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Generar HMAC usando SHA-256
    h = hmac.new(key, message, hashlib.sha256)
    
    # Devolver en formato hexadecimal
    return h.hexdigest()


def verify_hmac(message: str, hmac_to_verify: str, key: bytes) -> bool:
    """
    Verifica un HMAC de forma segura contra timing attacks.
    
    Args:
        message: Texto original
        hmac_to_verify: HMAC a verificar (hex string)
        key: Clave secreta para HMAC
    
    Returns:
        True si el HMAC es válido, False en caso contrario
    
    Nota:
        Usa hmac.compare_digest() para prevenir timing attacks
    """
    # Convertir mensaje a bytes si es string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Generar HMAC esperado
    expected_hmac = generate_hmac(message, key)
    
    # Comparación segura contra timing attacks
    return hmac.compare_digest(expected_hmac, hmac_to_verify)


def generate_hmac_key() -> bytes:
    """
    Genera una clave aleatoria de 256 bits para HMAC.
    
    Returns:
        Clave de 32 bytes (256 bits)
    
    Nota:
        Usa secrets.token_bytes() para generación criptográficamente segura
    """
    return secrets.token_bytes(32)  # 256 bits