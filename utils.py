import bcrypt
import jwt
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import logging
import os

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
        - Iteraciones: 480000
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
        iterations=480000,
    )
    key = kdf.derive(password.encode())
    logger.info("Clave derivada con PBKDF2-HMAC-SHA256 (480k iteraciones, 256 bits)")
    return key