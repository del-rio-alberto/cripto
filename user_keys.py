"""
Módulo para gestión de claves de usuario EC P-256.

Proporciona funciones para:
- Generar pares de claves EC P-256
- Cifrar claves privadas con contraseña usando PBKDF2 + AES-GCM
- Descifrar claves privadas
"""

import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Constantes para PBKDF2
PBKDF2_ITERATIONS = 100000
PBKDF2_SALT_LENGTH = 16
PBKDF2_KEY_LENGTH = 32  # 256 bits para AES-256

# Constantes para AES-GCM
AES_GCM_NONCE_LENGTH = 12
AES_GCM_TAG_LENGTH = 16


def generate_user_keypair():
    """
    Genera un par de claves EC P-256 para un usuario.
    
    Returns:
        tuple: (private_key, public_key) como objetos cryptography
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    return private_key, public_key


def _serialize_private_key(private_key):
    """
    Serializa una clave privada a formato PEM.
    
    Args:
        private_key: Objeto de clave privada EC
        
    Returns:
        bytes: Clave privada en formato PEM
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def _deserialize_private_key(pem_bytes):
    """
    Deserializa una clave privada desde formato PEM.
    
    Args:
        pem_bytes: Bytes en formato PEM
        
    Returns:
        Objeto de clave privada EC
    """
    return serialization.load_pem_private_key(
        pem_bytes,
        password=None
    )


def _serialize_public_key(public_key):
    """
    Serializa una clave pública a formato PEM.
    
    Args:
        public_key: Objeto de clave pública EC
        
    Returns:
        bytes: Clave pública en formato PEM
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _derive_key_from_password(password, salt):
    """
    Deriva una clave de cifrado desde una contraseña usando PBKDF2.
    
    Args:
        password: Contraseña del usuario (str)
        salt: Salt aleatorio (bytes)
        
    Returns:
        bytes: Clave derivada de 32 bytes
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    
    # Convertir contraseña a bytes si es string
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    return kdf.derive(password)


def encrypt_private_key(private_key, password):
    """
    Cifra una clave privada con la contraseña del usuario.
    
    Utiliza PBKDF2-HMAC-SHA256 para derivar la clave de cifrado
    y AES-GCM para cifrar la clave privada.
    
    Args:
        private_key: Objeto de clave privada EC
        password: Contraseña del usuario (str o bytes)
        
    Returns:
        str: Blob cifrado en formato JSON base64 que contiene:
             {
                 "salt": base64,
                 "nonce": base64,
                 "ciphertext": base64
             }
    """
    # Serializar la clave privada a PEM
    private_key_pem = _serialize_private_key(private_key)
    
    # Generar salt aleatorio
    salt = os.urandom(PBKDF2_SALT_LENGTH)
    
    # Derivar clave de cifrado desde la contraseña
    encryption_key = _derive_key_from_password(password, salt)
    
    # Generar nonce aleatorio para AES-GCM
    nonce = os.urandom(AES_GCM_NONCE_LENGTH)
    
    # Cifrar con AES-GCM
    aesgcm = AESGCM(encryption_key)
    ciphertext = aesgcm.encrypt(nonce, private_key_pem, None)
    
    # El ciphertext de AES-GCM ya incluye el tag al final
    # Crear estructura de datos
    encrypted_data = {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }
    
    # Retornar como JSON string
    return json.dumps(encrypted_data)


def decrypt_private_key(encrypted_blob, password):
    """
    Descifra una clave privada cifrada con la contraseña del usuario.
    
    Args:
        encrypted_blob: Blob cifrado en formato JSON (str)
        password: Contraseña del usuario (str o bytes)
        
    Returns:
        Objeto de clave privada EC
        
    Raises:
        ValueError: Si la contraseña es incorrecta o el blob está corrupto
    """
    try:
        # Parsear el JSON
        encrypted_data = json.loads(encrypted_blob)
        
        # Decodificar componentes desde base64
        salt = base64.b64decode(encrypted_data["salt"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        
        # Derivar la clave de cifrado usando el mismo salt
        encryption_key = _derive_key_from_password(password, salt)
        
        # Descifrar con AES-GCM
        aesgcm = AESGCM(encryption_key)
        private_key_pem = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Deserializar la clave privada
        private_key = _deserialize_private_key(private_key_pem)
        
        return private_key
        
    except Exception as e:
        raise ValueError(f"Error al descifrar la clave privada: {str(e)}")


def get_public_key_pem(private_key):
    """
    Obtiene la clave pública en formato PEM desde una clave privada.
    
    Args:
        private_key: Objeto de clave privada EC
        
    Returns:
        str: Clave pública en formato PEM (base64)
    """
    public_key = private_key.public_key()
    public_key_pem = _serialize_public_key(public_key)
    return public_key_pem.decode('utf-8')


def generate_csr(private_key, common_name):
    """
    Genera un CSR (Certificate Signing Request) para un usuario.
    
    Args:
        private_key: Objeto de clave privada EC
        common_name: Nombre común (CN) para el certificado (username)
        
    Returns:
        bytes: CSR en formato PEM
    """
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).sign(private_key, hashes.SHA256())
    
    return csr.public_bytes(serialization.Encoding.PEM)
