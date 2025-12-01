import os
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Constantes
AES_KEY_LENGTH = 32  # 256 bits para AES-256
AES_GCM_NONCE_LENGTH = 12  # Tamaño recomendado para AES-GCM
HKDF_INFO = b"hybrid-encryption-v1"  # Información de contexto para HKDF


def derive_shared_key(private_key, peer_public_key):
    """
    Deriva una clave compartida usando ECDH P-256 y HKDF-SHA256.
    
    Proceso:
    1. Realiza intercambio ECDH entre la clave privada local y la clave pública del peer
    2. Deriva una clave simétrica de 32 bytes usando HKDF-SHA256
    
    Args:
        private_key: Clave privada EC P-256 (objeto cryptography o PEM bytes/str)
        peer_public_key: Clave pública EC P-256 del peer (objeto cryptography o PEM bytes/str)
        
    Returns:
        bytes: Clave compartida de 32 bytes derivada con HKDF
        
    Raises:
        ValueError: Si las claves no son válidas o no son EC P-256
    """
    try:
        # Convertir claves a objetos si vienen en formato PEM
        if isinstance(private_key, (bytes, str)):
            if isinstance(private_key, str):
                private_key = private_key.encode('utf-8')
            private_key = serialization.load_pem_private_key(
                private_key,
                password=None
            )
        
        if isinstance(peer_public_key, (bytes, str)):
            if isinstance(peer_public_key, str):
                peer_public_key = peer_public_key.encode('utf-8')
            peer_public_key = serialization.load_pem_public_key(peer_public_key)
        
        # Verificar que las claves sean EC P-256
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("La clave privada debe ser EC")
        if not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
            raise ValueError("La clave pública del peer debe ser EC")
        
        # Verificar que sean P-256 (SECP256R1)
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("La clave privada debe ser P-256 (SECP256R1)")
        if not isinstance(peer_public_key.curve, ec.SECP256R1):
            raise ValueError("La clave pública del peer debe ser P-256 (SECP256R1)")
        
        # Realizar intercambio ECDH
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Derivar clave simétrica usando HKDF-SHA256
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_LENGTH,
            salt=None,  # HKDF puede funcionar sin salt
            info=HKDF_INFO,
        )
        
        shared_key = hkdf.derive(shared_secret)
        
        return shared_key
        
    except Exception as e:
        raise ValueError(f"Error al derivar clave compartida: {str(e)}")


def encrypt_message(shared_key, plaintext):
    """
    Cifra un mensaje usando AES-256-GCM con la clave compartida.
    
    Args:
        shared_key: Clave simétrica de 32 bytes (derivada con derive_shared_key)
        plaintext: Mensaje a cifrar (str o bytes)
        
    Returns:
        tuple: (ciphertext_b64, nonce_b64) donde:
            - ciphertext_b64: Texto cifrado + tag en base64 (str)
            - nonce_b64: Nonce usado en base64 (str)
            
    Raises:
        ValueError: Si la clave no tiene el tamaño correcto
    """
    try:
        # Verificar tamaño de la clave
        if len(shared_key) != AES_KEY_LENGTH:
            raise ValueError(f"La clave compartida debe tener {AES_KEY_LENGTH} bytes")
        
        # Convertir plaintext a bytes si es string
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generar nonce aleatorio
        nonce = os.urandom(AES_GCM_NONCE_LENGTH)
        
        # Cifrar con AES-GCM
        aesgcm = AESGCM(shared_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # El ciphertext incluye el tag de autenticación al final
        # Codificar en base64 para facilitar transmisión
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')
        
        return ciphertext_b64, nonce_b64
        
    except Exception as e:
        raise ValueError(f"Error al cifrar mensaje: {str(e)}")


def decrypt_message(shared_key, ciphertext, nonce):
    """
    Descifra un mensaje usando AES-256-GCM con la clave compartida.
    
    Args:
        shared_key: Clave simétrica de 32 bytes (derivada con derive_shared_key)
        ciphertext: Texto cifrado en base64 (str) o bytes
        nonce: Nonce en base64 (str) o bytes
        
    Returns:
        bytes: Mensaje descifrado en bytes
        
    Raises:
        ValueError: Si la clave no es válida, el nonce es incorrecto, 
                   o la autenticación falla (mensaje corrupto o clave incorrecta)
    """
    try:
        # Verificar tamaño de la clave
        if len(shared_key) != AES_KEY_LENGTH:
            raise ValueError(f"La clave compartida debe tener {AES_KEY_LENGTH} bytes")
        
        # Decodificar desde base64 si es necesario
        if isinstance(ciphertext, str):
            ciphertext = base64.b64decode(ciphertext)
        
        if isinstance(nonce, str):
            nonce = base64.b64decode(nonce)
        
        # Verificar tamaño del nonce
        if len(nonce) != AES_GCM_NONCE_LENGTH:
            raise ValueError(f"El nonce debe tener {AES_GCM_NONCE_LENGTH} bytes")
        
        # Descifrar con AES-GCM
        aesgcm = AESGCM(shared_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext
        
    except Exception as e:
        raise ValueError(f"Error al descifrar mensaje: {str(e)}")
