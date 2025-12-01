"""
Módulo para firma digital de mensajes.

Proporciona funciones para:
- Firmar mensajes usando claves privadas EC con ECDSA-SHA256
- Verificar firmas de mensajes usando certificados X.509
"""

import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec


def sign_message(private_key_pem, message_bytes):
    """
    Firma un mensaje usando una clave privada EC con ECDSA-SHA256.
    
    Args:
        private_key_pem: Clave privada en formato PEM (str o bytes)
        message_bytes: Mensaje a firmar (bytes)
        
    Returns:
        str: Firma en formato base64
        
    Raises:
        ValueError: Si la clave privada no es válida o no es EC
        TypeError: Si message_bytes no es bytes
    """
    # Validar que el mensaje sea bytes
    if not isinstance(message_bytes, bytes):
        raise TypeError("message_bytes debe ser de tipo bytes")
    
    # Convertir PEM a bytes si es string
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode('utf-8')
    
    # Cargar la clave privada
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )
    except Exception as e:
        raise ValueError(f"Error al cargar la clave privada: {str(e)}")
    
    # Verificar que sea una clave EC
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("La clave privada debe ser de tipo EC (Elliptic Curve)")
    
    # Firmar el mensaje con ECDSA-SHA256
    try:
        signature = private_key.sign(
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )
    except Exception as e:
        raise ValueError(f"Error al firmar el mensaje: {str(e)}")
    
    # Retornar la firma en base64
    return base64.b64encode(signature).decode('utf-8')


def verify_message_signature(cert_pem, message_bytes, signature):
    """
    Verifica la firma de un mensaje usando un certificado X.509.
    
    Extrae la clave pública del certificado y verifica que la firma
    corresponda al mensaje usando ECDSA-SHA256.
    
    Args:
        cert_pem: Certificado X.509 en formato PEM (str o bytes)
        message_bytes: Mensaje original (bytes)
        signature: Firma en formato base64 (str)
        
    Returns:
        bool: True si la firma es válida, False en caso contrario
    """
    try:
        # Validar que el mensaje sea bytes
        if not isinstance(message_bytes, bytes):
            return False
        
        # Convertir certificado PEM a bytes si es string
        if isinstance(cert_pem, str):
            cert_pem = cert_pem.encode('utf-8')
        
        # Cargar el certificado
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
        except Exception:
            return False
        
        # Extraer la clave pública del certificado
        public_key = cert.public_key()
        
        # Verificar que sea una clave EC
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        
        # Decodificar la firma desde base64
        try:
            signature_bytes = base64.b64decode(signature)
        except Exception:
            return False
        
        # Verificar la firma con ECDSA-SHA256
        try:
            public_key.verify(
                signature_bytes,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            # La verificación falló (firma inválida)
            return False
            
    except Exception:
        # Cualquier otro error resulta en verificación fallida
        return False
