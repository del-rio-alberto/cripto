import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from hybrid_encryption import derive_shared_key, encrypt_message
from digital_signature import sign_message
from user_keys import generate_user_keypair, _serialize_public_key

def send_secure_message(sender, receiver, message_text):
    """
    Prepara un mensaje seguro para ser enviado.
    
    Realiza los siguientes pasos:
    1. Genera un par de claves EC efímero para esta transmisión.
    2. Deriva una clave compartida entre la clave efímera y la pública del receptor.
    3. Cifra el mensaje con AES-GCM usando la clave compartida.
    4. Firma el ciphertext con la clave privada del emisor.
    5. Empaqueta todo en un diccionario.
    
    Args:
        sender: Puede ser:
            - Un diccionario con claves 'private_key' y 'cert'.
            - Una tupla (private_key, cert).
            Donde:
                - private_key: Clave privada EC P-256 (objeto o PEM).
                - cert: Certificado X.509 del emisor (objeto o PEM).
        receiver: Puede ser:
            - Un certificado X.509 (objeto o PEM).
            - Un diccionario con clave 'cert'.
        message_text: El mensaje a enviar (str o bytes).
        
    Returns:
        dict: Diccionario con los campos:
            - ciphertext: Texto cifrado (base64).
            - nonce: Nonce usado en el cifrado (base64).
            - signature: Firma del ciphertext (base64).
            - cert_emisor: Certificado del emisor (PEM str).
            - pubkey_efimera: Clave pública efímera (PEM str).
            
    Raises:
        ValueError: Si los argumentos no son válidos o faltan claves/certificados.
    """
    # 1. Extraer claves y certificados del emisor
    sender_private_key = None
    sender_cert_pem = None
    
    if isinstance(sender, dict):
        sender_private_key = sender.get('private_key')
        sender_cert = sender.get('cert')
    elif isinstance(sender, (tuple, list)) and len(sender) >= 2:
        sender_private_key = sender[0]
        sender_cert = sender[1]
    else:
        raise ValueError("El argumento 'sender' debe ser un diccionario o tupla con (private_key, cert)")
        
    if not sender_private_key or not sender_cert:
        raise ValueError("Faltan la clave privada o el certificado del emisor")

    # Normalizar certificado del emisor a PEM string
    if isinstance(sender_cert, x509.Certificate):
        sender_cert_pem = sender_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    elif isinstance(sender_cert, bytes):
        sender_cert_pem = sender_cert.decode('utf-8')
    elif isinstance(sender_cert, str):
        sender_cert_pem = sender_cert
    else:
        raise ValueError("Formato de certificado del emisor no soportado")

    # 2. Extraer certificado del receptor y su clave pública
    receiver_cert_obj = None
    
    if isinstance(receiver, dict):
        receiver_cert_input = receiver.get('cert')
    else:
        receiver_cert_input = receiver
        
    if isinstance(receiver_cert_input, (str, bytes)):
        if isinstance(receiver_cert_input, str):
            receiver_cert_input = receiver_cert_input.encode('utf-8')
        receiver_cert_obj = x509.load_pem_x509_certificate(receiver_cert_input)
    elif isinstance(receiver_cert_input, x509.Certificate):
        receiver_cert_obj = receiver_cert_input
    else:
        raise ValueError("El argumento 'receiver' debe contener un certificado válido")
        
    receiver_public_key = receiver_cert_obj.public_key()
    
    # 3. Generar par de claves efímero
    ephemeral_private_key, ephemeral_public_key = generate_user_keypair()
    
    # 4. Derivar clave compartida (Ephem Private + Receiver Public)
    shared_key = derive_shared_key(ephemeral_private_key, receiver_public_key)
    
    # 5. Cifrar el mensaje
    # encrypt_message devuelve (ciphertext_b64, nonce_b64)
    ciphertext_b64, nonce_b64 = encrypt_message(shared_key, message_text)
    
    # 6. Firmar el ciphertext   
    if isinstance(sender_private_key, ec.EllipticCurvePrivateKey):
        sender_private_key_pem = sender_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    elif isinstance(sender_private_key, str):
        sender_private_key_pem = sender_private_key.encode('utf-8')
    else:
        sender_private_key_pem = sender_private_key
        
    # El mensaje a firmar es el ciphertext 
    signature_b64 = sign_message(sender_private_key_pem, ciphertext_b64.encode('utf-8'))
    
    # 7. Preparar clave pública efímera para enviar (PEM)
    ephemeral_public_key_pem = _serialize_public_key(ephemeral_public_key).decode('utf-8')
    
    # 8. Construir diccionario de retorno
    return {
        "ciphertext": ciphertext_b64,
        "nonce": nonce_b64,
        "signature": signature_b64,
        "cert_emisor": sender_cert_pem,
        "pubkey_efimera": ephemeral_public_key_pem
    }
