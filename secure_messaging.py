import os
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from hybrid_encryption import derive_shared_key, encrypt_message, decrypt_message
from digital_signature import sign_message, verify_message_signature
from user_keys import generate_user_keypair, _serialize_public_key
from pki_helper import verify_certificate_chain

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


def _load_file(path):
    with open(path, 'rb') as f:
        return f.read()


def receive_secure_message(receiver, payload_dict):
    """
    Recibe y descifra un mensaje seguro.
    
    Pasos:
    1. Verificar certificado del emisor (cadena + CRL).
    2. Usar pubkey_efimera_emisor + clave_privada_receptor -> ECDH.
    3. Derivar shared_key.
    4. Verificar firma.
    5. Descifrar AES-GCM.
    6. Devolver plaintext.
    
    Args:
        receiver: Diccionario con 'private_key' (EC Private Key obj o PEM)
                  o directamente la clave privada.
        payload_dict: Diccionario recibido de send_secure_message.
        
    Returns:
        str: Mensaje en texto plano.
        
    Raises:
        ValueError: Si falla validación, firma o descifrado.
    """
    # Extraer datos del payload
    try:
        ciphertext_b64 = payload_dict['ciphertext']
        nonce_b64 = payload_dict['nonce']
        signature_b64 = payload_dict['signature']
        sender_cert_pem = payload_dict['cert_emisor']
        ephemeral_pub_pem = payload_dict['pubkey_efimera']
    except KeyError as e:
        raise ValueError(f"Payload incompleto, falta: {e}")

    # 1. Verificar certificado del emisor
    # Cargar artefactos PKI (Root CA, Intermediate CA, CRL)
    root_pem = None
    inter_pem = None
    crl_pem = None
    
    # Rutas posibles
    possible_roots = ["root_ca.crt", "pki/root/certs/root.cert.pem"]
    possible_inters = ["intermediate_ca.crt", "pki/intermediate/intermediate.crt"]
    possible_crls = ["intermediate_ca.crl", "pki/intermediate/crl.pem"]
    
    for p in possible_roots:
        if os.path.exists(p):
            root_pem = _load_file(p)
            break
            
    for p in possible_inters:
        if os.path.exists(p):
            inter_pem = _load_file(p)
            break
            
    for p in possible_crls:
        if os.path.exists(p):
            crl_pem = _load_file(p)
            break
            
    if not root_pem or not inter_pem:
        raise ValueError("No se encontraron los certificados de CA (Root/Intermediate) en el sistema")
        
    if not crl_pem:
        raise ValueError("No se encontró la CRL en el sistema")
        
    # Validar cadena
    sender_cert_bytes = sender_cert_pem.encode('utf-8') if isinstance(sender_cert_pem, str) else sender_cert_pem
    
    if not verify_certificate_chain(sender_cert_bytes, inter_pem, root_pem, crl_pem):
        raise ValueError("Validación de certificado del emisor fallida (Cadena o CRL inválidos)")
        
    # 2. Obtener clave privada del receptor
    receiver_private_key = None
    if isinstance(receiver, dict):
        receiver_private_key = receiver.get('private_key')
    else:
        receiver_private_key = receiver
        
    if not receiver_private_key:
        raise ValueError("Se requiere la clave privada del receptor")
        
    # 3. Derivar clave compartida
    shared_key = derive_shared_key(receiver_private_key, ephemeral_pub_pem)
    
    # 4. Verificar firma
    msg_to_verify = ciphertext_b64.encode('utf-8')
    if not verify_message_signature(sender_cert_pem, msg_to_verify, signature_b64):
        raise ValueError("Firma del mensaje inválida")
        
    # 5. Descifrar mensaje
    plaintext_bytes = decrypt_message(shared_key, ciphertext_b64, nonce_b64)
    
    return plaintext_bytes.decode('utf-8')
