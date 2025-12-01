import ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec

# 1. Comandos para cargar en Flask (Snippet de ejemplo)
def get_flask_ssl_context(cert_path, key_path):
    """
    Retorna el contexto SSL para Flask.
    Uso: app.run(ssl_context=get_flask_ssl_context('user.crt', 'user.key'))
    """
    return (cert_path, key_path)

# 2. Verificar firma digital
def verify_signature(public_key, signature, data):
    """
    Verifica una firma digital.
    Devuelve True si es válida, False si no.
    """
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        return True
    except Exception:
        return False

# 3. Verificar cadena de certificados y CRL
def verify_certificate_chain(user_cert_pem, intermediate_cert_pem, root_cert_pem, crl_pem):
    """
    Verifica la cadena: User -> Intermediate -> Root y comprueba CRL.
    """
    try:
        # Cargar objetos
        user_cert = x509.load_pem_x509_certificate(user_cert_pem)
        inter_cert = x509.load_pem_x509_certificate(intermediate_cert_pem)
        root_cert = x509.load_pem_x509_certificate(root_cert_pem)
        crl = x509.load_pem_x509_crl(crl_pem)

        # 1. Verificar firma del User Cert con Intermediate Key
        inter_public_key = inter_cert.public_key()
        if isinstance(inter_public_key, ec.EllipticCurvePublicKey):
            inter_public_key.verify(
                user_cert.signature,
                user_cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            inter_public_key.verify(
                user_cert.signature,
                user_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                user_cert.signature_hash_algorithm
            )

        # 2. Verificar firma del Intermediate Cert con Root Key
        root_public_key = root_cert.public_key()
        if isinstance(root_public_key, ec.EllipticCurvePublicKey):
            root_public_key.verify(
                inter_cert.signature,
                inter_cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            root_public_key.verify(
                inter_cert.signature,
                inter_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                inter_cert.signature_hash_algorithm
            )

        # 3. Comprobar CRL (Revocación)
        # Verificar firma de la CRL con Intermediate Key (quien la emite)
        if isinstance(inter_public_key, ec.EllipticCurvePublicKey):
             inter_public_key.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        else:
             inter_public_key.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                padding.PKCS1v15(),
                crl.signature_hash_algorithm
            )
            
        # Buscar si el certificado de usuario está revocado
        revoked = crl.get_revoked_certificate_by_serial_number(user_cert.serial_number)
        if revoked is not None:
            raise Exception("Certificado revocado")

        return True

    except Exception as e:
        print(f"Error de validación: {e}")
        return False
