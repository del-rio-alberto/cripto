
import datetime
from datetime import timezone
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID

def generate_private_key(key_size=4096):
    """Genera una clave privada RSA."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

def generate_root_ca(private_key, common_name="Root CA"):
    """Genera un certificado autofirmado para la CA Raíz."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Mi Organizacion"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(timezone.utc) + datetime.timedelta(days=3650) # 10 años
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256())
    
    return cert

def generate_csr(private_key, common_name):
    """Genera una Solicitud de Firma de Certificado (CSR)."""
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Mi Organizacion"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True,
    ).sign(private_key, hashes.SHA256())
    
    return csr

def sign_csr(csr, ca_cert, ca_key, ca_is_root=False):
    """Firma un CSR con la clave de una CA."""
    builder = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(timezone.utc) + datetime.timedelta(days=3650) # 10 años
    )
    
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
        
    cert = builder.sign(ca_key, hashes.SHA256())
    return cert

def generate_crl(ca_cert, ca_key):
    """Genera una Lista de Revocación de Certificados (CRL) vacía."""
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.datetime.now(timezone.utc))
    builder = builder.next_update(datetime.datetime.now(timezone.utc) + datetime.timedelta(days=1))
    
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl

def save_pem(data, filename):
    """Guarda datos (clave, cert, csr, crl) en un archivo PEM."""
    with open(filename, "wb") as f:
        if isinstance(data, (x509.Certificate, x509.CertificateSigningRequest, x509.CertificateRevocationList)):
            f.write(data.public_bytes(serialization.Encoding.PEM))
        elif isinstance(data, rsa.RSAPrivateKey):
            f.write(data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

def load_private_key(filename):
    """Carga una clave privada desde un archivo PEM."""
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )

def load_certificate(filename):
    """Carga un certificado desde un archivo PEM."""
    with open(filename, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def setup_pki():
    """Orquesta el flujo completo de generación."""
    print("Generando CA Raíz...")
    root_key = generate_private_key()
    root_cert = generate_root_ca(root_key, "Root CA")
    save_pem(root_key, "root_ca.key")
    save_pem(root_cert, "root_ca.crt")
    
    print("Generando CA Intermedia...")
    inter_key = generate_private_key()
    inter_csr = generate_csr(inter_key, "Intermediate CA")
    save_pem(inter_key, "intermediate_ca.key")
    save_pem(inter_csr, "intermediate_ca.csr")
    
    print("Firmando CA Intermedia...")
    inter_cert = sign_csr(inter_csr, root_cert, root_key)
    save_pem(inter_cert, "intermediate_ca.crt")
    
    print("Generando CRL para CA Intermedia...")
    crl = generate_crl(inter_cert, inter_key)
    save_pem(crl, "intermediate_ca.crl")
    
    print("Configuración PKI completada.")

def issue_certificate(username, csr_pem):
    """
    Emite un certificado para un usuario basado en un CSR.
    
    Args:
        username (str): Nombre del usuario (se usará como CN).
        csr_pem (bytes): Contenido del CSR en formato PEM.
        
    Returns:
        bytes: Certificado emitido en formato PEM.
    """
    # Cargar CA Intermedia y su clave
    try:
        ca_cert = load_certificate("intermediate_ca.crt")
        ca_key = load_private_key("intermediate_ca.key")
    except FileNotFoundError:
        raise Exception("Error: CA Intermedia no encontrada. Ejecuta setup_pki() primero.")

    # Cargar CSR
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
    except Exception as e:
        raise ValueError(f"CSR inválido: {e}")

    # Validar firma del CSR
    if not csr.is_signature_valid:
        raise ValueError("Firma del CSR inválida.")

    # Validar que la clave pública sea EC P-256
    public_key = csr.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("La clave pública debe ser de Curva Elíptica.")
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("La curva debe ser SECP256R1 (P-256).")

    # Construir el certificado
    # Forzamos el CN al username proporcionado para seguridad
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Mi Organizacion"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(timezone.utc) + datetime.timedelta(days=365) # 1 año
    )

    # Añadir extensiones
    # Basic Constraints: CA=False
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    
    # Key Usage: digitalSignature, keyEncipherment
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    # Extended Key Usage: clientAuth
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=False
    )

    # Firmar el certificado
    cert = builder.sign(ca_key, hashes.SHA256())
    
    # Guardar certificado
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    # Asegurar directorio certs
    if not os.path.exists("certs"):
        os.makedirs("certs")
        
    cert_filename = f"certs/{username}.crt"
    with open(cert_filename, "wb") as f:
        f.write(cert_pem)
        
    # Registrar en log
    with open("issued_certs.log", "a") as log:
        log.write(f"{cert.serial_number},{datetime.datetime.now(timezone.utc).isoformat()},{username},Valid\n")
        
    return cert_pem

def revoke_certificate(serial):
    """
    Revoca un certificado añadiéndolo a la CRL.
    
    Args:
        serial (int): Número de serie del certificado a revocar.
        
    Returns:
        bool: True si la revocación fue exitosa.
    """
    # Cargar CA Intermedia y su clave
    try:
        ca_cert = load_certificate("intermediate_ca.crt")
        ca_key = load_private_key("intermediate_ca.key")
    except FileNotFoundError:
        raise Exception("Error: CA Intermedia no encontrada.")
    
    # Cargar CRL actual
    crl_path = "intermediate_ca.crl"
    try:
        with open(crl_path, "rb") as f:
            current_crl = x509.load_pem_x509_crl(f.read())
    except FileNotFoundError:
        # Si no existe CRL, crear una nueva vacía
        current_crl = generate_crl(ca_cert, ca_key)
    
    # Crear nueva CRL con el certificado revocado añadido
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.datetime.now(timezone.utc))
    builder = builder.next_update(datetime.datetime.now(timezone.utc) + datetime.timedelta(days=1))
    
    # Añadir todos los certificados revocados existentes
    for revoked_cert in current_crl:
        builder = builder.add_revoked_certificate(revoked_cert)
    
    # Añadir el nuevo certificado revocado
    revoked_cert = x509.RevokedCertificateBuilder().serial_number(
        serial
    ).revocation_date(
        datetime.datetime.now(timezone.utc)
    ).build()
    
    builder = builder.add_revoked_certificate(revoked_cert)
    
    # Firmar la CRL con la CA intermedia
    new_crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    
    # Guardar la CRL actualizada
    save_pem(new_crl, crl_path)
    
    print(f"Certificado con serial {serial} revocado exitosamente.")
    return True

def is_revoked(cert_pem):
    """
    Verifica si un certificado está revocado.
    
    Args:
        cert_pem (bytes): Certificado en formato PEM.
        
    Returns:
        bool: True si el certificado está revocado, False en caso contrario.
    """
    # Cargar CRL
    crl_path = "intermediate_ca.crl"
    try:
        with open(crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
    except FileNotFoundError:
        # Si no existe CRL, ningún certificado está revocado
        return False
    
    # Parsear el certificado
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as e:
        raise ValueError(f"Certificado PEM inválido: {e}")
    
    # Verificar si el número de serie está en la CRL
    revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    
    return revoked is not None

if __name__ == "__main__":
    setup_pki()
