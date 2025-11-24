
import datetime
from datetime import timezone
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
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

if __name__ == "__main__":
    setup_pki()
