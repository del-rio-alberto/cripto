#!/usr/bin/env python3
"""Debug script para verificar la cadena de certificados"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pki import (
    generate_private_key,
    generate_root_ca,
    generate_csr,
    sign_csr,
    generate_crl
)
from pki_helper import verify_certificate_chain

# Generar PKI
print("Generando PKI...")
root_key = generate_private_key()
root_cert = generate_root_ca(root_key, "Test Root CA")

inter_key = generate_private_key()
inter_csr = generate_csr(inter_key, "Test Intermediate CA")
inter_cert = sign_csr(inter_csr, root_cert, root_key)

# Generar certificado de usuario con EC P-256
user_key = ec.generate_private_key(ec.SECP256R1())
user_csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test_user"),
]))
user_csr = user_csr_builder.sign(user_key, hashes.SHA256())

user_cert_builder = x509.CertificateBuilder().subject_name(
    user_csr.subject
).issuer_name(
    inter_cert.subject
).public_key(
    user_csr.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    root_cert.not_valid_before
).not_valid_after(
    root_cert.not_valid_after
).add_extension(
    x509.BasicConstraints(ca=False, path_length=None), critical=True
)
user_cert = user_cert_builder.sign(inter_key, hashes.SHA256())

# Generar CRL
crl = generate_crl(inter_cert, inter_key)

print(f"Root key type: {type(root_key)}")
print(f"Inter key type: {type(inter_key)}")
print(f"User key type: {type(user_key)}")
print(f"Root public key type: {type(root_cert.public_key())}")
print(f"Inter public key type: {type(inter_cert.public_key())}")
print(f"User public key type: {type(user_cert.public_key())}")

# Convertir a PEM
user_cert_pem = user_cert.public_bytes(serialization.Encoding.PEM)
inter_cert_pem = inter_cert.public_bytes(serialization.Encoding.PEM)
root_cert_pem = root_cert.public_bytes(serialization.Encoding.PEM)
crl_pem = crl.public_bytes(serialization.Encoding.PEM)

# Verificar cadena
print("\nVerificando cadena...")
result = verify_certificate_chain(user_cert_pem, inter_cert_pem, root_cert_pem, crl_pem)
print(f"Resultado: {result}")
