#!/usr/bin/env python3
"""
Script de prueba para verificar los endpoints PKI de Flask.
Genera certificados, firma datos y verifica usando los endpoints.
"""

import base64
import requests
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

# Configuración
BASE_URL = "http://localhost:5000"

def test_pki_endpoints():
    print("=== Test de Endpoints PKI ===\n")
    
    # 1. Generar PKI completa
    print("1. Generando PKI...")
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
    
    print("✓ PKI generada\n")
    
    # 2. Test de verificación de firma
    print("2. Probando /pki/verify-signature...")
    test_data = "Mensaje de prueba para firma"
    signature = user_key.sign(test_data.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
    
    payload = {
        "certificate_pem": base64.b64encode(
            user_cert.public_bytes(serialization.Encoding.PEM)
        ).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8'),
        "data": test_data
    }
    
    response = requests.post(f"{BASE_URL}/pki/verify-signature", json=payload)
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.json()}")
    
    if response.status_code == 200 and response.json().get('valid'):
        print("   ✓ Firma verificada correctamente\n")
    else:
        print("   ✗ Error en verificación de firma\n")
    
    # 3. Test de verificación de cadena
    print("3. Probando /pki/verify-chain...")
    payload = {
        "user_cert_pem": base64.b64encode(
            user_cert.public_bytes(serialization.Encoding.PEM)
        ).decode('utf-8'),
        "intermediate_cert_pem": base64.b64encode(
            inter_cert.public_bytes(serialization.Encoding.PEM)
        ).decode('utf-8'),
        "root_cert_pem": base64.b64encode(
            root_cert.public_bytes(serialization.Encoding.PEM)
        ).decode('utf-8'),
        "crl_pem": base64.b64encode(
            crl.public_bytes(serialization.Encoding.PEM)
        ).decode('utf-8')
    }
    
    response = requests.post(f"{BASE_URL}/pki/verify-chain", json=payload)
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.json()}")
    
    if response.status_code == 200 and response.json().get('valid'):
        print("   ✓ Cadena verificada correctamente\n")
    else:
        print("   ✗ Error en verificación de cadena\n")
    
    print("=== Tests completados ===")

if __name__ == "__main__":
    try:
        test_pki_endpoints()
    except requests.exceptions.ConnectionError:
        print("Error: No se pudo conectar al servidor Flask.")
        print("Asegúrate de que el servidor esté corriendo en http://localhost:5000")
    except Exception as e:
        print(f"Error: {e}")
