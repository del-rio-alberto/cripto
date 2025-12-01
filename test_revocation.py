#!/usr/bin/env python3
"""
Script de prueba para el sistema de revocación de certificados.
"""

from pki import issue_certificate, revoke_certificate, is_revoked, load_certificate
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

def generate_user_csr(username):
    """Genera un CSR de usuario con clave EC P-256."""
    # Generar clave privada EC P-256
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    # Crear CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Mi Organizacion"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])).sign(private_key, hashes.SHA256())
    
    # Retornar CSR en formato PEM
    return csr.public_bytes(serialization.Encoding.PEM), private_key

def main():
    print("=" * 60)
    print("PRUEBA DEL SISTEMA DE REVOCACIÓN DE CERTIFICADOS")
    print("=" * 60)
    
    # 1. Emitir un certificado de prueba
    print("\n1. Emitiendo certificado de prueba para 'test_user'...")
    csr_pem, private_key = generate_user_csr("test_user")
    cert_pem = issue_certificate("test_user", csr_pem)
    
    # Parsear el certificado para obtener el serial
    cert = x509.load_pem_x509_certificate(cert_pem)
    serial_number = cert.serial_number
    print(f"   ✓ Certificado emitido con serial: {serial_number}")
    
    # 2. Verificar que el certificado NO está revocado
    print("\n2. Verificando que el certificado NO está revocado...")
    if is_revoked(cert_pem):
        print("   ✗ ERROR: El certificado aparece como revocado (no debería)")
        return False
    else:
        print("   ✓ Certificado válido (no revocado)")
    
    # 3. Revocar el certificado
    print(f"\n3. Revocando certificado con serial {serial_number}...")
    revoke_certificate(serial_number)
    print("   ✓ Certificado revocado")
    
    # 4. Verificar que el certificado ESTÁ revocado
    print("\n4. Verificando que el certificado ESTÁ revocado...")
    if is_revoked(cert_pem):
        print("   ✓ Certificado correctamente marcado como revocado")
    else:
        print("   ✗ ERROR: El certificado NO aparece como revocado (debería)")
        return False
    
    # 5. Emitir otro certificado y verificar que NO está revocado
    print("\n5. Emitiendo segundo certificado para 'test_user2'...")
    csr_pem2, private_key2 = generate_user_csr("test_user2")
    cert_pem2 = issue_certificate("test_user2", csr_pem2)
    
    cert2 = x509.load_pem_x509_certificate(cert_pem2)
    serial_number2 = cert2.serial_number
    print(f"   ✓ Certificado emitido con serial: {serial_number2}")
    
    print("\n6. Verificando que el segundo certificado NO está revocado...")
    if is_revoked(cert_pem2):
        print("   ✗ ERROR: El segundo certificado aparece como revocado (no debería)")
        return False
    else:
        print("   ✓ Segundo certificado válido (no revocado)")
    
    # 7. Verificar que el primer certificado sigue revocado
    print("\n7. Verificando que el primer certificado sigue revocado...")
    if is_revoked(cert_pem):
        print("   ✓ Primer certificado sigue marcado como revocado")
    else:
        print("   ✗ ERROR: El primer certificado ya no aparece como revocado")
        return False
    
    print("\n" + "=" * 60)
    print("✓ TODAS LAS PRUEBAS PASARON EXITOSAMENTE")
    print("=" * 60)
    return True

if __name__ == "__main__":
    try:
        success = main()
        exit(0 if success else 1)
    except Exception as e:
        print(f"\nERROR: {e}")
        exit(1)
