#!/usr/bin/env python3
"""
Script de verificación manual para el módulo de firma digital.
Prueba las funciones básicas sin necesidad de pytest.
"""

import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

from digital_signature import sign_message, verify_message_signature


def test_basic_functionality():
    """Prueba básica de firma y verificación."""
    print("=" * 60)
    print("Test 1: Funcionalidad básica de firma y verificación")
    print("=" * 60)
    
    # Generar par de claves
    print("1. Generando par de claves EC P-256...")
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Generar certificado autofirmado
    print("2. Generando certificado X.509 autofirmado...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
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
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).sign(private_key, hashes.SHA256())
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    # Mensaje de prueba
    message = b"Este es un mensaje de prueba para firmar digitalmente"
    print(f"3. Mensaje a firmar: {message.decode('utf-8')}")
    
    # Firmar el mensaje
    print("4. Firmando mensaje con ECDSA-SHA256...")
    signature = sign_message(private_key_pem, message)
    print(f"   Firma (base64): {signature[:50]}...")
    
    # Verificar la firma
    print("5. Verificando firma...")
    is_valid = verify_message_signature(cert_pem, message, signature)
    
    if is_valid:
        print("   ✓ Firma VÁLIDA")
    else:
        print("   ✗ Firma INVÁLIDA")
        return False
    
    print("\n✓ Test 1 PASADO\n")
    return True


def test_invalid_signature():
    """Prueba con firma inválida."""
    print("=" * 60)
    print("Test 2: Detección de firma inválida")
    print("=" * 60)
    
    # Generar par de claves y certificado
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
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
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256())
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    # Firmar mensaje original
    original_message = b"Mensaje original"
    signature = sign_message(private_key_pem, original_message)
    
    # Intentar verificar con mensaje modificado
    print("1. Verificando firma con mensaje modificado...")
    modified_message = b"Mensaje MODIFICADO"
    is_valid = verify_message_signature(cert_pem, modified_message, signature)
    
    if not is_valid:
        print("   ✓ Firma correctamente rechazada")
    else:
        print("   ✗ ERROR: Firma inválida aceptada")
        return False
    
    print("\n✓ Test 2 PASADO\n")
    return True


def test_wrong_certificate():
    """Prueba con certificado incorrecto."""
    print("=" * 60)
    print("Test 3: Detección de certificado incorrecto")
    print("=" * 60)
    
    # Generar primer par de claves
    private_key_1 = ec.generate_private_key(ec.SECP256R1())
    private_key_1_pem = private_key_1.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Generar segundo par de claves
    private_key_2 = ec.generate_private_key(ec.SECP256R1())
    
    # Generar certificado para la segunda clave
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "wrong.example.com"),
    ])
    
    cert_2 = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key_2.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key_2, hashes.SHA256())
    
    cert_2_pem = cert_2.public_bytes(serialization.Encoding.PEM)
    
    # Firmar con la primera clave
    message = b"Mensaje de prueba"
    print("1. Firmando con clave privada #1...")
    signature = sign_message(private_key_1_pem, message)
    
    # Intentar verificar con certificado de la segunda clave
    print("2. Verificando con certificado de clave privada #2...")
    is_valid = verify_message_signature(cert_2_pem, message, signature)
    
    if not is_valid:
        print("   ✓ Firma correctamente rechazada")
    else:
        print("   ✗ ERROR: Firma con certificado incorrecto aceptada")
        return False
    
    print("\n✓ Test 3 PASADO\n")
    return True


def test_multiple_messages():
    """Prueba con múltiples mensajes."""
    print("=" * 60)
    print("Test 4: Firma y verificación de múltiples mensajes")
    print("=" * 60)
    
    # Generar par de claves y certificado
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
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
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256())
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    # Mensajes de prueba
    messages = [
        b"Mensaje corto",
        b"Mensaje con caracteres especiales: !@#$%^&*()",
        b"",  # Mensaje vacío
        b"A" * 1000,  # Mensaje largo
    ]
    
    for i, message in enumerate(messages, 1):
        msg_preview = message[:50] if len(message) <= 50 else message[:47] + b"..."
        print(f"{i}. Probando mensaje: {msg_preview}")
        
        signature = sign_message(private_key_pem, message)
        is_valid = verify_message_signature(cert_pem, message, signature)
        
        if is_valid:
            print(f"   ✓ Firma válida")
        else:
            print(f"   ✗ ERROR: Firma inválida")
            return False
    
    print("\n✓ Test 4 PASADO\n")
    return True


def main():
    """Ejecuta todos los tests."""
    print("\n" + "=" * 60)
    print("VERIFICACIÓN DEL MÓDULO DE FIRMA DIGITAL")
    print("=" * 60 + "\n")
    
    tests = [
        test_basic_functionality,
        test_invalid_signature,
        test_wrong_certificate,
        test_multiple_messages,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test FALLÓ con excepción: {e}")
            failed += 1
    
    # Resumen
    print("=" * 60)
    print("RESUMEN")
    print("=" * 60)
    print(f"Tests pasados: {passed}/{len(tests)}")
    print(f"Tests fallidos: {failed}/{len(tests)}")
    
    if failed == 0:
        print("\n✓ TODOS LOS TESTS PASARON")
        return 0
    else:
        print(f"\n✗ {failed} TEST(S) FALLARON")
        return 1


if __name__ == "__main__":
    sys.exit(main())
