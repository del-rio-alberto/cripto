"""
Tests unitarios para el módulo de firma digital.

Prueba las funciones sign_message y verify_message_signature
con diferentes escenarios.
"""

import pytest
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from datetime import datetime, timedelta

from digital_signature import sign_message, verify_message_signature


# Fixtures para generar claves y certificados de prueba
@pytest.fixture
def ec_keypair():
    """Genera un par de claves EC P-256 para pruebas."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key


@pytest.fixture
def private_key_pem(ec_keypair):
    """Retorna la clave privada en formato PEM."""
    return ec_keypair.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


@pytest.fixture
def certificate_pem(ec_keypair):
    """Genera un certificado X.509 autofirmado para pruebas."""
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
        ec_keypair.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).sign(ec_keypair, hashes.SHA256())
    
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def test_message():
    """Mensaje de prueba."""
    return b"Este es un mensaje de prueba para firmar"


# Tests de sign_message
def test_sign_message_success(private_key_pem, test_message):
    """Test: Firmar un mensaje exitosamente."""
    signature = sign_message(private_key_pem, test_message)
    
    # Verificar que la firma es una cadena base64 válida
    assert isinstance(signature, str)
    assert len(signature) > 0
    
    # Verificar que se puede decodificar desde base64
    signature_bytes = base64.b64decode(signature)
    assert isinstance(signature_bytes, bytes)
    assert len(signature_bytes) > 0


def test_sign_message_with_string_pem(private_key_pem, test_message):
    """Test: Firmar con clave privada como string."""
    private_key_str = private_key_pem.decode('utf-8')
    signature = sign_message(private_key_str, test_message)
    
    assert isinstance(signature, str)
    assert len(signature) > 0


def test_sign_message_invalid_key():
    """Test: Error al firmar con clave privada inválida."""
    invalid_pem = b"-----BEGIN PRIVATE KEY-----\nINVALID\n-----END PRIVATE KEY-----"
    
    with pytest.raises(ValueError, match="Error al cargar la clave privada"):
        sign_message(invalid_pem, b"test message")


def test_sign_message_non_bytes_message(private_key_pem):
    """Test: Error al firmar con mensaje que no es bytes."""
    with pytest.raises(TypeError, match="message_bytes debe ser de tipo bytes"):
        sign_message(private_key_pem, "not bytes")


# Tests de verify_message_signature
def test_verify_message_signature_success(private_key_pem, certificate_pem, test_message):
    """Test: Verificar firma válida exitosamente."""
    # Firmar el mensaje
    signature = sign_message(private_key_pem, test_message)
    
    # Verificar la firma
    is_valid = verify_message_signature(certificate_pem, test_message, signature)
    
    assert is_valid is True


def test_verify_message_signature_with_string_cert(private_key_pem, certificate_pem, test_message):
    """Test: Verificar con certificado como string."""
    signature = sign_message(private_key_pem, test_message)
    cert_str = certificate_pem.decode('utf-8')
    
    is_valid = verify_message_signature(cert_str, test_message, signature)
    
    assert is_valid is True


def test_verify_message_signature_invalid_signature(certificate_pem, test_message):
    """Test: Verificación falla con firma inválida."""
    # Crear una firma falsa
    fake_signature = base64.b64encode(b"fake signature bytes").decode('utf-8')
    
    is_valid = verify_message_signature(certificate_pem, test_message, fake_signature)
    
    assert is_valid is False


def test_verify_message_signature_modified_message(private_key_pem, certificate_pem, test_message):
    """Test: Verificación falla si el mensaje fue modificado."""
    # Firmar el mensaje original
    signature = sign_message(private_key_pem, test_message)
    
    # Intentar verificar con un mensaje diferente
    modified_message = b"Este es un mensaje MODIFICADO"
    is_valid = verify_message_signature(certificate_pem, modified_message, signature)
    
    assert is_valid is False


def test_verify_message_signature_wrong_certificate(test_message):
    """Test: Verificación falla con certificado incorrecto."""
    # Generar un par de claves diferente
    other_private_key = ec.generate_private_key(ec.SECP256R1())
    other_private_key_pem = other_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Generar certificado diferente
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "other.example.com"),
    ])
    
    other_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        other_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(other_private_key, hashes.SHA256())
    
    other_cert_pem = other_cert.public_bytes(serialization.Encoding.PEM)
    
    # Firmar con la primera clave
    first_private_key = ec.generate_private_key(ec.SECP256R1())
    first_private_key_pem = first_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    signature = sign_message(first_private_key_pem, test_message)
    
    # Intentar verificar con el certificado incorrecto
    is_valid = verify_message_signature(other_cert_pem, test_message, signature)
    
    assert is_valid is False


def test_verify_message_signature_invalid_certificate(private_key_pem, test_message):
    """Test: Verificación falla con certificado inválido."""
    signature = sign_message(private_key_pem, test_message)
    invalid_cert = b"-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"
    
    is_valid = verify_message_signature(invalid_cert, test_message, signature)
    
    assert is_valid is False


def test_verify_message_signature_invalid_base64():
    """Test: Verificación falla con firma que no es base64 válido."""
    # Generar un certificado válido
    private_key = ec.generate_private_key(ec.SECP256R1())
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
    
    # Usar una firma que no es base64 válido
    invalid_signature = "not-valid-base64!@#$"
    
    is_valid = verify_message_signature(cert_pem, b"test", invalid_signature)
    
    assert is_valid is False


def test_verify_message_signature_non_bytes_message(certificate_pem):
    """Test: Verificación falla si el mensaje no es bytes."""
    fake_signature = base64.b64encode(b"fake").decode('utf-8')
    
    is_valid = verify_message_signature(certificate_pem, "not bytes", fake_signature)
    
    assert is_valid is False


# Test de integración completo
def test_full_sign_and_verify_workflow(private_key_pem, certificate_pem):
    """Test de integración: Flujo completo de firma y verificación."""
    messages = [
        b"Mensaje corto",
        b"Mensaje mas largo con caracteres especiales: !@#$%^&*()",
        b"Mensaje con unicode: \xc3\xa1\xc3\xa9\xc3\xad\xc3\xb3\xc3\xba",
        b"",  # Mensaje vacío
        b"A" * 1000,  # Mensaje largo
    ]
    
    for message in messages:
        # Firmar
        signature = sign_message(private_key_pem, message)
        
        # Verificar
        is_valid = verify_message_signature(certificate_pem, message, signature)
        
        assert is_valid is True, f"Fallo para mensaje: {message[:50]}"
