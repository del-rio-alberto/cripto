"""
Test 1: Firmar y verificar mensajes.

Prueba las funciones de firma digital usando ECDSA-SHA256.
"""

import pytest
from digital_signature import sign_message, verify_message_signature
from user_keys import generate_user_keypair
from pki import issue_certificate, generate_csr
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class TestDigitalSignature:
    """Tests para firmar y verificar mensajes."""
    
    def test_sign_and_verify_message(self, user_keypair):
        """
        Test básico: Firmar un mensaje y verificar la firma.
        
        Usa un certificado autogenerado para la verificación.
        """
        private_key_pem, public_key_pem = user_keypair
        
        # Mensaje de prueba
        message = b"Este es un mensaje de prueba"
        
        # Firmar el mensaje
        signature = sign_message(private_key_pem, message)
        
        # Verificar que la firma es una cadena base64
        assert isinstance(signature, str)
        assert len(signature) > 0
        
        # Para verificar, necesitamos un certificado que contenga la clave pública
        # Generamos un certificado auto-firmado temporal para pruebas
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        import datetime
        
        # Cargar la clave privada
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8') if isinstance(private_key_pem, str) else private_key_pem,
            password=None
        )
        
        # Crear certificado autofirmado
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"Test User"),
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
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).sign(private_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        
        # Verificar la firma
        is_valid = verify_message_signature(cert_pem, message, signature)
        
        assert is_valid is True
    
    def test_verify_with_wrong_message(self, user_keypair):
        """Verificar que una firma no valida con un mensaje diferente."""
        private_key_pem, _ = user_keypair
        
        original_message = b"Mensaje original"
        tampered_message = b"Mensaje modificado"
        
        # Firmar el mensaje original
        signature = sign_message(private_key_pem, original_message)
        
        # Crear certificado
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        import datetime
        
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8') if isinstance(private_key_pem, str) else private_key_pem,
            password=None
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"Test User"),
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
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).sign(private_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        
        # Intentar verificar con mensaje modificado
        is_valid = verify_message_signature(cert_pem, tampered_message, signature)
        
        assert is_valid is False
    
    def test_sign_with_invalid_key(self):
        """Verificar que firmar con una clave inválida lanza ValueError."""
        invalid_key = b"clave invalida"
        message = b"mensaje"
        
        with pytest.raises(ValueError):
            sign_message(invalid_key, message)
    
    def test_verify_with_invalid_signature(self, user_keypair):
        """Verificar que una firma inválida no se valida."""
        private_key_pem, _ = user_keypair
        
        message = b"Mensaje de prueba"
        
        # Crear certificado
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        import datetime
        
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8') if isinstance(private_key_pem, str) else private_key_pem,
            password=None
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"Test User"),
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
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).sign(private_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        
        # Firma inválida (base64 aleatorio)
        invalid_signature = "SGVsbG9Xb3JsZA=="
        
        is_valid = verify_message_signature(cert_pem, message, invalid_signature)
        
        assert is_valid is False
