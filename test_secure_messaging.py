import pytest
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from secure_messaging import send_secure_message
from user_keys import generate_user_keypair
from hybrid_encryption import derive_shared_key, decrypt_message
from digital_signature import verify_message_signature

def generate_self_signed_cert(private_key, common_name):
    """Genera un certificado autofirmado para testing."""
    subject = issuer = x509.Name([
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
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256())
    
    return cert

class TestSecureMessaging:
    
    def test_send_secure_message_flow(self):
        # 1. Setup: Crear claves y certificados para Alice (Sender) y Bob (Receiver)
        alice_private, alice_public = generate_user_keypair()
        alice_cert = generate_self_signed_cert(alice_private, u"Alice")
        
        bob_private, bob_public = generate_user_keypair()
        bob_cert = generate_self_signed_cert(bob_private, u"Bob")
        
        # 2. Ejecutar send_secure_message
        message = "Hola Bob, este es un mensaje seguro."
        
        # Preparar inputs
        sender = {'private_key': alice_private, 'cert': alice_cert}
        
        # Llamada a la función
        result = send_secure_message(sender, bob_cert, message)
        
        # 3. Verificar estructura del resultado
        assert isinstance(result, dict)
        assert "ciphertext" in result
        assert "nonce" in result
        assert "signature" in result
        assert "cert_emisor" in result
        assert "pubkey_efimera" in result
        
        # 4. Verificar que se puede descifrar (Simular lado del receptor)
        
        # a) Recuperar clave efímera
        ephemeral_pub_pem = result["pubkey_efimera"].encode('utf-8')
        ephemeral_pub = serialization.load_pem_public_key(ephemeral_pub_pem)
        
        # b) Derivar clave compartida (Bob Private + Ephemeral Public)
        shared_key = derive_shared_key(bob_private, ephemeral_pub)
        
        # c) Descifrar
        decrypted = decrypt_message(shared_key, result["ciphertext"], result["nonce"])
        assert decrypted.decode('utf-8') == message
        
        # 5. Verificar firma
        # La firma es sobre el ciphertext
        is_valid = verify_message_signature(
            result["cert_emisor"],
            result["ciphertext"].encode('utf-8'),
            result["signature"]
        )
        assert is_valid is True

    def test_send_secure_message_input_formats(self):
        """Prueba con diferentes formatos de entrada (PEM vs Objetos)."""
        alice_private, _ = generate_user_keypair()
        alice_cert = generate_self_signed_cert(alice_private, u"Alice")
        bob_private, _ = generate_user_keypair()
        bob_cert = generate_self_signed_cert(bob_private, u"Bob")
        
        # Convertir a PEM
        alice_key_pem = alice_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        alice_cert_pem = alice_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        bob_cert_pem = bob_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        message = "Test PEM inputs"
        
        # Sender como tupla (PEM, PEM)
        sender = (alice_key_pem, alice_cert_pem)
        
        # Receiver como PEM string
        result = send_secure_message(sender, bob_cert_pem, message)
        
        assert result["ciphertext"] is not None
        
        # Verificar firma
        assert verify_message_signature(
            result["cert_emisor"],
            result["ciphertext"].encode('utf-8'),
            result["signature"]
        )

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
