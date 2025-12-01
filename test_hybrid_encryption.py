"""
Tests para el módulo de cifrado híbrido.

Prueba las funciones de:
- Derivación de clave compartida con ECDH
- Cifrado y descifrado con AES-256-GCM
- Casos de error y validación
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from hybrid_encryption import (
    derive_shared_key,
    encrypt_message,
    decrypt_message,
    AES_KEY_LENGTH
)
from user_keys import generate_user_keypair, _serialize_public_key


class TestDeriveSharedKey:
    """Tests para la derivación de clave compartida con ECDH."""
    
    def test_derive_shared_key_basic(self):
        """Test básico: dos partes derivan la misma clave compartida."""
        # Generar claves para Alice y Bob
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        
        # Alice deriva clave usando su privada y la pública de Bob
        alice_shared = derive_shared_key(alice_private, bob_public)
        
        # Bob deriva clave usando su privada y la pública de Alice
        bob_shared = derive_shared_key(bob_private, alice_public)
        
        # Ambas claves deben ser iguales
        assert alice_shared == bob_shared
        assert len(alice_shared) == AES_KEY_LENGTH
    
    def test_derive_shared_key_with_pem(self):
        """Test usando claves en formato PEM."""
        # Generar claves
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        
        # Serializar claves a PEM
        alice_private_pem = alice_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        bob_public_pem = _serialize_public_key(bob_public)
        
        # Derivar clave usando PEM
        shared_key = derive_shared_key(alice_private_pem, bob_public_pem)
        
        assert len(shared_key) == AES_KEY_LENGTH
    
    def test_derive_shared_key_deterministic(self):
        """Test que la derivación es determinista."""
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        
        # Derivar la misma clave múltiples veces
        shared1 = derive_shared_key(alice_private, bob_public)
        shared2 = derive_shared_key(alice_private, bob_public)
        shared3 = derive_shared_key(alice_private, bob_public)
        
        assert shared1 == shared2 == shared3
    
    def test_derive_shared_key_different_peers(self):
        """Test que claves con diferentes peers son distintas."""
        alice_private, _ = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        charlie_private, charlie_public = generate_user_keypair()
        
        # Alice deriva claves con Bob y Charlie
        alice_bob_shared = derive_shared_key(alice_private, bob_public)
        alice_charlie_shared = derive_shared_key(alice_private, charlie_public)
        
        # Las claves deben ser diferentes
        assert alice_bob_shared != alice_charlie_shared


class TestEncryptDecrypt:
    """Tests para cifrado y descifrado de mensajes."""
    
    def test_encrypt_decrypt_basic(self):
        """Test básico de cifrado y descifrado."""
        # Generar clave compartida
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        shared_key = derive_shared_key(alice_private, bob_public)
        
        # Mensaje de prueba
        plaintext = "Hola, este es un mensaje secreto!"
        
        # Cifrar
        ciphertext, nonce = encrypt_message(shared_key, plaintext)
        
        # Verificar que el ciphertext es diferente al plaintext
        assert ciphertext != plaintext
        assert isinstance(ciphertext, str)
        assert isinstance(nonce, str)
        
        # Descifrar
        decrypted = decrypt_message(shared_key, ciphertext, nonce)
        
        # Verificar que el mensaje descifrado es igual al original
        assert decrypted.decode('utf-8') == plaintext
    
    def test_encrypt_decrypt_bytes(self):
        """Test con mensaje en bytes."""
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        shared_key = derive_shared_key(alice_private, bob_public)
        
        plaintext = b"Mensaje en bytes \x00\x01\x02"
        
        ciphertext, nonce = encrypt_message(shared_key, plaintext)
        decrypted = decrypt_message(shared_key, ciphertext, nonce)
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_empty_message(self):
        """Test con mensaje vacío."""
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        shared_key = derive_shared_key(alice_private, bob_public)
        
        plaintext = ""
        
        ciphertext, nonce = encrypt_message(shared_key, plaintext)
        decrypted = decrypt_message(shared_key, ciphertext, nonce)
        
        assert decrypted.decode('utf-8') == plaintext
    
    def test_encrypt_decrypt_long_message(self):
        """Test con mensaje largo."""
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        shared_key = derive_shared_key(alice_private, bob_public)
        
        plaintext = "A" * 10000  # 10KB de texto
        
        ciphertext, nonce = encrypt_message(shared_key, plaintext)
        decrypted = decrypt_message(shared_key, ciphertext, nonce)
        
        assert decrypted.decode('utf-8') == plaintext
    
    def test_different_nonces_produce_different_ciphertexts(self):
        """Test que el mismo mensaje con diferentes nonces produce diferentes ciphertexts."""
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        shared_key = derive_shared_key(alice_private, bob_public)
        
        plaintext = "Mensaje de prueba"
        
        ciphertext1, nonce1 = encrypt_message(shared_key, plaintext)
        ciphertext2, nonce2 = encrypt_message(shared_key, plaintext)
        
        # Los nonces deben ser diferentes
        assert nonce1 != nonce2
        # Los ciphertexts deben ser diferentes
        assert ciphertext1 != ciphertext2
    
    def test_wrong_key_fails_decryption(self):
        """Test que descifrar con clave incorrecta falla."""
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        charlie_private, charlie_public = generate_user_keypair()
        
        # Alice cifra con clave compartida con Bob
        alice_bob_key = derive_shared_key(alice_private, bob_public)
        plaintext = "Mensaje secreto"
        ciphertext, nonce = encrypt_message(alice_bob_key, plaintext)
        
        # Charlie intenta descifrar con su clave compartida con Alice
        alice_charlie_key = derive_shared_key(alice_private, charlie_public)
        
        # Debe fallar la autenticación
        with pytest.raises(ValueError):
            decrypt_message(alice_charlie_key, ciphertext, nonce)
    
    def test_tampered_ciphertext_fails(self):
        """Test que un ciphertext modificado falla la autenticación."""
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        shared_key = derive_shared_key(alice_private, bob_public)
        
        plaintext = "Mensaje original"
        ciphertext, nonce = encrypt_message(shared_key, plaintext)
        
        # Modificar el ciphertext (cambiar un carácter)
        import base64
        ciphertext_bytes = base64.b64decode(ciphertext)
        tampered = bytearray(ciphertext_bytes)
        tampered[0] ^= 0xFF  # Flip bits del primer byte
        tampered_b64 = base64.b64encode(bytes(tampered)).decode('utf-8')
        
        # Debe fallar la autenticación
        with pytest.raises(ValueError):
            decrypt_message(shared_key, tampered_b64, nonce)
    
    def test_wrong_nonce_fails(self):
        """Test que usar un nonce incorrecto falla."""
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        shared_key = derive_shared_key(alice_private, bob_public)
        
        plaintext = "Mensaje de prueba"
        ciphertext, nonce = encrypt_message(shared_key, plaintext)
        
        # Generar otro mensaje para obtener un nonce diferente
        _, wrong_nonce = encrypt_message(shared_key, "Otro mensaje")
        
        # Debe fallar con nonce incorrecto
        with pytest.raises(ValueError):
            decrypt_message(shared_key, ciphertext, wrong_nonce)


class TestEndToEndScenario:
    """Tests de escenarios completos de comunicación."""
    
    def test_alice_bob_communication(self):
        """Test de comunicación bidireccional entre Alice y Bob."""
        # Generar claves para Alice y Bob
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        
        # Ambos derivan la misma clave compartida
        alice_shared = derive_shared_key(alice_private, bob_public)
        bob_shared = derive_shared_key(bob_private, alice_public)
        
        # Alice envía mensaje a Bob
        alice_message = "Hola Bob, ¿cómo estás?"
        ciphertext1, nonce1 = encrypt_message(alice_shared, alice_message)
        bob_received = decrypt_message(bob_shared, ciphertext1, nonce1)
        assert bob_received.decode('utf-8') == alice_message
        
        # Bob responde a Alice
        bob_message = "¡Hola Alice! Estoy bien, gracias."
        ciphertext2, nonce2 = encrypt_message(bob_shared, bob_message)
        alice_received = decrypt_message(alice_shared, ciphertext2, nonce2)
        assert alice_received.decode('utf-8') == bob_message
    
    def test_multiple_participants(self):
        """Test con múltiples participantes."""
        # Generar claves para Alice, Bob y Charlie
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        charlie_private, charlie_public = generate_user_keypair()
        
        # Alice se comunica con Bob
        alice_bob_key = derive_shared_key(alice_private, bob_public)
        message_to_bob = "Mensaje para Bob"
        ct_bob, nonce_bob = encrypt_message(alice_bob_key, message_to_bob)
        
        # Bob puede descifrar
        bob_alice_key = derive_shared_key(bob_private, alice_public)
        assert decrypt_message(bob_alice_key, ct_bob, nonce_bob).decode('utf-8') == message_to_bob
        
        # Charlie NO puede descifrar el mensaje de Alice a Bob
        charlie_alice_key = derive_shared_key(charlie_private, alice_public)
        with pytest.raises(ValueError):
            decrypt_message(charlie_alice_key, ct_bob, nonce_bob)
        
        # Alice se comunica con Charlie
        alice_charlie_key = derive_shared_key(alice_private, charlie_public)
        message_to_charlie = "Mensaje para Charlie"
        ct_charlie, nonce_charlie = encrypt_message(alice_charlie_key, message_to_charlie)
        
        # Charlie puede descifrar
        charlie_alice_key = derive_shared_key(charlie_private, alice_public)
        assert decrypt_message(charlie_alice_key, ct_charlie, nonce_charlie).decode('utf-8') == message_to_charlie


class TestErrorHandling:
    """Tests para manejo de errores."""
    
    def test_invalid_key_size_encrypt(self):
        """Test que encrypt_message rechaza claves de tamaño incorrecto."""
        invalid_key = b"clave_muy_corta"
        
        with pytest.raises(ValueError, match="debe tener 32 bytes"):
            encrypt_message(invalid_key, "mensaje")
    
    def test_invalid_key_size_decrypt(self):
        """Test que decrypt_message rechaza claves de tamaño incorrecto."""
        invalid_key = b"clave_muy_corta"
        
        with pytest.raises(ValueError, match="debe tener 32 bytes"):
            decrypt_message(invalid_key, "Y2lwaGVydGV4dA==", "bm9uY2U=")
    
    def test_invalid_nonce_size(self):
        """Test que decrypt_message rechaza nonces de tamaño incorrecto."""
        alice_private, alice_public = generate_user_keypair()
        bob_private, bob_public = generate_user_keypair()
        shared_key = derive_shared_key(alice_private, bob_public)
        
        import base64
        invalid_nonce = base64.b64encode(b"short").decode('utf-8')
        
        with pytest.raises(ValueError, match="nonce debe tener"):
            decrypt_message(shared_key, "Y2lwaGVydGV4dA==", invalid_nonce)


if __name__ == "__main__":
    # Ejecutar tests con pytest
    pytest.main([__file__, "-v"])
