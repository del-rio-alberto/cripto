"""
Test 2-3: ECDH entre dos pares de claves y cifrado/descifrado AES-GCM.

Prueba el intercambio de claves ECDH y el cifrado híbrido.
"""

import pytest
from hybrid_encryption import derive_shared_key, encrypt_message, decrypt_message
from cryptography.hazmat.primitives import serialization


class TestECDH:
    """Test 2: ECDH entre dos pares de claves."""
    
    def test_ecdh_key_derivation(self, two_keypairs):
        """
        Verificar que ECDH deriva la misma clave compartida
        desde ambos lados de la comunicación.
        """
        (alice_priv, alice_pub), (bob_priv, bob_pub) = two_keypairs
        
        # Alice deriva la clave compartida usando su clave privada y la pública de Bob
        shared_key_alice = derive_shared_key(alice_priv, bob_pub)
        
        # Bob deriva la clave compartida usando su clave privada y la pública de Alice
        shared_key_bob = derive_shared_key(bob_priv, alice_pub)
        
        # Ambas claves deben ser iguales
        assert shared_key_alice == shared_key_bob
        
        # Verificar que la clave tiene el tamaño correcto (32 bytes para AES-256)
        assert len(shared_key_alice) == 32
        assert len(shared_key_bob) == 32
    
    def test_ecdh_different_keypairs_different_keys(self):
        """
        Verificar que pares de claves diferentes generan
        claves compartidas diferentes.
        """
        from user_keys import generate_user_keypair
        from cryptography.hazmat.primitives import serialization
        
        # Generar tres pares de claves
        alice_priv_obj, alice_pub_obj = generate_user_keypair()
        bob_priv_obj, bob_pub_obj = generate_user_keypair()
        charlie_priv_obj, charlie_pub_obj = generate_user_keypair()
        
        # Serializar a PEM
        alice_priv = alice_priv_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        alice_pub = alice_pub_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        bob_priv = bob_priv_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        bob_pub = bob_pub_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        charlie_priv = charlie_priv_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        charlie_pub = charlie_pub_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Alice-Bob
        shared_alice_bob = derive_shared_key(alice_priv, bob_pub)
        
        # Alice-Charlie
        shared_alice_charlie = derive_shared_key(alice_priv, charlie_pub)
        
        # Las claves compartidas deben ser diferentes
        assert shared_alice_bob != shared_alice_charlie
    
    def test_ecdh_with_pem_strings(self, two_keypairs):
        """Verificar que ECDH funciona con claves en formato PEM string."""
        (alice_priv, alice_pub), (bob_priv, bob_pub) = two_keypairs
        
        # Derivar con PEM strings
        shared_key = derive_shared_key(alice_priv, bob_pub)
        
        assert len(shared_key) == 32


class TestAESGCM:
    """Test 3: Cifrado y descifrado AES-GCM."""
    
    def test_encrypt_decrypt_message(self, two_keypairs):
        """
        Test básico: Cifrar un mensaje y descifrarlo correctamente.
        """
        (alice_priv, alice_pub), (bob_priv, bob_pub) = two_keypairs
        
        # Derivar clave compartida
        shared_key = derive_shared_key(alice_priv, bob_pub)
        
        # Mensaje de prueba
        plaintext = "Este es un mensaje secreto de prueba"
        
        # Cifrar
        ciphertext_b64, nonce_b64 = encrypt_message(shared_key, plaintext)
        
        # Verificar que se obtienen cadenas base64
        assert isinstance(ciphertext_b64, str)
        assert isinstance(nonce_b64, str)
        assert len(ciphertext_b64) > 0
        assert len(nonce_b64) > 0
        
        # Descifrar
        decrypted = decrypt_message(shared_key, ciphertext_b64, nonce_b64)
        
        # Verificar que el mensaje descifrado es correcto
        assert decrypted.decode('utf-8') == plaintext
    
    def test_encrypt_with_bytes(self, two_keypairs):
        """Verificar que el cifrado funciona con bytes."""
        (alice_priv, alice_pub), (bob_priv, bob_pub) = two_keypairs
        
        shared_key = derive_shared_key(alice_priv, bob_pub)
        
        plaintext = b"Mensaje en bytes"
        
        ciphertext_b64, nonce_b64 = encrypt_message(shared_key, plaintext)
        decrypted = decrypt_message(shared_key, ciphertext_b64, nonce_b64)
        
        assert decrypted == plaintext
    
    def test_decrypt_with_wrong_key_fails(self, two_keypairs):
        """
        Verificar que descifrar con una clave incorrecta falla.
        """
        (alice_priv, alice_pub), (bob_priv, bob_pub) = two_keypairs
        
        # Usar clave de Alice para cifrar
        shared_key_alice = derive_shared_key(alice_priv, bob_pub)
        
        plaintext = "Mensaje secreto"
        ciphertext_b64, nonce_b64 = encrypt_message(shared_key_alice, plaintext)
        
        # Intentar descifrar con una clave diferente
        from user_keys import generate_user_keypair
        from cryptography.hazmat.primitives import serialization
        
        charlie_priv_obj, charlie_pub_obj = generate_user_keypair()
        charlie_priv = charlie_priv_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        charlie_pub = charlie_pub_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        wrong_key = derive_shared_key(charlie_priv, bob_pub)
        
        # El descifrado debe fallar
        with pytest.raises(ValueError):
            decrypt_message(wrong_key, ciphertext_b64, nonce_b64)
    
    def test_decrypt_with_tampered_ciphertext_fails(self, two_keypairs):
        """
        Verificar que descifrar un ciphertext modificado falla
        (integridad de AES-GCM).
        """
        (alice_priv, alice_pub), (bob_priv, bob_pub) = two_keypairs
        
        shared_key = derive_shared_key(alice_priv, bob_pub)
        
        plaintext = "Mensaje original"
        ciphertext_b64, nonce_b64 = encrypt_message(shared_key, plaintext)
        
        # Modificar el ciphertext (cambiar un carácter)
        tampered_ciphertext = ciphertext_b64[:-1] + ('A' if ciphertext_b64[-1] != 'A' else 'B')
        
        # El descifrado debe fallar por falta de integridad
        with pytest.raises(ValueError):
            decrypt_message(shared_key, tampered_ciphertext, nonce_b64)
    
    def test_encrypt_empty_message(self, two_keypairs):
        """Verificar que se puede cifrar un mensaje vacío."""
        (alice_priv, alice_pub), (bob_priv, bob_pub) = two_keypairs
        
        shared_key = derive_shared_key(alice_priv, bob_pub)
        
        plaintext = ""
        ciphertext_b64, nonce_b64 = encrypt_message(shared_key, plaintext)
        decrypted = decrypt_message(shared_key, ciphertext_b64, nonce_b64)
        
        assert decrypted.decode('utf-8') == plaintext
    
    def test_encrypt_long_message(self, two_keypairs):
        """Verificar que se pueden cifrar mensajes largos."""
        (alice_priv, alice_pub), (bob_priv, bob_pub) = two_keypairs
        
        shared_key = derive_shared_key(alice_priv, bob_pub)
        
        # Mensaje largo (1000 caracteres)
        plaintext = "A" * 1000
        
        ciphertext_b64, nonce_b64 = encrypt_message(shared_key, plaintext)
        decrypted = decrypt_message(shared_key, ciphertext_b64, nonce_b64)
        
        assert decrypted.decode('utf-8') == plaintext
