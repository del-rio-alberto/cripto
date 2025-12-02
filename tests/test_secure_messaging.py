"""
Test 6: Envío y recepción completa del flujo híbrido.

Prueba el flujo completo de mensajería segura con firma, ECDH, y cifrado AES-GCM.
"""

import os
import pytest
from secure_messaging import send_secure_message, receive_secure_message
from user_keys import generate_user_keypair
from pki import setup_pki, issue_certificate, generate_csr
from cryptography.hazmat.primitives import serialization


class TestSecureMessaging:
    """Test 6: Flujo completo de mensajería segura."""
    
    def create_user_with_cert(self, username, temp_dir):
        """
        Helper: Crea un usuario con claves y certificado.
        
        Returns:
            dict: private_key (objeto), cert_pem (bytes)
        """
        # Generar claves
        private_key, public_key = generate_user_keypair()
        
        # Generar CSR y emitir certificado
        csr_pem = generate_csr(private_key, username)
        cert_pem = issue_certificate(username, csr_pem.public_bytes(serialization.Encoding.PEM))
        
        return {
            'private_key': private_key,
            'cert_pem': cert_pem
        }
    
    def test_send_and_receive_secure_message(self, temp_dir):
        """
        Test completo: Alice envía un mensaje a Bob y Bob lo recibe correctamente.
        """
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            # Configurar PKI
            setup_pki()
            
            # Crear usuarios
            alice = self.create_user_with_cert("alice", temp_dir)
            bob = self.create_user_with_cert("bob", temp_dir)
            
            # Mensaje de prueba
            message_text = "Hola Bob, este es un mensaje secreto de Alice."
            
            # Alice envía el mensaje
            sender = {'private_key': alice['private_key'], 'cert': alice['cert_pem']}
            payload = send_secure_message(sender, bob['cert_pem'], message_text)
            
            # Verificar campos del payload
            assert 'ciphertext' in payload
            assert 'nonce' in payload
            assert 'signature' in payload
            assert 'cert_emisor' in payload
            assert 'pubkey_efimera' in payload
            
            # Bob recibe el mensaje
            receiver = {'private_key': bob['private_key'], 'cert': bob['cert_pem']}
            decrypted_message = receive_secure_message(receiver, payload)
            
            # Verificar
            assert decrypted_message == message_text
            
        finally:
            os.chdir(original_dir)
    
    def test_tampered_message_fails(self, temp_dir):
        """
        Verificar que un mensaje modificado no se descifra correctamente.
        """
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            setup_pki()
            
            alice = self.create_user_with_cert("alice", temp_dir)
            bob = self.create_user_with_cert("bob", temp_dir)
            
            message_text = "Mensaje original"
            
            # Enviar
            sender = {'private_key': alice['private_key'], 'cert': alice['cert_pem']}
            payload = send_secure_message(sender, bob['cert_pem'], message_text)
            
            # Modificar el ciphertext
            payload['ciphertext'] = payload['ciphertext'][:-1] + ('A' if payload['ciphertext'][-1] != 'A' else 'B')
            
            # Intentar descifrar - debe fallar
            receiver = {'private_key': bob['private_key'], 'cert': bob['cert_pem']}
            with pytest.raises(ValueError):
                receive_secure_message(receiver, payload)
            
        finally:
            os.chdir(original_dir)
    
    def test_invalid_signature_fails(self, temp_dir):
        """
        Verificar que un mensaje con firma inválida no se acepta.
        """
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            setup_pki()
            
            alice = self.create_user_with_cert("alice", temp_dir)
            bob = self.create_user_with_cert("bob", temp_dir)
            
            message_text = "Mensaje con firma"
            
            # Enviar
            sender = {'private_key': alice['private_key'], 'cert': alice['cert_pem']}
            payload = send_secure_message(sender, bob['cert_pem'], message_text)
            
            # Modificar la firma
            payload['signature'] = "SGVsbG9Xb3JsZElzSW52YWxpZFNpZ25hdHVyZQ=="
            
            # Intentar descifrar - debe fallar
            receiver = {'private_key': bob['private_key'], 'cert': bob['cert_pem']}
            with pytest.raises(ValueError):
                receive_secure_message(receiver, payload)
            
        finally:
            os.chdir(original_dir)
    
    def test_bidirectional_communication(self, temp_dir):
        """
        Verificar que la comunicación funciona en ambas direcciones.
        """
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            setup_pki()
            
            alice = self.create_user_with_cert("alice", temp_dir)
            bob = self.create_user_with_cert("bob", temp_dir)
            
            # Alice -> Bob
            msg1 = "Hola Bob"
            sender1 = {'private_key': alice['private_key'], 'cert': alice['cert_pem']}
            payload1 = send_secure_message(sender1, bob['cert_pem'], msg1)
            receiver1 = {'private_key': bob['private_key'], 'cert': bob['cert_pem']}
            decrypted1 = receive_secure_message(receiver1, payload1)
            assert decrypted1 == msg1
            
            # Bob -> Alice
            msg2 = "Hola Alice"
            sender2 = {'private_key': bob['private_key'], 'cert': bob['cert_pem']}
            payload2 = send_secure_message(sender2, alice['cert_pem'], msg2)
            receiver2 = {'private_key': alice['private_key'], 'cert': alice['cert_pem']}
            decrypted2 = receive_secure_message(receiver2, payload2)
            assert decrypted2 == msg2
            
        finally:
            os.chdir(original_dir)
    
    def test_long_message(self, temp_dir):
        """
        Verificar que se pueden enviar mensajes largos.
        """
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            setup_pki()
            
            alice = self.create_user_with_cert("alice", temp_dir)
            bob = self.create_user_with_cert("bob", temp_dir)
            
            # Mensaje largo
            long_message = "A" * 5000
            
            sender = {'private_key': alice['private_key'], 'cert': alice['cert_pem']}
            payload = send_secure_message(sender, bob['cert_pem'], long_message)
            
            receiver = {'private_key': bob['private_key'], 'cert': bob['cert_pem']}
            decrypted = receive_secure_message(receiver, payload)
            
            assert decrypted == long_message
            
        finally:
            os.chdir(original_dir)
