"""
Test 4-5: Emisión de certificados y revocación con CRL.

Prueba la emisión de certificados por la CA intermedia y la revocación.
"""

import os
import pytest
from pki import issue_certificate, revoke_certificate, is_revoked, generate_csr
from user_keys import generate_user_keypair
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class TestCertificateIssuance:
    """Test 4: Emisión de certificados."""
    
    def test_issue_certificate_basic(self, temp_dir):
        """
        Test básico: Emitir un certificado para un usuario.
        """
        # Cambiar al directorio temporal
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            # Configurar PKI
            from pki import setup_pki
            setup_pki()
            
            # Generar par de claves para el usuario
            private_key, public_key = generate_user_keypair()
            
            # Generar CSR directamente con el objeto de clave
            csr_pem = generate_csr(private_key, "testuser")
            
            # Emitir certificado
            cert_pem = issue_certificate("testuser", csr_pem.public_bytes(serialization.Encoding.PEM))
            
            # Verificar que se obtuvo un certificado
            assert cert_pem is not None
            assert isinstance(cert_pem, bytes)
            
            # Cargar y verificar el certificado
            cert = x509.load_pem_x509_certificate(cert_pem)
            
            # Verificar que el CN es correcto
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
            assert cn == "testuser"
            
            # Verificar que el certificado está firmado (tiene número de serie)
            assert cert.serial_number > 0
            
        finally:
            os.chdir(original_dir)
    
    def test_issue_certificate_for_multiple_users(self, temp_dir):
        """
        Verificar que se pueden emitir certificados para múltiples usuarios.
        """
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            from pki import setup_pki
            setup_pki()
            
            users = ["alice", "bob", "charlie"]
            certificates = []
            
            for username in users:
                # Generar claves y CSR
                private_key, _ = generate_user_keypair()
                csr_pem = generate_csr(private_key, username)
                
                # Emitir certificado
                cert_pem = issue_certificate(username, csr_pem.public_bytes(serialization.Encoding.PEM))
                certificates.append(cert_pem)
                
                # Verificar CN
                cert = x509.load_pem_x509_certificate(cert_pem)
                cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
                assert cn == username
            
            # Verificar que todos los certificados son diferentes
            assert len(set(certificates)) == len(users)
            
        finally:
            os.chdir(original_dir)


class TestCertificateRevocation:
    """Test 5: Revocación y verificación con CRL."""
    
    def test_revoke_certificate(self, temp_dir):
        """
        Test básico: Revocar un certificado y verificar que aparece en la CRL.
        """
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            from pki import setup_pki
            setup_pki()
            
            # Emitir un certificado
            private_key, _ = generate_user_keypair()
            csr_pem = generate_csr(private_key, "revoketest")
            cert_pem = issue_certificate("revoketest", csr_pem.public_bytes(serialization.Encoding.PEM))
            
            # Obtener el serial number
            cert = x509.load_pem_x509_certificate(cert_pem)
            serial = cert.serial_number
            
            # Verificar que NO está revocado inicialmente
            assert is_revoked(cert_pem) is False
            
            # Revocar el certificado
            result = revoke_certificate(serial)
            assert result is True
            
            # Verificar que AHORA está revocado
            assert is_revoked(cert_pem) is True
            
        finally:
            os.chdir(original_dir)
    
    def test_non_revoked_certificate(self, temp_dir):
        """
        Verificar que un certificado no revocado no aparece en la CRL.
        """
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            from pki import setup_pki
            setup_pki()
            
            # Emitir un certificado
            private_key, _ = generate_user_keypair()
            csr_pem = generate_csr(private_key, "validuser")
            cert_pem = issue_certificate("validuser", csr_pem.public_bytes(serialization.Encoding.PEM))
            
            # Verificar que NO está revocado
            assert is_revoked(cert_pem) is False
            
        finally:
            os.chdir(original_dir)
    
    def test_revoke_multiple_certificates(self, temp_dir):
        """
        Verificar que se pueden revocar múltiples certificados.
        """
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            from pki import setup_pki
            setup_pki()
            
            # Emitir varios certificados
            certs = []
            serials = []
            
            for i in range(3):
                private_key, _ = generate_user_keypair()
                csr_pem = generate_csr(private_key, f"user{i}")
                cert_pem = issue_certificate(f"user{i}", csr_pem.public_bytes(serialization.Encoding.PEM))
                
                cert = x509.load_pem_x509_certificate(cert_pem)
                certs.append(cert_pem)
                serials.append(cert.serial_number)
            
            # Revocar el primero y el tercero
            revoke_certificate(serials[0])
            revoke_certificate(serials[2])
            
            # Verificar estado
            assert is_revoked(certs[0]) is True
            assert is_revoked(certs[1]) is False
            assert is_revoked(certs[2]) is True
            
        finally:
            os.chdir(original_dir)
    
    def test_revoke_invalid_serial(self, temp_dir):
        """
        Verificar el comportamiento al intentar revocar un serial inexistente.
        """
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            from pki import setup_pki
            setup_pki()
            
            # Intentar revocar un serial que no existe
            invalid_serial = 999999
            
            # Esto no debería lanzar excepción, pero podría retornar False o True
            # dependiendo de la implementación
            result = revoke_certificate(invalid_serial)
            
            # Simplemente verificar que no lanza excepción
            assert result is not None
            
        finally:
            os.chdir(original_dir)
