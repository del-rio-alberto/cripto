#!/usr/bin/env python3
"""
Tests para los endpoints de gestión de certificados.
Verifica la emisión, revocación y obtención de CRL.
"""

import unittest
import os
import sys
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Importar módulos del proyecto
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
import pki


class TestCertRoutes(unittest.TestCase):
    """Tests para los endpoints de certificados."""
    
    @classmethod
    def setUpClass(cls):
        """Configuración inicial para todos los tests."""
        # Asegurar que PKI está configurada
        if not os.path.exists("intermediate_ca.key"):
            pki.setup_pki()
    
    def setUp(self):
        """Configuración antes de cada test."""
        self.app = app.test_client()
        self.app.testing = True
    
    def test_issue_certificate_endpoint(self):
        """Test de emisión de certificado vía endpoint."""
        username = "test_issue_user"
        
        # 1. Generar clave usuario EC P-256
        user_key = ec.generate_private_key(ec.SECP256R1())
        
        # 2. Generar CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])).sign(user_key, hashes.SHA256())
        
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        csr_pem_b64 = base64.b64encode(csr_pem).decode('utf-8')
        
        # 3. Llamar al endpoint
        response = self.app.post('/cert/issue', json={
            'username': username,
            'csr_pem': csr_pem_b64
        })
        
        # 4. Verificar respuesta
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertIn('certificate_pem', data)
        self.assertEqual(data['username'], username)
        
        # 5. Verificar que el certificado es válido
        cert_pem = base64.b64decode(data['certificate_pem'])
        cert = x509.load_pem_x509_certificate(cert_pem)
        
        # Verificar Subject
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, username)
        
        # 6. Verificar que el archivo fue creado
        self.assertTrue(os.path.exists(f"certs/{username}.crt"))
        
        print(f"✓ Test de emisión de certificado exitoso para '{username}'")
    
    def test_issue_certificate_missing_data(self):
        """Test de emisión con datos faltantes."""
        # Sin username
        response = self.app.post('/cert/issue', json={
            'csr_pem': 'dummy'
        })
        self.assertEqual(response.status_code, 400)
        
        # Sin CSR
        response = self.app.post('/cert/issue', json={
            'username': 'testuser'
        })
        self.assertEqual(response.status_code, 400)
        
        print("✓ Test de validación de datos faltantes exitoso")
    
    def test_revoke_by_serial(self):
        """Test de revocación por número de serial."""
        username = "test_revoke_serial"
        
        # 1. Emitir un certificado
        user_key = ec.generate_private_key(ec.SECP256R1())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])).sign(user_key, hashes.SHA256())
        
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        cert_pem = pki.issue_certificate(username, csr_pem)
        cert = x509.load_pem_x509_certificate(cert_pem)
        serial = cert.serial_number
        
        # 2. Revocar por serial
        response = self.app.post('/cert/revoke', json={
            'serial': serial
        })
        
        # 3. Verificar respuesta
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['serial'], serial)
        
        # 4. Verificar que está en la CRL
        self.assertTrue(pki.is_revoked(cert_pem))
        
        print(f"✓ Test de revocación por serial exitoso (serial: {serial})")
    
    def test_revoke_by_username(self):
        """Test de revocación por username."""
        username = "test_revoke_username"
        
        # 1. Emitir un certificado
        user_key = ec.generate_private_key(ec.SECP256R1())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])).sign(user_key, hashes.SHA256())
        
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        cert_pem = pki.issue_certificate(username, csr_pem)
        
        # 2. Revocar por username
        response = self.app.post('/cert/revoke', json={
            'username': username
        })
        
        # 3. Verificar respuesta
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertIn('serial', data)
        
        # 4. Verificar que está en la CRL
        self.assertTrue(pki.is_revoked(cert_pem))
        
        print(f"✓ Test de revocación por username exitoso ('{username}')")
    
    def test_revoke_nonexistent_username(self):
        """Test de revocación con username inexistente."""
        response = self.app.post('/cert/revoke', json={
            'username': 'nonexistent_user_12345'
        })
        
        # Debe devolver 404
        self.assertEqual(response.status_code, 404)
        
        print("✓ Test de revocación de usuario inexistente exitoso")
    
    def test_revoke_missing_data(self):
        """Test de revocación sin datos."""
        response = self.app.post('/cert/revoke', json={})
        
        # Debe devolver 400
        self.assertEqual(response.status_code, 400)
        
        print("✓ Test de validación de datos faltantes en revocación exitoso")
    
    def test_get_crl(self):
        """Test de obtención de CRL."""
        # 1. Llamar al endpoint
        response = self.app.get('/cert/crl')
        
        # 2. Verificar respuesta
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertIn('crl_pem', data)
        
        # 3. Verificar que la CRL es válida
        crl_pem = base64.b64decode(data['crl_pem'])
        crl = x509.load_pem_x509_crl(crl_pem)
        
        # Verificar que es un objeto CRL válido
        self.assertIsNotNone(crl.last_update)
        self.assertIsNotNone(crl.next_update)
        
        print("✓ Test de obtención de CRL exitoso")
    
    def test_full_workflow(self):
        """Test del flujo completo: emitir, verificar, revocar, verificar CRL."""
        username = "test_workflow_user"
        
        # 1. Generar clave y CSR
        user_key = ec.generate_private_key(ec.SECP256R1())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])).sign(user_key, hashes.SHA256())
        
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        csr_pem_b64 = base64.b64encode(csr_pem).decode('utf-8')
        
        # 2. Emitir certificado
        response = self.app.post('/cert/issue', json={
            'username': username,
            'csr_pem': csr_pem_b64
        })
        self.assertEqual(response.status_code, 200)
        cert_pem_b64 = response.get_json()['certificate_pem']
        cert_pem = base64.b64decode(cert_pem_b64)
        
        # 3. Verificar que NO está revocado
        self.assertFalse(pki.is_revoked(cert_pem))
        
        # 4. Revocar certificado
        response = self.app.post('/cert/revoke', json={
            'username': username
        })
        self.assertEqual(response.status_code, 200)
        
        # 5. Verificar que SÍ está revocado
        self.assertTrue(pki.is_revoked(cert_pem))
        
        # 6. Obtener CRL y verificar
        response = self.app.get('/cert/crl')
        self.assertEqual(response.status_code, 200)
        crl_pem = base64.b64decode(response.get_json()['crl_pem'])
        crl = x509.load_pem_x509_crl(crl_pem)
        
        # Verificar que el certificado está en la CRL
        cert = x509.load_pem_x509_certificate(cert_pem)
        revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        self.assertIsNotNone(revoked)
        
        print(f"✓ Test de flujo completo exitoso para '{username}'")


if __name__ == '__main__':
    print("=== Tests de Endpoints de Certificados ===\n")
    unittest.main(verbosity=2)
