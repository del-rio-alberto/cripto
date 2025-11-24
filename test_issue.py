import unittest
import os
import pki
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

class TestIssueCertificate(unittest.TestCase):
    def setUp(self):
        # Asegurar que PKI está configurada
        if not os.path.exists("intermediate_ca.key"):
            pki.setup_pki()
            
    def test_issue_certificate_success(self):
        username = "testuser"
        
        # 1. Generar clave usuario EC P-256
        user_key = ec.generate_private_key(ec.SECP256R1())
        
        # 2. Generar CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])).sign(user_key, hashes.SHA256())
        
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        
        # 3. Emitir certificado
        cert_pem = pki.issue_certificate(username, csr_pem)
        
        # 4. Verificar certificado
        cert = x509.load_pem_x509_certificate(cert_pem)
        
        # Verificar Subject
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, username)
        
        # Verificar Issuer (debe ser Intermediate CA)
        inter_cert = pki.load_certificate("intermediate_ca.crt")
        self.assertEqual(cert.issuer, inter_cert.subject)
        
        # Verificar Extensiones
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertFalse(bc.ca)
        
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.digital_signature)
        self.assertTrue(ku.key_encipherment)
        
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(x509.ExtendedKeyUsageOID.CLIENT_AUTH, eku)
        
        # Verificar archivo creado
        self.assertTrue(os.path.exists(f"certs/{username}.crt"))
        
        # Verificar log
        with open("issued_certs.log", "r") as f:
            content = f.read()
            self.assertIn(username, content)
            self.assertIn("Valid", content)

    def test_invalid_key_type(self):
        # Intentar con clave RSA (debería fallar)
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "baduser"),
        ])).sign(key, hashes.SHA256())
        
        with self.assertRaises(ValueError) as cm:
            pki.issue_certificate("baduser", csr.public_bytes(serialization.Encoding.PEM))
        self.assertIn("Curva Elíptica", str(cm.exception))

if __name__ == '__main__':
    unittest.main()
