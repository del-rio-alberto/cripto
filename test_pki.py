
import unittest
import os
import pki
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

class TestPKI(unittest.TestCase):
    def setUp(self):
        # Limpieza antes de los tests
        self.files = [
            "root_ca.key", "root_ca.crt",
            "intermediate_ca.key", "intermediate_ca.csr", "intermediate_ca.crt",
            "intermediate_ca.crl"
        ]
        for f in self.files:
            if os.path.exists(f):
                os.remove(f)

    def tearDown(self):
        # Limpieza después de los tests
        for f in self.files:
            if os.path.exists(f):
                os.remove(f)

    def test_pki_generation(self):
        pki.setup_pki()
        
        # Verificar si los archivos existen
        for f in self.files:
            self.assertTrue(os.path.exists(f), f"Archivo {f} no encontrado")
            
        # Verificar CA Raíz
        root_cert = pki.load_certificate("root_ca.crt")
        self.assertEqual(root_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, "Root CA")
        self.assertEqual(root_cert.issuer, root_cert.subject) # Autofirmado
        
        # Verificar CA Intermedia
        inter_cert = pki.load_certificate("intermediate_ca.crt")
        self.assertEqual(inter_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, "Intermediate CA")
        self.assertEqual(inter_cert.issuer, root_cert.subject) # Firmado por Root
        
        # Verificar Cadena
        root_key = pki.load_private_key("root_ca.key")
        root_public_key = root_key.public_key()
        
        try:
            root_public_key.verify(
                inter_cert.signature,
                inter_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                inter_cert.signature_hash_algorithm,
            )
        except Exception as e:
            self.fail(f"Verificación de certificado fallida: {e}")

if __name__ == '__main__':
    unittest.main()
