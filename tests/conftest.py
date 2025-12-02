import os
import sys
import tempfile
import shutil
import pytest

# Añadir el directorio padre al path para importar los módulos
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from user_keys import generate_user_keypair
from pki import setup_pki, issue_certificate, generate_csr


@pytest.fixture
def temp_dir():
    """Crea un directorio temporal para las pruebas."""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def user_keypair():
    """Genera un par de claves EC P-256 para pruebas."""
    from cryptography.hazmat.primitives import serialization
    
    private_key, public_key = generate_user_keypair()
    
    # Serializar a PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_key_pem, public_key_pem


@pytest.fixture
def two_keypairs():
    """Genera dos pares de claves EC P-256 para pruebas de ECDH."""
    alice_priv, alice_pub = generate_user_keypair()
    bob_priv, bob_pub = generate_user_keypair()
    return (alice_priv, alice_pub), (bob_priv, bob_pub)


@pytest.fixture(scope="session")
def pki_setup():
    """
    Configura la PKI completa una vez por sesión de tests.
    Asume que setup_pki() crea root_ca y intermediate_ca.
    """
    # Guardar el directorio actual
    original_dir = os.getcwd()
    
    # Cambiar a un directorio temporal para evitar conflictos
    temp_pki_dir = tempfile.mkdtemp()
    os.chdir(temp_pki_dir)
    
    # Configurar PKI
    setup_pki()
    
    # Cargar los archivos generados
    with open('root_ca.crt', 'rb') as f:
        root_cert = f.read()
    with open('intermediate_ca.crt', 'rb') as f:
        intermediate_cert = f.read()
    with open('intermediate_ca.key', 'rb') as f:
        intermediate_key = f.read()
    with open('intermediate_ca.crl', 'rb') as f:
        crl = f.read()
    
    # Volver al directorio original
    os.chdir(original_dir)
    
    yield {
        'root_cert': root_cert,
        'intermediate_cert': intermediate_cert,
        'intermediate_key': intermediate_key,
        'crl': crl,
        'pki_dir': temp_pki_dir
    }
    
    # Limpiar
    shutil.rmtree(temp_pki_dir)
