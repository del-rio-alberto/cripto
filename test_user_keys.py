"""
Tests para el módulo de gestión de claves de usuario.

Verifica:
- Generación de pares de claves EC P-256
- Cifrado y descifrado de claves privadas
- Integración con base de datos
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from user_keys import (
    generate_user_keypair,
    encrypt_private_key,
    decrypt_private_key,
    get_public_key_pem,
    _serialize_private_key,
    _deserialize_private_key
)


def test_generate_keypair():
    """Verifica que se genera correctamente un par de claves EC P-256."""
    private_key, public_key = generate_user_keypair()
    
    # Verificar que son objetos de clave válidos
    assert private_key is not None
    assert public_key is not None
    
    # Verificar que es EC P-256
    assert isinstance(private_key.curve, ec.SECP256R1)
    
    # Verificar que la clave pública corresponde a la privada
    derived_public_key = private_key.public_key()
    assert derived_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) == public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    print("✓ Test de generación de keypair exitoso")


def test_encrypt_decrypt_private_key():
    """Verifica el cifrado y descifrado de claves privadas."""
    # Generar un par de claves
    private_key, _ = generate_user_keypair()
    password = "mi_contraseña_segura_123"
    
    # Cifrar la clave privada
    encrypted_blob = encrypt_private_key(private_key, password)
    
    # Verificar que el blob cifrado es un string JSON
    assert isinstance(encrypted_blob, str)
    assert "salt" in encrypted_blob
    assert "nonce" in encrypted_blob
    assert "ciphertext" in encrypted_blob
    
    # Descifrar la clave privada
    decrypted_key = decrypt_private_key(encrypted_blob, password)
    
    # Verificar que la clave descifrada es la misma
    original_pem = _serialize_private_key(private_key)
    decrypted_pem = _serialize_private_key(decrypted_key)
    
    assert original_pem == decrypted_pem
    
    print("✓ Test de cifrado/descifrado exitoso")


def test_decrypt_with_wrong_password():
    """Verifica que falla el descifrado con contraseña incorrecta."""
    private_key, _ = generate_user_keypair()
    password = "contraseña_correcta"
    wrong_password = "contraseña_incorrecta"
    
    # Cifrar con la contraseña correcta
    encrypted_blob = encrypt_private_key(private_key, password)
    
    # Intentar descifrar con contraseña incorrecta
    try:
        decrypt_private_key(encrypted_blob, wrong_password)
        # Si no lanza excepción, el test falla
        raise AssertionError("Debería haber lanzado ValueError con contraseña incorrecta")
    except ValueError:
        # Comportamiento esperado
        pass
    
    print("✓ Test de contraseña incorrecta exitoso")


def test_get_public_key_pem():
    """Verifica la obtención de clave pública en formato PEM."""
    private_key, _ = generate_user_keypair()
    
    public_key_pem = get_public_key_pem(private_key)
    
    # Verificar que es un string PEM válido
    assert isinstance(public_key_pem, str)
    assert "BEGIN PUBLIC KEY" in public_key_pem
    assert "END PUBLIC KEY" in public_key_pem
    
    print("✓ Test de obtención de clave pública exitoso")


def test_integration_with_database():
    """Verifica la integración con la base de datos."""
    from data_access import (
        init_database,
        create_user,
        store_user_keypair,
        get_user_encrypted_private_key,
        get_user_public_key,
        reset_database
    )
    from utils import hash_password, generate_salt, derive_key_from_password
    
    # Resetear base de datos
    reset_database()
    
    # Crear usuario
    username = "test_user"
    password = "test_password_123"
    password_hash = hash_password(password)
    salt = generate_salt()
    encryption_key = derive_key_from_password(password, salt)
    
    create_user(username, password_hash, salt, encryption_key)
    
    # Generar keypair
    private_key, _ = generate_user_keypair()
    encrypted_private_key = encrypt_private_key(private_key, password)
    public_key_pem = get_public_key_pem(private_key)
    
    # Guardar en BD
    store_user_keypair(username, encrypted_private_key, public_key_pem)
    
    # Recuperar de BD
    retrieved_encrypted = get_user_encrypted_private_key(username)
    retrieved_public = get_user_public_key(username)
    
    # Verificar que se guardó correctamente
    assert retrieved_encrypted == encrypted_private_key
    assert retrieved_public == public_key_pem
    
    # Descifrar y verificar
    decrypted_key = decrypt_private_key(retrieved_encrypted, password)
    original_pem = _serialize_private_key(private_key)
    decrypted_pem = _serialize_private_key(decrypted_key)
    
    assert original_pem == decrypted_pem
    
    print("✓ Test de integración con BD exitoso")


if __name__ == "__main__":
    print("Ejecutando tests de user_keys...\n")
    
    test_generate_keypair()
    test_encrypt_decrypt_private_key()
    test_decrypt_with_wrong_password()
    test_get_public_key_pem()
    test_integration_with_database()
    
    print("\n✓ Todos los tests pasaron exitosamente!")
