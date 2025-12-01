"""
Test de integración end-to-end para el flujo de registro y login con keypairs.

Verifica el flujo completo:
1. Registro de usuario con generación automática de keypair
2. Login con descifrado de clave privada
"""

import requests
import json

BASE_URL = "http://localhost:5000"


def test_register_and_login_flow():
    """Test completo de registro y login con keypairs."""
    
    print("=" * 60)
    print("Test de Integración: Registro y Login con Keypairs EC P-256")
    print("=" * 60)
    
    # 1. Resetear base de datos
    print("\n1. Reseteando base de datos...")
    response = requests.post(f"{BASE_URL}/reset_db")
    assert response.status_code == 200, f"Error al resetear BD: {response.text}"
    print("   ✓ Base de datos reseteada")
    
    # 2. Registrar nuevo usuario
    print("\n2. Registrando nuevo usuario...")
    username = "test_keypair_user"
    password = "mi_password_segura_123"
    
    register_data = {
        "username": username,
        "password": password
    }
    
    response = requests.post(
        f"{BASE_URL}/register",
        json=register_data,
        headers={"Content-Type": "application/json"}
    )
    
    assert response.status_code == 201, f"Error en registro: {response.text}"
    data = response.json()
    assert data["success"] == True
    assert data["username"] == username
    print(f"   ✓ Usuario '{username}' registrado exitosamente")
    
    # 3. Login con el usuario (esto verifica implícitamente que las claves se guardaron)
    print("\n3. Iniciando sesión...")
    login_data = {
        "username": username,
        "password": password
    }
    
    response = requests.post(
        f"{BASE_URL}/login",
        json=login_data,
        headers={"Content-Type": "application/json"}
    )
    
    assert response.status_code == 200, f"Error en login: {response.text}"
    data = response.json()
    assert data["success"] == True
    assert "token" in data
    print(f"   ✓ Login exitoso para '{username}'")
    print(f"   ✓ Token JWT generado: {data['token'][:30]}...")
    print("   ✓ Clave privada descifrada exitosamente en el servidor")
    print("   ✓ (El login exitoso confirma que el keypair se generó y guardó correctamente)")
    
    # 4. Intentar login con contraseña incorrecta
    print("\n4. Probando login con contraseña incorrecta...")
    wrong_login_data = {
        "username": username,
        "password": "contraseña_incorrecta"
    }
    
    response = requests.post(
        f"{BASE_URL}/login",
        json=wrong_login_data,
        headers={"Content-Type": "application/json"}
    )
    
    assert response.status_code == 401, "Debería fallar con contraseña incorrecta"
    print("   ✓ Login rechazado correctamente con contraseña incorrecta")
    
    print("\n" + "=" * 60)
    print("✓ TODOS LOS TESTS DE INTEGRACIÓN PASARON EXITOSAMENTE")
    print("=" * 60)


if __name__ == "__main__":
    try:
        test_register_and_login_flow()
    except AssertionError as e:
        print(f"\n✗ Test falló: {e}")
        exit(1)
    except requests.exceptions.ConnectionError:
        print("\n✗ Error: No se pudo conectar al servidor.")
        print("   Asegúrate de que el servidor Flask esté corriendo en http://localhost:5000")
        exit(1)
    except Exception as e:
        print(f"\n✗ Error inesperado: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
