import requests
import json
import traceback

BASE_URL = "http://localhost:5000"


def test_register():
  """Prueba el registro de un usuario"""
  print("\n" + "="*50)
  print("TEST: REGISTRO DE USUARIO")
  print("="*50)

  response = requests.post(f"{BASE_URL}/register", json={
      "username": "pedro",
      "password": "password123"
  })

  print(f"Status: {response.status_code}")
  print(f"Response:\n{json.dumps(response.json(), indent=2)}")

  if response.status_code == 201:
    print("Registro exitoso")
  else:
    print("Error en registro")

  return response.status_code == 201


def test_login():
  """Prueba el login y obtención de token"""
  print("\n" + "="*50)
  print("TEST: LOGIN")
  print("="*50)

  response = requests.post(f"{BASE_URL}/login", json={
      "username": "pedro",
      "password": "password123"
  })

  print(f"Status: {response.status_code}")
  data = response.json()
  print(f"Response:\n{json.dumps(data, indent=2)}")

  if response.status_code == 200 and 'token' in data:
    print("Login exitoso")
    return data['token']
  else:
    print("Error en login")
    return None


def test_encrypt_decrypt(token):
  """Prueba cifrado y descifrado"""
  print("\n" + "="*50)
  print("TEST: CIFRADO")
  print("="*50)

  plaintext_original = "Este es un mensaje secreto"
  headers = {"Authorization": f"Bearer {token}"}

  # CIFRAR
  response = requests.post(f"{BASE_URL}/encrypt",
                           json={"plaintext": plaintext_original},
                           headers=headers)

  print(f"Status: {response.status_code}")
  encrypted_data = response.json()
  print(f"Cifrado:\n{json.dumps(encrypted_data, indent=2)}")

  if response.status_code != 200:
    print("Error en cifrado")
    return False

  print("Cifrado exitoso")

  # DESCIFRAR
  print("\n" + "="*50)
  print("TEST: DESCIFRADO")
  print("="*50)

  response = requests.post(f"{BASE_URL}/decrypt",
                           json={
                               "ciphertext": encrypted_data['ciphertext'],
                               "nonce": encrypted_data['nonce'],
                               "tag": encrypted_data['tag']
                           },
                           headers=headers)

  print(f"Status: {response.status_code}")
  decrypted_data = response.json()
  print(f"Descifrado:\n{json.dumps(decrypted_data, indent=2)}")

  if response.status_code != 200:
    print("Error en descifrado")
    return False

  # Verificar que el texto coincide
  plaintext_decrypted = decrypted_data.get('plaintext')

  print(f"\nTexto original:  '{plaintext_original}'")
  print(f"Texto descifrado: '{plaintext_decrypted}'")

  if plaintext_decrypted == plaintext_original:
    print("CIFRADO/DESCIFRADO CORRECTO - Los textos coinciden")
    return True
  else:
    print("ERROR - Los textos NO coinciden")
    return False


def run_all_tests():
  """Ejecuta todas las pruebas en secuencia"""

  try:
    # Test 1: Registro
    if not test_register():
      print("\nDeteniendo pruebas, error en registro")
      return

    # Test 2: Login
    token = test_login()
    if not token:
      print("\nDeteniendo pruebas, error en el login")
      return

    # Test 3 y 4: Cifrado y Descifrado
    test_encrypt_decrypt(token)

    print("\n" + "="*50)
    print("TODAS LAS PRUEBAS COMPLETADAS")
    print("="*50)

  except requests.exceptions.ConnectionError:
    print("\nERROR: No se pudo conectar al servidor")
    print("Ejecuta primero: python app.py")
  except Exception as e:
    print(f"\nERROR INESPERADO: {str(e)}")
    traceback.print_exc()


if __name__ == "__main__":
  run_all_tests()
