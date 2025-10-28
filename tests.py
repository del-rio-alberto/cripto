import requests
import json
import time
import traceback
from typing import Optional, Dict

BASE_URL = "http://localhost:5000"

# Colores para consola
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

# Contadores de tests
total_tests = 0
passed_tests = 0
failed_tests = 0

def print_header(title):
    """Imprime un encabezado bonito"""
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{title}{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}")

def print_test(name):
    """Imprime el nombre del test actual"""
    print(f"\n{Colors.YELLOW}▶ {name}{Colors.END}")

def print_success(message):
    """Imprime mensaje de éxito"""
    print(f"{Colors.GREEN}✓ {message}{Colors.END}")

def print_error(message):
    """Imprime mensaje de error"""
    print(f"{Colors.RED}✗ {message}{Colors.END}")

def print_info(message):
    """Imprime información"""
    print(f"{Colors.CYAN}ℹ {message}{Colors.END}")

def assert_test(condition, success_msg, error_msg):
    """Verifica una condición y actualiza contadores"""
    global total_tests, passed_tests, failed_tests
    total_tests += 1
    
    if condition:
        passed_tests += 1
        print_success(success_msg)
        return True
    else:
        failed_tests += 1
        print_error(error_msg)
        return False

def print_json(data):
    """Imprime JSON formateado"""
    print(json.dumps(data, indent=2, ensure_ascii=False))


# ============================================================================
# TESTS DE REGISTRO
# ============================================================================

def test_register_success():
    """Test: Registro exitoso de usuarios"""
    print_header("TESTS DE REGISTRO")
    
    users = [
        {"username": "alice", "password": "AlicePass123!"},
        {"username": "bob", "password": "BobSecure456@"},
        {"username": "charlie", "password": "Charlie789#"}
    ]
    
    tokens = {}
    
    for user in users:
        print_test(f"Registrando usuario: {user['username']}")
        
        response = requests.post(f"{BASE_URL}/register", json=user)
        
        print_info(f"Status: {response.status_code}")
        print_json(response.json())
        
        assert_test(
            response.status_code == 201,
            f"Usuario {user['username']} registrado correctamente",
            f"Error al registrar {user['username']}"
        )
        
        if response.status_code == 201:
            # Hacer login inmediatamente
            login_response = requests.post(f"{BASE_URL}/login", json=user)
            if login_response.status_code == 200:
                tokens[user['username']] = login_response.json()['token']
    
    return tokens


def test_register_failures():
    """Test: Fallos esperados en registro"""
    print_header("TESTS DE FALLOS EN REGISTRO")
    
    # Test 1: Usuario duplicado
    print_test("Intentar registrar usuario duplicado (alice)")
    response = requests.post(f"{BASE_URL}/register", json={
        "username": "alice",
        "password": "OtraPassword123!"
    })
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 409,
        "Correctamente rechazado usuario duplicado (409)",
        "Debería rechazar usuario duplicado"
    )
    
    # Test 2: Contraseña corta
    print_test("Intentar registrar con contraseña muy corta")
    response = requests.post(f"{BASE_URL}/register", json={
        "username": "newuser",
        "password": "123"
    })
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 400,
        "Correctamente rechazada contraseña corta (400)",
        "Debería rechazar contraseña corta"
    )
    
    # Test 3: Datos faltantes
    print_test("Intentar registrar sin contraseña")
    response = requests.post(f"{BASE_URL}/register", json={
        "username": "incomplete"
    })
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 400,
        "Correctamente rechazado registro incompleto (400)",
        "Debería rechazar datos faltantes"
    )


# ============================================================================
# TESTS DE LOGIN
# ============================================================================

def test_login_failures():
    """Test: Fallos esperados en login"""
    print_header("TESTS DE FALLOS EN LOGIN")
    
    # Test 1: Usuario inexistente
    print_test("Intentar login con usuario inexistente")
    response = requests.post(f"{BASE_URL}/login", json={
        "username": "noexiste",
        "password": "Password123!"
    })
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 401,
        "Correctamente rechazado usuario inexistente (401)",
        "Debería rechazar usuario inexistente"
    )
    
    # Test 2: Contraseña incorrecta
    print_test("Intentar login con contraseña incorrecta")
    response = requests.post(f"{BASE_URL}/login", json={
        "username": "alice",
        "password": "PasswordIncorrecta"
    })
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 401,
        "Correctamente rechazada contraseña incorrecta (401)",
        "Debería rechazar contraseña incorrecta"
    )
    
    # Test 3: Datos faltantes
    print_test("Intentar login sin contraseña")
    response = requests.post(f"{BASE_URL}/login", json={
        "username": "alice"
    })
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 400,
        "Correctamente rechazado login incompleto (400)",
        "Debería rechazar datos faltantes"
    )


# ============================================================================
# TESTS DE CIFRADO/DESCIFRADO
# ============================================================================

def test_encrypt_decrypt_success(tokens):
    """Test: Cifrado y descifrado exitoso"""
    print_header("TESTS DE CIFRADO/DESCIFRADO")
    
    token = tokens.get('alice')
    if not token:
        print_error("No hay token de Alice disponible")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    plaintext_original = "Este es un mensaje súper secreto con ñ y emojis 🔒"
    
    # CIFRADO
    print_test("Cifrar mensaje con AES-256-GCM")
    response = requests.post(
        f"{BASE_URL}/encrypt",
        json={"plaintext": plaintext_original},
        headers=headers
    )
    
    print_info(f"Status: {response.status_code}")
    encrypted_data = response.json()
    print_json(encrypted_data)
    
    assert_test(
        response.status_code == 200 and 'ciphertext' in encrypted_data,
        "Mensaje cifrado correctamente con AES-256-GCM",
        "Error al cifrar mensaje"
    )
    
    assert_test(
        encrypted_data.get('algorithm') == 'AES-256-GCM',
        "Algoritmo correcto: AES-256-GCM",
        "Algoritmo incorrecto"
    )
    
    assert_test(
        encrypted_data.get('key_size') == 256,
        "Tamaño de clave correcto: 256 bits",
        "Tamaño de clave incorrecto"
    )
    
    # DESCIFRADO
    print_test("Descifrar mensaje")
    response = requests.post(
        f"{BASE_URL}/decrypt",
        json={
            "ciphertext": encrypted_data['ciphertext'],
            "nonce": encrypted_data['nonce'],
            "tag": encrypted_data['tag']
        },
        headers=headers
    )
    
    print_info(f"Status: {response.status_code}")
    decrypted_data = response.json()
    print_json(decrypted_data)
    
    assert_test(
        response.status_code == 200,
        "Mensaje descifrado correctamente",
        "Error al descifrar mensaje"
    )
    
    plaintext_decrypted = decrypted_data.get('plaintext')
    assert_test(
        plaintext_decrypted == plaintext_original,
        f"Textos coinciden: '{plaintext_original}'",
        f"Textos NO coinciden: '{plaintext_original}' != '{plaintext_decrypted}'"
    )
    
    return encrypted_data


def test_encrypt_decrypt_failures(tokens, valid_encrypted_data):
    """Test: Fallos esperados en cifrado/descifrado"""
    print_header("TESTS DE FALLOS EN CIFRADO/DESCIFRADO")
    
    token = tokens.get('alice')
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test 1: Cifrar sin token
    print_test("Intentar cifrar sin token de autenticación")
    response = requests.post(
        f"{BASE_URL}/encrypt",
        json={"plaintext": "test"}
    )
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 401,
        "Correctamente rechazado sin token (401)",
        "Debería rechazar sin token"
    )
    
    # Test 2: Cifrar sin plaintext
    print_test("Intentar cifrar sin plaintext")
    response = requests.post(
        f"{BASE_URL}/encrypt",
        json={},
        headers=headers
    )
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 400,
        "Correctamente rechazado sin plaintext (400)",
        "Debería rechazar sin plaintext"
    )
    
    # Test 3: Descifrar con tag manipulado (ataque de integridad)
    print_test("Intentar descifrar con tag manipulado")
    manipulated_tag = "AAAAAAAAAAAAAAAAAAAAAA=="  # Tag inválido
    response = requests.post(
        f"{BASE_URL}/decrypt",
        json={
            "ciphertext": valid_encrypted_data['ciphertext'],
            "nonce": valid_encrypted_data['nonce'],
            "tag": manipulated_tag
        },
        headers=headers
    )
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 400,
        "Correctamente detectada manipulación del tag (400)",
        "Debería detectar manipulación del tag"
    )
    
    # Test 4: Descifrar con datos incompletos
    print_test("Intentar descifrar sin tag")
    response = requests.post(
        f"{BASE_URL}/decrypt",
        json={
            "ciphertext": valid_encrypted_data['ciphertext'],
            "nonce": valid_encrypted_data['nonce']
        },
        headers=headers
    )
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 400,
        "Correctamente rechazado sin tag (400)",
        "Debería rechazar datos incompletos"
    )


# ============================================================================
# TESTS DE HMAC
# ============================================================================

def test_hmac_success(tokens):
    """Test: Generación y verificación de HMAC"""
    print_header("TESTS DE HMAC")
    
    token = tokens.get('alice')
    headers = {"Authorization": f"Bearer {token}"}
    message = "Documento importante que debe ser autenticado"
    
    # GENERAR HMAC
    print_test("Generar HMAC-SHA256")
    response = requests.post(
        f"{BASE_URL}/hmac/generate",
        json={"message": message},
        headers=headers
    )
    
    print_info(f"Status: {response.status_code}")
    hmac_data = response.json()
    print_json(hmac_data)
    
    assert_test(
        response.status_code == 200 and 'hmac' in hmac_data,
        "HMAC generado correctamente",
        "Error al generar HMAC"
    )
    
    assert_test(
        hmac_data.get('algorithm') == 'HMAC-SHA256',
        "Algoritmo correcto: HMAC-SHA256",
        "Algoritmo incorrecto"
    )
    
    assert_test(
        hmac_data.get('key_size') == 256,
        "Tamaño de clave correcto: 256 bits",
        "Tamaño de clave incorrecto"
    )
    
    # VERIFICAR HMAC VÁLIDO
    print_test("Verificar HMAC válido")
    response = requests.post(
        f"{BASE_URL}/hmac/verify",
        json={
            "message": message,
            "hmac": hmac_data['hmac']
        },
        headers=headers
    )
    
    print_info(f"Status: {response.status_code}")
    verify_data = response.json()
    print_json(verify_data)
    
    assert_test(
        response.status_code == 200 and verify_data.get('valid') == True,
        "HMAC válido verificado correctamente",
        "Error al verificar HMAC válido"
    )
    
    # VERIFICAR HMAC INVÁLIDO
    print_test("Verificar HMAC inválido (mensaje modificado)")
    response = requests.post(
        f"{BASE_URL}/hmac/verify",
        json={
            "message": "Mensaje MODIFICADO",
            "hmac": hmac_data['hmac']
        },
        headers=headers
    )
    
    print_info(f"Status: {response.status_code}")
    verify_data = response.json()
    print_json(verify_data)
    
    assert_test(
        response.status_code == 200 and verify_data.get('valid') == False,
        "HMAC inválido detectado correctamente",
        "Debería detectar HMAC inválido"
    )


def test_hmac_failures(tokens):
    """Test: Fallos esperados en HMAC"""
    print_header("TESTS DE FALLOS EN HMAC")
    
    token = tokens.get('alice')
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test 1: Generar HMAC sin mensaje
    print_test("Intentar generar HMAC sin mensaje")
    response = requests.post(
        f"{BASE_URL}/hmac/generate",
        json={},
        headers=headers
    )
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 400,
        "Correctamente rechazado sin mensaje (400)",
        "Debería rechazar sin mensaje"
    )
    
    # Test 2: Verificar HMAC sin datos
    print_test("Intentar verificar HMAC sin datos")
    response = requests.post(
        f"{BASE_URL}/hmac/verify",
        json={"message": "test"},
        headers=headers
    )
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 400,
        "Correctamente rechazado sin HMAC (400)",
        "Debería rechazar datos incompletos"
    )


# ============================================================================
# TESTS DE MENSAJERÍA
# ============================================================================

def test_messaging_success(tokens):
    """Test: Envío y recepción de mensajes cifrados"""
    print_header("TESTS DE MENSAJERÍA")
    
    alice_token = tokens.get('alice')
    bob_token = tokens.get('bob')
    
    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    bob_headers = {"Authorization": f"Bearer {bob_token}"}
    
    # ALICE ENVÍA MENSAJE A BOB
    print_test("Alice envía mensaje cifrado a Bob")
    message_text = "Hola Bob, este es un mensaje secreto 🔐"
    
    response = requests.post(
        f"{BASE_URL}/messages",
        json={
            "to": "bob",
            "message": message_text
        },
        headers=alice_headers
    )
    
    print_info(f"Status: {response.status_code}")
    send_data = response.json()
    print_json(send_data)
    
    assert_test(
        response.status_code == 201 and 'message_id' in send_data,
        f"Mensaje enviado correctamente (ID: {send_data.get('message_id')})",
        "Error al enviar mensaje"
    )
    
    message_id = send_data.get('message_id')
    
    # Verificar información de cifrado
    encryption_info = send_data.get('encryption_info', {})
    assert_test(
        encryption_info.get('algorithm') == 'AES-256-GCM',
        "Mensaje cifrado con AES-256-GCM",
        "Algoritmo de cifrado incorrecto"
    )
    
    assert_test(
        encryption_info.get('authenticated') == True,
        "Mensaje autenticado correctamente",
        "Mensaje no autenticado"
    )
    
    # BOB LISTA SUS MENSAJES
    print_test("Bob lista sus mensajes")
    time.sleep(0.5)  # Pequeña pausa
    
    response = requests.get(
        f"{BASE_URL}/messages",
        headers=bob_headers
    )
    
    print_info(f"Status: {response.status_code}")
    messages_data = response.json()
    print_json(messages_data)
    
    assert_test(
        response.status_code == 200 and len(messages_data.get('messages', [])) > 0,
        f"Bob tiene {len(messages_data.get('messages', []))} mensaje(s)",
        "Bob no tiene mensajes"
    )
    
    # BOB LEE EL MENSAJE
    print_test(f"Bob lee el mensaje (ID: {message_id})")
    
    response = requests.get(
        f"{BASE_URL}/messages/{message_id}",
        headers=bob_headers
    )
    
    print_info(f"Status: {response.status_code}")
    message_data = response.json()
    print_json(message_data)
    
    assert_test(
        response.status_code == 200,
        "Mensaje leído correctamente",
        "Error al leer mensaje"
    )
    
    assert_test(
        message_data.get('message') == message_text,
        f"Mensaje descifrado correctamente: '{message_text}'",
        "Mensaje descifrado no coincide"
    )
    
    # Verificar integridad
    verification = message_data.get('verification', {})
    assert_test(
        verification.get('gcm_tag_valid') == True,
        "GCM tag verificado correctamente (integridad OK)",
        "GCM tag inválido"
    )
    
    assert_test(
        verification.get('hmac_valid') == True,
        "HMAC verificado correctamente (autenticación OK)",
        "HMAC inválido"
    )
    
    # BOB ENVÍA RESPUESTA A ALICE
    print_test("Bob envía respuesta a Alice")
    
    response = requests.post(
        f"{BASE_URL}/messages",
        json={
            "to": "alice",
            "message": "Hola Alice, recibí tu mensaje 👍"
        },
        headers=bob_headers
    )
    
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    
    assert_test(
        response.status_code == 201,
        "Respuesta enviada correctamente",
        "Error al enviar respuesta"
    )
    
    # ALICE LEE SU MENSAJE
    print_test("Alice lista sus mensajes")
    
    response = requests.get(
        f"{BASE_URL}/messages",
        headers=alice_headers
    )
    
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    
    assert_test(
        response.status_code == 200 and len(response.json().get('messages', [])) > 0,
        f"Alice tiene {len(response.json().get('messages', []))} mensaje(s)",
        "Alice no tiene mensajes"
    )


def test_messaging_failures(tokens):
    """Test: Fallos esperados en mensajería"""
    print_header("TESTS DE FALLOS EN MENSAJERÍA")
    
    alice_token = tokens.get('alice')
    bob_token = tokens.get('bob')
    
    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    bob_headers = {"Authorization": f"Bearer {bob_token}"}
    
    # Test 1: Enviar mensaje a usuario inexistente
    print_test("Intentar enviar mensaje a usuario inexistente")
    response = requests.post(
        f"{BASE_URL}/messages",
        json={
            "to": "noexiste",
            "message": "Hola"
        },
        headers=alice_headers
    )
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 404,
        "Correctamente rechazado destinatario inexistente (404)",
        "Debería rechazar destinatario inexistente"
    )
    
    # Test 2: Enviar mensaje sin datos
    print_test("Intentar enviar mensaje sin datos")
    response = requests.post(
        f"{BASE_URL}/messages",
        json={},
        headers=alice_headers
    )
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 400,
        "Correctamente rechazado mensaje incompleto (400)",
        "Debería rechazar datos faltantes"
    )
    
    # Test 3: Leer mensaje que no te pertenece
    print_test("Bob intenta leer mensaje de Alice (no autorizado)")
    # Primero Alice envía mensaje a Charlie
    send_response = requests.post(
        f"{BASE_URL}/messages",
        json={"to": "charlie", "message": "Solo para Charlie"},
        headers=alice_headers
    )
    charlie_message_id = send_response.json().get('message_id')

    # Bob intenta leer ese mensaje
    response = requests.get(
        f"{BASE_URL}/messages/{charlie_message_id}",
        headers=bob_headers
    )
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code in [403, 404],  # Puede ser 403 o 404 según implementación
        "Correctamente rechazado acceso no autorizado",
        "Debería rechazar acceso a mensajes de otros"
    )
    
    # Test 4: Leer mensaje inexistente
    print_test("Intentar leer mensaje inexistente")
    response = requests.get(
        f"{BASE_URL}/messages/99999",
        headers=alice_headers
    )
    print_info(f"Status: {response.status_code}")
    print_json(response.json())
    assert_test(
        response.status_code == 404,
        "Correctamente rechazado mensaje inexistente (404)",
        "Debería rechazar mensaje inexistente"
    )


# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def run_all_tests():
    """Ejecuta todos los tests en secuencia"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}")
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║   TEST EXHAUSTIVO - SISTEMA DE MENSAJERÍA CIFRADA        ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print(Colors.END)

    try:
        # Verificar conexión al servidor
        print_info("Verificando conexión al servidor...")
        try:
            requests.get(f"{BASE_URL}/", timeout=2)
            print_success("Servidor disponible")
        except:
            print_error("No se pudo conectar al servidor")
            print_info("Asegúrate de ejecutar: python app.py")
            return

        # Resetear base de datos antes de ejecutar tests
        print_info("Reseteando base de datos...")
        try:
            response = requests.post(f"{BASE_URL}/reset_db", timeout=5)
            if response.status_code == 200:
                print_success("Base de datos reseteada correctamente")
            else:
                print_error(f"Error al resetear base de datos: {response.status_code}")
                return
        except Exception as e:
            print_error(f"No se pudo resetear la base de datos: {str(e)}")
            return

        # Ejecutar tests
        tokens = test_register_success()
        test_register_failures()

        test_login_failures()

        encrypted_data = test_encrypt_decrypt_success(tokens)
        test_encrypt_decrypt_failures(tokens, encrypted_data)

        test_hmac_success(tokens)
        test_hmac_failures(tokens)

        test_messaging_success(tokens)
        test_messaging_failures(tokens)
        
        # Resumen final
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}RESUMEN DE TESTS{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"\nTotal de tests: {Colors.BOLD}{total_tests}{Colors.END}")
        print(f"Tests exitosos: {Colors.GREEN}{Colors.BOLD}{passed_tests}{Colors.END}")
        print(f"Tests fallidos: {Colors.RED}{Colors.BOLD}{failed_tests}{Colors.END}")
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        print(f"Tasa de éxito: {Colors.BOLD}{success_rate:.1f}%{Colors.END}")
        
        if failed_tests == 0:
            print(f"\n{Colors.GREEN}{Colors.BOLD}✓ TODOS LOS TESTS PASARON CORRECTAMENTE ✓{Colors.END}\n")
        else:
            print(f"\n{Colors.YELLOW}⚠ Algunos tests fallaron. Revisa los errores anteriores.{Colors.END}\n")
        
    except requests.exceptions.ConnectionError:
        print_error("No se pudo conectar al servidor")
        print_info("Ejecuta primero: python app.py")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Tests interrumpidos por el usuario{Colors.END}")
    except Exception as e:
        print_error(f"ERROR INESPERADO: {str(e)}")
        traceback.print_exc()


if __name__ == "__main__":
    run_all_tests()