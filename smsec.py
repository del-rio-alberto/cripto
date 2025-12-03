import cmd
import requests
import os
import getpass
import base64

from user_keys import generate_user_keypair, encrypt_private_key, decrypt_private_key, get_public_key_pem, generate_csr
from secure_messaging import send_secure_message, receive_secure_message

class SMSecShell(cmd.Cmd):
    intro = 'Bienvenido al cliente SMSec. Escribe help o ? para listar los comandos.\n'
    prompt = '(smsec) '
    
    def __init__(self):
        super().__init__()
        self.base_url = 'http://localhost:5000'
        self.token = None
        self.username = None
        self.keys_dir = 'keys'
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)

    def _get_private_key_path(self, username):
        return os.path.join(self.keys_dir, f'{username}.key')

    def _get_public_key_path(self, username):
        return os.path.join(self.keys_dir, f'{username}.pub')

    def _get_cert_path(self, username):
        return os.path.join(self.keys_dir, f'{username}.crt')

    def _get_csr_path(self, username):
        return os.path.join(self.keys_dir, f'{username}.csr')

    def _get_password(self, prompt):
        env_pass = os.environ.get('SMSEC_PASSWORD')
        if env_pass:
            print(f"{prompt} [Using env var]")
            return env_pass
        return getpass.getpass(prompt)

    def do_genkey(self, arg):
        """Genera un par de claves EC P-256 localmente: genkey <username>"""
        if not arg:
            print("Uso: genkey <username>")
            return
            
        username = arg
        password = self._get_password(f"Introduce contraseña para cifrar la clave de {username}: ")
        
        try:
            # Generar par de claves
            private_key, public_key = generate_user_keypair()
            
            # Cifrar clave privada
            encrypted_private_key = encrypt_private_key(private_key, password)
            
            # Guardar clave privada cifrada
            with open(self._get_private_key_path(username), 'w') as f:
                f.write(encrypted_private_key)
                
            # Guardar clave pública
            public_key_pem = get_public_key_pem(private_key)
            with open(self._get_public_key_path(username), 'w') as f:
                f.write(public_key_pem)
                
            print(f"Claves generadas para '{username}' en {self.keys_dir}/")
            
        except Exception as e:
            print(f"Error al generar claves: {e}")

    def do_csr(self, arg):
        """Genera un CSR para obtener un certificado: csr <username>"""
        if not arg:
            print("Uso: csr <username>")
            return
            
        username = arg
        
        # Verificar si existe la clave privada
        key_path = self._get_private_key_path(username)
        if not os.path.exists(key_path):
            print(f"No se encontró clave privada para '{username}'. Ejecuta 'genkey {username}' primero.")
            return
            
        password = self._get_password(f"Introduce contraseña para descifrar la clave de {username}: ")
        
        try:
            # Leer clave cifrada
            with open(key_path, 'r') as f:
                encrypted_key = f.read()
                
            # Descifrar clave
            private_key = decrypt_private_key(encrypted_key, password)
            
            # Generar CSR
            csr_pem = generate_csr(private_key, username)
            
            # Guardar CSR
            with open(self._get_csr_path(username), 'wb') as f:
                f.write(csr_pem)
                
            print(f"CSR generado para '{username}' en {self._get_csr_path(username)}")
            
        except Exception as e:
            print(f"Error al generar CSR: {e}")

    def do_getcert(self, arg):
        """Obtiene un certificado del servidor: getcert <username>"""
        if not arg:
            print("Uso: getcert <username>")
            return
            
        username = arg
        csr_path = self._get_csr_path(username)
        cert_path = self._get_cert_path(username)
        
        # Opción 1: Si existe CSR local, intentar emitir nuevo certificado
        if os.path.exists(csr_path):
            print(f"Encontrado CSR local para '{username}'. Solicitando emisión...")
            try:
                with open(csr_path, 'rb') as f:
                    csr_pem = f.read()
                    
                csr_b64 = base64.b64encode(csr_pem).decode('utf-8')
                
                response = requests.post(f'{self.base_url}/cert/issue', json={
                    'username': username,
                    'csr_pem': csr_b64
                })
                
                if response.status_code == 200:
                    data = response.json()
                    cert_pem_b64 = data['certificate_pem']
                    cert_pem = base64.b64decode(cert_pem_b64)
                    
                    with open(cert_path, 'wb') as f:
                        f.write(cert_pem)
                        
                    print(f"Certificado emitido y guardado en {cert_path}")
                    return
                else:
                    print(f"Error al emitir certificado: {response.json().get('error')}")
                    print("Intentando descargar certificado existente...")
            except Exception as e:
                print(f"Error al solicitar emisión: {e}")
        
        # Opción 2: Descargar certificado existente
        try:
            response = requests.get(f'{self.base_url}/cert/{username}')
            
            if response.status_code == 200:
                data = response.json()
                cert_pem_b64 = data['certificate_pem']
                cert_pem = base64.b64decode(cert_pem_b64)
                
                with open(cert_path, 'wb') as f:
                    f.write(cert_pem)
                    
                print(f"Certificado descargado y guardado en {cert_path}")
            else:
                print(f"Error al obtener certificado: {response.json().get('error')}")
                
        except Exception as e:
            print(f"Error de conexión: {e}")

    def do_register(self, arg):
        """Registra un nuevo usuario: register <username>"""
        if not arg:
            print("Uso: register <username>")
            return
        
        username = arg
        password = self._get_password(f"Introduce contraseña para el servidor (usuario {username}): ")
        
        try:
            response = requests.post(f'{self.base_url}/register', json={
                'username': username,
                'password': password
            })
            if response.status_code == 201:
                print(f"Usuario '{username}' registrado correctamente en el servidor.")
            else:
                print(f"Error: {response.json().get('error', 'Error desconocido')}")
        except requests.exceptions.RequestException as e:
            print(f"Error de conexión: {e}")

    def do_login(self, arg):
        """Inicia sesión: login <username> <password>"""
        args = arg.split()
        if len(args) != 2:
            print("Uso: login <username> <password>")
            return
        
        username, password = args
        try:
            response = requests.post(f'{self.base_url}/login', json={
                'username': username,
                'password': password
            })
            if response.status_code == 200:
                data = response.json()
                self.token = data['token']
                self.username = data['username']
                print(f"Login exitoso como '{self.username}'.")
                self.prompt = f'({self.username}) '
            else:
                print(f"Error: {response.json().get('error', 'Error desconocido')}")
        except requests.exceptions.RequestException as e:
            print(f"Error de conexión: {e}")

    def do_send(self, arg):
        """Envía un mensaje seguro: send <emisor> <destinatario> <mensaje>"""
        # Parsear argumentos respetando comillas
        import shlex
        try:
            args = shlex.split(arg)
        except ValueError:
            print("Error al parsear argumentos. Asegúrate de cerrar las comillas.")
            return

        if len(args) != 3:
            print("Uso: send <emisor> <destinatario> <mensaje>")
            return
        
        sender_user, receiver_user, message = args
        
        # 1. Cargar clave privada del emisor
        sender_key_path = self._get_private_key_path(sender_user)
        if not os.path.exists(sender_key_path):
            print(f"No se encontró clave privada para '{sender_user}'.")
            return
            
        password = self._get_password(f"Introduce contraseña de {sender_user}: ")
        
        try:
            with open(sender_key_path, 'r') as f:
                encrypted_key = f.read()
            sender_private_key = decrypt_private_key(encrypted_key, password)
        except Exception as e:
            print(f"Error al descifrar clave privada: {e}")
            return

        # 2. Cargar certificado del emisor (para incluirlo en el mensaje)
        sender_cert_path = self._get_cert_path(sender_user)
        if not os.path.exists(sender_cert_path):
            print(f"No se encontró certificado para '{sender_user}'. Ejecuta 'getcert {sender_user}' primero.")
            return
            
        with open(sender_cert_path, 'r') as f:
            sender_cert_pem = f.read()

        # 3. Obtener certificado del destinatario
        receiver_cert_path = self._get_cert_path(receiver_user)
        receiver_cert_pem = None
        
        # Intentar cargar localmente
        if os.path.exists(receiver_cert_path):
            with open(receiver_cert_path, 'r') as f:
                receiver_cert_pem = f.read()
        else:
            # Intentar descargar del servidor
            print(f"Certificado de '{receiver_user}' no encontrado localmente. Intentando descargar...")
            try:
                response = requests.get(f'{self.base_url}/cert/{receiver_user}')
                if response.status_code == 200:
                    data = response.json()
                    cert_b64 = data['certificate_pem']
                    receiver_cert_pem = base64.b64decode(cert_b64).decode('utf-8')
                    # Guardar para futuro uso
                    with open(receiver_cert_path, 'w') as f:
                        f.write(receiver_cert_pem)
                else:
                    print(f"No se pudo obtener certificado de '{receiver_user}'.")
                    return
            except Exception as e:
                print(f"Error de conexión al obtener certificado: {e}")
                return

        # 4. Generar mensaje seguro (Client-Side)
        try:
            sender_data = {'private_key': sender_private_key, 'cert': sender_cert_pem}
            receiver_data = {'cert': receiver_cert_pem}
            
            secure_payload = send_secure_message(sender_data, receiver_data, message)
            
            # 5. Enviar al servidor
            # Necesitamos estar logueados como el emisor para enviar (o al menos tener un token válido)
            # Por simplicidad, asumimos que el usuario ya hizo login o hacemos login automático si tenemos credenciales (no las tenemos aquí)
            # Requerimos que el usuario haga login primero con 'login <user> <pass>'
            
            if not self.token:
                print("Debes iniciar sesión primero (login <user> <pass>).")
                return
                
            if self.username != sender_user:
                print(f"Advertencia: Estás logueado como '{self.username}' pero enviando como '{sender_user}'.")
            
            headers = {'Authorization': f'Bearer {self.token}'}
            payload = {
                'to': receiver_user,
                'ciphertext': secure_payload['ciphertext'],
                'nonce': secure_payload['nonce'],
                'signature': secure_payload['signature'],
                'cert_emisor': secure_payload['cert_emisor'],
                'ephemeral_pubkey': secure_payload['pubkey_efimera']
            }
            
            response = requests.post(f'{self.base_url}/messages/secure', json=payload, headers=headers)
            
            if response.status_code == 201:
                print("Mensaje seguro enviado correctamente.")
            else:
                print(f"Error del servidor: {response.json().get('error')}")
                
        except Exception as e:
            print(f"Error al procesar mensaje seguro: {e}")

    def do_inbox(self, arg):
        """Lista mensajes recibidos: inbox [user]"""
        # Si se pasa usuario, verificamos que coincida con el login
        if arg and arg != self.username:
            print(f"Estás logueado como '{self.username}', no puedes ver el inbox de '{arg}'.")
            return
            
        if not self.token:
            print("Debes iniciar sesión primero.")
            return
        
        unread_only = 'false'
        if arg.lower() == 'true':
            unread_only = 'true'
            
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.get(f'{self.base_url}/messages', params={'unread_only': unread_only}, headers=headers)
            
            if response.status_code == 200:
                messages = response.json()['messages']
                if not messages:
                    print("No hay mensajes.")
                for msg in messages:
                    status = "Nuevo" if not msg['read'] else "Leído"
                    print(f"[{msg['message_id']}] De: {msg['from']} - {msg['timestamp']} ({status})")
            else:
                print(f"Error: {response.json().get('error', 'Error desconocido')}")
        except requests.exceptions.RequestException as e:
            print(f"Error de conexión: {e}")

    def do_read(self, arg):
        """Lee y descifra un mensaje: read <message_id>"""
        if not self.token:
            print("Debes iniciar sesión primero.")
            return
        
        if not arg:
            print("Uso: read <message_id>")
            return
            
        message_id = arg
        
        try:
            # 1. Obtener mensaje cifrado (RAW)
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.get(f'{self.base_url}/messages/{message_id}/raw', headers=headers)
            
            if response.status_code != 200:
                print(f"Error al obtener mensaje: {response.json().get('error')}")
                return
                
            msg_data = response.json()['message']
            
            # 2. Descifrar localmente
            # Cargar clave privada del receptor (usuario actual)
            key_path = self._get_private_key_path(self.username)
            if not os.path.exists(key_path):
                print(f"No se encontró clave privada local para '{self.username}'.")
                return
                
            password = self._get_password(f"Introduce contraseña para descifrar mensaje (usuario {self.username}): ")
            
            try:
                with open(key_path, 'r') as f:
                    encrypted_key = f.read()
                private_key = decrypt_private_key(encrypted_key, password)
            except Exception as e:
                print(f"Contraseña incorrecta o error de clave: {e}")
                return
                
            # Preparar datos para receive_secure_message
            receiver_data = {'private_key': private_key}
            payload_dict = {
                'ciphertext': msg_data['ciphertext'],
                'nonce': msg_data['nonce'],
                'signature': msg_data['signature'],
                'cert_emisor': msg_data['cert_emisor'],
                'pubkey_efimera': msg_data['ephemeral_pubkey'] # Nota: en BD se guarda como ephemeral_pubkey
            }
            
            plaintext = receive_secure_message(receiver_data, payload_dict)
            
            print("\n=== MENSAJE RECIBIDO ===")
            print(f"De: {msg_data['username_from']}")
            print(f"Fecha: {msg_data['timestamp']}")
            print(f"Mensaje: {plaintext}")
            print("========================\n")
            
        except Exception as e:
            print(f"Error al descifrar/verificar mensaje: {e}")

    def do_reset(self, arg):
        """Resetea la base de datos: reset"""
        try:
            response = requests.post(f'{self.base_url}/reset_db')
            if response.status_code == 200:
                print("Base de datos reseteada.")
                self.token = None
                self.username = None
                self.prompt = '(smsec) '
            else:
                print(f"Error: {response.json().get('error', 'Error desconocido')}")
        except requests.exceptions.RequestException as e:
            print(f"Error de conexión: {e}")

    def do_exit(self, arg):
        """Salir del programa"""
        print('Sesión cerrada.')
        return True

if __name__ == '__main__':
    SMSecShell().cmdloop()
