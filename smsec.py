import cmd
import requests

class SMSecShell(cmd.Cmd):
    intro = 'Bienvenido al cliente SMSec. Escribe help o ? para listar los comandos.\n'
    prompt = '(smsec) '
    
    def __init__(self):
        super().__init__()
        self.base_url = 'http://localhost:5000'
        self.token = None
        self.username = None

    def do_register(self, arg):
        """Registra un nuevo usuario: register <username> <password>"""
        args = arg.split()
        if len(args) != 2:
            print("Uso: register <username> <password>")
            return
        
        username, password = args
        try:
            response = requests.post(f'{self.base_url}/register', json={
                'username': username,
                'password': password
            })
            if response.status_code == 201:
                print(f"Usuario '{username}' registrado correctamente.")
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

    def do_encrypt(self, arg):
        """Cifra un mensaje: encrypt <texto>"""
        if not self.token:
            print("Debes iniciar sesión primero.")
            return
        
        if not arg:
            print("Uso: encrypt <texto>")
            return

        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.post(f'{self.base_url}/encrypt', json={'plaintext': arg}, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                print("Cifrado exitoso:")
                print(f"Ciphertext: {data['ciphertext']}")
                print(f"Nonce: {data['nonce']}")
                print(f"Tag: {data['tag']}")
            else:
                print(f"Error: {response.json().get('error', 'Error desconocido')}")
        except requests.exceptions.RequestException as e:
            print(f"Error de conexión: {e}")

    def do_decrypt(self, arg):
        """Descifra un mensaje: decrypt <ciphertext> <nonce> <tag>"""
        if not self.token:
            print("Debes iniciar sesión primero.")
            return
        
        args = arg.split()
        if len(args) != 3:
            print("Uso: decrypt <ciphertext> <nonce> <tag>")
            return
        
        ciphertext, nonce, tag = args
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.post(f'{self.base_url}/decrypt', json={
                'ciphertext': ciphertext,
                'nonce': nonce,
                'tag': tag
            }, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                print(f"Texto descifrado: {data['plaintext']}")
            else:
                print(f"Error: {response.json().get('error', 'Error desconocido')}")
        except requests.exceptions.RequestException as e:
            print(f"Error de conexión: {e}")

    def do_send(self, arg):
        """Envía un mensaje: send <destinatario> <mensaje>"""
        if not self.token:
            print("Debes iniciar sesión primero.")
            return
        
        args = arg.split(' ', 1)
        if len(args) != 2:
            print("Uso: send <destinatario> <mensaje>")
            return
        
        to_user, message = args
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.post(f'{self.base_url}/messages', json={
                'to': to_user,
                'message': message
            }, headers=headers)
            
            if response.status_code == 201:
                print("Mensaje enviado correctamente.")
            else:
                print(f"Error: {response.json().get('error', 'Error desconocido')}")
        except requests.exceptions.RequestException as e:
            print(f"Error de conexión: {e}")

    def do_list(self, arg):
        """Lista mensajes: list [unread_only] (true/false)"""
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
        """Lee un mensaje específico: read <message_id>"""
        if not self.token:
            print("Debes iniciar sesión primero.")
            return
        
        if not arg:
            print("Uso: read <message_id>")
            return
        
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.get(f'{self.base_url}/messages/{arg}', headers=headers)
            
            if response.status_code == 200:
                msg = response.json()
                print(f"De: {msg['from']}")
                print(f"Para: {msg['to']}")
                print(f"Fecha: {msg['timestamp']}")
                print(f"Mensaje: {msg['message']}")
                print(f"Verificación: GCM={msg['verification']['gcm_tag_valid']}, HMAC={msg['verification']['hmac_valid']}")
            else:
                print(f"Error: {response.json().get('error', 'Error desconocido')}")
        except requests.exceptions.RequestException as e:
            print(f"Error de conexión: {e}")

    def do_hmac_gen(self, arg):
        """Genera HMAC: hmac_gen <mensaje>"""
        if not self.token:
            print("Debes iniciar sesión primero.")
            return
        
        if not arg:
            print("Uso: hmac_gen <mensaje>")
            return
            
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.post(f'{self.base_url}/hmac/generate', json={'message': arg}, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                print(f"HMAC: {data['hmac']}")
            else:
                print(f"Error: {response.json().get('error', 'Error desconocido')}")
        except requests.exceptions.RequestException as e:
            print(f"Error de conexión: {e}")

    def do_hmac_verify(self, arg):
        """Verifica HMAC: hmac_verify <mensaje> <hmac>"""
        if not self.token:
            print("Debes iniciar sesión primero.")
            return
        
        args = arg.rsplit(' ', 1) # Split desde la derecha para manejar espacios en el mensaje
        if len(args) != 2:
            print("Uso: hmac_verify <mensaje> <hmac>")
            return
            
        message, hmac_val = args
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.post(f'{self.base_url}/hmac/verify', json={
                'message': message,
                'hmac': hmac_val
            }, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                print(f"Resultado: {data['message']}")
            else:
                print(f"Error: {response.json().get('error', 'Error desconocido')}")
        except requests.exceptions.RequestException as e:
            print(f"Error de conexión: {e}")

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
