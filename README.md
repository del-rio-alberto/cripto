SMSec: Sistema de Mensajería Segura
---


## Pasos para ejecutarlo:

1. Crear la imagen:

```docker build . -t smsec```

2. Crear el contenedor:

```docker run -p 5000:5000 smsec```

3. Acceder a la app en el navegador

```curl http://localhost:5000/```

## Crear infraestructura de PKI
```bash
bash ./create_root_ca.sh
bash ./create_intermediate_ca.sh
```

## CLI
Comandos disponibles:
- `setup <usuario>` - Configura un usuario completo (genkey + csr + register + getcert + login)
- `genkey <usuario>` - Genera par de claves
- `csr <usuario>` - Genera Certificate Signing Request
- `getcert <usuario>` - Obtiene certificado del servidor
- `register <usuario>` - Registra usuario en el servidor
- `login <usuario> <password>` - Inicia sesión
- `send <destinatario> <mensaje>` - Envía mensaje seguro
- `inbox` - Lista mensajes recibidos
- `read <id>` - Lee y descifra un mensaje
- `reset` - Resetea la base de datos
- `exit` - Salir

### DEMO CLI
```bash
pip install -r requirements.txt
python smsec.py

// terminal 1
setup pepe

// terminal 2
setup pedro 

// terminal 1
send pedro "Hola pedro"

// terminal 2
inbox
read 1
```