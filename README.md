SMSec: Sistema de Mensajería Segura
---


Pasos para ejecutarlo:

1. Crear la imagen:

```docker build . -t smsec```

2. Crear el contenedor:

```docker run -p 5000:5000 smsec```

3. Acceder a la app en el navegador

```curl http://localhost:5000/```


# DEMO - Sistema de Mensajería Cifrada

## 1. Registro de usuarios
POST /register  
{
  "username": "alice",
  "password": "Password123!"
}

POST /register  
{
  "username": "bob",
  "password": "SecurePass456!"
}

Genera hash bcrypt, salt, clave AES-256 y clave HMAC-256.

---

## 2. Login de Alice
POST /login  
{
  "username": "alice",
  "password": "Password123!"
}

Devuelve token JWT válido por 24h.

---

## 3. Alice cifra un texto
POST /encrypt  
Headers: Authorization: Bearer <token_alice>  
{
  "plaintext": "Hola Bob, esto es una prueba"
}

Devuelve ciphertext, nonce y tag (AES-256-GCM).

---

## 4. Alice descifra el texto
POST /decrypt  
Headers: Authorization: Bearer <token_alice>  
{
  "ciphertext": "<del_paso_anterior>",
  "nonce": "<del_paso_anterior>",
  "tag": "<del_paso_anterior>"
}

Verifica integridad con GCM tag y devuelve el texto original.

---

## 5. Alice genera HMAC
POST /hmac/generate  
Headers: Authorization: Bearer <token_alice>  
{
  "message": "Documento importante"
}

Devuelve HMAC-SHA256 del mensaje.

---

## 6. Alice verifica HMAC
POST /hmac/verify  
Headers: Authorization: Bearer <token_alice>  
{
  "message": "Documento importante",
  "hmac": "<del_paso_anterior>"
}

Verifica que el HMAC sea válido.

---

## 7. Alice envía mensaje cifrado a Bob
POST /messages  
Headers: Authorization: Bearer <token_alice>  
{
  "to": "bob",
  "message": "Hola Bob, te envío información confidencial"
}

Cifra con AES-256-GCM, calcula HMAC-SHA256 y almacena todo en la base de datos.

---

## 8. Login de Bob
POST /login  
{
  "username": "bob",
  "password": "SecurePass456!"
}

Devuelve token JWT para Bob.

---

## 9. Bob lista sus mensajes
GET /messages  
Headers: Authorization: Bearer <token_bob>

Devuelve lista de mensajes (sin descifrar) con metadata.

---

## 10. Bob lee el mensaje de Alice
GET /messages/1  
Headers: Authorization: Bearer <token_bob>

Verifica tag GCM y HMAC, descifra mensaje y marca como leído.  
Devuelve mensaje descifrado y confirmación de integridad.

---

## Resumen del flujo
1. Register (Alice, Bob)  
2. Login Alice → Token  
3. Encrypt/Decrypt demo → AES-GCM  
4. HMAC generate/verify → HMAC-SHA256  
5. Alice envía mensaje a Bob → Cifrado + Autenticado  
6. Login Bob → Token  
7. Bob lista mensajes  
8. Bob lee mensaje → Descifra + Verifica integridad
