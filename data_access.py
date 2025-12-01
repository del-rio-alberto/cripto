import sqlite3
import base64
import logging
from datetime import datetime
from typing import Optional, Dict, List
from utils import generate_hmac_key

logger = logging.getLogger(__name__)

DB_NAME = 'smsec.db'
  
# Inicialización de la base de datos
def init_database():
    """
    Inicializa la base de datos con las tablas necesarias.
    
    Tablas creadas:
        - users: Almacena usuarios, hashes de contraseñas y claves de cifrado
        - messages: Almacena mensajes cifrados entre usuarios
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Tabla de usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            encrypted_private_key TEXT NOT NULL,
            public_key_pem TEXT NOT NULL,
            certificate_pem TEXT,
            encryption_key TEXT NOT NULL,
            hmac_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla de mensajes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username_from TEXT NOT NULL,
            username_to TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            nonce TEXT NOT NULL,
            tag TEXT NOT NULL,
            signature TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            read INTEGER DEFAULT 0,
            FOREIGN KEY (username_from) REFERENCES users(username),
            FOREIGN KEY (username_to) REFERENCES users(username)
        )
    ''')

    # Índices para mejorar rendimiento
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_messages_to 
        ON messages(username_to)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_messages_from 
        ON messages(username_from)
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Base de datos inicializada correctamente")


def get_db_connection():
    """
    Obtiene una conexión a la base de datos SQLite.
    
    Returns:
        Conexión SQLite configurada con row_factory
    """
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # Permite acceder a columnas por nombre
    return conn


def create_user(username: str, password_hash: str, salt: bytes, encryption_key: bytes, encrypted_private_key: str, public_key_pem: str) -> None:
    """
    Crea un nuevo usuario en la base de datos con todas sus claves.
    
    Args:
        username: Nombre del usuario
        password_hash: Hash de la contraseña (bcrypt)
        salt: Salt para derivación de clave
        encryption_key: Clave de cifrado AES derivada
        encrypted_private_key: Clave privada cifrada (JSON)
        public_key_pem: Clave pública (PEM)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Generar clave HMAC para el usuario
    hmac_key = generate_hmac_key()
    
    # Convertir a base64 para almacenar
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    encryption_key_b64 = base64.b64encode(encryption_key).decode('utf-8')
    hmac_key_b64 = base64.b64encode(hmac_key).decode('utf-8')
    
    cursor.execute('''
        INSERT INTO users (
            username, password_hash, salt, encryption_key, hmac_key,
            encrypted_private_key, public_key_pem
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        username, password_hash, salt_b64, encryption_key_b64, hmac_key_b64,
        encrypted_private_key, public_key_pem
    ))
    
    conn.commit()
    conn.close()


def get_user_password_hash(username: str) -> Optional[str]:
    """
    Obtiene el hash de contraseña de un usuario.
    
    Args:
        username: Nombre del usuario
        
    Returns:
        Hash de la contraseña o None si el usuario no existe
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    
    return row['password_hash'] if row else None


def get_user_encryption_key(username: str) -> Optional[bytes]:
    """
    Obtiene la clave de cifrado de un usuario.
    
    Args:
        username: Nombre del usuario
        
    Returns:
        Clave de cifrado de 32 bytes o None si el usuario no existe
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT encryption_key FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    return base64.b64decode(row['encryption_key'])


def user_exists(username: str) -> bool:
    """
    Verifica si un usuario existe en la base de datos.
    
    Args:
        username: Nombre del usuario
        
    Returns:
        True si el usuario existe, False en caso contrario
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
    exists = cursor.fetchone() is not None
    conn.close()
    
    return exists


def store_message(username_from: str, username_to: str, ciphertext: str, nonce: str, tag: str, hmac: str, timestamp: str) -> int:
    """
    Guarda un mensaje cifrado en la base de datos.

    Args:
        username_from: Usuario que envía el mensaje
        username_to: Usuario destinatario
        ciphertext: Mensaje cifrado en base64
        nonce: Nonce usado en el cifrado (base64)
        tag: Tag de autenticación (base64)
        hmac: HMAC del mensaje
        timestamp: Timestamp del mensaje

    Returns:
        ID del mensaje creado
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO messages (username_from, username_to, ciphertext, nonce, tag, hmac, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (username_from, username_to, ciphertext, nonce, tag, hmac, timestamp))

    message_id = cursor.lastrowid
    conn.commit()
    conn.close()

    logger.info(f"Mensaje guardado de '{username_from}' a '{username_to}' (ID: {message_id})")
    return message_id


def get_user_messages(username: str, unread_only: bool) -> list:
    """
    Obtiene todos los mensajes recibidos por un usuario.
    
    Args:
        username: Nombre del usuario
        
    Returns:
        Lista de diccionarios con los mensajes cifrados
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT
            id as message_id,
            username_from as "from",
            timestamp,
            read
        FROM messages
        WHERE username_to = ?
    '''
    
    if unread_only:
        query += ' AND read = 0'
    
    query += ' ORDER BY timestamp DESC'
    
    cursor.execute(query, (username,))
    rows = cursor.fetchall()
    conn.close()
    
    # Convertir rows a lista de diccionarios
    messages = []
    for row in rows:
        messages.append({
            'message_id': row['message_id'],
            'from': row['from'],
            'timestamp': row['timestamp'],
            'read': bool(row['read'])
        })
    
    return messages


def get_user_hmac_key(username: str) -> Optional[bytes]:
    """
    Obtiene la clave HMAC de un usuario.
    
    Args:
        username: Nombre del usuario
    
    Returns:
        Clave HMAC en bytes o None si no existe
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT hmac_key FROM users WHERE username = ?',
        (username,)
    )
    row = cursor.fetchone()
    conn.close()
    
    if not row or not row['hmac_key']:
        return None
    
    # La clave está almacenada en base64
    return base64.b64decode(row['hmac_key'])


def get_message_by_id(message_id: int) -> Optional[Dict]:
    """
    Obtiene un mensaje específico por su ID.
    
    Args:
        message_id: ID del mensaje
    
    Returns:
        Diccionario con toda la información del mensaje o None
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT 
            id,
            username_from,
            username_to,
            ciphertext,
            nonce,
            tag,
            hmac,
            timestamp,
            read
        FROM messages
        WHERE id = ?
    ''', (message_id,))
    
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    return {
        'message_id': row['id'],
        'username_from': row['username_from'],
        'username_to': row['username_to'],
        'ciphertext': row['ciphertext'],
        'nonce': row['nonce'],
        'tag': row['tag'],
        'hmac': row['hmac'],
        'timestamp': row['timestamp'],
        'read': bool(row['read'])
    }


def mark_message_as_read(message_id: int) -> None:
    """
    Marca un mensaje como leído.

    Args:
        message_id: ID del mensaje
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        'UPDATE messages SET read = 1 WHERE id = ?',
        (message_id,)
    )

    conn.commit()
    conn.close()





def get_user_encrypted_private_key(username: str) -> Optional[str]:
    """
    Obtiene la clave privada cifrada de un usuario.
    
    Args:
        username: Nombre del usuario
        
    Returns:
        Clave privada cifrada (JSON string) o None si no existe
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT encrypted_private_key FROM users WHERE username = ?',
        (username,)
    )
    row = cursor.fetchone()
    conn.close()
    
    return row['encrypted_private_key'] if row else None


def get_user_public_key(username: str) -> Optional[str]:
    """
    Obtiene la clave pública de un usuario.
    
    Args:
        username: Nombre del usuario
        
    Returns:
        Clave pública en formato PEM o None si no existe
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT public_key FROM users WHERE username = ?',
        (username,)
    )
    row = cursor.fetchone()
    conn.close()
    
    return row['public_key'] if row else None


def reset_database() -> None:
    """
    Resetea la base de datos eliminando todas las tablas y recreándolas.
    Útil para limpiar el estado entre ejecuciones de tests.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Eliminar tablas si existen
    cursor.execute('DROP TABLE IF EXISTS messages')
    cursor.execute('DROP TABLE IF EXISTS users')

    conn.commit()
    conn.close()

    # Recrear las tablas
    init_database()
    logger.info("Base de datos reseteada correctamente")
