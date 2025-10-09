import sqlite3
import base64
import logging
from typing import Optional, Dict

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
            encryption_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla de mensajes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            nonce TEXT NOT NULL,
            tag TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
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


def create_user(username: str, password_hash: str, salt: bytes, encryption_key: bytes) -> bool:
    """
    Crea un nuevo usuario en la base de datos.
    
    Args:
        username: Nombre de usuario único
        password_hash: Hash bcrypt de la contraseña
        salt: Salt usado para derivar la clave de cifrado
        encryption_key: Clave de cifrado derivada del password
        
    Returns:
        True si el usuario se creó correctamente
        
    Raises:
        sqlite3.IntegrityError: Si el usuario ya existe
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO users (username, password_hash, salt, encryption_key)
            VALUES (?, ?, ?, ?)
        ''', (
            username,
            password_hash,
            base64.b64encode(salt).decode(),
            base64.b64encode(encryption_key).decode()
        ))
        conn.commit()
        logger.info(f"Usuario '{username}' creado exitosamente")
        return True
    finally:
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


def save_message(from_user: str, to_user: str, ciphertext: str, nonce: str, tag: str) -> int:
    """
    Guarda un mensaje cifrado en la base de datos.
    
    Args:
        from_user: Usuario que envía el mensaje
        to_user: Usuario destinatario
        ciphertext: Mensaje cifrado en base64
        nonce: Nonce usado en el cifrado (base64)
        tag: Tag de autenticación (base64)
        
    Returns:
        ID del mensaje creado
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO messages (from_user, to_user, ciphertext, nonce, tag)
        VALUES (?, ?, ?, ?, ?)
    ''', (from_user, to_user, ciphertext, nonce, tag))
    
    message_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    logger.info(f"Mensaje guardado de '{from_user}' a '{to_user}' (ID: {message_id})")
    return message_id


def get_messages_for_user(username: str) -> list:
    """
    Obtiene todos los mensajes recibidos por un usuario.
    
    Args:
        username: Nombre del usuario
        
    Returns:
        Lista de diccionarios con los mensajes cifrados
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, from_user, ciphertext, nonce, tag, created_at
        FROM messages
        WHERE to_user = ?
        ORDER BY created_at DESC
    ''', (username,))
    
    rows = cursor.fetchall()
    conn.close()
    
    messages = []
    for row in rows:
        messages.append({
            'id': row['id'],
            'from': row['from_user'],
            'ciphertext': row['ciphertext'],
            'nonce': row['nonce'],
            'tag': row['tag'],
            'created_at': row['created_at']
        })
    
    return messages