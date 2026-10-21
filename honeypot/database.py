import sqlite3
import os
from datetime import datetime

DB_PATH = os.environ.get("DB_PATH", "honeypot.db")

def init_db(db_path: str = DB_PATH):
    """Inicializa las tablas de auditoria forense en SQLite."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Tabla 1: Intentos de autenticacion (Fuerza bruta / Diccionarios)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            status TEXT NOT NULL,          -- 'SUCCESS' o 'FAILED'
            country TEXT DEFAULT 'Unknown',
            city TEXT DEFAULT 'Unknown',
            latitude REAL DEFAULT 0.0,
            longitude REAL DEFAULT 0.0,
            isp TEXT DEFAULT 'Unknown'
        )
    """)

    # Tabla 2: Comandos ejecutados en sesiones simuladas
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS session_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            username TEXT NOT NULL,
            command TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

def log_auth_attempt(ip: str, port: int, username: str, password: str, status: str, geo_info: dict, db_path: str = DB_PATH):
    """Registra un intento de login con su informacion de Threat Intel."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO auth_attempts 
        (timestamp, ip, port, username, password, status, country, city, latitude, longitude, isp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.utcnow().isoformat(),
        ip,
        port,
        username,
        password,
        status,
        geo_info.get("country", "Unknown"),
        geo_info.get("city", "Unknown"),
        geo_info.get("lat", 0.0),
        geo_info.get("lon", 0.0),
        geo_info.get("isp", "Unknown")
    ))
    conn.commit()
    conn.close()

def log_command(session_id: str, ip: str, username: str, command: str, db_path: str = DB_PATH):
    """Registra un comando ingresado por el atacante en la fake shell."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO session_commands (session_id, timestamp, ip, username, command)
        VALUES (?, ?, ?, ?, ?)
    """, (
        session_id,
        datetime.utcnow().isoformat(),
        ip,
        username,
        command
    ))
    conn.commit()
    conn.close()
