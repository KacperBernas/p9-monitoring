
import sqlite3
from pathlib import Path

DATABASE_PATH = Path("/app/data/security.db")


def get_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_database():
    connection = get_connection()

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                username TEXT,
                ip_address TEXT,
                endpoint TEXT,
                result TEXT NOT NULL,
                details TEXT,
                request_id TEXT
            )
        """)

        columns = connection.execute(
            "PRAGMA table_info(security_events)"
        ).fetchall()

        column_names = {column["name"] for column in columns}

        if "request_id" not in column_names:
            connection.execute(
                "ALTER TABLE security_events ADD COLUMN request_id TEXT"
            )

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN'
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            )
        """)

        connection.commit()

    finally:
        connection.close()
