import sqlite3

DATABASE_PATH = "example.db"


def get_connection():
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            hashed_password TEXT,
            is_active BOOLEAN DEFAULT 0,
            otp TEXT,
            otp_expires_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()