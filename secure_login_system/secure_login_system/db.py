"""
db.py
------
SQLite data access layer. Every query uses parameterized placeholders
(`?`) — user input is NEVER interpolated into SQL strings — which is
the standard defense against SQL injection.
"""

import os
import sqlite3
from datetime import datetime

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "users.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            failed_login_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            success INTEGER NOT NULL,
            reason TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------
# User queries — every value is passed as a bound parameter (the `?`
# placeholders below), never string-formatted into the SQL text.
# ---------------------------------------------------------------------
def get_user_by_username(username: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


def get_user_by_email(email: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return row


def get_user_by_id(user_id: int):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


def create_user(username: str, email: str, password_hash: str) -> int:
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (username, email, password_hash, datetime.utcnow().isoformat()),
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    return user_id


def set_totp_secret(user_id: int, secret: str):
    conn = get_db()
    conn.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id))
    conn.commit()
    conn.close()


def enable_totp(user_id: int):
    conn = get_db()
    conn.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def disable_totp(user_id: int):
    conn = get_db()
    conn.execute("UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def record_login_attempt(username: str, success: bool, reason: str = ""):
    conn = get_db()
    conn.execute(
        "INSERT INTO login_events (username, success, reason, created_at) VALUES (?, ?, ?, ?)",
        (username, 1 if success else 0, reason, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def increment_failed_attempts(username: str) -> int:
    conn = get_db()
    conn.execute(
        "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?",
        (username,),
    )
    row = conn.execute(
        "SELECT failed_login_attempts FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.commit()
    conn.close()
    return row["failed_login_attempts"] if row else 0


def reset_failed_attempts(username: str):
    conn = get_db()
    conn.execute(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE username = ?",
        (username,),
    )
    conn.commit()
    conn.close()


def set_locked_until(username: str, locked_until_iso: str):
    conn = get_db()
    conn.execute("UPDATE users SET locked_until = ? WHERE username = ?", (locked_until_iso, username))
    conn.commit()
    conn.close()
