"""Sicherheitsrelevante Funktionen für Passwort-Hashing und Session-Management."""

import hashlib
import secrets
import time
from typing import Optional

from .config import SESSION_LIFETIME
from .database import get_connection


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Erzeugt einen scrypt-Hash im Format ``scrypt$salt$hash``."""
    salt = salt or secrets.token_bytes(16)
    password_hash = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1
    )
    return f"scrypt${salt.hex()}${password_hash.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Prüft einen Client-Hash oder einen älteren scrypt-Hash."""
    try:
        if not stored_hash.startswith("scrypt$"):
            return secrets.compare_digest(password, stored_hash)
        algorithm, salt_hex, hash_hex = stored_hash.split("$", 2)
        if algorithm != "scrypt":
            return False
        calculated_hash = hash_password(
            password, bytes.fromhex(salt_hex)
        ).split("$", 2)[2]
        return secrets.compare_digest(calculated_hash, hash_hex)
    except (ValueError, TypeError):
        return False


def hash_session_token(token: str) -> str:
    """Hasht ein Session-Token, bevor es in der Datenbank gespeichert wird."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(email: str) -> tuple[str, int]:
    """Erstellt eine Session und gibt Cookie-Token und Ablaufzeit zurück."""
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + SESSION_LIFETIME
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO sessions (token_hash, email, expires_at) "
            "VALUES (?, ?, ?)",
            (hash_session_token(token), email, expires_at),
        )
    return token, expires_at


def find_active_session(token: str) -> Optional[str]:
    """Liefert die E-Mail einer aktiven Session oder ``None``."""
    now = int(time.time())
    with get_connection() as connection:
        row = connection.execute(
            "SELECT email FROM sessions WHERE token_hash = ? AND expires_at > ?",
            (hash_session_token(token), now),
        ).fetchone()
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
    return row["email"] if row else None


def delete_session(token: str) -> None:
    """Entfernt eine Session anhand ihres Cookie-Tokens."""
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM sessions WHERE token_hash = ?", (hash_session_token(token),)
        )