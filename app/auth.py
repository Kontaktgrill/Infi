"""Sicherheitsrelevante Funktionen für Passwort-Hashing und Session-Management."""

import hashlib
import secrets
import time

from .config import SESSION_LIFETIME
from .database import get_connection


def hash_password(password, salt=None):
    """Hash ein Klartext-Passwort mit scrypt und einem zufälligen Salt.

    Das Passwort wird niemals im Klartext gespeichert. Jeder Benutzer bekommt einen
    eigenen Salt, wodurch identische Passwörter auch bei gleichem Passwort nicht
    dieselbe Hash-Kette erzeugen.
    """
    salt = salt or secrets.token_bytes(16)
    password_hash = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1
    )
    return f"scrypt${salt.hex()}${password_hash.hex()}"


def verify_password(password, stored_hash):
    """Prüft, ob ein eingegebenes Passwort zum gespeicherten Hash passt.

    Der gespeicherte Wert enthält Algorithmus, Salt und Hash. Dadurch kann die
    Prüfung mit exakt demselben scrypt-Verfahren erneut erfolgen, ohne das
    Originalpasswort zu kennen.
    """
    try:
        algorithm, salt_hex, hash_hex = stored_hash.split("$", 2)
        if algorithm != "scrypt":
            return False
        calculated_hash = hash_password(
            password, bytes.fromhex(salt_hex)
        ).split("$", 2)[2]
        return secrets.compare_digest(calculated_hash, hash_hex)
    except (ValueError, TypeError):
        return False


def hash_session_token(token):
    """Erzeugt einen Hash eines Session-Tokens.

    Der Token selbst wird nicht in der Datenbank gespeichert. Dadurch bleibt die
    Session-Logik robuster, falls die Datenbank einmal ausgelesen wird.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(email):
    """Erzeugt eine neue Session für eine E-Mail-Adresse.

    Ein zufälliger Token wird als Login-Token ausgegeben. In der Datenbank wird
    nur der Hash des Tokens gespeichert, damit die Session später geprüft werden
    kann, ohne das Originaltoken dauerhaft zu speichern.
    """
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + SESSION_LIFETIME
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO sessions (token_hash, email, expires_at) "
            "VALUES (?, ?, ?)",
            (hash_session_token(token), email, expires_at),
        )
    return token, expires_at


def find_active_session(token):
    """Prüft, ob ein Session-Token noch gültig ist und liefert den Benutzer.

    Eine Session gilt nur dann als aktiv, wenn der Hash des Tokens gefunden wird
    und der Ablaufzeitpunkt noch in der Zukunft liegt. Abgelaufene Einträge werden
    dabei sofort aufgeräumt.
    """
    now = int(time.time())
    with get_connection() as connection:
        row = connection.execute(
            "SELECT email FROM sessions WHERE token_hash = ? AND expires_at > ?",
            (hash_session_token(token), now),
        ).fetchone()
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
    return row["email"] if row else None


def delete_session(token):
    """Löscht eine Session anhand des Tokens aus der Datenbank."""
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM sessions WHERE token_hash = ?", (hash_session_token(token),)
        )