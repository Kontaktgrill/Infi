"""E-Mail-Bestätigung für einzelne Login-Versuche."""

from __future__ import annotations

import hashlib
import secrets
import time

from .database import get_connection

LOGIN_EMAIL_LIFETIME = 10 * 60


def create_login_email_challenge(email: str) -> tuple[str, str]:
    """Erstellt einen Login-Schlüssel und das dazugehörige E-Mail-Token."""
    challenge = secrets.token_urlsafe(32)
    email_token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + LOGIN_EMAIL_LIFETIME
    challenge_hash = hashlib.sha256(challenge.encode("utf-8")).hexdigest()
    token_hash = hashlib.sha256(email_token.encode("utf-8")).hexdigest()

    with get_connection() as connection:
        connection.execute(
            "DELETE FROM login_email_tokens WHERE email = ?", (email,)
        )
        connection.execute(
            "INSERT INTO login_email_tokens "
            "(token_hash, challenge_hash, email, confirmed, expires_at) "
            "VALUES (?, ?, ?, 0, ?)",
            (token_hash, challenge_hash, email, expires_at),
        )
    return challenge, email_token


def confirm_login_email(email_token: str) -> bool:
    """Bestätigt ein gültiges E-Mail-Token genau einmal."""
    token_hash = hashlib.sha256(email_token.encode("utf-8")).hexdigest()
    with get_connection() as connection:
        result = connection.execute(
            "UPDATE login_email_tokens SET confirmed = 1 "
            "WHERE token_hash = ? AND confirmed = 0 AND expires_at > ?",
            (token_hash, int(time.time())),
        )
    return result.rowcount == 1


def consume_confirmed_login(email_challenge: str) -> str | None:
    """Verbraucht eine bestätigte Login-Anfrage und gibt die E-Mail zurück."""
    challenge_hash = hashlib.sha256(
        email_challenge.encode("utf-8")
    ).hexdigest()
    with get_connection() as connection:
        row = connection.execute(
            "SELECT email FROM login_email_tokens "
            "WHERE challenge_hash = ? AND confirmed = 1 AND expires_at > ?",
            (challenge_hash, int(time.time())),
        ).fetchone()
        if row is None:
            return None
        connection.execute(
            "DELETE FROM login_email_tokens WHERE challenge_hash = ?",
            (challenge_hash,),
        )
        return row["email"]
