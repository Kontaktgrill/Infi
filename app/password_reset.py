"""Erzeugt und verarbeitet zeitlich begrenzte Passwort-Reset-Tokens."""

from __future__ import annotations

import hashlib
import secrets
import smtplib
import time
from email.message import EmailMessage
from urllib.parse import quote

from .config import (
    APP_BASE_URL,
    EMAIL_FROM,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USE_TLS,
    SMTP_USERNAME,
)
from .database import get_connection

PASSWORD_RESET_LIFETIME = 60 * 60


def generate_reset_token() -> str:
    """Erzeugt ein kryptografisch sicheres Reset-Token."""
    return secrets.token_urlsafe(32)


def hash_reset_token(token: str) -> str:
    """Hasht ein Reset-Token für die sichere Speicherung."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def store_reset_token(email: str, token: str) -> int:
    """Speichert ein neues, einstündig gültiges Reset-Token."""
    expires_at = int(time.time()) + PASSWORD_RESET_LIFETIME
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM password_reset_tokens WHERE email = ?", (email,)
        )
        connection.execute(
            "INSERT INTO password_reset_tokens (token_hash, email, expires_at) "
            "VALUES (?, ?, ?)",
            (hash_reset_token(token), email, expires_at),
        )
    return expires_at


def consume_reset_token(token: str, password_hash: str) -> bool:
    """Ändert das Passwort und verbraucht ein gültiges Token."""
    now = int(time.time())
    with get_connection() as connection:
        row = connection.execute(
            "SELECT email FROM password_reset_tokens "
            "WHERE token_hash = ? AND expires_at > ?",
            (hash_reset_token(token), now),
        ).fetchone()
        if row is None:
            return False
        connection.execute(
            "UPDATE users SET password_hash = ? WHERE email = ?",
            (password_hash, row["email"]),
        )
        connection.execute(
            "DELETE FROM password_reset_tokens WHERE token_hash = ?",
            (hash_reset_token(token),),
        )
        return True


def send_password_reset_email(
    recipient_email: str, reset_token: str, *, base_url: str | None = None
) -> None:
    """Erstellt und versendet eine Passwort-Reset-E-Mail."""
    base = (base_url or APP_BASE_URL).rstrip("/")
    reset_link = f"{base}/reset.html?token={quote(reset_token, safe='')}"
    message = EmailMessage()
    message["Subject"] = "Passwort zurücksetzen"
    message["From"] = EMAIL_FROM
    message["To"] = recipient_email
    message.set_content(
        "Klicken Sie auf den folgenden Link, um Ihr Passwort zurückzusetzen:\n\n"
        f"{reset_link}\n\nDieser Link ist eine Stunde gültig."
    )
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp_server:
        if SMTP_USE_TLS:
            smtp_server.starttls()
        if SMTP_USERNAME and SMTP_PASSWORD:
            smtp_server.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp_server.send_message(message)
