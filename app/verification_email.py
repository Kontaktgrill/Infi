"""Hilfsfunktionen zum Versenden von Verifikations-E-Mails."""

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


def send_email(message: EmailMessage) -> None:
    """Versendet eine vorbereitete E-Mail über die konfigurierte SMTP-Verbindung."""
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp_server:
        if SMTP_USE_TLS:
            smtp_server.starttls()
        if SMTP_USERNAME and SMTP_PASSWORD:
            smtp_server.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp_server.send_message(message)


def generate_verification_token() -> str:
    """Erzeugt ein kryptografisch sicheres Verifikations-Token."""
    return secrets.token_urlsafe(32)


def hash_verification_token(token: str) -> str:
    """Hasht ein Verifikations-Token für die sichere Speicherung."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def build_verification_link(token: str, base_url: str | None = None) -> str:
    """Erstellt den URL-kodierten Link zur E-Mail-Bestätigung."""
    base = (base_url or APP_BASE_URL).rstrip("/")
    return f"{base}/verify?token={quote(token, safe='')}"


def store_verification_token(email: str, token: str, expires_in: int = 60 * 60 * 24) -> int:
    """Speichert ein Verifikations-Token mit Ablaufzeit."""
    expires_at = int(time.time()) + expires_in
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO email_verification_tokens (token_hash, email, expires_at) "
            "VALUES (?, ?, ?)",
            (hash_verification_token(token), email, expires_at),
        )
    return expires_at


def verify_email_token(token: str) -> str | None:
    """Aktiviert die E-Mail-Adresse und verbraucht ein gültiges Token."""
    now = int(time.time())
    token_hash = hash_verification_token(token)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT email FROM email_verification_tokens "
            "WHERE token_hash = ? AND expires_at > ?",
            (token_hash, now),
        ).fetchone()
        if row is None:
            return None

        email = row["email"]
        connection.execute(
            "UPDATE users SET email_verified = 1 WHERE email = ?",
            (email,),
        )
        connection.execute(
            "DELETE FROM email_verification_tokens WHERE token_hash = ?",
            (token_hash,),
        )
        return email


def send_verification_email(
    recipient_email: str,
    verification_token: str,
    *,
    base_url: str | None = None,
) -> None:
    """Was: Sendet eine E-Mail zur Adressbestätigung.

    Wie: Erstellt eine Text- und HTML-Nachricht mit dem Verifikations-Link und
    verschickt sie über SMTP.
    Args:
        recipient_email: Empfängeradresse.
        verification_token: Token für den Bestätigungs-Link.
        base_url: Optionale Basis-URL der Anwendung.
    """
    verification_link = build_verification_link(verification_token, base_url)

    message = EmailMessage()
    message["Subject"] = "Bestätigen Sie Ihre E-Mail-Adresse"
    message["From"] = EMAIL_FROM
    message["To"] = recipient_email
    message.set_content(
        "Bitte bestätigen Sie Ihre E-Mail-Adresse, indem Sie auf den folgenden "
        "Link klicken:\n\n"
        f"{verification_link}\n\n"
        "Wenn Sie kein Konto erstellt haben, können Sie diese E-Mail "
        "ignorieren."
    )
    message.add_alternative(
        "<html><body>"
        "<p>Bitte bestätigen Sie Ihre E-Mail-Adresse:</p>"
        f"<p><a href=\"{verification_link}\">Bestätigen</a></p>"
        "<p>Wenn Sie kein Konto erstellt haben, ignorieren Sie diese E-Mail.</p>"
        "</body></html>",
        subtype="html",
    )

    send_email(message)


def send_login_confirmation_email(
    recipient_email: str,
    confirmation_token: str,
    *,
    base_url: str | None = None,
) -> None:
    """Versendet den Bestätigungslink für einen einzelnen Login."""
    base = (base_url or APP_BASE_URL).rstrip("/")
    confirmation_link = (
        f"{base}/login-verify?token={quote(confirmation_token, safe='')}"
    )
    message = EmailMessage()
    message["Subject"] = "Login bestätigen"
    message["From"] = EMAIL_FROM
    message["To"] = recipient_email
    message.set_content(
        "Bestätigen Sie den Login, indem Sie auf diesen Link klicken:\n\n"
        f"{confirmation_link}\n\nDieser Link ist zehn Minuten gültig."
    )
    send_email(message)
