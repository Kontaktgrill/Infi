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


def generate_verification_token() -> str:
    """Erzeugt einen zufälligen Token für die E-Mail-Verifikation."""
    return secrets.token_urlsafe(32)


def hash_verification_token(token: str) -> str:
    """Hash eines Verifikations-Tokens, damit der echte Token nicht gespeichert wird."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def build_verification_link(token: str, base_url: str | None = None) -> str:
    """Erstellt die vollständige Bestätigungs-URL für einen Token."""
    base = (base_url or APP_BASE_URL).rstrip("/")
    return f"{base}/verify?token={quote(token, safe='')}"


def store_verification_token(email: str, token: str, expires_in: int = 60 * 60 * 24) -> int:
    """Speichert einen Token für die Verifikation in der Datenbank."""
    expires_at = int(time.time()) + expires_in
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO email_verification_tokens (token_hash, email, expires_at) "
            "VALUES (?, ?, ?)",
            (hash_verification_token(token), email, expires_at),
        )
    return expires_at


def verify_email_token(token: str) -> str | None:
    """Validiert einen Token und aktiviert die E-Mail-Adresse des Benutzers."""
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
    """Sendet eine Bestätigungs-E-Mail an die angegebene Adresse."""
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

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp_server:
        if SMTP_USE_TLS:
            smtp_server.starttls()
        if SMTP_USERNAME and SMTP_PASSWORD:
            smtp_server.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp_server.send_message(message)
