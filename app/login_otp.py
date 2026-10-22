"""TOTP-Zwei-Faktor-Authentifizierung für Authenticator-Apps."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from urllib.parse import quote

from .database import get_connection

OTP_PERIOD = 30
OTP_DIGITS = 6
MAX_OTP_ATTEMPTS = 5
CHALLENGE_LIFETIME = 10 * 60


def generate_totp_secret() -> str:
    """Erzeugt einen geheimen Base32-Schlüssel für eine Authenticator-App."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def build_totp_uri(email: str, secret: str) -> str:
    """Erstellt eine otpauth-URI zur Einrichtung in einer Authenticator-App."""
    issuer = "Login-App"
    label = quote(f"{issuer}:{email}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={OTP_DIGITS}&period={OTP_PERIOD}"
    )


def _totp_code(secret: str, counter: int) -> str:
    """Berechnet den TOTP-Code für einen Zeitabschnitt."""
    padded_secret = secret + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded_secret, casefold=True)
    digest = hmac.new(
        key, counter.to_bytes(8, "big"), hashlib.sha1
    ).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{value % (10 ** OTP_DIGITS):0{OTP_DIGITS}d}"


def verify_totp(secret: str, otp: str) -> bool:
    """Prüft einen TOTP-Code mit einer kleinen Zeitabweichung von einem Abschnitt."""
    if len(otp) != OTP_DIGITS or not otp.isdigit():
        return False
    counter = int(time.time()) // OTP_PERIOD
    return any(
        hmac.compare_digest(_totp_code(secret, counter + offset), otp)
        for offset in (-1, 0, 1)
    )


def create_login_challenge(email: str) -> str:
    """Speichert eine kurz gültige Challenge nach erfolgreicher Passwortprüfung."""
    challenge = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + CHALLENGE_LIFETIME
    with get_connection() as connection:
        connection.execute("DELETE FROM login_otp_tokens WHERE email = ?", (email,))
        connection.execute(
            "INSERT INTO login_otp_tokens "
            "(token_hash, email, otp_hash, expires_at) VALUES (?, ?, ?, ?)",
            (hashlib.sha256(challenge.encode()).hexdigest(), email, "", expires_at),
        )
    return challenge


def verify_login_otp(challenge: str, otp: str) -> str | None:
    """Prüft Challenge und TOTP-Code und gibt bei Erfolg die E-Mail zurück."""
    challenge_hash = hashlib.sha256(challenge.encode()).hexdigest()
    now = int(time.time())
    with get_connection() as connection:
        row = connection.execute(
            "SELECT email, attempts FROM login_otp_tokens "
            "WHERE token_hash = ? AND expires_at > ?",
            (challenge_hash, now),
        ).fetchone()
        if row is None or row["attempts"] >= MAX_OTP_ATTEMPTS:
            return None

        user = connection.execute(
            "SELECT totp_secret FROM users WHERE email = ?", (row["email"],)
        ).fetchone()
        if user is None or not verify_totp(user["totp_secret"], otp):
            connection.execute(
                "UPDATE login_otp_tokens SET attempts = attempts + 1 "
                "WHERE token_hash = ?",
                (challenge_hash,),
            )
            return None

        connection.execute(
            "DELETE FROM login_otp_tokens WHERE token_hash = ?", (challenge_hash,)
        )
        return row["email"]
