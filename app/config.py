"""Zentrale Konfiguration der Webanwendung.

Diese Werte werden von Server- und Auth-Logik gemeinsam genutzt, damit
Pfad, Port, Session-Gültigkeit und E-Mail-Settings an einer Stelle zentral
verwaltet werden.
"""

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE = BASE_DIR / "users.db"
STATIC_DIR = BASE_DIR / "static"
HOST = "127.0.0.1"
PORT = 8020
SESSION_LIFETIME = 60 * 60  # 1 Stunde in Sekunden

APP_BASE_URL = "http://127.0.0.1:8020"
EMAIL_FROM = "noreply@your-app.test"
SMTP_HOST = "sandbox.smtp.mailtrap.io"
SMTP_PORT = 2525
SMTP_USERNAME = "5cdeb6de07a822"
SMTP_PASSWORD = "acbafc5ff95495"
SMTP_USE_TLS = True
