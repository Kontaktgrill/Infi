"""HTTP-Server und API-Endpunkte für Registrierung und Anmeldung.

Was macht dieser Code:
    Liefert die Weboberfläche und verarbeitet Authentifizierungsanfragen.
Wie funktioniert er:
    Der RequestHandler ordnet HTTP-Routen den passenden Methoden zu und
    verwendet Datenbank-, E-Mail-, Session- und OTP-Hilfsfunktionen.
Welche Args nimmt er:
    Der Server verwendet HTTP-Anfragen; ``run_server`` nimmt keine Argumente.
"""

import http.server
import json
import smtplib
import sqlite3
from http import cookies
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from app.auth import (
    create_session,
    delete_session,
    find_active_session,
    hash_password,
    verify_password,
)
from app.config import HOST, PORT, SESSION_LIFETIME, STATIC_DIR
from app.database import get_connection, initialise_database
from app.login_email import (
    confirm_login_email,
    consume_confirmed_login,
    create_login_email_challenge,
)
from app.login_otp import (
    build_totp_uri,
    create_login_challenge,
    generate_totp_secret,
    verify_login_otp,
)
from app.password_reset import (
    consume_reset_token,
    generate_reset_token,
    send_password_reset_email,
    store_reset_token,
)
from app.verification_email import (
    send_login_confirmation_email,
    send_verification_email,
    generate_verification_token,
    store_verification_token,
    verify_email_token,
)


JSON = dict[str, Any]


def is_valid_email(email: str) -> bool:
    """Prüft die einfache E-Mail-Validierung der Anwendung."""
    if not email or any(character.isspace() for character in email):
        return False
    if email.count("@") != 1:
        return False
    local_part, domain = email.split("@")
    return bool(local_part and domain and "." in domain)


def send_json(
    handler: http.server.BaseHTTPRequestHandler,
    status: int,
    payload: JSON,
    extra_headers: Optional[dict[str, str]] = None,
) -> None:
    """Serialisiert eine JSON-Antwort und schreibt sie in die Verbindung."""
    response = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(response)))
    for name, value in (extra_headers or {}).items():
        handler.send_header(name, value)
    handler.end_headers()
    try:
        handler.wfile.write(response)
    except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
        # Der Browser kann die Anfrage abbrechen, nachdem die Antwort feststeht.
        return


def get_cookie_value(
    handler: http.server.BaseHTTPRequestHandler, name: str
) -> Optional[str]:
    """Liest einen Cookie-Wert aus einer Anfrage."""
    request_cookies = cookies.SimpleCookie(handler.headers.get("Cookie", ""))
    cookie = request_cookies.get(name)
    return cookie.value if cookie else None


class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        """Übergibt den Static-Ordner an den Standard-HTTP-Handler."""
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, format_string: str, *args: Any) -> None:
        """Gibt eine kurze Anfrage-Meldung aus."""
        print(f"{self.address_string()} - {format_string % args}")

    def read_json(self) -> Optional[JSON]:
        """Liest den JSON-Body; bei ungültigen Daten kommt ``None`` zurück."""
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def send_error_json(self, status: int, message: str) -> None:
        """Sendet eine standardisierte Fehlerantwort."""
        send_json(self, status, {"error": message})

    @staticmethod
    def get_text(data: Optional[JSON], key: str) -> str:
        """Liest einen Textwert aus Request-Daten oder liefert einen Leerstring."""
        value = data.get(key, "") if data else ""
        return value if isinstance(value, str) else ""

    def send_html(self, status: int, body: str) -> None:
        """Sendet eine einfache HTML-Antwort."""
        encoded_body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded_body)))
        self.end_headers()
        self.wfile.write(encoded_body)

    def do_GET(self):
        """Verarbeitet Verifikation, Session-Abfrage und statische Dateien."""
        if self.path.startswith("/login-verify"):
            parsed = urlparse(self.path)
            token = parse_qs(parsed.query).get("token", [""])[0]
            if not token or not confirm_login_email(token):
                self.send_html(
                    400,
                    "<html><body>Der Login-Bestätigungslink ist ungültig oder abgelaufen.</body></html>",
                )
                return
            self.send_html(
                200,
                "<html><body>Login bestätigt. Kehren Sie zur Login-Seite zurück.</body></html>",
            )
            return

        if self.path.startswith("/api/login-email-status"):
            self.login_email_status()
            return

        if self.path.startswith("/verify"):
            parsed = urlparse(self.path)
            token = parse_qs(parsed.query).get("token", [""])[0]
            if not token:
                self.send_html(
                    400,
                    "<html><body>Fehler: Kein Verifikations-Token vorhanden.</body></html>",
                )
                return

            email = verify_email_token(token)
            if email is None:
                self.send_html(
                    400,
                    "<html><body>Der Verifizierungs-Link ist ungültig oder abgelaufen.</body></html>",
                )
                return

            self.send_html(
                200,
                f"<html><body>Die E-Mail-Adresse {email} wurde erfolgreich verifiziert.</body></html>",
            )
            return

        if self.path == "/api/me":
            token = get_cookie_value(self, "session")
            email = find_active_session(token) if token else None
            if email is None:
                send_json(self, 401, {"authenticated": False})
            else:
                send_json(self, 200, {"authenticated": True, "email": email})
            return
        if self.path.startswith("/api/"):
            send_json(self, 404, {"error": "Endpunkt nicht gefunden."})
            return
        super().do_GET()

    def do_POST(self):
        """Ordnet POST-Pfade den passenden API-Handlern zu."""
        routes = {
            "/api/register": self.register,
            "/api/login": self.login,
            "/api/login-email-status": self.login_email_status,
            "/api/logout": self.logout,
            "/api/request-password-reset": self.request_password_reset,
            "/api/reset-password": self.reset_password,
            "/api/verify-login-otp": self.verify_login_otp,
        }
        route = routes.get(self.path)
        if route:
            route()
        else:
            send_json(self, 404, {"error": "Endpunkt nicht gefunden."})

    def register(self):
        """Prüft Registrierungsdaten, legt den Benutzer an und versendet den Link."""
        data = self.read_json()
        email = self.get_text(data, "email").strip().lower()
        password = self.get_text(data, "password")
        if not is_valid_email(email):
            self.send_error_json(400, "Bitte eine gültige E-Mail-Adresse eingeben.")
            return
        if len(password) < 8:
            self.send_error_json(400, "Das Passwort muss mindestens 8 Zeichen haben.")
            return

        try:
            with get_connection() as connection:
                connection.execute(
                    "INSERT INTO users "
                    "(email, password_hash, created_at, email_verified, totp_secret) "
                    "VALUES (?, ?, strftime('%s', 'now'), 0, ?)",
                    (email, hash_password(password), generate_totp_secret()),
                )
        except sqlite3.IntegrityError:
            self.send_error_json(409, "Diese E-Mail-Adresse ist bereits registriert.")
            return

        verification_token = generate_verification_token()
        store_verification_token(email, verification_token)
        try:
            send_verification_email(email, verification_token)
        except Exception as exc:  # pragma: no cover - SMTP-Setup kann lokal fehlen.
            print(f"Verifikations-E-Mail konnte nicht gesendet werden: {exc}")

        send_json(
            self,
            201,
            {
                "message": (
                    "Registrierung erfolgreich. Bitte prüfen Sie Ihre E-Mails, "
                    "um die Adresse zu verifizieren."
                )
            },
        )

    def login(self):
        """Prüft das Passwort und startet die E-Mail-Bestätigung."""
        data = self.read_json()
        email = self.get_text(data, "email").strip().lower()
        password = self.get_text(data, "password")
        with get_connection() as connection:
            user = connection.execute(
                "SELECT email, password_hash, email_verified, totp_secret "
                "FROM users WHERE email = ?",
                (email,),
            ).fetchone()
        if user is None:
            self.send_error_json(401, "E-Mail-Adresse oder Passwort ist falsch.")
            return

        if user["email_verified"] != 1:
            self.send_error_json(403, "Bitte verifizieren Sie zuerst Ihre E-Mail-Adresse.")
            return

        if not verify_password(password, user["password_hash"]):
            self.send_error_json(401, "E-Mail-Adresse oder Passwort ist falsch.")
            return

        totp_secret = user["totp_secret"]
        if not totp_secret:
            totp_secret = generate_totp_secret()
            with get_connection() as connection:
                connection.execute(
                    "UPDATE users SET totp_secret = ? WHERE email = ?",
                    (totp_secret, user["email"]),
                )
        email_challenge, confirmation_token = create_login_email_challenge(
            user["email"]
        )
        try:
            send_login_confirmation_email(user["email"], confirmation_token)
        except (OSError, smtplib.SMTPException) as exc:
            print(f"Login-Bestätigungs-E-Mail konnte nicht gesendet werden: {exc}")
            self.send_error_json(
                503, "Die Login-Bestätigungs-E-Mail konnte nicht gesendet werden."
            )
            return
        send_json(
            self,
            200,
            {
                "message": (
                    "Wir haben eine Login-Bestätigung an Ihre E-Mail-Adresse "
                    "gesendet. Bitte klicken Sie auf den Link."
                ),
                "email_confirmation_required": True,
                "email_challenge": email_challenge,
                "email": user["email"],
            },
        )

    def login_email_status(self):
        """Prüft, ob der Login-Link bereits bestätigt wurde."""
        parsed = urlparse(self.path)
        challenge = parse_qs(parsed.query).get("challenge", [""])[0]
        if not challenge:
            challenge = self.get_text(self.read_json(), "challenge")
        email = consume_confirmed_login(challenge) if challenge else None
        if email is None:
            send_json(self, 202, {"email_confirmed": False})
            return

        self.send_otp_step(email)

    def send_otp_step(self, email: str) -> None:
        """Erzeugt nach der E-Mail-Bestätigung die nächste OTP-Challenge."""
        with get_connection() as connection:
            user = connection.execute(
                "SELECT totp_secret FROM users WHERE email = ?", (email,)
            ).fetchone()
        if user is None or not user["totp_secret"]:
            self.send_error_json(401, "Login konnte nicht fortgesetzt werden.")
            return
        challenge_token = create_login_challenge(email)
        send_json(
            self,
            200,
            {
                "email_confirmed": True,
                "otp_required": True,
                "challenge_token": challenge_token,
                "totp_secret": user["totp_secret"],
                "totp_uri": build_totp_uri(email, user["totp_secret"]),
            },
        )

    def verify_login_otp(self):
        """Prüft den OTP-Code und erstellt danach die Session."""
        data = self.read_json()
        challenge_token = data.get("challenge_token", "") if data else ""
        otp = data.get("otp", "") if data else ""
        if (
            not isinstance(challenge_token, str)
            or not isinstance(otp, str)
            or len(otp) != 6
            or not otp.isdigit()
        ):
            self.send_error_json(400, "Bitte einen sechsstelligen Login-Code eingeben.")
            return
        email = verify_login_otp(challenge_token, otp)
        if email is None:
            self.send_error_json(401, "Der Login-Code ist ungültig oder abgelaufen.")
            return
        token, expires_at = create_session(email)
        cookie = (
            "session="
            f"{token}; HttpOnly; SameSite=Lax; Max-Age={SESSION_LIFETIME}; Path=/"
        )
        send_json(
            self,
            200,
            {
                "message": "Login erfolgreich.",
                "email": email,
                "expires_at": expires_at,
            },
            {"Set-Cookie": cookie},
        )

    def request_password_reset(self):
        """Erstellt bei Bedarf ein Reset-Token und versendet den Reset-Link."""
        data = self.read_json()
        email = self.get_text(data, "email").strip().lower()
        with get_connection() as connection:
            user_exists = connection.execute(
                "SELECT 1 FROM users WHERE email = ?", (email,)
            ).fetchone() is not None

        if user_exists:
            reset_token = generate_reset_token()
            store_reset_token(email, reset_token)
            try:
                send_password_reset_email(email, reset_token)
            except (OSError, smtplib.SMTPException) as exc:
                print(f"Passwort-Reset-E-Mail konnte nicht gesendet werden: {exc}")
                send_json(
                    self,
                    503,
                    {"error": "Die Reset-E-Mail konnte nicht gesendet werden."},
                )
                return

        send_json(
            self,
            200,
            {"message": "Falls ein Konto zu dieser E-Mail-Adresse existiert, "
                        "wurde ein Reset-Link gesendet."},
        )

    def reset_password(self):
        """Prüft den Reset-Link und aktualisiert das Passwort einmalig."""
        data = self.read_json()
        token = data.get("token", "") if data else ""
        password = data.get("password", "") if data else ""
        if not isinstance(token, str) or not isinstance(password, str):
            self.send_error_json(400, "Ungültige Reset-Daten.")
            return
        if len(password) < 8:
            self.send_error_json(400, "Das Passwort muss mindestens 8 Zeichen haben.")
            return
        if not consume_reset_token(token, hash_password(password)):
            self.send_error_json(400, "Der Reset-Link ist ungültig oder abgelaufen.")
            return
        send_json(
            self,
            200,
            {"message": "Passwort erfolgreich geändert. Sie können sich jetzt anmelden."},
        )

    def logout(self):
        """Löscht die aktuelle Session und leert das Session-Cookie."""
        token = get_cookie_value(self, "session")
        if token:
            delete_session(token)
        send_json(
            self,
            200,
            {"message": "Erfolgreich abgemeldet."},
            {"Set-Cookie": "session=; Max-Age=0; Path=/"},
        )


def run_server():
    """Initialisiert die Datenbank und startet den HTTP-Server."""
    initialise_database()
    server = http.server.ThreadingHTTPServer((HOST, PORT), RequestHandler)
    print(f"Login-App läuft auf http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer beendet.")
    finally:
        server.server_close()