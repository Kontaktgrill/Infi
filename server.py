import http.server
import json
import sqlite3
from http import cookies
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
from app.verification_email import (
    generate_verification_token,
    send_verification_email,
    store_verification_token,
    verify_email_token,
)


def is_valid_email(email):
    if not email or any(character.isspace() for character in email):
        return False
    if email.count("@") != 1:
        return False
    local_part, domain = email.split("@")
    return bool(local_part and domain and "." in domain)


def send_json(handler, status, payload, extra_headers=None):
    response = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(response)))
    for name, value in (extra_headers or {}).items():
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(response)


def get_cookie_value(handler, name):
    request_cookies = cookies.SimpleCookie(handler.headers.get("Cookie", ""))
    cookie = request_cookies.get(name)
    return cookie.value if cookie else None


class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, format_string, *args):
        print(f"{self.address_string()} - {format_string % args}")

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            return None

    def do_GET(self):
        if self.path.startswith("/verify"):
            parsed = urlparse(self.path)
            token = parse_qs(parsed.query).get("token", [""])[0]
            if not token:
                self.send_response(400)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<html><body>Fehler: Kein Verifikations-Token vorhanden.</body></html>")
                return

            email = verify_email_token(token)
            if email is None:
                self.send_response(400)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    b"<html><body>Der Verifizierungs-Link ist ung\xc3\xbcltig oder abgelaufen.</body></html>"
                )
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                (
                    f"<html><body>Die E-Mail-Adresse {email} wurde erfolgreich verifiziert.</body></html>"
                ).encode("utf-8")
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
        routes = {
            "/api/register": self.register,
            "/api/login": self.login,
            "/api/logout": self.logout,
        }
        route = routes.get(self.path)
        if route:
            route()
        else:
            send_json(self, 404, {"error": "Endpunkt nicht gefunden."})

    def register(self):
        data = self.read_json()
        email = (
            str(data.get("email", "")).strip().lower()
            if isinstance(data, dict)
            else ""
        )
        password = data.get("password", "") if isinstance(data, dict) else ""
        if not is_valid_email(email):
            send_json(
                self,
                400,
                {"error": "Bitte eine gültige E-Mail-Adresse eingeben."},
            )
            return
        if not isinstance(password, str) or len(password) < 8:
            send_json(
                self,
                400,
                {"error": "Das Passwort muss mindestens 8 Zeichen haben."},
            )
            return

        try:
            with get_connection() as connection:
                connection.execute(
                    "INSERT INTO users (email, password_hash, created_at, email_verified) "
                    "VALUES (?, ?, strftime('%s', 'now'), 0)",
                    (email, hash_password(password)),
                )
        except sqlite3.IntegrityError:
            send_json(
                self,
                409,
                {"error": "Diese E-Mail-Adresse ist bereits registriert."},
            )
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
        data = self.read_json()
        email = (
            str(data.get("email", "")).strip().lower()
            if isinstance(data, dict)
            else ""
        )
        password = data.get("password", "") if isinstance(data, dict) else ""
        with get_connection() as connection:
            user = connection.execute(
                "SELECT email, password_hash, email_verified FROM users WHERE email = ?",
                (email,),
            ).fetchone()
        if user is None or not isinstance(password, str):
            send_json(
                self,
                401,
                {"error": "E-Mail-Adresse oder Passwort ist falsch."},
            )
            return

        if user["email_verified"] != 1:
            send_json(
                self,
                403,
                {"error": "Bitte verifizieren Sie zuerst Ihre E-Mail-Adresse."},
            )
            return

        if not verify_password(password, user["password_hash"]):
            send_json(
                self,
                401,
                {"error": "E-Mail-Adresse oder Passwort ist falsch."},
            )
            return

        token, expires_at = create_session(user["email"])
        cookie = (
            "session="
            f"{token}; HttpOnly; SameSite=Lax; Max-Age={SESSION_LIFETIME}; Path=/"
        )
        send_json(
            self,
            200,
            {
                "message": "Login erfolgreich.",
                "email": user["email"],
                "expires_at": expires_at,
            },
            {"Set-Cookie": cookie},
        )

    def logout(self):
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
    initialise_database()
    server = http.server.ThreadingHTTPServer((HOST, PORT), RequestHandler)
    print(f"Login-App läuft auf http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer beendet.")
    finally:
        server.server_close()