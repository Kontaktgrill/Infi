## Github Repository
https://github.com/Kontaktgrill/Infi.git
# Kurze Beschreibung

 

Dieses Projekt ist eine kleine webbasierte Login-Anwendung. Sie stellt eine
deutsche Benutzeroberfläche für Registrierung, Anmeldung und
Passwortverwaltung bereit. Der Server und die API sind in Python umgesetzt,
die Benutzeroberfläche besteht aus HTML, CSS und JavaScript. Als Datenbank
wird SQLite verwendet.

## Projekt aufsetzen

### Voraussetzungen

- Python 3.10 oder neuer
- Ein SMTP-Konto zum Versenden von Bestätigungs- und
  Passwort-Reset-E-Mails

Das Projekt verwendet ausschließlich Python-Standardbibliotheken. Eine
Installation zusätzlicher Pakete über `pip` ist daher nicht erforderlich.

### Installation und Start

1. Repository herunterladen oder klonen und in das Projektverzeichnis
   wechseln:

   ```powershell
   cd ../Infi
   ```

2. Die E-Mail-Einstellungen in
   [`app/config.py`](./app/config.py) prüfen und anpassen. Dazu gehören
   insbesondere SMTP-Host, Port, Benutzername, Passwort, Absenderadresse und
   die Basis-URL der Anwendung. Zugangsdaten sollten nicht in einem
   öffentlichen Repository gespeichert werden.

3. Den Server starten:

   ```powershell
   python main.py
   ```

4. Die Anwendung im Browser öffnen:

   [http://127.0.0.1:8020](http://127.0.0.1:8020)

Beim Start wird die SQLite-Datenbank `users.db` automatisch initialisiert.
Die Standardadresse des Servers ist `127.0.0.1`, der Standardport ist `8020`.
Beide Werte können in [`app/config.py`](./app/config.py) geändert werden.

## Wichtigste Features

### Registrierung und E-Mail-Bestätigung

Neue Benutzer können sich mit ihrer E-Mail-Adresse und einem Passwort
registrieren. Nach der Registrierung wird eine Bestätigungs-E-Mail versendet.
Die E-Mail-Adresse wird erst nach dem Aufrufen des Bestätigungslinks als
verifiziert markiert.

### Mehrstufige Anmeldung

Die Anmeldung besteht aus mehreren Sicherheitsstufen:

1. Prüfung von E-Mail-Adresse und Passwort.
2. Bestätigung des Login-Versuchs über einen Link per E-Mail.
3. Eingabe eines zeitbasierten Einmalpassworts (TOTP) aus einer
   Authenticator-App, zum Beispiel Google Authenticator, Microsoft
   Authenticator oder Authy.

Beim ersten erforderlichen TOTP-Schritt stellt die Anwendung den geheimen
Authenticator-Schlüssel und die passende `otpauth`-URI bereit.

### Sichere Passwort- und Token-Verarbeitung

- Passwörter werden mit `scrypt` gehasht und nicht im Klartext gespeichert.
- Sitzungs-, Bestätigungs- und Reset-Tokens werden nur als Hashes in der
  Datenbank abgelegt.
- Tokens und Login-Challenges sind zeitlich begrenzt.
- Für die TOTP-Eingabe gibt es eine Begrenzung der Fehlversuche.

### Passwort zurücksetzen

Über **Passwort vergessen?** kann ein Benutzer einen Reset-Link anfordern.
Der Link wird per E-Mail versendet, ist zeitlich begrenzt und kann nur einmal
verwendet werden.

### Sitzungsverwaltung

Nach erfolgreicher Anmeldung wird eine serverseitige Sitzung mit einem
zeitlich begrenzten Cookie erstellt. Angemeldete Benutzer können ihre Sitzung
über die Abmeldefunktion beenden.

### Responsive Oberfläche

Die HTML-Oberfläche ist für unterschiedliche Bildschirmgrößen ausgelegt und
enthält getrennte Ansichten für Anmeldung, Registrierung, E-Mail-Bestätigung,
TOTP-Eingabe und Passwort-Reset.

## Wichtige Dateien

- [`main.py`](./main.py): Einstiegspunkt zum Starten des Servers
- [`server.py`](./server.py): HTTP-Server und API-Endpunkte
- [`app/config.py`](./app/config.py): Server-, Datenbank- und SMTP-Konfiguration
- [`app/database.py`](./app/database.py): SQLite-Verbindung und
  Datenbankinitialisierung
- [`app/auth.py`](./app/auth.py): Passwort-Hashing und Sitzungsverwaltung
- [`app/login_otp.py`](./app/login_otp.py): TOTP-Authentifizierung
- [`app/verification_email.py`](./app/verification_email.py):
  E-Mail-Bestätigung
- [`app/password_reset.py`](./app/password_reset.py): Passwort-Reset
- [`static/`](./static/): HTML-, CSS- und JavaScript-Dateien der
  Benutzeroberfläche
