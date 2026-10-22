"""Startpunkt der Login-Anwendung.

Was macht dieser Code:
    Startet den HTTP-Server der Anwendung.
Wie funktioniert er:
    Beim direkten Ausführen wird die Funktion ``run_server`` aus ``server.py``
    aufgerufen.
Welche Args nimmt er:
    Keine Kommandozeilenargumente.
"""

from server import run_server


if __name__ == "__main__":
    run_server()
