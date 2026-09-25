"""Datenbankzugriff und Initialisierung der SQLite-Struktur."""

import sqlite3

from .config import DATABASE


def get_connection():
    """Öffnet eine neue SQLite-Verbindung mit sinnvollen Standardeinstellungen.

    row_factory wird auf sqlite3.Row gesetzt, damit die Abfragen wie
    Dictionaries gelesen werden können. foreign_keys = ON verhindert inkonsistente
    Verweise zwischen Nutzern und Sessions.
    """
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialise_database():
    """Stellt sicher, dass alle benötigten Tabellen existieren.

    Die Tabellen werden nur angelegt, falls sie noch nicht vorhanden sind.
    Dadurch ist das Programm bei einem frischen Start sofort nutzbar, ohne das
    Schema manuell zu erstellen. Bei bereits existierenden Datenbanken werden
    vorhandene Strukturen zusätzlich auf die aktuellen Felder erweitert.
    """
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                email_verified INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (email)
                    REFERENCES users(email) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS email_verification_tokens (
                token_hash TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (email)
                    REFERENCES users(email) ON DELETE CASCADE
            );
            """
        )

        user_columns = connection.execute("PRAGMA table_info(users)").fetchall()
        if not any(column[1] == "email_verified" for column in user_columns):
            connection.execute(
                "ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0"
            )