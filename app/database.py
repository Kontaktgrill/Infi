"""Datenbankzugriff und Initialisierung der SQLite-Struktur."""

import sqlite3

from .config import DATABASE


def get_connection() -> sqlite3.Connection:
    """Öffnet eine SQLite-Verbindung mit den benötigten Einstellungen."""
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialise_database() -> None:
    """Erstellt das Schema und ergänzt fehlende Spalten älterer Datenbanken."""
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                email_verified INTEGER NOT NULL DEFAULT 0,
                totp_secret TEXT
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

            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                token_hash TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (email)
                    REFERENCES users(email) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS login_otp_tokens (
                token_hash TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (email)
                    REFERENCES users(email) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS login_email_tokens (
                token_hash TEXT PRIMARY KEY,
                challenge_hash TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                confirmed INTEGER NOT NULL DEFAULT 0,
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
        if not any(column[1] == "totp_secret" for column in user_columns):
            connection.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")