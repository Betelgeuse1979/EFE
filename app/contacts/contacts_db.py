import sqlite3
from pathlib import Path
from typing import Any

from app.config.settings import DB_PATH


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def create_contacts_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            display_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            public_key TEXT NOT NULL,
            key_fingerprint TEXT NOT NULL,
            generated_by_app TEXT,
            app_version TEXT,
            created_at TEXT NOT NULL,
            verified BOOLEAN DEFAULT FALSE
        )
        """
    )
    connection.commit()


def init_contacts_db(db_path: Path = DB_PATH) -> None:
    connection = get_connection(db_path)
    try:
        create_contacts_table(connection)
    finally:
        connection.close()


def add_contact(contact: dict[str, Any], verified: bool = False, db_path: Path = DB_PATH) -> int:
    connection = get_connection(db_path)
    try:
        create_contacts_table(connection)
        cursor = connection.execute(
            """
            INSERT INTO contacts (
                display_name, email, public_key, key_fingerprint,
                generated_by_app, app_version, created_at, verified
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                display_name=excluded.display_name,
                public_key=excluded.public_key,
                key_fingerprint=excluded.key_fingerprint,
                generated_by_app=excluded.generated_by_app,
                app_version=excluded.app_version,
                created_at=excluded.created_at,
                verified=excluded.verified
            """,
            (
                contact["display_name"],
                contact["email"],
                contact["public_key"],
                contact["key_fingerprint"],
                contact.get("generated_by_app"),
                contact.get("app_version"),
                contact["created_at"],
                int(verified),
            ),
        )
        connection.commit()
        if cursor.lastrowid:
            return int(cursor.lastrowid)
        saved = connection.execute("SELECT id FROM contacts WHERE email = ?", (contact["email"],)).fetchone()
        return int(saved["id"])
    finally:
        connection.close()


def list_contacts(db_path: Path = DB_PATH) -> list[sqlite3.Row]:
    connection = get_connection(db_path)
    try:
        create_contacts_table(connection)
        return list(connection.execute("SELECT * FROM contacts ORDER BY display_name, email"))
    finally:
        connection.close()


def get_contact_by_email(email: str, db_path: Path = DB_PATH) -> sqlite3.Row | None:
    connection = get_connection(db_path)
    try:
        create_contacts_table(connection)
        return connection.execute("SELECT * FROM contacts WHERE email = ?", (email,)).fetchone()
    finally:
        connection.close()


def verify_contact_key(email: str, db_path: Path = DB_PATH) -> bool:
    connection = get_connection(db_path)
    try:
        create_contacts_table(connection)
        cursor = connection.execute("UPDATE contacts SET verified = TRUE WHERE email = ?", (email,))
        connection.commit()
        return cursor.rowcount > 0
    finally:
        connection.close()
