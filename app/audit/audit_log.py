import sqlite3
from pathlib import Path

from app.config.settings import DB_PATH


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def create_audit_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action_type TEXT NOT NULL CHECK(action_type IN ('encrypt', 'decrypt')),
            filename TEXT NOT NULL,
            recipient_email TEXT,
            key_fingerprint TEXT,
            success BOOLEAN NOT NULL,
            error_message TEXT
        )
        """
    )
    connection.commit()


def init_audit_db(db_path: Path = DB_PATH) -> None:
    connection = get_connection(db_path)
    try:
        create_audit_table(connection)
    finally:
        connection.close()


def log_action(
    *,
    timestamp: str,
    action_type: str,
    filename: str,
    recipient_email: str | None,
    key_fingerprint: str | None,
    success: bool,
    error_message: str | None = None,
    db_path: Path = DB_PATH,
) -> int:
    connection = get_connection(db_path)
    try:
        create_audit_table(connection)
        cursor = connection.execute(
            """
            INSERT INTO audit_log (
                timestamp, action_type, filename, recipient_email,
                key_fingerprint, success, error_message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                action_type,
                filename,
                recipient_email,
                key_fingerprint,
                int(success),
                error_message,
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)
    finally:
        connection.close()


def list_audit_log(db_path: Path = DB_PATH) -> list[sqlite3.Row]:
    connection = get_connection(db_path)
    try:
        create_audit_table(connection)
        return list(connection.execute("SELECT * FROM audit_log ORDER BY id DESC"))
    finally:
        connection.close()
