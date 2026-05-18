from pathlib import Path

from app.config.settings import DB_PATH
from app.contacts.contacts_db import (
    add_contact,
    get_contact_by_email,
    init_contacts_db,
    list_contacts,
    verify_contact_key,
)
from app.crypto.key_manager import load_public_key_record


def _row_to_contact(row) -> dict | None:
    if row is None:
        return None
    contact = dict(row)
    contact["verified"] = bool(contact["verified"])
    return contact


def init_contact_book(db_path: Path = DB_PATH) -> None:
    init_contacts_db(db_path)


def import_contact_key(key_file: Path, verified: bool = False, db_path: Path = DB_PATH) -> dict:
    """Validate, save, and return a public key record as a plain dictionary."""
    record = load_public_key_record(key_file)
    add_contact(record, verified=verified, db_path=db_path)
    return record


def get_all_contacts(db_path: Path = DB_PATH) -> list[dict]:
    """Return saved contacts as plain dictionaries suitable for CLI or GUI display."""
    return [_row_to_contact(row) for row in list_contacts(db_path)]


def get_contact(email: str, db_path: Path = DB_PATH) -> dict | None:
    return _row_to_contact(get_contact_by_email(email, db_path))


def mark_contact_verified(email: str, db_path: Path = DB_PATH) -> bool:
    return verify_contact_key(email, db_path)


def is_contact_verified(email: str, db_path: Path = DB_PATH) -> bool:
    contact = get_contact(email, db_path)
    return bool(contact and contact["verified"])
