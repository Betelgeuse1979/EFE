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


def init_contact_book(db_path: Path = DB_PATH) -> None:
    init_contacts_db(db_path)


def import_contact_key(key_file: Path, verified: bool = False, db_path: Path = DB_PATH) -> dict:
    record = load_public_key_record(key_file)
    add_contact(record, verified=verified, db_path=db_path)
    return record


def get_all_contacts(db_path: Path = DB_PATH):
    return list_contacts(db_path)


def get_contact(email: str, db_path: Path = DB_PATH):
    return get_contact_by_email(email, db_path)


def mark_contact_verified(email: str, db_path: Path = DB_PATH) -> bool:
    return verify_contact_key(email, db_path)


def is_contact_verified(email: str, db_path: Path = DB_PATH) -> bool:
    contact = get_contact(email, db_path)
    return bool(contact and contact["verified"])
