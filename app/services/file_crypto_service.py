from datetime import datetime, timezone
from pathlib import Path

from app.config.settings import DB_PATH, PRIVATE_KEY_PATH
from app.crypto.decrypt import decrypt_file
from app.crypto.encrypt import encrypt_file_for_contact
from app.services.audit_service import record_audit_entry
from app.services.contact_service import get_contact
from app.services.key_service import get_user_key_fingerprint


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def encrypt_file_for_recipient(
    input_path: Path,
    recipient_email: str,
    output_path: Path | None = None,
    db_path: Path = DB_PATH,
) -> Path:
    contact = get_contact(recipient_email, db_path)
    if contact is None:
        raise ValueError(f"No contact found for {recipient_email}")

    try:
        encrypted_path = encrypt_file_for_contact(input_path, dict(contact), output_path)
        record_audit_entry(
            timestamp=_now(),
            action_type="encrypt",
            filename=input_path.name,
            recipient_email=contact["email"],
            key_fingerprint=contact["key_fingerprint"],
            success=True,
            db_path=db_path,
        )
        return encrypted_path
    except Exception as exc:
        record_audit_entry(
            timestamp=_now(),
            action_type="encrypt",
            filename=input_path.name,
            recipient_email=recipient_email,
            key_fingerprint=contact["key_fingerprint"],
            success=False,
            error_message=str(exc),
            db_path=db_path,
        )
        raise


def decrypt_received_file(
    input_path: Path,
    passphrase: bytes,
    output_path: Path | None = None,
    private_key_path: Path = PRIVATE_KEY_PATH,
    db_path: Path = DB_PATH,
) -> Path:
    key_fingerprint = None
    try:
        key_fingerprint = get_user_key_fingerprint(passphrase, private_key_path=private_key_path)
        decrypted_path = decrypt_file(
            input_path,
            output_path,
            private_key_path=private_key_path,
            passphrase=passphrase,
        )
        record_audit_entry(
            timestamp=_now(),
            action_type="decrypt",
            filename=input_path.name,
            recipient_email=None,
            key_fingerprint=key_fingerprint,
            success=True,
            db_path=db_path,
        )
        return decrypted_path
    except Exception as exc:
        record_audit_entry(
            timestamp=_now(),
            action_type="decrypt",
            filename=input_path.name,
            recipient_email=None,
            key_fingerprint=key_fingerprint,
            success=False,
            error_message=str(exc),
            db_path=db_path,
        )
        raise
