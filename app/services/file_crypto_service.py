from datetime import datetime, timezone
from pathlib import Path

from app.config.settings import DB_PATH, PRIVATE_KEY_PATH
from app.crypto.decrypt import decrypt_file
from app.crypto.encrypt import default_encrypted_output_path, encrypt_file_for_contact
from app.crypto.streaming_encrypt import default_v2_encrypted_output_path, encrypt_file_for_contact_streaming
from app.exceptions import ContactNotFoundError, OutputExistsError
from app.services.audit_service import record_audit_entry
from app.services.contact_service import get_contact
from app.services.key_service import get_user_key_fingerprint


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_record_audit_entry(**kwargs) -> None:
    try:
        record_audit_entry(**kwargs)
    except Exception:
        # Audit failures must not hide the original encrypt/decrypt result.
        pass


def encryption_preflight(
    input_path: Path,
    recipient_email: str,
    output_path: Path | None = None,
    db_path: Path = DB_PATH,
    format_version: str = "v1",
) -> dict:
    """Return encrypt readiness information as a plain dictionary for CLI/GUI use."""
    contact = get_contact(recipient_email, db_path)
    if contact is None:
        raise ContactNotFoundError(f"No contact found for {recipient_email}")

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if not input_path.is_file():
        raise IsADirectoryError(f"Input path is not a file: {input_path}")
    if format_version == "v1":
        resolved_output_path = output_path or default_encrypted_output_path()
    elif format_version == "v2":
        resolved_output_path = output_path or default_v2_encrypted_output_path()
    else:
        raise ValueError("Unsupported EFE format version.")

    if resolved_output_path.exists():
        raise OutputExistsError(f"Output file already exists: {resolved_output_path}")

    return {
        "recipient_email": contact["email"],
        "recipient_display_name": contact["display_name"],
        "recipient_verified": bool(contact["verified"]),
        "recipient_key_fingerprint": contact["key_fingerprint"],
        "input_path": str(input_path),
        "output_path": str(resolved_output_path),
        "format_version": format_version,
    }


def encrypt_file_for_recipient(
    input_path: Path,
    recipient_email: str,
    output_path: Path | None = None,
    db_path: Path = DB_PATH,
    format_version: str = "v1",
) -> dict:
    try:
        preflight = encryption_preflight(input_path, recipient_email, output_path, db_path, format_version)
    except ContactNotFoundError as exc:
        _safe_record_audit_entry(
            timestamp=_now(),
            action_type="encrypt",
            filename=input_path.name,
            recipient_email=recipient_email,
            key_fingerprint=None,
            success=False,
            error_message=str(exc),
            db_path=db_path,
        )
        raise

    contact = get_contact(recipient_email, db_path)

    try:
        if format_version == "v2":
            encrypted_path = encrypt_file_for_contact_streaming(input_path, dict(contact), Path(preflight["output_path"]))
        else:
            encrypted_path = encrypt_file_for_contact(input_path, dict(contact), Path(preflight["output_path"]))
        _safe_record_audit_entry(
            timestamp=_now(),
            action_type="encrypt",
            filename=input_path.name,
            recipient_email=contact["email"],
            key_fingerprint=contact["key_fingerprint"],
            success=True,
            db_path=db_path,
        )
        return {
            "output_path": str(encrypted_path),
            "recipient_email": contact["email"],
            "key_fingerprint": contact["key_fingerprint"],
            "recipient_verified": preflight["recipient_verified"],
            "format_version": format_version,
        }
    except Exception as exc:
        _safe_record_audit_entry(
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
) -> dict:
    key_fingerprint = None
    try:
        key_fingerprint = get_user_key_fingerprint(passphrase, private_key_path=private_key_path)
        decrypted_path = decrypt_file(
            input_path,
            output_path,
            private_key_path=private_key_path,
            passphrase=passphrase,
        )
        _safe_record_audit_entry(
            timestamp=_now(),
            action_type="decrypt",
            filename=input_path.name,
            recipient_email=None,
            key_fingerprint=key_fingerprint,
            success=True,
            db_path=db_path,
        )
        return {
            "output_path": str(decrypted_path),
            "key_fingerprint": key_fingerprint,
        }
    except Exception as exc:
        _safe_record_audit_entry(
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
