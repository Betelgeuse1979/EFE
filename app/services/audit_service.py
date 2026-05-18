from pathlib import Path

from app.audit.audit_log import init_audit_db, list_audit_log, log_action
from app.config.settings import DB_PATH


def init_audit_log(db_path: Path = DB_PATH) -> None:
    init_audit_db(db_path)


def record_audit_entry(
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
    return log_action(
        timestamp=timestamp,
        action_type=action_type,
        filename=filename,
        recipient_email=recipient_email,
        key_fingerprint=key_fingerprint,
        success=success,
        error_message=error_message,
        db_path=db_path,
    )


def get_audit_entries(db_path: Path = DB_PATH):
    return list_audit_log(db_path)
