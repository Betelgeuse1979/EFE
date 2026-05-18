from pathlib import Path

from app.audit.audit_log import init_audit_db, list_audit_log, log_action
from app.config.settings import DB_PATH
from app.exceptions import AuditLogError


def _row_to_dict(row) -> dict:
    return dict(row)


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
    try:
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
    except Exception as exc:
        raise AuditLogError(f"Could not write audit log entry: {exc}") from exc


def get_audit_entries(db_path: Path = DB_PATH) -> list[dict]:
    """Return audit entries as plain dictionaries suitable for CLI or GUI display."""
    return [_row_to_dict(row) for row in list_audit_log(db_path)]
