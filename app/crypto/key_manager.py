import base64
import binascii
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from app.config.settings import (
    APP_NAME,
    APP_VERSION,
    PRIVATE_KEY_PATH,
    PUBLIC_KEY_RECORD_PATH,
    ensure_data_dirs,
)
from app.crypto.fingerprint import calculate_fingerprint


def _public_key_to_text(public_key: x25519.X25519PublicKey) -> str:
    raw_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw_key).decode("ascii")


def _require_passphrase(passphrase: bytes) -> None:
    if not passphrase:
        raise ValueError("A private key passphrase is required.")


def validate_public_key_text(public_key_text: str) -> str:
    """Validate and return the canonical base64 text for an X25519 public key."""
    try:
        raw_key = base64.b64decode(public_key_text.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("Public key is not valid base64.") from exc

    if len(raw_key) != 32:
        raise ValueError("Public key must decode to 32 bytes for X25519.")

    try:
        public_key = x25519.X25519PublicKey.from_public_bytes(raw_key)
    except ValueError as exc:
        raise ValueError("Public key is not a valid X25519 public key.") from exc

    return _public_key_to_text(public_key)


def load_private_key(
    private_key_path: Path = PRIVATE_KEY_PATH,
    passphrase: bytes | None = None,
) -> x25519.X25519PrivateKey:
    key_bytes = private_key_path.read_bytes()
    if b"BEGIN PRIVATE KEY" in key_bytes and b"BEGIN ENCRYPTED PRIVATE KEY" not in key_bytes:
        raise ValueError(
            "Unencrypted private keys from older MVP versions are not supported. "
            "Regenerate your EFE key pair."
        )
    try:
        return serialization.load_pem_private_key(key_bytes, password=passphrase)
    except (TypeError, ValueError) as exc:
        raise ValueError("Could not unlock the private key. Check the passphrase.") from exc


def generate_user_key_pair(
    display_name: str,
    email: str,
    passphrase: bytes,
    private_key_path: Path = PRIVATE_KEY_PATH,
    public_key_record_path: Path = PUBLIC_KEY_RECORD_PATH,
    overwrite: bool = False,
) -> dict[str, str]:
    _require_passphrase(passphrase)
    ensure_data_dirs()
    if private_key_path.exists() and not overwrite:
        raise FileExistsError(f"Private key already exists: {private_key_path}")

    private_key = x25519.X25519PrivateKey.generate()
    public_key_text = _public_key_to_text(private_key.public_key())
    created_at = datetime.now(timezone.utc).isoformat()
    record = {
        "display_name": display_name,
        "email": email,
        "public_key": public_key_text,
        "key_fingerprint": calculate_fingerprint(public_key_text),
        "generated_by_app": APP_NAME,
        "app_version": APP_VERSION,
        "created_at": created_at,
    }

    # Security decision: the private key is encrypted at rest and is never copied
    # into the public export record or database. The passphrase is never stored.
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    private_key_path.write_bytes(private_bytes)
    public_key_record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def export_public_key(export_path: Path, public_key_record_path: Path = PUBLIC_KEY_RECORD_PATH) -> Path:
    ensure_data_dirs()
    if not public_key_record_path.exists():
        raise FileNotFoundError("No user public key found. Run init-user-key first.")
    export_path.write_text(public_key_record_path.read_text(encoding="utf-8"), encoding="utf-8")
    return export_path


def load_public_key_record(path: Path) -> dict[str, str]:
    record = json.loads(path.read_text(encoding="utf-8"))
    required = {"display_name", "email", "public_key", "key_fingerprint", "created_at"}
    missing = required - set(record)
    if missing:
        raise ValueError(f"Public key record is missing: {', '.join(sorted(missing))}")

    canonical_public_key = validate_public_key_text(record["public_key"])
    calculated = calculate_fingerprint(canonical_public_key)
    if calculated != record["key_fingerprint"]:
        raise ValueError("Public key fingerprint does not match the key material.")
    record["public_key"] = canonical_public_key
    return record


def public_key_from_text(public_key_text: str) -> x25519.X25519PublicKey:
    canonical_public_key = validate_public_key_text(public_key_text)
    raw_key = base64.b64decode(canonical_public_key.encode("ascii"), validate=True)
    return x25519.X25519PublicKey.from_public_bytes(raw_key)


def get_private_key_fingerprint(private_key_path: Path = PRIVATE_KEY_PATH, passphrase: bytes | None = None) -> str:
    private_key = load_private_key(private_key_path, passphrase=passphrase)
    public_key_text = _public_key_to_text(private_key.public_key())
    return calculate_fingerprint(public_key_text)
