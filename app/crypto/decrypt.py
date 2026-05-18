import base64
import binascii
import json
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from app.config.settings import DECRYPTED_DIR, ensure_data_dirs
from app.crypto.encrypt import FILE_FORMAT, _derive_file_key
from app.crypto.key_manager import load_private_key
from app.file_io import atomic_write_bytes

REQUIRED_HEADER_FIELDS = {
    "format",
    "generated_by_app",
    "app_version",
    "created_at",
    "original_filename",
    "recipient_email",
    "recipient_key_fingerprint",
    "ephemeral_public_key",
    "nonce",
}


def _private_public_key_text(private_key: x25519.X25519PrivateKey) -> str:
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_bytes).decode("ascii")


def _decode_base64_field(value: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (AttributeError, UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError(f"Invalid base64 value for {field_name}.") from exc


def _load_encrypted_payload(input_path: Path) -> tuple[dict, bytes]:
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("Encrypted file is not valid JSON.") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("header"), dict):
        raise ValueError("Encrypted file is missing a valid header.")

    header = payload["header"]
    missing = REQUIRED_HEADER_FIELDS - set(header)
    if missing:
        raise ValueError(f"Encrypted file header is missing: {', '.join(sorted(missing))}.")

    if header.get("format") != FILE_FORMAT:
        raise ValueError("Unsupported encrypted file format.")

    if "ciphertext" not in payload:
        raise ValueError("Encrypted file is missing ciphertext.")

    ciphertext = _decode_base64_field(payload["ciphertext"], "ciphertext")
    return header, ciphertext


def decrypt_file(
    input_path: Path,
    output_path: Path | None = None,
    private_key_path: Path | None = None,
    passphrase: bytes | None = None,
) -> Path:
    ensure_data_dirs()
    private_key = (
        load_private_key(private_key_path, passphrase=passphrase)
        if private_key_path
        else load_private_key(passphrase=passphrase)
    )
    header, ciphertext = _load_encrypted_payload(input_path)

    if output_path is None:
        output_path = DECRYPTED_DIR / header.get("original_filename", input_path.stem)

    ephemeral_public_bytes = _decode_base64_field(header["ephemeral_public_key"], "ephemeral_public_key")
    try:
        ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
    except ValueError as exc:
        raise ValueError("Invalid ephemeral public key in encrypted file.") from exc
    shared_secret = private_key.exchange(ephemeral_public_key)
    recipient_public_key = _private_public_key_text(private_key)
    file_key = _derive_file_key(shared_secret, ephemeral_public_bytes, recipient_public_key)
    nonce = _decode_base64_field(header["nonce"], "nonce")
    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")

    try:
        plaintext = ChaCha20Poly1305(file_key).decrypt(nonce, ciphertext, header_bytes)
    except InvalidTag as exc:
        raise ValueError(
            "Decryption failed. The file may be tampered with, corrupted, "
            "or encrypted for a different private key."
        ) from exc

    atomic_write_bytes(output_path, plaintext)
    return output_path
