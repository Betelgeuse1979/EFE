import base64
import binascii
import json
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from app.config.settings import DECRYPTED_DIR
from app.crypto.encrypt import ENCRYPTED_METADATA_MODE, FILE_FORMAT, _derive_file_key
from app.crypto.file_format import is_v2_file, safe_output_filename
from app.crypto.key_manager import load_private_key
from app.exceptions import InvalidEfeFileError
from app.file_io import atomic_write_bytes

REQUIRED_HEADER_FIELDS = {
    "format",
    "generated_by_app",
    "app_version",
    "created_at",
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
        raise InvalidEfeFileError(f"Invalid base64 value for {field_name}.") from exc


def _load_encrypted_payload(input_path: Path) -> tuple[dict, bytes, bool]:
    with input_path.open("rb") as input_file:
        first_byte = input_file.read(1)
    if first_byte != b"{":
        raise InvalidEfeFileError("Unsupported encrypted file format.")

    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InvalidEfeFileError("Encrypted file is not valid JSON.") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("header"), dict):
        raise InvalidEfeFileError("Encrypted file is missing a valid header.")

    header = payload["header"]
    missing = REQUIRED_HEADER_FIELDS - set(header)
    if missing:
        raise InvalidEfeFileError(f"Encrypted file header is missing: {', '.join(sorted(missing))}.")

    is_legacy = "original_filename" in header and "metadata_mode" not in header
    if not is_legacy and header.get("metadata_mode") != ENCRYPTED_METADATA_MODE:
        raise InvalidEfeFileError("Encrypted file is missing encrypted metadata mode.")

    if header.get("format") != FILE_FORMAT:
        raise InvalidEfeFileError("Unsupported encrypted file format.")

    if "ciphertext" not in payload:
        raise InvalidEfeFileError("Encrypted file is missing ciphertext.")

    ciphertext = _decode_base64_field(payload["ciphertext"], "ciphertext")
    return header, ciphertext, is_legacy


def _unpack_plaintext_with_metadata(decrypted_payload: bytes) -> tuple[dict, bytes]:
    if len(decrypted_payload) < 4:
        return {}, decrypted_payload

    metadata_length = struct.unpack(">I", decrypted_payload[:4])[0]
    metadata_start = 4
    metadata_end = metadata_start + metadata_length
    if metadata_length <= 0 or metadata_end > len(decrypted_payload):
        return {}, decrypted_payload

    try:
        metadata = json.loads(decrypted_payload[metadata_start:metadata_end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}, decrypted_payload
    if not isinstance(metadata, dict):
        return {}, decrypted_payload
    return metadata, decrypted_payload[metadata_end:]


def decrypt_file(
    input_path: Path,
    output_path: Path | None = None,
    private_key_path: Path | None = None,
    passphrase: bytes | None = None,
) -> Path:
    if is_v2_file(input_path):
        from app.crypto.streaming_decrypt import decrypt_streaming_file

        return decrypt_streaming_file(
            input_path,
            output_path,
            private_key_path=private_key_path,
            passphrase=passphrase,
        )

    private_key = (
        load_private_key(private_key_path, passphrase=passphrase)
        if private_key_path
        else load_private_key(passphrase=passphrase)
    )
    header, ciphertext, is_legacy = _load_encrypted_payload(input_path)

    ephemeral_public_bytes = _decode_base64_field(header["ephemeral_public_key"], "ephemeral_public_key")
    try:
        ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
    except ValueError as exc:
        raise InvalidEfeFileError("Invalid ephemeral public key in encrypted file.") from exc
    shared_secret = private_key.exchange(ephemeral_public_key)
    recipient_public_key = _private_public_key_text(private_key)
    file_key = _derive_file_key(shared_secret, ephemeral_public_bytes, recipient_public_key)
    nonce = _decode_base64_field(header["nonce"], "nonce")
    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")

    try:
        decrypted_payload = ChaCha20Poly1305(file_key).decrypt(nonce, ciphertext, header_bytes)
    except InvalidTag as exc:
        raise InvalidEfeFileError(
            "Decryption failed. The file may be tampered with, corrupted, "
            "or encrypted for a different private key."
        ) from exc

    if is_legacy:
        metadata = {"original_filename": header.get("original_filename")}
        plaintext = decrypted_payload
    else:
        metadata, plaintext = _unpack_plaintext_with_metadata(decrypted_payload)

    if output_path is None:
        output_path = DECRYPTED_DIR / safe_output_filename(metadata.get("original_filename"))

    atomic_write_bytes(output_path, plaintext)
    return output_path
