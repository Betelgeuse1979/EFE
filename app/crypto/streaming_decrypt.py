import base64
import binascii
import json
import os
import struct
import tempfile
from hashlib import sha256
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from app.config.settings import DECRYPTED_DIR
from app.crypto.file_format import (
    V2_HEADER_MAX_BYTES,
    V2_FOOTER_MAX_BYTES,
    V2_MAGIC,
    V2_MAJOR_VERSION,
    V2_MAX_CHUNK_SIZE,
    V2_METADATA_MAX_BYTES,
    safe_output_filename,
)
from app.crypto.key_manager import load_private_key
from app.crypto.streaming_encrypt import (
    CHUNK_RECORD,
    FOOTER_RECORD,
    V2_FORMAT_NAME,
    V2_METADATA_MODE,
    _chunk_aad,
    _chunk_nonce,
    _derive_v2_keys,
    _footer_aad,
)
from app.exceptions import InvalidEfeFileError, OutputExistsError, PermissionDeniedError

REQUIRED_V2_HEADER_FIELDS = {
    "format",
    "version_major",
    "version_minor",
    "generated_by_app",
    "app_version",
    "created_at",
    "key_exchange",
    "kdf",
    "aead",
    "metadata_mode",
    "chunk_size",
    "nonce_strategy",
    "recipient_key_fingerprint",
    "ephemeral_public_key",
    "metadata_nonce",
    "chunk_nonce_prefix",
    "footer_nonce",
}


def _read_exact(input_file, length: int, description: str) -> bytes:
    data = input_file.read(length)
    if len(data) != length:
        raise InvalidEfeFileError(f"Encrypted file is truncated while reading {description}.")
    return data


def _decode_base64_field(value: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (AttributeError, UnicodeEncodeError, binascii.Error) as exc:
        raise InvalidEfeFileError(f"Invalid base64 value for {field_name}.") from exc


def _load_v2_header(input_file) -> tuple[dict, bytes, bytes]:
    magic = _read_exact(input_file, 4, "magic bytes")
    if magic != V2_MAGIC:
        raise InvalidEfeFileError("Unsupported encrypted file format.")
    major, minor = struct.unpack(">BB", _read_exact(input_file, 2, "format version"))
    if major != V2_MAJOR_VERSION:
        raise InvalidEfeFileError("Unsupported EFE v2 major version.")

    header_length = struct.unpack(">I", _read_exact(input_file, 4, "public header length"))[0]
    if header_length <= 0 or header_length > V2_HEADER_MAX_BYTES:
        raise InvalidEfeFileError("Invalid EFE v2 public header length.")
    header_bytes = _read_exact(input_file, header_length, "public header")
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidEfeFileError("Invalid EFE v2 public header JSON.") from exc
    if not isinstance(header, dict):
        raise InvalidEfeFileError("Invalid EFE v2 public header.")

    missing = REQUIRED_V2_HEADER_FIELDS - set(header)
    if missing:
        raise InvalidEfeFileError(f"EFE v2 public header is missing: {', '.join(sorted(missing))}.")
    if header.get("format") != V2_FORMAT_NAME or header.get("metadata_mode") != V2_METADATA_MODE:
        raise InvalidEfeFileError("Unsupported EFE v2 format metadata.")
    if header.get("version_major") != major or header.get("version_minor") != minor:
        raise InvalidEfeFileError("EFE v2 version fields do not match.")

    chunk_size = header.get("chunk_size")
    if not isinstance(chunk_size, int) or chunk_size <= 0 or chunk_size > V2_MAX_CHUNK_SIZE:
        raise InvalidEfeFileError("Invalid EFE v2 chunk size.")

    return header, header_bytes, sha256(header_bytes).digest()


def _private_public_key_text(private_key: x25519.X25519PrivateKey) -> str:
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_bytes).decode("ascii")


def _load_v2_metadata(input_file, header: dict, header_bytes: bytes, metadata_key: bytes) -> dict:
    encrypted_metadata_length = struct.unpack(">I", _read_exact(input_file, 4, "encrypted metadata length"))[0]
    if encrypted_metadata_length <= 0 or encrypted_metadata_length > V2_METADATA_MAX_BYTES:
        raise InvalidEfeFileError("Invalid EFE v2 encrypted metadata length.")
    encrypted_metadata = _read_exact(input_file, encrypted_metadata_length, "encrypted metadata")
    metadata_nonce = _decode_base64_field(header["metadata_nonce"], "metadata_nonce")
    try:
        metadata_bytes = ChaCha20Poly1305(metadata_key).decrypt(metadata_nonce, encrypted_metadata, header_bytes)
    except InvalidTag as exc:
        raise InvalidEfeFileError("EFE v2 encrypted metadata could not be authenticated.") from exc
    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidEfeFileError("EFE v2 encrypted metadata is invalid.") from exc
    if not isinstance(metadata, dict):
        raise InvalidEfeFileError("EFE v2 encrypted metadata is invalid.")
    return metadata


def _write_decrypted_stream(output_path: Path, reader) -> None:
    temp_path = None
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists():
            raise OutputExistsError(f"Output file already exists: {output_path}")

        with tempfile.NamedTemporaryFile(delete=False, dir=output_path.parent, suffix=".incomplete") as temp_file:
            temp_path = Path(temp_file.name)
            reader(temp_file)
            temp_file.flush()
            os.fsync(temp_file.fileno())

        if output_path.exists():
            raise OutputExistsError(f"Output file already exists: {output_path}")
        os.replace(temp_path, output_path)
    except PermissionError as exc:
        if temp_path and temp_path.exists():
            temp_path.unlink()
        raise PermissionDeniedError(f"Permission denied for output path: {output_path}") from exc
    except Exception:
        if temp_path and temp_path.exists():
            temp_path.unlink()
        raise


def decrypt_streaming_file(
    input_path: Path,
    output_path: Path | None = None,
    private_key_path: Path | None = None,
    passphrase: bytes | None = None,
) -> Path:
    """Decrypt an experimental EFE v2 streaming binary package."""
    private_key = (
        load_private_key(private_key_path, passphrase=passphrase)
        if private_key_path
        else load_private_key(passphrase=passphrase)
    )
    with input_path.open("rb") as input_file:
        header, header_bytes, header_hash = _load_v2_header(input_file)
        ephemeral_public_bytes = _decode_base64_field(header["ephemeral_public_key"], "ephemeral_public_key")
        try:
            ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
        except ValueError as exc:
            raise InvalidEfeFileError("Invalid EFE v2 ephemeral public key.") from exc

        shared_secret = private_key.exchange(ephemeral_public_key)
        recipient_public_key = _private_public_key_text(private_key)
        metadata_key, chunk_key, footer_key = _derive_v2_keys(shared_secret, ephemeral_public_bytes, recipient_public_key)
        metadata = _load_v2_metadata(input_file, header, header_bytes, metadata_key)

        if output_path is None:
            output_path = DECRYPTED_DIR / safe_output_filename(metadata.get("original_filename"))

        chunk_nonce_prefix = _decode_base64_field(header["chunk_nonce_prefix"], "chunk_nonce_prefix")
        if len(chunk_nonce_prefix) != 4:
            raise InvalidEfeFileError("Invalid EFE v2 chunk nonce prefix.")
        footer_nonce = _decode_base64_field(header["footer_nonce"], "footer_nonce")
        if len(footer_nonce) != 12:
            raise InvalidEfeFileError("Invalid EFE v2 footer nonce.")

        expected_chunk_index = 0
        total_plaintext_size = 0
        chunk_records_hash = sha256()
        def read_chunks(temp_file) -> None:
            nonlocal expected_chunk_index, total_plaintext_size
            while True:
                record_type = input_file.read(1)
                if record_type == b"":
                    raise InvalidEfeFileError("EFE v2 file is missing its footer.")
                if record_type == FOOTER_RECORD:
                    footer_length = struct.unpack(">I", _read_exact(input_file, 4, "footer length"))[0]
                    if footer_length <= 0 or footer_length > V2_FOOTER_MAX_BYTES:
                        raise InvalidEfeFileError("Invalid EFE v2 footer length.")
                    encrypted_footer = _read_exact(input_file, footer_length, "footer")
                    try:
                        footer_bytes = ChaCha20Poly1305(footer_key).decrypt(
                            footer_nonce,
                            encrypted_footer,
                            _footer_aad(header_hash),
                        )
                    except InvalidTag as exc:
                        raise InvalidEfeFileError("EFE v2 footer could not be authenticated.") from exc
                    try:
                        footer = json.loads(footer_bytes.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise InvalidEfeFileError("EFE v2 footer is invalid.") from exc
                    if not isinstance(footer, dict):
                        raise InvalidEfeFileError("EFE v2 footer is invalid.")
                    trailing = input_file.read(1)
                    if trailing != b"":
                        raise InvalidEfeFileError("EFE v2 file has unauthenticated trailing data.")
                    expected_header_hash = base64.b64encode(header_hash).decode("ascii")
                    expected_records_hash = base64.b64encode(chunk_records_hash.digest()).decode("ascii")
                    if footer.get("public_header_sha256") != expected_header_hash:
                        raise InvalidEfeFileError("EFE v2 footer header hash is invalid.")
                    if footer.get("chunk_records_sha256") != expected_records_hash:
                        raise InvalidEfeFileError("EFE v2 footer chunk manifest is invalid.")
                    if footer.get("chunk_count") != expected_chunk_index:
                        raise InvalidEfeFileError("EFE v2 footer chunk count is invalid.")
                    if footer.get("total_plaintext_size") != total_plaintext_size:
                        raise InvalidEfeFileError("EFE v2 footer plaintext size is invalid.")
                    if metadata.get("original_size") != total_plaintext_size:
                        raise InvalidEfeFileError("EFE v2 encrypted metadata size does not match.")
                    return

                if record_type != CHUNK_RECORD:
                    raise InvalidEfeFileError("Invalid EFE v2 record type.")
                record_fields = _read_exact(input_file, 17, "chunk record header")
                chunk_index, final_flag, plaintext_length, ciphertext_length = struct.unpack(">QBII", record_fields)
                if chunk_index != expected_chunk_index:
                    raise InvalidEfeFileError("EFE v2 chunk order is invalid.")
                if plaintext_length > header["chunk_size"] or ciphertext_length < 16:
                    raise InvalidEfeFileError("Invalid EFE v2 chunk length.")
                ciphertext = _read_exact(input_file, ciphertext_length, "chunk ciphertext")
                record_header = record_type + record_fields
                chunk_records_hash.update(record_header)
                chunk_records_hash.update(ciphertext)
                try:
                    plaintext = ChaCha20Poly1305(chunk_key).decrypt(
                        _chunk_nonce(chunk_nonce_prefix, chunk_index),
                        ciphertext,
                        _chunk_aad(header_hash, chunk_index, plaintext_length, bool(final_flag)),
                    )
                except InvalidTag as exc:
                    raise InvalidEfeFileError("EFE v2 chunk could not be authenticated.") from exc
                if len(plaintext) != plaintext_length:
                    raise InvalidEfeFileError("EFE v2 chunk plaintext length is invalid.")
                temp_file.write(plaintext)
                total_plaintext_size += len(plaintext)
                expected_chunk_index += 1

        _write_decrypted_stream(output_path, read_chunks)

    return output_path
