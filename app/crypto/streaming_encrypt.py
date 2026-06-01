import base64
import json
import os
import struct
import tempfile
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config.settings import APP_NAME, APP_VERSION, ENCRYPTED_DIR
from app.crypto.file_format import (
    V2_DEFAULT_CHUNK_SIZE,
    V2_MAGIC,
    V2_MAJOR_VERSION,
    V2_MAX_CHUNK_SIZE,
    V2_MINOR_VERSION,
)
from app.crypto.key_manager import public_key_from_text
from app.exceptions import OutputExistsError, PermissionDeniedError

V2_FORMAT_NAME = "efe-streaming-binary-v2"
V2_METADATA_MODE = "encrypted-json-v2"
V2_METADATA_VERSION = 2
CHUNK_RECORD = b"C"
FOOTER_RECORD = b"F"


def default_v2_encrypted_output_path() -> Path:
    from uuid import uuid4

    return ENCRYPTED_DIR / f"efe-{uuid4().hex}.efe"


def _canonical_json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _derive_v2_keys(shared_secret: bytes, ephemeral_public_key: bytes, recipient_public_key: str) -> tuple[bytes, bytes, bytes]:
    key_material = HKDF(
        algorithm=hashes.SHA256(),
        length=96,
        salt=V2_MAGIC + ephemeral_public_key,
        info=f"{APP_NAME}:v2-streaming:{recipient_public_key}".encode("utf-8"),
    ).derive(shared_secret)
    return key_material[:32], key_material[32:64], key_material[64:96]


def _chunk_nonce(nonce_prefix: bytes, chunk_index: int) -> bytes:
    return nonce_prefix + struct.pack(">Q", chunk_index)


def _chunk_aad(header_hash: bytes, chunk_index: int, plaintext_length: int, final_chunk: bool) -> bytes:
    return b"EFE2-CHUNK" + header_hash + struct.pack(">QIB", chunk_index, plaintext_length, int(final_chunk))


def _footer_aad(header_hash: bytes) -> bytes:
    return b"EFE2-FOOTER" + header_hash


def _write_atomic_stream(output_path: Path, writer) -> None:
    temp_path = None
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists():
            raise OutputExistsError(f"Output file already exists: {output_path}")

        with tempfile.NamedTemporaryFile(delete=False, dir=output_path.parent) as temp_file:
            temp_path = Path(temp_file.name)
            writer(temp_file)
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


def encrypt_file_for_contact_streaming(
    input_path: Path,
    contact: dict,
    output_path: Path | None = None,
    *,
    chunk_size: int = V2_DEFAULT_CHUNK_SIZE,
) -> Path:
    """Write an experimental EFE v2 streaming binary package."""
    if output_path is None:
        output_path = default_v2_encrypted_output_path()
    if chunk_size <= 0 or chunk_size > V2_MAX_CHUNK_SIZE:
        raise ValueError("Invalid v2 chunk size.")

    original_size = input_path.stat().st_size
    recipient_public_key = public_key_from_text(contact["public_key"])
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_bytes = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    shared_secret = ephemeral_private_key.exchange(recipient_public_key)
    metadata_key, chunk_key, footer_key = _derive_v2_keys(shared_secret, ephemeral_public_bytes, contact["public_key"])
    metadata_nonce = os.urandom(12)
    chunk_nonce_prefix = os.urandom(4)
    footer_nonce = os.urandom(12)

    header = {
        "format": V2_FORMAT_NAME,
        "version_major": V2_MAJOR_VERSION,
        "version_minor": V2_MINOR_VERSION,
        "generated_by_app": APP_NAME,
        "app_version": APP_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "key_exchange": "X25519",
        "kdf": "HKDF-SHA256",
        "aead": "ChaCha20-Poly1305",
        "metadata_mode": V2_METADATA_MODE,
        "chunk_size": chunk_size,
        "nonce_strategy": "4-byte-random-prefix-plus-uint64-index",
        "recipient_key_fingerprint": contact["key_fingerprint"],
        "ephemeral_public_key": base64.b64encode(ephemeral_public_bytes).decode("ascii"),
        "metadata_nonce": base64.b64encode(metadata_nonce).decode("ascii"),
        "chunk_nonce_prefix": base64.b64encode(chunk_nonce_prefix).decode("ascii"),
        "footer_nonce": base64.b64encode(footer_nonce).decode("ascii"),
    }
    header_bytes = _canonical_json_bytes(header)
    header_hash = sha256(header_bytes).digest()
    metadata = {
        "metadata_version": V2_METADATA_VERSION,
        "original_filename": input_path.name,
        "original_size": original_size,
    }
    encrypted_metadata = ChaCha20Poly1305(metadata_key).encrypt(
        metadata_nonce,
        _canonical_json_bytes(metadata),
        header_bytes,
    )

    def write_package(output_file) -> None:
        output_file.write(V2_MAGIC)
        output_file.write(struct.pack(">BB", V2_MAJOR_VERSION, V2_MINOR_VERSION))
        output_file.write(struct.pack(">I", len(header_bytes)))
        output_file.write(header_bytes)
        output_file.write(struct.pack(">I", len(encrypted_metadata)))
        output_file.write(encrypted_metadata)

        chunk_records_hash = sha256()
        chunk_count = 0
        total_plaintext_size = 0
        with input_path.open("rb") as source_file:
            while True:
                chunk = source_file.read(chunk_size)
                if chunk == b"":
                    break
                final_chunk = total_plaintext_size + len(chunk) == original_size
                nonce = _chunk_nonce(chunk_nonce_prefix, chunk_count)
                aad = _chunk_aad(header_hash, chunk_count, len(chunk), final_chunk)
                ciphertext = ChaCha20Poly1305(chunk_key).encrypt(nonce, chunk, aad)
                record_header = CHUNK_RECORD + struct.pack(">QBII", chunk_count, int(final_chunk), len(chunk), len(ciphertext))
                output_file.write(record_header)
                output_file.write(ciphertext)
                chunk_records_hash.update(record_header)
                chunk_records_hash.update(ciphertext)
                total_plaintext_size += len(chunk)
                chunk_count += 1

        footer = {
            "footer_version": 1,
            "chunk_count": chunk_count,
            "total_plaintext_size": total_plaintext_size,
            "public_header_sha256": base64.b64encode(header_hash).decode("ascii"),
            "chunk_records_sha256": base64.b64encode(chunk_records_hash.digest()).decode("ascii"),
        }
        encrypted_footer = ChaCha20Poly1305(footer_key).encrypt(
            footer_nonce,
            _canonical_json_bytes(footer),
            _footer_aad(header_hash),
        )
        output_file.write(FOOTER_RECORD)
        output_file.write(struct.pack(">I", len(encrypted_footer)))
        output_file.write(encrypted_footer)

    _write_atomic_stream(output_path, write_package)
    return output_path
