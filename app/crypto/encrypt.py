import base64
import json
import os
import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config.settings import APP_NAME, APP_VERSION, ENCRYPTED_DIR
from app.crypto.key_manager import public_key_from_text
from app.file_io import atomic_write_text

FILE_FORMAT = "efe-X25519-ChaCha20Poly1305-v1"
CRYPTO_FORMAT_VERSION = "v1"
ENCRYPTED_METADATA_MODE = "encrypted-json-v1"
METADATA_VERSION = 1


def _derive_file_key(shared_secret: bytes, ephemeral_public_key: bytes, recipient_public_key: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ephemeral_public_key,
        info=f"{APP_NAME}:{recipient_public_key}".encode("utf-8"),
    ).derive(shared_secret)


def _pack_plaintext_with_metadata(input_path: Path, plaintext: bytes) -> bytes:
    metadata = {
        "metadata_version": METADATA_VERSION,
        "original_filename": input_path.name,
        "original_size": len(plaintext),
    }
    metadata_bytes = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return struct.pack(">I", len(metadata_bytes)) + metadata_bytes + plaintext


def default_encrypted_output_path() -> Path:
    return ENCRYPTED_DIR / f"efe-{uuid.uuid4().hex}.efe"


def encrypt_file_for_contact(input_path: Path, contact: dict, output_path: Path | None = None) -> Path:
    if output_path is None:
        output_path = default_encrypted_output_path()

    recipient_public_key = public_key_from_text(contact["public_key"])
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_bytes = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    shared_secret = ephemeral_private_key.exchange(recipient_public_key)
    file_key = _derive_file_key(shared_secret, ephemeral_public_bytes, contact["public_key"])
    nonce = os.urandom(12)

    plaintext = input_path.read_bytes()
    header = {
        "format": FILE_FORMAT,
        "generated_by_app": APP_NAME,
        "app_version": APP_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "metadata_mode": ENCRYPTED_METADATA_MODE,
        "recipient_email": contact["email"],
        "recipient_key_fingerprint": contact["key_fingerprint"],
        "ephemeral_public_key": base64.b64encode(ephemeral_public_bytes).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }
    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")
    ciphertext = ChaCha20Poly1305(file_key).encrypt(nonce, _pack_plaintext_with_metadata(input_path, plaintext), header_bytes)

    payload = {
        "header": header,
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    atomic_write_text(output_path, json.dumps(payload, indent=2))
    return output_path
