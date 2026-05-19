import io
import json
from pathlib import Path

from app.config.settings import PRIVATE_KEY_PATH, PUBLIC_KEY_RECORD_PATH
from app.crypto.key_manager import (
    export_public_key,
    generate_user_key_pair,
    get_private_key_fingerprint,
    load_public_key_record,
    load_private_key,
)
from app.file_io import atomic_write_bytes


def initialize_user_key(
    display_name: str,
    email: str,
    passphrase: bytes,
    overwrite: bool = False,
    private_key_path: Path = PRIVATE_KEY_PATH,
    public_key_record_path: Path = PUBLIC_KEY_RECORD_PATH,
) -> dict:
    """Create encrypted local key material and return the public key record."""
    return generate_user_key_pair(
        display_name,
        email,
        passphrase=passphrase,
        private_key_path=private_key_path,
        public_key_record_path=public_key_record_path,
        overwrite=overwrite,
    )


def export_user_public_key(output_path: Path, public_key_record_path: Path = PUBLIC_KEY_RECORD_PATH) -> Path:
    return export_public_key(output_path, public_key_record_path=public_key_record_path)


def build_public_key_qr_payload(public_key_record_path: Path = PUBLIC_KEY_RECORD_PATH) -> tuple[str, dict]:
    """Return the public key JSON payload used in QR exports and its record."""
    record = load_public_key_record(public_key_record_path)
    payload = json.dumps(record, separators=(",", ":"), sort_keys=True)
    return payload, record


def export_public_key_qr(
    output_path: Path,
    public_key_record_path: Path = PUBLIC_KEY_RECORD_PATH,
) -> dict:
    """Write a PNG QR code containing only the public key record JSON."""
    import qrcode

    payload, record = build_public_key_qr_payload(public_key_record_path)
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(payload)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")

    png_bytes = io.BytesIO()
    image.save(png_bytes, format="PNG")
    atomic_write_bytes(output_path, png_bytes.getvalue())
    return {
        "output_path": str(output_path),
        "key_fingerprint": record["key_fingerprint"],
    }


def load_user_private_key(passphrase: bytes, private_key_path: Path = PRIVATE_KEY_PATH):
    return load_private_key(private_key_path, passphrase=passphrase)


def get_user_key_fingerprint(passphrase: bytes, private_key_path: Path = PRIVATE_KEY_PATH) -> str:
    return get_private_key_fingerprint(private_key_path=private_key_path, passphrase=passphrase)
