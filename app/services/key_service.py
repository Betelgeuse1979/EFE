from pathlib import Path

from app.config.settings import PRIVATE_KEY_PATH, PUBLIC_KEY_RECORD_PATH
from app.crypto.key_manager import (
    export_public_key,
    generate_user_key_pair,
    get_private_key_fingerprint,
    load_private_key,
)


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


def load_user_private_key(passphrase: bytes, private_key_path: Path = PRIVATE_KEY_PATH):
    return load_private_key(private_key_path, passphrase=passphrase)


def get_user_key_fingerprint(passphrase: bytes, private_key_path: Path = PRIVATE_KEY_PATH) -> str:
    return get_private_key_fingerprint(private_key_path=private_key_path, passphrase=passphrase)
