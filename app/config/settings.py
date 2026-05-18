from pathlib import Path

APP_NAME = "efe"
APP_VERSION = "0.1.0"

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
KEYS_DIR = DATA_DIR / "keys"
ENCRYPTED_DIR = DATA_DIR / "encrypted"
DECRYPTED_DIR = DATA_DIR / "decrypted"
DB_PATH = DATA_DIR / "efe.db"

PRIVATE_KEY_PATH = KEYS_DIR / "efe_private_key.pem"
PUBLIC_KEY_RECORD_PATH = KEYS_DIR / "efe_public_key.json"


def ensure_data_dirs() -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)
    DECRYPTED_DIR.mkdir(parents=True, exist_ok=True)
