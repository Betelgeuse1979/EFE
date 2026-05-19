import os
import sys
from pathlib import Path

APP_NAME = "efe"
APP_FULL_NAME = "Encrypted File Exchange"
APP_VERSION = "0.1.0"
WINDOWS_APP_DIR_NAME = "EFE"
DATA_DIR_ENV_VAR = "EFE_DATA_DIR"

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def resolve_data_dir(
    *,
    environ: dict[str, str] | None = None,
    platform: str | None = None,
    home: Path | None = None,
) -> Path:
    r"""Resolve EFE's runtime data directory.

    EFE_DATA_DIR is intended for tests and development. Normal Windows builds
    use %LOCALAPPDATA%\EFE so runtime keys and databases are outside the repo.
    """
    env = environ if environ is not None else os.environ
    override = env.get(DATA_DIR_ENV_VAR)
    if override:
        return Path(override).expanduser()

    current_platform = platform if platform is not None else sys.platform
    user_home = home if home is not None else Path.home()

    if current_platform == "win32":
        local_app_data = env.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / WINDOWS_APP_DIR_NAME
        return user_home / "AppData" / "Local" / WINDOWS_APP_DIR_NAME

    return user_home / ".local" / "share" / APP_NAME


def build_data_paths(data_dir: Path) -> dict[str, Path]:
    keys_dir = data_dir / "keys"
    encrypted_dir = data_dir / "encrypted"
    decrypted_dir = data_dir / "decrypted"
    return {
        "data_dir": data_dir,
        "keys_dir": keys_dir,
        "encrypted_dir": encrypted_dir,
        "decrypted_dir": decrypted_dir,
        "db_path": data_dir / "efe.db",
        "private_key_path": keys_dir / "efe_private_key.pem",
        "public_key_record_path": keys_dir / "efe_public_key.json",
    }


DATA_DIR = resolve_data_dir()
_PATHS = build_data_paths(DATA_DIR)

KEYS_DIR = _PATHS["keys_dir"]
ENCRYPTED_DIR = _PATHS["encrypted_dir"]
DECRYPTED_DIR = _PATHS["decrypted_dir"]
DB_PATH = _PATHS["db_path"]

PRIVATE_KEY_PATH = _PATHS["private_key_path"]
PUBLIC_KEY_RECORD_PATH = _PATHS["public_key_record_path"]


def get_data_paths() -> dict[str, Path]:
    return dict(_PATHS)


def ensure_data_dirs() -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)
    DECRYPTED_DIR.mkdir(parents=True, exist_ok=True)
