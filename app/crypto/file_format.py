from pathlib import Path

V2_MAGIC = b"EFE2"
V2_MAJOR_VERSION = 2
V2_MINOR_VERSION = 0
V2_HEADER_MAX_BYTES = 1024 * 1024
V2_METADATA_MAX_BYTES = 1024 * 1024
V2_FOOTER_MAX_BYTES = 1024 * 1024
V2_DEFAULT_CHUNK_SIZE = 1024 * 1024
V2_MAX_CHUNK_SIZE = 16 * 1024 * 1024
V2_MAX_FILENAME_LENGTH = 180

FALLBACK_FILENAME = "decrypted_output"


def is_v2_file(input_path: Path) -> bool:
    try:
        with input_path.open("rb") as input_file:
            return input_file.read(len(V2_MAGIC)) == V2_MAGIC
    except FileNotFoundError:
        raise
    except OSError:
        return False


def safe_output_filename(filename: str | None) -> str:
    if not filename or not isinstance(filename, str):
        return FALLBACK_FILENAME
    safe_name = Path(filename).name.strip()
    if not safe_name or safe_name in {".", ".."}:
        return FALLBACK_FILENAME
    if len(safe_name) > V2_MAX_FILENAME_LENGTH:
        suffix = Path(safe_name).suffix
        stem_limit = max(1, V2_MAX_FILENAME_LENGTH - len(suffix))
        safe_name = f"{Path(safe_name).stem[:stem_limit]}{suffix}"
    return safe_name
