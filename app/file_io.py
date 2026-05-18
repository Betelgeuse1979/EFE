import os
import tempfile
from pathlib import Path

from app.exceptions import OutputExistsError, PermissionDeniedError


def atomic_write_bytes(output_path: Path, data: bytes) -> None:
    temp_path = None
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists():
            raise OutputExistsError(f"Output file already exists: {output_path}")

        with tempfile.NamedTemporaryFile(delete=False, dir=output_path.parent) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(data)
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


def atomic_write_text(output_path: Path, text: str, encoding: str = "utf-8") -> None:
    atomic_write_bytes(output_path, text.encode(encoding))
