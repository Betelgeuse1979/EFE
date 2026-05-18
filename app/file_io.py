import os
import tempfile
from pathlib import Path


def atomic_write_bytes(output_path: Path, data: bytes) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        raise FileExistsError(f"Output file already exists: {output_path}")

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, dir=output_path.parent) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(data)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        if output_path.exists():
            raise FileExistsError(f"Output file already exists: {output_path}")
        os.replace(temp_path, output_path)
    except Exception:
        if temp_path and temp_path.exists():
            temp_path.unlink()
        raise


def atomic_write_text(output_path: Path, text: str, encoding: str = "utf-8") -> None:
    atomic_write_bytes(output_path, text.encode(encoding))
