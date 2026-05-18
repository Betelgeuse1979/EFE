from app.exceptions import (
    ContactNotFoundError,
    InvalidEfeFileError,
    InvalidPublicKeyError,
    OutputExistsError,
    PermissionDeniedError,
    PrivateKeyUnlockError,
    UnverifiedContactError,
)


def user_error_message(exc: Exception) -> str:
    if isinstance(exc, OutputExistsError):
        return "Output file already exists. Choose a different output path."
    if isinstance(exc, PermissionDeniedError):
        return "Permission denied while accessing a file or directory. Check the path permissions."
    if isinstance(exc, ContactNotFoundError):
        return str(exc)
    if isinstance(exc, UnverifiedContactError):
        return str(exc)
    if isinstance(exc, InvalidPublicKeyError):
        return str(exc)
    if isinstance(exc, InvalidEfeFileError):
        return str(exc)
    if isinstance(exc, PrivateKeyUnlockError):
        return str(exc)
    if isinstance(exc, FileExistsError):
        return "Output file already exists. Choose a different output path."
    if isinstance(exc, PermissionError):
        return "Permission denied while accessing a file or directory. Check the path permissions."
    if isinstance(exc, FileNotFoundError):
        return "File or directory not found. Check the path and try again."
    if isinstance(exc, IsADirectoryError):
        return "Expected a file path but received a directory path."
    if isinstance(exc, ValueError):
        return str(exc)
    if isinstance(exc, OSError):
        return f"File system error: {exc}"
    return str(exc)
