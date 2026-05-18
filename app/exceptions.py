class EfeError(Exception):
    """Base class for expected EFE application errors."""


class ContactNotFoundError(ValueError, EfeError):
    """Raised when a requested contact does not exist."""


class UnverifiedContactError(ValueError, EfeError):
    """Raised when encryption is requested for an unverified contact."""


class OutputExistsError(FileExistsError, EfeError):
    """Raised when an output path already exists and would be overwritten."""


class InvalidEfeFileError(ValueError, EfeError):
    """Raised when a .efe file is invalid, corrupted, or not decryptable."""


class PrivateKeyUnlockError(ValueError, EfeError):
    """Raised when an encrypted private key cannot be unlocked."""


class InvalidPublicKeyError(ValueError, EfeError):
    """Raised when an imported public key record is invalid."""


class PermissionDeniedError(PermissionError, EfeError):
    """Raised when the filesystem denies a requested operation."""


class AuditLogError(EfeError):
    """Raised when an audit entry cannot be written or read."""
