import hashlib


def calculate_fingerprint(public_key: str) -> str:
    """Return a readable SHA-256 fingerprint for a public key string."""
    digest = hashlib.sha256(public_key.encode("utf-8")).hexdigest().upper()
    return ":".join(digest[i : i + 4] for i in range(0, len(digest), 4))
