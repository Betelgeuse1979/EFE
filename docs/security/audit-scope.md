# Proposed EFE Security Audit Scope

This document is intended for an external security reviewer. EFE has not yet been independently audited.

## Intended Audit Goal

Assess whether EFE's current local CLI and GUI prototype use cryptography, key management, file handling, and local persistence safely enough for continued development.

The audit should identify security issues, design weaknesses, unsafe assumptions, missing tests, and recommended fixes.

## Proposed Scope

### In Scope

- `app/crypto`
- `app/services`
- `app/file_io.py`
- `app/exceptions.py`
- `app/error_messages.py`
- CLI flows in `app/main.py`
- GUI passphrase and file workflows in `app/gui`
- SQLite contact and audit handling
- `.efe` file format
- public key import and fingerprint verification
- public key QR export
- private key storage and passphrase handling
- per-user app data directory handling, including `EFE_DATA_DIR` override behavior
- requirements and dependencies
- tests for tampering, malformed files, wrong keys, and failure modes

### Out Of Scope

- Cloud infrastructure
- Outlook/Gmail plugin
- Public key server
- Enterprise admin console
- Mobile apps
- QR scanning or webcam support
- Browser extensions
- Central identity provider integration
- Legal compliance certification

## Review Questions

- Is X25519 used safely?
- Is HKDF-SHA256 used safely?
- Is ChaCha20-Poly1305 used safely?
- Are private keys protected correctly at rest?
- Are passphrases handled safely?
- Is the `.efe` header authenticated correctly?
- Can tampering produce plaintext?
- Do wrong-key and wrong-recipient cases fail safely?
- Are malformed `.efe` files rejected safely?
- Are public keys validated correctly?
- Is public key QR export limited to public key records and free of private key material or passphrases?
- Is fingerprint verification adequate for the MVP?
- Are audit logs safe and free of plaintext or secret material?
- Are file writes safe and atomic enough for this local app?
- Is no-silent-overwrite behavior implemented correctly?
- Are runtime keys, database files, encrypted outputs, and decrypted outputs stored in appropriate per-user app data locations?
- Are dependencies reasonable and current enough for an MVP?
- Are CLI and GUI errors safe and understandable?

## Requested Deliverable

The reviewer should provide:

- findings grouped by severity
- evidence for each finding
- recommended fixes
- residual risk after recommended fixes
- notes on missing tests or documentation
- retest notes after fixes are implemented

## Severity Guidance

- Critical: likely plaintext exposure, private key compromise, or trivial bypass of encryption.
- High: realistic path to data exposure, wrong-key trust failure, or serious key handling weakness.
- Medium: meaningful hardening issue, confusing security UX, or incomplete failure handling.
- Low: documentation, test coverage, maintainability, or minor defensive improvements.
