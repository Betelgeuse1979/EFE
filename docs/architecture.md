# EFE Architecture Notes

EFE should be structured so the desktop app, CLI, and future local-first SME security products can reuse the same core capabilities.

This document describes intended modular direction. It is not a claim that the current MVP already has a polished public SDK.

## Current Shape

- `app/crypto`: cryptographic operations and `.efe` encryption/decryption helpers.
- `app/services`: service layer used by CLI and GUI.
- `app/contacts`: SQLite contact book and verification state.
- `app/audit`: SQLite audit log.
- `app/gui`: PySide6 desktop prototype.
- `app/main.py`: CLI entry point.
- `app/config`: app settings and runtime data directory resolution.

## Intended Reusable Modules

### efe-core / Crypto Service

The core encryption/decryption service should remain separate from GUI and CLI concerns. It should expose simple operations for encrypting a file to a recipient key and decrypting a `.efe` file with a local private key.

Future applications should call this layer rather than copying cryptographic code.

### Key Management

Key management should cover:

- local key generation
- passphrase-encrypted private key storage
- public key export
- public key QR export
- private key unlock
- future key rotation or migration support

Private keys and passphrases must never be copied into logs, QR codes, public key records, or business workflow databases.

### Contacts And Fingerprint Verification

Contacts and trust state should remain reusable:

- public key import
- public key validation
- key fingerprint calculation
- verified/unverified status
- warnings when encrypting to unverified contacts

Future tools should reuse this trust workflow instead of silently accepting public keys.

### Audit Service

The current audit service records local encryption/decryption metadata. Future business products may need richer evidence logs, but those should be layered above the basic audit service.

Audit logs must not store plaintext file contents, passphrases, private keys, or raw decrypted data.

### File Format Handling

The `.efe` file format should be treated as the shared protocol layer. File format parsing, validation, versioning, and compatibility checks should be reusable by:

- EFE desktop
- EFE CLI
- Bank Statement Converter encrypted export
- Cisco Backup encrypted storage
- future SME security products

Before v1, the file format should be stabilized and metadata leakage should be reviewed.

### Desktop GUI

The PySide6 GUI should stay thin. It should call services and show user-facing status, warnings, and errors. It should not duplicate cryptographic logic.

### Future Python SDK Or Reusable Package Layer

After the core behavior is stable, EFE may expose a small Python package layer for local integrations. Candidate package boundaries:

- key management
- contact import/verification
- `.efe` file read/write/validate
- encrypt/decrypt service calls
- audit logging adapters

This would allow future tools such as the Bank Statement Converter and Cisco Backup Tool to produce or consume `.efe` files without depending on GUI code.

