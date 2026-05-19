# Changelog

All notable changes to EFE, short for Encrypted File Exchange, will be documented here.

EFE is still an MVP and has not been independently audited. Release notes describe project milestones, not production-readiness or compliance certification.

## v0.6.1-security-docs

Documentation refresh for the v0.6 public-key QR export checkpoint.

### Changed

- Refreshed `docs/security/` to reflect the current CLI, PySide6 GUI prototype, service layer, and public key QR export.
- Documented that QR export contains the public key record only and does not include private keys or passphrases.
- Documented that QR scanning and webcam import are not implemented.
- Updated the proposed audit scope to include public key QR export and current dependencies.
- Added the security documentation link to `README.txt`.

### Security Notes

- No application behavior or crypto design changed in this release.
- EFE remains an MVP and has not been independently audited.

## v0.6-public-key-qr

Public key QR export milestone.

### Added

- Added `qrcode[pil]` as a dependency for QR PNG generation.
- Added CLI command:

```powershell
python -m app.main export-public-key-qr --output alice-public-key.png
```

- Added a `Save Public Key QR` button to the PySide6 Keys tab.
- Added service-layer QR export support in `key_service`.
- Added tests for QR PNG creation, no-overwrite behavior, return values, payload safety, and CLI command availability.

### Security Notes

- QR payloads contain only the validated public key JSON record.
- QR payloads do not include private key material or passphrases.
- Fingerprint verification is still required before trusting a public key.
- QR output uses existing atomic/no-overwrite file handling.
- QR scanning, webcam support, cloud sync, public key servers, and email-client integrations were not added.

## v0.4-gui-readiness

Service-layer cleanup before GUI work.

### Added

- Added custom exception classes for clearer service and UI error handling.
- Added GUI-friendly service return values.
- Added encryption preflight behavior for future UI workflows.
- Added shared user-facing error message mapping.

### Changed

- Improved separation between CLI parsing/output and application service logic.
- Preserved existing CLI behavior and crypto design.

## v0.3-path-a-hardening

CLI and product hardening milestone.

### Added

- Added atomic output writes for encrypted and decrypted files.
- Added no-silent-overwrite behavior for output files.
- Added clearer CLI user-facing errors for expected failure cases.
- Added `version` command.
- Expanded negative crypto and file-handling tests.

### Security Notes

- Failed decryption does not leave plaintext output behind.
- Failed encryption does not leave partial `.efe` output behind.
- No crypto design changes were made.

## Initial CLI MVP

Initial EFE command-line MVP.

### Added

- Local X25519 key generation.
- Passphrase-encrypted private keys at rest.
- Public key export and import.
- Public key fingerprint validation and verification workflow.
- SQLite contact book and audit log.
- File encryption and decryption using X25519, HKDF-SHA256, and ChaCha20-Poly1305.
- Custom `.efe` JSON encrypted file format.
- Basic README and test suite.

