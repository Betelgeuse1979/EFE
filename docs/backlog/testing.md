# EFE Testing Backlog

This checklist tracks security, reliability, and file-handling tests that should be expanded before a v1 public release.

Some items already have partial coverage. This backlog is intentionally broader than the current MVP test suite.

## Crypto And Package Failure Modes

- Wrong password.
- Wrong private key.
- Corrupted `.efe` package.
- Tampered ciphertext.
- Tampered metadata.
- Tampered encrypted metadata.
- Truncated `.efe` file.
- Invalid or unsupported format version.
- Missing required header fields.
- Invalid base64 fields.
- Zero-byte input files.
- Very large files.
- Documented file size limit if streaming is not implemented before v1.

## Filename And Metadata Cases

- Long filenames.
- Unicode filenames.
- Filenames with spaces and punctuation.
- Metadata privacy checks, especially ensuring new files do not leak `original_filename`.
- Header fields that are authenticated but intentionally not encrypted.

## File I/O And Environment Failures

- Interrupted encryption.
- Interrupted decryption.
- Low disk space.
- Permission denied.
- Network share failures.
- Removable drive disconnects.
- Existing output file collision.
- Temporary file cleanup after failure.

## v2 Streaming Format Tests

- Encrypt/decrypt a very large file without high memory use.
- Corrupted binary public header.
- Corrupted encrypted metadata block.
- Corrupted chunk ciphertext.
- Missing chunk.
- Reordered chunk.
- Duplicated chunk.
- Truncated final chunk.
- Missing footer or finalization marker.
- Extra unauthenticated trailing bytes.
- Wrong private key.
- Wrong private key passphrase.
- Interrupted streaming encryption.
- Interrupted streaming decryption.
- Low disk space during streaming encrypt/decrypt.
- Network share disconnect during streaming encrypt/decrypt.
- Removable drive disconnect during streaming encrypt/decrypt.
- Unicode filename.
- Very long filename.
- Zero-byte file.
- Many small files.
- Legacy v1 decrypt still works after v2 support is added.
- v1/v2 file format auto-detection rejects unknown formats safely.

## Contacts And Trust Workflow

- Contact fingerprint verification edge cases.
- Duplicate contact import with changed public key.
- Invalid public key records.
- Public key QR export payload safety.
- Encrypting to unverified contacts requires explicit confirmation.

## Audit And Evidence Integrity

- Audit log tampering.
- Audit log unavailable or locked.
- Audit logging failure must not hide the original encryption/decryption error.
- Audit logs must not store plaintext, passphrases, private keys, or raw decrypted data.
