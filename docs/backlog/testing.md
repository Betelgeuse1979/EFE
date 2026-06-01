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
- Documented file size limit if streaming is not promoted before v1.

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

- Covered in unit tests: v2 roundtrip, magic-byte detection, encrypted filename metadata privacy, Unicode filename, long filename bounding, zero-byte file, multi-chunk large-file path, wrong private key, wrong passphrase, corrupted public header, corrupted encrypted metadata, corrupted chunk, missing chunk, truncated final chunk, tampered footer, temp-output cleanup, v1 decrypt compatibility, and service-level v2 selection.
- Still needed: explicit reordered chunk test.
- Still needed: duplicated chunk test.
- Still needed: missing footer/finalization marker test.
- Still needed: low disk space during streaming encrypt/decrypt.
- Still needed: network share disconnect during streaming encrypt/decrypt.
- Still needed: removable drive disconnect during streaming encrypt/decrypt.
- Still needed: many small files.
- Still needed: larger memory-use tests outside the normal unit suite.
- Still needed: cross-version fixture files for v1/v2 compatibility.

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
