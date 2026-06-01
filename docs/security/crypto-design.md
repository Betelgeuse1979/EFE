# EFE Crypto Design

This document describes the current EFE cryptographic design. It is descriptive, not a certification or independent audit.

## Summary

EFE uses established primitives from Python's `cryptography` package:

- X25519 key agreement
- HKDF-SHA256 key derivation
- ChaCha20-Poly1305 authenticated encryption
- 12-byte random nonces
- passphrase-encrypted private keys at rest

EFE does not design custom cryptographic primitives. However, EFE does define custom protocol glue and custom `.efe` package formats. That glue has not been independently audited.

The default public encryption format remains the v1 JSON/Base64 package. Experimental v2 streaming binary support exists internally for testing and is not yet the default CLI or GUI format.

## Key Agreement

Each recipient has a static X25519 public/private key pair.

For each encryption operation, EFE generates a fresh ephemeral X25519 sender private key. EFE performs X25519 key agreement between:

- the ephemeral sender private key
- the recipient static public key

The encrypted file stores the ephemeral sender public key in the authenticated header so that the recipient can derive the same shared secret using their private key.

## Key Derivation

EFE derives the file encryption key using HKDF-SHA256.

Inputs include:

- X25519 shared secret
- ephemeral public key as HKDF salt
- EFE context and recipient public key in HKDF info

The derived key is 32 bytes and is used with ChaCha20-Poly1305.

## File Encryption

Default v1 file contents are encrypted with ChaCha20-Poly1305.

Each encryption uses:

- a fresh 32-byte derived file key
- a 12-byte random nonce from the OS random number generator
- the JSON header as associated authenticated data
- encrypted metadata prefixed to the plaintext before file bytes

ChaCha20-Poly1305 provides confidentiality and authentication for the encrypted file contents and encrypted metadata. The associated public header is authenticated but not encrypted.

## Experimental v2 Streaming Encryption

EFE also includes an internal experimental v2 streaming binary path. It is selected deliberately by services/tests and is not the default user-facing format yet.

The v2 path keeps the same primitive family:

- X25519 key agreement with a fresh ephemeral sender key per file.
- HKDF-SHA256 key derivation.
- Separate derived keys for encrypted metadata, content chunks, and the final footer/manifest.
- ChaCha20-Poly1305 authenticated encryption.
- A public technical header that is authenticated but not encrypted.
- Encrypted metadata containing the original filename and original file size.
- Chunked content encryption with a default 1 MiB chunk size.
- Per-chunk nonces built from a random 4-byte file nonce prefix and an 8-byte big-endian chunk index.
- A final authenticated footer containing chunk count, total plaintext size, public header hash, and chunk-record hash.

The v2 decrypt path auto-detects files beginning with the `EFE2` magic bytes. Existing v1 JSON files remain supported.

## Authenticated Header

The `.efe` public header includes technical metadata such as:

- format marker
- app version
- creation time
- metadata mode
- recipient email
- recipient key fingerprint
- ephemeral public key
- nonce

EFE serializes the header with deterministic JSON key ordering and passes it to ChaCha20-Poly1305 as associated authenticated data. If the header is modified, decryption fails.

## Encrypted File Metadata

New `.efe` files do not store the original filename in the public header. Instead, EFE encrypts a metadata JSON object together with the file bytes.

Encrypted metadata currently includes:

- metadata version
- original filename
- original file size

The metadata is authenticated because it is inside the ChaCha20-Poly1305 ciphertext. If encrypted metadata or ciphertext is modified, decryption fails. Legacy MVP files that stored `original_filename` in the public header are still supported for decryption where practical, but new files should not leak the original document name.

When EFE chooses a default encrypted output path, it uses a generic random `.efe` package filename instead of deriving the package name from the original filename.

## Public And Private Key Separation

Public keys may be shared. They are used by senders to encrypt files for a recipient.

Private keys must never be shared. They are stored locally and encrypted at rest with a user passphrase.

Public key authenticity matters because an attacker can provide their own public key and trick a sender into encrypting to the attacker. The public key is not secret, but it must be authentic.

Public key records can be exported as JSON files or as QR code PNG files. The QR payload contains only the public key record: display name, email, public key, key fingerprint, app metadata, and creation time. It must not contain private key material or passphrases. Fingerprint verification is still required after sharing by QR code.

## Fingerprint Verification

EFE calculates a fingerprint for public keys and displays it during import and contact verification. Users should verify the fingerprint through a separate trusted channel, such as a phone call, WhatsApp, or in person.

The fingerprint workflow exists to reduce the risk of trusting the wrong public key.

## Private Keys At Rest

Private keys are serialized with encrypted private key serialization from the `cryptography` package. The passphrase is not stored in SQLite, config files, or audit logs.

If the private key or passphrase is lost, previously encrypted files may be unrecoverable.

## Known Limitations

- The `.efe` formats and protocol glue have not been independently audited.
- The v2 streaming format is experimental and not yet the public default.
- EFE does not currently use age/pyrage.
- EFE does not use hardware-backed key storage.
- EFE does not provide enterprise key recovery.
- EFE provides QR export for public keys only; it does not provide QR scanning or webcam import.
- EFE does not protect decrypted files after successful decryption.
