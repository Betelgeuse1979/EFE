# EFE Crypto Design

This document describes the current EFE cryptographic design. It is descriptive, not a certification or independent audit.

## Summary

EFE uses established primitives from Python's `cryptography` package:

- X25519 key agreement
- HKDF-SHA256 key derivation
- ChaCha20-Poly1305 authenticated encryption
- 12-byte random nonces
- passphrase-encrypted private keys at rest

EFE does not design custom cryptographic primitives. However, EFE does define custom protocol glue and a custom `.efe` JSON file format. That glue has not been independently audited.

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

File contents are encrypted with ChaCha20-Poly1305.

Each encryption uses:

- a fresh 32-byte derived file key
- a 12-byte random nonce from the OS random number generator
- the JSON header as associated authenticated data

ChaCha20-Poly1305 provides confidentiality and authentication for the encrypted file contents. The associated header is authenticated but not encrypted.

## Authenticated Header

The `.efe` header includes metadata such as:

- format marker
- app version
- creation time
- original filename
- recipient email
- recipient key fingerprint
- ephemeral public key
- nonce

EFE serializes the header with deterministic JSON key ordering and passes it to ChaCha20-Poly1305 as associated authenticated data. If the header is modified, decryption fails.

## Public And Private Key Separation

Public keys may be shared. They are used by senders to encrypt files for a recipient.

Private keys must never be shared. They are stored locally and encrypted at rest with a user passphrase.

Public key authenticity matters because an attacker can provide their own public key and trick a sender into encrypting to the attacker. The public key is not secret, but it must be authentic.

## Fingerprint Verification

EFE calculates a fingerprint for public keys and displays it during import and contact verification. Users should verify the fingerprint through a separate trusted channel, such as a phone call, WhatsApp, or in person.

The fingerprint workflow exists to reduce the risk of trusting the wrong public key.

## Private Keys At Rest

Private keys are serialized with encrypted private key serialization from the `cryptography` package. The passphrase is not stored in SQLite, config files, or audit logs.

If the private key or passphrase is lost, previously encrypted files may be unrecoverable.

## Known Limitations

- The `.efe` format and protocol glue have not been independently audited.
- EFE does not currently use age/pyrage.
- EFE does not use hardware-backed key storage.
- EFE does not provide enterprise key recovery.
- EFE does not protect decrypted files after successful decryption.
