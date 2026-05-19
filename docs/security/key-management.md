# EFE Key Management

EFE uses local asymmetric key pairs so users can encrypt files for saved contacts and decrypt files sent to them.

## Local Key Generation

Users generate a local X25519 key pair with the CLI or GUI. The private key stays on the local machine. The public key is saved separately so it can be exported and shared.

## Public Key Export

Public keys may be shared. They are used by other people to encrypt files for the key owner.

The exported public key record contains harmless metadata:

- display name
- email
- public key
- key fingerprint
- app name
- app version
- creation time

Public keys are not secret, but they must be authentic.

## Private Key Storage

Private keys are stored locally and encrypted at rest with a passphrase. EFE does not store the passphrase in SQLite, config files, environment variables, or audit logs.

Private keys must never be shared.

If the private key or passphrase is lost, encrypted files may be unrecoverable.

## Public Key Import

When importing a contact public key, EFE validates that:

- the public key is valid base64
- the decoded key is 32 bytes
- the decoded key can be loaded as an X25519 public key
- the fingerprint matches the canonical public key material

Invalid public keys are rejected before they are saved to SQLite.

## Fingerprint Verification

EFE displays public key fingerprints so users can verify them through another trusted channel, such as a phone call, WhatsApp, or in person.

This matters because an attacker can provide their own public key. If a sender trusts the wrong key, they may encrypt sensitive files for the attacker.

## Verified And Unverified Contacts

Imported contacts can be marked verified after the fingerprint is checked.

If a contact key is unverified, EFE warns before encryption and requires explicit confirmation in the CLI. The GUI prototype also warns before encrypting to an unverified contact.

## Sensitive Personal Identifiers

Do not include ID numbers, passport numbers, or other sensitive personal identifiers in public key metadata.

Public key metadata is intended to be shareable. Adding sensitive personal identifiers increases privacy risk and is not required for key verification.

## Current Limitations

- There is no central public key directory.
- There is no certificate authority.
- There is no enterprise key recovery.
- There is no automatic key rotation.
- There is no hardware-backed key storage.
- There is no multi-device key sync.

## Recommended User Practices

- Use a strong private key passphrase.
- Store private key backups securely.
- Do not share private keys or passphrases.
- Verify public key fingerprints before trusting contacts.
- Treat decrypted files as sensitive ordinary files.
- Delete or protect decrypted copies according to organisational policy.
- Protect backups that may contain decrypted files or private keys.
