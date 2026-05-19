# EFE Threat Model

EFE, short for Encrypted File Exchange, is a local CLI MVP with a thin PySide6 desktop GUI prototype for encrypting and decrypting files and email attachments. It does not replace Outlook, Gmail, or any other email client. Users encrypt files locally and manually send the resulting `.efe` encrypted file through ordinary channels.

This document reflects the v0.6 public-key QR export checkpoint. EFE can export a user's public key record as a QR code PNG, but it does not implement QR scanning, webcam import, cloud sync, a public key server, or email-client integration.

## What EFE Protects

EFE is intended to protect file contents while they are outside the sender and recipient's direct control, for example while attached to email, copied through removable media, or stored in a normal file location before the intended recipient decrypts them.

EFE protects the confidentiality and integrity of encrypted `.efe` file contents when:

- the recipient public key is authentic
- the recipient private key remains secret
- the private key passphrase remains secret
- the sender and recipient devices are not compromised
- the encrypted file is decrypted only by the intended recipient

## What EFE Does Not Protect

EFE does not protect against:

- malware already on the sender machine
- malware already on the recipient machine
- a stolen private key passphrase
- a compromised private key
- a user trusting the wrong public key
- weak endpoint security
- screenshots, copy/paste, printing, or copying after decryption
- unauthorised access after a file is decrypted
- insecure backups of decrypted files
- users sending the decrypted original by mistake
- legal, compliance, or operational failures outside the tool

## Assets Protected

- Original file contents before encryption and after decryption
- Encrypted file contents inside `.efe` files
- Local private key material
- Private key passphrase, while entered by the user
- Recipient public keys and trust status in the local contact book
- Exported public key records, including JSON and QR code forms
- Audit log metadata

## Trust Assumptions

- The user's operating system, filesystem, Python runtime, and installed dependencies behave correctly.
- The `cryptography` package implements X25519, HKDF-SHA256, and ChaCha20-Poly1305 correctly.
- The PySide6 and `qrcode[pil]` dependencies behave correctly for GUI display and QR generation.
- The OS random number generator is secure.
- Users choose strong passphrases and keep them secret.
- Users verify public key fingerprints through a separate trusted channel.
- Users protect backups of private keys and decrypted files.
- Local filesystem permissions are meaningful on the user's device.

## Threat Actors

- An email account intruder who obtains encrypted attachments.
- A network observer or mail server operator who can see attachments in transit or at rest.
- A malicious or careless insider who obtains an encrypted file.
- A person who tricks a user into importing and trusting the wrong public key.
- Malware or a local attacker on the sender or recipient device.
- A thief who obtains a computer, backup, or local key files.

## Main Threats

- Reading file contents from intercepted email attachments.
- Tampering with encrypted files before delivery.
- Replacing a real public key with an attacker's public key.
- Guessing or stealing a private key passphrase.
- Copying private key files from the user's machine.
- Recovering sensitive data from decrypted output files or backups.
- Confusing users into trusting unverified keys.

## Mitigations Already Implemented

- X25519 key agreement with an ephemeral sender key for each encryption.
- HKDF-SHA256 key derivation.
- ChaCha20-Poly1305 authenticated encryption.
- 12-byte random nonce for each encryption.
- JSON header authenticated as associated data.
- Public key fingerprints.
- Contact verification status.
- Warning and explicit confirmation when encrypting to unverified contacts.
- Public key import validation.
- Public key QR export containing the public key record only.
- Passphrase-encrypted private keys at rest.
- Atomic output writes.
- No silent overwrite of existing output files.
- SQLite audit logging for encryption and decryption attempts.
- Tests for tampering, wrong key, malformed files, invalid keys, service behavior, CLI behavior, GUI imports, and public key QR export.

## Remaining Risks

- EFE is an MVP and has not been independently audited.
- The `.efe` file format and protocol glue are custom and should be reviewed.
- Private keys are protected by passphrase encryption, but not by hardware-backed storage.
- There is no enterprise key recovery.
- There is no central public key directory or certificate authority.
- QR export exists, but QR scanning and webcam import do not exist yet.
- Users may still trust the wrong key if they skip fingerprint verification.
- Decrypted files remain ordinary files and must be protected by users and organisations.
- EFE does not provide secure deletion.
- Audit logs contain metadata such as filenames, recipient email addresses, and key fingerprints.

## Out-of-Scope Threats

- Compromised operating systems.
- Malware with access to plaintext before encryption or after decryption.
- Compromised email accounts after a user sends decrypted files.
- Attacks against Outlook, Gmail, or other email clients.
- Cloud storage compromise outside EFE's local file handling.
- Physical coercion, social engineering, or legal compulsion.
- Full organisational compliance guarantees.
