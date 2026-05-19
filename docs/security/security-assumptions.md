# EFE Security Assumptions

EFE's security depends on several assumptions. If these assumptions do not hold, EFE may not protect files as intended.

## Device And Runtime

- The sender device is not already compromised.
- The recipient device is not already compromised.
- The operating system behaves correctly.
- Local filesystem permissions are respected.
- The user's per-user app data directory, such as `%LOCALAPPDATA%\EFE\` on Windows, is available and protected by normal OS account controls.
- Python and the installed runtime are trusted.
- Required dependencies are installed from trusted sources.
- The `cryptography` package behaves correctly.
- The PySide6 dependency behaves correctly for the GUI prototype.
- The `qrcode[pil]` dependency behaves correctly when generating public key QR PNG files.

## Randomness And Cryptography

- The operating system random number generator is secure.
- X25519, HKDF-SHA256, and ChaCha20-Poly1305 are implemented correctly by the dependency library.
- Nonces are generated with sufficient randomness.
- The private key encryption implementation behaves correctly.

## User Behaviour

- Users choose strong passphrases.
- Users do not share private keys.
- Users do not share private key passphrases.
- Users verify public key fingerprints correctly through a separate trusted channel.
- Users do not mark keys verified without checking the fingerprint.
- Users do not send decrypted original files by mistake.

## Key And File Handling

- Private key backups are protected.
- Decrypted files are handled safely after decryption.
- Decrypted file backups are protected or avoided.
- Users understand that decrypted files are ordinary plaintext files.
- Users protect the device against malware and unauthorised local access.

## Organisational Assumptions

- EFE is used as one technical safeguard inside a broader data protection process.
- Organisations maintain appropriate policies, training, access control, retention rules, incident response, and backup controls.
- EFE is not treated as a complete compliance solution.
