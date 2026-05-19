# EFE Known Limitations

EFE is an MVP. It is not production-ready, certified, or independently audited.

Known limitations include:

- EFE has not been independently audited.
- The `.efe` file format and protocol glue are custom.
- There is no secure deletion guarantee.
- EFE does not protect against malware.
- EFE does not protect against compromised sender or recipient devices.
- EFE does not protect files after a recipient decrypts and mishandles them.
- There is no central public key directory.
- There is no certificate authority.
- There is no enterprise recovery key.
- There is no hardware-backed key storage.
- There are no mobile apps.
- There is no Outlook or Gmail integration.
- There is no cloud sync.
- There is no automatic key rotation.
- Public key QR export exists, but QR scanning and webcam import do not exist yet.
- There is no automatic migration from older project-relative `data/` directories to the per-user app data directory.
- There is no guarantee of POPIA compliance.
- Audit logs contain metadata such as filenames, recipient emails, and fingerprints.
- Decrypted files are ordinary plaintext files and may be copied, backed up, screenshotted, printed, or otherwise exposed.
- If a user trusts the wrong public key, files may be encrypted to the wrong recipient.
- If a private key or passphrase is lost, encrypted files may be unrecoverable.

EFE should be treated as a local security MVP and reviewed before any high-risk or regulated production use.
