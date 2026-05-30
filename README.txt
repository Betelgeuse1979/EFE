efe
===

efe, short for Encrypted File Exchange, is a practical local-first encrypted file exchange tool. It helps users encrypt and decrypt files or email attachments without replacing Outlook, Gmail, or any other email client. You encrypt a file locally, then manually attach the encrypted .efe file to your normal email.

EFE v1 is intended to be free for basic desktop use. The .efe file format is also intended to become a reusable local protocol layer for future tools. Commercial or business workflow products may later be built around EFE, such as evidence logs, practical compliance support, encrypted exports, team deployment tooling, and support services.

Security Model
--------------

- Public keys may be shared.
- Private keys must never be shared.
- Private keys are encrypted at rest with a passphrase.
- Losing your private key or passphrase may make encrypted files unrecoverable.
- A public key fingerprint should be verified before trusting the key.
- efe does not upload files or keys to the cloud.
- efe never stores original file contents in SQLite.
- Do not put ID numbers, passport numbers, or other sensitive personal identifiers in public key metadata.

Compliance Positioning
----------------------

EFE is designed to help reduce the risk of unauthorised access to sensitive files sent through ordinary email.

Under South Africa's POPIA framework, organisations that process personal information are expected to take appropriate and reasonable technical and organisational measures to protect that information. If personal information is accessed or acquired by an unauthorised person, breach-notification obligations may arise.

EFE does not make an organisation automatically POPIA compliant and is not legal advice. It should be seen as one practical technical safeguard within a broader data protection process that may also include policies, staff training, access control, retention rules, incident response, secure backups, and evidence of reasonable steps taken.

This MVP uses Python's well-supported cryptography package with X25519 and ChaCha20-Poly1305. The crypto backend is intentionally isolated under app/crypto/ so it can be swapped to age or pyrage later.

efe is still an MVP and has not been independently audited. Do not rely on it yet for high-risk or regulated data.

Security Documentation
----------------------

See docs/security/ for the threat model, crypto design, file format, key management notes, security assumptions, known limitations, and proposed audit scope.

Roadmap And Architecture
------------------------

- Roadmap: docs/backlog/roadmap.md
- Architecture Notes: docs/architecture.md
- Testing Backlog: docs/backlog/testing.md

The roadmap keeps EFE local-first: core encryption/decryption should not require cloud infrastructure. Before a v1 public release, the .efe file format must be stabilized, metadata leakage must be reviewed, and large-file handling must be defined.

Setup
-----

cd efe
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

CLI Examples
------------

Generate your local key pair:

python -m app.main init-user-key --display-name "Alice Example" --email alice@example.com

You will be prompted for a private key passphrase. The passphrase is not shown on screen and is not stored by efe. Older unencrypted MVP keys should be regenerated.

Export your public key for sharing:

python -m app.main export-public-key --output alice-public-key.json

Export your public key as a QR code:

python -m app.main export-public-key-qr --output alice-public-key.png

The QR code contains the public key record only. It does not contain your private key or passphrase. Recipients should still verify the fingerprint before trusting the key.

Import a recipient public key:

python -m app.main import-contact-key bob-public-key.json

After checking the fingerprint by phone, WhatsApp, or in person, mark the contact as verified:

python -m app.main verify-contact-key bob@example.com

List contacts:

python -m app.main list-contacts

Encrypt a file for a saved recipient:

python -m app.main encrypt-file .\document.pdf --recipient-email bob@example.com

If the contact is unverified, efe warns you and requires explicit confirmation. For scripts, use --yes.

Decrypt a received file:

python -m app.main decrypt-file .\data\encrypted\document.pdf.efe

You will be prompted for your private key passphrase.

Encrypted and decrypted outputs are written atomically. If the output file already exists, efe stops and asks you to choose a different output path rather than silently overwriting it.

Show the audit log:

python -m app.main show-audit-log

Show version information:

python -m app.main version

Show where EFE stores local runtime data:

python -m app.main data-dir

GUI Prototype
-------------

The CLI remains available. A first PySide6 desktop prototype can be launched with:

python -m app.gui.app

The GUI calls the same service layer as the CLI and does not replace Outlook, Gmail, or any other email client.

Packaging Prototype
-------------------

EFE includes a developer packaging prototype for a Windows GUI one-folder build using PyInstaller. This is not a signed installer and does not mean EFE is production-ready.

.\packaging\build_windows_gui.ps1

See packaging/README.md for prerequisites, expected output, runtime data location, and known limitations. The prototype packages the GUI only; the CLI remains available from source with python -m app.main ...

Public Key Record
-----------------

Public key JSON records contain harmless metadata:

- display_name
- email
- public_key
- key_fingerprint
- generated_by_app
- app_version
- created_at

The fingerprint is calculated from the public key and displayed when importing. The user should verify it through another channel before marking the contact key as trusted.

When importing a contact key, efe checks that the public key is valid base64, decodes to a 32-byte X25519 public key, can be loaded by the cryptography library, and matches the supplied fingerprint before it is saved to SQLite.

Encrypted File Format
---------------------

Encrypted files use a JSON .efe format. A .efe file is an encrypted attachment or file; it is not an email message and does not contain email client data.

Required top-level fields:

- header
- ciphertext

Required header fields:

- format
- generated_by_app
- app_version
- created_at
- original_filename
- recipient_email
- recipient_key_fingerprint
- ephemeral_public_key
- nonce

Base64 fields:

- ciphertext
- header.ephemeral_public_key
- header.nonce

The full header is authenticated as additional data by ChaCha20-Poly1305. Tampering with any required header field, the ciphertext, the nonce, or the ephemeral public key causes decryption to fail.

{
  "header": {
    "format": "efe-X25519-ChaCha20Poly1305-v1",
    "generated_by_app": "efe",
    "app_version": "0.1.0",
    "created_at": "...",
    "original_filename": "...",
    "recipient_email": "...",
    "recipient_key_fingerprint": "...",
    "ephemeral_public_key": "...",
    "nonce": "..."
  },
  "ciphertext": "..."
}

Decryption also fails if the file is invalid JSON, missing required fields, contains invalid base64 values, was encrypted for a different private key, or the private key passphrase is wrong.

Data Layout
-----------

On Windows, EFE stores runtime user data under:

%LOCALAPPDATA%\EFE\

For example:

C:\Users\<User>\AppData\Local\EFE\

On non-Windows systems, EFE uses:

~/.local/share/efe/

Advanced development/testing override:

$env:EFE_DATA_DIR = "C:\path\to\test-data"

Normal users should not need to set EFE_DATA_DIR.

%LOCALAPPDATA%\EFE\
  keys/
    efe_private_key.pem
    efe_public_key.json
  encrypted/
  decrypted/
  efe.db

Older development builds used the project-relative data/ directory. EFE does not automatically migrate that data. If you need old development keys or contacts, manually copy data/keys/ and data/efe.db into the new data directory. Losing a private key or its passphrase may make encrypted files unrecoverable.

Tests
-----

cd efe
python -m unittest discover -s tests
