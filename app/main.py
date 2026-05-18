import argparse
import getpass
import sys
from pathlib import Path

from app.config.settings import APP_FULL_NAME, APP_NAME, APP_VERSION, DB_PATH, ensure_data_dirs
from app.crypto.encrypt import CRYPTO_FORMAT_VERSION, FILE_FORMAT
from app.services.audit_service import get_audit_entries, init_audit_log
from app.services.contact_service import (
    get_all_contacts,
    get_contact,
    import_contact_key,
    init_contact_book,
    mark_contact_verified,
)
from app.services.file_crypto_service import decrypt_received_file, encrypt_file_for_recipient
from app.services.key_service import export_user_public_key, initialize_user_key


def _init_db() -> None:
    ensure_data_dirs()
    init_contact_book(DB_PATH)
    init_audit_log(DB_PATH)


def _print_security_warnings() -> None:
    print("Security reminders:")
    print("- Public keys may be shared.")
    print("- Private keys must never be shared.")
    print("- Private keys are encrypted locally with your passphrase.")
    print("- Losing the private key or passphrase may make encrypted files unrecoverable.")
    print("- Verify a public key fingerprint before trusting the key.")
    print("- efe does not upload files or keys to the cloud.")
    print("- efe never stores original file contents in SQLite.")
    print("- efe is an MVP and has not been independently audited.")


def _prompt_new_passphrase() -> bytes:
    passphrase = getpass.getpass("Create private key passphrase: ")
    confirmation = getpass.getpass("Confirm private key passphrase: ")
    if passphrase != confirmation:
        raise ValueError("Passphrases do not match.")
    if not passphrase:
        raise ValueError("Passphrase cannot be empty.")
    return passphrase.encode("utf-8")


def _prompt_private_key_passphrase() -> bytes:
    passphrase = getpass.getpass("Private key passphrase: ")
    if not passphrase:
        raise ValueError("Passphrase cannot be empty.")
    return passphrase.encode("utf-8")


def _user_error_message(exc: Exception) -> str:
    if isinstance(exc, FileExistsError):
        return "Output file already exists. Choose a different output path."
    if isinstance(exc, PermissionError):
        return "Permission denied while accessing a file or directory. Check the path permissions."
    if isinstance(exc, FileNotFoundError):
        return "File or directory not found. Check the path and try again."
    if isinstance(exc, IsADirectoryError):
        return "Expected a file path but received a directory path."
    if isinstance(exc, ValueError):
        return str(exc)
    if isinstance(exc, OSError):
        return f"File system error: {exc}"
    return str(exc)


def cmd_init_user_key(args: argparse.Namespace) -> int:
    try:
        passphrase = _prompt_new_passphrase()
        record = initialize_user_key(args.display_name, args.email, passphrase=passphrase, overwrite=args.overwrite)
    except Exception as exc:
        print(f"Key generation failed: {_user_error_message(exc)}", file=sys.stderr)
        return 1
    _print_security_warnings()
    print(f"Created local private key and public key record for {record['email']}.")
    print(f"Public key fingerprint: {record['key_fingerprint']}")
    return 0


def cmd_export_public_key(args: argparse.Namespace) -> int:
    try:
        export_path = export_user_public_key(Path(args.output))
        print(f"Exported public key to: {export_path}")
        print("Public keys may be shared, but the receiver should verify the fingerprint with you.")
        return 0
    except Exception as exc:
        print(f"Public key export failed: {_user_error_message(exc)}", file=sys.stderr)
        return 1


def cmd_import_contact_key(args: argparse.Namespace) -> int:
    _init_db()
    verified = bool(args.verified or args.confirm_verified)
    try:
        record = import_contact_key(Path(args.key_file), verified=verified, db_path=DB_PATH)
    except Exception as exc:
        print(f"Contact key import failed: {_user_error_message(exc)}", file=sys.stderr)
        return 1
    print(f"Importing public key for {record['display_name']} <{record['email']}>")
    print(f"Fingerprint: {record['key_fingerprint']}")
    print("Verify this fingerprint through another channel, such as a phone call, WhatsApp, or in person.")
    print(f"Saved contact key. Verified: {'yes' if verified else 'no'}")
    return 0


def cmd_list_contacts(args: argparse.Namespace) -> int:
    _init_db()
    contacts = get_all_contacts(DB_PATH)
    if not contacts:
        print("No contacts saved yet.")
        return 0
    for contact in contacts:
        status = "verified" if contact["verified"] else "unverified"
        print(f"{contact['id']}: {contact['display_name']} <{contact['email']}> [{status}]")
        print(f"   fingerprint: {contact['key_fingerprint']}")
    return 0


def cmd_verify_contact_key(args: argparse.Namespace) -> int:
    _init_db()
    contact = get_contact(args.email, DB_PATH)
    if contact is None:
        print(f"No contact found for {args.email}", file=sys.stderr)
        return 1
    print(f"Contact: {contact['display_name']} <{contact['email']}>")
    print(f"Fingerprint: {contact['key_fingerprint']}")
    print("Only mark this verified after checking the fingerprint through another channel.")
    if not args.yes:
        answer = input("Mark this key as verified? Type YES to continue: ")
        if answer != "YES":
            print("Verification cancelled.")
            return 1
    mark_contact_verified(args.email, DB_PATH)
    print("Contact key marked as verified.")
    return 0


def cmd_encrypt_file(args: argparse.Namespace) -> int:
    _init_db()
    contact = get_contact(args.recipient_email, DB_PATH)
    input_path = Path(args.input_file)
    if contact is None:
        print(f"No contact found for {args.recipient_email}", file=sys.stderr)
        return 1

    if not contact["verified"]:
        print("Warning: this contact key is unverified.")
        print("Verify the fingerprint before trusting this key:")
        print(contact["key_fingerprint"])
        if not args.yes:
            answer = input("Encrypt anyway? Type YES to continue: ")
            if answer != "YES":
                print("Encryption cancelled.")
                return 1

    try:
        output_path = encrypt_file_for_recipient(
            input_path,
            args.recipient_email,
            Path(args.output) if args.output else None,
            db_path=DB_PATH,
        )
        print(f"Encrypted file written to: {output_path}")
        return 0
    except Exception as exc:
        print(f"Encryption failed: {_user_error_message(exc)}", file=sys.stderr)
        return 1


def cmd_decrypt_file(args: argparse.Namespace) -> int:
    _init_db()
    input_path = Path(args.input_file)
    try:
        passphrase = _prompt_private_key_passphrase()
        output_path = decrypt_received_file(
            input_path,
            passphrase,
            Path(args.output) if args.output else None,
            db_path=DB_PATH,
        )
        print(f"Decrypted file written to: {output_path}")
        return 0
    except Exception as exc:
        print(f"Decryption failed: {_user_error_message(exc)}", file=sys.stderr)
        return 1


def cmd_version(args: argparse.Namespace) -> int:
    print("EFE")
    print(APP_FULL_NAME)
    print(f"App version: {APP_VERSION}")
    print(f"Crypto format version: {CRYPTO_FORMAT_VERSION}")
    print(f"Crypto format: {FILE_FORMAT}")
    return 0


def cmd_show_audit_log(args: argparse.Namespace) -> int:
    _init_db()
    rows = get_audit_entries(DB_PATH)
    if not rows:
        print("No audit log entries yet.")
        return 0
    for row in rows:
        status = "success" if row["success"] else "failure"
        recipient = f" recipient={row['recipient_email']}" if row["recipient_email"] else ""
        print(f"{row['id']} {row['timestamp']} {row['action_type']} {status} file={row['filename']}{recipient}")
        if row["key_fingerprint"]:
            print(f"   fingerprint: {row['key_fingerprint']}")
        if row["error_message"]:
            print(f"   error: {row['error_message']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="efe local attachment encryption CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_key = subparsers.add_parser("init-user-key", help="Generate your local private key and public key record")
    init_key.add_argument("--display-name", required=True)
    init_key.add_argument("--email", required=True)
    init_key.add_argument("--overwrite", action="store_true")
    init_key.set_defaults(func=cmd_init_user_key)

    export_key = subparsers.add_parser("export-public-key", help="Export your public key for sharing")
    export_key.add_argument("--output", required=True)
    export_key.set_defaults(func=cmd_export_public_key)

    import_key = subparsers.add_parser("import-contact-key", help="Import a recipient public key")
    import_key.add_argument("key_file")
    import_key.add_argument("--verified", action="store_true", help="Mark as verified at import time")
    import_key.add_argument("--confirm-verified", action="store_true", help="Alias for --verified")
    import_key.set_defaults(func=cmd_import_contact_key)

    list_keys = subparsers.add_parser("list-contacts", help="List saved recipient public keys")
    list_keys.set_defaults(func=cmd_list_contacts)

    verify_key = subparsers.add_parser("verify-contact-key", help="Mark a contact key as verified")
    verify_key.add_argument("email")
    verify_key.add_argument("--yes", action="store_true", help="Skip interactive confirmation")
    verify_key.set_defaults(func=cmd_verify_contact_key)

    encrypt = subparsers.add_parser("encrypt-file", help="Encrypt a file for a saved recipient")
    encrypt.add_argument("input_file")
    encrypt.add_argument("--recipient-email", required=True)
    encrypt.add_argument("--output")
    encrypt.add_argument("--yes", action="store_true", help="Confirm encrypting to an unverified key")
    encrypt.set_defaults(func=cmd_encrypt_file)

    decrypt = subparsers.add_parser("decrypt-file", help="Decrypt an efe encrypted file")
    decrypt.add_argument("input_file")
    decrypt.add_argument("--output")
    decrypt.set_defaults(func=cmd_decrypt_file)

    audit = subparsers.add_parser("show-audit-log", help="Show encryption/decryption audit entries")
    audit.set_defaults(func=cmd_show_audit_log)

    version = subparsers.add_parser("version", help="Show EFE version information")
    version.set_defaults(func=cmd_version)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
