import argparse
import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path

from app.audit.audit_log import init_audit_db, list_audit_log, log_action
from app.config.settings import DB_PATH, ensure_data_dirs
from app.contacts.contacts_db import (
    add_contact,
    get_contact_by_email,
    init_contacts_db,
    list_contacts,
    verify_contact_key,
)
from app.crypto.decrypt import decrypt_file
from app.crypto.encrypt import encrypt_file_for_contact
from app.crypto.key_manager import (
    export_public_key,
    generate_user_key_pair,
    get_private_key_fingerprint,
    load_public_key_record,
)


def _init_db() -> None:
    ensure_data_dirs()
    init_contacts_db(DB_PATH)
    init_audit_db(DB_PATH)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def cmd_init_user_key(args: argparse.Namespace) -> int:
    try:
        passphrase = _prompt_new_passphrase()
        record = generate_user_key_pair(args.display_name, args.email, passphrase=passphrase, overwrite=args.overwrite)
    except Exception as exc:
        print(f"Key generation failed: {exc}", file=sys.stderr)
        return 1
    _print_security_warnings()
    print(f"Created local private key and public key record for {record['email']}.")
    print(f"Public key fingerprint: {record['key_fingerprint']}")
    return 0


def cmd_export_public_key(args: argparse.Namespace) -> int:
    export_path = export_public_key(Path(args.output))
    print(f"Exported public key to: {export_path}")
    print("Public keys may be shared, but the receiver should verify the fingerprint with you.")
    return 0


def cmd_import_contact_key(args: argparse.Namespace) -> int:
    _init_db()
    record = load_public_key_record(Path(args.key_file))
    print(f"Importing public key for {record['display_name']} <{record['email']}>")
    print(f"Fingerprint: {record['key_fingerprint']}")
    print("Verify this fingerprint through another channel, such as a phone call, WhatsApp, or in person.")
    verified = bool(args.verified)
    if not verified and args.confirm_verified:
        verified = True
    add_contact(record, verified=verified)
    print(f"Saved contact key. Verified: {'yes' if verified else 'no'}")
    return 0


def cmd_list_contacts(args: argparse.Namespace) -> int:
    _init_db()
    contacts = list_contacts()
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
    contact = get_contact_by_email(args.email)
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
    verify_contact_key(args.email)
    print("Contact key marked as verified.")
    return 0


def cmd_encrypt_file(args: argparse.Namespace) -> int:
    _init_db()
    contact = get_contact_by_email(args.recipient_email)
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
        output_path = encrypt_file_for_contact(input_path, dict(contact), Path(args.output) if args.output else None)
        log_action(
            timestamp=_now(),
            action_type="encrypt",
            filename=input_path.name,
            recipient_email=contact["email"],
            key_fingerprint=contact["key_fingerprint"],
            success=True,
        )
        print(f"Encrypted file written to: {output_path}")
        return 0
    except Exception as exc:
        log_action(
            timestamp=_now(),
            action_type="encrypt",
            filename=input_path.name,
            recipient_email=args.recipient_email,
            key_fingerprint=contact["key_fingerprint"],
            success=False,
            error_message=str(exc),
        )
        print(f"Encryption failed: {exc}", file=sys.stderr)
        return 1


def cmd_decrypt_file(args: argparse.Namespace) -> int:
    _init_db()
    input_path = Path(args.input_file)
    key_fingerprint = None
    try:
        passphrase = _prompt_private_key_passphrase()
        key_fingerprint = get_private_key_fingerprint(passphrase=passphrase)
        output_path = decrypt_file(input_path, Path(args.output) if args.output else None, passphrase=passphrase)
        log_action(
            timestamp=_now(),
            action_type="decrypt",
            filename=input_path.name,
            recipient_email=None,
            key_fingerprint=key_fingerprint,
            success=True,
        )
        print(f"Decrypted file written to: {output_path}")
        return 0
    except Exception as exc:
        log_action(
            timestamp=_now(),
            action_type="decrypt",
            filename=input_path.name,
            recipient_email=None,
            key_fingerprint=key_fingerprint,
            success=False,
            error_message=str(exc),
        )
        print(f"Decryption failed: {exc}", file=sys.stderr)
        return 1


def cmd_show_audit_log(args: argparse.Namespace) -> int:
    _init_db()
    rows = list_audit_log()
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

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
