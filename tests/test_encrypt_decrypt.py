import base64
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from app.config.settings import APP_NAME, APP_VERSION
from app.crypto.decrypt import decrypt_file
from app.crypto.encrypt import ENCRYPTED_METADATA_MODE, FILE_FORMAT, _derive_file_key, encrypt_file_for_contact
from app.crypto.key_manager import generate_user_key_pair, public_key_from_text


class EncryptDecryptTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.private_key_path = self.root / "private.pem"
        self.public_key_path = self.root / "public.json"
        self.default_decrypted_dir = self.root / "default-decrypted"
        self.passphrase = b"correct horse battery staple"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_encrypt_and_decrypt_round_trip(self):
        contact = generate_user_key_pair(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )
        source = self.root / "message.txt"
        encrypted = self.root / "message.txt.efe"
        decrypted = self.root / "message-decrypted.txt"
        source.write_text("hello from efe", encoding="utf-8")

        encrypt_file_for_contact(source, contact, encrypted)
        decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertNotEqual(encrypted.read_text(encoding="utf-8"), source.read_text(encoding="utf-8"))
        self.assertEqual(decrypted.read_text(encoding="utf-8"), "hello from efe")

    def _make_encrypted_file(self):
        contact = generate_user_key_pair(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )
        source = self.root / "message.txt"
        encrypted = self.root / "message.txt.efe"
        decrypted = self.root / "message-decrypted.txt"
        source.write_text("hello from efe", encoding="utf-8")
        encrypt_file_for_contact(source, contact, encrypted)
        return encrypted, decrypted

    def _read_payload(self, encrypted_path):
        return json.loads(encrypted_path.read_text(encoding="utf-8"))

    def _write_payload(self, encrypted_path, payload):
        encrypted_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _make_custom_encrypted_file(self, source: Path, encrypted: Path, metadata: dict, contact: dict) -> None:
        recipient_public_key = public_key_from_text(contact["public_key"])
        ephemeral_private_key = x25519.X25519PrivateKey.generate()
        ephemeral_public_bytes = ephemeral_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        shared_secret = ephemeral_private_key.exchange(recipient_public_key)
        file_key = _derive_file_key(shared_secret, ephemeral_public_bytes, contact["public_key"])
        nonce = os.urandom(12)
        header = {
            "format": FILE_FORMAT,
            "generated_by_app": APP_NAME,
            "app_version": APP_VERSION,
            "created_at": "2026-05-30T00:00:00+00:00",
            "metadata_mode": ENCRYPTED_METADATA_MODE,
            "recipient_email": contact["email"],
            "recipient_key_fingerprint": contact["key_fingerprint"],
            "ephemeral_public_key": base64.b64encode(ephemeral_public_bytes).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }
        metadata_bytes = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
        plaintext_payload = struct.pack(">I", len(metadata_bytes)) + metadata_bytes + source.read_bytes()
        ciphertext = ChaCha20Poly1305(file_key).encrypt(
            nonce,
            plaintext_payload,
            json.dumps(header, sort_keys=True).encode("utf-8"),
        )
        self._write_payload(
            encrypted,
            {
                "header": header,
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            },
        )

    def _make_legacy_encrypted_file(self, source: Path, encrypted: Path, contact: dict) -> None:
        recipient_public_key = public_key_from_text(contact["public_key"])
        ephemeral_private_key = x25519.X25519PrivateKey.generate()
        ephemeral_public_bytes = ephemeral_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        shared_secret = ephemeral_private_key.exchange(recipient_public_key)
        file_key = _derive_file_key(shared_secret, ephemeral_public_bytes, contact["public_key"])
        nonce = os.urandom(12)
        header = {
            "format": FILE_FORMAT,
            "generated_by_app": APP_NAME,
            "app_version": APP_VERSION,
            "created_at": "2026-05-30T00:00:00+00:00",
            "original_filename": source.name,
            "recipient_email": contact["email"],
            "recipient_key_fingerprint": contact["key_fingerprint"],
            "ephemeral_public_key": base64.b64encode(ephemeral_public_bytes).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }
        ciphertext = ChaCha20Poly1305(file_key).encrypt(
            nonce,
            source.read_bytes(),
            json.dumps(header, sort_keys=True).encode("utf-8"),
        )
        self._write_payload(
            encrypted,
            {
                "header": header,
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            },
        )

    def _assert_decrypt_fails_without_plaintext(self, encrypted_path, decrypted_path):
        with self.assertRaises(Exception):
            decrypt_file(
                encrypted_path,
                decrypted_path,
                private_key_path=self.private_key_path,
                passphrase=self.passphrase,
            )
        self.assertFalse(decrypted_path.exists())

    def test_tampered_ciphertext_fails_without_plaintext_output(self):
        encrypted, decrypted = self._make_encrypted_file()
        payload = self._read_payload(encrypted)
        ciphertext = bytearray(base64.b64decode(payload["ciphertext"]))
        ciphertext[0] ^= 1
        payload["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
        self._write_payload(encrypted, payload)

        self._assert_decrypt_fails_without_plaintext(encrypted, decrypted)

    def test_tampered_ciphertext_has_clear_error_message(self):
        encrypted, decrypted = self._make_encrypted_file()
        payload = self._read_payload(encrypted)
        ciphertext = bytearray(base64.b64decode(payload["ciphertext"]))
        ciphertext[0] ^= 1
        payload["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
        self._write_payload(encrypted, payload)

        with self.assertRaisesRegex(ValueError, "tampered with, corrupted"):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)
        self.assertFalse(decrypted.exists())

    def test_tampered_header_metadata_fails_without_plaintext_output(self):
        encrypted, decrypted = self._make_encrypted_file()
        payload = self._read_payload(encrypted)
        payload["header"]["recipient_email"] = "changed@example.com"
        self._write_payload(encrypted, payload)

        self._assert_decrypt_fails_without_plaintext(encrypted, decrypted)

    def test_new_encrypted_file_does_not_store_original_filename_in_plaintext(self):
        contact = generate_user_key_pair(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )
        sensitive_name = "Retrenchment_List_2026.txt"
        source = self.root / sensitive_name
        encrypted = self.root / "attachment.efe"
        source.write_text("sensitive content", encoding="utf-8")

        encrypt_file_for_contact(source, contact, encrypted)

        encrypted_bytes = encrypted.read_bytes()
        payload = self._read_payload(encrypted)
        self.assertNotIn("original_filename", payload["header"])
        self.assertNotIn(sensitive_name.encode("utf-8"), encrypted_bytes)

    def test_default_encrypted_output_name_does_not_include_original_filename(self):
        contact = generate_user_key_pair(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )
        source = self.root / "Payroll_April.txt"
        source.write_text("payroll", encoding="utf-8")
        with patch("app.crypto.encrypt.ENCRYPTED_DIR", self.root):
            encrypted_path = encrypt_file_for_contact(source, contact)

        self.assertTrue(encrypted_path.exists())
        self.assertNotIn(source.stem, encrypted_path.name)
        self.assertTrue(encrypted_path.name.startswith("efe-"))
        self.assertEqual(encrypted_path.suffix, ".efe")

    def test_decryption_restores_original_filename_from_encrypted_metadata(self):
        contact = generate_user_key_pair(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )
        source = self.root / "Payroll_April.txt"
        encrypted = self.root / "attachment.efe"
        source.write_text("payroll", encoding="utf-8")
        encrypt_file_for_contact(source, contact, encrypted)

        with patch("app.crypto.decrypt.DECRYPTED_DIR", self.default_decrypted_dir):
            decrypted_path = decrypt_file(encrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertEqual(decrypted_path.name, source.name)
        self.assertEqual(decrypted_path.read_text(encoding="utf-8"), "payroll")

    def test_tampered_encrypted_metadata_fails_without_plaintext_output(self):
        encrypted, decrypted = self._make_encrypted_file()
        payload = self._read_payload(encrypted)
        ciphertext = bytearray(base64.b64decode(payload["ciphertext"]))
        ciphertext[8] ^= 1
        payload["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
        self._write_payload(encrypted, payload)

        self._assert_decrypt_fails_without_plaintext(encrypted, decrypted)

    def test_legacy_plaintext_filename_files_still_decrypt(self):
        contact = generate_user_key_pair(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )
        source = self.root / "legacy-name.txt"
        encrypted = self.root / "legacy.efe"
        source.write_text("legacy content", encoding="utf-8")
        self._make_legacy_encrypted_file(source, encrypted, contact)

        with patch("app.crypto.decrypt.DECRYPTED_DIR", self.default_decrypted_dir):
            decrypted_path = decrypt_file(encrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertEqual(decrypted_path.name, "legacy-name.txt")
        self.assertEqual(decrypted_path.read_text(encoding="utf-8"), "legacy content")

    def test_unicode_filename_round_trip(self):
        contact = generate_user_key_pair(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )
        source = self.root / "résumé_客户.txt"
        encrypted = self.root / "unicode.efe"
        source.write_text("unicode", encoding="utf-8")
        encrypt_file_for_contact(source, contact, encrypted)

        with patch("app.crypto.decrypt.DECRYPTED_DIR", self.default_decrypted_dir):
            decrypted_path = decrypt_file(encrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertEqual(decrypted_path.name, source.name)
        self.assertEqual(decrypted_path.read_text(encoding="utf-8"), "unicode")

    def test_very_long_filename_is_bounded_safely_on_decrypt(self):
        contact = generate_user_key_pair(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )
        source = self.root / "short.txt"
        encrypted = self.root / "long-name.efe"
        long_name = f"{'a' * 260}.txt"
        source.write_text("long name", encoding="utf-8")
        self._make_custom_encrypted_file(
            source,
            encrypted,
            {"metadata_version": 1, "original_filename": long_name, "original_size": 9},
            contact,
        )

        with patch("app.crypto.decrypt.DECRYPTED_DIR", self.default_decrypted_dir):
            decrypted_path = decrypt_file(encrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertLessEqual(len(decrypted_path.name), 180)
        self.assertEqual(decrypted_path.suffix, ".txt")
        self.assertEqual(decrypted_path.read_text(encoding="utf-8"), "long name")

    def test_missing_encrypted_filename_metadata_falls_back_safely(self):
        contact = generate_user_key_pair(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )
        source = self.root / "source.txt"
        encrypted = self.root / "missing-name.efe"
        source.write_text("fallback", encoding="utf-8")
        self._make_custom_encrypted_file(
            source,
            encrypted,
            {"metadata_version": 1, "original_size": 8},
            contact,
        )

        with patch("app.crypto.decrypt.DECRYPTED_DIR", self.default_decrypted_dir):
            decrypted_path = decrypt_file(encrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertEqual(decrypted_path.name, "decrypted_output")
        self.assertEqual(decrypted_path.read_text(encoding="utf-8"), "fallback")

    def test_wrong_recipient_private_key_fails_without_plaintext_output(self):
        encrypted, decrypted = self._make_encrypted_file()
        wrong_private_key = self.root / "wrong-private.pem"
        wrong_public_key = self.root / "wrong-public.json"
        wrong_passphrase = b"wrong key passphrase"
        generate_user_key_pair(
            "Mallory Example",
            "mallory@example.com",
            passphrase=wrong_passphrase,
            private_key_path=wrong_private_key,
            public_key_record_path=wrong_public_key,
        )

        with self.assertRaises(Exception):
            decrypt_file(encrypted, decrypted, private_key_path=wrong_private_key, passphrase=wrong_passphrase)
        self.assertFalse(decrypted.exists())

    def test_corrupted_nonce_fails_without_plaintext_output(self):
        encrypted, decrypted = self._make_encrypted_file()
        payload = self._read_payload(encrypted)
        payload["header"]["nonce"] = base64.b64encode(b"too-short").decode("ascii")
        self._write_payload(encrypted, payload)

        self._assert_decrypt_fails_without_plaintext(encrypted, decrypted)

    def test_corrupted_ephemeral_public_key_fails_without_plaintext_output(self):
        encrypted, decrypted = self._make_encrypted_file()
        payload = self._read_payload(encrypted)
        payload["header"]["ephemeral_public_key"] = base64.b64encode(b"not-32-bytes").decode("ascii")
        self._write_payload(encrypted, payload)

        self._assert_decrypt_fails_without_plaintext(encrypted, decrypted)

    def test_invalid_json_file_fails_without_plaintext_output(self):
        encrypted, decrypted = self._make_encrypted_file()
        encrypted.write_text("{not valid json", encoding="utf-8")

        self._assert_decrypt_fails_without_plaintext(encrypted, decrypted)

    def test_invalid_json_file_has_clear_error_message(self):
        encrypted, decrypted = self._make_encrypted_file()
        encrypted.write_text("{not valid json", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "not valid JSON"):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

    def test_missing_required_header_field_fails_without_plaintext_output(self):
        encrypted, decrypted = self._make_encrypted_file()
        payload = self._read_payload(encrypted)
        del payload["header"]["nonce"]
        self._write_payload(encrypted, payload)

        self._assert_decrypt_fails_without_plaintext(encrypted, decrypted)

    def test_missing_required_header_field_has_clear_error_message(self):
        encrypted, decrypted = self._make_encrypted_file()
        payload = self._read_payload(encrypted)
        del payload["header"]["nonce"]
        self._write_payload(encrypted, payload)

        with self.assertRaisesRegex(ValueError, "header is missing: nonce"):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

    def test_invalid_base64_ciphertext_fails_without_plaintext_output(self):
        encrypted, decrypted = self._make_encrypted_file()
        payload = self._read_payload(encrypted)
        payload["ciphertext"] = "not valid base64!!!!"
        self._write_payload(encrypted, payload)

        self._assert_decrypt_fails_without_plaintext(encrypted, decrypted)

    def test_invalid_base64_ciphertext_has_clear_error_message(self):
        encrypted, decrypted = self._make_encrypted_file()
        payload = self._read_payload(encrypted)
        payload["ciphertext"] = "not valid base64!!!!"
        self._write_payload(encrypted, payload)

        with self.assertRaisesRegex(ValueError, "Invalid base64 value for ciphertext"):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

    def test_failed_encrypt_atomic_replace_leaves_no_partial_output(self):
        contact = generate_user_key_pair(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )
        source = self.root / "message.txt"
        encrypted = self.root / "message.txt.efe"
        source.write_text("hello from efe", encoding="utf-8")

        with patch("app.file_io.os.replace", side_effect=PermissionError("replace denied")):
            with self.assertRaises(PermissionError):
                encrypt_file_for_contact(source, contact, encrypted)

        self.assertFalse(encrypted.exists())
        leftovers = [path for path in self.root.iterdir() if path.name not in {"message.txt", "private.pem", "public.json"}]
        self.assertEqual(leftovers, [])

    def test_failed_decrypt_atomic_replace_leaves_no_plaintext_output(self):
        encrypted, decrypted = self._make_encrypted_file()

        with patch("app.file_io.os.replace", side_effect=PermissionError("replace denied")):
            with self.assertRaises(PermissionError):
                decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertFalse(decrypted.exists())

    def test_existing_encrypted_output_is_not_overwritten(self):
        contact = generate_user_key_pair(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )
        source = self.root / "message.txt"
        encrypted = self.root / "message.txt.efe"
        source.write_text("hello from efe", encoding="utf-8")
        encrypted.write_text("existing encrypted data", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            encrypt_file_for_contact(source, contact, encrypted)

        self.assertEqual(encrypted.read_text(encoding="utf-8"), "existing encrypted data")

    def test_existing_decrypted_output_is_not_overwritten(self):
        encrypted, decrypted = self._make_encrypted_file()
        decrypted.write_text("existing plaintext", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertEqual(decrypted.read_text(encoding="utf-8"), "existing plaintext")

    def test_missing_input_file_fails_without_output(self):
        contact = generate_user_key_pair(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )
        missing = self.root / "missing.txt"
        encrypted = self.root / "missing.txt.efe"

        with self.assertRaises(FileNotFoundError):
            encrypt_file_for_contact(missing, contact, encrypted)

        self.assertFalse(encrypted.exists())


if __name__ == "__main__":
    unittest.main()
