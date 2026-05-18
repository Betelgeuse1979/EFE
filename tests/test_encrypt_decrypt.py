import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.crypto.decrypt import decrypt_file
from app.crypto.encrypt import encrypt_file_for_contact
from app.crypto.key_manager import generate_user_key_pair


class EncryptDecryptTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.private_key_path = self.root / "private.pem"
        self.public_key_path = self.root / "public.json"
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
        payload["header"]["original_filename"] = "changed.txt"
        self._write_payload(encrypted, payload)

        self._assert_decrypt_fails_without_plaintext(encrypted, decrypted)

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
