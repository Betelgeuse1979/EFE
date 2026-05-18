import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from app.crypto.fingerprint import calculate_fingerprint
from app.crypto.key_manager import generate_user_key_pair, load_private_key, load_public_key_record


class KeyManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.private_key_path = self.root / "private.pem"
        self.public_key_path = self.root / "public.json"
        self.passphrase = b"local test passphrase"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_encrypted_private_key_loads_with_correct_passphrase(self):
        generate_user_key_pair(
            "Alice Example",
            "alice@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )

        private_key = load_private_key(self.private_key_path, passphrase=self.passphrase)
        self.assertIsNotNone(private_key.public_key())

    def test_encrypted_private_key_fails_with_wrong_passphrase(self):
        generate_user_key_pair(
            "Alice Example",
            "alice@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )

        with self.assertRaises(ValueError):
            load_private_key(self.private_key_path, passphrase=b"wrong passphrase")

    def test_old_unencrypted_private_key_is_rejected_clearly(self):
        private_key = x25519.X25519PrivateKey.generate()
        self.private_key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        with self.assertRaisesRegex(ValueError, "Unencrypted private keys"):
            load_private_key(self.private_key_path, passphrase=self.passphrase)

    def test_private_key_file_is_encrypted_at_rest(self):
        generate_user_key_pair(
            "Alice Example",
            "alice@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )

        key_text = self.private_key_path.read_text(encoding="utf-8")
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", key_text)
        self.assertNotIn("BEGIN PRIVATE KEY", key_text.replace("BEGIN ENCRYPTED PRIVATE KEY", ""))

    def test_invalid_base64_public_key_import_is_rejected(self):
        record = {
            "display_name": "Bad Key",
            "email": "bad@example.com",
            "public_key": "not valid base64!!!!",
            "key_fingerprint": "ABCD",
            "created_at": "2026-05-18T00:00:00+00:00",
        }
        self.public_key_path.write_text(json.dumps(record), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "not valid base64"):
            load_public_key_record(self.public_key_path)

    def test_wrong_length_public_key_import_is_rejected(self):
        public_key = "c2hvcnQ="
        record = {
            "display_name": "Bad Key",
            "email": "bad@example.com",
            "public_key": public_key,
            "key_fingerprint": calculate_fingerprint(public_key),
            "created_at": "2026-05-18T00:00:00+00:00",
        }
        self.public_key_path.write_text(json.dumps(record), encoding="utf-8")

        with self.assertRaises(ValueError):
            load_public_key_record(self.public_key_path)

    def test_public_key_fingerprint_mismatch_is_rejected(self):
        generate_user_key_pair(
            "Alice Example",
            "alice@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )
        record = json.loads(self.public_key_path.read_text(encoding="utf-8"))
        record["key_fingerprint"] = "WRONG"
        self.public_key_path.write_text(json.dumps(record), encoding="utf-8")

        with self.assertRaises(ValueError):
            load_public_key_record(self.public_key_path)


if __name__ == "__main__":
    unittest.main()
