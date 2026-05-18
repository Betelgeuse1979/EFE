import json
import tempfile
import unittest
from pathlib import Path

from app.services.audit_service import get_audit_entries
from app.services.contact_service import get_contact, import_contact_key, is_contact_verified, mark_contact_verified
from app.services.file_crypto_service import decrypt_received_file, encrypt_file_for_recipient
from app.services.key_service import initialize_user_key


class ServiceLayerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.db_path = self.root / "efe.db"
        self.private_key_path = self.root / "private.pem"
        self.public_key_path = self.root / "public.json"
        self.passphrase = b"service layer passphrase"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_public_key_record(self):
        return initialize_user_key(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )

    def test_contact_service_imports_and_verifies_contact(self):
        self._create_public_key_record()

        record = import_contact_key(self.public_key_path, verified=False, db_path=self.db_path)
        saved = get_contact("bob@example.com", db_path=self.db_path)

        self.assertEqual(record["email"], "bob@example.com")
        self.assertIsNotNone(saved)
        self.assertFalse(is_contact_verified("bob@example.com", db_path=self.db_path))

        self.assertTrue(mark_contact_verified("bob@example.com", db_path=self.db_path))
        self.assertTrue(is_contact_verified("bob@example.com", db_path=self.db_path))

    def test_contact_service_rejects_invalid_public_key_before_insert(self):
        bad_key_path = self.root / "bad-public.json"
        bad_key_path.write_text(
            json.dumps(
                {
                    "display_name": "Bad Key",
                    "email": "bad@example.com",
                    "public_key": "not valid base64!!!!",
                    "key_fingerprint": "ABCD",
                    "created_at": "2026-05-18T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            import_contact_key(bad_key_path, db_path=self.db_path)
        self.assertIsNone(get_contact("bad@example.com", db_path=self.db_path))

    def test_file_crypto_service_encrypts_decrypts_and_writes_audit_entries(self):
        self._create_public_key_record()
        import_contact_key(self.public_key_path, verified=True, db_path=self.db_path)
        source = self.root / "message.txt"
        encrypted = self.root / "message.txt.efe"
        decrypted = self.root / "message-decrypted.txt"
        source.write_text("hello from services", encoding="utf-8")

        encrypted_path = encrypt_file_for_recipient(source, "bob@example.com", encrypted, db_path=self.db_path)
        decrypted_path = decrypt_received_file(
            encrypted_path,
            self.passphrase,
            decrypted,
            private_key_path=self.private_key_path,
            db_path=self.db_path,
        )

        self.assertEqual(decrypted_path.read_text(encoding="utf-8"), "hello from services")
        entries = get_audit_entries(self.db_path)
        self.assertEqual([entry["action_type"] for entry in entries], ["decrypt", "encrypt"])
        self.assertTrue(all(entry["success"] for entry in entries))

    def test_file_crypto_service_failed_decrypt_logs_failure_without_plaintext(self):
        self._create_public_key_record()
        import_contact_key(self.public_key_path, verified=True, db_path=self.db_path)
        source = self.root / "message.txt"
        encrypted = self.root / "message.txt.efe"
        decrypted = self.root / "message-decrypted.txt"
        source.write_text("hello from services", encoding="utf-8")
        encrypt_file_for_recipient(source, "bob@example.com", encrypted, db_path=self.db_path)

        with self.assertRaises(Exception):
            decrypt_received_file(
                encrypted,
                b"wrong passphrase",
                decrypted,
                private_key_path=self.private_key_path,
                db_path=self.db_path,
            )

        self.assertFalse(decrypted.exists())
        entries = get_audit_entries(self.db_path)
        self.assertEqual(entries[0]["action_type"], "decrypt")
        self.assertEqual(entries[0]["success"], 0)


if __name__ == "__main__":
    unittest.main()
