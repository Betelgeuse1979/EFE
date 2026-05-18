import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from app.audit.audit_log import list_audit_log, log_action
from app.contacts.contacts_db import add_contact, get_contact_by_email, verify_contact_key


class ContactsAndAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "efe.db"
        self.contact = {
            "display_name": "Bob Example",
            "email": "bob@example.com",
            "public_key": "fake-public-key",
            "key_fingerprint": "ABCD:1234",
            "generated_by_app": "efe",
            "app_version": "0.1.0",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_contact_import_and_verification_status(self):
        add_contact(self.contact, verified=False, db_path=self.db_path)
        saved = get_contact_by_email("bob@example.com", db_path=self.db_path)

        self.assertIsNotNone(saved)
        self.assertEqual(saved["verified"], 0)

        self.assertTrue(verify_contact_key("bob@example.com", db_path=self.db_path))
        verified = get_contact_by_email("bob@example.com", db_path=self.db_path)
        self.assertEqual(verified["verified"], 1)

    def test_audit_logging(self):
        log_action(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action_type="encrypt",
            filename="document.pdf",
            recipient_email="bob@example.com",
            key_fingerprint="ABCD:1234",
            success=True,
            db_path=self.db_path,
        )

        rows = list_audit_log(db_path=self.db_path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["action_type"], "encrypt")
        self.assertEqual(rows[0]["success"], 1)


if __name__ == "__main__":
    unittest.main()
