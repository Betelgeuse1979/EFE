import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from app.exceptions import OutputExistsError
from app.services.key_service import build_public_key_qr_payload, export_public_key_qr, initialize_user_key


@unittest.skipIf(importlib.util.find_spec("qrcode") is None, "qrcode is not installed")
class PublicKeyQrExportTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.private_key_path = self.root / "private.pem"
        self.public_key_path = self.root / "public.json"
        self.qr_path = self.root / "public-key.png"
        self.passphrase = b"qr test passphrase"
        self.record = initialize_user_key(
            "Alice Example",
            "alice@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_qr_export_creates_png_file_and_returns_details(self):
        result = export_public_key_qr(self.qr_path, public_key_record_path=self.public_key_path)

        self.assertEqual(result["output_path"], str(self.qr_path))
        self.assertEqual(result["key_fingerprint"], self.record["key_fingerprint"])
        self.assertTrue(self.qr_path.exists())
        self.assertEqual(self.qr_path.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")

    def test_qr_export_does_not_overwrite_existing_file(self):
        self.qr_path.write_bytes(b"existing")

        with self.assertRaises(OutputExistsError):
            export_public_key_qr(self.qr_path, public_key_record_path=self.public_key_path)

        self.assertEqual(self.qr_path.read_bytes(), b"existing")

    def test_qr_payload_contains_only_public_key_record(self):
        payload, record = build_public_key_qr_payload(self.public_key_path)
        payload_data = json.loads(payload)

        self.assertEqual(payload_data, record)
        self.assertIn("public_key", payload_data)
        self.assertIn("key_fingerprint", payload_data)
        self.assertNotIn("private_key", payload)
        self.assertNotIn("PRIVATE KEY", payload)
        self.assertNotIn(self.passphrase.decode("utf-8"), payload)


if __name__ == "__main__":
    unittest.main()
