import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def test_version_command_outputs_app_and_crypto_versions(self):
        result = subprocess.run(
            [sys.executable, "-m", "app.main", "version"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("EFE", result.stdout)
        self.assertIn("Encrypted File Exchange", result.stdout)
        self.assertIn("App version:", result.stdout)
        self.assertIn("Crypto format version:", result.stdout)
        self.assertIn("efe-X25519-ChaCha20Poly1305-v1", result.stdout)

    def test_export_public_key_qr_help_is_available(self):
        result = subprocess.run(
            [sys.executable, "-m", "app.main", "export-public-key-qr", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("--output", result.stdout)
        self.assertIn("QR code PNG", result.stdout)

    def test_data_dir_command_outputs_configured_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env = {"EFE_DATA_DIR": temp_dir}
            result = subprocess.run(
                [sys.executable, "-m", "app.main", "data-dir"],
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, **env},
            )

        self.assertEqual(result.returncode, 0)
        self.assertIn(f"Data directory: {Path(temp_dir)}", result.stdout)
        self.assertIn("Keys directory:", result.stdout)
        self.assertIn("SQLite database:", result.stdout)


if __name__ == "__main__":
    unittest.main()
