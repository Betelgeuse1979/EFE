import subprocess
import sys
import unittest


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


if __name__ == "__main__":
    unittest.main()
