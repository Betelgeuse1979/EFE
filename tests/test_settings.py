import unittest
from pathlib import Path

from app.config.settings import build_data_paths, resolve_data_dir


class SettingsTests(unittest.TestCase):
    def test_windows_uses_localappdata_when_available(self):
        result = resolve_data_dir(
            environ={"LOCALAPPDATA": r"C:\Users\Alice\AppData\Local"},
            platform="win32",
            home=Path(r"C:\Users\Alice"),
        )

        self.assertEqual(result, Path(r"C:\Users\Alice\AppData\Local") / "EFE")

    def test_windows_falls_back_when_localappdata_is_missing(self):
        result = resolve_data_dir(
            environ={},
            platform="win32",
            home=Path(r"C:\Users\Alice"),
        )

        self.assertEqual(result, Path(r"C:\Users\Alice") / "AppData" / "Local" / "EFE")

    def test_non_windows_uses_local_share_path(self):
        result = resolve_data_dir(
            environ={},
            platform="linux",
            home=Path("/home/alice"),
        )

        self.assertEqual(result, Path("/home/alice") / ".local" / "share" / "efe")

    def test_efe_data_dir_override_wins(self):
        result = resolve_data_dir(
            environ={"EFE_DATA_DIR": "/tmp/efe-test-data", "LOCALAPPDATA": r"C:\Ignored"},
            platform="win32",
            home=Path(r"C:\Users\Alice"),
        )

        self.assertEqual(result, Path("/tmp/efe-test-data"))

    def test_derived_paths_are_under_resolved_data_dir(self):
        data_dir = Path("/tmp/efe-data")
        paths = build_data_paths(data_dir)

        self.assertEqual(paths["keys_dir"], data_dir / "keys")
        self.assertEqual(paths["encrypted_dir"], data_dir / "encrypted")
        self.assertEqual(paths["decrypted_dir"], data_dir / "decrypted")
        self.assertEqual(paths["db_path"], data_dir / "efe.db")
        self.assertEqual(paths["private_key_path"], data_dir / "keys" / "efe_private_key.pem")
        self.assertEqual(paths["public_key_record_path"], data_dir / "keys" / "efe_public_key.json")


if __name__ == "__main__":
    unittest.main()
