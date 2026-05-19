import subprocess
import unittest
from pathlib import Path


class PackagingPrototypeTests(unittest.TestCase):
    def test_packaging_files_exist(self):
        self.assertTrue(Path("requirements-dev.txt").exists())
        self.assertTrue(Path("packaging/build_windows_gui.ps1").exists())
        self.assertTrue(Path("packaging/efe_gui_launcher.py").exists())
        self.assertTrue(Path("packaging/README.md").exists())

    def test_packaging_docs_describe_gui_only_prototype(self):
        text = Path("packaging/README.md").read_text(encoding="utf-8")

        self.assertIn("GUI only", text)
        self.assertIn("not an installer", text)
        self.assertIn("%LOCALAPPDATA%\\EFE\\", text)
        self.assertIn("not been independently audited", text)

    def test_build_script_uses_pyinstaller_onedir(self):
        text = Path("packaging/build_windows_gui.ps1").read_text(encoding="utf-8")

        self.assertIn("-m PyInstaller", text)
        self.assertIn("--onedir", text)
        self.assertIn("--name EFE", text)
        self.assertIn("unittest discover -s tests", text)

    def test_generated_packaging_artifacts_are_not_tracked(self):
        result = subprocess.run(
            ["git", "ls-files", "build", "dist", "*.spec"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
