import importlib.util
import unittest


@unittest.skipIf(importlib.util.find_spec("PySide6") is None, "PySide6 is not installed")
class GuiImportTests(unittest.TestCase):
    def test_gui_modules_import(self):
        import app.gui.app
        import app.gui.main_window
        import app.gui.theme

        self.assertTrue(callable(app.gui.app.main))
        self.assertTrue(hasattr(app.gui.main_window, "MainWindow"))
        self.assertTrue(callable(app.gui.theme.apply_theme))
        self.assertIsInstance(app.gui.theme.windows_prefers_dark_mode(), bool)


if __name__ == "__main__":
    unittest.main()
