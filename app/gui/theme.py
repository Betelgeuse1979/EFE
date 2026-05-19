import sys
if sys.platform == "win32":
    import winreg

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication


def windows_prefers_dark_mode() -> bool:
    """Best-effort Windows app theme detection. Defaults to light if unavailable."""
    if sys.platform != "win32":
        return False
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return int(value) == 0
    except Exception:
        return False


def apply_theme(app: QApplication) -> str:
    """Apply a simple light or dark theme and return the theme name."""
    if windows_prefers_dark_mode():
        _apply_dark_palette(app)
        app.setStyleSheet(_dark_stylesheet())
        return "dark"
    _apply_light_palette(app)
    app.setStyleSheet(_light_stylesheet())
    return "light"


def _apply_light_palette(app: QApplication) -> None:
    app.setPalette(app.style().standardPalette())


def _apply_dark_palette(app: QApplication) -> None:
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#111827"))
    palette.setColor(QPalette.WindowText, QColor("#f9fafb"))
    palette.setColor(QPalette.Base, QColor("#0b1220"))
    palette.setColor(QPalette.AlternateBase, QColor("#162033"))
    palette.setColor(QPalette.ToolTipBase, QColor("#f9fafb"))
    palette.setColor(QPalette.ToolTipText, QColor("#111827"))
    palette.setColor(QPalette.Text, QColor("#f9fafb"))
    palette.setColor(QPalette.Button, QColor("#1f2937"))
    palette.setColor(QPalette.ButtonText, QColor("#f9fafb"))
    palette.setColor(QPalette.BrightText, QColor("#ffffff"))
    palette.setColor(QPalette.Highlight, QColor("#2563eb"))
    palette.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)


def _shared_stylesheet() -> str:
    return """
        QMainWindow { font-size: 13px; }
        QTabWidget::pane { border: 1px solid palette(mid); border-radius: 6px; }
        QTabBar::tab { padding: 9px 16px; margin-right: 2px; }
        QGroupBox#panel { border: 1px solid palette(mid); border-radius: 6px; margin-top: 12px; padding: 12px; }
        QGroupBox#panel::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; font-weight: 600; }
        QLabel#title { font-size: 22px; font-weight: 700; }
        QLabel#sectionTitle { font-size: 17px; font-weight: 700; }
        QLabel#subtitle { font-size: 14px; }
        QLabel#helper { color: palette(mid); }
        QLabel#pathLabel { font-family: Consolas, monospace; }
        QLabel#successText { color: #15803d; font-weight: 600; }
        QLabel#warningText { color: #b45309; font-weight: 600; }
        QPushButton { padding: 7px 12px; border-radius: 5px; }
        QPushButton#primaryButton { font-weight: 600; }
        QLineEdit, QComboBox { padding: 6px; border-radius: 5px; }
        QTableWidget { gridline-color: palette(mid); }
    """


def _light_stylesheet() -> str:
    return (
        _shared_stylesheet()
        + """
        QFrame#hero { background: #f3f7fb; border: 1px solid #d8e1ec; border-radius: 8px; }
        QPushButton#primaryButton { background: #1d4ed8; color: white; border: 1px solid #1d4ed8; }
        QPushButton { background: #f8fafc; border: 1px solid #cbd5e1; }
        QLineEdit, QComboBox { border: 1px solid #cbd5e1; background: white; }
    """
    )


def _dark_stylesheet() -> str:
    return (
        _shared_stylesheet()
        + """
        QFrame#hero { background: #162033; border: 1px solid #344155; border-radius: 8px; }
        QPushButton#primaryButton { background: #2563eb; color: white; border: 1px solid #2563eb; }
        QPushButton { background: #1f2937; border: 1px solid #4b5563; color: #f9fafb; }
        QLineEdit, QComboBox { border: 1px solid #4b5563; background: #0b1220; color: #f9fafb; }
    """
    )
