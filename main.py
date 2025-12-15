#!/usr/bin/env python3
"""
Email Security Analyzer
Edge Solutions LLC (edgesolutions.tech)

API-based email security monitoring combining:
- Abnormal Security
- Microsoft Graph API (O365)
- Claude AI Analysis (via edgesol-apim)

Author: Glenn Bezanson (glenn.bezanson@edge-solutions.com)
"""

import sys
import os
import logging
from pathlib import Path

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QFont, QFontDatabase

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_fonts():
    """Load Brandon font family"""
    fonts_dir = Path(__file__).parent / "resources" / "fonts"

    if fonts_dir.exists():
        for font_file in fonts_dir.glob("*.woff2"):
            QFontDatabase.addApplicationFont(str(font_file))
        for font_file in fonts_dir.glob("*.ttf"):
            QFontDatabase.addApplicationFont(str(font_file))
        for font_file in fonts_dir.glob("*.otf"):
            QFontDatabase.addApplicationFont(str(font_file))


def check_config():
    """Check if configuration is valid"""
    from core.config import ConfigManager
    config = ConfigManager()

    errors = config.validate()
    if errors:
        error_list = "\n".join([f"- {k}: {v}" for k, v in errors.items()])
        return False, f"Configuration errors:\n{error_list}\n\nPlease edit config.json"

    return True, ""


def main():
    """Application entry point"""
    # High DPI support
    if hasattr(Qt.ApplicationAttribute, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    if hasattr(Qt.ApplicationAttribute, 'AA_UseHighDpiPixmaps'):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("Email Security Analyzer")
    app.setOrganizationName("Edge Solutions")
    app.setOrganizationDomain("edgesolutions.tech")

    # Load fonts
    load_fonts()

    # Set default font
    font = QFont("Brandon", 12)
    if "Brandon" not in QFontDatabase.families():
        font = QFont("Segoe UI", 12)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    app.setFont(font)

    # Set app icon
    icon_path = Path(__file__).parent / "resources" / "icon.ico"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    # Check configuration
    config_valid, config_error = check_config()
    if not config_valid:
        logger.warning(config_error)
        # Show warning but continue - user can configure in settings
        QMessageBox.warning(
            None,
            "Configuration Warning",
            config_error + "\n\nThe application will start but some features may not work."
        )

    # Create and show main window
    from ui.main_window import MainWindow
    window = MainWindow()
    window.show()

    # Run event loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
