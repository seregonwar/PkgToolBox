import sys
import os
import logging
import json

# Aggiungi la directory root al path di Python
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import dei moduli
from GUI.main_window import MainWindow
from GUI.utils.avatar_fetcher import AvatarFetcher
from Utilities import Logger
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def check_settings_file_presence():
    """Check and create necessary directories and settings file"""
    temp_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PS4PKGToolTemp")
    if not os.path.exists(temp_directory):
        os.makedirs(temp_directory)
        Logger.log_information("Creating PS4PKGToolTemp directory...")
    
    settings_file_path = os.path.join(temp_directory, "settings.json")
    if not os.path.exists(settings_file_path) or os.path.getsize(settings_file_path) == 0:
        create_default_settings(settings_file_path)
    
    return temp_directory, settings_file_path

def create_default_settings(settings_file_path):
    """Create default settings file"""
    default_settings = {
        "theme": "Light",
        "night_mode": False,
        "font": "Arial",
        "font_size": 12,
        "bg_color": "#ffffff",
        "text_color": "#000000",
        "accent_color": "#3498db",
        "auto_expand": True,
        "show_hidden": False,
        "confirm_exit": True,
        "output_path": "",
        "temp_path": "",
        "pkg_directories": [],
        "scan_recursive": False,
        "play_bgm": False,
        "show_directory_settings_at_startup": True,
        "auto_sort_row": False,
        "local_server_ip": "",
        "ps4_ip": "",
        "nodejs_installed": False,
        "http_server_installed": False,
        "official_update_download_directory": "",
        "pkg_color_label": False,
        "game_pkg_forecolor": 0xDDDDDD,
        "patch_pkg_forecolor": 0xDDDDDD,
        "addon_pkg_forecolor": 0xDDDDDD,
        "app_pkg_forecolor": 0xDDDDDD,
        "game_pkg_backcolor": 0x333333,
        "patch_pkg_backcolor": 0x333333,
        "addon_pkg_backcolor": 0x333333,
        "app_pkg_backcolor": 0x333333,
        "rename_custom_format": "",
        "ps5bc_json_download_date": "",
        "psvr_neo_ps5bc_check": False,
        "pkg_titleId_column": True,
        "pkg_contentId_column": True,
        "pkg_region_column": True,
        "pkg_minimum_firmware_column": True,
        "pkg_version_column": True,
        "pkg_type_column": True,
        "pkg_category_column": True,
        "pkg_size_column": True,
        "pkg_location_column": True,
        "pkg_backport_column": True
    }
    
    with open(settings_file_path, 'w') as f:
        json.dump(default_settings, f, indent=4)
    Logger.log_information("Default settings created.")

def main():
    """Main application entry point"""
    # Initialize application
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Setup directories and settings
    temp_directory, settings_file_path = check_settings_file_presence()
    
    # The persisted theme is applied by MainWindow at startup (StyleManager).
    
    # App icon: the toolbox icon bundled with the app (never the avatar;
    # the avatar is used only in the Settings About page and the installer).
    toolbox = AvatarFetcher.bundled_icon_path()
    if os.path.exists(toolbox):
        app.setWindowIcon(QIcon(toolbox))
        window.setWindowIcon(QIcon(toolbox))

    # Start application
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
