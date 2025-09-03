import struct
import sys
import os
import logging
import ctypes
import argparse
import io
import json
from contextlib import redirect_stdout

# Aggiungi la directory root al path di Python
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import dei moduli usando percorsi assoluti
from GraphicUserInterface.main_window import MainWindow
from packages import PackagePS4, PackagePS5, PackagePS3
from packages import (
    AES_ctx, AES_set_key, AES_encrypt, AES_KEY_LEN_128, AES_cbc_decrypt,
    PGD_HEADER, MAC_KEY, sceDrmBBMacInit, sceDrmBBMacUpdate, bbmac_getkey,
    kirk_init, decrypt_pgd
)
from Utilities.Trophy import Archiver, TrophyFile, TRPCreator, TRPReader
from file_operations import extract_file, inject_file, modify_file_header
from Utilities import Logger, SettingsManager, Utils
from tools.repack import Repack
from tools.PS5_Game_Info import PS5GameInfo
from PyQt5.QtWidgets import QApplication

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

def execute_command(cmd, pkg, file, out, update_callback_info):
    """Execute PKG related commands"""
    logging.debug(f"execute_command called with cmd={cmd}, pkg={pkg}, file={file}, out={out}")
    if not cmd or not pkg:
        raise ValueError("The 'Command' and 'PKG' fields are required.")

    try:
        # Determine package type and create appropriate instance
        with open(pkg, "rb") as fp:
            magic = struct.unpack(">I", fp.read(4))[0]
            if magic == PackagePS4.MAGIC_PS4:
                target = PackagePS4(pkg)
            elif magic == PackagePS5.MAGIC_PS5:
                target = PackagePS5(pkg)
            elif magic == PackagePS3.MAGIC_PS3:
                target = PackagePS3(pkg)
            else:
                raise ValueError(f"Unknown PKG format: {magic:08X}")

        # Execute requested command
        if cmd == "info":
            return get_pkg_info(target, update_callback_info)
        elif cmd == "extract":
            return extract_pkg_file(target, file, out, update_callback_info)
        elif cmd == "dump":
            return dump_pkg(target, out, update_callback_info)
        elif cmd == "inject":
            return inject_pkg_file(target, file, out)
        elif cmd == "modify":
            return modify_pkg_header(target, file, out)
        else:
            raise ValueError(f"Unknown command: {cmd}")

    except Exception as e:
        logging.error(f"Error executing command: {str(e)}")
        raise

def get_pkg_info(package, callback):
    """Get PKG information"""
    f = io.StringIO()
    with redirect_stdout(f):
        package.info()
    info_output = f.getvalue()
    
    if not info_output:
        raise ValueError("No information found in the PKG file.")
    
    info_dict = {}
    for line in info_output.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            info_dict[key.strip()] = value.strip()
    
    callback(info_dict)
    return info_output

def extract_pkg_file(package, file_path, output_path, callback):
    """Extract file from PKG"""
    file_info = package.get_file_info(file_path)
    extract_file(package.original_file, file_info, output_path, callback)
    return f"File extracted: {file_path}"

def dump_pkg(package, output_path, callback):
    """Dump PKG contents"""
    try:
        result = package.dump(output_path, callback)
        return result
    except Exception as e:
        raise ValueError(f"Error during dump: {str(e)}")

def inject_pkg_file(package, file_path, input_path):
    """Inject file into PKG"""
    file_info = package.get_file_info(file_path)
    injected_size = inject_file(package.original_file, file_info, input_path)
    return f"Injected {injected_size} bytes"

def modify_pkg_header(package, offset, new_data):
    """Modify PKG header"""
    modified_size = modify_file_header(package.original_file, int(offset, 16), new_data.encode())
    return f"Modified {modified_size} bytes"

def is_admin():
    """Check if running with admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    """Main application entry point"""
    # Initialize application
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Setup directories and settings
    temp_directory, settings_file_path = check_settings_file_presence()
    
    # Create and show main window
    window = MainWindow(temp_directory)
    window.show()
    
    # Start application
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()