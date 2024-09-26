import logging
import sys
import os
import ctypes
import argparse
from package import Package
from gui import start_gui
import io
from contextlib import redirect_stdout
from file_operations import extract_file, inject_file, modify_file_header
import json
from Utilities import Logger, SettingsManager, Helper
from Utilities.PS4PKGToolHelper import MessageBoxHelper

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def ensure_settings_file_exists():
    if not os.path.exists(Helper.ps4pkg_tool_temp_directory):
        os.makedirs(Helper.ps4pkg_tool_temp_directory)
        Logger.log_information("Creating PS4PKGToolTemp directory...")
    
    if not os.path.exists(SettingFilePath) or os.path.getsize(SettingFilePath) == 0:
        create_default_settings()

def create_default_settings():
    default_settings = {
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
    with open(SettingFilePath, 'w') as f:
        json.dump(default_settings, f, indent=4)
    Logger.log_information("Default settings created.")

def load_settings(file_path):
    with open(file_path, 'r') as f:
        settings = json.load(f)
    app_settings = SettingsManager.load_settings(file_path)
    Logger.log_information("Settings loaded.")
    return app_settings

def choose_startup_form():
    if not app_settings.show_directory_settings_at_startup:
        startup_form = Main()
    else:
        startup_form = PKGDirectorySettings()
    startup_form.show()

class Main:
    def __init__(self):
        pass

    def show(self):
        Logger.log_information("Main form is shown.")

class PKGDirectorySettings:
    def __init__(self):
        pass

    def show(self):
        Logger.log_information("PKG Directory Settings form is shown.")

def run_command(cmd, pkg, file, out, update_info_callback):
    logging.debug(f"run_command called with cmd={cmd}, pkg={pkg}, file={file}, out={out}")
    if not cmd or not pkg:
        raise ValueError("The 'Command' and 'PKG' fields are mandatory.")

    args = argparse.Namespace(cmd=cmd, pkg=pkg, file=file, out=out)

    if args.cmd == "extract" and not args.file:
        raise ValueError("--file is mandatory for the extract command")
    if (args.cmd == "extract" or args.cmd == "dump") and not args.out:
        raise ValueError("--out is mandatory for extract and dump commands")

    target = Package(args.pkg)

    try:
        if args.cmd == "info":
            # Capture the output of the info() function
            f = io.StringIO()
            with redirect_stdout(f):
                target.info()
            info_output = f.getvalue()
            
            if not info_output:
                raise ValueError("No information found in the PKG file.")
            
            # Convert the output to a dictionary
            info_dict = {}
            for line in info_output.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    info_dict[key.strip()] = value.strip()
            
            # Search for the image
            image_data = None
            image_files = ['icon0.png', 'pic0.png', 'pic1.png']
            for img_file in image_files:
                try:
                    with io.BytesIO() as temp_buffer:
                        target.extract(img_file, temp_buffer)
                        image_data = temp_buffer.getvalue()
                    break
                except ValueError:
                    continue
            
            if image_data:
                info_dict['icon0'] = image_data
            
            update_info_callback(info_dict)
            Logger.log_information(f"Executed command: {cmd} on PKG: {pkg}, File: {file}, Output: {out}")
            return info_output  # Return the output
        elif args.cmd == "extract":
            file_info = target.get_file_info(args.file)
            extract_file(args.pkg, file_info, args.out, update_info_callback)
            Logger.log_information(f"Executed command: {cmd} on PKG: {pkg}, File: {file}, Output: {out}")
            return f"File extracted: {args.file}"
        elif args.cmd == "inject":
            file_info = target.get_file_info(args.file)
            injected_size = inject_file(args.pkg, file_info, args.out)
            Logger.log_information(f"Executed command: {cmd} on PKG: {pkg}, File: {file}, Input: {out}")
            return f"Injected {injected_size} bytes"
        elif args.cmd == "modify":
            modified_size = modify_file_header(args.pkg, int(args.file, 16), args.out.encode())
            Logger.log_information(f"Executed command: {cmd} on PKG: {pkg}, Offset: {file}, New Data: {out}")
            return f"Modified {modified_size} bytes"
        elif args.cmd == "dump":
            target.dump(args.out)
            Logger.log_information(f"Executed command: {cmd} on PKG: {pkg}, Output: {out}")
            return "Dump completed successfully"
    except FileExistsError as e:
        Logger.log_warning(f"File already exists during execution of command: {cmd} - {e}")
        raise
    except ValueError as e:
        Logger.log_error(f"Value error during execution of command: {cmd} - {e}")
        raise
    except Exception as e:
        Logger.log_error(f"Generic error during execution of command: {cmd} - {e}")
        raise

    return None  # Handle unforeseen cases

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

if __name__ == "__main__":
    run_as_admin()
    
    PS4PKGToolTempDirectory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PS4PKGToolTemp")
    SettingFilePath = os.path.join(PS4PKGToolTempDirectory, "Settings.conf")

    ensure_settings_file_exists()
    app_settings = load_settings(SettingFilePath)
    choose_startup_form()
    start_gui(run_command)
