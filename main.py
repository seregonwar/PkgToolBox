import struct
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
import ctypes
import argparse
from Utilities.Trophy import Archiver, TrophyFile, TRPCreator, TRPReader
from packages import PackagePS4, PackagePS5, PackagePS3  # Importa i nuovi moduli
from gui import start_gui
import io
from contextlib import redirect_stdout
from file_operations import extract_file, inject_file, modify_file_header
import json
from Utilities import (
    Logger, 
    SettingsManager, 
    Utils
)
from repack import Repack
from PS5_Game_Info import PS5GameInfo

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def check_settings_file_presence():
    temp_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PS4PKGToolTemp")
    if not os.path.exists(temp_directory):
        os.makedirs(temp_directory)
        Logger.log_information("Creating PS4PKGToolTemp directory...")
    
    if not os.path.exists(settings_file_path) or os.path.getsize(settings_file_path) == 0:
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
    with open(settings_file_path, 'w') as f:
        json.dump(default_settings, f, indent=4)
    Logger.log_information("Default settings created.")

def load_settings(file_path):
    with open(file_path, 'r') as f:
        settings = json.load(f)
    app_settings = SettingsManager.load_settings(file_path)
    logging.info("Settings loaded.")
    return app_settings

def choose_initial_form():
    if not app_settings.show_directory_settings_at_startup:
        initial_form = Main()
    else:
        initial_form = PKGDirectorySettings()
    initial_form.show()

class Main:
    def __init__(self):
        pass

    def show(self):
        logging.info("Main window displayed.")

class PKGDirectorySettings:
    def __init__(self):
        pass

    def show(self):
        logging.info("PKG Directory Settings window displayed.")

def extract_necessary_files(package, temp_dir):
    necessary_files = ['icon0.png', 'pic0.png', 'pic1.png']
    extracted_files = {}

    for file_name in necessary_files:
        try:
            file_path = os.path.join(temp_dir, file_name)
            with open(file_path, 'wb') as f:
                package.extract_file(file_name, f)
            extracted_files[file_name] = file_path
        except FileNotFoundError:
            logging.warning(f"File {file_name} not found in the package.")
        except Exception as e:
            logging.error(f"Error extracting {file_name}: {e}")
    
    return extracted_files

def execute_command(cmd, pkg, file, out, update_callback_info):
    logging.debug(f"execute_command called with cmd={cmd}, pkg={pkg}, file={file}, out={out}")
    if not cmd or not pkg:
        raise ValueError("The 'Command' and 'PKG' fields are required.")

    args = argparse.Namespace(cmd=cmd, pkg=pkg, file=file, out=out)

    if args.cmd == "extract" and not args.file:
        raise ValueError("--file is required for the extract command")
    if (args.cmd == "extract" or args.cmd == "dump") and not args.out:
        raise ValueError("--out is required for the extract and dump commands")

    try:
        # Determina il tipo di pacchetto e crea l'istanza appropriata
        with open(pkg, "rb") as fp:
            magic = struct.unpack(">I", fp.read(4))[0]
            if magic == PackagePS4.MAGIC_PS4:
                target = PackagePS4(pkg)
            elif magic == PackagePS5.MAGIC_PS5:
                target = PackagePS5(pkg)
            elif magic == PackagePS3.MAGIC_PS3:
                target = PackagePS3(pkg)
            else:
                raise ValueError(f"Formato PKG sconosciuto: {magic:08X}")

        temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PS4PKGToolTemp")
        extracted_files = extract_necessary_files(target, temp_dir)

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
            
            # Add extracted files to the info_dict
            for file_name, file_path in extracted_files.items():
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        info_dict[file_name] = f.read()
            
            # Extract country information
            country_info = target.extract_pkg_info().get("COUNTRY", "Unknown")
            info_dict['country'] = country_info
            
            update_callback_info(info_dict)
            logging.info(f"Executed command: {cmd} on PKG: {pkg}, File: {file}, Output: {out}")
            return info_output  # Return the output
        elif args.cmd == "extract":
            file_info = target.get_file_info(args.file)
            extract_file(args.pkg, file_info, args.out, update_callback_info)
            logging.info(f"Executed command: {cmd} on PKG: {pkg}, File: {file}, Output: {out}")
            return f"File extracted: {args.file}"
        elif args.cmd == "inject":
            file_info = target.get_file_info(args.file)
            injected_size = inject_file(args.pkg, file_info, args.out)
            logging.info(f"Executed command: {cmd} on PKG: {pkg}, File: {file}, Input: {out}")
            return f"Injected {injected_size} bytes"
        elif args.cmd == "modify":
            modified_size = modify_file_header(args.pkg, int(args.file, 16), args.out.encode())
            logging.info(f"Executed command: {cmd} on PKG: {pkg}, Offset: {file}, New Data: {out}")
            return f"Modified {modified_size} bytes"
        elif args.cmd == "dump":
            try:
                # Use a new function for safe dumping
                safe_dump(target, args.out, update_callback_info)
                logging.info(f"Executed command: {cmd} on PKG: {pkg}, Output: {out}")
                return "Dump completed successfully"
            except Exception as e:
                logging.error(f"Error during dump: {e}")
                raise ValueError(f"Error during dump: {e}")
        elif args.cmd == "trophy":
            trophy_file = TrophyFile(args.pkg)
            try:
                trophy_file.load(args.pkg)
                if not trophy_file._iserror:
                    logging.info("Trophy file loaded successfully.")
                    update_callback_info({
                        "Title": trophy_file.trphy.title,
                        "NPCommID": trophy_file.trphy.npcomm_id,
                        "Files": len(trophy_file.trophyItemList)
                    })
                    return "Trophy file loaded successfully"
                else:
                    logging.error("Error loading the Trophy file.", trophy_file._error)
                    raise ValueError("Error loading the Trophy file.")
            except Exception as e:
                logging.error(f"Error loading the Trophy file: {e}")
                raise ValueError(f"Error loading the Trophy file: {e}")
        elif args.cmd == "reverse_dump":
            try:
                result = target.reverse_dump(args.out, update_callback_info)
                logging.info(f"Executed command: {cmd} on PKG: {pkg}, Input Directory: {out}")
                return result
            except Exception as e:
                logging.error(f"Error during reverse dump: {e}")
                raise ValueError(f"Error during reverse dump: {e}")
        elif args.cmd == "repack":
            try:
                repacker = Repack(args.pkg, target.pkg_table_offset, target.pkg_entry_count, target.files)
                result = repacker.repack(args.file, args.out, "repack.log", update_callback_info)
                logging.info(f"Executed command: {cmd} on PKG: {pkg}, Input Directory: {file}, Output: {out}")
                return result
            except Exception as e:
                logging.error(f"Error during repack: {e}")
                raise ValueError(f"Error during repack: {e}")
        elif args.cmd == "ps5_game_info":
            ps5_game_info = PS5GameInfo()
            ps5_game_info.setupUi(None)  # Passa None come parametro poiché non abbiamo una finestra QMainWindow
            ps5_game_info.le_game_path.setText(args.pkg)
            ps5_game_info.main_procress()
            
            # Raccogli le informazioni dal QTreeWidget
            info_dict = {}
            root = ps5_game_info.tree.invisibleRootItem()
            child_count = root.childCount()
            for i in range(child_count):
                item = root.child(i)
                key = item.text(0)
                value = item.text(1)
                info_dict[key] = value
            
            update_callback_info(info_dict)
            return "PS5 Game Info extracted successfully"
    except FileExistsError as e:
        logging.warning(f"The file already exists during command execution: {cmd} - {e}")
        raise
    except ValueError as e:
        logging.error(f"Value error during command execution: {cmd} - {e}")
        raise
    except Exception as e:
        logging.error(f"Generic error during command execution: {cmd} - {e}")
        raise

    return None  # Handle unexpected cases

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    pass

if __name__ == "__main__":
    temp_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PS4PKGToolTemp")
    settings_file_path = os.path.join(temp_directory, "Settings.conf")

    check_settings_file_presence()
    app_settings = SettingsManager.load_settings(settings_file_path)
    start_gui(execute_command, temp_directory)

    # Add opening a terminal for debugging
    if os.name == 'nt':
        os.system('start cmd /K')  # Windows
    else:
        os.system('x-terminal-emulator -e bash')  # Linux

def safe_dump(package, output_dir, update_callback):
    """
    Perform a safe dump of the package, verifying the integrity of each file.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    for file_info in package.files():
        file_path = os.path.join(output_dir, file_info.name)
        
        # Extract the file
        with open(file_path, 'wb') as f:
            package.extract_file(file_info.name, f)
        
        # Verify the integrity of the extracted file
        if not verify_file_integrity(package, file_info, file_path):
            raise ValueError(f"Integrity error in file: {file_info.name}")
        
        update_callback({"status": f"Extracted: {file_info.name}"})
    
    logging.info("Dump completed successfully and integrity verified.")

def verify_file_integrity(package, file_info, extracted_path):
    """
    Verify the integrity of the extracted file by comparing it with the original in the package.
    """
    with open(extracted_path, 'rb') as f:
        extracted_data = f.read()
    
    original_data = package.read_file(file_info.name)
    
    if len(extracted_data) != len(original_data):
        logging.error(f"File size mismatch: {file_info.name}")
        return False
    
    if extracted_data != original_data:
        logging.error(f"File content mismatch: {file_info.name}")
        return False
    
    return True
