import os
import json
from datetime import datetime
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import QByteArray, Qt

class Helper:
    first_launch = True
    finalize_pkg_process = True
    ps4pkg_tool_temp_directory = "path/to/temp/directory"  
    orbis_pub_cmd = os.path.join(ps4pkg_tool_temp_directory, "orbis-pub-cmd.exe")
    ps5_bc_json_file = os.path.join(ps4pkg_tool_temp_directory, "ps5bc.json")
    ps4pkg_tool_log_file = os.path.join(ps4pkg_tool_temp_directory, "PS4PKGToolLog.txt")

    @staticmethod
    def round_bytes(num):
        if num < 1024:
            return f"{num} bytes"
        elif num < 1048576:
            return f"{round(num / 1024, 2)} KB"
        elif num < 1073741824:
            return f"{round(num / 1048576, 2)} MB"
        elif num < 1099511627776:
            return f"{round(num / 1073741824, 2)} GB"
        else:
            return f"{round(num / 1099511627776, 2)} TB"

    @staticmethod
    def extract_resources():
        pass

    @classmethod
    def get_backport_info_file(cls):
        return os.path.join(cls.ps4pkg_tool_temp_directory, "backport.json")

class Backport:
    backport_info_file = None
    pkg_file_list = []

    @staticmethod
    def check_pkg_backported(pkg_file):
        if Backport.backport_info_file is None:
            Backport.backport_info_file = Helper.get_backport_info_file()
        with open(Backport.backport_info_file, 'r') as f:
            Backport.pkg_file_list = json.load(f)
        matching_file = next((file for file in Backport.pkg_file_list if file["FilePath"].lower() == pkg_file.lower()), None)
        return matching_file["Backported"] if matching_file else None

    @staticmethod
    def save_data(data_grid_view):
        updated_pkg_file_list = []
        for row in data_grid_view:
            file_path = os.path.join(row[12], row[0])
            backported = "No" if row[13] == "No" else row[13]
            updated_pkg_file_list.append({"FilePath": file_path, "Backported": backported})
        with open(Backport.backport_info_file, 'w') as f:
            json.dump(updated_pkg_file_list, f, indent=4)

class Bitmap:
    pic0 = None
    pic1 = None
    fail_extract_image_list = ""

    @staticmethod
    def bytes_to_bitmap(img_bytes):
        pixmap = QPixmap()
        pixmap.loadFromData(QByteArray(img_bytes))
        return pixmap

    @staticmethod
    def resize_image(image, width, height):
        return image.scaled(width, height, aspectRatioMode=Qt.KeepAspectRatio, transformMode=Qt.SmoothTransformation)

class Trophy:
    trophy = None
    id_entry_list = []
    name_entry_list = []
    image_to_extract_list = []
    trophy_filename_to_extract_list = []
    trophy_temp_folder = os.path.join(Helper.ps4pkg_tool_temp_directory, "TrophyFile")
    out_path = ""

    @staticmethod
    def resize_image(image, width, height):
        return image.scaled(width, height, aspectRatioMode=Qt.KeepAspectRatio, transformMode=Qt.SmoothTransformation)