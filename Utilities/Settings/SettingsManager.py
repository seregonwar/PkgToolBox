import os
import json
from PyQt5.QtWidgets import QMessageBox
from Utilities.PS4PKGToolHelper.Helper import Helper
from Utilities.PS4PKGToolHelper.MessageBoxHelper import MessageBoxHelper
from Utilities.Settings.AppSettings import AppSettings

class SettingsManager:
    app_settings = AppSettings()
    setting_file_path = os.path.join(Helper.ps4pkg_tool_temp_directory, "Settings.conf")

    @staticmethod
    def save_settings(settings, file_path):
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                json.dump(settings.__dict__, f, indent=4)
        except Exception as ex:
            MessageBoxHelper.show_error(f"Error in saving settings: {ex}", True)

    @staticmethod
    def load_settings(file_path):
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    settings = json.load(f)
                    SettingsManager.app_settings.__dict__.update(settings)
        except Exception as ex:
            MessageBoxHelper.show_error(f"Error in loading settings: {ex}", True)
        return SettingsManager.app_settings