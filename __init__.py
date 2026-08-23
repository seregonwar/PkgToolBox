# Questo file rende la directory un package Python
from .GUI.main_window import MainWindow
from .GUI.utils.style_manager import StyleManager
from .GUI.dialogs.settings_dialog import SettingsDialog

__all__ = ['MainWindow', 'StyleManager', 'SettingsDialog'] 
