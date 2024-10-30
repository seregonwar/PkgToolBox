import requests
import json
import os
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtCore import QThread, pyqtSignal
import webbrowser

class UpdateChecker(QThread):
    update_available = pyqtSignal(str, str)  # version, download_url
    error_occurred = pyqtSignal(str)

    CURRENT_VERSION = "1.5.3"  # Versione corrente
    GITHUB_API_URL = "https://api.github.com/repos/seregonwar/PkgToolBox/releases/latest"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent

    def run(self):
        """Check for updates in background"""
        try:
            response = requests.get(self.GITHUB_API_URL)
            response.raise_for_status()
            
            release_info = response.json()
            latest_version = release_info['tag_name'].replace('v', '')
            
            if self._compare_versions(latest_version, self.CURRENT_VERSION) > 0:
                download_url = release_info['html_url']
                self.update_available.emit(latest_version, download_url)
        except Exception as e:
            self.error_occurred.emit(str(e))

    def _compare_versions(self, version1, version2):
        """Compare version strings"""
        v1_parts = [int(x) for x in version1.split('.')]
        v2_parts = [int(x) for x in version2.split('.')]
        
        for i in range(max(len(v1_parts), len(v2_parts))):
            v1 = v1_parts[i] if i < len(v1_parts) else 0
            v2 = v2_parts[i] if i < len(v2_parts) else 0
            if v1 > v2:
                return 1
            elif v1 < v2:
                return -1
        return 0

class UpdateDialog(QMessageBox):
    def __init__(self, version, download_url, parent=None):
        super().__init__(parent)
        self.download_url = download_url
        
        self.setWindowTitle("Update Available")
        self.setText(f"A new version ({version}) is available!")
        self.setInformativeText("Would you like to download it now?")
        self.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        self.setDefaultButton(QMessageBox.Yes)
        
        # Aggiungi pulsante per "Non mostrare più"
        self.setCheckBox(QMessageBox.StandardButton.Yes)
        self.checkBox().setText("Don't show this again")
        
        self.buttonClicked.connect(self.handle_click)

    def handle_click(self, button):
        if button == self.button(QMessageBox.Yes):
            webbrowser.open(self.download_url)
            
        # Salva la preferenza se selezionata
        if self.checkBox().isChecked():
            self.save_preference()

    def save_preference(self):
        """Save user preference to not show update dialog"""
        config_dir = os.path.join(os.path.expanduser("~"), ".pkgtoolbox")
        config_file = os.path.join(config_dir, "update_preferences.json")
        
        os.makedirs(config_dir, exist_ok=True)
        
        with open(config_file, 'w') as f:
            json.dump({"skip_updates": True}, f) 