import requests
import json
import os
import re
from PyQt5.QtWidgets import QMessageBox, QCheckBox
from PyQt5.QtCore import QThread, pyqtSignal
import webbrowser

class UpdateChecker(QThread):
    update_available = pyqtSignal(str, str)  # version, download_url
    error_occurred = pyqtSignal(str)

    CURRENT_VERSION = "1.4.03"  # Versione corrente
    GITHUB_API_URL = "https://api.github.com/repos/seregonwar/PkgToolBox/releases/latest"
    REQUEST_HEADERS = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "PkgToolBox/" + CURRENT_VERSION,
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent

    def run(self):
        """Check for updates in background"""
        try:
            response = requests.get(self.GITHUB_API_URL, headers=self.REQUEST_HEADERS, timeout=10)
            response.raise_for_status()

            release_info = response.json()
            tag = str(release_info.get('tag_name', '') or '')
            latest_version = self._normalize_version(tag)

            if not latest_version:
                raise ValueError("Invalid tag_name in release response")

            if self._compare_versions(latest_version, self.CURRENT_VERSION) > 0:
                download_url = release_info.get('html_url') or "https://github.com/seregonwar/PkgToolBox/releases"
                self.update_available.emit(latest_version, download_url)
        except Exception as e:
            self.error_occurred.emit(str(e))

    def _normalize_version(self, tag: str) -> str:
        """Normalize a Git tag (e.g. 'v1.4.3' or '1.4.3-beta') to numeric '1.4.3'."""
        tag = tag.strip()
        if tag.lower().startswith('v'):
            tag = tag[1:]
        # Keep only digits and dots at the start: 1.2.3 from 1.2.3-beta
        m = re.match(r"(\d+(?:\.\d+){0,3})", tag)
        return m.group(1) if m else ""

    def _compare_versions(self, version1, version2):
        """Compare version strings like '1.4.3'. Returns 1, 0, -1."""
        def parts(v):
            return [int(p) for p in v.split('.') if p.isdigit() or p.isnumeric()]

        v1_parts = parts(version1)
        v2_parts = parts(version2)

        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts += [0] * (max_len - len(v1_parts))
        v2_parts += [0] * (max_len - len(v2_parts))

        for a, b in zip(v1_parts, v2_parts):
            if a > b:
                return 1
            if a < b:
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

        # 'Don't show again' checkbox
        dont_show_cb = QCheckBox("Don't show this again")
        self.setCheckBox(dont_show_cb)

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