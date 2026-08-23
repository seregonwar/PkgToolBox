import json
import os
import re
import webbrowser

from PySide6.QtCore import QObject, QUrl, Signal
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest
from PySide6.QtWidgets import QCheckBox, QMessageBox


class UpdateChecker(QObject):
    """Asynchronous GitHub release check.

    Uses QNetworkAccessManager (non-blocking, no extra thread) instead of a
    QThread + requests, so closing the app never hits
    'QThread: Destroyed while thread is still running'.
    """
    update_available = Signal(str, str)  # version, download_url
    error_occurred = Signal(str)

    CURRENT_VERSION = "1.5.0"  # Versione corrente
    GITHUB_API_URL = "https://api.github.com/repos/seregonwar/PkgToolBox/releases/latest"
    REQUEST_HEADERS = {
        b"Accept": b"application/vnd.github+json",
        b"User-Agent": ("PkgToolBox/" + CURRENT_VERSION).encode(),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._manager = QNetworkAccessManager(self)
        self._manager.finished.connect(self._on_response)
        self._reply = None

    def start(self):
        """Kick off the (non-blocking) update check."""
        if self._reply is not None:
            return
        request = QNetworkRequest(QUrl(self.GITHUB_API_URL))
        for name, value in self.REQUEST_HEADERS.items():
            request.setRawHeader(name, value)
        self._reply = self._manager.get(request)

    def _on_response(self, reply: QNetworkReply):
        try:
            if reply.error() != QNetworkReply.NetworkError.NoError:
                self.error_occurred.emit(str(reply.errorString()))
                return

            data = bytes(reply.readAll())
            release_info = json.loads(data.decode("utf-8"))
            tag = str(release_info.get('tag_name', '') or '')
            latest_version = self._normalize_version(tag)

            if not latest_version:
                self.error_occurred.emit("Invalid tag_name in release response")
                return

            if self._compare_versions(latest_version, self.CURRENT_VERSION) > 0:
                download_url = release_info.get('html_url') or "https://github.com/seregonwar/PkgToolBox/releases"
                self.update_available.emit(latest_version, download_url)
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            reply.deleteLater()
            self._reply = None

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
