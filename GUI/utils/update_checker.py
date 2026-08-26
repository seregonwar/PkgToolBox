import json
import os
import platform
import re
import subprocess
import sys

from PySide6.QtCore import QObject, QUrl, Signal
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest


def pick_asset_for_current_platform(assets):
    """Choose the release asset that best matches the running OS/arch.

    Returns the asset dict (with 'name' and 'browser_download_url'), or None
    when no asset matches this platform.
    """
    if not assets:
        return None

    system = platform.system().lower()
    machine = platform.machine().lower()

    def has(name, *needles):
        lower = name.lower()
        return all(n.lower() in lower for n in needles)

    if system == "windows":
        # Inno Setup one-click installer first.
        for a in assets:
            if a.get("name", "").endswith("Setup.exe"):
                return a
        for a in assets:
            if a.get("name", "").lower().endswith(".exe"):
                return a
    elif system == "darwin":
        # Apple Silicon vs Intel — prefer a matching build when present.
        arm = machine in ("arm64", "aarch64")
        for a in assets:
            name = a.get("name", "")
            if not name.lower().endswith(".dmg"):
                continue
            if arm and has(name, "arm"):
                return a
            if not arm and (has(name, "x64", "intel") or not has(name, "arm")):
                return a
        for a in assets:
            if a.get("name", "").lower().endswith(".dmg"):
                return a
        for a in assets:
            if a.get("name", "").lower().endswith(".zip"):
                return a
    else:
        # Linux: AppImage is the self-contained install path, tarball fallback.
        for a in assets:
            if a.get("name", "").endswith(".AppImage"):
                return a
        for a in assets:
            if a.get("name", "").endswith(".tar.gz"):
                return a

    return None


def launch_downloaded_asset(path):
    """Open/run a downloaded installer with the platform's default handler.

    Windows runs the Inno Setup .exe, macOS mounts/opens the .dmg, and Linux
    makes the AppImage executable before opening it.
    """
    path = os.path.abspath(path)
    if sys.platform == "win32":
        os.startfile(path)  # noqa: S606 - intentional installer launch
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        if path.endswith(".AppImage"):
            os.chmod(path, 0o755)
        subprocess.Popen(["xdg-open", path])


class UpdateChecker(QObject):
    """Asynchronous GitHub release check + installer download.

    Uses QNetworkAccessManager (non-blocking, no extra thread) instead of a
    QThread + requests, so closing the app never hits
    'QThread: Destroyed while thread is still running'.
    """

    update_available = Signal(str, str, object)  # version, download_url, assets
    error_occurred = Signal(str)
    download_progress = Signal(int, int)  # bytes received, total bytes
    download_finished = Signal(str)       # local file path

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
        self._download_reply = None
        self._download_file = None
        self._download_path = None

    def start(self):
        """Kick off the (non-blocking) update check."""
        if self._reply is not None:
            return
        request = QNetworkRequest(QUrl(self.GITHUB_API_URL))
        for name, value in self.REQUEST_HEADERS.items():
            request.setRawHeader(name, value)
        self._reply = self._manager.get(request)

    def download_asset(self, url, destination):
        """Download an asset to `destination` (streamed to disk)."""
        if self._download_reply is not None:
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(destination)), exist_ok=True)
        except OSError as e:
            self.error_occurred.emit(str(e))
            return

        self._download_path = os.path.abspath(destination)
        self._download_file = open(self._download_path, "wb")
        request = QNetworkRequest(QUrl(url))
        for name, value in self.REQUEST_HEADERS.items():
            request.setRawHeader(name, value)
        self._download_reply = self._manager.get(request)
        self._download_reply.readyRead.connect(self._on_download_ready_read)
        self._download_reply.downloadProgress.connect(self._on_download_progress)

    def _on_response(self, reply: QNetworkReply):
        if reply is self._download_reply:
            self._on_download_finished(reply)
            return
        self._on_check_finished(reply)

    def _on_check_finished(self, reply: QNetworkReply):
        try:
            if reply.error() != QNetworkReply.NetworkError.NoError:
                self.error_occurred.emit(str(reply.errorString()))
                return

            data = bytes(reply.readAll())
            release_info = json.loads(data.decode("utf-8"))
            tag = str(release_info.get("tag_name", "") or "")
            latest_version = self._normalize_version(tag)

            if not latest_version:
                self.error_occurred.emit("Invalid tag_name in release response")
                return

            if self._compare_versions(latest_version, self.CURRENT_VERSION) > 0:
                download_url = (
                    release_info.get("html_url")
                    or "https://github.com/seregonwar/PkgToolBox/releases"
                )
                assets = release_info.get("assets") or []
                self.update_available.emit(latest_version, download_url, assets)
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            reply.deleteLater()
            self._reply = None

    def _on_download_ready_read(self):
        if self._download_file is None or self._download_reply is None:
            return
        self._download_file.write(bytes(self._download_reply.readAll()))

    def _on_download_progress(self, received, total):
        self.download_progress.emit(int(received), int(total))

    def _on_download_finished(self, reply: QNetworkReply):
        try:
            # Flush any remaining bytes before checking the outcome.
            if self._download_file is not None:
                self._download_file.write(bytes(reply.readAll()))

            if reply.error() != QNetworkReply.NetworkError.NoError:
                self.error_occurred.emit(str(reply.errorString()))
                return

            self.download_finished.emit(self._download_path)
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            if self._download_file is not None:
                try:
                    self._download_file.close()
                except Exception:
                    pass
                self._download_file = None
            reply.deleteLater()
            self._download_reply = None
            self._download_path = None

    def _normalize_version(self, tag: str) -> str:
        """Normalize a Git tag (e.g. 'v1.4.3' or '1.4.3-beta') to '1.4.3'."""
        tag = tag.strip()
        if tag.lower().startswith("v"):
            tag = tag[1:]
        m = re.match(r"(\d+(?:\.\d+){0,3})", tag)
        return m.group(1) if m else ""

    def _compare_versions(self, version1, version2):
        """Compare version strings like '1.4.3'. Returns 1, 0, -1."""
        def parts(v):
            return [int(p) for p in v.split(".") if p.isdigit() or p.isnumeric()]

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
