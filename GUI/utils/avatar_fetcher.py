"""Async fetch of the maintainer's GitHub avatar (always the latest).

Mirrors the UpdateChecker pattern: QNetworkAccessManager (non-blocking, no
extra thread, no 'QThread destroyed' crashes on exit), caches the result in
~/.pkgtoolbox/avatar.png and emits avatar_ready with the local path.
"""
import os
import sys

from PySide6.QtCore import QObject, QUrl, Signal
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest


class AvatarFetcher(QObject):
    """Fetch https://avatars.githubusercontent.com/u/109359355 (the latest
    avatar of the maintainer) and cache it for reuse.

    The URL always serves the current avatar, so each launch refreshes the
    app icon without any manual update.
    """
    avatar_ready = Signal(str)  # local path to the fetched avatar image

    AVATAR_URL = "https://avatars.githubusercontent.com/u/109359355?s=512"
    REQUEST_HEADERS = {
        b"User-Agent": b"PkgToolBox/1.5.0",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._manager = QNetworkAccessManager(self)
        self._manager.finished.connect(self._on_response)
        self._reply = None

    def start(self):
        """Kick off the (non-blocking) avatar fetch."""
        if self._reply is not None:
            return
        request = QNetworkRequest(QUrl(self.AVATAR_URL))
        for name, value in self.REQUEST_HEADERS.items():
            request.setRawHeader(name, value)
        self._reply = self._manager.get(request)

    def _on_response(self, reply: QNetworkReply):
        self._reply = None
        try:
            if reply.error() != QNetworkReply.NetworkError.NoError:
                return  # offline / error: keep the bundled fallback icon
            data = bytes(reply.readAll())
            if not data:
                return
            config_dir = os.path.join(os.path.expanduser("~"), ".pkgtoolbox")
            os.makedirs(config_dir, exist_ok=True)
            path = os.path.join(config_dir, "avatar.png")
            with open(path, "wb") as f:
                f.write(data)
            self.avatar_ready.emit(path)
        finally:
            reply.deleteLater()

    @staticmethod
    def cached_avatar():
        """Return the cached avatar path if a previous fetch succeeded."""
        path = os.path.join(os.path.expanduser("~"), ".pkgtoolbox", "avatar.png")
        return path if os.path.exists(path) else None

    @staticmethod
    def bundled_icon_path():
        """Path to the bundled fallback icon (source tree or PyInstaller bundle)."""
        if getattr(sys, 'frozen', False):
            base = getattr(sys, '_MEIPASS', None)
            if base:
                candidate = os.path.join(base, 'icons', 'default_icon.png')
                if os.path.exists(candidate):
                    return candidate
            candidate = os.path.join(os.path.dirname(sys.executable),
                                     '_internal', 'icons', 'default_icon.png')
            if os.path.exists(candidate):
                return candidate
        here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return os.path.join(here, 'icons', 'default_icon.png')
