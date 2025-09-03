"""
PFS Info tab widget for inspecting PS4 PKG PFS structure via shadPKG
"""
from PyQt5.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QMessageBox,
    QGroupBox,
    QCheckBox,
)
from PyQt5.QtCore import Qt, QObject, QThread, pyqtSignal
from .base_tab import BaseTab
from packages import PackagePS4


class PfsInfoTab(BaseTab):
    """Tab to run shadPKG pfs-info on the currently loaded PKG"""

    def setup_ui(self):
        # Controls group
        controls_group = QGroupBox("PFS Info Controls")
        controls_layout = QVBoxLayout()

        row = QHBoxLayout()
        self.run_btn = QPushButton("Run PFS Info")
        self.run_btn.clicked.connect(self.run_pfs_info)
        self.json_chk = QCheckBox("JSON output")
        row.addWidget(self.run_btn)
        row.addWidget(self.json_chk)
        row.addStretch(1)
        controls_layout.addLayout(row)
        controls_group.setLayout(controls_layout)

        # Output group
        output_group = QGroupBox("PFS Info Output")
        output_layout = QVBoxLayout()
        self.output_view = QTextEdit()
        self.output_view.setReadOnly(True)
        self.output_view.setMinimumHeight(360)
        self.output_view.setPlaceholderText("Click 'Run PFS Info' to analyze the loaded PS4 PKG")
        output_layout.addWidget(self.output_view)
        output_group.setLayout(output_layout)

        # Assemble
        self.layout.addWidget(controls_group)
        self.layout.addWidget(output_group)
        self.layout.addStretch(1)

    def run_pfs_info(self):
        package = self.get_package()
        if not package:
            QMessageBox.warning(self, "PFS Info", "Please load a PKG file first")
            return
        if not isinstance(package, PackagePS4):
            QMessageBox.warning(self, "PFS Info", "PFS Info is only available for PS4 PKG")
            return

        as_json = self.json_chk.isChecked()
        self.run_btn.setEnabled(False)
        self.output_view.clear()
        self.output_view.append("[+] Running shadPKG pfs-info{}...\n".format(" --json" if as_json else ""))

        class Worker(QObject):
            finished = pyqtSignal(str)
            failed = pyqtSignal(str)

            def __init__(self, pkg, json_flag):
                super().__init__()
                self._pkg = pkg
                self._json = json_flag

            def run(self):
                try:
                    out = self._pkg.get_pfs_info(as_json=self._json)
                    self.finished.emit(out)
                except Exception as e:
                    self.failed.emit(str(e))

        try:
            self._thr = QThread(self)
            self._wrk = Worker(package, as_json)
            self._wrk.moveToThread(self._thr)
            self._thr.started.connect(self._wrk.run)

            def _done(text: str):
                try:
                    self.output_view.clear()
                    self.output_view.append(text or "<no output>")
                finally:
                    self._thr.quit()
                    self.run_btn.setEnabled(True)

            def _fail(err: str):
                try:
                    QMessageBox.critical(self, "PFS Info", f"Failed: {err}")
                finally:
                    self._thr.quit()
                    self.run_btn.setEnabled(True)

            self._wrk.finished.connect(_done)
            self._wrk.failed.connect(_fail)
            self._thr.finished.connect(self._thr.deleteLater)
            self._thr.start()
        except Exception as e:
            self.run_btn.setEnabled(True)
            QMessageBox.critical(self, "PFS Info", f"Failed to start pfs-info: {e}")
