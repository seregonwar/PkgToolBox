"""PFS Info tab for dependency-free PS4/PS5 container inspection."""
from PySide6.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTextEdit,
    QMessageBox,
    QGroupBox,
    QCheckBox,
)
from PySide6.QtCore import QObject, QThread, Signal
from .base_tab import BaseTab
from packages import PackagePS4, PackagePS5


class PfsInfoTab(BaseTab):
    """Run the internal PFS inspector on the loaded PS4 package."""

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
        self.output_view.setPlaceholderText("Click 'Run PFS Info' to analyze the loaded PKG")
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
        if not isinstance(package, (PackagePS4, PackagePS5)):
            QMessageBox.warning(self, "PFS Info", "PFS Info is only available for PS4/PS5 PKG")
            return

        as_json = self.json_chk.isChecked()
        self.run_btn.setEnabled(False)
        self.output_view.clear()
        self.output_view.append("[+] Running internal PFS inspection{}...\n".format(" (JSON)" if as_json else ""))

        class Worker(QObject):
            finished = Signal(str)
            failed = Signal(str)

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
            # NOTE: bound methods (not closures) so Qt delivers them via queued
            # connection in the main thread — closures would run in the worker
            # thread and crash on macOS (NSWindow on non-main thread).
            self._wrk.finished.connect(self._on_pfs_done)
            self._wrk.failed.connect(self._on_pfs_failed)
            self._thr.finished.connect(self._thr.deleteLater)
            self._thr.start()
        except Exception as e:
            self.run_btn.setEnabled(True)
            QMessageBox.critical(self, "PFS Info", f"Failed to start pfs-info: {e}")

    def _on_pfs_done(self, text: str):
        """Main-thread slot: display pfs-info output."""
        try:
            self.output_view.clear()
            self.output_view.append(text or "<no output>")
        finally:
            self._thr.quit()
            self.run_btn.setEnabled(True)

    def _on_pfs_failed(self, err: str):
        """Main-thread slot: show the pfs-info error dialog."""
        try:
            QMessageBox.critical(self, "PFS Info", f"Failed: {err}")
        finally:
            self._thr.quit()
            self.run_btn.setEnabled(True)
