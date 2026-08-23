"""Sezione Modify: hex editor + editor campi header, su copia di lavoro."""
import os
import shutil

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QDialog, QFileDialog, QGroupBox,
                               QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                               QPushButton, QRadioButton, QTabWidget, QTextEdit,
                               QVBoxLayout, QWidget)

from .base_tab import BaseTab
from GUI.utils import StyleManager
from Utilities import Logger

HEX_ROWS = 16
PAGE_SIZE = 16 * 32  # 512 byte per pagina
FIELDS_SEARCH_SIZE = 0x40000  # primi 256 KB per la ricerca dei campi header


def hex_dump_html(data, base=0, row=HEX_ROWS, modified=None):
    """Hex dump in HTML con offset, colonna ASCII e byte modificati evidenziati."""
    modified = modified or {}
    lines = []
    for i in range(0, len(data), row):
        chunk = data[i:i + row]
        cells = []
        for j, b in enumerate(chunk):
            off = base + i + j
            txt = f"{b:02X}"
            if off in modified:
                txt = f'<span style="color:#ef4444;font-weight:bold">{txt}</span>'
            cells.append(txt)
        while len(cells) < row:
            cells.append("&nbsp;&nbsp;")
        hex_part = " ".join(cells)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{base + i:08X}  {hex_part}  |{ascii_part}|")
    return "<pre>" + "<br>".join(lines) + "</pre>"


class ModifyTab(BaseTab):
    """Editor hex con modifiche staged, applicate a una copia di lavoro.

    Il file originale non viene mai toccato: le modifiche vengono scritte su
    una copia in temp (che puoi esportare con 'Save As...').
    """

    def __init__(self, parent=None):
        self._source_file = None
        self._source_label = ""
        self._working_file = None
        self._pending = {}      # offset assoluto -> bytes
        self._page = 0
        self._file_size = 0
        self._warning_shown = False
        self._fields = []       # [(label, current_value, edit_widget)]
        super().__init__(parent)

    # ------------------------------------------------------------------
    def setup_ui(self):
        # ── Target (always visible) ──
        target_group = QGroupBox("Target")
        target_layout = QVBoxLayout(target_group)

        radios = QHBoxLayout()
        self.pkg_radio = QRadioButton("Loaded PKG file")
        self.file_radio = QRadioButton("File from PKG")
        self.pkg_radio.setChecked(True)
        self.pkg_radio.toggled.connect(self._on_target_changed)
        radios.addWidget(self.pkg_radio)
        radios.addWidget(self.file_radio)
        radios.addStretch(1)
        target_layout.addLayout(radios)

        file_row = QHBoxLayout()
        self.file_entry = QLineEdit()
        self.file_entry.setPlaceholderText("Pick a file from the loaded PKG or browse...")
        self.file_entry.setReadOnly(True)
        self.file_entry.setEnabled(False)
        pkg_btn = QPushButton("From PKG")
        pkg_btn.clicked.connect(self._pick_from_pkg)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_file)
        file_row.addWidget(self.file_entry, 1)
        file_row.addWidget(pkg_btn)
        file_row.addWidget(browse_btn)
        target_layout.addLayout(file_row)
        self.layout.addWidget(target_group)

        # ── Sub-sections: Hex Editor / Header Fields ──
        self.sub_tabs = QTabWidget()

        # Hex Editor page
        hex_page = QWidget()
        hex_page_layout = QVBoxLayout(hex_page)

        hex_group = QGroupBox("Hex Viewer")
        hex_layout = QVBoxLayout(hex_group)
        nav = QHBoxLayout()
        self.go_entry = QLineEdit()
        self.go_entry.setPlaceholderText("Offset (hex)")
        go_btn = QPushButton("Go")
        go_btn.clicked.connect(self._go_to_offset)
        prev_btn = QPushButton("\u25c0 Prev")
        prev_btn.clicked.connect(lambda: self._goto_page(self._page - 1))
        next_btn = QPushButton("Next \u25b6")
        next_btn.clicked.connect(lambda: self._goto_page(self._page + 1))
        self.page_label = QLabel("")
        nav.addWidget(QLabel("Offset:"))
        nav.addWidget(self.go_entry)
        nav.addWidget(go_btn)
        nav.addWidget(prev_btn)
        nav.addWidget(next_btn)
        nav.addWidget(self.page_label)
        nav.addStretch(1)
        hex_layout.addLayout(nav)

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setLineWrapMode(QTextEdit.NoWrap)
        font = QFont("Courier New", 10)
        font.setStyleHint(QFont.Monospace)
        self.hex_view.setFont(font)
        hex_layout.addWidget(self.hex_view)
        hex_page_layout.addWidget(hex_group, 3)

        edit_group = QGroupBox("Edit bytes")
        edit_layout = QHBoxLayout(edit_group)
        self.offset_entry = QLineEdit()
        self.offset_entry.setPlaceholderText("Offset (hex)")
        self.data_entry = QLineEdit()
        self.data_entry.setPlaceholderText("Data (hex, es. 00 01 7F)")
        stage_btn = QPushButton("Stage change")
        stage_btn.clicked.connect(self._stage_change)
        edit_layout.addWidget(QLabel("Offset:"))
        edit_layout.addWidget(self.offset_entry)
        edit_layout.addWidget(QLabel("Data:"))
        edit_layout.addWidget(self.data_entry, 1)
        edit_layout.addWidget(stage_btn)
        hex_page_layout.addWidget(edit_group)

        pending_row = QHBoxLayout()
        self.pending_label = QLabel("Pending changes: 0")
        pending_btn = QPushButton("View pending")
        pending_btn.clicked.connect(self._view_pending)
        clear_btn = QPushButton("Discard pending")
        clear_btn.clicked.connect(self._clear_pending)
        pending_row.addWidget(self.pending_label)
        pending_row.addStretch(1)
        pending_row.addWidget(pending_btn)
        pending_row.addWidget(clear_btn)
        hex_page_layout.addLayout(pending_row)

        actions = QHBoxLayout()
        self.write_btn = QPushButton("Write to copy")
        self.write_btn.clicked.connect(self._on_write)
        self.saveas_btn = QPushButton("Save As...")
        self.saveas_btn.clicked.connect(self._save_as)
        self.reload_btn = QPushButton("Load modified copy")
        self.reload_btn.clicked.connect(self._load_modified_copy)
        actions.addWidget(self.write_btn)
        actions.addWidget(self.saveas_btn)
        actions.addWidget(self.reload_btn)
        actions.addStretch(1)
        hex_page_layout.addLayout(actions)
        hex_page_layout.addStretch(1)
        self.sub_tabs.addTab(hex_page, "Hex Editor")

        # Header Fields page
        fields_page = QWidget()
        fields_page_layout = QVBoxLayout(fields_page)
        self.fields_group = QGroupBox("Known header fields")
        fields_layout = QVBoxLayout(self.fields_group)
        fields_row = QHBoxLayout()
        self.content_id_edit = QLineEdit()
        self.title_id_edit = QLineEdit()
        fields_row.addWidget(QLabel("Content ID:"))
        fields_row.addWidget(self.content_id_edit, 1)
        fields_row.addWidget(QLabel("Title ID:"))
        fields_row.addWidget(self.title_id_edit, 1)
        fields_layout.addLayout(fields_row)
        fields_hint = QLabel(
            "The values above are read from the loaded PKG and edited in place:\n"
            "'Stage field edits' locates each current value in the first 0x40000 bytes "
            "of the file, keeps its width (including trailing nulls) and adds it to the "
            "pending changes of the Hex Editor section."
        )
        fields_hint.setWordWrap(True)
        fields_layout.addWidget(fields_hint)
        stage_fields_btn = QPushButton("Stage field edits")
        stage_fields_btn.clicked.connect(self._stage_field_edits)
        fields_layout.addWidget(stage_fields_btn, alignment=Qt.AlignLeft)
        fields_page_layout.addWidget(self.fields_group)
        fields_page_layout.addWidget(
            QLabel("Pending edits are reviewed and written from the Hex Editor section."),
            alignment=Qt.AlignLeft,
        )
        fields_page_layout.addStretch(1)
        self.sub_tabs.addTab(fields_page, "Header Fields")
        self.layout.addWidget(self.sub_tabs, 3)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.layout.addWidget(self.status_label)
        self.layout.addStretch(1)

        self._refresh_hex()
        self._refresh_status()

    # ------------------------------------------------------------------
    # Target / source
    # ------------------------------------------------------------------
    def _on_target_changed(self):
        if self.pkg_radio.isChecked():
            pkg = self.parent_window.package
            self.file_entry.setEnabled(False)
            if pkg and getattr(pkg, "original_file", None):
                self._set_source(pkg.original_file, "Loaded PKG")
            else:
                self._set_source(None, None)
        else:
            self.file_entry.setEnabled(True)
            entry = self.file_entry.text()
            if entry:
                self._set_source(entry, os.path.basename(entry))
            else:
                self._set_source(None, None)

    def refresh_package(self):
        """Richiamato dal parent quando cambia il PKG caricato."""
        if self.pkg_radio.isChecked():
            self._on_target_changed()

    def _pick_from_pkg(self):
        mw = self.parent_window
        if not mw.package:
            QMessageBox.information(self, "Modify", "Load a PKG file first.")
            return
        infos = mw._pick_pkg_file(title="Select a file to edit")
        if not infos:
            return
        path = mw._extract_pkg_file(infos[0], subdir="modify")
        self.file_entry.setText(path)
        self._set_source(path, infos[0]["name"])

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file to edit")
        if path:
            self.file_entry.setText(path)
            self._set_source(path, os.path.basename(path))

    def _set_source(self, path, label):
        self._source_file = path
        self._source_label = label or ""
        self._working_file = None
        self._pending = {}
        self._page = 0
        self._warning_shown = False
        self._file_size = os.path.getsize(path) if path else 0
        self._load_header_fields()
        self._refresh_hex()
        self._refresh_status()

    def _read_path(self):
        """Legge dalla copia di lavoro se esiste, altrimenti dalla sorgente."""
        return self._working_file or self._source_file

    # ------------------------------------------------------------------
    # Hex view
    # ------------------------------------------------------------------
    def _refresh_hex(self):
        if not self._source_file:
            self.hex_view.setPlainText(
                "Load a PKG file (or pick a file from the PKG) to start editing.\n\n"
                "Edits are staged, then written to a working copy — never the original."
            )
            self.page_label.setText("")
            return
        total_pages = max(1, (self._file_size + PAGE_SIZE - 1) // PAGE_SIZE)
        self._page = max(0, min(self._page, total_pages - 1))
        base = self._page * PAGE_SIZE
        with open(self._read_path(), "rb") as f:
            f.seek(base)
            data = f.read(PAGE_SIZE)
        modified = {off: b for off, b in self._pending.items() if base <= off < base + PAGE_SIZE}
        self.hex_view.setHtml(hex_dump_html(data, base=base, modified=modified))
        self.page_label.setText(f"Page {self._page + 1}/{total_pages}  (0x{base:08X})")

    def _goto_page(self, page):
        if not self._source_file:
            return
        total_pages = max(1, (self._file_size + PAGE_SIZE - 1) // PAGE_SIZE)
        self._page = max(0, min(page, total_pages - 1))
        self._refresh_hex()

    def _go_to_offset(self):
        if not self._source_file:
            return
        try:
            off = int(self.go_entry.text().strip(), 16)
        except ValueError:
            QMessageBox.warning(self, "Offset", "Invalid hex offset.")
            return
        if not (0 <= off < self._file_size):
            QMessageBox.warning(self, "Offset",
                                f"Offset out of range (file size 0x{self._file_size:X}).")
            return
        self._page = off // PAGE_SIZE
        self._refresh_hex()

    # ------------------------------------------------------------------
    # Staging edits
    # ------------------------------------------------------------------
    def _stage_change(self):
        if not self._source_file:
            QMessageBox.warning(self, "Edit", "Select a target first.")
            return
        try:
            off = int(self.offset_entry.text().strip(), 16)
        except ValueError:
            QMessageBox.warning(self, "Edit", "Invalid offset (hex).")
            return
        try:
            new_data = bytes.fromhex(self.data_entry.text().strip())
        except ValueError:
            QMessageBox.warning(self, "Edit", "Invalid data (hex).")
            return
        if not new_data:
            QMessageBox.warning(self, "Edit", "Enter some data to write.")
            return
        if off < 0 or off + len(new_data) > self._file_size:
            QMessageBox.warning(self, "Edit",
                                f"Offset+data out of range (file size 0x{self._file_size:X}).")
            return
        self._pending[off] = new_data
        self.offset_entry.clear()
        self.data_entry.clear()
        self._refresh_hex()
        self._refresh_status()

    def _view_pending(self):
        if not self._pending:
            QMessageBox.information(self, "Pending changes", "No staged changes.")
            return
        lines = []
        for off in sorted(self._pending):
            data = self._pending[off]
            lines.append(f"0x{off:08X}  {' '.join(f'{b:02X}' for b in data)}")
        dlg = QDialog(self)
        dlg.setWindowTitle("Pending changes")
        dlg.resize(560, 320)
        lay = QVBoxLayout(dlg)
        view = QTextEdit()
        view.setReadOnly(True)
        view.setFont(QFont("Courier New", 10))
        view.setPlainText("\n".join(lines))
        lay.addWidget(view)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        lay.addWidget(close_btn, alignment=Qt.AlignRight)
        dlg.exec()

    def _clear_pending(self):
        if not self._pending:
            return
        self._pending = {}
        self._refresh_hex()
        self._refresh_status()

    # ------------------------------------------------------------------
    # Header fields
    # ------------------------------------------------------------------
    def _load_header_fields(self):
        self.fields_group.setVisible(False)
        self.content_id_edit.clear()
        self.title_id_edit.clear()
        pkg = self.parent_window.package
        if not pkg or not self._source_file or not self.pkg_radio.isChecked():
            return
        content_id = getattr(pkg, "content_id", None) or getattr(pkg, "pkg_content_id", None)
        title_id = getattr(pkg, "title_id", None)
        if content_id:
            self.content_id_edit.setText(str(content_id))
        if title_id:
            self.title_id_edit.setText(str(title_id))
        self.fields_group.setVisible(bool(content_id or title_id))

    @staticmethod
    def _find_field_run(data, value):
        """Trova il valore nel buffer e ne estende la larghezza sui null finali."""
        vb = value.encode("ascii", "ignore")
        idx = data.find(vb)
        if idx < 0:
            return None
        end = idx + len(vb)
        while end < len(data) and data[end] == 0 and end - idx < 64:
            end += 1
        return idx, end - idx

    def _stage_field_edits(self):
        if not self._source_file:
            return
        pkg = self.parent_window.package
        current = {
            "Content ID": getattr(pkg, "content_id", None) or getattr(pkg, "pkg_content_id", None),
            "Title ID": getattr(pkg, "title_id", None),
        }
        edits = {
            "Content ID": self.content_id_edit.text().strip(),
            "Title ID": self.title_id_edit.text().strip(),
        }

        with open(self._source_file, "rb") as f:
            head = f.read(FIELDS_SEARCH_SIZE)

        staged = 0
        for label, new_value in edits.items():
            if not new_value:
                continue
            cur = current.get(label)
            if not cur:
                QMessageBox.warning(self, "Header fields",
                                    f"'{label}' is not available for this PKG.")
                continue
            run = self._find_field_run(head, str(cur))
            if not run:
                QMessageBox.warning(self, "Header fields",
                                    f"'{label}' current value not found in the file header "
                                    f"(first 0x{FIELDS_SEARCH_SIZE:X} bytes).")
                continue
            start, width = run
            new_bytes = new_value.encode("ascii", "ignore")[:width]
            new_bytes = new_bytes + b"\x00" * (width - len(new_bytes))
            self._pending[start] = new_bytes
            staged += 1

        if staged:
            self._refresh_hex()
            self._refresh_status()
            QMessageBox.information(self, "Header fields",
                                    f"Staged {staged} field change(s).")

    # ------------------------------------------------------------------
    # Working copy + actions
    # ------------------------------------------------------------------
    def _ensure_working_copy(self):
        if self._working_file:
            return self._working_file
        if not self._source_file:
            raise ValueError("No target selected")
        mod_dir = os.path.join(self.parent_window.temp_directory, "modify", "working")
        os.makedirs(mod_dir, exist_ok=True)
        dest = os.path.join(mod_dir, os.path.basename(self._source_file) or "working.bin")
        shutil.copy2(self._source_file, dest)
        self._working_file = dest
        return dest

    def _apply_pending(self):
        if not self._pending:
            return
        path = self._ensure_working_copy()
        with open(path, "r+b") as f:
            for off, data in self._pending.items():
                f.seek(off)
                f.write(data)
        self._pending = {}
        self._refresh_hex()
        self._refresh_status()

    def _on_write(self):
        if not self._source_file:
            QMessageBox.warning(self, "Modify", "Select a target first.")
            return
        if not self._pending:
            QMessageBox.information(self, "Modify", "No staged changes.")
            return
        if not self._warning_shown:
            box = QMessageBox(self)
            box.setWindowTitle("Warning")
            box.setIcon(QMessageBox.Warning)
            box.setText(
                "Modifying a PKG invalidates its SHA-256 digests and NPDRM signature — "
                "a retail console will refuse the modified file.\n\n"
                "The original file is never touched: changes are written to a working "
                "copy in the temp directory, which you can export with 'Save As...'."
            )
            ok_btn = box.addButton("Continue", QMessageBox.AcceptRole)
            box.addButton("Cancel", QMessageBox.RejectRole)
            box.exec()
            if box.clickedButton() != ok_btn:
                return
            self._warning_shown = True
        try:
            self._apply_pending()
            Logger.log_information(f"Modify: changes applied to {self._working_file}")
            QMessageBox.information(self, "Modify",
                                    f"Changes written to working copy:\n{self._working_file}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to write changes: {str(e)}")

    def _save_as(self):
        if not self._source_file:
            QMessageBox.warning(self, "Modify", "Select a target first.")
            return
        try:
            if self._pending:
                self._apply_pending()
            elif not self._working_file:
                self._ensure_working_copy()
            out, _ = QFileDialog.getSaveFileName(
                self, "Save modified file", os.path.basename(self._source_file)
            )
            if not out:
                return
            shutil.copy2(self._working_file, out)
            QMessageBox.information(self, "Modify", f"Saved to:\n{out}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save: {str(e)}")

    def _load_modified_copy(self):
        if not self._working_file:
            QMessageBox.information(self, "Modify",
                                    "No working copy yet — stage and write some changes first.")
            return
        mw = self.parent_window
        if self.pkg_radio.isChecked():
            mw.load_pkg(self._working_file)
        else:
            QMessageBox.information(self, "Modify", f"Working copy:\n{self._working_file}")

    # ------------------------------------------------------------------
    def _refresh_status(self):
        n_changes = len(self._pending)
        n_bytes = sum(len(b) for b in self._pending.values())
        self.pending_label.setText(f"Pending changes: {n_changes} ({n_bytes} bytes)")
        self.write_btn.setEnabled(bool(self._pending) and self._source_file is not None)
        self.saveas_btn.setEnabled(
            self._source_file is not None and (bool(self._pending) or bool(self._working_file))
        )
        self.reload_btn.setEnabled(bool(self._working_file))
        if not self._source_file:
            self.status_label.setText("")
            return
        where = "working copy" if self._working_file else "source"
        self.status_label.setText(
            f"Target: {self._source_label} ({self._source_file}) — edits are staged and "
            f"written to a {where}, never the original."
        )
