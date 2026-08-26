"""Sezione Modify: hex editor (stile HxD/010 Editor) + editor campi header, su copia di lavoro."""
import os
import shutil
import struct

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QFileDialog,
                               QFrame, QGridLayout, QGroupBox, QHBoxLayout,
                               QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
                               QPushButton, QRadioButton, QSplitter, QTabWidget,
                               QTextEdit, QVBoxLayout, QWidget)

from .base_tab import BaseTab
from Utilities import Logger

# ── Layout del dump (formato fisso, monospace) ──────────────────────────────
HEX_ROWS = 16            # byte per riga
PAGE_ROWS = 32           # righe per pagina
PAGE_SIZE = HEX_ROWS * PAGE_ROWS  # 512 byte
LINE_LEN = 78            # lunghezza di una riga (senza newline)
BYTE0_COL = 10           # colonna del primo byte hex
BYTE8_COL = 35           # colonna del 9° byte (dopo il gap)
ASCII_COL = 61           # colonna del primo carattere ASCII

HEX_HEADER = (
    f"{'Offset':<8}  "
    + " ".join(f"{i:02X}" for i in range(8))
    + "  "
    + " ".join(f"{i:02X}" for i in range(8, 16))
    + "  "
    + f"{'ASCII':<16}"
)

HEX_ONLY_HEADER = " ".join(f"{i:02X}" for i in range(8)) + "  " + \
                  " ".join(f"{i:02X}" for i in range(8, 16))
HEX_ONLY_LINE_LEN = 48
HEX_ONLY_BYTE8_COL = 25
FIELDS_SEARCH_SIZE = 0x40000


def format_hex_line(base, data, row=HEX_ROWS):
    """Una riga del dump: offset + 16 byte (gruppi da 8) + colonna ASCII."""
    data = bytes(data)
    cells = [f"{b:02X}" for b in data] + ["  "] * (row - len(data))
    first = " ".join(cells[:8])
    second = " ".join(cells[8:16])
    ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
    ascii_part = ascii_part.ljust(row)
    return f"{base:08X}  {first}  {second}  |{ascii_part}|"


def format_hex_bytes(data, row=HEX_ROWS):
    """Render only the byte cells used by the split binary workspace."""
    cells = [f"{b:02X}" for b in bytes(data)] + ["  "] * (row - len(data))
    return " ".join(cells[:8]) + "  " + " ".join(cells[8:16])


def format_text_bytes(data, row=HEX_ROWS):
    """One visible character per byte; non-printable bytes use a middle dot."""
    return "".join(chr(b) if 32 <= b <= 126 else "·" for b in bytes(data)).ljust(row)


def encode_search_query(text, mode="text", encoding="utf-8"):
    """Convert a user-facing search query into bytes, raising a useful error."""
    if mode == "hex":
        compact = "".join(text.split())
        if not compact:
            return b""
        if len(compact) % 2:
            raise ValueError("Hex searches need pairs of digits, for example: 7F 45 4C 46.")
        try:
            return bytes.fromhex(compact)
        except ValueError as exc:
            raise ValueError("The hex search contains invalid characters.") from exc
    if not text:
        return b""
    try:
        return text.encode(encoding)
    except UnicodeEncodeError as exc:
        raise ValueError(f"The text cannot be represented as {encoding.upper()}.") from exc


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
        self._cursor_offset = None
        self._search_range = None   # (start, end) dell'ultimo match
        self._sel_range = None      # (start, end) della selezione corrente
        self._cursor_syncing = False
        self._scroll_syncing = False
        self._search_note = ""
        super().__init__(parent)

    # ------------------------------------------------------------------
    def setup_ui(self):
        hero = QFrame()
        hero.setObjectName("binaryHero")
        hero_layout = QHBoxLayout(hero)
        hero_copy = QVBoxLayout()
        title = QLabel("Binary workspace")
        title.setObjectName("binaryTitle")
        subtitle = QLabel(
            "Inspect bytes and readable text side by side. Changes stay staged until you write a copy."
        )
        subtitle.setObjectName("binarySubtitle")
        subtitle.setWordWrap(True)
        hero_copy.addWidget(title)
        hero_copy.addWidget(subtitle)
        hero_layout.addLayout(hero_copy, 1)
        self.layout.addWidget(hero)

        # ── Target (always visible, single compact row) ──
        target_group = QGroupBox("Target")
        target_group.setObjectName("binaryTarget")
        target_layout = QVBoxLayout(target_group)

        target_row = QHBoxLayout()
        self.pkg_radio = QRadioButton("Loaded source")
        self.file_radio = QRadioButton("File from contents")
        self.pkg_radio.setChecked(True)
        self.pkg_radio.toggled.connect(self._on_target_changed)
        target_row.addWidget(self.pkg_radio)
        target_row.addWidget(self.file_radio)
        target_row.addSpacing(12)
        self.file_entry = QLineEdit()
        self.file_entry.setPlaceholderText("Pick a mapped file or browse...")
        self.file_entry.setReadOnly(True)
        self.file_entry.setEnabled(False)
        target_row.addWidget(self.file_entry, 1)
        pkg_btn = QPushButton("From contents")
        pkg_btn.clicked.connect(self._pick_from_pkg)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_file)
        target_row.addWidget(pkg_btn)
        target_row.addWidget(browse_btn)
        target_layout.addLayout(target_row)
        self.layout.addWidget(target_group)

        # ── Sub-sections: binary view / staged changes / known metadata ──
        self.sub_tabs = QTabWidget()
        self.sub_tabs.setObjectName("binaryTabs")
        self.sub_tabs.addTab(self._build_hex_page(), "Binary view")
        self.sub_tabs.addTab(self._build_stage_page(), "Changes")
        self.sub_tabs.addTab(self._build_fields_page(), "Metadata")
        self.layout.addWidget(self.sub_tabs, 3)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.layout.addWidget(self.status_label)
        self.layout.addStretch(1)

        self._refresh_hex()
        self._refresh_status()

    # ── Hex Viewer page ───────────────────────────────────────────────
    def _build_hex_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 8)
        layout.setSpacing(10)

        # Two purposeful rows keep navigation and search usable at compact widths.
        toolbar = QFrame()
        toolbar.setObjectName("binaryToolbar")
        toolbar_layout = QVBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(10, 8, 10, 8)
        toolbar_layout.setSpacing(8)

        nav = QHBoxLayout()
        nav.addWidget(QLabel("Go to offset"))
        self.go_entry = QLineEdit()
        self.go_entry.setPlaceholderText("0x1A0")
        self.go_entry.setMaximumWidth(150)
        self.go_entry.returnPressed.connect(self._go_to_offset)
        go_btn = QPushButton("Go")
        go_btn.setObjectName("secondaryButton")
        go_btn.clicked.connect(self._go_to_offset)
        self.dec_check = QCheckBox("Dec")
        self.dec_check.setToolTip("Interpret the offset field as decimal")
        prev_btn = QPushButton("\u25c0 Prev")
        prev_btn.setObjectName("secondaryButton")
        prev_btn.clicked.connect(lambda: self._goto_page(self._page - 1))
        next_btn = QPushButton("Next \u25b6")
        next_btn.setObjectName("secondaryButton")
        next_btn.clicked.connect(lambda: self._goto_page(self._page + 1))
        nav.addWidget(self.go_entry)
        nav.addWidget(go_btn)
        nav.addWidget(self.dec_check)
        nav.addSpacing(12)
        nav.addWidget(prev_btn)
        nav.addWidget(next_btn)
        self.page_label = QLabel("Page —")
        self.page_label.setObjectName("binaryMuted")
        nav.addWidget(self.page_label)
        nav.addStretch(1)
        toolbar_layout.addLayout(nav)

        search = QHBoxLayout()
        search.addWidget(QLabel("Search"))
        self.find_mode = QComboBox()
        self.find_mode.addItem("Plain text", "text")
        self.find_mode.addItem("Hex bytes", "hex")
        self.find_mode.currentIndexChanged.connect(self._on_find_mode_changed)
        search.addWidget(self.find_mode)
        self.find_entry = QLineEdit()
        self.find_entry.setPlaceholderText("Type text exactly as it appears in the file")
        self.find_entry.returnPressed.connect(self._find_next)
        self.find_case = QCheckBox("Case sensitive")
        self.find_case.setChecked(True)
        find_btn = QPushButton("Find next")
        find_btn.clicked.connect(self._find_next)
        search.addWidget(self.find_entry, 1)
        search.addWidget(self.find_case)
        search.addWidget(find_btn)
        toolbar_layout.addLayout(search)
        layout.addWidget(toolbar)

        # View + Data Inspector (splitter)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setObjectName("binarySplitter")

        binary_surface = QFrame()
        binary_surface.setObjectName("binarySurface")
        surface_layout = QVBoxLayout(binary_surface)
        surface_layout.setContentsMargins(0, 0, 0, 0)
        surface_layout.setSpacing(0)

        headers = QHBoxLayout()
        headers.setContentsMargins(10, 7, 10, 7)
        offset_header = QLabel("OFFSET")
        offset_header.setObjectName("binaryPaneHeader")
        offset_header.setFixedWidth(86)
        hex_header = QLabel(HEX_ONLY_HEADER)
        hex_header.setObjectName("binaryPaneHeader")
        hex_header.setFont(self._mono_font())
        text_header = QLabel("TEXT / ASCII")
        text_header.setObjectName("binaryPaneHeader")
        headers.addWidget(offset_header)
        headers.addWidget(hex_header, 1)
        headers.addWidget(text_header)
        headers.setStretch(1, 1)
        surface_layout.addLayout(headers)

        panes = QHBoxLayout()
        panes.setContentsMargins(0, 0, 0, 0)
        panes.setSpacing(0)
        self.offset_view = self._make_binary_pane("offsetPane")
        self.offset_view.setFixedWidth(96)
        self.offset_view.setTextInteractionFlags(Qt.NoTextInteraction)
        self.offset_view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.hex_view = QPlainTextEdit()
        self.hex_view.setObjectName("hexPane")
        self.hex_view.setReadOnly(True)
        self.hex_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.hex_view.setFont(self._mono_font())
        self.hex_view.setTextInteractionFlags(
            Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard
        )
        self.hex_view.setCursor(Qt.IBeamCursor)
        self.hex_view.cursorPositionChanged.connect(self._on_hex_cursor_moved)
        self.hex_view.selectionChanged.connect(
            lambda: self._on_selection_changed(self.hex_view, "hex")
        )
        self.text_view = self._make_binary_pane("textPane")
        self.text_view.setMinimumWidth(170)
        self.text_view.setTextInteractionFlags(
            Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard
        )
        self.text_view.setCursor(Qt.IBeamCursor)
        self.text_view.cursorPositionChanged.connect(self._on_text_cursor_moved)
        self.text_view.selectionChanged.connect(
            lambda: self._on_selection_changed(self.text_view, "text")
        )
        panes.addWidget(self.offset_view)
        panes.addWidget(self.hex_view, 1)
        panes.addWidget(self.text_view)
        panes.setStretch(1, 1)
        surface_layout.addLayout(panes, 1)
        self._connect_scrollbars()
        splitter.addWidget(binary_surface)

        inspector = QGroupBox("Data inspector")
        inspector.setObjectName("binaryInspector")
        inspector_layout = QVBoxLayout(inspector)
        self.ins_offset = QLabel("Offset: —")
        self.ins_offset.setFont(self._mono_font())
        inspector_layout.addWidget(self.ins_offset)
        grid = QGridLayout()
        self.inspector_labels = {}
        rows = [
            ("u8", "u8"), ("s8", "s8"),
            ("u16 LE", "u16_le"), ("u16 BE", "u16_be"),
            ("u32 LE", "u32_le"), ("u32 BE", "u32_be"),
            ("u64 LE", "u64_le"), ("u64 BE", "u64_be"),
            ("f32", "f32"), ("f64", "f64"),
            ("ASCII", "ascii"),
        ]
        for index, (label, key) in enumerate(rows):
            row = index // 2
            column = (index % 2) * 2
            name = QLabel(label)
            name.setObjectName("binaryMuted")
            value = QLabel("—")
            value.setFont(self._mono_font())
            grid.addWidget(name, row, column, Qt.AlignLeft)
            grid.addWidget(value, row, column + 1, Qt.AlignLeft)
            self.inspector_labels[key] = value
        inspector_layout.addLayout(grid)
        inspector_layout.addStretch(1)
        splitter.addWidget(inspector)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 0)
        splitter.setSizes([760, 250])
        splitter.setCollapsible(1, True)
        layout.addWidget(splitter, 1)

        # Status strip
        self.hex_status = QLabel("")
        self.hex_status.setObjectName("binaryStatus")
        layout.addWidget(self.hex_status)
        return page

    # ── Stage & Write page ────────────────────────────────────────────
    def _build_stage_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        edit_group = QGroupBox("Edit bytes")
        edit_layout = QHBoxLayout(edit_group)
        self.offset_entry = QLineEdit()
        self.offset_entry.setPlaceholderText("Offset (hex)")
        self.data_entry = QLineEdit()
        self.data_entry.setPlaceholderText("Data (hex, es. 00 01 7F)")
        stage_btn = QPushButton("Stage change")
        stage_btn.clicked.connect(self._stage_change)
        cursor_btn = QPushButton("Use cursor offset")
        cursor_btn.setToolTip("Fill the offset field with the byte selected in the Hex Viewer")
        cursor_btn.clicked.connect(self._use_cursor_offset)
        edit_layout.addWidget(QLabel("Offset:"))
        edit_layout.addWidget(self.offset_entry)
        edit_layout.addWidget(QLabel("Data:"))
        edit_layout.addWidget(self.data_entry, 1)
        edit_layout.addWidget(stage_btn)
        edit_layout.addWidget(cursor_btn)
        layout.addWidget(edit_group)

        pending_group = QGroupBox("Pending changes")
        pending_layout = QVBoxLayout(pending_group)
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
        pending_layout.addLayout(pending_row)
        layout.addWidget(pending_group)

        actions_group = QGroupBox("Apply / export")
        actions = QHBoxLayout(actions_group)
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
        layout.addWidget(actions_group)

        hint = QLabel(
            "Edits are staged here (they never touch the original file), reviewed "
            "in the Hex Viewer (staged bytes shown in red), then written to a "
            "working copy you can export."
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)
        layout.addStretch(1)
        return page

    # ── Header Fields page ────────────────────────────────────────────
    def _build_fields_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
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
            "The values above are read from the loaded source and edited in place:\n"
            "'Stage field edits' locates each current value in the first 0x40000 bytes "
            "of the file, keeps its width (including trailing nulls) and adds it to the "
            "pending changes of the Stage & Write section."
        )
        fields_hint.setWordWrap(True)
        fields_layout.addWidget(fields_hint)
        stage_fields_btn = QPushButton("Stage field edits")
        stage_fields_btn.clicked.connect(self._stage_field_edits)
        fields_layout.addWidget(stage_fields_btn, alignment=Qt.AlignLeft)
        layout.addWidget(self.fields_group)
        layout.addWidget(
            QLabel("Pending edits are reviewed in the Hex Viewer and written from the "
                   "Stage & Write section."),
            alignment=Qt.AlignLeft,
        )
        layout.addStretch(1)
        return page

    @staticmethod
    def _mono_font():
        font = QFont("Courier New", 10)
        font.setStyleHint(QFont.Monospace)
        return font

    def _make_binary_pane(self, object_name):
        pane = QPlainTextEdit()
        pane.setObjectName(object_name)
        pane.setReadOnly(True)
        pane.setLineWrapMode(QPlainTextEdit.NoWrap)
        pane.setFont(self._mono_font())
        pane.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        return pane

    def _connect_scrollbars(self):
        panes = (self.offset_view, self.hex_view, self.text_view)
        for pane in panes:
            pane.verticalScrollBar().valueChanged.connect(
                lambda value, source=pane: self._sync_binary_scroll(source, value)
            )

    def _sync_binary_scroll(self, source, value):
        if self._scroll_syncing:
            return
        self._scroll_syncing = True
        try:
            for pane in (self.offset_view, self.hex_view, self.text_view):
                if pane is not source:
                    pane.verticalScrollBar().setValue(value)
        finally:
            self._scroll_syncing = False

    def _on_find_mode_changed(self):
        is_text = self.find_mode.currentData() == "text"
        self.find_case.setVisible(is_text)
        self.find_entry.setPlaceholderText(
            "Type text exactly as it appears in the file"
            if is_text else "Enter bytes, for example: 7F 45 4C 46"
        )
        self._search_range = None
        self._search_note = ""
        self._update_highlights()

    # ------------------------------------------------------------------
    # Target / source
    # ------------------------------------------------------------------
    def _on_target_changed(self):
        if self.pkg_radio.isChecked():
            pkg = self.parent_window.package
            self.file_entry.setEnabled(False)
            if pkg and getattr(pkg, "original_file", None):
                self._set_source(
                    pkg.original_file,
                    f"Loaded source · {os.path.basename(pkg.original_file)}",
                )
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
            QMessageBox.information(self, "Modify", "Load a package, project, or file first.")
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
        self._cursor_offset = None
        self._search_range = None
        self._sel_range = None
        self._search_note = ""
        self._file_size = os.path.getsize(path) if path else 0
        self._load_header_fields()
        self._refresh_hex()
        self._refresh_status()

    def _read_path(self):
        """Legge dalla copia di lavoro se esiste, altrimenti dalla sorgente."""
        return self._working_file or self._source_file

    def _read_at(self, offset, length):
        if not self._source_file:
            return b""
        with open(self._read_path(), "rb") as f:
            f.seek(offset)
            return f.read(length)

    # ------------------------------------------------------------------
    # Geometria del dump (offset <-> posizione nel widget)
    # ------------------------------------------------------------------
    @staticmethod
    def _byte_col(byte_idx):
        if 0 <= byte_idx < 8:
            return BYTE0_COL + byte_idx * 3
        return BYTE8_COL + (byte_idx - 8) * 3

    @staticmethod
    def _byte_index_at_col(col):
        if BYTE0_COL <= col <= BYTE0_COL + 22:   # 10..32
            d = col - BYTE0_COL
            if d % 3 == 0:
                return d // 3
        elif BYTE8_COL <= col <= BYTE8_COL + 22:  # 35..57
            d = col - BYTE8_COL
            if d % 3 == 0:
                return 8 + d // 3
        elif ASCII_COL <= col <= ASCII_COL + 15:  # 61..76
            return col - ASCII_COL
        return None

    def _pos_of_byte(self, line, byte_idx):
        """Legacy monolithic-dump position retained for format compatibility."""
        return line * (LINE_LEN + 1) + self._byte_col(byte_idx)

    @staticmethod
    def _hex_byte_col(byte_idx):
        return byte_idx * 3 if byte_idx < 8 else HEX_ONLY_BYTE8_COL + (byte_idx - 8) * 3

    @staticmethod
    def _hex_byte_index_at_col(col):
        if 0 <= col <= 22:
            return col // 3 if col % 3 == 0 else None
        if HEX_ONLY_BYTE8_COL <= col <= 47:
            delta = col - HEX_ONLY_BYTE8_COL
            return 8 + delta // 3 if delta % 3 == 0 else None
        return None

    def _pane_offset_at_pos(self, pane, pos, kind, loose=False):
        """Return the absolute byte represented by a position in either pane."""
        cursor = QTextCursor(pane.document())
        cursor.setPosition(pos)
        col = cursor.positionInBlock()
        if kind == "text":
            byte_idx = col if 0 <= col < HEX_ROWS else None
        else:
            byte_idx = self._hex_byte_index_at_col(col)
            if byte_idx is None and loose:
                for candidate in range(col - 1, max(-1, col - 4), -1):
                    byte_idx = self._hex_byte_index_at_col(candidate)
                    if byte_idx is not None:
                        break
        if byte_idx is None:
            return None
        base = self._page * PAGE_SIZE
        offset = base + cursor.blockNumber() * HEX_ROWS + byte_idx
        return offset if offset < self._file_size else None

    @staticmethod
    def _pane_pos_of_byte(line, byte_idx, kind):
        if kind == "text":
            return line * (HEX_ROWS + 1) + byte_idx
        return line * (HEX_ONLY_LINE_LEN + 1) + ModifyTab._hex_byte_col(byte_idx)

    # ------------------------------------------------------------------
    # Hex view
    # ------------------------------------------------------------------
    def _refresh_hex(self):
        if not self._source_file:
            self.offset_view.clear()
            self.hex_view.setPlainText(
                "Select a target above to inspect its bytes.\n\n"
                "Use the loaded source, choose a file from Contents, or browse your computer."
            )
            self.text_view.clear()
            self.page_label.setText("Page —")
            self.hex_status.setText("")
            return
        total_pages = max(1, (self._file_size + PAGE_SIZE - 1) // PAGE_SIZE)
        self._page = max(0, min(self._page, total_pages - 1))
        base = self._page * PAGE_SIZE
        data = self._read_at(base, PAGE_SIZE)
        row_count = max(1, (len(data) + HEX_ROWS - 1) // HEX_ROWS)
        rows = [data[i * HEX_ROWS:(i + 1) * HEX_ROWS] for i in range(row_count)]
        self.offset_view.setPlainText(
            "\n".join(f"{base + i * HEX_ROWS:08X}" for i in range(row_count))
        )
        self.hex_view.setPlainText("\n".join(format_hex_bytes(row) for row in rows))
        self.text_view.setPlainText("\n".join(format_text_bytes(row) for row in rows))
        self._update_highlights()
        self._update_status_strip()

    def _goto_page(self, page):
        if not self._source_file:
            return
        self._search_range = None
        self._search_note = ""
        total_pages = max(1, (self._file_size + PAGE_SIZE - 1) // PAGE_SIZE)
        self._page = max(0, min(page, total_pages - 1))
        self._refresh_hex()

    def _go_to_offset(self):
        if not self._source_file:
            return
        text = self.go_entry.text().strip()
        if not text:
            return
        try:
            if self.dec_check.isChecked():
                off = int(text, 10)
            else:
                off = int(text, 16) if not text.lower().startswith("0x") else int(text, 16)
        except ValueError:
            QMessageBox.warning(self, "Offset", "Invalid offset.")
            return
        if not (0 <= off < self._file_size):
            QMessageBox.warning(self, "Offset",
                                f"Offset out of range (file size 0x{self._file_size:X}).")
            return
        self._search_range = None
        self._search_note = ""
        self._page = off // PAGE_SIZE
        self._cursor_offset = off
        self._refresh_hex()
        self._move_cursor_to(off)

    def _move_cursor_to(self, off, focus="hex"):
        if not self._source_file:
            return
        base = self._page * PAGE_SIZE
        if not (base <= off < base + PAGE_SIZE):
            return
        rel = off - base
        line, byte_idx = divmod(rel, HEX_ROWS)
        self._cursor_syncing = True
        try:
            for pane, kind in ((self.hex_view, "hex"), (self.text_view, "text")):
                cursor = pane.textCursor()
                cursor.setPosition(self._pane_pos_of_byte(line, byte_idx, kind))
                pane.setTextCursor(cursor)
                pane.ensureCursorVisible()
        finally:
            self._cursor_syncing = False
        (self.text_view if focus == "text" else self.hex_view).setFocus()
        self._update_highlights()
        self._update_inspector()
        self._update_status_strip()

    # ── Find ──────────────────────────────────────────────────────────
    def _find_next(self):
        if not self._source_file:
            return
        mode = self.find_mode.currentData()
        try:
            pattern = encode_search_query(self.find_entry.text(), mode)
        except ValueError as exc:
            QMessageBox.warning(self, "Search", str(exc))
            return
        if not pattern:
            return
        start = self._search_range[1] if self._search_range else (self._cursor_offset or 0)
        case_sensitive = mode == "hex" or self.find_case.isChecked()
        found = self._search_file(pattern, start, self._file_size, case_sensitive)
        wrapped = False
        if found is None and start > 0:
            found = self._search_file(pattern, 0, start, case_sensitive)
            wrapped = found is not None
        if found is None:
            self._search_note = "No matches"
            self._update_status_strip()
            QMessageBox.information(self, "Search", "No matching bytes were found.")
            return
        self._search_range = (found, found + len(pattern))
        self._page = found // PAGE_SIZE
        self._cursor_offset = found
        self._sel_range = None
        self._search_note = (
            f"Match at 0x{found:08X}" + (" · wrapped to start" if wrapped else "")
        )
        self._refresh_hex()
        self._move_cursor_to(found, "text" if mode == "text" else "hex")

    def _search_file(self, pattern, start, stop, case_sensitive=True):
        """Streaming byte search bounded to [start, stop)."""
        if start >= stop:
            return None
        needle = pattern if case_sensitive else pattern.lower()
        chunk_size = 1 << 20
        overlap = max(0, len(pattern) - 1)
        tail = b""
        read_offset = start
        with open(self._read_path(), "rb") as stream:
            stream.seek(start)
            while read_offset < stop:
                block = stream.read(min(chunk_size, stop - read_offset))
                if not block:
                    break
                haystack = tail + block
                searchable = haystack if case_sensitive else haystack.lower()
                index = searchable.find(needle)
                if index >= 0:
                    absolute = read_offset - len(tail) + index
                    if absolute + len(pattern) <= stop:
                        return absolute
                tail = haystack[-overlap:] if overlap else b""
                read_offset += len(block)
        return None

    # ── Cursore / selezione ───────────────────────────────────────────
    def _on_hex_cursor_moved(self):
        self._on_pane_cursor_moved(self.hex_view, "hex")

    def _on_text_cursor_moved(self):
        self._on_pane_cursor_moved(self.text_view, "text")

    def _on_pane_cursor_moved(self, pane, kind):
        if self._cursor_syncing:
            return
        cursor = pane.textCursor()
        offset = self._pane_offset_at_pos(pane, cursor.position(), kind, loose=True)
        if offset is None:
            return
        self._cursor_offset = offset
        if not cursor.hasSelection():
            self._sel_range = None
        self._search_note = ""
        self._cursor_syncing = True
        try:
            rel = offset - self._page * PAGE_SIZE
            line, byte_idx = divmod(rel, HEX_ROWS)
            other, other_kind = ((self.text_view, "text") if kind == "hex"
                                 else (self.hex_view, "hex"))
            other_cursor = other.textCursor()
            other_cursor.setPosition(self._pane_pos_of_byte(line, byte_idx, other_kind))
            other.setTextCursor(other_cursor)
        finally:
            self._cursor_syncing = False
        self._update_highlights()
        self._update_inspector()
        self._update_status_strip()

    def _on_selection_changed(self, pane, kind):
        if self._cursor_syncing:
            return
        cursor = pane.textCursor()
        if cursor.hasSelection():
            first = self._pane_offset_at_pos(pane, cursor.selectionStart(), kind, loose=True)
            last = self._pane_offset_at_pos(
                pane, max(cursor.selectionStart(), cursor.selectionEnd() - 1), kind, loose=True
            )
            if first is not None and last is not None:
                self._sel_range = (min(first, last), max(first, last) + 1)
        else:
            self._sel_range = None
        self._update_highlights()
        self._update_status_strip()

    def _selected_bytes(self):
        return self._sel_range[1] - self._sel_range[0] if self._sel_range else 0

    # ── Evidenziazioni ────────────────────────────────────────────────
    def _update_highlights(self):
        if not self._source_file:
            self.hex_view.setExtraSelections([])
            self.text_view.setExtraSelections([])
            return
        base = self._page * PAGE_SIZE
        selections = {"hex": [], "text": []}

        def add_selection(kind, off, length, text_format):
            rel = off - base
            if not (0 <= rel < PAGE_SIZE):
                return
            line, byte_idx = divmod(rel, HEX_ROWS)
            pane = self.text_view if kind == "text" else self.hex_view
            pos = self._pane_pos_of_byte(line, byte_idx, kind)
            selection = QTextEdit.ExtraSelection()
            selection.cursor = QTextCursor(pane.document())
            selection.cursor.setPosition(pos)
            selection.cursor.setPosition(pos + length, QTextCursor.KeepAnchor)
            selection.format = text_format
            selections[kind].append(selection)

        modified_format = QTextCharFormat()
        modified_format.setForeground(QColor("#ef4444"))
        modified_format.setFontWeight(QFont.Bold)
        for off, data in self._pending.items():
            for k in range(len(data)):
                add_selection("hex", off + k, 2, modified_format)
                add_selection("text", off + k, 1, modified_format)

        if self._cursor_offset is not None and base <= self._cursor_offset < base + PAGE_SIZE:
            cursor_format = QTextCharFormat()
            cursor_format.setBackground(QColor(59, 130, 246, 70))
            add_selection("hex", self._cursor_offset, 2, cursor_format)
            add_selection("text", self._cursor_offset, 1, cursor_format)

        if self._sel_range:
            selection_format = QTextCharFormat()
            selection_format.setBackground(QColor(59, 130, 246, 105))
            for off in range(*self._sel_range):
                add_selection("hex", off, 2, selection_format)
                add_selection("text", off, 1, selection_format)

        if self._search_range:
            find_format = QTextCharFormat()
            find_format.setBackground(QColor(250, 204, 21, 120))
            s, e = self._search_range
            for off in range(s, e):
                add_selection("hex", off, 2, find_format)
                add_selection("text", off, 1, find_format)

        self.hex_view.setExtraSelections(selections["hex"])
        self.text_view.setExtraSelections(selections["text"])

    # ── Status strip ──────────────────────────────────────────────────
    def _update_status_strip(self):
        if not self._source_file:
            self.hex_status.setText("")
            return
        total_pages = max(1, (self._file_size + PAGE_SIZE - 1) // PAGE_SIZE)
        self.page_label.setText(f"Page {self._page + 1} of {total_pages}")
        cursor_txt = "—"
        if self._cursor_offset is not None and 0 <= self._cursor_offset < self._file_size:
            cursor_txt = f"0x{self._cursor_offset:08X} ({self._cursor_offset})"
        selected = self._selected_bytes()
        sel_txt = f"{selected} bytes" if selected else "0 bytes"
        if selected and self._sel_range:
            sel_txt += f" (0x{self._sel_range[0]:08X}–0x{self._sel_range[1] - 1:08X})"
        base = self._page * PAGE_SIZE
        search_txt = f"   |   <b>Search:</b> {self._search_note}" if self._search_note else ""
        self.hex_status.setText(
            f"<b>Cursor:</b> {cursor_txt}   |   <b>Selected:</b> {sel_txt}   |   "
            f"<b>Page:</b> {self._page + 1}/{total_pages} (0x{base:08X})   |   "
            f"<b>File:</b> {self._file_size:,} bytes (0x{self._file_size:X})"
            f"{search_txt}"
        )

    # ── Data Inspector ────────────────────────────────────────────────
    def _update_inspector(self):
        if not self._source_file or self._cursor_offset is None:
            self.ins_offset.setText("Offset: —")
            for label in self.inspector_labels.values():
                label.setText("—")
            return
        off = self._cursor_offset
        self.ins_offset.setText(f"Offset: 0x{off:08X} ({off})")
        data = self._read_at(off, 8)
        if len(data) < 1:
            for label in self.inspector_labels.values():
                label.setText("—")
            return

        def u(n, be=False):
            return int.from_bytes(data[:n], "big" if be else "little") if len(data) >= n else None

        def s(n, be=False):
            v = u(n, be)
            if v is None:
                return None
            return v - (1 << (8 * n)) if v & (1 << (8 * n - 1)) else v

        def fl(fmt):
            try:
                return struct.unpack(fmt, data[:4 if fmt.endswith("f") else 8])[0]
            except struct.error:
                return None

        def fmt_int(v, width):
            return "—" if v is None else f"{v} (0x{v:0{width}X})"

        self.inspector_labels["u8"].setText(fmt_int(u(1), 2))
        self.inspector_labels["s8"].setText("—" if s(1) is None else str(s(1)))
        self.inspector_labels["u16_le"].setText(fmt_int(u(2), 4))
        self.inspector_labels["u16_be"].setText(fmt_int(u(2, True), 4))
        self.inspector_labels["u32_le"].setText(fmt_int(u(4), 8))
        self.inspector_labels["u32_be"].setText(fmt_int(u(4, True), 8))
        self.inspector_labels["u64_le"].setText(fmt_int(u(8), 16))
        self.inspector_labels["u64_be"].setText(fmt_int(u(8, True), 16))
        f32 = fl("<f")
        self.inspector_labels["f32"].setText("—" if f32 is None else f"{f32:.6g}")
        f64 = fl("<d")
        self.inspector_labels["f64"].setText("—" if f64 is None else f"{f64:.6g}")
        ascii_txt = "".join(chr(b) if 32 <= b <= 126 else "·" for b in data)
        self.inspector_labels["ascii"].setText(ascii_txt)

    # ------------------------------------------------------------------
    # Staging edits
    # ------------------------------------------------------------------
    def _use_cursor_offset(self):
        if self._cursor_offset is None:
            QMessageBox.information(
                self, "Edit", "Click a byte in the Hex Viewer first."
            )
            return
        self.offset_entry.setText(f"{self._cursor_offset:X}")

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
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setFont(self._mono_font())
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
            f"Target: {self._source_label} — edits are staged and "
            f"written to a {where}, never the original."
        )
        self.status_label.setToolTip(self._source_file)
