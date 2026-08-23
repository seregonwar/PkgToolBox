"""Dialog per selezionare un file tra quelli contenuti nel PKG caricato."""
import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout)

from GUI.utils import FileUtils


class PkgFilePickerDialog(QDialog):
    """Elenca i file del PKG caricato e ritorna i file_info selezionati.

    Args:
        package: il package caricato (espone ``files`` e ``read_file``).
        file_filter: lista di estensioni (es. ['.trp', '.ucp']); None = tutti i file.
        multi: abilita la selezione multipla.
    """

    def __init__(self, package, parent=None, file_filter=None, multi=False,
                 title="Select a file from the loaded PKG"):
        super().__init__(parent)
        self.package = package
        self.file_filter = [
            f if f.startswith(".") else f".{f}" for f in (file_filter or [])
        ]
        self.setWindowTitle(title)
        self.resize(720, 520)
        self._build_ui(multi)

    def _build_ui(self, multi):
        layout = QVBoxLayout(self)

        self.search = QLineEdit()
        self.search.setPlaceholderText("🔍 Search files...")
        self.search.textChanged.connect(self._filter)
        layout.addWidget(self.search)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Size", "Type"])
        self.tree.setColumnWidth(0, 380)
        self.tree.setColumnWidth(1, 90)
        self.tree.setColumnWidth(2, 90)
        self.tree.setAlternatingRowColors(True)
        if multi:
            self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tree.itemDoubleClicked.connect(lambda *_: self.accept())
        # Colors (selection, hover) come from the active theme
        layout.addWidget(self.tree)

        self.note = QLabel()
        self.note.setWordWrap(True)
        layout.addWidget(self.note)

        buttons = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        ok_btn = QPushButton("OK")
        cancel_btn.clicked.connect(self.reject)
        ok_btn.clicked.connect(self.accept)
        ok_btn.setDefault(True)
        buttons.addStretch(1)
        buttons.addWidget(cancel_btn)
        buttons.addWidget(ok_btn)
        layout.addLayout(buttons)

        self._populate()

    # ------------------------------------------------------------------
    def _matches_filter(self, name):
        if not self.file_filter:
            return True
        return os.path.splitext(name)[1].lower() in self.file_filter

    def _populate(self):
        self.tree.clear()
        structure = {}
        for info in self.package.files.values():
            name = info.get("name")
            if not name or not self._matches_filter(name):
                continue
            parts = name.split("/")
            cur = structure
            for part in parts[:-1]:
                if part:
                    cur = cur.setdefault(part, {})
            cur[parts[-1]] = info

        matched = self._add_items(self.tree.invisibleRootItem(), structure)
        self.tree.expandAll()

        if not matched:
            self.note.setText(
                "No files of the required type were found in this PKG."
            )
        elif self.file_filter:
            self.note.setText(
                f"{matched} matching file(s) found in the loaded PKG "
                f"({', '.join(self.file_filter)})."
            )
        else:
            self.note.setText(f"{matched} file(s) found in the loaded PKG.")

    def _add_items(self, parent_item, structure):
        count = 0
        for name in sorted(structure.keys()):
            content = structure[name]
            if not isinstance(content, dict) or not content:
                continue  # cartella vuota (dopo il filtro)

            is_dir = any(isinstance(v, dict) for v in content.values())
            item = QTreeWidgetItem(parent_item)
            if is_dir:
                item.setText(0, name + "/")
                item.setIcon(0, FileUtils.get_file_icon("Directory"))
                sub = self._add_items(item, content)
                item.setText(1, FileUtils.format_size(self._dir_size(content)))
                item.setText(2, "Directory")
                count += sub
            else:
                item.setText(0, name)
                item.setText(1, FileUtils.format_size(content.get("size", 0)))
                item.setText(2, FileUtils.get_file_type(os.path.splitext(name)[1]))
                item.setIcon(0, FileUtils.get_file_icon(name))
                item.setData(0, Qt.UserRole, content)
                count += 1
        return count

    def _dir_size(self, node):
        total = 0
        for v in node.values():
            if isinstance(v, dict):
                if any(isinstance(x, dict) for x in v.values()):
                    total += self._dir_size(v)
                else:
                    total += v.get("size", 0)
        return total

    def _filter(self):
        text = self.search.text().lower()

        def walk(item):
            show = not text or text in item.text(0).lower()
            for i in range(item.childCount()):
                child = item.child(i)
                if walk(child):
                    show = True
            item.setHidden(not show)
            return show

        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            walk(root.child(i))

    # ------------------------------------------------------------------
    def selected_infos(self):
        """Ritorna i file_info dei file selezionati (id, name, size, ...)."""
        infos = []
        for item in self.tree.selectedItems():
            info = item.data(0, Qt.UserRole)
            if info:
                infos.append(info)
        return infos
