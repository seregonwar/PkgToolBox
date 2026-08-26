"""Guided TRP archive builder."""
import os
import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QComboBox,
    QStackedWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from GUI.utils import FileUtils
from Utilities.Trophy import TRPCreator


TRP_NAME_PATTERNS = (
    re.compile(r"^TROPCONF\.(?:E?SFM)$", re.IGNORECASE),
    re.compile(r"^TROP(?:_\d+)?\.(?:E?SFM)$", re.IGNORECASE),
    re.compile(r"^ICON0(?:_\d+)?\.PNG$", re.IGNORECASE),
    re.compile(r"^GR\d+(?:_\d+)?\.PNG$", re.IGNORECASE),
    re.compile(r"^TROP\d+\.PNG$", re.IGNORECASE),
)


def trp_asset_role(filename):
    """Return the archive role for a recognized TRP asset name."""
    name = os.path.basename(filename).upper()
    if not any(pattern.fullmatch(name) for pattern in TRP_NAME_PATTERNS):
        return None
    if name.endswith((".SFM", ".ESFM")):
        return "Configuration"
    if name.startswith("ICON0"):
        return "Set icon"
    if name.startswith("GR"):
        return "Grade artwork"
    return "Trophy artwork"


def validate_trp_assets(paths):
    """Validate the minimum inputs required for a useful TRP archive."""
    errors = []
    names = [os.path.basename(path) for path in paths]
    folded = [name.casefold() for name in names]
    duplicates = sorted({name for name in folded if folded.count(name) > 1})
    if duplicates:
        errors.append("Duplicate archive names: " + ", ".join(duplicates))
    unsupported = [name for name in names if trp_asset_role(name) is None]
    if unsupported:
        errors.append("Unsupported names: " + ", ".join(unsupported))
    if not any(name.upper().endswith((".SFM", ".ESFM")) for name in names):
        errors.append("Add a trophy configuration file (TROPCONF.SFM/ESFM or TROP.SFM/ESFM).")
    if not any(name.upper().endswith(".PNG") for name in names):
        errors.append("Add at least one PNG artwork file.")
    return errors


class TrpCreatorTab(QWidget):
    """Three-step workflow that validates inputs before creating a TRP."""

    def __init__(self, parent_window):
        super().__init__(parent_window)
        self.parent_window = parent_window
        self._step = 0
        self._build_ui()
        self._set_step(0)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        hero = QFrame()
        hero.setObjectName("trpHero")
        hero_layout = QVBoxLayout(hero)
        title = QLabel("Create a TRP archive")
        title.setObjectName("trpTitle")
        copy = QLabel(
            "A guided build: choose the archive version, add a valid trophy configuration "
            "and its artwork, then review exactly what will be written."
        )
        copy.setObjectName("trpSubtitle")
        copy.setWordWrap(True)
        hero_layout.addWidget(title)
        hero_layout.addWidget(copy)
        layout.addWidget(hero)

        rail = QHBoxLayout()
        self.step_labels = []
        for number, text in enumerate(("1  Format", "2  Trophy files", "3  Review & create")):
            label = QLabel(text)
            label.setObjectName("trpStep")
            label.setAlignment(Qt.AlignCenter)
            self.step_labels.append(label)
            rail.addWidget(label, 1)
        layout.addLayout(rail)

        self.pages = QStackedWidget()
        self.pages.setObjectName("trpWizard")
        self.pages.addWidget(self._build_format_step())
        self.pages.addWidget(self._build_files_step())
        self.pages.addWidget(self._build_review_step())
        layout.addWidget(self.pages, 1)

        nav = QHBoxLayout()
        self.validation_label = QLabel("")
        self.validation_label.setObjectName("trpValidation")
        self.validation_label.setWordWrap(True)
        self.back_button = QPushButton("Back")
        self.back_button.setObjectName("secondaryButton")
        self.back_button.clicked.connect(lambda: self._set_step(self._step - 1))
        self.next_button = QPushButton("Continue")
        self.next_button.clicked.connect(self._next_step)
        nav.addWidget(self.validation_label, 1)
        nav.addWidget(self.back_button)
        nav.addWidget(self.next_button)
        layout.addLayout(nav)

    def _build_format_step(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        group = QGroupBox("Archive format")
        content = QVBoxLayout(group)
        row = QHBoxLayout()
        row.addWidget(QLabel("TRP version"))
        self.version_combo = QComboBox()
        self.version_combo.addItem("Version 1 · legacy", 1)
        self.version_combo.addItem("Version 2 · SHA-1", 2)
        self.version_combo.addItem("Version 3 · extended header", 3)
        self.version_combo.setCurrentIndex(1)
        row.addWidget(self.version_combo)
        row.addStretch(1)
        content.addLayout(row)
        explanation = QLabel(
            "The title, NPCommID and trophy definitions belong in the SFM/ESFM configuration "
            "inside the archive. This builder does not ask for values it cannot safely encode."
        )
        explanation.setObjectName("trpHint")
        explanation.setWordWrap(True)
        content.addWidget(explanation)
        layout.addWidget(group)

        checklist = QGroupBox("What you will need")
        checklist_layout = QVBoxLayout(checklist)
        for line in (
            "1. A configuration such as TROPCONF.SFM, TROPCONF.ESFM, TROP.SFM or TROP.ESFM.",
            "2. PNG assets named ICON0.PNG, GRxx.PNG or TROPxx.PNG.",
            "3. A destination for the finished .trp file.",
        ):
            checklist_layout.addWidget(QLabel(line))
        layout.addWidget(checklist)
        layout.addStretch(1)
        return page

    def _build_files_step(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        header = QLabel("Add the files that belong inside the archive")
        header.setObjectName("trpSectionTitle")
        layout.addWidget(header)
        hint = QLabel(
            "Names are validated as you add them. Archive order is determined automatically; "
            "JPEG files are not accepted because TRP artwork is stored as PNG."
        )
        hint.setObjectName("trpHint")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.files_list = QTreeWidget()
        self.files_list.setObjectName("trpFiles")
        self.files_list.setHeaderLabels(["Archive name", "Role", "Size", "Status"])
        self.files_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        header_view = self.files_list.header()
        header_view.setSectionResizeMode(0, QHeaderView.Stretch)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        layout.addWidget(self.files_list, 1)

        buttons = QHBoxLayout()
        add_files = QPushButton("Add files…")
        add_files.clicked.connect(self.add_files)
        add_folder = QPushButton("Add folder…")
        add_folder.setObjectName("secondaryButton")
        add_folder.clicked.connect(self.add_folder)
        from_contents = QPushButton("From contents")
        from_contents.setObjectName("secondaryButton")
        from_contents.clicked.connect(self.add_from_contents)
        remove = QPushButton("Remove selected")
        remove.setObjectName("secondaryButton")
        remove.clicked.connect(self.remove_selected)
        clear = QPushButton("Clear")
        clear.setObjectName("secondaryButton")
        clear.clicked.connect(self.clear_files)
        buttons.addWidget(add_files)
        buttons.addWidget(add_folder)
        buttons.addWidget(from_contents)
        buttons.addStretch(1)
        buttons.addWidget(remove)
        buttons.addWidget(clear)
        layout.addLayout(buttons)
        return page

    def _build_review_step(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        summary_group = QGroupBox("Build summary")
        summary = QVBoxLayout(summary_group)
        self.summary_label = QLabel()
        self.summary_label.setObjectName("trpSummary")
        self.summary_label.setWordWrap(True)
        summary.addWidget(self.summary_label)
        layout.addWidget(summary_group)

        output_group = QGroupBox("Destination")
        output = QHBoxLayout(output_group)
        self.output_entry = QLineEdit()
        self.output_entry.setPlaceholderText("Choose where to save the TRP archive")
        browse = QPushButton("Choose…")
        browse.setObjectName("secondaryButton")
        browse.clicked.connect(self.choose_output)
        output.addWidget(self.output_entry, 1)
        output.addWidget(browse)
        layout.addWidget(output_group)

        self.create_button = QPushButton("Create TRP")
        self.create_button.clicked.connect(self.create_archive)
        layout.addWidget(self.create_button, alignment=Qt.AlignLeft)
        self.log = QTextEdit()
        self.log.setObjectName("trpLog")
        self.log.setReadOnly(True)
        self.log.setPlaceholderText("Build messages will appear here.")
        layout.addWidget(self.log, 1)
        return page

    def _paths(self):
        return [
            self.files_list.topLevelItem(i).data(0, Qt.UserRole)
            for i in range(self.files_list.topLevelItemCount())
        ]

    def _set_step(self, step):
        self._step = max(0, min(step, self.pages.count() - 1))
        self.pages.setCurrentIndex(self._step)
        self.back_button.setVisible(self._step > 0)
        self.next_button.setVisible(self._step < self.pages.count() - 1)
        for index, label in enumerate(self.step_labels):
            label.setProperty("state", "active" if index == self._step else
                              ("done" if index < self._step else "pending"))
            label.style().unpolish(label)
            label.style().polish(label)
        self._refresh_validation()
        if self._step == 2:
            self._refresh_summary()

    def _next_step(self):
        if self._step == 1:
            errors = validate_trp_assets(self._paths())
            if errors:
                QMessageBox.warning(self, "Trophy files", "\n".join(errors))
                self._refresh_validation()
                return
        self._set_step(self._step + 1)

    def _refresh_validation(self):
        if self._step != 1:
            self.validation_label.clear()
            return
        errors = validate_trp_assets(self._paths())
        if errors:
            self.validation_label.setText("Next required: " + errors[0])
            self.validation_label.setProperty("valid", False)
        else:
            self.validation_label.setText("Ready to review · all required file types are present")
            self.validation_label.setProperty("valid", True)
        self.validation_label.style().unpolish(self.validation_label)
        self.validation_label.style().polish(self.validation_label)

    def _add_path(self, path):
        path = os.path.abspath(path)
        name = os.path.basename(path)
        role = trp_asset_role(name)
        if role is None:
            return f"{name}: unsupported TRP filename"
        existing = {os.path.basename(item).casefold() for item in self._paths()}
        if name.casefold() in existing:
            return f"{name}: already added"
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            return f"{name}: {exc}"
        item = QTreeWidgetItem(self.files_list)
        item.setText(0, name)
        item.setText(1, role)
        item.setText(2, FileUtils.format_size(size))
        item.setText(3, "Ready")
        item.setData(0, Qt.UserRole, path)
        return None

    def _add_paths(self, paths):
        rejected = [message for path in paths if (message := self._add_path(path))]
        self._refresh_validation()
        if rejected:
            QMessageBox.information(
                self, "Some files were not added", "\n".join(rejected[:12])
            )

    def add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Add trophy configuration and artwork",
            "",
            "TRP assets (*.sfm *.esfm *.png);;All files (*.*)",
        )
        if paths:
            self._add_paths(paths)

    def add_folder(self):
        directory = QFileDialog.getExistingDirectory(self, "Add a trophy asset folder")
        if not directory:
            return
        paths = []
        for root, _, files in os.walk(directory):
            paths.extend(os.path.join(root, name) for name in files if trp_asset_role(name))
        self._add_paths(paths)

    def add_from_contents(self):
        infos = self.parent_window._pick_pkg_file(
            file_filter=[".png", ".sfm", ".esfm"],
            multi=True,
            title="Select trophy files from the loaded source",
        )
        paths = [self.parent_window._extract_pkg_file(info, subdir="trp_src") for info in infos]
        self._add_paths(paths)

    def remove_selected(self):
        for item in self.files_list.selectedItems():
            index = self.files_list.indexOfTopLevelItem(item)
            if index >= 0:
                self.files_list.takeTopLevelItem(index)
        self._refresh_validation()

    def clear_files(self):
        self.files_list.clear()
        self._refresh_validation()

    def _refresh_summary(self):
        paths = self._paths()
        configs = sum(path.upper().endswith((".SFM", ".ESFM")) for path in paths)
        artwork = sum(path.upper().endswith(".PNG") for path in paths)
        total = sum(os.path.getsize(path) for path in paths)
        version = self.version_combo.currentData()
        self.summary_label.setText(
            f"<b>TRP version {version}</b><br>"
            f"{len(paths)} files · {configs} configuration · {artwork} PNG assets · "
            f"{FileUtils.format_size(total)} before archive alignment.<br><br>"
            "The source files are read-only inputs. The builder writes a new archive at the destination below."
        )

    def choose_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save TRP archive", "", "TRP files (*.trp)")
        if path:
            if not path.lower().endswith(".trp"):
                path += ".trp"
            self.output_entry.setText(path)

    def create_archive(self):
        errors = validate_trp_assets(self._paths())
        if errors:
            QMessageBox.warning(self, "Cannot create TRP", "\n".join(errors))
            self._set_step(1)
            return
        output_path = self.output_entry.text().strip()
        if not output_path:
            self.choose_output()
            output_path = self.output_entry.text().strip()
        if not output_path:
            return
        if not output_path.lower().endswith(".trp"):
            output_path += ".trp"
            self.output_entry.setText(output_path)
        try:
            creator = TRPCreator()
            creator.SetVersion = self.version_combo.currentData()
            creator.Create(output_path, self._paths())
            if not os.path.isfile(output_path) or os.path.getsize(output_path) < 64:
                raise ValueError("The archive was not written correctly.")
            self.log.append(f"Created {output_path} ({FileUtils.format_size(os.path.getsize(output_path))})")
            QMessageBox.information(self, "TRP created", f"Archive created successfully:\n{output_path}")
        except Exception as exc:
            self.log.append(f"Build failed: {exc}")
            QMessageBox.critical(self, "TRP creation failed", str(exc))
