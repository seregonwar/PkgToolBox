"""Overview workspace for package images, publishing projects, and files."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGroupBox,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from GUI.utils import FileUtils
from .base_tab import BaseTab


class InfoTab(BaseTab):
    """A task-oriented landing page for the currently loaded source."""

    def setup_ui(self):
        hero = QFrame()
        hero.setObjectName("overviewHero")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(18, 16, 18, 16)
        self.title_label = QLabel("Open a package, publishing project or file")
        self.title_label.setObjectName("overviewTitle")
        self.title_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.subtitle_label = QLabel(
            "Inspect metadata, browse mapped files and continue with the right tool from one workspace."
        )
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setObjectName("overviewSubtitle")
        hero_layout.addWidget(self.title_label)
        hero_layout.addWidget(self.subtitle_label)
        self.layout.addWidget(hero)

        summary_layout = QHBoxLayout()
        summary_layout.setSpacing(10)
        self.summary_labels = {}
        for key, caption in (
            ("kind", "SOURCE"),
            ("platform", "PLATFORM"),
            ("files", "FILES"),
            ("status", "STATUS"),
        ):
            card = QFrame()
            card.setObjectName("summaryCard")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(14, 10, 14, 10)
            label = QLabel(caption)
            label.setObjectName("summaryCaption")
            value = QLabel("—")
            value.setObjectName("summaryValue")
            value.setWordWrap(True)
            card_layout.addWidget(label)
            card_layout.addWidget(value)
            summary_layout.addWidget(card, 1)
            self.summary_labels[key] = value
        self.layout.addLayout(summary_layout)

        actions = QHBoxLayout()
        self.contents_btn = QPushButton("Browse contents")
        self.contents_btn.clicked.connect(
            lambda: self.parent_window.show_section(self.parent_window.contents_workspace)
        )
        self.inspect_btn = QPushButton("Inspect or edit")
        self.inspect_btn.clicked.connect(
            lambda: self.parent_window.show_section(self.parent_window.modify_tab)
        )
        self.tools_btn = QPushButton("Open tools")
        self.tools_btn.clicked.connect(
            lambda: self.parent_window.show_section(self.parent_window.tools_workspace)
        )
        for button in (self.contents_btn, self.inspect_btn, self.tools_btn):
            button.setEnabled(False)
            actions.addWidget(button)
        actions.addStretch(1)
        self.layout.addLayout(actions)

        self.warning_label = QLabel()
        self.warning_label.setObjectName("sourceWarnings")
        self.warning_label.setWordWrap(True)
        self.warning_label.hide()
        self.layout.addWidget(self.warning_label)

        info_group = QGroupBox("Technical details")
        info_group.setObjectName("technicalGroup")
        info_layout = QVBoxLayout(info_group)
        self.info_table = QTableWidget(0, 2)
        self.info_table.setObjectName("technicalTable")
        self.info_table.setHorizontalHeaderLabels(["Field", "Value"])
        self.info_table.verticalHeader().hide()
        self.info_table.setShowGrid(False)
        self.info_table.setAlternatingRowColors(False)
        self.info_table.setWordWrap(False)
        self.info_table.setSelectionMode(QAbstractItemView.NoSelection)
        self.info_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.info_table.setFocusPolicy(Qt.NoFocus)
        self.info_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.info_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.info_table.verticalHeader().setDefaultSectionSize(32)
        info_layout.addWidget(self.info_table)
        # Compatibility for the handful of callers that still refer to the
        # old metadata widget by name.
        self.info_tree = self.info_table
        self.layout.addWidget(info_group, 1)

    def clear_source(self):
        self.title_label.setText("Open a package, publishing project or file")
        self.subtitle_label.setText(
            "Inspect metadata, browse mapped files and continue with the right tool from one workspace."
        )
        for label in self.summary_labels.values():
            label.setText("—")
        for button in (self.contents_btn, self.inspect_btn, self.tools_btn):
            button.setEnabled(False)
        self.warning_label.clear()
        self.warning_label.hide()
        self.info_table.clearContents()
        self.info_table.setRowCount(0)

    def update_source(self, source):
        """Refresh the human-readable summary after a source is loaded."""
        info = source.get_info()
        source_type = str(info.get("source_type") or "")
        is_project = source_type.endswith("Project")
        is_file = source_type == "Standalone File"
        title = (
            info.get("title_name") or info.get("title_id") or
            info.get("content_id") or info.get("file_name")
        )
        self.title_label.setText(str(title or "Loaded source"))
        self.subtitle_label.setText(
            f"{info.get('project_format', 'Publishing')} project — mapped paths are resolved and remain read-only."
            if is_project else
            "Standalone file — preview, inspect or stage edits without creating a package workspace."
            if is_file else
            "Package image — metadata and available plaintext content are ready to inspect."
        )
        self.summary_labels["kind"].setText(source_type or type(source).__name__)
        self.summary_labels["platform"].setText(str(info.get("platform") or self._infer_platform(source)))
        file_count = info.get("file_count", info.get("pkg_file_count", len(getattr(source, "files", {}))))
        total_size = info.get("total_size", info.get("pkg_size"))
        files_text = f"{file_count}"
        if isinstance(total_size, int):
            files_text += f" · {FileUtils.format_size(total_size)}"
        self.summary_labels["files"].setText(files_text)
        warnings = list(getattr(source, "warnings", []))
        self.summary_labels["status"].setText("Ready" if not warnings else f"{len(warnings)} warning(s)")
        if warnings:
            preview = "\n".join(f"• {warning}" for warning in warnings[:4])
            if len(warnings) > 4:
                preview += f"\n• …and {len(warnings) - 4} more"
            self.warning_label.setText(preview)
            self.warning_label.show()
        else:
            self.warning_label.hide()
        for button in (self.contents_btn, self.inspect_btn, self.tools_btn):
            button.setEnabled(True)

    @staticmethod
    def _infer_platform(source):
        name = type(source).__name__.lower()
        for platform in ("ps5", "ps4", "ps3"):
            if platform in name:
                return platform.upper()
        return "PlayStation"

    def update_info(self, info_dict):
        """Populate technical metadata without making it the primary workflow."""
        self.info_table.clearContents()
        self.info_table.setRowCount(0)
        descriptions = {
            "source_type": "Type of workspace source",
            "project_layout": "Publishing-project file mapping style",
            "volume_type": "Prospero publishing volume type",
            "available_files": "Mapped source files found on disk",
            "missing_files": "Mapped source files that could not be resolved",
            "validation": "Project consistency summary",
            "pkg_magic": "Magic number identifying the PKG format",
            "pkg_type": "Package container type",
            "pkg_file_count": "Number of files contained in the package",
            "pkg_entry_count": "Number of entries in the package table",
            "pkg_body_size": "Size of the package body",
            "pkg_content_id": "Unique identifier for the package content",
            "title_id": "Title identifier",
            "system_version": "Minimum required system version",
            "app_version": "Application version",
            "total_size": "Combined size of mapped content",
            "pkg_size": "Package image size",
            "content_id": "Content identifier",
            "passcode": "Whether the project declares a passcode; its value is never displayed",
        }
        groups = {
            "Identity": {
                "source_type", "platform", "project_format", "project_version", "project_layout",
                "volume_type", "pkg_type", "content_id", "pkg_content_id", "title_id",
                "title_name", "region",
            },
            "Version & content": {
                "app_version", "version", "content_version", "master_version", "category",
                "creation_date", "system_version", "required_system_software_version",
                "pkg_content_type", "content_type", "chunk_count", "scenario_count",
            },
            "Files & layout": {
                "file_count", "available_files", "missing_files", "total_size", "pkg_size",
                "pkg_magic", "pkg_revision", "pkg_file_count", "pkg_entry_count",
                "pkg_sc_entry_count", "pkg_table_offset", "pkg_body_offset", "pkg_body_size",
                "pfs_state", "pfs_image_offset", "pfs_image_size", "pfs_image_flags",
                "pfs_cache_size", "fih_offset", "fih_size", "sc_offset", "sc_size",
                "si_offset", "si_size",
            },
            "Security & validation": {
                "validation", "passcode", "pkg_drm_type", "drm_type", "application_drm_type",
                "pkg_content_flags", "content_flags", "encrypted_entries", "package_digest",
                "pfs_area_digest", "pfs_image_digest", "pfs_signed_digest",
            },
        }
        rows = []
        assigned = set()
        for group_name, keys in groups.items():
            available = [
                (key, info_dict[key]) for key in info_dict
                if key in keys and info_dict[key] not in (None, "None", "")
            ]
            if not available:
                continue
            rows.append(("section", group_name, "", ""))
            for key, value in available:
                display = FileUtils.format_size(value) if key.endswith("size") and isinstance(value, int) else str(value)
                rows.append(("value", key, display, descriptions.get(key, "")))
                assigned.add(key)
        remaining = [
            (key, value) for key, value in info_dict.items()
            if key not in assigned and value not in (None, "None", "")
        ]
        if remaining:
            rows.append(("section", "Additional metadata", "", ""))
            for key, value in remaining:
                rows.append(("value", key, str(value), descriptions.get(key, "")))

        self.info_table.setRowCount(len(rows))
        for row, (kind, key, value, description) in enumerate(rows):
            if kind == "section":
                item = QTableWidgetItem(key.upper())
                font = item.font()
                font.setBold(True)
                item.setFont(font)
                item.setFlags(Qt.ItemIsEnabled)
                self.info_table.setItem(row, 0, item)
                self.info_table.setSpan(row, 0, 1, 2)
                self.info_table.setRowHeight(row, 34)
                continue
            label = str(key).replace("_", " ").strip().title()
            key_item = QTableWidgetItem(label)
            value_item = QTableWidgetItem(value)
            tooltip = description or f"Raw field: {key}"
            key_item.setToolTip(tooltip)
            value_item.setToolTip(f"{tooltip}\n\n{value}")
            self.info_table.setItem(row, 0, key_item)
            self.info_table.setItem(row, 1, value_item)
