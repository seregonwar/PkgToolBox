from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QListWidget,
                               QListWidgetItem, QStackedWidget, QWidget, QGroupBox,
                               QGridLayout, QLabel, QComboBox, QSpinBox, QPushButton,
                               QCheckBox, QLineEdit, QFileDialog, QColorDialog,
                               QMessageBox, QApplication, QFrame)
from PySide6.QtGui import QFont, QColor, QFontDatabase, QPixmap
from PySide6.QtCore import Qt

from GUI.utils.style_manager import StyleManager
from GUI.utils.avatar_fetcher import AvatarFetcher


class SettingsDialog(QDialog):
    """Settings dialog with a sidebar of sections, live theme preview and
    Apply/OK/Cancel/Reset buttons.

    Nothing is persisted or applied to the main window until Apply/OK is
    pressed (language changes are applied live, as usual).
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self._current_font = QFont("Arial", 12)
        self._avatar_fetcher = None
        self.setup_ui()
        self.load_settings()
        self._refresh_avatar()

    # ── UI construction ────────────────────────────────────────────────────

    def setup_ui(self):
        self.setWindowTitle("Settings")
        self.setMinimumSize(680, 480)

        root = QVBoxLayout(self)

        body = QHBoxLayout()
        body.setSpacing(12)

        # Left navigation
        self.nav_list = QListWidget()
        self.nav_list.setFixedWidth(150)
        self.nav_list.setObjectName("settingsNav")
        for name in ("Aspetto", "Temi personalizzati", "Comportamento", "Percorsi", "Informazioni"):
            self.nav_list.addItem(QListWidgetItem(name))

        # Pages
        self.pages = QStackedWidget()
        self.pages.addWidget(self._create_appearance_page())
        self.pages.addWidget(self._create_custom_themes_page())
        self.pages.addWidget(self._create_behavior_page())
        self.pages.addWidget(self._create_paths_page())
        self.pages.addWidget(self._create_about_page())

        self.nav_list.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.nav_list.setCurrentRow(0)

        body.addWidget(self.nav_list)
        body.addWidget(self.pages, 1)
        root.addLayout(body)

        # Bottom buttons
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.reset_btn = QPushButton("Reset")
        self.apply_btn = QPushButton("Apply")
        self.ok_btn = QPushButton("OK")
        self.cancel_btn = QPushButton("Cancel")

        self.reset_btn.clicked.connect(self.reset_settings)
        self.apply_btn.clicked.connect(lambda: self._apply_and_save(close=False))
        self.ok_btn.clicked.connect(lambda: self._apply_and_save(close=True))
        self.cancel_btn.clicked.connect(self.reject)

        buttons.addWidget(self.reset_btn)
        buttons.addWidget(self.apply_btn)
        buttons.addWidget(self.ok_btn)
        buttons.addWidget(self.cancel_btn)
        root.addLayout(buttons)

    def _create_appearance_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        # Theme
        theme_group = QGroupBox("Theme")
        theme_layout = QGridLayout()

        theme_layout.addWidget(QLabel("Theme:"), 0, 0)
        self.theme_combo = QComboBox()
        self._refresh_theme_combo()
        self.theme_combo.currentIndexChanged.connect(self._on_theme_changed)
        theme_layout.addWidget(self.theme_combo, 0, 1)

        # Live preview
        self.theme_preview = QFrame()
        self.theme_preview.setFixedHeight(72)
        self.theme_preview.setFrameShape(QFrame.StyledPanel)
        preview_layout = QVBoxLayout(self.theme_preview)
        preview_layout.setContentsMargins(12, 8, 12, 8)
        preview_layout.setSpacing(6)
        self.preview_bg = QLabel("Background")
        self.preview_text = QLabel("Text color")
        self.preview_accent = QLabel("Accent")
        self.preview_accent.setAlignment(Qt.AlignCenter)
        preview_layout.addWidget(self.preview_bg)
        preview_layout.addWidget(self.preview_text)
        preview_layout.addWidget(self.preview_accent)
        theme_layout.addWidget(self.theme_preview, 1, 0, 1, 2)

        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)

        # Language
        language_group = QGroupBox("Language")
        language_layout = QGridLayout()
        language_layout.addWidget(QLabel("Language:"), 0, 0)
        self.language_combo = QComboBox()
        self.language_combo.addItems(["English", "Italian", "Spanish", "French", "German", "Japanese"])
        self.language_combo.currentTextChanged.connect(self.on_language_changed)
        language_layout.addWidget(self.language_combo, 0, 1)
        language_group.setLayout(language_layout)
        layout.addWidget(language_group)

        # Font
        font_group = QGroupBox("Font")
        font_layout = QGridLayout()
        font_layout.addWidget(QLabel("Font:"), 0, 0)
        self.font_combo = QComboBox()
        self.font_combo.addItems(QFontDatabase().families())
        font_layout.addWidget(self.font_combo, 0, 1)
        font_layout.addWidget(QLabel("Size:"), 1, 0)
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 24)
        self.font_size_spin.setValue(12)
        font_layout.addWidget(self.font_size_spin, 1, 1)
        font_group.setLayout(font_layout)
        layout.addWidget(font_group)

        layout.addStretch(1)
        return page

    # ── Custom themes page ───────────────────────────────────────────────────

    COLOR_LABELS = {
        'background': 'Background', 'secondary_bg': 'Secondary BG',
        'text': 'Text', 'secondary_text': 'Secondary Text',
        'accent': 'Accent', 'accent_hover': 'Accent hover',
        'border': 'Border', 'selection': 'Selection', 'hover': 'Hover',
        'error': 'Error', 'success': 'Success', 'warning': 'Warning',
    }

    def _create_custom_themes_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        top = QHBoxLayout()
        top.setSpacing(12)

        # Saved themes list
        list_group = QGroupBox("My Themes")
        list_layout = QVBoxLayout()
        self.ct_list = QListWidget()
        self.ct_list.setMinimumWidth(150)
        self.ct_list.itemSelectionChanged.connect(self._on_ct_selected)
        list_layout.addWidget(self.ct_list)
        self.ct_new_btn = QPushButton("New Theme")
        self.ct_new_btn.clicked.connect(self._new_custom_theme)
        list_layout.addWidget(self.ct_new_btn)
        list_group.setLayout(list_layout)
        top.addWidget(list_group)

        # Editor
        editor = QVBoxLayout()

        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Theme Name:"))
        self.ct_name_edit = QLineEdit()
        self.ct_name_edit.setPlaceholderText("e.g. Midnight Blue")
        name_row.addWidget(self.ct_name_edit, 1)
        editor.addLayout(name_row)

        # Color grid (swatch button + hex label per color key)
        colors_group = QGroupBox("Colors")
        grid = QGridLayout()
        grid.setColumnStretch(2, 1)
        self.ct_color_buttons = {}
        self.ct_color_labels = {}
        for i, key in enumerate(StyleManager.COLOR_KEYS):
            grid.addWidget(QLabel(self.COLOR_LABELS.get(key, key) + ":"), i, 0)
            btn = QPushButton()
            btn.setFixedSize(64, 26)
            btn.setToolTip("Click to pick a color")
            btn.clicked.connect(lambda checked=False, k=key: self._pick_ct_color(k))
            grid.addWidget(btn, i, 1)
            hex_label = QLabel()
            hex_label.setObjectName("ctHexLabel")
            grid.addWidget(hex_label, i, 2)
            self.ct_color_buttons[key] = btn
            self.ct_color_labels[key] = hex_label
        colors_group.setLayout(grid)
        editor.addWidget(colors_group)

        # Live preview — miniaturized mockup of the UI using every theme color
        preview_group = QGroupBox("Preview")
        preview_layout = QVBoxLayout(preview_group)
        self._create_ct_mockup()
        preview_layout.addWidget(self.ct_mockup_root)
        editor.addWidget(preview_group)

        # Action buttons
        actions = QHBoxLayout()
        self.ct_save_btn = QPushButton("Save Theme")
        self.ct_delete_btn = QPushButton("Delete Theme")
        self.ct_save_btn.clicked.connect(self._save_custom_theme)
        self.ct_delete_btn.clicked.connect(self._delete_custom_theme)
        actions.addWidget(self.ct_save_btn)
        actions.addWidget(self.ct_delete_btn)
        actions.addStretch(1)
        editor.addLayout(actions)

        top.addLayout(editor, 1)
        layout.addLayout(top)
        layout.addStretch(1)

        self._refresh_ct_list()
        if not self.ct_list.count():
            # No saved themes yet -> start with a blank editor
            self._new_custom_theme()
        return page

    def _refresh_ct_list(self):
        """Reload the saved themes list and the Appearance theme combo."""
        current = self.ct_list.currentItem().text() if self.ct_list.currentItem() else None
        self.ct_list.clear()
        for name in StyleManager.load_custom_themes():
            self.ct_list.addItem(name)
        if current and self.ct_list.findItems(current, Qt.MatchExactly):
            self.ct_list.setCurrentItem(self.ct_list.findItems(current, Qt.MatchExactly)[0])
        elif self.ct_list.count():
            # Select the first theme so the editor loads its colors
            self.ct_list.setCurrentRow(0)
        self._refresh_theme_combo()

    def _refresh_theme_combo(self):
        """Rebuild the Appearance theme combo from all available themes."""
        current = self.theme_combo.currentData()
        self.theme_combo.blockSignals(True)
        self.theme_combo.clear()
        for theme in StyleManager.get_available_themes():
            self.theme_combo.addItem(StyleManager.display_name(theme), theme)
        idx = self.theme_combo.findData(current)
        self.theme_combo.setCurrentIndex(idx if idx >= 0 else self.theme_combo.findData("Dark"))
        self.theme_combo.blockSignals(False)

    def _on_ct_selected(self):
        item = self.ct_list.currentItem()
        if not item:
            return
        name = item.text()
        theme = StyleManager.load_custom_themes().get(name, {})
        self.ct_name_edit.setText(name)
        for key in StyleManager.COLOR_KEYS:
            color = theme.get(key, StyleManager._COLOR_DEFAULTS.get(key, '#ffffff'))
            self._update_color_button(self.ct_color_buttons[key], color)
            self.ct_color_labels[key].setText(color)
        self._update_ct_preview()

    def _new_custom_theme(self):
        """Reset the editor to default colors and clear the name."""
        self.ct_list.clearSelection()
        self.ct_name_edit.clear()
        for key in StyleManager.COLOR_KEYS:
            color = StyleManager._COLOR_DEFAULTS.get(key, '#ffffff')
            self._update_color_button(self.ct_color_buttons[key], color)
            self.ct_color_labels[key].setText(color)
        self._update_ct_preview()

    def _pick_ct_color(self, key):
        color = QColorDialog.getColor(QColor(self.ct_color_labels[key].text()))
        if not color.isValid():
            return
        hex_color = color.name()
        self._update_color_button(self.ct_color_buttons[key], hex_color)
        self.ct_color_labels[key].setText(hex_color)
        self._update_ct_preview()

    def _create_ct_mockup(self):
        """Builds the miniaturized UI mockup used as the custom-theme preview."""
        self.ct_mockup_root = QWidget()
        root_layout = QVBoxLayout(self.ct_mockup_root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        self.ct_mock_window = QFrame()
        self.ct_mock_window.setFixedHeight(128)
        window_layout = QHBoxLayout(self.ct_mock_window)
        window_layout.setContentsMargins(8, 8, 8, 8)
        window_layout.setSpacing(8)

        # Sidebar with one selected item
        sidebar = QFrame()
        sidebar.setFixedWidth(64)
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(4, 4, 4, 4)
        sb_layout.setSpacing(4)
        self.ct_mock_nav = []
        for label in ["Info", "Files", "Trophy", "Modify"]:
            item = QLabel(label)
            item.setAlignment(Qt.AlignCenter)
            item.setFixedHeight(16)
            self.ct_mock_nav.append(item)
            sb_layout.addWidget(item)
        sb_layout.addStretch(1)
        self.ct_mock_sidebar = sidebar
        window_layout.addWidget(sidebar)

        # Content area
        content = QVBoxLayout()
        content.setSpacing(6)

        title_row = QHBoxLayout()
        self.ct_mock_title = QLabel("Window title")
        self.ct_mock_subtitle = QLabel("secondary text")
        title_row.addWidget(self.ct_mock_title)
        title_row.addWidget(self.ct_mock_subtitle)
        title_row.addStretch(1)
        content.addLayout(title_row)

        self.ct_mock_input = QFrame()
        self.ct_mock_input.setFixedHeight(20)
        content.addWidget(self.ct_mock_input)

        btn_row = QHBoxLayout()
        self.ct_mock_button = QLabel("Button")
        self.ct_mock_button.setAlignment(Qt.AlignCenter)
        self.ct_mock_button.setFixedSize(64, 20)
        btn_row.addWidget(self.ct_mock_button)
        btn_row.addStretch(1)
        content.addLayout(btn_row)

        badge_row = QHBoxLayout()
        self.ct_mock_success = QLabel("OK")
        self.ct_mock_warning = QLabel("!")
        self.ct_mock_error = QLabel("\u2715")
        for b in (self.ct_mock_success, self.ct_mock_warning, self.ct_mock_error):
            b.setAlignment(Qt.AlignCenter)
            b.setFixedSize(24, 16)
            badge_row.addWidget(b)
        badge_row.addStretch(1)
        content.addLayout(badge_row)
        content.addStretch(1)

        window_layout.addLayout(content, 1)
        root_layout.addWidget(self.ct_mock_window)

    def _update_ct_preview(self):
        """Update the custom-theme mockup from the current editor colors."""
        def val(key):
            return self.ct_color_labels[key].text() or StyleManager._COLOR_DEFAULTS.get(key, '#ffffff')

        bg = val('background')
        text = val('text')
        accent = val('accent')
        secondary = val('secondary_bg')
        border = val('border')
        secondary_text = val('secondary_text')
        selection = val('selection')
        success = val('success')
        warning = val('warning')
        error = val('error')

        self.ct_mock_window.setStyleSheet(
            f"background-color: {bg}; border: 1px solid {border}; border-radius: 6px;"
        )
        self.ct_mock_sidebar.setStyleSheet(f"background-color: {secondary}; border-radius: 4px;")
        for i, item in enumerate(self.ct_mock_nav):
            if i == 0:
                item.setStyleSheet(
                    f"background-color: {selection}; color: #ffffff; border-radius: 3px; font-size: 9px;"
                )
            else:
                item.setStyleSheet(f"background: transparent; color: {text}; font-size: 9px;")
        self.ct_mock_title.setStyleSheet(
            f"background: transparent; color: {text}; font-weight: 600; font-size: 11px;"
        )
        self.ct_mock_subtitle.setStyleSheet(
            f"background: transparent; color: {secondary_text}; font-size: 9px;"
        )
        self.ct_mock_input.setStyleSheet(
            f"background-color: {secondary}; border: 1px solid {border}; border-radius: 3px;"
        )
        self.ct_mock_button.setStyleSheet(
            f"background-color: {accent}; color: #ffffff; border-radius: 3px; font-size: 9px; font-weight: 600;"
        )
        self.ct_mock_success.setStyleSheet(
            f"background-color: {success}; color: #ffffff; border-radius: 3px; font-size: 8px;"
        )
        self.ct_mock_warning.setStyleSheet(
            f"background-color: {warning}; color: #ffffff; border-radius: 3px; font-size: 8px;"
        )
        self.ct_mock_error.setStyleSheet(
            f"background-color: {error}; color: #ffffff; border-radius: 3px; font-size: 8px;"
        )

    def _save_custom_theme(self):
        name = self.ct_name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Warning", "Please enter a theme name")
            return
        themes = StyleManager.load_custom_themes()
        themes[name] = {key: (self.ct_color_labels[key].text() or StyleManager._COLOR_DEFAULTS.get(key, '#ffffff'))
                        for key in StyleManager.COLOR_KEYS}
        try:
            StyleManager.save_custom_themes(themes)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save theme: {str(e)}")
            return
        self._refresh_ct_list()
        # Select the saved theme in the list
        items = self.ct_list.findItems(name, Qt.MatchExactly)
        if items:
            self.ct_list.setCurrentItem(items[0])

    def _delete_custom_theme(self):
        item = self.ct_list.currentItem()
        if not item:
            QMessageBox.warning(self, "Warning", "Select a theme to delete")
            return
        name = item.text()
        reply = QMessageBox.question(self, "Confirm Delete",
                                     f"Delete theme '{name}'?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        StyleManager.delete_custom_theme(name)
        self._refresh_ct_list()
        self._new_custom_theme()

    def _create_behavior_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        browser_group = QGroupBox("File Browser")
        browser_layout = QVBoxLayout()
        self.auto_expand_check = QCheckBox("Auto-expand file tree")
        self.show_hidden_check = QCheckBox("Show hidden files")
        self.confirm_exit_check = QCheckBox("Confirm before exit")
        browser_layout.addWidget(self.auto_expand_check)
        browser_layout.addWidget(self.show_hidden_check)
        browser_layout.addWidget(self.confirm_exit_check)
        browser_group.setLayout(browser_layout)
        layout.addWidget(browser_group)

        layout.addStretch(1)
        return page

    def _create_paths_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        paths_group = QGroupBox("Default Paths")
        paths_layout = QGridLayout()
        self.output_path_edit = QLineEdit()
        self.temp_path_edit = QLineEdit()
        output_browse = QPushButton("Browse")
        temp_browse = QPushButton("Browse")
        output_browse.clicked.connect(lambda: self._browse_directory(self.output_path_edit))
        temp_browse.clicked.connect(lambda: self._browse_directory(self.temp_path_edit))

        paths_layout.addWidget(QLabel("Output:"), 0, 0)
        paths_layout.addWidget(self.output_path_edit, 0, 1)
        paths_layout.addWidget(output_browse, 0, 2)
        paths_layout.addWidget(QLabel("Temp:"), 1, 0)
        paths_layout.addWidget(self.temp_path_edit, 1, 1)
        paths_layout.addWidget(temp_browse, 1, 2)
        paths_group.setLayout(paths_layout)
        layout.addWidget(paths_group)

        layout.addStretch(1)
        return page

    def _create_about_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        about_group = QGroupBox("PkgToolBox")
        about_layout = QVBoxLayout()
        about_layout.setAlignment(Qt.AlignHCenter)

        # Maintainer avatar: latest GitHub profile picture. Shows the cached
        # copy (or the bundled toolbox icon) immediately, then swaps in the
        # freshly fetched avatar when it arrives.
        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(96, 96)
        self.avatar_label.setAlignment(Qt.AlignCenter)
        self.avatar_label.setToolTip("SeregonWar")
        about_layout.addWidget(self.avatar_label)

        about_layout.addWidget(QLabel("Version: 1.5.0"))
        about_layout.addWidget(QLabel("Created by SeregonWar"))

        link_style = 'style="color:#3b82f6; text-decoration:none;"'
        donations = QLabel(
            '<a href="https://www.seregonwar.com/donations" ' + link_style +
            ' target="_blank">Donate · seregonwar.com/donations</a>'
        )
        donations.setTextFormat(Qt.RichText)
        donations.setOpenExternalLinks(True)
        about_layout.addWidget(donations)

        github = QLabel(
            '<a href="https://github.com/seregonwar/PkgToolBox" ' + link_style +
            ' target="_blank">github.com/seregonwar/PkgToolBox</a>'
        )
        github.setTextFormat(Qt.RichText)
        github.setOpenExternalLinks(True)
        about_layout.addWidget(github)

        about_group.setLayout(about_layout)
        layout.addWidget(about_group)

        layout.addStretch(1)
        return page

    def _refresh_avatar(self):
        """Show the cached avatar (or the bundled icon), then fetch the latest."""
        path = AvatarFetcher.cached_avatar() or AvatarFetcher.bundled_icon_path()
        self._set_avatar_pixmap(path)
        if self._avatar_fetcher is None:
            self._avatar_fetcher = AvatarFetcher(self)
            self._avatar_fetcher.avatar_ready.connect(self._set_avatar_pixmap)
        self._avatar_fetcher.start()

    def _set_avatar_pixmap(self, path):
        """Load and scale the avatar image into the label (best-effort)."""
        if not path or not hasattr(self, 'avatar_label'):
            return
        pixmap = QPixmap(path)
        if pixmap.isNull():
            return
        self.avatar_label.setPixmap(pixmap.scaled(
            96, 96, Qt.KeepAspectRatio, Qt.SmoothTransformation))

    # ── Live preview helpers ───────────────────────────────────────────────

    def _on_theme_changed(self, index):
        """Update the live preview of the selected theme."""
        theme = self.theme_combo.itemData(index) if index >= 0 else None
        if theme:
            colors = StyleManager.get_theme_colors(theme)
            self._update_preview(colors)

    def _update_preview(self, colors):
        bg = colors.get('background', '#ffffff')
        text = colors.get('text', '#000000')
        accent = colors.get('accent', '#3b82f6')
        border = colors.get('border', '#cbd5e1')
        secondary = colors.get('secondary_bg', bg)
        self.theme_preview.setStyleSheet(f"""
            QFrame {{
                background-color: {bg};
                border: 1px solid {border};
                border-radius: 8px;
            }}
            QLabel {{ background: transparent; color: {text}; }}
        """)
        self.preview_bg.setText(f"Background  {bg}")
        self.preview_text.setText(f"Text  {text}")
        self.preview_accent.setStyleSheet(
            f"background-color: {accent}; color: #ffffff; border-radius: 6px;"
            f"padding: 4px; font-weight: 600;"
        )
        self.preview_accent.setText(f"Accent  {accent}")
        self.preview_bg.setStyleSheet(
            f"background-color: {secondary}; color: {text}; border-radius: 6px; padding: 2px 6px;"
        )
        self.preview_text.setStyleSheet(
            f"background: transparent; color: {text}; padding: 2px 6px;"
        )

    def _update_color_button(self, button, color):
        button.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: {"#ffffff" if QColor(color).lightness() < 128 else "#000000"};
                min-width: 90px;
                padding: 5px;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
            }}
        """)
        button.setText(color)

    def _browse_directory(self, line_edit):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            line_edit.setText(directory)

    # ── Load / save ────────────────────────────────────────────────────────

    def _build_settings(self):
        theme = self.theme_combo.currentData()
        colors = StyleManager.get_theme_colors(theme)
        return {
            "appearance": {
                "theme": theme,
                "night_mode": StyleManager.is_dark_theme(theme),
                "font_family": self.font_combo.currentText(),
                "font_size": self.font_size_spin.value(),
                "colors": colors,
            },
            "behavior": {
                "auto_expand": self.auto_expand_check.isChecked(),
                "show_hidden": self.show_hidden_check.isChecked(),
                "confirm_exit": self.confirm_exit_check.isChecked(),
            },
            "paths": {
                "output": self.output_path_edit.text(),
                "temp": self.temp_path_edit.text(),
            },
            "language": self.language_combo.currentText(),
        }

    def _apply_and_save(self, close: bool):
        try:
            settings = self._build_settings()
            StyleManager.save_settings(settings)
            if self.parent:
                StyleManager.apply_theme(self.parent, settings)
                font = QFont(settings["appearance"]["font_family"], settings["appearance"]["font_size"])
                QApplication.setFont(font)
                if hasattr(self.parent, "settings_dict"):
                    self.parent.settings_dict = settings
            if close:
                self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {str(e)}")

    def load_settings(self):
        try:
            settings = StyleManager.load_settings()
            appearance = settings.get("appearance", {})

            theme = appearance.get("theme", "Dark")
            if theme == "Custom":
                # Legacy: the old 'Custom' pseudo-theme is replaced by the
                # dedicated custom themes section -> fall back to a saved theme.
                customs = StyleManager.load_custom_themes()
                theme = next(iter(customs)) if customs else "Dark"
            idx = self.theme_combo.findData(theme)
            self.theme_combo.setCurrentIndex(idx if idx >= 0 else self.theme_combo.findData("Dark"))
            self._on_theme_changed(self.theme_combo.currentIndex())

            lang = settings.get("language", "English")
            if self.language_combo.findText(lang) != -1:
                self.language_combo.setCurrentText(lang)

            font = QFont(appearance.get("font_family", "Arial"), appearance.get("font_size", 12))
            self._current_font = font
            self.font_combo.setCurrentText(font.family())
            self.font_size_spin.setValue(font.pointSize())

            behavior = settings.get("behavior", {})
            self.auto_expand_check.setChecked(behavior.get("auto_expand", True))
            self.show_hidden_check.setChecked(behavior.get("show_hidden", False))
            self.confirm_exit_check.setChecked(behavior.get("confirm_exit", True))

            paths = settings.get("paths", {})
            self.output_path_edit.setText(paths.get("output", ""))
            self.temp_path_edit.setText(paths.get("temp", ""))
        except Exception as e:
            QMessageBox.warning(self, "Warning", f"Failed to load settings: {str(e)}")

    def reset_settings(self):
        reply = QMessageBox.question(
            self, "Confirm Reset",
            "Are you sure you want to reset all settings to default?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        defaults = StyleManager.DEFAULT_SETTINGS.copy()
        idx = self.theme_combo.findData(defaults["appearance"]["theme"])
        self.theme_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.font_combo.setCurrentText("Arial")
        self.font_size_spin.setValue(12)
        self.auto_expand_check.setChecked(True)
        self.show_hidden_check.setChecked(False)
        self.confirm_exit_check.setChecked(True)
        self.output_path_edit.clear()
        self.temp_path_edit.clear()
        self._on_theme_changed(self.theme_combo.currentText())

    def on_language_changed(self, language):
        """Apply language change live to the main window."""
        lang_codes = {
            "English": "en", "Italian": "it", "Spanish": "es",
            "French": "fr", "German": "de", "Japanese": "ja",
        }
        if self.parent and language in lang_codes and hasattr(self.parent, "translator"):
            self.parent.translator.change_language(lang_codes[language])
            if hasattr(self.parent, "retranslate_ui"):
                self.parent.retranslate_ui()
