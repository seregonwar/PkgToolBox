from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QTabWidget, QWidget, QGroupBox, 
                            QGridLayout, QLabel, QComboBox, QSpinBox, QPushButton,
                            QCheckBox, QLineEdit, QHBoxLayout, QColorDialog, QFontDialog,
                            QFileDialog, QMessageBox, QApplication)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor, QFontDatabase
import os
import json

# Modifica l'import relativo in import assoluto
from GraphicUserInterface.utils.style_manager import StyleManager

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the settings dialog UI"""
        self.setWindowTitle("Settings")
        self.setMinimumWidth(500)
        
        layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Add tabs
        self.tab_widget.addTab(self.create_appearance_tab(), "Appearance")
        self.tab_widget.addTab(self.create_behavior_tab(), "Behavior")
        self.tab_widget.addTab(self.create_paths_tab(), "Paths")
        
        layout.addWidget(self.tab_widget)
        
        # Add buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save")
        cancel_button = QPushButton("Cancel")
        reset_button = QPushButton("Reset to Default")
        
        save_button.clicked.connect(self.save_settings)
        cancel_button.clicked.connect(self.reject)
        reset_button.clicked.connect(self.reset_settings)
        
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        button_layout.addWidget(reset_button)
        
        layout.addLayout(button_layout)
        
        # Load current settings
        self.load_settings()

    def create_appearance_tab(self):
        """Create and return the appearance tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Theme group
        theme_group = QGroupBox("Theme")
        theme_layout = QGridLayout()
        
        theme_layout.addWidget(QLabel("Theme:"), 0, 0)
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark", "System", "Custom"])
        self.theme_combo.currentTextChanged.connect(self.on_theme_changed)
        theme_layout.addWidget(self.theme_combo, 0, 1)
        
        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)
        
        # Language group
        language_group = QGroupBox("Language")
        language_layout = QGridLayout()
        
        language_layout.addWidget(QLabel("Language:"), 0, 0)
        self.language_combo = QComboBox()
        self.language_combo.addItems(["English", "Italian", "Spanish", "French", "German", "Japanese"])
        self.language_combo.currentTextChanged.connect(self.on_language_changed)
        language_layout.addWidget(self.language_combo, 0, 1)
        
        language_group.setLayout(language_layout)
        layout.addWidget(language_group)
        
        # Font group
        font_group = QGroupBox("Font")
        font_layout = QGridLayout()
        
        # Font family combo
        font_layout.addWidget(QLabel("Font:"), 0, 0)
        self.font_combo = QComboBox()
        self.font_combo.addItems(QFontDatabase().families())
        font_layout.addWidget(self.font_combo, 0, 1)
        
        # Font size spinner
        font_layout.addWidget(QLabel("Size:"), 1, 0)
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 24)
        self.font_size_spin.setValue(12)
        font_layout.addWidget(self.font_size_spin, 1, 1)
        
        # Font preview button
        self.font_button = QPushButton("Preview Font")
        self.font_button.clicked.connect(self.select_font)
        font_layout.addWidget(self.font_button, 2, 0, 1, 2)
        
        font_group.setLayout(font_layout)
        layout.addWidget(font_group)
        
        # Colors group
        self.colors_group = QGroupBox("Colors")
        colors_layout = QGridLayout()
        
        # Color buttons with labels and preview
        self.bg_color_button = QPushButton()
        self.text_color_button = QPushButton()
        self.accent_color_button = QPushButton()
        
        colors_layout.addWidget(QLabel("Background:"), 0, 0)
        colors_layout.addWidget(self.bg_color_button, 0, 1)
        colors_layout.addWidget(QLabel("Text:"), 1, 0)
        colors_layout.addWidget(self.text_color_button, 1, 1)
        colors_layout.addWidget(QLabel("Accent:"), 2, 0)
        colors_layout.addWidget(self.accent_color_button, 2, 1)
        
        self.bg_color_button.clicked.connect(lambda: self.pick_color("background"))
        self.text_color_button.clicked.connect(lambda: self.pick_color("text"))
        self.accent_color_button.clicked.connect(lambda: self.pick_color("accent"))
        
        # Disabilita i pulsanti dei colori se non è selezionato Custom
        self.colors_group.setEnabled(self.theme_combo.currentText() == "Custom")
        
        self.colors_group.setLayout(colors_layout)
        layout.addWidget(self.colors_group)
        
        return tab

    def create_behavior_tab(self):
        """Create and return the behavior tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # File browser settings
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
        
        layout.addStretch()
        return tab

    def create_paths_tab(self):
        """Create and return the paths tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        paths_group = QGroupBox("Default Paths")
        paths_layout = QGridLayout()
        
        self.output_path_edit = QLineEdit()
        self.temp_path_edit = QLineEdit()
        
        output_browse = QPushButton("Browse")
        temp_browse = QPushButton("Browse")
        
        output_browse.clicked.connect(lambda: self.browse_directory(self.output_path_edit))
        temp_browse.clicked.connect(lambda: self.browse_directory(self.temp_path_edit))
        
        paths_layout.addWidget(QLabel("Output:"), 0, 0)
        paths_layout.addWidget(self.output_path_edit, 0, 1)
        paths_layout.addWidget(output_browse, 0, 2)
        paths_layout.addWidget(QLabel("Temp:"), 1, 0)
        paths_layout.addWidget(self.temp_path_edit, 1, 1)
        paths_layout.addWidget(temp_browse, 1, 2)
        
        paths_group.setLayout(paths_layout)
        layout.addWidget(paths_group)
        
        layout.addStretch()
        return tab

    def select_font(self):
        """Open font selection dialog"""
        current_font = QApplication.font()
        font, ok = QFontDialog.getFont(current_font, self)
        if ok:
            self.current_font = font
            self.font_button.setText(f"{font.family()} - {font.pointSize()}pt")
            QApplication.setFont(font)

    def pick_color(self, color_type):
        """Open color picker dialog"""
        color = QColorDialog.getColor()
        if color.isValid():
            color_hex = color.name()
            
            # Aggiorna il pulsante con il nuovo colore
            button_style = f"""
                QPushButton {{
                    background-color: {color_hex};
                    color: {"#ffffff" if color.lightness() < 128 else "#000000"};
                    min-width: 100px;
                    padding: 5px;
                    border: 1px solid #bdc3c7;
                    border-radius: 4px;
                }}
            """
            
            # Aggiorna il pulsante appropriato e applica immediatamente il colore
            if color_type == "background":
                self.bg_color_button.setStyleSheet(button_style)
                self.bg_color_button.setText(color_hex)
                settings = {
                    "theme": self.theme_combo.currentText(),
                    "bg_color": color_hex,
                    "text_color": self.text_color_button.text(),
                    "accent_color": self.accent_color_button.text()
                }
            elif color_type == "text":
                self.text_color_button.setStyleSheet(button_style)
                self.text_color_button.setText(color_hex)
                settings = {
                    "theme": self.theme_combo.currentText(),
                    "bg_color": self.bg_color_button.text(),
                    "text_color": color_hex,
                    "accent_color": self.accent_color_button.text()
                }
            elif color_type == "accent":
                self.accent_color_button.setStyleSheet(button_style)
                self.accent_color_button.setText(color_hex)
                settings = {
                    "theme": self.theme_combo.currentText(),
                    "bg_color": self.bg_color_button.text(),
                    "text_color": self.text_color_button.text(),
                    "accent_color": color_hex
                }
                
            # Applica immediatamente le modifiche
            if self.parent:
                StyleManager.apply_theme(self.parent, settings)
                self.parent.repaint()
                QApplication.processEvents()

    def browse_directory(self, line_edit):
        """Browse for directory"""
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            line_edit.setText(directory)

    def save_settings(self):
        """Save settings and apply them"""
        try:
            settings = {
                "appearance": {
                    "theme": self.theme_combo.currentText(),
                    "night_mode": self.theme_combo.currentText() == "Dark",
                    "font_family": self.current_font.family() if hasattr(self, 'current_font') else "Arial",
                    "font_size": self.current_font.pointSize() if hasattr(self, 'current_font') else 12,
                    "colors": {
                        "background": self.bg_color_button.text() if self.bg_color_button.text().startswith('#') else "#ffffff",
                        "text": self.text_color_button.text() if self.text_color_button.text().startswith('#') else "#000000",
                        "accent": self.accent_color_button.text() if self.accent_color_button.text().startswith('#') else "#3498db"
                    }
                },
                "behavior": {
                    "auto_expand": self.auto_expand_check.isChecked(),
                    "show_hidden": self.show_hidden_check.isChecked(),
                    "confirm_exit": self.confirm_exit_check.isChecked()
                },
                "paths": {
                    "output": self.output_path_edit.text(),
                    "temp": self.temp_path_edit.text()
                }
            }

            # Salva le impostazioni
            StyleManager.save_settings(settings)
            
            # Applica le impostazioni
            if self.parent:
                StyleManager.apply_theme(self.parent, settings)
                
                # Applica il font
                font = QFont(settings["appearance"]["font_family"], 
                            settings["appearance"]["font_size"])
                QApplication.setFont(font)

            self.accept()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {str(e)}")

    def load_settings(self):
        """Load settings from config file"""
        try:
            config_file = os.path.join(os.path.expanduser("~"), ".pkgtoolbox", "config.json")
            if os.path.exists(config_file):
                with open(config_file, "r") as f:
                    settings = json.load(f)
                
                # Carica il tema
                self.theme_combo.setCurrentText(settings.get("theme", "Light"))
                
                # Carica il font
                font = QFont(settings.get("font_family", "Arial"), 
                            settings.get("font_size", 12))
                self.current_font = font
                self.font_button.setText(f"{font.family()} - {font.pointSize()}pt")
                
                # Carica i colori
                colors = settings.get("colors", {})
                if colors:
                    self.update_color_button(self.bg_color_button, colors.get("background", "#ffffff"))
                    self.update_color_button(self.text_color_button, colors.get("text", "#000000"))
                    self.update_color_button(self.accent_color_button, colors.get("accent", "#3498db"))
                
                # Carica altre impostazioni
                self.auto_expand_check.setChecked(settings.get("auto_expand", True))
                self.show_hidden_check.setChecked(settings.get("show_hidden", False))
                self.confirm_exit_check.setChecked(settings.get("confirm_exit", True))
                self.output_path_edit.setText(settings.get("output_path", ""))
                self.temp_path_edit.setText(settings.get("temp_path", ""))
                
            else:
                # Usa valori predefiniti se il file non esiste
                self.reset_settings()
                
        except Exception as e:
            QMessageBox.warning(self, "Warning", f"Failed to load settings: {str(e)}")
            self.reset_settings()

    def reset_settings(self):
        """Reset settings to default"""
        reply = QMessageBox.question(self, "Confirm Reset", 
                                   "Are you sure you want to reset all settings to default?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            # Reset to defaults
            self.theme_combo.setCurrentText("Light")
            
            font = QFont("Arial", 12)
            self.current_font = font
            self.font_button.setText("Arial - 12pt")
            
            self.bg_color_button.setStyleSheet("")
            self.text_color_button.setStyleSheet("")
            self.accent_color_button.setStyleSheet("")
            
            self.auto_expand_check.setChecked(True)
            self.show_hidden_check.setChecked(False)
            self.confirm_exit_check.setChecked(True)
            
            self.output_path_edit.clear()
            self.temp_path_edit.clear()
            
            # Save and apply default settings
            self.save_settings()

    def apply_settings(self, settings):
        """Apply settings to parent window"""
        if self.parent:
            try:
                # Applica il tema
                theme = settings.get("theme", "Light")
                
                # Gestisci i colori personalizzati
                if theme == "Custom":
                    colors = {
                        'bg_color': self.bg_color_button.text(),
                        'text_color': self.text_color_button.text(),
                        'accent_color': self.accent_color_button.text()
                    }
                    settings.update(colors)
                
                # Applica il font
                font = QFont(settings["font_family"], settings["font_size"])
                QApplication.setFont(font)
                
                # Applica il tema
                StyleManager.apply_theme(self.parent, settings)
                
                # Aggiorna le impostazioni del file browser
                if hasattr(self.parent, 'file_browser'):
                    if settings.get("auto_expand", True):
                        self.parent.file_browser.file_tree.expandAll()
                    else:
                        self.parent.file_browser.file_tree.collapseAll()
                
                # Forza l'aggiornamento visuale
                self.parent.repaint()
                QApplication.processEvents()
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to apply settings: {str(e)}")

    def on_theme_changed(self, theme):
        """Handle theme change"""
        self.colors_group.setEnabled(theme == "Custom")
        if theme != "Custom":
            # Imposta i colori predefiniti per il tema selezionato
            if theme == "Light":
                self.set_theme_colors("#ffffff", "#000000", "#3498db")
            elif theme == "Dark":
                self.set_theme_colors("#1e1e1e", "#ffffff", "#3498db")
            elif theme == "System":
                # Usa i colori di sistema
                from PyQt5.QtGui import QPalette
                palette = QApplication.palette()
                self.set_theme_colors(
                    palette.color(QPalette.Window).name(),
                    palette.color(QPalette.WindowText).name(),
                    palette.color(QPalette.Highlight).name()
                )

    def set_theme_colors(self, bg, text, accent):
        """Set theme colors"""
        self.update_color_button(self.bg_color_button, bg)
        self.update_color_button(self.text_color_button, text)
        self.update_color_button(self.accent_color_button, accent)

    def update_color_button(self, button, color):
        """Update color button appearance"""
        button.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: {"#ffffff" if QColor(color).lightness() < 128 else "#000000"};
                min-width: 100px;
                padding: 5px;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
            }}
        """)
        button.setText(color)

    def on_language_changed(self, language):
        """Handle language change"""
        lang_codes = {
            "English": "en",
            "Italian": "it",
            "Spanish": "es",
            "French": "fr",
            "German": "de",
            "Japanese": "ja"
        }
        
        if language in lang_codes:
            self.parent.translator.change_language(lang_codes[language])
            self.parent.retranslate_ui()