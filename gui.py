import logging
import sys
import os
import re
import shutil
import binascii
import subprocess
import io
import json
from PIL import Image, UnidentifiedImageError
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QTreeWidget, QTreeWidgetItem,
                             QFileDialog, QMessageBox, QTabWidget, QScrollArea, QSizePolicy,
                             QTextEdit, QSpinBox, QFrame, QStatusBar, QToolBar, QAction, QMenu, QInputDialog,
                             QProgressDialog, QListWidget, QListWidgetItem, QDialog)
from PyQt5.QtGui import QFont, QPixmap, QPalette, QColor, QRegExpValidator, QIcon, QBrush, QImage, QDesktopServices
from PyQt5.QtCore import Qt, QRegExp, QSize, QTimer, QUrl
from kiwisolver import *

from package import Package
from file_operations import extract_file, inject_file, modify_file_header
import concurrent.futures
# Import utilities
from Utilities import Logger, SettingsManager, TRPReader  
from Utilities.Trophy import Archiver, TRPCreator, TRPReader  
from repack import Repack

OUTPUT_FOLDER = "._temp_output"
Hexpattern = re.compile(r'[^\x20-\x7E]')


class PS4PKGTool(QMainWindow):
    def __init__(self, temp_directory):
        super().__init__()
        self.setWindowTitle("PKG Tool Box v1.1")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize all necessary widgets
        self.pkg_entry = QLineEdit()
        self.extract_out_entry = QLineEdit()
        self.dump_pkg_entry = QLineEdit()
        self.dump_out_entry = QLineEdit()
        self.inject_pkg_entry = QLineEdit()
        self.inject_file_entry = QLineEdit()
        self.inject_input_entry = QLineEdit()
        self.modify_pkg_entry = QLineEdit()
        self.offset_entry = QLineEdit()
        self.data_entry = QLineEdit()
        self.hex_viewer = QTextEdit()
        self.hex_editor = QTextEdit()
        self.trophy_entry = QLineEdit()
        self.trophy_info = QTextEdit()
        self.trophy_image_label = QLabel()
        self.search_entry = QLineEdit()
        self.replace_entry = QLineEdit()
        
        self.current_pkg = None
        self.package = None
        self.temp_directory = temp_directory
        
        self.setup_ui()
        
        self.file_path = None
        self.run_command_callback = None
        
        # Load settings
        try:
            self.settings = SettingsManager.load_settings("path/to/settings.conf")
            Logger.log_information("Application started with loaded settings.")
        except Exception as e:
            Logger.log_error(f"Error loading settings: {e}")
            QMessageBox.critical(self, "Error", f"Error loading settings: {e}")
            sys.exit(1)
        
        # Path to orbis-pub-cmd.exe
        self.orbis_pub_cmd_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "OrbisLibrary", "orbis-pub-cmd.exe")

        # Initialize night mode
        self.night_mode = self.load_night_mode()
        self.set_style()

    def setup_ui(self):
        self.create_statusbar()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Add title label
        title_label = QLabel("PkgToolBox")
        title_label.setAlignment(Qt.AlignCenter)
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        self.image_label = QLabel("No icon available")
        self.image_label.setFixedSize(300, 300)
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet("background-color: white; border: 1px solid white; border-radius: 10px;")
        left_layout.addWidget(self.image_label)

        pkg_layout = QHBoxLayout()
        self.pkg_entry.setPlaceholderText("Select PKG file")
        self.pkg_entry.setStyleSheet("background-color: white; color: #2c3e50; font-size: 14px; padding: 8px; border-radius: 5px;")
        pkg_button = QPushButton("Browse")
        pkg_button.setStyleSheet("font-size: 14px; padding: 8px 15px; background-color: #3498db; color: white; border-radius: 5px;")
        pkg_button.clicked.connect(self.browse_pkg)
        pkg_layout.addWidget(self.pkg_entry)
        pkg_layout.addWidget(pkg_button)
        left_layout.addLayout(pkg_layout)

        left_layout.addStretch(1)
        main_layout.addWidget(left_widget, 1)

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        self.tab_widget = QTabWidget()
        self.info_tab = QWidget()
        self.extract_tab = QWidget()
        self.dump_tab = QWidget()
        self.inject_tab = QWidget()
        self.modify_tab = QWidget()
        self.trophy_tab = QWidget()
        self.trp_create_tab = QWidget()  
        self.file_browser_tab = QWidget() 
        self.wallpaper_tab = QWidget() 
        
        self.tab_widget.addTab(self.info_tab, "Info")
        self.tab_widget.addTab(self.extract_tab, "Extract")
        self.tab_widget.addTab(self.dump_tab, "Dump")
        self.tab_widget.addTab(self.inject_tab, "Inject")
        self.tab_widget.addTab(self.modify_tab, "Modify")
        self.tab_widget.addTab(self.trophy_tab, "Trophy")
        self.tab_widget.addTab(self.trp_create_tab, "Create TRP")  
        self.tab_widget.addTab(self.file_browser_tab, "File Browser")  
        self.tab_widget.addTab(self.wallpaper_tab, "Wallpaper")  
        
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #3498db; }
            QTabBar::tab { background: #3498db; color: white; padding: 10px; }
            QTabBar::tab:selected { background: #2980b9; }
        """)
        
        right_layout.addWidget(self.tab_widget)

        self.setup_info_tab()
        self.setup_extract_tab()
        self.setup_dump_tab()
        self.setup_inject_tab()
        self.setup_modify_tab()
        self.setup_trophy_tab()
        self.setup_trp_create_tab()
        self.setup_file_browser_tab()
        self.setup_wallpaper_tab()

        main_layout.addWidget(right_widget, 2)

        # Add night mode toggle button
        self.night_mode_button = QPushButton("🌙")
        self.night_mode_button.setFixedSize(30, 30)
        self.night_mode_button.setStyleSheet("QPushButton { font-size: 14px; padding: 5px; background-color: #3498db; color: white; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        self.night_mode_button.clicked.connect(self.toggle_night_mode)
        self.add_night_mode_button()

        # Stile del frame
        self.setStyleSheet("""
            QMainWindow {
                border: 2px solid #3498db;
                border-radius: 10px;
                padding: 10px;
                background-color: #ecf0f1;
            }
            QLabel {
                font-size: 14px;
                color: #2c3e50;
                font-weight: bold;
            }
            QPushButton {
                font-size: 14px;
                color: white;
                background-color: #3498db;
                border: none;
                padding: 5px 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1f618d;
            }
        """)

        # Layout principale
        credits_layout = QVBoxLayout()

        # Etichetta del creatore
        credits_label = QLabel("Created by SeregonWar")
        credits_label.setAlignment(Qt.AlignCenter)
        credits_label.setStyleSheet("font-size: 14px; color: #2c3e50; font-weight: bold;")
        credits_layout.addWidget(credits_label)

        # Layout dei pulsanti social
        social_layout = QHBoxLayout()
        social_layout.setAlignment(Qt.AlignCenter)
        
        main_layout.addLayout(credits_layout)
        main_layout.addLayout(social_layout)

        # Funzione per aprire URL
        def open_url(url):
            QDesktopServices.openUrl(QUrl(url))

        # Pulsante X
        x_button = QPushButton("X")
        x_button.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                color: white;
                background-color: #3498db;
                border: none;
                padding: 5px 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1f618d;
            }
        """)
        x_button.clicked.connect(lambda: open_url("https://x.com/SeregonWar"))
        social_layout.addWidget(x_button)

        # Pulsante GitHub
        github_button = QPushButton("GitHub")
        github_button.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                color: white;
                background-color: #3498db;
                border: none;
                padding: 5px 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1f618d;
            }
        """)
        github_button.clicked.connect(lambda: open_url("https://github.com/seregonwar"))
        social_layout.addWidget(github_button)

        # Pulsante Reddit
        reddit_button = QPushButton("Reddit")
        reddit_button.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                color: white;
                background-color: #3498db;
                border: none;
                padding: 5px 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1f618d;
            }
        """)
        reddit_button.clicked.connect(lambda: open_url("https://www.reddit.com/user/S3R3GON/"))
        social_layout.addWidget(reddit_button)

        credits_layout.addLayout(social_layout)

        # Pulsante di donazione
        donation_button = QPushButton("Support me on Ko-fi")
        donation_button.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                color: white;
                background-color: #e74c3c;
                font-weight: bold;
                border: none;
                padding: 5px 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:pressed {
                background-color: #922b21;
            }
        """)
        donation_button.clicked.connect(lambda: open_url("https://ko-fi.com/seregon"))
        credits_layout.addWidget(donation_button)


    def add_night_mode_button(self):
        toolbar = QToolBar()
        toolbar.setIconSize(QSize(32, 32))
        toolbar.setStyleSheet("QToolBar { background: #2c3e50; spacing: 10px; }")
        self.addToolBar(Qt.TopToolBarArea, toolbar)
        toolbar.addWidget(self.night_mode_button)

    def toggle_night_mode(self):
        self.night_mode = not self.night_mode
        self.set_style()
        self.save_night_mode()

    def set_style(self):
        if self.night_mode:
            self.setStyleSheet("""
                QWidget { background-color: #000000; color: #ecf0f1; }
                QLineEdit, QTextEdit { background-color: #1c1c1c; color: #ecf0f1; border: 1px solid #7f8c8d; }
                QPushButton { background-color: #3498db; color: #ecf0f1; }
                QTreeWidget { background-color: #1c1c1c; color: #ecf0f1; }
                QTreeWidget::item { color: #ecf0f1; }
                QTabWidget::pane { border: 1px solid #7f8c8d; }
                QTabBar::tab { background: #1c1c1c; color: #ecf0f1; }
                QTabBar::tab:selected { background: #2980b9; }
                QLabel { color: #ecf0f1; }
            """)
        else:
            self.setStyleSheet("""
                QWidget { background-color: #ecf0f1; color: #2c3e50; }
                QLineEdit, QTextEdit { background-color: white; color: #2c3e50; border: 1px solid #bdc3c7; }
                QPushButton { background-color: #3498db; color: white; }
                QTreeWidget { background-color: white; color: #2c3e50; }
                QTreeWidget::item { color: #2c3e50; }
                QTabWidget::pane { border: 1px solid #3498db; }
                QTabBar::tab { background: #3498db; color: white; }
                QTabBar::tab:selected { background: #2980b9; }
                QLabel { color: #2c3e50; }
            """)

    def save_night_mode(self):
        settings = {"night_mode": self.night_mode}
        with open("settings.json", "w") as settings_file:
            json.dump(settings, settings_file)

    def load_night_mode(self):
        try:
            with open("settings.json", "r") as settings_file:
                settings = json.load(settings_file)
                return settings.get("night_mode", False)
        except FileNotFoundError:
            return False

    def create_toolbar(self):
        toolbar = QToolBar()
        toolbar.setIconSize(QSize(32, 32))
        toolbar.setStyleSheet("QToolBar { background: #2c3e50; spacing: 10px; }")
        self.addToolBar(toolbar)

        icon_style = "QToolButton { background-color: #34495e; border-radius: 5px; } QToolButton:hover { background-color: #3498db; }"

        info_action = QAction(QIcon("icons/info.png"), "Info", self)
        info_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(0))
        toolbar.addAction(info_action)

        extract_action = QAction(QIcon("icons/extract.png"), "Extract", self)
        extract_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(1))
        toolbar.addAction(extract_action)

        dump_action = QAction(QIcon("icons/dump.png"), "Dump", self)
        dump_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(2))
        toolbar.addAction(dump_action)

        inject_action = QAction(QIcon("icons/inject.png"), "Inject", self)
        inject_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(3))
        toolbar.addAction(inject_action)

        modify_action = QAction(QIcon("icons/modify.png"), "Modify", self)
        modify_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(4))
        toolbar.addAction(modify_action)

        trophy_action = QAction(QIcon("icons/trophy.png"), "Trophy", self)
        trophy_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(5))
        toolbar.addAction(trophy_action)

        trp_create_action = QAction(QIcon("icons/create.png"), "Create TRP", self)
        trp_create_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(6))
        toolbar.addAction(trp_create_action)

        wallpaper_action = QAction(QIcon("icons/wallpaper.png"), "Wallpaper", self)
        wallpaper_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(7))
        toolbar.addAction(wallpaper_action)

        toolbar.setStyleSheet(icon_style)

    def create_statusbar(self):
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready")
        self.statusBar.setStyleSheet("QStatusBar { background-color: #34495e; color: white; }")

    def setup_info_tab(self):
        layout = QVBoxLayout(self.info_tab)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Key", "Value", "Description"])
        self.tree.setColumnWidth(0, 200)
        self.tree.setColumnWidth(1, 200)
        self.tree.setStyleSheet("""
            QTreeWidget {
                background-color: white;
                color: black;
                font-size: 14px;
                border: none;
            }
            QTreeWidget::item {
                color: black;
            }
        """)
        self.tree.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.tree)

        # Dictionary of descriptions for each key
        self.key_descriptions = {
            "pkg_magic": "Magic number identifying the PKG file format",
            "pkg_type": "Type of the PKG (e.g., 0x1 for PS4)",
            "pkg_0x008": "Reserved field, usually 0",
            "pkg_file_count": "Number of files contained in the PKG",
            "pkg_entry_count": "Number of entries in the PKG table",
            "pkg_sc_entry_count": "Number of entries in the SC (System Contents) table",
            "pkg_entry_count_2": "Secondary entry count (usually same as pkg_entry_count)",
            "pkg_table_offset": "Offset to the start of the PKG table",
            "pkg_entry_data_size": "Size of the entry data in bytes",
            "pkg_body_offset": "Offset to the start of the PKG body",
            "pkg_body_size": "Size of the PKG body in bytes",
            "pkg_content_offset": "Offset to the start of the content",
            "pkg_content_size": "Size of the content in bytes",
            "pkg_content_id": "Unique identifier for the PKG content",
            "pkg_padding": "Padding data",
            "pkg_drm_type": "DRM type used (e.g., PS4)",
            "pkg_content_type": "Type of content in the PKG",
            "pkg_content_flags": "Flags describing the content",
            "pkg_promote_size": "Size of promotional content",
            "pkg_version_date": "Version date of the PKG",
            "pkg_version_hash": "Version hash",
            "pkg_0x088": "Reserved field",
            "pkg_0x08C": "Reserved field",
            "pkg_0x090": "Reserved field",
            "pkg_0x094": "Reserved field",
            "pkg_iro_tag": "IRO (Installation Requirement Option) tag",
            "pkg_drm_type_version": "Version of the DRM type",
            "Main Entry 1 Hash": "Hash of the first main entry",
            "Main Entry 2 Hash": "Hash of the second main entry",
            "Digest Table Hash": "Hash of the digest table",
            "Main Table Hash": "Hash of the main table",
            "DESTINATION_COUNTRY": "Region or country code for which the package is intended"
        }

    def create_file_selection_layout(self, entry_widget, browse_function):
        layout = QHBoxLayout()
        entry_widget.setPlaceholderText("Select file")
        entry_widget.setStyleSheet("QLineEdit { background-color: white; color: #2c3e50; font-size: 14px; padding: 8px; border: none; border-radius: 5px; }")
        button = QPushButton("Browse")
        button.setStyleSheet("QPushButton { font-size: 14px; padding: 8px 15px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        button.clicked.connect(browse_function)
        layout.addWidget(entry_widget)
        layout.addWidget(button)
        return layout

    def setup_extract_tab(self):
        layout = QVBoxLayout(self.extract_tab)
        
        layout.addLayout(self.create_file_selection_layout(self.extract_out_entry, lambda: self.browse_out(self.extract_out_entry)))

        self.extract_log = QTextEdit()
        self.extract_log.setReadOnly(True)
        self.extract_log.setStyleSheet("QTextEdit { background-color: white; color: #2c3e50; font-size: 14px; border: none; border-radius: 5px; }")
        layout.addWidget(self.extract_log)

        run_button = QPushButton("Execute Extract")
        run_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        run_button.clicked.connect(lambda: self.run_command("extract"))
        layout.addWidget(run_button)
        
        layout.addStretch(1)

    def setup_dump_tab(self):
        layout = QVBoxLayout(self.dump_tab)
        
        layout.addLayout(self.create_file_selection_layout(self.dump_pkg_entry, lambda: self.browse_pkg(self.dump_pkg_entry)))
        layout.addLayout(self.create_file_selection_layout(self.dump_out_entry, lambda: self.browse_out(self.dump_out_entry)))

        dump_button = QPushButton("Execute Dump")
        dump_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        dump_button.clicked.connect(lambda: self.run_command("dump"))
        layout.addWidget(dump_button)
        
        # Add a visual separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        layout.addWidget(separator)

        # Add widgets for reverse dump
        layout.addWidget(QLabel("Reverse Dump (reinsert modified files into the PKG):"))
        self.reverse_dump_in_entry = QLineEdit()
        layout.addLayout(self.create_file_selection_layout(self.reverse_dump_in_entry, lambda: self.browse_dir(self.reverse_dump_in_entry)))

        reverse_dump_button = QPushButton("Execute Reverse Dump")
        reverse_dump_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #e74c3c; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #c0392b; }")
        reverse_dump_button.clicked.connect(self.execute_reverse_dump)
        layout.addWidget(reverse_dump_button)
        
        layout.addStretch(1)

    def browse_dir(self, entry_widget):
        directory = QFileDialog.getExistingDirectory(self, "Select directory")
        if directory:
            entry_widget.setText(directory)

    def execute_reverse_dump(self):
        input_dir = self.reverse_dump_in_entry.text()
        if not input_dir:
            QMessageBox.warning(self, "Warning", "Please select an input directory for reverse dump.")
            return

        pkg_file = self.dump_pkg_entry.text()
        if not pkg_file:
            QMessageBox.warning(self, "Warning", "Please select a PKG file first.")
            return

        try:
            reply = QMessageBox.question(self, 'Confirm', 
                                         "You are about to perform a reverse dump. This operation will modify the original PKG file. Do you want to continue?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                progress = QProgressDialog("Executing reverse dump...", "Cancel", 0, len(self.package.files), self)
                progress.setWindowModality(Qt.WindowModal)
                progress.setWindowTitle("Progress")
                progress.show()

                def update_progress(status):
                    progress.setValue(progress.value() + 1)
                    QApplication.processEvents()

                repacker = Repack(pkg_file, self.package.pkg_table_offset, self.package.pkg_entry_count, self.package.files)
                result = repacker.reverse_dump(input_dir)
                
                progress.close()
                QMessageBox.information(self, "Reverse Dump Result", result)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error during reverse dump: {str(e)}")

    def setup_inject_tab(self):
        layout = QVBoxLayout(self.inject_tab)
        
        layout.addLayout(self.create_file_selection_layout(self.inject_pkg_entry, lambda: self.browse_pkg(self.inject_pkg_entry)))
        layout.addLayout(self.create_file_selection_layout(self.inject_file_entry, lambda: self.browse_pkg(self.inject_file_entry)))
        layout.addLayout(self.create_file_selection_layout(self.inject_input_entry, lambda: self.browse_pkg(self.inject_input_entry)))

        run_button = QPushButton("Execute Inject")
        run_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        run_button.clicked.connect(lambda: self.run_command("inject"))
        layout.addWidget(run_button)
        
        layout.addStretch(1)

    def setup_modify_tab(self):
        layout = QVBoxLayout(self.modify_tab)
        
        layout.addLayout(self.create_file_selection_layout(self.modify_pkg_entry, lambda: self.browse_pkg(self.modify_pkg_entry)))
        
        hex_layout = QHBoxLayout()
        self.hex_viewer.setReadOnly(True)
        self.hex_viewer.setStyleSheet("QTextEdit { background-color: white; color: #2c3e50; font-size: 14px; border: none; border-radius: 5px; }")
        hex_layout.addWidget(self.hex_viewer)
        self.hex_editor.setStyleSheet("QTextEdit { background-color: white; color: #2c3e50; font-size: 14px; border: none; border-radius: 5px; }")
        hex_layout.addWidget(self.hex_editor)
        layout.addLayout(hex_layout)

        offset_layout = QHBoxLayout()
        offset_layout.addWidget(QLabel("Offset (hex):"))
        self.offset_entry = QLineEdit()
        self.offset_entry.setPlaceholderText("Enter offset in hexadecimal")
        self.offset_entry.setValidator(QRegExpValidator(QRegExp("[0-9A-Fa-f]+")))
        self.offset_entry.setStyleSheet("QLineEdit { font-size: 14px; padding: 8px; border: none; border-radius: 5px; }")
        offset_layout.addWidget(self.offset_entry)
        layout.addLayout(offset_layout)

        data_layout = QHBoxLayout()
        data_layout.addWidget(QLabel("New Data (hex):"))
        self.data_entry = QLineEdit()
        self.data_entry.setPlaceholderText("Enter new data in hexadecimal")
        self.data_entry.setValidator(QRegExpValidator(QRegExp("[0-9A-Fa-f]+")))
        self.data_entry.setStyleSheet("QLineEdit { font-size: 14px; padding: 8px; border: none; border-radius: 5px; }")
        data_layout.addWidget(self.data_entry)
        layout.addLayout(data_layout)

        search_layout = QHBoxLayout()
        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Find hex")
        self.search_entry.setStyleSheet("QLineEdit { font-size: 14px; padding: 8px; border: none; border-radius: 5px; }")
        search_button = QPushButton("Trova")
        search_button.setStyleSheet("QPushButton { font-size: 14px; padding: 8px 15px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        search_button.clicked.connect(self.search_hex)
        search_layout.addWidget(self.search_entry)
        search_layout.addWidget(search_button)
        layout.addLayout(search_layout)

        replace_layout = QHBoxLayout()
        self.replace_entry = QLineEdit()
        self.replace_entry.setPlaceholderText("Replace hex")
        self.replace_entry.setStyleSheet("QLineEdit { font-size: 14px; padding: 8px; border: none; border-radius: 5px; }")
        replace_button = QPushButton("Replace")
        replace_button.setStyleSheet("QPushButton { font-size: 14px; padding: 8px 15px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        replace_button.clicked.connect(self.replace_hex)
        replace_layout.addWidget(self.replace_entry)
        replace_layout.addWidget(replace_button)
        layout.addLayout(replace_layout)

        run_button = QPushButton("Execute Modify")
        run_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        run_button.clicked.connect(lambda: self.run_command("modify"))
        layout.addWidget(run_button)
        
        layout.addStretch(1)

    def setup_trophy_tab(self):
        layout = QVBoxLayout(self.trophy_tab)
        
        self.trophy_entry = QLineEdit()
        layout.addLayout(self.create_file_selection_layout(self.trophy_entry, self.browse_trophy))

        self.trophy_info = QTextEdit()
        self.trophy_info.setReadOnly(True)
        self.trophy_info.setStyleSheet("QTextEdit { background-color: white; color: #2c3e50; font-size: 14px; border: none; border-radius: 5px; }")
        layout.addWidget(self.trophy_info)

        self.trophy_image_label = QLabel("No trophy image")
        self.trophy_image_label.setFixedSize(300, 300)
        self.trophy_image_label.setAlignment(Qt.AlignCenter)
        self.trophy_image_label.setStyleSheet("background-color: white; border: 1px solid white; border-radius: 10px;")
        layout.addWidget(self.trophy_image_label)

        self.trophy_edit_button = QPushButton("Edit Trophy Info")
        self.trophy_edit_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        self.trophy_edit_button.clicked.connect(self.edit_trophy_info)
        layout.addWidget(self.trophy_edit_button)

        self.trophy_recompile_button = QPushButton("Recompile TRP")
        self.trophy_recompile_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        self.trophy_recompile_button.clicked.connect(self.recompile_trp)
        layout.addWidget(self.trophy_recompile_button)

        run_button = QPushButton("Execute Trophy")
        run_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        run_button.clicked.connect(lambda: self.run_command("trophy"))
        layout.addWidget(run_button)
        
        layout.addStretch(1)
        self.trophy_files = [] 
        
        load_trophy_files_button = QPushButton("Load trophy files")
        load_trophy_files_button.clicked.connect(self.load_trophy_files)
        layout.addWidget(load_trophy_files_button)

    def load_trophy_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Seleziona i file dei trofei", "", "Tutti i file (*.*)")
        for file in files:
            with open(file, 'rb') as f:
                data = f.read()
            archiver = Archiver(len(self.trophy_files), os.path.basename(file), 0, len(data), data)
            self.trophy_files.append(archiver)
        QMessageBox.information(self, "Successo", f"Caricati {len(files)} file dei trofei")

    def setup_trp_create_tab(self):
        layout = QVBoxLayout(self.trp_create_tab)
        
        self.trp_entry = QLineEdit()
        layout.addLayout(self.create_file_selection_layout(self.trp_entry, self.browse_trophy))

        self.trp_info = QTextEdit()
        self.trp_info.setReadOnly(True)
        self.trp_info.setStyleSheet("QTextEdit { background-color: white; color: #2c3e50; font-size: 14px; border: none; border-radius: 5px; }")
        layout.addWidget(self.trp_info)

        self.trp_trophy_count = QSpinBox()
        self.trp_trophy_count.setRange(1, 100)
        self.trp_trophy_count.setValue(1)
        layout.addWidget(self.trp_trophy_count)

        self.trp_trophy_description = QTextEdit()
        self.trp_trophy_description.setPlaceholderText("Enter trophy descriptions and information")
        self.trp_trophy_description.setStyleSheet("QTextEdit { background-color: white; color: #2c3e50; font-size: 14px; border: none; border-radius: 5px; }")
        layout.addWidget(self.trp_trophy_description)

        run_button = QPushButton("Create TRP")
        run_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        run_button.clicked.connect(lambda: self.run_command("create_trp"))
        layout.addWidget(run_button)
        
        layout.addStretch(1)

    def setup_file_browser_tab(self):
        layout = QVBoxLayout(self.file_browser_tab)
        
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["File Name", "Size", "Type"])
        self.file_tree.setColumnWidth(0, 300)
        self.file_tree.setColumnWidth(1, 100)
        self.file_tree.setColumnWidth(2, 100)
        self.file_tree.setStyleSheet("""
            QTreeWidget { 
                background-color: white; 
                color: black; 
                font-size: 14px; 
                border: none; 
            }
            QTreeWidget::item { 
                color: black; 
            }
        """)
        self.file_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(self.show_context_menu)
        self.file_tree.itemDoubleClicked.connect(self.on_item_double_clicked)
        layout.addWidget(self.file_tree)

    def show_context_menu(self, position):
        menu = QMenu()
        extract_action = menu.addAction("Extract")
        hex_view_action = menu.addAction("View as Hex")
        text_view_action = menu.addAction("View as Text")
        
        extract_action.triggered.connect(self.extract_selected_file)
        hex_view_action.triggered.connect(self.view_file_as_hex)
        text_view_action.triggered.connect(self.view_file_as_text)
        
        menu.exec_(self.file_tree.viewport().mapToGlobal(position))

    def on_item_double_clicked(self, item, column):
        file_info = item.data(0, Qt.UserRole)
        if file_info:
            self.view_file_content(file_info)

    def view_file_content(self, file_info):
        try:
            data = self.package.read_file(file_info['id'])
            if self.is_text_file(file_info['name']):
                content = data.decode('utf-8', errors='replace')
                self.show_text_content(content, file_info['name'])
            else:
                hex_view = ' '.join([f'{b:02X}' for b in data])
                self.show_hex_content(hex_view, file_info['name'])
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Unable to read file content: {str(e)}")

    def show_text_content(self, content, file_name):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Content of {file_name}")
        layout = QVBoxLayout(dialog)
        text_edit = QTextEdit()
        text_edit.setPlainText(content)
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)
        dialog.resize(600, 400)
        dialog.exec_()

    def show_hex_content(self, content, file_name):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Hex view of {file_name}")
        layout = QVBoxLayout(dialog)
        text_edit = QTextEdit()
        text_edit.setPlainText(content)
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Courier"))
        layout.addWidget(text_edit)
        dialog.resize(600, 400)
        dialog.exec_()

    def setup_wallpaper_tab(self):
        layout = QVBoxLayout(self.wallpaper_tab)
        
        self.wallpaper_tree = QTreeWidget()
        self.wallpaper_tree.setHeaderLabels(["File Name", "Size"])
        self.wallpaper_tree.setColumnWidth(0, 200)
        self.wallpaper_tree.setColumnWidth(1, 100)
        self.wallpaper_tree.setStyleSheet("""
            QTreeWidget { 
                background-color: white; 
                color: black; 
                font-size: 14px; 
                border: none; 
            }
            QTreeWidget::item { 
                color: black; 
            }
        """)
        self.wallpaper_tree.itemClicked.connect(self.display_selected_wallpaper)
        layout.addWidget(self.wallpaper_tree)

        self.wallpaper_viewer = QLabel()
        self.wallpaper_viewer.setAlignment(Qt.AlignCenter)
        self.wallpaper_viewer.setStyleSheet("background-color: white; border: 1px solid #3498db; border-radius: 5px;")
        layout.addWidget(self.wallpaper_viewer)

        button_layout = QHBoxLayout()
        self.prev_button = QPushButton("Next")
        self.next_button = QPushButton("Previous")
        self.fullscreen_button = QPushButton("Fullscreen")
        self.prev_button.clicked.connect(self.show_previous_wallpaper)
        self.next_button.clicked.connect(self.show_next_wallpaper)
        self.fullscreen_button.clicked.connect(self.show_fullscreen_wallpaper)
        button_layout.addWidget(self.prev_button)
        button_layout.addWidget(self.next_button)
        button_layout.addWidget(self.fullscreen_button)
        layout.addLayout(button_layout)

        self.modify_wallpaper_button = QPushButton("Edit background")
        self.modify_wallpaper_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        self.modify_wallpaper_button.clicked.connect(self.modify_wallpaper)
        layout.addWidget(self.modify_wallpaper_button)

    def load_wallpapers(self):
        if self.package:
            self.wallpaper_tree.clear()
            wallpaper_files = [
                f for f in self.package.files.values() 
                if isinstance(f.get("name"), str) and f["name"].lower().endswith(('.png', '.jpg', '.jpeg'))
            ]
            for file_info in wallpaper_files:
                item = QTreeWidgetItem(self.wallpaper_tree)
                item.setText(0, file_info["name"])
                item.setText(1, str(file_info['size']))
            Logger.log_information(f"Loaded {len(wallpaper_files)} wallpapers")
            if not wallpaper_files:
                Logger.log_warning("No wallpaper files found in the package")
        else:
            QMessageBox.warning(self, "Warning", "No PKG file loaded. Please load a PKG file first.")

    def display_selected_wallpaper(self, item, column):
        try:
            file_name = item.text(0)
            Logger.log_information(f"Attempting to display wallpaper: {file_name}")
            
            file_info = next((f for f in self.package.files.values() if f.get("name") == file_name), None)
            if file_info:
                try:
                    image_data = self.package.read_file(file_info["id"])
                    Logger.log_information(f"Image data read, size: {len(image_data)} bytes")
                    
                    try:
                        pil_image = Image.open(io.BytesIO(image_data))
                        Logger.log_information(f"Image loaded with PIL: format={pil_image.format}, size={pil_image.size}, mode={pil_image.mode}")
                        
                        # Converti l'immagine in RGB se è in modalità RGBA
                        if pil_image.mode == 'RGBA':
                            pil_image = pil_image.convert('RGB')
                        
                        qimage = QImage(pil_image.tobytes(), pil_image.width, pil_image.height, QImage.Format_RGB888)
                        pixmap = QPixmap.fromImage(qimage)
                        
                        if not pixmap.isNull():
                            scaled_pixmap = pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                            self.wallpaper_viewer.setPixmap(scaled_pixmap)
                            self.wallpaper_viewer.setAlignment(Qt.AlignCenter)
                            Logger.log_information(f"Wallpaper displayed successfully: {file_name}")
                        else:
                            raise Exception("Failed to create valid QPixmap")
                    except Exception as e:
                        Logger.log_error(f"Error processing image: {str(e)}")
                        QMessageBox.warning(self, "Error", f"Error processing image: {str(e)}")
                except Exception as e:
                    Logger.log_error(f"Error during image loading: {str(e)}")
                    QMessageBox.warning(self, "Error", f"Unable to load image: {str(e)}")
            else:
                Logger.log_warning(f"File not found in package: {file_name}")
                QMessageBox.warning(self, "File not found", f"The file {file_name} does not exist in the package.")
        except Exception as e:
            Logger.log_error(f"Unexpected error in display_selected_wallpaper: {str(e)}")
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {str(e)}")

    def show_previous_wallpaper(self):
        current_row = self.wallpaper_list.currentRow()
        if current_row > 0:
            self.wallpaper_list.setCurrentRow(current_row - 1)
            self.display_selected_wallpaper(self.wallpaper_list.currentItem())

    def show_next_wallpaper(self):
        try:
            current_row = self.wallpaper_list.currentRow()
            if current_row < self.wallpaper_list.count() - 1:
                self.wallpaper_list.setCurrentRow(current_row + 1)
                self.display_selected_wallpaper(self.wallpaper_list.currentItem())
        except Exception as e:
            logging.error(f"Error during the display of the next wallpaper: {e}")
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")

    def show_fullscreen_wallpaper(self):
        current_item = self.wallpaper_tab.currentItem()
        if current_item:
            file_info = next((f for f in self.wallpaper_files if f["name"] == current_item.text()), None)
            if file_info:
                pixmap = QPixmap()
                pixmap.loadFromData(self.package.read_file(file_info["id"]))
                fullscreen_dialog = QDialog(self)
                fullscreen_dialog.setWindowTitle("Fullscreen Wallpaper")
                layout = QVBoxLayout(fullscreen_dialog)
                label = QLabel()
                label.setPixmap(pixmap.scaled(fullscreen_dialog.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))
                layout.addWidget(label)
                fullscreen_dialog.showFullScreen()

    def modify_wallpaper(self):
        selected_items = self.wallpaper_list.selectedItems()  
        if selected_items:
            item = selected_items[0]
            file_name = item.text()
            file_info = next((f for f in self.wallpaper_files if f["name"] == file_name), None)
            if file_info:
                # Extract the file temporarily
                temp_file_path = os.path.join(self.temp_directory, file_name)
                with open(temp_file_path, 'wb') as temp_file:
                    temp_file.write(self.package.read_file(file_info["id"]))

                # Open the default image editor for the operating system
                try:
                    if sys.platform == "win32":
                        os.startfile(temp_file_path)
                    elif sys.platform == "darwin":
                        subprocess.call(["open", temp_file_path])
                    else:
                        subprocess.call(["xdg-open", temp_file_path])
                    
                    QMessageBox.information(self, "Modify Wallpaper", f"Modifying wallpaper: {file_name}")
                    
                    # Wait for the user to finish editing and close the editor
                    reply = QMessageBox.question(self, 'Confirm', 
                                                 "Have you finished modifying the wallpaper?",
                                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                    
                    if reply == QMessageBox.Yes:
                        # Read the modified file and update it in the package
                        with open(temp_file_path, 'rb') as modified_file:
                            modified_data = modified_file.read()
                        self.package.update_file(file_info["id"], modified_data)
                        
                        # Update the display
                        self.display_selected_wallpaper(item)
                        QMessageBox.information(self, "Success", "Wallpaper updated successfully")
                    
                    # Remove the temporary file
                    os.remove(temp_file_path)
                
                except Exception as e:
                    Logger.log_error(f"Error opening image editor: {e}")
                    QMessageBox.critical(self, "Error", f"Error opening image editor: {e}")
            else:
                QMessageBox.warning(self, "Warning", "Selected wallpaper not found in the package.")
        else:
            QMessageBox.warning(self, "Warning", "No wallpaper selected.")

    def browse_pkg(self, entry_widget=None):
        filename, _ = QFileDialog.getOpenFileName(self, "Select PKG file", "", "PKG files (*.pkg)")
        if filename:
            self.current_pkg = os.path.dirname(filename)
            self.update_pkg_entries(filename)  
            self.file_path = filename
            try:
                self.package = Package(self.file_path)
                self.update_info(self.package.get_info())
                self.load_wallpapers()
                self.load_pkg_icon()
                self.load_files()  # Aggiungi questa riga per caricare i file nel browser
                Logger.log_information(f"PKG file loaded successfully: {filename}")
            except Exception as e:
                Logger.log_error(f"Error loading PKG file: {e}")
                QMessageBox.critical(self, "Error", f"Error loading PKG file: {e}")

    def update_info(self, info):
        if info:
            self.tree.clear()
            for key, value in info.items():
                item = QTreeWidgetItem(self.tree)
                item.setText(0, str(key))
                item.setText(1, str(value))
                if key in self.key_descriptions:
                    item.setText(2, self.key_descriptions[key])
            Logger.log_information("PKG information updated successfully.")
        else:
            QMessageBox.information(self, "Information", "No information found in the PKG file.")
            Logger.log_warning("No information found in the PKG file.")

    def load_files(self):
        if self.package:
            self.file_tree.clear()
            for file_id, file_info in self.package.files.items():
                item = QTreeWidgetItem(self.file_tree)
                item.setText(0, file_info.get("name", f"file_{file_id}"))
                item.setText(1, str(file_info['size']))
                item.setText(2, self.get_file_type(os.path.splitext(file_info.get("name", ""))[1]))
                item.setData(0, Qt.UserRole, file_info)
            self.file_tree.sortItems(0, Qt.AscendingOrder)
            Logger.log_information(f"Loaded {len(self.package.files)} files into the file browser")
        else:
            Logger.log_warning("No PKG file loaded. Unable to populate file browser.")

    def replace_hex(self):
        if not self.offset_entry.text():
            QMessageBox.critical(self, "Error", "No offset specified")
            return
        
        offset = int(self.offset_entry.text(), 16)
        replace_hex = self.replace_entry.text()
        try:
            replace_bytes = bytes.fromhex(replace_hex)
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid hex replace string")
            return

        with open(self.package.original_file, 'r+b') as f:
            f.seek(offset)
            f.write(replace_bytes)
        
        QMessageBox.information(self, "Replace", "Replacement completed")
        self.update_hex_view()

    def update_extract_log(self, message):
        self.extract_log.append(message)

    def update_hex_view(self):
        if self.package:
            with open(self.package.original_file, 'rb') as f:
                hex_data = f.read(1024)  # Read first 1024 bytes
            hex_view = ' '.join([f'{b:02X}' for b in hex_data])
            self.hex_viewer.setPlainText(hex_view)
            self.hex_editor.setPlainText(hex_view)

    def edit_trophy_info(self):
        Logger.log_information("Edit trophy info button clicked.")
        try:
            trophy_file_path, _ = QFileDialog.getOpenFileName(self, "Select Trophy file", "", "Trophy files (*.trp)")
            if trophy_file_path:
                with open(trophy_file_path, 'r+b') as f:
                    data = f.read()
                    # Aggiungi qui la logica per modificare le informazioni del trofeo
                    # Esempio: modifica il titolo del trofeo
                    new_title = "Nuovo Titolo Trofeo"
                    title_offset = data.find(b"Title")
                    if title_offset != -1:
                        f.seek(title_offset + len("Title"))
                        f.write(new_title.encode('utf-8'))
                        Logger.log_information("Trophy title updated successfully.")
                    else:
                        Logger.log_error("Title not found in the trophy file.")
                        QMessageBox.critical(self, "Error", "Title not found in the trophy file.")
                    
                    # Aggiungi la logica per modificare altre informazioni del trofeo
                    new_description = "Nuova Descrizione Trofeo"
                    description_offset = data.find(b"Description")
                    if description_offset != -1:
                        f.seek(description_offset + len("Description"))
                        f.write(new_description.encode('utf-8'))
                        Logger.log_information("Trophy description updated successfully.")
                    else:
                        Logger.log_error("Description not found in the trophy file.")
                        QMessageBox.critical(self, "Error", "Description not found in the trophy file.")
                    
                    new_npcomm_id = "NPWR12345_00"
                    npcomm_id_offset = data.find(b"NPCommID")
                    if npcomm_id_offset != -1:
                        f.seek(npcomm_id_offset + len("NPCommID"))
                        f.write(new_npcomm_id.encode('utf-8'))
                        Logger.log_information("Trophy NPCommID updated successfully.")
                    else:
                        Logger.log_error("NPCommID not found in the trophy file.")
                        QMessageBox.critical(self, "Error", "NPCommID not found in the trophy file.")
        except Exception as e:
            Logger.log_error(f"Error editing trophy info: {e}")
            QMessageBox.critical(self, "Error", f"Error editing trophy info: {e}")

    def recompile_trp(self):
        Logger.log_information("Recompile TRP button clicked.")
        try:
            trp_file_path, _ = QFileDialog.getOpenFileName(self, "Select TRP file", "", "TRP files (*.trp)")
            if trp_file_path:
                output_trp_path, _ = QFileDialog.getSaveFileName(self, "Save Recompiled TRP file", "", "TRP files (*.trp)")
                if output_trp_path:
                   
                    shutil.copy(trp_file_path, output_trp_path)
                    Logger.log_information("TRP file recompiled successfully.")
                    QMessageBox.information(self, "Success", "TRP file recompiled successfully.")
                    with open(output_trp_path, 'r+b') as f:
                        data = f.read()
                        new_data = data.replace(b"OldData", b"NewData")
                        f.seek(0)
                        f.write(new_data)
                        Logger.log_information("TRP file content updated successfully.")
        except Exception as e:
            Logger.log_error(f"Error recompiling TRP file: {e}")
            QMessageBox.critical(self, "Error", f"Error recompiling TRP file: {e}")

    def display_img(self, image_path):
        pixmap = QPixmap(image_path)
        self.image_label.setPixmap(pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def browse_pkg(self, entry_widget=None):
        filename, _ = QFileDialog.getOpenFileName(self, "Select PKG file", "", "PKG files (*.pkg)")
        if filename:
            self.current_pkg = os.path.dirname(filename)
            self.update_pkg_entries(filename)  
            self.file_path = filename
            try:
                self.package = Package(self.file_path)
                self.update_info(self.package.get_info())
                self.load_wallpapers()
                self.load_pkg_icon()
                self.load_files()  # Aggiungi questa riga per caricare i file nel browser
                Logger.log_information(f"PKG file loaded successfully: {filename}")
            except Exception as e:
                Logger.log_error(f"Error loading PKG file: {e}")
                QMessageBox.critical(self, "Error", f"Error loading PKG file: {e}")

    def search_hex(self):
        search_term = self.search_entry.text()
        try:
            search_bytes = bytes.fromhex(search_term)
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid hex string")
            return

        if self.package:
            with open(self.package.original_file, 'rb') as f:
                content = f.read()
                index = content.find(search_bytes)
                if index != -1:
                    self.offset_entry.setText(f"{index:X}")
                    QMessageBox.information(self, "Found", f"Hex sequence found at offset: {index:X}")
                else:
                    QMessageBox.information(self, "Not found", "Hex sequence not found in file")
        else:
            QMessageBox.critical(self, "Error", "No PKG file loaded")

    def browse_trophy(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Trophy file", "", "Trophy files (*.trp)")
        if filename:
            self.trophy_entry.setText(filename)
            self.load_trophy_info(filename)

    def load_trophy_info(self, filename):
        try:
            trp_reader = TRPReader(filename)
            trp_reader.load()
            
            info = f"Title: {trp_reader._title}\n"
            info += f"NPCommID: {trp_reader._npcommid}\n"
            info += f"Number of trophies: {len(trp_reader._trophyList)}\n\n"
            
            for trophy in trp_reader._trophyList:
                info += f"Trophy: {trophy.name}\n"
                info += f"Size: {trophy.size} bytes\n\n"
            
            self.trophy_info.setText(info)
            
            # Carica l'icona del trofeo
            icon_trophy = next((t for t in trp_reader._trophyList if t.name.upper() == "ICON0.PNG"), None)
            if icon_trophy:
                pixmap = QPixmap()
                pixmap.loadFromData(icon_trophy.bytes)
                self.trophy_image_label.setPixmap(pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        except Exception as e:
            self.trophy_info.setText(f"Error loading trophy file: {str(e)}")
            Logger.log_error(f"Error loading trophy file: {e}")

    def extract_selected_file(self):
        selected_items = self.file_tree.selectedItems()
        if selected_items:
            item = selected_items[0]
            file_name = item.text(0)
            Logger.log_information(f"Attempting to extract file: {file_name}")
            if self.package and self.package.files:
                Logger.log_information(f"Package contains {len(self.package.files)} files")
                file_info = next((f for f in self.package.files.values() if f.get('name') == file_name), None)
                if file_info:
                    Logger.log_information(f"File info: {file_info}")
                    output_path, _ = QFileDialog.getSaveFileName(self, "Save File", file_name)
                    if output_path:
                        try:
                            self.extract_file(self.package.original_file, file_info, output_path, self.update_extract_log)
                            QMessageBox.information(self, "Success", f"File extracted: {output_path}")
                            return f"File extracted: {output_path}"
                        except Exception as e:
                            Logger.log_error(f"Failed to extract file: {str(e)}")
                            QMessageBox.critical(self, "Error", f"Failed to extract file: {str(e)}")
                else:
                    Logger.log_warning(f"File {file_name} not found in package files")
                    QMessageBox.warning(self, "Warning", f"File {file_name} not found in the package.")
            else:
                Logger.log_error("No package loaded or package has no files")
                QMessageBox.warning(self, "Warning", "No package loaded or package has no files.")
        else:
            Logger.log_warning("No file selected for extraction")
            QMessageBox.warning(self, "Warning", "No file selected.")
        return None

    def load_files(self):
        if self.package:
            self.file_tree.clear()
            for file_id, file_info in self.package.files.items():
                item = QTreeWidgetItem(self.file_tree)
                item.setText(0, file_info.get("name", f"file_{file_id}"))
                item.setText(1, str(file_info['size']))
                item.setText(2, self.get_file_type(os.path.splitext(file_info.get("name", ""))[1]))
                item.setData(0, Qt.UserRole, file_info)
            self.file_tree.sortItems(0, Qt.AscendingOrder)
            Logger.log_information(f"Loaded {len(self.package.files)} files into the file browser")
        else:
            Logger.log_warning("No PKG file loaded. Unable to populate file browser.")

    def on_item_double_clicked(self, item, column):
        file_info = item.data(0, Qt.UserRole)
        if file_info:
            self.view_file_content(file_info)

    def view_file_content(self, file_info):
        try:
            data = self.package.read_file(file_info['id'])
            if self.is_text_file(file_info['name']):
                content = data.decode('utf-8', errors='replace')
                self.show_text_content(content, file_info['name'])
            else:
                hex_view = ' '.join([f'{b:02X}' for b in data])
                self.show_hex_content(hex_view, file_info['name'])
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Unable to read file content: {str(e)}")

    def show_text_content(self, content, file_name):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Content of {file_name}")
        layout = QVBoxLayout(dialog)
        text_edit = QTextEdit()
        text_edit.setPlainText(content)
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)
        dialog.resize(600, 400)
        dialog.exec_()

    def show_hex_content(self, content, file_name):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Hex view of {file_name}")
        layout = QVBoxLayout(dialog)
        text_edit = QTextEdit()
        text_edit.setPlainText(content)
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Courier"))
        layout.addWidget(text_edit)
        dialog.resize(600, 400)
        dialog.exec_()

    def is_text_file(self, file_name):
        text_extensions = ['.txt', '.xml', '.json', '.cfg', '.ini', '.log']
        return any(file_name.lower().endswith(ext) for ext in text_extensions)

    def get_file_type(self, extension):
        file_types = {
            '.png': 'Image',
            '.jpg': 'Image',
            '.jpeg': 'Image',
            '.trp': 'Trophy',
            '.sfo': 'System File',
            '.at3': 'Audio',
            '.mp3': 'Audio',
            '.txt': 'Text',
            '.xml': 'XML',
            '.sfm': 'Trophy Config',
            '.pfd': 'Trophy Data'
        }
        return file_types.get(extension, 'Unknown')

    def get_file_description(self, file_name, file_type):
        descriptions = {
            'TROPCONF.SFM': 'Trophy configuration file',
            'TROP.SFM': 'Default language trophy configuration',
            'ICON0.PNG': 'Main trophy icon',
            'TROP000.PNG': 'Trophy icon',
            'GR0000.PNG': 'Trophy group icon'
        }
        
        if file_name in descriptions:
            return descriptions[file_name]
        elif file_type == 'Trophy':
            return 'Trophy installer file'
        elif file_name.startswith('TROP') and file_name.endswith('.PNG'):
            return 'Trophy icon'
        elif file_name.startswith('GR') and file_name.endswith('.PNG'):
            return 'Trophy group icon'
        else:
            return 'Unknown file'


    def view_file_as_hex(self):
        selected_items = self.file_tree.selectedItems()
        if selected_items:
            item = selected_items[0]
            file_info = item.data(0, Qt.UserRole)
            if file_info:
                try:
                    data = self.package.read_file(file_info['id'])
                    hex_view = ' '.join([f'{b:02X}' for b in data])
                    self.show_hex_content(hex_view, file_info['name'])
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Unable to read file content: {str(e)}")
            else:
                QMessageBox.warning(self, "Warning", "No file selected.")
        else:
            QMessageBox.warning(self, "Warning", "No file selected.")

    def view_file_as_text(self):
        selected_items = self.file_tree.selectedItems()
        if selected_items:
            item = selected_items[0]
            file_info = item.data(0, Qt.UserRole)
            if file_info:
                try:
                    data = self.package.read_file(file_info['id'])
                    if self.is_text_file(file_info['name']):
                        content = data.decode('utf-8', errors='replace')
                        self.show_text_content(content, file_info['name'])
                    else:
                        QMessageBox.warning(self, "Warning", "Selected file is not a text file.")
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Unable to read file content: {str(e)}")
            else:
                QMessageBox.warning(self, "Warning", "No file selected.")
        else:
            QMessageBox.warning(self, "Warning", "No file selected.")

    def run_command(self, cmd):
        if self.run_command_callback:
            try:
                result = None 
                if cmd == "extract":
                    result = self.extract_selected_file()
                elif cmd == "dump":
                    output_path = self.dump_out_entry.text()
                    if not output_path:
                        output_path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
                    if not output_path:
                        return  
                    result = self.package.dump(output_path)
                elif cmd == "inject":
                    file_name = self.inject_file_entry.text()
                    input_file = self.inject_input_entry.text()
                    if not file_name or not input_file:
                        QMessageBox.warning(self, "Warning", "Please specify both file to inject and input file.")
                        return
                    file_info = self.package.files.get(file_name)
                    if not file_info:
                        QMessageBox.warning(self, "Warning", "Specified file not found in the package.")
                        return
                    result = inject_file(self.package.original_file, file_info, input_file)
                elif cmd == "modify":
                    offset = self.offset_entry.text()
                    new_data = self.data_entry.text()
                    if not offset or not new_data:
                        QMessageBox.warning(self, "Warning", "Please specify both offset and new data.")
                        return
                    offset = int(offset, 16)
                    new_data = bytes.fromhex(new_data)
                    result = modify_file_header(self.package.original_file, offset, new_data)
                elif cmd == "create_trp":
                    result = self.create_trp()
                else:
                    result = self.run_command_callback(cmd, self.package.original_file, None, None, None)
                if result:
                    QMessageBox.information(self, "Command Result", str(result))
            except Exception as e:
                Logger.log_error(f"Error executing command {cmd}: {str(e)}")
                QMessageBox.critical(self, "Error", str(e))
        else:
            QMessageBox.warning(self, "Warning", "Command callback not set")

    def create_trp(self):
        try:
            trp_creator = TRPCreator()
            trp_creator.SetVersion = 3  
            
            title = QInputDialog.getText(self, "TRP Creation", "Enter TRP Title:")[0]
            npcommid = QInputDialog.getText(self, "TRP Creation", "Enter NPCommID:")[0]
            trophy_count = self.trp_trophy_count.value()
            
            trp_creator.set_title(title)
            trp_creator.set_npcommid(npcommid)
            
            # Usa i file caricati in self.trophy_files
            for trophy_file in self.trophy_files:
                trp_creator._trophyList.append(trophy_file)
            
            output_path, _ = QFileDialog.getSaveFileName(self, "Save TRP File", "", "TRP files (*.trp)")
            if output_path:
                trp_creator.Create(output_path, [tf.name for tf in self.trophy_files])
                return f"File TRP creato: {output_path}"
            else:
                return "Creazione TRP annullata"
        except Exception as e:
            Logger.log_error(f"Errore durante la creazione del TRP: {e}")
            raise

    def load_wallpapers(self):
        if self.package:
            self.wallpaper_tree.clear()
            wallpaper_files = [
                f for f in self.package.files.values() 
                if isinstance(f.get("name"), str) and f["name"].lower().endswith(('.png', '.jpg', '.jpeg'))
            ]
            for file_info in wallpaper_files:
                item = QTreeWidgetItem(self.wallpaper_tree)
                item.setText(0, file_info["name"])
                item.setText(1, str(file_info['size']))
            Logger.log_information(f"Loaded {len(wallpaper_files)} wallpapers")
            if not wallpaper_files:
                Logger.log_warning("No wallpaper files found in the package")
        else:
            QMessageBox.warning(self, "Warning", "No PKG file loaded. Please load a PKG file first.")

    def display_selected_wallpaper(self, item, column):
        try:
            file_name = item.text(0)
            Logger.log_information(f"Attempting to display wallpaper: {file_name}")
            
            file_info = next((f for f in self.package.files.values() if f.get("name") == file_name), None)
            if file_info:
                try:
                    image_data = self.package.read_file(file_info["id"])
                    Logger.log_information(f"Image data read, size: {len(image_data)} bytes")
                    
                    try:
                        pil_image = Image.open(io.BytesIO(image_data))
                        Logger.log_information(f"Image loaded with PIL: format={pil_image.format}, size={pil_image.size}, mode={pil_image.mode}")
                        
                        # Converti l'immagine in RGB se è in modalità RGBA
                        if pil_image.mode == 'RGBA':
                            pil_image = pil_image.convert('RGB')
                        
                        qimage = QImage(pil_image.tobytes(), pil_image.width, pil_image.height, QImage.Format_RGB888)
                        pixmap = QPixmap.fromImage(qimage)
                        
                        if not pixmap.isNull():
                            scaled_pixmap = pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                            self.wallpaper_viewer.setPixmap(scaled_pixmap)
                            self.wallpaper_viewer.setAlignment(Qt.AlignCenter)
                            Logger.log_information(f"Wallpaper displayed successfully: {file_name}")
                        else:
                            raise Exception("Failed to create valid QPixmap")
                    except Exception as e:
                        Logger.log_error(f"Error processing image: {str(e)}")
                        QMessageBox.warning(self, "Error", f"Error processing image: {str(e)}")
                except Exception as e:
                    Logger.log_error(f"Error during image loading: {str(e)}")
                    QMessageBox.warning(self, "Error", f"Unable to load image: {str(e)}")
            else:
                Logger.log_warning(f"File not found in package: {file_name}")
                QMessageBox.warning(self, "File not found", f"The file {file_name} does not exist in the package.")
        except Exception as e:
            Logger.log_error(f"Unexpected error in display_selected_wallpaper: {str(e)}")
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {str(e)}")

    def update_pkg_entries(self, filename):
        # Update all input fields related to the PKG with the new filename
        self.pkg_entry.setText(filename)
        self.dump_pkg_entry.setText(filename)
        self.inject_pkg_entry.setText(filename)
        self.modify_pkg_entry.setText(filename)
        
        # Update other fields if necessary
        # For example, you might want to set a default output directory
        output_dir = os.path.join(os.path.dirname(filename), "output")
        self.extract_out_entry.setText(output_dir)
        self.dump_out_entry.setText(output_dir)

    def closeEvent(self, event):
        # Delete "_temp_output"
        output_folder_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUTPUT_FOLDER)
        shutil.rmtree(output_folder_path, ignore_errors=True)
        super().closeEvent(event)

    def browse_out(self, entry_widget):
        directory = QFileDialog.getExistingDirectory(self, "Select output directory")
        if directory:
            entry_widget.setText(directory)
    def extract_file(self, pkg_path, file_info, output_path, update_callback):
        try:
            with open(pkg_path, 'rb') as pkg_file:
                pkg_file.seek(file_info['offset'])
                data = pkg_file.read(file_info['size'])
            
            with open(output_path, 'wb') as out_file:
                out_file.write(data)
            
            # Estrai sempre icon0.png nella directory del PKG
            if file_info['name'].lower() == 'icon0.png':
                icon_path = os.path.join(os.path.dirname(pkg_path), "icon0.png")
                with open(icon_path, 'wb') as icon_file:
                    icon_file.write(data)
                Logger.log_information(f"icon0.png extracted to: {icon_path}")
            
            if update_callback:
                update_callback(f"Extracted {file_info['name']} to {output_path}")
            
            Logger.log_information(f"File extracted successfully: {output_path}")
            return f"File extracted successfully: {output_path}"
        except Exception as e:
            Logger.log_error(f"Failed to extract file: {str(e)}")
            raise Exception(f"Failed to extract file: {str(e)}")
        
    def load_pkg(self, pkg_path):
        try:
            self.package = Package(pkg_path)
            self.file_path = pkg_path
            self.update_info(self.package.get_info())
            self.load_wallpapers()
            Logger.log_information(f"PKG file loaded successfully: {pkg_path}")
        except Exception as e:
            Logger.log_error(f"Error loading PKG file: {str(e)}")
            QMessageBox.critical(self, "Error", f"Error loading PKG file: {str(e)}")

    def load_pkg_icon(self):
        try:
            Logger.log_information("Attempting to load PKG icon...")
            icon_file = next((f for f in self.package.files.values() if isinstance(f, dict) and f.get('name', '').lower() == 'icon0.png'), None)
            
            if icon_file:
                Logger.log_information(f"Icon file found in package: {icon_file}")
                icon_data = self.package.read_file(icon_file['id'])
                if icon_data:
                    try:
                        pil_image = Image.open(io.BytesIO(icon_data))
                        Logger.log_information(f"Icon loaded with PIL: format={pil_image.format}, size={pil_image.size}, mode={pil_image.mode}")
                        
                        # Converti l'immagine in RGB se è in modalità RGBA
                        if pil_image.mode == 'RGBA':
                            pil_image = pil_image.convert('RGB')
                        
                        qimage = QImage(pil_image.tobytes(), pil_image.width, pil_image.height, QImage.Format_RGB888)
                        pixmap = QPixmap.fromImage(qimage)
                        
                        if not pixmap.isNull():
                            scaled_pixmap = pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                            self.image_label.setPixmap(scaled_pixmap)
                            self.image_label.setAlignment(Qt.AlignCenter)
                            Logger.log_information("PKG icon loaded and displayed successfully.")
                            return
                        else:
                            raise Exception("Failed to create valid QPixmap for icon")
                    except Exception as e:
                        Logger.log_error(f"Error processing icon image from package: {str(e)}")
                else:
                    Logger.log_warning("Failed to read icon file data from package")
            else:
                Logger.log_warning("No icon0.png found in the package.")
            
            # Se non è stato possibile caricare l'icona dal pacchetto, cerchiamo l'icona estratta
            extracted_icon_path = os.path.join(os.path.dirname(self.package.original_file), "icon0.png")
            if os.path.exists(extracted_icon_path):
                Logger.log_information(f"Using extracted icon: {extracted_icon_path}")
                pixmap = QPixmap(extracted_icon_path)
                if not pixmap.isNull():
                    scaled_pixmap = pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    self.image_label.setPixmap(scaled_pixmap)
                    self.image_label.setAlignment(Qt.AlignCenter)
                    Logger.log_information("Extracted PKG icon loaded and displayed successfully.")
                    return
                else:
                    Logger.log_warning("Failed to create QPixmap from extracted icon")
            else:
                Logger.log_warning(f"Extracted icon not found: {extracted_icon_path}")
            
            # Se non è stato possibile caricare né l'icona dal pacchetto né quella estratta, usiamo un'icona di default
            default_icon_path = os.path.join(os.path.dirname(__file__), "default_icon.png")
            if os.path.exists(default_icon_path):
                Logger.log_information(f"Using default icon: {default_icon_path}")
                pixmap = QPixmap(default_icon_path)
                if not pixmap.isNull():
                    scaled_pixmap = pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    self.image_label.setPixmap(scaled_pixmap)
                    self.image_label.setAlignment(Qt.AlignCenter)
                    Logger.log_information("Default icon loaded and displayed successfully.")
                else:
                    Logger.log_warning("Failed to create QPixmap from default icon")
            else:
                Logger.log_error(f"Default icon not found: {default_icon_path}")
                self.image_label.setText("No icon available")
        
        except Exception as e:
            Logger.log_error(f"Unexpected error loading PKG icon: {str(e)}")
            self.image_label.setText("Error loading icon")

def start_gui(run_command_callback, temp_directory):
    app = QApplication(sys.argv)
    app.setStyle('Fusion') 
    window = PS4PKGTool(temp_directory)
    window.run_command_callback = run_command_callback
    window.show()
    sys.exit(app.exec_())
