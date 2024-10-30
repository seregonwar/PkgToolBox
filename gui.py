import logging
import sys
import os
import re
import shutil
import binascii
import subprocess
import io
import json
import requests
import struct  
from PIL import Image, UnidentifiedImageError
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QTreeWidget, QTreeWidgetItem,
                             QFileDialog, QMessageBox, QTabWidget, QScrollArea, QSizePolicy,
                             QTextEdit, QSpinBox, QFrame, QStatusBar, QToolBar, QAction, QMenu, QInputDialog, QHeaderView,
                             QProgressDialog, QListWidget, QListWidgetItem, QDialog, QTableWidget, QTableWidgetItem, QStackedLayout, QStyle, QSplitter,
                             QGroupBox, QComboBox, QCheckBox, QColorDialog, QGridLayout)
from PyQt5.QtGui import QFont, QPixmap, QPalette, QColor, QRegExpValidator, QIcon, QBrush, QImage, QDesktopServices, QFontDatabase
from PyQt5.QtCore import Qt, QRegExp, QSize, QTimer, QUrl, QMimeData
from kiwisolver import *

from packages import PackagePS4, PackagePS5, PackagePS3
from file_operations import extract_file, inject_file, modify_file_header
import concurrent.futures
# Import utilities
from Utilities import Logger, SettingsManager, TRPReader  
from Utilities.Trophy import Archiver, TRPCreator, TRPReader, ESMFDecrypter
from repack import Repack

from PS4_Passcode_Bruteforcer import PS4PasscodeBruteforcer
from PS5_Game_Info import PS5GameInfo

OUTPUT_FOLDER = "._temp_output"
Hexpattern = re.compile(r'[^\x20-\x7E]')


class PS4PKGTool(QMainWindow):
    def __init__(self, temp_directory):
        super().__init__()
        self.setWindowTitle("PKG Tool Box v1.5.2(dev update)")
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

        # Enable drag and drop
        self.setAcceptDrops(True)
        
        # Add a label for drag and drop
        self.drag_drop_label = QLabel("Drag PKG files here", self)
        self.drag_drop_label.setAlignment(Qt.AlignCenter)
        self.drag_drop_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                color: #7f8c8d;
                padding: 20px;
                border: 2px dashed #bdc3c7;
                border-radius: 10px;
                background-color: rgba(236, 240, 241, 0.5);
            }
        """)
        
        # Add the label to the main layout
        main_layout = self.centralWidget().layout()
        main_layout.insertWidget(0, self.drag_drop_label)

        # Aggiungi il pulsante delle impostazioni nella toolbar
        self.setup_settings_button()

    def dragEnterEvent(self, event):
        """Handles the event when a file is dragged over the window"""
        if event.mimeData().hasUrls():
            # Check if at least one file has .pkg extension
            for url in event.mimeData().urls():
                if url.toLocalFile().lower().endswith('.pkg'):
                    event.acceptProposedAction()
                    self.drag_drop_label.setStyleSheet("""
                        QLabel {
                            font-size: 16px;
                            color: #2ecc71;
                            padding: 20px;
                            border: 2px dashed #27ae60;
                            border-radius: 10px;
                            background-color: rgba(46, 204, 113, 0.1);
                        }
                    """)
                    return
        event.ignore()

    def dragLeaveEvent(self, event):
        """Handles the event when the dragged file leaves the window"""
        self.drag_drop_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                color: #7f8c8d;
                padding: 20px;
                border: 2px dashed #bdc3c7;
                border-radius: 10px;
                background-color: rgba(236, 240, 241, 0.5);
            }
        """)
        event.accept()

    def dropEvent(self, event):
        """Handles the event when the file is dropped in the window"""
        files = [url.toLocalFile() for url in event.mimeData().urls() 
                if url.toLocalFile().lower().endswith('.pkg')]
        
        if files:
            # Chiudi il file precedente se esiste
            if self.package:
                try:
                    self.package = None
                    Logger.log_information("Previous package closed")
                except Exception as e:
                    Logger.log_error(f"Error closing previous package: {str(e)}")

            # Carica il nuovo file
            try:
                self.load_pkg(files[0])
                self.pkg_entry.setText(files[0])
                self.update_pkg_entries(files[0])
                
                # Carica esplicitamente l'icona
                self.load_pkg_icon()
                
                # Se ci sono più file, mostra un messaggio
                if len(files) > 1:
                    QMessageBox.information(self, "Multiple files", 
                        "Multiple PKG files were dragged. Only the first file will be loaded.")
                
                self.drag_drop_label.setStyleSheet("""
                    QLabel {
                        font-size: 16px;
                        color: #7f8c8d;
                        padding: 20px;
                        border: 2px dashed #bdc3c7;
                        border-radius: 10px;
                        background-color: rgba(236, 240, 241, 0.5);
                    }
                """)
                
                Logger.log_information(f"PKG file loaded via drag and drop: {files[0]}")
            except Exception as e:
                Logger.log_error(f"Error loading new package: {str(e)}")
                QMessageBox.critical(self, "Error", f"Failed to load PKG file: {str(e)}")
        
        event.acceptProposedAction()

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

        # Crea un layout orizzontale per l'immagine e il content ID
        image_content_layout = QHBoxLayout()

        # Frame per l'immagine
        image_frame = QFrame()
        image_frame.setFixedSize(300, 300)
        image_frame.setStyleSheet("background-color: white; border: 1px solid white; border-radius: 10px;")
        
        # Usa QStackedLayout invece di QVBoxLayout per sovrapporre perfettamente i widget
        image_layout = QStackedLayout(image_frame)
        image_layout.setStackingMode(QStackedLayout.StackAll)  # Permette la sovrapposizione

        # Configura l'etichetta dell'immagine
        self.image_label = QLabel("No icon available")
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setFixedSize(300, 300)
        
        # Configura l'etichetta del drag and drop
        self.drag_drop_label = QLabel("Drag PKG files here")
        self.drag_drop_label.setAlignment(Qt.AlignCenter)
        self.drag_drop_label.setFixedSize(300, 300)
        self.drag_drop_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                color: #7f8c8d;
                border: 2px dashed #bdc3c7;
                border-radius: 10px;
                background-color: rgba(236, 240, 241, 0.7);
            }
        """)

        # Aggiungi i widget al layout nell'ordine corretto
        image_layout.addWidget(self.image_label)
        image_layout.addWidget(self.drag_drop_label)
        
        # Aggiungi il frame al layout orizzontale
        image_content_layout.addWidget(image_frame)

        # Aggiungi l'etichetta per il content ID
        self.content_id_label = QLabel()
        self.content_id_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.content_id_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #2c3e50; margin-left: 10px;")
        image_content_layout.addWidget(self.content_id_label)

        # Aggiungi il layout orizzontale al layout principale di sinistra
        left_layout.addLayout(image_content_layout)

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
        self.ps5_game_info_tab = QWidget()
        self.esmf_decrypter_tab = QWidget()

        self.tab_widget.addTab(self.info_tab, "Info")
        self.tab_widget.addTab(self.extract_tab, "Extract")
        self.tab_widget.addTab(self.dump_tab, "Dump")
        self.tab_widget.addTab(self.inject_tab, "Inject")
        self.tab_widget.addTab(self.modify_tab, "Modify")
        self.tab_widget.addTab(self.trophy_tab, "Trophy")
        self.tab_widget.addTab(self.esmf_decrypter_tab, "ESMF Decrypter")
        self.tab_widget.addTab(self.trp_create_tab, "Create TRP")  
        self.tab_widget.addTab(self.file_browser_tab, "File Browser")  
        self.tab_widget.addTab(self.wallpaper_tab, "Wallpaper")  
        self.tab_widget.addTab(self.ps5_game_info_tab, "PS5 Game Info - by sinajet")
        
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
        self.setup_ps5_game_info_tab()
        self.setup_esmf_decrypter_tab()
        
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
                font-size: 16px;
                color: white;
                background-color: #e74c3c;
                font-weight: bold;
                border: none;
                padding: 10px 20px;
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

        # Aggiungi un nuovo tab per il Passcode Bruteforcer
        self.bruteforce_tab = QWidget()
        self.tab_widget.addTab(self.bruteforce_tab, "Passcode Bruteforcer")
        self.setup_bruteforce_tab()

    def setup_bruteforce_tab(self):
        layout = QVBoxLayout(self.bruteforce_tab)
        
        self.bruteforce_out_entry = QLineEdit()
        layout.addLayout(self.create_file_selection_layout(self.bruteforce_out_entry, lambda: self.browse_out(self.bruteforce_out_entry)))

        self.bruteforce_log = QTextEdit()
        self.bruteforce_log.setReadOnly(True)
        self.bruteforce_log.setStyleSheet("QTextEdit { background-color: white; color: #2c3e50; font-size: 14px; border: none; border-radius: 5px; }")
        layout.addWidget(self.bruteforce_log)

        run_button = QPushButton("Start Bruteforce")
        run_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        run_button.clicked.connect(self.run_bruteforce)
        layout.addWidget(run_button)
        
        layout.addStretch(1)

    def run_bruteforce(self):
        if not self.package:
            QMessageBox.warning(self, "Warning", "Please load a PKG file first.")
            return

        output_directory = self.bruteforce_out_entry.text()

        if not output_directory:
            QMessageBox.warning(self, "Warning", "Please select an output directory.")
            return

        self.bruteforce_log.clear()
        self.bruteforcer = PS4PasscodeBruteforcer()
        
        def progress_callback(message):
            self.bruteforce_log.append(message)
            QApplication.processEvents()

        result = self.bruteforcer.brute_force_passcode(self.package.original_file, output_directory, progress_callback)
        self.bruteforce_log.append(result)

        if "Passcode found" in result:
            self.package = self.bruteforcer.get_package()
            self.update_info(self.package.get_info())
            self.load_wallpapers()
            self.load_pkg_icon()
            self.load_files()

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
                QMainWindow, QWidget { 
                    background-color: #1e1e1e; 
                    color: #ffffff; 
                }
                QLineEdit, QTextEdit { 
                    background-color: #2d2d2d; 
                    color: #ffffff; 
                    border: 1px solid #3d3d3d;
                    padding: 5px;
                }
                QPushButton { 
                    background-color: #0d47a1; 
                    color: white;
                    border: none;
                    padding: 8px;
                    border-radius: 4px;
                }
                QPushButton:hover {
                    background-color: #1565c0;
                }
                QTreeWidget { 
                    background-color: #2d2d2d;
                    alternate-background-color: #353535;
                    color: #ffffff;
                    border: 1px solid #3d3d3d;
                }
                QTreeWidget::item:hover {
                    background-color: #3d3d3d;
                }
                QTreeWidget::item:selected {
                    background-color: #0d47a1;
                }
                QHeaderView::section {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    padding: 5px;
                    border: 1px solid #3d3d3d;
                }
                QTabWidget::pane { 
                    border: 1px solid #3d3d3d; 
                }
                QTabBar::tab { 
                    background: #2d2d2d; 
                    color: #ffffff;
                    padding: 8px;
                }
                QTabBar::tab:selected { 
                    background: #0d47a1; 
                }
                QLabel { 
                    color: #ffffff; 
                }
                QMenu {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: 1px solid #3d3d3d;
                }
                QMenu::item:selected {
                    background-color: #0d47a1;
                }
                QGroupBox {
                    color: #ffffff;
                    border: 1px solid #3d3d3d;
                    margin-top: 1ex;
                }
                QGroupBox::title {
                    color: #ffffff;
                }
                QComboBox {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: 1px solid #3d3d3d;
                    padding: 5px;
                }
                QComboBox:drop-down {
                    border: none;
                }
                QComboBox::down-arrow {
                    image: none;
                    border: none;
                }
                QSpinBox {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: 1px solid #3d3d3d;
                    padding: 5px;
                }
                QCheckBox {
                    color: #ffffff;
                }
                QScrollBar {
                    background-color: #2d2d2d;
                }
                QScrollBar::handle {
                    background-color: #3d3d3d;
                }
                QToolTip {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: 1px solid #3d3d3d;
                }
            """)
        else:
            self.setStyleSheet("""
                QMainWindow, QWidget { 
                    background-color: #ffffff; 
                    color: #000000; 
                }
                QLineEdit, QTextEdit { 
                    background-color: #ffffff; 
                    color: #000000; 
                    border: 1px solid #bdc3c7;
                    padding: 5px;
                }
                QPushButton { 
                    background-color: #3498db; 
                    color: white;
                    border: none;
                    padding: 8px;
                    border-radius: 4px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
                QTreeWidget { 
                    background-color: #ffffff;
                    alternate-background-color: #f5f5f5;
                    color: #000000;
                    border: 1px solid #bdc3c7;
                }
                QTreeWidget::item:hover {
                    background-color: #e8f0fe;
                }
                QTreeWidget::item:selected {
                    background-color: #3498db;
                    color: white;
                }
                QHeaderView::section {
                    background-color: #f5f5f5;
                    color: #000000;
                    padding: 5px;
                    border: 1px solid #bdc3c7;
                }
                QTabWidget::pane { 
                    border: 1px solid #bdc3c7; 
                }
                QTabBar::tab { 
                    background: #f5f5f5; 
                    color: #000000;
                    padding: 8px;
                }
                QTabBar::tab:selected { 
                    background: #3498db;
                    color: white;
                }
                QGroupBox {
                    color: #000000;
                    border: 1px solid #bdc3c7;
                    margin-top: 1ex;
                }
                QGroupBox::title {
                    color: #000000;
                }
                QComboBox, QSpinBox {
                    background-color: #ffffff;
                    color: #000000;
                    border: 1px solid #bdc3c7;
                    padding: 5px;
                }
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
            "DESTINATION_COUNTRY": "Region or country code for which the package is intended",
            "pkg_revision": "PKG format revision",
            "pkg_metadata_offset": "Offset of metadata in PKG",
            "pkg_metadata_count": "Number of metadata entries",
            "pkg_metadata_size": "Total size of metadata",
            "item_count": "Total number of files in PKG",
            "data_offset": "Data offset in PKG",
            "data_size": "Total data size",
            "digest": "PKG verification hash",
            "pkg_data_riv": "Initialization vector for decryption",
            "pkg_header_digest": "PKG header hash",
            "drm_type": "DRM protection type",
            "content_type": "PKG content type",
            "package_type": "Package type",
            "package_flag": "Package flags",
            "package_size": "Total package size",
            "make_package_npdrm_revision": "NPDRM revision",
            "package_version": "Package version",
            "title_id": "Title ID",
            "qa_digest": "QA verification hash",
            "system_version": "Minimum required system version",
            "app_version": "Application version",
            "install_directory": "Installation directory",
            "is_encrypted": "Encryption status",
            "valid_files": "Number of valid files in PKG"
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
                                         "You are about to perform a reverse dump. This operation will create a new modified PKG file. Do you want to continue?",
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
        
        # File selection
        file_layout = QHBoxLayout()
        self.trophy_entry = QLineEdit()
        file_layout.addWidget(self.trophy_entry)
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_trophy)
        file_layout.addWidget(browse_button)
        layout.addLayout(file_layout)

        # Split the tab into two columns
        split_layout = QHBoxLayout()
        left_column = QVBoxLayout()
        right_column = QVBoxLayout()
        split_layout.addLayout(left_column)
        split_layout.addLayout(right_column)
        layout.addLayout(split_layout)

        # Left column: Trophy info and list
        self.trophy_info = QTextEdit()
        self.trophy_info.setReadOnly(True)
        self.trophy_info.setStyleSheet("QTextEdit { background-color: white; color: #2c3e50; font-size: 14px; border: none; border-radius: 5px; }")
        self.trophy_info.setMaximumHeight(100)
        left_column.addWidget(self.trophy_info)

        self.trophy_tree = QTreeWidget()
        self.trophy_tree.setHeaderLabels(["Nome", "Dimensione"])
        self.trophy_tree.setStyleSheet("""
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
        self.trophy_tree.itemClicked.connect(self.display_selected_trophy)
        left_column.addWidget(self.trophy_tree)

        # Right column: Trophy image viewer
        self.trophy_image_viewer = QLabel()
        self.trophy_image_viewer.setAlignment(Qt.AlignCenter)
        self.trophy_image_viewer.setStyleSheet("background-color: white; border: 1px solid #3498db; border-radius: 5px;")
        self.trophy_image_viewer.setMinimumSize(300, 300)
        right_column.addWidget(self.trophy_image_viewer)

        # Navigation buttons
        button_layout = QHBoxLayout()
        self.prev_trophy_button = QPushButton("Previous")
        self.next_trophy_button = QPushButton("Next")
        self.prev_trophy_button.clicked.connect(self.show_previous_trophy)
        self.next_trophy_button.clicked.connect(self.show_next_trophy)
        button_layout.addWidget(self.prev_trophy_button)
        button_layout.addWidget(self.next_trophy_button)
        right_column.addLayout(button_layout)

        # Action buttons
        self.trophy_edit_button = QPushButton("Edit Trophy Info")
        self.trophy_edit_button.clicked.connect(self.edit_trophy_info)
        layout.addWidget(self.trophy_edit_button)

        self.trophy_recompile_button = QPushButton("Recompile TRP")
        self.trophy_recompile_button.clicked.connect(self.recompile_trp)
        layout.addWidget(self.trophy_recompile_button)

        run_button = QPushButton("Execute Trophy")
        run_button.clicked.connect(lambda: self.run_command("trophy"))
        layout.addWidget(run_button)

        load_trophy_files_button = QPushButton("Load trophy files")
        load_trophy_files_button.clicked.connect(self.load_trophy_files)
        layout.addWidget(load_trophy_files_button)

        # Apply consistent styling to buttons
        for button in [browse_button, self.prev_trophy_button, self.next_trophy_button, 
                       self.trophy_edit_button, self.trophy_recompile_button, run_button, 
                       load_trophy_files_button]:
            button.setStyleSheet("""
                QPushButton { 
                    font-size: 14px; 
                    padding: 8px 15px; 
                    background-color: #3498db; 
                    color: white; 
                    border: none; 
                    border-radius: 5px; 
                } 
                QPushButton:hover { 
                    background-color: #2980b9; 
                }
            """)

        # Set stretch factors to give more space to the trophy list and image viewer
        split_layout.setStretch(0, 1)  # Left column
        split_layout.setStretch(1, 2)  # Right column
        left_column.setStretch(1, 1)   # Trophy tree
        right_column.setStretch(0, 1)  # Image viewer

    def load_trophy_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select trophy files", "", "All files (*.*)")
        for file in files:
            with open(file, 'rb') as f:
                data = f.read()
            archiver = Archiver(len(self.trophy_files), os.path.basename(file), 0, len(data), data)
            self.trophy_files.append(archiver)
        QMessageBox.information(self, "Success", f"Loaded {len(files)} trophy files")

    def setup_trp_create_tab(self):
        layout = QVBoxLayout(self.trp_create_tab)
        
        self.trp_create_entry = QLineEdit()
        layout.addLayout(self.create_file_selection_layout(self.trp_create_entry, lambda: self.browse_trp_create(self.trp_create_entry)))

        self.trp_create_log = QTextEdit()
        self.trp_create_log.setReadOnly(True)
        self.trp_create_log.setStyleSheet("QTextEdit { background-color: white; color: #2c3e50; font-size: 14px; border: none; border-radius: 5px; }")
        layout.addWidget(self.trp_create_log)

        run_button = QPushButton("Create TRP")
        run_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        run_button.clicked.connect(lambda: self.run_command("trp_create"))
        layout.addWidget(run_button)
        
        layout.addStretch(1)

    def setup_file_browser_tab(self):
        layout = QVBoxLayout(self.file_browser_tab)
        
        # Barra di ricerca con stile migliorato
        search_layout = QHBoxLayout()
        self.file_search = QLineEdit()
        self.file_search.setPlaceholderText("🔍 Cerca file...")
        self.file_search.textChanged.connect(self.filter_files)
        self.file_search.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #3498db;
                border-radius: 15px;
                font-size: 14px;
            }
        """)
        search_layout.addWidget(self.file_search)
        layout.addLayout(search_layout)
        
        # TreeWidget migliorato
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Nome", "Dimensione", "Tipo"])
        self.file_tree.setColumnWidth(0, 400)
        self.file_tree.setColumnWidth(1, 100)
        self.file_tree.setColumnWidth(2, 100)
        self.file_tree.setAlternatingRowColors(True)
        self.file_tree.setAnimated(True)
        self.file_tree.setIndentation(20)
        self.file_tree.setSortingEnabled(True)
        
        # Menu contestuale e doppio click
        self.file_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(self.show_context_menu)
        self.file_tree.itemDoubleClicked.connect(self.on_item_double_clicked)
        layout.addWidget(self.file_tree)

    def filter_files(self):
        search_text = self.file_search.text().lower()
        
        def filter_item(item):
            # Mostra l'item se il testo di ricerca è vuoto o se corrisponde
            should_show = not search_text or search_text in item.text(0).lower()
            
            # Se è una directory, controlla anche i figli
            if item.childCount() > 0:
                # Mostra/nascondi i figli
                for i in range(item.childCount()):
                    child = item.child(i)
                    child_visible = filter_item(child)
                    should_show = should_show or child_visible
            
            item.setHidden(not should_show)
            return should_show
        
        # Applica il filtro a tutti gli item di primo livello
        root = self.file_tree.invisibleRootItem()
        for i in range(root.childCount()):
            filter_item(root.child(i))

    def load_files(self):
        if self.package:
            self.file_tree.clear()
            
            # Dizionario per la struttura delle directory
            file_structure = {}
            
            for file_id, file_info in self.package.files.items():
                if not file_info.get("name"):
                    continue
                    
                file_path = file_info["name"]
                path_parts = file_path.split('/')
                
                current_dict = file_structure
                
                # Crea struttura directory
                for part in path_parts[:-1]:
                    if part:
                        current_dict = current_dict.setdefault(part, {})
                
                # Aggiungi file
                if path_parts[-1]:
                    current_dict[path_parts[-1]] = file_info

            def add_items(parent_item, structure, path=""):
                for name, content in sorted(structure.items()):
                    if isinstance(content, dict):
                        if any(isinstance(v, dict) for v in content.values()):
                            # Directory
                            folder_item = QTreeWidgetItem(parent_item)
                            folder_item.setText(0, name)
                            folder_item.setText(1, "")
                            folder_item.setText(2, "Directory")
                            folder_item.setIcon(0, self.style().standardIcon(QStyle.SP_DirIcon))
                            
                            # Calcola dimensione totale della directory
                            total_size = self.calculate_directory_size(content)
                            folder_item.setText(1, self.format_size(total_size))
                            
                            current_path = f"{path}/{name}" if path else name
                            add_items(folder_item, content, current_path)
                        else:
                            # File
                            self.add_file_item(parent_item, name, content)

            # Popola il tree
            add_items(self.file_tree.invisibleRootItem(), file_structure)
            self.file_tree.expandAll()
            
            # Aggiorna anche la sezione wallpapers
            self.load_wallpapers()
            
            Logger.log_information(f"Loaded {len(self.package.files)} files into browser")
        else:
            logging.warning("No PKG file loaded. Unable to populate file browser.")

    def calculate_directory_size(self, directory):
        total_size = 0
        for name, content in directory.items():
            if isinstance(content, dict):
                if any(isinstance(v, dict) for v in content.values()):
                    total_size += self.calculate_directory_size(content)
                else:
                    total_size += content.get('size', 0)
        return total_size

    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"

    def add_file_item(self, parent_item, name, file_info):
        file_item = QTreeWidgetItem(parent_item)
        file_item.setText(0, name)
        file_item.setText(1, self.format_size(file_info['size']))
        file_type = self.get_file_type(os.path.splitext(name)[1].lower())
        file_item.setText(2, file_type)
        file_item.setData(0, Qt.UserRole, file_info)
        
        # Imposta icona appropriata
        if file_type == 'Image':
            file_item.setIcon(0, self.style().standardIcon(QStyle.SP_FileIcon))
        elif file_type == 'Executable':
            file_item.setIcon(0, self.style().standardIcon(QStyle.SP_FileLinkIcon))
        else:
            file_item.setIcon(0, self.style().standardIcon(QStyle.SP_FileIcon))

    def setup_wallpaper_tab(self):
        layout = QVBoxLayout(self.wallpaper_tab)
        
        self.wallpaper_tree = QTreeWidget()
        self.wallpaper_tree.setHeaderLabels(["Name", "Size"])
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
        self.wallpaper_viewer.setMinimumSize(300, 300)
        layout.addWidget(self.wallpaper_viewer)

        button_layout = QHBoxLayout()
        self.prev_wallpaper_button = QPushButton("Previous")
        self.next_wallpaper_button = QPushButton("Next")
        self.prev_wallpaper_button.clicked.connect(self.show_previous_wallpaper)
        self.next_wallpaper_button.clicked.connect(self.show_next_wallpaper)
        button_layout.addWidget(self.prev_wallpaper_button)
        button_layout.addWidget(self.next_wallpaper_button)
        layout.addLayout(button_layout)

        for button in [self.prev_wallpaper_button, self.next_wallpaper_button]:
            button.setStyleSheet("""
                QPushButton {
                    font-size: 14px;
                    padding: 8px 15px;
                    background-color: #3498db;
                    color: white;
                    border: none;
                    border-radius: 5px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
            """)

    def setup_ps5_game_info_tab(self):
        layout = QVBoxLayout(self.ps5_game_info_tab)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title_label = QLabel("PS5 Game Information")
        title_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #3498db; margin-bottom: 10px;")
        layout.addWidget(title_label, alignment=Qt.AlignCenter)

        # Create an instance of PS5GameInfo
        self.ps5_game_info = PS5GameInfo()

        # File selection area
        file_frame = QFrame()
        file_frame.setStyleSheet("background-color: #f0f0f0; border-radius: 10px; padding: 10px;")
        file_layout = QHBoxLayout(file_frame)
        self.ps5_game_path_entry = QLineEdit()
        self.ps5_game_path_entry.setPlaceholderText("Select eboot.bin file")
        self.ps5_game_path_entry.setStyleSheet("padding: 6px; border: 1px solid #bdc3c7; border-radius: 5px;")
        self.ps5_game_path_button = QPushButton("Browse")
        self.ps5_game_path_button.setStyleSheet(
            "QPushButton { background-color: #3498db; color: white; padding: 6px 12px; border: none; border-radius: 5px; }"
            "QPushButton:hover { background-color: #2980b9; }"
        )
        file_layout.addWidget(self.ps5_game_path_entry, 3)
        file_layout.addWidget(self.ps5_game_path_button, 1)
        layout.addWidget(file_frame)

        # Game info table
        self.ps5_game_info_table = QTableWidget()
        self.ps5_game_info_table.setColumnCount(2)
        self.ps5_game_info_table.setHorizontalHeaderLabels(["Parameter", "Value"])
        self.ps5_game_info_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.ps5_game_info_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.ps5_game_info_table.setStyleSheet(
            "QTableWidget { border: 1px solid #bdc3c7; border-radius: 5px; }"
            "QHeaderView::section { background-color: #3498db; color: white; padding: 6px; }"
            "QTableWidget::item { padding: 4px; }"
        )
        layout.addWidget(self.ps5_game_info_table)

        # Buttons
        button_layout = QHBoxLayout()
        self.save_button = QPushButton("Save Changes")
        self.reload_button = QPushButton("Reload")
        for button in [self.save_button, self.reload_button]:
            button.setStyleSheet(
                "QPushButton { background-color: #2ecc71; color: white; padding: 8px 16px; border: none; border-radius: 5px; font-weight: bold; }"
                "QPushButton:hover { background-color: #27ae60; }"
            )
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.reload_button)
        layout.addLayout(button_layout)

        # Total Size Label
        self.total_size_label = QLabel()
        self.total_size_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #2c3e50; margin-top: 10px;")
        layout.addWidget(self.total_size_label)

        # PKG Status Label
        self.pkg_status_label = QLabel()
        self.pkg_status_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #2c3e50; margin-top: 10px;")
        layout.addWidget(self.pkg_status_label)

        # Connect buttons to actions
        self.ps5_game_path_button.clicked.connect(self.browse_ps5_eboot)
        self.save_button.clicked.connect(self.save_ps5_game_info)
        self.reload_button.clicked.connect(self.reload_ps5_game_info)

    def browse_ps5_eboot(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select PS5 eboot.bin file", "", "eboot.bin files (eboot.bin)")
        if filename:
            self.ps5_game_path_entry.setText(filename)
            self.load_ps5_game_info(os.path.dirname(filename))

    def load_ps5_game_info(self, directory):
        try:
            info = self.ps5_game_info.process(directory)
            if isinstance(info, dict):
                self.ps5_game_info_table.setRowCount(0)  # Clear existing rows
                for key, value in info.items():
                    row_position = self.ps5_game_info_table.rowCount()
                    self.ps5_game_info_table.insertRow(row_position)
                    key_item = QTableWidgetItem(key)
                    key_item.setFlags(key_item.flags() & ~Qt.ItemIsEditable)  # Make key non-editable
                    self.ps5_game_info_table.setItem(row_position, 0, key_item)
                    value_item = QTableWidgetItem(str(value))
                    self.ps5_game_info_table.setItem(row_position, 1, value_item)
                
                self.ps5_game_info_table.resizeColumnsToContents()
                
                # Display file size
                file_size = self.ps5_game_info.Fsize
                self.total_size_label.setText(f"Total Size: {file_size}")
                
                # Set PKG status (fake or original)
                self.pkg_status_label.setText(f"PKG Status: {self.ps5_game_info.Fcheck}")
            else:
                QMessageBox.warning(self, "Error", str(info))
        except Exception as e:
            error_message = f"Error loading PS5 game info: {str(e)}"
            Logger.log_error(error_message)
            QMessageBox.warning(self, "Error", error_message)

    def save_ps5_game_info(self):
        try:
            updated_info = {}
            for row in range(self.ps5_game_info_table.rowCount()):
                key = self.ps5_game_info_table.item(row, 0).text()
                value = self.ps5_game_info_table.item(row, 1).text()
                updated_info[key] = value
            
            # Update the main_dict in PS5GameInfo
            self.ps5_game_info.main_dict = updated_info
            
            # Save changes to param.json
            param_json_path = os.path.join(os.path.dirname(self.ps5_game_path_entry.text()), "sce_sys/param.json")
            
            if not os.path.exists(param_json_path):
                QMessageBox.warning(self, "Error", "The param.json file does not exist.")
                return
            
            with open(param_json_path, "r+") as f:
                existing_data = json.load(f)
                for key, value in updated_info.items():
                    if key in existing_data:
                        existing_data[key] = value
                f.seek(0)
                json.dump(existing_data, f, indent=4)
                f.truncate()
            
            QMessageBox.information(self, "Success", "Changes saved successfully")
        except Exception as e:
            error_message = f"Error saving PS5 game info: {str(e)}"
            Logger.log_error(error_message)
            QMessageBox.warning(self, "Error", error_message)

    def reload_ps5_game_info(self):
        directory = os.path.dirname(self.ps5_game_path_entry.text())
        self.load_ps5_game_info(directory)

    def setup_trp_create_tab(self):
        layout = QVBoxLayout(self.trp_create_tab)
        
        self.trp_create_entry = QLineEdit()
        layout.addLayout(self.create_file_selection_layout(self.trp_create_entry, lambda: self.browse_trp_create(self.trp_create_entry)))

        self.trp_create_log = QTextEdit()
        self.trp_create_log.setReadOnly(True)
        self.trp_create_log.setStyleSheet("QTextEdit { background-color: white; color: #2c3e50; font-size: 14px; border: none; border-radius: 5px; }")
        layout.addWidget(self.trp_create_log)

        run_button = QPushButton("Create TRP")
        run_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        run_button.clicked.connect(lambda: self.run_command("trp_create"))
        layout.addWidget(run_button)
        
        layout.addStretch(1)

    def setup_esmf_decrypter_tab(self):
        layout = QVBoxLayout(self.esmf_decrypter_tab)
        
        file_layout = QHBoxLayout()
        self.esmf_file_entry = QLineEdit()
        self.esmf_file_entry.setPlaceholderText("Select ESFM file")
        file_layout.addWidget(self.esmf_file_entry)
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_esmf_file)
        file_layout.addWidget(browse_button)
        layout.addLayout(file_layout)

        self.cusa_label = QLabel("CUSA: Not loaded")
        layout.addWidget(self.cusa_label)

        output_layout = QHBoxLayout()
        self.esmf_output_entry = QLineEdit()
        self.esmf_output_entry.setPlaceholderText("Select output folder")
        output_layout.addWidget(self.esmf_output_entry)
        output_browse_button = QPushButton("Browse")
        output_browse_button.clicked.connect(self.browse_esmf_output)
        output_layout.addWidget(output_browse_button)
        layout.addLayout(output_layout)

        decrypt_button = QPushButton("Decrypt ESFM")
        decrypt_button.clicked.connect(self.decrypt_esmf)
        layout.addWidget(decrypt_button)

        self.esmf_log = QTextEdit()
        self.esmf_log.setReadOnly(True)
        layout.addWidget(self.esmf_log)

    def browse_esmf_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select ESFM file", "", "ESFM files (*.ESFM)")
        if filename:
            self.esmf_file_entry.setText(filename)
            self.load_cusa_from_path(filename)

    def load_cusa_from_path(self, file_path):
        if self.package:
            content_id = self.package.content_id
            if content_id:
                cusa = self.extract_cusa_from_content_id(content_id)
                if cusa:
                    self.cusa_label.setText(f"CUSA: {cusa}")
                    self.cusa = cusa
                    self.esmf_log.append(f"CUSA extracted from content_id: {cusa}")
                else:
                    self.esmf_log.append("CUSA not found in content_id. Trying to extract from file name...")
                    cusa = self.extract_cusa_from_filename(file_path)
                    if cusa:
                        self.cusa_label.setText(f"CUSA: {cusa}")
                        self.cusa = cusa
                        self.esmf_log.append(f"CUSA extracted from filename: {cusa}")
                    else:
                        self.esmf_log.append("Unable to extract CUSA from filename.")
            else:
                self.esmf_log.append("No content_id found in package. Trying to extract CUSA from file name...")
                cusa = self.extract_cusa_from_filename(file_path)
                if cusa:
                    self.cusa_label.setText(f"CUSA: {cusa}")
                    self.cusa = cusa
                    self.esmf_log.append(f"CUSA extracted from filename: {cusa}")
                else:
                    self.esmf_log.append("Unable to extract CUSA from filename.")
        else:
            self.esmf_log.append("No package loaded. Trying to extract CUSA from file name...")
            cusa = self.extract_cusa_from_filename(file_path)
            if cusa:
                self.cusa_label.setText(f"CUSA: {cusa}")
                self.cusa = cusa
                self.esmf_log.append(f"CUSA extracted from filename: {cusa}")
            else:
                self.esmf_log.append("Unable to extract CUSA from filename.")

    def extract_cusa_from_content_id(self, content_id):
        match = re.search(r'(CUSA\d{5})', content_id)
        return match.group(1) if match else None

    def extract_cusa_from_filename(self, file_path):
        file_name = os.path.basename(file_path)
        match = re.search(r'(CUSA\d{5})', file_name)
        return match.group(1) if match else None

    def browse_esmf_output(self):
        directory = QFileDialog.getExistingDirectory(self, "Select output folder")
        if directory:
            self.esmf_output_entry.setText(directory)

    def decrypt_esmf(self):
        esmf_file = self.esmf_file_entry.text()
        output_folder = self.esmf_output_entry.text()

        if not esmf_file or not output_folder or not hasattr(self, 'cusa'):
            QMessageBox.warning(self, "Warning", "Please select ESFM file, output folder, and ensure CUSA is loaded.")
            return

        try:
            np_com_id = self.get_np_com_id_from_api(self.cusa)
            if not np_com_id:
                QMessageBox.warning(self, "Warning", "Failed to retrieve NP Communication ID from API.")
                return

            decrypter = ESMFDecrypter()
            result = decrypter.decrypt_esmf(esmf_file, np_com_id, output_folder)
            if result:
                self.esmf_log.append(f"Decryption successful. Output file: {result}")
                QMessageBox.information(self, "Success", f"ESFM file decrypted successfully.\nOutput file: {result}")
            else:
                self.esmf_log.append("Decryption failed.")
                QMessageBox.critical(self, "Error", "Decryption failed. Check the log for details.")
        except Exception as e:
            self.esmf_log.append(f"Error during decryption: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred during decryption: {str(e)}")

    def get_np_com_id_from_api(self, cusa):
        base_url = "https://m.np.playstation.com/api/trophy/v1/apps/CUSA{}/trophyTitles"
        url = base_url.format(cusa[4:])  # Rimuove "CUSA" dal codice
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if 'trophyTitles' in data and len(data['trophyTitles']) > 0:
                    np_com_id = data['trophyTitles'][0].get('npCommunicationId')
                    if np_com_id:
                        self.esmf_log.append(f"NP Communication ID retrieved: {np_com_id}")
                        return np_com_id
                    else:
                        self.esmf_log.append("NP Communication ID not found in API response")
                else:
                    self.esmf_log.append("No trophy titles found in API response")
            else:
                self.esmf_log.append(f"API request failed with status code: {response.status_code}")
        except Exception as e:
            self.esmf_log.append(f"Error during API request: {str(e)}")

        return None

    def load_pkg_icon(self):
        try:
            Logger.log_information("Attempting to load PKG icon...")
            
            # Recupera e visualizza il content ID
            content_id = self.get_content_id()
            if content_id:
                self.content_id_label.setText(f"Content ID: {content_id}")
                Logger.log_information(f"Content ID displayed: {content_id}")
            else:
                self.content_id_label.setText("Content ID: N/A")
                Logger.log_warning("No content ID found")

            # Per PS3, cerca prima nella directory temporanea
            if isinstance(self.package, PackagePS3):
                icon_path = os.path.join(self.package.temp_dir, 'ICON0.PNG')
                if os.path.exists(icon_path):
                    try:
                        with Image.open(icon_path) as pil_image:
                            if pil_image.mode != 'RGB':
                                pil_image = pil_image.convert('RGB')
                            pil_image.thumbnail((300, 300), Image.Resampling.LANCZOS)
                            qimage = QImage(pil_image.tobytes(), 
                                          pil_image.width, 
                                          pil_image.height, 
                                          3 * pil_image.width,
                                          QImage.Format_RGB888)
                            pixmap = QPixmap.fromImage(qimage)
                            if not pixmap.isNull():
                                self.image_label.setPixmap(pixmap)
                                self.image_label.setAlignment(Qt.AlignCenter)
                                Logger.log_information("PS3 PKG icon loaded and displayed successfully")
                                return
                    except Exception as e:
                        Logger.log_error(f"Error loading PS3 icon: {str(e)}")
            
            # Per PS4/PS5
            icon_file = next((f for f in self.package.files.values() 
                             if isinstance(f, dict) and f.get('name', '').lower() in ['icon0.png', 'ICON0.PNG']), None)
            
            if icon_file:
                Logger.log_information(f"Icon file found in package: {icon_file}")
                try:
                    icon_data = self.package.read_file(icon_file['id'])
                    pil_image = Image.open(io.BytesIO(icon_data))
                    Logger.log_information(f"Icon loaded with PIL: format={pil_image.format}, size={pil_image.size}, mode={pil_image.mode}")
                    
                    if pil_image.mode != 'RGB':
                        pil_image = pil_image.convert('RGB')
                    
                    pil_image.thumbnail((300, 300), Image.Resampling.LANCZOS)
                    qimage = QImage(pil_image.tobytes(), 
                                  pil_image.width, 
                                  pil_image.height, 
                                  3 * pil_image.width,
                                  QImage.Format_RGB888)
                    
                    pixmap = QPixmap.fromImage(qimage)
                    if not pixmap.isNull():
                        self.image_label.setPixmap(pixmap)
                        self.image_label.setAlignment(Qt.AlignCenter)
                        Logger.log_information("PKG icon loaded and displayed successfully.")
                        return
                except Exception as e:
                    Logger.log_error(f"Error processing icon image: {str(e)}")

        except Exception as e:
            Logger.log_error(f"Unexpected error loading PKG icon: {str(e)}")
            self.image_label.setText("Error loading icon")

    def get_content_id(self):
        """Retrieves the content ID based on package type"""
        try:
            if not self.package:
                return None
            
            if isinstance(self.package, PackagePS3):
                return getattr(self.package, 'content_id', None)
            elif isinstance(self.package, (PackagePS4, PackagePS5)):
                return getattr(self.package, 'pkg_content_id', None)
            
            # Try to retrieve from other common attributes
            for attr in ['content_id', 'pkg_content_id']:
                if hasattr(self.package, attr):
                    value = getattr(self.package, attr)
                    if value:
                        return value
                        
            return None
            
        except Exception as e:
            Logger.log_error(f"Error getting content ID: {str(e)}")
            return None

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
        self.wallpaper_tree.setHeaderLabels(["Name", "Size"])
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
        self.wallpaper_viewer.setMinimumSize(300, 300)
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
            
            # Trova tutti i file immagine
            wallpaper_files = [
                f for f in self.package.files.values() 
                if isinstance(f.get("name"), str) and 
                f["name"].lower().endswith(('.png', '.jpg', '.jpeg'))
            ]
            
            # Organizza in cartelle
            wallpaper_structure = {}
            for file_info in wallpaper_files:
                path_parts = file_info["name"].split('/')
                current_dict = wallpaper_structure
                
                # Crea struttura directory
                for part in path_parts[:-1]:
                    if part:
                        current_dict = current_dict.setdefault(part, {})
                
                # Aggiungi file
                if path_parts[-1]:
                    current_dict[path_parts[-1]] = file_info
            
            def add_wallpaper_items(parent_item, structure):
                for name, content in sorted(structure.items()):
                    if isinstance(content, dict):
                        if any(isinstance(v, dict) for v in content.values()):
                            # Directory
                            folder_item = QTreeWidgetItem(parent_item)
                            folder_item.setText(0, name)
                            folder_item.setIcon(0, self.style().standardIcon(QStyle.SP_DirIcon))
                            add_wallpaper_items(folder_item, content)
                        else:
                            # File
                            item = QTreeWidgetItem(parent_item)
                            item.setText(0, name)
                            item.setText(1, self.format_size(content['size']))
                            item.setIcon(0, self.style().standardIcon(QStyle.SP_FileIcon))
            
            # Popola il tree
            add_wallpaper_items(self.wallpaper_tree.invisibleRootItem(), wallpaper_structure)
            self.wallpaper_tree.expandAll()
            
            Logger.log_information(f"Loaded {len(wallpaper_files)} wallpapers")
            if not wallpaper_files:
                Logger.log_warning("No wallpaper files found in the package")
        else:
            QMessageBox.warning(self, "Warning", "No PKG file loaded. Please load a PKG file first.")

    def display_selected_wallpaper(self, item, column):
        try:
            if not self.package:
                return
            
            file_name = item.text(0)
            Logger.log_information(f"Attempting to display wallpaper: {file_name}")
            
            # Verifica che il file esista nel package corrente
            file_info = next((f for f in self.package.files.values() 
                             if f.get('name') == file_name), None)
            
            if not file_info:
                Logger.log_warning(f"File {file_name} not found in current package")
                return
            
            try:
                # Per PS3, usa il percorso del file estratto
                if isinstance(self.package, PackagePS3):
                    if 'path' in file_info:
                        with open(file_info['path'], 'rb') as f:
                            image_data = f.read()
                    else:
                        Logger.log_error(f"File path not found for {file_name}")
                        return
                else:
                    # Per altri pacchetti, usa il metodo read_file
                    image_data = self.package.read_file(file_info['id'])
                
                image = Image.open(io.BytesIO(image_data))
                image.thumbnail((300, 300), Image.Resampling.LANCZOS)
                
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                
                qimage = QImage(image.tobytes(), 
                              image.width, 
                              image.height, 
                              3 * image.width,
                              QImage.Format_RGB888)
                
                pixmap = QPixmap.fromImage(qimage)
                self.wallpaper_viewer.setPixmap(pixmap)
                self.wallpaper_viewer.setAlignment(Qt.AlignCenter)
                
            except Exception as e:
                Logger.log_error(f"Error processing wallpaper: {str(e)}")
                self.wallpaper_viewer.clear()
            
        except Exception as e:
            Logger.log_error(f"Error displaying wallpaper: {str(e)}")
            self.wallpaper_viewer.clear()

    def show_previous_wallpaper(self):
        current_item = self.wallpaper_tree.currentItem()  
        if current_item:
            current_index = self.wallpaper_tree.indexOfTopLevelItem(current_item)
            if current_index > 0:
                previous_item = self.wallpaper_tree.topLevelItem(current_index - 1)
                self.wallpaper_tree.setCurrentItem(previous_item)
                self.display_selected_wallpaper(previous_item, 0)

    def show_next_wallpaper(self):
        current_item = self.wallpaper_tree.currentItem()  
        if current_item:
            current_index = self.wallpaper_tree.indexOfTopLevelItem(current_item)
            if current_index < self.wallpaper_tree.topLevelItemCount() - 1:
                next_item = self.wallpaper_tree.topLevelItem(current_index + 1)
                self.wallpaper_tree.setCurrentItem(next_item)
                self.display_selected_wallpaper(next_item, 0)

    def show_fullscreen_wallpaper(self):
        try:
            current_item = self.wallpaper_tree.currentItem()  
            if current_item:
                file_name = current_item.text(0)
                file_info = next((f for f in self.package.files.values() if f.get("name") == file_name), None)
                if file_info:
                    pixmap = QPixmap()
                    pixmap.loadFromData(self.package.read_file(file_info["id"]))
                    
                    fullscreen_dialog = QDialog(self)
                    fullscreen_dialog.setWindowTitle("Fullscreen Wallpaper")
                    layout = QVBoxLayout(fullscreen_dialog)
                    label = QLabel()
                    
                    screen_size = QApplication.primaryScreen().size()
                    label.setPixmap(pixmap.scaled(screen_size, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                    
                    layout.addWidget(label)
                    fullscreen_dialog.showFullScreen()
        except Exception as e:
            Logger.log_error(f"Error displaying fullscreen wallpaper: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    def modify_wallpaper(self):
        selected_items = self.wallpaper_tree.selectedItems()  # Usa il widget corretto
        if selected_items:
            item = selected_items[0]
            file_name = item.text(0)
            file_info = next((f for f in self.package.files.values() if f.get("name") == file_name), None)
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
                        self.display_selected_wallpaper(item, 0)
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

    def update_info(self, info):
        if info:
            self.tree.clear()
            for key, value in info.items():
                item = QTreeWidgetItem(self.tree)
                item.setText(0, str(key))
                item.setText(1, str(value))
                if key in self.key_descriptions:
                    item.setText(2, self.key_descriptions[key])
            
            # Aggiungi logica per gestire i pacchetti PS3
            if isinstance(self.package, PackagePS3):
                Logger.log_information("PS3 PKG file loaded.")
                # Aggiungi ulteriori informazioni specifiche del PS3 se necessario
            
            Logger.log_information("PKG information updated successfully.")
        else:
            QMessageBox.information(self, "Information", "No information found in the PKG file.")
            Logger.log_warning("No information found in the PKG file.")

    def load_files(self):
        if self.package:
            self.file_tree.clear()
            
            # Crea un dizionario per organizzare i file in directory
            file_structure = {}
            
            for file_id, file_info in self.package.files.items():
                if not file_info.get("name"):
                    continue
                    
                file_path = file_info["name"]
                path_parts = file_path.split('/')
                
                if not any(path_parts):
                    continue
                    
                current_dict = file_structure
                
                # Crea la struttura delle directory
                for part in path_parts[:-1]:
                    if part:
                        current_dict = current_dict.setdefault(part, {})
                
                # Aggiungi il file alla struttura
                if path_parts[-1]:
                    current_dict[path_parts[-1]] = file_info

            def format_size(size):
                """Format file size in a readable way"""
                for unit in ['B', 'KB', 'MB', 'GB']:
                    if size < 1024:
                        return f"{size:.2f} {unit}"
                    size /= 1024
                return f"{size:.2f} TB"

            def get_file_type(name):
                """Determine file type based on extension"""
                ext = os.path.splitext(name)[1].lower()
                type_map = {
                    '.png': 'Image',
                    '.jpg': 'Image',
                    '.jpeg': 'Image',
                    '.bin': 'Binary',
                    '.self': 'Executable',
                    '.sprx': 'System Plugin',
                    '.rco': 'Resource',
                    '.sfo': 'System File',
                    '.ac3': 'Audio',
                    '.at3': 'Audio',
                    '.txt': 'Text',
                    '.xml': 'XML',
                    '.json': 'JSON',
                    '.pkg': 'Package'
                }
                return type_map.get(ext, 'Unknown')

            def add_items(parent_item, structure):
                for name, content in sorted(structure.items()):
                    if isinstance(content, dict):
                        if any(isinstance(v, dict) for v in content.values()):
                            # È una directory
                            folder_item = QTreeWidgetItem(parent_item)
                            folder_item.setText(0, name)
                            folder_item.setText(1, "")
                            folder_item.setText(2, "Directory")
                            folder_item.setIcon(0, self.style().standardIcon(QStyle.SP_DirIcon))
                            add_items(folder_item, content)
                        else:
                            # È un file
                            file_item = QTreeWidgetItem(parent_item)
                            file_item.setText(0, name)
                            file_item.setText(1, format_size(content['size']))
                            file_type = get_file_type(name)
                            file_item.setText(2, file_type)
                            file_item.setData(0, Qt.UserRole, content)
                            
                            # Imposta l'icona in base al tipo
                            if file_type == 'Image':
                                file_item.setIcon(0, self.style().standardIcon(QStyle.SP_FileIcon))
                            elif file_type == 'Executable':
                                file_item.setIcon(0, self.style().standardIcon(QStyle.SP_FileLinkIcon))
                            else:
                                file_item.setIcon(0, self.style().standardIcon(QStyle.SP_FileIcon))

            # Popola il QTreeWidget
            add_items(self.file_tree.invisibleRootItem(), file_structure)
            
            # Espandi tutte le cartelle
            self.file_tree.expandAll()
            
            logging.info(f"Loaded {len(self.package.files)} files into the file browser")
        else:
            logging.warning("No PKG file loaded. Unable to populate file browser.")

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
                # Determine package type and create appropriate instance
                with open(filename, "rb") as fp:
                    magic = struct.unpack(">I", fp.read(4))[0]
                    if magic == PackagePS4.MAGIC_PS4:
                        self.package = PackagePS4(self.file_path)
                        Logger.log_information("PS4 PKG detected")
                    elif magic == PackagePS5.MAGIC_PS5:
                        self.package = PackagePS5(self.file_path)
                        Logger.log_information("PS5 PKG detected")
                    elif magic == PackagePS3.MAGIC_PS3:
                        self.package = PackagePS3(self.file_path)
                        Logger.log_information("PS3 PKG detected")
                    else:
                        raise ValueError(f"Unknown PKG format: {magic:08X}")
                
                self.update_info(self.package.get_info())
                self.load_wallpapers()
                self.load_pkg_icon()
                self.load_files()

                # Estrai il CUSA dal content ID
                if hasattr(self.package, 'content_id'):
                    cusa_match = re.search(r'(CUSA\d{5})', self.package.content_id)
                    if cusa_match:
                        self.cusa = cusa_match.group(1)
                        Logger.log_information(f"CUSA extracted from content_id: {self.cusa}")
                elif hasattr(self.package, 'pkg_content_id'):
                    cusa_match = re.search(r'(CUSA\d{5})', self.package.pkg_content_id)
                    if cusa_match:
                        self.cusa = cusa_match.group(1)
                        Logger.log_information(f"CUSA extracted from pkg_content_id: {self.cusa}")

                Logger.log_information(f"PKG file loaded successfully: {filename}")
            except ValueError as e:
                Logger.log_error(f"Error loading PKG file: {e}")
                QMessageBox.critical(self, "Error", f"Error loading PKG file: {e}")
            except Exception as e:
                Logger.log_error(f"Unexpected error loading PKG file: {e}")
                QMessageBox.critical(self, "Error", f"Unexpected error loading PKG file: {e}")

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
        filename, _ = QFileDialog.getOpenFileName(self, "Select Trophy file", "", "Trophy files (*.trp *.ucp)")
        if filename:
            self.trophy_entry.setText(filename)
            self.load_trophy_info(filename)

    def load_trophy_info(self, filename):
        try:
            trp_reader = TRPReader(filename)
            trp_reader.load()
            
            info = f"Title: {trp_reader.title}\n"
            info += f"NPCommID: {trp_reader.np_comm_id}\n"
            info += f"Number of trophies: {len(trp_reader.trophy_list)}\n\n"
            
            self.trophy_info.setText(info)
            
            # Popola il QTreeWidget con l'elenco dei trofei
            self.trophy_tree.clear()
            for trophy in trp_reader.trophy_list:
                item = QTreeWidgetItem(self.trophy_tree)
                item.setText(0, trophy.name)
                item.setText(1, str(trophy.size))
            
            # Estrai i file dei trofei
            if hasattr(self, 'trophy_temp_dir') and self.trophy_temp_dir:
                shutil.rmtree(self.trophy_temp_dir, ignore_errors=True)
            self.trophy_temp_dir = trp_reader.extract()
            
            Logger.log_information(f"Trophy information loaded successfully: {filename}")
        except Exception as e:
            self.trophy_info.setText(f"Error loading trophy file: {str(e)}")
            Logger.log_error(f"Error loading trophy file: {e}")

    def display_selected_trophy(self, item, column):
        try:
            file_name = item.text(0)
            if not hasattr(self, 'trophy_temp_dir') or not self.trophy_temp_dir:
                Logger.log_warning("Trophy temporary directory not set")
                self.trophy_image_viewer.setText("No trophy file loaded")
                return
            
            file_path = os.path.join(self.trophy_temp_dir, file_name)
            
            if os.path.exists(file_path):
                pixmap = QPixmap(file_path)
                if not pixmap.isNull():
                    scaled_pixmap = pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    self.trophy_image_viewer.setPixmap(scaled_pixmap)
                    Logger.log_information(f"Trophy image displayed successfully: {file_name}")
                else:
                    self.trophy_image_viewer.setText("Unable to load image")
                    Logger.log_warning(f"Unable to load trophy image: {file_name}")
            else:
                self.trophy_image_viewer.setText("File not found")
                Logger.log_warning(f"Trophy file not found: {file_path}")
        except Exception as e:
            Logger.log_error(f"Error displaying trophy: {str(e)}")
            self.trophy_image_viewer.setText("Error displaying")

    def show_previous_trophy(self):
        current_item = self.trophy_tree.currentItem()
        if current_item:
            current_index = self.trophy_tree.indexOfTopLevelItem(current_item)
            if current_index > 0:
                previous_item = self.trophy_tree.topLevelItem(current_index - 1)
                self.trophy_tree.setCurrentItem(previous_item)
                self.display_selected_trophy(previous_item, 0)

    def show_next_trophy(self):
        current_item = self.trophy_tree.currentItem()
        if current_item:
            current_index = self.trophy_tree.indexOfTopLevelItem(current_item)
            if current_index < self.trophy_tree.topLevelItemCount() - 1:
                next_item = self.trophy_tree.topLevelItem(current_index + 1)
                self.trophy_tree.setCurrentItem(next_item)
                self.display_selected_trophy(next_item, 0)

    def closeEvent(self, event):
        if hasattr(self, 'trophy_temp_dir') and self.trophy_temp_dir and os.path.exists(self.trophy_temp_dir):
            shutil.rmtree(self.trophy_temp_dir, ignore_errors=True)
            self.trophy_temp_dir = None
            Logger.log_information("Trophy temporary directory cleaned up")
        event.accept()

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
                    result = self.package.dump(output_path) if self.package else "No package loaded"
                elif cmd == "inject":
                    file_name = self.inject_file_entry.text()
                    input_file = self.inject_input_entry.text()
                    if not file_name or not input_file:
                        QMessageBox.warning(self, "Warning", "Please specify both file to inject and input file.")
                        return
                    if not self.package:
                        QMessageBox.warning(self, "Warning", "No package loaded.")
                        return
                    file_info = self.package.files.get(file_name)
                    if not file_info:
                        QMessageBox.warning(self, "Warning", "Specified file not found in the package.")
                        return
                    result = inject_file(self.package.original_file, file_info, input_file)
                elif cmd == "modify":
                    if not self.package:
                        QMessageBox.warning(self, "Warning", "No package loaded.")
                        return
                    offset = self.offset_entry.text()
                    new_data = self.data_entry.text()
                    if not offset or not new_data:
                        QMessageBox.warning(self, "Warning", "Please specify both offset and new data.")
                        return
                    offset = int(offset, 16)
                    new_data = bytes.fromhex(new_data)
                    result = modify_file_header(self.package.original_file, offset, new_data)
                elif cmd == "trophy":
                    if not hasattr(self, 'trophy_temp_dir') or not self.trophy_temp_dir:
                        QMessageBox.warning(self, "Warning", "No trophy file loaded.")
                        return
                    result = f"Trophy files extracted to: {self.trophy_temp_dir}"
                else:
                    result = self.run_command_callback(cmd, self.package.original_file if self.package else None, None, None, None)
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
            
            # Use the uploaded files in self.trophy_files
            for trophy_file in self.trophy_files:
                trp_creator._trophyList.append(trophy_file)
            
            output_path, _ = QFileDialog.getSaveFileName(self, "Save TRP File", "", "TRP files (*.trp)")
            if output_path:
                trp_creator.Create(output_path, [tf.name for tf in self.trophy_files])
                return f"TRP file created: {output_path}"
            else:
                return "TRP creation cancelled"
        except Exception as e:
            Logger.log_error(f"Error during TRP creation: {e}")
            raise

    def load_wallpapers(self):
        if self.package:
            self.wallpaper_tree.clear()
            
            # Trova tutti i file immagine
            wallpaper_files = [
                f for f in self.package.files.values() 
                if isinstance(f.get("name"), str) and 
                f["name"].lower().endswith(('.png', '.jpg', '.jpeg'))
            ]
            
            # Organizza in cartelle
            wallpaper_structure = {}
            for file_info in wallpaper_files:
                path_parts = file_info["name"].split('/')
                current_dict = wallpaper_structure
                
                # Crea struttura directory
                for part in path_parts[:-1]:
                    if part:
                        current_dict = current_dict.setdefault(part, {})
                
                # Aggiungi file
                if path_parts[-1]:
                    current_dict[path_parts[-1]] = file_info
            
            def add_wallpaper_items(parent_item, structure):
                for name, content in sorted(structure.items()):
                    if isinstance(content, dict):
                        if any(isinstance(v, dict) for v in content.values()):
                            # Directory
                            folder_item = QTreeWidgetItem(parent_item)
                            folder_item.setText(0, name)
                            folder_item.setIcon(0, self.style().standardIcon(QStyle.SP_DirIcon))
                            add_wallpaper_items(folder_item, content)
                        else:
                            # File
                            item = QTreeWidgetItem(parent_item)
                            item.setText(0, name)
                            item.setText(1, self.format_size(content['size']))
                            item.setIcon(0, self.style().standardIcon(QStyle.SP_FileIcon))
            
            # Popola il tree
            add_wallpaper_items(self.wallpaper_tree.invisibleRootItem(), wallpaper_structure)
            self.wallpaper_tree.expandAll()
            
            Logger.log_information(f"Loaded {len(wallpaper_files)} wallpapers")
            if not wallpaper_files:
                Logger.log_warning("No wallpaper files found in the package")
        else:
            QMessageBox.warning(self, "Warning", "No PKG file loaded. Please load a PKG file first.")

    def display_selected_wallpaper(self, item, column):
        try:
            if not self.package:
                return
            
            file_name = item.text(0)
            Logger.log_information(f"Attempting to display wallpaper: {file_name}")
            
            # Verifica che il file esista nel package corrente
            file_info = next((f for f in self.package.files.values() 
                             if f.get('name') == file_name), None)
            
            if not file_info:
                Logger.log_warning(f"File {file_name} not found in current package")
                return
            
            try:
                # Per PS3, usa il percorso del file estratto
                if isinstance(self.package, PackagePS3):
                    if 'path' in file_info:
                        with open(file_info['path'], 'rb') as f:
                            image_data = f.read()
                    else:
                        Logger.log_error(f"File path not found for {file_name}")
                        return
                else:
                    # Per altri pacchetti, usa il metodo read_file
                    image_data = self.package.read_file(file_info['id'])
                
                image = Image.open(io.BytesIO(image_data))
                image.thumbnail((300, 300), Image.Resampling.LANCZOS)
                
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                
                qimage = QImage(image.tobytes(), 
                              image.width, 
                              image.height, 
                              3 * image.width,
                              QImage.Format_RGB888)
                
                pixmap = QPixmap.fromImage(qimage)
                self.wallpaper_viewer.setPixmap(pixmap)
                self.wallpaper_viewer.setAlignment(Qt.AlignCenter)
                
            except Exception as e:
                Logger.log_error(f"Error processing wallpaper: {str(e)}")
                self.wallpaper_viewer.clear()
            
        except Exception as e:
            Logger.log_error(f"Error displaying wallpaper: {str(e)}")
            self.wallpaper_viewer.clear()

    def show_previous_wallpaper(self):
        current_item = self.wallpaper_tree.currentItem()  
        if current_item:
            current_index = self.wallpaper_tree.indexOfTopLevelItem(current_item)
            if current_index > 0:
                previous_item = self.wallpaper_tree.topLevelItem(current_index - 1)
                self.wallpaper_tree.setCurrentItem(previous_item)
                self.display_selected_wallpaper(previous_item, 0)

    def show_next_wallpaper(self):
        current_item = self.wallpaper_tree.currentItem()  
        if current_item:
            current_index = self.wallpaper_tree.indexOfTopLevelItem(current_item)
            if current_index < self.wallpaper_tree.topLevelItemCount() - 1:
                next_item = self.wallpaper_tree.topLevelItem(current_index + 1)
                self.wallpaper_tree.setCurrentItem(next_item)
                self.display_selected_wallpaper(next_item, 0)

    def show_fullscreen_wallpaper(self):
        try:
            current_item = self.wallpaper_tree.currentItem()  
            if current_item:
                file_name = current_item.text(0)
                file_info = next((f for f in self.package.files.values() if f.get("name") == file_name), None)
                if file_info:
                    pixmap = QPixmap()
                    pixmap.loadFromData(self.package.read_file(file_info["id"]))
                    
                    fullscreen_dialog = QDialog(self)
                    fullscreen_dialog.setWindowTitle("Fullscreen Wallpaper")
                    layout = QVBoxLayout(fullscreen_dialog)
                    label = QLabel()
                    
                    screen_size = QApplication.primaryScreen().size()
                    label.setPixmap(pixmap.scaled(screen_size, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                    
                    layout.addWidget(label)
                    fullscreen_dialog.showFullScreen()
        except Exception as e:
            Logger.log_error(f"Error displaying fullscreen wallpaper: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    def modify_wallpaper(self):
        selected_items = self.wallpaper_tree.selectedItems()  # Usa il widget corretto
        if selected_items:
            item = selected_items[0]
            file_name = item.text(0)
            file_info = next((f for f in self.package.files.values() if f.get("name") == file_name), None)
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
                        self.display_selected_wallpaper(item, 0)
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
        
    def load_pkg(self, pkg_path):
        try:
            # Reset selections and references
            self.wallpaper_tree.clearSelection()
            self.file_tree.clearSelection()
            self.wallpaper_viewer.clear()
            self.image_label.clear()
            
            # Close previous package if it exists
            if self.package:
                try:
                    if hasattr(self.package, 'close'):
                        self.package.close()
                    self.package = None
                    Logger.log_information("Previous package closed and cleaned")
                except Exception as e:
                    Logger.log_error(f"Error closing previous package: {str(e)}")

            # Determine package type and create appropriate instance
            with open(pkg_path, "rb") as fp:
                magic = struct.unpack(">I", fp.read(4))[0]
                if magic == PackagePS4.MAGIC_PS4:
                    self.package = PackagePS4(pkg_path)
                    Logger.log_information("PS4 PKG detected")
                    # Extract content ID for PS4
                    if hasattr(self.package, 'pkg_content_id'):
                        self.content_id = self.package.pkg_content_id
                        Logger.log_information(f"Content ID found: {self.content_id}")
                elif magic == PackagePS5.MAGIC_PS5:
                    self.package = PackagePS5(pkg_path)
                    Logger.log_information("PS5 PKG detected")
                    # Extract content ID for PS5
                    if hasattr(self.package, 'pkg_content_id'):
                        self.content_id = self.package.pkg_content_id
                        Logger.log_information(f"Content ID found: {self.content_id}")
                elif magic == PackagePS3.MAGIC_PS3:
                    self.package = PackagePS3(pkg_path)
                    Logger.log_information("PS3 PKG detected")
                    # Extract content ID for PS3
                    if hasattr(self.package, 'content_id'):
                        self.content_id = self.package.content_id
                        Logger.log_information(f"Content ID found: {self.content_id}")
                else:
                    raise ValueError(f"Unknown PKG format: {magic:08X}")
                
            self.file_path = pkg_path
            self.update_info(self.package.get_info())
            self.load_wallpapers()
            self.load_pkg_icon()
            self.load_files()

            # Extract CUSA from content ID
            if hasattr(self.package, 'content_id'):
                cusa_match = re.search(r'(CUSA\d{5})', self.package.content_id)
                if cusa_match:
                    self.cusa = cusa_match.group(1)
                    Logger.log_information(f"CUSA extracted from content_id: {self.cusa}")
            elif hasattr(self.package, 'pkg_content_id'):
                cusa_match = re.search(r'(CUSA\d{5})', self.package.pkg_content_id)
                if cusa_match:
                    self.cusa = cusa_match.group(1)
                    Logger.log_information(f"CUSA extracted from pkg_content_id: {self.cusa}")

            Logger.log_information(f"PKG file loaded successfully: {pkg_path}")
        except Exception as e:
            Logger.log_error(f"Error loading PKG file: {str(e)}")
            QMessageBox.critical(self, "Error", f"Error loading PKG file: {str(e)}")
        
    def setup_esmf_decrypter_tab(self):
        layout = QVBoxLayout(self.esmf_decrypter_tab)
        
        file_layout = QHBoxLayout()
        self.esmf_file_entry = QLineEdit()
        self.esmf_file_entry.setPlaceholderText("Select ESFM file")
        file_layout.addWidget(self.esmf_file_entry)
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_esmf_file)
        file_layout.addWidget(browse_button)
        layout.addLayout(file_layout)

        self.cusa_label = QLabel("CUSA: Not loaded")
        layout.addWidget(self.cusa_label)

        output_layout = QHBoxLayout()
        self.esmf_output_entry = QLineEdit()
        self.esmf_output_entry.setPlaceholderText("Select output folder")
        output_layout.addWidget(self.esmf_output_entry)
        output_browse_button = QPushButton("Browse")
        output_browse_button.clicked.connect(self.browse_esmf_output)
        output_layout.addWidget(output_browse_button)
        layout.addLayout(output_layout)

        decrypt_button = QPushButton("Decrypt ESFM")
        decrypt_button.clicked.connect(self.decrypt_esmf)
        layout.addWidget(decrypt_button)

        self.esmf_log = QTextEdit()
        self.esmf_log.setReadOnly(True)
        layout.addWidget(self.esmf_log)

    def browse_esmf_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select ESFM file", "", "ESFM files (*.ESFM)")
        if filename:
            self.esmf_file_entry.setText(filename)
            self.load_cusa_from_path(filename)

    def load_cusa_from_path(self, file_path):
        if self.package:
            content_id = self.package.content_id
            if content_id:
                cusa = self.extract_cusa_from_content_id(content_id)
                if cusa:
                    self.cusa_label.setText(f"CUSA: {cusa}")
                    self.cusa = cusa
                    self.esmf_log.append(f"CUSA extracted from content_id: {cusa}")
                else:
                    self.esmf_log.append("CUSA not found in content_id. Trying to extract from file name...")
                    cusa = self.extract_cusa_from_filename(file_path)
                    if cusa:
                        self.cusa_label.setText(f"CUSA: {cusa}")
                        self.cusa = cusa
                        self.esmf_log.append(f"CUSA extracted from filename: {cusa}")
                    else:
                        self.esmf_log.append("Unable to extract CUSA from filename.")
            else:
                self.esmf_log.append("No content_id found in package. Trying to extract CUSA from file name...")
                cusa = self.extract_cusa_from_filename(file_path)
                if cusa:
                    self.cusa_label.setText(f"CUSA: {cusa}")
                    self.cusa = cusa
                    self.esmf_log.append(f"CUSA extracted from filename: {cusa}")
                else:
                    self.esmf_log.append("Unable to extract CUSA from filename.")
        else:
            self.esmf_log.append("No package loaded. Trying to extract CUSA from file name...")
            cusa = self.extract_cusa_from_filename(file_path)
            if cusa:
                self.cusa_label.setText(f"CUSA: {cusa}")
                self.cusa = cusa
                self.esmf_log.append(f"CUSA extracted from filename: {cusa}")
            else:
                self.esmf_log.append("Unable to extract CUSA from filename.")

    def extract_cusa_from_content_id(self, content_id):
        match = re.search(r'(CUSA\d{5})', content_id)
        return match.group(1) if match else None

    def extract_cusa_from_filename(self, file_path):
        file_name = os.path.basename(file_path)
        match = re.search(r'(CUSA\d{5})', file_name)
        return match.group(1) if match else None

    def browse_esmf_output(self):
        directory = QFileDialog.getExistingDirectory(self, "Select output folder")
        if directory:
            self.esmf_output_entry.setText(directory)

    def decrypt_esmf(self):
        esmf_file = self.esmf_file_entry.text()
        output_folder = self.esmf_output_entry.text()

        if not esmf_file or not output_folder or not hasattr(self, 'cusa'):
            QMessageBox.warning(self, "Warning", "Please select ESFM file, output folder, and ensure CUSA is loaded.")
            return

        try:
            np_com_id = self.get_np_com_id_from_api(self.cusa)
            if not np_com_id:
                QMessageBox.warning(self, "Warning", "Failed to retrieve NP Communication ID from API.")
                return

            decrypter = ESMFDecrypter()
            result = decrypter.decrypt_esmf(esmf_file, np_com_id, output_folder)
            if result:
                self.esmf_log.append(f"Decryption successful. Output file: {result}")
                QMessageBox.information(self, "Success", f"ESFM file decrypted successfully.\nOutput file: {result}")
            else:
                self.esmf_log.append("Decryption failed.")
                QMessageBox.critical(self, "Error", "Decryption failed. Check the log for details.")
        except Exception as e:
            self.esmf_log.append(f"Error during decryption: {str(e)}")
            QMessageBox.critical(self, "Error", f"An error occurred during decryption: {str(e)}")

    def get_np_com_id_from_api(self, cusa):
        base_url = "https://m.np.playstation.com/api/trophy/v1/apps/CUSA{}/trophyTitles"
        url = base_url.format(cusa[4:])  # Rimuove "CUSA" dal codice
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if 'trophyTitles' in data and len(data['trophyTitles']) > 0:
                    np_com_id = data['trophyTitles'][0].get('npCommunicationId')
                    if np_com_id:
                        self.esmf_log.append(f"NP Communication ID retrieved: {np_com_id}")
                        return np_com_id
                    else:
                        self.esmf_log.append("NP Communication ID not found in API response")
                else:
                    self.esmf_log.append("No trophy titles found in API response")
            else:
                self.esmf_log.append(f"API request failed with status code: {response.status_code}")
        except Exception as e:
            self.esmf_log.append(f"Error during API request: {str(e)}")

        return None

    def load_pkg_icon(self):
        try:
            Logger.log_information("Attempting to load PKG icon...")
            
            # Recupera e visualizza il content ID
            content_id = self.get_content_id()
            if content_id:
                self.content_id_label.setText(f"Content ID: {content_id}")
                Logger.log_information(f"Content ID displayed: {content_id}")
            else:
                self.content_id_label.setText("Content ID: N/A")
                Logger.log_warning("No content ID found")

            # Per PS3, cerca prima nella directory temporanea
            if isinstance(self.package, PackagePS3):
                icon_path = os.path.join(self.package.temp_dir, 'ICON0.PNG')
                if os.path.exists(icon_path):
                    try:
                        with Image.open(icon_path) as pil_image:
                            if pil_image.mode != 'RGB':
                                pil_image = pil_image.convert('RGB')
                            pil_image.thumbnail((300, 300), Image.Resampling.LANCZOS)
                            qimage = QImage(pil_image.tobytes(), 
                                          pil_image.width, 
                                          pil_image.height, 
                                          3 * pil_image.width,
                                          QImage.Format_RGB888)
                            pixmap = QPixmap.fromImage(qimage)
                            if not pixmap.isNull():
                                self.image_label.setPixmap(pixmap)
                                self.image_label.setAlignment(Qt.AlignCenter)
                                Logger.log_information("PS3 PKG icon loaded and displayed successfully")
                                return
                    except Exception as e:
                        Logger.log_error(f"Error loading PS3 icon: {str(e)}")
            
            # Per PS4/PS5
            icon_file = next((f for f in self.package.files.values() 
                             if isinstance(f, dict) and f.get('name', '').lower() in ['icon0.png', 'ICON0.PNG']), None)
            
            if icon_file:
                Logger.log_information(f"Icon file found in package: {icon_file}")
                try:
                    icon_data = self.package.read_file(icon_file['id'])
                    pil_image = Image.open(io.BytesIO(icon_data))
                    Logger.log_information(f"Icon loaded with PIL: format={pil_image.format}, size={pil_image.size}, mode={pil_image.mode}")
                    
                    if pil_image.mode != 'RGB':
                        pil_image = pil_image.convert('RGB')
                    
                    pil_image.thumbnail((300, 300), Image.Resampling.LANCZOS)
                    qimage = QImage(pil_image.tobytes(), 
                                  pil_image.width, 
                                  pil_image.height, 
                                  3 * pil_image.width,
                                  QImage.Format_RGB888)
                    
                    pixmap = QPixmap.fromImage(qimage)
                    if not pixmap.isNull():
                        self.image_label.setPixmap(pixmap)
                        self.image_label.setAlignment(Qt.AlignCenter)
                        Logger.log_information("PKG icon loaded and displayed successfully.")
                        return
                except Exception as e:
                    Logger.log_error(f"Error processing icon image: {str(e)}")

        except Exception as e:
            Logger.log_error(f"Unexpected error loading PKG icon: {str(e)}")
            self.image_label.setText("Error loading icon")

    def get_content_id(self):
        """Retrieves the content ID based on package type"""
        try:
            if not self.package:
                return None
            
            if isinstance(self.package, PackagePS3):
                return getattr(self.package, 'content_id', None)
            elif isinstance(self.package, (PackagePS4, PackagePS5)):
                return getattr(self.package, 'pkg_content_id', None)
            
            # Try to retrieve from other common attributes
            for attr in ['content_id', 'pkg_content_id']:
                if hasattr(self.package, attr):
                    value = getattr(self.package, attr)
                    if value:
                        return value
                        
            return None
            
        except Exception as e:
            Logger.log_error(f"Error getting content ID: {str(e)}")
            return None

    def setup_settings_button(self):
        """Add settings button to toolbar"""
        settings_toolbar = QToolBar()
        settings_toolbar.setIconSize(QSize(24, 24))
        settings_toolbar.setStyleSheet("""
            QToolBar {
                spacing: 10px;
                border: none;
                background: transparent;
            }
        """)
        
        # Usa l'icona dell'ingranaggio invece di quella generica
        settings_button = QAction(self.style().standardIcon(QStyle.SP_FileDialogDetailedView), "", self)
        settings_button.setToolTip("Settings")
        settings_button.triggered.connect(self.show_settings_dialog)
        
        settings_toolbar.addAction(settings_button)
        # Posiziona la toolbar nell'angolo in alto a destra
        self.addToolBar(Qt.TopToolBarArea, settings_toolbar)
        settings_toolbar.setMovable(False)  # Impedisce lo spostamento della toolbar

    def show_settings_dialog(self):
        """Show settings dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Settings")
        dialog.setMinimumWidth(500)
        
        layout = QVBoxLayout(dialog)
        
        # Tabs per le impostazioni
        tabs = QTabWidget()
        
        # Tab Appearance
        appearance_tab = QWidget()
        appearance_layout = QVBoxLayout(appearance_tab)
        
        # Theme Selection
        theme_group = QGroupBox("Theme")
        theme_layout = QVBoxLayout()
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark", "System"])
        theme_layout.addWidget(self.theme_combo)
        theme_group.setLayout(theme_layout)
        appearance_layout.addWidget(theme_group)
        
        # Font Settings
        font_group = QGroupBox("Font")
        font_layout = QGridLayout()
        
        self.font_combo = QComboBox()
        self.font_combo.addItems(QFontDatabase().families())
        
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 24)
        self.font_size_spin.setValue(12)
        
        font_layout.addWidget(QLabel("Font:"), 0, 0)
        font_layout.addWidget(self.font_combo, 0, 1)
        font_layout.addWidget(QLabel("Size:"), 1, 0)
        font_layout.addWidget(self.font_size_spin, 1, 1)
        
        font_group.setLayout(font_layout)
        appearance_layout.addWidget(font_group)
        
        # Colors
        colors_group = QGroupBox("Colors")
        colors_layout = QGridLayout()
        
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
        
        colors_group.setLayout(colors_layout)
        appearance_layout.addWidget(colors_group)
        
        tabs.addTab(appearance_tab, "Appearance")
        
        # Tab Behavior
        behavior_tab = QWidget()
        behavior_layout = QVBoxLayout(behavior_tab)
        
        self.auto_expand_check = QCheckBox("Auto-expand file tree")
        self.show_hidden_check = QCheckBox("Show hidden files")
        self.confirm_exit_check = QCheckBox("Confirm before exit")
        
        behavior_layout.addWidget(self.auto_expand_check)
        behavior_layout.addWidget(self.show_hidden_check)
        behavior_layout.addWidget(self.confirm_exit_check)
        behavior_layout.addStretch()
        
        tabs.addTab(behavior_tab, "Behavior")
        
        # Tab Paths
        paths_tab = QWidget()
        paths_layout = QVBoxLayout(paths_tab)
        
        paths_group = QGroupBox("Default Paths")
        paths_inner_layout = QGridLayout()
        
        self.output_path_edit = QLineEdit()
        self.temp_path_edit = QLineEdit()
        
        output_browse = QPushButton("Browse")
        temp_browse = QPushButton("Browse")
        
        output_browse.clicked.connect(lambda: self.browse_directory(self.output_path_edit))
        temp_browse.clicked.connect(lambda: self.browse_directory(self.temp_path_edit))
        
        paths_inner_layout.addWidget(QLabel("Output:"), 0, 0)
        paths_inner_layout.addWidget(self.output_path_edit, 0, 1)
        paths_inner_layout.addWidget(output_browse, 0, 2)
        paths_inner_layout.addWidget(QLabel("Temp:"), 1, 0)
        paths_inner_layout.addWidget(self.temp_path_edit, 1, 1)
        paths_inner_layout.addWidget(temp_browse, 1, 2)
        
        paths_group.setLayout(paths_inner_layout)
        paths_layout.addWidget(paths_group)
        paths_layout.addStretch()
        
        tabs.addTab(paths_tab, "Paths")
        
        layout.addWidget(tabs)
        
        # Buttons
        button_box = QHBoxLayout()
        save_button = QPushButton("Save")
        reset_button = QPushButton("Reset to Default")
        cancel_button = QPushButton("Cancel")
        
        save_button.clicked.connect(lambda: self.save_and_apply_settings(dialog))
        reset_button.clicked.connect(self.reset_settings)
        cancel_button.clicked.connect(dialog.reject)
        
        button_box.addWidget(save_button)
        button_box.addWidget(reset_button)
        button_box.addWidget(cancel_button)
        
        layout.addLayout(button_box)
        
        # Carica le impostazioni correnti
        self.load_settings()
        
        dialog.exec_()

    def save_and_apply_settings(self, dialog):
        """Save settings and apply them immediately"""
        self.save_settings()
        self.apply_settings()
        dialog.accept()

    def apply_settings(self):
        """Apply current settings"""
        # Applica il tema
        self.change_theme(self.theme_combo.currentText())
        
        # Applica il font
        font = QFont(self.font_combo.currentText(), self.font_size_spin.value())
        QApplication.setFont(font)
        
        # Applica i colori
        bg_color = self.bg_color_button.styleSheet()
        text_color = self.text_color_button.styleSheet()
        accent_color = self.accent_color_button.styleSheet()
        
        # Aggiorna lo stile dell'applicazione con i nuovi colori
        self.update_style_with_colors(bg_color, text_color, accent_color)
        
        # Applica le impostazioni di comportamento
        if hasattr(self, 'file_tree'):
            if self.auto_expand_check.isChecked():
                self.file_tree.expandAll()
            else:
                self.file_tree.collapseAll()

    def update_style_with_colors(self, bg_color, text_color, accent_color):
        """Update application style with custom colors"""
        bg_color = bg_color.replace("background-color: ", "").strip()
        text_color = text_color.replace("background-color: ", "").strip()
        accent_color = accent_color.replace("background-color: ", "").strip()
        
        if self.night_mode:
            self.setStyleSheet(f"""
                QMainWindow, QWidget {{ 
                    background-color: {bg_color or "#1e1e1e"}; 
                    color: {text_color or "#ffffff"}; 
                }}
                QPushButton {{ 
                    background-color: {accent_color or "#0d47a1"}; 
                    color: {text_color or "#ffffff"};
                }}
                /* ... resto dello stile dark mode ... */
            """)
        else:
            self.setStyleSheet(f"""
                QMainWindow, QWidget {{ 
                    background-color: {bg_color or "#ffffff"}; 
                    color: {text_color or "#000000"}; 
                }}
                QPushButton {{ 
                    background-color: {accent_color or "#3498db"}; 
                    color: {text_color or "#ffffff"};
                }}
                /* ... resto dello stile light mode ... */
            """)

    def reset_settings(self):
        """Reset all settings to default"""
        reply = QMessageBox.question(self, "Confirm Reset", 
                                   "Are you sure you want to reset all settings to default?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            # Reset theme
            self.theme_combo.setCurrentText("Light")
            self.night_mode = False
            
            # Reset font
            self.font_combo.setCurrentText("Arial")
            self.font_size_spin.setValue(12)
            QApplication.setFont(QFont("Arial", 12))
            
            # Reset colors
            self.bg_color_button.setStyleSheet("")
            self.text_color_button.setStyleSheet("")
            self.accent_color_button.setStyleSheet("")
            
            # Reset behavior settings
            self.auto_expand_check.setChecked(True)
            self.show_hidden_check.setChecked(False)
            self.confirm_exit_check.setChecked(True)
            
            # Reset paths
            self.output_path_edit.clear()
            self.temp_path_edit.clear()
            
            # Apply default style
            self.set_style()
            
            # Save default settings
            self.save_settings()
            
            Logger.log_information("Settings reset to default")

    def save_settings(self):
        """Save all settings to file"""
        settings = {
            "theme": self.theme_combo.currentText(),
            "night_mode": self.night_mode,
            "font": self.font_combo.currentText(),
            "font_size": self.font_size_spin.value(),
            "bg_color": self.bg_color_button.styleSheet(),
            "text_color": self.text_color_button.styleSheet(),
            "accent_color": self.accent_color_button.styleSheet(),
            "auto_expand": self.auto_expand_check.isChecked(),
            "show_hidden": self.show_hidden_check.isChecked(),
            "confirm_exit": self.confirm_exit_check.isChecked(),
            "output_path": self.output_path_edit.text(),
            "temp_path": self.temp_path_edit.text()
        }
        
        try:
            with open("settings.json", "w") as f:
                json.dump(settings, f, indent=4)
            Logger.log_information("Settings saved successfully")
        except Exception as e:
            Logger.log_error(f"Error saving settings: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to save settings: {str(e)}")

    def load_settings(self):
        """Load settings from file"""
        try:
            with open("settings.json", "r") as f:
                settings = json.load(f)
                
            # Load and apply theme
            self.theme_combo.setCurrentText(settings.get("theme", "Light"))
            self.night_mode = settings.get("night_mode", False)
            
            # Load font settings
            self.font_combo.setCurrentText(settings.get("font", "Arial"))
            self.font_size_spin.setValue(settings.get("font_size", 12))
            
            # Load colors
            self.bg_color_button.setStyleSheet(settings.get("bg_color", ""))
            self.text_color_button.setStyleSheet(settings.get("text_color", ""))
            self.accent_color_button.setStyleSheet(settings.get("accent_color", ""))
            
            # Load behavior settings
            self.auto_expand_check.setChecked(settings.get("auto_expand", True))
            self.show_hidden_check.setChecked(settings.get("show_hidden", False))
            self.confirm_exit_check.setChecked(settings.get("confirm_exit", True))
            
            # Load paths
            self.output_path_edit.setText(settings.get("output_path", ""))
            self.temp_path_edit.setText(settings.get("temp_path", ""))
            
            Logger.log_information("Settings loaded successfully")
        except FileNotFoundError:
            Logger.log_information("No settings file found, using defaults")
        except Exception as e:
            Logger.log_error(f"Error loading settings: {str(e)}")
            QMessageBox.warning(self, "Warning", f"Failed to load settings: {str(e)}")

    def change_theme(self, theme_name):
        """Change application theme"""
        if theme_name == "Dark":
            self.night_mode = True
        elif theme_name == "Light":
            self.night_mode = False
        elif theme_name == "System":
            # TODO: Implement system theme detection
            pass
        self.set_style()

    def pick_color(self, color_type):
        """Open color picker dialog"""
        color = QColorDialog.getColor()
        if color.isValid():
            style = f"background-color: {color.name()}"
            if color_type == "background":
                self.bg_color_button.setStyleSheet(style)
            elif color_type == "text":
                self.text_color_button.setStyleSheet(style)
            elif color_type == "accent":
                self.accent_color_button.setStyleSheet(style)
            self.apply_settings()

    def browse_directory(self, line_edit):
        """Browse for directory"""
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            line_edit.setText(directory)

def start_gui(run_command_callback, temp_directory):
    app = QApplication(sys.argv)
    app.setStyle('Fusion') 
    window = PS4PKGTool(temp_directory)
    window.run_command_callback = run_command_callback
    window.show()
    sys.exit(app.exec_())
