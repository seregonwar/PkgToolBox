import logging
import sys
import os
import re
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, QTabWidget,
                            QMessageBox, QToolBar, QAction, QTreeWidget, QTextEdit, QTableWidget, QFileDialog, QGroupBox, QGridLayout, QSpinBox, QTreeWidgetItem, QDialog, QProgressBar, QShortcut, QActionGroup, QComboBox, QCheckBox, QListWidget, QFrame)
from PyQt5.QtCore import Qt, QSize, QUrl, QObject, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QDesktopServices
from PyQt5.QtWidgets import QStyle
import struct
from GraphicUserInterface.components import FileBrowser, WallpaperViewer
from GraphicUserInterface.dialogs import SettingsDialog
from GraphicUserInterface.utils import StyleManager, ImageUtils, FileUtils
from GraphicUserInterface.widgets import ExtractTab, InfoTab, BruteforceTab
from GraphicUserInterface.widgets.pfs_info_tab import PfsInfoTab
from tools.PS5_Game_Info import PS5GameInfo
from packages import PackagePS4, PackagePS5, PackagePS3
from file_operations import extract_file, inject_file, modify_file_header
from Utilities.Trophy import ESMFDecrypter, TRPCreator
from tools.PS4_Passcode_Bruteforcer import PS4PasscodeBruteforcer
import re
from Utilities import Logger
import json
from PyQt5.QtWidgets import QTableWidgetItem
from PyQt5.QtGui import QKeySequence
import traceback
from Utilities import Logger, SettingsManager, TRPReader  
from .locales.translator import Translator
from GraphicUserInterface.utils.update_checker import UpdateChecker, UpdateDialog

class MainWindow(QMainWindow):
    COLORS = {
        'light': {
            'background': '#f5f6fa',
            'text': '#2f3640',
            'accent': '#3498db',
            'secondary': '#e1e5eb',
            'success': '#2ecc71',
            'warning': '#f1c40f',
            'error': '#e74c3c',
            'tree_alternate': '#f1f2f6',
            'tree_hover': '#dcdde1',
            'tree_selected': '#3498db'
        },
        'dark': {
            'background': '#2f3640',
            'text': '#f5f6fa',
            'accent': '#3498db',
            'secondary': '#353b48',
            'success': '#27ae60',
            'warning': '#f39c12',
            'error': '#c0392b',
            'tree_alternate': '#353b48',
            'tree_hover': '#485460',
            'tree_selected': '#3498db'
        }
    }

    def __init__(self, temp_directory):
        super().__init__()
        self.temp_directory = temp_directory
        self.package = None
        
        # Initialize settings manager
        self.settings = SettingsManager()
        
        # Initialize translator
        self.translator = Translator()
        
        # Load and apply appearance settings
        self.settings_dict = StyleManager.load_settings()
        appearance = self.settings_dict.get("appearance", {})
        # Font
        self.font = QFont(
            appearance.get("font_family", "Arial"),
            appearance.get("font_size", 12)
        )
        QApplication.setFont(self.font)
        # Theme
        StyleManager.apply_theme(self, self.settings_dict)
        
        # Setup UI
        self.setup_ui()
        self.setup_settings_button()
        
        # Apply saved language after UI is built (menus/tabs exist)
        try:
            self._apply_saved_language()
        except Exception:
            pass

        # Enable drag and drop
        self.setAcceptDrops(True)
        
        self.setup_shortcuts()
        self.setup_drag_drop()
        
        # Initialize update checker
        self.update_checker = UpdateChecker(self)
        self.update_checker.update_available.connect(self.show_update_dialog)
        self.update_checker.error_occurred.connect(self.handle_update_error)
        
        # Check for updates
        if not self.should_skip_updates():
            self.update_checker.start()

    def _apply_saved_language(self):
        """Read saved language from settings and apply to translator, then refresh UI."""
        saved = self.settings_dict.get("language", "English")
        # Accept either display names or language codes
        name_to_code = {
            'English': 'en', 'Italian': 'it', 'Spanish': 'es',
            'French': 'fr', 'German': 'de', 'Japanese': 'ja'
        }
        code = saved.lower() if len(saved) in (2, 3) else name_to_code.get(saved, 'en')
        if hasattr(self, 'translator'):
            if self.translator.change_language(code):
                if hasattr(self, 'retranslate_ui'):
                    self.retranslate_ui()

    def set_style(self):
        """Modern UI styling using Qt-supported properties only"""
        self.setStyleSheet("""
            /* Main Window */
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(74, 144, 226, 25%),
                    stop:0.3 rgba(80, 227, 194, 15%),
                    stop:0.7 rgba(245, 101, 101, 15%),
                    stop:1 rgba(196, 113, 237, 25%));
            }
            
            /* Cards */
            QWidget {
                background: rgba(255, 255, 255, 20%);
                border: 1px solid rgba(255, 255, 255, 30%);
                border-radius: 16px;
            }
            
            /* Modern Input Fields */
            QLineEdit, QTextEdit, QPlainTextEdit {
                background: rgba(255, 255, 255, 18%);
                border: 2px solid transparent;
                border-radius: 12px;
                padding: 14px 18px;
                font-size: 14px;
                font-weight: 500;
                color: #2d3748;
                selection-background-color: rgba(74, 144, 226, 30%);
            }
            QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
                border: 2px solid rgba(74, 144, 226, 60%);
                background: rgba(255, 255, 255, 24%);
            }
            
            /* Revolutionary Buttons */
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(74, 144, 226, 90%),
                    stop:1 rgba(80, 227, 194, 90%));
                border: none;
                border-radius: 14px;
                padding: 12px 24px;
                font-size: 14px;
                font-weight: 600;
                color: white;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(74, 144, 226, 100%),
                    stop:1 rgba(80, 227, 194, 100%));
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(74, 144, 226, 85%),
                    stop:1 rgba(80, 227, 194, 85%));
            }
            QPushButton:disabled {
                background: rgba(160, 174, 192, 0.4);
                color: rgba(160, 174, 192, 0.8);
            }
            
            /* Floating Tree/List Widgets */
            QTreeWidget, QListWidget {
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.15);
                border-radius: 16px;
                padding: 8px;
                alternate-background-color: rgba(255, 255, 255, 0.05);
                color: #2d3748;
                font-weight: 500;
            }
            QTreeWidget::item, QListWidget::item {
                padding: 8px 12px;
                border-radius: 8px;
                margin: 2px 0px;
            }
            QTreeWidget::item:hover, QListWidget::item:hover {
                background: rgba(74, 144, 226, 0.15);
                color: #1a202c;
            }
            QTreeWidget::item:selected, QListWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(74, 144, 226, 0.8),
                    stop:1 rgba(80, 227, 194, 0.8));
                color: white;
                font-weight: 600;
            }
            
            /* Modern Headers */
            QHeaderView::section {
                background: rgba(255, 255, 255, 0.12);
                border: none;
                border-radius: 8px;
                padding: 12px;
                font-weight: 600;
                color: #4a5568;
                margin: 2px;
            }
            
            /* Invisible Tabs (handled by sidebar) */
            QTabWidget::pane {
                background: transparent;
                border: none;
            }
            QTabBar::tab {
                background: transparent;
                border: none;
                padding: 0px;
                margin: 0px;
            }
            
            /* Floating Labels */
            QLabel {
                background: transparent;
                color: #2d3748;
                font-weight: 500;
                border: none;
            }
            
            /* Glass Menu Bar */
            QMenuBar {
                background: rgba(255, 255, 255, 12%);
                border: none;
                border-radius: 12px;
                padding: 4px 8px;
                color: #2d3748;
                font-weight: 500;
            }
            QMenuBar::item {
                background: transparent;
                padding: 8px 16px;
                border-radius: 8px;
            }
            QMenuBar::item:selected {
                background: rgba(74, 144, 226, 0.15);
            }
            QMenu {
                background: rgba(255, 255, 255, 95%);
                border: 1px solid rgba(255, 255, 255, 30%);
                border-radius: 12px;
                padding: 8px;
            }
            QMenu::item {
                padding: 10px 20px;
                border-radius: 8px;
                color: #2d3748;
            }
            QMenu::item:selected {
                background: rgba(74, 144, 226, 0.15);
            }
            
            /* Modern Combo Boxes */
            QComboBox {
                background: rgba(255, 255, 255, 0.12);
                border: 2px solid rgba(255, 255, 255, 0.2);
                border-radius: 12px;
                padding: 10px 16px;
                font-weight: 500;
                color: #2d3748;
            }
            QComboBox:hover {
                background: rgba(255, 255, 255, 0.18);
                border-color: rgba(74, 144, 226, 0.4);
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox QAbstractItemView {
                background: rgba(255, 255, 255, 95%);
                border: 1px solid rgba(255, 255, 255, 30%);
                border-radius: 12px;
                selection-background-color: rgba(74, 144, 226, 20%);
            }
            
            /* Elegant Scroll Bars */
            QScrollBar:vertical {
                background: rgba(255, 255, 255, 0.1);
                width: 8px;
                border-radius: 4px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: rgba(74, 144, 226, 0.6);
                border-radius: 4px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(74, 144, 226, 0.8);
            }
            QScrollBar:horizontal {
                background: rgba(255, 255, 255, 0.1);
                height: 8px;
                border-radius: 4px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background: rgba(74, 144, 226, 0.6);
                border-radius: 4px;
                min-width: 20px;
            }
            
            /* Floating Tooltips */
            QToolTip {
                background: rgba(45, 55, 72, 95%);
                color: white;
                border: 1px solid rgba(255, 255, 255, 20%);
                border-radius: 8px;
                padding: 8px 12px;
                font-weight: 500;
            }
            
            /* Modern Status Bar */
            QStatusBar {
                background: rgba(255, 255, 255, 0.08);
                border: none;
                border-radius: 12px;
                color: #4a5568;
                font-weight: 500;
            }
            
            /* Glass Group Boxes */
            QGroupBox {
                background: rgba(255, 255, 255, 12%);
                border: 1px solid rgba(255, 255, 255, 20%);
                border-radius: 16px;
                margin-top: 12px;
                padding-top: 12px;
                font-weight: 600;
                color: #2d3748;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 4px 12px;
                background: rgba(74, 144, 226, 10%);
                border-radius: 8px;
                color: #2d3748;
            }
        """)

    def setup_ui(self):
        """Setup the main UI"""
        self.setWindowTitle("PKG Tool Box v1.4.0")
        self.setGeometry(100, 100, 1200, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Split layout
        split_layout = QHBoxLayout()
        
        # Left panel for PKG info
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # PKG icon and info - Revolutionary glass card
        self.image_label = QLabel()
        self.image_label.setFixedSize(320, 320)
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet("""
            QLabel {
                background: rgba(255, 255, 255, 15%);
                border: 2px solid rgba(74, 144, 226, 30%);
                border-radius: 24px;
                padding: 20px;
            }
        """)
        
        self.content_id_label = QLabel()
        self.content_id_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: 600;
                color: #2d3748;
                padding: 16px 20px;
                background: rgba(255, 255, 255, 12%);
                border: 1px solid rgba(255, 255, 255, 20%);
                border-radius: 16px;
                margin: 8px 0px;
            }
        """)
        
        left_layout.addWidget(self.image_label)
        left_layout.addWidget(self.content_id_label)
        
        # Revolutionary drag-drop zone with glassmorphism
        self.drag_drop_label = QLabel("✨ Drop PKG files here or Browse")
        self.drag_drop_label.setAlignment(Qt.AlignCenter)
        self.drag_drop_label.setStyleSheet("""
            QLabel {
                font-size: 20px;
                font-weight: 600;
                color: #4a5568;
                padding: 40px;
                border: 3px dashed rgba(74, 144, 226, 40%);
                border-radius: 24px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(74, 144, 226, 8%),
                    stop:0.5 rgba(80, 227, 194, 6%),
                    stop:1 rgba(196, 113, 237, 8%));
            }
        """)
        left_layout.addWidget(self.drag_drop_label)
        
        # Revolutionary file selection with glassmorphism
        pkg_layout = QHBoxLayout()
        self.pkg_entry = QLineEdit()
        self.pkg_entry.setPlaceholderText("🎯 Select your PKG file...")
        self.pkg_entry.setStyleSheet("""
            QLineEdit {
                padding: 16px 20px;
                border: 2px solid rgba(74, 144, 226, 20%);
                border-radius: 16px;
                font-size: 15px;
                font-weight: 500;
                background: rgba(255, 255, 255, 12%);
                color: #2d3748;
            }
            QLineEdit:focus {
                border-color: rgba(74, 144, 226, 60%);
                background: rgba(255, 255, 255, 18%);
            }
            QLineEdit:hover {
                background: rgba(255, 255, 255, 15%);
            }
        """)
        
        browse_button = QPushButton("🚀 BROWSE")
        browse_button.clicked.connect(self.browse_pkg)
        browse_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(74, 144, 226, 90%),
                    stop:1 rgba(80, 227, 194, 90%));
                color: white;
                font-weight: 700;
                padding: 16px 28px;
                border: none;
                border-radius: 16px;
                font-size: 15px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(74, 144, 226, 100%),
                    stop:1 rgba(80, 227, 194, 100%));
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(74, 144, 226, 85%),
                    stop:1 rgba(80, 227, 194, 85%));
            }
        """)
        
        pkg_layout.addWidget(self.pkg_entry)
        pkg_layout.addWidget(browse_button)
        left_layout.addLayout(pkg_layout)
        
        left_layout.addStretch()
        
        # Revolutionary tab widget with glassmorphism
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                background: rgba(255, 255, 255, 8%);
                border: 1px solid rgba(255, 255, 255, 15%);
                border-radius: 24px;
                padding: 20px;
            }
            QTabBar::tab {
                background: transparent;
                border: none;
                padding: 0px;
                margin: 0px;
            }
        """)

        # Info tab
        self.info_tab = InfoTab(self)
        self.tab_widget.addTab(self.info_tab, "Info")
        
        # File Browser tab

        self.file_browser = FileBrowser(self)
        self.tab_widget.addTab(self.file_browser, "File Browser")
        
        # Wallpaper tab
        self.wallpaper_viewer = WallpaperViewer(self)
        self.tab_widget.addTab(self.wallpaper_viewer, "Wallpaper")
        
        # Extract tab
        self.extract_tab = ExtractTab(self)
        self.tab_widget.addTab(self.extract_tab, "Extract")
        
        # PFS Info tab
        self.pfs_info_tab = PfsInfoTab(self)
        self.tab_widget.addTab(self.pfs_info_tab, "PFS Info")
        
        # Inject tab
        self.inject_tab = QWidget()
        self.setup_inject_tab()
        self.tab_widget.addTab(self.inject_tab, "Inject")
        
        # Modify tab
        self.modify_tab = QWidget()
        self.setup_modify_tab()
        self.tab_widget.addTab(self.modify_tab, "Modify")
        
        # Trophy tab
        self.trophy_tab = QWidget()
        self.setup_trophy_tab()
        self.tab_widget.addTab(self.trophy_tab, "Trophy")
        
        # ESMF Decrypter tab
        self.esmf_decrypter_tab = QWidget()
        self.setup_esmf_decrypter_tab()
        self.tab_widget.addTab(self.esmf_decrypter_tab, "ESMF Decrypter")
        
        # Create TRP tab
        self.trp_create_tab = QWidget()
        self.setup_trp_create_tab()
        self.tab_widget.addTab(self.trp_create_tab, "Create TRP")
        
        # PS5 Game Info tab
        self.ps5_game_info_tab = QWidget()
        self.setup_ps5_game_info_tab()
        self.tab_widget.addTab(self.ps5_game_info_tab, "PS5 Game Info")
        
        # Passcode Bruteforcer tab
        self.bruteforce_tab = BruteforceTab(self)
        self.tab_widget.addTab(self.bruteforce_tab, "Passcode Bruteforcer")

        # Hide native tab bar – navigation handled by sidebar and build sidebar
        self.tab_widget.tabBar().hide()
        self.create_sidebar()
        
        split_layout.addWidget(self.sidebar_frame)
        split_layout.addWidget(left_panel, 1)
        split_layout.addWidget(self.tab_widget, 2)
        main_layout.addLayout(split_layout)
        
        # Credits and social buttons
        credits_layout = QHBoxLayout()
        
        # Left side - Credits label
        credits_label = QLabel()
        credits_label.setText('<a href="https://github.com/seregonwar" style="text-decoration:none; color:#2d3748;">Created by <b>SeregonWar</b></a>')
        credits_label.setTextFormat(Qt.RichText)
        credits_label.setOpenExternalLinks(True)
        credits_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: 600;
                color: #2d3748;
                padding: 6px 8px;
                background: rgba(255, 255, 255, 12%);
                border: 1px solid rgba(0,0,0,8%);
                border-radius: 8px;
            }
        """)
        credits_layout.addWidget(credits_label, 0, Qt.AlignLeft)
        
        # Center - Social buttons
        social_layout = QHBoxLayout()
        social_layout.setSpacing(12)
        
        # Stile comune per i pulsanti social (pill buttons)
        social_button_style = """
            QPushButton {
                font-size: 12px;
                color: white;
                background-color: #3498db;
                border: none;
                border-radius: 14px;
                padding: 6px 14px;
                min-width: 88px;
                height: 28px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """
        
        x_button = QPushButton("X")
        x_button.setToolTip("Open X / Twitter")
        github_button = QPushButton("GitHub")
        github_button.setToolTip("Open GitHub profile")
        reddit_button = QPushButton("Reddit")
        reddit_button.setToolTip("Open Reddit profile")
        
        for button in [x_button, github_button, reddit_button]:
            button.setStyleSheet(social_button_style)
            social_layout.addWidget(button)
        
        # Connetti i pulsanti agli URL
        x_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://x.com/SeregonWar")))
        github_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://github.com/seregonwar")))
        reddit_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://www.reddit.com/user/S3R3GON/")))
        
        social_widget = QWidget()
        social_widget.setLayout(social_layout)
        credits_layout.addWidget(social_widget, 1, Qt.AlignCenter)
        
        # Right side - Ko-fi button
        kofi_button = QPushButton("Support on Ko-fi")
        kofi_button.setToolTip("Buy me a coffee on Ko-fi")
        kofi_button.setStyleSheet("""
            QPushButton {
                font-size: 12px;
                color: white;
                background-color: #e74c3c;
                border: none;
                border-radius: 14px;
                padding: 6px 14px;
                min-width: 140px;
                height: 28px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        kofi_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://ko-fi.com/seregon")))
        credits_layout.addWidget(kofi_button, 0, Qt.AlignRight)
        
        # Aggiungi il layout dei credits al layout principale
        main_layout.addLayout(credits_layout)
        
        # Aggiungi menu bar
        menubar = self.menuBar()
        
        # Store menu references
        self.file_menu = menubar.addMenu('File')
        self.tools_menu = menubar.addMenu('Tools')
        self.view_menu = menubar.addMenu('View')
        self.help_menu = menubar.addMenu('Help')
        self.links_menu = menubar.addMenu('Links')
        
        # File menu actions
        self.open_action = QAction('Open PKG', self)
        self.open_action.setShortcut('Ctrl+O')
        self.open_action.triggered.connect(self.browse_pkg)
        self.file_menu.addAction(self.open_action)
        
        self.file_menu.addSeparator()
        
        self.exit_action = QAction('Exit', self)
        self.exit_action.setShortcut('Ctrl+Q')
        self.exit_action.triggered.connect(self.close)
        self.file_menu.addAction(self.exit_action)
        
        # Tools menu actions
        extract_action = QAction('Extract PKG', self)
        extract_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.extract_tab))
        self.tools_menu.addAction(extract_action)
        
        inject_action = QAction('Inject File', self)
        inject_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.inject_tab))
        self.tools_menu.addAction(inject_action)
        
        modify_action = QAction('Modify PKG', self)
        modify_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.modify_tab))
        self.tools_menu.addAction(modify_action)
        
        self.tools_menu.addSeparator()
        
        trophy_action = QAction('Trophy Tools', self)
        trophy_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.trophy_tab))
        self.tools_menu.addAction(trophy_action)
        
        esmf_action = QAction('ESMF Decrypter', self)
        esmf_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.esmf_decrypter_tab))
        self.tools_menu.addAction(esmf_action)
        
        trp_action = QAction('Create TRP', self)
        trp_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.trp_create_tab))
        self.tools_menu.addAction(trp_action)
        
        self.tools_menu.addSeparator()
        
        bruteforce_action = QAction('Passcode Bruteforcer', self)
        bruteforce_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.bruteforce_tab))
        self.tools_menu.addAction(bruteforce_action)
        
        # View menu
        view_menu = self.view_menu
        
        file_browser_action = QAction('File Browser', self)
        file_browser_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.file_browser))
        view_menu.addAction(file_browser_action)
        
        wallpaper_action = QAction('Wallpaper Viewer', self)
        wallpaper_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.wallpaper_viewer))
        view_menu.addAction(wallpaper_action)
        
        # Links menu
        links_menu = self.links_menu
        
        github_action = QAction('GitHub', self)
        github_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl("https://github.com/seregonwar")))
        links_menu.addAction(github_action)
        
        reddit_action = QAction('Reddit', self)
        reddit_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl("https://www.reddit.com/user/S3R3GON/")))
        links_menu.addAction(reddit_action)
        
        x_action = QAction('X (Twitter)', self)
        x_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl("https://x.com/SeregonWar")))
        links_menu.addAction(x_action)
        
        links_menu.addSeparator()
        
        kofi_action = QAction('Support on Ko-fi', self)
        kofi_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl("https://ko-fi.com/seregon")))
        links_menu.addAction(kofi_action)
        
        # Help menu
        help_menu = self.help_menu
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        # Theme submenu and actions
        theme_menu = view_menu.addMenu('Theme')
        theme_group = QActionGroup(self)
        self.theme_actions = {}
        themes = {
            'Light': {'bg': '#ffffff', 'text': '#000000', 'accent': '#3498db'},
            'Dark': {'bg': '#2f3640', 'text': '#f5f6fa', 'accent': '#3498db'},
            'Nord': {'bg': '#2e3440', 'text': '#eceff4', 'accent': '#88c0d0'},
            'Solarized': {'bg': '#fdf6e3', 'text': '#657b83', 'accent': '#268bd2'}
        }
        for theme_name, colors in themes.items():
            action = QAction(theme_name, self)
            action.setCheckable(True)
            action.triggered.connect(lambda checked, t=theme_name, c=colors: self.change_theme(t, c))
            theme_group.addAction(action)
            theme_menu.addAction(action)
            self.theme_actions[theme_name] = action
        # Mark saved theme as checked
        saved_theme = self.settings_dict.get("appearance", {}).get("theme", "Light")
        if saved_theme in self.theme_actions:
            self.theme_actions[saved_theme].setChecked(True)
        
        # Status bar
        self.status_bar = self.statusBar()
        self.pkg_info_label = QLabel()
        self.status_bar.addPermanentWidget(self.pkg_info_label)
        
        # Progress bar nella status bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.hide()
        self.status_bar.addPermanentWidget(self.progress_bar)

    def change_theme(self, theme_name, colors):
        """Change and persist theme selection"""
        try:
            # Map provided colors to StyleManager schema
            new_settings = self.settings_dict or {}
            if "appearance" not in new_settings:
                new_settings["appearance"] = {}
            if "colors" not in new_settings["appearance"]:
                new_settings["appearance"]["colors"] = {}
            new_settings["appearance"]["theme"] = theme_name
            new_settings["appearance"]["colors"].update({
                "background": colors.get('bg', '#ffffff'),
                "text": colors.get('text', '#000000'),
                "accent": colors.get('accent', '#3498db')
            })
            # Save and apply
            StyleManager.save_settings(new_settings)
            self.settings_dict = new_settings
            StyleManager.apply_theme(self, self.settings_dict)
            # Reflect selection in menu
            if hasattr(self, 'theme_actions') and theme_name in self.theme_actions:
                self.theme_actions[theme_name].setChecked(True)
        except Exception as e:
            logging.error(f"Failed to change theme: {e}")

    def create_sidebar(self):
        """Create sidebar with navigation; theme control moved to top toolbar"""
        self.sidebar_frame = QFrame()
        self.sidebar_frame.setObjectName("sidebar")
        self.sidebar_frame.setStyleSheet("""
            QFrame#sidebar {
                background: rgba(255, 255, 255, 12%);
                border: 1px solid rgba(255, 255, 255, 20%);
                border-radius: 24px;
            }
            QPushButton#navBtn {
                text-align: left;
                padding: 10px 14px;
                border: none;
                border-radius: 12px;
                font-weight: 500;
                color: #2d3748;
                background: transparent;
                font-size: 14px;
            }
            QPushButton#navBtn:hover {
                background: rgba(74, 144, 226, 15%);
                color: #1a202c;
            }
            QPushButton#navBtn:pressed {
                background: rgba(74, 144, 226, 25%);
            }
        """)
        layout = QVBoxLayout(self.sidebar_frame)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # Hamburger toggle
        self.sidebar_expanded = True
        self.sidebar_width_expanded = 260
        self.sidebar_width_collapsed = 52
        self.sidebar_frame.setFixedWidth(self.sidebar_width_expanded)

        toggle_btn = QPushButton("☰")
        toggle_btn.setToolTip("Toggle menu")
        toggle_btn.setFixedHeight(40)
        toggle_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(74, 144, 226, 20%),
                    stop:1 rgba(80, 227, 194, 20%));
                border: 1px solid rgba(74, 144, 226, 30%);
                border-radius: 12px;
                font-size: 18px;
                font-weight: bold;
                color: #2d3748;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(74, 144, 226, 30%),
                    stop:1 rgba(80, 227, 194, 30%));
            }
        """)
        toggle_btn.clicked.connect(self.toggle_sidebar)
        layout.addWidget(toggle_btn)

        # Navigation buttons
        def add_nav(text, widget):
            btn = QPushButton(text)
            btn.setObjectName("navBtn")
            btn.setFixedHeight(36)
            btn.setMinimumWidth(220)
            btn.clicked.connect(lambda: self.tab_widget.setCurrentWidget(widget))
            layout.addWidget(btn)
            return btn

        # Ensure widgets exist before wiring
        add_nav("🏷️ Info", self.info_tab)
        add_nav("📁 File Browser", self.file_browser)
        add_nav("🖼️ Wallpaper", self.wallpaper_viewer)
        add_nav("📦 Extract", self.extract_tab)
        add_nav("🧩 PFS Info", self.pfs_info_tab)
        add_nav("📥 Inject", self.inject_tab)
        add_nav("🛠️ Modify", self.modify_tab)
        add_nav("🏆 Trophy", self.trophy_tab)
        add_nav("🔓 ESMF Decrypter", self.esmf_decrypter_tab)
        add_nav("📦 Create TRP", self.trp_create_tab)
        add_nav("🕹️ PS5 Game Info", self.ps5_game_info_tab)
        add_nav("🔢 Passcode Bruteforcer", self.bruteforce_tab)

        layout.addStretch(1)

    def toggle_sidebar(self):
        """Toggle sidebar width between expanded and collapsed states"""
        self.sidebar_expanded = not getattr(self, 'sidebar_expanded', True)
        new_w = self.sidebar_width_expanded if self.sidebar_expanded else self.sidebar_width_collapsed
        self.sidebar_frame.setFixedWidth(new_w)

    def setup_settings_button(self):
        """Add top-left 'Tema' button and settings button to toolbar"""
        # Theme toolbar (left-most)
        theme_toolbar = QToolBar()
        theme_toolbar.setIconSize(QSize(24, 24))
        theme_toolbar.setStyleSheet("""
            QToolBar { spacing: 10px; border: none; background: transparent; }
            QToolButton { border: none; border-radius: 6px; padding: 6px 10px; font-weight: 600; }
            QToolButton:hover { background-color: rgba(52, 152, 219, 20%); }
        """)
        theme_action = QAction("Tema", self)
        theme_action.setToolTip("Cambia tema")
        theme_action.triggered.connect(self.show_theme_menu)
        theme_toolbar.addAction(theme_action)
        self.addToolBar(Qt.TopToolBarArea, theme_toolbar)
        theme_toolbar.setMovable(False)

        # Settings toolbar (kept, to the right)
        settings_toolbar = QToolBar()
        settings_toolbar.setIconSize(QSize(24, 24))
        settings_icon = self.style().standardIcon(QStyle.SP_FileDialogDetailedView)
        settings_button = QAction(settings_icon, "", self)
        settings_button.setToolTip("Settings")
        settings_button.triggered.connect(self.show_settings_dialog)
        settings_toolbar.setStyleSheet("""
            QToolBar { spacing: 10px; border: none; background: transparent; }
            QToolButton { border: none; border-radius: 6px; padding: 6px; }
            QToolButton:hover { background-color: rgba(52, 152, 219, 20%); }
        """)
        settings_toolbar.addAction(settings_button)
        self.addToolBar(Qt.TopToolBarArea, settings_toolbar)
        settings_toolbar.setMovable(False)

    def show_theme_menu(self):
        """Show a theme selection menu and apply chosen theme"""
        from PyQt5.QtWidgets import QMenu
        menu = QMenu(self)
        themes = {
            'Light': {'bg': '#ffffff', 'text': '#000000', 'accent': '#3498db'},
            'Dark': {'bg': '#2f3640', 'text': '#f5f6fa', 'accent': '#3498db'},
            'Nord': {'bg': '#2e3440', 'text': '#eceff4', 'accent': '#88c0d0'},
            'Solarized': {'bg': '#fdf6e3', 'text': '#657b83', 'accent': '#268bd2'}
        }
        for name, colors in themes.items():
            act = menu.addAction(name)
            act.triggered.connect(lambda checked, n=name, c=colors: self.change_theme(n, c))
        # Position menu under the mouse or near top-left
        menu.exec_(self.mapToGlobal(self.rect().topLeft() + self.menuBar().pos()))

    def show_settings_dialog(self):
        """Show settings dialog"""
        dialog = SettingsDialog(self)
        dialog.exec_()

    def dragEnterEvent(self, event):
        """Handle drag enter event"""
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                if url.toLocalFile().lower().endswith('.pkg'):
                    event.acceptProposedAction()
                    self.drag_drop_label.setStyleSheet("""
                        QLabel {
                            font-size: 18px;
                            color: #27ae60;
                            padding: 30px;
                            border: 3px dashed #27ae60;
                            border-radius: 15px;
                            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 rgba(46, 204, 113, 0.2),
                                stop:1 rgba(39, 174, 96, 0.1));
                            font-weight: 600;
                        }
                    """)
                    return
        event.ignore()

    def dragLeaveEvent(self, event):
        """Handle drag leave event"""
        self.drag_drop_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                color: #7f8c8d;
                padding: 30px;
                border: 3px dashed #bdc3c7;
                border-radius: 15px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(236, 240, 241, 0.8),
                    stop:1 rgba(189, 195, 199, 0.3));
                font-weight: 500;
            }
        """)
        event.accept()

    def dropEvent(self, event):
        """Handle drop event"""
        files = [url.toLocalFile() for url in event.mimeData().urls() 
                if url.toLocalFile().lower().endswith('.pkg')]
        
        if files:
            self.load_pkg(files[0])
            
            if len(files) > 1:
                QMessageBox.information(self, "Multiple files", 
                    "Multiple PKG files were dragged. Only the first file will be loaded.")
            
            self.drag_drop_label.setStyleSheet("""
                QLabel {
                    font-size: 18px;
                    color: #7f8c8d;
                    padding: 30px;
                    border: 3px dashed #bdc3c7;
                    border-radius: 15px;
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 rgba(236, 240, 241, 0.8),
                        stop:1 rgba(189, 195, 199, 0.3));
                    font-weight: 500;
                }
            """)
        
        event.acceptProposedAction()

    def load_pkg(self, pkg_path):
        """Load PKG file"""
        try:
            # Chiudi il package precedente se esiste
            if self.package:
                try:
                    if hasattr(self.package, 'close'):
                        self.package.close()
                    self.package = None
                    Logger.log_information("Previous package closed")
                except Exception as e:
                    Logger.log_error(f"Error closing previous package: {str(e)}")

            # Determine package type and load it
            with open(pkg_path, "rb") as fp:
                magic = struct.unpack(">I", fp.read(4))[0]
                if magic == PackagePS4.MAGIC_PS4:
                    self.package = PackagePS4(pkg_path)
                    Logger.log_information("PS4 PKG detected")
                elif magic == PackagePS5.MAGIC_PS5:
                    self.package = PackagePS5(pkg_path)
                    Logger.log_information("PS5 PKG detected")
                elif magic == PackagePS3.MAGIC_PS3:
                    self.package = PackagePS3(pkg_path)
                    Logger.log_information("PS3 PKG detected")
                else:
                    raise ValueError(f"Unknown PKG format: {magic:08X}")
            
            # Update UI
            self.pkg_entry.setText(pkg_path)
            self.load_pkg_icon()
            
            # Update file browser and wallpaper viewer
            if hasattr(self, 'file_browser'):
                self.file_browser.load_files(self.package)
            if hasattr(self, 'wallpaper_viewer'):
                self.wallpaper_viewer.load_wallpapers(self.package)
            
            # Update info tab
            info_dict = self.package.get_info()
            self.update_info(info_dict)
            
            # Cerca e carica automaticamente i file dei trofei
            self.load_trophy_files()
            
            Logger.log_information(f"PKG file loaded successfully: {pkg_path}")
            
        except Exception as e:
            error_msg = f"Error loading PKG file: {str(e)}"
            Logger.log_error(error_msg)
            QMessageBox.critical(self, "Error", error_msg)
            
            # Reset UI state
            self.package = None
            self.image_label.clear()
            self.content_id_label.clear()
            if hasattr(self, 'file_browser'):
                self.file_browser.clear()
            if hasattr(self, 'wallpaper_viewer'):
                self.wallpaper_viewer.clear_viewer()

    def load_trophy_files(self):
        """Cerca e carica automaticamente i file dei trofei"""
        try:
            if not self.package:
                return
                
            # Cerca file .trp o .ucp
            trophy_files = [
                f for f in self.package.files.values()
                if isinstance(f.get("name"), str) and 
                (f["name"].lower().endswith('.trp') or f["name"].lower().endswith('.ucp'))
            ]
            
            if trophy_files:
                # Estrai il primo file dei trofei trovato in una directory temporanea
                temp_dir = os.path.join(self.temp_directory, "trophies")
                os.makedirs(temp_dir, exist_ok=True)
                
                trophy_file = trophy_files[0]
                temp_path = os.path.join(temp_dir, os.path.basename(trophy_file["name"]))
                
                # Estrai il file
                with open(temp_path, "wb") as f:
                    data = self.package.read_file(trophy_file["id"])
                    f.write(data)
                
                # Carica il file nella sezione trofei
                self.trophy_entry.setText(temp_path)
                trophy_reader = TRPReader(temp_path)
                
                # Mostra le informazioni nel text edit
                info_text = f"""
                Title: {trophy_reader._title if trophy_reader._title else 'N/A'}
                NP Communication ID: {trophy_reader._npcommid if trophy_reader._npcommid else 'N/A'}
                Number of Trophies: {len(trophy_reader._trophyList) if trophy_reader._trophyList else 0}
                """
                self.trophy_info.setText(info_text)
                
                # Carica i trofei nella tree view
                self.trophy_tree.clear()
                for trophy in trophy_reader._trophyList:
                    item = QTreeWidgetItem(self.trophy_tree)
                    item.setText(0, trophy.name)
                    item.setText(1, self.get_trophy_type(trophy))
                    item.setText(2, self.get_trophy_grade(trophy))
                    item.setText(3, "No")  # Hidden di default
                    item.setData(0, Qt.UserRole, trophy)
                
                # Passa alla tab dei trofei
                self.tab_widget.setCurrentWidget(self.trophy_tab)
                
                Logger.log_information(f"Trophy file loaded: {trophy_file['name']}")
                
        except Exception as e:
            Logger.log_error(f"Error loading trophy files: {str(e)}")

    def load_pkg_icon(self):
        """Load and display PKG icon"""
        try:
            # Get content ID
            content_id = self.get_content_id()
            if content_id:
                self.content_id_label.setText(f"Content ID: {content_id}")
            
            # Find icon file
            icon_file = next((f for f in self.package.files.values() 
                            if isinstance(f, dict) and 
                            f.get('name', '').lower() in ['icon0.png', 'ICON0.PNG']), None)
            
            if icon_file:
                # Load and display icon
                icon_data = self.package.read_file(icon_file['id'])
                pixmap = ImageUtils.create_thumbnail(icon_data)
                self.image_label.setPixmap(pixmap)
                self.image_label.setAlignment(Qt.AlignCenter)
                
        except Exception as e:
            logging.error(f"Error loading PKG icon: {str(e)}")
            self.image_label.setText("Error loading icon")

    def get_content_id(self):
        """Get content ID from package"""
        try:
            if not self.package:
                return None
            
            if isinstance(self.package, PackagePS3):
                return getattr(self.package, 'content_id', None)
            elif isinstance(self.package, (PackagePS4, PackagePS5)):
                return getattr(self.package, 'pkg_content_id', None)
            
            return None
            
        except Exception as e:
            logging.error(f"Error getting content ID: {str(e)}")
            return None

    def load_settings(self):
        """Load application settings"""
        try:
            settings = StyleManager.load_settings()
            self.night_mode = settings.get("night_mode", False)
            StyleManager.apply_theme(self, settings)
        except Exception as e:
            logging.error(f"Error loading settings: {str(e)}")

    def setup_info_tab(self):
        """Setup the info tab"""
        layout = QVBoxLayout(self.info_tab)
        
        # Tree widget for info display
        self.info_tree = QTreeWidget()
        self.info_tree.setHeaderLabels(["Key", "Value", "Description"])
        self.info_tree.setColumnWidth(0, 200)
        self.info_tree.setColumnWidth(1, 200)
        layout.addWidget(self.info_tree)

    def setup_extract_tab(self):
        """Setup the extract tab"""
        layout = QVBoxLayout(self.extract_tab)
        
        # Output path selection
        output_layout = QHBoxLayout()
        self.extract_out_entry = QLineEdit()
        self.extract_out_entry.setPlaceholderText("Select output directory")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(lambda: self.browse_directory(self.extract_out_entry))
        output_layout.addWidget(self.extract_out_entry)
        output_layout.addWidget(browse_button)
        layout.addLayout(output_layout)
        
        # PFS Info controls
        pfs_controls = QHBoxLayout()
        self.pfs_info_button = QPushButton("PFS Info (shadPKG)")
        self.pfs_info_button.setToolTip("Show PFS structure without extracting files")
        self.pfs_info_button.clicked.connect(self.run_pfs_info)
        pfs_controls.addWidget(self.pfs_info_button)
        pfs_controls.addStretch(1)
        layout.addLayout(pfs_controls)

        # PFS Info output
        self.pfs_info_view = QTextEdit()
        self.pfs_info_view.setReadOnly(True)
        self.pfs_info_view.setPlaceholderText("Output PFS Info (shadPKG)")
        layout.addWidget(self.pfs_info_view)

        # Extract log
        self.extract_log = QTextEdit()
        self.extract_log.setReadOnly(True)
        layout.addWidget(self.extract_log)
        
        # Extract button
        extract_button = QPushButton("Extract")
        extract_button.clicked.connect(self.extract_pkg)
        layout.addWidget(extract_button)

    def setup_inject_tab(self):
        """Setup the inject tab (Work in Progress placeholder)"""
        layout = QVBoxLayout(self.inject_tab)
        wip = QLabel("🚧 Inject - Work in progress")
        wip.setAlignment(Qt.AlignCenter)
        wip.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: 700;
                color: #2d3748;
                padding: 24px;
                background: rgba(255, 255, 255, 12%);
                border: 1px solid rgba(0,0,0,8%);
                border-radius: 12px;
            }
        """)
        layout.addStretch(1)
        layout.addWidget(wip)
        layout.addStretch(1)

    def setup_modify_tab(self):
        """Setup the modify tab"""
        layout = QVBoxLayout(self.modify_tab)
        
        # Hex viewer
        self.hex_viewer = QTextEdit()
        self.hex_viewer.setReadOnly(True)
        self.hex_viewer.setFont(QFont("Courier"))
        layout.addWidget(self.hex_viewer)
        
        # Offset and data entry
        offset_layout = QHBoxLayout()
        self.offset_entry = QLineEdit()
        self.offset_entry.setPlaceholderText("Offset (hex)")
        self.data_entry = QLineEdit()
        self.data_entry.setPlaceholderText("New data (hex)")
        offset_layout.addWidget(QLabel("Offset:"))
        offset_layout.addWidget(self.offset_entry)
        offset_layout.addWidget(QLabel("Data:"))
        offset_layout.addWidget(self.data_entry)
        layout.addLayout(offset_layout)
        
        # Modify button
        modify_button = QPushButton("Modify")
        modify_button.clicked.connect(self.modify_pkg)
        layout.addWidget(modify_button)

    def setup_trophy_tab(self):
        """Setup the trophy tab"""
        layout = QVBoxLayout(self.trophy_tab)
        
        # File selection with better styling
        file_group = QGroupBox("Trophy File")
        file_layout = QHBoxLayout()
        
        self.trophy_entry = QLineEdit()
        self.trophy_entry.setPlaceholderText("Select trophy file (.trp)")
        self.trophy_entry.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 2px solid #3498db;
                border-radius: 15px;
                font-size: 14px;
            }
        """)
        
        browse_button = QPushButton("Browse")
        browse_button.setStyleSheet("""
            QPushButton {
                padding: 8px 15px;
                background: #3498db;
                color: white;
                border: none;
                border-radius: 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #2980b9;
            }
        """)
        browse_button.clicked.connect(self.browse_trophy)
        
        file_layout.addWidget(self.trophy_entry)
        file_layout.addWidget(browse_button)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Split view for trophy list and preview
        split_layout = QHBoxLayout()
        
        # Left side: Trophy list and info
        left_panel = QVBoxLayout()
        
        # Trophy info display
        self.trophy_info = QTextEdit()
        self.trophy_info.setReadOnly(True)
        self.trophy_info.setMaximumHeight(100)
        self.trophy_info.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border: 1px solid #3498db;
                border-radius: 5px;
                padding: 5px;
                font-size: 13px;
            }
        """)
        left_panel.addWidget(self.trophy_info)
        
        # Trophy list
        self.trophy_tree = QTreeWidget()
        self.trophy_tree.setHeaderLabels(["Trophy", "Type", "Grade", "Hidden"])
        self.trophy_tree.setStyleSheet("""
            QTreeWidget {
                border: 1px solid #3498db;
                border-radius: 5px;
            }
            QTreeWidget::item {
                padding: 5px;
            }
            QTreeWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
        """)
        self.trophy_tree.itemClicked.connect(self.display_selected_trophy)
        left_panel.addWidget(self.trophy_tree)
        
        # Right side: Trophy image and details
        right_panel = QVBoxLayout()
        
        # Trophy image viewer
        self.trophy_image_viewer = QLabel()
        self.trophy_image_viewer.setAlignment(Qt.AlignCenter)
        self.trophy_image_viewer.setStyleSheet("""
            QLabel {
                background-color: white;
                border: 1px solid #3498db;
                border-radius: 5px;
                min-height: 300px;
            }
        """)
        right_panel.addWidget(self.trophy_image_viewer)
        
        # Trophy details
        self.trophy_details = QTextEdit()
        self.trophy_details.setReadOnly(True)
        self.trophy_details.setMaximumHeight(150)
        self.trophy_details.setStyleSheet(self.trophy_info.styleSheet())
        right_panel.addWidget(self.trophy_details)
        
        # Navigation buttons
        nav_layout = QHBoxLayout()
        self.prev_trophy_button = QPushButton("Previous")
        self.next_trophy_button = QPushButton("Next")
        
        for button in [self.prev_trophy_button, self.next_trophy_button]:
            button.setStyleSheet(browse_button.styleSheet())
            
        self.prev_trophy_button.clicked.connect(self.show_previous_trophy)
        self.next_trophy_button.clicked.connect(self.show_next_trophy)
        
        nav_layout.addWidget(self.prev_trophy_button)
        nav_layout.addWidget(self.next_trophy_button)
        right_panel.addLayout(nav_layout)
        
        # Add panels to split layout
        split_layout.addLayout(left_panel)
        split_layout.addLayout(right_panel)
        layout.addLayout(split_layout)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.trophy_edit_button = QPushButton("Edit Trophy")
        self.trophy_recompile_button = QPushButton("Recompile TRP")
        self.trophy_decrypt_button = QPushButton("Decrypt Trophy")
        
        for button in [self.trophy_edit_button, self.trophy_recompile_button, self.trophy_decrypt_button]:
            button.setStyleSheet(browse_button.styleSheet())
            
        self.trophy_edit_button.clicked.connect(self.edit_trophy_info)
        self.trophy_recompile_button.clicked.connect(self.recompile_trp)
        self.trophy_decrypt_button.clicked.connect(self.decrypt_trophy)
        
        button_layout.addWidget(self.trophy_edit_button)
        button_layout.addWidget(self.trophy_recompile_button)
        button_layout.addWidget(self.trophy_decrypt_button)
        
        layout.addLayout(button_layout)

    def setup_esmf_decrypter_tab(self):
        """Setup the ESMF decrypter tab"""
        layout = QVBoxLayout(self.esmf_decrypter_tab)
        
        # File selection
        file_layout = QHBoxLayout()
        self.esmf_file_entry = QLineEdit()
        self.esmf_file_entry.setPlaceholderText("Select ESMF file")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(lambda: self.browse_file(self.esmf_file_entry, "ESMF files (*.ESMF)"))
        file_layout.addWidget(self.esmf_file_entry)
        file_layout.addWidget(browse_button)
        layout.addLayout(file_layout)
        
        # Output directory
        output_layout = QHBoxLayout()
        self.esmf_output_entry = QLineEdit()
        self.esmf_output_entry.setPlaceholderText("Select output directory")
        output_browse = QPushButton("Browse")
        output_browse.clicked.connect(lambda: self.browse_directory(self.esmf_output_entry))
        output_layout.addWidget(self.esmf_output_entry)
        output_layout.addWidget(output_browse)
        layout.addLayout(output_layout)
        
        # Decrypt button
        decrypt_button = QPushButton("Decrypt")
        decrypt_button.clicked.connect(self.decrypt_esmf)
        layout.addWidget(decrypt_button)
        
        # Log display
        self.esmf_log = QTextEdit()
        self.esmf_log.setReadOnly(True)
        layout.addWidget(self.esmf_log)

    def setup_ps5_game_info_tab(self):
        """Setup the PS5 game info tab"""
        layout = QVBoxLayout(self.ps5_game_info_tab)
        
        # File selection with better styling
        file_group = QGroupBox("File Selection")
        file_layout = QHBoxLayout()
        
        self.ps5_game_path_entry = QLineEdit()
        self.ps5_game_path_entry.setPlaceholderText("Select eboot.bin or param.json file")
        self.ps5_game_path_entry.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 2px solid #3498db;
                border-radius: 15px;
                font-size: 14px;
            }
        """)
        
        browse_button = QPushButton("Browse")
        browse_button.setStyleSheet("""
            QPushButton {
                padding: 8px 15px;
                background: #3498db;
                color: white;
                border: none;
                border-radius: 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #2980b9;
            }
        """)
        browse_button.clicked.connect(self.browse_ps5_game_file)
        
        file_layout.addWidget(self.ps5_game_path_entry)
        file_layout.addWidget(browse_button)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Info table with better styling
        self.ps5_game_info_table = QTableWidget()
        self.ps5_game_info_table.setColumnCount(2)
        self.ps5_game_info_table.setHorizontalHeaderLabels(["Parameter", "Value"])
        self.ps5_game_info_table.horizontalHeader().setStretchLastSection(True)
        self.ps5_game_info_table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                gridline-color: #ecf0f1;
            }
            QHeaderView::section {
                background-color: #3498db;
                color: white;
                padding: 8px;
                border: none;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #e8f0fe;
                color: #2c3e50;
            }
        """)
        layout.addWidget(self.ps5_game_info_table)
        
        # Control buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save Changes")
        reload_button = QPushButton("Reload")
        
        for button in [save_button, reload_button]:
            button.setStyleSheet("""
                QPushButton {
                    padding: 8px 20px;
                    background: #3498db;
                    color: white;
                    border: none;
                    border-radius: 15px;
                    font-weight: bold;
                    min-width: 120px;
                }
                QPushButton:hover {
                    background: #2980b9;
                }
            """)
        
        save_button.clicked.connect(self.save_ps5_game_info)
        reload_button.clicked.connect(self.reload_ps5_game_info)
        
        button_layout.addStretch()
        button_layout.addWidget(save_button)
        button_layout.addWidget(reload_button)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)

    def browse_ps5_game_file(self):
        """Browse for PS5 game file"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select eboot.bin or param.json",
            "",
            "PS5 Game Files (eboot.bin param.json);;All files (*.*)"
        )
        if filename:
            self.ps5_game_path_entry.setText(filename)
            self.load_ps5_game_info(filename)

    def load_ps5_game_info(self, file_path):
        """Load PS5 game info"""
        try:
            # Create PS5GameInfo instance
            self.ps5_game_info = PS5GameInfo()
            
            # Process the directory containing the file
            directory = os.path.dirname(file_path)
            info = self.ps5_game_info.process(directory)
            
            # Clear and resize table
            self.ps5_game_info_table.setRowCount(0)
            
            # Add info to table
            for key, value in info.items():
                row = self.ps5_game_info_table.rowCount()
                self.ps5_game_info_table.insertRow(row)
                
                # Add key and value
                self.ps5_game_info_table.setItem(row, 0, QTableWidgetItem(str(key)))
                self.ps5_game_info_table.setItem(row, 1, QTableWidgetItem(str(value)))
            
            # Adjust columns
            self.ps5_game_info_table.resizeColumnsToContents()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load PS5 game info: {str(e)}")

    def save_ps5_game_info(self):
        """Save PS5 game info changes"""
        try:
            if not hasattr(self, 'ps5_game_info'):
                QMessageBox.warning(self, "Warning", "No PS5 game info loaded")
                return
                
            # Get file path
            file_path = self.ps5_game_path_entry.text()
            if not file_path:
                QMessageBox.warning(self, "Warning", "No file selected")
                return
                
            # Collect changes from table
            changes = {}
            for row in range(self.ps5_game_info_table.rowCount()):
                key = self.ps5_game_info_table.item(row, 0).text()
                value = self.ps5_game_info_table.item(row, 1).text()
                changes[key] = value
            
            # Update the main_dict in PS5GameInfo
            self.ps5_game_info.main_dict = changes
            
            # Save changes to param.json
            param_json_path = os.path.join(os.path.dirname(file_path), "sce_sys/param.json")
            if os.path.exists(param_json_path):
                with open(param_json_path, "r+") as f:
                    existing_data = json.load(f)
                    for key, value in changes.items():
                        if key in existing_data:
                            existing_data[key] = value
                    f.seek(0)
                    json.dump(existing_data, f, indent=4)
                    f.truncate()
                
                QMessageBox.information(self, "Success", "Changes saved successfully")
            else:
                QMessageBox.warning(self, "Error", "param.json file not found")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save changes: {str(e)}")

    def reload_ps5_game_info(self):
        """Reload PS5 game info"""
        file_path = self.ps5_game_path_entry.text()
        if file_path:
            self.load_ps5_game_info(file_path)
        else:
            QMessageBox.warning(self, "Warning", "No file selected")

    def setup_bruteforce_tab(self):
        """Setup the passcode bruteforcer tab"""
        layout = QVBoxLayout(self.bruteforce_tab)
        
        # Output directory selection
        output_layout = QHBoxLayout()
        self.bruteforce_out_entry = QLineEdit()
        self.bruteforce_out_entry.setPlaceholderText("Select output directory")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(lambda: self.browse_directory(self.bruteforce_out_entry))
        output_layout.addWidget(self.bruteforce_out_entry)
        output_layout.addWidget(browse_button)
        layout.addLayout(output_layout)
        
        # Passcode input
        passcode_group = QGroupBox("Passcode")
        passcode_layout = QVBoxLayout()
        
        # Manual passcode input
        manual_layout = QHBoxLayout()
        self.passcode_entry = QLineEdit()
        self.passcode_entry.setPlaceholderText("Enter 32-character passcode (optional)")
        self.passcode_entry.setMaxLength(32)
        manual_layout.addWidget(self.passcode_entry)
        
        # Try passcode button
        try_button = QPushButton("Try Passcode")
        try_button.clicked.connect(self.try_manual_passcode)
        manual_layout.addWidget(try_button)
        
        passcode_layout.addLayout(manual_layout)
        
        # Threads selector, Seed, and Stop button
        control_layout = QHBoxLayout()
        control_layout.addWidget(QLabel("Threads:"))
        self.brute_threads_spin = QSpinBox()
        self.brute_threads_spin.setRange(1, 32)
        self.brute_threads_spin.setValue(1)
        self.brute_threads_spin.setToolTip("Number of parallel workers")
        control_layout.addWidget(self.brute_threads_spin)

        control_layout.addWidget(QLabel("Seed:"))
        self.brute_seed_edit = QLineEdit()
        self.brute_seed_edit.setPlaceholderText("optional integer")
        self.brute_seed_edit.setToolTip("Optional integer seed for deterministic traversal")
        self.brute_seed_edit.setMaximumWidth(160)
        control_layout.addWidget(self.brute_seed_edit)

        self.brute_stop_button = QPushButton("Stop")
        self.brute_stop_button.setEnabled(False)
        self.brute_stop_button.clicked.connect(self.stop_bruteforce)
        control_layout.addWidget(self.brute_stop_button)
        
        # Reset button
        self.brute_reset_button = QPushButton("Reset")
        self.brute_reset_button.setToolTip("Stop and clear progress (.brutestate/.success)")
        self.brute_reset_button.clicked.connect(self.reset_bruteforce)
        control_layout.addWidget(self.brute_reset_button)
        passcode_layout.addLayout(control_layout)

        # Or label
        or_label = QLabel("- OR -")
        or_label.setAlignment(Qt.AlignCenter)
        passcode_layout.addWidget(or_label)
        
        # Bruteforce button
        self.brute_start_button = QPushButton("Start Bruteforce")
        self.brute_start_button.clicked.connect(self.run_bruteforce)
        passcode_layout.addWidget(self.brute_start_button)
        
        passcode_group.setLayout(passcode_layout)
        layout.addWidget(passcode_group)
        
        # Log display
        self.bruteforce_log = QTextEdit()
        self.bruteforce_log.setReadOnly(True)
        layout.addWidget(self.bruteforce_log)

        # Live stats labels
        stats_layout = QHBoxLayout()
        self.brute_attempts_label = QLabel("Attempts: 0")
        self.brute_rate_label = QLabel("Rate: 0/s")
        stats_layout.addWidget(self.brute_attempts_label)
        stats_layout.addWidget(self.brute_rate_label)
        stats_layout.addStretch(1)
        layout.addLayout(stats_layout)

        # Live tested keys list (bounded)
        tested_group = QGroupBox("Tested Keys (live)")
        tested_layout = QVBoxLayout()
        self.tested_keys_list = QListWidget()
        self.tested_keys_list.setAlternatingRowColors(True)
        tested_layout.addWidget(self.tested_keys_list)
        self.tested_count_label = QLabel("Shown: 0 (max 1000)")
        tested_layout.addWidget(self.tested_count_label)
        tested_group.setLayout(tested_layout)
        layout.addWidget(tested_group)

    def try_manual_passcode(self):
        """Try decrypting with manual passcode"""
        if not self.package:
            QMessageBox.warning(self, "Warning", "Please load a PKG file first")
            return

        output_dir = self.bruteforce_out_entry.text()
        if not output_dir:
            QMessageBox.warning(self, "Warning", "Please select an output directory")
            return
        
        passcode = self.passcode_entry.text()
        if not passcode:
            QMessageBox.warning(self, "Warning", "Please enter a passcode")
            return
        
        try:
            bruteforcer = PS4PasscodeBruteforcer()
            result = bruteforcer.brute_force_passcode(
                self.package.original_file,
                output_dir,
                lambda msg: self.bruteforce_log.append(msg),
                manual_passcode=passcode
            )
            self.bruteforce_log.append(result)
            if "successfully" in result.lower():
                QMessageBox.information(self, "Success", result)
            else:
                QMessageBox.warning(self, "Warning", result)
        except Exception as e:
            error_msg = f"Failed to try passcode: {str(e)}"
            self.bruteforce_log.append(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def setup_trp_create_tab(self):
        """Setup the TRP creation tab"""
        layout = QVBoxLayout(self.trp_create_tab)
        
        # Trophy info
        info_group = QGroupBox("Trophy Information")
        info_layout = QGridLayout()
        
        # Title input
        self.trp_title_edit = QLineEdit()
        self.trp_title_edit.setPlaceholderText("Enter trophy title")
        info_layout.addWidget(QLabel("Title:"), 0, 0)
        info_layout.addWidget(self.trp_title_edit, 0, 1)
        
        # NPCommID input
        self.trp_npcommid_edit = QLineEdit()
        self.trp_npcommid_edit.setPlaceholderText("Enter NPCommID")
        info_layout.addWidget(QLabel("NPCommID:"), 1, 0)
        info_layout.addWidget(self.trp_npcommid_edit, 1, 1)
        
        # Trophy count
        self.trp_trophy_count = QSpinBox()
        self.trp_trophy_count.setRange(1, 100)
        self.trp_trophy_count.setValue(1)
        info_layout.addWidget(QLabel("Trophy Count:"), 2, 0)
        info_layout.addWidget(self.trp_trophy_count, 2, 1)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # File list
        files_group = QGroupBox("Trophy Files")
        files_layout = QVBoxLayout()
        
        self.trophy_files_list = QTreeWidget()
        self.trophy_files_list.setHeaderLabels(["Name", "Size"])
        files_layout.addWidget(self.trophy_files_list)
        
        # Add file button
        add_file_button = QPushButton("Add Trophy Files")
        add_file_button.clicked.connect(self.add_trophy_files)
        files_layout.addWidget(add_file_button)
        
        files_group.setLayout(files_layout)
        layout.addWidget(files_group)
        
        # Create button
        create_button = QPushButton("Create TRP")
        create_button.clicked.connect(self.create_trp)
        layout.addWidget(create_button)
        
        # Log display
        self.trp_create_log = QTextEdit()
        self.trp_create_log.setReadOnly(True)
        layout.addWidget(self.trp_create_log)

    def add_trophy_files(self):
        """Add trophy files to the list"""
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Trophy Files",
            "",
            "Trophy Files (*.png *.jpg *.jpeg)"
        )
        
        if files:
            for file_path in files:
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    
                    file_name = os.path.basename(file_path)
                    size = len(data)
                    
                    item = QTreeWidgetItem(self.trophy_files_list)
                    item.setText(0, file_name)
                    item.setText(1, FileUtils.format_size(size))
                    item.setData(0, Qt.UserRole, {
                        'path': file_path,
                        'data': data,
                        'size': size
                    })
                    
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Failed to add file {file_path}: {str(e)}")

    def create_trp(self):
        """Create TRP file"""
        if not self.trophy_files_list.topLevelItemCount():
            QMessageBox.warning(self, "Warning", "Please add trophy files first")
            return
            
        title = self.trp_title_edit.text()
        npcommid = self.trp_npcommid_edit.text()
        
        if not title or not npcommid:
            QMessageBox.warning(self, "Warning", "Please enter title and NPCommID")
            return
            
        try:
            # Get save location
            output_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save TRP File",
                "",
                "TRP files (*.trp)"
            )
            
            if not output_path:
                return
                
            # Create TRP
            creator = TRPCreator()
            creator.SetVersion = 1  # Imposta la versione a 1
            
            # Raccogli tutti i file
            files = []
            root = self.trophy_files_list.invisibleRootItem()
            for i in range(root.childCount()):
                item = root.child(i)
                file_data = item.data(0, Qt.UserRole)
                files.append(file_data['path'])
            
            # Crea il file TRP
            try:
                creator.Create(output_path, files)
                self.trp_create_log.append(f"TRP file created successfully: {output_path}")
                QMessageBox.information(self, "Success", "TRP file created successfully")
            except Exception as e:
                raise Exception(f"Failed to create TRP: {str(e)}")
            
        except Exception as e:
            self.trp_create_log.append(f"Error creating TRP: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to create TRP: {str(e)}")

    def browse_pkg(self):
        """Browse for PKG file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, 
            "Select PKG file",
            "",
            "PKG files (*.pkg)"
        )
        if filename:
            self.pkg_entry.setText(filename)
            self.load_pkg(filename)

    def browse_file(self, entry_widget, file_filter="All files (*.*)"):
        """Browse for file"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select file",
            "",
            file_filter
        )
        if filename:
            entry_widget.setText(filename)

    def browse_directory(self, entry_widget):
        """Browse for directory"""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Directory"
        )
        if directory:
            entry_widget.setText(directory)

    def extract_pkg(self):
        """Extract PKG contents"""
        if not self.package:
            QMessageBox.warning(self, "Warning", "Please load a PKG file first")
            return

        output_dir = self.extract_out_entry.text()
        if not output_dir:
            QMessageBox.warning(self, "Warning", "Please select an output directory")
            return

        # Run extraction in background to keep UI responsive
        try:
            self.extract_log.append(f"[+] Starting extraction to: {output_dir}")

            class ExtractWorker(QObject):
                progress = pyqtSignal(str)
                finished = pyqtSignal(str)
                failed = pyqtSignal(str)

                def __init__(self, pkg, out_dir):
                    super().__init__()
                    self._pkg = pkg
                    self._out = out_dir

                def run(self):
                    try:
                        # Prefer shadPKG for PS4, fallback to internal dump
                        if isinstance(self._pkg, PackagePS4):
                            try:
                                result = self._pkg.extract_via_shadpkg(self._out)
                            except Exception as e:
                                Logger.log_warning(f"shadPKG failed, using internal extraction: {e}")
                                self.progress.emit(f"[-] shadPKG failed, using internal extraction: {e}")
                                result = self._pkg.dump(self._out)
                        else:
                            result = self._pkg.dump(self._out)
                        self.finished.emit(result)
                    except Exception as e:
                        self.failed.emit(str(e))

            # Create thread and worker
            self.extract_thread = QThread(self)
            self.extract_worker = ExtractWorker(self.package, output_dir)
            self.extract_worker.moveToThread(self.extract_thread)
            self.extract_thread.started.connect(self.extract_worker.run)
            self.extract_worker.progress.connect(self.extract_log.append)

            def on_extract_finished(msg: str):
                try:
                    self.extract_log.append(msg)
                    QMessageBox.information(self, "Success", "PKG extracted successfully")
                finally:
                    self.extract_thread.quit()

            def on_extract_failed(err: str):
                try:
                    QMessageBox.critical(self, "Error", f"Failed to extract PKG: {err}")
                finally:
                    self.extract_thread.quit()

            self.extract_worker.finished.connect(on_extract_finished)
            self.extract_worker.failed.connect(on_extract_failed)
            self.extract_thread.finished.connect(self.extract_thread.deleteLater)
            self.extract_thread.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start extraction: {str(e)}")


    def inject_file(self):
        """Inject file into PKG (WIP placeholder)"""
        QMessageBox.information(self, "Work in Progress", "The Inject feature is currently under development.")
        return

    def run_pfs_info(self):
        """Run shadPKG pfs-info in background and display result"""
        if not self.package:
            QMessageBox.warning(self, "PFS Info", "Please load a PKG file first")
            return
        if not isinstance(self.package, PackagePS4):
            QMessageBox.warning(self, "PFS Info", "PFS Info è disponibile solo per PKG PS4")
            return

        # Disable button to prevent multiple runs
        self.pfs_info_button.setEnabled(False)
        self.pfs_info_view.clear()
        self.pfs_info_view.append("[+] Running shadPKG pfs-info...\n")

        class PfsInfoWorker(QObject):
            finished = pyqtSignal(str)
            failed = pyqtSignal(str)

            def __init__(self, pkg):
                super().__init__()
                self._pkg = pkg

            def run(self):
                try:
                    output = self._pkg.get_pfs_info(as_json=False)
                    self.finished.emit(output)
                except Exception as e:
                    self.failed.emit(str(e))

        try:
            self.pfs_thread = QThread(self)
            self.pfs_worker = PfsInfoWorker(self.package)
            self.pfs_worker.moveToThread(self.pfs_thread)
            self.pfs_thread.started.connect(self.pfs_worker.run)

            def on_done(text: str):
                try:
                    self.pfs_info_view.clear()
                    self.pfs_info_view.append(text or "<no output>")
                finally:
                    self.pfs_thread.quit()
                    self.pfs_info_button.setEnabled(True)

            def on_fail(err: str):
                try:
                    QMessageBox.critical(self, "PFS Info", f"Failed: {err}")
                finally:
                    self.pfs_thread.quit()
                    self.pfs_info_button.setEnabled(True)

            self.pfs_worker.finished.connect(on_done)
            self.pfs_worker.failed.connect(on_fail)
            self.pfs_thread.finished.connect(self.pfs_thread.deleteLater)
            self.pfs_thread.start()
        except Exception as e:
            self.pfs_info_button.setEnabled(True)
            QMessageBox.critical(self, "PFS Info", f"Failed to start pfs-info: {e}")

    def modify_pkg(self):
        """Modify PKG header"""
        if not self.package:
            QMessageBox.warning(self, "Warning", "Please load a PKG file first")
            return

        offset = self.offset_entry.text()
        new_data = self.data_entry.text()

        if not offset or not new_data:
            QMessageBox.warning(self, "Warning", "Please specify both offset and new data")
            return

        try:
            offset = int(offset, 16)
            new_data = bytes.fromhex(new_data)
            result = modify_file_header(self.package.original_file, offset, new_data)
            QMessageBox.information(self, "Success", f"Modified {result} bytes")
            self.update_hex_view()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to modify PKG: {str(e)}")

    def decrypt_esmf(self):
        """Decrypt ESMF file"""
        esmf_file = self.esmf_file_entry.text()
        output_dir = self.esmf_output_entry.text()

        if not esmf_file or not output_dir:
            QMessageBox.warning(self, "Warning", "Please select ESMF file and output directory")
            return

        try:
            decrypter = ESMFDecrypter()
            result = decrypter.decrypt_esmf(esmf_file, output_dir)
            self.esmf_log.append(result)
            QMessageBox.information(self, "Success", "ESMF decrypted successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to decrypt ESMF: {str(e)}")

    def run_bruteforce(self):
        """Run passcode bruteforcer"""
        if not self.package:
            QMessageBox.warning(self, "Warning", "Please load a PKG file first")
            return

        output_dir = self.bruteforce_out_entry.text()
        if not output_dir:
            QMessageBox.warning(self, "Warning", "Please select an output directory")
            return

        # Start background bruteforce in QThread
        try:
            # Prepare UI state
            self.brute_start_button.setEnabled(False)
            self.brute_stop_button.setEnabled(True)
            self.bruteforce_log.clear()
            self.tested_keys_list.clear()
            self.tested_count_label.setText("Shown: 0 (max 1000)")

            # Create bruteforcer and thread
            self.bruteforcer = PS4PasscodeBruteforcer()

            class BruteforceWorker(QObject):
                progress = pyqtSignal(str)
                tested = pyqtSignal(str)
                finished = pyqtSignal(str)

                def __init__(self, bruteforcer, input_file, output_dir, threads, seed_val):
                    super().__init__()
                    self._bf = bruteforcer
                    self._in = input_file
                    self._out = output_dir
                    self._threads = threads
                    self._seed = seed_val

                def run(self):
                    try:
                        result = self._bf.brute_force_passcode(
                            self._in,
                            self._out,
                            progress_callback=self.progress.emit,
                            manual_passcode=None,
                            num_workers=self._threads,
                            tested_callback=self.tested.emit,
                            seed=self._seed
                        )
                        self.finished.emit(result)
                    except Exception as e:
                        self.finished.emit(f"[-] Error: {str(e)}")

            # Parse seed (optional)
            seed_text = self.brute_seed_edit.text().strip()
            seed_val = None
            if seed_text:
                try:
                    seed_val = int(seed_text)
                except ValueError:
                    QMessageBox.warning(self, "Seed", "Seed must be an integer")
                    self.brute_start_button.setEnabled(True)
                    self.brute_stop_button.setEnabled(False)
                    return

            self.brute_thread = QThread(self)
            self.brute_worker = BruteforceWorker(self.bruteforcer, self.package.original_file, output_dir, self.brute_threads_spin.value(), seed_val)
            self.brute_worker.moveToThread(self.brute_thread)
            self.brute_thread.started.connect(self.brute_worker.run)
            self.brute_worker.progress.connect(self.bruteforce_log.append)
            self.brute_worker.progress.connect(self.on_bruteforce_progress)
            self.brute_worker.tested.connect(self.on_tested_key)
            self.brute_worker.finished.connect(self.on_bruteforce_finished)
            self.brute_worker.finished.connect(self.brute_thread.quit)
            self.brute_thread.finished.connect(self.brute_thread.deleteLater)
            self.brute_thread.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start bruteforce: {str(e)}")

    def stop_bruteforce(self):
        try:
            if hasattr(self, 'bruteforcer') and self.bruteforcer:
                # Prefer a stop() method if available, else set internal flag
                if hasattr(self.bruteforcer, 'stop') and callable(self.bruteforcer.stop):
                    self.bruteforcer.stop()
                else:
                    setattr(self.bruteforcer, '_stop', True)
            self.brute_stop_button.setEnabled(False)
        except Exception as e:
            logging.error(f"Failed to stop bruteforce: {e}")

    def reset_bruteforce(self):
        """Stop any running bruteforce, delete saved state/success files, and reset UI."""
        try:
            # 1) Stop current run if any
            self.stop_bruteforce()

            # 2) Determine current input file
            input_file = None
            try:
                if hasattr(self, 'package') and self.package and hasattr(self.package, 'original_file'):
                    input_file = self.package.original_file
            except Exception:
                input_file = None
            if not input_file:
                # fallback from UI text
                input_file = self.pkg_entry.text().strip()

            # 3) Delete state and success files
            if input_file:
                state_path = f"{input_file}.brutestate.json"
                success_path = f"{input_file}.success"
                try:
                    if os.path.exists(state_path):
                        os.remove(state_path)
                        self.bruteforce_log.append(f"[+] Removed state file: {state_path}")
                except Exception as e:
                    self.bruteforce_log.append(f"[-] Could not remove state file: {e}")
                try:
                    if os.path.exists(success_path):
                        os.remove(success_path)
                        self.bruteforce_log.append(f"[+] Removed success file: {success_path}")
                except Exception as e:
                    self.bruteforce_log.append(f"[-] Could not remove success file: {e}")

            # 4) Reset UI elements
            self.bruteforce_log.clear()
            self.tested_keys_list.clear()
            self.tested_count_label.setText("Shown: 0 (max 1000)")
            self.brute_attempts_label.setText("Attempts: 0")
            self.brute_rate_label.setText("Rate: 0/s")
            self.brute_start_button.setEnabled(True)
            self.brute_stop_button.setEnabled(False)

            QMessageBox.information(self, "Reset", "Bruteforce state has been reset.")
        except Exception as e:
            logging.error(f"Failed to reset bruteforce: {e}")
            QMessageBox.critical(self, "Reset", f"Failed to reset: {e}")

    def on_tested_key(self, key: str):
        # Append with bounded size to avoid memory growth
        MAX_ITEMS = 1000
        self.tested_keys_list.addItem(key)
        if self.tested_keys_list.count() > MAX_ITEMS:
            # Remove from top (oldest)
            item = self.tested_keys_list.takeItem(0)
            del item
        self.tested_count_label.setText(f"Shown: {self.tested_keys_list.count()} (max {MAX_ITEMS})")

    def on_bruteforce_finished(self, result: str):
        # Re-enable UI and show result
        self.brute_start_button.setEnabled(True)
        self.brute_stop_button.setEnabled(False)
        if result:
            self.bruteforce_log.append(result)
            if "successfully" in result.lower() or "[+]" in result:
                QMessageBox.information(self, "Success", result)
            elif result.lower().startswith("[-]"):
                # Show warning for negative outcome
                QMessageBox.warning(self, "Bruteforce", result)

    def on_bruteforce_progress(self, msg: str):
        # Parse attempts/rate lines like: "[~] Attempts: N | Rate: R/s" or with Threads
        try:
            m = re.search(r"Attempts:\s*(\d+).*Rate:\s*([0-9]+(?:\.[0-9]+)?)", msg)
            if m:
                self.brute_attempts_label.setText(f"Attempts: {m.group(1)}")
                self.brute_rate_label.setText(f"Rate: {m.group(2)}/s")
        except Exception:
            pass

    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, 
            "About PKG Tool Box",
            """<h3>PKG Tool Box v1.4.02</h3>
            <p>Created by SeregonWar</p>
            <p>A tool for managing PS3/PS4/PS5 PKG files.</p>
            <p><a href="https://github.com/seregonwar">GitHub</a> | 
            <a href="https://ko-fi.com/seregon">Support on Ko-fi</a></p>"""
        )

    def update_info(self, info_dict):
        """Update info tab with package information"""
        if hasattr(self.info_tab, 'update_info'):
            self.info_tab.update_info(info_dict)

    def update_pkg_entries(self, filename):
        """Update all PKG-related entries with the new filename"""
        self.pkg_entry.setText(filename)
        
        # Set default output directory based on PKG location
        output_dir = os.path.join(os.path.dirname(filename), "output")
        
        # Update entries in various tabs
        if hasattr(self.extract_tab, 'extract_out_entry'):
            self.extract_tab.extract_out_entry.setText(output_dir)
        if hasattr(self.bruteforce_tab, 'bruteforce_out_entry'):
            self.bruteforce_tab.bruteforce_out_entry.setText(output_dir)

    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        shortcuts = {
            'Ctrl+O': self.browse_pkg,
            'Ctrl+E': lambda: self.tab_widget.setCurrentWidget(self.extract_tab),
            'Ctrl+I': lambda: self.tab_widget.setCurrentWidget(self.info_tab),
            'Ctrl+F': self.file_browser.file_search.setFocus,
            'Ctrl+B': self.toggle_sidebar,  # Toggle sidebar
            'Ctrl+W': lambda: self.tab_widget.setCurrentWidget(self.wallpaper_viewer),
            'Ctrl+T': self.show_theme_menu,  # Open theme menu
            'F5': self.refresh_all,
            'F11': self.toggle_fullscreen
        }

        for key, func in shortcuts.items():
            sc = QShortcut(QKeySequence(key), self)
            sc.activated.connect(func)

        # Alt+1..9 to jump to primary sections
        tab_widgets = [
            self.info_tab,
            self.file_browser,
            self.wallpaper_viewer,
            self.extract_tab,
            self.inject_tab,
            self.modify_tab,
            self.trophy_tab,
            self.esmf_decrypter_tab,
        ]
        for i, widget in enumerate(tab_widgets, start=1):
            seq = QKeySequence(f"Alt+{i}")
            qs = QShortcut(seq, self)
            qs.activated.connect(lambda w=widget: self.tab_widget.setCurrentWidget(w))

    def setup_search(self):
        """Setup global search"""
        search_widget = QWidget()
        search_layout = QHBoxLayout(search_widget)
        
        self.global_search = QLineEdit()
        self.global_search.setPlaceholderText("Search everywhere...")
        self.global_search.textChanged.connect(self.perform_global_search)
        
        search_layout.addWidget(self.global_search)
        
        # Aggiungi alla toolbar
        search_toolbar = QToolBar()
        search_toolbar.addWidget(search_widget)
        self.addToolBar(Qt.TopToolBarArea, search_toolbar)

    def perform_global_search(self, text):
        """Perform search across all tabs"""
        if not text:
            return
            
        results = []
        
        # Cerca nei file
        if self.package:
            for file_info in self.package.files.values():
                if text.lower() in file_info.get('name', '').lower():
                    results.append(('File', file_info['name']))
        
        # Cerca nelle info
        for key, value in self.info_tree.items():
            if text.lower() in str(value).lower():
                results.append(('Info', f"{key}: {value}"))
        
        # Mostra risultati
        self.show_search_results(results)

    def show_error(self, title, message, details=None):
        """Show error dialog with details"""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Critical)
        msg.setWindowTitle(title)
        msg.setText(message)
        
        if details:
            msg.setDetailedText(details)
        
        msg.setStandardButtons(QMessageBox.Ok)
        return msg.exec_()

    def handle_error(self, error, operation="Operation"):
        """Handle errors with logging and user feedback"""
        error_msg = str(error)
        error_details = ''.join(traceback.format_exception(type(error), error, error.__traceback__))
        
        Logger.log_error(f"{operation} failed: {error_msg}\n{error_details}")
        self.show_error(
            f"{operation} Failed",
            error_msg,
            error_details
        )

    def setup_drag_drop(self):
        """Setup drag and drop between tabs"""
        self.setAcceptDrops(True)
        
        # Abilita drag and drop per i widget che lo supportano
        if hasattr(self.file_browser, 'file_tree'):
            self.file_browser.file_tree.setDragEnabled(True)
            self.file_browser.file_tree.setAcceptDrops(True)
        
        if hasattr(self.wallpaper_viewer, 'wallpaper_tree'):
            self.wallpaper_viewer.wallpaper_tree.setAcceptDrops(True)
        
        # Connetti i segnali se esistono
        if hasattr(self.file_browser, 'itemDropped'):
            self.file_browser.itemDropped.connect(self.handle_item_drop)
        if hasattr(self.wallpaper_viewer, 'itemDropped'):
            self.wallpaper_viewer.itemDropped.connect(self.handle_item_drop)

    def refresh_all(self):
        """Refresh all views and data"""
        try:
            if self.package:
                # Refresh file browser
                if hasattr(self, 'file_browser'):
                    self.file_browser.load_files(self.package)
                
                # Refresh wallpaper viewer
                if hasattr(self, 'wallpaper_viewer'):
                    self.wallpaper_viewer.load_wallpapers(self.package)
                
                # Refresh PKG icon and info
                self.load_pkg_icon()
                info_dict = self.package.get_info()
                self.update_info(info_dict)
                
                Logger.log_information("All views refreshed successfully")
            else:
                Logger.log_warning("No package loaded to refresh")
                
        except Exception as e:
            error_msg = f"Error refreshing views: {str(e)}"
            Logger.log_error(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def toggle_fullscreen(self):
        """Toggle fullscreen mode"""
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def browse_trophy(self):
        """Browse for trophy file"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select Trophy file",
            "",
            "Trophy files (*.trp *.ucp);;TRP files (*.trp);;UCP files (*.ucp);;All files (*.*)"
        )
        if filename:
            try:
                self.trophy_entry.setText(filename)
                
                # Carica le informazioni del trofeo
                trophy_reader = TRPReader(filename)
                
                # Mostra le informazioni nel text edit
                info_text = f"""
                Title: {trophy_reader._title if trophy_reader._title else 'N/A'}
                NP Communication ID: {trophy_reader._npcommid if trophy_reader._npcommid else 'N/A'}
                Number of Trophies: {len(trophy_reader._trophyList) if trophy_reader._trophyList else 0}
                File Type: {os.path.splitext(filename)[1].upper()[1:]}
                """
                self.trophy_info.setText(info_text)
                
                # Carica i trofei nella tree view
                self.trophy_tree.clear()
                for trophy in trophy_reader._trophyList:
                    item = QTreeWidgetItem(self.trophy_tree)
                    item.setText(0, trophy.name)
                    
                    # Determina il tipo di trofeo dal nome del file
                    if "TROP" in trophy.name.upper():
                        if "BRONZE" in trophy.name.upper():
                            trophy_type = "Bronze"
                        elif "SILVER" in trophy.name.upper():
                            trophy_type = "Silver"
                        elif "GOLD" in trophy.name.upper():
                            trophy_type = "Gold"
                        elif "PLATINUM" in trophy.name.upper():
                            trophy_type = "Platinum"
                        else:
                            trophy_type = "Unknown"
                    else:
                        trophy_type = "Unknown"
                        
                    item.setText(1, trophy_type)  # Tipo di trofeo
                    item.setText(2, self.get_trophy_grade(trophy))  # Grado del trofeo
                    item.setText(3, "No")  # Hidden di default
                    
                    # Salva i dati del trofeo nell'item
                    item.setData(0, Qt.UserRole, trophy)
                
                # Abilita/disabilita pulsanti in base al tipo di file
                is_trp = filename.lower().endswith('.trp')
                self.trophy_decrypt_button.setEnabled(is_trp)
                self.trophy_recompile_button.setEnabled(not is_trp)
                
                Logger.log_information(f"Trophy file loaded: {filename}")
                
            except Exception as e:
                error_msg = f"Error loading trophy file: {str(e)}"
                Logger.log_error(error_msg)
                QMessageBox.critical(self, "Error", error_msg)

    def display_selected_trophy(self, item, column):
        """Display selected trophy information"""
        try:
            trophy = item.data(0, Qt.UserRole)
            if not trophy:
                return
                
            # Aggiorna le informazioni del trofeo
            trophy_details = f"""
            Name: {trophy.name}
            Type: {self.get_trophy_type(trophy)}
            Grade: {self.get_trophy_grade(trophy)}
            Hidden: {'Yes' if hasattr(trophy, 'hidden') and trophy.hidden else 'No'}
            """
            self.trophy_details.setText(trophy_details)
            
            # Carica l'immagine del trofeo se disponibile
            if trophy.name.upper().endswith('.PNG'):
                try:
                    with open(self.trophy_entry.text(), 'rb') as f:
                        f.seek(trophy.offset)
                        image_data = f.read(trophy.size)
                    pixmap = ImageUtils.create_thumbnail(image_data)
                    self.trophy_image_viewer.setPixmap(pixmap)
                    self.trophy_image_viewer.setAlignment(Qt.AlignCenter)
                except Exception as e:
                    Logger.log_error(f"Error loading trophy image: {str(e)}")
                    self.trophy_image_viewer.clear()
            else:
                self.trophy_image_viewer.clear()
                
        except Exception as e:
            Logger.log_error(f"Error displaying trophy: {str(e)}")
            self.trophy_details.clear()
            self.trophy_image_viewer.clear()

    def get_trophy_type(self, trophy):
        """Get trophy type based on filename"""
        name = trophy.name.upper()
        if "BRONZE" in name:
            return "Bronze"
        elif "SILVER" in name:
            return "Silver"
        elif "GOLD" in name:
            return "Gold"
        elif "PLATINUM" in name:
            return "Platinum"
        return "Unknown"

    def get_trophy_grade(self, trophy):
        """Get trophy grade based on filename"""
        name = trophy.name.upper()
        if "TROP" in name:
            if "BRONZE" in name:
                if "COMMON" in name:
                    return "Common"
                elif "UNCOMMON" in name:
                    return "Uncommon"
                elif "RARE" in name:
                    return "Rare"
                elif "VERY_RARE" in name:
                    return "Very Rare"
                return "Common"  # Default per Bronze
            elif "SILVER" in name:
                if "COMMON" in name:
                    return "Common"
                elif "UNCOMMON" in name:
                    return "Uncommon"
                elif "RARE" in name:
                    return "Rare"
                elif "VERY_RARE" in name:
                    return "Very Rare"
                return "Uncommon"  # Default per Silver
            elif "GOLD" in name:
                if "COMMON" in name:
                    return "Common"
                elif "UNCOMMON" in name:
                    return "Uncommon"
                elif "RARE" in name:
                    return "Rare"
                elif "VERY_RARE" in name:
                    return "Very Rare"
                return "Rare"  # Default per Gold
            elif "PLATINUM" in name:
                if "COMMON" in name:
                    return "Common"
                elif "UNCOMMON" in name:
                    return "Uncommon"
                elif "RARE" in name:
                    return "Rare"
                elif "VERY_RARE" in name:
                    return "Very Rare"
                return "Very Rare"  # Default per Platinum
        return "Unknown"

    def show_previous_trophy(self):
        """Show previous trophy in the list"""
        current_item = self.trophy_tree.currentItem()
        if current_item:
            current_index = self.trophy_tree.indexOfTopLevelItem(current_item)
            if current_index > 0:
                previous_item = self.trophy_tree.topLevelItem(current_index - 1)
                self.trophy_tree.setCurrentItem(previous_item)
                self.display_selected_trophy(previous_item, 0)

    def show_next_trophy(self):
        """Show next trophy in the list"""
        current_item = self.trophy_tree.currentItem()
        if current_item:
            current_index = self.trophy_tree.indexOfTopLevelItem(current_item)
            if current_index < self.trophy_tree.topLevelItemCount() - 1:
                next_item = self.trophy_tree.topLevelItem(current_index + 1)
                self.trophy_tree.setCurrentItem(next_item)
                self.display_selected_trophy(next_item, 0)

    def edit_trophy_info(self):
        """Edit selected trophy information"""
        selected_items = self.trophy_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "No trophy selected")
            return
        
        item = selected_items[0]
        trophy_data = item.data(0, Qt.UserRole)
        
        if not trophy_data:
            return
        
        try:
            # Mostra dialog per modificare le informazioni
            dialog = QDialog(self)
            dialog.setWindowTitle("Edit Trophy Info")
            layout = QVBoxLayout(dialog)
            
            # Form per le informazioni modificabili
            form_layout = QGridLayout()
            name_edit = QLineEdit(trophy_data.get('name', ''))
            desc_edit = QTextEdit(trophy_data.get('description', ''))
            type_combo = QComboBox()
            type_combo.addItems(['Bronze', 'Silver', 'Gold', 'Platinum'])
            type_combo.setCurrentText(trophy_data.get('type', 'Bronze'))
            hidden_check = QCheckBox("Hidden")
            hidden_check.setChecked(trophy_data.get('hidden', False))
            
            form_layout.addWidget(QLabel("Name:"), 0, 0)
            form_layout.addWidget(name_edit, 0, 1)
            form_layout.addWidget(QLabel("Description:"), 1, 0)
            form_layout.addWidget(desc_edit, 1, 1)
            form_layout.addWidget(QLabel("Type:"), 2, 0)
            form_layout.addWidget(type_combo, 2, 1)
            form_layout.addWidget(hidden_check, 3, 1)
            
            layout.addLayout(form_layout)
            
            # Pulsanti
            buttons = QHBoxLayout()
            save_btn = QPushButton("Save")
            cancel_btn = QPushButton("Cancel")
            save_btn.clicked.connect(dialog.accept)
            cancel_btn.clicked.connect(dialog.reject)
            buttons.addWidget(save_btn)
            buttons.addWidget(cancel_btn)
            layout.addLayout(buttons)
            
            if dialog.exec_() == QDialog.Accepted:
                # Aggiorna i dati del trofeo
                trophy_data['name'] = name_edit.text()
                trophy_data['description'] = desc_edit.toPlainText()
                trophy_data['type'] = type_combo.currentText()
                trophy_data['hidden'] = hidden_check.isChecked()
                
                # Aggiorna la visualizzazione
                item.setText(0, trophy_data['name'])
                item.setText(1, trophy_data['type'])
                item.setText(2, trophy_data['grade'])
                item.setText(3, 'Yes' if trophy_data['hidden'] else 'No')
                
                self.display_selected_trophy(item, 0)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to edit trophy: {str(e)}")

    def recompile_trp(self):
        """Recompile TRP file"""
        try:
            if not hasattr(self, 'trophy_files'):
                QMessageBox.warning(self, "Warning", "No trophy files loaded")
                return
                
            output_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save TRP File",
                "",
                "TRP files (*.trp)"
            )
            
            if not output_path:
                return
                
            creator = TRPCreator()
            creator.create(output_path, self.trophy_files)
            
            QMessageBox.information(self, "Success", "TRP file created successfully")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create TRP: {str(e)}")

    def decrypt_trophy(self):
        """Decrypt selected trophy file"""
        try:
            if not self.trophy_entry.text():
                QMessageBox.warning(self, "Warning", "No trophy file selected")
                return
                
            output_dir = QFileDialog.getExistingDirectory(
                self,
                "Select Output Directory"
            )
            
            if not output_dir:
                return
                
            decrypter = TRPReader()
            decrypter.decrypt_trp(self.trophy_entry.text(), output_dir)
            
            QMessageBox.information(self, "Success", "Trophy file decrypted successfully")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to decrypt trophy: {str(e)}")

    def retranslate_ui(self):
        """Update UI text with current language"""
        # Update window title
        self.setWindowTitle(self.translator.translate("PKG Tool Box v1.4.0"))
        
        # Update menu items
        self.file_menu.setTitle(self.translator.translate("File"))
        self.tools_menu.setTitle(self.translator.translate("Tools"))
        self.view_menu.setTitle(self.translator.translate("View"))
        self.help_menu.setTitle(self.translator.translate("Help"))
        
        # Update actions
        self.open_action.setText(self.translator.translate("Open PKG"))
        self.exit_action.setText(self.translator.translate("Exit"))
        
        # Update tab names
        self.tab_widget.setTabText(0, self.translator.translate("Info"))
        self.tab_widget.setTabText(1, self.translator.translate("File Browser"))

        
        # Force update
        self.update()

    def should_skip_updates(self):
        """Check if user has chosen to skip updates"""
        try:
            config_file = os.path.join(os.path.expanduser("~"), ".pkgtoolbox", "update_preferences.json")
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    prefs = json.load(f)
                    return prefs.get("skip_updates", False)
        except:
            pass
        return False

    def show_update_dialog(self, version, download_url):
        """Show update dialog when new version is available"""
        dialog = UpdateDialog(version, download_url, self)
        dialog.exec_()

    def handle_update_error(self, error_msg):
        """Handle errors during update check"""
        Logger.log_error(f"Update check failed: {error_msg}")