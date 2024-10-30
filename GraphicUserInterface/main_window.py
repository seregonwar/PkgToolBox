import logging
import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, QTabWidget,
                            QMessageBox, QToolBar, QAction, QTreeWidget, QTextEdit, QTableWidget, QFileDialog, QGroupBox, QGridLayout, QSpinBox, QTreeWidgetItem, QDialog, QProgressBar, QShortcut, QActionGroup, QComboBox, QCheckBox)
from PyQt5.QtCore import Qt, QSize, QUrl
from PyQt5.QtGui import QFont, QDesktopServices
from PyQt5.QtWidgets import QStyle
import struct
from GraphicUserInterface.components import FileBrowser, WallpaperViewer
from GraphicUserInterface.dialogs import SettingsDialog
from GraphicUserInterface.utils import StyleManager, ImageUtils, FileUtils
from PS5_Game_Info import PS5GameInfo
from packages import PackagePS4, PackagePS5, PackagePS3
from file_operations import extract_file, inject_file, modify_file_header
from Utilities.Trophy import ESMFDecrypter, TRPCreator
from PS4_Passcode_Bruteforcer import PS4PasscodeBruteforcer
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
        
        # Load settings
        config_file = os.path.join(os.path.expanduser("~"), ".pkgtoolbox", "config.json")
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                settings_dict = json.load(f)
        else:
            settings_dict = {
                "theme": "Light",
                "night_mode": False,
                "font_family": "Arial",
                "font_size": 12,
                "bg_color": "#ffffff",
                "text_color": "#000000",
                "accent_color": "#3498db"
            }
        
        # Apply settings
        self.night_mode = settings_dict.get("night_mode", False)
        self.font = QFont(
            settings_dict.get("font_family", "Arial"),
            settings_dict.get("font_size", 12)
        )
        QApplication.setFont(self.font)
        
        # Apply theme
        theme_colors = {
            'bg_color': settings_dict.get("bg_color", "#ffffff"),
            'text_color': settings_dict.get("text_color", "#000000"),
            'accent_color': settings_dict.get("accent_color", "#3498db")
        }
        StyleManager.apply_theme(self, theme_colors)
        
        # Setup UI
        self.setup_ui()
        self.setup_settings_button()
        
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

    def set_style(self):
        """Set application style based on theme"""
        colors = self.COLORS['dark'] if self.night_mode else self.COLORS['light']
        
        self.setStyleSheet(f"""
            /* Base styles */
            QMainWindow, QWidget {{ 
                background-color: {colors['background']}; 
                color: {colors['text']}; 
            }}
            
            /* Input fields */
            QLineEdit, QTextEdit, QPlainTextEdit {{ 
                background-color: {colors['secondary']}; 
                color: {colors['text']}; 
                border: 1px solid {colors['accent']};
                border-radius: 4px;
                padding: 5px;
            }}
            
            /* Buttons */
            QPushButton {{ 
                background-color: {colors['accent']}; 
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {colors['tree_selected']};
            }}
            QPushButton:pressed {{
                background-color: {colors['tree_hover']};
            }}
            QPushButton:disabled {{
                background-color: {colors['secondary']};
                color: {colors['text']};
                opacity: 0.5;
            }}
            
            /* Tree and List Widgets */
            QTreeWidget, QListWidget {{ 
                background-color: {colors['background']};
                alternate-background-color: {colors['tree_alternate']};
                color: {colors['text']};
                border: 1px solid {colors['accent']};
                border-radius: 4px;
            }}
            QTreeWidget::item:hover, QListWidget::item:hover {{
                background-color: {colors['tree_hover']};
            }}
            QTreeWidget::item:selected, QListWidget::item:selected {{
                background-color: {colors['tree_selected']};
                color: white;
            }}
            
            /* Headers */
            QHeaderView::section {{
                background-color: {colors['secondary']};
                color: {colors['text']};
                padding: 5px;
                border: none;
            }}
            
            /* Tabs */
            QTabWidget::pane {{ 
                border: 1px solid {colors['accent']}; 
                border-radius: 4px;
            }}
            QTabBar::tab {{ 
                background: {colors['secondary']}; 
                color: {colors['text']};
                padding: 8px;
                margin: 2px;
                border-radius: 4px;
            }}
            QTabBar::tab:selected {{ 
                background: {colors['accent']}; 
                color: white;
            }}
            QTabBar::tab:hover {{
                background: {colors['tree_hover']};
            }}
            
            /* Labels */
            QLabel {{ 
                color: {colors['text']}; 
            }}
            
            /* Menus */
            QMenuBar {{
                background-color: {colors['background']};
                color: {colors['text']};
            }}
            QMenuBar::item {{
                background-color: transparent;
            }}
            QMenuBar::item:selected {{
                background-color: {colors['tree_hover']};
            }}
            QMenu {{
                background-color: {colors['background']};
                color: {colors['text']};
                border: 1px solid {colors['accent']};
            }}
            QMenu::item:selected {{
                background-color: {colors['tree_selected']};
                color: white;
            }}
            
            /* Combo Boxes */
            QComboBox {{
                background-color: {colors['secondary']};
                color: {colors['text']};
                border: 1px solid {colors['accent']};
                border-radius: 4px;
                padding: 5px;
            }}
            QComboBox:hover {{
                border-color: {colors['tree_selected']};
            }}
            QComboBox::drop-down {{
                border: none;
            }}
            QComboBox::down-arrow {{
                image: none;
                border: none;
            }}
            QComboBox QAbstractItemView {{
                background-color: {colors['background']};
                color: {colors['text']};
                selection-background-color: {colors['tree_selected']};
                selection-color: white;
            }}
            
            /* Spin Boxes */
            QSpinBox {{
                background-color: {colors['secondary']};
                color: {colors['text']};
                border: 1px solid {colors['accent']};
                border-radius: 4px;
                padding: 5px;
            }}
            
            /* Check Boxes */
            QCheckBox {{
                color: {colors['text']};
            }}
            QCheckBox::indicator {{
                width: 13px;
                height: 13px;
            }}
            
            /* Scroll Bars */
            QScrollBar:vertical {{
                background-color: {colors['secondary']};
                width: 12px;
                margin: 0px;
                border-radius: 6px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {colors['accent']};
                min-height: 20px;
                border-radius: 6px;
            }}
            QScrollBar:horizontal {{
                background-color: {colors['secondary']};
                height: 12px;
                margin: 0px;
                border-radius: 6px;
            }}
            QScrollBar::handle:horizontal {{
                background-color: {colors['accent']};
                min-width: 20px;
                border-radius: 6px;
            }}
            
            /* Tool Tips */
            QToolTip {{
                background-color: {colors['background']};
                color: {colors['text']};
                border: 1px solid {colors['accent']};
                border-radius: 4px;
                padding: 5px;
            }}
            
            /* Status Bar */
            QStatusBar {{
                background-color: {colors['secondary']};
                color: {colors['text']};
            }}
            
            /* Tool Bar */
            QToolBar {{
                background-color: {colors['background']};
                border: none;
                spacing: 10px;
            }}
            QToolBar::separator {{
                background-color: {colors['accent']};
                width: 1px;
                margin: 4px;
            }}
            
            /* Group Box */
            QGroupBox {{
                border: 1px solid {colors['accent']};
                border-radius: 4px;
                margin-top: 1ex;
                padding: 5px;
                color: {colors['text']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 3px;
                color: {colors['text']};
            }}
        """)

    def setup_ui(self):
        """Setup the main UI"""
        self.setWindowTitle("PKG Tool Box v1.5.3(dev version)")
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
        
        # PKG icon and info
        self.image_label = QLabel()
        self.image_label.setFixedSize(300, 300)
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet("background-color: white; border: 1px solid #3498db; border-radius: 5px;")
        
        self.content_id_label = QLabel()
        self.content_id_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        
        left_layout.addWidget(self.image_label)
        left_layout.addWidget(self.content_id_label)
        
        # Add drag-drop label
        self.drag_drop_label = QLabel("Drag PKG files here")
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
        left_layout.addWidget(self.drag_drop_label)
        
        # File selection
        pkg_layout = QHBoxLayout()
        self.pkg_entry = QLineEdit()
        self.pkg_entry.setPlaceholderText("Select PKG file")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_pkg)
        pkg_layout.addWidget(self.pkg_entry)
        pkg_layout.addWidget(browse_button)
        left_layout.addLayout(pkg_layout)
        
        left_layout.addStretch()
        
        # Right panel with tabs
        self.tab_widget = QTabWidget()
        
        # Info tab
        self.info_tab = QWidget()
        self.setup_info_tab()
        self.tab_widget.addTab(self.info_tab, "Info")
        
        # File Browser tab
        self.file_browser = FileBrowser(self)
        self.tab_widget.addTab(self.file_browser, "File Browser")
        
        # Wallpaper tab
        self.wallpaper_viewer = WallpaperViewer(self)
        self.tab_widget.addTab(self.wallpaper_viewer, "Wallpaper")
        
        # Extract tab
        self.extract_tab = QWidget()
        self.setup_extract_tab()
        self.tab_widget.addTab(self.extract_tab, "Extract")
        
        # Dump tab
        self.dump_tab = QWidget()
        self.setup_dump_tab()
        self.tab_widget.addTab(self.dump_tab, "Dump")
        
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
        self.bruteforce_tab = QWidget()
        self.setup_bruteforce_tab()
        self.tab_widget.addTab(self.bruteforce_tab, "Passcode Bruteforcer")
        
        split_layout.addWidget(left_panel, 1)
        split_layout.addWidget(self.tab_widget, 2)
        main_layout.addLayout(split_layout)
        
        # Credits and social buttons
        credits_layout = QHBoxLayout()
        
        # Left side - Credits label
        credits_label = QLabel("Created by SeregonWar")
        credits_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #7f8c8d;
                padding: 5px;
            }
        """)
        credits_layout.addWidget(credits_label)
        
        # Center - Social buttons
        social_layout = QHBoxLayout()
        social_layout.setSpacing(5)  # Riduce lo spazio tra i pulsanti
        
        # Stile comune per i pulsanti social
        social_button_style = """
            QPushButton {
                font-size: 11px;
                color: white;
                background-color: #3498db;
                border: none;
                border-radius: 3px;
                padding: 3px 8px;
                min-width: 60px;
                max-width: 60px;
                height: 20px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """
        
        x_button = QPushButton("X")
        github_button = QPushButton("GitHub")
        reddit_button = QPushButton("Reddit")
        
        for button in [x_button, github_button, reddit_button]:
            button.setStyleSheet(social_button_style)
            social_layout.addWidget(button)
        
        # Connetti i pulsanti agli URL
        x_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://x.com/SeregonWar")))
        github_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://github.com/seregonwar")))
        reddit_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://www.reddit.com/user/S3R3GON/")))
        
        social_widget = QWidget()
        social_widget.setLayout(social_layout)
        credits_layout.addWidget(social_widget)
        
        # Right side - Ko-fi button
        kofi_button = QPushButton("Support on Ko-fi")
        kofi_button.setStyleSheet("""
            QPushButton {
                font-size: 11px;
                color: white;
                background-color: #e74c3c;
                border: none;
                border-radius: 3px;
                padding: 3px 8px;
                min-width: 100px;
                max-width: 100px;
                height: 20px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        kofi_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://ko-fi.com/seregon")))
        credits_layout.addWidget(kofi_button)
        
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
        
        dump_action = QAction('Dump PKG', self)
        dump_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.dump_tab))
        self.tools_menu.addAction(dump_action)
        
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
        view_menu = menubar.addMenu('View')
        
        file_browser_action = QAction('File Browser', self)
        file_browser_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.file_browser))
        view_menu.addAction(file_browser_action)
        
        wallpaper_action = QAction('Wallpaper Viewer', self)
        wallpaper_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.wallpaper_viewer))
        view_menu.addAction(wallpaper_action)
        
        # Links menu
        links_menu = menubar.addMenu('Links')
        
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
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        # Aggiungi un menu View con opzioni per il tema
        theme_menu = view_menu.addMenu('Theme')
        theme_group = QActionGroup(self)
        
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
        
        # Status bar
        self.status_bar = self.statusBar()
        self.pkg_info_label = QLabel()
        self.status_bar.addPermanentWidget(self.pkg_info_label)
        
        # Progress bar nella status bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.hide()
        self.status_bar.addPermanentWidget(self.progress_bar)

    def setup_settings_button(self):
        """Add settings button to toolbar"""
        settings_toolbar = QToolBar()
        settings_toolbar.setIconSize(QSize(24, 24))
        
        # Crea un'icona personalizzata che si adatta al tema
        settings_icon = self.style().standardIcon(QStyle.SP_FileDialogDetailedView)
        settings_button = QAction(settings_icon, "", self)
        settings_button.setToolTip("Settings")
        settings_button.triggered.connect(self.show_settings_dialog)
        
        # Applica lo stile che si adatta al tema
        settings_toolbar.setStyleSheet("""
            QToolBar {
                spacing: 10px;
                border: none;
                background: transparent;
            }
            QToolButton {
                border: none;
                border-radius: 4px;
                padding: 4px;
            }
            QToolButton:hover {
                background-color: rgba(52, 152, 219, 0.2);
            }
        """)
        
        settings_toolbar.addAction(settings_button)
        self.addToolBar(Qt.TopToolBarArea, settings_toolbar)
        settings_toolbar.setMovable(False)

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
        """Handle drag leave event"""
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
                    font-size: 16px;
                    color: #7f8c8d;
                    padding: 20px;
                    border: 2px dashed #bdc3c7;
                    border-radius: 10px;
                    background-color: rgba(236, 240, 241, 0.5);
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
        
        # Extract log
        self.extract_log = QTextEdit()
        self.extract_log.setReadOnly(True)
        layout.addWidget(self.extract_log)
        
        # Extract button
        extract_button = QPushButton("Extract")
        extract_button.clicked.connect(self.extract_pkg)
        layout.addWidget(extract_button)

    def setup_dump_tab(self):
        """Setup the dump tab"""
        layout = QVBoxLayout(self.dump_tab)
        
        # Output directory selection
        output_layout = QHBoxLayout()
        self.dump_out_entry = QLineEdit()
        self.dump_out_entry.setPlaceholderText("Select output directory")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(lambda: self.browse_directory(self.dump_out_entry))
        output_layout.addWidget(self.dump_out_entry)
        output_layout.addWidget(browse_button)
        layout.addLayout(output_layout)
        
        # Dump button
        dump_button = QPushButton("Dump")
        dump_button.clicked.connect(self.dump_pkg)
        layout.addWidget(dump_button)

    def setup_inject_tab(self):
        """Setup the inject tab"""
        layout = QVBoxLayout(self.inject_tab)
        
        # File selection
        file_layout = QHBoxLayout()
        self.inject_file_entry = QLineEdit()
        self.inject_file_entry.setPlaceholderText("Select file to inject")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(lambda: self.browse_file(self.inject_file_entry))
        file_layout.addWidget(self.inject_file_entry)
        file_layout.addWidget(browse_button)
        layout.addLayout(file_layout)
        
        # Input file selection
        input_layout = QHBoxLayout()
        self.inject_input_entry = QLineEdit()
        self.inject_input_entry.setPlaceholderText("Select input file")
        input_browse = QPushButton("Browse")
        input_browse.clicked.connect(lambda: self.browse_file(self.inject_input_entry))
        input_layout.addWidget(self.inject_input_entry)
        input_layout.addWidget(input_browse)
        layout.addLayout(input_layout)
        
        # Inject button
        inject_button = QPushButton("Inject")
        inject_button.clicked.connect(self.inject_file)
        layout.addWidget(inject_button)

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
        
        # Or label
        or_label = QLabel("- OR -")
        or_label.setAlignment(Qt.AlignCenter)
        passcode_layout.addWidget(or_label)
        
        # Bruteforce button
        start_button = QPushButton("Start Bruteforce")
        start_button.clicked.connect(self.run_bruteforce)
        passcode_layout.addWidget(start_button)
        
        passcode_group.setLayout(passcode_layout)
        layout.addWidget(passcode_group)
        
        # Log display
        self.bruteforce_log = QTextEdit()
        self.bruteforce_log.setReadOnly(True)
        layout.addWidget(self.bruteforce_log)

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

        try:
            result = self.package.dump(output_dir)
            self.extract_log.append(result)
            QMessageBox.information(self, "Success", "PKG extracted successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to extract PKG: {str(e)}")

    def dump_pkg(self):
        """Dump PKG contents"""
        if not self.package:
            QMessageBox.warning(self, "Warning", "Please load a PKG file first")
            return

        output_dir = self.dump_out_entry.text()
        if not output_dir:
            QMessageBox.warning(self, "Warning", "Please select an output directory")
            return

        try:
            result = self.package.dump(output_dir)
            QMessageBox.information(self, "Success", result)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to dump PKG: {str(e)}")

    def inject_file(self):
        """Inject file into PKG"""
        if not self.package:
            QMessageBox.warning(self, "Warning", "Please load a PKG file first")
            return

        file_path = self.inject_file_entry.text()
        input_path = self.inject_input_entry.text()

        if not file_path or not input_path:
            QMessageBox.warning(self, "Warning", "Please select both file to inject and input file")
            return

        try:
            file_info = self.package.get_file_info(file_path)
            result = inject_file(self.package.original_file, file_info, input_path)
            QMessageBox.information(self, "Success", f"File injected: {result} bytes")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to inject file: {str(e)}")

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

        try:
            bruteforcer = PS4PasscodeBruteforcer()
            result = bruteforcer.brute_force_passcode(
                self.package.original_file,
                output_dir,
                lambda msg: self.bruteforce_log.append(msg)
            )
            self.bruteforce_log.append(result)
            QMessageBox.information(self, "Success", result)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to bruteforce passcode: {str(e)}")

    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, 
            "About PKG Tool Box",
            """<h3>PKG Tool Box v1.5.2</h3>
            <p>Created by SeregonWar</p>
            <p>A tool for managing PS3/PS4/PS5 PKG files.</p>
            <p><a href="https://github.com/seregonwar">GitHub</a> | 
            <a href="https://ko-fi.com/seregon">Support on Ko-fi</a></p>"""
        )

    def update_info(self, info_dict):
        """Update info tab with package information"""
        self.info_tree.clear()
        
        # Dizionario delle descrizioni per ogni chiave
        descriptions = {
            "pkg_magic": "Magic number identifying the PKG file format",
            "pkg_type": "Type of the PKG (e.g., 0x1 for PS4)",
            "pkg_file_count": "Number of files contained in the PKG",
            "pkg_entry_count": "Number of entries in the PKG table",
            "pkg_sc_entry_count": "Number of entries in the SC table",
            "pkg_entry_data_size": "Size of the entry data in bytes",
            "pkg_body_size": "Size of the PKG body in bytes",
            "pkg_content_id": "Unique identifier for the PKG content",
            "pkg_content_type": "Type of content in the PKG",
            "pkg_content_flags": "Flags describing the content",
            "pkg_promote_size": "Size of promotional content",
            "pkg_version_date": "Version date of the PKG",
            "pkg_version": "Package version",
            "pkg_revision": "PKG format revision",
            "title_id": "Title ID",
            "system_version": "Minimum required system version",
            "app_version": "Application version",
            "total_size": "Total package size",
            "pkg_size": "Package size",
            "install_directory": "Installation directory",
            "content_id": "Content ID",
            # ... aggiungi altre descrizioni secondo necessità ...
        }
        
        # Aggiungi le informazioni al tree widget
        for key, value in info_dict.items():
            item = QTreeWidgetItem(self.info_tree)
            item.setText(0, str(key))  # Chiave
            item.setText(1, str(value))  # Valore
            item.setText(2, descriptions.get(key, ""))  # Descrizione
        
        # Ridimensiona le colonne per adattarsi al contenuto
        self.info_tree.resizeColumnToContents(0)
        self.info_tree.resizeColumnToContents(1)
        self.info_tree.resizeColumnToContents(2)

    def update_pkg_entries(self, filename):
        """Update all PKG-related entries with the new filename"""
        self.pkg_entry.setText(filename)
        
        # Set default output directory based on PKG location
        output_dir = os.path.join(os.path.dirname(filename), "output")
        
        # Update entries in various tabs
        if hasattr(self, 'extract_out_entry'):
            self.extract_out_entry.setText(output_dir)
        if hasattr(self, 'dump_out_entry'):
            self.dump_out_entry.setText(output_dir)
        if hasattr(self, 'bruteforce_out_entry'):
            self.bruteforce_out_entry.setText(output_dir)

    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        shortcuts = {
            'Ctrl+O': self.browse_pkg,
            'Ctrl+E': lambda: self.tab_widget.setCurrentWidget(self.extract_tab),
            'Ctrl+D': lambda: self.tab_widget.setCurrentWidget(self.dump_tab),
            'Ctrl+I': lambda: self.tab_widget.setCurrentWidget(self.info_tab),
            'Ctrl+F': self.file_browser.file_search.setFocus,
            'Ctrl+B': lambda: self.tab_widget.setCurrentWidget(self.file_browser),
            'Ctrl+W': lambda: self.tab_widget.setCurrentWidget(self.wallpaper_viewer),
            'F5': self.refresh_all,
            'F11': self.toggle_fullscreen
        }
        
        for key, func in shortcuts.items():
            shortcut = QShortcut(QKeySequence(key), self)
            shortcut.activated.connect(func)

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
        self.setWindowTitle(self.translator.translate("PKG Tool Box v1.5.2"))
        
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
        # ... aggiorna altri tab ...
        
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