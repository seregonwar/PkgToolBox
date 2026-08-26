import logging
import os
import re
import shutil
import sys
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, QTabWidget,
                            QMessageBox, QToolBar, QTreeWidget, QTextEdit, QTableWidget, QTableWidgetItem, QFileDialog, QGroupBox, QGridLayout, QSpinBox, QTreeWidgetItem, QDialog, QProgressBar, QComboBox, QCheckBox, QListWidget, QFrame, QSplitter)
from PySide6.QtCore import Qt, QSize, QUrl, QObject, Signal, QThread, QTimer
from PySide6.QtGui import QFont, QDesktopServices, QAction, QShortcut, QActionGroup, QKeySequence, QGuiApplication, QPixmap
import struct
import xml.etree.ElementTree as ET
from GUI.components import FileBrowser, WallpaperViewer
from GUI.dialogs import SettingsDialog
from GUI.utils import StyleManager, ImageUtils, FileUtils
from GUI.utils.icons import get_icon, get_sidebar_icons, svg_file_to_icon, scale_pixmap_sharp
from GUI.widgets import InfoTab, BruteforceTab, ModifyTab, TrpCreatorTab
from GUI.widgets.pfs_info_tab import PfsInfoTab
from tools.PS5_Game_Info import PS5GameInfo
from packages import (
    GP4Project,
    GP5Project,
    StandaloneFileSource,
    PackagePS4,
    PackagePS5,
    PackagePS3,
    open_source,
)
from Utilities.Trophy import ESMFDecrypter, TRPCreator
from tools.PS4_Passcode_Bruteforcer import PS4PasscodeBruteforcer
from Utilities import Logger
import json

import traceback
from Utilities import Logger, TRPReader  
from .locales.translator import Translator
from GUI.dialogs.pkg_file_picker import PkgFilePickerDialog
from GUI.utils.update_checker import UpdateChecker, pick_asset_for_current_platform, launch_downloaded_asset

class MainWindow(QMainWindow):

    def __init__(self, temp_directory):
        super().__init__()
        self.temp_directory = temp_directory
        self.package = None
        self._dirty = False  # true when there are unsaved edits (e.g. PS5 game info)
        
        # Initialize settings manager
        
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

        # Setup UI
        self.setup_ui()
        self.setup_settings_button()
        self._place_window_on_screen()

        # Highlight the sidebar button of the active tab (all switch paths)
        self.tab_widget.currentChanged.connect(self._update_nav_highlight)
        # Inner workspaces keep the compact navigation highlight in sync.
        for workspace in (self.contents_workspace, self.modify_tab.sub_tabs, self.tools_workspace):
            workspace.currentChanged.connect(lambda _i: self._update_nav_highlight())
        self._update_nav_highlight()
        
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
        self.update_checker.update_available.connect(self.show_update_banner)
        self.update_checker.error_occurred.connect(self.handle_update_error)
        self.update_checker.download_progress.connect(self._on_update_download_progress)
        self.update_checker.download_finished.connect(self._on_update_download_finished)
        self._update_info = None  # {version, download_url, assets}

        # Check for updates once at startup, then poll periodically
        if not self.should_skip_updates():
            self.update_checker.start()
            self._update_poll_timer = QTimer(self)
            self._update_poll_timer.setInterval(6 * 60 * 60 * 1000)  # every 6 hours
            self._update_poll_timer.timeout.connect(self.update_checker.start)
            self._update_poll_timer.start()

        # Apply the persisted theme at startup (also enables system-theme following)
        self._reapply_saved_theme()

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

    def setup_ui(self):
        """Setup the main UI"""
        self.setWindowTitle("PKG Tool Box v1.5.0")
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Update banner (hidden until a newer release is detected)
        self.update_banner = QFrame()
        self.update_banner.setObjectName("updateBanner")
        self.update_banner.setVisible(False)
        banner_layout = QHBoxLayout(self.update_banner)
        banner_layout.setContentsMargins(12, 8, 12, 8)
        banner_layout.setSpacing(8)

        self.update_banner_label = QLabel()
        self.update_banner_label.setWordWrap(True)
        banner_layout.addWidget(self.update_banner_label, 1)

        self.update_download_btn = QPushButton("Download")
        self.update_download_btn.setCursor(Qt.PointingHandCursor)
        self.update_download_btn.clicked.connect(self._open_update_page)
        banner_layout.addWidget(self.update_download_btn)

        self.update_install_btn = QPushButton("Install")
        self.update_install_btn.setObjectName("updateInstallBtn")
        self.update_install_btn.setCursor(Qt.PointingHandCursor)
        self.update_install_btn.clicked.connect(self._install_update)
        banner_layout.addWidget(self.update_install_btn)

        self.update_dismiss_btn = QPushButton("\u2715")
        self.update_dismiss_btn.setObjectName("updateDismissBtn")
        self.update_dismiss_btn.setToolTip("Dismiss")
        self.update_dismiss_btn.setFixedSize(24, 24)
        self.update_dismiss_btn.setCursor(Qt.PointingHandCursor)
        self.update_dismiss_btn.clicked.connect(lambda: self.update_banner.hide())
        banner_layout.addWidget(self.update_dismiss_btn)

        main_layout.insertWidget(0, self.update_banner)
        self._style_update_banner()

        # Split layout
        split_layout = QHBoxLayout()
        
        # Left panel for PKG info (collapsible via the toolbar toggle / splitter)
        self.left_panel = QWidget()
        self.left_panel.setMinimumWidth(220)
        left_layout = QVBoxLayout(self.left_panel)
        
        # PKG icon and info — minimal card styled with theme colors
        tc = self._current_theme_colors()
        self.image_label = QLabel()
        self.image_label.setFixedSize(180, 180)
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet(f"""
            QLabel {{
                background-color: {tc['secondary_bg']};
                border: 1px solid {tc['border']};
                border-radius: 12px;
                padding: 12px;
            }}
        """)
        
        self.content_id_label = QLabel()
        self.content_id_label.setAlignment(Qt.AlignCenter)
        self.content_id_label.setWordWrap(True)
        self.content_id_label.setStyleSheet(f"""
            QLabel {{
                font-size: 14px;
                font-weight: 600;
                color: {tc['text']};
                padding: 10px 14px;
                background-color: {tc['secondary_bg']};
                border: 1px solid {tc['border']};
                border-radius: 10px;
                margin: 6px 0px;
            }}
        """)
        
        left_layout.addWidget(self.image_label)
        left_layout.addWidget(self.content_id_label)
        
        # Drag-drop zone — colors come from the active theme (all states)
        self.drag_drop_label = QLabel("Drop a package, project or file here")
        self.drag_drop_label.setAlignment(Qt.AlignCenter)
        self._set_drag_style(False)
        left_layout.addWidget(self.drag_drop_label)
        
        # PKG file selection (styling handled by the global theme)
        pkg_layout = QHBoxLayout()
        self.pkg_entry = QLineEdit()
        self.pkg_entry.setPlaceholderText("Select a package, GP4/GP5 project or file...")
        
        browse_button = QPushButton("Open…")
        browse_button.clicked.connect(self.browse_pkg)
        
        pkg_layout.addWidget(self.pkg_entry, 1)
        pkg_layout.addWidget(browse_button)
        left_layout.addLayout(pkg_layout)
        
        # Extract the loaded PKG into a user-chosen folder (modal dialog for
        # the destination, then background extraction). Disabled until a PKG
        # is loaded.
        self.extract_btn = QPushButton("Extract package")
        self.extract_btn.setToolTip("Extract or export the loaded source into a destination folder")
        self.extract_btn.setEnabled(False)
        self.extract_btn.clicked.connect(self.extract_pkg_dialog)
        left_layout.addWidget(self.extract_btn)

        left_layout.addStretch()
        
        # Tab widget (styling handled by the global theme; tab bar hidden —
        # navigation is driven by the sidebar)
        self.tab_widget = QTabWidget()

        # Four coherent workspaces replace the former long list of isolated
        # pages.  Existing widgets stay available as focused inner tabs.
        self.info_tab = InfoTab(self)
        self.tab_widget.addTab(self.info_tab, "Overview")

        self.contents_workspace = QTabWidget()
        self.contents_workspace.setDocumentMode(True)
        self.file_browser = FileBrowser(self)
        self.contents_workspace.addTab(self.file_browser, "Files")
        self.wallpaper_viewer = WallpaperViewer(self)
        self.contents_workspace.addTab(self.wallpaper_viewer, "Images")
        self.pfs_info_tab = PfsInfoTab(self)
        self.contents_workspace.addTab(self.pfs_info_tab, "Filesystem")
        self.tab_widget.addTab(self.contents_workspace, "Contents")
        
        self.modify_tab = ModifyTab(self)
        self.tab_widget.addTab(self.modify_tab, "Inspect & edit")
        
        self.tools_workspace = QTabWidget()
        self.tools_workspace.setDocumentMode(True)
        self.trophy_tab = QWidget()
        self.setup_trophy_tab()
        self.tools_workspace.addTab(self.trophy_tab, "Trophies")
        self.esmf_decrypter_tab = QWidget()
        self.setup_esmf_decrypter_tab()
        self.tools_workspace.addTab(self.esmf_decrypter_tab, "ESMF")
        self.trp_create_tab = TrpCreatorTab(self)
        self.tools_workspace.addTab(self.trp_create_tab, "Create TRP")
        self.ps5_game_info_tab = QWidget()
        self.setup_ps5_game_info_tab()
        self.tools_workspace.addTab(self.ps5_game_info_tab, "PS5 executable")
        self.bruteforce_tab = BruteforceTab(self)
        self.tools_workspace.addTab(self.bruteforce_tab, "Encryption")
        self.tab_widget.addTab(self.tools_workspace, "Tools")

        # Hide native tab bar – navigation handled by sidebar and build sidebar
        self.tab_widget.tabBar().hide()
        self.create_sidebar()
        
        split_layout.addWidget(self.sidebar_frame)

        # PKG panel + tab area in a draggable splitter; the left panel can be
        # dragged to 0 or hidden entirely with the toolbar toggle button
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.addWidget(self.left_panel)
        self.splitter.addWidget(self.tab_widget)
        self.splitter.setStretchFactor(0, 0)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setCollapsible(0, True)
        self.splitter.setCollapsible(1, False)
        self.splitter.setSizes([300, 900])
        split_layout.addWidget(self.splitter, 1)
        main_layout.addLayout(split_layout)

        # Restore the persisted panel visibility (hidden by default in the toggle)
        layout_state = self.settings_dict.get("layout", {})
        if layout_state.get("left_panel_visible", True) is False:
            self.left_panel.hide()
        
        # Credits and social buttons
        credits_layout = QHBoxLayout()

        # Left side - app logo (transparent PNG, works on light and dark themes;
        # scaled at the screen's devicePixelRatio so it stays sharp on Retina)
        self.logo_label = QLabel()
        self.logo_label.setToolTip("PkgToolBox")
        logo_path = self._app_resource_path("logos", "logo.png")
        if os.path.exists(logo_path):
            pixmap = QPixmap(logo_path)
            if not pixmap.isNull():
                self.logo_label.setPixmap(scale_pixmap_sharp(pixmap, 110, 37))
        credits_layout.addWidget(self.logo_label, 0, Qt.AlignLeft)

        # Center - Social buttons (official brand marks, tinted white/black
        # according to the active theme)
        social_layout = QHBoxLayout()
        social_layout.setSpacing(10)

        self.social_buttons = {}
        brand_links = [
            ("x", "Open X / Twitter", "https://x.com/SeregonWar"),
            ("github", "Open GitHub profile", "https://github.com/seregonwar"),
            ("reddit", "Open Reddit profile", "https://www.reddit.com/user/S3R3GON/"),
        ]
        for key, tooltip, url in brand_links:
            button = QPushButton()
            button.setToolTip(tooltip)
            button.setFixedSize(34, 34)
            button.setCursor(Qt.PointingHandCursor)
            button.clicked.connect(
                lambda _=False, u=url: QDesktopServices.openUrl(QUrl(u))
            )
            social_layout.addWidget(button)
            self.social_buttons[key] = button

        social_widget = QWidget()
        social_widget.setLayout(social_layout)
        credits_layout.addWidget(social_widget, 1, Qt.AlignCenter)

        # Right side - Support button (reuses the bundled SVG artwork)
        self.support_button = QPushButton()
        self.support_button.setToolTip(
            "Support SeregonWar — seregonwar.com/donations"
        )
        self.support_button.setCursor(Qt.PointingHandCursor)
        self.support_button.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl("https://www.seregonwar.com/donations"))
        )
        credits_layout.addWidget(self.support_button, 0, Qt.AlignRight)

        self._recolor_social_buttons()
        
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
        self.open_action = QAction('Open source…', self)
        self.open_action.setShortcut('Ctrl+O')
        self.open_action.triggered.connect(self.browse_pkg)
        self.file_menu.addAction(self.open_action)
        
        self.file_menu.addSeparator()
        
        self.exit_action = QAction('Exit', self)
        self.exit_action.setShortcut('Ctrl+Q')
        self.exit_action.triggered.connect(self.close)
        self.file_menu.addAction(self.exit_action)
        
        # Tools menu actions
        modify_action = QAction('Modify PKG', self)
        modify_action.triggered.connect(lambda: self.show_section(self.modify_tab))
        self.tools_menu.addAction(modify_action)
        
        self.tools_menu.addSeparator()
        
        trophy_action = QAction('Trophy Tools', self)
        trophy_action.triggered.connect(lambda: self.show_section(self.tools_workspace, self.trophy_tab))
        self.tools_menu.addAction(trophy_action)
        
        esmf_action = QAction('ESMF Decrypter', self)
        esmf_action.triggered.connect(lambda: self.show_section(self.tools_workspace, self.esmf_decrypter_tab))
        self.tools_menu.addAction(esmf_action)
        
        trp_action = QAction('Create TRP', self)
        trp_action.triggered.connect(lambda: self.show_section(self.tools_workspace, self.trp_create_tab))
        self.tools_menu.addAction(trp_action)
        
        self.tools_menu.addSeparator()
        
        bruteforce_action = QAction('Encryption Status', self)
        bruteforce_action.triggered.connect(lambda: self.show_section(self.tools_workspace, self.bruteforce_tab))
        self.tools_menu.addAction(bruteforce_action)
        
        # View menu
        view_menu = self.view_menu
        
        file_browser_action = QAction('File Browser', self)
        file_browser_action.triggered.connect(lambda: self.show_section(self.contents_workspace, self.file_browser))
        view_menu.addAction(file_browser_action)
        
        wallpaper_action = QAction('Wallpaper Viewer', self)
        wallpaper_action.triggered.connect(lambda: self.show_section(self.contents_workspace, self.wallpaper_viewer))
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
        
        support_action = QAction('Support SeregonWar', self)
        support_action.triggered.connect(
            lambda: QDesktopServices.openUrl(QUrl("https://www.seregonwar.com/donations"))
        )
        links_menu.addAction(support_action)
        
        # Help menu
        help_menu = self.help_menu
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        # Theme submenu and actions
        theme_menu = view_menu.addMenu('Theme')
        theme_group = QActionGroup(self)
        self.theme_actions = {}
        themes = StyleManager.get_available_themes()
        for theme_name in themes:
            colors = StyleManager.get_theme_colors(theme_name)
            action = QAction(theme_name, self)
            action.setCheckable(True)
            action.triggered.connect(lambda checked, t=theme_name, c=colors: self.change_theme(t, c))
            theme_group.addAction(action)
            theme_menu.addAction(action)
            self.theme_actions[theme_name] = action
        # Mark saved theme as checked
        saved_theme = self.settings_dict.get("appearance", {}).get("theme", "Dark")
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

    @staticmethod
    def _app_resource_path(*rel):
        """Resolve a bundled data file (source tree or PyInstaller bundle)."""
        if getattr(sys, 'frozen', False):
            base = getattr(sys, '_MEIPASS', None)
            if base:
                candidate = os.path.join(base, *rel)
                if os.path.exists(candidate):
                    return candidate
            candidate = os.path.join(os.path.dirname(sys.executable), '_internal', *rel)
            if os.path.exists(candidate):
                return candidate
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(here, *rel)

    def _current_theme_colors(self):
        """Resolve colors exactly as the global stylesheet does.

        Persisted overrides are relevant for System and custom themes too;
        using only the named theme made the sidebar disagree with the rest of
        the window after startup.
        """
        appearance = self.settings_dict.get("appearance", {})
        theme_name = appearance.get("theme", "Dark")
        stored = appearance.get("colors", {})
        resolved = StyleManager.get_theme_colors(
            theme_name, stored if theme_name == "Custom" else None
        ).copy()
        for key in resolved:
            if key in stored:
                resolved[key] = stored[key]
        return resolved

    def showEvent(self, event):
        """Re-assert the window placement the first time it is shown.

        Per the Qt docs, geometry set before show() can be overridden by the
        platform window system (macOS in particular restores or repositions
        the window when it appears). Re-applying the placement here, where
        frameGeometry() is accurate, keeps the window inside the visible
        screen area (below the menu bar, above the Dock).
        """
        super().showEvent(event)
        if not getattr(self, "_window_placed", False):
            self._place_window_on_screen()
            self._window_placed = True

    def _place_window_on_screen(self):
        """Place the window inside the visible screen area.

        Opens compact (1100x700 by default) and uses the screen's
        availableGeometry() (Qt docs: "the geometry excluding window manager
        reserved areas such as task bars and system menus" — on macOS the menu
        bar and Dock). Once the window is visible the FRAME (which on macOS
        includes the title bar above the client area) is clamped inside the
        visible area, so neither the top nor the bottom ends up underneath the
        system bars. A modest minimum size is set so the layout cannot force
        the window taller than the screen (Qt never shrinks a top-level window
        below the content's minimum size hint).
        """
        default_w, default_h = 1100, 700
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is None:
            self.setGeometry(100, 100, default_w, default_h)
            return
        avail = screen.availableGeometry()
        # Never exceed the default, but never overflow the visible area either.
        width = min(default_w, max(640, avail.width() - 40))
        height = min(default_h, max(480, avail.height() - 40))
        # A sane minimum that still fits the visible screen, so layouts cannot
        # push the window taller than the available height.
        self.setMinimumSize(min(900, width), min(560, height))
        self.resize(width, height)
        # On compact displays the source card would squeeze the actual task
        # workspace below a useful width. It remains one click away in the
        # toolbar and is not persisted as a preference change.
        if hasattr(self, "left_panel") and width < 980:
            self.left_panel.hide()
        if (
            hasattr(self, "sidebar_frame") and width < 980
            and getattr(self, "sidebar_expanded", False)
        ):
            self.toggle_sidebar()

        if self.isVisible():
            # Clamp the frame (title bar included) inside the visible area.
            frame = self.frameGeometry()
            fw, fh = frame.width(), frame.height()
            if fh > avail.height():
                self.resize(width, max(480, avail.height() - 40))
                frame = self.frameGeometry()
                fw, fh = frame.width(), frame.height()
            x = avail.x() + (avail.width() - fw) // 2
            y = avail.y() + (avail.height() - fh) // 2
            x = max(avail.x(), min(x, avail.right() - fw + 1))
            y = max(avail.y(), min(y, avail.bottom() - fh + 1))
            self.move(x, y)
        else:
            # Pre-show: center the client area in the available space.
            x = avail.x() + (avail.width() - width) // 2
            y = avail.y() + (avail.height() - height) // 2
            self.move(x, y)

    def change_theme(self, theme_name, colors):
        """Change and persist theme selection"""
        try:
            new_settings = self.settings_dict or {}
            if "appearance" not in new_settings:
                new_settings["appearance"] = {}
            if "colors" not in new_settings["appearance"]:
                new_settings["appearance"]["colors"] = {}
            new_settings["appearance"]["theme"] = theme_name
            new_settings["appearance"]["night_mode"] = StyleManager.is_dark_theme(theme_name, colors)
            new_settings["appearance"]["colors"].update({
                "background": colors.get('background', '#ffffff'),
                "text": colors.get('text', '#000000'),
                "accent": colors.get('accent', '#3498db'),
                "secondary_bg": colors.get('secondary_bg', colors.get('background', '#f1f5f9')),
                "secondary_text": colors.get('secondary_text', colors.get('text', '#475569')),
                "border": colors.get('border', '#cbd5e1'),
                "selection": colors.get('selection', colors.get('accent', '#3b82f6')),
                "hover": colors.get('hover', '#e2e8f0'),
                "error": colors.get('error', '#dc2626'),
                "success": colors.get('success', '#16a34a'),
                "warning": colors.get('warning', '#d97706')
            })
            # Save and apply
            StyleManager.save_settings(new_settings)
            self.settings_dict = new_settings
            StyleManager.apply_theme(self, self.settings_dict)
            # Recolor sidebar icons and restyle it for the new theme
            self._recolor_sidebar_icons(colors)
            self._apply_sidebar_style(colors)
            self._recolor_toolbar_icons(colors)
            self._recolor_social_buttons(colors)
            self._style_update_banner()
            # Keep following the system scheme when System is selected
            self._follow_system_theme()
            # Reflect selection in menu
            if hasattr(self, 'theme_actions') and theme_name in self.theme_actions:
                self.theme_actions[theme_name].setChecked(True)
        except Exception as e:
            logging.error(f"Failed to change theme: {e}")

    def _reapply_saved_theme(self):
        """Re-apply the persisted theme (startup and system scheme changes)."""
        theme_name = self.settings_dict.get("appearance", {}).get("theme", "Dark")
        colors = self._current_theme_colors()
        StyleManager.apply_theme(self, self.settings_dict)
        self._recolor_sidebar_icons(colors)
        self._apply_sidebar_style(colors)
        self._recolor_toolbar_icons(colors)
        self._recolor_social_buttons(colors)
        self._style_update_banner()
        self._follow_system_theme()

    def _follow_system_theme(self):
        """Track OS light/dark changes while the 'System' theme is active."""
        theme = self.settings_dict.get("appearance", {}).get("theme", "Dark")
        hints = QApplication.styleHints()
        if theme != StyleManager.SYSTEM_THEME_NAME:
            if getattr(self, '_system_theme_conn', None) is not None:
                try:
                    hints.colorSchemeChanged.disconnect(self._system_theme_conn)
                except Exception:
                    pass
                self._system_theme_conn = None
            return
        if getattr(self, '_system_theme_conn', None) is None:
            try:
                self._system_theme_conn = hints.colorSchemeChanged.connect(
                    lambda _scheme: self._reapply_saved_theme()
                )
            except Exception:
                self._system_theme_conn = None

    def _recolor_sidebar_icons(self, colors):
        """Recolor sidebar navigation icons to match current theme."""
        if not hasattr(self, '_nav_buttons'):
            return
        icon_color = colors.get('secondary_text', colors.get('text', '#475569'))
        sidebar_icons = get_sidebar_icons(icon_color, 18)
        toggle_menu_icon = get_icon('menu', icon_color, 20)
        for btn, icon_key, _ in self._nav_buttons:
            new_icon = sidebar_icons.get(icon_key, get_icon('file', icon_color, 18))
            btn.setIcon(new_icon)
        # Recolor the hamburger toggle button
        if hasattr(self, 'sidebar_toggle_btn') and self.sidebar_toggle_btn:
            self.sidebar_toggle_btn.setIcon(toggle_menu_icon)

    def create_sidebar(self):
        """Create compact navigation for the four primary workspaces."""
        self.sidebar_frame = QFrame()
        self.sidebar_frame.setObjectName("sidebar")
        theme_name = self.settings_dict.get("appearance", {}).get("theme", "Dark")
        tc = self._current_theme_colors()
        self._apply_sidebar_style(tc)
        layout = QVBoxLayout(self.sidebar_frame)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)

        # Hamburger toggle
        self.sidebar_expanded = True
        self.sidebar_width_expanded = 210
        self.sidebar_width_collapsed = 56
        self.sidebar_frame.setFixedWidth(self.sidebar_width_expanded)

        icon_color = tc.get('secondary_text', tc.get('text', '#94a3b8'))

        toggle_btn = QPushButton()
        toggle_btn.setIcon(get_icon('menu', icon_color, 20))
        self.sidebar_toggle_btn = toggle_btn  # Store for recoloring
        toggle_btn.setToolTip("Toggle menu")
        toggle_btn.setFixedHeight(36)
        toggle_btn.setStyleSheet(
            f"QPushButton {{ border: none; border-radius: 8px; background: transparent; }}"
            f"QPushButton:hover {{ background-color: {tc['hover']}; }}"
        )
        toggle_btn.clicked.connect(self.toggle_sidebar)
        layout.addWidget(toggle_btn)

        # Navigation buttons with SVG icons (colored to match saved theme)
        self._nav_buttons = []  # (btn, icon_key, label) — used for recoloring + collapse
        self._nav_group_labels = []
        sidebar_icons = get_sidebar_icons(icon_color, 18)

        def add_section_label(text):
            label = QLabel(text)
            label.setObjectName("sidebarGroup")
            label.setContentsMargins(8, 6, 8, 2)
            layout.addWidget(label)
            self._nav_group_labels.append(label)
            return label

        def add_nav(icon_key, text, widget):
            btn = QPushButton(text.replace("&", "&&"))
            btn.setObjectName("navBtn")
            btn.setIcon(sidebar_icons.get(icon_key, get_icon('file', icon_color, 18)))
            btn.setToolTip(text)
            btn.setFixedHeight(34)
            btn.setMinimumWidth(194)
            btn.setCheckable(True)
            btn.setAutoExclusive(True)
            btn._nav_match = (widget, None)  # used by _update_nav_highlight

            def select():
                self.show_section(widget)

            btn.clicked.connect(select)
            layout.addWidget(btn)
            self._nav_buttons.append((btn, icon_key, text))
            return btn

        # The details live in visible inner tabs, so users always know which
        # stage they are in without scanning a dozen peer-level destinations.
        sections = [
            ("WORKSPACE", [
                ('info', 'Overview', self.info_tab),
                ('file_browser', 'Contents', self.contents_workspace),
                ('modify', 'Inspect & edit', self.modify_tab),
                ('trophy', 'Tools', self.tools_workspace),
            ]),
        ]

        for group, items in sections:
            add_section_label(group)
            for item in items:
                add_nav(*item)

        layout.addStretch(1)

    def show_section(self, workspace, inner_widget=None):
        """Navigate to a primary workspace and optionally one of its inner tabs."""
        self.tab_widget.setCurrentWidget(workspace)
        if inner_widget is not None and isinstance(workspace, QTabWidget):
            index = workspace.indexOf(inner_widget)
            if index >= 0:
                workspace.setCurrentIndex(index)
        self._update_nav_highlight()

    def _update_nav_highlight(self, index=None):
        """Highlight the sidebar button matching the active tab.

        Connected to tab_widget.currentChanged so it stays in sync no matter
        how the tab is switched (sidebar click, menu, shortcuts, drag & drop).
        """
        if index is None:
            index = self.tab_widget.currentIndex()
        if index < 0:
            return
        widget = self.tab_widget.widget(index)
        for btn, _icon_key, _text in self._nav_buttons:
            target, sub_index = getattr(btn, '_nav_match', (None, None))
            if target is not widget:
                checked = False
            elif sub_index is None:
                checked = True
            else:
                checked = hasattr(widget, 'sub_tabs') and widget.sub_tabs.currentIndex() == sub_index
            btn.setChecked(checked)

    def _apply_sidebar_style(self, tc):
        """(Re)apply sidebar stylesheet from a theme color dict."""
        self.sidebar_frame.setStyleSheet(f"""
            QFrame#sidebar {{
                background-color: {tc['secondary_bg']};
                border: 1px solid {tc['border']};
                border-radius: 10px;
            }}
            QLabel#sidebarGroup {{
                color: {tc['secondary_text']};
                font-size: 10px;
                font-weight: 700;
                letter-spacing: 1px;
                padding: 4px 8px;
            }}
            QPushButton#navBtn {{
                text-align: left;
                padding: 7px 10px;
                border: none;
                border-radius: 8px;
                font-weight: 500;
                color: {tc['text']};
                background: transparent;
                font-size: 13px;
            }}
            QPushButton#navBtn:hover {{
                background-color: {tc['hover']};
            }}
            QPushButton#navBtn:pressed {{
                background-color: {tc['selection']};
                color: #ffffff;
            }}
            QPushButton#navBtn:checked {{
                background-color: {tc['selection']};
                color: #ffffff;
                font-weight: 600;
            }}
            QPushButton#navBtn:checked:hover {{
                background-color: {tc['accent_hover']};
                color: #ffffff;
            }}
        """)
        if hasattr(self, 'sidebar_toggle_btn') and self.sidebar_toggle_btn:
            self.sidebar_toggle_btn.setStyleSheet(
                f"QPushButton {{ border: none; border-radius: 8px; background: transparent; }}"
                f"QPushButton:hover {{ background-color: {tc['hover']}; }}"
            )

    def toggle_sidebar(self):
        """Toggle sidebar width between expanded and collapsed states"""
        self.sidebar_expanded = not getattr(self, 'sidebar_expanded', True)
        new_w = self.sidebar_width_expanded if self.sidebar_expanded else self.sidebar_width_collapsed
        self.sidebar_frame.setFixedWidth(new_w)
        for btn, _icon_key, text in self._nav_buttons:
            btn.setText(text.replace("&", "&&") if self.sidebar_expanded else "")
            btn.setMinimumWidth(194 if self.sidebar_expanded else 0)
            btn.setToolTip(text)
        for label in self._nav_group_labels:
            label.setVisible(self.sidebar_expanded)

    def setup_settings_button(self):
        """Top toolbar: panel toggle, settings (gear), then the theme dropdown."""
        icon_color = self._toolbar_icon_color()
        style = """
            QToolBar { spacing: 10px; border: none; background: transparent; }
            QToolButton { border: none; border-radius: 6px; padding: 6px 8px; font-weight: 600; }
            QToolButton:hover { background-color: rgba(52, 152, 219, 20%); }
        """

        # Panel toggle — show/hide the left PKG panel, left-most
        panel_toolbar = QToolBar()
        panel_toolbar.setIconSize(QSize(22, 22))
        self.panel_action = QAction(get_icon('columns', icon_color, 22), "", self)
        self.panel_action.setToolTip("Hide/show the source panel")
        self.panel_action.triggered.connect(self.toggle_left_panel)
        panel_toolbar.setStyleSheet(style)
        panel_toolbar.addAction(self.panel_action)
        self.addToolBar(Qt.TopToolBarArea, panel_toolbar)
        panel_toolbar.setMovable(False)

        # Settings button — gear icon
        settings_toolbar = QToolBar()
        settings_toolbar.setIconSize(QSize(22, 22))
        self.settings_action = QAction(get_icon('settings', icon_color, 22), "", self)
        self.settings_action.setToolTip("Settings")
        self.settings_action.triggered.connect(self.show_settings_dialog)
        settings_toolbar.setStyleSheet(style)
        settings_toolbar.addAction(self.settings_action)
        self.addToolBar(Qt.TopToolBarArea, settings_toolbar)
        settings_toolbar.setMovable(False)

        # Theme dropdown — sun icon + label, after the settings gear
        theme_toolbar = QToolBar()
        theme_toolbar.setIconSize(QSize(22, 22))
        self.theme_action = QAction(get_icon('theme', icon_color, 22), "Tema", self)
        self.theme_action.setToolTip("Cambia tema")
        self.theme_action.triggered.connect(self.show_theme_menu)
        theme_toolbar.setStyleSheet(style)
        theme_toolbar.addAction(self.theme_action)
        self.addToolBar(Qt.TopToolBarArea, theme_toolbar)
        theme_toolbar.setMovable(False)

    def _toolbar_icon_color(self):
        """Colore delle icone della toolbar in base al tema attivo."""
        theme_name = self.settings_dict.get("appearance", {}).get("theme", "Dark")
        tc = self._current_theme_colors()
        return tc.get('secondary_text', tc.get('text', '#475569'))

    def _recolor_toolbar_icons(self, colors):
        """Ricolora le icone della toolbar (pannello, rotellina e tema)."""
        if not hasattr(self, 'settings_action'):
            return
        icon_color = colors.get('secondary_text', colors.get('text', '#475569'))
        self.panel_action.setIcon(get_icon('columns', icon_color, 22))
        self.settings_action.setIcon(get_icon('settings', icon_color, 22))
        self.theme_action.setIcon(get_icon('theme', icon_color, 22))

    def _recolor_social_buttons(self, colors=None):
        """Tint the brand buttons white/black per the active theme and load the
        Support button artwork from the bundled SVG."""
        if not hasattr(self, 'social_buttons'):
            return
        theme_name = self.settings_dict.get("appearance", {}).get("theme", "Dark")
        if colors is None:
            colors = self._current_theme_colors()
        dark = StyleManager.is_dark_theme(theme_name, colors)
        icon_color = "#ffffff" if dark else "#0f172a"
        hover = colors.get('hover', "#334155" if dark else "#e2e8f0")
        social_style = (
            "QPushButton { border: none; border-radius: 8px; background: transparent; }"
            f"QPushButton:hover {{ background-color: {hover}; }}"
        )
        for key, button in self.social_buttons.items():
            button.setIcon(get_icon(f"brand_{key}", icon_color, 20))
            button.setIconSize(QSize(20, 20))
            button.setStyleSheet(social_style)

        support_svg = self._app_resource_path("assets", "seregonwar_support_button.svg")
        if os.path.exists(support_svg):
            self.support_button.setIcon(svg_file_to_icon(support_svg, 190, 32))
            self.support_button.setIconSize(QSize(190, 32))
            self.support_button.setStyleSheet(
                "QPushButton { border: none; background: transparent; padding: 2px; }"
                "QPushButton:hover { background: transparent; }"
            )

    def toggle_left_panel(self):
        """Hide/show the left PKG panel (persisted in settings)."""
        visible = not self.left_panel.isVisible()
        self.left_panel.setVisible(visible)
        layout_state = self.settings_dict.setdefault("layout", {})
        layout_state["left_panel_visible"] = visible
        try:
            StyleManager.save_settings(self.settings_dict)
        except Exception as e:
            logging.error(f"Failed to persist panel visibility: {e}")

    def show_theme_menu(self):
        """Show a theme selection menu and apply chosen theme"""
        from PySide6.QtWidgets import QMenu
        menu = QMenu(self)
        themes = StyleManager.get_available_themes()
        for name in themes:
            colors = StyleManager.get_theme_colors(name)
            act = menu.addAction(StyleManager.display_name(name))
            act.triggered.connect(lambda checked, n=name, c=colors: self.change_theme(n, c))
        # Position menu under the mouse or near top-left
        menu.exec(self.mapToGlobal(self.rect().topLeft() + self.menuBar().pos()))

    def show_settings_dialog(self):
        """Show settings dialog"""
        dialog = SettingsDialog(self)
        dialog.exec()

    def _set_drag_style(self, active: bool):
        """Style the drag & drop zone with the active theme colors."""
        tc = self._current_theme_colors()
        if active:
            color = tc.get('accent', '#3b82f6')
            border = tc.get('accent', '#3b82f6')
            weight = 600
        else:
            color = tc.get('secondary_text', '#94a3b8')
            border = tc.get('border', '#334155')
            weight = 500
        self.drag_drop_label.setStyleSheet(f"""
            QLabel {{
                font-size: 16px;
                color: {color};
                padding: 32px;
                border: 2px dashed {border};
                border-radius: 12px;
                background-color: {tc.get('secondary_bg', '#1e293b')};
                font-weight: {weight};
            }}
        """)

    def dragEnterEvent(self, event):
        """Handle drag enter event"""
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                if os.path.isfile(url.toLocalFile()):
                    event.acceptProposedAction()
                    self._set_drag_style(True)
                    return
        event.ignore()

    def dragLeaveEvent(self, event):
        """Handle drag leave event"""
        self._set_drag_style(False)
        event.accept()

    def dropEvent(self, event):
        """Handle drop event"""
        files = [url.toLocalFile() for url in event.mimeData().urls()
                if os.path.isfile(url.toLocalFile())]
        
        if files:
            self.load_pkg(files[0])
            
            if len(files) > 1:
                QMessageBox.information(self, "Multiple sources",
                    "Multiple sources were dragged. Only the first one will be loaded.")
            
            self._set_drag_style(False)
        
        event.acceptProposedAction()

    def load_pkg(self, pkg_path):
        """Load a package, publishing project, or file into the workspace."""
        try:
            self._dirty = False
            # Chiudi il package precedente se esiste
            if self.package:
                try:
                    if hasattr(self.package, 'close'):
                        self.package.close()
                    self.package = None
                    self.extract_btn.setEnabled(False)
                    Logger.log_information("Previous package closed")
                except Exception as e:
                    Logger.log_error(f"Error closing previous package: {str(e)}")

            self.package = open_source(pkg_path)
            self.extract_btn.setEnabled(True)
            Logger.log_information(f"{type(self.package).__name__} detected")
            
            # Update UI
            self.pkg_entry.setText(pkg_path)
            is_project = isinstance(self.package, (GP4Project, GP5Project))
            is_file = isinstance(self.package, StandaloneFileSource)
            supports_pfs = isinstance(self.package, (PackagePS4, PackagePS5))
            self.extract_btn.setText(
                "Export project files" if is_project else
                "Export file" if is_file else
                "Extract package"
            )
            self.extract_btn.setToolTip(
                "Copy the files mapped by this publishing project to a clean folder"
                if is_project else
                "Copy this file to a destination folder" if is_file else
                "Extract the loaded package into a destination folder"
            )
            self.contents_workspace.setTabEnabled(
                self.contents_workspace.indexOf(self.pfs_info_tab), supports_pfs
            )
            self.tools_workspace.setTabEnabled(
                self.tools_workspace.indexOf(self.bruteforce_tab), not (is_project or is_file)
            )
            self.modify_tab.sub_tabs.setTabEnabled(2, not (is_project or is_file))
            self.contents_workspace.setTabToolTip(
                self.contents_workspace.indexOf(self.pfs_info_tab),
                "PFS inspection applies to PS4/PS5 package images" if not supports_pfs else "Inspect the package filesystem",
            )
            self.tools_workspace.setTabToolTip(
                self.tools_workspace.indexOf(self.bruteforce_tab),
                "Encryption checks apply to package images" if (is_project or is_file) else "Inspect package encryption",
            )
            self.drag_drop_label.setText(
                "Publishing project loaded" if is_project else
                "Standalone file loaded" if is_file else
                "Package loaded"
            )
            self.load_pkg_icon()
            
            # Il tab Modify segue il PKG caricato
            if hasattr(self, 'modify_tab'):
                self.modify_tab.refresh_package()
            
            # Update file browser and wallpaper viewer
            if hasattr(self, 'file_browser'):
                self.file_browser.load_files(self.package)
            if hasattr(self, 'wallpaper_viewer'):
                self.wallpaper_viewer.load_wallpapers(self.package)
            
            # Update info tab
            info_dict = self.package.get_info()
            self.update_info(info_dict)
            if hasattr(self.info_tab, 'update_source'):
                self.info_tab.update_source(self.package)
            
            # Cerca e carica automaticamente i file dei trofei
            self.load_trophy_files()
            
            self.show_section(self.info_tab)
            Logger.log_information(f"Source loaded successfully: {pkg_path}")
            
        except Exception as e:
            error_msg = f"Error loading source: {str(e)}"
            Logger.log_error(error_msg)
            QMessageBox.critical(self, "Error", error_msg)
            
            # Reset UI state
            self.package = None
            self.extract_btn.setEnabled(False)
            self.image_label.clear()
            self.content_id_label.clear()
            if hasattr(self, 'file_browser'):
                self.file_browser.clear()
            if hasattr(self, 'wallpaper_viewer'):
                self.wallpaper_viewer.clear_viewer()
            if hasattr(self, 'modify_tab'):
                self.modify_tab.refresh_package()
            if hasattr(self, 'info_tab') and hasattr(self.info_tab, 'clear_source'):
                self.info_tab.clear_source()

    def load_trophy_files(self):
        """Cerca e carica automaticamente i file dei trofei"""
        try:
            if not self.package:
                return
                
            # Cerca file .trp o .ucp
            trophy_files = [
                f for f in self.package.files.values()
                if isinstance(f.get("name"), str) and 
                f.get("present", True) and
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
                self._trophy_reader = trophy_reader
                
                # Carica i trofei nella tree view (popola anche titolo/NPCommID dall'SFM)
                self._populate_trophy_tree(trophy_reader, self.trophy_npcommid_entry.text().strip())
                
                # Mostra le informazioni nel text edit
                self.trophy_info.setText(self._build_trophy_info(trophy_reader, temp_path))
                
                Logger.log_information(f"Trophy file loaded: {trophy_file['name']}")
                
        except Exception as e:
            Logger.log_error(f"Error loading trophy files: {str(e)}")

    def load_pkg_icon(self):
        """Load and display PKG icon"""
        try:
            self.image_label.clear()
            self.image_label.setText("No icon")
            self.content_id_label.clear()
            # Get content ID
            content_id = self.get_content_id()
            if content_id:
                self.content_id_label.setText(f"Content ID: {content_id}")
            
            # Find icon file
            icon_file = next((
                f for f in self.package.files.values()
                if isinstance(f, dict)
                and f.get("present", True)
                and (
                    f.get('name', '').replace('\\', '/').lower().endswith('/icon0.png')
                    or f.get('name', '').lower() == 'icon0.png'
                )
            ), None)
            if icon_file is None and isinstance(self.package, StandaloneFileSource):
                only_file = self.package.files.get(0)
                if only_file and only_file.get("name", "").lower().endswith((".png", ".jpg", ".jpeg")):
                    icon_file = only_file
            
            if icon_file:
                # Load and display icon (scaled to the 180px panel card)
                icon_data = self.package.read_file(icon_file['id'])
                pixmap = ImageUtils.create_thumbnail(icon_data)
                self.image_label.setPixmap(scale_pixmap_sharp(pixmap, 180, 180))
                self.image_label.setAlignment(Qt.AlignCenter)
                
        except Exception as e:
            logging.error(f"Error loading PKG icon: {str(e)}")
            self.image_label.setText("Error loading icon")

    def get_content_id(self):
        """Get content ID from package"""
        try:
            if not self.package:
                return None
            
            return getattr(self.package, 'content_id', None)
            
        except Exception as e:
            logging.error(f"Error getting content ID: {str(e)}")
            return None

    def setup_info_tab(self):
        """Setup the info tab"""
        layout = QVBoxLayout(self.info_tab)
        
        # Tree widget for info display
        self.info_tree = QTreeWidget()
        self.info_tree.setHeaderLabels(["Key", "Value", "Description"])
        self.info_tree.setColumnWidth(0, 200)
        self.info_tree.setColumnWidth(1, 200)
        layout.addWidget(self.info_tree)

    def setup_trophy_tab(self):
        """Setup the trophy tab"""
        layout = QVBoxLayout(self.trophy_tab)
        
        # File selection with better styling
        file_group = QGroupBox("Trophy File")
        file_layout = QHBoxLayout()
        
        self.trophy_entry = QLineEdit()
        self.trophy_entry.setPlaceholderText("Select trophy file (.trp)")
        
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_trophy)
        
        pkg_button = QPushButton("From contents")
        pkg_button.setToolTip("Pick a trophy file from the loaded source")
        pkg_button.clicked.connect(self.pick_pkg_trophy)
        
        file_layout.addWidget(self.trophy_entry)
        file_layout.addWidget(browse_button)
        file_layout.addWidget(pkg_button)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        # NP Communication ID — serve a decifrare il config ESFM cifrato
        np_group = QGroupBox("NP Communication ID")
        np_layout = QHBoxLayout(np_group)
        self.trophy_npcommid_entry = QLineEdit()
        self.trophy_npcommid_entry.setPlaceholderText("es. NPWR05506_00 (solo se il config è cifrato)")
        np_apply_btn = QPushButton("Apply")
        np_apply_btn.clicked.connect(self._apply_trophy_npcommid)
        np_layout.addWidget(QLabel("NP Comm ID:"))
        np_layout.addWidget(self.trophy_npcommid_entry, 1)
        np_layout.addWidget(np_apply_btn)
        self.trophy_npcommid_hint = QLabel(
            "Only needed when the trophy config (ESFM) is encrypted. The NPWR identifier "
            "can be recovered from console trophy data or trusted trophy databases."
        )
        self.trophy_npcommid_hint.setWordWrap(True)
        np_layout.addWidget(self.trophy_npcommid_hint, 2)
        layout.addWidget(np_group)
        
        # Split view for trophy list and preview
        split_layout = QHBoxLayout()
        
        # Left side: Trophy list and info
        left_panel = QVBoxLayout()
        
        # Trophy info display
        self.trophy_info = QTextEdit()
        self.trophy_info.setReadOnly(True)
        self.trophy_info.setMaximumHeight(100)
        # Colors come from the active theme
        left_panel.addWidget(self.trophy_info)
        
        # Trophy list
        self.trophy_tree = QTreeWidget()
        self.trophy_tree.setHeaderLabels(["Trophy", "Type", "Grade", "Hidden"])
        # Colors (hover, selection) come from the active theme
        self.trophy_tree.itemClicked.connect(self.display_selected_trophy)
        left_panel.addWidget(self.trophy_tree)
        
        # Right side: Trophy image and details
        right_panel = QVBoxLayout()
        
        # Trophy image viewer
        self.trophy_image_viewer = QLabel()
        self.trophy_image_viewer.setObjectName("previewCanvas")
        self.trophy_image_viewer.setAlignment(Qt.AlignCenter)
        self.trophy_image_viewer.setMinimumHeight(180)
        right_panel.addWidget(self.trophy_image_viewer)
        
        # Trophy details
        self.trophy_details = QTextEdit()
        self.trophy_details.setReadOnly(True)
        self.trophy_details.setMaximumHeight(150)
        right_panel.addWidget(self.trophy_details)
        
        # Navigation buttons
        nav_layout = QHBoxLayout()
        self.prev_trophy_button = QPushButton("Previous")
        self.next_trophy_button = QPushButton("Next")
        
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
        pkg_button = QPushButton("From contents")
        pkg_button.setToolTip("Pick an ESMF file from the loaded source")
        pkg_button.clicked.connect(self.pick_pkg_esmf)
        file_layout.addWidget(self.esmf_file_entry)
        file_layout.addWidget(browse_button)
        file_layout.addWidget(pkg_button)
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
        
        # NP Communication ID (serve a derivare la chiave di decifratura)
        np_layout = QHBoxLayout()
        self.esmf_npcommid_entry = QLineEdit()
        self.esmf_npcommid_entry.setPlaceholderText("NP Communication ID (es. NPWR05506_00)")
        np_layout.addWidget(QLabel("NP Comm ID:"))
        np_layout.addWidget(self.esmf_npcommid_entry, 1)
        layout.addLayout(np_layout)
        
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
        self.ps5_game_path_entry.setPlaceholderText("Select eboot.bin, param.json or param.sfo file")
        
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_ps5_game_file)
        
        pkg_button = QPushButton("From contents")
        pkg_button.setToolTip("Pick eboot.bin / param.json / param.sfo from the loaded source")
        pkg_button.clicked.connect(self.pick_pkg_ps5)
        
        file_layout.addWidget(self.ps5_game_path_entry)
        file_layout.addWidget(browse_button)
        file_layout.addWidget(pkg_button)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Info table with better styling
        self.ps5_game_info_table = QTableWidget()
        self.ps5_game_info_table.setColumnCount(2)
        self.ps5_game_info_table.setHorizontalHeaderLabels(["Parameter", "Value"])
        self.ps5_game_info_table.horizontalHeader().setStretchLastSection(True)
        self.ps5_game_info_table.setShowGrid(False)
        self.ps5_game_info_table.setAlternatingRowColors(False)
        layout.addWidget(self.ps5_game_info_table)
        # Track edits so closeEvent can warn about unsaved changes
        self.ps5_game_info_table.itemChanged.connect(self._on_ps5_table_edited)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.ps5_save_button = QPushButton("Save Changes")
        reload_button = QPushButton("Reload")
        
        self.ps5_save_button.clicked.connect(self.save_ps5_game_info)
        self.ps5_save_button.setEnabled(False)
        reload_button.clicked.connect(self.reload_ps5_game_info)
        
        button_layout.addStretch()
        button_layout.addWidget(self.ps5_save_button)
        button_layout.addWidget(reload_button)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)

    def browse_ps5_game_file(self):
        """Browse for a PS5/PS4 game file"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select eboot.bin, param.json or param.sfo",
            "",
            "Game Files (eboot.bin param.json param.sfo);;All files (*.*)"
        )
        if filename:
            self.ps5_game_path_entry.setText(filename)
            self.load_ps5_game_info(filename)

    def _on_ps5_table_edited(self, item):
        """Mark the app as having unsaved changes when an editable row is edited."""
        if item.data(Qt.UserRole) == "__header__":
            return
        if not getattr(self, '_loading_ps5', False):
            self._dirty = True

    def load_ps5_game_info(self, file_path):
        """Load game info (eboot.bin + param.json/param.sfo) into the table."""
        try:
            # Create PS5GameInfo instance
            self.ps5_game_info = PS5GameInfo()

            # Process the directory containing the file
            directory = os.path.dirname(file_path)
            result = self.ps5_game_info.process(directory)
            if "error" in result:
                raise ValueError(result["error"])

            # Populate without marking the app dirty (guard flag)
            self._loading_ps5 = True
            table = self.ps5_game_info_table
            table.setRowCount(0)

            for group in result["groups"]:
                # Group header row spanning both columns
                row = table.rowCount()
                table.insertRow(row)
                header_item = QTableWidgetItem(str(group["title"]))
                header_item.setData(Qt.UserRole, "__header__")
                header_item.setFlags(header_item.flags() & ~Qt.ItemIsEditable)
                font = header_item.font()
                font.setBold(True)
                header_item.setFont(font)
                table.setItem(row, 0, header_item)
                table.setSpan(row, 0, 1, 2)

                for label, value, editable, target in group["rows"]:
                    row = table.rowCount()
                    table.insertRow(row)
                    key_item = QTableWidgetItem(str(label))
                    value_item = QTableWidgetItem(str(value))
                    if not editable:
                        key_item.setFlags(key_item.flags() & ~Qt.ItemIsEditable)
                        value_item.setFlags(value_item.flags() & ~Qt.ItemIsEditable)
                    # The param.json target path for save-back (None = read-only)
                    key_item.setData(Qt.UserRole, target)
                    table.setItem(row, 0, key_item)
                    table.setItem(row, 1, value_item)

            table.resizeColumnsToContents()
            self._loading_ps5 = False
            self._dirty = False

            editable = result.get("editable")
            self.ps5_save_button.setEnabled(editable == "param.json")
            if editable == "param.json":
                self.ps5_save_button.setToolTip("Save changes back to sce_sys/param.json")
            else:
                self.ps5_save_button.setToolTip(
                    "Saving is only available for PS5 packages (param.json)"
                )

        except Exception as e:
            self._loading_ps5 = False
            QMessageBox.critical(self, "Error", f"Failed to load game info: {str(e)}")

    def save_ps5_game_info(self):
        """Save editable PS5 param.json values back to the extracted copy."""
        try:
            if not hasattr(self, 'ps5_game_info'):
                QMessageBox.warning(self, "Warning", "No game info loaded")
                return

            # Get file path
            file_path = self.ps5_game_path_entry.text()
            if not file_path:
                QMessageBox.warning(self, "Warning", "No file selected")
                return

            if getattr(self.ps5_game_info, "editable", None) != "param.json":
                QMessageBox.information(
                    self, "Save",
                    "Saving is only supported for PS5 packages (param.json); "
                    "PS4 param.sfo is shown read-only."
                )
                return

            # Collect only editable rows (header rows carry no target path).
            changes = {}
            table = self.ps5_game_info_table
            for row in range(table.rowCount()):
                key_item = table.item(row, 0)
                value_item = table.item(row, 1)
                if key_item is None or value_item is None:
                    continue
                target = key_item.data(Qt.UserRole)
                if not target or target == "__header__":
                    continue
                changes[target] = value_item.text()

            param_json_path = os.path.join(
                os.path.dirname(file_path), "sce_sys", "param.json"
            )
            if not os.path.exists(param_json_path):
                QMessageBox.warning(self, "Error", "param.json file not found")
                return
            applied = self.ps5_game_info.save_param_json(param_json_path, changes)
            self._dirty = False
            QMessageBox.information(
                self, "Success", f"Saved {applied} change(s) to param.json"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save changes: {str(e)}")

    def reload_ps5_game_info(self):
        """Reload game info"""
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

    def browse_pkg(self):
        """Browse for a supported package or project source."""
        filename, _ = QFileDialog.getOpenFileName(
            self, 
            "Open package, publishing project or file",
            "",
            "All files (*.*);;Packages and projects (*.pkg *.gp4 *.gp5);;PKG packages (*.pkg);;Publishing projects (*.gp4 *.gp5)"
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

    def extract_pkg_dialog(self):
        """Extract a package or export the active source.

        A modal dialog asks for the destination directory, then the extraction
        runs in a background thread to keep the UI responsive.
        """
        if not self.package:
            QMessageBox.warning(self, "Extract", "Load a package, project, or file first.")
            return
        output_dir = QFileDialog.getExistingDirectory(
            self, "Select destination folder"
        )
        if not output_dir:
            return

        # Extract into a sub-folder named after the package title ID
        # (e.g. PPSA99099), recovered from the PKG itself.
        extract_dir = os.path.join(
            output_dir, self.package.get_title_id_folder_name()
        )

        self.extract_btn.setEnabled(False)

        class ExtractWorker(QObject):
            finished = Signal(str)
            failed = Signal(str)

            def __init__(self, pkg, out_dir):
                super().__init__()
                self._pkg = pkg
                self._out = out_dir

            def run(self):
                try:
                    result = self._pkg.dump(self._out)
                    self.finished.emit(result)
                except Exception as e:
                    self.failed.emit(str(e))

        try:
            self.extract_thread = QThread(self)
            self.extract_worker = ExtractWorker(self.package, extract_dir)
            self.extract_worker.moveToThread(self.extract_thread)
            self.extract_thread.started.connect(self.extract_worker.run)
            # Bound methods (not closures) so Qt delivers them in the main
            # thread via queued connection (closures would run in the worker
            # thread and crash on macOS).
            self.extract_worker.finished.connect(self._on_extract_finished)
            self.extract_worker.failed.connect(self._on_extract_failed)
            self.extract_thread.finished.connect(self.extract_thread.deleteLater)
            self.extract_thread.start()
        except Exception as e:
            self.extract_btn.setEnabled(True)
            QMessageBox.critical(self, "Extract", f"Failed to start extraction: {str(e)}")

    def _on_extract_finished(self, msg: str):
        """Main-thread slot: extraction completed."""
        try:
            QMessageBox.information(self, "Extract", msg or "PKG extracted successfully")
        finally:
            self.extract_thread.quit()
            self.extract_btn.setEnabled(True)

    def _on_extract_failed(self, err: str):
        """Main-thread slot: extraction failed."""
        try:
            QMessageBox.critical(self, "Extract", f"Failed to extract PKG: {err}")
        finally:
            self.extract_thread.quit()
            self.extract_btn.setEnabled(True)

    def decrypt_esmf(self):
        """Decrypt ESMF file"""
        esmf_file = self.esmf_file_entry.text()
        output_dir = self.esmf_output_entry.text()
        np_comm_id = self.esmf_npcommid_entry.text().strip()

        if not esmf_file or not output_dir:
            QMessageBox.warning(self, "Warning", "Please select ESMF file and output directory")
            return
        if not np_comm_id:
            QMessageBox.warning(
                self, "Warning",
                "Enter the NP Communication ID (es. NPWR05506_00) — it is used "
                "to derive the decryption key."
            )
            return

        try:
            decrypter = ESMFDecrypter()
            result = decrypter.decrypt_esfm_file(esmf_file, np_comm_id, output_dir)
            if result:
                self.esmf_log.append(f"Decrypted: {result}")
                QMessageBox.information(self, "Success", "ESMF decrypted successfully")
            else:
                self.esmf_log.append("Decryption failed (wrong NP Comm ID?).")
                QMessageBox.critical(self, "Error", "Failed to decrypt ESMF (wrong NP Comm ID?).")
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
                progress = Signal(str)
                tested = Signal(str)
                finished = Signal(str)

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
            """<h3>PKG Tool Box v1.5.0</h3>
            <p>Created by SeregonWar</p>
            <p>A workspace for PlayStation packages, GP4/GP5 projects, and standalone files.</p>
            <p><a href="https://github.com/seregonwar">GitHub</a> | 
            <a href="https://www.seregonwar.com/donations">Support SeregonWar</a></p>"""
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
        if hasattr(self.bruteforce_tab, 'bruteforce_out_entry'):
            self.bruteforce_tab.bruteforce_out_entry.setText(output_dir)

    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        shortcuts = {
            'Ctrl+O': self.browse_pkg,
            'Ctrl+I': lambda: self.show_section(self.info_tab),
            'Ctrl+F': self.file_browser.file_search.setFocus,
            'Ctrl+B': self.toggle_sidebar,  # Toggle sidebar
            'Ctrl+W': lambda: self.show_section(self.contents_workspace, self.wallpaper_viewer),
            'Ctrl+T': self.show_theme_menu,  # Open theme menu
            'F5': self.refresh_all,
            'F11': self.toggle_fullscreen
        }

        for key, func in shortcuts.items():
            sc = QShortcut(QKeySequence(key), self)
            sc.activated.connect(func)

        # Alt+1..4 follows the visible primary navigation.
        tab_widgets = [
            self.info_tab,
            self.contents_workspace,
            self.modify_tab,
            self.tools_workspace,
        ]
        for i, widget in enumerate(tab_widgets, start=1):
            seq = QKeySequence(f"Alt+{i}")
            qs = QShortcut(seq, self)
            qs.activated.connect(lambda w=widget: self.show_section(w))

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
        info_table = getattr(self.info_tab, "info_table", None)
        if info_table is not None:
            for row in range(info_table.rowCount()):
                key_item = info_table.item(row, 0)
                value_item = info_table.item(row, 1)
                if not key_item or not value_item:
                    continue
                key, value = key_item.text(), value_item.text()
                if text.lower() in value.lower() or text.lower() in key.lower():
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
        return msg.exec()

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

    @staticmethod
    def _apply_trophy_conf(root, reader, meta):
        """Applica un trophyconf XML (da SFM o ESFM decifrato) a reader/meta:
        titolo, NP Communication ID e la mappa id -> (tipo, hidden)."""
        if reader._title is None or reader._title == "Unknown Title":
            t = root.find('title-name')
            if t is not None and t.text:
                reader._title = t.text.strip()
        if reader._npcommid is None:
            n = root.find('npcommid')
            if n is not None and n.text:
                reader._npcommid = n.text.strip()

        type_map = {'B': 'Bronze', 'S': 'Silver', 'G': 'Gold', 'P': 'Platinum'}
        for elem in root.iter('trophy'):
            tid = elem.get('id')
            if tid is None:
                continue
            ttype = type_map.get((elem.get('ttype') or '').upper())
            hidden = (elem.get('hidden') or 'no').lower() == 'yes'
            meta[str(int(tid))] = (ttype, hidden)

    def _parse_sfm_config(self, reader, extra_npcommid=None):
        """Recupera tipo/grade/hidden (più titolo e NP Communication ID) dal
        config dei trofei. Prima legge l'SFM non cifrato (gestendo il BOM
        UTF-8), poi — se non trova nulla — tenta di decifrare l'ESFM con gli
        NP comm ID disponibili (quello fornito dall'utente, poi il content_id
        del PKG caricato, poi l'npcommid già noto).
        Ritorna una mappa id -> (tipo, hidden)."""
        meta = {}

        # 1° passata: config non cifrato (.SFM), con BOM UTF-8 tollerato
        for trophy in reader.trophy_list:
            if not trophy.name.upper().endswith('.SFM'):
                continue
            data = reader.extract_file_to_memory(trophy.name)
            if not data:
                continue
            data = data.lstrip(b'\xef\xbb\xbf \t\r\n')
            if not data.startswith(b'<'):
                continue
            try:
                root = ET.fromstring(data.decode('utf-8', 'ignore'))
            except ET.ParseError:
                continue
            self._apply_trophy_conf(root, reader, meta)

        if meta:
            return meta

        # 2° passata: config cifrato (.ESFM) — tenta la decifratura best-effort
        esfm = next((t for t in reader.trophy_list
                     if t.name.upper().endswith('.ESFM') and 'TROPHY' in t.name.upper()), None)
        if esfm is None:
            esfm = next((t for t in reader.trophy_list if t.name.upper().endswith('.ESFM')), None)
        if esfm is None:
            return meta

        data = reader.extract_file_to_memory(esfm.name)
        if not data:
            return meta

        candidates = []
        if extra_npcommid and extra_npcommid.strip():
            candidates.append(extra_npcommid.strip())
        pkg = getattr(self, 'package', None)
        cid = getattr(pkg, 'content_id', None) or getattr(pkg, 'pkg_content_id', None)
        if cid:
            candidates.append(str(cid))
        if reader._npcommid:
            candidates.append(reader._npcommid)
        if not candidates:
            return meta

        decrypter = ESMFDecrypter()
        for cand in dict.fromkeys(candidates):  # dedup preservando l'ordine
            text = decrypter.decrypt_esfm_bytes(data, cand)
            if not text:
                continue
            try:
                root = ET.fromstring(text)
            except ET.ParseError:
                continue
            self._apply_trophy_conf(root, reader, meta)
            if meta:
                break
        return meta

    @staticmethod
    def _trophy_id_from_name(name):
        """Estrae l'id del trofeo dal nome file (TROP000.PNG -> '0')."""
        m = re.search(r'TROP(\d+)', name.upper())
        return str(int(m.group(1))) if m else None

    def _build_trophy_info(self, reader, filename):
        """Testo informativo del TRP caricato, con hint se il config è cifrato."""
        lines = [
            f"Title: {reader._title if reader._title else 'N/A'}",
            f"NP Communication ID: {reader._npcommid if reader._npcommid else 'N/A'}",
            f"Number of Trophies: {len(reader._trophyList) if reader._trophyList else 0}",
            f"File Type: {os.path.splitext(filename)[1].upper()[1:]}",
        ]
        has_esfm = any(t.name.upper().endswith('.ESFM') for t in reader.trophy_list)
        has_plain = any(t.name.upper().endswith('.SFM') for t in reader.trophy_list)
        if reader._npcommid is None and has_esfm and not has_plain:
            lines.append("")
            lines.append("Config cifrato (ESFM): inserisci l'NP Comm ID sopra per decifrarlo.")
        return "\n".join(lines)

    def _populate_trophy_tree(self, reader, extra_npcommid=None):
        """Popola la tree dei trofei con nome/tipo/grade/hidden e mostra
        subito l'immagine del primo trofeo PNG disponibile."""
        self.trophy_tree.clear()
        meta = self._parse_sfm_config(reader, extra_npcommid=extra_npcommid)

        for trophy in reader.trophy_list:
            tid = self._trophy_id_from_name(trophy.name)
            if tid and tid in meta:
                trophy.trophy_type, trophy.hidden = meta[tid]

            item = QTreeWidgetItem(self.trophy_tree)
            item.setText(0, trophy.name)
            item.setText(1, self.get_trophy_type(trophy))
            item.setText(2, self.get_trophy_grade(trophy))
            item.setText(3, "Yes" if getattr(trophy, 'hidden', False) else "No")
            item.setData(0, Qt.UserRole, trophy)

        # Seleziona e mostra subito il primo trofeo con immagine
        for i in range(self.trophy_tree.topLevelItemCount()):
            item = self.trophy_tree.topLevelItem(i)
            trophy = item.data(0, Qt.UserRole)
            if trophy and trophy.name.upper().endswith('.PNG'):
                self.trophy_tree.setCurrentItem(item)
                self.display_selected_trophy(item, 0)
                break

    def browse_trophy(self):
        """Browse for trophy file"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select Trophy file",
            "",
            "Trophy files (*.trp *.ucp);;TRP files (*.trp);;UCP files (*.ucp);;All files (*.*)"
        )
        if filename:
            self._load_trophy_file(filename)

    def _apply_trophy_npcommid(self):
        """Rilegge il config dei trofei con l'NP Comm ID inserito dall'utente
        (per decifrare un config ESFM e recuperare tipo/grade)."""
        reader = getattr(self, '_trophy_reader', None)
        if reader is None:
            QMessageBox.information(self, "Trophy", "Load a trophy file first.")
            return
        npcommid = self.trophy_npcommid_entry.text().strip()
        self._populate_trophy_tree(reader, extra_npcommid=npcommid)
        self.trophy_info.setText(self._build_trophy_info(reader, self.trophy_entry.text()))
        Logger.log_information(
            f"Trophy config re-parsed with NP Comm ID: {npcommid or '(none)'}"
        )

    def _load_trophy_file(self, filename):
        """Carica un file trofeo (.trp/.ucp) nella sezione Trophy."""
        try:
            self.trophy_entry.setText(filename)

            # Carica il file dei trofei (popola anche titolo/NPCommID dall'SFM)
            trophy_reader = TRPReader(filename)
            self._trophy_reader = trophy_reader

            # Carica i trofei nella tree view
            self._populate_trophy_tree(trophy_reader, self.trophy_npcommid_entry.text().strip())

            # Mostra le informazioni nel text edit
            self.trophy_info.setText(self._build_trophy_info(trophy_reader, filename))

            # Abilita/disabilita pulsanti in base al tipo di file
            is_trp = filename.lower().endswith('.trp')
            self.trophy_decrypt_button.setEnabled(is_trp)
            self.trophy_recompile_button.setEnabled(not is_trp)

            Logger.log_information(f"Trophy file loaded: {filename}")

        except Exception as e:
            error_msg = f"Error loading trophy file: {str(e)}"
            Logger.log_error(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    # ------------------------------------------------------------------
    # Selezione di file estratti dal PKG caricato
    # ------------------------------------------------------------------
    def _pick_pkg_file(self, file_filter=None, multi=False,
                       title="Select a file from the loaded source"):
        """Apre il picker dei file del PKG caricato. Ritorna i file_info
        selezionati (vuoto se annullato o senza PKG)."""
        if not self.package:
            QMessageBox.information(
                self, "Contents", "Load a package, project, or file first."
            )
            return []
        dlg = PkgFilePickerDialog(
            self.package, self, file_filter=file_filter, multi=multi, title=title
        )
        if dlg.exec() != QDialog.Accepted:
            return []
        return dlg.selected_infos()

    def _extract_pkg_file(self, file_info, subdir="picked"):
        """Estrae un singolo file dal PKG in temp e ritorna il percorso."""
        name = file_info.get("name", "file")
        safe_name = name.replace("/", "_").replace("\\", "_")
        out_dir = os.path.join(self.temp_directory, subdir)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, safe_name)
        with open(out_path, "wb") as f:
            f.write(self.package.read_file(file_info["id"]))
        return out_path

    def _extract_pkg_folder_for_ps5(self, file_info):
        """Estrae la cartella del file selezionato preservando la struttura.
        PS5 Game Info ha bisogno di eboot.bin + sce_sys/param.json nella
        stessa directory."""
        name = file_info.get("name", "")
        folder = os.path.dirname(name)
        out_root = os.path.join(self.temp_directory, "ps5_game")
        if os.path.exists(out_root):
            shutil.rmtree(out_root, ignore_errors=True)
        os.makedirs(out_root, exist_ok=True)

        # Search the PFS payloads too: on PS5 packages eboot.bin lives inside
        # the PFS image, not in the CNT entry table.
        files = (
            self.package.get_all_files().values()
            if hasattr(self.package, "get_all_files")
            else self.package.files.values()
        )
        if folder:
            prefix = folder + "/"
            needed = [f for f in files if f.get("name", "").startswith(prefix)]
        else:
            # File alla radice: estrai ciò che serve a GameInfo (eboot.bin +
            # param.json per PS5, param.sfo per PS4). Il nome può essere
            # "sce_sys/param.json" oppure "param.json" a seconda di come il
            # PKG archivia i nomi CNT.
            root_names = ("eboot.bin", "sce_sys/param.json", "sce_sys/param.sfo",
                          "param.json", "param.sfo")
            needed = [f for f in files if f.get("name") in root_names]
        if not needed:
            needed = [file_info]

        for f in needed:
            rel = f.get("name", "file")
            out_path = os.path.join(out_root, rel)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as fh:
                # An encrypted eboot.bin entry (PS4) is written raw so the
                # parser can report it as encrypted instead of failing.
                allow_encrypted = str(rel).endswith("eboot.bin")
                fh.write(self.package.read_file(f["id"], allow_encrypted=allow_encrypted))
        return os.path.join(out_root, folder) if folder else out_root

    def pick_pkg_trophy(self):
        """Seleziona un file trofeo dal PKG e lo carica."""
        infos = self._pick_pkg_file(
            file_filter=[".trp", ".ucp"], title="Select a trophy file from the PKG"
        )
        if not infos:
            return
        path = self._extract_pkg_file(infos[0], subdir="trophies")
        self._load_trophy_file(path)

    def pick_pkg_esmf(self):
        """Seleziona un file ESMF dal PKG."""
        infos = self._pick_pkg_file(
            file_filter=[".esmf"], title="Select an ESMF file from the PKG"
        )
        if not infos:
            return
        self.esmf_file_entry.setText(
            self._extract_pkg_file(infos[0], subdir="esmf")
        )

    def pick_pkg_ps5(self):
        """Seleziona eboot.bin/param.json/param.sfo dal PKG e carica le info."""
        infos = self._pick_pkg_file(
            file_filter=[".bin", ".json", ".sfo"],
            title="Select eboot.bin, param.json or param.sfo from the PKG",
        )
        if not infos:
            return
        folder = self._extract_pkg_folder_for_ps5(infos[0])
        picked_path = os.path.join(
            folder, os.path.basename(infos[0]["name"])
        )
        self.ps5_game_path_entry.setText(picked_path)
        self.load_ps5_game_info(picked_path)

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
            Hidden: {'Yes' if getattr(trophy, 'hidden', False) else 'No'}
            Encrypted: {'Yes' if getattr(trophy, 'is_encrypted', False) else 'No'}
            Size: {trophy.size} bytes
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
        """Get trophy type based on parsed SFM data or filename"""
        ttype = getattr(trophy, 'trophy_type', None)
        if ttype:
            return ttype
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
        """Get trophy grade based on parsed SFM data or filename"""
        ttype = getattr(trophy, 'trophy_type', None)
        if ttype:
            return {"Bronze": "Common", "Silver": "Uncommon", "Gold": "Rare", "Platinum": "Very Rare"}.get(ttype, "Unknown")
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
            
            if dialog.exec() == QDialog.Accepted:
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
        self.setWindowTitle(self.translator.translate("PKG Tool Box v1.5.0"))
        
        # Update menu items
        self.file_menu.setTitle(self.translator.translate("File"))
        self.tools_menu.setTitle(self.translator.translate("Tools"))
        self.view_menu.setTitle(self.translator.translate("View"))
        self.help_menu.setTitle(self.translator.translate("Help"))
        
        # Update actions
        self.open_action.setText(self.translator.translate("Open source…"))
        self.exit_action.setText(self.translator.translate("Exit"))
        
        # Update tab names
        self.tab_widget.setTabText(0, self.translator.translate("Overview"))
        self.tab_widget.setTabText(1, self.translator.translate("Contents"))
        self.tab_widget.setTabText(2, self.translator.translate("Inspect & edit"))
        self.tab_widget.setTabText(3, self.translator.translate("Tools"))

        
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

    def show_update_banner(self, version, download_url, assets=None):
        """Show the in-app banner when a newer release is detected."""
        self._update_info = {
            "version": version,
            "download_url": download_url,
            "assets": assets or [],
        }
        self.update_banner_label.setText(
            f"New version <b>{version}</b> available "
            f"(you're on {UpdateChecker.CURRENT_VERSION})"
        )
        self.update_download_btn.setEnabled(True)
        self.update_install_btn.setEnabled(
            pick_asset_for_current_platform(self._update_info["assets"]) is not None
        )
        self.update_banner.setVisible(True)

    def _open_update_page(self):
        """Open the release page for the detected update in the browser."""
        if self._update_info:
            QDesktopServices.openUrl(QUrl(self._update_info["download_url"]))

    def _install_update(self):
        """Download the platform installer and launch it (auto-install)."""
        if not self._update_info:
            return
        asset = pick_asset_for_current_platform(self._update_info["assets"])
        if asset is None:
            QMessageBox.information(
                self, "Update",
                "No installer is available for your platform yet.\n"
                "Use Download to open the release page.",
            )
            return
        url = asset.get("browser_download_url")
        name = asset.get("name", "PkgToolBox-update")
        dest = os.path.join(os.path.expanduser("~"), ".pkgtoolbox", "updates", name)
        self.update_install_btn.setEnabled(False)
        self.update_install_btn.setText("Downloading…")
        self.progress_bar.setRange(0, 0)  # busy indicator until we know the size
        self.progress_bar.show()
        self.update_checker.download_asset(url, dest)

    def _on_update_download_progress(self, received, total):
        if total > 0:
            self.progress_bar.setRange(0, total)
            self.progress_bar.setValue(received)
        else:
            self.progress_bar.setRange(0, 0)

    def _on_update_download_finished(self, path):
        self.progress_bar.hide()
        self.update_install_btn.setText("Install")
        self.update_install_btn.setEnabled(True)
        try:
            launch_downloaded_asset(path)
            self.update_banner.hide()
        except Exception as e:
            Logger.log_error(f"Failed to launch installer: {e}")
            QMessageBox.warning(
                self, "Update",
                f"The update was downloaded but could not be launched:\n{e}",
            )

    def _style_update_banner(self):
        """Restyle the update banner with the active theme colors."""
        if not hasattr(self, 'update_banner'):
            return
        tc = self._current_theme_colors()
        accent = tc.get("accent", "#3b82f6")
        bg = tc.get("secondary_bg", tc.get("background", "#1e293b"))
        text = tc.get("text", "#e2e8f0")
        border = tc.get("border", "#334155")
        hover = tc.get("hover", "#334155")
        self.update_banner.setStyleSheet(
            "QFrame#updateBanner {"
            f"background-color: {bg}; border: 1px solid {accent}; border-radius: 10px;"
            "}"
            f"QLabel {{ color: {text}; font-size: 13px; }}"
            f"QPushButton {{ color: {text}; background-color: transparent;"
            f"border: 1px solid {border}; border-radius: 6px; padding: 5px 12px; }}"
            f"QPushButton:hover {{ background-color: {hover}; }}"
            f"QPushButton#updateInstallBtn {{ background-color: {accent};"
            f"color: #ffffff; border: none; }}"
            f"QPushButton#updateInstallBtn:hover {{ background-color: {accent}; }}"
            f"QPushButton#updateDismissBtn {{ border: none; padding: 0; }}"
        )

    def handle_update_error(self, error_msg):
        """Handle errors during update check or download."""
        Logger.log_error(f"Update check failed: {error_msg}")
        # Reset any in-flight download UI state
        if hasattr(self, 'update_install_btn'):
            self.update_install_btn.setEnabled(True)
            self.update_install_btn.setText("Install")
        if hasattr(self, 'progress_bar'):
            self.progress_bar.hide()

    def closeEvent(self, event):
        """Ask for confirmation before exiting.

        Priority:
        1. A background operation is running (extraction, pfs-info, bruteforce,
           file loading) -> always confirm, regardless of the setting.
        2. There are unsaved edits (e.g. PS5 game info table) -> always confirm.
        3. Otherwise respect 'Confirm before exit' and the remembered
           'Don't ask again' choice.
        """
        busy = self._has_busy_operations()
        dirty = getattr(self, '_dirty', False)
        skip = self.settings_dict.get("behavior", {}).get("skip_exit_confirmation", False)

        if not busy and not dirty:
            confirm = self.settings_dict.get("behavior", {}).get("confirm_exit", True)
            if not confirm or skip:
                event.accept()
                return

        box = QMessageBox(self)
        dont_ask = None
        if busy:
            box.setWindowTitle(self.translator.translate("Operation in Progress"))
            box.setText(self.translator.translate(
                "An operation is currently running. Exiting now will interrupt it."))
        elif dirty:
            box.setWindowTitle(self.translator.translate("Unsaved Changes"))
            box.setText(self.translator.translate(
                "There are unsaved changes. Do you want to exit without saving?"))
        else:
            box.setWindowTitle(self.translator.translate("Confirm Exit"))
            box.setText(self.translator.translate("Are you sure you want to exit?"))
            dont_ask = QCheckBox(self.translator.translate("Don't ask again"))
            box.setCheckBox(dont_ask)

        exit_btn = box.addButton(self.translator.translate("Exit"), QMessageBox.DestructiveRole)
        cancel_btn = box.addButton(self.translator.translate("Cancel"), QMessageBox.RejectRole)
        box.setDefaultButton(cancel_btn)
        box.exec()

        if box.clickedButton() == exit_btn:
            if dont_ask is not None and dont_ask.isChecked():
                self._set_skip_exit_confirmation(True)
            event.accept()
        else:
            event.ignore()

    def _has_busy_operations(self):
        """True when any background worker thread is still running."""
        for attr in ('extract_thread', 'pfs_thread', 'brute_thread'):
            th = getattr(self, attr, None)
            if th is not None and th.isRunning():
                return True
        for tab_attr, thread_attr in (('bruteforce_tab', 'brute_thread'),
                                      ('pfs_info_tab', '_thr'),
                                      ('file_browser', 'worker')):
            tab = getattr(self, tab_attr, None)
            if tab is not None:
                th = getattr(tab, thread_attr, None)
                if th is not None and th.isRunning():
                    return True
        return False

    def _set_skip_exit_confirmation(self, value):
        """Persist the 'Don't ask again' choice for the plain exit prompt."""
        self.settings_dict.setdefault("behavior", {})["skip_exit_confirmation"] = value
        try:
            StyleManager.save_settings(self.settings_dict)
        except Exception as e:
            Logger.log_error(f"Failed to save exit preference: {e}")
