import json
from PySide6.QtGui import QColor
import os
import logging

class StyleManager:
    DEFAULT_SETTINGS = {
        "appearance": {
            "theme": "Dark",
            "night_mode": True,
            "font_family": "Arial",
            "font_size": 12,
            "colors": {
                "background": "#0f172a",
                "text": "#f1f5f9",
                "accent": "#3b82f6"
            }
        }
    }

    # Load themes from themes.json
    _themes_loaded = False
    THEMES = {}

    @classmethod
    def _load_themes(cls):
        """Load theme definitions from themes.json if not already loaded."""
        if cls._themes_loaded and cls.THEMES:
            return
        try:
            themes_path = os.path.join(os.path.dirname(__file__), "themes.json")
            if os.path.exists(themes_path):
                with open(themes_path, "r", encoding='utf-8') as f:
                    cls.THEMES = json.load(f)
                    cls._themes_loaded = True
                    return
        except Exception as e:
            logging.error(f"Error loading themes.json: {e}")
        cls.THEMES = cls._get_fallback_themes()
        cls._themes_loaded = True

    @classmethod
    def _get_fallback_themes(cls):
        """Return fallback themes if themes.json fails to load."""
        return {
            'Light': {
                'background': '#ffffff', 'secondary_bg': '#f1f5f9',
                'text': '#0f172a', 'secondary_text': '#475569',
                'accent': '#3b82f6', 'accent_hover': '#2563eb',
                'border': '#cbd5e1', 'selection': '#3b82f6',
                'hover': '#e2e8f0', 'error': '#dc2626',
                'success': '#16a34a', 'warning': '#d97706'
            },
            'Dark': {
                'background': '#0f172a', 'secondary_bg': '#1e293b',
                'text': '#f1f5f9', 'secondary_text': '#94a3b8',
                'accent': '#3b82f6', 'accent_hover': '#2563eb',
                'border': '#334155', 'selection': '#1d4ed8',
                'hover': '#1e293b', 'error': '#ef4444',
                'success': '#22c55e', 'warning': '#f59e0b'
            }
        }
    
    # Virtual theme that follows the native OS palette (light/dark aware)
    SYSTEM_THEME_NAME = 'System'

    # ── User-defined themes (persisted in ~/.pkgtoolbox/custom_themes.json) ──
    CUSTOM_THEMES_FILE = 'custom_themes.json'

    # All theme color keys, in display order (used by the custom theme editor)
    COLOR_KEYS = ['background', 'secondary_bg', 'text', 'secondary_text',
                  'accent', 'accent_hover', 'border', 'selection', 'hover',
                  'error', 'success', 'warning']

    @classmethod
    def _custom_themes_path(cls):
        return os.path.join(os.path.expanduser("~"), ".pkgtoolbox", cls.CUSTOM_THEMES_FILE)

    @classmethod
    def load_custom_themes(cls):
        """Load user-defined themes from disk (dict of name -> color dict)."""
        try:
            with open(cls._custom_themes_path(), 'r', encoding='utf-8') as f:
                themes = json.load(f)
                return themes if isinstance(themes, dict) else {}
        except Exception:
            return {}

    @classmethod
    def save_custom_themes(cls, themes):
        """Persist all user-defined themes to disk."""
        path = cls._custom_themes_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(themes, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Error saving custom themes: {e}")
            raise

    @classmethod
    def delete_custom_theme(cls, name):
        """Remove a user-defined theme by name. Returns True if removed."""
        themes = cls.load_custom_themes()
        if name in themes:
            del themes[name]
            cls.save_custom_themes(themes)
            return True
        return False

    @classmethod
    def get_available_themes(cls):
        """Return list of available theme names (System first, then user themes)."""
        cls._load_themes()
        themes = list(cls.THEMES.keys())
        if cls.SYSTEM_THEME_NAME not in themes:
            themes.insert(0, cls.SYSTEM_THEME_NAME)
        for name in cls.load_custom_themes():
            if name not in themes:
                themes.append(name)
        return themes

    @classmethod
    def get_theme_colors(cls, theme_name, custom_colors=None):
        """Get colors for specified theme."""
        cls._load_themes()
        if theme_name == cls.SYSTEM_THEME_NAME:
            return cls._get_system_theme_colors()
        # User-defined themes take precedence over built-in ones
        custom = cls.load_custom_themes()
        if theme_name in custom:
            merged = cls._COLOR_DEFAULTS.copy()
            merged.update(custom[theme_name])
            return merged
        if theme_name == 'Custom' and custom_colors:
            base = cls.THEMES.get('Light', {}).copy()
            base.update({
                'background': custom_colors.get('bg_color', base.get('background', '#ffffff')),
                'text': custom_colors.get('text_color', base.get('text', '#000000')),
                'accent': custom_colors.get('accent_color', base.get('accent', '#3b82f6'))
            })
            return base
        return cls.THEMES.get(theme_name, cls.THEMES.get('Light', {}))

    @classmethod
    def _get_system_theme_colors(cls):
        """Build a full theme color set from the native Qt application palette.

        This is evaluated at call time, so it always reflects the current OS
        light/dark scheme (the app re-applies the theme on colorSchemeChanged).
        """
        from PySide6.QtWidgets import QApplication
        from PySide6.QtGui import QPalette

        pal = QApplication.palette()
        bg = pal.color(QPalette.ColorRole.Window)
        base = pal.color(QPalette.ColorRole.Base)
        text = pal.color(QPalette.ColorRole.WindowText)
        accent = pal.color(QPalette.ColorRole.Highlight)
        accent_hover = QColor(accent).lighter(115) if accent.lightness() < 128 else QColor(accent).darker(110)
        secondary_text = pal.color(QPalette.ColorRole.PlaceholderText)
        border = pal.color(QPalette.ColorRole.Mid)
        hover = pal.color(QPalette.ColorRole.AlternateBase)

        dark = bg.lightness() < 128
        return {
            'background': bg.name(),
            'secondary_bg': base.name(),
            'text': text.name(),
            'secondary_text': secondary_text.name(),
            'accent': accent.name(),
            'accent_hover': accent_hover.name(),
            'border': border.name(),
            'selection': accent.name(),
            'hover': hover.name(),
            'error': '#ef4444' if dark else '#dc2626',
            'success': '#22c55e' if dark else '#16a34a',
            'warning': '#f59e0b' if dark else '#d97706',
        }

    @classmethod
    def display_name(cls, theme_name):
        """Human-readable label for a theme name (used in menus/combos)."""
        if theme_name == cls.SYSTEM_THEME_NAME:
            return "Follow system theme"
        return theme_name

    # Per-key default colors for sensible fallbacks
    _COLOR_DEFAULTS = {
        'background': '#ffffff', 'secondary_bg': '#f1f5f9',
        'text': '#0f172a', 'secondary_text': '#475569',
        'accent': '#3b82f6', 'accent_hover': '#2563eb',
        'border': '#cbd5e1', 'selection': '#3b82f6',
        'hover': '#e2e8f0', 'error': '#dc2626',
        'success': '#16a34a', 'warning': '#d97706'
    }

    @classmethod
    def is_dark_theme(cls, theme_name, colors=None):
        """Determine if a theme is dark based on background lightness."""
        cls._load_themes()
        if colors is None:
            colors = cls.get_theme_colors(theme_name)
        bg = colors.get('background', '#ffffff')
        color = QColor(bg)
        return color.lightness() < 128

    @staticmethod
    def load_settings(filename="settings.json"):
        """Load settings from file"""
        try:
            config_dir = os.path.join(os.path.expanduser("~"), ".pkgtoolbox")
            config_file = os.path.join(config_dir, filename)
            
            if os.path.exists(config_file):
                with open(config_file, "r", encoding='utf-8') as f:
                    settings = json.load(f)
                    # Assicurati che tutte le chiavi necessarie esistano
                    if "appearance" not in settings:
                        settings["appearance"] = StyleManager.DEFAULT_SETTINGS["appearance"]
                    if "colors" not in settings["appearance"]:
                        settings["appearance"]["colors"] = StyleManager.DEFAULT_SETTINGS["appearance"]["colors"]
                    return settings
            return StyleManager.DEFAULT_SETTINGS
        except Exception as e:
            logging.error(f"Error loading settings: {e}")
            return StyleManager.DEFAULT_SETTINGS

    @staticmethod
    def save_settings(settings, filename="settings.json"):
        """Save settings to file"""
        try:
            config_dir = os.path.join(os.path.expanduser("~"), ".pkgtoolbox")
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            
            config_file = os.path.join(config_dir, filename)
            
            # Assicurati che le impostazioni siano nel formato corretto
            if "appearance" not in settings:
                settings["appearance"] = {}
            if "colors" not in settings["appearance"]:
                settings["appearance"]["colors"] = {}
            
            # Salva le impostazioni
            with open(config_file, "w", encoding='utf-8') as f:
                json.dump(settings, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Error saving settings: {e}")
            raise

    @classmethod
    def apply_theme(cls, widget, settings):
        """Apply theme to widget with full theme color support."""
        cls._load_themes()
        appearance = settings.get("appearance", {})
        theme_name = appearance.get("theme", "Dark")
        colors = appearance.get("colors", {})
        
        # Get the full theme colors from themes.json
        theme_colors = cls.get_theme_colors(theme_name, colors if theme_name == 'Custom' else None)
        
        # Merge overrides with per-key sensible defaults
        tc = {}
        for key in cls._COLOR_DEFAULTS:
            tc[key] = colors.get(key, theme_colors.get(key, cls._COLOR_DEFAULTS.get(key, '#ffffff')))
        
        # Compute icon color
        icon_color = tc.get('secondary_text', tc.get('text', '#475569'))
        
        # Apply stylesheet
        widget.setStyleSheet(f"""
            /* Base */
            QMainWindow, QWidget {{ 
                background-color: {tc['background']}; 
                color: {tc['text']}; 
            }}
            
            /* Input Fields */
            QLineEdit, QTextEdit, QPlainTextEdit {{ 
                background-color: {tc['secondary_bg']}; 
                color: {tc['text']}; 
                border: 1px solid {tc['border']};
                border-radius: 6px;
                padding: 8px 12px;
                selection-background-color: {tc['selection']};
                selection-color: #fff;
            }}
            QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
                border: 2px solid {tc['accent']};
            }}
            
            /* Buttons */
            QPushButton {{ 
                background-color: {tc['accent']}; 
                color: #fff;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {tc['accent_hover']};
            }}
            QPushButton:pressed {{
                background-color: {tc['selection']};
            }}
            QPushButton:disabled {{
                background-color: {tc['secondary_bg']};
                color: {tc['secondary_text']};
            }}
            
            /* Tree/List Widgets */
            QTreeWidget, QListWidget, QTableWidget {{ 
                background-color: {tc['secondary_bg']};
                alternate-background-color: {tc['hover']};
                color: {tc['text']};
                border: 1px solid {tc['border']};
                border-radius: 6px;
            }}
            QTreeWidget::item:hover, QListWidget::item:hover, QTableWidget::item:hover {{
                background-color: {tc['hover']};
            }}
            QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {{
                background-color: {tc['selection']};
                color: #fff;
            }}
            
            /* Headers */
            QHeaderView::section {{
                background-color: {tc['secondary_bg']};
                color: {tc['text']};
                padding: 8px 12px;
                border: none;
                border-bottom: 2px solid {tc['border']};
                font-weight: 600;
            }}
            
            /* Tabs */
            QTabWidget::pane {{ 
                border: 1px solid {tc['border']}; 
                border-radius: 8px;
                background-color: {tc['background']};
            }}
            QTabBar::tab {{ 
                background: {tc['secondary_bg']}; 
                color: {tc['text']};
                padding: 10px 20px;
                margin: 2px;
                border-radius: 6px;
            }}
            QTabBar::tab:selected {{ 
                background: {tc['accent']}; 
                color: #fff;
            }}
            QTabBar::tab:hover {{
                background: {tc['hover']};
            }}
            QTabBar::tab:disabled {{
                background: {tc['secondary_bg']};
                color: {tc['secondary_text']};
            }}
            
            /* Menus */
            QMenuBar {{
                background-color: {tc['secondary_bg']};
                color: {tc['text']};
                border: none;
            }}
            QMenuBar::item:selected {{
                background-color: {tc['hover']};
                border-radius: 4px;
            }}
            QMenu {{
                background-color: {tc['background']};
                color: {tc['text']};
                border: 1px solid {tc['border']};
                border-radius: 8px;
                padding: 4px;
            }}
            QMenu::item:selected {{
                background-color: {tc['selection']};
                color: #fff;
                border-radius: 4px;
            }}
            
            /* Combo/Spin Boxes */
            QComboBox, QSpinBox {{
                background-color: {tc['secondary_bg']};
                color: {tc['text']};
                border: 1px solid {tc['border']};
                border-radius: 6px;
                padding: 8px 12px;
            }}
            QComboBox:hover, QSpinBox:hover {{
                border-color: {tc['accent']};
            }}
            QComboBox::drop-down {{
                border: none;
            }}
            QComboBox QAbstractItemView {{
                background-color: {tc['background']};
                color: {tc['text']};
                border: 1px solid {tc['border']};
                selection-background-color: {tc['selection']};
                selection-color: #fff;
            }}
            
            /* Scroll Bars */
            QScrollBar:vertical {{
                background-color: transparent;
                width: 8px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {tc['border']};
                min-height: 20px;
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {tc['accent_hover']};
            }}
            QScrollBar:horizontal {{
                background-color: transparent;
                height: 8px;
            }}
            QScrollBar::handle:horizontal {{
                background-color: {tc['border']};
                min-width: 20px;
                border-radius: 4px;
            }}
            
            /* Group Box */
            QGroupBox {{
                border: 1px solid {tc['border']};
                border-radius: 8px;
                margin-top: 12px;
                padding: 16px;
                padding-top: 24px;
                color: {tc['text']};
                font-weight: 600;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
                color: {tc['text']};
            }}

            /* Overview workspace */
            QFrame#overviewHero, QFrame#summaryCard {{
                background-color: {tc['secondary_bg']};
                border: 1px solid {tc['border']};
                border-radius: 10px;
            }}
            QLabel#overviewTitle {{
                color: {tc['text']};
                font-size: 22px;
                font-weight: 700;
            }}
            QLabel#overviewSubtitle, QLabel#summaryCaption {{
                color: {tc['secondary_text']};
            }}
            QLabel#summaryCaption {{
                font-size: 10px;
                font-weight: 700;
            }}
            QLabel#summaryValue {{
                color: {tc['text']};
                font-size: 15px;
                font-weight: 650;
            }}
            QLabel#sourceWarnings {{
                color: {tc['warning']};
                background-color: {tc['secondary_bg']};
                border: 1px solid {tc['warning']};
                border-radius: 8px;
                padding: 10px 12px;
            }}
            QGroupBox#technicalGroup {{
                border: none;
                margin-top: 12px;
                padding: 10px 0 0 0;
            }}
            QTableWidget#technicalTable {{
                background-color: {tc['secondary_bg']};
                alternate-background-color: {tc['secondary_bg']};
                border: none;
                border-radius: 10px;
                gridline-color: transparent;
                outline: none;
            }}
            QTableWidget#technicalTable::item {{
                background-color: {tc['secondary_bg']};
                color: {tc['text']};
                border: none;
                padding: 6px 12px;
            }}
            QTableWidget#technicalTable::item:selected {{
                background-color: {tc['secondary_bg']};
                color: {tc['text']};
            }}
            QTableWidget#technicalTable QHeaderView::section {{
                background-color: {tc['secondary_bg']};
                color: {tc['secondary_text']};
                border: none;
                padding: 8px 12px;
                font-size: 11px;
                font-weight: 700;
            }}
            QLabel#browserSourceLabel {{
                color: {tc['text']};
                font-size: 14px;
                font-weight: 700;
            }}
            QLabel#browserEmptyState {{
                color: {tc['secondary_text']};
                background-color: {tc['secondary_bg']};
                border: none;
                border-radius: 12px;
                padding: 28px;
                font-size: 14px;
            }}
            QPushButton#secondaryButton {{
                color: {tc['text']};
                background-color: {tc['secondary_bg']};
                border: 1px solid {tc['border']};
                padding: 7px 12px;
                font-weight: 600;
            }}
            QPushButton#secondaryButton:hover {{
                background-color: {tc['hover']};
                border-color: {tc['accent']};
            }}
            QTreeWidget#contentTree {{
                background-color: {tc['secondary_bg']};
                alternate-background-color: {tc['secondary_bg']};
                border: none;
                border-radius: 10px;
                outline: none;
            }}
            QTreeWidget#contentTree::item {{
                background-color: transparent;
                color: {tc['text']};
                border: none;
                padding: 6px 4px;
            }}
            QTreeWidget#contentTree::item:hover {{
                background-color: {tc['hover']};
            }}
            QTreeWidget#contentTree::item:selected {{
                background-color: {tc['selection']};
                color: #ffffff;
            }}
            QTreeWidget#contentTree QHeaderView::section {{
                background-color: {tc['secondary_bg']};
                color: {tc['secondary_text']};
                border: none;
                padding: 8px 10px;
                font-size: 11px;
                font-weight: 700;
            }}
            QTabWidget#contentPreview::pane {{
                background-color: {tc['secondary_bg']};
                border: none;
                border-radius: 10px;
            }}
            QTabWidget#contentPreview QTextEdit,
            QTabWidget#contentPreview QPlainTextEdit {{
                background-color: {tc['secondary_bg']};
                border: none;
            }}
            QLabel#previewCanvas {{
                background-color: {tc['secondary_bg']};
                border: none;
                border-radius: 10px;
                color: {tc['secondary_text']};
            }}

            /* Binary workspace */
            QFrame#binaryHero, QFrame#binaryToolbar {{
                background-color: {tc['secondary_bg']};
                border: 1px solid {tc['border']};
                border-radius: 10px;
            }}
            QLabel#binaryTitle {{
                color: {tc['text']};
                font-size: 20px;
                font-weight: 700;
            }}
            QLabel#binarySubtitle, QLabel#binaryMuted, QLabel#binaryPaneHeader,
            QLabel#binaryStatus {{
                color: {tc['secondary_text']};
            }}
            QLabel#binaryPaneHeader {{
                font-size: 10px;
                font-weight: 700;
            }}
            QLabel#binaryStatus {{
                padding: 4px 2px;
            }}
            QGroupBox#binaryTarget {{
                margin-top: 10px;
                padding: 10px;
                padding-top: 20px;
            }}
            QTabWidget#binaryTabs::pane {{
                background-color: {tc['background']};
                border: 1px solid {tc['border']};
                border-radius: 8px;
            }}
            QFrame#binarySurface {{
                background-color: {tc['secondary_bg']};
                border: 1px solid {tc['border']};
                border-radius: 8px;
            }}
            QPlainTextEdit#offsetPane, QPlainTextEdit#hexPane,
            QPlainTextEdit#textPane {{
                background-color: {tc['secondary_bg']};
                color: {tc['text']};
                border: none;
                border-radius: 0;
                padding: 8px 10px;
            }}
            QPlainTextEdit#offsetPane {{
                color: {tc['secondary_text']};
                border-right: 1px solid {tc['border']};
            }}
            QPlainTextEdit#textPane {{
                border-left: 1px solid {tc['border']};
            }}
            QPlainTextEdit#hexPane:focus, QPlainTextEdit#textPane:focus {{
                border: none;
            }}
            QGroupBox#binaryInspector {{
                background-color: {tc['secondary_bg']};
            }}

            /* Guided TRP creator */
            QFrame#trpHero {{
                background-color: {tc['secondary_bg']};
                border: 1px solid {tc['border']};
                border-radius: 10px;
            }}
            QLabel#trpTitle {{
                color: {tc['text']};
                font-size: 20px;
                font-weight: 700;
            }}
            QLabel#trpSubtitle, QLabel#trpHint {{
                color: {tc['secondary_text']};
            }}
            QLabel#trpSectionTitle {{
                color: {tc['text']};
                font-size: 16px;
                font-weight: 700;
            }}
            QLabel#trpStep {{
                color: {tc['secondary_text']};
                background-color: {tc['secondary_bg']};
                border: 1px solid {tc['border']};
                border-radius: 8px;
                padding: 9px 12px;
                font-weight: 650;
            }}
            QLabel#trpStep[state="active"] {{
                color: #ffffff;
                background-color: {tc['accent']};
                border-color: {tc['accent']};
            }}
            QLabel#trpStep[state="done"] {{
                color: {tc['text']};
                border-color: {tc['accent']};
            }}
            QStackedWidget#trpWizard {{
                background-color: {tc['background']};
            }}
            QTreeWidget#trpFiles {{
                background-color: {tc['secondary_bg']};
                alternate-background-color: {tc['secondary_bg']};
                border: none;
                border-radius: 10px;
                outline: none;
            }}
            QTreeWidget#trpFiles::item {{
                background-color: transparent;
                border: none;
                padding: 7px 6px;
            }}
            QTreeWidget#trpFiles::item:hover {{
                background-color: {tc['hover']};
            }}
            QTreeWidget#trpFiles::item:selected {{
                background-color: {tc['selection']};
                color: #ffffff;
            }}
            QLabel#trpValidation {{
                color: {tc['warning']};
            }}
            QLabel#trpValidation[valid="true"] {{
                color: {tc['success']};
            }}
            QLabel#trpSummary {{
                color: {tc['text']};
                background-color: {tc['secondary_bg']};
                border-radius: 8px;
                padding: 14px;
            }}
            QTextEdit#trpLog {{
                border: none;
                background-color: {tc['secondary_bg']};
            }}
            
            /* Tool Tips */
            QToolTip {{
                background-color: {tc['secondary_bg']};
                color: {tc['text']};
                border: 1px solid {tc['border']};
                border-radius: 6px;
                padding: 8px 12px;
            }}
            
            /* Progress Bar */
            QProgressBar {{
                border: 1px solid {tc['border']};
                border-radius: 6px;
                text-align: center;
                background-color: {tc['secondary_bg']};
            }}
            QProgressBar::chunk {{
                background-color: {tc['accent']};
                border-radius: 4px;
            }}
            
            /* Labels */
            QLabel {{
                color: {tc['text']};
                background-color: transparent;
            }}
            
            /* Status Bar */
            QStatusBar {{
                background-color: {tc['secondary_bg']};
                color: {tc['secondary_text']};
                border-top: 1px solid {tc['border']};
            }}
        """)

    @staticmethod
    def adjust_color(color, amount):
        """Adjust color brightness"""
        if color.startswith('#'):
            color = color[1:]
        rgb = tuple(int(color[i:i+2], 16) for i in (0, 2, 4))
        rgb = tuple(min(255, max(0, c + amount)) for c in rgb)
        return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"
