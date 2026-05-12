import json
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget
import os
import logging

class StyleManager:
    DEFAULT_SETTINGS = {
        "appearance": {
            "theme": "Light",
            "night_mode": False,
            "font_family": "Arial",
            "font_size": 12,
            "colors": {
                "background": "#ffffff",
                "text": "#0f172a",
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
    
    @classmethod
    def get_available_themes(cls):
        """Return list of available theme names."""
        cls._load_themes()
        return list(cls.THEMES.keys())

    @classmethod
    def get_theme_colors(cls, theme_name, custom_colors=None):
        """Get colors for specified theme."""
        cls._load_themes()
        if theme_name == 'Custom' and custom_colors:
            base = cls.THEMES.get('Light', {}).copy()
            base.update({
                'background': custom_colors.get('bg_color', base.get('background', '#ffffff')),
                'text': custom_colors.get('text_color', base.get('text', '#000000')),
                'accent': custom_colors.get('accent_color', base.get('accent', '#3b82f6'))
            })
            return base
        return cls.THEMES.get(theme_name, cls.THEMES.get('Light', {}))

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
        theme_name = appearance.get("theme", "Light")
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
                background-color: {tc['secondary_bg']};
                width: 10px;
                border-radius: 5px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {tc['accent']};
                min-height: 20px;
                border-radius: 5px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {tc['accent_hover']};
            }}
            QScrollBar:horizontal {{
                background-color: {tc['secondary_bg']};
                height: 10px;
                border-radius: 5px;
            }}
            QScrollBar::handle:horizontal {{
                background-color: {tc['accent']};
                min-width: 20px;
                border-radius: 5px;
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