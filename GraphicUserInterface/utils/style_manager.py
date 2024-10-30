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
                "text": "#000000",
                "accent": "#3498db"
            }
        }
    }

    # Temi predefiniti
    THEMES = {
        'Light': {
            'background': '#ffffff',
            'secondary_bg': '#f5f6fa',
            'text': '#2c3e50',
            'secondary_text': '#7f8c8d',
            'accent': '#3498db',
            'accent_hover': '#2980b9',
            'border': '#bdc3c7',
            'selection': '#3498db',
            'hover': '#e8f0fe',
            'error': '#e74c3c',
            'success': '#2ecc71',
            'warning': '#f1c40f'
        },
        'Dark': {
            'background': '#1e1e1e',
            'secondary_bg': '#2d2d2d',
            'text': '#ffffff',
            'secondary_text': '#cccccc',
            'accent': '#3498db',
            'accent_hover': '#2980b9',
            'border': '#3d3d3d',
            'selection': '#0d47a1',
            'hover': '#353535',
            'error': '#e74c3c',
            'success': '#2ecc71',
            'warning': '#f1c40f'
        },
        'Custom': {
            'background': '#ffffff',
            'secondary_bg': '#f5f6fa',
            'text': '#2c3e50',
            'secondary_text': '#7f8c8d',
            'accent': '#3498db',
            'accent_hover': '#2980b9',
            'border': '#bdc3c7',
            'selection': '#3498db',
            'hover': '#e8f0fe',
            'error': '#e74c3c',
            'success': '#2ecc71',
            'warning': '#f1c40f'
        }
    }

    @staticmethod
    def get_theme_colors(theme_name, custom_colors=None):
        """Get colors for specified theme"""
        if theme_name == 'Custom' and custom_colors:
            colors = StyleManager.THEMES['Custom'].copy()
            colors.update({
                'background': custom_colors.get('bg_color', colors['background']),
                'text': custom_colors.get('text_color', colors['text']),
                'accent': custom_colors.get('accent_color', colors['accent'])
            })
            return colors
        return StyleManager.THEMES.get(theme_name, StyleManager.THEMES['Light'])

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

    @staticmethod
    def apply_theme(widget, settings):
        """Apply theme to widget"""
        # Estrai i colori dalle impostazioni
        appearance = settings.get("appearance", {})
        colors = appearance.get("colors", {})
        
        # Colori predefiniti
        default_colors = {
            'background': colors.get("background", "#ffffff"),
            'text': colors.get("text", "#000000"),
            'accent': colors.get("accent", "#3498db"),
            'secondary_bg': colors.get("background", "#ffffff"),  # Usa il colore di sfondo come fallback
            'secondary_text': colors.get("text", "#000000"),     # Usa il colore del testo come fallback
            'accent_hover': "#2980b9",
            'border': "#bdc3c7",
            'selection': "#3498db",
            'hover': "#e8f0fe",
            'error': "#e74c3c",
            'success': "#2ecc71",
            'warning': "#f1c40f"
        }
        
        # Applica lo stile
        widget.setStyleSheet(f"""
            /* Base */
            QMainWindow, QWidget {{ 
                background-color: {default_colors['background']}; 
                color: {default_colors['text']}; 
            }}
            
            /* Input Fields */
            QLineEdit, QTextEdit, QPlainTextEdit {{ 
                background-color: {default_colors['secondary_bg']}; 
                color: {default_colors['text']}; 
                border: 1px solid {default_colors['border']};
                border-radius: 4px;
                padding: 5px;
                selection-background-color: {default_colors['selection']};
                selection-color: white;
            }}
            
            /* Buttons */
            QPushButton {{ 
                background-color: {default_colors['accent']}; 
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {default_colors['accent_hover']};
            }}
            QPushButton:pressed {{
                background-color: {default_colors['selection']};
            }}
            QPushButton:disabled {{
                background-color: {default_colors['secondary_bg']};
                color: {default_colors['secondary_text']};
            }}
            
            /* Tree/List Widgets */
            QTreeWidget, QListWidget {{ 
                background-color: {default_colors['background']};
                alternate-background-color: {default_colors['secondary_bg']};
                color: {default_colors['text']};
                border: 1px solid {default_colors['border']};
                border-radius: 4px;
            }}
            QTreeWidget::item:hover, QListWidget::item:hover {{
                background-color: {default_colors['hover']};
            }}
            QTreeWidget::item:selected, QListWidget::item:selected {{
                background-color: {default_colors['selection']};
                color: white;
            }}
            
            /* Headers */
            QHeaderView::section {{
                background-color: {default_colors['secondary_bg']};
                color: {default_colors['text']};
                padding: 5px;
                border: none;
            }}
            
            /* Tabs */
            QTabWidget::pane {{ 
                border: 1px solid {default_colors['border']}; 
                border-radius: 4px;
            }}
            QTabBar::tab {{ 
                background: {default_colors['secondary_bg']}; 
                color: {default_colors['text']};
                padding: 8px;
                margin: 2px;
                border-radius: 4px;
            }}
            QTabBar::tab:selected {{ 
                background: {default_colors['accent']}; 
                color: white;
            }}
            QTabBar::tab:hover {{
                background: {default_colors['hover']};
            }}
            
            /* Menus */
            QMenuBar {{
                background-color: {default_colors['background']};
                color: {default_colors['text']};
            }}
            QMenuBar::item:selected {{
                background-color: {default_colors['hover']};
            }}
            QMenu {{
                background-color: {default_colors['background']};
                color: {default_colors['text']};
                border: 1px solid {default_colors['border']};
            }}
            QMenu::item:selected {{
                background-color: {default_colors['selection']};
                color: white;
            }}
            
            /* Combo/Spin Boxes */
            QComboBox, QSpinBox {{
                background-color: {default_colors['secondary_bg']};
                color: {default_colors['text']};
                border: 1px solid {default_colors['border']};
                border-radius: 4px;
                padding: 5px;
            }}
            QComboBox::drop-down {{
                border: none;
            }}
            QComboBox::down-arrow {{
                image: none;
            }}
            
            /* Scroll Bars */
            QScrollBar:vertical {{
                background-color: {default_colors['secondary_bg']};
                width: 12px;
                margin: 0px;
                border-radius: 6px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {default_colors['accent']};
                min-height: 20px;
                border-radius: 6px;
            }}
            QScrollBar:horizontal {{
                background-color: {default_colors['secondary_bg']};
                height: 12px;
                margin: 0px;
                border-radius: 6px;
            }}
            QScrollBar::handle:horizontal {{
                background-color: {default_colors['accent']};
                min-width: 20px;
                border-radius: 6px;
            }}
            
            /* Group Box */
            QGroupBox {{
                border: 1px solid {default_colors['border']};
                border-radius: 4px;
                margin-top: 1ex;
                padding: 5px;
                color: {default_colors['text']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 3px;
                color: {default_colors['text']};
            }}
            
            /* Tool Tips */
            QToolTip {{
                background-color: {default_colors['background']};
                color: {default_colors['text']};
                border: 1px solid {default_colors['border']};
                border-radius: 4px;
                padding: 5px;
            }}
            
            /* Progress Bar */
            QProgressBar {{
                border: 1px solid {default_colors['border']};
                border-radius: 4px;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background-color: {default_colors['accent']};
            }}
        """)
        
        # Forza l'aggiornamento dello stile per tutti i widget figli
        for child in widget.findChildren(QWidget):
            child.setStyleSheet(child.styleSheet())

    @staticmethod
    def adjust_color(color, amount):
        """Adjust color brightness"""
        if color.startswith('#'):
            color = color[1:]
        rgb = tuple(int(color[i:i+2], 16) for i in (0, 2, 4))
        rgb = tuple(min(255, max(0, c + amount)) for c in rgb)
        return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"