import json
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtCore import Qt

class StyleManager:
    DEFAULT_SETTINGS = {
        "theme": "Light",
        "night_mode": False,
        "font": "Arial",
        "font_size": 12,
        "bg_color": "#ffffff",
        "text_color": "#000000",
        "accent_color": "#3498db"
    }

    @staticmethod
    def load_settings(filename="settings.json"):
        """Load settings from file"""
        try:
            with open(filename, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return StyleManager.DEFAULT_SETTINGS.copy()
        except Exception as e:
            raise Exception(f"Error loading settings: {str(e)}")
    
    @staticmethod
    def save_settings(settings, filename="settings.json"):
        """Save settings to file"""
        try:
            with open(filename, "w") as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            raise Exception(f"Error saving settings: {str(e)}")
    
    @staticmethod
    def apply_theme(widget, settings):
        """Apply theme to widget"""
        # Estrai i colori dalle impostazioni
        bg_color = settings.get('bg_color', '').replace("background-color: ", "").strip()
        text_color = settings.get('text_color', '').replace("background-color: ", "").strip()
        accent_color = settings.get('accent_color', '').replace("background-color: ", "").strip()
        
        # Usa i colori predefiniti se non sono stati impostati
        if not bg_color:
            bg_color = "#1e1e1e" if settings.get('night_mode') else "#ffffff"
        if not text_color:
            text_color = "#ffffff" if settings.get('night_mode') else "#000000"
        if not accent_color:
            accent_color = "#3498db"
        
        # Applica lo stile con i colori corretti
        widget.setStyleSheet(f"""
            QMainWindow, QWidget {{ 
                background-color: {bg_color}; 
                color: {text_color}; 
            }}
            QLineEdit, QTextEdit {{ 
                background-color: {StyleManager.adjust_color(bg_color, 10)}; 
                color: {text_color}; 
                border: 1px solid {accent_color};
                border-radius: 4px;
                padding: 5px;
            }}
            QPushButton {{ 
                background-color: {accent_color}; 
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {StyleManager.adjust_color(accent_color, -20)};
            }}
            QTreeWidget {{ 
                background-color: {bg_color};
                alternate-background-color: {StyleManager.adjust_color(bg_color, 5)};
                color: {text_color};
                border: 1px solid {accent_color};
                border-radius: 4px;
            }}
            QTreeWidget::item:hover {{
                background-color: {StyleManager.adjust_color(bg_color, 10)};
            }}
            QTreeWidget::item:selected {{
                background-color: {accent_color};
                color: white;
            }}
            QHeaderView::section {{
                background-color: {StyleManager.adjust_color(bg_color, 5)};
                color: {text_color};
                padding: 5px;
                border: none;
            }}
            QTabWidget::pane {{ 
                border: 1px solid {accent_color}; 
                border-radius: 4px;
            }}
            QTabBar::tab {{ 
                background: {StyleManager.adjust_color(bg_color, 5)}; 
                color: {text_color};
                padding: 8px;
                margin: 2px;
                border-radius: 4px;
            }}
            QTabBar::tab:selected {{ 
                background: {accent_color}; 
                color: white;
            }}
            QMenu {{
                background-color: {bg_color};
                color: {text_color};
                border: 1px solid {accent_color};
            }}
            QMenu::item:selected {{
                background-color: {accent_color};
                color: white;
            }}
            QComboBox {{
                background-color: {StyleManager.adjust_color(bg_color, 5)};
                color: {text_color};
                border: 1px solid {accent_color};
                border-radius: 4px;
                padding: 5px;
            }}
            QSpinBox {{
                background-color: {StyleManager.adjust_color(bg_color, 5)};
                color: {text_color};
                border: 1px solid {accent_color};
                border-radius: 4px;
                padding: 5px;
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