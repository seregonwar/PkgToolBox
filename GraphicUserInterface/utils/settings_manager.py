import os
import json
from pathlib import Path
import logging

class SettingsManager:
    """Gestisce il caricamento, salvataggio e accesso alle impostazioni dell'applicazione"""
    
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
        },
        "language": {
            "current": "en",
            "available": ["en", "it", "es", "fr", "de", "ja"]
        },
        "behavior": {
            "auto_expand": True,
            "show_hidden": False,
            "confirm_exit": True,
            "auto_save": True
        },
        "paths": {
            "output": "",
            "temp": "",
            "last_pkg": "",
            "recent_files": []
        }
    }

    def __init__(self):
        """Inizializza il gestore delle impostazioni"""
        self._settings = self.DEFAULT_SETTINGS.copy()
        self._config_dir = os.path.join(str(Path.home()), ".pkgtoolbox")
        self._config_file = os.path.join(self._config_dir, "settings.json")
        
        # Assicurati che la directory di configurazione esista
        os.makedirs(self._config_dir, exist_ok=True)
        
        # Carica o crea le impostazioni
        if os.path.exists(self._config_file):
            self.load()
        else:
            # Se il file non esiste, usa Arial come font predefinito
            self._settings["appearance"]["font_family"] = "Arial"
            self.save()
            logging.info("Created new settings file with defaults")

    def load(self):
        """Carica le impostazioni dal file"""
        try:
            with open(self._config_file, 'r', encoding='utf-8') as f:
                stored_settings = json.load(f)
                self._settings = self._merge_settings(self.DEFAULT_SETTINGS, stored_settings)
            logging.info("Settings loaded successfully")
        except Exception as e:
            logging.error(f"Failed to load settings: {e}")
            self._settings = self.DEFAULT_SETTINGS.copy()
            self.save()

    def save(self):
        """Salva le impostazioni nel file"""
        try:
            os.makedirs(self._config_dir, exist_ok=True)
            with open(self._config_file, 'w', encoding='utf-8') as f:
                json.dump(self._settings, f, indent=4, ensure_ascii=False)
            logging.info("Settings saved successfully")
        except Exception as e:
            logging.error(f"Failed to save settings: {e}")

    def get(self, key_path: str, default=None):
        """Ottiene un valore dalle impostazioni usando un percorso con punti"""
        try:
            value = self._settings
            for key in key_path.split('.'):
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key_path: str, value):
        """Imposta un valore nelle impostazioni usando un percorso con punti"""
        try:
            keys = key_path.split('.')
            target = self._settings
            
            # Naviga attraverso il dizionario creando la struttura se necessario
            for key in keys[:-1]:
                if key not in target:
                    target[key] = {}
                target = target[key]
                
            # Imposta il valore
            target[keys[-1]] = value
            
            # Salva automaticamente se abilitato
            if self.get('behavior.auto_save', True):
                self.save()
            
            logging.info(f"Setting updated: {key_path} = {value}")
        except Exception as e:
            logging.error(f"Failed to set setting {key_path}: {e}")

    def _merge_settings(self, default, stored):
        """Unisce le impostazioni memorizzate con quelle predefinite"""
        result = default.copy()
        for key, value in stored.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_settings(result[key], value)
            else:
                result[key] = value
        return result

    def reset(self):
        """Resetta tutte le impostazioni ai valori predefiniti"""
        self._settings = self.DEFAULT_SETTINGS.copy()
        self.save()
        logging.info("Settings reset to defaults")

    @property
    def settings(self):
        """Restituisce una copia delle impostazioni correnti"""
        return self._settings.copy()