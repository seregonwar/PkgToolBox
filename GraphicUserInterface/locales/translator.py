from PyQt5.QtCore import QTranslator, QLocale
import json
import os
import sys

class Translator:
    def __init__(self):
        self.translator = QTranslator()
        self.current_language = "en"
        self.translations = {}
        self.load_translations()
        
    def load_translations(self):
        """Load all translation files"""
        locales_dir = None

        # Try PyInstaller frozen paths first
        try:
            if getattr(sys, 'frozen', False):
                # Prefer the unpacked temp directory
                base_path = getattr(sys, '_MEIPASS', None)
                if base_path:
                    candidate = os.path.join(base_path, 'GraphicUserInterface', 'locales')
                    if os.path.isdir(candidate):
                        locales_dir = candidate
                
                # PyInstaller onedir structure often places assets under _internal
                if not locales_dir:
                    exec_dir = os.path.dirname(sys.executable)
                    candidate = os.path.join(exec_dir, '_internal', 'GraphicUserInterface', 'locales')
                    if os.path.isdir(candidate):
                        locales_dir = candidate
        except Exception:
            # Ignore path detection errors and fallback below
            pass

        # Fallback to the package directory when running from source or if the above fails
        if not locales_dir:
            locales_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Load all json translations if the folder exists
        if os.path.isdir(locales_dir):
            for file in os.listdir(locales_dir):
                if file.endswith('.json'):
                    lang_code = file[:-5]  # Remove .json
                    with open(os.path.join(locales_dir, file), 'r', encoding='utf-8') as f:
                        self.translations[lang_code] = json.load(f)
        else:
            # If the folder is missing, keep an empty translations map (UI will show default text)
            self.translations = {}
    
    def translate(self, text):
        """Translate text to current language"""
        if self.current_language in self.translations:
            return self.translations[self.current_language].get(text, text)
        return text
    
    def change_language(self, lang_code):
        """Change current language"""
        if lang_code in self.translations:
            self.current_language = lang_code
            return True
        return False