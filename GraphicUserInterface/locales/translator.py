from PyQt5.QtCore import QTranslator, QLocale
import json
import os

class Translator:
    def __init__(self):
        self.translator = QTranslator()
        self.current_language = "en"
        self.translations = {}
        self.load_translations()
        
    def load_translations(self):
        """Load all translation files"""
        locales_dir = os.path.dirname(os.path.abspath(__file__))
        
        for file in os.listdir(locales_dir):
            if file.endswith('.json'):
                lang_code = file[:-5]  # Remove .json
                with open(os.path.join(locales_dir, file), 'r', encoding='utf-8') as f:
                    self.translations[lang_code] = json.load(f)
    
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