"""
Base tab widget for modular UI architecture
"""
from PyQt5.QtWidgets import QWidget, QVBoxLayout


class BaseTab(QWidget):
    """Base class for all tab widgets"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.layout = QVBoxLayout(self)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI components for this tab"""
        raise NotImplementedError("setup_ui() must be implemented by subclasses")
        
    def get_package(self):
        """Get the currently loaded package from parent window"""
        if hasattr(self.parent_window, 'package'):
            return self.parent_window.package
        return None
        
    def show_message(self, title, message, message_type="info"):
        """Show message dialog through parent window"""
        if hasattr(self.parent_window, 'show_message'):
            self.parent_window.show_message(title, message, message_type)
