from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit

class FileViewerDialog(QDialog):
    def __init__(self, data, file_name, mode="text", parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"View {file_name}")
        layout = QVBoxLayout(self)
        
        text_edit = QTextEdit()
        if mode == "hex":
            text_edit.setPlainText(' '.join(f'{b:02X}' for b in data))
        else:
            text_edit.setPlainText(data.decode('utf-8', errors='replace'))
        
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)
        self.resize(600, 400)
