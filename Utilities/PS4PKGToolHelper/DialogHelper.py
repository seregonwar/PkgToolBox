from PyQt5.QtWidgets import QFileDialog

class DialogHelper:
    @staticmethod
    def show_folder_browser_dialog():
        dialog = QFileDialog()
        dialog.setFileMode(QFileDialog.Directory)
        if dialog.exec_():
            return dialog.selectedFiles()[0]
        return None

    @staticmethod
    def show_save_file_dialog(title, filter):
        dialog = QFileDialog()
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        dialog.setNameFilter(filter)
        dialog.setWindowTitle(title)
        if dialog.exec_():
            return dialog.selectedFiles()[0]
        return None