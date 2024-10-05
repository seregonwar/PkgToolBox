from logging import Logger
from PyQt5.QtWidgets import QMessageBox

class MessageBoxHelper:
    @staticmethod
    def show_information(message, logging):
        if logging:
            Logger.log_information(message)
        QMessageBox.information(None, "PS4 PKG Tool", message)

    @staticmethod
    def show_error(message, logging):
        if logging:
            Logger.log_error(message)
        QMessageBox.critical(None, "PS4 PKG Tool", message)

    @staticmethod
    def show_warning(message, logging):
        if logging:
            Logger.log_warning(message)
        QMessageBox.warning(None, "PS4 PKG Tool", message)

    @staticmethod
    def dialog_result_yes_no(message):
        return QMessageBox.question(None, "PS4 PKG Tool", message, QMessageBox.Yes | QMessageBox.No)

    @staticmethod
    def dialog_result_yes_no_cancel(message):
        return QMessageBox.question(None, "PS4 PKG Tool", message, QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)