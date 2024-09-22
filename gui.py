import sys
import os
import re
import shutil
import binascii
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QTreeWidget, QTreeWidgetItem,
                             QFileDialog, QMessageBox, QTabWidget, QScrollArea, QSizePolicy,
                             QTextEdit, QSpinBox, QFrame, QStatusBar, QToolBar, QAction)
from PyQt5.QtGui import QFont, QPixmap, QPalette, QColor, QRegExpValidator, QIcon
from PyQt5.QtCore import Qt, QRegExp, QSize
from package import Package
from file_operations import extract_file, inject_file, modify_file_header

OUTPUT_FOLDER = "._temp_output"
Hexpattern = re.compile(r'[^\x20-\x7E]')

class PS4PKGTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PS4 PKG Tool")
        self.setGeometry(100, 100, 1200, 800)
        
        # set the icon of the main window
        self.setWindowIcon(QIcon("icons/toolbox-png.svg"))
        
        # Set blue background with a more modern shade
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(1,92,181,255))  # A more vibrant blue
        self.setPalette(palette)
        
        self.pkg_entry = QLineEdit()
        self.extract_pkg_entry = QLineEdit()
        self.file_entry = QLineEdit()
        self.extract_out_entry = QLineEdit()
        self.dump_pkg_entry = QLineEdit()
        self.dump_out_entry = QLineEdit()
        self.inject_pkg_entry = QLineEdit()
        self.inject_file_entry = QLineEdit()
        self.inject_input_entry = QLineEdit()
        self.modify_pkg_entry = QLineEdit()
        self.offset_entry = QLineEdit()
        self.data_entry = QLineEdit()
        self.hex_viewer = QTextEdit()
        self.hex_editor = QTextEdit()
        
        self.current_pkg = None
        
        self.setup_ui()

        self.file_path = None
        self.package = None
        self.run_command_callback = None

    def setup_ui(self):
        self.create_statusbar()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        self.image_label = QLabel("No photo yet")
        self.image_label.setFixedSize(300, 300)
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet("background-color: white; border: 1px solid white; border-radius: 10px;")
        left_layout.addWidget(self.image_label)

        pkg_layout = QHBoxLayout()
        self.pkg_entry.setPlaceholderText("Select PKG file")
        self.pkg_entry.setStyleSheet("background-color: white; color: #2c3e50; font-size: 14px; padding: 8px; border-radius: 5px;")
        pkg_button = QPushButton("Browse")
        pkg_button.setStyleSheet("font-size: 14px; padding: 8px 15px; background-color: #3498db; color: white; border-radius: 5px;")
        pkg_button.clicked.connect(self.browse_pkg)
        pkg_layout.addWidget(self.pkg_entry)
        pkg_layout.addWidget(pkg_button)
        left_layout.addLayout(pkg_layout)

        left_layout.addStretch(1)
        main_layout.addWidget(left_widget, 1)

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        self.tab_widget = QTabWidget()
        self.info_tab = QWidget()
        self.extract_tab = QWidget()
        self.dump_tab = QWidget()
        self.inject_tab = QWidget()
        self.modify_tab = QWidget()
        
        self.tab_widget.addTab(self.info_tab, "Info")
        self.tab_widget.addTab(self.extract_tab, "Extract")
        self.tab_widget.addTab(self.dump_tab, "Dump")
        self.tab_widget.addTab(self.inject_tab, "Inject")
        self.tab_widget.addTab(self.modify_tab, "Modify")
        
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #3498db; }
            QTabBar::tab { background: #3498db; color: white; padding: 10px; }
            QTabBar::tab:selected { background: #2980b9; }
        """)
        
        right_layout.addWidget(self.tab_widget)

        self.setup_info_tab()
        self.setup_extract_tab()
        self.setup_dump_tab()
        self.setup_inject_tab()
        self.setup_modify_tab()

        main_layout.addWidget(right_widget, 2)

    def create_toolbar(self):
        toolbar = QToolBar()
        toolbar.setIconSize(QSize(32, 32))
        toolbar.setStyleSheet("QToolBar { background: #2c3e50; spacing: 10px; }")
        self.addToolBar(toolbar)

        icon_style = "QToolButton { background-color: #34495e; border-radius: 5px; } QToolButton:hover { background-color: #3498db; }"

        info_action = QAction(QIcon("icons/info.png"), "Info", self)
        info_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(0))
        toolbar.addAction(info_action)

        extract_action = QAction(QIcon("icons/extract.png"), "Extract", self)
        extract_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(1))
        toolbar.addAction(extract_action)

        dump_action = QAction(QIcon("icons/dump.png"), "Dump", self)
        dump_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(2))
        toolbar.addAction(dump_action)

        inject_action = QAction(QIcon("icons/inject.png"), "Inject", self)
        inject_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(3))
        toolbar.addAction(inject_action)

        modify_action = QAction(QIcon("icons/modify.png"), "Modify", self)
        modify_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(4))
        toolbar.addAction(modify_action)

        toolbar.setStyleSheet(icon_style)

    def create_statusbar(self):
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready")
        self.statusBar.setStyleSheet("QStatusBar { background-color: #34495e; color: white; }")

    def setup_info_tab(self):
        layout = QVBoxLayout(self.info_tab)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Key", "Value"])
        self.tree.setColumnWidth(0, 200)
        self.tree.setStyleSheet("QTreeWidget { background-color: white; color: #2c3e50; font-size: 14px; border: none; }")
        layout.addWidget(self.tree)

        self.execute_output = QTextEdit()
        self.execute_output.setReadOnly(True)
        self.execute_output.setStyleSheet("QTextEdit { background-color: white; color: #2c3e50; font-size: 14px; border: none; border-radius: 5px; }")
        layout.addWidget(self.execute_output)

        run_button = QPushButton("Execute Info")
        run_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        run_button.clicked.connect(lambda: self.run_command("info"))
        layout.addWidget(run_button)

    def create_file_selection_layout(self, entry_widget, browse_function):
        layout = QHBoxLayout()
        entry_widget.setPlaceholderText("Select file")
        entry_widget.setStyleSheet("QLineEdit { background-color: white; color: #2c3e50; font-size: 14px; padding: 8px; border: none; border-radius: 5px; }")
        button = QPushButton("Browse")
        button.setStyleSheet("QPushButton { font-size: 14px; padding: 8px 15px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        button.clicked.connect(browse_function)
        layout.addWidget(entry_widget)
        layout.addWidget(button)
        return layout

    def setup_extract_tab(self):
        layout = QVBoxLayout(self.extract_tab)
        
        layout.addLayout(self.create_file_selection_layout(self.extract_pkg_entry, lambda: self.browse_pkg(self.extract_pkg_entry)))
        layout.addLayout(self.create_file_selection_layout(self.file_entry, self.browse_file))
        layout.addLayout(self.create_file_selection_layout(self.extract_out_entry, lambda: self.browse_out(self.extract_out_entry)))

        run_button = QPushButton("Execute Extract")
        run_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        run_button.clicked.connect(lambda: self.run_command("extract"))
        layout.addWidget(run_button)
        
        layout.addStretch(1)

    def setup_dump_tab(self):
        layout = QVBoxLayout(self.dump_tab)
        
        layout.addLayout(self.create_file_selection_layout(self.dump_pkg_entry, lambda: self.browse_pkg(self.dump_pkg_entry)))
        layout.addLayout(self.create_file_selection_layout(self.dump_out_entry, lambda: self.browse_out(self.dump_out_entry)))

        run_button = QPushButton("Execute Dump")
        run_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        run_button.clicked.connect(lambda: self.run_command("dump"))
        layout.addWidget(run_button)
        
        layout.addStretch(1)

    def setup_inject_tab(self):
        layout = QVBoxLayout(self.inject_tab)
        
        layout.addLayout(self.create_file_selection_layout(self.inject_pkg_entry, lambda: self.browse_pkg(self.inject_pkg_entry)))
        layout.addLayout(self.create_file_selection_layout(self.inject_file_entry, self.browse_file))
        layout.addLayout(self.create_file_selection_layout(self.inject_input_entry, self.browse_file))

        run_button = QPushButton("Execute Inject")
        run_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        run_button.clicked.connect(lambda: self.run_command("inject"))
        layout.addWidget(run_button)
        
        layout.addStretch(1)

    def setup_modify_tab(self):
        layout = QVBoxLayout(self.modify_tab)
        
        layout.addLayout(self.create_file_selection_layout(self.modify_pkg_entry, lambda: self.browse_pkg(self.modify_pkg_entry)))
        
        hex_layout = QHBoxLayout()
        self.hex_viewer.setReadOnly(True)
        self.hex_viewer.setStyleSheet("QTextEdit { background-color: white; color: #2c3e50; font-size: 14px; border: none; border-radius: 5px; }")
        hex_layout.addWidget(self.hex_viewer)
        self.hex_editor.setStyleSheet("QTextEdit { background-color: white; color: #2c3e50; font-size: 14px; border: none; border-radius: 5px; }")
        hex_layout.addWidget(self.hex_editor)
        layout.addLayout(hex_layout)

        offset_layout = QHBoxLayout()
        offset_layout.addWidget(QLabel("Offset (hex):"))
        self.offset_entry = QLineEdit()
        self.offset_entry.setPlaceholderText("Enter offset in hexadecimal")
        self.offset_entry.setValidator(QRegExpValidator(QRegExp("[0-9A-Fa-f]+")))
        self.offset_entry.setStyleSheet("QLineEdit { font-size: 14px; padding: 8px; border: none; border-radius: 5px; }")
        offset_layout.addWidget(self.offset_entry)
        layout.addLayout(offset_layout)

        data_layout = QHBoxLayout()
        data_layout.addWidget(QLabel("New Data (hex):"))
        self.data_entry = QLineEdit()
        self.data_entry.setPlaceholderText("Enter new data in hexadecimal")
        self.data_entry.setValidator(QRegExpValidator(QRegExp("[0-9A-Fa-f]+")))
        self.data_entry.setStyleSheet("QLineEdit { font-size: 14px; padding: 8px; border: none; border-radius: 5px; }")
        data_layout.addWidget(self.data_entry)
        layout.addLayout(data_layout)

        search_layout = QHBoxLayout()
        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Search hex")
        self.search_entry.setStyleSheet("QLineEdit { font-size: 14px; padding: 8px; border: none; border-radius: 5px; }")
        search_button = QPushButton("Find")
        search_button.setStyleSheet("QPushButton { font-size: 14px; padding: 8px 15px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        search_button.clicked.connect(self.search_hex)
        search_layout.addWidget(self.search_entry)
        search_layout.addWidget(search_button)
        layout.addLayout(search_layout)

        replace_layout = QHBoxLayout()
        self.replace_entry = QLineEdit()
        self.replace_entry.setPlaceholderText("Replace hex")
        self.replace_entry.setStyleSheet("QLineEdit { font-size: 14px; padding: 8px; border: none; border-radius: 5px; }")
        replace_button = QPushButton("Replace")
        replace_button.setStyleSheet("QPushButton { font-size: 14px; padding: 8px 15px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        replace_button.clicked.connect(self.replace_hex)
        replace_layout.addWidget(self.replace_entry)
        replace_layout.addWidget(replace_button)
        layout.addLayout(replace_layout)

        run_button = QPushButton("Execute Modify")
        run_button.setStyleSheet("QPushButton { font-size: 16px; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 5px; } QPushButton:hover { background-color: #2980b9; }")
        run_button.clicked.connect(lambda: self.run_command("modify"))
        layout.addWidget(run_button)
        
        layout.addStretch(1)

    def browse_pkg(self, entry_widget=None):
        filename, _ = QFileDialog.getOpenFileName(self, "Select PKG file", "", "PKG files (*.pkg)")
        if filename:
            self.current_pkg = filename
            self.update_pkg_entries()
            self.file_path = filename
            self.package = Package(self.file_path)
            self.process_pkg()

    def update_pkg_entries(self):
        # Update all PKG input fields with the current value
        self.pkg_entry.setText(self.current_pkg)
        self.extract_pkg_entry.setText(self.current_pkg)
        self.dump_pkg_entry.setText(self.current_pkg)
        self.inject_pkg_entry.setText(self.current_pkg)
        self.modify_pkg_entry.setText(self.current_pkg)

    def browse_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select file", "")
        if filename:
            self.file_entry.setText(filename)

    def browse_out(self, entry_widget):
        directory = QFileDialog.getExistingDirectory(self, "Select output directory")
        if directory:
            entry_widget.setText(directory)

    def run_command(self, cmd):
        if cmd == "info":
            pkg = self.pkg_entry.text()
            file = ""
            out = ""
        elif cmd == "extract":
            pkg = self.extract_pkg_entry.text()
            file = self.file_entry.text()
            out = self.extract_out_entry.text()
        elif cmd == "dump":
            pkg = self.dump_pkg_entry.text()
            file = ""
            out = self.dump_out_entry.text()
        elif cmd == "inject":
            pkg = self.inject_pkg_entry.text()
            file = self.inject_file_entry.text()
            out = self.inject_input_entry.text()
        elif cmd == "modify":
            pkg = self.modify_pkg_entry.text()
            try:
                offset = int(self.offset_entry.text(), 16)
            except ValueError:
                QMessageBox.critical(self, "Error", "Invalid hexadecimal offset.")
                return
            try:
                data = bytes.fromhex(self.data_entry.text())
            except ValueError:
                QMessageBox.critical(self, "Error", "Invalid hexadecimal data.")
                return
            file = offset
            out = data

        if not pkg:
            QMessageBox.critical(self, "Error", f"Select a PKG file for the {cmd} command.")
            return
        if cmd == "extract" and (not file or not out):
            QMessageBox.critical(self, "Error", "PKG, File, and Output are required for the extract command.")
            return
        if cmd == "dump" and not out:
            QMessageBox.critical(self, "Error", "PKG and Output are required for the dump command.")
            return
        if cmd == "inject" and (not file or not out):
            QMessageBox.critical(self, "Error", "PKG, File, and Input are required for the inject command.")
            return
        if cmd == "modify" and (not file or not out):
            QMessageBox.critical(self, "Error", "PKG, Offset, and New Data are required for the modify command.")
            return

        try:
            if cmd == "extract":
                extract_file(pkg, file, out)
            elif cmd == "inject":
                inject_file(pkg, file, out)
            elif cmd == "modify":
                modify_file_header(pkg, file, out)
            elif cmd == "info":
                output = self.run_command_callback(cmd, pkg, file, out, self.update_info)
                if output:
                    self.execute_output.setPlainText(self.normalize_output(output))
                else:
                    self.execute_output.setPlainText("No output received from the command.")
            else:
                output = self.run_command_callback(cmd, pkg, file, out, self.update_info)
            QMessageBox.information(self, "Command Executed", f"The {cmd.capitalize()} command was executed successfully.")
        except ValueError as e:
            QMessageBox.critical(self, "Error", str(e))
        except FileExistsError as e:
            response = QMessageBox.question(self, "File Exists", str(e) + "\nDo you want to overwrite the existing file?",
                                            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if response == QMessageBox.Yes:
                try:
                    # Implement logic to overwrite the file
                    if cmd == "dump":
                        shutil.rmtree(out)  # Remove existing directory
                        output = self.run_command_callback(cmd, pkg, file, out, self.update_info)
                        QMessageBox.information(self, "Command Executed", f"The {cmd.capitalize()} command was executed successfully, overwriting existing files.")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"An error occurred while executing the command: {str(e)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred while executing the command: {str(e)}")
    def update_info(self, info):
        if info:
            for key, value in info.items():
                if key == "icon0":
                    pixmap = QPixmap()
                    pixmap.loadFromData(value)
                    self.image_label.setPixmap(pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            QMessageBox.information(self, "Information", "No information found in the PKG file.")

    def normalize_value(self, value):
        if isinstance(value, bytes):
            return binascii.hexlify(value).decode('utf-8')
        elif isinstance(value, int):
            return f"0x{value:X}" if value > 9 else str(value)
        else:
            return str(value)

    def normalize_output(self, output):
        lines = output.split('\n')
        normalized = []
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                normalized.append(f"{key.strip()}: {self.normalize_value(value.strip())}")
            else:
                normalized.append(line)
        return '\n'.join(normalized)

    def process_pkg(self):
        icon0 = False
        if self.package is not None:
            files_to_extract = [
                {"file_id": 0x1000, "filename": "param.sfo"},
                {"file_id": 0x1200, "filename": "icon0.png"}
            ]
            
            self.image_label.clear()
            script_dir = os.path.dirname(os.path.abspath(__file__))
            output_folder_path = os.path.join(script_dir, OUTPUT_FOLDER)
            os.makedirs(output_folder_path, exist_ok=True)

            for file_info in files_to_extract:
                file_id = file_info["file_id"]
                filename = file_info["filename"]

                output_file_path = os.path.join(output_folder_path, filename)

                try:
                    self.package.extract(file_id, output_file_path)
                    if filename == "icon0.png":
                        icon0 = True
                except ValueError as e:
                    pass
                
            if icon0:
                icon0_path = os.path.join(output_folder_path, "icon0.png")
                self.display_img(icon0_path)
            sfo_path = os.path.join(output_folder_path, "param.sfo")

            if os.path.exists(sfo_path):
                sfo_info = self.sfo_offset_map(sfo_path)
                self.update_tree_with_sfo_info(sfo_info)

            # Update hex section
            self.update_hex_view()

    def update_hex_view(self):
        if self.package:
            with open(self.package.original_file, 'rb') as f:
                hex_data = f.read(1024)  # Read first 1024 bytes
            hex_view = ' '.join([f'{b:02X}' for b in hex_data])
            self.hex_viewer.setPlainText(hex_view)
            self.hex_editor.setPlainText(hex_view)

    def display_img(self, image_path):
        pixmap = QPixmap(image_path)
        self.image_label.setPixmap(pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def sfo_offset_map(self, file_path):
        with open(file_path, 'rb') as file:
            sfo = file.read()

        offset1 = sfo.find(b"\x00VERSION") + 8
        data1 = sfo[offset1:offset1 + 14].decode("ascii", errors='ignore')

        offset2 = sfo.find(b"\x5F00-") - 20
        data2 = sfo[offset2:offset2 + 2].decode("ascii", errors='ignore')

        offset3 = sfo.find(b"\x5F00-") - 16
        data3 = sfo[offset3:offset3 + 36].decode("ascii", errors='ignore')

        offset4 = sfo.find(b"\x2Csdk_ver=") + 9
        data4 = sfo[offset4:offset4 + 8].decode("ascii", errors='ignore')
        data4 = data4[:2] + "." + data4[2:4]

        offset5 = sfo.find(b"\x00\x00\x00\x00CUSA") - 128
        data5 = sfo[offset5:offset5 + 64].decode("ascii", errors='ignore')
        data5 = re.sub(Hexpattern, '', data5)

        offset6 = sfo.find(b"\x5F00-") - 9
        data6 = sfo[offset6:offset6 + 9].decode("ascii", errors='ignore')

        offset7 = sfo.find(b"\x00c_date") + 1
        data7 = sfo[offset7:offset7 + 264].decode("ascii", errors='ignore')
        
        pkg_size_fmt = os.path.getsize(self.file_path)
        pkg_size_formatted = self.pkg_size_fmt(pkg_size_fmt)

        sfo_dict = {
            "APP_TYPE": data2,
            "CONTENT_ID": data3,
            "SDK_version": data4,
            "TITLE_ID": data6,
            "APP_VER": data1,
            "TITLE": data5,
            "PUBTOOLINFO": data7,
            "Size": pkg_size_formatted,
        }

        if data2 == "gd":
            sfo_dict.pop("SDK_version", None)
        elif data2 == "gp":
            sfo_dict.pop("SDK_version", None)
        elif data2 == "ac":
            sfo_dict.pop("SDK_version", None)
            sfo_dict.pop("APP_VER", None)
        
        if len(data5) <= 3:
            sfo_dict.pop("TITLE", None)
            sfo_dict.pop("SDK_version", None)

        return sfo_dict

    def update_tree_with_sfo_info(self, sfo_dict):
        self.tree.clear()
        for key, value in sfo_dict.items():
            out_data = re.sub(Hexpattern, '', value)
            if out_data == "gd":
                out_data = "Game(gd)"
            elif out_data == "gp":
                out_data = "Patch(gp)"
            elif out_data == "ac":
                out_data = "Addon(ac)"
        
            QTreeWidgetItem(self.tree, [key, out_data])

    def pkg_size_fmt(self, sbytes):
        size_fmt = ["bytes", "KB", "MB", "GB"]
        size_max = 1024

        for unit in size_fmt:
            if sbytes < size_max:
                return f"{sbytes:.2f} {unit}"
            sbytes /= size_max
        return f"{sbytes:.2f} {size_fmt[-1]}"

    def closeEvent(self, event):
        # Delete "_temp_output"
        output_folder_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUTPUT_FOLDER)
        shutil.rmtree(output_folder_path, ignore_errors=True)
        super().closeEvent(event)

    def search_hex(self):
        search_hex = self.search_entry.text()
        try:
            search_bytes = bytes.fromhex(search_hex)
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid hex search string")
            return
        
        with open(self.package.original_file, 'rb') as f:
            data = f.read()
        
        offset = data.find(search_bytes)
        if offset != -1:
            self.offset_entry.setText(f"{offset:X}")
            QMessageBox.information(self, "Search Result", f"Found at offset: 0x{offset:X}")
        else:
            QMessageBox.information(self, "Search Result", "Not found")

    def replace_hex(self):
        if not self.offset_entry.text():
            QMessageBox.critical(self, "Error", "No offset specified")
            return
        
        offset = int(self.offset_entry.text(), 16)
        replace_hex = self.replace_entry.text()
        try:
            replace_bytes = bytes.fromhex(replace_hex)
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid hex replace string")
            return
        
        with open(self.package.original_file, 'r+b') as f:
            f.seek(offset)
            f.write(replace_bytes)
        
        QMessageBox.information(self, "Replace", "Replacement completed")
        self.update_hex_view()

def start_gui(run_command_callback):
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Use Fusion style for a modern look
    window = PS4PKGTool()
    window.run_command_callback = run_command_callback
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    start_gui(lambda cmd, pkg, file, out, update_info: print(f"Command: {cmd}, PKG: {pkg}, File: {file}, Out: {out}"))