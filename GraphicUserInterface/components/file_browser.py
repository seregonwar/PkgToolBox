from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget,
                            QLineEdit, QTreeWidgetItem, QMenu, QMessageBox, QFileDialog, 
                            QDialog, QVBoxLayout, QTextEdit, QLabel, QPushButton, QProgressBar,
                            QSlider)
from PyQt5.QtCore import Qt, QSize, QThread, pyqtSignal, QUrl
from PyQt5.QtWidgets import QStyle, QSplitter, QTabWidget
from PyQt5.QtGui import QFont, QIcon, QPixmap
from PyQt5.QtMultimedia import QMediaPlayer, QMediaContent
from ..utils import FileUtils, ImageUtils
import os
import threading
import queue
import time

class FileLoadWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal()
    
    def __init__(self, package, file_structure):
        super().__init__()
        self.package = package
        self.file_structure = file_structure
        
    def run(self):
        total = len(self.package.files)
        for i, (file_id, file_info) in enumerate(self.package.files.items()):
            if not file_info.get("name"):
                continue
                
            file_path = file_info["name"]
            path_parts = file_path.split('/')
            
            current_dict = self.file_structure
            
            # Build directory structure
            current_path = ""
            for part in path_parts[:-1]:
                if part:
                    current_path = os.path.join(current_path, part) if current_path else part
                    if part not in current_dict:
                        current_dict[part] = {
                            "_info": {
                                "is_dir": True,
                                "path": current_path,
                                "size": 0,
                                "files": [],
                                "subdirs": []
                            }
                        }
                    current_dict = current_dict[part]
            
            # Add file to structure
            if path_parts[-1]:
                current_dict[path_parts[-1]] = file_info
                # Update parent directory info
                parent_dict = self.file_structure
                for part in path_parts[:-1]:
                    if part:
                        parent_dict[part]["_info"]["size"] += file_info["size"]
                        if path_parts[-1] not in parent_dict[part]["_info"]["files"]:
                            parent_dict[part]["_info"]["files"].append(path_parts[-1])
                        parent_dict = parent_dict[part]
                
            self.progress.emit(int((i+1)/total * 100))
            
        # Update subdirs info
        def update_subdirs(structure):
            for name, content in structure.items():
                if isinstance(content, dict) and "_info" in content:
                    parent_subdirs = []
                    for key in content.keys():
                        if key != "_info" and isinstance(content[key], dict) and "_info" in content[key]:
                            parent_subdirs.append(key)
                    content["_info"]["subdirs"] = parent_subdirs
                    update_subdirs(content)
                    
        update_subdirs(self.file_structure)
        self.finished.emit()

class FileBrowser(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.file_queue = queue.Queue()
        self.preview_cache = {}
        self.media_player = QMediaPlayer()
        self.setup_ui()

    def add_file_item(self, parent_item, name, file_info):
        file_item = QTreeWidgetItem(parent_item)
        file_item.setText(0, name)
        file_item.setText(1, FileUtils.format_size(file_info['size']))
        file_item.setText(2, FileUtils.get_file_type(os.path.splitext(name)[1]))
        file_item.setIcon(0, FileUtils.get_file_icon(name))
        file_item.setData(0, Qt.UserRole, file_info)
        return file_item
        
    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        # Search bar with icon
        search_layout = QHBoxLayout()
        self.file_search = QLineEdit()
        self.file_search.setPlaceholderText("🔍 Search files...")
        self.file_search.textChanged.connect(self.filter_files)
        self.file_search.setStyleSheet("""
            QLineEdit {
                padding: 8px 12px;
                border: 2px solid #3498db;
                border-radius: 18px;
                font-size: 14px;
                background: #f8f9fa;
            }
            QLineEdit:focus {
                border-color: #2980b9;
                background: white;
            }
        """)
        
        # Action buttons
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_files)
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                padding: 8px 15px;
                border-radius: 15px;
                background: #3498db;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #2980b9;
            }
        """)
        
        # File tree
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Size", "Type"])
        self.file_tree.setColumnWidth(0, 400)
        self.file_tree.setColumnWidth(1, 100)
        self.file_tree.setColumnWidth(2, 100)
        self.file_tree.setAlternatingRowColors(True)
        self.file_tree.setAnimated(True)
        self.file_tree.setIndentation(20)
        self.file_tree.setSortingEnabled(True)
        self.file_tree.setStyleSheet("""
            QTreeWidget {
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                background-color: white;
            }
            QTreeWidget::item:hover {
                background-color: #e8f6ff;
            }
            QTreeWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
        """)
        
        self.expand_btn = QPushButton("Expand All")
        self.expand_btn.clicked.connect(self.file_tree.expandAll)
        self.expand_btn.setStyleSheet(self.refresh_btn.styleSheet())
        
        self.collapse_btn = QPushButton("Collapse All") 
        self.collapse_btn.clicked.connect(self.file_tree.collapseAll)
        self.collapse_btn.setStyleSheet(self.refresh_btn.styleSheet())
        
        toolbar.addWidget(self.file_search)
        toolbar.addWidget(self.refresh_btn)
        toolbar.addWidget(self.expand_btn)
        toolbar.addWidget(self.collapse_btn)
        
        main_layout.addLayout(toolbar)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #3498db;
            }
        """)
        main_layout.addWidget(self.progress_bar)
        
        # Splitter for tree and preview
        splitter = QSplitter(Qt.Horizontal)
        
        self.file_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(self.show_context_menu)
        self.file_tree.itemSelectionChanged.connect(self.on_selection_changed)
        self.file_tree.itemDoubleClicked.connect(self.on_item_double_clicked)
        
        # Preview panel
        self.preview_tabs = QTabWidget()
        self.preview_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #bdc3c7;
                border-radius: 5px;
            }
            QTabBar::tab {
                padding: 8px 12px;
                margin: 2px;
            }
            QTabBar::tab:selected {
                background: #3498db;
                color: white;
            }
        """)
        
        # Add widgets to splitter
        splitter.addWidget(self.file_tree)
        splitter.addWidget(self.preview_tabs)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        
        main_layout.addWidget(splitter)
        
    def filter_files(self):
        search_text = self.file_search.text().lower()
        
        def filter_item(item):
            should_show = not search_text or search_text in item.text(0).lower()
            
            if item.childCount() > 0:
                for i in range(item.childCount()):
                    child = item.child(i)
                    child_visible = filter_item(child)
                    should_show = should_show or child_visible
            
            item.setHidden(not should_show)
            return should_show
        
        root = self.file_tree.invisibleRootItem()
        for i in range(root.childCount()):
            filter_item(root.child(i))

    def load_files(self, package):
        """Load files from package into tree view"""
        self.file_tree.clear()
        self.preview_tabs.clear()
        
        if not package:
            return
            
        self.progress_bar.setVisible(True)
        file_structure = {}
        
        # Create and start worker thread
        self.worker = FileLoadWorker(package, file_structure)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_files_loaded)
        self.worker.finished.connect(lambda: self.progress_bar.setVisible(False))
        self.worker.start()
        
    def on_files_loaded(self):
        def add_items(parent_item, structure, path=""):
            for name, content in sorted(structure.items()):
                if isinstance(content, dict):
                    if "_info" in content:  # Directory
                        folder_item = QTreeWidgetItem(parent_item)
                        folder_item.setText(0, name)
                        folder_item.setText(1, FileUtils.format_size(content["_info"]["size"]))
                        folder_item.setText(2, "Directory")
                        folder_item.setIcon(0, FileUtils.get_file_icon('Directory'))
                        folder_item.setData(0, Qt.UserRole, content["_info"])
                        
                        current_path = os.path.join(path, name) if path else name
                        add_items(folder_item, content, current_path)
                    else:  # File
                        self.add_file_item(parent_item, name, content)

        add_items(self.file_tree.invisibleRootItem(), self.worker.file_structure)
        self.file_tree.expandAll()

    def refresh_files(self):
        if self.parent and self.parent.package:
            self.load_files(self.parent.package)

    def on_selection_changed(self):
        selected_items = self.file_tree.selectedItems()
        if not selected_items:
            return
            
        item = selected_items[0]
        file_info = item.data(0, Qt.UserRole)
        
        if not file_info:
            return
            
        self.update_preview(item, file_info)
        
    def update_preview(self, item, file_info):
        self.preview_tabs.clear()
        
        try:
            # Info tab
            info_widget = QWidget()
            info_layout = QVBoxLayout(info_widget)
            info_text = QTextEdit()
            info_text.setReadOnly(True)
            
            if file_info.get("is_dir"):
                info_text.setPlainText(f"""
                Directory Name: {item.text(0)}
                Total Size: {FileUtils.format_size(file_info['size'])}
                Files: {len(file_info['files'])}
                Subdirectories: {len(file_info['subdirs'])}
                Path: {file_info['path']}
                """)
            else:
                data = self.parent.package.read_file(file_info['id'])
                info_text.setPlainText(f"""
                File Name: {item.text(0)}
                Size: {FileUtils.format_size(file_info['size'])}
                Type: {FileUtils.get_file_type(os.path.splitext(item.text(0))[1])}
                Path: {file_info['name']}
                """)
                
                # Content preview based on file type
                if FileUtils.is_text_file(item.text(0)):
                    text_content = data.decode('utf-8', errors='replace')
                    text_widget = QTextEdit()
                    text_widget.setReadOnly(True)
                    text_widget.setPlainText(text_content)
                    self.preview_tabs.addTab(text_widget, "Text View")
                    
                elif FileUtils.get_file_type(os.path.splitext(item.text(0))[1]) == 'Image':
                    pixmap = ImageUtils.create_thumbnail(data)
                    image_label = QLabel()
                    image_label.setPixmap(pixmap)
                    image_label.setAlignment(Qt.AlignCenter)
                    self.preview_tabs.addTab(image_label, "Image Preview")
                    
                elif FileUtils.get_file_type(os.path.splitext(item.text(0))[1]) == 'Audio':
                    # Audio player widget
                    audio_widget = QWidget()
                    audio_layout = QVBoxLayout(audio_widget)
                    
                    # Create temporary file for audio playback
                    temp_file = os.path.join(os.path.dirname(__file__), "temp_audio")
                    with open(temp_file, "wb") as f:
                        f.write(data)
                        
                    # Set up media player
                    self.media_player.setMedia(QMediaContent(QUrl.fromLocalFile(temp_file)))
                    
                    # Add controls
                    play_btn = QPushButton("Play/Pause")
                    play_btn.clicked.connect(self.toggle_playback)
                    
                    # Add slider for seeking
                    seek_slider = QSlider(Qt.Horizontal)
                    seek_slider.setRange(0, self.media_player.duration())
                    seek_slider.sliderMoved.connect(self.media_player.setPosition)
                    
                    audio_layout.addWidget(play_btn)
                    audio_layout.addWidget(seek_slider)
                    
                    self.preview_tabs.addTab(audio_widget, "Audio Player")
                    
                # Hex view for files
                hex_widget = QTextEdit()
                hex_widget.setReadOnly(True)
                hex_widget.setFont(QFont("Courier"))
                hex_view = ' '.join([f'{b:02X}' for b in data])
                hex_widget.setPlainText(hex_view)
                self.preview_tabs.addTab(hex_widget, "Hex View")
            
            info_layout.addWidget(info_text)
            self.preview_tabs.addTab(info_widget, "Info")
            
        except Exception as e:
            error_widget = QLabel(f"Error loading preview: {str(e)}")
            self.preview_tabs.addTab(error_widget, "Error")

    def toggle_playback(self):
        if self.media_player.state() == QMediaPlayer.PlayingState:
            self.media_player.pause()
        else:
            self.media_player.play()

    def show_context_menu(self, position):
        menu = QMenu()
        menu.setStyleSheet("""
            QMenu {
                background-color: white;
                border: 1px solid #bdc3c7;
            }
            QMenu::item {
                padding: 5px 20px;
            }
            QMenu::item:selected {
                background-color: #3498db;
                color: white;
            }
        """)
        
        extract_action = menu.addAction(QIcon.fromTheme("document-save"), "Extract")
        hex_view_action = menu.addAction(QIcon.fromTheme("text-x-hex"), "View as Hex")
        text_view_action = menu.addAction(QIcon.fromTheme("text-plain"), "View as Text")
        
        extract_action.triggered.connect(self.extract_selected_file)
        hex_view_action.triggered.connect(self.view_file_as_hex)
        text_view_action.triggered.connect(self.view_file_as_text)
        
        menu.exec_(self.file_tree.viewport().mapToGlobal(position))

    def extract_selected_file(self):
        selected_items = self.file_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self.parent, "Warning", "No file selected")
            return
            
        item = selected_items[0]
        file_info = item.data(0, Qt.UserRole)
        
        if not file_info:
            return
            
        output_path, _ = QFileDialog.getSaveFileName(
            self.parent,
            "Save File",
            item.text(0)
        )
        
        if not output_path:
            return
            
        try:
            data = self.parent.package.read_file(file_info['id'])
            with open(output_path, 'wb') as f:
                f.write(data)
            QMessageBox.information(self.parent, "Success", f"File extracted to: {output_path}")
            
        except Exception as e:
            QMessageBox.critical(self.parent, "Error", f"Error extracting file: {str(e)}")

    def view_file_as_hex(self):
        selected_items = self.file_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self.parent, "Warning", "No file selected")
            return
            
        item = selected_items[0]
        file_info = item.data(0, Qt.UserRole)
        
        if not file_info:
            return
            
        try:
            data = self.parent.package.read_file(file_info['id'])
            hex_view = ' '.join([f'{b:02X}' for b in data])
            
            dialog = QDialog(self.parent)
            dialog.setWindowTitle(f"Hex View - {item.text(0)}")
            dialog.resize(800, 600)
            
            layout = QVBoxLayout(dialog)
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setFont(QFont("Courier", 10))
            text_edit.setPlainText(hex_view)
            text_edit.setStyleSheet("background-color: #f8f9fa;")
            
            layout.addWidget(text_edit)
            dialog.exec_()
            
        except Exception as e:
            QMessageBox.critical(self.parent, "Error", f"Error viewing file: {str(e)}")

    def view_file_as_text(self):
        selected_items = self.file_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self.parent, "Warning", "No file selected")
            return
            
        item = selected_items[0]
        file_info = item.data(0, Qt.UserRole)
        
        if not file_info:
            return
            
        if not FileUtils.is_text_file(item.text(0)):
            QMessageBox.warning(self.parent, "Warning", "Selected file is not a text file")
            return
            
        try:
            data = self.parent.package.read_file(file_info['id'])
            text_content = data.decode('utf-8', errors='replace')
            
            dialog = QDialog(self.parent)
            dialog.setWindowTitle(f"Text View - {item.text(0)}")
            dialog.resize(800, 600)
            
            layout = QVBoxLayout(dialog)
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setPlainText(text_content)
            text_edit.setStyleSheet("background-color: white;")
            
            layout.addWidget(text_edit)
            dialog.exec_()
            
        except Exception as e:
            QMessageBox.critical(self.parent, "Error", f"Error viewing file: {str(e)}")

    def on_item_double_clicked(self, item, column):
        file_info = item.data(0, Qt.UserRole)
        if not file_info:
            return
            
        if FileUtils.is_text_file(item.text(0)):
            self.view_file_as_text()
        elif FileUtils.get_file_type(os.path.splitext(item.text(0))[1]) == 'Image':
            try:
                data = self.parent.package.read_file(file_info['id'])
                pixmap = ImageUtils.create_thumbnail(data)
                
                dialog = QDialog(self.parent)
                dialog.setWindowTitle(f"Preview - {item.text(0)}")
                dialog.resize(800, 600)
                
                layout = QVBoxLayout(dialog)
                label = QLabel()
                label.setPixmap(pixmap.scaled(
                    dialog.size(),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation
                ))
                label.setAlignment(Qt.AlignCenter)
                
                layout.addWidget(label)
                dialog.exec_()
                
            except Exception as e:
                QMessageBox.critical(self.parent, "Error", f"Error showing preview: {str(e)}")
        else:
            self.view_file_as_hex()

    def clear(self):
        """Clear the file browser"""
        self.file_tree.clear()
        self.file_search.clear()
        self.preview_tabs.clear()
        self.preview_cache.clear()
