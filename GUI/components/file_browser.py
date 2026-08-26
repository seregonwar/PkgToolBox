from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget,
                            QLineEdit, QTreeWidgetItem, QMenu, QMessageBox, QFileDialog, 
                            QDialog, QVBoxLayout, QTextEdit, QLabel, QPushButton, QProgressBar,
                            QSlider, QFrame, QHeaderView)
from PySide6.QtCore import Qt, QThread, Signal, QUrl
from PySide6.QtWidgets import QSplitter, QTabWidget
from PySide6.QtGui import QFont, QIcon
from PySide6.QtMultimedia import QMediaPlayer, QAudioOutput
from ..utils import FileUtils, ImageUtils
import os
import queue

class FileLoadWorker(QThread):
    progress = Signal(int)
    finished = Signal()
    
    def __init__(self, package, file_structure):
        super().__init__()
        self.package = package
        self.file_structure = file_structure
        
    def run(self):
        # PS5 packages expose the PFS payloads (eboot.bin, sce_sys/keystone,
        # sce_sys/about/right.sprx, ...) alongside the CNT entries through
        # get_all_files(); every other package type uses the plain file table.
        all_files = (
            self.package.get_all_files()
            if hasattr(self.package, "get_all_files")
            else self.package.files
        )
        total = len(all_files)
        for i, (file_id, file_info) in enumerate(all_files.items()):
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
                
            self.progress.emit(int((i + 1) / total * 100) if total else 100)
            
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
    PREVIEW_LIMIT = 256 * 1024

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.file_queue = queue.Queue()
        self.preview_cache = {}
        self.media_player = QMediaPlayer()
        self.audio_output = QAudioOutput()
        self.media_player.setAudioOutput(self.audio_output)
        self.setup_ui()

    def add_file_item(self, parent_item, name, file_info):
        file_item = QTreeWidgetItem(parent_item)
        file_item.setText(0, name)
        file_item.setText(1, FileUtils.format_size(file_info['size']))
        file_item.setText(
            2,
            file_info.get("state")
            or ("Encrypted" if file_info.get("encrypted") else "Plaintext"),
        )
        file_item.setIcon(0, FileUtils.get_file_icon(name))
        file_item.setData(0, Qt.UserRole, file_info)
        return file_item
        
    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)
        
        # Two responsive rows avoid crushing the path and tree on compact
        # windows.
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        self.source_label = QLabel("No source loaded")
        self.source_label.setObjectName("browserSourceLabel")
        toolbar.addWidget(self.source_label)
        toolbar.addStretch(1)

        self.open_btn = QPushButton("Open file…")
        self.open_btn.setObjectName("secondaryButton")
        self.open_btn.setToolTip("Open a package, project or standalone file")
        self.open_btn.clicked.connect(self.parent.browse_pkg)
        toolbar.addWidget(self.open_btn)
        main_layout.addLayout(toolbar)

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.file_search = QLineEdit()
        self.file_search.setPlaceholderText("Search contents…")
        self.file_search.setClearButtonEnabled(True)
        self.file_search.setMinimumWidth(220)
        self.file_search.textChanged.connect(self.filter_files)
        controls.addWidget(self.file_search, 1)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setObjectName("secondaryButton")
        self.refresh_btn.clicked.connect(self.refresh_files)
        self.refresh_btn.setEnabled(False)
        controls.addWidget(self.refresh_btn)

        self.expand_btn = QPushButton("+")
        self.expand_btn.setObjectName("secondaryButton")
        self.expand_btn.setFixedWidth(36)
        self.expand_btn.setToolTip("Expand all folders")

        self.collapse_btn = QPushButton("−")
        self.collapse_btn.setObjectName("secondaryButton")
        self.collapse_btn.setFixedWidth(36)
        self.collapse_btn.setToolTip("Collapse all folders")
        
        # File tree
        self.file_tree = QTreeWidget()
        self.file_tree.setObjectName("contentTree")
        self.file_tree.setHeaderLabels(["Name", "Size", "Status"])
        self.file_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        for column in (1, 2):
            self.file_tree.header().setSectionResizeMode(column, QHeaderView.ResizeToContents)
        self.file_tree.setAlternatingRowColors(False)
        self.file_tree.setAnimated(True)
        self.file_tree.setIndentation(18)
        self.file_tree.setSortingEnabled(True)
        self.file_tree.setUniformRowHeights(True)
        self.file_tree.setFrameShape(QFrame.NoFrame)
        
        self.expand_btn.clicked.connect(self.file_tree.expandAll)
        self.collapse_btn.clicked.connect(self.file_tree.collapseAll)
        controls.addWidget(self.expand_btn)
        controls.addWidget(self.collapse_btn)
        main_layout.addLayout(controls)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        self.empty_state = QLabel(
            "Open a package, GP4/GP5 project or standalone file\n"
            "to browse its available contents."
        )
        self.empty_state.setObjectName("browserEmptyState")
        self.empty_state.setAlignment(Qt.AlignCenter)
        self.empty_state.setWordWrap(True)
        main_layout.addWidget(self.empty_state, 1)
        
        # Splitter for tree and preview
        self.splitter = QSplitter(Qt.Horizontal)
        
        self.file_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(self.show_context_menu)
        self.file_tree.itemSelectionChanged.connect(self.on_selection_changed)
        self.file_tree.itemDoubleClicked.connect(self.on_item_double_clicked)
        
        # Preview panel
        self.preview_tabs = QTabWidget()
        self.preview_tabs.setObjectName("contentPreview")
        
        # Add widgets to splitter — the preview (hex/text) gets the most room
        self.splitter.addWidget(self.file_tree)
        self.splitter.addWidget(self.preview_tabs)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setSizes([460, 500])
        self.preview_tabs.setMinimumWidth(320)
        self.splitter.hide()
        main_layout.addWidget(self.splitter, 1)
        
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
            self.clear()
            return

        info = package.get_info() if hasattr(package, "get_info") else {}
        source_name = (
            info.get("title_name") or info.get("title_id") or
            info.get("file_name") or os.path.basename(getattr(package, "original_file", "Source"))
        )
        count = len(package.get_all_files() if hasattr(package, "get_all_files") else package.files)
        self.source_label.setText(f"{source_name}  ·  {count} item(s)")
        self.refresh_btn.setEnabled(True)
        self.empty_state.hide()
        self.splitter.show()
        self.progress_bar.setVisible(True)
        file_structure = {}
        
        # Create and start worker thread. The finished signal carries a
        # reference to its own worker so a stale completion (from a previous
        # load_files() call still running in background) cannot double-add
        # the structure to the tree.
        self.worker = FileLoadWorker(package, file_structure)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(lambda w=self.worker: self.on_files_loaded(w))
        self.worker.start()
        
    def on_files_loaded(self, worker=None):
        # Ignore completions from superseded workers: their structure was
        # already replaced by a newer load_files() call.
        if worker is not None and worker is not self.worker:
            return
        # Clear again defensively: on_files_loaded may run after the tree was
        # repopulated by a newer worker in edge cases.
        self.file_tree.clear()

        def add_items(parent_item, structure, path=""):
            for name, content in sorted(structure.items()):
                if name == "_info":
                    continue
                if isinstance(content, dict):
                    if "_info" in content:  # Directory
                        folder_item = QTreeWidgetItem(parent_item)
                        folder_item.setText(0, name)
                        folder_item.setText(1, FileUtils.format_size(content["_info"]["size"]))
                        folder_item.setText(2, "Folder")
                        folder_item.setIcon(0, FileUtils.get_file_icon('Directory'))
                        folder_item.setData(0, Qt.UserRole, content["_info"])
                        
                        current_path = os.path.join(path, name) if path else name
                        add_items(folder_item, content, current_path)
                    else:  # File
                        self.add_file_item(parent_item, name, content)

        add_items(self.file_tree.invisibleRootItem(), self.worker.file_structure)
        # A full recursive expansion is overwhelming on real game projects;
        # reveal only the first level and let users drill down intentionally.
        root = self.file_tree.invisibleRootItem()
        for index in range(root.childCount()):
            root.child(index).setExpanded(True)
        self.progress_bar.setVisible(False)

        if not root.childCount():
            self.empty_state.setText("This source does not expose any browsable files.")
            self.empty_state.show()
            self.splitter.hide()

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
                lines = [
                    f"File Name: {item.text(0)}",
                    f"Size: {FileUtils.format_size(file_info['size'])}",
                    f"Type: {FileUtils.get_file_type(os.path.splitext(item.text(0))[1])}",
                    f"Path: {file_info['name']}",
                    f"State: {file_info.get('state') or ('Encrypted' if file_info.get('encrypted') else 'Plaintext')}",
                ]
                if file_info.get("source_path"):
                    lines.append(f"Source: {file_info.get('source_display', file_info['source_path'])}")
                else:
                    lines.append(f"Offset: 0x{file_info.get('offset', 0):X}")
                if FileUtils.get_file_type(os.path.splitext(item.text(0))[1]) == 'Image' and not file_info.get('encrypted'):
                    try:
                        image_info = self.parent.package.get_image_info(file_info['id'])
                        lines.extend([
                            f"Image format: {image_info.format}",
                            f"Dimensions: {image_info.width} × {image_info.height}",
                            f"Asset kind: {image_info.kind}",
                        ])
                    except Exception:
                        pass
                info_text.setPlainText("\n".join(lines))
                self.preview_tabs.addTab(info_widget, "Info")
                if file_info.get('encrypted') or file_info.get('present') is False:
                    return

                data = self.parent.package.read_file(file_info['id'])
                preview_data = data[:self.PREVIEW_LIMIT]
                truncated_note = (
                    f"\n\n— Preview limited to {FileUtils.format_size(self.PREVIEW_LIMIT)} "
                    f"of {FileUtils.format_size(len(data))} —"
                    if len(data) > self.PREVIEW_LIMIT else ""
                )
                
                # Content preview based on file type
                if FileUtils.is_text_file(item.text(0)):
                    text_content = preview_data.decode('utf-8', errors='replace') + truncated_note
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
                    self.media_player.setSource(QUrl.fromLocalFile(temp_file))
                    
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
                hex_view = ' '.join([f'{b:02X}' for b in preview_data]) + truncated_note
                hex_widget.setPlainText(hex_view)
                self.preview_tabs.addTab(hex_widget, "Hex View")
            
            info_layout.addWidget(info_text)
            if file_info.get("is_dir"):
                self.preview_tabs.addTab(info_widget, "Info")
            
        except Exception as e:
            error_widget = QLabel(f"Error loading preview: {str(e)}")
            self.preview_tabs.addTab(error_widget, "Error")

    def toggle_playback(self):
        if self.media_player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self.media_player.pause()
        else:
            self.media_player.play()

    def show_context_menu(self, position):
        # Parent the menu so it inherits the app stylesheet, and apply the
        # theme colors explicitly: a parentless QMenu does not receive the
        # MainWindow stylesheet and its text becomes unreadable.
        menu = QMenu(self)
        self._style_menu(menu)
        
        extract_action = menu.addAction(QIcon.fromTheme("document-save"), "Extract")
        hex_view_action = menu.addAction(QIcon.fromTheme("text-x-hex"), "View as Hex")
        text_view_action = menu.addAction(QIcon.fromTheme("text-plain"), "View as Text")

        selected = self.file_tree.itemAt(position)
        if selected is not None:
            self.file_tree.setCurrentItem(selected)
        info = selected.data(0, Qt.UserRole) if selected else None
        readable = bool(info and not info.get("is_dir") and info.get("present", True))
        extract_action.setEnabled(readable)
        hex_view_action.setEnabled(readable)
        text_view_action.setEnabled(
            readable and FileUtils.is_text_file(selected.text(0) if selected else "")
        )
        
        extract_action.triggered.connect(self.extract_selected_file)
        hex_view_action.triggered.connect(self.view_file_as_hex)
        text_view_action.triggered.connect(self.view_file_as_text)
        
        menu.exec(self.file_tree.viewport().mapToGlobal(position))

    def _style_menu(self, menu):
        """Applica i colori del tema attivo al menu contestuale."""
        try:
            from GUI.utils import StyleManager
            settings = StyleManager.load_settings()
            appearance = settings.get("appearance", {})
            theme_name = appearance.get("theme", "Dark")
            colors = appearance.get("colors", {})
            tc = StyleManager.get_theme_colors(
                theme_name, colors if theme_name == "Custom" else None
            )
        except Exception:
            return
        menu.setStyleSheet(f"""
            QMenu {{
                background-color: {tc['background']};
                color: {tc['text']};
                border: 1px solid {tc['border']};
                border-radius: 6px;
                padding: 4px;
            }}
            QMenu::item {{
                color: {tc['text']};
                padding: 6px 28px 6px 10px;
                border-radius: 4px;
            }}
            QMenu::item:selected {{
                background-color: {tc['selection']};
                color: #ffffff;
            }}
            QMenu::item:disabled {{
                color: {tc['secondary_text']};
            }}
            QMenu::separator {{
                background-color: {tc['border']};
                height: 1px;
                margin: 4px 8px;
            }}
        """)

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
            preview = data[:8 * 1024 * 1024]
            hex_view = ' '.join([f'{b:02X}' for b in preview])
            if len(data) > len(preview):
                hex_view += (
                    f"\n\n— View limited to {FileUtils.format_size(len(preview))} "
                    f"of {FileUtils.format_size(len(data))} —"
                )
            
            dialog = QDialog(self.parent)
            dialog.setWindowTitle(f"Hex View - {item.text(0)}")
            dialog.resize(800, 600)
            
            layout = QVBoxLayout(dialog)
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setFont(QFont("Courier", 10))
            text_edit.setPlainText(hex_view)
            # Colors come from the active theme
            
            layout.addWidget(text_edit)
            dialog.exec()
            
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
            preview = data[:8 * 1024 * 1024]
            text_content = preview.decode('utf-8', errors='replace')
            if len(data) > len(preview):
                text_content += (
                    f"\n\n— View limited to {FileUtils.format_size(len(preview))} "
                    f"of {FileUtils.format_size(len(data))} —"
                )
            
            dialog = QDialog(self.parent)
            dialog.setWindowTitle(f"Text View - {item.text(0)}")
            dialog.resize(800, 600)
            
            layout = QVBoxLayout(dialog)
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setPlainText(text_content)
            # Colors come from the active theme
            
            layout.addWidget(text_edit)
            dialog.exec()
            
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
                dialog.exec()
                
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
        self.source_label.setText("No source loaded")
        self.refresh_btn.setEnabled(False)
        self.progress_bar.hide()
        self.splitter.hide()
        self.empty_state.setText(
            "Open a package, GP4/GP5 project or standalone file\n"
            "to browse its available contents."
        )
        self.empty_state.show()
