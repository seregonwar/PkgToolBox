from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTreeWidget, QTreeWidgetItem, QDialog, QMessageBox, QApplication)
from PyQt5.QtCore import Qt
from ..utils import FileUtils, ImageUtils

class WallpaperViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Tree view for wallpapers
        self.wallpaper_tree = QTreeWidget()
        self.wallpaper_tree.setHeaderLabels(["Name", "Size"])
        self.wallpaper_tree.itemClicked.connect(self.display_selected_wallpaper)
        layout.addWidget(self.wallpaper_tree)

        # Image viewer
        self.wallpaper_viewer = QLabel()
        self.wallpaper_viewer.setAlignment(Qt.AlignCenter)
        self.wallpaper_viewer.setStyleSheet(
            "background-color: white; border: 1px solid #3498db; border-radius: 5px;")
        self.wallpaper_viewer.setMinimumSize(300, 300)
        layout.addWidget(self.wallpaper_viewer)

        # Control buttons
        button_layout = QHBoxLayout()
        self.prev_button = QPushButton("Previous")
        self.next_button = QPushButton("Next")
        self.fullscreen_button = QPushButton("Fullscreen")
        
        for button in [self.prev_button, self.next_button, self.fullscreen_button]:
            button.setStyleSheet("""
                QPushButton {
                    font-size: 14px;
                    padding: 8px 15px;
                    background-color: #3498db;
                    color: white;
                    border: none;
                    border-radius: 5px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
            """)
        
        self.prev_button.clicked.connect(self.show_previous_wallpaper)
        self.next_button.clicked.connect(self.show_next_wallpaper)
        self.fullscreen_button.clicked.connect(self.show_fullscreen_wallpaper)
        
        button_layout.addWidget(self.prev_button)
        button_layout.addWidget(self.next_button)
        button_layout.addWidget(self.fullscreen_button)
        layout.addLayout(button_layout)

    def load_wallpapers(self, package):
        """Load wallpapers from package"""
        self.wallpaper_tree.clear()
        
        if not package:
            return
            
        wallpaper_files = [
            f for f in package.files.values() 
            if isinstance(f.get("name"), str) and 
            f["name"].lower().endswith(('.png', '.jpg', '.jpeg'))
        ]
        
        wallpaper_structure = {}
        for file_info in wallpaper_files:
            path_parts = file_info["name"].split('/')
            current_dict = wallpaper_structure
            
            for part in path_parts[:-1]:
                if part:
                    current_dict = current_dict.setdefault(part, {})
            
            if path_parts[-1]:
                current_dict[path_parts[-1]] = file_info
        
        def add_wallpaper_items(parent_item, structure):
            for name, content in sorted(structure.items()):
                if isinstance(content, dict):
                    if any(isinstance(v, dict) for v in content.values()):
                        folder_item = QTreeWidgetItem(parent_item)
                        folder_item.setText(0, name)
                        folder_item.setIcon(0, FileUtils.get_file_icon('Directory'))
                        add_wallpaper_items(folder_item, content)
                    else:
                        item = QTreeWidgetItem(parent_item)
                        item.setText(0, name)
                        item.setText(1, FileUtils.format_size(content['size']))
                        item.setIcon(0, FileUtils.get_file_icon('Image'))
                        item.setData(0, Qt.UserRole, content)
        
        add_wallpaper_items(self.wallpaper_tree.invisibleRootItem(), wallpaper_structure)
        self.wallpaper_tree.expandAll()

    def display_selected_wallpaper(self, item):
        """Display selected wallpaper"""
        try:
            file_info = item.data(0, Qt.UserRole)
            if not file_info:
                return
            
            # Get image data from package
            image_data = self.parent.package.read_file(file_info['id'])
            
            # Create thumbnail
            pixmap = ImageUtils.create_thumbnail(image_data)
            
            # Display image
            self.wallpaper_viewer.setPixmap(pixmap)
            self.wallpaper_viewer.setAlignment(Qt.AlignCenter)
            
        except Exception as e:
            self.wallpaper_viewer.clear()
            QMessageBox.warning(self.parent, "Error", f"Error displaying wallpaper: {str(e)}")

    def show_previous_wallpaper(self):
        """Show previous wallpaper in the list"""
        current_item = self.wallpaper_tree.currentItem()
        if current_item:
            current_index = self.wallpaper_tree.indexOfTopLevelItem(current_item)
            if current_index > 0:
                previous_item = self.wallpaper_tree.topLevelItem(current_index - 1)
                self.wallpaper_tree.setCurrentItem(previous_item)
                self.display_selected_wallpaper(previous_item)

    def show_next_wallpaper(self):
        """Show next wallpaper in the list"""
        current_item = self.wallpaper_tree.currentItem()
        if current_item:
            current_index = self.wallpaper_tree.indexOfTopLevelItem(current_item)
            if current_index < self.wallpaper_tree.topLevelItemCount() - 1:
                next_item = self.wallpaper_tree.topLevelItem(current_index + 1)
                self.wallpaper_tree.setCurrentItem(next_item)
                self.display_selected_wallpaper(next_item)

    def show_fullscreen_wallpaper(self):
        """Show wallpaper in fullscreen"""
        try:
            current_item = self.wallpaper_tree.currentItem()
            if not current_item:
                return
                
            file_info = current_item.data(0, Qt.UserRole)
            if not file_info:
                return
            
            # Get image data
            image_data = self.parent.package.read_file(file_info['id'])
            
            # Create fullscreen dialog
            dialog = QDialog(self.parent)
            dialog.setWindowTitle("Fullscreen Wallpaper")
            layout = QVBoxLayout(dialog)
            
            # Create label for image
            fullscreen_label = QLabel()
            fullscreen_label.setAlignment(Qt.AlignCenter)
            
            # Get screen size and scale image
            screen_size = QApplication.primaryScreen().size()
            image = ImageUtils.load_and_scale_image(image_data, max(screen_size.width(), screen_size.height()))
            pixmap = ImageUtils.convert_to_qpixmap(image)
            
            # Set scaled pixmap
            fullscreen_label.setPixmap(pixmap.scaled(screen_size, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            
            layout.addWidget(fullscreen_label)
            dialog.showFullScreen()
            
        except Exception as e:
            QMessageBox.critical(self.parent, "Error", f"Error showing fullscreen: {str(e)}")

    def clear_viewer(self):
        """Clear the wallpaper viewer"""
        self.wallpaper_viewer.clear()
        self.wallpaper_tree.clear()

    def get_current_wallpaper(self):
        """Get current wallpaper info"""
        current_item = self.wallpaper_tree.currentItem()
        if current_item:
            return current_item.data(0, Qt.UserRole)
        return None

    def set_enabled(self, enabled):
        """Enable/disable the viewer"""
        self.setEnabled(enabled)
        self.wallpaper_tree.setEnabled(enabled)
        self.wallpaper_viewer.setEnabled(enabled)
        self.prev_button.setEnabled(enabled)
        self.next_button.setEnabled(enabled)
        self.fullscreen_button.setEnabled(enabled)