"""
Info tab widget for displaying PKG information
"""
from PyQt5.QtWidgets import (QVBoxLayout, QTreeWidget, QTreeWidgetItem, 
                            QGroupBox, QLabel)
from PyQt5.QtCore import Qt
from .base_tab import BaseTab

class InfoTab(BaseTab):
    """Tab for displaying PKG information"""
    
    def setup_ui(self):
        """Setup the info tab UI"""
        # Main info group
        info_group = QGroupBox("Package Information")
        info_layout = QVBoxLayout()
        
        # Tree widget for displaying info
        self.info_tree = QTreeWidget()
        self.info_tree.setHeaderLabels(["Property", "Value", "Description"])
        self.info_tree.setAlternatingRowColors(True)
        self.info_tree.setRootIsDecorated(False)
        
        # Style the tree widget
        self.info_tree.setStyleSheet("""
            QTreeWidget {
                border: 1px solid #bdc3c7;
                border-radius: 6px;
                background-color: white;
                selection-background-color: #3498db;
            }
            QTreeWidget::item {
                padding: 8px;
                border-bottom: 1px solid #ecf0f1;
            }
            QTreeWidget::item:hover {
                background-color: #f8f9fa;
            }
            QTreeWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
            QHeaderView::section {
                background-color: #34495e;
                color: white;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)
        
        info_layout.addWidget(self.info_tree)
        info_group.setLayout(info_layout)
        
        # Add to main layout
        self.layout.addWidget(info_group)
        
    def update_info(self, info_dict):
        """Update info display with package information"""
        self.info_tree.clear()
        
        # Dictionary of descriptions for each key
        descriptions = {
            "pkg_magic": "Magic number identifying the PKG file format",
            "pkg_type": "Type of the PKG (e.g., 0x1 for PS4)",
            "pkg_file_count": "Number of files contained in the PKG",
            "pkg_entry_count": "Number of entries in the PKG table",
            "pkg_sc_entry_count": "Number of entries in the SC table",
            "pkg_entry_data_size": "Size of the entry data in bytes",
            "pkg_body_size": "Size of the PKG body in bytes",
            "pkg_content_id": "Unique identifier for the PKG content",
            "pkg_content_type": "Type of content in the PKG",
            "pkg_content_flags": "Flags describing the content",
            "pkg_promote_size": "Size of promotional content",
            "pkg_version_date": "Version date of the PKG",
            "pkg_version": "Package version",
            "pkg_revision": "PKG format revision",
            "title_id": "Title ID",
            "system_version": "Minimum required system version",
            "app_version": "Application version",
            "total_size": "Total package size",
            "pkg_size": "Package size",
            "install_directory": "Installation directory",
            "content_id": "Content ID",
        }
        
        # Add information to tree widget
        for key, value in info_dict.items():
            item = QTreeWidgetItem(self.info_tree)
            item.setText(0, str(key))
            item.setText(1, str(value))
            item.setText(2, descriptions.get(key, ""))
        
        # Resize columns to fit content
        self.info_tree.resizeColumnToContents(0)
        self.info_tree.resizeColumnToContents(1)
        self.info_tree.resizeColumnToContents(2)
