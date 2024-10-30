from PyQt5.QtWidgets import QTreeWidget, QTreeWidgetItem
from PyQt5.QtCore import Qt

class CustomTreeWidget(QTreeWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the custom tree widget"""
        # Set basic properties
        self.setAlternatingRowColors(True)
        self.setAnimated(True)
        self.setIndentation(20)
        self.setSortingEnabled(True)
        self.setExpandsOnDoubleClick(True)
        
        # Style
        self.setStyleSheet("""
            QTreeWidget {
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                padding: 5px;
            }
            QTreeWidget::item {
                padding: 5px;
                border-bottom: 1px solid #ecf0f1;
            }
            QTreeWidget::item:hover {
                background-color: #e8f0fe;
            }
            QTreeWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
            QTreeWidget::branch:has-siblings:!adjoins-item {
                border-image: url(vline.png) 0;
            }
            QTreeWidget::branch:has-siblings:adjoins-item {
                border-image: url(branch-more.png) 0;
            }
            QTreeWidget::branch:!has-children:!has-siblings:adjoins-item {
                border-image: url(branch-end.png) 0;
            }
        """)

    def add_root_item(self, text, data=None):
        """Add a root level item"""
        item = QTreeWidgetItem(self)
        item.setText(0, text)
        if data:
            item.setData(0, Qt.UserRole, data)
        return item

    def add_child_item(self, parent, text, data=None):
        """Add a child item to parent"""
        item = QTreeWidgetItem(parent)
        item.setText(0, text)
        if data:
            item.setData(0, Qt.UserRole, data)
        return item

    def get_selected_data(self):
        """Get data from selected item"""
        selected = self.selectedItems()
        if selected:
            return selected[0].data(0, Qt.UserRole)
        return None