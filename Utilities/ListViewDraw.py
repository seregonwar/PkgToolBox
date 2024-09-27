from PyQt5.QtWidgets import QTreeWidget, QTreeWidgetItem
from PyQt5.QtGui import QColor, QBrush

class ListViewDraw:
    @staticmethod
    def color_list_view_header(tree_widget, back_color, fore_color):
        for i in range(tree_widget.columnCount()):
            tree_widget.headerItem().setBackground(i, QBrush(back_color))
            tree_widget.headerItem().setForeground(i, QBrush(fore_color))