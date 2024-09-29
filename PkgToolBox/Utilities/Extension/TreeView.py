from PyQt5.QtWidgets import QTreeWidgetItem

class TreeView:
    @staticmethod
    def get_all_nodes(node):
        list_nodes = [node]
        for i in range(node.childCount()):
            list_nodes.extend(TreeView.get_all_nodes(node.child(i)))
        return list_nodes