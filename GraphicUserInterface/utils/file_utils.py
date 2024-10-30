import os
from PyQt5.QtCore import QSize

class FileUtils:
    @staticmethod
    def format_size(size):
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    @staticmethod
    def get_file_type(extension):
        """Get file type based on extension"""
        type_map = {
            '.png': 'Image',
            '.jpg': 'Image', 
            '.jpeg': 'Image',
            '.bin': 'Binary',
            '.self': 'Executable',
            '.sprx': 'System Plugin',
            '.rco': 'Resource',
            '.sfo': 'System File',
            '.ac3': 'Audio',
            '.at3': 'Audio',
            '.txt': 'Text',
            '.xml': 'XML',
            '.json': 'JSON',
            '.pkg': 'Package'
        }
        return type_map.get(extension.lower(), 'Unknown')

    @staticmethod
    def is_text_file(filename):
        """Check if file is text based on extension"""
        text_extensions = ['.txt', '.xml', '.json', '.cfg', '.ini', '.log']
        return any(filename.lower().endswith(ext) for ext in text_extensions)

    @staticmethod
    def get_file_icon(file_type):
        """Get appropriate icon for file type"""
        from PyQt5.QtWidgets import QStyle, QApplication
        style = QApplication.style()
        
        icon_map = {
            'Image': style.standardIcon(QStyle.SP_FileIcon),
            'Executable': style.standardIcon(QStyle.SP_FileLinkIcon),
            'Directory': style.standardIcon(QStyle.SP_DirIcon)
        }
        return icon_map.get(file_type, style.standardIcon(QStyle.SP_FileIcon))