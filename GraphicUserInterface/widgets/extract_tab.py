"""
Extract tab widget for PKG extraction functionality
"""
from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                            QPushButton, QTextEdit, QFileDialog, QMessageBox,
                            QGroupBox)
from PyQt5.QtCore import Qt
from .base_tab import BaseTab
from packages import PackagePS4
from Utilities import Logger

class ExtractTab(BaseTab):
    """Tab for PKG extraction operations"""
    
    def setup_ui(self):
        """Setup the extract tab UI"""
        # Output directory selection
        output_group = QGroupBox("Output Directory")
        output_layout = QVBoxLayout()
        
        dir_layout = QHBoxLayout()
        self.extract_out_entry = QLineEdit()
        self.extract_out_entry.setPlaceholderText("Select output directory")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_output_directory)
        
        dir_layout.addWidget(self.extract_out_entry)
        dir_layout.addWidget(browse_button)
        output_layout.addLayout(dir_layout)
        output_group.setLayout(output_layout)

        # Extract button
        self.extract_button = QPushButton("Extract PKG")
        self.extract_button.clicked.connect(self.extract_pkg)
        self.extract_button.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                font-weight: bold;
                padding: 12px;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #2ecc71;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
        
        # Log display
        log_group = QGroupBox("Extraction Log")
        log_layout = QVBoxLayout()
        self.extract_log = QTextEdit()
        self.extract_log.setReadOnly(True)
        self.extract_log.setMaximumHeight(200)
        log_layout.addWidget(self.extract_log)
        log_group.setLayout(log_layout)
        
        # Add to main layout
        self.layout.addWidget(output_group)
        self.layout.addWidget(self.extract_button)
        self.layout.addWidget(log_group)
        self.layout.addStretch()
        
    def browse_output_directory(self):
        """Browse for output directory"""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory"
        )
        if directory:
            self.extract_out_entry.setText(directory)
            
    def extract_pkg(self):
        """Extract PKG contents"""
        package = self.get_package()
        if not package:
            QMessageBox.warning(self, "Warning", "Please load a PKG file first")
            return

        output_dir = self.extract_out_entry.text()
        if not output_dir:
            QMessageBox.warning(self, "Warning", "Please select an output directory")
            return

        try:
            self.extract_button.setEnabled(False)
            self.extract_log.append(f"[+] Starting extraction to: {output_dir}")
            
            # Force use shadPKG for PS4; fallback to internal dump on error
            if isinstance(package, PackagePS4):
                try:
                    result = package.extract_via_shadpkg(output_dir)
                    self.extract_log.append(f"[+] shadPKG extraction: {result}")
                except Exception as e:
                    Logger.log_warning(f"shadPKG failed from UI extract, fallback to dump: {e}")
                    self.extract_log.append(f"[-] shadPKG failed, using internal extraction: {e}")
                    result = package.dump(output_dir)
                    self.extract_log.append(f"[+] Internal extraction: {result}")
            else:
                result = package.dump(output_dir)
                self.extract_log.append(f"[+] Extraction completed: {result}")

            QMessageBox.information(self, "Success", "PKG extracted successfully")
            
        except Exception as e:
            error_msg = f"Failed to extract PKG: {str(e)}"
            self.extract_log.append(f"[-] {error_msg}")
            QMessageBox.critical(self, "Error", error_msg)
        finally:
            self.extract_button.setEnabled(True)

