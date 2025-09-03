"""
Dump tab widget for PKG dumping functionality
"""
from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                            QPushButton, QTextEdit, QFileDialog, QMessageBox,
                            QGroupBox)
from PyQt5.QtCore import Qt
from .base_tab import BaseTab
from packages import PackagePS4
from Utilities import Logger

class DumpTab(BaseTab):
    """Tab for PKG dump operations"""
    
    def setup_ui(self):
        """Setup the dump tab UI"""
        # Output directory selection
        output_group = QGroupBox("Output Directory")
        output_layout = QVBoxLayout()
        
        dir_layout = QHBoxLayout()
        self.dump_out_entry = QLineEdit()
        self.dump_out_entry.setPlaceholderText("Select output directory")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_output_directory)
        
        dir_layout.addWidget(self.dump_out_entry)
        dir_layout.addWidget(browse_button)
        output_layout.addLayout(dir_layout)
        output_group.setLayout(output_layout)
        
        # Dump button
        self.dump_button = QPushButton("Dump PKG")
        self.dump_button.clicked.connect(self.dump_pkg)
        self.dump_button.setStyleSheet("""
            QPushButton {
                background-color: #9b59b6;
                color: white;
                font-weight: bold;
                padding: 12px;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #8e44ad;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
        
        # Log display
        log_group = QGroupBox("Dump Log")
        log_layout = QVBoxLayout()
        self.dump_log = QTextEdit()
        self.dump_log.setReadOnly(True)
        self.dump_log.setMaximumHeight(200)
        log_layout.addWidget(self.dump_log)
        log_group.setLayout(log_layout)
        
        # Add to main layout
        self.layout.addWidget(output_group)
        self.layout.addWidget(self.dump_button)
        self.layout.addWidget(log_group)
        self.layout.addStretch()
        
    def browse_output_directory(self):
        """Browse for output directory"""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory"
        )
        if directory:
            self.dump_out_entry.setText(directory)
            
    def dump_pkg(self):
        """Dump PKG contents"""
        package = self.get_package()
        if not package:
            QMessageBox.warning(self, "Warning", "Please load a PKG file first")
            return

        output_dir = self.dump_out_entry.text()
        if not output_dir:
            QMessageBox.warning(self, "Warning", "Please select an output directory")
            return

        try:
            self.dump_button.setEnabled(False)
            self.dump_log.append(f"[+] Starting dump to: {output_dir}")
            
            # For PS4 use shadPKG; fallback to dump
            if isinstance(package, PackagePS4):
                try:
                    result = package.extract_via_shadpkg(output_dir)
                    self.dump_log.append(f"[+] shadPKG dump: {result}")
                except Exception as e:
                    Logger.log_warning(f"shadPKG failed from UI dump, fallback to dump: {e}")
                    self.dump_log.append(f"[-] shadPKG failed, using internal dump: {e}")
                    result = package.dump(output_dir)
                    self.dump_log.append(f"[+] Internal dump: {result}")
            else:
                result = package.dump(output_dir)
                self.dump_log.append(f"[+] Dump completed: {result}")

            QMessageBox.information(self, "Success", "PKG dumped successfully")
            
        except Exception as e:
            error_msg = f"Failed to dump PKG: {str(e)}"
            self.dump_log.append(f"[-] {error_msg}")
            QMessageBox.critical(self, "Error", error_msg)
        finally:
            self.dump_button.setEnabled(True)
