"""
Bruteforce tab widget for PS4 passcode bruteforcing functionality
"""
import os
import logging
from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                            QPushButton, QTextEdit, QGroupBox, QSpinBox,
                            QListWidget, QMessageBox)
from PyQt5.QtCore import Qt, QThread, QObject, pyqtSignal
from .base_tab import BaseTab
from tools.PS4_Passcode_Bruteforcer import PS4PasscodeBruteforcer
import re

class BruteforceTab(BaseTab):
    """Tab for PS4 passcode bruteforcing operations"""
    
    def setup_ui(self):
        """Setup the bruteforce tab UI"""
        # Output directory selection
        output_group = QGroupBox("Output Directory")
        output_layout = QVBoxLayout()
        
        output_dir_layout = QHBoxLayout()
        self.bruteforce_out_entry = QLineEdit()
        self.bruteforce_out_entry.setPlaceholderText("Select output directory")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_output_directory)
        
        output_dir_layout.addWidget(self.bruteforce_out_entry)
        output_dir_layout.addWidget(browse_button)
        output_layout.addLayout(output_dir_layout)
        output_group.setLayout(output_layout)
        
        # Passcode input group
        passcode_group = QGroupBox("Passcode Operations")
        passcode_layout = QVBoxLayout()
        
        # Manual passcode input
        manual_layout = QHBoxLayout()
        self.passcode_entry = QLineEdit()
        self.passcode_entry.setPlaceholderText("Enter 32-character passcode (optional)")
        self.passcode_entry.setMaxLength(32)
        manual_layout.addWidget(self.passcode_entry)
        
        # Try passcode button
        try_button = QPushButton("Try Passcode")
        try_button.clicked.connect(self.try_manual_passcode)
        try_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                font-weight: bold;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        manual_layout.addWidget(try_button)
        passcode_layout.addLayout(manual_layout)
        
        # Control layout for threads, seed, and buttons
        control_layout = QHBoxLayout()
        
        # Threads
        control_layout.addWidget(QLabel("Threads:"))
        self.brute_threads_spin = QSpinBox()
        self.brute_threads_spin.setRange(1, 32)
        self.brute_threads_spin.setValue(1)
        self.brute_threads_spin.setToolTip("Number of parallel workers")
        control_layout.addWidget(self.brute_threads_spin)

        # Seed
        control_layout.addWidget(QLabel("Seed:"))
        self.brute_seed_edit = QLineEdit()
        self.brute_seed_edit.setPlaceholderText("optional integer")
        self.brute_seed_edit.setToolTip("Optional integer seed for deterministic traversal")
        self.brute_seed_edit.setMaximumWidth(160)
        control_layout.addWidget(self.brute_seed_edit)

        # Control buttons
        button_layout = QHBoxLayout()
        
        self.brute_start_button = QPushButton("Start Bruteforce")
        self.brute_start_button.clicked.connect(self.run_bruteforce)
        self.brute_start_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
        
        self.brute_stop_button = QPushButton("Stop")
        self.brute_stop_button.setEnabled(False)
        self.brute_stop_button.clicked.connect(self.stop_bruteforce)
        self.brute_stop_button.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                font-weight: bold;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #e67e22;
            }
        """)
        
        self.brute_reset_button = QPushButton("Reset")
        self.brute_reset_button.setToolTip("Stop and clear progress (.brutestate/.success)")
        self.brute_reset_button.clicked.connect(self.reset_bruteforce)
        self.brute_reset_button.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                font-weight: bold;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        
        button_layout.addWidget(self.brute_start_button)
        button_layout.addWidget(self.brute_stop_button)
        button_layout.addWidget(self.brute_reset_button)
        
        control_layout.addStretch()
        control_layout.addLayout(button_layout)
        passcode_layout.addLayout(control_layout)
        
        passcode_group.setLayout(passcode_layout)
        
        # Statistics layout
        stats_group = QGroupBox("Live Statistics")
        stats_layout = QVBoxLayout()
        
        stats_info_layout = QHBoxLayout()
        self.brute_attempts_label = QLabel("Attempts: 0")
        self.brute_rate_label = QLabel("Rate: 0/s")
        stats_info_layout.addWidget(self.brute_attempts_label)
        stats_info_layout.addWidget(self.brute_rate_label)
        stats_info_layout.addStretch()
        stats_layout.addLayout(stats_info_layout)
        
        # Tested keys list
        self.tested_keys_list = QListWidget()
        self.tested_keys_list.setAlternatingRowColors(True)
        self.tested_keys_list.setMaximumHeight(150)
        stats_layout.addWidget(QLabel("Recently Tested Keys:"))
        stats_layout.addWidget(self.tested_keys_list)
        
        self.tested_count_label = QLabel("Shown: 0 (max 1000)")
        stats_layout.addWidget(self.tested_count_label)
        stats_group.setLayout(stats_layout)
        
        # Log display
        log_group = QGroupBox("Bruteforce Log")
        log_layout = QVBoxLayout()
        self.bruteforce_log = QTextEdit()
        self.bruteforce_log.setReadOnly(True)
        self.bruteforce_log.setMaximumHeight(200)
        log_layout.addWidget(self.bruteforce_log)
        log_group.setLayout(log_layout)
        
        # Add to main layout
        self.layout.addWidget(output_group)
        self.layout.addWidget(passcode_group)
        self.layout.addWidget(stats_group)
        self.layout.addWidget(log_group)
        self.layout.addStretch()
        
    def browse_output_directory(self):
        """Browse for output directory"""
        from PyQt5.QtWidgets import QFileDialog
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory"
        )
        if directory:
            self.bruteforce_out_entry.setText(directory)
            
    def try_manual_passcode(self):
        """Try decrypting with manual passcode"""
        package = self.get_package()
        if not package:
            QMessageBox.warning(self, "Warning", "Please load a PKG file first")
            return

        output_dir = self.bruteforce_out_entry.text()
        if not output_dir:
            QMessageBox.warning(self, "Warning", "Please select an output directory")
            return
        
        passcode = self.passcode_entry.text()
        if not passcode:
            QMessageBox.warning(self, "Warning", "Please enter a passcode")
            return
        
        try:
            bruteforcer = PS4PasscodeBruteforcer()
            result = bruteforcer.brute_force_passcode(
                package.original_file,
                output_dir,
                lambda msg: self.bruteforce_log.append(msg),
                manual_passcode=passcode
            )
            self.bruteforce_log.append(result)
            if "successfully" in result.lower():
                QMessageBox.information(self, "Success", result)
            else:
                QMessageBox.warning(self, "Warning", result)
        except Exception as e:
            error_msg = f"Failed to try passcode: {str(e)}"
            self.bruteforce_log.append(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def run_bruteforce(self):
        """Run passcode bruteforcer"""
        package = self.get_package()
        if not package:
            QMessageBox.warning(self, "Warning", "Please load a PKG file first")
            return

        output_dir = self.bruteforce_out_entry.text()
        if not output_dir:
            QMessageBox.warning(self, "Warning", "Please select an output directory")
            return

        try:
            # Prepare UI state
            self.brute_start_button.setEnabled(False)
            self.brute_stop_button.setEnabled(True)
            self.bruteforce_log.clear()
            self.tested_keys_list.clear()
            self.tested_count_label.setText("Shown: 0 (max 1000)")

            # Create bruteforcer and thread
            self.bruteforcer = PS4PasscodeBruteforcer()

            class BruteforceWorker(QObject):
                progress = pyqtSignal(str)
                tested = pyqtSignal(str)
                finished = pyqtSignal(str)

                def __init__(self, bruteforcer, input_file, output_dir, threads, seed_val):
                    super().__init__()
                    self._bf = bruteforcer
                    self._in = input_file
                    self._out = output_dir
                    self._threads = threads
                    self._seed = seed_val

                def run(self):
                    try:
                        result = self._bf.brute_force_passcode(
                            self._in,
                            self._out,
                            progress_callback=self.progress.emit,
                            manual_passcode=None,
                            num_workers=self._threads,
                            tested_callback=self.tested.emit,
                            seed=self._seed
                        )
                        self.finished.emit(result)
                    except Exception as e:
                        self.finished.emit(f"[-] Error: {str(e)}")

            # Parse seed (optional)
            seed_text = self.brute_seed_edit.text().strip()
            seed_val = None
            if seed_text:
                try:
                    seed_val = int(seed_text)
                except ValueError:
                    QMessageBox.warning(self, "Seed", "Seed must be an integer")
                    self.brute_start_button.setEnabled(True)
                    self.brute_stop_button.setEnabled(False)
                    return

            self.brute_thread = QThread(self)
            self.brute_worker = BruteforceWorker(
                self.bruteforcer, 
                package.original_file, 
                output_dir, 
                self.brute_threads_spin.value(), 
                seed_val
            )
            self.brute_worker.moveToThread(self.brute_thread)
            self.brute_thread.started.connect(self.brute_worker.run)
            self.brute_worker.progress.connect(self.bruteforce_log.append)
            self.brute_worker.progress.connect(self.on_bruteforce_progress)
            self.brute_worker.tested.connect(self.on_tested_key)
            self.brute_worker.finished.connect(self.on_bruteforce_finished)
            self.brute_worker.finished.connect(self.brute_thread.quit)
            self.brute_thread.finished.connect(self.brute_thread.deleteLater)
            self.brute_thread.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start bruteforce: {str(e)}")

    def stop_bruteforce(self):
        """Stop bruteforce operation"""
        try:
            if hasattr(self, 'bruteforcer') and self.bruteforcer:
                if hasattr(self.bruteforcer, 'stop') and callable(self.bruteforcer.stop):
                    self.bruteforcer.stop()
                else:
                    setattr(self.bruteforcer, '_stop', True)
            self.brute_stop_button.setEnabled(False)
        except Exception as e:
            logging.error(f"Failed to stop bruteforce: {e}")

    def reset_bruteforce(self):
        """Stop any running bruteforce, delete saved state/success files, and reset UI."""
        try:
            # Stop current run if any
            self.stop_bruteforce()

            # Determine current input file
            input_file = None
            package = self.get_package()
            if package and hasattr(package, 'original_file'):
                input_file = package.original_file
            
            if not input_file and hasattr(self.parent_window, 'pkg_entry'):
                input_file = self.parent_window.pkg_entry.text().strip()

            # Delete state and success files
            if input_file:
                state_path = f"{input_file}.brutestate.json"
                success_path = f"{input_file}.success"
                try:
                    if os.path.exists(state_path):
                        os.remove(state_path)
                        self.bruteforce_log.append(f"[+] Removed state file: {state_path}")
                except Exception as e:
                    self.bruteforce_log.append(f"[-] Could not remove state file: {e}")
                try:
                    if os.path.exists(success_path):
                        os.remove(success_path)
                        self.bruteforce_log.append(f"[+] Removed success file: {success_path}")
                except Exception as e:
                    self.bruteforce_log.append(f"[-] Could not remove success file: {e}")

            # Reset UI elements
            self.bruteforce_log.clear()
            self.tested_keys_list.clear()
            self.tested_count_label.setText("Shown: 0 (max 1000)")
            self.brute_attempts_label.setText("Attempts: 0")
            self.brute_rate_label.setText("Rate: 0/s")
            self.brute_start_button.setEnabled(True)
            self.brute_stop_button.setEnabled(False)

            QMessageBox.information(self, "Reset", "Bruteforce state has been reset.")
        except Exception as e:
            logging.error(f"Failed to reset bruteforce: {e}")
            QMessageBox.critical(self, "Reset", f"Failed to reset: {e}")

    def on_tested_key(self, key: str):
        """Handle tested key update"""
        MAX_ITEMS = 1000
        self.tested_keys_list.addItem(key)
        if self.tested_keys_list.count() > MAX_ITEMS:
            item = self.tested_keys_list.takeItem(0)
            del item
        self.tested_count_label.setText(f"Shown: {self.tested_keys_list.count()} (max {MAX_ITEMS})")

    def on_bruteforce_finished(self, result: str):
        """Handle bruteforce completion"""
        self.brute_start_button.setEnabled(True)
        self.brute_stop_button.setEnabled(False)
        if result:
            self.bruteforce_log.append(result)
            if "successfully" in result.lower() or "[+]" in result:
                QMessageBox.information(self, "Success", result)
            elif result.lower().startswith("[-]"):
                QMessageBox.warning(self, "Bruteforce", result)

    def on_bruteforce_progress(self, msg: str):
        """Handle progress updates"""
        try:
            m = re.search(r"Attempts:\s*(\d+).*Rate:\s*([0-9]+(?:\.[0-9]+)?)", msg)
            if m:
                self.brute_attempts_label.setText(f"Attempts: {m.group(1)}")
                self.brute_rate_label.setText(f"Rate: {m.group(2)}/s")
        except Exception:
            pass
