import struct
import os
import logging
import shutil
from tools.utils import Logger
from tools.PS5_Game_Info import PS5GameInfo
import json

class Repack:
    FLAG_ENCRYPTED = 0x1
    FLAG_DECRYPTED = 0x2

    def __init__(self, original_file, pkg_table_offset, pkg_entry_count, files):
        self.original_file = original_file
        self.pkg_table_offset = pkg_table_offset
        self.pkg_entry_count = pkg_entry_count
        self.files = files

    def repack(self, input_dir, output_pkg_file, log_file_path, progress_callback=None):
        """
        Repack the modified files into a new package.
        :param input_dir: Directory containing the modified files.
        :param output_pkg_file: Path where the new package will be saved.
        :param log_file_path: Path where the log file will be saved.
        :param progress_callback: Optional callback for reporting progress.
        """
        temp_pkg_file = output_pkg_file + ".tmp"
        new_offset = self.pkg_table_offset + (self.pkg_entry_count * struct.calcsize(">6IQ"))

        with open(self.original_file, 'rb') as pkg_file, open(temp_pkg_file, 'wb') as new_pkg:
            # Copy the package header
            header_size = self.pkg_table_offset
            new_pkg.write(pkg_file.read(header_size))

            # Repack the modified files
            for file_id, file_info in self.files.items():
                input_file_path = os.path.join(input_dir, file_info.get("name", f"file_{file_id}"))
                
                # Read the content from the file system or the original package
                if os.path.exists(input_file_path):
                    with open(input_file_path, 'rb') as input_file:
                        file_content = input_file.read()
                else:
                    pkg_file.seek(file_info['offset'])
                    file_content = pkg_file.read(file_info['size'])

                # Update the offset and size in file_info
                file_info['offset'] = new_offset
                file_info['size'] = len(file_content)

                # Write the file content to the new package
                new_pkg.write(file_content)
                new_offset += len(file_content)

                if progress_callback:
                    progress_callback({"status": f"Processed: {file_info.get('name', f'file_{file_id}')}"})


            # Rewrite the updated file table
            self._write_file_table(new_pkg)

        # Replace the original package file with the new one
        os.remove(self.original_file)
        os.rename(temp_pkg_file, self.original_file)

        logging.info(f"Repack completed. Log saved to: {log_file_path}")
        return f"Repack completed. Log saved to: {log_file_path}"

    def reverse_dump(self, input_dir):
        """
        Reinsert the dumped files into a new package file in a new directory.
        :param input_dir: Directory containing the dumped files.
        """
        try:
            original_dir, original_filename = os.path.split(self.original_file)
            modified_dir = os.path.join(original_dir, "modified_pkg")
            os.makedirs(modified_dir, exist_ok=True)
            
            new_pkg_file = os.path.join(modified_dir, original_filename)
            log_file_path = os.path.join(modified_dir, "reverse_dump_log.txt")
            
            with open(log_file_path, 'w') as log_file, open(self.original_file, 'rb') as pkg_file, open(new_pkg_file, 'wb') as new_pkg:
                # Copy the entire original PKG file first
                pkg_file.seek(0)
                shutil.copyfileobj(pkg_file, new_pkg)
                
                # Now, update only the modified files
                for file_id, file_info in self.files.items():
                    file_name = file_info.get("name", f"file_{file_id}")
                    input_file_path = os.path.join(input_dir, file_name)
                    
                    if os.path.exists(input_file_path):
                        with open(input_file_path, 'rb') as input_file:
                            file_content = input_file.read()
                        
                        # Update the file in the new PKG
                        new_pkg.seek(file_info['offset'])
                        new_pkg.write(file_content)
                        
                        # Update file info if size has changed
                        new_size = len(file_content)
                        if new_size != file_info['size']:
                            file_info['size'] = new_size
                            log_message = f"Updated: {file_name}, offset: {file_info['offset']}, new size: {new_size}\n"
                        else:
                            log_message = f"Replaced: {file_name}, offset: {file_info['offset']}, size: {new_size}\n"
                    else:
                        log_message = f"Kept original: {file_name}, offset: {file_info['offset']}, size: {file_info['size']}\n"

                    log_file.write(log_message)
                    Logger.log_information(log_message.strip())

                # Update the file table
                self._write_file_table(new_pkg)

            Logger.log_information(f"Reverse dump completed. New package saved as: {new_pkg_file}")
            Logger.log_information(f"Log saved in: {log_file_path}")
            return f"Reverse dump completed. New package saved as: {new_pkg_file}\nLog saved in: {log_file_path}"
        except Exception as e:
            Logger.log_error(f"Error during reverse dump: {str(e)}")
            return f"Reverse dump failed. Error: {str(e)}"

    def verify_and_adapt_file(self, file_name, file_content, file_info, ps5_info):
        if file_name == "eboot.bin":
            return self.adapt_eboot(file_content, file_info, ps5_info)
        elif file_name.startswith("sce_sys/"):
            return self.adapt_sce_sys_file(file_name, file_content, file_info, ps5_info)
        else:
            return file_content

    def adapt_eboot(self, file_content, file_info, ps5_info):
        Logger.log_information("Verifying and adapting eboot.bin")
        if ps5_info.Fcheck == '(<span style=" color:#55aa00;">Fake</span>)':
            Logger.log_warning("eboot.bin is detected as fake. Proceeding with caution.")
        # Aggiungi qui ulteriori controlli e adattamenti per eboot.bin
        return file_content

    def adapt_sce_sys_file(self, file_name, file_content, file_info, ps5_info):
        Logger.log_information(f"Verifying and adapting {file_name}")
        if file_name == "sce_sys/param.json":
            # Verifica che i dati in param.json corrispondano a quelli in ps5_info.main_dict
            try:
                param_data = json.loads(file_content.decode('utf-8'))
                for key, value in ps5_info.main_dict.items():
                    if key in param_data and str(param_data[key]) != str(value):
                        Logger.log_warning(f"Mismatch in param.json for {key}: expected {value}, found {param_data[key]}")
            except json.JSONDecodeError:
                Logger.log_error("Error decoding param.json")
        # Aggiungi qui ulteriori controlli e adattamenti per altri file in sce_sys
        return file_content

    def _write_file_table(self, pkg_file):
        """
        Write the updated file table to the package.
        :param pkg_file: Package file opened in write mode.
        """
        pkg_file.seek(self.pkg_table_offset)
        for file_id, file_info in self.files.items():
            entry = struct.pack(">6IQ",
                                file_id,
                                file_info['fn_offset'],
                                file_info['flags1'],
                                file_info['flags2'],
                                file_info['offset'],
                                file_info['size'],
                                file_info.get('padding', 0))
            pkg_file.write(entry)

    def verify_file_integrity(self, file_path, expected_size):
        if os.path.exists(file_path):
            actual_size = os.path.getsize(file_path)
            if actual_size != expected_size:
                Logger.log_error(f"File integrity check failed for {file_path}. Expected size: {expected_size}, Actual size: {actual_size}")
                return False
            return True
        else:
            Logger.log_error(f"File not found: {file_path}")
            return False