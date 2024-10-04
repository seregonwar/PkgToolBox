import struct
import os
import logging

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

    def reverse_dump(self, dump_dir):
        """
        Reinsert the dumped files into a new package copy.
        :param dump_dir: Directory containing the dumped files.
        """
        output_dir = "reverse_dump_output"
        os.makedirs(output_dir, exist_ok=True)
        output_pkg_file = os.path.join(output_dir, os.path.basename(self.original_file))

        temp_pkg_file = output_pkg_file + ".temp"
        new_offset = self.pkg_table_offset + (self.pkg_entry_count * struct.calcsize(">6IQ"))

        with open(self.original_file, 'rb') as pkg_file, open(temp_pkg_file, 'wb') as new_pkg:
            # Copy the package header
            header_size = self.pkg_table_offset
            new_pkg.write(pkg_file.read(header_size))

            # Repack the dumped files
            for file_id, file_info in self.files.items():
                dump_file_path = os.path.join(dump_dir, file_info.get("name", f"file_{file_id}"))
                
                if os.path.exists(dump_file_path):
                    with open(dump_file_path, 'rb') as dump_file:
                        file_content = dump_file.read()

                    # Update the offset and size in file_info
                    file_info['offset'] = new_offset
                    file_info['size'] = len(file_content)

                    # Write the file content to the new package
                    new_pkg.write(file_content)
                    new_offset += len(file_content)
                else:
                    # If the file doesn't exist in the dump, copy it from the original package
                    pkg_file.seek(file_info['offset'])
                    file_content = pkg_file.read(file_info['size'])
                    
                    # Write the file content to the new location
                    new_pkg.write(file_content)
                    
                    # Update the offset in file_info
                    file_info['offset'] = new_offset
                    new_offset += file_info['size']

            # Rewrite the updated file table
            self._write_file_table(new_pkg)

        # Move the temporary file to the output directory
        os.rename(temp_pkg_file, output_pkg_file)

        logging.info(f"Reverse dump completed. Modified package saved to: {output_pkg_file}")
        return f"Reverse dump completed. Modified package saved to: {output_pkg_file}"

    def _write_file_table(self, pkg_file):
        """
        Write the updated file table to the package.
        :param pkg_file: Package file opened in write mode.
        """
        pkg_file.seek(self.pkg_table_offset)
        for file_id, file_info in self.files.items():
            pkg_file.write(struct.pack(">6IQ", file_id, file_info['offset'], file_info['size'], 0, 0, 0, 0))
