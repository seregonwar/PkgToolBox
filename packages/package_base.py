import os
import struct
import io
import json
import re
import unicodedata
from PIL import Image
from .enums import DRMType, ContentType, IROTag
from tools.utils import Logger

class PackageBase:
    TYPE_MASK = 0x0000FFFF
    FLAG_RETAIL = 1 << 31
    FLAG_ENCRYPTED = 0x80000000

    def __init__(self, file: str):
        if not os.path.isfile(file):
            raise FileNotFoundError(f"The PKG file '{file}' does not exist.")
        
        self.original_file = file
        self.pkg_info = {}
        self.files = {}
        self.content_id = None
        self.drm_type = None
        self.content_type = None
        self.content_flags = None
        self.iro_tag = None
        self.version_date = None
        self.version_hash = None
        self.digest_table_hash = None
        self.entry_table_offset = None
        self.entry_table_size = None

    def _safe_decode(self, data):
        if isinstance(data, str):
            return data.rstrip('\x00')
        elif isinstance(data, bytes):
            try:
                return data.decode('utf-8', errors='ignore').rstrip('\x00')
            except UnicodeDecodeError:
                return data.decode('latin-1', errors='ignore').rstrip('\x00')
        elif isinstance(data, int):
            return str(data)
        else:
            return str(data)

    def _read_null_terminated_string(self, fp):
        result = bytearray()
        while True:
            try:
                char = fp.read(1)
                if char == b'\x00' or len(char) == 0:
                    break
                result.extend(char)
            except (OverflowError, OSError) as e:
                Logger.log_warning(f"Error reading string: {e}")
                break
        return bytes(result)

    def get_info(self):
        return {
            "content_id": self.content_id,
            "drm_type": self.drm_type,
            "content_type": self.content_type,
            "content_flags": self.content_flags,
            "iro_tag": self.iro_tag,
            "version_date": self.version_date,
            "version_hash": self.version_hash,
            "digest_table_hash": self.digest_table_hash,
            "entry_table_offset": self.entry_table_offset,
            "entry_table_size": self.entry_table_size,
        }

    def read_file(self, file_id):
        file_info = self.files.get(file_id)
        if not file_info:
            raise ValueError(f"File with ID {file_id} not found in the package.")
        
        with open(self.original_file, 'rb') as f:
            f.seek(file_info['offset'])
            data = f.read(file_info['size'])
        
        return data

    def extract_all_files(self, output_dir: str):
        """Extract all files listed in self.files to the specified output directory.

        This is a generic implementation used by package types. It expects
        `self.files` to be a mapping of file_id -> dict with at least:
          - 'offset': byte offset in the source package
          - 'size': size in bytes
          - optional 'name': output relative path
        """
        try:
            os.makedirs(output_dir, exist_ok=True)

            if not isinstance(self.files, dict) or not self.files:
                Logger.log_warning("No files table available for extraction.")
                return f"No files to extract. Output: {output_dir}"

            with open(self.original_file, 'rb') as src:
                for file_id, info in self.files.items():
                    try:
                        name = info.get('name', f'file_{file_id}')
                        # Normalize any path-like names to avoid traversal
                        safe_name = os.path.normpath(name).lstrip(os.sep).replace('..', '_')
                        out_path = os.path.join(output_dir, safe_name)
                        os.makedirs(os.path.dirname(out_path), exist_ok=True)

                        offset = info.get('offset')
                        size = info.get('size')
                        if offset is None or size is None:
                            Logger.log_warning(f"Skipping file_id {file_id}: missing offset/size")
                            continue

                        src.seek(offset)
                        chunk = src.read(size)
                        with open(out_path, 'wb') as dst:
                            dst.write(chunk)
                        Logger.log_information(f"Extracted: {safe_name}")
                    except Exception as e:
                        Logger.log_error(f"Error extracting file_id {file_id}: {e}")

            Logger.log_information(f"Extraction completed. Output: {output_dir}")
            return f"Extraction completed. Output: {output_dir}"
        except Exception as e:
            Logger.log_error(f"Extraction failed: {e}")
            raise
