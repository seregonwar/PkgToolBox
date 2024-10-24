import os
import struct
import io
import json
import re
import unicodedata
from PIL import Image
from .enums import DRMType, ContentType, IROTag
from utils import Logger

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
