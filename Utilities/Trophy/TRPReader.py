import struct
import os
import hashlib
from typing import List, Optional

class Archiver:
    def __init__(self, index: int, name: str, offset: int, size: int, data: Optional[bytes]):
        self.index = index
        self.name = name
        self.offset = offset
        self.size = size
        self.data = data

class TRPHeader:
    def __init__(self):
        self.magic: bytes = b''
        self.version: bytes = b''
        self.file_size: bytes = b''
        self.files_count: bytes = b''
        self.element_size: bytes = b''
        self.dev_flag: bytes = b''
        self.sha1: bytes = b''
        self.padding: bytes = b''

class TRPReader:
    def __init__(self):
        self._hdr = TRPHeader()
        self._trophy_list: List[Archiver] = []
        self._hdr_magic = b'\xdc\xa2M\x00'
        self._is_error = False
        self._read_bytes = False
        self._throw_error = True
        self._error = ''
        self._calculated_sha1: Optional[str] = None
        self._input_file = ''
        self._title_name = ''
        self._npcomm_id = ''

    def load(self, filename: str):
        try:
            self._is_error = False
            self._input_file = filename
            self._calculated_sha1 = None
            self._trophy_list = []
            
            with open(self._input_file, 'rb') as fs:
                self._read_header(fs)
                if self._hdr.magic != self._hdr_magic:
                    raise Exception("This file is not supported!")
                self._read_content(fs)
                if self.version > 1:
                    self._calculated_sha1 = self._calculate_sha1_hash()
        except Exception as ex:
            self._is_error = True
            self._error = str(ex)
        
        if self._is_error and self._throw_error:
            raise Exception(self._error)
        if not self._is_error or self._throw_error:
            return
        # Qui andrebbe implementata una funzione per mostrare l'errore

    def _read_header(self, fs):
        hdr = TRPHeader()
        hdr.magic = fs.read(4)
        hdr.version = fs.read(4)
        hdr.file_size = fs.read(8)
        hdr.files_count = fs.read(4)
        hdr.element_size = fs.read(4)
        hdr.dev_flag = fs.read(4)
        
        # Aggiungi controlli per la lunghezza dei dati letti
        if len(hdr.magic) < 4 or len(hdr.version) < 4 or len(hdr.file_size) < 8 or len(hdr.files_count) < 4 or len(hdr.element_size) < 4 or len(hdr.dev_flag) < 4:
            self._is_error = True
            self._error = "Errore durante il caricamento del file TRP: il buffer letto non ha la lunghezza corretta"
            return

        version = struct.unpack('<I', hdr.version)[0]
        if version == 1:
            hdr.padding = fs.read(36)
        elif version == 2:
            hdr.sha1 = fs.read(20)
            hdr.padding = fs.read(16)
        elif version == 3:
            hdr.sha1 = fs.read(20)
            hdr.padding = fs.read(48)
        
        self._hdr = hdr

    def _read_content(self, fs):
        for i in range(self.file_count):
            name = fs.read(36).decode('utf-8', errors='ignore').rstrip('\0')
            offset = struct.unpack('<I', fs.read(4))[0]
            size = struct.unpack('<Q', fs.read(8))[0]
            fs.read(16)  # Skip unused bytes
            
            if self._read_bytes:
                with open(self._input_file, 'rb') as file:
                    file.seek(offset)
                    data = file.read(size)
                self._trophy_list.append(Archiver(i, name, offset, size, data))
            else:
                self._trophy_list.append(Archiver(i, name, offset, size, None))

    @property
    def read_bytes(self) -> bool:
        return self._read_bytes

    @read_bytes.setter
    def read_bytes(self, value: bool):
        self._read_bytes = value

    @property
    def trophy_list(self) -> List[Archiver]:
        return self._trophy_list

    @property
    def file_size(self) -> int:
        return struct.unpack('>Q', self._hdr.file_size)[0]

    @property
    def file_count(self) -> int:
        return struct.unpack('<I', self._hdr.files_count)[0]

    @property
    def version(self) -> int:
        return struct.unpack('<I', self._hdr.version)[0]

    @property
    def sha1(self) -> Optional[str]:
        if self.version <= 1:
            return None
        return self._hdr.sha1.hex().upper()

    @property
    def calculated_sha1(self) -> Optional[str]:
        return self._calculated_sha1

    @property
    def is_error(self) -> bool:
        return self._is_error

    @property
    def throw_error(self) -> bool:
        return self._throw_error

    @throw_error.setter
    def throw_error(self, value: bool):
        self._throw_error = value

    @property
    def title_name(self) -> str:
        return self._title_name

    @title_name.setter
    def title_name(self, value: str):
        self._title_name = value

    @property
    def npcomm_id(self) -> str:
        return self._npcomm_id

    @npcomm_id.setter
    def npcomm_id(self, value: str):
        self._npcomm_id = value

    def extract(self, output_path: str):
        os.makedirs(output_path, exist_ok=True)
        with open(self._input_file, 'rb') as fs:
            for item in self.trophy_list:
                fs.seek(item.offset)
                data = fs.read(item.size)
                with open(os.path.join(output_path, item.name), 'wb') as out_file:
                    out_file.write(data)

    def extract_file(self, filename: str, output_path: str, custom_name: Optional[str] = None):
        item = next((x for x in self.trophy_list if x.name.upper().startswith(filename.upper())), None)
        if item is None:
            return
        
        os.makedirs(output_path, exist_ok=True)
        with open(self._input_file, 'rb') as fs:
            fs.seek(item.offset)
            data = fs.read(item.size)
            out_name = custom_name if custom_name else item.name
            with open(os.path.join(output_path, out_name), 'wb') as out_file:
                out_file.write(data)

    def extract_file_to_memory(self, filename: str) -> Optional[bytes]:
        item = next((x for x in self.trophy_list if x.name.upper().startswith(filename.upper())), None)
        if item is None:
            return None
        
        with open(self._input_file, 'rb') as fs:
            fs.seek(item.offset)
            return fs.read(item.size)

    def _calculate_sha1_hash(self) -> Optional[str]:
        if self.version <= 1:
            return None
        
        sha1 = hashlib.sha1()
        with open(self._input_file, 'rb') as fs:
            sha1.update(fs.read(28))
            sha1.update(b'\x00' * 20)
            fs.seek(48)
            sha1.update(fs.read())
        
        return sha1.hexdigest().upper()
