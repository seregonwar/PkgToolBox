import os
import hashlib
import tempfile
import shutil
from io import FileIO, BytesIO
import struct
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Archiver:
    def __init__(self, index, name, offset, size, bytes_data=None):
        self.index = index
        self.name = name
        self.offset = offset
        self.size = size
        self.bytes_data = bytes_data

class TRPReader:
    class TRPHeader:
        def __init__(self):
            self.magic = None
            self.version = None
            self.file_size = None
            self.files_count = None
            self.element_size = None
            self.dev_flag = None
            self.padding = None
            self.sha1 = None

    def __init__(self, filename=None):
        self._hdr = self.TRPHeader()
        self._trophyList = []
        self._hdrmagic = {
            bytes([220, 162, 77, 0]),    # Magic number originale
            bytes([5, 216, 3, 164]),     # Nuovo magic number (a403d805 in little-endian)
            bytes([126, 237, 245, 255])  # Nuovo magic number (fff5ed7e in little-endian)
        }
        self._iserror = False
        self._readbytes = False
        self._throwerror = True
        self._error = ""
        self._calculatedsha1 = None
        self._inputfile = filename
        self._title = None
        self._npcommid = None
        self._temp_dir = None
        if filename:
            self.load(filename)

    def load(self, filename=None):
        if filename is None and self._inputfile is None:
            raise ValueError("Filename must be provided either in the constructor or in the load method")
        
        if filename is not None:
            self._inputfile = filename

        try:
            self._iserror = False
            self._calculatedsha1 = None
            self._trophyList = []
            
            if not os.path.exists(self._inputfile):
                raise FileNotFoundError(f"File not found: {self._inputfile}")
            
            self.verify_file_structure()
            
            with open(self._inputfile, 'rb') as fs:
                self.read_content(fs)
                # Ensure that self._title is set here or in read_content
                if self._title is None:
                    self._title = "Unknown Title"  # Or an appropriate default value
        except Exception as e:
            self._iserror = True
            self._error = str(e)
            logger.error(f"Error loading trophy file: {self._error}")

        if self._iserror and self._throwerror:
            raise Exception(self._error)

    def read_header(self, fs):
        try:
            self._hdr.magic = fs.read(4)
            self._hdr.version = fs.read(4)
            self._hdr.file_size = fs.read(8)
            self._hdr.files_count = fs.read(4)
            self._hdr.element_size = fs.read(4)
            self._hdr.dev_flag = fs.read(4)

            version = self.bytes_to_int(self._hdr.version, 32)
            file_size = self.bytes_to_int(self._hdr.file_size, 64)
            files_count = self.bytes_to_int(self._hdr.files_count, 32)

            logger.debug(f"Header: magic={self._hdr.magic.hex()}, version={version}, file_size={file_size}, files_count={files_count}")

            if version == 1:
                self._hdr.padding = fs.read(36)
            elif version == 2:
                self._hdr.sha1 = fs.read(20)
                self._hdr.padding = fs.read(16)
            elif version == 3:
                self._hdr.sha1 = fs.read(20)
                self._hdr.padding = fs.read(48)
            else:
                raise ValueError(f"Invalid version: {version}")
        except Exception as e:
            logger.error(f"Error reading header: {e}")
            raise

    def read_content(self, fs):
        fs.seek(0)
        data = fs.read()
        png_signature = b'\x89PNG\r\n\x1a\n'
        esfm_signature = b'ESFM'
        
        i = 0
        while i < len(data):
            if data[i:i+8] == png_signature:
                offset = i
                size = self.get_png_size(data[i:])
                if size:
                    name = f"TROP{len(self._trophyList):03d}.PNG"
                    self._trophyList.append(Archiver(len(self._trophyList), name, offset, size))
                    logger.info(f"Trovata immagine PNG '{name}' all'offset 0x{offset:X}, dimensione {size}")
                    i += size
                else:
                    i += 1
            elif data[i:i+4] == esfm_signature:
                offset = i
                try:
                    size = struct.unpack('>I', data[i+4:i+8])[0] + 8  # Header ESFM (4 byte) + dimensione (4 byte)
                    if size > 0 and size < len(data) - i:
                        name = f"FILE{len(self._trophyList):03d}.ESFM"
                        self._trophyList.append(Archiver(len(self._trophyList), name, offset, size))
                        logger.info(f"Trovato file ESFM '{name}' all'offset 0x{offset:X}, dimensione {size}")
                        i += size
                    else:
                        logger.warning(f"Dimensione ESFM non valida all'offset 0x{offset:X}: {size}")
                        i += 1
                except struct.error:
                    logger.warning(f"Impossibile leggere la dimensione ESFM all'offset 0x{offset:X}")
                    i += 1
            else:
                i += 1
        
        if not self._trophyList:
            logger.warning("Nessun file trovato nel TRP. Il file potrebbe essere corrotto o vuoto.")
        else:
            logger.info(f"Trovati {len(self._trophyList)} file")
        
        # Aggiorniamo il conteggio dei file nell'header
        self._hdr.files_count = len(self._trophyList).to_bytes(4, byteorder='little')

    def get_png_size(self, data):
        try:
            idx = data.index(b'IEND')
            return idx + 12  # IEND chunk is 12 bytes long, including the 4-byte CRC
        except ValueError:
            return None

    @property
    def read_bytes(self):
        return self._readbytes

    @read_bytes.setter
    def read_bytes(self, value):
        self._readbytes = value

    @property
    def trophy_list(self):
        return self._trophyList

    @property
    def file_size(self):
        return self.bytes_to_int(self._hdr.file_size, 64)

    @property
    def file_count(self):
        return self.bytes_to_int(self._hdr.files_count, 32)

    @property
    def version(self):
        return self.bytes_to_int(self._hdr.version, 32)

    @property
    def sha1(self):
        if self.version <= 1:
            return None
        return self.byte_array_to_hex_string(self._hdr.sha1)

    @property
    def calculated_sha1(self):
        return self._calculatedsha1

    @property
    def is_error(self):
        return self._iserror

    @property
    def throw_error(self):
        return self._throwerror

    @throw_error.setter
    def throw_error(self, value):
        self._throwerror = value

    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, value):
        self._title = value

    @property
    def np_comm_id(self):
        return self._npcommid

    @np_comm_id.setter
    def np_comm_id(self, value):
        self._npcommid = value

    def extract_file_to_memory(self, filename):
        archiver = next((a for a in self._trophyList if a.name.upper().startswith(filename.upper())), None)
        if archiver is None:
            return None

        with open(self._inputfile, 'rb') as fs:
            fs.seek(archiver.offset)
            return fs.read(archiver.size)

    def byte_arrays_equal(self, first, second):
        if first == second:
            return True
        if len(first) != len(second):
            return False
        return all(a == b for a, b in zip(first, second))

    @staticmethod
    def byte_array_to_little_endian_int(byte_array):
        return int.from_bytes(byte_array, byteorder='little')

    @staticmethod
    def byte_array_to_utf8_string(byte_array, errors='ignore'):
        return ''.join(chr(b) for b in byte_array if 32 <= b <= 126 or b in (9, 10, 13))

    @staticmethod
    def byte_array_to_hex_string(byte_array):
        return ''.join(f'{b:02x}' for b in byte_array)

    @staticmethod
    def hex_string_to_long(hex_string):
        return int(hex_string, 16)

    def calculate_sha1_hash(self):
        if self.version <= 1:
            return None

        sha1 = hashlib.sha1()
        with open(self._inputfile, 'rb') as fs:
            sha1.update(fs.read(28))
            fs.seek(48)
            while chunk := fs.read(8192):
                sha1.update(chunk)
        return sha1.hexdigest()

    def extract(self):
        if self._inputfile is None:
            raise ValueError("No input file specified")

        input_dir = os.path.dirname(self._inputfile)
        input_filename = os.path.splitext(os.path.basename(self._inputfile))[0]
        
        if self._temp_dir is None:
            self._temp_dir = tempfile.mkdtemp(prefix=f"{input_filename}_extracted_", dir=input_dir)
        
        with open(self._inputfile, 'rb') as fs:
            for archiver in self._trophyList:
                fs.seek(archiver.offset)
                data = fs.read(archiver.size)
                output_file = os.path.join(self._temp_dir, archiver.name)
                with open(output_file, 'wb') as out:
                    out.write(data)
                logger.info(f"Extracted {archiver.name} to {output_file}")
        
        logger.info(f"All files extracted to: {self._temp_dir}")
        return self._temp_dir

    def cleanup(self):
        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                shutil.rmtree(self._temp_dir)
                logger.info(f"Temporary directory {self._temp_dir} has been removed")
            except Exception as e:
                logger.error(f"Error removing temporary directory {self._temp_dir}: {e}")
        self._temp_dir = None

    def extract_file(self, filename, outputpath, custom_name=None):
        archiver = next((a for a in self._trophyList if a.name.upper().startswith(filename.upper())), None)
        if archiver is None:
            return
        if not os.path.exists(outputpath):
            os.makedirs(outputpath)

        with open(self._inputfile, 'rb') as fs:
            fs.seek(archiver.offset)
            data = fs.read(archiver.size)
            output_file = os.path.join(outputpath, custom_name or archiver.name)
            with open(output_file, 'wb') as out:
                out.write(data)

    def verify_integrity(self):
        if self.version > 1 and self.sha1:
            calculated_sha1 = self.calculate_sha1_hash()
            if calculated_sha1.lower() != self.sha1.lower():
                print(f"Warning: SHA1 mismatch. File may be corrupted.")
                print(f"Calculated: {calculated_sha1}")
                print(f"Expected:   {self.sha1}")
            else:
                print("SHA1 verification passed.")
        
        expected_size = self.file_size
        actual_size = os.path.getsize(self._inputfile)
        if expected_size != actual_size:
            print(f"Warning: File size mismatch. Expected: {expected_size}, Actual: {actual_size}")
        
        if len(self._trophyList) != self.file_count:
            print(f"Warning: Trophy count mismatch. Expected: {self.file_count}, Actual: {len(self._trophyList)}")

        return self._trophyList

    def verify_trophy_data(self, name, offset, size):
        file_size = os.path.getsize(self._inputfile)
        if offset < 0 or size < 0 or offset + size > file_size:
            return False
        if offset == 0 and size == 0:
            return False
        if len(name.strip()) == 0:
            return False
        return True

    def verify_file_structure(self):
        try:
            actual_size = os.path.getsize(self._inputfile)
            if actual_size < 64:  # Dimensione minima dell'header
                logger.error(f"File troppo piccolo: {actual_size} byte")
                return False
            
            with open(self._inputfile, 'rb') as fs:
                magic = fs.read(4)
                if magic not in self._hdrmagic:
                    logger.warning(f"Numero magico del file non valido: {magic.hex()}, ma continuo comunque")
                else:
                    logger.info(f"Numero magico valido trovato: {magic.hex()}")
                
                version_bytes = fs.read(4)
                file_size_bytes = fs.read(8)
                files_count_bytes = fs.read(4)
                
                version = self.bytes_to_int(version_bytes, 32)
                file_size = self.bytes_to_int(file_size_bytes, 64)
                files_count = self.bytes_to_int(files_count_bytes, 32)
                
                logger.debug(f"Byte grezzi: version={version_bytes.hex()}, file_size={file_size_bytes.hex()}, files_count={files_count_bytes.hex()}")
                logger.debug(f"Struttura del file: version={version}, file_size={file_size}, files_count={files_count}")
                
                if file_size != actual_size:
                    logger.warning(f"Dimensione del file non corrispondente: prevista {file_size}, effettiva {actual_size}")
                    self._hdr.file_size = actual_size.to_bytes(8, byteorder='little')
                
                if version not in [1, 2, 3]:
                    logger.warning(f"Versione non valida: {version}, assumo versione 3")
                    version = 3
                    self._hdr.version = version.to_bytes(4, byteorder='little')
                
                if files_count <= 0 or files_count > 1000000:
                    logger.warning(f"Conteggio file non valido: {files_count}, proverò a estrarre comunque")
                    files_count = 0  # Resettiamo il conteggio e lasciamo che read_content lo determini
                    self._hdr.files_count = files_count.to_bytes(4, byteorder='little')
                
                return True
        except Exception as e:
            logger.error(f"Errore durante la verifica della struttura del file: {e}")
            return False

    @staticmethod
    def bytes_to_int(bytes_data, bits=32):
        value = int.from_bytes(bytes_data, byteorder='little', signed=False)
        if bits == 32:
            return value & 0xFFFFFFFF
        elif bits == 64:
            return value & 0xFFFFFFFFFFFFFFFF
        else:
            raise ValueError(f"Unsupported bit size: {bits}")

    def some_method_that_uses_title(self):
        if self._title is None:
            logger.warning("Title is not set")
            return

    def get_temp_dir(self):
        return self._temp_dir

    def read_content_flexible(self, fs):
        fs.seek(0)
        data = fs.read()
        png_signature = b'\x89PNG\r\n\x1a\n'
        esfm_signature = b'ESFM'
        
        i = 0
        while i < len(data):
            if data[i:i+8] == png_signature:
                offset = i
                size = self.get_png_size(data[i:])
                if size:
                    name = f"TROP{len(self._trophyList):03d}.PNG"
                    self._trophyList.append(Archiver(len(self._trophyList), name, offset, size))
                    logger.info(f"Trovata immagine PNG '{name}' all'offset 0x{offset:X}, dimensione {size}")
                    i += size
                else:
                    i += 1
            elif data[i:i+4] == esfm_signature:
                offset = i
                try:
                    size = struct.unpack('>I', data[i+4:i+8])[0] + 8
                    if size > 0 and size < len(data) - i:
                        name = f"FILE{len(self._trophyList):03d}.ESFM"
                        self._trophyList.append(Archiver(len(self._trophyList), name, offset, size))
                        logger.info(f"Trovato file ESFM '{name}' all'offset 0x{offset:X}, dimensione {size}")
                        i += size
                    else:
                        i += 1
                except struct.error:
                    i += 1
            else:
                i += 1
        
        if not self._trophyList:
            logger.warning("Nessun file trovato nel TRP. Il file potrebbe essere corrotto o vuoto.")
        else:
            logger.info(f"Trovati {len(self._trophyList)} file")
        
        self._hdr.files_count = len(self._trophyList).to_bytes(4, byteorder='little')