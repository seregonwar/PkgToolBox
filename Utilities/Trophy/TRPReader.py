import os
import hashlib
import tempfile
import shutil
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class Archiver:
    def __init__(self, index, name, offset, size, bytes_data=None, flag=0):
        self.index = index
        self.name = name
        self.offset = offset
        self.size = size
        self.bytes_data = bytes_data
        # flag: 3 = encrypted (ESFM), 0 = plain (PNG...)
        self.flag = flag

    @property
    def is_encrypted(self):
        return bool(self.flag)


class TRPReader:
    class TRPHeader:
        def __init__(self):
            self.magic = None
            self.version = 0
            self.file_size = 0
            self.files_count = 0
            self.element_size = 0x40
            self.dev_flag = 0
            self.sha1 = None
            self.key_index = 0
            self.padding = None

    # Byte sequences of the TRP magic number 0xDCA24D00 (stored big-endian)
    _hdrmagic = {
        bytes([220, 162, 77, 0]),    # DC A2 4D 00
        bytes([5, 216, 3, 164]),     # A4 03 D8 05 (alternate)
        bytes([126, 237, 245, 255])  # 7E ED F5 FF (alternate)
    }

    def __init__(self, filename=None):
        self._hdr = self.TRPHeader()
        self._trophyList = []
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
                self.read_header(fs)
                self.read_content(fs)
                if self._title is None:
                    self._title = "Unknown Title"
        except Exception as e:
            self._iserror = True
            self._error = str(e)
            logger.error(f"Error loading trophy file: {self._error}")

        if self._iserror and self._throwerror:
            raise Exception(self._error)

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------
    def read_header(self, fs):
        """Parsa l'header TRP. Tutti i campi numerici sono big-endian.

        v1: magic(4) version(4) file_size(8) files_count(4) element_size(4) dev_flag(4) padding[36]      = 64
        v2: magic(4) version(4) file_size(8) files_count(4) element_size(4) dev_flag(4) sha1[20] pad[16] = 64
        v3: magic(4) version(4) file_size(8) files_count(4) element_size(4) dev_flag(4) sha1[20] key_index(4) pad[44] = 96
        """
        try:
            self._hdr.magic = fs.read(4)
            self._hdr.version = int.from_bytes(fs.read(4), 'big')
            self._hdr.file_size = int.from_bytes(fs.read(8), 'big')
            self._hdr.files_count = int.from_bytes(fs.read(4), 'big')
            self._hdr.element_size = int.from_bytes(fs.read(4), 'big')
            self._hdr.dev_flag = int.from_bytes(fs.read(4), 'big')

            if self._hdr.version == 1:
                self._hdr.padding = fs.read(36)
            elif self._hdr.version == 2:
                self._hdr.sha1 = fs.read(20)
                self._hdr.padding = fs.read(16)
            elif self._hdr.version == 3:
                self._hdr.sha1 = fs.read(20)
                self._hdr.key_index = int.from_bytes(fs.read(4), 'big')
                self._hdr.padding = fs.read(44)
            else:
                raise ValueError(f"Invalid version: {self._hdr.version}")

            if not (0 < self._hdr.files_count <= 1000000):
                raise ValueError(f"Invalid file count in header: {self._hdr.files_count}")
            if not (32 <= self._hdr.element_size <= 256):
                logger.warning(f"Unusual entry size {self._hdr.element_size}, assuming 0x40")
                self._hdr.element_size = 0x40

            logger.debug(
                f"Header: magic={self._hdr.magic.hex()}, version={self._hdr.version}, "
                f"file_size={self._hdr.file_size}, files_count={self._hdr.files_count}, "
                f"element_size={self._hdr.element_size}, key_index={self._hdr.key_index}"
            )
        except Exception as e:
            logger.error(f"Error reading header: {e}")
            raise

    @property
    def header_size(self):
        """Dimensione dell'header in base alla versione."""
        return {1: 64, 2: 64, 3: 96}.get(self._hdr.version, 96)

    # ------------------------------------------------------------------
    # Entry table
    # ------------------------------------------------------------------
    def read_content(self, fs):
        """Legge la tabella delle entry reale (nome, offset, size, flag).

        Ogni entry (tipicamente 0x40 byte) è:
            name[32] + offset(8, BE) + size(8, BE) + flag(4, BE) + padding[12]
        """
        fs.seek(self.header_size)
        table = fs.read(self._hdr.element_size * self._hdr.files_count)

        if not self._parse_entry_table(table):
            logger.warning("Entry table non valida, ripiego sulla scansione delle firme")
            self._trophyList = []
            self._scan_signatures(fs)

        if not self._trophyList:
            logger.warning("No files found in the TRP. The file might be corrupted or empty.")
        else:
            logger.info(f"Found {len(self._trophyList)} files")

    def _parse_entry_table(self, table):
        """Estrae le entry dalla tabella. Ritorna True se ne trova almeno una valida."""
        file_size = os.path.getsize(self._inputfile)
        entry_size = self._hdr.element_size
        entries = []

        for i in range(self._hdr.files_count):
            base = i * entry_size
            if base + 32 > len(table):
                break

            raw_name = table[base:base + 32]
            name = raw_name.split(b'\x00')[0].decode('ascii', 'ignore').strip()
            if not name:
                continue

            # Layout standard Sony: offset(8) + size(8) + flag(4) + padding(12)
            offset = int.from_bytes(table[base + 32:base + 40], 'big')
            size = int.from_bytes(table[base + 40:base + 48], 'big')
            flag = int.from_bytes(table[base + 48:base + 52], 'big')

            # Variante con offset/size a 4 byte (es. file creati da TRPCreator)
            if not (0 < size <= file_size and 0 <= offset < file_size):
                offset32 = int.from_bytes(table[base + 32:base + 36], 'big')
                size32 = int.from_bytes(table[base + 36:base + 40], 'big')
                if 0 < size32 <= file_size and 0 <= offset32 < file_size:
                    offset, size, flag = offset32, size32, int.from_bytes(table[base + 40:base + 44], 'big')

            if size <= 0 or offset + size > file_size:
                logger.warning(f"Entry '{name}' fuori dai limiti (offset=0x{offset:X}, size={size}), ignorata")
                continue

            entries.append(Archiver(i, name, offset, size, flag=flag))

        if entries:
            self._trophyList = entries
            logger.info(f"Loaded {len(entries)} entries from the TRP entry table")
            return True
        return False

    def _scan_signatures(self, fs):
        """Fallback per file senza tabella valida: cerca PNG/ESFM per firma."""
        fs.seek(0)
        data = fs.read()
        n = len(data)
        png_signature = b'\x89PNG\r\n\x1a\n'
        esfm_signature = b'ESFM'

        i = 0
        while i < n - 8:
            if data[i:i + 8] == png_signature:
                size = self.get_png_size(data[i:])
                if size:
                    name = f"TROP{len(self._trophyList):03d}.PNG"
                    self._trophyList.append(Archiver(len(self._trophyList), name, i, size))
                    logger.info(f"Found PNG image '{name}' at offset 0x{i:X}, size {size}")
                    i += size
                else:
                    i += 1
            elif data[i:i + 4] == esfm_signature:
                try:
                    size = int.from_bytes(data[i + 4:i + 8], 'big') + 8
                    if 0 < size < n - i:
                        name = f"FILE{len(self._trophyList):03d}.ESFM"
                        self._trophyList.append(Archiver(len(self._trophyList), name, i, size, flag=3))
                        logger.info(f"Found ESFM file '{name}' at offset 0x{i:X}, size {size}")
                        i += size
                    else:
                        i += 1
                except (IndexError, ValueError):
                    i += 1
            else:
                i += 1

    @staticmethod
    def get_png_size(data):
        """Ritorna la dimensione del PNG leggendo i chunk fino a IEND, oppure None."""
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):
            return None
        pos = 8  # dopo la firma PNG
        n = len(data)
        while pos + 8 <= n:
            length = int.from_bytes(data[pos:pos + 4], 'big')
            ctype = data[pos + 4:pos + 8]
            if ctype == b'IEND':
                return pos + 12  # length(4) + 'IEND'(4) + CRC(4)
            pos += 12 + length
        return None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------
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
        return self._hdr.file_size

    @property
    def file_count(self):
        return self._hdr.files_count

    @property
    def version(self):
        return self._hdr.version

    @property
    def sha1(self):
        if self._hdr.version <= 1 or not self._hdr.sha1:
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

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------
    def extract_file_to_memory(self, filename):
        archiver = next((a for a in self._trophyList if a.name.upper().startswith(filename.upper())), None)
        if archiver is None:
            return None
        with open(self._inputfile, 'rb') as fs:
            fs.seek(archiver.offset)
            return fs.read(archiver.size)

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

    def decrypt_trp(self, input_file, output_dir):
        """Estrae i contenuti del file TRP in una directory di output."""
        try:
            if not self._trophyList:
                self.load(input_file)

            os.makedirs(output_dir, exist_ok=True)

            for trophy in self._trophyList:
                try:
                    file_ext = os.path.splitext(trophy.name)[1].lower()
                    with open(input_file, 'rb') as f:
                        f.seek(trophy.offset)
                        data = f.read(trophy.size)

                    if "TROP" in trophy.name.upper():
                        output_name = f"trophy_{trophy.index:03d}{file_ext}"
                    else:
                        output_name = trophy.name

                    output_path = os.path.join(output_dir, output_name)
                    with open(output_path, 'wb') as f:
                        f.write(data)

                    logging.info(f"Extracted: {output_name}")
                except Exception as e:
                    logging.error(f"Error extracting {trophy.name}: {e}")
                    continue

            return "Trophy file decrypted and extracted successfully"
        except Exception as e:
            error_msg = f"Error decrypting TRP: {str(e)}"
            logging.error(error_msg)
            raise Exception(error_msg)

    # ------------------------------------------------------------------
    # Integrity
    # ------------------------------------------------------------------
    def verify_file_structure(self):
        try:
            actual_size = os.path.getsize(self._inputfile)
            if actual_size < 64:  # Minimum header size
                logger.error(f"File too small: {actual_size} bytes")
                return False

            with open(self._inputfile, 'rb') as fs:
                magic = fs.read(4)
                if magic not in self._hdrmagic:
                    logger.warning(f"Invalid file magic number: {magic.hex()}, but continuing anyway")
                else:
                    logger.info(f"Valid magic number found: {magic.hex()}")

                version = int.from_bytes(fs.read(4), 'big')
                if version not in [1, 2, 3]:
                    logger.warning(f"Invalid version: {version}, assuming version 3")
                else:
                    logger.info(f"TRP version: {version}")

            return True
        except Exception as e:
            logger.error(f"Error during file structure verification: {e}")
            return False

    def calculate_sha1_hash(self):
        if self._hdr.version <= 1:
            return None

        sha1 = hashlib.sha1()
        with open(self._inputfile, 'rb') as fs:
            sha1.update(fs.read(28))
            fs.seek(48)  # salta il digest (28..48)
            while chunk := fs.read(8192):
                sha1.update(chunk)
        return sha1.hexdigest()

    def verify_integrity(self):
        if self._hdr.version > 1 and self.sha1:
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

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def byte_array_to_hex_string(byte_array):
        return ''.join(f'{b:02x}' for b in byte_array)

    @staticmethod
    def bytes_to_int(bytes_data, bits=32):
        """Compat: interpreta i byte come intero (il formato TRP è big-endian)."""
        return int.from_bytes(bytes_data, byteorder='big', signed=False)

    def get_temp_dir(self):
        return self._temp_dir
