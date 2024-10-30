import os
import hashlib
import struct
import logging
from io import BytesIO
from decimal import Decimal
import re
from pathlib import Path

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Archiver:
    def __init__(self, index, name, offset, size, bytes_data):
        self.index = index
        self.name = name
        self.offset = offset
        self.size = size
        self.bytes = bytes_data

class TRPCreator:
    class TRPHeader:
        def __init__(self):
            self.magic = None
            self.version = None
            self.file_size = None
            self.files_count = None
            self.element_size = None
            self.dev_flag = None
            self.sha1 = None
            self.padding = None

    def __init__(self):
        self._hdr = self.TRPHeader()
        self._trophyList = []
        self._hdrmagic = bytearray([220, 162, 77, 0])
        self._iserror = False
        self._setversion = 0
        self._set_title = None # Added set_title attribute
        self.header_size = 0x400
        self.trophy_size = 0x200
        self.image_size = 0x12000

    @property 
    def SetVersion(self):
        return self._setversion

    @SetVersion.setter
    def SetVersion(self, value):
        self._setversion = value
        
    @property
    def set_title(self): # Added set_title property
        return self._set_title
        
    @set_title.setter 
    def set_title(self, value):
        self._set_title = value

    def Create(self, filename, contents):
        try:
            if self._setversion < 1 or self._setversion > 3:
                raise ValueError("File version must be one of these { 1, 2, 3 }.")
            self._trophyList.clear()
            contents = self.SortList(contents)
            memoryStream = BytesIO()
            num1 = 0
            count = len(contents)
            num2 = 64 * len(contents)
            for m_Index, path in enumerate(contents):
                fileName = os.path.basename(path)
                with open(path, 'rb') as f:
                    m_Bytes = f.read()
                length = len(m_Bytes)
                pads = self.GetPads(length, 16)
                num1 += pads
                self._trophyList.append(Archiver(m_Index, fileName, int(Decimal(num2) + Decimal(96 if self._setversion == 3 else 64)), length, m_Bytes))
                num2 = int(Decimal(num2) + Decimal(length) + Decimal(pads))
            size = self.GetSize()
            header = self.GetHeader(self._setversion, int(Decimal((96 if self._setversion == 3 else 64) + len(self.GetHeaderFiles()) + size + num1)), count, 64, 0, None)
            memoryStream.write(header)
            headerFiles = self.GetHeaderFiles()
            memoryStream.write(headerFiles)
            bytes1 = self.GetBytes()
            memoryStream.write(bytes1)
            if self._setversion > 1:
                bytes2 = self.HexStringToBytes(self.CalculateSHA1Hash(memoryStream.getvalue()))
                memoryStream.seek(28)
                memoryStream.write(bytes2)
            with open(filename, 'wb') as f:
                f.write(memoryStream.getvalue())
            logger.info(f"File '{filename}' created successfully.")
        except Exception as e:
            logger.error(f"Error creating file: {e}")
            raise

    def CreateFromList(self, filename, contents):
        if self._setversion < 1 or self._setversion > 3:
            raise Exception("File version must be one of these { 1, 2, 3 }.")
        self._trophyList.clear()
        memoryStream = BytesIO()
        num1 = 0
        count = len(contents)
        num2 = 64 * len(contents)
        for m_Index, content in enumerate(contents):
            name = content.name
            bytes_data = content.bytes
            size = content.size
            pads = self.GetPads(size, 16)
            num1 += pads
            self._trophyList.append(Archiver(m_Index, name, int(Decimal(num2) + Decimal(96 if self._setversion == 3 else 64)), size, bytes_data))
            num2 = int(Decimal(num2) + Decimal(size) + Decimal(pads))
        size1 = self.GetSize()
        header = self.GetHeader(self._setversion, int(Decimal((96 if self._setversion == 3 else 64) + len(self.GetHeaderFiles()) + size1 + num1)), count, 64, 0, None)
        memoryStream.write(header)
        headerFiles = self.GetHeaderFiles()
        memoryStream.write(headerFiles)
        bytes1 = self.GetBytes()
        memoryStream.write(bytes1)
        if self._setversion > 1:
            bytes2 = self.HexStringToBytes(self.CalculateSHA1Hash(memoryStream.getvalue()))
            memoryStream.seek(28)
            memoryStream.write(bytes2)
        with open(filename, 'wb') as f:
            f.write(memoryStream.getvalue())

    def SortList(self, alist):
        patterns = [
            "TROPCONF.(E?)SFM",
            "TROP.(E?)SFM", 
            "TROP_\\d+.(E?)SFM",
            "ICON0.PNG",
            "ICON0_\\d+.PNG",
            "GR\\d+.PNG",
            "GR\\d+_\\d+.PNG",
            "TROP\\d+.PNG"
        ]
        arrayList1, arrayList2, arrayList3, arrayList4, arrayList5 = [], [], [], [], []
        for pattern in patterns:
            for item in alist:
                if re.match(pattern, os.path.basename(item), re.IGNORECASE):
                    if os.path.basename(item).upper().startswith("TROPCONF"):
                        arrayList1.append(item)
                    elif os.path.basename(item).upper().endswith("SFM"):
                        arrayList2.append(item)
                    elif os.path.basename(item).upper().startswith("ICON"):
                        arrayList3.append(item)
                    elif os.path.basename(item).upper().startswith("GR"):
                        arrayList4.append(item)
                    elif os.path.basename(item).upper().endswith("PNG"):
                        arrayList5.append(item)
        arrayList2.sort()
        arrayList3.sort()
        arrayList4.sort()
        arrayList5.sort()
        arrayList1.extend(arrayList2)
        arrayList1.extend(arrayList3)
        arrayList1.extend(arrayList4)
        arrayList1.extend(arrayList5)
        return arrayList1

    def GetHeaderFiles(self):
        buffer1 = bytearray([0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        buffer2 = bytearray([0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        memoryStream = BytesIO()
        for item in self._trophyList:
            bytes1 = item.name.encode('ascii')
            bytes1 = bytes1.ljust(32, b'\0')
            memoryStream.write(bytes1)
            bytes2 = item.offset.to_bytes(4, 'big')      # Cambiato da 'little' a 'big'
            memoryStream.write(bytes2)
            bytes3 = item.size.to_bytes(4, 'big')        # Cambiato da 'little' a 'big'
            memoryStream.write(bytes3)
            if item.name.upper().endswith(".SFM"):
                memoryStream.write(buffer1)
            elif item.name.upper().endswith(".ESFM"):
                memoryStream.write(buffer2)
            else:
                memoryStream.write(bytearray(16))
        return memoryStream.getvalue()

    def GetSize(self):
        uint64 = 0
        for item in self._trophyList:
            uint64 += item.size
        return uint64

    def GetBytes(self):
        memoryStream = BytesIO()
        for item in self._trophyList:
            memoryStream.write(item.bytes)
            pads = self.GetPads(len(item.bytes), 16)
            if pads >= 0:
                memoryStream.write(bytearray(pads))
        return memoryStream.getvalue()

    def GetHeader(self, version, file_size, files_count, element_size, dev_flag, sha1):
        trpHeader = self.TRPHeader()
        memoryStream = BytesIO()
        trpHeader.magic = self._hdrmagic
        memoryStream.write(trpHeader.magic)
        trpHeader.version = version.to_bytes(4, 'big')          # Cambiato da 'little' a 'big'
        memoryStream.write(trpHeader.version)
        trpHeader.file_size = file_size.to_bytes(8, 'big')      # Cambiato da 'little' a 'big'
        memoryStream.write(trpHeader.file_size)
        trpHeader.files_count = files_count.to_bytes(4, 'big')  # Cambiato da 'little' a 'big'
        memoryStream.write(trpHeader.files_count)
        trpHeader.element_size = element_size.to_bytes(4, 'big')# Cambiato da 'little' a 'big'
        memoryStream.write(trpHeader.element_size)
        trpHeader.dev_flag = dev_flag.to_bytes(4, 'big')        # Cambiato da 'little' a 'big'
        memoryStream.write(trpHeader.dev_flag)
        if version in [1, 2]:
            memoryStream.write(bytearray(36))
        elif version == 3:
            memoryStream.write(bytearray(20))
            memoryStream.write(bytearray([48, 49, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
        self._hdr = trpHeader
        return memoryStream.getvalue()

    def CalculateSHA1Hash(self, byte_data):
        sha1 = hashlib.sha1()
        sha1.update(byte_data)
        return sha1.hexdigest().upper()

    def HexStringToBytes(self, strInput):
        if not self.HexStringIsValid(strInput):
            return None
        return bytes.fromhex(strInput)

    def BytesToHexString(self, bytes_Input):
        return ''.join(f'{b:02X}' for b in bytes_Input)

    def HexStringIsValid(self, Hex):
        return all(c in '0123456789ABCDEFabcdef' for c in Hex)

    def GetPads(self, fsize, align=16):
        num = 0
        while (fsize + num) % align != 0:
            num += 1
        return num

    def create(self, output_path, trophy_files):
        """Create TRP file from trophy files"""
        try:
            # Ordina i file per nome per mantenere l'ordine corretto
            trophy_files = sorted(trophy_files, key=lambda x: x.name)
            
            # Calcola le dimensioni
            total_size = (
                self.header_size +  # Header
                (len(trophy_files) * self.trophy_size) +  # Trophy entries
                (len([f for f in trophy_files if f.name.upper().endswith('.PNG')]) * self.image_size)  # Images
            )
            
            # Crea il file TRP
            with open(output_path, 'wb') as f:
                # Scrivi l'header
                header = struct.pack('<4sIQII',
                    b'\xDC\xA2\x4D\x00',  # Magic
                    1,                     # Version
                    total_size,            # File size
                    len(trophy_files),     # Number of files
                    self.trophy_size       # Trophy entry size
                )
                f.write(header)
                
                # Padding fino a 0x400
                f.write(b'\x00' * (self.header_size - len(header)))
                
                # Scrivi i trofei
                for trophy in trophy_files:
                    if not trophy.name.upper().endswith('.PNG'):
                        continue
                        
                    # Leggi i dati del trofeo
                    with open(trophy.name, 'rb') as tf:
                        trophy_data = tf.read()
                    
                    # Scrivi i dati del trofeo
                    f.write(trophy_data[:self.trophy_size])
                    
                    # Padding se necessario
                    if len(trophy_data) < self.trophy_size:
                        f.write(b'\x00' * (self.trophy_size - len(trophy_data)))
                
                # Scrivi le immagini
                for trophy in trophy_files:
                    if trophy.name.upper().endswith('.PNG'):
                        with open(trophy.name, 'rb') as tf:
                            image_data = tf.read()
                        
                        # Scrivi l'immagine
                        f.write(image_data)
                        
                        # Padding se necessario
                        if len(image_data) < self.image_size:
                            f.write(b'\x00' * (self.image_size - len(image_data)))
            
            logging.info(f"TRP file created successfully: {output_path}")
            return True
            
        except Exception as e:
            error_msg = f"Error creating TRP file: {str(e)}"
            logging.error(error_msg)
            raise Exception(error_msg)

    def validate_trophy_files(self, files):
        """Validate trophy files before creating TRP"""
        try:
            # Verifica che ci siano file
            if not files:
                raise ValueError("No trophy files provided")
            
            # Verifica che ci siano solo file PNG e dati trofeo
            valid_extensions = {'.PNG', '.DAT'}
            for f in files:
                ext = os.path.splitext(f.name)[1].upper()
                if ext not in valid_extensions:
                    raise ValueError(f"Invalid file type: {f.name}")
            
            # Verifica che ci sia almeno un'immagine
            png_files = [f for f in files if f.name.upper().endswith('.PNG')]
            if not png_files:
                raise ValueError("No trophy images found")
            
            return True
            
        except Exception as e:
            error_msg = f"Trophy files validation failed: {str(e)}"
            logging.error(error_msg)
            raise Exception(error_msg)