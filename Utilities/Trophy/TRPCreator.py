import os
import re
import hashlib
from decimal import Decimal
from io import BytesIO

class Archiver:
    def __init__(self, index, name, offset, size, bytes_data):
        self.index = index
        self.name = name
        self.offset = offset
        self.size = size
        self.bytes = bytes_data

class TRPCreator:
    def __init__(self):
        self._hdr = self.TRPHeader()
        self._trophyList = []
        self._hdrmagic = bytearray([220, 162, 77, 0])
        self._iserror = False
        self._setversion = 0

    @property
    def SetVersion(self):
        return self._setversion

    @SetVersion.setter
    def SetVersion(self, value):
        self._setversion = value

    def Create(self, filename, contents):
        if self._setversion < 1 or self._setversion > 3:
            raise Exception("File version must be one of these { 1, 2, 3 }.")
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
            bytes2 = item.offset.to_bytes(4, 'big')
            memoryStream.write(bytes2)
            bytes3 = item.size.to_bytes(4, 'big')
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
        trpHeader.version = version.to_bytes(4, 'big')
        memoryStream.write(trpHeader.version)
        trpHeader.file_size = file_size.to_bytes(8, 'big')
        memoryStream.write(trpHeader.file_size)
        trpHeader.files_count = files_count.to_bytes(4, 'big')
        memoryStream.write(trpHeader.files_count)
        trpHeader.element_size = element_size.to_bytes(4, 'big')
        memoryStream.write(trpHeader.element_size)
        trpHeader.dev_flag = dev_flag.to_bytes(4, 'big')
        memoryStream.write(trpHeader.dev_flag)
        if version in [1, 2]:
            memoryStream.write(bytearray(36))
        elif version == 3:
            memoryStream.write(bytearray(20))
            memoryStream.write(bytearray([48, 49, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
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
