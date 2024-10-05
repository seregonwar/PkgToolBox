import hashlib
import struct

class TrophyFile:
    def __init__(self, file_path=None):
        self.SHA1 = ""
        self.Bytes = None
        self.Readbytes = False
        self.trophyItemList = []
        self._iserror = False
        self._error = ""
        self._inputfile = ""
        self._calculatedsha1 = ""
        self.trphy = self.TrophyHeader()

        if file_path:
            self.load(file_path)

    class TrophyHeader:
        def __init__(self):
            self.magic = bytearray(4)
            self.version = bytearray(4)
            self.file_size = bytearray(8)
            self.files_count = bytearray(4)
            self.element_size = bytearray(4)
            self.dev_flag = bytearray(4)
            self.sha1 = bytearray(20)
            self.padding = bytearray(36)

    class TrophyItem:
        def __init__(self, index, name, offset, size, total_bytes):
            self.Index = index
            self.Name = name
            self.Offset = offset
            self.Size = size
            self.TotalBytes = total_bytes

    @property
    def file_count(self):
        return struct.unpack('<I', self.trphy.files_count)[0]

    @property
    def version(self):
        return struct.unpack('<I', self.trphy.version)[0]

    def load_header(self, fs):
        hdr = self.TrophyHeader()
        hdr.magic = fs.read(4)
        hdr.version = fs.read(4)
        hdr.file_size = fs.read(8)
        hdr.files_count = fs.read(4)
        hdr.element_size = fs.read(4)
        hdr.dev_flag = fs.read(4)
        version = struct.unpack('<I', hdr.version)[0]
        if 1 <= version <= 3:
            if version == 1:
                hdr.padding = fs.read(36)
            elif version == 2:
                hdr.sha1 = fs.read(20)
                hdr.padding = fs.read(16)
            elif version == 3:
                hdr.sha1 = fs.read(20)
                hdr.padding = fs.read(48)
        return hdr

    def read_content(self, fs):
        for i in range(self.file_count):
            array = fs.read(36)
            array2 = fs.read(4)
            array3 = fs.read(8)
            array4 = fs.read(4)
            fs.seek(12, 1)
            name = array.decode('utf-8').replace('\0', '')
            offset = int.from_bytes(array2, 'little')
            size = int.from_bytes(array3, 'little')
            if self.Readbytes:
                with memoryview(self.Bytes) as mv:
                    total_bytes = mv[offset:offset + size].tobytes()
                    self.trophyItemList.append(self.TrophyItem(i, name, offset, size, total_bytes))
            else:
                self.trophyItemList.append(self.TrophyItem(i, name, offset, size, None))

    def calculate_sha1_hash(self):
        if self.version > 1:
            sha1 = hashlib.sha1()
            with memoryview(self.Bytes) as mv:
                sha1.update(mv[:28])
                sha1.update(b'\x00' * 20)
                sha1.update(mv[48:])
            return sha1.hexdigest().upper()
        return None

    def load(self, file_path):
        self.SHA1 = ""
        self.trophyItemList = []
        with open(file_path, 'rb') as file_stream:
            self.Bytes = file_stream.read()
            file_stream.seek(0)
            self.trphy = self.load_header(file_stream)
            if self.trphy.magic != b'\xdc\xa2\x4d\x00':
                raise Exception("This file is not supported!")
            self.read_content(file_stream)
            if self.version > 1:
                self.SHA1 = self.calculate_sha1_hash()

    def extract_file_to_memory(self, filename):
        for item in self.trophyItemList:
            if item.Name == filename:
                with memoryview(self.Bytes) as mv:
                    return mv[item.Offset:item.Offset + item.Size].tobytes()
        return None
