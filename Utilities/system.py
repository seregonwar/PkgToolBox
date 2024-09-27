import struct
from enum import Enum
from io import BytesIO

class EndianType(Enum):
    BigEndian = 'big'
    LittleEndian = 'little'

class EndianIO:
    def __init__(self, file_name=None, endian_type=EndianType.LittleEndian, file_mode='r+b', file_access='r+b', file_share=None, stream=None, byte_array=None):
        self.file_name = file_name
        self.endian_type = endian_type
        self.file_mode = file_mode
        self.file_access = file_access
        self.file_share = file_share
        self.stream = stream
        self.byte_array = byte_array
        self.opened = False
        self.in_stream = None
        self.out_stream = None

        if file_name:
            self.stream = open(file_name, file_mode)
        elif byte_array:
            self.stream = BytesIO(byte_array)
        elif stream:
            self.stream = stream

        if self.stream:
            self.open()

    def open(self):
        if self.opened:
            self.close()
        if self.stream:
            self.in_stream = EndianReader(self.stream, self.endian_type)
            self.out_stream = EndianWriter(self.stream, self.endian_type)
            self.opened = True

    def close(self):
        if self.opened:
            self.stream.close()
            self.opened = False

    def seek_to(self, position, origin=0):
        self.stream.seek(position, origin)

    def to_array(self):
        if isinstance(self.stream, BytesIO):
            return self.stream.getvalue()
        else:
            self.stream.seek(0)
            return self.stream.read()

    @property
    def position(self):
        return self.stream.tell()

    @position.setter
    def position(self, value):
        self.stream.seek(value)

    def __del__(self):
        self.close()

class EndianReader:
    def __init__(self, stream, endian_type=EndianType.LittleEndian):
        self.stream = stream
        self.endian_type = endian_type

    def seek_to(self, position, origin=0):
        self.stream.seek(position, origin)

    def read_bytes(self, count):
        return self.stream.read(count)

    def read_int16(self):
        return struct.unpack(self.endian_type.value + 'h', self.read_bytes(2))[0]

    def read_uint16(self):
        return struct.unpack(self.endian_type.value + 'H', self.read_bytes(2))[0]

    def read_int32(self):
        return struct.unpack(self.endian_type.value + 'i', self.read_bytes(4))[0]

    def read_uint32(self):
        return struct.unpack(self.endian_type.value + 'I', self.read_bytes(4))[0]

    def read_int64(self):
        return struct.unpack(self.endian_type.value + 'q', self.read_bytes(8))[0]

    def read_uint64(self):
        return struct.unpack(self.endian_type.value + 'Q', self.read_bytes(8))[0]

    def read_float(self):
        return struct.unpack(self.endian_type.value + 'f', self.read_bytes(4))[0]

    def read_double(self):
        return struct.unpack(self.endian_type.value + 'd', self.read_bytes(8))[0]

    def read_string(self, length):
        return self.read_bytes(length).decode('ascii').replace('\0', '')

    def read_unicode_string(self, length):
        return self.read_bytes(length * 2).decode('utf-16').replace('\0', '')

class EndianWriter:
    def __init__(self, stream, endian_type=EndianType.LittleEndian):
        self.stream = stream
        self.endian_type = endian_type

    def seek_to(self, position, origin=0):
        self.stream.seek(position, origin)

    def write_bytes(self, data):
        self.stream.write(data)

    def write_int16(self, value):
        self.write_bytes(struct.pack(self.endian_type.value + 'h', value))

    def write_uint16(self, value):
        self.write_bytes(struct.pack(self.endian_type.value + 'H', value))

    def write_int32(self, value):
        self.write_bytes(struct.pack(self.endian_type.value + 'i', value))

    def write_uint32(self, value):
        self.write_bytes(struct.pack(self.endian_type.value + 'I', value))

    def write_int64(self, value):
        self.write_bytes(struct.pack(self.endian_type.value + 'q', value))

    def write_uint64(self, value):
        self.write_bytes(struct.pack(self.endian_type.value + 'Q', value))

    def write_float(self, value):
        self.write_bytes(struct.pack(self.endian_type.value + 'f', value))

    def write_double(self, value):
        self.write_bytes(struct.pack(self.endian_type.value + 'd', value))

    def write_string(self, value):
        self.write_bytes(value.encode('ascii'))

    def write_unicode_string(self, value):
        self.write_bytes(value.encode('utf-16'))

# End of Selection