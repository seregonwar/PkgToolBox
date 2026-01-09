import io
import struct
import zipfile
import enum
from typing import Optional


class EndianType(enum.Enum):
    BigEndian = "big"
    LittleEndian = "little"


class Utils:
    @staticmethod
    def hex2binary(hex_str: str) -> bytes:
        return bytes.fromhex(hex_str)

    @staticmethod
    def hex_to_binary(hex_string: str) -> bytes:
        return bytes.fromhex(hex_string)

    @staticmethod
    def hex_to_dec(hex_bytes: bytes, reverse: str = "") -> int:
        if reverse == "reverse":
            hex_bytes = hex_bytes[::-1]
        return int.from_bytes(hex_bytes, byteorder="big")

    @staticmethod
    def read_write_data(
        file_to_use: str,
        file_to_use2: str = "",
        method_read_or_write_or_both: str = "",
        method_binary_or_integer: str = "",
        bin_data: Optional[bytes] = None,
        bin_data2: int = 0,
        offset: int = 0,
        count: int = 0,
    ):
        if method_read_or_write_or_both == "r":
            with open(file_to_use, "rb") as f:
                return f.read()
        elif method_read_or_write_or_both == "w":
            with open(file_to_use, "ab") as f:
                if method_binary_or_integer == "bi":
                    f.write(bin_data or b"")
                elif method_binary_or_integer == "in":
                    f.write(struct.pack("i", bin_data2))
        elif method_read_or_write_or_both == "b":
            with open(file_to_use, "rb") as fr, open(file_to_use2, "ab") as fw:
                fr.seek(offset)
                buffer_size = 4096
                while count > 0:
                    buffer = fr.read(min(buffer_size, count))
                    if not buffer:
                        break
                    fw.write(buffer)
                    count -= len(buffer)

    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        return a == b

    @staticmethod
    def extract_file_to_directory(zip_file_name: str, output_directory: str, member: str = None):
        with zipfile.ZipFile(zip_file_name, "r") as zip_ref:
            if member:
                zip_ref.extract(member, output_directory)
            else:
                zip_ref.extractall(output_directory)

    @staticmethod
    def byte_to_string(buff: bytes) -> str:
        return buff.hex().upper()

    @staticmethod
    def generate_stream_from_string(s: str) -> io.BytesIO:
        return io.BytesIO(s.encode())

    @staticmethod
    def read_uint32(stream: io.BytesIO) -> int:
        return struct.unpack("<I", stream.read(4))[0]

    @staticmethod
    def read_uint16(stream: io.BytesIO) -> int:
        return struct.unpack("<H", stream.read(2))[0]

    @staticmethod
    def read_ascii_string(stream: io.BytesIO, length: int) -> str:
        return stream.read(length).decode("ascii")

    @staticmethod
    def read_utf8_string(stream: io.BytesIO, length: int) -> str:
        return stream.read(length).decode("utf-8")

    @staticmethod
    def read_byte(stream: io.BytesIO, length: int) -> bytes:
        return stream.read(length)
