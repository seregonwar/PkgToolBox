import struct
import io
import zipfile
from typing import List, Optional

class Utils:
    @staticmethod
    def hex_to_binary(hex_string: str) -> bytes:
        return bytes.fromhex(hex_string)

    @staticmethod
    def hex_to_dec(hex_bytes: bytes, reverse: str = "") -> int:
        if reverse == "reverse":
            hex_bytes = hex_bytes[::-1]
        return int.from_bytes(hex_bytes, byteorder='little')

    @staticmethod
    def read_write_data(file_to_use: str, file_to_use2: str = "", method_read_or_write_or_both: str = "", 
                        method_binary_or_integer: str = "", bin_data: Optional[bytes] = None, 
                        bin_data2: int = 0, offset: int = 0, count: int = 0):
        if method_read_or_write_or_both == "r":
            with open(file_to_use, "rb") as f:
                return f.read()
        elif method_read_or_write_or_both == "w":
            with open(file_to_use, "ab") as f:
                if method_binary_or_integer == "bi":
                    f.write(bin_data)
                elif method_binary_or_integer == "in":
                    f.write(bin_data2.to_bytes(4, byteorder='little'))
        elif method_read_or_write_or_both == "b":
            with open(file_to_use, "rb") as fr, open(file_to_use2, "ab") as fw:
                working_buffer_size = min(4096, count) if count > 0 else 4096
                fr.seek(offset)
                while True:
                    buffer = fr.read(working_buffer_size)
                    if not buffer:
                        break
                    fw.write(buffer)
                    if count > 0:
                        count -= len(buffer)
                        if count <= 0:
                            break
                        working_buffer_size = min(working_buffer_size, count)

    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        return a == b

    @staticmethod
    def extract_file_to_directory(zip_file_name: str, output_directory: str):
        with zipfile.ZipFile(zip_file_name, 'r') as zip_ref:
            zip_ref.extract("TheFileToExtract", output_directory)

    @staticmethod
    def byte_to_string(buff: bytes) -> str:
        return buff.hex().upper()

    @staticmethod
    def generate_stream_from_string(s: str) -> io.BytesIO:
        return io.BytesIO(s.encode())

    @staticmethod
    def read_uint32(stream: io.BytesIO) -> int:
        return struct.unpack('<I', stream.read(4))[0]

    @staticmethod
    def read_uint16(stream: io.BytesIO) -> int:
        return struct.unpack('<H', stream.read(2))[0]

    @staticmethod
    def read_ascii_string(stream: io.BytesIO, length: int) -> str:
        return stream.read(length).decode('ascii')

    @staticmethod
    def read_utf8_string(stream: io.BytesIO, length: int) -> str:
        return stream.read(length).decode('utf-8')

    @staticmethod
    def read_byte(stream: io.BytesIO, length: int) -> bytes:
        return stream.read(length)

    @staticmethod
    def bytes_to_bitmap(img_bytes: bytes):
        # This would require a Python imaging library like Pillow
        from PIL import Image
        import io
        return Image.open(io.BytesIO(img_bytes))

    @staticmethod
    def is_linux() -> bool:
        import platform
        return platform.system() == "Linux"

    @staticmethod
    def contain(a: bytes, b: bytes) -> bool:
        return a == b

    @staticmethod
    def hex_to_string(hex_string: str) -> str:
        return bytes.fromhex(hex_string).decode('ascii')

    @staticmethod
    def hex(byte: int) -> str:
        return f"{byte:02X}"

    @staticmethod
    def byte_array_to_little_endian_integer(bits: bytes) -> int:
        return int.from_bytes(bits, byteorder='little')

    @staticmethod
    def byte_arrays_equal(first: bytes, second: bytes) -> bool:
        return first == second

    @staticmethod
    def byte_array_to_utf8_string(byte_array: bytes) -> str:
        return byte_array.decode('utf-8')

    @staticmethod
    def byte_array_to_hex_string(bytes_input: bytes) -> str:
        return bytes_input.hex().upper()

    @staticmethod
    def hex_string_to_long(str_hex: str) -> int:
        return int(str_hex, 16)

    @staticmethod
    def create_jagged_array(lengths: List[int]):
        def create_inner(index: int):
            if index == len(lengths) - 1:
                return [None] * lengths[index]
            return [create_inner(index + 1) for _ in range(lengths[index])]
        return create_inner(0)

    @staticmethod
    def clamp(value: int, min_value: int, max_value: int) -> int:
        return max(min(value, max_value), min_value)

    @staticmethod
    def clamp16(value: int) -> int:
        return Utils.clamp(value, -32768, 32767)

    @staticmethod
    def clamp4(value: int) -> int:
        return Utils.clamp(value, -8, 7)


