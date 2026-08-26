"""Small checked binary-reading primitives shared by PKG parsers."""

from __future__ import annotations

import os
import struct

from .exceptions import PackageBoundsError, PackageFormatError


def checked_range(offset: int, size: int, limit: int, label: str = "range") -> tuple[int, int]:
    if not isinstance(offset, int) or not isinstance(size, int):
        raise PackageBoundsError(f"{label} offset and size must be integers")
    if offset < 0 or size < 0 or offset > limit or size > limit - offset:
        raise PackageBoundsError(
            f"{label} is outside its container: offset=0x{offset:X}, "
            f"size=0x{size:X}, limit=0x{limit:X}"
        )
    return offset, offset + size


class BinaryReader:
    """Random-access reader that rejects short and out-of-range reads."""

    def __init__(self, fp, size: int | None = None):
        self.fp = fp
        if size is None:
            current = fp.tell()
            fp.seek(0, os.SEEK_END)
            size = fp.tell()
            fp.seek(current)
        self.size = size

    def read_at(self, offset: int, size: int, label: str = "data") -> bytes:
        checked_range(offset, size, self.size, label)
        self.fp.seek(offset)
        data = self.fp.read(size)
        if len(data) != size:
            raise PackageBoundsError(f"truncated {label}: expected {size} bytes, got {len(data)}")
        return data

    def unpack_at(self, fmt: str, offset: int, label: str = "field"):
        size = struct.calcsize(fmt)
        values = struct.unpack(fmt, self.read_at(offset, size, label))
        return values[0] if len(values) == 1 else values


def decode_c_string(data: bytes, encoding: str = "utf-8") -> str:
    raw = data.split(b"\0", 1)[0]
    try:
        return raw.decode(encoding)
    except UnicodeDecodeError as exc:
        raise PackageFormatError(f"invalid {encoding} string") from exc
