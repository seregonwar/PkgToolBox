"""Central package detection and construction."""

from __future__ import annotations

import os
import struct

from .exceptions import PackageFormatError
from .package_ps3 import PackagePS3
from .package_ps4 import PackagePS4
from .package_ps5 import PackagePS5
from .gp5_project import GP5Project
from .gp4_project import GP4Project
from .file_source import StandaloneFileSource


def _cnt_names(path: str) -> set[str]:
    """Read only enough of a root CNT to distinguish PS4 SFO from PS5 JSON."""
    file_size = os.path.getsize(path)
    if file_size < 0x20:
        return set()
    with open(path, "rb") as fp:
        header = fp.read(min(file_size, 0x5A0))
        if len(header) < 0x20 or header[:4] != b"\x7fCNT":
            return set()
        count = struct.unpack_from(">I", header, 0x10)[0]
        table_offset = struct.unpack_from(">I", header, 0x18)[0]
        if not 0 < count <= 10000 or table_offset > file_size or count * 0x20 > file_size - table_offset:
            return set()
        fp.seek(table_offset)
        entries = []
        for _ in range(count):
            record = fp.read(0x20)
            if len(record) != 0x20:
                return set()
            entries.append(struct.unpack(">6I8x", record))
        names_entry = next((entry for entry in entries if entry[0] == 0x0200), None)
        if not names_entry:
            return set()
        names_offset, names_size = names_entry[4], names_entry[5]
        if names_offset > file_size or names_size > file_size - names_offset or names_size > 64 * 1024 * 1024:
            return set()
        fp.seek(names_offset)
        table = fp.read(names_size)
        found = set()
        for entry in entries:
            name_offset = entry[1]
            if not name_offset or name_offset >= len(table):
                continue
            end = table.find(b"\0", name_offset)
            if end < 0:
                continue
            found.add(table[name_offset:end].decode("utf-8", errors="ignore").replace("\\", "/").lower())
        return found


def detect_package_type(path: str) -> str:
    with open(path, "rb") as fp:
        magic_data = fp.read(4)
    if len(magic_data) != 4:
        raise PackageFormatError("file is too small to contain a PKG header")
    magic = struct.unpack(">I", magic_data)[0]
    if magic == PackagePS5.MAGIC_PS5:
        return "ps5"
    if magic == PackagePS3.MAGIC_PS3:
        return "ps3"
    if magic == PackagePS4.MAGIC_PS4:
        names = _cnt_names(path)
        if any(name == "param.json" or name.endswith("/param.json") for name in names):
            return "ps5-meta"
        return "ps4"
    raise PackageFormatError(f"Unknown PKG format: {magic:08X}")


def open_package(path: str):
    package_type = detect_package_type(path)
    if package_type in ("ps5", "ps5-meta"):
        return PackagePS5(path)
    if package_type == "ps4":
        return PackagePS4(path)
    return PackagePS3(path)


def detect_source_type(path: str) -> str:
    """Detect any source accepted by the desktop workspace."""
    if str(path).lower().endswith(".gp5"):
        # Construction performs strict XML validation; the extension only
        # selects the inexpensive detector path here.
        GP5Project(path)
        return "gp5"
    if str(path).lower().endswith(".gp4"):
        GP4Project(path)
        return "gp4"
    if not str(path).lower().endswith(".pkg"):
        StandaloneFileSource(path)
        return "file"
    return detect_package_type(path)


def open_source(path: str):
    """Open a package, GP4/GP5 publishing project, or standalone file."""
    if str(path).lower().endswith(".gp5"):
        return GP5Project(path)
    if str(path).lower().endswith(".gp4"):
        return GP4Project(path)
    if str(path).lower().endswith(".pkg"):
        return open_package(path)
    return StandaloneFileSource(path)
