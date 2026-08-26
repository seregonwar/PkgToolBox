"""Parser for SELF (SCE ELF) containers and bare ELF headers.

Ported from LibProsperoPkg's ``ProsperoFself`` (C#) reader so PS4/PS5
executables (``eboot.bin``, ``*.sprx``) can be inspected without the native
library.  A SELF image starts with a 0x20-byte SCE header, followed by a
segment table (0x20 bytes per segment), the original ELF header plus program
headers, an extended-info block (authority id, versions, digest) and finally
the plaintext (or encrypted) segment data.

Only the header region is needed for inspection, so callers can feed a
``header_size``-sized prefix instead of the whole file.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Optional

from .exceptions import PackageFormatError

SELF_MAGIC = 0x1D3D154F
ELF_MAGIC = b"\x7fELF"

SCE_HEADER_SIZE = 0x20
SEG_ENTRY_SIZE = 0x20
EXT_INFO_SIZE = 0x40

#: ELF e_machine values.
ELF_MACHINES = {
    0x00: "None",
    0x02: "SPARC",
    0x03: "i386",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x16: "S390",
    0x28: "ARM",
    0x2A: "SuperH",
    0x32: "IA-64",
    0x3E: "x86-64",
    0x8C: "TMS320C6000",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}

#: ELF e_type values (including the SCE/Orbis extensions).
ELF_TYPES = {
    0x00: "ET_NONE",
    0x01: "ET_REL (relocatable)",
    0x02: "ET_EXEC (executable)",
    0x03: "ET_DYN (shared object)",
    0x04: "ET_CORE (core dump)",
    0xFE00: "ET_SCE_EXEC (PS executable)",
    0xFE10: "ET_SCE_RELEXEC (PS relocatable executable)",
    0xFF00: "ET_LOOS (OS-specific)",
}

#: SCE header program type (u32 at 0x08).
SELF_PROGRAM_TYPES = {
    0x00000101: "default (eboot)",
    0x00000102: "library",
    0x00000104: "module",
    0x00000108: "system module",
    0x0000010C: "system library",
    0x0000010D: "system utility",
    0x0000010E: "system debug",
    0x0000010F: "system nondebug",
    0x00000110: "system kernelfw",
}

#: Fake-self authority-id prefix used by LibProsperoPkg / fpk tooling.
FAKE_AUTHORITY_PREFIX = 0x31


@dataclass(frozen=True)
class SelfSegment:
    """One entry from the SELF segment table."""

    flags: int
    file_offset: int
    file_size: int
    mem_size: int

    @property
    def id(self) -> int:
        """Segment id (bits 20..35); for data segments this is the program-header index."""
        return (self.flags >> 20) & 0xFFFF

    @property
    def ordered(self) -> bool:
        return (self.flags & 0x1) != 0

    @property
    def encrypted(self) -> bool:
        return (self.flags & 0x2) != 0

    @property
    def signed(self) -> bool:
        return (self.flags & 0x4) != 0

    @property
    def compressed(self) -> bool:
        return (self.flags & 0x8) != 0

    @property
    def blocked(self) -> bool:
        return (self.flags & 0x800) != 0


@dataclass(frozen=True)
class SelfExtInfo:
    """Extended info (0x40 bytes) that follows the ELF program headers."""

    authority_id: int
    program_type: int
    app_version: int
    firmware_version: int
    digest: bytes


@dataclass(frozen=True)
class ElfHeader:
    """Decoded ELF identification + header fields (ELF32 or ELF64)."""

    elf_class: int       # 1 = 32-bit, 2 = 64-bit
    data: int            # 1 = little endian, 2 = big endian
    version: int
    osabi: int
    abi_version: int
    e_type: int
    e_machine: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int

    @property
    def class_name(self) -> str:
        return {1: "32-bit", 2: "64-bit"}.get(self.elf_class, f"class-{self.elf_class}")

    @property
    def endian_name(self) -> str:
        return {1: "little-endian", 2: "big-endian"}.get(self.data, f"data-{self.data}")

    @property
    def machine_name(self) -> str:
        return ELF_MACHINES.get(self.e_machine, f"0x{self.e_machine:04X}")

    @property
    def type_name(self) -> str:
        return ELF_TYPES.get(self.e_type, f"0x{self.e_type:04X}")


@dataclass(frozen=True)
class SelfInfo:
    """A parsed SELF image (SCE header + segments + embedded ELF + ext info)."""

    magic: int
    version: int
    mode: int
    endian: int
    attributes: int
    program_type: int
    header_size: int
    meta_size: int
    file_size: int
    segment_count: int
    flags: int
    segments: tuple[SelfSegment, ...]
    elf: Optional[ElfHeader]
    ext_info: Optional[SelfExtInfo]

    @property
    def mode_name(self) -> str:
        return {0: "debug", 1: "retail"}.get(self.mode, f"0x{self.mode:02X}")

    @property
    def program_type_name(self) -> str:
        return SELF_PROGRAM_TYPES.get(
            self.program_type, f"0x{self.program_type:08X}"
        )

    @property
    def is_fake(self) -> bool:
        """True when the SELF carries a fake-authority id (0x31.. prefix)."""
        if self.ext_info is not None:
            return (self.ext_info.authority_id >> 56) == FAKE_AUTHORITY_PREFIX
        return False

    @property
    def encrypted_segments(self) -> int:
        return sum(1 for seg in self.segments if seg.encrypted)

    @property
    def compressed_segments(self) -> int:
        return sum(1 for seg in self.segments if seg.compressed)


def detect_kind(data: bytes) -> str:
    """Return ``'self'``, ``'elf'`` or ``'unknown'`` for the given prefix."""
    if len(data) >= 4:
        if struct.unpack_from("<I", data, 0)[0] == SELF_MAGIC:
            return "self"
        if data[:4] == ELF_MAGIC:
            return "elf"
    return "unknown"


def parse_elf_header(data: bytes, offset: int = 0) -> Optional[ElfHeader]:
    """Parse the ELF identification and header at ``offset``.

    Returns None when the data is not a valid ELF header.
    """
    if len(data) < offset + 0x40 or data[offset:offset + 4] != ELF_MAGIC:
        return None
    ident = data[offset:offset + 16]
    elf_class, elf_data, version, osabi, abi_version = (
        ident[4], ident[5], ident[6], ident[7], ident[8]
    )
    if elf_class == 2:  # ELF64
        # e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
        # e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
        fields = struct.unpack_from("<HHIQQQIHHHHHH", data, offset + 0x10)
        return ElfHeader(
            elf_class, elf_data, version, osabi, abi_version,
            fields[0],  # e_type
            fields[1],  # e_machine
            fields[3],  # e_entry
            fields[4],  # e_phoff
            fields[5],  # e_shoff
            fields[6],  # e_flags
            fields[7],  # e_ehsize
            fields[8],  # e_phentsize
            fields[9],  # e_phnum
            fields[10],  # e_shentsize
            fields[11],  # e_shnum
            fields[12],  # e_shstrndx
        )
    if elf_class == 1 and len(data) >= offset + 0x34:  # ELF32
        fields = struct.unpack_from("<HHIIIIIHHHHHH", data, offset + 0x10)
        return ElfHeader(
            elf_class, elf_data, version, osabi, abi_version,
            fields[0],  # e_type
            fields[1],  # e_machine
            fields[3],  # e_entry
            fields[4],  # e_phoff
            fields[5],  # e_shoff
            fields[6],  # e_flags
            fields[7],  # e_ehsize
            fields[8],  # e_phentsize
            fields[9],  # e_phnum
            fields[10],  # e_shentsize
            fields[11],  # e_shnum
            fields[12],  # e_shstrndx
        )
    return None


def parse_self(data: bytes) -> SelfInfo:
    """Parse a SELF image from a buffer holding at least the header region."""
    if len(data) < SCE_HEADER_SIZE:
        raise PackageFormatError("buffer is smaller than an SCE header")
    magic, = struct.unpack_from("<I", data, 0)
    if magic != SELF_MAGIC:
        raise PackageFormatError(f"bad SCE magic: 0x{magic:08X}")

    version, mode, endian, attributes = data[0x04], data[0x05], data[0x06], data[0x07]
    program_type, = struct.unpack_from("<I", data, 0x08)
    header_size, meta_size = struct.unpack_from("<HH", data, 0x0C)
    file_size, = struct.unpack_from("<Q", data, 0x10)
    segment_count, flags = struct.unpack_from("<HH", data, 0x18)

    table_end = SCE_HEADER_SIZE + segment_count * SEG_ENTRY_SIZE
    if table_end > len(data):
        raise PackageFormatError("segment table overruns the buffer")
    if header_size > len(data):
        raise PackageFormatError("header size exceeds the buffer")

    segments = []
    for index in range(segment_count):
        entry = SCE_HEADER_SIZE + index * SEG_ENTRY_SIZE
        seg_flags, seg_offset, seg_size, seg_mem = struct.unpack_from("<4Q", data, entry)
        segments.append(SelfSegment(seg_flags, seg_offset, seg_size, seg_mem))

    elf_start = table_end
    elf = parse_elf_header(data, elf_start)
    ext_info = None
    if elf is not None:
        elf_len = elf.e_ehsize + elf.e_phnum * elf.e_phentsize
        ext_start = (elf_start + elf_len + 0xF) & ~0xF
        if (ext_start + EXT_INFO_SIZE <= header_size
                and ext_start + EXT_INFO_SIZE <= len(data)):
            authority, ext_ptype, app_version, fw_version = struct.unpack_from(
                "<4Q", data, ext_start
            )
            digest = data[ext_start + 0x20:ext_start + 0x40]
            ext_info = SelfExtInfo(authority, ext_ptype, app_version, fw_version, digest)

    return SelfInfo(
        magic, version, mode, endian, attributes, program_type,
        header_size, meta_size, file_size, segment_count, flags,
        tuple(segments), elf, ext_info,
    )


def format_packed_version(value: int) -> str:
    """Format a SELF extended-info version (u64 of BCD-style components).

    The value is written little-endian; its big-endian byte components read as
    ``major.minor...`` (e.g. ``0x0100`` -> ``01.00``).
    """
    hexstr = f"{value:016x}"
    pairs = [hexstr[index:index + 2] for index in range(0, 16, 2)]
    while len(pairs) > 1 and pairs[0] == "00":
        pairs.pop(0)
    return ".".join(pairs) or "00"
