"""PS5 NAPS streaming layout (``naps_pkg_layout.dat``) decoder.

Pure-Python port of LibProsperoPkg's ``PKG/ProsperoNapsLayout.cs``. The on-disk
structure is the ``[PackageLayout_NAPS]`` header plus fixed-stride sections:

    header   16 bytes  (two packed 64-bit words with the section counts)
    outer    8 bytes   per outer-block digest
    shuffle  8 bytes   per shuffle pattern (0 when shuffling is unused)
    fidx     6 bytes   per file: 1 type byte + 40-bit uncompressed start offset
    u2c     10 bytes   per group of 8 ublocks: uint24 base + 7 deltas
    cblock   9 bytes   per compressed-block record (run-base or block form)

All strides and bit offsets are validated against reference packages in the
upstream implementation; this module reproduces the decode side exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct

from .exceptions import PackageFormatError


HEADER_SIZE = 16
OUTER_BLOCK_DIGEST_STRIDE = 8
SHUFFLE_PATTERN_STRIDE = 8
FILE_OFFSET_STRIDE = 6
U2C_STRIDE = 10
CBLOCKINFO_STRIDE = 9
DEFAULT_ALIGNMENT = 16


@dataclass(frozen=True)
class NapsCounts:
    num_files: int
    compression_type: int
    num_keys: int
    num_shuffle_patterns: int
    num_ublocks: int
    num_outer_blocks: int
    num_cblock_info: int

    @property
    def num_u2c_entries(self) -> int:
        return ((self.num_ublocks + 7) & ~7) >> 3


@dataclass(frozen=True)
class NapsSection:
    offset: int
    size: int
    stride: int
    count: int


@dataclass(frozen=True)
class NapsSectionMap:
    header: NapsSection
    outer_block_digest: NapsSection
    shuffle_pattern: NapsSection
    uncompressed_offset: NapsSection
    u2c: NapsSection
    cblock_info: NapsSection
    total_size: int


@dataclass(frozen=True)
class NapsFileOffsetEntry:
    type: int
    uncompressed_offset_start: int


@dataclass(frozen=True)
class NapsU2cEntry:
    info_offset_base: int
    deltas: tuple[int, ...]

    @property
    def start_cblockinfo_index(self) -> tuple[int, ...]:
        result = [self.info_offset_base]
        result.extend(self.info_offset_base + delta for delta in self.deltas)
        return tuple(result)


@dataclass(frozen=True)
class NapsCblockInfoEntry:
    raw: bytes
    is_run_base: bool
    coffset_start_mod_256k: int = 0
    uoffset_start: int = 0
    clen_even_minus_1: int = 0
    even: int = 0
    odd: int = 0
    kde_predictor: int = 0
    shuffle_idx: int = 0
    coffset_end_mod_256k: int = 0
    tweak_idx_start: int = 0
    key_table_idx: int = 0
    coffset_start_256k: int = 0


@dataclass
class NapsLayoutDocument:
    counts: NapsCounts
    section_map: NapsSectionMap
    outer_block_digests: list[bytes] = field(default_factory=list)
    shuffle_patterns: list[bytes] = field(default_factory=list)
    file_offsets: list[NapsFileOffsetEntry] = field(default_factory=list)
    u2c_entries: list[NapsU2cEntry] = field(default_factory=list)
    cblock_infos: list[NapsCblockInfoEntry] = field(default_factory=list)


def decode_header(blob: bytes) -> NapsCounts:
    """Decode the 16-byte ``[PackageLayout_NAPS]`` header into section counts."""
    if len(blob) < HEADER_SIZE:
        raise PackageFormatError(f"NAPS header needs {HEADER_SIZE} bytes")
    word0, word1 = struct.unpack_from("<QQ", blob, 0)

    num_files_minus_1 = word0 & 0xFFFFFF
    compression_type = (word0 >> 24) & 0x3
    num_keys_minus_1 = (word0 >> 26) & 0x3
    num_shuffle_patterns = (word0 >> 28) & 0xF
    num_ublocks = (word0 >> 32) & 0xFFFFFF

    num_outer_blocks = word1 & 0xFFFFFF
    num_cblock_info_minus_2 = (word1 >> 24) & 0xFFFFFF

    return NapsCounts(
        num_files=num_files_minus_1 + 1,
        compression_type=compression_type,
        num_keys=num_keys_minus_1 + 1,
        num_shuffle_patterns=num_shuffle_patterns,
        num_ublocks=num_ublocks,
        num_outer_blocks=num_outer_blocks,
        num_cblock_info=num_cblock_info_minus_2 + 2,
    )


def section_map(counts: NapsCounts) -> NapsSectionMap:
    """Compute the offset/size of every section from the counts."""
    pos = 0
    header = NapsSection(pos, HEADER_SIZE, HEADER_SIZE, 1)
    pos += HEADER_SIZE

    outer = NapsSection(pos, counts.num_outer_blocks * OUTER_BLOCK_DIGEST_STRIDE,
                        OUTER_BLOCK_DIGEST_STRIDE, counts.num_outer_blocks)
    pos += outer.size

    shuffle = NapsSection(pos, counts.num_shuffle_patterns * SHUFFLE_PATTERN_STRIDE,
                          SHUFFLE_PATTERN_STRIDE, counts.num_shuffle_patterns)
    pos += shuffle.size

    fidx = NapsSection(pos, counts.num_files * FILE_OFFSET_STRIDE,
                       FILE_OFFSET_STRIDE, counts.num_files)
    pos += fidx.size

    u2c_count = counts.num_u2c_entries
    u2c = NapsSection(pos, u2c_count * U2C_STRIDE, U2C_STRIDE, u2c_count)
    pos += u2c.size

    cblock = NapsSection(pos, counts.num_cblock_info * CBLOCKINFO_STRIDE,
                         CBLOCKINFO_STRIDE, counts.num_cblock_info)
    pos += cblock.size

    return NapsSectionMap(header, outer, shuffle, fidx, u2c, cblock, pos)


def decode_file_offset_entry(raw: bytes) -> NapsFileOffsetEntry:
    """Decode a 6-byte fidx entry (1 type byte + 40-bit LE offset)."""
    if len(raw) < FILE_OFFSET_STRIDE:
        raise PackageFormatError(f"fidx entry needs {FILE_OFFSET_STRIDE} bytes")
    offset = int.from_bytes(raw[1:6], "little")
    return NapsFileOffsetEntry(raw[0], offset)


def decode_u2c_entry(raw: bytes) -> NapsU2cEntry:
    """Decode a 10-byte u2c entry (uint24 base + 7 delta bytes)."""
    if len(raw) < U2C_STRIDE:
        raise PackageFormatError(f"u2c entry needs {U2C_STRIDE} bytes")
    base = raw[0] | (raw[1] << 8) | (raw[2] << 16)
    return NapsU2cEntry(base, tuple(raw[3:10]))


def decode_cblockinfo_entry(raw: bytes) -> NapsCblockInfoEntry:
    """Decode a 9-byte CblockInfo entry (72-bit record)."""
    if len(raw) < CBLOCKINFO_STRIDE:
        raise PackageFormatError(f"cblockinfo entry needs {CBLOCKINFO_STRIDE} bytes")
    raw = bytes(raw[:CBLOCKINFO_STRIDE])
    lo = int.from_bytes(raw[:8], "little")
    hi = raw[8]

    is_run_base = (lo >> 18) & 1
    coffset_mod_256k = lo & 0x3FFFF

    if not is_run_base:
        return NapsCblockInfoEntry(
            raw=raw,
            is_run_base=False,
            coffset_start_mod_256k=coffset_mod_256k,
            uoffset_start=(lo >> 19) & 0x3FFFF,
            clen_even_minus_1=(lo >> 37) & 0x1FFFF,
            even=(lo >> 54) & 1,
            odd=(lo >> 55) & 1,
            kde_predictor=(lo >> 56) & 7,
            shuffle_idx=(lo >> 59) & 0xF,
        )
    return NapsCblockInfoEntry(
        raw=raw,
        is_run_base=True,
        coffset_end_mod_256k=coffset_mod_256k,
        tweak_idx_start=(lo >> 19) & 0xFFFFFFF,
        key_table_idx=(lo >> 47) & 0x3,
        coffset_start_256k=((lo >> 49) & 0x7FFF) | ((hi & 0x1FF) << 15),
    )


def parse(blob: bytes) -> NapsLayoutDocument:
    """Parse a full ``naps_pkg_layout.dat`` blob."""
    counts = decode_header(blob)
    sections = section_map(counts)
    if len(blob) < sections.total_size:
        raise PackageFormatError(
            f"NAPS blob is {len(blob)} bytes but the counts require {sections.total_size}"
        )

    def slice_section(section: NapsSection) -> list[bytes]:
        return [
            blob[section.offset + index * section.stride:
                 section.offset + (index + 1) * section.stride]
            for index in range(section.count)
        ]

    document = NapsLayoutDocument(counts=counts, section_map=sections)
    document.outer_block_digests = slice_section(sections.outer_block_digest)
    document.shuffle_patterns = slice_section(sections.shuffle_pattern)
    document.file_offsets = [
        decode_file_offset_entry(raw)
        for raw in slice_section(sections.uncompressed_offset)
    ]
    document.u2c_entries = [
        decode_u2c_entry(raw) for raw in slice_section(sections.u2c)
    ]
    document.cblock_infos = [
        decode_cblockinfo_entry(raw) for raw in slice_section(sections.cblock_info)
    ]
    return document
