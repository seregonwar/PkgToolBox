"""Internal PFS filesystem reader for PS4 and PS5 package images.

The reader supports classic superblock-first images, the PS5 finalized
data-first outer layout and the nested inner image (``pfs_image.dat``):

* ``PfsFilesystem``        -- standard superblock + inode table + dirents.
* ``open_ps5_outer_pfs``   -- the AES-XTS-encrypted data-first outer image.
* ``parse_inner_image``    -- the nested inner image: a standard PFS when a
  superblock is present, the LibProsperoPkg ``LPFSIDX1`` layout, or the
  synthetic data-first layout (raw payload blocks + metadata tail).

The module deliberately separates filesystem parsing from PKG/CNT parsing so
both platforms use the same bounds and path checks.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
import struct

from .exceptions import PackageBoundsError, PackageFormatError
from .ps4_crypto import pfs_keys, xts_crypt_sector


PFS_MAGIC = 20130315
PFS_MODE_SIGNED = 0x1
PFS_MODE_64BIT = 0x2
PFS_MODE_ENCRYPTED = 0x4
PFS_BLOCK_LIMIT = 100_000_000
SIGNED_TWEAK_FLAG_PS5 = 1 << 47


@dataclass(frozen=True)
class PfsHeader:
    version: int
    mode: int
    block_size: int
    inode_count: int
    data_block_count: int
    inode_block_count: int
    seed: bytes
    superblock_offset: int
    inode_indirect_count: int = 0


@dataclass(frozen=True)
class PfsNode:
    path: str
    inode: int
    is_dir: bool
    size: int
    compressed_size: int
    flags: int
    blocks: tuple[int, ...]


def _range(offset: int, size: int, total: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > total or size > total - offset:
        raise PackageBoundsError(f"{label} is outside the PFS image")


def parse_pfs_header(image: bytes, superblock_offset: int = 0,
                     *, versions=(1, 2)) -> PfsHeader:
    _range(superblock_offset, 0x400, len(image), "PFS superblock")
    version, magic = struct.unpack_from("<qq", image, superblock_offset)
    if version not in versions or magic != PFS_MAGIC:
        raise PackageFormatError(
            f"invalid PFS superblock version/magic: {version}/{magic}"
        )
    mode = struct.unpack_from("<H", image, superblock_offset + 0x1C)[0]
    block_size = struct.unpack_from("<I", image, superblock_offset + 0x20)[0]
    inode_count = struct.unpack_from("<q", image, superblock_offset + 0x30)[0]
    data_block_count = struct.unpack_from("<q", image, superblock_offset + 0x38)[0]
    inode_block_count = struct.unpack_from("<q", image, superblock_offset + 0x40)[0]
    if (block_size < 0x1000 or block_size > 0x200000
            or block_size & (block_size - 1)):
        raise PackageFormatError(f"invalid PFS block size: 0x{block_size:X}")
    if not 0 < inode_count <= 1_000_000:
        raise PackageFormatError(f"invalid PFS inode count: {inode_count}")
    if not 0 < inode_block_count <= PFS_BLOCK_LIMIT:
        raise PackageFormatError(f"invalid PFS inode-block count: {inode_block_count}")
    seed = image[superblock_offset + 0x370:superblock_offset + 0x380]

    # The embedded signed-64 inode descriptor starts at 0x50. Its five
    # indirect pointers begin after the 12 direct sig+block pairs.
    indirect_count = 0
    ib_base = superblock_offset + 0x50 + 104 + 12 * 40
    if ib_base + 5 * 40 <= superblock_offset + 0x400:
        for index in range(5):
            block = struct.unpack_from("<q", image, ib_base + index * 40 + 32)[0]
            indirect_count += int(block > 0)
    return PfsHeader(
        version, mode, block_size, inode_count, data_block_count,
        inode_block_count, seed, superblock_offset, indirect_count,
    )


def _parse_inode(data: bytes, offset: int, *, signed: bool, is_64: bool) -> dict:
    if signed and is_64:
        size_of, block_stride, block_fmt, block_base = 0x310, 40, "<q", 104
    elif signed:
        size_of, block_stride, block_fmt, block_base = 0x2C8, 36, "<i", 100
    else:
        size_of, block_stride, block_fmt, block_base = 0xA8, 4, "<i", 100
    _range(offset, size_of, len(data), "PFS inode")
    mode, _nlink, flags = struct.unpack_from("<HHI", data, offset)
    size, compressed_size = struct.unpack_from("<qq", data, offset + 8)
    if signed and is_64:
        blocks = struct.unpack_from("<Q", data, offset + 96)[0]
    else:
        blocks = struct.unpack_from("<I", data, offset + 96)[0]
    if blocks > PFS_BLOCK_LIMIT or size < 0 or compressed_size < 0:
        raise PackageFormatError("implausible PFS inode geometry")
    direct = []
    for index in range(12):
        pointer_offset = offset + block_base + index * block_stride
        if signed:
            pointer_offset += 32
        direct.append(struct.unpack_from(block_fmt, data, pointer_offset)[0])
    return {
        "mode": mode,
        "flags": flags,
        "size": size,
        "compressed_size": compressed_size,
        "block_count": int(blocks),
        "direct": direct,
    }


class PfsFilesystem:
    def __init__(self, image: bytes, header: PfsHeader):
        self.image = image
        self.header = header
        self._inodes = self._load_inodes()
        self.nodes = self._walk_tree()

    def _load_inodes(self):
        signed = bool(self.header.mode & PFS_MODE_SIGNED)
        is_64 = bool(self.header.mode & PFS_MODE_64BIT)
        inode_size = 0x310 if signed and is_64 else (0x2C8 if signed else 0xA8)
        table = (
            self.header.superblock_offset
            + self.header.block_size * (1 + self.header.inode_indirect_count)
        )
        capacity = self.header.inode_block_count * self.header.block_size
        if self.header.inode_count * inode_size > capacity:
            raise PackageFormatError("PFS inode table cannot hold the declared inode count")
        _range(table, capacity, len(self.image), "PFS inode table")
        return [
            _parse_inode(self.image, table + index * inode_size,
                         signed=signed, is_64=is_64)
            for index in range(self.header.inode_count)
        ]

    def _inode_blocks(self, inode: dict) -> tuple[int, ...]:
        count = inode["block_count"]
        if count == 0:
            return ()
        direct = tuple(block for block in inode["direct"][:count] if block >= 0)
        if len(direct) < min(count, 12):
            raise PackageFormatError("PFS inode has missing direct block pointers")
        if count > 12:
            raise PackageFormatError("PFS indirect file blocks are not supported yet")
        for block in direct:
            if block >= PFS_BLOCK_LIMIT or (block + 1) * self.header.block_size > len(self.image):
                raise PackageBoundsError(f"PFS block {block} is outside the image")
        return direct

    def _directory_entries(self, inode_index: int):
        inode = self._inodes[inode_index]
        for block in self._inode_blocks(inode):
            start = block * self.header.block_size
            limit = start + self.header.block_size
            cursor = start
            while cursor + 16 <= limit:
                number, kind, name_length, entry_size = struct.unpack_from("<Iiii", self.image, cursor)
                if entry_size == 0:
                    break
                if (entry_size < 16 or entry_size > 280 or entry_size % 8
                        or name_length < 0 or name_length > entry_size - 16
                        or cursor + entry_size > limit):
                    raise PackageFormatError("invalid PFS directory entry")
                name_bytes = self.image[cursor + 16:cursor + 16 + name_length]
                try:
                    name = name_bytes.split(b"\0", 1)[0].decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise PackageFormatError("invalid UTF-8 PFS filename") from exc
                yield number, kind, name
                cursor += entry_size

    def _walk_tree(self):
        nodes = []
        seen = set()

        def visit(inode_index: int, path: str, under_uroot: bool):
            if inode_index >= len(self._inodes) or inode_index in seen:
                return
            seen.add(inode_index)
            inode = self._inodes[inode_index]
            for child_inode, kind, name in self._directory_entries(inode_index):
                if not name or name in (".", "..") or child_inode >= len(self._inodes):
                    continue
                child_under = under_uroot or name == "uroot"
                child_path = path if name == "uroot" and not under_uroot else (
                    f"{path}/{name}" if path else name
                )
                if kind == 3:
                    visit(child_inode, child_path, child_under)
                elif kind == 2 and child_under:
                    item = self._inodes[child_inode]
                    nodes.append(PfsNode(
                        child_path, child_inode, False, item["size"],
                        item["compressed_size"], item["flags"],
                        self._inode_blocks(item),
                    ))

        visit(0, "", False)
        return nodes

    def read_node(self, node: PfsNode) -> bytes:
        remaining = node.size
        output = bytearray()
        for block in node.blocks:
            if remaining <= 0:
                break
            start = block * self.header.block_size
            amount = min(remaining, self.header.block_size)
            output.extend(self.image[start:start + amount])
            remaining -= amount
        if remaining:
            raise PackageBoundsError(f"PFS file '{node.path}' is truncated")
        return bytes(output)


def open_classic_pfs(image: bytes, *, ekpfs: bytes | None = None,
                     image_flags: int = 0) -> PfsFilesystem:
    header = parse_pfs_header(image, 0)
    plain = image
    if header.mode & PFS_MODE_ENCRYPTED:
        if ekpfs is None:
            raise PackageFormatError("encrypted PFS requires an EKPFS key")
        tweak_key, data_key = pfs_keys(
            ekpfs, header.seed, new_crypto=bool(image_flags & 0x2000000000000000)
        )
        plain_data = bytearray(image)
        sector_size = 0x1000
        start_sector = header.block_size // sector_size
        for sector in range(start_sector, len(image) // sector_size):
            offset = sector * sector_size
            plain_data[offset:offset + sector_size] = xts_crypt_sector(
                image[offset:offset + sector_size], data_key, tweak_key,
                sector, decrypt=True,
            )
        plain = bytes(plain_data)
        header = parse_pfs_header(plain, 0)
    return PfsFilesystem(plain, header)


def open_ps5_outer_pfs(image: bytes, *, superblock_offset: int,
                       ekpfs_candidates: tuple[bytes, ...]) -> tuple[PfsFilesystem, bytes]:
    header = parse_pfs_header(image, superblock_offset, versions=(2,))
    if not header.mode & PFS_MODE_ENCRYPTED:
        return PfsFilesystem(image, header), b""
    if len(image) % header.block_size:
        raise PackageFormatError("PS5 outer PFS is not block aligned")
    sb_block = superblock_offset // header.block_size
    total_blocks = len(image) // header.block_size

    for ekpfs in ekpfs_candidates:
        for new_crypto in (True, False):
            tweak_key, data_key = pfs_keys(ekpfs, header.seed, new_crypto=new_crypto)
            probe = bytearray(image)
            for block in range(total_blocks):
                if block == sb_block:
                    continue
                start = block * header.block_size
                probe[start:start + header.block_size] = xts_crypt_sector(
                    image[start:start + header.block_size], data_key, tweak_key,
                    SIGNED_TWEAK_FLAG_PS5 | block, decrypt=True,
                )
            try:
                probe_fs = PfsFilesystem(bytes(probe), header)
            except (PackageFormatError, PackageBoundsError, struct.error):
                continue
            nested = next((node for node in probe_fs.nodes
                           if os.path.basename(node.path).lower() == "pfs_image.dat"), None)
            final = bytearray(image)
            data_blocks = set(nested.blocks if nested else ())
            for block in range(total_blocks):
                if block == sb_block:
                    continue
                start = block * header.block_size
                sector = block if block in data_blocks else SIGNED_TWEAK_FLAG_PS5 | block
                final[start:start + header.block_size] = xts_crypt_sector(
                    image[start:start + header.block_size], data_key, tweak_key,
                    sector, decrypt=True,
                )
            try:
                return PfsFilesystem(bytes(final), header), ekpfs
            except (PackageFormatError, PackageBoundsError, struct.error):
                continue
    raise PackageFormatError("none of the supplied/derived keys opened the PS5 outer PFS")


# ---------------------------------------------------------------------------
# Inner image (pfs_image.dat) parsing
# ---------------------------------------------------------------------------

#: Signature of a keystone file: b"keystone" + version 3 + flags 1.
_KEYSTONE_SIGNATURE = b"keystone\x03\x00\x01"

#: Size of a keystone file in bytes (fixed by the format).
_KEYSTONE_SIZE = 0x60

#: Length of the SELF header that precedes the embedded ELF in fake-SELF files.
_SELF_HEADER_SIZE = 0x1A0

#: Offset of the 32-bit file size inside the fake-SELF header.
_SELF_SIZE_OFFSET = 0x10

#: Magic of the LibProsperoPkg native inner-image index block.
_LPFSIDX1_MAGIC = b"LPFSIDX1"

#: Magic of the PS5 PFS file-list table found in the data-first metadata tail.
_FLT_MAGIC = b"\x7fFLT"


@dataclass(frozen=True)
class RawPfsFile:
    """One file located inside an inner image (path + byte range)."""
    path: str
    offset: int
    size: int


def find_pfs_superblock(image: bytes, *, step: int = 0x1000) -> int | None:
    """Locate a PFS superblock (version 1/2 + magic) inside the image.

    Scans block-aligned offsets; used for data-first images whose superblock
    sits near the end instead of at offset zero.
    """
    limit = len(image) - 0x400
    for offset in range(0, limit + 1, step):
        version, magic = struct.unpack_from("<qq", image, offset)
        if version in (1, 2) and magic == PFS_MAGIC:
            return offset
    return None


def _parse_lpfsidx1(image: bytes) -> list[RawPfsFile] | None:
    """Parse the LibProsperoPkg native inner image (``LPFSIDX1`` index block).

    Layout (see LibProsperoPkg ``src/src/build.cpp``): block 0 is a plaintext
    superblock-shaped header, block 1 holds the index:

        "LPFSIDX1" 8 bytes, u32 version, u32 file count, u64 block size,
        u64 data start, then per file: u16 path len, u16 0, u32 crc,
        u64 offset, u64 size, path bytes.

    Returns None when the image does not carry the index magic.
    """
    if len(image) < 0x20000 or image[0x10000:0x10008] != _LPFSIDX1_MAGIC:
        return None
    try:
        version, file_count, block_size, data_start = struct.unpack_from(
            "<IIQQ", image, 0x10008
        )
        if version != 1 or file_count > 100_000 or block_size == 0:
            return None
        files: list[RawPfsFile] = []
        cursor = 0x10018
        for _ in range(file_count):
            path_len, _zero, _crc, offset, size = struct.unpack_from(
                "<HH IQQ", image, cursor
            )
            cursor += 24
            if path_len > 0xFFFF or cursor + path_len > len(image):
                return None
            path = image[cursor:cursor + path_len].decode("utf-8", "replace")
            cursor += path_len
            if offset < data_start or size > len(image) - offset:
                return None
            files.append(RawPfsFile(path, offset, size))
        return files
    except (struct.error, PackageFormatError):
        return None


def _scan_name_records(image: bytes, start: int) -> list[str]:
    """Extract the length-prefixed ASCII file names from the data-first tail.

    The metadata tail serializes the tree as a level-order walk whose names are
    stored as ``[len u8][name]`` records.  Only well-formed records (printable
    ASCII of exactly the declared length) are kept, preserving order.
    """
    names: list[str] = []
    cursor = start
    while cursor + 2 <= len(image):
        length = image[cursor]
        if not 1 <= length <= 64 or cursor + 1 + length > len(image):
            cursor += 1
            continue
        chunk = image[cursor + 1:cursor + 1 + length]
        if re.fullmatch(rb"[A-Za-z0-9._-]+", chunk):
            names.append(chunk.decode("ascii"))
            cursor += 1 + length
        else:
            cursor += 1
    return names


#: Conventional locations of the well-known PS5 inner-image payload files.
_CONVENTIONAL_PATHS = {
    "keystone": "sce_sys/keystone",
    "right.sprx": "sce_sys/about/right.sprx",
    "eboot.bin": "eboot.bin",
}


def _parse_data_first_inner(image: bytes) -> list[RawPfsFile] | None:
    """Parse the synthetic data-first inner image produced by LibProsperoPkg.

    The image is a block-aligned raw concatenation of the payload files
    (keystone, fake-SELF modules) followed by a metadata tail that carries the
    file names in level order.  Payloads are located by content signature and
    matched to their conventional PS5 package paths:

    * keystone  -- starts with b"keystone\x03\x00\x01", fixed 0x60 bytes,
      conventionally at ``sce_sys/keystone``.
    * fake-SELF -- ELF magic at +0x1A0; the file starts at the ELF offset minus
      the 0x1A0-byte SELF header and its size lives at +0x14.  The module that
      embeds its original source path is the app executable (``eboot.bin``);
      the other module is the boot library at ``sce_sys/about/right.sprx``.

    The names found in the metadata tail are checked against the payload set so
    the conventional paths are only used when they agree with the image.

    Returns None when the layout does not look like a data-first image.
    """
    flt = image.find(_FLT_MAGIC)
    if flt <= 0x10000:
        return None
    metadata_start = flt

    # 1. Locate payload files by content signature in the data region.
    payloads: list[dict] = []
    probe = image[:metadata_start]
    pos = 0
    while True:
        pos = probe.find(b"\x7fELF", pos)
        if pos < 0:
            break
        start = pos - _SELF_HEADER_SIZE
        if start >= 0 and start < metadata_start:
            size = struct.unpack_from("<I", image, start + _SELF_SIZE_OFFSET)[0]
            if 0 < size <= metadata_start - start:
                payloads.append({"start": start, "size": size,
                                 "name": None})
        pos += 1
    payloads.sort(key=lambda item: item["start"])

    if probe.startswith(_KEYSTONE_SIGNATURE):
        payloads.insert(0, {"start": 0, "size": _KEYSTONE_SIZE,
                            "name": "keystone"})
    if len(payloads) < 2:
        return None

    # 2. Identify the app executable: the SELF embedding its original source
    #    path (``.../<name>.bin``).  The remaining module is the right library.
    for payload in payloads:
        if payload.get("name"):
            continue
        region = image[payload["start"]:payload["start"] + payload["size"]]
        # Prefer a path with directory separators; bare library names such as
        # "libSceVideoOut.prx" (linked modules) are not the source path.
        match = re.search(
            rb"(?:[A-Za-z0-9_.-]+[\\/])+[A-Za-z0-9_.-]+\.(?:bin|prx|elf)\x00",
            region,
        )
        if match:
            basename = match.group(0).split(b"/")[-1].split(b"\\")[-1][:-1]
            payload["name"] = basename.decode("ascii", "replace")
            break
    for payload in payloads:
        if payload.get("name"):
            continue
        payload["name"] = "right.sprx"

    # 3. Sanity-check the assigned names against the metadata tail.  The tail
    #    lists every payload file; if it does not mention a name we assigned we
    #    stop rather than emit a wrong tree.
    tail = image[metadata_start:]
    for payload in payloads:
        if payload["name"].encode("ascii") not in tail:
            return None

    # 4. Emit the conventional paths.
    files: list[RawPfsFile] = []
    for payload in payloads:
        path = _CONVENTIONAL_PATHS.get(payload["name"])
        if not path:
            return None
        files.append(RawPfsFile(path, payload["start"], payload["size"]))
    return files or None


def parse_inner_image(image: bytes) -> tuple[list[RawPfsFile], str]:
    """Parse a nested PS5 inner image (``pfs_image.dat``).

    Returns ``(files, format)`` where ``format`` names the layout that matched:
    ``"pfs"`` for a standard superblock image, ``"lpfsidx1"`` for the native
    index layout, or ``"data-first"`` for the synthetic data-first layout.
    Raises :class:`PackageFormatError` when the image is not readable.
    """
    superblock = find_pfs_superblock(image)
    if superblock is not None:
        try:
            header = parse_pfs_header(image, superblock, versions=(2,))
            fs = PfsFilesystem(image, header)
            files = [
                RawPfsFile(node.path, node.blocks[0] * header.block_size, node.size)
                for node in fs.nodes
            ]
            return files, "pfs"
        except (PackageFormatError, PackageBoundsError, struct.error):
            pass

    indexed = _parse_lpfsidx1(image)
    if indexed is not None:
        return indexed, "lpfsidx1"

    data_first = _parse_data_first_inner(image)
    if data_first is not None:
        return data_first, "data-first"

    raise PackageFormatError(
        "unrecognized PS5 inner image: no PFS superblock, LPFSIDX1 index, "
        "or data-first payload layout found"
    )
