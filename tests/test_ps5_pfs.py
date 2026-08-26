"""Tests for the PS5 PFS / NAPS / crypto port from LibProsperoPkg."""

import struct
import unittest

from packages.exceptions import PackageFormatError
from packages.naps_layout import parse
from packages.pfs_fs import (
    _FLT_MAGIC,
    find_pfs_superblock,
    parse_inner_image,
)
from packages.ps5_crypto import derive_ekpfs


class EkpfsTests(unittest.TestCase):
    def test_derive_ekpfs_matches_reference(self):
        # Reference vector produced by LibProsperoPkg (SHA3-256, index 1) for
        # the PS5 package EKPFS with the standard all-zero passcode.
        ekpfs = derive_ekpfs("UP9000-PPSA99099_00-PROSPERO00000000", "0" * 32)
        self.assertEqual(len(ekpfs), 32)
        self.assertEqual(ekpfs.hex(), "7ec21081a1c5dccb89067cf41b5f670fddc736861360c2e03fe7fb93251ddc2b")

    def test_derive_ekpfs_rejects_bad_input(self):
        with self.assertRaises(PackageFormatError):
            derive_ekpfs("bad-id", "0" * 32)
        with self.assertRaises(PackageFormatError):
            derive_ekpfs("UP9000-PPSA99099_00-PROSPERO00000000", "short")


def _make_fake_self(size: int, source_path: bytes = b"") -> bytes:
    """Build a LibProsperoPkg-style fake SELF: header + ELF at +0x1A0."""
    header = bytearray(0x1A0)
    header[0:4] = b"\x54\x14\xf5\xee"
    struct.pack_into("<I", header, 0x10, size)
    elf = bytearray(size - 0x1A0)
    elf[0:4] = b"\x7fELF"
    if source_path:
        elf[0x40:0x40 + len(source_path)] = source_path + b"\x00"
    return bytes(header) + bytes(elf)


def build_data_first_inner_image():
    """Recreate the LibProsperoPkg synthetic data-first inner image layout."""
    keystone = b"keystone\x03\x00\x01" + b"\x00" * (0x60 - 12)
    sprx = _make_fake_self(0x31D0)
    eboot = _make_fake_self(0x2770, b"LibProsperoPKG/src/HomebrewTest/eboot.bin")

    image = bytearray(0x302E7)
    image[0x00:0x60] = keystone
    image[0x10000:0x10000 + len(sprx)] = sprx
    image[0x131D0:0x131D0 + len(eboot)] = eboot

    tail = bytearray()
    # Metadata tail: super-root entropy, then the file-list markers, then the
    # level-order name records (matching the LibProsperoPkg on-disk order).
    tail += struct.pack("<Q", 2)  # pseudo-version
    tail += b"\x8a\x00\x00\x51\x0b\x2a\x33\x01"
    tail += b"\x00\x01\x00\x18\x01\x0a\x4a\x01"
    tail += b"\x10\x00\x01\x89\x01\x6d\x41\x02"
    tail += b"\x42\xff\xff\xff\xff\xff\xff\xff"
    tail += b"\x81\x90\x90CPPD"
    tail += b"\x18\x18EA\x04FhA\x03G\x040\x02H\x05P"
    tail += b"\xd0\x31\xd0\x31`\x06`0``\x05HmPp'p"
    tail += b"'02\x02\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00?"
    tail += b"\x05uroot"
    tail += _FLT_MAGIC + b"\x05" + b"\x51" * 16
    tail += b"\x00" * 32
    tail += _FLT_MAGIC + b"\x01" + b"\x51" * 16 + b"\x00" * 16
    # name records in level order: sce_sys, eboot.bin, about, keystone, right.sprx
    tail += b"\x07sce_sys\x00"
    tail += b"\x09\x20eboot.bin"
    tail += b"\x05\x06\x05about"
    tail += b"\x08\x08keystone"
    tail += b"\x07\x0a\x20right.sprx"
    tail += b"\x00" * 64

    image[0x30000:0x30000 + len(tail)] = tail
    return bytes(image)


class InnerImageTests(unittest.TestCase):
    def test_data_first_inner_image_is_parsed(self):
        image = build_data_first_inner_image()
        files, layout = parse_inner_image(image)
        self.assertEqual(layout, "data-first")
        by_path = {f.path: f for f in files}
        self.assertEqual(set(by_path), {
            "sce_sys/keystone", "sce_sys/about/right.sprx", "eboot.bin",
        })
        self.assertEqual((by_path["sce_sys/keystone"].offset,
                          by_path["sce_sys/keystone"].size), (0x0, 0x60))
        self.assertEqual((by_path["sce_sys/about/right.sprx"].offset,
                          by_path["sce_sys/about/right.sprx"].size), (0x10000, 0x31D0))
        self.assertEqual((by_path["eboot.bin"].offset,
                          by_path["eboot.bin"].size), (0x131D0, 0x2770))
        # payload bytes round-trip exactly
        node = by_path["sce_sys/keystone"]
        self.assertEqual(image[node.offset:node.offset + node.size][:11],
                         b"keystone\x03\x00\x01")

    def test_unrecognized_inner_image_is_rejected(self):
        with self.assertRaises(PackageFormatError):
            parse_inner_image(b"\x00" * 0x4000)

    def test_find_pfs_superblock_scans_data_first_images(self):
        image = bytearray(0x60000)
        struct.pack_into("<qq", image, 0x50000, 2, 20130315)
        struct.pack_into("<H", image, 0x5001C, 0xD)
        struct.pack_into("<I", image, 0x50020, 0x10000)
        struct.pack_into("<q", image, 0x50030, 5)
        struct.pack_into("<q", image, 0x50038, 1)
        struct.pack_into("<q", image, 0x50040, 1)
        self.assertEqual(find_pfs_superblock(bytes(image)), 0x50000)


class NapsLayoutTests(unittest.TestCase):
    def _reference_blob(self):
        counts = struct.pack(
            "<QQ",
            0x1302000005,  # NumFiles=6, comp=2, Keys=1, Shuffle=0, UBlocks=19
            0x29000004,    # OuterBlocks=4, CblockInfo=43
        )
        outer = bytes(range(8)) * 4
        fidx = (
            b"\x00\x00\x00\x00\x00\x00"
            b"\x60\x00\x00\x00\x00\x00"
            b"\x30\x32\x00\x00\x00\x00"
            b"\xa0\x59\x00\x00\x00\x00"
            b"\x00\x00\x40\x00\x00\x00"
            b"\x00\x00\x4a\x00\x00\x40"
        )
        u2c = (
            b"\x01\x00\x00\x05\x06\x07\x0e\x10\x12\x14"
            b"\x17\x00\x00\x02\x04\x06\x08\x0a\x0c\x0d"
            b"\x26\x00\x00\x01\x02\x04\x04\x04\x04\x04"
        )
        cbi = bytes(43 * 9)
        blob = counts + outer + fidx + u2c + cbi
        return blob + b"\x00" * 11  # pad to 512 bytes

    def test_reference_blob_parses(self):
        doc = parse(self._reference_blob())
        counts = doc.counts
        self.assertEqual(counts.num_files, 6)
        self.assertEqual(counts.compression_type, 2)
        self.assertEqual(counts.num_ublocks, 19)
        self.assertEqual(counts.num_outer_blocks, 4)
        self.assertEqual(counts.num_cblock_info, 43)
        self.assertEqual(counts.num_u2c_entries, 3)
        self.assertEqual([(e.type, e.uncompressed_offset_start)
                          for e in doc.file_offsets][:4],
                         [(0x00, 0), (0x60, 0), (0x30, 0x32), (0xa0, 0x59)])
        self.assertEqual(doc.u2c_entries[0].start_cblockinfo_index,
                         (1, 6, 7, 8, 15, 17, 19, 21))

    def test_truncated_blob_is_rejected(self):
        with self.assertRaises(PackageFormatError):
            parse(b"\x00" * 8)


if __name__ == "__main__":
    unittest.main()
