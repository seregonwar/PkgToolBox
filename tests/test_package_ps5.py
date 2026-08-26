import json
import io
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from packages.package_ps5 import PackagePS5
from packages.factory import detect_package_type, open_package


FIH_SIZE = 0x10000
PFS_SIZE = 0x10000
CNT_OFFSET = FIH_SIZE + PFS_SIZE
CNT_SIZE = 0x10000
SI_DATA = b"PK\x03\x04synthetic-si"


def build_fih_package():
    data = bytearray(CNT_OFFSET + CNT_SIZE)

    data[0:4] = b"\x7fFIH"
    data[0x04] = 1
    data[0x05] = 0
    struct.pack_into("<H", data, 0x06, 3)
    struct.pack_into("<I", data, 0x08, 1)
    struct.pack_into("<Q", data, 0x10, FIH_SIZE)
    struct.pack_into("<Q", data, 0x18, PFS_SIZE)
    struct.pack_into("<Q", data, 0x58, CNT_OFFSET)
    data[0x30:0x50] = b"\xBB" * 32

    cnt = CNT_OFFSET
    data[cnt:cnt + 4] = b"\x7fCNT"
    struct.pack_into(">I", data, cnt + 0x04, 0x00020001)
    struct.pack_into(">I", data, cnt + 0x10, 5)
    struct.pack_into(">H", data, cnt + 0x14, 2)
    struct.pack_into(">H", data, cnt + 0x16, 5)
    struct.pack_into(">I", data, cnt + 0x18, 0x600)
    struct.pack_into(">Q", data, cnt + 0x20, 0x2000)
    struct.pack_into(">Q", data, cnt + 0x28, 0xE000)

    content_id = "UP0000-PPSA00001_00-SYNTHETIC000000"
    encoded_id = content_id.encode("ascii")
    data[cnt + 0x40:cnt + 0x70] = encoded_id.ljust(0x30, b"\x00")
    struct.pack_into(">I", data, cnt + 0x70, 0)
    struct.pack_into(">I", data, cnt + 0x74, 0x20)
    struct.pack_into(">I", data, cnt + 0x78, 0x02020000)
    struct.pack_into(">I", data, cnt + 0x7C, CNT_SIZE)
    struct.pack_into(">I", data, cnt + 0x80, 0x20200722)
    struct.pack_into(">I", data, cnt + 0x84, 0x01FE52E9)
    data[cnt + 0xFE0:cnt + 0x1000] = b"\xAA" * 32

    names = (
        b"\x00playgo-ficm.dat\x00param.json\x00icon0.png\x00"
        b"playgo-chunk.dat\x00"
    )
    name_offsets = {
        name.decode("ascii"): names.index(name)
        for name in (
            b"playgo-ficm.dat",
            b"param.json",
            b"icon0.png",
            b"playgo-chunk.dat",
        )
    }
    param = json.dumps({
        "titleId": "PPSA00001",
        "contentId": content_id,
        "contentVersion": "01.000.000",
        "localizedParameters": {
            "defaultLanguage": "en-US",
            "en-US": {"titleName": "Synthetic Package"},
        },
    }).encode("utf-8")
    icon = b"\x89PNG\r\n\x1a\nnot-a-filename"
    playgo = b"playgo payload"
    ficm = b"ficm payload"

    payloads = {
        0x2000: names,
        0x2100: icon,
        0x2200: param,
        0x2400: playgo,
        0x2500: ficm,
    }
    for relative_offset, payload in payloads.items():
        start = cnt + relative_offset
        data[start:start + len(payload)] = payload

    # Entry order deliberately differs from name-table order. This catches
    # positional name matching and reads from entry payload offsets.
    entries = [
        (0x1200, name_offsets["icon0.png"], 0x08000000, 0, 0x2100, len(icon)),
        (0x2000, name_offsets["param.json"], 0, 0, 0x2200, len(param)),
        (0x1001, name_offsets["playgo-chunk.dat"], 0x08000000, 0, 0x2400, len(playgo)),
        (0x2011, name_offsets["playgo-ficm.dat"], 0x08000000, 0, 0x2500, len(ficm)),
        (0x0200, 0, 0x40000000, 0, 0x2000, len(names)),
    ]
    for index, entry in enumerate(entries):
        struct.pack_into(">6I8x", data, cnt + 0x600 + index * 0x20, *entry)

    return bytes(data) + SI_DATA


class PackagePS5Tests(unittest.TestCase):
    def test_fih_cnt_layout_and_name_table_are_parsed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package_path = Path(temp_dir) / "synthetic.pkg"
            package_path.write_bytes(build_fih_package())

            package = PackagePS5(str(package_path))

            self.assertEqual(package.pkg_type, "debug")
            self.assertEqual(package.pkg_revision, 3)
            self.assertEqual(package.pkg_file_count, 5)
            self.assertEqual(package.pkg_sc_entry_count, 2)
            self.assertEqual(package.fih_offset, 0)
            self.assertEqual(package.fih_size, FIH_SIZE)
            self.assertEqual(package.pfs_offset, FIH_SIZE)
            self.assertEqual(package.pfs_size, PFS_SIZE)
            self.assertEqual(package.sc_offset, CNT_OFFSET)
            self.assertEqual(package.sc_size, CNT_SIZE)
            self.assertEqual(package.si_offset, CNT_OFFSET + CNT_SIZE)
            self.assertEqual(package.si_size, len(SI_DATA))
            self.assertEqual(package.entry_table_offset, CNT_OFFSET + 0x600)
            self.assertEqual(package.body_offset, CNT_OFFSET + 0x2000)
            self.assertEqual(package.package_digest, "aa" * 32)
            self.assertEqual(package.pfs_area_digest, "bb" * 32)

            self.assertEqual(package.files[0x0200]["name"], "entry_names")
            self.assertEqual(package.files[0x1200]["name"], "icon0.png")
            self.assertEqual(package.files[0x2000]["name"], "param.json")
            self.assertEqual(package.files[0x1001]["name"], "playgo-chunk.dat")
            self.assertEqual(package.files[0x2011]["name"], "playgo-ficm.dat")
            self.assertEqual(package.read_file(0x1200), b"\x89PNG\r\n\x1a\nnot-a-filename")
            self.assertIs(package._find_file_by_name("sce_sys/icon0.png"), package.files[0x1200])

            self.assertEqual(package.title_id, "PPSA00001")
            self.assertEqual(package.title_name, "Synthetic Package")

    def test_rejects_fih_with_cnt_offset_outside_file(self):
        data = bytearray(build_fih_package())
        struct.pack_into("<Q", data, 0x58, len(data) + 0x1000)

        with tempfile.TemporaryDirectory() as temp_dir:
            package_path = Path(temp_dir) / "invalid.pkg"
            package_path.write_bytes(data)

            with self.assertRaisesRegex(ValueError, "Invalid embedded CNT offset"):
                PackagePS5(str(package_path))

    def test_standalone_cnt_is_detected_as_ps5_meta(self):
        full = build_fih_package()
        standalone = full[CNT_OFFSET:CNT_OFFSET + CNT_SIZE]
        with tempfile.TemporaryDirectory() as temp_dir:
            package_path = Path(temp_dir) / "meta.pkg"
            package_path.write_bytes(standalone)

            self.assertEqual(detect_package_type(str(package_path)), "ps5-meta")
            package = open_package(str(package_path))
            self.assertIsInstance(package, PackagePS5)
            self.assertEqual(package.pkg_type, "meta")
            self.assertEqual(package.title_id, "PPSA00001")
            self.assertEqual(package.pfs_size, 0)

    def test_si_zip_is_listed_and_extracted_safely(self):
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest/info.txt", "supplementary")
            archive.writestr("../escape.txt", "blocked")
        package_data = build_fih_package()[:-len(SI_DATA)] + archive_bytes.getvalue()

        with tempfile.TemporaryDirectory() as temp_dir:
            package_path = Path(temp_dir) / "with-si.pkg"
            package_path.write_bytes(package_data)
            package = PackagePS5(str(package_path))
            self.assertEqual(len(package.get_si_entries()), 2)

            output_dir = Path(temp_dir) / "si"
            result = package.extract_si(str(output_dir))
            self.assertIn("1 file(s), 1 skipped", result)
            self.assertEqual((output_dir / "manifest" / "info.txt").read_text(), "supplementary")
            self.assertFalse((Path(temp_dir) / "escape.txt").exists())

    def test_title_id_folder_name(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package_path = Path(temp_dir) / "game.pkg"
            package_path.write_bytes(build_fih_package())
            package = PackagePS5(str(package_path))

            # PS5 title ID comes from param.json titleId
            self.assertEqual(package.title_id, "PPSA00001")
            self.assertEqual(package.get_title_id_folder_name(), "PPSA00001")

            # Falls back to the content ID component when titleId is absent
            package.title_id = None
            self.assertEqual(package.get_title_id_folder_name(), "PPSA00001")


if __name__ == "__main__":
    unittest.main()
