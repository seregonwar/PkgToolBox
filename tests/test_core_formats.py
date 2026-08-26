import os
import struct
import tempfile
import unittest
from pathlib import Path

from packages.exceptions import EncryptedEntryError, PackageFormatError
from packages.factory import detect_package_type, open_package
from packages.image_info import inspect_image
from packages.package_ps4 import PackagePS4
from packages.pfs import inspect_pfs
from packages.sfo import PSF_FORMAT_INTEGER, PSF_FORMAT_TEXT, parse_sfo
from packages.crypto_utils import AES_ctx, AES_set_iv, AES_set_key, AES_cbc_decrypt, AES_KEY_LEN_128


def build_sfo(values):
    keys = bytearray()
    value_data = bytearray()
    records = []
    for key, value in values:
        key_offset = len(keys)
        keys.extend(key.encode("utf-8") + b"\0")
        while len(value_data) % 4:
            value_data.append(0)
        value_offset = len(value_data)
        if isinstance(value, int):
            raw = struct.pack("<I", value)
            value_format = PSF_FORMAT_INTEGER
        else:
            raw = value.encode("utf-8") + b"\0"
            value_format = PSF_FORMAT_TEXT
        value_data.extend(raw)
        records.append((key_offset, value_format, len(raw), len(raw), value_offset))

    key_table_offset = 0x14 + len(records) * 0x10
    data_table_offset = key_table_offset + len(keys)
    output = bytearray(data_table_offset + len(value_data))
    output[:4] = b"\x00PSF"
    struct.pack_into("<4I", output, 4, 0x00000101, key_table_offset, data_table_offset, len(records))
    for index, (key_offset, value_format, length, max_length, value_offset) in enumerate(records):
        base = 0x14 + index * 0x10
        struct.pack_into("<H", output, base, key_offset)
        struct.pack_into(">H", output, base + 2, value_format)
        struct.pack_into("<3I", output, base + 4, length, max_length, value_offset)
    output[key_table_offset:data_table_offset] = keys
    output[data_table_offset:] = value_data
    return bytes(output)


def build_ps4_package(encrypted_icon=True):
    sfo = build_sfo([
        ("TITLE_ID", "CUSA12345"),
        ("TITLE", "Caffè Racer"),
        ("APP_VER", "01.23"),
        ("CATEGORY", "gd"),
        ("PARENTAL_LEVEL", 7),
    ])
    names = b"\0sce_sys/param.sfo\0sce_sys/icon0.png\0"
    param_name = names.index(b"sce_sys/param.sfo")
    icon_name = names.index(b"sce_sys/icon0.png")
    file_size = 0x6000
    output = bytearray(file_size)
    content_id = b"UP0000-CUSA12345_00-SYNTHETIC000000"
    header = struct.pack(
        ">5I2H2I4Q36s12s12I",
        PackagePS4.MAGIC_PS4, 1, 0, 3, 3, 1, 3, 0x1000, 0x60,
        0x2000, 0x3000, 0x2000, 0x3000,
        content_id.ljust(36, b"\0"), b"\0" * 12,
        1, 0x1A, 0x00100000, 0, 20260825, 1,
        0, 0, 0, 0, 0, 1,
    )
    output[:len(header)] = header
    struct.pack_into(">I6Q2I", output, 0x404, 1, 0x04, 0x5000, 0x1000, 0, 0, file_size, 0, 0x800)
    output[0x440:0x460] = b"\x11" * 32
    output[0x460:0x480] = b"\x22" * 32
    output[0x2000:0x2000 + len(names)] = names
    output[0x2100:0x2100 + len(sfo)] = sfo
    icon = b"\x89PNG\r\n\x1a\n" + b"encrypted-placeholder"
    output[0x3000:0x3000 + len(icon)] = icon
    entries = [
        (0x0200, 0, 0, 0, 0x2000, len(names)),
        (0x1000, param_name, 0, 0, 0x2100, len(sfo)),
        (0x1200, icon_name, 0x80000000 if encrypted_icon else 0, 0, 0x3000, len(icon)),
    ]
    for index, entry in enumerate(entries):
        struct.pack_into(">6I8x", output, 0x1000 + index * 0x20, *entry)
    return bytes(output)


class CoreFormatTests(unittest.TestCase):
    def test_sfo_parses_all_supported_value_types(self):
        document = parse_sfo(build_sfo([("TITLE", "Caffè"), ("PARENTAL_LEVEL", 12)]))
        self.assertEqual(document.as_dict(), {"TITLE": "Caffè", "PARENTAL_LEVEL": 12})
        self.assertEqual(document.entries[0].format_name, "text")

    def test_sfo_rejects_out_of_bounds_value(self):
        data = bytearray(build_sfo([("TITLE", "test")]))
        struct.pack_into("<I", data, 0x14 + 0x0C, 0xFFFFFFF0)
        with self.assertRaises(PackageFormatError):
            parse_sfo(bytes(data))

    def test_png_and_dds_headers(self):
        png = bytearray(33)
        png[:8] = b"\x89PNG\r\n\x1a\n"
        struct.pack_into(">I", png, 8, 13)
        png[12:16] = b"IHDR"
        struct.pack_into(">II", png, 16, 512, 512)
        self.assertEqual(inspect_image(bytes(png)).kind, "icon")

        dds = bytearray(128)
        dds[:4] = b"DDS "
        struct.pack_into("<I", dds, 4, 124)
        struct.pack_into("<II", dds, 12, 1080, 1920)
        struct.pack_into("<I", dds, 28, 4)
        info = inspect_image(bytes(dds))
        self.assertEqual((info.format, info.kind, info.mipmaps), ("DDS", "background", 4))

    def test_aes_requires_explicit_iv_and_preserves_blocks(self):
        ctx = AES_ctx()
        AES_set_key(ctx, bytes(range(16)), AES_KEY_LEN_128)
        with self.assertRaisesRegex(ValueError, "key and IV"):
            ctx.decrypt(b"\0" * 16)
        AES_set_iv(ctx, b"\0" * 16)
        plaintext = b"0123456789ABCDEF"
        ciphertext = ctx.encrypt(plaintext, use_padding=False)
        output = bytearray(16)
        AES_cbc_decrypt(ctx, ciphertext, output)
        self.assertEqual(bytes(output), plaintext)

    def test_ps4_metadata_encryption_and_internal_extraction(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package_path = Path(temp_dir) / "synthetic.pkg"
            package_path.write_bytes(build_ps4_package())
            package = PackagePS4(str(package_path))

            self.assertEqual(package.title_id, "CUSA12345")
            self.assertEqual(package.title_name, "Caffè Racer")
            self.assertEqual(package.region, "North America / Europe")
            self.assertEqual(package.files[0x1000]["name"], "sce_sys/param.sfo")
            self.assertTrue(package.is_encrypted())
            with self.assertRaises(EncryptedEntryError):
                package.read_file(0x1200)

            output_dir = Path(temp_dir) / "out"
            result = package.dump(str(output_dir))
            self.assertIn("1 plaintext file(s)", result)
            self.assertIn("1 encrypted skipped", result)
            self.assertIn("1 internal skipped", result)
            self.assertTrue((output_dir / "sce_sys" / "param.sfo").is_file())
            self.assertFalse((output_dir / "sce_sys" / "icon0.png").exists())
            self.assertFalse((output_dir / "entry_names").exists())
            self.assertEqual(package.get_pfs_report().state, "protected-or-unsupported")
            self.assertEqual(detect_package_type(str(package_path)), "ps4")
            self.assertIsInstance(open_package(str(package_path)), PackagePS4)

    def test_extraction_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package_path = Path(temp_dir) / "synthetic.pkg"
            package_path.write_bytes(build_ps4_package(encrypted_icon=False))
            package = PackagePS4(str(package_path))
            package.files[0x1200]["name"] = "../escape.png"
            result = package.dump(str(Path(temp_dir) / "out"))
            self.assertIn("1 invalid skipped", result)
            self.assertFalse((Path(temp_dir) / "escape.png").exists())

    def test_plaintext_pfsc_header_is_reported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            image_offset = 0x1000
            image_size = 0x30000
            data = bytearray(image_offset + image_size)
            pfsc = image_offset + 0x20000
            struct.pack_into("<4i4q", data, pfsc, 0x43534650, 0, 0, 0x10000,
                             0x10000, 0x30, 0x48, 0x20000)
            package_path = Path(temp_dir) / "plain-pfs.bin"
            package_path.write_bytes(data)
            report = inspect_pfs(str(package_path), image_offset=image_offset, image_size=image_size)
            self.assertEqual(report.state, "plaintext-pfsc")
            self.assertEqual(report.pfsc_offset, 0x20000)
            self.assertEqual(report.pfsc_block_count, 2)

    def test_title_id_folder_name_uses_sfo_then_content_id(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package_path = Path(temp_dir) / "synthetic.pkg"
            package_path.write_bytes(build_ps4_package())
            package = PackagePS4(str(package_path))

            # Prefers the SFO TITLE_ID
            self.assertEqual(package.get_title_id_folder_name(), "CUSA12345")

            # Falls back to the content ID when no SFO title is available
            package.title_id = None
            self.assertEqual(package.get_title_id_folder_name(), "CUSA12345")

            # Falls back to a sanitized file name when neither is present
            package.title_id = None
            package.content_id = None
            package.pkg_content_id = None
            self.assertEqual(package.get_title_id_folder_name(), "synthetic")


if __name__ == "__main__":
    unittest.main()
