"""Tests for the SELF/ELF parser and the Game Info tool (PS5 + PS4)."""

import json
import os
import struct
import tempfile
import unittest

from packages.exceptions import PackageFormatError
from packages.self_info import (
    ELF_MAGIC,
    SELF_MAGIC,
    detect_kind,
    format_packed_version,
    parse_elf_header,
    parse_self,
)
from packages.sfo import PSF_FORMAT_INTEGER, PSF_FORMAT_TEXT, parse_sfo
from tools.PS5_Game_Info import PS5GameInfo


# ---------------------------------------------------------------------------
# synthetic builders
# ---------------------------------------------------------------------------

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
    struct.pack_into("<4I", output, 4, 0x00000101, key_table_offset, data_table_offset,
                     len(records))
    for index, (key_offset, value_format, length, max_length, value_offset) in enumerate(records):
        base = 0x14 + index * 0x10
        struct.pack_into("<H", output, base, key_offset)
        struct.pack_into(">H", output, base + 2, value_format)
        struct.pack_into("<3I", output, base + 4, length, max_length, value_offset)
    output[key_table_offset:data_table_offset] = keys
    output[data_table_offset:] = value_data
    return bytes(output)


def build_elf64(entry=0x1000, e_type=0xFE00, machine=0x3E, phnum=2):
    elf_len = 0x40 + phnum * 0x38
    elf = bytearray(elf_len)
    elf[0:4] = ELF_MAGIC
    elf[4] = 2          # 64-bit
    elf[5] = 1          # little-endian
    elf[7] = 0x09       # FreeBSD/Orbis ABI
    struct.pack_into("<H", elf, 0x10, e_type)
    struct.pack_into("<H", elf, 0x12, machine)
    struct.pack_into("<Q", elf, 0x18, entry)
    struct.pack_into("<Q", elf, 0x20, 0x40)     # e_phoff
    struct.pack_into("<H", elf, 0x34, 0x40)     # e_ehsize
    struct.pack_into("<H", elf, 0x36, 0x38)     # e_phentsize
    struct.pack_into("<H", elf, 0x38, phnum)    # e_phnum
    return bytes(elf)


def build_self(authority_id=0x3100000000000001, app_version=0x01020000,
               firmware_version=0x05010000, magic=SELF_MAGIC, seg_count=0):
    elf_start = 0x20 + seg_count * 0x20
    elf = build_elf64()
    elf_len = len(elf)
    ext_start = (elf_start + elf_len + 0xF) & ~0xF
    header_size = ext_start + 0x40 + 0x30
    out = bytearray(header_size)
    struct.pack_into("<I", out, 0, magic)
    out[0x04] = 0            # version
    out[0x05] = 1            # mode (retail)
    out[0x06] = 1            # endian
    out[0x07] = 0x12         # attributes
    struct.pack_into("<I", out, 0x08, 0x00000101)   # program type
    struct.pack_into("<H", out, 0x0C, header_size)
    struct.pack_into("<H", out, 0x0E, 0x100)
    struct.pack_into("<Q", out, 0x10, header_size)
    struct.pack_into("<H", out, 0x18, seg_count)
    struct.pack_into("<H", out, 0x1A, 0x0022)
    out[elf_start:elf_start + elf_len] = elf
    struct.pack_into("<Q", out, ext_start, authority_id)
    struct.pack_into("<Q", out, ext_start + 0x08, 1)            # program type
    struct.pack_into("<Q", out, ext_start + 0x10, app_version)
    struct.pack_into("<Q", out, ext_start + 0x18, firmware_version)
    out[ext_start + 0x20:ext_start + 0x40] = bytes(range(32))    # digest
    return bytes(out)


def build_param_json():
    return {
        "titleId": "PPSA99099",
        "contentId": "UP9000-PPSA99099_00-PROSPERO00000000",
        "contentVersion": "01.000.000",
        "masterVersion": "01.00",
        "requiredSystemSoftwareVersion": "0x0200000000000000",
        "sdkVersion": "0x0200000000000000",
        "applicationDrmType": "free",
        "localizedParameters": {
            "defaultLanguage": "en-US",
            "en-US": {"titleName": "LibProsperoPKG"},
        },
        "pubtools": {"creationDate": "2026-01-01 00:00:00", "toolVersion": "2.00"},
        "ageLevel": {"US": 0, "DE": 0},
    }


# ---------------------------------------------------------------------------
# self_info
# ---------------------------------------------------------------------------

class SelfInfoTests(unittest.TestCase):
    def test_detect_kind(self):
        self.assertEqual(detect_kind(b"\x7fELF" + b"\x00" * 8), "elf")
        self.assertEqual(detect_kind(struct.pack("<I", SELF_MAGIC) + b"\x00" * 8), "self")
        self.assertEqual(detect_kind(b"\x00" * 16), "unknown")
        self.assertEqual(detect_kind(b""), "unknown")

    def test_parse_elf_header_64(self):
        elf = build_elf64(entry=0x1000)
        header = parse_elf_header(elf)
        self.assertIsNotNone(header)
        self.assertEqual(header.class_name, "64-bit")
        self.assertEqual(header.endian_name, "little-endian")
        self.assertEqual(header.machine_name, "x86-64")
        self.assertEqual(header.type_name, "ET_SCE_EXEC (PS executable)")
        self.assertEqual(header.e_entry, 0x1000)
        self.assertEqual(header.e_phnum, 2)
        self.assertEqual(header.e_phentsize, 0x38)

    def test_parse_self_with_fake_authority(self):
        data = build_self(authority_id=0x3100000000000001)
        info = parse_self(data)
        self.assertEqual(info.magic, SELF_MAGIC)
        self.assertEqual(info.mode_name, "retail")
        self.assertTrue(info.is_fake)
        self.assertIsNotNone(info.ext_info)
        self.assertEqual(info.ext_info.authority_id, 0x3100000000000001)
        self.assertEqual(info.elf.machine_name, "x86-64")
        self.assertEqual(info.elf.e_entry, 0x1000)

    def test_parse_self_with_signed_authority(self):
        data = build_self(authority_id=0x1D00000000000001)
        info = parse_self(data)
        self.assertFalse(info.is_fake)

    def test_parse_self_rejects_bad_magic(self):
        with self.assertRaises(PackageFormatError):
            parse_self(b"\x00" * 0x40)
        with self.assertRaises(PackageFormatError):
            parse_self(b"\x00" * 8)

    def test_parse_self_rejects_oversized_segment_table(self):
        data = build_self(seg_count=0)
        # Corrupt segment count so the table would overrun the buffer.
        bad = bytearray(data)
        struct.pack_into("<H", bad, 0x18, 0xFFFF)
        with self.assertRaises(PackageFormatError):
            parse_self(bytes(bad))

    def test_format_packed_version(self):
        self.assertEqual(format_packed_version(0x01020304), "01.02.03.04")
        self.assertEqual(format_packed_version(0x0100), "01.00")
        self.assertEqual(format_packed_version(0x0900), "09.00")
        self.assertEqual(format_packed_version(0), "00")


# ---------------------------------------------------------------------------
# PS5GameInfo tool
# ---------------------------------------------------------------------------

class GameInfoToolTests(unittest.TestCase):
    def test_process_ps5_folder(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "eboot.bin"), "wb") as f:
                f.write(build_self())
            os.makedirs(os.path.join(temp_dir, "sce_sys"), exist_ok=True)
            with open(os.path.join(temp_dir, "sce_sys", "param.json"), "w",
                      encoding="utf-8") as f:
                json.dump(build_param_json(), f)

            result = PS5GameInfo().process(temp_dir)
            self.assertEqual(result["platform"], "ps5")
            self.assertEqual(result["editable"], "param.json")
            by_title = {group["title"]: group for group in result["groups"]}
            eboot_rows = dict((label, value) for label, value, _e, _t in
                              by_title["eboot.bin"]["rows"])
            self.assertEqual(eboot_rows["Format"], "SELF (SCE ELF)")
            self.assertEqual(eboot_rows["Signed / Fake"], "Fake (fake authority id)")
            self.assertEqual(eboot_rows["Architecture"],
                             "x86-64 (64-bit, little-endian)")
            game_rows = dict((label, value) for label, value, _e, _t in
                             by_title["Game"]["rows"])
            self.assertEqual(game_rows["Title"], "LibProsperoPKG")
            self.assertEqual(game_rows["Title ID"], "PPSA99099")
            self.assertEqual(game_rows["Region"], "US")
            self.assertEqual(game_rows["Required System Software"], "02.00")

    def test_process_ps4_folder_with_sfo(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "eboot.bin"), "wb") as f:
                f.write(build_self())
            os.makedirs(os.path.join(temp_dir, "sce_sys"), exist_ok=True)
            with open(os.path.join(temp_dir, "sce_sys", "param.sfo"), "wb") as f:
                f.write(build_sfo([
                    ("TITLE", "Caffè Racer"),
                    ("TITLE_ID", "CUSA12345"),
                    ("CONTENT_ID", "EP0000-CUSA12345_00-SYNTHETIC000000"),
                    ("APP_VER", "01.23"),
                    ("VERSION", "01.000.000"),
                    ("CATEGORY", "gd"),
                    ("PARENTAL_LEVEL", 7),
                ]))

            result = PS5GameInfo().process(temp_dir)
            self.assertEqual(result["platform"], "ps4")
            self.assertIsNone(result["editable"])
            by_title = {group["title"]: group for group in result["groups"]}
            game_rows = dict((label, value) for label, value, _e, _t in
                             by_title["Game"]["rows"])
            self.assertEqual(game_rows["Platform"], "PS4")
            self.assertEqual(game_rows["Title"], "Caffè Racer")
            self.assertEqual(game_rows["Title ID"], "CUSA12345")
            self.assertEqual(game_rows["Category"], "Game (Digital)")
            self.assertEqual(game_rows["Region"], "EU")

    def test_process_missing_eboot_returns_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = PS5GameInfo().process(temp_dir)
            self.assertIn("error", result)

    def test_process_unrecognized_eboot_is_flagged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "eboot.bin"), "wb") as f:
                f.write(b"NPDRM-encrypted-garbage" * 4)
            result = PS5GameInfo().process(temp_dir)
            by_title = {group["title"]: group for group in result["groups"]}
            rows = dict((label, value) for label, value, _e, _t in
                        by_title["eboot.bin"]["rows"])
            self.assertEqual(rows["Format"], "Unrecognized")

    def test_bare_elf_eboot_is_flagged_unprotected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "eboot.bin"), "wb") as f:
                f.write(build_elf64())
            result = PS5GameInfo().process(temp_dir)
            by_title = {group["title"]: group for group in result["groups"]}
            rows = dict((label, value) for label, value, _e, _t in
                        by_title["eboot.bin"]["rows"])
            self.assertEqual(rows["Format"], "ELF (plaintext)")
            self.assertEqual(rows["Signed / Fake"], "Unprotected (decrypted ELF)")

    def test_save_param_json_dotted_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "param.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(build_param_json(), f)

            applied = PS5GameInfo().save_param_json(path, {
                "titleId": "PPSA99999",
                "localizedParameters.en-US.titleName": "Edited Title",
                "does.not.exist": "ignored",
            })
            self.assertEqual(applied, 2)
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["titleId"], "PPSA99999")
            self.assertEqual(data["localizedParameters"]["en-US"]["titleName"],
                             "Edited Title")
            self.assertNotIn("does", data)

    def test_sfo_roundtrip_uses_packages_parser(self):
        document = parse_sfo(build_sfo([("TITLE", "Caffè"), ("PARENTAL_LEVEL", 7)]))
        self.assertEqual(document.as_dict(),
                         {"TITLE": "Caffè", "PARENTAL_LEVEL": 7})


if __name__ == "__main__":
    unittest.main()
