"""Pure-logic tests for the hex editor dump format (no Qt widgets needed)."""

import unittest

from GUI.widgets.modify_tab import (
    ASCII_COL,
    BYTE0_COL,
    BYTE8_COL,
    LINE_LEN,
    HEX_HEADER,
    ModifyTab,
    encode_search_query,
    format_hex_bytes,
    format_hex_line,
    format_text_bytes,
)


class HexFormatTests(unittest.TestCase):
    def test_line_shape_and_length(self):
        line = format_hex_line(0x1000, bytes(range(16)))
        self.assertEqual(len(line), LINE_LEN)
        # offset column: 8 hex chars, 2 spaces, then the first byte
        self.assertEqual(line[:8], "00001000")
        self.assertEqual(line[8:10], "  ")
        self.assertEqual(line[BYTE0_COL:BYTE0_COL + 2], "00")
        # 8-byte gap between the two hex groups
        self.assertEqual(line[33:35], "  ")
        self.assertEqual(line[BYTE8_COL:BYTE8_COL + 2], "08")
        # ASCII column wrapped in pipes
        self.assertEqual(line[60], "|")
        self.assertEqual(line[61], ".")
        self.assertEqual(line[77], "|")

    def test_short_rows_are_padded_to_full_width(self):
        line = format_hex_line(0, b"\x01\x02")
        self.assertEqual(len(line), LINE_LEN)
        self.assertTrue(line.endswith("|..              |"))

    def test_header_aligns_with_first_byte_column(self):
        self.assertTrue(HEX_HEADER.startswith("Offset"))
        # The first "00" of the header must sit exactly above the first byte
        first_byte_header = HEX_HEADER[BYTE0_COL:BYTE0_COL + 2]
        self.assertEqual(first_byte_header, "00")
        self.assertEqual(HEX_HEADER[BYTE8_COL:BYTE8_COL + 2], "08")

    def test_column_mapping_round_trip(self):
        for byte_idx in range(16):
            col = ModifyTab._byte_col(byte_idx)
            self.assertEqual(ModifyTab._byte_index_at_col(col), byte_idx)
        # The gap between the two groups maps to no byte
        self.assertIsNone(ModifyTab._byte_index_at_col(33))
        self.assertIsNone(ModifyTab._byte_index_at_col(34))
        # ASCII column maps back to bytes
        for byte_idx in range(16):
            self.assertEqual(ModifyTab._byte_index_at_col(ASCII_COL + byte_idx), byte_idx)
        # Columns before the hex area map to nothing
        self.assertIsNone(ModifyTab._byte_index_at_col(9))
        self.assertIsNone(ModifyTab._byte_index_at_col(LINE_LEN))

    def test_split_hex_and_text_rows_stay_byte_aligned(self):
        data = b"Pkg ToolBox\x00\xff"
        hex_row = format_hex_bytes(data)
        text_row = format_text_bytes(data)
        self.assertEqual(len(hex_row), 48)
        self.assertEqual(len(text_row), 16)
        self.assertEqual(text_row[:11], "Pkg ToolBox")
        self.assertEqual(text_row[11:13], "··")
        for byte_idx in range(16):
            col = ModifyTab._hex_byte_col(byte_idx)
            self.assertEqual(ModifyTab._hex_byte_index_at_col(col), byte_idx)

    def test_search_query_accepts_plain_text_and_spaced_hex(self):
        self.assertEqual(encode_search_query("TROPHY", "text"), b"TROPHY")
        self.assertEqual(encode_search_query("54 52 50", "hex"), b"TRP")
        with self.assertRaisesRegex(ValueError, "pairs"):
            encode_search_query("ABC", "hex")


if __name__ == "__main__":
    unittest.main()
