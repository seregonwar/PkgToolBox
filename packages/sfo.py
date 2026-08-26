"""Parser for PlayStation PARAM.SFO/PSF metadata."""

from __future__ import annotations

from dataclasses import dataclass
import json
import struct
from typing import Any

from .binary import checked_range
from .exceptions import PackageFormatError


PSF_MAGIC = b"\x00PSF"
PSF_FORMAT_BINARY = 0x0004
PSF_FORMAT_TEXT = 0x0204
PSF_FORMAT_INTEGER = 0x0404
MAX_SFO_ENTRIES = 4096


@dataclass(frozen=True)
class SfoEntry:
    key: str
    format: int
    length: int
    max_length: int
    value: Any

    @property
    def format_name(self) -> str:
        return {
            PSF_FORMAT_BINARY: "binary",
            PSF_FORMAT_TEXT: "text",
            PSF_FORMAT_INTEGER: "integer",
        }.get(self.format, f"unknown-0x{self.format:04X}")


@dataclass(frozen=True)
class SfoDocument:
    version: int
    entries: tuple[SfoEntry, ...]

    def as_dict(self, binary: str = "hex") -> dict[str, Any]:
        result = {}
        for entry in self.entries:
            value = entry.value
            if isinstance(value, bytes):
                value = value.hex() if binary == "hex" else value
            result[entry.key] = value
        return result

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, indent=indent)


def _c_string(data: bytes, offset: int, limit: int, label: str) -> str:
    if offset < 0 or offset >= limit:
        raise PackageFormatError(f"{label} offset is outside its table")
    end = data.find(b"\0", offset, limit)
    if end < 0:
        raise PackageFormatError(f"unterminated {label}")
    try:
        return data[offset:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackageFormatError(f"invalid UTF-8 in {label}") from exc


def parse_sfo(data: bytes) -> SfoDocument:
    """Parse an SFO document with strict offset and length validation."""
    if len(data) < 0x14 or data[:4] != PSF_MAGIC:
        raise PackageFormatError("invalid or truncated PARAM.SFO header")

    version, key_offset, data_offset, count = struct.unpack_from("<4I", data, 4)
    if count > MAX_SFO_ENTRIES:
        raise PackageFormatError(f"unreasonable PARAM.SFO entry count: {count}")
    index_end = 0x14 + count * 0x10
    if key_offset < index_end or data_offset < key_offset or data_offset > len(data):
        raise PackageFormatError("invalid PARAM.SFO table layout")

    entries = []
    for index in range(count):
        record_offset = 0x14 + index * 0x10
        key_relative = struct.unpack_from("<H", data, record_offset)[0]
        value_format = struct.unpack_from(">H", data, record_offset + 2)[0]
        length, max_length, value_relative = struct.unpack_from("<3I", data, record_offset + 4)
        if max_length and length > max_length:
            raise PackageFormatError(f"PARAM.SFO value #{index} exceeds its declared maximum length")

        key_absolute = key_offset + key_relative
        key = _c_string(data, key_absolute, data_offset, f"key #{index}")
        value_absolute = data_offset + value_relative
        checked_range(value_absolute, length, len(data), f"PARAM.SFO value {key}")
        raw = data[value_absolute:value_absolute + length]

        if value_format == PSF_FORMAT_TEXT:
            try:
                value = raw.split(b"\0", 1)[0].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PackageFormatError(f"invalid UTF-8 value for {key}") from exc
        elif value_format == PSF_FORMAT_INTEGER:
            if length < 4:
                raise PackageFormatError(f"integer value {key} is shorter than four bytes")
            value = struct.unpack_from("<I", raw)[0]
        else:
            value = raw

        entries.append(SfoEntry(key, value_format, length, max_length, value))

    return SfoDocument(version, tuple(entries))
