"""Header-only image inspection for package assets."""

from __future__ import annotations

from dataclasses import dataclass
import struct

from .exceptions import PackageFormatError


@dataclass(frozen=True)
class ImageInfo:
    format: str
    width: int
    height: int
    kind: str
    mipmaps: int | None = None


def classify_image(width: int, height: int) -> str:
    if (width, height) in {(320, 176), (512, 512)}:
        return "icon"
    if (width, height) in {(1920, 1080), (3840, 2160)}:
        return "background"
    return "other"


def inspect_image(data: bytes) -> ImageInfo:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        if len(data) < 33 or data[12:16] != b"IHDR":
            raise PackageFormatError("invalid or truncated PNG IHDR")
        width, height = struct.unpack_from(">II", data, 16)
        if not width or not height:
            raise PackageFormatError("PNG has invalid dimensions")
        return ImageInfo("PNG", width, height, classify_image(width, height))

    if data.startswith(b"DDS "):
        if len(data) < 128 or struct.unpack_from("<I", data, 4)[0] != 124:
            raise PackageFormatError("invalid or truncated DDS header")
        height, width = struct.unpack_from("<II", data, 12)
        mipmaps = struct.unpack_from("<I", data, 28)[0] or 1
        if not width or not height:
            raise PackageFormatError("DDS has invalid dimensions")
        return ImageInfo("DDS", width, height, classify_image(width, height), mipmaps)

    raise PackageFormatError("unsupported image format")
