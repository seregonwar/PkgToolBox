"""Dependency-free PS4 PFS/PFSC structural inspection.

This module intentionally performs no speculative decryption. It reports the
container geometry and parses a visible plaintext PFS or PFSC header when one
is present. Protected images remain recognizable without returning corrupt
data or claiming successful extraction.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
import struct

from .binary import BinaryReader, checked_range
from .exceptions import PackageFormatError


PFSC_MAGIC = b"PFSC"


@dataclass(frozen=True)
class PfsReport:
    image_offset: int
    image_size: int
    image_count: int
    image_flags: int
    mount_image_offset: int
    mount_image_size: int
    cache_size: int
    signed_size: int
    seed: str | None
    state: str
    pfsc_offset: int | None = None
    pfsc_block_size: int | None = None
    pfsc_data_length: int | None = None
    pfsc_block_count: int | None = None
    note: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)

    def render(self, as_json: bool = False) -> str:
        if as_json:
            return json.dumps(self.as_dict(), indent=2)
        lines = [
            "--- Internal PFS inspection ---",
            f"State: {self.state}",
            f"Image: offset=0x{self.image_offset:X}, size={self.image_size:,} bytes",
            f"Image count: {self.image_count}",
            f"Image flags: 0x{self.image_flags:X}",
            f"Mount image: offset=0x{self.mount_image_offset:X}, size={self.mount_image_size:,} bytes",
            f"Cache size: {self.cache_size:,} bytes",
            f"Signed size: {self.signed_size:,} bytes",
        ]
        if self.seed:
            lines.append(f"Seed: {self.seed}")
        if self.pfsc_offset is not None:
            lines.extend([
                f"PFSC: offset=0x{self.pfsc_offset:X} relative to PFS",
                f"PFSC block size: {self.pfsc_block_size:,} bytes",
                f"PFSC data length: {self.pfsc_data_length:,} bytes",
                f"PFSC logical blocks: {self.pfsc_block_count:,}",
            ])
        if self.note:
            lines.append(f"Note: {self.note}")
        return "\n".join(lines)


def inspect_pfs(path: str, *, image_offset: int, image_size: int,
                image_count: int = 0, image_flags: int = 0,
                mount_image_offset: int = 0, mount_image_size: int = 0,
                cache_size: int = 0, signed_size: int = 0) -> PfsReport:
    file_size = os.path.getsize(path)
    checked_range(image_offset, image_size, file_size, "PFS image")
    if not image_size:
        return PfsReport(image_offset, image_size, image_count, image_flags,
                         mount_image_offset, mount_image_size, cache_size,
                         signed_size, None, "absent", note="The package declares no PFS image.")

    with open(path, "rb") as fp:
        reader = BinaryReader(fp, file_size)
        seed = None
        if image_size >= 0x380:
            seed = reader.read_at(image_offset + 0x370, 16, "PFS seed").hex()

        scan_size = min(image_size, max(cache_size * 2, 0x30000), 64 * 1024 * 1024)
        sample = reader.read_at(image_offset, scan_size, "PFS inspection window")

    pfsc_relative = None
    for relative in range(0, max(0, len(sample) - 4) + 1, 0x10000):
        if sample[relative:relative + 4] == PFSC_MAGIC:
            pfsc_relative = relative
            break

    if pfsc_relative is None:
        return PfsReport(
            image_offset, image_size, image_count, image_flags,
            mount_image_offset, mount_image_size, cache_size, signed_size,
            seed, "protected-or-unsupported",
            note=("No plaintext PFSC header is visible in the inspected window. "
                  "The image is normally AES-XTS protected; metadata entries in clear text remain extractable."),
        )

    if pfsc_relative + 0x30 > len(sample):
        raise PackageFormatError("truncated PFSC header")
    magic, _unk4, _unk8, block_size, block_size_2, block_offsets, _data_start, data_length = \
        struct.unpack_from("<4i4q", sample, pfsc_relative)
    if magic != 0x43534650 or block_size_2 <= 0 or data_length < 0:
        raise PackageFormatError("invalid PFSC header values")
    block_count = data_length // block_size_2
    map_size = (block_count + 1) * 8
    if block_offsets < 0 or pfsc_relative + block_offsets + map_size > image_size:
        raise PackageFormatError("PFSC sector map is outside the PFS image")

    return PfsReport(
        image_offset, image_size, image_count, image_flags,
        mount_image_offset, mount_image_size, cache_size, signed_size,
        seed, "plaintext-pfsc", pfsc_relative, block_size_2,
        data_length, block_count,
        note="PFSC structure validated without an external executable.",
    )
