"""Validated, dependency-free PS4 PKG metadata reader."""

from __future__ import annotations

import os
import tempfile

from Utilities import Logger

from .binary import BinaryReader, checked_range, decode_c_string
from .exceptions import PackageBoundsError, PackageFormatError, UnsupportedFeatureError
from .metadata import (
    describe_content_flags,
    describe_content_type,
    describe_drm_type,
    infer_region,
)
from .package_base import PackageBase
from .pfs import inspect_pfs
from .pkg_entry import PKG_ENTRY_ID_TO_NAME_FULL
from .ps4_crypto import (
    ENTRY_KEYS_ID,
    decrypt_entry,
    derive_key,
    parse_entry_key_digests,
    validate_passcode,
    verify_passcode,
)
from .sfo import parse_sfo


class PackagePS4(PackageBase):
    MAGIC_PS4 = 0x7F434E54
    HEADER_SIZE = 0x1000
    ENTRY_SIZE = 0x20
    ENTRY_NAMES_ID = 0x0200
    PARAM_SFO_ID = 0x1000
    MAX_ENTRY_COUNT = 10000
    MAX_METADATA_SIZE = 64 * 1024 * 1024

    def __init__(self, file: str):
        super().__init__(file)
        self.is_ps4 = False
        self.invalid_irotag = False
        self.sfo = None
        self.sfo_values = {}
        self.title_id = None
        self.title_name = None
        self.region = None
        self.pfs_image_count = 0
        self.pfs_image_flags = 0
        self.pfs_image_offset = 0
        self.pfs_image_size = 0
        self.mount_image_offset = 0
        self.mount_image_size = 0
        self.pkg_size = 0
        self.pfs_signed_size = 0
        self.pfs_cache_size = 0
        self.pfs_image_digest = None
        self.pfs_signed_digest = None
        self._pfs_report = None
        self._entry_key_digests = None

        with open(file, "rb") as fp:
            reader = BinaryReader(fp)
            magic = reader.unpack_at(">I", 0, "PS4 magic")
            if magic != self.MAGIC_PS4:
                raise PackageFormatError(f"Unknown PKG format: {magic:08X}")
            self._load(reader)
        self.is_ps4 = True

    def _load(self, reader: BinaryReader) -> None:
        if reader.size < 0xA0:
            raise PackageFormatError("truncated PS4 PKG header")
        header_format = ">5I2H2I4Q36s12s12I"
        values = reader.unpack_at(header_format, 0, "PS4 header")
        (
            self.pkg_magic, self.pkg_type, self.pkg_0x008, self.pkg_file_count,
            self.pkg_entry_count, self.pkg_sc_entry_count, self.pkg_entry_count_2,
            self.pkg_table_offset, self.pkg_entry_data_size, self.pkg_body_offset,
            self.pkg_body_size, self.pkg_content_offset, self.pkg_content_size,
            raw_content_id, self.pkg_padding, self.pkg_drm_type,
            self.pkg_content_type, self.pkg_content_flags, self.pkg_promote_size,
            self.pkg_version_date, self.pkg_version_hash, self.pkg_0x088,
            self.pkg_0x08C, self.pkg_0x090, self.pkg_0x094, self.pkg_iro_tag,
            self.pkg_drm_type_version,
        ) = values

        if not 0 < self.pkg_entry_count <= self.MAX_ENTRY_COUNT:
            raise PackageFormatError(f"invalid PS4 entry count: {self.pkg_entry_count}")
        if self.pkg_entry_count_2 not in (0, self.pkg_entry_count):
            raise PackageFormatError("PS4 entry-count fields disagree")
        if self.pkg_table_offset < 0xA0:
            raise PackageFormatError(f"invalid PS4 entry table offset: 0x{self.pkg_table_offset:X}")
        self.entry_table_offset = self.pkg_table_offset
        self.entry_table_size = self.pkg_entry_count * self.ENTRY_SIZE
        checked_range(self.entry_table_offset, self.entry_table_size, reader.size, "PS4 entry table")
        checked_range(self.pkg_body_offset, self.pkg_body_size, reader.size, "PS4 body")
        checked_range(self.pkg_content_offset, self.pkg_content_size, reader.size, "PS4 content")

        self.pkg_content_id = decode_c_string(raw_content_id)
        self.content_id = self.pkg_content_id
        self.drm_type = self.pkg_drm_type
        self.content_type = self.pkg_content_type
        self.content_flags = self.pkg_content_flags
        self.version_date = self.pkg_version_date
        self.version_hash = self.pkg_version_hash
        self.iro_tag = self.pkg_iro_tag

        digests = reader.read_at(0x100, 0x80, "PS4 digest table") if reader.size >= 0x180 else b""
        self.digests = [digests[i:i + 32].hex() for i in range(0, len(digests), 32)]
        self._read_pfs_header(reader)
        self._load_entries(reader)
        self._load_sfo()

    def _read_pfs_header(self, reader: BinaryReader) -> None:
        if reader.size < 0x490:
            return
        (
            self.pfs_image_count, self.pfs_image_flags, self.pfs_image_offset,
            self.pfs_image_size, self.mount_image_offset, self.mount_image_size,
            self.pkg_size, self.pfs_signed_size, self.pfs_cache_size,
        ) = reader.unpack_at(">I6Q2I", 0x404, "PS4 PFS header")
        self.pfs_image_digest = reader.read_at(0x440, 0x20, "PFS image digest").hex()
        self.pfs_signed_digest = reader.read_at(0x460, 0x20, "PFS signed digest").hex()
        if self.pfs_image_size:
            checked_range(self.pfs_image_offset, self.pfs_image_size, reader.size, "PFS image")
        if self.mount_image_size:
            checked_range(self.mount_image_offset, self.mount_image_size, reader.size, "mount image")
        if self.pkg_size and self.pkg_size > reader.size:
            raise PackageBoundsError(
                f"declared package size 0x{self.pkg_size:X} exceeds file size 0x{reader.size:X}"
            )

    def _load_entries(self, reader: BinaryReader) -> None:
        self.files = {}
        for index in range(self.pkg_entry_count):
            offset = self.pkg_table_offset + index * self.ENTRY_SIZE
            file_id, name_offset, flags1, flags2, data_offset, size, padding = \
                reader.unpack_at(">6IQ", offset, f"PS4 entry {index}")
            checked_range(data_offset, size, reader.size, f"PS4 entry 0x{file_id:04X}")
            if file_id in self.files:
                raise PackageFormatError(f"duplicate PS4 entry ID 0x{file_id:04X}")
            self.files[file_id] = {
                "id": file_id,
                "fn_offset": name_offset,
                "name_table_offset": name_offset,
                "flags1": flags1,
                "flags2": flags2,
                "offset": data_offset,
                "size": size,
                "padding": padding,
                "key_idx": (flags2 & 0xF000) >> 12,
                "encrypted": bool(flags1 & self.FLAG_ENCRYPTED),
            }

        names_entry = self.files.get(self.ENTRY_NAMES_ID)
        names = b""
        if names_entry and not names_entry["encrypted"] and names_entry["size"]:
            if names_entry["size"] > self.MAX_METADATA_SIZE:
                raise PackageFormatError("PS4 entry-names table is unreasonably large")
            names = reader.read_at(names_entry["offset"], names_entry["size"], "PS4 entry names")

        for file_id, entry in self.files.items():
            dynamic_name = None
            name_offset = entry["name_table_offset"]
            if names and name_offset:
                if name_offset < len(names):
                    end = names.find(b"\0", name_offset)
                    if end >= 0:
                        try:
                            dynamic_name = names[name_offset:end].decode("utf-8")
                        except UnicodeDecodeError:
                            Logger.log_warning(f"Invalid UTF-8 filename for entry 0x{file_id:04X}")
                else:
                    Logger.log_warning(f"Filename offset outside entry_names for 0x{file_id:04X}")
            entry["name"] = dynamic_name or PKG_ENTRY_ID_TO_NAME_FULL.get(file_id, f"file_{file_id:04X}")
        if names_entry:
            names_entry["name"] = "entry_names"

    def _load_sfo(self) -> None:
        entry = self.files.get(self.PARAM_SFO_ID)
        if not entry or entry["encrypted"]:
            return
        if entry["size"] > self.MAX_METADATA_SIZE:
            raise PackageFormatError("param.sfo is unreasonably large")
        self.sfo = parse_sfo(self.read_file(self.PARAM_SFO_ID))
        self.sfo_values = self.sfo.as_dict()
        self.title_id = self.sfo_values.get("TITLE_ID")
        self.title_name = self.sfo_values.get("TITLE") or self.sfo_values.get("TITLE_00")
        self.region = infer_region(self.title_id, "ps4")

    def is_encrypted(self) -> bool:
        return any(entry.get("encrypted", False) for entry in self.files.values())

    def get_file_data(self, file_id, *, allow_encrypted=False):
        return self.read_file(file_id, allow_encrypted=allow_encrypted)

    def dump(self, output_dir):
        return self.extract_all_files(output_dir)

    def get_pfs_report(self):
        if self._pfs_report is None:
            self._pfs_report = inspect_pfs(
                self.original_file,
                image_offset=self.pfs_image_offset,
                image_size=self.pfs_image_size,
                image_count=self.pfs_image_count,
                image_flags=self.pfs_image_flags,
                mount_image_offset=self.mount_image_offset,
                mount_image_size=self.mount_image_size,
                cache_size=self.pfs_cache_size,
                signed_size=self.pfs_signed_size,
            )
        return self._pfs_report

    def get_pfs_info(self, as_json: bool = False) -> str:
        return self.get_pfs_report().render(as_json=as_json)

    def get_sfo_info(self, as_json: bool = False):
        if not self.sfo:
            raise PackageFormatError("param.sfo is absent or encrypted")
        return self.sfo.to_json() if as_json else self.sfo.as_dict()

    def get_entry_key_digests(self):
        """Return the verified ENTRY_KEYS digest table used for passcodes."""
        if self._entry_key_digests is None:
            entry = self.files.get(ENTRY_KEYS_ID)
            if not entry:
                raise PackageFormatError("PS4 package has no ENTRY_KEYS entry (0x0010)")
            if entry.get("encrypted"):
                raise PackageFormatError("PS4 ENTRY_KEYS is unexpectedly encrypted")
            self._entry_key_digests = parse_entry_key_digests(self.read_file(ENTRY_KEYS_ID))
        return self._entry_key_digests

    def check_passcode(self, passcode: str) -> bool:
        validate_passcode(passcode)
        return verify_passcode(self.content_id, passcode, self.get_entry_key_digests())

    def read_file_with_passcode(self, file_id: int, passcode: str) -> bytes:
        """Read one entry, decrypting it only after authenticating the passcode."""
        if not self.check_passcode(passcode):
            raise ValueError("Incorrect PS4 package passcode")
        entry = self.files.get(file_id)
        if not entry:
            raise ValueError(f"File with ID {file_id} not found in the package")
        raw = self.read_file(file_id, allow_encrypted=True)
        return decrypt_entry(raw, self.content_id, passcode, entry)

    def extract_with_passcode(self, passcode, output_dir):
        validate_passcode(passcode)
        if not self.check_passcode(passcode):
            raise ValueError("Incorrect PS4 package passcode; no output was written")

        os.makedirs(output_dir, exist_ok=True)
        extracted = 0
        skipped = 0
        for file_id, entry in self.files.items():
            temporary_path = None
            try:
                name = entry.get("name", f"file_{file_id:04X}")
                output_path = self._safe_output_path(output_dir, name)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                data = self.read_file(file_id, allow_encrypted=True)
                if entry.get("encrypted"):
                    data = decrypt_entry(data, self.content_id, passcode, entry)
                with tempfile.NamedTemporaryFile(
                    mode="wb", dir=os.path.dirname(output_path),
                    prefix=".pkgtoolbox-", delete=False,
                ) as target:
                    temporary_path = target.name
                    target.write(data)
                os.replace(temporary_path, output_path)
                temporary_path = None
                extracted += 1
            except Exception as exc:
                if temporary_path:
                    try:
                        os.remove(temporary_path)
                    except OSError:
                        pass
                skipped += 1
                Logger.log_error(f"Could not extract PS4 entry 0x{file_id:04X}: {exc}")

        # EKPFS is derived here as part of the authenticated extraction path.
        # The filesystem reader consumes it when a PFS image is present.
        ekpfs = derive_key(self.content_id, passcode, 1)
        pfs_extracted = 0
        if self.pfs_image_size:
            from .pfs import extract_pfs
            pfs_extracted = extract_pfs(
                self.original_file,
                os.path.join(output_dir, "pfs"),
                image_offset=self.pfs_image_offset,
                image_size=self.pfs_image_size,
                image_flags=self.pfs_image_flags,
                ekpfs=ekpfs,
            )
        return (
            f"Authenticated PS4 extraction completed: {extracted} CNT entries, "
            f"{pfs_extracted} PFS files, {skipped} skipped. Output: {output_dir}"
        )

    def decrypt_pkg(self, key, output_dir):
        raise UnsupportedFeatureError(
            "Whole-file AES-CBC decryption was removed because PS4 PKG/PFS does not use that layout."
        )

    def get_info(self):
        info = super().get_info()
        info.update({
            "platform": "PS4",
            "pkg_magic": f"0x{self.pkg_magic:08X}",
            "pkg_type": f"0x{self.pkg_type:X}",
            "pkg_file_count": self.pkg_file_count,
            "pkg_entry_count": self.pkg_entry_count,
            "pkg_sc_entry_count": self.pkg_sc_entry_count,
            "pkg_table_offset": f"0x{self.pkg_table_offset:X}",
            "pkg_body_offset": f"0x{self.pkg_body_offset:X}",
            "pkg_body_size": self.pkg_body_size,
            "pkg_content_id": self.pkg_content_id,
            "title_id": self.title_id,
            "title_name": self.title_name,
            "region": self.region,
            "app_version": self.sfo_values.get("APP_VER"),
            "version": self.sfo_values.get("VERSION"),
            "category": self.sfo_values.get("CATEGORY"),
            "system_version": self.sfo_values.get("SYSTEM_VER"),
            "pkg_drm_type": describe_drm_type(self.pkg_drm_type),
            "pkg_content_type": describe_content_type(self.pkg_content_type),
            "pkg_content_flags": describe_content_flags(self.pkg_content_flags),
            "encrypted_entries": sum(1 for entry in self.files.values() if entry["encrypted"]),
            "plaintext_entries": sum(1 for entry in self.files.values() if not entry["encrypted"]),
            "pfs_state": self.get_pfs_report().state,
            "pfs_image_offset": f"0x{self.pfs_image_offset:X}",
            "pfs_image_size": self.pfs_image_size,
            "pfs_image_flags": f"0x{self.pfs_image_flags:X}",
            "pfs_cache_size": self.pfs_cache_size,
            "pfs_image_digest": self.pfs_image_digest,
            "pfs_signed_digest": self.pfs_signed_digest,
            "sfo_entry_count": len(self.sfo.entries) if self.sfo else 0,
            "image_asset_count": len(self.list_image_assets()),
        })
        for key, value in self.sfo_values.items():
            info[f"sfo.{key}"] = value.hex() if isinstance(value, bytes) else value
        return info
