import struct
import os
import json
import zipfile
import tempfile
from .package_base import PackageBase
from .exceptions import PackageBoundsError, PackageFormatError
from .metadata import infer_region
from .pfs_fs import (
    find_pfs_superblock,
    open_ps5_outer_pfs,
    parse_inner_image,
)
from .pkg_entry import PKG_ENTRY_ID_TO_NAME_FULL
from .ps5_crypto import derive_ekpfs
from Utilities import Logger

class PackagePS5(PackageBase):
    MAGIC_PS5 = 0x7F464948  # \x7fFIH
    MAGIC_PS5_META = 0x7F434E54  # standalone \x7fCNT envelope
    MAGIC_CNT = b"\x7fCNT"
    FIH_HEADER_SIZE = 0x10000
    CNT_HEADER_SIZE = 0x5A0
    CNT_ENTRY_SIZE = 0x20
    ENTRY_NAMES_ID = 0x0200
    CNT_PACKAGE_DIGEST_OFFSET = 0xFE0
    MAX_ENTRY_COUNT = 10000
    MAX_SI_ENTRY_COUNT = 10000
    MAX_SI_TOTAL_SIZE = 8 * 1024 * 1024 * 1024
    MAX_METADATA_SIZE = 64 * 1024 * 1024

    def __init__(self, file: str):
        super().__init__(file)
        self.is_ps5 = False
        self.pkg_type = None
        self.pkg_revision = None
        self.pkg_file_count = 0
        self.entry_table_offset = None
        self.entry_table_size = None
        self.body_offset = None
        self.body_size = None
        self.promote_size = None
        self.version_date = None
        self.version_hash = None
        self.iro_tag = None
        self.package_digest = None
        self.pfs_area_digest = None
        self.fih_offset = None
        self.fih_size = None
        self.pfs_offset = None
        self.pfs_size = None
        self.sc_offset = None
        self.sc_size = None
        self.si_offset = None
        self.si_size = None
        self.title_name = None
        self.pkg_sc_entry_count = 0
        self.cnt_offset = None
        self.cnt_flags = None
        self.fih_signed_byte = None
        self.fih_format_version = None

        with open(file, "rb") as fp:
            magic_data = fp.read(4)
            if len(magic_data) != 4:
                raise ValueError("Truncated PS5 PKG header")
            magic = struct.unpack(">I", magic_data)[0]
            Logger.log_information(f"Read magic number: {magic:08X}")
            if magic == self.MAGIC_PS5:
                self.is_ps5 = True
                self._load_ps5_pkg(fp)
            elif magic == self.MAGIC_PS5_META:
                self.is_ps5 = True
                self._load_ps5_meta(fp)
            else:
                raise ValueError(f"Unknown PKG format: {magic:08X}")

    def _load_ps5_pkg(self, fp):
        try:
            self._initialize_ps5_fields()

            file_size = os.path.getsize(self.original_file)
            self._read_fih_header(fp, file_size)
            self._read_cnt_header(fp, file_size)
            self.__load_ps5_files(fp, file_size)
            self._read_digests_and_layout(fp)

            # CNT names are relative to sce_sys in finalized PS5 packages.
            param_json = self._find_file_by_name("param.json")
            if param_json and not param_json.get("encrypted"):
                self._parse_param_json(fp, param_json)
            elif param_json:
                Logger.log_warning("param.json is encrypted; metadata parsing was refused")
            else:
                Logger.log_warning("param.json not found in the package")

            self._find_important_files()

        except Exception as e:
            Logger.log_error(f"Error loading PS5 PKG file: {str(e)}")
            self.files = {}
            raise ValueError(f"Error loading PS5 PKG file: {str(e)}")

    def _load_ps5_meta(self, fp):
        """Load a standalone PS5 CNT/meta envelope without the FIH wrapper."""
        try:
            self._initialize_ps5_fields()
            file_size = os.path.getsize(self.original_file)
            self.magic = self.MAGIC_CNT
            self.pkg_type = "meta"
            self.pkg_revision = None
            self.fih_offset = None
            self.fih_size = 0
            self.pfs_offset = None
            self.pfs_size = 0
            self.sc_offset = 0
            self.cnt_offset = 0
            self.fih_signed_byte = None
            self.fih_format_version = None
            self._read_cnt_header(fp, file_size)
            self.__load_ps5_files(fp, file_size)
            self._read_digests_and_layout(fp)
            param_json = self._find_file_by_name("param.json")
            if not param_json:
                raise ValueError("Standalone CNT does not contain param.json; it is probably a PS4 PKG")
            if param_json.get("encrypted"):
                raise ValueError("Standalone PS5 param.json is encrypted")
            self._parse_param_json(fp, param_json)
            self._find_important_files()
        except Exception as e:
            Logger.log_error(f"Error loading PS5 meta PKG file: {str(e)}")
            self.files = {}
            raise ValueError(f"Error loading PS5 meta PKG file: {str(e)}")

    @staticmethod
    def _unpack_from(fmt, data, offset):
        return struct.unpack_from(fmt, data, offset)[0]

    def _read_fih_header(self, fp, file_size):
        """Read the little-endian finalized-image wrapper."""
        fp.seek(0)
        header = fp.read(0x100)
        if len(header) < 0x100 or header[:4] != b"\x7fFIH":
            raise ValueError("Truncated or invalid PS5 FIH header")

        self.magic = header[:4]
        self.fih_signed_byte = header[0x05]
        self.fih_format_version = self._unpack_from("<H", header, 0x06)
        self.pkg_type = {
            0x00: "debug",
            0x80: "retail",
        }.get(self.fih_signed_byte, f"unknown (0x{self.fih_signed_byte:02X})")
        self.pkg_revision = self.fih_format_version
        self.pkg_0x008 = self._unpack_from("<I", header, 0x08)

        self.fih_offset = 0
        self.pfs_offset = self._unpack_from("<Q", header, 0x10)
        self.pfs_size = self._unpack_from("<Q", header, 0x18)
        self.sc_offset = self._unpack_from("<Q", header, 0x58)
        self.cnt_offset = self.sc_offset
        self.fih_size = self.FIH_HEADER_SIZE

        if self.pfs_offset != self.FIH_HEADER_SIZE:
            raise ValueError(f"Invalid PFS offset: 0x{self.pfs_offset:X}")
        if self.pfs_size > file_size - self.pfs_offset:
            raise ValueError(f"PFS region extends beyond end of file: 0x{self.pfs_size:X} bytes")
        if self.sc_offset < self.pfs_offset + self.pfs_size:
            raise ValueError(f"Embedded CNT overlaps the PFS region: 0x{self.sc_offset:X}")
        if self.sc_offset > file_size - self.CNT_HEADER_SIZE:
            raise ValueError(f"Invalid embedded CNT offset: 0x{self.sc_offset:X}")

    def _read_cnt_header(self, fp, file_size):
        """Read the big-endian CNT header embedded at FIH+0x58."""
        fp.seek(self.sc_offset)
        header = fp.read(self.CNT_HEADER_SIZE)
        if len(header) < self.CNT_HEADER_SIZE:
            raise ValueError("Truncated embedded CNT header")
        if header[:4] != self.MAGIC_CNT:
            actual = header[:4].hex().upper()
            raise ValueError(f"Invalid embedded CNT magic at 0x{self.sc_offset:X}: {actual}")

        self.cnt_flags = self._unpack_from(">I", header, 0x04)
        self.pkg_file_count = self._unpack_from(">I", header, 0x10)
        self.pkg_sc_entry_count = self._unpack_from(">H", header, 0x14)
        entry_table_relative = self._unpack_from(">I", header, 0x18)
        self.entry_table_size = self.pkg_file_count * self.CNT_ENTRY_SIZE
        self.entry_table_offset = self.sc_offset + entry_table_relative

        body_relative = self._unpack_from(">Q", header, 0x20)
        self.body_size = self._unpack_from(">Q", header, 0x28)
        self.body_offset = self.sc_offset + body_relative
        self.content_id = self._safe_decode(header[0x40:0x70])
        self.drm_type = self._unpack_from(">I", header, 0x70)
        self.content_type = self._unpack_from(">I", header, 0x74)
        self.content_flags = self._unpack_from(">I", header, 0x78)
        self.promote_size = self._unpack_from(">I", header, 0x7C)
        self.version_date = self._unpack_from(">I", header, 0x80)
        self.version_hash = self._unpack_from(">I", header, 0x84)
        self.iro_tag = self._unpack_from(">I", header, 0x88)

        if not 0 < self.pkg_file_count <= self.MAX_ENTRY_COUNT:
            raise ValueError(f"Invalid CNT entry count: {self.pkg_file_count}")

        table_relative_end = entry_table_relative + self.entry_table_size
        if entry_table_relative < self.CNT_HEADER_SIZE or table_relative_end > file_size - self.sc_offset:
            raise ValueError("CNT entry table is outside the package")

        # The CNT body ends at BodyOffset + BodySize. That boundary is also
        # the start of the optional SI (sce_suppl ZIP) segment.
        self.sc_size = body_relative + self.body_size
        if self.sc_size < max(self.CNT_HEADER_SIZE, table_relative_end):
            raise ValueError(f"Invalid embedded CNT size: 0x{self.sc_size:X}")
        if self.sc_size > file_size - self.sc_offset:
            raise ValueError("Embedded CNT extends beyond end of file")

        self.si_offset = self.sc_offset + self.sc_size
        self.si_size = file_size - self.si_offset

        Logger.log_information(
            f"Embedded CNT at 0x{self.sc_offset:X}: {self.pkg_file_count} entries, "
            f"content ID {self.content_id}"
        )

    def _initialize_ps5_fields(self):
        self.title_id = None
        self.content_version = None
        self.required_system_software_version = None
        self.application_category_type = None
        self.application_drm_type = None
        self.default_language = None
        self.title_names = {}
        self.sdk_version = None
        self.master_version = None
        self.target_content_version = None
        self.origin_content_version = None
        self.pubtools = {}
        self.creation_date = None
        self.publishing_tools_version = None
        self.attribute = None
        self.attribute2 = None
        self.attribute3 = None
        self.content_badge_type = None
        self.download_data_size = None
        self.mass_size = None
        self.flexible_memory_size = None
        self.age_levels = {}
        self.game_intents = []
        self.deeplink_uri = None
        self.version_file_uri = None
        self.region = None
        self.param_json = {}

    def _find_file_by_name(self, name, table=None):
        """Find a file by name with tolerant matching for PS5 packages.

        Normalizes path separators and allows suffix-based matches to account for
        cases where file names are stored without a stable root or with variant separators.
        ``table`` defaults to ``self.files``; pass ``get_all_files()`` to also
        search the PFS payloads.
        """
        if table is None:
            table = self.files
        try:
            def _norm(p: str) -> str:
                if not p:
                    return ""
                p = p.replace("\\", "/")
                # strip common leading prefixes
                while p.startswith("./"):
                    p = p[2:]
                if p.startswith("/"):
                    p = p[1:]
                # Heuristic: fix inverted directory name 'sys_sce' -> 'sce_sys'
                p = p.replace("sys_sce/", "sce_sys/")
                p = p.replace("/sys_sce/", "/sce_sys/")
                return p

            target = _norm(name).lower()
            for file in table.values():
                n = _norm(file.get("name", "")).lower()
                if not n:
                    continue
                if (n == target or n.endswith("/" + target)
                        or target.endswith("/" + n)):
                    return file
            return None
        except Exception:
            # Fallback to exact match if anything goes wrong
            return next((file for file in table.values() if file.get("name") == name), None)

    def _parse_param_json(self, fp, param_json):
        try:
            if param_json["size"] > self.MAX_METADATA_SIZE:
                raise ValueError("param.json is unreasonably large")
            fp.seek(param_json["offset"])
            json_data = fp.read(param_json["size"])
            if len(json_data) != param_json["size"]:
                raise ValueError("param.json is truncated")
            json_content = json.loads(json_data)
            if not isinstance(json_content, dict):
                raise ValueError("param.json root must be an object")
            self.param_json = json_content
            
            self.title_id = json_content.get("titleId")
            self.content_id = json_content.get("contentId")
            self.content_version = json_content.get("contentVersion")
            self.required_system_software_version = json_content.get("requiredSystemSoftwareVersion")
            self.application_category_type = json_content.get("applicationCategoryType")
            self.application_drm_type = json_content.get("applicationDrmType")
            
            localized_params = json_content.get("localizedParameters", {})
            self.default_language = localized_params.get("defaultLanguage")
            self.title_names = {}
            for lang, data in localized_params.items():
                if isinstance(data, dict) and "titleName" in data:
                    self.title_names[lang] = data["titleName"]
            
            self.sdk_version = json_content.get("sdkVersion")
            self.master_version = json_content.get("masterVersion")
            self.target_content_version = json_content.get("targetContentVersion")
            self.origin_content_version = json_content.get("originContentVersion")
            
            self.pubtools = json_content.get("pubtools", {})
            self.creation_date = self.pubtools.get("creationDate")
            self.publishing_tools_version = self.pubtools.get("toolVersion")
            
            self.attribute = json_content.get("attribute")
            self.attribute2 = json_content.get("attribute2")
            self.attribute3 = json_content.get("attribute3")
            self.content_badge_type = json_content.get("contentBadgeType")
            
            self.download_data_size = json_content.get("downloadDataSize")
            self.mass_size = json_content.get("massSize")
            
            kernel_info = json_content.get("kernel", {})
            self.flexible_memory_size = kernel_info.get("flexibleMemorySize")
            
            self.age_levels = json_content.get("ageLevel", {})
            
            game_intents = json_content.get("gameIntent", {}).get("permittedIntents", [])
            self.game_intents = [intent.get("intentType") for intent in game_intents if "intentType" in intent]
            
            self.deeplink_uri = json_content.get("deeplinkUri")
            self.version_file_uri = json_content.get("versionFileUri")
            self.title_name = (
                self.title_names.get(self.default_language)
                or self.title_names.get("en-US")
                or next(iter(self.title_names.values()), None)
            )
            self.region = infer_region(self.title_id, "ps5")
            
            Logger.log_information(f"Parsed param.json: Title ID: {self.title_id}, Content ID: {self.content_id}, Default Title: {self.title_names.get(self.default_language)}")
        except Exception as e:
            Logger.log_error(f"Error parsing param.json: {str(e)}")
            raise ValueError(f"Invalid PS5 param.json: {e}") from e

    def _find_important_files(self):
        # If files table is empty or missing, skip noisy warnings (likely encrypted/corrupted)
        if not getattr(self, 'files', None):
            Logger.log_information("Skipping important files check: no file index available (package may be encrypted)")
            return
        important_files = [
            "eboot.bin",
            "sce_sys/icon0.png",
            "sce_sys/pic0.png",
            "sce_sys/pic1.png",
            "sce_sys/playgo-chunk.dat",
            "sce_sys/playgo-manifest.xml",
            "sce_sys/trophy/trophy00.trp"
        ]

        # Only search the PFS payloads when they were already decrypted (the
        # outer-image decrypt is expensive and the browser calls it lazily).
        candidates = self.get_all_files() if getattr(self, "_pfs_fs", None) is not None else self.files
        for file_name in important_files:
            file_info = self._find_file_by_name(file_name, table=candidates)
            if file_info:
                Logger.log_information(f"Found important file: {file_name}")
            else:
                Logger.log_warning(f"Important file not found: {file_name}")

    def _read_digests_and_layout(self, fp):
        try:
            # FIH+0x30 contains the game/superblock digest. Keep the legacy
            # pfs_area_digest attribute as a compatibility alias for it.
            if self.fih_offset is not None:
                fp.seek(0x30)
                self.pfs_area_digest = fp.read(32).hex()
            else:
                self.pfs_area_digest = None

            package_digest_offset = self.sc_offset + self.CNT_PACKAGE_DIGEST_OFFSET
            if package_digest_offset + 32 <= self.sc_offset + self.sc_size:
                fp.seek(package_digest_offset)
                self.package_digest = fp.read(32).hex()
            else:
                self.package_digest = None

            if (self.package_digest in (None, '0' * 64)
                    and self.pfs_area_digest in (None, '0' * 64)):
                Logger.log_warning("PS5 package and PFS digests are unavailable or all zeros")
            
            Logger.log_information(f"Package digest: {self.package_digest}")
            Logger.log_information(f"PFS area digest: {self.pfs_area_digest}")

            if self.fih_offset is not None:
                Logger.log_information(f"FIH: offset 0x{self.fih_offset:X}, size 0x{self.fih_size:X}")
            if self.pfs_offset is not None:
                Logger.log_information(f"PFS: offset 0x{self.pfs_offset:X}, size 0x{self.pfs_size:X}")
            Logger.log_information(f"SC: offset 0x{self.sc_offset:X}, size 0x{self.sc_size:X}")
            Logger.log_information(f"SI: offset 0x{self.si_offset:X}, size 0x{self.si_size:X}")

        except Exception as e:
            Logger.log_error(f"Error reading digests and layout: {str(e)}")
            raise

    def __load_ps5_files(self, fp, file_size):
        try:
            Logger.log_information(f"Loading PS5 files. Entry table offset: 0x{self.entry_table_offset:X}, size: 0x{self.entry_table_size:X}")

            fp.seek(self.entry_table_offset)
            entry_count = self.pkg_file_count
            entry_format = ">6I8x"
            self.files = {}
            for i in range(entry_count):
                try:
                    entry_data = fp.read(self.CNT_ENTRY_SIZE)
                    if len(entry_data) < self.CNT_ENTRY_SIZE:
                        Logger.log_warning(f"Reached end of file while reading entries. Processed {i} entries.")
                        break
                    (file_id, name_table_offset, flags1, flags2,
                     relative_offset, entry_size) = struct.unpack(entry_format, entry_data)
                    absolute_offset = self.sc_offset + relative_offset

                    if (absolute_offset < self.sc_offset
                            or absolute_offset > file_size
                            or entry_size > file_size - absolute_offset
                            or relative_offset + entry_size > self.sc_size):
                        raise ValueError(
                            f"CNT entry 0x{file_id:04X} is outside the embedded container: "
                            f"offset 0x{relative_offset:X}, size 0x{entry_size:X}"
                        )

                    if file_id in self.files:
                        raise ValueError(f"Duplicate CNT entry ID 0x{file_id:04X}")
                    self.files[file_id] = {
                        "id": file_id,
                        "name_table_offset": name_table_offset,
                        "fn_offset": name_table_offset,
                        "flags1": flags1,
                        "flags2": flags2,
                        "relative_offset": relative_offset,
                        "offset": absolute_offset,
                        "size": entry_size,
                        "key_idx": (flags2 & 0xF000) >> 12,
                        "encrypted": (flags1 & PackageBase.FLAG_ENCRYPTED) == PackageBase.FLAG_ENCRYPTED
                    }
                except struct.error as e:
                    Logger.log_warning(f"Error unpacking file entry {i}: {str(e)}")
                    break

            if not self.files:
                raise ValueError("No valid files found in the embedded CNT")

            names_entry = self.files.get(self.ENTRY_NAMES_ID)
            if names_entry is None:
                Logger.log_warning("CNT ENTRY_NAMES entry (0x0200) was not found")
            elif names_entry.get("encrypted"):
                Logger.log_warning("CNT ENTRY_NAMES is encrypted; filenames were not read")
            elif names_entry["size"]:
                if names_entry["size"] > self.MAX_METADATA_SIZE:
                    raise ValueError("CNT ENTRY_NAMES table is unreasonably large")
                fp.seek(names_entry["offset"])
                names = fp.read(names_entry["size"])
                if len(names) != names_entry["size"]:
                    raise ValueError("Truncated CNT ENTRY_NAMES table")

                for file_id, file in self.files.items():
                    name_offset = file["name_table_offset"]
                    if name_offset == 0:
                        continue
                    if name_offset >= len(names):
                        Logger.log_warning(
                            f"Filename offset 0x{name_offset:X} for entry 0x{file_id:04X} "
                            "is outside ENTRY_NAMES"
                        )
                        continue
                    end = names.find(b'\x00', name_offset)
                    if end < 0:
                        Logger.log_warning(f"Unterminated filename for entry 0x{file_id:04X}")
                        continue
                    filename = self._safe_decode(names[name_offset:end])
                    if filename:
                        file["name"] = filename

            # ENTRY_NAMES is intentionally unnamed in the table. Giving this
            # structural entry a stable label makes it visible to callers.
            if names_entry is not None:
                names_entry.setdefault("name", "entry_names")

            # Entries without a name in the table (structural plumbing such as
            # digests / entry_keys / metas / imagedigs) get a stable label from
            # the known PS4/PS5 entry-id map, so they are never reported as
            # generic "file_NNN" artifacts.
            for file_id, file in self.files.items():
                if "name" not in file:
                    file["name"] = PKG_ENTRY_ID_TO_NAME_FULL.get(
                        file_id, f"file_{file_id:04X}"
                    )

            Logger.log_information(f"Loaded {len(self.files)} files from PS5 PKG")
        except Exception as e:
            Logger.log_error(f"Error loading PS5 file entries: {str(e)}")
            raise ValueError(f"Error loading PS5 file entries: {str(e)}")

    def is_encrypted(self):
        return any(entry.get("encrypted", False) for entry in self.files.values())

    # ------------------------------------------------------------------
    # PFS (outer image + nested inner image) access
    # ------------------------------------------------------------------

    #: Synthetic entry IDs for PFS files merged into ``get_all_files()``.
    #: They live above the CNT entry-ID space so they can never collide.
    PFS_ID_BASE = 0x80000000

    def get_all_files(self):
        """Return the CNT entries plus the PFS files (outer + inner).

        PFS files are exposed with synthetic entry IDs (``>= 0x80000000``) and
        the ``pfs`` marker so they flow through the same file-table consumers
        (file browser, preview, extraction).  Reading one of them via
        :meth:`read_file` returns the decrypted PFS payload.
        """
        if getattr(self, "_all_files", None) is None:
            merged = dict(self.files)
            next_id = self.PFS_ID_BASE
            for entry in self.get_pfs_files():
                while next_id in merged:
                    next_id += 1
                merged[next_id] = {
                    "id": next_id,
                    "name": entry["name"],
                    "size": entry["size"],
                    "offset": entry.get("offset", 0),
                    "source": entry.get("source", "pfs"),
                    "pfs": True,
                    "encrypted": False,
                }
                next_id += 1
            self._all_files = merged
        return self._all_files

    def read_file(self, file_id, *, allow_encrypted=False):
        entry = self.files.get(file_id)
        if entry is not None and entry.get("pfs"):
            return self.read_pfs_file(entry["name"])
        if entry is None:
            entry = self.get_all_files().get(file_id)
            if entry is not None and entry.get("pfs"):
                return self.read_pfs_file(entry["name"])
        return super().read_file(file_id, allow_encrypted=allow_encrypted)

    def _open_pfs(self):
        """Lazily decrypt and parse the PS5 outer PFS image.

        Returns the ``PfsFilesystem`` for the outer image (whose uroot holds
        ``pfs_image.dat`` + ``naps_pkg_layout.dat``), or None when the image is
        absent or cannot be opened with the standard all-zero passcode.
        """
        if getattr(self, "_pfs_fs", None) is not None:
            return self._pfs_fs
        self._pfs_fs = None
        if not self.pfs_size:
            return None
        try:
            with open(self.original_file, "rb") as fp:
                fp.seek(self.pfs_offset)
                image = fp.read(self.pfs_size)
            superblock = find_pfs_superblock(image)
            if superblock is None:
                Logger.log_warning("PS5 outer PFS superblock was not found")
                return None
            ekpfs = derive_ekpfs(self.content_id, "0" * 32)
            fs, _used = open_ps5_outer_pfs(
                image, superblock_offset=superblock, ekpfs_candidates=(ekpfs,)
            )
            self._pfs_fs = fs
            return fs
        except (PackageFormatError, PackageBoundsError, struct.error, OSError) as exc:
            Logger.log_warning(f"PS5 PFS could not be opened: {exc}")
            self._pfs_fs = None
            return None

    def get_pfs_files(self):
        """List the files inside the PS5 PFS (outer + nested inner image).

        Returns a list of ``{name, size, source, offset}`` dicts where
        ``source`` is ``"outer"`` for the finalized outer image and ``"inner"``
        for files inside ``pfs_image.dat``.  ``offset`` is the byte offset of
        the file within its image (``"outer"`` files) or within the inner
        image (``"inner"`` files).
        """
        fs = self._open_pfs()
        if fs is None:
            return []
        result = []
        inner_image = None
        for node in fs.nodes:
            result.append({
                "name": node.path,
                "size": node.size,
                "source": "outer",
                "offset": (node.blocks[0] if node.blocks else 0) * fs.header.block_size,
            })
            if os.path.basename(node.path).lower() == "pfs_image.dat":
                inner_image = fs.read_node(node)
        if inner_image is not None:
            try:
                inner_files, _layout = parse_inner_image(inner_image)
                for raw in inner_files:
                    result.append({
                        "name": raw.path,
                        "size": raw.size,
                        "source": "inner",
                        "offset": raw.offset,
                    })
            except PackageFormatError as exc:
                Logger.log_warning(f"PS5 inner image could not be parsed: {exc}")
        return result

    def read_pfs_file(self, path: str) -> bytes:
        """Read one file from inside the PS5 PFS by its package path."""
        fs = self._open_pfs()
        if fs is None:
            raise PackageFormatError("PS5 PFS is not readable")
        node = next((n for n in fs.nodes if n.path == path), None)
        if node is not None:
            return fs.read_node(node)
        inner_image = None
        for n in fs.nodes:
            if os.path.basename(n.path).lower() == "pfs_image.dat":
                inner_image = fs.read_node(n)
                break
        if inner_image is None:
            raise PackageFormatError(f"file '{path}' not found inside the PS5 PFS")
        inner_files, _layout = parse_inner_image(inner_image)
        raw = next((r for r in inner_files if r.path == path), None)
        if raw is None:
            raise PackageFormatError(f"file '{path}' not found inside the PS5 PFS")
        return inner_image[raw.offset:raw.offset + raw.size]

    def extract_pfs_files(self, output_dir: str):
        """Extract every readable file from the PS5 PFS.

        Outer-image files are written under ``<output_dir>/_outer`` and inner
        image files (the game payloads) directly under ``<output_dir>``.
        Returns a short summary string.
        """
        fs = self._open_pfs()
        if fs is None:
            return "PS5 PFS is not readable (encrypted with a non-standard passcode or absent)."
        os.makedirs(output_dir, exist_ok=True)
        extracted = 0
        skipped = 0

        inner_files = []
        inner_image = None
        for node in fs.nodes:
            temporary_path = None
            try:
                data = fs.read_node(node)
                base = "_outer"
                if os.path.basename(node.path).lower() == "pfs_image.dat":
                    inner_image = data
                    continue
                output_path = self._safe_output_path(
                    os.path.join(output_dir, base), node.path
                )
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
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
                Logger.log_error(f"Could not extract outer PFS file '{node.path}': {exc}")

        if inner_image is not None:
            try:
                inner_files, _layout = parse_inner_image(inner_image)
            except PackageFormatError as exc:
                Logger.log_warning(f"PS5 inner image could not be parsed: {exc}")
                inner_files = []
        for raw in inner_files:
            temporary_path = None
            try:
                output_path = self._safe_output_path(output_dir, raw.path)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with tempfile.NamedTemporaryFile(
                    mode="wb", dir=os.path.dirname(output_path),
                    prefix=".pkgtoolbox-", delete=False,
                ) as target:
                    temporary_path = target.name
                    target.write(inner_image[raw.offset:raw.offset + raw.size])
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
                Logger.log_error(f"Could not extract inner PFS file '{raw.path}': {exc}")

        return (
            f"PS5 PFS extraction completed: {extracted} file(s), {skipped} skipped. "
            f"Output: {output_dir}"
        )

    def get_pfs_report(self):
        """Return a plain-text report of the PS5 PFS structure."""
        fs = self._open_pfs()
        lines = ["--- PS5 PFS inspection ---"]
        if fs is None:
            lines.append("State: protected-or-unreadable")
            lines.append(
                "The outer PFS is encrypted with the package EKPFS (all-zero "
                "passcode) or absent; CNT metadata entries remain readable."
            )
            return "\n".join(lines)
        header = fs.header
        lines.extend([
            f"State: decrypted",
            f"Image: offset=0x{self.pfs_offset:X}, size={self.pfs_size:,} bytes",
            f"Superblock: offset=0x{header.superblock_offset:X}, version={header.version}",
            f"Mode flags: 0x{header.mode:X}, block size=0x{header.block_size:X}",
            f"Inodes: {header.inode_count}, data blocks: {header.data_block_count}",
        ])
        for entry in self.get_pfs_files():
            lines.append(
                f"  [{entry['source']:>5}] {entry['name']} "
                f"(size={entry['size']:,} bytes, offset=0x{entry['offset']:X})"
            )
        return "\n".join(lines)

    def get_pfs_info(self, as_json: bool = False) -> str:
        report = self.get_pfs_report()
        if not as_json:
            return report
        data = {
            "state": "decrypted" if self._open_pfs() is not None else "protected-or-unreadable",
            "pfs_offset": self.pfs_offset,
            "pfs_size": self.pfs_size,
            "files": self.get_pfs_files(),
        }
        return json.dumps(data, indent=2)

    def dump(self, output_dir):
        result = self.extract_all_files(output_dir)
        parts = [result]
        pfs_result = self.extract_pfs_files(os.path.join(output_dir, "pfs"))
        if "not readable" not in pfs_result:
            parts.append(pfs_result)
        si_entries = self.get_si_entries()
        if si_entries:
            parts.append(self.extract_si(os.path.join(output_dir, "sce_suppl")))
        return "\n".join(parts)

    def get_param_json(self):
        return dict(self.param_json)

    def get_si_entries(self):
        """List files from the appended SI/sce_suppl ZIP archive, if present."""
        if not self.si_size:
            return []
        try:
            with zipfile.ZipFile(self.original_file, "r") as archive:
                infos = archive.infolist()
                if len(infos) > self.MAX_SI_ENTRY_COUNT:
                    raise ValueError(f"SI archive has too many entries: {len(infos)}")
                total = sum(info.file_size for info in infos)
                if total > self.MAX_SI_TOTAL_SIZE:
                    raise ValueError(f"SI archive expands to an unsafe size: {total} bytes")
                return [
                    {
                        "name": info.filename,
                        "size": info.file_size,
                        "compressed_size": info.compress_size,
                        "compression": info.compress_type,
                        "crc32": f"{info.CRC:08x}",
                        "encrypted": bool(info.flag_bits & 0x1),
                        "is_dir": info.is_dir(),
                    }
                    for info in infos
                ]
        except zipfile.BadZipFile:
            Logger.log_warning("PS5 SI segment is present but is not a readable ZIP archive")
            return []

    def extract_si(self, output_dir):
        """Safely stream the appended SI ZIP archive without path traversal."""
        entries = self.get_si_entries()
        if not entries:
            return "No readable SI/sce_suppl archive found."
        os.makedirs(output_dir, exist_ok=True)
        extracted = 0
        skipped = 0
        with zipfile.ZipFile(self.original_file, "r") as archive:
            for entry in entries:
                if entry["is_dir"]:
                    continue
                if entry["encrypted"]:
                    skipped += 1
                    continue
                temporary_path = None
                try:
                    output_path = self._safe_output_path(output_dir, entry["name"])
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    with archive.open(entry["name"], "r") as source, tempfile.NamedTemporaryFile(
                        mode="wb", dir=os.path.dirname(output_path),
                        prefix=".pkgtoolbox-", delete=False,
                    ) as target:
                        temporary_path = target.name
                        remaining = entry["size"]
                        while remaining:
                            chunk = source.read(min(remaining, 1024 * 1024))
                            if not chunk:
                                raise ValueError(f"truncated SI member: {entry['name']}")
                            target.write(chunk)
                            remaining -= len(chunk)
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
                    Logger.log_error(f"Could not extract SI member '{entry['name']}': {exc}")
        return f"SI extraction completed: {extracted} file(s), {skipped} skipped. Output: {output_dir}"

    def get_info(self):
        info = super().get_info()
        if self.is_ps5:
            info.update({
                "pkg_magic": self.magic.hex() if isinstance(self.magic, bytes) else str(self.magic),
                "pkg_type": self.pkg_type.hex() if isinstance(self.pkg_type, bytes) else str(self.pkg_type),
                "pkg_revision": self.pkg_revision,
                "pkg_file_count": self.pkg_file_count,
                "pkg_sc_entry_count": self.pkg_sc_entry_count,
                "cnt_flags": f"0x{self.cnt_flags:X}" if isinstance(self.cnt_flags, int) else str(self.cnt_flags),
                "content_id": self.content_id,
                "title_id": self.title_id,
                "title_name": self.title_name,
                "region": self.region,
                "content_version": self.content_version,
                "required_system_software_version": self.required_system_software_version,
                "application_category_type": self.application_category_type,
                "application_drm_type": self.application_drm_type,
                "sdk_version": self.sdk_version,
                "master_version": self.master_version,
                "creation_date": self.creation_date,
                "publishing_tools_version": self.publishing_tools_version,
                "drm_type": f"0x{self.drm_type:X}" if isinstance(self.drm_type, int) else str(self.drm_type),
                "content_type": f"0x{self.content_type:X}" if isinstance(self.content_type, int) else str(self.content_type),
                "content_flags": f"0x{self.content_flags:X}" if isinstance(self.content_flags, int) else str(self.content_flags),
                "encrypted_entries": sum(1 for entry in self.files.values() if entry.get("encrypted")),
                "plaintext_entries": sum(1 for entry in self.files.values() if not entry.get("encrypted")),
                "image_asset_count": len(self.list_image_assets()),
                "package_digest": self.package_digest,
                "pfs_area_digest": self.pfs_area_digest,
                "fih_offset": f"0x{self.fih_offset:X}" if isinstance(self.fih_offset, int) else str(self.fih_offset),
                "fih_size": f"0x{self.fih_size:X}" if isinstance(self.fih_size, int) else str(self.fih_size),
                "pfs_offset": f"0x{self.pfs_offset:X}" if isinstance(self.pfs_offset, int) else str(self.pfs_offset),
                "pfs_size": f"0x{self.pfs_size:X}" if isinstance(self.pfs_size, int) else str(self.pfs_size),
                "sc_offset": f"0x{self.sc_offset:X}" if isinstance(self.sc_offset, int) else str(self.sc_offset),
                "sc_size": f"0x{self.sc_size:X}" if isinstance(self.sc_size, int) else str(self.sc_size),
                "si_offset": f"0x{self.si_offset:X}" if isinstance(self.si_offset, int) else str(self.si_offset),
                "si_size": f"0x{self.si_size:X}" if isinstance(self.si_size, int) else str(self.si_size),
            })
        for locale, title in self.title_names.items():
            info[f"title.{locale}"] = title
        si_entries = self.get_si_entries()
        info.update({
            "default_language": self.default_language,
            "target_content_version": self.target_content_version,
            "origin_content_version": self.origin_content_version,
            "download_data_size": self.download_data_size,
            "mass_size": self.mass_size,
            "flexible_memory_size": self.flexible_memory_size,
            "content_badge_type": self.content_badge_type,
            "game_intents": ", ".join(self.game_intents),
            "deeplink_uri": self.deeplink_uri,
            "version_file_uri": self.version_file_uri,
            "si_archive_state": "ZIP" if si_entries else ("unrecognized" if self.si_size else "absent"),
            "si_file_count": sum(1 for entry in si_entries if not entry["is_dir"]),
        })
        return info
