import struct
import os
import json
from .package_base import PackageBase
from .enums import DRMType, ContentType, IROTag
from utils import Logger

class PackagePS5(PackageBase):
    MAGIC_PS5 = 0x7F464948  # ?FIH for PS5

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
        self.title_name = None  # Aggiunto per risolvere l'errore

        with open(file, "rb") as fp:
            magic = struct.unpack(">I", fp.read(4))[0]
            Logger.log_information(f"Read magic number: {magic:08X}")
            if magic == self.MAGIC_PS5:
                self.is_ps5 = True
                self._load_ps5_pkg(fp)
            else:
                raise ValueError(f"Unknown PKG format: {magic:08X}")

    def _load_ps5_pkg(self, fp):
        try:
            header_format = ">4s2sH4sQ4I4Q2I14s16s16s16s16s16s16s16s16s16s16s16s16s16s16s16s"
            fp.seek(0)
            data = fp.read(struct.calcsize(header_format))
            unpacked_data = struct.unpack(header_format, data)

            Logger.log_information(f"Number of unpacked values: {len(unpacked_data)}")

            self.magic = unpacked_data[0]
            self.pkg_type = unpacked_data[1]
            self.pkg_revision = unpacked_data[2]
            self.pkg_0x008 = unpacked_data[3]
            self.pkg_file_count = unpacked_data[4]
            self.entry_table_offset, self.entry_table_size = unpacked_data[5:7]
            self.body_offset, self.body_size = unpacked_data[7:9]
            self.content_id = self._safe_decode(unpacked_data[9])
            self.drm_type, self.content_type = unpacked_data[10:12]
            self.content_flags, self.promote_size = unpacked_data[12:14]
            self.version_date = unpacked_data[14]
            self.version_hash = unpacked_data[15]
            self.iro_tag = unpacked_data[16]

            self._initialize_ps5_fields()

            if self.entry_table_offset == 0 or self.entry_table_size == 0:
                Logger.log_warning("Invalid entry table offset or size, package might be encrypted")
                self.files = {}
            else:
                self.__load_ps5_files(fp)

            param_json = self._find_file_by_name("sce_sys/param.json")
            if param_json:
                self._parse_param_json(fp, param_json)
            else:
                Logger.log_warning("param.json not found in the package")

            self._read_digests_and_layout(fp)
            self.files = self.files if hasattr(self, 'files') else {}

            self._find_important_files()

        except Exception as e:
            Logger.log_error(f"Error loading PS5 PKG file: {str(e)}")
            self.files = {}
            raise ValueError(f"Error loading PS5 PKG file: {str(e)}")

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

    def _find_file_by_name(self, name):
        return next((file for file in self.files.values() if file.get("name") == name), None)

    def _parse_param_json(self, fp, param_json):
        try:
            fp.seek(param_json["offset"])
            json_data = fp.read(param_json["size"])
            json_content = json.loads(json_data)
            
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
            
            Logger.log_information(f"Parsed param.json: Title ID: {self.title_id}, Content ID: {self.content_id}, Default Title: {self.title_names.get(self.default_language)}")
        except Exception as e:
            Logger.log_error(f"Error parsing param.json: {str(e)}")

    def _find_important_files(self):
        important_files = [
            "eboot.bin",
            "sce_sys/icon0.png",
            "sce_sys/pic0.png",
            "sce_sys/pic1.png",
            "sce_sys/playgo-chunk.dat",
            "sce_sys/playgo-manifest.xml",
            "sce_sys/trophy/trophy00.trp"
        ]
        
        for file_name in important_files:
            file_info = self._find_file_by_name(file_name)
            if file_info:
                Logger.log_information(f"Found important file: {file_name}")
            else:
                Logger.log_warning(f"Important file not found: {file_name}")

    def _read_digests_and_layout(self, fp):
        try:
            fp.seek(0x100)
            self.package_digest = fp.read(32).hex()
            self.pfs_area_digest = fp.read(32).hex()
            
            if self.package_digest == '0' * 64 and self.pfs_area_digest == '0' * 64:
                Logger.log_warning("Digests are all zeros, package might be corrupted or encrypted")
            
            fp.seek(0x400)
            layout_data = struct.unpack(">QQQQQQQQ", fp.read(64))
            self.fih_offset, self.fih_size = layout_data[0:2]
            self.pfs_offset, self.pfs_size = layout_data[2:4]
            self.sc_offset, self.sc_size = layout_data[4:6]
            self.si_offset, self.si_size = layout_data[6:8]
            
            if all(v == 0 for v in layout_data):
                Logger.log_warning("All layout values are zero, package might be corrupted or encrypted")
            
            Logger.log_information(f"Package digest: {self.package_digest}")
            Logger.log_information(f"PFS area digest: {self.pfs_area_digest}")

            Logger.log_information(f"FIH: offset 0x{self.fih_offset:X}, size 0x{self.fih_size:X}")
            Logger.log_information(f"PFS: offset 0x{self.pfs_offset:X}, size 0x{self.pfs_size:X}")
            Logger.log_information(f"SC: offset 0x{self.sc_offset:X}, size 0x{self.sc_size:X}")
            Logger.log_information(f"SI: offset 0x{self.si_offset:X}, size 0x{self.si_size:X}")

        except Exception as e:
            Logger.log_error(f"Errore durante la lettura dei digest e del layout: {str(e)}")
            raise

    def __load_ps5_files(self, fp):
        try:
            Logger.log_information(f"Loading PS5 files. Entry table offset: 0x{self.entry_table_offset:X}, size: 0x{self.entry_table_size:X}")

            fp.seek(self.entry_table_offset)
            entry_count = min(self.entry_table_size // 32, self.pkg_file_count, 10000)

            entry_format = ">IIQQII"
            self.files = {}
            for i in range(entry_count):
                try:
                    entry_data = fp.read(32)
                    if len(entry_data) < 32:
                        Logger.log_warning(f"Reached end of file while reading entries. Processed {i} entries.")
                        break
                    file_id, file_type, file_offset, file_size, padding1, padding2 = struct.unpack(entry_format, entry_data)
                    
                    file_end = os.path.getsize(self.original_file)
                    if file_offset >= file_end or file_size > file_end - file_offset:
                        Logger.log_warning(f"File with unreasonable offset or size: ID {file_id}, offset 0x{file_offset:X}, size 0x{file_size:X}")
                        continue

                    self.files[file_id] = {
                        "id": file_id,
                        "type": file_type,
                        "offset": file_offset,
                        "size": file_size,
                        "encrypted": (file_type & PackageBase.FLAG_ENCRYPTED) == PackageBase.FLAG_ENCRYPTED
                    }
                except struct.error as e:
                    Logger.log_warning(f"Error unpacking file entry {i}: {str(e)}")
                    break

            if not self.files:
                Logger.log_error("No valid files found in the package")

            for key, file in self.files.items():
                try:
                    fp.seek(file["offset"])
                    fn = fp.read(256).split(b'\x00')[0]
                    if fn:
                        self.files[key]["name"] = self._safe_decode(fn)
                except (OverflowError, OSError) as e:
                    Logger.log_warning(f"Error reading filename for file ID {key}: {e}")
                    self.files[key]["name"] = f"file_{key}"

            Logger.log_information(f"Loaded {len(self.files)} files from PS5 PKG")
        except Exception as e:
            Logger.log_error(f"Error loading PS5 file entries: {str(e)}")
            raise ValueError(f"Error loading PS5 file entries: {str(e)}")

    def get_info(self):
        info = super().get_info()
        if self.is_ps5:
            info.update({
                "pkg_magic": self.magic.hex() if isinstance(self.magic, bytes) else str(self.magic),
                "pkg_type": self.pkg_type.hex() if isinstance(self.pkg_type, bytes) else str(self.pkg_type),
                "pkg_revision": self.pkg_revision,
                "pkg_file_count": self.pkg_file_count,
                "content_id": self.content_id,
                "title_id": self.title_id,
                "title_name": self.title_name,
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
        return info