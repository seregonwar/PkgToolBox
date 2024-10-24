import struct
from .package_base import PackageBase
from .enums import DRMType, ContentType, IROTag
from utils import Logger
import os
class PackagePS4(PackageBase):
    MAGIC_PS4 = 0x7f434E54  # ?CNT for PS4

    def __init__(self, file: str):
        super().__init__(file)
        self.is_ps4 = False
        self.pkg_magic = None
        self.pkg_type = None
        self.pkg_file_count = 0
        self.pkg_entry_count = 0
        self.pkg_sc_entry_count = 0
        self.pkg_entry_count_2 = 0
        self.pkg_table_offset = 0
        self.pkg_entry_data_size = 0
        self.pkg_body_offset = 0
        self.pkg_body_size = 0
        self.pkg_content_offset = 0
        self.pkg_content_size = 0
        self.pkg_drm_type = None
        self.pkg_content_type = None
        self.pkg_content_flags = None
        self.pkg_promote_size = 0
        self.pkg_version_date = None
        self.pkg_version_hash = None
        self.pkg_iro_tag = None
        self.pkg_drm_type_version = None
        self.pkg_content_id = None

        with open(file, "rb") as fp:
            magic = struct.unpack(">I", fp.read(4))[0]
            Logger.log_information(f"Read magic number: {magic:08X}")
            if magic == self.MAGIC_PS4:
                self.is_ps4 = True
                self._load_ps4_pkg(fp)
            else:
                raise ValueError(f"Unknown PKG format: {magic:08X}")

    def _load_ps4_pkg(self, fp):
        try:
            header_format = ">5I2H2I4Q36s12s12I"
            fp.seek(0)
            data = fp.read(struct.calcsize(header_format))
            
            (self.pkg_magic, self.pkg_type, self.pkg_0x008, self.pkg_file_count, self.pkg_entry_count,
             self.pkg_sc_entry_count, self.pkg_entry_count_2, self.pkg_table_offset, self.pkg_entry_data_size,
             self.pkg_body_offset, self.pkg_body_size, self.pkg_content_offset, self.pkg_content_size,
             self.pkg_content_id, self.pkg_padding, self.pkg_drm_type, self.pkg_content_type,
             self.pkg_content_flags, self.pkg_promote_size, self.pkg_version_date, self.pkg_version_hash,
             self.pkg_0x088, self.pkg_0x08C, self.pkg_0x090, self.pkg_0x094, self.pkg_iro_tag,
             self.pkg_drm_type_version) = struct.unpack(header_format, data)

            Logger.log_information(f"Loaded header data: {self.pkg_magic}, {self.pkg_type}, {self.pkg_drm_type}, {self.pkg_content_type}")

            self.pkg_content_id = self._safe_decode(self.pkg_content_id)
            self.content_id = self.pkg_content_id

            fp.seek(0x100, os.SEEK_SET)
            data = fp.read(128)
            self.digests = [data[i:i+32].hex() for i in range(0, 128, 32)]

            try:
                self.pkg_content_type = ContentType(self.pkg_content_type)
            except ValueError:
                Logger.log_warning(f"Warning: {self.pkg_content_type} is not a valid ContentType. Setting to None.")
                self.pkg_content_type = None

            try:
                self.pkg_iro_tag = IROTag(self.pkg_iro_tag)
            except ValueError:
                Logger.log_warning(f"Warning: {self.pkg_iro_tag} is not a valid IROTag. Setting to None.")
                self.pkg_iro_tag = None
                self.invalid_irotag = True
            else:
                self.invalid_irotag = False

            self.__load_files(fp)
            self.files = self.files
        except Exception as e:
            Logger.log_error(f"Error loading PS4 PKG file: {str(e)}")
            raise ValueError(f"Error loading PS4 PKG file: {str(e)}")

    def __load_files(self, fp):
        old_pos = fp.tell()
        fp.seek(self.pkg_table_offset, os.SEEK_SET)

        entry_format = ">6IQ"
        self.files = {}
        for i in range(self.pkg_entry_count):
            entry_data = fp.read(struct.calcsize(entry_format))
            file_id, filename_offset, flags1, flags2, offset, size, padding = struct.unpack(entry_format, entry_data)
            self.files[file_id] = {
                "id": file_id,
                "fn_offset": filename_offset,
                "flags1": flags1,
                "flags2": flags2,
                "offset": offset,
                "size": size,
                "padding": padding,
                "key_idx": (flags2 & 0xF00) >> 12,
                "encrypted": (flags1 & PackageBase.FLAG_ENCRYPTED) == PackageBase.FLAG_ENCRYPTED
            }

        for key, file in self.files.items():
            try:
                fp.seek(self.files[0x200]["offset"] + file["fn_offset"])
                fn = self._read_null_terminated_string(fp)
                if fn:
                    try:
                        self.files[key]["name"] = self._safe_decode(fn)
                    except Exception as e:
                        Logger.log_warning(f"Failed to decode filename for file ID {key}: {e}")
                        self.files[key]["name"] = f"file_{key}"
            except (OverflowError, OSError) as e:
                Logger.log_warning(f"Error seeking to filename for file ID {key}: {e}")
                self.files[key]["name"] = f"file_{key}"

        fp.seek(old_pos)

    def get_info(self):
        info = super().get_info()
        if self.is_ps4:
            info.update({
                "pkg_magic": f"0x{self.pkg_magic:X}",
                "pkg_type": f"0x{self.pkg_type:X}",
                "pkg_0x008": self.pkg_0x008,
                "pkg_file_count": self.pkg_file_count,
                "pkg_entry_count": self.pkg_entry_count,
                "pkg_sc_entry_count": self.pkg_sc_entry_count,
                "pkg_entry_count_2": self.pkg_entry_count_2,
                "pkg_table_offset": f"0x{self.pkg_table_offset:X}",
                "pkg_entry_data_size": self.pkg_entry_data_size,
                "pkg_body_offset": f"0x{self.pkg_body_offset:X}",
                "pkg_body_size": self.pkg_body_size,
                "pkg_content_offset": f"0x{self.pkg_content_offset:X}",
                "pkg_content_size": self.pkg_content_size,
                "pkg_content_id": self.pkg_content_id,
                "pkg_padding": self.pkg_padding.hex() if isinstance(self.pkg_padding, bytes) else str(self.pkg_padding),
                "pkg_drm_type": self.pkg_drm_type.name if isinstance(self.pkg_drm_type, DRMType) else str(self.pkg_drm_type),
                "pkg_content_type": self.pkg_content_type.name if isinstance(self.pkg_content_type, ContentType) else str(self.pkg_content_type),
                "pkg_content_flags": f"0x{self.pkg_content_flags:X}",
                "pkg_promote_size": self.pkg_promote_size,
                "pkg_version_date": self.pkg_version_date,
                "pkg_version_hash": self.pkg_version_hash.hex() if isinstance(self.pkg_version_hash, bytes) else f"0x{self.pkg_version_hash:X}",
                "pkg_0x088": f"0x{self.pkg_0x088:X}",
                "pkg_0x08C": f"0x{self.pkg_0x08C:X}",
                "pkg_0x090": f"0x{self.pkg_0x090:X}",
                "pkg_0x094": f"0x{self.pkg_0x094:X}",
                "pkg_iro_tag": self.pkg_iro_tag.name if isinstance(self.pkg_iro_tag, IROTag) else str(self.pkg_iro_tag),
                "pkg_drm_type_version": self.pkg_drm_type_version,
                "Main Entry 1 Hash": self.digests[0] if len(self.digests) > 0 else "N/A",
                "Main Entry 2 Hash": self.digests[1] if len(self.digests) > 1 else "N/A",
                "Digest Table Hash": self.digests[2] if len(self.digests) > 2 else "N/A",
                "Main Table Hash": self.digests[3] if len(self.digests) > 3 else "N/A",
            })
        return info
