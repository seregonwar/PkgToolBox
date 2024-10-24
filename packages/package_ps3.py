import struct
import os
from .package_base import PackageBase
from utils import Logger

class PackagePS3(PackageBase):
    MAGIC_PS3 = 0x7f504b47 # ?PKG for PS3

    def __init__(self, file: str):
        super().__init__(file)
        self.is_ps3 = False
        self.pkg_revision = None
        self.pkg_metadata_offset = None
        self.pkg_metadata_count = None
        self.pkg_metadata_size = None
        self.item_count = None
        self.total_size = None
        self.data_offset = None
        self.data_size = None
        self.digest = None
        self.pkg_data_riv = None
        self.pkg_header_digest = None

        with open(file, "rb") as fp:
            magic = fp.read(4)
            if magic == struct.pack(">I", self.MAGIC_PS3):
                self.is_ps3 = True
                self._load_ps3_pkg(fp)
            else:
                raise ValueError(f"Unknown PKG format: {magic.hex()}")

    def _load_ps3_pkg(self, fp):
        try:
            header_format = ">4sH2H4I2Q48s16s16s16s"
            fp.seek(0)
            data = fp.read(struct.calcsize(header_format))
            (magic, self.pkg_revision, self.pkg_type, self.pkg_metadata_offset, self.pkg_metadata_count,
             self.pkg_metadata_size, self.item_count, self.total_size, self.data_offset, self.data_size,
             self.content_id, self.digest, self.pkg_data_riv, self.pkg_header_digest) = struct.unpack(header_format, data)

            if magic != struct.pack(">I", self.MAGIC_PS3):
                raise ValueError("Formato PKG PS3 non valido")

            self.pkg_magic = magic

            self._load_ps3_files(fp)

            Logger.log_information("PS3 PKG file loaded successfully.")
        except Exception as e:
            Logger.log_error(f"Error loading PS3 PKG file: {str(e)}")
            raise ValueError(f"Error loading PS3 PKG file: {str(e)}")

    def _load_ps3_files(self, fp):
        try:
            fp.seek(0x10)
            file_table_size = struct.unpack(">I", fp.read(4))[0]
            file_table_offset = fp.tell()

            self.files = {}
            for _ in range(file_table_size):
                file_entry_format = ">QII"
                file_entry_data = fp.read(struct.calcsize(file_entry_format))
                file_offset, file_size, name_offset = struct.unpack(file_entry_format, file_entry_data)

                current_pos = fp.tell()
                fp.seek(file_table_offset + name_offset)
                file_name = self._read_null_terminated_string(fp)
                fp.seek(current_pos)

                self.files[file_name] = {
                    "offset": file_offset,
                    "size": file_size
                }

            Logger.log_information("PS3 file table loaded successfully.")
        except Exception as e:
            Logger.log_error(f"Error loading PS3 file table: {str(e)}")
            raise ValueError(f"Error loading PS3 file table: {str(e)}")

    def get_info(self):
        info = super().get_info()
        if self.is_ps3:
            info.update({
                "pkg_magic": self.pkg_magic.hex() if isinstance(self.pkg_magic, bytes) else str(self.pkg_magic),
                "pkg_type": self.pkg_type,
                "pkg_metadata_offset": self.pkg_metadata_offset,
                "pkg_metadata_count": self.pkg_metadata_count,
                "pkg_metadata_size": self.pkg_metadata_size,
                "item_count": self.item_count,
                "total_size": self.total_size,
                "data_offset": self.data_offset,
                "data_size": self.data_size,
                "content_id": self.content_id,
                "digest": self.digest,
                "pkg_data_riv": self.pkg_data_riv,
                "pkg_header_digest": self.pkg_header_digest,
                "content_id": self.content_id,
                "drm_type": self.drm_type,
                "content_type": self.content_type,
                "content_flags": self.content_flags,
                "iro_tag": self.iro_tag,
                "version_date": self.version_date,
                "version_hash": self.version_hash,
                "digest_table_hash": self.digest_table_hash,
                "entry_table_offset": self.entry_table_offset,
                "entry_table_size": self.entry_table_size,
            })
        return info