from logging import Logger
import struct
import os
import typing
from enum import Enum
import io
import re
import logging
import shutil
from PIL import Image
from utils import print_aligned, bcolors, Logger
from typing import Dict, Any
import json
import re
import unicodedata


class Type(Enum):
    PAID_STANDALONE_FULL = 1
    UPGRADABLE = 2
    DEMO = 3
    FREEMIUM = 4


class DRMType(Enum):
    NONE = 0x0
    PS4 = 0xF
    PS5 = 0x10  # Added PS5 DRMType



class ContentType(Enum):
    CONTENT_TYPE_GD = 0x1A
    CONTENT_TYPE_AC = 0x1B
    CONTENT_TYPE_AL = 0x1C
    CONTENT_TYPE_DP = 0x1E



class IROTag(Enum):
    SHAREFACTORY_THEME = 0x1
    SYSTEM_THEME = 0x2


TYPE_MASK = 0x0000FFFF


class Package:
    MAGIC_PS4 = 0x7F434E54  # ?CNT for PS4
    MAGIC_PS5 = 0x7F464948  # ?FIH for PS5
    PS5_PKG_TYPE = 0x8302  # Specific PS5 package type
    TYPE_THEME = 0x81000001
    TYPE_GAME = 0x40000001
    FLAG_RETAIL = 1 << 31
    FLAG_ENCRYPTED = 0x80000000

    def __init__(self, file: str):
        if not os.path.isfile(file):
            raise FileNotFoundError(f"The PKG file '{file}' does not exist.")
        
        self.original_file = file
        self.pkg_info = {}
        self.is_ps5 = False
        self._files = {}  # Inizializza _files come dizionario vuoto
        self.content_id = None
        self.drm_type = None
        self.content_type = None
        self.content_flags = None
        self.iro_tag = None
        self.version_date = None
        self.version_hash = None
        self.digest_table_hash = None
        self.entry_table_offset = None
        self.entry_table_size = None
        
        with open(file, "rb") as fp:
            magic = struct.unpack(">I", fp.read(4))[0]
            if magic == self.MAGIC_PS4:
                self._load_ps4_pkg(fp)
            elif magic == self.MAGIC_PS5:
                self.is_ps5 = True
                self._load_ps5_pkg(fp)
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

            # Decode content ID safely
            self.pkg_content_id = self._safe_decode(self.pkg_content_id)
            self.content_id = self.pkg_content_id

            # Load hashes
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

            self.__load_files(fp)
            self.files = self._files
        except Exception as e:
            Logger.log_error(f"Error loading PS4 PKG file: {str(e)}")
            raise ValueError(f"Error loading PS4 PKG file: {str(e)}")

    def _safe_decode(self, data):
        if isinstance(data, str):
            return data.rstrip('\x00')
        elif isinstance(data, bytes):
            try:
                return data.decode('utf-8', errors='ignore').rstrip('\x00')
            except UnicodeDecodeError:
                return data.decode('latin-1', errors='ignore').rstrip('\x00')
        elif isinstance(data, int):
            return str(data)
        else:
            return str(data)

    def _read_null_terminated_string(self, fp):
        result = bytearray()
        while True:
            try:
                char = fp.read(1)
                if char == b'\x00' or len(char) == 0:
                    break
                result.extend(char)
            except (OverflowError, OSError) as e:
                Logger.log_warning(f"Error reading string: {e}")
                break
        return bytes(result)

    def __load_files(self, fp):
        old_pos = fp.tell()
        fp.seek(self.pkg_table_offset, os.SEEK_SET)

        entry_format = ">6IQ"
        self._files = {}
        for i in range(self.pkg_entry_count):
            entry_data = fp.read(struct.calcsize(entry_format))
            file_id, filename_offset, flags1, flags2, offset, size, padding = struct.unpack(entry_format, entry_data)
            self._files[file_id] = {
                "id": file_id,
                "fn_offset": filename_offset,
                "flags1": flags1,
                "flags2": flags2,
                "offset": offset,
                "size": size,
                "padding": padding,
                "key_idx": (flags2 & 0xF00) >> 12,
                "encrypted": (flags1 & Package.FLAG_ENCRYPTED) == Package.FLAG_ENCRYPTED
            }

        for key, file in self._files.items():
            try:
                fp.seek(self._files[0x200]["offset"] + file["fn_offset"])
                fn = self._read_null_terminated_string(fp)
                if fn:
                    try:
                        self._files[key]["name"] = self._safe_decode(fn)
                    except Exception as e:
                        Logger.log_warning(f"Failed to decode filename for file ID {key}: {e}")
                        self._files[key]["name"] = f"file_{key}"
            except (OverflowError, OSError) as e:
                Logger.log_warning(f"Error seeking to filename for file ID {key}: {e}")
                self._files[key]["name"] = f"file_{key}"

        fp.seek(old_pos)

    def _load_ps5_pkg(self, fp):
        try:
            self.is_ps5 = True
            header_format = ">4s2sH4sQ4I4Q2I14s16s16s16s16s16s16s"

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

            # Aggiungi questa verifica dopo aver letto l'offset della tabella di ingresso
            if self.entry_table_offset == 0:
                Logger.log_warning("Entry table offset is 0, attempting to find the correct offset")
                self.entry_table_offset = self._find_entry_table_offset(fp)

            # Assicurati che i valori siano ragionevoli
            file_size = fp.seek(0, 2)
            self.entry_table_offset = min(self.entry_table_offset, file_size)
            self.entry_table_size = min(self.entry_table_size, 1024 * 1024 * 10)  # Limita a 10 MB
            self.body_offset = min(self.body_offset, file_size)
            self.body_size = min(self.body_size, file_size - self.body_offset)

            # Log dei valori principali
            Logger.log_information(f"magic: {self.magic.hex()}")
            Logger.log_information(f"pkg_type: {self.pkg_type.hex()}")
            Logger.log_information(f"pkg_revision: {self.pkg_revision}")
            Logger.log_information(f"pkg_file_count: {self.pkg_file_count}")
            Logger.log_information(f"entry_table_offset: 0x{self.entry_table_offset:X}")
            Logger.log_information(f"entry_table_size: 0x{self.entry_table_size:X}")
            Logger.log_information(f"body_offset: 0x{self.body_offset:X}")
            Logger.log_information(f"body_size: 0x{self.body_size:X}")
            Logger.log_information(f"content_id: {self.content_id}")
            Logger.log_information(f"drm_type: 0x{self.drm_type:X}")
            Logger.log_information(f"content_type: 0x{self.content_type:X}")
            Logger.log_information(f"content_flags: 0x{self.content_flags:X}")
            Logger.log_information(f"promote_size: 0x{self.promote_size:X}")

            self._initialize_ps5_fields()
            self.__load_ps5_files(fp)
            self._parse_param_json(fp)
            self._read_digests_and_layout(fp)
            self.files = self._files
        except Exception as e:
            Logger.log_error(f"Error loading PS5 PKG file: {str(e)}")
            raise ValueError(f"Error loading PS5 PKG file: {str(e)}")

    def _find_entry_table_offset(self, fp):
        # Cerca l'offset corretto della tabella di ingresso
        # Questo è un esempio, potrebbe essere necessario adattarlo in base alla struttura esatta del file
        fp.seek(0)
        data = fp.read(0x1000)  # Leggi i primi 4KB del file
        offset = data.find(b'\x00\x00\x00\x01\x00\x00\x00\x01')  # Cerca un pattern comune all'inizio della tabella
        if offset != -1:
            return offset
        return 0  # Ritorna 0 se non trova nulla

    def _initialize_ps5_fields(self):
        self.application_category_type = None
        self.application_drm_type = None
        self.title_id = None
        self.title_name = None
        self.content_version = None
        self.required_system_software_version = None
        self.sdk_version = None
        self.publishing_tools_version = None
        self.creation_date = None
        self.pfs_timestamp = None
        self.package_digest = None
        self.pfs_area_digest = None
        self.fih_offset = self.fih_size = None
        self.pfs_offset = self.pfs_size = None
        self.sc_offset = self.sc_size = None
        self.si_offset = self.si_size = None
        self.master_version = None  # Aggiungi questa riga

    def _parse_param_json(self, fp):
        param_json = next((file for file in self._files.values() if file.get("name", "").lower() == "param.json"), None)
        if not param_json:
            Logger.log_warning("param.json not found in the package")
            return
        
        try:
            fp.seek(param_json["offset"])
            json_data = fp.read(param_json["size"])
            json_content = json.loads(json_data)
            
            # Estrai le informazioni rilevanti dal JSON
            self.title_id = json_content.get("titleId")
            self.content_id = json_content.get("contentId")
            self.content_version = json_content.get("contentVersion")
            self.required_system_software_version = json_content.get("requiredSystemSoftwareVersion")
            self.application_category_type = json_content.get("applicationCategoryType")
            self.application_drm_type = json_content.get("applicationDrmType")
            
            # Estrai il nome del titolo dalla sezione localizedParameters
            localized_params = json_content.get("localizedParameters", {})
            default_language = localized_params.get("defaultLanguage")
            if default_language and default_language in localized_params:
                self.title_name = localized_params[default_language].get("titleName")
            else:
                self.title_name = next(iter(localized_params.values()), {}).get("titleName")
            
            # Estrai altre informazioni utili
            self.sdk_version = json_content.get("sdkVersion")
            self.master_version = json_content.get("masterVersion")
            self.pubtools = json_content.get("pubtools", {})
            self.creation_date = self.pubtools.get("creationDate")
            self.publishing_tools_version = self.pubtools.get("toolVersion")
            
            Logger.log_information(f"Parsed param.json: Title ID: {self.title_id}, Content ID: {self.content_id}, Title: {self.title_name}")
        except Exception as e:
            Logger.log_error(f"Error parsing param.json: {str(e)}")

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
            entry_count = min(self.entry_table_size // 32, self.pkg_file_count, 10000)  # Limitiamo a 10000 file per sicurezza

            # Modifichiamo il formato della tabella dei file per PS5
            entry_format = ">IIQQII"
            self._files = {}
            for i in range(entry_count):
                try:
                    entry_data = fp.read(32)
                    if len(entry_data) < 32:
                        Logger.log_warning(f"Reached end of file while reading entries. Processed {i} entries.")
                        break
                    file_id, file_type, file_offset, file_size, padding1, padding2 = struct.unpack(entry_format, entry_data)
                    
                    # Modifica questa parte per essere più permissiva
                    file_end = os.path.getsize(self.original_file)
                    if file_offset >= file_end or file_size > file_end - file_offset:
                        Logger.log_warning(f"File with unreasonable offset or size: ID {file_id}, offset 0x{file_offset:X}, size 0x{file_size:X}")
                        continue

                    self._files[file_id] = {
                        "id": file_id,
                        "type": file_type,
                        "offset": file_offset,
                        "size": file_size,
                        "encrypted": (file_type & Package.FLAG_ENCRYPTED) == Package.FLAG_ENCRYPTED
                    }
                except struct.error as e:
                    Logger.log_warning(f"Error unpacking file entry {i}: {str(e)}")
                    break

            if not self._files:
                Logger.log_error("No valid files found in the package")

            # Load file names (if available)
            for key, file in self._files.items():
                try:
                    fp.seek(file["offset"])
                    fn = fp.read(256).split(b'\x00')[0]
                    if fn:
                        self._files[key]["name"] = self._safe_decode(fn)
                except (OverflowError, OSError) as e:
                    Logger.log_warning(f"Error reading filename for file ID {key}: {e}")
                    self._files[key]["name"] = f"file_{key}"

            Logger.log_information(f"Loaded {len(self._files)} files from PS5 PKG")
        except Exception as e:
            Logger.log_error(f"Error loading PS5 file entries: {str(e)}")
            raise ValueError(f"Error loading PS5 file entries: {str(e)}")

    def get_info(self):
        if self.is_ps5:
            return self._get_ps5_info()
        else:
            return self._get_ps4_info()

    def _get_ps5_info(self):
        info = {
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
        }
        if hasattr(self, 'iro_tag') and self.iro_tag is not None:
            info["iro_tag"] = f"0x{self.iro_tag:X}" if isinstance(self.iro_tag, int) else str(self.iro_tag)
        if hasattr(self, 'version_date') and self.version_date is not None:
            info["version_date"] = str(self.version_date)
        if hasattr(self, 'version_hash') and self.version_hash is not None:
            info["version_hash"] = self.version_hash.hex() if isinstance(self.version_hash, bytes) else str(self.version_hash)
        if hasattr(self, 'digest_table_hash') and self.digest_table_hash is not None:
            info["digest_table_hash"] = self.digest_table_hash
        return info

    def get_info(self):
        if self.is_ps5:
            return self._get_ps5_info()
        else:
            return self._get_ps4_info()

    def _get_ps4_info(self):
        info = {
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
            "DESTINATION_COUNTRY": self.get_destination_country(),
        }
        return info

    def get_icon(self):
        # First look for icon0.png using ID 0x1200
        icon0_file = self._files.get(0x1200)
        if icon0_file:
            with open(self.original_file, 'rb') as fp:
                fp.seek(icon0_file['offset'])
                icon_data = fp.read(icon0_file['size'])
                Logger.log_information(f"icon0.png data read, size: {len(icon_data)} bytes")
                return icon_data
        
        # If icon0.png is not found, look for the first PNG file
        for file in self._files.values():
            if isinstance(file.get("name"), str) and file["name"].lower().endswith('.png'):
                with open(self.original_file, 'rb') as fp:
                    fp.seek(file['offset'])
                    icon_data = fp.read(file['size'])
                    Logger.log_information(f"PNG file {file['name']} data read, size: {len(icon_data)} bytes")
                    return icon_data
        
        Logger.log_warning("No PNG file found in the package")
        return None

    def get_country(self):
        return self.get_destination_country()

    def get_files(self):
        return self.files

    def info(self) -> None:
        print_aligned("Magic:", f"0x{format(self.pkg_magic, 'X')}", color=bcolors.OKGREEN
                      if self.pkg_magic == Package.MAGIC_PS4 else bcolors.FAIL)

        if self.pkg_magic != Package.MAGIC_PS4:
            exit("Bad magic!")

        print_aligned("ID:", self.pkg_content_id)
        print_aligned("Type:", f"0x{format(self.pkg_type, 'X')}, {self.pkg_content_type.name}"
                               f"{', ' + self.pkg_iro_tag.name if self.pkg_iro_tag else ''}")
        print_aligned("DRM:", DRMType(self.pkg_drm_type).name)
        print_aligned("Entries:", self.pkg_entry_count)
        print_aligned("Entries(SC):", self.pkg_sc_entry_count)
        print_aligned("Files:", self.pkg_file_count)

        print_aligned("Main Entry 1 Hash:", self.digests[0])
        print_aligned("Main Entry 2 Hash:", self.digests[1])
        print_aligned("Digest Table Hash:", self.digests[2])
        print_aligned("Main Table Hash:", self.digests[3])

        print_aligned("Files:", "")
        for key, file in self._files.items():
            enc_txt = bcolors.OKGREEN if not file["encrypted"] else bcolors.FAIL
            enc_txt += f"{'UN' if not file['encrypted'] else ''}ENCRYPTED{bcolors.ENDC}"
            print_aligned(f"0x{format(key, 'X')}:", f"{file.get('name', '<unnamed>')} ({file['size']} bytes, "
                                                    f"starts 0x{format(file['offset'], 'X')}, {enc_txt})")

    def extract(self, file_name_or_id: typing.Union[str, int], out_path: typing.Union[str, io.BytesIO, io.BufferedWriter]) -> None:
        if isinstance(file_name_or_id, str):
            try:
                file_name_or_id = int(file_name_or_id, 16)
            except ValueError:
                pass  # it's a file name
        
        # Find the target
        chosen_file = self._files.get(file_name_or_id)
        if not chosen_file:
            for key, file in self._files.items():
                if file.get("name") == file_name_or_id:
                    chosen_file = file
                    break

        if not chosen_file:
            raise ValueError(f"Couldn't find file {file_name_or_id} in package!")

        # Open the file and seek to offset
        with open(self.original_file, "rb") as pkg_file:
            try:
                pkg_file.seek(chosen_file["offset"])
                data = pkg_file.read(chosen_file["size"])
            except (OverflowError, OSError) as e:
                raise ValueError(f"Error reading file data: {e}")

        if hasattr(self, 'decryption_key') and self.decryption_key:
            data = self.decrypt_data(data, self.decryption_key)

        if isinstance(out_path, (io.BytesIO, io.BufferedWriter)):
            out_path.write(data)
        else:
            dir = os.path.dirname(out_path)
            if dir:
                try:
                    os.makedirs(dir, exist_ok=True)
                except OSError as e:
                    Logger.log_error(f"Error creating directory {dir}: {e}")
                    # Usa una directory di fallback
                    dir = os.path.dirname(self.original_file)
                    out_path = os.path.join(dir, os.path.basename(out_path))
            
            try:
                with open(out_path, "wb") as out_file:
                    out_file.write(data)
            except OSError as e:
                Logger.log_error(f"Error writing file {out_path}: {e}")
                # Usa un nome file di fallback
                safe_name = self.sanitize_filename(os.path.basename(out_path))
                out_path = os.path.join(dir, safe_name)
                with open(out_path, "wb") as out_file:
                    out_file.write(data)

    def extract_raw(self, offset: int, size: int, out_file: str):
        with open(self.original_file, "rb") as pkg_file:
            pkg_file.seek(offset)
            with open(out_file, "wb") as out_file:
                out_file.write(pkg_file.read(size))

    def dump(self, out_path: str):
        if not os.path.isdir(out_path):
            os.makedirs(out_path)

        log_file_path = os.path.join(out_path, "dump_log.txt")
        with open(log_file_path, 'w') as log_file:
            for file_id, file_info in self.files.items():
                out = os.path.join(out_path, file_info.get("name", f"file_{file_id}"))

                try:
                    if os.path.isfile(out):
                        raise FileExistsError(f"File with matching name already exists: {out}")
                    
                    self.extract(file_id, out)
                    
                    if self.verify_file_integrity(file_id, out):
                        log_message = f"OK: File extracted successfully: {file_info.get('name', f'file_{file_id}')}\n"
                    else:
                        log_message = f"ERROR: Integrity not verified for file: {file_info.get('name', f'file_{file_id}')}\n"
                    
                    log_file.write(log_message)
                    logging.info(log_message.strip())
                except Exception as e:
                    log_message = f"ERROR: Unable to extract file {file_info.get('name', f'file_{file_id}')}: {str(e)}\n"
                    log_file.write(log_message)
                    logging.error(log_message.strip())

        logging.info(f"Dump completed. Log saved in: {log_file_path}")
        return f"Dump completed. Log saved in: {log_file_path}"

    def verify_file_integrity(self, file_id, extracted_path):
        try:
            with open(extracted_path, 'rb') as f:
                extracted_data = f.read()
            
            original_data = self.read_file(file_id)
            
            return len(extracted_data) == len(original_data) and extracted_data == original_data
        except IOError:
            return False

    def read_file(self, file_id):
        file_info = self._files.get(file_id)
        if not file_info:
            raise ValueError(f"File with ID {file_id} not found in the package.")
        
        with open(self.original_file, 'rb') as f:
            f.seek(file_info['offset'])
            data = f.read(file_info['size'])
        
        # Verifica se l'immagine è troncata
        try:
            Image.open(io.BytesIO(data)).verify()
        except Exception:
            # Se l'immagine è troncata, prova a leggere più dati
            with open(self.original_file, 'rb') as f:
                f.seek(file_info['offset'])
                data = f.read(file_info['size'] + 1024)  # Leggi 1KB in più
        
        return data

    def extract_pkg_info(self):
        sfo_info = {
            "pkg_magic": f"0x{format(self.pkg_magic, 'X')}",
            "pkg_type": f"0x{format(self.pkg_type, 'X')}",
            "pkg_0x008": self.pkg_0x008,
            "pkg_file_count": self.pkg_file_count,
            "pkg_entry_count": self.pkg_entry_count,
            "pkg_sc_entry_count": self.pkg_sc_entry_count,
            "pkg_entry_count_2": self.pkg_entry_count_2,
            "pkg_table_offset": f"0x{format(self.pkg_table_offset, 'X')}",
            "pkg_entry_data_size": self.pkg_entry_data_size,
            "pkg_body_offset": f"0x{format(self.pkg_body_offset, 'X')}",
            "pkg_body_size": self.pkg_body_size,
            "pkg_content_offset": f"0x{format(self.pkg_content_offset, 'X')}",
            "pkg_content_size": self.pkg_content_size,
            "pkg_content_id": self.pkg_content_id,
            "pkg_padding": self.pkg_padding,
            "pkg_drm_type": DRMType(self.pkg_drm_type).name if isinstance(self.pkg_drm_type, DRMType) else str(self.pkg_drm_type),
            "pkg_content_type": self.pkg_content_type.name if isinstance(self.pkg_content_type, ContentType) else str(self.pkg_content_type),
            "pkg_content_flags": self.pkg_content_flags,
            "pkg_promote_size": self.pkg_promote_size,
            "pkg_version_date": self.pkg_version_date,
            "pkg_version_hash": self.pkg_version_hash.hex() if isinstance(self.pkg_version_hash, bytes) else f"0x{format(self.pkg_version_hash, 'X')}",
            "pkg_0x088": f"0x{format(self.pkg_0x088, 'X')}",
            "pkg_0x08C": f"0x{format(self.pkg_0x08C, 'X')}",
            "pkg_0x090": f"0x{format(self.pkg_0x090, 'X')}",
            "pkg_0x094": f"0x{format(self.pkg_0x094, 'X')}",
            "pkg_iro_tag": self.pkg_iro_tag.name if self.pkg_iro_tag else "N/A",
            "pkg_drm_type_version": self.pkg_drm_type_version,
            "Main Entry 1 Hash": self.digests[0] if len(self.digests) > 0 else "N/A",
            "Main Entry 2 Hash": self.digests[1] if len(self.digests) > 1 else "N/A",
            "Digest Table Hash": self.digests[2] if len(self.digests) > 2 else "N/A",
            "Main Table Hash": self.digests[3] if len(self.digests) > 3 else "N/A",
            "DESTINATION_COUNTRY": self.get_destination_country(), 
            "icon0": self.extract_icon0()  
        }
        return sfo_info

    def get_destination_country(self):
        try:
            country_code = self._search_country_code()
            if country_code:
                return self._get_full_region_name(country_code)
        except Exception as e:
            Logger.log_error(f"Error extracting destination country: {e}")
        
        return "Unknown Region"

    def _search_country_code(self):
        # Search in param.sfo
        param_sfo = next((file for file in self._files.values() if file.get("name") == "param.sfo"), None)
        if param_sfo:
            with open(self.original_file, 'rb') as f:
                f.seek(param_sfo["offset"])
                sfo_data = f.read(param_sfo["size"])
                country_offset = sfo_data.find(b"DESTINATION_COUNTRY")
                if country_offset != -1:
                    for i in range(country_offset, len(sfo_data) - 1):
                        possible_country = sfo_data[i:i+2].decode('utf-8', errors='ignore')
                        if re.match(r'^[A-Z]{2}$', possible_country):
                            return possible_country

        # Search in content ID
        if self.pkg_content_id:
            match = re.search(r'([A-Z]{2})\d{4}', self.pkg_content_id)
            if match:
                return match.group(1)

        # Search in the entire PKG file
        with open(self.original_file, 'rb') as f:
            data = f.read()
            patterns = [
                rb'DESTINATION_COUNTRY.{0,20}([A-Z]{2})',
                rb'COUNTRY.{0,10}([A-Z]{2})',
                rb'REGION.{0,10}([A-Z]{2})',
                rb'([A-Z]{2})\d{4}-[A-Z]{4}\d{5}'
            ]
            for pattern in patterns:
                match = re.search(pattern, data)
                if match:
                    return match.group(1).decode('utf-8')

        return None

    def _get_full_region_name(self, country_code):
        region_map = {
            'JP': 'Japan',
            'US': 'North America',
            'EU': 'Europe',
            'GB': 'United Kingdom',
            'CN': 'China',
            'KR': 'South Korea',
            'HK': 'Hong Kong',
            'TW': 'Taiwan',
            'RU': 'Russia',
            'AU': 'Australia'
        }
        return region_map.get(country_code, f"Other Region ({country_code})")

    def extract_icon0(self):
        icon0_file = self._files.get(0x1200)
        if icon0_file:
            with open(self.original_file, 'rb') as fp:
                fp.seek(icon0_file['offset'])
                icon_data = fp.read(icon0_file['size'])
                try:
                    # Verifica che l'immagine sia valida
                    Image.open(io.BytesIO(icon_data))
                    Logger.log_information(f"icon0.png data read, size: {len(icon_data)} bytes")
                    return icon_data
                except Exception as e:
                    Logger.log_warning(f"icon0.png found but not a valid image: {str(e)}")
        
        # Se icon0.png non è trovato o non è valido, cerca il primo file immagine valido
        for file in self._files.values():
            if isinstance(file.get("name"), str) and file["name"].lower().endswith(('.png', '.jpg', '.jpeg')):
                with open(self.original_file, 'rb') as fp:
                    fp.seek(file['offset'])
                    icon_data = fp.read(file['size'])
                    try:
                        # Verifica che l'immagine sia valida
                        Image.open(io.BytesIO(icon_data))
                        Logger.log_information(f"Image file {file['name']} data read, size: {len(icon_data)} bytes")
                        return icon_data
                    except Exception as e:
                        Logger.log_warning(f"Image file {file['name']} found but not valid: {str(e)}")
        
        Logger.log_warning("No valid image file found in the package")
        return None

    def remove_file(self, file_name):
        for file_id, file_info in self._files.items():
            if file_info.get("name") == file_name:
                file_size = file_info.get("size", 0)
                del self._files[file_id]
                
                # update the package metadata
                self.pkg_content_size -= file_size
                self.pkg_entry_count -= 1
                self.pkg_file_count -= 1
                
                break
        else:
            raise ValueError(f"File '{file_name}' not found in the package")

    def list_files(self):
        return list(self._files.keys())

    def reverse_dump(self, input_dir: str, progress_callback=None):
        """
        Reconstructs the PKG with modified files from the input directory.
        """
        if not self.files:
            logging.error("No files found in the package.")
            return "Error: No files found in the package."

        log_file_path = os.path.join(input_dir, "reverse_dump_log.txt")
        
        # Create a backup copy of the original PKG file
        backup_file = f"{self.original_file}.bak"
        shutil.copy2(self.original_file, backup_file)
        logging.info(f"Backup created: {backup_file}")

        with open(log_file_path, 'w') as log_file, open(self.original_file, 'r+b') as pkg_file:
            # Preserve the original header
            pkg_file.seek(0)
            header = pkg_file.read(self.pkg_table_offset)

            # Create a new temporary file for the reconstructed PKG
            temp_pkg_file = f"{self.original_file}.temp"
            with open(temp_pkg_file, 'wb') as new_pkg:
                new_pkg.write(header)

                # Update the file table and rewrite the contents
                new_offset = self.pkg_table_offset
                for file_id, file_info in self.files.items():
                    input_file_path = os.path.join(input_dir, file_info.get("name", f"file_{file_id}"))
                    
                    if os.path.exists(input_file_path):
                        with open(input_file_path, 'rb') as input_file:
                            file_content = input_file.read()
                    else:
                        pkg_file.seek(file_info['offset'])
                        file_content = pkg_file.read(file_info['size'])

                    # Update the offset in file_info
                    file_info['offset'] = new_offset
                    file_info['size'] = len(file_content)

                    # Write the file content
                    new_pkg.write(file_content)
                    new_offset += len(file_content)

                    if progress_callback:
                        progress_callback({"status": f"Processed: {file_info.get('name', f'file_{file_id}')}"})

                # Rewrite the updated file table
                self._write_file_table(new_pkg)

            # Replace the original file with the new one
            os.remove(self.original_file)
            os.rename(temp_pkg_file, self.original_file)

        logging.info(f"Reverse dump completed. Log saved in: {log_file_path}")
        return f"Reverse dump completed. Log saved in: {log_file_path}"

    def _write_file_table(self, file):
        file.seek(self.pkg_table_offset)
        for file_id, file_info in self.files.items():  # Cambia self.files invece di self._files
            entry = struct.pack(">6IQ",
                                file_id,
                                file_info['fn_offset'],
                                file_info['flags1'],
                                file_info['flags2'],
                                file_info['offset'],
                                file_info['size'],
                                file_info['padding'])
            file.write(entry)

    def update_file(self, file_id, new_data):
        if file_id in self.files:  # Cambia self.files invece di self._files
            file_info = self.files[file_id]
            file_info['size'] = len(new_data)
            with open(self.original_file, 'r+b') as f:
                f.seek(file_info['offset'])
                f.write(new_data)
            Logger.log_information(f"File {file_id} updated successfully")
        else:
            raise ValueError(f"File with ID {file_id} not found in the package")

    def is_encrypted(self):
        if hasattr(self, 'pkg_content_flags'):
            return (self.pkg_content_flags & Package.FLAG_ENCRYPTED) == Package.FLAG_ENCRYPTED
        elif hasattr(self, 'content_flags'):
            return (self.content_flags & Package.FLAG_ENCRYPTED) == Package.FLAG_ENCRYPTED
        else:
            Logger.log_warning("Neither pkg_content_flags nor content_flags found. Assuming package is not encrypted.")
            return False

    def extract_with_passcode(self, passcode, output_directory):
        if self.is_correct_passcode(passcode):
            self.decryption_key = self.generate_decryption_key(passcode)
            self.extract_all_files(output_directory)
        else:
            raise ValueError("Incorrect passcode")

    def is_correct_passcode(self, passcode):
        try:
            test_key = self.generate_decryption_key(passcode)
            return True
        except:
            return False

    def generate_decryption_key(self, passcode):
        return passcode.encode()

    def extract_all_files(self, output_directory):
        for file_id, file_info in self.files.items():  # Cambia self.files invece di self._files
            safe_name = self.sanitize_filename(file_info.get("name", f"file_{file_id}"))
            output_path = os.path.join(output_directory, safe_name)
            self.extract(file_id, output_path)

    def sanitize_filename(self, filename):
        # Rimuovi caratteri non ASCII
        filename = unicodedata.normalize('NFKD', filename).encode('ASCII', 'ignore').decode()
        # Sostituisci caratteri non alfanumerici con underscore
        filename = re.sub(r'[^\w\-_\. ]', '_', filename)
        # Rimuovi spazi multipli
        filename = re.sub(r'\s+', ' ', filename).strip()
        # Limita la lunghezza del filename
        filename = filename[:255]  # Massima lunghezza per la maggior parte dei filesystem
        return filename if filename else "unnamed_file"

    def decrypt_data(self, data, key):
        return data