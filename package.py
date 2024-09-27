import struct
import os
import typing
from enum import Enum
import io

from utils import print_aligned, bcolors


class Type(Enum):
    PAID_STANDALONE_FULL = 1
    UPGRADABLE = 2
    DEMO = 3
    FREEMIUM = 4


class DRMType(Enum):
    NONE = 0x0
    PS4 = 0xF


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
    MAGIC = 0x7F434E54
    TYPE_THEME = 0x81000001
    TYPE_GAME = 0x40000001
    FLAG_RETAIL = 1 << 31
    FLAG_ENCRYPTED = 0x80000000

    def __init__(self, file: str):
        self.original_file = file
        self.pkg_info = {}
        if os.path.isfile(file):
            header_format = ">5I2H2I4Q36s12s12I"
            with open(file, "rb") as fp:
                data = fp.read(struct.calcsize(header_format))
                # Load the header
                self.pkg_magic, self.pkg_type, self.pkg_0x008, self.pkg_file_count, self.pkg_entry_count, \
                    self.pkg_sc_entry_count, self.pkg_entry_count_2, self.pkg_table_offset, self.pkg_entry_data_size, \
                    self.pkg_body_offset, self.pkg_body_size, self.pkg_content_offset, self.pkg_content_size, \
                    self.pkg_content_id, self.pkg_padding, self.pkg_drm_type, self.pkg_content_type, \
                    self.pkg_content_flags, self.pkg_promote_size, self.pkg_version_date, self.pkg_version_hash, \
                    self.pkg_0x088, self.pkg_0x08C, self.pkg_0x090, self.pkg_0x094, self.pkg_iro_tag, \
                    self.pkg_drm_type_version = struct.unpack(header_format, data)
                # Decode content ID
                self.pkg_content_id = self.pkg_content_id.decode()

                # Load hashes
                fp.seek(0x100, os.SEEK_SET)
                data = fp.read(struct.calcsize("128H"))
                self.digests = [data[0:32].hex(), data[32:64].hex(), data[64:96].hex(), data[96:128].hex()]

                self.pkg_content_type = ContentType(self.pkg_content_type)
                if self.pkg_iro_tag > 0:
                    self.pkg_iro_tag = IROTag(self.pkg_iro_tag)

                self.__load_files(fp)
                self.pkg_info = self.extract_pkg_info()

    def __load_files(self, fp):
        old_pos = fp.tell()
        fp.seek(self.pkg_table_offset, os.SEEK_SET)

        entry_format = ">6IQ"
        self._files = {}
        for i in range(self.pkg_entry_count):
            file_id, filename_offset, flags1, flags2, offset, size, padding = struct.unpack(
                entry_format, fp.read(struct.calcsize(entry_format)))
            self._files[file_id] = {
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
            fp.seek(self._files[0x200]["offset"] + file["fn_offset"])

            fn = ''.join(iter(lambda: fp.read(1).decode('ascii'), '\x00'))

            if fn:
                self._files[key]["name"] = fn
        fp.seek(old_pos)

    def info(self) -> None:
        print_aligned("Magic:", f"0x{format(self.pkg_magic, 'X')}", color=bcolors.OKGREEN
                      if self.pkg_magic == Package.MAGIC else bcolors.FAIL)

        if self.pkg_magic != Package.MAGIC:
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

    def extract(self, file_name_or_id: typing.Union[str, int], out_path: typing.Union[str, io.BytesIO]) -> None:
        if isinstance(file_name_or_id, str):
            try:
                file_name_or_id = int(file_name_or_id, 16)
            except ValueError:
                pass  # è un nome file
        
        # Find the target
        chosen_file = self._files.get(file_name_or_id)
        chosen_key = file_name_or_id
        if not chosen_file:
            for key, file in self._files.items():
                if file.get("name") == file_name_or_id:
                    chosen_file = file
                    chosen_key = key
                    break

        if not chosen_file:
            raise ValueError(f"Couldn't find file {file_name_or_id} in package!")

        # Open the file and seek to offset
        with open(self.original_file, "rb") as pkg_file:
            pkg_file.seek(chosen_file["offset"])
            if isinstance(out_path, io.BytesIO):
                out_path.write(pkg_file.read(chosen_file["size"]))
            else:
                dir = os.path.dirname(out_path)
                if dir:
                    os.makedirs(dir, exist_ok=True)
                with open(out_path, "wb") as out_file:
                    out_file.write(pkg_file.read(chosen_file["size"]))

    def extract_raw(self, offset: int, size: int, out_file: str):
        with open(self.original_file, "rb") as pkg_file:
            pkg_file.seek(offset)
            with open(out_file, "wb") as out_file:
                out_file.write(pkg_file.read(size))

    def dump(self, out_path: str):
        if not os.path.isdir(out_path):
            os.makedirs(out_path)

        for key in self._files:
            out = os.path.join(out_path, self._files[key].get("name", f"{key}"))

            if os.path.isfile(out):
                raise FileExistsError(f"File with matching name already exists: {out}")
            self.extract(key, out)

        return "Dump completed successfully"

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
            "pkg_drm_type": DRMType(self.pkg_drm_type).name,
            "pkg_content_type": self.pkg_content_type.name,
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
            "Main Entry 1 Hash": self.digests[0],
            "Main Entry 2 Hash": self.digests[1],
            "Digest Table Hash": self.digests[2],
            "Main Table Hash": self.digests[3],
            "DESTINATION_COUNTRY": self.get_destination_country(),  # Aggiunto il paese di destinazione
            "icon0": self.extract_icon0()  # Aggiunto per estrarre l'icona
        }
        return sfo_info

    def get_destination_country(self):
        # Logica per estrarre il paese di destinazione
        try:
            with open(self.original_file, 'rb') as f:
                f.seek(self.pkg_table_offset)  # Posizione ipotetica
                # Lettura ipotetica del paese di destinazione
                # La logica reale dipenderà dal formato del file PKG
                country_code = f.read(2).decode('utf-8')
                return country_code
        except Exception as e:
            return "Unknown"

    def extract_icon0(self):
        # Logica per estrarre l'icona (icon0.png)
        try:
            icon0_file = next(file for file in self._files.values() if file.get("name") == "icon0.png")
            with open(self.original_file, 'rb') as f:
                f.seek(icon0_file["offset"])
                return f.read(icon0_file["size"])
        except StopIteration:
            return None
        except Exception as e:
            return None