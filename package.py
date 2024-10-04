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
        if not os.path.isfile(file):
            raise FileNotFoundError(f"The PKG file '{file}' does not exist.")
        
        self.original_file = file
        self.pkg_info = {}
        if os.path.isfile(file):
            header_format = ">5I2H2I4Q36s12s12I"
            try:
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
                    self.pkg_content_id = self.pkg_content_id.decode('utf-8', errors='ignore')

                    # Load hashes
                    fp.seek(0x100, os.SEEK_SET)
                    data = fp.read(struct.calcsize("128H"))
                    self.digests = [data[0:32].hex(), data[32:64].hex(), data[64:96].hex(), data[96:128].hex()]

                    try:
                        self.pkg_content_type = ContentType(self.pkg_content_type)
                    except ValueError:
                        Logger.log_warning(f"Warning: {self.pkg_content_type} is not a valid ContentType. Setting to None.")
                        self.pkg_content_type = None  # Imposta a None se non è valido
                    try:
                        self.pkg_iro_tag = IROTag(self.pkg_iro_tag)
                    except ValueError:
                        Logger.log_warning(f"Warning: {self.pkg_iro_tag} is not a valid IROTag. Setting to None.")
                        self.pkg_iro_tag = None  # Imposta a None se non è valido

                    self.__load_files(fp)
                    self.files = self._files 
                    self.pkg_info = self.extract_pkg_info()
            except UnicodeDecodeError:
                raise ValueError("Error decoding PKG file: Invalid character encoding detected.")
            except struct.error:
                raise ValueError("Error unpacking PKG file: Incorrect file structure.")
            except Exception as e:
                self.__log_and_raise_error(e)

    def __log_and_raise_error(self, error):
        try:
            file_list = self.list_files()
            Logger.log_error(f"Error loading PKG file: {str(error)}. Files in PKG: {file_list}")
            raise ValueError(f"Error loading PKG file: {str(error)}. Files in PKG: {file_list}")
        except Exception as e:
            Logger.log_error(f"Error loading PKG file: {str(error)}. Additionally, failed to list files: {str(e)}")
            raise ValueError(f"Error loading PKG file: {str(error)}. Additionally, failed to list files: {str(e)}")

    def __load_files(self, fp):
        old_pos = fp.tell()
        fp.seek(self.pkg_table_offset, os.SEEK_SET)

        entry_format = ">6IQ"
        self._files = {}
        for i in range(self.pkg_entry_count):
            file_id, filename_offset, flags1, flags2, offset, size, padding = struct.unpack(
                entry_format, fp.read(struct.calcsize(entry_format)))
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
            fp.seek(self._files[0x200]["offset"] + file["fn_offset"])

            fn = b''
            while True:
                char = fp.read(1)
                if char == b'\x00':
                    break
                fn += char

            if fn:
                self._files[key]["name"] = fn.decode('utf-8', errors='ignore')
        fp.seek(old_pos)

    def get_info(self):
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
            pkg_file.seek(chosen_file["offset"])
            data = pkg_file.read(chosen_file["size"])

        if isinstance(out_path, (io.BytesIO, io.BufferedWriter)):
            out_path.write(data)
        else:
            dir = os.path.dirname(out_path)
            if dir:
                os.makedirs(dir, exist_ok=True)
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
        for file_id, file_info in self.files.items():
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
        if file_id in self._files:
            file_info = self._files[file_id]
            file_info['size'] = len(new_data)
            with open(self.original_file, 'r+b') as f:
                f.seek(file_info['offset'])
                f.write(new_data)
            Logger.log_information(f"File {file_id} updated successfully")
        else:
            raise ValueError(f"File with ID {file_id} not found in the package")