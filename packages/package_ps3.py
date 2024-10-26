import logging
import struct
import os
from .package_base import PackageBase
from .utils import Logger
from .enums import DRMType, ContentType, PackageType, PackageFlag
from . import AES_LIBRARY_AVAILABLE

if AES_LIBRARY_AVAILABLE:
    from .AesLibraryPs3.aes import AES_ctx, AES_set_key, AES_encrypt, AES_KEY_LEN_128, AES_cbc_decrypt
    from .AesLibraryPs3.kirk_engine import kirk_init, kirk_CMD7
    try:
        from .AesLibraryPs3.kirk_engine import decrypt_pgd
    except ImportError:
        from .AesLibraryPs3.amctrl import decrypt_pgd
    from Crypto.Cipher import AES 
else:

    def kirk_init():
        raise NotImplementedError("AesLibraryPs3 non è disponibile")
    
    def kirk_CMD7(*args):
        raise NotImplementedError("AesLibraryPs3 non è disponibile")
    
    def decrypt_pgd(*args):
        raise NotImplementedError("AesLibraryPs3 non è disponibile")
    
    AES = None  

class PackagePS3(PackageBase):
    MAGIC_PS3 = 0x7f504b47  # ?PKG per PS3
    PS3_AES_KEY = b'\x2E\x7B\x71\xD7\xC9\xC9\xA1\x4E\xA3\x22\x1F\x18\x88\x28\xB8\xF8'

    def __init__(self, file: str):
        super().__init__(file)
        self.is_ps3 = False
        self.pkg_revision = None
        self.pkg_type = None
        self.pkg_metadata_offset = None
        self.pkg_metadata_count = None
        self.pkg_metadata_size = None
        self.item_count = None
        self.total_size = None
        self.data_offset = None
        self.data_size = None
        self.content_id = None
        self.digest = None
        self.pkg_data_riv = None
        self.pkg_header_digest = None
        self.is_encrypted = True  # Assumiamo che sia crittografato di default
        self.public_key = None
        self.xor_key = None

        try:
            result = kirk_init()  # Inizializza il motore KIRK
            if result != 0:
                raise ValueError(f"Errore nell'inizializzazione di KIRK: {result}")
            
            with open(file, "rb") as fp:
                magic = struct.unpack(">I", fp.read(4))[0]
                if magic == self.MAGIC_PS3:
                    self.is_ps3 = True
                    self._load_ps3_pkg(fp)
                else:
                    raise ValueError(f"Formato PKG sconosciuto: {magic:08X}")
        except Exception as e:
            Logger.log_error(f"Errore durante l'inizializzazione: {str(e)}")
            raise

    def _load_ps3_pkg(self, fp):
        try:
            header_format = ">4sHHIIIIQQQ48s16s16s64s"
            fp.seek(0)
            data = fp.read(struct.calcsize(header_format))
            
            (magic, self.pkg_revision, self.pkg_type, self.pkg_metadata_offset, self.pkg_metadata_count,
             self.pkg_metadata_size, self.item_count, self.total_size, self.data_offset, self.data_size,
             content_id_and_padding, self.digest, self.pkg_data_riv, self.pkg_header_digest) = struct.unpack(header_format, data)

            self.content_id = self._safe_decode(content_id_and_padding[:0x30])
            self.digest = self.digest.hex()
            self.pkg_data_riv = bytes.fromhex(self.pkg_data_riv.hex())
            self.pkg_header_digest = self.pkg_header_digest.hex()
            self.public_key = data[0x70:0x80]

            Logger.log_information("Header PS3 PKG caricato con successo.")
            Logger.log_information(f"Metadata offset: 0x{self.pkg_metadata_offset:X}, count: {self.pkg_metadata_count}, size: {self.pkg_metadata_size}")
            Logger.log_information(f"Total size: {self.total_size}, Data offset: 0x{self.data_offset:X}, Data size: {self.data_size}")
            
            self._decrypt_and_load_metadata(fp)
            self._decrypt_and_load_files(fp)

        except Exception as e:
            Logger.log_error(f"Errore durante il caricamento del file PS3 PKG: {str(e)}")
            raise ValueError(f"Errore durante il caricamento del file PS3 PKG: {str(e)}")

    def _decrypt_and_load_metadata(self, fp):
        try:
            fp.seek(self.pkg_metadata_offset)
            encrypted_metadata = fp.read(self.pkg_metadata_size)
            print(f"Debug: Encrypted metadata size: {len(encrypted_metadata)}")
            print(f"Debug: First 16 bytes of encrypted metadata: {encrypted_metadata[:16].hex()}")
            
            decrypted_metadata = self._decrypt_data(encrypted_metadata)
            print(f"Debug: Decrypted metadata size: {len(decrypted_metadata)}")
            print(f"Debug: First 32 bytes of decrypted metadata: {decrypted_metadata[:32].hex()}")
            
            self.metadata = {}
            offset = 0
            for _ in range(self.pkg_metadata_count):
                if offset + 12 > len(decrypted_metadata):
                    break
                key, value_type, size = struct.unpack(">III", decrypted_metadata[offset:offset+12])
                offset += 12
                
                if offset + size > len(decrypted_metadata):
                    break

                value = decrypted_metadata[offset:offset+size]
                offset += size

                self.metadata[key] = value
                self._process_metadata(key, value)
                print(f"Debug: Metadata - key=0x{key:X}, value_type={value_type}, size={size}, value={self._safe_format(value)}")

            print(f"Debug: Processed {len(self.metadata)} metadata entries")

        except Exception as e:
            Logger.log_error(f"Errore durante il caricamento dei metadata: {str(e)}")
            raise ValueError(f"Errore durante il caricamento dei metadata: {str(e)}")

    def _decrypt_and_load_files(self, fp):
        try:
            Logger.log_information(f"Inizio caricamento file. Data offset: 0x{self.data_offset:X}, Item count: {self.item_count}")
            fp.seek(self.data_offset)
            encrypted_file_entries = fp.read(32 * self.item_count)
            print(f"Debug: Encrypted file entries size: {len(encrypted_file_entries)}")
            print(f"Debug: First 32 bytes of encrypted file entries: {encrypted_file_entries[:32].hex()}")
            
            decrypted_file_entries = self._decrypt_data(encrypted_file_entries)
            print(f"Debug: Decrypted file entries size: {len(decrypted_file_entries)}")
            print(f"Debug: First 32 bytes of decrypted file entries: {decrypted_file_entries[:32].hex()}")
            
            self.files = {}
            for i in range(self.item_count):
                entry = decrypted_file_entries[i*32:(i+1)*32]
                if len(entry) < 32:
                    Logger.log_warning(f"Entry del file {i+1} troppo corta. Saltata.")
                    continue
                
                file_name_offset, file_name_size, file_offset, file_size, flags = struct.unpack(">IIQQI", entry[:28])
                
                print(f"Debug: File {i+1} - name_offset=0x{file_name_offset:X}, name_size={file_name_size}, offset=0x{file_offset:X}, size={file_size}, flags=0x{flags:X}")
                
                if file_name_offset > self.total_size or file_offset > self.total_size:
                    Logger.log_warning(f"File {i+1}: Offset non valido. Saltato.")
                    continue
                
                if file_size > self.total_size:
                    Logger.log_warning(f"File {i+1}: Dimensione file sospetta. Potrebbe essere corrotto.")
                
                try:
                    fp.seek(self.data_offset + file_name_offset)
                    encrypted_file_name = fp.read(file_name_size)
                    file_name = self._decrypt_data(encrypted_file_name)[:file_name_size].decode('utf-8', errors='ignore')
                except Exception as e:
                    Logger.log_warning(f"Errore durante la decrittazione del nome del file {i+1}: {str(e)}")
                    file_name = f"unknown_file_{i}"

                self.files[file_name] = {
                    "offset": file_offset,
                    "size": file_size,
                    "flags": flags
                }

            Logger.log_information(f"Caricati {len(self.files)} file.")

        except Exception as e:
            Logger.log_error(f"Errore durante il caricamento dei file: {str(e)}")
            raise ValueError(f"Errore durante il caricamento dei file: {str(e)}")

    def _decrypt_data(self, data):
        try:
            if len(data) < 16:
                raise ValueError(f"Input data too short. Expected at least 16 bytes, got {len(data)} bytes.")
            
            print(f"Debug: Attempting to decrypt {len(data)} bytes of data")
            print(f"Debug: First 16 bytes of encrypted data: {data[:16].hex()}")
            
            # Prova prima con AES diretto
            if AES is not None:
                aes_key = self.PS3_AES_KEY
                cipher = AES.new(aes_key, AES.MODE_CBC, iv=data[:16])
                decrypted = cipher.decrypt(data[16:])
                print(f"Debug: AES decryption result - First 16 bytes: {decrypted[:16].hex()}")
                
                if not all(byte == 0 for byte in decrypted):
                    return decrypted
            
            # Se AES diretto non funziona o produce tutti zeri, prova con kirk_CMD7
            decrypted = bytearray(len(data))
            decrypted_size = kirk_CMD7(decrypted, data, len(data))
            
            if decrypted_size < 0:
                raise ValueError(f"kirk_CMD7 failed with error code: {decrypted_size}")
            if decrypted_size == 0:
                raise ValueError("No data was decrypted")
            
            print(f"Debug: Decrypted data size: {decrypted_size}")
            print(f"Debug: First 16 bytes of decrypted data: {decrypted[:16].hex()}")
            
            if all(byte == 0 for byte in decrypted[:decrypted_size]):
                print("Warning: Decrypted data is all zeros. This might indicate a problem with the decryption process.")
            
            return bytes(decrypted[:decrypted_size])
        except Exception as e:
            Logger.log_error(f"Errore durante la decrittazione dei dati: {str(e)}")
            raise

    def _process_metadata(self, key, value):
        try:
            if key == 0x1:
                self.drm_type = self._safe_get_enum(DRMType, value)
            elif key == 0x2:
                self.content_type = self._safe_get_enum(ContentType, value)
            elif key == 0x3:
                self.package_type = self._safe_get_enum(PackageType, value & 0xFFFF)
                self.package_flag = self._safe_get_enum(PackageFlag, (value >> 16) & 0xFFFF)
            elif key == 0x4:
                self.package_size = value
            elif key == 0x5:
                self.make_package_npdrm_revision = value >> 16
                self.package_version = value & 0xFFFF
            elif key == 0x6:
                self.title_id = self._safe_decode(value)
            elif key == 0x7:
                self.qa_digest = value.hex() if isinstance(value, bytes) else str(value)
            elif key == 0x8:
                if isinstance(value, int):
                    self.system_version = f"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF:02d}"
                    self.app_version = f"{(value >> 8) & 0xFF}.{value & 0xFF:02d}"
                else:
                    Logger.log_warning(f"Valore inaspettato per il metadata 0x8: {value}")
            elif key == 0xA:
                self.install_directory = self._safe_decode(value[8:]) if isinstance(value, bytes) and len(value) > 8 else str(value)
        except Exception as e:
            Logger.log_warning(f"Errore durante l'elaborazione del metadata con chiave 0x{key:X}: {str(e)}")

    def extract_file(self, file_name, output_path):
        if file_name not in self.files:
            raise ValueError(f"Il file {file_name} non esiste nel pacchetto.")

        file_info = self.files[file_name]
        with open(self.original_file, "rb") as pkg, open(output_path, "wb") as out:
            pkg.seek(file_info["offset"])
            encrypted_data = pkg.read(file_info["size"])
            decrypted_data = self._decrypt_data(encrypted_data)
            
            # Se il file è un PGD, decrittalo ulteriormente
            if file_name.endswith('.pgd'):
                decrypted_data = decrypt_pgd(decrypted_data, len(decrypted_data), 0, None)
            
            out.write(decrypted_data)

        Logger.log_information(f"File {file_name} estratto con successo in {output_path}")

    def get_info(self):
        try:
            info = super().get_info()
            if self.is_ps3:
                info.update({
                    "pkg_revision": f"0x{self.pkg_revision:04X}",
                    "pkg_type": f"0x{self.pkg_type:04X}",
                    "pkg_metadata_offset": f"0x{self.pkg_metadata_offset:X}",
                    "pkg_metadata_count": self.pkg_metadata_count,
                    "pkg_metadata_size": self.pkg_metadata_size,
                    "item_count": self.item_count,
                    "total_size": self.total_size,
                    "data_offset": f"0x{self.data_offset:X}",
                    "data_size": self.data_size,
                    "content_id": self.content_id,
                    "digest": self.digest,
                    "pkg_data_riv": self.pkg_data_riv,
                    "pkg_header_digest": self.pkg_header_digest,
                    "drm_type": getattr(self, 'drm_type', 'Sconosciuto'),
                    "content_type": getattr(self, 'content_type', 'Sconosciuto'),
                    "package_type": getattr(self, 'package_type', 'Sconosciuto'),
                    "package_flag": getattr(self, 'package_flag', 'Sconosciuto'),
                    "package_size": getattr(self, 'package_size', 'Sconosciuto'),
                    "make_package_npdrm_revision": getattr(self, 'make_package_npdrm_revision', 'Sconosciuto'),
                    "package_version": getattr(self, 'package_version', 'Sconosciuto'),
                    "title_id": getattr(self, 'title_id', 'Sconosciuto'),
                    "qa_digest": getattr(self, 'qa_digest', 'Sconosciuto'),
                    "system_version": getattr(self, 'system_version', 'Sconosciuto'),
                    "app_version": getattr(self, 'app_version', 'Sconosciuto'),
                    "install_directory": getattr(self, 'install_directory', 'Sconosciuto'),
                    "is_encrypted": self.is_encrypted,
                    "valid_files": len(self.files),
                })
            return info
        except Exception as e:
            Logger.log_error(f"Errore durante la generazione delle informazioni: {str(e)}")
            return {"error": str(e)}

    def _safe_get_enum(self, enum_class, value):
        try:
            return enum_class(value).name
        except ValueError:
            return f"Sconosciuto (0x{value:X})"

    def _safe_format(self, value):
        if isinstance(value, bytes):
            return f"0x{value.hex()}"
        elif isinstance(value, int):
            return f"0x{value:X}"
        elif isinstance(value, str):
            return f"'{value}'"
        else:
            return str(value)

    def dump(self, output_dir):
        """
        Esegue il dump del contenuto del pacchetto PS3 nella directory specificata.
        """
        os.makedirs(output_dir, exist_ok=True)
        
        for file_name, file_info in self.files.items():
            file_path = os.path.join(output_dir, file_name)
            
            # Crea le directory necessarie
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            try:
                with open(self.original_file, 'rb') as pkg_file:
                    pkg_file.seek(file_info['offset'])
                    file_data = pkg_file.read(file_info['size'])
                
                with open(file_path, 'wb') as out_file:
                    out_file.write(file_data)
                
                Logger.log_information(f"File estratto: {file_name}")
            except Exception as e:
                Logger.log_error(f"Errore durante l'estrazione del file {file_name}: {str(e)}")
        
        Logger.log_information(f"Dump completato. File estratti in: {output_dir}")
        return f"Dump completato. File estratti in: {output_dir}"

