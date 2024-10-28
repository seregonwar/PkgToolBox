import os
import struct
import binascii
from Crypto.Cipher import AES
import logging
from PIL import Image
import io
from .package_base import PackageBase
import shutil

class PackagePS3(PackageBase):
    MAGIC_PS3 = 0x7f504b47  # ?PKG per PS3
    
    def __init__(self, pkg_path):
        try:
            super().__init__(pkg_path)
            self.original_file = pkg_path
            self.files = {}
            self.content_id = None
            self.pkg_type = None
            self.pkg_info = {}
            
            # Chiavi AES per PS3/PSP
            self.psp_aes_key = bytes([0x07, 0xF2, 0xC6, 0x82, 0x90, 0xB5, 0x0D, 0x2C, 0x33, 0x81, 0x8D, 0x70, 0x9B, 0x60, 0xE6, 0x2B])
            self.ps3_aes_key = bytes([0x2E, 0x7B, 0x71, 0xD7, 0xC9, 0xC9, 0xA1, 0x4E, 0xA3, 0x22, 0x1F, 0x18, 0x88, 0x28, 0xB8, 0xF8])
            self.aes_key = bytes(16)
            self.pkg_file_key = bytes(16)
            self.ui_encrypted_file_start_offset = 0
            
            self.temp_dir = os.path.join(os.path.dirname(pkg_path), "._temp_output")
            os.makedirs(self.temp_dir, exist_ok=True)
            
            self.load_pkg_info()
            self.decrypt_and_extract()
            
        except Exception as e:
            logging.error(f"Error initializing PackagePS3: {str(e)}")
            raise

    def decrypt_and_extract(self):
        """Decripta il PKG ed estrae i file necessari"""
        try:
            # Decripta il PKG
            decrypted_pkg = self.decrypt_pkg_file(self.original_file)
            if not decrypted_pkg:
                raise ValueError("Failed to decrypt PKG")

            # Estrai i file
            self.extract_files(decrypted_pkg, self.temp_dir)

            # Carica EBOOT.BIN se presente
            eboot_path = os.path.join(self.temp_dir, 'USRDIR', 'EBOOT.BIN')
            if os.path.exists(eboot_path):
                with open(eboot_path, 'rb') as f:
                    self.eboot_data = f.read()
                    self.parse_eboot_info()
                logging.info("EBOOT.BIN loaded successfully")

            # Carica ICON0.PNG se presente
            icon_path = os.path.join(self.temp_dir, 'ICON0.PNG')
            if os.path.exists(icon_path):
                try:
                    with Image.open(icon_path) as img:
                        self.icon_data = img
                    logging.info("ICON0.PNG loaded successfully")
                except Exception as e:
                    logging.error(f"Error loading ICON0.PNG: {str(e)}")

        except Exception as e:
            logging.error(f"Error in decrypt_and_extract: {str(e)}")
            raise

    def parse_eboot_info(self):
        """Estrae informazioni da EBOOT.BIN"""
        try:
            if hasattr(self, 'eboot_data'):
                # Cerca il TITLE_ID
                title_id_offset = self.eboot_data.find(b'TITLE_ID')
                if title_id_offset != -1:
                    self.title_id = self.eboot_data[title_id_offset+9:title_id_offset+18].decode('utf-8')
                
                # Cerca la APP_VER
                app_ver_offset = self.eboot_data.find(b'APP_VER')
                if app_ver_offset != -1:
                    self.app_version = self.eboot_data[app_ver_offset+8:app_ver_offset+16].decode('utf-8')
                
                # Aggiungi altre informazioni che vuoi estrarre...
                
        except Exception as e:
            logging.error(f"Error parsing EBOOT.BIN: {str(e)}")

    def decrypt_pkg_file(self, pkg_file_name):
        try:
            moltiplicator = 65536
            encrypted_data = bytearray(16 * moltiplicator)
            decrypted_data = bytearray(16 * moltiplicator)

            with open(pkg_file_name, "rb") as pkg_read_stream:
                # Verifica magic number e tipo
                pkg_magic = pkg_read_stream.read(4)
                if pkg_magic != b'\x7F\x50\x4B\x47':
                    raise ValueError("Invalid PKG file")

                pkg_read_stream.seek(0x04)
                pkg_finalized = pkg_read_stream.read(1)[0]
                if pkg_finalized != 0x80:
                    raise ValueError("Debug PKG not supported")

                pkg_read_stream.seek(0x07)
                pkg_type = pkg_read_stream.read(1)[0]
                self.aes_key = self.ps3_aes_key if pkg_type == 0x01 else self.psp_aes_key

                # Leggi offset e dimensione file criptato
                pkg_read_stream.seek(0x24)
                self.ui_encrypted_file_start_offset = struct.unpack(">I", pkg_read_stream.read(4))[0]
                pkg_read_stream.seek(0x2C)
                ui_encrypted_file_length = struct.unpack(">I", pkg_read_stream.read(4))[0]

                # Leggi chiave file
                pkg_read_stream.seek(0x70)
                self.pkg_file_key = pkg_read_stream.read(16)
                inc_pkg_file_key = bytearray(self.pkg_file_key)

                # Decripta
                cipher = AES.new(self.aes_key, AES.MODE_ECB)
                decrypted_file = os.path.join(self.temp_dir, "pkg.dec")

                with open(decrypted_file, "wb") as out_file:
                    pkg_read_stream.seek(self.ui_encrypted_file_start_offset)
                    
                    remaining = ui_encrypted_file_length
                    while remaining > 0:
                        chunk_size = min(remaining, 16 * moltiplicator)
                        encrypted_chunk = pkg_read_stream.read(chunk_size)
                        
                        # Genera chiave XOR
                        key_chunk = bytearray(chunk_size)
                        for i in range(0, chunk_size, 16):
                            key_chunk[i:i+16] = inc_pkg_file_key
                            self.increment_array(inc_pkg_file_key, 15)
                            
                        # Cripta chiave e XOR con dati
                        xor_key = cipher.encrypt(bytes(key_chunk))
                        decrypted_chunk = bytes(a ^ b for a, b in zip(encrypted_chunk, xor_key[:len(encrypted_chunk)]))
                        
                        out_file.write(decrypted_chunk)
                        remaining -= chunk_size

                return decrypted_file

        except Exception as e:
            logging.error(f"Error decrypting PKG: {str(e)}")
            return None

    def get_info(self):
        """Restituisce le informazioni del pacchetto in un formato leggibile"""
        info = super().get_info()
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
            "drm_type": getattr(self, 'drm_type', 'Unknown'),
            "content_type": getattr(self, 'content_type', 'Unknown'),
            "package_type": getattr(self, 'package_type', 'Unknown'),
            "package_flag": getattr(self, 'package_flag', 'Unknown'),
            "package_size": getattr(self, 'package_size', 'Unknown'),
            "make_package_npdrm_revision": getattr(self, 'make_package_npdrm_revision', 'Unknown'),
            "package_version": getattr(self, 'package_version', 'Unknown'),
            "title_id": getattr(self, 'title_id', 'Unknown'),
            "qa_digest": getattr(self, 'qa_digest', 'Unknown'),
            "system_version": getattr(self, 'system_version', 'Unknown'),
            "app_version": getattr(self, 'app_version', 'Unknown'),
            "install_directory": getattr(self, 'install_directory', 'Unknown'),
            "is_encrypted": self.is_encrypted,
            "valid_files": len(self.files),
        })
        
        # Aggiungi info da EBOOT se disponibili
        if hasattr(self, 'eboot_data'):
            info.update({
                "eboot_title_id": getattr(self, 'title_id', 'Unknown'),
                "eboot_app_version": getattr(self, 'app_version', 'Unknown'),
                # Aggiungi altre info estratte da EBOOT...
            })
            
        return info

    def load_pkg_info(self):
        try:
            with open(self.original_file, "rb") as pkg:
                # Verifica magic number
                magic = pkg.read(4)
                if magic != b'\x7F\x50\x4B\x47':
                    logging.error(f"Invalid magic number: {magic.hex()}")
                    raise ValueError("Invalid PKG file format")

                # Leggi header PKG
                pkg.seek(0x04)
                self.pkg_revision = struct.unpack('>H', pkg.read(2))[0]
                pkg.seek(0x07)
                self.pkg_type = pkg.read(1)[0]
                
                # Leggi metadata
                pkg.seek(0x0C)
                self.pkg_metadata_offset = struct.unpack('>I', pkg.read(4))[0]
                self.pkg_metadata_count = struct.unpack('>I', pkg.read(4))[0]
                self.pkg_metadata_size = struct.unpack('>I', pkg.read(4))[0]
                
                # Leggi informazioni sui file
                pkg.seek(0x18)
                self.item_count = struct.unpack('>I', pkg.read(4))[0]
                self.total_size = struct.unpack('>Q', pkg.read(8))[0]
                self.data_offset = struct.unpack('>I', pkg.read(4))[0]
                self.data_size = struct.unpack('>Q', pkg.read(8))[0]
                
                # Leggi content ID (0x30)
                pkg.seek(0x30)
                content_id_bytes = pkg.read(0x30)
                try:
                    self.content_id = content_id_bytes.decode('utf-8').rstrip('\0')
                    if not self.content_id:
                        raise ValueError("Empty content ID")
                except (UnicodeDecodeError, ValueError):
                    try:
                        self.content_id = content_id_bytes.decode('ascii', errors='ignore').rstrip('\0')
                    except:
                        self.content_id = content_id_bytes.hex()[:32]
                
                # Leggi digest e altre informazioni di sicurezza (0x60)
                pkg.seek(0x60)
                self.digest = pkg.read(0x10).hex()
                self.pkg_data_riv = pkg.read(0x10).hex()
                self.pkg_header_digest = pkg.read(0x40).hex()
                
                # Leggi informazioni DRM e contenuto (0xB0)
                pkg.seek(0xB0)
                self.drm_type = struct.unpack('>I', pkg.read(4))[0]
                self.content_type = struct.unpack('>I', pkg.read(4))[0]
                self.package_type = struct.unpack('>H', pkg.read(2))[0]
                self.package_flag = struct.unpack('>H', pkg.read(2))[0]
                
                # Informazioni aggiuntive
                self.package_size = os.path.getsize(self.original_file)
                pkg.seek(0xBC)
                self.make_package_npdrm_revision = struct.unpack('>H', pkg.read(2))[0]
                self.package_version = struct.unpack('>H', pkg.read(2))[0]
                
                # Leggi title ID e altre informazioni (0xC4)
                pkg.seek(0xC4)
                title_id_bytes = pkg.read(0x9)
                try:
                    self.title_id = title_id_bytes.decode('utf-8').rstrip('\0')
                except:
                    self.title_id = title_id_bytes.hex()[:16]
                
                self.qa_digest = pkg.read(0x10).hex()
                
                # System version e app version (0xE4)
                pkg.seek(0xE4)
                self.system_version = struct.unpack('>I', pkg.read(4))[0]
                self.app_version = struct.unpack('>I', pkg.read(4))[0]
                
                # Install directory (0xF0)
                pkg.seek(0xF0)
                install_dir_bytes = pkg.read(0x20)
                try:
                    self.install_directory = install_dir_bytes.decode('utf-8').rstrip('\0')
                except:
                    self.install_directory = install_dir_bytes.hex()[:32]
                
                # Stato crittografia
                self.is_encrypted = True  # PS3 PKG sono sempre criptati

                logging.info("PKG info loaded successfully")
                logging.info(f"Content ID: {self.content_id}")
                logging.info(f"Title ID: {self.title_id}")

        except Exception as e:
            logging.error(f"Error loading PKG info: {str(e)}")
            raise

    def load_file_entries(self, pkg):
        try:
            if not self.pkg_metadata_offset or not self.pkg_metadata_count:
                raise ValueError("Invalid metadata information")
                
            pkg.seek(self.pkg_metadata_offset)
            
            for i in range(self.pkg_metadata_count):
                try:
                    entry_data = pkg.read(0x20)
                    if len(entry_data) < 0x20:
                        logging.error(f"Incomplete entry data at index {i}")
                        break
                        
                    name_offset, name_size, data_offset, data_size = struct.unpack('>IIII', entry_data[:16])
                    
                    # Verifica valori validi
                    file_size = os.path.getsize(self.original_file)
                    if (name_offset > file_size or 
                        data_offset > file_size or 
                        name_size > 1024 or  # Nome file ragionevolmente lungo
                        data_size > file_size):
                        logging.warning(f"Invalid entry values at index {i}")
                        continue
                    
                    # Leggi il nome del file
                    current_pos = pkg.tell()
                    pkg.seek(name_offset)
                    name_bytes = pkg.read(name_size)
                    pkg.seek(current_pos)
                    
                    # Gestione nome file
                    try:
                        name = name_bytes.decode('utf-8').rstrip('\0')
                    except UnicodeDecodeError:
                        try:
                            name = name_bytes.decode('latin-1').rstrip('\0')
                        except:
                            name = f"file_{i:04d}_{binascii.hexlify(name_bytes[:4]).decode()}"
                            logging.warning(f"Could not decode filename at index {i}")

                    self.files[name] = {
                        'id': i,
                        'name': name,
                        'offset': data_offset,
                        'size': data_size
                    }
                    
                except Exception as e:
                    logging.error(f"Error processing entry {i}: {str(e)}")
                    continue

            logging.info(f"Loaded {len(self.files)} file entries")

        except Exception as e:
            logging.error(f"Error loading file entries: {str(e)}")
            raise

    def extract_file(self, file_id, output_stream):
        try:
            file_info = next((f for f in self.files.values() if f['id'] == file_id), None)
            if not file_info:
                raise ValueError(f"File ID {file_id} not found")

            with open(self.original_file, 'rb') as pkg:
                pkg.seek(file_info['offset'])
                data = pkg.read(file_info['size'])
                
                # Decripta se necessario
                if self.pkg_type == 0x01:  # PS3
                    cipher = AES.new(self.ps3_aes_key, AES.MODE_ECB)
                    data = self.decrypt_data(data, cipher)
                elif self.pkg_type == 0x02:  # PSP
                    cipher = AES.new(self.psp_aes_key, AES.MODE_ECB)
                    data = self.decrypt_data(data, cipher)

                output_stream.write(data)

        except Exception as e:
            logging.error(f"Error extracting file: {str(e)}")
            raise

    def read_file(self, file_id):
        """Legge un file dal PKG o dalla directory temporanea"""
        try:
            file_info = next((f for f in self.files.values() if f['id'] == file_id), None)
            if not file_info:
                raise ValueError(f"File ID {file_id} not found")

            # Se il file è già stato estratto, leggi direttamente dal filesystem
            if 'path' in file_info and os.path.exists(file_info['path']):
                with open(file_info['path'], 'rb') as f:
                    return f.read()

            # Altrimenti leggi e decripta dal PKG
            with open(self.original_file, 'rb') as pkg:
                pkg.seek(file_info['offset'])
                data = pkg.read(file_info['size'])
                
                # Decripta se necessario
                if self.pkg_type == 0x01:  # PS3
                    cipher = AES.new(self.ps3_aes_key, AES.MODE_ECB)
                    data = self.decrypt_data(file_info['size'], 
                                          file_info['offset'],
                                          self.ui_encrypted_file_start_offset,
                                          self.ps3_aes_key,
                                          pkg)
                elif self.pkg_type == 0x02:  # PSP
                    cipher = AES.new(self.psp_aes_key, AES.MODE_ECB)
                    data = self.decrypt_data(file_info['size'], 
                                          file_info['offset'],
                                          self.ui_encrypted_file_start_offset,
                                          self.psp_aes_key,
                                          pkg)

                return data

        except Exception as e:
            logging.error(f"Error reading file: {str(e)}")
            raise

    def get_file_data(self, file_info):
        """Ottiene i dati di un file dal PKG o dalla directory temporanea"""
        try:
            # Se il file è già stato estratto, leggi direttamente dal filesystem
            if 'path' in file_info and os.path.exists(file_info['path']):
                with open(file_info['path'], 'rb') as f:
                    return f.read()

            # Altrimenti leggi dal PKG
            return self.read_file(file_info['id'])

        except Exception as e:
            logging.error(f"Error getting file data: {str(e)}")
            raise

    def decrypt_data(self, data_size, data_relative_offset, pkg_encrypted_file_start_offset, aes_key, encr_pkg_read_stream):
        """Decripta i dati del PKG PS3"""
        # Calcola la dimensione corretta
        size = data_size
        if size % 16 > 0:
            size = ((data_size // 16) + 1) * 16

        encrypted_data = bytearray(size)
        decrypted_data = bytearray(size)
        pkg_file_key_consec = bytearray(size)
        inc_pkg_file_key = bytearray(self.pkg_file_key)

        # Posizionamento corretto
        encr_pkg_read_stream.seek(data_relative_offset + pkg_encrypted_file_start_offset)
        encrypted_data = encr_pkg_read_stream.read(size)

        # Incrementa la chiave per la posizione relativa
        for _ in range(data_relative_offset // 16):
            self.increment_array(inc_pkg_file_key, 15)

        # Genera la chiave consecutiva
        for pos in range(0, size, 16):
            pkg_file_key_consec[pos:pos + 16] = inc_pkg_file_key
            self.increment_array(inc_pkg_file_key, 15)

        # Cripta la chiave consecutiva
        cipher = AES.new(aes_key, AES.MODE_ECB)
        pkg_xor_key_consec = cipher.encrypt(bytes(pkg_file_key_consec))

        # XOR dei dati
        for pos in range(size):
            decrypted_data[pos] = encrypted_data[pos] ^ pkg_xor_key_consec[pos]

        return decrypted_data[:data_size]  # Ritorna solo i dati effettivi, senza padding

    def decrypt_pkg_data(self, data, cipher):
        """Decripta dati generici con AES"""
        if len(data) % 16 != 0:
            padding = 16 - (len(data) % 16)
            data += b'\0' * padding
        return cipher.decrypt(data)

    def increment_array(self, source_array, position):
        """Incrementa l'array per la generazione della chiave"""
        if source_array[position] == 0xFF:
            if position != 0:
                if self.increment_array(source_array, position - 1):
                    source_array[position] = 0x00
                    return True
                else:
                    return False
            else:
                return False
        else:
            source_array[position] += 0x01
            return True

    def extract_files(self, decrypted_pkg_file_name, output_dir):
        """Estrae i file dal PKG decriptato"""
        try:
            twenty_mb = 1024 * 1024 * 20
            
            with open(decrypted_pkg_file_name, "rb") as decr_pkg_read_stream:
                # Leggi la tabella dei file
                file_table = decr_pkg_read_stream.read(320000)
                first_name_offset = struct.unpack(">I", file_table[:4])[0]
                ui_file_nr = first_name_offset // 32
                uifirst_file_offset = struct.unpack(">I", file_table[12:16])[0]

                # Leggi la tabella dei file completa
                decr_pkg_read_stream.seek(0)
                file_table = decr_pkg_read_stream.read(uifirst_file_offset)

                if ui_file_nr < 0:
                    raise ValueError("Decryption error detected during file extraction")

                # Reset del dizionario files
                self.files.clear()

                for ii in range(ui_file_nr):
                    position_idx = ii * 32
                    extracted_file_offset = struct.unpack(">I", file_table[position_idx + 12:position_idx + 16])[0]
                    extracted_file_size = struct.unpack(">I", file_table[position_idx + 20:position_idx + 24])[0]
                    extracted_file_name_offset = struct.unpack(">I", file_table[position_idx:position_idx + 4])[0]
                    extracted_file_name_size = struct.unpack(">I", file_table[position_idx + 4:position_idx + 8])[0]
                    content_type = file_table[position_idx + 24]
                    file_type = file_table[position_idx + 27]

                    name = file_table[extracted_file_name_offset:extracted_file_name_offset + extracted_file_name_size]
                    
                    # Gestione corretta dei nomi dei file
                    if content_type == 0x90:
                        # File/directory PSP
                        extracted_file_name = self.byte_array_to_ascii(name, True)
                    else:
                        # File/directory PS3 - necessita decriptazione
                        decrypted_name = self.decrypt_data(extracted_file_name_size, 
                                                         extracted_file_name_offset,
                                                         self.ui_encrypted_file_start_offset,
                                                         self.ps3_aes_key,
                                                         open(self.original_file, "rb"))
                        extracted_file_name = self.byte_array_to_ascii(decrypted_name, True)

                    # Determina se è un file o una directory
                    is_file = not (file_type == 0x04 and extracted_file_size == 0x00)

                    try:
                        file_path = os.path.join(output_dir, extracted_file_name)
                        if not is_file:
                            os.makedirs(file_path, exist_ok=True)
                            # Aggiungi la directory al dizionario files
                            self.files[extracted_file_name] = {
                                'id': ii,
                                'name': extracted_file_name,
                                'offset': extracted_file_offset,
                                'size': 0,
                                'is_directory': True,
                                'content_type': content_type
                            }
                            continue

                        os.makedirs(os.path.dirname(file_path), exist_ok=True)
                        
                        # Aggiungi il file al dizionario files
                        self.files[extracted_file_name] = {
                            'id': ii,
                            'name': extracted_file_name,
                            'offset': extracted_file_offset,
                            'size': extracted_file_size,
                            'is_directory': False,
                            'content_type': content_type,
                            'path': file_path  # Aggiungi il percorso completo
                        }
                        
                        with open(file_path, "wb") as extracted_file_write_stream:
                            if content_type == 0x90:
                                # Copia diretta per file PSP
                                decr_pkg_read_stream.seek(extracted_file_offset)
                                remaining = extracted_file_size
                                while remaining > 0:
                                    chunk_size = min(twenty_mb, remaining)
                                    chunk = decr_pkg_read_stream.read(chunk_size)
                                    extracted_file_write_stream.write(chunk)
                                    remaining -= chunk_size
                            else:
                                # Decripta per file PS3
                                remaining = extracted_file_size
                                offset = 0
                                with open(self.original_file, "rb") as encr_pkg_read_stream:
                                    while remaining > 0:
                                        chunk_size = min(twenty_mb, remaining)
                                        decrypted_chunk = self.decrypt_data(chunk_size,
                                                                          extracted_file_offset + offset,
                                                                          self.ui_encrypted_file_start_offset,
                                                                          self.ps3_aes_key,
                                                                          encr_pkg_read_stream)
                                        extracted_file_write_stream.write(decrypted_chunk[:chunk_size])
                                        remaining -= chunk_size
                                        offset += chunk_size

                    except Exception as ex:
                        logging.error(f"Error processing {extracted_file_name}: {str(ex)}")
                        continue

                # Carica ICON0.PNG se presente
                icon_path = os.path.join(output_dir, 'ICON0.PNG')
                if os.path.exists(icon_path):
                    self.icon_path = icon_path
                    logging.info(f"Found ICON0.PNG at {icon_path}")

                # Carica EBOOT.BIN se presente
                eboot_path = os.path.join(output_dir, 'USRDIR', 'EBOOT.BIN')
                if os.path.exists(eboot_path):
                    self.eboot_path = eboot_path
                    logging.info(f"Found EBOOT.BIN at {eboot_path}")

                logging.info(f"Files extracted successfully. Total files: {len(self.files)}")
                return True

        except Exception as ex:
            logging.error(f"Error during file extraction: {str(ex)}")
            return False

    def byte_array_to_ascii(self, byte_array, clean_end_of_string):
        """Converte un array di bytes in una stringa ASCII"""
        try:
            hex_string = ''.join([f'{b:02X}' for b in byte_array])
            ascii_string = ''
            i = 0
            while i < len(hex_string):
                try:
                    char_code = int(hex_string[i:i+2], 16)
                    if clean_end_of_string and char_code == 0:
                        break
                    ascii_string += chr(char_code)
                except:
                    pass
                i += 2
            return ascii_string.rstrip('\0')
        except:
            return f"unnamed_file_{binascii.hexlify(byte_array[:4]).decode()}"

    def dump(self, output_dir):
        """Extract all files from the PKG to the specified directory"""
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            # Decripta il PKG se necessario
            decrypted_pkg = self.decrypt_pkg_file(self.original_file)
            if not decrypted_pkg:
                raise ValueError("Failed to decrypt PKG")

            # Estrai i file
            success = self.extract_files(decrypted_pkg, output_dir)
            if not success:
                raise ValueError("Failed to extract files")

            # Copia i file dalla directory temporanea alla directory di output
            if os.path.exists(self.temp_dir) and output_dir != self.temp_dir:
                for root, dirs, files in os.walk(self.temp_dir):
                    for file in files:
                        src_path = os.path.join(root, file)
                        rel_path = os.path.relpath(src_path, self.temp_dir)
                        dst_path = os.path.join(output_dir, rel_path)
                        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                        shutil.copy2(src_path, dst_path)

            # Verifica la presenza di ICON0.PNG e EBOOT.BIN
            icon_path = os.path.join(output_dir, 'ICON0.PNG')
            if os.path.exists(icon_path):
                logging.info(f"ICON0.PNG extracted to: {icon_path}")

            eboot_path = os.path.join(output_dir, 'USRDIR', 'EBOOT.BIN')
            if os.path.exists(eboot_path):
                logging.info(f"EBOOT.BIN extracted to: {eboot_path}")

            return f"Package extracted successfully to: {output_dir}"

        except Exception as e:
            logging.error(f"Error during package dump: {str(e)}")
            raise ValueError(f"Error during package dump: {str(e)}")

