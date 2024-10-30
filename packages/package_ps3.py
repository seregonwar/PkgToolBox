import os
import struct
import binascii
from Crypto.Cipher import AES
import logging
from PIL import Image
import io
from .package_base import PackageBase
import shutil
import subprocess
import time
import datetime
import sys

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
            self.extracted_files = {}
            self.is_ready = False
            self.extraction_complete = False
            self._cleanup_lock = False
            self._closed = False
            
            # Crea directory temporanea in AppData/Local con timestamp
            appdata_local = os.getenv('LOCALAPPDATA')
            base_temp_dir = os.path.join(appdata_local, "PkgToolBox", "temp_output")
            os.makedirs(base_temp_dir, exist_ok=True)
            
            # Crea una nuova directory con timestamp
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            self.temp_dir = os.path.join(base_temp_dir, f"pkg_{timestamp}")
            
            # Pulisci le vecchie directory temporanee
            self._cleanup_old_temp_dirs(base_temp_dir)
            
            # Crea la nuova directory temporanea
            os.makedirs(self.temp_dir, exist_ok=True)
            logging.info(f"Created new temporary directory: {self.temp_dir}")
            
            # Carica le informazioni di base
            self.load_pkg_info()
            
            # Avvia l'estrazione e attendi il completamento
            self.extract_and_wait()
            
        except Exception as e:
            logging.error(f"Error initializing PackagePS3: {str(e)}")
            raise

    def __del__(self):
        """Cleanup solo quando l'oggetto viene effettivamente distrutto"""
        self.close()

    def close(self):
        """Explicit cleanup method"""
        if not self._closed:
            try:
                if (hasattr(self, 'extraction_complete') and self.extraction_complete and 
                    not self._cleanup_lock and hasattr(self, 'temp_dir')):
                    if os.path.exists(self.temp_dir):
                        try:
                            self._cleanup_lock = True
                            # Salva i contenuti importanti prima della pulizia
                            self._cache_important_files()
                            # Non eliminiamo la directory qui, verrà eliminata quando creiamo una nuova
                            logging.info("Package closed")
                        finally:
                            self._cleanup_lock = False
                self._closed = True
            except Exception as e:
                logging.error(f"Error in close: {str(e)}")

    def _cache_important_files(self):
        """Cache important files before cleanup"""
        try:
            for file_info in self.files.values():
                if not file_info.get('content'):  # Se il contenuto non è già in cache
                    if file_info['size'] < 1024*1024 or file_info['name'].lower().endswith(('.png', '.jpg', '.jpeg')):
                        try:
                            with open(file_info['path'], 'rb') as f:
                                file_info['content'] = f.read()
                        except Exception as e:
                            logging.error(f"Error caching file {file_info['name']}: {str(e)}")
        except Exception as e:
            logging.error(f"Error in _cache_important_files: {str(e)}")

    def decrypt_and_extract(self, progress=None):
        """Decripta il PKG ed estrae i file usando Ps3DebugLib.exe"""
        try:
            if getattr(sys, 'frozen', False):
                # Se l'app è "frozen" (compilata con PyInstaller)
                base_path = sys._MEIPASS
            else:
                # Se l'app è in esecuzione da script
                base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                
            ps3lib_path = os.path.join(base_path, "packages", "ps3lib", "Ps3DebugLib.exe")
            
            if not os.path.exists(ps3lib_path):
                logging.error(f"Ps3DebugLib.exe not found at: {ps3lib_path}")
                raise FileNotFoundError(f"Ps3DebugLib.exe not found at: {ps3lib_path}")

            # Crea directory di output nel temp_dir
            self.output_dir = os.path.join(self.temp_dir, "pkg_files")
            os.makedirs(self.output_dir, exist_ok=True)

            # Costruisci il comando
            cmd = [ps3lib_path, "-o", self.output_dir, self.original_file]

            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Monitora l'output
                for line in process.stdout:
                    line = line.strip()
                    if "%" in line and progress:
                        try:
                            progress_str = line.split('%')[0].strip().split()[-1]
                            current_progress = int(progress_str)
                            progress.setValue(current_progress)
                        except:
                            pass

                process.wait()
                
                if process.returncode != 0:
                    error = process.stderr.read()
                    raise RuntimeError(f"Ps3DebugLib.exe failed with error: {error}")

                # Aggiorna la lista dei file
                self.files = {}
                for root, _, files in os.walk(self.output_dir):
                    for file in sorted(files):
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, self.output_dir)
                        file_size = os.path.getsize(file_path)
                        
                        # Leggi subito il contenuto per file piccoli o immagini
                        if file_size < 1024*1024 or file.lower().endswith(('.png', '.jpg', '.jpeg')):
                            with open(file_path, 'rb') as f:
                                content = f.read()
                        else:
                            content = None
                            
                        self.files[relative_path] = {
                            'id': len(self.files),
                            'name': relative_path,
                            'size': file_size,
                            'path': file_path,
                            'content': content
                        }

                if progress:
                    progress.setValue(100)

            except subprocess.SubprocessError as e:
                logging.error(f"Error executing Ps3DebugLib.exe: {str(e)}")
                raise RuntimeError(f"Error executing Ps3DebugLib.exe: {str(e)}")

        except Exception as e:
            logging.error(f"Error in decrypt_and_extract: {str(e)}")
            raise

    def _decrypt_retail_pkg(self, pkg_file_name):
        """Mantiene la logica esistente per PKG retail"""
   

    def get_info(self):
        """Restituisce le informazioni del pacchetto in un formato leggibile"""
        info = {}
        
  
        is_retail = self.pkg_type == 0x01
        
        if not is_retail:
            info.update({
                "Package Type": "Debug PKG",
                "Content ID": self.content_id,
                "Title ID": getattr(self, 'title_id', 'Unknown'),
                "Total Size": f"{self.total_size:,} bytes ({self.total_size / (1024*1024*1024):.2f} GB)",
                "File Count": len(self.files),
                "Package Version": getattr(self, 'package_version', 'Unknown'),
                "System Version": getattr(self, 'system_version', 'Unknown'),
                "App Version": getattr(self, 'app_version', 'Unknown'),
                "NPDRM Type": getattr(self, 'drm_type', 'Unknown'),
                "Content Type": getattr(self, 'content_type', 'Unknown'),
                "Package Flag": getattr(self, 'package_flag', 'Unknown'),
                "Package Size": f"{self.package_size:,} bytes ({self.package_size / (1024*1024*1024):.2f} GB)",
                "Data Offset": f"0x{getattr(self, 'data_offset', 0):X}",
                "Data Size": f"{getattr(self, 'data_size', 0):,} bytes",
                "Metadata Offset": f"0x{getattr(self, 'pkg_metadata_offset', 0):X}",
                "Metadata Count": getattr(self, 'pkg_metadata_count', 0),
                "Metadata Size": getattr(self, 'pkg_metadata_size', 0),
                "Header Digest": getattr(self, 'pkg_header_digest', 'Unknown'),
                "Data RIV": getattr(self, 'pkg_data_riv', 'Unknown'),
                "Install Directory": getattr(self, 'install_directory', 'Unknown'),
                "Is Debug": "Yes"
            })
        else:
            info.update({
                "Package Type": f"Retail PKG (0x{self.pkg_type:04X})",
                "Package Revision": f"0x{self.pkg_revision:04X}",
                "Content ID": self.content_id,
                "Title ID": getattr(self, 'title_id', 'Unknown'),
                "Total Size": f"{self.total_size:,} bytes ({self.total_size / (1024*1024*1024):.2f} GB)",
                "File Count": len(self.files),
                "Package Version": f"0x{getattr(self, 'package_version', 0):04X}",
                "System Version": f"0x{getattr(self, 'system_version', 0):08X}",
                "App Version": getattr(self, 'app_version', 'Unknown'),
                "NPDRM Type": f"0x{getattr(self, 'drm_type', 0):08X}",
                "Content Type": f"0x{getattr(self, 'content_type', 0):08X}",
                "Package Flag": f"0x{getattr(self, 'package_flag', 0):04X}",
                "Package Size": f"{self.package_size:,} bytes ({self.package_size / (1024*1024*1024):.2f} GB)",
                "Data Offset": f"0x{getattr(self, 'data_offset', 0):X}",
                "Data Size": f"{getattr(self, 'data_size', 0):,} bytes",
                "Metadata Offset": f"0x{getattr(self, 'pkg_metadata_offset', 0):X}",
                "Metadata Count": getattr(self, 'pkg_metadata_count', 0),
                "Metadata Size": getattr(self, 'pkg_metadata_size', 0),
                "Header Digest": getattr(self, 'pkg_header_digest', 'Unknown'),
                "Data RIV": getattr(self, 'pkg_data_riv', 'Unknown'),
                "Install Directory": getattr(self, 'install_directory', 'Unknown'),
                "Is Debug": "No"
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
        """Legge un file dal PKG"""
        try:
            if not self.extraction_complete:
                raise RuntimeError("Package extraction not completed yet")

            if self._cleanup_lock:
                raise RuntimeError("Package is being extracted")

            file_info = next((f for f in self.files.values() if f['id'] == file_id), None)
            if not file_info:
                raise ValueError(f"File ID {file_id} not found")

            # Se il contenuto è già in cache, restituiscilo
            if 'content' in file_info and file_info['content'] is not None:
                return file_info['content']
            
            # Altrimenti leggi il file da disco
            if 'path' in file_info and os.path.exists(file_info['path']):
                with open(file_info['path'], 'rb') as f:
                    content = f.read()
                    # Cache il contenuto per file piccoli o immagini
                    if file_info['size'] < 1024*1024 or file_info['name'].lower().endswith(('.png', '.jpg', '.jpeg')):
                        file_info['content'] = content
                    return content

            raise FileNotFoundError(f"File content not found for ID {file_id}")

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
            
            # Modifica il modo in cui otteniamo il percorso di Ps3DebugLib.exe
            if getattr(sys, 'frozen', False):
                # Se l'app è "frozen" (compilata con PyInstaller)
                base_path = sys._MEIPASS
            else:
                # Se l'app è in esecuzione da script
                base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                
            ps3lib_path = os.path.join(base_path, "packages", "ps3lib", "Ps3DebugLib.exe")
            
            if not os.path.exists(ps3lib_path):
                logging.error(f"Ps3DebugLib.exe not found at: {ps3lib_path}")
                raise FileNotFoundError(f"Ps3DebugLib.exe not found at: {ps3lib_path}")

            # Costruisci il comando
            cmd = [ps3lib_path, "-o", output_dir, self.original_file]

            # Crea una progress bar usando QProgressDialog
            from PyQt5.QtWidgets import QProgressDialog
            from PyQt5.QtCore import Qt
            progress = QProgressDialog("Extracting PKG...", None, 0, 100)
            progress.setWindowModality(Qt.WindowModal)
            progress.setWindowTitle("Extracting")
            progress.setMinimumDuration(0)
            progress.setValue(0)
            progress.show()

            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Monitora l'output
                for line in process.stdout:
                    line = line.strip()
                    
                    if "%" in line:
                        try:
                            progress_str = line.split('%')[0].strip().split()[-1]
                            current_progress = int(progress_str)
                            progress.setValue(current_progress)
                        except:
                            pass
                
                # Attendi il completamento
                process.wait()
                
                if process.returncode != 0:
                    error = process.stderr.read()
                    raise RuntimeError(f"Ps3DebugLib.exe failed with error: {error}")

                # Aggiorna la lista dei file
                self.files = {}
                for root, _, files in os.walk(output_dir):
                    for file in sorted(files):
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, output_dir)
                        
                        file_size = os.path.getsize(file_path)
                        self.files[relative_path] = {
                            'id': len(self.files),
                            'name': relative_path,
                            'size': file_size,
                            'path': file_path
                        }

                progress.setValue(100)
                return f"Package extracted successfully to: {output_dir}"

            except subprocess.SubprocessError as e:
                logging.error(f"Error executing Ps3DebugLib.exe: {str(e)}")
                raise RuntimeError(f"Error executing Ps3DebugLib.exe: {str(e)}")
            finally:
                progress.close()

        except Exception as e:
            logging.error(f"Error during package dump: {str(e)}")
            raise ValueError(f"Error during package dump: {str(e)}")

    def extract_and_wait(self):
        """Estrae i file e attendi il completamento"""
        try:
            # Crea una progress bar usando QProgressDialog
            from PyQt5.QtWidgets import QProgressDialog
            from PyQt5.QtCore import Qt
            progress = QProgressDialog("Extracting PKG...", None, 0, 100)
            progress.setWindowModality(Qt.WindowModal)
            progress.setWindowTitle("Extracting")
            progress.setMinimumDuration(0)
            progress.setValue(0)
            progress.show()

            try:
                # Blocca il cleanup durante l'estrazione
                self._cleanup_lock = True
                
                # Esegui l'estrazione
                self.decrypt_and_extract(progress)
                
                # Attendi un momento per assicurarsi che tutti i file siano scritti
                time.sleep(0.5)
                
                # Imposta i flag quando l'estrazione è completata
                self.is_ready = True
                self.extraction_complete = True
                logging.info("PS3 PKG file loaded.")
                
            except Exception as e:
                logging.error(f"Error during extraction: {str(e)}")
                raise
            finally:
                progress.close()
                self._cleanup_lock = False  # Sblocca il cleanup

        except Exception as e:
            logging.error(f"Error in extract_and_wait: {str(e)}")
            raise

    def _cleanup_old_temp_dirs(self, base_dir):
        """Pulisce le vecchie directory temporanee"""
        try:
            # Mantieni solo le ultime 2 directory
            dirs = [os.path.join(base_dir, d) for d in os.listdir(base_dir) 
                   if os.path.isdir(os.path.join(base_dir, d))]
            dirs.sort(key=lambda x: os.path.getctime(x), reverse=True)
            
            # Rimuovi tutte le directory eccetto le ultime 2
            for old_dir in dirs[2:]:
                try:
                    shutil.rmtree(old_dir)
                    logging.info(f"Cleaned old temporary directory: {old_dir}")
                except Exception as e:
                    logging.error(f"Error cleaning old directory {old_dir}: {str(e)}")
        except Exception as e:
            logging.error(f"Error during cleanup of old directories: {str(e)}")