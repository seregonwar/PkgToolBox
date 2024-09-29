from cmath import e
import os
import hashlib
from Crypto.Cipher import AES
import struct
import re
import xml.etree.ElementTree as ET
from .Archiver import Archiver  # Modifica questa riga

class TRPHeader:
    def __init__(self):
        self.magic = None
        self.version = None
        self.file_size = None
        self.files_count = None
        self.element_size = None
        self.dev_flag = None
        self.sha1 = None
        self.padding = None

class TRPReader:
    def __init__(self, file_path=None):
        self._inputfile = file_path
        self._hdr = TRPHeader()
        self._trophyList = []
        self._hdrmagic = bytes([220, 162, 77, 0])
        self._throwerror = True
        self._iserror = False
        self._calculatedsha1 = None
        self._title = None  
        self._npcommid = None  

    TROPHY_KEY = bytes([0x21, 0xF4, 0x1A, 0x6B, 0xAD, 0x8A, 0x1D, 0x3E, 
                        0xCA, 0x7A, 0xD5, 0x86, 0xC1, 0x01, 0xB7, 0xA9])

    @staticmethod
    def aes_encrypt_cbc(key, iv, data):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(data)

    @staticmethod
    def aes_decrypt_cbc(key, iv, data):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(data)

    def generate_key(self, np_comm_id):
        if not np_comm_id or len(np_comm_id) > 16:
            print("Warning: Invalid NPCOMMID. Using default key.")
            np_comm_id = "NPWR00000_00"
        padded_id = np_comm_id.encode('ascii').ljust(16, b'\x00')
        return self.aes_encrypt_cbc(self.TROPHY_KEY, b'\x00' * 16, padded_id)

    def byte_arrays_equal(self, first, second):
        return first == second

    def load(self, filename=None):
        try:
            if filename:
                self._inputfile = filename
            elif not self._inputfile:
                raise ValueError("No file specified. Please provide a filename.")
            
            with open(self._inputfile, "rb") as file:
                self.read_header(file)
                
                if not self.byte_arrays_equal(self._hdr.magic, self._hdrmagic):
                    print("Warning: This file may not be a valid TRP file. Attempting to continue...")
                
                self.read_content(file)
                if self._hdr.version > 1:
                    self._calculatedsha1 = self.calculate_sha1_hash()
            
            # Verify file integrity by comparing SHA1
            if self._hdr.version > 1:
                print(f"Calculated SHA1: {self._calculatedsha1}")
                print(f"Header SHA1: {self._hdr.sha1.hex().upper()}")
                if self._calculatedsha1 != self._hdr.sha1.hex().upper():
                    print("Warning: SHA1 mismatch. The file might be corrupted.")
            
            print("Extracting title...")
            self._title = self.extract_title()
            print("Extracting NPCOMMID...")
            self._npcommid = self.extract_npcommid()
            print("Getting trophies...")
            self.get_trophies()
            print("Extracting trophy images...")
            self.extract_trophy_images()
            print("Decrypting and saving SFM files...")
            self.decrypt_and_save_sfm(os.path.join(os.path.dirname(self._inputfile), "decrypted_sfm"))
        except Exception as ex:
            self._iserror = True
            self._error = str(ex)
            print(f"Error during loading: {self._error}")
        
        # Attempt to repair and extract files even if there were errors
        print("Attempting to repair and extract...")
        self.repair_and_extract()

    def read_header(self, file):
        self._hdr.magic = file.read(4)
        self._hdr.version = int.from_bytes(file.read(4), byteorder='big')
        self._hdr.file_size = int.from_bytes(file.read(8), byteorder='big')
        self._hdr.files_count = int.from_bytes(file.read(4), byteorder='big')
        self._hdr.element_size = int.from_bytes(file.read(4), byteorder='big')
        self._hdr.dev_flag = int.from_bytes(file.read(4), byteorder='big')
        
        # Verifica e correzione dei valori non validi
        if self._hdr.version not in [1, 2, 3]:
            print(f"Warning: Invalid version {self._hdr.version}. Setting to 3.")
            self._hdr.version = 3
        
        actual_file_size = os.path.getsize(self._inputfile)
        if self._hdr.file_size != actual_file_size:
            print(f"Warning: File size mismatch. Header: {self._hdr.file_size}, Actual: {actual_file_size}")
            self._hdr.file_size = actual_file_size
        
        if self._hdr.files_count > 1000 or self._hdr.files_count <= 0:  # Un limite arbitrario, ma ragionevole
            print(f"Warning: Invalid file count {self._hdr.files_count}. Setting to 0.")
            self._hdr.files_count = 0
        
        if self._hdr.element_size not in [32, 64]:  # Valori tipici
            print(f"Warning: Unusual element size {self._hdr.element_size}. Setting to 64.")
            self._hdr.element_size = 64
        
        print(f"TRP Version: {self._hdr.version}")
        print(f"File size: {self._hdr.file_size}")
        print(f"Files count: {self._hdr.files_count}")
        print(f"Element size: {self._hdr.element_size}")
        print(f"Dev flag: {self._hdr.dev_flag}")
        
        if self._hdr.version > 1:
            self._hdr.sha1 = file.read(20)
            self._hdr.padding = file.read(48 if self._hdr.version == 3 else 16)
        else:
            self._hdr.padding = file.read(36)

    def repair_header(self):
        with open(self._inputfile, "rb+") as file:
            actual_size = os.path.getsize(self._inputfile)
            
            # Correct the version if invalid
            if self._hdr.version not in [1, 2, 3]:
                self._hdr.version = 3  # Set version to 3 as default
                file.seek(4)
                file.write(self._hdr.version.to_bytes(4, byteorder='little'))
            
            # Correct the file size
            file.seek(4)
            file.write(self._hdr.version.to_bytes(4, byteorder='big'))
            
            file.seek(8)
            file.write(actual_size.to_bytes(8, byteorder='big'))
            
            file.seek(20)
            file.write(estimated_file_count.to_bytes(4, byteorder='big'))
            file.write((64).to_bytes(4, byteorder='big'))
            
            # Correct the file count and element size
            estimated_file_count = min(len(self._trophyList), 255)  # Limit to a maximum of 255 files
            file.seek(20)
            file.write(estimated_file_count.to_bytes(4, byteorder='little'))
            file.write((64).to_bytes(4, byteorder='little'))  # Standard element size
            
            # Recalculate and update SHA1 if necessary
            if self._hdr.version > 1:
                file.seek(0)
                data = file.read()
                calculated_data = data[:28] + b'\x00'*20 + data[48:]
                new_sha1 = hashlib.sha1(calculated_data).digest()
                file.seek(28)
                file.write(new_sha1)

        print("Header repaired.")
        
        # Reread the header after repair
        with open(self._inputfile, "rb") as file:
            self.read_header(file)

    def repair_and_extract(self):
        output_path = os.path.join(os.path.dirname(self._inputfile), "repaired_trophies")
        if not os.path.exists(output_path):
            os.makedirs(output_path)
        
        for trophy in self._trophyList:
            try:
                with open(self._inputfile, "rb") as file:
                    file.seek(trophy.Offset)
                    data = file.read(trophy.Size)
                    
                    # Basic verification and repair
                    if len(data) != trophy.Size:
                        print(f"Warning: Size mismatch for {trophy.Name}. Expected: {trophy.Size}, Actual: {len(data)}")
                        # Padding with zeros if the file is shorter than expected
                        data = data.ljust(trophy.Size, b'\0')
                    
                    # Here you could add further checks and repairs specific to file type
                    
                    output_file = os.path.join(output_path, trophy.Name)
                    with open(output_file, "wb") as out_file:
                        out_file.write(data)
                    print(f"Extracted and potentially repaired: {trophy.Name}")
            except Exception as e:
                print(f"Error processing {trophy.Name}: {str(e)}")

    def read_content(self, file):
        expected_count = self._hdr.files_count
        if expected_count <= 0 or expected_count > 1000:
            print(f"Warning: Invalid file count {expected_count}. Attempting to read content anyway.")
            expected_count = 1000  # Impostiamo un limite massimo arbitrario
        
        for _ in range(expected_count):
            try:
                raw_name = file.read(36)
                if not raw_name:
                    print("Reached end of file. Stopping content reading.")
                    break
                name = raw_name.decode("utf-8", errors='ignore').strip("\x00")
                name = re.sub(r'[^\w\-_\. ]', '_', name)  # Replace invalid characters with underscore
                
                raw_offset = file.read(4)
                offset = int.from_bytes(raw_offset, byteorder="big")
            
                raw_size = file.read(8)
                size = int.from_bytes(raw_size, byteorder="big")
                
                file.seek(12, os.SEEK_CUR)  # Skip padding
                
                # Basic verification for offset and size
                if offset < 0 or size < 0 or offset + size > os.path.getsize(self._inputfile):
                    print(f"Warning: Invalid offset or size for {name}. Skipping.")
                    continue
                
                self._trophyList.append(Archiver(_, name, offset, size, None))
                print(f"Read trophy: {name}, offset: {offset}, size: {size}")
            except Exception as e:
                print(f"Error reading trophy entry: {str(e)}")
                break  # Stop reading if we encounter an error
        
        print(f"Actually read {len(self._trophyList)} trophy entries.")

    def byte_to_int(self, b):
        return int.from_bytes(b, byteorder="big")  # Changed from 'little' to 'big'

    def byte_to_long(self, b):
        return int.from_bytes(b, byteorder="big")  # Changed from 'little' to 'big'

    def file_count(self):
        return self.byte_to_int(self._hdr.files_count)

    def version(self):
        return self.byte_to_int(self._hdr.version)

    def calculate_sha1_hash(self):
        with open(self._inputfile, "rb") as file:
            data = file.read()
            if self.version() > 1:
                # Remove the 20 bytes of SHA1 from the header to calculate the hash correctly
                calculated_data = data[:28] + b'\x00'*20 + data[48:]
                sha1 = hashlib.sha1(calculated_data).hexdigest().upper()
                print(f"Calculated SHA1 from data: {sha1}")  # Debug
                print(f"First 100 bytes of calculated_data: {calculated_data[:100].hex()}")  # Debug
                return sha1
            return None

    def extract(self, output_path):
        if not os.path.exists(output_path):
            os.makedirs(output_path)
        for trophy in self._trophyList:
            with open(self._inputfile, "rb") as file:
                file.seek(trophy.Offset)
                data = file.read(trophy.Size)
                with open(os.path.join(output_path, trophy.Name), "wb") as output_file:
                    output_file.write(data)

    def extract_file(self, filename, output_path, custom_name=None):
        trophy = next((t for t in self._trophyList if t.Name.upper() == filename.upper()), None)
        if trophy:
            with open(self._inputfile, "rb") as file:
                file.seek(trophy.Offset)
                data = file.read(trophy.Size)
                if not os.path.exists(output_path):
                    os.makedirs(output_path)
                with open(os.path.join(output_path, custom_name or trophy.Name), "wb") as output_file:
                    output_file.write(data)

    def hex_string_to_long(self, hex_str):
        return int(hex_str, 16)

    @staticmethod
    def byte_array_to_utf8_string(byte_array, errors='replace'):
        return byte_array.decode('utf-8', errors=errors)

    def extract_title(self):
        # Try to extract the title from the TROPCONF.SFM or TROPCONF.ESFM file
        for trophy in self._trophyList:
            if trophy.Name.upper().startswith("TROPCONF"):
                with open(self._inputfile, "rb") as file:
                    file.seek(trophy.Offset)
                    data = file.read(trophy.Size)
                    
                    # Look for the title in the file
                    title_start = data.find(b"<title>") + len(b"<title>")
                    title_end = data.find(b"</title>")
                    if title_start != -1 and title_end != -1:
                        title = data[title_start:title_end].decode('utf-8', errors='replace')
                        return title.strip()
        return "Unknown Title"

    def get_title(self):
        return self._title

    def extract_npcommid(self):
        # Try to extract the NPCOMMID from the TROPCONF.SFM or TROPCONF.ESFM file
        for trophy in self._trophyList:
            if trophy.Name.upper().startswith("TROPCONF"):
                with open(self._inputfile, "rb") as file:
                    file.seek(trophy.Offset)
                    data = file.read(trophy.Size)
                    
                    # Look for the NPCOMMID in the file
                    npcommid_start = data.find(b"<npcommid>") + len(b"<npcommid>")
                    npcommid_end = data.find(b"</npcommid>")
                    if npcommid_start != -1 and npcommid_end != -1:
                        npcommid = data[npcommid_start:npcommid_end].decode('utf-8', errors='replace')
                        return npcommid.strip()
        return "NPWR00000_00"  # Default value if not found

    def get_npcommid(self):
        return self._npcommid

    def extract_trophy_images(self):
        output_path = os.path.join(os.path.dirname(self._inputfile), "trophy_images")
        if not os.path.exists(output_path):
            os.makedirs(output_path)
        
        for trophy in self._trophyList:
            if trophy.Name.upper().endswith('.PNG'):
                try:
                    with open(self._inputfile, "rb") as file:
                        file.seek(trophy.Offset)
                        encrypted_data = file.read(trophy.Size)
                        
                        # AES decryption
                        if len(encrypted_data) >= 32:  # Ensure we have enough data for IV and at least one block
                            iv = encrypted_data[:16]
                            data = encrypted_data[16:]
                            
                            # Ensure data is aligned to 16 bytes
                            padding_length = 16 - (len(data) % 16)
                            if padding_length < 16:
                                data += b'\x00' * padding_length
                            
                            key = self.generate_key(self._npcommid)
                            try:
                                decrypted_data = self.aes_decrypt_cbc(key, iv, data)
                                # Remove added padding
                                decrypted_data = decrypted_data[:trophy.Size - 16]
                            except Exception as e:
                                print(f"Decryption failed for {trophy.Name}: {str(e)}. Saving raw data.")
                                decrypted_data = encrypted_data
                        else:
                            print(f"Not enough data to decrypt {trophy.Name}. Saving raw data.")
                            decrypted_data = encrypted_data
                        
                        output_file = os.path.join(output_path, trophy.Name)
                        with open(output_file, "wb") as out_file:
                            out_file.write(decrypted_data)
                        print(f"Extracted trophy image: {trophy.Name}")
                except Exception as e:
                    print(f"Error extracting {trophy.Name}: {str(e)}")

    def decrypt_and_save_sfm(self, output_path):
        if not os.path.exists(output_path):
            os.makedirs(output_path)
        
        for trophy in self._trophyList:
            if trophy.Name.upper().endswith('.SFM') or trophy.Name.upper().endswith('.ESFM'):
                try:
                    with open(self._inputfile, "rb") as file:
                        file.seek(trophy.Offset)
                        data = file.read(trophy.Size)
                        
                        if trophy.Name.upper().endswith('.ESFM'):
                            # Decrypt ESFM
                            if len(data) >= 32:
                                iv = data[:16]
                                encrypted_data = data[16:]
                                
                                # Ensure data is aligned to 16 bytes
                                padding_length = 16 - (len(encrypted_data) % 16)
                                if padding_length < 16:
                                    encrypted_data += b'\x00' * padding_length
                                
                                key = self.generate_key(self._npcommid)
                                try:
                                    decrypted_data = self.aes_decrypt_cbc(key, iv, encrypted_data)
                                    # Remove added padding
                                    decrypted_data = decrypted_data[:trophy.Size - 16]
                                except Exception as e:
                                    print(f"Decryption failed for {trophy.Name}: {str(e)}. Saving raw data.")
                                    decrypted_data = data
                            else:
                                print(f"Not enough data to decrypt {trophy.Name}. Saving raw data.")
                                decrypted_data = data
                        else:
                            decrypted_data = data
                        
                        # Save the decrypted file
                        output_file = os.path.join(output_path, trophy.Name.replace('.ESFM', '.SFM'))
                        with open(output_file, "wb") as out_file:
                            out_file.write(decrypted_data)
                        print(f"Decrypted and saved: {output_file}")
                except Exception as e:
                    print(f"Error processing {trophy.Name}: {str(e)}")

    def decrypt_esfm(self, data):
        if len(data) < 16:
            return data  # Not enough data to decrypt

        iv = data[:16]
        encrypted_data = data[16:]
        key = self.generate_key(self._npcommid)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)

        # Remove PKCS7 padding
        padding_length = decrypted_data[-1]
        return decrypted_data[:-padding_length]

    def get_icon(self):
        for trophy in self._trophyList:
            if trophy.Name.upper() == "ICON0.PNG":
                with open(self._inputfile, "rb") as file:
                    file.seek(trophy.Offset)
                    icon_data = file.read(trophy.Size)
                    return icon_data
        return None

    def get_trophies(self):
        trophies = []
        for trophy in self._trophyList:
            if trophy.Name.upper().endswith('.SFM') or trophy.Name.upper().endswith('.ESFM'):
                try:
                    with open(self._inputfile, "rb") as file:
                        file.seek(trophy.Offset)
                        data = file.read(trophy.Size)
                    
                    if trophy.Name.upper().endswith('.ESFM'):
                        data = self.decrypt_esfm(data)
                    
                    root = ET.fromstring(data)
                    for trophy_elem in root.findall('.//trophy'):
                        trophy_info = {
                            'id': trophy_elem.get('id'),
                            'hidden': trophy_elem.get('hidden') == 'yes',
                            'type': trophy_elem.get('ttype'),
                            'name': trophy_elem.find('name').text if trophy_elem.find('name') is not None else 'Unknown',
                            'detail': trophy_elem.find('detail').text if trophy_elem.find('detail') is not None else 'No details'
                        }
                        trophies.append(trophy_info)
                except ET.ParseError as e:
                    print(f"Error parsing XML for {trophy.Name}: {str(e)}")
                except Exception as e:
                    print(f"Error processing trophy {trophy.Name}: {str(e)}")
        return trophies