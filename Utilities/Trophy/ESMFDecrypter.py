import os
import re
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import xml.etree.ElementTree as ET
import requests
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ESMFDecrypter:
    def __init__(self):
        self.trophy_key = bytes([
            0x21, 0xF4, 0x1A, 0x6B, 0xAD, 0x8A, 0x1D, 0x3E,
            0xCA, 0x7A, 0xD5, 0x86, 0xC1, 0x01, 0xB7, 0xA9
        ])
        self.valid_np_com_ids = []

    def decrypt_esfm_file(self, file_path, np_com_id, output_folder):
        logger.info(f"Starting decryption of file: {file_path}")
        
        iv = bytes([0] * 16)
        cipher = AES.new(self.trophy_key, AES.MODE_CBC, iv)
        key = cipher.encrypt(np_com_id.ljust(16, '\0').encode())

        with open(file_path, 'rb') as file:
            encrypted_data = file.read()

        total_size = len(encrypted_data)
        chunk_size = AES.block_size

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = bytearray()
        for i in range(0, total_size, chunk_size):
            chunk = encrypted_data[i:i + chunk_size]
            decrypted_chunk = cipher.decrypt(chunk)
            decrypted_data.extend(decrypted_chunk)
            logger.debug(f"Decrypted {i + chunk_size} of {total_size} bytes")
        
        decrypted_data = unpad(decrypted_data, AES.block_size)
        decrypted_data = ''.join(chr(byte) for byte in decrypted_data if 32 <= byte <= 126 or byte in (9, 10, 13))

        try:
            decrypted_xml = ET.fromstring(decrypted_data)
            logger.info("XML decrypted and parsed successfully")
        except ET.ParseError as e:
            logger.error(f"Error parsing decrypted XML: {e}")
            return None

        output_file_path = os.path.join(output_folder, os.path.basename(file_path)[:-5] + ".xml")
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            output_file.write(decrypted_data)

        logger.info(f"Decrypted file saved to: {output_file_path}")
        return output_file_path

    @staticmethod
    def validate_np_com_id(np_com_id):
        return re.match(r'^NPWR\d{5}_\d{2}$', np_com_id) is not None

    def brute_force_np_com_ids(self, start=1, end=25000, delay=1):
        base_url = "https://m.np.playstation.com/api/trophy/v1/npCommunicationIds/{}/trophyGroups"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }

        for i in range(start, end + 1):
            np_com_id = f"NPWR{i:05d}_00"
            url = base_url.format(np_com_id)
            
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    title_name = data.get('trophyTitleName', 'Unknown')
                    logger.info(f"Valid NP Communication ID found: {np_com_id} - {title_name}")
                    self.valid_np_com_ids.append((np_com_id, title_name))
                else:
                    logger.debug(f"Invalid or non-existent NP Communication ID: {np_com_id}")
            except Exception as e:
                logger.error(f"Error checking NP Communication ID {np_com_id}: {str(e)}")
            
            time.sleep(delay)  

        logger.info(f"Brute force completed. Found {len(self.valid_np_com_ids)} valid NP Communication IDs.")
        return self.valid_np_com_ids

def decrypt_esfm_file(file_path, np_com_id, output_folder):
    decrypter = ESMFDecrypter()
    if not decrypter.validate_np_com_id(np_com_id):
        logger.error("Invalid NP communication ID. Correct format: NPWRYYYYY_ZZ")
        return None
    return decrypter.decrypt_esfm_file(file_path, np_com_id, output_folder)

if __name__ == "__main__":
    decrypter = ESMFDecrypter()
    valid_ids = decrypter.brute_force_np_com_ids(start=1, end=100)  
    
    for np_com_id, title_name in valid_ids:
        print(f"NP Communication ID: {np_com_id} - Title: {title_name}")

  
    file_path = input("Enter the path of the ESFM file: ")
    output_folder = input("Enter the output folder: ")
    np_com_id = input("Enter the NP communication ID (format: NPWRYYYYY_ZZ): ")

    decrypted_file_path = decrypt_esfm_file(file_path, np_com_id, output_folder)
    if decrypted_file_path:
        logger.info(f"Decryption completed. File saved to: {decrypted_file_path}")
    else:
        logger.error("Error during file decryption.")