import os
import re
import logging
from Crypto.Cipher import AES
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

    def _derive_key(self, np_com_id):
        """Deriva la chiave ESFM: AES-CBC(trophy_key, IV zero) sul NP comm ID
        riempito di zero fino a un multiplo di 16 byte."""
        raw = np_com_id.encode('utf-8', 'ignore')
        raw = raw + b'\0' * ((16 - len(raw) % 16) % 16)
        iv = bytes([0] * 16)
        return AES.new(self.trophy_key, AES.MODE_CBC, iv).encrypt(raw)

    def decrypt_esfm_bytes(self, encrypted_data, np_com_id):
        """Decifra byte ESFM con la trophy key e il NP Communication ID.
        Ritorna il testo XML decifrato oppure None.

        Formato: IV[16] + ciphertext AES-CBC (PS4/PS3). Prima si prova il
        metodo corretto (IV letto dal file), poi il fallback storico (tutto il
        file come ciphertext con IV zero). Il risultato deve essere XML valido.
        """
        if not encrypted_data or len(encrypted_data) < 16:
            return None
        try:
            key = self._derive_key(np_com_id)
        except Exception as e:
            logger.error(f"ESFM key derivation failed: {e}")
            return None

        candidates = []
        # Metodo corretto: i primi 16 byte sono l'IV, il resto è ciphertext
        try:
            iv = encrypted_data[:16]
            dec = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted_data[16:])
            candidates.append(''.join(chr(b) for b in dec if 32 <= b <= 126 or b in (9, 10, 13)))
        except Exception:
            pass
        # Fallback legacy: tutto il file come ciphertext con IV zero
        try:
            iv0 = bytes([0] * 16)
            dec = AES.new(key, AES.MODE_CBC, iv0).decrypt(encrypted_data)
            candidates.append(''.join(chr(b) for b in dec if 32 <= b <= 126 or b in (9, 10, 13)))
        except Exception:
            pass

        for text in candidates:
            try:
                ET.fromstring(text)
                return text
            except ET.ParseError:
                continue
        return candidates[0] if candidates else None

    def decrypt_esfm_file(self, file_path, np_com_id, output_folder):
        logger.info(f"Starting decryption of file: {file_path}")

        with open(file_path, 'rb') as file:
            encrypted_data = file.read()

        decrypted_data = self.decrypt_esfm_bytes(encrypted_data, np_com_id)
        if not decrypted_data:
            logger.error("Decryption failed or produced no output")
            return None

        try:
            ET.fromstring(decrypted_data)
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