# This module is part of PKGToolBox, developed by seregonwar. It is a translated and adapted version from C++ to Python, based on the original implementation made by HoppersPS4.
# Credit to HoppersPS4 
# repository link: https://github.com/HoppersPS4/Waste_Ur_Time

import os
import sys
import time
import random
import string
import shutil
import subprocess
from pathlib import Path
from packages import PackagePS4, PackagePS5, PackagePS3
import struct
import logging

class PS4PasscodeBruteforcer:
    def __init__(self):
        self.passcode_found = False
        self.found_passcode = ""
        self.last_used_passcode = ""
        self.package_name = ""
        self.package_cid = ""
        self.debug_mode = False
        self.silence_mode = False
        self.package = None

    def generate_random_passcode(self, length=32):
        """Generate random passcode"""
        if self.debug_mode:
            return "00000000000000000000000000000000"

        # Usa lettere, numeri, - e _
        characters = string.ascii_letters + string.digits + "-_"
        return ''.join(random.choice(characters) for _ in range(length))

    def validate_passcode(self, passcode):
        """Validate passcode format"""
        # Verifica solo la lunghezza
        if len(passcode) != 32:
            raise ValueError("Passcode must be 32 characters long")
        
        return True

    def try_passcode(self, input_file, output_directory, passcode):
        """Try to decrypt with a specific passcode"""
        try:
            # Determine package type and create appropriate instance
            with open(input_file, "rb") as fp:
                magic = struct.unpack(">I", fp.read(4))[0]
                if magic == PackagePS4.MAGIC_PS4:
                    self.package = PackagePS4(input_file)
                elif magic == PackagePS5.MAGIC_PS5:
                    self.package = PackagePS5(input_file)
                elif magic == PackagePS3.MAGIC_PS3:
                    self.package = PackagePS3(input_file)
                else:
                    return f"[-] Unknown PKG format: {magic:08X}"

            if not self.package.is_encrypted():
                self.package.extract_all_files(output_directory)
                return "[+] Package is not encrypted. Files extracted."

            try:
                # Verifica solo la lunghezza del passcode
                if len(passcode) != 32:
                    return f"[-] Invalid passcode length: {len(passcode)}"
                
                self.package.extract_with_passcode(passcode, output_directory)
                self.passcode_found = True
                self.found_passcode = passcode
                return f"[+] Successfully decrypted with passcode: {passcode}"
            except ValueError as e:
                return f"[-] Failed to decrypt with passcode: {str(e)}"

        except Exception as e:
            logging.error(f"Error trying passcode: {str(e)}")
            return f"[-] Error: {str(e)}"

    def brute_force_passcode(self, input_file, output_directory, progress_callback=None, manual_passcode=None):
        """Brute force or try specific passcode"""
        self.ensure_output_directory(output_directory)

        try:
            # Determine package type and create appropriate instance
            with open(input_file, "rb") as fp:
                magic = struct.unpack(">I", fp.read(4))[0]
                if magic == PackagePS4.MAGIC_PS4:
                    self.package = PackagePS4(input_file)
                elif magic == PackagePS5.MAGIC_PS5:
                    self.package = PackagePS5(input_file)
                elif magic == PackagePS3.MAGIC_PS3:
                    self.package = PackagePS3(input_file)
                else:
                    return f"[-] Unknown PKG format: {magic:08X}"

            if not self.package.is_encrypted():
                self.package.extract_all_files(output_directory)
                return "[+] Package is not encrypted. Files extracted."

            if progress_callback:
                progress_callback("[+] Package is encrypted. Starting decryption...")

            # Se è fornito un passcode manuale, prova solo quello
            if manual_passcode:
                try:
                    self.validate_passcode(manual_passcode)
                    result = self.try_passcode(input_file, output_directory, manual_passcode)
                    if progress_callback:
                        progress_callback(result)
                    return result
                except ValueError as e:
                    return f"[-] Invalid passcode format: {str(e)}"

            # Altrimenti procedi con il brute force
            while not self.passcode_found:
                passcode = self.generate_random_passcode()
                self.last_used_passcode = passcode

                result = self.try_passcode(input_file, output_directory, passcode)
                if progress_callback:
                    progress_callback(result)

                if self.passcode_found:
                    break

            if self.passcode_found:
                success_file_name = f"{input_file}.success"
                try:
                    with open(success_file_name, "w") as success_file:
                        success_file.write(self.found_passcode)
                    return f"[+] Passcode found: {self.found_passcode}\n[+] Passcode has been saved to: {success_file_name}"
                except Exception as e:
                    return f"[+] Passcode found: {self.found_passcode}\n[-] Failed to create/save the success file: {e}"
            else:
                return "[-] Passcode not found."

        except FileNotFoundError:
            return f"[-] Package file not found: {input_file}"
        except Exception as e:
            logging.error(f"Error during brute force: {str(e)}")
            return f"[-] Error: {str(e)}"

    def ensure_output_directory(self, output_directory):
        """Assicura che la directory di output esista"""
        os.makedirs(output_directory, exist_ok=True)

    def get_package(self):
        """Restituisce l'oggetto package corrente"""
        return self.package

    def set_debug_mode(self, enabled):
        """Imposta la modalità debug"""
        self.debug_mode = enabled

    def set_silence_mode(self, enabled):
        """Imposta la modalità silenziosa"""
        self.silence_mode = enabled
