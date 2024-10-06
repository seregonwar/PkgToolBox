import os
import sys
import time
import signal
import random
import string
import shutil
import subprocess
from pathlib import Path
from package import Package

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
        if self.debug_mode:
            return "00000000000000000000000000000000"

        characters = string.ascii_letters + string.digits + "-_"
        return ''.join(random.choice(characters) for _ in range(length))

    def ensure_output_directory(self, output_directory):
        os.makedirs(output_directory, exist_ok=True)

    def is_pkg_file(self, file_name):
        return file_name.lower().endswith(".pkg")

    def read_cid(self, package_file):
        try:
            with open(package_file, "rb") as file:
                file.seek(0x40)
                cid_buffer = file.read(36)
                cid_string = ''.join(filter(lambda x: x in string.printable, cid_buffer.decode('latin-1')))
                return cid_string
        except Exception as e:
            print(f"[-] Failed to read the CID from the package file: {e}")
            return ""

    def check_executable(self, executable_name):
        return shutil.which(executable_name) is not None

    def brute_force_passcode(self, input_file, output_directory, progress_callback=None):
        self.ensure_output_directory(output_directory)

        try:
            self.package = Package(input_file)
        except FileNotFoundError:
            return f"[-] Package file not found: {input_file}"

        if not self.package.is_encrypted():
            self.package.extract_all_files(output_directory)
            return "[+] Package is not encrypted. Files extracted."

        if progress_callback:
            progress_callback("[+] Package is encrypted. Starting brute force...")

        while not self.passcode_found:
            passcode = self.generate_random_passcode()
            self.last_used_passcode = passcode

            try:
                self.package.extract_with_passcode(passcode, output_directory)
                self.passcode_found = True
                self.found_passcode = passcode
                if progress_callback:
                    progress_callback(f"[+] Passcode found: {passcode}")
                break
            except ValueError:
                if progress_callback:
                    progress_callback(f"[-] Incorrect passcode: {passcode}")
                continue

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

    def get_package(self):
        return self.package

