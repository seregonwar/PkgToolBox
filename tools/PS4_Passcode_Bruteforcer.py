"""PS4 passcode front-end for the dependency-free package engine.

The previous implementation accepted random passcodes through an invalid
whole-file AES-CBC routine. That could report false success and write corrupt
data. Until verified PFS key derivation is available, this class preserves the
GUI API but deliberately performs no brute-force loop.
"""

from __future__ import annotations

import os

from packages import open_package


class PS4PasscodeBruteforcer:
    UNSUPPORTED_MESSAGE = (
        "[-] Package encryption detected. The dependency-free engine currently "
        "extracts plaintext metadata only; passcode verification is disabled until "
        "the PFS key derivation is validated end-to-end. No protected data was written."
    )

    def __init__(self):
        self.passcode_found = False
        self.found_passcode = ""
        self.last_used_passcode = ""
        self.package_name = ""
        self.package_cid = ""
        self.debug_mode = False
        self.silence_mode = False
        self.package = None
        self._stop = False
        self._attempts_done = 0

    @staticmethod
    def validate_passcode(passcode):
        if not isinstance(passcode, str) or len(passcode) != 32:
            raise ValueError("Passcode must be exactly 32 characters long")
        return True

    def try_passcode(self, input_file, output_directory, passcode):
        self.validate_passcode(passcode)
        self.last_used_passcode = passcode
        self.package = open_package(input_file)
        encrypted = self.package.is_encrypted() if hasattr(self.package, "is_encrypted") else False
        if not encrypted:
            result = self.package.extract_all_files(output_directory)
            return f"[+] Package is not encrypted. {result}"
        return self.UNSUPPORTED_MESSAGE

    def brute_force_passcode(self, input_file, output_directory,
                             progress_callback=None, manual_passcode=None,
                             num_workers=1, tested_callback=None, seed=None):
        del num_workers, tested_callback, seed
        if not os.path.isfile(input_file):
            return f"[-] Package file not found: {input_file}"
        self._stop = False
        self.package = open_package(input_file)
        os.makedirs(output_directory, exist_ok=True)

        encrypted = self.package.is_encrypted() if hasattr(self.package, "is_encrypted") else False
        if not encrypted:
            result = self.package.extract_all_files(output_directory)
            message = f"[+] Package is not encrypted. {result}"
        elif manual_passcode is not None:
            try:
                message = self.try_passcode(input_file, output_directory, manual_passcode)
            except ValueError as exc:
                message = f"[-] Invalid passcode: {exc}"
        else:
            message = self.UNSUPPORTED_MESSAGE

        if progress_callback:
            progress_callback(message)
        return message

    def ensure_output_directory(self, output_directory):
        os.makedirs(output_directory, exist_ok=True)

    def get_package(self):
        return self.package

    def set_debug_mode(self, enabled):
        self.debug_mode = bool(enabled)

    def set_silence_mode(self, enabled):
        self.silence_mode = bool(enabled)

    def stop(self):
        self._stop = True

    @staticmethod
    def _get_state_path(input_file):
        return f"{input_file}.brutestate.json"
