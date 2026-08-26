"""Adapter that lets a standalone file participate in the desktop workspace."""

from __future__ import annotations

import os
import re
import shutil

from .image_info import inspect_image


class StandaloneFileSource:
    def __init__(self, file: str):
        if not os.path.isfile(file):
            raise FileNotFoundError(f"The file '{file}' does not exist.")
        self.original_file = os.path.abspath(file)
        self.content_id = None
        size = os.path.getsize(self.original_file)
        self.files = {0: {
            "id": 0,
            "name": os.path.basename(self.original_file),
            "size": size,
            "offset": 0,
            "encrypted": False,
            "source_path": self.original_file,
            "present": True,
            "state": "Standalone",
        }}

    def get_all_files(self):
        return self.files

    def get_info(self):
        extension = os.path.splitext(self.original_file)[1].lower() or "no extension"
        return {
            "source_type": "Standalone File",
            "platform": "Generic",
            "file_name": os.path.basename(self.original_file),
            "file_extension": extension,
            "file_count": 1,
            "available_files": 1,
            "missing_files": 0,
            "total_size": os.path.getsize(self.original_file),
            "validation": "Ready",
        }

    def read_file(self, file_id, *, allow_encrypted=False):
        del allow_encrypted
        if file_id != 0:
            raise ValueError(f"File with ID {file_id} not found.")
        with open(self.original_file, "rb") as stream:
            return stream.read()

    def get_image_info(self, file_id):
        with open(self.original_file, "rb") as stream:
            return inspect_image(stream.read(128))

    def list_image_assets(self):
        if not self.original_file.lower().endswith((".png", ".dds")):
            return []
        try:
            image = self.get_image_info(0)
        except Exception:
            return []
        return [{
            "id": 0,
            "name": os.path.basename(self.original_file),
            "format": image.format,
            "width": image.width,
            "height": image.height,
            "kind": image.kind,
            "mipmaps": image.mipmaps,
        }]

    def dump(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        target = os.path.join(output_dir, os.path.basename(self.original_file))
        if os.path.abspath(target) != self.original_file:
            shutil.copy2(self.original_file, target)
        return f"File exported to: {target}"

    def get_title_id_folder_name(self):
        base = os.path.splitext(os.path.basename(self.original_file))[0]
        return re.sub(r"[^A-Za-z0-9_.-]", "_", base).strip("._") or "File"

    def close(self):
        """Compatibility no-op."""

