import os
import re
import tempfile
from Utilities import Logger
from .binary import checked_range
from .exceptions import EncryptedEntryError, PackageBoundsError

class PackageBase:
    TYPE_MASK = 0x0000FFFF
    FLAG_RETAIL = 1 << 31
    FLAG_ENCRYPTED = 0x80000000

    #: PKG plumbing entries (PS4/PS5 spec) that are never game content: key
    #: material, digest tables, the entry-name table itself and the per-block
    #: image digests. They are kept in ``self.files`` for inspection but are
    #: skipped by ``extract_all_files`` so the output only contains real files.
    STRUCTURAL_ENTRY_IDS = frozenset({
        0x0001,  # digests
        0x0010,  # entry_keys
        0x0020,  # image_key
        0x0080,  # general_digests
        0x0100,  # metas
        0x0200,  # entry_names
        0x040A,  # imagedigs.dat
    })

    def __init__(self, file: str):
        if not os.path.isfile(file):
            raise FileNotFoundError(f"The PKG file '{file}' does not exist.")
        
        self.original_file = file
        self.pkg_info = {}
        self.files = {}
        self.content_id = None
        self.drm_type = None
        self.content_type = None
        self.content_flags = None
        self.iro_tag = None
        self.version_date = None
        self.version_hash = None
        self.digest_table_hash = None
        self.entry_table_offset = None
        self.entry_table_size = None

    def _safe_decode(self, data):
        if isinstance(data, str):
            return data.rstrip('\x00')
        elif isinstance(data, bytes):
            try:
                return data.decode('utf-8', errors='ignore').rstrip('\x00')
            except UnicodeDecodeError:
                return data.decode('latin-1', errors='ignore').rstrip('\x00')
        elif isinstance(data, int):
            return str(data)
        else:
            return str(data)

    def _read_null_terminated_string(self, fp):
        result = bytearray()
        while True:
            try:
                char = fp.read(1)
                if char == b'\x00' or len(char) == 0:
                    break
                result.extend(char)
            except (OverflowError, OSError) as e:
                Logger.log_warning(f"Error reading string: {e}")
                break
        return bytes(result)

    def get_info(self):
        return {
            "content_id": self.content_id,
            "drm_type": self.drm_type,
            "content_type": self.content_type,
            "content_flags": self.content_flags,
            "iro_tag": self.iro_tag,
            "version_date": self.version_date,
            "version_hash": self.version_hash,
            "digest_table_hash": self.digest_table_hash,
            "entry_table_offset": self.entry_table_offset,
            "entry_table_size": self.entry_table_size,
        }

    def read_file(self, file_id, *, allow_encrypted=False):
        file_info = self.files.get(file_id)
        if not file_info:
            raise ValueError(f"File with ID {file_id} not found in the package.")
        if file_info.get("encrypted") and not allow_encrypted:
            name = file_info.get("name", f"file_{file_id}")
            raise EncryptedEntryError(f"'{name}' is encrypted; plaintext access was refused")

        file_size = os.path.getsize(self.original_file)
        offset = file_info.get("offset")
        size = file_info.get("size")
        if offset is None or size is None:
            raise PackageBoundsError(f"File with ID {file_id} has no valid offset/size")
        checked_range(offset, size, file_size, f"entry {file_id}")
        with open(self.original_file, 'rb') as f:
            f.seek(offset)
            data = f.read(size)
        if len(data) != size:
            raise PackageBoundsError(f"File with ID {file_id} is truncated")
        return data

    def get_image_info(self, file_id):
        """Inspect a PNG/DDS header without loading the complete asset."""
        from .image_info import inspect_image

        file_info = self.files.get(file_id)
        if not file_info:
            raise ValueError(f"File with ID {file_id} not found in the package.")
        if file_info.get("encrypted"):
            name = file_info.get("name", f"file_{file_id}")
            raise EncryptedEntryError(f"'{name}' is encrypted; image inspection was refused")
        file_size = os.path.getsize(self.original_file)
        offset, size = file_info.get("offset"), file_info.get("size")
        if offset is None or size is None:
            raise PackageBoundsError(f"File with ID {file_id} has no valid offset/size")
        checked_range(offset, size, file_size, f"image entry {file_id}")
        with open(self.original_file, "rb") as fp:
            fp.seek(offset)
            header = fp.read(min(size, 128))
        return inspect_image(header)

    def list_image_assets(self):
        """Return validated metadata for every named plaintext PNG/DDS entry."""
        assets = []
        for file_id, file_info in self.files.items():
            name = str(file_info.get("name", ""))
            if file_info.get("encrypted") or not name.lower().endswith((".png", ".dds")):
                continue
            try:
                image = self.get_image_info(file_id)
            except Exception as exc:
                Logger.log_warning(f"Could not inspect image '{name}': {exc}")
                continue
            assets.append({
                "id": file_id,
                "name": name,
                "format": image.format,
                "width": image.width,
                "height": image.height,
                "kind": image.kind,
                "mipmaps": image.mipmaps,
            })
        return assets

    @staticmethod
    def _safe_output_path(output_dir: str, name: str) -> str:
        """Resolve an entry path and keep it strictly below output_dir."""
        root = os.path.realpath(output_dir)
        normalized = str(name or "unnamed").replace('\\', '/')
        parts = [part for part in normalized.split('/') if part not in ('', '.')]
        if not parts or any(part == '..' for part in parts):
            raise PackageBoundsError(f"unsafe package entry path: {name!r}")
        candidate = os.path.realpath(os.path.join(root, *parts))
        if os.path.commonpath([root, candidate]) != root:
            raise PackageBoundsError(f"package entry escapes output directory: {name!r}")
        return candidate

    def get_title_id_folder_name(self) -> str:
        """Return a filesystem-safe folder name based on the package title ID.

        Prefers ``title_id`` when the package provides one (param.sfo
        ``TITLE_ID``, PS5 ``param.json`` ``titleId``, PS3 header), then derives
        it from the content ID (the second hyphen-separated component, e.g.
        ``PPSA99099`` from ``UP9000-PPSA99099_00-...``), and finally falls
        back to a sanitized version of the package file name.
        """
        candidates = []
        title_id = getattr(self, "title_id", None)
        if title_id:
            candidates.append(str(title_id).strip())
        content_id = self.content_id or getattr(self, "pkg_content_id", None)
        if content_id:
            parts = str(content_id).split("-")
            if len(parts) >= 2:
                # 'CUSA12345_00' -> 'CUSA12345' (strip the _NN revision suffix)
                candidates.append(parts[1].split("_")[0].strip())
        for candidate in candidates:
            if re.fullmatch(r"[A-Za-z0-9]{4,16}", candidate):
                return candidate.upper()
        # Last resort: sanitized base name of the pkg file
        base = os.path.splitext(os.path.basename(self.original_file))[0]
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", base).strip("._")
        return safe or "Unknown"

    def extract_all_files(self, output_dir: str):
        """Extract all files listed in self.files to the specified output directory.

        This is a generic implementation used by package types. It expects
        `self.files` to be a mapping of file_id -> dict with at least:
          - 'offset': byte offset in the source package
          - 'size': size in bytes
          - optional 'name': output relative path
        """
        try:
            os.makedirs(output_dir, exist_ok=True)

            if not isinstance(self.files, dict) or not self.files:
                Logger.log_warning("No files table available for extraction.")
                return f"No files to extract. Output: {output_dir}"

            extracted = 0
            skipped_encrypted = 0
            skipped_internal = 0
            skipped_invalid = 0
            file_size = os.path.getsize(self.original_file)
            with open(self.original_file, 'rb') as src:
                for file_id, info in self.files.items():
                    temporary_path = None
                    try:
                        name = info.get('name', f'file_{file_id}')
                        if file_id in self.STRUCTURAL_ENTRY_IDS:
                            skipped_internal += 1
                            continue
                        if info.get('encrypted'):
                            skipped_encrypted += 1
                            Logger.log_warning(f"Skipping encrypted entry: {name}")
                            continue
                        out_path = self._safe_output_path(output_dir, name)
                        os.makedirs(os.path.dirname(out_path), exist_ok=True)

                        offset = info.get('offset')
                        size = info.get('size')
                        if offset is None or size is None:
                            raise PackageBoundsError("missing offset/size")

                        checked_range(offset, size, file_size, f"entry {file_id}")
                        src.seek(offset)
                        with tempfile.NamedTemporaryFile(
                            mode="wb", dir=os.path.dirname(out_path),
                            prefix=".pkgtoolbox-", delete=False,
                        ) as dst:
                            temporary_path = dst.name
                            remaining = size
                            while remaining:
                                chunk = src.read(min(remaining, 1024 * 1024))
                                if not chunk:
                                    raise PackageBoundsError(f"entry {file_id} is truncated")
                                dst.write(chunk)
                                remaining -= len(chunk)
                        os.replace(temporary_path, out_path)
                        temporary_path = None
                        extracted += 1
                        Logger.log_information(f"Extracted: {name}")
                    except Exception as e:
                        if temporary_path:
                            try:
                                os.remove(temporary_path)
                            except OSError:
                                pass
                        skipped_invalid += 1
                        Logger.log_error(f"Error extracting file_id {file_id}: {e}")

            result = (
                f"Internal extraction completed: {extracted} plaintext file(s), "
                f"{skipped_encrypted} encrypted skipped, "
                f"{skipped_internal} internal skipped, "
                f"{skipped_invalid} invalid skipped. "
                f"Output: {output_dir}"
            )
            Logger.log_information(result)
            return result
        except Exception as e:
            Logger.log_error(f"Extraction failed: {e}")
            raise
