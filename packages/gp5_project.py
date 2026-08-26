"""Reader and workspace adapter for PlayStation 5 GP5 projects.

GP5 files are XML publishing projects, not package images.  This module makes
them look like a read-only package source to the GUI while retaining the
important distinction in the metadata and extraction messages.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET

from .exceptions import PackageBoundsError, PackageFormatError
from .image_info import inspect_image


class GP5Project:
    """Parsed ``*.gp5`` project with a package-compatible file API."""

    FORMAT_NAME = "GP5"
    MAX_PROJECT_SIZE = 16 * 1024 * 1024
    VALID_VOLUME_TYPES = {
        "prospero_app",
        "prospero_patch",       # accepted for compatibility with existing projects
        "prospero_ac",
        "prospero_ac_nodata",
    }

    def __init__(self, file: str):
        if not os.path.isfile(file):
            raise FileNotFoundError(f"The {self.FORMAT_NAME} project '{file}' does not exist.")
        self.original_file = os.path.abspath(file)
        self.project_dir = os.path.dirname(self.original_file)
        self.files: dict[int, dict] = {}
        self.warnings: list[str] = []
        self.content_id = None
        self.title_id = None
        self.title_name = None
        self.volume_type = "prospero_app"
        self.layout = "flat"
        self.version = ""
        self.creation_date = ""
        self.chunk_count = 0
        self.scenario_count = 0
        self._parse()

    @staticmethod
    def _tag(element: ET.Element) -> str:
        return element.tag.rsplit("}", 1)[-1].lower()

    @staticmethod
    def _split_masks(value: str | None) -> list[str]:
        return [part.strip() for part in (value or "").split(";") if part.strip()]

    @staticmethod
    def _matches_masks(name: str, relative: str, masks: list[str]) -> bool:
        normalized = relative.replace("\\", "/")
        return any(
            fnmatch.fnmatch(name.lower(), mask.lower())
            or fnmatch.fnmatch(normalized.lower(), mask.lower())
            for mask in masks
        )

    def _resolve_source(self, raw_path: str | None, base_dir: str | None = None) -> str:
        """Resolve SDK-style paths without treating a leading backslash as root.

        gengp5 writes paths such as ``\\sce_sys\\param.json`` relative to the
        project. LibProsperoPKG may also write a genuine absolute source path.
        """
        raw = (raw_path or "").strip().strip('"')
        base = base_dir or self.project_dir
        if not raw:
            return os.path.abspath(base)
        if raw.startswith("\\"):
            raw = raw.lstrip("\\/")
            return os.path.abspath(os.path.join(base, *raw.replace("\\", "/").split("/")))
        if os.path.isabs(raw):
            return os.path.abspath(raw)
        # Keep Windows drive paths absolute on Windows; on other platforms the
        # unresolved path is retained and will be reported as missing.
        if re.match(r"^[A-Za-z]:[\\/]", raw):
            if os.name == "nt":
                return os.path.abspath(raw)
            return raw
        parts = raw.replace("\\", "/").split("/")
        return os.path.abspath(os.path.join(base, *parts))

    @staticmethod
    def _destination(raw_path: str | None, fallback: str = "") -> str:
        path = (raw_path or fallback or "").replace("\\", "/").lstrip("/")
        parts = [part for part in path.split("/") if part not in ("", ".")]
        if not parts or any(part == ".." for part in parts):
            raise PackageFormatError(f"unsafe GP5 destination path: {raw_path!r}")
        return "/".join(parts)

    def _add_file(self, destination: str, source: str) -> None:
        destination = self._destination(destination, os.path.basename(source))
        if any(info["name"].casefold() == destination.casefold() for info in self.files.values()):
            self.warnings.append(f"Duplicate destination ignored: {destination}")
            return
        present = os.path.isfile(source)
        size = os.path.getsize(source) if present else 0
        source_display = source
        try:
            if os.path.commonpath([self.project_dir, os.path.abspath(source)]) == self.project_dir:
                source_display = os.path.relpath(source, self.project_dir)
        except (OSError, ValueError):
            pass
        file_id = len(self.files)
        self.files[file_id] = {
            "id": file_id,
            "name": destination,
            "size": size,
            "offset": 0,
            "encrypted": False,
            "source_path": source,
            "source_display": source_display,
            "present": present,
            "state": "Available" if present else "Missing",
        }
        if not present:
            self.warnings.append(f"Missing source: {destination} → {source_display}")

    def _walk_directory(
        self,
        source_dir: str,
        destination_dir: str = "",
        dir_masks: list[str] | None = None,
        file_masks: list[str] | None = None,
    ) -> None:
        dir_masks = dir_masks or []
        file_masks = file_masks or []
        if not os.path.isdir(source_dir):
            self.warnings.append(f"Missing source directory: {source_dir}")
            return
        for root, dirs, names in os.walk(source_dir):
            relative_root = os.path.relpath(root, source_dir)
            relative_root = "" if relative_root == "." else relative_root.replace(os.sep, "/")
            dirs[:] = [
                name for name in dirs
                if not self._matches_masks(name, "/".join(filter(None, (relative_root, name))), dir_masks)
            ]
            for name in sorted(names):
                relative = "/".join(filter(None, (relative_root, name)))
                if self._matches_masks(name, relative, file_masks):
                    continue
                destination = "/".join(filter(None, (destination_dir.strip("/"), relative)))
                self._add_file(destination, os.path.join(root, name))

    def _parse_nested_node(self, node: ET.Element, destination_parent: str = "") -> None:
        for child in node:
            tag = self._tag(child)
            if tag == "file":
                destination = "/".join(filter(None, (
                    destination_parent.strip("/"),
                    self._destination(child.get("dst_path"), os.path.basename(child.get("src_path", ""))),
                )))
                self._add_file(destination, self._resolve_source(child.get("src_path")))
            elif tag == "dir":
                destination = "/".join(filter(None, (
                    destination_parent.strip("/"),
                    (child.get("dst_path") or "").replace("\\", "/").strip("/"),
                )))
                source = child.get("src_path")
                if source:
                    self._walk_directory(self._resolve_source(source), destination)
                self._parse_nested_node(child, destination)

    def _parse(self) -> None:
        size = os.path.getsize(self.original_file)
        if size > self.MAX_PROJECT_SIZE:
            raise PackageFormatError("GP5 project is unreasonably large")
        with open(self.original_file, "rb") as stream:
            payload = stream.read()
        upper = payload[:4096].upper()
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
            raise PackageFormatError("DTD/entity declarations are not allowed in GP5 projects")
        try:
            root = ET.fromstring(payload)
        except ET.ParseError as exc:
            raise PackageFormatError(f"invalid GP5 XML: {exc}") from exc
        if self._tag(root) != "psproject" or root.get("fmt", "").lower() != "gp5":
            raise PackageFormatError("not a GP5 psproject document")

        self.version = root.get("version", "")
        volume = next((child for child in root if self._tag(child) == "volume"), None)
        if volume is None:
            raise PackageFormatError("GP5 project has no volume")
        volume_type = next((child for child in volume if self._tag(child) == "volume_type"), None)
        self.volume_type = (volume_type.text or "prospero_app").strip() if volume_type is not None else "prospero_app"
        if self.volume_type not in self.VALID_VOLUME_TYPES:
            self.warnings.append(f"Unknown volume type: {self.volume_type}")
        package = next((child for child in volume if self._tag(child) == "package"), None)
        self.content_id = package.get("content_id") if package is not None else None
        self.creation_date = package.get("c_date", "") if package is not None else ""
        passcode = package.get("passcode", "") if package is not None else ""
        self.passcode_state = (
            "Default (all zeroes)" if passcode and set(passcode) == {"0"}
            else "Configured" if passcode else "Not specified"
        )
        chunk_info = next((child for child in volume if self._tag(child) == "chunk_info"), None)
        if chunk_info is not None:
            self.chunk_count = int(chunk_info.get("chunk_count", "0") or 0)
            self.scenario_count = int(chunk_info.get("scenario_count", "0") or 0)

        files_node = next((child for child in root if self._tag(child) == "files"), None)
        folders_node = next((child for child in root if self._tag(child) == "folders"), None)
        rootdir = next((child for child in root if self._tag(child) == "rootdir"), None)
        self.layout = "flat" if files_node is not None or folders_node is not None else "rootdir"

        if files_node is not None:
            for node in files_node:
                if self._tag(node) != "file":
                    continue
                self._add_file(
                    node.get("dst_path") or os.path.basename(node.get("src_path", "")),
                    self._resolve_source(node.get("src_path")),
                )
        if folders_node is not None:
            for node in folders_node:
                if self._tag(node) == "dir":
                    self._walk_directory(
                        self._resolve_source(node.get("src_path")),
                        (node.get("dst_path") or "").replace("\\", "/").strip("/"),
                    )
        if rootdir is not None:
            source = rootdir.get("src_path")
            if source:
                global_masks = self._split_masks(next((
                    (child.text or "") for child in root if self._tag(child) == "global_exclude"
                ), ""))
                self._walk_directory(
                    self._resolve_source(source),
                    "",
                    self._split_masks(rootdir.get("dir_exclude")),
                    global_masks + self._split_masks(rootdir.get("file_exclude")),
                )
            self._parse_nested_node(rootdir)

        self._load_param_json()

    def _load_param_json(self) -> None:
        entry = next((
            info for info in self.files.values()
            if info["name"].replace("\\", "/").lower().endswith("sce_sys/param.json")
            and info["present"]
        ), None)
        if not entry:
            return
        try:
            with open(entry["source_path"], "r", encoding="utf-8-sig") as stream:
                param = json.load(stream)
            self.title_id = param.get("titleId")
            self.title_name = param.get("localizedParameters", {}).get("en-US", {}).get("titleName") \
                or param.get("titleName")
            self.content_id = self.content_id or param.get("contentId")
            self.content_version = param.get("contentVersion")
        except (OSError, ValueError, TypeError) as exc:
            self.warnings.append(f"Could not read sce_sys/param.json: {exc}")

    def get_all_files(self):
        return self.files

    def get_info(self):
        present = sum(1 for entry in self.files.values() if entry["present"])
        missing = len(self.files) - present
        return {
            "source_type": "GP5 Project",
            "platform": "PS5",
            "project_format": "GP5",
            "project_version": self.version or "unspecified",
            "project_layout": self.layout,
            "volume_type": self.volume_type,
            "content_id": self.content_id,
            "title_id": self.title_id,
            "title_name": self.title_name,
            "content_version": getattr(self, "content_version", None),
            "creation_date": self.creation_date or None,
            "passcode": self.passcode_state,
            "chunk_count": self.chunk_count,
            "scenario_count": self.scenario_count,
            "file_count": len(self.files),
            "available_files": present,
            "missing_files": missing,
            "total_size": sum(entry["size"] for entry in self.files.values()),
            "validation": "Ready" if not self.warnings else f"{len(self.warnings)} warning(s)",
        }

    def read_file(self, file_id, *, allow_encrypted=False):
        del allow_encrypted
        entry = self.files.get(file_id)
        if not entry:
            raise ValueError(f"File with ID {file_id} not found in the {self.FORMAT_NAME} project.")
        if not entry["present"]:
            raise FileNotFoundError(f"{self.FORMAT_NAME} source file is missing: {entry['source_path']}")
        with open(entry["source_path"], "rb") as stream:
            return stream.read()

    def get_image_info(self, file_id):
        return inspect_image(self.read_file(file_id)[:128])

    def list_image_assets(self):
        assets = []
        for file_id, entry in self.files.items():
            if not entry["present"] or not entry["name"].lower().endswith((".png", ".dds")):
                continue
            try:
                image = self.get_image_info(file_id)
            except Exception:
                continue
            assets.append({
                "id": file_id,
                "name": entry["name"],
                "format": image.format,
                "width": image.width,
                "height": image.height,
                "kind": image.kind,
                "mipmaps": image.mipmaps,
            })
        return assets

    @staticmethod
    def _safe_output_path(output_dir: str, name: str) -> str:
        root = os.path.realpath(output_dir)
        normalized = name.replace("\\", "/")
        parts = [part for part in normalized.split("/") if part not in ("", ".")]
        if not parts or any(part == ".." for part in parts):
            raise PackageBoundsError(f"unsafe GP5 destination path: {name!r}")
        target = os.path.realpath(os.path.join(root, *parts))
        if os.path.commonpath([root, target]) != root:
            raise PackageBoundsError(f"GP5 destination escapes output directory: {name!r}")
        return target

    def dump(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        copied = 0
        missing = 0
        for entry in self.files.values():
            if not entry["present"]:
                missing += 1
                continue
            target = self._safe_output_path(output_dir, entry["name"])
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(target), prefix=".pkgtoolbox-", delete=False
            ) as temporary:
                temporary_path = temporary.name
            try:
                shutil.copy2(entry["source_path"], temporary_path)
                os.replace(temporary_path, target)
            except Exception:
                try:
                    os.remove(temporary_path)
                except OSError:
                    pass
                raise
            copied += 1
        return f"{self.FORMAT_NAME} project exported: {copied} file(s), {missing} missing. Output: {output_dir}"

    def get_title_id_folder_name(self):
        if self.title_id and re.fullmatch(r"[A-Za-z0-9]{4,16}", str(self.title_id)):
            return str(self.title_id).upper()
        if self.content_id:
            parts = str(self.content_id).split("-")
            if len(parts) > 1:
                candidate = parts[1].split("_")[0]
                if re.fullmatch(r"[A-Za-z0-9]{4,16}", candidate):
                    return candidate.upper()
        return os.path.splitext(os.path.basename(self.original_file))[0]

    def close(self):
        """Compatibility no-op: publishing projects keep no open handles."""
