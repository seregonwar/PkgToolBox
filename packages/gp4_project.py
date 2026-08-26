"""Read-only adapter for PlayStation 4 GP4 publishing projects."""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET

from .exceptions import PackageFormatError
from .gp5_project import GP5Project
from .metadata import infer_region
from .sfo import parse_sfo


class GP4Project(GP5Project):
    """Parse the explicit file mappings used by standard GP4 projects."""

    FORMAT_NAME = "GP4"
    VALID_VOLUME_TYPES = {
        "pkg_ps4_app",
        "pkg_ps4_patch",
        "pkg_ps4_remaster",
        "pkg_ps4_ac_data",
        "pkg_ps4_ac_nodata",
    }

    def _parse(self) -> None:
        size = os.path.getsize(self.original_file)
        if size > self.MAX_PROJECT_SIZE:
            raise PackageFormatError("GP4 project is unreasonably large")
        with open(self.original_file, "rb") as stream:
            payload = stream.read()
        upper = payload[:4096].upper()
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
            raise PackageFormatError("DTD/entity declarations are not allowed in GP4 projects")
        try:
            root = ET.fromstring(payload)
        except ET.ParseError as exc:
            raise PackageFormatError(f"invalid GP4 XML: {exc}") from exc
        if self._tag(root) != "psproject" or root.get("fmt", "").lower() != "gp4":
            raise PackageFormatError("not a GP4 psproject document")

        self.version = root.get("version", "")
        volume = next((child for child in root if self._tag(child) == "volume"), None)
        if volume is None:
            raise PackageFormatError("GP4 project has no volume")
        volume_type = next((child for child in volume if self._tag(child) == "volume_type"), None)
        self.volume_type = (volume_type.text or "pkg_ps4_app").strip() if volume_type is not None else "pkg_ps4_app"
        if self.volume_type not in self.VALID_VOLUME_TYPES:
            self.warnings.append(f"Unknown volume type: {self.volume_type}")
        package = next((child for child in volume if self._tag(child) == "package"), None)
        self.content_id = package.get("content_id") if package is not None else None
        passcode = package.get("passcode", "") if package is not None else ""
        self.passcode_state = (
            "Default (all zeroes)" if passcode and set(passcode) == {"0"}
            else "Configured" if passcode else "Not specified"
        )
        timestamp = next((child for child in volume if self._tag(child) == "volume_ts"), None)
        self.creation_date = (timestamp.text or "").strip() if timestamp is not None else ""
        chunk_info = next((child for child in volume if self._tag(child) == "chunk_info"), None)
        if chunk_info is not None:
            try:
                self.chunk_count = int(chunk_info.get("chunk_count", "0") or 0)
                self.scenario_count = int(chunk_info.get("scenario_count", "0") or 0)
            except ValueError as exc:
                raise PackageFormatError("invalid GP4 chunk/scenario count") from exc

        files_node = next((child for child in root if self._tag(child) == "files"), None)
        self.layout = "flat"
        if files_node is not None:
            for node in files_node:
                if self._tag(node) != "file":
                    continue
                source = node.get("orig_path") or node.get("src_path")
                destination = node.get("targ_path") or node.get("dst_path")
                self._add_file(
                    destination or os.path.basename(source or ""),
                    self._resolve_source(source),
                )
        self._load_param_sfo()

    def _load_param_sfo(self) -> None:
        entry = next((
            info for info in self.files.values()
            if info["name"].replace("\\", "/").lower().endswith("sce_sys/param.sfo")
            and info["present"]
        ), None)
        if not entry:
            return
        try:
            with open(entry["source_path"], "rb") as stream:
                values = parse_sfo(stream.read()).as_dict()
            self.title_id = values.get("TITLE_ID")
            self.title_name = values.get("TITLE") or values.get("TITLE_00")
            self.content_id = self.content_id or values.get("CONTENT_ID")
            self.content_version = values.get("APP_VER") or values.get("VERSION")
            self.region = infer_region(self.title_id, "ps4")
        except Exception as exc:
            self.warnings.append(f"Could not read sce_sys/param.sfo: {exc}")

    def get_info(self):
        info = super().get_info()
        info.update({
            "source_type": "GP4 Project",
            "platform": "PS4",
            "project_format": "GP4",
            "region": getattr(self, "region", None),
        })
        return info
