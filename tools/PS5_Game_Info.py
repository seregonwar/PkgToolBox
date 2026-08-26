"""Game info reader: eboot.bin (SELF/ELF) + param.json (PS5) or param.sfo (PS4).

Module created by sinajet, implemented by SeregonWar in PkgToolBox; the eboot
parsing now uses the pure-Python SELF/ELF parser in ``packages.self_info``
(ported from LibProsperoPkg) and PS4 packages are supported through the
``packages.sfo`` PARAM.SFO parser.
"""

import json
import os
import struct
from pathlib import Path

from packages.exceptions import PackageFormatError
from packages.self_info import (
    ELF_MAGIC,
    SCE_HEADER_SIZE,
    SELF_MAGIC,
    detect_kind,
    format_packed_version,
    parse_elf_header,
    parse_self,
)
from packages.sfo import parse_sfo

#: Readable labels for the most common PARAM.SFO keys (PS4).
SFO_LABELS = {
    "TITLE": "Title",
    "TITLE_ID": "Title ID",
    "CONTENT_ID": "Content ID",
    "APP_VER": "App Version",
    "VERSION": "System Version",
    "CATEGORY": "Category",
    "DOWNLOAD_DATA_SIZE": "Download Data Size",
    "SERVICE_ID": "Service ID",
    "PARENTAL_LEVEL": "Parental Level",
    "ATTRIBUTE": "Attributes",
    "QUALITY_LEVEL": "Quality Level",
    "RELEASE_DATE": "Release Date",
    "PS3_SYSTEM_VER": "PS3 System Version",
    "PUBTOOLINFO": "Pubtool Info",
}

#: PS4 PARAM.SFO category codes (CATEGORY).
SFO_CATEGORIES = {
    "gd": "Game (Digital)",
    "gp": "Game (Physical)",
    "gde": "Game (Digital, Extra)",
    "gdp": "Game (Digital, Pre-order)",
    "gpe": "Game (Physical, Extra)",
    "gpp": "Game (Physical, Pre-order)",
    "ga": "Application",
    "gw": "Web",
    "gi": "Invite",
    "hd": "Home (Digital)",
    "hp": "Home (Physical)",
    "at": "Add-on",
    "ac": "Add-on (Content)",
    "ad": "Add-on (Digital)",
    "ae": "Add-on (Extra)",
    "ap": "Add-on (Pre-order)",
    "ms": "PS Mobile",
    "pa": "PS App",
    "cn": "Companion",
    "dp": "Demo (Digital)",
    "pp": "Patch",
    "em": "Emulator",
    "v": "Video",
}

#: PS5 param.json key -> readable label for the headline rows.
PS5_JSON_LABELS = {
    "titleId": "Title ID",
    "contentId": "Content ID",
    "contentVersion": "Content Version",
    "masterVersion": "Master Version",
    "requiredSystemSoftwareVersion": "Required System Software",
    "sdkVersion": "SDK Version",
    "applicationCategoryType": "Application Category",
    "applicationDrmType": "DRM Type",
    "attribute": "Attribute",
    "attribute2": "Attribute 2",
    "attribute3": "Attribute 3",
    "contentBadgeType": "Content Badge",
    "downloadDataSize": "Download Data Size",
    "massSize": "Mass Size",
    "flexibleMemorySize": "Flexible Memory Size",
    "conceptId": "Concept ID",
    "creationDate": "Creation Date",
    "toolVersion": "Publishing Tool Version",
    "defaultLanguage": "Default Language",
}


def _format_version(value) -> str:
    """Format a hex firmware version (e.g. ``0x05100510``) as dotted BCD pairs."""
    text = str(value or "").strip()
    if not text.lower().startswith("0x"):
        return text
    digits = text[2:]
    if not digits or len(digits) % 2:
        return text
    pairs = [digits[index:index + 2] for index in range(0, len(digits), 2)]
    # Keep at least major.minor; drop only trailing zero components beyond that.
    while len(pairs) > 2 and pairs[-1] == "00":
        pairs.pop()
    return ".".join(pairs)


def _format_bytes(size) -> str:
    """Format a byte count readably."""
    try:
        size = int(size)
    except (TypeError, ValueError):
        return str(size)
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if size < 1024.0:
            return f"{size:.1f} {unit}" if unit != "bytes" else f"{size:.0f} bytes"
        size /= 1024.0
    return f"{size:.1f} PB"


def _region_from_content_id(content_id) -> str:
    prefix = str(content_id or "")[:2].upper()
    return {"UP": "US", "EP": "EU", "JP": "JP", "AS": "Asia"}.get(prefix, prefix or "")


class PS5GameInfo:
    def __init__(self):
        self.gPath = ""
        self.main_dict = {}
        self.groups = []
        self.platform = None       # 'ps5' | 'ps4' | 'unknown'
        self.editable = None       # 'param.json' when save-back is possible
        self.gname = ""
        self.gVer = ""
        self.region = ""
        self.sVer = ""

    # ------------------------------------------------------------------
    # entry point
    # ------------------------------------------------------------------
    def process(self, path):
        """Inspect a game folder (eboot.bin + sce_sys/param.json|param.sfo).

        Returns a dict with ``groups`` (ordered ``{title, rows}`` where each
        row is ``(label, value, editable, target)``), ``platform``, ``editable``
        and a flat ``main_dict`` for compatibility.
        """
        self.gPath = path
        self.main_dict = {}
        self.groups = []
        self.platform = "unknown"
        self.editable = None

        eboot_path = os.path.join(path, "eboot.bin")
        if not os.path.exists(eboot_path):
            return {"error": "Can't find eboot file. Please select correct path."}

        self._parse_eboot(eboot_path)

        json_path = os.path.join(path, "sce_sys", "param.json")
        if not os.path.exists(json_path):
            json_path = os.path.join(path, "param.json")
        sfo_path = os.path.join(path, "sce_sys", "param.sfo")
        if not os.path.exists(sfo_path):
            sfo_path = os.path.join(path, "param.sfo")
        if os.path.exists(json_path):
            self.platform = "ps5"
            self.editable = "param.json"
            self._parse_param_json(json_path)
        elif os.path.exists(sfo_path):
            self.platform = "ps4"
            self._parse_param_sfo(sfo_path)

        return {
            "platform": self.platform,
            "editable": self.editable,
            "groups": self.groups,
            "main_dict": dict(self.main_dict),
        }

    # ------------------------------------------------------------------
    # eboot.bin (SELF / ELF)
    # ------------------------------------------------------------------
    def _parse_eboot(self, eboot_path):
        try:
            with open(eboot_path, "rb") as fp:
                head = fp.read(SCE_HEADER_SIZE)
        except OSError as exc:
            self.groups.append({
                "title": "eboot.bin",
                "rows": [("Error", f"could not read file: {exc}", False, None)],
            })
            return

        kind = detect_kind(head)
        if kind == "elf":
            with open(eboot_path, "rb") as fp:
                elf_header = parse_elf_header(fp.read(0x40))
            rows = [
                ("Format", "ELF (plaintext)", False, None),
                ("Signed / Fake", "Unprotected (decrypted ELF)", False, None),
            ]
            if elf_header is not None:
                rows.extend([
                    ("Architecture", f"{elf_header.machine_name} ({elf_header.class_name}, "
                                     f"{elf_header.endian_name})", False, None),
                    ("ELF Type", elf_header.type_name, False, None),
                    ("Entry Point", f"0x{elf_header.e_entry:X}", False, None),
                ])
            self.groups.append({"title": "eboot.bin", "rows": rows})
            return

        if kind == "unknown":
            self.groups.append({
                "title": "eboot.bin",
                "rows": [
                    ("Format", "Unrecognized", False, None),
                    ("Note", "Not a SELF or ELF — the file is probably NPDRM-encrypted", False, None),
                ],
            })
            return

        # SELF container
        try:
            with open(eboot_path, "rb") as fp:
                header = fp.read(SCE_HEADER_SIZE)
                if len(header) < SCE_HEADER_SIZE:
                    raise PackageFormatError("truncated SCE header")
                header_size = struct.unpack_from("<H", header, 0x0C)[0]
                fp.seek(0)
                data = fp.read(header_size + 0x40)
            info = parse_self(data)
        except (PackageFormatError, OSError) as exc:
            self.groups.append({
                "title": "eboot.bin",
                "rows": [("Error", f"could not parse SELF: {exc}", False, None)],
            })
            return

        rows = [
            ("Format", "SELF (SCE ELF)", False, None),
            ("Signed / Fake", "Fake (fake authority id)" if info.is_fake
                              else "Signed (official)", False, None),
            ("Mode", info.mode_name, False, None),
            ("Program Type", info.program_type_name, False, None),
        ]
        if info.elf is not None:
            rows.append(("Architecture", f"{info.elf.machine_name} ({info.elf.class_name}, "
                                         f"{info.elf.endian_name})", False, None))
            rows.append(("ELF Type", info.elf.type_name, False, None))
            rows.append(("Entry Point", f"0x{info.elf.e_entry:X}", False, None))
        rows.append(("Segments", f"{info.segment_count} "
                                 f"({info.encrypted_segments} encrypted, "
                                 f"{info.compressed_segments} compressed)", False, None))
        rows.append(("Declared File Size", f"{info.file_size:,} bytes", False, None))
        if info.ext_info is not None:
            rows.extend([
                ("Authority ID", f"0x{info.ext_info.authority_id:016X}", False, None),
                ("App Version", format_packed_version(info.ext_info.app_version), False, None),
                ("Firmware Version", format_packed_version(info.ext_info.firmware_version), False, None),
                ("ELF Digest (SHA-256)", info.ext_info.digest.hex()[:32] + "…", False, None),
            ])
        self.groups.append({"title": "eboot.bin", "rows": rows})

    # ------------------------------------------------------------------
    # PS5 param.json
    # ------------------------------------------------------------------
    @staticmethod
    def _localized_title(parameters):
        if not isinstance(parameters, dict):
            return ""
        default = parameters.get("defaultLanguage")
        candidates = [default, "en-US", "en-GB"]
        candidates.extend(key for key, value in parameters.items() if isinstance(value, dict))
        for locale in candidates:
            value = parameters.get(locale) if locale else None
            if isinstance(value, dict) and value.get("titleName"):
                return str(value["titleName"])
        return ""

    def _parse_param_json(self, json_path):
        with open(json_path, "r", encoding="utf-8") as fp:
            data = json.load(fp)

        localized = data.get("localizedParameters", {})
        title_name = self._localized_title(localized)
        title_id = data.get("titleId", "")
        content_id = data.get("contentId", "")
        content_version = data.get("contentVersion", "")
        required_fw = data.get("requiredSystemSoftwareVersion", "")
        sdk_version = data.get("sdkVersion", "")

        self.gname = title_name
        self.gVer = content_version
        self.region = _region_from_content_id(content_id)
        self.sVer = _format_version(required_fw)[:5]

        # Build the Game group with readable labels (editable rows map back to
        # the param.json key so Save writes the right field).
        game_rows = []
        headline = [
            ("titleId", "Title ID"),
            ("contentId", "Content ID"),
            ("contentVersion", "Content Version"),
            ("masterVersion", "Master Version"),
            ("requiredSystemSoftwareVersion", "Required System Software"),
            ("sdkVersion", "SDK Version"),
            ("applicationCategoryType", "Application Category"),
            ("applicationDrmType", "DRM Type"),
            ("downloadDataSize", "Download Data Size"),
            ("massSize", "Mass Size"),
        ]
        for key, label in headline:
            if key not in data:
                continue
            value = data[key]
            if key in ("requiredSystemSoftwareVersion", "sdkVersion"):
                value = _format_version(value)
            elif key in ("downloadDataSize", "massSize"):
                value = _format_bytes(value)
            game_rows.append((label, value, True, key))
        if title_name:
            default_locale = localized.get("defaultLanguage") or "en-US"
            game_rows.insert(0, ("Title", title_name, True,
                                 f"localizedParameters.{default_locale}.titleName"))
        game_rows.insert(0, ("Region", self.region or "—", False, None))
        if game_rows:
            self.groups.append({"title": "Game", "rows": game_rows})

        # Everything else, flattened readably.  Complex nested objects are
        # skipped — the headline rows already cover the meaningful fields.
        metadata_rows = []
        for key in sorted(data):
            if key in dict(headline) or key in ("localizedParameters", "ageLevel",
                                                "gameIntent", "kernel"):
                continue
            value = data[key]
            if key == "pubtools":
                if isinstance(value, dict):
                    for sub_key in sorted(value):
                        if isinstance(value[sub_key], (dict, list)):
                            continue
                        label = PS5_JSON_LABELS.get(sub_key, f"pubtools.{sub_key}")
                        metadata_rows.append((label, value[sub_key], True, f"pubtools.{sub_key}"))
                continue
            if isinstance(value, (dict, list)):
                continue
            if key in ("versionFileUri", "deeplinkUri") and not str(value).strip():
                continue
            label = PS5_JSON_LABELS.get(key, key)
            metadata_rows.append((label, value, True, key))
        # Localized titles beyond the default are informative, not editable.
        if isinstance(localized, dict):
            for locale, loc_data in localized.items():
                if isinstance(loc_data, dict) and loc_data.get("titleName"):
                    metadata_rows.append(
                        (f"Title ({locale})", loc_data["titleName"], False, None)
                    )
        if isinstance(data.get("ageLevel"), dict):
            levels = data["ageLevel"]
            non_zero = {k: v for k, v in levels.items() if v not in (0, "0", "", None)}
            summary = f"{len(non_zero)} region(s)" if non_zero else "not rated"
            if non_zero:
                summary += f", max {max(non_zero.values())}"
            metadata_rows.append(("Age Rating", summary, False, None))
        if metadata_rows:
            self.groups.append({"title": "Metadata (param.json)", "rows": metadata_rows})

        # Flat compatibility dict.
        self.main_dict.update({"Title Name": title_name, "Content Version": content_version,
                               "Title ID": title_id, "Content ID": content_id,
                               "Required System Software Version": _format_version(required_fw),
                               "SDK Version": _format_version(sdk_version)})
        self.main_dict.update({key: data[key] for key in data
                               if not isinstance(data[key], (dict, list))})

    # ------------------------------------------------------------------
    # PS4 param.sfo
    # ------------------------------------------------------------------
    def _parse_param_sfo(self, sfo_path):
        with open(sfo_path, "rb") as fp:
            document = parse_sfo(fp.read())
        values = document.as_dict()

        content_id = values.get("CONTENT_ID", "")
        self.region = _region_from_content_id(content_id)

        game_rows = [
            ("Platform", "PS4", False, None),
            ("Region", self.region or "—", False, None),
        ]
        for key, label in (("TITLE", "Title"), ("TITLE_ID", "Title ID"),
                           ("CONTENT_ID", "Content ID"), ("APP_VER", "App Version"),
                           ("VERSION", "System Version")):
            if key in values:
                game_rows.append((label, values[key], False, None))
        if "CATEGORY" in values:
            code = values["CATEGORY"]
            game_rows.append(("Category", SFO_CATEGORIES.get(code, code), False, None))
        if "DOWNLOAD_DATA_SIZE" in values:
            game_rows.append(("Download Data Size", _format_bytes(values["DOWNLOAD_DATA_SIZE"]),
                              False, None))
        self.gname = str(values.get("TITLE", ""))
        self.gVer = str(values.get("APP_VER", ""))
        self.sVer = str(values.get("VERSION", ""))

        if game_rows:
            self.groups.append({"title": "Game", "rows": game_rows})

        metadata_rows = [
            (SFO_LABELS.get(key, key), value, False, None)
            for key, value in values.items()
            if key not in ("TITLE", "TITLE_ID", "CONTENT_ID", "APP_VER",
                           "VERSION", "CATEGORY", "DOWNLOAD_DATA_SIZE")
        ]
        if metadata_rows:
            self.groups.append({"title": "Metadata (param.sfo)", "rows": metadata_rows})

        self.main_dict.update(values)

    # ------------------------------------------------------------------
    # legacy helpers kept for compatibility
    # ------------------------------------------------------------------
    def convert_bytes(self, size):
        for unit in ["bytes", "KB", "MB", "GB", "TB"]:
            if size < 1024.0:
                return "%3.1f%s" % (size, unit)
            size /= 1024.0
        return size

    def folder_size(self, path="."):
        total = 0
        for item in Path(path).glob("**/*"):
            if item.is_file():
                total += item.stat().st_size
        return self.convert_bytes(total)

    def region_convertor(self, region):
        return {"UP": "US", "EP": "EU"}.get(region, region)

    def version_corrector(self, version):
        return _format_version(version)

    def load_eboot(self, file_path):
        """Load info from an eboot.bin file (kept for compatibility)."""
        self._parse_eboot(file_path)
        self.main_dict = {}
        for group in self.groups:
            for label, value, _editable, _target in group["rows"]:
                self.main_dict[label] = value
        return self.main_dict

    def save_param_json(self, file_path, changes):
        """Apply ``changes`` (target path -> value) to a param.json file.

        ``target`` may be a dotted path (e.g. ``localizedParameters.en-US.titleName``).
        """
        with open(file_path, "r", encoding="utf-8") as fp:
            data = json.load(fp)

        def set_path(node, path, value):
            parts = path.split(".")
            current = node
            for part in parts[:-1]:
                if not isinstance(current, dict) or part not in current:
                    return False
                current = current[part]
            if not isinstance(current, dict) or parts[-1] not in current:
                return False
            current[parts[-1]] = value
            return True

        applied = 0
        for target, value in changes.items():
            if not target:
                continue
            if set_path(data, target, value):
                applied += 1

        with open(file_path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, indent=4, ensure_ascii=False)
        return applied
