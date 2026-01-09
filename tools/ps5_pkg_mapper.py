import argparse
import json
import os
import sys
from typing import Dict, Any

# Ensure project root (PkgToolBox) is on sys.path when running as a script
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from packages import PackagePS4, PackagePS5
from tools.utils import Logger

IMPORTANT_SUFFIXES_PS5 = [
    "eboot.bin",
    "sce_sys/param.json",
    "sce_sys/icon0.png",
    "sce_sys/icon0.dds",
    "sce_sys/pic0.png",
    "sce_sys/pic0.dds",
    "sce_sys/pic1.png",
    "sce_sys/pic1.dds",
    "sce_sys/pic2.png",
    "sce_sys/pic2.dds",
    "sce_sys/playgo-chunk.dat",
    "sce_sys/playgo-ficm.dat",
    "sce_sys/playgo-hash-table.dat",
    "sce_sys/playgo-scenario.json",
    "sce_sys/trophy/trophy00.ucp",
    "sce_sys/trophy/trophy00.trp",
    "sce_sys/trophy2/trophy00.ucp",
    "sce_sys/nptitle.dat",
    "sce_sys/target-param.json",
    "sce_sys/origin-param.json",
]

# PS4 commonly observed filenames/paths 
IMPORTANT_SUFFIXES_PS4 = [
    "eboot.bin",
    "param.sfo",
    "icon0.png",
    "icon0.dds",
    "pic0.png",
    "pic0.dds",
    "pic1.png",
    "pic1.dds",
    "pic2.png",
    "pic2.dds",
    "playgo-chunk.dat",
    "playgo-chunk.sha",
    "playgo-manifest.xml",
    "app/playgo-chunk.dat",
    "changeinfo/changeinfo.xml",
]


def norm_path(p: str) -> str:
    if not p:
        return ""
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    if p.startswith("/"):
        p = p[1:]
    # Heuristic: fix inverted dir
    p = p.replace("sys_sce/", "sce_sys/").replace("/sys_sce/", "/sce_sys/")
    return p


def classify_name(name: str, suffixes) -> str:
    n = norm_path(name).lower()
    for suf in suffixes:
        if n.endswith(suf):
            return suf
    return "other"


def sniff_type(pkg_path: str, offset: int, size: int) -> Dict[str, Any]:
    """Read a small header at offset to guess file type/extension."""
    result = {"type": "unknown", "ext": None, "details": None}
    try:
        with open(pkg_path, "rb") as fp:
            fp.seek(int(offset))
            header = fp.read(min(64, max(0, int(size))))
        # Signatures
        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            return {"type": "image/png", "ext": ".png", "details": "PNG"}
        if header.startswith(b"DDS "):
            return {"type": "image/dds", "ext": ".dds", "details": "DDS"}
        if header.startswith(b"\xFF\xD8\xFF"):
            return {"type": "image/jpeg", "ext": ".jpg", "details": "JPEG"}
        if header.startswith(b"BM"):
            return {"type": "image/bmp", "ext": ".bmp", "details": "BMP"}
        if header.startswith(b"{") or header.startswith(b"["):
            return {"type": "application/json", "ext": ".json", "details": "JSON-like"}
        if header[:5].lower().startswith(b"<?xml") or header[:1] == b"<":
            return {"type": "text/xml", "ext": ".xml", "details": "XML-like"}
        if header.startswith(b"\x00PSF"):
            return {"type": "application/x-param-sfo", "ext": ".sfo", "details": "PARAM.SFO"}
        # Fallback: RIFF may indicate audio/container
        if header.startswith(b"RIFF"):
            return {"type": "audio/riff", "ext": ".riff", "details": "RIFF"}
    except Exception as e:
        result["details"] = f"sniff_error: {e}"
    return result


def maybe_export(pkg_path: str, entry: Dict[str, Any], export_dir: str) -> str:
    """Export entry bytes if sniffed type is an image. Returns output path or empty string."""
    if not export_dir:
        return ""
    sniff = entry.get("sniff", {})
    mime = sniff.get("type")
    ext = sniff.get("ext") or ".bin"
    if not mime or not mime.startswith("image/"):
        return ""
    try:
        os.makedirs(export_dir, exist_ok=True)
        out_name = f"{entry['id']}_{os.path.basename(entry.get('name') or '') or 'unnamed'}{ext}"
        out_name = out_name.replace('/', '_')
        out_path = os.path.join(export_dir, out_name)
        with open(pkg_path, "rb") as fp, open(out_path, "wb") as out:
            fp.seek(int(entry["offset"]))
            out.write(fp.read(int(entry["size"])))
        return out_path
    except Exception:
        return ""


def _detect_pkg_class(pkg_path: str):
    with open(pkg_path, "rb") as fp:
        magic_bytes = fp.read(4)
    magic = int.from_bytes(magic_bytes, byteorder="big", signed=False)
    Logger.log_information(f"Read magic number: {magic:08X}")
    # PS4 CNT magic: 0x7F434E54 ('\x7F' 'C' 'N' 'T')
    # PS5 magic observed: 0x7F464948 ('\x7F' 'F' 'I' 'H') and sometimes 0x7F504B47 ('\x7F' 'P' 'K' 'G')
    if magic == 0x7F434E54:
        return PackagePS4
    if magic in (0x7F504B47, 0x7F464948):
        return PackagePS5
    raise ValueError(f"Unknown PKG format: {magic:08X}")


def build_mapping(pkg_path: str, export_dir: str = "") -> Dict[str, Any]:
    PkgCls = _detect_pkg_class(pkg_path)
    pkg = PkgCls(pkg_path)
    suffixes = IMPORTANT_SUFFIXES_PS5 if isinstance(pkg, PackagePS5) else IMPORTANT_SUFFIXES_PS4

    mapping = {
        "package": os.path.basename(pkg_path),
        "size": os.path.getsize(pkg_path),
        "content_id": pkg.content_id,
        "title_id": getattr(pkg, "title_id", None),
        "platform": "PS5" if isinstance(pkg, PackagePS5) else "PS4",
        "entries": [],
        "important": {},
    }

    # PS5: annotate PFS region if available
    pfs_offset = getattr(pkg, "pfs_offset", None)
    pfs_size = getattr(pkg, "pfs_size", None)
    pfs_end = (pfs_offset + pfs_size) if isinstance(pfs_offset, int) and isinstance(pfs_size, int) else None

    # For PS5, also expose layout/digests to help diagnose encryption state
    if isinstance(pkg, PackagePS5):
        mapping["layout"] = {
            "fih_offset": getattr(pkg, "fih_offset", None),
            "fih_size": getattr(pkg, "fih_size", None),
            "pfs_offset": pfs_offset,
            "pfs_size": pfs_size,
            "sc_offset": getattr(pkg, "sc_offset", None),
            "sc_size": getattr(pkg, "sc_size", None),
            "si_offset": getattr(pkg, "si_offset", None),
            "si_size": getattr(pkg, "si_size", None),
            "package_digest": getattr(pkg, "package_digest", None),
            "pfs_area_digest": getattr(pkg, "pfs_area_digest", None),
        }

    files = getattr(pkg, "files", {}) or {}
    for file_id, info in files.items():
        name = norm_path(info.get("name", f"file_{file_id}"))
        cls = classify_name(name, suffixes)
        entry = {
            "id": file_id,
            "name": name,
            "offset": info.get("offset"),
            "size": info.get("size"),
            "encrypted": bool(info.get("encrypted", False)),
            "class": cls,
        }
        # Mark if the entry lies within PS5 PFS region
        if isinstance(entry["offset"], int) and isinstance(entry["size"], int) and pfs_end is not None:
            off = entry["offset"]
            entry["inside_pfs"] = (off >= pfs_offset and off < pfs_end)
        else:
            entry["inside_pfs"] = False
        # Content sniff to help classify unnamed entries (icons/images/json/xml)
        if entry["offset"] is not None and entry["size"]:
            entry["sniff"] = sniff_type(pkg_path, entry["offset"], entry["size"])
            # If still 'other' but we sniffed an image/json/xml, use ext as class hint
            if cls == "other" and entry["sniff"]["ext"]:
                entry["class"] = entry["sniff"]["ext"].lstrip('.')
        # Heuristic score for ranking candidates
        score = 0
        sz = int(entry["size"]) if entry["size"] else 0
        mime = entry.get("sniff", {}).get("type") if entry.get("sniff") else None
        if entry["class"] != "other":
            score += 2
        if mime and mime.startswith("image/"):
            score += 3
        if 4 * 1024 <= sz <= 8 * 1024 * 1024:
            score += 1
        if entry["encrypted"]:
            score -= 2
        if entry["inside_pfs"]:
            score -= 1
        entry["score"] = score
        # Optional export of images
        exported_to = maybe_export(pkg_path, entry, export_dir)
        if exported_to:
            entry["exported_to"] = exported_to
        mapping["entries"].append(entry)
        if cls != "other" and cls not in mapping["important"]:
            mapping["important"][cls] = entry

    mapping["summary"] = {
        "total_entries": len(mapping["entries"]),
        "important_found": sorted(list(mapping["important"].keys())),
        "missing_important": sorted([s for s in suffixes if s not in mapping["important"]]),
        "top_candidates": sorted(
            [
                {"id": e["id"], "name": e["name"], "class": e["class"], "score": e["score"], "sniff": e.get("sniff", {}), "inside_pfs": e.get("inside_pfs", False)}
                for e in mapping["entries"]
            ], key=lambda x: x["score"], reverse=True
        )[:10],
    }

    # If PS5 and zero entries, hint that it's likely encrypted/unsupported
    if isinstance(pkg, PackagePS5) and not mapping["entries"]:
        mapping["summary"]["note"] = "No entries available; package likely encrypted or unsupported without keys (entry table and layout are zero)."

    return mapping


def main():
    parser = argparse.ArgumentParser(description="Map PS5 PKG file entries and offsets into JSON report")
    parser.add_argument("pkg", help="Path to PS5 PKG file")
    parser.add_argument("-o", "--output", help="Output JSON path (default: <pkg>.map.json)")
    parser.add_argument("--export-dir", help="Directory to export detected images (PNG/DDS/JPEG/BMP)")
    args = parser.parse_args()

    pkg_path = os.path.abspath(args.pkg)
    if not os.path.isfile(pkg_path):
        raise SystemExit(f"File not found: {pkg_path}")

    try:
        Logger.log_information(f"Building mapping for: {pkg_path}")
        mapping = build_mapping(pkg_path, export_dir=args.export_dir or "")
        out_path = args.output or (pkg_path + ".map.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(mapping, f, indent=2, ensure_ascii=False)
        Logger.log_information(f"Mapping written: {out_path}")
        print(out_path)
    except Exception as e:
        Logger.log_error(f"Mapping failed: {e}")
        raise


if __name__ == "__main__":
    main()
