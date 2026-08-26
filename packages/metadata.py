"""Readable mappings and lightweight metadata inference for PS4/PS5."""

PS4_CONTENT_TYPES = {
    0x01: "Game Disc", 0x04: "App", 0x06: "Theme", 0x07: "Game Data",
    0x09: "Mini App", 0x0A: "Avatar Item", 0x0B: "Game Sharing",
    0x0D: "License / Activation", 0x0E: "Game Data Package",
    0x0F: "Theme Additional Content", 0x10: "PlayStation Store Content",
    0x11: "Music", 0x12: "Video", 0x14: "PS4 Game",
    0x15: "PS4 Application", 0x16: "PS4 Patch", 0x17: "PS4 Remaster",
    0x18: "PS4 DLC", 0x1A: "PS4 Full Game", 0x1B: "PS4 Patch",
    0x1C: "PS4 DLC",
}

PS4_DRM_TYPES = {
    0x00: "None", 0x01: "PlayStation Network", 0x02: "Local",
    0x03: "Free to Play", 0x0F: "PlayStation Now",
}

PS4_CONTENT_FLAGS = (
    (0x00100000, "FIRST_PATCH"), (0x00200000, "PATCHGO"),
    (0x00400000, "REMASTER"), (0x00800000, "PS_CLOUD"),
    (0x02000000, "GD_AC"), (0x04000000, "NON_GAME"),
    (0x08000000, "UNKNOWN_0x08000000"), (0x40000000, "SUBSEQUENT_PATCH"),
)


def describe_content_type(value: int) -> str:
    return PS4_CONTENT_TYPES.get(value, f"Unknown (0x{value:X})")


def describe_drm_type(value: int) -> str:
    return PS4_DRM_TYPES.get(value, f"Unknown (0x{value:X})")


def describe_content_flags(value: int) -> str:
    names = [name for mask, name in PS4_CONTENT_FLAGS if value & mask]
    names = [name for name in names if name != "SUBSEQUENT_PATCH"]
    if (value & 0x60000000) == 0x60000000:
        names.append("CUMULATIVE_PATCH")
    elif (value & 0x41000000) == 0x41000000:
        names.append("DELTA_PATCH")
    elif value & 0x40000000:
        names.append("SUBSEQUENT_PATCH")
    return ", ".join(dict.fromkeys(names)) or "None"


def infer_region(title_id: str | None, platform: str = "ps4") -> str:
    title_id = (title_id or "").upper()
    prefixes = {
        "CUSA": "North America / Europe", "PCAS": "Asia", "PCJS": "Japan",
        "PCSF": "Europe", "PCSB": "Europe", "PCSC": "Asia", "PCSD": "Asia",
        "PPSA": "North America / Europe", "ECAS": "Asia", "ELAS": "Asia",
        "ELJM": "Japan",
    }
    return prefixes.get(title_id[:4], "Unknown")
