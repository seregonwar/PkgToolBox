from enum import Enum, IntEnum

class Type(Enum):
    PAID_STANDALONE_FULL = 1
    UPGRADABLE = 2
    DEMO = 3
    FREEMIUM = 4

class DRMType(IntEnum):
    NONE = 0x0
    PS4 = 0xF
    PS5 = 0x10

class ContentType(IntEnum):
    UNKNOWN = 0x0
    GAME_DATA = 0x4
    GAME_EXEC = 0x5
    PS1_EMU = 0x6
    PSP = 0x7
    THEME = 0x9
    WIDGET = 0xA
    LICENSE = 0xB
    VSH_MODULE = 0xC
    PSN_AVATAR = 0xD
    PSPGO = 0xE
    MINIS = 0xF
    NEOGEO = 0x10
    VMC = 0x11
    PS2_CLASSIC = 0x12
    PSP_REMASTERED = 0x14
    PSP2GD = 0x15
    PSP2AC = 0x16
    PSP2LA = 0x17
    PSM = 0x18
    WT = 0x19
    PSP2_THEME = 0x1F

class PackageType(IntEnum):
    UNKNOWN = 0x0
    PATCH = 0x10
    DISC_GAME_PATCH = 0x11
    HDD_GAME_PATCH = 0x12
    NO_EBOOT_BIN = 0x13
    DEMO = 0xA
    KEY = 0xC
    UPGRADABLE = 0xD

class PackageFlag(IntEnum):
    NO_FLAGS = 0x0
    EBOOT = 0x2
    REQUIRE_LICENSE = 0x4
    HDD_MC = 0x8
    CUMULATIVE_PATCH = 0x10
    RENAME_DIRECTORY = 0x40
    EDAT = 0x80
    EMULATOR = 0x200
    VSH_MODULE = 0x400
    DISC_BINDED = 0x800
    STORAGE_TYPE = 0x2000
    NON_GAME = 0x4000

class IROTag(Enum):
    SHAREFACTORY_THEME = 0x1
    SYSTEM_THEME = 0x2
