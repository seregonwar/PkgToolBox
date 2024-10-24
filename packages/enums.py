from enum import Enum

class Type(Enum):
    PAID_STANDALONE_FULL = 1
    UPGRADABLE = 2
    DEMO = 3
    FREEMIUM = 4

class DRMType(Enum):
    NONE = 0x0
    PS4 = 0xF
    PS5 = 0x10

class ContentType(Enum):
    CONTENT_TYPE_GD = 0x1A
    CONTENT_TYPE_AC = 0x1B
    CONTENT_TYPE_AL = 0x1C
    CONTENT_TYPE_DP = 0x1E

class IROTag(Enum):
    SHAREFACTORY_THEME = 0x1
    SYSTEM_THEME = 0x2
