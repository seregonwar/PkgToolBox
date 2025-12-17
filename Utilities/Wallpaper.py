import os
import sys

if sys.platform == "win32":
    import winreg
    import ctypes
else:
    winreg = None
    ctypes = None
import tempfile
from enum import Enum

class Style(Enum):
    Tiled = 0
    Centered = 1
    Stretched = 2

class Wallpaper:
    SPI_SETDESKWALLPAPER = 20
    SPIF_UPDATEINIFILE = 0x01
    SPIF_SENDWININICHANGE = 0x02

    @staticmethod
    def set(style: Style):
        if sys.platform != "win32":
            return
        path = os.path.join(tempfile.gettempdir(), "Saved image", "wallpaper.JPG")
        
        # Assicurarsi che la directory esista
        os.makedirs(os.path.dirname(path), exist_ok=True)

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", 0, winreg.KEY_SET_VALUE)
        if style == Style.Stretched:
            winreg.SetValueEx(key, "WallpaperStyle", 0, winreg.REG_SZ, "2")
            winreg.SetValueEx(key, "TileWallpaper", 0, winreg.REG_SZ, "0")
        elif style == Style.Centered:
            winreg.SetValueEx(key, "WallpaperStyle", 0, winreg.REG_SZ, "1")
            winreg.SetValueEx(key, "TileWallpaper", 0, winreg.REG_SZ, "0")
        elif style == Style.Tiled:
            winreg.SetValueEx(key, "WallpaperStyle", 0, winreg.REG_SZ, "1")
            winreg.SetValueEx(key, "TileWallpaper", 0, winreg.REG_SZ, "1")
        winreg.CloseKey(key)

        ctypes.windll.user32.SystemParametersInfoW(
            Wallpaper.SPI_SETDESKWALLPAPER,
            0,
            path,
            Wallpaper.SPIF_UPDATEINIFILE | Wallpaper.SPIF_SENDWININICHANGE
        )


