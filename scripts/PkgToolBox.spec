# -*- mode: python ; coding: utf-8 -*-


import os
import sys
from PyInstaller.utils.hooks import collect_all

block_cipher = None

# Root del progetto: parent della cartella che contiene questo .spec (scripts/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(SPEC)))

# Rendi importabili i package del progetto (GUI, Utilities, ...) anche quando
# il .spec viene eseguito da PyInstaller (che mette su sys.path solo scripts/)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Funzione per verificare l'esistenza di un file o una directory
def resource_path(relative_path):
    path = os.path.join(PROJECT_ROOT, relative_path)
    if not os.path.exists(path):
        print(f"Warning: {path} not found")
    return path

# Raccogli tutti i dati necessari per Crypto
crypto_datas, crypto_binaries, crypto_hiddenimports = collect_all('Crypto')

# Raccogli tutti i moduli in Utilities
utilities_datas, utilities_binaries, utilities_hiddenimports = collect_all('Utilities')

# Includi il pacchetto dell'interfaccia grafica (serve per bundlare i JSON delle traduzioni)
gui_datas, gui_binaries, gui_hiddenimports = collect_all('GUI')

# Percorso icona eseguibile (formato diverso per piattaforma)
def resolve_icon_path():
    if sys.platform == 'darwin':
        # macOS richiede un .icns
        icon = resource_path(os.path.join('icons', 'icon.icns'))
        return icon if os.path.exists(icon) else None
    elif sys.platform == 'win32':
        return resource_path(os.path.join('icons', 'icon.ico'))
    else:
        # Linux non supporta icone sull'eseguibile ELF
        return None

icon_path = resolve_icon_path()

# UPX è disponibile solo su Windows in questo progetto
use_upx = sys.platform == 'win32'

a = Analysis(
    [os.path.join(PROJECT_ROOT, 'main.py')],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=[(os.path.join(PROJECT_ROOT, 'PS4PKGToolTemp'), 'PS4PKGToolTemp'),
           (os.path.join(PROJECT_ROOT, 'icons'), 'icons'),
           (os.path.join(PROJECT_ROOT, 'logos'), 'logos'),
           (os.path.join(PROJECT_ROOT, 'assets'), 'assets')] + utilities_datas + gui_datas,
    hiddenimports=['tools.PS4_Passcode_Bruteforcer', 'tools.PS5_Game_Info'] +
                  utilities_hiddenimports + gui_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='PkgToolBox',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=use_upx,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)

# Crea le DLL separate
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=use_upx,
    upx_exclude=[],
    name='PkgToolBox',
)

# Su macOS impacchetta tutto in un .app bundle
if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='PkgToolBox.app',
        icon=icon_path,
        bundle_identifier='com.seregonwar.PkgToolBox',
        # Without NSHighResolutionCapable macOS renders the whole app at 1x
        # on Retina displays -> blurry/pixelated UI (PyInstaller #4337).
        info_plist={'NSHighResolutionCapable': True},
    )

# Copia la cartella PS4PKGToolTemp nell'output (serve per settings.json/trofei)
import shutil
temp_folder = os.path.join(PROJECT_ROOT, 'PS4PKGToolTemp')
if not os.path.exists(temp_folder):
    os.makedirs(temp_folder)
shutil.copytree(temp_folder, os.path.join(DISTPATH, 'PS4PKGToolTemp'), dirs_exist_ok=True)

print(f"Build completed. Executable and libraries should be in {DISTPATH}")
