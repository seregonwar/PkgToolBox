# -*- mode: python ; coding: utf-8 -*-


import os
import sys
from PyInstaller.utils.hooks import collect_all

block_cipher = None

# Ottieni il percorso della directory corrente
current_dir = os.path.dirname(os.path.abspath('__main__'))

# Funzione per verificare l'esistenza di un file o una directory
def resource_path(relative_path):
    path = os.path.join(current_dir, relative_path)
    if not os.path.exists(path):
        print(f"Warning: {path} not found")
    return path

# Raccogli tutti i dati necessari per Crypto
crypto_datas, crypto_binaries, crypto_hiddenimports = collect_all('Crypto')

# Raccogli tutti i moduli in Utilities e file_operations
utilities_datas, utilities_binaries, utilities_hiddenimports = collect_all('Utilities')
file_operations_datas, file_operations_binaries, file_operations_hiddenimports = collect_all('file_operations')

# Includi il pacchetto dell'interfaccia grafica (serve per bundlare i JSON delle traduzioni)
gui_datas, gui_binaries, gui_hiddenimports = collect_all('GraphicUserInterface')

# Includi la cartella con gli strumenti PS3 necessari a runtime
ps3lib_tree = Tree(os.path.join('packages', 'ps3lib'), prefix=os.path.join('packages', 'ps3lib'))

# Percorso icona eseguibile
icon_path = resource_path(os.path.join('icons', 'icon.ico'))

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('PS4PKGToolTemp', 'PS4PKGToolTemp')] + utilities_datas + file_operations_datas + gui_datas,
    hiddenimports=['repack', 'gui', 'package', 'PS4_Passcode_Bruteforcer', 'PS5_Game_Info'] + 
                  utilities_hiddenimports + file_operations_hiddenimports + gui_hiddenimports,
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
    upx=True,
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
    ps3lib_tree,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='PkgToolBox',
)

# Crea una cartella per i file temporanei
temp_folder = 'PS4PKGToolTemp'
if not os.path.exists(temp_folder):
    os.makedirs(temp_folder)

# Copia la cartella PS4PKGToolTemp nell'eseguibile
import shutil
shutil.copytree(temp_folder, os.path.join(DISTPATH, temp_folder), dirs_exist_ok=True)

print(f"Build completed. Executable and libraries should be in {DISTPATH}")
