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

a = Analysis(
    ['main.py'],
    pathex=[current_dir],
    binaries=crypto_binaries,
    datas=crypto_datas,
    hiddenimports=[
        'PyQt5',
        'PIL',
        'kiwisolver',
        'concurrent.futures',
        'Utilities',
        'Utilities.Trophy',
        'repack',
    ] + crypto_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='PkgToolBox',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# Crea una cartella per i file temporanei
temp_folder = 'PS4PKGToolTemp'
if not os.path.exists(temp_folder):
    os.makedirs(temp_folder)

# Copia la cartella PS4PKGToolTemp nell'eseguibile
import shutil
shutil.copytree(temp_folder, os.path.join(DISTPATH, temp_folder), dirs_exist_ok=True)

print(f"Build completed. Executable should be in {DISTPATH}")
