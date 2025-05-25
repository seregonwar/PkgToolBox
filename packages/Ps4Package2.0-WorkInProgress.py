#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-FileCopyrightText: Copyright 2025 (Python port by SeregonWar)
# SPDX-License-Identifier: GPL-2.0-or-later
# Module complete with decryption, rsa/AES key derivation and unpacking ps4 pkg files.
# based on https://github.com/shadps4-emu/shadPS4/tree/main/src/core

import struct
import zlib
import os
import pathlib
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import hashlib # Per SHA256 (usato in HMAC)
import threading
from enum import IntEnum, Flag
from dataclasses import dataclass, field
from typing import Optional # Aggiunto per Optional

# PyCryptodome
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5 as Cipher_PKCS1_v1_5 # Per RSA PKCS#1 v1.5
from Crypto.Hash import SHA256, HMAC # Per PfsGenCryptoKey

from pkg_entry import PKG_ENTRY_ID_TO_NAME_FULL
from key import FakeKeyset, PkgDerivedKey3Keyset




# --- Costanti e Definizioni Strutture (aggiornate da .h forniti) ---
PFSC_MAGIC = 0x43534650  # "PFSC"
PKG_MAGIC_BE = 0x7F434E54   # ".CNT" (Big Endian nel file)
PKG_MAGIC_LE_VARIANT = 0x544E437F # "TNC\x7f" (Little Endian variant found in some files)



class PKGContentFlag(Flag): # Da pkg.h
    FIRST_PATCH = 0x100000
    PATCHGO = 0x200000
    REMASTER = 0x400000
    PS_CLOUD = 0x800000
    GD_AC = 0x2000000
    NON_GAME = 0x4000000
    UNKNOWN_0x8000000 = 0x8000000
    SUBSEQUENT_PATCH = 0x40000000
    DELTA_PATCH = 0x41000000
    CUMULATIVE_PATCH = 0x60000000

    # Flag aggiuntivi dal vecchio codice se ancora rilevanti o se diversi da pkg_header.pkg_content_flags
    # Questi erano nella lista FLAG_NAMES che ho usato prima, potrebbero non essere parte di PKGContentFlag
    # ma piuttosto di pkgheader.pkg_flags o pkg_content_flags in generale
    # PLAYGO = 0x00000001
    # DEBUG = 0x00000002
    # FSELF = 0x00000004
    # ... e così via. Bisogna distinguere chiaramente quali flag appartengono a quale campo.
    # Per ora, mi concentro su quelli esplicitamente in enum class PKGContentFlag

PKG_FLAG_NAMES_MAP = {
    PKGContentFlag.FIRST_PATCH: "FIRST_PATCH",
    PKGContentFlag.PATCHGO: "PATCHGO",
    PKGContentFlag.REMASTER: "REMASTER",
    PKGContentFlag.PS_CLOUD: "PS_CLOUD",
    PKGContentFlag.GD_AC: "GD_AC",
    PKGContentFlag.NON_GAME: "NON_GAME",
    PKGContentFlag.UNKNOWN_0x8000000: "UNKNOWN_0x8000000",
    PKGContentFlag.SUBSEQUENT_PATCH: "SUBSEQUENT_PATCH",
    PKGContentFlag.DELTA_PATCH: "DELTA_PATCH",
    PKGContentFlag.CUMULATIVE_PATCH: "CUMULATIVE_PATCH"
}

# Funzioni helper mancanti (implementazioni placeholder)
def get_pfsc_offset(data: bytes, logger_func=print) -> int:
    magic_bytes = PFSC_MAGIC.to_bytes(4, 'little')
    start_offset = 0x20000
    
    logger_func(f"Ricerca PFSC magic 0x{PFSC_MAGIC:08X} in {len(data)} bytes di dati PFS decrittati")
    logger_func(f"Start offset: 0x{start_offset:08X}")
    
    if len(data) < start_offset:
        logger_func(f"Dati insufficienti: {len(data)} < {start_offset}")
        return -1
    
    # Prova prima una ricerca completa per il magic
    magic_positions = []
    for i in range(0, len(data) - 4, 4):
        if data[i:i+4] == magic_bytes:
            magic_positions.append(i)
    
    if magic_positions:
        logger_func(f"Magic PFSC trovato alle posizioni: {[hex(pos) for pos in magic_positions]}")
        # Restituisci la prima posizione valida >= start_offset se esiste
        for pos in magic_positions:
            if pos >= start_offset:
                return pos
        # Altrimenti restituisci la prima posizione trovata
        return magic_positions[0]
    
    # Fallback alla ricerca originale con step 0x10000
    logger_func("Ricerca con step 0x10000...")
    current_search_offset = start_offset
    search_count = 0
    while current_search_offset < len(data) and search_count < 100:  # Limite di sicurezza
        # Leggi u32 all'offset corrente
        if current_search_offset + 4 > len(data):
            break # Non abbastanza dati per leggere un u32
        
        value = struct.unpack_from("<I", data, current_search_offset)[0]
        if search_count < 10:  # Log solo i primi 10 tentativi
            logger_func(f"Offset 0x{current_search_offset:08X}: 0x{value:08X}")
        
        if value == PFSC_MAGIC:
            logger_func(f"PFSC magic trovato all'offset 0x{current_search_offset:08X}")
            return current_search_offset
        current_search_offset += 0x10000
        search_count += 1
        logger_func(f"PFSC magic NON trovato dopo {search_count} tentativi")
    
    # Debug aggiuntivo: controlla i primi bytes dell'immagine decrittata
    if len(data) >= 64:
        logger_func(f"Primi 64 bytes dell'immagine PFS decrittata: {data[:64].hex()}")
    
    # Debug: cerca il magic in entrambi gli endianness
    magic_be = PFSC_MAGIC.to_bytes(4, 'big')  # Big endian
    magic_le = PFSC_MAGIC.to_bytes(4, 'little')  # Little endian
    
    logger_func(f"Cerco magic BE (0x43534650): {magic_be.hex()}")
    logger_func(f"Cerco magic LE (0x50465343): {magic_le.hex()}")
    
    # Cerca in tutto il buffer senza step
    for i in range(len(data) - 4):
        if data[i:i+4] == magic_be:
            logger_func(f"Magic PFSC (BE) trovato all'offset 0x{i:08X}")
            return i
        if data[i:i+4] == magic_le:
            logger_func(f"Magic PFSC (LE) trovato all'offset 0x{i:08X}")
            return i
    
    # Cerca pattern simili (potrebbero essere corrupted)
    logger_func("Cercando pattern simili a PFSC...")
    possible_patterns = [
        b'PFSC', b'CFSP', b'SCPF', b'SPFC',  # Permutazioni
        b'\x50\x46\x53\x43', b'\x43\x53\x46\x50'  # Espliciti
    ]
    
    for pattern in possible_patterns:
        for i in range(len(data) - 4):
            if data[i:i+4] == pattern:
                logger_func(f"Pattern simile '{pattern}' trovato all'offset 0x{i:08X}")
    
    return -1

def decompress_pfsc(compressed_data: bytes, decompressed_size: int, logger_func=print) -> bytes:
    """Optimized PFSC decompression function with support for multiple compression methods."""
    compressed_data_len = len(compressed_data)
    
    # Only log for smaller compressed data to reduce I/O overhead
    is_verbose = compressed_data_len < 1000000
    
    if is_verbose:
        logger_func(f"DEBUG decompress_pfsc: Dati compressi: {compressed_data_len} bytes, decompressione attesa: {decompressed_size} bytes")
    
    if compressed_data_len == 0:
        if is_verbose:
            logger_func("DEBUG decompress_pfsc: ERRORE - Dati compressi vuoti (0 bytes)")
        return b'\0' * decompressed_size
    
    # Check first few bytes for debugging
    if is_verbose:
        sample_size = min(32, compressed_data_len)
        logger_func(f"DEBUG decompress_pfsc: Primi {sample_size} bytes: {compressed_data[:sample_size].hex()}")
        if all(b == 0 for b in compressed_data[:min(100, compressed_data_len)]):
            logger_func("DEBUG decompress_pfsc: AVVISO - Dati compressi sembrano essere tutti zeri")
    
    # Cache for performance
    global _pfsc_decompress_cache
    cache_key = None
    
    # Try multiple decompression methods
    methods = [
        # Method 1: Raw deflate (no header)
        {'name': 'raw deflate (-MAX_WBITS)', 'wbits': -zlib.MAX_WBITS, 'offset': 0},
        # Method 2: Standard zlib
        {'name': 'standard zlib (15)', 'wbits': zlib.MAX_WBITS, 'offset': 0},
        # Method 3: Raw deflate with 2-byte header
        {'name': 'raw deflate with 2-byte header', 'wbits': -zlib.MAX_WBITS, 'offset': 2},
        # Method 4: Gzip
        {'name': 'gzip (16+MAX_WBITS)', 'wbits': 16 + zlib.MAX_WBITS, 'offset': 0},
    ]
    
    for method in methods:
        try:
            if method['offset'] > 0 and compressed_data_len > method['offset']:
                data_to_decompress = compressed_data[method['offset']:]
                if is_verbose:
                    logger_func(f"DEBUG decompress_pfsc: Provo metodo '{method['name']}' con offset {method['offset']}")
            else:
                data_to_decompress = compressed_data
                if is_verbose:
                    logger_func(f"DEBUG decompress_pfsc: Provo metodo '{method['name']}'")            
            
            decompressor = zlib.decompressobj(method['wbits'])
            decompressed = decompressor.decompress(data_to_decompress)
            decompressed += decompressor.flush()
            
            if is_verbose:
                logger_func(f"DEBUG decompress_pfsc: Successo con {method['name']}! Dimensione: {len(decompressed)} bytes")
            
            # Handle size adjustments
            if len(decompressed) < decompressed_size:
                if is_verbose:
                    logger_func(f"DEBUG decompress_pfsc: Aggiungo padding: {decompressed_size - len(decompressed)} bytes")
                decompressed += b'\0' * (decompressed_size - len(decompressed))
            elif len(decompressed) > decompressed_size:
                if is_verbose:
                    logger_func(f"DEBUG decompress_pfsc: Troncamento: {len(decompressed) - decompressed_size} bytes")
                decompressed = decompressed[:decompressed_size]
            
            # Cache the result if we have a cache key
            if '_pfsc_decompress_cache' in globals():
                if cache_key is None and compressed_data_len > 64:
                    # Assicuriamoci che compressed_data sia sempre bytes e non bytearray
                    data_bytes = bytes(compressed_data)
                    # Utilizza i primi e ultimi 32 byte come parte della chiave di cache
                    cache_key = (bytes(data_bytes[:32]), bytes(data_bytes[-32:]), compressed_data_len, decompressed_size)
                
                if cache_key is not None:
                    try:
                        if len(_pfsc_decompress_cache) > 100:  # Limit cache size
                            _pfsc_decompress_cache.clear()
                        _pfsc_decompress_cache[cache_key] = decompressed
                    except TypeError as cache_error:
                        # Se si verifica un errore di tipo con la cache, lo logghiamo ma continuiamo
                        if is_verbose:
                            logger_func(f"DEBUG decompress_pfsc: Errore cache: {cache_error}. Tipo di cache_key: {type(cache_key)}")
            
            if is_verbose:
                sample_size = min(32, len(decompressed))
                logger_func(f"DEBUG decompress_pfsc: Primi {sample_size} bytes: {decompressed[:sample_size].hex()}")
            
            return decompressed
            
        except zlib.error as e:
            if is_verbose:
                logger_func(f"DEBUG decompress_pfsc: Fallito metodo '{method['name']}': {str(e)}")
            continue
    
    # If we get here, all decompression methods failed
    if is_verbose:
        logger_func(f"DEBUG decompress_pfsc: Tutti i metodi di decompressione falliti. Restituisco buffer di zeri ({decompressed_size} bytes)")
    
    return b'\0' * decompressed_size

@dataclass
class PKGHeader:
    _FIELDS_SPEC = [
        ('magic', 'I'), ('pkg_type', 'I'), ('pkg_0x8', 'I'), ('pkg_file_count', 'I'),
        ('pkg_table_entry_count', 'I'), ('pkg_sc_entry_count', 'H'), ('pkg_table_entry_count_2', 'H'),
        ('pkg_table_entry_offset', 'I'), ('pkg_sc_entry_data_size', 'I'), ('pkg_body_offset', 'Q'),
        ('pkg_body_size', 'Q'), ('pkg_content_offset', 'Q'), ('pkg_content_size', 'Q'),
        ('pkg_content_id', '36s'), ('pkg_padding', '12s'), ('pkg_drm_type', 'I'),
        ('pkg_content_type', 'I'), ('pkg_content_flags', 'I'), ('pkg_promote_size', 'I'),
        ('pkg_version_date', 'I'), ('pkg_version_hash', 'I'), ('pkg_0x088', 'I'),
        ('pkg_0x08C', 'I'), ('pkg_0x090', 'I'), ('pkg_0x094', 'I'), ('pkg_iro_tag', 'I'),
        ('pkg_drm_type_version', 'I'), ('pkg_zeroes_1', '96s'), ('digest_entries1', '32s'),
        ('digest_entries2', '32s'), ('digest_table_digest', '32s'), ('digest_body_digest', '32s'),
        ('pkg_zeroes_2', '640s'), ('pkg_0x400', 'I'), ('pfs_image_count', 'I'),
        ('pfs_image_flags', 'Q'), ('pfs_image_offset', 'Q'), ('pfs_image_size', 'Q'),
        ('mount_image_offset', 'Q'), ('mount_image_size', 'Q'), ('pkg_size', 'Q'),
        ('pfs_signed_size', 'I'), ('pfs_cache_size', 'I'), ('pfs_image_digest', '32s'),
        ('pfs_signed_digest', '32s'), ('pfs_split_size_nth_0', 'Q'), ('pfs_split_size_nth_1', 'Q'),
        ('pkg_zeroes_3', '2896s'), 
        ('pkg_digest', '32s')
    ]
    # La dimensione totale dell'header nel file C++ è implicitamente gestita da file.Read(pkgheader).
    # Sembra che `sizeof(PKGHeader)` sia 0x1000 (4096 bytes)
    # Dobbiamo calcolare la dimensione dei pkg_zeroes_3 e pkg_digest per il formato struct.
    
    _FORMAT_FULL = ">" + "".join(item[1] for item in _FIELDS_SPEC)
    _TOTAL_PKGHEADER_SIZE = struct.calcsize(_FORMAT_FULL)


    magic: int
    pkg_type: int
    pkg_0x8: int
    pkg_file_count: int
    pkg_table_entry_count: int
    pkg_sc_entry_count: int
    pkg_table_entry_count_2: int
    pkg_table_entry_offset: int
    pkg_sc_entry_data_size: int
    pkg_body_offset: int
    pkg_body_size: int
    pkg_content_offset: int
    pkg_content_size: int
    pkg_content_id: bytes
    pkg_padding: bytes
    pkg_drm_type: int
    pkg_content_type: int
    pkg_content_flags: int
    pkg_promote_size: int
    pkg_version_date: int
    pkg_version_hash: int
    pkg_0x088: int
    pkg_0x08C: int
    pkg_0x090: int
    pkg_0x094: int
    pkg_iro_tag: int
    pkg_drm_type_version: int
    pkg_zeroes_1: bytes
    digest_entries1: bytes
    digest_entries2: bytes
    digest_table_digest: bytes
    digest_body_digest: bytes
    pkg_zeroes_2: bytes
    pkg_0x400: int
    pfs_image_count: int
    pfs_image_flags: int
    pfs_image_offset: int
    pfs_image_size: int
    mount_image_offset: int
    mount_image_size: int
    pkg_size: int
    pfs_signed_size: int
    pfs_cache_size: int
    pfs_image_digest: bytes
    pfs_signed_digest: bytes
    pfs_split_size_nth_0: int
    pfs_split_size_nth_1: int
    pkg_zeroes_3: bytes
    pkg_digest: bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls._TOTAL_PKGHEADER_SIZE:
            raise ValueError(f"Dati PKGHeader insuff. Richiesti {cls._TOTAL_PKGHEADER_SIZE}, forniti {len(data)}")
        values = struct.unpack(cls._FORMAT_FULL, data[:cls._TOTAL_PKGHEADER_SIZE])
        return cls(*values)


@dataclass
class PKGEntry:
    _FORMAT = ">IIIIIIQ"
    _SIZE = struct.calcsize(_FORMAT)
    
    id: int = 0
    filename_offset: int = 0
    flags1: int = 0
    flags2: int = 0
    offset: int = 0
    size: int = 0
    padding: int = 0
    name: str = ""

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls._SIZE:
            raise ValueError(f"Dati PKGEntry insuff. Richiesti {cls._SIZE}, forniti {len(data)}")
        id_val, fn_off, f1, f2, off, sz, pad = struct.unpack(cls._FORMAT, data)
        return cls(id_val, fn_off, f1, f2, off, sz, pad)



# --- Strutture da pfs.h ---
class PfsMode(Flag): # pfs.h
    NoneFlag = 0 # Rinominato per evitare conflitto con None keyword
    Signed = 0x1
    Is64Bit = 0x2
    Encrypted = 0x4
    UnknownFlagAlwaysSet = 0x8

@dataclass
class PFSHeaderPfs: # da pfs.h PSFHeader_ (struct con underscore)
    _FIELDS_SPEC = [ # Lista di tuple (nome_campo, formato_struct_senza_endian)
        ('version', 'q'), ('magic', 'q'), ('id', 'q'),
        ('fmode', 'B'), ('clean', 'B'), ('read_only', 'B'), ('rsv', 'B'),
        ('mode', 'H'), ('unk1', 'h'), ('block_size', 'i'), ('n_backup', 'i'),
        ('n_block', 'q'), ('dinode_count', 'q'), ('nd_block', 'q'),
        ('dinode_block_count', 'q'), ('superroot_ino', 'q')
    ]
    # Anteponi '<' per Little Endian all'intera stringa di formato
    _FORMAT = "<" + "".join(item[1] for item in _FIELDS_SPEC)
    _SIZE = struct.calcsize(_FORMAT)

    # Definizione dei campi per il costruttore __init__ generato da dataclass
    # (mantenere l'ordine di _FIELDS_SPEC)
    version: int
    magic: int
    id: int
    fmode: int
    clean: int
    read_only: int
    rsv: int
    mode: PfsMode # Sarà un int dopo unpack, convertire a PfsMode
    unk1: int
    block_size: int
    n_backup: int
    n_block: int
    dinode_count: int
    nd_block: int
    dinode_block_count: int
    superroot_ino: int

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls._SIZE:
            raise ValueError(f"Data too small for PFSHeaderPfs. Need at least {cls._SIZE} bytes, got {len(data)}")
        
        # Print detailed debug information about the input data
        print("\n=== PFS Header Debug Information ===")
        print(f"Data length: {len(data)} bytes")
        print(f"Expected size: {cls._SIZE} bytes")
        
        # Print first 64 bytes in hex
        hex_dump = []
        for i in range(0, min(64, len(data)), 8):
            chunk = data[i:i+8]
            hex_str = ' '.join(f"{b:02x}" for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hex_dump.append(f"{i:04x}: {hex_str.ljust(23)} {ascii_str}")
        
        print("First 64 bytes of data:")
        print('\n'.join(hex_dump))
        
        # Try to find known magic numbers in the data
        known_magics = {
            b'PSF0': 'PSF0 (standard PFS)',
            b'\x01\x00\x00\x00': 'Version 1 PFS (common in PKG files)'
        }
        
        for magic, desc in known_magics.items():
            magic_pos = data.find(magic)
            if magic_pos != -1:
                print(f"\nFound known magic '{magic.hex()}' ({desc}) at position: 0x{magic_pos:04x}")
                if magic_pos > 0:
                    print(f"  Data before magic: {data[magic_pos-8:magic_pos].hex()}")
                print(f"  Magic context: {data[magic_pos:magic_pos+16].hex()}")
        
        # Unpack the data
        try:
            values = struct.unpack_from(cls._FORMAT, data)
        except struct.error as e:
            print(f"\nERROR: Failed to unpack data: {e}")
            print(f"Format string: {cls._FORMAT}")
            print(f"Data length: {len(data)} bytes")
            raise
        
        # Print all unpacked values for debugging
        print("\nUnpacked values:")
        for (name, fmt), value in zip(cls._FIELDS_SPEC, values):
            print(f"  {name:<18} ({fmt}): {value} (0x{value:x})")
        
        # Create instance with all required fields
        header = cls(
            version=values[0],
            magic=values[1],
            id=values[2],
            fmode=values[3],
            clean=values[4],
            read_only=values[5],
            rsv=values[6],
            mode=values[7],
            unk1=values[8],
            block_size=values[9],
            n_backup=values[10],
            n_block=values[11],
            dinode_count=values[12],
            nd_block=values[13],
            dinode_block_count=values[14],
            superroot_ino=values[15]
        )
        
        # Set attributes individually for better error reporting
        for i, ((name, _), value) in enumerate(zip(cls._FIELDS_SPEC, values)):
            try:
                # Special handling for mode field to convert to PfsMode enum
                if name == 'mode':
                    value = PfsMode(value)
                setattr(header, name, value)
            except Exception as e:
                print(f"Error setting field {name} to value {value}: {e}")
                raise
        
        # Debug logging
        print("\nParsed PFS Header:")
        print(f"  Magic:           0x{header.magic:016x}")
        print(f"  Version:         {header.version}")
        print(f"  dinode_count:    {header.dinode_count}")
        print(f"  superroot_ino:   {header.superroot_ino}")
        print(f"  block_size:      {header.block_size}")
        print(f"  n_block:         {header.n_block}")
        print(f"  dinode_count:    {header.dinode_count}")
        print(f"  dinode_block_count: {header.dinode_block_count}")
        
        # Handle different magic numbers
        expected_magic = 0x30534650  # 'PSF0' in little endian
        if header.magic == 0x01332a0b:  # Common alternative magic
            print("\nNOTE: Detected alternative PFS magic 0x01332a0b (20130315)")
            print("This is a valid PFS header with version 1.")
            # For this format, superroot_ino might be 0, so we'll need to handle that
            if header.superroot_ino == 0:
                print("  superroot_ino is 0, will use inode 1 as root directory")
                header.superroot_ino = 1  # Use inode 1 as root
        elif header.magic != expected_magic:
            print(f"\nWARNING: Unexpected PFS magic: 0x{header.magic:08x} (expected 0x30534650)")
            print("This could indicate:")
            print("1. The data is at the wrong offset")
            print("2. The file is corrupted")
            print("3. The file format is not as expected")
        
        print("=== End of PFS Header Debug ===\n")
        
        return header

@dataclass
class PFSCHdrPFS: # Da pfs.h struct PFSCHdr
    _FIELDS_SPEC = [
        ('magic', 'i'), ('unk4', 'i'), ('unk8', 'i'), ('block_sz', 'i'),
        ('block_sz2', 'q'), ('block_offsets', 'q'), ('data_start', 'Q'), ('data_length', 'q')
    ]
    _FORMAT = "<" + "".join(item[1] for item in _FIELDS_SPEC)
    _SIZE = struct.calcsize(_FORMAT)

    magic: int
    unk4: int
    unk8: int
    block_sz: int
    block_sz2: int
    block_offsets: int
    data_start: int
    data_length: int

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls._SIZE:
            raise ValueError(f"Dati PFSCHdrPFS insuff. Richiesti {cls._SIZE}, forniti {len(data)}.")
        values = struct.unpack_from(cls._FORMAT, data, 0)
        return cls(*values)


class InodeMode(Flag): # pfs.h
    o_read = 1
    o_write = 2
    o_execute = 4
    g_read = 8
    g_write = 16
    g_execute = 32
    u_read = 64
    u_write = 128
    u_execute = 256
    dir = 16384  # S_IFDIR (0o040000)
    file = 32768 # S_IFREG (0o100000)
    # S_IFLNK (0o120000) non è qui, ma gestito in get_file_type in Python

class InodeFlags(Flag): # pfs.h
    compressed = 0x1
    unk1 = 0x2 # ... e così via
    readonly = 0x10
    internal = 0x20000

class InodeModePfs(Flag):
    o_read = 1; o_write = 2; o_execute = 4
    g_read = 8; g_write = 16; g_execute = 32
    u_read = 64; u_write = 128; u_execute = 256
    dir = 16384; file = 32768

class InodeFlagsPfs(Flag): # da pfs.h InodeFlags (enum)
    compressed = 0x1
    unk1 = 0x2
    unk2 = 0x4
    unk3 = 0x8
    readonly = 0x10
    unk4 = 0x20
    unk5 = 0x40
    unk6 = 0x80
    unk7 = 0x100
    unk8 = 0x200
    unk9 = 0x400
    unk10 = 0x800
    unk11 = 0x1000
    unk12 = 0x2000
    unk13 = 0x4000
    unk14 = 0x8000
    unk15 = 0x10000
    internal = 0x20000

@dataclass
class Inode: # Da pfs.h struct Inode
    _FIELDS_SPEC = [
        ('Mode', 'H'), ('Nlink', 'H'), ('Flags', 'I'), ('Size', 'q'), ('SizeCompressed', 'q'),
        ('Time1_sec', 'q'), ('Time2_sec', 'q'), ('Time3_sec', 'q'), ('Time4_sec', 'q'),
        ('Time1_nsec', 'I'), ('Time2_nsec', 'I'), ('Time3_nsec', 'I'), ('Time4_nsec', 'I'),
        ('Uid', 'I'), ('Gid', 'I'), ('Unk1', 'Q'), ('Unk2', 'Q'),
        ('Blocks', 'I'), ('loc', 'I')
    ]
    _FORMAT_BASE_TYPES_ONLY = "".join(item[1] for item in _FIELDS_SPEC)
    _FORMAT_BASE = "<" + _FORMAT_BASE_TYPES_ONLY
    _SIZE_BASE = struct.calcsize(_FORMAT_BASE)
    _PADDING_SIZE = 0xA8 - _SIZE_BASE
    if _PADDING_SIZE < 0: raise Exception(f"Formato Inode troppo grande: {_SIZE_BASE} vs 0xA8")
    _FORMAT_FULL = _FORMAT_BASE + (f"{_PADDING_SIZE}x" if _PADDING_SIZE > 0 else "")
    _SIZE = 0xA8

    Mode: int; Nlink: int; Flags: InodeFlagsPfs; Size: int; SizeCompressed: int
    Time1_sec: int; Time2_sec: int; Time3_sec: int; Time4_sec: int
    Time1_nsec: int; Time2_nsec: int; Time3_nsec: int; Time4_nsec: int
    Uid: int; Gid: int; Unk1: int; Unk2: int
    Blocks: int; loc: int

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls._SIZE_BASE: # Controlla contro la dimensione dei dati effettivamente spacchettati
            raise ValueError(f"Dati Inode insuff. per unpack. Richiesti {cls._SIZE_BASE}, forniti {len(data)}.")
        values = list(struct.unpack_from(cls._FORMAT_BASE, data, 0))
        flags_idx = next(i for i, spec in enumerate(cls._FIELDS_SPEC) if spec[0] == 'Flags')
        values[flags_idx] = InodeFlagsPfs(values[flags_idx])
        return cls(*values)

    def get_file_type(self) -> 'PFSFileType':
        if self.Mode == 0: return PFSFileType.PFS_INVALID
        mode_val = InodeModePfs(self.Mode)
        if InodeModePfs.dir in mode_val: return PFSFileType.PFS_DIR
        if InodeModePfs.file in mode_val: return PFSFileType.PFS_FILE
        return PFSFileType.PFS_INVALID



class PFSFileType(IntEnum):
    PFS_INVALID = 0
    PFS_FILE = 2
    PFS_DIR = 3
    PFS_CURRENT_DIR = 4
    PFS_PARENT_DIR = 5

@dataclass
class Dirent: # Da pfs.h
    _FORMAT_BASE = "<iiii" # ino, type, namelen, entsize (tutti s32 Little Endian)
    _NAME_BUFFER_SIZE = 512 # Definizione della costante
    _BASE_SIZE = struct.calcsize(_FORMAT_BASE) # Dimensione base senza nome
    _SIZE_BASE = _BASE_SIZE  # Aggiunto per compatibilità
    _SIZE = _BASE_SIZE + _NAME_BUFFER_SIZE # Dimensione totale con buffer nome pieno

    ino: int = 0
    type: int = 0 # Valori come PFS_FILE, PFS_DIR da pkg.cpp
    namelen: int = 0
    entsize: int = 0
    name_bytes: bytes = field(default_factory=lambda: b'\0'*Dirent._NAME_BUFFER_SIZE) # Raw name bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        # entsize indica la dimensione totale del dirent, inclusi padding e nome.
        # Leggiamo prima i campi fissi.
        base_size = struct.calcsize(cls._FORMAT_BASE)
        if len(data) < base_size:
            raise ValueError("Dati Dirent insufficienti per i campi base.")

        ino, type_val, namelen, entsize = struct.unpack_from(cls._FORMAT_BASE, data, 0)
        
        # Il nome effettivo è lungo `namelen`, il resto fino a `entsize` è padding (o fino a 512 se entsize è più grande)
        # Il buffer `name` in C++ è 512.
        # `std::string(dirent.name, dirent.namelen);` indica che solo namelen byte sono usati.
        actual_name_bytes = data[base_size : base_size + namelen]
        
        # Riempi name_bytes con il nome e il padding fino a 512, se necessario,
        # o tronca se namelen è > 512 (improbabile).
        full_name_buffer = bytearray(cls._NAME_BUFFER_SIZE)
        bytes_to_copy_to_buffer = min(namelen, cls._NAME_BUFFER_SIZE)
        full_name_buffer[:bytes_to_copy_to_buffer] = actual_name_bytes[:bytes_to_copy_to_buffer]

        return cls(ino, type_val, namelen, entsize, bytes(full_name_buffer))

    @property
    def name(self) -> str:
        try:
            return self.name_bytes[:self.namelen].decode('utf-8').rstrip('\0')
        except UnicodeDecodeError:
            return self.name_bytes[:self.namelen].hex() # Fallback

    def get_pfs_file_type(self) -> PFSFileType:
        # La logica in pkg.cpp usa dirent.type direttamente e lo confronta
        # con costanti come PFS_FILE, PFS_DIR.
        # Quindi, il valore di self.type dovrebbe già essere uno di PFSFileType.
        try:
            return PFSFileType(self.type)
        except ValueError:
            # Se self.type non è un valore valido in PFSFileType, cosa fare?
            # Potrebbe essere un tipo sconosciuto o un errore.
            # La logica C++ non sembra avere un fallback qui, implica che i tipi sono noti.
            # print(f"Warning: Dirent.type sconosciuto: {self.type} per '{self.name}'")
            return PFSFileType.PFS_INVALID


@dataclass
class FSTableEntry:
    name: str
    inode: int
    type: PFSFileType

# --- PKG Class (iniziata la revisione) ---
class RealCrypto:
    def __init__(self, logger_func=print):
        self.logger = logger_func
        self.logger("Crypto Reale: Inizializzazione...")
        try:
            self._key_pkg_derived_key3 = RSA.construct((
                int.from_bytes(PkgDerivedKey3Keyset.Modulus, 'big'),
                int.from_bytes(PkgDerivedKey3Keyset.PublicExponent, 'big'),
                int.from_bytes(PkgDerivedKey3Keyset.PrivateExponent, 'big'),
                int.from_bytes(PkgDerivedKey3Keyset.Prime1, 'big'),
                int.from_bytes(PkgDerivedKey3Keyset.Prime2, 'big')
                # Rimosso int.from_bytes(PkgDerivedKey3Keyset.Coefficient, 'big')
            ))
            self._key_fake = RSA.construct((
                int.from_bytes(FakeKeyset.Modulus, 'big'),
                int.from_bytes(FakeKeyset.PublicExponent, 'big'),
                int.from_bytes(FakeKeyset.PrivateExponent, 'big'),
                int.from_bytes(FakeKeyset.Prime1, 'big'),
                int.from_bytes(FakeKeyset.Prime2, 'big')
                # Rimosso int.from_bytes(FakeKeyset.Coefficient, 'big')
            ))
            self.logger("Chiavi RSA caricate con successo.")
        except Exception as e:
            self.logger(f"ERRORE CRITICO nel caricamento chiavi RSA: {e}")
            import traceback
            self.logger(traceback.format_exc()); raise

    def RSA2048Decrypt(self, output_key_buffer: bytearray, ciphertext: bytes, is_dk3: bool):
        self.logger(f"Crypto: RSA2048Decrypt. is_dk3={is_dk3}, input len={len(ciphertext)}")
        self.logger(f"  RSA Input ciphertext (primi 32B): {ciphertext[:32].hex()}")
        if len(ciphertext) != 256:
            self.logger(f"  Errore RSA: ciphertext len non è 256 (è {len(ciphertext)}) -> azzero output")
            output_key_buffer[:] = b'\0' * len(output_key_buffer); return
        
        key_to_use = self._key_pkg_derived_key3 if is_dk3 else self._key_fake
        cipher_rsa = Cipher_PKCS1_v1_5.new(key_to_use)
        
        # Non pre-azzerare output_key_buffer per vedere lo stato precedente se il decrypt fallisce silenziosamente
        # initial_output_buffer_state_sample = output_key_buffer[:min(8, len(output_key_buffer))].hex()

        try:
            # sentinel=object() farà sollevare ValueError in caso di errore di decrypt
            decrypted_data = cipher_rsa.decrypt(ciphertext, sentinel=object()) 
            self.logger(f"  RSA Decrypt OK. Lunghezza dati decrittati: {len(decrypted_data)}")
            
            if all(b == 0 for b in decrypted_data):
                self.logger("  AVVISO RSA: Dati decrittati sono tutti zeri.")
            # else:
                # self.logger(f"  RSA Dati decrittati (primi {min(16, len(decrypted_data))}B): {decrypted_data[:min(16, len(decrypted_data))].hex()}")

            bytes_to_copy = min(len(output_key_buffer), len(decrypted_data))
            output_key_buffer[:bytes_to_copy] = decrypted_data[:bytes_to_copy]
            if len(output_key_buffer) > bytes_to_copy:
                # Riempi il resto del buffer di output con zeri se decrypted_data è più corto
                output_key_buffer[bytes_to_copy:] = b'\0' * (len(output_key_buffer) - bytes_to_copy)
            
            # self.logger(f"  RSA Output buffer (primi {min(8, len(output_key_buffer))} byte): {output_key_buffer[:min(8, len(output_key_buffer))].hex()}")
        except ValueError as ve:
            # Questo blocco verrà eseguito se la decrittografia fallisce (es. padding errato, chiave errata)
            self.logger(f"ERRORE RSA Decrypt (ValueError): {ve}. Ciphertext (primi 16B): {ciphertext[:16].hex()}... Output buffer azzerato.")
            output_key_buffer[:] = b'\0' * len(output_key_buffer)
        except Exception as e:
            self.logger(f"ERRORE RSA Decrypt (Altra Eccezione): {e}. Ciphertext (primi 16B): {ciphertext[:16].hex()}... Output buffer azzerato.")
            output_key_buffer[:] = b'\0' * len(output_key_buffer)


    def ivKeyHASH256(self, cipher_input: bytes, ivkey_result_buffer: bytearray):
        # ... (implementazione come prima) ...
        if len(cipher_input) != 64 or len(ivkey_result_buffer) != 32:
             self.logger(f"Errore ivKeyHASH256: dimensioni non valide."); return
        h = SHA256.new(); h.update(cipher_input); ivkey_result_buffer[:] = h.digest()
        # self.logger(f"Crypto: ivKeyHASH256 OK.")

    def aesCbcCfb128Decrypt(self, ivkey: bytes, ciphertext: bytes, decrypted_buffer: bytearray):
        # ... (implementazione come prima) ...
        if len(ivkey) != 32 or len(ciphertext) != 256 or len(decrypted_buffer) != 256:
            self.logger("Errore aesCbcCfb128Decrypt: dimensioni non valide."); return
        key = ivkey[16:32]; iv = ivkey[0:16]
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted_buffer[:] = cipher_aes.decrypt(ciphertext)
        # self.logger(f"Crypto: aesCbcCfb128Decrypt OK.")

    def _xts_xor_block(self, x: bytearray, a: bytes, b: bytes) -> None:
        """XORs two 16-byte blocks and stores the result in the first argument."""
        for i in range(16):
            x[i] = a[i] ^ b[i]

    def _xts_mult(self, encrypted_tweak: bytearray) -> None:
        """
        Multiplies the encrypted tweak by α in GF(2^128) modulo x^128 + x^7 + x^2 + x + 1.
        This is equivalent to a left shift of the entire 128-bit value, with reduction.
        """
        # Get the carry from the high bit of the last byte
        carry = (encrypted_tweak[15] >> 7) & 1
        
        # Left shift the entire 128-bit value
        for i in range(15, 0, -1):
            encrypted_tweak[i] = ((encrypted_tweak[i] << 1) | ((encrypted_tweak[i-1] >> 7) & 1)) & 0xFF
        
        # Handle the first byte
        encrypted_tweak[0] = (encrypted_tweak[0] << 1) & 0xFF
        
        # If there was a carry, apply the reduction polynomial x^128 + x^7 + x^2 + x + 1
        # which is equivalent to XOR with 0x87 in the first byte
        if carry:
            encrypted_tweak[0] ^= 0x87

    def _xts_encrypt_tweak(self, tweak_key: bytes, sector_num: int) -> bytearray:
        """Encrypt the tweak for XTS mode.
        
        Args:
            tweak_key: 16-byte key for encrypting the tweak
            sector_num: Sector number to use in the tweak
            
        Returns:
            Encrypted tweak as bytearray
        """
        # Initialize a 16-byte tweak with the sector number in little-endian format
        tweak = bytearray(16)
        
        # Pack the sector number as little-endian 64-bit integer
        # and the second 64 bits as zero
        struct.pack_into("<Q", tweak, 0, sector_num)
        struct.pack_into("<Q", tweak, 8, 0)
        
        # Debug logging for first few sectors
        debug_sector = not hasattr(self, '_debug_sector_count') or self._debug_sector_count < 10
        
        if debug_sector:
            self.logger(f"\n=== Sector {sector_num} (0x{sector_num:x}) ===")
            self.logger(f"Tweak before encryption (hex): {tweak.hex()}")
            self.logger(f"Tweak key (hex): {tweak_key.hex()}")
        
        try:
            # Create AES cipher in ECB mode for the tweak
            tweak_cipher = AES.new(tweak_key, AES.MODE_ECB)
            
            # Encrypt the tweak
            encrypted_tweak = bytearray(tweak_cipher.encrypt(tweak))
            
            if debug_sector:
                self.logger(f"Encrypted tweak (hex): {encrypted_tweak.hex()}")
                # Log the tweak as 16 individual bytes for debugging
                tweak_bytes = ', '.join(f'0x{b:02x}' for b in encrypted_tweak)
                self.logger(f"Encrypted tweak bytes: [{tweak_bytes}]")
                if not hasattr(self, '_debug_sector_count'):
                    self._debug_sector_count = 0
                self._debug_sector_count += 1
            
            return encrypted_tweak
            
        except Exception as e:
            self.logger(f"ERROR in tweak encryption: {e}")
            self.logger(f"Sector: {sector_num} (0x{sector_num:x})")
            self.logger(f"Tweak key (hex): {tweak_key.hex()}")
            self.logger(f"Tweak before encryption (hex): {tweak.hex()}")
            import traceback
            self.logger(traceback.format_exc())
            raise
            
    def _xts_mult(self, encrypted_tweak: bytearray):
        """Multiply the tweak by α in GF(2^128)
        
        Args:
            encrypted_tweak: 16-byte tweak to be multiplied in-place
        """
        carry = 0
        for i in range(15, -1, -1):
            next_carry = (encrypted_tweak[i] >> 7) & 1
            encrypted_tweak[i] = ((encrypted_tweak[i] << 1) | carry) & 0xFF
            carry = next_carry
        
        if carry:
            encrypted_tweak[0] ^= 0x87
            
    def _xts_process_block(self, cipher, block: bytes, encrypted_tweak: bytearray, block_index: int = 0) -> bytes:
        """Process a single block in XTS mode.
        
        Args:
            cipher: AES cipher object in ECB mode
            block: 16-byte block to process
            tweak: 16-byte tweak (will be updated for subsequent blocks)
            block_index: Index of the block within the sector (0-based)
            
        Returns:
            Processed 16-byte block
        """
        if not block or len(block) != 16:
            error_msg = f"Block size must be 16 bytes, got {len(block) if block else 0}"
            self.logger(f"ERROR: {error_msg}")
            raise ValueError(error_msg)
            
        if len(encrypted_tweak) != 16:
            error_msg = f"Tweak size must be 16 bytes, got {len(encrypted_tweak)}"
            self.logger(f"ERROR: {error_msg}")
            raise ValueError(error_msg)
            
        # For blocks after the first in a sector, multiply the tweak by α^i where i is the block index
        current_tweak = bytearray(encrypted_tweak)
        if block_index > 0:
            for _ in range(block_index):
                self._xts_mult(current_tweak)
        
        # Debug logging for first few blocks and any interesting blocks
        debug_block = block_index < 10 or block_index % 100 == 0
        
        if debug_block:
            self.logger(f"\n=== Block {block_index} ===")
            self.logger(f"Input block:    {block.hex()}")
            self.logger(f"Tweak (α^{block_index}): {bytes(current_tweak).hex()}")
        
        try:
            # XTS Decryption steps:
            # 1. Xor the block with the tweak
            xored_block = bytearray(16)
            self._xts_xor_block(xored_block, block, current_tweak)
            
            if debug_block:
                self.logger(f"After XOR with tweak: {xored_block.hex()}")
            
            # 2. Decrypt the block using AES in ECB mode
            try:
                # Get the raw AES key from the cipher
                aes_key = cipher.key if hasattr(cipher, 'key') else None
                if debug_block and aes_key:
                    self.logger(f"Using AES key: {aes_key.hex()}")
                
                # Decrypt the block
                decrypted_xored = bytearray(cipher.decrypt(bytes(xored_block)))
                
                if debug_block:
                    self.logger(f"After AES decrypt: {decrypted_xored.hex()}")
                
                # 3. Xor again with the same tweak
                final_block = bytearray(16)
                self._xts_xor_block(final_block, decrypted_xored, current_tweak)
                
                if debug_block:
                    self.logger(f"After final XOR: {final_block.hex()}")
                    self.logger(f"Final block: {final_block.hex()}")
                
                # Check for all zeros in decrypted block (potential error case)
                if all(b == 0 for b in final_block):
                    if any(b != 0 for b in block):
                        self.logger(f"WARNING: Decrypted block is all zeros but input was not! Block index: {block_index}")
                        self.logger(f"Input block:    {block.hex()}")
                        self.logger(f"XORed block:    {xored_block.hex()}")
                        self.logger(f"Decrypted:      {decrypted_xored.hex()}")
                        self.logger(f"Tweak (α^{block_index}): {bytes(current_tweak).hex()}")
                        if aes_key:
                            self.logger(f"AES Key:        {aes_key.hex()}")
                
                return bytes(final_block)
                
            except Exception as e:
                self.logger(f"ERROR in AES decryption: {e}")
                self.logger(f"Block index:    {block_index}")
                self.logger(f"Input block:    {block.hex()}")
                self.logger(f"XORed block:    {xored_block.hex()}")
                self.logger(f"Tweak (α^{block_index}): {bytes(current_tweak).hex()}")
                if aes_key:
                    self.logger(f"AES Key:        {aes_key.hex()}")
                raise
            
        except Exception as e:
            self.logger(f"ERROR in XTS block processing: {e}")
            self.logger(f"Block index: {block_index}")
            self.logger(f"Block: {block.hex()}")
            self.logger(f"Tweak: {current_tweak.hex()}")
            if 'aes_key' in locals() and aes_key:
                self.logger(f"AES Key: {aes_key.hex()}")
            import traceback
            self.logger(traceback.format_exc())
            raise

    def _xts_encrypt_tweak(self, tweak_key: bytes, sector_num: int) -> bytearray:
        """Encrypt the tweak for XTS mode.
        
        The tweak is a 16-byte value where the first 8 bytes are the sector number
        in little-endian format, and the remaining 8 bytes are zero.
        """
        try:
            # Initialize tweak as 16 zero bytes
            tweak = bytearray(16)
            
            # Pack the sector number into the first 8 bytes in little-endian format
            struct.pack_into("<Q", tweak, 0, sector_num)
            
            # Debug logging for the first few sectors and sector 304
            if sector_num < 10 or sector_num == 304:
                self.logger(f"=== XTS Tweak Generation (Sector {sector_num} (0x{sector_num:x})) ===")
                self.logger(f"  Tweak key: {tweak_key.hex()}")
                self.logger(f"  Sector num: {sector_num} (0x{sector_num:x})")
                self.logger(f"  Tweak before encryption: {tweak.hex()}")
            
            # Create AES cipher for the tweak
            tweak_cipher = AES.new(tweak_key, AES.MODE_ECB)
            
            # Encrypt the tweak
            encrypted_tweak = bytearray(tweak_cipher.encrypt(tweak))
            
            # More debug logging
            if sector_num < 10 or sector_num == 304:
                self.logger(f"  Encrypted tweak: {encrypted_tweak.hex()}")
                
                # For sector 304, also log the expected encrypted tweak from the C++ code
                if sector_num == 304:
                    # This is the expected encrypted tweak from the C++ code
                    expected_tweak = bytes.fromhex("86e5f96871c98410ee8ba2842867cd5c")
                    self.logger(f"  Expected encrypted tweak: {expected_tweak.hex()}")
                    
                    if encrypted_tweak == expected_tweak:
                        self.logger("  Tweak encryption matches expected value!")
                    else:
                        self.logger("  WARNING: Tweak encryption does NOT match expected value!")
                        
                        # Log the difference
                        diff = [f"{i:02x}" for i in range(16) if encrypted_tweak[i] != expected_tweak[i]]
                        self.logger(f"  Bytes that differ: {', '.join(diff) if diff else 'None'}")
            
            return encrypted_tweak
            
        except Exception as e:
            self.logger(f"ERROR in _xts_encrypt_tweak (sector {sector_num}): {e}")
            self.logger(f"Tweak key: {tweak_key.hex() if tweak_key else 'None'}")
            self.logger(f"Sector num: {sector_num}")
            import traceback
            self.logger(traceback.format_exc())
            raise

    def _xts_mult(self, encrypted_tweak: bytearray):
        """Multiply the tweak by α in GF(2^128)
        
        Args:
            encrypted_tweak: 16-byte tweak to be multiplied in-place
        """
        carry = 0
        for i in range(15, -1, -1):
            next_carry = (encrypted_tweak[i] >> 7) & 1
            encrypted_tweak[i] = ((encrypted_tweak[i] << 1) | carry) & 0xFF
            carry = next_carry
        
        if carry:
            encrypted_tweak[0] ^= 0x87

    def _xts_xor_block(self, x: bytearray, a: bytes, b: bytes):
        """XORs two 16-byte blocks and stores the result in x.
        
        Args:
            x: Output buffer for the result
            a: First 16-byte block
            b: Second 16-byte block
            
        """
        for i in range(16):
            x[i] = a[i] ^ b[i]

    def decryptPFS(self, dataKey: bytes, tweakKey: bytes, src_image: bytes, dst_image: bytearray = None, sector: int = 0) -> bytes:
        """Decrypt PFS image data using XTS-AES mode.
        
        Args:
            dataKey: 16-byte data key for AES decryption
            tweakKey: 16-byte tweak key for tweak encryption
            src_image: Source encrypted data
            dst_image: Optional destination buffer (if None, a new one will be created)
            sector: Starting sector number (default: 0)
            
        Returns:
            Decrypted data as bytes
        """
        try:
            self.logger(f"DEBUG: Starting PFS decryption with sector {sector}")
            self.logger(f"DEBUG: dataKey: {dataKey.hex()}")
            self.logger(f"DEBUG: tweakKey: {tweakKey.hex()}")
            
            # Create AES ciphers for data and tweak
            data_cipher = AES.new(dataKey, AES.MODE_ECB)
            tweak_cipher = AES.new(tweakKey, AES.MODE_ECB)
            
            # Prepare destination buffer if not provided
            if dst_image is None:
                dst_image = bytearray(len(src_image))
                self.logger(f"DEBUG: Created new destination buffer of size {len(dst_image)} bytes")
            else:
                if len(dst_image) < len(src_image):
                    raise ValueError(f"Destination buffer too small: {len(dst_image)} < {len(src_image)}")
            
            # Process each 4096-byte sector
            sector_size = 4096
            total_blocks = (len(src_image) + 15) // 16  # Total number of 16-byte blocks
            
            for sector_offset in range(0, len(src_image), sector_size):
                current_sector = sector + (sector_offset // sector_size)
                sector_data = src_image[sector_offset:sector_offset + sector_size]
                
                # Generate the initial tweak for this sector (little-endian sector number)
                tweak = bytearray(16)
                struct.pack_into("<Q", tweak, 0, current_sector)
                
                # Encrypt the tweak
                encrypted_tweak = bytearray(tweak_cipher.encrypt(tweak))
                
                if current_sector < 5 or current_sector % 100 == 0:
                    self.logger(f"=== Sector {current_sector} ===")
                    self.logger(f"Tweak: {tweak.hex()}")
                    self.logger(f"Encrypted tweak: {encrypted_tweak.hex()}")
                
                # Process each 16-byte block in the sector
                blocks_in_sector = (len(sector_data) + 15) // 16
                for block_index in range(blocks_in_sector):
                    block_offset = block_index * 16
                    block = sector_data[block_offset:block_offset + 16]
                    
                    # Process the block with the current tweak
                    decrypted_block = self._xts_process_block(data_cipher, block, encrypted_tweak, block_index)
                    
                    # Copy to destination
                    dst_pos = sector_offset + block_offset
                    copy_len = min(16, len(sector_data) - block_offset)
                    if copy_len > 0:
                        dst_image[dst_pos:dst_pos+copy_len] = decrypted_block[:copy_len]
            
            # Save first 256 bytes for debugging
            debug_path = os.path.join(os.path.dirname(__file__), "debug_decrypted.bin")
            with open(debug_path, "wb") as f:
                f.write(dst_image[:min(256, len(dst_image))])
            self.logger(f"DEBUG: First 256 bytes of decrypted data saved to {debug_path}")
            
            return bytes(dst_image)
            
        except Exception as e:
            self.logger(f"ERROR in decryptPFS: {str(e)}")
            import traceback
            self.logger(traceback.format_exc())
            raise

    def aesCbcCfb128DecryptEntry(self, ivkey: bytes, ciphertext: bytes, decrypted_buffer: bytearray):
        if len(ivkey) != 32:
            self.logger("Errore aesCbcCfb128DecryptEntry: ivkey lunghezza non valida.")
            decrypted_buffer[:] = b'\0' * len(decrypted_buffer) # Zero out on error
            return

        if len(decrypted_buffer) != len(ciphertext):
            self.logger(f"Errore aesCbcCfb128DecryptEntry: Mismatch len decrypted_buffer ({len(decrypted_buffer)}) vs ciphertext ({len(ciphertext)}).")
            decrypted_buffer[:] = b'\0' * len(decrypted_buffer) # Zero out on error
            return

        key = ivkey[16:32]; iv = ivkey[0:16]
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        
        block_size = AES.block_size
        valid_len = (len(ciphertext) // block_size) * block_size
        
        if valid_len > 0:
            decrypted_part = cipher_aes.decrypt(ciphertext[:valid_len])
            decrypted_buffer[:valid_len] = decrypted_part
        
        # Copia la coda originale (crittata) se esiste
        if len(ciphertext) > valid_len:
            decrypted_buffer[valid_len:] = ciphertext[valid_len:]
        elif valid_len == 0 and len(ciphertext) > 0: # Ciphertext più corto di un blocco
             decrypted_buffer[:] = ciphertext[:] # Copia i dati originali (ancora crittati)
        elif valid_len == 0 and len(ciphertext) == 0: # Ciphertext è vuoto
            pass # Il buffer decrittato rimane vuoto o come inizializzato (dovrebbe essere vuoto)

        # self.logger(f"Crypto: aesCbcCfb128DecryptEntry processed. Input {len(ciphertext)}, valid_len {valid_len}.")

    def PfsGenCryptoKey(self, ekpfs: bytes, seed: bytes, dataKey_buffer: bytearray, tweakKey_buffer: bytearray):
        """
        Generate PFS crypto keys using HMAC-SHA256.
        
        Args:
            ekpfs: 32-byte EKPFS key
            seed: 16-byte seed (usually from PFS superblock)
            dataKey_buffer: 16-byte buffer to store the data key
            tweakKey_buffer: 16-byte buffer to store the tweak key
            
        Returns:
            True if successful, False otherwise
        """
        if len(ekpfs) != 32:
            self.logger(f"[ERROR] PfsGenCryptoKey: Invalid ekpfs length: {len(ekpfs)} (expected 32)")
            return False
            
        if len(seed) != 16:
            self.logger(f"[ERROR] PfsGenCryptoKey: Invalid seed length: {len(seed)} (expected 16)")
            return False
            
        if len(dataKey_buffer) != 16 or len(tweakKey_buffer) != 16:
            self.logger(f"[ERROR] PfsGenCryptoKey: Invalid output buffer size (data: {len(dataKey_buffer)}, tweak: {len(tweakKey_buffer)})")
            return False
            
        try:
            from Crypto.Hash import HMAC, SHA256
            
            self.logger(f"[DEBUG] ===== PfsGenCryptoKey (Aligned with C++) =====")
            self.logger(f"[DEBUG] Input EKPFS (hex): {ekpfs.hex()}")
            self.logger(f"[DEBUG] Input Seed (hex): {seed.hex()}")

            # Data for HMAC: index (1 as u32_le) concatenated with seed (16 bytes)
            # This matches the C++ `Crypto::PfsGenCryptoKey` logic where `index = 1;`
            # and `d` is constructed as `memcpy(d, &index, ...); memcpy(d + sizeof(uint32_t), seed.data(), ...);`
            index_bytes = struct.pack("<I", 1)  # 4 bytes, little-endian for index = 1
            hmac_data = index_bytes + seed      # Total 20 bytes
            
            self.logger(f"[DEBUG] Data for HMAC (index_le || seed) (hex): {hmac_data.hex()}")

            hmac_obj = HMAC.new(ekpfs, digestmod=SHA256)
            hmac_obj.update(hmac_data)
            hmac_result = hmac_obj.digest()  # 32 bytes
            
            self.logger(f"[DEBUG] HMAC Result (hex): {hmac_result.hex()}")

            # Assign keys based on C++ `Crypto::PfsGenCryptoKey`
            # C++ logic:
            #   std::copy(data_tweak_key.begin(), data_tweak_key.begin() + dataKey.size(), tweakKey.begin());
            #   std::copy(data_tweak_key.begin() + tweakKey.size(), ..., dataKey.begin());
            # This means: tweakKey = hmac_result[0:16], dataKey = hmac_result[16:32]
            
            tweakKey_from_hmac = hmac_result[0:16]
            dataKey_from_hmac = hmac_result[16:32]
            
            tweakKey_buffer[:] = tweakKey_from_hmac
            dataKey_buffer[:] = dataKey_from_hmac
            
            self.logger(f"[DEBUG] Derived TweakKey (hex): {tweakKey_from_hmac.hex()}")
            self.logger(f"[DEBUG] Derived DataKey (hex): {dataKey_from_hmac.hex()}")
            self.logger(f"[DEBUG] ============================================")
            
            return True
            
        except Exception as e:
            self.logger(f"[ERROR] PfsGenCryptoKey failed: {str(e)}")
            import traceback
            self.logger(f"[ERROR] Stack trace: {traceback.format_exc()}")
            return False

    def _xts_mult_test(self):
        """Test the _xts_mult function with known test vectors.
        
        Note: The test vectors are in little-endian byte order (tweak_block[0] is LSB).
        The expected output is also in little-endian byte order.
        
        Test cases cover:
        1. Simple left shift (no carry)
        2. Left shift with carry to next byte
        3. Left shift with carry across multiple bytes
        4. Reduction with polynomial x^128 + x^7 + x^2 + x + 1
        """
        test_vectors = [
            # (input_hex, expected_output_hex, description)
            
            # Test 1: 0x01 -> 0x02 (simple left shift of LSB)
            ("01000000000000000000000000000000", "02000000000000000000000000000000", 
             "0x01 -> 0x02 (simple left shift of LSB)"),
            
            # Test 2: 0x80 -> 0x00 with carry (0x100 mod 0x100 = 0x00, carry=1)
            # Then reduction with 0x87 (x^7 + x^2 + x + 1)
            ("80000000000000000000000000000000", "1b000000000000000000000000000000",
             "0x80 -> 0x1b (carry and reduction with 0x87)"),
            
            # Test 3: 0x01 in MSB (0x00...01) -> 0x02 (simple shift, no carry)
            ("00000000000000000000000000000001", "00000000000000000000000000000002",
             "0x00...01 -> 0x00...02 (simple shift in MSB)"),
            
            # Test 4: 0x80 in MSB (0x00...80) -> 0x00...00 with carry, then reduction
            ("00000000000000000000000000000080", "87000000000000000000000000000000",
             "0x00...80 -> 0x87...00 (carry and reduction)"),
            
            # Test 5: All bits set (0xFF...FF) -> 0xFF...FE with carry, then reduction
            ("ffffffffffffffffffffffffffffffff", "79ffffffffffffffffffffffffffffff",
             "0xFF...FF -> 0x79...FF (carry and reduction)"),
        ]
        
        self.logger("[TEST] Running _xts_mult tests...")
        all_passed = True
        
        for i, (input_hex, expected_hex, desc) in enumerate(test_vectors, 1):
            try:
                # Convert hex strings to byte arrays
                input_bytes = bytes.fromhex(input_hex)
                expected = bytes.fromhex(expected_hex)
                
                # Create a mutable copy for the test
                tweak = bytearray(input_bytes)
                
                # Debug: Log input
                self.logger(f"[TEST {i}] {desc}")
                self.logger(f"  Input:    {input_hex}")
                
                # Apply the multiplication
                self._xts_mult(tweak)
                
                # Check the result
                if tweak != expected:
                    self.logger(f"  [FAIL] Expected: {expected_hex}")
                    self.logger(f"  [FAIL] Got:      {tweak.hex()}")
                    all_passed = False
                else:
                    self.logger(f"  [PASS] Result:   {tweak.hex()}")
                
                self.logger("")
                    
            except Exception as e:
                self.logger(f"[TEST {i}] ERROR: {str(e)}")
                import traceback
                self.logger(traceback.format_exc())
                all_passed = False
        
        if all_passed:
            self.logger("[TEST] All _xts_mult tests passed!")
        else:
            self.logger("[TEST] Some _xts_mult tests failed!")
            
        return all_passed
        
    def _log_hex_dump(self, prefix, data):
        """Helper to log hex dumps with a prefix."""
        hex_str = ' '.join(f'{b:02x}' for b in data)
        self.logger(f"{prefix}{hex_str}")

    def PfsGenCryptoKey(self, ekpfs: bytes, seed: bytes, dataKey_buffer: bytearray, tweakKey_buffer: bytearray):
        """
        Genera le chiavi crittografiche per PFS.
        Corrisponde a Crypto::PfsGenCryptoKey nel codice C++.
        
        Args:
            ekpfs: Chiave EKPFS (32 byte)
            seed: Seme (16 byte)
            dataKey_buffer: Buffer di output per la chiave dati (16 byte)
            tweakKey_buffer: Buffer di output per la chiave tweak (16 byte)
        """
        from Crypto.Hash import HMAC, SHA256
        
        # Crea l'input per HMAC: 4 byte di index (1) + 16 byte di seed
        index = 1
        hmac_input = struct.pack("<I", index) + seed
        
        # Calcola HMAC-SHA256
        hmac = HMAC.new(ekpfs, digestmod=SHA256)
        hmac.update(hmac_input)
        hmac_result = hmac.digest()
        
        # I primi 16 byte sono la tweakKey, i successivi 16 la dataKey
        # Nota: in C++ l'ordine è invertito rispetto a quello che sembrerebbe dal nome dei parametri
        tweakKey_buffer[:] = hmac_result[0:16]
        dataKey_buffer[:] = hmac_result[16:32]
    
        # self.logger(f"Crypto: decryptEFSM OK.")
        
    def _xts_xor_block(self, x: bytearray, a: bytes, b: bytes) -> None:
        """
        XORs two 16-byte blocks and stores the result in the first argument.
        Equivalent to xtsXorBlock in C++.
        """
        for i in range(16):
            x[i] = a[i] ^ b[i]
    
    def _xts_mult(self, encrypted_tweak: bytearray) -> None:
        """
        Optimized multiplication by α in GF(2^128) for XTS mode.
        Equivalent to xtsMult in C++ but optimized for performance.
        """
        # Get the carry from the high bit of the last byte
        carry = encrypted_tweak[15] >> 7
        
        # Process all bytes in a single pass
        # This is equivalent to a left shift of the entire 128-bit value
        for i in range(15, 0, -1):
            encrypted_tweak[i] = ((encrypted_tweak[i] << 1) | (encrypted_tweak[i-1] >> 7)) & 0xFF
        
        # Handle the first byte
        encrypted_tweak[0] = (encrypted_tweak[0] << 1) & 0xFF
        
        # If there was a carry, apply the reduction polynomial x^128 + x^7 + x^2 + x + 1
        # which is equivalent to XOR with 0x87 in the first byte
        if carry:
            encrypted_tweak[0] ^= 0x87
    
    def decryptPFS(self, dataKey: bytes, tweakKey: bytes, src_image: bytes, dst_image: bytearray = None, sector: int = 0) -> bytes:
        """
        Decrypts PFS image data using XTS-AES mode with proper handling for partial blocks.
        
        Args:
            dataKey: 16-byte data key for AES decryption
            tweakKey: 16-byte tweak key for tweak encryption
            src_image: Source encrypted data
            dst_image: Optional destination buffer (if None, a new one will be created)
            sector: Starting sector number (default: 0)
            
        Returns:
            Decrypted data as bytes
        """
        # Initialize debug block counter if it doesn't exist
        if not hasattr(self, '_debug_block_count'):
            self._debug_block_count = 0
            
        try:
            # Test AES cipher with known values
            test_key = b'\x00' * 16
            test_plain = b'\x00' * 16
            test_cipher = AES.new(test_key, AES.MODE_ECB)
            encrypted_test = test_cipher.encrypt(test_plain)
            self.logger(f"DEBUG: AES test encryption: {encrypted_test.hex()}")
            
            # Verify decryption works
            decrypted_test = test_cipher.decrypt(encrypted_test)
            if decrypted_test != test_plain:
                self.logger(f"WARNING: AES test decryption failed! Got {decrypted_test.hex()}, expected {test_plain.hex()}")
            
            # Create the real ciphers
            cipher = AES.new(dataKey, AES.MODE_ECB)
            tweak_cipher = AES.new(tweakKey, AES.MODE_ECB)
            
            # Initialize destination buffer if not provided
            if dst_image is None:
                dst_image = bytearray(len(src_image))
            else:
                if len(dst_image) < len(src_image):
                    raise ValueError("Destination buffer too small")
            
            # Process each 0x1000-byte sector
            src_len = len(src_image)
            for i in range(0, src_len, 0x1000):
                # Get current sector data
                sector_end = min(i + 0x1000, src_len)
                sector_data = src_image[i:sector_end]
                if not sector_data:
                    break
                    
                # Calculate tweak for this sector (little-endian sector number)
                tweak = bytearray(16)
                current_sector = sector + (i // 0x1000)
                struct.pack_into("<Q", tweak, 0, current_sector)
                
                # Encrypt the tweak
                try:
                    encrypted_tweak = bytearray(tweak_cipher.encrypt(tweak))
                except Exception as e:
                    self.logger(f"ERROR encrypting tweak at sector {current_sector}: {e}")
                    raise
                
                # Debug logging for the first few sectors
                if i < 0x2000:  # First 2 sectors for debugging
                    self.logger(f"Sector {current_sector} (0x{current_sector:x}):")
                    self.logger(f"  Tweak: {tweak.hex()}")
                    self.logger(f"  Encrypted tweak: {encrypted_tweak.hex()}")
                    self.logger(f"  First 16 bytes of sector: {sector_data[:16].hex() if len(sector_data) >= 16 else sector_data.hex()}")
                
                # Process each 16-byte block in the sector
                current_tweak = bytearray(encrypted_tweak)  # Make a copy for this sector
                sector_len = len(sector_data)
                
                # Process all blocks in the sector
                num_blocks = (sector_len + 15) // 16
                for j in range(num_blocks):
                    block_start = j * 16
                    block_end = min(block_start + 16, sector_len)
                    block = sector_data[block_start:block_end]
                    
                    # Check if this is the last block and it's a partial block
                    is_last_block = (j == num_blocks - 1) and (sector_len % 16 != 0)
                    
                    if is_last_block and len(block) < 16:
                        # Handle partial last block using ciphertext stealing
                        # 1. Get the last full block (which was already decrypted)
                        last_full_block_start = ((sector_len // 16) - 1) * 16
                        last_full_block = sector_data[last_full_block_start:last_full_block_start+16]
                        
                        # 2. Decrypt the last full block again with the current tweak
                        decrypted_last_full = self._xts_process_block(cipher, last_full_block, current_tweak)
                        
                        # 3. Take the first len(block) bytes for our partial plaintext
                        partial_plaintext = decrypted_last_full[:len(block)]
                        
                        # 4. Store the partial plaintext in the output
                        dst_image[i+block_start:i+block_end] = partial_plaintext
                        
                        # Debug logging
                        if self._debug_block_count < 10:
                            self.logger(f"Partial Block {self._debug_block_count} (sector {current_sector}):")
                            self.logger(f"  Encrypted: {block.hex()}")
                            self.logger(f"  Decrypted: {partial_plaintext.hex()}")
                            self._debug_block_count += 1
                        
                        # No need to update tweak after last block
                        break
                    else:
                        # Process full block
                        decrypted_block = self._xts_process_block(cipher, block, current_tweak)
                        
                        # Copy the decrypted block to the destination
                        dst_image[i+block_start:i+block_end] = decrypted_block
                        
                        # Debug logging for the first few blocks
                        if self._debug_block_count < 10:
                            self.logger(f"Block {self._debug_block_count} (sector {current_sector}):")
                            self.logger(f"  Encrypted: {block.hex()}")
                            self.logger(f"  Decrypted: {decrypted_block.hex()}")
                            self._debug_block_count += 1
                        
                        # Update the tweak for the next block (if not the last block in sector)
                        if j < num_blocks - 1:
                            self._xts_mult(current_tweak)
            
            # Save the first 256 bytes of decrypted data for inspection
            debug_path = os.path.join(os.path.dirname(__file__), "debug_decrypted.bin")
            with open(debug_path, "wb") as f:
                f.write(dst_image[:min(256, len(dst_image))])
            self.logger(f"DEBUG: First 256 bytes of decrypted data saved to {debug_path}")
            
            return bytes(dst_image)
            
        except Exception as e:
            self.logger(f"ERROR in decryptPFS: {e}")
            import traceback
            self.logger(traceback.format_exc())
            raise
        
        # Initialize destination buffer if not provided
        if dst_image is None:
            dst_image = bytearray(len(src_image))
        else:
            if len(dst_image) < len(src_image):
                raise ValueError("Destination buffer too small")
        
        # Process each 0x1000-byte sector
        src_len = len(src_image)
        for i in range(0, src_len, 0x1000):
            # Get current sector data
            sector_end = min(i + 0x1000, src_len)
            sector_data = src_image[i:sector_end]
            if not sector_data:
                break
                
            # Calculate tweak for this sector (little-endian sector number)
            tweak = bytearray(16)
            current_sector = sector + (i // 0x1000)
            struct.pack_into("<Q", tweak, 0, current_sector)
            
            # Encrypt the tweak
            try:
                encrypted_tweak = bytearray(tweak_cipher.encrypt(tweak))
            except Exception as e:
                self.logger(f"ERROR encrypting tweak at sector {current_sector}: {e}")
                raise
            
            # Debug logging for the first few sectors
            if i < 0x2000:  # First 2 sectors for debugging
                self.logger(f"Sector {current_sector} (0x{current_sector:x}):")
                self.logger(f"  Tweak: {tweak.hex()}")
                self.logger(f"  Encrypted tweak: {encrypted_tweak.hex()}")
                self.logger(f"  First 16 bytes of sector: {sector_data[:16].hex() if len(sector_data) >= 16 else sector_data.hex()}")
            
            # Process each 16-byte block in the sector
            current_tweak = bytearray(encrypted_tweak)  # Make a copy for this sector
            sector_len = len(sector_data)
            
            # Process full blocks first (all but the last block if it's partial)
            num_blocks = (sector_len + 15) // 16
            for j in range(num_blocks):
                block_start = j * 16
                block_end = min(block_start + 16, sector_len)
                block = sector_data[block_start:block_end]
                
                # For the last block if it's partial, handle it specially
                is_last_block = (j == num_blocks - 1) and (sector_len % 16 != 0)
                
                if is_last_block:
                    # For the last partial block, we need to use ciphertext stealing
                    if len(block) < 16:
                        # Save the current tweak for later
                        last_tweak = bytearray(current_tweak)
                        
                        # Process the previous full block first
                        if j > 0:
                            prev_block_start = (j-1) * 16
                            prev_block = sector_data[prev_block_start:prev_block_start+16]
                            
                            # Encrypt the tweak for the previous block
                            prev_tweak = bytearray(encrypted_tweak)
                            for _ in range(j-1):
                                self._xts_mult(prev_tweak)
                            
                            # Process the previous full block
                            xored_block = bytearray(16)
                            self._xts_xor_block(xored_block, prev_block, prev_tweak)
                            decrypted_block = bytearray(cipher.decrypt(bytes(xored_block)))
                            final_block = bytearray(16)
                            self._xts_xor_block(final_block, decrypted_block, prev_tweak)
                            
                            # Save the result
                            dst_image[i+prev_block_start:i+prev_block_start+16] = final_block
                        
                        # Now handle the last partial block
                        # We need to read the full block that contains the partial data
                        full_block_start = (num_blocks - 1) * 16
                        full_block = sector_data[full_block_start:full_block_start+16]
                        
                        # Process the full block
                        xored_block = bytearray(16)
                        self._xts_xor_block(xored_block, full_block, last_tweak)
                        decrypted_block = bytearray(cipher.decrypt(bytes(xored_block)))
                        final_block = bytearray(16)
                        self._xts_xor_block(final_block, decrypted_block, last_tweak)
                        
                        # Save the partial result
                        partial_len = sector_len % 16
                        dst_image[i+full_block_start:i+full_block_start+partial_len] = final_block[:partial_len]
                        
                        # Debug log
                        if i < 0x2000:  # First 2 sectors for debugging
                            self.logger(f"Block {current_sector}:{j} (last partial):")
                            self.logger(f"  Input:    {block.hex()}")
                            self.logger(f"  Tweak:    {last_tweak.hex()}")
                            self.logger(f"  FullBlock:{full_block.hex()}")
                            self.logger(f"  Final:    {final_block[:partial_len].hex()}")
                        
                        break
                
                # For full blocks or when not the last partial block
                if len(block) == 16:
                    block_tweak = bytearray(current_tweak)
                    
                    # Xor the block with the encrypted tweak
                    xored_block = bytearray(16)
                    self._xts_xor_block(xored_block, block, block_tweak)
                    
                    # Decrypt the block
                    try:
                        decrypted_block = bytearray(cipher.decrypt(bytes(xored_block)))
                    except Exception as e:
                        self.logger(f"ERROR decrypting block at sector {current_sector}, offset {j*16}: {e}")
                        raise
                    
                    # Xor again with the encrypted tweak
                    final_block = bytearray(16)
                    self._xts_xor_block(final_block, decrypted_block, block_tweak)
                    
                    # Copy to destination
                    dst_image[i+block_start:i+block_end] = final_block[:len(block)]
                    
                    # Debug logging for the first few blocks
                    if i < 0x2000 and j < 4:  # First 2 sectors, first 4 blocks
                        self.logger(f"Block {current_sector}:{j}:")
                        self.logger(f"  Input:    {block.hex()}")
                        self.logger(f"  Tweak:    {block_tweak.hex()}")
                        self.logger(f"  XORed:    {xored_block.hex()}")
                        self.logger(f"  Decrypted:{decrypted_block.hex()}")
                        self.logger(f"  Final:    {final_block.hex()}")
                
                # Multiply the tweak by α in GF(2^128) for the next block
                if not is_last_block:  # Don't update tweak after the last block
                    prev_tweak = current_tweak.copy()
                    self._xts_mult(current_tweak)
        
        # Save the first 256 bytes of decrypted data for inspection
        debug_path = os.path.join(os.path.dirname(__file__), "debug_decrypted.bin")
        with open(debug_path, "wb") as f:
            f.write(dst_image[:min(256, len(dst_image))])
        self.logger(f"DEBUG: First 256 bytes of decrypted data saved to {debug_path}")
        
        # Check if the decrypted data is all zeros
        if len(dst_image) >= 32 and all(b == 0 for b in dst_image[:32]):
            self.logger("WARNING: First 32 bytes of decrypted data are all zeros!")
            
            # Try a known-answer test with the same keys
            self.logger("Performing known-answer test...")
            test_plain = b'\x00' * 16
            test_tweak = b'\x00' * 16
            test_cipher = AES.new(dataKey, AES.MODE_ECB)
            test_tweak_cipher = AES.new(tweakKey, AES.MODE_ECB)
            
            # Encrypt the tweak
            enc_tweak = test_tweak_cipher.encrypt(test_tweak)
            
            # Xor plaintext with encrypted tweak
            xored = bytes(a ^ b for a, b in zip(test_plain, enc_tweak))
            
            # Encrypt the result
            encrypted = test_cipher.encrypt(xored)
            
            # Xor with encrypted tweak again
            final = bytes(a ^ b for a, b in zip(encrypted, enc_tweak))
            
            self.logger(f"KAT - Plain: {test_plain.hex()}")
            self.logger(f"KAT - Tweak: {test_tweak.hex()}")
            self.logger(f"KAT - Enc tweak: {enc_tweak.hex()}")
            self.logger(f"KAT - Xored: {xored.hex()}")
            self.logger(f"KAT - Encrypted: {encrypted.hex()}")
            self.logger(f"KAT - Final: {final.hex()}")
        
        return bytes(dst_image)

# ... (rest of the code remains the same)
class PKG:
    def __init__(self, logger_func=print):
        self.logger = logger_func
        self.pkg_header: Optional[PKGHeader] = None
        self.pkg_file_size: int = 0 # Dimensione reale del file PKG su disco
        self.pkg_title_id: str = ""
        self.sfo_data: bytes = b""
        self.pkg_flags_str: str = ""

        self.extract_base_path: Optional[pathlib.Path] = None # Path base fornito dall'utente
        self.pkg_path: Optional[pathlib.Path] = None
        
        self.crypto = RealCrypto(logger_func=self.logger)

        self.dk3_ = bytearray(32) 
        self.ivKey = bytearray(32)
        self.imgKey = bytearray(256)
        self.ekpfsKey = bytearray(32)

        self.dataKey = bytearray(16)
        self.tweakKey = bytearray(16)
        
        self.decNp = bytearray()

        # Attributi specifici del PFS
        self.pfs_superblock_header: Optional[PFSHeaderPfs] = None # Header del PFS (superblocco)
        self.pfs_chdr: Optional[PFSCHdrPFS] = None                 # Header del PFSC effettivo
        self.pfsc_offset_in_pfs_image: int = -1 # Offset di PFSC *all'interno* dell'immagine PFS decrittata
        self.pfsc_content_actual_bytes: bytes = b'' # Contenuto effettivo del PFSC (dall'header PFSC in poi)
        
        self.sector_map: list[int] = []
        self.iNodeBuf: list[Inode] = []
        self.fs_table: list[FSTableEntry] = [] # Tabella flat di file/dir trovati nel PFS
        self.extract_paths: dict[int, pathlib.Path] = {} # Mappa: inode_num -> pathlib.Path completo di estrazione
        # self.current_dir_pfs non è più un membro di istanza, ma gestito localmente nel BFS.

    def _log(self, message):
        if self.logger: self.logger(message)

    def _read_pkg_header(self, f) -> bool:
        try:
            header_bytes = f.read(PKGHeader._TOTAL_PKGHEADER_SIZE)
            if len(header_bytes) < PKGHeader._TOTAL_PKGHEADER_SIZE:
                self._log("ERRORE: Lettura incompleta PKGHeader."); return False
            self.pkg_header = PKGHeader.from_bytes(header_bytes)
            return True
        except Exception as e:
            self._log(f"ERRORE lettura/parsing PKGHeader: {e}"); import traceback; self.logger(traceback.format_exc()); return False

    def _get_pkg_entry_name_by_type(self, entry_id: int) -> str:
        return PKG_ENTRY_ID_TO_NAME_FULL.get(entry_id, "")

    def get_title_id(self) -> str: return self.pkg_title_id

    def open_pkg(self, filepath: pathlib.Path) -> tuple[bool, str]:
        self._log(f"Apertura PKG: {filepath}")
        try:
            with open(filepath, "rb") as f:
                self.pkg_file_size = f.seek(0, os.SEEK_END); f.seek(0)
                if not self.pkg_header: # Se non già caricato
                 if not self._read_pkg_header(f): return False, "Fallimento lettura header PKG."
                
                if self.pkg_header.magic not in [PKG_MAGIC_BE, PKG_MAGIC_LE_VARIANT]:
                    return False, f"Magic PKG non valido: {self.pkg_header.magic:#x}"
                
                flags_list = [name for flag, name in PKG_FLAG_NAMES_MAP.items() if (self.pkg_header.pkg_content_flags & flag.value)]
                self.pkg_flags_str = ", ".join(flags_list)
                # self._log(f"Flags PKG: {self.pkg_flags_str}") # Log meno verboso per open

                # Title ID (dal C++ file.Seek(0x47) dopo aver letto l'header)
                # Questo implica un seek assoluto nel file, non relativo all'header in memoria.
                f.seek(0x47) 
                title_id_bytes_raw = f.read(9)
                self.pkg_title_id = title_id_bytes_raw.decode('ascii', errors='ignore').strip('\0')
                # self._log(f"Title ID (da seek 0x47): {self.pkg_title_id}")

                f.seek(self.pkg_header.pkg_table_entry_offset)
                for _ in range(self.pkg_header.pkg_table_entry_count):
                    entry_bytes = f.read(PKGEntry._SIZE)
                    if len(entry_bytes) < PKGEntry._SIZE: return False, "Lettura PKG entry incompleta."
                    entry = PKGEntry.from_bytes(entry_bytes)
                    entry.name = self._get_pkg_entry_name_by_type(entry.id)
                    if entry.name == "param.sfo":
                        curr_pos = f.tell(); f.seek(entry.offset)
                        self.sfo_data = f.read(entry.size)
                        # self._log(f"param.sfo trovato (size {len(self.sfo_data)})."); 
                        f.seek(curr_pos)
            self.pkg_path = filepath
            return True, "PKG aperto con successo."
        except Exception as e:
            self._log(f"Errore apertura PKG: {e}"); import traceback; self._log(traceback.format_exc()); return False, f"Errore: {e}"

    def extract(self, filepath: pathlib.Path, extract_base_path_gui: pathlib.Path) -> tuple[bool, str]:
        
        # Initialize variables outside the try block
        self.pkg_path = filepath
        self._log(f"Inizio estrazione da: {filepath} a GUI base: {extract_base_path_gui}")
        pfsc_content_actual_bytes = b'' # Initialize to ensure it's always defined
        
        # Main try block for the extract method
        try:
            # Using with statement for file handling
            with open(filepath, "rb") as f:
                if not self.pkg_header: 
                    f.seek(0)
                    if not self._read_pkg_header(f): return False, "Fallimento rilettura header."
                    f.seek(0x47); self.pkg_title_id = f.read(9).decode('ascii', errors='ignore').strip('\0')

                if self.pkg_header.magic not in [PKG_MAGIC_BE, PKG_MAGIC_LE_VARIANT]: return False, "Magic PKG non valido in extract."

                title_id_str = self.get_title_id() or filepath.stem
                is_update_dlc = "-UPDATE" in str(self.pkg_path).upper() or title_id_str.startswith(("EP", "IP", "HP")) or "_PATCH" in str(self.pkg_path).upper() or extract_base_path_gui.name.upper().endswith(("-UPDATE", "-DLC"))

                if extract_base_path_gui.name != title_id_str and extract_base_path_gui.parent.name != title_id_str and not is_update_dlc:
                    self.extract_base_path = extract_base_path_gui / title_id_str
                    
                else:
                    self.extract_base_path = extract_base_path_gui

                self._log(f"Directory estrazione effettiva: {self.extract_base_path}")
                self.extract_base_path.mkdir(parents=True, exist_ok=True)

                # --- Read PKG entries and store their raw bytes and parsed objects ---
                pkg_entries_data = []
                f.seek(self.pkg_header.pkg_table_entry_offset)
                for _ in range(self.pkg_header.pkg_table_entry_count):
                    entry_bytes = f.read(PKGEntry._SIZE)
                    if len(entry_bytes) < PKGEntry._SIZE:
                        return False, "Lettura tabella PKG entry incompleta."
                    entry = PKGEntry.from_bytes(entry_bytes)
                    entry.name = self._get_pkg_entry_name_by_type(entry.id)
                    pkg_entries_data.append({'obj': entry, 'bytes': entry_bytes})

                # --- Step 1: Derive main crypto keys (dk3, ekpfsKey) ---
                entry_0010_obj = next((item['obj'] for item in pkg_entries_data if item['obj'].id == 0x0010), None)
                if entry_0010_obj:
                    f.seek(entry_0010_obj.offset)
                    _ = f.read(32) # seed_digest
                    _ = [f.read(32) for _ in range(7)] 
                    key1_list = [f.read(256) for _ in range(7)]
                    self.crypto.RSA2048Decrypt(self.dk3_, key1_list[3], True)
                    self._log(f"  DEBUG dk3_ (primi 16B): {self.dk3_[:16].hex()}")
                else:
                    self._log("AVVISO: Entry PKG 0x0010 (ENTRY_KEYS) non trovata. dk3_ potrebbe non essere derivata.")
                    # dk3_ rimarrà inizializzata a zeri se non trovata.

                entry_0020_item = next((item for item in pkg_entries_data if item['obj'].id == 0x0020), None)
                if not entry_0020_item:
                    return False, "Entry PKG 0x0020 (IMAGE_KEY) non trovata, impossibile derivare ekpfsKey."
                
                entry_0020_obj = entry_0020_item['obj']
                entry_0020_bytes = entry_0020_item['bytes']

                f.seek(entry_0020_obj.offset)
                imgkeydata_crypted_bytes = f.read(entry_0020_obj.size)
                
                concat_buf = bytearray(64)
                concat_buf[:PKGEntry._SIZE] = entry_0020_bytes
                concat_buf[PKGEntry._SIZE:PKGEntry._SIZE+32] = self.dk3_[:32]
                
                self.crypto.ivKeyHASH256(bytes(concat_buf), self.ivKey)
                self._log(f"  DEBUG ivKey (calcolata da entry 0x0020 e dk3_, primi 16B): {self.ivKey[:16].hex()}")
                
                self._log(f"  DEBUG imgKey DA PASSARE A RSA (primi 32B prima di AES decrypt): {imgkeydata_crypted_bytes[:32].hex()}") # Questo è imgkeydata_crypted_bytes
                self.crypto.aesCbcCfb128Decrypt(self.ivKey, imgkeydata_crypted_bytes, self.imgKey)
                self._log(f"  DEBUG imgKey (dopo AES, primi 32B): {self.imgKey[:32].hex()}")
                self._log(f"  DEBUG imgKey (dopo AES, ultimi 32B se >32B): {self.imgKey[-32:].hex() if len(self.imgKey)>32 else self.imgKey.hex()}")
                
                self.crypto.RSA2048Decrypt(self.ekpfsKey, self.imgKey, False)
                self._log(f"  DEBUG ekpfsKey (dopo RSA): {self.ekpfsKey.hex()}")


                # --- Step 2: Extract system files (sce_sys) ---
                sce_sys_path = self.extract_base_path / "sce_sys"
                sce_sys_path.mkdir(parents=True, exist_ok=True)
                self._log(f"Directory output per SCE_SYS: {sce_sys_path}")
                self._log(f"Directory output radice per PFS: {self.extract_base_path}")


                for item in pkg_entries_data:
                    entry, original_entry_bytes = item['obj'], item['bytes']
                    out_fname_base = entry.name or str(entry.id)
                    
                    current_out_path = self.extract_base_path # Default per path complessi
                    if '/' in out_fname_base:
                        # Path come "app/playgo-chunk.dat" o "trophy/trophy00.trp"
                        # Questi vanno relativi alla radice di estrazione, non necessariamente in sce_sys
                        final_out_path = self.extract_base_path / out_fname_base
                    elif entry.id >= 0x0001 and entry.id <= 0x17F9 : # Range IDs di sistema tipici
                        final_out_path = sce_sys_path / out_fname_base
                    else: # Fallback per ID sconosciuti o non di sistema
                        final_out_path = self.extract_base_path / f"unknown_id_{entry.id:#06x}"

                    self._log(f"  Processing PKG SysEntry ID {entry.id:#06x} ('{out_fname_base}'), Offset: {entry.offset:#x}, Size: {entry.size} -> {final_out_path}")

                    if entry.size > 0:
                        f.seek(entry.offset)
                        file_content_from_pkg = f.read(entry.size)
                        data_to_write_final = file_content_from_pkg

                        # Decrittografia per specifici file di sistema
                        if entry.id in [0x0400, 0x0401, 0x0402, 0x0403]: # license.dat, license.info, nptitle.dat, npbind.dat
                            current_entry_decrypted_data = bytearray(entry.size)
                            temp_concat_np = bytearray(64)
                            temp_concat_np[:PKGEntry._SIZE] = original_entry_bytes # Usa i bytes dell'header dell'entry corrente (0x04xx)
                            temp_concat_np[PKGEntry._SIZE:PKGEntry._SIZE+32] = self.dk3_[:32]
                            
                            local_ivKey_for_sce_entry = bytearray(32) # Usa una ivKey locale per questa entry
                            self.crypto.ivKeyHASH256(bytes(temp_concat_np), local_ivKey_for_sce_entry)
                            # self._log(f"    DEBUG local_ivKey for {entry.name} (primi 16B): {local_ivKey_for_sce_entry[:16].hex()}")

                            self.crypto.aesCbcCfb128DecryptEntry(local_ivKey_for_sce_entry, file_content_from_pkg, current_entry_decrypted_data)
                            data_to_write_final = current_entry_decrypted_data
                        
                        final_out_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(final_out_path, "wb") as of:
                            of.write(data_to_write_final)
                        self._log(f"    Scritto: {final_out_path} ({len(data_to_write_final)} bytes)")

                # --- Step 3: Process PFS ---
                self._log("Inizio processamento PFS...")
                f.seek(self.pkg_header.pfs_image_offset + 0x370) # Offset del seed nel PKG
                seed_bytes = f.read(16)
                
                self._log("DEBUG PFS CRYPTO KEYS (prima di PfsGenCryptoKey):")
                self._log(f"  ekpfsKey: {self.ekpfsKey.hex()}")
                self._log(f"  seed_bytes: {seed_bytes.hex()}")
                self.crypto.PfsGenCryptoKey(self.ekpfsKey, seed_bytes, self.dataKey, self.tweakKey)
                self._log(f"  dataKey (dopo PfsGen): {self.dataKey.hex()}")
                self._log(f"  tweakKey (dopo PfsGen): {self.tweakKey.hex()}")


                # --- PFSC Discovery and Parsing ---
                self.pfsc_offset_in_pfs_image = -1
                # pfsc_content_actual_bytes è già inizializzato a b''

                if self.pkg_header.pfs_image_size == 0:
                    self._log("Nessuna immagine PFS (pfs_image_size è 0). Salto parsing PFS.")
                elif self.pkg_header.pfs_cache_size == 0:
                    self._log("ERRORE: pfs_cache_size è 0, il parsing PFS standard non è possibile.")
                else:
                    f.seek(self.pkg_header.pfs_image_offset)
                    
                    # Calcolo dimensione C++ per debug_pfs_decrypted_chunk.bin
                    # buffer_size_cpp = (self.pkg_header.pfs_image_offset + self.pkg_header.pfs_image_size + 0x3FFF) & ~0x3FFF
                    # len_to_read_for_pfsc_discovery_cpp = buffer_size_cpp - self.pkg_header.pfs_image_offset
                    # self._log(f"Buffer PFSC C++ (length) calcolato come: {len_to_read_for_pfsc_discovery_cpp:#x} bytes.")
                    # Usiamo una dimensione basata su pfs_cache_size o dimensione immagine PFS
                    len_to_read_for_pfsc_discovery = min(self.pkg_header.pfs_cache_size * 2, self.pkg_header.pfs_image_size, 0x400000) # Limita a 4MB per la scoperta iniziale
                    
                    initial_pfs_chunk_for_discovery = b''
                    if len_to_read_for_pfsc_discovery > 0:
                        initial_pfs_chunk_for_discovery = f.read(len_to_read_for_pfsc_discovery)
                    
                    effective_len_initial_decrypt = (len(initial_pfs_chunk_for_discovery) // 0x1000) * 0x1000

                    if effective_len_initial_decrypt == 0:
                        self._log(f"AVVISO: Chunk PFS iniziale ({len_to_read_for_pfsc_discovery} B) troppo corto per decrittare un settore. Impossibile trovare PFSC.")
                    else:
                        initial_pfs_chunk_to_decrypt = initial_pfs_chunk_for_discovery[:effective_len_initial_decrypt]
                        decrypted_initial_pfs_chunk = bytearray(effective_len_initial_decrypt)
                        self.crypto.decryptPFS(self.dataKey, self.tweakKey, initial_pfs_chunk_to_decrypt, decrypted_initial_pfs_chunk, 0)
                        
                        # --- Debug: Salva il chunk decrittato ---
                        debug_chunk_path = self.extract_base_path / "debug_pfs_decrypted_chunk.bin"
                        try:
                            with open(debug_chunk_path, "wb") as dbg_f:
                                dbg_f.write(decrypted_initial_pfs_chunk)
                            self._log(f"DEBUG: Chunk PFS decrittato salvato in: {debug_chunk_path}")
                            self._log(f"DEBUG: Chunk size: {len(decrypted_initial_pfs_chunk):#x} bytes")
                            self._log("DEBUG: Primi 256 bytes del chunk decrittato:")
                            for i_debug in range(0, min(256, len(decrypted_initial_pfs_chunk)), 32):
                                self._log(f"  {i_debug:04x}: {decrypted_initial_pfs_chunk[i_debug:i_debug+32].hex()}")
                                
                            # Log the sector map area if we can find it
                            if hasattr(self, 'pfsc_offset_in_pfs_image') and self.pfsc_offset_in_pfs_image > 0:
                                sector_map_start = self.pfsc_offset_in_pfs_image + pfs_chdr_initial.block_offsets
                                sector_map_end = sector_map_start + size_of_sector_map_table
                                if sector_map_end <= len(decrypted_initial_pfs_chunk):
                                    self._log(f"\nDEBUG: Sector Map Data (offset 0x{sector_map_start:08x} - 0x{sector_map_end:08x}):")
                                    for i in range(0, min(64, size_of_sector_map_table), 8):
                                        offset = sector_map_start + i
                                        if offset + 8 <= len(decrypted_initial_pfs_chunk):
                                            value = struct.unpack_from('<Q', decrypted_initial_pfs_chunk, offset)[0]
                                            self._log(f"  {offset:08x}: {value:016x}")
                        except Exception as e_dbg:
                            self._log(f"DEBUG: Errore salvataggio/analisi chunk decrittato: {e_dbg}")
                            import traceback
                            self._log(f"DEBUG: {traceback.format_exc()}")
                        # --- Fine Debug ---

                        current_pfsc_offset_in_decrypted_chunk = get_pfsc_offset(decrypted_initial_pfs_chunk, self._log)

                        if current_pfsc_offset_in_decrypted_chunk == -1:
                            self._log("Magic PFSC non trovato nel chunk PFS iniziale decrittato.")
                            self.pfsc_offset_in_pfs_image = -1 
                        elif current_pfsc_offset_in_decrypted_chunk + PFSCHdrPFS._SIZE > len(decrypted_initial_pfs_chunk):
                            self._log("ERRORE: Chunk PFS iniziale decrittato troppo piccolo per contenere PFSCHdr, anche se PFSC magic è stato trovato.")
                            self.pfsc_offset_in_pfs_image = -1
                        else:
                            pfs_chdr_initial = PFSCHdrPFS.from_bytes(decrypted_initial_pfs_chunk[current_pfsc_offset_in_decrypted_chunk:])
                            self._log(f"PFSC magic trovato a {current_pfsc_offset_in_decrypted_chunk:#x}. Header PFSC iniziale letto.")
                            self.pfsc_offset_in_pfs_image = current_pfsc_offset_in_decrypted_chunk
                            
                            num_data_blocks = 0
                            if pfs_chdr_initial.block_sz2 > 0:
                                num_data_blocks = int(pfs_chdr_initial.data_length / pfs_chdr_initial.block_sz2) if pfs_chdr_initial.data_length % pfs_chdr_initial.block_sz2 == 0 else int(pfs_chdr_initial.data_length // pfs_chdr_initial.block_sz2 + 1)
                            
                            size_of_sector_map_table = (num_data_blocks + 1) * 8
                            estimated_pfsc_internal_content_size = pfs_chdr_initial.block_offsets + size_of_sector_map_table # Minima stima iniziale
                            
                            initial_sector_map_data_offset_in_pfsc = pfs_chdr_initial.block_offsets
                            initial_sector_map_data_abs_offset_in_chunk = self.pfsc_offset_in_pfs_image + initial_sector_map_data_offset_in_pfsc
                            
                            if initial_sector_map_data_abs_offset_in_chunk + size_of_sector_map_table > len(decrypted_initial_pfs_chunk):
                                self._log(f"AVVISO: Chunk iniziale ({len(decrypted_initial_pfs_chunk)} B) non contiene l'intera tabella degli offset dei settori.")
                                available_sector_map_bytes = len(decrypted_initial_pfs_chunk) - initial_sector_map_data_abs_offset_in_chunk
                                if available_sector_map_bytes > 0 and available_sector_map_bytes >= (num_data_blocks * 8 + 8) : # Se abbiamo almeno l'ultima entry della mappa
                                     temp_map_data = decrypted_initial_pfs_chunk[initial_sector_map_data_abs_offset_in_chunk : initial_sector_map_data_abs_offset_in_chunk + (num_data_blocks * 8 + 8)]
                                     total_compressed_data_size = struct.unpack_from("<Q", temp_map_data, num_data_blocks * 8)[0]
                                     estimated_pfsc_internal_content_size = max(estimated_pfsc_internal_content_size, pfs_chdr_initial.data_start + total_compressed_data_size)
                                else: # Stima più grezza se non abbiamo l'intera mappa
                                     estimated_pfsc_internal_content_size = max(estimated_pfsc_internal_content_size, pfs_chdr_initial.data_start + pfs_chdr_initial.data_length)
                            else: 
                                temp_map_data = decrypted_initial_pfs_chunk[initial_sector_map_data_abs_offset_in_chunk : initial_sector_map_data_abs_offset_in_chunk + size_of_sector_map_table]
                                if num_data_blocks >=0 and (num_data_blocks * 8 + 8) <= len(temp_map_data) : 
                                   total_compressed_data_size = struct.unpack_from("<Q", temp_map_data, num_data_blocks * 8)[0]
                                   estimated_pfsc_internal_content_size = max(
                                       pfs_chdr_initial.block_offsets + size_of_sector_map_table, 
                                       pfs_chdr_initial.data_start + total_compressed_data_size
                                   )
                            
                            # Debug log all relevant values
                            self._log(f"DEBUG: PFS Header Values:")
                            self._log(f"  block_sz: {pfs_chdr_initial.block_sz} (0x{pfs_chdr_initial.block_sz:x})")
                            self._log(f"  block_sz2: {pfs_chdr_initial.block_sz2} (0x{pfs_chdr_initial.block_sz2:x})")
                            self._log(f"  block_offsets: {pfs_chdr_initial.block_offsets} (0x{pfs_chdr_initial.block_offsets:x})")
                            self._log(f"  data_start: {pfs_chdr_initial.data_start} (0x{pfs_chdr_initial.data_start:x})")
                            self._log(f"  data_length: {pfs_chdr_initial.data_length} (0x{pfs_chdr_initial.data_length:x})")
                            self._log(f"  num_data_blocks: {num_data_blocks} (0x{num_data_blocks:x})")
                            self._log(f"  size_of_sector_map_table: {size_of_sector_map_table} (0x{size_of_sector_map_table:x})")
                            
                            if 'total_compressed_data_size' in locals():
                                self._log(f"  total_compressed_data_size: {total_compressed_data_size} (0x{total_compressed_data_size:x})")
                            
                            # Ensure we don't have negative values
                            if estimated_pfsc_internal_content_size < 0:
                                self._log(f"ERRORE: Dimensione PFSC interna stimata negativa: {estimated_pfsc_internal_content_size}")
                                self._log("  Questo indica un problema con la decrittazione o con i valori dell'header PFSC.")
                                self._log("  Verificare che i dati decrittati siano corretti e che l'header PFSC sia valido.")
                                
                                # Try to recover by using just the PFSC header size as a fallback
                                estimated_pfsc_internal_content_size = PFSCHdrPFS._SIZE
                                self._log(f"  Utilizzo dimensione minima di fallback: {estimated_pfsc_internal_content_size} bytes")
                            
                            total_pfsc_span_in_pfs_image = self.pfsc_offset_in_pfs_image + estimated_pfsc_internal_content_size
                            
                            # Ensure we don't exceed the PFS image size
                            if total_pfsc_span_in_pfs_image > self.pkg_header.pfs_image_size:
                                self._log(f"AVVISO: La dimensione stimata del PFSC ({total_pfsc_span_in_pfs_image} B) eccede la dimensione dell'immagine PFS ({self.pkg_header.pfs_image_size} B).")
                                self._log(f"  Verrà utilizzata la dimensione dell'immagine PFS meno l'offset PFSC.")
                                total_pfsc_span_in_pfs_image = self.pkg_header.pfs_image_size - self.pfsc_offset_in_pfs_image
                                if total_pfsc_span_in_pfs_image < PFSCHdrPFS._SIZE:
                                    self._log(f"  AVVISO GRAVE: Lo spazio disponibile ({total_pfsc_span_in_pfs_image} B) è minore della dimensione minima dell'header PFSC ({PFSCHdrPFS._SIZE} B)")
                                    total_pfsc_span_in_pfs_image = PFSCHdrPFS._SIZE
                            
                            # Align to 0x1000 boundary
                            total_len_to_read_for_full_pfsc_aligned = ((total_pfsc_span_in_pfs_image + 0xFFF) // 0x1000) * 0x1000
                            
                            self._log(f"Dimensione interna PFSC stimata: {estimated_pfsc_internal_content_size} B. Totale da leggere/decrittare per PFSC completo: {total_len_to_read_for_full_pfsc_aligned} B")

                            f.seek(self.pkg_header.pfs_image_offset)
                            # Ensure we don't try to read a negative length
                            read_length = min(total_len_to_read_for_full_pfsc_aligned, self.pkg_header.pfs_image_size)
                            if read_length <= 0:
                                raise ValueError(f"Invalid read length: {read_length}. PFSC offset: {self.pfsc_offset_in_pfs_image}, estimated size: {estimated_pfsc_internal_content_size}")
                                
                            full_pfs_chunk_for_pfsc_processing = f.read(read_length)
                            effective_len_full_pfsc_decrypt = (len(full_pfs_chunk_for_pfsc_processing) // 0x1000) * 0x1000

                            if effective_len_full_pfsc_decrypt == 0:
                                self._log("ERRORE: Nessun dato da decrittare per il PFSC completo.")
                                self.pfsc_offset_in_pfs_image = -1 
                            elif effective_len_full_pfsc_decrypt < self.pfsc_offset_in_pfs_image + PFSCHdrPFS._SIZE :
                                self._log(f"ERRORE: Non è stato possibile leggere abbastanza dati ({effective_len_full_pfsc_decrypt}) per l'header PFSC completo.")
                                self.pfsc_offset_in_pfs_image = -1
                            else:
                                full_pfs_chunk_to_decrypt = full_pfs_chunk_for_pfsc_processing[:effective_len_full_pfsc_decrypt]
                                decrypted_full_pfsc_area = bytearray(effective_len_full_pfsc_decrypt)
                                self.crypto.decryptPFS(self.dataKey, self.tweakKey, full_pfs_chunk_to_decrypt, decrypted_full_pfsc_area, 0)
                                self._log(f"Area PFS completa (basata su cache_size*2) decrittata: {len(decrypted_full_pfsc_area)} bytes")
                                
                                # --- AGGIUNGI DEBUG per area PFSC completa ---
                                debug_full_pfsc_path = self.extract_base_path / "debug_DECRYPTED_FULL_PFSC_AREA.bin"
                                try:
                                    with open(debug_full_pfsc_path, "wb") as dbg_f_full:
                                        dbg_f_full.write(decrypted_full_pfsc_area)
                                    self._log(f"DEBUG: Area PFSC completa decrittata salvata in: {debug_full_pfsc_path}")
                                    self._log(f"DEBUG: Primi 256B di quest'area: {decrypted_full_pfsc_area[:256].hex()}")
                                    
                                    # Controlla l'area dove ti aspetti il superblocco compresso:
                                    # Offset del superblocco compresso dentro decrypted_full_pfsc_area:
                                    # self.pfsc_offset_in_pfs_image (offset di PFSC dentro decrypted_full_pfsc_area)
                                    # + self.pfs_chdr.data_start (offset dell'area dati dentro PFSC)
                                    # + self.sector_map[0] (offset del superblocco dentro l'area dati)
                                    if num_data_blocks > 0 and size_of_sector_map_table > 0: # Assicurati che siano stati calcolati
                                        temp_map_data = decrypted_full_pfsc_area[initial_sector_map_data_abs_offset_in_chunk : initial_sector_map_data_abs_offset_in_chunk + size_of_sector_map_table]
                                        # Log primi 5 valori della sector_map (se disponibili)
                                        sector_map_preview = []
                                        for i in range(min(5, num_data_blocks + 1)):
                                            if i * 8 + 8 <= len(temp_map_data):
                                                sector_map_preview.append(struct.unpack_from("<Q", temp_map_data, i * 8)[0])
                                        if sector_map_preview:
                                            self._log(f"DEBUG: Primi {len(sector_map_preview)} valori della sector_map estratti direttamente da decrypted_full_pfsc_area: {sector_map_preview}")
                                        
                                        # Stima offset superblocco assumendo che pfs_chdr_initial sia valido
                                        if len(sector_map_preview) >= 1:
                                            estimated_sb_offset = self.pfsc_offset_in_pfs_image + pfs_chdr_initial.data_start + sector_map_preview[0]
                                            estimated_sb_size = 0
                                            if len(sector_map_preview) >= 2:
                                                estimated_sb_size = sector_map_preview[1] - sector_map_preview[0]
                                            else:
                                                estimated_sb_size = 144  # Dimensione riportata in log precedenti
                                                
                                            self._log(f"DEBUG: Stima posizione superblocco compresso in DECRYPTED_FULL_PFSC_AREA: "
                                                    f"offset {estimated_sb_offset:#x} (dim: {estimated_sb_size})")
                                            
                                            if estimated_sb_offset + estimated_sb_size <= len(decrypted_full_pfsc_area):
                                                sb_compressed_sample = decrypted_full_pfsc_area[estimated_sb_offset:estimated_sb_offset + min(64, estimated_sb_size)]
                                                self._log(f"DEBUG: Primi {min(64, estimated_sb_size)} byte superblocco COMPRESSO da area completa: {sb_compressed_sample.hex()}")
                                                
                                                # Salva campione più ampio (256 bytes o size del superblocco) prima e dopo l'offset stimato
                                                sample_size = max(256, estimated_sb_size)
                                                sample_start = max(0, estimated_sb_offset - 128)
                                                sample_end = min(len(decrypted_full_pfsc_area), estimated_sb_offset + sample_size + 128)
                                                sb_area_sample = decrypted_full_pfsc_area[sample_start:sample_end]
                                                sb_sample_path = self.extract_base_path / "debug_superblock_area_sample.bin"
                                                with open(sb_sample_path, "wb") as sb_sample_f:
                                                    sb_sample_f.write(sb_area_sample)
                                                self._log(f"DEBUG: Campione area intorno al superblocco compresso salvato in: {sb_sample_path}")
                                                self._log(f"DEBUG: Campione inizia a offset assoluto {sample_start:#x}, superblocco atteso a {estimated_sb_offset:#x} (offset {estimated_sb_offset-sample_start} nel file)")
                                            else:
                                                self._log("DEBUG: Offset stimato del superblocco fuori dai limiti di decrypted_full_pfsc_area!")
                                except Exception as e_dbg_full:
                                    self._log(f"DEBUG: Errore debug area PFSC completa: {e_dbg_full}")
                                # --- FINE DEBUG ---
                                
                                actual_pfsc_data_end_offset_in_chunk = min(self.pfsc_offset_in_pfs_image + estimated_pfsc_internal_content_size, len(decrypted_full_pfsc_area))
                                pfsc_content_actual_bytes = decrypted_full_pfsc_area[self.pfsc_offset_in_pfs_image : actual_pfsc_data_end_offset_in_chunk]
                                
                                if len(pfsc_content_actual_bytes) < PFSCHdrPFS._SIZE:
                                    self._log(f"ERRORE: pfsc_content_actual_bytes ({len(pfsc_content_actual_bytes)}) troppo corto per PFSCHdrPFS dopo decrittazione completa.")
                                    self.pfsc_offset_in_pfs_image = -1
                                else:
                                    self.pfs_chdr = PFSCHdrPFS.from_bytes(pfsc_content_actual_bytes)
                                    self._log(f"PFSC Header definitivo letto. Magic: {self.pfs_chdr.magic:#x}, BlockOffsets: {self.pfs_chdr.block_offsets:#x}, Block Size2: {self.pfs_chdr.block_sz2}, Data Length: {self.pfs_chdr.data_length}")
                                    self._log(f"DEBUG: Lunghezza pfsc_content_actual_bytes dopo lettura header: {len(pfsc_content_actual_bytes)}")
                                    # Salviamo una referenza a pfsc_content_actual_bytes nella variabile d'istanza
                                    self.pfsc_content_actual_bytes = pfsc_content_actual_bytes
                                    
                                    self.sector_map.clear()
                                    if self.pfs_chdr.block_sz2 > 0:
                                        # Questo è il numero di blocchi di dati completi (divisione intera/troncamento)
                                        num_data_blocks_in_pfsc = int(self.pfs_chdr.data_length // self.pfs_chdr.block_sz2)
                                    else:
                                        num_data_blocks_in_pfsc = 0
                                    # La mappa ha un'entry in più per l'offset finale
                                    map_size_entries = num_data_blocks_in_pfsc + 1
                                    map_offset_in_pfsc_content_final = self.pfs_chdr.block_offsets
                                    map_size_bytes_final = map_size_entries * 8
                                    
                                    # Debug log per verificare i valori prima del controllo
                                    self._log(f"DEBUG: Check accesso SectorMap: map_offset={map_offset_in_pfsc_content_final:#x}, map_size_bytes={map_size_bytes_final}, len(pfsc_content)={len(self.pfsc_content_actual_bytes)}")
                                    
                                    if map_offset_in_pfsc_content_final + map_size_bytes_final > len(self.pfsc_content_actual_bytes):
                                        self._log(f"ERRORE: pfsc_content_actual_bytes ({len(self.pfsc_content_actual_bytes)}) troppo corto per la sector_map completa (fino a {map_offset_in_pfsc_content_final + map_size_bytes_final}). N. blocchi attesi in mappa: {map_size_entries}")
                                        self.pfsc_offset_in_pfs_image = -1
                                    else:
                                        current_sector_map_data = self.pfsc_content_actual_bytes[map_offset_in_pfsc_content_final : map_offset_in_pfsc_content_final + map_size_bytes_final]
                                        for i in range(map_size_entries): # Itera per il numero corretto di entry
                                            self.sector_map.append(struct.unpack_from("<Q", current_sector_map_data, i * 8)[0])
                                        self._log(f"Sector map definitiva caricata: {len(self.sector_map)} entries (attese {map_size_entries}).")
                # Fine del blocco else per pfs_image_size/cache_size (L1385 originale)

                # Ora, dopo aver tentato di inizializzare self.pfs_chdr e self.sector_map
                if self.pfsc_offset_in_pfs_image != -1 and self.pfs_chdr and self.sector_map:
                    # Parsing Inodes e Dirents
                    self._log("Inizio parsing Inodes e Dirents dal contenuto PFSC caricato...")
                    self.iNodeBuf.clear(); self.fs_table.clear(); self.extract_paths.clear() # Corretta indentazione
                    
                    actual_total_inodes = 0
                    root_dir_inode_num = 0
                    
                    decomp_block_buf = bytearray(self.pfs_chdr.block_sz2 if self.pfs_chdr.block_sz2 > 0 else 0x10000)
                    if not decomp_block_buf: decomp_block_buf = bytearray(0x10000)
                    
                    # NOTA: I valori nella sector_map sono offset ASSOLUTI all'interno di pfsc_content_actual_bytes,
                    # non sono relativi a pfs_chdr.data_start
                    num_data_blocks_for_pfs_parsing = 0 
                    if self.pfs_chdr.block_sz2 > 0:
                         # Uso divisione intera come nella lettura della sector_map (troncamento)
                         num_data_blocks_for_pfs_parsing = int(self.pfs_chdr.data_length // self.pfs_chdr.block_sz2)

                    self._log(f"DEBUG: Numero di data blocks per PFS parsing: {num_data_blocks_for_pfs_parsing}")
                    self._log(f"DEBUG: Lunghezza sector_map: {len(self.sector_map)}")
                    
                    if num_data_blocks_for_pfs_parsing > 0 and len(self.sector_map) > 0:
                        # L'offset del superblocco (blocco 0) è direttamente da sector_map[0]
                        # ed è relativo all'inizio di pfsc_content_actual_bytes
                        super_block_offset_in_pfsc_content = self.sector_map[0]
                        
                        # Calcola la dimensione del blocco superblocco dai dati della sector_map
                        super_block_size_compressed = 0
                        if len(self.sector_map) > 1:
                            super_block_size_compressed = self.sector_map[1] - super_block_offset_in_pfsc_content
                        else:
                            self._log("AVVISO: Impossibile determinare la dimensione compressa del superblocco dalla sector_map.")
                            # Usa una dimensione stimata per la lettura (potrebbe causare errori)
                            super_block_size_compressed = 4096  # Valore arbitrario
                        
                        self._log(f"DEBUG: Superblocco PFS: offset in pfsc_content = {super_block_offset_in_pfsc_content:#x}, size_comp = {super_block_size_compressed:#x}")
                        
                        # Verifica che l'offset e la dimensione siano validi rispetto ai dati disponibili
                        if super_block_offset_in_pfsc_content + super_block_size_compressed > len(pfsc_content_actual_bytes):
                            self._log(f"ERRORE: Dati insuff. per Superblocco PFS in pfsc_content_actual_bytes. "
                                     f"Offset: {super_block_offset_in_pfsc_content:#x}, Size: {super_block_size_compressed:#x}, "
                                     f"Len pfsc_content: {len(pfsc_content_actual_bytes):#x}")
                            self.pfsc_offset_in_pfs_image = -1
                            actual_total_inodes = 0
                        elif super_block_size_compressed > 0:
                            # Estrai i dati compressi del superblocco direttamente dal contenuto PFSC usando l'offset della sector_map
                            super_block_compressed_data = pfsc_content_actual_bytes[
                                super_block_offset_in_pfsc_content : 
                                super_block_offset_in_pfsc_content + super_block_size_compressed
                            ]
                            
                            # --- Debug: Salva superblocco COMPRESSO ---
                            debug_sb_comp_path = self.extract_base_path / "debug_SUPERBLOCK_compressed.bin"
                            try:
                                with open(debug_sb_comp_path, "wb") as dbg_sb_c_f:
                                    dbg_sb_c_f.write(super_block_compressed_data)
                                self._log(f"DEBUG: Superblocco PFS COMPRESSO salvato in: {debug_sb_comp_path}")
                                self._log(f"DEBUG: Dimensione superblocco COMPRESSO: {len(super_block_compressed_data)}")
                                if len(super_block_compressed_data) >= 64:
                                    self._log(f"DEBUG: Primi 64 byte superblocco COMPRESSO: {super_block_compressed_data[:64].hex()}")
                                # Log dei valori iniziali della sector_map per debug
                                self._log(f"DEBUG: Primi 5 valori della sector_map: {self.sector_map[:min(5, len(self.sector_map))]}")
                                self._log(f"DEBUG: Offset superblocco in pfsc_content: {super_block_offset_in_pfsc_content:#x}")
                                self._log(f"DEBUG: Lunghezza pfsc_content: {len(pfsc_content_actual_bytes):#x}")
                            except Exception as e_dbg_sb_c:
                                self._log(f"DEBUG: Errore salvataggio superblocco compresso: {e_dbg_sb_c}")
                            # --- Fine Debug ---
                            
                            # --- LOGICA DECISIONALE PER COMPRESSIONE ---
                            if super_block_size_compressed == len(decomp_block_buf):
                                self._log(f"DEBUG: Superblocco PFS (size {super_block_size_compressed}) non compresso. Copia diretta.")
                                decompressed_superblock_data = super_block_compressed_data  # Copia diretta
                            elif 0 < super_block_size_compressed < len(decomp_block_buf):
                                self._log(f"DEBUG: Superblocco PFS compresso (size {super_block_size_compressed}). Decompressione...")
                                # Decompressione tramite zlib
                                decompressed_superblock_data = decompress_pfsc(super_block_compressed_data, len(decomp_block_buf), self._log)
                            else:
                                self._log(f"AVVISO: Dimensione compressa superblocco ({super_block_size_compressed}) anomala. Considero come non compresso.")
                                # Fallback: copiamo direttamente la porzione attesa
                                bytes_to_copy = min(super_block_size_compressed, len(decomp_block_buf))
                                decompressed_superblock_data = super_block_compressed_data[:bytes_to_copy]
                            # --- FINE LOGICA DECISIONALE ---
                            
                            # --- Debug: Salva superblocco decompresso ---
                            debug_sb_path = self.extract_base_path / "debug_SUPERBLOCK_decompressed.bin"
                            try:
                                with open(debug_sb_path, "wb") as dbg_sb_f:
                                    dbg_sb_f.write(decompressed_superblock_data)
                                self._log(f"DEBUG: Superblocco PFS decompresso salvato in: {debug_sb_path}")
                                self._log(f"DEBUG: Dimensione superblocco decompresso: {len(decompressed_superblock_data)}")
                                if len(decompressed_superblock_data) >= 80: # Abbastanza per i campi di interesse
                                    self._log(f"DEBUG: Primi 80 byte superblocco decomp: {decompressed_superblock_data[:80].hex()}")
                                    # Estrai dinode_count e superroot_ino direttamente per verifica
                                    dinode_count_raw = decompressed_superblock_data[48:56]  # offset 48, 8 bytes (q)
                                    superroot_ino_raw = decompressed_superblock_data[72:80] # offset 72, 8 bytes (q)
                                    dinode_count_direct = struct.unpack('<q', dinode_count_raw)[0]
                                    superroot_ino_direct = struct.unpack('<q', superroot_ino_raw)[0]
                                    self._log(f"DEBUG: dinode_count (lettura diretta): {dinode_count_direct}")
                                    self._log(f"DEBUG: superroot_ino (lettura diretta): {superroot_ino_direct}")
                            except Exception as e_dbg_sb:
                                self._log(f"DEBUG: Errore salvataggio superblocco: {e_dbg_sb}")
                            # --- Fine Debug ---
                            
                            if len(decompressed_superblock_data) < PFSHeaderPfs._SIZE:
                                self._log(f"ERRORE: Superblocco PFS decompresso troppo piccolo ({len(decompressed_superblock_data)})")
                                self.pfsc_offset_in_pfs_image = -1
                            else:
                                self.pfs_superblock_header = PFSHeaderPfs.from_bytes(decompressed_superblock_data)
                                actual_total_inodes = self.pfs_superblock_header.dinode_count
                                root_dir_inode_num = self.pfs_superblock_header.superroot_ino
                                self._log(f"PFS Superblocco parsato. Totale Inodes: {actual_total_inodes}, Root Inode: {root_dir_inode_num}")
                        elif num_data_blocks_for_pfs_parsing > 0 : # super_block_size_compressed è 0, ma ci aspettiamo blocchi
                             self._log("AVVISO: Dimensione compressa del superblocco è 0, ma ci sono blocchi di dati PFS.")
                             actual_total_inodes = 0 # Non possiamo procedere senza superblocco
                        else: # num_data_blocks_for_pfs_parsing == 0 and super_block_size_compressed == 0
                             self._log("AVVISO: Nessun blocco dati PFS e superblocco vuoto o non determinabile.")
                             actual_total_inodes = 0
                    else: 
                        self._log("AVVISO: Nessun blocco dati nel PFSC (num_data_blocks_for_pfs_parsing è 0).")
                        actual_total_inodes = 0
                    
                    if actual_total_inodes > 0:
                        occupied_inode_blocks_count = (actual_total_inodes * Inode._SIZE + (len(decomp_block_buf) - 1)) // len(decomp_block_buf)
                        self._log(f"Numero stimato di blocchi per inodes: {occupied_inode_blocks_count}")

                        for i_block_idx_in_map in range(1, min(1 + occupied_inode_blocks_count, num_data_blocks_for_pfs_parsing + 1)): 
                            if i_block_idx_in_map >= len(self.sector_map) or i_block_idx_in_map +1 >= len(self.sector_map) : break

                            block_offset_in_pfsc_content = self.sector_map[i_block_idx_in_map]
                            block_size_compressed = self.sector_map[i_block_idx_in_map+1] - block_offset_in_pfsc_content
                            
                            if block_offset_in_pfsc_content + block_size_compressed > len(pfsc_content_actual_bytes):
                                self._log(f"ERRORE: Lettura fuori limiti per blocco inode (map idx {i_block_idx_in_map}).") 
                                break
                            if block_size_compressed == 0 : continue

                            compressed_inode_block_data = pfsc_content_actual_bytes[block_offset_in_pfsc_content : block_offset_in_pfsc_content + block_size_compressed]
                            
                            # --- LOGICA DECISIONALE PER COMPRESSIONE DEI BLOCCHI INODE ---
                            if block_size_compressed == len(decomp_block_buf):
                                self._log(f"DEBUG: Blocco inode {i_block_idx_in_map} (size {block_size_compressed}) non compresso. Copia diretta.")
                                decompressed_inode_data = compressed_inode_block_data  # Copia diretta
                            elif 0 < block_size_compressed < len(decomp_block_buf):
                                self._log(f"DEBUG: Blocco inode {i_block_idx_in_map} compresso (size {block_size_compressed}). Decompressione...")
                                # Decompressione tramite zlib
                                decompressed_inode_data = decompress_pfsc(compressed_inode_block_data, len(decomp_block_buf), self._log)
                            else:
                                self._log(f"AVVISO: Dimensione compressa blocco inode {i_block_idx_in_map} ({block_size_compressed}) anomala. Considero come non compresso.")
                                # Fallback: copiamo direttamente la porzione attesa
                                bytes_to_copy = min(block_size_compressed, len(decomp_block_buf))
                                decompressed_inode_data = compressed_inode_block_data[:bytes_to_copy]
                            # --- FINE LOGICA DECISIONALE ---
                            
                            actual_decomp_len_inode_block = len(decompressed_inode_data)
                            
                            # --- Debug: Salva il blocco inode decompresso ---
                            debug_inode_block_path = self.extract_base_path / f"debug_INODE_BLOCK_{i_block_idx_in_map}_decompressed.bin"
                            try:
                                with open(debug_inode_block_path, "wb") as dbg_inode_f:
                                    dbg_inode_f.write(decompressed_inode_data)
                                self._log(f"DEBUG: Blocco inode {i_block_idx_in_map} decompresso salvato in: {debug_inode_block_path}")
                            except Exception as e_dbg_inode:
                                self._log(f"DEBUG: Errore salvataggio blocco inode: {e_dbg_inode}")

                            for ino_offset_in_block in range(0, actual_decomp_len_inode_block, Inode._SIZE):
                                if len(self.iNodeBuf) >= actual_total_inodes: break
                                inode_bytes = decompressed_inode_data[ino_offset_in_block : ino_offset_in_block + Inode._SIZE]
                                if len(inode_bytes) < Inode._SIZE: break 
                                inode = Inode.from_bytes(inode_bytes)
                                self.iNodeBuf.append(inode)
                            if len(self.iNodeBuf) >= actual_total_inodes: break
                        self._log(f"Letti {len(self.iNodeBuf)}/{actual_total_inodes} inodes.")
                    
                    # Debug info per inodes iniziali
                    if self.iNodeBuf: # Se iNodeBuf non è vuoto
                        self._log(f"DEBUG: Inode 1 (iNodeBuf[0]): Mode={self.iNodeBuf[0].Mode:#06x}, Tipo={self.iNodeBuf[0].get_file_type().name}")
                        if len(self.iNodeBuf) > 1: # Se esiste anche l'inode 2
                            self._log(f"DEBUG: Inode 2 (iNodeBuf[1]): Mode={self.iNodeBuf[1].Mode:#06x}, Tipo={self.iNodeBuf[1].get_file_type().name}")
                        if len(self.iNodeBuf) > 2: # Se esiste anche l'inode 3
                            self._log(f"DEBUG: Inode 3 (iNodeBuf[2]): Mode={self.iNodeBuf[2].Mode:#06x}, Tipo={self.iNodeBuf[2].get_file_type().name}")
                    
                    # Logica migliorata per determinare root_dir_inode_num
                    if self.pfs_superblock_header:
                        actual_total_inodes = self.pfs_superblock_header.dinode_count
                        root_dir_inode_num = self.pfs_superblock_header.superroot_ino
                        self._log(f"Dal superblocco PFS: actual_total_inodes={actual_total_inodes}, superroot_ino={root_dir_inode_num}")
                    else:
                        actual_total_inodes = len(self.iNodeBuf) if self.iNodeBuf else 0
                        root_dir_inode_num = 0  # Lo cambieremo nel fallback qui sotto
                        self._log(f"Superblocco PFS non disponibile. Usando actual_total_inodes={actual_total_inodes} da len(iNodeBuf)")

                    # Assicuriamoci che root_dir_inode_num sia valido (> 0 e <= len(iNodeBuf))
                    if root_dir_inode_num <= 0 or root_dir_inode_num > len(self.iNodeBuf) or len(self.iNodeBuf) == 0:
                        self._log(f"superroot_ino ({root_dir_inode_num}) non valido o iNodeBuf vuoto. Tentativo di fallback.")
                        
                        # Logica di fallback migliorata
                        if len(self.iNodeBuf) > 0:
                            # Tentativo 1: Inode 2 (comune per root PFS)
                            potential_root_idx = 2 - 1 
                            if 0 <= potential_root_idx < len(self.iNodeBuf) and \
                               self.iNodeBuf[potential_root_idx].get_file_type() == PFSFileType.PFS_DIR and \
                               self.iNodeBuf[potential_root_idx].Blocks > 0:
                                root_dir_inode_num = 2
                                self._log(f"Fallback: Uso inode 2 come root.")
                        else:
                            self._log("ERRORE CRITICO: iNodeBuf è vuoto. Impossibile determinare un root inode valido.")
                            return False, "Estrazione fallita: iNodeBuf vuoto, impossibile trovare un root inode valido."
                    
                    # Verifica finale della root
                    if root_dir_inode_num <= 0 or root_dir_inode_num > len(self.iNodeBuf):
                        self._log(f"ERRORE CRITICO: Impossibile determinare root inode PFS valido. Root num: {root_dir_inode_num}, iNodeBuf len: {len(self.iNodeBuf)}")
                    elif self.iNodeBuf[root_dir_inode_num-1].get_file_type() != PFSFileType.PFS_DIR:
                        self._log(f"AVVISO: Root inode PFS determinato ({root_dir_inode_num}) non è una directory standard, ma procediamo comunque per tentare BFS.")
                        self._log(f"DEBUG: Inode {root_dir_inode_num} Mode: {self.iNodeBuf[root_dir_inode_num-1].Mode:#06x}, Type: {self.iNodeBuf[root_dir_inode_num-1].get_file_type().name}, Blocks: {self.iNodeBuf[root_dir_inode_num-1].Blocks}")
                    else:
                        self._log(f"Inode root {root_dir_inode_num} confermato come directory con Mode: {self.iNodeBuf[root_dir_inode_num-1].Mode:#06x}")
                    
                    # Processa la directory radice usando BFS solo se root_dir_inode_num è valido
                    if root_dir_inode_num > 0 and root_dir_inode_num <= len(self.iNodeBuf):
                        self._process_pfs_directory_bfs(root_dir_inode_num, self.extract_base_path)
                        self._log(f"Completato parsing ricorsivo. Trovate {len(self.fs_table)} voci in fs_table.")
                        
                        # --- INIZIO LOGICA PER UROOT E FPT INTERNA ---
                        self._log(f"DEBUG: Controllo pre-FPT interna. fs_table ha {len(self.fs_table)} elementi.")
                        self._log(f"DEBUG: fs_table attuale (prima del parsing FPT uroot): {[(e.name, e.inode, e.type.name) for e in self.fs_table]}")
                        self._log(f"DEBUG: extract_paths attuale (prima del parsing FPT uroot): {self.extract_paths}")

                        uroot_entry_details = None
                        uroot_inode_num_for_fpt = -1

                        for fs_entry_item in list(self.fs_table):
                            if fs_entry_item.name == "uroot":
                                if 0 <= fs_entry_item.inode - 1 < len(self.iNodeBuf):
                                    uroot_inode_obj_check = self.iNodeBuf[fs_entry_item.inode - 1]
                                    if uroot_inode_obj_check.get_file_type() == PFSFileType.PFS_FILE:
                                        self._log(f"Trovato file 'uroot' (inode {fs_entry_item.inode}, type dall'inode: {uroot_inode_obj_check.get_file_type().name}) che PUNTA a FPT.")
                                        uroot_entry_details = fs_entry_item
                                        uroot_inode_num_for_fpt = fs_entry_item.inode
                                        break
                                    else:
                                        self._log(f"Trovata entry 'uroot' (inode {fs_entry_item.inode}) ma il suo inode type è {uroot_inode_obj_check.get_file_type().name}, non PFS_FILE. Non la userò per FPT.")
                                else:
                                    self._log(f"AVVISO: Trovata entry 'uroot' ma il suo inode {fs_entry_item.inode} è fuori range per iNodeBuf (len {len(self.iNodeBuf)}).")

                        if uroot_entry_details and uroot_inode_num_for_fpt != -1:
                            self._log(f"DEBUG: uroot_entry_details trovato: True, uroot_inode_num_for_fpt: {uroot_inode_num_for_fpt}")
                            self._log(f"DEBUG: ENTRATO nel blocco di parsing FPT interna per uroot (inode {uroot_inode_num_for_fpt}).")
                            
                            uroot_inode_obj = self.iNodeBuf[uroot_inode_num_for_fpt - 1]
                            
                            try:
                                with open(self.pkg_path, "rb") as pkg_file_for_uroot:
                                    uroot_file_content_bytes = self._extract_single_pfs_file_data_to_memory(pkg_file_for_uroot, uroot_inode_obj)
                                    
                                    if uroot_file_content_bytes:
                                        self._log(f"DEBUG: Contenuto di uroot estratto con successo. Dimensione: {len(uroot_file_content_bytes)} bytes")
                                        self._parse_internal_flat_path_table(uroot_file_content_bytes, self.extract_base_path)
                                        self._log(f"DEBUG: Dopo _parse_internal_flat_path_table, fs_table ora ha {len(self.fs_table)} voci.")
                                    else:
                                        self._log("AVVISO: Nessun contenuto estratto per uroot. Impossibile processare FPT interna.")
                                        
                            except Exception as e_uroot_extract:
                                self._log(f"ERRORE durante l'estrazione del contenuto di uroot (inode {uroot_inode_num_for_fpt}): {e_uroot_extract}")
                                import traceback
                                self._log(traceback.format_exc())
                    elif self.pkg_header and self.pkg_header.pfs_image_size > 0: # Solo se PFS era atteso
                        self._log(f"ERRORE: Impossibile procedere con BFS, root_dir_inode_num ({root_dir_inode_num}) non valido o iNodeBuf (len {len(self.iNodeBuf)}) problematico.")

            # Determine return value for the extract method based on success
            if self.pfsc_offset_in_pfs_image == -1 and self.pkg_header and self.pkg_header.pfs_image_size > 0:
                 # This implies PFS was expected but failed to parse properly before BFS
                 return False, "Estrazione metadati completata, ma parsing PFS fallito."
            elif not self.fs_table and self.pkg_header and self.pkg_header.pfs_image_size > 0:
                 return True, "Estrazione metadati e parsing PFS completati. fs_table è vuota (PFS potrebbe essere vuoto o errore di parsing dirent)."
            elif not self.pkg_header or self.pkg_header.pfs_image_size == 0:
                 return True, "Estrazione metadati completata. Nessuna immagine PFS da processare."
            else:
                 return True, "Estrazione metadati e parsing PFS (inclusa tabella file) completati. Procedere con extract_pfs_files."

        except Exception as e: # This is the missing except block for the extract method's try
            self._log(f"ERRORE CRITICO durante l'estrazione dei metadati o parsing PFS iniziale: {e}")
            import traceback
            self._log(traceback.format_exc())
            return False, f"Errore critico durante estrazione/PFS parsing: {e}"

    def _process_flat_path_table(self, flat_path_data, parent_path):
        """Processa un flat_path_table trovato nell'inode 'uroot'.
        
        Args:
            flat_path_data (bytes): I dati decompressi del flat_path_table
            parent_path (Path): Path padre dove creare i file/directory estratti
        """
        self._log("\nInizio parsing flat_path_table in uroot...")
        
        # Salva i dati per un'analisi più approfondita
        debug_fpt_path = self.extract_base_path / "debug_FLAT_PATH_TABLE_from_uroot.bin"
        try:
            with open(debug_fpt_path, "wb") as f:
                f.write(flat_path_data)
            self._log(f"DEBUG: Dati flat_path_table salvati in: {debug_fpt_path}")
        except Exception as e:
            self._log(f"DEBUG: Errore salvataggio flat_path_table: {e}")
        
        # Analisi dei primi byte per debug
        first_bytes = flat_path_data[:min(64, len(flat_path_data))]
        self._log(f"DEBUG: Primi {len(first_bytes)}B del flat_path_table: {first_bytes.hex()}")
        
        # Cerca la stringa "flat_path_table" a offset 0x10
        if len(flat_path_data) >= 0x20 and flat_path_data[0x10:0x1f] == b'flat_path_table':
            self._log("DEBUG: Trovato marker 'flat_path_table' a offset 0x10")
        
        # Basato sulla logica C++ descritta dall'utente
        offset = 0
        ndinode_counter = 0  # Inode della directory a cui appartengono le entry in flat_path_table
        
        # Processa le meta-entry (ino != 0) che descrivono la struttura
        while offset + Dirent._SIZE_BASE <= len(flat_path_data):
            try:
                dirent = Dirent.from_bytes(flat_path_data[offset:])
                self._log(f"  META-ENTRY: ino={dirent.ino}, type={dirent.type}, "
                         f"namelen={dirent.namelen}, entsize={dirent.entsize}, name='{dirent.name}'")
                
                # Terminatore delle meta-entry
                if dirent.ino == 0 or dirent.entsize == 0:
                    self._log("  FINE META-ENTRY: Trovato terminatore")
                    offset += dirent.entsize if dirent.entsize > 0 else 4
                    break
                    
                # Salta le meta-entry senza nome valido
                if not dirent.name or dirent.namelen == 0:
                    self._log("  SKIP META-ENTRY: Nome vuoto")
                    offset += dirent.entsize if dirent.entsize > 0 else 4
                    continue
                
                # Se troviamo 'uroot', impostiamo il contatore
                if dirent.name == 'uroot' and dirent.ino > 0:
                    ndinode_counter = dirent.ino
                    self._log(f"  TROVATO UROOT: Impostato ndinode_counter a {ndinode_counter}")
                
                offset += dirent.entsize if dirent.entsize > 0 else 4
                
            except Exception as e:
                self._log(f"  ERRORE durante il parsing della meta-entry a offset {offset}: {e}")
                offset += 4  # Prova a riprendersi saltando avanti
        
        self._log(f"  Dopo le meta-entry, offset = {offset:#x}, ndinode_counter = {ndinode_counter}")
        
        # Se non abbiamo trovato 'uroot', usiamo l'inode 2 come fallback
        if ndinode_counter == 0:
            ndinode_counter = 2
            self._log(f"  Nessun inode 'uroot' trovato, uso fallback inode {ndinode_counter}")
        
        # Ora processa le entry reali
        while offset + Dirent._SIZE_BASE <= len(flat_path_data):
            try:
                dirent = Dirent.from_bytes(flat_path_data[offset:])
                self._log(f"  ENTRY: ino={dirent.ino}, type={dirent.type}, "
                         f"namelen={dirent.namelen}, entsize={dirent.entsize}, name='{dirent.name}'")
                
                # Terminatore
                if dirent.ino == 0 or dirent.entsize == 0:
                    self._log(f"  Fine parsing flat_path_table, offset finale = {offset:#x}")
                    break
                    
                # Salta le entry senza nome valido
                if not dirent.name or dirent.namelen == 0:
                    self._log("  SKIP ENTRY: Nome vuoto")
                    offset += dirent.entsize if dirent.entsize > 0 else 4
                    continue
                
                # Aggiungi al filesystem
                entry_path = parent_path / dirent.name
                self.fs_table[str(entry_path)] = {
                    'inode': dirent.ino,
                    'type': dirent.get_pfs_file_type(),
                    'size': 0,  # Dovrà essere riempito dall'inode
                    'offset': 0  # Dovrà essere riempito dall'inode
                }
                self._log(f"  AGGIUNTO: {entry_path} (inode {dirent.ino})")
                
                # Se è una directory, aggiungila alla coda BFS
                if dirent.get_pfs_file_type() == PFSFileType.PFS_DIR:
                    self._log(f"  CREAZIONE DIR: '{entry_path}'")
                    entry_path.mkdir(parents=True, exist_ok=True)
                    if hasattr(self, 'bfs_queue'):
                        self.bfs_queue.append((dirent.ino, entry_path))
                        self._log(f"  ACCODATO per BFS: inode {dirent.ino} ('{entry_path}')")
                
                offset += dirent.entsize if dirent.entsize > 0 else 4
                
            except Exception as e:
                self._log(f"  ERRORE durante il parsing dell'entry a offset {offset}: {e}")
                offset += 4  # Prova a riprendersi saltando avanti
        
        self._log(f"Fine parsing flat_path_table. Trovate entry reali.\n")
        return

    def _process_flat_path_table(self, flat_path_data, parent_path):
        """Processa un flat_path_table trovato nell'inode 'uroot'.
        
        Args:
            flat_path_data (bytes): I dati decompressi del flat_path_table
            parent_path (Path): Path padre dove creare i file/directory estratti
        """
        self._log("\nInizio parsing flat_path_table in uroot...")
        
        try:
            # Save the raw data for debugging
            debug_path = parent_path / "debug_flat_path_table.bin"
            with open(debug_path, "wb") as f:
                f.write(flat_path_data)
            self._log(f"  Dati flat_path_table salvati in: {debug_path}")
            
            # Check for flat_path_table marker
            if not flat_path_data.startswith(b'flat_path_table'):
                self._log("  AVVISO: Il blocco dati non inizia con 'flat_path_table'")
                return []

            offset = 0
            entries = []
            
            # Skip the header (16 bytes)
            offset = 16
            
            # Parse directory entries
            while offset + 16 <= len(flat_path_data):
                # Read dirent structure
                dirent = Dirent.from_bytes(flat_path_data[offset:])
                
                # Check for end of entries
                if dirent.ino == 0 or dirent.entsize == 0:
                    break
                    
                # Skip invalid entries
                if dirent.namelen == 0 or dirent.namelen > 256:
                    offset += dirent.entsize if dirent.entsize > 0 else 16
                    continue
                    
                # Get entry name
                name = dirent.name.decode('utf-8', errors='replace')
                self._log(f"  Trovata entry: ino={dirent.ino}, type={dirent.type}, name='{name}'")
                
                # Add to entries list
                entries.append((name, dirent.ino, dirent.get_pfs_file_type()))
                
                # Move to next entry
                offset += dirent.entsize if dirent.entsize > 0 else 16
                
            self._log(f"  Trovate {len(entries)} voci nella flat_path_table")
            return entries
            
        except Exception as e:
            self._log(f"  ERRORE durante il parsing della flat_path_table: {e}")
            import traceback
            self._log(traceback.format_exc())
            return []
        
        self._log(f"Fine parsing flat_path_table. Trovate {len(real_entries)} entry reali.\n")
        return real_entries

    def _extract_inode_data(self, inode_obj: Inode, output_path: Path) -> bool:
        """Estrai i dati di un inode in un file.
        
        Args:
            inode_obj: L'oggetto Inode da estrarre
            output_path: Percorso di destinazione del file
            
        Returns:
            bool: True se l'estrazione è riuscita, False altrimenti
        """
        try:
            self._log(f"  Estrazione inode {inode_obj} in {output_path}")
            
            # Crea la directory di destinazione se non esiste
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Leggi i dati dell'inode
            data = bytearray()
            for block_idx in range(inode_obj.Blocks):
                map_idx = inode_obj.loc + block_idx
                if map_idx >= len(self.sector_map) - 1:
                    break
                    
                block_offset = self.sector_map[map_idx]
                next_block_offset = self.sector_map[map_idx + 1]
                block_size = next_block_offset - block_offset
                
                if block_offset + block_size > len(self.pfsc_content_actual_bytes):
                    self._log(f"    ERRORE: Blocco {block_idx} fuori dai limiti")
                    break
                    
                block_data = self.pfsc_content_actual_bytes[block_offset:block_offset + block_size]
                
                # Se il blocco è compresso, decomprimilo
                if block_size < 0x10000:  # Dimensione tipica di un blocco non compresso
                    try:
                        block_data = decompress_pfsc(block_data, 0x10000, self._log)
                    except Exception as e:
                        self._log(f"    ERRORE decompressione blocco {block_idx}: {e}")
                        continue
                
                data.extend(block_data)
            
            # Scrivi i dati nel file di output
            with open(output_path, 'wb') as f:
                f.write(data[:inode_obj.Size])  # Tronca alla dimensione effettiva
                
            self._log(f"  Estrazione completata: {output_path} ({len(data)} bytes)")
            return True
            
        except Exception as e:
            self._log(f"ERRORE durante l'estrazione dell'inode: {e}")
            import traceback
            self._log(traceback.format_exc())
            return False

    def _process_pfs_directory_bfs(self, root_inode_num: int, root_dir_initial_path: pathlib.Path):
        if not (self.pfs_chdr and self.sector_map and self.iNodeBuf):
            self._log("ERRORE BFS: Strutture PFS non inizializzate.")
            return

        decomp_block_buf_size = self.pfs_chdr.block_sz2 if self.pfs_chdr.block_sz2 > 0 else 0x10000
        decomp_block_buf = bytearray(decomp_block_buf_size)

        # extract_paths[root_inode_num] è stato impostato in extract()
        queue = [(root_inode_num, root_dir_initial_path)]
        visited_dirs_for_bfs = {root_inode_num}
        head = 0

        while head < len(queue):
            current_dir_inode_num, current_dir_path = queue[head]; head += 1
            
            self._log(f"  BFS: Processo directory inode {current_dir_inode_num} ('{current_dir_path}')")
            
            dir_inode_idx = current_dir_inode_num - 1
            if not (0 <= dir_inode_idx < len(self.iNodeBuf)):
                self._log(f"    ERRORE BFS: Indice inode dir {dir_inode_idx} non valido. Salto.")
                continue
            
            dir_inode_obj = self.iNodeBuf[dir_inode_idx]
            self._log(f"    BFS: Inode {current_dir_inode_num} (idx {dir_inode_idx}) ha Mode={dir_inode_obj.Mode:#06x}, Tipo={dir_inode_obj.get_file_type().name}, Size={dir_inode_obj.Size}, Blocks={dir_inode_obj.Blocks}, Loc={dir_inode_obj.loc}")

            # Se l'inode non è una directory, non processare come tale
            if dir_inode_obj.get_file_type() != PFSFileType.PFS_DIR:
                self._log(f"    AVVISO BFS: Inode {current_dir_inode_num} (Mode={dir_inode_obj.Mode:#06x}) non è una directory PFS standard. Non verranno lette dirent da esso.")
                continue
            
            first_block_idx_for_dir_in_map = dir_inode_obj.loc 
            num_blocks_for_dir = dir_inode_obj.Blocks

            for i_dir_block in range(num_blocks_for_dir):
                map_idx_dir = first_block_idx_for_dir_in_map + i_dir_block
                if map_idx_dir >= len(self.sector_map) - 1:
                    break
                
                block_offset_in_pfsc = self.sector_map[map_idx_dir]
                block_csize = self.sector_map[map_idx_dir + 1] - block_offset_in_pfsc
                
                if block_offset_in_pfsc + block_csize > len(self.pfsc_content_actual_bytes):
                    break
                if block_csize == 0:
                    continue

                compressed_dir_block_data = self.pfsc_content_actual_bytes[block_offset_in_pfsc : block_offset_in_pfsc + block_csize]
                
                decompressed_data = bytearray(decomp_block_buf_size)
                if block_csize == decomp_block_buf_size:  # Non compresso
                    decompressed_data[:] = compressed_dir_block_data
                else:  # Compresso
                    decompressed_data[:] = decompress_pfsc(bytes(compressed_dir_block_data), decomp_block_buf_size, self._log)
                
                actual_decomp_len_dir = len(decompressed_data)

                # Salva il blocco decompresso per debug
                debug_dirent_block_path = self.extract_base_path / f"debug_DIRENT_BLOCK_inode{current_dir_inode_num}_block{i_dir_block}.bin"
                try:
                    with open(debug_dirent_block_path, "wb") as dbg_df:
                        dbg_df.write(decompressed_data)
                except Exception as e:
                    self._log(f"    ERRORE salvataggio blocco debug: {e}")

                offset_in_dir_block = 0
                dirents_processed_in_block = 0
                while offset_in_dir_block < actual_decomp_len_dir:
                    if actual_decomp_len_dir - offset_in_dir_block < Dirent._SIZE_BASE:
                        break
                    
                    dirent = Dirent.from_bytes(decompressed_data[offset_in_dir_block:])
                    
                    if dirent.entsize == 0:
                        self._log(f"          Terminazione dirent: entsize=0")
                        break
                    if dirent.ino == 0:
                        self._log(f"          Terminazione dirent: ino=0")
                        break
                    
                    entry_name = dirent.name
                    entry_inode_num = dirent.ino
                    entry_pfs_type_from_dirent = dirent.get_pfs_file_type()
                    dirents_processed_in_block += 1
                    
                    self._log(f"          Trovata Dirent: '{entry_name}' (inode {entry_inode_num}), Dirent.type={dirent.type} -> {entry_pfs_type_from_dirent.name}, Entsize: {dirent.entsize}")

                    # Salta le prime due entry (.) e (..)
                    if dirents_processed_in_block <= 2 and entry_name in [".", ".."]:
                        self._log(f"            Saltando Dirent speciale PFS: '{entry_name}'")
                        if entry_name == ".":
                            self.extract_paths[entry_inode_num] = current_dir_path
                        elif entry_name == ".." and current_dir_path != self.extract_base_path:
                            self.extract_paths[entry_inode_num] = current_dir_path.parent

                        offset_in_dir_block += dirent.entsize
                        continue
                        
                    if not (0 <= entry_inode_num - 1 < len(self.iNodeBuf)):
                        self._log(f"            AVVISO BFS: Dirent '{entry_name}' (inode {entry_inode_num}) non in iNodeBuf. Salto.")
                        offset_in_dir_block += dirent.entsize
                        continue
                    
                    target_inode_for_dirent = self.iNodeBuf[entry_inode_num - 1]
                    if target_inode_for_dirent.Mode == 0:
                        self._log(f"            AVVISO BFS: Dirent '{entry_name}' punta a inode {entry_inode_num} con Mode=0. Salto.")
                        offset_in_dir_block += dirent.entsize
                        continue

                    # Aggiungi a fs_table
                    self.fs_table.append(FSTableEntry(entry_name, entry_inode_num, entry_pfs_type_from_dirent))
                    
                    current_entry_path = current_dir_path / entry_name
                    self.extract_paths[entry_inode_num] = current_entry_path

                    if entry_pfs_type_from_dirent == PFSFileType.PFS_DIR:
                        if entry_inode_num not in visited_dirs_for_bfs:
                            self._log(f"            Accodata subdir: '{current_entry_path}' (inode {entry_inode_num})")
                            current_entry_path.mkdir(parents=True, exist_ok=True)
                            queue.append((entry_inode_num, current_entry_path))
                            visited_dirs_for_bfs.add(entry_inode_num)
                            
                    offset_in_dir_block += dirent.entsize
                    if dirent.entsize < Dirent._SIZE_BASE and dirent.entsize != 0:
                        self._log(f"AVVISO BFS: Dirent.entsize ({dirent.entsize}) anomalo per '{entry_name}'.")
                        break
                
                self._log(f"      Blocco dirent {i_dir_block} per inode {current_dir_inode_num}: processate {dirents_processed_in_block} dirents.")
            

        

    def _read_decrypt_decompress_pfs_block(self, 
                                        block_map_idx: int, 
                                        is_compressed_flag: bool, 
                                        pkg_file_handle, 
                                        decomp_buffer: bytearray) -> tuple[Optional[bytes], str]:
        """
        Legge, decifra e decomprime un blocco PFS.
        
        Args:
            block_map_idx: Indice del blocco nella mappa dei blocchi
            is_compressed_flag: Se True, il blocco è compresso
            pkg_file_handle: File handle del PKG
            decomp_buffer: Buffer per i dati decompressi
            
        Returns:
            tuple: (dati_decompressi, messaggio_errore) o (None, messaggio_errore) in caso di errore
        """
        try:
            # Verifica che l'indice del blocco sia valido
            if block_map_idx < 0 or block_map_idx >= len(self.sector_map):
                return None, f"Indice blocco {block_map_idx} fuori dai limiti (0-{len(self.sector_map)-1})"
                
            # Leggi il blocco cifrato
            block_offset = self.sector_map[block_map_idx]
            pkg_file_handle.seek(block_offset)
            
            # Leggi i dati cifrati
            block_size = 0x10000  # Dimensione fissa del blocco
            encrypted_block = pkg_file_handle.read(block_size)
            
            # Decifra il blocco
            decrypted_block = bytearray(len(encrypted_block))
            self.crypto.decryptPFS(self.dataKey, self.tweakKey, encrypted_block, decrypted_block, block_map_idx)
            
            # Se il blocco è compresso, decomprimilo
            if is_compressed_flag:
                try:
                    decompressed = decompress_pfsc(decrypted_block, len(decomp_buffer), self._log)
                    if decompressed is None:
                        return None, f"Decompressione fallita per il blocco {block_map_idx}"
                    return decompressed, ""
                except Exception as e:
                    return None, f"Errore durante la decompressione del blocco {block_map_idx}: {str(e)}"
            else:
                # Se non è compresso, copia i dati nel buffer di output
                decomp_buffer[:len(decrypted_block)] = decrypted_block
                return bytes(decomp_buffer[:len(decrypted_block)]), ""
                
        except Exception as e:
            return None, f"Errore durante la lettura/decifratura del blocco {block_map_idx}: {str(e)}"

    def extract_pfs_files(self) -> tuple[bool, str]:
        self._log("Inizio estrazione file da PFS...")
        if not self.fs_table: return True, "Nessun file/directory trovato nella tabella PFS (fs_table vuota)."
        if not self.iNodeBuf: return False, "iNodeBuf vuoto ma fs_table non lo è. Errore di parsing Inode."
        if not self.extract_paths: return False, "extract_paths vuoto. Errore di parsing Dirent/Path."
        if self.pfsc_offset_in_pfs_image == -1 : return False, "PFSC non trovato o non processato. Impossibile estrarre file PFS."
        if not self.pfs_chdr: return False, "Header PFSC (pfs_chdr) non disponibile." # Aggiunto pfs_chdr come attributo di istanza
        
        num_extracted = 0
        total_to_extract = sum(1 for x in self.fs_table if x.type == PFSFileType.PFS_FILE)
        self._log(f"Trovati {total_to_extract} file da estrarre da PFS.")

        try:
            with open(self.pkg_path, "rb") as pkg_file:
                # Il buffer per i blocchi decompressi, dimensionato a pfs_chdr.block_sz2
                decomp_block_buf = bytearray(self.pfs_chdr.block_sz2 if self.pfs_chdr.block_sz2 > 0 else 0x10000)
                if not decomp_block_buf: decomp_block_buf = bytearray(0x10000) # Fallback

                # Buffer per leggere un blocco XTS (0x1000) + possibile overflow per dati non allineati
                # La dimensione massima di un blocco compresso PFS è block_sz2 (es. 0x10000)
                # Un blocco XTS è 0x1000. Quindi un blocco PFS può spannare più blocchi XTS.
                # Dobbiamo leggere e decrittare blocco XTS per blocco XTS.
                xts_read_buffer = bytearray(0x1000) # Per leggere un blocco XTS alla volta
                xts_decrypted_buffer = bytearray(0x1000) # Per il blocco XTS decrittato

                for fs_entry in self.fs_table:
                    if fs_entry.type == PFSFileType.PFS_FILE:
                        inode_abs_num = fs_entry.inode
                        inode_idx = inode_abs_num -1 
                        
                        if not (0 <= inode_idx < len(self.iNodeBuf)):
                            self._log(f"ERRORE: Indice inode {inode_idx} (da num {inode_abs_num}) fuori limiti per file '{fs_entry.name}'. Salto."); continue
                        
                        inode_obj = self.iNodeBuf[inode_idx]
                        if inode_obj.Mode == 0:
                            self._log(f"AVVISO: Inode {inode_abs_num} (idx {inode_idx}) non valido per file '{fs_entry.name}'. Salto."); continue

                        out_path = self.extract_paths.get(inode_abs_num)
                        if not out_path:
                            self._log(f"ERRORE: Path estrazione non trovato per inode {inode_abs_num} ('{fs_entry.name}'). Salto."); continue
                        
                        self._log(f"  Estrazione file PFS: '{out_path}' (inode {inode_abs_num}, size {inode_obj.Size})")

                        if inode_obj.Size == 0:
                            out_path.parent.mkdir(parents=True, exist_ok=True); open(out_path, "wb").close()
                            num_extracted += 1; continue
                        
                        # loc è l'indice del primo blocco del file nella self.sector_map
                        first_file_block_map_idx = inode_obj.loc 
                        num_file_blocks = inode_obj.Blocks
                        
                        # Validazione indici mappa
                        if not (0 <= first_file_block_map_idx < len(self.sector_map) and 
                                first_file_block_map_idx + num_file_blocks <= len(self.sector_map) -1 ): # L'ultimo entry della mappa è l'offset finale
                            self._log(f"ERRORE: loc/num_blocks Inode ({first_file_block_map_idx}/{num_file_blocks}) non validi per sector_map (len {len(self.sector_map)}) per '{fs_entry.name}'. Salto."); continue
                        
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(out_path, "wb") as out_f_pfs:
                            written_total_for_file = 0
                            is_compressed = InodeFlagsPfs.compressed in inode_obj.Flags
                            if is_compressed: self._log(f"    File '{fs_entry.name}' è compresso.")

                            for j_file_block in range(num_file_blocks):
                                current_map_idx = first_file_block_map_idx + j_file_block
                                
                                # Offset del blocco (compresso) relativo all'inizio dell'area dati PFSC
                                compressed_block_offset_in_data_area = self.sector_map[current_map_idx]
                                # Dimensione del blocco (compresso)
                                compressed_block_size = self.sector_map[current_map_idx + 1] - compressed_block_offset_in_data_area
                                
                                if compressed_block_size == 0: continue # Blocco vuoto

                                # Offset del blocco (compresso) RELATIVO all'inizio dell'IMMAGINE PFS (originale, crittata nel PKG)
                                abs_offset_compressed_block_in_pfs_image = self.pfsc_offset_in_pfs_image + self.pfs_chdr.data_start + compressed_block_offset_in_data_area
                                
                                # Dati del blocco (ancora compressi, ma decrittati XTS)
                                current_block_data_buffer = bytearray(compressed_block_size)
                                read_for_current_block_data = 0

                                # Leggi e decritta per blocchi XTS
                                for xts_offset_in_block in range(0, compressed_block_size, 0x1000):
                                    xts_block_to_read_abs_offset_in_pfs_image = abs_offset_compressed_block_in_pfs_image + xts_offset_in_block
                                    xts_block_num_for_decryption = xts_block_to_read_abs_offset_in_pfs_image // 0x1000
                                    offset_within_this_xts_block = xts_block_to_read_abs_offset_in_pfs_image % 0x1000

                                    # Offset di lettura nel file PKG
                                    pkg_file.seek(self.pkg_header.pfs_image_offset + (xts_block_num_for_decryption * 0x1000))
                                    read_len_xts = pkg_file.readinto(xts_read_buffer)
                                    if read_len_xts < 0x1000 and offset_within_this_xts_block + (compressed_block_size - xts_offset_in_block) > read_len_xts:
                                        # Se non abbiamo letto un blocco XTS intero E ne avevamo bisogno
                                        raise IOError(f"Lettura PKG incompleta per blocco XTS {xts_block_num_for_decryption} per '{fs_entry.name}'. Letto {read_len_xts} invece di 0x1000.")

                                    self.crypto.decryptPFS(self.dataKey, self.tweakKey, xts_read_buffer[:read_len_xts], xts_decrypted_buffer[:read_len_xts], xts_block_num_for_decryption)
                                    
                                    bytes_to_copy_from_xts = min(0x1000 - offset_within_this_xts_block, compressed_block_size - read_for_current_block_data)
                                    current_block_data_buffer[read_for_current_block_data : read_for_current_block_data + bytes_to_copy_from_xts] = \
                                        xts_decrypted_buffer[offset_within_this_xts_block : offset_within_this_xts_block + bytes_to_copy_from_xts]
                                    read_for_current_block_data += bytes_to_copy_from_xts
                                
                                # Ora current_block_data_buffer contiene il blocco (compresso se flag impostato), decrittato da XTS.
                                final_data_for_this_block = bytes(current_block_data_buffer)

                                if is_compressed:
                                    # La dimensione decompressa è self.pfs_chdr.block_sz2 (o fallback 0x10000)
                                    # Assicurati che decomp_block_buf sia della dimensione corretta
                                    if len(decomp_block_buf) != self.pfs_chdr.block_sz2 and self.pfs_chdr.block_sz2 > 0:
                                        decomp_block_buf = bytearray(self.pfs_chdr.block_sz2)
                                    elif len(decomp_block_buf) == 0 : # Caso fallback
                                        decomp_block_buf = bytearray(0x10000)

                                    decompressed_part = decompress_pfsc(final_data_for_this_block, len(decomp_block_buf), self._log)
                                    final_data_for_this_block = decompressed_part
                                
                                bytes_to_write_this_block = min(len(final_data_for_this_block), inode_obj.Size - written_total_for_file)
                                if bytes_to_write_this_block > 0:
                                    out_f_pfs.write(final_data_for_this_block[:bytes_to_write_this_block])
                                    written_total_for_file += bytes_to_write_this_block
                            
                            if written_total_for_file != inode_obj.Size: 
                                self._log(f"AVVISO: Dimensione finale '{fs_entry.name}' ({written_total_for_file}) non corrisponde a inode.Size ({inode_obj.Size}).")
                        num_extracted +=1
                        self._log(f"    File '{out_path}' estratto ({written_total_for_file} bytes). {num_extracted}/{total_to_extract}")

            self._log(f"Estrazione PFS completata. {num_extracted} file estratti.")
            return True, f"{num_extracted} file estratti."
        except IOError as e: 
            self._log(f"Errore I/O estrazione PFS: {e}")
            return False, f"Errore I/O: {e}"
        except Exception as e:
            self._log(f"Errore generico estrazione PFS: {e}")
            import traceback
            self._log(traceback.format_exc())
            return False, f"Errore: {e}"

    # Note: This duplicate implementation has been removed because it conflicted with the one at line ~2301
    # and was causing a KeyError when trying to access self.extract_paths[root_inode_num]

    def _extract_single_pfs_file_data_to_memory(self, pkg_file_handle, inode_obj: Inode) -> Optional[bytes]:
        """
        Estrae i dati di un singolo file PFS (descritto da inode_obj) e li restituisce come bytes.
        Utilizza il file handle del PKG già aperto.
        """
        self._log(f"[DEBUG] Inizio _extract_single_pfs_file_data_to_memory per inode: {inode_obj}")
        
        # Log dettagliato delle strutture PFS/PKG
        self._log(f"[DEBUG] PKG Header - pfs_image_offset: {self.pkg_header.pfs_image_offset:#x}")
        self._log(f"[DEBUG] PFS Header - pfsc_offset_in_pfs_image: {self.pfsc_offset_in_pfs_image:#x}")
        self._log(f"[DEBUG] PFS Header - data_start: {self.pfs_chdr.data_start:#x}")
        
        if not (self.pfs_chdr and self.sector_map and self.pkg_header and self.pfsc_offset_in_pfs_image != -1):
            error_msg = "ERRORE _extract_single_pfs_file_data_to_memory: Strutture PFS/PKG non inizializzate."
            self._log(error_msg)
            self._log(f"[DEBUG] pfs_chdr: {self.pfs_chdr is not None}, sector_map: {len(self.sector_map) if self.sector_map else 0}, pkg_header: {self.pkg_header is not None}, pfsc_offset: {self.pfsc_offset_in_pfs_image}")
            return None
            
        if inode_obj.Size == 0:
            self._log("[DEBUG] Dimensione inode è 0, restituisco dati vuoti")
            return b''

        self._log(f"[DEBUG] Estrazione in memoria - Size: {inode_obj.Size}, Blocks: {inode_obj.Blocks}, Loc: {inode_obj.loc}, Flags: {inode_obj.Flags}")

        file_data_accumulator = bytearray()
        written_total_for_file = 0
        
        decomp_block_buf_size = self.pfs_chdr.block_sz2 if self.pfs_chdr.block_sz2 > 0 else 0x10000
        self._log(f"[DEBUG] decomp_block_buf_size: {decomp_block_buf_size}, block_sz2: {self.pfs_chdr.block_sz2}")
        
        xts_read_buffer = bytearray(0x1000)
        xts_decrypted_buffer = bytearray(0x1000)

        is_compressed = InodeFlagsPfs.compressed in inode_obj.Flags
        self._log(f"[DEBUG] Inode compresso: {is_compressed}, Flags: {inode_obj.Flags}")

        first_file_block_map_idx = inode_obj.loc 
        num_file_blocks = inode_obj.Blocks
        self._log(f"[DEBUG] first_file_block_map_idx: {first_file_block_map_idx}, num_file_blocks: {num_file_blocks}, sector_map len: {len(self.sector_map)}")

        # Log dei valori della sector_map per i blocchi interessati
        for i in range(max(0, first_file_block_map_idx - 2), min(len(self.sector_map), first_file_block_map_idx + num_file_blocks + 2)):
            self._log(f"[DEBUG] sector_map[{i}]: {self.sector_map[i]:#x}")

        if not (0 <= first_file_block_map_idx < len(self.sector_map) and 
                first_file_block_map_idx + num_file_blocks < len(self.sector_map)):
            error_msg = f"ERRORE (mem extract): loc/num_blocks Inode ({first_file_block_map_idx}/{num_file_blocks}) non validi per sector_map (len {len(self.sector_map)})."
            self._log(error_msg)
            return None

        for j_file_block in range(num_file_blocks):
            current_map_idx = first_file_block_map_idx + j_file_block
            
            block_offset_in_pfsc_data_area = self.sector_map[current_map_idx]
            block_size_in_pfsc_data_area = self.sector_map[current_map_idx + 1] - block_offset_in_pfsc_data_area
            
            self._log(f"[DEBUG] Blocco {j_file_block} (map_idx={current_map_idx}):")
            self._log(f"  - block_offset_in_pfsc_data_area: {block_offset_in_pfsc_data_area:#x}")
            self._log(f"  - block_size_in_pfsc_data_area: {block_size_in_pfsc_data_area:#x}")
            
            if block_size_in_pfsc_data_area == 0:
                self._log("[DEBUG] Dimensione blocco 0, salto")
                continue

            abs_offset_block_in_pfs_image_for_xts = self.pfsc_offset_in_pfs_image + self.pfs_chdr.data_start + block_offset_in_pfsc_data_area
            
            self._log(f"  - pfsc_offset_in_pfs_image: {self.pfsc_offset_in_pfs_image:#x}")
            self._log(f"  - pfs_chdr.data_start: {self.pfs_chdr.data_start:#x}")
            self._log(f"  - block_offset_in_pfsc_data_area: {block_offset_in_pfsc_data_area:#x}")
            self._log(f"  => abs_offset_block_in_pfs_image_for_xts: {abs_offset_block_in_pfs_image_for_xts:#x}")
            
            current_block_data_after_xts = bytearray(block_size_in_pfsc_data_area)
            read_for_this_pfs_block = 0

            for xts_sub_offset_in_pfs_block in range(0, block_size_in_pfsc_data_area, 0x1000):
                pkg_read_offset_for_xts = self.pkg_header.pfs_image_offset + abs_offset_block_in_pfs_image_for_xts + xts_sub_offset_in_pfs_block
                xts_sector_num_for_tweak = (abs_offset_block_in_pfs_image_for_xts + xts_sub_offset_in_pfs_block) // 0x1000
                bytes_to_read_for_this_xts_chunk = min(0x1000, block_size_in_pfsc_data_area - xts_sub_offset_in_pfs_block)
                
                self._log(f"  Chunk {xts_sub_offset_in_pfs_block // 0x1000}:")
                self._log(f"    pkg_header.pfs_image_offset: {self.pkg_header.pfs_image_offset:#x}")
                self._log(f"    abs_offset_block_in_pfs_image_for_xts: {abs_offset_block_in_pfs_image_for_xts:#x}")
                self._log(f"    xts_sub_offset_in_pfs_block: {xts_sub_offset_in_pfs_block:#x}")
                self._log(f"    => pkg_read_offset_for_xts: {pkg_read_offset_for_xts:#x}")
                self._log(f"    xts_sector_num_for_tweak: {xts_sector_num_for_tweak} (0x{xts_sector_num_for_tweak:x})")
                
                # DEBUG: Special handling for the problematic chunk at 0x14F000
                if pkg_read_offset_for_xts == 0x14F000 or (pkg_read_offset_for_xts >= 0x14F000 and pkg_read_offset_for_xts < 0x150000):
                    self._log(f"\n[DEBUG] ===== TARGET CHUNK DEBUG (0x14F000) =====")
                    self._log(f"[DEBUG] Current file position before seek: {pkg_file_handle.tell():#x}")
                    self._log(f"[DEBUG] Attempting to read {bytes_to_read_for_this_xts_chunk} bytes at offset {pkg_read_offset_for_xts:#x}")
                
                # Save current position and perform the seek
                current_pos = pkg_file_handle.tell()
                pkg_file_handle.seek(pkg_read_offset_for_xts)
                
                # DEBUG: For the target chunk, log position after seek
                if pkg_read_offset_for_xts == 0x14F000 or (pkg_read_offset_for_xts >= 0x14F000 and pkg_read_offset_for_xts < 0x150000):
                    self._log(f"[DEBUG] File position after seek: {pkg_file_handle.tell():#x}")
                
                # Clear the buffer before reading
                xts_read_buffer[:] = b'\0' * len(xts_read_buffer)
                
                # Use read() instead of readinto for more reliable operation
                pkg_file_handle.seek(pkg_read_offset_for_xts)
                temp_read_data = pkg_file_handle.read(bytes_to_read_for_this_xts_chunk)
                read_len_xts = len(temp_read_data)
                
                if read_len_xts == bytes_to_read_for_this_xts_chunk:
                    # Copy the read data into our buffer
                    xts_read_buffer[:read_len_xts] = temp_read_data
                else:
                    # Handle partial read or EOF
                    self._log(f"[WARNING] Partial read: got {read_len_xts} bytes, expected {bytes_to_read_for_this_xts_chunk} at offset {pkg_read_offset_for_xts:#x}")
                    if read_len_xts > 0:
                        xts_read_buffer[:read_len_xts] = temp_read_data
                        # Zero out the rest of the buffer
                        xts_read_buffer[read_len_xts:bytes_to_read_for_this_xts_chunk] = b'\0' * (bytes_to_read_for_this_xts_chunk - read_len_xts)
                    else:
                        self._log(f"[ERROR] Failed to read any data at offset {pkg_read_offset_for_xts:#x}")
                        return None
                
                # Log the first 32 bytes of the read data for verification
                if pkg_read_offset_for_xts == 0x14F000 or (pkg_read_offset_for_xts >= 0x14F000 and pkg_read_offset_for_xts < 0x150000):
                    self._log(f"[DEBUG] Successfully read {read_len_xts} bytes at offset {pkg_read_offset_for_xts:#x}")
                    self._log(f"[DEBUG] First 32 bytes: {temp_read_data[:32].hex() if temp_read_data else 'None'}")
                    
                    # Save the read data for debugging
                    debug_path = self.extract_base_path / f"fixed_read_{pkg_read_offset_for_xts:08x}.bin"
                    try:
                        with open(debug_path, 'wb') as df:
                            df.write(temp_read_data)
                        self._log(f"[DEBUG] Saved fixed read to {debug_path}")
                    except Exception as e:
                        self._log(f"[DEBUG] Error saving debug data: {e}")
                
                if read_len_xts != bytes_to_read_for_this_xts_chunk:
                    error_msg = f"ERRORE (mem extract): Lettura PKG incompleta per blocco XTS. Richiesti {bytes_to_read_for_this_xts_chunk}, letti {read_len_xts}."
                    self._log(error_msg)
                    
                    # Try to continue with partial read if possible
                    if read_len_xts <= 0:
                        return None

                # Salva i dati prima della decrittazione
                data_before_decrypt = bytes(xts_read_buffer[:read_len_xts])
                
                # Salva i dati grezzi su disco per analisi
                raw_data_path = self.extract_base_path / f"debug_raw_block_{j_file_block}_chunk{xts_sub_offset_in_pfs_block // 0x1000}.bin"
                try:
                    with open(raw_data_path, "wb") as f:
                        f.write(data_before_decrypt)
                    self._log(f"    [DEBUG] Salvati dati grezzi in {raw_data_path}")
                except Exception as e:
                    self._log(f"    [DEBUG] Errore salvataggio dati grezzi: {e}")
                
                # Esegui la decrittazione
                self.crypto.decryptPFS(self.dataKey, self.tweakKey, 
                                       data_before_decrypt, 
                                       xts_decrypted_buffer[:read_len_xts], 
                                       xts_sector_num_for_tweak)
                
                # Salva i dati dopo la decrittazione
                data_after_decrypt = bytes(xts_decrypted_buffer[:read_len_xts])
                
                # Salva i dati decrittati su disco per analisi
                decrypted_data_path = self.extract_base_path / f"debug_decrypted_block_{j_file_block}_chunk{xts_sub_offset_in_pfs_block // 0x1000}.bin"
                try:
                    with open(decrypted_data_path, "wb") as f:
                        f.write(data_after_decrypt)
                    self._log(f"    [DEBUG] Salvati dati decrittati in {decrypted_data_path}")
                except Exception as e:
                    self._log(f"    [DEBUG] Errore salvataggio dati decrittati: {e}")
                
                # Log dei primi 32 byte prima e dopo la decrittazione
                self._log(f"    [DEBUG] Dati prima decrittazione (primi 32 byte): {data_before_decrypt[:32].hex()}")
                self._log(f"    [DEBUG] Dati dopo decrittazione (primi 32 byte): {data_after_decrypt[:32].hex()}")
                
                # Controlla se i dati sono tutti zeri
                if all(b == 0 for b in data_before_decrypt[:32]):
                    self._log("    [WARNING] Dati prima della decrittazione sono tutti zeri!")
                if all(b == 0 for b in data_after_decrypt[:32]):
                    self._log("    [WARNING] Dati dopo la decrittazione sono tutti zeri!")
                
                # Salva i dati decrittati nel buffer
                current_block_data_after_xts[read_for_this_pfs_block : read_for_this_pfs_block + read_len_xts] = data_after_decrypt
                read_for_this_pfs_block += read_len_xts
            
            final_data_for_this_pfs_block = bytes(current_block_data_after_xts)
            self._log(f"[DEBUG] Dimensione blocco dopo XTS: {len(final_data_for_this_pfs_block)} byte")

            if is_compressed:
                self._log(f"[DEBUG] Decompressione blocco {j_file_block}, dimensione compressa: {len(final_data_for_this_pfs_block)}")
                
                # Salva i dati compressi su disco per analisi
                compressed_debug_path = self.extract_base_path / f"debug_compressed_block_{j_file_block}.bin"
                try:
                    with open(compressed_debug_path, "wb") as f:
                        f.write(final_data_for_this_pfs_block)
                    self._log(f"[DEBUG] Salvati dati compressi in {compressed_debug_path}")
                except Exception as e:
                    self._log(f"[DEBUG] Errore salvataggio dati compressi: {e}")
                
                decomp_buffer_for_file_block = bytearray(decomp_block_buf_size)
                decompressed_part = decompress_pfsc(final_data_for_this_pfs_block, len(decomp_buffer_for_file_block), self._log)
                
                if decompressed_part is None:
                    self._log(f"ERRORE (mem extract): Decompressione fallita per blocco file {j_file_block}.")
                    return None
                    
                final_data_for_this_pfs_block = decompressed_part
                self._log(f"[DEBUG] Dimensione dopo decompressione: {len(final_data_for_this_pfs_block)} byte")
            
            bytes_to_append = min(len(final_data_for_this_pfs_block), inode_obj.Size - written_total_for_file)
            if bytes_to_append > 0:
                file_data_accumulator.extend(final_data_for_this_pfs_block[:bytes_to_append])
                written_total_for_file += bytes_to_append
                self._log(f"[DEBUG] Aggiunti {bytes_to_append} byte al buffer (totale: {written_total_for_file}/{inode_obj.Size})")
            
            # Salva i primi 32 byte dei dati finali per verifica
            self._log(f"[DEBUG] Primi 32 byte dei dati finali: {bytes(file_data_accumulator[:32]).hex()}")
            
            # Se abbiamo abbastanza dati, controlla se sono tutti zeri
            if len(file_data_accumulator) >= 32:
                all_zeros = all(b == 0 for b in file_data_accumulator[:32])
                self._log(f"[DEBUG] I primi 32 byte sono tutti zeri: {all_zeros}")
                
                if all_zeros:
                    self._log("[WARNING] I primi 32 byte sono tutti zeri! Potrebbe esserci un problema con la lettura o la decrittazione.")
                    
                    # Prova a leggere direttamente dal file PKG per verificare i dati grezzi
                    try:
                        with open(self.pkg_path, 'rb') as f:
                            f.seek(pkg_read_offset_for_xts)
                            raw_data = f.read(32)
                            self._log(f"[DEBUG] Dati grezzi letti direttamente da {self.pkg_path} all'offset {pkg_read_offset_for_xts:#x}: {raw_data.hex()}")
                    except Exception as e:
                        self._log(f"[DEBUG] Errore durante la lettura diretta del file PKG: {e}")
        
        if written_total_for_file != inode_obj.Size: 
            self._log(f"AVVISO (mem extract): Dimensione finale ({written_total_for_file}) non corrisponde a inode.Size ({inode_obj.Size}).")
        
        return bytes(file_data_accumulator)

    def _parse_internal_flat_path_table(self, fpt_data: bytes, base_extract_path: Path):
        self._log(f"Parsing FPT interna (size {len(fpt_data)} bytes) in '{base_extract_path}'")
        
        debug_fpt_path = self.extract_base_path / "debug_INTERNAL_FPT_data.bin"
        try:
            with open(debug_fpt_path, "wb") as f: f.write(fpt_data)
            self._log(f"  Dati FPT interna salvati in: {debug_fpt_path}")
        except Exception as e: self._log(f"  Errore salvataggio FPT interna: {e}")

        offset = 0
        dirents_in_fpt = 0
        
        while offset < len(fpt_data):
            if len(fpt_data) - offset < Dirent._BASE_SIZE:
                self._log(f"  FPT Interna: Dati rimanenti ({len(fpt_data) - offset}) troppo pochi per una Dirent base. Fine parsing.")
                break
            
            try:
                dirent = Dirent.from_bytes(fpt_data[offset:])
            except ValueError as ve:
                self._log(f"  ERRORE parsing Dirent in FPT interna a offset {offset}: {ve}")
                break

            if dirent.entsize == 0:
                self._log(f"  FPT Interna: Dirent con entsize=0 a offset {offset}. Fine parsing.")
                break
            if dirent.ino == 0 and dirent.namelen == 0 : 
                self._log(f"  FPT Interna: Dirent terminatore (ino=0, namelen=0) a offset {offset}. Fine parsing.")
                break
            
            entry_name = dirent.name
            entry_inode_num = dirent.ino
            
            self._log(f"    FPT Interna Dirent: '{entry_name}' (inode {entry_inode_num}), Dirent.type={dirent.type} ({dirent.get_pfs_file_type().name}), Entsize: {dirent.entsize}")

            if not entry_name: 
                self._log(f"      FPT Interna: Nome dirent vuoto a offset {offset}. Salto.")
                offset += dirent.entsize
                continue

            if not (0 <= entry_inode_num - 1 < len(self.iNodeBuf)):
                self._log(f"      AVVISO FPT Interna: Dirent '{entry_name}' (inode {entry_inode_num}) non in iNodeBuf. Salto.")
                offset += dirent.entsize
                continue
            
            target_inode_obj = self.iNodeBuf[entry_inode_num - 1]
            if target_inode_obj.Mode == 0:
                 self._log(f"      AVVISO FPT Interna: Dirent '{entry_name}' punta a inode {entry_inode_num} con Mode=0. Salto.")
                 offset += dirent.entsize
                 continue

            actual_entry_type = target_inode_obj.get_file_type()
            
            self.fs_table.append(FSTableEntry(entry_name, entry_inode_num, actual_entry_type))
            
            current_entry_full_path = base_extract_path / entry_name
            self.extract_paths[entry_inode_num] = current_entry_full_path

            if actual_entry_type == PFSFileType.PFS_DIR:
                self._log(f"      FPT Interna: Creazione directory '{current_entry_full_path}' (inode {entry_inode_num})")
                current_entry_full_path.mkdir(parents=True, exist_ok=True)
            else: 
                self._log(f"      FPT Interna: Trovato file/link '{current_entry_full_path}' (inode {entry_inode_num})")
            
            dirents_in_fpt += 1
            offset += dirent.entsize
            if dirent.entsize < Dirent._BASE_SIZE and dirent.entsize != 0: 
                self._log(f"AVVISO FPT Interna: Dirent.entsize ({dirent.entsize}) anomalo per '{entry_name}'. Interruzione parsing FPT.")
                break
        
        self._log(f"  FPT Interna: Processate {dirents_in_fpt} dirents.")

        # --- INIZIO LOGICA PER UROOT E FPT INTERNA (COME SUGGERITO DALL'UTENTE) ---
        self._log(f"DEBUG: Controllo pre-FPT interna. fs_table ha {len(self.fs_table)} elementi.")
        self._log(f"DEBUG: fs_table attuale (prima del parsing FPT uroot): {[(e.name, e.inode, e.type.name) for e in self.fs_table]}")
        self._log(f"DEBUG: extract_paths attuale (prima del parsing FPT uroot): {self.extract_paths}")

        uroot_entry_details: Optional[FSTableEntry] = None
        uroot_inode_num_for_fpt = -1
        # original_uroot_fs_table_idx = -1 # Non strettamente necessario qui

        for fs_entry_item in list(self.fs_table): # Iteriamo su una copia per sicurezza se fs_table fosse modificata altrove (anche se non qui)
            if fs_entry_item.name == "uroot":
                # Controlla che l'inode sia valido prima di accedere a iNodeBuf
                if 0 <= fs_entry_item.inode - 1 < len(self.iNodeBuf):
                    uroot_inode_obj_check = self.iNodeBuf[fs_entry_item.inode - 1]
                    # La dirent potrebbe dire PFS_DIR ma l'inode PFS_FILE, o viceversa.
                    # L'inode ha l'autorità finale sul tipo.
                    if uroot_inode_obj_check.get_file_type() == PFSFileType.PFS_FILE:
                        self._log(f"Trovato file 'uroot' (inode {fs_entry_item.inode}, type dall'inode: {uroot_inode_obj_check.get_file_type().name}) che PUNTA a FPT.")
                        uroot_entry_details = fs_entry_item
                        uroot_inode_num_for_fpt = fs_entry_item.inode
                        break 
                    else:
                        self._log(f"Trovata entry 'uroot' (inode {fs_entry_item.inode}) ma il suo inode type è {uroot_inode_obj_check.get_file_type().name}, non PFS_FILE. Non la userò per FPT.")
                else:
                    self._log(f"AVVISO: Trovata entry 'uroot' ma il suo inode {fs_entry_item.inode} è fuori range per iNodeBuf (len {len(self.iNodeBuf)}).")

        if uroot_entry_details and uroot_inode_num_for_fpt != -1:
            self._log(f"DEBUG: uroot_entry_details trovato: True, uroot_inode_num_for_fpt: {uroot_inode_num_for_fpt}")
            self._log(f"DEBUG: ENTRATO nel blocco di parsing FPT interna per uroot (inode {uroot_inode_num_for_fpt}).")
            
            uroot_inode_obj = self.iNodeBuf[uroot_inode_num_for_fpt - 1]
            
            # Apri di nuovo il file PKG per estrarre i dati di uroot
            # È importante usare un nuovo handle o assicurarsi che la posizione sia corretta.
            uroot_file_content_bytes: Optional[bytes] = None
            try:
                with open(self.pkg_path, "rb") as pkg_file_for_uroot: # self.pkg_path deve essere settato
                    uroot_file_content_bytes = self._extract_single_pfs_file_data_to_memory(pkg_file_for_uroot, uroot_inode_obj)
            except Exception as e_uroot_extract:
                self._log(f"ERRORE durante l'estrazione del contenuto di uroot (inode {uroot_inode_num_for_fpt}): {e_uroot_extract}")
                import traceback
                self._log(traceback.format_exc())

            if uroot_file_content_bytes is not None:
                self._log(f"Contenuto del file uroot (inode {uroot_inode_num_for_fpt}, size {len(uroot_file_content_bytes)}) estratto in memoria.")
                # Salva per debug
                debug_uroot_path = self.extract_base_path / f"debug_UROOD_FILE_CONTENT_inode{uroot_inode_num_for_fpt}.bin"
                try:
                    with open(debug_uroot_path, "wb") as f_uroot_dbg: 
                        f_uroot_dbg.write(uroot_file_content_bytes)
                    self._log(f"Contenuto del file uroot (inode {uroot_inode_num_for_fpt}, size {len(uroot_file_content_bytes)}) salvato in {debug_uroot_path}")
                except Exception as e_save_uroot: 
                    self._log(f"Errore salvataggio debug uroot: {e_save_uroot}")
                
                # Prima di parsare la FPT interna, svuota la fs_table e extract_paths attuali
                # perché la FPT interna è la "vera" tabella dei file.
                self._log("Resettando fs_table e extract_paths prima di parsare FPT interna da uroot.")
                self.fs_table.clear()
                self.extract_paths.clear()
                
                # Il base_extract_path per la FPT interna è la radice dell'estrazione del PKG.
                self._parse_internal_flat_path_table(uroot_file_content_bytes, self.extract_base_path)
                self._log(f"Dopo parsing FPT interna da uroot, fs_table ha {len(self.fs_table)} voci.")
                self._log(f"DEBUG: fs_table DOPO parsing FPT uroot: {[(e.name, e.inode, e.type.name) for e in self.fs_table]}")
                self._log(f"DEBUG: extract_paths DOPO parsing FPT uroot: {self.extract_paths}")
            else:
                self._log(f"ERRORE: Impossibile estrarre contenuto di uroot (inode {uroot_inode_num_for_fpt}). FPT interna non parsata.")
        else:
            self._log("DEBUG: Nessun file 'uroot' valido trovato o uroot_inode_num_for_fpt non impostato. Salto parsing FPT interna.")
        # --- FINE LOGICA PER UROOT E FPT INTERNA ---

# --- Interfaccia Grafica (Tkinter) ---
class PKGToolGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("PKG Tool")
        master.geometry("700x550")

        self.filepath_label = tk.Label(self.master, text="File PKG:")
        self.filepath_label.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.filepath_entry = tk.Entry(self.master, width=60)
        self.filepath_entry.grid(row=0, column=1, padx=5, pady=2)
        self.browse_file_button = tk.Button(self.master, text="Sfoglia...", command=self.browse_pkg_file)
        self.browse_file_button.grid(row=0, column=2, padx=5, pady=2)

        self.extract_base_path_label = tk.Label(self.master, text="Directory Output:")
        self.extract_base_path_label.grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.extract_base_path_entry = tk.Entry(self.master, width=60)
        self.extract_base_path_entry.grid(row=1, column=1, padx=5, pady=2)
        self.browse_output_button = tk.Button(self.master, text="Sfoglia...", command=self.browse_output_directory)
        self.browse_output_button.grid(row=1, column=2, padx=5, pady=2)

        self.extract_button = tk.Button(self.master, text="Estrai PKG", command=self.extract_pkg)
        self.extract_button.grid(row=2, column=0, columnspan=3, pady=10)
        
        log_frame = tk.Frame(master)
        log_frame.grid(row=3, column=0, columnspan=3, sticky="nsew", padx=5, pady=5)
        master.grid_rowconfigure(3, weight=1) # Permette al log_frame di espandersi
        master.grid_columnconfigure(1, weight=1) # Permette all'entry del path di espandersi

        self.log_text_area = scrolledtext.ScrolledText(log_frame, width=80, height=20, state=tk.DISABLED)
        self.log_text_area.pack(fill=tk.BOTH, expand=True)


    def browse_pkg_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("PKG files", "*.pkg")])
        if filepath:
            self.filepath_entry.delete(0, tk.END); self.filepath_entry.insert(0, filepath)

    def browse_output_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.extract_base_path_entry.delete(0, tk.END); self.extract_base_path_entry.insert(0, directory)

    def log_to_scrolledtext(self, message):
        if not hasattr(self, 'log_text_area') or not self.log_text_area.winfo_exists(): return
        self.log_text_area.config(state=tk.NORMAL)
        self.log_text_area.insert(tk.END, str(message) + "\n")
        self.log_text_area.see(tk.END)
        self.log_text_area.config(state=tk.DISABLED)
        self.master.update_idletasks()

    def extract_pkg(self):
        pkg_filepath_str = self.filepath_entry.get()
        extract_base_path_str = self.extract_base_path_entry.get()
        if not pkg_filepath_str or not extract_base_path_str:
            messagebox.showerror("Errore", "Seleziona file PKG e directory di output."); return
        
        filepath = pathlib.Path(pkg_filepath_str)
        extract_base_path = pathlib.Path(extract_base_path_str)
        if not filepath.is_file():
            messagebox.showerror("Errore", f"File PKG non trovato: {filepath}"); return
        extract_base_path.mkdir(parents=True, exist_ok=True)
        
        self.log_text_area.config(state=tk.NORMAL); self.log_text_area.delete(1.0, tk.END)
        self.extract_button.config(state=tk.DISABLED)
        
        threading.Thread(target=self._run_extraction_thread, args=(filepath, extract_base_path), daemon=True).start()

    def _run_extraction_thread(self, filepath: pathlib.Path, extract_base_path: pathlib.Path):
        pkg_instance = PKG(logger_func=self.log_to_scrolledtext)
        try:
            self.log_to_scrolledtext(f"--- Inizio Analisi PKG: {filepath.name} ---")
            success, message = pkg_instance.open_pkg(filepath)
            if not success:
                self.log_to_scrolledtext(f"ERRORE APERTURA PKG: {message}"); messagebox.showerror("Errore Apertura", message); return
            self.log_to_scrolledtext(message)
            self.log_to_scrolledtext(f"PKG Analizzato: TitleID={pkg_instance.get_title_id()}, Flags={pkg_instance.pkg_flags_str}")
            if pkg_instance.sfo_data: self.log_to_scrolledtext(f"param.sfo trovato (size {len(pkg_instance.sfo_data)}).")

            self.log_to_scrolledtext(f"\n--- Inizio Estrazione Metadati e Parsing PFS ---")
            success, message = pkg_instance.extract(filepath, extract_base_path)
            if not success:
                self.log_to_scrolledtext(f"ERRORE ESTRAZIONE METADATI/PFS: {message}"); messagebox.showerror("Errore Estrazione Metadati", message); return
            self.log_to_scrolledtext(message)
            
            if not pkg_instance.fs_table and pkg_instance.pkg_header.pfs_cache_size > 0 : # Se c'era un PFS atteso
                 self.log_to_scrolledtext("AVVISO: fs_table vuota, ma PFS sembrava presente. Controllare log di parsing.")
            elif not pkg_instance.fs_table:
                 self.log_to_scrolledtext("Nessun file trovato/processato da PFS.")
            else: 
                self.log_to_scrolledtext(f"\n--- Inizio Estrazione File da PFS ({len(pkg_instance.fs_table)} voci) ---")
                success, message = pkg_instance.extract_pfs_files()
                if not success: self.log_to_scrolledtext(f"ERRORE ESTRAZIONE FILE PFS: {message}")
                else: self.log_to_scrolledtext(f"Estrazione File da PFS completata: {message}")

            self.log_to_scrolledtext("\n--- Estrazione Completata ---")
            messagebox.showinfo("Completato", "Processo di estrazione terminato. Controlla il log.")
        except Exception as e:
            err_msg = f"ERRORE CRITICO: {e}"; self.log_to_scrolledtext(err_msg)
            import traceback; self.log_to_scrolledtext(traceback.format_exc())
            messagebox.showerror("Errore Critico", err_msg)
        finally:
            if self.master.winfo_exists(): self.extract_button.config(state=tk.NORMAL)

if __name__ == "__main__":
    import argparse
    import sys
    
    # Check if we have command line arguments
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="PKG Extractor Command Line")
        parser.add_argument("--pkg", help="Path to PKG file", required=True)
        parser.add_argument("--output", help="Output directory", required=True)
        args = parser.parse_args()
        
        # Run in command line mode
        print(f"Running in command line mode with: {args.pkg} -> {args.output}")
        pkg = PKG()
        pkg.extract(pathlib.Path(args.pkg), pathlib.Path(args.output))
        
    else: 
        # Run in GUI mode
        root = tk.Tk()
        app = PKGToolGUI(root)
        root.mainloop()
