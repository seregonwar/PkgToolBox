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

# --- Definizioni da keys.h ---
# Queste verranno usate nella classe Crypto

class FakeKeyset:
    Exponent1 = bytes([
        0x6D, 0x48, 0xE0, 0x54, 0x40, 0x25, 0xC8, 0x41, 0x29, 0x52, 0x42, 0x27, 0xEB, 0xD2, 0xC7,
        0xAB, 0x6B, 0x9C, 0x27, 0x0A, 0xB4, 0x1F, 0x94, 0x4E, 0xFA, 0x42, 0x1D, 0xB7, 0xBC, 0xB9,
        0xAE, 0xBC, 0x04, 0x6F, 0x75, 0x8F, 0x10, 0x5F, 0x89, 0xAC, 0xAB, 0x9C, 0xD2, 0xFA, 0xE6,
        0xA4, 0x13, 0x83, 0x68, 0xD4, 0x56, 0x38, 0xFE, 0xE5, 0x2B, 0x78, 0x44, 0x9C, 0x34, 0xE6,
        0x5A, 0xA0, 0xBE, 0x05, 0x70, 0xAD, 0x15, 0xC3, 0x2D, 0x31, 0xAC, 0x97, 0x5D, 0x88, 0xFC,
        0xC1, 0x62, 0x3D, 0xE2, 0xED, 0x11, 0xDB, 0xB6, 0x9E, 0xFC, 0x5A, 0x5A, 0x03, 0xF6, 0xCF,
        0x08, 0xD4, 0x5D, 0x90, 0xC9, 0x2A, 0xB9, 0x9B, 0xCF, 0xC8, 0x1A, 0x65, 0xF3, 0x5B, 0xE8,
        0x7F, 0xCF, 0xA5, 0xA6, 0x4C, 0x5C, 0x2A, 0x12, 0x0F, 0x92, 0xA5, 0xE3, 0xF0, 0x17, 0x1E,
        0x9A, 0x97, 0x45, 0x86, 0xFD, 0xDB, 0x54, 0x25])
    Exponent2 = bytes([
        0x2A, 0x51, 0xCE, 0x02, 0x44, 0x28, 0x50, 0xE8, 0x30, 0x20, 0x7C, 0x9C, 0x55, 0xBF, 0x60,
        0x39, 0xBC, 0xD1, 0xF0, 0xE7, 0x68, 0xF8, 0x08, 0x5B, 0x61, 0x1F, 0xA7, 0xBF, 0xD0, 0xE8,
        0x8B, 0xB5, 0xB1, 0xD5, 0xD9, 0x16, 0xAC, 0x75, 0x0C, 0x6D, 0xF2, 0xE0, 0xB5, 0x97, 0x75,
        0xD2, 0x68, 0x16, 0x1F, 0x00, 0x7D, 0x8B, 0x17, 0xE8, 0x78, 0x48, 0x41, 0x71, 0x2B, 0x18,
        0x96, 0x80, 0x11, 0xDB, 0x68, 0x39, 0x9C, 0xD6, 0xE0, 0x72, 0x42, 0x86, 0xF0, 0x1B, 0x16,
        0x0D, 0x3E, 0x12, 0x94, 0x3D, 0x25, 0xA8, 0xA9, 0x30, 0x9E, 0x54, 0x5A, 0xD6, 0x36, 0x6C,
        0xD6, 0x8C, 0x20, 0x62, 0x8F, 0xA1, 0x6B, 0x1F, 0x7C, 0x6D, 0xB2, 0xB1, 0xC1, 0x2E, 0xAD,
        0x36, 0x02, 0x9C, 0x3A, 0xCA, 0x2F, 0x09, 0xD2, 0x45, 0x9E, 0xEB, 0xF2, 0xBC, 0x6C, 0xAA,
        0x3B, 0x3E, 0x90, 0xBC, 0x38, 0x67, 0x35, 0x4D])
    PublicExponent = bytes([0, 1, 0, 1]) # e = 65537
    Coefficient = bytes([
        0x0B, 0x67, 0x1C, 0x0D, 0x6C, 0x57, 0xD3, 0xE7, 0x05, 0x65, 0x94, 0x31, 0x56, 0x55, 0xFD,
        0x28, 0x08, 0xFA, 0x05, 0x8A, 0xCC, 0x55, 0x39, 0x61, 0x97, 0x63, 0xA0, 0x16, 0x27, 0x3D,
        0xED, 0xC1, 0x16, 0x40, 0x2A, 0x12, 0xEA, 0x6F, 0xD9, 0xD8, 0x58, 0x56, 0xA8, 0x56, 0x8B,
        0x0D, 0x38, 0x5E, 0x1E, 0x80, 0x3B, 0x5F, 0x40, 0x80, 0x6F, 0x62, 0x4F, 0x28, 0xA2, 0x69,
        0xF3, 0xD3, 0xF7, 0xFD, 0xB2, 0xC3, 0x52, 0x43, 0x20, 0x92, 0x9D, 0x97, 0x8D, 0xA0, 0x15,
        0x07, 0x15, 0x6E, 0xA4, 0x0D, 0x56, 0xD3, 0x37, 0x1A, 0xC4, 0x9E, 0xDF, 0x02, 0x49, 0xB8,
        0x0A, 0x84, 0x62, 0xF5, 0xFA, 0xB9, 0x3F, 0xA4, 0x09, 0x76, 0xCC, 0xAA, 0xB9, 0x9B, 0xA6,
        0x4F, 0xC1, 0x6A, 0x64, 0xCE, 0xD8, 0x77, 0xAB, 0x4B, 0xF9, 0xA0, 0xAE, 0xDA, 0xF1, 0x67,
        0x87, 0x7C, 0x98, 0x5C, 0x7E, 0xB8, 0x73, 0xF5])
    Modulus = bytes([
        0xC6, 0xCF, 0x71, 0xE7, 0xE5, 0x9A, 0xF0, 0xD1, 0x2A, 0x2C, 0x45, 0x8B, 0xF9, 0x2A, 0x0E,
        0xC1, 0x43, 0x05, 0x8B, 0xC3, 0x71, 0x17, 0x80, 0x1D, 0xCD, 0x49, 0x7D, 0xDE, 0x35, 0x9D,
        0x25, 0x9B, 0xA0, 0xD7, 0xA0, 0xF2, 0x7D, 0x6C, 0x08, 0x7E, 0xAA, 0x55, 0x02, 0x68, 0x2B,
        0x23, 0xC6, 0x44, 0xB8, 0x44, 0x18, 0xEB, 0x56, 0xCF, 0x16, 0xA2, 0x48, 0x03, 0xC9, 0xE7,
        0x4F, 0x87, 0xEB, 0x3D, 0x30, 0xC3, 0x15, 0x88, 0xBF, 0x20, 0xE7, 0x9D, 0xFF, 0x77, 0x0C,
        0xDE, 0x1D, 0x24, 0x1E, 0x63, 0xA9, 0x4F, 0x8A, 0xBF, 0x5B, 0xBE, 0x60, 0x19, 0x68, 0x33,
        0x3B, 0xFC, 0xED, 0x9F, 0x47, 0x4E, 0x5F, 0xF8, 0xEA, 0xCB, 0x3D, 0x00, 0xBD, 0x67, 0x01,
        0xF9, 0x2C, 0x6D, 0xC6, 0xAC, 0x13, 0x64, 0xE7, 0x67, 0x14, 0xF3, 0xDC, 0x52, 0x69, 0x6A,
        0xB9, 0x83, 0x2C, 0x42, 0x30, 0x13, 0x1B, 0xB2, 0xD8, 0xA5, 0x02, 0x0D, 0x79, 0xED, 0x96,
        0xB1, 0x0D, 0xF8, 0xCC, 0x0C, 0xDF, 0x81, 0x95, 0x4F, 0x03, 0x58, 0x09, 0x57, 0x0E, 0x80,
        0x69, 0x2E, 0xFE, 0xFF, 0x52, 0x77, 0xEA, 0x75, 0x28, 0xA8, 0xFB, 0xC9, 0xBE, 0xBF, 0x9F,
        0xBB, 0xB7, 0x79, 0x8E, 0x18, 0x05, 0xE1, 0x80, 0xBD, 0x50, 0x34, 0x94, 0x81, 0xD3, 0x53,
        0xC2, 0x69, 0xA2, 0xD2, 0x4C, 0xCF, 0x6C, 0xF4, 0x57, 0x2C, 0x10, 0x4A, 0x3F, 0xFB, 0x22,
        0xFD, 0x8B, 0x97, 0xE2, 0xC9, 0x5B, 0xA6, 0x2B, 0xCD, 0xD6, 0x1B, 0x6B, 0xDB, 0x68, 0x7F,
        0x4B, 0xC2, 0xA0, 0x50, 0x34, 0xC0, 0x05, 0xE5, 0x8D, 0xEF, 0x24, 0x67, 0xFF, 0x93, 0x40,
        0xCF, 0x2D, 0x62, 0xA2, 0xA0, 0x50, 0xB1, 0xF1, 0x3A, 0xA8, 0x3D, 0xFD, 0x80, 0xD1, 0xF9,
        0xB8, 0x05, 0x22, 0xAF, 0xC8, 0x35, 0x45, 0x90, 0x58, 0x8E, 0xE3, 0x3A, 0x7C, 0xBD, 0x3E,
        0x27])
    Prime1 = bytes([
        0xFE, 0xF6, 0xBF, 0x1D, 0x69, 0xAB, 0x16, 0x25, 0x08, 0x47, 0x55, 0x6B, 0x86, 0xE4, 0x35,
        0x88, 0x72, 0x2A, 0xB1, 0x3D, 0xF8, 0xB6, 0x44, 0xCA, 0xB3, 0xAB, 0x19, 0xD1, 0x04, 0x24,
        0x28, 0x0A, 0x74, 0x55, 0xB8, 0x15, 0x45, 0x09, 0xCC, 0x13, 0x1C, 0xF2, 0xBA, 0x37, 0xA9,
        0x03, 0x90, 0x8F, 0x02, 0x10, 0xFF, 0x25, 0x79, 0x86, 0xCC, 0x18, 0x50, 0x9A, 0x10, 0x5F,
        0x5B, 0x4C, 0x1C, 0x4E, 0xB0, 0xA7, 0xE3, 0x59, 0xB1, 0x2D, 0xA0, 0xC6, 0xB0, 0x20, 0x2C,
        0x21, 0x33, 0x12, 0xB3, 0xAF, 0x72, 0x34, 0x83, 0xCD, 0x52, 0x2F, 0xAF, 0x0F, 0x20, 0x5A,
        0x1B, 0xC0, 0xE2, 0xA3, 0x76, 0x34, 0x0F, 0xD7, 0xFC, 0xC1, 0x41, 0xC9, 0xF9, 0x79, 0x40,
        0x17, 0x42, 0x21, 0x3E, 0x9D, 0xFD, 0xC7, 0xC1, 0x50, 0xDE, 0x44, 0x5A, 0xC9, 0x31, 0x89,
        0x6A, 0x78, 0x05, 0xBE, 0x65, 0xB4, 0xE8, 0x2D])
    Prime2 = bytes([
        0xC7, 0x9E, 0x47, 0x58, 0x00, 0x7D, 0x62, 0x82, 0xB0, 0xD2, 0x22, 0x81, 0xD4, 0xA8, 0x97,
        0x1B, 0x79, 0x0C, 0x3A, 0xB0, 0xD7, 0xC9, 0x30, 0xE3, 0xC3, 0x53, 0x8E, 0x57, 0xEF, 0xF0,
        0x9B, 0x9F, 0xB3, 0x90, 0x52, 0xC6, 0x94, 0x22, 0x36, 0xAA, 0xE6, 0x4A, 0x5F, 0x72, 0x1D,
        0x70, 0xE8, 0x76, 0x58, 0xC8, 0xB2, 0x91, 0xCE, 0x9C, 0xC3, 0xE9, 0x09, 0x7F, 0x2E, 0x47,
        0x97, 0xCC, 0x90, 0x39, 0x15, 0x35, 0x31, 0xDE, 0x1F, 0x0C, 0x8C, 0x0D, 0xC1, 0xC2, 0x92,
        0xBE, 0x97, 0xBF, 0x2F, 0x91, 0xA1, 0x8C, 0x7D, 0x50, 0xA8, 0x21, 0x2F, 0xD7, 0xA2, 0x9A,
        0x7E, 0xB5, 0xA7, 0x2A, 0x90, 0x02, 0xD9, 0xF3, 0x3D, 0xD1, 0xEB, 0xB8, 0xE0, 0x5A, 0x79,
        0x9E, 0x7D, 0x8D, 0xCA, 0x18, 0x6D, 0xBD, 0x9E, 0xA1, 0x80, 0x28, 0x6B, 0x2A, 0xFE, 0x51,
        0x24, 0x9B, 0x6F, 0x4D, 0x84, 0x77, 0x80, 0x23])
    PrivateExponent = bytes([ # d
        0x7F, 0x76, 0xCD, 0x0E, 0xE2, 0xD4, 0xDE, 0x05, 0x1C, 0xC6, 0xD9, 0xA8, 0x0E, 0x8D, 0xFA,
        0x7B, 0xCA, 0x1E, 0xAA, 0x27, 0x1A, 0x40, 0xF8, 0xF1, 0x22, 0x87, 0x35, 0xDD, 0xDB, 0xFD,
        0xEE, 0xF8, 0xC2, 0xBC, 0xBD, 0x01, 0xFB, 0x8B, 0xE2, 0x3E, 0x63, 0xB2, 0xB1, 0x22, 0x5C,
        0x56, 0x49, 0x6E, 0x11, 0xBE, 0x07, 0x44, 0x0B, 0x9A, 0x26, 0x66, 0xD1, 0x49, 0x2C, 0x8F,
        0xD3, 0x1B, 0xCF, 0xA4, 0xA1, 0xB8, 0xD1, 0xFB, 0xA4, 0x9E, 0xD2, 0x21, 0x28, 0x83, 0x09,
        0x8A, 0xF6, 0xA0, 0x0B, 0xA3, 0xD6, 0x0F, 0x9B, 0x63, 0x68, 0xCC, 0xBC, 0x0C, 0x4E, 0x14,
        0x5B, 0x27, 0xA4, 0xA9, 0xF4, 0x2B, 0xB9, 0xB8, 0x7B, 0xC0, 0xE6, 0x51, 0xAD, 0x1D, 0x77,
        0xD4, 0x6B, 0xB9, 0xCE, 0x20, 0xD1, 0x26, 0x66, 0x7E, 0x5E, 0x9E, 0xA2, 0xE9, 0x6B, 0x90,
        0xF3, 0x73, 0xB8, 0x52, 0x8F, 0x44, 0x11, 0x03, 0x0C, 0x13, 0x97, 0x39, 0x3D, 0x13, 0x22,
        0x58, 0xD5, 0x43, 0x82, 0x49, 0xDA, 0x6E, 0x7C, 0xA1, 0xC5, 0x8C, 0xA5, 0xB0, 0x09, 0xE0,
        0xCE, 0x3D, 0xDF, 0xF4, 0x9D, 0x3C, 0x97, 0x15, 0xE2, 0x6A, 0xC7, 0x2B, 0x3C, 0x50, 0x93,
        0x23, 0xDB, 0xBA, 0x4A, 0x22, 0x66, 0x44, 0xAC, 0x78, 0xBB, 0x0E, 0x1A, 0x27, 0x43, 0xB5,
        0x71, 0x67, 0xAF, 0xF4, 0xAB, 0x48, 0x46, 0x93, 0x73, 0xD0, 0x42, 0xAB, 0x93, 0x63, 0xE5,
        0x6C, 0x9A, 0xDE, 0x50, 0x24, 0xC0, 0x23, 0x7D, 0x99, 0x79, 0x3F, 0x22, 0x07, 0xE0, 0xC1,
        0x48, 0x56, 0x1B, 0xDF, 0x83, 0x09, 0x12, 0xB4, 0x2D, 0x45, 0x6B, 0xC9, 0xC0, 0x68, 0x85,
        0x99, 0x90, 0x79, 0x96, 0x1A, 0xD7, 0xF5, 0x4D, 0x1F, 0x37, 0x83, 0x40, 0x4A, 0xEC, 0x39,
        0x37, 0xA6, 0x80, 0x92, 0x7D, 0xC5, 0x80, 0xC7, 0xD6, 0x6F, 0xFE, 0x8A, 0x79, 0x89, 0xC6,
        0xB1])

class PkgDerivedKey3Keyset:
    Exponent1 = bytes([
        0x52, 0xCC, 0x2D, 0xA0, 0x9C, 0x9E, 0x75, 0xE7, 0x28, 0xEE, 0x3D, 0xDE, 0xE3, 0x45, 0xD1,
        0x4F, 0x94, 0x1C, 0xCC, 0xC8, 0x87, 0x29, 0x45, 0x3B, 0x8D, 0x6E, 0xAB, 0x6E, 0x2A, 0xA7,
        0xC7, 0x15, 0x43, 0xA3, 0x04, 0x8F, 0x90, 0x5F, 0xEB, 0xF3, 0x38, 0x4A, 0x77, 0xFA, 0x36,
        0xB7, 0x15, 0x76, 0xB6, 0x01, 0x1A, 0x8E, 0x25, 0x87, 0x82, 0xF1, 0x55, 0xD8, 0xC6, 0x43,
        0x2A, 0xC0, 0xE5, 0x98, 0xC9, 0x32, 0xD1, 0x94, 0x6F, 0xD9, 0x01, 0xBA, 0x06, 0x81, 0xE0,
        0x6D, 0x88, 0xF2, 0x24, 0x2A, 0x25, 0x01, 0x64, 0x5C, 0xBF, 0xF2, 0xD9, 0x99, 0x67, 0x3E,
        0xF6, 0x72, 0xEE, 0xE4, 0xE2, 0x33, 0x5C, 0xF8, 0x00, 0x40, 0xE3, 0x2A, 0x9A, 0xF4, 0x3D,
        0x22, 0x86, 0x44, 0x3C, 0xFB, 0x0A, 0xA5, 0x7C, 0x3F, 0xCC, 0xF5, 0xF1, 0x16, 0xC4, 0xAC,
        0x88, 0xB4, 0xDE, 0x62, 0x94, 0x92, 0x6A, 0x13])
    Exponent2 = bytes([
        0x7C, 0x9D, 0xAD, 0x39, 0xE0, 0xD5, 0x60, 0x14, 0x94, 0x48, 0x19, 0x7F, 0x88, 0x95, 0xD5,
        0x8B, 0x80, 0xAD, 0x85, 0x8A, 0x4B, 0x77, 0x37, 0x85, 0xD0, 0x77, 0xBB, 0xBF, 0x89, 0x71,
        0x4A, 0x72, 0xCB, 0x72, 0x68, 0x38, 0xEC, 0x02, 0xC6, 0x7D, 0xC6, 0x44, 0x06, 0x33, 0x51,
        0x1C, 0xC0, 0xFF, 0x95, 0x8F, 0x0D, 0x75, 0xDC, 0x25, 0xBB, 0x0B, 0x73, 0x91, 0xA9, 0x6D,
        0x42, 0xD8, 0x03, 0xB7, 0x68, 0xD4, 0x1E, 0x75, 0x62, 0xA3, 0x70, 0x35, 0x79, 0x78, 0x00,
        0xC8, 0xF5, 0xEF, 0x15, 0xB9, 0xFC, 0x4E, 0x47, 0x5A, 0xC8, 0x70, 0x70, 0x5B, 0x52, 0x98,
        0xC0, 0xC2, 0x58, 0x4A, 0x70, 0x96, 0xCC, 0xB8, 0x10, 0xE1, 0x2F, 0x78, 0x8B, 0x2B, 0xA1,
        0x7F, 0xF9, 0xAC, 0xDE, 0xF0, 0xBB, 0x2B, 0xE2, 0x66, 0xE3, 0x22, 0x92, 0x31, 0x21, 0x57,
        0x92, 0xC4, 0xB8, 0xF2, 0x3E, 0x76, 0x20, 0x37])
    PublicExponent = bytes([0, 1, 0, 1])
    Coefficient = bytes([
        0x45, 0x97, 0x55, 0xD4, 0x22, 0x08, 0x5E, 0xF3, 0x5C, 0xB4, 0x05, 0x7A, 0xFD, 0xAA, 0x42,
        0x42, 0xAD, 0x9A, 0x8C, 0xA0, 0x6C, 0xBB, 0x1D, 0x68, 0x54, 0x54, 0x6E, 0x3E, 0x32, 0xE3,
        0x53, 0x73, 0x76, 0xF1, 0x3E, 0x01, 0xEA, 0xD3, 0xCF, 0xEB, 0xEB, 0x23, 0x3E, 0xC0, 0xBE,
        0xCE, 0xEC, 0x2C, 0x89, 0x5F, 0xA8, 0x27, 0x3A, 0x4C, 0xB7, 0xE6, 0x74, 0xBC, 0x45, 0x4C,
        0x26, 0xC8, 0x25, 0xFF, 0x34, 0x63, 0x25, 0x37, 0xE1, 0x48, 0x10, 0xC1, 0x93, 0xA6, 0xAF,
        0xEB, 0xBA, 0xE3, 0xA2, 0xF1, 0x3D, 0xEF, 0x63, 0xD8, 0xF4, 0xFD, 0xD3, 0xEE, 0xE2, 0x5D,
        0xE9, 0x33, 0xCC, 0xAD, 0xBA, 0x75, 0x5C, 0x85, 0xAF, 0xCE, 0xA9, 0x3D, 0xD1, 0xA2, 0x17,
        0xF3, 0xF6, 0x98, 0xB3, 0x50, 0x8E, 0x5E, 0xF6, 0xEB, 0x02, 0x8E, 0xA1, 0x62, 0xA7, 0xD6,
        0x2C, 0xEC, 0x91, 0xFF, 0x15, 0x40, 0xD2, 0xE3])
    Modulus = bytes([
        0xd2, 0x12, 0xfc, 0x33, 0x5f, 0x6d, 0xdb, 0x83, 0x16, 0x09, 0x62, 0x8b, 0x03, 0x56, 0x27,
        0x37, 0x82, 0xd4, 0x77, 0x85, 0x35, 0x29, 0x39, 0x2d, 0x52, 0x6b, 0x8c, 0x4c, 0x8c, 0xfb,
        0x06, 0xc1, 0x84, 0x5b, 0xe7, 0xd4, 0xf7, 0xbc, 0xd2, 0x4e, 0x62, 0x45, 0xcd, 0x2a, 0xbb,
        0xd7, 0x77, 0x76, 0x45, 0x36, 0x55, 0x27, 0x3f, 0xb3, 0xf5, 0xf9, 0x8e, 0xda, 0x4b, 0xef,
        0xaa, 0x59, 0xae, 0xb3, 0x9b, 0xea, 0x54, 0x98, 0xd2, 0x06, 0x32, 0x6a, 0x58, 0x31, 0x2a,
        0xe0, 0xd4, 0x4f, 0x90, 0xb5, 0x0a, 0x7d, 0xec, 0xf4, 0x3a, 0x9c, 0x52, 0x67, 0x2d, 0x99,
        0x31, 0x8e, 0x0c, 0x43, 0xe6, 0x82, 0xfe, 0x07, 0x46, 0xe1, 0x2e, 0x50, 0xd4, 0x1f, 0x2d,
        0x2f, 0x7e, 0xd9, 0x08, 0xba, 0x06, 0xb3, 0xbf, 0x2e, 0x20, 0x3f, 0x4e, 0x3f, 0xfe, 0x44,
        0xff, 0xaa, 0x50, 0x43, 0x57, 0x91, 0x69, 0x94, 0x49, 0x15, 0x82, 0x82, 0xe4, 0x0f, 0x4c,
        0x8d, 0x9d, 0x2c, 0xc9, 0x5b, 0x1d, 0x64, 0xbf, 0x88, 0x8b, 0xd4, 0xc5, 0x94, 0xe7, 0x65,
        0x47, 0x84, 0x1e, 0xe5, 0x79, 0x10, 0xfb, 0x98, 0x93, 0x47, 0xb9, 0x7d, 0x85, 0x12, 0xa6,
        0x40, 0x98, 0x2c, 0xf7, 0x92, 0xbc, 0x95, 0x19, 0x32, 0xed, 0xe8, 0x90, 0x56, 0x0d, 0x65,
        0xc1, 0xaa, 0x78, 0xc6, 0x2e, 0x54, 0xfd, 0x5f, 0x54, 0xa1, 0xf6, 0x7e, 0xe5, 0xe0, 0x5f,
        0x61, 0xc1, 0x20, 0xb4, 0xb9, 0xb4, 0x33, 0x08, 0x70, 0xe4, 0xdf, 0x89, 0x56, 0xed, 0x01,
        0x29, 0x46, 0x77, 0x5f, 0x8c, 0xb8, 0xa9, 0xf5, 0x1e, 0x2e, 0xb3, 0xb9, 0xbf, 0xe0, 0x09,
        0xb7, 0x8d, 0x28, 0xd4, 0xa6, 0xc3, 0xb8, 0x1e, 0x1f, 0x07, 0xeb, 0xb4, 0x12, 0x0b, 0x95,
        0xb8, 0x85, 0x30, 0xfd, 0xdc, 0x39, 0x13, 0xd0, 0x7c, 0xdc, 0x8f, 0xed, 0xf9, 0xc9, 0xa3,
        0xc1])
    Prime1 = bytes([
        0xF9, 0x67, 0xAD, 0x99, 0x12, 0x31, 0x0C, 0x56, 0xA2, 0x2E, 0x16, 0x1C, 0x46, 0xB3, 0x4D,
        0x5B, 0x43, 0xBE, 0x42, 0xA2, 0xF6, 0x86, 0x96, 0x80, 0x42, 0xC3, 0xC7, 0x3F, 0xC3, 0x42,
        0xF5, 0x87, 0x49, 0x33, 0x9F, 0x07, 0x5D, 0x6E, 0x2C, 0x04, 0xFD, 0xE3, 0xE1, 0xB2, 0xAE,
        0x0A, 0x0C, 0xF0, 0xC7, 0xA6, 0x1C, 0xA1, 0x63, 0x50, 0xC8, 0x09, 0x9C, 0x51, 0x24, 0x52,
        0x6C, 0x5E, 0x5E, 0xBD, 0x1E, 0x27, 0x06, 0xBB, 0xBC, 0x9E, 0x94, 0xE1, 0x35, 0xD4, 0x6D,
        0xB3, 0xCB, 0x3C, 0x68, 0xDD, 0x68, 0xB3, 0xFE, 0x6C, 0xCB, 0x8D, 0x82, 0x20, 0x76, 0x23,
        0x63, 0xB7, 0xE9, 0x68, 0x10, 0x01, 0x4E, 0xDC, 0xBA, 0x27, 0x5D, 0x01, 0xC1, 0x2D, 0x80,
        0x5E, 0x2B, 0xAF, 0x82, 0x6B, 0xD8, 0x84, 0xB6, 0x10, 0x52, 0x86, 0xA7, 0x89, 0x8E, 0xAE,
        0x9A, 0xE2, 0x89, 0xC6, 0xF7, 0xD5, 0x87, 0xFB])
    Prime2 = bytes([
        0xD7, 0xA1, 0x0F, 0x9A, 0x8B, 0xF2, 0xC9, 0x11, 0x95, 0x32, 0x9A, 0x8C, 0xF0, 0xD9, 0x40,
        0x47, 0xF5, 0x68, 0xA0, 0x0D, 0xBD, 0xC1, 0xFC, 0x43, 0x2F, 0x65, 0xF9, 0xC3, 0x61, 0x0F,
        0x25, 0x77, 0x54, 0xAD, 0xD7, 0x58, 0xAC, 0x84, 0x40, 0x60, 0x8D, 0x3F, 0xF3, 0x65, 0x89,
        0x75, 0xB5, 0xC6, 0x2C, 0x51, 0x1A, 0x2F, 0x1F, 0x22, 0xE4, 0x43, 0x11, 0x54, 0xBE, 0xC9,
        0xB4, 0xC7, 0xB5, 0x1B, 0x05, 0x0B, 0xBC, 0x56, 0x9A, 0xCD, 0x4A, 0xD9, 0x73, 0x68, 0x5E,
        0x5C, 0xFB, 0x92, 0xB7, 0x8B, 0x0D, 0xFF, 0xF5, 0x07, 0xCA, 0xB4, 0xC8, 0x9B, 0x96, 0x3C,
        0x07, 0x9E, 0x3E, 0x6B, 0x2A, 0x11, 0xF2, 0x8A, 0xB1, 0x8A, 0xD7, 0x2E, 0x1B, 0xA5, 0x53,
        0x24, 0x06, 0xED, 0x50, 0xB8, 0x90, 0x67, 0xB1, 0xE2, 0x41, 0xC6, 0x92, 0x01, 0xEE, 0x10,
        0xF0, 0x61, 0xBB, 0xFB, 0xB2, 0x7D, 0x4A, 0x73])
    PrivateExponent = bytes([
        0x32, 0xD9, 0x03, 0x90, 0x8F, 0xBD, 0xB0, 0x8F, 0x57, 0x2B, 0x28, 0x5E, 0x0B, 0x8D, 0xB3,
        0xEA, 0x5C, 0xD1, 0x7E, 0xA8, 0x90, 0x88, 0x8C, 0xDD, 0x6A, 0x80, 0xBB, 0xB1, 0xDF, 0xC1,
        0xF7, 0x0D, 0xAA, 0x32, 0xF0, 0xB7, 0x7C, 0xCB, 0x88, 0x80, 0x0E, 0x8B, 0x64, 0xB0, 0xBE,
        0x4C, 0xD6, 0x0E, 0x9B, 0x8C, 0x1E, 0x2A, 0x64, 0xE1, 0xF3, 0x5C, 0xD7, 0x76, 0x01, 0x41,
        0x5E, 0x93, 0x5C, 0x94, 0xFE, 0xDD, 0x46, 0x62, 0xC3, 0x1B, 0x5A, 0xE2, 0xA0, 0xBC, 0x2D,
        0xEB, 0xC3, 0x98, 0x0A, 0xA7, 0xB7, 0x85, 0x69, 0x70, 0x68, 0x2B, 0x64, 0x4A, 0xB3, 0x1F,
        0xCC, 0x7D, 0xDC, 0x7C, 0x26, 0xF4, 0x77, 0xF6, 0x5C, 0xF2, 0xAE, 0x5A, 0x44, 0x2D, 0xD3,
        0xAB, 0x16, 0x62, 0x04, 0x19, 0xBA, 0xFB, 0x90, 0xFF, 0xE2, 0x30, 0x50, 0x89, 0x6E, 0xCB,
        0x56, 0xB2, 0xEB, 0xC0, 0x91, 0x16, 0x92, 0x5E, 0x30, 0x8E, 0xAE, 0xC7, 0x94, 0x5D, 0xFD,
        0x35, 0xE1, 0x20, 0xF8, 0xAD, 0x3E, 0xBC, 0x08, 0xBF, 0xC0, 0x36, 0x74, 0x9F, 0xD5, 0xBB,
        0x52, 0x08, 0xFD, 0x06, 0x66, 0xF3, 0x7A, 0xB3, 0x04, 0xF4, 0x75, 0x29, 0x5D, 0xE9, 0x5F,
        0xAA, 0x10, 0x30, 0xB2, 0x0F, 0x5A, 0x1A, 0xC1, 0x2A, 0xB3, 0xFE, 0xCB, 0x21, 0xAD, 0x80,
        0xEC, 0x8F, 0x20, 0x09, 0x1C, 0xDB, 0xC5, 0x58, 0x94, 0xC2, 0x9C, 0xC6, 0xCE, 0x82, 0x65,
        0x3E, 0x57, 0x90, 0xBC, 0xA9, 0x8B, 0x06, 0xB4, 0xF0, 0x72, 0xF6, 0x77, 0xDF, 0x98, 0x64,
        0xF1, 0xEC, 0xFE, 0x37, 0x2D, 0xBC, 0xAE, 0x8C, 0x08, 0x81, 0x1F, 0xC3, 0xC9, 0x89, 0x1A,
        0xC7, 0x42, 0x82, 0x4B, 0x2E, 0xDC, 0x8E, 0x8D, 0x73, 0xCE, 0xB1, 0xCC, 0x01, 0xD9, 0x08,
        0x70, 0x87, 0x3C, 0x44, 0x08, 0xEC, 0x49, 0x8F, 0x81, 0x5A, 0xE2, 0x40, 0xFF, 0x77, 0xFC,
        0x0D])

# --- Costanti e Definizioni Strutture (aggiornate da .h forniti) ---
PFSC_MAGIC = 0x43534650  # "PFSC"
PKG_MAGIC_BE = 0x7F434E54   # ".CNT" (Big Endian nel file)
PKG_MAGIC_LE_VARIANT = 0x544E437F # "TNC\x7f" (Little Endian variant found in some files)

# --- pkg_type.h / pkg_type.cpp ---
# Questa mappatura è enorme, la includerò direttamente nella classe PKG o come costante globale.
# Per ora, la lascio come l'avevo prima, ma la aggiornerò.
PKG_ENTRY_ID_TO_NAME = {
    
    0x0001: "digests",
    0x0010: "entry_keys",
    0x0020: "image_key",
    0x0080: "general_digests",
    0x0100: "metas",
    0x0200: "entry_names",
    0x0400: "license.dat",
    0x0401: "license.info",
    0x0402: "nptitle.dat",
    0x0403: "npbind.dat",
    0x0404: "selfinfo.dat",
    0x0406: "imageinfo.dat",
    0x0407: "target-deltainfo.dat",
    0x0408: "origin-deltainfo.dat",
    0x0409: "psreserved.dat",
    0x1000: "param.sfo",
    0x1001: "playgo-chunk.dat",
    0x1002: "playgo-chunk.sha",
    0x1003: "playgo-manifest.xml",
    0x1004: "pronunciation.xml",
    0x1005: "pronunciation.sig",
    0x1006: "pic1.png",
    0x1007: "pubtoolinfo.dat",
    0x1008: "app/playgo-chunk.dat",
    0x1009: "app/playgo-chunk.sha",
    0x100A: "app/playgo-manifest.xml",
    0x100B: "shareparam.json",
    0x100C: "shareoverlayimage.png",
    0x100D: "save_data.png",
    0x100E: "shareprivacyguardimage.png",
    0x1200: "icon0.png",
    0x1201: "icon0_00.png",
    0x1202: "icon0_01.png",
    0x1203: "icon0_02.png",
    0x1204: "icon0_03.png",
    0x1205: "icon0_04.png",
    0x1206: "icon0_05.png",
    0x1207: "icon0_06.png",
    0x1208: "icon0_07.png",
    0x1209: "icon0_08.png",
    0x120A: "icon0_09.png",
    0x120B: "icon0_10.png",
    0x120C: "icon0_11.png",
    0x120D: "icon0_12.png",
    0x120E: "icon0_13.png",
    0x120F: "icon0_14.png",
    0x1210: "icon0_15.png",
    0x1211: "icon0_16.png",
    0x1212: "icon0_17.png",
    0x1213: "icon0_18.png",
    0x1214: "icon0_19.png",
    0x1215: "icon0_20.png",
    0x1216: "icon0_21.png",
    0x1217: "icon0_22.png",
    0x1218: "icon0_23.png",
    0x1219: "icon0_24.png",
    0x121A: "icon0_25.png",
    0x121B: "icon0_26.png",
    0x121C: "icon0_27.png",
    0x121D: "icon0_28.png",
    0x121E: "icon0_29.png",
    0x121F: "icon0_30.png",
    0x1220: "pic0.png",
    0x1240: "snd0.at9",
    0x1241: "pic1_00.png",
    0x1242: "pic1_01.png",
    0x1243: "pic1_02.png",
    0x1244: "pic1_03.png",
    0x1245: "pic1_04.png",
    0x1246: "pic1_05.png",
    0x1247: "pic1_06.png",
    0x1248: "pic1_07.png",
    0x1249: "pic1_08.png",
    0x124A: "pic1_09.png",
    0x124B: "pic1_10.png",
    0x124C: "pic1_11.png",
    0x124D: "pic1_12.png",
    0x124E: "pic1_13.png",
    0x124F: "pic1_14.png",
    0x1250: "pic1_15.png",
    0x1251: "pic1_16.png",
    0x1252: "pic1_17.png",
    0x1253: "pic1_18.png",
    0x1254: "pic1_19.png",
    0x1255: "pic1_20.png",
    0x1256: "pic1_21.png",
    0x1257: "pic1_22.png",
    0x1258: "pic1_23.png",
    0x1259: "pic1_24.png",
    0x125A: "pic1_25.png",
    0x125B: "pic1_26.png",
    0x125C: "pic1_27.png",
    0x125D: "pic1_28.png",
    0x125E: "pic1_29.png",
    0x125F: "pic1_30.png",
    0x1260: "changeinfo/changeinfo.xml",
    0x1261: "changeinfo/changeinfo_00.xml",
    0x1262: "changeinfo/changeinfo_01.xml",
    0x1263: "changeinfo/changeinfo_02.xml",
    0x1264: "changeinfo/changeinfo_03.xml",
    0x1265: "changeinfo/changeinfo_04.xml",
    0x1266: "changeinfo/changeinfo_05.xml",
    0x1267: "changeinfo/changeinfo_06.xml",
    0x1268: "changeinfo/changeinfo_07.xml",
    0x1269: "changeinfo/changeinfo_08.xml",
    0x126A: "changeinfo/changeinfo_09.xml",
    0x126B: "changeinfo/changeinfo_10.xml",
    0x126C: "changeinfo/changeinfo_11.xml",
    0x126D: "changeinfo/changeinfo_12.xml",
    0x126E: "changeinfo/changeinfo_13.xml",
    0x126F: "changeinfo/changeinfo_14.xml",
    0x1270: "changeinfo/changeinfo_15.xml",
    0x1271: "changeinfo/changeinfo_16.xml",
    0x1272: "changeinfo/changeinfo_17.xml",
    0x1273: "changeinfo/changeinfo_18.xml",
    0x1274: "changeinfo/changeinfo_19.xml",
    0x1275: "changeinfo/changeinfo_20.xml",
    0x1276: "changeinfo/changeinfo_21.xml",
    0x1277: "changeinfo/changeinfo_22.xml",
    0x1278: "changeinfo/changeinfo_23.xml",
    0x1279: "changeinfo/changeinfo_24.xml",
    0x127A: "changeinfo/changeinfo_25.xml",
    0x127B: "changeinfo/changeinfo_26.xml",
    0x127C: "changeinfo/changeinfo_27.xml",
    0x127D: "changeinfo/changeinfo_28.xml",
    0x127E: "changeinfo/changeinfo_29.xml",
    0x127F: "changeinfo/changeinfo_30.xml",
    0x1280: "icon0.dds",
    0x1281: "icon0_00.dds",
    0x1282: "icon0_01.dds",
    0x1283: "icon0_02.dds",
    0x1284: "icon0_03.dds",
    0x1285: "icon0_04.dds",
    0x1286: "icon0_05.dds",
    0x1287: "icon0_06.dds",
    0x1288: "icon0_07.dds",
    0x1289: "icon0_08.dds",
    0x128A: "icon0_09.dds",
    0x128B: "icon0_10.dds",
    0x128C: "icon0_11.dds",
    0x128D: "icon0_12.dds",
    0x128E: "icon0_13.dds",
    0x128F: "icon0_14.dds",
    0x1290: "icon0_15.dds",
    0x1291: "icon0_16.dds",
    0x1292: "icon0_17.dds",
    0x1293: "icon0_18.dds",
    0x1294: "icon0_19.dds",
    0x1295: "icon0_20.dds",
    0x1296: "icon0_21.dds",
    0x1297: "icon0_22.dds",
    0x1298: "icon0_23.dds",
    0x1299: "icon0_24.dds",
    0x129A: "icon0_25.dds",
    0x129B: "icon0_26.dds",
    0x129C: "icon0_27.dds",
    0x129D: "icon0_28.dds",
    0x129E: "icon0_29.dds",
    0x129F: "icon0_30.dds",
    0x12A0: "pic0.dds",
    0x12C0: "pic1.dds",
    0x12C1: "pic1_00.dds",
    0x12C2: "pic1_01.dds",
    0x12C3: "pic1_02.dds",
    0x12C4: "pic1_03.dds",
    0x12C5: "pic1_04.dds",
    0x12C6: "pic1_05.dds",
    0x12C7: "pic1_06.dds",
    0x12C8: "pic1_07.dds",
    0x12C9: "pic1_08.dds",
    0x12CA: "pic1_09.dds",
    0x12CB: "pic1_10.dds",
    0x12CC: "pic1_11.dds",
    0x12CD: "pic1_12.dds",
    0x12CE: "pic1_13.dds",
    0x12CF: "pic1_14.dds",
    0x12D0: "pic1_15.dds",
    0x12D1: "pic1_16.dds",
    0x12D2: "pic1_17.dds",
    0x12D3: "pic1_18.dds",
    0x12D4: "pic1_19.dds",
    0x12D5: "pic1_20.dds",
    0x12D6: "pic1_21.dds",
    0x12D7: "pic1_22.dds",
    0x12D8: "pic1_23.dds",
    0x12D9: "pic1_24.dds",
    0x12DA: "pic1_25.dds",
    0x12DB: "pic1_26.dds",
    0x12DC: "pic1_27.dds",
    0x12DD: "pic1_28.dds",
    0x12DE: "pic1_29.dds",
    0x12DF: "pic1_30.dds",
    0x1400: "trophy/trophy00.trp",
    0x1401: "trophy/trophy01.trp",
    0x1402: "trophy/trophy02.trp",
    0x1403: "trophy/trophy03.trp",
    0x1404: "trophy/trophy04.trp",
    0x1405: "trophy/trophy05.trp",
    0x1406: "trophy/trophy06.trp",
    0x1407: "trophy/trophy07.trp",
    0x1408: "trophy/trophy08.trp",
    0x1409: "trophy/trophy09.trp",
    0x140A: "trophy/trophy10.trp",
    0x140B: "trophy/trophy11.trp",
    0x140C: "trophy/trophy12.trp",
    0x140D: "trophy/trophy13.trp",
    0x140E: "trophy/trophy14.trp",
    0x140F: "trophy/trophy15.trp",
    0x1410: "trophy/trophy16.trp",
    0x1411: "trophy/trophy17.trp",
    0x1412: "trophy/trophy18.trp",
    0x1413: "trophy/trophy19.trp",
    0x1414: "trophy/trophy20.trp",
    0x1415: "trophy/trophy21.trp",
    0x1416: "trophy/trophy22.trp",
    0x1417: "trophy/trophy23.trp",
    0x1418: "trophy/trophy24.trp",
    0x1419: "trophy/trophy25.trp",
    0x141A: "trophy/trophy26.trp",
    0x141B: "trophy/trophy27.trp",
    0x141C: "trophy/trophy28.trp",
    0x141D: "trophy/trophy29.trp",
    0x141E: "trophy/trophy30.trp",
    0x141F: "trophy/trophy31.trp",
    0x1420: "trophy/trophy32.trp",
    0x1421: "trophy/trophy33.trp",
    0x1422: "trophy/trophy34.trp",
    0x1423: "trophy/trophy35.trp",
    0x1424: "trophy/trophy36.trp",
    0x1425: "trophy/trophy37.trp",
    0x1426: "trophy/trophy38.trp",
    0x1427: "trophy/trophy39.trp",
    0x1428: "trophy/trophy40.trp",
    0x1429: "trophy/trophy41.trp",
    0x142A: "trophy/trophy42.trp",
    0x142B: "trophy/trophy43.trp",
    0x142C: "trophy/trophy44.trp",
    0x142D: "trophy/trophy45.trp",
    0x142E: "trophy/trophy46.trp",
    0x142F: "trophy/trophy47.trp",
    0x1430: "trophy/trophy48.trp",
    0x1431: "trophy/trophy49.trp",
    0x1432: "trophy/trophy50.trp",
    0x1433: "trophy/trophy51.trp",
    0x1434: "trophy/trophy52.trp",
    0x1435: "trophy/trophy53.trp",
    0x1436: "trophy/trophy54.trp",
    0x1437: "trophy/trophy55.trp",
    0x1438: "trophy/trophy56.trp",
    0x1439: "trophy/trophy57.trp",
    0x143A: "trophy/trophy58.trp",
    0x143B: "trophy/trophy59.trp",
    0x143C: "trophy/trophy60.trp",
    0x143D: "trophy/trophy61.trp",
    0x143E: "trophy/trophy62.trp",
    0x143F: "trophy/trophy63.trp",
    0x1440: "trophy/trophy64.trp",
    0x1441: "trophy/trophy65.trp",
    0x1442: "trophy/trophy66.trp",
    0x1443: "trophy/trophy67.trp",
    0x1444: "trophy/trophy68.trp",
    0x1445: "trophy/trophy69.trp",
    0x1446: "trophy/trophy70.trp",
    0x1447: "trophy/trophy71.trp",
    0x1448: "trophy/trophy72.trp",
    0x1449: "trophy/trophy73.trp",
    0x144A: "trophy/trophy74.trp",
    0x144B: "trophy/trophy75.trp",
    0x144C: "trophy/trophy76.trp",
    0x144D: "trophy/trophy77.trp",
    0x144E: "trophy/trophy78.trp",
    0x144F: "trophy/trophy79.trp",
    0x1450: "trophy/trophy80.trp",
    0x1451: "trophy/trophy81.trp",
    0x1452: "trophy/trophy82.trp",
    0x1453: "trophy/trophy83.trp",
    0x1454: "trophy/trophy84.trp",
    0x1455: "trophy/trophy85.trp",
    0x1456: "trophy/trophy86.trp",
    0x1457: "trophy/trophy87.trp",
    0x1458: "trophy/trophy88.trp",
    0x1459: "trophy/trophy89.trp",
    0x145A: "trophy/trophy90.trp",
    0x145B: "trophy/trophy91.trp",
    0x145C: "trophy/trophy92.trp",
    0x145D: "trophy/trophy93.trp",
    0x145E: "trophy/trophy94.trp",
    0x145F: "trophy/trophy95.trp",
    0x1460: "trophy/trophy96.trp",
    0x1461: "trophy/trophy97.trp",
    0x1462: "trophy/trophy98.trp",
    0x1463: "trophy/trophy99.trp",
    0x1600: "keymap_rp/001.png",
    0x1601: "keymap_rp/002.png",
    0x1602: "keymap_rp/003.png",
    0x1603: "keymap_rp/004.png",
    0x1604: "keymap_rp/005.png",
    0x1605: "keymap_rp/006.png",
    0x1606: "keymap_rp/007.png",
    0x1607: "keymap_rp/008.png",
    0x1608: "keymap_rp/009.png",
    0x1609: "keymap_rp/010.png",
    0x1610: "keymap_rp/00/001.png",
    0x1611: "keymap_rp/00/002.png",
    0x1612: "keymap_rp/00/003.png",
    0x1613: "keymap_rp/00/004.png",
    0x1614: "keymap_rp/00/005.png",
    0x1615: "keymap_rp/00/006.png",
    0x1616: "keymap_rp/00/007.png",
    0x1617: "keymap_rp/00/008.png",
    0x1618: "keymap_rp/00/009.png",
    0x1619: "keymap_rp/00/010.png",
    0x1620: "keymap_rp/01/001.png",
    0x1621: "keymap_rp/01/002.png",
    0x1622: "keymap_rp/01/003.png",
    0x1623: "keymap_rp/01/004.png",
    0x1624: "keymap_rp/01/005.png",
    0x1625: "keymap_rp/01/006.png",
    0x1626: "keymap_rp/01/007.png",
    0x1627: "keymap_rp/01/008.png",
    0x1628: "keymap_rp/01/009.png",
    0x1629: "keymap_rp/01/010.png",
    0x1630: "keymap_rp/02/001.png",
    0x1631: "keymap_rp/02/002.png",
    0x1632: "keymap_rp/02/003.png",
    0x1633: "keymap_rp/02/004.png",
    0x1634: "keymap_rp/02/005.png",
    0x1635: "keymap_rp/02/006.png",
    0x1636: "keymap_rp/02/007.png",
    0x1637: "keymap_rp/02/008.png",
    0x1638: "keymap_rp/02/009.png",
    0x1639: "keymap_rp/02/010.png",
    0x1640: "keymap_rp/03/001.png",
    0x1641: "keymap_rp/03/002.png",
    0x1642: "keymap_rp/03/003.png",
    0x1643: "keymap_rp/03/004.png",
    0x1644: "keymap_rp/03/005.png",
    0x1645: "keymap_rp/03/006.png",
    0x1646: "keymap_rp/03/007.png",
    0x1647: "keymap_rp/03/008.png",
    0x1648: "keymap_rp/03/0010.png", # Sembra un typo nel C++, dovrebbe essere 009? O 010?
    0x1650: "keymap_rp/04/001.png",
    0x1651: "keymap_rp/04/002.png",
    0x1652: "keymap_rp/04/003.png",
    0x1653: "keymap_rp/04/004.png",
    0x1654: "keymap_rp/04/005.png",
    0x1655: "keymap_rp/04/006.png",
    0x1656: "keymap_rp/04/007.png",
    0x1657: "keymap_rp/04/008.png",
    0x1658: "keymap_rp/04/009.png",
    0x1659: "keymap_rp/04/010.png",
    0x1660: "keymap_rp/05/001.png",
    0x1661: "keymap_rp/05/002.png",
    0x1662: "keymap_rp/05/003.png",
    0x1663: "keymap_rp/05/004.png",
    0x1664: "keymap_rp/05/005.png",
    0x1665: "keymap_rp/05/006.png",
    0x1666: "keymap_rp/05/007.png",
    0x1667: "keymap_rp/05/008.png",
    0x1668: "keymap_rp/05/009.png",
    0x1669: "keymap_rp/05/010.png",
    0x1670: "keymap_rp/06/001.png",
    0x1671: "keymap_rp/06/002.png",
    0x1672: "keymap_rp/06/003.png",
    0x1673: "keymap_rp/06/004.png",
    0x1674: "keymap_rp/06/005.png",
    0x1675: "keymap_rp/06/006.png",
    0x1676: "keymap_rp/06/007.png",
    0x1677: "keymap_rp/06/008.png",
    0x1678: "keymap_rp/06/009.png",
    0x1679: "keymap_rp/06/010.png",
    0x1680: "keymap_rp/07/001.png",
    0x1681: "keymap_rp/07/002.png",
    0x1682: "keymap_rp/07/003.png",
    0x1683: "keymap_rp/07/004.png",
    0x1684: "keymap_rp/07/005.png",
    0x1685: "keymap_rp/07/006.png",
    0x1686: "keymap_rp/07/007.png",
    0x1687: "keymap_rp/07/008.png",
    0x1688: "keymap_rp/07/009.png",
    0x1689: "keymap_rp/07/010.png",
    0x1690: "keymap_rp/08/001.png",
    0x1691: "keymap_rp/08/002.png",
    0x1692: "keymap_rp/08/003.png",
    0x1693: "keymap_rp/08/004.png",
    0x1694: "keymap_rp/08/005.png",
    0x1695: "keymap_rp/08/006.png",
    0x1696: "keymap_rp/08/007.png",
    0x1697: "keymap_rp/08/008.png",
    0x1698: "keymap_rp/08/009.png",
    0x1699: "keymap_rp/08/010.png",
    0x16A0: "keymap_rp/09/001.png",
    0x16A1: "keymap_rp/09/002.png",
    0x16A2: "keymap_rp/09/003.png",
    0x16A3: "keymap_rp/09/004.png",
    0x16A4: "keymap_rp/09/005.png",
    0x16A5: "keymap_rp/09/006.png",
    0x16A6: "keymap_rp/09/007.png",
    0x16A7: "keymap_rp/09/008.png",
    0x16A8: "keymap_rp/09/009.png",
    0x16A9: "keymap_rp/09/010.png",
    0x16B0: "keymap_rp/10/001.png",
    0x16B1: "keymap_rp/10/002.png",
    0x16B2: "keymap_rp/10/003.png",
    0x16B3: "keymap_rp/10/004.png",
    0x16B4: "keymap_rp/10/005.png",
    0x16B5: "keymap_rp/10/006.png",
    0x16B6: "keymap_rp/10/007.png",
    0x16B7: "keymap_rp/10/008.png",
    0x16B8: "keymap_rp/10/009.png",
    0x16B9: "keymap_rp/10/010.png",
    0x16C0: "keymap_rp/11/001.png",
    0x16C1: "keymap_rp/11/002.png",
    0x16C2: "keymap_rp/11/003.png",
    0x16C3: "keymap_rp/11/004.png",
    0x16C4: "keymap_rp/11/005.png",
    0x16C5: "keymap_rp/11/006.png",
    0x16C6: "keymap_rp/11/007.png",
    0x16C7: "keymap_rp/11/008.png",
    0x16C8: "keymap_rp/11/009.png",
    0x16C9: "keymap_rp/11/010.png",
    0x16D0: "keymap_rp/12/001.png",
    0x16D1: "keymap_rp/12/002.png",
    0x16D2: "keymap_rp/12/003.png",
    0x16D3: "keymap_rp/12/004.png",
    0x16D4: "keymap_rp/12/005.png",
    0x16D5: "keymap_rp/12/006.png",
    0x16D6: "keymap_rp/12/007.png",
    0x16D7: "keymap_rp/12/008.png",
    0x16D8: "keymap_rp/12/009.png",
    0x16D9: "keymap_rp/12/010.png",
    0x16E0: "keymap_rp/13/001.png",
    0x16E1: "keymap_rp/13/002.png",
    0x16E2: "keymap_rp/13/003.png",
    0x16E3: "keymap_rp/13/004.png",
    0x16E4: "keymap_rp/13/005.png",
    0x16E5: "keymap_rp/13/006.png",
    0x16E6: "keymap_rp/13/007.png",
    0x16E7: "keymap_rp/13/008.png",
    0x16E8: "keymap_rp/13/009.png",
    0x16E9: "keymap_rp/13/010.png",
    0x16F0: "keymap_rp/14/001.png",
    0x16F1: "keymap_rp/14/002.png",
    0x16F2: "keymap_rp/14/003.png",
    0x16F3: "keymap_rp/14/004.png",
    0x16F4: "keymap_rp/14/005.png",
    0x16F5: "keymap_rp/14/006.png",
    0x16F6: "keymap_rp/14/007.png",
    0x16F7: "keymap_rp/14/008.png",
    0x16F8: "keymap_rp/14/009.png",
    0x16F9: "keymap_rp/14/010.png",
    0x1700: "keymap_rp/15/001.png",
    0x1701: "keymap_rp/15/002.png",
    0x1702: "keymap_rp/15/003.png",
    0x1703: "keymap_rp/15/004.png",
    0x1704: "keymap_rp/15/005.png",
    0x1705: "keymap_rp/15/006.png",
    0x1706: "keymap_rp/15/007.png",
    0x1707: "keymap_rp/15/008.png",
    0x1708: "keymap_rp/15/009.png",
    0x1709: "keymap_rp/15/010.png",
    0x1710: "keymap_rp/16/001.png",
    0x1711: "keymap_rp/16/002.png",
    0x1712: "keymap_rp/16/003.png",
    0x1713: "keymap_rp/16/004.png",
    0x1714: "keymap_rp/16/005.png",
    0x1715: "keymap_rp/16/006.png",
    0x1716: "keymap_rp/16/007.png",
    0x1717: "keymap_rp/16/008.png",
    0x1718: "keymap_rp/16/009.png",
    0x1719: "keymap_rp/16/010.png",
    0x1720: "keymap_rp/17/001.png",
    0x1721: "keymap_rp/17/002.png",
    0x1722: "keymap_rp/17/003.png",
    0x1723: "keymap_rp/17/004.png",
    0x1724: "keymap_rp/17/005.png",
    0x1725: "keymap_rp/17/006.png",
    0x1726: "keymap_rp/17/007.png",
    0x1727: "keymap_rp/17/008.png",
    0x1728: "keymap_rp/17/009.png",
    0x1729: "keymap_rp/17/010.png",
    0x1730: "keymap_rp/18/001.png",
    0x1731: "keymap_rp/18/002.png",
    0x1732: "keymap_rp/18/003.png",
    0x1733: "keymap_rp/18/004.png",
    0x1734: "keymap_rp/18/005.png",
    0x1735: "keymap_rp/18/006.png",
    0x1736: "keymap_rp/18/007.png",
    0x1737: "keymap_rp/18/008.png",
    0x1738: "keymap_rp/18/009.png",
    0x1739: "keymap_rp/18/010.png",
    0x1740: "keymap_rp/19/001.png",
    0x1741: "keymap_rp/19/002.png",
    0x1742: "keymap_rp/19/003.png",
    0x1743: "keymap_rp/19/004.png",
    0x1744: "keymap_rp/19/005.png",
    0x1745: "keymap_rp/19/006.png",
    0x1746: "keymap_rp/19/007.png",
    0x1747: "keymap_rp/19/008.png",
    0x1748: "keymap_rp/19/009.png",
    0x1749: "keymap_rp/19/010.png",
    0x1750: "keymap_rp/20/001.png",
    0x1751: "keymap_rp/20/002.png",
    0x1752: "keymap_rp/20/003.png",
    0x1753: "keymap_rp/20/004.png",
    0x1754: "keymap_rp/20/005.png",
    0x1755: "keymap_rp/20/006.png",
    0x1756: "keymap_rp/20/007.png",
    0x1757: "keymap_rp/20/008.png",
    0x1758: "keymap_rp/20/009.png",
    0x1759: "keymap_rp/20/010.png",
    0x1760: "keymap_rp/21/001.png",
    0x1761: "keymap_rp/21/002.png",
    0x1762: "keymap_rp/21/003.png",
    0x1763: "keymap_rp/21/004.png",
    0x1764: "keymap_rp/21/005.png",
    0x1765: "keymap_rp/21/006.png",
    0x1766: "keymap_rp/21/007.png",
    0x1767: "keymap_rp/21/008.png",
    0x1768: "keymap_rp/21/009.png",
    0x1769: "keymap_rp/21/010.png",
    0x1770: "keymap_rp/22/001.png",
    0x1771: "keymap_rp/22/002.png",
    0x1772: "keymap_rp/22/003.png",
    0x1773: "keymap_rp/22/004.png",
    0x1774: "keymap_rp/22/005.png",
    0x1775: "keymap_rp/22/006.png",
    0x1776: "keymap_rp/22/007.png",
    0x1777: "keymap_rp/22/008.png",
    0x1778: "keymap_rp/22/009.png",
    0x1779: "keymap_rp/22/010.png",
    0x1780: "keymap_rp/23/001.png",
    0x1781: "keymap_rp/23/002.png",
    0x1782: "keymap_rp/23/003.png",
    0x1783: "keymap_rp/23/004.png",
    0x1784: "keymap_rp/23/005.png",
    0x1785: "keymap_rp/23/006.png",
    0x1786: "keymap_rp/23/007.png",
    0x1787: "keymap_rp/23/008.png",
    0x1788: "keymap_rp/23/009.png",
    0x1789: "keymap_rp/23/010.png",
    0x1790: "keymap_rp/24/001.png",
    0x1791: "keymap_rp/24/002.png",
    0x1792: "keymap_rp/24/003.png",
    0x1793: "keymap_rp/24/004.png",
    0x1794: "keymap_rp/24/005.png",
    0x1795: "keymap_rp/24/006.png",
    0x1796: "keymap_rp/24/007.png",
    0x1797: "keymap_rp/24/008.png",
    0x1798: "keymap_rp/24/009.png",
    0x1799: "keymap_rp/24/010.png",
    0x17A0: "keymap_rp/25/001.png",
    0x17A1: "keymap_rp/25/002.png",
    0x17A2: "keymap_rp/25/003.png",
    0x17A3: "keymap_rp/25/004.png",
    0x17A4: "keymap_rp/25/005.png",
    0x17A5: "keymap_rp/25/006.png",
    0x17A6: "keymap_rp/25/007.png",
    0x17A7: "keymap_rp/25/008.png",
    0x17A8: "keymap_rp/25/009.png",
    0x17A9: "keymap_rp/25/010.png",
    0x17B0: "keymap_rp/26/001.png",
    0x17B1: "keymap_rp/26/002.png",
    0x17B2: "keymap_rp/26/003.png",
    0x17B3: "keymap_rp/26/004.png",
    0x17B4: "keymap_rp/26/005.png",
    0x17B5: "keymap_rp/26/006.png",
    0x17B6: "keymap_rp/26/007.png",
    0x17B7: "keymap_rp/26/008.png",
    0x17B8: "keymap_rp/26/009.png",
    0x17B9: "keymap_rp/26/010.png",
    0x17C0: "keymap_rp/27/001.png",
    0x17C1: "keymap_rp/27/002.png",
    0x17C2: "keymap_rp/27/003.png",
    0x17C3: "keymap_rp/27/004.png",
    0x17C4: "keymap_rp/27/005.png",
    0x17C5: "keymap_rp/27/006.png",
    0x17C6: "keymap_rp/27/007.png",
    0x17C7: "keymap_rp/27/008.png",
    0x17C8: "keymap_rp/27/009.png",
    0x17C9: "keymap_rp/27/010.png",
    0x17D0: "keymap_rp/28/001.png",
    0x17D1: "keymap_rp/28/002.png",
    0x17D2: "keymap_rp/28/003.png",
    0x17D3: "keymap_rp/28/004.png",
    0x17D4: "keymap_rp/28/005.png",
    0x17D5: "keymap_rp/28/006.png",
    0x17D6: "keymap_rp/28/007.png",
    0x17D7: "keymap_rp/28/008.png",
    0x17D8: "keymap_rp/28/009.png",
    0x17D9: "keymap_rp/28/010.png",
    0x17E0: "keymap_rp/29/001.png",
    0x17E1: "keymap_rp/29/002.png",
    0x17E2: "keymap_rp/29/003.png",
    0x17E3: "keymap_rp/29/004.png",
    0x17E4: "keymap_rp/29/005.png",
    0x17E5: "keymap_rp/29/006.png",
    0x17E6: "keymap_rp/29/007.png",
    0x17E7: "keymap_rp/29/008.png",
    0x17E8: "keymap_rp/29/009.png",
    0x17E9: "keymap_rp/29/010.png",
    0x17F0: "keymap_rp/30/001.png",
    0x17F1: "keymap_rp/30/002.png",
    0x17F2: "keymap_rp/30/003.png",
    0x17F3: "keymap_rp/30/004.png",
    0x17F4: "keymap_rp/30/005.png",
    0x17F5: "keymap_rp/30/006.png",
    0x17F6: "keymap_rp/30/007.png",
    0x17F7: "keymap_rp/30/008.png",
    0x17F8: "keymap_rp/30/009.png",
    0x17F9: "keymap_rp/30/010.png",
    # ... Aggiungi tutti i 611 se necessario

}
# Funzione per caricare dinamicamente PkgEntries da pkg_type.cpp (o hardcodarla)
def _load_pkg_entry_names():
    # Questo è solo un esempio, in pratica dovresti parsare pkg_type.cpp
    # o copiare l'array PkgEntries qui.
    # Per ora, uso una versione ridotta.
    _pkg_entries_raw = { # Da pkg_type.cpp

    0x0001: "digests",
    0x0010: "entry_keys",
    0x0020: "image_key",
    0x0080: "general_digests",
    0x0100: "metas",
    0x0200: "entry_names",
    0x0400: "license.dat",
    0x0401: "license.info",
    0x0402: "nptitle.dat",
    0x0403: "npbind.dat",
    0x0404: "selfinfo.dat",
    0x0406: "imageinfo.dat",
    0x0407: "target-deltainfo.dat",
    0x0408: "origin-deltainfo.dat",
    0x0409: "psreserved.dat",
    0x1000: "param.sfo",
    0x1001: "playgo-chunk.dat",
    0x1002: "playgo-chunk.sha",
    0x1003: "playgo-manifest.xml",
    0x1004: "pronunciation.xml",
    0x1005: "pronunciation.sig",
    0x1006: "pic1.png",
    0x1007: "pubtoolinfo.dat",
    0x1008: "app/playgo-chunk.dat",
    0x1009: "app/playgo-chunk.sha",
    0x100A: "app/playgo-manifest.xml",
    0x100B: "shareparam.json",
    0x100C: "shareoverlayimage.png",
    0x100D: "save_data.png",
    0x100E: "shareprivacyguardimage.png",
    0x1200: "icon0.png",
    0x1201: "icon0_00.png",
    0x1202: "icon0_01.png",
    0x1203: "icon0_02.png",
    0x1204: "icon0_03.png",
    0x1205: "icon0_04.png",
    0x1206: "icon0_05.png",
    0x1207: "icon0_06.png",
    0x1208: "icon0_07.png",
    0x1209: "icon0_08.png",
    0x120A: "icon0_09.png",
    0x120B: "icon0_10.png",
    0x120C: "icon0_11.png",
    0x120D: "icon0_12.png",
    0x120E: "icon0_13.png",
    0x120F: "icon0_14.png",
    0x1210: "icon0_15.png",
    0x1211: "icon0_16.png",
    0x1212: "icon0_17.png",
    0x1213: "icon0_18.png",
    0x1214: "icon0_19.png",
    0x1215: "icon0_20.png",
    0x1216: "icon0_21.png",
    0x1217: "icon0_22.png",
    0x1218: "icon0_23.png",
    0x1219: "icon0_24.png",
    0x121A: "icon0_25.png",
    0x121B: "icon0_26.png",
    0x121C: "icon0_27.png",
    0x121D: "icon0_28.png",
    0x121E: "icon0_29.png",
    0x121F: "icon0_30.png",
    0x1220: "pic0.png",
    0x1240: "snd0.at9",
    0x1241: "pic1_00.png",
    0x1242: "pic1_01.png",
    0x1243: "pic1_02.png",
    0x1244: "pic1_03.png",
    0x1245: "pic1_04.png",
    0x1246: "pic1_05.png",
    0x1247: "pic1_06.png",
    0x1248: "pic1_07.png",
    0x1249: "pic1_08.png",
    0x124A: "pic1_09.png",
    0x124B: "pic1_10.png",
    0x124C: "pic1_11.png",
    0x124D: "pic1_12.png",
    0x124E: "pic1_13.png",
    0x124F: "pic1_14.png",
    0x1250: "pic1_15.png",
    0x1251: "pic1_16.png",
    0x1252: "pic1_17.png",
    0x1253: "pic1_18.png",
    0x1254: "pic1_19.png",
    0x1255: "pic1_20.png",
    0x1256: "pic1_21.png",
    0x1257: "pic1_22.png",
    0x1258: "pic1_23.png",
    0x1259: "pic1_24.png",
    0x125A: "pic1_25.png",
    0x125B: "pic1_26.png",
    0x125C: "pic1_27.png",
    0x125D: "pic1_28.png",
    0x125E: "pic1_29.png",
    0x125F: "pic1_30.png",
    0x1260: "changeinfo/changeinfo.xml",
    0x1261: "changeinfo/changeinfo_00.xml",
    0x1262: "changeinfo/changeinfo_01.xml",
    0x1263: "changeinfo/changeinfo_02.xml",
    0x1264: "changeinfo/changeinfo_03.xml",
    0x1265: "changeinfo/changeinfo_04.xml",
    0x1266: "changeinfo/changeinfo_05.xml",
    0x1267: "changeinfo/changeinfo_06.xml",
    0x1268: "changeinfo/changeinfo_07.xml",
    0x1269: "changeinfo/changeinfo_08.xml",
    0x126A: "changeinfo/changeinfo_09.xml",
    0x126B: "changeinfo/changeinfo_10.xml",
    0x126C: "changeinfo/changeinfo_11.xml",
    0x126D: "changeinfo/changeinfo_12.xml",
    0x126E: "changeinfo/changeinfo_13.xml",
    0x126F: "changeinfo/changeinfo_14.xml",
    0x1270: "changeinfo/changeinfo_15.xml",
    0x1271: "changeinfo/changeinfo_16.xml",
    0x1272: "changeinfo/changeinfo_17.xml",
    0x1273: "changeinfo/changeinfo_18.xml",
    0x1274: "changeinfo/changeinfo_19.xml",
    0x1275: "changeinfo/changeinfo_20.xml",
    0x1276: "changeinfo/changeinfo_21.xml",
    0x1277: "changeinfo/changeinfo_22.xml",
    0x1278: "changeinfo/changeinfo_23.xml",
    0x1279: "changeinfo/changeinfo_24.xml",
    0x127A: "changeinfo/changeinfo_25.xml",
    0x127B: "changeinfo/changeinfo_26.xml",
    0x127C: "changeinfo/changeinfo_27.xml",
    0x127D: "changeinfo/changeinfo_28.xml",
    0x127E: "changeinfo/changeinfo_29.xml",
    0x127F: "changeinfo/changeinfo_30.xml",
    0x1280: "icon0.dds",
    0x1281: "icon0_00.dds",
    0x1282: "icon0_01.dds",
    0x1283: "icon0_02.dds",
    0x1284: "icon0_03.dds",
    0x1285: "icon0_04.dds",
    0x1286: "icon0_05.dds",
    0x1287: "icon0_06.dds",
    0x1288: "icon0_07.dds",
    0x1289: "icon0_08.dds",
    0x128A: "icon0_09.dds",
    0x128B: "icon0_10.dds",
    0x128C: "icon0_11.dds",
    0x128D: "icon0_12.dds",
    0x128E: "icon0_13.dds",
    0x128F: "icon0_14.dds",
    0x1290: "icon0_15.dds",
    0x1291: "icon0_16.dds",
    0x1292: "icon0_17.dds",
    0x1293: "icon0_18.dds",
    0x1294: "icon0_19.dds",
    0x1295: "icon0_20.dds",
    0x1296: "icon0_21.dds",
    0x1297: "icon0_22.dds",
    0x1298: "icon0_23.dds",
    0x1299: "icon0_24.dds",
    0x129A: "icon0_25.dds",
    0x129B: "icon0_26.dds",
    0x129C: "icon0_27.dds",
    0x129D: "icon0_28.dds",
    0x129E: "icon0_29.dds",
    0x129F: "icon0_30.dds",
    0x12A0: "pic0.dds",
    0x12C0: "pic1.dds",
    0x12C1: "pic1_00.dds",
    0x12C2: "pic1_01.dds",
    0x12C3: "pic1_02.dds",
    0x12C4: "pic1_03.dds",
    0x12C5: "pic1_04.dds",
    0x12C6: "pic1_05.dds",
    0x12C7: "pic1_06.dds",
    0x12C8: "pic1_07.dds",
    0x12C9: "pic1_08.dds",
    0x12CA: "pic1_09.dds",
    0x12CB: "pic1_10.dds",
    0x12CC: "pic1_11.dds",
    0x12CD: "pic1_12.dds",
    0x12CE: "pic1_13.dds",
    0x12CF: "pic1_14.dds",
    0x12D0: "pic1_15.dds",
    0x12D1: "pic1_16.dds",
    0x12D2: "pic1_17.dds",
    0x12D3: "pic1_18.dds",
    0x12D4: "pic1_19.dds",
    0x12D5: "pic1_20.dds",
    0x12D6: "pic1_21.dds",
    0x12D7: "pic1_22.dds",
    0x12D8: "pic1_23.dds",
    0x12D9: "pic1_24.dds",
    0x12DA: "pic1_25.dds",
    0x12DB: "pic1_26.dds",
    0x12DC: "pic1_27.dds",
    0x12DD: "pic1_28.dds",
    0x12DE: "pic1_29.dds",
    0x12DF: "pic1_30.dds",
    0x1400: "trophy/trophy00.trp",
    0x1401: "trophy/trophy01.trp",
    0x1402: "trophy/trophy02.trp",
    0x1403: "trophy/trophy03.trp",
    0x1404: "trophy/trophy04.trp",
    0x1405: "trophy/trophy05.trp",
    0x1406: "trophy/trophy06.trp",
    0x1407: "trophy/trophy07.trp",
    0x1408: "trophy/trophy08.trp",
    0x1409: "trophy/trophy09.trp",
    0x140A: "trophy/trophy10.trp",
    0x140B: "trophy/trophy11.trp",
    0x140C: "trophy/trophy12.trp",
    0x140D: "trophy/trophy13.trp",
    0x140E: "trophy/trophy14.trp",
    0x140F: "trophy/trophy15.trp",
    0x1410: "trophy/trophy16.trp",
    0x1411: "trophy/trophy17.trp",
    0x1412: "trophy/trophy18.trp",
    0x1413: "trophy/trophy19.trp",
    0x1414: "trophy/trophy20.trp",
    0x1415: "trophy/trophy21.trp",
    0x1416: "trophy/trophy22.trp",
    0x1417: "trophy/trophy23.trp",
    0x1418: "trophy/trophy24.trp",
    0x1419: "trophy/trophy25.trp",
    0x141A: "trophy/trophy26.trp",
    0x141B: "trophy/trophy27.trp",
    0x141C: "trophy/trophy28.trp",
    0x141D: "trophy/trophy29.trp",
    0x141E: "trophy/trophy30.trp",
    0x141F: "trophy/trophy31.trp",
    0x1420: "trophy/trophy32.trp",
    0x1421: "trophy/trophy33.trp",
    0x1422: "trophy/trophy34.trp",
    0x1423: "trophy/trophy35.trp",
    0x1424: "trophy/trophy36.trp",
    0x1425: "trophy/trophy37.trp",
    0x1426: "trophy/trophy38.trp",
    0x1427: "trophy/trophy39.trp",
    0x1428: "trophy/trophy40.trp",
    0x1429: "trophy/trophy41.trp",
    0x142A: "trophy/trophy42.trp",
    0x142B: "trophy/trophy43.trp",
    0x142C: "trophy/trophy44.trp",
    0x142D: "trophy/trophy45.trp",
    0x142E: "trophy/trophy46.trp",
    0x142F: "trophy/trophy47.trp",
    0x1430: "trophy/trophy48.trp",
    0x1431: "trophy/trophy49.trp",
    0x1432: "trophy/trophy50.trp",
    0x1433: "trophy/trophy51.trp",
    0x1434: "trophy/trophy52.trp",
    0x1435: "trophy/trophy53.trp",
    0x1436: "trophy/trophy54.trp",
    0x1437: "trophy/trophy55.trp",
    0x1438: "trophy/trophy56.trp",
    0x1439: "trophy/trophy57.trp",
    0x143A: "trophy/trophy58.trp",
    0x143B: "trophy/trophy59.trp",
    0x143C: "trophy/trophy60.trp",
    0x143D: "trophy/trophy61.trp",
    0x143E: "trophy/trophy62.trp",
    0x143F: "trophy/trophy63.trp",
    0x1440: "trophy/trophy64.trp",
    0x1441: "trophy/trophy65.trp",
    0x1442: "trophy/trophy66.trp",
    0x1443: "trophy/trophy67.trp",
    0x1444: "trophy/trophy68.trp",
    0x1445: "trophy/trophy69.trp",
    0x1446: "trophy/trophy70.trp",
    0x1447: "trophy/trophy71.trp",
    0x1448: "trophy/trophy72.trp",
    0x1449: "trophy/trophy73.trp",
    0x144A: "trophy/trophy74.trp",
    0x144B: "trophy/trophy75.trp",
    0x144C: "trophy/trophy76.trp",
    0x144D: "trophy/trophy77.trp",
    0x144E: "trophy/trophy78.trp",
    0x144F: "trophy/trophy79.trp",
    0x1450: "trophy/trophy80.trp",
    0x1451: "trophy/trophy81.trp",
    0x1452: "trophy/trophy82.trp",
    0x1453: "trophy/trophy83.trp",
    0x1454: "trophy/trophy84.trp",
    0x1455: "trophy/trophy85.trp",
    0x1456: "trophy/trophy86.trp",
    0x1457: "trophy/trophy87.trp",
    0x1458: "trophy/trophy88.trp",
    0x1459: "trophy/trophy89.trp",
    0x145A: "trophy/trophy90.trp",
    0x145B: "trophy/trophy91.trp",
    0x145C: "trophy/trophy92.trp",
    0x145D: "trophy/trophy93.trp",
    0x145E: "trophy/trophy94.trp",
    0x145F: "trophy/trophy95.trp",
    0x1460: "trophy/trophy96.trp",
    0x1461: "trophy/trophy97.trp",
    0x1462: "trophy/trophy98.trp",
    0x1463: "trophy/trophy99.trp",
    0x1600: "keymap_rp/001.png",
    0x1601: "keymap_rp/002.png",
    0x1602: "keymap_rp/003.png",
    0x1603: "keymap_rp/004.png",
    0x1604: "keymap_rp/005.png",
    0x1605: "keymap_rp/006.png",
    0x1606: "keymap_rp/007.png",
    0x1607: "keymap_rp/008.png",
    0x1608: "keymap_rp/009.png",
    0x1609: "keymap_rp/010.png",
    0x1610: "keymap_rp/00/001.png",
    0x1611: "keymap_rp/00/002.png",
    0x1612: "keymap_rp/00/003.png",
    0x1613: "keymap_rp/00/004.png",
    0x1614: "keymap_rp/00/005.png",
    0x1615: "keymap_rp/00/006.png",
    0x1616: "keymap_rp/00/007.png",
    0x1617: "keymap_rp/00/008.png",
    0x1618: "keymap_rp/00/009.png",
    0x1619: "keymap_rp/00/010.png",
    0x1620: "keymap_rp/01/001.png",
    0x1621: "keymap_rp/01/002.png",
    0x1622: "keymap_rp/01/003.png",
    0x1623: "keymap_rp/01/004.png",
    0x1624: "keymap_rp/01/005.png",
    0x1625: "keymap_rp/01/006.png",
    0x1626: "keymap_rp/01/007.png",
    0x1627: "keymap_rp/01/008.png",
    0x1628: "keymap_rp/01/009.png",
    0x1629: "keymap_rp/01/010.png",
    0x1630: "keymap_rp/02/001.png",
    0x1631: "keymap_rp/02/002.png",
    0x1632: "keymap_rp/02/003.png",
    0x1633: "keymap_rp/02/004.png",
    0x1634: "keymap_rp/02/005.png",
    0x1635: "keymap_rp/02/006.png",
    0x1636: "keymap_rp/02/007.png",
    0x1637: "keymap_rp/02/008.png",
    0x1638: "keymap_rp/02/009.png",
    0x1639: "keymap_rp/02/010.png",
    0x1640: "keymap_rp/03/001.png",
    0x1641: "keymap_rp/03/002.png",
    0x1642: "keymap_rp/03/003.png",
    0x1643: "keymap_rp/03/004.png",
    0x1644: "keymap_rp/03/005.png",
    0x1645: "keymap_rp/03/006.png",
    0x1646: "keymap_rp/03/007.png",
    0x1647: "keymap_rp/03/008.png",
    0x1648: "keymap_rp/03/0010.png", # Sembra un typo nel C++, dovrebbe essere 009? O 010?
    0x1650: "keymap_rp/04/001.png",
    0x1651: "keymap_rp/04/002.png",
    0x1652: "keymap_rp/04/003.png",
    0x1653: "keymap_rp/04/004.png",
    0x1654: "keymap_rp/04/005.png",
    0x1655: "keymap_rp/04/006.png",
    0x1656: "keymap_rp/04/007.png",
    0x1657: "keymap_rp/04/008.png",
    0x1658: "keymap_rp/04/009.png",
    0x1659: "keymap_rp/04/010.png",
    0x1660: "keymap_rp/05/001.png",
    0x1661: "keymap_rp/05/002.png",
    0x1662: "keymap_rp/05/003.png",
    0x1663: "keymap_rp/05/004.png",
    0x1664: "keymap_rp/05/005.png",
    0x1665: "keymap_rp/05/006.png",
    0x1666: "keymap_rp/05/007.png",
    0x1667: "keymap_rp/05/008.png",
    0x1668: "keymap_rp/05/009.png",
    0x1669: "keymap_rp/05/010.png",
    0x1670: "keymap_rp/06/001.png",
    0x1671: "keymap_rp/06/002.png",
    0x1672: "keymap_rp/06/003.png",
    0x1673: "keymap_rp/06/004.png",
    0x1674: "keymap_rp/06/005.png",
    0x1675: "keymap_rp/06/006.png",
    0x1676: "keymap_rp/06/007.png",
    0x1677: "keymap_rp/06/008.png",
    0x1678: "keymap_rp/06/009.png",
    0x1679: "keymap_rp/06/010.png",
    0x1680: "keymap_rp/07/001.png",
    0x1681: "keymap_rp/07/002.png",
    0x1682: "keymap_rp/07/003.png",
    0x1683: "keymap_rp/07/004.png",
    0x1684: "keymap_rp/07/005.png",
    0x1685: "keymap_rp/07/006.png",
    0x1686: "keymap_rp/07/007.png",
    0x1687: "keymap_rp/07/008.png",
    0x1688: "keymap_rp/07/009.png",
    0x1689: "keymap_rp/07/010.png",
    0x1690: "keymap_rp/08/001.png",
    0x1691: "keymap_rp/08/002.png",
    0x1692: "keymap_rp/08/003.png",
    0x1693: "keymap_rp/08/004.png",
    0x1694: "keymap_rp/08/005.png",
    0x1695: "keymap_rp/08/006.png",
    0x1696: "keymap_rp/08/007.png",
    0x1697: "keymap_rp/08/008.png",
    0x1698: "keymap_rp/08/009.png",
    0x1699: "keymap_rp/08/010.png",
    0x16A0: "keymap_rp/09/001.png",
    0x16A1: "keymap_rp/09/002.png",
    0x16A2: "keymap_rp/09/003.png",
    0x16A3: "keymap_rp/09/004.png",
    0x16A4: "keymap_rp/09/005.png",
    0x16A5: "keymap_rp/09/006.png",
    0x16A6: "keymap_rp/09/007.png",
    0x16A7: "keymap_rp/09/008.png",
    0x16A8: "keymap_rp/09/009.png",
    0x16A9: "keymap_rp/09/010.png",
    0x16B0: "keymap_rp/10/001.png",
    0x16B1: "keymap_rp/10/002.png",
    0x16B2: "keymap_rp/10/003.png",
    0x16B3: "keymap_rp/10/004.png",
    0x16B4: "keymap_rp/10/005.png",
    0x16B5: "keymap_rp/10/006.png",
    0x16B6: "keymap_rp/10/007.png",
    0x16B7: "keymap_rp/10/008.png",
    0x16B8: "keymap_rp/10/009.png",
    0x16B9: "keymap_rp/10/010.png",
    0x16C0: "keymap_rp/11/001.png",
    0x16C1: "keymap_rp/11/002.png",
    0x16C2: "keymap_rp/11/003.png",
    0x16C3: "keymap_rp/11/004.png",
    0x16C4: "keymap_rp/11/005.png",
    0x16C5: "keymap_rp/11/006.png",
    0x16C6: "keymap_rp/11/007.png",
    0x16C7: "keymap_rp/11/008.png",
    0x16C8: "keymap_rp/11/009.png",
    0x16C9: "keymap_rp/11/010.png",
    0x16D0: "keymap_rp/12/001.png",
    0x16D1: "keymap_rp/12/002.png",
    0x16D2: "keymap_rp/12/003.png",
    0x16D3: "keymap_rp/12/004.png",
    0x16D4: "keymap_rp/12/005.png",
    0x16D5: "keymap_rp/12/006.png",
    0x16D6: "keymap_rp/12/007.png",
    0x16D7: "keymap_rp/12/008.png",
    0x16D8: "keymap_rp/12/009.png",
    0x16D9: "keymap_rp/12/010.png",
    0x16E0: "keymap_rp/13/001.png",
    0x16E1: "keymap_rp/13/002.png",
    0x16E2: "keymap_rp/13/003.png",
    0x16E3: "keymap_rp/13/004.png",
    0x16E4: "keymap_rp/13/005.png",
    0x16E5: "keymap_rp/13/006.png",
    0x16E6: "keymap_rp/13/007.png",
    0x16E7: "keymap_rp/13/008.png",
    0x16E8: "keymap_rp/13/009.png",
    0x16E9: "keymap_rp/13/010.png",
    0x16F0: "keymap_rp/14/001.png",
    0x16F1: "keymap_rp/14/002.png",
    0x16F2: "keymap_rp/14/003.png",
    0x16F3: "keymap_rp/14/004.png",
    0x16F4: "keymap_rp/14/005.png",
    0x16F5: "keymap_rp/14/006.png",
    0x16F6: "keymap_rp/14/007.png",
    0x16F7: "keymap_rp/14/008.png",
    0x16F8: "keymap_rp/14/009.png",
    0x16F9: "keymap_rp/14/010.png",
    0x1700: "keymap_rp/15/001.png",
    0x1701: "keymap_rp/15/002.png",
    0x1702: "keymap_rp/15/003.png",
    0x1703: "keymap_rp/15/004.png",
    0x1704: "keymap_rp/15/005.png",
    0x1705: "keymap_rp/15/006.png",
    0x1706: "keymap_rp/15/007.png",
    0x1707: "keymap_rp/15/008.png",
    0x1708: "keymap_rp/15/009.png",
    0x1709: "keymap_rp/15/010.png",
    0x1710: "keymap_rp/16/001.png",
    0x1711: "keymap_rp/16/002.png",
    0x1712: "keymap_rp/16/003.png",
    0x1713: "keymap_rp/16/004.png",
    0x1714: "keymap_rp/16/005.png",
    0x1715: "keymap_rp/16/006.png",
    0x1716: "keymap_rp/16/007.png",
    0x1717: "keymap_rp/16/008.png",
    0x1718: "keymap_rp/16/009.png",
    0x1719: "keymap_rp/16/010.png",
    0x1720: "keymap_rp/17/001.png",
    0x1721: "keymap_rp/17/002.png",
    0x1722: "keymap_rp/17/003.png",
    0x1723: "keymap_rp/17/004.png",
    0x1724: "keymap_rp/17/005.png",
    0x1725: "keymap_rp/17/006.png",
    0x1726: "keymap_rp/17/007.png",
    0x1727: "keymap_rp/17/008.png",
    0x1728: "keymap_rp/17/009.png",
    0x1729: "keymap_rp/17/010.png",
    0x1730: "keymap_rp/18/001.png",
    0x1731: "keymap_rp/18/002.png",
    0x1732: "keymap_rp/18/003.png",
    0x1733: "keymap_rp/18/004.png",
    0x1734: "keymap_rp/18/005.png",
    0x1735: "keymap_rp/18/006.png",
    0x1736: "keymap_rp/18/007.png",
    0x1737: "keymap_rp/18/008.png",
    0x1738: "keymap_rp/18/009.png",
    0x1739: "keymap_rp/18/010.png",
    0x1740: "keymap_rp/19/001.png",
    0x1741: "keymap_rp/19/002.png",
    0x1742: "keymap_rp/19/003.png",
    0x1743: "keymap_rp/19/004.png",
    0x1744: "keymap_rp/19/005.png",
    0x1745: "keymap_rp/19/006.png",
    0x1746: "keymap_rp/19/007.png",
    0x1747: "keymap_rp/19/008.png",
    0x1748: "keymap_rp/19/009.png",
    0x1749: "keymap_rp/19/010.png",
    0x1750: "keymap_rp/20/001.png",
    0x1751: "keymap_rp/20/002.png",
    0x1752: "keymap_rp/20/003.png",
    0x1753: "keymap_rp/20/004.png",
    0x1754: "keymap_rp/20/005.png",
    0x1755: "keymap_rp/20/006.png",
    0x1756: "keymap_rp/20/007.png",
    0x1757: "keymap_rp/20/008.png",
    0x1758: "keymap_rp/20/009.png",
    0x1759: "keymap_rp/20/010.png",
    0x1760: "keymap_rp/21/001.png",
    0x1761: "keymap_rp/21/002.png",
    0x1762: "keymap_rp/21/003.png",
    0x1763: "keymap_rp/21/004.png",
    0x1764: "keymap_rp/21/005.png",
    0x1765: "keymap_rp/21/006.png",
    0x1766: "keymap_rp/21/007.png",
    0x1767: "keymap_rp/21/008.png",
    0x1768: "keymap_rp/21/009.png",
    0x1769: "keymap_rp/21/010.png",
    0x1770: "keymap_rp/22/001.png",
    0x1771: "keymap_rp/22/002.png",
    0x1772: "keymap_rp/22/003.png",
    0x1773: "keymap_rp/22/004.png",
    0x1774: "keymap_rp/22/005.png",
    0x1775: "keymap_rp/22/006.png",
    0x1776: "keymap_rp/22/007.png",
    0x1777: "keymap_rp/22/008.png",
    0x1778: "keymap_rp/22/009.png",
    0x1779: "keymap_rp/22/010.png",
    0x1780: "keymap_rp/23/001.png",
    0x1781: "keymap_rp/23/002.png",
    0x1782: "keymap_rp/23/003.png",
    0x1783: "keymap_rp/23/004.png",
    0x1784: "keymap_rp/23/005.png",
    0x1785: "keymap_rp/23/006.png",
    0x1786: "keymap_rp/23/007.png",
    0x1787: "keymap_rp/23/008.png",
    0x1788: "keymap_rp/23/009.png",
    0x1789: "keymap_rp/23/010.png",
    0x1790: "keymap_rp/24/001.png",
    0x1791: "keymap_rp/24/002.png",
    0x1792: "keymap_rp/24/003.png",
    0x1793: "keymap_rp/24/004.png",
    0x1794: "keymap_rp/24/005.png",
    0x1795: "keymap_rp/24/006.png",
    0x1796: "keymap_rp/24/007.png",
    0x1797: "keymap_rp/24/008.png",
    0x1798: "keymap_rp/24/009.png",
    0x1799: "keymap_rp/24/010.png",
    0x17A0: "keymap_rp/25/001.png",
    0x17A1: "keymap_rp/25/002.png",
    0x17A2: "keymap_rp/25/003.png",
    0x17A3: "keymap_rp/25/004.png",
    0x17A4: "keymap_rp/25/005.png",
    0x17A5: "keymap_rp/25/006.png",
    0x17A6: "keymap_rp/25/007.png",
    0x17A7: "keymap_rp/25/008.png",
    0x17A8: "keymap_rp/25/009.png",
    0x17A9: "keymap_rp/25/010.png",
    0x17B0: "keymap_rp/26/001.png",
    0x17B1: "keymap_rp/26/002.png",
    0x17B2: "keymap_rp/26/003.png",
    0x17B3: "keymap_rp/26/004.png",
    0x17B4: "keymap_rp/26/005.png",
    0x17B5: "keymap_rp/26/006.png",
    0x17B6: "keymap_rp/26/007.png",
    0x17B7: "keymap_rp/26/008.png",
    0x17B8: "keymap_rp/26/009.png",
    0x17B9: "keymap_rp/26/010.png",
    0x17C0: "keymap_rp/27/001.png",
    0x17C1: "keymap_rp/27/002.png",
    0x17C2: "keymap_rp/27/003.png",
    0x17C3: "keymap_rp/27/004.png",
    0x17C4: "keymap_rp/27/005.png",
    0x17C5: "keymap_rp/27/006.png",
    0x17C6: "keymap_rp/27/007.png",
    0x17C7: "keymap_rp/27/008.png",
    0x17C8: "keymap_rp/27/009.png",
    0x17C9: "keymap_rp/27/010.png",
    0x17D0: "keymap_rp/28/001.png",
    0x17D1: "keymap_rp/28/002.png",
    0x17D2: "keymap_rp/28/003.png",
    0x17D3: "keymap_rp/28/004.png",
    0x17D4: "keymap_rp/28/005.png",
    0x17D5: "keymap_rp/28/006.png",
    0x17D6: "keymap_rp/28/007.png",
    0x17D7: "keymap_rp/28/008.png",
    0x17D8: "keymap_rp/28/009.png",
    0x17D9: "keymap_rp/28/010.png",
    0x17E0: "keymap_rp/29/001.png",
    0x17E1: "keymap_rp/29/002.png",
    0x17E2: "keymap_rp/29/003.png",
    0x17E3: "keymap_rp/29/004.png",
    0x17E4: "keymap_rp/29/005.png",
    0x17E5: "keymap_rp/29/006.png",
    0x17E6: "keymap_rp/29/007.png",
    0x17E7: "keymap_rp/29/008.png",
    0x17E8: "keymap_rp/29/009.png",
    0x17E9: "keymap_rp/29/010.png",
    0x17F0: "keymap_rp/30/001.png",
    0x17F1: "keymap_rp/30/002.png",
    0x17F2: "keymap_rp/30/003.png",
    0x17F3: "keymap_rp/30/004.png",
    0x17F4: "keymap_rp/30/005.png",
    0x17F5: "keymap_rp/30/006.png",
    0x17F6: "keymap_rp/30/007.png",
    0x17F7: "keymap_rp/30/008.png",
    0x17F8: "keymap_rp/30/009.png",
    0x17F9: "keymap_rp/30/010.png",
}
    
    return _pkg_entries_raw

PKG_ENTRY_ID_TO_NAME_FULL = _load_pkg_entry_names()


class PKGContentFlag(Flag): # Da pkg.h
    FIRST_PATCH = 0x100000
    PATCHGO = 0x200000
    REMASTER = 0x400000
    PS_CLOUD = 0x800000
    GD_AC = 0x2000000
    NON_GAME = 0x4000000
    UNKNOWN_0x8000000 = 0x8000000 # Nome esplicito per chiarezza
    SUBSEQUENT_PATCH = 0x40000000
    DELTA_PATCH = 0x41000000 # NB: Questo è un valore combinato
    CUMULATIVE_PATCH = 0x60000000 # NB: Questo è un valore combinato

    # Flag aggiuntivi dal vecchio codice se ancora rilevanti o se diversi da pkg_header.pkg_content_flags
    # Questi erano nella lista FLAG_NAMES che ho usato prima, potrebbero non essere parte di PKGContentFlag
    # ma piuttosto di pkgheader.pkg_flags o pkg_content_flags in generale
    # PLAYGO = 0x00000001
    # DEBUG = 0x00000002
    # FSELF = 0x00000004
    # ... e così via. Bisogna distinguere chiaramente quali flag appartengono a quale campo.
    # Per ora, mi concentro su quelli esplicitamente in enum class PKGContentFlag

PKG_FLAG_NAMES_MAP = { # Da PKG::flagNames
    PKGContentFlag.FIRST_PATCH: "FIRST_PATCH",
    PKGContentFlag.PATCHGO: "PATCHGO",
    PKGContentFlag.REMASTER: "REMASTER",
    PKGContentFlag.PS_CLOUD: "PS_CLOUD",
    PKGContentFlag.GD_AC: "GD_AC",
    PKGContentFlag.NON_GAME: "NON_GAME",
    PKGContentFlag.UNKNOWN_0x8000000: "UNKNOWN_0x8000000",
    PKGContentFlag.SUBSEQUENT_PATCH: "SUBSEQUENT_PATCH",
    PKGContentFlag.DELTA_PATCH: "DELTA_PATCH", # Questo potrebbe essere problematico se il valore non è una singola potenza di 2
    PKGContentFlag.CUMULATIVE_PATCH: "CUMULATIVE_PATCH" # Idem
}

# Funzioni helper mancanti (implementazioni placeholder)
def get_pfsc_offset(data: bytes) -> int:
    """Cerca il magic PFSC (0x43534650) nei dati e restituisce l'offset."""
    magic_bytes = PFSC_MAGIC.to_bytes(4, 'little') # PFSC_MAGIC è little endian nel contesto PFS
    # La ricerca C++ inizia da 0x20000
    start_offset = 0x20000
    if len(data) < start_offset:
        return -1
    offset = data.find(magic_bytes, start_offset)
    return offset

def decompress_pfsc(compressed_data: bytes, decompressed_size: int) -> bytes:
    """Decomprime i dati PFSC (probabilmente zlib)."""
    # Il codice C++ usa zlib con windowBits = -15 (raw deflate)
    try:
        # Prova prima con zlib.decompress e wbits=-15 per raw deflate
        # Se questo fallisce, potrebbe essere zlib standard o un altro formato.
        # Il C++ fa `inflater.Put(compressedData.data(), compressedData.size()); inflater.MessageEnd();`
        # e poi `inflater.Get(decompressedData.data(), decompressedData.size());`
        # Questo suggerisce un flusso completo zlib.
        # Se i dati compressi includono un header zlib, wbits positivo.
        # Se sono raw deflate, wbits negativo.
        # Il C++ usa `Inflator inflater(nullptr, false, -15);` -> raw, no header.
        decompressor = zlib.decompressobj(-zlib.MAX_WBITS) # Raw deflate
        decompressed = decompressor.decompress(compressed_data)
        decompressed += decompressor.flush()
        if len(decompressed) != decompressed_size:
            # Potrebbe essere necessario gestire questo caso in modo più robusto
            # print(f"Attenzione: Decompressione PFSC ha prodotto {len(decompressed)} bytes, attesi {decompressed_size}")
            # Potrebbe essere necessario paddare o troncare, o è un errore.
            # Per ora, restituisci ciò che abbiamo, il chiamante potrebbe gestirlo.
            pass # Non fare nulla, lascia che il chiamante gestisca la dimensione
        return decompressed
    except zlib.error as e:
        # Fallback a zlib standard se raw fallisce, anche se il C++ sembra usare raw.
        # print(f"Errore decompressione PFSC (raw deflate): {e}. Tentativo con zlib standard.")
        try:
            return zlib.decompress(compressed_data)
        except zlib.error as e2:
            # print(f"Errore decompressione PFSC (standard zlib): {e2}. Restituzione dati compressi.")
            # Come ultima risorsa, restituisci i dati compressi, anche se non è corretto.
            # Il chiamante dovrebbe verificare la dimensione.
            # Questo è improbabile se il formato è noto per essere zlib raw.
            return compressed_data # Fallback problematico

@dataclass
class PKGHeader: # Da pkg.h
    # Tutti i campi sono Big Endian (es. u32_be)
    _FORMAT_PKGHEADER_BASE = (
        "I"    # magic
        "I"     # pkg_type
        "I"     # pkg_0x8
        "I"     # pkg_file_count
        "I"     # pkg_table_entry_count
        "H"     # pkg_sc_entry_count
        "H"     # pkg_table_entry_count_2
        "I"     # pkg_table_entry_offset
        "I"     # pkg_sc_entry_data_size
        "Q"     # pkg_body_offset
        "Q"     # pkg_body_size
        "Q"     # pkg_content_offset
        "Q"     # pkg_content_size
        "36s"   # pkg_content_id (0x24 bytes)
        "12s"   # pkg_padding (0xC bytes)
        "I"     # pkg_drm_type
        "I"     # pkg_content_type
        "I"     # pkg_content_flags
        "I"     # pkg_promote_size
        "I"     # pkg_version_date
        "I"     # pkg_version_hash
        "I"     # pkg_0x088
        "I"     # pkg_0x08C
        "I"     # pkg_0x090
        "I"     # pkg_0x094
        "I"     # pkg_iro_tag
        "I"     # pkg_drm_type_version
        "96s"   # pkg_zeroes_1 (0x60 bytes)
        "32s"   # digest_entries1
        "32s"   # digest_entries2
        "32s"   # digest_table_digest
        "32s"   # digest_body_digest
        "640s"  # pkg_zeroes_2 (0x280 bytes)
        "I"     # pkg_0x400
        "I"     # pfs_image_count
        "Q"     # pfs_image_flags
        "Q"     # pfs_image_offset
        "Q"     # pfs_image_size
        "Q"     # mount_image_offset
        "Q"     # mount_image_size
        "Q"     # pkg_size
        "I"     # pfs_signed_size
        "I"     # pfs_cache_size
        "32s"   # pfs_image_digest
        "32s"   # pfs_signed_digest
        "Q"     # pfs_split_size_nth_0
        "Q"     # pfs_split_size_nth_1
        # pkg_zeroes_3 (0xB50 bytes) -> 0x1000 - offset_attuale
        # pkg_digest (0x20 bytes)
    )
    # La dimensione totale dell'header nel file C++ è implicitamente gestita da file.Read(pkgheader).
    # Sembra che `sizeof(PKGHeader)` sia 0x1000 (4096 bytes)
    # Dobbiamo calcolare la dimensione dei pkg_zeroes_3 e pkg_digest per il formato struct.
    
    _SIZE_BEFORE_ZEROES3 = struct.calcsize( "".join(_FORMAT_PKGHEADER_BASE) )
    _SIZE_PKG_ZEROES3 = 0xB50
    _SIZE_PKG_DIGEST = 0x20
    _TOTAL_PKGHEADER_SIZE = _SIZE_BEFORE_ZEROES3 + _SIZE_PKG_ZEROES3 + _SIZE_PKG_DIGEST
    
    # Verifica se _TOTAL_PKGHEADER_SIZE è 0x1000
    # print(f"Calculated PKGHeader size: {hex(_TOTAL_PKGHEADER_SIZE)}") # Dovrebbe essere 0x1000

    _FORMAT_FULL = "".join(_FORMAT_PKGHEADER_BASE) + f"{_SIZE_PKG_ZEROES3}s" + f"{_SIZE_PKG_DIGEST}s"


    magic: int = 0
    pkg_type: int = 0
    pkg_0x8: int = 0
    pkg_file_count: int = 0
    pkg_table_entry_count: int = 0
    pkg_sc_entry_count: int = 0
    pkg_table_entry_count_2: int = 0
    pkg_table_entry_offset: int = 0
    pkg_sc_entry_data_size: int = 0
    pkg_body_offset: int = 0
    pkg_body_size: int = 0
    pkg_content_offset: int = 0
    pkg_content_size: int = 0
    pkg_content_id: bytes = b'\0'*36
    pkg_padding: bytes = b'\0'*12
    pkg_drm_type: int = 0
    pkg_content_type: int = 0
    pkg_content_flags: int = 0
    pkg_promote_size: int = 0
    pkg_version_date: int = 0
    pkg_version_hash: int = 0
    pkg_0x088: int = 0
    pkg_0x08C: int = 0
    pkg_0x090: int = 0
    pkg_0x094: int = 0
    pkg_iro_tag: int = 0
    pkg_drm_type_version: int = 0
    pkg_zeroes_1: bytes = b'\0'*0x60
    digest_entries1: bytes = b'\0'*32
    digest_entries2: bytes = b'\0'*32
    digest_table_digest: bytes = b'\0'*32
    digest_body_digest: bytes = b'\0'*32
    pkg_zeroes_2: bytes = b'\0'*0x280
    pkg_0x400: int = 0
    pfs_image_count: int = 0
    pfs_image_flags: int = 0
    pfs_image_offset: int = 0
    pfs_image_size: int = 0
    mount_image_offset: int = 0
    mount_image_size: int = 0
    pkg_size: int = 0 # Dimensione del PKG come da header
    pfs_signed_size: int = 0
    pfs_cache_size: int = 0
    pfs_image_digest: bytes = b'\0'*32
    pfs_signed_digest: bytes = b'\0'*32
    pfs_split_size_nth_0: int = 0
    pfs_split_size_nth_1: int = 0
    pkg_zeroes_3: bytes = b'\0'*_SIZE_PKG_ZEROES3
    pkg_digest: bytes = b'\0'*_SIZE_PKG_DIGEST

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls._TOTAL_PKGHEADER_SIZE:
            raise ValueError(f"Dati insufficienti per PKGHeader. Richiesti {cls._TOTAL_PKGHEADER_SIZE}, forniti {len(data)}")
        
        # Attenzione: pkg_content_id è un array di u8, quindi bytes.
        # Lo stesso per pkg_padding e i vari digest e zeroes.
        # struct.unpack li restituirà come bytes.
        values = struct.unpack(cls._FORMAT_FULL, data[:cls._TOTAL_PKGHEADER_SIZE])
        return cls(*values)


@dataclass
class PKGEntry: # Da pkg.h
    # Tutti i campi sono Big Endian
    _FORMAT = ">IIIIIIQ" # id, filename_offset, flags1, flags2, offset, size, padding
    _SIZE = struct.calcsize(_FORMAT) # Dovrebbe essere 32 bytes
    
    id: int = 0
    filename_offset: int = 0
    flags1: int = 0
    flags2: int = 0
    offset: int = 0
    size: int = 0
    padding: int = 0 # u64_be
    name: str = "" # Aggiunto per convenienza

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls._SIZE:
            raise ValueError(f"Dati insufficienti per PKGEntry. Richiesti {cls._SIZE}, forniti {len(data)}")
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
class PSFHeader_: # pfs.h - Nota: PSFHeader_ (con underscore) come nel file C++
    # Endianness non specificato, assumo Little Endian come default per PS4, a meno che non sia un formato standardizzato diversamente
    _FORMAT = "<qqqbBBBHhqIqqqq" # Controllare i tipi: s64 -> q, u8 -> B, PfsMode -> H (ushort), s16 -> h, s32 -> i
    _SIZE = struct.calcsize(_FORMAT)

    version: int = 0 # s64
    magic: int = 0   # s64
    id: int = 0      # s64
    fmode: int = 0   # u8
    clean: int = 0   # u8
    read_only: int = 0 # u8
    rsv: int = 0     # u8
    mode: PfsMode = PfsMode.NoneFlag # PfsMode (ushort)
    unk1: int = 0    # s16
    block_size: int = 0 # s32
    n_backup: int = 0   # s32
    n_block: int = 0    # s64
    dinode_count: int = 0 # s64
    nd_block: int = 0     # s64
    dinode_block_count: int = 0 # s64
    superroot_ino: int = 0    # s64

    @classmethod
    def from_bytes(cls, data: bytes):
        vals = list(struct.unpack_from(cls._FORMAT, data, 0))
        vals[7] = PfsMode(vals[7]) # Converte l'intero in enum PfsMode
        return cls(*vals)

@dataclass
class PFSCHdrPFS: # Rinominato per evitare conflitto con la versione precedente
    # Da pfs.h, la struct che il codice C++ pkg.cpp usa quando legge da pfsc.data()
    # magic: s32, unk4: s32, unk8: s32, block_sz: s32
    # block_sz2: s64, block_offsets: s64, data_start: u64, data_length: s64
    _FORMAT = "<iiiiqqQq" # Assumendo Little Endian
    _SIZE = struct.calcsize(_FORMAT)

    magic: int = 0         # s32
    unk4: int = 0          # s32
    unk8: int = 0          # s32
    block_sz: int = 0      # s32 -> questo è pfsChdr.block_sz nel C++ ? no, quello è block_sz2
                           # pkg.cpp: num_blocks = (int)(pfsChdr.data_length / pfsChdr.block_sz2);
                           # La struct in C++ è:
                           # struct PFSCHdr { s32 magic; s32 unk4; s32 unk8; s32 block_sz;
                           #                  s64 block_sz2; s64 block_offsets; u64 data_start; s64 data_length; };
                           # Quindi i primi 4 sono s32.
    block_sz2: int = 0     # s64 -> questo è pfsChdr.block_sz2
    block_offsets: int = 0 # s64 -> offset relativo all'inizio di PFSC per la tabella dei blocchi
    data_start: int = 0    # u64 -> offset relativo all'inizio di PFSC per l'inizio dei dati
    data_length: int = 0   # s64 -> lunghezza totale dei dati

    @classmethod
    def from_bytes(cls, data: bytes):
        return cls(*struct.unpack_from(cls._FORMAT, data, 0))


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


@dataclass
class Inode: # pfs.h
    # u16 Mode; u16 Nlink; u32 Flags; s64 Size; s64 SizeCompressed;
    # s64 Time1_sec; s64 Time2_sec; s64 Time3_sec; s64 Time4_sec;
    # u32 Time1_nsec; u32 Time2_nsec; u32 Time3_nsec; u32 Time4_nsec;
    # u32 Uid; u32 Gid; u64 Unk1; u64 Unk2;
    # u32 Blocks; u32 loc;
    # La dimensione totale della struct Inode in C++ è 0xA8 (168 bytes).
    # Calcoliamo la dimensione del formato attuale:
    _FORMAT_BASE = "<HH I qqqq qqqq II QQ II" # H=u16, I=u32, q=s64, Q=u64
    # Mode, Nlink, Flags, Size, SizeCompressed, T1s, T2s, T3s, T4s, T1n, T2n, T3n, T4n, Uid, Gid, Unk1, Unk2, Blocks, loc
    _SIZE_BASE = struct.calcsize(_FORMAT_BASE)
    _PADDING_SIZE = 0xA8 - _SIZE_BASE
    
    if _PADDING_SIZE < 0:
        raise Exception(f"Formato Inode troppo grande: {_SIZE_BASE} vs 0xA8")

    _FORMAT_FULL = _FORMAT_BASE + f"{_PADDING_SIZE}x" # 'x' per byte di padding
    _SIZE = 0xA8

    Mode: int = 0           # u16
    Nlink: int = 0          # u16
    Flags: InodeFlags = InodeFlags(0) # u32
    Size: int = 0           # s64
    SizeCompressed: int = 0 # s64
    Time1_sec: int = 0      # s64 (atime)
    Time2_sec: int = 0      # s64 (mtime)
    Time3_sec: int = 0      # s64 (ctime)
    Time4_sec: int = 0      # s64 (birthtime)
    Time1_nsec: int = 0     # u32
    Time2_nsec: int = 0     # u32
    Time3_nsec: int = 0     # u32
    Time4_nsec: int = 0     # u32
    Uid: int = 0            # u32
    Gid: int = 0            # u32
    Unk1: int = 0           # u64
    Unk2: int = 0           # u64
    Blocks: int = 0         # u32 (numero di blocchi usati dal file/dir)
    loc: int = 0            # u32 (indice del primo blocco dati in sectorMap)
    # padding per arrivare a 0xA8 bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < cls._SIZE:
            raise ValueError(f"Dati Inode insufficienti. Richiesti {cls._SIZE}, forniti {len(data)}")
        
        values = list(struct.unpack_from(cls._FORMAT_BASE, data, 0))
        values[2] = InodeFlags(values[2]) # Converte Flags in enum
        # Il padding viene ignorato da struct.unpack se non specificato nel formato restituito
        
        # Ricrea l'oggetto con i campi corretti, il padding è gestito da _FORMAT_FULL implicitamente
        # Ma se vogliamo essere espliciti per il costruttore:
        num_fields_in_format_base = len(cls._FORMAT_BASE.replace("<","").replace(">","").replace("x","").split())

        # Se _PADDING_SIZE > 0, significa che ci sono campi di padding alla fine
        # non catturati da _FORMAT_BASE. struct.unpack con _FORMAT_FULL li salterebbe.
        # L'approccio migliore è usare i campi nominati e ignorare il padding.
        
        return cls(*values[:num_fields_in_format_base])


    def get_file_type(self) -> 'PFSFileType': # Forward declaration per linter
        # Da pfs.h InodeMode (dir = 16384, file = 32768)
        # Questo è diverso da S_IFMT (0o170000) usato precedentemente.
        # Dobbiamo usare i valori da InodeMode.
        if self.Mode == 0: return PFSFileType.PFS_INVALID
        
        # Controlla se il bit 'dir' (16384 o 0x4000) è settato
        if (self.Mode & InodeMode.dir.value) == InodeMode.dir.value:
            return PFSFileType.PFS_DIR
        # Controlla se il bit 'file' (32768 o 0x8000) è settato
        # Nota: un file può anche avere altri bit settati (permessi)
        # Un controllo più robusto potrebbe essere if (self.Mode & (InodeMode.dir | InodeMode.file ...))
        # Ma solitamente o è dir o è file (o symlink, etc, non definiti qui)
        if (self.Mode & InodeMode.file.value) == InodeMode.file.value:
            return PFSFileType.PFS_FILE
        
        # Aggiungere gestione symlink se InodeMode includesse un valore per esso.
        # Altrimenti, è sconosciuto o non un file/dir standard.
        return PFSFileType.PFS_INVALID

class PFSFileType(IntEnum): # pfs.h (costanti definite) e pkg.cpp (uso)
    PFS_INVALID = 0     # Valore implicito se non corrisponde
    PFS_FILE = 2        # da #define PFS_FILE 2 in pfs.h
    PFS_DIR = 3         # da #define PFS_DIR 3 in pfs.h
    PFS_CURRENT_DIR = 4 # da #define PFS_CURRENT_DIR 4 in pfs.h
    PFS_PARENT_DIR = 5  # da #define PFS_PARENT_DIR 5 in pfs.h
    # PFS_SYMLINK non è definito con un #define in pfs.h, ma Dirent.type potrebbe usarlo.
    # La logica in pkg.cpp per Dirent.type usa valori simili a DT_REG, DT_DIR.
    # Dirent.type: 1 (file), 2 (dir) in pkg.cpp. Adattiamo PFSFileType.
    # Sembra che ci siano due sistemi di tipi: uno per Inode.Mode e uno per Dirent.type.
    # Per coerenza con pkg.cpp `Extract` (parte dirent):
    # table.type = dirent.type;
    # if (table.type == PFS_FILE || table.type == PFS_DIR)
    # E poi if (table.type == PFS_DIR) per creare directory.
    # I valori 2 e 3 sembrano corretti per dirent.type.
    # Per Inode.get_file_type(), si adatterà per restituire questi valori.


@dataclass
class Dirent: # pfs.h
    # s32 ino; s32 type; s32 namelen; s32 entsize; char name[512];
    _FORMAT_BASE = "<iiii" # ino, type, namelen, entsize (tutti s32 Little Endian)
    _NAME_BUFFER_SIZE = 512 # Definizione della costante
    _BASE_SIZE = struct.calcsize(_FORMAT_BASE) # Dimensione base senza nome
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
    type: PFSFileType # O il tipo più generico usato da dirent.type se diverso


# --- Implementazione Crypto Reale ---
class RealCrypto:
    def __init__(self, logger_func=print):
        self.logger = logger_func
        self.logger("Crypto Reale: Inizializzazione...")

        # Carica chiavi RSA (da `keys.h`)
        try:
            self._key_pkg_derived_key3 = self._construct_rsa_priv_key(
                n=int.from_bytes(PkgDerivedKey3Keyset.Modulus, 'big'),
                e=int.from_bytes(PkgDerivedKey3Keyset.PublicExponent, 'big'),
                d=int.from_bytes(PkgDerivedKey3Keyset.PrivateExponent, 'big'),
                p=int.from_bytes(PkgDerivedKey3Keyset.Prime1, 'big'),
                q=int.from_bytes(PkgDerivedKey3Keyset.Prime2, 'big'),
                u=int.from_bytes(PkgDerivedKey3Keyset.Coefficient, 'big') # u = q^-1 mod p
                # dP = d mod (p-1) -> Exponent1
                # dQ = d mod (q-1) -> Exponent2
                # PyCryptodome può calcolare dP, dQ, u se non forniti, ma è meglio fornirli se li abbiamo.
            )
            self._key_fake = self._construct_rsa_priv_key(
                n=int.from_bytes(FakeKeyset.Modulus, 'big'),
                e=int.from_bytes(FakeKeyset.PublicExponent, 'big'),
                d=int.from_bytes(FakeKeyset.PrivateExponent, 'big'),
                p=int.from_bytes(FakeKeyset.Prime1, 'big'),
                q=int.from_bytes(FakeKeyset.Prime2, 'big'),
                u=int.from_bytes(FakeKeyset.Coefficient, 'big')
            )
            # DebugRifKeyset non sembra usato nel flusso PKG, lo ometto per ora
            self.logger("Chiavi RSA caricate con successo.")
        except Exception as e:
            self.logger(f"ERRORE CRITICO nel caricamento chiavi RSA: {e}")
            raise

    def _bytes_to_int(self, b_val):
        return int.from_bytes(b_val, byteorder='big')

    def _construct_rsa_priv_key(self, n, e, d, p, q, u=None, dP=None, dQ=None):
        # PyCryptodome RSA.construct richiede una tupla: (n, e, d, p, q, u)
        # dove u è q^-1 mod p (coefficient).
        # Se dP, dQ sono noti, e sono d mod (p-1) e d mod (q-1), possono migliorare le prestazioni
        # ma non sono strettamente necessari se d è fornito.
        # Il C++ usa Exponent1 (dP) e Exponent2 (dQ).
        
        # Se p e q sono forniti, ignoriamo 'u' passato e lasciamo che PyCryptodome lo calcoli.
        # Questo dovrebbe risolvere l'errore "Invalid RSA component u with p".
        if p is not None and q is not None:
            # Potremmo anche passare dP e dQ se fossero forniti e validi,
            # ma per ora ci concentriamo sulla correzione di 'u'.
            # componenti = (n, e, d, p, q, dP, dQ) se dP/dQ fossero passati e usati.
            components = (n, e, d, p, q)
        elif p is None or q is None : # p o q (o entrambi) sono None
            components = (n, e, d)
        # Non dovrebbe esserci un altro caso se p e q sono sempre entrambi forniti o entrambi None
        # per le chiavi private complete.
        else: 
            # Fallback improbabile, ma per sicurezza.
            components = (n, e, d)
        
        key = RSA.construct(components)
        # Verifica (opzionale ma raccomandata)
        # if not key.has_private(): raise ValueError("Chiave RSA non privata.")
        # if key.n != n or key.e != e or key.d != d:
        #     raise ValueError("Componenti chiave RSA non corrispondono dopo costruzione.")
        return key

    def RSA2048Decrypt(self, output_key_buffer: bytearray, ciphertext: bytes, is_dk3: bool):
        self.logger(f"Crypto: RSA2048Decrypt chiamato. is_dk3={is_dk3}, input len={len(ciphertext)}")
        
        if len(ciphertext) != 256: # RSA-2048 opera su blocchi di 256 bytes
            self.logger(f"Errore RSA: ciphertext len non è 256 (è {len(ciphertext)})")
            output_key_buffer[:] = b'\0' * len(output_key_buffer)
            return

        key_to_use = self._key_pkg_derived_key3 if is_dk3 else self._key_fake
        
        # CryptoPP usa RSAES_PKCS1v15_Decryptor.
        # PyCryptodome: Cipher_PKCS1_v1_5.new(key)
        cipher_rsa = Cipher_PKCS1_v1_5.new(key_to_use)
        
        try:
            # Il decryptor PKCS#1 v1.5 in Crypto++ non prende un marcatore speciale per la sentinella.
            # PyCryptodome.decrypt aspetta un marcatore se non viene passato None.
            # Tuttavia, la documentazione di CryptoPP per RSAES_PKCS1v15_Decryptor::Decrypt
            # non menziona un marcatore di sentinella, quindi dovremmo passare None
            # o gestire l'eccezione se il padding è errato.
            #
            # Il C++ fa:
            # CryptoPP::DecodingResult result = rsaDecryptor.Decrypt(rng, ciphertext.data(), decrypted.size(), decrypted.data());
            # std::copy(decrypted.begin(), decrypted.begin() + dec_key.size(), dec_key.begin());
            #
            # `decrypted` è 256 bytes, `dec_key` è 32 bytes.
            # Questo significa che il payload decrittato è copiato nei primi 32 byte di dec_key.
            
            decrypted_data = cipher_rsa.decrypt(ciphertext, None) # Sentinel=None per raw PKCS#1 v1.5 unpadding

            # Il risultato della decrittazione PKCS#1v1.5 avrà una lunghezza variabile (max key_size - 11).
            # Il codice C++ copia i primi `dec_key.size()` (32) byte dal buffer `decrypted` (256).
            # Questo implica che il messaggio utile è all'inizio e ha almeno 32 byte.
            # È insolito che non ci sia un controllo sulla lunghezza di `decrypted_data`.
            
            bytes_to_copy = min(len(output_key_buffer), len(decrypted_data))
            output_key_buffer[:bytes_to_copy] = decrypted_data[:bytes_to_copy]
            if len(output_key_buffer) > bytes_to_copy:
                output_key_buffer[bytes_to_copy:] = b'\0' * (len(output_key_buffer) - bytes_to_copy)
            
            self.logger(f"Crypto: RSA Decrypt OK. Output (primi 8 byte): {output_key_buffer[:8].hex()}")

        except ValueError as ve: # Spesso indica errore di padding o decrittazione
            self.logger(f"Errore RSA Decrypt: {ve}. Ciphertext: {ciphertext[:16].hex()}...")
            output_key_buffer[:] = b'\0' * len(output_key_buffer) # Azzera in caso di errore
        except Exception as e:
            self.logger(f"Errore RSA Decrypt generico: {e}")
            output_key_buffer[:] = b'\0' * len(output_key_buffer)

    def ivKeyHASH256(self, cipher_input: bytes, ivkey_result_buffer: bytearray):
        # cipher_input è std::span<const CryptoPP::byte, 64>
        # ivkey_result è std::span<CryptoPP::byte, 32>
        if len(cipher_input) != 64:
             self.logger(f"Errore ivKeyHASH256: input len non è 64 (è {len(cipher_input)})")
             ivkey_result_buffer[:] = b'\0' * len(ivkey_result_buffer)
             return
        if len(ivkey_result_buffer) != 32:
             self.logger(f"Errore ivKeyHASH256: output buffer len non è 32 (è {len(ivkey_result_buffer)})")
             # Non azzerare, potrebbe essere un errore di chiamata

        h = SHA256.new()
        h.update(cipher_input)
        digest = h.digest() # 32 bytes
        ivkey_result_buffer[:] = digest
        self.logger(f"Crypto: ivKeyHASH256 OK. Output (primi 8 byte): {ivkey_result_buffer[:8].hex()}")

    def aesCbcCfb128Decrypt(self, ivkey: bytes, ciphertext: bytes, decrypted_buffer: bytearray):
        # ivkey: 32 bytes (16 per IV, 16 per Key)
        # ciphertext: 256 bytes
        # decrypted_buffer: 256 bytes
        if len(ivkey) != 32 or len(ciphertext) != 256 or len(decrypted_buffer) != 256:
            self.logger("Errore aesCbcCfb128Decrypt: dimensioni input/output non valide.")
            decrypted_buffer[:] = b'\0' * len(decrypted_buffer)
            return

        key = ivkey[16:32] # Secondi 16 byte
        iv = ivkey[0:16]   # Primi 16 byte

        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher_aes.decrypt(ciphertext)
        decrypted_buffer[:] = decrypted_data
        self.logger(f"Crypto: aesCbcCfb128Decrypt OK.")


    def aesCbcCfb128DecryptEntry(self, ivkey: bytes, ciphertext: bytes, decrypted_buffer: bytearray):
        # Simile alla precedente, ma ciphertext e decrypted_buffer possono avere lunghezze variabili (multipli di 16)
        if len(ivkey) != 32:
            self.logger("Errore aesCbcCfb128DecryptEntry: ivkey len non è 32.")
            decrypted_buffer[:] = b'\0' * len(decrypted_buffer)
            return
        if len(ciphertext) % AES.block_size != 0 or len(decrypted_buffer) != len(ciphertext):
            self.logger("Errore aesCbcCfb128DecryptEntry: dimensioni ciphertext/decrypted_buffer non valide o non multiple di block_size.")
            decrypted_buffer[:] = b'\0' * len(decrypted_buffer)
            return

        key = ivkey[16:32]
        iv = ivkey[0:16]

        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher_aes.decrypt(ciphertext)
        decrypted_buffer[:] = decrypted_data
        self.logger(f"Crypto: aesCbcCfb128DecryptEntry OK per {len(ciphertext)} bytes.")

    def PfsGenCryptoKey(self, ekpfs: bytes, seed: bytes, dataKey_buffer: bytearray, tweakKey_buffer: bytearray):
        # ekpfs: 32 bytes (dal C++, ma `PKG::ekpfsKey` è `std::array<u8, 32>`)
        # seed: 16 bytes
        # dataKey_buffer: 16 bytes
        # tweakKey_buffer: 16 bytes
        if len(ekpfs) != 32 or len(seed) != 16 or len(dataKey_buffer) != 16 or len(tweakKey_buffer) != 16:
            self.logger("Errore PfsGenCryptoKey: dimensioni input/output non valide.")
            dataKey_buffer[:] = b'\0'*16
            tweakKey_buffer[:] = b'\0'*16
            return

        # C++: CryptoPP::HMAC<CryptoPP::SHA256> hmac(ekpfs.data(), ekpfs.size());
        #      uint32_t index = 1;
        #      std::memcpy(d, &index, sizeof(uint32_t)); // d è 20 bytes
        #      std::memcpy(d + sizeof(uint32_t), seed.data(), seed.size());
        #      hmac.CalculateDigest(data_tweak_key.data(), d, d.size()); // d.size() è 20
        #      std::copy(data_tweak_key.begin(), data_tweak_key.begin() + 16, tweakKey.begin());
        #      std::copy(data_tweak_key.begin() + 16, data_tweak_key.begin() + 16 + 16, dataKey.begin());

        hmac_sha256 = HMAC.new(ekpfs, digestmod=SHA256)
        
        index_bytes = struct.pack("<I", 1) # Little endian u32 per index = 1
        d_payload = index_bytes + seed # Totale 4 + 16 = 20 bytes
        
        hmac_sha256.update(d_payload)
        data_tweak_key_digest = hmac_sha256.digest() # SHA256 produce 32 bytes
        
        tweakKey_buffer[:] = data_tweak_key_digest[0:16]
        dataKey_buffer[:] = data_tweak_key_digest[16:32]
        self.logger(f"Crypto: PfsGenCryptoKey OK. DataKey: {dataKey_buffer.hex()}, TweakKey: {tweakKey_buffer.hex()}")

    def _xts_mult(self, tweak_block: bytearray):
        # tweak_block è un bytearray di 16 byte, modificato in-place
        feedback = 0
        for k in range(16):
            tmp = (tweak_block[k] >> 7) & 1
            tweak_block[k] = ((tweak_block[k] << 1) + feedback) & 0xFF
            feedback = tmp
        if feedback != 0:
            tweak_block[0] ^= 0x87 # Polinomio GF(2^128) x^128 + x^7 + x^2 + x + 1

    def decryptPFS(self, dataKey: bytes, tweakKey: bytes, src_image_block: bytes, dst_image_buffer: bytearray, sector_num: int):
        # dataKey: 16 bytes
        # tweakKey: 16 bytes
        # src_image_block: 0x1000 bytes (un settore PFS criptato)
        # dst_image_buffer: 0x1000 bytes (per il settore PFS decrittato)
        # sector_num: numero del settore (per il calcolo del tweak iniziale)
        # La logica C++ itera su src_image (potenzialmente grande) in blocchi di 0x1000.
        # Questa funzione Python dovrebbe essere chiamata per ogni blocco di 0x1000.

        if len(dataKey)!=16 or len(tweakKey)!=16 or len(src_image_block)!=0x1000 or len(dst_image_buffer)!=0x1000:
            self.logger("Errore decryptPFS: dimensioni input/output non valide.")
            dst_image_buffer[:] = b'\0' * len(dst_image_buffer)
            return

        # AES-ECB per la chiave dati (per decrittare blocco xorato col tweak)
        cipher_data = AES.new(dataKey, AES.MODE_ECB)
        # AES-ECB per la chiave tweak (per criptare il numero di settore)
        cipher_tweak = AES.new(tweakKey, AES.MODE_ECB)

        # Calcola il tweak iniziale per questo settore
        # current_sector è sector_num
        # C++: std::memcpy(tweak.data(), &current_sector, sizeof(u64)); // il resto di tweak è 0
        tweak_initial_val = bytearray(16)
        tweak_initial_val[0:8] = struct.pack("<Q", sector_num) # Little Endian u64

        encrypted_tweak = bytearray(cipher_tweak.encrypt(bytes(tweak_initial_val))) # T_j per il primo blocco del settore

        for i in range(0, 0x1000, 16): # Itera sui 16-byte AES blocks all'interno del settore di 0x1000 byte
            ciphertext_sub_block = src_image_block[i : i+16]
            
            # XOR ciphertext con tweak crittato: C_i ^ T_j
            xor_buffer = bytes(a ^ b for a, b in zip(ciphertext_sub_block, encrypted_tweak))
            
            # Decritta con la chiave dati: D_K(C_i ^ T_j)
            decrypted_sub_block_intermediate = cipher_data.decrypt(xor_buffer)
            
            # XOR di nuovo con tweak crittato per ottenere plaintext: P_i = D_K(C_i ^ T_j) ^ T_j
            plaintext_sub_block = bytes(a ^ b for a, b in zip(decrypted_sub_block_intermediate, encrypted_tweak))
            
            dst_image_buffer[i : i+16] = plaintext_sub_block
            
            # Aggiorna il tweak per il prossimo blocco AES: T_{j+1} = T_j * alpha
            if i + 16 < 0x1000: # Non aggiornare dopo l'ultimo blocco
                self._xts_mult(encrypted_tweak)
        # self.logger(f"Crypto: decryptPFS OK per settore {sector_num}.")

    def decryptEFSM(self, trophyKey: bytes, NPcommID: bytes, efsmIv: bytes, ciphertext: bytes, decrypted_buffer: bytearray):
        # trophyKey: 16 bytes
        # NPcommID: 16 bytes (C++ usa std::array<u8,16> np_comm_id, ma legge 12 e padda a 0)
        # efsmIv: 16 bytes
        # ciphertext: lunghezza variabile
        # decrypted_buffer: stessa lunghezza di ciphertext
        
        if not (len(trophyKey) == 16 and len(NPcommID) == 16 and len(efsmIv) == 16 and \
                len(ciphertext) % AES.block_size == 0 and len(decrypted_buffer) == len(ciphertext)):
            self.logger("Errore decryptEFSM: dimensioni input/output non valide.")
            decrypted_buffer[:] = b'\0' * len(decrypted_buffer)
            return

        # Step 1: Encrypt NPcommID con trophyKey e IV di zeri per ottenere trpKey
        trophy_iv_zeros = b'\0' * 16
        cipher_step1 = AES.new(trophyKey, AES.MODE_CBC, trophy_iv_zeros)
        trpKey = cipher_step1.encrypt(NPcommID) # trpKey è 16 bytes

        # Step 2: Decrypt EFSM (ciphertext) con trpKey e efsmIv
        cipher_step2 = AES.new(trpKey, AES.MODE_CBC, efsmIv)
        decrypted_data = cipher_step2.decrypt(ciphertext)
        decrypted_buffer[:] = decrypted_data

        # removePadding è fatto esternamente nel codice C++
        self.logger(f"Crypto: decryptEFSM OK per {len(ciphertext)} bytes.")

# --- PKG Class (iniziata la revisione) ---
class PKG:
    def __init__(self, logger_func=print):
        self.logger = logger_func
        self.pkg_header: Optional[PKGHeader] = None
        self.pkg_file_size: int = 0 # Dimensione reale del file PKG su disco
        self.pkg_title_id: str = ""
        self.sfo_data: bytes = b""
        self.pkg_flags_str: str = ""

        self.extract_base_path: Optional[pathlib.Path] = None # Rinominato da extract_path per chiarezza
        self.pkg_path: Optional[pathlib.Path] = None
        
        self.crypto = RealCrypto(logger_func=self.logger)

        # Membri che erano prima array C++, ora bytearray Python per chiavi mutevoli
        self.dk3_ = bytearray(256) # Dimensione chiave RSA (anche se solo 32 byte sono usati dopo decritt.)
        self.ivKey = bytearray(32) # SHA256 digest size
        self.imgKey = bytearray(256) # Dimensione chiave AES (o dati criptati)
        self.ekpfsKey = bytearray(32) # ekpfsKey è 32 byte in pkg.h, non 16 come pensavo prima. CryptoPP lo tratta come 256bit.
                                    # Ma PfsGenCryptoKey lo usa come 256-bit HMAC key.

        self.dataKey = bytearray(16) # AES-128 XTS data key
        self.tweakKey = bytearray(16) # AES-128 XTS tweak key
        
        self.decNp = bytearray() # Verrà ridimensionato dinamicamente

        self.pfsc_offset_in_pfs_image: int = 0 # Offset di PFSC *all'interno* dell'immagine PFS decrittata
        self.sector_map: list[int] = [] # Lista di u64 (interi Python)
        self.iNodeBuf: list[Inode] = [] # Lista di oggetti Inode (potrebbe diventare un dict: inode_num -> Inode)
        self.fs_table: list[FSTableEntry] = []
        self.extract_paths: dict[int, pathlib.Path] = {} # inode_num -> path
        self.current_dir_pfs: Optional[pathlib.Path] = None # Per la logica di costruzione path PFS

    def _log(self, message):
        if self.logger:
            self.logger(message)

    def _read_pkg_header(self, f) -> bool:
        try:
            header_bytes = f.read(PKGHeader._TOTAL_PKGHEADER_SIZE)
            if len(header_bytes) < PKGHeader._TOTAL_PKGHEADER_SIZE:
                self._log("ERRORE: Lettura incompleta dell'header PKG.")
                return False
            self.pkg_header = PKGHeader.from_bytes(header_bytes)
            return True
        except Exception as e:
            self._log(f"ERRORE durante la lettura o parsing dell'header PKG: {e}")
            return False

    def _get_pkg_entry_name_by_type(self, entry_id: int) -> str:
        # Usa la mappa completa da pkg_type.cpp
        return PKG_ENTRY_ID_TO_NAME_FULL.get(entry_id, "")


    def open_pkg(self, filepath: pathlib.Path) -> tuple[bool, str]:
        self._log(f"Apertura PKG: {filepath}")
        try:
            with open(filepath, "rb") as f:
                self.pkg_file_size = f.seek(0, os.SEEK_END)
                f.seek(0)

                if not self._read_pkg_header(f):
                    return False, "Fallimento lettura header PKG."

                # Il magic number è Big Endian nel file. La classe PKGHeader lo gestisce.
                # if self.pkg_header.magic != PKG_MAGIC_BE:
                if self.pkg_header.magic not in [PKG_MAGIC_BE, PKG_MAGIC_LE_VARIANT]:
                    return False, f"Magic PKG non valido. Trovato: {self.pkg_header.magic:#x}, Attesi: {PKG_MAGIC_BE:#x} o {PKG_MAGIC_LE_VARIANT:#x}"
                
                self.pkg_flags_str = ""
                flags_list = []
                # Il C++ itera su PKG::flagNames, che è un array di coppie (PKGContentFlag, string_view)
                # Dobbiamo iterare sulla nostra mappa PKG_FLAG_NAMES_MAP
                for flag_enum_val, flag_name_str in PKG_FLAG_NAMES_MAP.items():
                    # PKG::isFlagSet(pkgheader.pkg_content_flags, flag.first)
                    # flag.first è l'enum PKGContentFlag. Il suo valore è l'intero.
                    if (self.pkg_header.pkg_content_flags & flag_enum_val.value) == flag_enum_val.value:
                        flags_list.append(flag_name_str)
                self.pkg_flags_str = ", ".join(flags_list)
                self._log(f"Flags PKG (da pkg_content_flags): {self.pkg_flags_str}")

                # Title ID (da pkg.cpp)
                # file.Seek(0x47); file.Read(pkgTitleID);
                # pkg_content_id è un campo char[0x24] nell'header.
                # L'header è a 0x0. pkg_content_id è all'offset 0x30 (dec) = 0x1E (hex) dall'inizio di pkg_header struct.
                # No, pkg_content_id è a offset 0x30 nel FILE PKG.
                # L'offset di pkg_content_id all'interno della struct PKGHeader in C++ è 0x30.
                # Quindi `pkgheader.pkg_content_id` contiene già i dati.
                # `file.Seek(0x47)` è un offset assoluto dal file.
                # `pkgTitleID` è char[9]. `0x47` è 71. `0x30` è 48. `71 - 48 = 23`.
                # Quindi legge da `pkg_content_id[23]` per 9 byte.
                # No, il commento dice: "// Find title id it is part of pkg_content_id starting at offset 0x40"
                # "file.Seek(0x47); // skip first 7 characters of content_id"
                # Questo è confuso. Se content_id inizia a 0x40 (dec 64) e skippo 7, arrivo a 0x47.
                # pkg_content_id è a 0x48 (0x30) nell'header letto.
                # Se pkg_content_id (36 byte) è a offset 0x30 (dec 48) nel file,
                # e si fa f.seek(0x47) (dec 71), significa che si salta
                # 71 - 48 = 23 byte dall'inizio di pkg_content_id.
                # Questo non corrisponde a "skip first 7 characters".
                #
                # Rivediamo pkg.h: `u8 pkg_content_id[0x24]; // offset 0x30`
                # Quindi `pkg_content_id` è a `0x30` dall'inizio dell'header.
                # `file.Read(pkgheader)` legge tutto l'header.
                # `file.Seek(0x47)`: offset assoluto nel file.
                #
                # Se l'header è stato letto, il file pointer è dopo l'header.
                # La logica C++ sembra ri-utilizzare `file` per seekare *all'interno* dei dati già letti in `pkgheader`
                # o fa un seek assoluto e rilegge.
                #
                # Assumiamo che pkgTitleID sia parte di pkg_header.pkg_content_id:
                # pkg_content_id (36 bytes)
                # Il C++ salta 7 caratteri di content_id. Quindi legge da content_id[7] per 9 byte.
                title_id_bytes = self.pkg_header.pkg_content_id[7 : 7+9]
                self.pkg_title_id = title_id_bytes.decode('ascii', errors='ignore').strip('\0')
                self._log(f"Title ID: {self.pkg_title_id}")

                offset_table = self.pkg_header.pkg_table_entry_offset
                n_files = self.pkg_header.pkg_table_entry_count
                self._log(f"Tabella entries: offset={offset_table:#x}, count={n_files}")

                f.seek(offset_table) # Seek assoluto alla tabella delle entry

                for i in range(n_files):
                    entry_bytes = f.read(PKGEntry._SIZE)
                    if len(entry_bytes) < PKGEntry._SIZE:
                        return False, f"Lettura incompleta per PKG entry {i}"
                    
                    entry = PKGEntry.from_bytes(entry_bytes)
                    entry.name = self._get_pkg_entry_name_by_type(entry.id)
                    
                    if entry.name == "param.sfo":
                        current_pos_table = f.tell()
                        f.seek(entry.offset) # Offset assoluto del param.sfo nel PKG
                        self.sfo_data = f.read(entry.size)
                        self._log(f"Trovato param.sfo: size={len(self.sfo_data)}")
                        f.seek(current_pos_table)
            
            self.pkg_path = filepath
            return True, "PKG aperto con successo."

        except FileNotFoundError:
            return False, "File PKG non trovato."
        except Exception as e:
            self._log(f"Errore durante l'apertura del PKG: {e}")
            import traceback
            self._log(traceback.format_exc())
            return False, f"Errore: {e}"

    def get_title_id(self) -> str:
        """Restituisce il Title ID del PKG."""
        return self.pkg_title_id

    def extract(self, filepath: pathlib.Path, extract_base_path_gui: pathlib.Path) -> tuple[bool, str]:
        self.pkg_path = filepath
        # La logica C++ per `extract_path` è un po' complessa, coinvolge il Title ID.
        # `extract_path` nel C++ è il path base + TitleID (a meno che non sia un DLC/Update).
        # `extract_base_path_gui` è il path scelto dall'utente.
        # Costruiamo self.extract_base_path (il vero output path) qui.
        
        self._log(f"Inizio estrazione da: {filepath}")
        self._log(f"Directory di output base (GUI): {extract_base_path_gui}")

        try:
            with open(filepath, "rb") as f:
                if not self.pkg_header: # Se non è stato chiamato open_pkg prima
                    if not self._read_pkg_header(f):
                        return False, "Fallimento lettura header PKG in extract."
                    # Estrai title ID se non già fatto
                    if not self.pkg_title_id:
                        title_id_bytes = self.pkg_header.pkg_content_id[7 : 7+9]
                        self.pkg_title_id = title_id_bytes.decode('ascii', errors='ignore').strip('\0')

                if self.pkg_header.magic not in [PKG_MAGIC_BE, PKG_MAGIC_LE_VARIANT]:
                    return False, f"Magic PKG non valido in extract. Trovato: {self.pkg_header.magic:#x}, Attesi: {PKG_MAGIC_BE:#x} o {PKG_MAGIC_LE_VARIANT:#x}"

                # Determina il path di estrazione finale (extract_path della classe C++)
                # Questa logica è usata per `extractPaths[ndinode_counter]` in C++
                # e per il path base delle entry di sce_sys.
                # Qui la applichiamo per definire self.extract_base_path
                title_id_str = self.get_title_id()
                if not title_id_str: # Fallback se il title id non è valido
                    title_id_str = filepath.stem # Usa il nome del file PKG senza estensione

                # Logica C++ per path DLC/Update
                is_update_or_dlc = False
                pkg_path_str_upper = str(self.pkg_path).upper()
                # Heuristica per DLC/Update basata sul nome del file PKG
                if "-UPDATE" in pkg_path_str_upper or \
                   title_id_str.startswith("EP") or title_id_str.startswith("IP") or \
                   "_PATCH" in pkg_path_str_upper : # Aggiunto per patch
                    is_update_or_dlc = True
                
                # Se il nome della cartella di output scelta dall'utente finisce con -UPDATE
                if extract_base_path_gui.name.upper().endswith("-UPDATE"):
                    is_update_or_dlc = True
                
                # Se la cartella genitore dell'output scelto non è già il TitleID E non è un update/dlc
                if extract_base_path_gui.name != title_id_str and \
                   extract_base_path_gui.parent.name != title_id_str and \
                   not is_update_or_dlc:
                    self.extract_base_path = extract_base_path_gui / title_id_str
                else:
                    self.extract_base_path = extract_base_path_gui
                
                self._log(f"Directory di estrazione effettiva: {self.extract_base_path}")
                self.extract_base_path.mkdir(parents=True, exist_ok=True)

                # Controlli di dimensione (da pkg.cpp)
                current_file_size = f.seek(0, os.SEEK_END) # Dimensione reale del file
                if self.pkg_header.pkg_size > current_file_size: # pkg_size nell'header
                    # Potrebbe essere un file troncato o l'header è sbagliato.
                    # Il C++ non sembra fare questo controllo con pkgSize (che è current_file_size)
                    # ma con pkg_header.pkg_size > pkgSize (che è current_file_size).
                    # Quindi se la dimensione nell'header è maggiore di quella reale, è un problema.
                    self._log(f"Attenzione: pkg_header.pkg_size ({self.pkg_header.pkg_size}) > dimensione file reale ({current_file_size})")
                    # Non un errore fatale qui, ma un avviso. Il C++ lo considera un errore.
                    # return False, "Dimensione file PKG differente da quella nell'header."
                
                # Questo controllo è più stringente:
                # pkg_content_offset e pkg_content_size sono u64_be nell'header.
                if (self.pkg_header.pkg_content_size + self.pkg_header.pkg_content_offset) > self.pkg_header.pkg_size:
                    # Questo si riferisce ai valori DENTRO l'header.
                    return False, "Dimensione contenuto (da header) più grande della dimensione PKG (da header)."


                # --- Variabili Crypto (dal codice C++) ---
                # Le dimensioni sono specificate in pkg.h per i membri della classe PKG
                # self.dk3_ (256), self.ivKey (32), self.imgKey (256), self.ekpfsKey (32)
                # Queste sono già inizializzate come bytearray della dimensione corretta.
                # Le variabili locali del C++ come concatenated_ivkey_dk3 (64), seed_digest (32),
                # digest1 (7x32), key1 (7x256), imgkeydata (256) saranno gestite al momento.
                
                # --- Estrazione Metadati (sce_sys) ---
                offset_table = self.pkg_header.pkg_table_entry_offset # u32_be
                n_files = self.pkg_header.pkg_table_entry_count       # u32_be
                f.seek(offset_table)

                sce_sys_path = self.extract_base_path / "sce_sys"
                sce_sys_path.mkdir(parents=True, exist_ok=True)
                self._log(f"Creata directory: {sce_sys_path}")

                # Leggi tutte le entry prima di processarle, per evitare seek avanti e indietro confusionari
                pkg_entries_data = []
                for _ in range(n_files):
                    entry_bytes = f.read(PKGEntry._SIZE)
                    if len(entry_bytes) < PKGEntry._SIZE:
                        return False, "Lettura incompleta della tabella delle entry PKG."
                    entry = PKGEntry.from_bytes(entry_bytes)
                    entry.name = self._get_pkg_entry_name_by_type(entry.id)
                    pkg_entries_data.append({'obj': entry, 'bytes': entry_bytes})


                for entry_item in pkg_entries_data:
                    entry = entry_item['obj']
                    original_entry_bytes = entry_item['bytes'] # Questi sono i 32 byte dell'entry letti dal file

                    output_filename = entry.name if entry.name else str(entry.id)
                    output_filepath_sce_sys = sce_sys_path / output_filename
                    
                    self._log(f"  Processing PKG Entry ID {entry.id:#06x} ('{output_filename}'), Offset: {entry.offset:#x}, Size: {entry.size}")

                    # Logica di gestione delle entry specifiche (crypto)
                    # Nota: dk3_, ivKey, imgKey, ekpfsKey sono membri di self.
                    if entry.id == 0x1: # DIGESTS
                        self._log("    Trovato DIGESTS (saltato).")
                    elif entry.id == 0x10: # ENTRY_KEYS
                        self._log("    Trovato ENTRY_KEYS.")
                        f.seek(entry.offset)
                        seed_digest = f.read(32) # std::array<u8, 32>
                        digest1_list = [f.read(32) for _ in range(7)] # std::array<std::array<u8, 32>, 7>
                        key1_list = [f.read(256) for _ in range(7)]   # std::array<std::array<u8, 256>, 7>
                        
                        # PKG::crypto.RSA2048Decrypt(dk3_, key1[3], true);
                        self.crypto.RSA2048Decrypt(self.dk3_, key1_list[3], True) # is_dk3 = True
                        self._log(f"    DK3 (decrittato): {self.dk3_[:8].hex() if self.dk3_ else 'None'}...")
                    elif entry.id == 0x20: # IMAGE_KEY
                        self._log("    Trovato IMAGE_KEY.")
                        f.seek(entry.offset)
                        imgkeydata = f.read(256) # std::array<u8, 256>
                        
                        # Costruzione concatenated_ivkey_dk3
                        # std::memcpy(concatenated_ivkey_dk3.data(), &entry, sizeof(entry));
                        # std::memcpy(concatenated_ivkey_dk3.data() + sizeof(entry), dk3_.data(), sizeof(dk3_));
                        # sizeof(entry) è PKGEntry._SIZE (32 bytes). dk3_ è 256 bytes, ma solo 32 usati?
                        # Il commento C++ dice "The Concatenated iv + dk3 imagekey for HASH256"
                        # e ivKey è 32 bytes. dk3_ è il *risultato* di RSA, quindi 32 bytes (non 256).
                        # Sembra che dk3_ in C++ `std::array<u8, 32> dk3_;` sia di 32 byte.
                        # Il parametro di RSA2048Decrypt è `std::span<CryptoPP::byte, 32> dec_key`
                        # Quindi self.dk3_ dovrebbe essere usato come buffer di 32 byte.
                        # Ma la variabile membro è 256. Questo è un punto da chiarire.
                        # Assumiamo che i primi 32 byte di self.dk3_ (quelli decrittati) siano usati.
                        
                        # L'array `concatenated_ivkey_dk3` è `std::array<u8, 64>`
                        # Questo implica sizeof(entry) == 32 e sizeof(dk3_) == 32
                        if self.dk3_ is None or len(self.dk3_) < 32:
                             return False, "dk3_ non inizializzato o troppo corto per concatenazione."

                        concat_buffer_for_hash = bytearray(64)
                        concat_buffer_for_hash[:PKGEntry._SIZE] = original_entry_bytes
                        concat_buffer_for_hash[PKGEntry._SIZE : PKGEntry._SIZE + 32] = self.dk3_[:32] # Usa i primi 32 byte
                        
                        self.crypto.ivKeyHASH256(bytes(concat_buffer_for_hash), self.ivKey)
                        self._log(f"    ivKey (da hash): {self.ivKey[:8].hex()}...")
                        
                        # self.imgKey è 256. imgkeydata è 256.
                        self.crypto.aesCbcCfb128Decrypt(self.ivKey, imgkeydata, self.imgKey)
                        self._log(f"    imgKey (decrittato): {self.imgKey[:8].hex()}...")
                        
                        # self.ekpfsKey è 32. self.imgKey è 256.
                        self.crypto.RSA2048Decrypt(self.ekpfsKey, self.imgKey, False) # is_dk3 = False (usa FakeKeyset)
                        self._log(f"    ekpfsKey (decrittato): {self.ekpfsKey[:8].hex()}...")
                    elif entry.id == 0x80: # GENERAL_DIGESTS
                        self._log("    Trovato GENERAL_DIGESTS (saltato).")
                    
                    # Estrazione generica dei file da sce_sys
                    if entry.size > 0:
                        f.seek(entry.offset)
                        data_to_write = f.read(entry.size)
                        
                        if entry.id in [0x0400, 0x0401, 0x0402, 0x0403]: # nptitle, npbind, ecc.
                            self._log(f"    Decrittografia NPDRM per {output_filename} (ID: {entry.id:#06x})")
                            
                            # Prepara self.decNp (era decNp in C++)
                            if len(self.decNp) < entry.size:
                                self.decNp = bytearray(entry.size)
                            
                            # Costruisci concatenated_ivkey_dk3_ per questa entry (locale al C++)
                            # std::array<u8, 64> concatenated_ivkey_dk3_;
                            temp_concat_np = bytearray(64)
                            temp_concat_np[:PKGEntry._SIZE] = original_entry_bytes
                            # temp_concat_np[PKGEntry._SIZE : PKGEntry._SIZE + 32] = self.dk3_[:32]
                            if self.dk3_ is None or len(self.dk3_) < 32:
                                return False, "dk3_ non inizializzato o troppo corto per NPDRM."
                            temp_concat_np[PKGEntry._SIZE : PKGEntry._SIZE + 32] = self.dk3_[:32]

                            # Il C++ riusa self.ivKey per il risultato di ivKeyHASH256.
                            # Ma è più sicuro usare un buffer temporaneo se ivKey è usato altrove.
                            # Qui, il C++ sovrascrive self.ivKey. Facciamo lo stesso.
                            self.crypto.ivKeyHASH256(bytes(temp_concat_np), self.ivKey)
                            
                            # Passa data_to_write (cipherNp) e self.decNp (per output)
                            self.crypto.aesCbcCfb128DecryptEntry(self.ivKey, data_to_write, self.decNp)
                            
                            data_to_write = self.decNp[:entry.size] # Usa la porzione rilevante di decNp
                            self._log(f"    {output_filename} (decrittato NPDRM).")

                        with open(output_filepath_sce_sys, "wb") as outfile:
                            outfile.write(data_to_write)
                        self._log(f"    Scritto: {output_filepath_sce_sys} ({len(data_to_write)} bytes)")

                # --- Processamento PFS ---
                self._log("Inizio processamento PFS...")
                # Leggi il seed PFS
                seed_pfs_offset = self.pkg_header.pfs_image_offset + 0x370 # pfs_image_offset è u64_be
                f.seek(seed_pfs_offset)
                seed_bytes = f.read(16) # std::array<u8, 16>
                self._log(f"Seed PFS letto (offset {seed_pfs_offset:#x}): {seed_bytes.hex()}")

                # Genera dataKey e tweakKey
                # self.ekpfsKey (32), seed_bytes (16), self.dataKey (16), self.tweakKey (16)
                self.crypto.PfsGenCryptoKey(self.ekpfsKey, seed_bytes, self.dataKey, self.tweakKey)
                self._log(f"DataKey PFS: {self.dataKey.hex()}")
                self._log(f"TweakKey PFS: {self.tweakKey.hex()}")

                # Logica di lettura e decrittografia PFS Image
                # const u32 length = pkgheader.pfs_cache_size * 0x2; nel C++ è usato per dimensionare pfsc e pfs_decrypted
                # pfs_cache_size è u32_be.
                # Questo 'length' è la dimensione dei dati *dopo* la decompressione di PFSC.
                # Prima dobbiamo decrittare l'intera pfs_image.
                
                pfs_image_ondisk_offset = self.pkg_header.pfs_image_offset # u64_be
                pfs_image_ondisk_size = self.pkg_header.pfs_image_size   # u64_be
                
                if pfs_image_ondisk_size == 0:
                    self._log("Immagine PFS ha dimensione 0, salto processamento PFS.")
                    # Potrebbe essere un PKG senza PFS (es. solo metadati sce_sys)
                    return True, "Estrazione SCE_SYS completata, PFS non presente o vuoto."

                self._log(f"Dimensione immagine PFS (su disco, crittata): {pfs_image_ondisk_size:#x} bytes a offset {pfs_image_ondisk_offset:#x}")
                
                pfs_decrypted_image_buffer = bytearray(pfs_image_ondisk_size)
                
                # Decrittografa l'immagine PFS in blocchi di 0x1000
                # Il C++ in `PKG::Extract` ha una sezione:
                # std::vector<u8> pfs_encrypted(length); file.Seek(pkgheader.pfs_image_offset); file.Read(pfs_encrypted);
                # PKG::crypto.decryptPFS(dataKey, tweakKey, pfs_encrypted, pfs_decrypted, 0);
                # Questo è strano perché `length` è `pfs_cache_size * 2`, non `pfs_image_size`.
                # E `decryptPFS` è chiamato con sector = 0.
                #
                # Invece, la logica in `PKG::ExtractFiles` per i singoli file PFS è più dettagliata:
                # Legge blocchi di 0x11000 dal PKG, li decritta, poi estrae il settore.
                #
                # Per la decrittazione iniziale dell'intera PFS Image in PKG::Extract:
                # Se `length` si riferisce a una porzione dell'immagine PFS che contiene PFSC,
                # e non all'intera immagine, allora il C++ sta decrittando solo una parte.
                # Tuttavia, `pfsc_offset = GetPFSCOffset(pfs_decrypted);` suggerisce che
                # `pfs_decrypted` dovrebbe contenere abbastanza dati da trovare PFSC_MAGIC.
                # `GetPFSCOffset` cerca da 0x20000 in poi.
                #
                # Scenario 1: Il C++ decritta solo `length` byte da `pfs_image_offset`.
                # Scenario 2: Il C++ decritta l'intera `pfs_image_size` (o `pfs_signed_size`).
                #
                # La riga `file.Read(pfs_encrypted);` senza specificare la dimensione usa la dimensione del vettore `pfs_encrypted` (cioè `length`).
                # Quindi, il C++ legge e decritta `pfs_cache_size * 2` byte dall'offset `pfs_image_offset`.
                # Questo deve essere sufficiente per contenere PFSC.
                
                bytes_to_decrypt_for_pfsc_discovery = self.pkg_header.pfs_cache_size * 2 # u32_be per cache_size
                if bytes_to_decrypt_for_pfsc_discovery == 0 and pfs_image_ondisk_size > 0:
                    # Se cache_size è 0 ma pfs_image_size no, forse dobbiamo decrittare tutta l'immagine?
                    # O è un errore? Il C++ dice `if (length !=0)` per questo blocco.
                    # Se `pfs_cache_size` è 0, `length` è 0, e il blocco if non viene eseguito.
                    self._log("pfs_cache_size è 0, la logica C++ salterebbe la decrittazione PFS iniziale.")
                    # Questo sembra implicare che non ci sia PFS o che sia gestito diversamente.
                    # Però poi il codice procede a cercare inode e dirent. Contraddittorio.
                    # Assumiamo per ora che se pfs_image_size > 0, dobbiamo tentare.
                    # Se pfs_cache_size è 0, usiamo pfs_image_size come fallback per la decrittazione iniziale?
                    # O forse il PKG è strutturato in modo che pfs_cache_size non sia rilevante qui.
                    # Data la logica C++, se length è 0, non si fa nulla qui per `pfsc` vector.
                    # Questo significa che `num_blocks` rimarrebbe 0.
                    # Poi il loop `for (int i = 0; i < num_blocks; i++)` non verrebbe eseguito.
                    # E `ExtractFiles` non sarebbe chiamato.
                    # Quindi, se `pfs_cache_size` è 0, il PFS non viene estratto.
                    if pfs_image_ondisk_size > 0:
                         self._log("AVVISO: pfs_cache_size è 0 ma pfs_image_size > 0. Comportamento C++ implica nessun parsing PFS.")
                    # Comunque, se siamo qui, significa che vogliamo procedere.
                    # Se `bytes_to_decrypt_for_pfsc_discovery` è 0, GetPFSCOffset fallirà.
                    # Forse in alcuni PKG, l'immagine PFS non è compressa/strutturata con PFSC?
                    # Per ora, se `bytes_to_decrypt_for_pfsc_discovery` è 0 ma `pfs_image_ondisk_size` > 0,
                    # proviamo a decrittare una porzione fissa o l'intera immagine per trovare PFSC.
                    # Oppure, se `pfs_cache_size` è 0, è un segnale che non c'è un PFS standard da parsare così.
                    # Il codice C++ ha `if (length !=0)` che circonda tutta la logica di lettura di pfsc e sectorMap.
                    # Quindi, se `pkgheader.pfs_cache_size` è 0, `length` è 0, e tutto il parsing PFS viene saltato.
                    self._log("pfs_cache_size è 0. Secondo la logica C++, il parsing PFS verrebbe saltato.")
                    # Se il tuo PKG ha pfs_cache_size=0 ma ha un PFS, questa parte fallirà come nel C++.
                    # Potrebbe non essere un errore, ma un tipo di PKG senza PFS.
                    if pfs_image_ondisk_size > 0 and bytes_to_decrypt_for_pfsc_discovery == 0:
                        # Fallback speculativo: proviamo a decrittare l'intera immagine PFS
                        # se cache_size è 0 ma image_size no. Questo devia dal C++.
                        # Manteniamoci fedeli al C++: se length è 0, num_blocks sarà 0.
                        self._log("PKG::Extract -> length (pfs_cache_size*2) è 0. Nessun blocco PFS da processare secondo la logica C++.")
                        pass # num_blocks rimarrà 0


                pfsc_content_view = b"" # Inizializzazione
                pfs_data_for_pfsc_search = bytearray(bytes_to_decrypt_for_pfsc_discovery)
                current_decrypted_offset = 0
                num_pfs_blocks_to_initially_decrypt = (bytes_to_decrypt_for_pfsc_discovery + 0xFFF) // 0x1000

                if bytes_to_decrypt_for_pfsc_discovery > 0:
                    self._log(f"Decrittografia iniziale di {bytes_to_decrypt_for_pfsc_discovery} byte da PFS image (offset {pfs_image_ondisk_offset:#x}) per trovare PFSC.")
                    f.seek(pfs_image_ondisk_offset)
                    # Leggi i dati grezzi dal file PKG
                    raw_pfs_data_chunk = f.read(bytes_to_decrypt_for_pfsc_discovery)
                    if len(raw_pfs_data_chunk) < bytes_to_decrypt_for_pfsc_discovery:
                        return False, "Lettura incompleta della porzione iniziale dell'immagine PFS."

                    for i in range(num_pfs_blocks_to_initially_decrypt):
                        block_start = i * 0x1000
                        block_end = block_start + 0x1000
                        
                        src_block = raw_pfs_data_chunk[block_start:block_end]
                        if not src_block: break # Fine dei dati

                        # Assicurati che src_block sia di 0x1000 byte (padda se necessario per l'ultimo)
                        if len(src_block) < 0x1000:
                            src_block = src_block + b'\0' * (0x1000 - len(src_block))
                        
                        dst_buffer_for_block = pfs_data_for_pfsc_search[block_start:block_end] # E' una view!
                        self.crypto.decryptPFS(self.dataKey, self.tweakKey, src_block, dst_buffer_for_block, i) # sector = i

                    self._log("Porzione iniziale immagine PFS (stub) decrittata.")
                
                # Trova PFSC nell'immagine PFS (parzialmente) decrittata
                self.pfsc_offset_in_pfs_image = get_pfsc_offset(pfs_data_for_pfsc_search)
                if self.pfsc_offset_in_pfs_image == -1:
                    # Se `bytes_to_decrypt_for_pfsc_discovery` era 0, questo fallirà come previsto.
                    if bytes_to_decrypt_for_pfsc_discovery > 0:
                         return False, "Magic PFSC non trovato nell'immagine PFS decrittata."
                    else:
                         self._log("Magic PFSC non trovato, ma atteso perché pfs_cache_size era 0.")
                         # Non si procede oltre con il parsing PFS se num_blocks rimane 0.
                else:
                    self._log(f"PFSC trovato a offset {self.pfsc_offset_in_pfs_image:#x} (relativo a PFS decrittata)")


                # Estrai PFSC header e sector map (logica da `if (length != 0)`)
                num_data_blocks_in_pfsc = 0 # Corrisponde a num_blocks in C++
                
                if bytes_to_decrypt_for_pfsc_discovery > 0 and self.pfsc_offset_in_pfs_image != -1:
                    # pfsc_data_view è la porzione di pfs_data_for_pfsc_search che inizia da PFSC_MAGIC
                    # La dimensione di questa view è `bytes_to_decrypt_for_pfsc_discovery - self.pfsc_offset_in_pfs_image`
                    pfsc_content_view = memoryview(pfs_data_for_pfsc_search)[self.pfsc_offset_in_pfs_image:]
                    
                    if len(pfsc_content_view) < PFSCHdrPFS._SIZE:
                        return False, "Dati PFSC insufficienti per l'header PFSCHdr."

                    pfs_chdr = PFSCHdrPFS.from_bytes(pfsc_content_view[:PFSCHdrPFS._SIZE])
                    self._log(f"PFSCHdr (da pfsc): magic={pfs_chdr.magic:#x}, data_len={pfs_chdr.data_length}, block_offsets_rel={pfs_chdr.block_offsets:#x}, block_sz2={pfs_chdr.block_sz2:#x}")

                    if pfs_chdr.magic != PFSC_MAGIC:
                        # Questo è un controllo dopo aver già trovato PFSC_MAGIC con GetPFSCOffset.
                        # Quindi dovrebbe sempre corrispondere. Se non lo fa, c'è un problema.
                        self._log(f"AVVISO: Magic in PFSCHdr ({pfs_chdr.magic:#x}) non corrisponde a PFSC_MAGIC atteso ({PFSC_MAGIC:#x})")
                        # Non un errore fatale, il C++ non lo tratta come tale qui.

                    if pfs_chdr.block_sz2 > 0: # block_sz2 è il "block size" dei dati logici (spesso 0x10000)
                        num_data_blocks_in_pfsc = int(pfs_chdr.data_length // pfs_chdr.block_sz2)
                    
                    self.sector_map = []
                    # pfs_chdr.block_offsets è l'offset (da inizio PFSC) della mappa dei settori.
                    # Ogni entry della mappa è u64.
                    # num_data_blocks_in_pfsc + 1 entries.
                    sector_map_start_in_pfsc_content = pfs_chdr.block_offsets
                    for i in range(num_data_blocks_in_pfsc + 1): 
                        map_entry_offset = sector_map_start_in_pfsc_content + i * 8 # 8 bytes per u64
                        if map_entry_offset + 8 > len(pfsc_content_view):
                            self._log(f"AVVISO: Lettura sector_map oltre pfsc_content_view per entry {i}")
                            break 
                        self.sector_map.append(struct.unpack_from("<Q", pfsc_content_view, map_entry_offset)[0])
                    self._log(f"Mappa settori PFSC letta ({len(self.sector_map)} entries). Primo offset dati: {self.sector_map[0] if self.sector_map else 'N/A'}")
                else:
                    # Questo blocco viene eseguito se length == 0 (cioè pfs_cache_size == 0) o se PFSC non è stato trovato
                    self._log("Salto lettura sector map perché length è 0 o PFSC non trovato.")
                    # num_data_blocks_in_pfsc rimarrà 0.

                # --- Parsing Inodes e Dirents ---
                self.iNodeBuf = []
                self.fs_table = []
                self.extract_paths = {} 
                self.current_dir_pfs = self.extract_base_path # Path base per file/dir PFS

                ndinode_total_count = 0 # Numero totale di inodes (da leggere dal blocco 0)
                # `decompressed_block_buffer` è per un singolo blocco logico PFSC (tipicamente 0x10000)
                decompressed_block_buffer = bytearray(0x10000) 
                occupied_inode_blocks = 0 # Inizializzazione
                
                # Variabili per la logica di `uroot_reached` e `dinode_reached`
                ndinode_counter_processed = 0 # Corrisponde a ndinode_counter nel C++
                dinode_block_reached = False # Flag per indicare che stiamo processando blocchi dirent
                uroot_block_reached = False # Flag per la logica "flat_path_table"

                # Inizializza il path per la radice del PFS. L'inode della radice non è ancora noto.
                # extractPaths[<inode_num_root>] = self.current_dir_pfs
                # Questa parte è complicata dal C++ che usa ndinode_counter per extractPaths.
                # Sarà gestita dinamicamente.
                
                self._log(f"Inizio parsing Inodes e Dirents da {num_data_blocks_in_pfsc} blocchi di dati PFSC...")
                for i_block_pfsc in range(num_data_blocks_in_pfsc): # num_data_blocks_in_pfsc è `num_blocks`
                    if i_block_pfsc + 1 >= len(self.sector_map):
                        self._log(f"AVVISO: Indice blocco PFSC {i_block_pfsc} fuori range per sector_map (len: {len(self.sector_map)})")
                        break
                    
                    # Offset del settore DENTRO i dati di pfsc_content_view
                    # Questi sono gli offset dei dati compressi/non compressi.
                    sector_offset_in_pfsc_data = self.sector_map[i_block_pfsc] 
                    sector_data_size = self.sector_map[i_block_pfsc+1] - sector_offset_in_pfsc_data
                    
                    # self._log(f"  Blocco dati PFSC {i_block_pfsc}: offset in pfsc_content_view={sector_offset_in_pfsc_data:#x}, size={sector_data_size:#x}")

                    if sector_offset_in_pfsc_data + sector_data_size > len(pfsc_content_view):
                        self._log(f"AVVISO: Blocco {i_block_pfsc} sfora pfsc_content_view. Tentativo di correzione.")
                        actual_size_readable = len(pfsc_content_view) - sector_offset_in_pfsc_data
                        if actual_size_readable <=0: continue
                        sector_data_size = min(sector_data_size, actual_size_readable)
                        if sector_data_size <=0: continue
                    
                    # Estrai il blocco di dati (compresso o meno)
                    # `compressedData` nel C++ è un buffer temporaneo per questo.
                    current_sector_data_bytes = bytes(pfsc_content_view[sector_offset_in_pfsc_data : sector_offset_in_pfsc_data + sector_data_size])
                    
                    if sector_data_size == 0x10000: # Non compresso
                        decompressed_block_buffer[:] = current_sector_data_bytes
                    elif 0 < sector_data_size < 0x10000: # Compresso
                        # `DecompressPFSC` nel C++ prende std::span<char>
                        decompressed_block_buffer[:] = decompress_pfsc(current_sector_data_bytes, 0x10000)
                    elif sector_data_size == 0:
                        # self._log(f"    Blocco {i_block_pfsc} ha dimensione 0, saltato.")
                        continue
                    else: # Errore?
                        self._log(f"    Blocco {i_block_pfsc} ha dimensione inattesa {sector_data_size:#x}, saltato.")
                        continue

                    # Blocco 0: leggi ndinode_total_count
                    if i_block_pfsc == 0:
                        ndinode_total_count = struct.unpack_from("<I", decompressed_block_buffer, 0x30)[0]
                        self._log(f"Numero totale di Inodes (ndinode) dal blocco 0: {ndinode_total_count}")
                        if ndinode_total_count == 0:
                            self._log("ndinode_total_count è 0, PFS potrebbe essere vuoto o la struttura è diversa.")
                            break # Niente da fare se non ci sono inode
                    
                    # Calcola quanti blocchi sono occupati dagli inode
                    # 0xA8 è sizeof(Inode)
                    occupied_inode_blocks = (ndinode_total_count * Inode._SIZE) // 0x10000
                    if ((ndinode_total_count * Inode._SIZE) % 0x10000) != 0:
                        occupied_inode_blocks += 1
                    
                    # Parsing Inodes (se siamo nei blocchi degli inode)
                    # C++: if (i >= 1 && i <= occupied_blocks)
                    # i in C++ è l'indice del blocco, 0-based.
                    # Quindi il blocco 0 contiene il superblocco (con ndinode).
                    # I blocchi da 1 a `occupied_inode_blocks` contengono gli inode.
                    if 1 <= i_block_pfsc <= occupied_inode_blocks:
                        # self._log(f"    Parsing Inodes dal blocco PFSC {i_block_pfsc}...")
                        for inode_offset_in_block in range(0, 0x10000, Inode._SIZE):
                            if len(self.iNodeBuf) >= ndinode_total_count: break # Letti tutti gli inode
                            
                            inode_data_segment = decompressed_block_buffer[inode_offset_in_block : inode_offset_in_block + Inode._SIZE]
                            if len(inode_data_segment) < Inode._SIZE: break # Dati insufficienti

                            inode = Inode.from_bytes(inode_data_segment)
                            if inode.Mode == 0: # Inode non valido, fine degli inode in questo blocco
                                # self._log(f"      Inode con Mode=0 a offset {inode_offset_in_block}, fine per questo blocco.")
                                break
                            self.iNodeBuf.append(inode)
                            # self._log(f"      Aggiunto Inode: Index={len(self.iNodeBuf)-1}, Mode={inode.Mode:#x}, Size={inode.Size}, Blocks={inode.Blocks}, Loc={inode.loc}")
                        if len(self.iNodeBuf) >= ndinode_total_count:
                             self._log(f"    Tutti gli {ndinode_total_count} Inodes sono stati letti.")
                    
                    # Parsing Dirents (se siamo nei blocchi dopo quelli degli inode)
                    # O anche nel blocco 0 se ndinode_total_count è piccolo e i dirent iniziano lì.
                    # La logica C++ per uroot_reached e dinode_reached è per identificare il tipo di blocco.

                    # Gestione "flat_path_table" per uroot_reached (setta path radice iniziale)
                    # Questo blocco in C++ è complesso e usa ndinode_counter in modo particolare per extractPaths.
                    # Cerca di determinare il path base per l'inode `ndinode_counter`.
                    # `ndinode_counter` sembra essere usato come un indice di inode per `extractPaths`.
                    # Questo suggerisce che `ndinode_counter` potrebbe rappresentare il numero di inode della root.
                    # Tentativo di replica:
                    try:
                        flat_path_table_str = decompressed_block_buffer[0x10 : 0x10+15].decode('ascii')
                        if flat_path_table_str == "flat_path_table":
                            uroot_block_reached = True
                            self._log(f"    Blocco PFSC {i_block_pfsc} contiene 'flat_path_table'. uroot_reached=True.")
                    except UnicodeDecodeError:
                        pass # Non è una stringa ascii, quindi non è flat_path_table

                    if uroot_block_reached:
                        current_offset_in_uroot_block = 0
                        # `ent_size` deve essere letto dal dirent stesso. Inizializzalo a un valore >0 per il primo loop.
                        current_dirent_size_in_uroot = Dirent._BASE_SIZE # Valore minimo
                        while current_offset_in_uroot_block < 0x10000:
                            dirent_data_uroot = decompressed_block_buffer[current_offset_in_uroot_block:]
                            if len(dirent_data_uroot) < Dirent._BASE_SIZE: break
                            
                            dirent_uroot = Dirent.from_bytes(dirent_data_uroot)
                            current_dirent_size_in_uroot = dirent_uroot.entsize
                            if current_dirent_size_in_uroot == 0: break # Evita loop infinito

                            if dirent_uroot.ino != 0:
                                ndinode_counter_processed += 1 # Questo è l'inode della directory root
                            else: # dirent.ino == 0 (fine delle entry uroot o entry speciale)
                                # Qui il C++ imposta extractPaths[ndinode_counter_processed]
                                # ndinode_counter_processed ora dovrebbe essere l'inode della directory root del PFS.
                                root_inode_for_path = ndinode_counter_processed # Salva l'inode della root
                                
                                # La logica del path base (come in PKG::Extract sopra)
                                temp_current_dir_pfs = self.extract_base_path # Inizia dal path di estrazione globale
                                
                                # Se il C++ ha `extract_path.parent_path().filename() != title_id`
                                # E `!fmt::UTF(extract_path.u8string()).data.ends_with("-UPDATE")`
                                # Qui `extract_path` C++ è `self.extract_base_path` Python.
                                # `title_id` è `self.get_title_id()`.
                                parent_of_base = self.extract_base_path.parent
                                base_name = self.extract_base_path.name
                                title_id_str = self.get_title_id()

                                # Riadatta la logica da `extract` per `self.extract_base_path`
                                # Qui, `self.current_dir_pfs` è il path base di estrazione per il PFS.
                                # Non c'è bisogno di aggiungere title_id di nuovo se extract_base_path lo include già.
                                
                                self.extract_paths[root_inode_for_path] = self.extract_base_path # Path per la root del PFS
                                self.current_dir_pfs = self.extract_base_path # Imposta current_dir alla root
                                self._log(f"    Path radice PFS (uroot, inode ~{root_inode_for_path}) impostato a: {self.current_dir_pfs}")
                                self.current_dir_pfs.mkdir(parents=True, exist_ok=True)
                                
                                uroot_block_reached = False # Resetta il flag
                                break # Esci dal loop uroot
                            current_offset_in_uroot_block += current_dirent_size_in_uroot
                    
                    # Controlla se è un blocco Dirent standard (con "." e "..")
                    # pkg.cpp: const char dot = decompressedData[0x10]; const std::string_view dotdot(&decompressedData[0x28], 2);
                    # if (dot == '.' && dotdot == "..") { dinode_reached = true; }
                    # Questi offset sono relativi all'inizio del blocco decompresso.
                    # La struct Dirent ha: ino (4), type (4), namelen (4), entsize (4) -> totale 16 bytes (0x10)
                    # Quindi a 0x10 inizia il `name` del primo dirent.
                    # Se il primo dirent è ".", il suo nome (1 byte) è a 0x10.
                    # Il secondo dirent (se entsize del primo è es. 0x18) inizierebbe a 0x18.
                    # I suoi campi base (ino, type, namelen, entsize) occupano 16 byte (fino a 0x28).
                    # Il suo nome inizierebbe a 0x28. Se è "..", allora ok.
                    # Dobbiamo leggere i primi due dirent per verificare.
                    
                    if not dinode_block_reached and i_block_pfsc >= occupied_inode_blocks: # Controlla solo dopo i blocchi inode
                        # Leggi i primi due dirent per vedere se sono "." e ".."
                        first_dirent_data = decompressed_block_buffer[0:]
                        if len(first_dirent_data) >= Dirent._BASE_SIZE:
                            first_d = Dirent.from_bytes(first_dirent_data)
                            if first_d.name == "." and first_d.entsize > 0 and len(first_dirent_data) >= first_d.entsize + Dirent._BASE_SIZE:
                                second_dirent_data = decompressed_block_buffer[first_d.entsize:]
                                second_d = Dirent.from_bytes(second_dirent_data)
                                if second_d.name == "..":
                                    dinode_block_reached = True
                                    self._log(f"    Blocco PFSC {i_block_pfsc} è un blocco Dirent standard (trovati '.' e '..').")
                                    # Se è il primo blocco dirent e uroot non ha impostato la root,
                                    # l'inode di "." è l'inode della root.
                                    if first_d.ino not in self.extract_paths:
                                        self.extract_paths[first_d.ino] = self.extract_base_path
                                        self.current_dir_pfs = self.extract_base_path
                                        self._log(f"    Path radice PFS (dirent '.', inode {first_d.ino}) impostato a: {self.current_dir_pfs}")
                                        self.current_dir_pfs.mkdir(parents=True, exist_ok=True)


                    # Parsing Dirent effettivo
                    if dinode_block_reached: # Solo se siamo in un blocco dirent identificato
                        current_offset_in_dirent_block = 0
                        current_dirent_size = Dirent._BASE_SIZE # Valore minimo
                        
                        while current_offset_in_dirent_block < 0x10000:
                            dirent_data = decompressed_block_buffer[current_offset_in_dirent_block:]
                            if len(dirent_data) < Dirent._BASE_SIZE: break

                            dirent = Dirent.from_bytes(dirent_data)
                            current_dirent_size = dirent.entsize
                            if current_dirent_size == 0: break # Evita loop infinito
                            
                            # self._log(f"      Dirent: Ino={dirent.ino}, Name='{dirent.name}', Type={dirent.type}, Entsize={current_dirent_size}")

                            if dirent.ino == 0: # Fine delle entry in questo blocco
                                break

                            # Aggiungi a fs_table
                            # Il tipo in Dirent C++ è s32, ma usato come enum implicito.
                            # PFS_FILE = 2, PFS_DIR = 3. Ma Dirent.type in FreeBSD è DT_REG=8, DT_DIR=4.
                            # Il codice C++ fa: table.type = dirent.type;
                            # Poi if (table.type == PFS_FILE || table.type == PFS_DIR)
                            # Questo implica che i valori in dirent.type sono quelli di PFS_FILE/PFS_DIR.
                            # Ma poi fa if (table.type == PFS_DIR) // Create dirs.
                            # Se dirent.type usa i valori standard DT_*, allora bisogna convertirli.
                            # La mia classe Dirent.get_pfs_file_type() converte DT_* in PFSFileType.
                            # Ma il C++ assegna dirent.type direttamente.
                            # Questo è un punto di confusione. Per ora, assumo che dirent.type sia già
                            # nei valori di PFSFileType usati in C++ (2 per file, 3 per dir, 4 per ".").
                            
                            # Da pkg.cpp:
                            # table.type = dirent.type;
                            # if (table.type == PFS_CURRENT_DIR) { current_dir = extractPaths[table.inode]; }
                            # extractPaths[table.inode] = current_dir / std::filesystem::path(table.name);
                            # if (table.type == PFS_FILE || table.type == PFS_DIR) {
                            #   if (table.type == PFS_DIR) { std::filesystem::create_directory(extractPaths[table.inode]); }
                            #   ndinode_counter++;
                            # }
                            
                            # Mappiamo dirent.type ai valori PFSFileType
                            mapped_type = PFSFileType.PFS_INVALID
                            if dirent.type == PFSFileType.PFS_FILE.value : mapped_type = PFSFileType.PFS_FILE
                            elif dirent.type == PFSFileType.PFS_DIR.value : mapped_type = PFSFileType.PFS_DIR
                            elif dirent.type == PFSFileType.PFS_CURRENT_DIR.value : mapped_type = PFSFileType.PFS_CURRENT_DIR
                            elif dirent.type == PFSFileType.PFS_PARENT_DIR.value : mapped_type = PFSFileType.PFS_PARENT_DIR
                            # Aggiungere altri se necessario

                            self.fs_table.append(FSTableEntry(dirent.name, dirent.ino, mapped_type))
                            
                            current_fs_table_entry = self.fs_table[-1]

                            if current_fs_table_entry.type == PFSFileType.PFS_CURRENT_DIR:
                                # Se l'inode di "." non è ancora in extract_paths, è un errore logico
                                # o la root non è stata ancora impostata correttamente da uroot/primo blocco dirent.
                                if current_fs_table_entry.inode in self.extract_paths:
                                    self.current_dir_pfs = self.extract_paths[current_fs_table_entry.inode]
                                    # self._log(f"        Cambiato current_dir_pfs a: {self.current_dir_pfs} (da inode {current_fs_table_entry.inode} '.')")
                                else:
                                    # Questo potrebbe essere il primo "." incontrato se uroot non c'era
                                    if not self.extract_paths: # Non è stata impostata nessuna root
                                        self.extract_paths[current_fs_table_entry.inode] = self.extract_base_path
                                        self.current_dir_pfs = self.extract_base_path
                                        self._log(f"        Path radice PFS (dirent '.', inode {current_fs_table_entry.inode}) impostato tardivamente a: {self.current_dir_pfs}")
                                        self.current_dir_pfs.mkdir(parents=True, exist_ok=True)
                                    else:
                                        self._log(f"        AVVISO: Inode {current_fs_table_entry.inode} (per '.') non trovato in extract_paths. current_dir_pfs non aggiornato.")
                            
                            # Calcola e memorizza il path per l'inode corrente
                            # Non farlo per ".." (non ha un suo path univoco in questo contesto)
                            # E "." ha già il suo path (quello di current_dir_pfs)
                            if current_fs_table_entry.name != ".." :
                                if self.current_dir_pfs: # Assicurati che current_dir_pfs sia impostato
                                    self.extract_paths[current_fs_table_entry.inode] = self.current_dir_pfs / current_fs_table_entry.name
                                else: # current_dir_pfs non impostato, probabile errore di logica root
                                    self._log(f"        AVVISO: current_dir_pfs non impostato. Impossibile calcolare path per {current_fs_table_entry.name} (inode {current_fs_table_entry.inode}).")
                                    # Fallback speculativo se è una dir o file nella root non ancora definita
                                    if not self.extract_paths:
                                        self.extract_paths[current_fs_table_entry.inode] = self.extract_base_path / current_fs_table_entry.name


                            # Crea directory e aggiorna contatore
                            if current_fs_table_entry.type == PFSFileType.PFS_DIR:
                                if current_fs_table_entry.name != "." and current_fs_table_entry.name != "..":
                                    if current_fs_table_entry.inode in self.extract_paths:
                                        dir_to_create = self.extract_paths[current_fs_table_entry.inode]
                                        # self._log(f"        Creazione directory: {dir_to_create}")
                                        dir_to_create.mkdir(parents=True, exist_ok=True)
                                    else:
                                         self._log(f"        AVVISO: Path non trovato per directory {current_fs_table_entry.name} (inode {current_fs_table_entry.inode}). Non creata.")
                            
                            if current_fs_table_entry.type == PFSFileType.PFS_FILE or \
                               (current_fs_table_entry.type == PFSFileType.PFS_DIR and \
                                current_fs_table_entry.name != "." and current_fs_table_entry.name != ".."):
                                ndinode_counter_processed +=1

                            current_offset_in_dirent_block += current_dirent_size
                        
                        # Condizione di uscita dal loop principale dei blocchi PFSC
                        # C++: if ((ndinode_counter + 1) == ndinode) end_reached = true;
                        # ndinode_counter è il numero di file/dir processati.
                        # ndinode è il numero totale di inode.
                        # "+1" è perché la radice stessa è contata?
                        if (ndinode_counter_processed + 1) >= ndinode_total_count and ndinode_total_count > 0 :
                            self._log(f"    Raggiunto il conteggio atteso di inode processati ({ndinode_counter_processed} di {ndinode_total_count}). Interruzione parsing blocchi PFSC.")
                            break # Esci dal loop for i_block_pfsc
                
                # --- Fine loop for i_block_pfsc ---
                if (ndinode_counter_processed + 1) < ndinode_total_count and num_data_blocks_in_pfsc > 0 and ndinode_total_count > 0:
                    self._log(f"AVVISO: Finito di processare blocchi PFSC, ma conteggio inode ({ndinode_counter_processed}) < atteso ({ndinode_total_count-1}).")

                self._log(f"Letti {len(self.iNodeBuf)} Inodes e {len(self.fs_table)} voci Dirent.")
                if not self.iNodeBuf and ndinode_total_count > 0 :
                     return False, "Errore: ndinode > 0 ma iNodeBuf è vuoto. Controllare logica di parsing inode."
                if not self.fs_table and ndinode_total_count > 0 and num_data_blocks_in_pfsc > occupied_inode_blocks :
                     self._log(f"Attenzione: fs_table vuota nonostante ci fossero blocchi dirent previsti.")


                # Verifica finale e preparazione per ExtractFiles
                # La logica di indicizzazione di iNodeBuf in C++ PKG::ExtractFiles:
                # int inode_number = fsTable[index].inode;
                # int sector_loc = iNodeBuf[inode_number].loc;
                # Questo implica che `inode_number` (che è `dirent.ino`) è un indice 0-based per `iNodeBuf`.
                # Questo è molto improbabile se `dirent.ino` sono numeri di inode reali (1, 2, 50, ...).
                #
                # Se iNodeBuf è una lista riempita con push_back, gli inode sono in ordine di apparizione,
                # non indicizzati dal loro numero.
                # Soluzioni:
                # 1. Modificare iNodeBuf in un dizionario {inode_num: InodeObject} durante il parsing.
                #    Questo richiede di sapere il numero dell'inode mentre lo si legge, il che non è banale.
                # 2. Creare la mappa dopo aver letto tutti gli inode e dirent.
                #    Possiamo iterare fs_table, prendere dirent.ino, e trovare l'inode corrispondente in iNodeBuf.
                #    Come? L'inode stesso non contiene il suo numero.
                #
                # L'unica spiegazione per il codice C++ è che `fsTable[index].inode` *non* sia il vero numero
                # di inode, ma un indice già mappato per `iNodeBuf`.
                # Ma `fsTable.inode = dirent.ino;` contraddice questo.
                #
                # Assumiamo che `iNodeBuf` in C++ sia effettivamente una `std::map<int, Inode>` o che
                # `ndinode` sia il numero massimo e `iNodeBuf` sia un `std::vector` preallocato e riempito
                # agli indici corretti (es. `iNodeBuf[dirent.ino] = node;`).
                # Dato `iNodeBuf.push_back(node);`, è una lista.
                #
                # Per Python, convertiamo iNodeBuf in un dizionario.
                # La chiave sarà l'indice (0 a N-1) nella lista iNodeBuf.
                # E `fsTable[idx].inode` dovrà essere trasformato in questo indice.
                # Questo è ancora problematico.
                #
                # Alternativa più sicura:
                # Quando si leggono gli inode, se ndinode_total_count è N, e leggiamo M <= N inode validi,
                # iNodeBuf avrà M elementi.
                # dirent.ino è un numero (es. 1-based).
                # Dobbiamo mappare dirent.ino all'Inode corretto.
                # Se gli inode sono compatti da 1 a N, allora iNodeBuf[dirent.ino - 1] è l'inode.
                # Questa è un'ipotesi forte.
                #
                # Il codice C++ fa `int ndinode_counter = 0;` e lo incrementa per ogni dirent PFS_FILE o PFS_DIR.
                # E in `uroot_reached`, `extractPaths[ndinode_counter]` è usato.
                # Se `fsTable[index].inode` si riferisse a questo `ndinode_counter` sequenziale,
                # allora `iNodeBuf[fsTable[index].inode]` avrebbe senso.
                # Ma `table.inode = dirent.ino;` usa il `dirent.ino` grezzo.
                #
                # È probabile che ci sia un'incomprensione da parte mia o una semplificazione nel codice C++ fornito
                # riguardo a come `iNodeBuf` è indicizzato.
                #
                # Per ora, `ExtractFiles` in Python dovrà cercare l'inode in `iNodeBuf`
                # basandosi su qualche proprietà (se `dirent.ino` non è un indice diretto).
                # Oppure, se assumiamo che `dirent.ino` sia 1-based e compatto, allora
                # `iNodeBuf[dirent.ino - 1]` è l'approccio.

                return True, "Estrazione metadati e parsing PFS completati."

        except FileNotFoundError:
            return False, f"File PKG non trovato: {filepath}"
        except Exception as e:
            self._log(f"Errore durante l'estrazione: {e}")
            import traceback
            self._log(traceback.format_exc())
            return False, f"Errore estrazione: {e}"

    def extract_pfs_files(self) -> tuple[bool, str]:
        """Estrae i file effettivi basandosi su fs_table e iNodeBuf.
           Corrisponde a PKG::ExtractFiles iterato su tutti gli elementi di fsTable.
        """
        self._log("Inizio estrazione file da PFS...")
        if not self.fs_table:
            msg = "fs_table è vuota. Nessun file da estrarre da PFS."
            self._log(msg)
            return True, msg # Non un errore, solo niente da fare.
        if not self.iNodeBuf:
            # Questo è un errore se fs_table non è vuota e ci si aspetta degli inode.
             msg = "iNodeBuf è vuoto ma fs_table non lo è. Impossibile estrarre file."
             self._log(msg)
             return False, msg
        if not self.extract_paths:
            msg = "extract_paths è vuoto. Impossibile determinare dove estrarre i file."
            self._log(msg)
            return False, msg

        num_extracted_files = 0
        total_files_to_extract = sum(1 for item in self.fs_table if item.type == PFSFileType.PFS_FILE)
        self._log(f"Trovati {total_files_to_extract} file da estrarre da PFS.")

        # Tentativo di creare una mappa inode_number -> Inode object
        # Se gli inode sono numerati in modo non compatto, iNodeBuf (lista) non è indicizzabile direttamente.
        # Per ora, manteniamo l'ipotesi che dirent.ino possa essere usato per accedere a iNodeBuf,
        # magari con un offset (es. -1 se 1-based e compatto). Questa è la parte più incerta.
        # Il C++ fa `iNodeBuf[inode_number]` dove `inode_number = fsTable[index].inode`.
        # Se `fsTable[index].inode` è, per esempio, 50, e `iNodeBuf` ha solo 10 elementi, crash.
        # Quindi, `inode_number` in C++ deve essere un indice valido per il vector `iNodeBuf`.
        # Questo significa che o `dirent.ino` sono già 0-based e compatti per gli inode attivi,
        # o c'è una mappatura non mostrata.
        #
        # Soluzione pragmatica per Python: se `iNodeBuf` è una lista di inode nell'ordine in cui sono stati letti,
        # e `dirent.ino` è il numero *assoluto* dell'inode (1-based, potenzialmente sparso),
        # allora dobbiamo trovare un modo per mappare `dirent.ino` a un `Inode` in `iNodeBuf`.
        # Se non c'è un campo `inode_number` dentro `Inode` stesso, questa mappa è difficile da costruire
        # a meno che non si assuma che `iNodeBuf` sia stato riempito in modo che `iNodeBuf[dirent.ino-X]`
        # sia l'inode corretto (dove X è un offset, es. 1, e gli inode sono compatti).
        #
        # Per la traduzione, proviamo l'ipotesi più semplice del C++: fs_table[idx].inode è un indice 0-based per iNodeBuf.
        # Questo è molto probabile che sia sbagliato se fs_table[idx].inode è un numero di inode reale.
        #
        # Rettifica: il codice C++ `iNodeBuf.push_back(node);` significa che iNodeBuf è una lista densa.
        # Se `fsTable[idx].inode` è, diciamo, 5 (come numero di inode), e il 5° inode valido letto
        # è `iNodeBuf[4]`, allora il C++ dovrebbe fare `iNodeBuf[map_inode_num_to_idx(fsTable[idx].inode)]`.
        # A meno che, `fsTable[idx].inode` sia già l'indice.
        #
        # Rivediamo il ciclo di parsing dirent in C++:
        # `table.inode = dirent.ino;`
        # `ndinode_counter++;`
        # Se `extractPaths` e `fsTable` usano `ndinode_counter` come "numero di inode normalizzato",
        # e `iNodeBuf` è indicizzato da questo, allora `dirent.ino` deve essere ignorato per l'indicizzazione.
        # Ma poi `PKG::ExtractFiles` usa `fsTable[index].inode` (che è `dirent.ino`) per `iNodeBuf`.
        # C'è una forte incoerenza o una semplificazione nel codice fornito.
        #
        # Adottiamo un approccio robusto: costruire un dizionario `inode_map = {inode_number_reale: Inode}`.
        # Questo però richiede che Inode abbia un campo per il suo numero, o che lo inferiamo.
        #
        # L'approccio più fedele al C++ (assumendo che funzioni lì) è usare `fs_entry.inode`
        # come indice, sperando sia corretto o che l'errore diventi evidente.
        # Se `iNodeBuf` è 0-indexed e `fs_entry.inode` è 1-based e compatto, allora `iNodeBuf[fs_entry.inode - 1]`
        # è la via.

        try:
            with open(self.pkg_path, "rb") as pkg_file: # Riapri il PKG per leggere i dati dei file
                for fs_entry in self.fs_table:
                    if fs_entry.type == PFSFileType.PFS_FILE:
                        inode_num_abs = fs_entry.inode # Numero inode (da dirent.ino)
                        
                        # Tentativo di accedere a iNodeBuf.
                        # Se inode_num_abs è 1-based e gli inode in iNodeBuf sono compatti da 1 in poi:
                        inode_obj_idx = inode_num_abs - 1 
                        if not (0 <= inode_obj_idx < len(self.iNodeBuf)):
                            self._log(f"  ERRORE: Indice inode {inode_obj_idx} (da inode num {inode_num_abs}) fuori dai limiti per iNodeBuf (len {len(self.iNodeBuf)}). File: '{fs_entry.name}'. Salto.")
                            continue
                        
                        actual_inode_object = self.iNodeBuf[inode_obj_idx]
                        if actual_inode_object.Mode == 0: # Inode non valido/non utilizzato
                            self._log(f"  AVVISO: Inode {inode_num_abs} (indice {inode_obj_idx}) è Inode non valido (Mode=0). File: '{fs_entry.name}'. Salto.")
                            continue

                        file_path_to_extract = self.extract_paths.get(inode_num_abs)
                        if not file_path_to_extract:
                            self._log(f"  ERRORE: Path di estrazione non trovato per inode {inode_num_abs} ('{fs_entry.name}'). Salto.")
                            continue
                        
                        self._log(f"  Estrazione file: '{fs_entry.name}' (inode {inode_num_abs}) a '{file_path_to_extract}'")
                        self._log(f"    Inode info: Size={actual_inode_object.Size}, Blocks={actual_inode_object.Blocks}, Loc={actual_inode_object.loc} (indice in sectorMap)")

                        if actual_inode_object.Size == 0:
                            open(file_path_to_extract, "wb").close()
                            self._log(f"    File vuoto creato: {file_path_to_extract}")
                            num_extracted_files += 1
                            continue
                        
                        # sector_loc è l'indice del primo blocco del file nella sectorMap
                        first_sector_map_idx = actual_inode_object.loc
                        num_data_blocks_for_file = actual_inode_object.Blocks

                        if not (0 <= first_sector_map_idx < len(self.sector_map) and
                                first_sector_map_idx + num_data_blocks_for_file < len(self.sector_map)):
                            self._log(f"    ERRORE: loc Inode ({first_sector_map_idx}) o numero blocchi ({num_data_blocks_for_file}) non validi per sector_map (len {len(self.sector_map)}). File: '{fs_entry.name}'. Salto.")
                            continue
                        
                        with open(file_path_to_extract, "wb") as out_file_pfs:
                            bytes_written_total = 0
                            decompressed_block_data_pfs = bytearray(0x10000) # Per blocco logico (decompresso)
                            
                            # Buffer per leggere dal PKG e per i dati decrittati (come in C++)
                            # u64 pfsc_buf_size = 0x11000;
                            # std::vector<u8> pfsc(pfsc_buf_size);
                            # std::vector<u8> pfs_decrypted(pfsc_buf_size);
                            # Questi buffer sono usati per leggere un chunk dal file PKG che contiene il settore XTS,
                            # decrittarlo, e poi estrarre il settore dati (compresso o meno).
                            read_chunk_from_pkg = bytearray(0x11000)
                            decrypted_chunk_from_pkg = bytearray(0x11000)

                            for j_block_in_file in range(num_data_blocks_for_file):
                                current_sector_map_idx = first_sector_map_idx + j_block_in_file
                                
                                # sectorOffset è l'offset del blocco dati DENTRO l'immagine PFSC
                                # sectorSize è la dimensione di questo blocco dati (compresso o meno)
                                sector_offset_in_pfsc_img = self.sector_map[current_sector_map_idx]
                                sector_data_actual_size = self.sector_map[current_sector_map_idx + 1] - sector_offset_in_pfsc_img
                                
                                # fileOffset è l'offset assoluto nel file PKG di questo blocco dati
                                # C++: (pkgheader.pfs_image_offset + pfsc_offset + sectorOffset);
                                # pfsc_offset qui è pfsc_offset_in_pfs_image (offset di PFSC dentro PFS decrittata)
                                absolute_sector_data_offset_in_pkg = self.pkg_header.pfs_image_offset + \
                                                                   self.pfsc_offset_in_pfs_image + \
                                                                   sector_offset_in_pfsc_img
                                
                                # currentSector1 è il numero del blocco XTS (0x1000 bytes)
                                # C++: (pfsc_offset + sectorOffset) / 0x1000;
                                # Questo è l'indice del blocco XTS *all'interno dell'immagine PFS*
                                xts_block_num_in_pfs_image = (self.pfsc_offset_in_pfs_image + sector_offset_in_pfsc_img) // 0x1000
                                
                                # previousData calcola quanto del blocco XTS precede i dati del nostro settore
                                # C++: int sectorOffsetMask = (sectorOffset + pfsc_offset) & 0xFFFFF000; (equiv. to //0x1000 * 0x1000)
                                #      int previousData = (sectorOffset + pfsc_offset) - sectorOffsetMask;
                                # Questo è l'offset dei dati del settore *all'interno* del suo blocco XTS di appartenenza.
                                offset_of_sector_in_its_xts_block = (self.pfsc_offset_in_pfs_image + sector_offset_in_pfsc_img) % 0x1000
                                
                                # Seek nel PKG per leggere il chunk che contiene il blocco XTS
                                # C++: pkgFile.Seek(fileOffset - previousData); pkgFile.Read(pfsc); // pfsc è 0x11000
                                # fileOffset - previousData = (pfs_img_off + pfsc_off + sect_off) - ((pfsc_off + sect_off) % 0x1000)
                                # Questo è l'inizio del blocco XTS che contiene l'inizio dei dati del nostro settore.
                                read_start_pos_in_pkg = self.pkg_header.pfs_image_offset + (xts_block_num_in_pfs_image * 0x1000)

                                pkg_file.seek(read_start_pos_in_pkg)
                                bytes_actually_read = pkg_file.readinto(read_chunk_from_pkg)

                                # Verifica se abbiamo letto abbastanza per coprire il nostro settore dati
                                needed_len_in_chunk = offset_of_sector_in_its_xts_block + sector_data_actual_size
                                if bytes_actually_read < needed_len_in_chunk:
                                    self._log(f"    AVVISO: Lettura PKG incompleta per blocco {j_block_in_file} di '{fs_entry.name}'. "
                                              f"Letti {bytes_actually_read}, necessari {needed_len_in_chunk}. Salto file.")
                                    # Dovrebbe interrompere l'estrazione di QUESTO file.
                                    # Usiamo una variabile per uscire dal loop esterno del file.
                                    raise IOError("Lettura PKG incompleta per settore file PFS.")


                                # Decritta il chunk letto (0x11000 bytes)
                                # decryptPFS in C++ è chiamato con `pfsc` (read_chunk_from_pkg) come src,
                                # `pfs_decrypted` (decrypted_chunk_from_pkg) come dst, e `currentSector1` (xts_block_num_in_pfs_image).
                                # La funzione `decryptPFS` decritterà `len(src_image_block)` bytes.
                                # Qui, src_image_block è read_chunk_from_pkg (0x11000).
                                self.crypto.decryptPFS(self.dataKey, self.tweakKey, 
                                                       read_chunk_from_pkg, # src
                                                       decrypted_chunk_from_pkg, # dst
                                                       xts_block_num_in_pfs_image) # numero del primo settore XTS nel chunk

                                # Estrai i dati del settore (compressi o meno) dal chunk decrittato
                                # C++: std::memcpy(compressedData.data(), pfs_decrypted.data() + previousData, sectorSize);
                                # `compressedData` ha `sectorSize` (sector_data_actual_size)
                                # `pfs_decrypted` è `decrypted_chunk_from_pkg`
                                # `previousData` è `offset_of_sector_in_its_xts_block`
                                sector_data_bytes = decrypted_chunk_from_pkg[
                                    offset_of_sector_in_its_xts_block : 
                                    offset_of_sector_in_its_xts_block + sector_data_actual_size
                                ]
                                
                                # Decomprimi se necessario
                                if sector_data_actual_size == 0x10000: # Non compresso
                                    decompressed_block_data_pfs[:] = sector_data_bytes
                                elif 0 < sector_data_actual_size < 0x10000: # Compresso
                                    decompressed_block_data_pfs[:] = decompress_pfsc(bytes(sector_data_bytes), 0x10000)
                                elif sector_data_actual_size == 0:
                                    continue # Salta blocco vuoto
                                else:
                                    self._log(f"    AVVISO: Blocco dati {j_block_in_file} per '{fs_entry.name}' ha dimensione non valida {sector_data_actual_size}. Salto.")
                                    continue
                                
                                # Scrivi i dati decompressi
                                # C++: size_decompressed += 0x10000; (nel loop)
                                #      if (j < nblocks - 1) { inflated.WriteRaw<u8>(decompressedData.data(), decompressedData.size()); }
                                #      else { const u32 write_size = decompressedData.size() - (size_decompressed - bsize); ... }
                                #      `bsize` è `actual_inode_object.Size`.
                                #      `size_decompressed` nel C++ sembra calcolare la dimensione totale decompressa *finora*.
                                #      No, `size_decompressed` è la dimensione decompressa *potenziale* se tutti i blocchi fossero 0x10000.
                                #      Al blocco finale, (size_decompressed - bsize) è quanto si è decompresso in più rispetto alla dimensione reale.
                                #      Quindi, si scrive `0x10000 - (overshot_amount)`.

                                if j_block_in_file < num_data_blocks_for_file - 1:
                                    out_file_pfs.write(decompressed_block_data_pfs)
                                    bytes_written_total += 0x10000
                                else: # Ultimo blocco
                                    # Calcola quanto scrivere dall'ultimo blocco
                                    bytes_remaining_for_file = actual_inode_object.Size - bytes_written_total
                                    bytes_to_write_from_last_block = min(bytes_remaining_for_file, 0x10000)
                                    if bytes_to_write_from_last_block > 0:
                                        out_file_pfs.write(decompressed_block_data_pfs[:bytes_to_write_from_last_block])
                                        bytes_written_total += bytes_to_write_from_last_block
                                    # La logica C++ per `write_size` è un po' diversa, ma il risultato dovrebbe essere lo stesso:
                                    # non scrivere oltre la dimensione reale del file.
                            
                            if bytes_written_total != actual_inode_object.Size:
                                self._log(f"    AVVISO: Dimensione finale per '{fs_entry.name}' ({bytes_written_total}) "
                                          f"non corrisponde a quella dell'inode ({actual_inode_object.Size}).")
                        num_extracted_files +=1
                        self._log(f"    File '{fs_entry.name}' estratto ({bytes_written_total} bytes). {num_extracted_files}/{total_files_to_extract}")

            self._log(f"Estrazione file PFS completata. {num_extracted_files} file estratti.")
            return True, f"{num_extracted_files} file estratti."
        
        except IOError as e:
            self._log(f"Errore di I/O durante l'estrazione dei file PFS: {e}")
            return False, f"Errore I/O estrazione PFS: {e}"
        except Exception as e:
            self._log(f"Errore generico durante l'estrazione dei file PFS: {e}")
            import traceback
            self._log(traceback.format_exc())
            return False, f"Errore generico estrazione PFS: {e}"

# --- Interfaccia Grafica (Tkinter) ---
class PKGToolGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("PKG Tool")

        self.filepath_label = tk.Label(self.master, text="File PKG:")
        self.filepath_label.pack()

        self.filepath_entry = tk.Entry(self.master, width=50)
        self.filepath_entry.pack()

        self.browse_file_button = tk.Button(self.master, text="Sfoglia File PKG", command=self.browse_pkg_file)
        self.browse_file_button.pack()

        self.extract_base_path_label = tk.Label(self.master, text="Directory di output:")
        self.extract_base_path_label.pack()

        self.extract_base_path_entry = tk.Entry(self.master, width=50)
        self.extract_base_path_entry.pack()

        self.browse_output_button = tk.Button(self.master, text="Sfoglia Directory Output", command=self.browse_output_directory)
        self.browse_output_button.pack()

        self.extract_button = tk.Button(self.master, text="Estrai", command=self.extract_pkg)
        self.extract_button.pack()

        # Etichetta per i risultati o messaggi di stato
        self.result_label = tk.Label(self.master, text="")
        self.result_label.pack()

        # Area di testo scrollabile per i log
        self.log_text_area = scrolledtext.ScrolledText(self.master, width=70, height=15, state=tk.DISABLED)
        self.log_text_area.pack()

    def browse_pkg_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("PKG files", "*.pkg")])
        if filepath: # Se un file è stato selezionato
            self.filepath_entry.delete(0, tk.END) # Svuota il campo
            self.filepath_entry.insert(0, filepath) # Inserisci il nuovo percorso

    def browse_output_directory(self):
        directory = filedialog.askdirectory()
        if directory: # Se una directory è stata selezionata
            self.extract_base_path_entry.delete(0, tk.END) # Svuota il campo
            self.extract_base_path_entry.insert(0, directory) # Inserisci il nuovo percorso

    def extract_pkg(self):
        pkg_filepath_str = self.filepath_entry.get()
        if not pkg_filepath_str:
            messagebox.showerror("Errore", "Seleziona un file PKG.")
            return
        
        extract_base_path_str = self.extract_base_path_entry.get()
        if not extract_base_path_str:
            messagebox.showerror("Errore", "Seleziona una directory di output.")
            return

        filepath = pathlib.Path(pkg_filepath_str)
        extract_base_path = pathlib.Path(extract_base_path_str)
        
        # Crea un'istanza di PKG per ogni estrazione per resettare lo stato interno
        pkg_instance = PKG(logger_func=self.log_to_scrolledtext) 
        
        # Abilita il logging su scrolledtext
        self.log_text_area.config(state=tk.NORMAL)
        self.log_text_area.delete(1.0, tk.END) # Pulisci log precedente
        
        # Esegui l'estrazione in un thread separato per non bloccare la GUI
        # e per visualizzare i log in tempo reale.
        threading.Thread(target=self._run_extraction_thread, args=(pkg_instance, filepath, extract_base_path), daemon=True).start()

    def _run_extraction_thread(self, pkg_instance: PKG, filepath: pathlib.Path, extract_base_path: pathlib.Path):
        try:
            self.log_to_scrolledtext(f"Inizio apertura PKG: {filepath}")
            success, message = pkg_instance.open_pkg(filepath)
            if not success:
                self.log_to_scrolledtext(f"Errore apertura PKG: {message}")
                messagebox.showerror("Errore Apertura", message)
                self.log_text_area.config(state=tk.DISABLED)
                return
            self.log_to_scrolledtext(message)

            self.log_to_scrolledtext(f"Inizio estrazione da: {filepath} a {extract_base_path}")
            # Passiamo extract_base_path come directory base scelta dall'utente
            success, message = pkg_instance.extract(filepath, extract_base_path) 
            if not success:
                self.log_to_scrolledtext(f"Errore durante l'estrazione dei metadati/PFS: {message}")
                messagebox.showerror("Errore Estrazione Metadati", message)
                self.log_text_area.config(state=tk.DISABLED)
                return
            self.log_to_scrolledtext(message)

            self.log_to_scrolledtext(f"Inizio estrazione file da PFS...")
            success, message = pkg_instance.extract_pfs_files()
            if not success:
                self.log_to_scrolledtext(f"Errore durante l'estrazione dei file PFS: {message}")
                messagebox.showerror("Errore Estrazione File PFS", message)
            else:
                self.log_to_scrolledtext(f"Estrazione completata: {message}")
                messagebox.showinfo("Completato", f"Estrazione completata. {message}")
        
        except Exception as e:
            error_msg = f"Errore imprevisto durante l'estrazione: {e}"
            self.log_to_scrolledtext(error_msg)
            import traceback
            self.log_to_scrolledtext(traceback.format_exc())
            messagebox.showerror("Errore Imprevisto", error_msg)
        finally:
            self.log_text_area.config(state=tk.DISABLED)

    def log_to_scrolledtext(self, message):
        """Aggiunge un messaggio all'area di testo scrollabile."""
        if self.log_text_area:
            # Assicura che il widget sia abilitato per la modifica
            current_state = self.log_text_area.cget("state")
            self.log_text_area.config(state=tk.NORMAL)
            self.log_text_area.insert(tk.END, message + "\n")
            self.log_text_area.see(tk.END) # Scrolla alla fine
            self.log_text_area.config(state=current_state) # Ripristina lo stato precedente
            self.master.update_idletasks() # Forza l'aggiornamento della GUI

if __name__ == "__main__":
    root = tk.Tk()
    app = PKGToolGUI(root)
    root.mainloop()
