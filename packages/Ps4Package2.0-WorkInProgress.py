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
PKG_ENTRY_ID_TO_NAME_FULL = { # Corretto
    0x0001: "digests", 0x0010: "entry_keys", 0x0020: "image_key", 0x0080: "general_digests",
    0x0100: "metas", 0x0200: "entry_names", 0x0400: "license.dat", 0x0401: "license.info",
    0x0402: "nptitle.dat", 0x0403: "npbind.dat", 0x0404: "selfinfo.dat",
    0x0406: "imageinfo.dat", 0x0407: "target-deltainfo.dat", 0x0408: "origin-deltainfo.dat",
    0x0409: "psreserved.dat", 0x1000: "param.sfo", 0x1001: "playgo-chunk.dat",
    0x1002: "playgo-chunk.sha", 0x1003: "playgo-manifest.xml", 0x1004: "pronunciation.xml",
    0x1005: "pronunciation.sig", 0x1006: "pic1.png", 0x1007: "pubtoolinfo.dat",
    0x1008: "app/playgo-chunk.dat", 0x1009: "app/playgo-chunk.sha", 0x100A: "app/playgo-manifest.xml",
    0x100B: "shareparam.json", 0x100C: "shareoverlayimage.png", 0x100D: "save_data.png",
    0x100E: "shareprivacyguardimage.png", 0x1200: "icon0.png",
    0x1201: "icon0_00.png", 0x1202: "icon0_01.png", 0x1203: "icon0_02.png",
    0x1204: "icon0_03.png", 0x1205: "icon0_04.png", 0x1206: "icon0_05.png",
    0x1207: "icon0_06.png", 0x1208: "icon0_07.png", 0x1209: "icon0_08.png",
    0x120A: "icon0_09.png", 0x120B: "icon0_10.png", 0x120C: "icon0_11.png",
    0x120D: "icon0_12.png", 0x120E: "icon0_13.png", 0x120F: "icon0_14.png",
    0x1210: "icon0_15.png", 0x1211: "icon0_16.png", 0x1212: "icon0_17.png",
    0x1213: "icon0_18.png", 0x1214: "icon0_19.png", 0x1215: "icon0_20.png",
    0x1216: "icon0_21.png", 0x1217: "icon0_22.png", 0x1218: "icon0_23.png",
    0x1219: "icon0_24.png", 0x121A: "icon0_25.png", 0x121B: "icon0_26.png",
    0x121C: "icon0_27.png", 0x121D: "icon0_28.png", 0x121E: "icon0_29.png",
    0x121F: "icon0_30.png", 0x1220: "pic0.png", 0x1240: "snd0.at9",
    0x1241: "pic1_00.png", 0x1242: "pic1_01.png", 0x1243: "pic1_02.png",
    0x1244: "pic1_03.png", 0x1245: "pic1_04.png", 0x1246: "pic1_05.png",
    0x1247: "pic1_06.png", 0x1248: "pic1_07.png", 0x1249: "pic1_08.png",
    0x124A: "pic1_09.png", 0x124B: "pic1_10.png", 0x124C: "pic1_11.png",
    0x124D: "pic1_12.png", 0x124E: "pic1_13.png", 0x124F: "pic1_14.png",
    0x1250: "pic1_15.png", 0x1251: "pic1_16.png", 0x1252: "pic1_17.png",
    0x1253: "pic1_18.png", 0x1254: "pic1_19.png", 0x1255: "pic1_20.png",
    0x1256: "pic1_21.png", 0x1257: "pic1_22.png", 0x1258: "pic1_23.png",
    0x1259: "pic1_24.png", 0x125A: "pic1_25.png", 0x125B: "pic1_26.png",
    0x125C: "pic1_27.png", 0x125D: "pic1_28.png", 0x125E: "pic1_29.png",
    0x125F: "pic1_30.png", 0x1260: "changeinfo/changeinfo.xml",
    0x1261: "changeinfo/changeinfo_00.xml", 0x1262: "changeinfo/changeinfo_01.xml",
    0x1263: "changeinfo/changeinfo_02.xml", 0x1264: "changeinfo/changeinfo_03.xml",
    0x1265: "changeinfo/changeinfo_04.xml", 0x1266: "changeinfo/changeinfo_05.xml",
    0x1267: "changeinfo/changeinfo_06.xml", 0x1268: "changeinfo/changeinfo_07.xml",
    0x1269: "changeinfo/changeinfo_08.xml", 0x126A: "changeinfo/changeinfo_09.xml",
    0x126B: "changeinfo/changeinfo_10.xml", 0x126C: "changeinfo/changeinfo_11.xml",
    0x126D: "changeinfo/changeinfo_12.xml", 0x126E: "changeinfo/changeinfo_13.xml",
    0x126F: "changeinfo/changeinfo_14.xml", 0x1270: "changeinfo/changeinfo_15.xml",
    0x1271: "changeinfo/changeinfo_16.xml", 0x1272: "changeinfo/changeinfo_17.xml",
    0x1273: "changeinfo/changeinfo_18.xml", 0x1274: "changeinfo/changeinfo_19.xml",
    0x1275: "changeinfo/changeinfo_20.xml", 0x1276: "changeinfo/changeinfo_21.xml",
    0x1277: "changeinfo/changeinfo_22.xml", 0x1278: "changeinfo/changeinfo_23.xml",
    0x1279: "changeinfo/changeinfo_24.xml", 0x127A: "changeinfo/changeinfo_25.xml",
    0x127B: "changeinfo/changeinfo_26.xml", 0x127C: "changeinfo/changeinfo_27.xml",
    0x127D: "changeinfo/changeinfo_28.xml", 0x127E: "changeinfo/changeinfo_29.xml",
    0x127F: "changeinfo/changeinfo_30.xml", 0x1280: "icon0.dds",
    0x1281: "icon0_00.dds", 0x1282: "icon0_01.dds", 0x1283: "icon0_02.dds",
    0x1284: "icon0_03.dds", 0x1285: "icon0_04.dds", 0x1286: "icon0_05.dds",
    0x1287: "icon0_06.dds", 0x1288: "icon0_07.dds", 0x1289: "icon0_08.dds",
    0x128A: "icon0_09.dds", 0x128B: "icon0_10.dds", 0x128C: "icon0_11.dds",
    0x128D: "icon0_12.dds", 0x128E: "icon0_13.dds", 0x128F: "icon0_14.dds",
    0x1290: "icon0_15.dds", 0x1291: "icon0_16.dds", 0x1292: "icon0_17.dds",
    0x1293: "icon0_18.dds", 0x1294: "icon0_19.dds", 0x1295: "icon0_20.dds",
    0x1296: "icon0_21.dds", 0x1297: "icon0_22.dds", 0x1298: "icon0_23.dds",
    0x1299: "icon0_24.dds", 0x129A: "icon0_25.dds", 0x129B: "icon0_26.dds",
    0x129C: "icon0_27.dds", 0x129D: "icon0_28.dds", 0x129E: "icon0_29.dds",
    0x129F: "icon0_30.dds", 0x12A0: "pic0.dds", 0x12C0: "pic1.dds",
    0x12C1: "pic1_00.dds", 0x12C2: "pic1_01.dds", 0x12C3: "pic1_02.dds",
    0x12C4: "pic1_03.dds", 0x12C5: "pic1_04.dds", 0x12C6: "pic1_05.dds",
    0x12C7: "pic1_06.dds", 0x12C8: "pic1_07.dds", 0x12C9: "pic1_08.dds",
    0x12CA: "pic1_09.dds", 0x12CB: "pic1_10.dds", 0x12CC: "pic1_11.dds",
    0x12CD: "pic1_12.dds", 0x12CE: "pic1_13.dds", 0x12CF: "pic1_14.dds",
    0x12D0: "pic1_15.dds", 0x12D1: "pic1_16.dds", 0x12D2: "pic1_17.dds",
    0x12D3: "pic1_18.dds", 0x12D4: "pic1_19.dds", 0x12D5: "pic1_20.dds",
    0x12D6: "pic1_21.dds", 0x12D7: "pic1_22.dds", 0x12D8: "pic1_23.dds",
    0x12D9: "pic1_24.dds", 0x12DA: "pic1_25.dds", 0x12DB: "pic1_26.dds",
    0x12DC: "pic1_27.dds", 0x12DD: "pic1_28.dds", 0x12DE: "pic1_29.dds",
    0x12DF: "pic1_30.dds", 0x1400: "trophy/trophy00.trp",
    0x1401: "trophy/trophy01.trp", 0x1402: "trophy/trophy02.trp",
    0x1403: "trophy/trophy03.trp", 0x1404: "trophy/trophy04.trp",
    0x1405: "trophy/trophy05.trp", 0x1406: "trophy/trophy06.trp",
    0x1407: "trophy/trophy07.trp", 0x1408: "trophy/trophy08.trp",
    0x1409: "trophy/trophy09.trp", 0x140A: "trophy/trophy10.trp",
    0x140B: "trophy/trophy11.trp", 0x140C: "trophy/trophy12.trp",
    0x140D: "trophy/trophy13.trp", 0x140E: "trophy/trophy14.trp",
    0x140F: "trophy/trophy15.trp", 0x1410: "trophy/trophy16.trp",
    0x1411: "trophy/trophy17.trp", 0x1412: "trophy/trophy18.trp",
    0x1413: "trophy/trophy19.trp", 0x1414: "trophy/trophy20.trp",
    0x1415: "trophy/trophy21.trp", 0x1416: "trophy/trophy22.trp",
    0x1417: "trophy/trophy23.trp", 0x1418: "trophy/trophy24.trp",
    0x1419: "trophy/trophy25.trp", 0x141A: "trophy/trophy26.trp",
    0x141B: "trophy/trophy27.trp", 0x141C: "trophy/trophy28.trp",
    0x141D: "trophy/trophy29.trp", 0x141E: "trophy/trophy30.trp",
    0x141F: "trophy/trophy31.trp", 0x1420: "trophy/trophy32.trp",
    0x1421: "trophy/trophy33.trp", 0x1422: "trophy/trophy34.trp",
    0x1423: "trophy/trophy35.trp", 0x1424: "trophy/trophy36.trp",
    0x1425: "trophy/trophy37.trp", 0x1426: "trophy/trophy38.trp",
    0x1427: "trophy/trophy39.trp", 0x1428: "trophy/trophy40.trp",
    0x1429: "trophy/trophy41.trp", 0x142A: "trophy/trophy42.trp",
    0x142B: "trophy/trophy43.trp", 0x142C: "trophy/trophy44.trp",
    0x142D: "trophy/trophy45.trp", 0x142E: "trophy/trophy46.trp",
    0x142F: "trophy/trophy47.trp", 0x1430: "trophy/trophy48.trp",
    0x1431: "trophy/trophy49.trp", 0x1432: "trophy/trophy50.trp",
    0x1433: "trophy/trophy51.trp", 0x1434: "trophy/trophy52.trp",
    0x1435: "trophy/trophy53.trp", 0x1436: "trophy/trophy54.trp",
    0x1437: "trophy/trophy55.trp", 0x1438: "trophy/trophy56.trp",
    0x1439: "trophy/trophy57.trp", 0x143A: "trophy/trophy58.trp",
    0x143B: "trophy/trophy59.trp", 0x143C: "trophy/trophy60.trp",
    0x143D: "trophy/trophy61.trp", 0x143E: "trophy/trophy62.trp",
    0x143F: "trophy/trophy63.trp", 0x1440: "trophy/trophy64.trp",
    0x1441: "trophy/trophy65.trp", 0x1442: "trophy/trophy66.trp",
    0x1443: "trophy/trophy67.trp", 0x1444: "trophy/trophy68.trp",
    0x1445: "trophy/trophy69.trp", 0x1446: "trophy/trophy70.trp",
    0x1447: "trophy/trophy71.trp", 0x1448: "trophy/trophy72.trp",
    0x1449: "trophy/trophy73.trp", 0x144A: "trophy/trophy74.trp",
    0x144B: "trophy/trophy75.trp", 0x144C: "trophy/trophy76.trp",
    0x144D: "trophy/trophy77.trp", 0x144E: "trophy/trophy78.trp",
    0x144F: "trophy/trophy79.trp", 0x1450: "trophy/trophy80.trp",
    0x1451: "trophy/trophy81.trp", 0x1452: "trophy/trophy82.trp",
    0x1453: "trophy/trophy83.trp", 0x1454: "trophy/trophy84.trp",
    0x1455: "trophy/trophy85.trp", 0x1456: "trophy/trophy86.trp",
    0x1457: "trophy/trophy87.trp", 0x1458: "trophy/trophy88.trp",
    0x1459: "trophy/trophy89.trp", 0x145A: "trophy/trophy90.trp",
    0x145B: "trophy/trophy91.trp", 0x145C: "trophy/trophy92.trp",
    0x145D: "trophy/trophy93.trp", 0x145E: "trophy/trophy94.trp",
    0x145F: "trophy/trophy95.trp", 0x1460: "trophy/trophy96.trp",
    0x1461: "trophy/trophy97.trp", 0x1462: "trophy/trophy98.trp",
    0x1463: "trophy/trophy99.trp",  0x1600: "keymap_rp/001.png",
    0x1601: "keymap_rp/002.png",    0x1602: "keymap_rp/003.png",
    0x1603: "keymap_rp/004.png",    0x1604: "keymap_rp/005.png",
    0x1605: "keymap_rp/006.png",    0x1606: "keymap_rp/007.png",
    0x1607: "keymap_rp/008.png",    0x1608: "keymap_rp/009.png",
    0x1609: "keymap_rp/010.png",    0x1610: "keymap_rp/00/001.png",
    0x1611: "keymap_rp/00/002.png", 0x1612: "keymap_rp/00/003.png",
    0x1613: "keymap_rp/00/004.png", 0x1614: "keymap_rp/00/005.png",
    0x1615: "keymap_rp/00/006.png", 0x1616: "keymap_rp/00/007.png",
    0x1617: "keymap_rp/00/008.png", 0x1618: "keymap_rp/00/009.png",
    0x1619: "keymap_rp/00/010.png", 0x1620: "keymap_rp/01/001.png",
    0x1621: "keymap_rp/01/002.png", 0x1622: "keymap_rp/01/003.png",
    0x1623: "keymap_rp/01/004.png", 0x1624: "keymap_rp/01/005.png",
    0x1625: "keymap_rp/01/006.png", 0x1626: "keymap_rp/01/007.png",
    0x1627: "keymap_rp/01/008.png", 0x1628: "keymap_rp/01/009.png",
    0x1629: "keymap_rp/01/010.png", 0x1630: "keymap_rp/02/001.png",
    0x1631: "keymap_rp/02/002.png", 0x1632: "keymap_rp/02/003.png",
    0x1633: "keymap_rp/02/004.png", 0x1634: "keymap_rp/02/005.png",
    0x1635: "keymap_rp/02/006.png", 0x1636: "keymap_rp/02/007.png",
    0x1637: "keymap_rp/02/008.png", 0x1638: "keymap_rp/02/009.png",
    0x1639: "keymap_rp/02/010.png", 0x1640: "keymap_rp/03/001.png",
    0x1641: "keymap_rp/03/002.png", 0x1642: "keymap_rp/03/003.png",
    0x1643: "keymap_rp/03/004.png", 0x1644: "keymap_rp/03/005.png",
    0x1645: "keymap_rp/03/006.png", 0x1646: "keymap_rp/03/007.png",
    0x1647: "keymap_rp/03/008.png", 0x1648: "keymap_rp/03/009.png", # Corretto il nome file da '0010' a '009'
    0x1649: "keymap_rp/03/010.png", # Aggiunto per coerenza se 0x1648 era un errore di battitura per 009
    0x1650: "keymap_rp/04/001.png", 0x1651: "keymap_rp/04/002.png",
    0x1652: "keymap_rp/04/003.png", 0x1653: "keymap_rp/04/004.png",
    0x1654: "keymap_rp/04/005.png", 0x1655: "keymap_rp/04/006.png",
    0x1656: "keymap_rp/04/007.png", 0x1657: "keymap_rp/04/008.png",
    0x1658: "keymap_rp/04/009.png", 0x1659: "keymap_rp/04/010.png",
    0x1660: "keymap_rp/05/001.png", 0x1661: "keymap_rp/05/002.png",
    0x1662: "keymap_rp/05/003.png", 0x1663: "keymap_rp/05/004.png",
    0x1664: "keymap_rp/05/005.png", 0x1665: "keymap_rp/05/006.png",
    0x1666: "keymap_rp/05/007.png", 0x1667: "keymap_rp/05/008.png",
    0x1668: "keymap_rp/05/009.png", 0x1669: "keymap_rp/05/010.png",
    0x1670: "keymap_rp/06/001.png", 0x1671: "keymap_rp/06/002.png",
    0x1672: "keymap_rp/06/003.png", 0x1673: "keymap_rp/06/004.png",
    0x1674: "keymap_rp/06/005.png", 0x1675: "keymap_rp/06/006.png",
    0x1676: "keymap_rp/06/007.png", 0x1677: "keymap_rp/06/008.png",
    0x1678: "keymap_rp/06/009.png", 0x1679: "keymap_rp/06/010.png",
    0x1680: "keymap_rp/07/001.png", 0x1681: "keymap_rp/07/002.png",
    0x1682: "keymap_rp/07/003.png", 0x1683: "keymap_rp/07/004.png",
    0x1684: "keymap_rp/07/005.png", 0x1685: "keymap_rp/07/006.png",
    0x1686: "keymap_rp/07/007.png", 0x1687: "keymap_rp/07/008.png",
    0x1688: "keymap_rp/07/009.png", 0x1689: "keymap_rp/07/010.png",
    0x1690: "keymap_rp/08/001.png", 0x1691: "keymap_rp/08/002.png",
    0x1692: "keymap_rp/08/003.png", 0x1693: "keymap_rp/08/004.png",
    0x1694: "keymap_rp/08/005.png", 0x1695: "keymap_rp/08/006.png",
    0x1696: "keymap_rp/08/007.png", 0x1697: "keymap_rp/08/008.png",
    0x1698: "keymap_rp/08/009.png", 0x1699: "keymap_rp/08/010.png",
    0x16A0: "keymap_rp/09/001.png", 0x16A1: "keymap_rp/09/002.png",
    0x16A2: "keymap_rp/09/003.png", 0x16A3: "keymap_rp/09/004.png",
    0x16A4: "keymap_rp/09/005.png", 0x16A5: "keymap_rp/09/006.png",
    0x16A6: "keymap_rp/09/007.png", 0x16A7: "keymap_rp/09/008.png",
    0x16A8: "keymap_rp/09/009.png", 0x16A9: "keymap_rp/09/010.png",
    0x16B0: "keymap_rp/10/001.png", 0x16B1: "keymap_rp/10/002.png",
    0x16B2: "keymap_rp/10/003.png", 0x16B3: "keymap_rp/10/004.png",
    0x16B4: "keymap_rp/10/005.png", 0x16B5: "keymap_rp/10/006.png",
    0x16B6: "keymap_rp/10/007.png", 0x16B7: "keymap_rp/10/008.png",
    0x16B8: "keymap_rp/10/009.png", 0x16B9: "keymap_rp/10/010.png",
    0x16C0: "keymap_rp/11/001.png", 0x16C1: "keymap_rp/11/002.png",
    0x16C2: "keymap_rp/11/003.png", 0x16C3: "keymap_rp/11/004.png",
    0x16C4: "keymap_rp/11/005.png", 0x16C5: "keymap_rp/11/006.png",
    0x16C6: "keymap_rp/11/007.png", 0x16C7: "keymap_rp/11/008.png",
    0x16C8: "keymap_rp/11/009.png", 0x16C9: "keymap_rp/11/010.png",
    0x16D0: "keymap_rp/12/001.png", 0x16D1: "keymap_rp/12/002.png",
    0x16D2: "keymap_rp/12/003.png", 0x16D3: "keymap_rp/12/004.png",
    0x16D4: "keymap_rp/12/005.png", 0x16D5: "keymap_rp/12/006.png",
    0x16D6: "keymap_rp/12/007.png", 0x16D7: "keymap_rp/12/008.png",
    0x16D8: "keymap_rp/12/009.png", 0x16D9: "keymap_rp/12/010.png",
    0x16E0: "keymap_rp/13/001.png", 0x16E1: "keymap_rp/13/002.png",
    0x16E2: "keymap_rp/13/003.png", 0x16E3: "keymap_rp/13/004.png",
    0x16E4: "keymap_rp/13/005.png", 0x16E5: "keymap_rp/13/006.png",
    0x16E6: "keymap_rp/13/007.png", 0x16E7: "keymap_rp/13/008.png",
    0x16E8: "keymap_rp/13/009.png", 0x16E9: "keymap_rp/13/010.png",
    0x16F0: "keymap_rp/14/001.png", 0x16F1: "keymap_rp/14/002.png",
    0x16F2: "keymap_rp/14/003.png", 0x16F3: "keymap_rp/14/004.png",
    0x16F4: "keymap_rp/14/005.png", 0x16F5: "keymap_rp/14/006.png",
    0x16F6: "keymap_rp/14/007.png", 0x16F7: "keymap_rp/14/008.png",
    0x16F8: "keymap_rp/14/009.png", 0x16F9: "keymap_rp/14/010.png",
    0x1700: "keymap_rp/15/001.png", 0x1701: "keymap_rp/15/002.png",
    0x1702: "keymap_rp/15/003.png", 0x1703: "keymap_rp/15/004.png",
    0x1704: "keymap_rp/15/005.png", 0x1705: "keymap_rp/15/006.png",
    0x1706: "keymap_rp/15/007.png", 0x1707: "keymap_rp/15/008.png",
    0x1708: "keymap_rp/15/009.png", 0x1709: "keymap_rp/15/010.png",
    0x1710: "keymap_rp/16/001.png", 0x1711: "keymap_rp/16/002.png",
    0x1712: "keymap_rp/16/003.png", 0x1713: "keymap_rp/16/004.png",
    0x1714: "keymap_rp/16/005.png", 0x1715: "keymap_rp/16/006.png",
    0x1716: "keymap_rp/16/007.png", 0x1717: "keymap_rp/16/008.png",
    0x1718: "keymap_rp/16/009.png", 0x1719: "keymap_rp/16/010.png",
    0x1720: "keymap_rp/17/001.png", 0x1721: "keymap_rp/17/002.png",
    0x1722: "keymap_rp/17/003.png", 0x1723: "keymap_rp/17/004.png",
    0x1724: "keymap_rp/17/005.png", 0x1725: "keymap_rp/17/006.png",
    0x1726: "keymap_rp/17/007.png", 0x1727: "keymap_rp/17/008.png",
    0x1728: "keymap_rp/17/009.png", 0x1729: "keymap_rp/17/010.png",
    0x1730: "keymap_rp/18/001.png", 0x1731: "keymap_rp/18/002.png",
    0x1732: "keymap_rp/18/003.png", 0x1733: "keymap_rp/18/004.png",
    0x1734: "keymap_rp/18/005.png", 0x1735: "keymap_rp/18/006.png",
    0x1736: "keymap_rp/18/007.png", 0x1737: "keymap_rp/18/008.png",
    0x1738: "keymap_rp/18/009.png", 0x1739: "keymap_rp/18/010.png",
    0x1740: "keymap_rp/19/001.png", 0x1741: "keymap_rp/19/002.png",
    0x1742: "keymap_rp/19/003.png", 0x1743: "keymap_rp/19/004.png",
    0x1744: "keymap_rp/19/005.png", 0x1745: "keymap_rp/19/006.png",
    0x1746: "keymap_rp/19/007.png", 0x1747: "keymap_rp/19/008.png",
    0x1748: "keymap_rp/19/009.png", 0x1749: "keymap_rp/19/010.png",
    0x1750: "keymap_rp/20/001.png", 0x1751: "keymap_rp/20/002.png",
    0x1752: "keymap_rp/20/003.png", 0x1753: "keymap_rp/20/004.png",
    0x1754: "keymap_rp/20/005.png", 0x1755: "keymap_rp/20/006.png",
    0x1756: "keymap_rp/20/007.png", 0x1757: "keymap_rp/20/008.png",
    0x1758: "keymap_rp/20/009.png", 0x1759: "keymap_rp/20/010.png",
    0x1760: "keymap_rp/21/001.png", 0x1761: "keymap_rp/21/002.png",
    0x1762: "keymap_rp/21/003.png", 0x1763: "keymap_rp/21/004.png",
    0x1764: "keymap_rp/21/005.png", 0x1765: "keymap_rp/21/006.png",
    0x1766: "keymap_rp/21/007.png", 0x1767: "keymap_rp/21/008.png",
    0x1768: "keymap_rp/21/009.png", 0x1769: "keymap_rp/21/010.png",
    0x1770: "keymap_rp/22/001.png", 0x1771: "keymap_rp/22/002.png",
    0x1772: "keymap_rp/22/003.png", 0x1773: "keymap_rp/22/004.png",
    0x1774: "keymap_rp/22/005.png", 0x1775: "keymap_rp/22/006.png",
    0x1776: "keymap_rp/22/007.png", 0x1777: "keymap_rp/22/008.png",
    0x1778: "keymap_rp/22/009.png", 0x1779: "keymap_rp/22/010.png",
    0x1780: "keymap_rp/23/001.png", 0x1781: "keymap_rp/23/002.png",
    0x1782: "keymap_rp/23/003.png", 0x1783: "keymap_rp/23/004.png",
    0x1784: "keymap_rp/23/005.png", 0x1785: "keymap_rp/23/006.png",
    0x1786: "keymap_rp/23/007.png", 0x1787: "keymap_rp/23/008.png",
    0x1788: "keymap_rp/23/009.png", 0x1789: "keymap_rp/23/010.png",
    0x1790: "keymap_rp/24/001.png", 0x1791: "keymap_rp/24/002.png",
    0x1792: "keymap_rp/24/003.png", 0x1793: "keymap_rp/24/004.png",
    0x1794: "keymap_rp/24/005.png", 0x1795: "keymap_rp/24/006.png",
    0x1796: "keymap_rp/24/007.png", 0x1797: "keymap_rp/24/008.png",
    0x1798: "keymap_rp/24/009.png", 0x1799: "keymap_rp/24/010.png",
    0x17A0: "keymap_rp/25/001.png", 0x17A1: "keymap_rp/25/002.png",
    0x17A2: "keymap_rp/25/003.png", 0x17A3: "keymap_rp/25/004.png",
    0x17A4: "keymap_rp/25/005.png", 0x17A5: "keymap_rp/25/006.png",
    0x17A6: "keymap_rp/25/007.png", 0x17A7: "keymap_rp/25/008.png",
    0x17A8: "keymap_rp/25/009.png", 0x17A9: "keymap_rp/25/010.png",
    0x17B0: "keymap_rp/26/001.png", 0x17B1: "keymap_rp/26/002.png",
    0x17B2: "keymap_rp/26/003.png", 0x17B3: "keymap_rp/26/004.png",
    0x17B4: "keymap_rp/26/005.png", 0x17B5: "keymap_rp/26/006.png",
    0x17B6: "keymap_rp/26/007.png", 0x17B7: "keymap_rp/26/008.png",
    0x17B8: "keymap_rp/26/009.png", 0x17B9: "keymap_rp/26/010.png",
    0x17C0: "keymap_rp/27/001.png", 0x17C1: "keymap_rp/27/002.png",
    0x17C2: "keymap_rp/27/003.png", 0x17C3: "keymap_rp/27/004.png",
    0x17C4: "keymap_rp/27/005.png", 0x17C5: "keymap_rp/27/006.png",
    0x17C6: "keymap_rp/27/007.png", 0x17C7: "keymap_rp/27/008.png",
    0x17C8: "keymap_rp/27/009.png", 0x17C9: "keymap_rp/27/010.png",
    0x17D0: "keymap_rp/28/001.png", 0x17D1: "keymap_rp/28/002.png",
    0x17D2: "keymap_rp/28/003.png", 0x17D3: "keymap_rp/28/004.png",
    0x17D4: "keymap_rp/28/005.png", 0x17D5: "keymap_rp/28/006.png",
    0x17D6: "keymap_rp/28/007.png", 0x17D7: "keymap_rp/28/008.png",
    0x17D8: "keymap_rp/28/009.png", 0x17D9: "keymap_rp/28/010.png",
    0x17E0: "keymap_rp/29/001.png", 0x17E1: "keymap_rp/29/002.png",
    0x17E2: "keymap_rp/29/003.png", 0x17E3: "keymap_rp/29/004.png",
    0x17E4: "keymap_rp/29/005.png", 0x17E5: "keymap_rp/29/006.png",
    0x17E6: "keymap_rp/29/007.png", 0x17E7: "keymap_rp/29/008.png",
    0x17E8: "keymap_rp/29/009.png", 0x17E9: "keymap_rp/29/010.png",
    0x17F0: "keymap_rp/30/001.png", 0x17F1: "keymap_rp/30/002.png",
    0x17F2: "keymap_rp/30/003.png", 0x17F3: "keymap_rp/30/004.png",
    0x17F4: "keymap_rp/30/005.png", 0x17F5: "keymap_rp/30/006.png",
    0x17F6: "keymap_rp/30/007.png", 0x17F7: "keymap_rp/30/008.png",
    0x17F8: "keymap_rp/30/009.png", 0x17F9: "keymap_rp/30/010.png"
}

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
    """Optimized PFSC decompression function with reduced logging for performance."""
    compressed_data_len = len(compressed_data)
    
    # Only log for smaller compressed data to reduce I/O overhead in performance-critical paths
    is_verbose = compressed_data_len < 1000000  # Only verbose logging for smaller files
    
    if is_verbose:
        logger_func(f"DEBUG decompress_pfsc: Dati compressi: {compressed_data_len} bytes, decompressed_size atteso: {decompressed_size} bytes")
    
    if compressed_data_len == 0:
        if is_verbose:
            logger_func("DEBUG decompress_pfsc: ERRORE - I dati compressi sono vuoti (0 bytes)")
        return b'\0' * decompressed_size
    
    # Check first few bytes only in verbose mode
    if is_verbose:
        sample_size = min(32, compressed_data_len)
        logger_func(f"DEBUG decompress_pfsc: Primi {sample_size} bytes dati compressi: {compressed_data[:sample_size].hex()}")
        
        # Check if data seems to be all zeros
        if all(b == 0 for b in compressed_data[:min(100, compressed_data_len)]):
            logger_func("DEBUG decompress_pfsc: AVVISO - I dati compressi sembrano essere tutti zeri")
    
    # Cache the result of common decompression sizes
    # This significantly improves performance for repeated decompression of same-sized blocks
    global _pfsc_decompress_cache
    cache_key = None
    
    try:
        # Use the cache for blocks under 1MB to avoid memory issues
        if compressed_data_len < 1024*1024:
            if '_pfsc_decompress_cache' not in globals():
                _pfsc_decompress_cache = {}
                
            # Generate a cache key based on the compressed data
            if compressed_data_len > 64:
                # Use first and last 32 bytes as a fingerprint for cache key
                cache_key = (compressed_data[:32], compressed_data[-32:], compressed_data_len, decompressed_size)
                if cache_key in _pfsc_decompress_cache:
                    return _pfsc_decompress_cache[cache_key]
        
        # For performance, use a raw decompressobj
        decompressor = zlib.decompressobj(-zlib.MAX_WBITS)  # Raw deflate
        decompressed = decompressor.decompress(compressed_data)
        decompressed += decompressor.flush()
        
        if is_verbose:
            actual_decompressed_len = len(decompressed)
            logger_func(f"DEBUG decompress_pfsc: Decompressione RIUSCITA. Dimensione effettiva: {actual_decompressed_len} bytes")
        
        # Handle size adjustments
        if len(decompressed) < decompressed_size:
            if is_verbose:
                logger_func(f"DEBUG decompress_pfsc: Padding aggiunto: {decompressed_size - len(decompressed)} bytes")
            decompressed += b'\0' * (decompressed_size - len(decompressed))
        elif len(decompressed) > decompressed_size:
            if is_verbose:
                logger_func(f"DEBUG decompress_pfsc: Troncamento: {len(decompressed) - decompressed_size} bytes rimossi")
            decompressed = decompressed[:decompressed_size]
        
        # Only log in verbose mode
        if is_verbose:
            sample_size_output = min(32, len(decompressed))
            logger_func(f"DEBUG decompress_pfsc: Primi {sample_size_output} bytes decompressione: {decompressed[:sample_size_output].hex()}")
        
        # Save to cache if we have a cache key
        if cache_key is not None and '_pfsc_decompress_cache' in globals():
            # Limit cache size
            if len(_pfsc_decompress_cache) > 100:  # Don't let cache grow too large
                _pfsc_decompress_cache.clear()
            _pfsc_decompress_cache[cache_key] = decompressed
        
        return decompressed
        
    except zlib.error as e:
        if is_verbose:
            logger_func(f"DEBUG decompress_pfsc: ERRORE Zlib durante la decompressione: {e}")
        
        # Try alternative approach with standard zlib
        try:
            if is_verbose:
                logger_func("DEBUG decompress_pfsc: Tentativo con wbits=15 (standard zlib)...")
            
            decompressor_alt = zlib.decompressobj(15)
            decompressed_alt = decompressor_alt.decompress(compressed_data)
            decompressed_alt += decompressor_alt.flush()
            
            if is_verbose:
                logger_func(f"DEBUG decompress_pfsc: Alternativa riuscita! Dimensione: {len(decompressed_alt)} bytes")
            
            if len(decompressed_alt) < decompressed_size:
                decompressed_alt += b'\0' * (decompressed_size - len(decompressed_alt))
            elif len(decompressed_alt) > decompressed_size:
                decompressed_alt = decompressed_alt[:decompressed_size]
            
            # Save to cache if we have a cache key
            if cache_key is not None and '_pfsc_decompress_cache' in globals():
                _pfsc_decompress_cache[cache_key] = decompressed_alt
                
            return decompressed_alt
            
        except zlib.error as e2:
            if is_verbose:
                logger_func(f"DEBUG decompress_pfsc: Anche approccio alternativo fallito: {e2}")
        
        # Return a zero buffer
        if is_verbose:
            logger_func(f"DEBUG decompress_pfsc: Restituzione buffer di zeri ({decompressed_size} bytes)")
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
            raise ValueError(f"Dati insufficienti per PFSHeaderPfs. Richiesti {cls._SIZE}, forniti {len(data)}.")
        values = list(struct.unpack_from(cls._FORMAT, data, 0))
        
        # Trova l'indice di 'mode' in _FIELDS_SPEC per convertirlo in Enum
        mode_idx = -1
        for i, field_spec in enumerate(cls._FIELDS_SPEC):
            if field_spec[0] == 'mode':
                mode_idx = i
                break
        if mode_idx != -1:
            values[mode_idx] = PfsMode(values[mode_idx])
        else:
            # Questo non dovrebbe accadere se 'mode' è in _FIELDS_SPEC
            raise KeyError("'mode' field not found in _FIELDS_SPEC for PFSHeaderPfs")
            
        return cls(*values)

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
    PFS_INVALID = 0; PFS_FILE = 2; PFS_DIR = 3
    PFS_CURRENT_DIR = 4; PFS_PARENT_DIR = 5

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
    name: str; inode: int; type: PFSFileType


# --- Implementazione Crypto Reale ---
"""class RealCrypto:
    def __init__(self, logger_func=print):
        self.logger = logger_func
        self.logger("Crypto Reale: Inizializzazione...")
        try:
            self._key_pkg_derived_key3 = RSA.construct((
                int.from_bytes(PkgDerivedKey3Keyset.Modulus, 'big'),
                int.from_bytes(PkgDerivedKey3Keyset.PublicExponent, 'big'),
                int.from_bytes(PkgDerivedKey3Keyset.PrivateExponent, 'big'),
                int.from_bytes(PkgDerivedKey3Keyset.Prime1, 'big'),
                int.from_bytes(PkgDerivedKey3Keyset.Prime2, 'big'),
                # PyCryptodome calcola 'u' (coefficient) se p e q sono forniti e u è None.
                # Per usare i valori da keys.h, passiamo anche Exponent1 (dP), Exponent2 (dQ)
                # e Coefficient (u). Tuttavia, RSA.construct accetta (n,e,d,p,q,u) oppure (n,e,d,p,q,dP,dQ,u).
                # Per semplicità e dato che abbiamo tutti i componenti CRT:
                # Usiamo dP=Exponent1, dQ=Exponent2, u=Coefficient
                # Ma la tupla base (n,e,d,p,q,u) è sufficiente.
                # Per usare dP, dQ: RSA.construct((n,e,d,p,q,dP,dQ,u))
                # Se dP, dQ, u non sono noti, RSA.construct((n,e,d,p,q)) li calcola.
                # Poiché abbiamo 'u' (Coefficient), lo usiamo.
                 int.from_bytes(PkgDerivedKey3Keyset.Coefficient, 'big')
            ))
            self._key_fake = RSA.construct((
                int.from_bytes(FakeKeyset.Modulus, 'big'),
                int.from_bytes(FakeKeyset.PublicExponent, 'big'),
                int.from_bytes(FakeKeyset.PrivateExponent, 'big'),
                int.from_bytes(FakeKeyset.Prime1, 'big'),
                int.from_bytes(FakeKeyset.Prime2, 'big'),
                int.from_bytes(FakeKeyset.Coefficient, 'big')
            ))
            self.logger("Chiavi RSA caricate con successo.")
        except Exception as e:
            self.logger(f"ERRORE CRITICO nel caricamento chiavi RSA: {e}")
            import traceback
            self.logger(traceback.format_exc()); raise

    def RSA2048Decrypt(self, output_key_buffer: bytearray, ciphertext: bytes, is_dk3: bool):
        # ... (implementazione come prima, assicurarsi che sia corretta) ...
        # Nota: il messaggio decrittato da RSA PKCS#1v1.5 è più corto della dimensione della chiave.
        # Il C++ copia i primi N byte (es. 32) nel buffer di output.
        self.logger(f"Crypto: RSA2048Decrypt. is_dk3={is_dk3}, input len={len(ciphertext)}")
        if len(ciphertext) != 256:
            self.logger(f"Errore RSA: ciphertext len non è 256 (è {len(ciphertext)})")
            output_key_buffer[:] = b'\0' * len(output_key_buffer); return
        key_to_use = self._key_pkg_derived_key3 if is_dk3 else self._key_fake
        cipher_rsa = Cipher_PKCS1_v1_5.new(key_to_use)
        try:
            decrypted_data = cipher_rsa.decrypt(ciphertext, sentinel=None) 
            bytes_to_copy = min(len(output_key_buffer), len(decrypted_data))
            output_key_buffer[:bytes_to_copy] = decrypted_data[:bytes_to_copy]
            if len(output_key_buffer) > bytes_to_copy:
                output_key_buffer[bytes_to_copy:] = b'\0' * (len(output_key_buffer) - bytes_to_copy)
            # self.logger(f"Crypto: RSA Decrypt OK. Output (primi {min(8, len(output_key_buffer))} byte): {output_key_buffer[:min(8, len(output_key_buffer))].hex()}")
        except Exception as e:
            self.logger(f"Errore RSA Decrypt: {e}. Ciphertext: {ciphertext[:16].hex()}...");
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

    def aesCbcCfb128DecryptEntry(self, ivkey: bytes, ciphertext: bytes, decrypted_buffer: bytearray):
        # ... (implementazione come prima) ...
        if len(ivkey) != 32 or len(ciphertext) % AES.block_size != 0 or len(decrypted_buffer) != len(ciphertext):
            self.logger("Errore aesCbcCfb128DecryptEntry: dimensioni non valide."); return
        key = ivkey[16:32]; iv = ivkey[0:16]
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted_buffer[:] = cipher_aes.decrypt(ciphertext)
        # self.logger(f"Crypto: aesCbcCfb128DecryptEntry OK.")

    def PfsGenCryptoKey(self, ekpfs: bytes, seed: bytes, dataKey_buffer: bytearray, tweakKey_buffer: bytearray):
        # ... (implementazione come prima) ...
        if len(ekpfs) != 32 or len(seed) != 16 or len(dataKey_buffer) != 16 or len(tweakKey_buffer) != 16:
            self.logger("Errore PfsGenCryptoKey: dimensioni non valide."); return
        hmac_sha256 = HMAC.new(ekpfs, digestmod=SHA256)
        d_payload = struct.pack("<I", 1) + seed
        hmac_sha256.update(d_payload)
        digest = hmac_sha256.digest()
        tweakKey_buffer[:] = digest[0:16]; dataKey_buffer[:] = digest[16:32]
        # self.logger(f"Crypto: PfsGenCryptoKey OK.")

    def _xts_mult(self, tweak_block: bytearray):
        # ... (implementazione come prima) ...
        feedback = 0;
        for k in range(16):
            tmp = (tweak_block[k] >> 7) & 1
            tweak_block[k] = ((tweak_block[k] << 1) + feedback) & 0xFF
            feedback = tmp
        if feedback != 0: tweak_block[0] ^= 0x87


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
"""
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
        # ... (implementazione come prima) ...
        if len(ekpfs) != 32 or len(seed) != 16 or len(dataKey_buffer) != 16 or len(tweakKey_buffer) != 16:
            self.logger("Errore PfsGenCryptoKey: dimensioni non valide."); return
        hmac_sha256 = HMAC.new(ekpfs, digestmod=SHA256)
        d_payload = struct.pack("<I", 1) + seed
        hmac_sha256.update(d_payload)
        digest = hmac_sha256.digest()
        tweakKey_buffer[:] = digest[0:16]; dataKey_buffer[:] = digest[16:32]
        # self.logger(f"Crypto: PfsGenCryptoKey OK.")

    def _xts_mult(self, tweak_block: bytearray):
        # ... (implementazione come prima) ...
        feedback = 0;
        for k in range(16):
            tmp = (tweak_block[k] >> 7) & 1
            tweak_block[k] = ((tweak_block[k] << 1) + feedback) & 0xFF
            feedback = tmp
        if feedback != 0: tweak_block[0] ^= 0x87

    def decryptPFS(self, dataKey: bytes, tweakKey: bytes, src_image_block: bytes, dst_image_buffer: bytearray, sector_num: int):
        """Decrypt PFS blocks using optimized implementation for better performance."""
        block_size = 0x1000
        if not (len(dataKey)==16 and len(tweakKey)==16 and \
                len(src_image_block) % block_size == 0 and \
                len(dst_image_buffer) == len(src_image_block)):
            self.logger(f"Errore decryptPFS: dimensioni input/output non valide o src non multiplo di {block_size}."); return

        # Use optimized implementation for large blocks to improve performance
        if len(src_image_block) > block_size * 4:  # For larger data, use optimized version
            try:
                import numpy as np
                # Convert to numpy arrays for faster processing
                src_np = np.frombuffer(src_image_block, dtype=np.uint8)
                dst_np = np.frombuffer(dst_image_buffer, dtype=np.uint8)
                
                cipher_data = AES.new(dataKey, AES.MODE_ECB)
                cipher_tweak = AES.new(tweakKey, AES.MODE_ECB)
                num_main_blocks = len(src_image_block) // block_size
                
                # Process blocks in larger chunks (can be adjusted for optimal performance)
                chunk_size = min(16, num_main_blocks)  # Process multiple sectors at once
                
                for chunk_start in range(0, num_main_blocks, chunk_size):
                    chunk_end = min(chunk_start + chunk_size, num_main_blocks)
                    
                    for main_block_idx in range(chunk_start, chunk_end):
                        current_main_block_offset = main_block_idx * block_size
                        current_sector_for_tweak = sector_num + main_block_idx
                        
                        # Initialize tweak for this sector
                        tweak_initial_val = bytearray(16)
                        tweak_initial_val[0:8] = struct.pack("<Q", current_sector_for_tweak)
                        encrypted_tweak = bytearray(cipher_tweak.encrypt(bytes(tweak_initial_val)))
                        
                        # Process 16-byte blocks within the sector
                        for i in range(0, block_size, 16):
                            offset = current_main_block_offset + i
                            
                            # Extract current block
                            ct_block = src_np[offset:offset+16]
                            
                            # Fast XOR with numpy
                            xor_buf = np.bitwise_xor(ct_block, np.frombuffer(encrypted_tweak, dtype=np.uint8))
                            
                            # Decrypt
                            dec_interm = cipher_data.decrypt(xor_buf.tobytes())
                            
                            # Final XOR
                            pt_block = np.bitwise_xor(np.frombuffer(dec_interm, dtype=np.uint8), 
                                                   np.frombuffer(encrypted_tweak, dtype=np.uint8))
                            
                            # Store result
                            dst_np[offset:offset+16] = pt_block
                            
                            # Update tweak for next block
                            if i + 16 < block_size:
                                self._xts_mult(encrypted_tweak)
                
                # No need to copy back since we used a view into the original buffer
                return
                
            except ImportError:
                # If numpy isn't available, fall back to standard implementation
                pass
            except Exception as e:
                self.logger(f"Optimized decryptPFS fallback to standard: {e}")
                pass
        
        # Standard implementation (fallback)
        cipher_data = AES.new(dataKey, AES.MODE_ECB)
        cipher_tweak = AES.new(tweakKey, AES.MODE_ECB)
        num_main_blocks = len(src_image_block) // block_size
        
        # Use bytearray.fromhex for faster XOR operations
        for main_block_idx in range(num_main_blocks):
            current_main_block_offset = main_block_idx * block_size
            current_sector_for_tweak = sector_num + main_block_idx
            tweak_initial_val = bytearray(16)
            tweak_initial_val[0:8] = struct.pack("<Q", current_sector_for_tweak)
            encrypted_tweak = bytearray(cipher_tweak.encrypt(bytes(tweak_initial_val)))
            
            # Process multiple blocks at once if possible
            for i in range(0, block_size, 16):
                aes_block_offset_in_src = current_main_block_offset + i
                ct_sub_block = src_image_block[aes_block_offset_in_src:aes_block_offset_in_src+16]
                
                # Faster XOR operation with bytes
                xor_buf = bytes(a ^ b for a, b in zip(ct_sub_block, encrypted_tweak))
                dec_interm = cipher_data.decrypt(xor_buf)
                pt_sub_block = bytes(a ^ b for a, b in zip(dec_interm, encrypted_tweak))
                
                dst_image_buffer[aes_block_offset_in_src:aes_block_offset_in_src+16] = pt_sub_block
                
                if i + 16 < block_size:
                    self._xts_mult(encrypted_tweak)

    def decryptEFSM(self, trophyKey: bytes, NPcommID: bytes, efsmIv: bytes, ciphertext: bytes, decrypted_buffer: bytearray):
        # ... (implementazione come prima) ...
        if not (len(trophyKey) == 16 and len(NPcommID) == 16 and len(efsmIv) == 16 and \
                len(ciphertext) % AES.block_size == 0 and len(decrypted_buffer) == len(ciphertext)):
            self.logger("Errore decryptEFSM: dimensioni non valide."); return
        trophy_iv_zeros = b'\0' * 16
        cipher1 = AES.new(trophyKey, AES.MODE_CBC, trophy_iv_zeros)
        trpKey = cipher1.encrypt(NPcommID)
        cipher2 = AES.new(trpKey, AES.MODE_CBC, efsmIv)
        decrypted_buffer[:] = cipher2.decrypt(ciphertext)
        # self.logger(f"Crypto: decryptEFSM OK.")

# --- PKG Class (con logica PFS migliorata) ---
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
        self.pkg_path = filepath
        self._log(f"Inizio estrazione da: {filepath} a GUI base: {extract_base_path_gui}")
        pfsc_content_actual_bytes = b'' # Initialize to ensure it's always defined
        # Removing problematic try block and using with statement's own error handling
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
                        except Exception as e_dbg:
                            self._log(f"DEBUG: Errore salvataggio chunk decrittato: {e_dbg}")
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
                            
                            total_pfsc_span_in_pfs_image = self.pfsc_offset_in_pfs_image + estimated_pfsc_internal_content_size
                            total_len_to_read_for_full_pfsc_aligned = ((total_pfsc_span_in_pfs_image + 0xFFF) // 0x1000) * 0x1000
                            
                            self._log(f"Dimensione interna PFSC stimata: {estimated_pfsc_internal_content_size}. Totale da leggere/decrittare per PFSC completo: {total_len_to_read_for_full_pfsc_aligned}")

                            f.seek(self.pkg_header.pfs_image_offset)
                            full_pfs_chunk_for_pfsc_processing = f.read(min(total_len_to_read_for_full_pfsc_aligned, self.pkg_header.pfs_image_size))
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
                            
                            decompressed_superblock_data = decompress_pfsc(super_block_compressed_data, len(decomp_block_buf), self._log)
                            
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
                            decompressed_inode_data = decompress_pfsc(compressed_inode_block_data, len(decomp_block_buf), self._log)
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
                    
                    # Logica migliorata per determinare root_dir_inode_num
                    if self.pfs_superblock_header:
                        actual_total_inodes = self.pfs_superblock_header.dinode_count
                        root_dir_inode_num = self.pfs_superblock_header.superroot_ino
                        self._log(f"Dal superblocco PFS: actual_total_inodes={actual_total_inodes}, superroot_ino={root_dir_inode_num}")
                    else:
                        actual_total_inodes = 0 # Non possiamo fidarci se il superblocco non è stato letto
                        root_dir_inode_num = 0

                    if actual_total_inodes == 0 and self.iNodeBuf: # Se ndinode era 0 ma abbiamo letto inodes
                        actual_total_inodes = len(self.iNodeBuf)
                        self._log(f"AVVISO: ndinode_total_count era 0, ma iNodeBuf ha {len(self.iNodeBuf)} elementi. Uso len(iNodeBuf).")

                    # Logica migliorata di fallback per root_dir_inode_num
                    if root_dir_inode_num <= 0 or root_dir_inode_num > actual_total_inodes: # Inode 0 non è valido
                        self._log(f"superroot_ino ({root_dir_inode_num}) non valido. Tentativo di fallback.")
                        
                        # Tentativo 1: Usa inode 2 se esiste ed è una directory (comune nei filesystem Unix)
                        potential_root_idx = 2 - 1 # Indice per iNodeBuf (0-based)
                        if 0 <= potential_root_idx < len(self.iNodeBuf) and \
                           self.iNodeBuf[potential_root_idx].get_file_type() == PFSFileType.PFS_DIR and \
                           self.iNodeBuf[potential_root_idx].Blocks > 0:
                            root_dir_inode_num = 2
                            self._log(f"Fallback: Uso inode 2 come root (trovato e directory).")
                        else:
                            # Tentativo 2: Cerca il primo inode directory valido
                            found_fallback_root = False
                            for idx, inode_entry in enumerate(self.iNodeBuf):
                                inode_num_candidate = idx + 1 # Assumendo 1-based per il numero di inode
                                if inode_entry.get_file_type() == PFSFileType.PFS_DIR and inode_entry.Blocks > 0:
                                    # Prendi il primo inode directory con blocchi
                                    root_dir_inode_num = inode_num_candidate
                                    self._log(f"Fallback: Trovato primo inode directory valido ({root_dir_inode_num}) come potenziale root.")
                                    found_fallback_root = True
                                    break
                            if not found_fallback_root and self.iNodeBuf:
                                root_dir_inode_num = 1 # Ultima spiaggia
                    
                    # Verifica finale della root
                    if root_dir_inode_num <= 0 or root_dir_inode_num > len(self.iNodeBuf):
                        self._log(f"ERRORE CRITICO: Impossibile determinare root inode PFS valido. Root num: {root_dir_inode_num}, iNodeBuf len: {len(self.iNodeBuf)}")
                    elif self.iNodeBuf[root_dir_inode_num-1].get_file_type() != PFSFileType.PFS_DIR:
                        self._log(f"AVVISO: Root inode PFS determinato ({root_dir_inode_num}) non è una directory standard, ma procediamo comunque.")
                    
                    # Processa la directory radice usando BFS
                    self._process_pfs_directory_bfs(root_dir_inode_num, self.extract_base_path)
                    self._log(f"Completato parsing ricorsivo. Trovate {len(self.fs_table)} voci in fs_table.")

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
        
        # Basato sulla logica C++ descritta dall'utente
        offset = 0
        ndinode_counter = 0  # Inode della directory a cui appartengono le entry in flat_path_table
        
        # Prima cerchiamo entry speciali (ino != 0) che possono contenere informazioni sulla struttura
        while offset < len(flat_path_data):
            if len(flat_path_data) - offset < Dirent._SIZE_BASE:
                self._log(f"  FINE FLAT_PATH_TABLE: dimensione rimanente {len(flat_path_data) - offset} < {Dirent._SIZE_BASE}")
                break
                
            dirent = Dirent.from_bytes(flat_path_data[offset:])
            self._log(f"  FPT Entry: offset=0x{offset:x}, ino={dirent.ino}, type={dirent.type}, "
                     f"namelen={dirent.namelen}, entsize={dirent.entsize}, name='{dirent.name}'")
            
            if dirent.entsize == 0:
                self._log(f"  FINE FLAT_PATH_TABLE: trovata dirent con entsize=0")
                break
                
            if dirent.ino != 0:
                # Entry speciale (probabilmente metadati o entry . e ..)
                ndinode_counter = dirent.ino  # Salva l'ultimo inode counter
                self._log(f"  METADATO: Aggiornato ndinode_counter a {ndinode_counter}")
            else:
                # Trovata la prima entry con ino=0, il che segna l'inizio delle vere entry di file/directory
                self._log(f"  MARKER: Trovata entry con ino=0. Inizio delle vere entry di file/directory")
                offset += dirent.entsize
                break
                
            offset += dirent.entsize
        
        # Da qui, leggiamo le vere entry di file/directory (dopo il marker ino=0)
        self._log(f"\n  INIZIO PARSING ENTRY REALI (offset=0x{offset:x}, parent_inode={ndinode_counter})")
        
        # Leggi e processa le entry reali
        real_entries = []
        while offset < len(flat_path_data):
            if len(flat_path_data) - offset < Dirent._SIZE_BASE:
                break
                
            dirent = Dirent.from_bytes(flat_path_data[offset:])
            if dirent.entsize == 0 or dirent.ino == 0:
                break
                
            entry_name = dirent.name
            entry_inode_num = dirent.ino
            entry_type = dirent.get_pfs_file_type()
            
            self._log(f"  ENTRY REALE: '{entry_name}' (inode {entry_inode_num}), type={dirent.type} -> {entry_type.name}")
            
            # Aggiungi alla fs_table e all'elenco delle entry reali
            self.fs_table.append(FSTableEntry(entry_name, entry_inode_num, entry_type))
            real_entries.append((entry_name, entry_inode_num, entry_type))
            
            # Imposta il percorso di estrazione
            entry_path = parent_path / entry_name
            self.extract_paths[entry_inode_num] = entry_path
            
            # Crea directory se necessario
            if entry_type == PFSFileType.PFS_DIR:
                self._log(f"  CREAZIONE DIR: '{entry_path}'")
                entry_path.mkdir(parents=True, exist_ok=True)
                
                # Accoda per il BFS se è una directory
                # Note: Non usiamo visited_dirs_for_bfs qui poiché queste sono le vere entry
                # e vogliamo processarle tutte indipendentemente da uroot
                queue = getattr(self, 'bfs_queue', [])
                if hasattr(self, 'bfs_queue'):
                    queue.append((entry_inode_num, entry_path))
                    self._log(f"  ACCODATO per BFS: inode {entry_inode_num} ('{entry_path}')")
            
            offset += dirent.entsize
        
        self._log(f"Fine parsing flat_path_table. Trovate {len(real_entries)} entry reali.\n")
        return real_entries

    def _process_flat_path_table(self, flat_path_data, parent_path):
        """Processa un flat_path_table trovato nell'inode 'uroot'.
        
        Args:
            flat_path_data (bytes): I dati decompressati del flat_path_table
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
        
        # Basato sulla logica C++ descritta dall'utente
        offset = 0
        ndinode_counter = 0  # Inode della directory a cui appartengono le entry in flat_path_table
        
        # Prima cerchiamo entry speciali (ino != 0) che possono contenere informazioni sulla struttura
        while offset < len(flat_path_data):
            if len(flat_path_data) - offset < Dirent._SIZE_BASE:
                self._log(f"  FINE FLAT_PATH_TABLE: dimensione rimanente {len(flat_path_data) - offset} < {Dirent._SIZE_BASE}")
                break
                
            dirent = Dirent.from_bytes(flat_path_data[offset:])
            self._log(f"  FPT Entry: offset=0x{offset:x}, ino={dirent.ino}, type={dirent.type}, "
                     f"namelen={dirent.namelen}, entsize={dirent.entsize}, name='{dirent.name}'")
            
            if dirent.entsize == 0:
                self._log(f"  FINE FLAT_PATH_TABLE: trovata dirent con entsize=0")
                break
                
            if dirent.ino != 0:
                # Entry speciale (probabilmente metadati o entry . e ..)
                ndinode_counter = dirent.ino  # Salva l'ultimo inode counter
                self._log(f"  METADATO: Aggiornato ndinode_counter a {ndinode_counter}")
            else:
                # Trovata la prima entry con ino=0, il che segna l'inizio delle vere entry di file/directory
                self._log(f"  MARKER: Trovata entry con ino=0. Inizio delle vere entry di file/directory")
                offset += dirent.entsize
                break
                
            offset += dirent.entsize
        
        # Da qui, leggiamo le vere entry di file/directory (dopo il marker ino=0)
        self._log(f"\n  INIZIO PARSING ENTRY REALI (offset=0x{offset:x}, parent_inode={ndinode_counter})")
        
        # Leggi e processa le entry reali
        real_entries = []
        while offset < len(flat_path_data):
            if len(flat_path_data) - offset < Dirent._SIZE_BASE:
                break
                
            dirent = Dirent.from_bytes(flat_path_data[offset:])
            if dirent.entsize == 0 or dirent.ino == 0:
                break
                
            entry_name = dirent.name
            entry_inode_num = dirent.ino
            entry_type = dirent.get_pfs_file_type()
            
            self._log(f"  ENTRY REALE: '{entry_name}' (inode {entry_inode_num}), type={dirent.type} -> {entry_type.name}")
            
            # Aggiungi alla fs_table e all'elenco delle entry reali
            self.fs_table.append(FSTableEntry(entry_name, entry_inode_num, entry_type))
            real_entries.append((entry_name, entry_inode_num, entry_type))
            
            # Imposta il percorso di estrazione
            entry_path = parent_path / entry_name
            self.extract_paths[entry_inode_num] = entry_path
            
            # Crea directory se necessario
            if entry_type == PFSFileType.PFS_DIR:
                self._log(f"  CREAZIONE DIR: '{entry_path}'")
                entry_path.mkdir(parents=True, exist_ok=True)
                
                # Accoda per il BFS se è una directory
                # Note: Non usiamo visited_dirs_for_bfs qui poiché queste sono le vere entry
                # e vogliamo processarle tutte indipendentemente da uroot
                if hasattr(self, 'bfs_queue'):
                    self.bfs_queue.append((entry_inode_num, entry_path))
                    self._log(f"  ACCODATO per BFS: inode {entry_inode_num} ('{entry_path}')")
            
            offset += dirent.entsize
        
        self._log(f"Fine parsing flat_path_table. Trovate {len(real_entries)} entry reali.\n")
        return real_entries

    def _process_pfs_directory_bfs(self, root_dir_inode_num, current_output_path):
        """Processa la directory del PFS in modo BFS (breadth-first search).
        
        Args:
            root_dir_inode_num (int): Numero di inode della directory root da cui iniziare
            current_output_path (Path): Path di output per i file estratti
        """
        self._log(f"Inizio parsing ricorsivo (BFS) delle directory da root inode {root_dir_inode_num}")
        
        # Assicura che la directory di output esista
        self.extract_base_path.mkdir(parents=True, exist_ok=True)
        self.extract_paths[root_dir_inode_num] = self.extract_base_path
        
        # Inizializza una coda BFS con la root directory
        queue = [(root_dir_inode_num, current_output_path)]
        self.bfs_queue = queue  # Salva la coda nell'oggetto per permettere accesso da _process_flat_path_table
        visited_dirs_for_bfs = set([root_dir_inode_num])
        
        # Buffer per decompressione blocchi dirent
        decomp_block_buf_size = self.pfs_chdr.block_sz2 if self.pfs_chdr.block_sz2 > 0 else 0x10000
        decomp_block_buf = bytearray(decomp_block_buf_size)
        
        # Ciclo principale BFS
        while queue:
            current_dir_inode_num, current_dir_path = queue.pop(0)
            dir_inode_idx = current_dir_inode_num - 1
            
            if not (0 <= dir_inode_idx < len(self.iNodeBuf)):
                self._log(f"    ERRORE BFS: Inode {current_dir_inode_num} fuori limite (len iNodeBuf={len(self.iNodeBuf)}). Salto.")
                continue
                
            dir_inode_obj = self.iNodeBuf[dir_inode_idx]
            self._log(f"  BFS: Processo directory inode {current_dir_inode_num} ('{current_dir_path}')")
            
            # Ottieni file_type dall'inode
            file_type = dir_inode_obj.get_file_type()
            self._log(f"    BFS: Inode {current_dir_inode_num} (idx {dir_inode_idx}) ha Mode={dir_inode_obj.Mode:#06x}, "
                     f"Tipo dedotto={file_type.name if file_type else 'None'}, Size={dir_inode_obj.Size}, "
                     f"Blocks={dir_inode_obj.Blocks}, Loc={dir_inode_obj.loc}")
            
            # Se l'inode non sembra essere una directory secondo Mode, ma è stato messo in coda dal BFS,
            # significa che il suo Dirent.type lo indica come directory, e ci fidiamo di quello.
            # Questo è necessario per directory speciali come 'uroot' che hanno Mode=0x816d (PFS_FILE)
            # ma sono effettivamente directory.
            if file_type != PFSFileType.PFS_DIR:
                self._log(f"    AVVISO BFS: Inode {current_dir_inode_num} non sembra una directory secondo Mode={dir_inode_obj.Mode:#06x} "
                         f"(Tipo={file_type.name if file_type else 'None'}), ma è stato messo in coda come directory, "
                         f"quindi procediamo comunque.")
            
            first_block_idx_for_dir_in_map = dir_inode_obj.loc
            num_blocks_for_dir = dir_inode_obj.Blocks
            
            self._log(f"    Dir Inode {current_dir_inode_num}: loc={first_block_idx_for_dir_in_map}, blocks={num_blocks_for_dir}, size={dir_inode_obj.Size}")
            
            # Processa blocchi di dati della directory
            for i_dir_block in range(num_blocks_for_dir):
                # map_idx_dir è l'indice nella self.sector_map
                map_idx_dir = first_block_idx_for_dir_in_map + i_dir_block
                
                if map_idx_dir >= len(self.sector_map) - 1:
                    self._log(f"      AVVISO BFS: Indice mappa {map_idx_dir} fuori limiti per dirent di inode {current_dir_inode_num}. Ultimo blocco processato."); break
                
                # block_offset_in_pfsc è l'offset del blocco (compresso) relativo all'inizio di pfsc_content_actual_bytes
                block_offset_in_pfsc = self.sector_map[map_idx_dir]
                block_csize = self.sector_map[map_idx_dir + 1] - block_offset_in_pfsc
                
                self._log(f"      Blocco dirent {i_dir_block} (map_idx {map_idx_dir}): offset_in_pfsc_content={block_offset_in_pfsc:#x}, csize={block_csize:#x}")

                if block_offset_in_pfsc + block_csize > len(self.pfsc_content_actual_bytes):
                    self._log(f"      ERRORE BFS: Lettura fuori limiti per blocco dirent {i_dir_block} di inode {current_dir_inode_num}. "
                             f"Accesso a {block_offset_in_pfsc + block_csize} in buffer di {len(self.pfsc_content_actual_bytes)}"); break
                if block_csize == 0: 
                    self._log(f"      Blocco dirent {i_dir_block} ha csize 0. Salto."); continue

                compressed_dir_block_data = self.pfsc_content_actual_bytes[block_offset_in_pfsc : block_offset_in_pfsc + block_csize]
                
                try:
                    decompressed_data = decompress_pfsc(compressed_dir_block_data, decomp_block_buf_size, self._log)
                    if not any(decompressed_data) and any(compressed_dir_block_data):
                        self._log(f"      AVVISO BFS: Blocco dirent {i_dir_block} per inode {current_dir_inode_num} decompresso a zeri. "
                                 f"Dati compressi (primi 32B): {compressed_dir_block_data[:32].hex()}")
                        continue
                    
                    # Salva il blocco dirent decompresso per la directory root (inode 1) o uroot (inode 2)
                    if current_dir_inode_num == 1 or current_dir_inode_num == 2:
                        block_type = "ROOT" if current_dir_inode_num == 1 else "UROOT"
                        debug_block_path = self.extract_base_path / f"debug_{block_type}_BLOCK_inode{current_dir_inode_num}_block{i_dir_block}.bin"
                        try:
                            with open(debug_block_path, "wb") as dbg_f:
                                dbg_f.write(decompressed_data)
                            self._log(f"DEBUG: Blocco decompresso per inode {current_dir_inode_num} ({block_type}, blocco {i_dir_block}) salvato: {debug_block_path}")
                            
                            # Se è l'inode 2 (uroot), controllo anche se contiene "flat_path_table"
                            if current_dir_inode_num == 2 and len(decompressed_data) > 0x20:
                                # Cerca la stringa "flat_path_table" a vari offset
                                for offset in [0, 0x10, 0x20]:
                                    if len(decompressed_data) > offset + 15:
                                        potential_fpt = decompressed_data[offset:offset+15]
                                        if b"flat_path_table" in potential_fpt:
                                            self._log(f"DEBUG: Trovato 'flat_path_table' nell'inode 2 (uroot) all'offset 0x{offset:x}")
                        except Exception as e_dbg_f:
                            self._log(f"DEBUG: Errore salvataggio blocco: {e_dbg_f}")
                except Exception as e_dec:
                    self._log(f"      ERRORE BFS: Decompressione fallita per blocco dirent {i_dir_block} di inode {current_dir_inode_num}: {e_dec}"); continue
                
                actual_decomp_len_dir = len(decompressed_data)

                offset_in_dir_block = 0
                while offset_in_dir_block < actual_decomp_len_dir:
                    if actual_decomp_len_dir - offset_in_dir_block < Dirent._SIZE_BASE: break
                    
                    dirent = Dirent.from_bytes(decompressed_data[offset_in_dir_block:])
                    
                    # Log dettagliato per tutti i campi della dirent, specialmente per inode 1 (root) e 2 (uroot)
                    if current_dir_inode_num == 1 or current_dir_inode_num == 2:  # Logga solo per root e uroot
                        name_bytes_hex = dirent.name_bytes[:dirent.namelen].hex() if hasattr(dirent, 'name_bytes') else 'N/A'
                        self._log(f"        Raw Dirent Data: offset={offset_in_dir_block:#06x}, ino={dirent.ino}, type={dirent.type}, namelen={dirent.namelen}, "
                                 f"entsize={dirent.entsize}, name_raw='{name_bytes_hex}', name_str='{dirent.name}'")
                        # Dump hex dei primi 32 byte della dirent per debug
                        dirent_bytes = decompressed_data[offset_in_dir_block:offset_in_dir_block+min(32, dirent.entsize or 32)]
                        self._log(f"        Dirent Hex: {dirent_bytes.hex()}")
                    
                    if dirent.entsize == 0 or dirent.ino == 0:
                        self._log(f"        TERMINAZIONE LOOP: dirent.entsize={dirent.entsize}, dirent.ino={dirent.ino}")
                        break
                    
                    entry_name = dirent.name
                    entry_inode_num = dirent.ino
                    entry_pfs_type_from_dirent = dirent.get_pfs_file_type() # Basato su dirent.type
                    
                    # Logga il tipo dalla dirent
                    self._log(f"      Dirent: '{entry_name}' (inode {entry_inode_num}), Dirent.type={dirent.type} -> PFSFileType.{entry_pfs_type_from_dirent.name}")
                    
                    # Gestione speciale per uroot: se troviamo flat_path_table
                    if current_dir_inode_num == 2 and entry_name == "flat_path_table":
                        self._log(f"      TROVATO flat_path_table nell'inode uroot! Attivazione parsing speciale per flat_path_table.")
                        self._process_flat_path_table(decompressed_data, current_dir_path)
                        # Una volta processato il flat_path_table, interrompiamo il parsing normale delle dirent
                        # poiché il resto dei dati deve essere interpretato in modo diverso
                        break
                    
                    if entry_name in [".", ".."]:
                        offset_in_dir_block += dirent.entsize; continue
                    
                    if not (0 <= entry_inode_num - 1 < len(self.iNodeBuf)):
                        self._log(f"        AVVISO BFS: Dirent '{entry_name}' punta a inode {entry_inode_num} che non è in iNodeBuf (len {len(self.iNodeBuf)}). Salto.");
                        offset_in_dir_block += dirent.entsize; continue

                    # Se è una directory secondo la dirent, logga anche il Mode dell'inode corrispondente
                    if entry_pfs_type_from_dirent == PFSFileType.PFS_DIR:
                        target_inode_obj = self.iNodeBuf[entry_inode_num -1]
                        self._log(f"        -> Inode {entry_inode_num} associato ha Mode={target_inode_obj.Mode:#06x} (Tipo dedotto da Mode: {target_inode_obj.get_file_type().name})")
                    
                    # Solo aggiungi a fs_table se non già presente (per inode number)
                    # Questo potrebbe non essere necessario se la visita è strettamente gerarchica senza re-visitare
                    # if not any(fe.inode == entry_inode_num for fe in self.fs_table):
                    self.fs_table.append(FSTableEntry(entry_name, entry_inode_num, entry_pfs_type_from_dirent))
                    
                    current_entry_path = current_dir_path / entry_name
                    self.extract_paths[entry_inode_num] = current_entry_path

                    if entry_pfs_type_from_dirent == PFSFileType.PFS_DIR: # Usa il tipo dalla dirent per accodare
                        if entry_inode_num not in visited_dirs_for_bfs:
                            self._log(f"        Trovata subdir: '{current_entry_path}' (inode {entry_inode_num})")
                            current_entry_path.mkdir(parents=True, exist_ok=True)
                            queue.append((entry_inode_num, current_entry_path))
                            visited_dirs_for_bfs.add(entry_inode_num)
                    else:
                        self._log(f"        Trovato file: '{current_entry_path}' (inode {entry_inode_num})")
                        
                    offset_in_dir_block += dirent.entsize
        
        self._log(f"Completato parsing ricorsivo. Trovate {len(self.fs_table)} voci in fs_table.")
        
        # Se siamo arrivati qui, il metodo extract è stato completato.
        # Il messaggio di ritorno dovrebbe riflettere lo stato del parsing PFS.
        if self.pfsc_offset_in_pfs_image == -1 or not self.pfs_chdr or not self.fs_table :
            return True, "Estrazione file di sistema completata. Parsing PFS fallito o PFS non presente/vuoto."
        else:
            return True, "Analisi PKG e parsing PFS completati. Estrazione file PFS seguirà."


    def _read_decrypt_decompress_pfs_block(self, 
                                         block_map_idx: int, 
                                         is_compressed_flag: bool, 
                                         pkg_file_handle, 
                                         decomp_buffer: bytearray) -> tuple[Optional[bytes], str]:
        # ... (codice esistente non modificato)
        pass # Added pass to make the function syntactically correct

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
        
        except IOError as e: self._log(f"Errore I/O estrazione PFS: {e}"); return False, f"Errore I/O: {e}"
        except Exception as e:
            self._log(f"Errore generico estrazione PFS: {e}"); import traceback; self._log(traceback.format_exc()); return False, f"Errore: {e}"

    # Note: This duplicate implementation has been removed because it conflicted with the one at line ~2301
    # and was causing a KeyError when trying to access self.extract_paths[root_inode_num]

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
