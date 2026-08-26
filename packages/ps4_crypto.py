"""PS4 PKG passcode derivation and entry decryption.

The package passcode is verified against ENTRY_KEYS before it is ever used for
extraction.  This keeps manual entry and brute-force attempts on the same,
format-defined cryptographic path.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from Crypto.Cipher import AES

from .exceptions import PackageFormatError


PASSCODE_LENGTH = 32
CONTENT_ID_LENGTH = 36
ENTRY_KEYS_ID = 0x0010
ENTRY_KEYS_SIZE = 0x800
ENTRY_KEY_COUNT = 7


def validate_passcode(passcode: str) -> bytes:
    if not isinstance(passcode, str) or len(passcode) != PASSCODE_LENGTH:
        raise ValueError("Passcode must contain exactly 32 ASCII characters")
    try:
        return passcode.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Passcode must contain ASCII characters only") from exc


def derive_key(content_id: str, passcode: str, index: int) -> bytes:
    """Derive one of the seven PS4 package keys."""
    if not isinstance(content_id, str) or len(content_id) != CONTENT_ID_LENGTH:
        raise PackageFormatError("PS4 content ID must contain exactly 36 characters")
    if not 0 <= index < ENTRY_KEY_COUNT:
        raise ValueError("Derived-key index must be between 0 and 6")
    passcode_bytes = validate_passcode(passcode)
    try:
        content_bytes = content_id.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PackageFormatError("PS4 content ID is not ASCII") from exc

    index_digest = hashlib.sha256(struct.pack(">I", index)).digest()
    content_digest = hashlib.sha256(content_bytes.ljust(48, b"\0")).digest()
    return hashlib.sha256(index_digest + content_digest + passcode_bytes).digest()


def derived_key_digest(key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("A PS4 derived key must contain exactly 32 bytes")
    return bytes(left ^ right for left, right in zip(hashlib.sha256(key).digest(), key))


def parse_entry_key_digests(data: bytes) -> tuple[bytes, ...]:
    """Read the seven verification digests from an ENTRY_KEYS payload."""
    minimum = 32 + ENTRY_KEY_COUNT * 32
    if len(data) < minimum:
        raise PackageFormatError(
            f"ENTRY_KEYS is truncated: expected at least {minimum} bytes, got {len(data)}"
        )
    return tuple(data[32 + i * 32:64 + i * 32] for i in range(ENTRY_KEY_COUNT))


def verify_passcode(content_id: str, passcode: str, digests: tuple[bytes, ...]) -> bool:
    if len(digests) != ENTRY_KEY_COUNT or any(len(item) != 32 for item in digests):
        raise PackageFormatError("ENTRY_KEYS does not contain seven valid digests")
    key = derive_key(content_id, passcode, 0)
    return hmac.compare_digest(derived_key_digest(key), digests[0])


def entry_meta_bytes(entry: dict) -> bytes:
    """Serialize the exact 0x20-byte metadata record used for entry crypto."""
    try:
        return struct.pack(
            ">6IQ",
            entry["id"],
            entry.get("name_table_offset", entry.get("fn_offset", 0)),
            entry["flags1"],
            entry["flags2"],
            entry["offset"],
            entry["size"],
            entry.get("padding", 0),
        )
    except (KeyError, TypeError, struct.error) as exc:
        raise PackageFormatError("Invalid PS4 entry metadata for decryption") from exc


def decrypt_entry(data: bytes, content_id: str, passcode: str, entry: dict) -> bytes:
    """Decrypt a block-aligned encrypted CNT metadata entry."""
    if not entry.get("encrypted"):
        return data
    if not data or len(data) % AES.block_size:
        raise PackageFormatError(
            f"Encrypted entry 0x{entry.get('id', 0):04X} is not AES block aligned"
        )
    seed = derive_key(content_id, passcode, int(entry.get("key_idx", 0)))
    iv_key = hashlib.sha256(entry_meta_bytes(entry) + seed).digest()
    return AES.new(iv_key[16:], AES.MODE_CBC, iv_key[:16]).decrypt(data)


def pfs_keys(ekpfs: bytes, seed: bytes, *, new_crypto: bool = False) -> tuple[bytes, bytes]:
    """Return the AES-XTS (tweak, data) keys for an encrypted PFS image."""
    if len(ekpfs) != 32 or len(seed) != 16:
        raise ValueError("EKPFS must be 32 bytes and the PFS seed must be 16 bytes")
    base = hmac.new(ekpfs, seed, hashlib.sha256).digest() if new_crypto else ekpfs
    material = hmac.new(base, struct.pack("<I", 1) + seed, hashlib.sha256).digest()
    return material[:16], material[16:]


def xts_crypt_sector(data: bytes, data_key: bytes, tweak_key: bytes,
                     sector_number: int, *, decrypt: bool) -> bytes:
    """Apply PS4 AES-XTS-128 to one complete sector."""
    if len(data) % AES.block_size:
        raise ValueError("XTS sector must be AES block aligned")
    if len(data_key) != 16 or len(tweak_key) != 16:
        raise ValueError("AES-XTS-128 requires two 16-byte keys")
    tweak = bytearray(AES.new(tweak_key, AES.MODE_ECB).encrypt(
        struct.pack("<Q", sector_number) + b"\0" * 8
    ))
    cipher = AES.new(data_key, AES.MODE_ECB)
    output = bytearray(len(data))
    for offset in range(0, len(data), AES.block_size):
        block = bytes(value ^ tweak[i] for i, value in enumerate(data[offset:offset + 16]))
        transformed = cipher.decrypt(block) if decrypt else cipher.encrypt(block)
        output[offset:offset + 16] = bytes(value ^ tweak[i] for i, value in enumerate(transformed))
        carry = 0
        for index in range(16):
            value = tweak[index]
            tweak[index] = ((value << 1) & 0xFF) | carry
            carry = value >> 7
        if carry:
            tweak[0] ^= 0x87
    return bytes(output)
