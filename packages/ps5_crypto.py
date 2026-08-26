"""PS5 package key derivation (EKPFS, PFS image keys).

Pure-Python port of LibProsperoPkg's ``pfs_keys`` primitives (C++ ``src/src/pfs_keys.cpp``,
C# ``PFS/ProsperoPfsKeys.cs``):

* ``derive_ekpfs``   -- the 32-byte package key used to mount PS5 PFS images.
  SHA3-256 schedule with key index 1.
* ``pfs_gen_crypto_key`` / ``derive_pfs_encryption_keys`` -- the AES-XTS
  (tweak, data) key pair derived from the EKPFS plus the superblock seed.
* ``derive_image_encryption_keys`` -- the ``new_crypt`` schedule used by the
  PS5 finalized (nwonly) outer image: base key = HMAC-SHA256(EKPFS, seed).

The reference derivation (C++ ``compute_package_key``, ``PackageKeyDigest::sha3_256``):

    index_hash   = SHA3-256(BE32(index))                      # index = 1
    content_hash = SHA3-256(content_id padded to 48 bytes)
    data         = index_hash || content_hash || passcode     # 96 bytes
    EKPFS        = SHA3-256(data)
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from .exceptions import PackageFormatError


CONTENT_ID_LENGTH = 36
PASSCODE_LENGTH = 32
PADDED_CONTENT_ID_LENGTH = 48
EKPFS_LENGTH = 32
SEED_LENGTH = 16


def _validate_content_id(content_id: str) -> bytes:
    if not isinstance(content_id, str) or len(content_id) != CONTENT_ID_LENGTH:
        raise PackageFormatError("PS5 content ID must contain exactly 36 characters")
    try:
        return content_id.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PackageFormatError("PS5 content ID is not ASCII") from exc


def _validate_passcode(passcode: str) -> bytes:
    if not isinstance(passcode, str) or len(passcode) != PASSCODE_LENGTH:
        raise PackageFormatError("PS5 passcode must contain exactly 32 ASCII characters")
    try:
        return passcode.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PackageFormatError("PS5 passcode must be ASCII") from exc


def compute_package_key(content_id: str, passcode: str, index: int,
                        *, sha3: bool = False) -> bytes:
    """Derive one of the PS5 package keys.

    ``sha3=False`` reproduces the classic SHA-256 schedule (index 0/1 used for
    the entry-key material); ``sha3=True`` selects the PS5 SHA3-256 schedule
    used for the EKPFS.
    """
    content_bytes = _validate_content_id(content_id)
    passcode_bytes = _validate_passcode(passcode)
    digest = hashlib.sha3_256 if sha3 else hashlib.sha256

    index_digest = digest(struct.pack(">I", index)).digest()
    padded = content_bytes.ljust(PADDED_CONTENT_ID_LENGTH, b"\0")
    content_digest = digest(padded).digest()
    data = index_digest + content_digest + passcode_bytes
    return digest(data).digest()


def derive_ekpfs(content_id: str, passcode: str) -> bytes:
    """Return the 32-byte PS5 EKPFS for a content ID + passcode.

    Matches LibProsperoPkg ``derive_ekpfs`` (SHA3-256 schedule, index 1).
    """
    return compute_package_key(content_id, passcode, 1, sha3=True)


def pfs_gen_crypto_key(ekpfs: bytes, seed: bytes, index: int = 1) -> bytes:
    """HMAC-SHA256(EKPFS, LE32(index) || seed) -- the PFS crypto key."""
    if len(ekpfs) != EKPFS_LENGTH or len(seed) != SEED_LENGTH:
        raise ValueError("EKPFS must be 32 bytes and the PFS seed must be 16 bytes")
    message = struct.pack("<I", index) + seed
    return hmac.new(ekpfs, message, hashlib.sha256).digest()


def derive_pfs_encryption_keys(ekpfs: bytes, seed: bytes, *,
                               new_crypt: bool = False) -> tuple[bytes, bytes]:
    """Return the AES-XTS (tweak, data) key pair for an encrypted PFS image.

    ``new_crypt=True`` applies the HMAC-EKPFS base-key schedule used by the
    PS5 finalized outer image; ``False`` uses the raw EKPFS (inner image /
    classic path).
    """
    if len(ekpfs) != EKPFS_LENGTH or len(seed) != SEED_LENGTH:
        raise ValueError("EKPFS must be 32 bytes and the PFS seed must be 16 bytes")
    base_key = hmac.new(ekpfs, seed, hashlib.sha256).digest() if new_crypt else ekpfs
    enc_key = pfs_gen_crypto_key(base_key, seed, 1)
    return enc_key[:16], enc_key[16:]


def derive_image_encryption_keys(ekpfs: bytes, seed: bytes) -> tuple[bytes, bytes]:
    """AES-XTS (tweak, data) keys for the PS5 finalized outer image (new_crypt)."""
    return derive_pfs_encryption_keys(ekpfs, seed, new_crypt=True)
