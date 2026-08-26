"""Explicit AES-CBC helpers retained for non-PKG utility compatibility.

PKG/PFS decryption must not use these as a whole-file transform. Callers must
provide the format-defined IV; this module never generates one implicitly.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


AES_KEY_LEN_128 = 16


class AES_ctx:
    def __init__(self):
        self.key = None
        self.iv = None

    def set_key(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes")
        self.key = bytes(key)

    def set_iv(self, iv):
        if len(iv) != AES.block_size:
            raise ValueError("AES-CBC IV must be exactly 16 bytes")
        self.iv = bytes(iv)

    def _cipher(self):
        if self.key is None or self.iv is None:
            raise ValueError("AES key and IV must be set explicitly")
        return AES.new(self.key, AES.MODE_CBC, self.iv)

    def encrypt(self, data, *, use_padding=True):
        source = pad(data, AES.block_size) if use_padding else data
        if len(source) % AES.block_size:
            raise ValueError("AES-CBC input must be block aligned")
        return self._cipher().encrypt(source)

    def decrypt(self, data, *, remove_padding=False):
        if len(data) % AES.block_size:
            raise ValueError("AES-CBC ciphertext must be block aligned")
        plaintext = self._cipher().decrypt(data)
        return unpad(plaintext, AES.block_size) if remove_padding else plaintext


def AES_set_key(ctx, key, key_len):
    if key_len not in (16, 24, 32) or len(key) < key_len:
        raise ValueError("invalid AES key length")
    ctx.set_key(key[:key_len])


def AES_set_iv(ctx, iv):
    ctx.set_iv(iv)


def AES_cbc_decrypt(ctx, data, out):
    plaintext = ctx.decrypt(data, remove_padding=False)
    if len(out) < len(plaintext):
        raise ValueError("output buffer is too small")
    out[:len(plaintext)] = plaintext
