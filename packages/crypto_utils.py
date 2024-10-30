from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long
from Crypto.Random import get_random_bytes

# Constants
AES_KEY_LEN_128 = 16

# AES context
class AES_ctx:
    def __init__(self):
        self.key = None
        self.iv = None

    def set_key(self, key):
        self.key = key

    def set_iv(self, iv):
        self.iv = iv

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(pad(data, AES.block_size))

    def decrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(data), AES.block_size)

# AES functions
def AES_set_key(ctx, key, key_len):
    ctx.key = key[:key_len]
    ctx.iv = get_random_bytes(AES.block_size)

def AES_cbc_encrypt(ctx, data, out):
    out[:] = ctx.encrypt(data)

def AES_cbc_decrypt(ctx, data, out):
    out[:] = ctx.decrypt(data) 