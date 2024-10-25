import ctypes
from kirk_engine_lib import *

AES_KEY_LEN_128 = 128
AES_KEY_LEN_192 = 192
AES_KEY_LEN_256 = 256

AES_BUFFER_SIZE = 16

AES_MAXKEYBITS = 256
AES_MAXKEYBYTES = AES_MAXKEYBITS // 8
AES_MAXROUNDS = 14
pwuAESContextBuffer = "rijndael_ctx"

class rijndael_ctx(ctypes.Structure):
    _fields_ = [
        ("enc_only", ctypes.c_int),
        ("Nr", ctypes.c_int),
        ("ek", ctypes.c_uint32 * (4 * (AES_MAXROUNDS + 1))),
        ("dk", ctypes.c_uint32 * (4 * (AES_MAXROUNDS + 1)))
    ]

AES_ctx = rijndael_ctx

def rijndael_set_key(ctx, key, bits):
    pass

def rijndael_set_key_enc_only(ctx, key, bits):
    pass

def rijndael_decrypt(ctx, src, dst):
    pass

def rijndael_encrypt(ctx, src, dst):
    pass

def AES_set_key(ctx, key, bits):
    pass

def AES_encrypt(ctx, src, dst):
    pass

def AES_decrypt(ctx, src, dst):
    pass

def AES_cbc_encrypt(ctx, src, dst, size):
    pass

def AES_cbc_decrypt(ctx, src, dst, size):
    pass

def AES_CMAC(ctx, input, length, mac):
    pass

def rijndaelKeySetupEnc(rk, cipherKey, keyBits):
    pass

def rijndaelKeySetupDec(rk, cipherKey, keyBits):
    pass

def rijndaelEncrypt(rk, Nr, pt, ct):
    pass
