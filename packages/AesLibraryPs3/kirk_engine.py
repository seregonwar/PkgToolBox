import time
import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from .key_vault import *
from .aes import AES_ctx, AES_set_key, AES_cbc_encrypt, AES_cbc_decrypt, AES_CMAC

# Costanti
KIRK_CMD_DECRYPT_PRIVATE = 1
KIRK_CMD_ENCRYPT_IV_0 = 4
KIRK_CMD_DECRYPT_IV_0 = 7
KIRK_CMD_PRIV_SIGN_CHECK = 10
KIRK_CMD_SHA1_HASH = 11
KIRK_CMD_ECDSA_GEN_KEYS = 12
KIRK_CMD_ECDSA_MULTIPLY_POINT = 13
KIRK_CMD_PRNG = 14
KIRK_CMD_ECDSA_SIGN = 16
KIRK_CMD_ECDSA_VERIFY = 17

KIRK_MODE_CMD1 = 1
KIRK_MODE_CMD2 = 2
KIRK_MODE_CMD3 = 3
KIRK_MODE_ENCRYPT_CBC = 4
KIRK_MODE_DECRYPT_CBC = 5

# Variabili globali
g_fuse90 = 0
g_fuse94 = 0
PRNG_DATA = bytearray(0x14)
is_kirk_initialized = False
aes_kirk1 = AES_ctx()

def kirk_init():
    return kirk_init2(b"Lazy Dev should have initialized!", 33, 0xBABEF00D, 0xDEADBEEF)

def kirk_init2(rnd_seed, seed_size, fuseid_90, fuseid_94):
    global g_fuse90, g_fuse94, is_kirk_initialized, PRNG_DATA, aes_kirk1
    
    temp = bytearray(0x104)
    key = bytes([0x07, 0xAB, 0xEF, 0xF8, 0x96, 0x8C, 0xF3, 0xD6, 0x14, 0xE0, 0xEB, 0xB2, 0x9D, 0x8B, 0x4E, 0x74])
    curtime = int(time.time())

    if seed_size > 0:
        seedbuf = bytearray(seed_size + 4)
        seedbuf[0:4] = seed_size.to_bytes(4, 'little')
        kirk_CMD11(PRNG_DATA, seedbuf, seed_size + 4)

    temp[4:4+len(PRNG_DATA)] = PRNG_DATA
    temp[0x18:0x1C] = curtime.to_bytes(4, 'little')
    temp[0x1C:0x1C+len(key)] = key

    if len(kirk1_key) != 16:
        print(f"Error: Invalid kirk1_key length. Expected 16 bytes, got {len(kirk1_key)} bytes.")
        return -1

    print(f"Debug: kirk1_key = {kirk1_key.hex()}")  # Aggiungi questo log
    AES_set_key(aes_kirk1, kirk1_key, 128)

    g_fuse90 = fuseid_90
    g_fuse94 = fuseid_94
    is_kirk_initialized = True

    return 0

def kirk_4_7_get_key(key_type):
    key_map = {
        0x02: kirk7_key02,
        0x03: kirk7_key03,
        0x04: kirk7_key04,
        0x05: kirk7_key05,
        0x07: kirk7_key07,
        0x0C: kirk7_key0C,
        0x0D: kirk7_key0D,
        0x0E: kirk7_key0E,
        0x0F: kirk7_key0F,
        0x10: kirk7_key10,
        0x11: kirk7_key11,
        0x12: kirk7_key12,
        0x38: kirk7_key38,
        0x39: kirk7_key39,
        0x3A: kirk7_key3A,
        0x44: kirk7_key44,
        0x4B: kirk7_key4B,
        0x53: kirk7_key53,
        0x57: kirk7_key57,
        0x5D: kirk7_key5D,
        0x63: kirk7_key63,
        0x64: kirk7_key64
    }
    return key_map.get(key_type, None)

def kirk_CMD7(dst, src, size):
    header = src[:16]
    mode, unk_4, unk_8, keyseed, data_size = struct.unpack("<IIIII", header)
    
    if mode != KIRK_MODE_DECRYPT_CBC:
        return -1
    
    key = kirk_4_7_get_key(keyseed)
    if key is None:
        return -1
    
    aes_ctx = AES_ctx()
    AES_set_key(aes_ctx, key, 128)
    
    # Assicuriamoci che ci siano abbastanza dati da decrittare
    if len(src) < 16 + size:
        print(f"Error: Not enough data to decrypt. Expected {16 + size} bytes, got {len(src)} bytes.")
        return -1
    
    AES_cbc_decrypt(aes_ctx, src[16:16+size], dst, size)
    return 0

def kirk_CMD11(outbuff, inbuff, size):
    header = inbuff[:4]
    data_size, = struct.unpack("<I", header)
    
    if data_size == 0 or size == 0:
        return -1
    
    sha1 = SHA1.new()
    sha1.update(inbuff[4:4+data_size])
    outbuff[:20] = sha1.digest()
    
    return 0

def kirk_CMD14(outbuff, outsize):
    global PRNG_DATA
    
    if outsize <= 0:
        return 0
    
    temp = bytearray(0x104)
    key = bytes([0xA7, 0x2E, 0x4C, 0xB6, 0xC3, 0x34, 0xDF, 0x85, 0x70, 0x01, 0x49, 0xFC, 0xC0, 0x87, 0xC4, 0x77])
    curtime = int(time.time())
    
    temp[4:4+len(PRNG_DATA)] = PRNG_DATA
    temp[0x18:0x1C] = curtime.to_bytes(4, 'little')
    temp[0x1C:0x1C+len(key)] = key
    
    kirk_CMD11(PRNG_DATA, temp, 0x104)
    
    while outsize > 0:
        blockrem = outsize % 0x14
        block = outsize // 0x14
        
        if block:
            outbuff[:0x14] = PRNG_DATA[:0x14]
            outbuff = outbuff[0x14:]
            outsize -= 0x14
            kirk_CMD14(outbuff, outsize)
        elif blockrem:
            outbuff[:blockrem] = PRNG_DATA[:blockrem]
            outsize -= blockrem
    
    return 0

def sceUtilsBufferCopyWithRange(outbuff, outsize, inbuff, insize, cmd):
    if cmd == KIRK_CMD_DECRYPT_IV_0:
        return kirk_CMD7(outbuff, inbuff, insize)
    elif cmd == KIRK_CMD_SHA1_HASH:
        return kirk_CMD11(outbuff, inbuff, insize)
    elif cmd == KIRK_CMD_PRNG:
        return kirk_CMD14(outbuff, outsize)
    else:
        return -1

# Inizializzazione
kirk_init()

# Aggiungiamo una funzione wrapper per kirk_CMD14
def kirk_CMD14_wrapper(outbuff, outsize):
    return kirk_CMD14(outbuff, outsize)
