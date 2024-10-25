import struct
from .kirk_engine import *  # Cambiamo l'importazione da kirk_engine_lib a kirk_engine
from .aes import *

# Aggiungiamo le definizioni delle classi mancanti
class MAC_KEY:
    def __init__(self):
        self.type = 0
        self.key = bytes(16)
        self.pad = bytes(16)
        self.pad_size = 0

class CIPHER_KEY:
    def __init__(self):
        self.type = 0
        self.key = bytes(16)
        self.seed = 0

class PGD_HEADER:
    def __init__(self):
        self.buf = None
        self.key_index = 0
        self.drm_type = 0
        self.mac_type = 0
        self.cipher_type = 0
        self.open_flag = 0
        self.vkey = bytes(16)
        self.data_size = 0
        self.block_size = 0
        self.data_offset = 0
        self.align_size = 0
        self.table_offset = 0
        self.block_nr = 0

# KIRK buffer.
kirk_buf = bytearray(0x0814)

# AMCTRL keys.
amctrl_key1 = bytes([0xE3, 0x50, 0xED, 0x1D, 0x91, 0x0A, 0x1F, 0xD0, 0x29, 0xBB, 0x1C, 0x3E, 0xF3, 0x40, 0x77, 0xFB])
amctrl_key2 = bytes([0x13, 0x5F, 0xA4, 0x7C, 0xAB, 0x39, 0x5B, 0xA4, 0x76, 0xB8, 0xCC, 0xA9, 0x8F, 0x3A, 0x04, 0x45])
amctrl_key3 = bytes([0x67, 0x8D, 0x7F, 0xA3, 0x2A, 0x9C, 0xA0, 0xD1, 0x50, 0x8A, 0xD8, 0x38, 0x5E, 0x4B, 0x01, 0x7E])

dnas_key1A90 = bytes([0xED,0xE2,0x5D,0x2D,0xBB,0xF8,0x12,0xE5,0x3C,0x5C,0x59,0x32,0xFA,0xE3,0xE2,0x43])
dnas_key1AA0 = bytes([0x27,0x74,0xFB,0xEB,0xA4,0xA0,0x01,0xD7,0x02,0x56,0x9E,0x33,0x8C,0x19,0x57,0x83])

# sceNpDrmGetFixedKey keys.
npdrm_enc_keys = bytes([
    0x07, 0x3D, 0x9E, 0x9D, 0xA8, 0xFD, 0x3B, 0x2F, 0x63, 0x18, 0x93, 0x2E, 0xF8, 0x57, 0xA6, 0x64,
    0x37, 0x49, 0xB7, 0x01, 0xCA, 0xE2, 0xE0, 0xC5, 0x44, 0x2E, 0x06, 0xB6, 0x1E, 0xFF, 0x84, 0xF2,
    0x9D, 0x31, 0xB8, 0x5A, 0xC8, 0xFA, 0x16, 0x80, 0x73, 0x60, 0x18, 0x82, 0x18, 0x77, 0x91, 0x9D,
])
npdrm_fixed_key = bytes([
    0x38, 0x20, 0xD0, 0x11, 0x07, 0xA3, 0xFF, 0x3E, 0x0A, 0x4C, 0x20, 0x85, 0x39, 0x10, 0xB5, 0x54,
])

# KIRK wrapper functions.
def kirk4(buf, size, type):
    header = struct.pack("<IIIII", 4, 0, 0, type, size)
    buf = header + buf
    retv = sceUtilsBufferCopyWithRange(buf, size + 0x14, buf, size, 4)
    
    if retv:
        return 0x80510311
    
    return 0

def kirk7(buf, size, type):
    header = struct.pack("<IIIII", 5, 0, 0, type, size)
    buf = header + buf
    retv = sceUtilsBufferCopyWithRange(buf, size + 0x14, buf, size, 7)
    
    if retv:
        return 0x80510311
    
    return 0

def kirk5(buf, size):
    header = struct.pack("<IIIII", 4, 0, 0, 0x0100, size)
    buf = header + buf
    retv = sceUtilsBufferCopyWithRange(buf, size + 0x14, buf, size, 5)
    
    if retv:
        return 0x80510312
    
    return 0

def kirk8(buf, size):
    header = struct.pack("<IIIII", 5, 0, 0, 0x0100, size)
    buf = header + buf
    retv = sceUtilsBufferCopyWithRange(buf, size+0x14, buf, size, 8)
    
    if retv:
        return 0x80510312
    
    return 0

def kirk14(buf):
    retv = sceUtilsBufferCopyWithRange(buf, 0x14, None, 0, 14)
    
    if retv:
        return 0x80510315
    
    return 0

# Internal functions.
def encrypt_buf(buf, size, key, key_type):
    for i in range(16):
        buf[0x14+i] ^= key[i]
    
    retv = kirk4(buf, size, key_type)
    
    if retv:
        return retv
    
    key[:] = buf[size+4:size+20]
    
    return 0

def decrypt_buf(buf, size, key, key_type):
    tmp = buf[size+0x14-16:size+0x14]
    
    retv = kirk7(buf, size, key_type)
    
    if retv:
        return retv
    
    for i in range(16):
        buf[i] ^= key[i]
    
    key[:] = tmp
    
    return 0

def cipher_buf(kbuf, dbuf, size, ckey):
    kbuf[0x14:0x24] = ckey.key
    
    for i in range(16):
        kbuf[0x14 + i] ^= amctrl_key3[i]
    
    if ckey.type == 2:
        retv = kirk8(kbuf, 16)
    else:
        retv = kirk7(kbuf, 16, 0x39)
    
    if retv:
        return retv
    
    for i in range(16):
        kbuf[i] ^= amctrl_key2[i]
    
    tmp2 = kbuf[:0x10]
    
    if ckey.seed == 1:
        tmp1 = bytes(16)
    else:
        tmp1 = tmp2[:12] + struct.pack("<I", ckey.seed - 1)
    
    for i in range(0, size, 16):
        kbuf[0x14+i:0x20+i] = tmp2[:12] + struct.pack("<I", ckey.seed)
        ckey.seed += 1
    
    retv = decrypt_buf(kbuf, size, tmp1, 0x63)
    
    if retv:
        return retv
    
    for i in range(size):
        dbuf[i] ^= kbuf[i]
    
    return 0

# BBMac functions.
def sceDrmBBMacInit(mkey, type):
    mkey.type = type
    mkey.pad_size = 0
    mkey.key = bytes(16)
    mkey.pad = bytes(16)
    return 0

def sceDrmBBMacUpdate(mkey, buf, size):
    if mkey.pad_size > 16:
        return 0x80510302
    
    if mkey.pad_size + size <= 16:
        mkey.pad = mkey.pad[:mkey.pad_size] + buf[:size] + mkey.pad[mkey.pad_size+size:]
        mkey.pad_size += size
        return 0
    else:
        kbuf = kirk_buf[0x14:]
        kbuf[:mkey.pad_size] = mkey.pad[:mkey.pad_size]
        
        p = mkey.pad_size
        
        mkey.pad_size += size
        mkey.pad_size &= 0x0f
        if mkey.pad_size == 0:
            mkey.pad_size = 16
        
        size -= mkey.pad_size
        mkey.pad = buf[size:size+mkey.pad_size] + mkey.pad[mkey.pad_size:]
        
        type = 0x3A if mkey.type == 2 else 0x38
        
        while size:
            ksize = min(size + p, 0x0800)
            kbuf[p:ksize] = buf[:ksize-p]
            retv = encrypt_buf(kirk_buf, ksize, mkey.key, type)
            
            if retv:
                return retv
            
            size -= (ksize - p)
            buf = buf[ksize-p:]
            p = 0
        
        return 0

def sceDrmBBMacFinal(mkey, buf, vkey):
    if mkey.pad_size > 16:
        return 0x80510302
    
    code = 0x3A if mkey.type == 2 else 0x38
    kbuf = kirk_buf[0x14:]
    
    kbuf[:16] = bytes(16)
    retv = kirk4(kirk_buf, 16, code)
    
    if retv:
        return retv
    
    tmp = kbuf[:16]
    
    t0 = 0x87 if tmp[0] & 0x80 else 0
    for i in range(15):
        v1 = tmp[i]
        v0 = tmp[i+1]
        v1 <<= 1
        v0 >>= 7
        v0 |= v1
        tmp[i] = v0
    v0 = tmp[15]
    v0 <<= 1
    v0 ^= t0
    tmp[15] = v0
    
    if mkey.pad_size < 16:
        t0 = 0x87 if tmp[0] & 0x80 else 0
        for i in range(15):
            v1 = tmp[i]
            v0 = tmp[i+1]
            v1 <<= 1
            v0 >>= 7
            v0 |= v1
            tmp[i] = v0
        v0 = tmp[15]
        v0 <<= 1
        v0 ^= t0
        tmp[15] = v0
        
        mkey.pad = mkey.pad[:mkey.pad_size] + bytes([0x80]) + mkey.pad[mkey.pad_size+1:]
        if mkey.pad_size + 1 < 16:
            mkey.pad = mkey.pad[:mkey.pad_size+1] + bytes(16-mkey.pad_size-1) + mkey.pad[16:]
    
    for i in range(16):
        mkey.pad[i] ^= tmp[i]
    
    kbuf[:16] = mkey.pad
    tmp1 = mkey.key
    
    retv = encrypt_buf(kirk_buf, 0x10, tmp1, code)
    
    if retv:
        return retv
    
    for i in range(0x10):
        tmp1[i] ^= amctrl_key1[i]
    
    if mkey.type == 2:
        kbuf[:16] = tmp1
        
        retv = kirk5(kirk_buf, 0x10)
        
        if retv:
            return retv
        
        retv = kirk4(kirk_buf, 0x10, code)
        
        if retv:
            return retv
        
        tmp1 = kbuf[:16]
    
    if vkey:
        for i in range(0x10):
            tmp1[i] ^= vkey[i]
        kbuf[:16] = tmp1
        
        retv = kirk4(kirk_buf, 0x10, code)
        
        if retv:
            return retv
        
        tmp1 = kbuf[:16]
    
    buf[:16] = tmp1
    
    mkey.key = bytes(16)
    mkey.pad = bytes(16)
    mkey.pad_size = 0
    mkey.type = 0
    
    return 0

def sceDrmBBMacFinal2(mkey, out, vkey):
    type = mkey.type
    retv = sceDrmBBMacFinal(mkey, tmp := bytearray(16), vkey)
    if retv:
        return retv
    
    kbuf = kirk_buf[0x14:]
    
    if type == 3:
        kbuf[:0x10] = out[:0x10]
        kirk7(kirk_buf, 0x10, 0x63)
    else:
        kirk_buf[:0x10] = out[:0x10]
    
    retv = 0
    for i in range(0x10):
        if kirk_buf[i] != tmp[i]:
            retv = 0x80510300
            break
    
    return retv

# BBCipher functions.
def sceDrmBBCipherInit(ckey, type, mode, header_key, version_key, seed):
    kbuf = kirk_buf[0x14:]
    ckey.type = type
    if mode == 2:
        ckey.seed = seed + 1
        ckey.key = header_key[:16]
        if version_key:
            for i in range(16):
                ckey.key[i] ^= version_key[i]
        retv = 0
    elif mode == 1:
        ckey.seed = 1
        retv = kirk14(kirk_buf)
        
        if retv:
            return retv
        
        kbuf[:0x10] = kirk_buf[:0x10]
        kbuf[0x0c:0x10] = bytes(4)
        
        if ckey.type == 2:
            for i in range(16):
                kbuf[i] ^= amctrl_key2[i]
            retv = kirk5(kirk_buf, 0x10)
            for i in range(16):
                kbuf[i] ^= amctrl_key3[i]
        else:
            for i in range(16):
                kbuf[i] ^= amctrl_key2[i]
            retv = kirk4(kirk_buf, 0x10, 0x39)
            for i in range(16):
                kbuf[i] ^= amctrl_key3[i]
        
        if retv:
            return retv
        
        ckey.key = kbuf[:0x10]
        header_key[:0x10] = kbuf[:0x10]
        
        if version_key:
            for i in range(16):
                ckey.key[i] ^= version_key[i]
    else:
        retv = 0
    
    return retv

def sceDrmBBCipherUpdate(ckey, data, size):
    p = 0
    
    while size > 0:
        dsize = min(size, 0x0800)
        retv = cipher_buf(kirk_buf, data[p:p+dsize], dsize, ckey)
        
        if retv:
            break
        
        size -= dsize
        p += dsize
    
    return retv

def sceDrmBBCipherFinal(ckey):
    ckey.key = bytes(16)
    ckey.type = 0
    ckey.seed = 0
    
    return 0

# Extra functions.
def bbmac_build_final2(type, mac):
    kbuf = kirk_buf[0x14:]
    
    if type == 3:
        kbuf[:16] = mac[:16]
        kirk4(kirk_buf, 0x10, 0x63)
        mac[:16] = kbuf[:16]
    
    return 0

def bbmac_getkey(mkey, bbmac, vkey):
    type = mkey.type
    retv = sceDrmBBMacFinal(mkey, tmp := bytearray(16), None)
    
    if retv:
        return retv
    
    kbuf = kirk_buf[0x14:]
    
    if type == 3:
        kbuf[:0x10] = bbmac[:0x10]
        kirk7(kirk_buf, 0x10, 0x63)
    else:
        kirk_buf[:0x10] = bbmac[:0x10]
    
    tmp1 = kirk_buf[:16]
    kbuf[:16] = tmp1
    
    code = 0x3A if type == 2 else 0x38
    kirk7(kirk_buf, 0x10, code)
    
    for i in range(0x10):
        vkey[i] = tmp[i] ^ kirk_buf[i]
    
    return 0

def bbmac_forge(mkey, bbmac, vkey, buf):
    if mkey.pad_size > 16:
        return 0x80510302
    
    type = 0x3A if mkey.type == 2 else 0x38
    kbuf = kirk_buf[0x14:]
    
    kbuf[:16] = bytes(16)
    retv = kirk4(kirk_buf, 16, type)
    
    if retv:
        return retv
    
    tmp = kbuf[:16]
    
    t0 = 0x87 if tmp[0] & 0x80 else 0
    for i in range(15):
        v1 = tmp[i]
        v0 = tmp[i+1]
        v1 <<= 1
        v0 >>= 7
        v0 |= v1
        tmp[i] = v0
    v0 = tmp[15]
    v0 <<= 1
    v0 ^= t0
    tmp[15] = v0
    
    if mkey.pad_size < 16:
        t0 = 0x87 if tmp[0] & 0x80 else 0
        for i in range(15):
            v1 = tmp[i]
            v0 = tmp[i+1]
            v1 <<= 1
            v0 >>= 7
            v0 |= v1
            tmp[i] = v0
        v0 = tmp[15]
        v0 <<= 1
        v0 ^= t0
        tmp[15] = t0
        
        mkey.pad = mkey.pad[:mkey.pad_size] + bytes([0x80]) + mkey.pad[mkey.pad_size+1:]
        if mkey.pad_size + 1 < 16:
            mkey.pad = mkey.pad[:mkey.pad_size+1] + bytes(16-mkey.pad_size-1) + mkey.pad[16:]
    
    for i in range(16):
        mkey.pad[i] ^= tmp[i]
    for i in range(0x10):
        mkey.pad[i] ^= mkey.key[i]
    
    kbuf[:0x10] = bbmac[:0x10]
    kirk7(kirk_buf, 0x10, 0x63)
    
    kbuf[:0x10] = kirk_buf[:0x10]
    kirk7(kirk_buf, 0x10, type)
    
    tmp1 = kirk_buf[:0x10]
    for i in range(0x10):
        tmp1[i] ^= vkey[i]
    for i in range(0x10):
        tmp1[i] ^= amctrl_key1[i]
    
    kbuf[:0x10] = tmp1
    kirk7(kirk_buf, 0x10, type)
    
    tmp1 = kirk_buf[:0x10]
    for i in range(16):
        mkey.pad[i] ^= tmp1[i]
    
    for i in range(16):
        buf[i] ^= mkey.pad[i]
    
    return 0

# sceNpDrm functions.
def sceNpDrmGetFixedKey(key, npstr, type):
    if (type & 0x01000000) == 0:
        return 0x80550901
    
    type &= 0x000000ff
    
    strbuf = npstr.ljust(0x30, b'\x00')[:0x30]
    
    mkey = MAC_KEY()
    retv = sceDrmBBMacInit(mkey, 1)
    
    if retv:
        return retv
    
    retv = sceDrmBBMacUpdate(mkey, strbuf, 0x30)
    
    if retv:
        return retv
    
    retv = sceDrmBBMacFinal(mkey, key, npdrm_fixed_key)
    
    if retv:
        return 0x80550902
    
    if type == 0:
        return 0
    if type > 3:
        return 0x80550901
    
    type = (type - 1) * 16
    
    akey = AES_ctx()
    AES_set_key(akey, npdrm_enc_keys[type:type+16], 128)
    AES_encrypt(akey, key, key)
    
    return 0

def decrypt_pgd(pgd_data, pgd_size, flag, key):
    PGD = PGD_HEADER()
    mkey = MAC_KEY()
    ckey = CIPHER_KEY()
    
    # Read in the PGD header parameters.
    PGD.buf = pgd_data
    PGD.key_index = struct.unpack("<I", pgd_data[4:8])[0]
    PGD.drm_type = struct.unpack("<I", pgd_data[8:12])[0]
    
    # Set the hashing, crypto and open modes.
    if PGD.drm_type == 1:
        PGD.mac_type = 1
        flag |= 4
        
        if PGD.key_index > 1:
            PGD.mac_type = 3
            flag |= 8
        
        PGD.cipher_type = 1
    else:
        PGD.mac_type = 2
        PGD.cipher_type = 2
    
    PGD.open_flag = flag
    
    # Get the fixed DNAS key.
    fkey = None
    if (flag & 0x2) == 0x2:
        fkey = dnas_key1A90
    if (flag & 0x1) == 0x1:
        fkey = dnas_key1AA0
    
    if fkey is None:
        print(f"PGD: Invalid PGD DNAS flag! {flag:08x}")
        return -1
    
    # Test MAC hash at 0x80 (DNAS hash).
    sceDrmBBMacInit(mkey, PGD.mac_type)
    sceDrmBBMacUpdate(mkey, pgd_data[:0x80], 0x80)
    result = sceDrmBBMacFinal2(mkey, pgd_data[0x80:0x90], fkey)
    
    if result:
        print("PGD: Invalid PGD 0x80 MAC hash!")
        return -1
    
    # Test MAC hash at 0x70 (key hash).
    sceDrmBBMacInit(mkey, PGD.mac_type)
    sceDrmBBMacUpdate(mkey, pgd_data[:0x70], 0x70)
    
    # Generate the key from MAC 0x70.
    bbmac_getkey(mkey, pgd_data[0x70:0x80], PGD.vkey)
    
    # Decrypt the PGD header block (0x30 bytes).
    sceDrmBBCipherInit(ckey, PGD.cipher_type, 2, pgd_data[0x10:0x20], PGD.vkey, 0)
    sceDrmBBCipherUpdate(ckey, pgd_data[0x30:0x60], 0x30)
    sceDrmBBCipherFinal(ckey)
    
    # Get the decryption parameters from the decrypted header.
    PGD.data_size = struct.unpack("<I", pgd_data[0x44:0x48])[0]
    PGD.block_size = struct.unpack("<I", pgd_data[0x48:0x4c])[0]
    PGD.data_offset = struct.unpack("<I", pgd_data[0x4c:0x50])[0]
    
    # Additional size variables.
    PGD.align_size = (PGD.data_size + 15) & ~15
    PGD.table_offset = PGD.data_offset + PGD.align_size
    PGD.block_nr = (PGD.align_size + PGD.block_size - 1) & ~(PGD.block_size - 1)
    PGD.block_nr = PGD.block_nr // PGD.block_size
    
    if (PGD.align_size + PGD.block_nr * 16) > pgd_size:
        print("ERROR: Invalid PGD data size!")
        return -1
    
    # Test MAC hash at 0x60 (table hash).
    sceDrmBBMacInit(mkey, PGD.mac_type)
    sceDrmBBMacUpdate(mkey, pgd_data[PGD.table_offset:PGD.table_offset+PGD.block_nr*16], PGD.block_nr * 16)
    result = sceDrmBBMacFinal2(mkey, pgd_data[0x60:0x70], PGD.vkey)
    
    if result:
        print("ERROR: Invalid PGD 0x60 MAC hash!")
        return -1
    
    # Decrypt the data.
    sceDrmBBCipherInit(ckey, PGD.cipher_type, 2, pgd_data[0x30:0x40], PGD.vkey, 0)
    sceDrmBBCipherUpdate(ckey, pgd_data[0x90:0x90+PGD.align_size], PGD.align_size)
    sceDrmBBCipherFinal(ckey)
    
    return PGD.data_size
