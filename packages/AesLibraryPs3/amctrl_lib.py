import ctypes

class MAC_KEY(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),
        ("key", ctypes.c_uint8 * 16),
        ("pad", ctypes.c_uint8 * 16),
        ("pad_size", ctypes.c_int)
    ]

class CIPHER_KEY(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("seed", ctypes.c_uint32),
        ("key", ctypes.c_uint8 * 16)
    ]

class PGD_HEADER(ctypes.Structure):
    _fields_ = [
        ("vkey", ctypes.c_uint8 * 16),
        ("open_flag", ctypes.c_int),
        ("key_index", ctypes.c_int),
        ("drm_type", ctypes.c_int),
        ("mac_type", ctypes.c_int),
        ("cipher_type", ctypes.c_int),
        ("data_size", ctypes.c_int),
        ("align_size", ctypes.c_int),
        ("block_size", ctypes.c_int),
        ("block_nr", ctypes.c_int),
        ("data_offset", ctypes.c_int),
        ("table_offset", ctypes.c_int),
        ("buf", ctypes.POINTER(ctypes.c_uint8))
    ]

def sceDrmBBMacInit(mkey, type):
    pass

def sceDrmBBMacUpdate(mkey, buf, size):
    pass

def sceDrmBBMacFinal(mkey, buf, vkey):
    pass

def sceDrmBBMacFinal2(mkey, out, vkey):
    pass

def bbmac_build_final2(type, mac):
    pass

def bbmac_getkey(mkey, bbmac, vkey):
    pass

def bbmac_forge(mkey, bbmac, vkey, buf):
    pass

def sceDrmBBCipherInit(ckey, type, mode, header_key, version_key, seed):
    pass

def sceDrmBBCipherUpdate(ckey, data, size):
    pass

def sceDrmBBCipherFinal(ckey):
    pass

def sceNpDrmGetFixedKey(key, npstr, type):
    pass

def decrypt_pgd(pgd_data, pgd_size, flag, key):
    pass
