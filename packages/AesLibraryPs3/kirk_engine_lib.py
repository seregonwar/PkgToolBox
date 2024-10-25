import ctypes

u8 = ctypes.c_uint8
u16 = ctypes.c_uint16
u32 = ctypes.c_uint32

def round_up(x, n):
    return (-(-(x) & -(n)))

def array_size(x):
    return len(x)

KIRK_OPERATION_SUCCESS = 0
KIRK_NOT_ENABLED = 1
KIRK_INVALID_MODE = 2
KIRK_HEADER_HASH_INVALID = 3
KIRK_DATA_HASH_INVALID = 4
KIRK_SIG_CHECK_INVALID = 5
KIRK_UNK_1 = 6
KIRK_UNK_2 = 7
KIRK_UNK_3 = 8
KIRK_UNK_4 = 9
KIRK_UNK_5 = 0xA
KIRK_UNK_6 = 0xB
KIRK_NOT_INITIALIZED = 0xC
KIRK_INVALID_OPERATION = 0xD
KIRK_INVALID_SEED_CODE = 0xE
KIRK_INVALID_SIZE = 0xF
KIRK_DATA_SIZE_ZERO = 0x10

KIRK_CMD_DECRYPT_PRIVATE = 1
KIRK_CMD_2 = 2
KIRK_CMD_3 = 3
KIRK_CMD_ENCRYPT_IV_0 = 4
KIRK_CMD_ENCRYPT_IV_FUSE = 5
KIRK_CMD_ENCRYPT_IV_USER = 6
KIRK_CMD_DECRYPT_IV_0 = 7
KIRK_CMD_DECRYPT_IV_FUSE = 8
KIRK_CMD_DECRYPT_IV_USER = 9
KIRK_CMD_PRIV_SIGN_CHECK = 10
KIRK_CMD_SHA1_HASH = 11
KIRK_CMD_ECDSA_GEN_KEYS = 12
KIRK_CMD_ECDSA_MULTIPLY_POINT = 13
KIRK_CMD_PRNG = 14
KIRK_CMD_15 = 15
KIRK_CMD_ECDSA_SIGN = 16
KIRK_CMD_ECDSA_VERIFY = 17

KIRK_MODE_CMD1 = 1
KIRK_MODE_CMD2 = 2
KIRK_MODE_CMD3 = 3
KIRK_MODE_ENCRYPT_CBC = 4
KIRK_MODE_DECRYPT_CBC = 5

SUBCWR_NOT_16_ALGINED = 0x90A
SUBCWR_HEADER_HASH_INVALID = 0x920
SUBCWR_BUFFER_TOO_SMALL = 0x1000

class KIRK_AES128CBC_HEADER(ctypes.Structure):
    _fields_ = [
        ("mode", ctypes.c_int),
        ("unk_4", ctypes.c_int),
        ("unk_8", ctypes.c_int),
        ("keyseed", ctypes.c_int),
        ("data_size", ctypes.c_int)
    ]

class KIRK_CMD1_HEADER(ctypes.Structure):
    _fields_ = [
        ("AES_key", u8 * 16),
        ("CMAC_key", u8 * 16),
        ("CMAC_header_hash", u8 * 16),
        ("CMAC_data_hash", u8 * 16),
        ("unused", u8 * 32),
        ("mode", u32),
        ("ecdsa_hash", u8),
        ("unk3", u8 * 11),
        ("data_size", u32),
        ("data_offset", u32),
        ("unk4", u8 * 8),
        ("unk5", u8 * 16)
    ]

class KIRK_CMD1_ECDSA_HEADER(ctypes.Structure):
    _fields_ = [
        ("AES_key", u8 * 16),
        ("header_sig_r", u8 * 20),
        ("header_sig_s", u8 * 20),
        ("data_sig_r", u8 * 20),
        ("data_sig_s", u8 * 20),
        ("mode", u32),
        ("ecdsa_hash", u8),
        ("unk3", u8 * 11),
        ("data_size", u32),
        ("data_offset", u32),
        ("unk4", u8 * 8),
        ("unk5", u8 * 16)
    ]

class ECDSA_SIG(ctypes.Structure):
    _fields_ = [
        ("r", u8 * 0x14),
        ("s", u8 * 0x14)
    ]

class ECDSA_POINT(ctypes.Structure):
    _fields_ = [
        ("x", u8 * 0x14),
        ("y", u8 * 0x14)
    ]

class KIRK_SHA1_HEADER(ctypes.Structure):
    _fields_ = [
        ("data_size", u32)
    ]

class KIRK_CMD12_BUFFER(ctypes.Structure):
    _fields_ = [
        ("private_key", u8 * 0x14),
        ("public_key", ECDSA_POINT)
    ]

class KIRK_CMD13_BUFFER(ctypes.Structure):
    _fields_ = [
        ("multiplier", u8 * 0x14),
        ("public_key", ECDSA_POINT)
    ]

class KIRK_CMD16_BUFFER(ctypes.Structure):
    _fields_ = [
        ("enc_private", u8 * 0x20),
        ("message_hash", u8 * 0x14)
    ]

class KIRK_CMD17_BUFFER(ctypes.Structure):
    _fields_ = [
        ("public_key", ECDSA_POINT),
        ("message_hash", u8 * 0x14),
        ("signature", ECDSA_SIG)
    ]

def kirk_init():
    pass

def kirk_init2(a, b, c, d):
    pass

def kirk_CMD0(outbuff, inbuff, size, generate_trash):
    pass

def kirk_CMD1(outbuff, inbuff, size):
    pass

def kirk_CMD1_ex(outbuff, inbuff, size, header):
    pass

def kirk_CMD4(outbuff, inbuff, size):
    pass

def kirk_CMD7(outbuff, inbuff, size):
    pass

def kirk_CMD10(inbuff, insize):
    pass

def kirk_CMD11(outbuff, inbuff, size):
    pass

def kirk_CMD12(outbuff, outsize):
    pass

def kirk_CMD13(outbuff, outsize, inbuff, insize):
    pass

def kirk_CMD14(outbuff, outsize):
    pass

def kirk_CMD16(outbuff, outsize, inbuff, insize):
    pass

def kirk_CMD17(inbuff, insize):
    pass

def kirk_4_7_get_key(key_type):
    pass

def decrypt_kirk16_private(dA_out, dA_enc):
    pass

def encrypt_kirk16_private(dA_out, dA_dec):
    pass

def sceUtilsSetFuseID(fuse):
    pass

def sceUtilsBufferCopyWithRange(outbuff, outsize, inbuff, insize, cmd):
    pass

def ecdsa_get_params(type, p, a, b, N, Gx, Gy):
    pass

def ecdsa_set_curve(p, a, b, N, Gx, Gy):
    pass

def ecdsa_set_pub(Q):
    pass

def ecdsa_set_priv(k):
    pass

def ecdsa_verify(hash, R, S):
    pass

def ecdsa_sign(hash, R, S):
    pass

def ec_priv_to_pub(k, Q):
    pass

def ec_pub_mult(k, Q):
    pass

def bn_copy(d, a, n):
    pass

def bn_compare(a, b, n):
    pass

def bn_reduce(d, N, n):
    pass

def bn_add(d, a, b, N, n):
    pass

def bn_sub(d, a, b, N, n):
    pass

def bn_to_mon(d, N, n):
    pass

def bn_from_mon(d, N, n):
    pass

def bn_mon_mul(d, a, b, N, n):
    pass

def bn_mon_inv(d, a, N, n):
    pass

def hex_dump(str, buf, size):
    pass
