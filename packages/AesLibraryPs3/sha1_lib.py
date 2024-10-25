import ctypes

POINTER = ctypes.POINTER(ctypes.c_ubyte)
UINT4 = ctypes.c_uint32
BYTE = ctypes.c_ubyte

FALSE = 0
TRUE = not FALSE

class SHA_CTX(ctypes.Structure):
    _fields_ = [
        ("digest", UINT4 * 5),
        ("countLo", UINT4),
        ("countHi", UINT4),
        ("data", UINT4 * 16),
        ("Endianness", ctypes.c_int)
    ]

def SHAInit(ctx):
    pass

def SHAUpdate(ctx, buffer, count):
    pass

def SHAFinal(output, ctx):
    pass

def endianTest(endianness):
    pass
