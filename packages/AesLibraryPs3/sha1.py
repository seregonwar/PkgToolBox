import ctypes
from sha1_lib import SHA_CTX, SHAInit, SHAUpdate, SHAFinal, endianTest

SHS_DATASIZE = 64
SHS_DIGESTSIZE = 20

def f1(x, y, z):
    return z ^ (x & (y ^ z))

def f2(x, y, z):
    return x ^ y ^ z

def f3(x, y, z):
    return (x & y) | (z & (x | y))

def f4(x, y, z):
    return x ^ y ^ z

K1 = 0x5A827999
K2 = 0x6ED9EBA1
K3 = 0x8F1BBCDC
K4 = 0xCA62C1D6

h0init = 0x67452301
h1init = 0xEFCDAB89
h2init = 0x98BADCFE
h3init = 0x10325476
h4init = 0xC3D2E1F0

def ROTL(n, X):
    return ((X << n) | (X >> (32 - n))) & 0xFFFFFFFF

def expand(W, i):
    W[i & 15] = ROTL(1, W[i & 15] ^ W[(i - 14) & 15] ^ W[(i - 8) & 15] ^ W[(i - 3) & 15])
    return W[i & 15]

def subRound(a, b, c, d, e, f, k, data):
    e = (e + ROTL(5, a) + f(b, c, d) + k + data) & 0xFFFFFFFF
    b = ROTL(30, b)
    return e, a, b, c, d

def SHSTransform(digest, data):
    A, B, C, D, E = digest
    eData = list(ctypes.cast(data, ctypes.POINTER(ctypes.c_uint32))[:16])

    for i in range(80):
        if i < 16:
            E, A, B, C, D = subRound(A, B, C, D, E, f1, K1, eData[i])
        elif i < 20:
            E, A, B, C, D = subRound(A, B, C, D, E, f1, K1, expand(eData, i))
        elif i < 40:
            E, A, B, C, D = subRound(A, B, C, D, E, f2, K2, expand(eData, i))
        elif i < 60:
            E, A, B, C, D = subRound(A, B, C, D, E, f3, K3, expand(eData, i))
        else:
            E, A, B, C, D = subRound(A, B, C, D, E, f4, K4, expand(eData, i))

    digest[0] = (digest[0] + A) & 0xFFFFFFFF
    digest[1] = (digest[1] + B) & 0xFFFFFFFF
    digest[2] = (digest[2] + C) & 0xFFFFFFFF
    digest[3] = (digest[3] + D) & 0xFFFFFFFF
    digest[4] = (digest[4] + E) & 0xFFFFFFFF

def SHAtoByte(input, len):
    return bytes(ctypes.cast(input, ctypes.POINTER(ctypes.c_ubyte))[:len])
