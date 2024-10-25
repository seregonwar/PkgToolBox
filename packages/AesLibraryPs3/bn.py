import ctypes
from .kirk_engine import *  # Cambiamo l'importazione da kirk_engine_lib a kirk_engine

def bn_print(name, a, n):
    print(f"{name} = ", end="")
    for i in range(n):
        print(f"{a[i]:02x}", end="")
    print()

def bn_zero(d, n):
    ctypes.memset(d, 0, n)

def bn_copy(d, a, n):
    ctypes.memmove(d, a, n)

def bn_compare(a, b, n):
    for i in range(n):
        if a[i] < b[i]:
            return -1
        if a[i] > b[i]:
            return 1
    return 0

def bn_add_1(d, a, b, n):
    c = 0
    for i in range(n-1, -1, -1):
        dig = a[i] + b[i] + c
        c = dig >> 8
        d[i] = dig & 0xFF
    return c

def bn_sub_1(d, a, b, n):
    c = 1
    for i in range(n-1, -1, -1):
        dig = a[i] + 255 - b[i] + c
        c = dig >> 8
        d[i] = dig & 0xFF
    return 1 - c

def bn_reduce(d, N, n):
    if bn_compare(d, N, n) >= 0:
        bn_sub_1(d, d, N, n)

def bn_add(d, a, b, N, n):
    if bn_add_1(d, a, b, n):
        bn_sub_1(d, d, N, n)
    bn_reduce(d, N, n)

def bn_sub(d, a, b, N, n):
    if bn_sub_1(d, a, b, n):
        bn_add_1(d, d, N, n)

inv256 = bytes([
    0x01, 0xab, 0xcd, 0xb7, 0x39, 0xa3, 0xc5, 0xef,
    0xf1, 0x1b, 0x3d, 0xa7, 0x29, 0x13, 0x35, 0xdf,
    0xe1, 0x8b, 0xad, 0x97, 0x19, 0x83, 0xa5, 0xcf,
    0xd1, 0xfb, 0x1d, 0x87, 0x09, 0xf3, 0x15, 0xbf,
    0xc1, 0x6b, 0x8d, 0x77, 0xf9, 0x63, 0x85, 0xaf,
    0xb1, 0xdb, 0xfd, 0x67, 0xe9, 0xd3, 0xf5, 0x9f,
    0xa1, 0x4b, 0x6d, 0x57, 0xd9, 0x43, 0x65, 0x8f,
    0x91, 0xbb, 0xdd, 0x47, 0xc9, 0xb3, 0xd5, 0x7f,
    0x81, 0x2b, 0x4d, 0x37, 0xb9, 0x23, 0x45, 0x6f,
    0x71, 0x9b, 0xbd, 0x27, 0xa9, 0x93, 0xb5, 0x5f,
    0x61, 0x0b, 0x2d, 0x17, 0x99, 0x03, 0x25, 0x4f,
    0x51, 0x7b, 0x9d, 0x07, 0x89, 0x73, 0x95, 0x3f,
    0x41, 0xeb, 0x0d, 0xf7, 0x79, 0xe3, 0x05, 0x2f,
    0x31, 0x5b, 0x7d, 0xe7, 0x69, 0x53, 0x75, 0x1f,
    0x21, 0xcb, 0xed, 0xd7, 0x59, 0xc3, 0xe5, 0x0f,
    0x11, 0x3b, 0x5d, 0xc7, 0x49, 0x33, 0x55, 0xff,
])

def bn_mon_muladd_dig(d, a, b, N, n):
    z = (-(d[n-1] + a[n-1]*b) * inv256[N[n-1]//2]) & 0xFF
    dig = d[n-1] + a[n-1]*b + N[n-1]*z
    dig >>= 8
    for i in range(n-2, -1, -1):
        dig += d[i] + a[i]*b + N[i]*z
        d[i+1] = dig & 0xFF
        dig >>= 8
    d[0] = dig & 0xFF
    dig >>= 8
    if dig:
        bn_sub_1(d, d, N, n)
    bn_reduce(d, N, n)

def bn_mon_mul(d, a, b, N, n):
    t = bytearray(512)
    bn_zero(t, n)
    for i in range(n-1, -1, -1):
        bn_mon_muladd_dig(t, a, b[i], N, n)
    bn_copy(d, t, n)

def bn_to_mon(d, N, n):
    for _ in range(8*n):
        bn_add(d, d, d, N, n)

def bn_from_mon(d, N, n):
    t = bytearray(512)
    bn_zero(t, n)
    t[n-1] = 1
    bn_mon_mul(d, d, t, N, n)

def bn_mon_exp(d, a, N, n, e, en):
    t = bytearray(512)
    bn_zero(d, n)
    d[n-1] = 1
    bn_to_mon(d, N, n)
    for i in range(en):
        for mask in [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]:
            bn_mon_mul(t, d, d, N, n)
            if e[i] & mask:
                bn_mon_mul(d, t, a, N, n)
            else:
                bn_copy(d, t, n)

def bn_mon_inv(d, a, N, n):
    t = bytearray(512)
    s = bytearray(512)
    bn_zero(s, n)
    s[n-1] = 2
    bn_sub_1(t, N, s, n)
    bn_mon_exp(d, a, N, n, t, n)
