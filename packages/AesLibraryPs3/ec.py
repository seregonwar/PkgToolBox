import ctypes
from .bn import (bn_add, bn_sub, bn_mon_mul, bn_mon_inv, bn_to_mon, bn_from_mon,
                 bn_reduce, bn_copy, bn_compare)

class Point(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_uint8 * 20),
        ("y", ctypes.c_uint8 * 20)
    ]

ec_p = (ctypes.c_uint8 * 20)()
ec_a = (ctypes.c_uint8 * 20)()
ec_b = (ctypes.c_uint8 * 20)()
ec_N = (ctypes.c_uint8 * 21)()
ec_G = Point()
ec_Q = Point()
ec_k = (ctypes.c_uint8 * 21)()

def hex_dump(s, buf, size):
    if s:
        print(f"{s}:", end="")
    
    for i in range(size):
        if i % 32 == 0:
            print(f"\n{i:04X}:", end="")
        print(f" {buf[i]:02X}", end="")
    print("\n")

def elt_copy(d, a):
    ctypes.memmove(d, a, 20)

def elt_zero(d):
    ctypes.memset(d, 0, 20)

def elt_is_zero(d):
    return all(x == 0 for x in d)

def elt_add(d, a, b):
    bn_add(d, a, b, ec_p, 20)

def elt_sub(d, a, b):
    bn_sub(d, a, b, ec_p, 20)

def elt_mul(d, a, b):
    bn_mon_mul(d, a, b, ec_p, 20)

def elt_square(d, a):
    elt_mul(d, a, a)

def elt_inv(d, a):
    s = (ctypes.c_uint8 * 20)()
    elt_copy(s, a)
    bn_mon_inv(d, s, ec_p, 20)

def point_to_mon(p):
    bn_to_mon(p.x, ec_p, 20)
    bn_to_mon(p.y, ec_p, 20)

def point_from_mon(p):
    bn_from_mon(p.x, ec_p, 20)
    bn_from_mon(p.y, ec_p, 20)

def point_zero(p):
    elt_zero(p.x)
    elt_zero(p.y)

def point_is_zero(p):
    return elt_is_zero(p.x) and elt_is_zero(p.y)

def point_double(r, p):
    s = (ctypes.c_uint8 * 20)()
    t = (ctypes.c_uint8 * 20)()
    pp = Point()
    ctypes.memmove(ctypes.byref(pp), ctypes.byref(p), ctypes.sizeof(Point))

    if elt_is_zero(pp.y):
        point_zero(r)
        return

    elt_square(t, pp.x)
    elt_add(s, t, t)
    elt_add(s, s, t)
    elt_add(s, s, ec_a)
    elt_add(t, pp.y, pp.y)
    elt_inv(t, t)
    elt_mul(s, s, t)

    elt_square(r.x, s)
    elt_add(t, pp.x, pp.x)
    elt_sub(r.x, r.x, t)

    elt_sub(t, pp.x, r.x)
    elt_mul(r.y, s, t)
    elt_sub(r.y, r.y, pp.y)

def point_add(r, p, q):
    s = (ctypes.c_uint8 * 20)()
    t = (ctypes.c_uint8 * 20)()
    u = (ctypes.c_uint8 * 20)()
    pp = Point()
    qq = Point()
    ctypes.memmove(ctypes.byref(pp), ctypes.byref(p), ctypes.sizeof(Point))
    ctypes.memmove(ctypes.byref(qq), ctypes.byref(q), ctypes.sizeof(Point))

    if point_is_zero(pp):
        elt_copy(r.x, qq.x)
        elt_copy(r.y, qq.y)
        return

    if point_is_zero(qq):
        elt_copy(r.x, pp.x)
        elt_copy(r.y, pp.y)
        return

    elt_sub(u, qq.x, pp.x)

    if elt_is_zero(u):
        elt_sub(u, qq.y, pp.y)
        if elt_is_zero(u):
            point_double(r, pp)
        else:
            point_zero(r)
        return

    elt_inv(t, u)
    elt_sub(u, qq.y, pp.y)
    elt_mul(s, t, u)

    elt_square(r.x, s)
    elt_add(t, pp.x, qq.x)
    elt_sub(r.x, r.x, t)

    elt_sub(t, pp.x, r.x)
    elt_mul(r.y, s, t)
    elt_sub(r.y, r.y, pp.y)

def point_mul(d, a, b):
    point_zero(d)

    for i in range(21):
        for mask in [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]:
            point_double(d, d)
            if a[i] & mask:
                point_add(d, d, b)

def generate_ecdsa(outR, outS, k, hash):
    e = (ctypes.c_uint8 * 21)()
    kk = (ctypes.c_uint8 * 21)()
    m = (ctypes.c_uint8 * 21)()
    R = (ctypes.c_uint8 * 21)()
    S = (ctypes.c_uint8 * 21)()
    minv = (ctypes.c_uint8 * 21)()
    mG = Point()

    e[0] = R[0] = S[0] = 0
    ctypes.memmove(e[1:], hash, 20)
    bn_reduce(e, ec_N, 21)

    # Sostituiamo la chiamata diretta a kirk_CMD14 con una funzione di placeholder
    # che verrà implementata altrove
    from .kirk_engine import kirk_CMD14_wrapper
    kirk_CMD14_wrapper(m[1:], 20)
    
    m[0] = 0

    point_mul(mG, m, ec_G)
    point_from_mon(mG)
    R[0] = 0
    elt_copy(R[1:], mG.x)

    bn_copy(kk, k, 21)
    bn_reduce(kk, ec_N, 21)
    bn_to_mon(m, ec_N, 21)
    bn_to_mon(e, ec_N, 21)
    bn_to_mon(R, ec_N, 21)
    bn_to_mon(kk, ec_N, 21)

    bn_mon_mul(S, R, kk, ec_N, 21)
    bn_add(kk, S, e, ec_N, 21)
    bn_mon_inv(minv, m, ec_N, 21)
    bn_mon_mul(S, minv, kk, ec_N, 21)

    bn_from_mon(R, ec_N, 21)
    bn_from_mon(S, ec_N, 21)
    ctypes.memmove(outR, R[1:], 0x20)
    ctypes.memmove(outS, S[1:], 0x20)

def check_ecdsa(Q, inR, inS, hash):
    Sinv = (ctypes.c_uint8 * 21)()
    e = (ctypes.c_uint8 * 21)()
    R = (ctypes.c_uint8 * 21)()
    S = (ctypes.c_uint8 * 21)()
    w1 = (ctypes.c_uint8 * 21)()
    w2 = (ctypes.c_uint8 * 21)()
    r1 = Point()
    r2 = Point()
    rr = (ctypes.c_uint8 * 21)()

    e[0] = 0
    ctypes.memmove(e[1:], hash, 20)
    bn_reduce(e, ec_N, 21)
    R[0] = 0
    ctypes.memmove(R[1:], inR, 20)
    bn_reduce(R, ec_N, 21)
    S[0] = 0
    ctypes.memmove(S[1:], inS, 20)
    bn_reduce(S, ec_N, 21)

    bn_to_mon(R, ec_N, 21)
    bn_to_mon(S, ec_N, 21)
    bn_to_mon(e, ec_N, 21)
    bn_mon_inv(Sinv, S, ec_N, 21)
    bn_mon_mul(w1, e, Sinv, ec_N, 21)
    bn_mon_mul(w2, R, Sinv, ec_N, 21)

    bn_from_mon(w1, ec_N, 21)
    bn_from_mon(w2, ec_N, 21)

    point_mul(r1, w1, ec_G)
    point_mul(r2, w2, Q)

    point_add(r1, r1, r2)

    point_from_mon(r1)

    rr[0] = 0
    ctypes.memmove(rr[1:], r1.x, 20)
    bn_reduce(rr, ec_N, 21)

    bn_from_mon(R, ec_N, 21)
    bn_from_mon(S, ec_N, 21)

    return bn_compare(rr, R, 21) == 0

def ec_priv_to_pub(k, Q):
    ec_temp = Point()
    bn_to_mon(k, ec_N, 21)
    point_mul(ec_temp, k, ec_G)
    point_from_mon(ec_temp)
    ctypes.memmove(Q, ec_temp.x, 20)
    ctypes.memmove(Q[20:], ec_temp.y, 20)

def ec_pub_mult(k, Q):
    ec_temp = Point()
    point_mul(ec_temp, k, ec_Q)
    point_from_mon(ec_temp)
    ctypes.memmove(Q, ec_temp.x, 20)
    ctypes.memmove(Q[20:], ec_temp.y, 20)

def ecdsa_set_curve(p, a, b, N, Gx, Gy):
    ctypes.memmove(ec_p, p, 20)
    ctypes.memmove(ec_a, a, 20)
    ctypes.memmove(ec_b, b, 20)
    ctypes.memmove(ec_N, N, 21)

    bn_to_mon(ec_a, ec_p, 20)
    bn_to_mon(ec_b, ec_p, 20)

    ctypes.memmove(ec_G.x, Gx, 20)
    ctypes.memmove(ec_G.y, Gy, 20)
    point_to_mon(ec_G)

    return 0

def ecdsa_set_pub(Q):
    ctypes.memmove(ec_Q.x, Q, 20)
    ctypes.memmove(ec_Q.y, Q[20:], 20)
    point_to_mon(ec_Q)

def ecdsa_set_priv(ink):
    k = (ctypes.c_uint8 * 21)()
    k[0] = 0
    ctypes.memmove(k[1:], ink, 20)
    bn_reduce(k, ec_N, 21)

    ctypes.memmove(ec_k, k, ctypes.sizeof(ec_k))

def ecdsa_verify(hash, R, S):
    return check_ecdsa(ec_Q, R, S, hash)

def ecdsa_sign(hash, R, S):
    generate_ecdsa(R, S, ec_k, hash)

def point_is_on_curve(p):
    s = (ctypes.c_uint8 * 20)()
    t = (ctypes.c_uint8 * 20)()
    x = p
    y = p[20:]

    elt_square(t, x)
    elt_mul(s, t, x)

    elt_mul(t, x, ec_a)
    elt_add(s, s, t)

    elt_add(s, s, ec_b)

    elt_square(t, y)
    elt_sub(s, s, t)
    hex_dump("S", s, 20)
    hex_dump("T", t, 20)
    return elt_is_zero(s)

def dump_ecc():
    hex_dump("P", ec_p, 20)
    hex_dump("a", ec_a, 20)
    hex_dump("b", ec_b, 20)
    hex_dump("N", ec_N, 21)
    hex_dump("Gx", ec_G.x, 20)
    hex_dump("Gy", ec_G.y, 20)
