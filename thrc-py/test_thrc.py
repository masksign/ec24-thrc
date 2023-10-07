"""
test_thrc.py
Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

=== Threshold Raccoon signature scheme: Tests
"""

from nist_kat_drbg import NIST_KAT_DRBG
from thrc_api import TRaccoon
from polyr import *
import os,sys,math

#   some debug printing things

def dbg_sum(v, q=549824583172097,g=15,s=31337):
    """Simple recursive poly/vector/matrix checksum routine."""
    if isinstance(v, int):
        return ((g * s + v) % q)
    elif isinstance(v, list):
        for x in v:
            s = dbg_sum(x,q=q,g=g,s=s)
    return s

def dbg_dim(v, s=''):
    t = v
    while isinstance(t, list):
        s += '[' + str(len(t)) + ']'
        t = t[0]
    s += ' = ' + str(dbg_sum(v))
    return s


def dbg_sig(v, lab='', q=RACC_Q):
    """Print statistics of entries."""
    r = ''
    if isinstance(v[0], list):
        for i in range(len(v)):
            r += f'\n\t{lab}[{i}] = ' + dbg_sig(v[i])
        return r
    n = 0
    a = 0
    s = 0
    for x in v:
        x = ((x + (q // 2)) % q) - (q // 2)
        n += 1
        a += x
        s += x * x
    a = a/n
    s = (s/n - a**2)**0.5
    if s > 0:
        lg_s = math.log(s)/math.log(2)
    else:
        lg_s = -999
    if a > 1E-20:
        sg_a = 1
        lg_a = math.log(a)/math.log(2)
    elif a < -1E-20:
        sg_a = -1
        lg_a = math.log(-a)/math.log(2)
    else:
        sg_a = 0
        lg_a = -999

    r += f'(n= {n}, {sg_a:+2}, lg_a= {lg_a:5.2f}, lg_s= {lg_s:5.2f})'
    return r

if (__name__ == "__main__"):

    kappa = 128
    act_sz = 3
    th_t = 3
    th_n = 4

    #   test parameters
    if len(sys.argv) >= 2:
        kappa = int(sys.argv[1])
    if len(sys.argv) >= 3:
        act_sz = int(sys.argv[2])
    if len(sys.argv) >= 4:
        th_t = int(sys.argv[3])
    if len(sys.argv) >= 5:
        th_n = int(sys.argv[4])

    act = list(range(act_sz))

    print(f'kappa= {kappa}  act={act}  T= {th_t}  N= {th_n}')

    #   initialize nist pseudo random
    entropy_input = bytes(range(48))
    drbg = NIST_KAT_DRBG(entropy_input)
    rand = drbg.random_bytes
    rand = os.urandom

    #   one instance here for testing
    if kappa == 128:
        iut = TRaccoon( kappa=128, max_t=1024, lg_st=20, lg_swt=42,
                        nu_t=37, nu_w=40, ell=4, k=5, omega=19,
                        random_bytes=rand)
    elif kappa == 192:
        iut = TRaccoon( kappa=192, max_t=1024, lg_st=20, lg_swt=42,
                        nu_t=36, nu_w=40, ell=6, k=7, omega=31,
                        random_bytes=rand)
    elif kappa == 256:
        iut = TRaccoon( kappa=256, max_t=1024, lg_st=20, lg_swt=42,
                        nu_t=35, nu_w=41, ell=7, k=8, omega=44,
                        random_bytes=rand)
    else:
        print(f'kappa must be in { 128, 192, 256 }')
        exit(0)

    #   mu is "message hash" here
    mu = bytes(range(iut.mu_sz))
    sid = bytes(range(100, 100 + iut.sid_sz))

    print("--- Key Generation: ---");
    vk, sk = iut.keygen( th_t=th_t, th_n=th_n )

    (A_seed, t) = vk
    view = [ None ] * th_n
    for ski in sk:
        (j, s, seeds) = ski
        print(f'sk[{j}]: s' + dbg_dim(s))

    print("vk: A_seed = " + A_seed.hex())
    print("vk  t:", dbg_dim(t), dbg_sig(t, 't'))

    vk_b = iut.encode_vk(vk)
    print("|vk| =", len(vk_b), iut.vk_sz)
    (A_seed, t) = iut.decode_vk(vk_b)

    print("--- Round 1: ---");
    view = [ None ] * th_n
    ctrb_1 = [ None ] * th_n
    for j in act:
        view[j],ctrb_1[j] = iut.sign_1(vk, sk[j], sid, act, mu)
        (cmt_i, m_i) = ctrb_1[j]
        print(f'cmt{j}:', cmt_i.hex())
        print(f'm{j}:', dbg_dim(m_i))

    print("--- Round 2: ---");
    ctrb_2 = [ None ] * th_n
    for j in act:
        ctrb_2[j] = iut.sign_2(view[j], ctrb_1)
        (w, sig) = ctrb_2[j]
        print(f'w{j}:', dbg_dim(w))

    print("--- Round 3: ---");
    ctrb_3 = [ None ] * th_n
    for j in act:
        ctrb_3[j] = iut.sign_3(view[j], ctrb_2)
        print(f'z{j}:', dbg_dim(ctrb_3[j]))

    print("--- Combine: ---");
    sig = iut.combine(vk, sid, mu, act, ctrb_1, ctrb_2, ctrb_3)
    if sig == None:
        print('ERROR: Combine failed (is |act| smaller than threshold T ?)')
        exit(-1)
    (c_hash, z, h) = sig

    print("sig c:", c_hash.hex())
    print("sig z:", dbg_dim(z), dbg_sig(z, 'z'))
    print("sig h:", dbg_dim(h), dbg_sig(h, 'h'))
    print("B2", iut.b2)
    sig_b = iut.encode_sig(sig)
    print("|sig|:", len(sig_b))
    (c_hash, z, h) = iut.decode_sig(sig_b)

    print("zh", iut._check_bounds(z, h))

    print("=== Verify ===")
    rsp = iut.verify(vk, mu, sig)
    print(rsp)

    iut.ctrb_sz(act_sz)

    exit(0)
