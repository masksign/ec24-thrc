"""
sample_gauss.py
Copyright (c) 2023 Raccoon Signature Team. See LICENSE.
=== Real Gaussian Sampler (XOF / Deterministic Marsaglia Polar)
"""
from Crypto.Hash import SHAKE256

import mpmath as mp
mp.mp.prec  =   256                     #   bits of precision for mpmath
RG_PREC     =   64                      #   Bits per sample: Rounded Gaussian
DG_PREC     =   127                     #   Bits per sample: Discrete Gaussian
BYTEORDER   =   "little"

### Uniform samplers

def unif_uint(xof, prec):
    """Sample xof output to an integer in [0, 2**prec-1]."""
    xof_sz  = ((prec + 7) // 8)         #   bytes extracted from xof
    byt     = xof.read(xof_sz)          #   get bytes from xof
    x       = int.from_bytes(byt, BYTEORDER) & ((1 << prec) - 1)
    return  x

def unif_real(xof, prec):
    """Sample xof output to a signed float in [-1, 1-2**-(prec-1)]."""
    mp_scl  = mp.ldexp(1, -(prec - 1))  #   1/s_oflo as a mpf
    x       = unif_uint(xof, prec)
    if x >= (1 << (prec-1)):            #   two's complement signed
        x -= 1 << prec
    return mp_scl * mp.mpf(x)           #   scale to [-1, 1 - 2**-(prec-1)].

### Rounded Gaussians

def mp_round(x):
    """Round to integer."""
    half = mp.ldexp(1, -1)              #   1*2**-1
    return int(mp.floor(x + half))      #   floor(x + 1/2)

def sample_rounded(sig2, seed, n=512, prec=RG_PREC):
    """Deterministic rounded Gaussian sampler with std. deviation 2**lg_s."""
    xof = SHAKE256.new(seed)
    #   sig' = sqrt(sig**2-1/12). cs2 = -2*sig'**2
    cs2 = mp.fdiv(1,6) - mp.ldexp(sig2, 1)
    v   = [0] * n
    i   = 0
    while i < n:
        x0  = unif_real(xof, prec=prec)
        x1  = unif_real(xof, prec=prec)
        s   = x0 * x0 + x1 * x1
        if s > 0 and s < 1:
            s       = mp.sqrt( cs2 * mp.log(s) / s )
            v[i]    = mp_round(s * x0)
            v[i+1]  = mp_round(s * x1)
            i += 2
    return v

### Discrete Gaussians

NCF_TAIL    =   18.7                    #   left + right tail < 2**-256.8

def mp_dg_ndf(sig, prec=DG_PREC):
    """Calculate non-negative half of Discrete Gaussian density function."""
    hlf =   mp.ldexp(1, -1)             #   1/2
    tl  =   int(sig * NCF_TAIL + 1)     #   length of CDF ("tail")
    xs  =   -hlf / (sig**2)             #   scale: -1/2*sig**2
    #   create unscaled CDF
    v   =   [ mp.exp( xs * mp.mpf(i**2) ) for i in range(tl) ]
    s   =   hlf                         #   cdf[0]/2 = 1/2
    for x in v[1:]:
        s   +=  x
    s   =   hlf / s                     #   scaling factor
    return  [ s * x for x in v ]

def mp_build_cdf(sig, prec=DG_PREC):
    """Create a (one-sided, zero-centered) Cumulative Distribution Table."""
    mxm =   (1 << (prec - 1)) - 1       #   one-sided max unform value
    v   =   mp_dg_ndf(sig, prec)
    c   =   v[0]
    cdf =   [ int(mp.ceil(mp.ldexp(c, prec - 1))) ]
    for x in v[1:]:
        c   +=  mp.ldexp(x, 1)          #   prob mass of both sides
        t   =   int(mp.nint(mp.ldexp(c, prec - 1)))
        if  t == cdf[-1] or t >= mxm:   #   out of precision
            break
        cdf +=  [ t ]
    cdf +=  [ mxm ]                     #   final value
    return cdf

def sample_cdf(cdf, x, prec=DG_PREC):
    s   =   1 - 2 * (x & 1)             #   low bit is sign
    x   >>= 1
    x   &=  (1 << (prec - 1)) - 1       #   mask one-sided max
    for i in range(len(cdf)):
        if x <= cdf[i]:
            return s * i
    return s * len(cdf)                 #   (should not happen)

def sample_sigma_t(cdf, seed, n=512, prec=DG_PREC):
    """Deterministic table-based discrete Gaussian sampler."""
    xof =   SHAKE256.new(seed)
    v   = [0] * n
    for i in range(n):
        x   =   unif_uint(xof, prec)
        v[i] =  sample_cdf(cdf, x, prec)
    return v

#   --- some testing code ----------------------------------------------

import os

if (__name__ == "__main__"):

    #   debug functions
    def ndf(x, sig=1):
        c   = 1 / (sig * mp.sqrt(2*mp.pi))
        return c * mp.exp(-(x / sig)**2/2)

    def print_cdf(cdf):
        for i in range(len(cdf)):
            x0 = cdf[i] & ((1 << 63) - 1)
            x1 = cdf[i] >> 63
            print(f'\t{{ INT64_C(0x{x0:016x}), INT64_C(0x{x1:016x}) }},')

    def test_cdf(sig):
        cdf =   mp_build_cdf(sig)
        tz  =   len(cdf) + 1
        cnt =   [0] * (2 * tz)
        xof =   SHAKE256.new(os.urandom(64))
        n   =   1000000
        for _ in range(n):
            z   =   unif_uint(xof, DG_PREC)
            x   =   sample_cdf(cdf, z)
            cnt[x + tz] +=  1

        ss  =   0.0
        for i in range(2*tz):
            if cnt[i] > 0:
                x   = i - tz
                f   = float(ndf(x, sig))
                g   = cnt[i]/n
                d   = f - g
                ss += g * x**2
                print(f'{x:6} {cnt[i]:9}  f= {f:.6f}  g= {g:.6f}  d= {d:9.6f}')
        ss = float(ss)**0.5
        print(f'sigma= {ss}')

    def test_rounded(lg_s, nn=100000):
        sig =   2**lg_s
        s   =   0
        r   =   0
        n   =   0
        for i in range(nn // 512):
            v = sample_rounded(sig**2, os.urandom(32))
            for x in v:
                n += 1
                s += x
                r += x*x

        avg = float(mp.fdiv(s, n))
        std = float(mp.sqrt(mp.fdiv(r, n) - mp.fdiv(s, n)**2))

        print(f'n= {n}  avg= {avg:f}  std= {std:f} ({float(sig):f})')

    #   basic test

    #test_rounded(20)
    v = sample_rounded((2**20)**2, b'abc')
    print(v)
    r = 0
    for x in v:
        r += x**2
    print(mp.sqrt(r / len(v)))

    exit(0)


