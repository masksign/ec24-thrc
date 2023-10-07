//  thrc_gauss.c
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Real Gaussian Sampler (XOF / Deterministic Marsaglia Polar)

#include <math.h>
#include "plat_local.h"
#include "racc_param.h"
#include "thrc_gauss.h"
#include "sha3_t.h"

//  Deterministic Rounded Gaussian sampler with variance sig2

void sample_rounded(int64_t r[RACC_N], double sig2, const uint8_t *seed,
                    size_t seed_sz)
{
    //  Continuous sampling uses sig' = sqrt( sig^2 - 1/12 ) to get the
    //  desired distribution. See https://eprint.iacr.org/2017/1025
    //  this constant is "inside the square root": cs2 = -2 * sig'**2
    long double cs2 = (1.0L / 6.0L) - ldexpl(sig2, 1);

    const long double d63 = ldexpl(1.0L, -63);  //  2^-63
    long double s, x0, x1;
    int64_t z0, z1;

    int i;
    uint8_t buf[16];
    sha3_t kec;

    //  sample from squeezed output
    sha3_init(&kec, SHAKE256_RATE);
    sha3_absorb(&kec, seed, seed_sz);
    sha3_pad(&kec, SHAKE_PAD);

    //  polynomial ring element
    for (i = 0; i < RACC_N; i += 2) {

        //  Marsaglia Polar Method (not currently constant time)
        do {
            //  get 128 bits from SHAKE
            sha3_squeeze(&kec, buf, 16);

            //  z0,z1 have two's complement [-2^63,2^63-1] range
            z0 = (int64_t)get64u_le(buf);
            z1 = (int64_t)get64u_le(buf + 8);
            x0 = d63 * ((long double)z0);
            x1 = d63 * ((long double)z1);
            s = x0 * x0 + x1 * x1;

        } while (s == 0.0L || s >= 1.0L);

        //  long double (64-bit mantissa precision)
        s = sqrtl(cs2 * logl(s) / s);
        r[i] = llrintl(x0 * s);
        r[i + 1] = llrintl(x1 * s);
    }
}

#if 1
#include <stdio.h>

int test_gauss()
{
    int i;
    long double sig, x;
    int64_t v[RACC_N];

    sample_rounded(v, 20, (uint8_t *)"abc", 3);

    printf("[%ld", v[0]);
    sig = v[0];
    sig *= sig;
    for (i = 1; i < RACC_N; i++) {
        printf(", %ld", v[i]);
        x = v[i];
        sig += x * x;
    }
    printf("]\n");
    sig = sqrtl(sig / ((long double)RACC_N));
    printf("sigma= %Lf\n", sig);

    return 0;
}
#endif
