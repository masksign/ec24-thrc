//  xof_sample.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Raccoon signature scheme -- Samplers and XOF functions

#ifndef _XOF_SAMPLE_H_
#define _XOF_SAMPLE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "racc_param.h"

//  === Global namespace prefix
#ifdef RACC_
#define xof_sample_q RACC_(xof_sample_q)
#define xof_sample_u RACC_(xof_sample_u)
#define xof_chal_mu RACC_(xof_chal_mu)
#define xof_chal_hash RACC_(xof_chal_hash)
#define xof_chal_poly RACC_(xof_chal_poly)

#define xof_sample_q4x RACC_(xof_sample_q4x)
#endif

#ifdef __cplusplus
extern "C" {
#endif

//  Compute mu = H(tr, m) where tr = H(pk), "m" is message of "m_sz" bytes.
void xof_chal_mu(uint8_t mu[RACC_MU_SZ], const uint8_t tr[RACC_TR_SZ],
                 const uint8_t *m, size_t m_sz);

//  Expand "seed" of "seed_sz" bytes to a uniform polynomial (mod q).
//  The input seed is assumed to alredy contain domain separation.
void xof_sample_q(int64_t r[RACC_N], const uint8_t *seed, size_t seed_sz);

//  Sample "bits"-wide signed coefficients from "seed[seed_sz]".
//  The input seed is assumed to alredy contain domain separation.
void xof_sample_u(int64_t r[RACC_N], int bits, const uint8_t *seed,
                  size_t seed_sz);

//  Hash "w" vector with "mu" to produce challenge hash "ch".
void xof_chal_hash(uint8_t ch[], const uint8_t mu[RACC_MU_SZ],
                   const int64_t w[][RACC_N]);

//  Create a challenge polynomial "cp" from a challenge hash "ch".
void xof_chal_poly( int64_t cp[RACC_N], const uint8_t ch[RACC_CH_SZ],
                    int omega);

#ifdef RACC_AVX2
//  Expand four seeds of "s_l64" words, prefixed with four heders
void xof_sample_q4x(int64_t r0[RACC_N], int64_t r1[RACC_N],  // results
                    int64_t r2[RACC_N], int64_t r3[RACC_N], uint64_t h0,
                    uint64_t h1,  //    header words
                    uint64_t h2, uint64_t h3, const uint64_t *s0,
                    const uint64_t *s1,  // seed inputs
                    const uint64_t *s2, const uint64_t *s3,
                    size_t s_l64);  //  s length in 64-bit words
#endif

#ifdef __cplusplus
}
#endif

//  _XOF_SAMPLE_H_
#endif
