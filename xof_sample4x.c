//  xof_sample4x.c
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === AVX2 mod Q Sampler
//  (note: Currently SHAKE-128 only)

#ifdef RACC_AVX2

#include <string.h>
#include <immintrin.h>
#include "KeccakP-1600-times4-SnP.h"

#include "plat_local.h"
#include "thrc_param.h"
#include "sha3_t.h"
#include "xof_sample.h"

//  expand 7x64-bit words into 8 x 56-bit masked, with 4 stripe

static inline void unp_4x8_49(void *d0, void *d1, void *d2, void *d3,
                              const __m256i *v)
{
    const __m256i m49 = _mm256_set1_epi64x(RACC_QMSK);
    const __m128i wi0 = _mm_set_epi32(12, 8, 4, 0);
    const __m128i wi1 = _mm_set_epi32(13, 9, 5, 1);
    const __m128i wi2 = _mm_set_epi32(14, 10, 6, 2);
    const __m128i wi3 = _mm_set_epi32(15, 11, 7, 3);

    XALIGN(64) __m256i r[4];
    const void *br = (const void *)r;

    //  unpack 4x4
    r[0] = v[0] & m49;
    r[1] = (_mm256_srli_epi64(v[0], 56) ^ _mm256_slli_epi64(v[1], 8)) & m49;
    r[2] = (_mm256_srli_epi64(v[1], 48) ^ _mm256_slli_epi64(v[2], 16)) & m49;
    r[3] = (_mm256_srli_epi64(v[2], 40) ^ _mm256_slli_epi64(v[3], 24)) & m49;
    _mm256_storeu_si256(d0, _mm256_i32gather_epi64(br, wi0, 8));
    _mm256_storeu_si256(d1, _mm256_i32gather_epi64(br, wi1, 8));
    _mm256_storeu_si256(d2, _mm256_i32gather_epi64(br, wi2, 8));
    _mm256_storeu_si256(d3, _mm256_i32gather_epi64(br, wi3, 8));

    r[0] = (_mm256_srli_epi64(v[3], 32) ^ _mm256_slli_epi64(v[4], 32)) & m49;
    r[1] = (_mm256_srli_epi64(v[4], 24) ^ _mm256_slli_epi64(v[5], 40)) & m49;
    r[2] = (_mm256_srli_epi64(v[5], 16) ^ _mm256_slli_epi64(v[6], 48)) & m49;
    r[3] = _mm256_srli_epi64(v[6], 8) & m49;
    _mm256_storeu_si256(d0 + 32, _mm256_i32gather_epi64(br, wi0, 8));
    _mm256_storeu_si256(d1 + 32, _mm256_i32gather_epi64(br, wi1, 8));
    _mm256_storeu_si256(d2 + 32, _mm256_i32gather_epi64(br, wi2, 8));
    _mm256_storeu_si256(d3 + 32, _mm256_i32gather_epi64(br, wi3, 8));
}

//  rejection sampler on a block

static inline int reject_q(int64_t *r, const int64_t *v, int len, int end)
{
    int i, j;
    int64_t x;

    j = 0;
    for (i = 0; i < len && j < end; i++) {
        x = v[i];
        if (x < RACC_Q) {
            r[j++] = x;
        }
    }

    return j;
}

//  sample 4 mod q vectors of length n

static void xof128_q4x(int64_t *r0, int64_t *r1, int64_t *r2, int64_t *r3,
                       __m256i *ks)
{
    int l, l0, l1, l2, l3;
    XALIGN(64) int64_t v[4][24];

    l0 = RACC_N;
    l1 = RACC_N;
    l2 = RACC_N;
    l3 = RACC_N;

    do {
        //  permutation
        KeccakP1600times4_PermuteAll_24rounds(ks);

        //  unpack 21 words into linear 24 words
        unp_4x8_49(&v[0][0], &v[1][0], &v[2][0], &v[3][0], &ks[0]);
        unp_4x8_49(&v[0][8], &v[1][8], &v[2][8], &v[3][8], &ks[7]);
        unp_4x8_49(&v[0][16], &v[1][16], &v[2][16], &v[3][16], &ks[14]);

        //  rejection sampler
        l = reject_q(r0, v[0], 24, l0);
        l0 -= l;
        r0 += l;

        l = reject_q(r1, v[1], 24, l1);
        l1 -= l;
        r1 += l;

        l = reject_q(r2, v[2], 24, l2);
        l2 -= l;
        r2 += l;

        l = reject_q(r3, v[3], 24, l3);
        l3 -= l;
        r3 += l;

    } while (l0 != 0 || l1 != 0 || l2 != 0 || l3 != 0);
}

//  Expand four seeds of "s_l64" words, prefixed with four headers

void xof_sample_q4x(int64_t r0[RACC_N], int64_t r1[RACC_N],  // results
                    int64_t r2[RACC_N], int64_t r3[RACC_N], uint64_t h0,
                    uint64_t h1,  //    header words
                    uint64_t h2, uint64_t h3, const uint64_t *s0,
                    const uint64_t *s1,  // seed inputs
                    const uint64_t *s2, const uint64_t *s3,
                    size_t s_l64)  //   s length in 64-bit words
{
    const size_t r = SHAKE128_RATE / 8;
    size_t i;

    //  state
    XALIGN(32) union {
        uint64_t u64[25][4];
        __m256i u256[25];
    } s;

    //  load header
    s.u256[0] = _mm256_set_epi64x(h3, h2, h1, h0);

    //  load seeds
    for (i = 0; i < s_l64; i++) {
        s.u256[1 + i] = _mm256_set_epi64x(s3[i], s2[i], s1[i], s0[i]);
    }

    //  padding 1
    s.u256[1 + s_l64] = _mm256_set1_epi64x(SHAKE_PAD);

    //  zeroes 1
    for (i = 2 + s_l64; i < r - 1; i++) {
        s.u256[i] = _mm256_setzero_si256();
    }
    //  padding 2
    s.u256[r - 1] = _mm256_set1_epi64x(1llu << 63);

    //  zeroes 2
    for (i = r; i < 25; i++) {
        s.u256[i] = _mm256_setzero_si256();
    }

    //  expand
    xof128_q4x(r0, r1, r2, r3, s.u256);
}

//  RACC_AVX2
#endif
