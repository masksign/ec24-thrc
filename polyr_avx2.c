//  polyr_avx2.c
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === AVX2 Arithmetic (WiP)

#ifdef RACC_AVX2

#include <stddef.h>
#include <stdbool.h>
#include <immintrin.h>
#include "polyr.h"
#include "mont64.h"

//  === Polynomial API

//  Zeroize a polynomial:   r = 0.

void polyr_zero(int64_t *r)
{
    int i;
    __m256i *r4 = (__m256i *)r;

    for (i = 0; i < RACC_N / 4; i++) {
        r4[i] = _mm256_setzero_si256();
    }
}

//  Copy a polynomial:  r = a.

void polyr_copy(int64_t *r, const int64_t *a)
{
    int i;
    __m256i *r4 = (__m256i *)r;
    const __m256i *a4 = (const __m256i *)a;

    for (i = 0; i < RACC_N / 4; i++) {
        r4[i] = a4[i];
    }
}

//  Add polynomials:  r = a + b.

void polyr_add(int64_t *r, const int64_t *a, const int64_t *b)
{
    int i;
    __m256i *r4 = (__m256i *)r;
    const __m256i *a4 = (const __m256i *)a;
    const __m256i *b4 = (const __m256i *)b;

    for (i = 0; i < RACC_N / 4; i++) {
        r4[i] = _mm256_add_epi64(a4[i], b4[i]);
    }
}

//  Subtract polynomials:  r = a - b.

void polyr_sub(int64_t *r, const int64_t *a, const int64_t *b)
{
    int i;
    __m256i *r4 = (__m256i *)r;
    const __m256i *a4 = (const __m256i *)a;
    const __m256i *b4 = (const __m256i *)b;

    for (i = 0; i < RACC_N / 4; i++) {
        r4[i] = _mm256_sub_epi64(a4[i], b4[i]);
    }
}

//  Add polynomials mod q:  r = a + b  (mod q).

void polyr_addq(int64_t *r, const int64_t *a, const int64_t *b)
{
    polyr_addm(r, a, b, RACC_Q);
}

//  Subtract polynomials mod q:  r = a - b  (mod q).

void polyr_subq(int64_t *r, const int64_t *a, const int64_t *b)
{
    polyr_subm(r, a, b, RACC_Q);
}

//  Add polynomials:  r = a + b, conditionally subtract m on overflow

void polyr_addm(int64_t *r, const int64_t *a, const int64_t *b, int64_t m)
{
    int i;
    __m256i *r4 = (__m256i *)r;
    const __m256i *a4 = (const __m256i *)a;
    const __m256i *b4 = (const __m256i *)b;
    const __m256i m4 = _mm256_set1_epi64x(m);
    __m256i t4, u4;

    for (i = 0; i < RACC_N / 4; i++) {
        t4 = _mm256_add_epi64(a4[i], b4[i]);
        u4 = _mm256_cmpgt_epi64(m4, t4);
        u4 = _mm256_andnot_si256(u4, m4);
        r4[i] = _mm256_sub_epi64(t4, u4);
    }
}

//  Subtract polynomials:  r = a - b, conditionally add m on underflow.

void polyr_subm(int64_t *r, const int64_t *a, const int64_t *b, int64_t m)
{
    int i;
    __m256i *r4 = (__m256i *)r;
    const __m256i *a4 = (const __m256i *)a;
    const __m256i *b4 = (const __m256i *)b;
    const __m256i m4 = _mm256_set1_epi64x(m);
    const __m256i z4 = _mm256_setzero_si256();
    __m256i t4, u4;

    for (i = 0; i < RACC_N / 4; i++) {
        t4 = _mm256_sub_epi64(a4[i], b4[i]);
        u4 = _mm256_cmpgt_epi64(z4, t4);
        u4 = _mm256_and_si256(u4, m4);
        r4[i] = _mm256_add_epi64(t4, u4);
    }
}

#endif
