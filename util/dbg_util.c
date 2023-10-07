//  dbg_util.c
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === private tests and benchmarks

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plat_local.h"
#include "dbg_util.h"
#include "sha3_t.h"

#ifndef RACC_N
#define RACC_N 512
#endif

#ifndef RACC_Q
#define RACC_Q 549824583172097
#endif

//  [debug] mod q checksums of polynomials. "len" is number of polys

int64_t dbg_sum(const int64_t *v, size_t len)
{
    size_t i;
    int64_t s;

    s = 31337;
    for (i = 0; i < RACC_N * len; i++) {
        s = (15 * s + v[i]) % RACC_Q;
    }
    while (s < 0) {
        s += RACC_Q;
    }
    return s;
}

//  [debug] print dimensions and checksums; "len" is number of polys

int64_t dbg_dim(const char *lab, const void *vp, size_t len)
{
    int64_t s;
    const int64_t *v = (const int64_t *)vp;
    s = dbg_sum(v, len);
    printf("%s[%zu][%d] = %ld\n", lab, len, RACC_N, s);
    return s;
}

//  [debug] print 64-bit vectors of "len" elements

void dbg_vec(const char *lab, const void *vp, size_t len)
{
    size_t i;
    const int64_t *v = (const int64_t *)vp;
    printf("%s[%zu][%zu] = [%ld", lab, len / RACC_N, len % RACC_N, v[0]);
    for (i = 1; i < len; i++) {
        printf(", %ld", v[i]);
    }
    printf("]\n");
}

//  [debug] (shake) checksums of data

void dbg_chk(const char *lab, uint8_t *data, size_t data_sz)
{
    size_t i;
    uint8_t md[16] = {0};

    shake256(md, sizeof(md), data, data_sz);
    printf("%s: ", lab);
    for (i = 0; i < sizeof(md); i++) {
        printf("%02x", md[i]);
    }
    printf(" (%zu)\n", data_sz);
}

//  [debug] dump a hex string

void dbg_hex(const char *lab, const uint8_t *data, size_t data_sz)
{
    size_t i;
    printf("%s = ", lab);
    for (i = 0; i < data_sz; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

