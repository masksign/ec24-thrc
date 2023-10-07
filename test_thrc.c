//  test_thrc.c
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Threshold Raccoon signature scheme -- core scheme.

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "thrc_core.h"
#include "nist_random.h"
#include "thrc_serial.h"
#include "dbg_util.h"

//  for deterministic testing..
//#define THRC_CHECKSUMS

//  standard library process time

static inline double cpu_clock_secs()
{
    return ((double)clock()) / ((double)CLOCKS_PER_SEC);
}

void print_bench(const char *lab, int div, double ts, uint64_t cc)
{
    printf("[CLK]\t%s(%d)\t%8.3f ms\t%8.3f Mcyc\n", lab, div,
           1000.0 * ts / ((double) div), 1E-6 * ((double)(cc / div)));
    fflush(stdout);
}

#define TS_CC_START { ts = cpu_clock_secs(); cc = plat_get_cycle(); }

#define TS_CC_END(lab) { \
    cc = plat_get_cycle() - cc; \
    ts = cpu_clock_secs() - ts; \
    print_bench(lab, act_sz, ts, cc); \
}

#define TS_CC_END1(lab) { \
    cc = plat_get_cycle() - cc; \
    ts = cpu_clock_secs() - ts; \
    print_bench(lab, 1, ts, cc); \
}


//  --- threshold test / simulation code

int test_thrc(int act_sz, int th_t, int th_n)
{
    const thrc_param_t *par;
    int i, j;
    XALIGN(32) thrc_vk_t vk;
    XALIGN(32) thrc_sig_t sig;

    uint8_t mu[THRC_MU_SZ];
    uint8_t sid[THRC_SID_SZ];

    if (th_t < 0 || th_n < 2 || act_sz < 2 ||
        act_sz > th_n || th_n > THRC_N_MAX) {
        fprintf(stderr,
                "Illegal parameters |act|=%d, T=%d, N=%d\n",
                act_sz, th_t, th_n);
        return -1;
    }

    //  benchmarking
    double ts;
    uint64_t cc;

    size_t l = 0;

    //  test parameters

    par     = &par_thrc128;

    int64_t act[THRC_N_MAX];

    for (i = 0; i < act_sz; i++) {
        act[i] = i;
    }

    //

    uint8_t         *buf = NULL;
    size_t          mem_buf_sz = th_n * 0x10000;
    thrc_sk_t       *sk = NULL;
    size_t          mem_sk_sz = th_n * sizeof(thrc_sk_t);
    thrc_view_t     *view = NULL;
    size_t          mem_view_sz = act_sz * sizeof(thrc_view_t);
    thrc_ctrb_1_t   *ctrb_1 = NULL;
    size_t          mem_ctrb_1_sz = act_sz * sizeof(thrc_ctrb_1_t);
    thrc_ctrb_2_t   *ctrb_2 = NULL;
    size_t          mem_ctrb_2_sz = act_sz * sizeof(thrc_ctrb_2_t);
    thrc_ctrb_3_t   *ctrb_3 = NULL;
    size_t          mem_ctrb_3_sz = act_sz * sizeof(thrc_ctrb_3_t);

    //  get aligned work memory

    if (posix_memalign((void **) &buf,    32, mem_buf_sz)    ||
        posix_memalign((void **) &sk,     32, mem_sk_sz)     ||
        posix_memalign((void **) &view,   32, mem_view_sz)   ||
        posix_memalign((void **) &ctrb_1, 32, mem_ctrb_1_sz) ||
        posix_memalign((void **) &ctrb_2, 32, mem_ctrb_2_sz) ||
        posix_memalign((void **) &ctrb_3, 32, mem_ctrb_3_sz)) {
        perror("posix_memalign()");
        return 0;
    }

    /*
    printf("thrc_sk_t      %p %zu\n", sk, sizeof(thrc_sk_t));
    printf("thrc_view_t    %p %zu\n", view, sizeof(thrc_view_t));
    printf("thrc_ctrb_1_t  %p %zu\n", ctrb_1, sizeof(thrc_ctrb_1_t));
    printf("thrc_ctrb_2_t  %p %zu\n", ctrb_2, sizeof(thrc_ctrb_2_t));
    printf("thrc_ctrb_3_t  %p %zu\n", ctrb_3, sizeof(thrc_ctrb_3_t));
    */

    uint8_t vk_b[10000];        //  verification key
    size_t vk_sz = 0;
    uint8_t sig_b[100000];      //  signature
    size_t sig_sz = 0;

    for (i = 0; i < RACC_CRH; i++) {
        mu[i] = i;
        sid[i] = 100+i;
    }

    //  initialize nist pseudo random
    uint8_t seed[48];

    for (i = 0; i < 48; i++) {
        seed[i] = i;
    }
#ifndef THRC_CHECKSUMS
    if (getrandom(seed, sizeof(seed), GRND_NONBLOCK) != sizeof(seed)) {
        perror("getrandom()");
    }
#endif
    dbg_hex("seed", seed, sizeof(seed));

    nist_randombytes_init(seed, NULL, 256);

    printf("\n[SIZ]\tT\t =%9d\n[SIZ]\tN\t =%9d\n", th_t, th_n);

    //  key generation

    printf("--- Key Generation: ---\n");

    ts = cpu_clock_secs();
    cc = plat_get_cycle();

    TS_CC_START
    thrc_keygen(&vk, sk, th_t, th_n, par);
    TS_CC_END("thrc_keygen")

    //  test serialize & deserialize

    dbg_dim("vk: t", &vk.t, par->k);
    dbg_hex("vk: A_seed", vk.a_seed, THRC_AS_SZ);

    vk_sz = thrc_encode_vk(vk_b, &vk, par);
    printf("SER vk = %zu\n", vk_sz);
    memset(&vk, 0xAA, sizeof(vk));
    printf("DES vk = %zu\n", thrc_decode_vk(&vk, vk_b, par));

    l = 0;
    for (i = 0; i < th_n; i++) {
        l += thrc_encode_sk(buf + l, &sk[i], th_n, par);
    }
    printf("SER sk = %zu\n", l);
    size_t sk_sz = l;

    memset(sk, 0xBB, mem_sk_sz);
    l = 0;
    for (i = 0; i < th_n; i++) {
        l += thrc_decode_sk(&sk[i], buf + l, th_n, par);
    }
    printf("DES sk = %zu\n", l);


#ifdef THRC_CHECKSUMS
    for (i = 0; i < th_n; i++) {
        printf("%d\t", i);
        dbg_dim("s", sk[i].s, par->ell);
    }
#endif

    //  === sign, round 1

    printf("--- Round 1: ---\n");

    TS_CC_START

    for (i = 0; i < act_sz; i++) {
        j = act[i];
        if (!thrc_sign_1(&view[i], &ctrb_1[i],
                    &vk, &sk[j], sid, act, act_sz, mu, par )) {
            printf("FAIL: thrc_sign_1() i= %d j= %d\n", i, j);
        }
#ifdef THRC_CHECKSUMS
        printf("%d\t", i);
        dbg_dim("m", ctrb_1[i].m, par->ell);
        dbg_hex("cmt", ctrb_1[i].cmt, RACC_CRH);
#endif
    }

    TS_CC_END("thrc_sign_1")

    //  test serialize & deserialize
    l = 0;
    for (i = 0; i < act_sz; i++) {
        l += thrc_encode_ctrb_1(buf + l, &ctrb_1[i], par);
    }
    printf("SER ctrb_1 = %zu\n", l);

    memset(ctrb_1, 0x11, sizeof(mem_ctrb_1_sz));
    l = 0;
    for (i = 0; i < act_sz; i++) {
        l += thrc_decode_ctrb_1(&ctrb_1[i], buf + l, par);
    }
    size_t ctrb_1_sz = l;
    printf("DES ctrb_1 = %zu\n", l);

    //  === sign, round 2

    printf("--- Round 2: ---\n");

    TS_CC_START

    for (i = 0; i < act_sz; i++) {
        j = act[i];
        if (!thrc_sign_2(&view[i], &ctrb_2[i], ctrb_1)) {
            printf("FAIL: thrc_sign_2() i= %d j= %d\n", i, j);
        }
#ifdef THRC_CHECKSUMS
        printf("%d\t", i);
        dbg_dim("w", ctrb_2[i].w, par->k);
#endif
    }

    TS_CC_END("thrc_sign_2")

    //  test serialize & deserialize

    l = 0;
    for (i = 0; i < act_sz; i++) {
        l += thrc_encode_ctrb_2(buf + l, &ctrb_2[i], act_sz, par);
    }
    size_t ctrb_2_sz = l;
    printf("SER ctrb_2 = %zu\n", l);

    memset(ctrb_2, 0x22, sizeof(mem_ctrb_2_sz));
    l = 0;
    for (i = 0; i < act_sz; i++) {
        l += thrc_decode_ctrb_2(&ctrb_2[i], buf + l, act_sz, par);
    }
    printf("DES ctrb_2 = %zu\n", l);

    //  === sign, round 3

    printf("--- Round 3: ---\n");

    TS_CC_START

    for (i = 0; i < act_sz; i++) {
        j = act[i];
        if (!thrc_sign_3(&view[i], &ctrb_3[i], ctrb_2)) {
            printf("FAIL: thrc_sign_3() i= %d j= %d\n", i, j);
        }
#ifdef THRC_CHECKSUMS
        printf("%d\t", i);
        dbg_dim("z", ctrb_3[i].z, par->ell);
#endif
    }

    TS_CC_END("thrc_sign_3")

    //  test serialize & deserialize

    l = 0;
    for (i = 0; i < act_sz; i++) {
        l += thrc_encode_ctrb_3(buf + l, &ctrb_3[i], par);
    }
    size_t ctrb_3_sz = l;
    printf("SER ctrb_3 = %zu\n", l);

    memset(ctrb_3, 0x33, sizeof(mem_ctrb_3_sz));
    l = 0;
    for (i = 0; i < act_sz; i++) {
        l += thrc_decode_ctrb_3(&ctrb_3[i], buf + l, par);
    }
    printf("DES ctrb_3 = %zu\n", l);

    //  === sign, combine

    printf("--- Combine: ---\n");

    TS_CC_START

    if (!thrc_combine(&sig, &vk, mu, act_sz, ctrb_1, ctrb_2, ctrb_3, par)) {
        printf("FAIL: thrc_combine()\n");
    }

    TS_CC_END1("thrc_combine")

    dbg_hex("sig c:", sig.ch, RACC_CH_SZ);
    dbg_dim("sig z:", sig.z, par->ell);
    dbg_dim("sig h:", sig.h, par->k);

    //  === verify

    sig_sz = thrc_encode_sig(sig_b, sizeof(sig_b), &sig, par);
    printf("SER sig = %zu\n", sig_sz);

    memset(&sig, 0xCC, sizeof(sig));
    printf("thrc_decode_sig: %zu (%zu)\n",
        thrc_decode_sig(&sig, sig_b, sig_sz, par), sig_sz);

    printf("--- Verify: ---\n");

    TS_CC_START

    if (!thrc_verify(&vk, mu, &sig, par)) {
        printf("FAIL: thrc_verify()\n");
    } else {
        printf("Verify OK.\n");
    }

    TS_CC_END1("thrc_verify")

    //  summary
    printf("[SIZ]\t|vk|\t =%9zu\n", vk_sz);
    printf("[SIZ]\t|sk|\t =%9zu\n", sk_sz);
    printf("[SIZ]\t|sk|/N\t =%9zu\n", sk_sz / th_n);
    printf("[SIZ]\t|sig|\t =%9zu\n", sig_sz);
    l = ctrb_1_sz + ctrb_2_sz + ctrb_3_sz;
    printf("[SIZ]\t|ctrb|\t =%9zu +%9zu +%9zu\t= %9zu\n",
        ctrb_1_sz, ctrb_2_sz, ctrb_3_sz, l);
    printf("[SIZ]\t|ctrb|/T =%9zu +%9zu +%9zu\t= %9zu\n",
        ctrb_1_sz / act_sz, ctrb_2_sz / act_sz, ctrb_3_sz / act_sz,
        l / act_sz);

    printf("\n");

    free(buf);
    free(sk);
    free(view);
    free(ctrb_1);
    free(ctrb_2);
    free(ctrb_3);

    return 0;
}

int main(int argc, char **argv)
{
    int th_t = 0, th_n = 0, act_sz = 0;
    if (argc != 4) {
        fprintf(stderr, "Usage: <xtest> |act| T N\n");
        return -1;
    }
    act_sz = atoi(argv[1]);
    th_t = atoi(argv[2]);
    th_n = atoi(argv[3]);

    return test_thrc(act_sz, th_t, th_n);
}

