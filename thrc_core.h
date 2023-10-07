//  thrc_core.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Threshold Raccoon signature scheme -- core scheme.

#ifndef _THRC_CORE_H_
#define _THRC_CORE_H_

#include "plat_local.h"
#include "thrc_param.h"

//  maximum values for static structures
#define THRC_N_MAX      1024
#define THRC_K_MAX      5
#define THRC_ELL_MAX    4

//  === Internal structures ===

//  raccoon public key
typedef struct {
    XALIGN(32) int64_t t[THRC_K_MAX][RACC_N];  //   public key
    uint8_t a_seed[THRC_AS_SZ];                //   seed for a
} thrc_vk_t;

//  raccoon secret key
typedef struct {
    XALIGN(32) int64_t s[THRC_ELL_MAX][RACC_N];  // secret key
    uint8_t sij[THRC_N_MAX][THRC_SD_SZ];
    uint8_t sji[THRC_N_MAX][THRC_SD_SZ];
    int j, th_t, th_n;                          //  parameters
} thrc_sk_t;

//  raccoon signature
typedef struct {
    XALIGN(32) int64_t h[THRC_K_MAX][RACC_N];   //  hint
    XALIGN(32) int64_t z[THRC_ELL_MAX][RACC_N]; //  signature data
    uint8_t ch[RACC_CH_SZ];                     //  challenge hash
} thrc_sig_t;

//  Contribution from Round 1

typedef struct {
    XALIGN(32) int64_t m[THRC_ELL_MAX][RACC_N];
    uint8_t cmt[RACC_CRH];
} thrc_ctrb_1_t;

//  Contribution from Round 2

typedef struct {
    XALIGN(32) int64_t w[THRC_K_MAX][RACC_N];
    uint8_t sig[THRC_N_MAX][THRC_MAC_SZ];
} thrc_ctrb_2_t;

//  Contribution from Round 3

typedef struct {
    XALIGN(32) int64_t z[THRC_ELL_MAX][RACC_N];
} thrc_ctrb_3_t;

//  signing view

typedef struct {
    int     rnd;                                //  round in {1,2,3}
    const   thrc_param_t *par;
    int64_t act[THRC_N_MAX];
    int     act_t;

    XALIGN(32) thrc_vk_t vk;                    //  filled in sign_1
    XALIGN(32) thrc_sk_t sk;
    XALIGN(32) uint8_t seh[THRC_SEH_SZ];
    XALIGN(32) uint8_t mu[THRC_MU_SZ];
    XALIGN(32) int64_t r[THRC_ELL_MAX][RACC_N];
    XALIGN(32) int64_t w[THRC_K_MAX][RACC_N];
    XALIGN(32) thrc_ctrb_1_t ctrb_1[THRC_N_MAX];
} thrc_view_t;

//  threshold key generation

//  Alg. 4: KeyGen(pp, T, N). Threshold Raccoon keypair generation

bool thrc_keygen(   thrc_vk_t *vk, thrc_sk_t sk[],
                    int th_t, int th_n, const thrc_param_t *par);

//  Alg. 5: ShareSign_1(state, sid, act, msg)

bool thrc_sign_1(   thrc_view_t *view, thrc_ctrb_1_t *ctrb_1,
                    const thrc_vk_t *vk, const thrc_sk_t *sk,
                    const uint8_t *sid, const int64_t *act, int act_t,
                    const uint8_t *mu, const thrc_param_t *par);

//  Alg. 6: ShareSign_2(state, sid, contrib_1)

bool thrc_sign_2(   thrc_view_t *view, thrc_ctrb_2_t *ctrb_2,
                    const thrc_ctrb_1_t ctrb_1[] );

//  Alg. 7: ShareSign_3(state, sid, contrib_2)

bool thrc_sign_3(   thrc_view_t *view, thrc_ctrb_3_t *ctrb_3,
                    const thrc_ctrb_2_t ctrb_2[] );

//  Alg. 8: Combine(vk, sid, msg, contrib_1, contrib_2, contrib_3)

bool thrc_combine(  thrc_sig_t *sig,
                    const thrc_vk_t *vk, const uint8_t *mu,
                    int ctrb_sz,
                    const thrc_ctrb_1_t ctrb_1[],
                    const thrc_ctrb_2_t ctrb_2[],
                    const thrc_ctrb_3_t ctrb_3[],
                    const thrc_param_t *par );

//  Alg. 3: Verify(vk, msg, sigma). Return false if the signature is invalid.

bool thrc_verify(   const thrc_vk_t *vk, const uint8_t *mu,
                    const thrc_sig_t *sig, const thrc_param_t *par);

//  _THRC_CORE_H_
#endif
