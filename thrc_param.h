//  thrc_param.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Threshold Raccoon signature scheme -- Derived parameters.

#ifndef _THRC_PARAM_H_
#define _THRC_PARAM_H_

//  you only need to include thrc_param.h, not both
#include "racc_param.h"

//  note: we are only partially defining parameters dynamically
typedef struct {
    int sec;    //  kappa / 8
    int max_t;  //  maximum number of signers
    int lg_st;  //  sigma_t = 2**lg_st
    int lg_swt; //  sigma_w * sqrt(T) = 2**lg_swt
    int nu_t;   //  public bit drop
    int nu_w;   //  challenge bit drop
    int ell;    //  secret length
    int k;      //  error length
    int omega;  //  weight of the challenge
} thrc_param_t;

//  parameter sets (thrc_param.c)

extern const thrc_param_t par_thrc128;
extern const thrc_param_t par_thrc192;
extern const thrc_param_t par_thrc256;

//  bytes in Q
#define THRC_Q_BYT ((RACC_Q_BITS + 7) / 8)

//  Size of secret quantities in 64-bit words
#define THRC_K64 (RACC_KAPPA / 64)

//  Size of the A seed
#define THRC_AS_SZ 16

//  Size of the "master secret"
#define THRC_SD_SZ RACC_SEC

//  Size of MACs
#define THRC_MAC_SZ RACC_SEC

//  Size of sssion id
#define THRC_SID_SZ RACC_CRH

//  Size of session hash H( sid, mu, act )
#define THRC_SEH_SZ RACC_CRH

//  Signature (+ public key) hash mu size
#define THRC_MU_SZ  RACC_CRH

//  Commitment size
#define THRC_CMT_SZ RACC_CRH

//  Size of the "master secret" used to generate secret key
#define THRC_KG_SZ 32

//  Header creation macros
#define THRC_HDR8(id, i, j, k)                                       \
    (((uint64_t)id) | (((uint64_t)i) << 8) | (((uint64_t)j) << 16) | \
     (((uint64_t)k) << 24))

#define THRC_HDR24(id, i, j) \
    (((uint64_t)id) | (((uint64_t)i) << 16) | (((uint64_t)j) << 40))

#define THRC_HDR24K(id, i, j, k) \
    (((uint64_t)id) | (((uint64_t)k) << 8) | \
    (((uint64_t)i) << 16) | (((uint64_t)j) << 40))

//  _THRC_PARAM_H_
#endif
