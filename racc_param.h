//  racc_param.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Raccoon signature scheme -- Derived parameters.

#ifndef _RACC_PARAM_H_
#define _RACC_PARAM_H_

//  shared parameters
#ifndef RACC_N
#define RACC_N 512
#endif

#ifndef RACC_Q
#define RACC_Q 549824583172097
#endif

#ifndef RACC_KAPPA
#define RACC_KAPPA 128
#endif

//  high level version.
//      0 = Private versions
//      1 = Initial NIST Submssion
//      2 = Threshold Raccoon
#define RACC_VER 2

//  Byte size of symmetric keys / pre-image security
#define RACC_SEC (RACC_KAPPA / 8)

//  Byte size for collision resistant hashes
#define RACC_CRH ((2 * RACC_KAPPA) / 8)

//  Size of A_seed
#if RACC_VER == 1
#define RACC_AS_SZ RACC_SEC
#else
#define RACC_AS_SZ 16
#endif

//  Size of public key hash used in BUFFing -- needs CRH
#define RACC_TR_SZ RACC_CRH

//  size of pk-bound message mu = H(H(pk), msg)
#define RACC_MU_SZ RACC_CRH

//  Size of challenge hash
#define RACC_CH_SZ RACC_CRH

//  Size of "mask keys" in serialized secret key
#define RACC_MK_SZ RACC_SEC

//  shared / derived parameters
#if (RACC_Q == 549824583172097) && (RACC_N == 512)
#define RACC_Q_BITS 49
#define RACC_LGN 9
#else
#error "No known parameter defined."
#endif

#define RACC_QMSK ((1LL << RACC_Q_BITS) - 1)

//  _RACC_PARAM_H_
#endif
