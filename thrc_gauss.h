//  thrc_gauss.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Gaussian samplers for Thrshold Raccoon

#ifndef _THRC_GAUSS_H_
#define _THRC_GAUSS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "racc_param.h"

//  === Global namespace prefix
#ifdef THRC_
#define sample_rounded THRC_(sample_rounded)
#endif

#ifdef __cplusplus
extern "C" {
#endif

//  Deterministic Rounded Gaussian sampler with variance sig2
void sample_rounded(int64_t r[RACC_N], double sig2, const uint8_t *seed,
                    size_t seed_sz);

#ifdef __cplusplus
}
#endif

//  _THRC_GAUSS_H_
#endif
