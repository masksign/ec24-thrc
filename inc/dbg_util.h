//	dbg_util.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//	=== debug utilities

#ifndef _DBG_UTIL_H_
#define _DBG_UTIL_H_

#include <stddef.h>
#include <stdint.h>

//  [debug] mod q checksums of polynomials. "len" is number of polys
int64_t dbg_sum(const int64_t *v, size_t len);

//  [debug] print dimensions and checksums; "len" is number of polys
int64_t dbg_dim(const char *lab, const void *vp, size_t len);

//  [debug] print 64-bit vectors of "len" elements
void dbg_vec(const char *lab, const void *vp, size_t len);

//  [debug] (shake) checksums of data
void dbg_chk(const char *lab, uint8_t *data, size_t data_sz);

//  [debug] dump a hex string
void dbg_hex(const char *lab, const uint8_t *data, size_t data_sz);

//	_DBG_UTIL_H_
#endif

