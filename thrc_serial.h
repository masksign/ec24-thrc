//  thrc_serial.h
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Raccoon signature scheme -- Serialize/deserialize.

#ifndef _THRC_SERIAL_H_
#define _THRC_SERIAL_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "racc_param.h"

//  === Global namespace prefix

/*
#ifdef THRC_
#define thrc_encode_vk THRC_(encode_vk)
#define thrc_decode_vk THRC_(decode_vk)
#endif
*/

#ifdef __cplusplus
extern "C" {
#endif

//  Encode Secret Key Share
size_t thrc_encode_sk(uint8_t *b, const thrc_sk_t *sk,
                        int act_n, const thrc_param_t *par);

//  Decode Secret Key Share
size_t thrc_decode_sk(thrc_sk_t *sk, const uint8_t *b,
                        int act_n, const thrc_param_t *par);

//  Encode the public key "vk" to bytes "b". Return length in bytes.
size_t thrc_encode_vk(uint8_t *b, const thrc_vk_t *vk,
                        const thrc_param_t *par);

//  Decode a public key from "b" to "vk". Return length in bytes.
size_t thrc_decode_vk(thrc_vk_t *vk, const uint8_t *b,
                        const thrc_param_t *par);

//  Encode signature "sig" to "*b" of max "b_sz" bytes. Return length in
//  bytes or zero in case of overflow.
size_t thrc_encode_sig( uint8_t *b, size_t b_sz, const thrc_sig_t *sig,
                        const thrc_param_t *par);

//  decode bytes "b" into signature "sig". Return length in bytes.
size_t thrc_decode_sig( thrc_sig_t *sig, const uint8_t *b,  size_t b_sz,
                        const thrc_param_t *par);

//  Encode Contrib_1
size_t thrc_encode_ctrb_1(uint8_t *b, const thrc_ctrb_1_t *ctrb_1,
                            const thrc_param_t *par);

//  Decode Contrib_1
size_t thrc_decode_ctrb_1(thrc_ctrb_1_t *ctrb_1, const uint8_t *b,
                            const thrc_param_t *par);

//  Encode Contrib_2
size_t thrc_encode_ctrb_2(uint8_t *b, const thrc_ctrb_2_t *ctrb_2,
                            int act_t, const thrc_param_t *par);

//  Decode Contrib_2
size_t thrc_decode_ctrb_2(thrc_ctrb_2_t *ctrb_2, const uint8_t *b,
                            int act_t, const thrc_param_t *par);

//  Encode Contrib_3
size_t thrc_encode_ctrb_3(uint8_t *b, const thrc_ctrb_3_t *ctrb_3,
                            const thrc_param_t *par);

//  Decode Contrib_3
size_t thrc_decode_ctrb_3(thrc_ctrb_3_t *ctrb_3, const uint8_t *b,
                            const thrc_param_t *par);

#ifdef __cplusplus
}
#endif

//  _THRC_SERIAL_H_
#endif
