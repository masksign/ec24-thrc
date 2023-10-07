//  thrc_serial.c
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Raccoon signature scheme -- Serialize/deserialize.

#include <string.h>
#include "thrc_core.h"
#include "plat_local.h"
#include "thrc_serial.h"

#define THRC_HLBITS 1
#define THRC_ZLBITS 41

//  Encode vector v[RACC_N] as packed "bits" sized elements to  *b".
//  Return the number of bytes written -- at most ceil(RACC_N * bits/8).

static inline size_t inline_encode_bits(uint8_t *b, const int64_t v[RACC_N],
                                        size_t bits)
{
    size_t i, j, l;
    int64_t x, m;

    i = 0;  //  source word v[i]
    j = 0;  //  destination byte b[j]
    l = 0;  //  number of bits in x
    x = 0;  //  bit buffer

    m = (1llu << bits) - 1llu;

    while (i < RACC_N) {
        while (l < 8 && i < RACC_N) {
            x |= (v[i++] & m) << l;
            l += bits;
        }
        while (l >= 8) {
            b[j++] = (uint8_t)(x & 0xFF);
            x >>= 8;
            l -= 8;
        }
    }
    if (l > 0) {
        b[j++] = (uint8_t)(x & 0xFF);
    }

    return j;  //   return number of bytes written
}

//  Decode bytes from "*b" as RACC_N vector elements of "bits" each.
//  The decoding is unsigned if "is_signed"=false, two's complement
//  signed representation assumed if "is_signed"=true. Return the
//  number of bytes read -- upper bounded by ceil(RACC_N * bits/8).

static inline size_t inline_decode_bits(int64_t v[RACC_N], const uint8_t *b,
                                        size_t bits, bool is_signed)
{
    size_t i, j, l;
    int64_t x, m, s;

    i = 0;  //  source byte b[i]
    j = 0;  //  destination word v[j]
    l = 0;  //  number of bits in x
    x = 0;  //  bit buffer

    if (is_signed) {
        s = 1llu << (bits - 1);  // extract sign bit
        m = s - 1;
    } else {
        s = 0;  //  sign bit ignored
        m = (1llu << bits) - 1;
    }

    while (j < RACC_N) {

        while (l < bits) {
            x |= ((uint64_t)b[i++]) << l;
            l += 8;
        }
        while (l >= bits && j < RACC_N) {
            v[j++] = (x & m) - (x & s);
            x >>= bits;
            l -= bits;
        }
    }

    return i;  //   return number of bytes read
}

//  === Interface

//  Encode Secret Key Share

size_t thrc_encode_sk(uint8_t *b, const thrc_sk_t *sk,
                        int th_n, const thrc_param_t *par)
{
    int i;
    size_t l = 0;
    size_t sec_sz = par->sec;

    put32u_le(b + l, sk->j);
    l += 4;
    put32u_le(b + l, sk->th_t);
    l += 4;
    put32u_le(b + l, sk->th_n);
    l += 4;

    //  encode s vector
    for (i = 0; i < par->ell; i++) {
        l += inline_encode_bits(b + l, sk->s[i], RACC_Q_BITS);
    }

    //  encode seeds
    for (i = 0; i < th_n; i++) {
        memcpy(b + l, sk->sij[i], sec_sz);
        l += sec_sz;
    }
    for (i = 0; i < th_n; i++) {
        memcpy(b + l, sk->sji[i], sec_sz);
        l += sec_sz;
    }

    return l;
}

//  Decode Secret Key Share

size_t thrc_decode_sk(thrc_sk_t *sk, const uint8_t *b,
                        int th_n, const thrc_param_t *par)
{
    int i;
    size_t l = 0;
    size_t sec_sz = par->sec;

    sk->j = get32u_le(b + l);
    l += 4;
    sk->th_t = get32u_le(b + l);
    l += 4;
    sk->th_n = get32u_le(b + l);
    l += 4;

    //  decode s vector
    for (i = 0; i < par->ell; i++) {
        l += inline_decode_bits(sk->s[i], b + l, RACC_Q_BITS, false);
    }

    //  decode seeds
    for (i = 0; i < th_n; i++) {
        memcpy(sk->sij[i], b + l, sec_sz);
        l += sec_sz;
    }
    for (i = 0; i < th_n; i++) {
        memcpy(sk->sji[i], b + l, sec_sz);
        l += sec_sz;
    }

    return l;
}

//  Encode Contrib_1

size_t thrc_encode_ctrb_1(uint8_t *b, const thrc_ctrb_1_t *ctrb_1,
                            const thrc_param_t *par)
{
    int i;
    size_t l = 0;

    //  encode cmt
    memcpy(b + l, ctrb_1->cmt, RACC_CRH);
    l += RACC_CRH;

    //  encode m vector
    for (i = 0; i < par->ell; i++) {
        l += inline_encode_bits(b + l, ctrb_1->m[i], RACC_Q_BITS);
    }

    return l;
}

//  Decode Contrib_1

size_t thrc_decode_ctrb_1(thrc_ctrb_1_t *ctrb_1, const uint8_t *b,
                            const thrc_param_t *par)
{
    int i;
    size_t l = 0;

    //  decode cmt
    memcpy(ctrb_1->cmt, b + l, RACC_CRH);
    l += RACC_CRH;

    //  decode m vector
    for (i = 0; i < par->ell; i++) {
        l += inline_decode_bits(ctrb_1->m[i], b + l, RACC_Q_BITS, false);
    }

    return l;
}

//  Encode Contrib_2

size_t thrc_encode_ctrb_2(uint8_t *b, const thrc_ctrb_2_t *ctrb_2,
                            int act_t, const thrc_param_t *par)
{
    int i;
    size_t l = 0;
    size_t sec_sz = par->sec;


    //  encode w vector
    for (i = 0; i < par->k; i++) {
        l += inline_encode_bits(b + l, ctrb_2->w[i], RACC_Q_BITS);
    }

    //  encode macs
    for (i = 0; i < act_t; i++) {
        memcpy(b + l, ctrb_2->sig[i], sec_sz);
        l += sec_sz;
    }

    return l;
}

//  Decode Contrib_2

size_t thrc_decode_ctrb_2(thrc_ctrb_2_t *ctrb_2, const uint8_t *b,
                            int act_t, const thrc_param_t *par)
{
    int i;
    size_t l = 0;
    size_t sec_sz = par->sec;

    //  decode w vector
    for (i = 0; i < par->k; i++) {
        l += inline_decode_bits(ctrb_2->w[i], b + l, RACC_Q_BITS, false);
    }

    //  decode macs
    for (i = 0; i < act_t; i++) {
        memcpy(ctrb_2->sig[i], b + l, sec_sz);
        l += sec_sz;
    }

    return l;
}

//  Encode Contrib_3

size_t thrc_encode_ctrb_3(uint8_t *b, const thrc_ctrb_3_t *ctrb_3,
                            const thrc_param_t *par)
{
    int i;
    size_t l = 0;

    //  encode z vector
    for (i = 0; i < par->ell; i++) {
        l += inline_encode_bits(b + l, ctrb_3->z[i], RACC_Q_BITS);
    }

    return l;
}

//  Decode Contrib_3

size_t thrc_decode_ctrb_3(thrc_ctrb_3_t *ctrb_3, const uint8_t *b,
                            const thrc_param_t *par)
{
    int i;
    size_t l = 0;

    //  decode z vector
    for (i = 0; i < par->ell; i++) {
        l += inline_decode_bits(ctrb_3->z[i], b + l, RACC_Q_BITS, false);
    }

    return l;
}

//  Encode the public key "vk" to bytes "b". Return length in bytes.

size_t thrc_encode_vk(uint8_t *b, const thrc_vk_t *vk,
                        const thrc_param_t *par)
{
    int i;
    size_t l;

    l = 0;  //  l holds the length

    //  encode A seed
    memcpy(b + l, vk->a_seed, THRC_AS_SZ);
    l += THRC_AS_SZ;

    //  encode t vector
    for (i = 0; i < par->k; i++) {
        //  domain is q_t; has log2(q) - log(p_t) bits
        l += inline_encode_bits(b + l, vk->t[i], RACC_Q_BITS - par->nu_t);
    }

    return l;
}

//  Decode a public key from "b" to "vk". Return length in bytes.

size_t thrc_decode_vk(thrc_vk_t *vk, const uint8_t *b,
                        const thrc_param_t *par)
{
    int i;
    size_t l;

    l = 0;

    //  decode A seed
    memcpy(vk->a_seed, b + l, THRC_AS_SZ);
    l += THRC_AS_SZ;

    //  decode t vector
    for (i = 0; i < par->k; i++) {
        //  domain is q_t; has log2(q) - log(p_t) bits, unsigned
        l += inline_decode_bits(vk->t[i], b + l, RACC_Q_BITS - par->nu_t, false);
    }

    return l;
}


//  macro for encoding n bits from y
//  (note -- returns from function on overflow)
#define ENC_SIG_PUT_BITS(y, n) \
    {                          \
        while (n > 0) {        \
            n--;               \
            z |= (y & 1) << k; \
            y >>= 1;           \
            k++;               \
            if (k == 8) {      \
                if (l >= b_sz) \
                    return 0;  \
                b[l++] = z;    \
                k = 0;         \
                z = 0;         \
            }                  \
        }                      \
    }

//  Encode signature "sig" to "*b" of max "b_sz" bytes. Return length in
//  bytes or zero in case of overflow.

size_t thrc_encode_sig( uint8_t *b, size_t b_sz, const thrc_sig_t *sig,
                        const thrc_param_t *par)
{
    int i;
    size_t j, k, l, n;
    size_t hlbits = THRC_HLBITS;
    size_t zlbits = THRC_ZLBITS;
    int64_t x, y, s;
    uint8_t z;

    //  encode challenge hash
    memcpy(b, sig->ch, RACC_CH_SZ);
    l = RACC_CH_SZ;  // byte position (length)
    k = 0;           // bit position 0..7
    z = 0x00;        // byte fraction

    //  encode hint
    for (i = 0; i < par->k; i++) {
        for (j = 0; j < RACC_N; j++) {

            x = sig->h[i][j];

            //  normalize
            while (x < -RACC_Q / 2)
                x += RACC_Q;
            while (x > RACC_Q / 2)
                x -= RACC_Q;

            //  set sign
            if (x < 0) {
                x = -x;
                s = 1;
            } else {
                s = 0;
            }

            //  low bits
            y = x & ((1LL << hlbits) - 1);
            x >>= hlbits;

            //  high bits (run of 1's)
            y |= ((1LL << x) - 1) << hlbits;

            if (y == 0) {
                //  stop bit, no sign
                n = hlbits + 1;
            } else {
                //  stop bit (0) and sign
                y |= s << (hlbits + x + 1);
                n = hlbits + x + 2;
            }

            //  encode n bits from y
            ENC_SIG_PUT_BITS(y, n);
        }
    }

    //  encode z
    for (i = 0; i < par->ell; i++) {
        for (j = 0; j < RACC_N; j++) {

            x = sig->z[i][j];

            //  normalize
            while (x < -RACC_Q / 2)
                x += RACC_Q;
            while (x > RACC_Q / 2)
                x -= RACC_Q;

            //  set sign
            if (x < 0) {
                x = -x;
                s = 1;
            } else {
                s = 0;
            }

            //  low bits
            y = x & ((1LL << zlbits) - 1);
            x >>= zlbits;

            //  high bits (run of 1's)
            y |= ((1LL << x) - 1) << zlbits;

            if (y == 0) {
                //  stop bit, no sign
                n = zlbits + 1;
            } else {
                //  stop bit (0) and sign
                y |= s << (zlbits + x + 1);
                n = zlbits + x + 2;
            }

            //  encode n bits from y
            ENC_SIG_PUT_BITS(y, n);
        }
    }

    //  fractional byte
    if (k > 0) {
        if (l >= b_sz)
            return 0;
        b[l++] = z;
    }
    if (l >= b_sz)
        return 0;

    return l;
}

#undef ENC_SIG_PUT_BITS

//  macro that gets a single bit
#define DEC_SIG_GET_BIT(bit) \
    {                        \
        bit = (z >> k) & 1;  \
        k++;                 \
        if (k == 8) {        \
            if (l >= b_sz)   \
                return 0;    \
            z = b[l++];      \
            k = 0;           \
        }                    \
    }

//  decode bytes "b" into signature "sig". Return length in bytes.

size_t thrc_decode_sig( thrc_sig_t *sig, const uint8_t *b, size_t b_sz,
                        const thrc_param_t *par)
{
    int i;
    size_t j, k, l, n;
    uint8_t bit, z;
    int64_t x;
    size_t hlbits = THRC_HLBITS;
    size_t zlbits = THRC_ZLBITS;

    //  decode challenge hash
    memcpy(sig->ch, b, RACC_CH_SZ);
    l = RACC_CH_SZ;

    z = b[l++];
    k = 0;

    //  decode h
    for (i = 0; i < par->k; i++) {
        for (j = 0; j < RACC_N; j++) {
            x = 0;  //  get low bits
            for (n = 0; n < hlbits; n++) {
                DEC_SIG_GET_BIT(bit)
                x |= ((int64_t)bit) << n;
            }
            DEC_SIG_GET_BIT(bit)  //    run length and stop bit
            while (bit == 1) {
                x += (1LL << hlbits);
                DEC_SIG_GET_BIT(bit);
            }
            if (x != 0) {  //   use sign bit if x != 0
                DEC_SIG_GET_BIT(bit)
                if (bit) {  //  negative sign
                    x = RACC_Q - x;
                }
            }

            //  normalize
            if (x > RACC_Q / 2)
                x -= RACC_Q;

            sig->h[i][j] = x;
        }
    }

    //  decode z
    for (i = 0; i < par->ell; i++) {
        for (j = 0; j < RACC_N; j++) {
            x = 0;  //  get low bits
            for (n = 0; n < zlbits; n++) {
                DEC_SIG_GET_BIT(bit)
                x |= ((int64_t)bit) << n;
            }
            DEC_SIG_GET_BIT(bit)  //    run length and stop bit
            while (bit == 1) {
                x += (1LL << zlbits);
                DEC_SIG_GET_BIT(bit);
            }
            if (x != 0) {  //   use sign bit if x != 0
                DEC_SIG_GET_BIT(bit)
                if (bit) {  //  negative sign
                    x = RACC_Q - x;
                }
            }
            sig->z[i][j] = x;
        }
    }
/*
    //  check zero padding
    if (k > 0) {
        if ((z >> k) != 0)  //  fractional bits
            return 0;
        while (l < b_sz) {  //  zero padding
            if (b[l++] != 0)
                return 0;
        }
    }
*/
    return l;
}

#undef DEC_SIG_GET_BIT
