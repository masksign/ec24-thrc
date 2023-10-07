//  thrc_core.c
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === Threshold Raccoon signature scheme -- core scheme.

#include <string.h>
#include <math.h>
#include <stdlib.h>

#include "plat_local.h"
#include "thrc_core.h"
#include "polyr.h"
#include "mont64.h"
#include "ct_util.h"
#include "xof_sample.h"
#include "sha3_t.h"
#include "thrc_gauss.h"
#include "nist_random.h"

//  parameters

const thrc_param_t par_thrc128 = {  .sec    = 16,
                                    .max_t  = 1024,
                                    .lg_st  = 20,
                                    .lg_swt = 42,
                                    .nu_t   = 37,
                                    .nu_w   = 40,
                                    .ell    = 4,
                                    .k      = 5,
                                    .omega  = 19    };

//  ExpandA(): Use domain separated XOF to create matrix elements

static void expand_aij(int64_t aij[RACC_N], int i_k, int i_ell,
                       const uint8_t seed[RACC_AS_SZ])
{
    uint8_t buf[RACC_AS_SZ + 8];

    //  --- 3.  hdrA := Ser8(65, i, j, 0, 0, 0, 0, 0)
    buf[0] = 'A';  //   ascii 65
    buf[1] = i_k;
    buf[2] = i_ell;
    memset(buf + 3, 0x00, 8 - 3);

    //  --- 4.  Ai,j <- SampleQ(hdrA, seed)
    memcpy(buf + 8, seed, RACC_AS_SZ);
    xof_sample_q(aij, buf, RACC_AS_SZ + 8);
}

//  compute the B2 bound
//  ( From "Direct Forgery and SelfTargetMSIS." )

static double thrc_b2_bound(const thrc_param_t *par)
{
    return  exp(0.25) * (ldexp(par->omega, par->lg_st) +
                            ldexp(1.0, par->lg_swt)) *
                                sqrt(RACC_N * (par->k + par->ell))
            + ( ldexp(1.0, par->nu_w + 1) + ldexp(par->omega, par->nu_t)) *
                            sqrt(RACC_N * par->k);
}

//  sum of squares (centered)

static double sum_squares(const int64_t *v, size_t v_sz)
{
    size_t i;
    double s, x;

    s = 0.0;
    for (i = 0; i < v_sz; i++) {
        x = (double) (mont64_csub(v[i] + (RACC_Q >> 1),
                        RACC_Q) - (RACC_Q >> 1));       //  center x
        s += x * x;                                     //  square x
    }
    return s;
}

//  Check the two-norm bound. Return True if ok.

static bool check_bounds(   const int64_t z[][RACC_N],
                            const int64_t h[][RACC_N],
                            const thrc_param_t *par)
{
    double b2, n2;

    b2 = thrc_b2_bound(par);
    n2 = sqrt( sum_squares(z[0], par->ell * RACC_N) +
                ldexp( sum_squares(h[0], par->k * RACC_N), 2 * par->nu_w ) );

    //printf("n2= %f  B2= %f    %f\n", n2, b2, n2/b2);
    return n2 <= b2;
}

//  "rounding" shift right (in place)

static inline void round_shift_r(int64_t r[RACC_N], int64_t q, int s)
{
    int i;
    int64_t x, rc;

    rc = 1ll << (s - 1);
    for (i = 0; i < RACC_N; i++) {
        x = (r[i] + rc) >> s;
        r[i] = mont64_csub(x, q);
    }
}

//  hashes a static-length label and a vector of 64-bit values

static void hash_vec(   uint8_t h[RACC_CRH],
                        const uint8_t *dat, size_t dat_sz,
                        const int64_t *v, size_t v_len)
{
    size_t i;
    sha3_t kec;
    uint8_t buf[8];
    int64_t x;

    sha3_init(&kec, SHAKE256_RATE);

    put64u_le(buf, THRC_HDR24('H', dat_sz, THRC_Q_BYT * v_len));
    sha3_absorb(&kec, buf, 8);

    //  data
    sha3_absorb(&kec, dat, dat_sz);

    //  vector
    for (i = 0; i < v_len; i++) {
        x = v[i];
        x = mont64_cadd(x, RACC_Q);
        x = mont64_csub(x, RACC_Q);
        put64u_le(buf, x);
        sha3_absorb(&kec, buf, THRC_Q_BYT);
    }

    sha3_pad(&kec, SHAKE_PAD);
    sha3_squeeze(&kec, h, RACC_CRH);
}

//  Alg. 3: Verify(vk, msg, sigma). Return false if the signature is invalid.

bool thrc_verify(   const thrc_vk_t *vk, const uint8_t *mu,
                    const thrc_sig_t *sig, const thrc_param_t *par)
{
    XALIGN(32) int64_t tmp[RACC_N], aij[RACC_N], c_ntt[RACC_N];
    XALIGN(32) int64_t w[THRC_K_MAX][RACC_N];
    XALIGN(32) int64_t z_ntt[THRC_ELL_MAX][RACC_N];
    XALIGN(32) uint8_t c_hash[RACC_CRH];

    int i, j;

    //  --- 1.  (c, z, h) := parse(sigma)   [caller]

    xof_chal_poly(c_ntt, sig->ch, par->omega);
    polyr_fntt(c_ntt);

    //  --- 2.  c' := Hc(vk, msg, [A * z - 2^nu_t * c * t]_nu_w + h)

    int64_t q_w = (RACC_Q >> par->nu_w);
    int64_t neg2t = mont64_mulq( -(1ll << par->nu_t), MONT_RR );

    for (i = 0; i < par->ell; i++) {
        polyr_copy(z_ntt[i], sig->z[i]);
        polyr_fntt(z_ntt[i]);
    }

    for (i = 0; i < par->k; i++) {
        polyr_ntt_smul(tmp, vk->t[i], neg2t);   //  scale t by -2^nu_t
        polyr_fntt(tmp);
        polyr_ntt_cmul(tmp, tmp, c_ntt);        //  .. - 2^nu_t * c * t]
        for (j = 0; j < par->ell; j++) {
            expand_aij(aij, i, j, vk->a_seed);
            polyr_ntt_mula(tmp, z_ntt[j], aij, tmp);    //  A * z
        }
        polyr_intt(tmp);

        round_shift_r(tmp, q_w, par->nu_w);     //  [..]_nu_w
        polyr_addm(tmp, tmp, sig->h[i], q_w);   //  + h
        polyr_nonneg(w[i], tmp, q_w);
    }
    hash_vec(c_hash, mu, THRC_MU_SZ, w[0], par->k * RACC_N);

    //  --- 3.  if {c = c'} and ||(z, 2^nu_w * h)||_2 <= B2 then
    //  --- 4.      return 1

    if (    memcmp(sig->ch, c_hash, RACC_CRH) == 0 &&
            check_bounds(sig->z, sig->h, par) ) {
        return true;
    }

    //  --- 5.  (else) return 0
    return false;
}

//  Alg. 4: KeyGen(pp, T, N). Threshold Raccoon keypair generation.

bool thrc_keygen(thrc_vk_t *vk, thrc_sk_t sk[],
                 int th_t, int th_n, const thrc_param_t *par)
{
    int i, j, k;
    int64_t xr;
    XALIGN(32) int64_t aij[RACC_N];
    XALIGN(32) int64_t sv[THRC_ELL_MAX][RACC_N];
    XALIGN(32) int64_t ev[THRC_K_MAX][RACC_N];
    XALIGN(32) uint8_t key[8 + THRC_KG_SZ];
    int64_t *pv = NULL;

    //  "pv" polynomial can be very large, needs to be allocated dynamically
    if (posix_memalign((void **) &pv, 32,
                        th_t * par->k * RACC_N * sizeof(int64_t))) {
        return false;
    }

    //  all key material is a deterministic function of this
    randombytes(key + 8, THRC_KG_SZ);

    //  --- 1.  A <- Rq^{k * ell}
    put64u_le(key, THRC_HDR8('A', 0, 0, 0));
    shake256(vk->a_seed, RACC_AS_SZ, key, 8 + THRC_KG_SZ);

    //  --- 2.  (s, e) <- D_t^ell * D_t^k

    double sigt2 = ldexp(1, 2 * par->lg_st);
    for (i = 0; i < par->ell; i++) {
        put64u_le(key, THRC_HDR8('s', i, 0, 0));
        sample_rounded(sv[i], sigt2, key, 8 + THRC_KG_SZ);
        //  save s for P(0)
        polyr_copy(&pv[i * RACC_N], sv[i]);  // 5. .. P(0) = s
        polyr_fntt(sv[i]);            //    NTT domain
    }

    for (i = 0; i < par->k; i++) {
        put64u_le(key, THRC_HDR8('e', i, 1, 0));
        sample_rounded(ev[i], sigt2, key, 8 + THRC_KG_SZ);
    }

    //  --- 3.  t := [ A*s + e ]_nu_t
    for (i = 0; i < par->k; i++) {
        polyr_zero(vk->t[i]);
        for (j = 0; j < par->ell; j++) {
            expand_aij(aij, i, j, vk->a_seed);
            polyr_ntt_mula(vk->t[i], sv[j], aij, vk->t[i]);
        }
        polyr_intt(vk->t[i]);
        polyr_add(vk->t[i], vk->t[i], ev[i]);
        round_shift_r(vk->t[i], RACC_Q >> (par->nu_t), par->nu_t);
    }

    //  --- 4.  vk := (A, t)
    //  (serialization is outside this function)

    //  --- 5.  P <- Rq^ell with deg(P) = T - 1, P(0) = s
    for (i = 1; i < th_t; i++) {
        for (j = 0; j < par->ell; j++) {
            put64u_le(key, THRC_HDR24('p', i, j));
            xof_sample_q(&pv[(i * par->k + j) * RACC_N],
                            key, 8 + THRC_KG_SZ);
        }
    }

    //  --- 6.  (s_i) for i in [N] := (P(i)) for i in [N]
    xr = 0;
    for (i = 0; i < th_n; i++) {
        sk[i].j     =   i;      //  we use 0,1,2,.. but compute P(i+1)
        sk[i].th_n  =   th_n;
        sk[i].th_t  =   th_t;

        xr = mont64_csub(xr + MONT_R, RACC_Q);  //  R, 2R, 3R ..
        for (j = 0; j < par->ell; j++) {
            polyr_copy(sk[i].s[j],
                &pv[((th_t - 1) * par->k + j) * RACC_N]);
            for (k = 2; k <= th_t; k++) {
                polyr_ntt_smul(sk[i].s[j], sk[i].s[j], xr);
                polyr_addq(sk[i].s[j], sk[i].s[j],
                    &pv[((th_t - k) * par->k + j) * RACC_N]);
            }
        }
    }

    //  --- 7.  for i in [N] do
    for (i = 0; i < th_n; i++) {

        //  --- 8.  (vk_{sig,i}, sk_{sig,i}) <- KeyGen_sig()

        //  --- 9.  for j in [N] do
        for (j = 0; j < th_n; j++) {

            //  --- 10. seed_{i,j} = {0,1}^kappa
            put64u_le(key, THRC_HDR24('k', i, j));
            shake256(sk[i].sij[j], THRC_SD_SZ, key, 8 + THRC_KG_SZ);
            memcpy(sk[j].sji[i], sk[i].sij[j], THRC_SD_SZ);
        }
    }

    //  --- 11. for i in [N] do
    //      --- 12. sk_i := ( s_i, (vk_sig,i) for i in [N], sk_{sig,i},
    //                          (seed_{i,j}, seed_{j,i}) for j in [N] )

    //  --  13. return ( vk, (sk_i) for i in [N] )
    free(pv);

    return true;
}

//  Hash Contrib_1 internal data structure

static void hash_ctrb_1(uint8_t h[RACC_CRH],
                        const thrc_ctrb_1_t ctrb_1[],
                        const thrc_view_t *view)
{
    int i;
    uint8_t buf[RACC_CRH];
    sha3_t kec;

    sha3_init(&kec, SHAKE256_RATE);
    //  add domsep here?
    sha3_absorb(&kec, view->seh, THRC_SEH_SZ);

    for (i = 0; i < view->act_t; i++) {
        hash_vec(buf,   ctrb_1[i].cmt, RACC_CRH,
                        ctrb_1[i].m[0], view->par->ell * RACC_N);
        sha3_absorb(&kec, buf, RACC_CRH);
    }

    sha3_pad(&kec, SHAKE_PAD);
    sha3_squeeze(&kec, h, RACC_CRH);
}

//  Hcom commitment function.

static void hcom(   uint8_t cmt[RACC_CRH],
                    const uint8_t seh[THRC_SEH_SZ],
                    const int64_t w[THRC_K_MAX][RACC_N],
                    const thrc_param_t *par)
{
    hash_vec(cmt, seh, RACC_CRH,
            (const int64_t *) w, par->k * RACC_N);  //  seh, w
}

//  Mask generation PRF.

static void mask_prf(   int64_t m[RACC_N],
                        int idx_i, int idx_j, int idx_k,
                        const uint8_t seed[THRC_SD_SZ],
                        const uint8_t seh[THRC_SEH_SZ])
{
    XALIGN(32) uint8_t buf[8 + THRC_SD_SZ + THRC_SID_SZ];

    put64u_le( buf, THRC_HDR24K('m', idx_i, idx_j, idx_k) );
    memcpy(buf + 8, seed, THRC_SD_SZ);
    memcpy(buf + 8 + THRC_SD_SZ, seh, THRC_SEH_SZ);
    xof_sample_q( m, buf, 8 + THRC_SD_SZ + THRC_SEH_SZ );
}

static void mask_prf4x( int64_t m[4][RACC_N],
                        int idx_i, int idx_j,
                        const uint8_t seed[THRC_SD_SZ],
                        const uint8_t seh[THRC_SEH_SZ])
{
    int k;

#ifdef RACC_AVX2
    XALIGN(32) uint8_t buf[THRC_SD_SZ + THRC_SID_SZ];
    uint64_t h[4], *sd;

    memcpy(buf, seed, THRC_SD_SZ);
    memcpy(buf + THRC_SD_SZ, seh, THRC_SEH_SZ);

    for (k = 0; k < 4; k++) {
        h[k] = THRC_HDR24K('m', idx_i, idx_j, k);
    }
    sd = (uint64_t *) buf;
    xof_sample_q4x( m[0], m[1], m[2], m[3],
                    h[0], h[1], h[2], h[3],
                    sd, sd, sd, sd,
                    sizeof(buf) / 8 );
#else
    for (k = 0; k < 4; k++) {
        mask_prf(m[k], idx_i, idx_j, k, seed, seh);
    }
#endif
}

//  Alg. 5: ShareSign_1(state, sid, act, msg)."""
bool thrc_sign_1(   thrc_view_t *view, thrc_ctrb_1_t *ctrb_1,
                    const thrc_vk_t *vk, const thrc_sk_t *sk,
                    const uint8_t *sid,
                    const int64_t *act, int act_t,
                    const uint8_t *mu,
                    const thrc_param_t *par )
{
    int i, j, k, idx_i, idx_j;
    XALIGN(32) int64_t aij[RACC_N];
    XALIGN(32) int64_t tmp[RACC_N];
    XALIGN(32) int64_t r_ntt[THRC_ELL_MAX][RACC_N];
    XALIGN(32) uint8_t key[8 + THRC_KG_SZ];
    XALIGN(32) uint8_t buf[THRC_SID_SZ + THRC_MU_SZ];

    //  --- 1.  assert{ ConsistCheck1(state, sid, act, msg) }
    if (act_t < sk->th_t || act_t > par->max_t) {
        return false;
    }
    view->rnd = 0;

    //  copy public key and secret key
    memset(view, 0, sizeof(thrc_view_t));
    memcpy(&view->vk, vk, sizeof(thrc_vk_t));
    memcpy(&view->sk, sk, sizeof(thrc_sk_t));

    //  other variables
    memcpy(view->mu, mu, THRC_MU_SZ);
    for (i = 0; i < act_t; i++) {
        view->act[i] = act[i];
    }
    view->par = par;
    view->act_t = act_t;

    //  session hash
    memcpy(buf, sid, THRC_SID_SZ);
    memcpy(buf + THRC_SID_SZ, mu, THRC_MU_SZ);
    hash_vec(view->seh, buf, THRC_SID_SZ + THRC_MU_SZ, act, act_t);

    //  master secret for this party
    randombytes(key + 8, THRC_KG_SZ);

    //  --- 2.  (r_j, e'_j) <- D_w^ell * D_w^k

    double sigw2 = ldexp(1, 2 * par->lg_swt) / ((double) act_t);
    for (i = 0; i < par->ell; i++) {
        put64u_le(key, THRC_HDR8('r', i, 0, 0));
        sample_rounded(view->r[i], sigw2, key, 8 + THRC_KG_SZ);
    }

    for (i = 0; i < par->k; i++) {
        put64u_le(key, THRC_HDR8('e', i, 2, 0));
        sample_rounded(view->w[i], sigw2, key, 8 + THRC_KG_SZ);
    }

    //  --- 3.  w_j := A * r_j + e'_j

    for (i = 0; i < par->ell; i++) {
        polyr_copy(r_ntt[i], view->r[i]);
        polyr_fntt(r_ntt[i]);
    }

    for (i = 0; i < par->k; i++) {
        polyr_zero(tmp);
        for (j = 0; j < par->ell; j++) {
            expand_aij(aij, i, j, vk->a_seed);
            polyr_ntt_mula(tmp, r_ntt[j], aij, tmp);
        }
        polyr_intt(tmp);
        polyr_addq(view->w[i], view->w[i], tmp);
    }
    for (i = 0; i < par->k; i++) {
        polyr_nonneg(view->w[i], view->w[i], RACC_Q);
    }

    //  --- 4.  cmt_j := Hcom(sid, act, msg, w_j)

    hcom(ctrb_1->cmt, view->seh, view->w, par);

    //  --- 5.  m_j := SUM_{i in act} PRF(seed_{j,i}, sid)

    idx_j = view->sk.j;
    for (k = 0; k < par->ell; k++) {
        polyr_zero(ctrb_1->m[k]);
    }
    for (i = 0; i < view->act_t; i++) {
        idx_i = act[i];
        if (par->ell == 4) {
            mask_prf4x(r_ntt, idx_j, idx_i, view->sk.sji[idx_i], view->seh);
        } else {
            for (k = 0; k < par->ell; k++) {
                mask_prf(r_ntt[k], idx_j, idx_i, k, view->sk.sji[idx_i], view->seh);
            }
        }

        for (k = 0; k < par->ell; k++) {
            polyr_addq(ctrb_1->m[k], ctrb_1->m[k], r_ntt[k]);
        }
    }

    view->rnd = 1;

    return true;
}

//  Compute a symmetric MAC "signature" for Contrib_1

static void sig_mac_ctrb_1( uint8_t h[THRC_MAC_SZ],
                            int i, int j,
                            const uint8_t seed[THRC_SD_SZ],
                            const uint8_t ctrb_1_h[RACC_CRH])
{
    sha3_t kec;
    uint8_t buf[8];

    sha3_init(&kec, SHAKE256_RATE);
    put64u_le(buf, THRC_HDR24('M', i, j));
    sha3_absorb(&kec, buf, 8);
    sha3_absorb(&kec, seed, THRC_SD_SZ);
    sha3_absorb(&kec, ctrb_1_h, RACC_CRH);

    sha3_pad(&kec, SHAKE_PAD);
    sha3_squeeze(&kec, h, THRC_MAC_SZ);
}

//  Alg. 6: ShareSign_2(state, sid, contrib_1)

bool thrc_sign_2(   thrc_view_t *view, thrc_ctrb_2_t *ctrb_2,
                    const thrc_ctrb_1_t ctrb_1[] )
{
    int i, idx_i;
    uint8_t ctrb_1_h[RACC_CRH];

    //  --- 1:  assert{ ConsistCheck_2 (state, sid, contrib_1 ) }
    if (view->rnd != 1) {
        return false;
    }
    view->rnd = 0;

    //  --- 2:  Fetch sk_sig,j from state.sk
    //  --- 3:  sigma_j <- Sign_sig(sk_sig, sid || act || msg || contrib_1)

    hash_ctrb_1(ctrb_1_h, ctrb_1, view);
    for (i = 0; i < view->act_t; i++) {
        idx_i = view->act[i];
        sig_mac_ctrb_1(ctrb_2->sig[i], idx_i, view->sk.j,
                        view->sk.sij[idx_i], ctrb_1_h);
    }

    //  --- 4:  Fetch w_j from stae.sessions[sid].internal
    //  --- 5:  state.session[sid] := { sid, act, msg, 2,
    //                                  {r_j, w_j, cmt_j, m_j }, contrib_1 }

    for (i = 0; i < view->act_t; i++) {
        memcpy(&view->ctrb_1[i], &ctrb_1[i], sizeof(thrc_ctrb_1_t));
    }

    //  --- 6: return contrib_2[j] := (w_j, sigma_j)
    for (i = 0; i < view->par->k; i++) {
        polyr_copy(ctrb_2->w[i], view->w[i]);
    }

    view->rnd = 2;
    return true;
}

//  Inverse: Given a and n, return a^-1 (mod n) -- if exists.

static int64_t inverse_n(int64_t a, int64_t n)
{
    __int128 q, t, r0, r1, s0, s1;

    r0 = a;
    r1 = n;
    s0 = 1;
    s1 = 0;

    while (r1 != 0) {
        q   = r0 / r1;
        t   = r1;
        r1  = r0 - q * r1;
        r0  = t;
        t   = s1;
        s1  = s0 - q * s1;
        s0  = t;
    }
    s0 %= n;
    if (s0 < 0)
        s0 += n;

    return s0;
}

//  lambda_{S,i} := PROD_{j in S\{i}} -j / (i - j).

static int64_t lagrange(int64_t *s, int t, int64_t i)
{
    int j, k;
    __int128 a, b;

    a = 1;
    b = 1;

    for (k = 0; k < t; k++) {
        j = s[k];
        if (j != i) {
            a = (a * (-j - 1)) % RACC_Q;
            b = (b * (i - j)) % RACC_Q;
        }
    }
    if (a < 0)
        a += RACC_Q;
    if (b < 0)
        b += RACC_Q;
    b = inverse_n((int64_t) b, RACC_Q);

    a = (a * b) % RACC_Q;
    if (a < 0)
        a += RACC_Q;

    return a;
}

//  Alg. 7: ShareSign_3(state, sid, contrib_2)

bool thrc_sign_3(   thrc_view_t *view, thrc_ctrb_3_t *ctrb_3,
                    const thrc_ctrb_2_t ctrb_2[] )
{
    XALIGN(32) int64_t w[THRC_K_MAX][RACC_N];
    int i, j, idx_i, idx_j;
    XALIGN(32) int64_t tmp[RACC_N];
    XALIGN(32) int64_t prf[THRC_ELL_MAX][RACC_N];
    XALIGN(32) uint8_t ctrb_1_h[RACC_CRH];
    XALIGN(32) uint8_t buf[RACC_CRH];
    XALIGN(32) uint8_t c_hash[RACC_CRH];
    XALIGN(32) int64_t c_ntt[RACC_N];
    int64_t lam_j;

    //  --- 1.  assert{ ConsistCheck_3(state, sid, contrib_2 ) }
    if (view->rnd != 2) {
        return false;
    }
    view->rnd = 0;

    //  --- 2.  Let session = state.sessions[sid]
    //  --- 3.  Fetch (sid, act, msg) from session
    //  --- 4.  Fetch r_j from session.internal and s_j,
    //              (vk_{sig,i}) for i in [N],
    //              (seed_{i,j}) for i in act from state.sk
    //  --- 5.  Fetch contrib_1 = (cmt_i, m_i) for i in act
    //              from session.contrib_1
    //  --- 6.  Parse contrib_2 = (w_i, sigma_i) for i in act
    //  --- 7.  for i in act do
    //      --- 8.  assert { cmt_i = H_com(sid, msg, act, w_i ) }

    for (i = 0; i < view->act_t; i++) {
        hcom(buf, view->seh, ctrb_2[i].w, view->par);
        if (memcmp(buf, view->ctrb_1[i].cmt, RACC_CRH) != 0) {
            return false;
        }
    }

    //      --- 9.  assert { Verify_sig(vk_{sig,i},
    //                      sid || act || msg || contrib_1, sig_i ) = 1 }

    hash_ctrb_1(ctrb_1_h, view->ctrb_1, view);

    //  find j index
    idx_j = -1;
    for (i = 0; i < view->act_t; i++) {
        if (view->act[i] == view->sk.j) {
            idx_j = i;
            break;
        }
    }
    if (idx_j < 0) {
        return false;
    }
    for (i = 0; i < view->act_t; i++) {
        idx_i = view->act[i];
        sig_mac_ctrb_1(buf, view->sk.j, idx_i, view->sk.sji[idx_i], ctrb_1_h);
        if (memcmp(buf, ctrb_2[i].sig[idx_j], THRC_MAC_SZ) != 0) {
            return false;
        }
    }

    //  --- 10. w := [ SUM_{i in act} w_i ]_nu_w

    for (i = 0; i < view->par->k; i++) {
        polyr_copy(w[i], ctrb_2[0].w[i]);
        for (j = 1; j < view->act_t; j++) {
            polyr_addq(w[i], w[i], ctrb_2[j].w[i]);
        }
        round_shift_r(w[i], RACC_Q >> (view->par->nu_w), view->par->nu_w);
    }

    //  --- 11. c := H_c(state.vk, msg, w)

    hash_vec(c_hash, view->mu, THRC_MU_SZ, w[0], view->par->k * RACC_N);
    xof_chal_poly(c_ntt, c_hash, view->par->omega);
    polyr_fntt(c_ntt);

    //  --- 12. m*_j := SUM_{i in act} PRF(seed_{i,j}, sid)
    idx_j = view->sk.j;

    for (i = 0; i < view->par->ell; i++) {
        polyr_zero(ctrb_3->z[i]);
    }

    for (j = 0; j < view->act_t; j++) {
        idx_i = view->act[j];

        if (view->par->ell == 4) {
            mask_prf4x(prf, idx_i, idx_j, view->sk.sij[idx_i], view->seh);
        } else {
            for (i = 0; i < view->par->ell; i++) {
                mask_prf(prf[i], idx_i, idx_j, i,
                            view->sk.sij[idx_i], view->seh);
            }
        }

        for (i = 0; i < view->par->ell; i++) {
            polyr_addq(ctrb_3->z[i], ctrb_3->z[i], prf[i]);
        }
    }

    //  --- 13. z_j := c * lambda_{act,j} * s_j + r_j  + m*_j

    lam_j   = lagrange(view->act, view->act_t, view->sk.j);
    lam_j   = mont64_cadd(mont64_mulq(lam_j, MONT_RR), RACC_Q);
    polyr_ntt_smul(c_ntt, c_ntt, lam_j);

    for (i = 0; i < view->par->ell; i++) {
        polyr_copy(tmp, view->sk.s[i]);
        polyr_fntt(tmp);
        polyr_ntt_cmul(tmp, tmp, c_ntt);
        polyr_intt(tmp);
        polyr_addq(tmp, tmp, view->r[i]);
        polyr_addq(ctrb_3->z[i], ctrb_3->z[i], tmp);
    }

    //  --- 14. return  contrib_3[j] := z_j
    view->rnd = 3;
    return true;
}

//  Alg. 8: Combine(vk, sid, msg, contrib_1, contrib_2, contrib_3).

bool thrc_combine(  thrc_sig_t *sig,
                    const thrc_vk_t *vk, const uint8_t *mu,
                    int ctrb_sz,
                    const thrc_ctrb_1_t ctrb_1[],
                    const thrc_ctrb_2_t ctrb_2[],
                    const thrc_ctrb_3_t ctrb_3[],
                    const thrc_param_t *par )
{
    XALIGN(32) int64_t w[THRC_K_MAX][RACC_N];
    XALIGN(32) int64_t c_ntt[RACC_N];
    XALIGN(32) int64_t aij[RACC_N];
    XALIGN(32) int64_t tmp[RACC_N];
    int i, j;

    //  --- 1.  Parse   contrib1 = (cmt_i, m_i) for i in act
    //                  contrib2 = (w_i, sig_i) for i in act
    //                  contrib3 = (z_i) for i in act

    //  --- 2.  Parse vk = (A, t)

    //  --- 3.  w := [ SUM_{i in act} w_i ]_nu_w

    for (i = 0; i < par->k; i++) {
        polyr_copy(w[i], ctrb_2[0].w[i]);
        for (j = 1; j < ctrb_sz; j++) {
            polyr_addq(w[i], w[i], ctrb_2[j].w[i]);
        }
        round_shift_r(w[i], RACC_Q >> (par->nu_w), par->nu_w);
    }

    //  --- 4.  z := SUM_{i in act} (z_i - m_i)

    for (i = 0; i < par->ell; i++) {
        polyr_subq(sig->z[i], ctrb_3[0].z[i], ctrb_1[0].m[i]);
        for (j = 1; j < ctrb_sz; j++) {
            polyr_addq(sig->z[i], sig->z[i], ctrb_3[j].z[i]);
            polyr_subq(sig->z[i], sig->z[i], ctrb_1[j].m[i]);
        }
    }

    //  --- 5.  c := H_c(state.vk, msg, w)

    hash_vec(sig->ch, mu, THRC_MU_SZ, w[0], par->k * RACC_N);
    xof_chal_poly(c_ntt, sig->ch, par->omega);
    polyr_fntt(c_ntt);

    //  --- 6.  y := [A * z - 2^nu_t * c * t]_nu_w

    XALIGN(32) int64_t z_ntt[THRC_ELL_MAX][RACC_N];
    int64_t q_w = (RACC_Q >> par->nu_w);
    int64_t neg2t = mont64_mulq( -(1ll << par->nu_t), MONT_RR );

    for (i = 0; i < par->ell; i++) {
        polyr_copy(z_ntt[i], sig->z[i]);
        polyr_fntt(z_ntt[i]);
    }

    for (i = 0; i < par->k; i++) {
        polyr_ntt_smul(tmp, vk->t[i], neg2t);   //  scale t by -2^nu_t
        polyr_fntt(tmp);
        polyr_ntt_cmul(tmp, tmp, c_ntt);        //  .. - 2^nu_t * c * t]
        for (j = 0; j < par->ell; j++) {
            expand_aij(aij, i, j, vk->a_seed);          //  A * z
            polyr_ntt_mula(tmp, z_ntt[j], aij, tmp);
        }
        polyr_intt(tmp);

        round_shift_r(tmp, q_w, par->nu_w);     //  [..]_nu_w

        //  --- 7.  h := w - y
        polyr_subm(tmp, w[i], tmp, q_w);
        polyr_center(sig->h[i], tmp, q_w);
    }

    //  --- 8.  Return sigma := (c, z, h)

    if (!check_bounds(sig->z, sig->h, par)) {
        return false;
    }

    return true;
}

