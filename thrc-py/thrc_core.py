"""
thrc_core.py
Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

=== Masked Raccoon signature scheme: Core implementation.
"""

import os

from Crypto.Hash import SHAKE128,SHAKE256
from nist_kat_drbg import NIST_KAT_DRBG
from polyr import *
from thrc_gauss import sample_rounded

BYTEORDER = "little"

class ThRc_Core:

    ### Public Interface

    #   initialize
    def __init__(self,  kappa=128, max_t=1024, lg_st=20, lg_swt=42,
                        nu_t=37, nu_w=40, ell=4, k=5, omega=19,
                        n=RACC_N, q=RACC_Q, random_bytes=os.urandom):
        """Initialize a Raccoon instance."""

        self.n      =   n
        self.q      =   q
        self.q_bits =   self.q.bit_length()

        self.name   =   f'TRaccoon-{kappa}-{max_t}'
        self.kappa  =   kappa
        self.max_t  =   max_t
        self.lg_st  =   lg_st               # log2(sigma_t)
        self.lg_swt =   lg_swt              # log2(sigma_w * sqrt(T))
        self.nu_t   =   nu_t
        self.q_t    =   q >> nu_t
        self.nu_w   =   nu_w
        self.q_w    =   q >> nu_w
        self.ell    =   ell
        self.k      =   k
        self.omega  =   omega

        self.sec    =   self.kappa//8       # pre-image resistance, bytes
        self.crh    =   2*self.sec          # collision resistance, bytes
        self.as_sz  =   16                  # "A" seed size
        self.kg_sz  =   32                  # key generation secret size
        self.sd_sz  =   self.sec            # seed size
        self.mac_sz =   self.sec            # mac size
        self.mu_sz  =   self.crh            # mu digest H(tr, m) size
        self.ch_sz  =   self.crh            # Challenge hash size
        self.sid_sz =   self.crh            # Session identifier
        self.seh_sz =   self.crh            # Session hash H(sid, M, act)
        #self.mk_sz =   self.sec            # serialization "key" size

        self.random_bytes = random_bytes

        #   calculate derived parmeters
        self.b2     =   self._compute_b2_bound()

    def plain_sign(self, vk, sk, mu):
        """ Alg. 2: Sign(vk, sk, msg)."""

        #   --- 0.  (initialize)
        (A_seed, t) = vk
        A_ntt   = self._expand_a(A_seed)
        key = self.random_bytes(self.kg_sz)     # master random

        #   --- 1.  (r_j, e'_j) <- D_w^ell * D_w^k
        sigw2 = 1 << (2*self.lg_swt)
        r   = [ sample_rounded(sigw2, self._hdr8('r', i) + key)
                for i in range(self.ell) ]
        e2  = [ sample_rounded(sigw2, self._hdr8('e', i, 2) + key)
                for i in range(self.k) ]

        #   --- 2.  [ w := A * r + e' ]_nu_w
        r_ntt   = vec_ntt(r)
        w_ntt   = mul_mat_vec_ntt(A_ntt, r_ntt)
        w       = vec_intt(w_ntt)
        w       = vec_add(w, e2)
        w       = vec_rshift(w, self.nu_w, self.q_w)

        #   --- 3.  c := H_c(state.vk, msg, w)
        c_hash  = self._hash_vec(mu, w)
        c       = self._chal_poly(c_hash)
        c_ntt   = ntt(c.copy())

        #   --- 4.  z := c * s + r
        s_ntt   = vec_ntt(sk)
        z_ntt   = vec_mul_ntt(c_ntt, s_ntt)
        z_ntt   = vec_add(z_ntt, r_ntt)
        z       = vec_intt(z_ntt)

        #   --- 5.  y := [A * z - 2^nu_t * c * t]_nu_w
        y_ntt   = mul_mat_vec_ntt(A_ntt, z_ntt)
        tmp     = vec_lshift(t, self.nu_t)
        tmp     = vec_ntt(tmp)
        tmp     = vec_mul_ntt(c_ntt, tmp)
        y_ntt   = vec_sub(y_ntt, tmp)
        y       = vec_intt(y_ntt)
        y       = vec_rshift(y, self.nu_w, self.q_w)

        #   --- 6.  h := w - y
        h       = vec_sub(w, y)

        #   --- 7.  return sigma := (c, z, h)
        return  (c_hash, z, h)

    def verify(self, vk, mu, sig):
        """Alg. 3: Verify(vk, msg, sigma)."""

        #   --- 1.  (c, z, h) := parse(sigma)
        (c_hash, z, h) = sig
        (A_seed, t) = vk

        c       = self._chal_poly(c_hash)
        c_ntt   = ntt(c)

        #   --- 2.  c' := Hc(vk, msg, [A * z - 2^nu_t * c * t]_nu_w + h)
        A_ntt   = self._expand_a(A_seed)
        z_ntt   = vec_ntt(z)

        w_ntt   = mul_mat_vec_ntt(A_ntt, z_ntt)
        tmp     = vec_lshift(t, self.nu_t)
        tmp     = vec_ntt(tmp)
        tmp     = vec_mul_ntt(c_ntt, tmp)
        w_ntt   = vec_sub(w_ntt, tmp)
        w       = vec_intt(w_ntt)
        w       = vec_rshift(w, self.nu_w, self.q_w)
        w       = vec_add(w, h, self.q_w)
        c_hash2 = self._hash_vec(mu, w)

        #   --- 3.  if {c = c'} and ||(z, 2^nu_w * h)||_2 <= B2 then
        #   --- 4.      return 1
        #   --- 5.  (else) return 0

        return (c_hash == c_hash2) and self._check_bounds(z, h)


    def keygen(self, th_t=1, th_n=1):
        """Alg. 4: KeyGen(pp, T, N). Threshold Raccoon keypair generation."""
        assert th_t <= self.max_t, f'input T > max_t'

        #   --- 0.  initialize
        key     = self.random_bytes(self.kg_sz)     # master random

        #   --- 1.  A <- Rq^{k * ell}
        A_seed  = self._xof(self._hdr8('A') + key, sz=self.as_sz)
        A_ntt   = self._expand_a(A_seed)

        #   --- 2.  (s, e) <- D_t^ell * D_t^k
        sigt2   = 1 << (2 * self.lg_st)     #   saigma_t^2 = (2**lg_st)**2
        s       = [ sample_rounded(sigt2, self._hdr8('s', i) + key)
                        for i in range(self.ell) ]
        #   xxx changed the dom sep
        e1      = [ sample_rounded(sigt2, self._hdr8('e', i, 1) + key)
                        for i in range(self.k) ]

        #   --- 3.  t := [ A*s + e ]_nu_t
        s_ntt   = vec_ntt(s)
        t_ntt   = mul_mat_vec_ntt(A_ntt, s_ntt)
        t       = vec_intt(t_ntt)
        t       = vec_add(t, e1)
        t       = vec_rshift(t, self.nu_t, self.q_t)

        #   --- 4.  vk := (A, t)
        vk      = (A_seed, t)

        #   --- 5.  P <- Rq^ell with deg(P) = T - 1, P(0) = s
        p   =   [ s ]
        for i in range(1, th_t):
            p   += [ [ self._xof_sample_q(self._hdr24('p', i, j) + key)
                        for j in range(self.ell) ] ]

        #   --- 6.  (s_i) for i in [N] := (P(i)) for i in [N]
        s   =   []
        for i in range(0, th_n):                    #   x = 1, 2,.. N
            si = p[th_t - 1]                        #   Horner's rule
            for j in range(th_t - 2, -1, -1):       #   T-2, .. 1, 0
                si = vec_scale(i + 1, si)           #   <- i+1
                si = vec_add(si, p[j])
            s += [ si ]

        #   --- 7.  for i in [N] do
        sig     = [ None ] * th_n
        seed    = [ [ None ] * th_n for _ in range(th_n) ]
        for i in range(th_n):
            #   --- 8.  (vk_{sig,i}, sk_{sig,i}) <- KeyGen_sig()
            #   --- 9.  for j in [N] do
            for j in range(th_n):
                #   --- 10. seed_{i,j} = {0,1}^kappa
                seed[i][j] = self._xof(self._hdr24('k', i, j) + key)

        #   --- 11. for i in [N] do
        sk  = []
        for i in range(th_n):
        #       --- 12. sk_i := ( s_i, (vk_sig,i) for i in [N], sk_{sig,i},
        #                           (seed_{i,j}, seed_{j,i}) for j in [N] )
            sk += [ (i, s[i],
                    [ (seed[i][j], seed[j][i]) for j in range(th_n) ]) ]

        #   --  13. return ( vk, (sk_i) for i in [N] )
        return vk, sk

    def sign_1(self, vk, sk, sid, act, mu):
        """Alg. 5:  ShareSign_1(state, sid, act, msg)."""
        #   --- 0.  (initialize)
        (j, s, seeds)   = sk
        view        = {}            #   empty dict
        view['j']   = j
        view['s']   = s             #   secret
        view['seeds'] = seeds       #   secret
        view['vk']  = vk            #   public

        assert len(sid) == self.sid_sz
        seh = self._hash_vec(sid + mu, act)     # session hash
        view['seh'] = seh
        act_t = len(act)                        # T value for this signature

        (A_seed, t) = vk
        A_ntt   = self._expand_a(A_seed)
        key = self.random_bytes(self.kg_sz)     # master random

        #   --- 1.  assert{ ConsistCheck1(state, sid, act, msg) }

        #   --- 2.  (r_j, e'_j) <- D_w^ell * D_w^k
        sigw2   = (1 << (2 * self.lg_swt)) / act_t  # sigma_w^2
        r       = [ sample_rounded(sigw2, self._hdr8('r', i) + key)
                        for i in range(self.ell) ]
        e2      = [ sample_rounded(sigw2, self._hdr8('e', i, 2) + key)
                        for i in range(self.k) ]

        #   --- 3.  w_j := A * r_j + e'_j
        r_ntt   = vec_ntt(r)
        w_ntt   = mul_mat_vec_ntt(A_ntt, r_ntt)
        w       = vec_intt(w_ntt)
        w       = vec_add(w, e2)

        #   --- 4.  cmt_j := Hcom(sid, act, msg, w_j)
        cmt     = self._hcom(seh, w)

        #   --- 5.  Fetch (seed_{j,i} )i  in act from state.sk
        #   --- 6.  m_j := SUM_{i in act} PRF(seed_{j,i}, sid)
        j       = view['j']
        seeds   = view['seeds']
        m       = None
        for i in act:
            (_, seed_ji) = seeds[i]
            x   = self._mask_prf( j, i, seed_ji, seh )
            if m == None:
                m = x
            else:
                m = vec_add(m, x)

        #   --- 7.  state.session[sid] :=
        #               { sid, act, msg, 1, {r_j, w_j, cmt_j, m_j}, 0 }
        view['act'] = act
        view['mu']  = mu
        view['r']   = r
        view['w']   = w
        view['cmt'] = cmt
        view['rnd'] = 1

        #   --- 8.  return contrib_1[j] := (cmt_j, m_j)
        ctrb_1 = (cmt, m)
        return  view, ctrb_1

    def sign_2(self, view, ctrb_1):
        "Alg. 6: ShareSign_2(state, sid, contrib_1)."""

        #   --- 1:  assert{ ConsistCheck_2 (state, sid, contrib_1 ) }
        assert view['rnd'] == 1
        view['rnd'] = 2

        #   --- 2:  Fetch sk_sig,j from state.sk
        #   --- 3:  sigma_j <- Sign_sig(sk_sig, sid || act || msg || contrib_1)

        seh     = view['seh']
        act     = view['act']
        j       = view['j']
        seeds   = view['seeds']
        sig     = []        #   list of MACs

        ctrb_1_h = self._hash_ctrb_1(seh, act, ctrb_1)
        for i in act:
            (seed_ij, _) = seeds[i]
            sig += [ self._sig_mac_ctrb_1(i, j, seed_ij, ctrb_1_h) ]

        #   --- 4:  Fetch w_j from stae.sessions[sid].internal
        w   = view['w']

        #   --- 5:  state.session[sid] := { sid, act, msg, 2,
        #                               {r_j, w_j, cmt_j, m_j }, contrib_1 }
        view['ctrb_1'] = ctrb_1

        #   --- 6: return contrib_2[j] := (w_j, sigma_j)
        ctrb_2_j = (w, sig)

        return ctrb_2_j

    def _aggregate_w(self, w_act):
        """Aggregated rounded commitment in R^k_qw."""
        w = w_act[0]
        for wi in w_act[1:]:
            w = vec_add(w, wi)
        w = [ poly_rshift(wi, self.nu_w, self.q_w) for wi in w ]
        return w

    def sign_3(self, view, ctrb_2):
        """Alg. 7: ShareSign_3(state, sid, contrib_2)."""

        #   --- 1.  assert{ ConsistCheck_3(state, sid, contrib_2 ) }
        assert view['rnd'] == 2

        #   --- 2.  Let session = state.sessions[sid]
        #   --- 3.  Fetch (sid, act, msg) from session
        seh     = view['seh']
        j       = view['j']
        act     = view['act']
        mu      = view['mu']

        #   --- 4.  Fetch r_j from session.internal and s_j,
        #               (vk_{sig,i}) for i in [N],
        #               (seed_{i,j}) for i in act from state.sk
        r       = view['r']
        s       = view['s']
        seeds   = view['seeds']

        #   --- 5.  Fetch contrib_1 = (cmt_i, m_i) for i in act
        #               from session.contrib_1
        #   --- 6.  Parse contrib_2 = (w_i, sigma_i) for i in act
        #   --- 7.  for i in act do
        #       --- 8.  assert { cmt_i = H_com(sid, msg, act, w_i ) }

        ctrb_1  =   view['ctrb_1']
        w_act = []
        sig_act = []
        for i in act:
            (cmt_i, _) = ctrb_1[i]
            (w_i, sig_i) = ctrb_2[i]
            w_act   +=  [ w_i ]
            sig_act +=  [ sig_i ]
            if cmt_i != self._hcom(seh, w_i):
                return None

        #       --- 9.  assert { Verify_sig(vk_{sig,i},
        #                       sid || act || msg || contrib_1, sig_i ) = 1 }

        ctrb_1_h = self._hash_ctrb_1(seh, act, ctrb_1)
        j_idx = act.index(j)
        for i in act:
            (_, seed_ji) = seeds[i]
            i_idx = act.index(i)
            mac = self._sig_mac_ctrb_1(j, i, seed_ji, ctrb_1_h)
            if mac != sig_act[i_idx][j_idx]:
                return None

        #   --- 10. w := [ SUM_{i in act} w_i ]_nu_w
        w       = self._aggregate_w(w_act)

        #   --- 11. c := H_c(state.vk, msg, w)
        c_hash  = self._hash_vec(mu, w)
        c       = self._chal_poly(c_hash)

        #   --- 12. m*_j := SUM_{i in act} PRF(seed_{i,j}, sid)
        m       = None
        for i in act:
            (seed_ij, _) = seeds[i]
            x   = self._mask_prf( i, j, seed_ij, seh)
            if m == None:
                m = x
            else:
                m = vec_add(m, x)

        #   --- 13. z_j := c * lambda_{act,j} * s_j + r_j  + m*_j
        lam_j   =   self._lagrange(act, j)
        c_ntt   =   ntt(poly_scale(lam_j, c))
        s_ntt   =   vec_ntt(s)
        z_ntt   =   vec_mul_ntt(c_ntt, s_ntt)
        z       =   vec_intt(z_ntt)
        z       =   vec_add(z, r)
        z       =   vec_add(z, m)

        #   --- 14. return  contrib_3[j] := z_j
        ctrb_3 = z

        view['rnd'] = 3

        return  ctrb_3

    def combine(self, vk, sid, mu, act, ctrb_1, ctrb_2, ctrb_3):
        """ Alg. 8: Combine(vk, sid, msg, contrib_1, contrib_2, contrib_3)."""

        #   --- 1.  Parse   contrib1 = (cmt_i, m_i) for i in act
        #                   contrib2 = (w_i, sig_i) for i in act
        #                   contrib3 = (z_i) for i in act
        m_act   = []
        w_act   = []
        z_act   = []
        for i in act:
            (cmt_i, m_i) = ctrb_1[i]
            m_act += [ m_i ]
            (w_i, sig_i) = ctrb_2[i]
            w_act += [ w_i ]
            z_i = ctrb_3[i]
            z_act += [ z_i ]

        #   --- 2.  Parse vk = (A, t)
        (A_seed, t) = vk
        A_ntt   = self._expand_a(A_seed)

        #   --- 3.  w := [ SUM_{i in act} w_i ]_nu_w
        w       = self._aggregate_w(w_act)

        #   --- 4.  z := SUM_{i in act} (z_i - m_i)
        z       = z_act[0]
        for zi in z_act[1:]:
            z = vec_add(z, zi)
        for mi in m_act:
            z = vec_sub(z, mi)

        z_ntt   = vec_ntt(z)

        #   --- 5.  c := H_c(state.vk, msg, w)
        c_hash  = self._hash_vec(mu, w)
        c_ntt   = ntt(self._chal_poly(c_hash))

        #   --- 6.  y := [A * z - 2^nu_t * c * t]_nu_w
        y_ntt   = mul_mat_vec_ntt(A_ntt, z_ntt)
        tmp     = vec_lshift(t, self.nu_t)
        tmp     = vec_ntt(tmp)
        tmp     = vec_mul_ntt(c_ntt, tmp)
        y_ntt   = vec_sub(y_ntt, tmp)
        y       = vec_intt(y_ntt)

        print("y", y[0][0:4])
        y       = vec_rshift(y, self.nu_w, self.q_w)

        #   --- 7.  h := w - y
        h       = vec_center(vec_sub(w, y, self.q_w), self.q_w)

        #   --- 8.  Return sigma := (c, z, h)
        if not self._check_bounds(z, h):    #   can fail
            return None
        return  (c_hash, z, h)

    def set_random(self, random_bytes):
        """Set the key material RBG."""
        self.random_bytes   =   random_bytes

    #   --- internal methods ---

    def _compute_b2_bound(self):
        """Derive rejection bounds from parameters."""
        kappa   = self.kappa
        omega   = self.omega
        nu_w    = self.nu_w
        nu_t    = self.nu_t
        k       = self.k
        ell     = self.ell
        n       = self.n
        sigma_t = 2**self.lg_st
        swt     = 2**self.lg_swt    # sigma_w * sqrt(T)

        #   --- From "Direct Forgery and SelfTargetMSIS."
        return  (   1.2840254166877414840734205680624364583 *   # =exp(0.25)
                    (omega * sigma_t + swt) * ((n * (k + ell))**0.5)
                    + (2**(nu_w+1) + omega * 2**nu_t) * ((n * k)**0.5))

    def _sum_squares(self, v, q=RACC_Q):
        """Compute sum of squares of signed values."""
        s = 0
        c = q // 2
        for vi in v:
            for x in vi:
                x %= q
                if x > c:
                    x -= q
                s += x * x
        return s

    def _check_bounds(self, z, h):
        """Check the two-norm bound. Return True if ok."""
        s2z = self._sum_squares(z)
        s2h = self._sum_squares(h)
        n2  = (s2z + (2**(2 * (self.nu_w)) * s2h))**0.5
        print(f'n2= {n2}  B2= {self.b2}  {n2/self.b2}')
        return n2 <= self.b2

    def _n_inv(self, a, n):
        """ Inverse: Given a and n, return a^-1 (mod n) -- if exists."""
        (r0, r1) = (a, n)
        (s0, s1) = (1, 0)
        while r1 != 0:
            q = r0 // r1
            (r0, r1) = (r1, r0 - q * r1)
            (s0, s1) = (s1, s0 - q * s1)
        return s0 % n

    def _lagrange(self, s, i):
        """ lambda_{S,i} := PROD_{j in S\{i}} -j / (i - j)."""
        a = 1
        b = 1
        for j in s:
            if j != i:
                a *= -(j + 1)       #   <- note
                b *= i - j
        return (a * self._n_inv(b, self.q)) % self.q

    def _xof(self, x, sz=None):
        """Generic XOF function."""
        if sz == None:
            sz = self.sec
        return SHAKE256.new(x).read(sz)

    def _sig_mac_ctrb_1(self, i, j, seed, ctrb_1_h):
        """Compute a symmetric MAC "signature" for Contrib_1."""
        return SHAKE256.new(self._hdr24('M', i, j) +
            seed + ctrb_1_h).read(self.mac_sz)

    def _mask_prf(self,  i, j, seed, sid):
        """Mask generation PRF."""
        assert len(seed) == self.sd_sz
        assert len(sid) == self.sid_sz
        x = []
        for k in range(self.ell):
            buf = self._hdr24('m', i, j, k) + seed + sid
            x += [ self._xof_sample_q( buf ) ]
        return x

    def _hdr8(self, ds, b1=0, b2=0, b3=0, b4=0, b5=0, b6=0, b7=0 ):
        """Create a domain separation prefix with byte fields."""
        return bytes([ord(ds), b1, b2, b3, b4, b5, b6, b7])

    def _hdr24(self, ds, i=0, j=0, k=0):
        """Create a dom prefix with two 24-bit indexes, one 8-bit."""
        return (bytes([ord(ds), k]) + int(i).to_bytes(3, BYTEORDER)
                                    + int(j).to_bytes(3, BYTEORDER) )

    def _xof_sample_q(self, seed, kappa=128):
        """Expand a seed to n uniform values [0,q-1] using a XOF."""
        blen = (self.q_bits + 7) // 8
        mask = (1 << self.q_bits) - 1
        if kappa <= 128:
            xof = SHAKE128.new(seed)
        else:
            xof = SHAKE256.new(seed)
        v = [0] * self.n
        i = 0
        while i < self.n:
            z = xof.read(blen)
            x = int.from_bytes(z, BYTEORDER) & mask
            if (x < self.q):
                v[i] = x
                i += 1
        return v

    def _expand_a(self, seed):
        """ExpandA(): Expand "seed" into a k*ell matrix A."""
        a = [[None for _ in range(self.ell)] for _ in range(self.k)]
        #   matrix rejection sampler
        for i in range(self.k):
            for j in range(self.ell):
                #   XOF( 'A' || row || col || seed )
                a[i][j] = self._xof_sample_q(self._hdr8('A', i, j) + seed)
        return a

    def _hash_vec(self, dat, vec, ds='H'):
        """hashes a label and a vector of 64-bit values."""
        #   flatten vector if needed
        if isinstance(vec[0], list):
            v = []
            for vi in vec:
                v.extend(vi)
        else:
            v = vec

        q_byt = (self.q_bits + 7) // 8
        #   header || dat || data
        xof = SHAKE256.new(self._hdr24(ds, len(dat), q_byt * len(v)) + dat)
        for x in v:
            xof.update(int(x % RACC_Q).to_bytes(q_byt, byteorder=BYTEORDER))
        return xof.read(self.crh)

    def _hcom(self, seh, w):
        """Hcom commitment function."""
        return self._hash_vec(seh, w)

    def _hash_ctrb_1(self, seh, act, ctrb_1):
        """Commitment signing hash."""
        assert len(seh) == self.seh_sz
        xof = SHAKE256.new()
        #   add domsep here?
        xof.update(seh)
        for i in act:
            (cmt_i, m_i) = ctrb_1[i]
            xof.update(self._hash_vec(cmt_i, m_i))
        return xof.read(self.crh)

    def _chal_poly(self, c_hash):
        """ChalPoly(c_hash): Derive the challenge polynomial from c_hash."""
        mask_n  = (self.n - 1)

        #   For each sample, we need logn bits for the position and
        #   1 bit for the sign
        blen = (mask_n.bit_length() + 1 + 7) // 8
        xof = SHAKE256.new(self._hdr8('c', self.omega) + c_hash)

        #   Create a "w"-weight ternary polynomial
        c_poly = [0] * self.n
        wt = 0
        while wt < self.omega:
            z = xof.read(blen)
            x = int.from_bytes(z, BYTEORDER)
            sign = x & 1
            idx = (x >> 1) & mask_n
            if (c_poly[idx] == 0):
                c_poly[idx] = (2 * sign - 1)
                wt += 1
        return c_poly

#   --- some testing code ----------------------------------------------

if (__name__ == "__main__"):

    #   one instance here for testing
    iut = TRaccoon()

