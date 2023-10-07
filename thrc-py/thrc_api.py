"""
thrc_api.py
Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

=== Masked Raccoon signature scheme: Serialization, parameters, BUFF interface.
"""

from Crypto.Hash import SHAKE256
from nist_kat_drbg import NIST_KAT_DRBG
from thrc_core import ThRc_Core
from polyr import *

#   Encoding and decoding methods for NIST Test Vectors

class TRaccoon(ThRc_Core):

    def __init__(self, *args, **kwargs):
        """This is a subclass that provides serialization."""
        super().__init__(*args, **kwargs)

        #   nist serialization sizes
        self.vk_sz  =   (self.as_sz +
                            self.k * self.n * (self.q_bits - self.nu_t) // 8)

        #   serialization parameters
        self.ser_hlbits = 1
        self.ser_zlbits = 41

    def ctrb_sz(self,act_sz):
        ctrb_1_sz = (self.crh + self.ell * self.n * self.q_bits // 8)
        ctrb_2_sz = (act_sz * self.sec + self.k * self.n * self.q_bits // 8)
        ctrb_3_sz = (self.ell * self.n * self.q_bits // 8)
        ctrb_sz =   ctrb_1_sz + ctrb_2_sz + ctrb_3_sz
        print(f'|ctrb| = {ctrb_1_sz} + {ctrb_2_sz} + {ctrb_3_sz} = {ctrb_sz}')

    @staticmethod
    def _encode_bits(v, bits):
        """Encode vector v of integers into bytes, 'bits' per element."""
        x = 0                           # bit buffer
        l = 0                           # number of bits in x
        i = 0                           # index in vector v[i]
        b = b''                         # zero-length array of bytes
        m = (1 << bits) - 1             # bit mask

        while i < len(v):
            while l < 8 and i < len(v):
                x |= (v[i] & m) << l    # load an integer into x
                i += 1
                l += bits
            while l >= 8:
                b += bytes([x & 0xFF])  # store a bytes from x
                x >>= 8
                l -= 8
        if l > 0:
            b += bytes([x])             # a byte with leftover bits

        return b

    @staticmethod
    def _decode_bits(b, bits, n, is_signed=False):
        """
        Decode bytes from 'b' into a vector of 'n' integers, 'bits' each.
        """
        x = 0                           # bit buffer
        i = 0                           # source byte index b[i]
        v = []                          # zero-length result vector
        l = 0                           # number of bits in x

        if is_signed:
            s = 1 << (bits - 1)         # sign bit is negative
            m = s - 1                   # mask bits-1 bits
        else:
            s = 0                       # unsigned: no sign bit
            m = (1 << bits) - 1         # mask given number of bits

        while len(v) < n:
            while l < bits:             # read bytes until full integer
                x |= int(b[i]) << l
                i += 1
                l += 8
            while l >= bits and len(v) < n: # write integer(s)
                v += [ (x & m) - (x & s) ]
                x >>= bits
                l -= bits

        return v, i     #   return the vector and number of bytes read

    def encode_vk(self, vk):
        """Serialize the signature verification (public) key."""
        (seed, t) = vk
        b = seed
        for ti in t:
            b += self._encode_bits(ti, self.q_bits - self.nu_t)
        return b

    def decode_vk(self, b):
        """Decode the verification key from bytes."""
        seed = b[0:self.as_sz]
        l = len(seed)
        t = []
        for i in range(self.k):
            p,pl = self._decode_bits(b[l:], self.q_bits - self.nu_t, self.n);
            t += [p]
            l += pl
        vk = (seed, t)

        return vk, l

    def _bits_enc_sig(self, v, lbits):
        """Signature component encoding into bits"""
        b = []
        for x in v:
            x %= self.q
            if x == 0:                  #   no sign bit for x == 0
                sgn = None
            elif x > self.q // 2:       #   negative half
                sgn = 1                 #   set sign
                x = self.q - x          #   absolute value
            else:                       #   positive half
                sgn = 0
            for _ in range(lbits):  #   low bits verbatim
                b += [ x & 1 ]
                x >>= 1
            b += [ 1 ] * x              #   high bits as a run
            b += [ 0 ]                  #   stop bit
            if sgn != None:             #   sign bit
                b += [ sgn ]
        return b

    def _bits_dec_sig(self, b, lbits):
        """Signature z component decoding into integers"""
        v = []
        i = 0
        for _ in range(self.n):
            x = 0
            for j in range(lbits):      #   get low bits
                x += b[i + j] << j
            i += lbits
            hi = 0
            while b[i] == 1:            #   decode hi bit run
                hi += 1
                i += 1
            i += 1                      #   stop bit (0)
            x += hi << lbits
            if x != 0:                  #   use sign if x != 0
                if b[i] == 1:           #   negative
                    x = -x
                i += 1
            v += [ x % self.q ]
        return v,  i                    #   also return read length i

    def encode_sig(self, sig):
        """Serialize a signature as bytes. No zero padding / length check."""
        (c_hash, z, h) = sig
        s = c_hash                      #   challenge hash
        b = []                          #   bit string
        for hi in h:                    #   h bit strings
            b += self._bits_enc_sig(hi, lbits=self.ser_hlbits)
        for zi in z:                    #   z bit strings
            b += self._bits_enc_sig(zi, lbits=self.ser_zlbits)
        i = 0                           #   convert to bytes
        x = 0
        for bit in b:
            x += bit << i
            i += 1
            if i == 8:
                s += bytes([x])
                i = 0
                x = 0
        if i > 0:
            s += bytes([x])
        return s

    def decode_sig(self, s):
        """Deserialize a signature."""
        c_hash = s[0:self.ch_sz]        #   challenge hash
        b = []                          #   convert rest to a bit string
        for x in s[self.ch_sz:]:
            b += [ (x >> i) & 1 for i in range(8) ]
        h = [ None for _ in range(self.k) ]
        i = 0
        for j in range(self.k):
            h[j], l = self._bits_dec_sig(b[i:], lbits=self.ser_hlbits)
            i   +=  l
        z = [ None for _ in range(self.ell) ]
        for j in range(self.ell):
            z[j], l = self._bits_dec_sig(b[i:], lbits=self.ser_zlbits)
            i   +=  l
        sig = (c_hash, z, h)
        return sig

    def _buff_mu(self, tr, msg):
        """BUFF helper: mu = H( tr | msg ), where tr = H(vk)."""
        xof = SHAKE256.new(tr)
        xof.update(msg)
        return xof.read(self.mu_sz)

    #   interface that directly uses byte sequences

    def byte_keygen(self):
        """(API) Key pair generation directly into bytes."""
        msk, vk = self.keygen()
        return self.encode_vk(vk), self.encode_sk(msk)

    def byte_signature(self, msg, sk):
        """Detached signature generation directly from/to bytes."""
        msk, tr, _ = self.decode_sk(sk)
        mu = self._buff_mu(tr, msg)
        sig_b = []
        while len(sig_b) != self.sig_sz:
            sig = self.sign_mu(msk, mu)
            sig_b = self.encode_sig(sig)
            if len(sig_b) < self.sig_sz:
                sig_b += bytes([0] * (self.sig_sz - len(sig_b)))
        return sig_b

    def byte_verify(self, msg, sm, vk):
        """Detached Signature verification directly from bytes."""
        if len(sm) < self.sig_sz:
            return False
        vk, tr, _ = self.decode_vk(vk)
        sig = self.decode_sig(sm[0:self.sig_sz])
        mu = self._buff_mu(tr, msg)
        return self.verify_mu(vk, mu, sig)

    def byte_sign(self, msg, sk):
        """(API) Signature "envelope" generation directly from/to bytes."""
        sig = self.byte_signature(msg, sk)
        return sig + msg

    def byte_open(self, sm, vk):
        """(API) Signature verification directly from bytes."""
        msg = sm[self.sig_sz:]
        return self.byte_verify(msg, sm, vk), msg


