#   anon_thrc

Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

Optimized C Implementation of Threshold Raccoon scheme. Instructions for performance evaluation. See the `thrc-py` subdirectory for the Python implementation.

Note that this code is not fully constant time, and many consistency checks are omitted.

To build on an typical AVX2-equipped Linux system (e.g. a Ubuntu 22.04 PC), run `make`:
```
$ make
cc -Wall -Wextra -Ofast -DRACC_AVX2 -march=native -Iinc -c ntt64.c -o ntt64.o
```
This builds an executable named `xtest` that accepts three parameters:
```
Usage: ./xtest |act| T N
```
Here `|act|` is the number of active signers, `T` is the threshold, and `N` is the total number of signers. For signatures to succeed one needs to have `|act| >= T` (this is threshold cryptography) and also `|ACT| <= N` because you you have that many key shares.

An example run with 64 signers, threshold of 64, and 64 keys is:
```
$ ./xtest 64 64 64
seed = 6fc380e9fc82ea968ca17168cd026dcf29c3d2b682d315fc3dc311ce677f4df886fb084befc13264b6b6a099aa07e0a5

[SIZ]   T    =       64
[SIZ]   N    =       64
--- Key Generation: ---
[CLK]   thrc_keygen(64)    0.448 ms    0.947 Mcyc
vk: t[5][512] = 260798603667759
vk: A_seed = 7ae2b952406bf45be274f8536c2eb899
SER vk = 3856
DES vk = 3856
SER sk = 934656
DES sk = 934656
--- Round 1: ---
[CLK]   thrc_sign_1(64)    5.048 ms   10.662 Mcyc
SER ctrb_1 = 804864
DES ctrb_1 = 804864
--- Round 2: ---
[CLK]   thrc_sign_2(64)    1.732 ms    3.657 Mcyc
SER ctrb_2 = 1069056
DES ctrb_2 = 1069056
--- Round 3: ---
[CLK]   thrc_sign_3(64)    4.418 ms    9.330 Mcyc
SER ctrb_3 = 802816
DES ctrb_3 = 802816
--- Combine: ---
[CLK]   thrc_combine(1)    0.367 ms    0.775 Mcyc
sig c: = 377ee36e2f061b6118c47f5bf19950d52c3e3119cb2806fdf1a7a363e2b3101a
sig z:[4][512] = 174531694365962
sig h:[5][512] = 481061407865154
SER sig = 12704
thrc_decode_sig: 0 (12704)
--- Verify: ---
FAIL: thrc_verify()
[CLK]   thrc_verify(1)     0.223 ms    0.471 Mcyc
[SIZ]   |vk|     =     3856
[SIZ]   |sk|     =   934656
[SIZ]   |sk|/N   =    14604
[SIZ]   |sig|    =    12704
[SIZ]   |ctrb|   =   804864 +  1069056 +   802816   =   2676736
[SIZ]   |ctrb|/T =    12576 +    16704 +    12544   =     41824
```
This indicates success. Note that each run is randomized with the default flags.

## Note on benchmarking used in the paper

See `thrc_bench.sh`. The data is available in `dat`.

We used the same methodology as SUPERCOP in relation to turbo boost. To disable frequency scaling until the next boot. Intel: `echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo`.  "u2" data is with turbo boost disabled.


