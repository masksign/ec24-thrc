#   thrc-py

Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

Python implementation of Masked Raccoon, aimed at readability.

Test: `python3 test_thrc.py <kappa> <|act|> <T> <N>`.

Here `kappa` is the security level { 128, 192, 256}, `|act|` is the number of active signers, `T` is the threshold, and `N` is the total number of signers.

For signatures to succeed one needs to have `|act| >= T` (this is threshold cryptography) and also `|ACT| <= N` because you you have that many key shares.

A succesful run with the "default" parameter set prints equivalent:
```
$ python3 test_thrc.py 128 3 3 4
kappa= 128  act=[0, 1, 2]  T= 3  N= 4
--- Key Generation: ---
(..)
=== Verify ===
n2= 299040673415206.56  B2= 626733896241521.1  0.477141375643686
True
|ctrb| = 12576 + 15728 + 12544 = 40848
```

