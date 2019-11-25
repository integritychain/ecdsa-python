#!/usr/bin/env python

import random  # Deterministic is fine
from ecdsa import CurveP256, ECDSA
from tqdm import tqdm

ecdsa = ECDSA(CurveP256)

for index in tqdm(range(100)):
    rndLength = random.getrandbits(10)
    message = bytearray(random.getrandbits(8) for _ in range(rndLength))
    keyPair = ecdsa.generate_keypair()
    r, s = ecdsa.sign(message, keyPair.private)
    ecdsa.verify(message, keyPair.public, r, s)
