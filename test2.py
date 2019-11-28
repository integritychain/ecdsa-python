#!/usr/bin/env python

import random  # Deterministic is fine
from ecdsa import CurveP256, CurveP384, CurveP521, ECDSA, Point, Coordinate
from tqdm import tqdm

ecdsa = ECDSA(CurveP256)

# Msg = 5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8
# d = 519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464
# Qx = 1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83
# Qy = ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9
# k = 94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de
# R = f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac
# S = 8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903

message = bytes.fromhex('e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3')
publicKey = Point(Coordinate(0xe424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c, CurveP256.PRIME),
                  Coordinate(0x970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927, CurveP256.PRIME))
r = 0xbf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f
s = 0x17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c

print(ecdsa.verify(message, publicKey, r, s))

for index in tqdm(range(100)):
    rndLength = random.getrandbits(10)
    message = bytearray(random.getrandbits(8) for _ in range(rndLength))
    keyPair = ecdsa.generate_keypair()
    r, s = ecdsa.sign(message, keyPair.private)
    ecdsa.verify(message, keyPair.public, r, s)
