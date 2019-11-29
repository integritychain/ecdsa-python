#!/usr/bin/env python

import random  # Deterministic is fine
from ecdsa import Coordinate, CurveP256, ECDSA


print("1. Testing coordinate arithmetic (not pow, inv)")
for index in range(1000):
    a = random.getrandbits(256)
    b = random.getrandbits(256)
    c = random.getrandbits(256)
    d = random.getrandbits(256)
    e = random.getrandbits(256)
    f = random.getrandbits(256)
    mod = random.getrandbits(256)
    res1 = e*((f + Coordinate(a, mod) + Coordinate(b, mod)) - Coordinate(c, mod)) * Coordinate(d, mod)
    res2 = e*(((f + a + b) - c) * d) % mod
    assert res1.coord == res2
print("PASS\n")


print("2. Testing coordinate inverse function")
for index in range(1000):
    x1 = Coordinate(random.getrandbits(256), CurveP256.PRIME)
    x2 = Coordinate.inv(x1, CurveP256.PRIME)
    assert (x1 * x2).coord == 1
print("PASS\n")


print("3. Testing curve point doubling")
g = CurveP256.GENERATOR
p2 = CurveP256.double(g)
assert p2.x.coord == 56515219790691171413109057904011688695424810155802929973526481321309856242040
assert p2.y.coord == 3377031843712258259223711451491452598088675519751548567112458094635497583569
print("PASS\n")


print("4. Testing curve point addition")
p3 = CurveP256.add(p2, g)
assert p3.x.coord == 42877656971275811310262564894490210024759287182177196162425349131675946712428
assert p3.y.coord == 61154801112014214504178281461992570017247172004704277041681093927569603776562
print("PASS\n")


print("5. Testing point multiplication")
ecdsa = ECDSA(CurveP256)
x = ecdsa._multiply_k_p(5, g)
print("   g times 5: {}".format(x))
assert x.x.coord == 36794669340896883012101473439538929759152396476648692591795318194054580155373
assert x.y.coord == 101659946828913883886577915207667153874746613498030835602133042203824767462820
print("PASS\n")


print("6. 10x CAVP KeyPair.rsp vectors, point multiplication")
z = ecdsa._multiply_k_p(0xc9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357, g)
assert z.x.coord == 0xd0720dc691aa80096ba32fed1cb97c2b620690d06de0317b8618d5ce65eb728f
assert z.y.coord == 0x9681b517b1cda17d0d83d335d9c4a8a9a9b0b1b3c7106d8f3c72bc5093dc275f
z = ecdsa._multiply_k_p(0x710735c8388f48c684a97bd66751cc5f5a122d6b9a96a2dbe73662f78217446d, g)
assert z.x.coord == 0xf6836a8add91cb182d8d258dda6680690eb724a66dc3bb60d2322565c39e4ab9
assert z.y.coord == 0x1f837aa32864870cb8e8d0ac2ff31f824e7beddc4bb7ad72c173ad974b289dc2
z = ecdsa._multiply_k_p(0x78d5d8b7b3e2c16b3e37e7e63becd8ceff61e2ce618757f514620ada8a11f6e4, g)
assert z.x.coord == 0x76711126cbb2af4f6a5fe5665dad4c88d27b6cb018879e03e54f779f203a854e
assert z.y.coord == 0xa26df39960ab5248fd3620fd018398e788bd89a3cea509b352452b69811e6856
z = ecdsa._multiply_k_p(0x2a61a0703860585fe17420c244e1de5a6ac8c25146b208ef88ad51ae34c8cb8c, g)
assert z.x.coord == 0xe1aa7196ceeac088aaddeeba037abb18f67e1b55c0a5c4e71ec70ad666fcddc8
assert z.y.coord == 0xd7d35bdce6dedc5de98a7ecb27a9cd066a08f586a733b59f5a2cdb54f971d5c8
z = ecdsa._multiply_k_p(0x01b965b45ff386f28c121c077f1d7b2710acc6b0cb58d8662d549391dcf5a883, g)
assert z.x.coord == 0x1f038c5422e88eec9e88b815e8f6b3e50852333fc423134348fc7d79ef8e8a10
assert z.y.coord == 0x43a047cb20e94b4ffb361ef68952b004c0700b2962e0c0635a70269bc789b849
z = ecdsa._multiply_k_p(0xfac92c13d374c53a085376fe4101618e1e181b5a63816a84a0648f3bdc24e519, g)
assert z.x.coord == 0x7258f2ab96fc84ef6ccb33e308cd392d8b568ea635730ceb4ebd72fa870583b9
assert z.y.coord == 0x489807ca55bdc29ca5c8fe69b94f227b0345cccdbe89975e75d385cc2f6bb1e2
z = ecdsa._multiply_k_p(0xf257a192dde44227b3568008ff73bcf599a5c45b32ab523b5b21ca582fef5a0a, g)
assert z.x.coord == 0xd2e01411817b5512b79bbbe14d606040a4c90deb09e827d25b9f2fc068997872
assert z.y.coord == 0x503f138f8bab1df2c4507ff663a1fdf7f710e7adb8e7841eaa902703e314e793
z = ecdsa._multiply_k_p(0xadd67e57c42a3d28708f0235eb86885a4ea68e0d8cfd76eb46134c596522abfd, g)
assert z.x.coord == 0x55bed2d9c029b7f230bde934c7124ed52b1330856f13cbac65a746f9175f85d7
assert z.y.coord == 0x32805e311d583b4e007c40668185e85323948e21912b6b0d2cda8557389ae7b0
z = ecdsa._multiply_k_p(0x4494860fd2c805c5c0d277e58f802cff6d731f76314eb1554142a637a9bc5538, g)
assert z.x.coord == 0x5190277a0c14d8a3d289292f8a544ce6ea9183200e51aec08440e0c1a463a4e4
assert z.y.coord == 0xecd98514821bd5aaf3419ab79b71780569470e4fed3da3c1353b28fe137f36eb
z = ecdsa._multiply_k_p(0xd40b07b1ea7b86d4709ef9dc634c61229feb71abd63dc7fc85ef46711a87b210, g)
assert z.x.coord == 0xfbcea7c2827e0e8085d7707b23a3728823ea6f4878b24747fb4fd2842d406c73
assert z.y.coord == 0x2393c85f1f710c5afc115a39ba7e18abe03f19c9d4bb3d47d19468b818efa535
print("PASS\n")


print("7. Generate key pair, sign and verify")
keyPair = ecdsa.generate_keypair()
r, s = ecdsa.sign(b'sample', keyPair)
good_sig = ecdsa.verify(b'sample', keyPair.public, r, s)
assert good_sig == True
print("PASS\n")
