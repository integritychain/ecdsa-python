#!/usr/bin/env python

import random, hashlib
from Crypto.Hash import SHA256  # pycryptodome
from ecdsa import Coordinate, CurveP256, ECDSA, KeyPair, Point

print("1. Testing coordinate inverse function")
for index in range(100):
    x1 = Coordinate(random.getrandbits(256), CurveP256.PRIME)
    x2 = Coordinate.inv(x1, CurveP256.PRIME)
    assert (x1 * x2).coord == 1

print("2. Testing point doubling")
g = CurveP256.GENERATOR  # Point(CurveP256.GX256, CurveP256.GY256)
p2 = CurveP256.double(g)
assert p2.x.coord == 56515219790691171413109057904011688695424810155802929973526481321309856242040
assert p2.y.coord == 3377031843712258259223711451491452598088675519751548567112458094635497583569
print("   g doubled: {}".format(p2))

print("3. Testing point addition")
p3 = CurveP256.add(p2, g)
assert p3.x.coord == 42877656971275811310262564894490210024759287182177196162425349131675946712428
assert p3.y.coord == 61154801112014214504178281461992570017247172004704277041681093927569603776562
print("   g tripled: {}".format(p3))

print("4. Testing point multiplication")
ecdsa = ECDSA(CurveP256)
x = ecdsa._multiply_k_p(5, g)
print("   g times 5: {}".format(x))
assert x.x.coord == 36794669340896883012101473439538929759152396476648692591795318194054580155373
assert x.y.coord == 101659946828913883886577915207667153874746613498030835602133042203824767462820

print("5. 10x CAVP vectors")
# See https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3ecdsatestvectors.zip KeyPair.rsp
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

print("6. Generate key pair")
keyPair = ecdsa.generate_keypair()
print(keyPair)

print("7. Generate k, kp")
k, kp = ecdsa._get_k_kp()
print(k, kp)

 
print("8. Sign...")
k = Coordinate(0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60, CurveP256.ORDER)
r = ecdsa._multiply_k_p(k.coord, CurveP256.GENERATOR).x.coord % CurveP256.ORDER
print("My r: ", r)
print("Exp   ", 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716)
assert r == 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716

# def invvv(x):
#     result = 1
#     for bit in bin(CurveP256.ORDER - 2)[::-1]:
#         if bit == '1':
#             result = (result * x) % CurveP256.ORDER
#         x = (x * x) % CurveP256.ORDER
#     return result


message = "sample".encode("ascii")
h = hashlib.sha256(b"sample").digest()
hh = int.from_bytes(h, byteorder='big') % CurveP256.ORDER
keyPair = KeyPair(private=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721, public=None)
#kp = invvv(k.coord)
kp = Coordinate.inv(k, CurveP256.ORDER).coord
s = (kp * (hh + (keyPair.private * r) % CurveP256.ORDER) % CurveP256.ORDER)
print("S is:", hex(s))
print("S Targ  F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
assert s == 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8


print("9. Verify")
keyPair = KeyPair(public=Point(Coordinate(0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6, CurveP256.PRIME),
                               Coordinate(0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299, CurveP256.PRIME)),
                  private=None)

#w = invvv(s)
w = Coordinate.inv(Coordinate(s, CurveP256.ORDER), CurveP256.ORDER).coord

u1 = (hh * w) % CurveP256.ORDER
u2 = (r*w) % CurveP256.ORDER
vA = ecdsa._multiply_k_p(u1, CurveP256.GENERATOR)
vB = ecdsa._multiply_k_p(u2, keyPair.public)
v = CurveP256.add(vA, vB).x.coord % CurveP256.ORDER
print("v is: ", v)
assert v == r

print("\n\n10. My sign")
ecdsa = ECDSA(CurveP256)
keyPair = KeyPair(public=Point(Coordinate(0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6, CurveP256.PRIME),
                               Coordinate(0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299, CurveP256.PRIME)),
                  private=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721)
k = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
r, s = ecdsa.sign(b'sample', keyPair.private, k)
print(r, hex(s))

ecdsa.verify(b'sample', keyPair.public, r, s)
