# See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

import hashlib, secrets
from collections import namedtuple

# TODO
#  1. Remove Assertions
#  2. Add a ton of input validations, point at infinity, CurveP256 formal name
#  3. Comment like crazy, add NIST/RFC references
#  4. Disclaimer about clarity and brevity, sacrificing performance and side-channel resistance (e.g. not constant time)
#  5. Rewrite test1.py to more carefully test each (happy/unhappy) function


class Coordinate:
    def __init__(self, coord, modulus): self.modulus = modulus; self.coord = coord % self.modulus
    def __add__(self, right): return Coordinate(self.coord + right.coord, self.modulus)
    def __radd__(self, left): return Coordinate(self.coord + left, self.modulus)
    def __sub__(self, right): return Coordinate(self.coord + self.modulus - right.coord, self.modulus)
    def __mul__(self, right): return Coordinate(self.coord * right.coord, self.modulus)
    def __rmul__(self, left): return Coordinate(self.coord * left, self.modulus)
    def __pow__(self, right): return Coordinate(pow(self.coord, right, self.modulus), self.modulus)
    def __truediv__(self, right): return self * Coordinate.inv(right, self.modulus)

    @classmethod
    def inv(cls, x, modulus):
        result = Coordinate(1, modulus)
        for bit in bin(modulus-2)[::-1]:
            if bit == '1':
                result = result * x
            x = x * x
        return result


Point = namedtuple('Point', 'x y')


class CurveP256:
    PRIME = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    ORDER = 115792089210356248762697446949407573529996955224135760342422259061068512044369
    GENERATOR = Point(Coordinate(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, PRIME),
                      Coordinate(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5, PRIME))
    A = PRIME - 3

    @classmethod
    def add(cls, p1, p2):
        # x3 = (y2 - y1)^2 / (x2 - x1)^2 - x1 - x2
        x3 = (p2.y - p1.y) ** 2 / (p2.x - p1.x) ** 2 - p1.x - p2.x
        # y3 = (2 * x1 + x2) * (y2 - y1) / (x2 - x1) - (y2 - y1)^3 / (x2 - x1)^3 - y1
        y3 = (2 * p1.x + p2.x) * (p2.y - p1.y) / (p2.x - p1.x) - (p2.y - p1.y) ** 3 / (p2.x - p1.x) ** 3 - p1.y
        return Point(x3, y3)

    @classmethod
    def double(cls, p):
        # x3 = (3 * x1^2 + a)^2 / (2 * y1)^2 - x1 - x1
        x3 = (cls.A + 3 * p.x**2)**2 / (2 * p.y)**2 - p.x - p.x
        # y3 = (2 * x1 + x1) * (3 * x1^2 + a) / (2 * y1) - (3 * x1^2 + a)^3 / (2 * y1)^3 - y1
        y3 = (2 * p.x + p.x) * (cls.A + 3 * p.x**2) / (2 * p.y) - (cls.A + 3 * p.x**2)**3 / (2 * p.y)**3 - p.y
        return Point(x3, y3)


KeyPair = namedtuple('KeyPair', 'public private')


class ECDSA:

    def __init__(self, curve):
        self.curve = curve

    def generate_keypair(self):
        c = secrets.randbits(256+64)
        private = (c % (self.curve.ORDER - 1)) + 1
        public = self.multiply_k_p(private, self.curve.GENERATOR)
        return KeyPair(public=public, private=private)

    def get_k_kp(self):
        c = secrets.randbits(256+64)
        k = c % (self.curve.ORDER - 1) + 1
        kp = Coordinate.inv(Coordinate(k, self.curve.ORDER), self.curve.ORDER)
        if k * kp.coord % self.curve.ORDER != 1: raise RuntimeError("k * kp != 1")
        return k, kp.coord

    def multiply_k_p(self, k, p):
        accumulator = None
        for bit in bin(k)[::-1]:
            if bit == '1':
                if accumulator is None: accumulator = p
                else: accumulator = self.curve.add(accumulator, p)
            p = self.curve.double(p)
        return accumulator

    def sign(self, message, private_key, k=None):
        z = hashlib.sha256(message).digest()
        z_int = int.from_bytes(z, byteorder='big') % self.curve.ORDER
        if k is None: k, kp = self.get_k_kp()
        else: kp = Coordinate.inv(Coordinate(k, self.curve.ORDER), self.curve.ORDER).coord
        r = self.multiply_k_p(k, self.curve.GENERATOR).x.coord % self.curve.ORDER
        s = (kp * (z_int + (private_key * r) % self.curve.ORDER) % self.curve.ORDER)
        return r, s

    def verify(self, message, public_key, r, s):
        z = hashlib.sha256(message).digest()
        z_int = int.from_bytes(z, byteorder='big') % self.curve.ORDER
        w = Coordinate.inv(Coordinate(s, self.curve.ORDER), self.curve.ORDER).coord
        u1 = (z_int * w) % self.curve.ORDER
        u2 = (r * w) % self.curve.ORDER
        v1 = self.multiply_k_p(u1, self.curve.GENERATOR)
        v2 = self.multiply_k_p(u2, public_key)
        v = self.curve.add(v1, v2).x.coord % self.curve.ORDER
        if r != v: raise RuntimeError("Signature validation failed r={} s={} v={}".format(r, s, v))
        return True
