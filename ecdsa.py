#!/usr/bin/env python

# See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

import hashlib, secrets
from collections import namedtuple


class Coordinate:
    P256 = 115792089210356248762697446949407573530086143415290314195533631308867097853951

    def __init__(self, coord): self.coord = coord % self.P256
    # def __repr__(self): return self.coord.to_bytes(32, 'little').hex()
    def __add__(self, right): return Coordinate(self.coord + right.coord)
    def __radd__(self, left): return Coordinate(self.coord + left)
    def __sub__(self, right): return Coordinate(self.coord + self.P256 - right.coord)
    def __mul__(self, right): return Coordinate(self.coord * right.coord)
    def __rmul__(self, left): return Coordinate(self.coord * left)
    def __pow__(self, right): return Coordinate(pow(self.coord, right, self.P256))
    def __truediv__(self, right): return self * Coordinate.inv(right)

    @classmethod
    def inv(cls, x):
        result = Coordinate(1)
        for bit in bin(Coordinate.P256 - 2)[::-1]:
            if bit == '1':
                result = result * x
            x = x * x
        return result

    #  2. B.5.1 Per-Message Secret Number Generation Using Extra Random Bits


Point = namedtuple('Point', 'x y')


class CurveP256:
    GENERATOR = Point(Coordinate(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296),
                      Coordinate(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5))
    ORDER = 115792089210356248762697446949407573529996955224135760342422259061068512044369
    A = Coordinate.P256 - 3

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

    @classmethod
    def multiply_k_p(cls, k, p):
        accumulator = None
        for bit in bin(k)[::-1]:
            if bit == '1':
                if accumulator is None: accumulator = p
                else: accumulator = CurveP256.add(accumulator, p)
            p = CurveP256.double(p)
        return accumulator

    @classmethod
    def invvv(cls, x):
        result = 1
        for bit in bin(CurveP256.ORDER - 2)[::-1]:
            if bit == '1':
                result = (result * x) % CurveP256.ORDER
            x = (x * x) % CurveP256.ORDER
        return result

    @classmethod
    def get_k_kp(cls):
        c = secrets.randbits(256+64)
        k = c % (cls.ORDER - 1) + 1
        kp = cls.invvv(k)
        assert k * kp % cls.ORDER == 1
        return k, kp


KeyPair = namedtuple('KeyPair', 'public private')


class ECDSA:

    def __init__(self, curve):
        self.curve = curve  # To provide constants

    #  1. B.4.1 Key Pair Generation Using Extra Random Bits
    def generate_keypair(self):
        c = secrets.randbits(256+64)
        private = (c % (self.curve.ORDER - 1)) + 1
        public = CurveP256.multiply_k_p(private, self.curve.GENERATOR)
        keypair = KeyPair(public=public, private=private)
        return keypair

    def sign(self, message, privateKey, k=None):
        z = hashlib.sha256(message).digest()
        zint = int.from_bytes(z, byteorder='big') % self.curve.ORDER
        if k is None: k, kp = self.curve.get_k_kp()
        else: kp = self.curve.invvv(k)
        r = self.curve.multiply_k_p(k, self.curve.GENERATOR).x.coord % self.curve.ORDER
        s = (kp * (zint + (privateKey * r) % self.curve.ORDER) % self.curve.ORDER)
        return r, s

    def verify(self, message, publicKey, r, s):
        z = hashlib.sha256(message).digest()
        zint = int.from_bytes(z, byteorder='big') % self.curve.ORDER
        w = self.curve.invvv(s)
        u1 = (zint * w) % CurveP256.ORDER
        u2 = (r * w) % CurveP256.ORDER
        vA = CurveP256.multiply_k_p(u1, CurveP256.GENERATOR)
        vB = CurveP256.multiply_k_p(u2, publicKey)
        # v = ((vA + vB).x.coord % Coordinate.P256) % CurveP256.ORDER  ############# put curve add here!!!!!!!!!!!!!
        v = CurveP256.add(vA, vB).x.coord % CurveP256.ORDER
        print("V {}\nr {}".format(v, r))
