#!/usr/bin/env python

# See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

import secrets

# TODO:
#  2. Put into github once it works
#  3. Implement ECDSA!


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
    @classmethod
    def get_k_kp(cls):
        c = secrets.randbits(256+64)
        k = Coordinate(c % (CurveP256.ORDER - 1) + 1)
        kp = cls.inv(k)
        t = (k * kp).coord
        assert (k * kp).coord == 1
        return k, kp


class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __repr__(self): return "x={:d} y={:d}".format(self.x.coord, self.y.coord)


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


#  1. B.4.1 Key Pair Generation Using Extra Random Bits
class KeyPair:
    def __init__(self):
        c = secrets.randbits(256+64)
        self.private = (c % (CurveP256.ORDER - 1)) + 1
        self.public = CurveP256.multiply_k_p(self.private, CurveP256.GENERATOR)




