# Supports ECDSA generate keys, sign and verify for P-256/SHA256, P-384/SHA384 and P-521/SHA512
# This reference code prioritizes simplicity and brevity over performance and side-channel resistance.
# It is strictly for educational purposes and should not be used in production.

# See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

import hashlib, secrets
from collections import namedtuple

# TODO
#  1. Additional input validations, calculation checks, point at infinity, etc
#  2. Comments with NIST/RFC references
#  3. Safecurve checks, testing


# Coordinate suitable for an arbitrary modulus
class Coordinate:

    # Each operation returns new coordinate inheriting source modulus
    def __init__(self, coord, modulus): self.modulus = modulus; self.coord = coord % self.modulus       # Constructor
    def __add__(self, right): return Coordinate(self.coord + right.coord, self.modulus)                 # coord + coord
    def __radd__(self, left): return Coordinate(self.coord + left, self.modulus)                        # int + coord
    def __sub__(self, right): return Coordinate(self.coord + self.modulus - right.coord, self.modulus)  # coord - coord
    def __mul__(self, right): return Coordinate(self.coord * right.coord, self.modulus)                 # coord * coord
    def __rmul__(self, left): return Coordinate(self.coord * left, self.modulus)                        # int * coord
    def __pow__(self, right): return Coordinate(pow(self.coord, right, self.modulus), self.modulus)     # coord ** int
    def __truediv__(self, right): return self * Coordinate.inv(right, self.modulus)                     # coord * inv(coord)

    # Modular inverse is coord ** (modulus - 2) calculated by square and multiply
    @classmethod
    def inv(cls, x, modulus):
        xp = x
        result = Coordinate(1, modulus)
        for bit in bin(modulus-2)[::-1]:  # Iterate through the exponent bits from LSB to MSB
            if bit == '1':
                result = result * xp
            xp = xp * xp
        if (x * result).coord != 1: raise RuntimeError("x * xp != 1")  # Confirm inversion
        return result


# Conveniently pull two coordinates into a point
Point = namedtuple('Point', 'x y')


# See section D.1.2.3 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
class CurveP256:
    PRIME = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    ORDER = 115792089210356248762697446949407573529996955224135760342422259061068512044369
    GENERATOR = Point(Coordinate(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, PRIME),
                      Coordinate(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5, PRIME))
    A = PRIME - 3
    HASHER = "sha256"

    # Equation courtesy of https://www.hyperelliptic.org/EFD/g1p/auto-montgom.html
    @classmethod
    def add(cls, p1, p2):
        # x3 = (y2 - y1)^2 / (x2 - x1)^2 - x1 - x2
        x3 = (p2.y - p1.y) ** 2 / (p2.x - p1.x) ** 2 - p1.x - p2.x
        # y3 = (2 * x1 + x2) * (y2 - y1) / (x2 - x1) - (y2 - y1)^3 / (x2 - x1)^3 - y1
        y3 = (2 * p1.x + p2.x) * (p2.y - p1.y) / (p2.x - p1.x) - (p2.y - p1.y) ** 3 / (p2.x - p1.x) ** 3 - p1.y
        return Point(x3, y3)

    # Equation courtesy of https://www.hyperelliptic.org/EFD/g1p/auto-montgom.html
    @classmethod
    def double(cls, p):
        # x3 = (3 * x1^2 + a)^2 / (2 * y1)^2 - x1 - x1
        x3 = (cls.A + 3 * p.x**2)**2 / (2 * p.y)**2 - p.x - p.x
        # y3 = (2 * x1 + x1) * (3 * x1^2 + a) / (2 * y1) - (3 * x1^2 + a)^3 / (2 * y1)^3 - y1
        y3 = (2 * p.x + p.x) * (cls.A + 3 * p.x**2) / (2 * p.y) - (cls.A + 3 * p.x**2)**3 / (2 * p.y)**3 - p.y
        return Point(x3, y3)


# See section D.1.2.4 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf ; Inherits add/double from P-256
class CurveP384(CurveP256):
    PRIME = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
    ORDER = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643
    GENERATOR = Point(Coordinate(0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7, PRIME),
                      Coordinate(0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f, PRIME))
    A = PRIME - 3
    HASHER = "sha384"


# See section D.1.2.5 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf ; Inherits add/double from P-256
class CurveP521(CurveP256):
    PRIME = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151
    ORDER = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449
    GENERATOR = Point(Coordinate(0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66, PRIME),
                      Coordinate(0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650, PRIME))
    A = PRIME - 3
    HASHER = "sha512"


# Conveniently pull two keys into a pair; immutable but does not have to be fully populated
KeyPair = namedtuple('KeyPair', 'public private')


class ECDSA:

    def __init__(self, curve):
        self.curve = curve

    def generate_keypair(self, private=None):
        c = secrets.randbits(256+64)
        if private is None: private = (c % (self.curve.ORDER - 1)) + 1
        public = self._multiply_k_p(private, self.curve.GENERATOR)
        return KeyPair(public=public, private=private)

    def sign(self, message, private_key, k=None):
        z = hashlib.new(self.curve.HASHER, message).digest()
        z_int = int.from_bytes(z, byteorder='big') % self.curve.ORDER
        if k is None: k, kp = self._get_k_kp()
        else: kp = Coordinate.inv(Coordinate(k, self.curve.ORDER), self.curve.ORDER).coord
        r = self._multiply_k_p(k, self.curve.GENERATOR).x.coord % self.curve.ORDER
        s = (kp * (z_int + (private_key * r) % self.curve.ORDER) % self.curve.ORDER)
        if r == 0 or s == 0: return self.sign(message, private_key)
        return r, s

    def verify(self, message, public_key, r, s):
        if r == 0 or s == 0 or r >= self.curve.ORDER or s >= self.curve.ORDER: return False
        z = hashlib.sha256(message).digest()
        z_int = int.from_bytes(z, byteorder='big') % self.curve.ORDER
        w = Coordinate.inv(Coordinate(s, self.curve.ORDER), self.curve.ORDER).coord
        u1 = (z_int * w) % self.curve.ORDER
        u2 = (r * w) % self.curve.ORDER
        v1 = self._multiply_k_p(u1, self.curve.GENERATOR)
        v2 = self._multiply_k_p(u2, public_key)
        v = self.curve.add(v1, v2).x.coord % self.curve.ORDER
        #print(hex(r), hex(v))
        if r != v: return False
        return True

    def _get_k_kp(self):
        c = secrets.randbits(256+64)
        k = c % (self.curve.ORDER - 1) + 1
        kp = Coordinate.inv(Coordinate(k, self.curve.ORDER), self.curve.ORDER)
        if k * kp.coord % self.curve.ORDER != 1: raise RuntimeError("k * kp != 1")
        return k, kp.coord

    def _multiply_k_p(self, k, p):
        accumulator = None
        for bit in bin(k)[::-1]:
            if bit == '1':
                if accumulator is None: accumulator = p
                else: accumulator = self.curve.add(accumulator, p)
            p = self.curve.double(p)
        return accumulator
