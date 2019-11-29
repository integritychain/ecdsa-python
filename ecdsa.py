#
# Supports ECDSA generate keys, sign and verify for P-256/SHA256, P-384/SHA384 and P-521/SHA512
# This reference code prioritizes simplicity and brevity over performance and side-channel resistance.
# It is strictly for educational purposes and should not be used in production.
#

# References:
#  [1] NIST FIPS 186-4 https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
#  [2] CAVP Test Vectors https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3ecdsatestvectors.zip
#  [3] RFC 6979 https://tools.ietf.org/html/rfc6979
#  [4] Explicit-Formulas Database, Montgomery Curves https://www.hyperelliptic.org/EFD/g1p/auto-montgom.html

import hashlib, secrets
from collections import namedtuple


# Coordinate suitable for an arbitrary modulus (and can be used with both curve modulus and order)
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


# Conveniently pull two coordinates into a point; immutable but does not have to be fully populated
Point = namedtuple('Point', 'x y')


# See Section D.1.2.3 of [1]
class CurveP256:
    PRIME = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    ORDER = 115792089210356248762697446949407573529996955224135760342422259061068512044369
    GENERATOR = Point(Coordinate(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, PRIME),
                      Coordinate(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5, PRIME))
    A = PRIME - 3
    B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    HASHER = "sha256"  # Hasher choice fixed for simplicity

    # Equation courtesy of [4]
    @classmethod
    def add(cls, p1, p2):
        if p1.x.coord == p2.x.coord or p1.y.coord == p2.y.coord: raise RuntimeError("Cannot adds point having an equal coordinate")
        # x3 = (y2 - y1)^2 / (x2 - x1)^2 - x1 - x2
        x3 = (p2.y - p1.y) ** 2 / (p2.x - p1.x) ** 2 - p1.x - p2.x
        # y3 = (2 * x1 + x2) * (y2 - y1) / (x2 - x1) - (y2 - y1)^3 / (x2 - x1)^3 - y1
        y3 = (2 * p1.x + p2.x) * (p2.y - p1.y) / (p2.x - p1.x) - (p2.y - p1.y) ** 3 / (p2.x - p1.x) ** 3 - p1.y
        return Point(x3, y3)

    # Equation courtesy of [4]
    @classmethod
    def double(cls, p):
        if p.x.coord == 0 or p.y.coord == 0: raise RuntimeError("Cannot double a point with 0 coordinate")
        # x3 = (3 * x1^2 + a)^2 / (2 * y1)^2 - x1 - x1
        x3 = (cls.A + 3 * p.x**2)**2 / (2 * p.y)**2 - p.x - p.x
        # y3 = (2 * x1 + x1) * (3 * x1^2 + a) / (2 * y1) - (3 * x1^2 + a)^3 / (2 * y1)^3 - y1
        y3 = (2 * p.x + p.x) * (cls.A + 3 * p.x**2) / (2 * p.y) - (cls.A + 3 * p.x**2)**3 / (2 * p.y)**3 - p.y
        return Point(x3, y3)

    @classmethod
    def isOnCurve(cls, p):
        # Check y^2 ≡ x^3 – 3x + b (mod p)
        right = cls.B + p.x**3 + cls.A*p.x
        left = p.y**2
        return right.coord == left.coord


# See Section D.1.2.4 of [1]; Inherits add, double and isOnCurve from P-256
class CurveP384(CurveP256):
    PRIME = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
    ORDER = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643
    GENERATOR = Point(Coordinate(0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7, PRIME),
                      Coordinate(0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f, PRIME))
    A = PRIME - 3
    B = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
    HASHER = "sha384"  # Hasher choice fixed for simplicity


# See Section D.1.2.5 of [1]; Inherits add, double and isOnCurve from P-256
class CurveP521(CurveP256):
    PRIME = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151
    ORDER = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449
    GENERATOR = Point(Coordinate(0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66, PRIME),
                      Coordinate(0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650, PRIME))
    A = PRIME - 3
    B = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
    HASHER = "sha512"  # Hasher choice fixed for simplicity


# Conveniently pull two keys into a pair; immutable but does not have to be fully populated
KeyPair = namedtuple('KeyPair', 'public private')


class ECDSA:

    def __init__(self, curve):
        self.curve = curve

    # See Section B.4.1 of [1]
    def generate_keypair(self, private=None):
        c = secrets.randbits(self.curve.ORDER.bit_length()+64)
        if private is None: private = (c % (self.curve.ORDER - 1)) + 1  # Allow private to be specified for testing
        public = self._multiply_k_p(private, self.curve.GENERATOR)
        return KeyPair(public=public, private=private)

    # See Section 4.6 of [1]
    def sign(self, message, key_pair, k=None):
        z = hashlib.new(self.curve.HASHER, message).digest()  # See Section 6.4-4 of [1]
        z_int = int.from_bytes(z, byteorder='big') % self.curve.ORDER
        if k is None: k, kp = self._get_k_kp()  # See Section 6.3 of [1]; Allow k to be specified for testing
        else: kp = Coordinate.inv(Coordinate(k, self.curve.ORDER), self.curve.ORDER).coord
        r = self._multiply_k_p(k, self.curve.GENERATOR).x.coord % self.curve.ORDER
        s = (kp * (z_int + (key_pair.private * r) % self.curve.ORDER) % self.curve.ORDER)
        if r == 0 or s == 0: r, s = self.sign(message, key_pair)  # If r or s are zero, try again
        if key_pair.public is not None:  # To skip signature validation, do not pass public key
            good_signature = self.verify(message, key_pair.public, r, s)
            if not good_signature: return None, None
        return r, s

    # See Section 4.7 of [1]
    def verify(self, message, public_key, r, s):
        if r == 0 or s == 0 or r >= self.curve.ORDER or s >= self.curve.ORDER: return False
        if not self.curve.isOnCurve(public_key): return False
        z = hashlib.new(self.curve.HASHER, message).digest()
        z_int = int.from_bytes(z, byteorder='big') % self.curve.ORDER
        w = Coordinate.inv(Coordinate(s, self.curve.ORDER), self.curve.ORDER).coord
        u1 = (z_int * w) % self.curve.ORDER
        u2 = (r * w) % self.curve.ORDER
        v1 = self._multiply_k_p(u1, self.curve.GENERATOR)
        v2 = self._multiply_k_p(u2, public_key)
        v = self.curve.add(v1, v2).x.coord % self.curve.ORDER
        if r != v: return False
        return True

    # See Appendix B.5.1 of [1]
    def _get_k_kp(self):
        c = secrets.randbits(self.curve.ORDER.bit_length()+64)
        k = c % (self.curve.ORDER - 1) + 1
        kp = Coordinate.inv(Coordinate(k, self.curve.ORDER), self.curve.ORDER)
        return k, kp.coord

    # Multiply scalar times point via 'double and add' algorithm
    def _multiply_k_p(self, k, p):
        accumulator = None
        for bit in bin(k)[::-1]:  # Iterate through the scalar multiplier bits from LSB to MSB
            if bit == '1':
                if accumulator is None: accumulator = p
                else: accumulator = self.curve.add(accumulator, p)
            p = self.curve.double(p)
        return accumulator
