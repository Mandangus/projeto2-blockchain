from ecdsa import SECP256k1, ellipticcurve
from hashlib import sha256
import secrets

class EllipticCurveOperations:
    def __init__(self):
        self.curve = SECP256k1.curve
        self.generator = SECP256k1.generator
        self.order = self.generator.order()
        self.a = self.curve.a()
        self.b = self.curve.b()
        self.gx, self.gy = self.generator.x(), self.generator.y()

    def scalar_mult(self, k, x, y):
        point = ellipticcurve.Point(self.curve, x, y) * k
        return point.x(), point.y()

    def add(self, x1, y1, x2, y2):
        p1 = ellipticcurve.Point(self.curve, x1, y1)
        p2 = ellipticcurve.Point(self.curve, x2, y2)
        p3 = p1 + p2
        return p3.x(), p3.y()

    def is_on_curve(self, x, y):
        # Check if (x, y) is on the curve
        point = ellipticcurve.Point(self.curve, x, y)
        return self.curve.contains_point(point.x(), point.y())

    def hash_to_curve(self, message):
        h = sha256(message).digest()
        h_int = int.from_bytes(h, 'big') % self.order
        point = self.generator * h_int
        return point.x(), point.y()

    def rand_field_element(self):
        return secrets.randbelow(self.order - 1) + 1

    def point_from_private_key(self, private_key):
        point = self.generator * private_key
        return point.x(), point.y()
