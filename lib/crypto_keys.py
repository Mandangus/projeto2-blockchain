from ecdsa import SigningKey, VerifyingKey, SECP256k1
from elliptic_curve import EllipticCurveOperations

class PublicKey:
    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y

    def __str__(self):
        return f"X({self.x})\nY({self.y})\n"


class PrivateKey:
    def __init__(self, curve):
        self.curve = curve
        self.sk = SigningKey.generate(curve=SECP256k1)
        self.vk = self.sk.verifying_key
        self.d = int.from_bytes(self.sk.to_string(), 'big')
        self.x, self.y = self.curve.point_from_private_key(self.d)
        self.public_key = PublicKey(self.curve, self.x, self.y)
