import unittest
from crypto_keys import PrivateKey, PublicKey
from elliptic_curve import EllipticCurveOperations
from ring import PublicKeyRing, sign, verify

class TestRingSignature(unittest.TestCase):
    def setUp(self):
        self.curve = EllipticCurveOperations()
        self.private_key1 = PrivateKey(self.curve)
        self.private_key2 = PrivateKey(self.curve)
        self.private_key3 = PrivateKey(self.curve)

        # Create public key ring and add public keys
        self.public_key_ring = PublicKeyRing()
        self.public_key_ring.add(self.private_key1.public_key)
        self.public_key_ring.add(self.private_key2.public_key)
        self.public_key_ring.add(self.private_key3.public_key)

        self.message = b"Test message for ring signature"

    def test_key_generation(self):
        self.assertIsInstance(self.private_key1.public_key, PublicKey)
        self.assertIsInstance(self.private_key2.public_key, PublicKey)
        self.assertIsInstance(self.private_key3.public_key, PublicKey)

    def test_sign_and_verify(self):
        # Sign with private_key1
        signature = sign(self.message, self.private_key1, self.public_key_ring)

        # Verify the signature
        is_valid = verify(self.message, self.public_key_ring, signature)
        self.assertTrue(is_valid)

    def test_signature_with_modified_message(self):
        # Sign with private_key1
        signature = sign(self.message, self.private_key1, self.public_key_ring)

        # Verify with a modified message
        modified_message = b"Modified message"
        is_valid = verify(modified_message, self.public_key_ring, signature)
        self.assertFalse(is_valid)

    def test_signature_with_modified_ring(self):
        # Sign with private_key1
        signature = sign(self.message, self.private_key1, self.public_key_ring)

        # Create a modified public key ring
        modified_ring = PublicKeyRing()
        modified_ring.add(self.private_key2.public_key)  # Only add one key

        # Verify the signature with the modified ring
        is_valid = verify(self.message, modified_ring, signature)
        self.assertFalse(is_valid)

if __name__ == "__main__":
    unittest.main()
