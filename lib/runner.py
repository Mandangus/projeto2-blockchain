from crypto_keys import PrivateKey
from elliptic_curve import EllipticCurveOperations
from ring import PublicKeyRing, sign, verify

def generate_random_public_keys(curve, n):
    """Generates n random public keys."""
    public_keys = []
    for _ in range(n):
        temp_private_key = PrivateKey(curve)
        public_keys.append(temp_private_key.public_key)
    return public_keys

def main():
    curve = EllipticCurveOperations()

    try:
        n = int(input("Enter the number of random public keys to generate: "))
    except ValueError:
        print("Please enter a valid integer.")
        return

    public_key_ring = PublicKeyRing()
    random_public_keys = generate_random_public_keys(curve, n)
    for public_key in random_public_keys:
        public_key_ring.add(public_key)

    user_private_key = PrivateKey(curve)
    public_key_ring.add(user_private_key.public_key)

    message = input("Enter the message to sign: ").encode()

    signature = sign(message, user_private_key, public_key_ring)

    is_valid = verify(message, public_key_ring, signature)

    if is_valid:
        print("\nSignature verification successful! The message is authentic.")
    else:
        print("\nSignature verification failed. The message is not authentic.")

if __name__ == "__main__":
    main()
