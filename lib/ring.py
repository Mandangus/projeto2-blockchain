from hashlib import sha256

class PublicKeyRing:
    def __init__(self):
        self.public_keys = []

    def add(self, public_key):
        self.public_keys.append(public_key)

    def to_bytes(self):
        result = b""
        for public_key in self.public_keys:
            result += public_key.x.to_bytes(32, 'big') + public_key.y.to_bytes(32, 'big')
        return result

    def __len__(self):
        return len(self.public_keys)


class RingSignature:
    def __init__(self, hash_x, hash_y, challenge_values, response_values):
        self.hash_x = hash_x
        self.hash_y = hash_y
        self.challenge_values = challenge_values
        self.response_values = response_values

    def __str__(self):
        return f"Ring Signature:\nHash X={self.hash_x}\nHash Y={self.hash_y}\nChallenges={self.challenge_values}\nResponses={self.response_values}"


def hash_all(elements):
    """Hash a list of integer elements and return the hash as an integer."""
    hasher = sha256()
    for element in elements:
        hasher.update(element.to_bytes(32, 'big'))
    return int.from_bytes(hasher.digest(), 'big')


def sign(message, private_key, public_key_ring):
    """
    Generate a ring signature for the given message using the private key and public key ring.
    
    Args:
        message (bytes): The message to be signed.
        private_key (PrivateKey): The signer's private key.
        public_key_ring (PublicKeyRing): The ring of public keys.

    Returns:
        RingSignature: The generated ring signature.
    """
    ring_size = len(public_key_ring)
    curve = private_key.curve
    base_point_x, base_point_y = curve.gx, curve.gy

    # Arrays to hold elliptic curve points and signature components
    a_x_points, a_y_points = [0] * ring_size, [0] * ring_size
    b_x_points, b_y_points = [0] * ring_size, [0] * ring_size
    challenge_values, response_values = [0] * ring_size, [0] * ring_size

    # Compute the hash point (hx, hy) based on the message and public keys
    message_ring_bytes = message + public_key_ring.to_bytes()
    hx, hy = curve.hash_to_curve(message_ring_bytes)
    total_challenge_sum = 0

    signer_index = None

    for j in range(ring_size):
        # Generate random challenge and response values for each participant
        challenge_values[j] = curve.rand_field_element()
        response_values[j] = curve.rand_field_element()

        if public_key_ring.public_keys[j] == private_key.public_key:
            # Save the index of the actual signer
            signer_index = j

            # Compute A = g^r and B = H(m, R)^r for the signer
            a_x_points[signer_index], a_y_points[signer_index] = curve.scalar_mult(response_values[signer_index], base_point_x, base_point_y)
            b_x_points[signer_index], b_y_points[signer_index] = curve.scalar_mult(response_values[signer_index], hx, hy)
        else:
            # For non-signers, compute A = g^t * y^c and B = H(m, R)^(xi*c + t)
            a_x_temp, a_y_temp = curve.scalar_mult(response_values[j], base_point_x, base_point_y)
            a_x_point, a_y_point = curve.add(a_x_temp, a_y_temp, *curve.scalar_mult(challenge_values[j], public_key_ring.public_keys[j].x, public_key_ring.public_keys[j].y))
            a_x_points[j], a_y_points[j] = a_x_point, a_y_point

            b_x_points[j], b_y_points[j] = curve.scalar_mult(response_values[j] + challenge_values[j] * private_key.d, hx, hy)
            total_challenge_sum += challenge_values[j]

    # Compute the challenge for the actual signer based on the hash of all values
    hash_of_points = hash_all([hx, hy, *a_x_points, *a_y_points, *b_x_points, *b_y_points])
    challenge_values[signer_index] = (hash_of_points - total_challenge_sum) % curve.order

    # Compute the response for the actual signer
    response_values[signer_index] = (response_values[signer_index] - challenge_values[signer_index] * private_key.d) % curve.order

    # Generate the final hashed result from the signer's private key and message
    hash_signature_x, hash_signature_y = curve.scalar_mult(private_key.d, hx, hy)
    return RingSignature(hash_signature_x, hash_signature_y, challenge_values, response_values)


def verify(message, public_key_ring, ring_signature):
    """
    Verify a ring signature for a given message and public key ring.

    Args:
        message (bytes): The message that was signed.
        public_key_ring (PublicKeyRing): The ring of public keys.
        ring_signature (RingSignature): The ring signature to verify.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    ring_size = len(public_key_ring)
    if ring_size == 0:
        return False

    curve = public_key_ring.public_keys[0].curve
    hx, hy = curve.hash_to_curve(message + public_key_ring.to_bytes())
    total_challenge_sum = 0

    a_x_points, a_y_points = [0] * ring_size, [0] * ring_size
    b_x_points, b_y_points = [0] * ring_size, [0] * ring_size

    for j in range(ring_size):
        # Ensure each challenge and response value is within the valid range
        if not (0 <= ring_signature.challenge_values[j] < curve.order and
                0 <= ring_signature.response_values[j] < curve.order):
            return False

        # Compute A = g^t * y^c for each participant
        a_x_temp, a_y_temp = curve.scalar_mult(ring_signature.response_values[j], curve.gx, curve.gy)
        a_x_point, a_y_point = curve.add(a_x_temp, a_y_temp, *curve.scalar_mult(ring_signature.challenge_values[j], public_key_ring.public_keys[j].x, public_key_ring.public_keys[j].y))
        a_x_points[j], a_y_points[j] = a_x_point, a_y_point

        # Compute B = H(m, R)^t * tau^c for each participant
        b_x_temp, b_y_temp = curve.scalar_mult(ring_signature.response_values[j], hx, hy)
        b_x_point, b_y_point = curve.add(b_x_temp, b_y_temp, *curve.scalar_mult(ring_signature.challenge_values[j], ring_signature.hash_x, ring_signature.hash_y))
        b_x_points[j], b_y_points[j] = b_x_point, b_y_point

        total_challenge_sum += ring_signature.challenge_values[j]

    # Verify if the total challenge matches the hash of all A and B points
    hash_of_points = hash_all([hx, hy, *a_x_points, *a_y_points, *b_x_points, *b_y_points])
    return total_challenge_sum % curve.order == hash_of_points % curve.order
