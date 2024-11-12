import matplotlib.pyplot as plt
from crypto_keys import PrivateKey
from elliptic_curve import EllipticCurveOperations
from ring import PublicKeyRing, sign, verify

try:
    n = int(input("Enter the number of public keys to add to the ring: "))
    if n <= 0:
        raise ValueError("Number of public keys must be a positive integer.")
except ValueError as e:
    print(f"Invalid input: {e}")
    exit()

curve = EllipticCurveOperations()
public_key_ring = PublicKeyRing()
private_keys = []

for i in range(n):
    private_key = PrivateKey(curve)
    private_keys.append(private_key)
    public_key_ring.add(private_key.public_key)

message = b"Visualizing the ring signature process"
signature = sign(message, private_keys[0], public_key_ring)

is_valid = verify(message, public_key_ring, signature)

fig, ax = plt.subplots()

for i, public_key in enumerate(public_key_ring.public_keys):
    ax.plot(public_key.x, public_key.y, 'bo', label=f'Public Key {i+1}' if i == 0 else "")
    ax.text(public_key.x, public_key.y, f"PK{i+1}", ha='right')

ax.plot(signature.hash_x, signature.hash_y, 'ro', label='Signature Hash')
ax.text(signature.hash_x, signature.hash_y, "Signature Hash", ha='right')

plt.title("Ring Signature Process Visualization")
ax.legend()
plt.xlabel("Elliptic Curve X Coordinate")
plt.ylabel("Elliptic Curve Y Coordinate")

# Display verification result
plt.figtext(0.5, 0.02, f"Signature Verification: {'Valid' if is_valid else 'Invalid'}", ha="center", fontsize=12)

plt.show()
