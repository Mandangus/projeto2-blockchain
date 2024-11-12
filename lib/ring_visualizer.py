import matplotlib.pyplot as plt
from crypto_keys import PrivateKey
from elliptic_curve import EllipticCurveOperations
from ring import PublicKeyRing, sign, verify

# Setup elliptic curve and keys
curve = EllipticCurveOperations()
private_key1 = PrivateKey(curve)
private_key2 = PrivateKey(curve)
private_key3 = PrivateKey(curve)

# Create public key ring
public_key_ring = PublicKeyRing()
public_key_ring.add(private_key1.public_key)
public_key_ring.add(private_key2.public_key)
public_key_ring.add(private_key3.public_key)

# Sign a message
message = b"Visualizing the ring signature process"
signature = sign(message, private_key1, public_key_ring)

# Verification status
is_valid = verify(message, public_key_ring, signature)

# Visualization
fig, ax = plt.subplots()

# Plot the keys in the ring
for i, public_key in enumerate(public_key_ring.public_keys):
    ax.plot(public_key.x, public_key.y, 'bo', label=f'Public Key {i+1}' if i == 0 else "")
    ax.text(public_key.x, public_key.y, f"PK{i+1}", ha='right')

# Plot the signature points
ax.plot(signature.hash_x, signature.hash_y, 'ro', label='Signature Hash')
ax.text(signature.hash_x, signature.hash_y, "Signature Hash", ha='right')

# Add legend and titles
plt.title("Ring Signature Process Visualization")
ax.legend()
plt.xlabel("Elliptic Curve X Coordinate")
plt.ylabel("Elliptic Curve Y Coordinate")

# Display verification result
plt.figtext(0.5, 0.02, f"Signature Verification: {'Valid' if is_valid else 'Invalid'}", ha="center", fontsize=12)

plt.show()
