 SSC0958 - Criptomoedas e Blockchain  \\ **Projeto 2**
# Unique Ring Signatures (URS) in Python


## Table of Contents
- [Overview](#overview)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Usage](#usage)
- [Elliptic Curve Details](#elliptic-curve-details)
- [References](#references)

## Overview
Ring signatures allow a signer to prove they belong to a group of public keys without revealing their individual identity. This URS implementation uses elliptic curve cryptography to securely manage key rings and verify signatures.

## Installation
Requires Python 3 and the `ecdsa` library:
```bash
pip install ecdsa
```

## Project Structure

- **crypto_keys.py**: Public and private key classes.
- **elliptic_curve.py**: Elliptic curve operations (point addition, scalar multiplication, hashing).
- **ring.py**: Core ring signature logic for signing and verifying.

## Usage

### Key Generation
```python
from crypto_keys import PrivateKey
from elliptic_curve import EllipticCurveOperations

curve = EllipticCurveOperations()
private_key = PrivateKey(curve)
public_key = private_key.public_key
```

### Creating a Public Key Ring
```python
from ring import PublicKeyRing

public_key_ring = PublicKeyRing()
public_key_ring.add(public_key)
# Add more public keys as needed
```

### Signing a Message
```python
from ring import sign

message = b"Your message here"
signature = sign(message, private_key, public_key_ring)
```

### Verifying a Signature
```python
from ring import verify

is_valid = verify(message, public_key_ring, signature)
print("Signature valid:", is_valid)
```

## Elliptic Curve Details
Uses SECP256k1 elliptic curve (also used in Bitcoin) for strong security and compatibility, provided by the `ecdsa` library.

## References
- [NSA Suite B Implementer's Guide to FIPS 186-3](https://www.nsa.gov/ia/_files/ecdsa.pdf)
- [SECG SEC1 Standard](https://www.secg.org/download/aid-780/sec1-v2.pdf)
- "Unique Ring Signatures: Short and Provably Secure" ([full version](http://eprint.iacr.org/2012/577.pdf))

---

This implementation can be applied in areas requiring anonymity, such as cryptocurrency transactions, secure voting, and confidential communications.
