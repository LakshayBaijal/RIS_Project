# src/crypto/ecc.py
# ECC primitives using ECPy (Python 3.12 compatible)
from ecpy.curves import Curve, Point
from hashlib import sha256

curve = Curve.get_curve('secp256r1')
G = curve.generator
n = curve.order

def scalar_mul(k, P=None):
    """Return k * P (scalar multiplication)."""
    if P is None:
        P = G
    return k * P

def point_add(P, Q):
    """Return P + Q."""
    return P + Q

def point_to_bytes(P):
    """Serialize EC point (uncompressed)."""
    x = int(P.x).to_bytes(32, 'big')
    y = int(P.y).to_bytes(32, 'big')
    return x + y

def bytes_to_point(b):
    """Deserialize bytes → EC point."""
    x = int.from_bytes(b[:32], 'big')
    y = int.from_bytes(b[32:], 'big')
    return Point(x, y, curve)

def hash_to_int(data: bytes):
    """Hash arbitrary bytes to integer mod curve order."""
    h = sha256(data).digest()
    return int.from_bytes(h, 'big') % n

def demo():
    """Simple sanity check."""
    priv = 7
    pub = scalar_mul(priv)
    print("Private key =", priv)
    print("Public  key  =", pub)
    print("Serialized   =", point_to_bytes(pub).hex()[:20], "...")
    assert bytes_to_point(point_to_bytes(pub)) == pub
    print("✅ ECC test passed successfully.")

def point_sub(P, Q):
    """
    Subtract two points on the same curve: P - Q = P + (-Q)
    """
    # same curve assumed
    neg_Q = Point(Q.x, (-Q.y) % curve.field, curve)
    return point_add(P, neg_Q)



if __name__ == "__main__":
    demo()
