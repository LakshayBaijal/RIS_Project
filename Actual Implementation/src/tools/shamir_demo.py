# src/tools/shamir_demo.py
from src.lsss.shamir import split_secret, reconstruct_secret
from ecpy.curves import Curve
import random

def demo():
    curve = Curve.get_curve('secp256r1')
    secret = random.randrange(1, curve.order)
    print("Original secret:", secret)

    n, t = 5, 3
    shares = split_secret(secret, n, t)
    print("\nGenerated shares (index, value):")
    for s in shares:
        print(s)

    # Reconstruct from any t shares
    subset = random.sample(shares, t)
    recovered = reconstruct_secret(subset)
    print("\nReconstructed from", t, "shares:", recovered)

    print("✅ Match:", recovered == secret)

if __name__ == "__main__":
    demo()
