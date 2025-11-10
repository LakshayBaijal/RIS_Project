# src/tools/encryptor_demo.py
# Combine ECC + AES + Shamir sharing into one working demo

import os, random, base64
from ecpy.curves import Curve
from hashlib import sha256

from src.crypto.ecc import scalar_mul, point_to_bytes
from src.crypto.sym import derive_key_from_point, aes_encrypt, aes_decrypt
from src.lsss.shamir import split_secret, reconstruct_secret

def demo():
    curve = Curve.get_curve('secp256r1')

    # --- Step 1: Generate random ECC scalar s and point P = s*G
    s = random.randrange(1, curve.order)
    P = scalar_mul(s)
    print("Random secret scalar s:", s)
    print("Point P = s*G computed.")

    # --- Step 2: Derive 32-byte AES key from P
    key = derive_key_from_point(point_to_bytes(P))
    print("Derived AES key:", key.hex()[:32], "...")

    # --- Step 3: Encrypt sample plaintext
    plaintext = b"This is a full ECC + AES + Secret-Sharing integrated demo."
    ct = aes_encrypt(key, plaintext)
    print("\nCiphertext (base64 snippet):", ct["ct_b64"][:60], "...")

    # --- Step 4: Split s into shares (n=5, t=3)
    n, t = 5, 3
    shares = split_secret(s, n, t)
    print(f"\nGenerated {n} shares (threshold={t}):")
    for idx, share in shares:
        print(f"  Share {idx}: {share}")

    # --- Step 5: Reconstruct s from any t shares
    subset = random.sample(shares, t)
    s_rec = reconstruct_secret(subset)
    print("\nReconstructed s:", s_rec)
    print("✅ Match:", s_rec == s)

    # --- Step 6: Derive key again from reconstructed s and decrypt
    P2 = scalar_mul(s_rec)
    key2 = derive_key_from_point(point_to_bytes(P2))
    pt2 = aes_decrypt(key2, ct["nonce_b64"], ct["ct_b64"])
    print("\nDecryption success:", pt2 == plaintext)
    print("Decrypted plaintext:", pt2)

if __name__ == "__main__":
    demo()
