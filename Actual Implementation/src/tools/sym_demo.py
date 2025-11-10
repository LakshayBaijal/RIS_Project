# src/tools/sym_demo.py
# Demo that derives a symmetric key from an ECC point and does AES-GCM encrypt/decrypt.

from src.crypto.ecc import scalar_mul, point_to_bytes
from src.crypto.sym import derive_key_from_point, aes_encrypt, aes_decrypt

def demo():
    # 1) Choose a secret scalar s (for demo we choose a small number; in real use pick random)
    s = 123456789  # demo secret scalar
    P = scalar_mul(s)  # s * G

    # 2) Derive a 32-byte symmetric key from serialized point
    P_bytes = point_to_bytes(P)
    key = derive_key_from_point(P_bytes)
    print("Derived key (hex):", key.hex()[:64], "...")

    # 3) Encrypt a sample plaintext
    plaintext = b"Hello, this is a symmetric encryption test - Lakshay demo."
    ct = aes_encrypt(key, plaintext)
    print("Ciphertext (nonce b64):", ct['nonce_b64'])
    print("Ciphertext (ct b64)  :", ct['ct_b64'][:80], "...")

    # 4) Decrypt and verify
    pt2 = aes_decrypt(key, ct['nonce_b64'], ct['ct_b64'])
    print("Decrypted matches:", pt2 == plaintext)
    print("Decrypted plaintext (start):", pt2[:80])

if __name__ == "__main__":
    demo()
