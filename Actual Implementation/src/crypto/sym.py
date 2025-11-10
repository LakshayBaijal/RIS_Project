# src/crypto/sym.py
# AES-GCM helpers + derive symmetric key from an EC point
import os
import base64
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key_from_point(point_bytes: bytes) -> bytes:
    """
    Derive a 32-byte symmetric key from an EC point's serialized bytes.
    Uses SHA-256 and returns 32 bytes.
    """
    h = sha256(point_bytes).digest()
    return h  # 32 bytes

def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> dict:
    """
    Encrypt plaintext with AES-GCM.
    key: 16/24/32 bytes (we'll use 32 bytes)
    Returns dict with base64-encoded nonce and ciphertext.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return {
        "nonce_b64": base64.b64encode(nonce).decode(),
        "ct_b64": base64.b64encode(ct).decode()
    }

def aes_decrypt(key: bytes, nonce_b64: str, ct_b64: str, aad: bytes = b"") -> bytes:
    """
    Decrypt base64 nonce & ciphertext with AES-GCM.
    Returns plaintext bytes (raises exception on auth failure).
    """
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    return aesgcm.decrypt(nonce, ct, aad)
