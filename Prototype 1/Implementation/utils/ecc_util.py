# utils/ecc_util.py
"""
ECC Utility Functions
Handles ECC key generation, signing, and verification.
Uses elliptic curve cryptography (secp256r1) — suitable for IoT & lightweight systems.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

# Generate ECC key pair
def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Sign a message using ECC private key
def sign_message(private_key, message: bytes) -> bytes:
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

# Verify ECC signature
def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

# Serialize keys to PEM (for storage/transmission)
def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Load keys back from PEM
def load_private_key(pem_data):
    return serialization.load_pem_private_key(pem_data, password=None)

def load_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data)
