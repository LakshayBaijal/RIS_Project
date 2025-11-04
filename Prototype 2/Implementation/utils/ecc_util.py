from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
import base64

def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    print("\n🔑 [ECC] Generated Key Pair")
    print("Private Key (PEM):\n", priv_pem)
    print("Public Key (PEM):\n", pub_pem)

    return private_key, public_key

def sign_message(private_key, message: bytes) -> str:
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    sig_b64 = base64.b64encode(signature).decode()
    print("\n🖋 [ECC] Message Signed → Signature (Base64):", sig_b64)
    return sig_b64

def verify_signature(public_key, message: bytes, signature_b64: str) -> bool:
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        print("✅ [ECC] Signature Verified Successfully!")
        return True
    except Exception as e:
        print("❌ [ECC] Verification Failed:", e)
        return False
