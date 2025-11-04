import os, base64, json
from hashlib import sha256
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
from Crypto.Cipher import AES

def gen_ecc_keypair() -> Tuple[ec.EllipticCurvePrivateKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv, pub_pem

def load_pubkey(pem: str):
    return serialization.load_pem_public_key(pem.encode())

def load_privkey(pem: str):
    return serialization.load_pem_private_key(pem.encode(), password=None)

def privkey_to_pem(priv) -> str:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

def _derive_aes_key(shared_secret: bytes, info: bytes = b"ecies") -> bytes:
    return sha256(shared_secret + info).digest()  # 32 bytes

def ecies_encrypt_for_pubkey(recipient_pub_pem: str, plaintext: bytes) -> dict:
    recipient_pub = load_pubkey(recipient_pub_pem)
    eph_priv = ec.generate_private_key(ec.SECP256R1())
    shared = eph_priv.exchange(ec.ECDH(), recipient_pub)
    aes_key = _derive_aes_key(shared, b"ecies-wrap")

    cipher = AES.new(aes_key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext)

    eph_pub_pem = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return {
        "eph_pub": eph_pub_pem,
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def ecies_decrypt_with_privkey(recipient_priv_pem: str, envelope: dict) -> bytes:
    recip_priv = load_privkey(recipient_priv_pem)
    eph_pub = load_pubkey(envelope["eph_pub"])
    shared = recip_priv.exchange(ec.ECDH(), eph_pub)
    aes_key = _derive_aes_key(shared, b"ecies-wrap")

    nonce = base64.b64decode(envelope["nonce"])
    ct = base64.b64decode(envelope["ct"])
    tag = base64.b64decode(envelope["tag"])

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt
