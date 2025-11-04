# utils/aes_util.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Generate a 256-bit symmetric AES key
def gen_sym_key():
    return get_random_bytes(32)  # 32 bytes = 256 bits

# Encrypt using AES-GCM
def aes_encrypt(key, plaintext: bytes) -> dict:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }

# Decrypt using AES-GCM
def aes_decrypt(key, enc_dict: dict) -> bytes:
    nonce = base64.b64decode(enc_dict["nonce"])
    ciphertext = base64.b64decode(enc_dict["ciphertext"])
    tag = base64.b64decode(enc_dict["tag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
