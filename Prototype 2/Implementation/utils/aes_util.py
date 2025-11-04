from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64, json

def gen_sym_key():
    key = get_random_bytes(32)  # 256-bit key
    print("\n🧬 [AES] Generated 256-bit Symmetric Key (Base64):", base64.b64encode(key).decode())
    return key

def aes_encrypt(key: bytes, plaintext: bytes) -> dict:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    out = {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }
    print("\n🔐 [AES] Encryption Result:\n", json.dumps(out, indent=2))
    return out

def aes_decrypt(key: bytes, enc: dict) -> bytes:
    nonce = base64.b64decode(enc["nonce"])
    ciphertext = base64.b64decode(enc["ciphertext"])
    tag = base64.b64decode(enc["tag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ciphertext, tag)
    print("\n🔓 [AES] Decrypted Plaintext:", pt.decode(errors="ignore"))
    return pt
