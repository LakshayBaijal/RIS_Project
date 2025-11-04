from utils.ecc_util import generate_ecc_keypair, sign_message, verify_signature
from utils.aes_util import gen_sym_key, aes_encrypt, aes_decrypt

print("────────────────────────────────────────────")
print("STEP 1 • Crypto Utilities Demo (ECC + AES)")
print("────────────────────────────────────────────")

# ECC
priv, pub = generate_ecc_keypair()
msg = b"Industrial IoT demo message"
sig_b64 = sign_message(priv, msg)
_ = verify_signature(pub, msg, sig_b64)

# AES
key = gen_sym_key()
enc = aes_encrypt(key, b"Confidential Industrial IoT Data")
_ = aes_decrypt(key, enc)

print("\n✅ STEP 1 complete.")
