from utils.ecc_util import generate_ecc_keypair, sign_message, verify_signature

# Step 1: Generate keypair
priv, pub = generate_ecc_keypair()
print("[+] ECC keypair generated")

# Step 2: Sign and verify message
msg = b"Industrial IoT Secure Test"
sig = sign_message(priv, msg)
valid = verify_signature(pub, msg, sig)

print("[+] Signature verified:", valid)
