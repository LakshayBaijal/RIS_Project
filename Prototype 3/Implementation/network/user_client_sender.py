import argparse, json, socket, base64
from utils.ecies import gen_ecc_keypair, privkey_to_pem, ecies_decrypt_with_privkey
from Crypto.Cipher import AES

def send_req(port, req):
    with socket.create_connection(("127.0.0.1", port)) as s:
        f = s.makefile("rwb")
        f.write((json.dumps(req) + "\n").encode())
        f.flush()
        line = f.readline()
        return json.loads(line.decode().strip())

def aes_encrypt(key: bytes, plaintext: str) -> dict:
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    enc = {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
        "tag": base64.b64encode(tag).decode()
    }

    print("\n==================== ENCRYPTION ====================")
    print(f"Plaintext: {plaintext}")
    print(f"AES Nonce (b64): {enc['nonce']}")
    print(f"AES Ciphertext (b64): {enc['ct']}")
    print(f"AES Tag (b64): {enc['tag']}")
    print("====================================================\n")
    return enc

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--channel", default="room1")
    args = ap.parse_args()

    user_id, channel = args.user, args.channel
    priv, pub_pem = gen_ecc_keypair()
    priv_pem = privkey_to_pem(priv)

    dept_pub = send_req(5001, {"op":"get_pubkey"})["pubkey_pem"]
    role_pub = send_req(5002, {"op":"get_pubkey"})["pubkey_pem"]
    dept_cert = send_req(5001, {"op":"request_cert","user_id":user_id,"attribute":"dept:power"})["cert"]
    role_cert = send_req(5002, {"op":"request_cert","user_id":user_id,"attribute":"role:engineer"})["cert"]

    join_req = {
        "op":"join_channel",
        "user_id":user_id,
        "channel":channel,
        "pubkeys":{"dept":dept_pub,"role":role_pub},
        "certs":{"dept":dept_cert,"role":role_cert},
        "user_pub":pub_pem
    }
    join_resp = send_req(6001, join_req)
    session_key = ecies_decrypt_with_privkey(priv_pem, join_resp["session_key_enc"])
    print(f"[{user_id}] Joined channel '{channel}'")
    print(f"Session Key (b64): {base64.b64encode(session_key).decode()}")

    print(f"\n[{user_id}] Ready to send messages. Type 'exit' to quit.\n")
    while True:
        msg = input("> ").strip()
        if msg.lower() == "exit": break
        enc = aes_encrypt(session_key, msg)
        send_req(6001, {"op":"post","user_id":user_id,"channel":channel,"msg_enc":enc,"sender":user_id})

if __name__ == "__main__":
    main()
