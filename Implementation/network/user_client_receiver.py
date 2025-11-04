import argparse, json, socket, time, base64
from utils.ecies import gen_ecc_keypair, privkey_to_pem, ecies_decrypt_with_privkey
from Crypto.Cipher import AES

def send_req(port, req):
    with socket.create_connection(("127.0.0.1", port)) as s:
        f = s.makefile("rwb")
        f.write((json.dumps(req) + "\n").encode())
        f.flush()
        line = f.readline()
        return json.loads(line.decode().strip())

def aes_decrypt(key: bytes, enc: dict) -> str:
    nonce = base64.b64decode(enc["nonce"])
    ct = base64.b64decode(enc["ct"])
    tag = base64.b64decode(enc["tag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    text = pt.decode()
    print("\n==================== DECRYPTION ====================")
    print(f"AES Nonce (b64): {enc['nonce']}")
    print(f"AES Ciphertext (b64): {enc['ct']}")
    print(f"AES Tag (b64): {enc['tag']}")
    print(f"Recovered Plaintext: {text}")
    print("====================================================\n")
    return text

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
    print(f"[{user_id}] Receiver joined '{channel}'")
    print(f"Session Key (b64): {base64.b64encode(session_key).decode()}")

    last = -1
    while True:
        resp = send_req(6001, {"op": "fetch", "user_id": user_id, "channel": channel, "last_index": last})
        msgs = resp.get("messages", [])
        if msgs:
            for m in msgs:
                aes_decrypt(session_key, m)
            last += len(msgs)
        time.sleep(2)

if __name__ == "__main__":
    main()
