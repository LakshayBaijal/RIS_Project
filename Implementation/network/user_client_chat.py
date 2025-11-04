import argparse, json, socket, threading, time, base64
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

def fetch_loop(user_id, channel, session_key):
    last = -1
    while True:
        try:
            resp = send_req(6001, {"op": "fetch", "user_id": user_id, "channel": channel, "last_index": last})
            msgs = resp.get("messages", [])
            if msgs:
                for m in msgs:
                    try:
                        plain = aes_decrypt(session_key, m)
                        print(f"\n💬 [{m['sender']}] {plain}")
                    except Exception as e:
                        print(f"\n⚠️  Decryption error: {e}")
                last += len(msgs)
                print("> ", end="", flush=True)
        except Exception as e:
            print(f"\n⚠️  Fetch error: {e}")
        time.sleep(2)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--channel", default="room1")
    args = ap.parse_args()
    user_id, channel = args.user, args.channel

    # ECC Key Pair
    priv, pub_pem = gen_ecc_keypair()
    priv_pem = privkey_to_pem(priv)
    print(f"[{user_id}] ECC Key Pair Generated ✅")
    print(f"Public Key (PEM):\n{pub_pem}")
    print("----------------------------------------------------\n")

    # Authorities
    dept_pub = send_req(5001, {"op": "get_pubkey"})["pubkey_pem"]
    role_pub = send_req(5002, {"op": "get_pubkey"})["pubkey_pem"]

    dept_cert = send_req(5001, {"op": "request_cert", "user_id": user_id, "attribute": "dept:power"})["cert"]
    if user_id.lower().endswith(("a","1")):
        role_cert = send_req(5002, {"op": "request_cert", "user_id": user_id, "attribute": "role:engineer"})["cert"]
    else:
        role_cert = {"payload": {"user_id": user_id, "attribute": "none", "issued_by": "none"}, "signature": "00"}

    print(f"[{user_id}] Received Certificates:")
    print(json.dumps({"dept": dept_cert, "role": role_cert}, indent=2))
    print("----------------------------------------------------\n")

    # Join Cloud Channel
    join_req = {
        "op": "join_channel",
        "user_id": user_id,
        "channel": channel,
        "pubkeys": {"dept": dept_pub, "role": role_pub},
        "certs": {"dept": dept_cert, "role": role_cert},
        "user_pub": pub_pem
    }
    join_resp = send_req(6001, join_req)
    if join_resp.get("status") != "granted":
        print(f"[{user_id}] ❌ Access denied: {join_resp.get('msg')}")
        return

    env = join_resp["session_key_enc"]
    session_key = ecies_decrypt_with_privkey(priv_pem, env)
    print(f"[{user_id}] ✅ Joined channel '{channel}'")
    print(f"Session Key (b64): {base64.b64encode(session_key).decode()}")
    print("----------------------------------------------------\n")

    threading.Thread(target=fetch_loop, args=(user_id, channel, session_key), daemon=True).start()

    print(f"[{user_id}] Connected to secure chat. Type 'exit' to leave.\n")

    while True:
        msg = input("> ").strip()
        if not msg:
            continue
        if msg.lower() == "exit":
            print(f"[{user_id}] Left chat.")
            break

        enc = aes_encrypt(session_key, msg)
        send_req(6001, {"op": "post", "user_id": user_id, "channel": channel, "msg_enc": enc, "sender": user_id})

if __name__ == "__main__":
    main()
