import argparse, json, socket, time, base64, os
from utils.ecies import gen_ecc_keypair, privkey_to_pem, ecies_decrypt_with_privkey
from Crypto.Cipher import AES

def send_req(port, req):
    with socket.create_connection(("127.0.0.1", port)) as s:
        f = s.makefile("rwb")
        f.write((json.dumps(req) + "\n").encode()); f.flush()
        line = f.readline()
        return json.loads(line.decode().strip())

def aes_encrypt(key: bytes, plaintext: str) -> dict:
    pt = plaintext.encode()
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(pt)
    import base64
    return {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def aes_decrypt(key: bytes, enc: dict) -> str:
    import base64
    nonce = base64.b64decode(enc["nonce"])
    ct = base64.b64decode(enc["ct"])
    tag = base64.b64decode(enc["tag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt.decode()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True, help="user id")
    ap.add_argument("--channel", default="room1")
    args = ap.parse_args()

    user_id = args.user
    channel = args.channel

    priv, pub_pem = gen_ecc_keypair()
    priv_pem = privkey_to_pem(priv)
    print(f"[{user_id}] ECC keypair ready. Public key snippet:\n{pub_pem.splitlines()[1][:32]}...")

    dept_pub = send_req(5001, {"op": "get_pubkey"})["pubkey_pem"]
    role_pub = send_req(5002, {"op": "get_pubkey"})["pubkey_pem"]

    dept_cert = send_req(5001, {"op":"request_cert","user_id":user_id,"attribute":"dept:power"})["cert"]
    if user_id.lower().endswith(("a","1")):
        role_cert = send_req(5002, {"op":"request_cert","user_id":user_id,"attribute":"role:engineer"})["cert"]
    else:
        role_cert = {"payload":{"user_id":user_id,"attribute":"none","issued_by":"none"},"signature":"00"}

    join_req = {
        "op":"join_channel",
        "user_id": user_id,
        "channel": channel,
        "pubkeys":{"dept": dept_pub, "role": role_pub},
        "certs":{"dept": dept_cert, "role": role_cert},
        "user_pub": pub_pem
    }
    join_resp = send_req(6001, join_req)
    print(f"[{user_id}] Join response:", join_resp.get("status"))

    if join_resp.get("status") != "granted":
        print(f"[{user_id}] Access denied. Reason:", join_resp.get("msg"))
        return

    env = join_resp["session_key_enc"]
    session_key = ecies_decrypt_with_privkey(priv_pem, env)
    print(f"[{user_id}] 🔑 Channel session key (b64): {base64.b64encode(session_key).decode()[:24]}...")

    msg_text = f"hello from {user_id}"
    enc = aes_encrypt(session_key, msg_text)
    post_resp = send_req(6001, {"op":"post","user_id":user_id,"channel":channel,"msg_enc":enc,"sender":user_id})
    idx = post_resp.get("index", -1)
    print(f"[{user_id}] Posted message index #{idx}")

    fetch = send_req(6001, {"op":"fetch","user_id":user_id,"channel":channel,"last_index":-1})
    print(f"[{user_id}] fetch count:", len(fetch.get("messages", [])))
    for i, m in enumerate(fetch["messages"]):
        try:
            plain = aes_decrypt(session_key, m)
            print(f"[{user_id}] #{i} {m['sender']}: {plain}")
        except Exception as e:
            print(f"[{user_id}] #{i} decryption failed:", e)

if __name__ == "__main__":
    main()
