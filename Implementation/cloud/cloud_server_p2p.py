import socket, threading, json, base64, os
from typing import Dict, List
from termcolor import colored
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from utils.ecies import ecies_encrypt_for_pubkey

HOST, PORT = "127.0.0.1", 6001

def verify_cert(cert, pubkey_pem):
    from cryptography.hazmat.primitives import serialization
    payload = json.dumps(cert["payload"]).encode()
    raw = base64.b16decode(cert["signature"].encode())
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    sig = utils.encode_dss_signature(r, s)
    pubkey = serialization.load_pem_public_key(pubkey_pem.encode())
    pubkey.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
    return True

class CloudP2PServer:
    """
    Ops:
      - join_channel: verify certs; generate channel key if absent; return ECIES-encrypted session key for user
        { op, user_id, channel, pubkeys:{dept,role}, certs:{dept,role}, user_pub }
        -> { status, channel, session_key_enc: {eph_pub,nonce,ct,tag} }

      - post: append encrypted message (already AES-GCM with channel key on client)
        { op, user_id, channel, msg_enc:{nonce,ct,tag}, sender }

      - fetch: return list of encrypted messages since index
        { op, user_id, channel, last_index } -> { status, from_index, messages:[{sender,nonce,ct,tag}] }
    """
    def __init__(self, host=HOST, port=PORT):
        self.host, self.port = host, port
        self.channels: Dict[str, Dict] = {}  
        print(colored(f"[Cloud:P2P] Listening on {self.host}:{self.port}", "cyan"))
        print(colored("[Cloud:P2P] Policy: dept:power AND role:engineer", "cyan"))

    def _ensure_channel(self, name: str):
        if name not in self.channels:
            self.channels[name] = {
                "key": os.urandom(32), 
                "members": set(),
                "messages": []
            }

    def _handle_join(self, req: dict):
        user_id = req["user_id"]
        channel = req["channel"]
        certs = req["certs"]; pubs = req["pubkeys"]
        user_pub = req["user_pub"]

        dept_ok = verify_cert(certs["dept"], pubs["dept"])
        role_ok = verify_cert(certs["role"], pubs["role"])
        if not (dept_ok and role_ok):
            return {"status": "denied", "msg": "cert verification failed"}

        self._ensure_channel(channel)
        self.channels[channel]["members"].add(user_id)
        session_key = self.channels[channel]["key"]

        env = ecies_encrypt_for_pubkey(user_pub, session_key)
        print(colored(f"[Cloud:P2P] ✅ {user_id} joined '{channel}'. Members={len(self.channels[channel]['members'])}", "green"))
        return {"status": "granted", "channel": channel, "session_key_enc": env}

    def _handle_post(self, req: dict):
        ch = req["channel"]
        self._ensure_channel(ch)
        entry = {
            "sender": req.get("sender", req["user_id"]),
            "nonce": req["msg_enc"]["nonce"],
            "ct": req["msg_enc"]["ct"],
            "tag": req["msg_enc"]["tag"]
        }
        self.channels[ch]["messages"].append(entry)
        print(colored(f"[Cloud:P2P] 📩 message in '{ch}' from {entry['sender']} (#{len(self.channels[ch]['messages'])-1})", "yellow"))
        return {"status": "ok", "index": len(self.channels[ch]["messages"]) - 1}

    def _handle_fetch(self, req: dict):
        ch = req["channel"]; last = int(req.get("last_index", -1))
        self._ensure_channel(ch)
        msgs = self.channels[ch]["messages"][last+1:]
        return {"status":"ok","from_index": last+1,"messages": msgs}

    def handle_client(self, conn, addr):
        try:
            f = conn.makefile("rwb")
            line = f.readline()
            if not line: return
            req = json.loads(line.decode().strip())
            op = req.get("op")

            if op == "join_channel":
                resp = self._handle_join(req)
            elif op == "post":
                resp = self._handle_post(req)
            elif op == "fetch":
                resp = self._handle_fetch(req)
            else:
                resp = {"status":"error","msg":"unknown op"}

            f.write((json.dumps(resp)+"\n").encode()); f.flush()
        except Exception as e:
            try:
                conn.sendall((json.dumps({"status":"error","msg":str(e)})+"\n").encode())
            except: pass
            print("[Cloud:P2P] Error:", e)
        finally:
            conn.close()

    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(20)
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    CloudP2PServer().serve_forever()
