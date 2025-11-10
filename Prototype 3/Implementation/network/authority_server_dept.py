import socket, threading, json
from typing import Dict
from authority.authority_server import Authority
from cryptography.hazmat.primitives import serialization

HOST = "127.0.0.1"
PORT = 5001

def pubkey_to_pem(pubkey) -> str:
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

class DeptAuthorityServer:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.auth = Authority("DeptAuthority")
        self.pubkey_pem = pubkey_to_pem(self.auth.public_key)
        print(f"[DeptAuthority] Listening on {self.host}:{self.port} ...")
        print("[DeptAuthority] Available ops: get_pubkey, request_cert")

    def handle_client(self, conn: socket.socket, addr):
        try:
            f = conn.makefile("rwb")
            line = f.readline()
            if not line:
                return
            req = json.loads(line.decode().strip())
            op = req.get("op")

            if op == "get_pubkey":
                resp = {"status": "ok", "pubkey_pem": self.pubkey_pem, "issuer": "DeptAuthority"}
                f.write((json.dumps(resp) + "\n").encode()); f.flush()
                print(f"[DeptAuthority] Served get_pubkey to {addr}")

            elif op == "request_cert":
                user_id = req.get("user_id")
                attribute = req.get("attribute")  
                if not user_id or not attribute:
                    f.write(json.dumps({"status":"error","msg":"missing fields"}).encode()+b"\n"); f.flush()
                    return
                cert = self.auth.issue_attribute(user_id, attribute)
                resp = {"status":"ok","cert":cert}
                f.write((json.dumps(resp) + "\n").encode()); f.flush()
                print(f"[DeptAuthority] Issued '{attribute}' to {user_id} for {addr}")

            else:
                f.write(json.dumps({"status":"error","msg":"unknown op"}).encode()+b"\n"); f.flush()

        except Exception as e:
            try:
                conn.sendall((json.dumps({"status":"error","msg":str(e)})+"\n").encode())
            except: pass
            print("[DeptAuthority] Error handling client:", e)
        finally:
            conn.close()

    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)
            while True:
                conn, addr = s.accept()
                t = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                t.start()

if __name__ == "__main__":
    DeptAuthorityServer().serve_forever()
