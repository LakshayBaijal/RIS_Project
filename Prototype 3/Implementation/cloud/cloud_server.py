import socket, threading, json, base64
from termcolor import colored
from authority.authority_server import Authority
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

HOST = "127.0.0.1"
PORT = 6000

def verify_cert(cert, pubkey_pem):
    payload = json.dumps(cert["payload"]).encode()
    raw = base64.b16decode(cert["signature"].encode())
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    sig = utils.encode_dss_signature(r, s)
    pubkey = serialization.load_pem_public_key(pubkey_pem.encode())

    try:
        pubkey.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

class CloudServer:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        print(colored(f"[Cloud] Server started on {self.host}:{self.port}", "cyan"))
        print(colored("[Cloud] Access policy: (dept:power AND role:engineer)\n", "cyan"))

    def handle_client(self, conn, addr):
        try:
            f = conn.makefile("rwb")
            line = f.readline()
            if not line:
                return
            req = json.loads(line.decode().strip())
            op = req.get("op")

            if op == "access_request":
                certs = req.get("certs", {})
                pubkeys = req.get("pubkeys", {})

                dept_cert = certs.get("dept")
                role_cert = certs.get("role")

                dept_pub = pubkeys.get("dept")
                role_pub = pubkeys.get("role")

                dept_ok = verify_cert(dept_cert, dept_pub)
                role_ok = verify_cert(role_cert, role_pub)

                print(f"[Cloud] Dept Cert Verification: {dept_ok}")
                print(f"[Cloud] Role Cert Verification: {role_ok}")

                if dept_ok and role_ok:
                    resp = {
                        "status": "granted",
                        "data": "Confidential Energy Grid Data: Node voltage = 220V, Load = 90%."
                    }
                    print(colored(f"[Cloud] ✅ Access Granted to {dept_cert['payload']['user_id']}\n", "green"))
                else:
                    resp = {"status": "denied", "msg": "Access denied — certificate verification failed."}
                    print(colored(f"[Cloud] ❌ Access Denied for {addr}\n", "red"))

                f.write((json.dumps(resp) + "\n").encode())
                f.flush()

        except Exception as e:
            conn.sendall(json.dumps({"status": "error", "msg": str(e)}).encode() + b"\n")
        finally:
            conn.close()

    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)
            print(colored("[Cloud] Awaiting connections...\n", "cyan"))
            while True:
                conn, addr = s.accept()
                t = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                t.start()

if __name__ == "__main__":
    CloudServer().serve_forever()
