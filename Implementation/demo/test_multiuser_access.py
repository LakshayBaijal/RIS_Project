import threading, json, socket, time

def send_req(port, req):
    with socket.create_connection(("127.0.0.1", port)) as s:
        f = s.makefile("rwb")
        f.write((json.dumps(req) + "\n").encode()); f.flush()
        line = f.readline()
        return json.loads(line.decode().strip())

def user_flow(user_id, role_needed=True):
    dept_pub = send_req(5001, {"op": "get_pubkey"})["pubkey_pem"]
    role_pub = send_req(5002, {"op": "get_pubkey"})["pubkey_pem"]

    dept_cert = send_req(5001, {"op": "request_cert", "user_id": user_id, "attribute": "dept:power"})["cert"]

    if role_needed:
        role_cert = send_req(5002, {"op": "request_cert", "user_id": user_id, "attribute": "role:engineer"})["cert"]
    else:
        role_cert = {"payload": {"user_id": user_id, "attribute": "none", "issued_by": "none"}, "signature": "00"}

    req = {
        "op": "access_request",
        "certs": {"dept": dept_cert, "role": role_cert},
        "pubkeys": {"dept": dept_pub, "role": role_pub}
    }

    resp = send_req(6000, req)
    print(f"\n[{user_id}] → Response from Cloud:\n", json.dumps(resp, indent=2))

if __name__ == "__main__":
    t1 = threading.Thread(target=user_flow, args=("userA", True))
    t2 = threading.Thread(target=user_flow, args=("userB", False))

    t1.start(); time.sleep(1)
    t2.start()

    t1.join(); t2.join()