import socket, json

def send_req(port, req):
    with socket.create_connection(("127.0.0.1", port)) as s:
        f = s.makefile("rwb")
        f.write((json.dumps(req) + "\n").encode()); f.flush()
        line = f.readline()
        return json.loads(line.decode().strip())

dept_pub = send_req(5001, {"op": "get_pubkey"})["pubkey_pem"]
role_pub = send_req(5002, {"op": "get_pubkey"})["pubkey_pem"]

dept_cert = send_req(5001, {"op": "request_cert", "user_id": "userA", "attribute": "dept:power"})["cert"]
role_cert = send_req(5002, {"op": "request_cert", "user_id": "userA", "attribute": "role:engineer"})["cert"]

req = {
    "op": "access_request",
    "certs": {"dept": dept_cert, "role": role_cert},
    "pubkeys": {"dept": dept_pub, "role": role_pub}
}

print("→ Sending access request to Cloud with both certificates...")
resp = send_req(6000, req)
print(json.dumps(resp, indent=2))
