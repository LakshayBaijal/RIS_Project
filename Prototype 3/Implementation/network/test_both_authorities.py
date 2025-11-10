import socket, json

def send_req(port, req):
    with socket.create_connection(("127.0.0.1", port)) as s:
        f = s.makefile("rwb")
        f.write((json.dumps(req) + "\n").encode()); f.flush()
        line = f.readline()
        return json.loads(line.decode().strip())

print("→ requesting DeptAuthority pubkey (port 5001)")
resp1 = send_req(5001, {"op":"get_pubkey"})
print("DeptAuthority:", resp1["issuer"])
print(resp1["pubkey_pem"][:100], "...\n")

print("→ requesting RoleAuthority pubkey (port 5002)")
resp2 = send_req(5002, {"op":"get_pubkey"})
print("RoleAuthority:", resp2["issuer"])
print(resp2["pubkey_pem"][:100], "...\n")

print("→ requesting certificates from both authorities for userA")
cert_dept = send_req(5001, {"op":"request_cert","user_id":"userA","attribute":"dept:power"})
cert_role = send_req(5002, {"op":"request_cert","user_id":"userA","attribute":"role:engineer"})

print("Dept cert:\n", json.dumps(cert_dept, indent=2)[:300], "...\n")
print("Role cert:\n", json.dumps(cert_role, indent=2)[:300], "...\n")
