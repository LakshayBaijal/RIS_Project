import socket, json

HOST, PORT = "127.0.0.1", 5001

def send_req(req: dict):
    with socket.create_connection((HOST, PORT)) as s:
        f = s.makefile("rwb")
        f.write((json.dumps(req) + "\n").encode()); f.flush()
        line = f.readline()
        return json.loads(line.decode().strip())

print("→ requesting DeptAuthority pubkey")
resp1 = send_req({"op":"get_pubkey"})
print(json.dumps(resp1, indent=2)[:600], "...\n")

print("→ requesting certificate for userA: 'dept:power'")
resp2 = send_req({"op":"request_cert","user_id":"userA","attribute":"dept:power"})
print(json.dumps(resp2, indent=2)[:600], "...\n")
