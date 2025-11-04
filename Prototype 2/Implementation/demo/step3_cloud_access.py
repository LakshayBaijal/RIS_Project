from authority.authority_server import Authority
from user.user_client import User
from cloud.cloud_server import CloudServer

print("────────────────────────────────────────────")
print("STEP 3 • Cloud Access Control (ABE-style)")
print("────────────────────────────────────────────")

# 1) set up authority and user
auth = Authority("DeptAuthority")
user = User("user123")

# 2) issue certificates (keep the cert objects AND let user store attrs)
cert_power = auth.issue_attribute("user123", "dept:power")
user.receive_attribute(cert_power, auth)

cert_role = auth.issue_attribute("user123", "role:engineer")
user.receive_attribute(cert_role, auth)

user_certs = [cert_power, cert_role]           # what the cloud will verify
authority_pubkeys = {"DeptAuthority": auth.public_key}

# 3) cloud with policy → requires both attributes
cloud = CloudServer(["dept:power", "role:engineer"])

# 4) grant access (prints AES key, nonce, ciphertext, tag, and decrypted data)
result = cloud.grant_access(user_certs, authority_pubkeys)

print("\n[Result] Cloud response:", result if result else "ACCESS DENIED")
print("\n✅ STEP 3 complete.")
