from authority.authority_server import Authority
from user.user_client import User
from cloud.cloud_server import CloudServer

print("────────────────────────────────────────────")
print("STEP 4 • Multi-Authority Access Control Demo")
print("────────────────────────────────────────────")

# 1️⃣ initialize two independent authorities
dept_auth = Authority("DeptAuthority")
role_auth = Authority("RoleAuthority")

# 2️⃣ user setup
user = User("user007")

# 3️⃣ each authority issues their own attribute
cert_dept = dept_auth.issue_attribute("user007", "dept:power")
user.receive_attribute(cert_dept, dept_auth)

cert_role = role_auth.issue_attribute("user007", "role:engineer")
user.receive_attribute(cert_role, role_auth)

# 4️⃣ prepare certs and authority key registry
user_certs = [cert_dept, cert_role]
authority_pubkeys = {
    "DeptAuthority": dept_auth.public_key,
    "RoleAuthority": role_auth.public_key
}

# 5️⃣ cloud server policy requiring both attributes
cloud = CloudServer(["dept:power", "role:engineer"])

# 6️⃣ verify and grant access
result = cloud.grant_access(user_certs, authority_pubkeys)

print("\n[Result] Cloud Response:", result if result else "ACCESS DENIED")
print("\n✅ STEP 4 complete.")
