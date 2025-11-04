from authority.authority_server import Authority
from user.user_client import User

print("────────────────────────────────────────────")
print("STEP 2 • Authority → User Certificate Demo")
print("────────────────────────────────────────────")

# 1. setup
auth = Authority("DeptAuthority")
user = User("user123")

# 2. issue & verify attributes
cert1 = auth.issue_attribute("user123", "dept:power")
user.receive_attribute(cert1, auth)

cert2 = auth.issue_attribute("user123", "role:engineer")
user.receive_attribute(cert2, auth)

# 3. show all user attributes
user.show_attributes()

print("\n✅ STEP 2 complete.")
