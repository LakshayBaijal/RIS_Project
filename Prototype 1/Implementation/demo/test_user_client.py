import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from authority.authority_server import Authority
from user.user_client import UserClient

# Step 1: Create authority and user
auth1 = Authority("DeptAuthority")
user = UserClient("user123")

# Step 2: User requests attributes from authority
user.request_attribute(auth1, "dept:power")
user.request_attribute(auth1, "role:engineer")

# Step 3: List stored attributes
print("\n[+] Attributes currently stored for user:")
print(user.list_attributes())

# Step 4: Export user keys and attribute certificates
keys = user.export_keys()
print("\n[+] Exported user public key snippet:")
print(keys["public_key"][:100], "...")

print("\n[+] Full attribute certificate store:")
print(user.export_attributes())
