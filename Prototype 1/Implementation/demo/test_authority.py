import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from authority.authority_server import Authority

# Step 1: Create Authority
auth = Authority("DeptAuthority")

# Step 2: Issue an attribute certificate
cert = auth.issue_attribute(user_id="user123", attribute="dept:power")

# Step 3: Verify it
is_valid = auth.verify_attribute(cert)

print("[+] Attribute Certificate Verified:", is_valid)
