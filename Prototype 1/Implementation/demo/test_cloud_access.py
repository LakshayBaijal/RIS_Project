import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from authority.authority_server import Authority
from user.user_client import UserClient
from cloud.cloud_server import CloudServer

# Step 1: Setup Authority and User
auth = Authority("DeptAuthority")
user = UserClient("user123")

# Step 2: Authority issues and user collects attributes
user.request_attribute(auth, "dept:power")
user.request_attribute(auth, "role:engineer")

# Step 3: Cloud requires both attributes
cloud = CloudServer(["dept:power", "role:engineer"])

# Step 4: Cloud verifies user's signed attributes
pubkeys = {"DeptAuthority": auth.public_key}
access = cloud.grant_access(user.attributes, pubkeys)

print("\n[Result] Access response:", access)
