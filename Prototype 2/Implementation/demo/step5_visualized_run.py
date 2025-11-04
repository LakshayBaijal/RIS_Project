import os, json, datetime
from termcolor import colored
from authority.authority_server import Authority
from user.user_client import User
from cloud.cloud_server import CloudServer

LOG_PATH = "logs/demo_run.txt"
os.makedirs("logs", exist_ok=True)

def log(msg):
    """Append message to log file."""
    with open(LOG_PATH, "a") as f:
        f.write(msg + "\n")

def banner(title):
    line = "─" * 60
    text = f"\n{line}\n{title}\n{line}"
    print(colored(text, "cyan"))
    log(text)

def highlight(label, msg, color="yellow"):
    text = f"[{label}] {msg}"
    print(colored(text, color))
    log(text)

# clear old logs
open(LOG_PATH, "w").close()

# ──────────────────────────────────────────────
banner("STEP 5 • Visualization & Logging Demo (Multi-Authority)")
# ──────────────────────────────────────────────

# 1️⃣ initialize authorities
dept_auth = Authority("DeptAuthority")
role_auth = Authority("RoleAuthority")

# 2️⃣ initialize user
user = User("userX")

highlight("AUTH", "Both authorities generated ECC key pairs ✅", "green")

# 3️⃣ issue certs from both authorities
cert1 = dept_auth.issue_attribute("userX", "dept:power")
user.receive_attribute(cert1, dept_auth)

cert2 = role_auth.issue_attribute("userX", "role:engineer")
user.receive_attribute(cert2, role_auth)

highlight("USER", "User now holds 2 verified certs ✅", "green")

# 4️⃣ build authority registry
authority_pubkeys = {
    "DeptAuthority": dept_auth.public_key,
    "RoleAuthority": role_auth.public_key,
}

# 5️⃣ initialize cloud
cloud = CloudServer(["dept:power", "role:engineer"])

# 6️⃣ perform access check
highlight("CLOUD", "Performing attribute verification...", "cyan")
result = cloud.grant_access([cert1, cert2], authority_pubkeys)

# 7️⃣ summary visualization
banner("FINAL SUMMARY")
summary = {
    "Authorities": list(authority_pubkeys.keys()),
    "User ID": user.user_id,
    "Attributes Verified": ["dept:power", "role:engineer"],
    "Access Result": "✅ Granted" if result else "❌ Denied",
    "Plaintext": result,
    "Timestamp": str(datetime.datetime.now())
}
pretty = json.dumps(summary, indent=2)
print(colored(pretty, "yellow"))
log(pretty)

highlight("REPORT", f"Full log saved to: {LOG_PATH}", "cyan")

print(colored("\n✅ STEP 5 completed successfully!", "green"))
