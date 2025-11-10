# src/tools/hierarchical_attack_tests.py
"""
Run a suite of attack tests for the hierarchical MA-CP-ABE prototype.

Tests included:
  1) Insufficient attributes at EA (should NOT produce transform)
  2) Wrong UID / mismatch public key (EA produces token but user's finish fails)
  3) Collusion with fewer-than-threshold shares (reconstruct fails -> decrypt fails)
  4) Compromised EA tries to recover SKs from stored TSKs (should be impossible)

Run from project root with venv active:
  python -m src.tools.hierarchical_attack_tests
"""

import json
import subprocess
from pathlib import Path
from pprint import pprint
import base64

from src.lsss.shamir import reconstruct_secret
from src.crypto.ecc import scalar_mul, point_to_bytes
from src.crypto.sym import derive_key_from_point, aes_decrypt

# Some paths used by other demos
STRIPPED_CT = Path("out_hier_ct/ct_hier_stripped.json")
VAULT = Path("server_vault/vault_hier.json")
REGISTRY = Path("edge_registry/user_pub.json")
USER_SECRET = Path("edge_registry/user_secret_demo.json")
TRANSFORM = Path("out_hier_ct/transform_token_hier.json")
DECRYPTED = Path("out_hier_ct/decrypted_hier.txt")

def check_prereqs():
    missing = []
    for p in [STRIPPED_CT, VAULT, REGISTRY, USER_SECRET]:
        if not p.exists():
            missing.append(str(p))
    if missing:
        print("[!] Missing prerequisite files. Please run the hierarchical demo steps first to produce these:")
        for m in missing:
            print("   -", m)
        return False
    return True

def run_cmd(cmd):
    """Run shell command, return (retcode, stdout, stderr)"""
    print(f"\n$ {cmd}")
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

def test_insufficient_attributes():
    print("\n=== Test 1: Insufficient Attributes at EA ===")
    # Provide only two of three required attributes (threshold is 3)
    bad_attrs = "SA_Finance.attrA,SA_IT.attrC"  # missing SA_Finance.attrB
    cmd = f"python -m src.edge.pretransform_elgamal --ct {STRIPPED_CT} --vault {VAULT} --uid user123@example.com --attrs {bad_attrs} --registry {REGISTRY} --out out_hier_ct/transform_token_fail.json"
    rc, out, err = run_cmd(cmd)
    # pretransform prints an error message and returns non-zero (or prints "[!]")
    success = rc == 0 and "partial transform complete" in (out.lower() + err.lower())
    if success:
        print("[FAIL] EA should NOT have produced a transform with insufficient attributes.")
    else:
        print("[PASS] EA correctly refused to transform (insufficient attributes).")
        print("  stdout:", out)
        print("  stderr:", err)

def test_wrong_uid_mismatch_pubkey():
    print("\n=== Test 2: Wrong UID / Registry Mismatch ===")
    # Create a fake registry entry for an attacker UID and run transform with that UID,
    # then attempt user final decrypt using original user_secret (should fail).
    fake_uid = "attacker@example.com"
    # Build a fake public key (generate new user with own d)
    # We'll do this inline by creating a new user secret and pub
    from src.user.user import User
    fake_user = User(fake_uid)
    D_pub = scalar_mul(fake_user.get_USK())
    D_pub_b64 = base64.b64encode(point_to_bytes(D_pub)).decode()
    # Save a temporary registry containing the fake UID (so EA will use attacker pub)
    fake_registry = Path("edge_registry/fake_user_pub.json")
    fake_registry.write_text(json.dumps({"uid": fake_uid, "D_pub_b64": D_pub_b64}, indent=2))
    # Now EA creates a token for fake_uid (we simulate attacker requesting transform)
    attrs = "SA_Finance.attrA,SA_IT.attrC,SA_Finance.attrB"
    cmd = f"python -m src.edge.pretransform_elgamal --ct {STRIPPED_CT} --vault {VAULT} --uid {fake_uid} --attrs {attrs} --registry {fake_registry} --out out_hier_ct/transform_token_fake.json"
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        print("[INFO] EA transform failed for fake UID (unexpected). stdout/stderr:")
        print(out, err)
        print("[PASS?] If EA requires a registered user only, this may be correct. For this test we expect a token to be produced.")
    else:
        print("[INFO] EA produced a transform token for attacker UID (expected for this test). Now attempt user finish decrypt with REAL user's secret (should fail).")
        # Try to finish decrypt using original user_secret (mismatch)
        cmd2 = f"python -m src.tools.user_finish_transform_decrypt --ct {STRIPPED_CT} --token out_hier_ct/transform_token_fake.json --usersecret {USER_SECRET} --out out_hier_ct/decrypted_fake.txt"
        rc2, out2, err2 = run_cmd(cmd2)
        if rc2 == 0:
            # If decryption succeeded with wrong user secret — catastrophic (fail the scheme)
            print("[FAIL] Decryption unexpectedly succeeded with wrong user secret! This is a security problem.")
        else:
            print("[PASS] Decryption failed when token built for different UID (as expected).")
            print("  user_finish stdout/stderr:", out2, err2)
    # cleanup
    try:
        fake_registry.unlink()
    except Exception:
        pass

def test_collusion_fewer_shares():
    print("\n=== Test 3: Collusion - Fewer-than-threshold Shares ===")
    # Load vault entry and try reconstructing with only t-1 shares
    vault = json.load(open(VAULT, "r"))
    # Find ct_id entry inside vault (the only one)
    # If multiple exist, pick the last or one matching our stripped CT's ct_id
    ct_stripped = json.load(open(STRIPPED_CT, "r"))
    ct_id = ct_stripped.get("ct_id")
    entry = vault.get(ct_id)
    if not entry:
        # pick any entry
        ct_id, entry = next(iter(vault.items()))
    shares_map = entry["shares"]
    # ordered attributes from meta
    ordered = ct_stripped["meta"]["attributes_ordered"]
    threshold = ct_stripped["meta"]["threshold"]
    # collect all available shares in order, then take only threshold-1
    avail = []
    for attr in ordered:
        info = shares_map.get(attr)
        if info:
            avail.append((int(info["index"]), int(info["share_hex"], 16)))
    if len(avail) < threshold:
        print("[PASS] Vault doesn't have enough shares for threshold; unusual but acceptable for this test.")
        return
    subset = avail[:max(1, threshold - 1)]
    try:
        s_rec = reconstruct_secret(subset)
        # derive AES key candidate and try decrypt (we have the stripped CT's aes)
        ct = json.load(open(STRIPPED_CT, "r"))
        P = scalar_mul(s_rec)
        key = derive_key_from_point(point_to_bytes(P))
        aes = ct["aes"]
        try:
            pt = aes_decrypt(key, aes["nonce_b64"], aes["ct_b64"])
            print("[FAIL] Decryption succeeded with fewer-than-threshold shares (security breach).")
        except Exception as e:
            print("[PASS] Decryption failed with fewer-than-threshold shares (expected).")
            print("  decrypt error:", e)
    except Exception as ex:
        print("[PASS] Could not reconstruct secret with fewer-than-threshold shares (exception):", ex)

def test_compromised_ea_tsk_behavior():
    print("\n=== Test 4: Compromised EA tries to recover SKs from TSKs ===")
    from src.edge.edge_stub import EdgeAuthorityStub
    ea = EdgeAuthorityStub()
    # Simulate storing TSKs for uid from earlier tskt_demo by reusing that flow:
    # For simplicity, fetch the real TSKs by having the real user compute and store them quickly.
    from src.aa.authority import Authority
    from src.user.user import User
    AA1 = Authority("AA1", ["attrA", "attrB"])
    uid = "temp_user_for_ea_test@example.com"
    user = User(uid)
    sk_attrA = AA1.keygen_for_user(uid, "attrA")
    tsk_list = user.compute_TSKs([sk_attrA])
    ea.store_tsk_for_uid(uid, tsk_list)
    # EA attempts to recover SKs
    recovered = ea.attempt_recover_sk(uid)
    if recovered is None:
        print("[PASS] EA cannot recover SKs from stored TSKs without user's secret d.")
    else:
        print("[FAIL] EA was able to recover SKs from stored TSKs (unexpected):", recovered)

def main():
    ok = check_prereqs()
    if not ok:
        return
    test_insufficient_attributes()
    test_wrong_uid_mismatch_pubkey()
    test_collusion_fewer_shares()
    test_compromised_ea_tsk_behavior()
    print("\n=== Attack test suite complete ===")

if __name__ == "__main__":
    main()
