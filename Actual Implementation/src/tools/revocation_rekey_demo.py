# src/tools/revocation_rekey_demo.py
"""
Revocation + simple rekey simulation demo.

Usage (examples):
  # 1) Mark user as revoked for a CT and show EA refuses transform:
  python -m src.tools.revocation_rekey_demo \
    --ct out_hier_ct/ct_hier_stripped.json \
    --vault server_vault/vault_hier.json \
    --uid user123@example.com \
    --attrs SA_Finance.attrA,SA_IT.attrC,SA_Finance.attrB

  # 2) Same as above but also perform rekey (admin re-encrypts CT with a fresh secret)
  python -m src.tools.revocation_rekey_demo \
    --ct out_hier_ct/ct_hier_stripped.json \
    --vault server_vault/vault_hier.json \
    --uid user123@example.com \
    --attrs SA_Finance.attrA,SA_IT.attrC,SA_Finance.attrB \
    --rekey

Notes:
 - This demo keeps a per-vault revocation list file: server_vault/revocation.json
 - Rekey is demonstrated as an admin operation that has access to the vault (for the demo only).
 - Rekey replaces vault shares for the given ct_id and updates the stripped CT's AES ciphertext and P_bytes.
"""

import argparse, json, time, uuid
from pathlib import Path
from pprint import pprint

from src.lsss.shamir import reconstruct_secret, split_secret
from src.crypto.ecc import scalar_mul, point_to_bytes
from src.crypto.sym import derive_key_from_point, aes_decrypt, aes_encrypt
from src.crypto.ecc import point_to_bytes, bytes_to_point
from src.crypto.ecc import curve as ec_curve  # just for order if needed

def load_json(p: Path):
    with open(p, "r") as f:
        return json.load(f)

def save_json(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(obj, f, indent=2)

def add_revocation(vault_path: Path, ct_id: str, uid: str):
    rev_path = vault_path.parent / "revocation.json"
    if rev_path.exists():
        rev = load_json(rev_path)
    else:
        rev = {}
    lst = rev.get(ct_id, [])
    if uid not in lst:
        lst.append(uid)
    rev[ct_id] = lst
    save_json(rev_path, rev)
    return rev_path, rev

def is_revoked(vault_path: Path, ct_id: str, uid: str):
    rev_path = vault_path.parent / "revocation.json"
    if not rev_path.exists():
        return False
    rev = load_json(rev_path)
    lst = rev.get(ct_id, [])
    return uid in lst

def ea_pretransform_with_revocation(ct_path: Path, vault_path: Path, uid: str, attrs_list: list, registry_path: Path, out_path: Path):
    """
    EA transform logic similar to pretransform_elgamal but checks revocation list first.
    For demo we will compute and return the same ElGamal transform token (C1/C2).
    """
    start = time.time()

    ct = load_json(ct_path)
    ct_id = ct.get("ct_id")
    meta = ct.get("meta", {})
    threshold = meta.get("threshold")
    attrs_required = meta.get("attributes_ordered", [])

    if is_revoked(vault_path, ct_id, uid):
        return False, f"UID {uid} is revoked for ct_id {ct_id} — EA refuses transform."

    # load vault shares
    vault = load_json(vault_path)
    entry = vault.get(ct_id)
    if not entry:
        return False, f"No vault entry for ct_id {ct_id}"

    shares_map = entry.get("shares", {})

    # collect usable shares according to user attrs
    usable = []
    for attr in attrs_required:
        if attr in attrs_list and attr in shares_map:
            info = shares_map[attr]
            usable.append((int(info["index"]), int(info["share_hex"], 16)))
    if len(usable) < threshold:
        return False, f"Not enough authorized attributes ({len(usable)}) to meet threshold {threshold}"

    usable = usable[:threshold]

    # reconstruct s
    s_rec = reconstruct_secret(usable)
    P_s = scalar_mul(s_rec)

    # Load user public (not used for this revocation check demo; we'll create a simple transform token)
    # For privacy-preserving transform we would proceed as in pretransform_elgamal (ElGamal).
    # For simplicity we return the AES key here if not privacy-preserving, but we will instead perform ElGamal-like transform.
    # We'll reuse pretransform logic: sample r, compute C1 = rG, C2 = P_s + r*D_pub (requires registry)
    reg = load_json(registry_path)
    D_pub_b64 = None
    if reg.get("uid") == uid and "D_pub_b64" in reg:
        D_pub_b64 = reg["D_pub_b64"]
    elif isinstance(reg, dict) and uid in reg:
        D_pub_b64 = reg[uid].get("D_pub_b64")
    if not D_pub_b64:
        return False, f"No public key for uid={uid} in registry"

    D_pub = bytes_to_point(bytes(bytearray.fromhex(D_pub_b64) if all(c in "0123456789abcdefABCDEF" for c in D_pub_b64) else bytes())) if False else None
    # Note: We cannot reliably decode hex/base64 in a single line; simply import bytes_to_point via base64 as used by other scripts.
    import base64
    D_pub = bytes_to_point(base64.b64decode(D_pub_b64))

    # sample r and compute C1, C2
    from ecpy.curves import Curve
    curve = Curve.get_curve('secp256r1')
    r = int.from_bytes(uuid.uuid4().bytes, 'big') % curve.order
    C1 = scalar_mul(r)
    rD = scalar_mul(r, D_pub)
    C2 = point_add(P_s, rD) if 'point_add' in globals() else None
    # we can't rely on point_add being in globals; import it
    from src.crypto.ecc import point_add
    C2 = point_add(P_s, rD)

    token = {
        "ct_id": ct_id,
        "uid": uid,
        "C1_b64": base64.b64encode(point_to_bytes(C1)).decode(),
        "C2_b64": base64.b64encode(point_to_bytes(C2)).decode()
    }
    save_json(out_path, token)
    elapsed = time.time() - start
    return True, {"msg": "EA transform OK", "token": str(out_path), "time": elapsed}

def admin_rekey(ct_path: Path, vault_path: Path, threshold: int, new_threshold: int = None):
    """
    Admin rekey: admin reconstructs plaintext using vault (admin-privileged),
    generates a fresh s', re-encrypts the plaintext and writes updated CT and vault shares.

    Returns (new_ct_path, time_taken)
    """
    t0 = time.time()
    ct = load_json(ct_path)
    ct_id = ct.get("ct_id")
    vault = load_json(vault_path)
    entry = vault.get(ct_id)
    if entry is None:
        raise RuntimeError("No vault entry for ct_id")

    # Reconstruct secret s using ALL shares stored (admin assumed privileged)
    shares_map = entry["shares"]
    all_shares = []
    for attr, info in shares_map.items():
        all_shares.append((int(info["index"]), int(info["share_hex"], 16)))
    # if fewer than threshold, can't reconstruct
    threshold_current = ct["meta"]["threshold"]
    if len(all_shares) < threshold_current:
        raise RuntimeError("Not enough shares in vault to reconstruct original secret for admin rekey")

    s_old = reconstruct_secret(all_shares[:threshold_current])
    P_old = scalar_mul(s_old)
    key_old = derive_key_from_point(point_to_bytes(P_old))
    # decrypt plaintext
    aes = ct["aes"]
    plaintext = aes_decrypt(key_old, aes["nonce_b64"], aes["ct_b64"])

    # create new s' and encrypt
    curve = ec_curve
    s_new = int.from_bytes(uuid.uuid4().bytes, 'big') % curve.order
    P_new = scalar_mul(s_new)
    new_key = derive_key_from_point(point_to_bytes(P_new))
    new_aes = aes_encrypt(new_key, plaintext)

    # split new secret into shares matching existing attrs ordering
    attrs_ordered = ct["meta"]["attributes_ordered"]
    n = len(attrs_ordered)
    t = threshold if new_threshold is None else new_threshold
    new_shares = split_secret(s_new, n, t)

    # update vault entry with new shares
    new_map = {}
    for (idx, share_val), attr in zip(new_shares, attrs_ordered):
        owner = entry["shares"][attr]["owner"] if attr in entry["shares"] else None
        new_map[attr] = {"owner": owner, "index": idx, "share_hex": hex(share_val)}
    entry["shares"] = new_map
    # update vault and stripped ct (we'll update aes and P_bytes too)
    vault[ct_id] = entry
    save_json(vault_path, vault)

    # update stripped CT: replace aes and P_bytes
    ct["P_bytes_b64"] = base64.b64encode(point_to_bytes(P_new)).decode()
    ct["aes"] = new_aes
    ct["meta"]["rekeyed_at"] = time.time()
    save_json(ct_path, ct)

    t1 = time.time()
    return True, t1 - t0

# ---- CLI ----
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ct", required=True, help="Path to stripped CT (ct with ct_id but no shares)")
    ap.add_argument("--vault", required=True, help="Path to vault JSON")
    ap.add_argument("--uid", required=True, help="UID to revoke")
    ap.add_argument("--attrs", required=True, help="Comma-separated attrs EA sees for the UID")
    ap.add_argument("--registry", default="edge_registry/user_pub.json", help="User pub registry path")
    ap.add_argument("--out-transform", default="out_hier_ct/transform_revoked.json", help="EA transform output path (if allowed)")
    ap.add_argument("--rekey", action="store_true", help="If set, admin rekeys the CT (re-encrypt & replace shares)")
    args = ap.parse_args()

    ct_path = Path(args.ct)
    vault_path = Path(args.vault)
    uid = args.uid
    attrs_list = [a.strip() for a in args.attrs.split(",") if a.strip()]
    registry_path = Path(args.registry)
    out_transform = Path(args.out_transform)

    # 1) Add revocation
    ct = load_json(ct_path)
    ct_id = ct.get("ct_id")
    rev_path, rev = add_revocation(vault_path, ct_id, uid)
    print("✅ Added revocation entry:")
    print("  revocation file:", rev_path)
    print("  current revocation list for ct:", rev.get(ct_id))

    # 2) EA attempts transform (should be refused for revoked UID)
    ok, res = ea_pretransform_with_revocation(ct_path, vault_path, uid, attrs_list, registry_path, out_transform)
    if not ok:
        print("EA transform refused (expected for revoked uid):", res)
    else:
        print("Unexpected: EA produced token for revoked UID:", res)

    # 3) Show transform for a non-revoked UID (simulate another user)
    nonrev_uid = "nonrevoked@example.com"
    # ensure registry has a public key for nonrev_uid ; create one temporarily if needed
    regp = Path(registry_path)
    reg = load_json(regp) if regp.exists() else {}
    if not (reg.get("uid") == nonrev_uid or (isinstance(reg, dict) and nonrev_uid in reg)):
        # create one
        from src.user.user import User
        u2 = User(nonrev_uid)
        from src.crypto.ecc import point_to_bytes
        import base64
        pub_b64 = base64.b64encode(point_to_bytes(scalar_mul(u2.get_USK()))).decode()
        reg_entry = {"uid": nonrev_uid, "D_pub_b64": pub_b64}
        Path(regp).write_text(json.dumps(reg_entry, indent=2))
        print("Wrote demo registry entry for non-revoked uid:", nonrev_uid)

    ok2, res2 = ea_pretransform_with_revocation(ct_path, vault_path, nonrev_uid, attrs_list, registry_path, out_transform)
    if ok2:
        print("EA transform for non-revoked user OK:", res2)
    else:
        print("EA transform for non-revoked user failed (unexpected):", res2)

    # 4) Optional: admin rekey
    if args.rekey:
        print("\n--- ADMIN REKEY OPERATION (this may take a moment) ---")
        try:
            ok3, tcost = admin_rekey(ct_path, vault_path, threshold=ct["meta"]["threshold"])
            print(f"Admin rekey completed in {tcost:.4f}s. Vault and stripped CT updated.")
        except Exception as e:
            print("Admin rekey failed:", e)
            raise

    # 5) After rekey, verify revoked uid still refused, nonrevoked still allowed
    print("\n--- Post-rekey checks (if rekey performed) ---")
    if args.rekey:
        ok4, res4 = ea_pretransform_with_revocation(ct_path, vault_path, uid, attrs_list, registry_path, out_transform)
        print("Revoked UID transform attempt after rekey:", ("REFUSED" if not ok4 else "ALLOWED (unexpected)"), res4)
        ok5, res5 = ea_pretransform_with_revocation(ct_path, vault_path, nonrev_uid, attrs_list, registry_path, out_transform)
        print("Non-revoked UID transform attempt after rekey:", ("ALLOWED" if ok5 else "REFUSED (unexpected)"), res5)

    print("\nDone. Revocation + (optional) rekey demo complete.")
