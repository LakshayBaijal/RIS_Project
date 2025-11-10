# src/edge/pretransform_elgamal.py
"""
EA partial transform (privacy-preserving):
- Inputs:
    --ct       : stripped CT (contains ct_id, AES fields, meta)
    --vault    : server-side vault.json with shares
    --uid      : user identifier
    --attrs    : comma-separated attributes EA believes user has (simulated authorization)
    --registry : JSON mapping uid -> user public key (D_pub) as base64-encoded point bytes
    --out      : output transform token JSON (C1, C2) that user will finish locally
- Behavior:
    1) Check threshold using user attrs.
    2) Reconstruct s from vault shares.
    3) Load user public D_pub from registry.
    4) Sample random r; compute:
          C1 = r·G
          C2 = (s·G) + r·D_pub
    5) Output token { ct_id, uid, C1_b64, C2_b64 }
- EA does NOT learn the AES key or plaintext; only user can complete using d.

Usage:
  python -m src.edge.pretransform_elgamal \
    --ct out_multi_ct/ct_multi_stripped.json \
    --vault server_vault/vault.json \
    --uid user123@example.com \
    --attrs attrA,attrC,attrB \
    --registry edge_registry/user_pub.json \
    --out out_multi_ct/transform_token.json
"""

import json, base64, argparse, os, random
from pathlib import Path

from ecpy.curves import Curve
from src.lsss.shamir import reconstruct_secret
from src.crypto.ecc import (
    scalar_mul, point_add, point_to_bytes, bytes_to_point, G, n
)

def load_json(p: Path):
    with open(p, "r") as f:
        return json.load(f)

def save_json(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(obj, f, indent=2)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ct", required=True)
    ap.add_argument("--vault", required=True)
    ap.add_argument("--uid", required=True)
    ap.add_argument("--attrs", required=True, help="Comma-separated user attributes")
    ap.add_argument("--registry", required=True, help="JSON file: {'uid': '...', 'D_pub_b64': '...'} OR dict of many users")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    ct = load_json(Path(args.ct))
    if "ct_id" not in ct or "meta" not in ct:
        print("[!] Stripped CT missing ct_id/meta.")
        return
    ct_id = ct["ct_id"]
    meta = ct["meta"]
    attrs_required = meta.get("attributes_ordered", [])
    threshold = meta.get("threshold")
    if not attrs_required or threshold is None:
        print("[!] CT meta incomplete.")
        return

    vault = load_json(Path(args.vault))
    entry = vault.get(ct_id)
    if not entry or "shares" not in entry:
        print(f"[!] Vault has no shares for ct_id={ct_id}.")
        return
    shares_map = entry["shares"]

    # Load registry: can be a single-user file or a multi-user dict
    reg = load_json(Path(args.registry))
    D_pub_b64 = None
    if "D_pub_b64" in reg and reg.get("uid") == args.uid:
        D_pub_b64 = reg["D_pub_b64"]
    elif isinstance(reg, dict) and args.uid in reg:
        D_pub_b64 = reg[args.uid].get("D_pub_b64")
    if not D_pub_b64:
        print(f"[!] No public key for uid={args.uid} in registry.")
        return
    D_pub = bytes_to_point(base64.b64decode(D_pub_b64))

    # Attributes EA sees for this user (simulating TSK check)
    user_attrs = [a.strip() for a in args.attrs.split(",") if a.strip()]
    print(f"[*] EA transform for UID={args.uid}")
    print(f"    User attrs: {user_attrs}")
    print(f"    Policy    : {attrs_required} (threshold={threshold})")

    # Build usable shares
    usable = []
    for attr in attrs_required:
        if attr in user_attrs and attr in shares_map:
            info = shares_map[attr]
            idx = int(info["index"])
            val = int(info["share_hex"], 16)
            usable.append((idx, val))
    if len(usable) < threshold:
        print(f"[!] Not enough authorized attributes ({len(usable)}) to meet threshold {threshold}.")
        return

    usable = usable[:threshold]

    # Reconstruct s and compute s·G
    curve = Curve.get_curve('secp256r1')
    s = reconstruct_secret(usable)
    P_s = scalar_mul(s)  # s·G

    # Sample random r and compute C1 = r·G, C2 = s·G + r·D_pub
    r = random.randrange(1, curve.order)
    C1 = scalar_mul(r)           # r·G
    rD = scalar_mul(r, D_pub)    # r·D_pub
    C2 = point_add(P_s, rD)      # s·G + r·D_pub

    token = {
        "ct_id": ct_id,
        "uid": args.uid,
        "C1_b64": base64.b64encode(point_to_bytes(C1)).decode(),
        "C2_b64": base64.b64encode(point_to_bytes(C2)).decode()
    }
    save_json(Path(args.out), token)
    print("✅ EA partial transform complete (key hidden from EA).")
    print("  ct_id :", ct_id)
    print("  token :", args.out)
    print("  (User will compute s·G = C2 - d·C1, then H(s·G) to decrypt.)")

if __name__ == "__main__":
    main()
