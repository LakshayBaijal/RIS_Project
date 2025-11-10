# src/edge/predecrypt.py
"""
EA pre-decrypt script (demo):
- Reads stripped CT (no shares) and server-side vault (with shares).
- Verifies that the user has enough attributes (simulated via CLI) to meet threshold.
- Reconstructs secret s from the vault shares, derives AES key = H(s*G).
- Outputs a small "pre-decrypt token" JSON containing {ct_id, key_b64} for the user.

Usage:
  python -m src.edge.predecrypt \
    --ct out_multi_ct/ct_multi_stripped.json \
    --vault server_vault/vault.json \
    --uid user123@example.com \
    --attrs attrA,attrC,attrB \
    --out out_multi_ct/pre_token.json
"""

import json, base64, argparse
from pathlib import Path

from src.lsss.shamir import reconstruct_secret
from src.crypto.ecc import scalar_mul, point_to_bytes
from src.crypto.sym import derive_key_from_point

def load_json(p: Path):
    with open(p, "r") as f:
        return json.load(f)

def save_json(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(obj, f, indent=2)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ct", required=True, help="Path to stripped CT (with ct_id, no shares)")
    ap.add_argument("--vault", required=True, help="Path to server vault JSON")
    ap.add_argument("--uid", required=True, help="User ID (for logging)")
    ap.add_argument("--attrs", required=True, help="Comma-separated attribute list EA sees for this UID")
    ap.add_argument("--out", required=True, help="Path to write pre-decrypt token JSON")
    args = ap.parse_args()

    ct_path = Path(args.ct)
    vault_path = Path(args.vault)
    out_path = Path(args.out)

    ct = load_json(ct_path)
    if "ct_id" not in ct:
        print("[!] Stripped CT missing ct_id.")
        return
    ct_id = ct["ct_id"]
    meta = ct.get("meta", {})
    threshold = meta.get("threshold")
    attrs_ordered = meta.get("attributes_ordered", [])

    if threshold is None or not attrs_ordered:
        print("[!] CT meta incomplete (need threshold and attributes_ordered).")
        return

    vault = load_json(vault_path)
    entry = vault.get(ct_id)
    if not entry or "shares" not in entry:
        print(f"[!] Vault has no shares for ct_id={ct_id}.")
        return

    shares_map = entry["shares"]  # { attr: {owner, index, share_hex}, ... }

    # Attributes EA believes the user has (simulated; in real flow we'd validate with TSKs)
    user_attrs = [a.strip() for a in args.attrs.split(",") if a.strip()]
    print(f"[*] EA pre-decrypt for UID={args.uid}")
    print(f"    User attrs (EA view): {user_attrs}")
    print(f"    Policy requires: {attrs_ordered} (threshold={threshold})")

    # intersect: only attrs present both in CT and user list
    usable = []
    for attr in attrs_ordered:
        if attr in user_attrs and attr in shares_map:
            info = shares_map[attr]
            idx = int(info["index"])
            val = int(info["share_hex"], 16)
            usable.append((idx, val))

    if len(usable) < threshold:
        print(f"[!] Not enough authorized attributes ({len(usable)}) to meet threshold {threshold}.")
        return

    # pick first t usable shares (any t suffice)
    usable = usable[:threshold]

    # Reconstruct s and derive key
    s_rec = reconstruct_secret(usable)
    P = scalar_mul(s_rec)
    key = derive_key_from_point(point_to_bytes(P))   # 32-byte AES key
    key_b64 = base64.b64encode(key).decode()

    token = {
        "ct_id": ct_id,
        "uid": args.uid,
        "key_b64": key_b64
    }
    save_json(out_path, token)
    print("✅ EA pre-decrypt OK")
    print("  ct_id  :", ct_id)
    print("  token  :", out_path)
    print("  (NOTE) In this demo, EA has computed the final AES key for the user.\n"
          "         In a stricter design, we'd only return a transform that still requires the user's USK.")

if __name__ == "__main__":
    main()
