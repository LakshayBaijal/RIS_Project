# src/tools/share_vault_pack.py
"""
Moves shares out of a public CT and into a server-side Share Vault.
- Input: a CT JSON produced by multi_aa_encrypt_demo (contains 'shares')
- Output 1 (server): vault.json (append-only), keyed by ct_id
- Output 2 (client): ct_stripped.json (no 'shares', includes 'ct_id')

Usage:
  python -m src.tools.share_vault_pack \
    --in-ct out_multi_ct/ct_multi.json \
    --vault server_vault/vault.json \
    --out-ct out_multi_ct/ct_multi_stripped.json
"""

import json, os, uuid, argparse
from pathlib import Path

def load_json(p: Path):
    with open(p, "r") as f:
        return json.load(f)

def save_json(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(obj, f, indent=2)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in-ct", required=True, help="Path to CT with shares (public)")
    parser.add_argument("--vault", required=True, help="Path to server-side vault JSON")
    parser.add_argument("--out-ct", required=True, help="Path to write stripped CT (no shares)")
    args = parser.parse_args()

    in_ct = Path(args.in_ct)
    vault_path = Path(args.vault)
    out_ct = Path(args.out_ct)

    if not in_ct.exists():
        print("[!] Input CT not found:", in_ct)
        return

    ct = load_json(in_ct)
    if "shares" not in ct or not isinstance(ct["shares"], dict):
        print("[!] Input CT has no 'shares' field; nothing to vault.")
        return

    # 1) Generate a unique ciphertext ID
    ct_id = str(uuid.uuid4())

    # 2) Load or create vault
    if vault_path.exists():
        vault = load_json(vault_path)
        if not isinstance(vault, dict):
            print("[!] Vault is not a dict JSON; refusing to overwrite.")
            return
    else:
        vault = {}

    # 3) Store shares under ct_id
    if ct_id in vault:
        print("[!] Collision on ct_id (very unlikely). Rerun.")
        return
    vault[ct_id] = {
        "meta": ct.get("meta", {}),
        "shares": ct["shares"]  # move entire shares map
    }

    # 4) Write updated vault
    save_json(vault_path, vault)

    # 5) Produce stripped CT for distribution: remove shares, add ct_id
    ct_stripped = dict(ct)
    ct_stripped.pop("shares", None)
    ct_stripped["ct_id"] = ct_id
    save_json(out_ct, ct_stripped)

    print("✅ Vault pack complete")
    print("  ct_id       :", ct_id)
    print("  vault saved :", vault_path)
    print("  stripped CT :", out_ct)
    print("\nNext: distribute ONLY the stripped CT. Keep the vault on the server.")
    print("      EA will use ct_id to fetch hidden shares during pre-decrypt.")

if __name__ == "__main__":
    main()
