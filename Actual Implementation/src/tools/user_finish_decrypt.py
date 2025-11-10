# src/tools/user_finish_decrypt.py
"""
User-side final decrypt using EA pre-token.
- Reads stripped CT (with AES fields but no shares)
- Reads pre_token.json (contains ct_id and base64 AES key from EA)
- Verifies ct_id match
- Decrypts and writes plaintext to a file

Usage:
  python -m src.tools.user_finish_decrypt \
    --ct out_multi_ct/ct_multi_stripped.json \
    --token out_multi_ct/pre_token.json \
    --out out_multi_ct/decrypted.txt
"""

import argparse, json, base64
from pathlib import Path
from src.crypto.sym import aes_decrypt

def load_json(p: Path):
    with open(p, "r") as f:
        return json.load(f)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ct", required=True, help="Path to stripped CT JSON")
    ap.add_argument("--token", required=True, help="Path to pre_token.json from EA")
    ap.add_argument("--out", required=True, help="Path to write decrypted plaintext")
    args = ap.parse_args()

    ct_path = Path(args.ct)
    token_path = Path(args.token)
    out_path = Path(args.out)

    ct = load_json(ct_path)
    token = load_json(token_path)

    # basic checks
    if "ct_id" not in ct or "aes" not in ct:
        print("[!] CT missing ct_id or aes fields.")
        return
    if token.get("ct_id") != ct.get("ct_id"):
        print("[!] Token ct_id does not match CT ct_id.")
        return
    if "key_b64" not in token:
        print("[!] Token missing key_b64.")
        return

    key = base64.b64decode(token["key_b64"])
    aes = ct["aes"]
    try:
        plaintext = aes_decrypt(key, aes["nonce_b64"], aes["ct_b64"])
    except Exception as e:
        print("[!] Decryption failed:", e)
        return

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(plaintext)
    print("✅ Decryption complete.")
    print("   Output:", out_path)
    # Also show a preview safely
    preview = plaintext[:120]
    try:
        print("   Preview:", preview.decode(errors="replace"))
    except Exception:
        print("   Preview (bytes):", preview)

if __name__ == "__main__":
    main()
