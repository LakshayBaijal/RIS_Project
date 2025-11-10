# src/tools/user_finish_transform_decrypt.py
"""
User-side final decryption after EA partial transform.
- Inputs:
    --ct         : stripped ciphertext (contains AES fields)
    --token      : EA transform token (C1_b64, C2_b64)
    --usersecret : JSON with user's d (demo-only)
    --out        : file path for decrypted plaintext

Steps:
  1. Load user's secret d
  2. Decode C1, C2 (points)
  3. Compute P_s = C2 - d*C1
  4. Derive AES key = H(point_to_bytes(P_s))
  5. AES decrypt and write plaintext
"""

import json, base64, argparse
from pathlib import Path
from src.crypto.ecc import bytes_to_point, scalar_mul, point_sub, point_to_bytes
from src.crypto.sym import derive_key_from_point, aes_decrypt

def load_json(p: Path):
    with open(p, "r") as f:
        return json.load(f)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ct", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--usersecret", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    ct = load_json(Path(args.ct))
    token = load_json(Path(args.token))
    sec = load_json(Path(args.usersecret))

    d = int(sec["d_hex"], 16)
    C1 = bytes_to_point(base64.b64decode(token["C1_b64"]))
    C2 = bytes_to_point(base64.b64decode(token["C2_b64"]))

    # compute P_s = C2 - d*C1
    dC1 = scalar_mul(d, C1)
    P_s = point_sub(C2, dC1)

    key = derive_key_from_point(point_to_bytes(P_s))

    aes = ct["aes"]
    plaintext = aes_decrypt(key, aes["nonce_b64"], aes["ct_b64"])

    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_bytes(plaintext)

    print("✅ User final decrypt successful.")
    print("   Output:", outp)
    try:
        print("   Preview:", plaintext.decode(errors='replace')[:120])
    except Exception:
        print("   Preview (bytes):", plaintext[:120])

if __name__ == "__main__":
    main()
