# src/tools/victim_export.py
# Generates ciphertext + per-share JSON files for cross-device attack demo.
# Usage:
#   python -m src.tools.victim_export --infile demo.txt --outdir out_ct --n 5 --t 3

import os, json, base64, argparse, random
from pathlib import Path
from ecpy.curves import Curve

from src.crypto.ecc import scalar_mul, point_to_bytes
from src.crypto.sym import derive_key_from_point, aes_encrypt
from src.lsss.shamir import split_secret

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--infile", required=True, help="Path to plaintext file")
    parser.add_argument("--outdir", default="out_ct", help="Output directory")
    parser.add_argument("--n", type=int, default=5, help="number of shares")
    parser.add_argument("--t", type=int, default=3, help="threshold")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    share_dir = outdir / "shares"
    outdir.mkdir(parents=True, exist_ok=True)
    share_dir.mkdir(parents=True, exist_ok=True)

    # --- read plaintext
    pt = Path(args.infile).read_bytes()

    # --- ECC scalar + key derivation
    curve = Curve.get_curve('secp256r1')
    s = random.randrange(1, curve.order)
    P = scalar_mul(s)
    key = derive_key_from_point(point_to_bytes(P))

    # --- Encrypt
    aes = aes_encrypt(key, pt)

    # --- Split secret s
    shares = split_secret(s, args.n, args.t)

    # --- Save ciphertext JSON
    ct_json = {
        "info": {
            "curve": "secp256r1",
            "n_shares": args.n,
            "threshold": args.t,
        },
        # serialize P for reference (not needed to reconstruct in this toy)
        "P_bytes_b64": base64.b64encode(point_to_bytes(P)).decode(),
        "aes": aes,  # {"nonce_b64":..., "ct_b64":...}
    }
    (outdir / "ct.json").write_text(json.dumps(ct_json, indent=2))

    # --- Save per-share files
    for idx, share_val in shares:
        share_obj = {"index": idx, "share_hex": hex(share_val)}
        (share_dir / f"share_{idx}.json").write_text(json.dumps(share_obj, indent=2))

    print("✅ Export complete")
    print(f"Ciphertext : {outdir/'ct.json'}")
    print(f"Shares dir : {share_dir} ({len(shares)} files)")
    print("Tip: serve this directory so another laptop can fetch files:\n"
          f"  cd {outdir} && python -m http.server 8000")

if __name__ == "__main__":
    main()
