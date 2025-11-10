# src/attacks/attacker_fetch_and_crack.py
"""
Attacker script to fetch ciphertext + shares from victim and try to reconstruct & decrypt.

Usage examples (from project root):
# 1) If victim is serving files over HTTP at http://<victim_ip>:8000/
python -m src.attacks.attacker_fetch_and_crack --base-url "http://<victim_ip>:8000"

# 2) If files are already copied locally:
python -m src.attacks.attacker_fetch_and_crack --ct-path "/path/to/out_ct/ct.json" --shares-dir "/path/to/out_ct/shares"

Notes:
- This script uses only stdlib for downloads (urllib) so no extra pip packages are required.
- Run it with the same project codebase (so imports like src.crypto work). Use `python -m ...` from project root.
"""
import argparse
import json
import os
import base64
import urllib.request
from pathlib import Path
import tempfile
import time

# Crypto imports from your project (ensure you run with project root in PYTHONPATH or via `python -m`)
from src.lsss.shamir import reconstruct_secret
from src.crypto.ecc import scalar_mul, point_to_bytes
from src.crypto.sym import derive_key_from_point, aes_decrypt

def download_file(url, dest_path):
    try:
        urllib.request.urlretrieve(url, dest_path)
        return True
    except Exception as e:
        print(f"[download_file] failed to fetch {url}: {e}")
        return False

def load_json(path):
    with open(path, 'r') as f:
        return json.load(f)

def attempt_attack_from_dir(ct_path, shares_dir):
    print("[*] Attacker trying local folder:", ct_path, "shares:", shares_dir)
    ct = load_json(ct_path)
    threshold = ct.get("info", {}).get("threshold")
    if threshold is None:
        print("[!] ct.json missing threshold; cannot proceed.")
        return False

    # collect available shares in shares_dir
    share_files = sorted(Path(shares_dir).glob("share_*.json"))
    print(f"[*] Found {len(share_files)} share files on disk.")
    shares = []
    for sf in share_files:
        try:
            j = load_json(sf)
            idx = int(j["index"])
            share_val = int(j["share_hex"], 16)
            shares.append((idx, share_val))
        except Exception as e:
            print("  skip", sf, "err:", e)
        if len(shares) >= threshold:
            break

    if len(shares) < threshold:
        print(f"[!] Not enough shares ({len(shares)}) to reach threshold {threshold}.")
        return False

    # reconstruct secret s
    s_rec = reconstruct_secret(shares[:threshold])
    print("[*] Reconstructed secret s (int):", s_rec)

    # derive P and key, then try decrypt
    P = scalar_mul(s_rec)
    key = derive_key_from_point(point_to_bytes(P))
    try:
        plaintext = aes_decrypt(key, ct["aes"]["nonce_b64"], ct["aes"]["ct_b64"])
        print("[SUCCESS] Attack recovered plaintext:")
        print(plaintext.decode(errors='replace'))
        return True
    except Exception as e:
        print("[FAIL] Decryption failed (auth error or wrong key):", e)
        return False

def attempt_attack_from_url(base_url):
    """
    base_url should be a directory serving ct.json and shares/ folder, e.g.:
    http://victim-ip:8000/   where ct.json is at that URL and shares/share_1.json etc.
    """
    print("[*] Attacker fetching from base URL:", base_url)
    tmpdir = Path(tempfile.mkdtemp(prefix="attacker_"))
    print("[*] Using temp dir:", tmpdir)
    ct_url = base_url.rstrip("/") + "/ct.json"
    ct_path = tmpdir / "ct.json"
    if not download_file(ct_url, ct_path):
        print("[!] Could not fetch ct.json from", ct_url)
        return False

    ct = load_json(ct_path)
    threshold = ct.get("info", {}).get("threshold")
    if threshold is None:
        print("[!] ct.json missing threshold; cannot proceed.")
        return False

    shares_dir = tmpdir / "shares"
    shares_dir.mkdir(parents=True, exist_ok=True)

    # try downloading share files share_1.json .. share_n.json until threshold reached
    n = ct.get("info", {}).get("n_shares", 0)
    if n == 0:
        n = 10  # fallback upper bound
    collected = []
    for i in range(1, n+1):
        url = base_url.rstrip("/") + f"/shares/share_{i}.json"
        dest = shares_dir / f"share_{i}.json"
        ok = download_file(url, dest)
        if not ok:
            print(f"  [warn] could not fetch {url} (skipping).")
            continue
        try:
            j = load_json(dest)
            idx = int(j["index"])
            share_val = int(j["share_hex"], 16)
            collected.append((idx, share_val))
            print(f"  [fetched] share_{i}.json")
        except Exception as e:
            print("  [skip] invalid share file:", e)
        if len(collected) >= threshold:
            break

    if len(collected) < threshold:
        print(f"[!] Only collected {len(collected)} shares; threshold {threshold} not reached.")
        return False

    # reconstruct and attempt decrypt (reuse logic)
    return attempt_attack_from_dir(ct_path, shares_dir)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", help="Base URL where victim serves ct.json and shares/, e.g. http://victim:8000")
    parser.add_argument("--ct-path", help="Local path to ct.json (if already copied locally)")
    parser.add_argument("--shares-dir", help="Local path to shares directory (if already copied locally)")
    args = parser.parse_args()

    if args.base_url:
        success = attempt_attack_from_url(args.base_url)
    elif args.ct_path and args.shares_dir:
        success = attempt_attack_from_dir(Path(args.ct_path), Path(args.shares_dir))
    else:
        print("Usage: provide --base-url OR both --ct-path and --shares-dir")
        success = False

    if success:
        print("[*] Attack finished: SUCCESS")
    else:
        print("[*] Attack finished: FAILURE")

if __name__ == "__main__":
    main()
