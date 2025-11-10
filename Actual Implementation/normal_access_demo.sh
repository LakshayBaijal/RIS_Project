#!/usr/bin/env bash
# normal_access_demo.sh
# Demonstrates normal legitimate access: multi-AA encrypt -> pack vault -> EA pre-decrypt -> user finish decrypt
set -euo pipefail

echo
echo "=== NORMAL ACCESS DEMO ==="
echo "Make sure venv is active: source venv/bin/activate"
echo

ROOT="$(pwd)"
echo "Working dir: $ROOT"
echo

# 1) run multi-authority encrypt demo (creates out_multi_ct/ct_multi.json)
echo "[1] Running multi-authority encryption demo..."
python -m src.tools.multi_aa_encrypt_demo
echo

# 2) pack vault and create stripped CT (vault saved in server_vault/vault.json)
echo "[2] Packing stripped CT + server vault..."
python -m src.tools.share_vault_pack \
  --in-ct out_multi_ct/ct_multi.json \
  --vault server_vault/vault.json \
  --out-ct out_multi_ct/ct_multi_stripped.json
echo

# 3) EA pre-decrypt (Edge Authority computes transform/token for legitimate user)
echo "[3] EA pre-decrypt (edge) for user 'user123@example.com' using attrs attrA,attrC,attrB..."
python -m src.edge.predecrypt \
  --ct out_multi_ct/ct_multi_stripped.json \
  --vault server_vault/vault.json \
  --uid user123@example.com \
  --attrs attrA,attrC,attrB \
  --out out_multi_ct/pre_token.json
echo

# 4) User final decrypt (user finishes and recovers plaintext)
echo "[4] User final decrypt (user uses token to finish decrypt)..."
python -m src.tools.user_finish_decrypt \
  --ct out_multi_ct/ct_multi_stripped.json \
  --token out_multi_ct/pre_token.json \
  --out out_multi_ct/decrypted.txt
echo

# 5) show result preview (first lines)
echo "[5] Show decrypted output preview (first 5 lines of out_multi_ct/decrypted.txt):"
if [ -f out_multi_ct/decrypted.txt ]; then
  head -n 5 out_multi_ct/decrypted.txt || true
else
  echo "ERROR: decrypted file not found: out_multi_ct/decrypted.txt"
  exit 1
fi

echo
echo "NORMAL ACCESS DEMO complete."
echo "Files produced:"
ls -la out_multi_ct | sed -n '1,120p' || true
echo
echo "If you want to later demo the attack, run the victim/attacker scripts we prepared."
