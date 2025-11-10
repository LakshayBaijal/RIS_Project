#!/usr/bin/env bash
# File: ea_predecrypt.sh
# Usage: ./ea_predecrypt.sh
set -euo pipefail

echo
echo "=== Step 3: EA pre-decrypt (edge) ==="
python -m src.edge.predecrypt \
  --ct out_multi_ct/ct_multi_stripped.json \
  --vault server_vault/vault.json \
  --uid user123@example.com \
  --attrs attrA,attrC,attrB \
  --out out_multi_ct/pre_token.json

echo
echo "EA pre-decrypt done. Token: out_multi_ct/pre_token.json"
ls -la out_multi_ct/pre_token.json || true
