#!/usr/bin/env bash
# File: pack_vault_and_strip.sh
# Usage: ./pack_vault_and_strip.sh
set -euo pipefail

echo
echo "=== Step 2: Pack vault and create stripped CT ==="
python -m src.tools.share_vault_pack \
  --in-ct out_multi_ct/ct_multi.json \
  --vault server_vault/vault.json \
  --out-ct out_multi_ct/ct_multi_stripped.json

echo
echo "Vault packed and stripped CT created:"
ls -la server_vault/vault.json out_multi_ct/ct_multi_stripped.json || true
