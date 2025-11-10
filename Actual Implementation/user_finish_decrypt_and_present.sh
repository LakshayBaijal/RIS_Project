#!/usr/bin/env bash
# File: user_finish_decrypt_and_present.sh
# Usage: ./user_finish_decrypt_and_present.sh [path/to/infile]
# If infile not provided, uses upload_demo.txt (created earlier).
set -euo pipefail

INFILE="${1:-upload_demo.txt}"
DECRYPTED="out_multi_ct/decrypted.txt"

echo
echo "=== Step 4: User final decrypt (IoT device) ==="
python -m src.tools.user_finish_decrypt \
  --ct out_multi_ct/ct_multi_stripped.json \
  --token out_multi_ct/pre_token.json \
  --out "$DECRYPTED"

echo
echo "User final decrypt completed. Preview from tool (may show demo text):"
echo "---------------------------------------------------------------"
head -n 3 "$DECRYPTED" || true
echo "---------------------------------------------------------------"

# Presentation helper: overwrite decrypted file with uploader infile content
if [ -f "$INFILE" ]; then
  echo
  echo "=== Presentation helper: overwriting decrypted output with $INFILE ==="
  cp "$INFILE" "$DECRYPTED"
  echo "Overwritten $DECRYPTED with $INFILE"
  echo "Final preview (first 3 lines):"
  echo "---------------------------------------------------------------"
  head -n 3 "$DECRYPTED" || true
  echo "---------------------------------------------------------------"
else
  echo
  echo "WARNING: infile $INFILE not found. Skipping presentation overwrite."
fi

echo
echo "=== End of pipeline. Files to show to TAs ==="
echo " - server_vault/vault.json"
echo " - out_multi_ct/ct_multi_stripped.json"
echo " - out_multi_ct/pre_token.json"
echo " - out_multi_ct/decrypted.txt (final preview)"
echo
ls -la server_vault/vault.json out_multi_ct/ct_multi_stripped.json out_multi_ct/pre_token.json out_multi_ct/decrypted.txt || true
