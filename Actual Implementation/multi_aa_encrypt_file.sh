#!/usr/bin/env bash
# File: multi_aa_encrypt_file.sh
# Usage: ./multi_aa_encrypt_file.sh [path/to/infile]
# If no infile provided, creates upload_demo.txt with "I am a good boy".
set -euo pipefail

INFILE="${1:-upload_demo.txt}"

if [ ! -f "$INFILE" ]; then
  echo "I am a good boy" > "$INFILE"
  echo "Created default infile: $INFILE"
else
  echo "Using provided infile: $INFILE"
fi

echo
echo "=== Step 1: Run multi-authority encrypt demo ==="
# This is the real demo command (same as you've used)
python -m src.tools.multi_aa_encrypt_demo

echo
echo "multi-authority encrypt done. Output: out_multi_ct/ct_multi.json"
