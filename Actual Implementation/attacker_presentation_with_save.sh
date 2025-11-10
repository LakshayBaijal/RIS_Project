#!/usr/bin/env bash
# attacker_presentation_with_save.sh
# Usage: ./attacker_presentation_with_save.sh "http://10.1.33.104:8000"
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 VICTIM_BASE_URL"
  exit 1
fi

BASE_URL="$1"
OUTDIR="./attacker_output"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/log.txt"
RECOVERED="$OUTDIR/recovered.txt"

echo "Starting attacker (presentation mode)..."
echo "Base URL: $BASE_URL"
echo "Output dir: $OUTDIR"
echo

# Run attacker and capture full output
python -u -m src.attacks.attacker_fetch_and_crack --base-url "$BASE_URL" 2>&1 | tee "$LOG"

# extract recovered plaintext lines and save them (best-effort)
grep -A4 "\[SUCCESS\] Attack recovered plaintext" "$LOG" > "$RECOVERED" || true

echo
echo "Attacker finished. Saved logs:"
echo " - Log : $LOG"
echo " - Recovered snippet : $RECOVERED"
echo
echo "Recovered plaintext (if any):"
cat "$RECOVERED" || echo "(no recovered plaintext captured in log)"
