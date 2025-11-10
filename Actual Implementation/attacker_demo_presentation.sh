#!/usr/bin/env bash
# attacker_demo_presentation.sh
# Usage: ./attacker_demo_presentation.sh "http://10.1.33.104:8000"
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 VICTIM_BASE_URL"
  echo "Example: $0 http://10.1.33.104:8000"
  exit 1
fi

BASE_URL="$1"
MAX_RETRIES=10
SLEEP=1
TMPDIR=$(mktemp -d /tmp/attacker_demo.XXXX)
OUTLOG="$TMPDIR/attacker_output.log"

echo
echo "=== ATTACKER DEMO (presentation-friendly) ==="
echo "Base URL: $BASE_URL"
echo "Temp dir: $TMPDIR"
echo

# Check server reachable (ct.json) with retries
echo "[1] Checking victim server availability..."
i=0
while [ $i -lt $MAX_RETRIES ]; do
  if curl -s --head --fail --max-time 2 "$BASE_URL/ct.json" >/dev/null 2>&1; then
    echo "  -> ct.json reachable on attempt $((i+1))"
    break
  fi
  echo "  -> ct.json not reachable yet (attempt $((i+1)))"
  i=$((i+1))
  sleep $SLEEP
done
if [ $i -ge $MAX_RETRIES ]; then
  echo "ERROR: victim server did not respond after $MAX_RETRIES tries."
  exit 2
fi

echo
echo "[2] Run attacker fetch & crack (this prints progress). Output saved to: $OUTLOG"
# Run attacker tool; capture both stdout/stderr
python -u -m src.attacks.attacker_fetch_and_crack --base-url "$BASE_URL" 2>&1 | tee "$OUTLOG"

echo
echo "[3] Quick summary (last 30 lines of output):"
tail -n 30 "$OUTLOG" || true
echo
echo "Temp dir kept at $TMPDIR for investigation. Remove when done."
