#!/usr/bin/env bash
# local_rehearse_demo.sh
# Start victim server, run attacker locally against 127.0.0.1, collect logs, stop server.
set -euo pipefail
BASE_DIR="$(pwd)"
OUTDIR="$BASE_DIR/out_ct"
LOGFILE="/tmp/out_ct_http.log"
ATT_LOG="/tmp/attacker_demo_local.log"

echo "Ensure venv is active (source venv/bin/activate)."
echo
echo "[A] Prepare plaintext + CT + shares..."
echo "Hello from victim device. Attack me if you can :)" > demo.txt
python -m src.tools.victim_export --infile demo.txt --outdir "$OUTDIR" --n 5 --t 3

echo
echo "[B] Start server in background (port 8000)..."
cd "$OUTDIR"
: > "$LOGFILE"
python -m http.server 8000 > "$LOGFILE" 2>&1 &
HTTP_PID=$!
sleep 0.6
echo "Server PID: $HTTP_PID (logs -> $LOGFILE)"

echo
echo "[C] Run attacker locally..."
cd "$BASE_DIR"
python -u -m src.attacks.attacker_fetch_and_crack --base-url "http://127.0.0.1:8000" 2>&1 | tee "$ATT_LOG"

echo
echo "[D] Show server log tail and attacker log tail:"
echo "server log:"
tail -n 20 "$LOGFILE" || true
echo
echo "attacker log:"
tail -n 30 "$ATT_LOG" || true

echo
echo "[E] Stopping server..."
kill "$HTTP_PID" || true
echo "Rehearsal completed."
