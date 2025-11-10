#!/usr/bin/env bash
# victim_demo.sh
# Run on Victim laptop. Creates demo plaintext, exports CT+shares, and serves them on HTTP.
set -euo pipefail
BASE_DIR="$(pwd)"
OUTDIR="$BASE_DIR/out_ct"
LOGFILE="/tmp/out_ct_http.log"

echo "Activating venv (assumes venv exists)..."
# source venv/bin/activate   # Uncomment if you want script to source venv automatically

echo
echo "1) Create demo plaintext..."
echo "Hello from victim device. Attack me if you can :)" > demo.txt
echo "Written demo.txt"

echo
echo "2) Export ciphertext + shares (n=5, t=3) into out_ct..."
python -m src.tools.victim_export --infile demo.txt --outdir "$OUTDIR" --n 5 --t 3

echo
echo "3) Show files created:"
ls -la "$OUTDIR"
ls -la "$OUTDIR/shares" || true

echo
echo "4) Start simple HTTP server on port 8000 from $OUTDIR (log -> $LOGFILE) ..."
cd "$OUTDIR"
# start server in background
python -m http.server 8000 > "$LOGFILE" 2>&1 &
SERVER_PID=$!
sleep 0.5
echo "HTTP server started (PID=$SERVER_PID). Log: $LOGFILE"
echo

echo "5) Show your machine IP addresses (share the LAN IP with attacker):"
hostname -I || true
echo
echo "6) Tail the server log for a moment (press Ctrl-C to stop tail):"
sleep 0.2
tail -n 8 "$LOGFILE" || true

echo
echo "When attacker finishes, press ENTER to stop HTTP server."
read -r _
echo "Stopping server (PID=$SERVER_PID)..."
kill "$SERVER_PID" || true
echo "Server stopped. Done."
