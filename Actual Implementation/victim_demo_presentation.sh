#!/usr/bin/env bash
# victim_demo_presentation.sh
# Create plaintext, export ct+shares, start HTTP server, print IP & log path.
set -euo pipefail

BASE_DIR="$(pwd)"
OUTDIR="$BASE_DIR/out_ct"
LOGFILE="/tmp/out_ct_http.log"

echo
echo "=== VICTIM DEMO (presentation-friendly) ==="
echo "Working directory: $BASE_DIR"
echo

# REQUIRE: venv active. We don't auto-source; presenter should run `source venv/bin/activate`
# (uncomment following line if you want automatic activate and your venv path is standard)
# source venv/bin/activate

echo "[1] Create demo plaintext..."
echo "Hello from victim device. Attack me if you can :)" > demo.txt
echo "  -> demo.txt created"

echo
echo "[2] Export ciphertext + shares (n=5, t=3) -> $OUTDIR"
python -m src.tools.victim_export --infile demo.txt --outdir "$OUTDIR" --n 5 --t 3

echo
echo "[3] Files created (showing top):"
ls -la "$OUTDIR" | sed -n '1,20p' || true
ls -la "$OUTDIR/shares" | sed -n '1,50p' || true

echo
echo "[4] Start HTTP server (port 8000). Logs -> $LOGFILE"
cd "$OUTDIR"
# ensure logfile exists
: > "$LOGFILE"
python -m http.server 8000 > "$LOGFILE" 2>&1 &
HTTP_PID=$!
sleep 0.7

# pick a LAN IP (first non-docker, non-loopback)
LAN_IP=$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i !~ /^(127|172\.17|docker)/) {print $i; exit}}')
if [ -z "$LAN_IP" ]; then
  # fallback to first entry
  LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi

echo
echo "HTTP server started (PID=$HTTP_PID)"
echo "Serve directory: $OUTDIR"
echo "Share this URL with attacker: http://$LAN_IP:8000"
echo
echo "[5] Tail server log (show last lines). Keep this terminal visible during demo."
echo "----- server log (tail) -----"
tail -n 12 "$LOGFILE" || true
echo "-----------------------------"

echo
echo "When attacker finishes, press ENTER to stop the server and end demo."
read -r _
echo "Stopping HTTP server (PID=$HTTP_PID)..."
kill "$HTTP_PID" || true
echo "Server stopped. Demo complete."
