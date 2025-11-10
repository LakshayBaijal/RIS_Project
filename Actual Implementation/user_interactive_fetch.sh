#!/usr/bin/env bash
# user_interactive_fetch.sh
# Interactive fetcher for demo (Terminal B).
# Usage: ./user_interactive_fetch.sh http://<VICTIM_IP>:<PORT>
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 VICTIM_BASE_URL"
  echo "Example: $0 http://127.0.0.1:8000"
  exit 1
fi

BASE="$1"
echo
echo "Interactive fetcher connected to: $BASE"
echo "Options:"
echo "  1) Fetch ct.json (first lines)"
echo "  2) List /shares/ directory"
echo "  3) Fetch share_1.json"
echo "  4) Open CT in browser (prints URL to open)"
echo "  q) Quit"
echo

while true; do
  read -rp "Choose (1/2/3/4/q): " c
  case "$c" in
    1)
      echo ">>> GET $BASE/ct.json"
      curl -s "$BASE/ct.json" | sed -n '1,12p'
      echo
      ;;
    2)
      echo ">>> GET $BASE/shares/"
      # try directory listing
      curl -s "$BASE/shares/" | sed -n '1,40p' || true
      echo
      ;;
    3)
      echo ">>> GET $BASE/shares/share_1.json"
      curl -s "$BASE/shares/share_1.json" | sed -n '1,40p' || echo "(not found)"
      echo
      ;;
    4)
      echo "Open this URL in a browser (copy-paste): $BASE"
      echo
      ;;
    q|Q)
      echo "Quitting."
      exit 0
      ;;
    *)
      echo "Invalid. Choose 1/2/3/4/q."
      ;;
  esac
done
