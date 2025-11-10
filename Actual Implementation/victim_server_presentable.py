#!/usr/bin/env python3
# victim_server_presentable.py
# Run this from the project root (so it can serve the 'out_ct' directory).
#
# Usage:
#   cd /path/to/project
#   python3 victim_server_presentable.py --dir out_ct --port 8000
#
# The server logs requests to /tmp/out_ct_http.log and prints alerts on console
# when ct.json or shares/* are fetched.

import argparse
import datetime
import html
import http.server
import json
import logging
import os
import socketserver
import sys
from pathlib import Path

LOG_PATH = "/tmp/out_ct_http.log"

class PresentableHandler(http.server.SimpleHTTPRequestHandler):
    def log_and_alert(self, code=200):
        client_ip = self.client_address[0]
        now = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
        method = self.command
        path = self.path
        ua = self.headers.get('User-Agent', '-')
        log_entry = {
            "time": now,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "user_agent": ua
        }
        # append to logfile as JSON line for clarity and machine parsing
        try:
            with open(LOG_PATH, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"[!] Failed to write log: {e}", file=sys.stderr)

        # Print a nice human-readable line to console (presentation view)
        pretty = f"[{now}] {client_ip} -> {method} {path} (UA: {ua})"
        print(pretty)

        # If ct.json or shares accessed, print an ALERT line (so audience notices)
        p = path.lstrip("/")
        if p.endswith("ct.json") or p.startswith("shares/") or "/shares/" in p:
            alert = f"*** ALERT: sensitive file requested by {client_ip}: {path} ***"
            print(alert)
            # also append alert as separate JSON line
            try:
                with open(LOG_PATH, "a") as f:
                    f.write(json.dumps({"alert_time": now, "alert": alert}) + "\n")
            except Exception:
                pass

    # override to log after serving
    def send_response(self, code, message=None):
        super().send_response(code, message)
        # don't log here; we will log at end after response headers are sent

    def end_headers(self):
        super().end_headers()
        # log every served request once headers done
        try:
            self.log_and_alert(200)
        except Exception as e:
            print(f"[!] logging failed: {e}", file=sys.stderr)

    # keep the default directory listing and file serving behaviour
    def log_message(self, format, *args):
        # suppress default logging to stderr (we handle logs separately)
        return

def run_server(serve_dir: str, port: int):
    os.chdir(serve_dir)
    handler = PresentableHandler
    # set up simple logging file header
    try:
        Path(LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write("\n=== Server started: " + datetime.datetime.now().isoformat() + " ===\n")
    except Exception:
        pass

    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"Serving directory {serve_dir} on 0.0.0.0:{port}")
        print(f"Logs appended to {LOG_PATH}")
        print("Press Ctrl-C to stop server.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer shutting down.")
        except Exception as e:
            print(f"Server error: {e}", file=sys.stderr)

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=False, default="out_ct", help="Directory to serve (default out_ct)")
    ap.add_argument("--port", required=False, default=8000, type=int, help="Port to serve on")
    return ap.parse_args()

if __name__ == "__main__":
    args = parse_args()
    serve_dir = args.dir
    if not Path(serve_dir).exists():
        print(f"Error: serve directory {serve_dir} does not exist. Create CT/shares first (victim_export).")
        sys.exit(1)
    run_server(serve_dir, args.port)
