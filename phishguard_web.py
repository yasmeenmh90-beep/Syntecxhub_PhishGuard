#!/usr/bin/env python3
"""PhishGuard web inspector. Launch:  python3 phishguard_web.py

Runs only on this computer (127.0.0.1) and opens your browser. Ctrl+C to stop.
"""
import argparse

from expert_system.webapp import serve

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8770)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    serve(port=args.port, open_browser=not args.no_browser)
