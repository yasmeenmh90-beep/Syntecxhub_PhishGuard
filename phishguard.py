#!/usr/bin/env python3
"""PhishGuard command line. Run `python3 phishguard.py --help` for all commands."""
import sys

from expert_system.cli import main

if __name__ == "__main__":
    sys.exit(main())
