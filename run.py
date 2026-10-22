#!/usr/bin/env python3
"""Run without installing:  python run.py analyze logs/access.log"""
from protectrequest.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
