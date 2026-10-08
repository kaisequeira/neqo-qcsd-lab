#!/usr/bin/env python3
"""Build or verify a public, source-bound rapid collection runtime."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from qcsd_lab.rapid_portable_runtime import main

if __name__ == "__main__":
    raise SystemExit(main())
