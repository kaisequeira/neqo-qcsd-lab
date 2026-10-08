#!/usr/bin/env python3
"""Public resource-domain study entrypoint, independent of historical launch gates."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from qcsd_lab.resource_study import main

if __name__ == "__main__":
    raise SystemExit(main())
