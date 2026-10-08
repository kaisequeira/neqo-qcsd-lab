#!/usr/bin/env python3
"""Independently inspect the actual installed portable rapid runtime."""
import json
import sys

sys.dont_write_bytecode = True
from qcsd_lab.rapid_portable_runtime import verify_installed

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"collection", "prepare"}:
        raise SystemExit("one installed runtime role is required")
    print(json.dumps(verify_installed(sys.argv[1]), sort_keys=True))
