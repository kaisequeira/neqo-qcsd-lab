#!/usr/bin/env python3
"""Create a browser-free unqualified graph; execute no network or admission."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from qcsd_lab.supplied_static_graph import canonical_bytes, import_graph, verify_import


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    if args.source.is_symlink() or not args.source.is_file():
        raise ValueError("supplied source must be a regular file")
    source = args.source.read_bytes()
    manifest, binding = import_graph(source, args.source_sha256, args.domain)
    verify_import(source, args.source_sha256, args.domain, manifest, binding)
    args.output_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, value in (("native-input.json", manifest), ("input-binding.json", binding)):
        fd = os.open(args.output_root / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o444)
        with os.fdopen(fd, "wb") as output:
            output.write(canonical_bytes(value))
            output.flush()
            os.fsync(output.fileno())
    print(json.dumps({"domain": args.domain, "native_input": str(args.output_root / "native-input.json"),
                      "input_binding": str(args.output_root / "input-binding.json"),
                      "resource_count": len(manifest["resources"]),
                      "origin_count": len(binding["origins"]), "scientific_credit": False,
                      "evidence_state": "unqualified-input-only"}))


if __name__ == "__main__":
    main()
