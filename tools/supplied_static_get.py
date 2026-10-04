#!/usr/bin/env python3
"""Produce/reopen zero-credit Native GET evidence; grant no study authority."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from qcsd_lab.supplied_static_get import execute_full_get, validate_proof, runtime_binding, _load, _read


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("execute", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--runtime-binding", type=Path, required=True)
        command.add_argument("--source-sha256", required=True)
        command.add_argument("--domain", required=True)
        command.add_argument("--output-root", type=Path, required=True)
        if name == "execute":
            command.add_argument("--source", type=Path, required=True)
            command.add_argument("--input-root", type=Path, required=True)
            command.add_argument("--max-response-bytes", type=int, default=16_777_216)
            command.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()
    binding = runtime_binding(_load(_read(args.runtime_binding)))
    common = {"expected_runtime": binding, "source_sha256": args.source_sha256, "domain": args.domain}
    if args.command == "execute":
        proof = execute_full_get(args.source, args.input_root, args.output_root, **common,
                                 max_response_bytes=args.max_response_bytes, timeout_seconds=args.timeout_seconds)
    else:
        proof = validate_proof(args.output_root, **common)
    print(json.dumps({"domain": proof["domain"], "resource_count": proof["resource_count"],
                      "origin_count": proof["origin_count"], "complete_native_GET": True,
                      "scientific_credit": False, "site_credit": 0, "formal_accepted_trace_count": 0,
                      "proof": str(args.output_root / "full-get-proof.json")}))


if __name__ == "__main__":
    main()
