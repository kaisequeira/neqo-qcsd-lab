#!/usr/bin/env python3
"""Read-only original deep proof and separate create-only partial-lane receipts."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parents[1] / "src"))
from qcsd_lab import rapid_partial_lane as reader


def main():
    p = argparse.ArgumentParser(description=__doc__)
    actions = p.add_subparsers(dest="action", required=True)
    source = actions.add_parser("bind-source")
    for name in ("source-root", "output"): source.add_argument("--" + name, type=Path, required=True)
    for name in ("lab-head", "native-head"): source.add_argument("--" + name, required=True)
    declare = actions.add_parser("declare")
    for name in ("source-binding", "spec", "evidence-root", "intent", "result", "audit-root", "output"):
        declare.add_argument("--" + name, type=Path, required=True)
    verify = actions.add_parser("verify")
    for name in ("receipt", "audit-root"): verify.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    try:
        if args.action == "bind-source":
            result = reader.bind_source(args.source_root.absolute(), args.lab_head, args.native_head, args.output.absolute())
        elif args.action == "declare":
            result = reader.declare(source_binding=reader.reference(args.source_binding.absolute()), spec=args.spec.absolute(),
                evidence_root=args.evidence_root.absolute(), intent=args.intent.absolute(), result=args.result.absolute(),
                audit_root=args.audit_root.absolute(), output=args.output.absolute())
        else:
            result = reader.verify(reader.reference(args.receipt.absolute()), audit_root=args.audit_root.absolute())
        print(json.dumps({"operation": args.action, "status": "closed", "result": result}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"operation": args.action, "status": "refused", "error_type": type(error).__name__}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
