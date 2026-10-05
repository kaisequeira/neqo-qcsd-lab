#!/usr/bin/env python3
"""Audit selection once and publish direct complete-graph capture inputs."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from qcsd_lab import rapid_selected_capture_input as selected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("audit-enrollment", "audit-whole-terminal", "audit-static-terminal"):
        command = commands.add_parser(name)
        command.add_argument("--original-source-root", type=Path, required=True)
        command.add_argument("--original-source-manifest", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        if name == "audit-enrollment":
            command.add_argument("--enrollment", type=Path, required=True)
        else:
            command.add_argument("--context", type=Path, required=True)
            command.add_argument("--terminal", type=Path, required=True)
    publish = commands.add_parser("publish-input")
    publish.add_argument("--audit", type=Path, required=True)
    publish.add_argument("--candidate-id", required=True)
    publish.add_argument("--output", type=Path, required=True)
    prepare = commands.add_parser("prepare-input")
    prepare.add_argument("--input", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify-input")
    verify.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    if args.command.startswith("audit-"):
        result = selected.audit_legacy(args.output, source_root=args.original_source_root,
            source_manifest=selected.reference(args.original_source_manifest),
            enrollment=getattr(args, "enrollment", None), context=getattr(args, "context", None), terminal=getattr(args, "terminal", None),
            original_role=selected.original.ROLE if args.command == "audit-static-terminal" else selected.whole.ROLE)
    elif args.command == "publish-input":
        result = selected.publish_input(args.output, audit=args.audit, candidate_id=args.candidate_id)
    elif args.command == "prepare-input":
        result = selected.prepare_input(args.input, args.output)
    else:
        value, manifest, _ = selected.validate_input(args.input)
        print(json.dumps({"verified": True, "resources": len(manifest["resources"]), "formal_credit_added": 0}), flush=True)
        return 0
    print(json.dumps({"receipt": selected.reference(result), "formal_credit_added": 0}), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f"selected capture input: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(2)
