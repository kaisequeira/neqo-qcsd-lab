#!/usr/bin/env python3
"""Root-only physical discovery; HOST declaration/check remain network free."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import graph_input as graph


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    declare = actions.add_parser("declare", help="HOST only: reserve next unseen frozen catalogue identities")
    for name in ["source", "catalogue", "parent-context", "source-metadata", "output"]:
        declare.add_argument("--" + name, type=Path, required=True)
    declare.add_argument("--lab-commit", required=True)
    declare.add_argument("--browser-image", required=True)
    declare.add_argument("--count", type=int, required=True)
    declare.add_argument("--previous-plan", type=Path, action="append", required=True)
    declare.add_argument("--previous-batch", type=Path, action="append", required=True)
    check = actions.add_parser("check", help="HOST only: reopen declared Source and immutable input bindings")
    check.add_argument("--plan", type=Path, required=True)
    physical = actions.add_parser("discover", help="PHYSICAL: one declared candidate in the exact browser image")
    physical.add_argument("--plan", type=Path, required=True)
    physical.add_argument("--candidate-index", type=int, required=True)
    physical.add_argument("--output", type=Path, required=True)
    verify = actions.add_parser("verify-input", help="HOST only: reopen all successful convergence/whole-graph evidence")
    verify.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "declare":
            path = graph.declare(source=args.source, lab_commit=args.lab_commit, catalogue=args.catalogue,
                parent_context=args.parent_context, browser_image=args.browser_image,
                source_metadata=args.source_metadata, count=args.count, previous_plans=args.previous_plan,
                previous_batches=args.previous_batch, output=args.output)
            result = {"operation": "declare", "status": "closed", "plan": str(path), **graph.ZERO}
        elif args.action == "check":
            value = graph.check_plan(args.plan)
            result = {"operation": "check", "status": "closed", "candidate_count": len(value["candidates"]),
                      "original_prefix_count": value["original_prefix"]["candidate_count"], **graph.ZERO}
        elif args.action == "verify-input":
            result = {"operation": "verify-input", "status": "closed", **graph.verify_input(args.input)}
        else:
            code = graph.discover(args.plan, args.candidate_index, args.output)
            result = {"operation": "discover", "status": "closed" if code == 0 else "failed",
                      "evidence_root": str(args.output.absolute()), **graph.ZERO}
            print(json.dumps(result, sort_keys=True))
            return code
    except Exception as error:
        # Exceptions can contain source URLs/headers. Retained physical failures
        # contain their exact text; console summaries intentionally omit it.
        print(json.dumps({"operation": args.action, "status": "error",
                          "error_type": type(error).__name__, **graph.ZERO}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
