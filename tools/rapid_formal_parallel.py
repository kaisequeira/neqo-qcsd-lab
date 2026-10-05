#!/usr/bin/env python3
"""Prepare a create-only pair of official 20-trace rapid v5 capture lanes.

Use tools/rapid_parallel_capture.py launch/verify for the actual gated batch.
Final corpus publication continues through tools/rapid_capture.py.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab.rapid_operation_facts import OperationFacts


def main(argv=None):
    parser = argparse.ArgumentParser(description=(__doc__ + "\nRolling v6 lanes require a prospectively bound scheduling capsule in each plan."))
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--spec-2", type=Path, help="second lane spec; only plan receipt may differ for a g02 successor")
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--installation", type=Path, help="prospectively published zero-credit capture-control capsule")
    parser.add_argument("--lane", action="append",
                        help="exact official campaign name; provide exactly twice")
    for index in (1, 2):
        parser.add_argument(f"--declaration-{index}", type=Path, help="registered class block declaration")
        parser.add_argument(f"--mode-{index}", choices=("undefended", "front", "tamaraw", "buflo", "cs-buflo"))
        parser.add_argument(f"--generation-{index}", type=int, default=1)
        parser.add_argument(f"--activation-{index}", type=Path, help="actual qualified runtime activation for a failed lane")
    parser.add_argument("--predecessor-1", type=Path)
    parser.add_argument("--predecessor-2", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="new formal authority JSON file")
    args = parser.parse_args(argv)
    try:
        if args.lane is not None:
            if args.declaration_1 is not None or args.declaration_2 is not None or args.mode_1 is not None or args.mode_2 is not None:
                raise ValueError("choose ordinary lane names or registered block requests")
            context = OperationFacts()
            with context.scope():
                path = formal.prepare_batch(args.spec, args.evidence_root, args.lane, args.output,
                                            [args.predecessor_1, args.predecessor_2], second_spec=args.spec_2,
                                            installation=args.installation, _context=context)
        else:
            if any(value is None for value in (args.declaration_1, args.declaration_2, args.mode_1, args.mode_2)):
                raise ValueError("registered preparation needs a declaration and defense for each worker")
            requests = [dict(declaration=getattr(args, f"declaration_{index}"),
                mode=getattr(args, f"mode_{index}"), generation=getattr(args, f"generation_{index}"),
                activation=getattr(args, f"activation_{index}"), predecessor=getattr(args, f"predecessor_{index}"))
                for index in (1, 2)]
            path = formal.prepare_registered_batch(args.spec, args.evidence_root, requests, args.output,
                                                   second_spec=args.spec_2, installation=args.installation)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"formal parallel preparation: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"authority": str(path), "formal_accepted_trace_count": 0,
                      "scientific_credit": False}, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
