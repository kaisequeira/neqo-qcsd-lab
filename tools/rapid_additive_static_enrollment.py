#!/usr/bin/env python3
"""Create append-only class membership from genuinely admitted complete inputs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from qcsd_lab import rapid_additive_static_enrollment as additive
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import rapid_rolling_capture as rolling


def input_map(path: Path) -> dict:
    value = selected.get._load(selected.get._read(path))
    if not isinstance(value, dict) or not value:
        raise ValueError("input map needs candidate keys and exact regular receipt/manifest paths")
    result = {}
    for candidate_id, item in value.items():
        if not isinstance(candidate_id, str) or not candidate_id:
            raise ValueError("input map candidate identity is invalid")
        result[candidate_id] = selected.reference(Path(item)) if isinstance(item, str) else dict(item)
        selected.reopen(result[candidate_id])
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("initialize")
    for name in ("root", "seed-enrollment", "seed-selection-audit", "seed-inputs", "seed-progress", "runtime-spec"):
        initialize.add_argument("--" + name, type=Path, required=True)
    enroll = commands.add_parser("enroll")
    for name in ("root", "inputs", "prepared-workloads"):
        enroll.add_argument("--" + name, type=Path, required=True)
    enroll.add_argument("--acquisition-root", type=Path)
    verify = commands.add_parser("verify-enrollment")
    verify.add_argument("--enrollment", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "initialize":
        result = additive.initialize(args.root, seed_enrollment=args.seed_enrollment,
            runtime=rolling.load_runtime(args.runtime_spec), seed_selection_audit=args.seed_selection_audit,
            seed_inputs=input_map(args.seed_inputs), seed_progress=selected.reference(args.seed_progress))
        policy = additive.verify_policy(args.root)
        summary = {"receipt": selected.reference(result), "retained_classes": len(policy["seed_classes"]),
            "retained_sample_anchor": policy["seed_progress"], "formal_credit_added": 0}
    else:
        result = (additive.enroll(args.root, acquisition_root=args.acquisition_root,
            inputs=input_map(args.inputs), prepared_workloads=input_map(args.prepared_workloads))
            if args.command == "enroll" else args.enrollment)
        batch, classes, _ = additive.verify_enrollment(result)
        summary = {"receipt": selected.reference(result), "enrolled_classes": len(classes),
            "new_selected_classes": len(batch["selected_candidate_ids"]),
            "unassessed_reservations": len(batch["unassessed_reservations"]), "formal_credit_added": 0}
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f"additive selected enrollment: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(2)
