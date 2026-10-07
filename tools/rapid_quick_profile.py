#!/usr/bin/env python3
"""Publish an explicit prospective direct launch profile and one-slot plans."""
from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_quick_profile as quick
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab.rapid_operation_facts import OperationFacts


def _runtime_spec(path):
    """An explicit current installation template; it grants no legacy authority."""
    raw = lanes._load(lanes._read(path))
    value = raw["inputs"]
    if set(value) != lanes.PATH_KEYS | {"collection_image_digest", "execution_generation"}:
        raise ValueError("quick runtime specification fields differ")
    return lanes.CaptureSpec(**{key: (Path(item).absolute() if Path(item).is_absolute()
        else (path.absolute().parent / item).absolute()) if key in lanes.PATH_KEYS else item for key, item in value.items()})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    profile = sub.add_parser("profile")
    profile.add_argument("--canonical", type=Path, required=True)
    profile.add_argument("--canonical-sha256", required=True)
    profile.add_argument("--workload", action="append")
    profile.add_argument("--runtime-spec", type=Path)
    plan = sub.add_parser("plan")
    plan.add_argument("--profile", type=Path, required=True)
    plan.add_argument("--profile-sha256", required=True)
    plan.add_argument("--slot-start", type=int, required=True)
    plan.add_argument("--slot-count", type=int, default=1)
    plan.add_argument("--generation", type=int, default=1)
    plan.add_argument("--spec-output", type=Path, required=True)
    for action in (profile, plan):
        action.add_argument("--spec", type=Path, required=True)
        action.add_argument("--spec-sha256", required=True)
        action.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if rolling._ref(args.spec)["sha256"] != args.spec_sha256:
            raise ValueError("quick profile specification digest changed")
        context = OperationFacts()
        with context.scope():
            if args.action == "profile":
                canonical = rolling._ref(args.canonical)
                if canonical["sha256"] != args.canonical_sha256:
                    raise ValueError("quick profile current canonical digest changed")
                spec = _runtime_spec(args.spec)
                result = quick.publish_profile(spec, canonical, args.output,
                    workloads=args.workload, runtime_spec=_runtime_spec(args.runtime_spec) if args.runtime_spec else None,
                    _context=context)
            else:
                reference = rolling._ref(args.profile)
                if reference["sha256"] != args.profile_sha256:
                    raise ValueError("quick profile declared digest changed")
                spec = _runtime_spec(args.spec)
                path = quick.publish_plan(spec, reference, args.output,
                    slot_start=args.slot_start, slot_count=args.slot_count, generation=args.generation)
                candidate = replace(spec, plan_receipt=path)
                quick.verify_plan(candidate, _context=context)
                rolling._write_spec(args.spec_output, candidate)
                result = {"plan": rolling._ref(path), "spec": rolling._ref(args.spec_output)}
            context.check()
        print(json.dumps({"status": "closed", "action": args.action, "result": result,
            "scientific_credit": False}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        print(f"quick profile: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
