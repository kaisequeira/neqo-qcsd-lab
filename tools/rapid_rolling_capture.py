#!/usr/bin/env python3
"""Start serial formal lanes before all fifty sites have finished admission.

Enroll the next one to five eligible sites in the frozen candidate order.
Each setting starts after its own successful full canary and the batch's real
response-only qualification. Failed lanes use a fresh immediate generation;
completed peers remain unchanged. The final target stays 50 x 5 x 64.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_rolling_capture as rolling


def _spec(path, spec):
    rolling._write_spec(path, spec)
    return str(path)


def run(args):
    if args.command == "scheduling":
        from qcsd_lab.rapid_rolling_schedule import publish_schedule
        return {"scheduling": publish_schedule(lanes.load_capture_spec(args.spec),
            rolling.load_runtime(args.runtime_spec), args.qualification_spec,
            rolling._ref(args.original_canonical), rolling._ref(args.current_canonical),
            args.output, reason=args.reason), "scientific_credit": False}
    if args.command == "canary-equivalence":
        from qcsd_lab.rapid_rolling_readiness import publish_source_equivalence
        old, current = rolling.load_runtime(args.original_runtime_spec), rolling.load_runtime(args.runtime_spec)
        reference = lanes._load(lanes._read(args.canary))
        return publish_source_equivalence(reference, args.output,
            original_runtime={key: old[key] for key in lanes.RUNTIME_KEYS},
            runtime={key: current[key] for key in lanes.RUNTIME_KEYS},
            current_inventory=rolling._ref(args.current_inventory), mode=args.mode)
    if args.command == "init":
        root = lanes._regular_directory(args.evidence_root)
        path = rolling.initialize_study(args.acquisition_root, root, rolling.load_runtime(args.runtime_spec))
        return {"policy": str(path), "formal_trace_target": 16000, "scientific_credit": False}
    if args.command == "enroll":
        path = rolling.enroll(args.evidence_root, acquisition_root=args.acquisition_root, count=args.count)
        batch, classes = rolling.verify_enrollment(path)
        return {"enrollment": str(path), "batch_sites": len(batch["selected_candidate_ids"]),
                "enrolled_sites": len(classes), "scientific_credit": False}
    if args.command == "front-amendment":
        from qcsd_lab.rapid_front_capture_amendment import publish_amendment
        path = publish_amendment(args.enrollment, rolling.load_runtime(args.runtime_spec), args.output,
                                 capture_policy=args.capture_policy)
        return {"front_capture_amendment": rolling._ref(path), "scientific_credit": False}
    if args.command == "plan":
        readiness = lanes._load(lanes._read(args.readiness)) if args.readiness else {}
        runtime = rolling.load_runtime(args.runtime_spec) if args.runtime_spec else None
        path = rolling.publish_plan(args.evidence_root, args.enrollment, args.qualification_spec,
                                    args.output, readiness=readiness, runtime_inputs=runtime,
                                    scheduling=rolling._ref(args.scheduling) if args.scheduling else None,
                                    front_capture_amendment=args.front_capture_amendment)
        spec = rolling.capture_spec(args.evidence_root, args.enrollment, args.qualification_spec, path)
        _, plan = rolling.verify_capture_plan(spec)
        return {"plan": str(path), "spec": _spec(args.spec_output, spec),
                "planned_traces": plan["planned_trace_count"], "ready_settings": sorted(readiness),
                "scientific_credit": False}
    if args.command in {"publish-manifest", "verify-manifest"}:
        if args.command == "publish-manifest":
            references = lanes._load(lanes._read(args.lane_closures))
            if not isinstance(references, list):
                raise ValueError("rolling lane closures require an explicit list of immutable references")
            return rolling.publish_corpus(args.evidence_root, references, args.output)
        return rolling.verify_corpus_manifest(args.evidence_root, args.manifest)
    spec = lanes.load_capture_spec(args.spec)
    if args.command == "launch":
        payload = lanes._payload(spec.plan_receipt, lanes.PLAN_TYPE)
        if (type(payload.get("study_version")) is not int or payload["study_version"] != 6
            or payload.get("cohort_generation") != "rolling-50"):
            raise ValueError("rolling launch requires its prospective version-six plan")
        # launch_lane independently verifies the full plan in the actual bound
        # image and reopens that proof before publishing the lane intent.
    else:
        rolling.verify_capture_plan(spec)
    root = lanes._regular_directory(args.evidence_root)
    if args.command == "successor":
        path = rolling.publish_successor(spec, args.lane, args.generation, args.output)
        return {"plan": str(path), "spec": _spec(args.spec_output, replace(spec, plan_receipt=path)),
                "scientific_credit": False}
    if args.command == "launch":
        receipt = lanes.launch_lane(spec, root, args.lane, predecessor_intent=args.predecessor_intent)
        return {"receipt": str(receipt), "scientific_credit": "formal-only-if-bound-to-rolling-enrollment"}
    if args.command == "retire-lane":
        return {"receipt": str(lanes.retire_lane(spec, root, args.intent,
            batch_authority=args.batch_authority, batch_output=args.batch_output,
            public_started=args.public_started, public_completed=args.public_completed)), "scientific_credit": False}
    if args.command == "complete-lane":
        return rolling.check_lane_in_image(spec, root, args.intent, complete=True)
    return rolling.check_lane_in_image(spec, root, args.receipt, complete=False)


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("scheduling", "canary-equivalence", "init", "enroll", "front-amendment", "plan", "successor", "launch", "complete-lane", "verify-lane",
                 "retire-lane", "publish-manifest", "verify-manifest"):
        item = commands.add_parser(name)
        if name not in {"canary-equivalence", "scheduling", "front-amendment"}:
            item.add_argument("--evidence-root", type=Path, required=True)
        if name == "scheduling":
            for flag in ("spec", "runtime-spec", "qualification-spec", "original-canonical", "current-canonical", "output"):
                item.add_argument("--" + flag, type=Path, required=True)
            item.add_argument("--reason", required=True)
        elif name == "canary-equivalence":
            item.add_argument("--canary", type=Path, required=True)
            item.add_argument("--original-runtime-spec", type=Path, required=True)
            item.add_argument("--runtime-spec", type=Path, required=True)
            item.add_argument("--current-inventory", type=Path, required=True)
            item.add_argument("--mode", choices=plan.MODES, required=True)
            item.add_argument("--output", type=Path, required=True)
        elif name == "init":
            item.add_argument("--acquisition-root", type=Path, required=True)
            item.add_argument("--runtime-spec", type=Path, required=True)
        elif name == "enroll":
            item.add_argument("--acquisition-root", type=Path)
            item.add_argument("--count", type=int, choices=range(1, 6), default=1)
        elif name == "plan":
            item.add_argument("--enrollment", type=Path, required=True)
            item.add_argument("--qualification-spec", type=Path, required=True)
            item.add_argument("--runtime-spec", type=Path)
            item.add_argument("--front-capture-amendment", type=Path)
            item.add_argument("--readiness", type=Path)
            item.add_argument("--scheduling", type=Path)
            item.add_argument("--output", type=Path, required=True)
            item.add_argument("--spec-output", type=Path, required=True)
        elif name == "front-amendment":
            from qcsd_lab.rapid_front_capture_amendment import CAPTURE_POLICY, WINDOW_CAPTURE_POLICY
            item.add_argument("--enrollment", type=Path, required=True)
            item.add_argument("--runtime-spec", type=Path, required=True)
            item.add_argument("--output", type=Path, required=True)
            item.add_argument("--capture-policy", choices=(CAPTURE_POLICY, WINDOW_CAPTURE_POLICY), default=CAPTURE_POLICY)
        elif name in {"publish-manifest", "verify-manifest"}:
            item.add_argument("--lane-closures" if name == "publish-manifest" else "--manifest", type=Path, required=True)
            if name == "publish-manifest":
                item.add_argument("--output", type=Path, required=True)
        else:
            item.add_argument("--spec", type=Path, required=True)
            if name in {"launch", "successor"}:
                item.add_argument("--lane", required=True)
                if name == "launch":
                    item.add_argument("--predecessor-intent", type=Path)
                else:
                    item.add_argument("--generation", type=int, required=True)
                    item.add_argument("--output", type=Path, required=True)
                    item.add_argument("--spec-output", type=Path, required=True)
            else:
                item.add_argument("--receipt" if name == "verify-lane" else "--intent", type=Path, required=True)
                if name == "retire-lane":
                    for flag in ("batch-authority", "batch-output", "public-started", "public-completed"):
                        item.add_argument("--" + flag, type=Path)
    return parser


def main(argv=None):
    try:
        value = run(_parser().parse_args(argv))
    except (ValueError, TypeError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"rolling capture: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(value, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
