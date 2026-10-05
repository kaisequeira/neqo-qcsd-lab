#!/usr/bin/env python3
"""Prepare serial ordinary formal lanes without padding qualification."""
from pathlib import Path
import argparse
import json
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from qcsd_lab import rapid_undefended_capture as ordinary
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab.rapid_operation_facts import OperationFacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    for name in ("renew", "inputs", "plan"):
        item = actions.add_parser(name)
        item.add_argument("--enrollment", type=Path, required=True)
        if name != "renew":
            item.add_argument("--runtime-spec", type=Path, required=True)
        item.add_argument("--output", type=Path, required=True)
        if name == "inputs":
            item.add_argument("--ordinary-renewal", type=Path)
        elif name == "plan":
            item.add_argument("--ordinary-input", type=Path, required=True)
            item.add_argument("--ordinary-readiness", type=Path, required=True)
            item.add_argument("--spec-output", type=Path, required=True)
            item.add_argument("--application-body-identity-policy")
    args = parser.parse_args()
    with OperationFacts().scope() as context:
        runtime = None
        if args.action != "renew":
            context.watch_file(args.runtime_spec)
            runtime = rolling.load_runtime(args.runtime_spec)
        if args.action == "renew":
            path = ordinary.publish_renewal(args.enrollment, args.output)
            result = {"ordinary_renewal": rolling._ref(path), "scientific_credit": False}
        elif args.action == "inputs":
            path = ordinary.publish_inputs(args.enrollment, runtime, args.output,
                renewal=rolling._ref(args.ordinary_renewal) if args.ordinary_renewal is not None else None)
            result = {"ordinary_input": rolling._ref(path), "scientific_credit": False}
        else:
            ready = lanes._load(context.watch_file(args.ordinary_readiness))
            if not isinstance(ready, dict) or set(ready) != {"undefended"}:
                raise ValueError("ordinary plan requires the exact public ordinary readiness map")
            batch, _, _ = rolling._verify_enrollment(args.enrollment)
            path = rolling.publish_plan(rolling._open_ref(batch["policy"]).parent,
                args.enrollment, args.ordinary_input, args.output,
                readiness=ready, runtime_inputs=runtime,
                application_body_identity_policy=args.application_body_identity_policy, _context=context)
            spec = rolling.capture_spec(rolling._open_ref(batch["policy"]).parent,
                args.enrollment, args.ordinary_input, path)
            _, payload = rolling.verify_capture_plan(spec, _context=context)
            context.check()
            rolling._write_spec(args.spec_output, spec)
            result = {"plan": rolling._ref(path), "spec": rolling._ref(args.spec_output),
                "planned_traces": payload["planned_trace_count"], "scientific_credit": False}
        context.check()
        print(json.dumps(result, sort_keys=True, allow_nan=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
