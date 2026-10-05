#!/usr/bin/env python3
"""Publish explicit ordinary transport authority and renewed formal inputs."""
import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from qcsd_lab import rapid_ordinary_transport_control as transport
from qcsd_lab import rapid_rolling_capture as rolling


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    control = sub.add_parser("publish-control")
    for name in ("plan", "runtime-spec", "output"):
        control.add_argument("--" + name, type=Path, required=True)
    renewal = sub.add_parser("renewal")
    for name in ("runtime-spec", "transport-control", "output"):
        renewal.add_argument("--" + name, type=Path, required=True)
    inputs = sub.add_parser("inputs")
    for name in ("enrollment", "runtime-spec", "ordinary-renewal", "transport-control", "output"):
        inputs.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    runtime = rolling.load_runtime(args.runtime_spec)
    if args.command == "publish-control":
        path = transport.publish_control(args.plan, runtime, args.output)
    elif args.command == "renewal":
        path = transport.publish_renewal(rolling._ref(args.transport_control), runtime, args.output)
    else:
        path = transport.publish_inputs(args.enrollment, runtime, rolling._ref(args.ordinary_renewal),
            rolling._ref(args.transport_control), args.output)
    print(json.dumps({"output": rolling._ref(path), "capture_reexecuted": False,
        "runtime_rebuilt": False, "formal_accepted_trace_count": 0, "scientific_credit": False},
        sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
