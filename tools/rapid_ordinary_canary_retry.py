#!/usr/bin/env python3
"""Publish explicit readiness from an original-image ordinary deep retry."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from qcsd_lab import rapid_ordinary_canary_retry as retry
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_lane_evidence as lanes


def reference(path):
    path = Path(path).absolute()
    return {"path": str(path), "sha256": readiness._sha(readiness._read(path))}


def operation(root):
    return {key: reference(root / ("undefended-deep" + suffix))
        for key, suffix in (("started", "-started.json"), ("completed", "-completed.json"),
                            ("stdout", ".stdout.log"), ("stderr", ".stderr.log"))}


def run(args):
    from qcsd_lab.rapid_rolling_capture import RUNTIME_TYPE
    runtime_spec = readiness._json(readiness._read(args.runtime_spec.absolute()))
    if (set(runtime_spec) != {"schema_version", "artifact_type", "inputs"}
        or type(runtime_spec["schema_version"]) is not int or runtime_spec["schema_version"] != 1
        or runtime_spec["artifact_type"] != RUNTIME_TYPE):
        raise ValueError("ordinary retry runtime requires the exact public runtime schema")
    runtime = runtime_spec["inputs"]
    if args.command == "runtime-overlay":
        from qcsd_lab.rapid_rolling_capture import RUNTIME_FIELDS, _runtime
        if set(runtime) != RUNTIME_FIELDS:
            raise ValueError("ordinary retry runtime has missing or extra fields")
        module_root = readiness._path(args.module_root.absolute(), directory=True)
        for name, digest in retry._sources().items():
            readiness._read(module_root / "src/qcsd_lab" / name, digest)
        from qcsd_lab.util import durable_create
        value = {**runtime_spec, "inputs": _runtime({**runtime, "module_root": str(module_root)})}
        durable_create(args.output, readiness._encoded(value))
        return {"runtime_spec": reference(args.output), "actual_runtime_rebuilt": False, "scientific_credit": False}
    directory, root = args.plan.absolute().parent, readiness._path(args.retry_root.absolute(), directory=True)
    raw = readiness._json(readiness._read(args.plan.absolute()))
    if raw.get("expected_lab_commit") != readiness._json(readiness._read(Path(runtime["source_manifest"]))).get("lab_commit"):
        raise ValueError("ordinary retry must retain the original measured Source labels")
    value = {"plan": reference(args.plan), "deep_receipt": reference(directory / "undefended-deep-verification.json"),
        "capture": {key: reference(directory / "logs" / ("undefended-capture" + suffix))
            for key, suffix in (("started", "-started.json"), ("completed", "-completed.json"),
                                ("stdout", ".stdout.log"), ("stderr", ".stderr.log"))},
        "deep": operation(root / "operations"), "failed_deep": operation(directory / "logs"),
        "transport_declaration": reference(root / "transport-declaration.json")}
    published = retry.publish(value, {key: runtime[key] for key in lanes.RUNTIME_KEYS}, args.output)
    return {"readiness": reference(args.output), "retry_type": published["artifact_type"],
        "capture_reexecuted": False, "formal_accepted_trace_count": 0, "scientific_credit": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    overlay = sub.add_parser("runtime-overlay")
    overlay.add_argument("--runtime-spec", type=Path, required=True)
    overlay.add_argument("--module-root", type=Path, required=True)
    overlay.add_argument("--output", type=Path, required=True)
    publish = sub.add_parser("publish")
    for name in ("plan", "retry-root", "runtime-spec", "output"):
        publish.add_argument("--" + name, type=Path, required=True)
    print(json.dumps(run(parser.parse_args()), sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
