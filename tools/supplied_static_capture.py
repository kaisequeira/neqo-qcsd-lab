#!/usr/bin/env python3
"""Declare, verify and enroll complete fixed-resource GETs; never browser evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from qcsd_lab import supplied_static_admission as admission
from qcsd_lab import supplied_static_bootstrap_get as bootstrap
from qcsd_lab import supplied_static_get as get
from qcsd_lab import supplied_static_preparation as preparation


def run(args):
    if args.command == "context-init":
        binding = get.runtime_binding(get._load(get._read(args.runtime_binding)))
        args.context.mkdir(mode=0o700, parents=False, exist_ok=False)
        path = admission.initialize_context(args.context, args.source,
                source_sha256=args.source_sha256, expected_runtime=binding,
                max_response_bytes=args.max_response_bytes, capture_megabytes=args.capture_megabytes,
                parent_context=args.parent_context,
                candidate_order=get._load(get._read(args.candidate_order)) if args.candidate_order else None,
                ordering_rationale=args.ordering_rationale)
        context = admission.load_context(args.context)
        return {"provenance": str(path), "candidate_count": len(context.candidates),
                "data_role": preparation.ROLE, "scientific_credit": False, "formal_accepted_trace_count": 0}
    context = admission.load_context(args.context)
    namespace = get._load(get._read(args.namespace)) if getattr(args, "namespace", None) else None
    if args.command == "execute-get":
        proof = bootstrap.execute(args.context, args.position, args.get_root,
                    max_response_bytes=args.max_response_bytes, timeout_seconds=args.timeout_seconds)
        return {"proof": str(args.get_root / "full-get-proof.json"), "resource_count": proof["resource_count"],
                "origin_count": proof["origin_count"], "scientific_credit": False, "formal_accepted_trace_count": 0}
    if args.command == "namespace":
        mapping = preparation.namespace_mapping(args.get_root, args.execution_root,
            started=args.started, completed=args.completed, stdout=args.stdout, stderr=args.stderr,
            expected_runtime=context.provenance["runtime_binding"])
        get._json(args.output, mapping)
        return {"namespace": preparation.reference(args.output), "scientific_credit": False}
    if args.command == "verify-get":
        proof = bootstrap.validate_proof(args.get_root, **admission._get_arguments(context, args.position), namespace=namespace)
        return {"valid": True, "resource_count": proof["resource_count"], "origin_count": proof["origin_count"],
                "scientific_credit": False, "formal_accepted_trace_count": 0}
    if args.command == "admit":
        policies = get._load(get._read(args.traffic_policies))
        path = admission.admit(context, args.position, args.get_root, policies=policies, namespace=namespace)
    elif args.command == "defer-get":
        path = admission.record_get_deferral(context, args.position, args.get_root, namespace=namespace)
    elif args.command == "input-decision":
        path = admission.record_input_rejection(context, args.position)
    else:
        path = args.terminal
    facts = admission.verify_terminal(path, context)
    return {"terminal": str(path), "candidate_id": facts["candidate_id"], "outcome": facts["outcome"],
            "data_role": preparation.ROLE, "scientific_credit": False, "formal_accepted_trace_count": 0}


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    for name in ("context-init", "execute-get", "verify-get", "namespace", "admit", "defer-get", "input-decision", "verify-terminal"):
        item = commands.add_parser(name)
        item.add_argument("--context", type=Path, required=True)
        if name == "context-init":
            item.add_argument("--source", type=Path, required=True)
            item.add_argument("--source-sha256", required=True)
            item.add_argument("--runtime-binding", type=Path, required=True)
            item.add_argument("--max-response-bytes", type=int, default=16_777_216)
            item.add_argument("--capture-megabytes", type=int, default=64)
            item.add_argument("--parent-context", type=Path)
            item.add_argument("--candidate-order", type=Path)
            item.add_argument("--ordering-rationale")
            continue
        if name != "verify-terminal":
            item.add_argument("--position", type=int, required=True)
        if name in ("execute-get", "verify-get", "admit", "defer-get", "namespace"):
            item.add_argument("--get-root", type=Path, required=True)
        if name in ("verify-get", "admit", "defer-get"):
            item.add_argument("--namespace", type=Path)
        if name == "execute-get":
            item.add_argument("--max-response-bytes", type=int)
            item.add_argument("--timeout-seconds", type=int, default=120)
        if name == "admit":
            item.add_argument("--traffic-policies", type=Path, required=True)
        if name == "namespace":
            item.add_argument("--execution-root", type=Path, required=True)
            for key in ("started", "completed", "stdout", "stderr", "output"):
                item.add_argument("--" + key, type=Path, required=True)
        if name == "verify-terminal":
            item.add_argument("--terminal", type=Path, required=True)
    return value


def main(argv=None):
    try:
        result = run(parser().parse_args(argv))
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"static capture: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
