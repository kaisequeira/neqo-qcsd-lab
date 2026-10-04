#!/usr/bin/env python3
"""Append independently GET-qualified whole browser graphs to the static study."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from qcsd_lab import whole_graph_supplement as whole
from qcsd_lab import supplied_static_get as get


def run(args):
    if args.command == "context-init":
        path = whole.initialize_context(args.context, original_context=args.original_context, plans=args.discovery_plan,
            graph_inputs=args.graph_input, failed_discoveries=args.failed_discovery,
            expected_runtime=get._load(get._read(args.runtime_binding)), parent_context=args.parent_context)
        context = whole.load_context(args.context)
        return {"context": str(path), "candidate_count": len(context.candidates), "data_role": whole.ROLE}
    context = whole.load_context(args.context)
    namespace = get._load(get._read(args.namespace)) if getattr(args, "namespace", None) else None
    if args.command == "execute-get":
        proof = whole.execute_get(args.context, args.position, args.get_root)
        return {"proof": str(args.get_root / "full-get-proof.json"), "resource_count": proof["resource_count"]}
    if args.command == "namespace":
        value = whole.namespace_mapping(args.get_root, args.execution_root,
            started=args.started, completed=args.completed, stdout=args.stdout, stderr=args.stderr,
            expected_runtime=context.provenance["runtime_binding"], failed_phase=args.failed_phase)
        get._json(args.output, value)
        return {"namespace": str(args.output)}
    if args.command == "verify-get":
        proof = whole.reopen_get(args.get_root, context=context, position=args.position, namespace=namespace)
        return {"valid": True, "resource_count": proof["resource_count"]}
    if args.command == "admit":
        path = whole.admit(context, args.position, args.get_root, namespace=namespace)
    elif args.command == "defer":
        path = whole.record_deferral(context, args.position, get_root=args.get_root, namespace=namespace)
    elif args.command == "status":
        status = whole.acquisition_status(context)
        return {"closed_ordered_decisions": len(status["terminal_prefix"])}
    else:
        path = args.terminal
    facts = whole.verify_terminal(path, context)
    return {"terminal": str(path), "candidate_id": facts["candidate_id"], "outcome": facts["outcome"]}


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("context-init", help="HOST: freeze appended declaration order and complete input evidence")
    for name in ("context", "original-context", "runtime-binding"):
        init.add_argument("--" + name, type=Path, required=True)
    init.add_argument("--discovery-plan", type=Path, action="append", required=True)
    init.add_argument("--graph-input", type=Path, action="append", default=[])
    init.add_argument("--failed-discovery", type=Path, action="append", default=[])
    init.add_argument("--parent-context", type=Path)
    for name in ("execute-get", "verify-get", "admit", "defer", "namespace", "verify-terminal", "status"):
        command = commands.add_parser(name)
        command.add_argument("--context", type=Path, required=True)
        if name in ("execute-get", "verify-get", "admit", "defer"):
            command.add_argument("--position", type=int, required=True)
            command.add_argument("--get-root", type=Path, required=name != "defer")
        if name in ("verify-get", "admit", "defer"):
            command.add_argument("--namespace", type=Path)
        if name == "verify-terminal":
            command.add_argument("--terminal", type=Path, required=True)
        if name == "namespace":
            command.add_argument("--failed-phase", choices=("bootstrap", "full"))
            for key in ("get-root", "execution-root", "started", "completed", "stdout", "stderr", "output"):
                command.add_argument("--" + key, type=Path, required=True)
    return root


def main():
    args = parser().parse_args()
    try:
        value = run(args)
    except (ValueError, OSError, KeyError) as error:
        # Resource/response values and producer stderr stay in retained files.
        print(json.dumps({"operation": args.command, "status": "failed", "error_type": type(error).__name__,
                          "scientific_credit": False, "formal_accepted_trace_count": 0}, sort_keys=True))
        return 1
    print(json.dumps({**value, "scientific_credit": False, "formal_accepted_trace_count": 0}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
