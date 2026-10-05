#!/usr/bin/env python3
"""Prospective per-class selected budget input and append-only enrollment."""
from pathlib import Path
import argparse
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from qcsd_lab import rapid_selected_capture_input as plain
from qcsd_lab import rapid_selected_budget_input as selected
from qcsd_lab import rapid_per_class_selected_enrollment as ledger
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab.rapid_operation_facts import OperationFacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit-budget")
    for name in ("output", "source-root", "source-inventory", "context", "terminal"):
        audit.add_argument("--" + name, type=Path, required=True)
    publish = sub.add_parser("publish-input")
    publish.add_argument("--audit", type=Path, required=True)
    publish.add_argument("--candidate-id", required=True)
    publish.add_argument("--output", type=Path, required=True)
    prepare = sub.add_parser("prepare-input")
    prepare.add_argument("--input", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    init = sub.add_parser("init")
    for name in ("evidence-root", "seed-enrollment", "seed-progress", "runtime-spec"):
        init.add_argument("--" + name, type=Path, required=True)
    enroll = sub.add_parser("enroll")
    for name in ("evidence-root", "acquisition-root", "inputs"):
        enroll.add_argument("--" + name, type=Path, required=True)
    check = sub.add_parser("verify-enrollment")
    check.add_argument("--enrollment", type=Path, required=True)
    args = parser.parse_args()
    context = OperationFacts()
    with context.scope():
        if args.command == "audit-budget":
            result = selected.audit_budget(args.output, source_root=args.source_root,
                source_inventory=plain.reference(args.source_inventory), context=args.context, terminal=args.terminal)
        elif args.command == "publish-input":
            result = selected.publish_input(args.output, audit=args.audit, candidate_id=args.candidate_id)
        elif args.command == "prepare-input":
            result = selected.prepare_input(args.input, args.output)
        elif args.command == "init":
            result = ledger.initialize(args.evidence_root, seed_enrollment=args.seed_enrollment,
                seed_progress=plain.reference(args.seed_progress), runtime=rolling.load_runtime(args.runtime_spec))
        elif args.command == "enroll":
            value = json.loads(plain.reopen(plain.reference(args.inputs)).read_bytes())
            if set(value) != {"inputs", "prepared_workloads"}:
                raise ValueError("per-class enrollment map fields differ")
            result = ledger.enroll(args.evidence_root, acquisition_root=args.acquisition_root, **value)
        else:
            batch, classes, policy = ledger.verify_enrollment(args.enrollment)
            rows, limits = ledger.select_classes(batch, classes, policy)
            context.check()
            print(json.dumps({"enrolled_classes": len(classes), "selected_classes": len(rows), "capture_limits": limits,
                "formal_credit_added": 0}), flush=True)
            return 0
        context.check()
        print(json.dumps({"reference": plain.reference(result), "formal_credit_added": 0}), flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
