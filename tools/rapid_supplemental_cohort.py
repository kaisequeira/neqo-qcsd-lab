#!/usr/bin/env python3
"""Declare a rapid50 supplement queue without replaying its static predecessor."""
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from qcsd_lab import rapid_supplemental_cohort as cohort
from qcsd_lab import supplied_static_get as get


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--seed-enrollment", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--runtime-binding", type=Path, required=True)
    parser.add_argument("--discovery-plan", type=Path, action="append", required=True)
    parser.add_argument("--graph-input", type=Path, action="append", default=[])
    parser.add_argument("--failed-discovery", type=Path, action="append", default=[])
    args = parser.parse_args()
    from qcsd_lab.rapid_operation_facts import OperationFacts
    with OperationFacts().scope() as action:
        path = cohort.initialize(args.context, seed_enrollment=args.seed_enrollment,
            profile=args.profile, plans=args.discovery_plan, graph_inputs=args.graph_input,
            failed_discoveries=args.failed_discovery,
            expected_runtime=get._load(get._read(args.runtime_binding)))
        action.check()
    print(json.dumps({"context": str(path), "scientific_credit": False,
        "formal_accepted_trace_count": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
