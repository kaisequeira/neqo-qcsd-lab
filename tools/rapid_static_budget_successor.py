#!/usr/bin/env python3
"""Declare a retained-prefix response-budget epoch; no network/image actions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from qcsd_lab import supplied_static_budget_successor as budget


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    declare = commands.add_parser("declare")
    declare.add_argument("--context", type=Path, required=True)
    declare.add_argument("--original-context", type=Path, required=True)
    declare.add_argument("--retained-attempt", type=Path, required=True)
    declare.add_argument("--retained-operation", type=Path, action="append", default=[])
    for name in ("status", "transport-roots", "account-terminal"):
        item = commands.add_parser(name)
        item.add_argument("--context", type=Path, required=True)
        if name == "account-terminal":
            item.add_argument("--position", type=int, required=True)
    return value


def run(args):
    if args.command == "declare":
        budget.initialize_context(args.context, original_context=args.original_context,
            retained_attempt=args.retained_attempt, retained_operations=args.retained_operation)
    context = budget.load_context(args.context)
    if args.command == "account-terminal":
        path = budget.account_terminal(context, args.position)
        facts = budget.verify_terminal(path, context)
        return {"terminal": str(path), "outcome": facts["outcome"], **budget.refs.ZERO}
    if args.command == "transport-roots":
        return {"read_only_roots": [str(path) for path in budget.roots(context)], **budget.refs.ZERO}
    status = budget.acquisition_status(context)
    return {"context": str(context.root), "prospective_get_context": str(context.active.root),
        "first_prospective_position": context.provenance["first_prospective_position"],
        "response_bytes_per_new_class": budget.RESPONSE_BYTES, "timeout_seconds": budget.TIMEOUT_SECONDS,
        "recording_megabytes_per_new_class": budget.RECORDING_MEGABYTES,
        "counts": {key: status[key] for key in ("terminal_count", "admitted", "operational-deferred", "input-ineligible", "next_candidate_position")},
        "original_admission_identity_preserved": budget.identity(context) == budget.static.identity(context.original),
        **budget.refs.ZERO}


def main(argv=None):
    try:
        result = run(parser().parse_args(argv))
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"static budget successor: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
