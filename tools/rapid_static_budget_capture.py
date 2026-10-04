#!/usr/bin/env python3
"""Declare a typed budget-prefix/whole-graph-tail enrollment selector."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from qcsd_lab import static_budget_capture as capture
from qcsd_lab import supplied_static_budget_successor as budget


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    declare = commands.add_parser("declare-mixed-context")
    declare.add_argument("--context", type=Path, required=True)
    declare.add_argument("--budget-context", type=Path, required=True)
    declare.add_argument("--supplement-context", type=Path, required=True)
    declare.add_argument("--parent-context", type=Path)
    status = commands.add_parser("status")
    status.add_argument("--context", type=Path, required=True)
    account = commands.add_parser("account-terminal")
    account.add_argument("--context", type=Path, required=True)
    account.add_argument("--position", type=int, required=True)
    return value


def run(args):
    if args.command == "account-terminal":
        path = capture.account_terminal(budget.load_context(args.context), args.position)
        return {"terminal": str(path), **capture.refs.ZERO}
    if args.command == "declare-mixed-context":
        capture.initialize_context(args.context, budget_context=args.budget_context,
            supplement_context=args.supplement_context, parent_context=args.parent_context)
    context = capture.load_context(args.context)
    return {"context": str(context.root), **capture.acquisition_status(context)}


if __name__ == "__main__":
    print(json.dumps(run(parser().parse_args()), sort_keys=True))
