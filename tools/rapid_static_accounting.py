#!/usr/bin/env python3
"""Current-Source-owned accounting of genuine closed ordinary GET terminals.

This command performs no GET, browser, Docker or Native action. The historical
guarded Core002 operator remains separate and retains its original inventory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from qcsd_lab import rapid_admission_operation_facts as observed
from qcsd_lab import supplied_static_admission as static
from qcsd_lab import supplied_static_budget_successor as budget
from qcsd_lab import supplied_static_get as get
from qcsd_lab import supplied_static_bootstrap_get as bootstrap

CORE_SHA256 = "a297fd337517ddffc30fc6e08b5961e2556f9311cbe5f7837baa0209bcf298d1"


def _names():
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
    names = set(subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard", "-z"], env=env).decode().split("\0")) - {"", "neqo-qcsd"}
    names.update("neqo-qcsd/" + name for name in subprocess.check_output(["git", "-C", str(ROOT / "neqo-qcsd"), "ls-files", "-z"], env=env).decode().split("\0") if name)
    return names


def bind_source(context, inventory, digest):
    raw = context.watch_file(inventory)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("accounting current Source inventory changed")
    files = json.loads(raw)["files"]
    if set(files) != _names():
        raise ValueError("accounting current Source membership differs")
    for relative, expected in files.items():
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("accounting Source inventory path escapes")
        path = ROOT / relative
        raw = context.watch_file(path)
        if (hashlib.sha256(raw).hexdigest() != expected["sha256"]
                or path.stat().st_mode & 0o7777 != expected["mode"]):
            raise ValueError("accounting current Source file bytes or mode differ")
    core = Path(budget.__file__).absolute()
    if core != ROOT / "src/qcsd_lab/supplied_static_budget_successor.py" or hashlib.sha256(core.read_bytes()).hexdigest() != CORE_SHA256:
        raise ValueError("accounting requires the exact unchanged Core002 module")
    return files


def account_budget(root, position):
    """Create-only guarded parent followed by the unchanged Core account body."""
    from qcsd_lab.static_evidence_transport import _path
    with observed.action():
        context = budget.load_context(root)
        if position != budget.acquisition_status(context)["next_candidate_position"]:
            raise ValueError("budget accounting cannot skip or repeat an ordered position")
        static.verify_terminal(static.terminal_path(context.active, position), context.active)
        output = budget.terminal_path(context, position)
        attempts = context.root / "attempts"
        _path(context.root, directory=True)
        observed.before_publication()
        if attempts.exists() or attempts.is_symlink():
            _path(attempts, directory=True)
        else:
            attempts.mkdir(mode=0o700, parents=False, exist_ok=False)
            get.util.fsync_directory(context.root)
        output.parent.mkdir(mode=0o700, parents=False, exist_ok=False)
        _path(output.parent, directory=True)
        get.util.fsync_directory(output.parent)
        get.util.fsync_directory(attempts)
        terminal = budget.account_terminal(context, position)
        facts = budget.verify_terminal(terminal, budget.load_context(root))
        return {"action_type": observed.ACTION_TYPE, "terminal": str(terminal),
                "outcome": facts["outcome"], **budget.refs.ZERO}


def run(args):
    with observed.action() as context:
        files = bind_source(context, args.source_inventory, args.source_inventory_sha256)
        with bootstrap.host_accounting_scope(context, args.bootstrap_authority, args.bootstrap_authority_sha256):
            result = _run_bound(args)
        if set(files) != _names():
            raise ValueError("accounting Source membership changed before success")
        return result


def _run_bound(args):
        if args.command == "account-budget":
            result = account_budget(args.context, args.position)
        else:
            current = static.load_context(args.context)
            namespace = get._load(get._read(args.namespace)) if getattr(args, "namespace", None) else None
            if args.command == "admit":
                path = static.admit(current, args.position, args.get_root,
                    policies=get._load(get._read(args.traffic_policies)), namespace=namespace)
            elif args.command == "defer-get":
                path = static.record_get_deferral(current, args.position, args.get_root, namespace=namespace)
            else:
                path = args.terminal
            facts = static.verify_terminal(path, current)
            result = {"action_type": observed.ACTION_TYPE, "terminal": str(path),
                      "outcome": facts["outcome"], "scientific_credit": False,
                      "formal_accepted_trace_count": 0}
        return result


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--source-inventory", type=Path, required=True)
    value.add_argument("--source-inventory-sha256", required=True)
    value.add_argument("--bootstrap-authority", type=Path, required=True)
    value.add_argument("--bootstrap-authority-sha256", required=True)
    commands = value.add_subparsers(dest="command", required=True)
    for name in ("account-budget", "admit", "defer-get", "verify-terminal"):
        item = commands.add_parser(name)
        item.add_argument("--context", type=Path, required=True)
        if name == "verify-terminal":
            item.add_argument("--terminal", type=Path, required=True)
        else:
            item.add_argument("--position", type=int, required=True)
        if name in {"admit", "defer-get"}:
            item.add_argument("--get-root", type=Path, required=True)
            item.add_argument("--namespace", type=Path)
        if name == "admit":
            item.add_argument("--traffic-policies", type=Path, required=True)
    return value


def main(argv=None):
    try:
        result = run(parser().parse_args(argv))
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(json.dumps({"error_type": type(error).__name__, "accounting_closed": False}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
