#!/usr/bin/env python3
"""Run bounded host operations against an unchanged frozen rapid admission context.

The page budget limits total distinct selected ordinals across context history.
It changes operator routing only; scientific decisions use the frozen CLI.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

sys.dont_write_bytecode = True
BLOCKERS = {"retryable-operational-error", "interrupted-or-pending"}
REGISTRY_RECORD_TYPES = {
    6: "private-frozen-v6-primary-document-policy-ordered-root-log-registry-v6",
    7: "private-frozen-v7-approved-origins-chaff-policy-ordered-root-log-registry-v7",
    8: "private-frozen-v8-bound-buflo-release-policy-ordered-root-log-registry-v8",
    9: "private-frozen-v9-buflo-ack-start-policy-ordered-root-log-registry-v9",
    10: "private-frozen-v10-tamaraw-owned-retry-policy-ordered-root-log-registry-v10",
    11: "private-frozen-v11-front-congestion-omission-policy-ordered-root-log-registry-v11",
    12: "private-frozen-v12-terminal-primary-partial-cell-policy-ordered-root-log-registry-v12",
}
FAILURES = {
    "failed-attempt-needs-explicit-terminal": ("attempt_failure", "ATTEMPT_FAILURE_TYPE", "unsuccessful_attempt_failure_facts", "--attempt-failure"),
    "page-policy-failure-needs-explicit-terminal": ("page_policy_failure", "PAGE_POLICY_FAILURE_TYPE", "page_policy_failure_facts", "--page-policy-failure"),
    "collector-failure-needs-explicit-terminal": ("collector_failure", "COLLECTOR_FAILURE_TYPE", "operational_collector_failure_facts", "--collector-failure"),
}


def now():
    return datetime.now(timezone.utc).isoformat()


def raw(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or linked input: {path}")
    return path.read_bytes()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def control_paths(root):
    root = Path(root).resolve(strict=True)
    stem = root.parent / (".rapid-acquisition-control-" + digest(os.fsencode(root)))
    return Path(str(stem) + ".lock"), Path(str(stem) + ".policy.json")


@contextmanager
def context_lock(root):
    """Reject peer coordinators; retain the inode so release cannot race unlink."""
    import fcntl
    path, _ = control_paths(root)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("another host coordinator holds this admission context") from error
        yield path
    finally:
        os.close(descriptor)


def checked(path, expected):
    value = raw(path)
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None or digest(value) != expected:
        raise ValueError(f"independently bound input changed: {path}")
    return value


def git(root, *args):
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_CONFIG_GLOBAL="/dev/null",
               GIT_CONFIG_SYSTEM="/dev/null", GIT_OPTIONAL_LOCKS="0")
    return subprocess.run(["git", "-C", str(root), *args], env=env, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def clean_source(root, commit):
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None or git(root, "rev-parse", "HEAD").decode().strip() != commit:
        raise ValueError("frozen verifier checkout commit differs")
    if git(root, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("frozen verifier checkout is dirty")


def load_engine(checkout, commit):
    clean_source(checkout, commit)
    if "qcsd_lab.rapid_site_admission" in sys.modules:
        raise ValueError("a different admission engine is already imported")
    sys.path[:0] = [str(checkout / "src"), str(checkout)]
    engine = importlib.import_module("qcsd_lab.rapid_site_admission")
    if Path(engine.__file__).resolve() != checkout / "src/qcsd_lab/rapid_site_admission.py":
        raise ValueError("admission engine did not load from the checked source")
    return engine


def verify_runtime_source(context, checkout, commit):
    source = context.expected_runtime_source
    if source["lab_commit"] != commit:
        raise ValueError("clean verifier source differs from the declared admission runtime")
    expected = source["neqo_commit"]
    if expected != source["neqo_pinned_commit"]:
        raise ValueError("admission runtime Native source is not pinned")
    clean_source(checkout / "neqo-qcsd", expected)
    gitlink = git(checkout, "ls-files", "--stage", "--", "neqo-qcsd").decode().split()
    if len(gitlink) != 4 or gitlink[:3] != ["160000", expected, "0"]:
        raise ValueError("clean verifier Gitlink differs from the declared Native source")


def registry_record_type(context):
    revision = context.selection_amendment_revision
    if type(revision) is not int or revision not in REGISTRY_RECORD_TYPES:
        raise ValueError("coordinator requires a frozen revision6, revision7, revision8, revision9 or revision10 or revision11 admission API")
    expected_policy = "prepared-approved-origins-v1" if revision >= 7 else None
    if context.qualified_chaff_origin_policy != expected_policy:
        raise ValueError("coordinator qualified chaff origin policy differs from its exact revision")
    if revision == 8 and context.buflo_incoming_credit_release_policy != "rapid-v5-half-period-10000us-v1":
        raise ValueError("coordinator BufLO release policy differs from its exact revision")
    if revision in {9, 10, 11, 12} and context.buflo_incoming_credit_release_policy != "rapid-v5-half-period-10000us-ack-start-v2":
        raise ValueError("coordinator BufLO ACK-start policy differs from its exact revision")
    if revision in {10, 11, 12} and context.tamaraw_capture_policy != "rapid-v5-tamaraw-owned-retry-outgoing-10000us-v1":
        raise ValueError("coordinator Tamaraw capture policy differs from its exact revision")
    if revision in {11, 12} and context.front_capture_policy != "rapid-v5-front-bounded-outgoing-congestion-omission-1pct-v1":
        raise ValueError("coordinator FRONT capture policy differs from its exact revision")
    if revision == 12 and context.terminal_primary_partial_cell_policy != "rapid-v5-one-owned-terminal-primary-partial-incoming-cell-v1":
        raise ValueError("coordinator terminal primary partial cell policy differs from its exact revision")
    return REGISTRY_RECORD_TYPES[revision]


def load_registry(engine, context, path, expected, seen=()):
    """Reopen the existing registry chain; actual root decisions use official APIs."""
    path = Path(path).absolute()
    if path in seen or len(seen) >= 64:
        raise ValueError("root registry chain repeats or is unbounded")
    value = engine._load(checked(path, expected))
    fields = {"schema_version", "record_type", "created_at", "provenance_sha256",
              "selection_amendment_sha256", "previous_registry", "root_surveys",
              "scientific_credit", "docker_executed"}
    if (set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["record_type"] != registry_record_type(context)
        or value["provenance_sha256"] != context.provenance_sha256
        or value["selection_amendment_sha256"] != context.selection_amendment_sha256
        or value["scientific_credit"] is not False or value["docker_executed"] is not False
        or set(value["root_surveys"]) != {"curated", "fallback"}
        or engine._utc(value["created_at"]) > datetime.now(timezone.utc)):
        raise ValueError("root registry changed its frozen context or zero-credit role")
    for refs in value["root_surveys"].values():
        if not isinstance(refs, list):
            raise ValueError("root registry raw references are malformed")
        for ref in refs:
            engine._child(context.root, ref)
    previous = value["previous_registry"]
    if previous is not None:
        if not isinstance(previous, dict) or set(previous) != {"path", "sha256"}:
            raise ValueError("root registry predecessor is malformed")
        older = load_registry(engine, context, previous["path"], previous["sha256"], (*seen, path))
        grew = False
        for group, refs in value["root_surveys"].items():
            before = older["root_surveys"][group]
            if len(refs) < len(before) or refs[:len(before)] != before:
                raise ValueError("root registry replaced or reordered prior raw evidence")
            grew |= len(refs) > len(before)
        if not grew or engine._utc(older["created_at"]) > engine._utc(value["created_at"]):
            raise ValueError("root registry successor did not append later evidence")
    return value


def verify_bootstrap(engine, context, checkout, argv):
    if not isinstance(argv, list) or not argv or argv[0] != "docker" or any(not isinstance(x, str) for x in argv):
        raise ValueError("bootstrap must be an explicit Docker argv list")
    image = context.execution_binding["admission_image_digest"]
    if len(argv) < 3 or argv[-2] != image or not argv[-1].endswith("/tools/rapid_acquire.py"):
        raise ValueError("bootstrap changed the bound image or official admission CLI")
    env = [argv[i + 1] for i, word in enumerate(argv[:-1]) if word in {"-e", "--env"}]
    if [entry for entry in env if entry.startswith("QCSD_LAB_IMAGE_DIGEST=")] != [f"QCSD_LAB_IMAGE_DIGEST={image}"]:
        raise ValueError("bootstrap lacks the exact admission image environment")
    mounts = [argv[i + 1].rsplit(":", 2) for i, word in enumerate(argv[:-1]) if word in {"-v", "--volume"}]
    container_source = str(PurePosixPath(argv[-1]).parents[1])
    if [entry for entry in env if entry.startswith("QCSD_LAB_ROOT=")] != [f"QCSD_LAB_ROOT={container_source}"]:
        raise ValueError("bootstrap source root differs from the mounted official CLI")
    source_mounts = [parts for parts in mounts if len(parts) == 3 and parts[1] == container_source]
    context_mounts = [parts for parts in mounts if len(parts) == 3 and Path(parts[0]).resolve() == context.root]
    if (len(source_mounts) != 1 or source_mounts[0][2] != "ro"
        or len(context_mounts) != 1 or context_mounts[0][2] != "rw"):
        raise ValueError("bootstrap must mount exact context read-write and frozen source read-only")
    mounted = Path(source_mounts[0][0]).resolve(strict=True)
    if raw(mounted / "tools/rapid_acquire.py") != raw(checkout / "tools/rapid_acquire.py"):
        raise ValueError("mounted admission CLI differs from the clean verifier checkout")
    for modules in context.mounted_module_hashes.values():
        for name, expected in modules.items():
            if name == "neqo-qcsd-client":
                continue  # Native bytes are independently bound by the existing context/image proofs.
            module = importlib.import_module(name)
            relative = Path(module.__file__).resolve().relative_to(checkout)
            checked(checkout / relative, expected)
            checked(mounted / relative, expected)
    name_positions = [i + 1 for i, word in enumerate(argv[:-1]) if word == "--name"]
    if len(name_positions) != 1:
        raise ValueError("bootstrap requires one replaceable container name")
    return context_mounts[0][1], name_positions[0]


def choose_step(events, page_count, page_budget):
    """Finish an existing page; otherwise bound total visited ordinals, including history."""
    if any(event["kind"] == "blocked" for event in events):
        raise ValueError("generic operational error or pending intent remains")
    visited = sorted({event["ordinal"] for event in events if event.get("ordinal") is not None})
    if any(type(ordinal) is not int or not 0 <= ordinal < page_count for ordinal in visited):
        raise ValueError("page history differs from verified navigation")
    audit = {"visited_page_ordinals": visited, "unassessed_page_ordinals": [n for n in range(page_count) if n not in visited],
             "pre_existing_history_above_budget": len(visited) > page_budget}
    latest = events[-1] if events else {"kind": "none"}
    if latest["kind"] in {"failure", "prepared"}:
        if (latest.get("ordinal") is None or latest.get("eligible") is True
            or len(visited) >= page_budget or not audit["unassessed_page_ordinals"]):
            return "seal", latest, audit
        return "probe-page", {"ordinal": audit["unassessed_page_ordinals"][0]}, audit
    if latest["kind"] == "screen":
        return "prepare", latest, audit
    if latest["kind"] == "page":
        return "screen-page", latest, audit
    if latest["kind"] in {"navigation", "none"}:
        if not page_count:
            return "navigate", latest, audit
        if len(visited) >= page_budget or not audit["unassessed_page_ordinals"]:
            raise ValueError("page budget exhausted without a verified terminal proof")
        return "probe-page", {"ordinal": audit["unassessed_page_ordinals"][0]}, audit
    raise ValueError(f"unsupported verified history: {latest['kind']}")


def verified_events(engine, context, candidate_id, rows):
    from qcsd_lab.rapid_page_evidence import verify_navigation_receipt
    events, navigation, nav_hash, nav_facts = [], None, None, None
    child = lambda ref: engine._child(context.root, ref)

    def retain_navigation(path):
        nonlocal navigation, nav_hash, nav_facts
        current = digest(raw(path))
        facts = verify_navigation_receipt(path, profile_receipt=engine._load(context.profile_bytes),
            source_bytes=context.source_bytes, catalogue_bytes=context.catalogue_bytes, candidate_id=candidate_id,
            execution_binding=context.execution_binding, expected_implementation_hashes=context.mounted_module_hashes["navigation"],
            not_before_utc=context.not_before_utc)
        if nav_hash is not None and nav_hash != current:
            raise ValueError("candidate navigation page list changed")
        navigation, nav_hash, nav_facts = path, current, facts

    for row in rows:
        state = row["state"]
        if state in BLOCKERS:
            events.append({"kind": "blocked"})
        elif state == "navigation-ready":
            retain_navigation(child(row.get("navigation") or row["navigation_observation"]))
            events.append({"kind": "navigation"})
        elif state in FAILURES:
            key, receipt_type, function, flag = FAILURES[state]
            path = child(row[key]); facts = getattr(engine, function)(path, context, candidate_id)
            payload = engine._unpack(raw(path), getattr(engine, receipt_type))
            if "navigation" in payload["inputs"]:
                retain_navigation(child(payload["inputs"]["navigation"]))
            events.append({"kind": "failure", "ordinal": facts["action"]["selected_page_ordinal"],
                           "path": str(path), "flag": flag, "inputs": payload["inputs"]})
        elif state == "browser-policy-failure-needs-explicit-terminal":
            path = child(row["navigation_observation"])
            engine.browser_policy_failure_facts(path, context, candidate_id)
            events.append({"kind": "failure", "ordinal": None, "path": str(path), "flag": "--browser-policy-failure", "inputs": {}})
        elif state == "exact-page-h3-ready":
            path = child(row["page_h3"]); inputs = engine._load(raw(path.parent / "inputs.json"))
            retain_navigation(child(inputs["navigation"]))
            facts = engine._page_facts(context, candidate_id, navigation, path)
            events.append({"kind": "page", "ordinal": facts["selected_page_ordinal"], "path": str(path)})
        elif state == "automated-url-domain-screen-passed":
            path = child(row["automated_screen"]); facts = engine.verify_automated_site_screen(path, context, candidate_id=candidate_id)
            inputs = engine._unpack(raw(path), engine.AUTOMATED_SCREEN_TYPE)["inputs"]
            retain_navigation(child(inputs["navigation"]))
            events.append({"kind": "screen", "ordinal": facts["selected_page_ordinal"], "path": str(path), "inputs": inputs})
        elif state == "prepared-needs-terminal":
            path = child(row["preparation"]); facts, page, _ = engine._preparation_facts(path, context, candidate_id)
            inputs = engine._unpack(raw(path), engine.PREPARATION_TYPE)["inputs"]
            retain_navigation(child(inputs["navigation"]))
            events.append({"kind": "prepared", "ordinal": page["selected_page_ordinal"], "path": str(path),
                           "eligible": facts["cross_origin_resource_count"] >= 1, "inputs": inputs})
        else:
            raise ValueError(f"unsupported candidate attempt state: {state}")
    return events, navigation, len(nav_facts["pages"]) if nav_facts else 0


def plan_action(engine, context, registry, status, budget):
    if any(row["state"] in BLOCKERS for rows in status["attempts"].values() for row in rows):
        raise ValueError("generic operational error or pending intent remains; no retry")
    candidate = status["next_candidate"]
    if candidate is None:
        raise ValueError("fixed candidate list exhausted")
    candidate_id = candidate["candidate_id"]
    if engine.unsafe_catalogue_domain_reason(candidate["domain"]) is not None:
        return {"action": "seal", "live": False, "candidate": candidate, "arguments": [], "pages": None}
    group = "curated" if candidate["source_kind"] == "curated" else "fallback"
    refs = registry["root_surveys"][group]
    decision = engine.verify_root_screen(context, candidate_id, refs)
    root_args = [part for ref in refs for part in ("--root-log", str(engine._child(context.root, ref)))]
    if not engine._root_allows_policy_progression(context, decision["root_screen"]):
        return {"action": "seal", "live": False, "candidate": candidate, "arguments": ["--defer-root", *root_args], "pages": None}
    events, navigation, count = verified_events(engine, context, candidate_id, status["attempts"].get(candidate_id, []))
    action, event, audit = choose_step(events, count, budget)
    args = []
    if action == "seal":
        args = [event.get("flag", "--preparation"), event["path"], *root_args]
        if "automated_screen" in event["inputs"]:
            args += ["--automated-screen", str(engine._child(context.root, event["inputs"]["automated_screen"]))]
    elif action == "probe-page":
        args = ["--navigation", str(navigation), "--selected-page-ordinal", str(event["ordinal"])]
    elif action == "screen-page":
        args = ["--navigation", str(navigation), "--page-h3", event["path"], "--selected-page-ordinal", str(event["ordinal"])]
    elif action == "prepare":
        args = [part for key in ("navigation", "page_h3") for part in ("--" + key.replace("_", "-"), str(engine._child(context.root, event["inputs"][key])))]
        args += ["--automated-screen", event["path"]]
    return {"action": action, "live": action in {"navigate", "probe-page", "prepare"},
            "candidate": candidate, "arguments": args, "pages": audit}


def action_argv(plan, context, host, bootstrap, container_context, name_position, label):
    prefix = list(bootstrap if plan["live"] else host)
    arguments = list(plan["arguments"])
    if plan["live"]:
        prefix[name_position] = "qcsd-acquisition-" + label
        for index, item in enumerate(arguments):
            if item.startswith(str(context.root) + os.sep):
                arguments[index] = str(PurePosixPath(container_context) / Path(item).relative_to(context.root).as_posix())
    return [*prefix, plan["action"], container_context if plan["live"] else str(context.root),
            "--candidate", plan["candidate"]["candidate_id"], *arguments]


def execute(engine, argv, directory):
    engine.durable_create(directory / "argv.json", engine._json(argv))
    engine.durable_create(directory / "started.json", engine._json({"started_at": now(), "argv_sha256": digest(engine._json(argv)), "scientific_credit": False}))
    result = None
    try:
        with (directory / "stdout.log").open("xb") as stdout, (directory / "stderr.log").open("xb") as stderr:
            try:
                result = subprocess.run(argv, stdout=stdout, stderr=stderr, check=False)
            finally:
                for stream in (stdout, stderr):
                    stream.flush(); os.fsync(stream.fileno())
    finally:
        engine.durable_create(directory / "completed.json", engine._json({
            "completed_at": now(), "exit_code": result.returncode if result else None,
            "stdout_sha256": digest(raw(directory / "stdout.log")), "stderr_sha256": digest(raw(directory / "stderr.log")),
            "scientific_credit": False,
        }))
    if result is None or result.returncode:
        raise RuntimeError(f"actual CLI failed; preserved logs under {directory}")
    return engine._load(raw(directory / "stdout.log"))


def bounded_actions(engine, args, output, reopen, host):
    reason = "max-actions"
    for number in range(args.max_actions):
        context, bootstrap, container_context, name_position, registry, status = reopen()
        if args.stop_file and (args.stop_file.exists() or args.stop_file.is_symlink()):
            return "boundary-stop-file"
        if status["admitted_site_count"] >= args.stop_at_admissions:
            return "requested-admissions"
        plan = plan_action(engine, context, registry, status, args.page_budget)
        directory = output / f"action-{number + 1:06d}"
        directory.mkdir()
        engine.durable_create(directory / "status.json", engine._json(status))
        engine.durable_create(directory / "plan.json", engine._json(plan))
        label = digest(engine._json({"operation_root": str(output), "number": number + 1}))[:24]
        command = action_argv(plan, context, host, bootstrap, container_context, name_position, label)
        if args.plan_only:
            engine.durable_create(directory / "argv.json", engine._json(command))
            return "plan-only"
        fresh_context, fresh_bootstrap, fresh_container, fresh_name, fresh_registry, fresh_status = reopen()
        fresh_plan = plan_action(engine, fresh_context, fresh_registry, fresh_status, args.page_budget)
        if status != fresh_status or plan != fresh_plan or command != action_argv(fresh_plan, fresh_context, host, fresh_bootstrap, fresh_container, fresh_name, label):
            raise ValueError("proposed action changed before execution")
        if args.stop_file and (args.stop_file.exists() or args.stop_file.is_symlink()):
            return "boundary-stop-file"
        result = execute(engine, command, directory)
        if result.get("candidate_id") != plan["candidate"]["candidate_id"]:
            raise ValueError("actual CLI output candidate differs")
        if any(row["state"] in BLOCKERS for rows in result["status"]["attempts"].values() for row in rows):
            raise ValueError("actual CLI retained a generic or pending operation; no retry")
        print(f"{plan['action']}: candidate={plan['candidate']['domain']} admitted={result['status']['admitted_site_count']}", flush=True)
    return reason


def run_operation(engine, args, checkout, reopen, lock_path):
    context, bootstrap, container_context, name_position, registry, status = reopen()
    final = next(contract for contract in engine._load(context.profile_bytes)["payload"]["cohort_contracts"] if contract["role"] == "final")
    if args.stop_at_admissions > final["class_count"]:
        raise ValueError("requested admissions exceed the frozen final cohort size")
    _, binding_path = control_paths(context.root)
    prior = None
    if binding_path.exists() or binding_path.is_symlink():
        prior = engine._load(raw(binding_path))
        fields = {"context", "provenance_sha256", "page_budget", "policy", "scientific_credit"}
        if (set(prior) != fields or prior["context"] != str(context.root)
            or prior["provenance_sha256"] != context.provenance_sha256
            or type(prior["page_budget"]) is not int or prior["page_budget"] != args.page_budget
            or prior["scientific_credit"] is not False):
            raise ValueError("unchanged context must retain its declared operator page budget")
        first_policy = engine._load(checked(prior["policy"]["path"], prior["policy"]["sha256"]))
        checked(Path(prior["policy"]["path"]).parent / "initial-status.json", first_policy["initial_status_sha256"])
        if (first_policy["context"] != prior["context"] or first_policy["provenance_sha256"] != prior["provenance_sha256"]
            or first_policy["page_budget"] != prior["page_budget"] or first_policy["scientific_credit"] is not False):
            raise ValueError("initial operator page policy differs from its retained binding")
    output = args.operation_root.resolve()
    if output.is_relative_to(context.root):
        raise ValueError("operator logs must remain outside the admission evidence root")
    output.mkdir(parents=True, exist_ok=False)
    engine.durable_create(output / "initial-status.json", engine._json(status))
    policy = {"schema_version": 1, "policy": "bounded-selected-pages-host-coordinator-v1", "declared_at": now(),
        "context": str(context.root), "provenance_sha256": context.provenance_sha256,
        "selection_amendment_revision": context.selection_amendment_revision,
        "qualified_chaff_origin_policy": context.qualified_chaff_origin_policy,
        **({"buflo_incoming_credit_release_policy": context.buflo_incoming_credit_release_policy}
           if context.selection_amendment_revision in {8, 9, 10, 11, 12} else {}),
        **({"tamaraw_capture_policy": context.tamaraw_capture_policy}
           if context.selection_amendment_revision in {10, 11, 12} else {}),
        **({"front_capture_policy": context.front_capture_policy}
           if context.selection_amendment_revision in {11, 12} else {}),
        **({"terminal_primary_partial_cell_policy": context.terminal_primary_partial_cell_policy}
           if context.selection_amendment_revision == 12 else {}),
        "source_checkout": str(checkout), "source_commit": args.source_commit,
        "operator_commit": args.operator_commit, "coordinator_sha256": args.coordinator_sha256,
        "bootstrap": {"path": str(args.bootstrap.absolute()), "sha256": args.bootstrap_sha256},
        "root_registry": {"path": str(args.root_registry.absolute()), "sha256": args.root_registry_sha256},
        "initial_status_sha256": digest(raw(output / "initial-status.json")),
        "page_budget": args.page_budget, "budget_scope": "total-distinct-selected-ordinals-in-unchanged-context-history",
        "pre_existing_history": "retained-and-grandfathered; finish-already-started-exact-page-sequence",
        "deferral_scope": "exact-observed-page-only; unassessed-pages-remain-unassessed; no-domain-wide-failure-claim",
        "host_coordinator_lock": str(lock_path), "context_budget_binding": str(binding_path),
        "handoff": "existing external controller must be closed before coordinator execution",
        "max_actions": args.max_actions, "stop_at_admissions": args.stop_at_admissions,
        "stop_file": str(args.stop_file.absolute()) if args.stop_file else None,
        "scientific_credit": False, "formal_trace_target": final["formal_sample_target"], "scientific_acceptance_changed": False}
    engine.durable_create(output / "policy.json", engine._json(policy))
    host = [sys.executable, "-B", "-I", "-c",
            "import runpy,sys; sys.path[:0]=[sys.argv.pop(1),sys.argv.pop(1)]; runpy.run_path(sys.argv.pop(1),run_name='__main__')",
            str(checkout / "src"), str(checkout), str(checkout / "tools/rapid_acquire.py")]
    try:
        if prior is None:
            engine.durable_create(binding_path, engine._json({"context": str(context.root),
                "provenance_sha256": context.provenance_sha256, "page_budget": args.page_budget,
                "policy": {"path": str(output / "policy.json"), "sha256": digest(raw(output / "policy.json"))},
                "scientific_credit": False}))
        binding_hash = digest(raw(binding_path))
        original_reopen = reopen
        def bound_reopen():
            binding = engine._load(checked(binding_path, binding_hash))
            original_policy = engine._load(checked(binding["policy"]["path"], binding["policy"]["sha256"]))
            checked(Path(binding["policy"]["path"]).parent / "initial-status.json", original_policy["initial_status_sha256"])
            return original_reopen()
        reason = bounded_actions(engine, args, output, bound_reopen, host)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        engine.durable_create(output / "blocked.json", engine._json({"recorded_at": now(),
            "exception_type": type(error).__name__, "message": str(error), "scientific_credit": False}))
        raise
    engine.durable_create(output / "stopped.json", engine._json({"reason": reason, "completed_at": now(), "scientific_credit": False}))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("context", "source-checkout", "bootstrap", "root-registry", "operation-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("context-provenance-sha256", "source-commit", "bootstrap-sha256", "root-registry-sha256", "coordinator-sha256", "operator-commit"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--max-actions", type=int, default=20)
    parser.add_argument("--stop-at-admissions", type=int, default=1)
    parser.add_argument("--page-budget", type=int, default=1)
    parser.add_argument("--stop-file", type=Path, help="Creation requests a stop at the next action boundary")
    parser.add_argument("--plan-only", action="store_true", help="Publish the policy and first verified plan without executing it")
    args = parser.parse_args(argv)
    if min(args.page_budget, args.max_actions, args.stop_at_admissions) < 1:
        raise ValueError("page-budget, max-actions and stop-at-admissions must be positive")
    checkout = args.source_checkout.resolve(strict=True)
    checked(Path(__file__), args.coordinator_sha256)
    operator_root = Path(__file__).resolve().parents[1]
    if git(operator_root, "rev-parse", "HEAD").decode().strip() != args.operator_commit or git(operator_root, "show", args.operator_commit + ":tools/rapid_acquisition_control.py") != raw(__file__):
        raise ValueError("coordinator bytes differ from the independently selected operator commit")
    engine = load_engine(checkout, args.source_commit)

    def reopen():
        checked(Path(__file__), args.coordinator_sha256)
        clean_source(checkout, args.source_commit)
        checked(args.context / "provenance.json", args.context_provenance_sha256)
        context = engine.load_admission_context(args.context)
        registry_record_type(context)
        verify_runtime_source(context, checkout, args.source_commit)
        bootstrap = engine._load(checked(args.bootstrap, args.bootstrap_sha256))
        container_context, name_position = verify_bootstrap(engine, context, checkout, bootstrap)
        registry = load_registry(engine, context, args.root_registry, args.root_registry_sha256)
        return context, bootstrap, container_context, name_position, registry, engine.acquisition_status(context)

    with context_lock(args.context) as lock_path:
        return run_operation(engine, args, checkout, reopen, lock_path)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"STOP {type(error).__name__}: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1)
