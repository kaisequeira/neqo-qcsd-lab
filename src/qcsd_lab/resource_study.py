"""Progressive controlled resource-domain replay with independently recoverable cells."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import threading
import time
from typing import Any

from .resource_study_inputs import (MODES, candidate_catalogue, canonical_json, sha256_file)
from .resource_study_store import StudyStore, DuplicateSession
from .resource_study_verify import ACCEPTANCE, load, verify_receipt
from .resource_study_storage import require_storage, storage_snapshot

RECORD = "qcsd-resource-domain-study-v1"
CHUNK = 20
INPUT_LIMIT = 16 * 1024 * 1024


def coordinator_provenance() -> dict:
    """Record the host code actually coordinating and verifying this attempt."""
    source = Path(__file__).parent
    names = ("resource_study.py", "resource_study_runtime.py", "resource_study_store.py",
             "resource_study_verify.py", "resource_study_inputs.py", "resource_study_storage.py",
             "resource_study_supplements.py", "resource_study_epochs.py",
             "fidelity.py", "capture.py", "process_scheduler.py")
    return {"record_type": "qcsd-resource-study-host-code-v1",
            "files": {name: sha256_file(source / name) for name in names},
            "installed_native_and_sdk": "recorded separately in runtime"}


def authenticated_input(path: Path, digest: str) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(INPUT_LIMIT + 1)
    if len(raw) > INPUT_LIMIT or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("input changed or exceeds the frozen input byte limit")
    return raw


def create_json(path: Path, value: Any) -> None:
    """Durably publish once; readers never observe partial receipts."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + "." + os.urandom(8).hex())
    try:
        with temporary.open("xb") as handle:
            handle.write(canonical_json(value))
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o444)
        os.link(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def runtime_identity(canonical: Path) -> dict[str, Any]:
    from .rapid_portable_runtime import _verify
    value = load(canonical)
    _verify(canonical.parent, value)
    return {"collection_image_digest": value["collection_image_digest"],
            "prepare_image_digest": value["prepare_image_digest"],
            "client_sha256": value["installed_client_sha256"], "platform": value["platform"],
            "native_commit": value["source"]["neqo_commit"],
            "source": value["source"], "canonical_sha256": sha256_file(canonical)}


def initialize(source: Path, root: Path) -> dict[str, Any]:
    catalogue = candidate_catalogue(source)
    raw = authenticated_input(source, catalogue["source_sha256"])
    plan = {"schema_version": 1, "record_type": RECORD, "class_count": 50,
            "resources_per_session": 20, "sessions_per_mode": 400, "modes": list(MODES),
            "total_sessions": 100000, "chunk_sessions": CHUNK,
            "capture_position": "client-eth0-before-nat", "acceptance": ACCEPTANCE,
            "source_sha256": catalogue["source_sha256"],
            "storage_reserve_bytes": 2 * 1024 ** 3,
            "design": "controlled-resource-domain-http3-replay",
            "created_at": datetime.now(timezone.utc).isoformat()}
    store = StudyStore(root)
    store.initialize(plan)
    create_json(root / "inputs/candidates.json", catalogue)
    copied = root / "inputs/supplied-resources.json"
    with copied.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    copied.chmod(0o444)
    if sha256_file(copied) != catalogue["source_sha256"]:
        raise ValueError("source changed while preparing the study")
    return store.status()


def add_inventories(root: Path, paths: list[Path]) -> None:
    """Add explicit, frozen reserve pools without changing existing enrollment."""
    from .resource_study_supplements import load_inventory_candidates
    StudyStore(root).plan()
    catalogue = load_inventory_candidates(paths)
    digest = hashlib.sha256(canonical_json(catalogue)).hexdigest()
    destination = root / "inputs/supplements" / digest
    if destination.exists():
        if load(destination / "catalogue.json") != catalogue:
            raise ValueError("supplement catalogue changed")
    else:
        temporary = destination.with_name("." + digest + "." + os.urandom(8).hex())
        temporary.mkdir(parents=True, exist_ok=False)
        for index, ref in enumerate(catalogue["inventory_files"], 1):
            raw = authenticated_input(Path(ref["path"]), ref["sha256"])
            target = temporary / f"inventory-{index:03d}.json"
            with target.open("xb") as handle:
                handle.write(raw)
                handle.flush(); os.fsync(handle.fileno())
            target.chmod(0o444)
            if sha256_file(target) != ref["sha256"]:
                raise ValueError("supplement inventory changed while freezing it")
        create_json(temporary / "catalogue.json", catalogue)
        temporary.rename(destination)
    admissions = sorted((root / "inputs/supplement-admissions").glob("*.json"))
    if not any(load(p)["catalogue_sha256"] == digest for p in admissions):
        create_json(root / "inputs/supplement-admissions" / f"{len(admissions) + 1:06d}.json", {
            "catalogue_sha256": digest, "scientific_credit": False,
            "reason": "explicit operator reserve inventory import"})


def candidate_pool(root: Path) -> dict:
    plan = StudyStore(root).plan()
    source = root / "inputs/supplied-resources.json"
    if sha256_file(source) != plan["source_sha256"]:
        raise ValueError("frozen supplied resources changed")
    catalogue = load(root / "inputs/candidates.json")
    if catalogue != candidate_catalogue(source):
        raise ValueError("candidate catalogue differs from its frozen source")
    candidates = {r["hostname"]: r for r in catalogue["candidates"]}
    for admission in sorted((root / "inputs/supplement-admissions").glob("*.json")):
        digest = load(admission)["catalogue_sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("supplement admission has an invalid digest")
        path = root / "inputs/supplements" / digest / "catalogue.json"
        supplemental = load(path)
        if hashlib.sha256(canonical_json(supplemental)).hexdigest() != path.parent.name:
            raise ValueError("supplement catalogue differs from its frozen digest")
        for index, ref in enumerate(supplemental["inventory_files"], 1):
            if sha256_file(path.parent / f"inventory-{index:03d}.json") != ref["sha256"]:
                raise ValueError("frozen supplement inventory changed")
        for row in supplemental["candidates"]:
            host = row["hostname"]
            if host not in candidates:
                candidates[host] = row
            else:
                current = candidates[host]
                current["urls"] += [url for url in row["urls"] if url not in current["urls"]]
                current["source_occurrences"] += row["source_occurrences"]
                current["url_count"] = len(current["urls"])
                current["eligible"] = current["url_count"] >= 20
    return candidates


def enroll(root: Path, runtime: dict, hostnames: list[str], *, backend=None) -> dict:
    if backend is None:
        from .resource_study_runtime import PreparationRuntime
        backend = PreparationRuntime(root, runtime)
    store = StudyStore(root)
    candidates = candidate_pool(root)
    completed = {r["hostname"] for r in store.enrolled()}
    results = []
    for hostname in hostnames:
        if hostname in completed:
            results.append({"hostname": hostname, "status": "already-enrolled"})
            continue
        candidate = candidates.get(hostname)
        if candidate is None or not candidate["eligible"]:
            raise ValueError("hostname is not an eligible frozen candidate")
        attempt = root / "enrollment-attempts" / hostname / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        try:
            require_storage(root, reserve_bytes=store.plan().get("storage_reserve_bytes", 2 * 1024 ** 3))
            enrollment = backend.prepare(candidate, attempt)
            selected = enrollment.get("urls", [])
            if (enrollment.get("hostname") != hostname or len(selected) != 20
                    or len(set(selected)) != 20 or any(url not in candidate["urls"] for url in selected)
                    or selected != sorted(selected, key=candidate["urls"].index)):
                raise ValueError("prepared enrollment differs from its frozen candidate pool/order")
            store.enroll(enrollment)
            completed.add(hostname)
            results.append({"hostname": hostname, "status": "enrolled", "resources": 20})
        except (OSError, ValueError, RuntimeError) as error:
            create_json(attempt / "excluded.json", {"hostname": hostname, "status": "not-enrolled",
                "reason": str(error), "exception": type(error).__name__, "scientific_credit": False})
            results.append({"hostname": hostname, "status": "not-enrolled", "reason": str(error)})
    return {"enrollment": results, "progress": store.status()}


def seal(root: Path, attempt: dict, enrollment: dict, runtime: dict, result: dict, *, pilot=False) -> Path:
    """Publish one receipt after independently checking the complete staged session."""
    sealing_started = time.monotonic()
    source = root / attempt["path"] / "capture"
    destination = root / "corpus" / attempt["hostname"] / attempt["mode"] / f"session-{attempt['slot']:06d}"
    if pilot:
        destination = root / "pilots" / attempt["hostname"] / attempt["mode"] / attempt["attempt_id"]
    if destination.exists():
        raise ValueError("accepted session destination already exists; recover it first")
    create_json(source / "attempt-owner.json", {"attempt_id": attempt["attempt_id"]})
    primary = source / "captures/direct-quic.pcapng"
    trace = source / "traces/direct-quic.csv"
    primary.rename(source / "traffic.pcapng")
    trace.rename(source / "trace.csv")
    # The raw UDP scratch capture duplicates the filtered primary. Successful
    # evidence retains only the primary and the separate kernel measurement.
    raw = source / "diagnostics/direct-quic-raw.pcapng"
    destination.parent.mkdir(parents=True, exist_ok=True)
    source.rename(destination)
    relative = lambda path: path.relative_to(root).as_posix()
    enrollment_path = root / "classes" / attempt["hostname"] / "enrollment.json"
    paths = {"run": relative(destination / "neqo/run.json"),
             "packets": relative(destination / "neqo/packets.csv"),
             "pcap": relative(destination / "traffic.pcapng"),
             "trace": relative(destination / "trace.csv"),
             "collector": relative(destination / "attempt.json"),
             "workload": enrollment["workload_path"], "enrollment": relative(enrollment_path)}
    optional = {"schedule": "neqo/schedule.csv", "events": "neqo/events.csv",
                "kernel_tx": "diagnostics/kernel-tx-evidence.json", "post_veth": "diagnostics/kernel-tx-post-veth-raw.pcapng"}
    for key, path in optional.items():
        if (destination / path).is_file():
            paths[key] = relative(destination / path)
    from .capture import split_endpoint
    endpoint = load(destination / "neqo/run.json")["endpoints"][0]
    local_ip, local_port = split_endpoint(endpoint["local_address"])
    remote_ip, remote_port = split_endpoint(endpoint["remote_address"])
    for path in destination.rglob("*"):
        if path.is_file():
            if path.is_symlink():
                raise ValueError("collector created a linked artifact")
            path.chmod(0o444)
    files = {relative(p): sha256_file(p) for p in destination.rglob("*") if p.is_file()}
    for path in paths.values():
        files[path] = sha256_file(root / path)
    receipt = {"schema_version": 1, "record_type": "qcsd-resource-domain-session-verification-v1",
        "acceptance": ACCEPTANCE, "verified": True, "hostname": attempt["hostname"],
        "purpose": "pilot" if pilot else "formal", "scientific_credit": not pilot,
        "mode": attempt["mode"], "slot": attempt["slot"], "attempt_id": attempt["attempt_id"],
        "five_tuple": [local_ip, local_port, remote_ip, remote_port, 17],
        "capture_position": "client-eth0-before-nat", "workload_sha256": enrollment["workload_sha256"],
        "runtime": runtime, "collector_version": "qcsd-resource-study-coordinator-v1",
        "coordinator_provenance": coordinator_provenance(),
        "mode_policies": result.get("mode_policies", {}),
        "mode_settings": enrollment.get("mode_settings", {}).get(attempt["mode"], {}),
        "artifact_paths": paths, "files": files,
        "completed_at": datetime.now(timezone.utc).isoformat()}
    facts = verify_receipt(root, receipt)
    # Scratch removal is allowed only after raw verification succeeds. Failed
    # attempts retain it for diagnosis; successful receipts bind the retained
    # inventory rather than two copies of the same primary observation.
    moved_raw = destination / "diagnostics/direct-quic-raw.pcapng"
    if moved_raw.exists():
        receipt["files"].pop(relative(moved_raw), None)
        moved_raw.unlink()
    facts["retained_bytes"] = sum((root / name).stat().st_size for name in receipt["files"]
        if destination in (root / name).parents)
    facts["shared_input_bytes_excluded"] = True
    receipt["facts"] = facts
    if "attempt_elapsed_seconds" in result:
        receipt["attempt_wall_seconds"] = result["attempt_elapsed_seconds"] + time.monotonic() - sealing_started
    create_json(destination / "session.json", receipt)
    return destination / "session.json"


def temporary_clock_failure(result: dict) -> bool:
    """Retry a discarded clock-disturbed sample; never relax its acceptance."""
    if (result.get("success") is not False or result.get("resource_error") is not None
            or result.get("runner_complete") is not True
            or result.get("runner_binding_valid") is not True
            or result.get("scheduler_runtime_evidence_valid") is not True
            or result.get("runner_returncode") != 0):
        return False
    failure = result.get("failure")
    if not isinstance(failure, dict) or failure.get("stage") != "capture":
        return False
    details = failure.get("details", [])
    return any(isinstance(row, dict) and isinstance(row.get("reason"), str)
               and row["reason"].startswith((
                   "direct/runner reconciliation failed: direct/runner timestamp mismatch",
                   "direct/runner reconciliation failed: primary capture: wrapper realtime/monotonic elapsed difference exceeds"))
               for row in details)


def capture(root: Path, runtime: dict, *, workers=2, budget=None, modes=MODES,
            hostnames=None, stop=None, backend=None, chunk_sessions=CHUNK, pilot=False) -> dict:
    """Balanced chunks; a failing cell pauses for this invocation only.

    A subsequent invocation retries that cell without resetting others. Workers
    never capture the same hostname concurrently. Every attempted reservation
    is durable before any packet is sent.
    """
    if type(workers) is not int or workers < 2:
        raise ValueError("measured capture requires at least two declared workers")
    if budget is not None and (type(budget) is not int or budget <= 0):
        raise ValueError("attempt budget must be positive")
    if type(chunk_sessions) is not int or not 1 <= chunk_sessions <= CHUNK:
        raise ValueError("chunk size must be between one and twenty")
    if not modes or any(m not in MODES for m in modes) or len(set(modes)) != len(modes):
        raise ValueError("unregistered or duplicate traffic setting")
    store = StudyStore(root)
    from .resource_study_epochs import active_cell
    storage = require_storage(root, reserve_bytes=store.plan().get("storage_reserve_bytes", 2 * 1024 ** 3))
    enrolled = [e for e in store.enrolled() if hostnames is None or e["hostname"] in hostnames]
    if not enrolled:
        raise ValueError("live enrollment is required before capture")
    pilot_blocked = set()
    missing_pilots = []
    if not pilot:
        for mode in modes:
            selected = [e for e in enrolled if e.get("mode_readiness", {}).get(mode, True)
                        and active_cell(store, e["hostname"], mode)]
            if not selected:
                continue
            ready = False
            for path in sorted((root / "pilots").glob(f"*/{mode}/*/session.json")):
                candidate = load(path)
                if (candidate.get("purpose") == "pilot" and candidate.get("mode") == mode
                        and candidate.get("runtime", {}).get("client_sha256")
                        == runtime.get("client_sha256")):
                    verify_receipt(root, candidate)
                    proven = load(root / candidate["artifact_paths"]["enrollment"])
                    if any(e.get("mode_settings", {}).get(mode) != proven.get("mode_settings", {}).get(mode)
                            or e.get("mode_policies", {}).get(mode) != proven.get("mode_policies", {}).get(mode)
                            for e in selected):
                        continue
                    ready = True
                    break
            if not ready:
                missing_pilots.append(mode)
                pilot_blocked.update((e["hostname"], mode) for e in selected)
        ready_cells = [(e["hostname"], mode) for mode in modes for e in enrolled
                       if e.get("mode_readiness", {}).get(mode, True)
                       and active_cell(store, e["hostname"], mode)
                       and (e["hostname"], mode) not in pilot_blocked]
        if not ready_cells:
            raise ValueError("requested modes need a focused pilot or live admission: capture --pilot --chunk 1")
    if backend is None:
        from .resource_study_runtime import CaptureRuntime
        backend = CaptureRuntime(root, runtime, workers)
    stop = stop or threading.Event()
    paused, busy, completed_pilots, attempts = set(pilot_blocked), set(), set(), 0
    allocation_errors = []
    clock_failures = {}
    if pilot:
        chunk_sessions = 1
    cell_order = [(e["hostname"], m) for m in modes for e in enrolled
                  if e.get("mode_readiness", {}).get(m, True) and active_cell(store, e["hostname"], m)]
    enrollment_by_host = {e["hostname"]: e for e in enrolled}
    def accepted(cell):
        return next((r["accepted"] for r in store.status()["cells"]
                     if (r["hostname"], r["mode"]) == cell), 0)

    def chunk(worker, cell, allowance):
        host, mode = cell
        attempted, credited = 0, 0
        while attempted < allowance and not stop.is_set() and accepted(cell) < 400:
            try:
                attempt = store.allocate_attempt(host, mode, purpose="pilot" if pilot else "formal")
            except (OSError, ValueError, RuntimeError) as error:
                # A changed epoch can require its own pilot even when another
                # cell has a mode pilot. No reservation or packet is invented;
                # healthy cells continue and the refused cell stays uncredited.
                return {"cell": cell, "attempted": attempted, "accepted": credited,
                        "paused": True, "allocation_error": str(error)}
            attempted += 1
            attempt_started = time.monotonic()
            result = {}
            try:
                require_storage(root, reserve_bytes=store.plan().get("storage_reserve_bytes", 2 * 1024 ** 3))
                result = backend.capture(worker, attempt, enrollment_by_host[host])
                store.mark_captured(attempt["attempt_id"])
                if result.get("success") is not True:
                    raise ValueError("collector rejected session: " + str(result.get("failure")))
                result["attempt_elapsed_seconds"] = time.monotonic() - attempt_started
                clock_failures[cell] = 0
                receipt_path = seal(root, attempt, enrollment_by_host[host], runtime, result, pilot=pilot)
                if pilot:
                    store.fail_attempt(attempt["attempt_id"], "focused pilot passed; no formal credit", kind="pilot",
                        wall_seconds=time.monotonic() - attempt_started)
                    return {"cell": cell, "attempted": attempted, "accepted": 0, "paused": False, "pilot_passed": True}
                else:
                    # seal independently checks raw evidence before publishing.
                    # The ledger rechecks the full immutable inventory around
                    # this callback. Reuse only this in-memory proof of these
                    # exact receipt fields; recovery always reruns the reader.
                    bound = load(receipt_path)
                    def checked_this_attempt(actual_root, value):
                        if actual_root != root or value != bound:
                            raise ValueError("receipt changed after independent verification")
                        return bound["facts"]
                    store.commit_verified(receipt_path, validator=checked_this_attempt)
                    credited += 1
            except DuplicateSession as error:
                # The immutable recording is retained but cannot satisfy a
                # distinct-five-tuple quota. Move it away from the slot path.
                destination = root / "corpus" / host / mode / f"session-{attempt['slot']:06d}"
                if destination.exists():
                    target = root / "failures" / host / mode / attempt["attempt_id"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    destination.rename(target)
                store.fail_attempt(attempt["attempt_id"], str(error), kind="duplicate",
                    wall_seconds=time.monotonic() - attempt_started)
                continue
            except (OSError, ValueError, RuntimeError) as error:
                rejected = root / "corpus" / host / mode / f"session-{attempt['slot']:06d}"
                owner = rejected / "attempt-owner.json"
                if rejected.exists() and owner.is_file() and load(owner).get("attempt_id") == attempt["attempt_id"]:
                    target = root / "failures" / host / mode / attempt["attempt_id"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    rejected.rename(target)
                store.fail_attempt(attempt["attempt_id"], str(error), kind="pilot-failed" if pilot else "failed",
                    wall_seconds=time.monotonic() - attempt_started)
                create_json(root / attempt["path"] / "failure.json", {
                    "attempt_id": attempt["attempt_id"], "mode": mode, "hostname": host,
                    "reason": str(error), "exception": type(error).__name__, "scientific_credit": False})
                if temporary_clock_failure(result):
                    clock_failures[cell] = clock_failures.get(cell, 0) + 1
                    if clock_failures[cell] < 3:
                        continue
                return {"cell": cell, "attempted": attempted, "accepted": credited, "paused": True}
        return {"cell": cell, "attempted": attempted, "accepted": credited, "paused": False}

    with backend, ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}
        available = list(range(workers))
        while futures or (available and not stop.is_set()):
            while available and not stop.is_set() and (budget is None or attempts < budget):
                choices = [c for c in cell_order if c not in paused and c not in completed_pilots
                           and c[0] not in busy and accepted(c) < 400]
                if not choices:
                    break
                cell = min(choices, key=lambda c: (accepted(c), cell_order.index(c)))
                allowance = min(chunk_sessions, 400 - accepted(cell), (budget - attempts) if budget else chunk_sessions)
                worker = available.pop(0)
                attempts += allowance
                busy.add(cell[0])
                futures[executor.submit(chunk, worker, cell, allowance)] = worker
            if not futures:
                break
            done, _ = wait(futures, timeout=1, return_when=FIRST_COMPLETED)
            for future in done:
                worker = futures.pop(future)
                available.append(worker)
                result = future.result()
                busy.remove(result["cell"][0])
                if result["paused"]:
                    paused.add(result["cell"])
                if result.get("allocation_error"):
                    allocation_errors.append({"hostname": result["cell"][0], "mode": result["cell"][1],
                                              "reason": result["allocation_error"]})
                if result.get("pilot_passed"):
                    completed_pilots.add(result["cell"])
    return {"progress": store.status(), "paused_cells": sorted(paused), "stop_requested": stop.is_set(),
            "pilot_cells_passed": sorted(completed_pilots), "missing_mode_pilots": missing_pilots,
            "allocation_errors": allocation_errors,
            "storage": storage_snapshot(root)}


def verify(root: Path, *, recover=False, all_receipts=False) -> dict:
    store = StudyStore(root)
    recovered = {}
    if recover:
        from .resource_study_runtime import docker_lock
        with docker_lock():
            recovered = store.recover()
    paths = sorted((root / "corpus").glob("*/*/session-*/session.json"))
    accepted = 0
    errors = []
    # First-credit commits perform independent raw verification. Explicit full
    # audit rereads all evidence; routine status only queries the ledger.
    for path in paths:
        try:
            if all_receipts:
                verify_receipt(root, load(path))
            store.commit_verified(path, validator=verify_receipt)
            accepted += 1
        except (OSError, ValueError) as error:
            errors.append({"receipt": path.relative_to(root).as_posix(), "reason": str(error)})
    return {"verified_receipts": accepted, "errors": errors, "recovery": recovered, "progress": store.status()}


def parser():
    result = argparse.ArgumentParser(prog="qcsd-lab resource-study", description=__doc__)
    actions = result.add_subparsers(dest="action", required=True)
    for action in ("prepare", "capture", "status", "verify", "export"):
        child = actions.add_parser(action)
        child.add_argument("--root", type=Path, required=True)
        if action in {"prepare", "capture"}:
            child.add_argument("--runtime", type=Path)
            child.add_argument("--hostname", action="append", default=[])
        if action == "prepare":
            child.add_argument("--source", type=Path)
            child.add_argument("--inventory", type=Path, action="append", default=[], help="explicitly add a Native URL inventory as a reserve pool")
            child.add_argument("--enroll", action="store_true")
            child.add_argument("--epoch-of", type=Path)
            child.add_argument("--epoch-change", choices=("resources", "mode", "native", "acceptance", "qualification", "add-host"))
            child.add_argument("--affected-hostname", action="append", default=[])
            child.add_argument("--affected-mode", choices=MODES, action="append", default=[])
        elif action == "capture":
            child.add_argument("--workers", type=int, default=2)
            child.add_argument("--attempts", type=int)
            child.add_argument("--chunk", type=int, default=CHUNK, help="one for an all-mode pilot; twenty for sustained capture")
            child.add_argument("--pilot", action="store_true", help="verify modes without formal session credit")
            child.add_argument("--mode", choices=MODES, action="append")
        elif action == "verify":
            child.add_argument("--recover", action="store_true", help="only after capture workers have stopped")
            child.add_argument("--all", action="store_true", dest="all_receipts")
        elif action == "export":
            child.add_argument("--output", type=Path, required=True)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    root = args.root.absolute()
    try:
        if args.action == "prepare":
            if not (root / "study.json").exists():
                if args.source is None:
                    raise ValueError("first prepare needs --source")
                initialize(args.source.absolute(), root)
            elif args.source is not None and sha256_file(args.source) != StudyStore(root).plan()["source_sha256"]:
                raise ValueError("existing study has a different frozen supplied source")
            if args.inventory:
                add_inventories(root, [p.absolute() for p in args.inventory])
            if args.enroll:
                if args.runtime is None or not args.hostname:
                    raise ValueError("live preparation needs --runtime and --hostname")
                output = enroll(root, runtime_identity(args.runtime.absolute()), args.hostname)
            else:
                output = StudyStore(root).status()
            if args.epoch_of is not None:
                if args.epoch_change is None:
                    raise ValueError("epoch admission needs an explicit --epoch-change")
                from .resource_study_epochs import create_epoch
                output = create_epoch(args.epoch_of.absolute(), root, change=args.epoch_change,
                    affected_hostnames=args.affected_hostname, affected_modes=args.affected_mode)
            elif args.epoch_change is not None or args.affected_hostname or args.affected_mode:
                raise ValueError("epoch scope needs --epoch-of")
        elif args.action == "capture":
            if args.runtime is None:
                raise ValueError("capture requires --runtime")
            stop = threading.Event()
            previous = {}
            for sig in (signal.SIGINT, signal.SIGTERM):
                previous[sig] = signal.signal(sig, lambda *_: stop.set())
            try:
                output = capture(root, runtime_identity(args.runtime.absolute()), workers=args.workers,
                    budget=args.attempts, modes=args.mode or MODES, hostnames=args.hostname or None, stop=stop,
                    chunk_sessions=args.chunk, pilot=args.pilot)
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
        elif args.action == "status":
            from .resource_study_epochs import is_parent, status
            output = status(root) if is_parent(root) else StudyStore(root).status()
        elif args.action == "verify":
            from .resource_study_epochs import is_parent, verify as verify_epochs
            output = verify_epochs(root, recover=args.recover) if is_parent(root) else verify(root, recover=args.recover, all_receipts=args.all_receipts)
        else:
            from .resource_study_epochs import is_parent, export_manifest
            output = export_manifest(root, args.output.absolute()) if is_parent(root) else StudyStore(root).export_manifest(args.output.absolute())
        print(json.dumps(output, sort_keys=True, allow_nan=False))
        return 1 if output.get("errors") or output.get("paused_cells") else 0
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({"status": "refused", "reason": str(error), "error": type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
