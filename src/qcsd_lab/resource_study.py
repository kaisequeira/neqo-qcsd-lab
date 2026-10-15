"""Progressive controlled resource-domain replay with independently recoverable cells."""
from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext
from copy import deepcopy
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
from .resource_study_network import (ACCEPTANCE as NETWORK_ACCEPTANCE, TUPLE_SCOPE,
                                     DEFAULT_POOL, build_network_plan, receipt_binding,
                                     validate_network_plan)

RECORD = "qcsd-resource-domain-study-v1"
CHUNK = 20
INPUT_LIMIT = 16 * 1024 * 1024
DEFAULT_STORAGE_RESERVE_BYTES = 60 * 1024 ** 3


def coordinator_provenance(*, resource_selection=False, class_selection=False) -> dict:
    """Record the host code actually coordinating and verifying this attempt."""
    source = Path(__file__).parent
    names = ("resource_study.py", "resource_study_runtime.py", "resource_study_store.py",
             "resource_study_verify.py", "resource_study_inputs.py", "resource_study_storage.py",
             "resource_study_supplements.py", "resource_study_epochs.py",
             "resource_study_network.py", "resource_study_audit.py", "resource_study_cohorts.py",
             "fidelity.py", "capture.py", "process_scheduler.py", "resource_study_integrity.py")
    if resource_selection:
        names += ("resource_study_selection.py",)
    if class_selection:
        names += ("resource_study_lineage.py",)
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


def initialize(source: Path, root: Path, *, storage_reserve_bytes=DEFAULT_STORAGE_RESERVE_BYTES,
               class_network_pool=DEFAULT_POOL) -> dict[str, Any]:
    catalogue = candidate_catalogue(source)
    raw = authenticated_input(source, catalogue["source_sha256"])
    if type(storage_reserve_bytes) is not int or storage_reserve_bytes < 2 * 1024 ** 3:
        raise ValueError("study storage reserve must be an integer of at least two GiB")
    primary = [row["hostname"] for row in catalogue["candidates"] if row["eligible"]][:50]
    network = build_network_plan(primary, pool=class_network_pool)
    plan = {"schema_version": 1, "record_type": RECORD, "class_count": 50,
            "resources_per_session": 20, "sessions_per_mode": 400, "modes": list(MODES),
            "total_sessions": 100000, "chunk_sessions": CHUNK,
            "capture_position": "client-eth0-before-nat", "acceptance": NETWORK_ACCEPTANCE,
            "class_network": network, "tuple_uniqueness_scope": TUPLE_SCOPE,
            "source_sha256": catalogue["source_sha256"],
            "storage_reserve_bytes": storage_reserve_bytes,
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


def _selection_request(path, digest, hostnames):
    requested = path is not None or digest is not None
    if requested and (path is None or digest is None or len(hostnames) != 1):
        raise ValueError("explicit resource selection needs both flags and exactly one hostname")
    return requested


def _selection_unused(store, hostname):
    if any(row["hostname"] == hostname for row in store.enrolled()):
        raise ValueError("explicit resource selection cannot replace an enrolled hostname")
    with store._transaction() as connection:
        if connection.execute("SELECT 1 FROM attempts LIMIT 1").fetchone():
            raise ValueError("explicit resource selection requires a root with no prior attempts")


def enroll(root: Path, runtime: dict, hostnames: list[str], *, backend=None,
           resource_selection: Path | None = None, resource_selection_sha256: str | None = None) -> dict:
    selection_requested = _selection_request(resource_selection, resource_selection_sha256, hostnames)
    store = StudyStore(root)
    from .resource_study_epochs import check_enrollment_selection
    check_enrollment_selection(store, hostnames)
    selection = binding = None
    if selection_requested:
        from .resource_study_selection import load_selection, freeze_selection
        _selection_unused(store, hostnames[0])
        selection = load_selection(root, resource_selection, resource_selection_sha256, hostnames[0])
        binding = freeze_selection(root, selection)
    if backend is None:
        from .resource_study_runtime import PreparationRuntime
        backend = PreparationRuntime(root, runtime)
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
        if "class_selection" in store.plan() and hostname not in store.plan()["class_network"]["assignments"]:
            raise ValueError("hostname is outside the prospective selected50")
        from .resource_study_cohorts import require_input_selection
        require_input_selection(store, hostname, selection)
        if selection is not None:
            candidate = deepcopy(candidate)
            candidate["urls"] = list(selection["manifest"]["urls"])
            candidate["url_count"] = len(candidate["urls"])
        attempt = root / "enrollment-attempts" / hostname / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        try:
            require_storage(root, reserve_bytes=store.plan().get("storage_reserve_bytes", 2 * 1024 ** 3))
            enrollment = backend.prepare(candidate, attempt)
            selected = enrollment.get("urls", [])
            if (enrollment.get("hostname") != hostname or len(selected) != 20
                    or len(set(selected)) != 20 or any(url not in candidate["urls"] for url in selected)
                    or selected != sorted(selected, key=candidate["urls"].index)):
                raise ValueError("prepared enrollment differs from its frozen candidate pool/order")
            if binding is not None:
                from .resource_study_selection import bind_preparation, validate_selection_proof
                if selected != selection["manifest"]["urls"]:
                    raise ValueError("prepared enrollment differs from its exact explicit resource selection")
                enrollment = bind_preparation(root, enrollment, binding, attempt / "job.json")
                validate_selection_proof(root, enrollment)
                if "class_selection" not in store.plan():
                    from .resource_study_epochs import _verify_preparation
                    _verify_preparation(store, hostname, enrollment=enrollment)
            if "class_selection" in store.plan():
                from .resource_study_lineage import bind_enrollment, validate_enrollment
                from .resource_study_cohorts import bind_input_authority
                from .resource_study_epochs import _verify_preparation
                enrollment = bind_enrollment(store, enrollment)
                enrollment = bind_input_authority(store, enrollment)
                validate_enrollment(store, enrollment)
                _verify_preparation(store, hostname, enrollment=enrollment)
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
    destination = root / StudyStore(root).publication_path(attempt)
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
    if "resource_selection" in enrollment:
        from .resource_study_selection import selection_artifact_paths, validate_selection_proof
        validate_selection_proof(root, enrollment)
        paths.update(selection_artifact_paths(enrollment))
    if "class_selection" in enrollment:
        from .resource_study_lineage import MANIFEST, INVENTORY, SOURCE, validate_enrollment
        validate_enrollment(StudyStore(root), enrollment)
        paths.update(class_selection=MANIFEST, class_selection_inventory=INVENTORY,
                     class_selection_source=SOURCE)
        from .resource_study_cohorts import input_authority_artifact_paths
        paths.update(input_authority_artifact_paths(enrollment))
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
        "coordinator_provenance": (coordinator_provenance(resource_selection=True)
            if "resource_selection" in enrollment else coordinator_provenance()),
        "mode_policies": result.get("mode_policies", {}),
        "mode_settings": enrollment.get("mode_settings", {}).get(attempt["mode"], {}),
        "artifact_paths": paths, "files": files,
        "completed_at": datetime.now(timezone.utc).isoformat()}
    plan = StudyStore(root).plan()
    from .resource_study_epochs import stable_lineage_active
    if "class_selection" in plan or stable_lineage_active(StudyStore(root)):
        receipt["coordinator_provenance"] = coordinator_provenance(
            resource_selection="resource_selection" in enrollment, class_selection=True)
    if validate_network_plan(plan) is not None:
        receipt["acceptance"] = NETWORK_ACCEPTANCE
        receipt["study_sha256"] = sha256_file(root / "study.json")
        receipt["tuple_uniqueness_scope"] = TUPLE_SCOPE
        receipt["class_network"] = receipt_binding(plan, receipt["study_sha256"], attempt["hostname"])
        paths["study"] = "study.json"
        paths["class_network"] = relative(destination / "class-network.json")
        paths["scheduler"] = relative(destination / "diagnostics/scheduler-runtime-evidence.json")
        files["study.json"] = receipt["study_sha256"]
        if paths["class_network"] not in files or paths["scheduler"] not in files:
            raise ValueError("capture has no bound persistent class topology/scheduler observation")
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


TAMARAW_RETRY_POLICY = "bounded-fresh-tamaraw-strict-rejections-v1"
TAMARAW_MAX_RETRIES = 2
TAMARAW_RETRY_REASONS = (
    "Tamaraw physical release proof lacks scheduled outgoing handoffs",
    "terminal primary partial does not authorize another missed cell",
)


def tamaraw_retry_reason(mode: str, result: dict, error: Exception, *,
                         origin: str, policy: dict) -> str | None:
    """Permit a fresh attempt, never accept or reinterpret this rejection.

    These two exact errors are distinct from clock disturbance and from other
    binding/integrity failures. The adapter's explicit null resource_error
    requires its unchanged-client/enrollment and complete 20-response check.
    A seal error qualifies only before commit, with a successful collector.
    """
    if (mode != "tamaraw" or type(error) is not ValueError
            or not isinstance(policy, dict) or not policy
            or result.get("mode_policies") != policy
            or "resource_error" not in result or result["resource_error"] is not None
            or type(result.get("runner_returncode")) is not int or result["runner_returncode"] != 0
            or any(result.get(key) is not True for key in (
                "runner_complete", "endpoint_count_valid", "process_scheduler_valid",
                "scheduler_runtime_evidence_valid", "operationally_valid"))
            or result.get("runner_timed_out") is not False
            or result.get("runner_completion_status") != "complete"
            or any(key not in result or result[key] is not None for key in (
                "runner_output_error", "runner_error", "runner_error_class", "runner_process_failure"))):
        return None
    for required, valid in (("observer_topology_required", "observer_topology_valid"),
                            ("kernel_tx_evidence_required", "kernel_tx_evidence_valid")):
        if type(result.get(required)) is not bool or result[required] and result.get(valid) is not True:
            return None
    views = result.get("views")
    if (not isinstance(views, list) or len(views) != 1 or not isinstance(views[0], dict)
            or views[0].get("primary") is not True or views[0].get("valid") is not True):
        return None
    for field, flag in (("capture_clock_integrity", "valid"),
                        ("direct_runner_reconciliation", "evidence_eligible")):
        if not isinstance(views[0].get(field), dict) or views[0][field].get(flag) is not True:
            return None
    if (origin == "seal" and result.get("success") is True
            and result.get("runner_binding_valid") is True and result.get("failure") is None):
        return str(error) if str(error) in TAMARAW_RETRY_REASONS else None
    failure = result.get("failure")
    if (origin != "collector" or result.get("success") is not False
            or result.get("runner_binding_valid") is not False
            or not isinstance(failure, dict) or set(failure) != {"stage", "details"}
            or failure["stage"] != "runner-binding"
            or not isinstance(failure["details"], list) or len(failure["details"]) != 1):
        return None
    detail = failure["details"][0]
    if (not isinstance(detail, dict) or detail.get("incomplete_resources") != []
            or detail.get("scheduler_runtime_evidence_valid") is not True
            or detail.get("runner_timed_out") is not False
            or type(detail.get("runner_returncode")) is not int or detail["runner_returncode"] != 0
            or detail.get("completion_status") != "complete"
            or any(key not in detail or detail[key] is not None for key in (
                "operational_failure", "runner_output_error", "runner_error",
                "runner_error_class", "runner_process_failure"))):
        return None
    reason = detail.get("runner_binding_error")
    return reason if reason in TAMARAW_RETRY_REASONS else None


@contextmanager
def _capture_executor(backend, workers):
    """Construct the pool after real runtime auxiliary confinement, join first."""
    with backend:
        scope = getattr(backend, "coordinator_affinity_scope", None)
        # Existing injected test backends have no physical topology. The
        # public CLI always constructs CaptureRuntime and its strict scope.
        with (nullcontext() if scope is None else scope()) as observe_executor:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                with (nullcontext() if observe_executor is None else observe_executor(executor)):
                    yield executor


def capture(root: Path, runtime: dict, *, workers=2, budget=None, modes=MODES,
            hostnames=None, stop=None, backend=None, chunk_sessions=CHUNK, pilot=False) -> dict:
    from .resource_study_cohorts import source_operation
    with source_operation(root) as source_auth:
        return _capture(root, runtime, workers=workers, budget=budget, modes=modes,
            hostnames=hostnames, stop=stop, backend=backend, chunk_sessions=chunk_sessions,
            pilot=pilot, _source_auth=source_auth)


def _capture(root: Path, runtime: dict, *, workers=2, budget=None, modes=MODES,
             hostnames=None, stop=None, backend=None, chunk_sessions=CHUNK, pilot=False,
             _source_auth=None) -> dict:
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
    from .resource_study_cohorts import eligible_cells
    plan = store.plan()
    fixed_network = validate_network_plan(plan) is not None
    storage = require_storage(root, reserve_bytes=plan.get("storage_reserve_bytes", 2 * 1024 ** 3))
    enrolled = [e for e in store.enrolled() if hostnames is None or e["hostname"] in hostnames]
    if not enrolled:
        raise ValueError("live enrollment is required before capture")
    startup_cells = eligible_cells(store, [(e["hostname"], mode) for mode in modes for e in enrolled
        if e.get("mode_readiness", {}).get(mode, True)])
    pilot_blocked = set()
    missing_pilots = []
    if not pilot:
        for mode in modes:
            selected = [e for e in enrolled if e.get("mode_readiness", {}).get(mode, True)
                        and (e["hostname"], mode) in startup_cells]
            if not selected:
                continue
            ready = False
            proven_hosts = set()
            for path in sorted((root / "pilots").glob(f"*/{mode}/*/session.json")):
                candidate = load(path)
                if (candidate.get("purpose") == "pilot" and candidate.get("mode") == mode
                        and candidate.get("runtime", {}).get("client_sha256")
                        == runtime.get("client_sha256")):
                    if fixed_network and (candidate.get("runtime") != runtime
                            or candidate.get("hostname") not in {e["hostname"] for e in selected}):
                        continue
                    verify_receipt(root, candidate)
                    proven = load(root / candidate["artifact_paths"]["enrollment"])
                    if fixed_network:
                        current = next(e for e in selected if e["hostname"] == candidate["hostname"])
                        if (proven != current or candidate.get("mode_settings") != current.get("mode_settings", {}).get(mode)
                                or candidate.get("mode_policies") != current.get("mode_policies", {}).get(mode)):
                            continue
                        proven_hosts.add(candidate["hostname"])
                        continue
                    if any(e.get("mode_settings", {}).get(mode) != proven.get("mode_settings", {}).get(mode)
                            or e.get("mode_policies", {}).get(mode) != proven.get("mode_policies", {}).get(mode)
                            for e in selected):
                        continue
                    ready = True
                    break
            if fixed_network:
                missing_hosts = {e["hostname"] for e in selected} - proven_hosts
                if missing_hosts:
                    missing_pilots.extend({"hostname": host, "mode": mode} for host in sorted(missing_hosts))
                    pilot_blocked.update((host, mode) for host in missing_hosts)
            elif not ready:
                missing_pilots.append(mode)
                pilot_blocked.update((e["hostname"], mode) for e in selected)
        ready_cells = [(e["hostname"], mode) for mode in modes for e in enrolled
                       if e.get("mode_readiness", {}).get(mode, True)
                       and (e["hostname"], mode) in startup_cells
                       and (e["hostname"], mode) not in pilot_blocked]
        if not ready_cells:
            raise ValueError("requested modes need a focused pilot or live admission: capture --pilot --chunk 1")
    if backend is None:
        from .resource_study_runtime import CaptureRuntime
        backend = CaptureRuntime(root, runtime, workers, hostnames=[e["hostname"] for e in enrolled])
    stop = stop or threading.Event()
    paused, busy, completed_pilots, attempts = set(pilot_blocked), set(), set(), 0
    allocation_errors = []
    clock_failures = {}
    tamaraw_retries = {}
    if pilot:
        chunk_sessions = 1
    cell_order = [(e["hostname"], m) for m in modes for e in enrolled
                  if e.get("mode_readiness", {}).get(m, True) and (e["hostname"], m) in startup_cells]
    enrollment_by_host = {e["hostname"]: e for e in enrolled}
    def scheduling_counts(cells):
        from .resource_study_cohorts import counts_snapshot
        snapshot = counts_snapshot(store, cells)
        if snapshot is None:
            local = {(row["hostname"], row["mode"]): row["accepted"] for row in store.status()["cells"]}
            snapshot = {cell: local.get(cell, 0) for cell in cells}
        if (set(snapshot) != set(cells)
                or any(type(value) is not int or not 0 <= value <= 400 for value in snapshot.values())):
            raise ValueError("scheduling accepted counts exceed their scientific cells")
        return snapshot

    def capture_chunk(worker, cell, allowance, initial_count):
        host, mode = cell
        attempted, credited = 0, 0
        # This hint limits the chunk only. Every reservation and commit still
        # checks fresh parent/global slot and tuple authority independently.
        while attempted < allowance and not stop.is_set() and initial_count + credited < 400:
            try:
                attempt = store.allocate_attempt(host, mode, purpose="pilot" if pilot else "formal")
            except (OSError, ValueError, RuntimeError) as error:
                # A changed epoch can require its own pilot even when another
                # cell has a mode pilot. No reservation or packet is invented;
                # healthy cells continue and the refused cell stays uncredited.
                return {"cell": cell, "attempted": attempted, "accepted": credited,
                        "paused": True, "allocation_error": str(error)}
            attempted += 1
            retry_state = tamaraw_retries.get(cell)
            if retry_state is not None and retry_state["pending_retry"] is not None:
                retry_state["pending_retry"]["fresh_attempt_id"] = attempt["attempt_id"]
                retry_state["actual_retries"] += 1
                retry_state["pending_retry"] = None
            attempt_started = time.monotonic()
            result = {}
            failure_origin = "backend"
            try:
                require_storage(root, reserve_bytes=store.plan().get("storage_reserve_bytes", 2 * 1024 ** 3))
                result = backend.capture(worker, attempt, enrollment_by_host[host])
                store.mark_captured(attempt["attempt_id"])
                if result.get("success") is not True:
                    failure_origin = "collector"
                    raise ValueError("collector rejected session: " + str(result.get("failure")))
                result["attempt_elapsed_seconds"] = time.monotonic() - attempt_started
                clock_failures[cell] = 0
                failure_origin = "seal"
                receipt_path = seal(root, attempt, enrollment_by_host[host], runtime, result, pilot=pilot)
                failure_origin = "commit"
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
                destination = root / store.publication_path(attempt)
                owner = destination / "attempt-owner.json"
                if destination.exists() and owner.is_file() and load(owner).get("attempt_id") == attempt["attempt_id"]:
                    target = root / "failures" / host / mode / attempt["attempt_id"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    destination.rename(target)
                store.fail_attempt(attempt["attempt_id"], str(error), kind="duplicate",
                    wall_seconds=time.monotonic() - attempt_started)
                continue
            except (OSError, ValueError, RuntimeError) as error:
                rejected = root / store.publication_path(attempt)
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
                reason = tamaraw_retry_reason(mode, result, error, origin=failure_origin,
                    policy=enrollment_by_host[host].get("mode_policies", {}).get(mode))
                if reason is not None:
                    retry_state = tamaraw_retries.setdefault(cell, {
                        "actual_retries": 0, "rejections": [], "pending_retry": None})
                    row = {"rejected_attempt_id": attempt["attempt_id"], "reason": reason,
                        "retry_permitted": len(retry_state["rejections"]) < TAMARAW_MAX_RETRIES,
                        "fresh_attempt_id": None, "scientific_credit": False}
                    retry_state["rejections"].append(row)
                    if row["retry_permitted"]:
                        retry_state["pending_retry"] = row
                        continue
                return {"cell": cell, "attempted": attempted, "accepted": credited, "paused": True}
        return {"cell": cell, "attempted": attempted, "accepted": credited, "paused": False}

    def chunk(worker, cell, allowance, initial_count):
        from .resource_study_cohorts import bind_source
        with bind_source(_source_auth):
            try:
                return capture_chunk(worker, cell, allowance, initial_count)
            finally:
                release = getattr(backend, "release", None)
                if release is not None:
                    release(worker)

    with _capture_executor(backend, workers) as executor:
        futures = {}
        available = list(range(workers))
        while futures or (available and not stop.is_set()):
            eligible = [c for c in cell_order if c not in paused and c not in completed_pilots and c[0] not in busy]
            counts = (scheduling_counts(eligible) if available and not stop.is_set()
                      and (budget is None or attempts < budget) and eligible else {})
            while available and not stop.is_set() and (budget is None or attempts < budget):
                choices = [c for c in cell_order if c not in paused and c not in completed_pilots
                           and c[0] not in busy and counts.get(c, 400) < 400]
                if not choices:
                    break
                cell = min(choices, key=lambda c: (counts[c], cell_order.index(c)))
                allowance = min(chunk_sessions, 400 - counts[cell], (budget - attempts) if budget else chunk_sessions)
                worker = available.pop(0)
                attempts += allowance
                busy.add(cell[0])
                futures[executor.submit(chunk, worker, cell, allowance, counts[cell])] = worker
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
            "tamaraw_strict_rejection_retries": {"policy": TAMARAW_RETRY_POLICY,
                "max_retries_per_cell_per_invocation": TAMARAW_MAX_RETRIES,
                "success_resets_budget": False, "attempt_budget": budget,
                "dispatched_attempt_allowance": attempts, "chunk_sessions": chunk_sessions,
                "pilot": pilot, "cells": [{"hostname": cell[0], "mode": cell[1],
                    "actual_retry_count": state["actual_retries"], "rejections": state["rejections"],
                    "retry_pending_without_allocation": state["pending_retry"] is not None}
                    for cell, state in sorted(tamaraw_retries.items())]},
            "storage": storage_snapshot(root)}


def verify(root: Path, *, recover=False, all_receipts=False) -> dict:
    store = StudyStore(root)
    recovered = {}
    if recover:
        from .resource_study_runtime import docker_lock
        with docker_lock():
            recovered = store.recover()
    paths = store.verification_paths()
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
    shared = actions.add_parser("capture-roots", help="one protected flight for two current Native93 CS writer roots")
    shared.add_argument("--root", type=Path, required=True, help="existing selected50 parent")
    shared.add_argument("--runtime", type=Path, required=True)
    shared.add_argument("--cells", type=Path, required=True, help="immutable explicit root/hostname/CS plan")
    shared.add_argument("--cells-sha256", required=True)
    shared.add_argument("--workers", type=int, default=11)
    shared.add_argument("--attempts", type=int, required=True)
    shared.add_argument("--chunk", type=int, default=CHUNK)
    shared.add_argument("--pilot", action="store_true")
    for action in ("cohort-init", "cohort-template", "cohort-admit", "cohort-first-template", "cohort-first-admit"):
        child = actions.add_parser(action, help="explicit compatible-runtime cohort protocol; no imported credit")
        child.add_argument("--root", type=Path, required=True, help="existing selected50 parent")
        child.add_argument("--cohort-root", type=Path, required=True, help="fresh separate immutable cohort ledger")
        if action in {"cohort-template", "cohort-first-template"}:
            child.add_argument("--affected-hostname", action="append", required=True)
            child.add_argument("--affected-mode", choices=MODES, action="append", required=True)
        elif action in {"cohort-admit", "cohort-first-admit"}:
            child.add_argument("--declaration", type=Path, required=True)
            child.add_argument("--declaration-sha256", required=True)
    for action in ("prepare", "capture", "status", "verify", "export"):
        child = actions.add_parser(action)
        child.add_argument("--root", type=Path, required=True)
        if action in {"prepare", "capture"}:
            child.add_argument("--runtime", type=Path)
            child.add_argument("--hostname", action="append", default=[])
        if action == "prepare":
            child.add_argument("--source", type=Path)
            child.add_argument("--storage-reserve-bytes", type=int,
                               help="freeze reserve in the new plan (default sixty GiB); cannot alter an existing plan")
            child.add_argument("--class-network-pool", help="freeze an RFC1918 /23 for fifty disjoint class /29s")
            child.add_argument("--stable-map-parent", type=Path,
                               help="freeze a fresh Xoilac-to-MAL candidate root retaining49 class assignments; no parent admission")
            child.add_argument("--inventory", type=Path, action="append", default=[], help="explicitly add a Native URL inventory as a reserve pool")
            child.add_argument("--enroll", action="store_true")
            child.add_argument("--resource-selection", type=Path,
                               help="immutable exact twenty-URL selection from the authenticated class pool")
            child.add_argument("--resource-selection-sha256", help="SHA-256 of the exact selection manifest bytes")
            child.add_argument("--epoch-of", type=Path)
            child.add_argument("--epoch-change", choices=("resources", "mode", "native", "acceptance", "qualification", "add-host", "network", "replace-unused-class"))
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
        if action in {"verify", "export"}:
            child.add_argument("--verification-workers", type=int, default=1,
                               help="bounded spawned raw-proof workers for parent audits only (default one)")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    root = args.root.absolute()
    try:
        if args.action == "cohort-init":
            from .resource_study_cohorts import initialize_cohort
            output = initialize_cohort(root, args.cohort_root.absolute())
        elif args.action == "cohort-template":
            from .resource_study_cohorts import compatibility_template
            output = compatibility_template(root, args.cohort_root.absolute(),
                affected_hostnames=args.affected_hostname, affected_modes=args.affected_mode)
        elif args.action == "cohort-admit":
            from .resource_study_cohorts import create_cohort
            output = create_cohort(root, args.cohort_root.absolute(), args.declaration.absolute(), args.declaration_sha256)
        elif args.action == "cohort-first-template":
            from .resource_study_cohorts import first_mode_template
            output = first_mode_template(root, args.cohort_root.absolute(),
                affected_hostnames=args.affected_hostname, affected_modes=args.affected_mode)
        elif args.action == "cohort-first-admit":
            from .resource_study_cohorts import create_first_modes
            output = create_first_modes(root, args.cohort_root.absolute(), args.declaration.absolute(), args.declaration_sha256)
        elif args.action == "prepare":
            stable_initialized = False
            if args.stable_map_parent is not None:
                if (len(args.inventory) != 1 or args.class_network_pool is not None
                        or args.resource_selection is not None or args.resource_selection_sha256 is not None
                        or args.epoch_of is not None or args.epoch_change is not None
                        or args.affected_hostname or args.affected_mode):
                    raise ValueError("stable-map initialization needs one reserve inventory and a separate admission operation")
                from .resource_study_lineage import initialize as initialize_stable
                if args.source is not None and sha256_file(args.source) != StudyStore(args.stable_map_parent).plan()["source_sha256"]:
                    raise ValueError("stable-map original source differs from its parent")
                initialize_stable(args.stable_map_parent.absolute(), root, args.inventory[0].absolute(),
                    storage_reserve_bytes=args.storage_reserve_bytes if args.storage_reserve_bytes is not None else DEFAULT_STORAGE_RESERVE_BYTES)
                stable_initialized = True
            selection_requested = _selection_request(args.resource_selection, args.resource_selection_sha256, args.hostname)
            if selection_requested:
                if not args.enroll or args.runtime is None:
                    raise ValueError("explicit resource selection requires live --enroll and --runtime")
                if (args.epoch_of is not None or args.epoch_change is not None
                        or args.affected_hostname or args.affected_mode):
                    if (args.epoch_of is None or args.epoch_change != "resources"
                            or args.affected_hostname != args.hostname
                            or args.affected_mode and (len(args.affected_mode) != len(MODES)
                                or set(args.affected_mode) != set(MODES))):
                        raise ValueError("explicit resource selection epoch scope must be one matching hostname and all five resource modes")
                if (root / "study.json").exists():
                    _selection_unused(StudyStore(root), args.hostname[0])
            if not (root / "study.json").exists():
                if args.source is None:
                    raise ValueError("first prepare needs --source")
                initialize(args.source.absolute(), root,
                    storage_reserve_bytes=args.storage_reserve_bytes if args.storage_reserve_bytes is not None else DEFAULT_STORAGE_RESERVE_BYTES,
                    class_network_pool=args.class_network_pool or DEFAULT_POOL)
            elif args.source is not None and sha256_file(args.source) != StudyStore(root).plan()["source_sha256"]:
                raise ValueError("existing study has a different frozen supplied source")
            plan = StudyStore(root).plan()
            if (args.storage_reserve_bytes is not None and args.storage_reserve_bytes != plan.get("storage_reserve_bytes")
                    or args.class_network_pool is not None and args.class_network_pool != plan.get("class_network", {}).get("pool")):
                raise ValueError("existing immutable study reserve/network pool cannot change")
            if args.inventory and not stable_initialized:
                add_inventories(root, [p.absolute() for p in args.inventory])
            if args.enroll:
                if args.runtime is None or not args.hostname:
                    raise ValueError("live preparation needs --runtime and --hostname")
                runtime = runtime_identity(args.runtime.absolute())
                output = (enroll(root, runtime, args.hostname,
                    resource_selection=args.resource_selection,
                    resource_selection_sha256=args.resource_selection_sha256)
                    if selection_requested else enroll(root, runtime, args.hostname))
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
        elif args.action == "capture-roots":
            cells = load_shared_capture_plan(args.cells.absolute(), args.cells_sha256, root)
            stop = threading.Event()
            previous = {}
            for sig in (signal.SIGINT, signal.SIGTERM):
                previous[sig] = signal.signal(sig, lambda *_: stop.set())
            try:
                output = capture_roots(root, runtime_identity(args.runtime.absolute()), cells,
                    workers=args.workers, budget=args.attempts, stop=stop,
                    chunk_sessions=args.chunk, pilot=args.pilot)
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
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
            from .resource_study_audit import verification_workers
            verification_workers(args.verification_workers)
            parent = is_parent(root)
            if not parent and args.verification_workers != 1:
                raise ValueError("parallel receipt verification requires an epoch parent study")
            output = (verify_epochs(root, recover=args.recover, verification_workers=args.verification_workers)
                      if parent else verify(root, recover=args.recover, all_receipts=args.all_receipts))
        else:
            from .resource_study_epochs import is_parent, export_manifest
            from .resource_study_audit import verification_workers
            verification_workers(args.verification_workers)
            parent = is_parent(root)
            if not parent and args.verification_workers != 1:
                raise ValueError("parallel receipt verification requires an epoch parent study")
            output = (export_manifest(root, args.output.absolute(), verification_workers=args.verification_workers)
                      if parent else StudyStore(root).export_manifest(args.output.absolute()))
        print(json.dumps(output, sort_keys=True, allow_nan=False))
        return 1 if output.get("errors") or output.get("paused_cells") else 0
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({"status": "refused", "reason": str(error), "error": type(error).__name__}))
        return 1


SHARED_CAPTURE_PLAN = "qcsd-resource-domain-two-root-CS-capture-plan-v1"


def _shared_cells(cells):
    from .resource_study_epochs import _hostname
    from .resource_study_runtime import shared_roots
    if type(cells) is not list or not 2 <= len(cells) <= 50:
        raise ValueError("shared capture needs between two and fifty explicit cells")
    normalized = []
    for row in cells:
        if (type(row) is not dict or set(row) != {"root", "hostname", "mode"}
                or type(row["root"]) is not str or row["mode"] != "cs-buflo"
                or _hostname(row["hostname"]) != row["hostname"]):
            raise ValueError("shared capture cells must be exact root/hostname/CS bindings")
        normalized.append((Path(row["root"]), row["hostname"], row["mode"]))
    roots = shared_roots(list(dict.fromkeys(root for root, _, _ in normalized)))
    if len({(host, mode) for _, host, mode in normalized}) != len(normalized):
        raise ValueError("shared capture repeats a logical hostname/mode cell")
    return roots, normalized


def _multiroot_context(parent, runtime, cells):
    """Authenticate both current writers; reservation/credit repeat live guards."""
    from . import resource_study_epochs as epochs
    from . import resource_study_cohorts as cohorts
    from .resource_study_runtime import require_shared_runtime
    require_shared_runtime(runtime)
    roots, normalized = _shared_cells(cells)
    parent = epochs._regular(parent, directory=True)
    if parent in roots or any(parent in root.parents or root in parent.parents for root in roots):
        raise ValueError("shared capture parent and writer roots must be separate")
    stores = {root: StudyStore(root) for root in roots}
    parent_store = StudyStore(parent)
    contexts, jobs = {}, {}
    with epochs._lock(parent):
        records = epochs._records(parent_store)
        if not records or records[-1]["record_type"] != cohorts.ADMISSION:
            raise ValueError("shared capture requires the committed runtime-cohort protocol")
        current = records[-1]
        for root, store in stores.items():
            member_parent = epochs._membership(store)
            if member_parent is None or member_parent.root != parent:
                raise ValueError("shared capture writer has another or missing parent")
            plan = store.plan()
            if ("class_selection" not in plan or validate_network_plan(plan, require=True) is None):
                raise ValueError("shared capture needs the unchanged stable selected50 plan")
            contexts[root] = {"plan": plan, "study_sha256": store._file("study.json")[1]["sha256"]}
        first = contexts[roots[0]]["plan"]
        if any(contexts[root]["plan"].get(key) != first.get(key)
               for root in roots for key in ("class_selection", "class_network", "source_sha256", "acceptance", "tuple_uniqueness_scope")):
            raise ValueError("shared capture roots have different frozen class plans")
        enrolled = {root: {value["hostname"]: value for value in store.enrolled()}
                    for root, store in stores.items()}
        for root, host, mode in normalized:
            store = stores[root]
            cell = epochs._active(store, host, mode, records)
            entry = cohorts._entry(current["cohorts"], (host, mode))
            if cohorts._writer(entry)["cell"] != cell:
                raise ValueError("shared capture cell is not the exact current cohort writer")
            enrollment = enrolled[root].get(host)
            if (enrollment is None or enrollment["runtime"] != runtime
                    or cell["definition"]["ready"] is not True
                    or cell["definition"]["native"] != [runtime["client_sha256"], runtime["platform"], runtime["native_commit"]]):
                raise ValueError("shared capture enrollment/runtime/readiness differs")
            jobs[(host, mode)] = {"root": root, "store": store, "enrollment": enrollment}
        authority = {"sequence": current["sequence"], "sha256": epochs._sha(current)}
    return contexts, jobs, authority


def _shared_pilot(root, enrollment, runtime, mode):
    """The same fixed-network own-host/enrollment/full-runtime public pilot gate."""
    for path in sorted((root / "pilots").glob(f"*/{mode}/*/session.json")):
        candidate = load(path)
        if (candidate.get("purpose") != "pilot" or candidate.get("mode") != mode
                or candidate.get("hostname") != enrollment["hostname"] or candidate.get("runtime") != runtime):
            continue
        verify_receipt(root, candidate)
        proven = load(root / candidate["artifact_paths"]["enrollment"])
        if (proven == enrollment and candidate.get("mode_settings") == enrollment.get("mode_settings", {}).get(mode)
                and candidate.get("mode_policies") == enrollment.get("mode_policies", {}).get(mode)):
            return True
    return False


def capture_roots(parent: Path, runtime: dict, cells: list, *, workers=11, budget=None,
                  stop=None, backend=None, chunk_sessions=CHUNK, pilot=False):
    """Two current CS writer roots, one bounded global queue and Docker flight.

    Counts only choose work. Each owning Store still performs its original
    fresh global quota/tuple/head/fence and matching-pilot checks at mutation.
    No historical raw proof is reused or asserted by this launcher.
    """
    if type(workers) is not int or not 2 <= workers <= 11:
        raise ValueError("shared capture requires between two and eleven workers")
    if type(budget) is not int or not 1 <= budget <= 1900:
        raise ValueError("shared capture needs a finite attempt budget between one and 1900")
    if type(chunk_sessions) is not int or not 1 <= chunk_sessions <= CHUNK:
        raise ValueError("chunk size must be between one and twenty")
    if type(pilot) is not bool:
        raise ValueError("shared pilot flag must be boolean")
    roots, _ = _shared_cells(cells)
    from .resource_study_cohorts import source_operation
    with source_operation(roots[0]) as source_auth:
        if source_auth is None:
            raise ValueError("shared capture requires committed cohort Source authority")
        return _capture_roots(parent, runtime, cells, workers=workers, budget=budget,
            stop=stop, backend=backend, chunk_sessions=chunk_sessions, pilot=pilot,
            _source_auth=source_auth)


def load_shared_capture_plan(path, digest, parent):
    from .resource_study_selection import _read, _json
    value = _json(_read(path, digest))
    if (set(value) != {"record_type", "schema_version", "parent", "cells"}
            or value["record_type"] != SHARED_CAPTURE_PLAN or type(value["schema_version"]) is not int
            or value["schema_version"] != 1 or value["parent"] != str(parent)):
        raise ValueError("shared capture plan differs from its explicit parent/schema")
    _shared_cells(value["cells"])
    return value["cells"]


def _capture_roots(parent, runtime, cells, *, workers, budget, stop, backend,
                   chunk_sessions, pilot, _source_auth):
    """Balanced chunks; a failing cell pauses for this invocation only.

    A subsequent invocation retries that cell without resetting others. Workers
    never capture the same hostname concurrently. Every attempted reservation
    is durable before any packet is sent.
    """
    contexts, jobs, authority = _multiroot_context(parent, runtime, cells)
    roots = list(contexts)
    storage = {str(root): require_storage(root,
        reserve_bytes=context["plan"].get("storage_reserve_bytes", 2 * 1024 ** 3))
        for root, context in contexts.items()}
    pilot_blocked, missing_pilots = set(), []
    if not pilot:
        for cell, job in jobs.items():
            if not _shared_pilot(job["root"], job["enrollment"], runtime, cell[1]):
                pilot_blocked.add(cell)
                missing_pilots.append({"root": str(job["root"]), "hostname": cell[0], "mode": cell[1]})
        if set(jobs) == pilot_blocked:
            raise ValueError("requested cells need their own matching focused pilots")
    if backend is None:
        from .resource_study_runtime import MultiRootCaptureRuntime
        backend = MultiRootCaptureRuntime(contexts, runtime, workers,
            cell_roots={host: job["root"] for (host, mode), job in jobs.items()})
    stop = stop or threading.Event()
    paused, busy, completed_pilots, attempts = set(pilot_blocked), set(), set(), 0
    allocation_errors = []
    clock_failures = {}
    tamaraw_retries = {}
    if pilot:
        chunk_sessions = 1
    cell_order = list(jobs)
    def scheduling_counts(cells):
        from .resource_study_cohorts import counts_snapshot
        snapshot = {}
        for root in roots:
            selected = [cell for cell in cells if jobs[cell]["root"] == root]
            if selected:
                values = counts_snapshot(next(jobs[cell]["store"] for cell in selected), selected)
                if values is None:
                    raise ValueError("shared capture requires committed runtime-cohort count authority")
                snapshot.update(values)
        if (set(snapshot) != set(cells)
                or any(type(value) is not int or not 0 <= value <= 400 for value in snapshot.values())):
            raise ValueError("scheduling accepted counts exceed their scientific cells")
        return snapshot

    def capture_chunk(worker, cell, allowance, initial_count):
        host, mode = cell
        job = jobs[cell]
        root, store = job["root"], job["store"]
        enrollment_by_host = {host: job["enrollment"]}
        attempted, credited = 0, 0
        # This hint limits the chunk only. Every reservation and commit still
        # checks fresh parent/global slot and tuple authority independently.
        while attempted < allowance and not stop.is_set() and initial_count + credited < 400:
            try:
                attempt = store.allocate_attempt(host, mode, purpose="pilot" if pilot else "formal")
            except (OSError, ValueError, RuntimeError) as error:
                # A changed epoch can require its own pilot even when another
                # cell has a mode pilot. No reservation or packet is invented;
                # healthy cells continue and the refused cell stays uncredited.
                return {"cell": cell, "attempted": attempted, "accepted": credited,
                        "paused": True, "allocation_error": str(error)}
            attempted += 1
            retry_state = tamaraw_retries.get(cell)
            if retry_state is not None and retry_state["pending_retry"] is not None:
                retry_state["pending_retry"]["fresh_attempt_id"] = attempt["attempt_id"]
                retry_state["actual_retries"] += 1
                retry_state["pending_retry"] = None
            attempt_started = time.monotonic()
            result = {}
            failure_origin = "backend"
            try:
                require_storage(root, reserve_bytes=store.plan().get("storage_reserve_bytes", 2 * 1024 ** 3))
                result = backend.capture(worker, attempt, enrollment_by_host[host])
                store.mark_captured(attempt["attempt_id"])
                if result.get("success") is not True:
                    failure_origin = "collector"
                    raise ValueError("collector rejected session: " + str(result.get("failure")))
                result["attempt_elapsed_seconds"] = time.monotonic() - attempt_started
                clock_failures[cell] = 0
                failure_origin = "seal"
                receipt_path = seal(root, attempt, enrollment_by_host[host], runtime, result, pilot=pilot)
                failure_origin = "commit"
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
                destination = root / store.publication_path(attempt)
                owner = destination / "attempt-owner.json"
                if destination.exists() and owner.is_file() and load(owner).get("attempt_id") == attempt["attempt_id"]:
                    target = root / "failures" / host / mode / attempt["attempt_id"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    destination.rename(target)
                store.fail_attempt(attempt["attempt_id"], str(error), kind="duplicate",
                    wall_seconds=time.monotonic() - attempt_started)
                continue
            except (OSError, ValueError, RuntimeError) as error:
                rejected = root / store.publication_path(attempt)
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
                reason = tamaraw_retry_reason(mode, result, error, origin=failure_origin,
                    policy=enrollment_by_host[host].get("mode_policies", {}).get(mode))
                if reason is not None:
                    retry_state = tamaraw_retries.setdefault(cell, {
                        "actual_retries": 0, "rejections": [], "pending_retry": None})
                    row = {"rejected_attempt_id": attempt["attempt_id"], "reason": reason,
                        "retry_permitted": len(retry_state["rejections"]) < TAMARAW_MAX_RETRIES,
                        "fresh_attempt_id": None, "scientific_credit": False}
                    retry_state["rejections"].append(row)
                    if row["retry_permitted"]:
                        retry_state["pending_retry"] = row
                        continue
                return {"cell": cell, "attempted": attempted, "accepted": credited, "paused": True}
        return {"cell": cell, "attempted": attempted, "accepted": credited, "paused": False}

    def chunk(worker, cell, allowance, initial_count):
        from .resource_study_cohorts import bind_source
        with bind_source(_source_auth):
            try:
                return capture_chunk(worker, cell, allowance, initial_count)
            finally:
                release = getattr(backend, "release", None)
                if release is not None:
                    release(worker)

    with _capture_executor(backend, workers) as executor:
        futures = {}
        available = list(range(workers))
        while futures or (available and not stop.is_set()):
            eligible = [c for c in cell_order if c not in paused and c not in completed_pilots and c[0] not in busy]
            counts = (scheduling_counts(eligible) if available and not stop.is_set()
                      and (budget is None or attempts < budget) and eligible else {})
            while available and not stop.is_set() and (budget is None or attempts < budget):
                choices = [c for c in cell_order if c not in paused and c not in completed_pilots
                           and c[0] not in busy and counts.get(c, 400) < 400]
                if not choices:
                    break
                cell = min(choices, key=lambda c: (counts[c], cell_order.index(c)))
                allowance = min(chunk_sessions, 400 - counts[cell], (budget - attempts) if budget else chunk_sessions)
                worker = available.pop(0)
                attempts += allowance
                busy.add(cell[0])
                futures[executor.submit(chunk, worker, cell, allowance, counts[cell])] = worker
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
    return {"record_type": "qcsd-resource-domain-two-root-CS-capture-result-v1",
        "schema_version": 1, "parent": str(parent), "admission_at_start": authority,
        "roots": [{"root": str(root), "study_sha256": context["study_sha256"],
                   "progress": StudyStore(root).status()} for root, context in contexts.items()],
        "paused_cells": [{"root": str(jobs[cell]["root"]), "hostname": cell[0], "mode": cell[1]}
                         for cell in sorted(paused)],
        "pilot_cells_passed": [{"root": str(jobs[cell]["root"]), "hostname": cell[0], "mode": cell[1]}
                               for cell in sorted(completed_pilots)],
        "missing_mode_pilots": missing_pilots, "allocation_errors": allocation_errors,
        "stop_requested": stop.is_set(), "workers": workers,
        "dispatched_attempt_allowance": attempts, "attempt_budget": budget,
        "chunk_sessions": chunk_sessions, "pilot": pilot,
        "storage": storage, "wrapper_issues_credit": False,
        "receipt_raw_and_ledger_gates": "original owning-root seal/reserve/commit/pilot predicates"}


if __name__ == "__main__":
    raise SystemExit(main())
