"""Bounded formal capture of existing admitted cells across fixed runtime lanes.

The catalog selects work; it grants no admission, pilot, reservation or credit.
Each owning Store retains the original fresh head/quota/tuple/receipt gates.
"""
from copy import deepcopy
from concurrent.futures import wait, FIRST_COMPLETED
import hashlib
from pathlib import Path
import threading
import time

from . import resource_study as study
from .resource_study_inputs import MODES, canonical_json, sha256_file
from .resource_study_store import StudyStore, DuplicateSession
from .resource_study_verify import load
from .resource_study_storage import require_storage
from .resource_study_network import validate_network_plan

CATALOG = "qcsd-resource-domain-existing-member-runtime-capture-catalog-v1"
RESULT = "qcsd-resource-domain-existing-member-runtime-catalog-capture-result-v1"
RECEIPT_BINDING = "qcsd-resource-domain-existing-member-runtime-catalog-receipt-v1"
RUNTIME_FIELDS = {"collection_image_digest", "prepare_image_digest", "client_sha256",
                  "platform", "native_commit", "source", "canonical_sha256"}
_capture_executor = study._capture_executor
seal, create_json = study.seal, study.create_json
temporary_clock_failure, tamaraw_retry_reason = study.temporary_clock_failure, study.tamaraw_retry_reason
BUFLO_MAX_CONSECUTIVE_COLLECTOR_FAILURES = study.BUFLO_MAX_CONSECUTIVE_COLLECTOR_FAILURES
TAMARAW_MAX_RETRIES = study.TAMARAW_MAX_RETRIES


def runtime_key(runtime):
    if type(runtime) is not dict or set(runtime) != RUNTIME_FIELDS:
        raise ValueError("catalog requires an exact full seven-field runtime")
    return hashlib.sha256(canonical_json(runtime)).hexdigest()


def normalize_catalog(value, parent):
    """Validate finite explicit scope, without granting current-writer authority."""
    from .resource_study_epochs import _hostname, _mode
    from .resource_study_selection import _digest
    parent = Path(parent)
    if (type(value) is not dict or set(value) != {"record_type", "schema_version", "parent",
            "admission", "cells", "worker_runtime_keys"}
            or value["record_type"] != CATALOG or type(value["schema_version"]) is not int
            or value["schema_version"] != 1 or value["parent"] != str(parent)
            or not parent.is_absolute()):
        raise ValueError("catalog has another explicit parent/schema")
    head = value["admission"]
    if (type(head) is not dict or set(head) != {"sequence", "sha256"}
            or type(head["sequence"]) is not int or head["sequence"] < 1):
        raise ValueError("catalog requires an exact committed admission head")
    _digest(head["sha256"])
    cells, lanes = value["cells"], value["worker_runtime_keys"]
    if type(cells) is not list or not 1 <= len(cells) <= 250:
        raise ValueError("catalog requires between one and250 explicit cells")
    if type(lanes) is not list or not 2 <= len(lanes) <= 11:
        raise ValueError("catalog requires two to eleven fixed runtime lanes")
    seen, hosts, keys = set(), {}, set()
    for row in cells:
        if (type(row) is not dict or set(row) != {"root", "hostname", "mode", "runtime"}
                or type(row["root"]) is not str or not Path(row["root"]).is_absolute()
                or _hostname(row["hostname"]) != row["hostname"] or _mode(row["mode"]) != row["mode"]
                or row["mode"] not in MODES):
            raise ValueError("catalog cells require exact owning root/hostname/mode/full-runtime")
        cell = row["hostname"], row["mode"]
        if cell in seen:
            raise ValueError("catalog repeats a logical cell")
        seen.add(cell)
        key = runtime_key(row["runtime"]);keys.add(key)
        owner = row["root"], canonical_json(row["runtime"])
        if row["hostname"] in hosts and hosts[row["hostname"]] != owner:
            raise ValueError("one catalog hostname must have one root and full runtime")
        hosts[row["hostname"]] = owner
    if any(type(key) is not str for key in lanes):
        raise ValueError("catalog lane runtime keys must be SHA256 strings")
    if len(hosts) > 50 or set(lanes) != keys:
        raise ValueError("all selected runtime groups require fixed compatible lanes")
    for key in lanes:_digest(key)
    return deepcopy(value)


def load_capture_catalog(path, digest, parent):
    from .resource_study_selection import _read, _json
    return normalize_catalog(_json(_read(path, digest)), parent)


def catalog_context(parent, catalog):
    """Authenticate original all-root membership, exact current writers and runtime."""
    from . import resource_study_epochs as epochs
    from . import resource_study_cohorts as cohorts
    parent = epochs._regular(parent, directory=True)
    catalog = normalize_catalog(catalog, parent)
    roots = [epochs._regular(Path(row["root"]), directory=True) for row in catalog["cells"]]
    roots = list(dict.fromkeys(roots))
    if (parent in roots or any(parent in root.parents or root in parent.parents for root in roots)
            or any(a in b.parents or b in a.parents for index,a in enumerate(roots)for b in roots[index+1:])):
        raise ValueError("catalog parent and owning roots must be separate canonical directories")
    stores = {root: StudyStore(root) for root in roots}
    contexts, jobs = {}, {}
    with epochs._lock(parent):
        parent_store = StudyStore(parent)
        with cohorts.capture_records_scope(parent_store,writer_root=roots[0],latest_only=False)as owned:
            # Real public startup already owns the exact full validation.
            # Standalone/injected context callers retain the original reader.
            records = epochs._records(parent_store)if owned is None else owned
            if not records or records[-1]["record_type"] != cohorts.ADMISSION:
                raise ValueError("catalog requires the committed existing runtime-cohort protocol")
            current = records[-1]
            authority = {"sequence": current["sequence"], "sha256": epochs._sha(current)}
            if catalog["admission"] != authority:
                raise ValueError("catalog admission head is stale or changed")
            for root, store in stores.items():
                owner = epochs._membership(store)
                if owner is None or owner.root != parent:
                    raise ValueError("catalog writer has another or missing parent")
                plan = store.plan()
                if "class_selection" not in plan or validate_network_plan(plan, require=True) is None:
                    raise ValueError("catalog needs the unchanged selected50 fixed-network plan")
                contexts[root] = {"plan": plan, "study_sha256": store._file("study.json")[1]["sha256"]}
            first = contexts[roots[0]]["plan"]
            if any(contexts[root]["plan"].get(key) != first.get(key) for root in roots
                    for key in ("class_selection", "class_network", "source_sha256", "acceptance", "tuple_uniqueness_scope")):
                raise ValueError("catalog roots have different frozen class plans")
            enrolled = {root: {e["hostname"]: e for e in store.enrolled()} for root,store in stores.items()}
            for row in catalog["cells"]:
                root, host, mode = Path(row["root"]), row["hostname"], row["mode"]
                store, runtime = stores[root], row["runtime"]
                cell = epochs._active(store, host, mode, records)
                entry = cohorts._entry(current["cohorts"], (host, mode))
                if cohorts._writer(entry)["cell"] != cell:
                    raise ValueError("catalog cell is not the exact current cohort writer")
                enrollment = enrolled[root].get(host)
                if (enrollment is None or enrollment["runtime"] != runtime
                        or cell["definition"]["ready"] is not True
                        or cell["definition"]["native"] != [runtime["client_sha256"],runtime["platform"],runtime["native_commit"]]):
                    raise ValueError("catalog enrollment/full-runtime/readiness differs")
                if "resource_version_input_authority" in enrollment:
                    raise ValueError("initial catalog role does not adopt resource-version members")
                jobs[(host,mode)] = {"root":root,"store":store,"enrollment":enrollment,
                                    "runtime":deepcopy(runtime),"runtime_key":runtime_key(runtime)}
    return contexts, jobs, authority


def receipt_binding(catalog, worker, cell):
    row = next(row for row in catalog["cells"]if (row["hostname"],row["mode"]) == cell)
    key = runtime_key(row["runtime"])
    if type(worker) is not int or not 0 <= worker < len(catalog["worker_runtime_keys"]) or catalog["worker_runtime_keys"][worker] != key:
        raise ValueError("catalog reservation cannot use an incompatible runtime lane")
    return {"record_type":RECEIPT_BINDING,"schema_version":1,"parent":catalog["parent"],
            "catalog_sha256":hashlib.sha256(canonical_json(catalog)).hexdigest(),
            "admission_at_start":deepcopy(catalog["admission"]),"root":row["root"],
            "hostname":row["hostname"],"mode":row["mode"],"runtime_key":key,"worker":worker,
            "worker_runtime_key":catalog["worker_runtime_keys"][worker],"runtime":deepcopy(row["runtime"])}


def check_catalog_head(parent, catalog, writer_root):
    """Rejoin the requested head inside the actual owned capture authority."""
    from . import resource_study_epochs as epochs
    from .resource_study_cohorts import capture_records_scope, ADMISSION
    store=StudyStore(parent)
    def compare(records):
        if(not records or records[-1]["record_type"]!=ADMISSION
                or {"sequence":records[-1]["sequence"],"sha256":epochs._sha(records[-1])}!=catalog["admission"]):
            raise ValueError("catalog admission head changed before or during its owned flight")
    with capture_records_scope(store,writer_root=writer_root,latest_only=True)as captured:
        if captured is None:
            # Explicit injected test backends have no owned CaptureAuthority.
            # The public Catalog backend always takes the borrowed branch.
            with epochs._lock(parent):compare(epochs._records(store))
        else:
            compare(captured)


def validate_receipt_binding(binding, root, attempt, enrollment, runtime):
    """Metadata-only binding; original raw and fresh SQL decide all credit."""
    from .resource_study_selection import _digest
    if (type(binding) is not dict or set(binding) != {"record_type","schema_version","parent","catalog_sha256",
            "admission_at_start","root","hostname","mode","runtime_key","worker","worker_runtime_key","runtime"}
            or binding["record_type"] != RECEIPT_BINDING or type(binding["schema_version"]) is not int
            or binding["schema_version"] != 1 or type(binding["worker"]) is not int or not 0 <= binding["worker"] < 11
            or binding["root"] != str(root) or binding["hostname"] != attempt["hostname"]
            or binding["hostname"] != enrollment["hostname"] or binding["mode"] != attempt["mode"]
            or binding["runtime"] != runtime or enrollment["runtime"] != runtime
            or binding["runtime_key"] != runtime_key(runtime) or binding["worker_runtime_key"] != binding["runtime_key"]):
        raise ValueError("catalog receipt root/attempt/full-runtime/lane binding differs")
    _digest(binding["catalog_sha256"])
    if type(binding["parent"]) is not str or not Path(binding["parent"]).is_absolute():
        raise ValueError("catalog receipt parent path differs")
    head=binding["admission_at_start"]
    if type(head) is not dict or set(head)!={"sequence","sha256"}or type(head["sequence"]) is not int or head["sequence"]<1:
        raise ValueError("catalog receipt admission metadata differs")
    _digest(head["sha256"])


def choose_assignment(available, cell_order, jobs, counts, paused, busy, dispatches):
    """Choose a compatible free lane before any reservation; rotate equal-count cells."""
    choices = [(cell,worker)for cell in cell_order if cell not in paused and cell[0] not in busy
        and counts.get(cell,400)<400 for worker in available
        if jobs[cell]["runtime_key"] == jobs["_lane_keys"][worker]]
    if not choices:return None
    return min(choices,key=lambda item:(counts[item[0]],dispatches.get(item[0],0),cell_order.index(item[0]),available.index(item[1])))


def capture_catalog(parent, catalog, *, workers=11, budget=None, stop=None, backend=None,
                    chunk_sessions=study.CHUNK, catalog_source=None, proof_workers=1):
    if type(workers) is not int or not 2<=workers<=11:
        raise ValueError("catalog requires two to eleven workers")
    if type(budget) is not int or not 1<=budget<=100000:
        raise ValueError("catalog needs a finite one to100000 attempt budget")
    if type(proof_workers) is not int or proof_workers not in (1, 2):
        raise ValueError("formal proof child capacity must be1 or2")
    if type(chunk_sessions) is not int or not 1<=chunk_sessions<=study.CHUNK:
        raise ValueError("catalog chunk must be between one and twenty")
    catalog=normalize_catalog(catalog,Path(parent))
    if len(catalog["worker_runtime_keys"]) != workers:
        raise ValueError("catalog lane count differs from requested workers")
    def check_catalog_input():
        if catalog_source is not None:
            if type(catalog_source)is not dict or set(catalog_source)!={"path","sha256"}:
                raise ValueError("catalog source reference differs")
            if load_capture_catalog(Path(catalog_source["path"]),catalog_source["sha256"],Path(parent))!=catalog:
                raise ValueError("catalog source bytes changed")
    check_catalog_input()
    from .resource_study_cohorts import source_operation
    roots=[Path(row["root"])for row in catalog["cells"]]
    with source_operation(roots[0])as source_auth:
        if source_auth is None:raise ValueError("catalog requires committed cohort Source authority")
        result=_capture_catalog(Path(parent),catalog,workers=workers,budget=budget,stop=stop,backend=backend,
            chunk_sessions=chunk_sessions,_source_auth=source_auth,proof_workers=proof_workers)
        check_catalog_input()
        result["catalog_input"]=deepcopy(catalog_source)
        return result


def _capture_catalog(parent,catalog,*,workers,budget,stop,backend,chunk_sessions,_source_auth,proof_workers):
    from .resource_study_verify_child import VerificationChildren
    if backend is not None:
        # Explicit injected backends keep their original context/fallback path.
        with VerificationChildren(proof_workers) as proof_verifier:
            return _capture_catalog_owned(parent,catalog,workers=workers,budget=budget,
                stop=stop,backend=backend,chunk_sessions=chunk_sessions,
                _source_auth=_source_auth,_startup_authority=None,proof_verifier=proof_verifier)
    from .resource_study_runtime import _catalog_capture_authority
    roots=list(dict.fromkeys(Path(row["root"])for row in catalog["cells"]))
    # One actual owner and one complete original validation span context,
    # topology, reservations and positive cleanup. No caller proof is accepted.
    with _catalog_capture_authority(roots)as authority:
        with VerificationChildren(proof_workers) as proof_verifier:
            return _capture_catalog_owned(parent,catalog,workers=workers,budget=budget,
                stop=stop,backend=None,chunk_sessions=chunk_sessions,
                _source_auth=_source_auth,_startup_authority=authority,proof_verifier=proof_verifier)


def _capture_catalog_owned(parent,catalog,*,workers,budget,stop,backend,
                           chunk_sessions,_source_auth,_startup_authority,proof_verifier):
    contexts,jobs,authority=catalog_context(parent,catalog)
    roots=list(contexts)
    storage={str(root):require_storage(root,reserve_bytes=context["plan"].get("storage_reserve_bytes",2*1024**3))for root,context in contexts.items()}
    pilot=False
    missing_pilots=[];paused=set()
    for cell,job in jobs.items():
        if not study._shared_pilot(job["root"],job["enrollment"],job["runtime"],cell[1]):
            paused.add(cell);missing_pilots.append({"root":str(job["root"]),"hostname":cell[0],"mode":cell[1]})
    if len(paused)==len(jobs):raise ValueError("catalog selected cells need their own matching focused pilots")
    lanes=tuple(catalog["worker_runtime_keys"])
    host_keys={host:job["runtime_key"]for(host,mode),job in jobs.items()}
    if backend is None:
        from .resource_study_runtime import CatalogCaptureRuntime
        backend=CatalogCaptureRuntime(contexts,workers,
            cell_roots={host:job["root"]for(host,mode),job in jobs.items()},
            host_runtimes={host:job["runtime"]for(host,mode),job in jobs.items()},
            worker_runtime_keys=list(lanes),
            host_modes={host:sorted(mode for h,mode in jobs if h==host)for host in host_keys},
            _startup_authority=_startup_authority)
    if tuple(backend.runtime_keys)!=lanes or backend.host_runtime_keys!=host_keys:
        raise ValueError("catalog backend lane/full-runtime binding differs")
    stop=stop or threading.Event()
    busy,completed_pilots,attempts=set(),set(),0
    allocation_errors=[];clock_failures={};buflo_failures={};tamaraw_retries={}
    from .resource_study_verify_child import measure_phase
    attempt_timings=[];timing_lock=threading.Lock()
    cell_order=list(jobs)
    def scheduling_counts(cells):
        from .resource_study_cohorts import counts_snapshot
        snapshot = {}
        for root in roots:
            selected = [cell for cell in cells if jobs[cell]["root"] == root]
            if selected:
                values = counts_snapshot(next(jobs[cell]["store"] for cell in selected), selected, latest_only=True)
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
        runtime = job["runtime"]
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
            attempt_timing = {"attempt_id":attempt["attempt_id"],"root":str(root),"hostname":host,"mode":mode}
            failure_origin = "backend"
            try:
                require_storage(root, reserve_bytes=store.plan().get("storage_reserve_bytes", 2 * 1024 ** 3))
                with measure_phase(attempt_timing,"capture"):
                    result = backend.capture(worker, attempt, enrollment_by_host[host])
                store.mark_captured(attempt["attempt_id"])
                if result.get("success") is not True:
                    failure_origin = "collector"
                    raise ValueError("collector rejected session: " + str(result.get("failure")))
                result["attempt_elapsed_seconds"] = time.monotonic() - attempt_started
                clock_failures[cell] = 0
                failure_origin = "seal"
                with measure_phase(attempt_timing,"seal"):
                    receipt_path = seal(root, attempt, enrollment_by_host[host], runtime, result, pilot=pilot,
                        catalog_binding=receipt_binding(catalog, worker, cell),proof_verifier=proof_verifier)
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
                    attempt_timing["proof"] = deepcopy(bound["raw_verification_timing"])
                    def checked_this_attempt(actual_root, value):
                        if actual_root != root or value != bound:
                            raise ValueError("receipt changed after independent verification")
                        return bound["facts"]
                    with measure_phase(attempt_timing,"commit"):
                        store.commit_verified(receipt_path, validator=checked_this_attempt)
                    credited += 1
                    if mode == "buflo":
                        buflo_failures[cell] = 0
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
                if mode == "buflo":
                    failure = result.get("failure")
                    if (not pilot and failure_origin == "collector"
                            and result.get("success") is False
                            and isinstance(failure, dict)
                            and type(failure.get("stage")) is str and failure["stage"]
                            and type(failure.get("details")) is list and failure["details"]
                            and all(type(detail) is dict and detail for detail in failure["details"])):
                        buflo_failures[cell] = buflo_failures.get(cell, 0) + 1
                        if buflo_failures[cell] < BUFLO_MAX_CONSECUTIVE_COLLECTOR_FAILURES:
                            continue
                    # BF never stacks its streak with the separate clock/T
                    # retry policies; all failures above remain durable negatives.
                    return {"cell": cell, "attempted": attempted, "accepted": credited, "paused": True}
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
            finally:
                attempt_timing["last_phase"] = failure_origin
                with timing_lock:
                    attempt_timings.append(attempt_timing)
        return {"cell": cell, "attempted": attempted, "accepted": credited, "paused": False}

    def chunk(worker, cell, allowance, initial_count, capture_auth):
        from .resource_study_cohorts import bind_source, bind_capture_authority
        with bind_source(_source_auth), bind_capture_authority(capture_auth, writer_root=jobs[cell]["root"]):
            try:
                return capture_chunk(worker, cell, allowance, initial_count)
            finally:
                release = getattr(backend, "release", None)
                if release is not None:
                    release(worker)

    with _capture_executor(backend,workers)as executor:
        check_catalog_head(parent,catalog,roots[0])
        futures={};available=list(range(workers));dispatches={}
        while futures or(available and not stop.is_set()):
            eligible=[cell for cell in cell_order if cell not in paused and cell[0]not in busy]
            counts=scheduling_counts(eligible)if available and not stop.is_set()and attempts<budget and eligible else{}
            while available and not stop.is_set()and attempts<budget:
                # Pure choice sees the frozen lane map; no incompatible cell
                # ever obtains a durable reservation on the wrong lane.
                chosen=choose_assignment(available,cell_order,{**jobs,"_lane_keys":lanes},counts,paused,busy,dispatches)
                if chosen is None:break
                cell,worker=chosen
                allowance=min(chunk_sessions,400-counts[cell],budget-attempts)
                available.remove(worker);attempts+=allowance;busy.add(cell[0])
                dispatches[cell]=dispatches.get(cell,0)+1
                futures[executor.submit(chunk,worker,cell,allowance,counts[cell],getattr(backend,"_capture_authority",None))]=worker
            if not futures:break
            done,_=wait(futures,timeout=1,return_when=FIRST_COMPLETED)
            for future in done:
                worker=futures.pop(future);available.append(worker);value=future.result();busy.remove(value["cell"][0])
                if value["paused"]:paused.add(value["cell"])
                if value.get("allocation_error"):
                    allocation_errors.append({"hostname":value["cell"][0],"mode":value["cell"][1],"reason":value["allocation_error"]})
        check_catalog_head(parent,catalog,roots[0])
    # Original source_operation exit and each backend all-root authority scope
    # recheck the full source/head/fence/SQL boundaries, including on failure.
    return {"record_type":RESULT,"schema_version":1,"parent":str(parent),"admission_at_start":authority,
        "catalog":deepcopy(catalog),"catalog_sha256":hashlib.sha256(canonical_json(catalog)).hexdigest(),
        "runtime_lanes":list(lanes),"coordinator_provenance":{**study.coordinator_provenance(class_selection=True),
            "files":{**study.coordinator_provenance(class_selection=True)["files"],"resource_study_catalog.py":sha256_file(Path(__file__))}},
        "roots":[{"root":str(root),"study_sha256":context["study_sha256"],"progress":StudyStore(root).status()}for root,context in contexts.items()],
        "paused_cells":[{"root":str(jobs[cell]["root"]),"hostname":cell[0],"mode":cell[1]}for cell in sorted(paused)],
        "missing_mode_pilots":missing_pilots,"allocation_errors":allocation_errors,"stop_requested":stop.is_set(),
        "workers":workers,"dispatched_attempt_allowance":attempts,"attempt_budget":budget,"chunk_sessions":chunk_sessions,
        "pilot":False,"storage":storage,"wrapper_issues_credit":False,
        "new_formal_verification_timing":{"capacity":proof_verifier.capacity,"attempts":sorted(attempt_timings,key=lambda row:row["attempt_id"])},
        "receipt_raw_and_ledger_gates":"original owning-root seal/reserve/commit and exact own-pilot predicates"}
