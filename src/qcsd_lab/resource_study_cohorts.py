"""Explicit compatible-runtime cohorts within one logical resource-study cell.

This is a new parent protocol, not a V3 epoch or a replacement enrollment.
Admissions preserve the currently credited rows in their original immutable
roots. They authorize only prospective reservations in the latest cohort.
An operator's compatibility declaration does not certify traffic or issue
credit: every new formal receipt still passes the original Store/raw gates.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from copy import deepcopy
import hashlib
import json
import os
import stat
import threading
from pathlib import Path
from types import FunctionType

from .resource_study_inputs import MODES, canonical_json, sha256_file
from .resource_study_store import StudyStore, _PLAN_READ_SCOPE, _create, _load, _json, _tuple, _hostname, _mode, _digest
from .resource_study_audit import ReceiptReplay, verification_workers as _verification_workers
from .resource_study_verify import verify_receipt
from . import resource_study_reader_compatibility as reader_compatibility

ADMISSION = "qcsd-resource-domain-runtime-cohort-admission-v1"
DECLARATION = "qcsd-resource-domain-compatible-runtime-declaration-v1"
FIRST_MODE_DECLARATION = "qcsd-resource-domain-first-mode-cohort-declaration-v1"
COMPOSITION = "qcsd-resource-domain-runtime-cohort-composition-v1"
SNAPSHOT = "qcsd-resource-domain-runtime-cohort-retained-accepted-v1"
MARKER_TYPE = "qcsd-resource-domain-runtime-cohort-membership-v1"
MARKER = "runtime-cohort-membership.json"
VERIFIER = "qcsd-resource-domain-runtime-cohort-verifier-contract-v1"
INPUT_CONTEXT = "inputs/runtime-cohort-input-context.json"
INPUT_CONTEXT_TYPE = "qcsd-resource-domain-runtime-cohort-input-context-v1"
INPUT_AUTHORITY_KEY = "runtime_cohort_input_authority"
INPUT_AUTHORITY_TYPE = "qcsd-resource-domain-runtime-cohort-input-binding-v1"
V3 = "qcsd-resource-domain-cell-epoch-admission-v3"
ACTIVE = ("reserved", "captured", "unverified")

# Conservative complete declared package-import closure, including dormant
# branches. Hash these source bytes only; never import/execute that graph.
RAW_DEPENDENCIES = (
    '__init__.py',
    'acquisition_errors.py',
    'acquisition_selection.py',
    'acquisition_timing.py',
    'application_response_policy.py',
    'browser_egress.py',
    'browser_egress_dns.py',
    'browser_egress_dns_evidence.py',
    'browser_egress_dns_packets.py',
    'browser_egress_fixture.py',
    'browser_egress_observer.py',
    'browser_egress_qualification.py',
    'buflo_duration_budget.py',
    'buflo_evaluation.py',
    'buflo_handoff.py',
    'buflo_reference.py',
    'buflo_study.py',
    'build_storage.py',
    'capture.py',
    'capture_acceptance_policy.py',
    'capture_session.py',
    'cdp_targets.py',
    'chaff_qualification.py',
    'class_acquisition.py',
    'class_attestation.py',
    'class_campaigns.py',
    'class_capture20.py',
    'class_catalogue.py',
    'class_cohort.py',
    'class_cohort20.py',
    'class_curated_source.py',
    'class_evaluation.py',
    'class_final_selection20.py',
    'class_fitting.py',
    'class_handoff.py',
    'class_history20.py',
    'class_layout.py',
    'class_pair_screening20.py',
    'class_pipeline.py',
    'class_profile_result.py',
    'class_public20.py',
    'class_readiness20.py',
    'class_run_binding.py',
    'class_study.py',
    'class_successor.py',
    'class_validation20.py',
    'cohort_allocation.py',
    'defenses.py',
    'discover.py',
    'discovery_evidence.py',
    'experiment.py',
    'fidelity.py',
    'fitting.py',
    'fitting_morphing.py',
    'fitting_trace.py',
    'fitting_walkie_talkie.py',
    'fitting_wtfpad.py',
    'front_fixed_configuration.py',
    'front_incoming_acceptance.py',
    'front_preparation_evidence.py',
    'h3_prebaseline.py',
    'kernel_tx.py',
    'kernel_tx_runtime.py',
    'manifest.py',
    'orchestrator.py',
    'parameters.py',
    'per_class_selected_capture_amendment.py',
    'pinned_cdp.py',
    'playwright_driver.py',
    'prepare.py',
    'process_scheduler.py',
    'profiles.py',
    'qualification_control_authority.py',
    'qualification_delivery_compatibility.py',
    'rapid_action_local_source_facts.py',
    'rapid_additive_static_enrollment.py',
    'rapid_ael_fifteen_qualification.py',
    'rapid_attempt_failure_evidence.py',
    'rapid_browser_policy_evidence.py',
    'rapid_canary_control_bridge.py',
    'rapid_capture_control_compatibility.py',
    'rapid_capture_control_installation.py',
    'rapid_capture_plan.py',
    'rapid_capture_traffic.py',
    'rapid_chunk_partial_lane.py',
    'rapid_class_epochs.py',
    'rapid_collector_failure_evidence.py',
    'rapid_enrolled_subgroup.py',
    'rapid_epoch_corpus.py',
    'rapid_epoch_target_chunks.py',
    'rapid_epoch_target_parallel_schedule.py',
    'rapid_fixed_condition_target.py',
    'rapid_formal_parallel.py',
    'rapid_front_capture_amendment.py',
    'rapid_front_quick_compatibility.py',
    'rapid_front_quick_profile.py',
    'rapid_lane_evidence.py',
    'rapid_mixed_implementation_target.py',
    'rapid_operation_facts.py',
    'rapid_ordinary_canary_carry.py',
    'rapid_ordinary_canary_retry.py',
    'rapid_ordinary_group_canary.py',
    'rapid_ordinary_parallel_schedule.py',
    'rapid_ordinary_transport_control.py',
    'rapid_original_static_parallel_schedule.py',
    'rapid_page_evidence.py',
    'rapid_parallel_capture.py',
    'rapid_parallel_partial_lane.py',
    'rapid_partial_lane.py',
    'rapid_partial_progress.py',
    'rapid_per_class_selected_enrollment.py',
    'rapid_per_class_selected_input.py',
    'rapid_per_mode_native_target.py',
    'rapid_portable_runtime.py',
    'rapid_quick_profile.py',
    'rapid_rolling_capture.py',
    'rapid_rolling_readiness.py',
    'rapid_rolling_schedule.py',
    'rapid_runtime_compatibility.py',
    'rapid_runtime_epochs.py',
    'rapid_runtime_inspector.py',
    'rapid_selected_budget_input.py',
    'rapid_selected_capture_input.py',
    'rapid_selected_input_renewal.py',
    'rapid_selected_parallel_schedule.py',
    'rapid_selection_amendment.py',
    'rapid_site_admission.py',
    'rapid_slot_chunks.py',
    'rapid_static_parallel_schedule.py',
    'rapid_study_profile.py',
    'rapid_supplemental_cohort.py',
    'rapid_target_chunks.py',
    'rapid_target_overlay_source.py',
    'rapid_target_parallel_schedule.py',
    'rapid_undefended_capture.py',
    'resource_study.py',
    'resource_study_audit.py',
    'resource_study_cohorts.py',
    'resource_study_epochs.py',
    'resource_study_inputs.py',
    'resource_study_integrity.py',
    'resource_study_lineage.py',
    'resource_study_native.py',
    'resource_study_network.py',
    'resource_study_reader_compatibility.py',
    'resource_study_runtime.py',
    'resource_study_selection.py',
    'resource_study_storage.py',
    'resource_study_store.py',
    'resource_study_supplements.py',
    'resource_study_verify.py',
    'response_budget_qualification.py',
    'runtime_provenance.py',
    'selected_capture_amendment.py',
    'static_budget_capture.py',
    'static_budget_capture_amendment.py',
    'static_evidence_transport.py',
    'supplied_static_admission.py',
    'supplied_static_bootstrap_get.py',
    'supplied_static_budget_successor.py',
    'supplied_static_capture_amendment.py',
    'supplied_static_get.py',
    'supplied_static_graph.py',
    'supplied_static_preparation.py',
    'tamaraw_fixed_configuration.py',
    'util.py',
    'verification.py',
    'whole_graph_capture_amendment.py',
    'whole_graph_input.py',
    'whole_graph_supplement.py',
)


def _epochs():
    from . import resource_study_epochs
    return resource_study_epochs


def _same(left, right):
    return canonical_json(left) == canonical_json(right)


def _fresh_verifier_contract():
    """Closed dispatch registry: this version supports one unchanged raw reader.

    Different Native tuples are data, not different acceptance rules. A future
    verifier version needs an explicit reviewed registry entry; unknown source
    contracts never fall through to whichever verifier happens to pass.
    """
    source = Path(__file__).parent
    names = ("resource_study_verify.py", "resource_study_inputs.py", "fidelity.py",
             "resource_study_native.py", "resource_study_network.py",
             "resource_study_selection.py", "resource_study_lineage.py",
             "kernel_tx.py", "process_scheduler.py", "capture.py")
    closure = {name: sha256_file(source / name) for name in RAW_DEPENDENCIES}
    return {"record_type": VERIFIER, "schema_version": 1,
            "implementation": "resource-study-raw-v1",
            "files": {name: closure[name] for name in names},
            "transitive_source_sha256": _epochs()._sha(closure),
            "transitive_source_files": len(closure),
            "transitive_source_scope": "complete declared package-import closure; conservative dormant branches included"}


_SOURCE_OPERATION = ContextVar("resource-study-cohort-source-operation", default=None)


def _source_stamps():
    """Source-only metadata; never a dataset/head/row/proof cache."""
    root = Path(__file__).parent
    stamps, total = {}, 0
    for name in RAW_DEPENDENCIES:
        path = _epochs()._regular(root / name)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4 * 1024**2:
            raise ValueError("qualifying Source file type/size differs")
        total += info.st_size
        stamps[name] = (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
            info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if total > 32 * 1024**2: raise ValueError("qualifying Source graph exceeds its bounded size")
    return stamps


class _SourceAuthorization:
    __slots__ = ("pid", "profile", "stamps", "active")

    def __init__(self):
        self.pid = os.getpid()
        self.stamps = _source_stamps()
        self.profile = canonical_json(_fresh_verifier_contract())
        if self.stamps != _source_stamps(): raise ValueError("qualifying Source changed during authentication")
        self.active = True

    def check(self):
        if not self.active or self.pid != os.getpid() or self.stamps != _source_stamps():
            raise ValueError("qualifying Source operation is closed, foreign, or changed")


def verifier_contract():
    """Fresh hash outside an operation; bounded Source metadata guards within.

    Operation entry/exit rehash every Source file. This shares no admission
    head, SQL state, accepted count, receipt, raw facts, or scientific proof.
    """
    auth = _SOURCE_OPERATION.get()
    if auth is None: return _fresh_verifier_contract()
    if type(auth) is not _SourceAuthorization: raise ValueError("foreign Source operation handle")
    auth.check()
    return _load(auth.profile)


@contextmanager
def bind_source(auth):
    """Explicit same-process worker handoff; no dataset write authority."""
    if auth is None:
        yield
        return
    if type(auth) is not _SourceAuthorization: raise ValueError("foreign Source operation handle")
    auth.check()
    previous = _SOURCE_OPERATION.get()
    if previous is not None and previous is not auth: raise ValueError("Source operations cannot widen or overlap")
    token = _SOURCE_OPERATION.set(auth)
    try:
        yield
    finally:
        _SOURCE_OPERATION.reset(token)


@contextmanager
def source_operation(store_or_root):
    """One capture operation, with all worker contexts joined before exit."""
    store = store_or_root if isinstance(store_or_root, StudyStore) else StudyStore(Path(store_or_root).absolute())
    if not (store.root / MARKER).exists() and not (store.root / MARKER).is_symlink():
        yield None
        return
    if _SOURCE_OPERATION.get() is not None: raise ValueError("Source operation must have one explicit owner")
    auth = _SourceAuthorization()
    token = _SOURCE_OPERATION.set(auth)
    body_error = None
    try:
        yield auth
    except BaseException as error:
        body_error = error
        raise
    finally:
        try:
            auth.check()
            if not _same(_load(auth.profile), _fresh_verifier_contract()) or auth.stamps != _source_stamps():
                raise ValueError("qualifying Source bytes changed before operation closed")
        except BaseException as failure:
            if body_error is None: raise
            body_error.add_note("Source closure also refused: " + str(failure))
        finally:
            auth.active = False
            _SOURCE_OPERATION.reset(token)


def verify_by_contract(member, root, receipt):
    execution = verifier_contract()
    qualified = reader_compatibility.qualify_execution(execution)
    reader_compatibility.require_supported(member["verifier"], qualified)
    _receipt_verifier_contract(member, receipt)
    result = verify_receipt(root, receipt)
    if not _same(execution, verifier_contract()):
        raise ValueError("cohort raw verifier source changed during replay")
    return result


def _records_file(path, *, content=False):
    """One immutable input, with the same canonical FD/path authority on hits."""
    path = Path(path)
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or any(p.is_symlink() for p in (path, *path.parents))):
        raise ValueError("records input path is not canonical and unlinked")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o444):
            raise ValueError("records input is not one immutable regular authority")
        digest, chunks = hashlib.sha256(), []
        if content:
            for block in iter(lambda: stream.read(1024**2), b""):
                digest.update(block); chunks.append(block)
        after = os.fstat(stream.fileno())
    def stamp(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if (stamp(before) != stamp(after) or stamp(before) != stamp(path.lstat())
            or path.resolve(strict=True) != path
            or any(p.is_symlink() for p in (path, *path.parents))):
        raise ValueError("records input FD/path changed")
    raw = b"".join(chunks) if content else None
    if content and len(raw) != before.st_size:
        raise ValueError("records input size changed during hashing")
    return stamp(before), digest.hexdigest() if content else None, raw


class _RecordsRead:
    """Immutable data reuse within exactly one synchronous records() call.

    SQL connections, rows, head, counts, membership and raw proof are never
    retained here. The original Store.plan SQL suffix runs on every hit.
    """
    def __init__(self):
        self.pid, self.thread, self.active = os.getpid(), threading.get_ident(), True
        self.files, self.plans, self.stores, self.sciences = {}, {}, {}, {}

    def check(self):
        if not self.active or self.pid != os.getpid() or self.thread != threading.get_ident():
            raise ValueError("records read scope is closed or foreign")

    def file(self, path, expected=None):
        self.check(); path = Path(path); key = str(path)
        old = self.files.get(key)
        stamp, digest, raw = _records_file(path, content=old is None)
        if old is None:
            old = self.files[key] = (stamp, digest)
        elif stamp != old[0]:
            raise ValueError("immutable records input changed within its call")
        if expected is not None and old[1] != expected:
            raise ValueError("immutable records input SHA differs")
        return raw

    def plan_data(self, store):
        self.check(); root = str(store.root); old = self.plans.get(root)
        if old is None:
            raw = self.file(store.root / "study.json")
            # This file can already be fenced by another read in this call.
            if raw is None:
                _, _, raw = _records_file(store.root / "study.json", content=True)
            plan = _load(raw)
            if type(plan) is not dict: raise ValueError("records study plan must be an object")
            names = ["study.json"]
            if "class_selection" in plan:
                names += ["inputs/class-selection/selection.json", "inputs/supplied-resources.json",
                          "inputs/class-selection/reserve-inventory.json"]
            for name in names: self.file(store.root / name)
            data = store._plan_data()  # Whole original parsing/context checks.
            if data[1]["sha256"] != self.files[str(store.root / "study.json")][1]:
                raise ValueError("validated plan differs from its fenced study bytes")
            for name in names: self.file(store.root / name)
            old = self.plans[root] = (type(store)._plan_data, names, deepcopy(data))
        if type(store)._plan_data is not old[0]:
            raise ValueError("records plan parser changed within its call")
        for name in old[1]: self.file(store.root / name)
        return deepcopy(old[2])

    def store(self, root):
        self.check(); key = str(root)
        if key not in self.stores: self.stores[key] = StudyStore(root)
        return self.stores[key]

    def science(self, cell):
        self.check(); key = (cell["root"], _epochs()._sha(cell["definition"]))
        if key not in self.sciences:
            value = deepcopy(cell["definition"])
            del value["native"]; del value["ready"]
            value["network"].pop("mapping_sha256", None)
            self.sciences[key] = value
        return deepcopy(self.sciences[key])

    def finish(self):
        self.check()
        for path, old in self.files.items():
            stamp, digest, _ = _records_file(Path(path), content=True)
            if (stamp, digest) != old:
                raise ValueError("records input bytes changed before call closure")

    def discard(self):
        self.active = False
        self.files.clear(); self.plans.clear(); self.stores.clear(); self.sciences.clear()


@contextmanager
def _records_read_scope():
    if _PLAN_READ_SCOPE.get() is not None:
        raise ValueError("records read scope must have one call owner")
    scope = _RecordsRead(); token = _PLAN_READ_SCOPE.set(scope); body_error = None
    try:
        yield scope
    except BaseException as error:
        body_error = error
        raise
    finally:
        try:
            scope.finish()
        except BaseException as failure:
            if body_error is None: raise
            body_error.add_note("Records input closure also refused: " + str(failure))
        finally:
            scope.discard(); _PLAN_READ_SCOPE.reset(token)


def _records_cell(cell):
    scope = _PLAN_READ_SCOPE.get()
    if scope is not None and type(scope) is not _RecordsRead:
        raise ValueError("foreign records cell-read scope")
    store = StudyStore(cell["root"]) if scope is None else scope.store(cell["root"])
    if scope is not None:
        scope.file(store._relative(cell["enrollment_path"]), cell["enrollment_sha256"])
    # The original class-row SELECT/path/SHA/stamp check runs on every call,
    # including hits in the Store's existing immutable enrollment cache.
    value = _epochs()._cell(store, cell["hostname"], cell["mode"])
    if scope is not None:
        scope.file(store._relative(cell["enrollment_path"]), cell["enrollment_sha256"])
    return deepcopy(value)


def _science(cell, transition):
    from .resource_study_lineage import validate_cells
    validate_cells([cell], transition)
    scope = _PLAN_READ_SCOPE.get()
    if scope is not None:
        if type(scope) is not _RecordsRead: raise ValueError("foreign records science-read scope")
        return scope.science(cell)
    value = deepcopy(cell["definition"])
    del value["native"]
    del value["ready"]
    # Both original member/candidate definitions remain intact. Only the
    # logical comparison projects the authenticated stable-map lineage.
    value["network"].pop("mapping_sha256", None)
    return value


def _projection(transition):
    return {"class_transition_sha256": _epochs()._sha(transition),
            "normalization": "mapping_sha256 only after original validate_cells; full member definitions retained"}


def _member(cell, verifier):
    e = _epochs()
    return {"cohort_id": e._sha(cell), "cell": deepcopy(cell),
            "verifier": deepcopy(verifier), "frozen_accepted": None}


def _initial_registry(record, contract=None):
    contract = verifier_contract() if contract is None else contract
    return [{"hostname": cell["hostname"], "mode": cell["mode"],
             "science": _science(cell, record["class_transition"]), "members": [_member(cell, contract)],
             "writer": _epochs()._sha(cell)} for cell in record["cells"]]


def _entry(registry, key):
    matches = [entry for entry in registry if (entry["hostname"], entry["mode"]) == key]
    if len(matches) != 1:
        raise ValueError("runtime cohort cell is absent or repeated")
    return matches[0]


def _writer(entry):
    matches = [member for member in entry["members"] if member["cohort_id"] == entry["writer"]]
    if len(matches) != 1 or matches[0]["frozen_accepted"] is not None:
        raise ValueError("runtime cohort writer is absent, repeated, or frozen")
    return matches[0]


def _rows(store, key, connection=None, *, active=False):
    table = "attempts" if active else "accepted"
    suffix = " AND state IN ('reserved','captured','unverified')" if active else ""
    sql = f"SELECT * FROM {table} WHERE hostname=? AND mode=?{suffix} ORDER BY slot,attempt_id"
    if connection is not None:
        return [dict(row) for row in connection.execute(sql, key)]
    with store._transaction() as owned:
        return [dict(row) for row in owned.execute(sql, key)]


def _row_ref(root, row):
    return {"root": root, "hostname": row["hostname"], "mode": row["mode"],
            "slot": row["slot"], "attempt_id": row["attempt_id"],
            "five_tuple": row["five_tuple"], "receipt_path": row["receipt_path"],
            "receipt_sha256": row["receipt_sha256"], "accepted_row_sha256": _epochs()._sha(row)}


def _accepted_attempts(store, key, rows, connection=None):
    sql = "SELECT * FROM attempts WHERE hostname=? AND mode=? AND state='accepted' ORDER BY slot,attempt_id"
    if connection is None:
        with store._transaction() as owned:
            attempts = {row["attempt_id"]: dict(row) for row in owned.execute(sql, key)}
    else:
        attempts = {row["attempt_id"]: dict(row) for row in connection.execute(sql, key)}
    if set(attempts) != {row["attempt_id"] for row in rows}:
        raise ValueError("runtime cohort accepted index differs from accepted attempt states")
    fields = ("hostname", "mode", "slot", "attempt_id", "receipt_path", "receipt_sha256", "inventory")
    if any(not _same({field: row[field] for field in fields},
                     {field: attempts[row["attempt_id"]][field] for field in fields}) for row in rows):
        raise ValueError("runtime cohort accepted row/reservation binding differs")


def _accepted(entry, *, self_store=None, connection=None):
    result, slots, tuples = [], set(), set()
    for member in entry["members"]:
        root = member["cell"]["root"]
        store = self_store if self_store is not None and str(self_store.root) == root else StudyStore(root)
        own = connection if store is self_store else None
        key = entry["hostname"], entry["mode"]
        rows = _rows(store, key, own)
        _accepted_attempts(store, key, rows, own)
        if member["frozen_accepted"] is not None:
            marker = _epochs()._read(store.root / MARKER)
            parent = StudyStore(marker["parent"])
            if not _same(marker, _marker(store, parent)):
                raise ValueError("frozen runtime cohort parent membership differs")
            frozen = _frozen_value(parent, member)
            if not _same(frozen["rows"], [_row_ref(root, row) for row in rows]):
                raise ValueError("retained runtime cohort accepted rows changed")
            if _rows(store, key, own, active=True):
                raise ValueError("frozen runtime cohort acquired an active reservation")
        for row in rows:
            if (type(row["slot"]) is not int or not 1 <= row["slot"] <= 400
                    or _json(_tuple(_load(row["five_tuple"]))).decode() != row["five_tuple"]
                    or row["slot"] in slots or row["five_tuple"] in tuples):
                raise ValueError("runtime cohorts repeat a global slot/tuple or exceed the cell quota")
            slots.add(row["slot"]); tuples.add(row["five_tuple"])
            result.append((member, store, row))
    if len(result) > 400:
        raise ValueError("logical runtime-cohort cell exceeds four hundred")
    return result


def _manifest(registry):
    rows = [_row_ref(str(store.root), row) for entry in registry for _, store, row in _accepted(entry)]
    return sorted(rows, key=lambda row: (row["hostname"], row["mode"], row["slot"], row["root"]))


def _marker(store, parent):
    return {"record_type": MARKER_TYPE, "root": str(store.root),
            "study_sha256": store._file("study.json")[1]["sha256"],
            "parent": str(parent.root), "parent_study_sha256": parent._file("study.json")[1]["sha256"]}


def _check_markers(parent, record):
    e = _epochs()
    roots = {m["cell"]["root"] for entry in record["cohorts"] for m in entry["members"]}
    if set(record["cohort_memberships"]) != roots:
        raise ValueError("runtime cohort membership inventory differs")
    for root in sorted(roots):
        store = StudyStore(root)
        value = e._read(store.root / MARKER)
        if not _same(value, _marker(store, parent)) or e._sha(value) != record["cohort_memberships"][root]:
            raise ValueError("immutable runtime cohort membership differs")
        if e._membership(store).root != parent.root:
            raise ValueError("runtime cohort root has a different epoch parent")


def _frozen_value(parent, member):
    """Authenticate immutable carry metadata; do not scan its old ledger here."""
    e = _epochs()
    ref = member["frozen_accepted"]
    if type(ref) is not dict or set(ref) != {"path", "sha256"} or not ref["path"].startswith("runtime-cohorts/"):
        raise ValueError("runtime cohort retained manifest reference differs")
    path = parent._relative(ref["path"])
    value = e._read(path)
    fields = {"root", "hostname", "mode", "slot", "attempt_id", "five_tuple", "receipt_path", "receipt_sha256", "accepted_row_sha256"}
    cell = member["cell"]
    if (type(value) is not dict or set(value) != {"record_type", "cohort_id", "rows", "authority"}
            or value["record_type"] != SNAPSHOT or value["cohort_id"] != member["cohort_id"]
            or value["authority"] != "existing-accepted-SQL-rows; no new raw qualification"
            or type(value["rows"]) is not list or len(value["rows"]) > 400
            or e._sha(value) != ref["sha256"] or sha256_file(path) != ref["sha256"]):
        raise ValueError("runtime cohort retained manifest immutable authority differs")
    slots, tuples, ids = set(), set(), set()
    for row in value["rows"]:
        if (type(row) is not dict or set(row) != fields
                or (row["root"], row["hostname"], row["mode"]) != (cell["root"], cell["hostname"], cell["mode"])
                or type(row["slot"]) is not int or not 1 <= row["slot"] <= 400
                or type(row["attempt_id"]) is not str or len(row["attempt_id"]) != 32
                or any(c not in "0123456789abcdef" for c in row["attempt_id"])
                or _json(_tuple(_load(row["five_tuple"]))).decode() != row["five_tuple"]
                or row["slot"] in slots or row["five_tuple"] in tuples or row["attempt_id"] in ids):
            raise ValueError("runtime cohort retained manifest row/slot/tuple identity differs")
        _digest(row["receipt_sha256"]); _digest(row["accepted_row_sha256"])
        StudyStore(cell["root"])._relative(row["receipt_path"])
        slots.add(row["slot"]); tuples.add(row["five_tuple"]); ids.add(row["attempt_id"])
    if not _same(value["rows"], sorted(value["rows"], key=lambda row: (row["slot"], row["attempt_id"]))):
        raise ValueError("runtime cohort retained manifest order differs")
    return value


def _check_frozen(parent, registry):
    """Ancestry authenticates manifests; selected-cell guards join fresh SQL."""
    for entry in registry:
        slots, tuples = set(), set()
        for member in entry["members"]:
            if member["frozen_accepted"] is None: continue
            for row in _frozen_value(parent, member)["rows"]:
                if row["slot"] in slots or row["five_tuple"] in tuples:
                    raise ValueError("frozen runtime cohort manifests repeat global slots or tuples")
                slots.add(row["slot"]); tuples.add(row["five_tuple"])
        if len(slots) > 400: raise ValueError("frozen runtime cohort manifest union exceeds four hundred")


def _scope_keys(cells, hosts, modes):
    if len(hosts) != len(set(hosts)) or len(modes) != len(set(modes)) or not hosts or not modes:
        raise ValueError("runtime cohort requires unique explicit hostname and mode scope")
    for host in hosts: _hostname(host)
    for mode in modes: _mode(mode)
    keys = {(host, mode) for host in hosts for mode in modes}
    if not keys <= cells.keys():
        raise ValueError("runtime cohort cannot add or replace logical science cells")
    return keys


def _declaration(parent, new, records, hosts, modes):
    e = _epochs()
    if not records or records[-1].get("class_transition") is None:
        raise ValueError("runtime cohorts require an authenticated stable V3 selected50 parent")
    cells = {e._key(cell): cell for cell in records[-1]["cells"]}
    keys = _scope_keys(cells, hosts, modes)
    contract = verifier_contract()
    registry = records[-1]["cohorts"] if records[-1]["record_type"] == ADMISSION else _initial_registry(records[-1], contract)
    affected = []
    for key in sorted(keys):
        old, candidate = cells[key], e._cell(new, *key)
        if (not _same(_science(old, records[-1]["class_transition"]), _science(candidate, records[-1]["class_transition"]))
                or _same(old["definition"]["native"], candidate["definition"]["native"])
                or candidate["definition"]["ready"] is not True):
            raise ValueError("runtime cohort requires changed Native and exactly unchanged science with ready new mode")
        affected.append({"hostname": key[0], "mode": key[1],
                         "previous_definition_sha256": old["definition_sha256"],
                         "new_definition_sha256": candidate["definition_sha256"]})
    return {"record_type": DECLARATION, "schema_version": 1,
            "parent_study_sha256": parent._file("study.json")[1]["sha256"],
            "predecessor_admission_sha256": e._sha(records[-1]),
            "selected_hostnames": records[-1]["class_transition"]["class_selection"]["selected_hostnames"],
            "affected": affected, "retained_accepted_manifest_sha256": e._sha(_manifest(registry)),
            "verifier": contract, "compatible_treatment": False,
            "stable_lineage_projection": _projection(records[-1]["class_transition"]),
            "runtime_is_analysis_stratum": True, "rationale": ""}


def compatibility_template(parent, cohort_root, *, affected_hostnames=(), affected_modes=()):
    e = _epochs()
    parent, new = StudyStore(Path(parent).absolute()), StudyStore(Path(cohort_root).absolute())
    with e._lock(parent.root):
        return _declaration(parent, new, e._records(parent), list(affected_hostnames), list(affected_modes))


def _initialization_inputs(current, source, candidates):
    """Authenticate immutable preparation inputs, never enrollment or evidence.

    Catalogues keep their original inventory identifiers. The one literal MAL
    reserve is imported locally by the original API after initialization, so
    its required source occurrences identify the new root's actual inventory.
    """
    from .resource_study_lineage import MANIFEST, INVENTORY, SOURCE, INCLUDED
    from .resource_study_inputs import candidate_catalogue
    from .resource_study_selection import _read, _supplement, _pool
    files, observed, catalogues, order, edges = {}, [], {}, [], set()
    for relative in (MANIFEST, INVENTORY, SOURCE, "inputs/candidates.json"):
        raw = _read(source.root / relative)
        files[relative] = raw
        observed.append((source, relative, hashlib.sha256(raw).hexdigest()))
    if not _same(_load(files["inputs/candidates.json"]), candidate_catalogue(source.root / SOURCE)):
        raise ValueError("current candidate catalogue differs from its frozen original source")
    reserve_sha = source.plan()["class_selection"]["reserve_inventory"]["sha256"]
    bound = ([m["cell"] for entry in current[-1]["cohorts"] for m in entry["members"]]
             if current[-1]["record_type"] == ADMISSION else current[-1]["cells"])
    for store in candidates:
        member_cells = [cell for cell in bound if cell["root"] == str(store.root)]
        for host in sorted({cell["hostname"] for cell in member_cells}):
            urls = _pool(store.root, host)["urls"]
            for cell in member_cells:
                if cell["hostname"] != host: continue
                wanted = cell["definition"]["urls"]
                if any(url not in urls for url in wanted) or wanted != sorted(wanted, key=urls.index):
                    raise ValueError("current member candidate pool lacks its frozen ordered twenty resources")
        previous = None
        for index, path in enumerate(sorted((store.root / "inputs/supplement-admissions").glob("*.json")), 1):
            if path.name != f"{index:06d}.json": raise ValueError("current supplement admission sequence differs")
            relative = path.relative_to(store.root).as_posix()
            raw = _read(path); admission_sha = hashlib.sha256(raw).hexdigest()
            admission = _load(raw); digest = _digest(admission.get("catalogue_sha256"))
            refs = {}
            value = _supplement(store.root, {"path": relative, "sha256": admission_sha, "catalogue_sha256": digest}, refs)
            copied = {}
            for name, expected in refs.items():
                data = _read(store.root / name, expected)
                observed.append((store, name, expected))
                if name != relative: copied[name] = data
            if any(row["hostname"] == INCLUDED for row in value["candidates"]):
                if (len(value["candidates"]) != 1 or len(value["inventory_files"]) != 1
                        or value["inventory_files"][0]["sha256"] != reserve_sha):
                    raise ValueError("supplement cannot alter the literal stable MAL reserve authority")
                continue
            if digest not in catalogues:
                catalogues[digest] = (raw, copied)
                order.append(digest)
            elif catalogues[digest] != (raw, copied):
                raise ValueError("current supplement digest has conflicting immutable input bytes")
            if previous is not None and previous != digest: edges.add((previous, digest))
            previous = digest
    # Preserve every existing ordered supplement prefix. Contradictory roots
    # refuse instead of silently changing a resource's position in the pool.
    remaining = set(order); ordered = []
    while remaining:
        ready = [key for key in order if key in remaining and not any(b == key and a in remaining for a, b in edges)]
        if not ready: raise ValueError("current supplement prefixes have contradictory resource order")
        for key in ready: ordered.append(key); remaining.remove(key)
    admissions = []
    for digest in ordered:
        raw, copied = catalogues[digest]
        for name, data in copied.items():
            if name in files and files[name] != data: raise ValueError("initialization input path conflicts")
            files[name] = data
        admissions.append(raw)
    if sum(map(len, files.values())) + sum(map(len, admissions)) > 256 * 1024**2:
        raise ValueError("immutable initialization input context exceeds its bounded size")
    return files, admissions, observed


def _input_context(root, plan):
    """Local immutable input proof only; never construct a Store or query SQL."""
    from .resource_study_selection import _read
    if (type(plan) is not dict or type(plan.get("class_selection")) is not dict
            or type(plan.get("class_network")) is not dict):
        raise ValueError("runtime-cohort input authority requires an original stable plan")
    root = Path(root).absolute()
    raw = _read(root / INPUT_CONTEXT); value = _load(raw)
    study_raw = _read(root / "study.json")
    fields = {"record_type", "schema_version", "root", "study_sha256", "parent", "predecessor",
              "predecessor_sha256", "class_selection_sha256", "source_sha256", "scientific_credit"}
    prior = value.get("predecessor", {}) if type(value) is dict else {}
    transition = prior.get("class_transition") if type(prior) is dict else None
    parent = value.get("parent", {}) if type(value) is dict else {}
    if (type(value) is not dict or set(value) != fields or value["record_type"] != INPUT_CONTEXT_TYPE
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["root"] != str(root) or value["study_sha256"] != hashlib.sha256(study_raw).hexdigest()
            or not _same(plan, _load(study_raw))
            or value["source_sha256"] != plan["source_sha256"]
            or value["class_selection_sha256"] != _epochs()._sha(plan["class_selection"])
            or value["scientific_credit"] is not False or type(parent) is not dict
            or set(parent) != {"root", "study_sha256"}
            or parent["root"] != plan["class_selection"]["parent_root"]
            or parent["study_sha256"] != plan["class_selection"]["parent_study_sha256"]
            or type(prior) is not dict or prior.get("record_type") not in (V3, ADMISSION)
            or type(prior.get("sequence")) is not int or prior["sequence"] < 0
            or prior.get("parent_study_sha256") != parent["study_sha256"]
            or _epochs()._sha(prior) != value["predecessor_sha256"]
            or type(transition) is not dict
            or not _same(transition.get("class_selection"), plan["class_selection"])
            or not _same(transition.get("class_network"), plan["class_network"])):
        raise ValueError("runtime-cohort local input context root/source/map/predecessor differs")
    return value, hashlib.sha256(raw).hexdigest()


def _input_cells(context, hostname):
    e = _epochs(); _hostname(hostname)
    cells = context["predecessor"].get("cells")
    if type(cells) is not list or not cells or len(cells) > 250 or any(type(cell) is not dict for cell in cells):
        raise ValueError("runtime-cohort input context cell inventory differs")
    chosen = [cell for cell in cells if cell.get("hostname") == hostname]
    if not chosen: raise ValueError("runtime-cohort input authority lacks an admitted same-host template")
    if any(type(cell.get("definition")) is not dict for cell in chosen):
        raise ValueError("runtime-cohort input authority cell definitions must be objects")
    reference = chosen[0]["definition"]
    urls = reference.get("urls")
    if (type(urls) is not list or len(urls) != 20 or any(type(url) is not str for url in urls)
            or len(set(urls)) != 20):
        raise ValueError("runtime-cohort input authority needs exactly twenty distinct frozen URLs")
    _digest(reference.get("workload_sha256"))
    network = context["predecessor"]["class_transition"]["class_network"]
    allowed_maps = {_epochs()._sha(network), network["predecessor_sha256"]}
    for cell in chosen:
        definition = cell["definition"]
        if (cell["definition_sha256"] != e._sha(definition)
                or definition.get("network", {}).get("mapping_sha256") not in allowed_maps
                or any(not _same(definition.get(name), reference.get(name)) for name in ("urls", "workload_sha256", "acceptance"))
                or not _same(definition.get("network", {}).get("assignment"), reference.get("network", {}).get("assignment"))):
            raise ValueError("runtime-cohort input templates disagree on frozen resources/workload/address")
    return chosen


def require_input_selection(store, hostname, selected):
    """Fail before Native preparation unless this fresh cohort keeps exact20."""
    path = store.root / INPUT_CONTEXT
    if not path.exists() and not path.is_symlink(): return
    context, _ = _input_context(store.root, store.plan())
    _require_current_input_context(context)
    cells = _input_cells(context, hostname)
    if (type(selected) is not dict or type(selected.get("manifest")) is not dict
            or selected["manifest"].get("hostname") != hostname
            or not _same(selected["manifest"].get("urls"), cells[0]["definition"]["urls"])):
        raise ValueError("runtime cohort preparation requires the exact prior twenty-URL explicit selection")


def _require_current_input_context(context):
    """Live preparation only; the pure receipt branch never queries a ledger."""
    e = _epochs(); parent = StudyStore(context["parent"]["root"])
    with e._lock(parent.root):
        current = e._records(parent)
        if (parent._file("study.json")[1]["sha256"] != context["parent"]["study_sha256"]
                or not current or not _same(context["predecessor"], current[-1])
                or context["predecessor_sha256"] != e._sha(current[-1])):
            raise ValueError("runtime-cohort preparation input authority has a stale actual parent head")


def _input_binding(enrollment):
    binding = enrollment.get(INPUT_AUTHORITY_KEY)
    if (type(binding) is not dict or set(binding) != {"record_type", "context_path", "context_sha256"}
            or binding["record_type"] != INPUT_AUTHORITY_TYPE or binding["context_path"] != INPUT_CONTEXT):
        raise ValueError("runtime-cohort enrollment input binding is partial or unsupported")
    _digest(binding["context_sha256"])
    return binding


def bind_input_authority(store, enrollment):
    from .resource_study_lineage import INCLUDED
    path = store.root / INPUT_CONTEXT
    if not path.exists() and not path.is_symlink():
        if INPUT_AUTHORITY_KEY in enrollment: raise ValueError("input binding lacks its initialized context")
        return enrollment
    if enrollment["hostname"] == INCLUDED: return enrollment  # Whole literal-reserve reader remains authoritative.
    if INPUT_AUTHORITY_KEY in enrollment: raise ValueError("runtime-cohort input binding already exists")
    context, digest = _input_context(store.root, store.plan())
    _require_current_input_context(context)
    result = deepcopy(enrollment)
    result[INPUT_AUTHORITY_KEY] = {"record_type": INPUT_AUTHORITY_TYPE, "context_path": INPUT_CONTEXT, "context_sha256": digest}
    result["files"][INPUT_CONTEXT] = digest
    validate_input_authority(store, result, plan=store.plan())
    return result


def validate_input_authority(store, enrollment, *, plan):
    """Pure new-type branch; full original selection/preparation proof retained.

    Admission joins the actual current head separately. Raw workers authenticate
    only this frozen local snapshot and actual input bytes; they query no ledger.
    """
    from .resource_study_lineage import bind_enrollment, INCLUDED
    from .resource_study_selection import _pool, _supplement, validate_selection_proof
    from .resource_study_inputs import candidate_catalogue
    if type(enrollment) is not dict or type(enrollment.get("files")) is not dict:
        raise ValueError("runtime-cohort enrollment and file inventory must be typed objects")
    binding = _input_binding(enrollment)
    context, digest = _input_context(store.root, plan)
    if digest != binding["context_sha256"] or enrollment.get("files", {}).get(INPUT_CONTEXT) != digest:
        raise ValueError("runtime-cohort input context differs from enrollment inventory")
    expected = bind_enrollment(store, {**enrollment, "files": {}}, plan=plan)
    if (not _same(enrollment.get("class_selection"), expected["class_selection"])
            or any(enrollment["files"].get(name) != value for name, value in expected["files"].items())):
        raise ValueError("runtime-cohort enrollment lacks original immutable stable context")
    host = enrollment["hostname"]
    if host == INCLUDED or host not in plan["class_network"]["assignments"]:
        raise ValueError("supplemental cohort authority cannot replace literal MAL or selected50")
    cells = _input_cells(context, host); definition = cells[0]["definition"]
    if (not _same(enrollment.get("urls"), definition["urls"])
            or enrollment.get("workload_sha256") != definition["workload_sha256"]
            or not _same(definition["network"]["assignment"], plan["class_network"]["assignments"][host])):
        raise ValueError("runtime-cohort enrollment changes frozen twenty resources/workload/class address")
    if "resource_selection" not in enrollment: raise ValueError("runtime-cohort input authority needs full explicit selection proof")
    validate_selection_proof(store.root, enrollment)
    pool = _pool(store.root, host)
    values = candidate_catalogue(store.root / "inputs/supplied-resources.json")["candidates"]
    candidate = next((deepcopy(row) for row in values if row["hostname"] == host), None)
    for ref in pool["supplements"]:
        imported = _supplement(store.root, ref, {})
        row = next((row for row in imported["candidates"] if row["hostname"] == host), None)
        if row is None: continue
        if candidate is None: candidate = deepcopy(row)
        else:
            candidate["urls"] += [url for url in row["urls"] if url not in candidate["urls"]]
            candidate["source_occurrences"] += row["source_occurrences"]
    if (candidate is None or not _same(enrollment.get("source_occurrences"), candidate["source_occurrences"])
            or any(url not in candidate["urls"] for url in enrollment["urls"])
            or enrollment["urls"] != sorted(enrollment["urls"], key=candidate["urls"].index)):
        raise ValueError("runtime-cohort source occurrence identities or complete pool order differ")


def input_authority_artifact_paths(enrollment):
    if INPUT_AUTHORITY_KEY not in enrollment: return {}
    _input_binding(enrollment)
    return {"runtime_cohort_input_context": INPUT_CONTEXT}


def initialize_cohort(parent, cohort_root):
    """Freeze current plan, catalogue and reserve inputs in a fresh empty ledger.

    Preparation/enrollment are separate original live operations. This copies
    no enrollments, attempts, accepted rows, pilots, or runtime qualification.
    """
    e = _epochs()
    from .resource_study_lineage import INVENTORY
    from .resource_study import add_inventories, candidate_pool
    from .resource_study_selection import _read
    parent = StudyStore(Path(parent).absolute())
    root = Path(cohort_root).absolute()
    if root.exists() or root.is_symlink(): raise ValueError("new runtime cohort root is already claimed")
    with e._lock(parent.root):
        current = e._records(parent)
        if not current or current[-1].get("class_transition") is None:
            raise ValueError("runtime cohort initialization requires stable selected50 authority")
        roots = ({m["cell"]["root"] for entry in current[-1]["cohorts"] for m in entry["members"]}
                 if current[-1]["record_type"] == ADMISSION else {c["root"] for c in current[-1]["cells"]})
        candidates = [StudyStore(path) for path in sorted(roots)]
        source = next((store for store in candidates if "class_selection" in store.plan()), None)
        if source is None: raise ValueError("current stable cohort context is absent")
        plan = source.plan()
        files, admissions, observed = _initialization_inputs(current, source, candidates)
        for relative, raw in files.items(): _create(root / relative, raw)
        result = StudyStore(root).initialize(plan)
        if not _same(result, plan): raise ValueError("fresh runtime cohort plan changed")
        add_inventories(root, [root / INVENTORY])
        copied = {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}
        for index, raw in enumerate(admissions, 2):
            relative = f"inputs/supplement-admissions/{index:06d}.json"
            _create(root / relative, raw)
            copied[relative] = hashlib.sha256(raw).hexdigest()
        pool = candidate_pool(root)
        for cell in current[-1]["cells"]:
            urls = pool.get(cell["hostname"], {}).get("urls", [])
            wanted = cell["definition"]["urls"]
            if any(url not in urls for url in wanted) or wanted != sorted(wanted, key=urls.index):
                raise ValueError("initialized candidate pool cannot preserve current ordered twenty resources")
        for store, relative, digest in observed: _read(store.root / relative, digest)
        context = {"record_type": INPUT_CONTEXT_TYPE, "schema_version": 1, "root": str(root),
            "study_sha256": StudyStore(root)._file("study.json")[1]["sha256"],
            "parent": {"root": str(parent.root), "study_sha256": parent._file("study.json")[1]["sha256"]},
            "predecessor": deepcopy(current[-1]), "predecessor_sha256": e._sha(current[-1]),
            "class_selection_sha256": e._sha(plan["class_selection"]), "source_sha256": plan["source_sha256"],
            "scientific_credit": False}
        _create(root / INPUT_CONTEXT, canonical_json(context))
        _, context_sha = _input_context(root, plan)
        return {"record_type": "qcsd-resource-domain-runtime-cohort-initialization-v1",
                "parent": str(parent.root), "root": str(root), "predecessor_admission_sha256": e._sha(current[-1]),
                "study_sha256": StudyStore(root)._file("study.json")[1]["sha256"],
                "copied_preparation_inputs": copied,
                "input_source_roots": [str(store.root) for store in candidates],
                "input_context": {"path": INPUT_CONTEXT, "sha256": context_sha},
                "supplement_catalogues_copied": len(admissions), "local_literal_MAL_inventory_imported": True,
                "enrolled": False, "admitted": False, "scientific_credit": False}


def _validate_declaration(value, expected):
    if (type(value) is not dict or set(value) != set(expected)
            or value.get("compatible_treatment") is not True
            or value.get("runtime_is_analysis_stratum") is not True
            or type(value.get("rationale")) is not str or not value["rationale"].strip()):
        raise ValueError("explicit operator compatible-treatment declaration is required")
    actual = dict(value)
    actual.update(compatible_treatment=False, rationale="")
    if not _same(actual, expected):
        raise ValueError("runtime compatibility declaration changed scope, retained credit, or scientific inputs")


def _mode_profile(cell, transition):
    value = _science(cell, transition)
    del value["urls"]; del value["workload_sha256"]
    value["network"].pop("assignment", None)
    return value


def _first_declaration(parent, new, records, hosts, modes, *, contract=None, retained_digest=None, check_prior_credit=True):
    e = _epochs()
    if not records or records[-1].get("class_transition") is None:
        raise ValueError("first mode requires authenticated stable selected50 authority")
    if not hosts or not modes or len(hosts) != len(set(hosts)) or len(modes) != len(set(modes)):
        raise ValueError("first mode requires unique explicit host/mode scope")
    transition = records[-1]["class_transition"]
    selected = transition["class_selection"]["selected_hostnames"]
    cells = records[-1]["cells"]
    historic_keys = {e._key(cell) for record in records for cell in record["cells"]}
    roots = sorted({cell["root"] for record in records for cell in record["cells"]})
    contract = verifier_contract() if contract is None else contract
    registry = records[-1]["cohorts"] if records[-1]["record_type"] == ADMISSION else _initial_registry(records[-1], contract)
    profiles_by_mode = {mode: [_mode_profile(cell, transition) for cell in cells if cell["mode"] == mode] for mode in modes}
    affected = []
    for host in sorted(hosts):
        _hostname(host)
        if host not in selected: raise ValueError("first mode hostname is outside selected50")
        siblings = [cell for cell in cells if cell["hostname"] == host]
        if not siblings: raise ValueError("first mode has no admitted same-host resource template")
        donor_roots = sorted({m["cell"]["root"] for entry in registry if entry["hostname"] == host for m in entry["members"]})
        for mode in sorted(modes):
            _mode(mode)
            key = host, mode
            if key in historic_keys: raise ValueError("first mode cannot replace or resurrect a previously admitted cell")
            if check_prior_credit:
                for root in roots:
                    with StudyStore(root)._transaction() as connection:
                        if connection.execute("SELECT 1 FROM accepted WHERE hostname=? AND mode=?", key).fetchone():
                            raise ValueError("first mode has prior unadmitted accepted credit")
            templates = [e._cell(StudyStore(root), host, mode) for root in donor_roots]
            candidate = e._cell(new, host, mode)
            science = _science(candidate, transition)
            if candidate["definition"]["ready"] is not True or any(not _same(_science(t, transition), science) for t in templates):
                raise ValueError("first mode changed its frozen same-host mode template or is not ready")
            for sibling in siblings:
                actual = _science(sibling, transition)
                if any(not _same(science[field], actual[field]) for field in ("urls", "workload_sha256", "acceptance", "network")):
                    raise ValueError("first mode changed ordered resources, workload, or physical class network")
            profiles = profiles_by_mode[mode]
            candidate_profile = _mode_profile(candidate, transition)
            if not profiles or any(not _same(profile, candidate_profile) for profile in profiles):
                raise ValueError("first mode changed or lacks the approved global mode profile")
            affected.append({"hostname": host, "mode": mode, "unadmitted_mode_templates": templates,
                             "new_definition_sha256": candidate["definition_sha256"]})
    return {"record_type": FIRST_MODE_DECLARATION, "schema_version": 1,
        "parent_study_sha256": parent._file("study.json")[1]["sha256"],
        "predecessor_admission_sha256": e._sha(records[-1]), "selected_hostnames": selected,
        "affected": affected, "retained_accepted_manifest_sha256": e._sha(_manifest(registry)) if retained_digest is None else retained_digest,
        "verifier": contract, "stable_lineage_projection": _projection(transition),
        "new_mode_authorized": False, "runtime_is_analysis_stratum": True,
        "zero_prior_accepted": 0, "rationale": ""}


def _validate_first_declaration(value, expected):
    if (type(value) is not dict or set(value) != set(expected) or value.get("new_mode_authorized") is not True
            or value.get("runtime_is_analysis_stratum") is not True or type(value.get("zero_prior_accepted")) is not int
            or value["zero_prior_accepted"] != 0 or type(value.get("rationale")) is not str or not value["rationale"].strip()):
        raise ValueError("explicit first-mode authority and zero prior credit required")
    actual = dict(value); actual.update(new_mode_authorized=False, rationale="")
    if not _same(actual, expected): raise ValueError("first-mode authority changed frozen scope/template/credit")


def first_mode_template(parent, cohort_root, *, affected_hostnames=(), affected_modes=()):
    e = _epochs()
    parent, new = StudyStore(Path(parent).absolute()), StudyStore(Path(cohort_root).absolute())
    with e._lock(parent.root):
        return _first_declaration(parent, new, e._records(parent), list(affected_hostnames), list(affected_modes))


def create_cohort(parent, cohort_root, declaration_path, declaration_sha256):
    return _create_admission(parent, cohort_root, declaration_path, declaration_sha256, first=False)


def create_first_modes(parent, cohort_root, declaration_path, declaration_sha256):
    return _create_admission(parent, cohort_root, declaration_path, declaration_sha256, first=True)


def _create_admission(parent, cohort_root, declaration_path, declaration_sha256, *, first):
    e = _epochs()
    from .resource_study_lineage import prepare_fences, publication_scope, validate_cells, no_retired_history
    parent, new = StudyStore(Path(parent).absolute()), StudyStore(Path(cohort_root).absolute())
    path = e._regular(Path(declaration_path).absolute())
    declaration = e._read(path)
    if sha256_file(path) != declaration_sha256 or e._sha(declaration) != declaration_sha256:
        raise ValueError("runtime cohort declaration must use its exact canonical immutable bytes")
    with e.docker_lock(), e._lock(parent.root):
        records = e._records(parent)
        context, _ = _input_context(new.root, new.plan())
        if (not _same(context["parent"], {"root": str(parent.root), "study_sha256": parent._file("study.json")[1]["sha256"]})
                or not _same(context["predecessor"], records[-1]) or context["predecessor_sha256"] != e._sha(records[-1])):
            raise ValueError("runtime cohort input authority has a stale or foreign actual parent head")
        hosts = sorted({row["hostname"] for row in declaration["affected"]})
        modes = sorted({row["mode"] for row in declaration["affected"]})
        expected = (_first_declaration if first else _declaration)(parent, new, records, hosts, modes)
        (_validate_first_declaration if first else _validate_declaration)(declaration, expected)
        current_plans = [StudyStore(root).plan() for root in
                         sorted({c["root"] for c in records[-1]["cells"]})]
        if not any("class_selection" in plan and _same(e._plan(new), plan) for plan in current_plans):
            raise ValueError("runtime cohort plan differs from the current stable plan")
        prior_roots = {c["root"] for r in records for c in r["cells"]}
        if str(new.root) in prior_roots or (new.root / MARKER).exists() or (new.root / MARKER).is_symlink():
            raise ValueError("runtime cohort requires a fresh unclaimed root")
        e._idle([StudyStore(root) for root in sorted(prior_roots | {str(new.root)})])
        with new._transaction() as connection:
            if connection.execute("SELECT 1 FROM attempts").fetchone() or connection.execute("SELECT 1 FROM accepted").fetchone():
                raise ValueError("runtime cohort cannot import attempts or accepted rows")
        no_retired_history(new)
        for host in hosts: e._verify_preparation(new, host)
        registry = deepcopy(records[-1]["cohorts"] if records[-1]["record_type"] == ADMISSION else _initial_registry(records[-1], expected["verifier"]))
        cells = {e._key(c): c for c in records[-1]["cells"]}
        for affected in declaration["affected"]:
            key = affected["hostname"], affected["mode"]
            if first:
                candidate = e._cell(new, *key)
                member = _member(candidate, declaration["verifier"])
                registry.append({"hostname": key[0], "mode": key[1], "science": _science(candidate, records[-1]["class_transition"]),
                                 "members": [member], "writer": member["cohort_id"]})
                cells[key] = candidate
                continue
            entry = _entry(registry, key)
            previous = _writer(entry)
            frozen = {"record_type": SNAPSHOT, "cohort_id": previous["cohort_id"],
                      "rows": [_row_ref(previous["cell"]["root"], row) for row in
                               _rows(StudyStore(previous["cell"]["root"]), key)],
                      "authority": "existing-accepted-SQL-rows; no new raw qualification"}
            relative = "runtime-cohorts/" + e._sha(frozen) + ".json"
            _create(parent.root / relative, canonical_json(frozen))
            previous["frozen_accepted"] = {"path": relative, "sha256": e._sha(frozen)}
            candidate = e._cell(new, *key)
            member = _member(candidate, declaration["verifier"])
            entry["members"].append(member); entry["writer"] = member["cohort_id"]
            cells[key] = candidate
        validate_cells([m["cell"] for entry in registry for m in entry["members"]], records[-1]["class_transition"])
        e._bind(new, parent)
        fences = prepare_fences(parent, records, cells, records[-1]["class_transition"])
        markers = dict(records[-1].get("cohort_memberships", {}))
        for root in sorted({m["cell"]["root"] for entry in registry for m in entry["members"]}):
            store = StudyStore(root); value = _marker(store, parent)
            if root not in markers:
                if (store.root / MARKER).exists() or (store.root / MARKER).is_symlink():
                    raise ValueError("uncommitted runtime cohort marker; explicit recovery required")
                _create(store.root / MARKER, canonical_json(value))
            markers[root] = e._sha(value)
        value = {"record_type": ADMISSION, "sequence": len(records), "previous_sha256": e._sha(records[-1]),
                 "parent_study_sha256": parent._file("study.json")[1]["sha256"], "change": "first-mode" if first else "runtime-cohort",
                 "affected": [[row["hostname"], row["mode"]] for row in declaration["affected"]],
                 "cells": [cells[key] for key in sorted(cells)], "exclusions": records[-1]["exclusions"],
                 "class_transition": records[-1]["class_transition"], "write_fences": fences,
                 "cohorts": registry, "cohort_memberships": markers,
                 "compatibility_declaration": {"path": str(path), "sha256": declaration_sha256}}
        _validate_record(parent, records, value, contract=expected["verifier"])
        if sha256_file(path) != declaration_sha256 or not _same(expected["verifier"], verifier_contract()):
            raise ValueError("runtime compatibility declaration or qualifying reader changed before publication")
        _create(parent.root / "epoch-admissions" / f"{len(records):06d}.json", canonical_json(value))
        with publication_scope(parent, records, value), parent._transaction() as connection:
            old = canonical_json({"sequence": len(records)-1, "sha256": e._sha(records[-1])}).decode()
            actual = connection.execute("SELECT value FROM meta WHERE key='epoch_head'").fetchone()
            if actual is None or actual[0] != old:
                raise ValueError("runtime cohort parent changed before publication")
            connection.execute("UPDATE meta SET value=? WHERE key='epoch_head'",
                               (canonical_json({"sequence": len(records), "sha256": e._sha(value)}).decode(),))
        return value


def _validate_record(parent, records, value, *, contract=None):
    e = _epochs()
    contract = verifier_contract() if contract is None else contract
    qualified = reader_compatibility.qualify_execution(verifier_contract())
    reader_compatibility.require_supported(contract, qualified)
    if type(value) is dict and value.get("change") == "first-mode":
        return _validate_first_record(parent, records, value, contract)
    fields = {"record_type", "sequence", "previous_sha256", "parent_study_sha256", "change", "affected", "cells",
              "exclusions", "class_transition", "write_fences", "cohorts", "cohort_memberships", "compatibility_declaration"}
    prior = records[-1]
    if (type(value) is not dict or set(value) != fields or value["record_type"] != ADMISSION
            or type(value["sequence"]) is not int or value["sequence"] != len(records)
            or value["previous_sha256"] != e._sha(prior) or value["change"] != "runtime-cohort"
            or value["parent_study_sha256"] != parent._file("study.json")[1]["sha256"]
            or not _same(value["class_transition"], prior.get("class_transition"))
            or value["class_transition"] is None or not _same(value["exclusions"], prior["exclusions"])):
        raise ValueError("runtime cohort parent ancestry/selected50/exclusions differ")
    ref = value["compatibility_declaration"]
    if type(ref) is not dict or set(ref) != {"path", "sha256"}:
        raise ValueError("runtime cohort declaration reference differs")
    declaration = e._read(ref["path"])
    if sha256_file(ref["path"]) != ref["sha256"] or e._sha(declaration) != ref["sha256"]:
        raise ValueError("runtime cohort declaration immutable bytes changed")
    previous = prior["cohorts"] if prior["record_type"] == ADMISSION else _initial_registry(prior, contract)
    old_entries = {(r["hostname"], r["mode"]): r for r in previous}
    new_entries = {(r["hostname"], r["mode"]): r for r in value["cohorts"]}
    old_cells, new_cells = ({e._key(c): c for c in r["cells"]} for r in (prior, value))
    if (type(declaration.get("affected")) is not list
            or any(type(row) is not dict or set(row) != {"hostname", "mode", "previous_definition_sha256", "new_definition_sha256"}
                   for row in declaration["affected"])):
        raise ValueError("runtime cohort declared affected cells are malformed")
    affected = {(row["hostname"], row["mode"]) for row in declaration["affected"]}
    if (len(new_entries) != len(value["cohorts"]) or new_entries.keys() != old_entries.keys()
            or len(new_cells) != len(value["cells"]) or new_cells.keys() != old_cells.keys()
            or not affected or len(affected) != len(declaration["affected"])
            or value["affected"] != [list(key) for key in sorted(affected)]):
        raise ValueError("runtime cohort logical cell inventory or affected scope differs")
    previous_roots = {c["root"] for record in records for c in record["cells"]}
    next_roots = {new_cells[key]["root"] for key in affected}
    if len(next_roots) != 1 or next_roots & previous_roots:
        raise ValueError("runtime cohort writer must use one genuinely fresh independent root")
    expected = {"record_type": DECLARATION, "schema_version": 1,
                "parent_study_sha256": value["parent_study_sha256"], "predecessor_admission_sha256": e._sha(prior),
                "selected_hostnames": value["class_transition"]["class_selection"]["selected_hostnames"],
                "affected": declaration["affected"], "retained_accepted_manifest_sha256": declaration["retained_accepted_manifest_sha256"],
                "verifier": contract, "compatible_treatment": False,
                "stable_lineage_projection": _projection(value["class_transition"]),
                "runtime_is_analysis_stratum": True, "rationale": ""}
    _validate_declaration(declaration, expected)
    for key, entry in new_entries.items():
        old = old_entries[key]
        if key not in affected:
            if not _same(entry, old) or not _same(new_cells[key], old_cells[key]):
                raise ValueError("runtime cohort changed an unaffected cell")
            continue
        if (set(entry) != {"hostname", "mode", "science", "members", "writer"}
                or not _same(entry["science"], old["science"]) or len(entry["members"]) != len(old["members"])+1):
            raise ValueError("runtime cohort changes logical science or member ancestry")
        for before, after in zip(old["members"], entry["members"][:-1]):
            expected_member = dict(after)
            if before["cohort_id"] == old["writer"]:
                if after["frozen_accepted"] is None: raise ValueError("previous cohort writer was not frozen")
                expected_member["frozen_accepted"] = None
            if not _same(before, expected_member):
                raise ValueError("runtime cohort rewrites a previous member")
        member = _writer(entry)
        candidate = new_cells[key]
        if (not _same(member, _member(candidate, declaration["verifier"]))
                or entry["members"][-1] is not member or not _same(entry["science"], _science(candidate, value["class_transition"]))
                or _same(candidate["definition"]["native"], old_cells[key]["definition"]["native"])
                or candidate["definition"]["ready"] is not True):
            raise ValueError("runtime cohort writer/Native/ready identity differs")
        row = next((row for row in declaration["affected"] if (row["hostname"], row["mode"]) == key), None)
        if not _same(row, {"hostname": key[0], "mode": key[1],
                          "previous_definition_sha256": old_cells[key]["definition_sha256"],
                          "new_definition_sha256": candidate["definition_sha256"]}):
            raise ValueError("runtime cohort declared definition binding differs")
    _validate_members(parent, value, new_cells, contract)


def _validate_first_record(parent, records, value, contract):
    e = _epochs(); prior = records[-1]
    fields = {"record_type", "sequence", "previous_sha256", "parent_study_sha256", "change", "affected", "cells",
              "exclusions", "class_transition", "write_fences", "cohorts", "cohort_memberships", "compatibility_declaration"}
    if (set(value) != fields or value["record_type"] != ADMISSION or value["change"] != "first-mode"
            or type(value["sequence"]) is not int or value["sequence"] != len(records)
            or value["previous_sha256"] != e._sha(prior)
            or value["parent_study_sha256"] != parent._file("study.json")[1]["sha256"]
            or not _same(value["class_transition"], prior.get("class_transition"))
            or value["class_transition"] is None or not _same(value["exclusions"], prior["exclusions"])):
        raise ValueError("first-mode parent ancestry/selected50/exclusions differ")
    ref = value["compatibility_declaration"]
    if type(ref) is not dict or set(ref) != {"path", "sha256"}:
        raise ValueError("first-mode declaration reference differs")
    declaration = e._read(ref["path"])
    if sha256_file(ref["path"]) != ref["sha256"] or e._sha(declaration) != ref["sha256"]:
        raise ValueError("first-mode declaration immutable bytes changed")
    if (type(declaration.get("affected")) is not list or not declaration["affected"]
            or any(type(row) is not dict or set(row) != {"hostname", "mode", "unadmitted_mode_templates", "new_definition_sha256"}
                   for row in declaration["affected"])):
        raise ValueError("first-mode affected templates are malformed")
    affected = {(row["hostname"], row["mode"]) for row in declaration["affected"]}
    previous = prior["cohorts"] if prior["record_type"] == ADMISSION else _initial_registry(prior, contract)
    old_entries = {(r["hostname"], r["mode"]): r for r in previous}
    new_entries = {(r["hostname"], r["mode"]): r for r in value["cohorts"]}
    old_cells, new_cells = ({e._key(c): c for c in r["cells"]} for r in (prior, value))
    if (len(affected) != len(declaration["affected"]) or affected & old_entries.keys()
            or len(new_entries) != len(value["cohorts"]) or new_entries.keys() != old_entries.keys() | affected
            or len(new_cells) != len(value["cells"]) or new_cells.keys() != old_cells.keys() | affected
            or value["affected"] != [list(key) for key in sorted(affected)]):
        raise ValueError("first-mode logical cell inventory differs")
    next_roots = {new_cells[key]["root"] for key in affected}
    previous_roots = {c["root"] for record in records for c in record["cells"]}
    if len(next_roots) != 1 or next_roots & previous_roots:
        raise ValueError("first mode requires one genuinely fresh independent root")
    new = StudyStore(next(iter(next_roots)))
    expected = _first_declaration(parent, new, records,
        sorted({key[0] for key in affected}), sorted({key[1] for key in affected}),
        contract=contract, retained_digest=declaration["retained_accepted_manifest_sha256"], check_prior_credit=False)
    _validate_first_declaration(declaration, expected)
    for key, old in old_entries.items():
        if not _same(new_entries[key], old) or not _same(new_cells[key], old_cells[key]):
            raise ValueError("first-mode admission rewrites an existing logical cell")
    for key in affected:
        candidate = new_cells[key]; member = _member(candidate, contract)
        expected_entry = {"hostname": key[0], "mode": key[1],
            "science": _science(candidate, value["class_transition"]), "members": [member], "writer": member["cohort_id"]}
        if not _same(new_entries[key], expected_entry) or candidate["definition"]["ready"] is not True:
            raise ValueError("first-mode member must have zero carry and its exact ready enrollment")
    _validate_members(parent, value, new_cells, contract)


def _validate_members(parent, value, new_cells, contract):
    e = _epochs()
    qualified = reader_compatibility.qualify_execution(verifier_contract())
    from .resource_study_lineage import validate_cells
    for entry in value["cohorts"]:
        ids = [m["cohort_id"] for m in entry["members"]]
        if len(ids) != len(set(ids)) or _writer(entry)["cell"] != new_cells[(entry["hostname"], entry["mode"])]:
            raise ValueError("runtime cohort member identity repeats or latest writer differs")
        for member in entry["members"]:
            cell = member["cell"]
            reader_compatibility.require_supported(member["verifier"], qualified)
            if (set(member) != {"cohort_id", "cell", "verifier", "frozen_accepted"}
                    or member["cohort_id"] != e._sha(cell)
                    or not _same(_science(cell, value["class_transition"]), entry["science"])
                    or not _same(cell, _records_cell(cell))):
                raise ValueError("runtime cohort enrollment/source/verifier identity changed")
    validate_cells([m["cell"] for entry in value["cohorts"] for m in entry["members"]], value["class_transition"])
    _check_frozen(parent, value["cohorts"])
    _check_markers(parent, value)


def records(parent):
    """Authenticate one head with call-local immutable inputs and fresh SQL."""
    with _records_read_scope():
        return _records(parent)


def _records(parent):
    """Read the V3 prefix with its original validator; new types stay explicit."""
    e = _epochs()
    head = e._meta(parent, "epoch_head")
    authority = json.loads(head)
    if (set(authority) != {"sequence", "sha256"} or type(authority["sequence"]) is not int or authority["sequence"] < 0):
        raise ValueError("runtime cohort head is malformed")
    values = [e._read(parent.root / "epoch-admissions" / f"{i:06d}.json") for i in range(authority["sequence"]+1)]
    first = next((i for i, value in enumerate(values) if value.get("record_type") == ADMISSION), None)
    if first is None: return e._legacy_records(parent)
    if first == 0 or values[first-1].get("record_type") != V3:
        raise ValueError("runtime cohort lacks an authenticated stable V3 prefix")
    prefix_head = canonical_json({"sequence": first-1, "sha256": e._sha(values[first-1])}).decode()
    original_meta = e._meta
    def historical_meta(store, key):
        return prefix_head if store is parent and key == "epoch_head" else original_meta(store, key)
    namespace = dict(e._legacy_records.__globals__); namespace["_meta"] = historical_meta
    legacy = FunctionType(e._legacy_records.__code__, namespace, e._legacy_records.__name__, e._legacy_records.__defaults__)
    result = deepcopy(legacy(parent))
    execution = verifier_contract()
    qualified = reader_compatibility.qualify_execution(execution)
    for value in values[first:]:
        ref = value.get("compatibility_declaration")
        if type(ref) is not dict or set(ref) != {"path", "sha256"}:
            raise ValueError("runtime cohort declaration reference differs")
        declaration = e._read(ref["path"])
        if type(declaration) is not dict:
            raise ValueError("runtime cohort declaration must be an object")
        contract = reader_compatibility.admission_contract(declaration.get("verifier"), qualified)
        _validate_record(parent, result, value, contract=contract); result.append(value)
    if e._sha(result[-1]) != authority["sha256"] or e._meta(parent, "epoch_head") != head:
        raise ValueError("runtime cohort head changed during authenticated ancestry read")
    from .resource_study_lineage import enforce_selected
    enforce_selected(parent, result)
    if not _same(execution, verifier_contract()):
        raise ValueError("qualifying reader source changed during cohort ancestry read")
    return result


def has_authority(parent):
    """Cheap type dispatch only; records() still authenticates the whole head."""
    e = _epochs(); head = e._meta(parent, "epoch_head")
    if head is None: return False
    authority = json.loads(head)
    if (type(authority) is not dict or set(authority) != {"sequence", "sha256"}
            or type(authority["sequence"]) is not int or authority["sequence"] < 0):
        raise ValueError("runtime cohort head is malformed")
    return e._read(parent.root / "epoch-admissions" / f"{authority['sequence']:06d}.json").get("record_type") == ADMISSION


def _scoped(store, key):
    marker = store.root / MARKER
    scope = getattr(store._stable_write_local, "cohort_scope", None)
    if not marker.exists() and not marker.is_symlink():
        if scope is not None: raise ValueError("runtime cohort writer lost its membership marker")
        return None
    if scope is None or scope["key"] != key or scope["root"] != str(store.root):
        raise ValueError("runtime cohort SQL mutation lacks exact parent-lock authority")
    if not _same(_epochs()._read(marker), scope["marker"]):
        raise ValueError("runtime cohort membership changed inside write scope")
    return scope


@contextmanager
def _write_scope(store, parent, records, key, entries, actions):
    from .resource_study_lineage import write_scope
    if getattr(store._stable_write_local, "cohort_scope", None) is not None:
        raise ValueError("runtime cohort authority cannot nest or widen")
    store._stable_write_local.cohort_scope = {"parent": parent, "records": records, "key": key,
        "root": str(store.root), "entry": _entry(records[-1]["cohorts"], key),
        "marker": _marker(store, parent)}
    try:
        with write_scope(store, parent, records, entries, actions): yield
    finally:
        del store._stable_write_local.cohort_scope


def allocate_slots(store, hostname, mode, connection):
    scope = _scoped(store, (hostname, mode))
    if scope is None: return None
    entry = scope["entry"]
    if _writer(entry)["cell"]["root"] != str(store.root):
        raise ValueError("superseded runtime cohort cannot reserve new sessions")
    occupied = {row["slot"] for _, _, row in _accepted(entry, self_store=store, connection=connection)}
    for member in entry["members"]:
        root = member["cell"]["root"]
        current = store if root == str(store.root) else StudyStore(root)
        pending = _rows(current, scope["key"], connection if current is store else None, active=True)
        if pending: raise ValueError("logical runtime-cohort cell already has an active reservation")
    return occupied


def credit_conflict(store, connection, attempt, value, five_tuple):
    key = value["hostname"], value["mode"]
    scope = _scoped(store, key)
    if scope is None: return None
    if _writer(scope["entry"])["cell"]["root"] != str(store.root):
        raise ValueError("superseded runtime cohort cannot acquire credit")
    rows = _accepted(scope["entry"], self_store=store, connection=connection)
    encoded_tuple = _json(_tuple(five_tuple)).decode()
    if len(rows) >= 400 or any(row["slot"] == value["slot"] or row["five_tuple"] == encoded_tuple for _, _, row in rows):
        return "verified runtime-cohort session repeats a global slot/tuple or exceeds four hundred"
    if encoded_tuple in _epochs()._excluded(scope["parent"], scope["records"], key):
        return "verified runtime-cohort session repeats an excluded ancestor tuple"
    for member in scope["entry"]["members"]:
        root = member["cell"]["root"]
        other = store if root == str(store.root) else StudyStore(root)
        def withdrawn(conn):
            return other._withdrawals(conn) and conn.execute(
                "SELECT 1 FROM integrity_withdrawals WHERE hostname=? AND mode=? AND five_tuple=?", (*key, encoded_tuple)).fetchone()
        if other is store:
            found = withdrawn(connection)
        else:
            with other._transaction() as conn: found = withdrawn(conn)
        if found: return "verified runtime-cohort session repeats a withdrawn tuple"
    return None


def accepted_count(store, hostname, mode):
    e = _epochs(); parent = e._membership(store)
    present = (store.root / MARKER).exists() or (store.root / MARKER).is_symlink()
    if parent is None:
        if present: raise ValueError("runtime cohort marker lacks epoch parent")
        return None
    with e._lock(parent.root):
        current = e._records(parent)
        if not current or current[-1]["record_type"] != ADMISSION:
            if present: raise ValueError("runtime cohort marker has no committed admission")
            return None
        if not present: raise ValueError("runtime cohort count lost its committed membership marker")
        entry = _entry(current[-1]["cohorts"], (_hostname(hostname), _mode(mode)))
        if not any(m["cell"]["root"] == str(store.root) for m in entry["members"]):
            raise ValueError("runtime cohort root is not admitted for this cell")
        return len(_accepted(entry))


def eligible_cells(store, cells):
    """One parent-locked startup hint using the original active-cell guards.

    No authority or mutable ledger state escapes the call. Reservations,
    counts, pilots and credit continue to authenticate their own fresh state.
    """
    if (type(cells) not in (list, tuple) or len(cells) > 250
            or any(type(cell) not in (list, tuple) or len(cell) != 2 for cell in cells)):
        raise ValueError("bounded explicit eligibility cells required")
    keys = [(_hostname(cell[0]), _mode(cell[1])) for cell in cells]
    if len(keys) != len(set(keys)):
        raise ValueError("eligibility cell scope repeats")
    if not keys:
        return frozenset()
    e = _epochs()
    parent = e._membership(store)
    if parent is None:
        return frozenset(key for key in keys if e.active_cell(store, *key))
    with e._lock(parent.root):
        current = e._records(parent)
        selected = {e._key(cell): cell for cell in current[-1]["cells"]}
        result = set()
        for key in keys:
            cell = selected.get(key)
            if cell is not None and cell["root"] == str(store.root):
                e._active(store, *key, current)
                result.add(key)
        return frozenset(result)


def counts_snapshot(store, cells):
    """One parent-locked scheduling hint; reservations/credit recheck authority.

    Only the requested current writer cells are included. No count/head/row
    snapshot is retained by this module or used as mutation authority.
    """
    if (type(cells) not in (list, tuple) or len(cells) > 250
            or any(type(cell) not in (list, tuple) or len(cell) != 2 for cell in cells)):
        raise ValueError("bounded explicit scheduling cells required")
    keys = [(_hostname(cell[0]), _mode(cell[1])) for cell in cells]
    if len(keys) != len(set(keys)): raise ValueError("scheduling cell scope repeats")
    e = _epochs(); parent = e._membership(store)
    present = (store.root / MARKER).exists() or (store.root / MARKER).is_symlink()
    if parent is None:
        if present: raise ValueError("runtime cohort marker lacks epoch parent")
        return None
    with e._lock(parent.root):
        current = e._records(parent)
        if not current or current[-1]["record_type"] != ADMISSION:
            if present: raise ValueError("runtime cohort marker has no committed admission")
            return None
        if not present: raise ValueError("runtime cohort scheduling lost its committed membership marker")
        result = {}
        for key in keys:
            entry = _entry(current[-1]["cohorts"], key)
            if _writer(entry)["cell"]["root"] != str(store.root):
                raise ValueError("scheduling cell is not owned by this current cohort writer")
            result[key] = len(_accepted(entry))
        return result


def reserve(store, parent, records, hostname, mode, operation, *, purpose):
    e = _epochs(); key = _hostname(hostname), _mode(mode)
    entry = _entry(records[-1]["cohorts"], key); member = _writer(entry)
    if member["cell"]["root"] != str(store.root) or not _same(member["cell"], e._cell(store, *key)):
        raise ValueError("runtime cohort writer is stale or enrollment changed")
    if purpose == "formal": e._pilot(store, member["cell"])
    with _write_scope(store, parent, records, key, [(*key, None)],
                      {("attempts", "INSERT"), ("attempts", "UPDATE"), ("measurements", "INSERT"), ("measurements", "UPDATE")}):
        attempt = operation()
        try:
            _create(store.root / attempt["path"] / "epoch-purpose.json", canonical_json({
                "purpose": purpose, "attempt_id": attempt["attempt_id"], "admission_sha256": e._sha(records[-1]),
                "definition_sha256": member["cell"]["definition_sha256"], "cohort_id": member["cohort_id"]}))
        except BaseException:
            store.fail_attempt(attempt["attempt_id"], "runtime cohort purpose publication failed", kind="filesystem")
            raise
        return attempt


def credit(store, parent, records, receipt_path, operation):
    e = _epochs(); receipt = store._receipt(receipt_path)[0]
    key = receipt["hostname"], receipt["mode"]
    entry = _entry(records[-1]["cohorts"], key)
    with store._transaction() as connection:
        row = connection.execute("SELECT * FROM attempts WHERE attempt_id=?", (receipt["attempt_id"],)).fetchone()
    if row is None: raise ValueError("runtime cohort credit lacks original reservation")
    member = next((m for m in entry["members"] if m["cell"]["root"] == str(store.root)), None)
    if member is None: raise ValueError("runtime cohort receipt has no immutable member")
    _check_input_receipt(member, receipt)
    if row["state"] == "accepted":
        if not any(m["cell"]["root"] == str(store.root) for m in entry["members"]):
            raise ValueError("accepted replay is outside the cohort registry")
        return operation()
    member = _writer(entry)
    if member["cell"]["root"] != str(store.root): raise ValueError("stale runtime cohort credit writer")
    intent = e._read(store.root / row["path"] / "epoch-purpose.json")
    expected = {"purpose": "formal", "attempt_id": receipt["attempt_id"], "admission_sha256": e._sha(records[-1]),
                "definition_sha256": member["cell"]["definition_sha256"], "cohort_id": member["cohort_id"]}
    if not _same(intent, expected): raise ValueError("runtime cohort credit changes its original reservation")
    e._pilot(store, member["cell"])
    with _write_scope(store, parent, records, key, [(*key, receipt["attempt_id"])],
                      {("attempts", "UPDATE"), ("accepted", "INSERT"), ("measurements", "INSERT"), ("measurements", "UPDATE")}):
        return operation()


def _receipt_verifier_contract(member, receipt):
    """Preserve capture-producer identity separately from the strict reader.

    A bound old producer may differ from a later independently qualifying
    reader. Never select an older/weaker reader from producer hashes. Dispatch
    is exclusively the authenticated member.verifier contract, and every
    receipt still executes its complete strict raw predicates. Producer bytes
    remain bound by the original receipt/inventory, without relabelling them.
    """
    provenance = receipt.get("coordinator_provenance", {})
    files = provenance.get("files", {})
    if (provenance.get("record_type") != "qcsd-resource-study-host-code-v1"
            or type(files) is not dict or not files):
        raise ValueError("historical capture producer provenance is malformed")
    for name, digest in files.items():
        if type(name) is not str or not name.endswith(".py") or "/" in name or "\\" in name or name in {".py", "..py"}:
            raise ValueError("historical capture producer source name is malformed")
        _digest(digest)
    _check_input_receipt(member, receipt)


def _check_input_receipt(member, receipt):
    from .resource_study_selection import _read
    cell = member["cell"]
    enrollment = _load(_read(Path(cell["root"]) / cell["enrollment_path"], cell["enrollment_sha256"]))
    paths = input_authority_artifact_paths(enrollment)
    if paths:
        digest = _input_binding(enrollment)["context_sha256"]
        if (receipt.get("artifact_paths", {}).get("runtime_cohort_input_context") != INPUT_CONTEXT
                or receipt.get("files", {}).get(INPUT_CONTEXT) != digest):
            raise ValueError("runtime-cohort receipt omits its immutable input-context artifact")
    elif "runtime_cohort_input_context" in receipt.get("artifact_paths", {}):
        raise ValueError("receipt claims partial runtime-cohort input authority")


def status(parent, *, deep=False, verification_workers=1):
    e = _epochs(); _verification_workers(verification_workers)
    if not deep and verification_workers != 1: raise ValueError("parallel verification requires a deep cohort audit")
    parent = StudyStore(Path(parent).absolute())
    with e._lock(parent.root):
        with (ReceiptReplay(verification_workers) if deep and verification_workers > 1 else nullcontext(None)) as replay:
            current = e._records(parent)
            if current[-1]["record_type"] != ADMISSION: raise ValueError("parent has no runtime cohort admission")
            contract = verifier_contract(); cells, refs, count = [], [], 0
            qualified = reader_compatibility.qualify_execution(contract)
            admission_readers = {}
            for entry in current[-1]["cohorts"]:
                for member in entry["members"]:
                    reader_compatibility.require_supported(member["verifier"], qualified)
                    admission_readers[e._sha(member["verifier"])] = deepcopy(member["verifier"])
                key = entry["hostname"], entry["mode"]
                rows = _accepted(entry); excluded = e._excluded(parent, current, key)
                for member, store, row in rows:
                    if row["five_tuple"] in excluded: raise ValueError("runtime cohort resurrects an excluded ancestor tuple")
                    reader_compatibility.require_supported(member["verifier"], qualified)
                    if deep:
                        store._assert_inventory(_load(row["inventory"]))
                        raw, observed = store._file(row["receipt_path"], row["receipt_sha256"])
                        receipt = _load(raw)
                        if (not _same(observed, _load(row["inventory"])[row["receipt_path"]])
                                or (receipt.get("hostname"), receipt.get("mode"), receipt.get("slot"), receipt.get("attempt_id")) !=
                                (row["hostname"], row["mode"], row["slot"], row["attempt_id"])):
                            raise ValueError("runtime cohort receipt/index identity differs")
                        _receipt_verifier_contract(member, receipt)
                        if replay is not None: replay.submit(store.root, raw, row["five_tuple"])
                        else:
                            facts = verify_by_contract(member, store.root, receipt)
                            if _json(facts["five_tuple"]).decode() != row["five_tuple"]:
                                raise ValueError("runtime cohort raw tuple differs from ledger")
                    refs.append({**_row_ref(str(store.root), row), "cohort_id": member["cohort_id"],
                                 "native": member["cell"]["definition"]["native"], "verifier_sha256": e._sha(member["verifier"])})
                cells.append({"hostname": key[0], "mode": key[1], "accepted": len(rows), "target": 400,
                              "writer_cohort": entry["writer"], "cohort_count": len(entry["members"])})
                count += len(rows)
            if not _same(contract, verifier_contract()): raise ValueError("raw verifier source changed during cohort audit")
            complete = len(cells) == 250 and len({c["hostname"] for c in cells}) == 50 and all(c["accepted"] == 400 for c in cells) and count == 100000
            result = {"record_type": COMPOSITION, "schema_version": 1, "parent_study_sha256": parent._file("study.json")[1]["sha256"],
                    "admission_sha256": e._sha(current[-1]), "class_selection": current[-1]["class_transition"]["class_selection"],
                    "cells": cells, "accepted": refs, "accepted_count": count, "total_sessions": 100000,
                    "qualifying_verifiers": admission_readers,
                    "execution_reader": contract,
                    "reader_execution_bindings": {digest: reader_compatibility.execution_binding(value, qualified)
                        for digest, value in sorted(admission_readers.items())},
                    "producer_provenance": "preserved verbatim in each bound source receipt; independent from qualifying reader identity",
                    "complete": complete, "raw_deep_verified": deep, "scientific_credit": deep and complete,
                    "scope": "explicit compatible Native strata; separate immutable cohort roots; global logical-cell slots",
                    "status_authority": "raw-deep-verified" if deep else "existing-accepted-SQL-index; no fresh raw qualification"}

        if not _same(contract, verifier_contract()):
            raise ValueError("raw verifier source changed before all cohort workers joined")
        return result
