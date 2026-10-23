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
import sys
import threading
from pathlib import Path
from types import FunctionType

from .resource_study_inputs import MODES, canonical_json, sha256_file
from .resource_study_store import StudyStore, _PLAN_READ_SCOPE, _AUTHORITY_INPUT_COLLECTOR, _observe_authority, _create, _load, _json, _tuple, _hostname, _mode, _digest
from .resource_study_audit import ReceiptReplay, verification_workers as _verification_workers
from .resource_study_verify import verify_receipt
from . import resource_study_reader_compatibility as reader_compatibility

ADMISSION = "qcsd-resource-domain-runtime-cohort-admission-v1"
DECLARATION = "qcsd-resource-domain-compatible-runtime-declaration-v1"
FIRST_MODE_DECLARATION = "qcsd-resource-domain-first-mode-cohort-declaration-v1"
BUDGET_DECLARATION = "qcsd-resource-domain-buflo-budget-amendment-declaration-v1"
BUDGET_STRATA = "qcsd-resource-domain-buflo-budget-science-strata-v1"
BUDGET_AMENDMENT = "prospective per-cell 640-to-1280 BuFLO budget; separately labelled science strata; unchanged original application workload; shared400 quota; historical credit unchanged"
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
RAW_DEPENDENCIES = ('__init__.py', 'acquisition_errors.py', 'acquisition_selection.py', 'acquisition_timing.py', 'application_response_policy.py', 'browser_egress.py', 'browser_egress_dns.py', 'browser_egress_dns_evidence.py', 'browser_egress_dns_packets.py', 'browser_egress_fixture.py', 'browser_egress_observer.py', 'browser_egress_qualification.py', 'buflo_duration_budget.py', 'buflo_evaluation.py', 'buflo_fin_permission.py', 'buflo_handoff.py', 'buflo_reference.py', 'buflo_study.py', 'build_storage.py', 'capture.py', 'capture_acceptance_policy.py', 'capture_session.py', 'cdp_targets.py', 'chaff_qualification.py', 'class_acquisition.py', 'class_attestation.py', 'class_campaigns.py', 'class_capture20.py', 'class_catalogue.py', 'class_cohort.py', 'class_cohort20.py', 'class_curated_source.py', 'class_evaluation.py', 'class_final_selection20.py', 'class_fitting.py', 'class_handoff.py', 'class_history20.py', 'class_layout.py', 'class_pair_screening20.py', 'class_pipeline.py', 'class_profile_result.py', 'class_public20.py', 'class_readiness20.py', 'class_run_binding.py', 'class_study.py', 'class_successor.py', 'class_validation20.py', 'cohort_allocation.py', 'defenses.py', 'discover.py', 'discovery_evidence.py', 'experiment.py', 'fidelity.py', 'fitting.py', 'fitting_morphing.py', 'fitting_trace.py', 'fitting_walkie_talkie.py', 'fitting_wtfpad.py', 'front_fixed_configuration.py', 'front_incoming_acceptance.py', 'front_preparation_evidence.py', 'h3_prebaseline.py', 'kernel_tx.py', 'kernel_tx_runtime.py', 'manifest.py', 'orchestrator.py', 'parameters.py', 'per_class_selected_capture_amendment.py', 'pinned_cdp.py', 'playwright_driver.py', 'prepare.py', 'process_scheduler.py', 'profiles.py', 'qualification_control_authority.py', 'qualification_delivery_compatibility.py', 'rapid_action_local_source_facts.py', 'rapid_additive_static_enrollment.py', 'rapid_ael_fifteen_qualification.py', 'rapid_attempt_failure_evidence.py', 'rapid_browser_policy_evidence.py', 'rapid_canary_control_bridge.py', 'rapid_capture_control_compatibility.py', 'rapid_capture_control_installation.py', 'rapid_capture_plan.py', 'rapid_capture_traffic.py', 'rapid_chunk_partial_lane.py', 'rapid_class_epochs.py', 'rapid_collector_failure_evidence.py', 'rapid_enrolled_subgroup.py', 'rapid_epoch_corpus.py', 'rapid_epoch_target_chunks.py', 'rapid_epoch_target_parallel_schedule.py', 'rapid_fixed_condition_target.py', 'rapid_formal_parallel.py', 'rapid_front_capture_amendment.py', 'rapid_front_quick_compatibility.py', 'rapid_front_quick_profile.py', 'rapid_lane_evidence.py', 'rapid_mixed_implementation_target.py', 'rapid_operation_facts.py', 'rapid_ordinary_canary_carry.py', 'rapid_ordinary_canary_retry.py', 'rapid_ordinary_group_canary.py', 'rapid_ordinary_parallel_schedule.py', 'rapid_ordinary_transport_control.py', 'rapid_original_static_parallel_schedule.py', 'rapid_page_evidence.py', 'rapid_parallel_capture.py', 'rapid_parallel_partial_lane.py', 'rapid_partial_lane.py', 'rapid_partial_progress.py', 'rapid_per_class_selected_enrollment.py', 'rapid_per_class_selected_input.py', 'rapid_per_mode_native_target.py', 'rapid_portable_runtime.py', 'rapid_quick_profile.py', 'rapid_rolling_capture.py', 'rapid_rolling_readiness.py', 'rapid_rolling_schedule.py', 'rapid_runtime_compatibility.py', 'rapid_runtime_epochs.py', 'rapid_runtime_inspector.py', 'rapid_selected_budget_input.py', 'rapid_selected_capture_input.py', 'rapid_selected_input_renewal.py', 'rapid_selected_parallel_schedule.py', 'rapid_selection_amendment.py', 'rapid_site_admission.py', 'rapid_slot_chunks.py', 'rapid_static_parallel_schedule.py', 'rapid_study_profile.py', 'rapid_supplemental_cohort.py', 'rapid_target_chunks.py', 'rapid_target_overlay_source.py', 'rapid_target_parallel_schedule.py', 'rapid_undefended_capture.py', 'resource_study.py', 'resource_study_audit.py', 'resource_study_cohorts.py', 'resource_study_catalog.py', 'resource_study_epochs.py', 'resource_study_inputs.py', 'resource_study_integrity.py', 'resource_study_lineage.py', 'resource_study_native.py', 'resource_study_network.py', 'resource_study_reader_compatibility.py', 'resource_study_resource_version_inputs.py', 'resource_study_resource_versions.py', 'resource_study_runtime.py', 'resource_study_selection.py', 'resource_study_storage.py', 'resource_study_store.py', 'resource_study_supplements.py', 'resource_study_verify.py', 'resource_study_verify_child.py', 'response_budget_qualification.py', 'runtime_provenance.py', 'selected_capture_amendment.py', 'static_budget_capture.py', 'static_budget_capture_amendment.py', 'static_evidence_transport.py', 'supplied_static_admission.py', 'supplied_static_bootstrap_get.py', 'supplied_static_budget_successor.py', 'supplied_static_capture_amendment.py', 'supplied_static_get.py', 'supplied_static_graph.py', 'supplied_static_preparation.py', 'tamaraw_fixed_configuration.py', 'util.py', 'verification.py', 'whole_graph_capture_amendment.py', 'whole_graph_input.py', 'whole_graph_supplement.py', 'resource_study_atomic_publish.py', 'resource_study_semantic_refusals.py', 'resource_study_fixed_mode_preparation.py')


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
    if content:
        _observe_authority("file", path, raw)
    return stamp(before), digest.hexdigest() if content else None, raw


def _records_root(path):
    """Fence directory identity without treating live child entries as immutable."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or path.resolve(strict=True) != path:
        raise ValueError("records root path is not canonical")
    nodes = (path, *path.parents)
    def identities():
        result = []
        for node in nodes:
            info = node.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("records root contains a linked or nondirectory component")
            # Directory contents legitimately change during capture. Their
            # identity, owner and permissions remain guarded on every use.
            result.append((str(node), info.st_dev, info.st_ino, info.st_uid,
                           info.st_gid, info.st_mode))
        return tuple(result)
    before = identities()
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(descriptor)
        observed = (str(path), opened.st_dev, opened.st_ino, opened.st_uid,
                    opened.st_gid, opened.st_mode)
        if not stat.S_ISDIR(opened.st_mode) or observed != before[0]:
            raise ValueError("records root FD/path differs")
        after = identities()
    finally:
        os.close(descriptor)
    if before != after or path.resolve(strict=True) != path:
        raise ValueError("records root changed during its identity check")
    return before


_CAPTURE_AUTHORITY = ContextVar("resource-study-capture-authority", default=None)


class _CaptureAuthority:
    """Private ancestry with operation-owned immutable input observations.

    Entry/exit rehash every bound byte. Interior callbacks reopen and fence
    every immutable FD/path/stamp while rereading all original fresh SQL.
    No SQL/head/row/count/tuple result or scientific proof is cached here.
    """
    def __init__(self, root, docker_owner):
        from .resource_study_runtime import _DockerLockOwner
        if type(docker_owner) is not _DockerLockOwner:
            raise ValueError("capture authority requires the actual Docker lock owner")
        docker_owner.check()
        self.pid, self.owner_thread = os.getpid(), threading.get_ident()
        self.docker_owner, self.active, self.collecting = docker_owner, True, True
        self.files, self.roots, self.classes, self.absences = {}, {}, {}, set()
        roots = root if type(root) in (list, tuple) else (root,)
        if not roots or len(roots) != len(set(map(str, roots))):
            raise ValueError("capture authority requires distinct owning roots")
        self.writers = frozenset(str(Path(path).absolute()) for path in roots)
        self.records, self.parent, self.meta, self.fences = None, None, {}, {}
        self._validation_digest = None
        self._collecting_source_snapshot = None
        self.epoch_lock = None
        self.source_auth = _SOURCE_OPERATION.get()
        self.owns_source = self.source_auth is None
        if self.owns_source:
            self.source_auth = _SourceAuthorization()
        elif type(self.source_auth) is not _SourceAuthorization:
            raise ValueError("foreign capture Source authorization")
        self.implementations = self._implementations()
        token = _AUTHORITY_INPUT_COLLECTOR.set(self)
        try:
            with bind_source(self.source_auth), self._collecting_source_window():
                # Fresh Stores prevent warmed membership/prefix caches from
                # omitting dependencies during unchanged full validation.
                parents = [_epochs()._membership(StudyStore(path)) for path in self.writers]
                if all(parent is None for parent in parents):
                    return
                if any(parent is None for parent in parents) or len({str(parent.root) for parent in parents}) != 1:
                    raise ValueError("capture authority owning roots have different parents")
                self.parent = StudyStore(parents[0].root)
                with _epochs()._lock(self.parent.root):
                    lock_path = self.parent.root / "epoch-admission.lock"
                    lock_fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    self.epoch_lock = (lock_path, lock_fd, self._db_identity(os.fstat(lock_fd)))
                    self._check_epoch_lock()
                    self.records = deepcopy(records(self.parent))
                    if not self.records or self.records[-1].get("class_transition") is None:
                        self.records = None
                        return
                    for path in tuple(self.roots):
                        actual = _epochs()._membership(StudyStore(path))
                        if actual is None or actual.root != self.parent.root:
                            raise ValueError("capture authority root membership differs")
                    head = self.records[-1]
                    current_roots = {cell["root"] for cell in head["cells"]}
                    if not self.writers <= current_roots:
                        raise ValueError("capture authority includes a superseded owning root")
                    self.fences = dict(head["write_fences"])
                    if set(self.roots) != set(self.fences):
                        raise ValueError("capture authority root/fence census differs")
                    self.observe_absence(self.parent.root / "epoch-admissions" / f"{len(self.records):06d}.json")
                    from .resource_study_lineage import EXCLUDED
                    for path in self.roots:
                        for kind in ("classes", "attempts", "corpus", "pilots"):
                            self.observe_absence(Path(path) / kind / EXCLUDED)
                        study = self.files[str(Path(path) / "study.json")]
                        member = self.files[str(Path(path) / "epoch-membership.json")]
                        plan, membership = _load(study[2]), _load(member[2])
                        expected = {"study_sha256": study[1],
                            "epoch_parent": membership["parent"],
                            "epoch_membership_sha256": member[1]}
                        if "class_network" in plan:
                            expected.update(tuple_uniqueness_scope=plan["tuple_uniqueness_scope"],
                                class_network_sha256=hashlib.sha256(canonical_json(plan["class_network"])).hexdigest())
                        if path == str(self.parent.root):
                            expected["epoch_head"] = canonical_json({"sequence": len(self.records)-1,
                                "sha256": _epochs()._sha(head)}).decode()
                        self.meta[path] = expected
                    self._bind_classes()
                    self.collecting = False
                    self.check(full_bytes=True)
                    self._validation_digest = self._validated_digest()
        except BaseException:
            self.close()
            raise
        finally:
            _AUTHORITY_INPUT_COLLECTOR.reset(token)

    @staticmethod
    def _implementations():
        from . import resource_study_network as network
        from . import resource_study_lineage as lineage
        from . import resource_study_runtime as runtime
        from . import resource_study_resource_version_inputs as resource_inputs
        from . import resource_study_selection as selection
        return (StudyStore._file, StudyStore._connect, StudyStore._plan_data,
            _epochs()._read, _epochs()._cell, _epochs()._records, records, _records,
            _records_file, _records_root, _RecordsRead, _records_read_scope,
            _RecordsRead.__init__, _RecordsRead.check, _RecordsRead.file,
            _RecordsRead.plan_data, _RecordsRead.network_plan, _RecordsRead.store,
            _RecordsRead.frozen_value, _RecordsRead.science, _RecordsRead.finish,
            _RecordsRead.discard, _check_frozen, _uncached_frozen_value,
            network._uncached_validate_network_plan, canonical_json, deepcopy,
            lineage.check_fence_connection, runtime._DockerLockOwner.check,
            selection._read, resource_inputs._read, resource_inputs.read_context,
            _CaptureAuthority._validated_digest, _SourceAuthorization,
            _SourceAuthorization.check, _SourceAuthorization.check.__code__,
            _source_stamps, _source_stamps.__code__,
            _fresh_verifier_contract, _fresh_verifier_contract.__code__,
            sha256_file, sha256_file.__code__,
            _CaptureAuthority._check_collecting_source,
            _CaptureAuthority._check_collecting_source.__code__,
            _CaptureAuthority._collecting_source_window,
            _CaptureAuthority._collecting_source_window.__wrapped__,
            _CaptureAuthority._collecting_source_window.__wrapped__.__code__)

    def _check_collecting_source(self):
        """Only the constructor's same-thread read-only collection window.

        This compares the complete entry census, not any SQL, input file,
        lineage, count or receipt. Both window boundaries reopen and hash
        every qualifying Source byte before any authority can be returned.
        """
        old = self._collecting_source_snapshot
        auth = self.source_auth
        if (type(old) is not tuple or len(old) != 6
                or not self.active or self.pid != os.getpid() or self.pid != old[1]
                or threading.get_ident() != self.owner_thread or self.owner_thread != old[2]
                or _AUTHORITY_INPUT_COLLECTOR.get() is not self
                or type(auth) is not _SourceAuthorization or auth is not old[0]
                or _SOURCE_OPERATION.get() is not auth
                or auth.active is not True or auth.pid != self.pid
                or type(auth.profile) is not bytes or auth.profile != old[3]
                or type(auth.stamps) is not dict or auth.stamps is not old[4]
                or auth.stamps != old[5]):
            raise ValueError("capture authority collecting Source window is closed, foreign, or changed")

    @contextmanager
    def _collecting_source_window(self):
        """Amortize Source-only scans during constructor input collection.

        No authority is yielded to a caller inside this private window. The
        original validator still rereads all input/SQL/fence state, and every
        noncollecting check keeps its original complete Source metadata scan.
        """
        if (self.collecting is not True or self._collecting_source_snapshot is not None
                or not self.active or self.pid != os.getpid()
                or self.owner_thread != threading.get_ident()
                or _AUTHORITY_INPUT_COLLECTOR.get() is not self
                or type(self.source_auth) is not _SourceAuthorization
                or _SOURCE_OPERATION.get() is not self.source_auth
                or self._implementations() != self.implementations):
            raise ValueError("capture authority collecting Source entry is foreign or changed")
        self.docker_owner.check()
        self.source_auth.check()
        if self.source_auth.profile != canonical_json(_fresh_verifier_contract()):
            raise ValueError("capture authority qualifying Source bytes changed before collection")
        self.source_auth.check()
        self._collecting_source_snapshot = (self.source_auth, self.pid, self.owner_thread,
            self.source_auth.profile, self.source_auth.stamps, deepcopy(self.source_auth.stamps))
        body_error = None
        try:
            yield
        except BaseException as error:
            body_error = error
            raise
        finally:
            try:
                if self._implementations() != self.implementations:
                    raise ValueError("capture authority reader implementation changed during collection")
                self.docker_owner.check()
                self._check_collecting_source()
                self.source_auth.check()
                if self.source_auth.profile != canonical_json(_fresh_verifier_contract()):
                    raise ValueError("capture authority qualifying Source bytes changed during collection")
                self.source_auth.check()
            except BaseException as failure:
                if body_error is None:
                    raise
                body_error.add_note("Collecting Source closure also refused: " + str(failure))
            finally:
                self._collecting_source_snapshot = None

    def _owner(self):
        if not self.active or self.pid != os.getpid():
            raise ValueError("capture authority is closed or foreign")
        if self._implementations() != self.implementations:
            raise ValueError("capture authority reader implementation changed")
        self.docker_owner.check()
        if self.collecting is True:
            self._check_collecting_source()
        else:
            self.source_auth.check()

    def _collector(self):
        self._owner()
        if threading.get_ident() != self.owner_thread:
            raise ValueError("capture authority collector has a foreign thread")

    def observe_file(self, path, raw):
        self._collector()
        # Compare the actual successfully parsed bytes to a canonical FD read;
        # never adopt an unchecked later file. Disable only recursive collection.
        token = _AUTHORITY_INPUT_COLLECTOR.set(None)
        try:
            observed = _records_file(Path(path), content=True)
        finally:
            _AUTHORITY_INPUT_COLLECTOR.reset(token)
        if type(raw) is not bytes or observed[2] != raw:
            raise ValueError("capture authority input changed during trusted read")
        key = str(Path(path)); old = self.files.get(key)
        if old is not None and old != observed:
            raise ValueError("capture authority input differs from its trusted bytes")
        if old is None:
            if not self.collecting:
                raise ValueError("capture authority full validator discovered an unbound input")
            self.files[key] = observed

    @staticmethod
    def _db_identity(info):
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("capture authority database is not one regular file")
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)

    def observe_store(self, store):
        self._collector(); path = str(store.root)
        observed = _records_root(store.root); old = self.roots.get(path)
        if old is not None:
            self._check_root(path, old)
            return
        if not self.collecting:
            raise ValueError("capture authority full validator discovered an unbound root")
        root_fd = os.open(store.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            db_fd = os.open(store.database, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                identity = self._db_identity(os.fstat(db_fd))
                if identity != self._db_identity(store.database.lstat()):
                    raise ValueError("capture authority database FD/path differs")
                info = os.fstat(root_fd)
                if (path, info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode) != observed[0]:
                    raise ValueError("capture authority root FD/path differs")
                self.roots[path] = (observed, root_fd, db_fd, identity)
            except BaseException:
                os.close(db_fd)
                raise
        except BaseException:
            os.close(root_fd)
            raise

    def observe_cell(self, cell):
        self._collector()
        key = cell["root"], cell["hostname"]
        value = cell["enrollment_path"], cell["enrollment_sha256"]
        old = self.classes.get(key)
        if old is not None and old != value:
            raise ValueError("capture authority trusted cell binding differs")
        if old is None:
            if not self.collecting:
                raise ValueError("capture authority full validator discovered an unbound class")
            self.classes[key] = value

    def observe_absence(self, path):
        self._collector(); path = Path(path)
        if path.exists() or path.is_symlink():
            raise ValueError("capture authority forbidden artifact appeared")
        if not self.collecting and str(path) not in self.absences:
            raise ValueError("capture authority full validator discovered an unbound absence")
        self.absences.add(str(path))

    def _bind_classes(self):
        """Authenticate the full class census, including unselected history."""
        self._collector()
        expected = dict(self.classes)
        for record in self.records:
            for cell in record["cells"]:
                key = cell["root"], cell["hostname"]
                value = cell["enrollment_path"], cell["enrollment_sha256"]
                if key in expected and expected[key] != value:
                    raise ValueError("capture authority historical enrollment binding differs")
                expected[key] = value
        census = {}
        for path, old in self.roots.items():
            self._check_root(path, old)
            store = StudyStore(path)
            with store._transaction() as connection:
                rows = [tuple(row) for row in connection.execute(
                    "SELECT hostname,path,sha256 FROM classes ORDER BY hostname")]
            for host, relative, digest in rows:
                _hostname(host)
                key, value = (path, host), (relative, digest)
                if key in expected and expected[key] != value:
                    raise ValueError("capture authority current SQL enrollment binding changed")
                raw, observed = store._file(relative, digest)
                enrollment = _load(raw)
                if (observed["mode"] != "0444" or type(enrollment) is not dict
                        or enrollment.get("hostname") != host):
                    raise ValueError("capture authority enrollment bytes or hostname changed")
                census[key] = value
            with store._transaction() as connection:
                after = [tuple(row) for row in connection.execute(
                    "SELECT hostname,path,sha256 FROM classes ORDER BY hostname")]
            if after != rows:
                raise ValueError("capture authority class census changed during authentication")
            self._check_root(path, old)
        if any(census.get(key) != value for key, value in expected.items()):
            raise ValueError("capture authority historical enrollment is absent from its SQL root")
        self.classes = census

    def _check_root(self, path, old):
        expected, root_fd, db_fd, identity = old
        if _records_root(Path(path)) != expected:
            raise ValueError("capture authority root identity changed")
        info = os.fstat(root_fd)
        if (path, info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode) != expected[0]:
            raise ValueError("capture authority pinned root FD changed")
        if (self._db_identity(os.fstat(db_fd)) != identity
                or self._db_identity((Path(path) / "ledger.sqlite3").lstat()) != identity):
            raise ValueError("capture authority database identity changed")

    def _check_epoch_lock(self):
        path, descriptor, expected = self.epoch_lock
        if (self._db_identity(os.fstat(descriptor)) != expected
                or self._db_identity(path.lstat()) != expected):
            raise ValueError("capture authority parent lock identity changed")

    def check(self, *, full_bytes=False):
        self._owner()
        if type(full_bytes) is not bool:
            raise ValueError("capture authority byte-check policy must be explicit boolean")
        self._check_epoch_lock()
        if self.records is None or self.collecting:
            raise ValueError("capture authority has no completed full validation")
        for path, expected in self.files.items():
            # _records_file opens a new nofollow FD on every hit and checks
            # canonical/unlinked paths plus before/after FD/path stamps.
            # The entry stamp includes dev/inode/uid/gid/mode/nlink/size/
            # mtime_ns/ctime_ns; immutable payloads are rehashed at closure.
            actual = _records_file(Path(path), content=full_bytes)
            if actual[0] != expected[0] or full_bytes and actual != expected:
                raise ValueError("capture authority immutable bytes changed")
        for path in self.absences:
            if Path(path).exists() or Path(path).is_symlink():
                raise ValueError("capture authority forbidden artifact appeared")
        from .resource_study_lineage import EXCLUDED, check_fence_connection
        for path, old in self.roots.items():
            self._check_root(path, old)
            store = StudyStore(path)
            with store._transaction() as connection:
                check_fence_connection(store, connection, expected_sha=self.fences[path])
                actual = dict(connection.execute("SELECT key,value FROM meta"))
                if any(actual.get(key) != value for key, value in self.meta[path].items()):
                    raise ValueError("capture authority current SQL meta binding changed")
                rows = {r["hostname"]: (r["path"], r["sha256"])
                        for r in connection.execute("SELECT hostname,path,sha256 FROM classes")}
                expected = {host: value for (root, host), value in self.classes.items() if root == path}
                if rows != expected:
                    raise ValueError("capture authority current SQL enrollment binding changed")
                for table in ("classes", "attempts", "accepted"):
                    if connection.execute(f"SELECT 1 FROM {table} WHERE hostname=?", (EXCLUDED,)).fetchone():
                        raise ValueError("capture authority retired hostname acquired SQL history")
            self._check_root(path, old)
        self._owner()

    def _validated_digest(self):
        """Seal the complete collected validation census, not mutable SQL state."""
        files = []
        for path, (stamp, digest, raw) in sorted(self.files.items()):
            if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError("capture authority cached immutable bytes differ")
            files.append((path, stamp, digest))
        # FD numbers themselves are not ancestry: check() still authenticates
        # the retained actual descriptors against these sealed identities.
        roots = [(path, value[0], value[3]) for path, value in sorted(self.roots.items())]
        classes = [(key, value) for key, value in sorted(self.classes.items())]
        state = {"records": self.records, "parent_root": str(self.parent.root),
            "writers": sorted(self.writers), "files": files, "roots": roots,
            "classes": classes, "absences": sorted(self.absences),
            "meta": self.meta, "fences": self.fences,
            "epoch_lock": (str(self.epoch_lock[0]), self.epoch_lock[2])}
        return hashlib.sha256(canonical_json(state)).digest()

    def finish(self):
        self._collector()
        # Check before using the private parent path to acquire its lock, and
        # before iterating a census which must not have lost a dependency.
        parent_root = self.parent.root
        if self._validation_digest is None or self._validated_digest() != self._validation_digest:
            raise ValueError("capture authority private validated dependency census changed")
        self.check(full_bytes=True)
        token = _AUTHORITY_INPUT_COLLECTOR.set(self)
        try:
            with bind_source(self.source_auth), _epochs()._lock(parent_root):
                if self._validated_digest() != self._validation_digest:
                    raise ValueError("capture authority private validated dependency census changed")
                # Entry ran full semantic ancestry validation. Its exact files,
                # bindings and census remain sealed; fresh SQL/fence/head and
                # both full immutable-byte checks still run at closure.
                self.check(full_bytes=True)
                if self._validated_digest() != self._validation_digest:
                    raise ValueError("capture authority private validated dependency census changed")
                if not _same(_load(self.source_auth.profile), _fresh_verifier_contract()):
                    raise ValueError("capture authority qualifying Source bytes changed")
        finally:
            _AUTHORITY_INPUT_COLLECTOR.reset(token)

    def close(self):
        self.active = False
        if self.epoch_lock is not None:
            os.close(self.epoch_lock[1])
            self.epoch_lock = None
        for _, root_fd, db_fd, _ in self.roots.values():
            os.close(db_fd); os.close(root_fd)
        self.roots.clear(); self.files.clear(); self.classes.clear(); self.absences.clear()
        self.meta.clear(); self.fences.clear(); self.records = None
        self._validation_digest = None
        if self.owns_source:
            self.source_auth.active = False


@contextmanager
def bind_capture_authority(auth, *, writer_root=None):
    if auth is None:
        if _CAPTURE_AUTHORITY.get() is not None:
            raise ValueError("capture authority binding cannot be dropped")
        yield
        return
    if type(auth) is not _CaptureAuthority:
        raise ValueError("foreign capture authority handle")
    auth._owner()
    if writer_root is None:
        if threading.get_ident() != auth.owner_thread:
            raise ValueError("capture worker requires its explicit owning root")
        writer = None
    else:
        writer = str(Path(writer_root).absolute())
        if writer not in auth.writers:
            raise ValueError("capture worker has a foreign owning root")
    old = _CAPTURE_AUTHORITY.get(); binding = (auth, threading.get_ident(), writer)
    if old is not None and old != binding:
        raise ValueError("capture authorities cannot nest or widen")
    token = _CAPTURE_AUTHORITY.set(binding)
    try:
        with bind_source(auth.source_auth):
            yield
    finally:
        _CAPTURE_AUTHORITY.reset(token)


@contextmanager
def capture_authority_scope(root, docker_owner):
    if _CAPTURE_AUTHORITY.get() is not None or _AUTHORITY_INPUT_COLLECTOR.get() is not None:
        raise ValueError("capture authority scope cannot nest")
    if sys.platform != "linux":
        yield None
        return
    auth = _CaptureAuthority(root, docker_owner)
    if auth.records is None:
        auth.close()
        yield None
        return
    body_error = None
    try:
        with bind_capture_authority(auth):
            try:
                yield auth
            except BaseException as error:
                body_error = error
                raise
            finally:
                try:
                    auth.finish()
                except BaseException as failure:
                    if body_error is None:
                        raise
                    body_error.add_note("Capture authority closure also refused: " + str(failure))
    finally:
        auth.close()


def require_capture_membership(store, parent):
    """A bound owning root cannot escape through an unbound fallback."""
    binding = _CAPTURE_AUTHORITY.get()
    if binding is None:
        return
    if (type(binding) is not tuple or len(binding) != 3
            or type(binding[0]) is not _CaptureAuthority or binding[1] != threading.get_ident()):
        raise ValueError("capture authority callback is foreign or unbound")
    auth = binding[0]
    auth._owner()
    if str(store.root) in auth.writers and parent is None:
        raise ValueError("capture authority owning root lost its membership")


@contextmanager
def capture_records_scope(parent, *, writer_root, latest_only=False):
    """Copy callback inputs without exposing the private validated ancestry.

    The opt-in current-head list is only for guards which consume records[-1].
    Complete history remains private and still runs every original full check.
    """
    if type(latest_only) is not bool:
        raise ValueError("capture records view must select an explicit boolean")
    binding = _CAPTURE_AUTHORITY.get()
    if binding is None:
        # Caller retains its original _records position and short circuits.
        yield None
        return
    if (type(binding) is not tuple or len(binding) != 3
            or type(binding[0]) is not _CaptureAuthority or binding[1] != threading.get_ident()):
        raise ValueError("capture authority callback is foreign or unbound")
    auth = binding[0]
    if parent.root != auth.parent.root:
        raise ValueError("capture authority callback has a foreign parent")
    writer = str(Path(writer_root).absolute())
    if writer not in auth.writers or binding[2] not in (None, writer):
        raise ValueError("capture authority callback has a foreign owning root")
    auth.check(); body_error = None
    try:
        # Never hand a callback the private value, including nested head data.
        yield deepcopy(auth.records[-1:] if latest_only else auth.records)
    except BaseException as error:
        body_error = error
        raise
    finally:
        try:
            auth.check()
        except BaseException as failure:
            if body_error is None:
                raise
            body_error.add_note("Capture authority callback closure also refused: " + str(failure))


class _RecordsRead:
    """Immutable data reuse within exactly one synchronous records() call.

    SQL connections, rows, head, counts, membership and raw proof are never
    retained here. The original Store.plan SQL suffix runs on every hit.
    """
    def __init__(self):
        from . import resource_study_network as network
        self.pid, self.thread, self.active = os.getpid(), threading.get_ident(), True
        self.files, self.plans, self.stores, self.sciences = {}, {}, {}, {}
        self.roots, self.frozen_values = {}, {}
        self.network_plans = {}
        self.network_validator = network._uncached_validate_network_plan
        self.lineage_plans = {}
        self.lineage_mapping = network.mapping_sha256
        self.lineage_mapping_code = getattr(self.lineage_mapping, "__code__", None)
        self.store_plan = StudyStore.plan
        self.store_plan_code = getattr(self.store_plan, "__code__", None)

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

    def _cached_plan_data(self, store):
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
        return old[2]

    def plan_data(self, store):
        # The public Store.plan path still receives its independent full copy.
        return deepcopy(self._cached_plan_data(store))

    def _lineage_check(self):
        self.check()
        from . import resource_study_network as network
        if (network._uncached_validate_network_plan is not self.network_validator
                or network.mapping_sha256 is not self.lineage_mapping
                or getattr(network.mapping_sha256, "__code__", None) is not self.lineage_mapping_code
                or StudyStore.plan is not self.store_plan
                or getattr(StudyStore.plan, "__code__", None) is not self.store_plan_code):
            raise ValueError("records lineage mapping validator or Store.plan changed within its call")

    def lineage_plan(self, store):
        """Fresh original SQL/FD joins, with a small independently copied view.

        The full cached plan never escapes this method. Cached lineage values
        are immutable bytes and one validated digest, not SQL rows or authority.
        The original complete plan is parsed/validated once, every input is FD9
        fenced on every hit, and finish compares memory and derived values to
        the freshly rehashed original study bytes before records() can return.
        """
        self._lineage_check()
        if type(store) is not StudyStore:
            return store.plan(), None
        from . import resource_study_network as network
        value, observation, assignments = self._cached_plan_data(store)
        root = str(store.root)
        row = self.lineage_plans.get(root)
        if row is None:
            raw = network._network_plan_cache_bytes(value)
            if raw is None:
                return store.plan(), None  # Preserve unsupported original semantics.
            mapping = self.lineage_mapping(value)
            self._lineage_check()
            if network._network_plan_cache_bytes(value) != raw:
                raise ValueError("records lineage plan changed during initial validation")
            row = self.lineage_plans[root] = (raw, mapping)
        mapping = row[1]
        # Exactly the live Store.plan suffix: no connection, row or SQL decision
        # is retained. Only the pure mapping digest comes from the sealed plan.
        with store._transaction() as connection:
            bound = connection.execute("SELECT value FROM meta WHERE key='study_sha256'").fetchone()
            if bound is None or bound[0] != observation["sha256"] or observation["mode"] != "0444":
                raise ValueError("immutable study/ledger binding changed")
            if assignments is not None:
                for key, expected in (("tuple_uniqueness_scope", value["tuple_uniqueness_scope"]),
                                      ("class_network_sha256", mapping)):
                    bound = connection.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
                    if bound is None or bound[0] != expected:
                        raise ValueError("ledger persistent network/tuple scope binding changed")
        projection = {"source_sha256": value["source_sha256"],
                      "class_network": {"assignments": deepcopy(value["class_network"]["assignments"])}}
        if "record_type" in value["class_network"]:
            projection["class_network"]["record_type"] = deepcopy(value["class_network"]["record_type"])
        if "class_selection" in value:
            projection["class_selection"] = deepcopy(value["class_selection"])
        self._lineage_check()
        return projection, mapping


    def network_plan(self, plan, *, require=False):
        """Memoize successful pure decisions, never assignments or SQL state."""
        self.check()
        from . import resource_study_network as network
        if network._uncached_validate_network_plan is not self.network_validator:
            raise ValueError("records network validator changed within its call")
        raw = network._network_plan_cache_bytes(plan) if type(require) is bool else None
        if raw is None:
            return self.network_validator(plan, require=require)
        key = (require, raw)
        if key not in self.network_plans:
            value = self.network_validator(plan, require=require)
            if (network._uncached_validate_network_plan is not self.network_validator
                    or network._network_plan_cache_bytes(plan) != raw):
                raise ValueError("records network plan or validator changed during validation")
            if value is not None and value is not plan["class_network"]["assignments"]:
                return value  # Preserve an unsupported validator's return semantics.
            self.network_plans[key] = value is not None
        return plan["class_network"]["assignments"] if self.network_plans[key] else None

    def store(self, root):
        self.check(); key = str(root)
        observed = _records_root(root)
        if key in self.roots and self.roots[key] != observed:
            raise ValueError("records root identity changed within its call")
        self.roots.setdefault(key, observed)
        if key not in self.stores: self.stores[key] = StudyStore(root)
        return self.stores[key]

    def frozen_value(self, parent, member):
        self.check()
        key = (str(parent.root), _epochs()._sha(member))
        ref = member["frozen_accepted"]
        if (type(ref) is not dict or set(ref) != {"path", "sha256"}
                or type(ref["path"]) is not str or not ref["path"].startswith("runtime-cohorts/")):
            raise ValueError("runtime cohort retained manifest reference differs")
        path = parent._relative(ref["path"])
        self.file(path, ref["sha256"])
        self.store(member["cell"]["root"])
        if key not in self.frozen_values:
            value = _uncached_frozen_value(parent, member)
            self.file(path, ref["sha256"])
            self.frozen_values[key] = deepcopy(value)
        return deepcopy(self.frozen_values[key])

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
        if self.lineage_plans:
            self._lineage_check()
        checked_lineage = set()
        for root, old in self.roots.items():
            if _records_root(root) != old:
                raise ValueError("records root identity changed before call closure")
        for path, old in self.files.items():
            stamp, digest, raw = _records_file(Path(path), content=True)
            if (stamp, digest) != old:
                raise ValueError("records input bytes changed before call closure")
            root = str(Path(path).parent)
            if Path(path).name == "study.json" and root in self.lineage_plans:
                from . import resource_study_network as network
                expected = self.lineage_plans[root]
                original = _load(raw)
                memory = self.plans[root][2][0]
                if (type(expected) is not tuple or len(expected) != 2
                        or network._network_plan_cache_bytes(original) != expected[0]
                        or network._network_plan_cache_bytes(memory) != expected[0]
                        or self.lineage_mapping(original) != expected[1]):
                    raise ValueError("records lineage memory or projection differs from complete original study bytes")
                self._lineage_check()
                checked_lineage.add(root)
        if checked_lineage != set(self.lineage_plans):
            raise ValueError("records lineage cache lacks a complete study closure")

    def discard(self):
        self.active = False
        self.files.clear(); self.plans.clear(); self.stores.clear(); self.sciences.clear()
        self.roots.clear(); self.frozen_values.clear()
        self.network_plans.clear(); self.lineage_plans.clear()


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
    if "pending_retirements" in entry:
        from .resource_study_semantic_refusals import pending10_accepted
        return pending10_accepted(entry, self_store=self_store, connection=connection)
    if "semantic_refusals" in entry:
        from .resource_study_semantic_refusals import accepted
        return accepted(entry, self_store=self_store, connection=connection)
    if "resource_versions" in entry:
        return _accepted_resource_version(entry, self_store=self_store, connection=connection)
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


def _accepted_resource_version(entry, *, self_store=None, connection=None):
    """Recheck all historical SQL bindings; count only the active v1 members."""
    from .resource_study_resource_versions import target_member_ids, member_version
    eligible = target_member_ids(entry)
    result, slots, tuples = [], {}, set()
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
                raise ValueError("historical resource-version parent membership differs")
            frozen = _frozen_value(parent, member)
            if not _same(frozen["rows"], [_row_ref(root, row) for row in rows]):
                raise ValueError("historical resource-version accepted rows changed")
            if _rows(store, key, own, active=True):
                raise ValueError("historical resource-version member acquired a reservation")
        version = member_version(entry, member["cohort_id"])
        occupied = slots.setdefault(version, set())
        for row in rows:
            if (type(row["slot"]) is not int or not 1 <= row["slot"] <= 400
                    or _json(_tuple(_load(row["five_tuple"]))).decode() != row["five_tuple"]
                    or row["slot"] in occupied or row["five_tuple"] in tuples):
                raise ValueError("resource-version history repeats a tuple or its own version's400 slots")
            occupied.add(row["slot"]); tuples.add(row["five_tuple"])
            if member["cohort_id"] in eligible:
                result.append((member, store, row))
        if len(occupied) > 400:
            raise ValueError("resource-version logical cell exceeds four hundred")
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
    """Reuse immutable carry metadata only within one records() call."""
    scope = _PLAN_READ_SCOPE.get()
    if scope is None:
        return _uncached_frozen_value(parent, member)
    if type(scope) is not _RecordsRead:
        raise ValueError("foreign records frozen-manifest read scope")
    return scope.frozen_value(parent, member)


def _uncached_frozen_value(parent, member):
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
    scope = _PLAN_READ_SCOPE.get()
    if scope is not None and type(scope) is not _RecordsRead:
        raise ValueError("foreign records frozen-manifest root scope")
    store = None if scope is None else scope.store(cell["root"])
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
        (StudyStore(cell["root"]) if store is None else store)._relative(row["receipt_path"])
        slots.add(row["slot"]); tuples.add(row["five_tuple"]); ids.add(row["attempt_id"])
    if not _same(value["rows"], sorted(value["rows"], key=lambda row: (row["slot"], row["attempt_id"]))):
        raise ValueError("runtime cohort retained manifest order differs")
    return value


def _check_frozen(parent, registry):
    """Ancestry authenticates manifests; selected-cell guards join fresh SQL."""
    for entry in registry:
        if "pending_retirements" in entry:
            from .resource_study_semantic_refusals import pending10_check_frozen
            pending10_check_frozen(parent, entry)
            continue
        if "semantic_refusals" in entry:
            from .resource_study_semantic_refusals import check_frozen
            check_frozen(parent, entry)
            continue
        if "resource_versions" in entry:
            _check_resource_frozen(parent, entry)
            continue
        slots, tuples = set(), set()
        for member in entry["members"]:
            if member["frozen_accepted"] is None: continue
            for row in _frozen_value(parent, member)["rows"]:
                if row["slot"] in slots or row["five_tuple"] in tuples:
                    raise ValueError("frozen runtime cohort manifests repeat global slots or tuples")
                slots.add(row["slot"]); tuples.add(row["five_tuple"])
        if len(slots) > 400: raise ValueError("frozen runtime cohort manifest union exceeds four hundred")


def _check_resource_frozen(parent, entry):
    from .resource_study_resource_versions import member_version
    slots, tuples = {}, set()
    for member in entry["members"]:
        if member["frozen_accepted"] is None:
            continue
        occupied = slots.setdefault(member_version(entry, member["cohort_id"]), set())
        for row in _frozen_value(parent, member)["rows"]:
            if row["slot"] in occupied or row["five_tuple"] in tuples:
                raise ValueError("frozen resource-version members repeat their own slots or historical tuples")
            occupied.add(row["slot"]); tuples.add(row["five_tuple"])
        if len(occupied) > 400:
            raise ValueError("frozen resource-version union exceeds its own four hundred")


def _scope_keys(cells, hosts, modes):
    if len(hosts) != len(set(hosts)) or len(modes) != len(set(modes)) or not hosts or not modes:
        raise ValueError("runtime cohort requires unique explicit hostname and mode scope")
    for host in hosts: _hostname(host)
    for mode in modes: _mode(mode)
    keys = {(host, mode) for host in hosts for mode in modes}
    if not keys <= cells.keys():
        raise ValueError("runtime cohort cannot add or replace logical science cells")
    return keys


# The producer remains the original Native122 runtime. This is an explicit
# append-only cover-selection admission, never an ordinary Native change.
COVER_DECLARATION = "qcsd-resource-domain-same-runtime-buflo-capped-cover-declaration-v1"
COVER_CHANGE = "buflo-capped-cover"
COVER_CAP = 65536
COVER_POLICY640 = "rapid-v7-fixed-64ms-640s-duration-budget-v1"


def _cover_input(store, enrollment, key):
    paths, inventory = enrollment.get("paths"), enrollment.get("files")
    if type(paths) is not dict or type(inventory) is not dict:
        raise ValueError("cover replacement lacks its original enrollment launch inventory")
    relative = paths.get(key)
    if (type(relative) is not str or Path(relative).is_absolute()
            or Path(relative).as_posix() != relative or ".." in Path(relative).parts):
        raise ValueError("cover replacement launch input is not canonical and relative")
    digest = inventory.get(relative); _digest(digest)
    path = store._relative(relative)
    scope = _PLAN_READ_SCOPE.get()
    if scope is not None:
        if type(scope) is not _RecordsRead: raise ValueError("foreign cover records input scope")
        scope.file(path, digest)
    _, actual, raw = _records_file(path, content=True)
    if actual != digest:
        raise ValueError("cover replacement immutable launch input changed")
    return {"path": relative, "sha256": digest}, _load(raw)


def _cover_binding(cell, *, capped):
    """Saved launch metadata only; no new qualification or capture operation."""
    from . import resource_study_native as native
    from . import chaff_qualification as chaff
    from .resource_study_runtime import BF122_SHARED_RUNTIME
    if type(capped) is not bool or cell["mode"] != "buflo":
        raise ValueError("cover replacement is exclusively a typed BuFLO transition")
    store = StudyStore(cell["root"])
    if not _same(cell, _records_cell(cell)):
        raise ValueError("cover replacement cell differs from its immutable enrollment")
    raw, observation = store._file(cell["enrollment_path"], cell["enrollment_sha256"])
    enrollment = _load(raw)
    if (observation["mode"] != "0444" or enrollment.get("hostname") != cell["hostname"]
            or enrollment.get("mode_readiness", {}).get("buflo") is not True
            or not _same(enrollment.get("runtime"), BF122_SHARED_RUNTIME)
            or cell["definition"]["ready"] is not True
            or cell["definition"]["policies"].get("buflo_duration_policy") != COVER_POLICY640):
        raise ValueError("cover replacement requires the exact ready Native122640 producer")
    manifest_ref, application = _cover_input(store, enrollment, "manifest")
    prepared_ref, prepared = _cover_input(store, enrollment, "prepared_workload")
    resources = application.get("resources") if type(application) is dict else None
    if (type(resources) is not list or len(resources) != 20
            or any(type(row) is not dict or type(row.get("id")) is not int for row in resources)
            or [row["id"] for row in resources] != list(range(20))
            or [row.get("url") for row in resources] != cell["definition"]["urls"]
            or len(set(cell["definition"]["urls"])) != 20
            or enrollment.get("workload_path") != manifest_ref["path"]
            or enrollment.get("workload_sha256") != manifest_ref["sha256"]
            or cell["definition"]["workload_sha256"] != manifest_ref["sha256"]
            or type(prepared) is not dict or not _same(prepared.get("resources"), resources)):
        raise ValueError("cover replacement changed the frozen original ordered twenty")
    selection = None
    if capped:
        selection = native.validate_buflo_capped_enrollment(store.root, enrollment)
        if (type(selection) is not dict or type(selection.get("cap_bytes")) is not int
                or selection["cap_bytes"] != COVER_CAP):
            raise ValueError("cover replacement requires genuine saved65536 qualification")
        sidecar_ref, _ = _cover_input(store, enrollment, "buflo_chaff_sidecar")
        cover_ref, manifest = _cover_input(store, enrollment, "buflo_chaff_manifest")
        if (selection["sidecar_sha256"] != sidecar_ref["sha256"]
                or selection["native_manifest_sha256"] != cover_ref["sha256"]
                or selection["application_workload_sha256"] != prepared_ref["sha256"]):
            raise ValueError("cover replacement saved qualification launch binding differs")
        launch = {"chaff_manifest": cover_ref, "sidecar": sidecar_ref}
    else:
        if "buflo_chaff_selection" in enrollment:
            raise ValueError("cover replacement before member must be uncapped")
        cover_ref, manifest = _cover_input(store, enrollment, "chaff_manifest")
        launch = {"chaff_manifest": cover_ref}
    rows = manifest.get("resources") if type(manifest) is dict else None
    identifier = manifest.get("selected_chaff_resource_id") if type(manifest) is dict else None
    if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict
            or type(identifier) is not int or not 0 <= identifier < 20
            or rows[0].get("id") != identifier or type(rows[0].get("id")) is not int
            or rows[0].get("url") != resources[identifier]["url"]
            or manifest.get("application_workload_sha256") != prepared_ref["sha256"]):
        raise ValueError("cover replacement manifest is outside its original prepared twenty")
    resource = rows[0]; proof = resource.get("chaff_qualification")
    if type(proof) is not dict:
        raise ValueError("cover replacement lacks its saved qualified response identity")
    response = proof.get("expected_response")
    chaff._validate_expected_response(response)
    if response["content_encoding"] != "identity":
        raise ValueError("cover replacement response must retain identity encoding")
    if capped:
        if (not 1 <= identifier <= 19 or response["body_bytes"] > COVER_CAP
                or selection["selected_chaff_resource_id"] != identifier):
            raise ValueError("cover replacement capped auxiliary identity differs")
        # Native's saved validator already replayed the complete sustained
        # candidate-prefix/receipt contract and derived these exact bytes.
    else:
        expected = prepared.get("preparation", {}).get("expected_responses")
        if (type(expected) is not list or len(expected) != 20
                or any(type(row) is not dict or type(row.get("resource_id")) is not int
                       or type(row.get("bytes")) is not int or row["bytes"] <= 0 for row in expected)
                or {row["resource_id"] for row in expected} != set(range(20))):
            raise ValueError("uncapped cover lacks original complete prepared response identities")
        candidates = sorted((row for row in expected if row["bytes"] >= 1200),
            key=lambda row: (-row["bytes"], row["resource_id"], resources[row["resource_id"]]["url"]))
        if not candidates or identifier != candidates[0]["resource_id"] or response["body_bytes"] <= COVER_CAP:
            raise ValueError("uncapped cover must be the original over65536 largest-body selector")
        request_bytes = proof.get("request_stream_bytes")
        digest = proof.get("response_qualification_sha256"); _digest(digest)
        if type(request_bytes) is not int or request_bytes <= 0:
            raise ValueError("uncapped cover saved request size is invalid")
        sidecar = {"base_manifest": {"sha256": prepared_ref["sha256"]}, "application_resource_id": 0,
            "selected_chaff_resource_id": identifier, "resource": {"headers": resources[identifier]["headers"],
            "expected_response": response, "request_stream_bytes": request_bytes,
            "response_qualification_sha256": digest}}
        if not _same(manifest, chaff.derive_response_only_chaff_manifest(sidecar, resources[identifier])):
            raise ValueError("uncapped cover differs from its exact saved legacy manifest")
    # Repeat original immutable file fences around the saved cap validator.
    for key in ("manifest", "prepared_workload", "buflo_chaff_sidecar", "buflo_chaff_manifest") if capped else ("manifest", "prepared_workload", "chaff_manifest"):
        _cover_input(store, enrollment, key)
    return {"enrollment": {"root": cell["root"], "path": cell["enrollment_path"], "sha256": cell["enrollment_sha256"]},
        "runtime": deepcopy(enrollment["runtime"]), "application_manifest": manifest_ref,
        "prepared_workload": prepared_ref, "launch_inputs": launch, "selection": selection,
        "resource": {"id": identifier, "url": resource["url"], "headers": deepcopy(resource["headers"]),
                     "expected_response": deepcopy(response)}}


def _cover_affected(old, candidate, entry, transition):
    if (old["mode"] != "buflo" or candidate["mode"] != "buflo" or "science_strata" in entry
            or _writer(entry)["cell"] != old or not _same(old["definition"], candidate["definition"])
            or old["definition"]["ready"] is not True
            or not _same(entry["science"], _science(candidate, transition))):
        raise ValueError("cover replacement must preserve the complete ready640 scientific definition")
    before, after = _cover_binding(old, capped=False), _cover_binding(candidate, capped=True)
    if (not _same(before["runtime"], after["runtime"])
            or before["resource"]["id"] == after["resource"]["id"]):
        raise ValueError("cover replacement needs the same full runtime and a changed auxiliary")
    return {"hostname": old["hostname"], "mode": "buflo", "previous_cohort_id": entry["writer"],
        "previous_definition_sha256": old["definition_sha256"],
        "new_definition_sha256": candidate["definition_sha256"],
        "before_cover": before, "after_cover": after}


def _cover_declaration(parent, new, records, hosts, modes, *, contract=None, retained_digest=None):
    e = _epochs()
    if (not records or records[-1]["record_type"] != ADMISSION
            or records[-1].get("class_transition") is None or modes != ["buflo"]):
        raise ValueError("cover replacement requires existing selected50 BuFLO cohort authority")
    prior = records[-1]; cells = {e._key(cell): cell for cell in prior["cells"]}
    keys = _scope_keys(cells, hosts, modes)
    roster = prior["class_transition"]["class_selection"]["selected_hostnames"]
    if len(roster) != 50 or len(set(roster)) != 50 or not set(hosts) <= set(roster):
        raise ValueError("cover replacement host must remain in the original selected50")
    contract = verifier_contract() if contract is None else contract
    affected = [_cover_affected(cells[key], e._cell(new, *key), _entry(prior["cohorts"], key), prior["class_transition"])
                for key in sorted(keys)]
    return {"record_type": COVER_DECLARATION, "schema_version": 1,
        "parent_study_sha256": parent._file("study.json")[1]["sha256"],
        "predecessor_admission_sha256": e._sha(prior), "selected_hostnames": roster,
        "affected": affected,
        "retained_accepted_manifest_sha256": e._sha(_manifest(prior["cohorts"])) if retained_digest is None else retained_digest,
        "verifier": contract, "stable_lineage_projection": _projection(prior["class_transition"]),
        "cover_change_authorized": False, "cover_selection_is_analysis_stratum": True, "rationale": ""}


def _validate_cover_declaration(value, expected):
    if (type(value) is not dict or set(value) != set(expected) or value.get("cover_change_authorized") is not True
            or value.get("cover_selection_is_analysis_stratum") is not True
            or type(value.get("rationale")) is not str or not value["rationale"].strip()):
        raise ValueError("explicit capped cover replacement authority and analysis label required")
    actual = dict(value); actual.update(cover_change_authorized=False, rationale="")
    if not _same(actual, expected):
        raise ValueError("cover replacement declaration changed frozen scope, launch inputs or retained credit")


def cover_template(parent, cohort_root, *, affected_hostnames=(), affected_modes=()):
    e = _epochs()
    parent, new = StudyStore(Path(parent).absolute()), StudyStore(Path(cohort_root).absolute())
    with e._lock(parent.root):
        return _cover_declaration(parent, new, e._records(parent), list(affected_hostnames), list(affected_modes))


def create_cover_replacement(parent, cohort_root, declaration_path, declaration_sha256):
    return _create_admission(parent, cohort_root, declaration_path, declaration_sha256, first=False, cover=True)


def _validate_cover_record(parent, records, value, contract):
    """Historical same-runtime cap admission; never reassert a zero-row root."""
    e = _epochs(); prior = records[-1]
    fields = {"record_type", "sequence", "previous_sha256", "parent_study_sha256", "change", "affected", "cells",
              "exclusions", "class_transition", "write_fences", "cohorts", "cohort_memberships", "compatibility_declaration"}
    if (type(value) is not dict or set(value) != fields or value["record_type"] != ADMISSION or value["change"] != COVER_CHANGE
            or type(value["sequence"]) is not int or value["sequence"] != len(records)
            or value["previous_sha256"] != e._sha(prior)
            or value["parent_study_sha256"] != parent._file("study.json")[1]["sha256"]
            or not _same(value["class_transition"], prior.get("class_transition"))
            or value["class_transition"] is None or not _same(value["exclusions"], prior["exclusions"])):
        raise ValueError("cover replacement parent ancestry/selected50/exclusions differ")
    ref = value["compatibility_declaration"]
    if type(ref) is not dict or set(ref) != {"path", "sha256"}:
        raise ValueError("cover replacement declaration reference differs")
    declaration = e._read(ref["path"])
    if sha256_file(ref["path"]) != ref["sha256"] or e._sha(declaration) != ref["sha256"]:
        raise ValueError("cover replacement declaration immutable bytes changed")
    affected_rows = declaration.get("affected")
    row_fields = {"hostname", "mode", "previous_cohort_id", "previous_definition_sha256", "new_definition_sha256", "before_cover", "after_cover"}
    if (type(affected_rows) is not list or not affected_rows
            or any(type(row) is not dict or set(row) != row_fields for row in affected_rows)):
        raise ValueError("cover replacement affected bindings are malformed")
    affected = {(row["hostname"], row["mode"]) for row in affected_rows}
    old_entries = {(r["hostname"], r["mode"]): r for r in prior["cohorts"]}
    new_entries = {(r["hostname"], r["mode"]): r for r in value["cohorts"]}
    old_cells, new_cells = ({e._key(c): c for c in r["cells"]} for r in (prior, value))
    if (len(affected) != len(affected_rows) or not affected <= old_entries.keys()
            or any(mode != "buflo" for _, mode in affected)
            or len(new_entries) != len(value["cohorts"]) or new_entries.keys() != old_entries.keys()
            or len(new_cells) != len(value["cells"]) or new_cells.keys() != old_cells.keys()
            or value["affected"] != [list(key) for key in sorted(affected)]):
        raise ValueError("cover replacement logical cell inventory differs")
    next_roots = {new_cells[key]["root"] for key in affected}
    previous_roots = {c["root"] for record in records for c in record["cells"]}
    if len(next_roots) != 1 or next_roots & previous_roots:
        raise ValueError("cover replacement requires one genuinely fresh independent root")
    expected = _cover_declaration(parent, StudyStore(next(iter(next_roots))), records,
        sorted({host for host, _ in affected}), ["buflo"], contract=contract,
        retained_digest=declaration.get("retained_accepted_manifest_sha256"))
    _validate_cover_declaration(declaration, expected)
    for key, entry in new_entries.items():
        old = old_entries[key]
        if key not in affected:
            if not _same(entry, old) or not _same(new_cells[key], old_cells[key]):
                raise ValueError("cover replacement changed an unaffected cell")
            continue
        if (set(entry) != {"hostname", "mode", "science", "members", "writer"}
                or not _same(entry["science"], old["science"])
                or len(entry["members"]) != len(old["members"])+1):
            raise ValueError("cover replacement changed logical science or member ancestry")
        for before, after in zip(old["members"], entry["members"][:-1]):
            expected_member = dict(after)
            if before["cohort_id"] == old["writer"]:
                if after["frozen_accepted"] is None: raise ValueError("cover replacement did not freeze previous writer")
                expected_member["frozen_accepted"] = None
            if not _same(before, expected_member):
                raise ValueError("cover replacement rewrites a historical member")
        candidate = new_cells[key]; member = _writer(entry)
        if (entry["members"][-1] is not member or not _same(member, _member(candidate, contract))
                or not _same(candidate["definition"], old_cells[key]["definition"])
                or not _same(entry["science"], _science(candidate, value["class_transition"]))):
            raise ValueError("cover replacement writer/unchanged definition identity differs")
    _validate_members(parent, value, new_cells, contract)


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


CS180_DECLARATION = "qcsd-resource-domain-Ang-CS180-condition-amendment-declaration-v1"
CS180_STRATA = "qcsd-resource-domain-Ang-CS120-CS180-science-strata-v1"
CS180_CHANGE = "Ang-CS120-to-CS180-current20-native137-condition-v1"
CS180_AMENDMENT = "prospective Ang CS120-to-CS180/240 and exact current20 resource19 content version; genuine Native137; separately labelled full science; original shared400 and history unchanged"
T16_DECLARATION = "qcsd-resource-domain-Tamaraw-initial16-condition-amendment-declaration-v1"
T16_STRATA = "qcsd-resource-domain-Tamaraw-initial8192-initial16-science-strata-v1"
T16_CHANGE = "Tamaraw-initial8192-to-initial16-Native139-condition-v1"
T16_AMENDMENT = "prospective same-host frozen20 Tamaraw initial8192-to-initial16; genuine Native139; separately labelled full science; original shared400, members and qualifying history unchanged"


def _t16_science(old):
    """Only the explicit initial stream credit and its policy/hash may change."""
    from . import tamaraw_fixed_configuration as t
    try:
        settings = old["settings"]
        if (len(old["urls"]) != 20 or len(set(old["urls"])) != 20
                or old["policies"].get(t.FIELD) != t.POLICY
                or not _same(settings["policies"], old["policies"])
                or settings["configuration_sha256"] != t.configuration_sha256()
                or not _same(settings["resolved_configuration"], t.resolved_configuration())
                or not _same([settings["timeout_seconds"], settings["capture_seconds"]], [120, 180])):
            raise ValueError("initial16 requires exact original fixed8192 Tamaraw science")
        result = deepcopy(old)
        result["policies"][t.FIELD] = t.INITIAL16_POLICY
        result["settings"].update(configuration_sha256=t.configuration_sha256(selected_policy=t.INITIAL16_POLICY),
            resolved_configuration=t.resolved_configuration(selected_policy=t.INITIAL16_POLICY),
            policies=deepcopy(result["policies"]))
        return result
    except (KeyError, TypeError) as error:
        raise ValueError("initial16 original science is malformed") from error


def _t16_pair(old_cell, new_cell, transition):
    from .tamaraw_fixed_configuration import INITIAL16_NATIVE
    if (old_cell["hostname"] != new_cell["hostname"] or old_cell["mode"] != "tamaraw"
            or new_cell["mode"] != "tamaraw" or new_cell["definition"]["native"][2] != INITIAL16_NATIVE
            or new_cell["definition"]["ready"] is not True
            or not _same(_t16_science(_science(old_cell, transition)), _science(new_cell, transition))):
        raise ValueError("initial16 changes another cell, Native, resources, settings or acceptance")


def _t16_strata(old, science, member_id):
    if (old["mode"] != "tamaraw" or "science_strata" in old or "condition_strata" in old
            or "resource_versions" in old or "semantic_refusals" in old
            or not _same(_t16_science(old["science"]), science)):
        raise ValueError("initial16 requires one exact ordinary Tamaraw condition transition")
    return {"record_type": T16_STRATA, "schema_version": 1, "shared_quota": 400,
        "strata": [{"condition": "original-initial8192", "science": deepcopy(old["science"]),
                    "members": [member["cohort_id"] for member in old["members"]]},
                   {"condition": T16_CHANGE, "science": deepcopy(science), "members": [member_id]}]}


def _t16_condition_sciences(entry):
    value = entry["condition_strata"]
    if (set(entry) != {"hostname", "mode", "science", "members", "writer", "condition_strata"}
            or entry["mode"] != "tamaraw" or type(value) is not dict
            or set(value) != {"record_type", "schema_version", "shared_quota", "strata"}
            or value["record_type"] != T16_STRATA or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or type(value["shared_quota"]) is not int or value["shared_quota"] != 400
            or type(value["strata"]) is not list or len(value["strata"]) != 2):
        raise ValueError("initial16 requires the exact typed two-condition shared400 ledger")
    assigned, sciences = [], {}
    for stratum, label in zip(value["strata"], ("original-initial8192", T16_CHANGE)):
        if (type(stratum) is not dict or set(stratum) != {"condition", "science", "members"}
                or stratum["condition"] != label or type(stratum["members"]) is not list or not stratum["members"]
                or any(type(identity) is not str for identity in stratum["members"])):
            raise ValueError("initial16 condition member schema differs")
        assigned.extend(stratum["members"])
        sciences.update({identity: stratum["science"] for identity in stratum["members"]})
    if (len(assigned) != len(set(assigned)) or assigned != [member["cohort_id"] for member in entry["members"]]
            or entry["writer"] not in value["strata"][1]["members"]
            or not _same(_t16_science(value["strata"][0]["science"]), value["strata"][1]["science"])
            or not _same(entry["science"], value["strata"][1]["science"])):
        raise ValueError("initial16 rewrites full science, member history or current writer")
    return sciences


def _t16_declaration_value(parent, prior, affected, retained_digest, contract):
    value = _cs180_declaration_value(parent, prior, affected, retained_digest, contract)
    value.update(record_type=T16_DECLARATION, methodology_amendment=T16_AMENDMENT)
    return value


def _validate_t16_declaration(value, expected):
    # Exact fields, explicit approval and unchanged full ancestry, not Native-only compatibility.
    _validate_cs180_declaration(value, expected)


def _t16_declaration(parent, new, records, hosts, modes):
    e = _epochs()
    if (len(hosts) != 1 or modes != ["tamaraw"] or not records or records[-1].get("class_transition") is None
            or hosts[0] not in records[-1]["class_transition"]["class_selection"]["selected_hostnames"]):
        raise ValueError("initial16 requires exactly one existing selected50 Tamaraw cell")
    cells = {e._key(cell): cell for cell in records[-1]["cells"]}; key = hosts[0], "tamaraw"
    if key not in cells: raise ValueError("initial16 cannot introduce a first mode")
    old, candidate = cells[key], e._cell(new, *key)
    _t16_pair(old, candidate, records[-1]["class_transition"])
    contract = verifier_contract()
    registry = records[-1]["cohorts"] if records[-1]["record_type"] == ADMISSION else _initial_registry(records[-1], contract)
    entry = _entry(registry, key)
    _t16_strata(entry, _science(candidate, records[-1]["class_transition"]), "prospective-member")
    affected = [{"hostname": key[0], "mode": key[1], "previous_definition_sha256": old["definition_sha256"],
                 "new_definition_sha256": candidate["definition_sha256"]}]
    return _t16_declaration_value(parent, records[-1], affected, e._sha(_manifest(registry)), contract)


def tamaraw16_template(parent, cohort_root, *, affected_hostnames=(), affected_modes=()):
    e = _epochs(); parent, new = StudyStore(Path(parent).absolute()), StudyStore(Path(cohort_root).absolute())
    with e._lock(parent.root):
        return _t16_declaration(parent, new, e._records(parent), list(affected_hostnames), list(affected_modes))


def create_tamaraw16_condition(parent, cohort_root, declaration_path, declaration_sha256):
    return _create_admission(parent, cohort_root, declaration_path, declaration_sha256, first=False, tamaraw16=True)


def _cs180_science(old):
    """Exact prospective science transform; no arbitrary duration/workload waiver."""
    from .resource_study_native import (CS180_OLD_WORKLOAD, CS180_WORKLOAD,
        CS180_PARAMETERS, CS180_POLICY)
    try:
        settings=old["settings"]
        if (old["workload_sha256"] != CS180_OLD_WORKLOAD
                or len(old["urls"]) != 20 or len(set(old["urls"])) != 20
                or settings["parameters_sha256"] != CS180_PARAMETERS
                or [settings["timeout_seconds"],settings["capture_seconds"]] != [120,180]
                or old["policies"].get("parameter_policy") != "fixed-cs-buflo-cpsp-live-v1"
                or "cs_buflo_duration_policy" in old["policies"]
                or not _same(settings["policies"],old["policies"])):
            raise ValueError("CS180 requires exact original Ang CS120 science")
        result=deepcopy(old)
        result["workload_sha256"]=CS180_WORKLOAD
        result["policies"]["cs_buflo_duration_policy"]=CS180_POLICY
        result["settings"].update(timeout_seconds=180,capture_seconds=240)
        result["settings"]["policies"]=deepcopy(result["policies"])
        return result
    except (KeyError,TypeError) as error:
        raise ValueError("CS180 original science is malformed") from error


def _cs180_pair(old_cell,new_cell,transition):
    from .resource_study_native import CS180_HOST,CS180_NATIVE
    if ((old_cell["hostname"],old_cell["mode"]) != (CS180_HOST,"cs-buflo")
            or (new_cell["hostname"],new_cell["mode"]) != (CS180_HOST,"cs-buflo")
            or new_cell["definition"]["native"][2] != CS180_NATIVE
            or _same(old_cell["definition"]["native"],new_cell["definition"]["native"])
            or new_cell["definition"]["ready"] is not True
            or not _same(_cs180_science(_science(old_cell,transition)),_science(new_cell,transition))):
        raise ValueError("CS180 changes another cell, Native, workload, parameters, acceptance or ordered20")


def _cs180_strata(old,science,member_id):
    if (old["hostname"] != "angkanet26.com" or old["mode"] != "cs-buflo"
            or "science_strata" in old or "condition_strata" in old
            or not _same(_cs180_science(old["science"]),science)):
        raise ValueError("CS180 requires one exact prospective condition transition")
    return {"record_type":CS180_STRATA,"schema_version":1,"shared_quota":400,
        "strata":[{"condition":"original-CS120/180","science":deepcopy(old["science"]),
                   "members":[m["cohort_id"] for m in old["members"]]},
                  {"condition":CS180_CHANGE,"science":deepcopy(science),"members":[member_id]}]}


def _condition_sciences(entry):
    value=entry["condition_strata"]
    if type(value) is dict and value.get("record_type") == T16_STRATA:
        return _t16_condition_sciences(entry)
    if (set(entry)!={"hostname","mode","science","members","writer","condition_strata"}
            or (entry["hostname"],entry["mode"])!=("angkanet26.com","cs-buflo")
            or type(value) is not dict or set(value)!={"record_type","schema_version","shared_quota","strata"}
            or value["record_type"]!=CS180_STRATA or type(value["schema_version"]) is not int
            or value["schema_version"]!=1 or type(value["shared_quota"]) is not int or value["shared_quota"]!=400
            or type(value["strata"]) is not list or len(value["strata"])!=2):
        raise ValueError("CS180 requires the exact two-condition shared400 ledger")
    assigned=[];sciences={}
    for stratum,label in zip(value["strata"],("original-CS120/180",CS180_CHANGE)):
        if (type(stratum) is not dict or set(stratum)!={"condition","science","members"}
                or stratum["condition"]!=label or type(stratum["members"]) is not list
                or not stratum["members"] or any(type(i) is not str for i in stratum["members"])):
            raise ValueError("CS180 condition member schema differs")
        assigned.extend(stratum["members"])
        sciences.update({identity:stratum["science"] for identity in stratum["members"]})
    if (len(assigned)!=len(set(assigned)) or assigned!=[m["cohort_id"] for m in entry["members"]]
            or entry["writer"] not in value["strata"][1]["members"]
            or not _same(_cs180_science(value["strata"][0]["science"]),value["strata"][1]["science"])
            or not _same(entry["science"],value["strata"][1]["science"])):
        raise ValueError("CS180 rewrites full science, member history or writer")
    return sciences


def _cs180_declaration_value(parent,prior,affected,retained_digest,contract):
    return {"record_type":CS180_DECLARATION,"schema_version":1,
        "parent_study_sha256":parent._file("study.json")[1]["sha256"],
        "predecessor_admission_sha256":_epochs()._sha(prior),
        "selected_hostnames":prior["class_transition"]["class_selection"]["selected_hostnames"],
        "affected":affected,"retained_accepted_manifest_sha256":retained_digest,
        "verifier":contract,"stable_lineage_projection":_projection(prior["class_transition"]),
        "condition_change_authorized":False,"methodology_amendment":CS180_AMENDMENT,
        "two_condition_strata_shared400":True,"historical_credit_preserved":True,"rationale":""}


def _validate_cs180_declaration(value,expected):
    if (type(value) is not dict or set(value)!=set(expected)
            or value.get("condition_change_authorized") is not True
            or value.get("two_condition_strata_shared400") is not True
            or value.get("historical_credit_preserved") is not True
            or type(value.get("rationale")) is not str or not value["rationale"].strip()):
        raise ValueError("explicit Ang CS180 condition methodology declaration required")
    actual=dict(value);actual.update(condition_change_authorized=False,rationale="")
    if not _same(actual,expected):
        raise ValueError("CS180 declaration changes actual parent, science, retained history or source")


def _cs180_declaration(parent,new,records,hosts,modes):
    e=_epochs()
    if (hosts!=["angkanet26.com"] or modes!=["cs-buflo"] or not records
            or records[-1].get("class_transition") is None):
        raise ValueError("CS180 admission requires exact one Ang CS cell and genuine selected50 parent")
    cells={e._key(c):c for c in records[-1]["cells"]};key=(hosts[0],modes[0])
    if key not in cells: raise ValueError("CS180 cannot introduce a first mode")
    old,candidate=cells[key],e._cell(new,*key)
    _cs180_pair(old,candidate,records[-1]["class_transition"])
    contract=verifier_contract()
    registry=records[-1]["cohorts"] if records[-1]["record_type"]==ADMISSION else _initial_registry(records[-1],contract)
    if "science_strata" in _entry(registry,key) or "condition_strata" in _entry(registry,key):
        raise ValueError("CS180 condition was already amended")
    affected=[{"hostname":key[0],"mode":key[1],"previous_definition_sha256":old["definition_sha256"],
        "new_definition_sha256":candidate["definition_sha256"]}]
    return _cs180_declaration_value(parent,records[-1],affected,e._sha(_manifest(registry)),contract)


def cs180_template(parent,cohort_root,*,affected_hostnames=(),affected_modes=()):
    e=_epochs();parent,new=StudyStore(Path(parent).absolute()),StudyStore(Path(cohort_root).absolute())
    with e._lock(parent.root):
        return _cs180_declaration(parent,new,e._records(parent),list(affected_hostnames),list(affected_modes))


def create_cs180_condition(parent,cohort_root,declaration_path,declaration_sha256):
    return _create_admission(parent,cohort_root,declaration_path,declaration_sha256,first=False,condition=True)


def _budget_science(old):
    """Only the explicitly approved640-to1280 budget/settings delta is legal."""
    from . import buflo_duration_budget as budget
    try:
        settings = old["settings"]
        if (not _same(settings["parameters"], budget.CADENCE64_PARAMETERS)
                or settings["parameters_sha256"] != budget.CADENCE64_PARAMETER_SHA256
                or not _same([settings["timeout_seconds"], settings["capture_seconds"]], [680, 740])
                or old["policies"]["buflo_duration_policy"] != budget.CADENCE64_POLICY
                or not _same(settings["policies"], old["policies"])):
            raise ValueError("budget amendment requires the exact original640 BuFLO science")
        result = deepcopy(old)
        result["policies"]["buflo_duration_policy"] = budget.CADENCE64_1280_POLICY
        result["settings"].update(parameters=deepcopy(budget.CADENCE64_1280_PARAMETERS),
            parameters_sha256=budget.CADENCE64_1280_PARAMETER_SHA256,
            timeout_seconds=1320, capture_seconds=1380)
        result["settings"]["policies"] = deepcopy(result["policies"])
        return result
    except (KeyError, TypeError) as error:
        raise ValueError("budget amendment has malformed original640 science") from error


def _budget_strata(old, science, member_id):
    from . import buflo_duration_budget as budget
    if "science_strata" in old or not _same(_budget_science(old["science"]), science):
        raise ValueError("budget amendment requires one prospective exact640-to1280 transition")
    return {"record_type": BUDGET_STRATA, "schema_version": 1, "shared_quota": 400,
        "strata": [
            {"policy": budget.CADENCE64_POLICY, "science": deepcopy(old["science"]),
             "members": [member["cohort_id"] for member in old["members"]]},
            {"policy": budget.CADENCE64_1280_POLICY, "science": deepcopy(science), "members": [member_id]}]}


def _stratum_sciences(entry):
    """Validate the closed ledger, retaining every historical full science value."""
    if "pending_retirements" in entry:
        from .resource_study_semantic_refusals import pending10_member_sciences
        return pending10_member_sciences(entry)
    if "semantic_refusals" in entry:
        from .resource_study_semantic_refusals import member_sciences
        return member_sciences(entry)
    if "condition_strata" in entry:
        return _condition_sciences(entry)
    if "resource_versions" in entry:
        from .resource_study_resource_versions import member_sciences
        return member_sciences(entry)
    base = {"hostname", "mode", "science", "members", "writer"}
    if "science_strata" not in entry:
        if set(entry) != base: raise ValueError("runtime cohort entry fields differ")
        return {member["cohort_id"]: entry["science"] for member in entry["members"]}
    from . import buflo_duration_budget as budget
    value = entry["science_strata"]
    if (set(entry) != base | {"science_strata"} or entry["mode"] != "buflo"
            or type(value) is not dict or set(value) != {"record_type", "schema_version", "shared_quota", "strata"}
            or value["record_type"] != BUDGET_STRATA or type(value["schema_version"]) is not int
            or value["schema_version"] != 1 or type(value["shared_quota"]) is not int or value["shared_quota"] != 400
            or type(value["strata"]) is not list or len(value["strata"]) != 2):
        raise ValueError("BuFLO budget strata require the exact typed two-stratum shared400 ledger")
    sciences, assigned = {}, []
    for stratum, policy in zip(value["strata"], (budget.CADENCE64_POLICY, budget.CADENCE64_1280_POLICY)):
        if (type(stratum) is not dict or set(stratum) != {"policy", "science", "members"}
                or stratum["policy"] != policy or type(stratum["members"]) is not list or not stratum["members"]
                or any(type(identity) is not str for identity in stratum["members"])):
            raise ValueError("BuFLO budget stratum label/member schema differs")
        assigned.extend(stratum["members"])
        sciences.update({identity: stratum["science"] for identity in stratum["members"]})
    if (len(assigned) != len(set(assigned)) or assigned != [member["cohort_id"] for member in entry["members"]]
            or entry["writer"] not in value["strata"][1]["members"]
            or not _same(_budget_science(value["strata"][0]["science"]), value["strata"][1]["science"])
            or not _same(entry["science"], value["strata"][1]["science"])):
        raise ValueError("BuFLO budget strata rewrite science, member ancestry, or current writer")
    return sciences


def _budget_declaration(parent, new, records, hosts, modes):
    e = _epochs()
    if not records or records[-1].get("class_transition") is None or modes != ["buflo"]:
        raise ValueError("budget amendment requires stable selected50 and explicit BuFLO-only scope")
    cells = {e._key(cell): cell for cell in records[-1]["cells"]}
    keys = _scope_keys(cells, hosts, modes)
    contract = verifier_contract()
    registry = records[-1]["cohorts"] if records[-1]["record_type"] == ADMISSION else _initial_registry(records[-1], contract)
    affected = []
    for key in sorted(keys):
        old, candidate = cells[key], e._cell(new, *key)
        if ("science_strata" in _entry(registry, key)
                or not _same(_budget_science(_science(old, records[-1]["class_transition"])),
                             _science(candidate, records[-1]["class_transition"]))
                or candidate["definition"]["ready"] is not True):
            raise ValueError("budget amendment changes more than the exact ready640-to1280 science")
        affected.append({"hostname": key[0], "mode": key[1],
            "previous_definition_sha256": old["definition_sha256"], "new_definition_sha256": candidate["definition_sha256"]})
    return _budget_declaration_value(parent, records[-1], affected, e._sha(_manifest(registry)), contract)


def _budget_declaration_value(parent, prior, affected, retained_digest, contract):
    return {"record_type": BUDGET_DECLARATION, "schema_version": 1,
        "parent_study_sha256": parent._file("study.json")[1]["sha256"],
        "predecessor_admission_sha256": _epochs()._sha(prior),
        "selected_hostnames": prior["class_transition"]["class_selection"]["selected_hostnames"],
        "affected": affected, "retained_accepted_manifest_sha256": retained_digest,
        "verifier": contract, "stable_lineage_projection": _projection(prior["class_transition"]),
        "budget_change_authorized": False, "methodology_amendment": BUDGET_AMENDMENT,
        "two_budget_strata_shared400": True, "historical_credit_preserved": True, "rationale": ""}


def _validate_budget_declaration(value, expected):
    if (type(value) is not dict or set(value) != set(expected)
            or value.get("budget_change_authorized") is not True
            or value.get("two_budget_strata_shared400") is not True
            or value.get("historical_credit_preserved") is not True
            or type(value.get("rationale")) is not str or not value["rationale"].strip()):
        raise ValueError("explicit two-stratum BuFLO budget methodology amendment is required")
    actual = dict(value); actual.update(budget_change_authorized=False, rationale="")
    if not _same(actual, expected):
        raise ValueError("budget amendment changed parent, scope, science, retained credit, or qualifying reader")


def budget_template(parent, cohort_root, *, affected_hostnames=(), affected_modes=()):
    e = _epochs()
    parent, new = StudyStore(Path(parent).absolute()), StudyStore(Path(cohort_root).absolute())
    with e._lock(parent.root):
        return _budget_declaration(parent, new, e._records(parent), list(affected_hostnames), list(affected_modes))


def create_budget_amendment(parent, cohort_root, declaration_path, declaration_sha256):
    return _create_admission(parent, cohort_root, declaration_path, declaration_sha256, first=False, budget=True)


def _resource_member_input(cell, *, context=None):
    """Authenticate a distinct v1 input; never reinterpret it as old catalogue data."""
    from . import resource_study_resource_version_inputs as inputs
    root = Path(cell["root"]); path = root / inputs.INPUT_CONTEXT
    if not (path.exists() or path.is_symlink()):
        if context is not None:
            raise ValueError("current resource-version member lost its separate frozen input authority")
        return False
    if context is None:
        context, _ = inputs.read_context(root, StudyStore(root).plan())
    scope = {(context["input"]["hostname"], row["mode"])
             for row in context["input"]["mode_roots"] if row["root"] == str(root)}
    if (context["context"]["root"] != str(root) or (cell["hostname"], cell["mode"]) not in scope
            or cell["definition"]["urls"] != context["urls"]
            or cell["definition"]["workload_sha256"] != context["context"]["application_manifest_sha256"]):
        raise ValueError("current resource-version member differs from its separate frozen input authority")
    return True


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
        from . import resource_study_resource_version_inputs as resource_inputs
        resource_context = store.root / resource_inputs.INPUT_CONTEXT
        resource_version = resource_context.exists() or resource_context.is_symlink()
        if resource_version:
            # A v1 member is explicitly outside its old catalogue. Preserve its
            # new frozen authority, without copying those URLs into the old
            # source pool or making unrelated49 initialization depend on it.
            context, _ = resource_inputs.read_context(store.root, store.plan())
            for cell in member_cells:
                _resource_member_input(cell, context=context)
        for host in sorted({cell["hostname"] for cell in member_cells}):
            if resource_version:
                continue
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


def _cs180_input_declaration(prior):
    """Preparation intent bound to the actual old snapshot; grants no admission."""
    from .resource_study_native import CS180_HOST,CS180_NATIVE,CS180_POLICY,CS180_OLD_WORKLOAD,CS180_WORKLOAD
    cells=[cell for cell in prior["cells"] if (cell["hostname"],cell["mode"])==(CS180_HOST,"cs-buflo")]
    if len(cells)!=1:
        raise ValueError("CS180 input authority requires exactly one existing Ang CS writer")
    cell=cells[0]
    _cs180_science(_science(cell,prior["class_transition"]))
    return {"record_type":"qcsd-Ang-CS180-prospective-preparation-intent-v1","schema_version":1,
        "policy":CS180_POLICY,"hostname":CS180_HOST,"mode":"cs-buflo",
        "previous_definition_sha256":cell["definition_sha256"],"old_workload_sha256":CS180_OLD_WORKLOAD,
        "new_workload_sha256":CS180_WORKLOAD,"native_commit":CS180_NATIVE,"shared_quota":400,
        "scientific_credit":False}


def _t16_input_declaration(prior, hostname):
    from . import tamaraw_fixed_configuration as t
    _hostname(hostname)
    if (prior.get("class_transition") is None
            or hostname not in prior["class_transition"]["class_selection"]["selected_hostnames"]):
        raise ValueError("initial16 requires an existing selected50 host")
    cells = [cell for cell in prior["cells"] if (cell["hostname"], cell["mode"]) == (hostname, "tamaraw")]
    if len(cells) != 1: raise ValueError("initial16 preparation requires one existing Tamaraw writer")
    cell = cells[0]; _t16_science(_science(cell, prior["class_transition"]))
    if prior.get("record_type") == ADMISSION:
        entry = _entry(prior["cohorts"], (hostname, "tamaraw"))
        if set(entry) != {"hostname", "mode", "science", "members", "writer"}:
            raise ValueError("initial16 cannot combine resource, budget, semantic or prior condition amendments")
    return {"record_type": "qcsd-Tamaraw-initial16-prospective-preparation-intent-v1", "schema_version": 1,
        "policy": t.INITIAL16_POLICY, "hostname": hostname, "mode": "tamaraw",
        "previous_definition_sha256": cell["definition_sha256"], "workload_sha256": cell["definition"]["workload_sha256"],
        "native_commit": t.INITIAL16_NATIVE, "shared_quota": 400, "scientific_credit": False}


def require_tamaraw_preparation(store, hostname, selected_policy):
    """Check actual old head and explicit condition intent before network preparation."""
    from . import tamaraw_fixed_configuration as t
    selected = t.POLICY if selected_policy is None else t.validate_policy(selected_policy)
    path = store.root / INPUT_CONTEXT
    if not path.exists() and not path.is_symlink():
        if selected == t.INITIAL16_POLICY: raise ValueError("initial16 needs an initialized actual-parent condition context")
        return
    context, _ = _input_context(store.root, store.plan())
    intent = context.get("tamaraw16_condition")
    if intent is not None or selected == t.INITIAL16_POLICY:
        _require_current_input_context(context)
        if (selected != t.INITIAL16_POLICY or not _same(intent, _t16_input_declaration(context["predecessor"], hostname))):
            raise ValueError("initial16 preparation differs from its exact old-parent one-cell intent")


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
    if type(value) is dict and "cs180_condition" in value:
        fields.add("cs180_condition")
    if type(value) is dict and "tamaraw16_condition" in value:
        fields.add("tamaraw16_condition")
        if "cs180_condition" in value: raise ValueError("distinct science amendments cannot share a preparation root")
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
    if "cs180_condition" in value and not _same(value["cs180_condition"],_cs180_input_declaration(prior)):
        raise ValueError("CS180 input intent changes original parent cell, policy or full scope")
    if "tamaraw16_condition" in value:
        intent = value["tamaraw16_condition"]
        if type(intent) is not dict or not _same(intent, _t16_input_declaration(prior, intent.get("hostname"))):
            raise ValueError("initial16 input intent changes actual parent cell or full science scope")
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
    from .resource_study_native import CS180_POLICY,CS180_WORKLOAD,_cs180_scope
    selected_cs=enrollment.get("mode_policies",{}).get("cs-buflo",{}).get("cs_buflo_duration_policy")
    intent=context.get("cs180_condition")
    workload=definition["workload_sha256"]
    if intent is not None:
        if (host!="angkanet26.com" or selected_cs!=CS180_POLICY
                or not _same(intent,_cs180_input_declaration(context["predecessor"]))):
            raise ValueError("explicit CS180 initialization requires its genuine new policy enrollment")
        _cs180_scope(host,enrollment["runtime"],enrollment["workload_sha256"])
        workload=CS180_WORKLOAD
    elif selected_cs is not None:
        raise ValueError("CS180 enrollment lacks explicit original-parent condition input intent")
    from . import tamaraw_fixed_configuration as t
    selected_tamaraw = enrollment.get("mode_policies", {}).get("tamaraw", {}).get(t.FIELD)
    t16_intent = context.get("tamaraw16_condition")
    if t16_intent is not None:
        if (selected_tamaraw != t.INITIAL16_POLICY
                or not _same(t16_intent, _t16_input_declaration(context["predecessor"], host))
                or enrollment.get("runtime", {}).get("native_commit") != t.INITIAL16_NATIVE
                or enrollment.get("runtime", {}).get("source", {}).get("neqo_commit") != t.INITIAL16_NATIVE):
            raise ValueError("initial16 enrollment lacks its exact Native139 old-parent condition authority")
    elif selected_tamaraw == t.INITIAL16_POLICY:
        raise ValueError("initial16 enrollment lacks explicit actual-parent preparation intent")
    if (not _same(enrollment.get("urls"), definition["urls"])
            or enrollment.get("workload_sha256") != workload
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


def initialize_cohort(parent, cohort_root, *, cs_buflo_duration_policy=None,
                      tamaraw_initial16_hostname=None):
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
        if cs_buflo_duration_policy is not None:
            from .resource_study_native import cs_duration_policy
            cs_duration_policy(cs_buflo_duration_policy)
            _cs180_input_declaration(current[-1])
        if tamaraw_initial16_hostname is not None:
            if cs_buflo_duration_policy is not None: raise ValueError("initial16 cannot combine another science amendment")
            _t16_input_declaration(current[-1], tamaraw_initial16_hostname)
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
            if _resource_member_input(cell):
                continue
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
        if cs_buflo_duration_policy is not None:
            context["cs180_condition"]=_cs180_input_declaration(current[-1])
        if tamaraw_initial16_hostname is not None:
            context["tamaraw16_condition"] = _t16_input_declaration(current[-1], tamaraw_initial16_hostname)
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


def _create_admission(parent, cohort_root, declaration_path, declaration_sha256, *, first, budget=False, cover=False, condition=False, tamaraw16=False):
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
        if condition and ("cs180_condition" not in context
                or not _same(context["cs180_condition"],_cs180_input_declaration(records[-1]))):
            raise ValueError("CS180 admission lacks its original actual-parent preparation intent")
        if not condition and "cs180_condition" in context:
            raise ValueError("CS180 initialized root requires explicit condition admission")
        if tamaraw16:
            intent = context.get("tamaraw16_condition")
            if (type(intent) is not dict or not _same(intent, _t16_input_declaration(records[-1], intent.get("hostname")))
                    or first or budget or cover or condition):
                raise ValueError("initial16 needs its exact actual-parent intent and separate condition admission")
        elif "tamaraw16_condition" in context:
            raise ValueError("initial16 initialized root requires explicit condition admission")
        hosts = sorted({row["hostname"] for row in declaration["affected"]})
        modes = sorted({row["mode"] for row in declaration["affected"]})
        if condition and (first or budget or cover):
            raise ValueError("CS180 condition cannot combine another admission authority")
        if cover and (first or budget):
            raise ValueError("cover replacement cannot combine first-mode or budget authority")
        if first and budget: raise ValueError("budget amendment cannot introduce a first mode")
        expected = (_t16_declaration if tamaraw16 else _cs180_declaration if condition else _cover_declaration if cover else _budget_declaration if budget else _first_declaration if first else _declaration)(parent, new, records, hosts, modes)
        (_validate_t16_declaration if tamaraw16 else _validate_cs180_declaration if condition else _validate_cover_declaration if cover else _validate_budget_declaration if budget else _validate_first_declaration if first else _validate_declaration)(declaration, expected)
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
            if condition or tamaraw16:
                science = _science(candidate, records[-1]["class_transition"])
                entry["condition_strata"] = (_t16_strata if tamaraw16 else _cs180_strata)(entry, science, member["cohort_id"])
                entry["science"] = science
            elif budget:
                if "resource_versions" in entry:
                    raise ValueError("a resource version cannot silently acquire a joint budget amendment")
                science = _science(candidate, records[-1]["class_transition"])
                entry["science_strata"] = _budget_strata(entry, science, member["cohort_id"])
                entry["science"] = science
            elif "condition_strata" in entry:
                entry["condition_strata"]["strata"][1]["members"].append(member["cohort_id"])
            elif "resource_versions" in entry:
                entry["resource_versions"]["strata"][-1]["members"].append(member["cohort_id"])
            elif "science_strata" in entry:
                entry["science_strata"]["strata"][1]["members"].append(member["cohort_id"])
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
                 "parent_study_sha256": parent._file("study.json")[1]["sha256"], "change": T16_CHANGE if tamaraw16 else CS180_CHANGE if condition else COVER_CHANGE if cover else "buflo-duration-budget" if budget else "first-mode" if first else "runtime-cohort",
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
    if type(value) is dict and value.get("change") == "unqualified-historical-target-retirement-exact10-v1":
        from .resource_study_semantic_refusals import pending10_validate_record
        return pending10_validate_record(parent, records, value, contract)
    if type(value) is dict and value.get("change") == "scientific-refusal-retirement-CS211-three-v1":
        from .resource_study_semantic_refusals import validate_record
        return validate_record(parent, records, value, contract)
    if type(value) is dict and value.get("change") == "Fonts-all5-aggregate8-to-ordinary5-resource-version-retirement-v2":
        return _v2_validate_resource_record(parent, records, value, contract)
    if type(value) is dict and value.get("change") == "resource-version-retirement":
        return _validate_resource_record(parent, records, value, contract)
    if type(value) is dict and value.get("change") == COVER_CHANGE:
        return _validate_cover_record(parent, records, value, contract)
    if type(value) is dict and value.get("change") == "first-mode":
        return _validate_first_record(parent, records, value, contract)
    condition = type(value) is dict and value.get("change") == CS180_CHANGE
    tamaraw16 = type(value) is dict and value.get("change") == T16_CHANGE
    budget = type(value) is dict and value.get("change") == "buflo-duration-budget"
    fields = {"record_type", "sequence", "previous_sha256", "parent_study_sha256", "change", "affected", "cells",
              "exclusions", "class_transition", "write_fences", "cohorts", "cohort_memberships", "compatibility_declaration"}
    prior = records[-1]
    if (type(value) is not dict or set(value) != fields or value["record_type"] != ADMISSION
            or type(value["sequence"]) is not int or value["sequence"] != len(records)
            or value["previous_sha256"] != e._sha(prior) or value["change"] != (T16_CHANGE if tamaraw16 else CS180_CHANGE if condition else "buflo-duration-budget" if budget else "runtime-cohort")
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
    if condition:
        if affected != {("angkanet26.com", "cs-buflo")}:
            raise ValueError("CS180 cannot change another logical cell")
        _cs180_pair(old_cells[("angkanet26.com", "cs-buflo")], new_cells[("angkanet26.com", "cs-buflo")], value["class_transition"])
        expected = _cs180_declaration_value(parent, prior, declaration["affected"],
            declaration["retained_accepted_manifest_sha256"], contract)
    if budget:
        if any(key[1] != "buflo" for key in affected):
            raise ValueError("budget amendment cannot change another mode")
        expected = _budget_declaration_value(parent, prior, declaration["affected"],
            declaration["retained_accepted_manifest_sha256"], contract)
    if tamaraw16:
        if len(affected) != 1 or next(iter(affected))[1] != "tamaraw":
            raise ValueError("initial16 cannot change another logical cell")
        key = next(iter(affected)); _t16_pair(old_cells[key], new_cells[key], value["class_transition"])
        expected = _t16_declaration_value(parent, prior, declaration["affected"], declaration["retained_accepted_manifest_sha256"], contract)
    (_validate_t16_declaration if tamaraw16 else _validate_cs180_declaration if condition else _validate_budget_declaration if budget else _validate_declaration)(declaration, expected)
    for key, entry in new_entries.items():
        old = old_entries[key]
        if key not in affected:
            if not _same(entry, old) or not _same(new_cells[key], old_cells[key]):
                raise ValueError("runtime cohort changed an unaffected cell")
            continue
        expected_fields = {"hostname", "mode", "science", "members", "writer"}
        if "pending_retirements" in old:
            expected_fields.add("pending_retirements")
            if not _same(entry["pending_retirements"], old["pending_retirements"]):
                raise ValueError("Native-only cohort rewrites immutable unqualified-history retirement")
        if "semantic_refusals" in old:
            expected_fields.add("semantic_refusals")
            if not _same(entry["semantic_refusals"], old["semantic_refusals"]):
                raise ValueError("Native-only cohort rewrites immutable semantic-refusal history")
        if condition or tamaraw16 or "condition_strata" in old: expected_fields.add("condition_strata")
        if budget or "science_strata" in old: expected_fields.add("science_strata")
        if "resource_versions" in old:
            if budget: raise ValueError("resource-version and budget changes need separate explicit authority")
            expected_fields.add("resource_versions")
        if (set(entry) != expected_fields
                or not (budget or condition or tamaraw16) and not _same(entry["science"], old["science"])
                or len(entry["members"]) != len(old["members"])+1):
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
                or not (budget or tamaraw16) and _same(candidate["definition"]["native"], old_cells[key]["definition"]["native"])
                or candidate["definition"]["ready"] is not True):
            raise ValueError("runtime cohort writer/Native/ready identity differs")
        if condition or tamaraw16:
            expected_strata = (_t16_strata if tamaraw16 else _cs180_strata)(old, entry["science"], member["cohort_id"])
            if not _same(entry["condition_strata"], expected_strata):
                raise ValueError("CS180 rewrites historical condition science strata")
        elif "condition_strata" in old:
            expected_strata = deepcopy(old["condition_strata"])
            expected_strata["strata"][1]["members"].append(member["cohort_id"])
            if not _same(entry["condition_strata"], expected_strata):
                raise ValueError("Native-only cohort rewrites CS condition strata")
        if budget:
            expected_strata = _budget_strata(old, entry["science"], member["cohort_id"])
            if not _same(entry["science_strata"], expected_strata):
                raise ValueError("budget amendment rewrites the historical science strata")
        elif "science_strata" in old:
            expected_strata = deepcopy(old["science_strata"])
            expected_strata["strata"][1]["members"].append(member["cohort_id"])
            if not _same(entry["science_strata"], expected_strata):
                raise ValueError("Native-only cohort rewrites budget strata")
        if "resource_versions" in old:
            expected_versions = deepcopy(old["resource_versions"])
            expected_versions["strata"][-1]["members"].append(member["cohort_id"])
            if not _same(entry["resource_versions"], expected_versions):
                raise ValueError("Native-only cohort rewrites the active or historical resource-version membership")
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
        sciences = _stratum_sciences(entry)
        ids = [m["cohort_id"] for m in entry["members"]]
        if len(ids) != len(set(ids)) or _writer(entry)["cell"] != new_cells[(entry["hostname"], entry["mode"])]:
            raise ValueError("runtime cohort member identity repeats or latest writer differs")
        for member in entry["members"]:
            cell = member["cell"]
            reader_compatibility.require_supported(member["verifier"], qualified)
            if (set(member) != {"cohort_id", "cell", "verifier", "frozen_accepted"}
                    or member["cohort_id"] != e._sha(cell)
                    or not _same(_science(cell, value["class_transition"]), sciences[member["cohort_id"]])
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


def counts_snapshot(store, cells, *, latest_only=False):
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
    require_capture_membership(store, parent)
    present = (store.root / MARKER).exists() or (store.root / MARKER).is_symlink()
    if parent is None:
        if present: raise ValueError("runtime cohort marker lacks epoch parent")
        return None
    with e._lock(parent.root), capture_records_scope(parent, writer_root=store.root,
                                                    latest_only=latest_only) as captured_records:
        current = e._records(parent) if captured_records is None else captured_records
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
    _check_resource_receipt(entry, member, receipt)
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
    if "resource_version_input_authority" in enrollment:
        from .resource_study_resource_version_inputs import validate_receipt
        validate_receipt(Path(cell["root"]), enrollment, receipt)


def _check_resource_receipt(entry, member, receipt):
    """Additional active-version identity only; original raw replay stays required."""
    if "resource_versions" not in entry:
        return
    from . import resource_study_resource_versions as versions
    if member["cohort_id"] not in versions.target_member_ids(entry):
        # Original accepted replays remain historical; allocation/counting never
        # includes these members and a new credit still requires the v1 writer.
        return
    ref = entry["resource_versions"]["declaration"]
    raw = _epochs()._read(ref["path"])
    if sha256_file(ref["path"]) != ref["sha256"] or _epochs()._sha(raw) != ref["sha256"]:
        raise ValueError("active resource receipt declaration changed")
    versions.validate_target_receipt_binding(receipt, member["cell"], raw, resource_entry=entry)


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
                        _check_resource_receipt(entry, member, receipt)
                        if replay is not None: replay.submit(store.root, raw, row["five_tuple"])
                        else:
                            facts = verify_by_contract(member, store.root, receipt)
                            if _json(facts["five_tuple"]).decode() != row["five_tuple"]:
                                raise ValueError("runtime cohort raw tuple differs from ledger")
                    refs.append({**_row_ref(str(store.root), row), "cohort_id": member["cohort_id"],
                                 "native": member["cell"]["definition"]["native"], "verifier_sha256": e._sha(member["verifier"])})
                cells.append({"hostname": key[0], "mode": key[1], "accepted": len(rows), "target": 400,
                              "writer_cohort": entry["writer"], "cohort_count": len(entry["members"])})
                if "science_strata" in entry:
                    cells[-1]["budget_science_strata"] = [{"policy": stratum["policy"],
                        "science_sha256": e._sha(stratum["science"]), "cohort_ids": list(stratum["members"]),
                        "accepted": sum(member["cohort_id"] in stratum["members"] for member, _, _ in rows)}
                        for stratum in entry["science_strata"]["strata"]]
                if "resource_versions" in entry:
                    versions = entry["resource_versions"]
                    cells[-1]["resource_version_strata"] = {
                        "policy": versions["policy"], "declaration": deepcopy(versions["declaration"]),
                        "active_workload_sha256": entry["science"]["workload_sha256"],
                        "historically_valid_target_excluded": sum(len(_frozen_value(parent, member)["rows"])
                            for member in entry["members"]
                            if member["cohort_id"] not in versions["strata"][-1]["members"]),
                        "active_target_accepted": len(rows)}
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
                    "scope": "explicit Native and, only where admitted, separately labelled640/1280 budget strata; separate immutable roots; shared logical-cell400 slots",
                    "status_authority": "raw-deep-verified" if deep else "existing-accepted-SQL-index; no fresh raw qualification"}
            if any("resource_version_strata" in cell for cell in cells):
                result["historically_valid_target_excluded"] = sum(
                    cell.get("resource_version_strata", {}).get("historically_valid_target_excluded", 0)
                    for cell in cells)
                result["target_count_policy"] = "only active resource versions count; exact retired receipts remain immutable history and tuple exclusions"

        if not _same(contract, verifier_contract()):
            raise ValueError("raw verifier source changed before all cohort workers joined")
        from .resource_study_semantic_refusals import status_projection, pending10_status_projection
        return pending10_status_projection(current, status_projection(current, result))


RESOURCE_CHANGE = "resource-version-retirement"
RESOURCE_PRIOR = "qcsd-resource-domain-resource-retirement-prior-accepted-v1"


def _resource_material(parent, prior, input_ref, contract, *, accepted_rows=None, replacements=None):
    """Read original member/preparation identities; never import target credit."""
    from . import resource_study_resource_version_inputs as inputs
    from . import resource_study_resource_versions as versions
    e = _epochs()
    if type(input_ref) is not dict or set(input_ref) != {"path", "sha256"}:
        raise ValueError("resource retirement input plan reference differs")
    inputs._path(input_ref["path"]); _digest(input_ref["sha256"])
    if replacements is None:
        # Constructors require the exact original operator operands. An issued
        # admission instead replays the immutable copies in its prepared roots.
        plan, raw, application = inputs.load_input_plan(input_ref["path"], input_ref["sha256"])
        if hashlib.sha256(raw).hexdigest() != input_ref["sha256"]:
            raise ValueError("resource retirement input plan bytes changed")
    else:
        if type(replacements) is not list or len(replacements) != 5:
            raise ValueError("resource retirement local replay needs all five declared replacements")
        for cell in replacements:
            versions._cell(cell)
        host = replacements[0]["hostname"]
        if ([(cell["hostname"], cell["mode"]) for cell in replacements]
                != [(host, mode) for mode in versions.MODE_ORDER]):
            raise ValueError("resource retirement local replay replacement scope differs")
        first = StudyStore(replacements[0]["root"])
        context, _ = inputs.read_context(first.root, first.plan())
        plan, application = context["input"], context["application_manifest_raw"]
        if (context["context"]["input_plan_sha256"] != input_ref["sha256"]
                or plan["hostname"] != host
                or plan["mode_roots"] != [{"mode": cell["mode"], "root": cell["root"]}
                                          for cell in replacements]):
            raise ValueError("resource retirement local plan differs from the issued all5 declaration")
    inputs.validate_input_plan(plan, prior, application)
    candidates = []
    stores = {}
    for scope in plan["mode_roots"]:
        root = scope["root"]; store = stores.setdefault(root, StudyStore(root))
        context, _ = inputs.read_context(store.root, store.plan())
        original = context["original_context"]
        if (context["context"]["input_plan_sha256"] != input_ref["sha256"]
                or not _same(context["input"], plan)
                or not _same(original["predecessor"], prior)
                or original["predecessor_sha256"] != e._sha(prior)
                or original["parent"] != {"root": str(parent.root),
                                          "study_sha256": parent._file("study.json")[1]["sha256"]}):
            raise ValueError("resource retirement preparation uses a stale/foreign original parent or input plan")
        candidates.append(e._cell(store, plan["hostname"], scope["mode"]))
    if replacements is not None and not _same(candidates, replacements):
        raise ValueError("resource retirement local members differ from the issued replacements")
    rows = _manifest(prior["cohorts"]) if accepted_rows is None else accepted_rows
    expected = versions.replacement_template(prior, rows, candidates, application,
        hostname=plan["hostname"], verifier=contract, missing_mode_templates=plan["mode_templates"],
        preparation_policy=plan.get("preparation_policy"))
    return plan, application, candidates, rows, stores, expected


def resource_template(parent, input_path, input_sha256):
    """Prospective all5 template; actual preparation/publication remain separate."""
    e = _epochs(); parent = StudyStore(Path(parent).absolute())
    input_ref = {"path": str(Path(input_path).absolute()), "sha256": _digest(input_sha256)}
    with e._lock(parent.root):
        current = e._records(parent)
        if not current or current[-1]["record_type"] != ADMISSION:
            raise ValueError("resource retirement requires the actual current cohort head")
        value = _resource_material(parent, current[-1], input_ref, verifier_contract())[-1]
        return {**value, "resource_version_input": input_ref}


def _resource_exclusions(prior, declaration):
    """Original exclusion schema, extended across every retired cohort member."""
    e = _epochs(); result = []
    rows = declaration["retirement"]["rows"]
    for entry in sorted(prior["cohorts"], key=lambda item: (item["hostname"], item["mode"])):
        if entry["hostname"] != declaration["hostname"]:
            continue
        for member in entry["members"]:
            cell = member["cell"]
            selected = [row for row in rows if row["root"] == cell["root"] and row["mode"] == cell["mode"]]
            if not selected:
                continue
            value = {"cell": [cell["hostname"], cell["mode"]], "root": cell["root"],
                     "study_sha256": cell["study_sha256"], "enrollment_sha256": cell["enrollment_sha256"],
                     "receipts": [{"five_tuple": _tuple(_load(row["five_tuple"])),
                         "receipt_path": row["receipt_path"], "receipt_sha256": row["receipt_sha256"],
                         "attempt_id": row["attempt_id"]} for row in selected], "scientific_credit": False}
            relative = "epoch-ancestry/" + e._sha(value) + ".json"
            ref = {"cell": value["cell"], "path": relative, "sha256": e._sha(value)}
            if ref not in prior["exclusions"]:
                result.append((ref, value))
    return result


def _freeze_resource_writer(parent, entry):
    """Freeze only the current old writer; previous immutable members stay whole."""
    e = _epochs(); previous = _writer(entry)
    root = previous["cell"]["root"]
    frozen = {"record_type": SNAPSHOT, "cohort_id": previous["cohort_id"],
              "rows": [_row_ref(root, row) for row in _rows(StudyStore(root), (entry["hostname"], entry["mode"]))],
              "authority": "existing-accepted-SQL-rows; no new raw qualification"}
    relative = "runtime-cohorts/" + e._sha(frozen) + ".json"
    path = parent.root / relative
    if path.exists():
        if not _same(e._read(path), frozen): raise ValueError("resource retirement frozen writer manifest differs")
    else:
        _create(path, canonical_json(frozen))
    previous["frozen_accepted"] = {"path": relative, "sha256": e._sha(frozen)}


def _resource_entry(before, candidate, declaration_ref, contract, transition):
    from . import resource_study_resource_versions as versions
    member = _member(candidate, contract); science = _science(candidate, transition)
    strata = []; members = []
    if before is not None:
        if "resource_versions" in before or "science_strata" in before:
            raise ValueError("resource retirement cannot silently repeat a version or combine a budget change")
        members = deepcopy(before["members"])
        strata.append({"version": 0, "science": deepcopy(before["science"]),
                       "members": [old["cohort_id"] for old in members], "target_eligible": False})
    members.append(member)
    strata.append({"version": 1, "science": science, "members": [member["cohort_id"]], "target_eligible": True})
    value = {"hostname": candidate["hostname"], "mode": candidate["mode"], "science": science,
             "members": members, "writer": member["cohort_id"],
             "resource_versions": {"record_type": versions.STRATA, "schema_version": 1, "policy": versions.POLICY,
                                   "declaration": deepcopy(declaration_ref), "strata": strata}}
    versions.member_sciences(value)
    return value


def _v1_create_resource_version(parent, declaration_path, declaration_sha256):
    """Atomic same-host all5 target retirement under the original ownership gates."""
    from . import resource_study_resource_version_inputs as inputs
    from . import resource_study_resource_versions as versions
    from .resource_study_lineage import prepare_fences, publication_scope, no_retired_history
    e = _epochs(); parent = StudyStore(Path(parent).absolute())
    path = e._regular(Path(declaration_path).absolute()); declaration = e._read(path)
    if sha256_file(path) != declaration_sha256 or e._sha(declaration) != declaration_sha256:
        raise ValueError("resource retirement declaration requires exact canonical immutable bytes")
    input_ref = declaration.get("resource_version_input")
    if type(input_ref) is not dict or set(input_ref) != {"path", "sha256"}:
        raise ValueError("resource retirement declaration lacks its exact prepared input plan")
    core = {name: value for name, value in declaration.items() if name != "resource_version_input"}
    with e.docker_lock(), e._lock(parent.root):
        records = e._records(parent); prior = records[-1]; contract = verifier_contract()
        plan, application, candidates, rows, stores, _ = _resource_material(parent, prior, input_ref, contract)
        versions.validate_declaration(core, prior, rows, candidates, application,
            hostname=plan["hostname"], verifier=contract, missing_mode_templates=plan["mode_templates"])
        previous_roots = {cell["root"] for record in records for cell in record["cells"]}
        if set(stores) & previous_roots:
            raise ValueError("resource retirement requires genuinely new independent roots")
        e._idle([StudyStore(root) for root in sorted(previous_roots | set(stores))])
        for store in stores.values():
            inputs.require_current_context(store, parent, prior, input_ref)
            no_retired_history(store)
            if (store.root / MARKER).exists() or (store.root / MARKER).is_symlink():
                raise ValueError("resource version has an existing membership marker")
            with store._transaction() as connection:
                if connection.execute("SELECT 1 FROM attempts").fetchone() or connection.execute("SELECT 1 FROM accepted").fetchone():
                    raise ValueError("resource retirement cannot import prior attempts, pilots or accepted rows")
            e._verify_preparation(store, plan["hostname"])
        declaration_ref = {"path": str(path), "sha256": declaration_sha256}
        registry = deepcopy(prior["cohorts"]); entries = {e._key(entry): entry for entry in registry}
        cells = {e._key(cell): deepcopy(cell) for cell in prior["cells"]}
        for candidate in candidates:
            key = e._key(candidate); before = entries.get(key)
            if before is not None: _freeze_resource_writer(parent, before)
            replacement = _resource_entry(before, candidate, declaration_ref, contract, prior["class_transition"])
            if before is None: registry.append(replacement)
            else: registry[registry.index(before)] = replacement
            entries[key] = replacement; cells[key] = candidate
        exclusions = deepcopy(prior["exclusions"])
        for exclusion_ref, value in _resource_exclusions(prior, core):
            destination = parent.root / exclusion_ref["path"]
            if destination.exists():
                if not _same(e._read(destination), value): raise ValueError("resource retirement exclusion bytes differ")
            else: _create(destination, canonical_json(value))
            exclusions.append(exclusion_ref)
        snapshot = {"record_type": RESOURCE_PRIOR, "predecessor_admission_sha256": e._sha(prior), "rows": rows}
        snapshot_relative = "resource-versions/" + e._sha(snapshot) + ".json"
        _create(parent.root / snapshot_relative, canonical_json(snapshot))
        retired = core["retirement"]; retired_relative = "resource-versions/" + e._sha(retired) + ".json"
        _create(parent.root / retired_relative, canonical_json(retired))
        for store in stores.values(): e._bind(store, parent)
        fences = prepare_fences(parent, records, cells, prior["class_transition"])
        markers = dict(prior.get("cohort_memberships", {}))
        for root in sorted(stores):
            store = stores[root]; marker = _marker(store, parent)
            _create(store.root / MARKER, canonical_json(marker)); markers[root] = e._sha(marker)
        value = {"record_type": ADMISSION, "sequence": len(records), "previous_sha256": e._sha(prior),
            "parent_study_sha256": parent._file("study.json")[1]["sha256"], "change": RESOURCE_CHANGE,
            "affected": [[plan["hostname"], mode] for mode in versions.MODE_ORDER],
            "cells": [cells[key] for key in sorted(cells)], "exclusions": exclusions,
            "class_transition": deepcopy(prior["class_transition"]), "write_fences": fences,
            "cohorts": sorted(registry, key=lambda entry: (entry["hostname"], entry["mode"])),
            "cohort_memberships": markers, "compatibility_declaration": declaration_ref,
            "resource_version_input": input_ref,
            "prior_accepted_snapshot": {"path": snapshot_relative, "sha256": e._sha(snapshot)},
            "resource_retirement": {"path": retired_relative, "sha256": e._sha(retired)}}
        _validate_record(parent, records, value, contract=contract)
        e._idle([StudyStore(root) for root in sorted(previous_roots | set(stores))])
        if sha256_file(path) != declaration_sha256 or not _same(contract, verifier_contract()):
            raise ValueError("resource retirement source or declaration changed before publication")
        _create(parent.root / "epoch-admissions" / f"{len(records):06d}.json", canonical_json(value))
        with publication_scope(parent, records, value), parent._transaction() as connection:
            old = canonical_json({"sequence": len(records)-1, "sha256": e._sha(prior)}).decode()
            actual = connection.execute("SELECT value FROM meta WHERE key='epoch_head'").fetchone()
            if actual is None or actual[0] != old: raise ValueError("resource retirement current parent changed")
            connection.execute("UPDATE meta SET value=? WHERE key='epoch_head'",
                (canonical_json({"sequence": len(records), "sha256": e._sha(value)}).decode(),))
        return value


def _validate_resource_record(parent, records, value, contract):
    from . import resource_study_resource_versions as versions
    e = _epochs(); prior = records[-1]
    fields = {"record_type", "sequence", "previous_sha256", "parent_study_sha256", "change", "affected", "cells",
              "exclusions", "class_transition", "write_fences", "cohorts", "cohort_memberships", "compatibility_declaration",
              "resource_version_input", "prior_accepted_snapshot", "resource_retirement"}
    if (type(value) is not dict or set(value) != fields or value["record_type"] != ADMISSION
            or value["change"] != RESOURCE_CHANGE or type(value["sequence"]) is not int or value["sequence"] != len(records)
            or value["previous_sha256"] != e._sha(prior)
            or value["parent_study_sha256"] != parent._file("study.json")[1]["sha256"]
            or value["parent_study_sha256"] != prior["parent_study_sha256"]
            or not _same(value["class_transition"], prior["class_transition"])):
        raise ValueError("resource retirement parent/class-lineage envelope differs")
    ref = value["compatibility_declaration"]; declaration = e._read(ref["path"])
    if sha256_file(ref["path"]) != ref["sha256"] or e._sha(declaration) != ref["sha256"]:
        raise ValueError("resource retirement exact declaration bytes differ")
    if declaration.get("resource_version_input") != value["resource_version_input"]:
        raise ValueError("resource retirement input plan reference differs")
    core = {name: item for name, item in declaration.items() if name != "resource_version_input"}
    snapshot_ref = value["prior_accepted_snapshot"]
    if set(snapshot_ref) != {"path", "sha256"} or not snapshot_ref["path"].startswith("resource-versions/"):
        raise ValueError("resource retirement prior accepted manifest reference differs")
    snapshot = e._read(parent._relative(snapshot_ref["path"]))
    if (set(snapshot) != {"record_type", "predecessor_admission_sha256", "rows"}
            or snapshot["record_type"] != RESOURCE_PRIOR or snapshot["predecessor_admission_sha256"] != e._sha(prior)
            or e._sha(snapshot) != snapshot_ref["sha256"]
            or sha256_file(parent._relative(snapshot_ref["path"])) != snapshot_ref["sha256"]):
        raise ValueError("resource retirement prior accepted snapshot changed")
    affected = core.get("affected")
    if type(affected) is not list or any(type(row) is not dict or "replacement" not in row for row in affected):
        raise ValueError("resource retirement declared replacement inventory differs")
    plan, application, candidates, rows, _, _ = _resource_material(parent, prior, value["resource_version_input"],
        contract, accepted_rows=snapshot["rows"], replacements=[row["replacement"] for row in affected])
    versions.validate_declaration(core, prior, rows, candidates, application,
        hostname=plan["hostname"], verifier=contract, missing_mode_templates=plan["mode_templates"])
    retired_ref = value["resource_retirement"]
    if set(retired_ref) != {"path", "sha256"} or not retired_ref["path"].startswith("resource-versions/"):
        raise ValueError("resource retirement historical manifest reference differs")
    retired = e._read(parent._relative(retired_ref["path"]))
    if (e._sha(retired) != retired_ref["sha256"]
            or sha256_file(parent._relative(retired_ref["path"])) != retired_ref["sha256"]
            or not _same(retired, core["retirement"])):
        raise ValueError("resource retirement must preserve the exact target-excluded valid historical rows")
    added_exclusions = _resource_exclusions(prior, core)
    for exclusion_ref, expected in added_exclusions:
        actual = e._read(parent._relative(exclusion_ref["path"]))
        if not _same(actual, expected) or e._sha(actual) != exclusion_ref["sha256"]:
            raise ValueError("resource retirement ancestor tuple exclusion differs")
    if value["exclusions"] != [*prior["exclusions"], *[ref for ref, _ in added_exclusions]]:
        raise ValueError("resource retirement loses old exclusions or adds undeclared tuples")
    selected = {(plan["hostname"], mode) for mode in MODES}
    old_entries = {e._key(entry): entry for entry in prior["cohorts"]}
    entries = {e._key(entry): entry for entry in value["cohorts"]}
    old_cells = {e._key(cell): cell for cell in prior["cells"]}; cells = {e._key(cell): cell for cell in value["cells"]}
    if (len(entries) != len(value["cohorts"]) or set(entries) != set(old_entries) | selected
            or len(cells) != len(value["cells"]) or set(cells) != set(old_cells) | selected
            or value["affected"] != [list(key) for key in sorted(selected)]):
        raise ValueError("resource retirement must change exactly one hostname and all five modes")
    candidate_map = {e._key(cell): cell for cell in candidates}
    previous_roots = {cell["root"] for record in records for cell in record["cells"]}
    if any(cell["root"] in previous_roots for cell in candidates):
        raise ValueError("resource retirement reuses an old ledger root")
    for key, entry in entries.items():
        if key not in selected:
            if not _same(entry, old_entries[key]) or not _same(cells[key], old_cells[key]):
                raise ValueError("resource retirement changes one of the unaffected49 classes")
            continue
        before = deepcopy(old_entries.get(key))
        if before is not None:
            old_writer = _writer(before)
            actual_old = next((member for member in entry["members"]
                               if member["cohort_id"] == old_writer["cohort_id"]), None)
            if actual_old is None or actual_old["frozen_accepted"] is None:
                raise ValueError("resource retirement fails to freeze the old writer")
            old_writer["frozen_accepted"] = deepcopy(actual_old["frozen_accepted"])
            frozen = _frozen_value(parent, actual_old)
            expected_rows = [row for row in rows if row["root"] == old_writer["cell"]["root"]
                             and (row["hostname"], row["mode"]) == key]
            if not _same(frozen["rows"], expected_rows):
                raise ValueError("resource retirement old writer receipt set differs from actual prior inventory")
        expected = _resource_entry(before, candidate_map[key], ref, contract, prior["class_transition"])
        if not _same(entry, expected) or not _same(cells[key], candidate_map[key]):
            raise ValueError("resource retirement rewrites old members or invents new source/science/credit carry")
    _validate_members(parent, value, cells, contract)


def semantic_refusal_template(parent, cohort_root, *, evidence_path, evidence_sha256, parent_transfer_path, parent_transfer_sha256, rationale):
    from .resource_study_semantic_refusals import template
    return template(parent, cohort_root, evidence_path=evidence_path, evidence_sha256=evidence_sha256,
        parent_transfer_path=parent_transfer_path, parent_transfer_sha256=parent_transfer_sha256, rationale=rationale)


def create_semantic_refusal(parent, cohort_root, declaration_path, declaration_sha256):
    from .resource_study_semantic_refusals import create
    return create(parent, cohort_root, declaration_path, declaration_sha256)


def pending10_retirement_template(parent, cohort_root, *, evidence_path, evidence_sha256, parent_transfer_path, parent_transfer_sha256, rationale):
    """Exact D-only methodological retirement; no trace-invalidity or credit claim."""
    from .resource_study_semantic_refusals import pending10_template
    return pending10_template(parent, cohort_root, evidence_path=evidence_path, evidence_sha256=evidence_sha256,
        parent_transfer_path=parent_transfer_path, parent_transfer_sha256=parent_transfer_sha256, rationale=rationale)


def create_pending10_retirement(parent, cohort_root, declaration_path, declaration_sha256):
    from .resource_study_semantic_refusals import pending10_create
    return pending10_create(parent, cohort_root, declaration_path, declaration_sha256)


RESOURCE_CHANGE_V2 = "Fonts-all5-aggregate8-to-ordinary5-resource-version-retirement-v2"


def _v2_resource_entry(before, candidate, declaration_ref, contract, transition, preparation_policy):
    from . import resource_study_resource_versions as versions
    member = _member(candidate, contract); science = _science(candidate, transition)
    strata = []; members = []
    if before is not None:
        if "resource_versions" in before or "science_strata" in before:
            raise ValueError("resource retirement cannot silently repeat a version or combine a budget change")
        members = deepcopy(before["members"])
        strata.append({"version": 0, "science": deepcopy(before["science"]),
                       "members": [old["cohort_id"] for old in members], "target_eligible": False})
    members.append(member)
    strata.append({"version": 1, "science": science, "members": [member["cohort_id"]], "target_eligible": True})
    value = {"hostname": candidate["hostname"], "mode": candidate["mode"], "science": science,
             "members": members, "writer": member["cohort_id"],
             "resource_versions": {"record_type": versions.STRATA_V2, "schema_version": 2, "policy": versions.POLICY_V2,
                                   "preparation_policy": deepcopy(preparation_policy),
                                   "declaration": deepcopy(declaration_ref), "strata": strata}}
    versions.member_sciences(value)
    return value

def _v2_create_resource_version(parent, declaration_path, declaration_sha256):
    """Atomic same-host all5 target retirement under the original ownership gates."""
    from . import resource_study_resource_version_inputs as inputs
    from . import resource_study_resource_versions as versions
    from .resource_study_lineage import prepare_fences, publication_scope, no_retired_history
    e = _epochs(); parent = StudyStore(Path(parent).absolute())
    path = e._regular(Path(declaration_path).absolute()); declaration = e._read(path)
    if sha256_file(path) != declaration_sha256 or e._sha(declaration) != declaration_sha256:
        raise ValueError("resource retirement declaration requires exact canonical immutable bytes")
    input_ref = declaration.get("resource_version_input")
    if type(input_ref) is not dict or set(input_ref) != {"path", "sha256"}:
        raise ValueError("resource retirement declaration lacks its exact prepared input plan")
    core = {name: value for name, value in declaration.items() if name != "resource_version_input"}
    with e.docker_lock(), e._lock(parent.root):
        records = e._records(parent); prior = records[-1]; contract = verifier_contract()
        plan, application, candidates, rows, stores, _ = _resource_material(parent, prior, input_ref, contract)
        versions.validate_declaration(core, prior, rows, candidates, application,
            hostname=plan["hostname"], verifier=contract, missing_mode_templates=plan["mode_templates"],
            preparation_policy=plan["preparation_policy"])
        previous_roots = {cell["root"] for record in records for cell in record["cells"]}
        if set(stores) & previous_roots:
            raise ValueError("resource retirement requires genuinely new independent roots")
        e._idle([StudyStore(root) for root in sorted(previous_roots | set(stores))])
        for store in stores.values():
            inputs.require_current_context(store, parent, prior, input_ref)
            no_retired_history(store)
            if (store.root / MARKER).exists() or (store.root / MARKER).is_symlink():
                raise ValueError("resource version has an existing membership marker")
            with store._transaction() as connection:
                if connection.execute("SELECT 1 FROM attempts").fetchone() or connection.execute("SELECT 1 FROM accepted").fetchone():
                    raise ValueError("resource retirement cannot import prior attempts, pilots or accepted rows")
            e._verify_preparation(store, plan["hostname"])
        declaration_ref = {"path": str(path), "sha256": declaration_sha256}
        registry = deepcopy(prior["cohorts"]); entries = {e._key(entry): entry for entry in registry}
        cells = {e._key(cell): deepcopy(cell) for cell in prior["cells"]}
        for candidate in candidates:
            key = e._key(candidate); before = entries.get(key)
            if before is not None: _freeze_resource_writer(parent, before)
            replacement = _v2_resource_entry(before, candidate, declaration_ref, contract, prior["class_transition"],
                plan["preparation_policy"])
            if before is None: registry.append(replacement)
            else: registry[registry.index(before)] = replacement
            entries[key] = replacement; cells[key] = candidate
        exclusions = deepcopy(prior["exclusions"])
        for exclusion_ref, value in _resource_exclusions(prior, core):
            destination = parent.root / exclusion_ref["path"]
            if destination.exists():
                if not _same(e._read(destination), value): raise ValueError("resource retirement exclusion bytes differ")
            else: _create(destination, canonical_json(value))
            exclusions.append(exclusion_ref)
        snapshot = {"record_type": RESOURCE_PRIOR, "predecessor_admission_sha256": e._sha(prior), "rows": rows}
        snapshot_relative = "resource-versions/" + e._sha(snapshot) + ".json"
        _create(parent.root / snapshot_relative, canonical_json(snapshot))
        retired = core["retirement"]; retired_relative = "resource-versions/" + e._sha(retired) + ".json"
        _create(parent.root / retired_relative, canonical_json(retired))
        for store in stores.values(): e._bind(store, parent)
        fences = prepare_fences(parent, records, cells, prior["class_transition"])
        markers = dict(prior.get("cohort_memberships", {}))
        for root in sorted(stores):
            store = stores[root]; marker = _marker(store, parent)
            _create(store.root / MARKER, canonical_json(marker)); markers[root] = e._sha(marker)
        value = {"record_type": ADMISSION, "sequence": len(records), "previous_sha256": e._sha(prior),
            "parent_study_sha256": parent._file("study.json")[1]["sha256"], "change": RESOURCE_CHANGE_V2,
            "affected": [[plan["hostname"], mode] for mode in versions.MODE_ORDER],
            "cells": [cells[key] for key in sorted(cells)], "exclusions": exclusions,
            "class_transition": deepcopy(prior["class_transition"]), "write_fences": fences,
            "cohorts": sorted(registry, key=lambda entry: (entry["hostname"], entry["mode"])),
            "cohort_memberships": markers, "compatibility_declaration": declaration_ref,
            "resource_version_input": input_ref,
            "prior_accepted_snapshot": {"path": snapshot_relative, "sha256": e._sha(snapshot)},
            "resource_retirement": {"path": retired_relative, "sha256": e._sha(retired)}}
        _validate_record(parent, records, value, contract=contract)
        e._idle([StudyStore(root) for root in sorted(previous_roots | set(stores))])
        if sha256_file(path) != declaration_sha256 or not _same(contract, verifier_contract()):
            raise ValueError("resource retirement source or declaration changed before publication")
        _create(parent.root / "epoch-admissions" / f"{len(records):06d}.json", canonical_json(value))
        with publication_scope(parent, records, value), parent._transaction() as connection:
            old = canonical_json({"sequence": len(records)-1, "sha256": e._sha(prior)}).decode()
            actual = connection.execute("SELECT value FROM meta WHERE key='epoch_head'").fetchone()
            if actual is None or actual[0] != old: raise ValueError("resource retirement current parent changed")
            connection.execute("UPDATE meta SET value=? WHERE key='epoch_head'",
                (canonical_json({"sequence": len(records), "sha256": e._sha(value)}).decode(),))
        return value

def _v2_validate_resource_record(parent, records, value, contract):
    from . import resource_study_resource_versions as versions
    e = _epochs(); prior = records[-1]
    fields = {"record_type", "sequence", "previous_sha256", "parent_study_sha256", "change", "affected", "cells",
              "exclusions", "class_transition", "write_fences", "cohorts", "cohort_memberships", "compatibility_declaration",
              "resource_version_input", "prior_accepted_snapshot", "resource_retirement"}
    if (type(value) is not dict or set(value) != fields or value["record_type"] != ADMISSION
            or value["change"] != RESOURCE_CHANGE_V2 or type(value["sequence"]) is not int or value["sequence"] != len(records)
            or value["previous_sha256"] != e._sha(prior)
            or value["parent_study_sha256"] != parent._file("study.json")[1]["sha256"]
            or value["parent_study_sha256"] != prior["parent_study_sha256"]
            or not _same(value["class_transition"], prior["class_transition"])):
        raise ValueError("resource retirement parent/class-lineage envelope differs")
    ref = value["compatibility_declaration"]; declaration = e._read(ref["path"])
    if sha256_file(ref["path"]) != ref["sha256"] or e._sha(declaration) != ref["sha256"]:
        raise ValueError("resource retirement exact declaration bytes differ")
    if declaration.get("resource_version_input") != value["resource_version_input"]:
        raise ValueError("resource retirement input plan reference differs")
    core = {name: item for name, item in declaration.items() if name != "resource_version_input"}
    snapshot_ref = value["prior_accepted_snapshot"]
    if set(snapshot_ref) != {"path", "sha256"} or not snapshot_ref["path"].startswith("resource-versions/"):
        raise ValueError("resource retirement prior accepted manifest reference differs")
    snapshot = e._read(parent._relative(snapshot_ref["path"]))
    if (set(snapshot) != {"record_type", "predecessor_admission_sha256", "rows"}
            or snapshot["record_type"] != RESOURCE_PRIOR or snapshot["predecessor_admission_sha256"] != e._sha(prior)
            or e._sha(snapshot) != snapshot_ref["sha256"]
            or sha256_file(parent._relative(snapshot_ref["path"])) != snapshot_ref["sha256"]):
        raise ValueError("resource retirement prior accepted snapshot changed")
    affected = core.get("affected")
    if type(affected) is not list or any(type(row) is not dict or "replacement" not in row for row in affected):
        raise ValueError("resource retirement declared replacement inventory differs")
    plan, application, candidates, rows, _, _ = _resource_material(parent, prior, value["resource_version_input"],
        contract, accepted_rows=snapshot["rows"], replacements=[row["replacement"] for row in affected])
    versions.validate_declaration(core, prior, rows, candidates, application,
        hostname=plan["hostname"], verifier=contract, missing_mode_templates=plan["mode_templates"],
            preparation_policy=plan["preparation_policy"])
    retired_ref = value["resource_retirement"]
    if set(retired_ref) != {"path", "sha256"} or not retired_ref["path"].startswith("resource-versions/"):
        raise ValueError("resource retirement historical manifest reference differs")
    retired = e._read(parent._relative(retired_ref["path"]))
    if (e._sha(retired) != retired_ref["sha256"]
            or sha256_file(parent._relative(retired_ref["path"])) != retired_ref["sha256"]
            or not _same(retired, core["retirement"])):
        raise ValueError("resource retirement must preserve the exact target-excluded valid historical rows")
    added_exclusions = _resource_exclusions(prior, core)
    for exclusion_ref, expected in added_exclusions:
        actual = e._read(parent._relative(exclusion_ref["path"]))
        if not _same(actual, expected) or e._sha(actual) != exclusion_ref["sha256"]:
            raise ValueError("resource retirement ancestor tuple exclusion differs")
    if value["exclusions"] != [*prior["exclusions"], *[ref for ref, _ in added_exclusions]]:
        raise ValueError("resource retirement loses old exclusions or adds undeclared tuples")
    selected = {(plan["hostname"], mode) for mode in MODES}
    old_entries = {e._key(entry): entry for entry in prior["cohorts"]}
    entries = {e._key(entry): entry for entry in value["cohorts"]}
    old_cells = {e._key(cell): cell for cell in prior["cells"]}; cells = {e._key(cell): cell for cell in value["cells"]}
    if (len(entries) != len(value["cohorts"]) or set(entries) != set(old_entries) | selected
            or len(cells) != len(value["cells"]) or set(cells) != set(old_cells) | selected
            or value["affected"] != [list(key) for key in sorted(selected)]):
        raise ValueError("resource retirement must change exactly one hostname and all five modes")
    candidate_map = {e._key(cell): cell for cell in candidates}
    previous_roots = {cell["root"] for record in records for cell in record["cells"]}
    if any(cell["root"] in previous_roots for cell in candidates):
        raise ValueError("resource retirement reuses an old ledger root")
    for key, entry in entries.items():
        if key not in selected:
            if not _same(entry, old_entries[key]) or not _same(cells[key], old_cells[key]):
                raise ValueError("resource retirement changes one of the unaffected49 classes")
            continue
        before = deepcopy(old_entries.get(key))
        if before is not None:
            old_writer = _writer(before)
            actual_old = next((member for member in entry["members"]
                               if member["cohort_id"] == old_writer["cohort_id"]), None)
            if actual_old is None or actual_old["frozen_accepted"] is None:
                raise ValueError("resource retirement fails to freeze the old writer")
            old_writer["frozen_accepted"] = deepcopy(actual_old["frozen_accepted"])
            frozen = _frozen_value(parent, actual_old)
            expected_rows = [row for row in rows if row["root"] == old_writer["cell"]["root"]
                             and (row["hostname"], row["mode"]) == key]
            if not _same(frozen["rows"], expected_rows):
                raise ValueError("resource retirement old writer receipt set differs from actual prior inventory")
        expected = _v2_resource_entry(before, candidate_map[key], ref, contract, prior["class_transition"],
            plan["preparation_policy"])
        if not _same(entry, expected) or not _same(cells[key], candidate_map[key]):
            raise ValueError("resource retirement rewrites old members or invents new source/science/credit carry")
    _validate_members(parent, value, cells, contract)

def create_resource_version(parent, declaration_path, declaration_sha256):
    # Declaration dispatch precedes the unchanged original ownership gates.
    from . import resource_study_resource_versions as versions
    e = _epochs(); path = e._regular(Path(declaration_path).absolute())
    value = e._read(path)
    if type(value) is dict and value.get("record_type") == versions.DECLARATION_V2:
        return _v2_create_resource_version(parent, declaration_path, declaration_sha256)
    return _v1_create_resource_version(parent, declaration_path, declaration_sha256)
