# Source055 candidate controls: all Source048 behavioral fixtures/oracles are
# byte whole; only the dated/current profile test below is updated and extended.
"""Disposable Linux authority controls; no traffic or qualification claims.

Real original V3/cohort/SQLite fixtures and actual kernel flock are used. The
existing fixture's preparation/raw leaves remain explicitly synthetic. The
backend below always refuses capture: its real reservation/state callbacks
exercise the coordinator without granting any scientific credit. No successful
authority, SQL fence, or raw validator is replaced by these controls.
"""
from contextlib import contextmanager
from collections import Counter
from contextvars import copy_context
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_runtime as runtime
from qcsd_lab.resource_study_inputs import canonical_json
from qcsd_lab.resource_study_store import StudyStore, _create
from tests.test_resource_study_lineage import campaign
from tests.test_resource_study_runtime_cohorts import cohort_campaign, HOST, MODE


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="genuine Linux fdinfo/flock authority")


@pytest.fixture(autouse=True)
def lock_home(tmp_path, monkeypatch):
    # Relocate only the lock pathname. The real docker_lock/flock/fdinfo bodies
    # run; neither kernel ownership nor a successful guard is mocked.
    home = tmp_path / "lock-home"
    home.mkdir(mode=0o700)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return home


@contextmanager
def scoped(store):
    with runtime.docker_lock() as owner:
        with cohorts.capture_authority_scope(store.root, owner) as auth:
            assert auth is not None
            yield auth, owner


def attack_sql(store, sql, parameters=()):
    """Out-of-band adversarial write; never used to obtain valid authority.

    The attack connection supplies its own trigger function, as an unrelated
    program can. The original production connection and fence stay unchanged.
    """
    with sqlite3.connect(store.database) as connection:
        connection.create_function(lineage.FENCE_FUNCTION, 5, lambda *args: 1)
        connection.execute(sql, parameters)


class RefusingBackend:
    def __init__(self, store):
        self.root = store.root
        self.full_reads = 0
        self.steps = []

    def __enter__(self):
        self.lock = runtime.docker_lock()
        self.owner = self.lock.__enter__()
        self.steps.append("docker-held")
        self.previous_profile = sys.getprofile()
        self.previous_thread_profile = threading.getprofile()
        code = epochs._legacy_records.__code__

        def profile(frame, event, argument):
            if event == "call" and frame.f_code is code:
                self.full_reads += 1

        sys.setprofile(profile)
        threading.setprofile(profile)
        return self

    @contextmanager
    def capture_authority_scope(self):
        assert self.steps[-1] == "docker-held"
        with cohorts.capture_authority_scope(self.root, self.owner) as auth:
            self._capture_authority = auth
            self.steps.append("authority-entered")
            try:
                yield auth
            finally:
                assert self.steps[-1] == "kernel-teardown-restored"
                del self._capture_authority
        self.steps.append("authority-closed")

    @contextmanager
    def coordinator_affinity_scope(self):
        self.steps.append("affinity-entered")
        try:
            yield None
        finally:
            self.steps.append("kernel-teardown-restored")

    def capture(self, worker, attempt, enrollment):
        return {"success": False, "failure": "explicit unit backend refusal"}

    def release(self, worker):
        pass

    def __exit__(self, *errors):
        self.steps.append("docker-unlock")
        sys.setprofile(self.previous_profile)
        threading.setprofile(self.previous_thread_profile)
        self.lock.__exit__(*errors)


def test_real_capture_callbacks_replay_full_history_only_at_flight_ends(cohort_campaign, lock_home, monkeypatch):
    """Original RED reaches the count assertion, not a new missing API.

    Original _capture_executor ignores the backend's new optional scope, so
    original reservation/mark/fail callbacks execute normally and replay the
    full validator. Candidate entry/exit must replace those repeated replays.
    """
    c = cohort_campaign
    backend = RefusingBackend(c.old)
    monkeypatch.setattr(study, "require_storage", lambda *a, **k: {})
    monkeypatch.setattr(study, "storage_snapshot", lambda *a, **k: {})
    report = study.capture(c.old.root, epochs._enrollments(c.old)[HOST][0]["runtime"],
        workers=2, budget=3, modes=("front", "tamaraw", "cs-buflo"),
        hostnames=[HOST], backend=backend, chunk_sessions=1, pilot=True)
    assert report["progress"]["attempts"]["failed"] == 3
    assert report["progress"]["accepted_count"] == 1
    assert len(report["paused_cells"]) == 3
    assert backend.full_reads == 1, "capture callbacks must retain one full entry validation and sealed closure checks"
    assert backend.steps[-3:] == ["kernel-teardown-restored", "authority-closed", "docker-unlock"]


def test_original_noncapture_records_replays_remain_full(cohort_campaign):
    c = cohort_campaign
    expected = epochs._records(c.parent)
    assert epochs._records(c.parent) == expected
    assert cohorts.records(c.parent) == expected


def test_callback_copies_are_isolated_and_arbitrary_records_stays_full(cohort_campaign, lock_home):
    c = cohort_campaign
    with scoped(c.old):
        expected = epochs._records(c.parent)
        with cohorts.capture_records_scope(c.parent, writer_root=c.old.root) as first:
            assert first == expected
            first[0]["cells"].clear()
        with cohorts.capture_records_scope(c.parent, writer_root=c.old.root) as second:
            assert second == expected
        assert epochs._records(c.parent) == expected
        assert cohorts.records(c.parent) == expected


@pytest.mark.parametrize("relative", ["epoch-admissions/000000.json", "study.json", "class-write-fence.json"])
def test_full_bytes_and_identity_are_checked_at_next_callback(cohort_campaign, lock_home, relative):
    c = cohort_campaign
    with pytest.raises((ValueError, OSError)):
        with scoped(c.old):
            path = c.parent.root / relative
            before = path.stat()
            raw = path.read_bytes()
            path.chmod(0o644)
            path.write_bytes(raw + b"\n")
            path.chmod(0o444)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            with pytest.raises((ValueError, OSError)):
                c.old.allocate_attempt(HOST, MODE, purpose="pilot")


@pytest.mark.parametrize("change", ["head", "next-file", "retired-path", "root", "database", "lock-path", "epoch-lock", "unlock"])
def test_exact_authority_and_kernel_ownership_changes_refuse_before_reservation(cohort_campaign, lock_home, change):
    c = cohort_campaign
    with pytest.raises((ValueError, OSError)):
        with scoped(c.old) as (auth, owner):
            if change == "head":
                attack_sql(c.parent, "UPDATE meta SET value=? WHERE key='epoch_head'", ("{}",))
            elif change == "next-file":
                _create(c.parent.root / "epoch-admissions" / f"{len(auth.records):06d}.json", b"{}\n")
            elif change == "retired-path":
                (c.parent.root / "pilots" / lineage.EXCLUDED).mkdir(parents=True)
            elif change == "root":
                displaced = c.parent.root.with_name("displaced-parent")
                c.parent.root.rename(displaced)
                c.parent.root.mkdir()
            elif change == "database":
                path = c.parent.database
                path.rename(path.with_name("displaced-ledger.sqlite3"))
                path.write_bytes(b"replacement is not the pinned database")
            elif change == "lock-path":
                owner.path.rename(owner.path.with_name("displaced-docker.lock"))
                owner.path.write_bytes(b"")
            elif change == "epoch-lock":
                path = c.parent.root / "epoch-admission.lock"
                path.rename(path.with_name("displaced-epoch.lock"))
                path.write_bytes(b"")
            else:
                fcntl.flock(owner.handle, fcntl.LOCK_UN)
            with pytest.raises((ValueError, OSError)):
                c.old.allocate_attempt(HOST, MODE, purpose="pilot")


@pytest.mark.parametrize("change", ["classes", "study-meta", "network-meta", "membership-meta", "schema", "retired-sql"])
def test_fresh_all_root_sql_projection_refuses_unselected_authority_tampering(cohort_campaign, lock_home, change):
    c = cohort_campaign
    with pytest.raises((ValueError, OSError)):
        with scoped(c.old):
            if change == "classes":
                attack_sql(c.parent, "UPDATE classes SET sha256=? WHERE hostname=?", ("0" * 64, "alpha.example"))
            elif change in {"study-meta", "network-meta", "membership-meta"}:
                key = {"study-meta": "study_sha256", "network-meta": "class_network_sha256",
                       "membership-meta": "epoch_membership_sha256"}[change]
                attack_sql(c.parent, "UPDATE meta SET value=? WHERE key=?", ("0" * 64, key))
            elif change == "schema":
                attack_sql(c.parent, "DROP TRIGGER " + next(iter(lineage.fence_ddl())))
            else:
                attack_sql(c.parent, "UPDATE classes SET hostname=? WHERE hostname=?",
                    (lineage.EXCLUDED, "alpha.example"))
            with pytest.raises((ValueError, OSError)):
                c.old.allocate_attempt(HOST, MODE, purpose="pilot")


def test_actual_current_attempts_and_duplicate_tuples_remain_fresh(cohort_campaign, lock_home):
    c = cohort_campaign
    with scoped(c.old):
        first = c.old.allocate_attempt(HOST, MODE, purpose="pilot")
        with pytest.raises(ValueError, match="active reservation"):
            c.old.allocate_attempt(HOST, MODE, purpose="pilot")
        c.old.mark_captured(first["attempt_id"])
        c.old.fail_attempt(first["attempt_id"], "explicit no-credit test completion")
        # Real fresh credit path and immutable receipt/index guards from the
        # original fixture; only its raw leaf is explicitly synthetic.
        c.credit(c.old, port=31001)
        with pytest.raises(ValueError, match="tuple|duplicate|repeats"):
            c.credit(c.old, port=31001)
        assert c.old.status()["accepted_count"] == 2


def test_explicit_worker_binding_and_foreign_context_refusal(cohort_campaign, lock_home):
    c = cohort_campaign
    with scoped(c.old) as (auth, owner):
        with pytest.raises(ValueError, match="nest"):
            with cohorts.capture_authority_scope(c.old.root, owner):
                pass
        inherited = copy_context()

        def read_scope():
            with cohorts.capture_records_scope(c.parent, writer_root=c.old.root) as value:
                return value

        def bound_worker():
            with cohorts.bind_capture_authority(auth, writer_root=c.old.root):
                attempt = c.old.allocate_attempt(HOST, MODE, purpose="pilot")
                c.old.fail_attempt(attempt["attempt_id"], "worker finished without credit")
                return attempt["attempt_id"]

        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(ValueError, match="foreign|unbound"):
                pool.submit(inherited.run, read_scope).result()
            assert len(pool.submit(bound_worker).result()) == 32
        foreign = StudyStore(c.parent.root.parent / "foreign-parent")
        with pytest.raises(ValueError, match="foreign parent"):
            with cohorts.capture_records_scope(foreign, writer_root=c.old.root):
                pass
    with pytest.raises(ValueError, match="closed|foreign"):
        with cohorts.bind_capture_authority(auth, writer_root=c.old.root):
            pass


def test_body_error_survives_last_read_closure_failure(cohort_campaign, lock_home):
    c = cohort_campaign

    class BodyFailure(Exception):
        pass

    with pytest.raises(BodyFailure, match="original body") as caught:
        with scoped(c.old):
            path = c.parent.root / "study.json"
            path.chmod(0o644)
            path.write_bytes(path.read_bytes() + b"\n")
            path.chmod(0o444)
            raise BodyFailure("original body")
    assert any("Capture authority closure also refused" in note for note in caught.value.__notes__)


def test_copy_implementation_cannot_be_replaced_with_an_alias(cohort_campaign, lock_home, monkeypatch):
    c = cohort_campaign
    with pytest.raises(ValueError, match="implementation changed"):
        with scoped(c.old):
            monkeypatch.setattr(cohorts, "deepcopy", lambda value: value)
            with pytest.raises(ValueError, match="implementation changed"):
                with cohorts.capture_records_scope(c.parent, writer_root=c.old.root):
                    pytest.fail("a replaced copy must not expose private authority")


def test_public_admission_lock_stays_genuine_and_closes_before_unlock(cohort_campaign, lock_home, monkeypatch):
    c = cohort_campaign
    # Restore the real lock after campaign's explicitly controlled setup.
    monkeypatch.setattr(epochs, "docker_lock", runtime.docker_lock)
    with scoped(c.old) as (auth, owner):
        owner.check()
        # Original initialization and declaration remain allowed; neither
        # publishes a head. The actual admission must stop at the held lock.
        candidate = c.fresh()
        path, digest, _ = c.declaration(candidate)
        with pytest.raises(RuntimeError, match="Docker lifecycle"):
            cohorts.create_cohort(c.parent.root, candidate.root, path, digest)
        assert not (c.parent.root / "epoch-admissions" / f"{len(auth.records):06d}.json").exists()
        assert epochs._records(c.parent) == auth.records
    with runtime.docker_lock() as next_owner:
        next_owner.check()


def test_runtime_cohort_shape_after_current_profile_is_bound(cohort_campaign, lock_home):
    """Run after Source055 metadata binding, not as original semantic RED.

    Uses actual public runtime-cohort admission/compatibility declarations and
    frozen carry rows. It is not a live head15 receipt or formal pilot proof.
    """
    c = cohort_campaign
    first = c.fresh(native="b")
    c.append(first)
    second = c.fresh(native="e")
    c.append(second)
    with scoped(second) as (auth, _):
        last_sequence = auth.records[-1]["sequence"]
        assert auth.records[-1]["record_type"] == cohorts.ADMISSION
        with cohorts.capture_records_scope(c.parent, writer_root=second.root) as actual:
            assert actual == epochs._records(c.parent)
        assert cohorts.counts_snapshot(second, [(HOST, MODE)]) == {(HOST, MODE): 1}
        attempt = second.allocate_attempt(HOST, MODE, purpose="pilot")
        second.fail_attempt(attempt["attempt_id"], "no-credit prospective cohort control")
    # After ownership closes, the unchanged public publication route works.
    third = c.fresh(native="b")
    assert c.append(third)["sequence"] == last_sequence + 1


def test_two_owning_roots_bind_workers_without_sharing_connections(cohort_campaign, lock_home):
    """Stable V3 authority supports two roots before later cohort metadata tests."""
    c = cohort_campaign
    roots = [c.parent.root, c.old.root]
    with runtime.docker_lock() as owner:
        with cohorts.capture_authority_scope(roots, owner) as auth:
            assert auth.writers == frozenset(map(str, roots))
            # Parent still owns its original alpha/beta cells; child owns MAL.
            with cohorts.capture_records_scope(c.parent, writer_root=c.parent.root) as value:
                assert value == epochs._records(c.parent)
            with cohorts.capture_records_scope(c.parent, writer_root=c.old.root) as value:
                assert value == epochs._records(c.parent)
            def worker(root, other):
                with cohorts.bind_capture_authority(auth, writer_root=root):
                    with cohorts.capture_records_scope(c.parent, writer_root=root) as value:
                        assert value == auth.records
                    with pytest.raises(ValueError, match="foreign owning root"):
                        with cohorts.capture_records_scope(c.parent, writer_root=other):
                            pass
                    return threading.get_ident()
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(worker, roots[0], roots[1]), pool.submit(worker, roots[1], roots[0])]
                assert all(type(f.result()) is int for f in futures)


def test_every_bound_file_is_fully_read_at_each_callback(cohort_campaign, lock_home, monkeypatch):
    c = cohort_campaign
    reads = Counter()
    original = cohorts._records_file

    def observed(path, *, content=False):
        if content:
            reads[str(path)] += 1
        return original(path, content=content)

    # Observe and delegate the complete original FD/content guard. The wrapper
    # is installed before the scope snapshots implementation identities.
    monkeypatch.setattr(cohorts, "_records_file", observed)
    with scoped(c.old) as (auth, _):
        bound = set(auth.files)
        assert str(c.parent.root / "epoch-admissions/000000.json") in bound
        assert str(c.old.root / lineage.SOURCE) in bound
        assert str(c.old.root / lineage.INVENTORY) in bound
        reads.clear()
        with cohorts.capture_records_scope(c.parent, writer_root=c.old.root):
            pass
        assert all(reads[path] >= 2 for path in bound)


def test_runtime_cohort_fresh_accepted_attempt_join_after_profile_binding(cohort_campaign, lock_home):
    """After current metadata is bound, cached ancestry cannot replace SQL joins."""
    c = cohort_campaign
    current = c.fresh()
    c.append(current)
    with scoped(current):
        assert cohorts.counts_snapshot(current, [(HOST, MODE)]) == {(HOST, MODE): 1}
        # Frozen manifest bytes stay unchanged. Its actual accepted/attempt
        # rows must still agree in the original fresh selected-cell SQL path.
        attack_sql(c.old, "UPDATE attempts SET receipt_sha256=? WHERE hostname=? AND mode=? AND state='accepted'",
            ("0" * 64, HOST, MODE))
        with pytest.raises(ValueError, match="accepted row/reservation binding"):
            cohorts.counts_snapshot(current, [(HOST, MODE)])


def test_lost_own_membership_cannot_take_unbound_hook_fallbacks(cohort_campaign, lock_home):
    c = cohort_campaign
    with pytest.raises((ValueError, OSError)):
        with scoped(c.old):
            attempt = c.old.allocate_attempt(HOST, MODE, purpose="pilot")
            attack_sql(c.old, "DELETE FROM meta WHERE key='epoch_membership_sha256'")
            (c.old.root / "epoch-membership.json").unlink()
            callbacks = [
                lambda: cohorts.counts_snapshot(c.old, [(HOST, MODE)]),
                lambda: c.old.allocate_attempt(HOST, MODE, purpose="pilot"),
                lambda: c.old.mark_captured(attempt["attempt_id"]),
                lambda: c.old.commit_verified(c.old_receipt),
            ]
            for callback in callbacks:
                with pytest.raises(ValueError, match="owning root lost its membership"):
                    callback()


@pytest.mark.parametrize("method", ["plan_data", "network_plan", "frozen_value", "finish"])
def test_current_reader_methods_cannot_change_within_capture(cohort_campaign, lock_home, monkeypatch, method):
    c = cohort_campaign
    with scoped(c.old):
        with monkeypatch.context() as changed:
            changed.setattr(cohorts._RecordsRead, method, lambda *args, **kwargs: None)
            with pytest.raises(ValueError, match="reader implementation changed"):
                cohorts.counts_snapshot(c.old, [(HOST, MODE)])


def test_current_scientific_parent_is_distinct_from_capture_execution():
    from qcsd_lab import resource_study_reader_compatibility as compatibility
    import hashlib
    current = cohorts.verifier_contract()
    qualified = compatibility.qualify_execution(current)
    assert compatibility.EXECUTION_KIND == "055"
    assert compatibility.execution_files()["process_scheduler.py"] == "8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf"
    assert compatibility.prior_flight_execution_contract()["transitive_source_sha256"] == "849249d7280973d40cde6392784dc35e9f5b7096809914ee8878f4b95c7d552a"
    assert compatibility.prior_monitor_execution_contract()["transitive_source_sha256"] == "bae215a4bb7ef5190c20329533a6ddb2a932396d9ed88bf161d745de8e683396"
    for profile, digest in ((compatibility.prior_analysis_execution_contract(), "2bee8641e6cb774cab67e030b6672bf1a79144e8d94082ae83ada9d198fecbc1"),
                            (compatibility.prior_flight_execution_contract(), "3064e6a015b54ff1bd00d62be478a381165ff0b5e3d5fc78c5b7a526a31cfbaf"),
                            (compatibility.prior_monitor_execution_contract(), "2d9b7a5bfa67c024f15597b941be57c0b6c54532a69801213c7a2580fd95b180")):
        assert hashlib.sha256(compatibility._encoded(profile)).hexdigest() == digest
    for parent in (compatibility.legacy_contract(), compatibility.prior_execution_contract(),
                   compatibility.prior_capture_execution_contract(), compatibility.prior_analysis_execution_contract(),
                   compatibility.prior_flight_execution_contract(), compatibility.prior_monitor_execution_contract()):
        assert current != parent
        assert compatibility.require_supported(parent, qualified) is True
        assert compatibility.execution_binding(parent, qualified)["admission_reader"] == parent
        with pytest.raises(ValueError, match="execution reader"):
            compatibility.qualify_execution(parent)
    binding = compatibility.execution_binding(current, qualified)
    assert binding["capture_flight_authority_projection_changed"] is True
    assert binding["authority_issued"] is False and binding["scientific_credit_added"] == 0


@pytest.mark.parametrize("name", ["process_scheduler.py", "resource_study_cohorts.py", "resource_study_store.py",
                                  "resource_study.py", "resource_study_runtime.py", "resource_study_reader_compatibility.py"])
def test_unapproved_execution_and_dated_admission_hashes_refuse(name):
    from qcsd_lab import resource_study_reader_compatibility as compatibility
    current = cohorts.verifier_contract()
    qualified = compatibility.qualify_execution(current)
    files = compatibility.execution_files()
    files[name] = "0" * 64
    with pytest.raises(ValueError, match="execution reader"):
        compatibility.qualify_execution(compatibility._profile(files))
    files = dict(compatibility.LEGACY_FILES)
    files.update(compatibility.PRIOR_MONITOR_EXECUTION_FILES)
    files[name] = "0" * 64
    with pytest.raises(ValueError, match="admission reader"):
        compatibility.require_supported(compatibility._profile(files), qualified)
