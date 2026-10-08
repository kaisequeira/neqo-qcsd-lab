"""Coordinator/ledger integration; synthetic capture is not Native evidence.

The actual coordinator, immutable publisher and SQLite store execute here.
Only the capture backend and independent scientific validator are controlled:
the fake PCAP payload cannot establish QUIC, clock or defense conformance.
Those properties belong to test_resource_study_verify and real runtime gates.
"""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import threading

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab.resource_study_inputs import MODES, canonical_json, sha256_file
from qcsd_lab.resource_study_store import StudyStore


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))
    path.chmod(0o444)
    return sha256_file(path)


def _runtime(*, lab="a", client="e"):
    return {"collection_image_digest": "sha256:" + lab * 64,
        "prepare_image_digest": "sha256:" + lab * 64,
        "client_sha256": client * 64, "platform": "linux/amd64",
        "source": {"neqo_commit": "d" * 40, "lab_commit": lab * 40},
        "canonical_sha256": lab * 64}


def _enrollment(root, hostname, runtime=None, *, urls=None):
    urls = urls or [f"https://{hostname}/object?index={index}" for index in range(20)]
    path = root / "classes" / hostname / "workload.json"
    digest = _write(path, {"resources": [
        {"id": index, "url": url, "known_valid": True, "dependencies": []}
        for index, url in enumerate(urls)]})
    return {"hostname": hostname, "urls": urls, "workload_sha256": digest,
        "workload_path": path.relative_to(root).as_posix(),
        "files": {path.relative_to(root).as_posix(): digest},
        "runtime": runtime or _runtime(), "mode_readiness": {mode: True for mode in MODES},
        "mode_settings": {mode: {"controlled_fixture": mode} for mode in MODES}}


@pytest.fixture
def controlled_validator(monkeypatch):
    """Independently check the fake backend's exact 20-response document."""
    calls = []

    def validate(root, receipt):
        paths = receipt["artifact_paths"]
        enrollment = study.load(root / paths["enrollment"])
        run = study.load(root / paths["run"])
        assert run["completed"] is True
        assert len(run["endpoints"]) == 1
        assert run["responses"] == [
            {"id": index, "url": url, "status": 200, "complete": True}
            for index, url in enumerate(enrollment["urls"])]
        assert run["fixture_connection_instances"] == 1
        assert receipt["five_tuple"][1] == run["fixture_port"]
        for relative, digest in receipt["files"].items():
            assert sha256_file(root / relative) == digest
        calls.append(receipt["attempt_id"])
        return {"verified": True, "scope": "synthetic coordinator fixture only"}

    monkeypatch.setattr(study, "verify_receipt", validate)
    return calls


@pytest.fixture
def held(tmp_path, controlled_validator):
    root = tmp_path / "study"
    store = StudyStore(root)
    store.initialize({"schema_version": 1, "record_type": study.RECORD,
        "class_count": 50, "resources_per_session": 20, "sessions_per_mode": 400,
        "total_sessions": 100000, "modes": list(MODES), "fixture": True})
    for hostname in ("alpha.example", "bravo.example"):
        store.enroll(_enrollment(root, hostname))
    # Synthetic pilot-reader setup only: no reservations, raw Native claim or
    # accepted ledger rows. The controlled validator still checks 20 responses.
    enrollment = store.enrolled()[0]
    for index, mode in enumerate(MODES):
        directory = root / "pilots" / enrollment["hostname"] / mode / "controlled-boundary"
        run = directory / "run.json"
        _write(run, {"completed": True, "fixture_connection_instances": 1,
            "fixture_port": 41000 + index,
            "endpoints": [{"id": 0}],
            "responses": [{"id": resource, "url": url, "status": 200, "complete": True}
                for resource, url in enumerate(enrollment["urls"])]})
        original = root / "classes" / enrollment["hostname"] / "enrollment.json"
        _write(directory / "session.json", {"purpose": "pilot", "mode": mode,
            "runtime": _runtime(), "five_tuple": ["192.0.2.1", 41000 + index, "198.51.100.1", 443, 17],
            "attempt_id": "controlled-pilot-no-ledger-reservation",
            "artifact_paths": {"run": run.relative_to(root).as_posix(),
                "enrollment": original.relative_to(root).as_posix()},
            "files": {run.relative_to(root).as_posix(): sha256_file(run),
                original.relative_to(root).as_posix(): sha256_file(original)}})
    return root, store


class CaptureBackend:
    def __init__(self, root, *, fail_cell=None, stop=None, repeat_tuple=False, overlap=False):
        self.root = root
        self.fail_cell = fail_cell
        self.stop = stop
        self.repeat_tuple = repeat_tuple
        self.calls = []
        self.active = set()
        self.max_active = 0
        self.lock = threading.Lock()
        self.first_pair = threading.Barrier(2) if overlap else None
        self.entered = self.closed = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *_):
        self.closed = True

    def capture(self, worker, attempt, enrollment):
        # Public allocation must commit its reservation before backend traffic.
        with sqlite3.connect(self.root / "ledger.sqlite3") as database:
            row = database.execute("SELECT hostname,mode,slot,state FROM attempts WHERE attempt_id=?",
                (attempt["attempt_id"],)).fetchone()
        assert row == (attempt["hostname"], attempt["mode"], attempt["slot"], "reserved")
        assert (self.root / attempt["path"]).is_dir()
        with self.lock:
            assert attempt["hostname"] not in self.active
            self.active.add(attempt["hostname"])
            self.max_active = max(self.max_active, len(self.active))
            self.calls.append((worker, deepcopy(attempt)))
            index = len(self.calls)
        try:
            if self.first_pair is not None and index <= 2:
                self.first_pair.wait(timeout=10)
            if self.fail_cell == (attempt["hostname"], attempt["mode"]):
                return {"success": False, "failure": "controlled first-cell failure"}
            port = 42000 if self.repeat_tuple else 42000 + index
            self.write_capture(attempt, enrollment, port)
            if self.stop is not None:
                self.stop.set()
            return {"success": True, "mode_policies": {"fixture": attempt["mode"]}}
        finally:
            with self.lock:
                self.active.remove(attempt["hostname"])

    def write_capture(self, attempt, enrollment, port):
        directory = self.root / attempt["path"] / "capture"
        _write(directory / "neqo/run.json", {"completed": True,
            "fixture_connection_instances": 1, "fixture_port": port,
            "endpoints": [{"id": 0, "local_address": f"192.0.2.1:{port}",
                "remote_address": "198.51.100.1:443"}],
            "responses": [{"id": index, "url": url, "status": 200, "complete": True}
                for index, url in enumerate(enrollment["urls"])]})
        for relative in ("captures/direct-quic.pcapng", "traces/direct-quic.csv",
                         "neqo/packets.csv", "diagnostics/direct-quic-raw.pcapng"):
            path = directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"SYNTHETIC COORDINATOR FIXTURE; NOT PCAP/QUIC PROOF\n")
        _write(directory / "attempt.json", {"attempt_id": attempt["attempt_id"],
            "scope": "synthetic capture backend"})


def test_initialize_freezes_actual_source_eligibility_and_zero_credit(tmp_path):
    source = tmp_path / "supplied.json"
    _write(source, [{"crUX_domain": "page.example", "resources": [
        {"resource_domain": "alpha.example", "resource_urls": [
            f"https://alpha.example/o?n={index}" for index in range(20)]},
        {"resource_domain": "small.example", "resource_urls": [
            f"https://small.example/o?n={index}" for index in range(19)]}]}])
    root = tmp_path / "study"
    result = study.initialize(source, root)
    catalogue = study.load(root / "inputs/candidates.json")
    assert {row["hostname"]: row["eligible"] for row in catalogue["candidates"]} == {
        "alpha.example": True, "small.example": False}
    assert (root / "inputs/supplied-resources.json").read_bytes() == source.read_bytes()
    assert StudyStore(root).plan()["source_sha256"] == sha256_file(source)
    assert result["accepted_count"] == result["enrolled_count"] == 0
    assert result["session_target"] == 100000 and not result["complete"]
    immutable = {name: (root / name).read_bytes() for name in (
        "study.json", "inputs/candidates.json", "inputs/supplied-resources.json")}
    with pytest.raises((ValueError, FileExistsError)):
        study.initialize(source, root)
    assert {name: (root / name).read_bytes() for name in immutable} == immutable


def _source(path, hostnames):
    _write(path, [{"crUX_domain": "page.example", "resources": [
        {"resource_domain": host, "resource_urls": [
            f"https://{host}/object?index={index}" for index in range(20)]}
        for host in hostnames]}])


def test_enrollment_failure_is_local_and_healthy_source_class_remains_available(tmp_path):
    root = tmp_path / "study"
    source = tmp_path / "source.json"
    _source(source, ("alpha.example", "bravo.example"))
    study.initialize(source, root)

    class Backend:
        def prepare(self, candidate, attempt):
            if candidate["hostname"] == "alpha.example":
                raise ValueError("controlled eligibility preparation failed")
            return _enrollment(root, candidate["hostname"], urls=candidate["urls"][:20])

    result = study.enroll(root, _runtime(), ["alpha.example", "bravo.example"], backend=Backend())
    assert [row["status"] for row in result["enrollment"]] == ["not-enrolled", "enrolled"]
    assert result["progress"]["enrolled_count"] == 1 and result["progress"]["accepted_count"] == 0
    assert StudyStore(root).enrolled()[0]["hostname"] == "bravo.example"
    assert len(list((root / "enrollment-attempts/alpha.example").glob("*/excluded.json"))) == 1


@pytest.mark.parametrize("mutation", ["foreign-host", "unfrozen-resource"])
def test_enrollment_cannot_import_foreign_class_or_unfrozen_urls(tmp_path, mutation):
    root = tmp_path / "study"
    source = tmp_path / "source.json"
    _source(source, ("alpha.example",))
    study.initialize(source, root)

    class Backend:
        def prepare(self, candidate, attempt):
            if mutation == "foreign-host":
                return _enrollment(root, "foreign.example")
            urls = list(candidate["urls"][:20])
            urls[-1] = "https://alpha.example/not-in-frozen-source"
            return _enrollment(root, "alpha.example", urls=urls)

    result = study.enroll(root, _runtime(), ["alpha.example"], backend=Backend())
    assert result["enrollment"][0]["status"] == "not-enrolled"
    assert result["progress"]["enrolled_count"] == 0 and result["progress"]["accepted_count"] == 0


def test_failed_cell_pauses_while_healthy_cell_finishes_twenty_session_chunk(held):
    root, store = held
    backend = CaptureBackend(root, fail_cell=("alpha.example", "undefended"))
    result = study.capture(root, _runtime(), backend=backend,
        modes=("undefended",), budget=40, chunk_sessions=20)
    assert backend.entered and backend.closed and not backend.active
    assert result["paused_cells"] == [("alpha.example", "undefended")]
    assert result["progress"]["accepted_count"] == 20
    assert result["progress"]["failed"] == 1
    calls = [attempt for _, attempt in backend.calls]
    assert sum(attempt["hostname"] == "alpha.example" for attempt in calls) == 1
    assert [attempt["slot"] for attempt in calls if attempt["hostname"] == "bravo.example"] == list(range(1, 21))
    assert store.status()["enrolled_count"] == 2


def test_one_session_chunks_cover_five_mode_pilot_without_formal_credit(held):
    root, store = held
    backend = CaptureBackend(root)
    result = study.capture(root, _runtime(), backend=backend,
        hostnames=["alpha.example"], budget=5, chunk_sessions=1, pilot=True)
    assert [attempt["mode"] for _, attempt in backend.calls] == list(MODES)
    assert result["progress"]["accepted_count"] == 0
    assert result["progress"]["accepted_by_mode"] == {mode: 0 for mode in MODES}
    assert all(attempt["slot"] == 1 for _, attempt in backend.calls)
    assert len({attempt["attempt_id"] for _, attempt in backend.calls}) == 5
    assert store.status()["failed"] == 5
    for _, attempt in backend.calls:
        path = root / "pilots/alpha.example" / attempt["mode"] / attempt["attempt_id"] / "session.json"
        receipt = study.load(path)
        assert receipt["purpose"] == "pilot" and receipt["scientific_credit"] is False
        assert not (root / "corpus/alpha.example" / attempt["mode"] / "session-000001").exists()
        with pytest.raises(ValueError, match="pilot recordings"):
            store.commit_verified(path, validator=study.verify_receipt)


def test_workers_overlap_only_distinct_domains_and_keep_reservations_durable(held):
    root, _ = held
    backend = CaptureBackend(root, overlap=True)
    result = study.capture(root, _runtime(), backend=backend,
        modes=("undefended", "front"), budget=8, chunk_sessions=1)
    assert backend.max_active == 2 and not backend.active
    assert {worker for worker, _ in backend.calls} == {0, 1}
    assert result["progress"]["accepted_count"] == 8
    assert len({attempt["attempt_id"] for _, attempt in backend.calls}) == 8


def test_stop_and_resume_preserve_first_receipt_and_next_missing_slot(held):
    root, store = held
    stop = threading.Event()
    backend = CaptureBackend(root, stop=stop)
    stopped = study.capture(root, _runtime(), backend=backend, stop=stop,
        hostnames=["alpha.example"], modes=("undefended",), budget=20)
    assert stopped["stop_requested"] and stopped["progress"]["accepted_count"] == 1
    first = root / "corpus/alpha.example/undefended/session-000001/session.json"
    held_bytes = first.read_bytes()
    next_backend = CaptureBackend(root)
    # Use a different fixture tuple from the earlier connection.
    next_backend.calls = [(-1, {"fixture": "seed port counter only"})]
    resumed = study.capture(root, _runtime(), backend=next_backend,
        hostnames=["alpha.example"], modes=("undefended",), budget=1, chunk_sessions=1)
    current = next_backend.calls[-1][1]
    assert current["slot"] == 2 and current["attempt"] == 2
    assert resumed["progress"]["accepted_count"] == 2
    assert first.read_bytes() == held_bytes and store.status()["failed"] == 0


def test_orphan_published_slot_is_not_moved_or_overwritten_by_a_new_attempt(held):
    root, store = held
    orphan = root / "corpus/alpha.example/undefended/session-000001/session.json"
    _write(orphan, {"attempt_id": "f" * 32, "recording": "older publication; not new worker output"})
    original = orphan.read_bytes()
    backend = CaptureBackend(root)
    try:
        study.capture(root, _runtime(), backend=backend,
            hostnames=["alpha.example"], modes=("undefended",), budget=1, chunk_sessions=1)
    except ValueError:
        pass
    assert orphan.is_file() and orphan.read_bytes() == original
    assert not list((root / "failures").glob("*/*/*/session.json"))
    assert store.status()["accepted_count"] == 0


def test_duplicate_tuple_recording_stays_uncredited_and_first_slot_immutable(held):
    root, store = held
    backend = CaptureBackend(root, repeat_tuple=True)
    result = study.capture(root, _runtime(), backend=backend,
        hostnames=["alpha.example"], modes=("undefended",), budget=2, chunk_sessions=1)
    assert result["progress"]["accepted_count"] == 1
    assert result["progress"]["duplicate"] == 1
    assert (root / "corpus/alpha.example/undefended/session-000001/session.json").is_file()
    assert not (root / "corpus/alpha.example/undefended/session-000002").exists()
    duplicate = backend.calls[-1][1]
    assert (root / "failures/alpha.example/undefended" / duplicate["attempt_id"] / "session.json").is_file()
    assert store.status()["failed"] == 0


def test_seal_then_crash_recovery_credits_same_attempt_after_public_verify(held):
    root, store = held
    enrollment = store.enrolled()[0]
    attempt = store.allocate_attempt(enrollment["hostname"], "undefended")
    backend = CaptureBackend(root)
    backend.write_capture(attempt, enrollment, 45001)
    store.mark_captured(attempt["attempt_id"])
    path = study.seal(root, attempt, enrollment, _runtime(), {"success": True})
    before = path.read_bytes()
    recovered = study.verify(root, recover=True)
    assert recovered["errors"] == [] and recovered["progress"]["accepted_count"] == 1
    assert recovered["recovery"]["pending_verification"][0]["attempt_id"] == attempt["attempt_id"]
    assert path.read_bytes() == before
    assert store.allocate_attempt(enrollment["hostname"], "undefended")["slot"] == 2


def test_new_lab_runtime_preserves_native_client_mode_and_retains_actual_provenance(held):
    root, store = held
    renewed = _runtime(lab="b")
    result = study.capture(root, renewed, backend=CaptureBackend(root),
        hostnames=["alpha.example"], modes=("undefended",), budget=1, chunk_sessions=1)
    assert result["progress"]["accepted_count"] == 1
    receipt = study.load(root / "corpus/alpha.example/undefended/session-000001/session.json")
    assert receipt["runtime"] == renewed
    assert receipt["runtime"] != store.enrolled()[0]["runtime"]
    assert receipt["mode_settings"] == {"controlled_fixture": "undefended"}


def test_formal_receipt_gets_one_independent_raw_verification(held, controlled_validator):
    root, _ = held
    backend = CaptureBackend(root)
    result = study.capture(root, _runtime(), backend=backend,
        hostnames=["alpha.example"], modes=("undefended",), budget=1, chunk_sessions=1)
    assert result["progress"]["accepted_count"] == 1
    assert controlled_validator.count(backend.calls[0][1]["attempt_id"]) == 1


def test_formal_capture_requires_its_pilot_before_any_reservation(held):
    root, store = held
    for path in (root / "pilots").glob("*/front/*/session.json"):
        path.unlink()
    backend = CaptureBackend(root)
    with pytest.raises(ValueError, match="focused pilot"):
        study.capture(root, _runtime(), backend=backend,
            hostnames=["alpha.example"], modes=("front",), budget=1, chunk_sessions=1)
    assert not backend.entered and not backend.calls
    assert store.status()["attempts"] == {} and store.status()["accepted_count"] == 0


def test_missing_mode_pilot_preserves_healthy_formal_progress(held):
    root, store = held
    for path in (root / "pilots").glob("*/buflo/*/session.json"):
        path.unlink()
    backend = CaptureBackend(root)
    result = study.capture(root, _runtime(), backend=backend,
        hostnames=["alpha.example"], modes=("buflo", "undefended"), budget=1, chunk_sessions=1)
    assert result["paused_cells"] == [("alpha.example", "buflo")]
    assert result["missing_mode_pilots"] == ["buflo"]
    assert result["progress"]["accepted_count"] == 1
    assert [attempt["mode"] for _, attempt in backend.calls] == ["undefended"]
    assert store.status()["attempts"] == {"accepted": 1}


def test_cell_reservation_refusal_does_not_abort_healthy_worker(held, monkeypatch):
    root, store = held
    original = StudyStore.allocate_attempt
    def refuse_one(self, hostname, mode, **kwargs):
        if hostname == "alpha.example":
            raise ValueError("active epoch needs its own genuine matching mode pilot")
        return original(self, hostname, mode, **kwargs)
    monkeypatch.setattr(StudyStore, "allocate_attempt", refuse_one)
    backend = CaptureBackend(root)
    result = study.capture(root, _runtime(), backend=backend,
        modes=("undefended",), budget=2, chunk_sessions=1)
    assert result["paused_cells"] == [("alpha.example", "undefended")]
    assert result["progress"]["accepted_count"] == 1
    assert [attempt["hostname"] for _, attempt in backend.calls] == ["bravo.example"]
    assert store.status()["attempts"] == {"accepted": 1}
    assert result["allocation_errors"] == [{"hostname": "alpha.example", "mode": "undefended",
        "reason": "active epoch needs its own genuine matching mode pilot"}]


@pytest.mark.parametrize("workers,budget,chunk,modes", [
    (1, 1, 1, ("undefended",)), (True, 1, 1, ("undefended",)),
    (2, 0, 1, ("undefended",)), (2, 1, 0, ("undefended",)),
    (2, 1, 21, ("undefended",)), (2, 1, 1, ("unknown",)),
    (2, 1, 1, ("front", "front")),
])
def test_bad_scheduler_requests_fail_before_backend_entry(held, workers, budget, chunk, modes):
    root, store = held
    backend = CaptureBackend(root)
    with pytest.raises(ValueError):
        study.capture(root, _runtime(), backend=backend, workers=workers,
            budget=budget, chunk_sessions=chunk, modes=modes)
    assert not backend.entered and not backend.calls
    assert store.status()["accepted_count"] == 0


def test_runtime_metadata_reuses_client_without_native_compilation(tmp_path, monkeypatch):
    from qcsd_lab import rapid_portable_runtime as portable
    value = _runtime(lab="b")
    canonical = tmp_path / "canonical.json"
    _write(canonical, {"collection_image_digest": value["collection_image_digest"],
        "prepare_image_digest": value["prepare_image_digest"], "platform": value["platform"],
        "installed_client_sha256": value["client_sha256"], "source": value["source"]})
    observed = []
    monkeypatch.setattr(portable, "_verify", lambda root, data: observed.append((root, deepcopy(data))))
    assert study.runtime_identity(canonical) == {**value,
        "native_commit": value["source"]["neqo_commit"], "canonical_sha256": sha256_file(canonical)}
    assert observed == [(canonical.parent, study.load(canonical))]
