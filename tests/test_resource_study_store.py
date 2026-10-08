"""Transactional ledger controls with an explicit synthetic raw-validator boundary.

These tests execute no Native client or capture. Their validator examines only
the controlled unit run document; production must supply independent raw proof.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading

import pytest

from qcsd_lab.resource_study_store import DuplicateSession, MODES, RECORD, StudyStore


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    path.chmod(0o600)
    return digest(path)


def plan():
    return {"schema_version": 1, "record_type": "qcsd-resource-domain-study-v1",
        "class_count": 50, "resources_per_session": 20, "sessions_per_mode": 400,
        "total_sessions": 100000, "modes": list(MODES),
        "source": {"unit_fixture": "no runtime or historical credit"}}


def enroll(store, hostname="example.org"):
    urls = [f"https://{hostname}/resource?identifier={index}" for index in range(20)]
    path = store.root / "classes" / hostname / "workload.json"
    write(path, {"urls": urls})
    value = {"hostname": hostname, "urls": urls, "workload_sha256": digest(path),
        "files": {path.relative_to(store.root).as_posix(): digest(path)},
        "runtime": {"source": {"neqo_commit": "d" * 40, "lab_commit": "a" * 40},
            "platform": "linux/amd64", "client_sha256": "e" * 64, "image_digest": "sha256:" + "f" * 64}}
    store.enroll(value)
    return value


@pytest.fixture
def store(tmp_path):
    result = StudyStore(tmp_path / "study")
    result.initialize(plan()); enroll(result)
    return result


def receipt(store, attempt, port=40001, *, verified=True):
    directory = store.root / attempt["path"]
    run = directory / "run.json"
    write(run, {"completed": True, "http3": True, "resources": list(range(20)),
        "fresh_connection_instances": 1})
    path = directory / "verification.json"
    value = {"schema_version": 1, "record_type": RECORD, "verified": verified,
        **{key: attempt[key] for key in ("hostname", "mode", "slot", "attempt_id")},
        "five_tuple": ["192.0.2.1", port, "198.51.100.1", 443, 17],
        "files": {run.relative_to(store.root).as_posix(): digest(run)}}
    write(path, value)
    return path


def unit_raw_validator(root, value):
    run = json.loads((root / next(name for name in value["files"] if name.endswith("/run.json"))).read_bytes())
    return run == {"completed": True, "http3": True, "resources": list(range(20)), "fresh_connection_instances": 1}


def test_initialize_is_durable_create_only_and_has_zero_credit(tmp_path):
    store = StudyStore(tmp_path / "study"); value = plan()
    assert store.initialize(value) == value
    held = (store.root / "study.json").stat().st_mtime_ns
    assert store.initialize(value) == value
    assert (store.root / "study.json").stat().st_mtime_ns == held
    changed = deepcopy(value); changed["source"]["different"] = True
    with pytest.raises(ValueError, match="different immutable"):
        store.initialize(changed)
    connection = store._connect()
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
    finally:
        connection.close()
    assert store.status()["accepted_count"] == 0
    assert store.status()["session_target"] == 100000 and not store.status()["complete"]


def test_connection_allows_sqlite_sidecar_to_disappear_during_open(store, monkeypatch):
    from qcsd_lab import resource_study_store as module
    sidecar = Path(str(store.database) + "-journal")
    sidecar.write_bytes(b"")
    original = module._unlinked
    observed = []

    def sqlite_closed_idle_sidecar(path, **kwargs):
        if Path(path) == sidecar:
            sidecar.unlink()
            observed.append(sidecar)
        return original(path, **kwargs)

    monkeypatch.setattr(module, "_unlinked", sqlite_closed_idle_sidecar)
    assert store.status()["accepted_count"] == 0
    assert observed == [sidecar]


def test_connection_refuses_a_linked_sqlite_sidecar(store, tmp_path):
    sidecar = Path(str(store.database) + "-journal")
    target = tmp_path / "foreign-journal"
    target.write_bytes(b"")
    sidecar.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        store.status()


@pytest.fixture
def cache_store(tmp_path):
    result = StudyStore(tmp_path / "study")
    result.initialize(plan())
    host = "example.org"
    urls = [f"https://{host}/resource?identifier={index}" for index in range(20)]
    workload = result.root / "classes" / host / "workload.json"
    write(workload, {"urls": urls})
    historical = result.root / "enrollment-attempts" / host / "probe/history.json"
    write(historical, {"retained_probe": "unused historical preparation bytes"})
    result.enroll({"hostname": host, "urls": urls, "workload_sha256": digest(workload),
        "runtime": {"source": {"neqo_commit": "d" * 40},
            "platform": "linux/amd64", "client_sha256": "e" * 64},
        "files": {path.relative_to(result.root).as_posix(): digest(path)
            for path in (workload, historical)}})
    return result, historical


def test_enrollment_cache_hashes_history_once_but_rehashes_new_raw_and_shared_inputs(cache_store, monkeypatch):
    store, historical = cache_store
    counts = {}
    original = store._file

    def counted(relative, digest=None):
        counts[relative] = counts.get(relative, 0) + 1
        return original(relative, digest)

    monkeypatch.setattr(store, "_file", counted)
    first = store.allocate_attempt("example.org", "undefended")
    path = receipt(store, first)
    value = json.loads(path.read_bytes())
    workload = "classes/example.org/workload.json"
    value["files"][workload] = digest(store.root / workload)
    write(path, value)
    store.commit_verified(path, validator=unit_raw_validator)
    second = store.allocate_attempt("example.org", "undefended")
    store.fail_attempt(second["attempt_id"], "controlled interruption")
    assert len(store.enrolled()) == 1
    assert counts[historical.relative_to(store.root).as_posix()] == 1
    assert counts[workload] >= 3
    assert counts[first["path"] + "/run.json"] >= 2
    # A new process/Store must authenticate the complete inventory again.
    new = StudyStore(store.root)
    new_calls = []
    new_file = new._file
    monkeypatch.setattr(new, "_file", lambda name, digest=None: (new_calls.append(name), new_file(name, digest))[1])
    new.enrolled()
    assert historical.relative_to(store.root).as_posix() in new_calls


@pytest.mark.parametrize("mutation", ["bytes", "mode", "inode", "ctime-restored-mtime"])
def test_cached_enrollment_metadata_changes_fail_before_reservation(cache_store, mutation):
    store, historical = cache_store
    store.enrolled()
    before = historical.stat()
    original = historical.read_bytes()
    if mutation == "bytes":
        historical.write_bytes(original.replace(b"unused", b"edited"))
    elif mutation == "mode":
        historical.chmod(0o400)
    elif mutation == "inode":
        historical.unlink(); historical.write_bytes(original); historical.chmod(before.st_mode & 0o7777)
    else:
        historical.chmod(0o400); historical.chmod(before.st_mode & 0o7777)
        os.utime(historical, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert historical.stat().st_mtime_ns == before.st_mtime_ns
        assert historical.stat().st_ctime_ns != before.st_ctime_ns
    with pytest.raises(ValueError, match="enrollment.*changed"):
        store.allocate_attempt("example.org", "undefended")
    assert store.status()["attempts"] == {}


def test_enrollment_cache_closes_initial_hash_toc_tou(cache_store, monkeypatch):
    store, historical = cache_store
    original = store._file
    name = historical.relative_to(store.root).as_posix()

    def changed_after_read(relative, digest=None):
        result = original(relative, digest)
        if relative == name:
            historical.write_bytes(historical.read_bytes().replace(b"unused", b"edited"))
        return result

    monkeypatch.setattr(store, "_file", changed_after_read)
    with pytest.raises(ValueError, match="initial hash"):
        store.allocate_attempt("example.org", "undefended")
    assert not store._enrollment_cache and store.status()["attempts"] == {}


def test_enrollment_cache_final_fence_catches_mutation_during_raw_verifier(cache_store):
    store, historical = cache_store
    attempt = store.allocate_attempt("example.org", "undefended")
    path = receipt(store, attempt)

    def changed(root, value):
        assert unit_raw_validator(root, value)
        historical.chmod(0o400)
        return True

    with pytest.raises(ValueError, match="enrollment.*changed"):
        store.commit_verified(path, validator=changed)
    assert store.status()["accepted_count"] == 0


def test_enrollment_cache_refuses_changed_inventory_authority_even_when_files_match(cache_store):
    store, _ = cache_store
    store.enrolled()
    with sqlite3.connect(store.database) as connection:
        row = connection.execute("SELECT inventory FROM classes").fetchone()
        # Equivalent JSON is still a changed SQLite authority key.
        connection.execute("UPDATE classes SET inventory=?", (json.dumps(json.loads(row[0])),))
    with pytest.raises(ValueError, match="enrollment.*changed"):
        store.allocate_attempt("example.org", "undefended")


def test_measured_index_includes_failed_duplicate_work_and_excludes_pilots_and_shared_bytes(store, monkeypatch):
    first = store.allocate_attempt("example.org", "undefended")
    path = publish(store, first, shared=True)
    value = json.loads(path.read_bytes()); value["attempt_wall_seconds"] = 12
    write(path, value)
    expected = sum((store.root / name).stat().st_size for name in value["files"]
        if name.startswith("corpus/")) + path.stat().st_size
    store.commit_verified(path, validator=unit_raw_validator)
    # Identical replay does not double-count bytes or measured work.
    store.commit_verified(path)
    failed = store.allocate_attempt("example.org", "undefended")
    store.fail_attempt(failed["attempt_id"], "failed backend", wall_seconds=8)
    duplicate = store.allocate_attempt("example.org", "undefended")
    repeated = receipt(store, duplicate)
    data = json.loads(repeated.read_bytes()); data["attempt_wall_seconds"] = 5
    write(repeated, data)
    with pytest.raises(DuplicateSession):
        store.commit_verified(repeated, validator=unit_raw_validator)
    # Coordinator records actual elapsed failure work after retaining collision.
    store.fail_attempt(duplicate["attempt_id"], "tuple collision", kind="duplicate", wall_seconds=7)
    pilot = store.allocate_attempt("example.org", "undefended")
    store.fail_attempt(pilot["attempt_id"], "pilot passed; zero credit", kind="pilot", wall_seconds=100)
    original = store._file
    monkeypatch.setattr(store, "_file", lambda name, digest=None: original(name, digest)
        if name == "study.json" else (_ for _ in ()).throw(AssertionError("status reread raw evidence")))
    result = store.status()
    measured = result["measurements_by_mode"]["undefended"]
    assert result["accepted_count"] == 1 and result["duplicate"] == 1 and result["failed"] == 2
    assert measured["accepted_wall_samples"] == 1 and measured["mean_accepted_wall_seconds"] == 12
    assert measured["formal_attempt_wall_samples"] == 3 and measured["formal_attempt_wall_seconds"] == 27
    assert measured["failed_wall_samples"] == measured["duplicate_wall_samples"] == measured["pilot_wall_samples"] == 1
    assert measured["accepted_per_attributable_attempt_hour"] == pytest.approx(3600 / 27)
    assert measured["accepted_retained_bytes_samples"] == 1
    assert measured["mean_accepted_retained_bytes"] == measured["accepted_retained_bytes"] == expected
    assert "not elapsed flight utilization" in measured["scope"]


def test_missing_wall_measurement_never_invents_rate_or_native_duration(store):
    attempt = store.allocate_attempt("example.org", "undefended")
    store.commit_verified(receipt(store, attempt), validator=unit_raw_validator)
    value = store.status()["measurements_by_mode"]["undefended"]
    assert value["accepted_wall_samples"] == value["formal_attempt_wall_samples"] == 0
    assert value["mean_accepted_wall_seconds"] is None
    assert value["accepted_per_attributable_attempt_hour"] is None
    assert value["accepted_retained_bytes_samples"] == 1 and value["mean_accepted_retained_bytes"] > 0


@pytest.mark.parametrize("wall", [True, -1, "12", float("inf"), float("nan"), 10 ** 400])
def test_invalid_wall_measurements_refuse_without_changing_attempt(store, wall):
    attempt = store.allocate_attempt("example.org", "undefended")
    with pytest.raises(ValueError, match="wall time"):
        store.fail_attempt(attempt["attempt_id"], "fixture failure", wall_seconds=wall)
    assert store.status()["reserved"] == 1 and store.status()["failed"] == 0


def test_additive_measurement_index_restores_no_unmeasured_legacy_claims(store):
    attempt = store.allocate_attempt("example.org", "undefended")
    store.commit_verified(receipt(store, attempt), validator=unit_raw_validator)
    with sqlite3.connect(store.database) as connection:
        connection.execute("DROP TABLE measurements")
    result = StudyStore(store.root).status()
    assert result["accepted_count"] == 1
    measured = result["measurements_by_mode"]["undefended"]
    assert measured["accepted_wall_samples"] == measured["accepted_retained_bytes_samples"] == 0
    assert measured["mean_accepted_wall_seconds"] is None and measured["mean_accepted_retained_bytes"] is None


@pytest.mark.parametrize("field,value", [("schema_version", True), ("class_count", 49),
    ("resources_per_session", 19), ("sessions_per_mode", 64), ("total_sessions", 16000),
    ("modes", ["undefended"]), ("record_type", "historical-study"), ("accepted_count", 1)])
def test_initialize_refuses_changed_scope(tmp_path, field, value):
    supplied = plan(); supplied[field] = value
    with pytest.raises(ValueError):
        StudyStore(tmp_path / "study").initialize(supplied)
    assert not (tmp_path / "study").exists()


def test_enrollment_retains_queries_and_order_without_credit(store):
    value = store.enrolled()[0]
    assert [url.rsplit("=", 1)[1] for url in value["urls"]] == [str(index) for index in range(20)]
    assert store.enroll(value) == value
    assert store.status()["enrolled_count"] == 1
    assert len(store.status()["cells"]) == 5 and store.status()["accepted_count"] == 0
    value["urls"].reverse()
    with pytest.raises(ValueError, match="different immutable enrollment"):
        store.enroll(value)


@pytest.mark.parametrize("change", ["short", "duplicate", "different-host", "http", "credential", "fragment", "unsafe-file", "workload-sha", "runtime", "credit"])
def test_enrollment_refuses_invalid_resources_or_authority(store, change):
    value = store.enrolled()[0]
    if change == "short": value["urls"].pop()
    elif change == "duplicate": value["urls"][-1] = value["urls"][0]
    elif change == "different-host": value["urls"][0] = "https://other.org/one"
    elif change == "http": value["urls"][0] = value["urls"][0].replace("https:", "http:")
    elif change == "credential": value["urls"][0] = "https://user@example.org/one"
    elif change == "fragment": value["urls"][0] += "#not-a-new-resource"
    elif change == "unsafe-file": value["files"] = {"../outside.json": "a" * 64}
    elif change == "workload-sha": value["workload_sha256"] = "a" * 64
    elif change == "runtime": value["runtime"] = {}
    else: value["accepted_count"] = 1
    with pytest.raises((ValueError, FileNotFoundError)):
        store.enroll(value)


@pytest.mark.parametrize("change", ["bytes", "mode", "symlink", "hardlink"])
def test_enrolled_input_fence_closes_before_reservation(store, change):
    path = store.root / "classes/example.org/workload.json"
    if change == "bytes": path.write_bytes(b"changed\n")
    elif change == "mode": path.chmod(0o4600)
    elif change == "symlink":
        saved = path.with_name("saved.json"); path.rename(saved); path.symlink_to(saved)
    else: path.with_name("linked.json").hardlink_to(path)
    with pytest.raises((ValueError, FileNotFoundError)):
        store.allocate_attempt("example.org", "front")


@pytest.mark.parametrize("host,mode", [("../escape", "front"), ("EXAMPLE.org", "front"),
    ("bad_host.org", "front"), ("example.org", "csbuflo"), ("example.org", "../front")])
def test_allocator_refuses_unsafe_host_or_mode(store, host, mode):
    with pytest.raises(ValueError): store.allocate_attempt(host, mode)


def test_attempt_reservations_are_independent_monotonic_and_no_overwrite(store):
    first = store.allocate_attempt("example.org", "front")
    assert first["slot"] == first["attempt"] == 1
    assert (store.root / first["path"]).is_dir()
    other = StudyStore(store.root)
    with pytest.raises(ValueError, match="active reservation"):
        other.allocate_attempt("example.org", "front")
    second_mode = other.allocate_attempt("example.org", "tamaraw")
    assert second_mode["slot"] == 1
    marker = store.root / first["path"] / "failed.raw"; marker.write_bytes(b"preserve")
    store.fail_attempt(first["attempt_id"], "transport failed")
    next_attempt = other.allocate_attempt("example.org", "front")
    assert (next_attempt["slot"], next_attempt["attempt"]) == (1, 2)
    assert next_attempt["attempt_id"] != first["attempt_id"] and marker.read_bytes() == b"preserve"


def test_reservation_is_committed_before_attempt_directory_birth(store, monkeypatch):
    original = Path.mkdir
    def mkdir(path, *args, **kwargs):
        if path.name.startswith("attempt-"):
            with sqlite3.connect(store.database) as connection:
                assert connection.execute("SELECT count(*) FROM attempts WHERE state='reserved'").fetchone()[0] == 1
            raise OSError("controlled filesystem failure before traffic")
        return original(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(Path, "mkdir", mkdir)
        with pytest.raises(OSError): store.allocate_attempt("example.org", "buflo")
    assert store.status()["failed"] == 1
    assert store.allocate_attempt("example.org", "buflo")["attempt"] == 2


def test_concurrent_connections_reserve_one_cell_only(store):
    barrier = threading.Barrier(4)
    def allocate(_):
        barrier.wait()
        try: return StudyStore(store.root).allocate_attempt("example.org", "front")
        except ValueError: return None
    with ThreadPoolExecutor(max_workers=4) as pool: rows = list(pool.map(allocate, range(4)))
    assert sum(row is not None for row in rows) == 1
    assert store.status()["reserved"] == 1


def test_first_credit_needs_independent_raw_validation_and_replay_is_exact(store):
    attempt = store.allocate_attempt("example.org", "undefended"); path = receipt(store, attempt)
    with pytest.raises(ValueError, match="independent raw validator"):
        store.commit_verified(path)
    assert store.status()["unverified"] == 1 and store.status()["accepted_count"] == 0
    assert store.commit_verified(path, validator=unit_raw_validator)["idempotent"] is False
    assert StudyStore(store.root).commit_verified(path)["idempotent"] is True
    assert store.status()["accepted_count"] == 1
    assert store.allocate_attempt("example.org", "undefended")["slot"] == 2
    with pytest.raises(ValueError): store.fail_attempt(attempt["attempt_id"], "overwrite accepted")


@pytest.mark.parametrize("result", [None, False, {"verified": 1}, {"verified": False}])
def test_unconfirmed_validator_never_credits(store, result):
    attempt = store.allocate_attempt("example.org", "front")
    with pytest.raises(ValueError, match="did not pass"):
        store.commit_verified(receipt(store, attempt), validator=lambda *args: result)
    assert store.status()["accepted_count"] == 0


def test_real_fixture_raw_failure_is_not_promoted_by_verified_flag(store):
    attempt = store.allocate_attempt("example.org", "front"); path = receipt(store, attempt)
    value = json.loads(path.read_bytes()); raw = store.root / next(iter(value["files"]))
    value["files"][raw.relative_to(store.root).as_posix()] = write(raw, {"completed": False})
    write(path, value)
    with pytest.raises(ValueError, match="did not pass"): store.commit_verified(path, validator=unit_raw_validator)
    assert store.status()["accepted_count"] == 0


@pytest.mark.parametrize("change", ["verified-int", "schema-bool", "wrong-attempt", "wrong-slot", "wrong-mode", "tuple-bool", "tuple-address", "outside", "sha", "linked-receipt", "borrowed-attempt"])
def test_malicious_receipt_refuses_before_callback(store, change):
    attempt = store.allocate_attempt("example.org", "front"); path = receipt(store, attempt)
    value = json.loads(path.read_bytes())
    if change == "verified-int": value["verified"] = 1
    elif change == "schema-bool": value["schema_version"] = True
    elif change == "wrong-attempt": value["attempt_id"] = "0" * 32
    elif change == "wrong-slot": value["slot"] = 2
    elif change == "wrong-mode": value["mode"] = "buflo"
    elif change == "tuple-bool": value["five_tuple"][1] = True
    elif change == "tuple-address": value["five_tuple"][0] = "0.0.0.0"
    elif change == "outside": value["files"] = {"../secret": "a" * 64}
    elif change == "sha": value["files"][next(iter(value["files"]))] = "a" * 64
    elif change == "borrowed-attempt":
        other = store.allocate_attempt("example.org", "tamaraw"); borrowed = receipt(store, other)
        value["files"] = json.loads(borrowed.read_bytes())["files"]
    if change == "linked-receipt":
        saved = path.with_name("held.json"); path.rename(saved); path.symlink_to(saved)
    else: write(path, value)
    with pytest.raises((ValueError, FileNotFoundError)):
        store.commit_verified(path, validator=lambda *args: pytest.fail("invalid receipt reached validator"))
    assert store.status()["accepted_count"] == 0


@pytest.mark.parametrize("change", ["raw-bytes", "raw-mode", "receipt-bytes", "receipt-mode", "study-bytes", "enrollment-mode"])
def test_validator_closing_fence_refuses_mid_verification_mutation(store, change):
    attempt = store.allocate_attempt("example.org", "front"); path = receipt(store, attempt)
    def validator(root, value):
        raw = root / next(iter(value["files"]))
        if change == "raw-bytes": raw.write_bytes(b"changed after check")
        elif change == "raw-mode": raw.chmod(0o1600)
        elif change == "receipt-bytes": path.write_bytes(path.read_bytes() + b" ")
        elif change == "receipt-mode": path.chmod(0o400)
        elif change == "study-bytes":
            (root / "study.json").chmod(0o644); (root / "study.json").write_bytes(b"changed")
        else: (root / "classes/example.org/enrollment.json").chmod(0o400)
        return True
    with pytest.raises(ValueError): store.commit_verified(path, validator=validator)
    with sqlite3.connect(store.database) as connection:
        assert connection.execute("SELECT count(*) FROM accepted").fetchone()[0] == 0


def test_tuple_collision_is_preserved_uncredited_and_scope_is_per_cell(store):
    first = store.allocate_attempt("example.org", "front")
    store.commit_verified(receipt(store, first), validator=unit_raw_validator)
    repeated = store.allocate_attempt("example.org", "front")
    path = receipt(store, repeated)
    with pytest.raises(DuplicateSession): store.commit_verified(path, validator=unit_raw_validator)
    assert path.exists() and store.status()["duplicate"] == 1 and store.status()["accepted_count"] == 1
    replacement = store.allocate_attempt("example.org", "front")
    assert (replacement["slot"], replacement["attempt"]) == (2, 3)
    mode = store.allocate_attempt("example.org", "buflo")
    store.commit_verified(receipt(store, mode), validator=unit_raw_validator)
    assert store.status()["accepted_count"] == 2


def test_ipv6_equivalent_spellings_cannot_evade_tuple_dedup(store):
    first = store.allocate_attempt("example.org", "front"); path = receipt(store, first)
    value = json.loads(path.read_bytes()); value["five_tuple"][0] = "2001:db8::1"; value["five_tuple"][2] = "2001:db8::2"
    write(path, value); store.commit_verified(path, validator=unit_raw_validator)
    second = store.allocate_attempt("example.org", "front"); path = receipt(store, second)
    value = json.loads(path.read_bytes()); value["five_tuple"][0] = "2001:0db8:0:0:0:0:0:1"; value["five_tuple"][2] = "2001:0db8:0:0:0:0:0:2"
    write(path, value)
    with pytest.raises(DuplicateSession): store.commit_verified(path, validator=unit_raw_validator)


def test_recovery_preserves_pending_evidence_and_fails_uncaptured_reservations(store):
    accepted = store.allocate_attempt("example.org", "front")
    store.commit_verified(receipt(store, accepted), validator=unit_raw_validator)
    interrupted = store.allocate_attempt("example.org", "front")
    raw = store.root / interrupted["path"] / "partial.pcapng"; raw.write_bytes(b"retain original failed bytes")
    captured = store.allocate_attempt("example.org", "buflo"); path = receipt(store, captured)
    with pytest.raises(ValueError): store.commit_verified(path)
    result = StudyStore(store.root).recover()
    assert result["interrupted"] == [interrupted["attempt_id"]]
    assert result["pending_verification"][0]["attempt_id"] == captured["attempt_id"]
    assert result["accepted_count"] == 1 and result["files_deleted"] == 0 and raw.exists()
    assert store.allocate_attempt("example.org", "front")["slot"] == 2
    assert store.commit_verified(path, validator=unit_raw_validator)["accepted"]


def test_recovery_handles_crash_before_directory_creation(store):
    attempt = store.allocate_attempt("example.org", "front")
    (store.root / attempt["path"]).rmdir()  # explicit crash-shape fixture, no evidence existed
    assert store.recover()["interrupted"] == [attempt["attempt_id"]]
    assert store.allocate_attempt("example.org", "front")["attempt"] == 2


def test_export_is_create_only_and_incomplete_claim_stays_false(store, tmp_path):
    attempt = store.allocate_attempt("example.org", "front"); path = receipt(store, attempt)
    store.commit_verified(path, validator=unit_raw_validator)
    output = tmp_path / "snapshot.json"
    value = store.export_manifest(output)
    assert value["accepted_count"] == 1 and value["complete"] is False and value["scientific_credit"] is False
    assert value["accepted"][0]["receipt_sha256"] == digest(path)
    assert not value["accepted"][0]["receipt_path"].startswith("/")
    with pytest.raises(FileExistsError): store.export_manifest(output)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError): store.export_manifest(tmp_path / "changed.json")


def test_same_receipt_concurrent_commit_is_idempotent(store):
    attempt = store.allocate_attempt("example.org", "front"); path = receipt(store, attempt)
    barrier = threading.Barrier(2)
    def validator(root, value): barrier.wait(); return unit_raw_validator(root, value)
    def commit(_): return StudyStore(store.root).commit_verified(path, validator=validator)
    with ThreadPoolExecutor(max_workers=2) as pool: values = list(pool.map(commit, range(2)))
    assert sorted(value["idempotent"] for value in values) == [False, True]
    assert store.status()["accepted_count"] == 1


def publish(store, attempt, *, shared=False, runtime=None):
    path = receipt(store, attempt)
    value = json.loads(path.read_bytes())
    destination = store.root / f'corpus/{attempt["hostname"]}/{attempt["mode"]}/session-{attempt["slot"]:06d}'
    destination.parent.mkdir(parents=True, exist_ok=True)
    path.parent.rename(destination)
    path = destination / "verification.json"; path.unlink()  # unit publication replaces only its unbound draft
    value["files"] = {name.replace(attempt["path"], destination.relative_to(store.root).as_posix(), 1): sha for name, sha in value["files"].items()}
    if shared:
        enrollment = store.enrolled()[0]
        value["files"].update(enrollment["files"])
        enrolled_path = f'classes/{attempt["hostname"]}/enrollment.json'
        value["files"][enrolled_path] = digest(store.root / enrolled_path)
    if runtime is not None: value["runtime"] = runtime
    path = destination / "session.json"; write(path, value)
    return path


def test_published_corpus_allows_only_exact_enrolled_shared_inputs(store):
    attempt = store.allocate_attempt("example.org", "front")
    path = publish(store, attempt, shared=True)
    assert store.commit_verified(path, validator=unit_raw_validator)["accepted"]
    assert store.status()["accepted_count"] == 1


@pytest.mark.parametrize("change", ["wrong-slot", "foreign-class", "unregistered-shared", "shared-digest", "shared-mode"])
def test_corpus_refuses_foreign_slot_or_shared_authority(store, change):
    attempt = store.allocate_attempt("example.org", "front")
    path = publish(store, attempt, shared=True)
    value = json.loads(path.read_bytes())
    if change == "wrong-slot":
        wrong = path.parent.with_name("session-000002"); path.parent.rename(wrong); path = wrong / "session.json"
        value["files"] = {name.replace("session-000001", "session-000002"): sha for name, sha in value["files"].items()}
    elif change == "foreign-class":
        enrollment = enroll(store, "other.org"); value["files"].update(enrollment["files"])
    elif change == "unregistered-shared":
        extra = store.root / "classes/example.org/unregistered.json"; write(extra, {"unit": True})
        value["files"][extra.relative_to(store.root).as_posix()] = digest(extra)
    elif change == "shared-digest":
        raw = store.root / "classes/example.org/workload.json"; raw.write_bytes(b"replaced shared workload")
        value["files"][raw.relative_to(store.root).as_posix()] = digest(raw)
    else: (store.root / "classes/example.org/workload.json").chmod(0o1600)
    write(path, value)
    with pytest.raises(ValueError):
        store.commit_verified(path, validator=lambda *args: pytest.fail("foreign corpus/input reached validator"))
    assert store.status()["accepted_count"] == 0


def test_recover_discovers_published_receipt_before_ledger_commit(store):
    attempt = store.allocate_attempt("example.org", "front"); store.mark_captured(attempt["attempt_id"])
    path = publish(store, attempt, shared=True)
    assert not (store.root / attempt["path"]).exists()
    result = StudyStore(store.root).recover()
    assert result["interrupted"] == [] and result["accepted_count"] == 0
    assert result["pending_verification"] == [{"attempt_id": attempt["attempt_id"],
        "receipt_path": path.relative_to(store.root).as_posix(), "receipt_sha256": digest(path)}]
    with pytest.raises(ValueError, match="active reservation"):
        store.allocate_attempt("example.org", "front")
    assert store.commit_verified(path, validator=unit_raw_validator)["accepted"]


def test_recovery_retains_unfinished_corpus_publication_without_reusing_slot(store):
    attempt = store.allocate_attempt("example.org", "front")
    destination = store.root / "corpus/example.org/front/session-000001"
    destination.mkdir(parents=True); raw = destination / "run.partial"; raw.write_bytes(b"preserve incomplete publication")
    recovered = store.recover()
    assert recovered["interrupted"] == []
    assert recovered["pending_verification"][0]["receipt_path"] is None and raw.exists()
    with pytest.raises(ValueError, match="active reservation"):
        store.allocate_attempt("example.org", "front")


def test_runtime_orchestration_renewal_preserves_scientific_identity(store):
    runtime = deepcopy(store.enrolled()[0]["runtime"])
    runtime["source"]["lab_commit"] = "b" * 40
    runtime["image_digest"] = "sha256:" + "0" * 64
    runtime["actual_sdk_provenance"] = "new truthful unit SDK receipt"
    attempt = store.allocate_attempt("example.org", "front")
    path = publish(store, attempt, runtime=runtime)
    assert store.commit_verified(path, validator=unit_raw_validator)["accepted"]
    assert json.loads(path.read_bytes())["runtime"] == runtime


@pytest.mark.parametrize("change", ["client", "platform", "native", "mode-settings"])
def test_runtime_scientific_or_mode_setting_changes_refuse(store, change):
    runtime = deepcopy(store.enrolled()[0]["runtime"])
    if change == "client": runtime["client_sha256"] = "f" * 64
    elif change == "platform": runtime["platform"] = "linux/arm64"
    elif change == "native": runtime["source"]["neqo_commit"] = "a" * 40
    attempt = store.allocate_attempt("example.org", "front")
    path = publish(store, attempt, runtime=runtime)
    if change == "mode-settings":
        value = json.loads(path.read_bytes()); value["mode_settings"] = {"different": "undeclared"}; write(path, value)
    with pytest.raises(ValueError): store.commit_verified(path, validator=unit_raw_validator)
    assert store.status()["accepted_count"] == 0
