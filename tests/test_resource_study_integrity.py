"""Disposable ledger controls, never real Native/raw scientific evidence.

The existing coordinator fixture checks twenty synthetic complete responses.
Only that raw boundary is synthetic; withdrawal, SQL, publication, duplicate
classification, recovery and public nonparent receipt discovery are real.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_integrity as integrity
from qcsd_lab.resource_study_store import StudyStore, DuplicateSession, _json

_spec = importlib.util.spec_from_file_location("integrity_coordinator_fixture", Path(__file__).with_name("test_resource_study.py"))
_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)
held, controlled_validator = _fixture.held, _fixture.controlled_validator
CaptureBackend, _runtime = _fixture.CaptureBackend, _fixture._runtime
_epoch_spec = importlib.util.spec_from_file_location("integrity_epoch_fixture", Path(__file__).with_name("test_resource_study_epochs.py"))
_epoch_fixture = importlib.util.module_from_spec(_epoch_spec)
_epoch_spec.loader.exec_module(_epoch_fixture)
roots = _epoch_fixture.roots


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def change(path, raw):
    path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(0o444)


def accepted(held, port=45001):
    root, store = held
    enrollment = store.enrolled()[0]
    attempt = store.allocate_attempt(enrollment["hostname"], "undefended")
    backend = CaptureBackend(root)
    backend.write_capture(attempt, enrollment, port)
    store.mark_captured(attempt["attempt_id"])
    path = study.seal(root, attempt, enrollment, _runtime(), {"success": True})
    store.commit_verified(path, validator=study.verify_receipt)
    return attempt, path


def damaged(held):
    attempt, receipt = accepted(held)
    root, store = held
    artifact = receipt.parent / "neqo/packets.csv"
    expected = digest(artifact)
    change(artifact, b"preserved controlled corruption; no physical packet claim\n")
    declaration = {"attempt_id": attempt["attempt_id"], "receipt_sha256": digest(receipt),
        "artifact_path": artifact.relative_to(root).as_posix(),
        "expected_sha256": expected, "actual_sha256": digest(artifact)}
    return attempt, receipt, artifact, declaration


def rows(store):
    with store._transaction() as connection:
        return {name: [list(row) for row in connection.execute(f"SELECT * FROM {name} ORDER BY 1")]
                for name in ("meta", "classes", "accepted", "attempts", "measurements")}


def preservation(directory):
    return {p.relative_to(directory).as_posix(): (p.read_bytes(), p.stat().st_ino,
            p.stat().st_mtime_ns, p.stat().st_ctime_ns, p.stat().st_mode)
            for p in directory.rglob("*") if p.is_file()}


def test_single_withdrawal_exact_rows_journal_and_idempotence(held):
    attempt, receipt, artifact, declaration = damaged(held)
    root, store = held
    original = preservation(receipt.parent)
    before = rows(store)
    result = integrity.withdraw_accepted(root, **declaration)
    assert result["record_type"] == integrity.RESULT_TYPE
    assert result["accepted_delta"] == -1 and result["scientific_credit_added"] == 0
    assert result["accepted_count_before"] == 1 and result["accepted_count_after"] == 0
    journal_path = root / "integrity-withdrawals" / (attempt["attempt_id"] + ".json")
    journal_raw = journal_path.read_bytes()
    journal = json.loads(journal_raw)
    assert journal_raw == _json(journal) and journal_path.stat().st_mode & 0o777 == 0o444
    assert journal["original"]["accepted9"] == before["accepted"][0]
    assert list(journal["original"]["attempt"].values()) != before["attempts"][0]  # JSON object order is not SQL order.
    assert journal["observation"]["declaration"] == declaration
    assert journal["observation"]["receipt"]["uid"] == receipt.stat().st_uid
    after = rows(store)
    assert after["meta"] == before["meta"] and after["classes"] == before["classes"]
    assert after["accepted"] == []
    with store._transaction() as connection:
        actual = integrity._rows(connection, attempt["attempt_id"])
        assert actual == result["sql_after"]
        added = [dict(row) for row in connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name LIKE '%integrity_withdrawals%' ORDER BY type,name")]
        assert added == integrity.schema_additions()
    assert store.status()["attempts"]["withdrawn"] == 1
    assert store.status()["measurements_by_mode"]["undefended"]["accepted_wall_samples"] == 0
    assert integrity.withdraw_accepted(root, **declaration) == result
    assert journal_path.read_bytes() == journal_raw and preservation(receipt.parent) == original
    with pytest.raises(ValueError, match="withdrawn receipt"):
        store.commit_verified(receipt, validator=study.verify_receipt)


@pytest.mark.parametrize("field", ["receipt_sha256", "expected_sha256", "actual_sha256", "artifact_path"])
def test_declaration_mismatch_refuses_without_journal_or_sql(held, field):
    _, _, _, declaration = damaged(held)
    root, store = held
    before = rows(store)
    declaration[field] = "0" * 64 if field != "artifact_path" else "study.json"
    with pytest.raises(ValueError):
        integrity.withdraw_accepted(root, **declaration)
    assert rows(store) == before
    assert not (root / "integrity-withdrawals").exists()


def test_second_mismatch_and_writable_artifact_refuse(held):
    _, receipt, artifact, declaration = damaged(held)
    root, store = held
    second = receipt.parent / "trace.csv"
    original = second.read_bytes()
    change(second, b"second mismatch")
    with pytest.raises(ValueError, match="single declared"):
        integrity.withdraw_accepted(root, **declaration)
    change(second, original)
    artifact.chmod(0o600)
    with pytest.raises(ValueError, match="metadata"):
        integrity.withdraw_accepted(root, **declaration)
    assert store.status()["accepted_count"] == 1


def test_foreign_artifact_owner_refuses_before_withdrawal(held, monkeypatch):
    _, _, _, declaration = damaged(held)
    root, store = held
    # Only descriptor metadata is synthetic; actual file/SQL/journal are real.
    monkeypatch.setattr(integrity.os, "fstat", lambda _: SimpleNamespace(st_uid=integrity.os.getuid() + 1))
    with pytest.raises(ValueError, match="custody UID"):
        integrity.withdraw_accepted(root, **declaration)
    assert store.status()["accepted_count"] == 1
    assert not (root / "integrity-withdrawals").exists()


def test_orphan_journal_replay_and_metadata_drift_refusal(held, monkeypatch):
    _, _, artifact, declaration = damaged(held)
    root, store = held
    install = integrity._install
    def crash(_):
        raise RuntimeError("synthetic crash after durable journal before SQL mutation")
    monkeypatch.setattr(integrity, "_install", crash)
    with pytest.raises(RuntimeError, match="synthetic crash"):
        integrity.withdraw_accepted(root, **declaration)
    journal_path = root / "integrity-withdrawals" / (declaration["attempt_id"] + ".json")
    original = journal_path.read_bytes()
    assert store.status()["accepted_count"] == 1
    monkeypatch.setattr(integrity, "_install", install)
    change(artifact, artifact.read_bytes())  # Same SHA, changed custody metadata.
    with pytest.raises(ValueError, match="metadata drift"):
        integrity.withdraw_accepted(root, **declaration)
    assert journal_path.read_bytes() == original and store.status()["accepted_count"] == 1


def test_orphan_journal_exact_replay_uses_original_timestamp(held, monkeypatch):
    _, _, _, declaration = damaged(held)
    root, store = held
    install = integrity._install
    monkeypatch.setattr(integrity, "_install", lambda _: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        integrity.withdraw_accepted(root, **declaration)
    path = root / "integrity-withdrawals" / (declaration["attempt_id"] + ".json")
    raw = path.read_bytes()
    monkeypatch.setattr(integrity, "_install", install)
    monkeypatch.setattr(integrity, "_now", lambda: pytest.fail("orphan replay changed timestamp"))
    integrity.withdraw_accepted(root, **declaration)
    assert path.read_bytes() == raw and store.status()["accepted_count"] == 0


def test_sql_rollback_after_delete_and_exact_retry(held, monkeypatch):
    _, _, _, declaration = damaged(held)
    root, store = held
    original = integrity._rows
    calls = 0
    def crash_after_changes(connection, identifier):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("crash before transaction commit")
        return original(connection, identifier)
    monkeypatch.setattr(integrity, "_rows", crash_after_changes)
    with pytest.raises(RuntimeError, match="before transaction"):
        integrity.withdraw_accepted(root, **declaration)
    assert store.status()["accepted_count"] == 1
    monkeypatch.setattr(integrity, "_rows", original)
    integrity.withdraw_accepted(root, **declaration)
    assert store.status()["accepted_count"] == 0


@pytest.mark.parametrize("fence", ["file", "symlink", "schema"])
def test_physical_and_schema_v3_fences_refuse(held, fence):
    _, _, _, declaration = damaged(held)
    root, store = held
    if fence == "schema":
        with sqlite3.connect(store.database) as connection:
            connection.execute("CREATE TABLE qcsd_class_v3_fake(value TEXT)")
    elif fence == "symlink":
        (root / "class-write-fence.json").symlink_to(root / "missing")
    else:
        (root / "class-write-fence.json").write_bytes(b"{}")
    with pytest.raises(ValueError):
        integrity.withdraw_accepted(root, **declaration)
    with sqlite3.connect(store.database) as connection:
        assert connection.execute("SELECT count(*) FROM accepted").fetchone()[0] == 1
    assert not (root / "integrity-withdrawals").exists()


def test_withdrawn_tuple_direct_sql_and_duplicate_classification(held):
    _, receipt, _, declaration = damaged(held)
    root, store = held
    result = integrity.withdraw_accepted(root, **declaration)
    original = result["sql_before"]["accepted"]
    with store._transaction() as connection:
        for spelling in (original["five_tuple"], json.dumps(json.loads(original["five_tuple"]), separators=(",", ":"))):
            values = list(original.values())
            values[3] = spelling
            with pytest.raises(sqlite3.IntegrityError, match="withdrawn five-tuple"):
                connection.execute("INSERT INTO accepted VALUES(?,?,?,?,?,?,?,?,?)", values)
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("DELETE FROM integrity_withdrawals")
    original_bytes = preservation(receipt.parent)
    attempt = store.allocate_attempt("alpha.example", "undefended")
    assert attempt["slot"] == 1 and store.publication_path(attempt) == attempt["path"] + "/verified"
    enrollment = store.enrolled()[0]
    CaptureBackend(root).write_capture(attempt, enrollment, 45001)
    store.mark_captured(attempt["attempt_id"])
    replacement = study.seal(root, attempt, enrollment, _runtime(), {"success": True})
    with pytest.raises(DuplicateSession, match="withdrawn tuple"):
        store.commit_verified(replacement, validator=study.verify_receipt)
    assert preservation(receipt.parent) == original_bytes
    assert store.status()["duplicate"] == 1 and store.status()["accepted_count"] == 0


def test_replacement_seal_recover_public_verify_never_reads_old_receipt(held, monkeypatch):
    _, original, _, declaration = damaged(held)
    root, store = held
    integrity.withdraw_accepted(root, **declaration)
    preserved = preservation(original.parent)
    attempt = store.allocate_attempt("alpha.example", "undefended")
    enrollment = store.enrolled()[0]
    CaptureBackend(root).write_capture(attempt, enrollment, 45002)
    store.mark_captured(attempt["attempt_id"])
    replacement = study.seal(root, attempt, enrollment, _runtime(), {"success": True})
    assert replacement == root / attempt["path"] / "verified/session.json"
    old_reader = StudyStore._receipt
    def guarded(self, path):
        assert path != original
        return old_reader(self, path)
    monkeypatch.setattr(StudyStore, "_receipt", guarded)
    recovered = store.recover()
    assert recovered["pending_verification"][0]["receipt_path"] == replacement.relative_to(root).as_posix()
    result = study.verify(root, all_receipts=True)
    assert result["errors"] == [] and result["verified_receipts"] == 1
    assert result["progress"]["accepted_count"] == 1 and result["progress"]["attempts"]["withdrawn"] == 1
    assert preservation(original.parent) == preserved
    assert study.verify(root, all_receipts=True)["errors"] == []
    assert study.coordinator_provenance()["files"]["resource_study_integrity.py"] == digest(__import__("pathlib").Path(integrity.__file__))


def test_actual_capture_duplicate_cleanup_preserves_original_corpus(held):
    root, store = held
    attempt, receipt = accepted(held, port=42000)
    artifact = receipt.parent / "neqo/packets.csv"
    expected = digest(artifact)
    change(artifact, b"controlled damaged raw file")
    integrity.withdraw_accepted(root, attempt_id=attempt["attempt_id"], receipt_sha256=digest(receipt),
        artifact_path=artifact.relative_to(root).as_posix(), expected_sha256=expected, actual_sha256=digest(artifact))
    original = preservation(receipt.parent)
    backend = CaptureBackend(root, repeat_tuple=True)
    result = study.capture(root, _runtime(), backend=backend, hostnames=["alpha.example"],
        modes=("undefended",), budget=1, chunk_sessions=1)
    fresh = backend.calls[0][1]
    assert result["progress"]["accepted_count"] == 0 and result["progress"]["duplicate"] == 1
    assert preservation(receipt.parent) == original
    assert (root / "failures/alpha.example/undefended" / fresh["attempt_id"] / "session.json").is_file()
    assert not (root / fresh["path"] / "verified").exists()


def test_recovery_without_new_publication_ignores_withdrawn_slot(held, monkeypatch):
    _, receipt, _, declaration = damaged(held)
    root, store = held
    integrity.withdraw_accepted(root, **declaration)
    before = preservation(receipt.parent)
    attempt = store.allocate_attempt("alpha.example", "undefended")
    monkeypatch.setattr(StudyStore, "_receipt", lambda *args: pytest.fail("recovery inspected old withdrawn receipt"))
    result = store.recover()
    assert result["interrupted"] == [attempt["attempt_id"]] and result["pending_verification"] == []
    assert preservation(receipt.parent) == before


def test_committed_replay_refuses_row_and_schema_drift(held):
    _, _, _, declaration = damaged(held)
    root, store = held
    integrity.withdraw_accepted(root, **declaration)
    with store._transaction() as connection:
        connection.execute("UPDATE attempts SET reason='changed' WHERE attempt_id=?", (declaration["attempt_id"],))
    with pytest.raises(ValueError, match="rows or count drift"):
        integrity.withdraw_accepted(root, **declaration)
    with sqlite3.connect(store.database) as connection:
        connection.execute("DROP TRIGGER integrity_withdrawals_accepted_insert")
    with pytest.raises(ValueError, match="schema changed"):
        store.publication_path({"hostname": "alpha.example", "mode": "undefended", "slot": 1, "path": "attempts/fresh"})


@pytest.mark.parametrize("lost", ["journal", "whole-schema"])
def test_lost_withdrawal_protection_cannot_restore_old_publication_path(held, lost):
    _, _, _, declaration = damaged(held)
    root, store = held
    integrity.withdraw_accepted(root, **declaration)
    if lost == "journal":
        path = root / "integrity-withdrawals" / (declaration["attempt_id"] + ".json")
        change(path, path.read_bytes() + b" ")
    else:
        with sqlite3.connect(store.database) as connection:
            for name in integrity.SCHEMA:
                if name != integrity.TABLE:
                    connection.execute(f"DROP TRIGGER {name}")
            connection.execute("DROP TABLE integrity_withdrawals")
    with pytest.raises(ValueError):
        store.publication_path({"hostname": "alpha.example", "mode": "undefended", "slot": 1, "path": "attempts/fresh"})


def test_normal_publication_and_recovery_path_unchanged(held):
    root, store = held
    attempt = store.allocate_attempt("alpha.example", "undefended")
    assert store.publication_path(attempt) == "corpus/alpha.example/undefended/session-000001"
    assert store.recover()["interrupted"] == [attempt["attempt_id"]]
    with sqlite3.connect(store.database) as connection:
        assert not connection.execute("SELECT 1 FROM sqlite_master WHERE name GLOB 'integrity_withdrawals*'").fetchone()


def test_real_parent_epoch_scope_and_other_participant_fence(roots):
    # Existing fixture controls preparation/raw proof only. Genuine epoch
    # publication, ancestry reader, membership, locks and withdrawal run here.
    parent, child = roots("parent"), roots("child", parameter=1)
    epochs = _epoch_fixture.epochs
    epochs.create_epoch(parent.root, child.root, change="mode", affected_modes=["front"])
    attempt = parent._allocate_attempt("beta.example", "undefended")
    receipt = _epoch_fixture.receipt(parent, attempt)
    parent._commit_verified(receipt, validator=lambda root, value: {"verified": True})
    artifact = parent.root / attempt["path"] / "raw.bin"
    expected = digest(artifact)
    change(artifact, b"controlled mismatch in retained original parent")
    declaration = {"attempt_id": attempt["attempt_id"], "receipt_sha256": digest(receipt),
        "artifact_path": artifact.relative_to(parent.root).as_posix(), "expected_sha256": expected, "actual_sha256": digest(artifact)}
    fence = child.root / "class-write-fence.json"
    fence.symlink_to(child.root / "missing-manifest")
    with pytest.raises(ValueError, match="physical write fence"):
        integrity.withdraw_accepted(parent.root, **declaration)
    fence.unlink()  # Disposable fixture only, never a production-fence removal.
    result = integrity.withdraw_accepted(parent.root, **declaration)
    journal = json.loads(Path(result["journal"]["path"]).read_bytes())
    assert journal["parent_scope"]["parent"] == str(parent.root)
    assert {row["root"] for row in journal["parent_scope"]["members"]} == {str(parent.root), str(child.root)}
    assert len(journal["parent_scope"]["admissions"]) == 2
    assert result["accepted_delta"] == -1
