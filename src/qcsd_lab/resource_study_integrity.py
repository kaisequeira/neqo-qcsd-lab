"""Explicit single-receipt withdrawal; never a scientific verification result.

Caller must already own global quiet lifecycle custody. This library also owns
the existing parent epoch lock. It preserves the damaged recording verbatim,
and refuses stable-map ledgers whose categorical DELETE fences need a separate
protocol. There is deliberately no public capture/recovery CLI default here.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat

from .resource_study_store import StudyStore, _create, _digest, _json, _load, _now, _unlinked

JOURNAL_TYPE = "qcsd-resource-study-single-withdrawal-journal-v1"
RESULT_TYPE = "qcsd-resource-study-single-withdrawal-result-v1"
TABLE = "integrity_withdrawals"
SCHEMA = {
    TABLE: "CREATE TABLE integrity_withdrawals(attempt_id TEXT PRIMARY KEY REFERENCES attempts(attempt_id), hostname TEXT NOT NULL, mode TEXT NOT NULL, slot INTEGER NOT NULL, five_tuple TEXT NOT NULL, journal_path TEXT UNIQUE NOT NULL, journal_sha256 TEXT NOT NULL, UNIQUE(hostname,mode,five_tuple))",
    "integrity_withdrawals_no_delete": "CREATE TRIGGER integrity_withdrawals_no_delete BEFORE DELETE ON integrity_withdrawals BEGIN SELECT RAISE(ABORT,'integrity withdrawal is immutable'); END",
    "integrity_withdrawals_no_update": "CREATE TRIGGER integrity_withdrawals_no_update BEFORE UPDATE ON integrity_withdrawals BEGIN SELECT RAISE(ABORT,'integrity withdrawal is immutable'); END",
    "integrity_withdrawals_accepted_insert": "CREATE TRIGGER integrity_withdrawals_accepted_insert BEFORE INSERT ON accepted WHEN EXISTS(SELECT 1 FROM integrity_withdrawals WHERE hostname=NEW.hostname AND mode=NEW.mode AND json(five_tuple)=json(NEW.five_tuple)) BEGIN SELECT RAISE(ABORT,'withdrawn five-tuple cannot receive credit'); END",
    "integrity_withdrawals_accepted_update": "CREATE TRIGGER integrity_withdrawals_accepted_update BEFORE UPDATE ON accepted WHEN EXISTS(SELECT 1 FROM integrity_withdrawals WHERE hostname=NEW.hostname AND mode=NEW.mode AND json(five_tuple)=json(NEW.five_tuple)) BEGIN SELECT RAISE(ABORT,'withdrawn five-tuple cannot receive credit'); END",
}


def schema_declaration():
    """Exact explicit sqlite_master additions (SQLite autoindices excluded)."""
    return [{"type": "table" if name == TABLE else "trigger", "name": name,
             "tbl_name": TABLE if name == TABLE or name.endswith(("no_delete", "no_update")) else "accepted",
             "sql": sql} for name, sql in SCHEMA.items()]


def schema_additions():
    """Complete new schema rows for an exact external recovery comparison."""
    return sorted(schema_declaration() + [
        {"type": "index", "name": f"sqlite_autoindex_{TABLE}_{number}", "tbl_name": TABLE, "sql": None}
        for number in (1, 2, 3)], key=lambda row: (row["type"], row["name"]))


def validate_schema(connection):
    rows = [dict(row) for row in connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name GLOB 'integrity_withdrawals*' ORDER BY name")]
    if rows and rows != sorted(schema_declaration(), key=lambda row: row["name"]):
        raise ValueError("integrity withdrawal schema changed")
    return bool(rows)


def _install(connection):
    if not validate_schema(connection):
        for sql in SCHEMA.values():
            connection.execute(sql)
    validate_schema(connection)


def _observe(store, relative):
    """Hash one immutable file with stable descriptor and path identity."""
    path = _unlinked(store._relative(relative))
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if before.st_uid != os.getuid():
            raise ValueError("immutable artifact owner differs from current custody UID")
        digest = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            digest.update(block)
        after = os.fstat(descriptor)
        current = _unlinked(path).stat()
        def identity(info):
            return {"device": info.st_dev, "inode": info.st_ino, "bytes": info.st_size,
                    "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
                    "mode": stat.S_IMODE(info.st_mode), "nlink": info.st_nlink,
                    "uid": info.st_uid, "gid": info.st_gid}
        if identity(before) != identity(after) or identity(after) != identity(current) or stat.S_IMODE(after.st_mode) != 0o444:
            raise ValueError("immutable artifact metadata changed during observation")
        return {"path": relative, "sha256": digest.hexdigest(), **identity(after)}
    finally:
        os.close(descriptor)


def _ref(store, relative):
    observed = _observe(store, relative)
    return {"path": str(store.root / relative), "sha256": observed["sha256"]}


def _physical_fence(store, connection=None):
    fence = store.root / "class-write-fence.json"
    if fence.exists() or fence.is_symlink():
        raise ValueError("integrity withdrawal refuses V3 physical write fence")
    if connection is None:
        # Detect schema-only fences before Store registers their denying SQL
        # functions; a missing physical manifest must still be an explicit
        # refusal, and this census never creates or repairs a database.
        _unlinked(store.database)
        connection = sqlite3.connect(store.database.as_uri() + "?mode=ro", uri=True)
        try:
            return _physical_fence(store, connection)
        finally:
            connection.close()
    if connection.execute("SELECT 1 FROM sqlite_master WHERE name GLOB 'qcsd_class_v3_*'").fetchone():
        raise ValueError("integrity withdrawal refuses V3 schema write fence")


def _scope(store, parent):
    from .resource_study_epochs import _records
    records = _records(parent)
    if any("class_transition" in row or "write_fences" in row for row in records):
        raise ValueError("integrity withdrawal refuses committed V3 transition")
    roots = sorted({str(store.root), str(parent.root), *(cell["root"] for row in records for cell in row["cells"])})
    members = []
    for root in roots:
        member = StudyStore(root)
        _physical_fence(member)
        member.plan()
        with member._transaction() as connection:
            _physical_fence(member, connection)
            if connection.execute("SELECT 1 FROM attempts WHERE state IN ('reserved','captured','unverified')").fetchone():
                raise ValueError("integrity withdrawal requires every participant quiescent")
            meta = [list(row) for row in connection.execute("SELECT * FROM meta ORDER BY key")]
            classes = [list(row) for row in connection.execute("SELECT * FROM classes ORDER BY hostname")]
        members.append({"root": root, "study_sha256": member._file("study.json")[1]["sha256"],
                        "meta": meta, "classes": classes})
    return {"parent": str(parent.root), "members": members,
            "admissions": [_ref(parent, f"epoch-admissions/{sequence:06d}.json") for sequence in range(len(records))]}


def _rows(connection, identifier):
    result = {}
    for key, table in (("accepted", "accepted"), ("attempt", "attempts"), ("measurement", "measurements")):
        row = connection.execute(f"SELECT * FROM {table} WHERE attempt_id=?", (identifier,)).fetchone()
        result[key] = None if row is None else dict(row)
    return result


def check_withdrawals(store, connection):
    """Do not turn a lost tombstone/journal into ordinary corpus discovery."""
    installed = validate_schema(connection)
    withdrawn = {row[0] for row in connection.execute("SELECT attempt_id FROM attempts WHERE state='withdrawn'")}
    tombstones = list(connection.execute(f"SELECT * FROM {TABLE}")) if installed else []
    if withdrawn != {row["attempt_id"] for row in tombstones}:
        raise ValueError("withdrawal states lost their exact tuple tombstones")
    for row in tombstones:
        if _observe(store, row["journal_path"])["sha256"] != row["journal_sha256"]:
            raise ValueError("withdrawal immutable journal hash changed")
        raw, info = store._file(row["journal_path"], row["journal_sha256"])
        journal = _load(raw)
        accepted = journal.get("original", {}).get("accepted", {})
        if (info["mode"] != "0444" or raw != _json(journal) or journal.get("record_type") != JOURNAL_TYPE
                or journal.get("root") != str(store.root) or journal.get("attempt_id") != row["attempt_id"]
                or row["journal_path"] != f'integrity-withdrawals/{row["attempt_id"]}.json'
                or any(accepted.get(key) != row[key] for key in ("attempt_id", "hostname", "mode", "slot", "five_tuple"))
                or _rows(connection, row["attempt_id"]) != {"accepted": None, **journal.get("withdrawn", {})}):
            raise ValueError("withdrawal tombstone/journal row drift")
    return installed


def _authenticate(store, rows, declaration):
    accepted, attempt, measurement = (rows[key] for key in ("accepted", "attempt", "measurement"))
    if accepted is None or attempt is None or measurement is None or attempt["state"] != "accepted" or measurement["outcome"] != "accepted":
        raise ValueError("withdrawal requires one already-accepted attempt and measurement")
    if any((row["hostname"], row["mode"]) != (accepted["hostname"], accepted["mode"]) for row in (attempt, measurement)):
        raise ValueError("accepted attempt/measurement identity drift")
    if any(attempt[key] != accepted[key] for key in ("slot", "receipt_path", "receipt_sha256", "inventory")):
        raise ValueError("accepted attempt row drift")
    receipt_path = accepted["receipt_path"]
    receipt_observation = _observe(store, receipt_path)
    if receipt_observation["sha256"] != declaration["receipt_sha256"] or accepted["receipt_sha256"] != declaration["receipt_sha256"]:
        raise ValueError("original immutable receipt hash differs")
    receipt = _load(store._file(receipt_path, declaration["receipt_sha256"])[0])
    if (receipt.get("record_type") != "qcsd-resource-domain-session-verification-v1"
            or receipt.get("schema_version") != 1 or receipt.get("verified") is not True
            or receipt.get("purpose", "formal") != "formal" or receipt.get("scientific_credit", True) is not True
            or any(receipt.get(key) != accepted[key] for key in ("hostname", "mode", "slot", "attempt_id"))
            or _json(receipt.get("five_tuple")).decode() != accepted["five_tuple"]):
        raise ValueError("original receipt identity drift")
    inventory = _load(accepted["inventory"])
    files = receipt.get("files")
    if not isinstance(files, dict) or set(inventory) != set(files) | {receipt_path} or inventory[receipt_path] != {"sha256": declaration["receipt_sha256"], "mode": "0444"}:
        raise ValueError("receipt and accepted inventory drift")
    artifact = declaration["artifact_path"]
    prefix = receipt_path.rsplit("/", 1)[0] + "/"
    if not artifact.startswith(prefix) or artifact not in files or files[artifact] != declaration["expected_sha256"]:
        raise ValueError("declared mismatch is not the original listed session artifact")
    observed = []
    for name, digest in sorted(files.items()):
        if inventory[name] != {"sha256": digest, "mode": "0444"}:
            raise ValueError("receipt and accepted inventory drift")
        item = _observe(store, name)
        if item["sha256"] != (declaration["actual_sha256"] if name == artifact else digest):
            raise ValueError("artifact mismatch differs from the single declared mismatch")
        observed.append(item)
    return {"declaration": declaration, "receipt": receipt_observation, "listed_files": observed}


def _result(store, journal, digest):
    return {"schema_version": 1, "record_type": RESULT_TYPE,
            "root": str(store.root), "journal": {"path": str(store.root / "integrity-withdrawals" / (journal["attempt_id"] + ".json")), "sha256": digest},
            "sql_before": journal["original"], "sql_after": {"accepted": None, **journal["withdrawn"]},
            "accepted_count_before": journal["accepted_count_before"], "accepted_count_after": journal["accepted_count_after"],
            "accepted_delta": -1, "scientific_credit_added": 0, "files_deleted": 0,
            "requires_independent_full_verify_export": True}


def _validate_journal(store, journal, declaration, scope):
    keys = {"schema_version", "record_type", "root", "attempt_id", "study_sha256", "parent_scope",
            "original", "withdrawn", "observation", "accepted_count_before", "accepted_count_after", "observed_at"}
    original = journal.get("original", {})
    attempt = original.get("attempt", {})
    measurement = original.get("measurement", {})
    expected = {"attempt": {**attempt, "state": "withdrawn", "updated_at": journal.get("observed_at"),
        "reason": "explicit integrity withdrawal: " + declaration["artifact_path"], "kind": "integrity-withdrawal"},
        "measurement": {**measurement, "outcome": "withdrawn"}}
    accepted = original.get("accepted", {})
    # accepted9 uses actual PRAGMA table order, never sorted object-key order.
    columns = ("hostname", "mode", "slot", "five_tuple", "attempt_id", "receipt_path", "receipt_sha256", "inventory", "verified_at")
    if (set(journal) != keys or journal["schema_version"] != 1 or journal["record_type"] != JOURNAL_TYPE
            or journal["root"] != str(store.root) or journal["attempt_id"] != declaration["attempt_id"]
            or journal["study_sha256"] != store._file("study.json")[1]["sha256"]
            or journal["parent_scope"] != scope or set(original) != {"accepted", "accepted9", "attempt", "measurement"}
            or original["accepted9"] != [accepted.get(key) for key in columns]
            or journal["observation"].get("declaration") != declaration or journal["withdrawn"] != expected
            or not isinstance(journal["observed_at"], str) or not journal["observed_at"]
            or type(journal["accepted_count_before"]) is not int or journal["accepted_count_before"] < 1
            or type(journal["accepted_count_after"]) is not int or journal["accepted_count_after"] != journal["accepted_count_before"] - 1):
        raise ValueError("withdrawal journal or scope drift")


def withdraw_accepted(root, *, attempt_id, receipt_sha256, artifact_path, expected_sha256, actual_sha256):
    """Withdraw exactly one explicit corrupted accepted receipt, idempotently.

    A journal published before a crash can be replayed only against its exact
    original rows and file metadata. A committed replay requires exact withdrawn
    rows, tombstone, unchanged scope/count and unchanged damaged evidence.
    """
    if not isinstance(attempt_id, str) or not re.fullmatch("[0-9a-f]{32}", attempt_id):
        raise ValueError("withdrawal needs an explicit attempt ID")
    for digest in (receipt_sha256, expected_sha256, actual_sha256):
        _digest(digest)
    if expected_sha256 == actual_sha256:
        raise ValueError("withdrawal requires a real declared hash mismatch")
    store = StudyStore(root)
    store._relative(artifact_path)
    _physical_fence(store)
    from .resource_study_epochs import _membership, _lock
    parent = _membership(store) or store
    declaration = {"attempt_id": attempt_id, "receipt_sha256": receipt_sha256,
                   "artifact_path": artifact_path, "expected_sha256": expected_sha256, "actual_sha256": actual_sha256}
    journal_relative = f"integrity-withdrawals/{attempt_id}.json"
    with _lock(parent.root):
        scope = _scope(store, parent)
        path = store.root / journal_relative
        journal = None
        if path.exists() or path.is_symlink():
            _observe(store, journal_relative)
            raw, info = store._file(journal_relative)
            if info["mode"] != "0444":
                raise ValueError("withdrawal journal is not immutable")
            journal = _load(raw)
            if raw != _json(journal):
                raise ValueError("withdrawal journal or scope drift")
            _validate_journal(store, journal, declaration, scope)
        with store._transaction() as connection:
            _physical_fence(store, connection)
            rows = _rows(connection, attempt_id)
            count = connection.execute("SELECT count(*) FROM accepted").fetchone()[0]
            exists = validate_schema(connection)
            tombstone = connection.execute(f"SELECT * FROM {TABLE} WHERE attempt_id=?", (attempt_id,)).fetchone() if exists else None
            if tombstone is not None:
                if journal is None:
                    raise ValueError("withdrawal tombstone lost its immutable journal")
                digest = hashlib.sha256(_json(journal)).hexdigest()
                expected = [attempt_id, journal["original"]["accepted"]["hostname"], journal["original"]["accepted"]["mode"], journal["original"]["accepted"]["slot"], journal["original"]["accepted"]["five_tuple"], journal_relative, digest]
                if list(tombstone) != expected or rows != {"accepted": None, **journal["withdrawn"]} or count != journal["accepted_count_after"]:
                    raise ValueError("committed withdrawal rows or count drift")
                observation = _authenticate(store, {key: journal["original"][key] for key in ("accepted", "attempt", "measurement")}, declaration)
                if observation != journal["observation"]:
                    raise ValueError("withdrawn evidence metadata drift")
                return _result(store, journal, digest)
            observation = _authenticate(store, rows, declaration)
            if journal is None:
                at = _now()
                withdrawn = {"attempt": {**rows["attempt"], "state": "withdrawn", "updated_at": at,
                    "reason": "explicit integrity withdrawal: " + artifact_path, "kind": "integrity-withdrawal"},
                    "measurement": {**rows["measurement"], "outcome": "withdrawn"}}
                journal = {"schema_version": 1, "record_type": JOURNAL_TYPE, "root": str(store.root), "attempt_id": attempt_id,
                    "study_sha256": store._file("study.json")[1]["sha256"], "parent_scope": scope,
                    "original": {**rows, "accepted9": list(rows["accepted"].values())}, "withdrawn": withdrawn,
                    "observation": observation, "accepted_count_before": count, "accepted_count_after": count - 1, "observed_at": at}
                _create(path, _json(journal))
            elif ({key: journal["original"][key] for key in rows} != rows or count != journal["accepted_count_before"] or observation != journal["observation"]):
                raise ValueError("pending withdrawal rows, count or metadata drift")
            digest = hashlib.sha256(_json(journal)).hexdigest()
            _install(connection)
            accepted = rows["accepted"]
            connection.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)", (attempt_id, accepted["hostname"], accepted["mode"], accepted["slot"], accepted["five_tuple"], journal_relative, digest))
            if connection.execute("DELETE FROM accepted WHERE attempt_id=?", (attempt_id,)).rowcount != 1:
                raise ValueError("withdrawal did not remove exactly one accepted row")
            target = journal["withdrawn"]["attempt"]
            if connection.execute("UPDATE attempts SET state=?,updated_at=?,reason=?,kind=? WHERE attempt_id=? AND state='accepted'", (target["state"], target["updated_at"], target["reason"], target["kind"], attempt_id)).rowcount != 1:
                raise ValueError("withdrawal attempt compare-and-swap failed")
            if connection.execute("UPDATE measurements SET outcome='withdrawn' WHERE attempt_id=? AND outcome='accepted'", (attempt_id,)).rowcount != 1:
                raise ValueError("withdrawal measurement compare-and-swap failed")
            if _rows(connection, attempt_id) != {"accepted": None, **journal["withdrawn"]} or connection.execute("SELECT count(*) FROM accepted").fetchone()[0] != count - 1:
                raise ValueError("withdrawal SQL after-state differs")
        return _result(store, journal, digest)
