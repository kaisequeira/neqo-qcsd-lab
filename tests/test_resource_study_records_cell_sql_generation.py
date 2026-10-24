"""Disposable real-SQL controls for one records() call's immutable cell reuse.

The cell callback is explicitly a small SQL fixture, not production enrollment
or scientific authority. SQLite WAL generations, independent commits, file
identity, immutable enrollment bytes and the actual records-scope code are
real. No capture, native execution, preparation or deployment is qualified.
ROOT alone executes these prospective tests against its selected Source.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import os
import sqlite3
from types import SimpleNamespace

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as real_epochs
from qcsd_lab.resource_study_store import StudyStore, _PLAN_READ_SCOPE


@pytest.fixture
def sql_cells(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "actual-wal-cell-fixture"
    root.mkdir()
    store = StudyStore(root)
    writer = sqlite3.connect(store.database, isolation_level=None)
    assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    writer.executescript("""
        CREATE TABLE classes (
            hostname TEXT PRIMARY KEY, path TEXT NOT NULL,
            sha256 TEXT NOT NULL, ready INTEGER NOT NULL
        );
        CREATE TABLE accepted (attempt_id TEXT PRIMARY KEY);
    """)
    store.database.chmod(0o600)
    cells = {}
    for host in ("one.example", "two.example"):
        relative = "classes/" + host + "/enrollment.json"
        path = root / relative
        path.parent.mkdir(parents=True)
        raw = ("immutable enrollment for " + host + "\n").encode()
        path.write_bytes(raw)
        path.chmod(0o444)
        digest = hashlib.sha256(raw).hexdigest()
        definition = {"urls": ["https://" + host + "/r" + str(i) for i in range(20)],
                      "native": ["explicit-test-runtime"], "ready": True}
        cell = {"root": str(root), "hostname": host, "mode": "front",
                "study_sha256": "1" * 64, "enrollment_path": relative,
                "enrollment_sha256": digest, "definition": definition,
                "definition_sha256": real_epochs._sha(definition)}
        cells[host] = cell
        writer.execute("INSERT INTO classes VALUES (?, ?, ?, 1)",
                       (host, relative, digest))

    observations, queries = [], []
    env = SimpleNamespace(root=root, store=store, writer=writer, cells=cells,
                          cell=cells["one.example"], queries=queries,
                          observations=observations, after_sql_read=None)

    def observe(kind, value):
        observations.append((kind, deepcopy(value)))

    def current_cell(actual_store, host, mode):
        # A new genuine SQLite read every time the original cell callback is
        # reached. Accepted-only commits are observed but do not change this
        # immutable fixture cell, just as they do not change its definition.
        assert actual_store.root == root
        assert mode == "front" and host in cells
        with sqlite3.connect(actual_store.database) as connection:
            row = connection.execute(
                "SELECT path, sha256, ready FROM classes WHERE hostname=?",
                (host,)).fetchone()
            accepted = connection.execute("SELECT COUNT(*) FROM accepted").fetchone()[0]
        queries.append({"host": host, "row": row, "accepted_count": accepted})
        if row is None:
            raise ValueError("original current class is not enrolled")
        cell = cells[host]
        if row != (cell["enrollment_path"], cell["enrollment_sha256"], 1):
            raise ValueError("original current class row differs")
        if env.after_sql_read is not None:
            hook, env.after_sql_read = env.after_sql_read, None
            hook()
        value = deepcopy(cell)
        observe("cell", value)
        return value

    env.reader = current_cell
    env.epochs = SimpleNamespace(_cell=current_cell, _sha=real_epochs._sha,
                                 _observe_authority=observe)
    # Patch BEFORE constructing the scope: the real scope seals this callback
    # and its code. No production scope or Source authority is synthesized.
    monkeypatch.setattr(cohorts, "_epochs", lambda: env.epochs)
    try:
        yield env
    finally:
        writer.close()
        assert _PLAN_READ_SCOPE.get() is None


def test_120_stable_visits_share_one_cell_sql_read_but_close_fresh(sql_cells):
    """Causal on original126: same public helper completes, query count is120."""
    e = sql_cells
    with cohorts._records_read_scope():
        for _ in range(120):
            assert cohorts._records_cell(e.cell) == e.cell
        assert len(e.queries) == 1
        assert len(e.observations) == 120
    assert len(e.queries) == 2  # One fresh, unique-cell closure SQL read.
    assert len(e.observations) == 121


@pytest.mark.parametrize("change", ["delete", "definition"])
def test_persistent_class_commit_reaches_original_sql_refusal(sql_cells, change):
    e = sql_cells
    with pytest.raises(ValueError, match="original current class"):
        with cohorts._records_read_scope():
            assert cohorts._records_cell(e.cell) == e.cell
            if change == "delete":
                e.writer.execute("DELETE FROM classes WHERE hostname=?", (e.cell["hostname"],))
            else:
                e.writer.execute("UPDATE classes SET sha256=? WHERE hostname=?",
                                 ("0" * 64, e.cell["hostname"]))
            cohorts._records_cell(e.cell)
    assert len(e.queries) >= 2
    assert e.queries[1]["row"] is None if change == "delete" else e.queries[1]["row"][1] == "0" * 64


def test_committed_aba_restore_forces_original_sql_even_when_cell_is_equal(sql_cells):
    e = sql_cells
    with cohorts._records_read_scope():
        assert cohorts._records_cell(e.cell) == e.cell
        e.writer.execute("UPDATE classes SET sha256=? WHERE hostname=?",
                         ("0" * 64, e.cell["hostname"]))
        e.writer.execute("UPDATE classes SET sha256=? WHERE hostname=?",
                         (e.cell["enrollment_sha256"], e.cell["hostname"]))
        assert cohorts._records_cell(e.cell) == e.cell
        assert len(e.queries) == 2
    assert len(e.queries) == 3


def test_accepted_only_commit_refreshes_cell_without_scientific_refusal(sql_cells):
    e = sql_cells
    with cohorts._records_read_scope():
        assert cohorts._records_cell(e.cell) == e.cell
        e.writer.execute("INSERT INTO accepted VALUES ('newly-committed')")
        assert cohorts._records_cell(e.cell) == e.cell
        assert len(e.queries) == 2
        assert e.queries[-1]["accepted_count"] == 1
        assert cohorts._records_cell(e.cell) == e.cell
        assert len(e.queries) == 2


def test_uncommitted_or_rolled_back_class_write_is_not_a_committed_generation(sql_cells):
    e = sql_cells
    with cohorts._records_read_scope():
        assert cohorts._records_cell(e.cell) == e.cell
        e.writer.execute("BEGIN IMMEDIATE")
        try:
            e.writer.execute("UPDATE classes SET ready=0 WHERE hostname=?", (e.cell["hostname"],))
            assert cohorts._records_cell(e.cell) == e.cell
            assert len(e.queries) == 1
        finally:
            e.writer.execute("ROLLBACK")
        assert cohorts._records_cell(e.cell) == e.cell
        assert len(e.queries) == 1


def test_commit_between_cache_decode_and_second_generation_cannot_return_stale_hit(sql_cells, monkeypatch):
    e = sql_cells
    original_load = cohorts._load
    with cohorts._records_read_scope():
        assert cohorts._records_cell(e.cell) == e.cell
        armed = True

        def load_with_real_commit(raw):
            nonlocal armed
            value = original_load(raw)
            if armed:
                armed = False
                e.writer.execute("INSERT INTO accepted VALUES ('during-hit')")
            return value

        monkeypatch.setattr(cohorts, "_load", load_with_real_commit)
        assert cohorts._records_cell(e.cell) == e.cell
        assert len(e.queries) == 2
        assert e.queries[-1]["accepted_count"] == 1


def test_commit_during_original_read_does_not_seal_an_unstable_generation(sql_cells):
    e = sql_cells
    with cohorts._records_read_scope() as scope:
        e.after_sql_read = lambda: e.writer.execute("INSERT INTO accepted VALUES ('during-original-read')")
        assert cohorts._records_cell(e.cell) == e.cell
        assert scope.cell_values == {}
        assert cohorts._records_cell(e.cell) == e.cell
        assert len(e.queries) == 2
        assert e.queries[-1]["accepted_count"] == 1


def test_same_root_commit_invalidates_other_cached_cells_before_their_visit(sql_cells):
    e = sql_cells
    second = e.cells["two.example"]
    with cohorts._records_read_scope():
        assert cohorts._records_cell(e.cell) == e.cell
        assert cohorts._records_cell(second) == second
        e.writer.execute("INSERT INTO accepted VALUES ('root-wide-change')")
        assert cohorts._records_cell(e.cell) == e.cell
        assert cohorts._records_cell(second) == second
        assert [x["host"] for x in e.queries] == ["one.example", "two.example"] * 2
    assert len(e.queries) == 6  # One fresh finish per unique cell, not per visit.


def test_database_inode_replacement_refuses_before_cached_cell_return(sql_cells):
    e = sql_cells
    replacement = e.root / "replacement.sqlite3"
    with sqlite3.connect(replacement) as connection:
        connection.execute("CREATE TABLE replacement(value)")
    replacement.chmod(0o600)
    with pytest.raises(ValueError, match="database identity changed"):
        with cohorts._records_read_scope():
            assert cohorts._records_cell(e.cell) == e.cell
            os.replace(replacement, e.store.database)
            cohorts._records_cell(e.cell)


def test_returned_cell_is_independent_of_cache_and_later_call(sql_cells):
    e = sql_cells
    with cohorts._records_read_scope():
        value = cohorts._records_cell(e.cell)
        value["definition"]["urls"].clear()
        assert cohorts._records_cell(e.cell) == e.cell
        assert len(e.queries) == 1
    before = len(e.queries)
    with cohorts._records_read_scope():
        assert cohorts._records_cell(e.cell) == e.cell
        assert len(e.queries) == before + 1


def test_recomputed_cache_digest_does_not_replace_original_memory_witness(sql_cells):
    e = sql_cells
    with pytest.raises(ValueError, match="cached cell memory changed"):
        with cohorts._records_read_scope() as scope:
            cohorts._records_cell(e.cell)
            key = next(iter(scope.cell_values))
            generation, raw, _ = scope.cell_values[key]
            changed = raw + b" "  # Still valid equivalent JSON; wrong authority bytes.
            scope.cell_values[key] = (generation, changed, hashlib.sha256(changed).hexdigest())
            cohorts._records_cell(e.cell)


def test_coherently_replaced_cache_and_witness_still_refuse_fresh_sql_at_finish(sql_cells):
    e = sql_cells
    with pytest.raises(ValueError, match="fresh original cell differs"):
        with cohorts._records_read_scope() as scope:
            cohorts._records_cell(e.cell)
            key = next(iter(scope.cell_values))
            generation = scope.cell_values[key][0]
            changed = deepcopy(e.cell)
            changed["definition"]["urls"][0] = "https://unqualified.invalid/changed"
            raw = cohorts._json(changed)
            digest = hashlib.sha256(raw).hexdigest()
            scope.cell_values[key] = (generation, raw, digest)
            scope.cell_witnesses[key] = (raw, digest)


@pytest.mark.parametrize("change", ["function", "code"])
def test_original_cell_reader_identity_and_code_are_sealed(sql_cells, monkeypatch, change):
    e = sql_cells
    with pytest.raises(ValueError, match="original cell reader changed"):
        with cohorts._records_read_scope():
            cohorts._records_cell(e.cell)
            if change == "function":
                monkeypatch.setattr(e.epochs, "_cell", lambda *args: deepcopy(e.cell))
            else:
                monkeypatch.setattr(e.reader, "__code__", e.reader.__code__.replace(co_name="changed_cell_reader"))
            cohorts._records_cell(e.cell)


@pytest.mark.parametrize("change", ["bytes", "mode"])
def test_cached_visit_retains_real_enrollment_file_guards(sql_cells, change):
    e = sql_cells
    path = e.root / e.cell["enrollment_path"]
    with pytest.raises(ValueError):
        with cohorts._records_read_scope():
            cohorts._records_cell(e.cell)
            path.chmod(0o644)
            if change == "bytes":
                path.write_bytes(path.read_bytes() + b"changed")
                path.chmod(0o444)
            cohorts._records_cell(e.cell)


def test_no_scope_keeps_original_fresh_cell_sql_path(sql_cells):
    e = sql_cells
    assert _PLAN_READ_SCOPE.get() is None
    for _ in range(3):
        assert cohorts._records_cell(e.cell) == e.cell
    assert len(e.queries) == 3


def test_non_wal_database_uses_original_sql_fallback_and_closes_monitor(sql_cells):
    e = sql_cells
    assert e.writer.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
    with cohorts._records_read_scope() as scope:
        for _ in range(3):
            assert cohorts._records_cell(e.cell) == e.cell
        assert len(e.queries) == 3
        assert scope.cell_monitors == {} and scope.cell_values == {}
        assert str(e.root) in scope.cell_generation_unavailable
    assert len(e.queries) == 4


def test_monitor_is_readonly_autocommit_and_both_resources_close(sql_cells):
    e = sql_cells
    with cohorts._records_read_scope() as scope:
        cohorts._records_cell(e.cell)
        monitor = scope.cell_monitors[str(e.root)]
        connection, fd = monitor.connection, monitor.fd
        assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
        assert not connection.in_transaction and connection.total_changes == 0
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute("INSERT INTO accepted VALUES ('forbidden-monitor-write')")
        assert not connection.in_transaction and connection.total_changes == 0
        assert cohorts._records_cell(e.cell) == e.cell
    assert monitor.closed and monitor.fd is None and monitor.connection is None
    with pytest.raises(OSError):
        os.fstat(fd)
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")
    assert not scope.active
    assert scope.cell_monitors == scope.cell_generations == scope.cell_values == scope.cell_witnesses == {}


def test_scope_refuses_foreign_thread_and_use_after_discard(sql_cells):
    e = sql_cells
    with cohorts._records_read_scope() as scope:
        cohorts._records_cell(e.cell)
        store = scope.stores[str(e.root)]
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(scope.cell, store, e.cell)
            with pytest.raises(ValueError, match="closed or foreign"):
                result.result()
    with pytest.raises(ValueError, match="closed or foreign"):
        scope.cell(store, e.cell)


def test_body_exception_and_monitor_cleanup_survive_closure_refusal(sql_cells):
    e = sql_cells
    class BodyFailure(Exception):
        pass
    with pytest.raises(BodyFailure, match="original body") as caught:
        with cohorts._records_read_scope() as scope:
            cohorts._records_cell(e.cell)
            monitor = scope.cell_monitors[str(e.root)]
            e.writer.execute("DELETE FROM classes WHERE hostname=?", (e.cell["hostname"],))
            raise BodyFailure("original body")
    assert any("Records input closure also refused" in note for note in caught.value.__notes__)
    assert monitor.closed and monitor.connection is None and monitor.fd is None
    assert not scope.active and _PLAN_READ_SCOPE.get() is None
