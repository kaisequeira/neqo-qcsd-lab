"""Call-local immutable reuse controls; no capture or deployment qualification.

The original disposable ledger/cohort fixtures run actual admission and index
guards with their explicitly controlled preparation/raw leaves. These controls
observe parsing, named read-only SELECT refusals, and committed database
changes injected only into disposable fixture connections.
They grant no live capture or source-deployment qualification. ROOT alone runs
this source.
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_supplements as supplements
from qcsd_lab.resource_study_store import StudyStore, _PLAN_READ_SCOPE
from tests.test_resource_study_lineage import campaign
from tests.test_resource_study_runtime_cohorts import cohort_campaign, observed_transactions


INPUTS = ("study.json", lineage.MANIFEST, lineage.SOURCE, lineage.INVENTORY)


def test_records_parses_stable_catalogues_once_per_root_per_call(cohort_campaign, monkeypatch):
    c = cohort_campaign; new = c.fresh(); c.append(new)
    source_calls, reserve_calls = Counter(), Counter()
    source, reserve = lineage.candidate_catalogue, supplements.load_inventory_candidates

    def catalogue(path):
        source_calls[str(path)] += 1
        return source(path)

    def inventory(paths):
        paths = list(paths)
        reserve_calls.update(map(str, paths))
        return reserve(paths)

    monkeypatch.setattr(lineage, "candidate_catalogue", catalogue)
    monkeypatch.setattr(supplements, "load_inventory_candidates", inventory)
    first = cohorts.records(c.parent)
    assert first[-1]["record_type"] == cohorts.ADMISSION
    for store in (c.old, new):
        assert source_calls[str(store.root / lineage.SOURCE)] == 1
        assert reserve_calls[str(store.root / lineage.INVENTORY)] == 1
    assert cohorts.records(c.parent) == first
    for store in (c.old, new):
        assert source_calls[str(store.root / lineage.SOURCE)] == 2
        assert reserve_calls[str(store.root / lineage.INVENTORY)] == 2
    assert _PLAN_READ_SCOPE.get() is None


@pytest.mark.parametrize("key", ["study_sha256", "tuple_uniqueness_scope", "class_network_sha256"])
def test_plan_cache_hit_still_joins_fresh_sql_meta(campaign, monkeypatch, key):
    _, child, _ = campaign; store = child(enroll_class=False); queries = Counter()

    def observe(actual, sql, parameters):
        if actual.root == store.root and sql.startswith("SELECT value FROM meta WHERE key="):
            name = "study_sha256" if not parameters else parameters[0]
            queries[name] += 1

    with cohorts._records_read_scope():
        with observed_transactions(monkeypatch, observe):
            for _ in range(3): store.plan()
        assert all(queries[name] == 3 for name in ("study_sha256", "tuple_uniqueness_scope", "class_network_sha256"))

        def wrong_meta(actual, sql, parameters):
            name = "study_sha256" if not parameters else parameters[0]
            if (actual.root == store.root and sql.startswith("SELECT value FROM meta WHERE key=")
                    and name == key):
                return SimpleNamespace(fetchone=lambda: ("changed-live-meta",))

        with observed_transactions(monkeypatch, wrong_meta), pytest.raises(ValueError, match="binding changed"):
            store.plan()


@pytest.mark.parametrize("relative", INPUTS)
@pytest.mark.parametrize("change", ["bytes", "mode", "hardlink"])
def test_every_cached_plan_input_remains_fenced(campaign, relative, change):
    _, child, _ = campaign; store = child(enroll_class=False); path = store.root / relative
    original = path.read_bytes(); link = path.parent / (path.name + ".second-authority")
    try:
        with pytest.raises(ValueError), cohorts._records_read_scope():
            store.plan()
            if change == "bytes":
                path.chmod(0o644); path.write_bytes(original + b"\n"); path.chmod(0o444)
            elif change == "mode": path.chmod(0o644)
            else: os.link(path, link)
            store.plan()
    finally:
        if link.exists(): link.unlink()
        path.chmod(0o644); path.write_bytes(original); path.chmod(0o444)
    assert _PLAN_READ_SCOPE.get() is None


def test_call_exit_rehashes_inputs_after_the_last_read(campaign):
    _, child, _ = campaign; store = child(enroll_class=False); path = store.root / lineage.SOURCE
    original = path.read_bytes()
    try:
        with pytest.raises(ValueError), cohorts._records_read_scope():
            store.plan()
            path.chmod(0o644); path.write_bytes(original + b"\n"); path.chmod(0o444)
    finally:
        path.chmod(0o644); path.write_bytes(original); path.chmod(0o444)


def test_each_plan_input_is_fully_hashed_at_entry_and_exit(campaign, monkeypatch):
    _, child, _ = campaign; store = child(enroll_class=False); hashes = Counter()
    original = cohorts._records_file

    def observed(path, *, content=False):
        if content: hashes[str(path)] += 1
        return original(path, content=content)

    monkeypatch.setattr(cohorts, "_records_file", observed)
    with cohorts._records_read_scope():
        store.plan(); store.plan()
    assert hashes == Counter({str(store.root / name): 2 for name in INPUTS})


def test_cached_input_cannot_be_replaced_by_a_same_bytes_symlink(campaign):
    _, child, _ = campaign; store = child(enroll_class=False); path = store.root / lineage.SOURCE
    raw = path.read_bytes(); other = path.parent / "same-bytes-source.json"
    other.write_bytes(raw); other.chmod(0o444)
    try:
        with pytest.raises(ValueError), cohorts._records_read_scope():
            store.plan(); path.unlink(); path.symlink_to(other)
            store.plan()
    finally:
        path.unlink(); path.write_bytes(raw); path.chmod(0o444)


def test_plan_and_science_results_do_not_escape_as_cache_aliases(campaign):
    parent, child, _ = campaign; store = child(enroll_class=False)
    from qcsd_lab import resource_study_epochs as epochs
    # Actual original-map cell plus its genuine stable selected-map transition.
    transition = {"class_selection": store.plan()["class_selection"], "class_network": store.plan()["class_network"]}
    host = next(h for h in parent.plan()["class_network"]["assignments"] if h in {r["hostname"] for r in parent.enrolled()})
    cell = epochs._cell(parent, host, "front")
    with cohorts._records_read_scope() as scope:
        expected = store.plan(); damaged = store.plan(); damaged["class_network"]["assignments"].clear()
        assert store.plan() == expected
        science = cohorts._science(cell, transition); other = deepcopy(science); science["urls"].clear()
        assert cohorts._science(cell, transition) == other
    assert scope.files == scope.plans == scope.stores == scope.sciences == {}
    with pytest.raises(ValueError, match="closed or foreign"): scope.plan_data(store)


def test_scope_rejects_nested_and_foreign_thread_ownership(campaign):
    _, child, _ = campaign; store = child(enroll_class=False)
    with cohorts._records_read_scope() as scope:
        store.plan()
        with pytest.raises(ValueError, match="one call owner"), cohorts._records_read_scope(): pass
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(scope.plan_data, store)
            with pytest.raises(ValueError, match="closed or foreign"): future.result()
    assert _PLAN_READ_SCOPE.get() is None


def test_body_failure_is_preserved_when_input_closure_also_fails(campaign):
    _, child, _ = campaign; store = child(enroll_class=False); path = store.root / lineage.INVENTORY
    class BodyFailure(Exception): pass
    try:
        with pytest.raises(BodyFailure, match="original body") as caught:
            with cohorts._records_read_scope() as scope:
                store.plan(); path.chmod(0o644)
                raise BodyFailure("original body")
        assert any("Records input closure also refused" in note for note in caught.value.__notes__)
        assert not scope.active and _PLAN_READ_SCOPE.get() is None
    finally: path.chmod(0o444)


def test_cached_store_cell_still_reads_the_current_class_row(cohort_campaign):
    c = cohort_campaign; new = c.fresh(); c.append(new)
    record = cohorts.records(c.parent)[-1]
    cell = next(cell for cell in record["cells"] if cell["root"] == str(new.root))
    with cohorts._records_read_scope():
        assert cohorts._records_cell(cell) == cell
        copied = cohorts._records_cell(cell); copied["definition"]["urls"].clear()
        assert cohorts._records_cell(cell) == cell

        # A real second-connection commit changes SQLite's data_version.
        # A SELECT proxy alone does not change the captured database generation.
        with sqlite3.connect(new.root / "ledger.sqlite3") as writer:
            # Fault injection is confined to this disposable fixture connection.
            # Live writer connections retain their original denying function.
            writer.create_function(lineage.FENCE_FUNCTION, 5, lambda *_: 1)
            cursor = writer.execute("SELECT * FROM classes WHERE hostname=?", (cell["hostname"],))
            original = cursor.fetchone()
            columns = [item[0] for item in cursor.description]
            assert original is not None
            try:
                writer.execute("DELETE FROM classes WHERE hostname=?", (cell["hostname"],))
                writer.commit()
                with pytest.raises(ValueError, match="not enrolled"):
                    cohorts._records_cell(cell)
            finally:
                names = ",".join('"' + name.replace('"', '""') + '"' for name in columns)
                writer.execute("INSERT INTO classes (" + names + ") VALUES (" + ",".join("?" for _ in original) + ")", original)
                writer.commit()
        assert cohorts._records_cell(cell) == cell
