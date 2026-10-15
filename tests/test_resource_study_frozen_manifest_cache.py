"""Call-local retained-manifest controls; no raw or live-credit qualification.

The small filesystem fixture contains synthetic, fully validated carry metadata,
not accepted ledger credit. The final control uses the existing disposable
cohort fixture and its real SQL joins with explicitly controlled raw leaves.
ROOT alone executes these tests.
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import os
from types import SimpleNamespace

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab.resource_study_inputs import canonical_json
from qcsd_lab.resource_study_store import StudyStore, _PLAN_READ_SCOPE, _create, _json
from tests.test_resource_study_lineage import campaign
from tests.test_resource_study_runtime_cohorts import cohort_campaign, observed_transactions


@pytest.fixture
def retained(tmp_path):
    parent = StudyStore(tmp_path.resolve() / "parent")
    root = tmp_path.resolve() / "historical"
    parent.root.mkdir(mode=0o700); root.mkdir(mode=0o700)
    member = {"cohort_id": "a" * 64,
              "cell": {"root": str(root), "hostname": "example.test", "mode": "front"},
              "frozen_accepted": {"path": "runtime-cohorts/retained.json", "sha256": None}}
    rows = []
    for slot in range(1, 401):
        row = {"hostname": "example.test", "mode": "front", "slot": slot,
               "five_tuple": _json(["10.232.0.2", 30000 + slot, "203.0.113.8", 443, 17]).decode(),
               "attempt_id": f"{slot:032x}", "receipt_path": f"corpus/example.test/front/{slot:06d}/session.json",
               "receipt_sha256": "b" * 64, "inventory": "{}", "verified_at": "2026-10-15T00:00:00+00:00"}
        rows.append(cohorts._row_ref(str(root), row))
    value = {"record_type": cohorts.SNAPSHOT, "cohort_id": member["cohort_id"],
             "authority": "existing-accepted-SQL-rows; no new raw qualification", "rows": rows}
    path = parent._relative(member["frozen_accepted"]["path"])
    _create(path, canonical_json(value))
    member["frozen_accepted"]["sha256"] = epochs._sha(value)
    return SimpleNamespace(parent=parent, root=root, member=member, value=value, path=path)


def count_uncached(monkeypatch):
    calls = []
    original = cohorts._uncached_frozen_value

    def observed(parent, member):
        calls.append((str(parent.root), epochs._sha(member)))
        return original(parent, member)

    monkeypatch.setattr(cohorts, "_uncached_frozen_value", observed)
    return calls


def test_four_hundred_rows_validate_once_per_records_call(retained, monkeypatch):
    f = retained; calls = count_uncached(monkeypatch)
    with cohorts._records_read_scope() as scope:
        for _ in range(3): assert cohorts._frozen_value(f.parent, f.member) == f.value
        assert len(calls) == 1 and len(scope.frozen_values) == 1
    assert not scope.active and scope.frozen_values == scope.roots == scope.files == scope.stores == {}
    with cohorts._records_read_scope(): assert cohorts._frozen_value(f.parent, f.member) == f.value
    assert len(calls) == 2
    # Outside a records call the original validator remains uncached.
    assert cohorts._frozen_value(f.parent, f.member) == f.value
    assert cohorts._frozen_value(f.parent, f.member) == f.value
    assert len(calls) == 4 and _PLAN_READ_SCOPE.get() is None


def test_first_and_last_manifest_reads_hash_complete_bytes(retained, monkeypatch):
    f = retained; full = Counter(); original = cohorts._records_file

    def observed(path, *, content=False):
        if content: full[str(path)] += 1
        return original(path, content=content)

    monkeypatch.setattr(cohorts, "_records_file", observed)
    with cohorts._records_read_scope():
        cohorts._frozen_value(f.parent, f.member); cohorts._frozen_value(f.parent, f.member)
    assert full == Counter({str(f.path): 2})


def test_cached_results_are_deep_copies(retained):
    f = retained
    with cohorts._records_read_scope():
        first = cohorts._frozen_value(f.parent, f.member)
        first["rows"][0]["receipt_path"] = "changed.json"; first["rows"].pop()
        assert cohorts._frozen_value(f.parent, f.member) == f.value


def test_parent_and_member_are_both_cache_identity(retained, monkeypatch, tmp_path):
    f = retained; calls = count_uncached(monkeypatch)
    other = StudyStore(tmp_path.resolve() / "second-parent"); other.root.mkdir(mode=0o700)
    _create(other._relative(f.member["frozen_accepted"]["path"]), canonical_json(f.value))
    with cohorts._records_read_scope():
        cohorts._frozen_value(f.parent, f.member); cohorts._frozen_value(other, f.member)
        assert len(calls) == 2
        damaged = deepcopy(f.member); damaged["cohort_id"] = "c" * 64
        with pytest.raises(ValueError, match="immutable authority"):
            cohorts._frozen_value(f.parent, damaged)
    assert len(calls) == 3


@pytest.mark.parametrize("change", ["bytes", "restore", "mode", "hardlink", "symlink", "replace"])
def test_manifest_mutation_cannot_hit_the_cache(retained, change):
    f = retained; raw = f.path.read_bytes(); other = f.path.with_name("other.json")
    try:
        with pytest.raises(ValueError), cohorts._records_read_scope():
            cohorts._frozen_value(f.parent, f.member)
            if change in ("bytes", "restore"):
                f.path.chmod(0o644); f.path.write_bytes(raw + b" ")
                if change == "restore": f.path.write_bytes(raw)
                f.path.chmod(0o444)
            elif change == "mode": f.path.chmod(0o644)
            elif change == "hardlink": os.link(f.path, other)
            elif change == "symlink":
                _create(other, raw); f.path.unlink(); f.path.symlink_to(other)
            else:
                f.path.unlink(); _create(f.path, raw)
            cohorts._frozen_value(f.parent, f.member)
    finally:
        if f.path.is_symlink(): f.path.unlink()
        if other.exists(): other.unlink()
        if f.path.exists(): f.path.chmod(0o644)
        f.path.write_bytes(raw); f.path.chmod(0o444)
    assert _PLAN_READ_SCOPE.get() is None


def test_mutation_after_last_use_is_refused_at_scope_exit(retained):
    f = retained; raw = f.path.read_bytes()
    try:
        with pytest.raises(ValueError), cohorts._records_read_scope():
            cohorts._frozen_value(f.parent, f.member)
            f.path.chmod(0o644); f.path.write_bytes(raw + b"\n"); f.path.chmod(0o444)
    finally:
        f.path.chmod(0o644); f.path.write_bytes(raw); f.path.chmod(0o444)


def test_first_validation_cannot_publish_a_changed_manifest_into_cache(retained, monkeypatch):
    f = retained; raw = f.path.read_bytes(); original = cohorts._uncached_frozen_value

    def changed(parent, member):
        value = original(parent, member)
        f.path.chmod(0o644); f.path.write_bytes(raw + b"\n"); f.path.chmod(0o444)
        return value

    monkeypatch.setattr(cohorts, "_uncached_frozen_value", changed)
    try:
        with pytest.raises(ValueError), cohorts._records_read_scope() as scope:
            cohorts._frozen_value(f.parent, f.member)
        assert scope.frozen_values == {} and not scope.active
    finally:
        f.path.chmod(0o644); f.path.write_bytes(raw); f.path.chmod(0o444)


@pytest.mark.parametrize("change", ["duplicate-slot", "duplicate-tuple", "bad-path", "out-of-order", "over-quota"])
def test_rehashed_invalid_manifests_still_run_original_validator(retained, change):
    f = retained; value = deepcopy(f.value)
    if change == "duplicate-slot": value["rows"][1]["slot"] = 1
    elif change == "duplicate-tuple": value["rows"][1]["five_tuple"] = value["rows"][0]["five_tuple"]
    elif change == "bad-path": value["rows"][0]["receipt_path"] = "../outside.json"
    elif change == "out-of-order": value["rows"].reverse()
    else: value["rows"].append(deepcopy(value["rows"][0]))
    f.path.chmod(0o644); f.path.write_bytes(canonical_json(value)); f.path.chmod(0o444)
    member = deepcopy(f.member); member["frozen_accepted"]["sha256"] = epochs._sha(value)
    with pytest.raises(ValueError), cohorts._records_read_scope(): cohorts._frozen_value(f.parent, member)


def test_member_root_binding_cannot_reuse_another_root(retained, tmp_path):
    f = retained; other = tmp_path.resolve() / "different-history"; other.mkdir(mode=0o700)
    with cohorts._records_read_scope():
        cohorts._frozen_value(f.parent, f.member)
        member = deepcopy(f.member); member["cell"]["root"] = str(other)
        with pytest.raises(ValueError, match="row/slot/tuple identity"):
            cohorts._frozen_value(f.parent, member)


@pytest.mark.parametrize("change", ["mode", "replace", "symlink"])
def test_member_root_identity_is_guarded_on_cache_hits(retained, change):
    f = retained; held = f.root.with_name("held-history"); original_mode = f.root.stat().st_mode & 0o777
    try:
        with pytest.raises(ValueError), cohorts._records_read_scope():
            cohorts._frozen_value(f.parent, f.member)
            if change == "mode": f.root.chmod(0o755)
            else:
                f.root.rename(held)
                if change == "replace": f.root.mkdir(mode=original_mode)
                else: f.root.symlink_to(held, target_is_directory=True)
            cohorts._frozen_value(f.parent, f.member)
    finally:
        if change == "mode": f.root.chmod(original_mode)
        else:
            if f.root.is_symlink(): f.root.unlink()
            else: f.root.rmdir()
            held.rename(f.root)


def test_live_directory_entries_are_not_immutable_authority(retained):
    f = retained
    with cohorts._records_read_scope():
        cohorts._frozen_value(f.parent, f.member)
        child = f.root / "new-attempt"; child.mkdir(); child.rmdir()
        assert cohorts._frozen_value(f.parent, f.member) == f.value


def test_scope_rejects_foreign_thread_and_closed_handles(retained):
    f = retained
    with cohorts._records_read_scope() as scope:
        cohorts._frozen_value(f.parent, f.member)
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(scope.frozen_value, f.parent, f.member)
            with pytest.raises(ValueError, match="closed or foreign"): result.result()
    with pytest.raises(ValueError, match="closed or foreign"): scope.frozen_value(f.parent, f.member)
    assert scope.frozen_values == scope.roots == {} and _PLAN_READ_SCOPE.get() is None


def test_selected_accepted_and_attempt_rows_remain_fresh(cohort_campaign, monkeypatch):
    c = cohort_campaign; new = c.fresh(); c.append(new)
    record = cohorts.records(c.parent)[-1]
    entry = next(entry for entry in record["cohorts"] if entry["hostname"] == c.old.enrolled()[0]["hostname"] and entry["mode"] == "front")
    queries = Counter()

    def observed(store, sql, parameters):
        if sql.startswith("SELECT * FROM accepted WHERE"): queries[(str(store.root), "accepted")] += 1
        if sql.startswith("SELECT * FROM attempts WHERE") and "state='accepted'" in sql:
            queries[(str(store.root), "attempts")] += 1

    with cohorts._records_read_scope(), observed_transactions(monkeypatch, observed):
        for _ in range(2): assert len(cohorts._accepted(entry)) == 1
    for store in (c.old, new):
        assert queries[(str(store.root), "accepted")] == queries[(str(store.root), "attempts")] == 2

    def missing_accepted(store, sql, parameters):
        if store.root == c.old.root and sql.startswith("SELECT * FROM accepted WHERE"): return []

    with cohorts._records_read_scope():
        assert len(cohorts._accepted(entry)) == 1
        with observed_transactions(monkeypatch, missing_accepted), pytest.raises(ValueError, match="accepted index differs"):
            cohorts._accepted(entry)
