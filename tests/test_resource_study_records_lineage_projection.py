"""ROOT-only disposable SQL/FD and mutation controls for a prospective cache.

These exercise the real original stable-plan parser/ledger in campaign fixtures.
No live capture, runtime qualification or scientific credit is claimed.
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from types import SimpleNamespace

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_network as network
from qcsd_lab.resource_study_store import _PLAN_READ_SCOPE
from tests.test_resource_study_lineage import campaign
from tests.test_resource_study_runtime_cohorts import observed_transactions


def sample(campaign):
    _, child, _ = campaign
    store = child(enroll_class=False)
    plan = store.plan()
    host = lineage.INCLUDED
    cell = {"root": str(store.root), "hostname": host, "definition": {"network": {
        "mapping_sha256": network.mapping_sha256(plan),
        "assignment": deepcopy(plan["class_network"]["assignments"][host])}}}
    transition = {"class_network": plan["class_network"], "class_selection": plan["class_selection"]}
    return store, cell, transition


def test_hundred_singletons_keep_every_sql_join_without_full_plan_reencoding(campaign, monkeypatch):
    store, cell, transition = sample(campaign)
    queries, reads = Counter(), Counter()
    native = network._network_plan_cache_bytes
    original = cohorts._records_file

    def encoded(value):
        reads["full-plan-canonicalization"] += 1
        return native(value)

    def file(path, *, content=False):
        if str(path).startswith(str(store.root)+"/"):
            reads["full-file" if content else "FD9-hit"] += 1
        return original(path, content=content)

    def observe(actual, sql, parameters):
        if actual.root == store.root and sql.startswith("SELECT value FROM meta WHERE key="):
            queries["study_sha256" if not parameters else parameters[0]] += 1

    monkeypatch.setattr(network, "_network_plan_cache_bytes", encoded)
    monkeypatch.setattr(cohorts, "_records_file", file)
    with observed_transactions(monkeypatch, observe):
        with cohorts._records_read_scope() as scope:
            lineage.validate_cells([cell], transition)
            warm = reads["full-plan-canonicalization"]
            hit_count = reads["FD9-hit"]
            for _ in range(100):
                lineage.validate_cells([cell], transition)
            assert reads["full-plan-canonicalization"] == warm
            assert reads["FD9-hit"] >= hit_count + 400
            assert all(queries[k] == 101 for k in
                       ("study_sha256", "tuple_uniqueness_scope", "class_network_sha256"))
            assert len(scope.lineage_plans) == 1
        assert reads["full-plan-canonicalization"] > warm  # Full memory/disk closure check.
    assert reads["full-file"] >= 8 and scope.lineage_plans == {} and _PLAN_READ_SCOPE.get() is None


def test_public_plan_and_small_projection_mutation_do_not_escape_as_aliases(campaign):
    store, cell, transition = sample(campaign)
    with cohorts._records_read_scope() as scope:
        lineage.validate_cells([cell], transition)
        public = store.plan()
        public["class_network"]["assignments"].clear()
        public["class_selection"]["selected_hostnames"].reverse()
        projected, digest = scope.lineage_plan(store)
        projected["class_network"]["assignments"].clear()
        projected["class_selection"]["selected_hostnames"].reverse()
        lineage.validate_cells([cell], transition)
        second, actual = scope.lineage_plan(store)
        assert actual == digest and second["class_selection"] == transition["class_selection"]
        assert second["class_network"]["assignments"][cell["hostname"]] == cell["definition"]["network"]["assignment"]


@pytest.mark.parametrize("key", ["study_sha256", "tuple_uniqueness_scope", "class_network_sha256"])
def test_warm_projection_keeps_fresh_original_sql_refusals(campaign, monkeypatch, key):
    store, cell, transition = sample(campaign)
    with cohorts._records_read_scope():
        lineage.validate_cells([cell], transition)

        def wrong(actual, sql, parameters):
            name = "study_sha256" if not parameters else parameters[0]
            if actual.root == store.root and sql.startswith("SELECT value FROM meta WHERE key=") and name == key:
                return SimpleNamespace(fetchone=lambda: ("changed-live-ledger",))

        with observed_transactions(monkeypatch, wrong), pytest.raises(ValueError, match="binding changed"):
            lineage.validate_cells([cell], transition)


@pytest.mark.parametrize("relative", ["study.json", lineage.SOURCE])
def test_warm_projection_keeps_fd_and_final_whole_byte_fences(campaign, relative):
    store, cell, transition = sample(campaign)
    path = store.root/relative
    original = path.read_bytes()
    try:
        with pytest.raises(ValueError), cohorts._records_read_scope():
            lineage.validate_cells([cell], transition)
            path.chmod(0o644)
            path.write_bytes(original+b"\n")
            path.chmod(0o444)
            lineage.validate_cells([cell], transition)
    finally:
        path.chmod(0o644)
        path.write_bytes(original)
        path.chmod(0o444)
    assert _PLAN_READ_SCOPE.get() is None


def test_private_memory_change_cannot_pass_the_original_study_closure(campaign):
    store, cell, transition = sample(campaign)
    with pytest.raises(ValueError, match="memory or projection"), cohorts._records_read_scope() as scope:
        lineage.validate_cells([cell], transition)
        # An otherwise unused field is still part of the whole original plan.
        scope.plans[str(store.root)][2][0]["changed_private_metadata"] = True
    assert not scope.active and scope.lineage_plans == {}


@pytest.mark.parametrize("function", ["mapping_sha256", "_uncached_validate_network_plan"])
def test_warm_projection_refuses_validator_replacement(campaign, monkeypatch, function):
    store, cell, transition = sample(campaign)
    with cohorts._records_read_scope():
        lineage.validate_cells([cell], transition)
        with monkeypatch.context() as patch:
            patch.setattr(network, function, lambda *a, **kw: None)
            with pytest.raises(ValueError, match="validator or Store.plan changed"):
                lineage.validate_cells([cell], transition)


def test_projection_has_one_call_pid_thread_and_closed_lifetime(campaign):
    store, cell, transition = sample(campaign)
    with cohorts._records_read_scope() as scope:
        lineage.validate_cells([cell], transition)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(scope.lineage_plan, store)
            with pytest.raises(ValueError, match="closed or foreign"):
                future.result()
    with pytest.raises(ValueError, match="closed or foreign"):
        scope.lineage_plan(store)
