"""Call-local network decisions; no live capture or scientific qualification.

The network and stable-map fixtures run the original pure validators. The
disposable Store control retains real plan SQL joins and immutable-file checks.
ROOT alone executes these tests.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
import os

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_network as network
from qcsd_lab.resource_study_store import StudyStore, _PLAN_READ_SCOPE
from tests.test_resource_study_network import HOSTS, plan


@pytest.fixture
def stable():
    predecessor = network.build_network_plan([lineage.EXCLUDED, *HOSTS[:49]])
    mapping, selection = lineage.build(predecessor, "a" * 64, "/synthetic-parent",
        "b" * 64, "c" * 64, "d" * 64)
    return {**plan(), "class_network": mapping, "class_selection": selection,
            "source_sha256": "a" * 64}


def observed_validator(monkeypatch):
    calls = []
    original = network._uncached_validate_network_plan

    def observed(value, *, require=False):
        calls.append((value, require))
        return original(value, require=require)

    monkeypatch.setattr(network, "_uncached_validate_network_plan", observed)
    return calls


@pytest.mark.parametrize("stable_plan", [False, True])
def test_equal_complete_plans_validate_once_per_flag_and_return_current_alias(stable, stable_plan, monkeypatch):
    value = stable if stable_plan else plan(); calls = observed_validator(monkeypatch)
    with cohorts._records_read_scope() as scope:
        first = network.validate_network_plan(value)
        other = deepcopy(value)
        other = dict(reversed(list(other.items())))
        assert network.validate_network_plan(other) is other["class_network"]["assignments"]
        assert first is value["class_network"]["assignments"] and first is not other["class_network"]["assignments"]
        assert network.validate_network_plan(value, require=True) is first
        assert network.mapping_sha256(other) == lineage.digest(value["class_network"])
        assert len(calls) == 2 and len(scope.network_plans) == 2
    assert scope.network_plans == {} and not scope.active
    with cohorts._records_read_scope(): network.validate_network_plan(value)
    assert len(calls) == 3
    network.validate_network_plan(value); network.validate_network_plan(value)
    assert len(calls) == 5 and _PLAN_READ_SCOPE.get() is None


def test_historical_none_does_not_satisfy_required_mapping(monkeypatch):
    value = {"acceptance": "historical"}; calls = observed_validator(monkeypatch)
    with cohorts._records_read_scope() as scope:
        assert network.validate_network_plan(value) is None
        assert network.validate_network_plan(deepcopy(value)) is None
        for _ in range(2):
            with pytest.raises(ValueError, match="requires frozen"):
                network.validate_network_plan(value, require=True)
        assert len(calls) == 3 and len(scope.network_plans) == 1


@pytest.mark.parametrize("change", ["address", "source", "selection-order", "predecessor", "tuple-scope"])
def test_warm_stable_plan_cannot_hide_changed_science(stable, change):
    with cohorts._records_read_scope():
        network.validate_network_plan(stable)
        changed = deepcopy(stable)
        if change == "address": changed["class_network"]["assignments"][lineage.INCLUDED]["client_ipv4"] = "10.232.0.99"
        elif change == "source": changed["source_sha256"] = "e" * 64
        elif change == "selection-order": changed["class_selection"]["selected_hostnames"].reverse()
        elif change == "predecessor": changed["class_network"]["predecessor_sha256"] = "e" * 64
        else: changed["tuple_uniqueness_scope"] = "per-flight"
        with pytest.raises(ValueError): network.validate_network_plan(changed)


def test_returned_assignments_mutation_cannot_reuse_old_decision():
    value = plan()
    with cohorts._records_read_scope():
        assignments = network.validate_network_plan(value)
        assignments[HOSTS[0]]["client_ipv4"] = "10.232.0.99"
        with pytest.raises(ValueError, match="address assignment"):
            network.validate_network_plan(value)


def test_full_plan_bytes_not_only_map_are_cache_identity(monkeypatch):
    value = plan(); calls = observed_validator(monkeypatch)
    with cohorts._records_read_scope() as scope:
        network.validate_network_plan(value)
        value["otherwise_unused_metadata"] = {"a": [1, False, None, 2.5]}
        network.validate_network_plan(value)
        value["otherwise_unused_metadata"]["a"][0] = 2
        network.validate_network_plan(value)
        assert len(calls) == len(scope.network_plans) == 3


@pytest.mark.parametrize("change", ["tuple", "dict-subclass", "integer-key", "nan", "cycle"])
def test_non_json_native_plans_keep_uncached_original_semantics(change, monkeypatch):
    value = plan()
    if change == "tuple": value["extra"] = (1, 2)
    elif change == "dict-subclass":
        class Derived(dict): pass
        value = Derived(value)
    elif change == "integer-key": value[1] = "extra"
    elif change == "nan": value["extra"] = float("nan")
    else: value["extra"] = value
    calls = observed_validator(monkeypatch)
    with cohorts._records_read_scope() as scope:
        for _ in range(2):
            assert network.validate_network_plan(value) is value["class_network"]["assignments"]
        assert len(calls) == 2 and scope.network_plans == {}


def test_tuple_selection_cannot_alias_valid_json_list_key(stable):
    with cohorts._records_read_scope():
        network.validate_network_plan(stable)
        changed = deepcopy(stable)
        changed["class_selection"]["reserve_order"] = tuple(lineage.RESERVES)
        with pytest.raises(ValueError, match="selection/predecessor"):
            network.validate_network_plan(changed)


@pytest.mark.parametrize("required", [0, 1, None, "required"])
def test_non_boolean_require_uses_original_uncached_semantics(required, monkeypatch):
    value = plan(); calls = observed_validator(monkeypatch)
    with cohorts._records_read_scope() as scope:
        for _ in range(2): assert network.validate_network_plan(value, require=required) is value["class_network"]["assignments"]
        assert len(calls) == 2 and scope.network_plans == {}


def test_validator_replacement_after_warm_decision_is_refused(monkeypatch):
    value = plan()
    with cohorts._records_read_scope():
        network.validate_network_plan(value)
        with monkeypatch.context() as patch:
            patch.setattr(network, "_uncached_validate_network_plan", lambda plan, **kwargs: None)
            with pytest.raises(ValueError, match="validator changed"):
                network.validate_network_plan(value)


@pytest.mark.parametrize("change", ["plan", "validator"])
def test_first_validation_cannot_publish_a_changed_key_or_validator(change, monkeypatch):
    value = plan(); original = network._uncached_validate_network_plan

    def changed(value, *, require=False):
        result = original(value, require=require)
        if change == "plan": value["changed_during_validation"] = True
        else: monkeypatch.setattr(network, "_uncached_validate_network_plan", lambda plan, **kwargs: None)
        return result

    monkeypatch.setattr(network, "_uncached_validate_network_plan", changed)
    with pytest.raises(ValueError, match="changed during validation"), cohorts._records_read_scope() as scope:
        network.validate_network_plan(value)
    assert scope.network_plans == {} and not scope.active


def test_scope_rejects_foreign_thread_pid_closed_and_foreign_context(monkeypatch):
    value = plan()
    with cohorts._records_read_scope() as scope:
        network.validate_network_plan(value)
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(ValueError, match="closed or foreign"):
                pool.submit(scope.network_plan, value).result()
        original_pid = os.getpid()
        with monkeypatch.context() as patch:
            patch.setattr(cohorts.os, "getpid", lambda: original_pid + 1)
            with pytest.raises(ValueError, match="closed or foreign"): scope.network_plan(value)
    with pytest.raises(ValueError, match="closed or foreign"): scope.network_plan(value)
    token = _PLAN_READ_SCOPE.set(object())
    try:
        with pytest.raises(ValueError, match="foreign records network"): network.validate_network_plan(value)
    finally: _PLAN_READ_SCOPE.reset(token)


def test_body_failure_discards_all_decisions():
    with pytest.raises(RuntimeError, match="original body"), cohorts._records_read_scope() as scope:
        network.validate_network_plan(plan())
        raise RuntimeError("original body")
    assert scope.network_plans == {} and not scope.active and _PLAN_READ_SCOPE.get() is None


def test_cached_network_decision_keeps_live_sql_and_study_file_guards(tmp_path, monkeypatch):
    store = StudyStore(tmp_path.resolve() / "study"); store.initialize(plan())
    original = StudyStore._transaction; statements = []

    @contextmanager
    def observed(self):
        with original(self) as connection:
            connection.set_trace_callback(statements.append)
            yield connection

    monkeypatch.setattr(StudyStore, "_transaction", observed)
    with cohorts._records_read_scope():
        store.plan(); store.plan()
        for key in ("study_sha256", "tuple_uniqueness_scope", "class_network_sha256"):
            assert sum(sql == f"SELECT value FROM meta WHERE key='{key}'" for sql in statements) == 2
        with store._transaction() as connection:
            connection.execute("UPDATE meta SET value=? WHERE key='class_network_sha256'", ("f" * 64,))
        with pytest.raises(ValueError, match="scope binding"): store.plan()
    with original(store) as connection:
        connection.execute("UPDATE meta SET value=? WHERE key='class_network_sha256'", (network.mapping_sha256(plan()),))
    path = store.root / "study.json"; raw = path.read_bytes()
    try:
        with pytest.raises(ValueError), cohorts._records_read_scope():
            store.plan()
            path.chmod(0o644); path.write_bytes(raw + b" "); path.chmod(0o444)
            store.plan()
    finally:
        path.chmod(0o644); path.write_bytes(raw); path.chmod(0o444)
