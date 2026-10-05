"""HOST call counts and fences, with original proof/runtime boundaries synthetic.

Real render, exact authority/bridge schemas, dependency registration and closing
byte/mode/membership fences execute. No installed or speed/capture claim.
"""
from copy import deepcopy
from pathlib import Path

import pytest

from qcsd_lab import qualification_control_authority as control
from qcsd_lab import qualification_delivery_compatibility as delivery
from qcsd_lab import rapid_canary_control_bridge as bridge
from qcsd_lab import rapid_capture_plan as campaigns
from qcsd_lab import rapid_operation_facts as operations
from qcsd_lab import rapid_rolling_readiness as ready
from qcsd_lab.supplied_static_admission import capture_limits
from tests.test_rapid_canary_control_bridge import authority_case, case
from tests.test_rapid_operation_facts import scheduled


def authority(case):
    return control.declare(case.output, original_witness=case.original_ref,
                           consumer=case.roles[1], body_policy=delivery.POLICY)


def counted(monkeypatch, module, name, counts):
    original = getattr(module, name)
    def call(*args, **kwargs):
        counts[name] = counts.get(name, 0) + 1
        return original(*args, **kwargs)
    monkeypatch.setattr(module, name, call)


def test_eighty_real_campaign_renders_bind_and_prove_identical_authority_once(authority_case, monkeypatch):
    case = authority_case
    reference = authority(case)
    counts = {}
    for module, name in [(delivery, "validate"), (delivery, "_bind"), (delivery, "_raw_dependencies"), (control, "_derive")]:
        counted(monkeypatch, module, name, counts)
    sites = [campaigns.Site("candidate-" + str(i), "site-" + str(i), str(i) * 64,
        "https://fixture" + str(i) + ".invalid", "fixture-set", "f" * 64) for i in range(1, 6)]
    owner = operations.OperationFacts()
    rendered = []
    with owner.scope():
        for block in range(1, 17):
            for mode in campaigns.MODES:
                lane = campaigns.Lane("formal", block, 2, mode,
                    campaigns._campaign_name("formal", block, 2, mode, 1, 6),
                    tuple(site.workload_id for site in sites), 4,
                    None if mode == "undefended" else "fixture-set", study_version=6)
                rendered.append(campaigns.render_lane_campaign(lane, sites,
                    static_capture_limits=capture_limits(16_777_216, 64),
                    application_body_identity_policy=delivery.POLICY,
                    qualification_delivery_compatibility=reference))
        owner.check()
    assert len(rendered) == 80 and len(set(rendered)) == 80
    assert counts == {"validate": 1, "_bind": 1, "_raw_dependencies": 1, "_derive": 1}
    assert operations.current_context() is None


@pytest.mark.parametrize("mutation", ["raw", "mode", "membership"])
def test_authority_memo_closing_fence_refuses_mutation(authority_case, monkeypatch, mutation):
    case = authority_case
    tree = case.watched.parent / "complete-raw-tree"
    tree.mkdir(); (tree / "first").write_bytes(b"complete original raw member")
    dependencies = delivery._raw_dependencies
    def raw(reference, value):
        files, trees = dependencies(reference, value)
        return files, [*trees, tree]
    monkeypatch.setattr(delivery, "_raw_dependencies", raw)
    reference = authority(case)
    owner = operations.OperationFacts()
    with owner.scope():
        control.validate(reference, body_policy=delivery.POLICY)
        control.validate(reference, body_policy=delivery.POLICY)
        owner.check()
        if mutation == "raw":case.watched.write_bytes(b"changed retained raw")
        elif mutation == "mode":case.watched.chmod(case.watched.stat().st_mode ^ 0o040)
        else:(tree / "new-member").write_bytes(b"unreported member")
        effects = []
        with pytest.raises(ValueError, match="operation dependency"):
            owner.check(); effects.append("must not execute")
        assert effects == []


def test_cached_authority_keeps_canonical_image_and_policy_refusals(authority_case):
    reference = authority(authority_case)
    owner = operations.OperationFacts()
    with owner.scope():
        control.validate(reference, body_policy=delivery.POLICY)
        with pytest.raises(ValueError, match="canonical"):
            control.validate(reference, body_policy=delivery.POLICY, canonical={"different": True})
        with pytest.raises(ValueError, match="image"):
            control.validate(reference, body_policy=delivery.POLICY, actual_image="sha256:" + "7" * 64)
        with pytest.raises(ValueError):control.validate(reference, body_policy="unknown")
        owner.check()


def test_new_owned_action_cannot_inherit_authority_binding_or_result(authority_case, monkeypatch):
    reference = authority(authority_case)
    counts = {}
    counted(monkeypatch, delivery, "validate", counts)
    owner = operations.OperationFacts()
    with owner.scope():
        for _ in range(2):control.validate(reference, body_policy=delivery.POLICY)
        owner.check(); owner.begin_action()
        control.validate(reference, body_policy=delivery.POLICY)
        owner.check()
    assert counts["validate"] == 2


def test_authority_transport_roots_are_bound_once_and_return_independent_copies(authority_case, monkeypatch):
    reference = authority(authority_case)
    counts = {}
    counted(monkeypatch, delivery, "validate", counts)
    counted(monkeypatch, delivery, "_raw_dependencies", counts)
    owner = operations.OperationFacts()
    with owner.scope():
        results = [control.roots(reference, body_policy=delivery.POLICY) for _ in range(80)]
        assert all(result == results[0] for result in results)
        results[0].append(Path("/changed-returned-copy"))
        assert Path("/changed-returned-copy") not in control.roots(reference, body_policy=delivery.POLICY)
        owner.check()
    assert counts == {"validate": 1, "_raw_dependencies": 3}


def test_binding_key_includes_exact_consumer_and_completed_role_document(authority_case, monkeypatch):
    reference = authority(authority_case)
    value = ready._json(ready._reference(reference)[1])
    counts = {}
    counted(monkeypatch, delivery, "_bind", counts)
    owner = operations.OperationFacts()
    with owner.scope():
        control._bind(owner, reference, value)
        control._bind(owner, reference, deepcopy(value))
        changed = deepcopy(value); changed["consumer"] = changed["producer"]
        control._bind(owner, reference, changed)
        owner.check()
    assert counts["_bind"] == 2


def test_bridge_derivation_and_transport_are_once_per_action(case, monkeypatch):
    reference = bridge.declare(case.output, **case.inputs)
    counts = {}
    counted(monkeypatch, bridge, "_derive", counts)
    owner = operations.OperationFacts()
    with owner.scope():
        results = [bridge.validate(reference, runtime=case.inputs["current_runtime"], mode="tamaraw") for _ in range(80)]
        roots = [bridge.roots(reference, runtime=case.inputs["current_runtime"], mode="tamaraw") for _ in range(80)]
        assert all(result == results[0] for result in results)
        assert all(root == roots[0] for root in roots)
        assert counts["_derive"] == 1
        results[0]["source"]["lab_commit"] = "changed local returned copy"
        assert bridge.validate(reference, runtime=case.inputs["current_runtime"], mode="tamaraw")["source"] != results[0]["source"]
        with pytest.raises(ValueError):bridge.validate(reference, runtime=case.inputs["original_runtime"], mode="tamaraw")
        with pytest.raises(ValueError):bridge.validate(reference, runtime=case.inputs["current_runtime"], mode="front")
        owner.check(); owner.begin_action()
        bridge.validate(reference, runtime=case.inputs["current_runtime"], mode="tamaraw")
        owner.check()
        assert counts["_derive"] == 2


@pytest.mark.parametrize("mutation", ["raw", "mode", "member"])
def test_bridge_cached_result_closes_full_original_and_current_raw(case, mutation):
    reference = bridge.declare(case.output, **case.inputs)
    owner = operations.OperationFacts()
    with owner.scope():
        bridge.validate(reference, runtime=case.inputs["current_runtime"], mode="tamaraw")
        bridge.roots(reference, runtime=case.inputs["current_runtime"], mode="tamaraw")
        if mutation == "raw":Path(case.inputs["current_witness"]["path"]).write_bytes(b"changed original witness")
        elif mutation == "mode":Path(case.inputs["current_witness"]["path"]).chmod(0o600)
        else:(case.new_root / "unreported.py").write_bytes(b"new Source member")
        with pytest.raises(ValueError, match="operation dependency"):owner.check()


def test_complete_canary_binding_dedup_and_new_action_fences(scheduled, monkeypatch):
    runtime = {key: scheduled.base.serializable()[key] for key in ready.RUNTIME_KEYS}
    owner = operations.OperationFacts()
    counts = {}
    counted(monkeypatch, owner, "_references", counts)
    owner.bind_canary(scheduled.canary, runtime)
    first = counts["_references"]
    for _ in range(80):owner.bind_canary(scheduled.canary, runtime)
    assert counts["_references"] == first
    owner.check(); owner.begin_action(); owner.bind_canary(scheduled.canary, runtime)
    assert counts["_references"] == first * 2
    owner.check()
    (scheduled.canary_result / "unreported-member").write_bytes(b"mutation after memo")
    with pytest.raises(ValueError, match="operation dependency"):owner.check()
