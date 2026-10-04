"""Prospective traffic seams; no installed qualification or scientific credit."""
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from qcsd_lab import buflo_duration_budget as budget
from qcsd_lab import capture_acceptance_policy as capture
from qcsd_lab import rapid_capture_traffic as traffic
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_operation_facts as operation
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import supplied_static_capture_amendment as amendment
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import manifest as manifests
from tests.test_supplied_static_capture_amendment import original, qualifier_and_canary, REPOSITORY
from tests.test_supplied_static_get import actual_contract_fixture, load, write
from tests.test_supplied_static_preparation import fixed_graph


def duration_inputs(a):
    for relative in amendment.authority_files(budget.POLICY).values():
        target = Path(a.runtime["runtime_source_root"]) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY / relative).read_bytes())
    for role in ("runtime_source_root", "execution_root"):
        for relative in (budget.PARAMETER_PATH, traffic.PROVENANCE_PATH):
            target = Path(a.runtime[role]) / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPOSITORY / relative).read_bytes())


def publish(a):
    duration_inputs(a)
    return amendment.publish_amendment(a.enrollment, a.runtime, a.output,
        buflo_policy=capture.BUFLO_KERNEL_PREPARATION_POLICY, buflo_duration_policy=budget.POLICY)


def planned(a):
    publish(a)
    qualifier, sidecars, canary, facts = qualifier_and_canary(a)
    canary_path = rolling._open_ref(canary["plan"])
    value = load(canary_path)
    value.update({traffic.FIELD: budget.POLICY, "campaigns": [{"mode": "buflo"}]})
    write(canary_path, value)
    canary["plan"] = rolling._ref(canary_path)
    facts["traffic_hashes"] = traffic.expected(budget.POLICY)
    output = a.study / "duration-plan.json"
    rolling.publish_plan(a.study, a.enrollment, qualifier, output, readiness={"buflo": canary},
                         runtime_inputs=a.runtime, static_capture_amendment=a.output)
    spec = rolling.capture_spec(a.study, a.enrollment, qualifier, output)
    return spec, canary, facts


def test_duration_amendment_preserves_original_get_and_declares_new_source_before_derived_files(original):
    a = original
    originals = {path: path.read_bytes() for path in (a.original, a.terminal, a.enrollment,
        a.get_root / "full-get-proof.json", a.context.root / "provenance.json", a.study / "policy.json")}
    publish(a)
    closed = amendment.validate_amendment(a.output, enrollment=a.enrollment, runtime=a.runtime)
    derived = load(a.target)
    assert closed[traffic.FIELD] == budget.POLICY and closed["modes"] == ["buflo"]
    assert closed["contract"] == amendment.DURATION_CONTRACT
    assert derived["preparation"]["data_role"] == amendment.DURATION_ROLE
    assert derived["resources"] == a.manifest["resources"]
    assert derived["preparation"]["static_get_evidence"] == a.manifest["preparation"]["static_get_evidence"]
    declaration = rolling._open_ref(closed["declaration"])
    value = rolling.admission._unpack(declaration.read_bytes(), amendment.DECLARATION_TYPE)
    assert set(value["authority_sources"]) == set(amendment.authority_files(budget.POLICY))
    assert value["traffic_artifacts"] == traffic.artifacts(a.runtime, budget.POLICY)
    manifests.validate_research_preparation(derived, workload_id=a.original.stem)
    assert all(path.read_bytes() == raw for path, raw in originals.items())


def test_only_buflo_campaign_changes_and_other_mode_slots_are_byte_exact(original):
    a = original
    spec, canary, _ = planned(a)
    sites, payload = rolling.verify_capture_plan(spec)
    assert payload[traffic.FIELD] == budget.POLICY
    assert payload["planned_trace_count"] == 320 and len(payload["lanes"]) == 80
    historical = deepcopy(lanes.TRAFFIC_FILES)
    for row in payload["lanes"]:
        lane = rolling.plan.Lane(**{key: tuple(value) if key == "workload_ids" else value
            for key, value in row.items() if key != "campaign_sha256"})
        raw = (spec.campaign_dir / (lane.campaign_name + ".yml")).read_bytes()
        actual = yaml.safe_load(raw)
        if lane.mode == "buflo":
            assert actual["defenses"][0]["parameters"].endswith("/buflo-duration200.json")
            assert (actual["limits"]["timeout_seconds"], actual["limits"]["capture_seconds"]) == (240, 300)
            assert rolling.require_mode_readiness(spec, lane) == canary
        else:
            assert raw == rolling.plan.render_lane_campaign(lane, sites, static_capture_limits=payload["capture_limits"])
            assert (actual["limits"]["timeout_seconds"], actual["limits"]["capture_seconds"]) == (120, 180)
    assert lanes.TRAFFIC_FILES == historical
    assert traffic.spec_files(spec) == traffic.files(budget.POLICY)
    assert traffic.files() == historical
    facts = operation.OperationFacts()
    facts.bind_capture(spec)
    facts.check()
    target = spec.execution_root / traffic.PROVENANCE_PATH
    target.write_bytes(target.read_bytes() + b"\n")
    with pytest.raises(ValueError):
        facts.check()


@pytest.mark.parametrize("change", ["parameters", "provenance", "duration-helper", "traffic-helper", "lane-authority", "readiness-authority"])
def test_duration_authority_rejects_changed_bound_bytes(original, change):
    a = original
    publish(a)
    if change in {"parameters", "provenance"}:
        relative = budget.PARAMETER_PATH if change == "parameters" else traffic.PROVENANCE_PATH
        target = Path(a.runtime["execution_root"]) / relative
    else:
        name = {"duration-helper": "buflo_duration_budget", "traffic-helper": "rapid_capture_traffic",
                "lane-authority": "rapid_lane_evidence", "readiness-authority": "rapid_rolling_readiness"}[change]
        target = Path(a.runtime["runtime_source_root"]) / amendment.DURATION_SOURCE_FILES[name]
    target.write_bytes(target.read_bytes() + b"\n# changed prospective authority\n")
    with pytest.raises(ValueError):
        amendment.validate_amendment(a.output, enrollment=a.enrollment, runtime=a.runtime)


@pytest.mark.parametrize("selected", [None, False, "other-policy"])
def test_a_plan_cannot_infer_or_forge_the_new_duration(selected):
    value = {"study_version": 6, "static_capture_amendment": {"path": "/bound", "sha256": "a" * 64},
             traffic.FIELD: selected}
    with pytest.raises(ValueError):
        traffic.plan_files(value)
    assert traffic.plan_files({"study_version": 6}) == lanes.TRAFFIC_FILES


def test_duration_canary_cannot_authorize_other_modes_or_multiple_settings():
    plan = {traffic.FIELD: budget.POLICY, "static_capture_amendment": {}, "campaigns": [{"mode": "buflo"}]}
    assert traffic.canary_files(plan, "buflo") == traffic.files(budget.POLICY)
    for mode in ("undefended", "front", "tamaraw", "cs-buflo"):
        with pytest.raises(ValueError): traffic.canary_files(plan, mode)
    plan["campaigns"].append({"mode": "front"})
    with pytest.raises(ValueError): traffic.canary_files(plan)


def test_duration_canary_policy_is_exactly_the_amendment_policy(original):
    a = original
    spec, canary, facts = planned(a)
    path = rolling._open_ref(canary["plan"])
    value = load(path); value.pop(traffic.FIELD); write(path, value)
    canary["plan"] = rolling._ref(path)
    closed = amendment.validate_amendment(a.output, enrollment=a.enrollment, runtime=a.runtime)
    with pytest.raises(ValueError, match="duration policy"):
        amendment.require_canary(canary, facts, rolling._ref(a.output), closed, mode="buflo")


def test_cli_duration_choice_is_explicit_and_old_defaults_remain_none():
    from tools.rapid_rolling_capture import _parser
    required = ["static-amendment", "--enrollment", "/enrollment", "--runtime-spec", "/runtime", "--output", "/new"]
    assert _parser().parse_args(required).buflo_duration_policy is None
    assert _parser().parse_args(required + ["--buflo-duration-policy", budget.POLICY]).buflo_duration_policy == budget.POLICY
    with pytest.raises(SystemExit): _parser().parse_args(required + ["--buflo-duration-policy", "longer"])


def test_current_amended_qualification_authority_has_no_legacy_scheduling_derivation(original, monkeypatch):
    # Fresh qualification/preflight authenticates these prospective imports
    # explicitly. It does not reuse the historical scheduling AST contract.
    from qcsd_lab import rapid_runtime_compatibility as legacy
    def prohibited(*args, **kwargs):
        raise AssertionError("new serial static authority entered historical scheduling derivation")
    monkeypatch.setattr(legacy, "qualification_dependencies", prohibited)
    a = original
    publish(a)
    derived = load(a.target)
    original_facts = amendment.preparation.validate_static_preparation(a.manifest["preparation"], a.manifest["resources"])
    assert amendment.validate_preparation(derived["preparation"], derived["resources"]) == original_facts
    closed = amendment.validate_amendment(a.output, enrollment=a.enrollment, runtime=a.runtime)
    assert closed[traffic.FIELD] == budget.POLICY
    declaration = amendment._declaration(rolling._open_ref(closed["declaration"]))
    assert set(declaration["authority_sources"]) == set(amendment.authority_files(budget.POLICY))
