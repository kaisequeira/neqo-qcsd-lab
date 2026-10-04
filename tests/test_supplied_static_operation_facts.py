"""Real static preparation/enrollment joins operation-local raw closure.

GET outputs are synthetic exact-contract fixtures. Only the external named
qualification and canary primitives are substituted; no traffic is collected.
"""
from pathlib import Path

import pytest

from tests.test_supplied_static_get import actual_contract_fixture
from tests.test_supplied_static_preparation import fixed_graph, runtime, write, POLICIES
from qcsd_lab import supplied_static_admission as admission
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_operation_facts as operations
from qcsd_lab import rapid_rolling_readiness as readiness


@pytest.fixture
def static_spec(fixed_graph, tmp_path, monkeypatch):
    get_root, _, context = fixed_graph
    terminal = admission.admit(context, 1, get_root, policies=POLICIES)
    study, capture_runtime = runtime(tmp_path)
    rolling.initialize_study(context.root, study, capture_runtime, supplied_static=True)
    enrollment = rolling.enroll(study)
    original, _ = admission.prepared_workload(context, terminal)
    workloads = Path(capture_runtime["workload_root"])
    (workloads / original.name).write_bytes(original.read_bytes())
    sidecars = Path(capture_runtime["campaign_dir"]).parent / "chaff-response-qualification-store/sets/static-test"
    sidecars.mkdir(parents=True)
    write(sidecars / "_qualification-set.json", {"external_qualification_primitive": "HOST fixture only"})
    qualifier = study / "qualifier-spec.json"
    write(qualifier, {"schema_version": 1, "qualification_sets": [{"qualification_set": "static-test",
        "manifest": str(sidecars / "_qualification-set.json"), "sidecar_root": str(sidecars), "prefix_spec_root": None}]})
    monkeypatch.setattr(rolling, "validate_named_qualification_set_manifest", lambda *args, **kwargs: None)
    monkeypatch.setattr(readiness, "validate_canary", lambda *args, **kwargs: {})
    plan = study / "plan.json"
    rolling.publish_plan(study, enrollment, qualifier, plan,
                         readiness={"undefended": {"external_canary_primitive": "HOST fixture only"}})
    return rolling.capture_spec(study, enrollment, qualifier, plan), get_root


@pytest.mark.parametrize("mutation", ["body", "mode", "membership"])
def test_cached_static_plan_reopens_external_complete_get_tree(static_spec, mutation):
    spec, get_root = static_spec
    facts = operations.OperationFacts()
    expected = rolling.verify_capture_plan(spec, _context=facts)
    assert rolling.verify_capture_plan(spec, _context=facts) == expected
    target = get_root / "native/run.json"
    if mutation == "body":
        target.write_bytes(target.read_bytes() + b"\n")
    elif mutation == "mode":
        target.chmod((target.stat().st_mode & 0o777) ^ 0o040)
    else:
        (get_root / "new-raw-member.json").write_bytes(b"{}\n")
    with pytest.raises(ValueError, match="dependency"):
        facts.check()


def test_new_static_operation_reopens_raw_proof_instead_of_reusing_prior_facts(static_spec):
    spec, get_root = static_spec
    rolling.verify_capture_plan(spec, _context=operations.OperationFacts())
    target = get_root / "native/run.json"
    target.write_bytes(target.read_bytes() + b"\n")
    with pytest.raises(ValueError):
        rolling.verify_capture_plan(spec, _context=operations.OperationFacts())
