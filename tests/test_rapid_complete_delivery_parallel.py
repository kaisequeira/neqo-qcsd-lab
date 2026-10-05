"""Prospective parallel delivery: real plans/GET fences; synthetic image/120/canary.

No fixture here claims installed Source, Native traffic or scientific credit.
The separate selected old worker tests retain the unchanged actuator/recovery ABI.
"""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from qcsd_lab import application_response_policy as app
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_operation_facts as operations
from qcsd_lab import rapid_original_static_parallel_schedule as original_schedule
from qcsd_lab import rapid_static_parallel_schedule as amended
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_rolling_schedule as schedule
from qcsd_lab import qualification_delivery_compatibility as compatibility
from qcsd_lab import response_budget_qualification as budget
from tests.test_rapid_original_static_parallel_schedule import current, common_data_root
from tests.test_supplied_static_capture_amendment import original, REPOSITORY
from tests.test_supplied_static_get import actual_contract_fixture, load, write
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_rapid_static_parallel_schedule import current as _amended_current_fixture

POLICY = app.COMPLETE_APPLICATION_DELIVERY_POLICY


def bind_synthetic_canary_only(monkeypatch, c):
    """Isolate the existing fake physical canary, retain every available ref.

    Schedule/capture/enrollment/full GET/Source fences remain real. This
    fixture never manufactures physical capture/deep operation receipts.
    """
    bind = operations.OperationFacts.bind_canary
    def synthetic_boundary(context, reference, runtime=None):
        if reference != c.canary:
            return bind(context, reference, runtime)
        assert runtime == {key: c.a.runtime[key] for key in lanes.RUNTIME_KEYS}
        plan = context._reference(reference["plan"])
        context._references(reference, plan.parent)
    monkeypatch.setattr(operations.OperationFacts, "bind_canary", synthetic_boundary)


@pytest.fixture
def delivery(current, monkeypatch):
    c = current
    for relative in amended.DELIVERY_CONTROL_FILES:
        for key in ("runtime_source_root", "module_root", "execution_root"):
            target = Path(c.a.runtime[key]) / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPOSITORY / relative).read_bytes())
    reopen = schedule.reopen_runtime
    def runtime_boundary(reference, runtime, *, _inspector=False):
        canonical, sources = reopen(reference, runtime, _inspector=_inspector)
        sources.update({name: (Path(runtime["runtime_source_root"]) / name).read_bytes()
                        for name in amended.DELIVERY_CONTROL_FILES})
        return canonical, sources
    monkeypatch.setattr(schedule, "reopen_runtime", runtime_boundary)
    sidecar = c.sidecars / c.a.original.name
    value = load(sidecar)
    value["schema_version"] = budget.SIDECAR_SCHEMA_VERSION
    write(sidecar, value)
    c.facts[app.APPLICATION_BODY_IDENTITY_FIELD] = POLICY
    c.facts["content_equality_across_visits_claimed"] = False
    calls = []
    def named_boundary(path, *, delivery_compatibility=None, body_policy=None, **arguments):
        assert body_policy == POLICY
        assert arguments["expected_workload_ids"] == [c.a.original.stem]
        assert arguments["require_current_implementation"] is False
        assert arguments["prefix_spec_root"] is None
        calls.append((Path(path), delivery_compatibility))
    monkeypatch.setattr(compatibility, "load_named_qualification_set", named_boundary)
    # Policy changes declare fresh campaign namespaces. The strict predecessor
    # registration is immutable and cannot be overwritten by this new policy.
    campaigns = Path(c.a.runtime["campaign_dir"]).with_name("complete-delivery-campaigns")
    campaigns.mkdir()
    c.a.runtime["campaign_dir"] = str(campaigns)
    serial = c.a.study / "serial-complete-delivery.json"
    rolling.publish_plan(c.a.study, c.a.enrollment, c.spec.qualification_spec, serial,
        readiness={c.mode: c.canary}, runtime_inputs=c.a.runtime, application_body_identity_policy=POLICY)
    c.spec = rolling.capture_spec(c.a.study, c.a.enrollment, c.spec.qualification_spec, serial)
    c.output = c.a.study / "delivery-schedule.json"
    c.budget_calls = calls
    bind_synthetic_canary_only(monkeypatch, c)
    return c


def capsule(c):
    return original_schedule.publish_schedule(c.spec, c.a.runtime, c.spec.qualification_spec,
        c.canonical, c.canonical, c.output, reason="prospective complete-delivery HOST contract")


def parallel(c, reference):
    path = c.a.study / "parallel-complete-delivery.json"
    rolling.publish_plan(c.a.study, c.a.enrollment, c.spec.qualification_spec, path,
        readiness={c.mode: c.canary}, runtime_inputs=c.a.runtime, scheduling=reference,
        application_body_identity_policy=POLICY,
        qualification_delivery_compatibility=c.facts.get("qualification_delivery_compatibility"))
    return replace(c.spec, plan_receipt=path)


def test_complete_delivery_two_registered_workers_and_successor_preserve_peer(delivery):
    c = delivery
    protected = {path: path.read_bytes() for path in
        (c.a.original, c.a.target, c.a.get_root / "full-get-proof.json", c.a.terminal, c.a.enrollment)}
    reference = capsule(c)
    value = schedule.validate_schedule(reference, runtime=c.a.runtime)
    assert value["schema_version"] == 2 and value["contract"] == original_schedule.DELIVERY_CONTRACT
    assert value[app.APPLICATION_BODY_IDENTITY_FIELD] == POLICY and value["scientific_credit"] is False
    spec = parallel(c, reference)
    _sites, payload = rolling.verify_capture_plan(spec)
    workers = [row for row in payload["lanes"] if row["mode"] == c.mode][:2]
    assert len({row["campaign_name"] for row in workers}) == 2
    assert all(row["visits_per_workload"] == 4 for row in workers)
    peer = spec.campaign_dir / (workers[1]["campaign_name"] + ".yml")
    peer_bytes = peer.read_bytes()
    original_plan = spec.plan_receipt.read_bytes()
    successor = c.a.study / "failed-only-generation-two-plan.json"
    rolling.publish_successor(spec, workers[0]["campaign_name"], 2, successor)
    _sites, recovered = rolling.verify_capture_plan(replace(spec, plan_receipt=successor))
    assert recovered[app.APPLICATION_BODY_IDENTITY_FIELD] == POLICY
    assert recovered["scheduling"] == reference
    assert len(recovered["lanes"]) == 1 and recovered["lanes"][0]["generation"] == 2
    assert recovered["lanes"][0]["block"] == workers[0]["block"]
    assert peer.read_bytes() == peer_bytes and spec.plan_receipt.read_bytes() == original_plan
    assert all(path.read_bytes() == before for path, before in protected.items())
    assert c.budget_calls


@pytest.mark.parametrize("mutation", ["absent", "null", "unknown", "bool", "schema-one", "contract-one"])
@pytest.mark.parametrize("current", ["tamaraw"], indirect=True)
def test_closed_capsule_refuses_missing_or_changed_delivery_authority(delivery, mutation):
    c = delivery
    reference = capsule(c)
    value = load(c.output)
    if mutation == "absent": del value[app.APPLICATION_BODY_IDENTITY_FIELD]
    elif mutation == "null": value[app.APPLICATION_BODY_IDENTITY_FIELD] = None
    elif mutation == "unknown": value[app.APPLICATION_BODY_IDENTITY_FIELD] = "unreviewed"
    elif mutation == "bool": value[app.APPLICATION_BODY_IDENTITY_FIELD] = True
    elif mutation == "schema-one": value["schema_version"] = 1
    else: value["contract"] = original_schedule.CONTRACT
    write(c.output, value)
    with pytest.raises(ValueError): schedule.validate_schedule(rolling._ref(c.output))
    assert not (c.a.study / "parallel-complete-delivery.json").exists()


@pytest.mark.parametrize("current", ["tamaraw"], indirect=True)
def test_original_witness_policy_current_consumer_and_roots_are_bound(delivery, monkeypatch):
    c = delivery
    witness_path = c.a.study / "exact-qualification-witness.json"
    write(witness_path, {"synthetic": "explicit original qualification/current installed consumer boundary"})
    witness = rolling._ref(witness_path)
    canonical = load(rolling._open_ref(c.canonical))
    producer = {"sha256": "7" * 64}
    consumer = {"sha256": "9" * 64}
    producer_source = deepcopy(canonical["source"])
    producer_source["lab_commit"] = "7" * 40
    producer_image = "sha256:" + "7" * 64
    seen = []
    def validate(reference, *, body_policy, canonical=None, actual_image=None):
        assert reference == witness and body_policy == POLICY
        assert canonical is None or canonical == load(rolling._open_ref(c.canonical))
        assert actual_image is None or actual_image == c.spec.collection_image_digest
        seen.append(reference)
        return {"producer_source": producer_source, "producer_image": producer_image}, producer, consumer
    monkeypatch.setattr(compatibility, "validate", validate)
    checked = []
    monkeypatch.setattr(compatibility, "validate_sidecar", lambda sidecar, canonical, **kwargs: checked.append((sidecar, kwargs)))
    c.facts["qualification_delivery_compatibility"] = witness
    sidecar = load(c.sidecars / c.a.original.name)
    sidecar.update(implementation_receipt=producer,
        qualification_source={**producer_source, "image_digest": producer_image}, qualification_image_digest=producer_image)
    write(c.sidecars / c.a.original.name, sidecar)
    campaigns = Path(c.a.runtime["campaign_dir"]).with_name("witnessed-complete-delivery-campaigns")
    campaigns.mkdir()
    c.a.runtime["campaign_dir"] = str(campaigns)
    new_serial = c.a.study / "serial-witnessed-delivery.json"
    rolling.publish_plan(c.a.study, c.a.enrollment, c.spec.qualification_spec, new_serial,
        readiness={c.mode: c.canary}, runtime_inputs=c.a.runtime,
        application_body_identity_policy=POLICY, qualification_delivery_compatibility=witness)
    c.spec = rolling.capture_spec(c.a.study, c.a.enrollment, c.spec.qualification_spec, new_serial)
    reference = capsule(c)
    value = schedule.validate_schedule(reference)
    assert value["qualification_delivery_compatibility"] == witness
    assert checked[0][1]["workload_sha256"] == rolling._ref(c.a.original)["sha256"]
    original_schedule.validate_current_qualification(producer, consumer, reference,
        actual_image=c.spec.collection_image_digest)
    with pytest.raises(ValueError):
        original_schedule.validate_current_qualification({"sha256": "changed"}, consumer, reference,
            actual_image=c.spec.collection_image_digest)
    external = c.a.study / "external-exact-runtime"
    external.mkdir()
    monkeypatch.setattr(compatibility, "roots", lambda ref, *, body_policy: [external] if ref == witness and body_policy == POLICY else [])
    assert external in schedule.mount_roots(reference)
    assert seen and c.budget_calls[-1][1] == witness


@pytest.mark.parametrize("current", ["tamaraw"], indirect=True)
def test_plan_policy_and_raw_fences_cannot_be_changed(delivery):
    c = delivery
    reference = capsule(c)
    spec = parallel(c, reference)
    context = operations.OperationFacts()
    with context.scope():
        schedule.validate_schedule(reference, _context=context)
        context.check()
        raw = c.a.get_root / "native/packets.csv"
        before = raw.read_bytes()
        raw.write_bytes(before + b"changed retained raw\n")
        with pytest.raises(ValueError): context.check()
        raw.write_bytes(before)
        context.check()
    value = lanes._payload(spec.plan_receipt, lanes.PLAN_TYPE)
    value.pop(app.APPLICATION_BODY_IDENTITY_FIELD)
    write(spec.plan_receipt, rolling.admission._bind(lanes.PLAN_TYPE, value))
    with pytest.raises(ValueError): rolling.verify_capture_plan(spec)


@pytest.mark.parametrize("mode", ["front", "buflo"])
def test_amended_version_two_header_is_explicit_and_cannot_widen_version_one(mode):
    from datetime import UTC, datetime
    value = {name: None for name in amended.KEYS}
    value.update(schema_version=2, artifact_type=amended.CAPSULE_TYPE, contract=amended.DELIVERY_CONTRACT,
        limits=dict(schedule.LIMITS), formal_accepted_trace_count=0, scientific_credit=False,
        reason="prospective amended policy header only", mode=mode, published_at=datetime.now(UTC).isoformat(),
        application_body_identity_policy=POLICY)
    amended._header(value)
    value["schema_version"] = 1
    with pytest.raises(ValueError): amended._header(value)


@pytest.fixture(params=["front", "buflo200"])
def amended_delivery(original, request, monkeypatch):
    # Declare this policy at the fixture's first public plan publication. The
    # existing fixture supplies only the explicitly synthetic canary boundary;
    # amendment, GET, planner, registered campaigns and capsule are real.
    publish = rolling.publish_plan
    def first_complete_plan(*args, **kwargs):
        validate = readiness.validate_canary
        def canary_boundary(*canary_args, **canary_kwargs):
            facts = validate(*canary_args, **canary_kwargs)
            facts[app.APPLICATION_BODY_IDENTITY_FIELD] = POLICY
            facts["content_equality_across_visits_claimed"] = False
            return facts
        with monkeypatch.context() as local:
            local.setattr(readiness, "validate_canary", canary_boundary)
            return publish(*args, **kwargs, application_body_identity_policy=POLICY)
    monkeypatch.setattr(rolling, "publish_plan", first_complete_plan)
    c = _amended_current_fixture.__wrapped__(original, request, monkeypatch)
    monkeypatch.setattr(rolling, "publish_plan", publish)
    for relative in amended.DELIVERY_CONTROL_FILES:
        for key in ("runtime_source_root", "module_root", "execution_root"):
            target = Path(c.a.runtime[key]) / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPOSITORY / relative).read_bytes())
    reopen = schedule.reopen_runtime
    def runtime_boundary(reference, runtime, *, _inspector=False):
        assert _inspector is True
        canonical, sources = reopen(reference, runtime)
        sources.update({name: (Path(runtime["runtime_source_root"]) / name).read_bytes()
                        for name in amended.DELIVERY_CONTROL_FILES})
        return canonical, sources
    monkeypatch.setattr(schedule, "reopen_runtime", runtime_boundary)
    sidecars = Path(load(c.spec.qualification_spec)["qualification_sets"][0]["sidecar_root"])
    value = load(sidecars / c.a.original.name)
    value["schema_version"] = budget.SIDECAR_SCHEMA_VERSION
    write(sidecars / c.a.original.name, value)
    def named_boundary(_value, **kwargs):
        assert kwargs["require_current_implementation"] is False
        assert kwargs["expected_qualification_scope"] == "response-only"
        assert kwargs["prefix_spec_root"] is None
    monkeypatch.setattr(budget, "validate_named_qualification_set_manifest", named_boundary)
    bind_synthetic_canary_only(monkeypatch, c)
    return c


def test_amended_complete_policy_public_capsule_and_plan_are_mode_scoped(amended_delivery):
    c = amended_delivery
    protected = {path: path.read_bytes() for path in
        (c.a.original, c.a.target, c.a.output, c.a.get_root / "full-get-proof.json")}
    reference = amended.publish_schedule(c.spec, c.a.runtime, c.spec.qualification_spec,
        c.canonical, c.canonical, c.output, reason="prospective fresh amended complete delivery")
    value = schedule.validate_schedule(reference)
    assert value["schema_version"] == 2 and value["contract"] == amended.DELIVERY_CONTRACT
    assert value["mode"] == c.mode and value[app.APPLICATION_BODY_IDENTITY_FIELD] == POLICY
    output = c.a.study / "parallel-complete-amended-plan.json"
    rolling.publish_plan(c.a.study, c.a.enrollment, c.spec.qualification_spec, output,
        readiness={c.mode: c.canary}, runtime_inputs=c.a.runtime, scheduling=reference,
        static_capture_amendment=c.a.output, application_body_identity_policy=POLICY)
    _sites, payload = rolling.verify_capture_plan(rolling.capture_spec(
        c.a.study, c.a.enrollment, c.spec.qualification_spec, output))
    assert payload[app.APPLICATION_BODY_IDENTITY_FIELD] == POLICY
    assert payload["static_capture_amendment"] == value["static_capture_amendment"]
    assert len({row["campaign_name"] for row in payload["lanes"] if row["mode"] == c.mode}) == 16
    assert all(path.read_bytes() == raw for path, raw in protected.items())
