"""Prospective HOST controls; runtime/canary facts synthetic, zero credit."""
from copy import deepcopy
from pathlib import Path
import hashlib
import json
import pytest
import yaml

from qcsd_lab import buflo_duration_budget as budget, parameters
from qcsd_lab import capture_acceptance_policy as capture
from qcsd_lab import rapid_capture_traffic as traffic
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import supplied_static_capture_amendment as amendment
from qcsd_lab import manifest as manifests
from tests.test_supplied_static_capture_amendment import original, qualifier_and_canary, REPOSITORY
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_supplied_static_get import actual_contract_fixture, load, write
from tests.test_buflo_duration_budget import _run


def publish64(a):
    for relative in amendment.authority_files(budget.CADENCE64_POLICY).values():
        path = Path(a.runtime["runtime_source_root"]) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((REPOSITORY / relative).read_bytes())
    for root in ("runtime_source_root", "execution_root"):
        for relative, digest in traffic.parameter_files(budget.CADENCE64_POLICY):
            raw = (REPOSITORY / relative).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == digest
            path = Path(a.runtime[root]) / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    return amendment.publish_amendment(a.enrollment, a.runtime, a.output,
        buflo_policy=capture.CADENCE64_KERNEL_PREPARATION_POLICY,
        buflo_duration_policy=budget.CADENCE64_POLICY)


def test_public64_parameters_provenance_and_real_native_parameter_binding(monkeypatch):
    monkeypatch.setattr(parameters, "LAB_ROOT", REPOSITORY)
    path = REPOSITORY / budget.CADENCE64_PARAMETER_PATH
    raw = path.read_bytes()
    assert raw == budget.cadence64_parameter_bytes()
    artifact = parameters.validate_parameter_artifact(path, expected_kind="buflo",
        allow_study_candidate=True, expected_qcsd_profile="research-1200", expected_udp_payload_ceiling=1200)
    assert artifact.input_policy == budget.CADENCE64_INPUT_POLICY
    assert artifact.provenance_sha256 == traffic.CADENCE64_PROVENANCE_SHA256
    run = _run(raw, path=str(path))
    run["defense_parameters"][budget.RUN_FIELD] = dict(budget.CADENCE64_RECEIPT)
    parameters.validate_run_parameter_binding(run, kind="buflo", sha256=artifact.sha256, expected_path=path)
    run["defense_parameters"][budget.RUN_FIELD] = dict(budget.RECEIPT)
    with pytest.raises(ValueError):
        parameters.validate_run_parameter_binding(run, kind="buflo", sha256=artifact.sha256, expected_path=path)
    with pytest.raises(ValueError):
        parameters.validate_parameter_artifact(path, expected_kind="buflo")


def test_cadence64_amendment_keeps_full_graph_and_all_original_evidence_bytes(original):
    a = original
    old = {p: p.read_bytes() for p in (a.original, a.terminal, a.enrollment,
        a.get_root / "full-get-proof.json", a.context.root / "provenance.json", a.study / "policy.json")}
    publish64(a)
    closed = amendment.validate_amendment(a.output, enrollment=a.enrollment, runtime=a.runtime)
    derived = load(a.target)
    assert closed[traffic.FIELD] == budget.CADENCE64_POLICY
    assert closed["contract"] == amendment.CADENCE64_CONTRACT
    assert closed["modes"] == ["buflo"]
    assert derived["resources"] == a.manifest["resources"]
    assert derived["preparation"]["data_role"] == amendment.CADENCE64_ROLE
    assert derived["preparation"][capture.FIELD] == capture.CADENCE64_ACK_START_POLICY
    assert derived["preparation"]["static_get_evidence"] == a.manifest["preparation"]["static_get_evidence"]
    manifests.validate_research_preparation(derived, workload_id=a.original.stem)
    assert all(p.read_bytes() == raw for p, raw in old.items())
    with pytest.raises(ValueError):
        amendment.publish_amendment(a.enrollment, a.runtime, a.output,
            buflo_policy=capture.CADENCE64_KERNEL_PREPARATION_POLICY,
            buflo_duration_policy=budget.CADENCE64_POLICY)


def test_cadence64_stock_campaign_render_changes_only_explicit_buflo_lane(original):
    a = original
    publish64(a)
    qualifier, _, canary, facts = qualifier_and_canary(a)
    path = rolling._open_ref(canary["plan"])
    value = load(path)
    value.update({traffic.FIELD: budget.CADENCE64_POLICY, "campaigns": [{"mode": "buflo"}]})
    write(path, value)
    canary["plan"] = rolling._ref(path)
    facts["traffic_hashes"] = traffic.expected(budget.CADENCE64_POLICY)
    output = a.study / "cadence64-plan.json"
    rolling.publish_plan(a.study, a.enrollment, qualifier, output, readiness={"buflo": canary},
                         runtime_inputs=a.runtime, static_capture_amendment=a.output)
    spec = rolling.capture_spec(a.study, a.enrollment, qualifier, output)
    sites, payload = rolling.verify_capture_plan(spec)
    for row in payload["lanes"]:
        lane = rolling.plan.Lane(**{key: tuple(item) if key == "workload_ids" else item
                                   for key, item in row.items() if key != "campaign_sha256"})
        raw = (spec.campaign_dir / (lane.campaign_name + ".yml")).read_bytes()
        actual = yaml.safe_load(raw)
        if lane.mode == "buflo":
            assert actual["defenses"][0]["parameters"].endswith("/buflo-cadence64-budget640.json")
            assert (actual["limits"]["timeout_seconds"], actual["limits"]["capture_seconds"]) == (680, 740)
        else:
            assert raw == rolling.plan.render_lane_campaign(lane, sites, static_capture_limits=payload["capture_limits"])
    assert traffic.files() == lanes.TRAFFIC_FILES
    assert traffic.files(budget.POLICY)["buflo_parameters_sha256"][1] == budget.PARAMETER_SHA256


@pytest.mark.parametrize("policies,duration", [
    ({capture.BUFLO_KERNEL_PREPARATION_FIELD: capture.BUFLO_KERNEL_PREPARATION_POLICY}, budget.CADENCE64_POLICY),
    ({capture.BUFLO_KERNEL_PREPARATION_FIELD: capture.CADENCE64_KERNEL_PREPARATION_POLICY}, budget.CADENCE64_POLICY),
    ({capture.BUFLO_KERNEL_PREPARATION_FIELD: capture.CADENCE64_KERNEL_PREPARATION_POLICY,
      capture.FIELD: capture.CADENCE64_ACK_START_POLICY}, budget.POLICY),
    ({capture.BUFLO_KERNEL_PREPARATION_FIELD: capture.CADENCE64_KERNEL_PREPARATION_POLICY,
      capture.FIELD: capture.ACK_START_POLICY}, budget.CADENCE64_POLICY),
])
def test_mixed_missing_or_legacy_policy_pairs_cannot_select64(policies, duration):
    with pytest.raises(ValueError):
        amendment._policies(policies, buflo_duration_policy=duration)


@pytest.mark.parametrize("selected", [True, False, "unknown", 640, 640.0])
def test_traffic_cannot_infer64_from_nonpolicy_values(selected):
    with pytest.raises(ValueError):
        traffic.files(selected)


def test_static_cli_new_choice_requires_explicit_complete_pair_and_old_default_is_none():
    from tools.rapid_rolling_capture import _parser
    base = ["static-amendment", "--enrollment", "/old", "--runtime-spec", "/runtime", "--output", "/new"]
    assert _parser().parse_args(base).buflo_duration_policy is None
    args = _parser().parse_args(base + ["--buflo-policy", capture.CADENCE64_KERNEL_PREPARATION_POLICY,
                                      "--buflo-duration-policy", budget.CADENCE64_POLICY])
    assert amendment.policies(buflo_policy=args.buflo_policy, buflo_duration_policy=args.buflo_duration_policy) == {
        capture.BUFLO_KERNEL_PREPARATION_FIELD: capture.CADENCE64_KERNEL_PREPARATION_POLICY,
        capture.FIELD: capture.CADENCE64_ACK_START_POLICY}
    with pytest.raises(ValueError):
        amendment.policies(front_policy=capture.FRONT_RESERVE_POLICY,
            buflo_policy=capture.CADENCE64_KERNEL_PREPARATION_POLICY, buflo_duration_policy=budget.CADENCE64_POLICY)


@pytest.fixture
def synthetic_target_pair(tmp_path, monkeypatch):
    """Unit seam fixture; no original plan, readiness, Native or deep proof."""
    from dataclasses import asdict, replace
    from types import SimpleNamespace
    from qcsd_lab import rapid_parallel_capture as parallel
    from qcsd_lab import rapid_target_parallel_schedule as workers
    from qcsd_lab import rapid_slot_chunks as slots
    runtime = {key: str(tmp_path / key) for key in parallel.RUNTIME_KEYS}
    runtime["collection_image_digest"] = "sha256:" + "0" * 64
    for key in ("runtime_source_root", "module_root", "execution_root"):
        for relative, digest in traffic.parameter_files(budget.CADENCE64_POLICY):
            raw = (REPOSITORY / relative).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == digest
            path = Path(runtime[key]) / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o644)
    for key in ("runtime_source_root", "execution_root"):
        for filename in ("buflo-live.json", "buflo-live.json.provenance.json",
                         "cs-buflo-ctsp-live.json", "cs-buflo-ctsp-live.json.provenance.json"):
            relative = "config/defense-params/" + filename
            (Path(runtime[key]) / relative).write_bytes((REPOSITORY / relative).read_bytes())
    campaign_dir = Path(runtime["execution_root"]) / "config/campaigns"
    campaign_dir.mkdir(parents=True)
    specs, payloads, references, campaigns, verified = {}, {}, [], [], []
    for index, start in enumerate((0, 16)):
        lane = slots.ChunkLane("formal", 1, 17, "buflo", "unset", ("synthetic-full-graph",),
            16, "synthetic-whole-group", start, "a" * 64)
        lane = replace(lane, campaign_name=slots.name(lane, 1))
        lane = slots.checked_lane(asdict(lane))
        campaign = campaign_dir / (lane.campaign_name + ".yml")
        raw = yaml.safe_dump({"defenses": [{"kind": "buflo", "parameters":
            "../defense-params/buflo-cadence64-budget640.json"}]}).encode()
        campaign.write_bytes(raw)
        campaign_sha = hashlib.sha256(raw).hexdigest()
        path = tmp_path / ("synthetic-spec-" + str(index) + ".json")
        path.write_bytes(b"explicitly synthetic unit-seam spec\n")
        spec = SimpleNamespace(campaign_dir=campaign_dir,
            **{key: Path(runtime[key]) for key in ("runtime_source_root", "module_root", "execution_root")},
            serializable=lambda: dict(runtime))
        payload = {"study_version": 6, "static_capture_amendment": {"synthetic": True},
            traffic.FIELD: budget.CADENCE64_POLICY,
            "lanes": [{**asdict(lane), "campaign_sha256": campaign_sha}],
            "_synthetic_capsule": {"mode": "buflo", "target_id": "synthetic-no-credit",
                                   "condition_sha256": "b" * 64}}
        specs[path], payloads[id(spec)] = spec, payload
        references.append({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        campaigns.append({"path": str(campaign), "sha256": campaign_sha})
    def verify(spec, *, require_current):
        assert require_current is True
        verified.append(spec)
        return (SimpleNamespace(workload_id="synthetic-full-graph"),), payloads[id(spec)]
    def worker(payload, lane, sites, spec):
        assert lane.mode == "buflo" and tuple(lane.workload_ids) == (sites[0].workload_id,)
        return {(sites[0].workload_id, lane.mode, lane.slot_start + local)
                for local in range(lane.visits_per_workload)}
    monkeypatch.setattr(lanes, "load_capture_spec", lambda path: specs[path])
    monkeypatch.setattr(workers, "verify_plan", verify)
    monkeypatch.setattr(workers, "require_plan", lambda payload: payload["_synthetic_capsule"])
    monkeypatch.setattr(workers, "require_worker", worker)
    monkeypatch.setattr(workers, "is_payload", lambda payload: True)
    value = {"artifact_type": "qcsd-two-worker-formal-lane-authority", "runtime": runtime,
             "lane_specs": references, "campaigns": campaigns}
    return value, payloads, verified


def test_target64_fixture_dispatch_fences_all_three_parameter_copies(synthetic_target_pair):
    from qcsd_lab import rapid_parallel_capture as parallel
    value, _, verified = synthetic_target_pair
    assert parallel._target_buflo_cadence64_parameter_fixture(value) == "buflo-cadence64-budget640.json"
    assert len(verified) == 2
    previous = parameters.LAB_ROOT
    with parallel._execution_parameter_context(value):
        assert parameters.LAB_ROOT == Path(value["runtime"]["execution_root"])
    assert parameters.LAB_ROOT == previous


@pytest.mark.parametrize("mutation", ["legacy-policy", "other-mode", "repeat-slot", "campaign-bytes",
                                      "module-copy", "module-mode", "runtime"])
def test_target64_context_refuses_changed_policy_mode_slot_copy_or_authority(synthetic_target_pair, mutation):
    from qcsd_lab import rapid_parallel_capture as parallel
    value, payloads, _ = synthetic_target_pair
    first, second = tuple(payloads.values())
    if mutation == "legacy-policy":
        second[traffic.FIELD] = budget.POLICY
    elif mutation == "other-mode":
        second["_synthetic_capsule"]["mode"] = "front"
    elif mutation == "repeat-slot":
        second["lanes"] = deepcopy(first["lanes"])
        value["campaigns"][1] = deepcopy(value["campaigns"][0])
    elif mutation == "campaign-bytes":
        Path(value["campaigns"][1]["path"]).write_bytes(b"changed\n")
    elif mutation == "module-copy":
        (Path(value["runtime"]["module_root"]) / budget.CADENCE64_PARAMETER_PATH).write_bytes(b"{}\n")
    elif mutation == "module-mode":
        (Path(value["runtime"]["module_root"]) / budget.CADENCE64_PARAMETER_PATH).chmod(0o600)
    elif mutation == "runtime":
        value["runtime"] = {**value["runtime"], "client_binary": "/changed-client"}
    with pytest.raises(ValueError):
        parallel._target_buflo_cadence64_parameter_fixture(value)
