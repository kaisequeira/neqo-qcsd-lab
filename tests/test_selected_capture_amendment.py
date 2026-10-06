"""HOST selected raw-GET contracts; runtime/named120/canary boundaries synthetic.

The existing strict bootstrap/full GET fixture, direct selected proof, immutable
membership and public amendment/rolling/manifest/transport validators run here.
No installed, Native, network, capture, or admission credit is claimed.
"""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys
from tempfile import TemporaryDirectory

import pytest

from qcsd_lab import selected_capture_amendment as amendment
from qcsd_lab import supplied_static_capture_amendment as dispatch
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_capture_traffic as traffic
from qcsd_lab import rapid_operation_facts as operation
from qcsd_lab import capture_acceptance_policy as capture
from qcsd_lab import manifest as manifests
from qcsd_lab import static_evidence_transport as transport
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import rapid_site_admission as receipts
from tests.test_selected_capture_input import (
    additive_case, selected_graph, runtime, qualifier_fixture, forbid_history,
    REPOSITORY, load, write,
)
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_supplied_static_get import actual_contract_fixture


def producer(case):
    runtime = case["runtime"]
    for name, relative in amendment.authority_files(traffic.budget.POLICY).items():
        target = Path(runtime["runtime_source_root"]) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY / relative).read_bytes())
    files = {**traffic.files(), **traffic.files(traffic.budget.POLICY)}
    # The ordinary FRONT tuple retains the original BuFLO parameter identity.
    for relative, expected in set(traffic.files().values()) | set(files.values()):
        raw = (REPOSITORY / relative).read_bytes()
        assert graph.digest(raw) == expected
        for key in ("runtime_source_root", "execution_root"):
            target = Path(runtime[key]) / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
    return runtime


def publish(case, monkeypatch, mode):
    runtime = producer(case)
    # Synthetic named fixture leaves a workload file; the amendment is the
    # create-only writer of the actual capture manifest.
    qualifier = qualifier_fixture(case, monkeypatch)
    target = Path(runtime["workload_root"]) / case["second"]["prepared"].name
    target.unlink()
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:12:30Z")
    path = case["new_study"] / (mode + "-amendment.json")
    kwargs = ({"front_policy": capture.FRONT_RESERVE_POLICY} if mode == "front" else
        {"buflo_policy": capture.BUFLO_KERNEL_PREPARATION_POLICY,
         "buflo_duration_policy": traffic.budget.POLICY})
    dispatch.publish_amendment(case["new_enrollment"], runtime, path, **kwargs)
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:14:00Z")
    return path, qualifier, dispatch.validate_amendment(path, enrollment=case["new_enrollment"], runtime=runtime)


def canary(case, authority, mode):
    [row] = authority["workloads"]
    resources = load(Path(row["capture_manifest"]["path"]))["resources"]
    facts = {"workload_sha256": row["capture_manifest"]["sha256"],
        "authority_source": {**load(Path(case["runtime"]["source_manifest"])),
            "image_digest": case["runtime"]["collection_image_digest"]},
        "client_sha256": graph.digest(Path(case["runtime"]["client_binary"]).read_bytes()),
        "traffic_hashes": traffic.expected(authority.get(traffic.FIELD)),
        "full_graph": {"resource_count": len(resources),
            "resource_records_sha256": rolling.lanes._sha(readiness._encoded(resources)),
            "origins": sorted({rolling.origin(item["url"]) for item in resources})}}
    plan_path = case["new_study"] / (mode + "-canary-plan.json")
    plan = {"static_capture_amendment": rolling._ref(Path(authority["declaration"]["path"]).with_name(mode + "-amendment.json")),
        "campaigns": [{"mode": mode}],
        **({traffic.FIELD: authority[traffic.FIELD]} if traffic.FIELD in authority else {})}
    write(plan_path, plan)
    start = case["new_study"] / (mode + "-capture-started.json")
    write(start, {"started_at": "2026-10-04T00:13:30Z"})
    return {"plan": rolling._ref(plan_path), "capture": {"started": rolling._ref(start)}}, facts


def flight():
    path = REPOSITORY / "tools/_rapid_class_mode_flight/flight/operator.py"
    spec = importlib.util.spec_from_file_location("selected_amendment_flight", path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = result
    spec.loader.exec_module(result)
    return result


@pytest.mark.parametrize("mode", ["front", "buflo"])
def test_public_fixed_setting_preserves_raw_graph_membership_and_serial_plan(additive_case, monkeypatch, mode):
    case = additive_case
    original_files = {path: path.read_bytes() for path in (
        case["new_enrollment"], case["second"]["prepared"], case["second"]["input"],
        case["second"]["raw"] / "native/run.json")}
    path, qualifier, authority = publish(case, monkeypatch, mode)
    [row] = authority["workloads"]
    derived = load(Path(row["capture_manifest"]["path"]))
    assert amendment.is_amended(derived["preparation"])
    assert derived["resources"] == load(case["second"]["prepared"])["resources"]
    assert derived["preparation"][capture.FIELD] == capture.ACK_START_POLICY
    assert authority["modes"] == [mode] and authority["scientific_credit"] is False
    assert authority["formal_accepted_trace_count"] == 0
    assert all(path.read_bytes() == raw for path, raw in original_files.items())
    manifests.validate_research_preparation(derived, workload_id=row["workload_id"])
    roots = transport.manifest_roots(derived)
    files, trees = amendment.preparation_inputs(derived["preparation"])
    assert all(any(file.is_relative_to(root) for root in roots) for file in files)
    assert case["second"]["raw"] in trees
    assert case["new_study"] not in trees
    assert case["raw"] not in trees  # class1's independent raw is unrelated to class2
    forbid_history(monkeypatch)
    reference, facts = canary(case, authority, mode)
    monkeypatch.setattr(readiness, "validate_canary", lambda *args, **kwargs: facts)
    target = case["new_study"] / (mode + "-plan.json")
    rolling.publish_plan(case["new_study"], case["new_enrollment"], qualifier, target,
        readiness={mode: reference}, static_capture_amendment=path)
    spec = rolling.capture_spec(case["new_study"], case["new_enrollment"], qualifier, target)
    sites, payload = rolling.verify_capture_plan(spec)
    assert sites[0].workload_sha256 == row["capture_manifest"]["sha256"]
    assert payload["planned_trace_count"] == 320
    assert payload["static_capture_amendment"] == rolling._ref(path)
    assert all(any(file.is_relative_to(root) for root in rolling.enrollment_roots(spec)) for file in files)
    lane = next(item for item in payload["lanes"] if item["mode"] == mode)
    parsed_lane = rolling.plan.Lane(**{key: tuple(value) if key == "workload_ids" else value
        for key, value in lane.items() if key != "campaign_sha256"})
    rolling.require_mode_readiness(spec, parsed_lane)
    api = flight()
    assert api.typed_canary_limits([derived], case["policy"], mode, authority.get(traffic.FIELD)) == traffic.budget.capture_limits(
        mode, {**case["policy"]["capture_limits"], "max_attempts": 1}, policy=authority.get(traffic.FIELD))


def test_full_occurrence_headers_edges_and_source_cannot_change(additive_case, monkeypatch):
    path, _, authority = publish(additive_case, monkeypatch, "front")
    manifest_path = Path(authority["workloads"][0]["capture_manifest"]["path"])
    raw = manifest_path.read_bytes()
    for change in ("drop", "repeat", "header", "edge", "origin", "policy", "role", "cap"):
        value = load(manifest_path)
        if change == "drop": value["resources"].pop()
        elif change == "repeat": value["resources"].append(copy.deepcopy(value["resources"][-1]))
        elif change == "header": value["resources"][-1]["headers"].append(["x-test", "different"])
        elif change == "edge": value["resources"][-1]["depends_on"] = []
        elif change == "origin": value["preparation"]["approved_origins"].pop()
        elif change == "policy": value["preparation"][capture.FRONT_FIELD] = capture.FRONT_WINDOW_POLICY
        elif change == "role": value["preparation"]["data_role"] = selected.ROLE
        else: value["preparation"]["max_response_bytes"] += 1
        write(manifest_path, value)
        with pytest.raises(ValueError):
            dispatch.validate_amendment(path, enrollment=additive_case["new_enrollment"], runtime=additive_case["runtime"])
        manifest_path.write_bytes(raw)
    for relative in ("src/qcsd_lab/selected_capture_amendment.py", traffic.files()["research_profile_sha256"][0]):
        target = Path(additive_case["runtime"]["runtime_source_root"]) / relative
        before = target.read_bytes()
        target.write_bytes(before + b"\n")
        with pytest.raises(ValueError): dispatch.validate_amendment(path, enrollment=additive_case["new_enrollment"], runtime=additive_case["runtime"])
        target.write_bytes(before)


@pytest.mark.parametrize("kwargs", [
    {"front_policy": capture.FRONT_WINDOW_POLICY},
    {"buflo_policy": capture.BUFLO_KERNEL_PREPARATION_POLICY},
    {"front_policy": capture.FRONT_RESERVE_POLICY, "buflo_duration_policy": traffic.budget.POLICY},
    {"front_policy": capture.FRONT_RESERVE_POLICY, "buflo_policy": capture.BUFLO_KERNEL_PREPARATION_POLICY,
     "buflo_duration_policy": traffic.budget.POLICY},
])
def test_absent_unknown_or_mixed_fixed_setting_refuses_before_writes(tmp_path, kwargs):
    target = tmp_path / "refused.json"
    with pytest.raises(ValueError):
        amendment.publish_amendment(tmp_path / "no-enrollment.json", {}, target, **kwargs)
    assert not target.exists() and not target.with_name("refused-current-inputs").exists()


def test_portable_metadata_stage_preserves_stale_old_input_until_renewal(additive_case, monkeypatch):
    case = additive_case
    api = flight()
    before = case["second"]["input"].read_bytes()
    # Prospective consumer Source change: the audit/raw producer remains exact,
    # while current direct-validator bytes differ at a new imported location.
    from qcsd_lab import application_response_policy as responses
    current = case["new_study"] / "current-app-policy.py"
    current.write_bytes(Path(responses.__file__).read_bytes() + b"\n# prospective consumer fixture\n")
    monkeypatch.setattr(responses, "__file__", str(current))
    with pytest.raises(ValueError): selected.validate_input(case["second"]["input"])
    _, _, bindings, originals, roots, _ = api.selected_inputs(case["new_enrollment"], case["new_study"], prospective_amendment=True)
    assert bindings[0]["original_workload"]["sha256"] == graph.digest(case["second"]["prepared"].read_bytes())
    assert originals[0]["resources"] == load(case["second"]["prepared"])["resources"]
    runtime = producer(case)
    # Current authority snapshots match the actual imported consumer bytes.
    target = Path(runtime["runtime_source_root"]) / dispatch.SOURCE_FILES["application_response_policy"]
    target.write_bytes(current.read_bytes())
    runtime["module_root"] = runtime["runtime_source_root"]
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:12:30Z")
    path = case["new_study"] / "renewed.json"
    dispatch.publish_amendment(case["new_enrollment"], runtime, path, front_policy=capture.FRONT_RESERVE_POLICY)
    [row] = dispatch.validate_amendment(path, enrollment=case["new_enrollment"], runtime=runtime)["workloads"]
    assert row["current_selected_input"] != selected.reference(case["second"]["input"])
    assert row["original_manifest"]["sha256"] == graph.digest(case["second"]["prepared"].read_bytes())
    assert case["second"]["input"].read_bytes() == before
    selected.validate_input(selected.reopen(row["current_selected_input"]))


def test_old_unamended_and_parallel_selected_modes_stay_refused(additive_case, monkeypatch):
    qualifier = qualifier_fixture(additive_case, monkeypatch)
    for mode in ("front", "buflo"):
        with pytest.raises(ValueError, match="prospective fixed capture policy"):
            rolling.publish_plan(additive_case["new_study"], additive_case["new_enrollment"], qualifier,
                additive_case["new_study"] / (mode + "-old-plan.json"), readiness={mode: {}})
    with pytest.raises(ValueError, match="serial setting authority"):
        rolling.publish_plan(additive_case["new_study"], additive_case["new_enrollment"], qualifier,
            additive_case["new_study"] / "parallel-plan.json", readiness={"tamaraw": {}}, scheduling={})


def test_amended_transport_roots_do_not_depend_on_installed_import_path(additive_case, monkeypatch):
    _, _, authority = publish(additive_case, monkeypatch, "front")
    manifest = load(Path(authority["workloads"][0]["capture_manifest"]["path"]))
    host_roots = transport.manifest_roots(manifest)
    selected_input = selected.reopen(manifest["preparation"]["selected_input_evidence"]["receipt"])
    bound = selected._bound_validator_files(load(selected_input)["payload"])
    assert all(any(path.is_relative_to(root) for root in host_roots) for path in bound)

    with TemporaryDirectory(prefix="qcsd-selected-installed-", dir="/var/tmp") as directory:
        installed = Path(directory) / "qcsd_lab" / "rapid_selected_capture_input.py"
        installed.parent.mkdir()
        assert not any(installed.is_relative_to(root) for root in host_roots)
        original = Path(selected.__file__).read_bytes()
        installed.write_bytes(original)
        monkeypatch.setattr(selected, "__file__", str(installed))
        assert transport.manifest_roots(manifest) == host_roots

        installed.write_bytes(original + b"\n# changed installed validator\n")
        with pytest.raises(ValueError):
            transport.manifest_roots(manifest)
