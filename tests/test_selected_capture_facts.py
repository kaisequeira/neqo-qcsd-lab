"""Selected serial role/fence controls before parallel scheduling.

The actual-input case reopens a hash-bound selected manifest, its real direct
GET proof and actual additive membership through OperationFacts.bind_capture.
Runtime/qualifier/plan writer fields are synthetic and grant no capture credit.
New amended-role selectors are separately tested at their raw-input boundary;
an actual prospective amendment/qualification/canary remains Root-owned.
"""
from pathlib import Path
import hashlib
import json
import os

import pytest

from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_operation_facts as facts
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import selected_capture_amendment as amendment
from qcsd_lab import supplied_static_preparation as original

ROOT = Path(__file__).resolve().parents[1]


def make_spec(tmp_path, manifest, cohort=None, declared_role=None):
    source, execution = tmp_path / "source", tmp_path / "execution"
    source.mkdir()
    execution.mkdir()
    workloads = execution / "config/workloads"
    campaigns = execution / "config/campaigns"
    workloads.mkdir(parents=True)
    campaigns.mkdir()
    name = "selected-fixture"
    workload = workloads / (name + ".json")
    workload.write_text(json.dumps(manifest) + "\n")
    profile = execution / lanes.STUDY_PROFILE_FILE
    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.write_bytes((ROOT / lanes.STUDY_PROFILE_FILE).read_bytes())
    paths = {}
    for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"):
        path = source / key
        path.write_bytes(b"synthetic runtime boundary\n")
        paths[key] = path
    if cohort is None:
        cohort = tmp_path / "cohort.json"
        cohort.write_bytes(b"{}\n")
    qualifier = tmp_path / "qualifier.json"
    qualifier.write_bytes(b'{"qualification_sets":[]}\n')
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"payload": {"study_version": 6,
        "data_role": selected.ROLE if declared_role is None else declared_role,
        "lanes": [], "sites": [{"workload_id": name}]}}) + "\n")
    spec = lanes.CaptureSpec(data_root=tmp_path, runtime_source_root=source,
        module_root=source, execution_root=execution, acquisition_root=tmp_path,
        cohort=cohort, qualification_spec=qualifier, workload_root=workloads,
        campaign_dir=campaigns, plan_receipt=plan, collection_image_digest="sha256:" + "a" * 64,
        execution_generation="synthetic-role-fence", **paths)
    from qcsd_lab.rapid_capture_traffic import plan_files
    for relative, _ in plan_files({}).values():
        path = execution / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / relative).read_bytes())
    return spec, workload


def synthetic_membership(monkeypatch):
    # Other cases exercise the role/fence boundary, not an invented enrollment.
    monkeypatch.setattr(facts.OperationFacts, "_enrollment", lambda self, path: self.watch_file(path))


def test_actual_selected_manifest_reaches_capture_binding(tmp_path):
    path_text = os.environ.get("QCSD_TEST_SELECTED_MANIFEST")
    expected = os.environ.get("QCSD_TEST_SELECTED_MANIFEST_SHA256")
    enrollment = os.environ.get("QCSD_TEST_SELECTED_ENROLLMENT")
    enrollment_sha = os.environ.get("QCSD_TEST_SELECTED_ENROLLMENT_SHA256")
    if not all((path_text, expected, enrollment, enrollment_sha)):
        pytest.skip("provide actual hash-bound selected preparation and additive membership")
    raw = Path(path_text).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected
    assert hashlib.sha256(Path(enrollment).read_bytes()).hexdigest() == enrollment_sha
    manifest = json.loads(raw)
    assert selected.is_selected(manifest["preparation"])
    spec, workload = make_spec(tmp_path, manifest, cohort=Path(enrollment))
    context = facts.OperationFacts()
    context.bind_capture(spec)
    receipt = Path(manifest["preparation"]["selected_input_evidence"]["receipt"]["path"])
    assert receipt in context._files
    payload = json.loads(receipt.read_bytes())["payload"]
    assert (Path(payload["raw_root"]), False) in context._trees
    assert Path(enrollment) in context._files
    context.check()
    workload.write_bytes(workload.read_bytes() + b" ")
    with pytest.raises(ValueError, match="bytes or mode"):
        context.check()


@pytest.mark.parametrize("role", [amendment.ROLE, amendment.DURATION_ROLE])
def test_selected_amended_role_uses_exact_raw_input_selector(role, tmp_path, monkeypatch):
    synthetic_membership(monkeypatch)
    raw_tree = tmp_path / "raw-get"
    raw_tree.mkdir()
    raw = raw_tree / "native.stderr.log"
    raw.write_bytes(b"retained raw\n")
    declaration = tmp_path / "declaration.json"
    declaration.write_bytes(b"retained declaration\n")
    selected_inputs = []

    def inputs(preparation):
        assert preparation["data_role"] == role
        selected_inputs.append(preparation)
        return {declaration}, {raw_tree}

    monkeypatch.setattr(amendment, "preparation_inputs", inputs)
    spec, _ = make_spec(tmp_path, {"resources": [], "preparation": {"data_role": role}})
    context = facts.OperationFacts()
    context.bind_capture(spec)
    assert len(selected_inputs) == 1 and declaration in context._files
    assert (raw_tree, False) in context._trees
    context.check()


@pytest.mark.parametrize("role", [original.ROLE, "unknown-selected-role"])
def test_selected_plan_refuses_other_preparation_roles(role, tmp_path, monkeypatch):
    synthetic_membership(monkeypatch)
    spec, _ = make_spec(tmp_path, {"resources": [], "preparation": {"data_role": role}})
    with pytest.raises(ValueError, match="declared selected data role"):
        facts.OperationFacts().bind_capture(spec)


def test_original_static_guard_stays_strict_for_plain_selected(tmp_path, monkeypatch):
    synthetic_membership(monkeypatch)
    spec, _ = make_spec(tmp_path, {"resources": [], "preparation": {"data_role": selected.ROLE}},
                        declared_role=original.ROLE)
    with pytest.raises(ValueError, match="declared static data role"):
        facts.OperationFacts().bind_capture(spec)


@pytest.mark.parametrize("mutation", ["bytes", "mode", "membership"])
def test_selected_amended_raw_fence_retained(mutation, tmp_path, monkeypatch):
    synthetic_membership(monkeypatch)
    raw_tree = tmp_path / "raw-get"
    raw_tree.mkdir()
    raw = raw_tree / "native.stderr.log"
    raw.write_bytes(b"retained raw\n")
    raw.chmod(0o600)
    monkeypatch.setattr(amendment, "preparation_inputs", lambda preparation: (set(), {raw_tree}))
    spec, _ = make_spec(tmp_path, {"resources": [], "preparation": {"data_role": amendment.ROLE}})
    context = facts.OperationFacts()
    context.bind_capture(spec)
    if mutation == "bytes":
        raw.write_bytes(b"changed raw\n")
    elif mutation == "mode":
        raw.chmod(0o644)
    else:
        (raw_tree / "extra.json").write_bytes(b"unexpected\n")
    with pytest.raises(ValueError, match="tree bytes, mode or membership"):
        context.check()
