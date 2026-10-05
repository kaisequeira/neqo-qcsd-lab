"""Ordinary-only authority controls; HOST fixtures grant no capture credit.

Synthetic cases retain the real input/plan/render/fence code and substitute
only original admission and completed-canary authorities. The opt-in actual
case uses the real current eleven-class enrollment and its own five raw GETs.
"""
from dataclasses import asdict
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest
import yaml

from qcsd_lab import rapid_undefended_capture as ordinary
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_additive_static_enrollment as additive
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab.rapid_operation_facts import OperationFacts

ROOT = Path(__file__).resolve().parents[1]


def portable():
    path = ROOT / "tools/_rapid_class_mode_flight/flight/operator.py"
    spec = importlib.util.spec_from_file_location("ordinary_portable_control", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def fixtures(tmp_path, monkeypatch):
    execution = tmp_path / "execution"
    campaigns = execution / "config/campaigns"
    workloads = execution / "config/workloads"
    campaigns.mkdir(parents=True)
    workloads.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    (source / "qcsd-lab").write_bytes(b"synthetic launcher boundary\n")
    (execution / "qcsd-lab").write_bytes((source / "qcsd-lab").read_bytes())
    for relative, _ in lanes.TRAFFIC_FILES.values():
        target = execution / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    profile = execution / lanes.STUDY_PROFILE_FILE
    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.write_bytes((ROOT / lanes.STUDY_PROFILE_FILE).read_bytes())
    source_meta = tmp_path / "source.json"
    source_meta.write_bytes(encoded({"lab_commit": "a" * 40, "lab_dirty": False,
        "neqo_commit": "b" * 40, "neqo_pinned_commit": "b" * 40, "neqo_dirty": False,
        "lab_patch_sha256": None, "neqo_patch_sha256": None, "image_digest": None}))
    client = tmp_path / "client"
    client.write_bytes(b"synthetic installed-client boundary")
    runtime = {"data_root": str(tmp_path), "execution_root": str(execution),
        "runtime_source_root": str(source), "module_root": str(ROOT),
        "source_manifest": str(source_meta), "client_binary": str(client),
        "base_launcher": str(source / "qcsd-lab"), "host_launcher": str(execution / "qcsd-lab"),
        "workload_root": str(workloads), "campaign_dir": str(campaigns),
        "execution_generation": "synthetic-ordinary", "collection_image_digest": "sha256:" + "c" * 64}
    study = tmp_path / "study"
    study.mkdir()
    policy_path = study / "policy.json"
    policy_path.write_bytes(b"synthetic verified policy boundary")
    enrollment = study / "enrollment.json"
    enrollment.write_bytes(b"synthetic verified enrollment boundary")
    (study / "provenance.json").write_bytes(b"synthetic admission provenance")
    limits = {"capture_megabytes": 64, "capture_seconds": 180, "max_attempts": 3,
        "max_response_bytes": 16777216, "per_origin_cooldown_seconds": 0,
        "settle_seconds": 2, "timeout_seconds": 120}
    identity = {"profile_sha256": "d" * 64, "selection_amendment_sha256": "e" * 64}
    policy = {"contract": additive.CONTRACT, "runtime": runtime, "capture_limits": limits,
        "data_role": selected.ROLE, "admission_identity": identity, "published_at": "2026-10-05T00:00:00Z"}
    rows = []
    for index in range(7, 12):
        original = study / ("site-" + str(index) + ".json")
        manifest = {"resources": [{"id": 0, "request_headers": {}, "depends_on": [], "fixture": index},
            {"id": 1, "request_headers": {"accept": "fixture"}, "depends_on": [0], "fixture": index}],
            "preparation": {"data_role": selected.ROLE, "final_url": "https://site" + str(index) + ".example/"}}
        original.write_bytes(encoded(manifest))
        shutil.copyfile(original, workloads / original.name)
        rows.append({"class_index": index, "candidate_id": "candidate-" + str(index),
            "workload_id": original.stem, "prepared_workload": selected.reference(original)})
    batch = {"selected_candidate_ids": [row["candidate_id"] for row in rows],
        "policy": rolling._ref(policy_path), "ordinal": 3, "admission_root": str(study),
        "declared_at": "2026-10-05T00:00:00Z"}
    monkeypatch.setattr(rolling, "_verify_enrollment", lambda path: (batch, rows, policy))
    monkeypatch.setattr(rolling, "verify_enrollment", lambda path: (batch, rows))
    monkeypatch.setattr(rolling, "verify_policy", lambda root: policy)
    monkeypatch.setattr(additive, "verify_enrollment", lambda path: (batch, rows, policy))
    monkeypatch.setattr(selected, "validate_preparation", lambda preparation, resources: {})
    monkeypatch.setattr(OperationFacts, "_enrollment", lambda self, path: self.watch_file(path))
    # First-class actual canary validation is an explicit controlled boundary.
    monkeypatch.setattr(readiness, "validate_canary", lambda reference, **kwargs: {
        "mode": "undefended", "workload_sha256": rows[0]["prepared_workload"]["sha256"],
        "recorded_image_deep_reopened": True})
    return enrollment, runtime, batch, rows, policy


def publish(tmp_path, monkeypatch):
    enrollment, runtime, batch, rows, policy = fixtures(tmp_path, monkeypatch)
    inputs = ordinary.publish_inputs(enrollment, runtime, tmp_path / "ordinary-input.json")
    output = tmp_path / "plan.json"
    rolling.publish_plan(Path(batch["policy"]["path"]).parent, enrollment, inputs, output,
        readiness={"undefended": {"controlled": "original-current-canary"}}, runtime_inputs=runtime)
    spec = rolling.capture_spec(Path(batch["policy"]["path"]).parent, enrollment, inputs, output)
    return spec, batch, rows, policy


def test_public_ordinary_plan_uses_no_qualification(tmp_path, monkeypatch):
    spec, _, rows, _ = publish(tmp_path, monkeypatch)
    sites, value = rolling.verify_capture_plan(spec)
    lanes._qualification_layout(spec)
    assert value[ordinary.FIELD] == ordinary.CONTRACT
    assert value["planned_trace_count"] == 5 * 64
    assert len(value["lanes"]) == 16
    assert all(row["mode"] == "undefended" for row in value["lanes"])
    assert all(site.qualification_set is None and site.qualification_set_manifest_sha256 is None for site in sites)
    assert not (spec.campaign_dir.parent / "chaff-response-qualification-store").exists()
    for lane in plan.plan_lanes(sites, final=True, study_version=6, rolling_batch=3):
        campaign = yaml.safe_load(lanes._render_lane_campaign(spec, lane, sites))
        assert campaign["defenses"] == ["undefended"]
        assert campaign["workloads"] == {row["workload_id"]: 4 for row in rows}
        assert "chaff_qualification_set" not in campaign


def test_default_qualified_sites_still_refuse_absent_group():
    site = plan.Site("candidate", "site", "a" * 64, "https://site.example", None, None)
    with pytest.raises(ValueError):
        plan.plan_lanes([site], final=True, study_version=6, rolling_batch=3)


@pytest.mark.parametrize("mode", ["front", "tamaraw", "buflo", "cs-buflo"])
def test_ordinary_input_refuses_defended_plans_before_writes(tmp_path, monkeypatch, mode):
    enrollment, runtime, batch, _, _ = fixtures(tmp_path, monkeypatch)
    inputs = ordinary.publish_inputs(enrollment, runtime, tmp_path / "ordinary.json")
    with pytest.raises(ValueError, match="ordinary readiness|fixed capture policy"):
        rolling.publish_plan(Path(batch["policy"]["path"]).parent, enrollment, inputs,
            tmp_path / "plan.json", readiness={mode: {}}, runtime_inputs=runtime)
    assert not (tmp_path / "plan.json").exists()


@pytest.mark.parametrize("field", ["runtime", "capture_limits", "control_sources", "sites", "enrollment"])
def test_rehashed_input_substitution_refused(tmp_path, monkeypatch, field):
    spec, _, _, _ = publish(tmp_path, monkeypatch)
    value = json.loads(spec.qualification_spec.read_bytes())
    value[field] = {} if field != "sites" else []
    spec.qualification_spec.write_bytes(encoded(value))
    with pytest.raises(ValueError, match="changed its exact"):
        rolling.verify_capture_plan(spec)


def test_changed_full_graph_refused(tmp_path, monkeypatch):
    enrollment, runtime, _, rows, _ = fixtures(tmp_path, monkeypatch)
    path = Path(runtime["workload_root"]) / (rows[0]["workload_id"] + ".json")
    value = json.loads(path.read_bytes())
    value["resources"].pop()
    path.write_bytes(encoded(value))
    with pytest.raises(ValueError, match="pruned"):
        ordinary.publish_inputs(enrollment, runtime, tmp_path / "ordinary.json")


def test_body_policy_preserved_without_qualification_witness(tmp_path, monkeypatch):
    from qcsd_lab.application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY as tag
    enrollment, runtime, batch, _, _ = fixtures(tmp_path, monkeypatch)
    monkeypatch.setattr(readiness, "validate_canary", lambda reference, **kwargs: {
        "application_body_identity_policy": tag, "mode": "undefended", "recorded_image_deep_reopened": True,
        "workload_sha256": hashlib.sha256((Path(runtime["workload_root"]) / "site-7.json").read_bytes()).hexdigest()})
    inputs = ordinary.publish_inputs(enrollment, runtime, tmp_path / "ordinary.json")
    output = tmp_path / "plan.json"
    rolling.publish_plan(Path(batch["policy"]["path"]).parent, enrollment, inputs, output,
        readiness={"undefended": {}}, runtime_inputs=runtime, application_body_identity_policy=tag)
    spec = rolling.capture_spec(Path(batch["policy"]["path"]).parent, enrollment, inputs, output)
    sites, value = rolling.verify_capture_plan(spec)
    campaign = yaml.safe_load(lanes._render_lane_campaign(spec, plan.plan_lanes(sites, final=True,
        study_version=6, rolling_batch=3)[0], sites))
    assert value["application_body_identity_policy"] == tag
    assert campaign["application_body_identity_policy"] == tag
    assert "qualification_delivery_compatibility" not in campaign


def test_input_and_workload_byte_mode_fences(tmp_path, monkeypatch):
    spec, _, _, _ = publish(tmp_path, monkeypatch)
    with OperationFacts().scope() as context:
        ordinary.validate_inputs(spec.qualification_spec, enrollment=spec.cohort,
            runtime={key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS})
        spec.qualification_spec.chmod(0o644)
        with pytest.raises(ValueError, match="mode"):
            context.check()


def test_installed_control_refuses_old_runtime_source(tmp_path, monkeypatch):
    spec, _, _, _ = publish(tmp_path, monkeypatch)
    with pytest.raises((ValueError, FileNotFoundError)):
        ordinary.validate_inputs(spec.qualification_spec, enrollment=spec.cohort,
            runtime={key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}, require_current=True)


def test_portable_ordinary_renewal_refuses_defended_stage(tmp_path, monkeypatch):
    helper = portable()
    monkeypatch.setattr(helper, "checked_runtime", lambda args: ({}, {}, ROOT))
    args = SimpleNamespace(name="ordinary-control", campaign_seed=17,
        ordinary_renewal=tmp_path / "renewal.json", enrollment=tmp_path / "enrollment.json",
        mode="tamaraw", reuse_response_manifest=None)
    args.ordinary_renewal.write_bytes(b"controlled renewal")
    with pytest.raises(ValueError, match="unqualified undefended"):
        helper.stage(args)


def test_portable_renewal_mount_is_exact_file_read_only(tmp_path):
    helper = portable()
    renewal = tmp_path / "renewal.json"
    renewal.write_bytes(b"controlled renewal")
    plan_value = {"name": "ordinary-control", "reuse": None,
        "canonical_runtime": {"collection_image_digest": "sha256:" + "c" * 64},
        "clean_runtime_root": str(tmp_path / "source"), "execution_root": str(tmp_path / "execution"),
        "helper_path": str(helper.FIRST_HELPER), "ordinary_renewal": helper.ref(renewal),
        "static_preparation_roots": [], "group_preparation_roots": [],
        "campaigns": [{"mode": "undefended"}]}
    (tmp_path / "plan.json").write_bytes(b"controlled flight plan")
    argv = helper.image_argv(plan_value, tmp_path, "preamble")
    assert f"{renewal}:{renewal}:ro" in argv
    assert argv[argv.index("--network") + 1] == "none"
    with pytest.raises(ValueError, match="no padding qualification"):
        helper.image_argv(plan_value, tmp_path, "qualify-image")


def test_portable_typed_renewal_intake_keeps_exact_graph_binding(tmp_path, monkeypatch):
    helper = portable()
    renewal = tmp_path / "renewal.json"
    renewal.write_bytes(b"controlled renewal")
    manifest = {"resources": [{"id": 0, "url": "https://fixture.example/", "depends_on": []},
        {"id": 1, "url": "https://fixture.example/a", "depends_on": [0]}],
        "preparation": {"data_role": selected.ROLE}}
    binding = {"candidate_id": "fixture", "class_index": 7}
    seen = []
    def intake(path, enrollment, study):
        seen.append((path, enrollment, study))
        return {}, {}, [copy.deepcopy(binding)], [manifest], [], {}
    monkeypatch.setattr(ordinary, "flight_inputs", intake)
    result = helper.selected_inputs(tmp_path / "enrollment", tmp_path / "study",
        ordinary_renewal=helper.ref(renewal))
    assert result[2][0]["full_graph"] == helper.graph(manifest)
    assert result[2][0]["class_index"] == 7
    assert len(seen) == 1


@pytest.mark.parametrize("missing", [False, True])
def test_other_or_unclosed_canary_cannot_publish_ordinary_plan(tmp_path, monkeypatch, missing):
    enrollment, runtime, batch, _, _ = fixtures(tmp_path, monkeypatch)
    monkeypatch.setattr(readiness, "validate_canary", lambda reference, **kwargs: {
        "mode": "undefended", "workload_sha256": "a" * 64,
        "recorded_image_deep_reopened": not missing})
    inputs = ordinary.publish_inputs(enrollment, runtime, tmp_path / "ordinary.json")
    with pytest.raises(ValueError, match="enrolled full-site"):
        rolling.publish_plan(Path(batch["policy"]["path"]).parent, enrollment, inputs, tmp_path / "plan.json",
            readiness={"undefended": {}}, runtime_inputs=runtime)
    assert not (tmp_path / "plan.json").exists()


def test_actual_eleven_enrollment_tail_retains_full_graphs(tmp_path):
    path_text = os.environ.get("QCSD_TEST_SELECTED_ENROLLMENT")
    digest = os.environ.get("QCSD_TEST_SELECTED_ENROLLMENT_SHA256")
    if not path_text or not digest:
        pytest.skip("provide actual hash-bound eleven-class selected enrollment")
    enrollment = Path(path_text)
    assert hashlib.sha256(enrollment.read_bytes()).hexdigest() == digest
    batch, classes, policy = rolling._verify_enrollment(enrollment)
    assert len(classes) == 11
    chosen = classes[-5:]
    assert [row["class_index"] for row in chosen] == list(range(7, 12))
    # The real eleven-class records bind an older selected direct Source.
    # Reissue only their unchanged raw GET inputs into this HOST fixture.
    renewal_path = ordinary.publish_renewal(enrollment, tmp_path / "renewal.json")
    renewal, _, _, _ = ordinary.validate_renewal(renewal_path, enrollment)
    for row in renewal["rows"]:
        current = selected.reopen(row["current_manifest"])
        original = json.loads(selected.reopen(row["original_manifest"]).read_bytes())
        assert json.loads(current.read_bytes())["resources"] == original["resources"]
        shutil.copyfile(current, tmp_path / current.name)
    sites = ordinary._admitted_sites(batch, classes, policy, tmp_path, renewal=renewal)
    assert [site.candidate_id for site in sites] == batch["selected_candidate_ids"]
    assert [site.workload_sha256 for site in sites] == [row["current_manifest"]["sha256"] for row in renewal["rows"]]
    assert len(plan.plan_lanes(sites, final=True, study_version=6, rolling_batch=batch["ordinal"])) == 16
    assert all(site.qualification_set is None for site in sites)
    assert sum(len(json.loads((tmp_path / (site.workload_id + ".json")).read_bytes())["resources"]) for site in sites) > 0


def finalized_ordinary(tmp_path, monkeypatch):
    """Real portable finalize; only prevalidated admission/runtime boundary is synthetic."""
    helper = portable()
    output = tmp_path / "flight"
    execution = output / "execution-root"
    (execution / "config/workloads").mkdir(parents=True)
    for name in ("logs", "plans"):
        (output / name).mkdir()
    enrollment = tmp_path / "enrollment.json"
    enrollment.write_bytes(b"controlled original admission boundary")
    renewal = tmp_path / "renewal.json"
    renewal.write_bytes(b"controlled authenticated renewal boundary")
    manifest = {"resources": [{"id": 0, "url": "https://fixture.example/", "depends_on": [], "request_headers": {}}],
        "preparation": {"data_role": selected.ROLE}}
    original = tmp_path / "original.json"
    original.write_bytes(encoded(manifest))
    copied = execution / "config/workloads/site.json"
    copied.write_bytes(original.read_bytes())
    binding = {"candidate_id": "candidate", "class_index": 7, "workload_id": "site",
        "original_workload": helper.ref(original), "full_graph": helper.graph(manifest),
        "selection_sha256": "d" * 64, "admission_root": str(tmp_path), "terminal": helper.ref(enrollment)}
    limits = {"capture_megabytes": 64, "capture_seconds": 180, "max_attempts": 1,
        "max_response_bytes": 16777216, "per_origin_cooldown_seconds": 0,
        "settle_seconds": 2, "timeout_seconds": 120}
    canonical_path = output / "canonical-runtime.json"
    canonical_path.write_bytes(encoded({"collection_image_digest": "sha256:" + "c" * 64}))
    setup = {"mode": "undefended", "name": "ordinary-control", "campaign_seed": 17,
        "original_limits": limits, "execution_root": str(execution), "host_python": "/controlled/python",
        "expected_lab_commit": "a" * 40, "expected_native_commit": "b" * 40,
        "canonical_runtime": json.loads(canonical_path.read_bytes()),
        "canonical_runtime_sha256": helper.ref(canonical_path)["sha256"],
        "canonical_runtime_reference": helper.ref(canonical_path),
        "study_root": str(tmp_path), "enrollment": helper.ref(enrollment), "reuse": None,
        "ordinary_renewal": helper.ref(renewal)}
    (output / "setup.json").write_bytes(encoded(setup))
    (output / "runtime-spec.json").write_bytes(b"controlled matching runtime boundary")
    monkeypatch.setattr(helper, "checked_setup", lambda args: (setup, output, ROOT,
        {"workload_root": str(copied.parent)}, [binding], [manifest]))
    monkeypatch.setattr(helper, "static_roots", lambda manifest: [])
    monkeypatch.setattr(helper, "group_roots", lambda manifests: [])
    helper.finalize(SimpleNamespace())
    plan_value = json.loads((output / "plan.json").read_bytes())
    commands = json.loads((output / "commands.json").read_bytes())
    return helper, output, execution, plan_value, commands


def record_controlled_operation(helper, output, name, command):
    (output / "logs" / (name + "-started.json")).write_bytes(encoded({"command": command,
        "started_at": "2026-10-06T00:00:00+00:00"}))
    for suffix in (".stdout.log", ".stderr.log"):
        (output / "logs" / (name + suffix)).write_bytes(b"")
    (output / "logs" / (name + "-completed.json")).write_bytes(encoded({"returncode": 0,
        "completed_at": "2026-10-06T00:00:01+00:00", "stdout_sha256": helper.digest(b""),
        "stderr_sha256": helper.digest(b"")}))


def test_real_finalize_ordinary_commands_have_no_padding_gate(tmp_path, monkeypatch):
    helper, output, execution, value, commands = finalized_ordinary(tmp_path, monkeypatch)
    assert set(commands) == {"preamble", "preflight", "inputs", "plan"}
    assert commands["inputs"][6].endswith("tools/rapid_undefended_capture.py")
    assert commands["plan"][6].endswith("tools/rapid_undefended_capture.py")
    assert "--ordinary-input" in commands["plan"]
    assert "--ordinary-readiness" in commands["plan"]
    campaign = yaml.safe_load((execution / value["campaigns"][0]["campaign_relative"]).read_bytes())
    assert campaign["defenses"] == [{"name": "undefended", "kind": "none"}]
    assert "chaff_qualification_set" not in campaign
    assert json.loads((execution / "config/workloads/site.json").read_bytes())["resources"] == [
        {"id": 0, "url": "https://fixture.example/", "depends_on": [], "request_headers": {}}]


@pytest.mark.parametrize("mutation", [None, "preamble-command", "preamble-plan", "qualify", "missing-input"])
def test_ordinary_root_dispatch_requires_real_preamble_and_input_only(tmp_path, monkeypatch, mutation):
    helper, output, execution, value, commands = finalized_ordinary(tmp_path, monkeypatch)
    plan_path = output / "plan.json"
    plan_digest = helper.digest(plan_path.read_bytes())
    monkeypatch.setattr(helper, "checked_plan", lambda args: (value, output, execution))
    calls = []
    monkeypatch.setattr(helper, "module", lambda *args: SimpleNamespace(
        recorded_run=lambda command, *args, **kwargs: calls.append(command)))
    record_controlled_operation(helper, output, "preamble", commands["preamble"])
    (output / "preamble-complete.json").write_bytes(encoded({"plan_sha256": plan_digest}))
    args = SimpleNamespace(plan=plan_path, plan_sha256=plan_digest, step="preflight")
    if mutation == "preamble-command":
        record_controlled_operation(helper, output, "preamble", ["substituted"])
    elif mutation == "preamble-plan":
        (output / "preamble-complete.json").write_bytes(encoded({"plan_sha256": "0" * 64}))
    elif mutation == "qualify":
        args.step = "qualify"
    elif mutation == "missing-input":
        args.step = "plan"
        (output / "readiness.json").write_bytes(encoded({"undefended": {"controlled": "deep boundary"}}))
    if mutation is not None:
        with pytest.raises((ValueError, FileNotFoundError)):
            helper.run(args)
        assert calls == []
    else:
        helper.run(args)
        assert calls == [commands["preflight"]]
        assert not (output / "logs/qualify-started.json").exists()
        args.step = "inputs"
        helper.run(args)
        record_controlled_operation(helper, output, "inputs", commands["inputs"])
        (output / "readiness.json").write_bytes(encoded({"undefended": {"controlled": "deep boundary"}}))
        args.step = "plan"
        helper.run(args)
        assert calls == [commands["preflight"], commands["inputs"], commands["plan"]]


@pytest.mark.parametrize("outside", [None, "receipt", "receipt-traversal", "current_input", "current_manifest"])
def test_ordinary_renewal_formal_transport_is_inside_authenticated_data_root(tmp_path, monkeypatch, outside):
    data = tmp_path / "data"
    data.mkdir()
    enrollment, runtime, batch, classes, policy = fixtures(data, monkeypatch)
    sites = ordinary._admitted_sites(batch, classes, policy, Path(runtime["workload_root"]))
    monkeypatch.setattr(ordinary, "_admitted_sites", lambda *args, **kwargs: sites)
    receipt = data / "renewal.json"
    receipt.write_bytes(b"controlled authentic renewal boundary")
    renewed = {"rows": [{"current_input": {"path": str(data / "input.json")},
        "current_manifest": {"path": str(data / "manifest.json")}}]}
    if outside in {"receipt", "receipt-traversal"}:
        receipt = (data / ".." / "external-renewal.json") if outside == "receipt-traversal" else tmp_path / "external-renewal.json"
        receipt.write_bytes(b"controlled authentic renewal boundary")
    elif outside:
        renewed["rows"][0][outside]["path"] = str(tmp_path / "external.json")
    monkeypatch.setattr(ordinary, "validate_renewal", lambda *args: (renewed, None, None, None))
    if outside:
        with pytest.raises(ValueError, match="authenticated runtime data root"):
            ordinary.publish_inputs(enrollment, runtime, data / "ordinary-input.json", renewal=rolling._ref(receipt))
        assert not (data / "ordinary-input.json").exists()
    else:
        path = ordinary.publish_inputs(enrollment, runtime, data / "ordinary-input.json", renewal=rolling._ref(receipt))
        assert json.loads(path.read_bytes())["renewal"] == rolling._ref(receipt)


def test_direct_installed_ordinary_qualification_dispatch_refused(tmp_path, monkeypatch):
    helper = portable()
    monkeypatch.setattr(helper, "checked_plan", lambda *args, **kwargs: (
        {"ordinary_renewal": {"controlled": "authenticated renewal boundary"}}, tmp_path, tmp_path))
    with pytest.raises(ValueError, match="no padding qualification"):
        helper.image_action(SimpleNamespace(command="qualify-image"))
