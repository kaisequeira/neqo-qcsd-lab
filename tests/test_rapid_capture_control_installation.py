"""Prospective installation authority with only image/acquisition actuation fixture.

The tests use actual old/new control source bytes, the real source projection,
fixed traffic checks, closed raw execution records and qualified-file inventories.
Docker output and the small synthetic cohort's existing image-plan/context
actuators are fixtures; they grant no actual capture or admission credit.
"""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import rapid_capture_control_installation as installation
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_site_admission as admission
from qcsd_lab import runtime_provenance as provenance
from qcsd_lab import util
from tests.test_rapid_capture_control_compatibility import sources, groups, runtime as make_runtime
from tests.test_rapid_lane_evidence import setup


@pytest.fixture
def installed(sources, setup, tmp_path, monkeypatch):
    old, new = (dict(value) for value in sources)
    author = Path(__file__).parents[1]
    for name, (relative, _) in lanes.TRAFFIC_FILES.items():
        for value in (old, new):
            value[relative] = (author / relative).read_bytes()
    source_roots = [tmp_path / "original-clean-source", tmp_path / "control-clean-source"]
    for root, contents in zip(source_roots, (old, new), strict=True):
        for name, raw in contents.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    base = replace(setup.spec, runtime_source_root=source_roots[0], module_root=source_roots[0],
                   base_launcher=source_roots[0] / "qcsd-lab")
    base.host_launcher.write_bytes(old["qcsd-lab"])
    # Relative qualifier references retain exact original bytes when relocated.
    rows = []
    for row in json.loads(base.qualification_spec.read_bytes())["qualification_sets"]:
        row["manifest"] = f"chaff-response-qualification-store/sets/{row['qualification_set']}/_qualification-set.json"
        row["sidecar_root"] = f"chaff-response-qualification-store/sets/{row['qualification_set']}"
        rows.append(row)
    qualifier = base.execution_root / "config/qualification-spec.json"
    qualifier.write_bytes(admission._json({"schema_version": 1, "qualification_sets": rows}))
    base = replace(base, qualification_spec=qualifier)
    execution = base.data_root / "control-execution"
    shutil.copytree(base.execution_root, execution)
    current = replace(base, runtime_source_root=source_roots[1], module_root=source_roots[1],
        execution_root=execution, qualification_spec=execution / "config/qualification-spec.json",
        workload_root=execution / "config/workloads", campaign_dir=execution / "config/campaigns",
        host_launcher=execution / "qcsd-lab", base_launcher=source_roots[1] / "qcsd-lab",
        source_manifest=base.data_root / "control-source.json",
        collection_image_digest="sha256:" + "f" * 64, execution_generation="control-installation-001")
    current.host_launcher.write_bytes(new["qcsd-lab"])
    runtimes = []
    for successor, spec, contents in ((False, base, old), (True, current, new)):
        value = make_runtime(contents, successor=successor)
        receipt = value["qualification_implementation"]
        receipt["neqo_qcsd_client"]["sha256"] = value["client_sha256"] = admission._sha(spec.client_binary.read_bytes())
        receipt["sha256"] = qualification._implementation_aggregate(receipt)
        spec.source_manifest.write_bytes(admission._json(receipt["source"]))
        value["source_manifest_sha256"] = admission._sha(spec.source_manifest.read_bytes())
        value["traffic_hashes"] = {key: digest for key, (_, digest) in lanes.TRAFFIC_FILES.items()}
        runtimes.append(value)
    old_runtime, new_runtime = runtimes
    monkeypatch.setattr(qualification, "_qualification_execution_context", lambda:
        (old_runtime["qualification_implementation"], old_runtime["runtime_source"], base.collection_image_digest))
    monkeypatch.setattr(util, "source_metadata", lambda: old_runtime["runtime_source"])
    monkeypatch.setenv("QCSD_LAB_ROOT", str(base.runtime_source_root))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", base.collection_image_digest)
    proof = lanes.executed_image_plan_check(base.serializable())
    assert installation._runtime_projection(proof) == old_runtime
    files = {name: admission._sha(raw) for name, raw in new.items()}
    python_receipt = {"schema_version": 2, "artifact_type": provenance.RUNTIME_RECEIPT_TYPE,
        "domain": provenance.RUNTIME_RECEIPT_DOMAIN, "source": new_runtime["qualification_implementation"]["source"],
        "source_files": files,
        "installed_modules": {name: {"path": f"/installed/{name}", "sha256": digest}
            for name, digest in files.items() if name.startswith("src/qcsd_lab/")},
        "installed_tools": {name: {"path": f"/installed/{name}", "sha256": files[name]}
            for name in provenance._REQUIRED_TOOL_SOURCES},
        "installed_entrypoint": {"path": "/installed/qcsd-lab", "sha256": files["qcsd-lab"]}}
    python_receipt["payload_sha256"] = provenance._payload_sha256(python_receipt, domain=provenance.RUNTIME_RECEIPT_DOMAIN)
    inventory = groups(old)
    for group in inventory.values():
        if "neqo-qcsd-client" in group:
            group["neqo-qcsd-client"] = old_runtime["client_sha256"]
    state = SimpleNamespace(base=base, current=current, root=setup.root, old=old, new=new, groups=inventory,
        old_proof=proof, new_proof={"runtime_proof": new_runtime, "python_runtime_receipt": python_receipt},
        calls=[], fail_role=None, capsule=setup.root / "control-installation.json")
    monkeypatch.setattr(admission, "load_admission_context", lambda root:
        SimpleNamespace(mounted_module_hashes=inventory))

    def actuation(command, **options):
        assert options == {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "check": False, "timeout": 300}
        role = "new-runtime" if "-I" in command else "original-plan"
        state.calls.append(command)
        output = state.new_proof if role == "new-runtime" else state.old_proof
        return subprocess.CompletedProcess(command, 7 if state.fail_role == role else 0,
            admission._json(output), b"fixture image stderr\n")

    monkeypatch.setattr(installation.subprocess, "run", actuation)
    return state


def publish(state):
    return installation.publish_installation(state.base, state.current, state.root, state.capsule,
        reason="Install the reviewed control-only two-worker interface before any formal flight.")


def reseal(path, mutate):
    value = admission._unpack(path.read_bytes(), installation.CAPSULE_TYPE)
    mutate(value)
    path.write_bytes(admission._json(admission._bind(installation.CAPSULE_TYPE, value)))


def test_actual_closed_checks_allow_fresh_layout_without_reacquisition_or_credit(installed, monkeypatch):
    monkeypatch.setenv("QCSD_RAPID_COLLECTION_COMPATIBILITY", "/untrusted/ambient-capsule.json")
    capsule = publish(installed)
    payload, bridge = installation.validate_capsule(capsule, actual_image=installed.current.collection_image_digest)
    assert len(installed.calls) == 2
    assert "-I" not in installed.calls[0] and "-I" in installed.calls[1]
    assert all("QCSD_RAPID_COLLECTION_COMPATIBILITY" not in item for argv in installed.calls for item in argv)
    assert payload["scientific_credit"] is False and payload["formal_accepted_trace_count"] == 0
    assert bridge["acquisition_source_groups"] == installed.groups
    installation.check_current_spec(payload, installed.current)
    assert payload["base_spec"]["execution_root"] != payload["runtime_spec"]["execution_root"]
    with pytest.raises(FileExistsError):
        publish(installed)


def test_initial_qualified_bytes_remain_exact_but_later_lane_authority_can_add_files(installed):
    publish(installed)
    (installed.current.campaign_dir / "official-later-g02.yml").write_bytes(b"new separately authorized lane\n")
    installation.validate_capsule(installed.capsule)
    initial = next(installed.current.workload_root.glob("*.json"))
    initial.write_bytes(initial.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="initial qualified"):
        installation.validate_capsule(installed.capsule)


@pytest.mark.parametrize("role", ["workload", "qualification", "client", "traffic", "acquisition"])
def test_changed_scientific_input_cannot_install_control(installed, role):
    if role == "workload":
        path = next(installed.current.workload_root.glob("*.json"))
    elif role == "qualification":
        path = next((installed.current.campaign_dir.parent / "chaff-response-qualification-store").rglob("*.json"))
    elif role == "client":
        path = installed.current.client_binary
    elif role == "traffic":
        path = installed.current.execution_root / next(iter(lanes.TRAFFIC_FILES.values()))[0]
    else:
        path = installed.current.runtime_source_root / "src/qcsd_lab/prepare.py"
    path.write_bytes(path.read_bytes() + b"\n# changed\n")
    with pytest.raises(ValueError):
        publish(installed)
    assert not installed.capsule.exists()


@pytest.mark.parametrize("earlier", ["intent", "result"])
def test_installation_cannot_follow_existing_formal_identity(installed, earlier):
    if earlier == "intent":
        path = installed.root / "lanes/formal-lane/intent.json"
        path.parent.mkdir(parents=True)
        path.write_bytes(admission._json(admission._bind(lanes.INTENT_TYPE,
            {"campaign_name": "rapid-study-formal-s01", "started_at": admission._now()})))
    else:
        (installed.base.execution_root / "results/rapid-study-formal-s01").mkdir(parents=True)
    with pytest.raises(ValueError, match="formal"):
        publish(installed)
    assert not installed.calls and not installed.capsule.exists()


@pytest.mark.parametrize("mutation", ["credit", "command", "started", "stdout", "chronology", "client", "missing_module"])
def test_resealed_capsule_cannot_replace_actual_closed_execution_or_runtime(installed, mutation):
    publish(installed)
    if mutation == "stdout":
        payload = admission._unpack(installed.capsule.read_bytes(), installation.CAPSULE_TYPE)
        (installed.root / payload["new_runtime_check"]["execution"]["stdout"]["path"]).write_bytes(b"{}\n")
    else:
        def modify(value):
            record = value["new_runtime_check"]["execution"]
            if mutation == "credit":
                value["scientific_credit"] = True
            elif mutation == "command":
                record["command"].append("--invented")
            elif mutation == "started":
                record["started_at"] = "2020-01-01T00:00:00Z"
            elif mutation == "chronology":
                value["published_at"] = "2020-01-01T00:00:00Z"
            else:
                proof = value["new_runtime_check"]["proof"]
                if mutation == "client":
                    proof["runtime_proof"]["client_sha256"] = "0" * 64
                else:
                    receipt = proof["python_runtime_receipt"]
                    del receipt["source_files"]["src/qcsd_lab/rapid_formal_parallel.py"]
                    del receipt["installed_modules"]["src/qcsd_lab/rapid_formal_parallel.py"]
                    receipt["payload_sha256"] = provenance._payload_sha256(receipt, domain=provenance.RUNTIME_RECEIPT_DOMAIN)
                record["stdout"] = lanes._put_object(installed.root, admission._json(proof))
        reseal(installed.capsule, modify)
    with pytest.raises(ValueError):
        installation.validate_capsule(installed.capsule)


def test_failed_real_actuation_retains_started_complete_and_raw_logs_without_capsule(installed):
    installed.fail_role = "new-runtime"
    with pytest.raises(ValueError, match="actual capture-control image check failed"):
        publish(installed)
    path = installed.root / "control-installation-checks/control-installation/new-runtime/completed.json"
    record = json.loads(path.read_bytes())
    assert record["returncode"] == 7 and record["error"] is None
    assert admission._child(installed.root, record["started_record"]).is_file()
    assert lanes._object(installed.root, record["stderr"]) == b"fixture image stderr\n"
    assert not installed.capsule.exists()


def test_current_spec_rejects_wrong_runtime_but_permits_separate_g02_plan(installed):
    publish(installed)
    plan = installed.current.data_root / "g02-plan.json"
    plan.write_bytes(installed.current.plan_receipt.read_bytes())
    installation.check_current_spec(installed.capsule, replace(installed.current, plan_receipt=plan))
    with pytest.raises(ValueError, match="worker spec"):
        installation.check_current_spec(installed.capsule,
            replace(installed.current, execution_generation="unreviewed-runtime"))


def test_capsule_cannot_claim_another_actual_image(installed):
    publish(installed)
    with pytest.raises(ValueError, match="actual image"):
        installation.validate_capsule(installed.capsule, actual_image="sha256:" + "0" * 64)
