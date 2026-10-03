"""Run the actual launcher's capsule routing code without Docker."""
import copy
import json
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def transport(tmp_path):
    source = (Path(__file__).resolve().parents[1] / "qcsd-lab").read_text()
    marker = '    rapid_compatibility_rows="$(/usr/bin/python3 -I -c \'\n'
    script = source.split(marker, 1)[1].split("\n' \"${rapid_compatibility_host}\"", 1)[0]
    data = tmp_path / "data"
    old, execution, evidence = [data / name for name in ("serial", "parallel", "evidence")]
    for path in (old, execution, evidence):
        path.mkdir(parents=True)
    image = "sha256:" + "1" * 64
    def spec(root):
        return {"data_root": str(data), "runtime_source_root": str(root), "module_root": str(root),
            "execution_root": str(root), "source_manifest": str(root / "source.json"),
            "client_binary": str(root / "client"), "base_launcher": str(root / "qcsd-lab"),
            "collection_image_digest": image, "plan_receipt": str(root / "plan.json")}
    payload = {"base_spec": spec(old), "runtime_spec": spec(execution), "evidence_root": str(evidence)}
    def run(kind, value, *, path=None, secondary=""):
        path = path or evidence / "installation.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"receipt_type": kind, "payload": value}))
        return subprocess.run(["/usr/bin/python3", "-I", "-c", script, str(path), str(execution), image,
                               str(secondary)], text=True, capture_output=True, check=False)
    return payload, execution, evidence, run


def test_installation_transport_allows_retained_old_layout_and_binds_actual_image(transport):
    payload, _, evidence, run = transport
    result = run("qcsd-rapid-v5-capture-control-installation-v2", payload)
    assert result.returncode == 0, result.stderr
    rows = result.stdout.splitlines()
    assert rows[:3] == ["capture-control-installation", str(evidence / "installation.json"),
                        str(evidence / "installation.json")]
    assert payload["base_spec"]["execution_root"] in rows[3:]
    assert payload["runtime_spec"]["execution_root"] in rows[3:]


@pytest.mark.parametrize("mutation", ["image", "execution", "data", "evidence", "type"])
def test_installation_transport_rejects_changed_actual_authority(transport, mutation):
    payload, _, _, run = transport
    value = copy.deepcopy(payload)
    kind = "qcsd-rapid-v5-capture-control-installation-v2"
    if mutation == "image":
        value["runtime_spec"]["collection_image_digest"] = "sha256:" + "2" * 64
    elif mutation == "execution":
        value["runtime_spec"]["execution_root"] = value["base_spec"]["execution_root"]
    elif mutation == "data":
        value["base_spec"]["data_root"] = value["base_spec"]["execution_root"]
    elif mutation == "evidence":
        value["evidence_root"] = value["runtime_spec"]["execution_root"]
    else:
        kind = "qcsd-two-worker-diagnostic-authority"
    assert run(kind, value).returncode != 0


def test_historical_transport_keeps_its_own_path_and_epoch_layout(transport):
    payload, execution, evidence, run = transport
    value = {**payload, "base_spec": copy.deepcopy(payload["runtime_spec"])}
    capsule = execution / "config/rapid-runtime-epochs/lane.json"
    result = run("qcsd-rapid-v5-collection-runtime-launch-capsule-v1", value, path=capsule)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[:3] == ["runtime-epoch", "/lab/config/rapid-runtime-epochs/lane.json", "-"]
    assert run("qcsd-rapid-v5-collection-runtime-launch-capsule-v1", value,
               path=evidence / "outside.json").returncode != 0
    value["base_spec"] = payload["base_spec"]
    assert run("qcsd-rapid-v5-collection-runtime-launch-capsule-v1", value, path=capsule).returncode != 0


def test_runtime_transport_binds_original_installation_for_two_step_qualification(transport):
    payload, execution, evidence, run = transport
    installation = evidence / "installation.json"
    assert run("qcsd-rapid-v5-capture-control-installation-v2", payload).returncode == 0
    runtime = {**payload, "base_spec": copy.deepcopy(payload["runtime_spec"])}
    capsule = execution / "config/rapid-runtime-epochs/lane.json"
    result = run("qcsd-rapid-v5-collection-runtime-launch-capsule-v1", runtime,
                 path=capsule, secondary=installation)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[2] == str(installation)
    changed = copy.deepcopy(payload)
    changed["runtime_spec"]["collection_image_digest"] = "sha256:" + "3" * 64
    installation.write_text(json.dumps({"receipt_type": "qcsd-rapid-v5-capture-control-installation-v2", "payload": changed}))
    assert run("qcsd-rapid-v5-collection-runtime-launch-capsule-v1", runtime,
               path=capsule, secondary=installation).returncode != 0
