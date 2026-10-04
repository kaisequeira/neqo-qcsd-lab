"""Real file/Git bindings stay separate from scientific lane reconstruction."""
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_parallel_capture as parallel


ROOT = Path(__file__).resolve().parents[1]


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def ref(path):
    return {"path": str(path), "sha256": parallel.sha(path.read_bytes())}


@pytest.fixture
def context(tmp_path, monkeypatch):
    runtime, data = tmp_path / "frozen-source", tmp_path / "study"
    execution = data / "execution"
    package = runtime / "src/qcsd_lab"
    package.mkdir(parents=True)
    for name in ("__init__.py", "util.py", "rapid_parallel_capture.py"):
        (package / name).write_bytes((ROOT / "src/qcsd_lab" / name).read_bytes())
    native = runtime / "neqo-qcsd"
    native.mkdir()
    git(native, "init", "-q")
    (native / "README.md").write_text("fixture Native identity, no capture credit\n")
    git(native, "add", "README.md")
    git(native, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", "fixture Native identity")
    native_head = git(native, "rev-parse", "HEAD")
    (runtime / "qcsd-lab").write_bytes((ROOT / "qcsd-lab").read_bytes())
    git(runtime, "init", "-q")
    git(runtime, "add", "src", "qcsd-lab")
    git(runtime, "update-index", "--add", "--cacheinfo", "160000," + native_head + ",neqo-qcsd")
    git(runtime, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", "fixture frozen Source")
    source_path = data / "source.json"
    put(source_path, {"lab_commit": git(runtime, "rev-parse", "HEAD"), "lab_dirty": False,
        "neqo_commit": native_head, "neqo_pinned_commit": native_head, "neqo_dirty": False})
    execution.mkdir()
    (execution / "qcsd-lab").write_bytes((runtime / "qcsd-lab").read_bytes())
    for relative, _ in lanes.TRAFFIC_FILES.values():
        target = execution / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    target = execution / lanes.STUDY_PROFILE_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((ROOT / lanes.STUDY_PROFILE_FILE).read_bytes())
    campaigns, workloads = execution / "config/campaigns", execution / "config/workloads"
    campaigns.mkdir(parents=True)
    workloads.mkdir()
    acquisition = data / "acquisition"
    acquisition.mkdir()
    client = data / "client"
    client.write_bytes(b"fixture retained client, not scientific evidence")
    cohort, plan, qualifier = (data / name for name in ("cohort.json", "plan.json", "qualification.json"))
    put(cohort, {"receipt_type": "qcsd-rapid-v6-immutable-enrollment-batch"})
    put(plan, {"fixture": "science remains a later gate"})
    sidecars = campaigns.parent / "chaff-response-qualification-store/sets/fixture120"
    put(sidecars / "_qualification-set.json", {"fixture": "not qualified"})
    put(qualifier, {"schema_version": 1, "qualification_sets": [{"qualification_set": "fixture120",
        "manifest": str(sidecars / "_qualification-set.json"), "sidecar_root": str(sidecars),
        "prefix_spec_root": None}]})
    spec = lanes.CaptureSpec(data, runtime, runtime, execution, acquisition, cohort, qualifier,
        workloads, campaigns, plan, source_path, client, runtime / "qcsd-lab", execution / "qcsd-lab",
        "sha256:" + "a" * 64, "fixture-001")
    spec_path = data / "spec.json"
    put(spec_path, {"schema_version": 1, "artifact_type": "qcsd-rapid-v6-rolling-capture-spec",
                    "inputs": spec.serializable()})
    evidence = data / "evidence"
    intent_paths, campaign_paths = [], []
    for index in range(2):
        intent = evidence / "lanes" / f"worker-{index}" / "intent.json"
        put(intent, {"fixture": "original intent bytes"})
        campaign = campaigns / f"worker-{index}.yml"
        campaign.write_text("fixture campaign; scientific parser must reject this\n")
        intent_paths.append(ref(intent))
        campaign_paths.append(ref(campaign))
    authority = {"schema_version": 1, "artifact_type": formal.AUTHORITY_TYPE,
        "runtime": {key: spec.serializable()[key] for key in parallel.RUNTIME_KEYS},
        "campaigns": campaign_paths, "capture_spec": ref(spec_path),
        "lane_specs": [ref(spec_path), ref(spec_path)], "evidence_root": str(evidence),
        "lane_intents": intent_paths, "installation": None}
    path = data / "authority.json"
    put(path, authority)
    module_spec = importlib.util.spec_from_file_location("qcsd_lab._lifecycle_fixture", package / "rapid_parallel_capture.py")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    def forbidden(*args, **kwargs):
        raise AssertionError("lightweight lifecycle check invoked scientific admission")
    monkeypatch.setattr(formal, "_audit", forbidden)
    return SimpleNamespace(module=module, path=path, value=authority, spec_path=spec_path,
                           execution=execution, runtime=runtime, evidence=evidence)


def check(context):
    return context.module.lifecycle_inputs(context.path, context.execution,
                                           parallel.sha(context.path.read_bytes()))


def test_real_clean_git_runtime_binding_does_not_grant_scientific_admission(context):
    assert check(context) is None
    assert not (context.evidence / "deep-verification.json").exists()


@pytest.mark.parametrize("change", ["authority-sha", "campaign", "intent", "spec",
    "launcher", "source-git", "native-git", "package", "runtime-spec"])
def test_changed_runtime_or_sealed_reference_is_rejected_before_lifecycle(context, change):
    if change == "authority-sha":
        with pytest.raises(ValueError, match="authority hash"):
            context.module.lifecycle_inputs(context.path, context.execution, "0" * 64)
        return
    if change in {"campaign", "intent"}:
        row = context.value["campaigns" if change == "campaign" else "lane_intents"][0]
        path = Path(row["path"])
        path.write_bytes(path.read_bytes() + b"changed")
    elif change in {"spec", "runtime-spec"}:
        value = json.loads(context.spec_path.read_bytes())
        value["inputs"]["collection_image_digest"] = "sha256:" + "b" * 64
        put(context.spec_path, value)
        if change == "runtime-spec":
            context.value["lane_specs"] = [ref(context.spec_path), ref(context.spec_path)]
            context.value["capture_spec"] = context.value["lane_specs"][0]
            put(context.path, context.value)
    elif change == "launcher":
        (context.execution / "qcsd-lab").write_bytes(b"another launcher")
    elif change == "native-git":
        (context.runtime / "neqo-qcsd/README.md").write_text("dirty Native")
    elif change == "package":
        context.module.__file__ = str(ROOT / "src/qcsd_lab/rapid_parallel_capture.py")
    else:
        (context.runtime / "src/qcsd_lab/util.py").write_text("dirty Source")
    with pytest.raises(ValueError):
        check(context)


def test_formal_entry_keeps_one_actual_audit_for_selection_and_worker_inputs(monkeypatch):
    calls, audited = [], ({"runtime": "fixture"}, ["first", "second"])
    contexts = []
    def audit(path, *, _context=None):
        contexts.append(_context)
        calls.append("audit")
        return audited
    monkeypatch.setattr(formal, "_audit", audit)
    monkeypatch.setattr(parallel, "host_source", lambda value: calls.append("source"))
    def inputs(path, index, *, _audited=None, _context=None):
        assert _audited is audited and index == 0
        assert _context is contexts[0] and _context is not None
        calls.append("worker")
        return {"campaign_path": "same original full-graph campaign"}
    monkeypatch.setattr(formal, "worker_inputs", inputs)
    assert parallel.formal_entry_inputs(Path("unused"))["campaign_path"] == "same original full-graph campaign"
    assert calls == ["audit", "source", "worker"]


def test_scientific_failure_still_aborts_formal_entry(monkeypatch):
    def reject(path, *, _context=None):
        raise ValueError("original full scientific validator rejected the lane")
    monkeypatch.setattr(formal, "_audit", reject)
    with pytest.raises(ValueError, match="full scientific validator"):
        parallel.formal_entry_inputs(Path("unused"))
