"""HOST adapter contracts. Browser, installed image and external replay are synthetic."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from qcsd_lab import whole_graph_input as inputs

REPOSITORY = Path(__file__).parents[1]


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    path.chmod(0o644)


def plan(version):
    kind = (inputs.CONTINUATION_PLAN_TYPE if version == 7 else
        f"qcsd-external-navigation-seeded-whole-graph-catalogue-plan-v{version}")
    spec = inputs.VERSIONS[kind]
    root = REPOSITORY / "tools" / f"whole_graph_discovery_v{version}"
    value = {"schema_version": version, "artifact_type": kind, "contract": spec[1],
        "producer_sources": {name: inputs.reference(root / name) for name in spec[3]}}
    if version >= 5:
        policy, sources = inputs.CONTROL_SOURCES[version]
        value["discovery_control"] = {"policy": policy,
            "sources": {name: inputs.reference(root / name) for name in sources},
            "installed_image_source_changed": False,
            "module_loading": "explicit-separate-modules-no-installed-module-replacement"}
    return value


@pytest.mark.parametrize("version", [4, 5, 6, 7])
def test_exact_portable_pairs_and_separate_control_modules(version):
    value = plan(version)
    assert inputs._producer(value) == REPOSITORY / "tools" / f"whole_graph_discovery_v{version}" / "operator.py"


@pytest.mark.parametrize("mutation", ["pair", "schema-bool", "policy", "installed", "mode", "missing-navigation", "foreign-module"])
def test_unknown_or_relabelled_control_refuses_before_external_execution(mutation, monkeypatch):
    value = plan(6)
    if mutation == "pair": value["producer_sources"]["graph_input.py"]["sha256"] = "0" * 64
    elif mutation == "schema-bool": value["schema_version"] = True
    elif mutation == "policy": value["discovery_control"]["policy"] = inputs.CONTROL_SOURCES[5][0]
    elif mutation == "installed": value["discovery_control"]["installed_image_source_changed"] = True
    elif mutation == "mode": value["discovery_control"]["sources"]["navigation_control.py"]["mode"] = "0755"
    elif mutation == "missing-navigation": del value["discovery_control"]["sources"]["navigation_control.py"]
    else: value["discovery_control"]["sources"]["navigation_control.py"] = value["producer_sources"]["graph_input.py"]
    monkeypatch.setattr(inputs.subprocess, "run", lambda *a, **k: pytest.fail("must refuse before subprocess"))
    with pytest.raises(ValueError): inputs._producer(value)


def failed(tmp_path, monkeypatch, version):
    value = plan(version)
    metadata = tmp_path / "declared-metadata.json"
    write(metadata, {"lab_commit": "2b-original-browser", "native_commit": "c24-original-client"})
    value.update(browser_image="sha256:" + "a" * 64, source_metadata=inputs.reference(metadata),
        declared_at="2026-10-05T01:00:00Z", candidates=[{"candidate_id": "reserved-12"}], max_origin_passes=4)
    declaration = tmp_path / "plan.json"
    write(declaration, value)
    root = tmp_path / "attempt"
    root.mkdir()
    image = root / "image-source-metadata.json"
    image.write_bytes(metadata.read_bytes())
    runtime = {"image_digest": value["browser_image"], "source_metadata": json.loads(image.read_bytes()),
        "installed_metadata_sha256": inputs.graph.digest(image.read_bytes()),
        "execution_role": f"actual-browser-image-navigation-seeded-graph-input-only-v{version}"}
    if version >= 5: runtime["external_discovery_control"] = value["discovery_control"]
    begin = {"schema_version": 1, "plan": inputs.reference(declaration), "candidate": value["candidates"][0],
        "runtime": runtime, "started_at": "2026-10-05T01:01:00Z", **inputs.ZERO}
    write(root / "started.json", begin)
    failure = {"schema_version": 1, "plan": begin["plan"], "candidate": begin["candidate"],
        "completed_at": "2026-10-05T01:02:00Z", "elapsed_ns": 1, "error_type": "RecoverableAcquisitionError",
        "message": "sanitized fixture", "traceback": "fixture", "completed_passes": [], "completed_navigation": None,
        "failure_stage": "navigation", "outcome": "operational-discovery-failure-no-admission", **inputs.ZERO}
    if version >= 5:
        failure.update(exception_evidence={"raw_terminal": "retained"},
            exception_evidence_sha256=inputs.discovery_digest({"raw_terminal": "retained"}))
    write(root / "failed.json", failure)
    # The independent external verifier is separately held and reviewed.
    monkeypatch.setattr(inputs, "load_plan", lambda path: value)
    return root, failure, begin


@pytest.mark.parametrize("version", [4, 5, 6, 7])
def test_new_failure_keeps_actual_runtime_and_exception_evidence(tmp_path, monkeypatch, version):
    root, value, _ = failed(tmp_path, monkeypatch, version)
    assert inputs.load_failure(root / "failed.json") == value


@pytest.mark.parametrize("mutation", ["role", "runtime-control", "credit", "candidate", "digest", "extra", "bool-duration", "success"])
def test_new_failure_refuses_altered_runtime_credit_and_evidence(tmp_path, monkeypatch, mutation):
    root, value, begin = failed(tmp_path, monkeypatch, 6)
    if mutation == "role": begin["runtime"]["execution_role"] = "actual-browser-image-navigation-seeded-graph-input-only-v4"
    elif mutation == "runtime-control": del begin["runtime"]["external_discovery_control"]
    elif mutation == "credit": value["site_credit"] = 1
    elif mutation == "candidate": value["candidate"] = {"candidate_id": "unreserved"}
    elif mutation == "digest": value["exception_evidence"]["raw_terminal"] = "changed"
    elif mutation == "extra": value["runtime"] = begin["runtime"]
    elif mutation == "bool-duration": value["elapsed_ns"] = True
    else: write(root / "whole-graph-input.json", {})
    write(root / "started.json", begin)
    write(root / "failed.json", value)
    with pytest.raises(ValueError): inputs.load_failure(root / "failed.json")


def test_v6_navigation_control_file_is_in_raw_failure_fence(tmp_path, monkeypatch):
    root, value, _ = failed(tmp_path, monkeypatch, 6)
    for name in ("started", "result", "control", "completed"):
        write(root / f"navigation-{name}.json", {"fixture": name})
    value["completed_navigation"] = {name: inputs.reference(root / f"navigation-{name}.json")
        for name in ("started", "result", "control", "completed")}
    write(root / "failed.json", value)
    inputs.load_failure(root / "failed.json")
    write(root / "navigation-control.json", {"fixture": "changed"})
    with pytest.raises(ValueError): inputs.load_failure(root / "failed.json")


@pytest.mark.parametrize("mutation", [None, "indices", "candidate", "reservations", "prior-plan"])
def test_continuation_occupies_prior_queue_slots_without_fake_failure_decision(tmp_path, monkeypatch, mutation):
    from types import SimpleNamespace
    from qcsd_lab import whole_graph_supplement as whole
    context = tmp_path / "context"
    context.mkdir()
    write(context / "provenance.json", {"synthetic": "original-context"})
    prefix = SimpleNamespace(root=context, candidates=[{"candidate_id": "original", "domain": "original.example"}])
    original = {"schema_version": 4, "artifact_type": "qcsd-external-navigation-seeded-whole-graph-catalogue-plan-v4",
        "original_prefix": {"context": inputs.reference(context / "provenance.json")}, "reserved_candidates": [],
        "candidates": [{"candidate_id": f"reserved-{n}", "domain": f"site{n}.example", "catalogue_position": n}
            for n in range(11,16)]}
    path = tmp_path / "original-plan.json"
    write(path, original)
    continuation = {"schema_version": 7, "artifact_type": inputs.CONTINUATION_PLAN_TYPE,
        "original_prefix": original["original_prefix"], "previous_plans": [inputs.reference(path)],
        "reserved_candidates": deepcopy(original["candidates"]), "candidates": deepcopy(original["candidates"][1:]),
        "reservation_continuation": {"refs": {"original_plan": inputs.reference(path)},
            "original_candidate_indices": [2,3,4,5], "original_failed_candidate": original["candidates"][0]}}
    monkeypatch.setattr(inputs, "load_plan", lambda p: original)
    if mutation == "indices": continuation["reservation_continuation"]["original_candidate_indices"] = [1,2,3,4]
    elif mutation == "candidate": continuation["candidates"] = original["candidates"][:4]
    elif mutation == "reservations": continuation["reserved_candidates"] = original["candidates"][1:]
    elif mutation == "prior-plan": continuation["previous_plans"] = []
    if mutation:
        with pytest.raises(ValueError): whole._plan_rows([original, continuation], prefix)
    else:
        before = whole._plan_rows([original], prefix)
        assert whole._plan_rows([original, continuation], prefix) == before
        assert [row["position"] for row in before] == [2,3,4,5,6]
