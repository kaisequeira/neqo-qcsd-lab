"""V13 closed HOST failure reopening, with no acquisition or credit claims.

Browser/DNS/HTTP and static historical declaration validation are controlled
unit boundaries. The real public reader, pinned producer selector, physical
plan, HOST operation/raw/fence validator and failed attempt/canonical validator
run together. No project subprocess is executed by the portable unit cases.
"""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

from qcsd_lab import whole_graph_input as inputs


HERE = Path(__file__).resolve().parents[1] / "tools/whole_graph_discovery_v13"
_spec = importlib.util.spec_from_file_location("_test_v13_closed_host_failure", HERE / "graph_input.py")
producer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(producer)
PUBLIC = "93.184.216.34"
CANDIDATE = {"catalogue_position": 1, "candidate_id": "unit-example", "domain": "example.com",
             "rank": 1, "stratum": "unit", "source_url": "https://example.com/"}


def rewrite(path, value, *, mode=0o600):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(mode)


@pytest.fixture
def failure(tmp_path, monkeypatch):
    authority = tmp_path / "authority"
    authority.mkdir(mode=0o700)
    host = tmp_path / "host"
    host.mkdir(mode=0o700)
    operations = host / "operations"
    operations.mkdir(mode=0o700)
    predecessor = tmp_path / "predecessor"
    predecessor.mkdir(mode=0o700)
    predecessor_raw = predecessor / "original-failed-raw.json"
    producer.create(predecessor_raw, {"role": "unit-original-failed-raw-input-only"})
    bound_input = authority / "immutable-input.json"
    producer.create(bound_input, {"role": "unit-transitive-input-only"})
    metadata = {"image_digest": None, "lab_commit": "a" * 40, "lab_dirty": False,
        "lab_patch_sha256": None, "neqo_commit": "b" * 40, "neqo_pinned_commit": "b" * 40,
        "neqo_dirty": False, "neqo_patch_sha256": None}
    metadata_path = authority / "image-source.json"
    producer.create(metadata_path, metadata)
    plan = {"schema_version": 13, "artifact_type": inputs.V13_PLAN_TYPE, "contract": inputs.V13_CONTRACT,
        "source_metadata": producer.reference(metadata_path), "browser_image": "sha256:" + "1" * 64,
        "source": {"root": str(producer.SOURCE_ROOT), "lab_commit": "c" * 40,
                   "gitlinks": {"neqo-qcsd": "d" * 40}},
        "producer_sources": producer.sources(), "candidates": [deepcopy(CANDIDATE)],
        "declared_at": producer.now(), "original_prefix": {}, **producer.LIMITS, **producer.ZERO}
    plan_path = authority / "plan.json"
    producer.create(plan_path, plan)

    # A bounded declaration fixture replaces broad catalogue/Git history only.
    # physical_plan, verify_host_validation, verify_fence and verify_tree remain real.
    monkeypatch.setattr(producer, "static_plan", lambda path: (producer.load(path), []))
    monkeypatch.setattr(producer, "verify_snapshot", lambda source: None)
    monkeypatch.setattr(producer, "check_plan",
                        lambda *a: pytest.fail("failure reopening repeated the full historical HOST check"))
    monkeypatch.setattr(inputs, "load_plan",
                        lambda *a: pytest.fail("V13 failure reader repeated the full plan reopening"))
    def fence(value):
        previous = producer.tree_unbounded(predecessor)
        files = [producer.reference(bound_input), producer.reference(metadata_path),
                 *previous["files"].values()]
        return {"files": sorted(files, key=lambda ref: ref["path"]),
                "trees": {str(predecessor): previous["directories"]}}
    monkeypatch.setattr(producer, "dependency_fence", fence)
    recorder = authority / "unit-recorder.py"
    recorder.write_text("# Not executed; a controlled unit recorder identity.\n")
    recorder.chmod(0o644)
    monkeypatch.setattr(producer, "RECORDER_SHA", producer.reference(recorder)["sha256"])
    prefix = operations / "host-plan-check"
    stdout, stderr = Path(str(prefix) + ".stdout.log"), Path(str(prefix) + ".stderr.log")
    stdout.write_text(json.dumps({"status": "closed", "action": "check", "candidate_count": 1,
                                 **producer.ZERO}) + "\n")
    stderr.write_bytes(b"")
    stdout.chmod(0o644)
    stderr.chmod(0o644)
    started, completed = Path(str(prefix) + "-started.json"), Path(str(prefix) + "-completed.json")
    command = [sys.executable, "-I", "-B", str(producer.HERE / "operator.py"), "check", "--plan", str(plan_path)]
    producer.create(started, {"command": command, "started_at": producer.now()})
    producer.create(completed, {"returncode": 0, "completed_at": producer.now(),
        "stdout_sha256": producer.reference(stdout)["sha256"],
        "stderr_sha256": producer.reference(stderr)["sha256"]})
    started.chmod(0o644)
    completed.chmod(0o644)
    operation = {key: producer.reference(path) for key, path in
                 (("started", started), ("completed", completed), ("stdout", stdout), ("stderr", stderr))}
    host_value = {"schema_version": 1, "artifact_type": "qcsd-complete-v13-host-plan-validation-v1",
        "plan": producer.reference(plan_path), "producer_sources": plan["producer_sources"],
        "recorder": producer.reference(recorder), "verify_interpreter": str(Path(sys.executable).absolute()),
        "check_operation": operation, "dependency_fence": fence(plan),
        "closed_at": producer.now(), **producer.ZERO}
    host_path = operations / "host-plan-validation.json"
    producer.create(host_path, host_value)

    monkeypatch.setattr(producer.util, "DEFAULT_SOURCE_METADATA", metadata_path)
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", plan["browser_image"])
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA", str(metadata_path))
    def dns(url):
        return {"url": url, "hostname": "example.com", "addresses": [PUBLIC],
                "selected_address": PUBLIC, "started_at": producer.now(), "completed_at": producer.now()}
    def response(url, records, timeout):
        return {"url": url, "method": "GET", "status": 200, "headers": [["Content-Type", "text/html"]],
            "remote_address": PUBLIC, "tls_hostname": "example.com", "tls_certificate_verified": True,
            "body_read_bytes": 0, "complete_body_claimed": False,
            "started_at": producer.now(), "completed_at": producer.now()}
    original_resolution = producer.homepage.resolve
    monkeypatch.setattr(producer.homepage, "resolve",
        lambda root, **kwargs: original_resolution(root, **kwargs, resolver=dns, requester=response))
    monkeypatch.setattr(producer.acquisition, "public_origin_ip_pins", lambda approved: {origin: PUBLIC for origin in approved})
    def deliberate_browser_failure(*args, **kwargs):
        raise ValueError("deliberate zero-credit unit browser failure")
    monkeypatch.setattr(producer.browser, "discover_page", deliberate_browser_failure)
    output = tmp_path / "failed-attempt"
    assert producer.discover(plan_path, 1, output, host_path) == 1
    path = output / "failed.json"
    calls = []
    def external(operator, action, flag, argument, *, timeout=60):
        assert operator == inputs.reopen(plan["producer_sources"]["operator.py"])
        assert (action, flag, argument, timeout) == ("verify-failure", "--failure", path.absolute(), None)
        calls.append(action)
        producer.verify_failure(argument)
    monkeypatch.setattr(inputs, "_verify_external", external)
    monkeypatch.setattr(inputs.subprocess, "run", lambda *a, **k: pytest.fail("unit reader executed a project subprocess"))
    return {"path": path, "plan_path": plan_path, "plan": plan, "host_path": host_path,
            "bound_input": bound_input, "predecessor": predecessor, "predecessor_raw": predecessor_raw,
            "calls": calls, "stdout": stdout, "completed": completed}


def test_v13_failure_uses_exact_closed_host_route_once_without_replaying_plan(failure):
    path = failure["path"]
    before = path.read_bytes()
    value = inputs.load_failure(path)
    assert value["failure_stage"] == "complete-occurrence-convergence"
    assert value["outcome"] == "operational-discovery-failure-no-admission"
    assert all(type(value[key]) is type(expected) and value[key] == expected
               for key, expected in inputs.ZERO.items())
    assert failure["calls"] == ["verify-failure"]
    assert path.read_bytes() == before and path.stat().st_mode & 0o7777 == 0o600
    assert not path.with_name("whole-graph-input.json").exists()


@pytest.mark.parametrize("mutation", ["missing-closure", "closure-full-mode", "closure-raw-sha",
    "closure-returncode", "closure-command", "closure-chronology", "closure-fence",
    "producer-sha", "producer-mode", "failed-tree-extra", "failed-tree-mode",
    "attempt-chronology", "runtime-source", "predecessor-bytes", "predecessor-membership",
    "successful-output", "renamed-output"])
def test_closed_failure_refuses_changed_authority_raw_trees_and_terminal_role(mutation, failure):
    path = failure["path"]
    assert inputs.load_failure(path)["scientific_credit"] is False
    value = producer.load(path)
    closure = producer.load(failure["host_path"])
    if mutation == "missing-closure":
        failure["host_path"].unlink()
    elif mutation == "closure-full-mode":
        failure["host_path"].chmod(0o444)
        value["host_validation"] = producer.reference(failure["host_path"])
    elif mutation.startswith("closure-"):
        if mutation == "closure-raw-sha":
            closure["check_operation"]["stdout"]["sha256"] = "0" * 64
        elif mutation in ("closure-returncode", "closure-command"):
            key = "completed" if mutation == "closure-returncode" else "started"
            raw_path = Path(closure["check_operation"][key]["path"])
            raw = producer.load(raw_path)
            if key == "completed":
                raw["returncode"] = 1
            else:
                raw["command"][-1] = str(failure["plan_path"].with_name("unbound-plan.json"))
            rewrite(raw_path, raw, mode=0o644)
            closure["check_operation"][key] = producer.reference(raw_path)
        elif mutation == "closure-chronology":
            closure["closed_at"] = "2099-01-01T00:00:00+00:00"
        else:
            closure["dependency_fence"]["files"] = []
        rewrite(failure["host_path"], closure)
        value["host_validation"] = producer.reference(failure["host_path"])
    elif mutation in ("producer-sha", "producer-mode"):
        plan = producer.load(failure["plan_path"])
        plan["producer_sources"]["canonical_homepage.py"]["sha256" if mutation == "producer-sha" else "mode"] = (
            "0" * 64 if mutation == "producer-sha" else "0444")
        rewrite(failure["plan_path"], plan)
        value["plan"] = producer.reference(failure["plan_path"])
    elif mutation == "failed-tree-extra":
        (path.parent / "unaccounted-raw-file").write_bytes(b"unaccounted")
    elif mutation == "failed-tree-mode":
        (path.parent / "pass-01-started.json").chmod(0o444)
    elif mutation == "attempt-chronology":
        value["completed_at"] = "2000-01-01T00:00:00+00:00"
    elif mutation == "runtime-source":
        metadata = path.parent / "image-source-metadata.json"
        metadata.write_bytes(b'{"different-runtime":true}\n')
        # Rebind inventory to reach the actual runtime identity guard.
        value["attempt_inventory"] = producer.tree(path.parent, excluded=("failed.json",))
    elif mutation == "predecessor-bytes":
        failure["predecessor_raw"].write_bytes(b'{"changed-original-failure":true}\n')
    elif mutation == "predecessor-membership":
        (failure["predecessor"] / "unaccounted-original-raw").write_bytes(b"extra")
    elif mutation == "successful-output":
        path.with_name("whole-graph-input.json").write_bytes(b"{}")
    else:
        renamed = path.with_name("different-output.json")
        path.rename(renamed)
        path = renamed
    if mutation not in ("renamed-output",):
        rewrite(path, value)
    with pytest.raises((ValueError, OSError)):
        inputs.load_failure(path)


@pytest.mark.parametrize("mutation", ["plan-credit", "failure-credit", "candidate", "outcome", "schema-bool", "contract"])
def test_reader_refuses_untyped_or_nonzero_v13_role_before_external_execution(mutation, failure):
    path = failure["path"]
    assert inputs.load_failure(path)["scientific_credit"] is False
    value = producer.load(path)
    if mutation in ("plan-credit", "schema-bool", "contract"):
        plan = producer.load(failure["plan_path"])
        if mutation == "plan-credit":
            plan["site_credit"] = 1
        elif mutation == "schema-bool":
            plan["schema_version"] = True
        else:
            plan["contract"] = "unregistered-v13-contract"
        rewrite(failure["plan_path"], plan)
        value["plan"] = producer.reference(failure["plan_path"])
    elif mutation == "failure-credit":
        value["formal_accepted_trace_count"] = 1
    elif mutation == "candidate":
        value["candidate"] = {**CANDIDATE, "candidate_id": "unselected"}
    else:
        value["outcome"] = "eligible"
    rewrite(path, value)
    with pytest.raises(ValueError):
        inputs.load_failure(path)
    assert failure["calls"] == ["verify-failure"]


@pytest.mark.parametrize("version", [4, 8, 12])
def test_older_controlled_failure_keeps_original_full_plan_route(version, tmp_path, monkeypatch):
    plan = {"schema_version": version, "artifact_type": next(
        key for key, value in inputs.VERSIONS.items() if value[0] == version)}
    plan_path = tmp_path / "old-plan.json"
    rewrite(plan_path, plan)
    failure = tmp_path / "failed.json"
    rewrite(failure, {"plan": inputs.reference(plan_path)})
    calls = []
    monkeypatch.setattr(inputs, "_producer", lambda *a: pytest.fail("legacy route used the V13 producer selector"))
    monkeypatch.setattr(inputs, "load_plan", lambda path: calls.append(path) or plan)
    marker = {"unit-original-controlled-failure": version}
    monkeypatch.setattr(inputs, "_controlled_failure", lambda path, value, verified: marker)
    assert inputs.load_failure(failure) is marker
    assert calls == [plan_path]


def test_optional_authentic_v13_failure_reopens_without_new_plan_check(monkeypatch):
    text = os.environ.get("QCSD_V13_FAILURE_PATH")
    if text is None:
        pytest.skip("authentic retained V13 failure is not bound")
    expected = os.environ.get("QCSD_V13_FAILURE_SHA256")
    if expected is None:
        pytest.fail("authentic failure requires an explicit full SHA256")
    path = Path(text).absolute()
    before = inputs.get._read(path)
    assert hashlib.sha256(before).hexdigest() == expected
    assert path.stat().st_mode & 0o7777 == 0o600
    monkeypatch.setattr(inputs, "load_plan",
                        lambda *a: pytest.fail("authentic V13 failure repeated full historical plan"))
    value = inputs.load_failure(path)
    assert value["scientific_credit"] is False and value["site_credit"] == 0
    assert value["formal_accepted_trace_count"] == 0 and path.read_bytes() == before
