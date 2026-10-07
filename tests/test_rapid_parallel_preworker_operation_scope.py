"""Portable CLI scope checks with controlled audit and physical boundaries.

These engineering fixtures exercise real dispatch, audit and ordinary worker
hooks. They claim no installed image, network operation or scientific credit.
"""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_operation_facts as operations
from qcsd_lab import rapid_ordinary_parallel_schedule as workers
from qcsd_lab import rapid_parallel_capture as shared
from qcsd_lab import rapid_rolling_schedule as schedule
from qcsd_lab import rapid_slot_chunks as chunks


ACTIONS = ("formal-entry-inputs", "formal-inputs", "formal-dns", "preflight",
           "initialize", "prepare-release")


class AuditBoundary(RuntimeError):
    pass


def _write(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
    return path


def _ref(path: Path):
    return {"path": str(path), "sha256": shared.sha(path.read_bytes())}


def _argv(action, path: Path, output: Path):
    return [action, "--authority", str(path), "--output", str(output),
            "--sha256", shared.sha(path.read_bytes()), "--index", "0",
            "--cpus", "[0, 2, 4, 7, 9]"]


@pytest.mark.parametrize("action", ACTIONS)
def test_real_cli_audit_and_ordinary_worker_hooks_share_one_context(tmp_path, monkeypatch, action):
    root = tmp_path / "evidence"
    root.mkdir()
    source = _write(tmp_path / "source/control.py", b"immutable source\n")
    spec_values = {key: str(tmp_path / key) for key in shared.RUNTIME_KEYS}
    spec_values["collection_image_digest"] = "sha256:" + "a" * 64
    spec_values["plan_receipt"] = str(tmp_path / "plan.json")
    spec = SimpleNamespace(campaign_dir=tmp_path / "campaigns",
                           serializable=lambda: dict(spec_values))
    spec_path = _write(tmp_path / "spec.json", {"engineering_fixture": True})
    base = SimpleNamespace(serializable=lambda: {})
    old = {"runtime": {}, "declared_at": "2000-01-01T00:00:00Z"}
    payload = {**old, "scheduling": {"engineering_fixture": True},
               workers.FIELD: workers.CONTRACT, "ordinary_parallel_base_spec": {}}
    observed = []

    def capsule(reference, **options):
        context = operations.current_context()
        assert context is not None
        observed.append(context)
        context.watch_file(source)
        context.watch_tree(source.parent)
        return {"base_spec": {}}

    # Only schedule derivation and physical lane parsing are controlled. The
    # real legacy scope bridge, require_plan, require_worker and disjoint guard run.
    monkeypatch.setattr(workers, "validate_schedule", workers._scope(capsule))
    monkeypatch.setattr(workers, "_spec", lambda value: base)
    monkeypatch.setattr(workers, "_base", lambda value: ([], old))
    monkeypatch.setattr(shared, "_runtime_authority", lambda *args, **kwargs: None)
    monkeypatch.setattr(lanes, "load_capture_spec", lambda path: spec)
    facts = []
    for index in range(2):
        lane = chunks.ChunkLane("formal", index + 1, 1, "undefended", "",
                                ("site",), 1, None, index, "b" * 64)
        lane = replace(lane, campaign_name=chunks.name(lane, 1))
        campaign = _write(spec.campaign_dir / (lane.campaign_name + ".yml"), b"fixture campaign\n")
        intent_path = _write(root / "lanes" / lane.campaign_name / "intent.json", {})
        intent = {"started_at": "2000-01-01T00:01:00Z", "actuator": formal.ACTUATOR,
                  "campaign_sha256": _ref(campaign)["sha256"]}
        lineage = {"image_check": {"proof": {"cohort_generation": "rolling-50",
                                             "plan_payload": payload}}}
        facts.append((spec, root, intent_path, intent, lineage, lane,
                      [SimpleNamespace(workload_id="site")]))
    monkeypatch.setattr(formal, "_lane", lambda value, index, **options: facts[index])
    monkeypatch.setattr(lanes, "_lane", lambda proof, name: next(fact[5] for fact in facts
                                                               if fact[5].campaign_name == name))
    contexts = []

    def scheduling(reference, worker_spec, *, _context, **options):
        assert _context is operations.current_context()
        contexts.append(_context)

    monkeypatch.setattr(schedule, "require_schedule", scheduling)
    value = {"schema_version": 1, "artifact_type": formal.AUTHORITY_TYPE,
        "runtime": {key: spec_values[key] for key in shared.RUNTIME_KEYS},
        "campaigns": [_ref(spec.campaign_dir / (fact[5].campaign_name + ".yml")) for fact in facts],
        "capture_spec": _ref(spec_path), "lane_specs": [_ref(spec_path), _ref(spec_path)],
        "evidence_root": str(root), "lane_intents": [_ref(fact[2]) for fact in facts],
        "installation": None}
    path = _write(tmp_path / "authority.json", value)
    audit = formal._audit

    def closed_audit(target, *, _context=None):
        assert _context is operations.current_context() and _context is not None
        assert audit(target, _context=_context)[0] == value
        assert len(observed) == 4 and len(contexts) == 2
        assert all(context is _context for context in observed + contexts)
        raise AuditBoundary("controlled post-audit boundary")

    monkeypatch.setattr(formal, "_audit", closed_audit)
    with pytest.raises(AuditBoundary, match="post-audit"):
        shared.main(_argv(action, path, tmp_path / "output"))
    assert operations.current_context() is None


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("drift", [None, "bytes", "full-mode", "tree-membership"])
@pytest.mark.parametrize("failure", [False, True])
def test_cli_closes_dependencies_on_return_and_exception(tmp_path, monkeypatch, capsys,
                                                        action, drift, failure):
    path = _write(tmp_path / "authority.json", {"artifact_type": formal.AUTHORITY_TYPE})
    output = tmp_path / "output"
    dependency = _write(tmp_path / "immutable/member", b"original")
    dependency.chmod(0o644)
    metadata = dependency.stat()
    contexts = []
    result = {"engineering_fixture": action, "scientific_credit": False}

    def effect(context):
        assert context is operations.current_context() and context is not None
        contexts.append(context)
        context.watch_file(dependency)
        context.watch_tree(dependency.parent)
        if drift == "bytes":
            dependency.write_bytes(b"tampered")
            os.utime(dependency, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        elif drift == "full-mode":
            dependency.chmod(0o664)
        elif drift == "tree-membership":
            (dependency.parent / "new-empty-directory").mkdir()
        if failure:
            raise AuditBoundary("controlled delegate failure")
        return result

    def audit(target, *, _context=None):
        assert target == path
        return {}, []

    def inputs(target, index, *, _audited=None, _context=None):
        assert target == path
        if action == "formal-entry-inputs":
            assert _audited == ({}, [])
            assert index in (0, 1)
            if index == 1:
                return {"engineering_fixture": "second worker", "scientific_credit": False}
        else:
            assert index == 0
        return effect(_context)

    def preflight(target, expected_sha, *, _context=None):
        assert target == path and expected_sha == shared.sha(path.read_bytes())
        return effect(_context)

    def initialize(target, destination, expected_sha, available, *, _context=None):
        assert destination == output and available == [0, 2, 4, 7, 9]
        return preflight(target, expected_sha, _context=_context)

    def prepare(target, destination, *, _context=None):
        assert target == path and destination == output
        effect(_context)
        return "c" * 64

    monkeypatch.setattr(formal, "_audit", audit)
    monkeypatch.setattr(shared, "host_source", lambda value: None)
    monkeypatch.setattr(formal, "worker_inputs", inputs)
    monkeypatch.setattr(formal, "resolve_dns", inputs)
    monkeypatch.setattr(formal, "image_preflight", preflight)
    monkeypatch.setattr(formal, "initialize", initialize)
    monkeypatch.setattr(formal, "prepare_release", prepare)
    parent = operations.OperationFacts()
    with parent.scope():
        if drift is not None:
            with pytest.raises(ValueError, match="operation dependency"):
                shared.main(_argv(action, path, output))
        elif failure:
            with pytest.raises(AuditBoundary, match="delegate failure"):
                shared.main(_argv(action, path, output))
        else:
            for _ in range(2):
                assert shared.main(_argv(action, path, output)) is None
                raw = capsys.readouterr().out
                if action == "prepare-release":
                    assert raw == "c" * 64 + "\n"
                else:
                    expected = ({**result, "second_worker_inputs": {
                        "engineering_fixture": "second worker", "scientific_credit": False}}
                        if action == "formal-entry-inputs" else result)
                    assert json.loads(raw) == expected
            assert contexts[0] is not contexts[1]
        assert operations.current_context() is parent
        assert all(context is not parent for context in contexts)
    assert operations.current_context() is None


@pytest.mark.parametrize("action", ["select", "lifecycle-inputs", "release", "gate",
                                    "retire", "verify", "verify-installed"])
def test_other_cli_actions_do_not_acquire_preworker_scope(monkeypatch, action):
    def dispatch(args, *, _context=None):
        assert args.action == action
        assert _context is None and operations.current_context() is None
        return 7
    monkeypatch.setattr(shared, "_dispatch", dispatch)
    assert shared.main([action]) == 7
