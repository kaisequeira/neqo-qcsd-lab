"""Transport original rolling policy dependencies without regranting credit.

The existing fixture substitutes only admission/qualification actuation. Plans,
policy references, parent namespaces and file hashes use the public APIs.
"""
from __future__ import annotations

import copy
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_site_admission as admission
from tests.test_rapid_lane_evidence import setup
from tests.test_rapid_rolling_capture import rolling_setup, _planned


def _publish(fixture, enrollment, runtime, output):
    rolling.publish_plan(fixture.root, enrollment, fixture.base.spec.qualification_spec, output,
        readiness={"undefended": {"retained-canary": "undefended"}}, runtime_inputs=runtime)
    return rolling.capture_spec(fixture.root, enrollment, fixture.base.spec.qualification_spec, output)


@pytest.fixture
def metadata(rolling_setup, tmp_path):
    original, enrollment = _planned(rolling_setup)
    runtime = dict(rolling_setup.runtime)
    for key in ("runtime_source_root", "module_root"):
        target = tmp_path / ("current-" + key)
        shutil.copytree(Path(runtime[key]), target)
        runtime[key] = str(target)
    runtime["base_launcher"] = str(Path(runtime["runtime_source_root"]) / "qcsd-lab")
    export = tmp_path / "current-export"
    export.mkdir()
    for key in ("source_manifest", "client_binary"):
        target = export / Path(runtime[key]).name
        target.write_bytes(Path(runtime[key]).read_bytes())
        runtime[key] = str(target)
    spec = _publish(rolling_setup, enrollment, runtime, rolling_setup.root / "current-plan.json")
    payload = lanes._payload(spec.plan_receipt, lanes.PLAN_TYPE)
    return SimpleNamespace(fixture=rolling_setup, original=original, spec=spec, enrollment=enrollment,
        runtime=runtime, lane=payload["lanes"][0]["campaign_name"])


def _mounts(command):
    return [tuple(command[index+1].rsplit(":", 2)) for index, item in enumerate(command) if item == "--volume"]


@pytest.mark.parametrize("campaign", [False, True])
def test_image_preflight_always_mounts_the_actual_initial_policy_runtime(metadata, campaign):
    value = metadata
    command = lanes.image_check_command(value.spec, campaign_name=value.lane if campaign else None)
    mounts = _mounts(command)
    for root in (value.original.runtime_source_root, value.original.module_root,
                 value.original.acquisition_root, value.spec.runtime_source_root, value.spec.module_root,
                 value.spec.source_manifest.parent):
        assert (str(root), str(root), "ro") in mounts
    assert all(mode == "ro" for _, _, mode in mounts)
    assert command[command.index("--network")+1] == "none" and "--read-only" in command


def test_shell_and_readonly_deep_roots_retain_the_original_source_identity(metadata):
    value = metadata
    roots = set(rolling.readiness_roots(value.spec, value.lane))
    assert value.original.runtime_source_root in roots and value.original.module_root in roots
    target = value.fixture.root / "lanes" / value.lane / "complete.json"
    command = rolling.lane_check_command(value.spec, value.fixture.root, target, complete=False)
    assert (str(value.original.runtime_source_root), str(value.original.runtime_source_root), "ro") in _mounts(command)
    assert all(mode == "ro" for _, _, mode in _mounts(command))
    policy = admission._unpack((value.fixture.root / "policy.json").read_bytes(), rolling.POLICY_TYPE)
    assert policy["runtime"]["runtime_source_root"] == str(value.original.runtime_source_root)
    assert value.spec.runtime_source_root != value.original.runtime_source_root


def test_missing_original_launcher_fails_before_any_image_or_capture(metadata, monkeypatch):
    metadata.original.base_launcher.unlink()
    monkeypatch.setattr(lanes.subprocess, "run", lambda *args, **kwargs: pytest.fail("missing input reached Docker"))
    with pytest.raises((OSError, ValueError)):
        lanes.image_check_command(metadata.spec)
    assert not (metadata.fixture.root / "lanes").exists()


def _replace_enrollment(value, payload):
    value.enrollment.write_bytes(admission._json(admission._bind(rolling.ENROLLMENT_TYPE, payload)))
    plan = lanes._payload(value.spec.plan_receipt, lanes.PLAN_TYPE)
    plan["bindings"]["cohort_sha256"] = lanes._sha(value.enrollment.read_bytes())
    value.spec.plan_receipt.write_bytes(admission._json(admission._bind(lanes.PLAN_TYPE, plan)))


def test_resealed_corrupt_original_runtime_reference_is_rejected(metadata):
    policy_path = metadata.fixture.root / "policy.json"
    policy = admission._unpack(policy_path.read_bytes(), rolling.POLICY_TYPE)
    policy["base_launcher"]["sha256"] = "0"*64
    policy_path.write_bytes(admission._json(admission._bind(rolling.POLICY_TYPE, policy)))
    enrollment = admission._unpack(metadata.enrollment.read_bytes(), rolling.ENROLLMENT_TYPE)
    enrollment["policy"] = rolling._ref(policy_path)
    _replace_enrollment(metadata, enrollment)
    with pytest.raises(ValueError, match="referenced bytes changed"):
        rolling.enrollment_roots(metadata.spec)


def test_same_bytes_at_an_unclaimed_enrollment_path_cannot_add_mounts(metadata):
    copy_path = metadata.fixture.root / "unclaimed-enrollment.json"
    copy_path.write_bytes(metadata.enrollment.read_bytes())
    with pytest.raises(ValueError, match="claimed batch namespace"):
        rolling.enrollment_roots(replace(metadata.spec, cohort=copy_path))


def _second_context(value, monkeypatch, tmp_path):
    fixture = value.fixture
    current = copy.copy(fixture.context)
    current.root = tmp_path / "second-admission-context"
    shutil.copytree(fixture.context.root, current.root)
    contexts = {fixture.context.root: fixture.context, current.root: current}
    monkeypatch.setattr(admission, "load_admission_context", lambda path: contexts[Path(path)])
    original_prefix = fixture.status["terminal_prefix"]
    new_prefix = [admission.evidence_reference(current.root,
        current.root / admission._child(fixture.context.root, row).relative_to(fixture.context.root))
        for row in fixture.terminals[:2]]
    monkeypatch.setattr(admission, "acquisition_status", lambda context:
        {"terminal_prefix": new_prefix if context.root == current.root else original_prefix})
    enrollment = rolling.enroll(fixture.root, acquisition_root=current.root)
    spec = _publish(fixture, enrollment, value.runtime, fixture.root / "second-context-plan.json")
    return SimpleNamespace(fixture=fixture, enrollment=enrollment, spec=spec, current=current)


def test_parent_enrollment_keeps_all_separately_bound_admission_contexts(metadata, monkeypatch, tmp_path):
    value = _second_context(metadata, monkeypatch, tmp_path)
    roots = set(rolling.enrollment_roots(value.spec))
    assert value.current.root in roots and metadata.original.acquisition_root in roots
    assert metadata.original.runtime_source_root in roots
    assert set(rolling.readiness_roots(value.spec,
        lanes._payload(value.spec.plan_receipt, lanes.PLAN_TYPE)["lanes"][0]["campaign_name"])) >= roots


def test_resealed_parent_at_another_path_cannot_supply_transport_roots(metadata, monkeypatch, tmp_path):
    value = _second_context(metadata, monkeypatch, tmp_path)
    alternate = tmp_path / "unclaimed-parent.json"
    alternate.write_bytes(metadata.enrollment.read_bytes())
    batch = admission._unpack(value.enrollment.read_bytes(), rolling.ENROLLMENT_TYPE)
    batch["parent"] = rolling._ref(alternate)
    _replace_enrollment(value, batch)
    with pytest.raises(ValueError, match="immediate parent"):
        rolling.enrollment_roots(value.spec)
