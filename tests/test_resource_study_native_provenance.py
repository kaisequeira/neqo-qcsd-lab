"""Offline controls for SDK provenance attachment; these prove no live capture."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil

import pytest

from qcsd_lab import buflo_duration_budget as buflo
from qcsd_lab import capture_session as collector
from qcsd_lab import parameters as artifacts
from qcsd_lab import resource_study_native as native
from qcsd_lab import util
from qcsd_lab.resource_study_inputs import sha256_file


SOURCE_ROOT = Path(native.__file__).resolve().parents[2]
# External review tests substitute only the proposed adapter module. The
# authentic, unchanged SDK fixtures still come from the real package.
if not (SOURCE_ROOT / "config/defense-params").is_dir():
    SOURCE_ROOT = Path(util.LAB_ROOT)
NAMES = {"buflo": "buflo-cadence64-budget640.json",
         "cs-buflo": "cs-buflo-cpsp-live.json"}
PATHS = {"buflo": "params/buflo.json", "cs-buflo": "params/cs-buflo.json"}
KEYS = {"buflo": "buflo_parameters", "cs-buflo": "cs_buflo_parameters"}


@pytest.fixture
def enrolled(tmp_path, monkeypatch):
    sdk = tmp_path / "sdk"
    root = tmp_path / "enrollment"
    root.mkdir()
    paths, files = {}, {}
    for mode, name in NAMES.items():
        source = SOURCE_ROOT / "config/defense-params" / name
        destination = sdk / "config/defense-params" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        shutil.copy2(artifacts.parameter_provenance_path(source),
                     artifacts.parameter_provenance_path(destination))
        parameter = root / PATHS[mode]
        parameter.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, parameter)
        paths[KEYS[mode]] = PATHS[mode]
        files[PATHS[mode]] = sha256_file(parameter)
    monkeypatch.setattr(util, "LAB_ROOT", sdk)
    monkeypatch.setattr(artifacts, "LAB_ROOT", sdk)
    return root, {"paths": paths, "files": files,
                  "mode_policies": native.mode_policies()}, sdk


def object_write(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


@pytest.mark.parametrize("mode", tuple(NAMES))
def test_exact_sdk_sidecar_attached_and_stock_collector_copies_it(enrolled, tmp_path, mode):
    root, enrollment, sdk = enrolled
    assert not artifacts.parameter_provenance_path(root / PATHS[mode]).exists()
    defense, context = native._capture_inputs(mode, root, enrollment)
    source = sdk / "config/defense-params" / NAMES[mode]
    provenance = artifacts.parameter_provenance_path(source)
    assert defense.parameters_path == root / PATHS[mode]
    assert defense.parameters_sha256 == sha256_file(source) == enrollment["files"][PATHS[mode]]
    assert defense.parameters_provenance == provenance.relative_to(sdk).as_posix()
    assert defense.parameters_provenance_path == provenance
    assert defense.parameters_provenance_sha256 == sha256_file(provenance)
    assert defense.parameters_input_policy == (
        buflo.CADENCE64_INPUT_POLICY if mode == "buflo"
        else artifacts.BUFLO_STUDY_PARAMETER_INPUT_POLICY)
    assert context.qcsd_profile == "research-1200"
    assert context.udp_payload_ceiling == 1200
    assert context.limits.timeout_seconds == (680 if mode == "buflo" else 120)
    assert context.limits.capture_seconds == (740 if mode == "buflo" else 180)
    capture = tmp_path / ("capture-" + mode) / "neqo"
    capture.mkdir(parents=True)
    collector._copy_defense_parameter_artifacts(defense, capture)
    parameter_copy = capture / artifacts.PARAMETER_ARTIFACT_NAME
    sidecar_copy = capture / artifacts.PARAMETER_PROVENANCE_ARTIFACT_NAME
    assert parameter_copy.read_bytes() == (root / PATHS[mode]).read_bytes()
    assert sidecar_copy.read_bytes() == provenance.read_bytes()
    checked = artifacts.validate_frozen_parameter_artifact(
        parameter_copy, provenance_path=sidecar_copy, original_parameter_name=NAMES[mode],
        expected_kind=defense.kind, allow_reviewed_fixture=False, allow_study_candidate=True,
        expected_qcsd_profile=context.qcsd_profile,
        expected_udp_payload_ceiling=context.udp_payload_ceiling, expected_workloads=())
    assert checked.sha256 == defense.parameters_sha256
    assert checked.provenance_sha256 == defense.parameters_provenance_sha256
    assert checked.input_policy == defense.parameters_input_policy


@pytest.mark.parametrize("mode", tuple(NAMES))
@pytest.mark.parametrize("change", ("sidecar-sha", "kind", "profile", "ceiling",
    "sidecar-name", "enrollment-sha", "enrolled-bytes", "source-bytes",
    "mode-policy", "sidecar-missing"))
def test_mismatched_provenance_or_enrolled_mode_refused(enrolled, mode, change):
    root, enrollment, sdk = enrolled
    source = sdk / "config/defense-params" / NAMES[mode]
    provenance = artifacts.parameter_provenance_path(source)
    receipt = json.loads(provenance.read_bytes())
    if change == "sidecar-sha":
        receipt["parameter_file"]["sha256"] = "0" * 64
    elif change == "kind":
        receipt["defense_kind"] = "cs_buflo" if mode == "buflo" else "buflo"
    elif change == "profile":
        receipt["qcsd_profile"] = "reviewed-1500"
    elif change == "ceiling":
        receipt["udp_payload_ceiling"] = 1500
    elif change == "sidecar-name":
        receipt["parameter_file"]["path"] = "other.json"
    elif change == "enrollment-sha":
        enrollment["files"][PATHS[mode]] = "0" * 64
    elif change == "enrolled-bytes":
        (root / PATHS[mode]).write_bytes((root / PATHS[mode]).read_bytes() + b" ")
    elif change == "source-bytes":
        source.write_bytes(source.read_bytes() + b" ")
    elif change == "mode-policy":
        key = "buflo_duration_policy" if mode == "buflo" else "parameter_policy"
        enrollment["mode_policies"][mode][key] = "unregistered-policy"
    elif change == "sidecar-missing":
        provenance.unlink()
    if change in {"sidecar-sha", "kind", "profile", "ceiling", "sidecar-name"}:
        object_write(provenance, receipt)
    with pytest.raises(ValueError):
        native._capture_inputs(mode, root, enrollment)


@pytest.mark.parametrize("mode", tuple(NAMES))
@pytest.mark.parametrize("linked", ("parameter", "source", "sidecar", "source-parent"))
def test_linked_parameter_or_source_authority_refused(enrolled, mode, linked):
    root, enrollment, sdk = enrolled
    source = sdk / "config/defense-params" / NAMES[mode]
    path = (root / PATHS[mode] if linked == "parameter" else
            artifacts.parameter_provenance_path(source) if linked == "sidecar" else source)
    if linked == "source-parent":
        path = source.parent
        moved = path.with_name("actual-params")
        path.rename(moved)
        path.symlink_to(moved, target_is_directory=True)
    else:
        moved = path.with_name(path.name + ".actual")
        path.rename(moved)
        path.symlink_to(moved)
    with pytest.raises(ValueError, match="nonsymlink"):
        native._capture_inputs(mode, root, enrollment)


@pytest.mark.parametrize("mode", tuple(NAMES))
def test_source_and_enrollment_mutation_with_refreshed_sidecar_still_refused(enrolled, mode):
    root, enrollment, sdk = enrolled
    source = sdk / "config/defense-params" / NAMES[mode]
    values = json.loads(source.read_bytes())
    if mode == "buflo":
        values["duration_budget_policy"] = buflo.POLICY
    else:
        values["outgoing_padding_mode"] = "total"
    object_write(source, values)
    (root / PATHS[mode]).write_bytes(source.read_bytes())
    enrollment["files"][PATHS[mode]] = sha256_file(source)
    provenance = artifacts.parameter_provenance_path(source)
    receipt = json.loads(provenance.read_bytes())
    receipt["parameter_file"]["sha256"] = sha256_file(source)
    object_write(provenance, receipt)
    with pytest.raises(ValueError):
        native._capture_inputs(mode, root, enrollment)


@pytest.mark.parametrize("mode", tuple(NAMES))
@pytest.mark.parametrize("relative", ("../borrowed.json", "/outside.json"))
def test_enrolled_parameter_path_escape_refused(enrolled, mode, relative):
    root, enrollment, _sdk = enrolled
    enrollment["paths"][KEYS[mode]] = relative
    with pytest.raises(ValueError, match="not relative"):
        native._capture_inputs(mode, root, enrollment)


def test_undefended_needs_no_provenance_and_keeps_original_contract(tmp_path):
    enrollment = {"mode_policies": native.mode_policies()}
    defense, context = native._capture_inputs("undefended", tmp_path, enrollment)
    assert defense == collector.Defense(name="undefended", kind="none", baseline=True)
    assert context.limits.timeout_seconds == 120
    assert context.limits.capture_seconds == 180


def test_configuration_modes_keep_original_paths_and_no_reactive_artifacts(tmp_path):
    enrollment = {"mode_policies": native.mode_policies(),
                  "paths": {"front_config": "params/front.toml",
                            "tamaraw_config": "params/tamaraw.toml"}}
    for mode in ("front", "tamaraw"):
        defense, context = native._capture_inputs(mode, tmp_path, enrollment)
        assert defense.parameters_path is None
        assert defense.parameters_provenance_path is None
        assert getattr(context, mode + "_configuration_path") == tmp_path / enrollment["paths"][mode + "_config"]
