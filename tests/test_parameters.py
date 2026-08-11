from __future__ import annotations

import json
from pathlib import Path

import pytest

import qcsd_lab.parameters as parameters
from qcsd_lab.parameters import (
    REVIEWED_PARAMETER_INPUT_POLICY,
    parameter_provenance_path,
    validate_parameter_artifact,
    validate_run_parameter_binding,
)
from qcsd_lab.util import atomic_json, sha256_file


FIXTURES = Path(__file__).parents[1] / "config/defense-params"


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("traffic-morphing-live.json", "traffic_morphing"),
        ("wtfpad-live.json", "wtf_pad"),
        ("walkie-talkie-live.json", "walkie_talkie"),
    ],
)
def test_checked_in_smoke_artifacts_bind_hash_kind_profile_and_ceiling(name, kind):
    path = FIXTURES / name
    artifact = validate_parameter_artifact(
        path,
        expected_kind=kind,
        allow_reviewed_fixture=True,
        expected_qcsd_profile="live",
        expected_udp_payload_ceiling=1200,
    )

    assert artifact.sha256 == sha256_file(path)
    assert artifact.provenance_path == parameter_provenance_path(path).resolve()
    assert artifact.provenance_sha256 == sha256_file(artifact.provenance_path)
    assert artifact.input_policy == REVIEWED_PARAMETER_INPUT_POLICY


def test_reviewed_fixture_requires_explicit_smoke_opt_in():
    with pytest.raises(ValueError, match="only by smoke campaigns"):
        validate_parameter_artifact(
            FIXTURES / "wtfpad-live.json",
            expected_kind="wtf_pad",
        )


@pytest.mark.parametrize(
    ("keyword", "value", "message"),
    [
        ("expected_kind", "walkie_talkie", "kind does not match"),
        ("expected_qcsd_profile", "published", "profile does not match"),
        ("expected_qcsd_profile", "research-1200", "profile does not match"),
        ("expected_udp_payload_ceiling", 1450, "ceiling does not match"),
    ],
)
def test_receipt_must_match_campaign_contract(keyword, value, message):
    options = {
        "expected_kind": "traffic_morphing",
        "allow_reviewed_fixture": True,
        "expected_qcsd_profile": "live",
        "expected_udp_payload_ceiling": 1200,
    }
    options[keyword] = value
    with pytest.raises(ValueError, match=message):
        validate_parameter_artifact(FIXTURES / "traffic-morphing-live.json", **options)


def test_reviewed_fixture_cannot_be_supplied_from_an_arbitrary_path(tmp_path):
    source = FIXTURES / "wtfpad-live.json"
    parameter = tmp_path / source.name
    parameter.write_bytes(source.read_bytes())
    provenance = parameter_provenance_path(parameter)
    provenance.write_bytes(parameter_provenance_path(source).read_bytes())

    with pytest.raises(ValueError, match="must be checked in"):
        validate_parameter_artifact(parameter, allow_reviewed_fixture=True)


def test_parameter_tamper_breaks_receipt_hash(tmp_path, monkeypatch):
    parameter, provenance = _copy_fixture(tmp_path, monkeypatch, "wtfpad-live.json")
    value = json.loads(parameter.read_text(encoding="utf-8"))
    value["incoming"]["burst"]["tokens"][0] += 1
    atomic_json(parameter, value)

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        validate_parameter_artifact(
            parameter,
            expected_kind="wtf_pad",
            allow_reviewed_fixture=True,
            expected_qcsd_profile="live",
            expected_udp_payload_ceiling=1200,
        )
    assert provenance.is_file()


def test_receipt_tamper_and_runtime_shape_are_rejected(tmp_path, monkeypatch):
    parameter, provenance = _copy_fixture(tmp_path, monkeypatch, "walkie-talkie-live.json")
    receipt = json.loads(provenance.read_text(encoding="utf-8"))
    receipt["production_ready"] = True
    atomic_json(provenance, receipt)
    with pytest.raises(ValueError, match="non-production smoke fixture"):
        validate_parameter_artifact(parameter, allow_reviewed_fixture=True)

    receipt["production_ready"] = False
    value = json.loads(parameter.read_text(encoding="utf-8"))
    value["packet_size"] = 1199
    atomic_json(parameter, value)
    receipt["parameter_file"]["sha256"] = sha256_file(parameter)
    atomic_json(provenance, receipt)
    with pytest.raises(ValueError, match="runtime shape"):
        validate_parameter_artifact(parameter, allow_reviewed_fixture=True)


def test_research_1200_receipt_rejects_a_1201_byte_parameter_artifact(tmp_path, monkeypatch):
    parameter, provenance = _copy_fixture(tmp_path, monkeypatch, "walkie-talkie-live.json")
    receipt = json.loads(provenance.read_text(encoding="utf-8"))
    receipt["qcsd_profile"] = "research-1200"
    atomic_json(provenance, receipt)

    validate_parameter_artifact(
        parameter,
        expected_kind="walkie_talkie",
        allow_reviewed_fixture=True,
        expected_qcsd_profile="research-1200",
        expected_udp_payload_ceiling=1200,
    )

    value = json.loads(parameter.read_text(encoding="utf-8"))
    value["packet_size"] = 1201
    atomic_json(parameter, value)
    receipt["parameter_file"]["sha256"] = sha256_file(parameter)
    atomic_json(provenance, receipt)
    with pytest.raises(ValueError, match="runtime shape"):
        validate_parameter_artifact(
            parameter,
            expected_kind="walkie_talkie",
            allow_reviewed_fixture=True,
            expected_qcsd_profile="research-1200",
            expected_udp_payload_ceiling=1200,
        )


def test_named_profiles_can_be_bound_to_campaign_workloads():
    validate_parameter_artifact(
        FIXTURES / "traffic-morphing-live.json",
        expected_kind="traffic_morphing",
        allow_reviewed_fixture=True,
        expected_workloads={"cloudflare-quiche", "chromium-quic-page", "simple", "complex"},
    )
    with pytest.raises(ValueError, match="cover all"):
        validate_parameter_artifact(
            FIXTURES / "traffic-morphing-live.json",
            expected_kind="traffic_morphing",
            allow_reviewed_fixture=True,
            expected_workloads={"not-in-the-fixture"},
        )


def test_smoke_walkie_talkie_allows_extra_fixture_only_identities():
    artifact = validate_parameter_artifact(
        FIXTURES / "walkie-talkie-live.json",
        expected_kind="walkie_talkie",
        allow_reviewed_fixture=True,
        expected_qcsd_profile="live",
        expected_udp_payload_ceiling=1200,
        expected_workloads={"cloudflare-quiche", "chromium-quic-page"},
    )
    assert artifact.input_policy == REVIEWED_PARAMETER_INPUT_POLICY


def test_walkie_talkie_rejects_cross_side_duplicate_identity(tmp_path, monkeypatch):
    parameter, provenance = _copy_fixture(tmp_path, monkeypatch, "walkie-talkie-live.json")
    value = json.loads(parameter.read_text(encoding="utf-8"))
    value["profiles"][0]["decoy"] = value["profiles"][1]["real"]
    atomic_json(parameter, value)
    receipt = json.loads(provenance.read_text(encoding="utf-8"))
    receipt["parameter_file"]["sha256"] = sha256_file(parameter)
    atomic_json(provenance, receipt)

    with pytest.raises(ValueError, match="profiles are duplicated"):
        validate_parameter_artifact(
            parameter,
            expected_kind="walkie_talkie",
            allow_reviewed_fixture=True,
        )


def test_parameter_symlinks_are_rejected(tmp_path):
    parameter = tmp_path / "walkie-talkie-live.json"
    parameter.symlink_to(FIXTURES / "walkie-talkie-live.json")
    with pytest.raises(ValueError, match="symbolic links"):
        validate_parameter_artifact(parameter, allow_reviewed_fixture=True)


def test_runner_parameter_receipt_binds_kind_hash_path_and_workload():
    path = Path("/results/sample/neqo/defense-parameters.json")
    run = {
        "defense_parameters": {
            "kind": "wtf_pad",
            "sha256": "a" * 64,
            "path": str(path),
        },
        "resolved_configuration": {"defense": {"workload_id": "simple"}},
    }
    validate_run_parameter_binding(
        run,
        kind="wtf_pad",
        sha256="a" * 64,
        expected_path=path,
        expected_workload_id="simple",
    )
    run["defense_parameters"]["sha256"] = "b" * 64
    with pytest.raises(ValueError, match="run binding mismatch"):
        validate_run_parameter_binding(run, kind="wtf_pad", sha256="a" * 64)


def _copy_fixture(tmp_path, monkeypatch, name):
    monkeypatch.setattr(parameters, "LAB_ROOT", tmp_path)
    destination = tmp_path / "config/defense-params"
    destination.mkdir(parents=True)
    source = FIXTURES / name
    parameter = destination / name
    parameter.write_bytes(source.read_bytes())
    provenance = parameter_provenance_path(parameter)
    provenance.write_bytes(parameter_provenance_path(source).read_bytes())
    return parameter, provenance
