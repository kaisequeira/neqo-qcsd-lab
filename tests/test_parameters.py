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


def test_unbound_checked_in_walkie_talkie_fixture_fails_before_execution():
    with pytest.raises(ValueError, match="not bound to workload SHA-256"):
        validate_parameter_artifact(
            FIXTURES / "walkie-talkie-live.json",
            expected_kind="walkie_talkie",
            allow_reviewed_fixture=True,
            expected_qcsd_profile="live",
            expected_udp_payload_ceiling=1200,
        )


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


def test_wtf_pad_smoke_fixture_requires_the_runtime_infinity_formula(tmp_path, monkeypatch):
    parameter, provenance = _copy_fixture(tmp_path, monkeypatch, "wtfpad-live.json")
    value = json.loads(parameter.read_text(encoding="utf-8"))
    value["fitting"]["infinity_token_formulas"]["burst"] = "k_inf = p_inf / (1 - p_inf) * K"
    atomic_json(parameter, value)
    receipt = json.loads(provenance.read_text(encoding="utf-8"))
    receipt["parameter_file"]["sha256"] = sha256_file(parameter)
    atomic_json(provenance, receipt)

    with pytest.raises(ValueError, match="fitting metadata is invalid"):
        validate_parameter_artifact(
            parameter,
            expected_kind="wtf_pad",
            allow_reviewed_fixture=True,
            expected_qcsd_profile="live",
            expected_udp_payload_ceiling=1200,
        )


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


def test_walkie_talkie_schema_four_requires_exact_receiver_continuation() -> None:
    value = json.loads((FIXTURES / "walkie-talkie-live.json").read_text(encoding="utf-8"))
    parameters._validate_runtime_shape(
        value,
        "walkie_talkie",
        1_200,
        Path("walkie-talkie.json"),
        expected_schema_version=4,
    )

    for mutation in ("missing", "changed", "missing-policy", "changed-policy"):
        changed = json.loads(json.dumps(value))
        if mutation == "missing":
            del changed["receiver_continuation"]
        elif mutation == "changed":
            changed["receiver_continuation"]["cells_per_nonzero_incoming_component"] = 2
        elif mutation == "missing-policy":
            del changed["receiver_continuation"]["allocation_policy"]
        else:
            changed["receiver_continuation"]["release_policy"] = "eager"
        with pytest.raises(ValueError, match="runtime shape"):
            parameters._validate_runtime_shape(
                changed,
                "walkie_talkie",
                1_200,
                Path("walkie-talkie.json"),
                expected_schema_version=4,
            )

    legacy = json.loads((FIXTURES / "walkie-talkie-live.json").read_text(encoding="utf-8"))
    legacy["schema_version"] = 2
    legacy["matching_algorithm"] = "minimum-cost-one-to-one"
    with pytest.raises(ValueError, match="runtime shape"):
        parameters._validate_runtime_shape(
            legacy,
            "walkie_talkie",
            1_200,
            Path("walkie-talkie-live.json"),
            expected_schema_version=2,
        )

    superseded = json.loads((FIXTURES / "walkie-talkie-live.json").read_text(encoding="utf-8"))
    superseded["schema_version"] = 3
    with pytest.raises(ValueError, match="versioned client-only runtime contract"):
        parameters._validate_runtime_shape(
            superseded,
            "walkie_talkie",
            1_200,
            Path("walkie-talkie-live.json"),
            expected_schema_version=4,
        )


def test_walkie_talkie_live_fixture_has_exact_receiver_continuation_derivation() -> None:
    value = json.loads((FIXTURES / "walkie-talkie-live.json").read_text(encoding="utf-8"))
    expected = [
        ([(3, 129)], 26, 158_400),
        ([(2, 129), (8, 33), (8, 33), (4, 33), (4, 33), (0, 129), (2, 33)], 55, 541_200),
        ([(3, 129)], 21, 158_400),
        ([(4, 129), (3, 33), (3, 33)], 66, 246_000),
    ]

    assert value["schema_version"] == 4
    assert value["receiver_continuation"] == parameters._WALKIE_TALKIE_RECEIVER_CONTINUATION
    for profile, (bursts, cost, scheduled_bytes) in zip(value["profiles"], expected, strict=True):
        assert [(burst["outgoing"], burst["incoming"]) for burst in profile["bursts"]] == bursts
        assert profile["matching_cost_packets"] == cost
        assert profile["total_scheduled_bytes"] == scheduled_bytes


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


def test_smoke_walkie_talkie_binds_exact_workload_hashes_and_allows_extra_identities(
    tmp_path, monkeypatch
):
    parameter, provenance = _copy_fixture(tmp_path, monkeypatch, "walkie-talkie-live.json")
    bindings = _controlled_workload_bindings(tmp_path, ["cloudflare-quiche", "chromium-quic-page"])
    receipt = json.loads(provenance.read_text(encoding="utf-8"))
    receipt["workload_sha256"] = bindings
    atomic_json(provenance, receipt)
    artifact = validate_parameter_artifact(
        parameter,
        expected_kind="walkie_talkie",
        allow_reviewed_fixture=True,
        expected_qcsd_profile="live",
        expected_udp_payload_ceiling=1200,
        expected_workloads=bindings,
    )
    assert artifact.input_policy == REVIEWED_PARAMETER_INPUT_POLICY

    mismatched = {**bindings, "chromium-quic-page": "f" * 64}
    with pytest.raises(ValueError, match="exact campaign workload SHA-256"):
        validate_parameter_artifact(
            parameter,
            expected_kind="walkie_talkie",
            allow_reviewed_fixture=True,
            expected_qcsd_profile="live",
            expected_udp_payload_ceiling=1200,
            expected_workloads=mismatched,
        )

    with pytest.raises(ValueError, match="require campaign workload SHA-256 bindings"):
        validate_parameter_artifact(
            parameter,
            expected_kind="walkie_talkie",
            allow_reviewed_fixture=True,
            expected_workloads=set(bindings),
        )


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
    if name == "walkie-talkie-live.json":
        receipt = json.loads(provenance.read_text(encoding="utf-8"))
        receipt["workload_sha256"] = _controlled_workload_bindings(tmp_path, ["unit-test-workload"])
        atomic_json(provenance, receipt)
    return parameter, provenance


def _controlled_workload_bindings(tmp_path: Path, workload_ids: list[str]) -> dict[str, str]:
    workload_dir = tmp_path / "config/workloads"
    workload_dir.mkdir(parents=True, exist_ok=True)
    bindings = {}
    for index, workload_id in enumerate(workload_ids):
        workload = workload_dir / f"{workload_id}.json"
        workload.write_text(
            json.dumps({"resources": [], "test_identity": index}, sort_keys=True),
            encoding="utf-8",
        )
        bindings[workload_id] = sha256_file(workload)
    return bindings
