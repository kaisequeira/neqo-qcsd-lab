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
        parameters._validate_runtime_shape(
            value,
            "walkie_talkie",
            1_200,
            parameter,
            expected_schema_version=5,
        )


def test_walkie_talkie_schema_five_requires_exact_receiver_continuation() -> None:
    value = json.loads((FIXTURES / "walkie-talkie-live.json").read_text(encoding="utf-8"))
    parameters._validate_runtime_shape(
        value,
        "walkie_talkie",
        1_200,
        Path("walkie-talkie.json"),
        expected_schema_version=5,
    )

    for mutation in (
        "missing",
        "changed",
        "missing-policy",
        "changed-policy",
        "changed-activation",
        "changed-provisioning",
        "changed-reserve",
        "missing-base-allocation",
        "changed-base-allocation",
        "missing-reserve-lifecycle",
        "changed-reserve-lifecycle",
        "missing-resource-precondition",
        "changed-resource-precondition",
        "missing-causal-capacity",
        "changed-causal-capacity",
        "missing-prefix-delivery",
        "changed-prefix-delivery",
        "missing-loss-limitation",
        "changed-loss-limitation",
        "unknown-field",
    ):
        changed = json.loads(json.dumps(value))
        if mutation == "missing":
            del changed["receiver_continuation"]
        elif mutation == "changed":
            changed["receiver_continuation"]["cells_per_nonzero_incoming_component"] = 2
        elif mutation == "missing-policy":
            del changed["receiver_continuation"]["allocation_policy"]
        elif mutation == "changed-policy":
            changed["receiver_continuation"]["release_policy"] = "eager"
        elif mutation == "changed-activation":
            changed["receiver_continuation"]["request_activation_policy"] = "created-locally"
        elif mutation == "changed-provisioning":
            changed["receiver_continuation"]["provisioning_policy"] = "on-demand"
        elif mutation == "changed-reserve":
            changed["receiver_continuation"]["reserve_policy"] = "none"
        elif mutation == "missing-base-allocation":
            del changed["receiver_continuation"]["base_allocation_policy"]
        elif mutation == "changed-base-allocation":
            changed["receiver_continuation"]["base_allocation_policy"] = "any-stream"
        elif mutation == "missing-reserve-lifecycle":
            del changed["receiver_continuation"]["reserve_lifecycle_policy"]
        elif mutation == "changed-reserve-lifecycle":
            changed["receiver_continuation"]["reserve_lifecycle_policy"] = "refill-always"
        elif mutation == "missing-resource-precondition":
            del changed["receiver_continuation"]["resource_precondition"]
        elif mutation == "changed-resource-precondition":
            changed["receiver_continuation"]["resource_precondition"] = "any-resource"
        elif mutation == "missing-causal-capacity":
            del changed["receiver_continuation"]["causal_capacity_precondition"]
        elif mutation == "changed-causal-capacity":
            changed["receiver_continuation"]["causal_capacity_precondition"] = "one-stream"
        elif mutation == "missing-prefix-delivery":
            del changed["receiver_continuation"]["request_prefix_delivery_precondition"]
        elif mutation == "changed-prefix-delivery":
            changed["receiver_continuation"]["request_prefix_delivery_precondition"] = "any-one"
        elif mutation == "missing-loss-limitation":
            del changed["receiver_continuation"]["post_outgoing_loss_liveness_limitation"]
        elif mutation == "changed-loss-limitation":
            changed["receiver_continuation"]["post_outgoing_loss_liveness_limitation"] = "always"
        else:
            changed["receiver_continuation"]["unknown"] = True
        with pytest.raises(ValueError, match="runtime shape"):
            parameters._validate_runtime_shape(
                changed,
                "walkie_talkie",
                1_200,
                Path("walkie-talkie.json"),
                expected_schema_version=5,
            )

    no_causal_prefix = json.loads(json.dumps(value))
    no_causal_prefix["profiles"][0]["bursts"][0]["outgoing"] = 0
    with pytest.raises(ValueError, match="first molded component must contain outgoing cells"):
        parameters._validate_runtime_shape(
            no_causal_prefix,
            "walkie_talkie",
            1_200,
            Path("walkie-talkie.json"),
            expected_schema_version=5,
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

    for superseded_schema in (3, 4):
        superseded = json.loads((FIXTURES / "walkie-talkie-live.json").read_text(encoding="utf-8"))
        superseded["schema_version"] = superseded_schema
        with pytest.raises(ValueError, match="versioned client-only runtime contract"):
            parameters._validate_runtime_shape(
                superseded,
                "walkie_talkie",
                1_200,
                Path("walkie-talkie-live.json"),
                expected_schema_version=5,
            )


def test_walkie_talkie_live_fixture_has_exact_receiver_continuation_derivation() -> None:
    value = json.loads((FIXTURES / "walkie-talkie-live.json").read_text(encoding="utf-8"))
    expected = [
        ([(3, 129)], 26, 158_400),
        ([(2, 129), (8, 33), (8, 33), (4, 33), (4, 33), (0, 129), (2, 33)], 55, 541_200),
        ([(3, 129)], 21, 158_400),
        ([(4, 129), (3, 33), (3, 33)], 66, 246_000),
    ]

    assert value["schema_version"] == 5
    assert value["generated_by"] == "qcsd_lab.walkietalkie 0.7.2"
    assert (
        value["receiver_continuation"]
        == parameters._WALKIE_TALKIE_RECEIVER_CONTINUATION_SCHEMA_FIVE
    )
    for profile, (bursts, cost, scheduled_bytes) in zip(value["profiles"], expected, strict=True):
        assert [(burst["outgoing"], burst["incoming"]) for burst in profile["bursts"]] == bursts
        assert profile["matching_cost_packets"] == cost
        assert profile["total_scheduled_bytes"] == scheduled_bytes


def test_schema_six_rejects_superseded_receiver_and_binding_shapes() -> None:
    value = {
        "schema_version": 6,
        "adaptation": "qcsd-client-only",
        "paper_equivalent": False,
        "packet_size": 1_200,
        "matching_algorithm": "minimum-base-symmetric-mold-padding-cost-one-to-one",
        "receiver_continuation": parameters._WALKIE_TALKIE_RECEIVER_CONTINUATION,
        "qualification_bindings": [
            {
                "workload_id": "alpha",
                "chaff_qualification_sidecar_sha256": "a" * 64,
                "prefix_pack_spec_sha256": "b" * 64,
                "qualified_chaff_manifest_sha256": "c" * 64,
                "application_resource_id": 0,
                "selected_chaff_resource_id": 6,
                "qualified_parallel_chaff_streams": 20,
                "walkie_talkie_required_chaff_streams": 20,
            },
            {
                "workload_id": "bravo",
                "chaff_qualification_sidecar_sha256": "d" * 64,
                "prefix_pack_spec_sha256": "e" * 64,
                "qualified_chaff_manifest_sha256": "f" * 64,
                "application_resource_id": 0,
                "selected_chaff_resource_id": 0,
                "qualified_parallel_chaff_streams": 6,
                "walkie_talkie_required_chaff_streams": 6,
            },
        ],
        "profiles": [
            {
                "real": "alpha",
                "decoy": "bravo",
                "matching_cost_packets": 0,
                "training_inputs": {"real": [], "decoy": []},
                "variation": {
                    "real": {
                        "visit_count": 1,
                        "varying_components": 0,
                        "maximum_component_spread": 0,
                    },
                    "decoy": {
                        "visit_count": 1,
                        "varying_components": 0,
                        "maximum_component_spread": 0,
                    },
                },
                "source_envelopes": {
                    "real": [{"outgoing": 1, "incoming": 1}],
                    "decoy": [{"outgoing": 1, "incoming": 1}],
                },
                "batch_ends": {"real": [1], "decoy": [1]},
                "molded_batch_ends": [1],
                "total_scheduled_bytes": 3_600,
                "bursts": [{"outgoing": 1, "incoming": 2}],
            }
        ],
    }
    parameters._validate_runtime_shape(
        value,
        "walkie_talkie",
        1_200,
        Path("walkie-talkie.json"),
        expected_schema_version=6,
    )
    for sender_field in (
        "sender_framing_cells_per_nonzero_outgoing_component",
        "sender_framing_formula",
        "sender_framing_policy",
    ):
        changed = json.loads(json.dumps(value))
        del changed["receiver_continuation"][sender_field]
        with pytest.raises(ValueError, match="runtime shape"):
            parameters._validate_runtime_shape(
                changed,
                "walkie_talkie",
                1_200,
                Path("walkie-talkie.json"),
                expected_schema_version=6,
            )
    changed = json.loads(json.dumps(value))
    changed["receiver_continuation"] = parameters._WALKIE_TALKIE_RECEIVER_CONTINUATION_SCHEMA_FIVE
    with pytest.raises(ValueError, match="runtime shape"):
        parameters._validate_runtime_shape(
            changed,
            "walkie_talkie",
            1_200,
            Path("walkie-talkie.json"),
            expected_schema_version=6,
        )
    changed = json.loads(json.dumps(value))
    del changed["qualification_bindings"][0]["selected_chaff_resource_id"]
    with pytest.raises(ValueError, match="binding is malformed"):
        parameters._validate_runtime_shape(
            changed,
            "walkie_talkie",
            1_200,
            Path("walkie-talkie.json"),
            expected_schema_version=6,
        )
    changed = json.loads(json.dumps(value))
    changed["qualification_bindings"][0]["application_resource_id"] = False
    with pytest.raises(ValueError, match="qualification binding"):
        parameters._validate_runtime_shape(
            changed,
            "walkie_talkie",
            1_200,
            Path("walkie-talkie.json"),
            expected_schema_version=6,
        )


def test_research_1200_receipt_rejects_a_1201_byte_parameter_artifact(tmp_path, monkeypatch):
    parameter, provenance = _copy_fixture(tmp_path, monkeypatch, "walkie-talkie-live.json")
    receipt = json.loads(provenance.read_text(encoding="utf-8"))
    receipt["qcsd_profile"] = "research-1200"
    atomic_json(provenance, receipt)

    with pytest.raises(ValueError, match="historical test oracles only"):
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
        parameters._validate_runtime_shape(
            value,
            "walkie_talkie",
            1_200,
            parameter,
            expected_schema_version=5,
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


def test_reviewed_walkie_talkie_fixture_is_historical_only_even_when_bound(tmp_path, monkeypatch):
    parameter, provenance = _copy_fixture(tmp_path, monkeypatch, "walkie-talkie-live.json")
    bindings = _controlled_workload_bindings(tmp_path, ["cloudflare-quiche", "chromium-quic-page"])
    receipt = json.loads(provenance.read_text(encoding="utf-8"))
    receipt["workload_sha256"] = bindings
    atomic_json(provenance, receipt)
    with pytest.raises(ValueError, match="historical test oracles only"):
        validate_parameter_artifact(
            parameter,
            expected_kind="walkie_talkie",
            allow_reviewed_fixture=True,
            expected_qcsd_profile="live",
            expected_udp_payload_ceiling=1200,
            expected_workloads=bindings,
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
        parameters._validate_runtime_shape(
            value,
            "walkie_talkie",
            1_200,
            parameter,
            expected_schema_version=5,
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


def test_buflo_guard_requires_the_inclusive_exact_duration_opportunity() -> None:
    value = {
        "schema_version": 1,
        "interval_us": 20_000,
        "minimum_duration_us": 10_000_000,
        "packet_size": 1_200,
        "max_events": 500,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
    }
    with pytest.raises(ValueError, match="runtime shape is invalid"):
        parameters._validate_buflo(value, 1_200, Path("buflo.json"))

    value["max_events"] = 501
    parameters._validate_buflo(value, 1_200, Path("buflo.json"))


def test_buflo_guard_is_capped_per_direction_at_ten_thousand() -> None:
    value = {
        "schema_version": 1,
        "interval_us": 10_000,
        "minimum_duration_us": 10_000,
        "packet_size": 1_200,
        "max_events": 10_001,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
    }
    with pytest.raises(ValueError, match="runtime shape is invalid"):
        parameters._validate_buflo(value, 1_200, Path("buflo.json"))


def test_buflo_terminal_provenance_rejects_missing_changed_and_extra_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parameter, provenance = _copy_fixture(
        tmp_path, monkeypatch, "buflo-live.json"
    )
    original = json.loads(provenance.read_text(encoding="utf-8"))
    mutations = []
    missing = json.loads(json.dumps(original))
    del missing["terminal_subcell_policy"]
    mutations.append(missing)
    changed = json.loads(json.dumps(original))
    changed["terminal_subcell_observer_effect"] = "drifted"
    mutations.append(changed)
    old_translation = json.loads(json.dumps(original))
    old_translation["terminal_translation_version"] = 1
    mutations.append(old_translation)
    float_translation = json.loads(json.dumps(original))
    float_translation["terminal_translation_version"] = 2.0
    mutations.append(float_translation)
    for invalid_schema in (True, 1.0):
        confused_schema = json.loads(json.dumps(original))
        confused_schema["schema_version"] = invalid_schema
        mutations.append(confused_schema)
    unsafe_parser_contract = json.loads(json.dumps(original))
    unsafe_parser_contract["terminal_parser_safety"] = (
        "latch-requires-zero-live-parser-lease-bytes-and-zero-pending-parser-boundaries"
    )
    mutations.append(unsafe_parser_contract)
    extra = json.loads(json.dumps(original))
    extra["unreceipted_terminal_semantics"] = True
    mutations.append(extra)

    for receipt in mutations:
        atomic_json(provenance, receipt)
        with pytest.raises(ValueError, match="BuFLO"):
            validate_parameter_artifact(
                parameter,
                expected_kind="buflo",
                allow_study_candidate=True,
                expected_qcsd_profile="research-1200",
                expected_udp_payload_ceiling=1_200,
            )


def test_cs_buflo_provenance_v2_is_exact_and_legacy_v1_remains_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parameter, provenance = _copy_fixture(
        tmp_path, monkeypatch, "cs-buflo-ctsp-live.json"
    )
    options = {
        "expected_kind": "cs_buflo",
        "allow_study_candidate": True,
        "expected_qcsd_profile": "research-1200",
        "expected_udp_payload_ceiling": 1_200,
    }
    validate_parameter_artifact(parameter, **options)
    current = json.loads(provenance.read_text(encoding="utf-8"))
    assert current["schema_version"] == 2
    assert current["paper_early_termination_semantics"] == (
        "server-done-xmitting-requires-empty-output-buffer-and-onload-or-strict-"
        "quiet-time-and-either-client-padding-done-or-current-write-real-plus-"
        "junk-power-of-two-crossing"
    )
    assert current["pinned_author_padding_done_active_consumers"] == 0
    assert current["live_early_termination_semantics"] == (
        "stop-new-client-opportunities-at-first-eligible-frozen-padding-target-"
        "or-directional-power-of-two-crossing-outgoing-by-observed-udp-and-"
        "incoming-by-fully-consumed-scheduled-credit-then-drain-advertised-"
        "credit-exactly-once"
    )

    for invalid_schema in (True, 1.0, 2.0):
        invalid = json.loads(json.dumps(current))
        invalid["schema_version"] = invalid_schema
        atomic_json(provenance, invalid)
        with pytest.raises(ValueError, match="provenance"):
            validate_parameter_artifact(parameter, **options)
    invalid_consumer_count = json.loads(json.dumps(current))
    invalid_consumer_count["pinned_author_padding_done_active_consumers"] = False
    atomic_json(provenance, invalid_consumer_count)
    with pytest.raises(ValueError, match="translation divergence"):
        validate_parameter_artifact(parameter, **options)
    for field in (
        "rate_boundary_translation_version",
        "early_termination_translation_version",
    ):
        invalid_version = json.loads(json.dumps(current))
        invalid_version[field] = 2.0
        atomic_json(provenance, invalid_version)
        with pytest.raises(ValueError, match="translation divergence"):
            validate_parameter_artifact(parameter, **options)

    legacy = json.loads(json.dumps(current))
    legacy["schema_version"] = 1
    legacy["early_termination_semantics"] = (
        "udp_client_only_observed_udp_power_of_two_crossing"
    )
    for key in (
        parameters._CS_BUFLO_SEMANTICS_V2_KEYS
        - parameters._LEGACY_CS_BUFLO_SEMANTICS_V1_KEYS
    ):
        legacy.pop(key)
    atomic_json(provenance, legacy)
    validate_parameter_artifact(parameter, **options)

    legacy["paper_early_termination_semantics"] = "unreceipted-v1-extension"
    atomic_json(provenance, legacy)
    with pytest.raises(ValueError, match="wrong fields"):
        validate_parameter_artifact(parameter, **options)


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
