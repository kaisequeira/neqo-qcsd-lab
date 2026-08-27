from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import buflo_evaluation, buflo_handoff, buflo_study, capture_session, orchestrator
from qcsd_lab.buflo_study import (
    DEBIAN_BASE_IMAGE,
    PARAMETER_FILES,
    RUST_BASE_IMAGE,
    STUDY_PLAN,
    generated_stage_cells,
    load_study_plan,
    run_study_action,
    validate_campaign_matrix,
    validate_controlled_campaign_receipt,
    validate_formal_capture_capacity,
    validate_parameters,
    validate_established_seven_baseline,
    validate_reference_gate_receipt,
    validate_staged_capture_prerequisites,
    validate_study_environment_receipt,
    validate_validation_attestation,
)
from qcsd_lab.capture_session import (
    _client_resource_usage_valid,
    _merge_runner_wakeup_metrics,
    _parse_client_resource_usage,
    _runner_wakeup_metrics_valid,
)
from qcsd_lab.defenses import (
    DEFENSE_ADAPTATIONS,
    DEFENSE_ORDER,
    DEFENSE_RUNTIME_KINDS,
    DEFENSE_VARIANT_LABELS,
)
from qcsd_lab.fidelity import (
    SCHEDULE_PREFIX_FIELDS,
    SCHEDULE_QCSD_FIELDS,
    _cs_buflo_padding_targets_match,
    _cs_buflo_payload_padding_target,
    _schedule_realization_metrics,
    fidelity_eligible,
    new_defense_terminal_receipts_valid,
)
from qcsd_lab.util import LAB_ROOT


def _reference_execution_fixture(tmp_path: Path) -> Path:
    build_execution = _build_execution_value()
    source = {
        "image_digest": "sha256:" + "e" * 64,
        "lab_commit": "b" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": buflo_study.EMPTY_SHA256,
        "neqo_commit": "c" * 40,
        "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": buflo_study.EMPTY_SHA256,
    }
    isolation = {
        "environment_marker": "QCSD_REFERENCE_ISOLATED=1",
        "docker_network_mode": "none",
        "observed_interfaces": ["lo"],
        "reference_inputs_read_only": True,
        "output_mount_writable": True,
        "output_create_only": True,
        "ordinary_collection_contains_author_code": False,
    }
    value = buflo_study._reference_execution_value(
        source=source,
        build_execution={
            "sha256": hashlib.sha256(
                (json.dumps(build_execution, indent=2, sort_keys=True) + "\n").encode()
            ).hexdigest(),
            "receipt": build_execution,
        },
        isolation=isolation,
        execution_id="d" * 32,
        started_at="2026-08-27T00:00:00+00:00",
        finished_at="2026-08-27T00:00:00+00:00",
        duration_seconds=0.0,
    )
    destination = tmp_path / "reference-execution.json"
    destination.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def _build_execution_value(
    image_id: str = "sha256:" + "a" * 64,
    *,
    cohort_version: int = 1,
) -> dict[str, object]:
    source = {
        "image_digest": image_id,
        "lab_commit": "b" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": buflo_study.EMPTY_SHA256,
        "neqo_commit": "c" * 40,
        "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": buflo_study.EMPTY_SHA256,
    }
    images = {
        target: {
            "tag": f"neqo-qcsd-lab-{target}:test",
            "id": image_id if target == "collection" else "sha256:" + digest * 64,
            "repo_digests": [],
        }
        for target, digest in (("collection", "a"), ("prepare", "d"), ("reference", "e"))
    }
    commands = [
        {
            "target": target,
            "argv": [
                "docker",
                "build",
                "--pull",
                "--no-cache",
                "--target",
                target,
                "--tag",
                images[target]["tag"],
                "--file",
                str((LAB_ROOT / "Dockerfile").resolve()),
                str(LAB_ROOT.resolve()),
            ],
            "exit_code": 0,
            "image_id": images[target]["id"],
        }
        for target in ("collection", "prepare", "reference")
    ]
    value: dict[str, object] = {
        "schema_version": 1,
        "artifact_type": buflo_study.BUILD_EXECUTION_ARTIFACT_TYPE,
        "cohort_version": cohort_version,
        "started_at": "2026-08-27T00:00:00+00:00",
        "finished_at": "2026-08-27T00:00:01+00:00",
        "duration_seconds": 1.0,
        "docker": {"client_version": "29.0.1", "server_version": "29.0.1"},
        "commands": commands,
        "images": images,
        "source": source,
        "build_inputs": {
            "schema_version": 1,
            "artifact_type": "qcsd-study-build-inputs",
            "rust_base_image": RUST_BASE_IMAGE,
            "debian_base_image": DEBIAN_BASE_IMAGE,
            "uv_lock_sha256": buflo_study.sha256_file(LAB_ROOT / "uv.lock"),
            "cargo_lock_sha256": buflo_study.sha256_file(
                LAB_ROOT / "neqo-qcsd/Cargo.lock"
            ),
        },
        "dockerfile_sha256": buflo_study.sha256_file(LAB_ROOT / "Dockerfile"),
        "cache_policy": {
            "pull": True,
            "no_cache": True,
            "scope": "Docker-layer-cache-disabled;declared-BuildKit-dependency-cache-mounts-only",
        },
    }
    value["payload_sha256"] = buflo_study._canonical_digest(value)
    return value


def _runner_wakeup_receipt() -> dict[str, object]:
    return {
        "schema_version": 1,
        "semantics": (
            "actual_select_return_source; socket_wins_simultaneous_readiness; "
            "controller_subset_is_effective_earliest_deadline; "
            "scheduled_cells_are_not_wakeups"
        ),
        "wait_returns": 12,
        "socket_readiness_wakeups": 7,
        "timer_wakeups": 5,
        "controller_deadline_timer_wakeups": 4,
        "other_timer_wakeups": 1,
    }


def test_registry_appends_two_candidate_scientific_identities() -> None:
    assert DEFENSE_ORDER[-2:] == ("buflo", "cs-buflo")
    assert DEFENSE_RUNTIME_KINDS["buflo"] == "buflo"
    assert DEFENSE_RUNTIME_KINDS["cs-buflo"] == "cs_buflo"
    assert DEFENSE_ADAPTATIONS["buflo"].implementation_status == "candidate"
    assert DEFENSE_ADAPTATIONS["cs-buflo"].implementation_status == "candidate"
    assert DEFENSE_VARIANT_LABELS == {
        "cs-buflo-ctsp": "CS-BuFLO (CTSP)",
        "cs-buflo-cpsp": "CS-BuFLO (CPSP)",
    }


def test_study_plan_binds_existing_parameter_paths_and_exact_counts() -> None:
    plan = load_study_plan()
    treatments = {item["name"]: item for item in plan["treatments"]}

    for name, (_kind, expected) in PARAMETER_FILES.items():
        if name in treatments:
            assert (STUDY_PLAN.parent / treatments[name]["parameters"]).resolve() == expected
            assert expected.is_file()
    assert plan["controlled"]["expected_samples"] == 160
    assert plan["implementation_baselines"] == {
        "lab_commit": "8988a48a8e43cc9d47505cae12ee7758bc7fa5ee",
        "neqo_commit": "6aceaac85243d6e0e34354108e010705d3c83088",
    }
    assert plan["established_seven_baseline_oracle"] == {
        "path": "config/buflo-study/v1/established-seven-baseline.json",
        "sha256": buflo_study.ESTABLISHED_SEVEN_BASELINE_SHA256,
    }
    assert plan["historical_corpus_guard"]["historical_exporter"] == {
        "path": "tools/classifier_handoff.py",
        "sha256": "f91964df8b6af3b1d89a8c2ff2de1997a59e9ffe36124fa8e20c694515152a72",
    }
    assert plan["regression"]["expected_samples"] == 18
    assert plan["public_stages"]["smoke"]["expected_samples"] == 20
    assert plan["public_stages"]["rehearsal"]["expected_samples"] == 40
    assert plan["public_stages"]["formal"]["expected_samples"] == 1_500
    assert plan["public_stages"]["formal"]["treatments"] == [
        "undefended",
        "buflo",
        "cs-buflo",
    ]
    assert "cs-buflo-cpsp" not in plan["public_stages"]["formal"]["treatments"]
    assert plan["capture_admission"] == {
        "staged_prerequisites": {
            "smoke": ["regression"],
            "rehearsal": ["regression", "smoke"],
            "formal": ["regression", "smoke", "rehearsal"],
        },
        "reference_gate": "isolated-create-only-conformance-receipt",
        "source_lineage": "one-exact-clean-collection-image",
        "formal_minimum_available_hours": 12.5,
        "formal_disk_safety_multiplier": 3,
        "formal_disk_projection_basis": ("verified-smoke-plus-rehearsal-bytes-per-sample"),
    }


def test_established_seven_baseline_rechecks_config_and_behavior_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = validate_established_seven_baseline()
    assert evidence["defenses"] == list(DEFENSE_ORDER[:7])
    assert evidence["passed"] is True

    monkeypatch.setitem(DEFENSE_RUNTIME_KINDS, "front", "tamaraw")
    with pytest.raises(ValueError, match="identities changed"):
        validate_established_seven_baseline()


def test_cs_buflo_provenance_explicitly_receipts_source_live_estimator_divergence() -> None:
    expected = {
        "source_semantics": (
            "author-oracle-advances-16KiB-boundaries-on-actually-transmitted-"
            "real-plus-junk-bytes-per-endpoint-and-direction"
        ),
        "live_semantics": (
            "qcsd-live-advances-16KiB-boundaries-on-exact-fresh-application-"
            "stream-bytes-outgoing-excludes-retransmission-and-defense-added-"
            "bytes-and-uses-consumed-application-offsets-incoming"
        ),
        "rate_boundary_translation_version": 2,
        "rate_boundary_counter_semantics": (
            "client_only_quic_fresh_application_stream_bytes_outgoing_"
            "retransmission_excluded_and_consumed_application_offsets_incoming"
        ),
        "author_rate_boundary_counter_semantics": (
            "per_direction_actually_transmitted_real_plus_junk_bytes"
        ),
        "translation_classification": "expected-client-only-qcsd-adaptation-difference",
        "early_termination_semantics": ("udp_client_only_observed_udp_power_of_two_crossing"),
        "expected_difference": (
            "adaptation-boundary-crossings-and-rate-transition-times-may-differ-"
            "from-the-author-artifact"
        ),
    }
    for treatment in ("cs-buflo-ctsp", "cs-buflo-cpsp"):
        parameter = PARAMETER_FILES[treatment][1]
        provenance = json.loads(
            parameter.with_name(parameter.name + ".provenance.json").read_text(encoding="utf-8")
        )
        assert {key: provenance[key] for key in expected} == expected


@pytest.mark.parametrize(
    ("rank", "observed"),
    (
        (0, [{"kind": "noqueue", "root": True}]),
        (
            1,
            [
                {
                    "kind": "netem",
                    "root": True,
                    "options": {
                        "limit": 1_000,
                        "delay": {"delay": 0.025, "jitter": 0, "correlation": 0},
                    },
                }
            ],
        ),
        (
            2,
            [
                {
                    "kind": "netem",
                    "root": True,
                    "options": {
                        "delay": {"delay": 0.025, "jitter": 0, "correlation": 0},
                        "rate": {
                            "rate": 625_000,
                            "packetoverhead": 0,
                            "cellsize": 0,
                            "celloverhead": 0,
                        },
                        "limit": 100,
                    },
                }
            ],
        ),
        (
            3,
            [
                {
                    "kind": "netem",
                    "root": True,
                    "options": {
                        "limit": 1_000,
                        "delay": {"delay": 0.025, "jitter": 0, "correlation": 0},
                        "loss-random": {"loss": 0.01, "correlation": 0},
                    },
                }
            ],
        ),
    ),
)
def test_controlled_receipt_requires_exact_bilateral_qdisc_evidence(
    rank: int, observed: list[dict[str, object]]
) -> None:
    profile = load_study_plan()["controlled"]["netem_profiles"][rank]
    endpoint = {
        "interface": "eth0",
        "applied_qdisc": profile["client_qdisc"],
        "observed_qdisc": observed,
    }
    receipt = {
        "schema_version": buflo_study.LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
        "stage": "controlled",
        "netem_profile": profile["id"],
        "netem_rank": rank,
        "client_qdisc": profile["client_qdisc"],
        "server_qdisc": profile["server_qdisc"],
        "workload_aliases": {
            "local-large": "local-large",
            "local-small": "local-small",
        },
        "fixture_scope": "controlled-live-manifests-including-two-origin-local-large",
        "treatment_order": [
            "undefended",
            "buflo",
            "cs-buflo-cpsp",
            "cs-buflo-ctsp",
        ],
        "evidence_class": "controlled-test-only-nonformal",
        "network": {
            "schema_version": 1,
            "artifact_type": "qcsd-buflo-controlled-network-v1",
            "image_digest": "sha256:" + "a" * 64,
            "network": "qcsd-buflo-study-v1",
            "client": {"role": "client", **endpoint},
            "servers": [
                {
                    "role": "server",
                    "alias": alias,
                    **endpoint,
                    "applied_qdisc": profile["server_qdisc"],
                }
                for alias in (
                    "qcsd-buflo-server-one",
                    "qcsd-buflo-server-two",
                )
            ],
            "directional_coverage": {
                "client_to_server": {
                    "shaped_egress": "client:eth0",
                    "opposite_ingress": "servers:eth0",
                },
                "server_to_client": {
                    "shaped_egress": "servers:eth0",
                    "opposite_ingress": "client:eth0",
                },
            },
        },
    }

    assert validate_controlled_campaign_receipt(receipt)["netem_rank"] == rank
    historical = dict(receipt)
    historical.pop("fixture_scope")
    historical["schema_version"] = 1
    assert validate_controlled_campaign_receipt(historical)["netem_rank"] == rank
    stripped = dict(receipt)
    stripped.pop("fixture_scope")
    with pytest.raises(ValueError, match="fields are invalid"):
        validate_controlled_campaign_receipt(stripped)
    changed_scope = json.loads(json.dumps(receipt))
    changed_scope["fixture_scope"] = "same-origin-regression-surrogates"
    with pytest.raises(ValueError, match="matrix binding"):
        validate_controlled_campaign_receipt(changed_scope)
    changed = json.loads(json.dumps(receipt))
    changed["network"]["directional_coverage"]["server_to_client"]["opposite_ingress"] = (
        "unobserved"
    )
    with pytest.raises(ValueError, match="bilateral"):
        validate_controlled_campaign_receipt(changed)


def test_validation_attestation_promotion_is_fail_closed(tmp_path: Path) -> None:
    attestation = tmp_path / "validation-attestation.json"
    attestation.write_text(
        json.dumps({"implementation_status": "validated-client-only-qcsd-adaptation"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="typed evidence is missing"):
        validate_validation_attestation(attestation)


def test_local_workload_preparation_freezes_real_probe_receipts_without_synthesis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workload = {
        "resources": [
            buflo_study._local_resource(
                0,
                "https://qcsd-buflo-server-one:4433/1024",
                "Document",
                1_024,
            )
        ]
    }
    response = {
        "resource_id": 0,
        "status": 200,
        "bytes": 1_024,
        "body_sha256": "a" * 64,
        "complete": True,
        "outcome": "succeeded",
        "request_headers": [["accept", "text/html"]],
    }
    runs = [
        {
            "neqo_version": "test-neqo",
            "neqo_base_commit": "1" * 40,
            "published_qcsd_commit": "2" * 40,
            "migration_commit": "3" * 40,
            "responses": [response],
        }
        for _index in range(3)
    ]
    directional_statistics = {
        "packet_count": 1,
        "observed_udp_payload_max": 1_200,
        "oversized_packet_count": 0,
    }
    total_statistics = {**directional_statistics, "packet_count": 2}
    udp = {
        "schema_version": 1,
        "configured_udp_payload_ceiling": 1_200,
        "runs": [
            {
                "run_index": index,
                "packets_sha256": chr(ord("d") + index) * 64,
                "incoming": directional_statistics,
                "outgoing": directional_statistics,
                "total": total_statistics,
            }
            for index in range(3)
        ],
    }

    def probe(
        *_args: object, **_kwargs: object
    ) -> tuple[dict[str, object], list[dict[str, object]], dict[str, object]]:
        return (
            {
                "runs": 3,
                "stable_resource_ids": [0],
                "expected_responses": [
                    {
                        key: response[key]
                        for key in ("resource_id", "status", "bytes", "body_sha256")
                    }
                ],
            },
            runs,
            udp,
        )

    monkeypatch.setattr("qcsd_lab.prepare._probe_response_stability", probe)
    monkeypatch.setattr(
        buflo_study,
        "source_metadata",
        lambda: {
            "image_digest": "sha256:" + "9" * 64,
            "lab_commit": "4" * 40,
            "lab_dirty": True,
            "lab_patch_sha256": "5" * 64,
            "neqo_commit": "3" * 40,
            "neqo_pinned_commit": "3" * 40,
            "neqo_dirty": True,
            "neqo_patch_sha256": "6" * 64,
        },
    )
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "9" * 64)

    buflo_study._prepare_local_workloads(
        tmp_path,
        {"local-probe": workload},
        label="test local workload",
    )

    frozen = json.loads((tmp_path / "local-probe.json").read_text(encoding="utf-8"))
    preparation = frozen["preparation"]
    assert preparation["chromium_version"] == "not-applicable-deterministic-local-server"
    assert preparation["lab_source"]["lab_dirty"] is True
    assert [run["packets_sha256"] for run in preparation["udp_payload_qualification"]["runs"]] == [
        "d" * 64,
        "e" * 64,
        "f" * 64,
    ]
    assert preparation["expected_responses"][0]["body_sha256"] == "a" * 64


def test_controlled_rate_driver_is_separate_bounded_and_live_size_gated() -> None:
    values = {
        workload_id: buflo_study._csbuflo_rate_driver_value(workload_id)
        for workload_id in ("local-small", "local-large")
    }
    assert len(set(values.values())) == 2
    assert all(
        len(value.encode("ascii")) == buflo_study.CSBUFLO_RATE_DRIVER_VALUE_BYTES
        for value in values.values()
    )
    assert buflo_study.CSBUFLO_RATE_DRIVER_VALUE_BYTES < 384 * 1_024
    assert (
        buflo_study.CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES
        == buflo_study.CSBUFLO_RATE_DRIVER_BOUNDARY_BYTES
        + 4 * buflo_study.CSBUFLO_RATE_DRIVER_CELL_BYTES
    )

    driver = buflo_study._controlled_csbuflo_rate_driver(1, "local-small")
    resources = [
        buflo_study._local_resource(
            0,
            "https://qcsd-buflo-server-one:4433/131072",
            "Document",
            131_072,
        ),
        driver,
    ]
    response = {
        "resource_id": 1,
        "complete": True,
        "outcome": "succeeded",
        "request_headers": driver["headers"],
        "request_stream_bytes": buflo_study.CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES,
    }
    proof = buflo_study._validate_controlled_csbuflo_rate_driver(
        "local-small",
        resources,
        runs=[{"responses": [response]} for _index in range(3)],
    )
    assert proof["encoded_request_stream_bytes"] == [
        buflo_study.CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES
    ] * 3
    observation = buflo_study._controlled_csbuflo_rate_driver_observation(
        "local-small", {"responses": [response]}
    )
    assert observation["post_boundary_cells"] == 4

    too_short = {**response, "request_stream_bytes": 16_384}
    with pytest.raises(ValueError, match="did not encode beyond"):
        buflo_study._validate_controlled_csbuflo_rate_driver(
            "local-small", resources, runs=[{"responses": [too_short]}]
        )


def test_controlled_driver_does_not_change_regression_manifests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, dict[str, dict[str, object]], bool]] = []

    def capture(
        _root: Path,
        manifests: dict[str, dict[str, object]],
        *,
        label: str,
        require_csbuflo_rate_driver: bool = False,
    ) -> None:
        calls.append((label, manifests, require_csbuflo_rate_driver))

    monkeypatch.setattr(buflo_study, "_prepare_local_workloads", capture)
    buflo_study._create_local_workloads(tmp_path)
    buflo_study._create_regression_workloads(tmp_path)

    _controlled_label, controlled, controlled_gate = calls[0]
    _regression_label, regression, regression_gate = calls[1]
    assert controlled_gate is True
    assert regression_gate is False
    assert [len(controlled[name]["resources"]) for name in ("local-small", "local-large")] == [
        2,
        5,
    ]
    assert [len(regression[name]["resources"]) for name in ("simple", "complex")] == [1, 4]
    assert {
        resource["url"].split("/", 3)[2]
        for resource in controlled["local-large"]["resources"]
    } == {"qcsd-buflo-server-one:4433", "qcsd-buflo-server-two:4434"}
    assert {
        resource["url"].split("/", 3)[2]
        for resource in regression["complex"]["resources"]
    } == {"qcsd-buflo-server-one:4433"}
    for workload_id in ("local-small", "local-large"):
        proof = buflo_study._validate_controlled_csbuflo_rate_driver(
            workload_id, controlled[workload_id]["resources"]
        )
        assert proof["resource_id"] == (1 if workload_id == "local-small" else 4)
    assert all(
        buflo_study.CSBUFLO_RATE_DRIVER_HEADER_NAME
        not in {header[0] for resource in manifest["resources"] for header in resource["headers"]}
        for manifest in regression.values()
    )


def _regression_prefix_manifest(workload_id: str) -> dict[str, object]:
    resources = [
        buflo_study._local_resource(
            0,
            "https://qcsd-buflo-server-one:4433/131072",
            "Document",
            131_072,
        )
    ]
    if workload_id == "complex":
        resources.extend(
            [
                buflo_study._local_resource(
                    1,
                    "https://qcsd-buflo-server-one:4433/1024",
                    "Script",
                    1_024,
                    depends_on=[0],
                ),
                buflo_study._local_resource(
                    2,
                    "https://qcsd-buflo-server-one:4433/4096",
                    "Script",
                    4_096,
                    depends_on=[0],
                ),
                buflo_study._local_resource(
                    3,
                    "https://qcsd-buflo-server-one:4433/2048",
                    "Image",
                    2_048,
                    depends_on=[2],
                ),
            ]
        )
    return {
        "preparation": {
            "source_url": resources[0]["url"],
            "final_url": resources[0]["url"],
            "approved_origins": [
                "https://qcsd-buflo-server-one:4433",
            ],
            "expected_responses": [
                {
                    "resource_id": resource["id"],
                    "status": 200,
                    "bytes": resource["data_length"],
                    "body_sha256": f"{resource['id'] + 1:x}" * 64,
                }
                for resource in resources
            ],
        },
        "resources": resources,
    }


@pytest.mark.parametrize(
    ("workload_id", "horizon", "survivors", "required_streams"),
    (("simple", 1, 2, 2), ("complex", 3, 4, 4)),
)
def test_regression_prefix_spec_uses_current_full_capacity_schema(
    tmp_path: Path,
    workload_id: str,
    horizon: int,
    survivors: int,
    required_streams: int,
) -> None:
    from qcsd_lab.chaff_qualification import validate_prefix_pack_spec

    manifest = _regression_prefix_manifest(workload_id)
    historical = json.loads(
        (LAB_ROOT / "config/defense-params/walkie-talkie-live.json").read_text(
            encoding="utf-8"
        )
    )
    profile = buflo_study._current_regression_walkie_talkie_profile(
        next(
            profile
            for profile in historical["profiles"]
            if profile["real"] == workload_id
        ),
        historical["packet_size"],
    )
    destination = tmp_path / f"{workload_id}.json"

    buflo_study._write_regression_prefix_spec(
        destination,
        workload_id,
        profile["bursts"],
        application_manifest=manifest,
    )

    value = json.loads(destination.read_text(encoding="utf-8"))
    validated = validate_prefix_pack_spec(
        value,
        workload_id=workload_id,
        application_manifest=manifest,
    )
    assert validated["numeric_profile"]["bursts"] == profile["bursts"]
    assert validated["application_resource_id"] == 0
    assert validated["selected_chaff_resource_id"] == 0
    assert validated["maximum_receiver_continuation_reserve_horizon"] == horizon
    assert validated["required_chaff_survivors"] == survivors
    assert validated["required_chaff_streams"] == required_streams
    assert len(validated["stream_activation_stages"]) == len(profile["bursts"])


def test_regression_prefix_spec_rejects_runtime_mould_drift(tmp_path: Path) -> None:
    manifest = _regression_prefix_manifest("simple")

    with pytest.raises(ValueError, match="differs from runtime mould"):
        buflo_study._write_regression_prefix_spec(
            tmp_path / "simple.json",
            "simple",
            [{"outgoing": 5, "incoming": 129}],
            application_manifest=manifest,
        )


def test_local_regression_prefix_spec_source_policy_is_fail_closed(tmp_path: Path) -> None:
    from qcsd_lab.chaff_qualification import validate_prefix_pack_spec

    manifest = _regression_prefix_manifest("simple")
    historical = json.loads(
        (LAB_ROOT / "config/defense-params/walkie-talkie-live.json").read_text(
            encoding="utf-8"
        )
    )
    profile = buflo_study._current_regression_walkie_talkie_profile(
        next(profile for profile in historical["profiles"] if profile["real"] == "simple"),
        historical["packet_size"],
    )
    destination = tmp_path / "simple.json"
    buflo_study._write_regression_prefix_spec(
        destination,
        "simple",
        profile["bursts"],
        application_manifest=manifest,
    )
    value = json.loads(destination.read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="binding is invalid"):
        validate_prefix_pack_spec(value, workload_id="simple")

    outside = json.loads(json.dumps(value))
    outside["workload_id"] = "outside-local-regression"
    with pytest.raises(ValueError, match="binding is invalid"):
        validate_prefix_pack_spec(
            outside,
            workload_id="outside-local-regression",
            application_manifest=manifest,
        )

    source_tamper = json.loads(json.dumps(value))
    source_tamper["source_walkie_talkie_artifact_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="binding is invalid"):
        validate_prefix_pack_spec(
            source_tamper,
            workload_id="simple",
            application_manifest=manifest,
        )

    numeric_tamper = json.loads(json.dumps(value))
    numeric_tamper["numeric_profile"]["bursts"][0]["outgoing"] += 1
    with pytest.raises(ValueError, match="numeric derivation is invalid"):
        validate_prefix_pack_spec(
            numeric_tamper,
            workload_id="simple",
            application_manifest=manifest,
        )


def test_controlled_and_regression_generators_are_exact_and_unique() -> None:
    controlled = generated_stage_cells("controlled")
    regression = generated_stage_cells("regression")

    assert len(controlled) == 160
    assert len({json.dumps(cell, sort_keys=True) for cell in controlled}) == 160
    assert len(regression) == 18
    assert len({json.dumps(cell, sort_keys=True) for cell in regression}) == 18
    matrix = Counter(
        (cell["workload"], cell["treatment"], cell["netem_profile"]) for cell in controlled
    )
    assert set(matrix.values()) == {5}
    qdiscs = {
        cell["netem_profile"]: (cell["client_qdisc"], cell["server_qdisc"]) for cell in controlled
    }
    assert qdiscs == {
        "clean": ("none", "none"),
        "symmetric-50ms-rtt": ("netem delay 25ms", "netem delay 25ms"),
        "symmetric-5mbit-50ms-rtt-100-packet-queue": (
            "netem delay 25ms rate 5mbit limit 100",
            "netem delay 25ms rate 5mbit limit 100",
        ),
        "symmetric-1pct-loss-50ms-rtt": (
            "netem delay 25ms loss 1%",
            "netem delay 25ms loss 1%",
        ),
    }


def test_ctsp_cpsp_gate_requires_oracle_and_controlled_aggregate() -> None:
    proof = buflo_study._ctsp_cpsp_oracle_proof()
    assert proof["ctsp_greater_than_or_equal_cpsp"] is True
    assert {tuple((row["natural_bytes"], row["cover_bytes"])) for row in proof["anchors"]} == {
        (1_000, 24),
        (1_000, 1_100),
    }
    costs = {
        (profile, workload, visit): {
            "cs-buflo-ctsp": {"wire_bytes": 4_096, "udp_payload_bytes": 4_000},
            "cs-buflo-cpsp": {"wire_bytes": 3_072, "udp_payload_bytes": 3_000},
        }
        for profile in ("clean", "symmetric-50ms-rtt", "symmetric-rate-delay", "symmetric-loss")
        for workload in ("local-small", "local-large")
        for visit in range(5)
    }
    evidence = [f"{index:064x}" for index in range(4)]
    result = buflo_study._validate_ctsp_cpsp_ordering(
        costs,
        evidence_sha256s=evidence,
        explanation_receipt=None,
    )
    assert result["controlled_ctsp_greater_than_or_equal_cpsp"] is True
    assert result["reviewed_explanation"] is None

    changed = {
        key: {
            "cs-buflo-ctsp": {"wire_bytes": 2_000, "udp_payload_bytes": 2_000},
            "cs-buflo-cpsp": {"wire_bytes": 3_000, "udp_payload_bytes": 3_000},
        }
        for key in costs
    }
    with pytest.raises(ValueError, match="without a reviewed explanation"):
        buflo_study._validate_ctsp_cpsp_ordering(
            changed,
            evidence_sha256s=evidence,
            explanation_receipt=None,
        )

    # Preserve tuple keys while making one pair contrary and another pair large
    # enough that the aggregate alone would still pass.
    masked_costs = {
        key: {mode: dict(metrics) for mode, metrics in value.items()}
        for key, value in costs.items()
    }
    first, second = list(masked_costs)[:2]
    masked_costs[first]["cs-buflo-ctsp"] = {
        "wire_bytes": 2_000,
        "udp_payload_bytes": 2_000,
    }
    masked_costs[second]["cs-buflo-ctsp"] = {
        "wire_bytes": 8_192,
        "udp_payload_bytes": 8_000,
    }
    with pytest.raises(ValueError, match="paired result"):
        buflo_study._validate_ctsp_cpsp_ordering(
            masked_costs,
            evidence_sha256s=evidence,
            explanation_receipt=None,
        )


def test_sustained_capacity_gate_requires_all_clean_cells() -> None:
    values = [
        {
            "treatment": treatment,
            "workload": workload,
            "visit": visit,
                "capacity": {
                    "passed": True,
                    "cell_size_bytes": 1_200 if treatment == "buflo" else 600,
                    "minimum_interval_us": (
                        20_000 if treatment == "buflo" else 4_096
                    ),
                    "outgoing_opportunities": 10,
                    "incoming_opportunities": 10,
                    "outgoing_full_cells": 10,
                    "incoming_consumed_bytes": (
                        12_000 if treatment == "buflo" else 6_000
                    ),
                    "incoming_advertised_bytes": (
                        12_000 if treatment == "buflo" else 6_000
                    ),
                    "incoming_terminal_cells": 10,
                    "incoming_consumption_delay_us_max": 1_000,
                    "runner_full_extended_schema_validated": True,
                    "runner_algorithm_evidence_sha256": "a" * 64,
                    "minimum_interval_exercised": True,
                    "exact_target_sizes": True,
                    "no_unresolved_credit": True,
                    **(
                        {
                            f"{direction}_minimum_interval_{field}": 2
                            for direction in ("outgoing", "incoming")
                            for field in ("opportunities", "terminal", "full")
                        }
                        if treatment != "buflo"
                        else {}
                    ),
                    **(
                        {
                            "incoming_minimum_interval_local_realized": 2,
                            "incoming_local_realized_cells": 10,
                            "request_rate_driver_resource_id": (
                                1 if workload == "local-small" else 4
                            ),
                            "request_rate_driver_request_stream_bytes": (
                                buflo_study.CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES
                            ),
                            "request_rate_driver_boundary_bytes": (
                                buflo_study.CSBUFLO_RATE_DRIVER_BOUNDARY_BYTES
                            ),
                            "request_rate_driver_post_boundary_cells": (
                                buflo_study.CSBUFLO_RATE_DRIVER_POST_BOUNDARY_CELLS
                            ),
                        }
                        if treatment != "buflo"
                        else {}
                    ),
                },
        }
        for treatment in ("buflo", "cs-buflo-ctsp", "cs-buflo-cpsp")
        for workload in ("local-small", "local-large")
        for visit in range(5)
    ]
    proof = buflo_study._validate_sustained_cell_capacity(values)
    assert proof["samples"] == 30
    assert proof["profiles"]["buflo"]["cell_size_bytes"] == 1_200
    assert proof["profiles"]["cs-buflo-ctsp"]["minimum_interval_us"] == 4_096
    for index, key, changed in (
        (0, "passed", False),
        (10, "incoming_minimum_interval_local_realized", 1),
        (20, "incoming_local_realized_cells", 9),
        (10, "incoming_advertised_bytes", 5_999),
        (10, "incoming_terminal_cells", 9),
        (10, "runner_full_extended_schema_validated", False),
        (10, "request_rate_driver_request_stream_bytes", 16_384),
        (10, "request_rate_driver_post_boundary_cells", 3),
    ):
        original = values[index]["capacity"][key]
        values[index]["capacity"][key] = changed
        with pytest.raises(ValueError, match="does not sustain"):
            buflo_study._validate_sustained_cell_capacity(values)
        values[index]["capacity"][key] = original


def test_controlled_endpoint_gate_names_all_new_mode_two_origin_cells() -> None:
    endpoints = [
        {"id": 0, "origin": "https://qcsd-buflo-server-one:4433/"},
        {"id": 1, "origin": "https://qcsd-buflo-server-two:4434/"},
    ]
    coverage = buflo_study._controlled_endpoint_coverage(
        endpoints,
        workload="local-large",
    )
    assert coverage["observed_endpoint_count"] == 2
    assert coverage["passed"] is True

    values = [
        {
            "treatment": cell["treatment"],
            "workload": cell["workload"],
            "visit": cell["visit"],
            "netem_profile": cell["netem_profile"],
            "endpoint_coverage": coverage,
        }
        for cell in generated_stage_cells("controlled")
        if cell["workload"] == "local-large"
        and cell["treatment"] in {"buflo", "cs-buflo-ctsp", "cs-buflo-cpsp"}
    ]
    proof = buflo_study._validate_controlled_multi_endpoint_coverage(values)
    assert proof["samples"] == 60
    assert proof["treatments"] == {
        "buflo": 20,
        "cs-buflo-ctsp": 20,
        "cs-buflo-cpsp": 20,
    }
    assert proof["passed"] is True

    with pytest.raises(ValueError, match="all 60 cells"):
        buflo_study._validate_controlled_multi_endpoint_coverage(values[:-1])
    with pytest.raises(ValueError, match="exact expected endpoint set"):
        buflo_study._controlled_endpoint_coverage(
            [endpoints[0], {"id": 1, "origin": endpoints[0]["origin"]}],
            workload="local-large",
        )


@pytest.mark.parametrize("stage", ("controlled", "regression"))
def test_standard_campaign_receipt_maps_every_local_stage_cell_exactly(stage: str) -> None:
    plan = load_study_plan()
    treatments = (
        tuple(plan["controlled"]["treatments"])
        if stage == "controlled"
        else tuple(plan["regression"]["treatments"])
    )
    workload_aliases = (
        {"local-large": "local-large", "local-small": "local-small"}
        if stage == "controlled"
        else {"complex": "local-large", "simple": "local-small"}
    )
    actual_ids = tuple(workload_aliases)
    aliases_by_target = {target: source for source, target in workload_aliases.items()}
    cells = generated_stage_cells(stage)
    profile_ranks = (
        {profile["id"]: rank for rank, profile in enumerate(plan["controlled"]["netem_profiles"])}
        if stage == "controlled"
        else {"clean": 0}
    )

    for profile, rank in profile_ranks.items():
        selected = [cell for cell in cells if cell["netem_profile"] == profile]
        campaign = SimpleNamespace(
            workloads=tuple(SimpleNamespace(id=value) for value in actual_ids),
            study_controlled={
                "stage": stage,
                "treatment_order": treatments,
                "workload_aliases": workload_aliases,
                "netem_rank": rank,
                "netem_profile": profile,
                "client_qdisc": selected[0]["client_qdisc"],
                "server_qdisc": selected[0]["server_qdisc"],
            },
        )
        observed = {
            json.dumps(
                orchestrator._controlled_study_cell(
                    campaign,
                    {
                        "workload_id": aliases_by_target[cell["workload"]],
                        "visit": cell["visit"],
                        "defense": cell["treatment"],
                    },
                ),
                sort_keys=True,
            )
            for cell in selected
        }
        expected = {
            json.dumps(
                {key: value for key, value in cell.items() if key != "sample_index"},
                sort_keys=True,
            )
            for cell in selected
        }
        assert observed == expected


def test_public_campaigns_are_exact_and_formal_is_latin_balanced() -> None:
    all_campaigns = validate_campaign_matrix()
    formal = validate_campaign_matrix("formal")

    assert all_campaigns["samples"] == 1_560
    assert formal["samples"] == 1_500
    assert len(formal["campaigns"]) == 10
    assert formal["formal_position_counts"]
    assert all(
        max(counts) - min(counts) <= 1 for counts in formal["formal_position_counts"].values()
    )


def test_cohort_v2_resolves_create_only_campaign_without_mutating_v1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = LAB_ROOT / "config/campaigns/buflo-study-v1-smoke.yml"
    original = source.read_bytes()
    monkeypatch.setattr(buflo_study, "COHORT_INPUT_ROOT", tmp_path / "cohort-inputs")

    resolved = buflo_study.campaign_paths(
        "smoke",
        cohort_version=2,
        create_resolved=True,
    )[0]
    document = buflo_study.yaml.safe_load(resolved.read_text(encoding="utf-8"))

    assert resolved == tmp_path / "cohort-inputs/v2/campaigns" / source.name
    assert document["chaff_qualification_set"] == "buflo-study-public5-v2"
    assert source.read_bytes() == original
    assert resolved.read_bytes() == buflo_study._rendered_campaign_bytes(
        source,
        cohort_version=2,
    )
    resolved.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ValueError, match="deterministic source"):
        buflo_study.campaign_paths("smoke", cohort_version=2)


def test_pre_formal_snapshot_binds_selected_cohort_campaigns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(buflo_study, "COHORT_INPUT_ROOT", tmp_path / "cohort-inputs")
    monkeypatch.setattr(
        buflo_study,
        "source_metadata",
        lambda: {"source": "test", "image_digest": "sha256:" + "a" * 64},
    )
    monkeypatch.setattr(buflo_study, "_validate_clean_source", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        buflo_study,
        "validate_historical_corpus_guard",
        lambda *args, **kwargs: {"passed": True},
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_build_execution_receipt",
        lambda *args, **kwargs: {
            "path": str(tmp_path / "build-execution-v2.json"),
            "sha256": "a" * 64,
        },
    )

    snapshot = buflo_study._historical_snapshot_value(
        phase="pre-formal",
        cohort_version=2,
        create_resolved_campaigns=True,
    )

    assert snapshot["cohort_version"] == 2
    assert snapshot["qualification_set"] == "buflo-study-public5-v2"
    assert len(snapshot["formal_campaigns"]) == 10
    assert all("/cohort-inputs/v2/campaigns/" in row["path"] for row in snapshot["formal_campaigns"])


def test_live_parameters_bind_scope_modes_sampling_and_guard() -> None:
    assert len(validate_parameters()) == 3
    buflo = json.loads((LAB_ROOT / "config/defense-params/buflo-live.json").read_text())
    ctsp = json.loads((LAB_ROOT / "config/defense-params/cs-buflo-ctsp-live.json").read_text())
    cpsp = json.loads((LAB_ROOT / "config/defense-params/cs-buflo-cpsp-live.json").read_text())
    assert buflo == {
        "schema_version": 1,
        "interval_us": 20_000,
        "minimum_duration_us": 10_000_000,
        "packet_size": 1_200,
        "max_events": 6_000,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
    }
    assert buflo["interval_us"] * buflo["max_events"] == 120_000_000
    common = {
        "incoming_padding_mode": "payload",
        "timing_sample_limit": 1_000,
        "jitter_denominator": 100,
        "jitter_max_numerator": 200,
        "early_termination": "local",
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
    }
    assert {key: ctsp[key] for key in common} == common
    assert {key: cpsp[key] for key in common} == common
    assert ctsp["outgoing_padding_mode"] == "total"
    assert cpsp["outgoing_padding_mode"] == "payload"


def test_reference_action_cannot_bypass_isolated_create_only_gate(tmp_path: Path) -> None:
    result = run_study_action(
        "reference",
        reference_root=tmp_path,
        destination=tmp_path / "receipt.json",
    )

    assert result.status == "blocked"
    assert any("network-isolated reference image" in blocker for blocker in result.blockers)
    assert not (tmp_path / "receipt.json").exists()


def test_executed_reference_receipt_semantically_binds_all_oracles_and_sources(
    tmp_path: Path,
) -> None:
    execution = _reference_execution_fixture(tmp_path)
    receipt = validate_reference_gate_receipt(execution)

    assert receipt["profiles_checked"] == 8
    assert receipt["archive"] == {
        "total_records": 4_000,
        "included_records": 3_824,
        "zero_baseline_records": 176,
        "defended_bytes": 7_592_598_380,
        "baseline_bytes": 3_326_013_453,
        "excluded_defended_bytes": 18_656_832,
    }
    assert receipt["sha256"] == hashlib.sha256(execution.read_bytes()).hexdigest()
    assert "dyer-paper-pdf" in receipt["external_sources"]
    assert "csbuflo-preprint-pdf" in receipt["external_sources"]


def test_executed_reference_receipt_rejects_self_declared_source_substitution(
    tmp_path: Path,
) -> None:
    canonical = (
        LAB_ROOT / "config/reference/buflo-csbuflo/buflo-csbuflo-conformance-v1.receipt.json"
    )
    value = json.loads(canonical.read_text(encoding="utf-8"))
    by_id = {source["source_id"]: source for source in value["external_sources"]}
    assert by_id["csbuflo-clientloop-c"]["sha256"] == (
        "6f0148c8891756e39980edf47f2d5fbc254d2da7b4a8096a678cf3bb7777a36e"
    )
    assert by_id["csbuflo-serverloop-c"]["sha256"] == (
        "abc798cecb918d5c89ccec825224d543862e95a9650334bb0b5d4dd99e17a3a9"
    )
    by_id["csbuflo-clientloop-c"]["sha256"] = "0" * 64
    substituted = tmp_path / "substituted-reference-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="immutable checked-in oracle"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    value = json.loads(canonical.read_text(encoding="utf-8"))
    by_id = {source["source_id"]: source for source in value["external_sources"]}
    by_id["csbuflo-serverloop-c"]["url"] = by_id["csbuflo-serverloop-c"]["url"].replace(
        "serverloop.c", "clientloop.c"
    )
    substituted = tmp_path / "substituted-reference-url-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="immutable checked-in oracle"):
        buflo_study._validate_canonical_reference_receipt(substituted)


def test_executed_reference_receipt_recomputes_slice_aggregate_and_golden_vectors(
    tmp_path: Path,
) -> None:
    canonical = buflo_study.CONFORMANCE_RECEIPT
    value = json.loads(canonical.read_text(encoding="utf-8"))
    slices = value["csbuflo_author_conformance"]["source_extraction"]["segment_sha256"]
    slices["jitter_function"] = "0" * 64
    substituted = tmp_path / "substituted-slice-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="source-slice inventory"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    value = json.loads(canonical.read_text(encoding="utf-8"))
    value["csbuflo_author_conformance"]["source_extraction_input_sha256"] = "0" * 64
    substituted = tmp_path / "substituted-slice-aggregate-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="source-slice aggregate"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    value = json.loads(canonical.read_text(encoding="utf-8"))
    value["csbuflo_author_conformance"]["golden_vectors"]["jitter"]["raw_1"] = 82
    substituted = tmp_path / "substituted-golden-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="author harness"):
        buflo_study._validate_canonical_reference_receipt(substituted)


def test_executed_reference_receipt_binds_rate_quantization_discrepancy(
    tmp_path: Path,
) -> None:
    canonical = buflo_study.CONFORMANCE_RECEIPT
    value = json.loads(canonical.read_text(encoding="utf-8"))
    discrepancy = value["csbuflo_paper_internal_discrepancies"][0]
    discrepancy["paper_prose_rule"] = "round-down-rho-to-a-power-of-two"
    substituted = tmp_path / "substituted-rate-discrepancy-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="paper-internal discrepancy"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    value = json.loads(canonical.read_text(encoding="utf-8"))
    value["csbuflo_estimator_contract"]["rate_quantization_resolution"] = (
        "paper-prose-round-up"
    )
    substituted = tmp_path / "substituted-rate-resolution-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="estimator contract"):
        buflo_study._validate_canonical_reference_receipt(substituted)


def test_executed_reference_receipt_recomputes_archive_ratio_and_byte_hash(
    tmp_path: Path,
) -> None:
    canonical = buflo_study.CONFORMANCE_RECEIPT
    value = json.loads(canonical.read_text(encoding="utf-8"))
    value["csbuflo_archive_conformance"]["bandwidth_ratio"] = 2.28279
    substituted = tmp_path / "substituted-archive-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="archive conformance"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    whitespace_changed = tmp_path / "whitespace-changed-receipt.json"
    whitespace_changed.write_text(canonical.read_text(encoding="utf-8") + " ", encoding="utf-8")
    assert json.loads(whitespace_changed.read_text(encoding="utf-8")) == json.loads(
        canonical.read_text(encoding="utf-8")
    )
    assert hashlib.sha256(whitespace_changed.read_bytes()).hexdigest() != (
        buflo_study.CONFORMANCE_RECEIPT_SHA256
    )
    with pytest.raises(ValueError, match="receipt SHA-256"):
        buflo_study._validate_canonical_reference_receipt(whitespace_changed)


def test_reference_execution_rejects_static_or_copied_canonical_receipt(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="execution receipt identity"):
        validate_reference_gate_receipt(buflo_study.CONFORMANCE_RECEIPT)
    copied = tmp_path / "copied-canonical.json"
    copied.write_bytes(buflo_study.CONFORMANCE_RECEIPT.read_bytes())
    with pytest.raises(ValueError, match="execution receipt identity"):
        validate_reference_gate_receipt(copied)


def test_reference_execution_receipt_rejects_tamper(tmp_path: Path) -> None:
    execution = _reference_execution_fixture(tmp_path)
    value = json.loads(execution.read_text(encoding="utf-8"))
    value["isolation"]["docker_network_mode"] = "bridge"
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)
    execution.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="isolation evidence"):
        validate_reference_gate_receipt(execution)


def test_staged_capture_rejects_missing_exact_prior_cohorts() -> None:
    with pytest.raises(ValueError, match="exact prerequisite set"):
        validate_staged_capture_prerequisites("formal", ())


def test_formal_capacity_requires_12_5_hours_and_threefold_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged = {
        "public": {
            "smoke": {
                "samples": 20,
                "authoritative_bytes": 20_000,
                "elapsed_seconds": 600,
            },
            "rehearsal": {
                "samples": 40,
                "authoritative_bytes": 40_000,
                "elapsed_seconds": 1_200,
            },
        }
    }
    monkeypatch.setattr(
        buflo_study.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=4_500_000),
    )

    capacity = validate_formal_capture_capacity(
        staged,
        available_window_hours=12.5,
        results_root=tmp_path,
    )

    assert capacity["minimum_sequential_cooldown_seconds"] == 45_000
    assert capacity["measured_projection_seconds"] == 45_000
    assert capacity["expected_formal_wall_seconds"] == 45_000
    assert capacity["projected_formal_bytes"] == 1_500_000
    assert capacity["required_free_bytes"] == 4_500_000
    with pytest.raises(ValueError, match="at least 12.5"):
        validate_formal_capture_capacity(
            staged,
            available_window_hours=12.49,
            results_root=tmp_path,
        )


def test_first_formal_block_uses_frozen_projected_storage_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = tmp_path / "buflo-study-v1-formal-01.yml"
    campaign.write_text("name: buflo-study-v1-formal-01\n", encoding="utf-8")
    result_root = tmp_path / "results" / "buflo-study-v1-formal-01"
    admission_value = {
        "stage": "formal",
        "results_root": str(tmp_path / "results"),
        "allowed_campaigns": [
            {
                "campaign_path": str(campaign.resolve()),
                "campaign_sha256": buflo_study.sha256_file(campaign),
                "result_root": str(result_root),
            }
        ],
        "formal_capacity": {"projected_formal_bytes": 1_000_000},
    }
    monkeypatch.setattr(
        buflo_study,
        "validate_capture_admission",
        lambda _admission: admission_value,
    )
    disk_probes: list[Path] = []
    monkeypatch.setattr(
        buflo_study.shutil,
        "disk_usage",
        lambda path: (disk_probes.append(Path(path)), SimpleNamespace(free=3_000_000))[1],
    )

    assert (
        buflo_study.admitted_result_root(
            tmp_path / "admission.json", campaign, require_sequence=True
        )
        == result_root
    )
    assert disk_probes == [tmp_path / "results"]


def test_capture_admission_rejects_cohort_mismatch_before_replay(tmp_path: Path) -> None:
    admission = tmp_path / "capture-admission.json"
    admission.write_text(json.dumps({"cohort_version": 2}), encoding="utf-8")

    with pytest.raises(ValueError, match="cohort version does not match"):
        buflo_study.validate_capture_admission(
            admission,
            expected_cohort_version=1,
        )


def test_formal_prelaunch_estimate_is_visible_only_on_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    buflo_study._report_frozen_formal_prelaunch(
        {
            "expected_formal_wall_hours": 12.5,
            "conservative_upper_seconds": 50_400,
            "projected_formal_bytes": 1_500_000,
            "required_free_bytes": 4_500_000,
        }
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "expected=12.500h" in captured.err
    assert "3x_required=4500000 bytes" in captured.err


def test_attestation_destination_cannot_overlap_result_inputs(tmp_path: Path) -> None:
    result_root = tmp_path / "formal-result"
    result_root.mkdir()
    with pytest.raises(ValueError, match="overlaps protected input"):
        buflo_study.create_validation_attestation(
            result_root / "attestation.json",
            formal_result_roots=(result_root,),
        )


def test_qualification_rejects_sidecar_from_non_prepare_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from qcsd_lab import chaff_qualification

    qualification_root = tmp_path / "sets"
    selected = qualification_root / "buflo-study-public5-v2"
    selected.mkdir(parents=True)
    for workload in buflo_study.WORKLOADS:
        (selected / f"{workload}.json").write_text(
            json.dumps({"qualification_image_digest": "sha256:" + "e" * 64}),
            encoding="utf-8",
        )
    monkeypatch.setattr(buflo_study, "QUALIFICATION_SET_ROOT", qualification_root)
    monkeypatch.setattr(
        buflo_study,
        "_qualification_build_binding",
        lambda *_args: (
            {"path": "build.json", "sha256": "f" * 64},
            "sha256:" + "d" * 64,
        ),
    )
    monkeypatch.setattr(chaff_qualification, "load_response_qualified_chaff", lambda *a, **k: None)

    ready, status = buflo_study.qualification_status(
        require_controlled=False,
        cohort_version=2,
    )
    assert ready is False
    assert "exact no-cache prepare image" in status


def test_launcher_requires_clean_capture_image_and_no_cache_build() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")

    assert 'verify_qualification_checkout "buflo-study capture"' in launcher
    assert 'verify_qualification_checkout "buflo study campaign run"' in launcher
    direct_run_guard = launcher.split('verify_qualification_checkout "buflo-study capture"', 1)[
        1
    ].split('verify_qualification_checkout "buflo-study qualify"', 1)[0]
    assert '"${1:-}" == "run"' in direct_run_guard
    assert "buflo-study-v1-(smoke|rehearsal|formal-[0-9]{2})" in direct_run_guard
    assert '"${1:-}" == "resume"' not in direct_run_guard
    assert launcher.count("docker build --pull --no-cache --target") == 3
    assert "artifacts/buflo-study/build-execution-v${study_cohort_version}.json" in launcher
    assert '"artifact_type": "qcsd-buflo-study-no-cache-build-execution"' in launcher
    assert '"build_execution": {' in launcher


def test_launcher_applies_least_privilege_rr1_capture_partition() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")
    entrypoint = (LAB_ROOT / "docker/collection-entrypoint").read_text(
        encoding="utf-8"
    )

    assert 'study_capture_scheduler_contract="qcsd-client-rr1-cpu10-v1"' in launcher
    assert 'runtime+=(--cpuset-cpus "10-11" --ulimit "rtprio=1:1")' in launcher
    assert "--cpuset-cpus 10-11" in launcher
    assert "--ulimit rtprio=1:1" in launcher
    assert launcher.count("--cpuset-cpus 0-9") == 2
    assert "SYS_NICE" not in launcher
    assert "--cpu-rt-runtime" not in launcher
    assert "unsupported capture scheduler contract" in entrypoint
    assert "taskset --cpu-list 11 qcsd-lab-internal" in entrypoint
    assert "+sys_nice" not in entrypoint


def test_versioned_build_receipts_coexist_and_reject_path_or_request_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = {
        version: tmp_path / f"build-execution-v{version}.json"
        for version in (1, 2)
    }
    monkeypatch.setattr(
        buflo_study,
        "build_execution_receipt_path",
        lambda cohort_version=1: paths[cohort_version],
    )
    for version, path in paths.items():
        path.write_text(
            json.dumps(
                _build_execution_value(cohort_version=version),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    v1_sha256 = buflo_study.sha256_file(paths[1])

    assert buflo_study.validate_build_execution_receipt(
        paths[1], expected_cohort_version=1
    )["cohort_version"] == 1
    assert buflo_study.validate_build_execution_receipt(
        paths[2], expected_cohort_version=2
    )["cohort_version"] == 2
    assert buflo_study.sha256_file(paths[1]) == v1_sha256
    with pytest.raises(ValueError, match="cohort version differs from the request"):
        buflo_study.validate_build_execution_receipt(
            paths[1], expected_cohort_version=2
        )

    copied = tmp_path / "copied-v1-as-v2.json"
    copied.write_bytes(paths[1].read_bytes())
    with pytest.raises(ValueError, match="path does not match its cohort version"):
        buflo_study.validate_build_execution_receipt(copied)


def test_all_public_v2_campaign_matrices_render_and_validate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(buflo_study, "COHORT_INPUT_ROOT", tmp_path / "cohort-inputs")

    assert buflo_study.validate_campaign_matrix("smoke", cohort_version=2)["samples"] == 20
    assert (
        buflo_study.validate_campaign_matrix("rehearsal", cohort_version=2)["samples"]
        == 40
    )
    assert buflo_study.validate_campaign_matrix("formal", cohort_version=2)["samples"] == 1_500


def test_versioned_public5_outputs_are_narrowly_ignored() -> None:
    versioned = (
        "config/chaff-response-qualification-store/sets/"
        "buflo-study-public5-v2/receipt.json"
    )
    unrelated = (
        "config/chaff-response-qualification-store/sets/"
        "unrelated-public5-v2/receipt.json"
    )
    ignored = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", versioned],
        cwd=LAB_ROOT,
        check=False,
    )
    visible = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", unrelated],
        cwd=LAB_ROOT,
        check=False,
    )
    dockerignore = (LAB_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

    assert ignored.returncode == 0
    assert visible.returncode == 1
    assert (
        "config/chaff-response-qualification-store/sets/buflo-study-public5-v*/"
        in dockerignore
    )
    assert "config/chaff-response-qualification-store/sets/*" not in dockerignore


def test_launcher_selects_exact_versioned_build_images_and_frozen_resume_admission() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")

    assert 'BUILD_COHORT_VERSION="${build_cohort_version}"' in launcher
    assert '"cohort_version": int(os.environ["BUILD_COHORT_VERSION"])' in launcher
    assert 'COLLECTION_IMAGE="${study_build_fields[1]}"' in launcher
    assert 'PREPARE_IMAGE="${study_build_fields[2]}"' in launcher
    assert 'REFERENCE_IMAGE="${study_build_fields[3]}"' in launcher
    assert 'QCSD_LAB_PREPARE_IMAGE="${PREPARE_IMAGE}"' in launcher
    assert 'study_capture_admission_host="${study_resume_root}/inputs/capture-admission.json"' in launcher
    assert "read_capture_admission_binding \"${study_capture_admission_host}\"" in launcher
    assert (
        '--volume "${reference_cohort_inputs}:'
        '/lab/artifacts/buflo-study/cohort-inputs:rw"' in launcher
    )


def test_launcher_build_v2_is_create_only_and_preserves_v1(tmp_path: Path) -> None:
    launcher = tmp_path / "qcsd-lab"
    launcher.write_bytes((LAB_ROOT / "qcsd-lab").read_bytes())
    launcher.chmod(0o755)
    (tmp_path / "neqo-qcsd").mkdir()
    (tmp_path / "neqo-qcsd/Cargo.lock").write_text("lock\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    binary_root = tmp_path / "bin"
    binary_root.mkdir()
    docker = binary_root / "docker"
    docker.write_text(
        """#!/bin/sh
set -eu
command="$1"
shift
case "$command" in
  info|build) exit 0 ;;
  version)
    printf '%s\n' '{"Client":{"Version":"29.0.1"},"Server":{"Version":"29.0.1"}}'
    ;;
  image)
    shift
    format=""
    last=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--format" ]; then format="$2"; shift 2; continue; fi
      last="$1"; shift
    done
    case "$format" in
      '{{.Id}}')
        case "$last" in
          *collection*) printf 'sha256:%064d\n' 1 ;;
          *prepare*) printf 'sha256:%064d\n' 2 ;;
          *reference*) printf 'sha256:%064d\n' 3 ;;
          *) printf '%s\n' "$last" ;;
        esac
        ;;
      '{{json .RepoDigests}}') printf '%s\n' '[]' ;;
      *) exit 0 ;;
    esac
    ;;
  run)
    case "$*" in
      */source.json)
        printf '%s\n' '{"lab_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","lab_dirty":false,"lab_patch_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","neqo_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","neqo_pinned_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","neqo_dirty":false,"neqo_patch_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}'
        ;;
      */study-build-inputs.json) printf '%s\n' '{}' ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 1 ;;
esac
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    environment = dict(os.environ)
    environment["PATH"] = f"{binary_root}:{environment['PATH']}"

    first = subprocess.run(
        [str(launcher), "build"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert first.returncode == 0, first.stderr
    v1 = tmp_path / "artifacts/buflo-study/build-execution-v1.json"
    v1_sha256 = hashlib.sha256(v1.read_bytes()).hexdigest()
    second = subprocess.run(
        [str(launcher), "build", "--cohort-version", "2"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert second.returncode == 0, second.stderr
    v2 = tmp_path / "artifacts/buflo-study/build-execution-v2.json"
    assert json.loads(v1.read_text(encoding="utf-8"))["cohort_version"] == 1
    assert json.loads(v2.read_text(encoding="utf-8"))["cohort_version"] == 2
    assert hashlib.sha256(v1.read_bytes()).hexdigest() == v1_sha256

    duplicate = subprocess.run(
        [str(launcher), "build", "--cohort-version=2"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert duplicate.returncode == 1
    assert "absent create-only receipt" in duplicate.stderr


def test_build_execution_receipt_rejects_semantically_rehashed_cache_enabled_command() -> None:
    value = json.loads(json.dumps(_build_execution_value()))
    value["commands"][0]["argv"].remove("--no-cache")
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)

    with pytest.raises(ValueError, match="--pull --no-cache"):
        buflo_study._validate_build_execution_value(value)


def test_build_execution_receipt_accepts_consistent_host_paths_from_container() -> None:
    value = json.loads(json.dumps(_build_execution_value()))
    for command in value["commands"]:
        command["argv"][-2] = "/host-checkout/neqo-qcsd-lab/Dockerfile"
        command["argv"][-1] = "/host-checkout/neqo-qcsd-lab"
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)

    assert buflo_study._validate_build_execution_value(value)["cohort_version"] == 1

    value["commands"][0]["argv"][-1] = "/different-build-context"
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)
    with pytest.raises(ValueError, match="--pull --no-cache"):
        buflo_study._validate_build_execution_value(value)

    value = json.loads(json.dumps(_build_execution_value()))
    value["commands"][1]["argv"][-2] = "/other-host-checkout/Dockerfile"
    value["commands"][1]["argv"][-1] = "/other-host-checkout"
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)
    with pytest.raises(ValueError, match="--pull --no-cache"):
        buflo_study._validate_build_execution_value(value)


@pytest.mark.parametrize(
    ("dockerfile", "build_root"),
    [
        ("/Dockerfile", "/"),
        ("//host/repo/Dockerfile", "//host/repo"),
        ("/host/a/../repo/Dockerfile", "/host/a/../repo"),
        ("relative/repo/Dockerfile", "relative/repo"),
    ],
)
def test_build_execution_receipt_rejects_noncanonical_or_unsafe_build_roots(
    dockerfile: str, build_root: str
) -> None:
    value = json.loads(json.dumps(_build_execution_value()))
    for command in value["commands"]:
        command["argv"][-2] = dockerfile
        command["argv"][-1] = build_root
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)

    with pytest.raises(ValueError, match="--pull --no-cache"):
        buflo_study._validate_build_execution_value(value)


@pytest.mark.parametrize(
    "name",
    [
        "buflo-study-v1-public-smoke-1200",
        "buflo-study-v1-public-rehearsal-1200",
        "buflo-study-v1-formal-01-1200",
        "buflo-study-v1-formal-10-1200",
    ],
)
def test_public_campaign_identity_cannot_bypass_capture_admission(name: str) -> None:
    assert orchestrator._public_buflo_campaign(name)


@pytest.mark.parametrize(
    "name",
    [
        "buflo-study-v1-smoke",
        "buflo-study-v1-formal-01",
        "buflo-study-v1-formal-1-1200",
        "buflo-study-v1-controlled-00-1200",
        "other-buflo-study-v1-public-smoke-1200",
    ],
)
def test_public_campaign_identity_rejects_near_miss_names(name: str) -> None:
    assert not orchestrator._public_buflo_campaign(name)


def test_public_campaign_run_requires_typed_admission_before_creating_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("QCSD_BUFLO_CAPTURE_ADMISSION", raising=False)
    campaign = SimpleNamespace(
        name="buflo-study-v1-public-smoke-1200",
        purpose="smoke",
    )

    with pytest.raises(ValueError, match="typed capture admission"):
        orchestrator._run_loaded_campaign(campaign, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_launcher_qualification_is_restartable_build_then_semantic_verify() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")

    assert "requires controlled roots and exactly one --destination" in launcher
    assert 'if [[ ! -e "${qualification_target}" ]]' in launcher
    assert "existing public5 evidence must be a non-symlink directory" in launcher
    assert '"${ROOT}/qcsd-lab" qualify-response-chaff' in launcher
    assert '--env "QCSD_BUFLO_QUALIFY_CONTROLLED_ONLY=1"' in launcher
    assert "QCSD_BUFLO_QUALIFY_VERIFY_ONLY=1" in launcher
    assert '--env "QCSD_BUFLO_QUALIFY_VERIFY_ONLY=1"' in launcher
    assert 'verify_qualification_checkout "buflo-study qualify"' in launcher
    assert 'qualification_set="buflo-study-public5-v${qualification_cohort_version}"' in launcher
    assert '--volume "${ROOT}/handoffs:/lab/handoffs:ro"' in launcher


def test_launcher_rejects_duplicate_qualification_cohort_version(tmp_path: Path) -> None:
    binary_root = tmp_path / "bin"
    binary_root.mkdir()
    docker = binary_root / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)
    environment = dict(os.environ)
    environment["PATH"] = f"{binary_root}:{environment['PATH']}"

    completed = subprocess.run(
        [
            "/bin/bash",
            str(LAB_ROOT / "qcsd-lab"),
            "buflo-study",
            "qualify",
            "--controlled-result",
            str(tmp_path / "controlled"),
            "--destination",
            str(tmp_path / "receipt.json"),
            "--cohort-version",
            "2",
            "--cohort-version",
            "3",
        ],
        cwd=LAB_ROOT,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 2
    assert "at most one --cohort-version" in completed.stderr


def test_study_environment_receipt_binds_minimized_docker_bases_and_locks() -> None:
    build_execution = _build_execution_value()
    value = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-environment",
        "docker": {
            "client_version": "29.0.1",
            "server_version": "29.0.1",
            "server_os": "linux",
            "server_arch": "arm64",
            "ncpu": 8,
            "mem_total_bytes": 16_000_000_000,
            "storage_driver": "overlayfs",
        },
        "collection_image": {
            "id": "sha256:" + "a" * 64,
            "repo_digests": ["collection@example.invalid@sha256:" + "b" * 64],
        },
        "build_inputs": {
            "schema_version": 1,
            "artifact_type": "qcsd-study-build-inputs",
            "rust_base_image": RUST_BASE_IMAGE,
            "debian_base_image": DEBIAN_BASE_IMAGE,
            "uv_lock_sha256": buflo_study.sha256_file(LAB_ROOT / "uv.lock"),
            "cargo_lock_sha256": buflo_study.sha256_file(LAB_ROOT / "neqo-qcsd/Cargo.lock"),
        },
        "build_execution": {
            "sha256": hashlib.sha256(
                (json.dumps(build_execution, indent=2, sort_keys=True) + "\n").encode()
            ).hexdigest(),
            "receipt": build_execution,
        },
        "clock_status": {
            "relationship": "container-shares-host-kernel-realtime-clock",
            "host": {
                "source": "timedatectl-NTPSynchronized-and-python-clock-gettime",
                "synchronized": True,
                "status_evidence": "NTPSynchronized=yes",
                "unavailable_reason": None,
                "realtime_unix_ns": 1_000_000_000_000,
                "monotonic_ns": 10_000,
            },
            "container": {
                "source": "python-clock-gettime-inside-collection-image",
                "synchronized": None,
                "status_evidence": None,
                "unavailable_reason": (
                    "container shares the host kernel clock and has no independent NTP service"
                ),
                "realtime_unix_ns": 1_000_000_000_001,
                "monotonic_ns": 20_000,
            },
        },
    }

    assert (
        validate_study_environment_receipt(value, expected_image_digest="sha256:" + "a" * 64)[
            "image_id"
        ]
        == "sha256:" + "a" * 64
    )
    scheduled = json.loads(json.dumps(value))
    scheduled["schema_version"] = 2
    scheduled["docker"]["ncpu"] = 12
    scheduled["capture_scheduler"] = (
        buflo_study._capture_scheduler_environment_contract()
    )
    validated = validate_study_environment_receipt(
        scheduled, expected_image_digest="sha256:" + "a" * 64
    )
    assert validated["capture_scheduler"]["client_affinity_cpus"] == [10]
    wrong_topology = json.loads(json.dumps(scheduled))
    wrong_topology["docker"]["ncpu"] = 16
    with pytest.raises(ValueError, match="exact 12-CPU topology"):
        validate_study_environment_receipt(wrong_topology)
    wrong_partition = json.loads(json.dumps(scheduled))
    wrong_partition["capture_scheduler"]["client_affinity_cpus"] = [9]
    with pytest.raises(ValueError, match="scheduler environment"):
        validate_study_environment_receipt(wrong_partition)
    changed = json.loads(json.dumps(value))
    changed["build_inputs"]["uv_lock_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="base image or lockfile"):
        validate_study_environment_receipt(changed)


def test_public_study_network_receipt_proves_bridge_has_no_netem(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QCSD_STUDY_NETWORK_CONDITION", "public-docker-bridge-no-netem")
    monkeypatch.setattr(
        capture_session,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout='[{"kind":"noqueue","root":true}]',
        ),
    )
    receipt = capture_session._public_study_network_condition("eth0", {"verified": True})

    assert receipt is not None and receipt["valid"] is True
    diagnostics = {
        "network_condition": receipt,
        "offloads": [{"interface": "eth0", "verified": True}],
    }
    buflo_study._validate_public_network_condition(diagnostics)

    changed = json.loads(json.dumps(receipt))
    changed["observed_qdisc"] = [{"kind": "netem", "root": True}]
    changed["netem_present"] = True
    changed["valid"] = False
    with pytest.raises(ValueError, match="no-netem"):
        buflo_study._validate_public_network_condition(
            {**diagnostics, "network_condition": changed}
        )


def test_redirect_attestation_explicitly_binds_empty_prepared_and_final_sequences(
    tmp_path: Path,
) -> None:
    workload_id = "getbootstrap-home-r4"
    data = json.loads(
        (LAB_ROOT / f"config/workloads/{workload_id}.json").read_text(encoding="utf-8")
    )
    expected = {row["resource_id"]: row for row in data["preparation"]["expected_responses"]}
    responses = []
    for resource in data["resources"]:
        identity = expected[resource["id"]]
        responses.append(
            {
                "resource_id": resource["id"],
                "url": resource["url"],
                "status": identity["status"],
                "complete": True,
                "outcome": "succeeded",
            }
        )
    neqo = tmp_path / "neqo"
    neqo.mkdir()
    (neqo / "run.json").write_text(json.dumps({"responses": responses}), encoding="utf-8")

    receipt = orchestrator._redirect_attestation(
        SimpleNamespace(id=workload_id, data=data),
        tmp_path,
    )

    assert receipt["all_redirect_sequences_empty"] is True
    assert receipt["navigation"]["redirect_sequence"] == []
    assert all(
        row["prepared_redirect_sequence"] == [] and row["final_redirect_sequence"] == []
        for row in receipt["resources"]
    )


def test_client_resource_usage_parser_has_exact_nullable_contract(tmp_path: Path) -> None:
    source = tmp_path / "time.txt"
    source.write_text(
        "user_cpu_seconds=1.25\n"
        "system_cpu_seconds=0.50\n"
        "maximum_rss_kib=42\n"
        "voluntary_context_switches=7\n"
        "involuntary_context_switches=2\n",
        encoding="utf-8",
    )

    usage = _parse_client_resource_usage(source, 2.5)

    assert _client_resource_usage_valid(usage)
    assert usage["maximum_rss_bytes"] == 42 * 1_024
    assert usage["timer_wakeups"] is None
    assert usage["timer_wakeups_unavailable_reason"]
    assert usage["rapl_energy_joules"] is None
    assert usage["rapl_unavailable_reason"]


def test_completed_buflo_resource_receipt_binds_runner_timer_wakeups(tmp_path: Path) -> None:
    source = tmp_path / "time.txt"
    source.write_text(
        "user_cpu_seconds=1.25\n"
        "system_cpu_seconds=0.50\n"
        "maximum_rss_kib=42\n"
        "voluntary_context_switches=7\n"
        "involuntary_context_switches=2\n",
        encoding="utf-8",
    )
    usage = _parse_client_resource_usage(source, 2.5)
    metrics = {
        "schema_version": 1,
        "semantics": (
            "actual_select_return_source; socket_wins_simultaneous_readiness; "
            "controller_subset_is_effective_earliest_deadline; "
            "scheduled_cells_are_not_wakeups"
        ),
        "wait_returns": 31,
        "socket_readiness_wakeups": 11,
        "timer_wakeups": 20,
        "controller_deadline_timer_wakeups": 17,
        "other_timer_wakeups": 3,
    }

    assert _runner_wakeup_metrics_valid(metrics)
    measured = _merge_runner_wakeup_metrics(usage, metrics, required=True)
    assert measured["source"] == "gnu-time-python-monotonic-and-runner-select-v1"
    assert measured["timer_wakeups"] == 20
    assert measured["timer_wakeups_unavailable_reason"] is None
    assert _client_resource_usage_valid(measured)
    with pytest.raises(ValueError, match="lacks runner wakeup metrics"):
        _merge_runner_wakeup_metrics(usage, None, required=True)

    invalid = dict(metrics)
    invalid["wait_returns"] += 1
    assert not _runner_wakeup_metrics_valid(invalid)
    with pytest.raises(ValueError, match="wake.*invalid"):
        _merge_runner_wakeup_metrics(usage, invalid, required=True)


def test_extended_schedule_reconciles_typed_partial_composition(tmp_path: Path) -> None:
    neqo = tmp_path / "neqo"
    neqo.mkdir()
    path = neqo / "schedule.csv"
    fields = SCHEDULE_PREFIX_FIELDS + SCHEDULE_QCSD_FIELDS
    rows = [
        _typed_schedule_row(0, "outgoing", "full", 600, 600, 3),
        _typed_schedule_row(
            1,
            "outgoing",
            "partial",
            600,
            500,
            9,
            reason="congestion_limited",
        ),
        _typed_schedule_row(
            2,
            "outgoing",
            "suppressed",
            600,
            0,
            4,
            reason="congestion_limited",
        ),
        _typed_schedule_row(3, "incoming", "satisfied", 600, None, None),
    ]
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    metrics = _schedule_realization_metrics(tmp_path)

    assert metrics["typed_congestion_reason_column"] is True
    assert metrics["typed_credit_advertisement_columns"] is True
    assert metrics["typed_credit_consumption_columns"] is True
    assert metrics["incoming_credit_advertised_events"] == 1
    assert metrics["incoming_credit_consumed_events"] == 1
    assert metrics["incoming_credit_advertisement_delay_us_max"] == 100
    assert metrics["incoming_credit_consumption_delay_us_max"] == 500
    assert metrics["invalid_typed_outcome_rows"] == 0
    assert metrics["invalid_congestion_reason_events"] == 0
    assert metrics["terminal_slots_unique"] is True
    assert metrics["terminal_desired_outgoing_bytes"] == 1_800
    assert metrics["terminal_observed_outgoing_bytes"] == 1_100
    assert metrics["typed_lateness_us_total"] == 16
    assert metrics["typed_lateness_us_max"] == 9
    assert sum(metrics["typed_composition_bytes"].values()) == 1_100

    rows[-1]["credit_consumed_at_us"] = 50
    rows[-1]["credit_consumption_delay_us"] = 50
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    invalid = _schedule_realization_metrics(tmp_path)
    assert invalid["incoming_credit_consumed_events"] == 0
    assert invalid["invalid_credit_consumption_events"] == 1


def test_buflo_fidelity_requires_every_zero_error_and_typed_terminal_once() -> None:
    diagnostics = {
        **_incoming_credit(501 * 1_200),
        "buflo_paper_equivalent": False,
        "buflo_client_only": True,
        "buflo_scheduled_outgoing_cells": 501,
        "buflo_scheduled_incoming_cells": 501,
        "buflo_full_outgoing_cells": 501,
        "buflo_partial_outgoing_cells": 0,
        "buflo_suppressed_outgoing_cells": 0,
        "buflo_missed_outgoing_cells": 0,
        "buflo_missed_incoming_cells": 0,
        "buflo_outgoing_unresolved_cells": 0,
        "buflo_incoming_unresolved_cells": 0,
        "buflo_catch_up_outgoing_cells": 0,
        "buflo_catch_up_incoming_cells": 0,
        "buflo_egress_backlog_pending": False,
        "buflo_application_complete": True,
        "buflo_minimum_duration_reached": True,
        "buflo_event_guard_triggered": False,
    }
    schedule = _schedule_metrics(outgoing=501, incoming=501)
    canonical_targets = list(range(0, 10_000_001, 20_000))
    schedule.update(
        terminal_satisfactions={"satisfied": 1_002},
        target_times_us_by_direction={
            "outgoing": canonical_targets,
            "incoming": canonical_targets,
        },
        scheduled_sizes_by_direction={
            "outgoing": [1_200] * 501,
            "incoming": [1_200] * 501,
        },
    )

    assert fidelity_eligible(
        "buflo",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    run = {
        "completion_status": "complete",
        "error": None,
        "runner_wakeup_metrics": _runner_wakeup_receipt(),
        "resolved_configuration": {"schema_version": 2, "defense": {"kind": "buflo"}},
        "defense_diagnostics": diagnostics,
        "buflo_summary": {
            "schema_version": 1,
            "kind": "buflo",
            "implementation_scope": "client_only_quic",
            "paper_equivalent": False,
            "incoming_opportunity_semantics": (
                "client_receive_credit_and_response_qualified_chaff_attempt"
            ),
            "unavailable_peer_properties": [
                "scheduled_server_datagram_timing",
                "scheduled_server_datagram_size",
            ],
            "diagnostics": diagnostics,
        },
        "cs_buflo_summary": None,
    }
    assert new_defense_terminal_receipts_valid(run, "buflo", require_application_complete=True)
    for key in (
        "buflo_partial_outgoing_cells",
        "buflo_missed_outgoing_cells",
        "buflo_catch_up_incoming_cells",
        "buflo_outgoing_unresolved_cells",
    ):
        changed = dict(diagnostics)
        changed[key] = 1
        assert not fidelity_eligible(
            "buflo",
            changed,
            sample_eligible=True,
            missed_events=0,
            outgoing_size_mismatches=0,
            schedule_metrics=schedule,
        )


def test_cs_buflo_fidelity_reconciles_typed_composition_and_rate_state() -> None:
    composition = {
        "application_stream_bytes": 400,
        "retransmission_stream_bytes": 100,
        "chaff_stream_bytes": 200,
        "defense_control_bytes": 2,
        "quic_padding_bytes": 300,
        "other_quic_bytes": 98,
    }
    diagnostics = {
        **_incoming_credit(600),
        "cs_buflo_paper_equivalent": False,
        "cs_buflo_client_only": True,
        "cs_buflo_payload_padding": True,
        "cs_buflo_total_padding": False,
        "cs_buflo_early_termination_semantics": (
            "udp_client_only_observed_udp_power_of_two_crossing"
        ),
        "cs_buflo_scheduled_outgoing_cells": 2,
        "cs_buflo_scheduled_incoming_cells": 1,
        "cs_buflo_full_outgoing_cells": 1,
        "cs_buflo_partial_outgoing_cells": 1,
        "cs_buflo_suppressed_outgoing_cells": 0,
        "cs_buflo_missed_outgoing_cells": 0,
        "cs_buflo_missed_incoming_cells": 0,
        "cs_buflo_desired_udp_bytes": 1_200,
        "cs_buflo_realized_udp_bytes": 1_100,
        **{f"cs_buflo_{key}": value for key, value in composition.items()},
        "cs_buflo_lateness_us_total": 12,
        "cs_buflo_lateness_us_max": 9,
        "cs_buflo_natural_outgoing_bytes": 500,
        "cs_buflo_natural_incoming_bytes": 300,
        "cs_buflo_cover_outgoing_bytes": 100,
        "cs_buflo_cover_incoming_bytes": 0,
        "cs_buflo_real_bearing_outgoing_bytes": 400,
        "cs_buflo_real_bearing_incoming_bytes": 300,
        "cs_buflo_realized_incoming_credit_bytes": 600,
        "cs_buflo_outgoing_padding_basis_natural_bytes": 500,
        "cs_buflo_incoming_padding_basis_natural_bytes": 300,
        "cs_buflo_outgoing_padding_basis_cover_bytes": 100,
        "cs_buflo_incoming_padding_basis_cover_bytes": 0,
        "cs_buflo_outgoing_padding_basis_total_bytes": 600,
        "cs_buflo_incoming_padding_basis_total_bytes": 300,
        "cs_buflo_reference_tcp_write_size_bytes": 548,
        "cs_buflo_reference_nominal_tcp_packet_size_bytes": 600,
        "cs_buflo_runtime_udp_packet_size_bytes": 600,
        "cs_buflo_outgoing_termination_accounted_bytes": 1_100,
        "cs_buflo_incoming_termination_accounted_bytes": 600,
        "cs_buflo_outgoing_last_termination_increment_bytes": 100,
        "cs_buflo_incoming_last_termination_increment_bytes": 100,
        "cs_buflo_outgoing_power_of_two_crossed": True,
        "cs_buflo_incoming_power_of_two_crossed": True,
        "cs_buflo_outgoing_padding_target_bytes": 1_024,
        "cs_buflo_incoming_padding_target_bytes": 512,
        "cs_buflo_outgoing_interval_us": 8_192,
        "cs_buflo_incoming_interval_us": 8_192,
        "cs_buflo_outgoing_rate_adaptations": 0,
        "cs_buflo_incoming_rate_adaptations": 0,
        "cs_buflo_rate_boundary_translation_version": 2,
        "cs_buflo_rate_boundary_counter_semantics": (
            "client_only_quic_fresh_application_stream_bytes_outgoing_"
            "retransmission_excluded_and_consumed_application_offsets_incoming"
        ),
        "cs_buflo_author_rate_boundary_counter_semantics": (
            "per_direction_actually_transmitted_real_plus_junk_bytes"
        ),
        "cs_buflo_rate_transitions": [],
        "cs_buflo_next_outgoing_adaptation_boundary_bytes": 16_384,
        "cs_buflo_next_incoming_adaptation_boundary_bytes": 16_384,
        "cs_buflo_outgoing_estimator_samples": 4,
        "cs_buflo_incoming_estimator_samples": 2,
        "cs_buflo_outgoing_minimum_interval_opportunities": 0,
        "cs_buflo_incoming_minimum_interval_opportunities": 0,
        "cs_buflo_incoming_minimum_interval_local_realized": 0,
        "cs_buflo_outgoing_minimum_interval_terminal": 0,
        "cs_buflo_incoming_minimum_interval_terminal": 0,
        "cs_buflo_outgoing_minimum_interval_full": 0,
        "cs_buflo_incoming_minimum_interval_full": 0,
        "cs_buflo_incoming_local_realized_cells": 1,
        "cs_buflo_outgoing_unresolved_cells": 0,
        "cs_buflo_incoming_unresolved_cells": 0,
        "cs_buflo_egress_backlog_pending": False,
        "cs_buflo_application_complete": True,
        "cs_buflo_quiet_time_reached": True,
        "cs_buflo_local_termination_latched": True,
        "cs_buflo_local_et_pending_request_cancellations": 0,
        "cs_buflo_local_et_stream_cancellations": 0,
        "cs_buflo_event_guard_triggered": False,
    }
    schedule = _schedule_metrics(outgoing=2, incoming=1)
    schedule.update(
        terminal_satisfactions={"full": 1, "partial": 1, "satisfied": 1},
        terminal_desired_outgoing_bytes=1_200,
        terminal_observed_outgoing_bytes=1_100,
        congestion_reasons={"congestion_limited": 1},
        typed_composition_bytes=composition,
        typed_lateness_us_total=12,
        typed_lateness_us_max=9,
        typed_real_bearing_outgoing_bytes=400,
    )

    assert fidelity_eligible(
        "cs-buflo-cpsp",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    run = {
        "completion_status": "complete",
        "error": None,
        "runner_wakeup_metrics": _runner_wakeup_receipt(),
        "resolved_configuration": {
            "schema_version": 2,
            "defense": {"kind": "cs_buflo"},
        },
        "defense_diagnostics": diagnostics,
        "buflo_summary": None,
        "cs_buflo_summary": {
            "schema_version": 2,
            "kind": "cs_buflo",
            "implementation_scope": "client_only_quic",
            "paper_equivalent": False,
            "incoming_opportunity_semantics": (
                "client_receive_credit_and_response_qualified_chaff_attempt"
            ),
            "unavailable_peer_properties": [
                "scheduled_server_datagram_timing",
                "scheduled_server_datagram_size",
            ],
            "incoming_cadence_boundary": (
                "complete_local_on_wire_max_stream_data_advertisement"
            ),
            "incoming_terminal_boundary": "eventual_peer_stream_offset_consumption",
            "incoming_boundary_separation": (
                "advertisement_rearms_cadence_but_does_not_claim_peer_datagram_or_consumption"
            ),
            "early_termination_semantics": ("udp_client_only_observed_udp_power_of_two_crossing"),
            "diagnostics": diagnostics,
        },
    }
    assert new_defense_terminal_receipts_valid(run, "cs_buflo", require_application_complete=True)
    wrong_boundary = json.loads(json.dumps(run))
    wrong_boundary["cs_buflo_summary"]["incoming_terminal_boundary"] = (
        "local-advertisement"
    )
    assert not new_defense_terminal_receipts_valid(
        wrong_boundary, "cs_buflo", require_application_complete=True
    )
    wrong_nested = json.loads(json.dumps(run))
    wrong_nested["cs_buflo_summary"]["diagnostics"][
        "scheduled_incoming_consumed_bytes"
    ] -= 1
    assert not new_defense_terminal_receipts_valid(
        wrong_nested, "cs_buflo", require_application_complete=True
    )
    quiet_only = json.loads(json.dumps(run))
    quiet_only["defense_diagnostics"]["cs_buflo_application_complete"] = False
    quiet_only["cs_buflo_summary"]["diagnostics"]["cs_buflo_application_complete"] = False
    assert new_defense_terminal_receipts_valid(quiet_only, "cs_buflo")
    assert not new_defense_terminal_receipts_valid(
        quiet_only, "cs_buflo", require_application_complete=True
    )
    changed = dict(diagnostics)
    changed["cs_buflo_quic_padding_bytes"] += 1
    assert not fidelity_eligible(
        "cs-buflo",
        changed,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    changed = dict(diagnostics)
    changed["cs_buflo_rate_boundary_counter_semantics"] = "author-counter"
    assert not fidelity_eligible(
        "cs-buflo",
        changed,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    for key, value in (
        ("cs_buflo_incoming_local_realized_cells", 0),
        ("cs_buflo_incoming_minimum_interval_local_realized", 1),
        ("scheduled_incoming_advertised_bytes", 599),
    ):
        changed = dict(diagnostics)
        changed[key] = value
        assert not fidelity_eligible(
            "cs-buflo",
            changed,
            sample_eligible=True,
            missed_events=0,
            outgoing_size_mismatches=0,
            schedule_metrics=schedule,
        )


def test_cs_buflo_rate_transition_vector_is_causally_validated() -> None:
    from qcsd_lab.fidelity import _cs_buflo_rate_transition_vector_valid

    transition = {
        "schema_version": 1,
        "direction": "outgoing",
        "at_us": 50_000,
        "boundary_bytes": 16_384,
        "real_bearing_bytes": 17_000,
        "eligible_samples": 4,
        "median_interval_us": 6_000,
        "previous_interval_us": 8_192,
        "resulting_interval_us": 4_096,
        "retained_current_interval": False,
    }
    assert _cs_buflo_rate_transition_vector_valid([transition])
    for key, value in (
        ("boundary_bytes", 32_768),
        ("real_bearing_bytes", 1_000),
        ("resulting_interval_us", 8_192),
        ("retained_current_interval", True),
    ):
        changed = {**transition, key: value}
        assert not _cs_buflo_rate_transition_vector_valid([changed])


@pytest.mark.parametrize(
    ("natural", "cover", "expected"),
    ((1_000, 24, 1_024), (1_000, 1_100, 3_072)),
)
def test_cs_buflo_cpsp_target_uses_power_of_two_quantum_not_power_of_two_target(
    natural: int, cover: int, expected: int
) -> None:
    assert _cs_buflo_payload_padding_target(natural, cover) == expected


def test_cs_buflo_padding_gate_distinguishes_cpsp_3072_from_ctsp_4096() -> None:
    common = {
        "cs_buflo_natural_outgoing_bytes": 1_000,
        "cs_buflo_natural_incoming_bytes": 1_000,
        "cs_buflo_cover_outgoing_bytes": 1_100,
        "cs_buflo_cover_incoming_bytes": 1_100,
        "cs_buflo_realized_udp_bytes": 4_096,
        "cs_buflo_realized_incoming_credit_bytes": 3_072,
        "cs_buflo_outgoing_padding_basis_natural_bytes": 1_000,
        "cs_buflo_incoming_padding_basis_natural_bytes": 1_000,
        "cs_buflo_outgoing_padding_basis_cover_bytes": 1_100,
        "cs_buflo_incoming_padding_basis_cover_bytes": 1_100,
        "cs_buflo_outgoing_padding_basis_total_bytes": 2_100,
        "cs_buflo_incoming_padding_basis_total_bytes": 2_100,
        "cs_buflo_incoming_termination_accounted_bytes": 3_072,
        "cs_buflo_incoming_last_termination_increment_bytes": 1_100,
        "cs_buflo_incoming_power_of_two_crossed": True,
        "cs_buflo_incoming_padding_target_bytes": 3_072,
    }
    cpsp = {
        **common,
        "cs_buflo_payload_padding": True,
        "cs_buflo_total_padding": False,
        "cs_buflo_outgoing_termination_accounted_bytes": 4_096,
        "cs_buflo_outgoing_last_termination_increment_bytes": 2_100,
        "cs_buflo_outgoing_power_of_two_crossed": True,
        "cs_buflo_outgoing_padding_target_bytes": 3_072,
    }
    ctsp = {
        **common,
        "cs_buflo_payload_padding": False,
        "cs_buflo_total_padding": True,
        "cs_buflo_outgoing_termination_accounted_bytes": 4_096,
        "cs_buflo_outgoing_last_termination_increment_bytes": 0,
        "cs_buflo_outgoing_power_of_two_crossed": False,
        "cs_buflo_outgoing_padding_target_bytes": 4_096,
    }

    assert _cs_buflo_padding_targets_match(cpsp)
    assert _cs_buflo_padding_targets_match(ctsp)
    assert not _cs_buflo_padding_targets_match(
        {**cpsp, "cs_buflo_outgoing_padding_target_bytes": 4_096}
    )
    assert not _cs_buflo_padding_targets_match(
        {**ctsp, "cs_buflo_outgoing_padding_target_bytes": 3_072}
    )


def _incoming_credit(value: int) -> dict[str, int]:
    return {
        "scheduled_incoming_requested_bytes": value,
        "scheduled_incoming_advertised_bytes": value,
        "scheduled_incoming_consumed_bytes": value,
        "scheduled_incoming_retired_bytes": 0,
        "scheduled_incoming_unresolved_bytes": 0,
    }


def _schedule_metrics(*, outgoing: int, incoming: int) -> dict[str, object]:
    return {
        "scheduled_outgoing_events": outgoing,
        "scheduled_incoming_events": incoming,
        "terminal_slots_unique": True,
        "duplicate_terminal_slots": 0,
        "invalid_terminal_rows": 0,
        "typed_congestion_reason_column": True,
        "typed_credit_advertisement_columns": True,
        "typed_credit_consumption_columns": True,
        "invalid_congestion_reason_events": 0,
        "invalid_typed_outcome_rows": 0,
        "incoming_credit_advertised_events": incoming,
        "incoming_credit_consumed_events": incoming,
        "incoming_credit_missing_events": 0,
        "incoming_credit_consumption_missing_events": 0,
        "invalid_credit_advertisement_events": 0,
        "invalid_credit_consumption_events": 0,
        "incoming_credit_advertisement_delay_us_total": incoming * 100,
        "incoming_credit_advertisement_delay_us_max": 100 if incoming else 0,
        "incoming_credit_advertisement_delay_us_values": [100] * incoming,
        "incoming_credit_consumption_delay_us_total": incoming * 500,
        "incoming_credit_consumption_delay_us_max": 500 if incoming else 0,
        "incoming_credit_consumption_delay_us_values": [500] * incoming,
        "terminal_satisfactions": {"satisfied": outgoing + incoming},
        "terminal_desired_outgoing_bytes": 0,
        "terminal_observed_outgoing_bytes": 0,
        "typed_composition_bytes": {},
        "typed_lateness_us_total": 0,
        "typed_lateness_us_max": 0,
        "typed_real_bearing_outgoing_bytes": 0,
        "target_times_us_by_direction": {"outgoing": [], "incoming": []},
        "scheduled_sizes_by_direction": {"outgoing": [], "incoming": []},
    }


def _typed_schedule_row(
    slot: int,
    direction: str,
    satisfaction: str,
    desired: int,
    observed: int | None,
    lateness: int | None,
    *,
    reason: str = "",
) -> dict[str, object]:
    row: dict[str, object] = {field: "" for field in SCHEDULE_PREFIX_FIELDS + SCHEDULE_QCSD_FIELDS}
    row.update(
        target_time_us=slot * 1_000,
        direction=direction,
        size=desired,
        connection=0,
        action_time_us=slot * 1_000,
        satisfaction=satisfaction,
        observed_size=("" if observed is None or satisfaction == "suppressed" else observed),
        miss_reason={"congestion_limited": "CongestionLimited"}.get(reason, ""),
        slot_id=slot,
        qcsd_outcome_schema_version=(2 if direction == "incoming" else 1),
        send_policy=("exact" if satisfaction == "satisfied" else "congestion_sensitive"),
        desired_udp_bytes=desired,
        observed_udp_bytes="" if observed is None else observed,
        congestion_reason=reason,
    )
    if satisfaction in {"full", "partial", "suppressed"}:
        assert observed is not None and lateness is not None
        row.update(
            application_stream_bytes=observed,
            retransmission_stream_bytes=0,
            chaff_stream_bytes=0,
            defense_control_bytes=0,
            quic_padding_bytes=0,
            other_quic_bytes=0,
            lateness_us=lateness,
        )
    if direction == "incoming":
        row.update(
            credit_advertised_at_us=slot * 1_000 + 100,
            credit_advertisement_delay_us=100,
            credit_consumed_at_us=slot * 1_000 + 500,
            credit_consumption_delay_us=500,
        )
    return row


def test_comparison_review_cannot_omit_declared_csbuflo_incoming_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = tmp_path / "handoff"
    handoff.mkdir()
    for name in ("SHA256SUMS", "dataset.json", "samples.jsonl"):
        (handoff / name).write_text(name + "\n", encoding="utf-8")
    evaluation_receipt = tmp_path / "evaluation.json"
    evaluation_receipt.write_text("{}\n", encoding="utf-8")

    common = [
        {"difference": "transport-and-observation-layer"},
        {"difference": "endpoint-cooperation-and-peer-datagram-unavailability"},
        {"difference": "closed-world-dataset-and-classifier-protocol"},
    ]
    qcsd_rows = [
        {"defense": "buflo", "known_expected_differences": common},
        {
            "defense": "cs-buflo",
            "known_expected_differences": [
                *common,
                {
                    "difference": (
                        "csbuflo-author-total-transmitted-vs-live-fresh-"
                        "application-stream-byte-adaptation-counter"
                    )
                },
                {"difference": "csbuflo-incoming-boundary-translation"},
            ],
        },
    ]
    evaluation = {"original_study_comparison": {"qcsd_rows": qcsd_rows}}
    monkeypatch.setattr(
        buflo_evaluation,
        "validate_evaluation_receipt",
        lambda *_args, **_kwargs: evaluation,
    )
    monkeypatch.setattr(
        buflo_handoff,
        "validate_study_handoff",
        lambda *_args, **_kwargs: handoff.resolve(),
    )

    required_ids = buflo_study._comparison_required_difference_ids(qcsd_rows)
    assert "csbuflo-incoming-boundary-translation" in required_ids
    required_ids.remove("csbuflo-incoming-boundary-translation")
    review = {
        "schema_version": 1,
        "artifact_type": buflo_study.COMPARISON_REVIEW_ARTIFACT_TYPE,
        "formal": True,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
        "evaluation": buflo_study._file_binding(evaluation_receipt),
        "handoff": {
            "root": str(handoff.resolve()),
            "sha256sums_sha256": hashlib.sha256(
                (handoff / "SHA256SUMS").read_bytes()
            ).hexdigest(),
            "dataset_sha256": hashlib.sha256(
                (handoff / "dataset.json").read_bytes()
            ).hexdigest(),
            "samples_sha256": hashlib.sha256(
                (handoff / "samples.jsonl").read_bytes()
            ).hexdigest(),
        },
        "reviewer": "independent-reviewer",
        "reviewed_at": "2026-08-27T00:00:00+00:00",
        "rows": [
            {
                "defense": row["defense"],
                "evaluation_row_sha256": buflo_study._canonical_digest(row),
                "classification": "expected",
                "explanation": "reviewed",
            }
            for row in qcsd_rows
        ],
        "required_differences": [
            {
                "difference": identifier,
                "classification": "expected",
                "explanation": "reviewed",
            }
            for identifier in sorted(required_ids)
        ],
        "passed": True,
    }
    review_path = tmp_path / "comparison-review.json"
    review_path.write_text(json.dumps(review, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="required-difference inventory"):
        buflo_study.validate_comparison_review(
            review_path,
            evaluation_receipt=evaluation_receipt,
            handoff=handoff,
            formal=True,
        )
