from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from qcsd_lab import buflo_study, orchestrator
from qcsd_lab import class_attestation as attestation
from qcsd_lab.capture_session import Defense, Limits
from qcsd_lab.class_study import bind_receipt, canonical_json_bytes
from qcsd_lab.util import sha256_file
from qcsd_lab.verification import VerifiedResult
from tests.test_buflo_study import _build_execution_value


def _digest(character: str = "a") -> str:
    return character * 64


def _completion_identity(cohort_version: int = 23) -> dict[str, str]:
    return {
        "completion_path": (
            f"/lab/artifacts/buflo-study/build-completion-v{cohort_version}.json"
        ),
        "completion_sha256": _digest("6"),
    }


def _runtime_inputs(
    modes: tuple[str, ...], parameters: dict[str, str]
) -> dict[str, dict[str, Any]]:
    runtime_kinds = {
        "undefended": "none",
        "static": "static",
        "front": "front",
        "tamaraw": "tamaraw",
        "traffic-morphing": "traffic_morphing",
        "wtf-pad": "wtf_pad",
        "walkie-talkie": "walkie_talkie",
        "buflo": "buflo",
        "cs-buflo": "cs_buflo",
    }
    result: dict[str, dict[str, Any]] = {}
    for mode in modes:
        if mode in parameters:
            result[mode] = {
                "identity_type": "hash-bound-parameter-artifact",
                "runtime_kind": runtime_kinds[mode],
                "parameters_sha256": parameters[mode],
                "provenance_sha256": _digest("9"),
                "input_policy": "sealed-class-study-fitting-v1",
            }
        elif mode == "static":
            result[mode] = {
                "identity_type": "hash-bound-static-schedule",
                "runtime_kind": "static",
                "schedule_sha256": _digest("8"),
                "mode": "chaff-and-shape",
            }
        else:
            result[mode] = {
                "identity_type": (
                    "source-bound-no-defense" if mode == "undefended" else "source-bound-built-in"
                ),
                "runtime_kind": runtime_kinds[mode],
            }
    return result


def _source(*, dirty: bool = False) -> dict[str, Any]:
    return {
        "image_digest": f"sha256:{_digest('1')}",
        "lab_commit": "2" * 40,
        "lab_dirty": dirty,
        "lab_patch_sha256": _digest("3") if dirty else attestation._EMPTY_SHA256,
        "neqo_commit": "4" * 40,
        "neqo_pinned_commit": "4" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": attestation._EMPTY_SHA256,
    }


def _browser_egress_result(root: Path, build: dict[str, Any]) -> dict[str, Any]:
    root.mkdir(exist_ok=True)
    final = root / "final.json"
    final.write_text("{}\n", encoding="utf-8")
    images = build["images"]
    return {
        "path": str(final.absolute()),
        "sha256": sha256_file(final),
        "payload_sha256": _digest("a"),
        "qualification_id": attestation.BROWSER_EGRESS_QUALIFICATION_ID,
        "cohort_version": 23,
        "qualification_started_at": "2026-08-28T01:10:00+00:00",
        "qualification_finished_at": "2026-08-28T01:20:00+00:00",
        "recorded_at": "2026-08-28T01:30:00+00:00",
        "prepare_image_id": images["prepare"]["id"],
        "build_execution": {
            "path": str(Path(build["path"]).absolute()),
            "sha256": build["sha256"],
            "size_bytes": Path(build["path"]).stat().st_size,
            "payload_sha256": build["payload_sha256"],
            "cohort_version": 23,
            **_completion_identity(),
            "collection_image_id": images["collection"]["id"],
            "prepare_image_id": images["prepare"]["id"],
            "reference_image_id": images["reference"]["id"],
        },
        "expanded_vectors_sha256": attestation.browser_egress_vectors_sha256(),
        "passed_vector_count": attestation.BROWSER_EGRESS_VECTOR_COUNT,
        "passed": True,
    }


def _completion_authority_inputs(
    tmp_path: Path,
    *,
    receipt_type: str = attestation.ACQUISITION_AUTHORITY_RECEIPT_TYPE,
) -> tuple[Path, Path, dict[str, Any]]:
    authority_path = tmp_path / "current-acquisition-authority.json"
    authority_path.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                {"fixture": "current-authority"},
                receipt_type=receipt_type,
            )
        )
    )
    binding = {
        "path": str(authority_path.resolve()),
        "sha256": sha256_file(authority_path),
    }
    provenance_path = tmp_path / "provenance.json"
    provenance_path.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                {
                    "acquisition_schema_version": attestation.ACQUISITION_SCHEMA_VERSION,
                    "acquisition_authority": binding,
                },
                receipt_type=attestation.ACQUISITION_PROVENANCE_TYPE,
            )
        )
    )
    completion = {
        "acquisition_schema_version": attestation.ACQUISITION_SCHEMA_VERSION,
        "completion_schema_version": attestation.ACQUISITION_COMPLETION_SCHEMA_VERSION,
        "checkpoint_schema_version": attestation.ACQUISITION_CHECKPOINT_SCHEMA_VERSION,
        "provenance_sha256": sha256_file(provenance_path),
    }
    return authority_path, provenance_path, completion


@pytest.mark.parametrize(
    "receipt_type",
    (
        attestation.ACQUISITION_AUTHORITY_RECEIPT_TYPE,
        attestation.FOUNDATION_RECEIPT_TYPE,
    ),
)
def test_current_completion_authority_verifies_offline_narrow_or_foundation_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    receipt_type: str,
) -> None:
    authority_path, _provenance_path, completion = _completion_authority_inputs(
        tmp_path,
        receipt_type=receipt_type,
    )
    binding = {
        "path": str(authority_path.resolve()),
        "sha256": sha256_file(authority_path),
    }
    observed: list[tuple[str, Path, dict[str, Any]]] = []

    def validate_narrow(path: Path, **kwargs: Any) -> dict[str, Any]:
        observed.append(("narrow", path, kwargs))
        return dict(binding)

    def validate_foundation(path: Path, **kwargs: Any) -> dict[str, Any]:
        observed.append(("foundation", path, kwargs))
        return dict(binding)

    monkeypatch.setattr(attestation, "validate_class_acquisition_authority", validate_narrow)
    monkeypatch.setattr(attestation, "validate_class_foundation_attestation", validate_foundation)

    result = attestation.validate_current_acquisition_completion_authority(
        completion,
        runner_root=tmp_path,
    )

    assert result == {"receipt_type": receipt_type, **binding}
    if receipt_type == attestation.ACQUISITION_AUTHORITY_RECEIPT_TYPE:
        assert observed == [
            (
                "narrow",
                authority_path.resolve(),
                {"runtime_role": None, "allow_historical": False},
            )
        ]
    else:
        assert observed == [
            (
                "foundation",
                authority_path.resolve(),
                {
                    "deep_code_gate": True,
                    "runtime_role": None,
                    "allow_historical": False,
                },
            )
        ]


@pytest.mark.parametrize("mutation", ("missing", "hash-tampered", "historical-v96"))
def test_current_completion_authority_rejects_missing_tampered_or_historical_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    authority_path, _provenance_path, completion = _completion_authority_inputs(tmp_path)

    if mutation == "missing":
        authority_path.unlink()
        expected = "regular file"
    elif mutation == "hash-tampered":
        authority_path.write_text("changed\n", encoding="utf-8")
        expected = "digest changed"
    else:
        expected = "historical.*verify-only"

        def reject_historical(path: Path, **kwargs: Any) -> dict[str, Any]:
            assert path == authority_path.resolve()
            assert kwargs == {"runtime_role": None, "allow_historical": False}
            raise ValueError("historical v96 acquisition authority is verify-only")

        monkeypatch.setattr(
            attestation,
            "validate_class_acquisition_authority",
            reject_historical,
        )

    with pytest.raises(ValueError, match=expected):
        attestation.validate_current_acquisition_completion_authority(
            completion,
            runner_root=tmp_path,
        )


def test_qualification_authority_derives_prepare_identity_from_exact_foundation_build(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    foundation_path = tmp_path / "foundation.json"
    build_path = tmp_path / "build.json"
    foundation_path.write_text("{}\n", encoding="utf-8")
    build_path.write_text("{}\n", encoding="utf-8")
    collection = _source()
    prepare_image = f"sha256:{_digest('8')}"
    build_sha = sha256_file(build_path)
    identity = {
        "cohort_version": 23,
        "sha256": build_sha,
        **_completion_identity(),
        "collection_image": collection["image_digest"],
        "started_at": "2026-08-28T00:00:00+00:00",
        "finished_at": "2026-08-28T01:00:00+00:00",
    }
    foundation = {
        "path": str(foundation_path.resolve()),
        "sha256": sha256_file(foundation_path),
        "payload_sha256": _digest("7"),
        "cohort_version": 23,
        "source": collection,
        "build_execution_identity": identity,
        "evidence": {
            "build_execution": {
                "path": str(build_path.resolve()),
                "sha256": build_sha,
            }
        },
    }
    observed: dict[str, Any] = {}

    def validate_foundation(_path: Path, **kwargs):
        observed.update(kwargs)
        return foundation

    build = {
        **identity,
        "path": str(build_path.resolve()),
        "completion_path": str(
            build_path.with_name("build-completion-v23.json").resolve()
        ),
        "source": collection,
        "images": {"prepare": {"id": prepare_image}},
    }
    build_observed: dict[str, Any] = {}

    def validate_build(_path: Path, **kwargs: Any) -> dict[str, Any]:
        build_observed.update(kwargs)
        return build

    monkeypatch.setattr(attestation, "validate_class_foundation_attestation", validate_foundation)
    monkeypatch.setattr(attestation, "validate_build_execution_receipt", validate_build)

    authority = attestation.class_qualification_authority(foundation_path, runtime_role="prepare")

    assert observed["runtime_role"] == "prepare"
    assert build_observed["allow_historical"] is False
    assert authority["foundation_attestation"]["sha256"] == foundation["sha256"]
    assert authority["schema_version"] == attestation.QUALIFICATION_AUTHORITY_SCHEMA_VERSION
    assert authority["build_execution"] == {
        "path": str(build_path.resolve()),
        "sha256": build_sha,
    }
    assert authority["prepare_image_digest"] == prepare_image
    assert authority["prepare_source"] == {**collection, "image_digest": prepare_image}
    for mutation in (
        {"completion_path": "/other/build-completion-v23.json"},
        {"completion_sha256": "not-a-digest"},
    ):
        forged = {
            **authority,
            "build_execution_identity": {
                **authority["build_execution_identity"],
                **mutation,
            },
        }
        with pytest.raises(ValueError, match="authority binding"):
            attestation.validate_class_qualification_authority(forged)

    monkeypatch.setattr(
        attestation,
        "validate_build_execution_receipt",
        lambda *_a, **_k: {**build, "source": {**collection, "lab_commit": "9" * 40}},
    )
    with pytest.raises(ValueError, match="differs from foundation source"):
        attestation.class_qualification_authority(foundation_path, runtime_role="prepare")


def test_current_build_identity_requires_and_canonicalizes_completion() -> None:
    build = {
        "cohort_version": 23,
        "path": "/host/artifacts/buflo-study/build-execution-v23.json",
        "sha256": _digest("1"),
        "completion_path": "/host/artifacts/buflo-study/build-completion-v23.json",
        "completion_sha256": _digest("6"),
        "collection_image": f"sha256:{_digest('2')}",
        "started_at": "2026-08-28T00:00:00+00:00",
        "finished_at": "2026-08-28T01:00:00+00:00",
    }
    identity = attestation._build_identity(build)
    assert identity["completion_path"] == (
        "/lab/artifacts/buflo-study/build-completion-v23.json"
    )
    for field in ("completion_path", "completion_sha256"):
        incomplete = dict(build)
        incomplete.pop(field)
        with pytest.raises(ValueError, match="completed schema-5"):
            attestation._build_identity(incomplete)
    wrong_location = {
        **build,
        "completion_path": "/other/build-completion-v23.json",
    }
    with pytest.raises(ValueError, match="completed schema-5"):
        attestation._build_identity(wrong_location)


def test_prior_class_schemas_are_explicit_historical_only_round_trips() -> None:
    source = _source()
    historical_identity = {
        "cohort_version": 23,
        "sha256": _digest("1"),
        "collection_image": source["image_digest"],
        "started_at": "2026-08-28T00:00:00+00:00",
        "finished_at": "2026-08-28T01:00:00+00:00",
    }
    assert attestation._build_identity(
        {
            **historical_identity,
            "path": "/evidence/build.json",
        },
        include_completion=False,
    ) == historical_identity
    authority = {
        "schema_version": attestation.HISTORICAL_QUALIFICATION_AUTHORITY_SCHEMA_VERSION,
        "artifact_type": attestation.QUALIFICATION_AUTHORITY_TYPE,
        "foundation_attestation": {
            "path": "/evidence/foundation.json",
            "sha256": _digest("2"),
            "payload_sha256": _digest("3"),
        },
        "build_execution": {
            "path": "/evidence/build.json",
            "sha256": historical_identity["sha256"],
        },
        "build_execution_identity": historical_identity,
        "collection_source": source,
        "prepare_source": {
            **source,
            "image_digest": f"sha256:{_digest('8')}",
        },
        "prepare_image_digest": f"sha256:{_digest('8')}",
    }
    with pytest.raises(ValueError, match="authority binding"):
        attestation.validate_class_qualification_authority(authority)
    assert attestation.validate_class_qualification_authority(
        authority, allow_historical=True
    ) == json.loads(canonical_json_bytes(authority))

    foundation = {
        "attestation_schema_version": attestation.HISTORICAL_FOUNDATION_SCHEMA_VERSION,
        "artifact_type": attestation.FOUNDATION_RECEIPT_TYPE,
        "study_id": attestation.STUDY_ID,
        "recorded_at": "2026-08-28T02:00:00+00:00",
        "implementation_status": "foundation-ready-for-class-acquisition",
        "promotion_authority": False,
        "implementation_scope": attestation.IMPLEMENTATION_SCOPE,
        "paper_equivalent": False,
        "no_waivers": True,
        "all_foundation_gates_passed": True,
        "hard_gates": attestation._hard_gate_records(
            attestation._FOUNDATION_GATES,
            {gate: [_digest("4")] for gate in attestation._FOUNDATION_GATES},
        ),
    }
    with pytest.raises(ValueError, match="promotion envelope"):
        attestation._validate_foundation_envelope(foundation)
    attestation._validate_foundation_envelope(
        json.loads(canonical_json_bytes(foundation)), allow_historical=True
    )

    readiness = {
        "attestation_schema_version": attestation.HISTORICAL_READINESS_SCHEMA_VERSION,
        "artifact_type": attestation.READINESS_RECEIPT_TYPE,
        "study_id": attestation.STUDY_ID,
        "implementation_status": attestation.READINESS_IMPLEMENTATION_STATUS,
        "promotion_authority": False,
        "implementation_scope": attestation.IMPLEMENTATION_SCOPE,
        "paper_equivalent": False,
        "no_waivers": True,
        "all_readiness_gates_passed": True,
        "hard_gates": attestation._hard_gate_records(
            attestation._READINESS_GATES,
            {gate: [_digest("5")] for gate in attestation._READINESS_GATES},
        ),
    }
    with pytest.raises(ValueError, match="promotion envelope"):
        attestation._validate_readiness_envelope(readiness)
    attestation._validate_readiness_envelope(
        json.loads(canonical_json_bytes(readiness)), allow_historical=True
    )


@pytest.mark.parametrize("entrypoint", ("foundation", "readiness"))
@pytest.mark.parametrize("stop_at", ("reference", "code", "qualification"))
def test_nested_gate_admission_mode_tracks_class_schema(
    entrypoint: str,
    stop_at: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = _source()
    build_path = tmp_path / "build-execution-v23.json"
    build = {
        "cohort_version": 23,
        "path": str(build_path.resolve()),
        "sha256": _digest("1"),
        "completion_path": str(
            build_path.with_name("build-completion-v23.json").resolve()
        ),
        "completion_sha256": _digest("6"),
        "collection_image": source["image_digest"],
        "started_at": "2026-08-28T00:00:00+00:00",
        "finished_at": "2026-08-28T01:00:00+00:00",
        "source": source,
    }
    state = {"historical": False}
    observed: list[tuple[str, bool | None]] = []

    class StopAtGate(Exception):
        pass

    def gate_validator(name: str, result):
        def validate(*_args: Any, **kwargs: Any) -> dict[str, Any]:
            observed.append((name, kwargs.get("allow_historical")))
            if name == stop_at:
                raise StopAtGate
            return result()

        return validate

    def identity() -> dict[str, Any]:
        return attestation._build_identity(
            build, include_completion=not state["historical"]
        )

    monkeypatch.setattr(
        attestation, "validate_build_execution_receipt", lambda *_a, **_k: build
    )
    monkeypatch.setattr(
        attestation,
        "validate_reference_gate_receipt",
        gate_validator(
            "reference",
            lambda: {
                "build_execution": identity(),
                "profiles_checked": 8,
                "sha256": _digest("2"),
            },
        ),
    )
    monkeypatch.setattr(
        attestation,
        "validate_regression_results",
        lambda *_a, **_k: {"samples": attestation.REGRESSION_SAMPLE_COUNT},
    )
    monkeypatch.setattr(
        attestation,
        "validate_code_gate_receipt",
        gate_validator("code", lambda: {}),
    )
    monkeypatch.setattr(
        attestation,
        "validate_qualification_receipt",
        gate_validator("qualification", lambda: {}),
    )

    if entrypoint == "foundation":
        monkeypatch.setattr(
            attestation, "_validate_browser_egress_qualification", lambda *_a, **_k: {}
        )
        monkeypatch.setattr(
            attestation, "validate_pinned_cdp_receipt", lambda *_a, **_k: {}
        )

        def invoke(*, historical: bool) -> None:
            attestation._foundation_value(
                cohort_version=23,
                build_execution_receipt=build_path,
                reference_receipt=tmp_path / "reference.json",
                code_gate_receipt=tmp_path / "code.json",
                controlled_qualification_receipt=tmp_path / "qualification.json",
                pinned_cdp_receipt=tmp_path / "pinned.json",
                browser_egress_qualification_root=tmp_path / "browser-egress",
                regression_result_roots=(),
                controlled_result_roots=(),
                recorded_at="2026-08-28T02:00:00+00:00",
                deep_code_gate=False,
                evidence_source=source,
                pinned_runtime_role="collection",
                attestation_schema_version=(
                    attestation.HISTORICAL_FOUNDATION_SCHEMA_VERSION
                    if historical
                    else attestation.FOUNDATION_SCHEMA_VERSION
                ),
                allow_historical=historical,
            )

    else:
        monkeypatch.setattr(attestation, "source_metadata", lambda: source)
        monkeypatch.setattr(
            attestation,
            "validate_class_foundation_attestation",
            lambda *_a, **_k: {"cohort_version": 23},
        )
        monkeypatch.setattr(
            attestation, "class_qualification_authority", lambda *_a, **_k: {}
        )

        def invoke(*, historical: bool) -> None:
            ordinary = tmp_path / "unused"
            attestation._readiness_value(
                foundation_attestation=ordinary,
                cohort_version=23,
                build_execution_receipt=build_path,
                reference_receipt=ordinary,
                code_gate_receipt=ordinary,
                controlled_qualification_receipt=ordinary,
                regression_result_roots=(),
                controlled_result_roots=(),
                candidate_catalogue=ordinary,
                stability_root=ordinary,
                workload_root=ordinary,
                acquisition_completion=ordinary,
                pilot_cohort_receipt=ordinary,
                pilot_cohort_assembly=ordinary,
                pilot_fitting_result_root=ordinary,
                pilot_numeric_bundle_root=ordinary,
                pilot_compatibility_result_root=ordinary,
                final_selection_receipt=ordinary,
                final_cohort_receipt=ordinary,
                final_cohort_assembly=ordinary,
                authoritative_fitting_result_root=ordinary,
                authoritative_fitting_bundle_root=ordinary,
                qualification_workload_root=ordinary,
                qualification_sidecar_root=ordinary,
                qualification_prefix_root=ordinary,
                certification_result_root=ordinary,
                deep_code_gate=False,
                attestation_schema_version=(
                    attestation.HISTORICAL_READINESS_SCHEMA_VERSION
                    if historical
                    else attestation.READINESS_SCHEMA_VERSION
                ),
                allow_historical=historical,
            )

    expected_names = ("reference", "code", "qualification")
    expected_names = expected_names[: expected_names.index(stop_at) + 1]
    for historical in (False, True):
        state["historical"] = historical
        observed.clear()
        with pytest.raises(StopAtGate):
            invoke(historical=historical)
        assert observed == [(name, historical) for name in expected_names]


def _study_environment(image_id: str) -> dict[str, Any]:
    build_execution = _build_execution_value(image_id)
    return {
        "schema_version": 2,
        "artifact_type": "qcsd-buflo-study-environment",
        "docker": {
            "client_version": "29.0.1",
            "server_version": "29.0.1",
            "server_os": "linux",
            "server_arch": "amd64",
            "ncpu": 12,
            "mem_total_bytes": 16_000_000_000,
            "storage_driver": "overlayfs",
        },
        "collection_image": {
            "id": image_id,
            "repo_digests": [f"collection.invalid/qcsd@{image_id}"],
        },
        "build_inputs": build_execution["build_inputs"],
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
        "capture_scheduler": buflo_study._capture_scheduler_environment_contract(),
    }


def _evaluation(*, full_replay: bool = True) -> dict[str, Any]:
    classes = [f"class-{index:03d}" for index in range(attestation.FINAL_CLASS_COUNT)]
    candidate_modes = ("buflo", "cs-buflo")
    blocks = range(1, attestation.FORMAL_BLOCK_COUNT + 1)
    directions = ("outgoing", "incoming")
    directional = [
        {
            "defense": mode,
            "workload_id": class_label,
            "acquisition_block_index": block,
            "direction": direction,
            "samples": attestation.FORMAL_VISITS_PER_BLOCK,
            "target_size_histogram": {},
            "desired_udp_bytes": 0,
            "observed_udp_bytes": 0,
            "target_realization_ratio": None,
            "satisfaction_counts": {},
            "congestion_reason_counts": {},
            "traffic_composition_bytes": {},
            "inter_target_delta_us": {},
            "estimated_jitter_us": {},
            "scheduling_lateness_us": {},
            "receive_credit_advertisement": {},
            "receive_credit_consumption": {},
            "inferred_rate_transition_count": 0,
            "inferred_rate_transition_histogram": {},
            "cs_buflo": {} if mode == "cs-buflo" else None,
        }
        for mode in candidate_modes
        for class_label in classes
        for block in blocks
        for direction in directions
    ]

    def grouped(mode: str) -> list[dict[str, Any]]:
        return [
            {
                "defense": mode,
                "workload_id": class_label,
                "acquisition_block_index": block,
                "samples": attestation.FORMAL_VISITS_PER_BLOCK,
            }
            for class_label in classes
            for block in blocks
        ]

    classes_sha256 = _digest("6")
    return {
        "sample_count": attestation.FORMAL_SAMPLE_COUNT,
        "class_count": attestation.FINAL_CLASS_COUNT,
        "classes": classes,
        "modes": list(attestation.FORMAL_MODES),
        "result_count": 72,
        "correctness": {
            "schema_version": 1,
            "passed": True,
            "sample_count": attestation.FORMAL_SAMPLE_COUNT,
            "passed_samples": attestation.FORMAL_SAMPLE_COUNT,
            "coverage": {
                "class_count": attestation.FINAL_CLASS_COUNT,
                "classes_sha256": classes_sha256,
                "modes": list(attestation.FORMAL_MODES),
                "acquisition_blocks": list(range(1, attestation.FORMAL_BLOCK_COUNT + 1)),
                "visits_per_class_mode_block": 2,
            },
            "checks": {
                "prepared_response_identity": "exact",
                "defense_fidelity": "independently-recomputed-eligible",
                "exact_receipt_match": True,
            },
        },
        "performance": {
            "schema_version": 1,
            "passed": True,
            "sample_count": attestation.FORMAL_SAMPLE_COUNT,
            "complete_samples": attestation.FORMAL_SAMPLE_COUNT,
            "coverage": {
                "class_count": attestation.FINAL_CLASS_COUNT,
                "modes": list(attestation.FORMAL_MODES),
                "acquisition_blocks": list(range(1, attestation.FORMAL_BLOCK_COUNT + 1)),
                "paired_visits": 2_000,
                "defended_baseline_pairs": 14_000,
            },
            "bootstrap": {
                "draws": 10_000,
                "seed": attestation.class_evaluation.FORMAL_BOOTSTRAP_SEED,
                "cluster": "acquisition_block+workload_id",
                "resampling": "joint-cluster-with-replacement",
            },
            "metric_inventory": [
                "ratio-of-sums wire and UDP-payload overhead",
                "packet-count overhead",
                "paired completion ratio and added seconds",
                "paired goodput",
                "client CPU, wall time, RSS, context switches, and timer wakeups",
                "transport retransmissions",
                "nullable RAPL energy",
                "direction/workload/acquisition-block breakdowns",
            ],
            "rapl": {
                "nullable": True,
                "available_samples": 0,
                "unavailable_samples": attestation.FORMAL_SAMPLE_COUNT,
                "unavailable_reasons": ["RAPL unavailable"],
            },
            "paired_by_mode": {
                mode: {
                    "performance_evidence_available": True,
                    "wire_ratio_of_sums": 2.0,
                    "additional_wire_percent": 100.0,
                    "duration_ratio_of_sums": 1.5,
                    "added_seconds_pair_quantiles": {
                        "p50": 1.25,
                        "p90": 2.0,
                        "p95": 2.5,
                    },
                }
                for mode in attestation.FORMAL_MODES
                if mode != "undefended"
            },
            "breakdowns": {"directional": {"all": {}}, "client": {"all": {}}},
        },
        "candidate_algorithm": {
            "schema_version": 1,
            "passed": True,
            "sample_count": 4_000,
            "coverage": {
                "class_count": attestation.FINAL_CLASS_COUNT,
                "classes_sha256": classes_sha256,
                "modes": list(candidate_modes),
                "acquisition_blocks": list(blocks),
                "visits_per_class_mode_block": attestation.FORMAL_VISITS_PER_BLOCK,
                "directions": list(directions),
                "diagnostic_schema_versions": [4],
            },
            "checks": {
                "run_schedule_events_packets_rederived": True,
                "classifier_input": False,
                "current_schema_required": True,
            },
            "breakdowns": {
                "available": True,
                "classifier_input": False,
                "schema_version": 3,
                "strata": directional,
                "buflo_terminal_tail_strata": grouped("buflo"),
                "buflo_schedule_stop_strata": grouped("buflo"),
                "cs_buflo_local_termination_strata": grouped("cs-buflo"),
            },
        },
        "dlsvm_capacity_preflight": {
            "schema_version": 2,
            "artifact_type": "qcsd-dlsvm-native-capacity-preflight",
            "path": "/artifacts/evaluation.dlsvm-preflight.json",
            "sha256": _digest("a"),
            "workload_sha256": _digest("b"),
            "projection_sha256": _digest("c"),
            "execution_model": dict(attestation.class_evaluation.CLASS_DLSVM_EXECUTION_MODEL),
            "execution_model_sha256": (
                attestation.class_evaluation.CLASS_DLSVM_EXECUTION_MODEL_SHA256
            ),
            "admission": {
                "wall_time_available": True,
                "memory_available": True,
                "cache_storage_available": True,
            },
        },
        "verification_strength": {
            "level": "full-replay" if full_replay else "reduced",
            "deep_handoff": full_replay,
            "classic_pcap_regenerated": full_replay,
            "correctness_recomputed": True,
            "performance_summary_recomputed": True,
            "performance_raw_evidence_recomputed": full_replay,
            "dlsvm_all_matrix_cells_recomputed": True,
            "dlsvm_capacity_preflight_revalidated": True,
            "dlsvm_current_capacity_admitted": True,
            "dlsvm_execution_model_sha256": (
                attestation.class_evaluation.CLASS_DLSVM_EXECUTION_MODEL_SHA256
            ),
            "candidate_algorithm_diagnostics_rederived": True,
            "classifier_attacks_replayed": full_replay,
            "limitations": [] if full_replay else ["not replayed"],
            "authorizes_final_attestation": False,
        },
        "results": [
            {
                "attack": attack,
                "training_defense": mode,
                "testing_defense": mode,
                "protocol": "temporal-heldout-test-adaptive",
                "accuracy": 0.5,
                "block_workload_bootstrap_95": {
                    "bootstrap_95": {
                        "accuracy": {"low": 0.45, "high": 0.55},
                    }
                },
            }
            for mode in ("buflo", "cs-buflo")
            for attack in ("panchenko", "vngpp", "dlsvm")
        ],
    }


def test_immutable_source_gate_rejects_dirty_or_unpinned_source() -> None:
    attestation._validate_immutable_source(_source(), label="test")
    with pytest.raises(ValueError, match="clean immutable"):
        attestation._validate_immutable_source(_source(dirty=True), label="test")
    unpinned = _source()
    unpinned["neqo_pinned_commit"] = "5" * 40
    with pytest.raises(ValueError, match="clean immutable"):
        attestation._validate_immutable_source(unpinned, label="test")


@pytest.mark.parametrize(
    "field",
    (
        "acquisition_schema_version",
        "completion_schema_version",
        "checkpoint_schema_version",
    ),
)
def test_readiness_current_acquisition_schema_gate_rejects_bool_alias(field: str) -> None:
    identity = {
        "acquisition_schema_version": attestation.ACQUISITION_SCHEMA_VERSION,
        "completion_schema_version": attestation.ACQUISITION_COMPLETION_SCHEMA_VERSION,
        "checkpoint_schema_version": attestation.ACQUISITION_CHECKPOINT_SCHEMA_VERSION,
    }
    assert attestation._require_current_acquisition_completion(identity) == identity
    identity[field] = True
    with pytest.raises(ValueError, match="requires current acquisition schema"):
        attestation._require_current_acquisition_completion(identity)


def test_class_result_materializes_and_revalidates_real_study_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_buflo_study import _write_schema5_build_pair

    root = tmp_path / "class-result"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    campaign_file = inputs / "campaign.yml"
    campaign_file.write_text("schema: 2\n", encoding="utf-8")
    campaign = orchestrator.Campaign(
        path=campaign_file,
        source_bytes=campaign_file.read_bytes(),
        name="classifier-multiorigin100-v1-canary-01-1200",
        purpose="evaluation",
        seed=1,
        profile="1200",
        workloads=(),
        request_policies=("as-defined",),
        defenses=(Defense("undefended", "none", True),),
        limits=Limits(),
        schema_version=2,
        evidence_role="canary",
        class_study_cohort_sha256=_digest("a"),
        class_study_cohort_assembly_sha256=_digest("b"),
    )
    receipt_path = tmp_path / "build-execution-v47.json"
    receipt, completion_path, completion = _write_schema5_build_pair(
        receipt_path,
        cohort_version=47,
    )
    image_id = receipt["images"]["collection"]["id"]
    environment = _study_environment(image_id)
    environment["schema_version"] = 3
    environment["build_inputs"] = dict(receipt["build_inputs"])
    environment["build_execution"] = {
        "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        "receipt": receipt,
        "completion_path": "/lab/artifacts/buflo-study/build-completion-v47.json",
        "completion_sha256": hashlib.sha256(completion_path.read_bytes()).hexdigest(),
        "completion_payload_sha256": completion["payload_sha256"],
        "completion": completion,
    }
    monkeypatch.delenv("QCSD_STUDY_ENVIRONMENT_PATH", raising=False)
    monkeypatch.setenv(
        "QCSD_STUDY_ENVIRONMENT_B64",
        base64.b64encode(json.dumps(environment).encode()).decode(),
    )

    orchestrator._materialize_study_environment(inputs, campaign, {"image_digest": image_id})
    path = inputs / "study-environment.json"
    verified = VerifiedResult(
        root=root,
        experiment={"configuration": {"study_environment_sha256": sha256_file(path)}},
        checksums={},
        accepted_samples={},
    )

    validated = attestation._validate_result_environment(verified, {"image_digest": image_id})
    assert validated["image_id"] == image_id
    assert validated["capture_scheduler"]["client_affinity_cpus"] == [10]


def test_acquisition_toolchain_must_match_current_image_and_neqo_source() -> None:
    source = _source()
    prepare_image = f"sha256:{_digest('8')}"
    build = {"images": {"prepare": {"id": prepare_image}}}
    acquisition_source = {**source, "image_digest": prepare_image}
    observed = {
        "chromium_version": attestation.EXPECTED_CHROMIUM_VERSION,
        "neqo_provenance": {
            "neqo_version": "neqo-qcsd 1",
            "neqo_base_commit": "5" * 40,
            "published_qcsd_commit": "6" * 40,
            "migration_commit": source["neqo_commit"],
        },
        "image_digest": prepare_image,
        "source": acquisition_source,
    }
    assert (
        attestation._require_acquisition_toolchain(observed, source=source, build_receipt=build)
        == observed
    )
    substituted = {
        **observed,
        "neqo_provenance": {
            **observed["neqo_provenance"],
            "migration_commit": "7" * 40,
        },
    }
    with pytest.raises(ValueError, match="current source/build"):
        attestation._require_acquisition_toolchain(substituted, source=source, build_receipt=build)

    for forged_version in ("forged-browser 0", "", 143, True):
        substituted = {**observed, "chromium_version": forged_version}
        with pytest.raises(ValueError, match="current source/build"):
            attestation._require_acquisition_toolchain(
                substituted,
                source=source,
                build_receipt=build,
            )


def test_foundation_runtime_accepts_only_bound_collection_or_prepare_image(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = _source()
    prepare_image = f"sha256:{_digest('8')}"
    build = tmp_path / "build.json"
    build.write_text("{}\n", encoding="utf-8")
    payload = {"source": source, "cohort_version": 23}
    attestation._validate_foundation_runtime(
        payload,
        runtime_role=None,
        build_execution_receipt=build,
    )
    monkeypatch.setattr(
        attestation,
        "validate_build_execution_receipt",
        lambda *_args, **_kwargs: {"images": {"prepare": {"id": prepare_image}}},
    )

    monkeypatch.setattr(attestation, "source_metadata", lambda: source)
    attestation._validate_foundation_runtime(
        payload,
        runtime_role="collection",
        build_execution_receipt=build,
    )
    monkeypatch.setattr(
        attestation,
        "source_metadata",
        lambda: {**source, "image_digest": prepare_image},
    )
    attestation._validate_foundation_runtime(
        payload,
        runtime_role="prepare",
        build_execution_receipt=build,
    )
    monkeypatch.setattr(
        attestation,
        "source_metadata",
        lambda: {**source, "image_digest": f"sha256:{_digest('9')}"},
    )
    with pytest.raises(ValueError, match="prepare runtime"):
        attestation._validate_foundation_runtime(
            payload,
            runtime_role="prepare",
            build_execution_receipt=build,
        )


def test_foundation_binds_pinned_cdp_and_seventh_browser_egress_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = _source()
    prepare_image = f"sha256:{_digest('8')}"
    files = {
        name: tmp_path / f"{name}.json"
        for name in ("build", "pinned", "reference", "code", "controlled")
    }
    for path in files.values():
        path.write_text("{}\n", encoding="utf-8")
    regression_root = tmp_path / "regression"
    controlled_root = tmp_path / "controlled-result"
    for root in (regression_root, controlled_root):
        root.mkdir()
        (root / "evidence.sha256").write_text("seal\n", encoding="utf-8")

    build_sha256 = sha256_file(files["build"])
    build_identity = {
        "cohort_version": 23,
        "sha256": build_sha256,
        **_completion_identity(),
        "collection_image": source["image_digest"],
        "started_at": "2026-08-28T00:00:00+00:00",
        "finished_at": "2026-08-28T01:00:00+00:00",
    }
    build = {
        **build_identity,
        "path": str(files["build"].resolve()),
        "completion_path": str(
            files["build"].with_name("build-completion-v23.json").resolve()
        ),
        "payload_sha256": _digest("5"),
        "source": source,
        "images": {
            "collection": {"id": source["image_digest"]},
            "prepare": {"id": prepare_image},
            "reference": {"id": f"sha256:{_digest('9')}"},
        },
    }
    build_binding = {"path": build["path"], "sha256": build_sha256}
    environment = {"build_execution": build_identity}
    pinned = {
        "probe_schema_version": attestation.PINNED_CDP_PROBE_SCHEMA_VERSION,
        "path": str(files["pinned"].resolve()),
        "sha256": sha256_file(files["pinned"]),
        "payload_sha256": _digest("6"),
        "recorded_at": "2026-08-28T02:00:00+00:00",
        "build_execution": {
            "path": "/lab/artifacts/buflo-study/build-execution-v23.json",
            "sha256": build_sha256,
            "payload_sha256": _digest("7"),
        },
        "build_execution_identity": build_identity,
        "probe_contract_sha256": _digest("8"),
    }
    observed: dict[str, Any] = {}

    def validate_pinned(_path: Path, **kwargs: Any) -> dict[str, Any]:
        observed.update(kwargs)
        return dict(pinned)

    monkeypatch.setattr(attestation, "validate_build_execution_receipt", lambda *_a, **_k: build)
    monkeypatch.setattr(attestation, "validate_pinned_cdp_receipt", validate_pinned)
    browser_egress_root = tmp_path / "browser-egress-qualification-v23"
    browser_egress = _browser_egress_result(browser_egress_root, build)
    browser_observed: dict[str, Any] = {}

    def verify_browser(root: Path, **kwargs: Any) -> dict[str, Any]:
        browser_observed.update(root=root, **kwargs)
        return dict(browser_egress)

    monkeypatch.setattr(
        attestation,
        "verify_browser_egress_qualification",
        verify_browser,
    )
    monkeypatch.setattr(
        attestation,
        "validate_reference_gate_receipt",
        lambda *_a, **_k: {
            "sha256": sha256_file(files["reference"]),
            "profiles_checked": 8,
            "build_execution": build_identity,
        },
    )
    monkeypatch.setattr(
        attestation,
        "validate_regression_results",
        lambda *_a, **_k: {
            "samples": 18,
            "source": source,
            "results": [{"environment": environment}],
        },
    )
    monkeypatch.setattr(
        attestation,
        "validate_code_gate_receipt",
        lambda *_a, **_k: {
            "sha256": sha256_file(files["code"]),
            "source": source,
            "build_execution_receipt": build_binding,
        },
    )
    monkeypatch.setattr(
        attestation,
        "validate_qualification_receipt",
        lambda *_a, **_k: {
            "sha256": sha256_file(files["controlled"]),
            "source": source,
            "build_execution": build_binding,
            "controlled_results": {
                "samples": 160,
                "results": [{"environment": environment}],
            },
        },
    )
    monkeypatch.setattr(
        attestation, "_one_build_execution_identity", lambda _values: build_identity
    )
    kwargs = {
        "cohort_version": 23,
        "build_execution_receipt": files["build"],
        "pinned_cdp_receipt": files["pinned"],
        "browser_egress_qualification_root": browser_egress_root,
        "reference_receipt": files["reference"],
        "code_gate_receipt": files["code"],
        "controlled_qualification_receipt": files["controlled"],
        "regression_result_roots": (regression_root,),
        "controlled_result_roots": (controlled_root,),
        "recorded_at": "2026-08-28T03:00:00+00:00",
        "deep_code_gate": True,
        "evidence_source": source,
        "pinned_runtime_role": "collection",
    }

    value = attestation._foundation_value(**kwargs)

    assert value["attestation_schema_version"] == attestation.FOUNDATION_SCHEMA_VERSION
    assert value["evidence"]["pinned_cdp_probe"]["build_execution_identity"] == (
        build_identity
    )
    assert [gate["gate"] for gate in value["hard_gates"]] == list(
        attestation._FOUNDATION_GATES
    )
    assert attestation._BROWSER_EGRESS_GATE == (
        "browser-egress-packet-qualification-"
        f"{attestation.BROWSER_EGRESS_VECTOR_COUNT}-of-"
        f"{attestation.BROWSER_EGRESS_VECTOR_COUNT}"
    )
    assert value["summary"]["browser_egress_vectors"] == (
        attestation.BROWSER_EGRESS_VECTOR_COUNT
    )
    assert value["evidence"]["pinned_cdp_probe"] == attestation._pinned_cdp_binding(
        pinned
    )
    assert value["evidence"]["browser_egress_qualification"] == (
        attestation._browser_egress_binding(browser_egress, browser_egress_root)
    )
    assert observed == {
        "build_execution_receipt": files["build"],
        "expected_cohort_version": 23,
        "runtime_role": "collection",
        "allow_historical": False,
    }
    assert files["pinned"] in attestation._protected_foundation_inputs(kwargs)
    assert browser_egress_root in attestation._protected_foundation_inputs(kwargs)
    assert browser_observed == {
        "root": browser_egress_root,
        "lab_root": attestation.LAB_ROOT,
        "expected_cohort_version": 23,
        "allow_historical": False,
    }
    observed.clear()
    assert attestation._foundation_value(**{**kwargs, "pinned_runtime_role": None}) == value
    assert observed["runtime_role"] is None

    pinned["recorded_at"] = "2026-08-28T04:00:00+00:00"
    with pytest.raises(ValueError, match="build finish <= pinned CDP probe <= foundation"):
        attestation._foundation_value(**kwargs)
    pinned["recorded_at"] = "2026-08-28T02:00:00+00:00"
    browser_egress["recorded_at"] = "2026-08-28T04:00:00+00:00"
    with pytest.raises(ValueError, match="browser-egress start"):
        attestation._foundation_value(**kwargs)


@pytest.mark.parametrize(
    "mutation",
    (
        lambda receipt: receipt.update(
            passed_vector_count=attestation.BROWSER_EGRESS_VECTOR_COUNT - 1
        ),
        lambda receipt: receipt.update(expanded_vectors_sha256=_digest("f")),
        lambda receipt: receipt["build_execution"].update(sha256=_digest("c")),
        lambda receipt: receipt["build_execution"].update(
            reference_image_id=f"sha256:{_digest('d')}"
        ),
        lambda receipt: receipt.update(prepare_image_id=f"sha256:{_digest('e')}"),
    ),
)
def test_browser_egress_gate_rejects_incomplete_or_different_build(
    mutation, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    build_path = tmp_path / "build.json"
    build_path.write_text("{}\n", encoding="utf-8")
    build = {
        "path": str(build_path.absolute()),
        "sha256": sha256_file(build_path),
        "payload_sha256": _digest("1"),
        "completion_sha256": _completion_identity()["completion_sha256"],
        "images": {
            "collection": {"id": f"sha256:{_digest('2')}"},
            "prepare": {"id": f"sha256:{_digest('3')}"},
            "reference": {"id": f"sha256:{_digest('4')}"},
        },
    }
    root = tmp_path / "browser-egress-qualification-v23"
    receipt = _browser_egress_result(root, build)
    mutation(receipt)
    monkeypatch.setattr(
        attestation,
        "verify_browser_egress_qualification",
        lambda *_a, **_k: receipt,
    )
    with pytest.raises(ValueError, match="different source/build/image"):
        attestation._validate_browser_egress_qualification(
            root, cohort_version=23, build=build
        )


@pytest.mark.parametrize("diagnostic", ("capture dropped packets", "resealed PCAP differs"))
def test_browser_egress_gate_propagates_deep_packet_verification_failure(
    diagnostic: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "browser-egress-qualification-v23"
    root.mkdir()

    def reject(*_args, **_kwargs):
        raise ValueError(diagnostic)

    monkeypatch.setattr(attestation, "verify_browser_egress_qualification", reject)
    with pytest.raises(ValueError, match=diagnostic):
        attestation._validate_browser_egress_qualification(
            root,
            cohort_version=23,
            build={
                "path": str(tmp_path / "build.json"),
                "images": {
                    "collection": {},
                    "prepare": {},
                    "reference": {},
                },
            },
        )


def test_foundation_validator_rejects_resealed_missing_pinned_cdp_gate(
    tmp_path: Path,
) -> None:
    evidence_file = tmp_path / "evidence.json"
    evidence_file.write_text("{}\n", encoding="utf-8")
    binding = attestation._file_binding(evidence_file)
    gate_evidence = {gate: [_digest("a")] for gate in attestation._FOUNDATION_GATES}
    payload = {
        "attestation_schema_version": attestation.FOUNDATION_SCHEMA_VERSION,
        "artifact_type": attestation.FOUNDATION_RECEIPT_TYPE,
        "study_id": attestation.STUDY_ID,
        "cohort_version": 23,
        "recorded_at": "2026-08-28T03:00:00+00:00",
        "implementation_status": "foundation-ready-for-class-acquisition",
        "promotion_authority": False,
        "implementation_scope": attestation.IMPLEMENTATION_SCOPE,
        "paper_equivalent": False,
        "no_waivers": True,
        "source": _source(),
        "build_execution_identity": {},
        "evidence": {
            "build_execution": binding,
            "reference": binding,
            "code_gate": binding,
            "controlled_qualification": binding,
            "regression_results": [],
            "controlled_results": [],
        },
        "summary": {},
        "hard_gates": attestation._hard_gate_records(
            attestation._FOUNDATION_GATES, gate_evidence
        ),
        "all_foundation_gates_passed": True,
    }
    path = tmp_path / "foundation.json"
    path.write_bytes(
        canonical_json_bytes(
            bind_receipt(payload, receipt_type=attestation.FOUNDATION_RECEIPT_TYPE)
        )
    )

    with pytest.raises(ValueError, match="pinned CDP probe binding"):
        attestation.validate_class_foundation_attestation(path)


def test_hard_gate_inventory_is_ordered_typed_and_nonempty() -> None:
    evidence = {
        gate: [_digest(str((index % 8) + 1))]
        for index, gate in enumerate(attestation._READINESS_GATES)
    }
    records = attestation._hard_gate_records(attestation._READINESS_GATES, evidence)
    attestation._validate_hard_gates(records, attestation._READINESS_GATES)
    records[0]["gate"] = records[1]["gate"]
    with pytest.raises(ValueError, match="hard gate"):
        attestation._validate_hard_gates(records, attestation._READINESS_GATES)


@pytest.mark.parametrize(
    ("schema", "retains_identity"),
    (
        (8, False),
        (9, True),
        (11, True),
        (12, True),
        (13, True),
        (14, True),
        (16, True),
        (17, True),
        (attestation.PINNED_CDP_PROBE_SCHEMA_VERSION, True),
    ),
)
def test_pinned_cdp_binding_preserves_schema_specific_identity_shape(
    tmp_path: Path,
    schema: int,
    retains_identity: bool,
) -> None:
    receipt_path = tmp_path / f"pinned-cdp-schema{schema}.json"
    receipt_path.write_text("historical pinned CDP\n", encoding="utf-8")
    receipt = {
        "path": str(receipt_path.resolve()),
        "sha256": sha256_file(receipt_path),
        "payload_sha256": _digest("1"),
        "probe_contract_sha256": _digest("2"),
        "probe_schema_version": schema,
        "build_execution": {"path": "/lab/build.json", "sha256": _digest("3")},
        "build_execution_identity": {"completion_sha256": _digest("4")},
    }

    binding = attestation._pinned_cdp_binding(receipt)
    assert ("build_execution_identity" in binding) is retains_identity
    if retains_identity:
        assert binding["build_execution_identity"] == receipt[
            "build_execution_identity"
        ]
        assert attestation._pinned_cdp_path_from_binding(binding) == receipt_path.resolve()
    else:
        with pytest.raises(ValueError, match="pinned CDP probe binding"):
            attestation._pinned_cdp_path_from_binding(binding)
    assert attestation._pinned_cdp_path_from_binding(
        binding,
        allow_historical=True,
    ) == receipt_path.resolve()


def test_stale_base_attestation_schemas_cannot_satisfy_current_admission() -> None:
    foundation = {
        "attestation_schema_version": 2,
        "artifact_type": attestation.FOUNDATION_RECEIPT_TYPE,
        "study_id": attestation.STUDY_ID,
    }
    readiness = {
        "attestation_schema_version": 1,
        "artifact_type": attestation.READINESS_RECEIPT_TYPE,
        "study_id": attestation.STUDY_ID,
    }
    with pytest.raises(ValueError, match="foundation promotion envelope"):
        attestation._validate_foundation_envelope(foundation)
    with pytest.raises(ValueError, match="readiness promotion envelope"):
        attestation._validate_readiness_envelope(readiness)


def test_successor_readiness_keeps_its_separate_schema_dispatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import qcsd_lab.class_successor as successor

    path = tmp_path / "successor-readiness.json"
    payload = {
        "attestation_schema_version": 1,
        "artifact_type": attestation.READINESS_RECEIPT_TYPE,
        "study_id": "classifier-multiorigin100-v2-g01-abcdef123456",
    }
    path.write_bytes(
        canonical_json_bytes(
            bind_receipt(payload, receipt_type=attestation.READINESS_RECEIPT_TYPE)
        )
    )
    observed: dict[str, Any] = {}

    def validate(candidate: Path, *, deep_code_gate: bool) -> dict[str, Any]:
        observed.update(path=candidate, deep=deep_code_gate)
        return {"successor": True}

    monkeypatch.setattr(successor, "validate_successor_readiness", validate)
    assert attestation.validate_class_readiness_attestation(path) == {"successor": True}
    assert observed == {"path": path.resolve(), "deep": True}

def test_formal_evidence_retains_and_rejects_mixed_capture_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "formal"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    (root / "evidence.sha256").write_text("seal\n", encoding="utf-8")
    files = {
        "inputs/class-study-launch.json": "launch\n",
        "inputs/class-study-foundation.json": "foundation\n",
        "inputs/class-study-readiness.json": "readiness\n",
        "inputs/class-study-historical-pre-snapshot.json": "pre\n",
    }
    for relative, content in files.items():
        (root / relative).write_text(content, encoding="utf-8")
    digests = {relative: sha256_file(root / relative) for relative in files}
    verified = VerifiedResult(
        root=root,
        experiment={
            "configuration": {
                "evidence_role": "formal",
                "class_study_launch_sha256": digests["inputs/class-study-launch.json"],
                "class_study_foundation_sha256": digests["inputs/class-study-foundation.json"],
                "class_study_readiness_sha256": digests["inputs/class-study-readiness.json"],
                "class_study_historical_pre_snapshot_sha256": digests[
                    "inputs/class-study-historical-pre-snapshot.json"
                ],
            }
        },
        checksums=digests,
        accepted_samples={},
    )
    monkeypatch.setattr(attestation, "verify_result", lambda _path: verified)

    binding = attestation._class_result_binding(root)
    assert binding["class_study_readiness_sha256"] == digests["inputs/class-study-readiness.json"]
    assert (
        binding["class_study_historical_pre_snapshot_sha256"]
        == digests["inputs/class-study-historical-pre-snapshot.json"]
    )
    record = {
        "class_study_foundation_sha256": binding["class_study_foundation_sha256"],
        "class_study_readiness_sha256": binding["class_study_readiness_sha256"],
        "class_study_historical_pre_snapshot_sha256": binding[
            "class_study_historical_pre_snapshot_sha256"
        ],
    }
    attestation._require_formal_authority_bindings(
        record,
        dict(record),
        foundation_sha256=record["class_study_foundation_sha256"],
        readiness_sha256=record["class_study_readiness_sha256"],
        historical_pre_sha256=record["class_study_historical_pre_snapshot_sha256"],
    )
    mixed = {**record, "class_study_readiness_sha256": _digest("f")}
    with pytest.raises(ValueError, match="different foundation/readiness/pre-formal authority"):
        attestation._require_formal_authority_bindings(
            record,
            mixed,
            foundation_sha256=record["class_study_foundation_sha256"],
            readiness_sha256=record["class_study_readiness_sha256"],
            historical_pre_sha256=record["class_study_historical_pre_snapshot_sha256"],
        )


@pytest.mark.parametrize(
    "role",
    (
        "pilot-fitting",
        "pilot-compatibility",
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    ),
)
def test_every_class_result_role_requires_sealed_foundation_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    root = tmp_path / role
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    (root / "evidence.sha256").write_text("seal\n", encoding="utf-8")
    files = {
        attestation.CLASS_STUDY_LAUNCH_INPUT: "launch\n",
        attestation._CLASS_STUDY_FOUNDATION_INPUT: "foundation\n",
    }
    if role in {"canary", "formal"}:
        files.update(
            {
                attestation._CLASS_STUDY_READINESS_INPUT: "readiness\n",
                attestation._CLASS_STUDY_HISTORICAL_PRE_INPUT: "pre\n",
            }
        )
    for relative, content in files.items():
        (root / relative).write_text(content, encoding="utf-8")
    digests = {relative: sha256_file(root / relative) for relative in files}
    configuration = {
        "evidence_role": role,
        "class_study_launch_sha256": digests[attestation.CLASS_STUDY_LAUNCH_INPUT],
    }
    if role in {"canary", "formal"}:
        configuration.update(
            class_study_readiness_sha256=digests[attestation._CLASS_STUDY_READINESS_INPUT],
            class_study_historical_pre_snapshot_sha256=digests[
                attestation._CLASS_STUDY_HISTORICAL_PRE_INPUT
            ],
        )
    verified = VerifiedResult(
        root=root,
        experiment={"configuration": configuration},
        checksums=digests,
        accepted_samples={},
    )
    monkeypatch.setattr(attestation, "verify_result", lambda _path: verified)

    with pytest.raises(ValueError, match="lacks required class_study_foundation"):
        attestation._class_result_binding(root)

    configuration["class_study_foundation_sha256"] = digests[
        attestation._CLASS_STUDY_FOUNDATION_INPUT
    ]
    assert (
        attestation._class_result_binding(root)["class_study_foundation_sha256"]
        == configuration["class_study_foundation_sha256"]
    )


def test_preformal_class_result_forbids_readiness_and_history_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "certification"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    (root / "evidence.sha256").write_text("seal\n", encoding="utf-8")
    for name, content in (
        (attestation.CLASS_STUDY_LAUNCH_INPUT, "launch\n"),
        (attestation._CLASS_STUDY_FOUNDATION_INPUT, "foundation\n"),
        (attestation._CLASS_STUDY_READINESS_INPUT, "unexpected\n"),
    ):
        (root / name).write_text(content, encoding="utf-8")
    checksums = {
        name: sha256_file(root / name)
        for name in (
            attestation.CLASS_STUDY_LAUNCH_INPUT,
            attestation._CLASS_STUDY_FOUNDATION_INPUT,
            attestation._CLASS_STUDY_READINESS_INPUT,
        )
    }
    verified = VerifiedResult(
        root=root,
        experiment={
            "configuration": {
                "evidence_role": "certification",
                "class_study_launch_sha256": checksums[attestation.CLASS_STUDY_LAUNCH_INPUT],
                "class_study_foundation_sha256": checksums[
                    attestation._CLASS_STUDY_FOUNDATION_INPUT
                ],
            }
        },
        checksums=checksums,
        accepted_samples={},
    )
    monkeypatch.setattr(attestation, "verify_result", lambda _path: verified)
    with pytest.raises(ValueError, match="unexpected class_study_readiness"):
        attestation._class_result_binding(root)


def test_final_runtime_binding_rejects_parameter_and_manifest_drift() -> None:
    parameters = {
        "traffic-morphing": _digest("a"),
        "wtf-pad": _digest("b"),
        "walkie-talkie": _digest("c"),
        "buflo": _digest("d"),
        "cs-buflo": _digest("e"),
    }
    certification = _runtime_inputs(attestation.COMPATIBILITY_MODES, parameters)
    manifest_sha256 = _digest("7")
    canary = {
        "defense_runtime_inputs": {"undefended": certification["undefended"]},
        "chaff_qualification_set_manifest_sha256": None,
    }
    formal = {
        "defense_runtime_inputs": {mode: certification[mode] for mode in attestation.FORMAL_MODES},
        "chaff_qualification_set_manifest_sha256": manifest_sha256,
    }
    attestation._require_final_runtime_bindings(
        canary,
        formal,
        block=1,
        certification_runtime_inputs=certification,
        final_qualification_manifest_sha256=manifest_sha256,
    )

    drifted = json.loads(json.dumps(formal))
    drifted["defense_runtime_inputs"]["traffic-morphing"]["parameters_sha256"] = _digest("f")
    with pytest.raises(ValueError, match="different runtime inputs"):
        attestation._require_final_runtime_bindings(
            canary,
            drifted,
            block=1,
            certification_runtime_inputs=certification,
            final_qualification_manifest_sha256=manifest_sha256,
        )

    drifted = {**formal, "chaff_qualification_set_manifest_sha256": _digest("f")}
    with pytest.raises(ValueError, match="different qualification manifest"):
        attestation._require_final_runtime_bindings(
            canary,
            drifted,
            block=1,
            certification_runtime_inputs=certification,
            final_qualification_manifest_sha256=manifest_sha256,
        )


def test_formal_capture_requires_strictly_later_canary_completion() -> None:
    canary = {"completed_at": "2026-08-29T10:00:00+10:00"}
    attestation._require_canary_before_formal(
        canary, {"started_at": "2026-08-29T10:00:00.000001+10:00"}
    )
    with pytest.raises(ValueError, match="did not follow"):
        attestation._require_canary_before_formal(canary, {"started_at": canary["completed_at"]})


def test_final_gate_requires_correctness_performance_and_full_replay() -> None:
    complete = _evaluation()
    result = attestation._require_evaluation_completion(complete, require_full_replay=True)
    assert result["correctness"]["passed"] is True
    assert result["performance"]["bootstrap"]["draws"] == 10_000
    assert result["candidate_algorithm"]["sample_count"] == 4_000
    assert result["dlsvm_preflight"]["admission"]["wall_time_available"] is True
    assert (
        result["dlsvm_execution_model_sha256"]
        == attestation.class_evaluation.CLASS_DLSVM_EXECUTION_MODEL_SHA256
    )

    attack_only = dict(complete)
    attack_only.pop("correctness")
    with pytest.raises(ValueError, match="client-correctness"):
        attestation._require_evaluation_completion(attack_only, require_full_replay=True)
    with pytest.raises(ValueError, match="fully and deeply replayed"):
        attestation._require_evaluation_completion(
            _evaluation(full_replay=False), require_full_replay=True
        )
    missing_preflight = _evaluation()
    missing_preflight.pop("dlsvm_capacity_preflight")
    with pytest.raises(ValueError, match="DLSVM capacity preflight"):
        attestation._require_evaluation_completion(
            missing_preflight,
            require_full_replay=True,
        )
    wrong_execution_model = _evaluation()
    wrong_execution_model["dlsvm_capacity_preflight"]["execution_model"] = {
        **attestation.class_evaluation.CLASS_DLSVM_EXECUTION_MODEL,
        "total_full_matrix_passes": 1,
    }
    with pytest.raises(ValueError, match="DLSVM capacity preflight"):
        attestation._require_evaluation_completion(
            wrong_execution_model,
            require_full_replay=True,
        )
    stale_capacity = _evaluation()
    stale_capacity["verification_strength"]["dlsvm_current_capacity_admitted"] = False
    with pytest.raises(ValueError, match="fully and deeply replayed"):
        attestation._require_evaluation_completion(
            stale_capacity,
            require_full_replay=True,
        )
    incomplete_algorithm = _evaluation()
    incomplete_algorithm["candidate_algorithm"]["breakdowns"]["strata"].pop()
    with pytest.raises(ValueError, match="directional coverage"):
        attestation._require_evaluation_completion(
            incomplete_algorithm,
            require_full_replay=True,
        )


def test_successor_full_final_lineage_reconstructs_positive_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise one coherent v2 readiness-to-promotion lineage end to end."""

    import qcsd_lab.class_pipeline as pipeline

    source = _source()
    study_id = f"classifier-multiorigin100-v2-g01-{_digest('a')[:12]}"
    foundation = tmp_path / "foundation.json"
    restart = tmp_path / "successor-restart.json"
    readiness_path = tmp_path / "readiness.json"
    historical_pre = tmp_path / "historical-pre.json"
    historical_post = tmp_path / "historical-post.json"
    evaluation_path = tmp_path / "evaluation.json"
    comparison_path = tmp_path / "comparison.json"
    for path in (
        foundation,
        restart,
        readiness_path,
        historical_pre,
        historical_post,
        evaluation_path,
        comparison_path,
    ):
        path.write_text(f"{path.name}\n", encoding="utf-8")

    certification_root = tmp_path / "certification"
    certification_root.mkdir()
    (certification_root / "evidence.sha256").write_text("certification seal\n", encoding="utf-8")
    certification_binding = {
        "root": str(certification_root.resolve()),
        "evidence_sha256": sha256_file(certification_root / "evidence.sha256"),
    }
    parameters = {
        mode: hashlib.sha256(mode.encode()).hexdigest() for mode in attestation._PARAMETER_MODES
    }
    runtime_inputs = _runtime_inputs(attestation.COMPATIBILITY_MODES, parameters)
    qualification_sha256 = _digest("7")
    build_identity = {
        "cohort_version": 23,
        "sha256": _digest("5"),
        **_completion_identity(),
        "collection_image": source["image_digest"],
        "started_at": "2026-08-29T00:00:00+10:00",
        "finished_at": "2026-08-29T01:00:00+10:00",
    }
    readiness = {
        "study_id": study_id,
        "cohort_version": 23,
        "source": source,
        "build_execution_identity": build_identity,
        "evidence": {
            "foundation": attestation._file_binding(foundation),
            "successor_restart": attestation._file_binding(restart),
            "certification_result": certification_binding,
        },
        "summary": {
            "certification_defense_runtime_inputs": runtime_inputs,
            "certification_defense_parameter_sha256": parameters,
            "final_qualification_set_manifest_sha256": qualification_sha256,
        },
    }
    monkeypatch.setattr(
        attestation,
        "validate_class_readiness_attestation",
        lambda *_args, **_kwargs: readiness,
    )
    monkeypatch.setattr(attestation, "source_metadata", lambda: source)
    monkeypatch.setattr(attestation, "_admission_from_readiness", lambda _value: object())

    readiness_sha256 = sha256_file(readiness_path)
    pre_sha256 = sha256_file(historical_pre)
    foundation_sha256 = sha256_file(foundation)
    successor_sha256 = sha256_file(restart)
    canary_roots: list[Path] = []
    formal_roots: list[Path] = []
    records: dict[Path, dict[str, Any]] = {}
    bindings: dict[Path, dict[str, Any]] = {}
    verified: dict[Path, VerifiedResult] = {}
    for block in range(1, attestation.FORMAL_BLOCK_COUNT + 1):
        for role in ("canary", "formal"):
            root = tmp_path / f"{role}-{block:02d}"
            root.mkdir()
            (root / "evidence.sha256").write_text(f"{role} {block} seal\n", encoding="utf-8")
            evidence_sha256 = sha256_file(root / "evidence.sha256")
            launch_sha256 = hashlib.sha256(f"{role}-{block}-launch".encode()).hexdigest()
            binding = {
                "root": str(root.resolve()),
                "evidence_sha256": evidence_sha256,
                "class_study_launch_sha256": launch_sha256,
                "class_study_foundation_sha256": foundation_sha256,
                "class_study_readiness_sha256": readiness_sha256,
                "class_study_historical_pre_snapshot_sha256": pre_sha256,
                "class_study_id": study_id,
                "class_study_successor_sha256": successor_sha256,
            }
            record = {
                **binding,
                "evidence_role": role,
                "block": block,
                "samples": (attestation.FINAL_CLASS_COUNT if role == "canary" else 1_600),
                "defense_runtime_inputs": (
                    {"undefended": runtime_inputs["undefended"]}
                    if role == "canary"
                    else {mode: runtime_inputs[mode] for mode in attestation.FORMAL_MODES}
                ),
                "defense_parameter_sha256": ({} if role == "canary" else parameters),
                "chaff_qualification_set_manifest_sha256": (
                    None if role == "canary" else qualification_sha256
                ),
            }
            started_minute = 10 + block * 2 + (2 if role == "formal" else 0)
            completed_minute = started_minute + 1
            verified[root.resolve()] = VerifiedResult(
                root=root.resolve(),
                experiment={
                    "source": source,
                    "started_at": f"2026-08-29T02:{started_minute:02d}:00+10:00",
                    "completed_at": f"2026-08-29T02:{completed_minute:02d}:00+10:00",
                },
                checksums={},
                accepted_samples={},
            )
            records[root.resolve()] = record
            bindings[root.resolve()] = binding
            (canary_roots if role == "canary" else formal_roots).append(root)

    certified = VerifiedResult(
        root=certification_root.resolve(),
        experiment={"completed_at": "2026-08-29T01:00:00+10:00"},
        checksums={},
        accepted_samples={},
    )

    def verify_class_result(
        path: Path,
        *,
        expected_role: str,
        expected_block: int,
        **_kwargs,
    ) -> dict[str, Any]:
        record = records[Path(path).resolve()]
        if record["evidence_role"] != expected_role:
            raise ValueError("class-study result has the wrong expected evidence role")
        if record["block"] != expected_block:
            raise ValueError("class-study result has the wrong acquisition block")
        return record

    monkeypatch.setattr(pipeline, "verify_class_study_result", verify_class_result)
    monkeypatch.setattr(
        attestation,
        "_class_result_binding",
        lambda path: bindings[Path(path).resolve()],
    )
    monkeypatch.setattr(
        attestation,
        "verify_result",
        lambda path: (
            certified
            if Path(path).resolve() == certification_root.resolve()
            else verified[Path(path).resolve()]
        ),
    )
    monkeypatch.setattr(
        attestation,
        "_validate_result_environment",
        lambda *_args, **_kwargs: {"build_execution": build_identity},
    )

    pre_value = {
        "study_id": study_id,
        "source": source,
        "recorded_at": "2026-08-29T01:30:00+10:00",
        "readiness": attestation._file_binding(readiness_path),
        "historical_corpus_guard_sha256": _digest("6"),
    }
    post_value = {
        **pre_value,
        "recorded_at": "2026-08-29T03:00:00+10:00",
        "pre_formal_snapshot": attestation._file_binding(historical_pre),
        "formal_results": [bindings[path.resolve()] for path in formal_roots],
        "payload_sha256": _digest("8"),
    }
    monkeypatch.setattr(
        attestation,
        "validate_class_historical_snapshot",
        lambda path, **_kwargs: (
            pre_value if Path(path).resolve() == historical_pre.resolve() else post_value
        ),
    )

    reconstructed = attestation._validate_post_snapshot_formal_results(
        readiness=readiness,
        readiness_attestation=readiness_path,
        pre=pre_value,
        pre_snapshot=historical_pre,
        formal_result_roots=formal_roots,
        recorded_at=attestation._aware_timestamp(
            post_value["recorded_at"], label="fixture post snapshot"
        ),
    )
    assert reconstructed == post_value["formal_results"]
    with pytest.raises(ValueError, match="wrong acquisition block"):
        attestation._validate_post_snapshot_formal_results(
            readiness=readiness,
            readiness_attestation=readiness_path,
            pre=pre_value,
            pre_snapshot=historical_pre,
            formal_result_roots=[formal_roots[1], formal_roots[0], *formal_roots[2:]],
            recorded_at=attestation._aware_timestamp(
                post_value["recorded_at"], label="fixture post snapshot"
            ),
        )
    records[formal_roots[0].resolve()]["evidence_role"] = "canary"
    with pytest.raises(ValueError, match="wrong expected evidence role"):
        attestation._validate_post_snapshot_formal_results(
            readiness=readiness,
            readiness_attestation=readiness_path,
            pre=pre_value,
            pre_snapshot=historical_pre,
            formal_result_roots=formal_roots,
            recorded_at=attestation._aware_timestamp(
                post_value["recorded_at"], label="fixture post snapshot"
            ),
        )
    records[formal_roots[0].resolve()]["evidence_role"] = "formal"
    with pytest.raises(ValueError, match="predates formal block completion"):
        attestation._validate_post_snapshot_formal_results(
            readiness=readiness,
            readiness_attestation=readiness_path,
            pre=pre_value,
            pre_snapshot=historical_pre,
            formal_result_roots=formal_roots,
            recorded_at=attestation._aware_timestamp(
                "2026-08-29T02:00:00+10:00", label="fixture early post snapshot"
            ),
        )

    handoff = tmp_path / "handoff"
    handoff.mkdir()
    embedded_post = handoff / attestation.CLASS_STUDY_HISTORICAL_POST_INPUT
    embedded_post.parent.mkdir(parents=True)
    embedded_post.write_bytes(historical_post.read_bytes())
    blocks = [
        {
            "result_root": str(path.resolve()),
            "result_evidence_sha256": bindings[path.resolve()]["evidence_sha256"],
        }
        for path in formal_roots
    ]
    dataset = {
        "study_id": study_id,
        "sample_count": attestation.FORMAL_SAMPLE_COUNT,
        "class_count": attestation.FINAL_CLASS_COUNT,
        "modes": list(attestation.FORMAL_MODES),
        "blocks": blocks,
        "execution_source": {"value": source},
        "exporter_source": source,
        "historical_post_snapshot": {
            "path": attestation.CLASS_STUDY_HISTORICAL_POST_INPUT,
            "sha256": sha256_file(historical_post),
            "payload_sha256": post_value["payload_sha256"],
        },
    }
    (handoff / "dataset.json").write_text(
        json.dumps(dataset, sort_keys=True) + "\n", encoding="utf-8"
    )
    (handoff / "samples.jsonl").write_text("{}\n", encoding="utf-8")
    (handoff / "SHA256SUMS").write_text("synthetic closed handoff\n", encoding="utf-8")
    monkeypatch.setattr(attestation, "verify_class_handoff", lambda *_a, **_k: handoff)

    launch_blocks = [
        {
            "block": block,
            "path": f"{attestation.CLASS_STUDY_LAUNCHES_PATH}/block-{block:02d}.json",
            "sha256": bindings[path.resolve()]["class_study_launch_sha256"],
        }
        for block, path in enumerate(formal_roots, start=1)
    ]
    launches = {
        "source_path": attestation.CLASS_STUDY_LAUNCH_INPUT,
        "blocks": launch_blocks,
        "bindings_sha256": attestation.canonical_json_sha256(launch_blocks),
    }
    evaluation = {
        **_evaluation(),
        "study_id": study_id,
        "class_study_launches": launches,
        "handoff": {"class_study_launches_sha256": attestation.canonical_json_sha256(launches)},
    }
    monkeypatch.setattr(
        attestation.class_evaluation,
        "verify_class_evaluation_receipt",
        lambda *_args, **_kwargs: evaluation,
    )
    monkeypatch.setattr(
        attestation,
        "validate_class_comparison_review",
        lambda *_args, **_kwargs: {
            "study_id": study_id,
            "reviewed_metric_count": 42,
        },
    )

    destination = tmp_path / "validation-attestation.json"
    created = attestation.create_class_validation_attestation(
        destination,
        readiness_attestation=readiness_path,
        canary_result_roots=canary_roots,
        formal_result_roots=formal_roots,
        historical_pre_snapshot=historical_pre,
        historical_post_snapshot=historical_post,
        handoff=handoff,
        evaluation_receipt=evaluation_path,
        comparison_review=comparison_path,
    )
    final = attestation.validate_class_validation_attestation(created)

    assert final["study_id"] == study_id
    assert final["promotion_authority"] is True
    assert final["summary"]["canary_samples"] == 1_000
    assert final["summary"]["formal_samples"] == 16_000
    assert final["evidence"]["successor_restart"] == attestation._file_binding(restart)
    assert len(final["evidence"]["canary_results"]) == 10
    assert len(final["evidence"]["formal_results"]) == 10

    embedded_post.write_text("substituted embedded post\n", encoding="utf-8")
    with pytest.raises(ValueError, match="handoff differs from formal source evidence"):
        attestation.validate_class_validation_attestation(
            created,
            deep_code_gate=False,
        )


def test_comparison_review_is_exhaustive_hash_bound_and_create_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    handoff = tmp_path / "handoff"
    handoff.mkdir()
    for name in ("SHA256SUMS", "dataset.json", "samples.jsonl"):
        (handoff / name).write_text(f"{name}\n", encoding="utf-8")
    evaluation_receipt = tmp_path / "evaluation.json"
    evaluation_receipt.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(attestation, "verify_class_handoff", lambda path, **_kwargs: Path(path))
    monkeypatch.setattr(
        attestation.class_evaluation,
        "verify_class_evaluation_receipt",
        lambda *_args, **_kwargs: _evaluation(full_replay=False),
    )

    evaluation = _evaluation(full_replay=False)
    rows = attestation.original_study_comparison_rows()
    inventory = attestation.historical_anchor_metric_inventory(rows)
    pairs = attestation._comparison_pairs(rows, inventory, evaluation)
    template = attestation.build_class_comparison_review_template(
        handoff=handoff,
        evaluation_receipt=evaluation_receipt,
    )
    assert template["comparison_rows"] == pairs
    assert all(review["disposition"] is None for review in template["reviews"])
    reviews = []
    for pair in pairs:
        qcsd = pair["qcsd_value"]
        if qcsd is None:
            disposition = "not-comparable"
            comparison = "the QCSD counterpart is unavailable under the registered attack inventory"
        else:
            disposition = "expected"
            comparison = (
                f"published {attestation._comparison_number_token(pair['published_value'])} "
                f"and QCSD {attestation._comparison_number_token(qcsd)} have the "
                "recorded discrepancy"
            )
        reviews.append(
            {
                "defense": pair["defense"],
                "anchor_id": pair["anchor_id"],
                "metric": pair["metric"],
                "pair_sha256": pair["pair_sha256"],
                "disposition": disposition,
                "explanation": (
                    f"For {pair['anchor_id']} metric {pair['metric']}, {comparison}; the "
                    f"{pair['defense']} published and QCSD transport, endpoints, dataset, "
                    "observer accounting, padding semantics, and classifier protocol "
                    "differ materially."
                ),
                "context_differences": sorted(attestation._COMPARISON_CONTEXT_FIELDS),
            }
        )

    destination = tmp_path / "comparison.json"
    output = attestation.create_class_comparison_review(
        destination,
        handoff=handoff,
        evaluation_receipt=evaluation_receipt,
        reviewer="Thesis researcher",
        reviewed_at="2026-08-28T20:00:00+10:00",
        reviews=reviews,
    )
    verified = attestation.validate_class_comparison_review(output)
    assert verified["reviewed_metric_count"] == len(reviews)
    assert verified["unexplained_discrepancies"] == 0
    assert verified["comparison_rows_sha256"] == attestation.canonical_json_sha256(
        verified["comparison_rows"]
    )
    assert all("absolute_discrepancy" in row for row in verified["comparison_rows"])
    with pytest.raises(FileExistsError):
        attestation.create_class_comparison_review(
            destination,
            handoff=handoff,
            evaluation_receipt=evaluation_receipt,
            reviewer="Thesis researcher",
            reviewed_at="2026-08-28T20:00:00+10:00",
            reviews=reviews,
        )

    incomplete = reviews[:-1]
    with pytest.raises(ValueError, match="omits published anchor metrics"):
        attestation.create_class_comparison_review(
            tmp_path / "incomplete.json",
            handoff=handoff,
            evaluation_receipt=evaluation_receipt,
            reviewer="Thesis researcher",
            reviewed_at="2026-08-28T20:00:00+10:00",
            reviews=incomplete,
        )


def test_create_comparison_review_post_write_validation_is_default_and_optional(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[Path] = []
    monkeypatch.setattr(
        attestation,
        "_comparison_review_value",
        lambda **_kwargs: {"fixture": True},
    )
    monkeypatch.setattr(
        attestation,
        "write_create_only_json",
        lambda destination, _value: Path(destination),
    )
    monkeypatch.setattr(
        attestation,
        "validate_class_comparison_review",
        lambda path, **_kwargs: calls.append(Path(path)),
    )

    inputs = {
        "handoff": tmp_path / "handoff",
        "evaluation_receipt": tmp_path / "evaluation.json",
        "reviewer": "Researcher",
        "reviewed_at": "2026-09-05T00:00:00+10:00",
        "reviews": (),
    }
    first = tmp_path / "comparison-default.json"
    assert attestation.create_class_comparison_review(first, **inputs) == first
    assert calls == [first]

    second = tmp_path / "comparison-pipeline.json"
    assert (
        attestation.create_class_comparison_review(
            second,
            **inputs,
            _post_write_validate=False,
        )
        == second
    )
    assert calls == [first]
    with pytest.raises(ValueError, match="post-write validation flag"):
        attestation.create_class_comparison_review(
            tmp_path / "comparison-invalid.json",
            **inputs,
            _post_write_validate=1,  # type: ignore[arg-type]
        )


def test_create_validation_attestation_post_write_validation_is_default_and_optional(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[Path, bool]] = []
    monkeypatch.setattr(
        attestation,
        "_protected_final_inputs",
        lambda _inputs: (),
    )
    monkeypatch.setattr(
        attestation,
        "_validation_value",
        lambda **_kwargs: {"fixture": True},
    )
    monkeypatch.setattr(
        attestation,
        "write_create_only_json",
        lambda destination, _value: Path(destination),
    )
    monkeypatch.setattr(
        attestation,
        "validate_class_validation_attestation",
        lambda path, *, deep_code_gate=True: calls.append((Path(path), deep_code_gate)),
    )

    first = tmp_path / "attestation-default.json"
    assert attestation.create_class_validation_attestation(first) == first
    assert calls == [(first, False)]

    second = tmp_path / "attestation-pipeline.json"
    assert (
        attestation.create_class_validation_attestation(
            second,
            _post_write_validate=False,
        )
        == second
    )
    assert calls == [(first, False)]
    with pytest.raises(ValueError, match="post-write validation flag"):
        attestation.create_class_validation_attestation(
            tmp_path / "attestation-invalid.json",
            _post_write_validate="false",  # type: ignore[arg-type]
        )


def test_readiness_receipt_reconstruction_rejects_hard_gate_identity_tamper(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence_file = tmp_path / "evidence.json"
    evidence_file.write_text("{}\n", encoding="utf-8")
    result = tmp_path / "result"
    result.mkdir()
    (result / "evidence.sha256").write_text("seal\n", encoding="utf-8")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "provenance.json").write_text("{}\n", encoding="utf-8")
    directory = tmp_path / "directory"
    directory.mkdir()

    file_binding = {"path": str(evidence_file.resolve()), "sha256": sha256_file(evidence_file)}
    result_binding = {
        "root": str(result.resolve()),
        "evidence_sha256": sha256_file(result / "evidence.sha256"),
    }
    bundle_binding = {
        "root": str(bundle.resolve()),
        "provenance": "provenance.json",
        "provenance_sha256": sha256_file(bundle / "provenance.json"),
        "artifacts": {},
    }
    directory_binding = {"root": str(directory.resolve())}
    gates = {
        gate: [_digest(str((index % 8) + 1))]
        for index, gate in enumerate(attestation._READINESS_GATES)
    }
    payload: dict[str, Any] = {
        "attestation_schema_version": attestation.READINESS_SCHEMA_VERSION,
        "artifact_type": attestation.READINESS_RECEIPT_TYPE,
        "study_id": attestation.STUDY_ID,
        "cohort_version": 23,
        "implementation_status": attestation.READINESS_IMPLEMENTATION_STATUS,
        "promotion_authority": False,
        "implementation_scope": attestation.IMPLEMENTATION_SCOPE,
        "paper_equivalent": False,
        "no_waivers": True,
        "source": _source(),
        "build_execution_identity": {},
        "evidence": {
            "foundation": file_binding,
            "build_execution": file_binding,
            "browser_egress_qualification": {"root": "/evidence/browser-egress"},
            "reference": file_binding,
            "code_gate": file_binding,
            "controlled_qualification": file_binding,
            "regression_results": [result_binding],
            "controlled_results": [result_binding],
            "candidate_catalogue": file_binding,
            "stability_root": directory_binding,
            "workload_root": directory_binding,
            "acquisition_completion": file_binding,
            "pilot_cohort": file_binding,
            "pilot_cohort_assembly": file_binding,
            "pilot_fitting_result": result_binding,
            "pilot_numeric_bundle": bundle_binding,
            "pilot_compatibility_result": result_binding,
            "final_selection": file_binding,
            "final_cohort": file_binding,
            "final_cohort_assembly": file_binding,
            "authoritative_fitting_result": result_binding,
            "authoritative_fitting_bundle": bundle_binding,
            "qualification_context": {
                "workload_root": directory_binding,
                "sidecar_root": directory_binding,
                "prefix_spec_root": directory_binding,
            },
            "certification_result": result_binding,
        },
        "summary": {},
        "hard_gates": attestation._hard_gate_records(attestation._READINESS_GATES, gates),
        "all_readiness_gates_passed": True,
    }

    monkeypatch.setattr(attestation, "_readiness_value", lambda **_kwargs: payload)
    inputs = {
        "foundation_attestation": evidence_file,
        "cohort_version": 23,
        "build_execution_receipt": evidence_file,
        "reference_receipt": evidence_file,
        "code_gate_receipt": evidence_file,
        "controlled_qualification_receipt": evidence_file,
        "regression_result_roots": [result],
        "controlled_result_roots": [result],
        "candidate_catalogue": evidence_file,
        "stability_root": directory,
        "workload_root": directory,
        "acquisition_completion": evidence_file,
        "pilot_cohort_receipt": evidence_file,
        "pilot_cohort_assembly": evidence_file,
        "pilot_fitting_result_root": result,
        "pilot_numeric_bundle_root": bundle,
        "pilot_compatibility_result_root": result,
        "final_selection_receipt": evidence_file,
        "final_cohort_receipt": evidence_file,
        "final_cohort_assembly": evidence_file,
        "authoritative_fitting_result_root": result,
        "authoritative_fitting_bundle_root": bundle,
        "qualification_workload_root": directory,
        "qualification_sidecar_root": directory,
        "qualification_prefix_root": directory,
        "certification_result_root": result,
    }
    destination = tmp_path / "readiness.json"
    attestation.create_class_readiness_attestation(destination, **inputs)
    assert (
        attestation.validate_class_readiness_attestation(destination)["promotion_authority"]
        is False
    )

    value = bind_receipt(payload, receipt_type=attestation.READINESS_RECEIPT_TYPE)
    value["payload"]["hard_gates"][0]["gate"] = value["payload"]["hard_gates"][1]["gate"]
    value = bind_receipt(value["payload"], receipt_type=attestation.READINESS_RECEIPT_TYPE)
    destination.write_bytes(canonical_json_bytes(value))
    with pytest.raises(ValueError, match="hard gate"):
        attestation.validate_class_readiness_attestation(destination)

    substituted = json.loads(json.dumps(payload))
    substituted["evidence"]["browser_egress_qualification"]["root"] = (
        "/evidence/substituted-browser-egress"
    )
    destination.write_bytes(
        canonical_json_bytes(
            bind_receipt(substituted, receipt_type=attestation.READINESS_RECEIPT_TYPE)
        )
    )
    with pytest.raises(ValueError, match="differs from reconstructed evidence"):
        attestation.validate_class_readiness_attestation(destination)


def test_readiness_derivation_rechecks_every_prerequisite_and_fitted_parameters(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import qcsd_lab.class_pipeline as pipeline

    source = _source()
    build_file = tmp_path / "build.json"
    ordinary_file = tmp_path / "receipt.json"
    acquisition_root = tmp_path / "acquisition"
    acquisition_root.mkdir()
    completion_file = acquisition_root / "completion.json"
    foundation_file = tmp_path / "foundation.json"
    selection_file = tmp_path / "selection.json"
    for path in (build_file, ordinary_file, foundation_file):
        path.write_text("{}\n", encoding="utf-8")
    selection = bind_receipt(
        {"feasible_pair_graph": [["a", "b"]]},
        receipt_type="qcsd-class-study-final-selection-input",
    )
    selection_file.write_bytes(canonical_json_bytes(selection))
    completion_file.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                {"study_id": attestation.STUDY_ID},
                receipt_type=attestation.COMPLETION_TYPE,
            )
        )
    )
    directory = tmp_path / "directory"
    directory.mkdir()

    result_roots: dict[str, Path] = {}
    for role in (
        "pilot-fitting",
        "pilot-compatibility",
        "authoritative-fitting",
        "certification",
    ):
        root = tmp_path / role
        root.mkdir()
        (root / "evidence.sha256").write_text(f"{role}\n", encoding="utf-8")
        (root / "inputs").mkdir()
        (root / attestation.CLASS_STUDY_LAUNCH_INPUT).write_text(
            f"{role} launch\n", encoding="utf-8"
        )
        (root / attestation._CLASS_STUDY_FOUNDATION_INPUT).write_bytes(foundation_file.read_bytes())
        result_roots[role] = root
    pilot_bundle = tmp_path / "pilot-bundle"
    final_bundle = tmp_path / "final-bundle"
    pilot_bundle.mkdir()
    final_bundle.mkdir()
    (pilot_bundle / attestation.NUMERIC_PROVENANCE_FILE).write_text("{}\n", encoding="utf-8")
    (final_bundle / attestation.PROVENANCE_FILE).write_text("{}\n", encoding="utf-8")

    build_identity = {
        "cohort_version": 23,
        "sha256": _digest("1"),
        **_completion_identity(),
        "collection_image": source["image_digest"],
        "started_at": "2026-08-28T00:00:00+00:00",
        "finished_at": "2026-08-28T01:00:00+00:00",
    }
    build = {
        **build_identity,
        "path": str(build_file.resolve()),
        "completion_path": str(
            build_file.with_name("build-completion-v23.json").resolve()
        ),
        "payload_sha256": _digest("0"),
        "source": source,
        "images": {
            "collection": {"id": source["image_digest"]},
            "prepare": {"id": f"sha256:{_digest('9')}"},
            "reference": {"id": f"sha256:{_digest('8')}"},
        },
    }
    build_binding = {"path": str(build_file.resolve()), "sha256": _digest("1")}
    environment = {"build_execution": build_identity}
    monkeypatch.setattr(attestation, "source_metadata", lambda: source)
    monkeypatch.setattr(attestation, "validate_build_execution_receipt", lambda *_a, **_k: build)
    monkeypatch.setattr(
        attestation,
        "validate_reference_gate_receipt",
        lambda *_a, **_k: {
            "sha256": _digest("2"),
            "profiles_checked": 8,
            "build_execution": build_identity,
        },
    )
    regression = {
        "samples": 18,
        "source": source,
        "results": [{"environment": environment}],
    }
    monkeypatch.setattr(attestation, "validate_regression_results", lambda *_a: regression)
    monkeypatch.setattr(
        attestation,
        "validate_code_gate_receipt",
        lambda *_a, **_k: {
            "sha256": _digest("3"),
            "source": source,
            "build_execution_receipt": build_binding,
        },
    )
    controlled = {
        "sha256": _digest("4"),
        "source": source,
        "build_execution": build_binding,
        "controlled_results": {
            "samples": 160,
            "results": [{"environment": environment}],
        },
    }
    monkeypatch.setattr(attestation, "validate_qualification_receipt", lambda *_a, **_k: controlled)
    monkeypatch.setattr(
        attestation, "_one_build_execution_identity", lambda _values: build_identity
    )
    pinned_cdp = {
        "probe_schema_version": attestation.PINNED_CDP_PROBE_SCHEMA_VERSION,
        "path": str(ordinary_file.resolve()),
        "sha256": sha256_file(ordinary_file),
        "payload_sha256": _digest("7"),
        "recorded_at": "2026-08-28T01:01:00+00:00",
        "build_execution": {
            "path": "/lab/artifacts/buflo-study/build-execution-v23.json",
            "sha256": build_identity["sha256"],
            "payload_sha256": _digest("8"),
        },
        "build_execution_identity": build_identity,
        "probe_contract_sha256": _digest("9"),
    }
    monkeypatch.setattr(
        attestation,
        "validate_pinned_cdp_receipt",
        lambda *_a, **_k: pinned_cdp,
    )
    browser_egress_root = tmp_path / "browser-egress-qualification-v23"
    browser_egress = _browser_egress_result(browser_egress_root, build)
    browser_egress_binding = attestation._browser_egress_binding(
        browser_egress, browser_egress_root
    )
    monkeypatch.setattr(
        attestation,
        "verify_browser_egress_qualification",
        lambda *_a, **_k: dict(browser_egress),
    )
    foundation_binding = {
        "path": str(foundation_file.resolve()),
        "sha256": sha256_file(foundation_file),
    }
    foundation = {
        "cohort_version": 23,
        "recorded_at": "2026-08-28T00:00:00+00:00",
        "source": source,
        "build_execution_identity": build_identity,
        "evidence": {
            "build_execution": attestation._file_binding(build_file),
            "pinned_cdp_probe": attestation._pinned_cdp_binding(pinned_cdp),
            "browser_egress_qualification": browser_egress_binding,
            "reference": attestation._file_binding(ordinary_file),
            "code_gate": attestation._file_binding(ordinary_file),
            "controlled_qualification": attestation._file_binding(ordinary_file),
            "regression_results": [attestation._result_binding(result_roots["pilot-fitting"])],
            "controlled_results": [
                attestation._result_binding(result_roots["pilot-compatibility"])
            ],
        },
    }
    monkeypatch.setattr(
        attestation,
        "validate_class_foundation_attestation",
        lambda *_a, **_k: foundation,
    )
    qualification_authority = {
        "schema_version": attestation.QUALIFICATION_AUTHORITY_SCHEMA_VERSION,
        "artifact_type": attestation.QUALIFICATION_AUTHORITY_TYPE,
        "foundation_attestation": {
            **foundation_binding,
            "payload_sha256": _digest("6"),
        },
        "build_execution": {
            "path": str(build_file.resolve()),
            "sha256": build_identity["sha256"],
        },
        "build_execution_identity": build_identity,
        "collection_source": source,
        "prepare_source": {
            **source,
            "image_digest": build["images"]["prepare"]["id"],
        },
        "prepare_image_digest": build["images"]["prepare"]["id"],
    }
    attestation.validate_class_qualification_authority(qualification_authority)
    selection = bind_receipt(
        {
            "feasible_pair_graph": [["a", "b"]],
            "pilot_compatibility": {
                "finalized_bundle": {
                    "qualification_authority": qualification_authority,
                    "qualification_authority_sha256": attestation.canonical_json_sha256(
                        qualification_authority
                    ),
                }
            },
        },
        receipt_type="qcsd-class-study-final-selection-input",
    )
    selection_file.write_bytes(canonical_json_bytes(selection))
    monkeypatch.setattr(
        attestation,
        "class_qualification_authority",
        lambda *_a, **_k: qualification_authority,
    )
    provenance_file = acquisition_root / "provenance.json"
    provenance_file.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                {
                    "study_id": attestation.STUDY_ID,
                    "foundation_attestation": foundation_binding,
                    "started_at": "2026-08-28T00:01:00+00:00",
                },
                receipt_type=attestation.ACQUISITION_PROVENANCE_TYPE,
            )
        )
    )
    observed_toolchain = {
        "chromium_version": attestation.EXPECTED_CHROMIUM_VERSION,
        "neqo_provenance": {
            "neqo_version": "fixture",
            "neqo_base_commit": "5" * 40,
            "published_qcsd_commit": "6" * 40,
            "migration_commit": source["neqo_commit"],
        },
        "image_digest": build["images"]["prepare"]["id"],
        "source": {
            **source,
            "image_digest": build["images"]["prepare"]["id"],
        },
    }
    completion_payload = {
        "study_id": attestation.STUDY_ID,
        "acquisition_schema_version": attestation.ACQUISITION_SCHEMA_VERSION,
        "completion_schema_version": attestation.ACQUISITION_COMPLETION_SCHEMA_VERSION,
        "checkpoint_schema_version": attestation.ACQUISITION_CHECKPOINT_SCHEMA_VERSION,
        "observed_toolchain": observed_toolchain,
        "provenance_sha256": sha256_file(provenance_file),
    }
    completion_file.write_bytes(
        canonical_json_bytes(
            bind_receipt(completion_payload, receipt_type=attestation.COMPLETION_TYPE)
        )
    )
    monkeypatch.setattr(
        attestation,
        "validate_acquisition_completion",
        lambda value, **_kwargs: attestation.validate_hash_bound_receipt(
            value,
            expected_type=attestation.COMPLETION_TYPE,
        ),
    )

    pilot_admission = SimpleNamespace(
        selection=SimpleNamespace(feasible_pairs=None),
        cohort_sha256=_digest("5"),
        assembly_sha256=_digest("6"),
    )
    final_selection_items = tuple(
        SimpleNamespace(candidate_id=f"c-{index}") for index in range(100)
    )
    final_admission = SimpleNamespace(
        selection=SimpleNamespace(
            feasible_pairs=(("a", "b"),),
            final=final_selection_items,
            reserves=tuple(SimpleNamespace(candidate_id=f"r-{index}") for index in range(20)),
        ),
        cohort_sha256=_digest("7"),
        assembly_sha256=_digest("8"),
        final_selection_sha256=sha256_file(selection_file),
    )
    monkeypatch.setattr(
        pipeline,
        "verify_cohort_admission",
        lambda cohort, *_a, **_k: (
            pilot_admission if Path(cohort).name.startswith("pilot") else final_admission
        ),
    )
    certification_parameters = {
        "traffic-morphing": _digest("a"),
        "wtf-pad": _digest("b"),
        "walkie-talkie": _digest("c"),
        "buflo": _digest("d"),
        "cs-buflo": _digest("e"),
    }
    role_records = {
        "pilot-fitting": {
            "samples": 480,
            "class_study_foundation_sha256": foundation_binding["sha256"],
        },
        "pilot-compatibility": {"samples": 1_080},
        "authoritative-fitting": {
            "samples": 2_000,
            "class_study_foundation_sha256": foundation_binding["sha256"],
        },
        "certification": {
            "samples": 900,
            "accepted": 900,
            "first_launch_unique_class_mode_pairs": 900,
            "class_study_foundation_sha256": foundation_binding["sha256"],
            "chaff_qualification_set_manifest_sha256": _digest("d"),
            "defense_parameter_sha256": certification_parameters,
            "defense_runtime_inputs": _runtime_inputs(
                attestation.COMPATIBILITY_MODES, certification_parameters
            ),
        },
    }
    role_records["pilot-compatibility"]["class_study_foundation_sha256"] = foundation_binding[
        "sha256"
    ]
    monkeypatch.setattr(
        pipeline,
        "verify_class_study_result",
        lambda *_a, expected_role, **_k: role_records[expected_role],
    )

    def validate_selection(
        *_args,
        pilot_fitting_result_root,
        qualification_authority,
        **_kwargs,
    ):
        assert pilot_fitting_result_root == result_roots["pilot-fitting"]
        assert qualification_authority == qualification_authority_fixture
        return ()

    def build_selection(
        *_args,
        pilot_fitting_result_root,
        qualification_authority,
        **_kwargs,
    ):
        assert pilot_fitting_result_root == result_roots["pilot-fitting"]
        assert qualification_authority == qualification_authority_fixture
        return selection

    qualification_authority_fixture = qualification_authority
    monkeypatch.setattr(pipeline, "validate_final_selection_input", validate_selection)
    monkeypatch.setattr(pipeline, "build_final_selection_input", build_selection)

    pilot_numeric = SimpleNamespace(
        stage=attestation.PILOT_STAGE,
        root=pilot_bundle,
        provenance={},
        artifact_hashes={"walkie_talkie": _digest("d")},
    )
    monkeypatch.setattr(
        attestation, "verify_numeric_fitting_bundle", lambda *_a, **_k: pilot_numeric
    )
    fitting = SimpleNamespace(
        stage=attestation.AUTHORITATIVE_STAGE,
        root=final_bundle,
        artifact_hashes={
            "traffic_morphing": _digest("a"),
            "wtf_pad": _digest("b"),
            "walkie_talkie": _digest("c"),
        },
        provenance={
            "runtime_authorized": True,
            "cohort": {
                "receipt_sha256": final_admission.cohort_sha256,
                "assembly_receipt_sha256": final_admission.assembly_sha256,
            },
            "qualification_inputs": {
                "qualification_bindings": [{} for _ in range(100)],
                "qualification_manifest_sha256": _digest("d"),
                "qualification_bindings_sha256": _digest("e"),
            },
            "source_result": {"source_fingerprints": source},
        },
    )
    monkeypatch.setattr(attestation, "verify_class_fitting_bundle", lambda *_a, **_k: fitting)

    def verified_result(root: Path) -> SimpleNamespace:
        root = Path(root)
        launch_sha256 = sha256_file(root / attestation.CLASS_STUDY_LAUNCH_INPUT)
        foundation_sha256 = sha256_file(root / attestation._CLASS_STUDY_FOUNDATION_INPUT)
        return SimpleNamespace(
            root=root,
            experiment={
                "source": source,
                "configuration": {
                    "evidence_role": root.name,
                    "class_study_launch_sha256": launch_sha256,
                    "class_study_foundation_sha256": foundation_sha256,
                },
            },
            checksums={
                attestation.CLASS_STUDY_LAUNCH_INPUT: launch_sha256,
                attestation._CLASS_STUDY_FOUNDATION_INPUT: foundation_sha256,
            },
        )

    monkeypatch.setattr(attestation, "verify_result", verified_result)
    monkeypatch.setattr(attestation, "_validate_result_environment", lambda *_a: environment)

    pilot_cohort = tmp_path / "pilot-cohort.json"
    final_cohort = tmp_path / "final-cohort.json"
    for path in (pilot_cohort, final_cohort):
        path.write_text("{}\n", encoding="utf-8")
    kwargs = {
        "foundation_attestation": foundation_file,
        "cohort_version": 23,
        "build_execution_receipt": build_file,
        "reference_receipt": ordinary_file,
        "code_gate_receipt": ordinary_file,
        "controlled_qualification_receipt": ordinary_file,
        "regression_result_roots": [result_roots["pilot-fitting"]],
        "controlled_result_roots": [result_roots["pilot-compatibility"]],
        "candidate_catalogue": ordinary_file,
        "stability_root": directory,
        "workload_root": directory,
        "acquisition_completion": completion_file,
        "pilot_cohort_receipt": pilot_cohort,
        "pilot_cohort_assembly": ordinary_file,
        "pilot_fitting_result_root": result_roots["pilot-fitting"],
        "pilot_numeric_bundle_root": pilot_bundle,
        "pilot_compatibility_result_root": result_roots["pilot-compatibility"],
        "final_selection_receipt": selection_file,
        "final_cohort_receipt": final_cohort,
        "final_cohort_assembly": ordinary_file,
        "authoritative_fitting_result_root": result_roots["authoritative-fitting"],
        "authoritative_fitting_bundle_root": final_bundle,
        "qualification_workload_root": directory,
        "qualification_sidecar_root": directory,
        "qualification_prefix_root": directory,
        "certification_result_root": result_roots["certification"],
        "deep_code_gate": True,
    }
    value = attestation._readiness_value(**kwargs)
    assert value["summary"]["certification_samples"] == 900
    assert value["summary"]["final_qualification_executions"] == 600
    assert value["summary"]["qualification_authority_sha256"] == (
        attestation.canonical_json_sha256(qualification_authority)
    )
    assert value["evidence"]["qualification_context"]["qualification_authority"] == (
        qualification_authority
    )
    assert value["evidence"]["browser_egress_qualification"] == browser_egress_binding
    assert len(value["hard_gates"]) == len(attestation._READINESS_GATES)

    browser_egress["passed_vector_count"] = attestation.BROWSER_EGRESS_VECTOR_COUNT - 1
    with pytest.raises(ValueError, match="different source/build/image"):
        attestation._readiness_value(**kwargs)
    browser_egress["passed_vector_count"] = attestation.BROWSER_EGRESS_VECTOR_COUNT

    substituted_root = tmp_path / "substituted-browser-egress"
    substituted_root.mkdir()
    (substituted_root / "final.json").write_text("{}\n", encoding="utf-8")
    foundation["evidence"]["browser_egress_qualification"] = {
        **browser_egress_binding,
        "root": str(substituted_root),
        "path": str(substituted_root / "final.json"),
    }
    with pytest.raises(ValueError, match="final receipt path is not canonical"):
        attestation._readiness_value(**kwargs)
    foundation["evidence"]["browser_egress_qualification"] = browser_egress_binding

    current_completion = completion_file.read_bytes()
    for legacy_schema in (*range(1, attestation.ACQUISITION_SCHEMA_VERSION), True):
        legacy_payload = {
            key: content
            for key, content in completion_payload.items()
            if key not in {"completion_schema_version", "checkpoint_schema_version"}
        }
        legacy_payload["acquisition_schema_version"] = legacy_schema
        completion_file.write_bytes(
            canonical_json_bytes(
                bind_receipt(legacy_payload, receipt_type=attestation.COMPLETION_TYPE)
            )
        )
        with pytest.raises(ValueError, match="requires current acquisition schema"):
            attestation._readiness_value(**kwargs)
    completion_file.write_bytes(current_completion)

    substituted_authority = json.loads(json.dumps(qualification_authority))
    substituted_authority["foundation_attestation"] = {
        "path": str((tmp_path / "other-foundation.json").resolve()),
        "sha256": _digest("f"),
        "payload_sha256": _digest("e"),
    }
    substituted_authority["build_execution"] = {
        "path": str((tmp_path / "other-build.json").resolve()),
        "sha256": _digest("f"),
    }
    substituted_authority["build_execution_identity"]["sha256"] = _digest("f")
    substituted_selection = bind_receipt(
        {
            **selection["payload"],
            "pilot_compatibility": {
                "finalized_bundle": {
                    "qualification_authority": substituted_authority,
                    "qualification_authority_sha256": attestation.canonical_json_sha256(
                        substituted_authority
                    ),
                }
            },
        },
        receipt_type="qcsd-class-study-final-selection-input",
    )
    selection_file.write_bytes(canonical_json_bytes(substituted_selection))
    with pytest.raises(ValueError, match="another qualification authority"):
        attestation._readiness_value(**kwargs)
    selection_file.write_bytes(canonical_json_bytes(selection))

    role_records["certification"]["defense_parameter_sha256"]["wtf-pad"] = _digest("f")
    with pytest.raises(ValueError, match="different fitted parameters"):
        attestation._readiness_value(**kwargs)
    role_records["certification"]["defense_parameter_sha256"]["wtf-pad"] = _digest("b")
    role_records["certification"]["defense_runtime_inputs"]["front"]["runtime_kind"] = "tamaraw"
    with pytest.raises(ValueError, match="front runtime kind"):
        attestation._readiness_value(**kwargs)
    role_records["certification"]["defense_runtime_inputs"] = _runtime_inputs(
        attestation.COMPATIBILITY_MODES, certification_parameters
    )
    role_records["pilot-compatibility"]["class_study_foundation_sha256"] = _digest("f")
    with pytest.raises(ValueError, match="do not share the exact foundation"):
        attestation._readiness_value(**kwargs)
    role_records["pilot-compatibility"]["class_study_foundation_sha256"] = foundation_binding[
        "sha256"
    ]
    role_records["certification"]["chaff_qualification_set_manifest_sha256"] = _digest("f")
    with pytest.raises(ValueError, match="different qualification manifest"):
        attestation._readiness_value(**kwargs)
