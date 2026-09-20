from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Lock
from types import ModuleType, SimpleNamespace

import pytest

import qcsd_lab.class_acquisition as acquisition_module
from qcsd_lab import buflo_study, class_attestation, pinned_cdp, playwright_driver
from qcsd_lab.acquisition_errors import RecoverableAcquisitionError
from qcsd_lab.browser_egress import (
    NON_REPLAYABLE_EGRESS_POLICY,
    NonReplayableEgressGuard,
    target_egress_apis,
)
from qcsd_lab.cdp_targets import (
    CDP_TARGET_INSTRUMENTATION_POLICY,
    EGRESS_PREARM_SUMMARY_SCHEMA_VERSION,
    SRCDOC_PSEUDO_DOCUMENT_POLICY,
    SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
    CdpTargetIntegrityError,
)
from qcsd_lab.class_acquisition import (
    CHECKPOINT_SCHEMA_VERSION,
    COMPLETION_SCHEMA_VERSION,
    COMPLETION_TYPE,
    GLOBAL_LIVE_PAGE_CAP,
    MAX_ACQUISITION_BACKEND_TIMEOUT_MS,
    MAX_APPROVED_ORIGINS,
    MAX_CANDIDATES_PER_ACTION,
    MAX_ORIGIN_PASSES,
    MAX_PASSIVE_RENDER_AFTER_LOAD_MS,
    PENDING_BASELINE_GUARD_MS,
    TERMINAL_SCHEMA_VERSION,
    ExistingAcquisitionBackend,
    InternalAcquisitionError,
    NavigationDiscovery,
    PreparedProbe,
    TerminalProbePolicyError,
    _converge_origins,
    _is_public_network_address,
    _navigation_request_allowed,
    _prepared_replay_identity_sha256,
    _probe_attempt_workload_id,
    _validate_probe_attempts,
    _verified_bound_file,
    _verified_navigation_link,
    acquisition_status,
    catalogue_boundary_navigation,
    initialise_runner,
    public_origin_ip_pins,
    run_due_acquisition,
    unsafe_catalogue_domain_reason,
    validate_acquisition_completion,
    write_acquisition_completion,
)
from qcsd_lab.class_catalogue import (
    CANDIDATE_RECEIPT_TYPE,
    CATALOGUE_SCHEMA_VERSION,
    DiscoveredLink,
    PageCandidate,
)
from qcsd_lab.class_study import (
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    STUDY_ID,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    bind_receipt,
    canonical_json_bytes,
    deterministic_candidate_order,
)
from qcsd_lab.discover import DiscoveryResult, origin
from qcsd_lab.discovery_evidence import (
    DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
    PASSIVE_RENDER_CONTRACT_SHA256,
    RENDER_OBSERVATION_SCHEMA_VERSION,
    evidence_sha256,
    passive_render_contract,
)
from qcsd_lab.prepare import PreparationError, PreparedWorkload, RecoverablePreparationError
from qcsd_lab.util import load_json
from tests.test_buflo_study import _write_schema5_build_pair
from tests.test_pinned_cdp import _observation as _pinned_cdp_observation

_PRODUCTION_FOUNDATION_ATTESTATION_BINDING = acquisition_module._foundation_attestation_binding
_HISTORICAL_ACQUISITION_CONTRACTS = load_json(
    Path(__file__).parent / "fixtures/class-acquisition-historical-contracts.json"
)


def _merge_frozen_contract(target: dict, overlay: dict) -> None:
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _merge_frozen_contract(target[key], value)
        else:
            target[key] = copy.deepcopy(value)


def _schema_five_fixed_projection(variant: dict) -> dict:
    projection = copy.deepcopy(_HISTORICAL_ACQUISITION_CONTRACTS["schema5_v10"]["fixed_provenance"])
    overlay_name = variant["fixed_projection_overlay"]
    if overlay_name is not None:
        _merge_frozen_contract(
            projection,
            _HISTORICAL_ACQUISITION_CONTRACTS["fixed_projection_overlays"][overlay_name],
        )
    projection["cdp_target_instrumentation_policy"] = variant["instrumentation_policy"]
    return projection


def _schema_six_fixed_projection(variant: dict) -> dict:
    schema_five_v14 = next(
        item
        for item in _HISTORICAL_ACQUISITION_CONTRACTS["schema5_source_variants"]
        if item["instrumentation_policy"].endswith("-v14")
    )
    projection = _schema_five_fixed_projection(schema_five_v14)
    _merge_frozen_contract(
        projection,
        _HISTORICAL_ACQUISITION_CONTRACTS["fixed_projection_overlays"]["schema6_from_schema5_v14"],
    )
    projection["cdp_target_instrumentation_policy"] = variant["instrumentation_policy"]
    projection["navigation_implementation"] = variant["navigation_implementation"]
    return projection


def _synthetic_historical_provenance(
    schema: int,
    *,
    fixed_projection: dict,
    source_lab_commit: str,
) -> dict:
    authority_field = "foundation_attestation" if schema == 5 else "acquisition_authority"
    return {
        "study_id": "classifier-multiorigin100-v1",
        "acquisition_schema_version": schema,
        "candidate_catalogue_sha256": "a" * 64,
        "candidate_catalogue_payload_sha256": "b" * 64,
        "candidate_count": 1,
        authority_field: {"path": "/frozen/historical-authority.json", "sha256": "c" * 64},
        "started_at": "2026-01-01T00:00:00Z",
        "image_digest": "native",
        "source": {
            "image_digest": "native",
            "lab_commit": source_lab_commit,
            "lab_dirty": False,
            "lab_patch_sha256": hashlib.sha256(b"").hexdigest(),
            "neqo_commit": "d" * 40,
            "neqo_pinned_commit": "d" * 40,
            "neqo_dirty": False,
            "neqo_patch_sha256": hashlib.sha256(b"").hexdigest(),
        },
        **copy.deepcopy(fixed_projection),
    }


@pytest.fixture(autouse=True)
def _miniature_ledger_selection_policy(monkeypatch: pytest.MonkeyPatch):
    """Isolate old one-candidate ledger fixtures from the full 600-candidate policy.

    Production-sized tests always use the real selector.  These fixtures
    deliberately replace catalogue loading to test receipt/legacy mechanics;
    they are not evidence that a miniature study can meet acquisition quotas.
    """
    original = acquisition_module._derive_checkpoint_selection

    def derive(candidates, catalogue, states, terminal_payloads):
        if len(candidates) == CANDIDATE_COUNT:
            return original(candidates, catalogue, states, terminal_payloads)
        ids = [candidate.candidate_id for candidate in candidates]
        terminals = [candidate_id for candidate_id in ids if candidate_id in terminal_payloads]
        remaining = [candidate_id for candidate_id in ids if candidate_id not in terminal_payloads]
        return (
            {
                "fixture_only": "miniature-ledger",
                "candidate_ids": ids,
                "terminal_ids": terminals,
                "remaining_ids": remaining,
                "needed_ids": remaining,
                "admission_ids": ids,
                "unassessed_ids": [],
                "prefix_ids": ids,
                "pilot_ids": terminals if not remaining else [],
                "quota_unmet_strata": [],
                "complete": not remaining,
            },
            [],
        )

    monkeypatch.setattr(acquisition_module, "_derive_checkpoint_selection", derive)


def _egress_prearm_summary() -> dict[str, object]:
    return {
        "schema_version": EGRESS_PREARM_SUMMARY_SCHEMA_VERSION,
        "policy": NON_REPLAYABLE_EGRESS_POLICY,
        "target_total": 1,
        "installed_total": 1,
        "pending_total": 0,
        "popup_guard_required_total": 1,
        "popup_guard_installed_total": 1,
        "by_target_type": {
            target_type: {
                "target_count": int(target_type == "page"),
                "installed_count": int(target_type == "page"),
                "pending_count": 0,
                "protected_api_observations": len(target_egress_apis("page"))
                if target_type == "page"
                else 0,
                "unavailable_api_observations": 0,
                "popup_guard_required_count": int(target_type == "page"),
                "popup_guard_installed_count": int(target_type == "page"),
            }
            for target_type in ("page", "iframe", "worker", "shared_worker")
        },
    }


def _non_replayable_egress_summary() -> dict[str, object]:
    guard = NonReplayableEgressGuard()
    guard.mark_context_guards_installed()
    guard.bind_root_page(object())
    return guard.success_summary()


def _terminal_internal_document_lifecycle_summary() -> dict[str, object]:
    return {
        "schema_version": SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
        "policy": SRCDOC_PSEUDO_DOCUMENT_POLICY,
        "enabled": True,
        "total": 0,
        "resolved": 0,
        "pending": 0,
        "aborted": 0,
        "open_candidates": 0,
        "network_history_saturated": False,
        "fetch_history_saturated": False,
        "candidate_limit_saturated": False,
        "terminal_outcome_counts": {
            "Network.loadingFailed": 0,
            "Network.loadingFinished": 0,
        },
        "diagnostics": [],
    }


@pytest.fixture(autouse=True)
def _clean_acquisition_source(monkeypatch: pytest.MonkeyPatch):
    """Model the clean immutable image required by the production runner."""

    empty_sha256 = hashlib.sha256(b"").hexdigest()
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "1" * 64)

    def clean_source():
        return {
            "image_digest": acquisition_module.os.environ["QCSD_LAB_IMAGE_DIGEST"],
            "lab_commit": "2" * 40,
            "lab_dirty": False,
            "lab_patch_sha256": empty_sha256,
            "neqo_commit": "3" * 40,
            "neqo_pinned_commit": "3" * 40,
            "neqo_dirty": False,
            "neqo_patch_sha256": empty_sha256,
        }

    monkeypatch.setattr(acquisition_module, "source_metadata", clean_source)

    # Most tests exercise acquisition state transitions with a deliberately
    # minimal hash-bound foundation fixture. Tests for the production boundary
    # explicitly restore the deep typed validator captured above.
    def fixture_foundation_binding(path: Path) -> dict[str, str]:
        source = path.absolute()
        if source.is_symlink() or not source.is_file():
            raise ValueError("class acquisition foundation must be a regular file")
        value = load_json(source)
        if source.read_bytes() != canonical_json_bytes(value):
            raise ValueError("class acquisition foundation is not canonically encoded")
        acquisition_module.validate_hash_bound_receipt(
            value,
            expected_type="qcsd-class-study-foundation-attestation",
        )
        return {
            "path": str(source),
            "sha256": acquisition_module.sha256_file(source),
        }

    monkeypatch.setattr(
        acquisition_module,
        "_foundation_attestation_binding",
        fixture_foundation_binding,
    )


def _foundation(path: Path) -> Path:
    path.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                {"study_id": STUDY_ID},
                receipt_type="qcsd-class-study-foundation-attestation",
            )
        )
    )
    return path


def _catalogue(path: Path) -> Path:
    candidates = deterministic_candidate_order(
        (
            ClassCandidate(
                f"class-{stratum_index}-{offset:02d}",
                f"site-{stratum_index}-{offset:02d}.example",
                stratum.minimum_rank + offset,
                False,
            )
            for stratum_index, stratum in enumerate(TRANCO_RANK_STRATA)
            for offset in range(CANDIDATES_PER_STRATUM)
        ),
        tranco_list_sha256="a" * 64,
    )
    value = bind_receipt(
        {
            "study_id": STUDY_ID,
            "catalogue_schema_version": CATALOGUE_SCHEMA_VERSION,
            "tranco": {
                "list_id": "TEST1",
                "list_sha256": "a" * 64,
                "source_url": "https://tranco-list.eu/download/TEST1/1000000",
                "retrieved_at": "2026-08-28T00:00:00Z",
                "row_count": 1_000_000,
                "entries_sha256": "b" * 64,
            },
            "selection": {
                "rank_strata": [stratum.as_dict() for stratum in TRANCO_RANK_STRATA],
                "per_stratum": CANDIDATES_PER_STRATUM,
                "ordering": "sha256(list_sha256 || study_id || canonical_domain)",
                "outcome_fields_used": [],
            },
            "candidates": [candidate.as_dict() for candidate in candidates],
        },
        receipt_type=CANDIDATE_RECEIPT_TYPE,
    )
    path.write_bytes(canonical_json_bytes(value))
    return path


def _write_rust_code_gate_fixture(
    root: Path,
    *,
    collection_source: dict[str, object],
) -> dict[str, object]:
    """Materialise the real Rust-gate reader's complete immutable input."""

    logs_root = root / "logs"
    logs_root.mkdir(parents=True)
    build_inputs = {
        "schema_version": 1,
        "artifact_type": "qcsd-study-build-inputs",
        "rust_base_image": buflo_study.RUST_BASE_IMAGE,
        "debian_base_image": buflo_study.DEBIAN_BASE_IMAGE,
        "uv_lock_sha256": buflo_study.sha256_file(buflo_study.LAB_ROOT / "uv.lock"),
        "cargo_lock_sha256": buflo_study.sha256_file(buflo_study.LAB_ROOT / "neqo-qcsd/Cargo.lock"),
    }
    build_source = {**collection_source, "image_digest": None}
    source_bytes = (json.dumps(build_source, indent=2, sort_keys=True) + "\n").encode()
    build_bytes = (json.dumps(build_inputs, indent=2, sort_keys=True) + "\n").encode()
    (root.parent / "source.json").write_bytes(source_bytes)
    (root.parent / "study-build-inputs.json").write_bytes(build_bytes)
    logs: dict[str, dict[str, object]] = {}
    for gate, _argv in buflo_study._RUST_CODE_GATE_COMMANDS:
        data = b"status=passed\n"
        (logs_root / f"{gate}.log").write_bytes(data)
        logs[gate] = {
            "path": f"logs/{gate}.log",
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    value: dict[str, object] = {
        "schema_version": 1,
        "artifact_type": "qcsd-rust-code-gate",
        "domain": "qcsd-rust-code-gate-v1",
        "passed": True,
        "target_arch": "amd64",
        "dockerfile_frontend": (
            "docker/dockerfile:1.7@sha256:"
            "a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
        ),
        "rust_base_image": buflo_study.RUST_BASE_IMAGE,
        "uv_image": (
            "ghcr.io/astral-sh/uv:0.10.7@sha256:"
            "edd1fd89f3e5b005814cc8f777610445d7b7e3ed05361f9ddfae67bebfe8456a"
        ),
        "source_metadata": build_source,
        "source_metadata_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "study_build_inputs": build_inputs,
        "study_build_inputs_sha256": hashlib.sha256(build_bytes).hexdigest(),
        "commands": [
            {"gate": gate, "argv": list(argv)}
            for gate, argv in buflo_study._RUST_CODE_GATE_COMMANDS
        ],
        "logs": logs,
        "tool_versions": {
            "cargo": "cargo 1.89.0",
            "clippy": "clippy 0.1.89",
            "rustc": "rustc 1.89.0",
            "rustfmt": "rustfmt 1.8.0",
        },
    }
    unsigned = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    value["sha256"] = hashlib.sha256(b"qcsd-rust-code-gate-v1\0" + unsigned).hexdigest()
    (root / "receipt.json").write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return value


def _real_prepare_runtime_foundation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, dict[str, object], dict[str, object]]:
    """Create a real current foundation around deterministic gate fixtures.

    Expensive packet/result parsing and the browser launch are replaced by
    deterministic gate outputs, but the build, reference, pinned-CDP, code,
    qualification, foundation and acquisition readers themselves all run.
    """

    cohort_version = 59
    build_path = tmp_path / "build-execution-v59.json"
    build_value, _completion_path, _completion = _write_schema5_build_pair(
        build_path,
        cohort_version=cohort_version,
    )
    collection_source = dict(build_value["source"])
    prepare_source = {
        **collection_source,
        "image_digest": build_value["images"]["prepare"]["id"],
    }
    active_source: dict[str, dict[str, object]] = {"value": collection_source}

    def runtime_source() -> dict[str, object]:
        return copy.deepcopy(active_source["value"])

    for module in (buflo_study, class_attestation, pinned_cdp, acquisition_module):
        monkeypatch.setattr(module, "source_metadata", runtime_source)
    monkeypatch.setattr(
        buflo_study,
        "build_execution_receipt_path",
        lambda _version=1: build_path.resolve(),
    )
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", str(collection_source["image_digest"]))

    rust_root = tmp_path / "rust-code-gate"
    _write_rust_code_gate_fixture(rust_root, collection_source=collection_source)
    monkeypatch.setattr(buflo_study, "RUST_CODE_GATE_ROOT", rust_root)

    build = buflo_study.validate_build_execution_receipt(
        build_path,
        expected_collection_image=str(collection_source["image_digest"]),
        expected_cohort_version=cohort_version,
    )
    build_identity = buflo_study._current_build_execution_identity(build)
    regression_roots = tuple(tmp_path / f"regression-{index}" for index in range(3))
    controlled_roots = tuple(tmp_path / f"controlled-{index}" for index in range(4))
    for root in (*regression_roots, *controlled_roots):
        root.mkdir()
        (root / "evidence.sha256").write_text(f"{root.name}\n", encoding="utf-8")

    def local_stage(
        stage: str,
        result_roots,
        *,
        explanation_receipt=None,
        _expected_collection_source=None,
    ):
        assert explanation_receipt is None
        selected_source = buflo_study._expected_clean_collection_source(
            _expected_collection_source,
            label=f"test {stage} source",
        )
        assert selected_source == collection_source
        roots = tuple(Path(root).resolve() for root in result_roots)
        expected_roots = controlled_roots if stage == "controlled" else regression_roots
        assert roots == tuple(root.resolve() for root in expected_roots)
        result = {
            "schema_version": 1,
            "samples": 160 if stage == "controlled" else 18,
            "authoritative_bytes": 1,
            "source": collection_source,
            "results": [
                {
                    "root": str(root),
                    "name": root.name,
                    "evidence_sha256": acquisition_module.sha256_file(root / "evidence.sha256"),
                    "samples": 40 if stage == "controlled" else 6,
                    "campaign_sha256": "1" * 64,
                    "authoritative_bytes": 1,
                    "environment": {"build_execution": build_identity},
                }
                for root in roots
            ],
        }
        if stage == "controlled":
            result.update(
                sustained_cell_capacity={"passed": True},
                multiple_endpoint_coverage={"passed": True},
                ctsp_cpsp_ordering={"passed": True},
            )
        else:
            result.update(
                established_seven_baseline=buflo_study.validate_established_seven_baseline(),
                buflo_timing_stress={"passed": True},
                multi_origin_nine_mode_compatibility={"passed": True},
            )
        return result

    monkeypatch.setattr(buflo_study, "_validate_local_stage_results", local_stage)

    def lab_commands() -> list[dict[str, object]]:
        records = []
        for gate, template in buflo_study._LAB_CODE_GATE_COMMANDS:
            argv = [str(Path(sys.executable)) if item == "python" else item for item in template]
            output = "fixture passed\n"
            records.append(
                {
                    "gate": gate,
                    "argv": argv,
                    "cwd": str(buflo_study.LAB_ROOT),
                    "exit_code": 0,
                    "stdout_bytes": len(output.encode()),
                    "stdout_sha256": hashlib.sha256(output.encode()).hexdigest(),
                    "stdout": output,
                }
            )
        return records

    monkeypatch.setattr(buflo_study, "_run_lab_code_gate_commands", lab_commands)
    code_path = buflo_study.create_code_gate_receipt(
        tmp_path / "code-gate-v59.json",
        regression_result_roots=regression_roots,
        cohort_version=cohort_version,
    )

    qualification_root = tmp_path / "qualification-sets"
    monkeypatch.setattr(buflo_study, "QUALIFICATION_SET_ROOT", qualification_root)
    set_root = qualification_root / buflo_study.qualification_set_for_cohort(cohort_version)
    set_root.mkdir(parents=True)
    for workload in buflo_study.WORKLOADS:
        (set_root / f"{workload}.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        buflo_study,
        "qualification_status",
        lambda *_args, **_kwargs: (True, "deterministic sustained set verified"),
    )
    qualification_path = buflo_study.create_qualification_receipt(
        tmp_path / "qualification-v59.json",
        controlled_roots,
        cohort_version=cohort_version,
    )

    reference_source = {
        **collection_source,
        "image_digest": build_value["images"]["reference"]["id"],
    }
    reference_value = buflo_study._reference_execution_value(
        source=reference_source,
        build_execution={
            "sha256": build["sha256"],
            "receipt": build_value,
            "completion_path": (
                f"/lab/artifacts/buflo-study/build-completion-v{cohort_version}.json"
            ),
            "completion_sha256": build["completion_sha256"],
            "completion_payload_sha256": build["completion_payload_sha256"],
            "completion": _completion,
        },
        isolation={
            "environment_marker": "QCSD_REFERENCE_ISOLATED=1",
            "docker_network_mode": "none",
            "observed_interfaces": ["lo"],
            "reference_inputs_read_only": True,
            "output_mount_writable": True,
            "output_create_only": True,
            "ordinary_collection_contains_author_code": False,
        },
        execution_id="d" * 32,
        started_at="2026-08-27T00:00:01+00:00",
        finished_at="2026-08-27T00:00:01+00:00",
        duration_seconds=0.0,
    )
    reference_path = tmp_path / "reference-execution-v59.json"
    reference_path.write_text(
        json.dumps(reference_value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    active_source["value"] = prepare_source
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", str(prepare_source["image_digest"]))
    pinned_observation = _pinned_cdp_observation()
    monkeypatch.setattr(
        pinned_cdp,
        "validate_default_playwright_driver_once",
        lambda: {"test_fixture": True},
    )
    monkeypatch.setattr(
        pinned_cdp,
        "_driver_binding",
        lambda _receipt: copy.deepcopy(pinned_observation["playwright_driver"]),
    )
    monkeypatch.setattr(
        pinned_cdp,
        "run_pinned_cdp_probe",
        lambda **_kwargs: copy.deepcopy(pinned_observation),
    )
    pinned_path = pinned_cdp.create_pinned_cdp_receipt(
        tmp_path / "pinned-cdp-execution-v59.json",
        build_execution_receipt=build_path,
        cohort_version=cohort_version,
        expected_uid=1000,
        expected_gid=1000,
    )

    browser_egress_root = tmp_path / "browser-egress-qualification-v59"
    browser_egress_root.mkdir()
    browser_egress_final = browser_egress_root / "final.json"
    browser_egress_final.write_text("{}\n", encoding="utf-8")
    build_finished = datetime.fromisoformat(str(build["finished_at"]))
    browser_egress = {
        "path": str(browser_egress_final.absolute()),
        "sha256": hashlib.sha256(browser_egress_final.read_bytes()).hexdigest(),
        "payload_sha256": "1" * 64,
        "qualification_id": class_attestation.BROWSER_EGRESS_QUALIFICATION_ID,
        "cohort_version": cohort_version,
        "qualification_started_at": (build_finished + timedelta(seconds=1)).isoformat(),
        "qualification_finished_at": (build_finished + timedelta(seconds=2)).isoformat(),
        "recorded_at": (build_finished + timedelta(seconds=3)).isoformat(),
        "prepare_image_id": build_value["images"]["prepare"]["id"],
        "build_execution": {
            "path": str(build_path.absolute()),
            "sha256": build["sha256"],
            "size_bytes": build_path.stat().st_size,
            "payload_sha256": build_value["payload_sha256"],
            "cohort_version": cohort_version,
            "completion_path": (
                f"/lab/artifacts/buflo-study/build-completion-v{cohort_version}.json"
            ),
            "completion_sha256": build["completion_sha256"],
            "collection_image_id": build_value["images"]["collection"]["id"],
            "prepare_image_id": build_value["images"]["prepare"]["id"],
            "reference_image_id": build_value["images"]["reference"]["id"],
        },
        "expanded_vectors_sha256": class_attestation.browser_egress_vectors_sha256(),
        "passed_vector_count": class_attestation.BROWSER_EGRESS_VECTOR_COUNT,
        "passed": True,
    }
    monkeypatch.setattr(
        class_attestation,
        "verify_browser_egress_qualification",
        lambda *_args, **_kwargs: copy.deepcopy(browser_egress),
    )

    active_source["value"] = collection_source
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", str(collection_source["image_digest"]))
    foundation_path = class_attestation.create_class_foundation_attestation(
        tmp_path / "class-study-foundation-v59.json",
        cohort_version=cohort_version,
        build_execution_receipt=build_path,
        pinned_cdp_receipt=pinned_path,
        browser_egress_qualification_root=browser_egress_root,
        reference_receipt=reference_path,
        code_gate_receipt=code_path,
        controlled_qualification_receipt=qualification_path,
        regression_result_roots=regression_roots,
        controlled_result_roots=controlled_roots,
    )

    active_source["value"] = prepare_source
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", str(prepare_source["image_digest"]))
    return foundation_path, build_path, collection_source, active_source


def _replace_receipt_payload(path: Path, payload: dict) -> None:
    if path.name == "provenance.json":
        schema = payload.get("acquisition_schema_version", acquisition_module.SCHEMA_VERSION)
        if schema in {2, 3, 4}:
            source_contract = _HISTORICAL_ACQUISITION_CONTRACTS["schema3_4"]
            payload["cdp_target_instrumentation_policy"] = source_contract["instrumentation_policy"]
            if schema >= 3:
                payload["passive_render_contract"] = copy.deepcopy(
                    source_contract["passive_render_contract"]
                )
                payload["passive_render_contract_sha256"] = source_contract[
                    "passive_render_contract_sha256"
                ]
        elif schema == 5:
            payload.update(
                copy.deepcopy(_HISTORICAL_ACQUISITION_CONTRACTS["schema5_v10"]["fixed_provenance"])
            )
            payload["source"]["lab_commit"] = _HISTORICAL_ACQUISITION_CONTRACTS["schema5_v10"][
                "source_revision"
            ]
        elif schema == 6:
            payload["cdp_target_instrumentation_policy"] = (
                acquisition_module._SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY
            )
            payload["passive_render_contract"] = copy.deepcopy(
                acquisition_module._SCHEMA_SIX_PASSIVE_RENDER_CONTRACT
            )
            payload["passive_render_contract_sha256"] = (
                acquisition_module._SCHEMA_SIX_PASSIVE_RENDER_CONTRACT_SHA256
            )
            payload["source"]["lab_commit"] = "6957614b83e67cced5fd262fe97814824d21c8f9"
        if schema < 6:
            if "acquisition_authority" in payload:
                payload["foundation_attestation"] = payload.pop("acquisition_authority")
            payload.pop("acquisition_selection_policy", None)
            if "baseline_scheduling_contract" in payload:
                payload["baseline_scheduling_contract"] = (
                    acquisition_module.BASELINE_SCHEDULING_CONTRACT
                )
    receipt_type = load_json(path)["receipt_type"]
    path.write_bytes(canonical_json_bytes(bind_receipt(payload, receipt_type=receipt_type)))


def _strip_schema_five_policy_evidence(value: dict) -> None:
    """Convert current attempt ledgers to their exact schema 1--4 shape."""

    candidates = value.get("candidates")
    states = candidates.values() if isinstance(candidates, dict) else (value,)
    for state in states:
        for attempt in state.get("navigation_attempts", []):
            attempt.pop("policy_evidence", None)
        for page in state.get("pages", []):
            for attempt in page.get("probe_attempts", []):
                attempt.pop("policy_evidence", None)


def _downgrade_observation_to_historical_contract(
    runner: Path,
    observation: dict,
    *,
    provenance_sha256: str,
    acquisition_schema_version: int,
) -> None:
    """Rewrite a current observation into an exact source-era evidence shape."""

    if acquisition_schema_version in {3, 4}:
        source_contract = _HISTORICAL_ACQUISITION_CONTRACTS["schema3_4"]
        render_schema_version = source_contract["render_observation"]["schema_version"]
        audit_schema_version = source_contract["discovery_event_audit_schema_version"]
        instrumentation_policy = source_contract["instrumentation_policy"]
        passive_render_contract = source_contract["passive_render_contract"]
        passive_render_contract_sha256 = source_contract["passive_render_contract_sha256"]
    elif acquisition_schema_version == 6:
        render_schema_version = acquisition_module._SCHEMA_SIX_RENDER_OBSERVATION_SCHEMA_VERSION
        audit_schema_version = acquisition_module._SCHEMA_SIX_DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION
        instrumentation_policy = acquisition_module._SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY
        passive_render_contract = acquisition_module._SCHEMA_SIX_PASSIVE_RENDER_CONTRACT
        passive_render_contract_sha256 = (
            acquisition_module._SCHEMA_SIX_PASSIVE_RENDER_CONTRACT_SHA256
        )
    else:  # pragma: no cover - test helper misuse
        raise AssertionError("unsupported historical observation fixture")

    prepared_path = Path(observation["prepared_path"])
    manifest = load_json(prepared_path)
    preparation = manifest["preparation"]
    render = copy.deepcopy(preparation["render_observation"])
    internal = render.pop("internal_document_lifecycle_summary")
    assert internal["total"] == 0 and internal["diagnostics"] == []
    if acquisition_schema_version in {3, 4}:
        for field in (
            "router_shutdown_ready",
            "bootstrap_prearm_summary",
            "egress_prearm_summary",
            "non_replayable_egress_summary",
            "browser_context_service_worker_count",
        ):
            render.pop(field)
        render["last_relevant_event_ms"] = (
            render["load_event_ms"]
            + source_contract["passive_render_contract"]["hard_cap_after_load_ms"]
            - source_contract["passive_render_contract"]["quiet_window_ms"]
        )
        render["quiet_started_ms"] = render["last_relevant_event_ms"]
        render["cutoff_ms"] = (
            render["load_event_ms"]
            + source_contract["passive_render_contract"]["hard_cap_after_load_ms"]
        )
    render["schema_version"] = render_schema_version
    render_sha256 = evidence_sha256(render)
    audit = copy.deepcopy(preparation["discovery_event_audit"])
    assert all(event.get("kind") != "browser-internal-document" for event in audit["events"])
    if acquisition_schema_version in {3, 4}:
        audit["events"][-1]["monotonic_ms"] = render["last_relevant_event_ms"]
    audit["schema_version"] = audit_schema_version
    audit["instrumentation_policy"] = instrumentation_policy
    audit["passive_render_contract_sha256"] = passive_render_contract_sha256
    audit["render_observation_sha256"] = render_sha256
    audit["summary"].pop("browser_internal_document_count")
    audit_sha256 = evidence_sha256(audit)
    preparation["passive_render_contract"] = copy.deepcopy(passive_render_contract)
    preparation["passive_render_contract_sha256"] = passive_render_contract_sha256
    preparation["render_observation"] = render
    preparation["render_observation_sha256"] = render_sha256
    preparation["discovery_event_audit"] = audit
    preparation["discovery_event_audit_sha256"] = audit_sha256
    coverage = preparation["coverage_admission"]
    coverage["passive_render_contract_sha256"] = passive_render_contract_sha256
    coverage["render_observation_sha256"] = render_sha256
    coverage["discovery_event_audit_sha256"] = audit_sha256
    prepared_path.write_bytes(canonical_json_bytes(manifest))
    prepared_sha256 = acquisition_module.sha256_file(prepared_path)
    resource_graph_sha256 = acquisition_module._prepared_replay_identity_sha256(
        manifest,
        acquisition_schema_version=acquisition_schema_version,
    )

    observation["runner_provenance_sha256"] = provenance_sha256
    observation["discovery_instrumentation_policy"] = instrumentation_policy
    observation["passive_render_contract_sha256"] = passive_render_contract_sha256
    observation["render_observation"] = render
    observation["render_observation_sha256"] = render_sha256
    observation["discovery_event_audit_sha256"] = audit_sha256
    observation["prepared_workload_sha256"] = prepared_sha256
    observation["resource_graph_sha256"] = resource_graph_sha256

    response_path = runner / observation["document_response_receipt_path"]
    response_payload = copy.deepcopy(load_json(response_path)["payload"])
    assert response_payload["document_response_schema_version"] == (
        acquisition_module.DOCUMENT_RESPONSE_SCHEMA_VERSION
    )
    response_payload["document_response_schema_version"] = (
        acquisition_module.SCHEMA_SIX_DOCUMENT_RESPONSE_SCHEMA_VERSION
    )
    response_payload["runner_provenance_sha256"] = provenance_sha256
    response_payload["prepared_workload_sha256"] = prepared_sha256
    response_payload["resource_graph_sha256"] = resource_graph_sha256
    response_payload["cdp_target_instrumentation_policy"] = instrumentation_policy
    _replace_receipt_payload(response_path, response_payload)
    observation["document_response_receipt_sha256"] = acquisition_module.sha256_file(response_path)
    acquisition_module._validate_versioned_class_study_preparation(
        manifest,
        workload_id=prepared_path.stem,
        acquisition_schema_version=acquisition_schema_version,
        instrumentation_policy=instrumentation_policy,
    )


def _first_terminal_state(runner: Path) -> tuple[str, dict]:
    checkpoint = load_json(runner / "checkpoint.json")
    return next(
        (candidate_id, state)
        for candidate_id, state in checkpoint["payload"]["candidates"].items()
        if state["terminal"] is not None
    )


def _rewrite_terminal_and_checkpoint(
    runner: Path,
    *,
    mutate,
) -> tuple[str, dict, dict]:
    checkpoint = load_json(runner / "checkpoint.json")
    checkpoint_payload = copy.deepcopy(checkpoint["payload"])
    candidate_id, state = next(
        (candidate_id, state)
        for candidate_id, state in checkpoint_payload["candidates"].items()
        if state["terminal"] is not None
    )
    terminal_path = runner / state["terminal"]["path"]
    terminal_payload = copy.deepcopy(load_json(terminal_path)["payload"])
    mutate(state, terminal_payload)
    if terminal_payload.get("terminal_schema_version") == TERMINAL_SCHEMA_VERSION:
        terminal_payload["checkpoint_state_sha256"] = (
            acquisition_module._normalised_terminal_state_sha256(
                state, kind=terminal_payload["kind"]
            )
        )
    _replace_receipt_payload(terminal_path, terminal_payload)
    state["terminal"]["sha256"] = hashlib.sha256(terminal_path.read_bytes()).hexdigest()
    _replace_receipt_payload(runner / "checkpoint.json", checkpoint_payload)
    return candidate_id, state, terminal_payload


def _prepared_manifest(url: str, approved_origins, *, source_override=None) -> dict:
    source_origin = origin(url)
    assert source_origin is not None
    resource_origins = [source_origin, *sorted(set(approved_origins) - {source_origin})]
    resources = [
        {
            "id": index,
            "url": url if index == 0 else f"{resource_origin}/resource-{index}",
            "type": "Document" if index == 0 else "Script",
            "depends_on": [] if index == 0 else [0],
            "headers": [],
        }
        for index, resource_origin in enumerate(resource_origins)
    ]
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    source = source_override or {
        "image_digest": "sha256:" + "1" * 64,
        "lab_commit": "2" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": empty_sha256,
        "neqo_commit": "3" * 40,
        "neqo_pinned_commit": "3" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": empty_sha256,
    }
    target_source = {
        "session_path": [],
        "target_id": "fixture-page",
        "target_type": "page",
        "generation": 0,
        "parent_session_path": None,
        "parent_frame_id": None,
    }
    events = []
    for resource in resources:
        resource_id = resource["id"]
        occurrence_id = f"request-{resource_id:08d}"
        dependency_evidence = (
            []
            if resource_id == 0
            else [
                {
                    "kind": "document-url",
                    "value": url,
                    "resolved_resource_id": 0,
                }
            ]
        )
        events.extend(
            [
                {
                    "sequence": len(events) + 1,
                    "monotonic_ms": 0,
                    "kind": "network-request",
                    "source": target_source,
                    "network_id": f"network-{resource_id}",
                    "occurrence_id": occurrence_id,
                    "occurrence_index": 0,
                    "method": "GET",
                    "url": resource["url"],
                    "frame_id": None,
                    "resource_type": resource["type"],
                    "safe_request_headers": resource["headers"],
                    "interception_required": True,
                    "redirected": False,
                    "redirect_from_occurrence_id": None,
                    "mapping": {"kind": "resource", "resource_id": resource_id},
                    "dependency_evidence": dependency_evidence,
                    "resolved_dependency_resource_ids": resource["depends_on"],
                },
                {
                    "sequence": len(events) + 2,
                    "monotonic_ms": 0,
                    "kind": "fetch-request",
                    "source": target_source,
                    "fetch_id": f"fetch-{resource_id}",
                    "network_id": f"network-{resource_id}",
                    "redirected_fetch_id": None,
                    "network_occurrence_id": occurrence_id,
                    "method": "GET",
                    "url": resource["url"],
                    "frame_id": None,
                    "policy_decision": "continue",
                    "policy_reason": None,
                    "relationship": "primary",
                },
                {
                    "sequence": len(events) + 3,
                    "monotonic_ms": 0,
                    "kind": "network-terminal",
                    "source": target_source,
                    "network_id": f"network-{resource_id}",
                    "outcome": "finished",
                    "network_occurrence_ids": [occurrence_id],
                },
            ]
        )
    worker_summary = {
        "held": 0,
        "released": 0,
        "pending": 0,
        "released_after_setup_envelopes": 0,
        "owner_target_types": {
            "page": 0,
            "iframe": 0,
            "worker": 0,
            "shared_worker": 0,
        },
    }
    render_observation = {
        "schema_version": RENDER_OBSERVATION_SCHEMA_VERSION,
        "clock": "monotonic-relative-ms",
        "navigation_started_ms": 0,
        "load_event_ms": 0,
        "last_relevant_event_ms": 0,
        "quiet_started_ms": 10_000,
        "cutoff_ms": 13_000,
        "active_request_ids": [],
        "active_request_count": 0,
        "router_shutdown_ready": True,
        "bootstrap_prearm_summary": {
            "schema_version": 1,
            "held_total": 0,
            "released_total": 0,
            "pending_total": 0,
            "release_before_setup_envelopes_total": 0,
            "by_worker_type": {
                "worker": copy.deepcopy(worker_summary),
                "shared_worker": copy.deepcopy(worker_summary),
            },
        },
        "egress_prearm_summary": _egress_prearm_summary(),
        "internal_document_lifecycle_summary": (_terminal_internal_document_lifecycle_summary()),
        "non_replayable_egress_summary": _non_replayable_egress_summary(),
        "browser_context_service_worker_count": 0,
        "cutoff_reason": "quiescent",
    }
    render_observation_sha256 = evidence_sha256(render_observation)
    discovery_event_audit = {
        "schema_version": DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
        "instrumentation_policy": CDP_TARGET_INSTRUMENTATION_POLICY,
        "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
        "render_observation_sha256": render_observation_sha256,
        "events": events,
        "summary": {
            "event_count": len(events),
            "target_event_count": 0,
            "browser_internal_document_count": 0,
            "network_request_count": len(resources),
            "fetch_request_count": len(resources),
            "fetch_internal_restart_count": 0,
            "terminal_event_count": len(resources),
            "resource_occurrence_count": len(resources),
            "exclusion_occurrence_count": 0,
        },
    }
    discovery_event_audit_sha256 = evidence_sha256(discovery_event_audit)
    return {
        "preparation": {
            "source_url": url,
            "final_url": url,
            "chromium_version": "test-chromium",
            "settle_ms": 10_000,
            "observed_request_count": len(resources),
            "observed_origins": list(approved_origins),
            "approved_origins": list(approved_origins),
            "origin_ip_pins": {value: "1.1.1.1" for value in sorted(approved_origins)},
            "exclusions": [],
            "browser_request_headers": [
                {"resource_id": resource["id"], "headers": resource["headers"]}
                for resource in resources
            ],
            "request_header_transformation": (
                "browser-safe-input-to-neqo-stability-frozen-runtime-v1"
            ),
            "passive_render_contract": passive_render_contract(),
            "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
            "render_observation": render_observation,
            "render_observation_sha256": render_observation_sha256,
            "discovery_event_audit": discovery_event_audit,
            "discovery_event_audit_sha256": discovery_event_audit_sha256,
            "max_response_bytes": 1_048_576,
            "timeout_seconds": 30,
            "stability_runs": 3,
            "stability_profile": "live",
            "stability_defense": "none",
            "stability_seed": 0,
            "udp_payload_qualification": {
                "schema_version": 1,
                "configured_udp_payload_ceiling": 1_200,
                "runs": [
                    {
                        "run_index": run_index,
                        "packets_sha256": f"{run_index + 1:064x}",
                        "total": {
                            "packet_count": 2,
                            "observed_udp_payload_max": 1_200,
                            "oversized_packet_count": 0,
                        },
                        "incoming": {
                            "packet_count": 1,
                            "observed_udp_payload_max": 1_200,
                            "oversized_packet_count": 0,
                        },
                        "outgoing": {
                            "packet_count": 1,
                            "observed_udp_payload_max": 1_199,
                            "oversized_packet_count": 0,
                        },
                    }
                    for run_index in range(3)
                ],
            },
            "neqo_version": "test-neqo",
            "neqo_base_commit": "4" * 40,
            "published_qcsd_commit": "5" * 40,
            "migration_commit": "6" * 40,
            "expected_responses": [
                {
                    "resource_id": resource["id"],
                    "status": 200,
                    "bytes": 100 + resource["id"],
                    "body_sha256": f"{resource['id'] + 1:064x}",
                }
                for resource in resources
            ],
            "lab_source": source,
            "prepare_image_digest": source["image_digest"],
            "coverage_admission": {
                "schema_version": 3,
                "policy": "all-approved-origins-and-rendered-resources",
                "required_origins": list(approved_origins),
                "required_resources": [
                    {"id": resource["id"], "url": resource["url"]} for resource in resources
                ],
                "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
                "render_observation_sha256": render_observation_sha256,
                "discovery_event_audit_sha256": discovery_event_audit_sha256,
                "origin_ip_pins_sha256": evidence_sha256(
                    {value: "1.1.1.1" for value in sorted(approved_origins)}
                ),
                "browser_request_headers_sha256": evidence_sha256(
                    [
                        {
                            "resource_id": resource["id"],
                            "headers": resource["headers"],
                        }
                        for resource in resources
                    ]
                ),
                "network_request_count": len(resources),
                "resource_occurrence_count": len(resources),
                "exclusion_occurrence_count": 0,
            },
        },
        "resources": resources,
    }


def _homepage_navigation(domain: str) -> NavigationDiscovery:
    homepage = f"https://{domain}/"
    homepage_origin = f"https://{domain}"
    return NavigationDiscovery(
        registrable_domain=domain,
        links=(),
        observed_origins=(homepage_origin,),
        page_observed_origins=((homepage, (homepage_origin,)),),
    )


def test_runner_distinguishes_component_limits_from_whole_action_cutoffs(
    tmp_path: Path,
) -> None:
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=_catalogue(tmp_path / "catalogue.json"),
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    provenance = load_json(runner / "provenance.json")["payload"]

    assert MAX_ACQUISITION_BACKEND_TIMEOUT_MS == 60_000
    assert MAX_PASSIVE_RENDER_AFTER_LOAD_MS == 30_000
    assert provenance["acquisition_schema_version"] == acquisition_module.SCHEMA_VERSION
    assert provenance["browser_tool"] == playwright_driver.expected_browser_tool_identity()
    tampered = copy.deepcopy(provenance)
    tampered["browser_tool"]["chromium_version"] = "caller-authored"
    with pytest.raises(ValueError, match="provenance policy"):
        acquisition_module._validate_runner_runtime(tampered)
    checkpoint = load_json(runner / "checkpoint.json")["payload"]
    assert checkpoint["checkpoint_schema_version"] == CHECKPOINT_SCHEMA_VERSION
    assert checkpoint["baseline_batches"] == []
    assert checkpoint["active_batch"] is None
    assert provenance["browser_navigation_timeout_ms"] == 60_000
    assert provenance["passive_render_hard_cap_after_load_ms"] == 30_000
    assert provenance["acquisition_action_timing_contract"] == (
        acquisition_module.ACTION_TIMING_CONTRACT
    )
    assert provenance["baseline_scheduling_contract"] == (
        acquisition_module.TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT
    )
    assert "browser_discovery_attempt_budget_ms" not in provenance
    assert "pending_baseline_guard_ms" not in provenance["origin_policy"]
    assert PENDING_BASELINE_GUARD_MS == 2_400_000


@pytest.mark.parametrize(
    "mutate_provenance",
    (
        lambda payload: payload["browser_tool"].update(chromium_revision="unattested"),
        lambda payload: payload["browser_tool"].update(schema_version=True),
        lambda payload: payload["passive_render_contract"]["viewport"].update(
            deviceScaleFactor=True
        ),
        lambda payload: payload.update(cdp_target_instrumentation_policy="stale-policy"),
        lambda payload: payload["origin_policy"].update(max_origins=31),
        lambda payload: payload.update(eligibility_inputs=["classifier"]),
        lambda payload: payload.update(unexpected_contract_field="resealed"),
    ),
    ids=(
        "browser-identity",
        "browser-schema-bool-alias",
        "passive-contract-bool-alias",
        "cdp-policy",
        "origin-policy",
        "eligibility-policy",
        "exact-keyset",
    ),
)
def test_current_completion_rejects_coherently_rebound_provenance_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate_provenance,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    catalogue_value, candidates = acquisition_module.load_candidate_catalogue_receipt(catalogue)
    monkeypatch.setattr(
        acquisition_module,
        "load_candidate_catalogue_receipt",
        lambda _path: (catalogue_value, candidates[:1]),
    )
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="ignored-caller-value",
    )
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=RejectingBackend(),
    )
    completion_payload = copy.deepcopy(
        load_json(write_acquisition_completion(runner, candidate_catalogue_path=catalogue))[
            "payload"
        ]
    )

    provenance_path = runner / "provenance.json"
    provenance_payload = copy.deepcopy(load_json(provenance_path)["payload"])
    mutate_provenance(provenance_payload)
    _replace_receipt_payload(provenance_path, provenance_payload)
    provenance_sha256 = hashlib.sha256(provenance_path.read_bytes()).hexdigest()

    checkpoint_path = runner / "checkpoint.json"
    checkpoint_payload = copy.deepcopy(load_json(checkpoint_path)["payload"])
    checkpoint_payload["provenance_sha256"] = provenance_sha256
    terminal_receipts: dict[str, dict] = {}
    for candidate_id, state in checkpoint_payload["candidates"].items():
        terminal_path = runner / state["terminal"]["path"]
        terminal_payload = copy.deepcopy(load_json(terminal_path)["payload"])
        terminal_payload["provenance_sha256"] = provenance_sha256
        _replace_receipt_payload(terminal_path, terminal_payload)
        state["terminal"]["sha256"] = hashlib.sha256(terminal_path.read_bytes()).hexdigest()
        terminal_receipts[candidate_id] = copy.deepcopy(state["terminal"])
    _replace_receipt_payload(checkpoint_path, checkpoint_payload)
    checkpoint = load_json(checkpoint_path)

    completion_payload.update(
        provenance_sha256=provenance_sha256,
        checkpoint_payload_sha256=checkpoint["payload_sha256"],
        terminal_receipts=terminal_receipts,
    )
    resealed_completion = bind_receipt(
        completion_payload,
        receipt_type=COMPLETION_TYPE,
    )
    assert (
        resealed_completion["payload"]["provenance_sha256"]
        == hashlib.sha256(provenance_path.read_bytes()).hexdigest()
    )
    assert (
        resealed_completion["payload"]["checkpoint_payload_sha256"] == checkpoint["payload_sha256"]
    )

    with pytest.raises(ValueError, match="versioned acquisition"):
        validate_acquisition_completion(
            resealed_completion,
            candidate_catalogue_path=catalogue,
            runner_root=runner,
        )


def test_batch_constants_and_public_action_bound_are_exact(tmp_path: Path) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    checkpoint_before = (runner / "checkpoint.json").read_bytes()

    assert MAX_CANDIDATES_PER_ACTION == 2
    assert GLOBAL_LIVE_PAGE_CAP == 5
    for invalid in (True, 0, 3):
        with pytest.raises(ValueError, match="max_candidates"):
            run_due_acquisition(
                runner,
                candidate_catalogue_path=catalogue,
                stability_root=tmp_path / "stability",
                workload_root=tmp_path / "workloads",
                backend=RejectingBackend(),
                max_candidates=invalid,
            )
    assert (runner / "checkpoint.json").read_bytes() == checkpoint_before


def test_compatible_batch_selection_is_anchor_first_and_page_capped() -> None:
    first, second, third = (
        SimpleNamespace(name="first"),
        SimpleNamespace(name="second"),
        SimpleNamespace(name="third"),
    )

    selected = acquisition_module._select_compatible_batch(
        ((first, 4, "probe"), (second, 4, "probe"), (third, 1, "probe")),
        maximum=MAX_CANDIDATES_PER_ACTION,
    )
    assert selected == (first, third)
    assert acquisition_module._select_compatible_batch(
        ((first, 4, "probe"), (second, 2, "probe")),
        maximum=MAX_CANDIDATES_PER_ACTION,
    ) == (first,)
    assert acquisition_module._select_compatible_batch(
        ((first, 1, "probe-a"), (second, 1, "probe-b")),
        maximum=MAX_CANDIDATES_PER_ACTION,
    ) == (first,)


def test_baseline_ledger_allows_non_global_flatten_order_for_compatible_pairs() -> None:
    first = datetime(2026, 8, 28, tzinfo=UTC)
    second = acquisition_module.earliest_safe_baseline(
        first + timedelta(milliseconds=acquisition_module.MINIMUM_BASELINE_SPACING_MS),
        (first,),
    )
    states = {
        "candidate-a": {
            "pages": [{}, {}, {}, {}],
            "baseline_started_at": acquisition_module._format_time(first),
        },
        "candidate-b": {
            "pages": [{}, {}, {}, {}],
            "baseline_started_at": acquisition_module._format_time(second),
        },
        "candidate-c": {
            "pages": [{}],
            "baseline_started_at": acquisition_module._format_time(first),
        },
    }

    def baseline_batch(start: datetime, candidate_ids: list[str]) -> dict:
        body = {
            "baseline_started_at": acquisition_module._format_time(start),
            "candidate_ids": candidate_ids,
            "live_page_count": sum(len(states[value]["pages"]) for value in candidate_ids),
        }
        return {
            "batch_id": acquisition_module._batch_identifier("baseline", body),
            **body,
        }

    batches = [
        baseline_batch(first, ["candidate-a", "candidate-c"]),
        baseline_batch(second, ["candidate-b"]),
    ]
    assert acquisition_module._validate_baseline_batches(
        batches,
        states=states,
        candidate_order=("candidate-a", "candidate-b", "candidate-c"),
    ) == tuple(batches)


@pytest.mark.parametrize(
    ("offset", "valid"),
    (
        (timedelta(seconds=24, microseconds=999_500), False),
        (timedelta(seconds=25), True),
        (timedelta(seconds=35), True),
        (timedelta(seconds=35, microseconds=500), False),
    ),
)
def test_probe_window_edges_use_exact_elapsed_time_not_rounded_milliseconds(
    offset: timedelta,
    valid: bool,
) -> None:
    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    observed = baseline + offset
    page = {
        "page": {"ordinal": 0},
        "observations": [],
        "probe_attempts": [
            {
                "probe_id": "t+30s",
                "workload_id": _probe_attempt_workload_id("candidate", 0, "t+30s", 1),
                "attempt": 1,
                "observed_at": acquisition_module._format_time(observed),
                "completed_at": acquisition_module._format_time(observed),
                "outcome": "interrupted",
                "reason": "fixture interruption",
                "policy_evidence": None,
            }
        ],
    }

    def validate() -> None:
        _validate_probe_attempts(
            page,
            candidate_id="candidate",
            baseline_started_at=acquisition_module._format_time(baseline),
            enforce_duration_limit=True,
        )

    if valid:
        validate()
    else:
        with pytest.raises(ValueError, match="probe-attempt ledger"):
            validate()


def test_due_scheduler_uses_the_same_exact_inclusive_window_edges() -> None:
    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    page = {
        "page": {"ordinal": 0},
        "observations": [],
        "probe_attempts": [],
    }
    state = {
        "baseline_started_at": acquisition_module._format_time(baseline),
        "pages": [page],
    }
    assert (
        acquisition_module._due_pages(
            state,
            baseline + timedelta(seconds=24, microseconds=999_500),
            candidate_id="candidate",
        )
        == []
    )
    assert acquisition_module._due_pages(
        state,
        baseline + timedelta(seconds=25),
        candidate_id="candidate",
    ) == [page]
    assert acquisition_module._due_pages(
        state,
        baseline + timedelta(seconds=35),
        candidate_id="candidate",
    ) == [page]
    with pytest.raises(acquisition_module.MissedProbeWindow):
        acquisition_module._due_pages(
            state,
            baseline + timedelta(seconds=35, microseconds=500),
            candidate_id="candidate",
        )


class RejectingBackend:
    def discover_navigation(self, domain: str):
        raise TerminalProbePolicyError(f"typed DNS rejection for {domain}")


class SlowBackend:
    def __init__(self, clock):
        self.clock = clock

    def discover_navigation(self, domain: str):
        self.clock.value += timedelta(seconds=10)
        return _homepage_navigation(domain)

    def discover(self, url, approved_origins):
        return DiscoveryResult(
            source_url=url,
            final_url=url,
            chromium_version="test",
            settle_ms=0,
            observed_request_count=1,
            observed_origins=list(approved_origins),
            approved_origins=list(approved_origins),
            exclusions=[],
            resources=[{"id": 0}],
            origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
            expandable_origins=list(approved_origins),
        )

    def prepare(self, workload_id, url, approved_origins, output_root, *, origin_ip_pins=None):
        output_root.mkdir(parents=True, exist_ok=True)
        path = output_root / f"{workload_id}.json"
        runtime_image = acquisition_module.os.environ.get("QCSD_LAB_IMAGE_DIGEST", "native")
        runtime_source = dict(acquisition_module.source_metadata())
        if runtime_image == "native" and runtime_source.get("image_digest") is None:
            runtime_source["image_digest"] = "native"
        manifest = _prepared_manifest(url, approved_origins, source_override=runtime_source)
        path.write_bytes(canonical_json_bytes(manifest))
        self.clock.value += timedelta(seconds=20)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return PreparedProbe(
            observed_at=self.clock.value.isoformat().replace("+00:00", "Z"),
            final_url=url,
            status=200,
            content_type="text/html",
            body_bytes=100,
            body_sha256=f"{1:064x}",
            resource_graph_sha256=_prepared_replay_identity_sha256(manifest),
            prepared=PreparedWorkload(
                path,
                digest,
                len(approved_origins),
                len(approved_origins),
            ),
            chromium_version="test-chromium",
            neqo_provenance={
                "neqo_version": "test-neqo",
                "neqo_base_commit": "4" * 40,
                "published_qcsd_commit": "5" * 40,
                "migration_commit": "6" * 40,
            },
            passive_render_contract_sha256=(
                manifest["preparation"]["passive_render_contract_sha256"]
            ),
            render_observation=manifest["preparation"]["render_observation"],
            render_observation_sha256=(manifest["preparation"]["render_observation_sha256"]),
            discovery_event_audit_sha256=(manifest["preparation"]["discovery_event_audit_sha256"]),
            preparation_origin_ip_pins=dict(origin_ip_pins or {}),
            document_response_chromium_version="test-chromium",
        )


class ProbeRejectingBackend(SlowBackend):
    def discover(self, url, approved_origins):
        raise TerminalProbePolicyError(f"probe policy rejected {url}")


class TwoPageBackend(SlowBackend):
    def discover_navigation(self, domain: str):
        self.clock.value += timedelta(seconds=10)
        homepage = f"https://{domain}/"
        linked = f"https://{domain}/about"
        candidate_origin = f"https://{domain}"
        return NavigationDiscovery(
            registrable_domain=domain,
            links=(DiscoveredLink(linked, "text/html"),),
            observed_origins=(candidate_origin,),
            page_observed_origins=(
                (homepage, (candidate_origin,)),
                (linked, (candidate_origin,)),
            ),
        )


class FakeClock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += timedelta(seconds=seconds)


class BatchBackend:
    """Instant, barrier-capable backend for transactional batch tests."""

    def __init__(
        self,
        observed_at: datetime,
        *,
        page_counts: dict[str, int] | None = None,
        runner: Path | None = None,
        navigation_barrier: Barrier | None = None,
        prepare_barrier: Barrier | None = None,
        interrupt_prefix: str | None = None,
    ) -> None:
        self.observed_at = observed_at
        self.page_counts = page_counts or {}
        self.runner = runner
        self.navigation_barrier = navigation_barrier
        self.prepare_barrier = prepare_barrier
        self.interrupt_prefix = interrupt_prefix
        self.interrupted = False
        self.lock = Lock()
        self.navigation_live = 0
        self.navigation_live_max = 0
        self.prepare_live = 0
        self.prepare_live_max = 0
        self.active_snapshots: list[dict] = []
        self.workload_ids: list[str] = []

    def _enter(self, stage: str) -> None:
        with self.lock:
            attribute = f"{stage}_live"
            maximum = f"{stage}_live_max"
            value = getattr(self, attribute) + 1
            setattr(self, attribute, value)
            setattr(self, maximum, max(getattr(self, maximum), value))

    def _leave(self, stage: str) -> None:
        with self.lock:
            attribute = f"{stage}_live"
            setattr(self, attribute, getattr(self, attribute) - 1)

    def _snapshot_active(self) -> None:
        if self.runner is None:
            return
        snapshot = copy.deepcopy(
            load_json(self.runner / "checkpoint.json")["payload"]["active_batch"]
        )
        with self.lock:
            self.active_snapshots.append(snapshot)

    def discover_navigation(self, domain: str) -> NavigationDiscovery:
        self._enter("navigation")
        try:
            if self.navigation_barrier is not None:
                self.navigation_barrier.wait(timeout=5)
            self._snapshot_active()
            page_count = self.page_counts.get(domain, 1)
            homepage = f"https://{domain}/"
            candidate_origin = f"https://{domain}"
            links = tuple(
                DiscoveredLink(f"https://{domain}/page-{ordinal}", "text/html")
                for ordinal in range(1, page_count)
            )
            page_urls = (homepage, *(link.url for link in links))
            return NavigationDiscovery(
                registrable_domain=domain,
                links=links,
                observed_origins=(candidate_origin,),
                page_observed_origins=tuple((url, (candidate_origin,)) for url in page_urls),
            )
        finally:
            self._leave("navigation")

    def discover(self, url, approved_origins):
        return DiscoveryResult(
            source_url=url,
            final_url=url,
            chromium_version="test",
            settle_ms=0,
            observed_request_count=1,
            observed_origins=list(approved_origins),
            approved_origins=list(approved_origins),
            exclusions=[],
            resources=[{"id": 0}],
            origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
            expandable_origins=list(approved_origins),
        )

    def prepare(self, workload_id, url, approved_origins, output_root, *, origin_ip_pins=None):
        self._enter("prepare")
        try:
            with self.lock:
                self.workload_ids.append(workload_id)
            if self.prepare_barrier is not None:
                self.prepare_barrier.wait(timeout=5)
            self._snapshot_active()
            should_interrupt = False
            with self.lock:
                if (
                    self.interrupt_prefix is not None
                    and workload_id.startswith(self.interrupt_prefix)
                    and not self.interrupted
                ):
                    self.interrupted = True
                    should_interrupt = True
            if should_interrupt:
                raise KeyboardInterrupt
            output_root.mkdir(parents=True, exist_ok=True)
            path = output_root / f"{workload_id}.json"
            manifest = _prepared_manifest(
                url,
                approved_origins,
                source_override=dict(acquisition_module.source_metadata()),
            )
            path.write_bytes(canonical_json_bytes(manifest))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            observed_at = acquisition_module._format_time(self.observed_at)
            return PreparedProbe(
                observed_at=observed_at,
                final_url=url,
                status=200,
                content_type="text/html",
                body_bytes=100,
                body_sha256=f"{1:064x}",
                resource_graph_sha256=_prepared_replay_identity_sha256(manifest),
                prepared=PreparedWorkload(
                    path,
                    digest,
                    len(approved_origins),
                    len(approved_origins),
                ),
                chromium_version="test-chromium",
                neqo_provenance={
                    "neqo_version": "test-neqo",
                    "neqo_base_commit": "4" * 40,
                    "published_qcsd_commit": "5" * 40,
                    "migration_commit": "6" * 40,
                },
                passive_render_contract_sha256=(
                    manifest["preparation"]["passive_render_contract_sha256"]
                ),
                render_observation=manifest["preparation"]["render_observation"],
                render_observation_sha256=(manifest["preparation"]["render_observation_sha256"]),
                discovery_event_audit_sha256=(
                    manifest["preparation"]["discovery_event_audit_sha256"]
                ),
                preparation_origin_ip_pins=dict(origin_ip_pins or {}),
                document_response_chromium_version="test-chromium",
            )
        finally:
            self._leave("prepare")


class NoNetworkBackend:
    """Fail if deterministic recovery accidentally performs live acquisition."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def _called(self, stage: str, identity: str):
        self.calls.append((stage, identity))
        pytest.fail(f"deterministic recovery performed {stage} network work")

    def discover_navigation(self, domain: str):
        return self._called("navigation", domain)

    def discover(self, url, approved_origins):
        return self._called("discovery", url)

    def prepare(self, workload_id, url, approved_origins, output_root, *, origin_ip_pins=None):
        return self._called("preparation", workload_id)


def test_direct_runner_initialisation_rejects_generic_hash_bound_foundation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    foundation = _foundation(tmp_path / "generic-foundation.json")
    destination = tmp_path / "runner"
    monkeypatch.setattr(
        acquisition_module,
        "_foundation_attestation_binding",
        _PRODUCTION_FOUNDATION_ATTESTATION_BINDING,
    )

    with pytest.raises(ValueError, match="foundation"):
        initialise_runner(
            destination,
            candidate_catalogue_path=catalogue,
            foundation_attestation=foundation,
            started_at="2026-08-28T00:00:00Z",
            browser_tool="test-browser@1",
        )
    assert not destination.exists()


def test_prepare_runtime_deep_foundation_supports_acquisition_and_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Exercise the production foundation boundary in the prepare image role."""

    foundation, build_path, collection_source, active_source = _real_prepare_runtime_foundation(
        tmp_path, monkeypatch
    )
    monkeypatch.setattr(
        buflo_study,
        "_run_lab_code_gate_commands",
        lambda: pytest.fail("acquisition authority validation must not execute Lab tests"),
    )
    catalogue_path = _catalogue(tmp_path / "catalogue.json")
    catalogue, candidates = acquisition_module.load_candidate_catalogue_receipt(catalogue_path)
    candidates = candidates[:2]
    monkeypatch.setattr(
        acquisition_module,
        "load_candidate_catalogue_receipt",
        lambda _path: (copy.deepcopy(catalogue), candidates),
    )
    monkeypatch.setattr(
        acquisition_module,
        "_foundation_attestation_binding",
        _PRODUCTION_FOUNDATION_ATTESTATION_BINDING,
    )

    foundation_payload = load_json(foundation)["payload"]
    code_gate_path = Path(foundation_payload["evidence"]["code_gate"]["path"])
    with pytest.raises(ValueError, match="identity or source"):
        buflo_study.validate_code_gate_receipt(code_gate_path, deep=False)
    with pytest.raises(ValueError, match="runtime differs"):
        class_attestation.validate_class_foundation_attestation(
            foundation,
            deep_code_gate=True,
            runtime_role="collection",
        )
    validated = class_attestation.validate_class_foundation_attestation(
        foundation,
        deep_code_gate=True,
        runtime_role="prepare",
    )
    authority = class_attestation.class_qualification_authority(
        foundation,
        deep_code_gate=True,
        runtime_role="prepare",
    )
    assert validated["source"] == collection_source
    assert authority["collection_source"] == collection_source
    assert authority["prepare_source"] == active_source["value"]

    prepare_source = dict(active_source["value"])
    active_source["value"] = {
        **prepare_source,
        "image_digest": "sha256:" + "9" * 64,
    }
    monkeypatch.setenv(
        "QCSD_LAB_IMAGE_DIGEST",
        str(active_source["value"]["image_digest"]),
    )
    rejected_runner = tmp_path / "wrong-runtime-runner"
    with pytest.raises(ValueError, match="runtime differs"):
        initialise_runner(
            rejected_runner,
            candidate_catalogue_path=catalogue_path,
            foundation_attestation=foundation,
            started_at="2027-01-01T00:00:00Z",
            browser_tool="playwright@1.52.0+/usr/bin/chromium",
        )
    assert not rejected_runner.exists()
    active_source["value"] = prepare_source
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", str(prepare_source["image_digest"]))

    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue_path,
        foundation_attestation=foundation,
        started_at="2027-01-01T00:00:00Z",
        browser_tool="playwright@1.52.0+/usr/bin/chromium",
    )
    status = run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue_path,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=RejectingBackend(),
        now=datetime(2027, 1, 1, tzinfo=UTC),
    )
    assert status["terminal_count"] == 2
    assert status["complete"] is True
    completion = write_acquisition_completion(
        runner,
        candidate_catalogue_path=catalogue_path,
    )
    assert completion.is_file()
    validate_acquisition_completion(
        load_json(completion),
        candidate_catalogue_path=catalogue_path,
        runner_root=runner,
    )

    active_source["value"] = {
        **prepare_source,
        "image_digest": "sha256:" + "9" * 64,
    }
    monkeypatch.setenv(
        "QCSD_LAB_IMAGE_DIGEST",
        str(active_source["value"]["image_digest"]),
    )
    with pytest.raises(ValueError, match="runtime differs"):
        class_attestation.class_qualification_authority(
            foundation,
            deep_code_gate=True,
            runtime_role="prepare",
        )

    active_source["value"] = prepare_source
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", str(prepare_source["image_digest"]))
    build_bytes = build_path.read_bytes()
    build_path.write_bytes(build_bytes + b" ")
    with pytest.raises(ValueError, match="build|digest|hash"):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue_path,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=NoNetworkBackend(),
            now=datetime(2027, 1, 1, tzinfo=UTC),
        )
    with pytest.raises(ValueError, match="build|digest|hash"):
        class_attestation.class_qualification_authority(
            foundation,
            deep_code_gate=True,
            runtime_role="prepare",
        )
    build_path.write_bytes(build_bytes)


@pytest.mark.parametrize("deep", (None, False, True), ids=("default", "shallow", "deep"))
def test_current_code_gate_validation_does_not_execute_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    deep: bool | None,
) -> None:
    foundation, build_path, collection_source, _active_source = _real_prepare_runtime_foundation(
        tmp_path, monkeypatch
    )
    code_gate_path = Path(load_json(foundation)["payload"]["evidence"]["code_gate"]["path"])
    before = {path: path.read_bytes() for path in (foundation, build_path, code_gate_path)}
    monkeypatch.setattr(
        buflo_study,
        "_run_lab_code_gate_commands",
        lambda: pytest.fail("code-gate validation must not execute Lab tests"),
    )

    validated = buflo_study.validate_code_gate_receipt(
        code_gate_path,
        expected_cohort_version=59,
        _expected_collection_source=collection_source,
        **({} if deep is None else {"deep": deep}),
    )

    assert validated["passed"] is True
    assert validated["source"] == collection_source
    assert validated["lab_commands"] == load_json(code_gate_path)["lab_commands"]
    assert {path: path.read_bytes() for path in before} == before


def test_current_code_gate_creation_executes_once_and_rejects_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    foundation, _build_path, collection_source, active_source = _real_prepare_runtime_foundation(
        tmp_path, monkeypatch
    )
    code_gate_path = Path(load_json(foundation)["payload"]["evidence"]["code_gate"]["path"])
    prior = load_json(code_gate_path)
    regression_roots = tuple(Path(record["root"]) for record in prior["live_regression"]["results"])
    active_source["value"] = collection_source
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", str(collection_source["image_digest"]))
    executions = []

    def run_commands():
        executions.append("executed")
        return copy.deepcopy(prior["lab_commands"])

    monkeypatch.setattr(buflo_study, "_run_lab_code_gate_commands", run_commands)
    created = buflo_study.create_code_gate_receipt(
        tmp_path / "explicit-code-gate-v59.json",
        regression_result_roots=regression_roots,
        cohort_version=59,
    )
    assert executions == ["executed"]
    for kwargs in ({}, {"deep": False}, {"deep": True}):
        assert buflo_study.validate_code_gate_receipt(created, **kwargs)["passed"] is True
    assert executions == ["executed"]

    def fail_commands():
        raise RuntimeError("explicit Lab gate failed")

    monkeypatch.setattr(buflo_study, "_run_lab_code_gate_commands", fail_commands)
    rejected_destination = tmp_path / "failed-code-gate-v59.json"
    with pytest.raises(RuntimeError, match="explicit Lab gate failed"):
        buflo_study.create_code_gate_receipt(
            rejected_destination,
            regression_result_roots=regression_roots,
            cohort_version=59,
        )
    assert not rejected_destination.exists()


@pytest.mark.parametrize("deep", (False, True), ids=("shallow", "deep"))
@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        pytest.param(
            lambda value: value["lab_commands"].pop(),
            "command inventory",
            id="inventory",
        ),
        pytest.param(
            lambda value: value["lab_commands"].reverse(),
            "command receipt",
            id="order",
        ),
        pytest.param(
            lambda value: value["lab_commands"][0].update(gate="unattested-gate"),
            "command receipt",
            id="gate",
        ),
        pytest.param(
            lambda value: value["lab_commands"][0]["argv"].append("--collect-only"),
            "command receipt",
            id="argv",
        ),
        pytest.param(
            lambda value: value["lab_commands"][0].update(cwd="/another-lab"),
            "command receipt",
            id="cwd",
        ),
        pytest.param(
            lambda value: value["lab_commands"][0].update(exit_code=1),
            "command receipt",
            id="exit-code",
        ),
        pytest.param(
            lambda value: value["lab_commands"][0].update(stdout_bytes=0),
            "command receipt",
            id="stdout-length",
        ),
        pytest.param(
            lambda value: value["lab_commands"][0].update(stdout_sha256="0" * 64),
            "command receipt",
            id="stdout-hash",
        ),
        pytest.param(
            lambda value: value["lab_commands"][0].update(
                stdout="F" + value["lab_commands"][0]["stdout"][1:]
            ),
            "command receipt",
            id="stdout-content-same-length",
        ),
        pytest.param(
            lambda value: value["source"].update(lab_commit="9" * 40),
            "identity or source",
            id="source-binding",
        ),
        pytest.param(
            lambda value: value["build_execution_receipt"].update(sha256="0" * 64),
            "selected cohort build",
            id="build-binding",
        ),
        pytest.param(
            lambda value: value["rust_code_gate"].update(receipt_sha256="0" * 64),
            "Rust build gate",
            id="rust-binding",
        ),
        pytest.param(
            lambda value: value["live_regression"].update(samples=17),
            "regression18 evidence",
            id="regression-binding",
        ),
    ),
)
def test_current_code_gate_validation_rejects_tampering_without_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    deep: bool,
    mutate,
    message: str,
) -> None:
    foundation, _build_path, collection_source, _active_source = _real_prepare_runtime_foundation(
        tmp_path, monkeypatch
    )
    code_gate_path = Path(load_json(foundation)["payload"]["evidence"]["code_gate"]["path"])
    monkeypatch.setattr(
        buflo_study,
        "_run_lab_code_gate_commands",
        lambda: pytest.fail("invalid code-gate evidence must not execute Lab tests"),
    )
    value = load_json(code_gate_path)
    mutate(value)
    code_gate_path.write_bytes(canonical_json_bytes(value))

    with pytest.raises(ValueError, match=message):
        buflo_study.validate_code_gate_receipt(
            code_gate_path,
            deep=deep,
            expected_cohort_version=59,
            _expected_collection_source=collection_source,
        )


@pytest.mark.parametrize("operation", ("run", "completion"))
def test_direct_runner_mutators_reject_generic_foundation_on_resume(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    operation: str,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "generic-foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    checkpoint_before = (runner / "checkpoint.json").read_bytes()
    backend = NoNetworkBackend()
    monkeypatch.setattr(
        acquisition_module,
        "_foundation_attestation_binding",
        _PRODUCTION_FOUNDATION_ATTESTATION_BINDING,
    )

    with pytest.raises(ValueError, match="foundation"):
        if operation == "run":
            run_due_acquisition(
                runner,
                candidate_catalogue_path=catalogue,
                stability_root=tmp_path / "stability",
                workload_root=tmp_path / "workloads",
                backend=backend,
                now=datetime(2026, 8, 28, tzinfo=UTC),
            )
        else:
            write_acquisition_completion(
                runner,
                candidate_catalogue_path=catalogue,
            )
    assert backend.calls == []
    assert (runner / "checkpoint.json").read_bytes() == checkpoint_before
    assert not (runner / "completion.json").exists()


def _catalogue_candidate_identities(catalogue: Path, count: int) -> list[tuple[str, str]]:
    return [
        (candidate["candidate_id"], candidate["domain"])
        for candidate in load_json(catalogue)["payload"]["candidates"][:count]
    ]


def test_navigation_pair_is_prepublished_and_coordinator_merged(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    now = datetime(2026, 8, 28, tzinfo=UTC)
    backend = BatchBackend(
        now,
        runner=runner,
        navigation_barrier=Barrier(MAX_CANDIDATES_PER_ACTION),
    )

    status = run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=backend,
        now=now,
    )

    expected_ids = [value[0] for value in _catalogue_candidate_identities(catalogue, 2)]
    assert backend.navigation_live_max == MAX_CANDIDATES_PER_ACTION
    assert len(backend.active_snapshots) == MAX_CANDIDATES_PER_ACTION
    for active in backend.active_snapshots:
        assert active["stage"] == "navigation"
        assert active["candidate_ids"] == expected_ids
        assert active["live_page_count"] == MAX_CANDIDATES_PER_ACTION
        assert [attempt["candidate_id"] for attempt in active["attempts"]] == (expected_ids)
        assert all(
            attempt["started_at"] == active["published_at"] for attempt in active["attempts"]
        )
        assert all(
            attempt["page_ordinal"] is None
            and attempt["probe_id"] is None
            and attempt["workload_id"] is None
            for attempt in active["attempts"]
        )
    checkpoint = load_json(runner / "checkpoint.json")["payload"]
    assert checkpoint["active_batch"] is None
    assert all(
        checkpoint["candidates"][candidate_id]["state"] == "baseline-ready"
        for candidate_id in expected_ids
    )
    assert all(
        checkpoint["candidates"][candidate_id]["navigation_attempts"]
        == [
            {
                "attempt": 1,
                "started_at": acquisition_module._format_time(now),
                "completed_at": acquisition_module._format_time(now),
                "outcome": "completed",
                "reason": None,
                "policy_evidence": None,
            }
        ]
        for candidate_id in expected_ids
    )
    assert status["pending_count"] == 120


def test_five_page_pair_uses_one_baseline_and_never_exceeds_global_cap(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    identities = _catalogue_candidate_identities(catalogue, 2)
    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    backend = BatchBackend(
        baseline + timedelta(seconds=25),
        page_counts={identities[0][1]: 2, identities[1][1]: 3},
        runner=runner,
        navigation_barrier=Barrier(2),
        prepare_barrier=Barrier(GLOBAL_LIVE_PAGE_CAP),
    )
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "now": baseline,
    }
    run_due_acquisition(runner, **arguments)
    backend.active_snapshots.clear()
    run_due_acquisition(runner, **arguments)

    expected_ids = [candidate_id for candidate_id, _domain in identities]
    payload = load_json(runner / "checkpoint.json")["payload"]
    assert payload["active_batch"] is None
    assert payload["baseline_batches"] == [
        {
            "batch_id": payload["baseline_batches"][0]["batch_id"],
            "baseline_started_at": acquisition_module._format_time(baseline),
            "candidate_ids": expected_ids,
            "live_page_count": GLOBAL_LIVE_PAGE_CAP,
        }
    ]
    assert backend.prepare_live_max == GLOBAL_LIVE_PAGE_CAP
    probe_snapshots = [active for active in backend.active_snapshots if active["stage"] == "probe"]
    assert len(probe_snapshots) == GLOBAL_LIVE_PAGE_CAP
    assert all(
        active["candidate_ids"] == expected_ids
        and active["live_page_count"] == GLOBAL_LIVE_PAGE_CAP
        and len(active["attempts"]) == GLOBAL_LIVE_PAGE_CAP
        for active in probe_snapshots
    )
    assert (
        sum(len(payload["candidates"][candidate_id]["pages"]) for candidate_id in expected_ids)
        == GLOBAL_LIVE_PAGE_CAP
    )
    assert all(
        len(page["observations"]) == 1
        for candidate_id in expected_ids
        for page in payload["candidates"][candidate_id]["pages"]
    )

    original = copy.deepcopy(payload)
    mutations = []

    def wrong_live_page_count(changed: dict) -> None:
        batch = changed["baseline_batches"][0]
        batch["live_page_count"] -= 1
        body = {key: value for key, value in batch.items() if key != "batch_id"}
        batch["batch_id"] = acquisition_module._batch_identifier("baseline", body)

    mutations.append(wrong_live_page_count)

    def malformed_candidate_id(changed: dict) -> None:
        batch = changed["baseline_batches"][0]
        batch["candidate_ids"][0] = {}
        body = {key: value for key, value in batch.items() if key != "batch_id"}
        batch["batch_id"] = acquisition_module._batch_identifier("baseline", body)

    mutations.append(malformed_candidate_id)
    mutations.append(lambda changed: changed["baseline_batches"].clear())
    for mutate in mutations:
        changed = copy.deepcopy(original)
        mutate(changed)
        _replace_receipt_payload(runner / "checkpoint.json", changed)
        with pytest.raises(ValueError):
            acquisition_status(runner, candidate_catalogue_path=catalogue, now=baseline)
    _replace_receipt_payload(runner / "checkpoint.json", original)


def test_schema4_live_probing_state_rejects_rebound_structure_and_observations(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    [(candidate_id, domain)] = _catalogue_candidate_identities(catalogue, 1)
    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    backend = BatchBackend(
        baseline + timedelta(seconds=25),
        page_counts={domain: 2},
        runner=runner,
    )
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "now": baseline,
        "max_candidates": 1,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    original = copy.deepcopy(load_json(runner / "checkpoint.json")["payload"])
    assert original["candidates"][candidate_id]["state"] == "probing"

    def swapped_url(changed: dict) -> None:
        changed["candidates"][candidate_id]["pages"][0]["page"]["url"] = "https://outside.example/"

    def reversed_pages(changed: dict) -> None:
        changed["candidates"][candidate_id]["pages"].reverse()

    def duplicate_page(changed: dict) -> None:
        pages = changed["candidates"][candidate_id]["pages"]
        pages[1] = copy.deepcopy(pages[0])

    def malformed_observation(changed: dict) -> None:
        changed["candidates"][candidate_id]["pages"][0]["observations"][0].pop("status")

    def rebound_extra_field(changed: dict) -> None:
        changed["candidates"][candidate_id]["uncontracted"] = True

    def rebound_prepared_attempt_identity(changed: dict) -> None:
        observation = changed["candidates"][candidate_id]["pages"][0]["observations"][0]
        observation["prepared_path"] = str(
            Path(observation["prepared_path"]).with_name("other.json")
        )

    def divergent_observation_start(changed: dict) -> None:
        observation = changed["candidates"][candidate_id]["pages"][0]["observations"][0]
        observed = datetime.fromisoformat(observation["observed_at"].replace("Z", "+00:00"))
        observation["observed_at"] = acquisition_module._format_time(
            observed + timedelta(milliseconds=1)
        )

    def completion_outside_attempt(changed: dict) -> None:
        page = changed["candidates"][candidate_id]["pages"][0]
        completed = datetime.fromisoformat(
            page["probe_attempts"][0]["completed_at"].replace("Z", "+00:00")
        )
        page["observations"][0]["probe_completed_at"] = acquisition_module._format_time(
            completed + timedelta(milliseconds=1)
        )

    def boolean_navigation_attempt(changed: dict) -> None:
        changed["candidates"][candidate_id]["navigation_attempts"][0]["attempt"] = True

    def noncanonical_probe_timestamp(changed: dict) -> None:
        attempt = changed["candidates"][candidate_id]["pages"][0]["probe_attempts"][0]
        instant = datetime.fromisoformat(attempt["observed_at"].replace("Z", "+00:00"))
        attempt["observed_at"] = instant.astimezone(timezone(timedelta(hours=10))).isoformat()

    def noncanonical_navigation_timestamp(changed: dict) -> None:
        attempt = changed["candidates"][candidate_id]["navigation_attempts"][0]
        instant = datetime.fromisoformat(attempt["completed_at"].replace("Z", "+00:00"))
        attempt["completed_at"] = instant.astimezone(timezone(timedelta(hours=10))).isoformat()

    for mutate in (
        swapped_url,
        reversed_pages,
        duplicate_page,
        malformed_observation,
        rebound_extra_field,
        rebound_prepared_attempt_identity,
        divergent_observation_start,
        completion_outside_attempt,
        boolean_navigation_attempt,
        noncanonical_probe_timestamp,
        noncanonical_navigation_timestamp,
    ):
        changed = copy.deepcopy(original)
        mutate(changed)
        _replace_receipt_payload(runner / "checkpoint.json", changed)
        with pytest.raises(ValueError):
            acquisition_status(runner, candidate_catalogue_path=catalogue, now=baseline)
    _replace_receipt_payload(runner / "checkpoint.json", original)


def test_schema4_pending_state_rejects_rebound_extra_fields(tmp_path: Path) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    payload = load_json(runner / "checkpoint.json")["payload"]
    first_state = next(iter(payload["candidates"].values()))
    first_state["uncontracted"] = True
    _replace_receipt_payload(runner / "checkpoint.json", payload)
    with pytest.raises(ValueError, match="pending checkpoint fields"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_active_probe_pair_recovers_every_attempt_transactionally(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    identities = _catalogue_candidate_identities(catalogue, 2)
    candidate_ids = [candidate_id for candidate_id, _domain in identities]
    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    backend = BatchBackend(
        baseline + timedelta(seconds=25),
        runner=runner,
        navigation_barrier=Barrier(2),
        prepare_barrier=Barrier(2),
        interrupt_prefix=candidate_ids[0],
    )
    common = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": backend,
    }
    run_due_acquisition(runner, now=baseline, **common)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(runner, now=baseline, **common)

    original = copy.deepcopy(load_json(runner / "checkpoint.json")["payload"])
    active = original["active_batch"]
    assert active["stage"] == "probe"
    assert active["candidate_ids"] == candidate_ids
    assert active["live_page_count"] == 2
    assert all(
        original["candidates"][attempt["candidate_id"]]["pages"][0]["pending_probe"]["workload_id"]
        == attempt["workload_id"]
        for attempt in active["attempts"]
    )
    status = acquisition_status(
        runner,
        candidate_catalogue_path=catalogue,
        now=baseline + timedelta(seconds=26),
    )
    assert status["recovery_required_count"] == 2
    assert status["active_batch"] == {
        "batch_id": active["batch_id"],
        "stage": "probe",
        "published_at": active["published_at"],
        "candidate_ids": candidate_ids,
        "live_page_count": 2,
        "attempt_count": 2,
    }

    duplicate = copy.deepcopy(original)
    duplicate_active = duplicate["active_batch"]
    duplicate_active["attempts"][1] = copy.deepcopy(duplicate_active["attempts"][0])
    active_body = {key: value for key, value in duplicate_active.items() if key != "batch_id"}
    duplicate_active["batch_id"] = acquisition_module._batch_identifier("active", active_body)
    _replace_receipt_payload(runner / "checkpoint.json", duplicate)
    with pytest.raises(ValueError):
        acquisition_status(runner, candidate_catalogue_path=catalogue)

    null_pending = copy.deepcopy(original)
    first_attempt = null_pending["active_batch"]["attempts"][0]
    first_state = null_pending["candidates"][first_attempt["candidate_id"]]
    next(
        page
        for page in first_state["pages"]
        if page["page"]["ordinal"] == first_attempt["page_ordinal"]
    )["pending_probe"] = None
    _replace_receipt_payload(runner / "checkpoint.json", null_pending)
    with pytest.raises(ValueError, match="pending probe is null"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)

    _replace_receipt_payload(runner / "checkpoint.json", original)
    recovery_time = baseline + timedelta(seconds=27)
    backend.observed_at = recovery_time
    checkpoint_before = (runner / "checkpoint.json").read_bytes()
    with pytest.raises(ValueError, match="recovery exceeds the candidate action bound"):
        run_due_acquisition(runner, now=recovery_time, max_candidates=1, **common)
    assert (runner / "checkpoint.json").read_bytes() == checkpoint_before
    resumed = run_due_acquisition(runner, now=recovery_time, **common)
    assert resumed["recovery_required_count"] == 0
    assert resumed["active_batch"] is None
    recovered = load_json(runner / "checkpoint.json")["payload"]
    for candidate_id in candidate_ids:
        page = recovered["candidates"][candidate_id]["pages"][0]
        assert [attempt["attempt"] for attempt in page["probe_attempts"]] == [1]
        assert page["probe_attempts"][0]["outcome"] == "interrupted"
        assert page["observations"] == []
    resumed = run_due_acquisition(runner, now=recovery_time, **common)
    assert resumed["recovery_required_count"] == 0
    recovered = load_json(runner / "checkpoint.json")["payload"]
    for candidate_id in candidate_ids:
        page = recovered["candidates"][candidate_id]["pages"][0]
        assert [attempt["attempt"] for attempt in page["probe_attempts"]] == [1, 2]
        assert [attempt["outcome"] for attempt in page["probe_attempts"]] == [
            "interrupted",
            "completed",
        ]
        assert page["probe_attempts"][0]["completed_at"] == (
            acquisition_module._format_time(recovery_time)
        )
        assert page["observations"][0]["observed_at"] == (
            acquisition_module._format_time(recovery_time)
        )
    assert all(workload_id.endswith(("-a001", "-a002")) for workload_id in backend.workload_ids)


def test_active_recovery_is_the_only_action_when_an_unrelated_pair_is_due(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    identities = _catalogue_candidate_identities(catalogue, 4)
    candidate_ids = [candidate_id for candidate_id, _domain in identities]
    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    setup_backend = BatchBackend(baseline + timedelta(seconds=25), runner=runner)
    common = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": setup_backend,
        "now": baseline,
    }
    run_due_acquisition(runner, **common)
    run_due_acquisition(runner, **common)
    payload = load_json(runner / "checkpoint.json")["payload"]
    due_ids = candidate_ids[:2]
    active_ids = candidate_ids[2:]
    due_before = {
        candidate_id: copy.deepcopy(payload["candidates"][candidate_id]) for candidate_id in due_ids
    }
    due_at = baseline + timedelta(
        milliseconds=acquisition_module.STABILITY_PROBE_WINDOWS[1].target_ms
    )
    started_at = acquisition_module._format_time(due_at)
    attempts = []
    for candidate_id in active_ids:
        state = payload["candidates"][candidate_id]
        state["navigation_attempts"] = []
        state["pending_navigation"] = {"attempt": 1, "started_at": started_at}
        attempts.append(
            {
                "candidate_id": candidate_id,
                "page_ordinal": None,
                "probe_id": None,
                "workload_id": None,
                "attempt": 1,
                "started_at": started_at,
            }
        )
    payload["active_batch"] = acquisition_module._new_active_batch(
        "navigation",
        published_at=due_at,
        attempts=attempts,
    )
    _replace_receipt_payload(runner / "checkpoint.json", payload)

    backend = NoNetworkBackend()
    status = run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=backend,
        now=due_at,
    )
    recovered = load_json(runner / "checkpoint.json")["payload"]
    assert backend.calls == []
    assert recovered["active_batch"] is None
    assert {
        candidate_id: recovered["candidates"][candidate_id] for candidate_id in due_ids
    } == due_before
    for candidate_id in active_ids:
        state = recovered["candidates"][candidate_id]
        assert "pending_navigation" not in state
        assert [attempt["outcome"] for attempt in state["navigation_attempts"]] == ["interrupted"]
    assert status["due_now_count"] == 2
    assert status["work_due_now"] is True


def _complete_one_probing_candidate(
    runner: Path,
    *,
    catalogue: Path,
    stability: Path,
    workloads: Path,
    backend: SlowBackend,
    clock: FakeClock,
) -> tuple[str, dict]:
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": workloads,
        "backend": backend,
        "clock": clock,
        "max_candidates": 1,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    candidate_id, state = next(
        (candidate_id, state)
        for candidate_id, state in checkpoint["payload"]["candidates"].items()
        if state["state"] == "probing"
    )
    baseline = datetime.fromisoformat(state["baseline_started_at"].replace("Z", "+00:00"))
    for window in acquisition_module.STABILITY_PROBE_WINDOWS[1:]:
        clock.value = baseline + timedelta(milliseconds=window.target_ms)
        run_due_acquisition(runner, **arguments)
    final = load_json(runner / "checkpoint.json")
    return candidate_id, final["payload"]["candidates"][candidate_id]


def _leave_one_finalisable_candidate(
    runner: Path,
    *,
    catalogue: Path,
    stability: Path,
    workloads: Path,
    backend: SlowBackend,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[str, dict]:
    """Simulate a kill after final probe merge and before publication."""

    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": workloads,
        "backend": backend,
        "clock": clock,
        "max_candidates": 1,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    candidate_id, state = next(
        (candidate_id, state)
        for candidate_id, state in checkpoint["payload"]["candidates"].items()
        if state["state"] == "probing"
    )
    baseline = datetime.fromisoformat(state["baseline_started_at"].replace("Z", "+00:00"))
    window = acquisition_module.STABILITY_PROBE_WINDOWS[1]
    clock.value = baseline + timedelta(milliseconds=window.target_ms)
    run_due_acquisition(runner, **arguments)

    original = acquisition_module._terminalise_completed_probe_candidate
    monkeypatch.setattr(
        acquisition_module,
        "_terminalise_completed_probe_candidate",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt),
    )
    window = acquisition_module.STABILITY_PROBE_WINDOWS[2]
    clock.value = baseline + timedelta(milliseconds=window.target_ms)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(runner, **arguments)
    monkeypatch.setattr(
        acquisition_module,
        "_terminalise_completed_probe_candidate",
        original,
    )
    payload = load_json(runner / "checkpoint.json")["payload"]
    state = payload["candidates"][candidate_id]
    assert acquisition_module._probe_candidate_is_finalisable(state)
    return candidate_id, state


def test_finalisable_probe_resume_is_local_crash_safe_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    workloads = tmp_path / "workloads"
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    candidate_id, finalisable_state = _leave_one_finalisable_candidate(
        runner,
        catalogue=catalogue,
        stability=stability,
        workloads=workloads,
        backend=SlowBackend(clock),
        clock=clock,
        monkeypatch=monkeypatch,
    )
    terminal_time = acquisition_module._finalisable_probe_terminal_time(finalisable_state)
    status = acquisition_status(
        runner,
        candidate_catalogue_path=catalogue,
        now=clock.value,
    )
    assert status["finalisable_count"] == 1
    assert status["due_now_count"] == 0
    assert status["work_due_now"] is True

    candidate_stability = stability / candidate_id
    candidate_stability.mkdir()
    prelink_temp = candidate_stability / ".page-00.json.prelink.qcsd-tmp"
    prelink_temp.write_bytes(b"partial stability receipt")
    original_terminalise = acquisition_module._terminalise
    monkeypatch.setattr(
        acquisition_module,
        "_terminalise",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt),
    )
    backend = NoNetworkBackend()
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": workloads,
        "backend": backend,
        "clock": clock,
        "max_candidates": 1,
    }
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(runner, **arguments)
    receipt = candidate_stability / "page-00.json"
    admitted = workloads / f"{candidate_id}.json"
    assert not prelink_temp.exists()
    assert receipt.is_file()
    assert admitted.is_file()
    assert not (runner / "terminals" / f"{candidate_id}.json").exists()
    assert backend.calls == []

    receipt_bytes = receipt.read_bytes()
    admitted_bytes = admitted.read_bytes()
    postlink_temp = candidate_stability / ".page-00.json.postlink.qcsd-tmp"
    acquisition_module.os.link(receipt, postlink_temp)
    monkeypatch.setattr(acquisition_module, "_terminalise", original_terminalise)
    completed = run_due_acquisition(runner, **arguments)
    assert completed["finalisable_count"] == 0
    assert backend.calls == []
    assert not postlink_temp.exists()
    assert receipt.read_bytes() == receipt_bytes
    assert admitted.read_bytes() == admitted_bytes

    checkpoint = load_json(runner / "checkpoint.json")["payload"]
    state = checkpoint["candidates"][candidate_id]
    terminal_path = runner / state["terminal"]["path"]
    terminal_bytes = terminal_path.read_bytes()
    terminal_payload = load_json(terminal_path)["payload"]
    assert terminal_payload["terminalised_at"] == acquisition_module._format_time(terminal_time)
    assert terminal_payload["baseline_batch"] == checkpoint["baseline_batches"][0]

    _catalogue_receipt, candidates = acquisition_module.load_candidate_catalogue_receipt(catalogue)
    [candidate] = [value for value in candidates if value.candidate_id == candidate_id]
    second_postlink_temp = candidate_stability / ".page-00.json.second.qcsd-tmp"
    acquisition_module.os.link(receipt, second_postlink_temp)
    acquisition_module._terminalise_completed_probe_candidate(
        candidate,
        state,
        runner=runner,
        provenance_path=runner / "provenance.json",
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=workloads,
        terminalised_at=terminal_time,
        baseline_batch=checkpoint["baseline_batches"][0],
    )
    assert not second_postlink_temp.exists()
    assert receipt.read_bytes() == receipt_bytes
    assert admitted.read_bytes() == admitted_bytes
    assert terminal_path.read_bytes() == terminal_bytes


def test_due_at_latest_edge_outranks_unrelated_finalisable_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    candidate_ids = [value[0] for value in _catalogue_candidate_identities(catalogue, 2)]
    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    clock = FakeClock(baseline)
    (tmp_path / "stability").mkdir()

    class MixedFinalBackend(BatchBackend):
        def __init__(self) -> None:
            super().__init__(baseline + timedelta(seconds=25), runner=runner)
            self.mode = "normal"
            self.events: list[str] = []

        def prepare(
            self,
            workload_id,
            url,
            approved_origins,
            output_root,
            *,
            origin_ip_pins=None,
        ):
            self.events.append(f"prepare:{workload_id.split('-p')[0]}")
            if self.mode == "split" and "-t72h-" in workload_id:
                if workload_id.startswith(candidate_ids[0]):
                    raise TerminalProbePolicyError("deterministic final-page rejection")
                raise RecoverableAcquisitionError("retry remains due")
            return super().prepare(
                workload_id,
                url,
                approved_origins,
                output_root,
                origin_ip_pins=origin_ip_pins,
            )

    backend = MixedFinalBackend()
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")["payload"]
    shared_baseline = datetime.fromisoformat(
        checkpoint["baseline_batches"][0]["baseline_started_at"].replace("Z", "+00:00")
    )
    window = acquisition_module.STABILITY_PROBE_WINDOWS[1]
    clock.value = shared_baseline + timedelta(milliseconds=window.target_ms)
    backend.observed_at = clock.value
    run_due_acquisition(runner, **arguments)

    original_save = acquisition_module._save_acquisition_checkpoint
    crashed = False

    def crash_after_mixed_merge(*args, **kwargs):
        nonlocal crashed
        original_save(*args, **kwargs)
        payload = load_json(runner / "checkpoint.json")["payload"]
        first = payload["candidates"][candidate_ids[0]]
        second = payload["candidates"][candidate_ids[1]]
        if (
            not crashed
            and payload["active_batch"] is None
            and first["pages"][0].get("rejection") is not None
            and second["pages"][0]["probe_attempts"][-1]["outcome"] == "recoverable-failure"
        ):
            crashed = True
            raise KeyboardInterrupt

    monkeypatch.setattr(acquisition_module, "_save_acquisition_checkpoint", crash_after_mixed_merge)
    window = acquisition_module.STABILITY_PROBE_WINDOWS[2]
    clock.value = shared_baseline + timedelta(milliseconds=window.latest_ms)
    backend.observed_at = clock.value
    backend.mode = "split"
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(runner, **arguments)
    monkeypatch.setattr(acquisition_module, "_save_acquisition_checkpoint", original_save)

    status = acquisition_status(runner, candidate_catalogue_path=catalogue, now=clock.value)
    assert status["due_now_count"] == 1
    assert status["finalisable_count"] == 1
    backend.mode = "normal"
    backend.events.clear()
    original_finaliser = acquisition_module._terminalise_completed_probe_candidate

    def clock_advancing_finaliser(candidate, *args, **kwargs):
        backend.events.append(f"finalise:{candidate.candidate_id}")
        if candidate.candidate_id == candidate_ids[0]:
            clock.value += timedelta(milliseconds=1)
        return original_finaliser(candidate, *args, **kwargs)

    monkeypatch.setattr(
        acquisition_module,
        "_terminalise_completed_probe_candidate",
        clock_advancing_finaliser,
    )
    run_due_acquisition(runner, **arguments)
    assert backend.events == [
        f"prepare:{candidate_ids[1]}",
        f"finalise:{candidate_ids[1]}",
    ]
    checkpoint = load_json(runner / "checkpoint.json")["payload"]
    assert checkpoint["candidates"][candidate_ids[0]]["terminal"] is None
    assert checkpoint["candidates"][candidate_ids[1]]["terminal"] is not None
    assert (
        checkpoint["candidates"][candidate_ids[0]]["pages"][0]["probe_attempts"][-1]["outcome"]
        == "terminal-policy-rejection"
    )
    assert [
        attempt["outcome"]
        for attempt in checkpoint["candidates"][candidate_ids[1]]["pages"][0]["probe_attempts"][-2:]
    ] == ["recoverable-failure", "completed"]

    network_calls = list(backend.events)
    run_due_acquisition(runner, **arguments)
    assert backend.events == [*network_calls, f"finalise:{candidate_ids[0]}"]
    checkpoint = load_json(runner / "checkpoint.json")["payload"]
    assert all(checkpoint["candidates"][candidate_id]["terminal"] for candidate_id in candidate_ids)
    for candidate_id in candidate_ids:
        terminal = load_json(runner / checkpoint["candidates"][candidate_id]["terminal"]["path"])
        assert terminal["payload"]["baseline_batch"] == checkpoint["baseline_batches"][0]
        assert all(
            attempt["outcome"] != "interrupted"
            for attempt in checkpoint["candidates"][candidate_id]["pages"][0]["probe_attempts"]
        )


def test_finalisable_publication_replays_prepared_evidence_before_any_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    workloads = tmp_path / "workloads"
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    candidate_id, state = _leave_one_finalisable_candidate(
        runner,
        catalogue=catalogue,
        stability=stability,
        workloads=workloads,
        backend=SlowBackend(clock),
        clock=clock,
        monkeypatch=monkeypatch,
    )
    prepared = Path(state["pages"][0]["observations"][0]["prepared_path"])
    prepared.write_bytes(b"forged prepared evidence")
    checkpoint_before = (runner / "checkpoint.json").read_bytes()
    with pytest.raises(ValueError):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=stability,
            workload_root=workloads,
            backend=NoNetworkBackend(),
            clock=clock,
            max_candidates=1,
        )
    assert not (stability / candidate_id).exists()
    assert not (workloads / f"{candidate_id}.json").exists()
    assert not (runner / "terminals" / f"{candidate_id}.json").exists()
    assert (runner / "checkpoint.json").read_bytes() == checkpoint_before


def test_missed_terminal_replays_response_evidence_before_publication(tmp_path: Path) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    backend = BatchBackend(baseline + timedelta(seconds=25), runner=runner)
    common = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "max_candidates": 1,
    }
    run_due_acquisition(runner, now=baseline, **common)
    run_due_acquisition(runner, now=baseline, **common)
    payload = load_json(runner / "checkpoint.json")["payload"]
    [baseline_batch] = payload["baseline_batches"]
    [candidate_id] = baseline_batch["candidate_ids"]
    state = payload["candidates"][candidate_id]
    observation = state["pages"][0]["observations"][0]
    response_receipt = runner / observation["document_response_receipt_path"]
    response_receipt.write_bytes(b"forged response evidence")
    checkpoint_before = (runner / "checkpoint.json").read_bytes()
    missed_at = datetime.fromisoformat(
        state["baseline_started_at"].replace("Z", "+00:00")
    ) + timedelta(milliseconds=acquisition_module.STABILITY_PROBE_WINDOWS[1].latest_ms + 1)
    assert (
        acquisition_status(
            runner,
            candidate_catalogue_path=catalogue,
            now=missed_at,
        )["missed_window_count"]
        == 1
    )
    with pytest.raises(ValueError):
        run_due_acquisition(runner, now=missed_at, **common)
    assert not (stability / candidate_id).exists()
    assert not (runner / "terminals" / f"{candidate_id}.json").exists()
    assert (runner / "checkpoint.json").read_bytes() == checkpoint_before


def test_due_batch_rechecks_actual_publication_clock_before_launch(tmp_path: Path) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    setup = BatchBackend(baseline + timedelta(seconds=25), runner=runner)
    common = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "max_candidates": 1,
    }
    run_due_acquisition(runner, backend=setup, now=baseline, **common)
    run_due_acquisition(runner, backend=setup, now=baseline, **common)
    payload = load_json(runner / "checkpoint.json")["payload"]
    [candidate_id] = payload["baseline_batches"][0]["candidate_ids"]
    state = payload["candidates"][candidate_id]
    armed = datetime.fromisoformat(state["baseline_started_at"].replace("Z", "+00:00"))
    window = acquisition_module.STABILITY_PROBE_WINDOWS[1]
    latest = armed + timedelta(milliseconds=window.latest_ms)
    after = latest + timedelta(milliseconds=1)

    class CrossingClock:
        def __init__(self) -> None:
            self.values = iter((latest, latest, after, after, after, after))
            self.last = after

        def __call__(self) -> datetime:
            self.last = next(self.values, self.last)
            return self.last

    backend = NoNetworkBackend()
    status = run_due_acquisition(
        runner,
        backend=backend,
        clock=CrossingClock(),
        **common,
    )
    assert backend.calls == []
    assert status["terminal_count"] == 1
    terminal_state = load_json(runner / "checkpoint.json")["payload"]["candidates"][candidate_id]
    terminal = load_json(runner / terminal_state["terminal"]["path"])["payload"]
    assert terminal["kind"] == "probe-window-missed"
    assert len(terminal_state["pages"][0]["probe_attempts"]) == 1


def test_baseline_arm_reclassifies_when_clock_crosses_a_schedule_boundary(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    identities = _catalogue_candidate_identities(catalogue, 2)
    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    setup = BatchBackend(
        baseline + timedelta(seconds=25),
        page_counts={domain: 4 for _candidate_id, domain in identities},
        runner=runner,
    )
    common = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
    }
    run_due_acquisition(runner, backend=setup, now=baseline, **common)
    run_due_acquisition(runner, backend=setup, now=baseline, **common)
    before = load_json(runner / "checkpoint.json")["payload"]
    [existing_batch] = before["baseline_batches"]
    existing = datetime.fromisoformat(existing_batch["baseline_started_at"].replace("Z", "+00:00"))
    low_boundary = existing + timedelta(
        milliseconds=(
            acquisition_module.STABILITY_PROBE_WINDOWS[1].earliest_ms - PENDING_BASELINE_GUARD_MS
        )
    )
    inside = low_boundary + timedelta(milliseconds=1)
    assert acquisition_module.baseline_is_safe(low_boundary, (existing,))
    assert not acquisition_module.baseline_is_safe(inside, (existing,))

    class CrossingClock:
        def __init__(self) -> None:
            self.values = iter((low_boundary, low_boundary, inside, inside, inside))
            self.last = inside

        def __call__(self) -> datetime:
            self.last = next(self.values, self.last)
            return self.last

    backend = NoNetworkBackend()
    status = run_due_acquisition(
        runner,
        backend=backend,
        clock=CrossingClock(),
        **common,
    )
    after = load_json(runner / "checkpoint.json")["payload"]
    assert backend.calls == []
    assert after["baseline_batches"] == before["baseline_batches"]
    assert after["active_batch"] is None
    assert sum(state["state"] == "baseline-ready" for state in after["candidates"].values()) == 1
    assert status["pending_start_blocked"] is True
    assert status["work_due_now"] is False


class InterruptOnceBackend(SlowBackend):
    def __init__(self, clock):
        super().__init__(clock)
        self.interrupted = False
        self.workload_ids = []

    def prepare(self, workload_id, url, approved_origins, output_root, *, origin_ip_pins=None):
        self.workload_ids.append(workload_id)
        if not self.interrupted:
            self.interrupted = True
            raise KeyboardInterrupt
        return super().prepare(
            workload_id,
            url,
            approved_origins,
            output_root,
            origin_ip_pins=origin_ip_pins,
        )


class InterruptAfterManifestBackend(SlowBackend):
    def __init__(self, clock):
        super().__init__(clock)
        self.interrupted = False
        self.workload_ids = []

    def prepare(self, workload_id, url, approved_origins, output_root, *, origin_ip_pins=None):
        self.workload_ids.append(workload_id)
        if not self.interrupted:
            self.interrupted = True
            output_root.mkdir(parents=True, exist_ok=True)
            (output_root / f"{workload_id}.json").write_bytes(b"orphaned first-attempt manifest")
            raise KeyboardInterrupt
        return super().prepare(
            workload_id,
            url,
            approved_origins,
            output_root,
            origin_ip_pins=origin_ip_pins,
        )


class TransientNavigationBackend(SlowBackend):
    def __init__(self, clock):
        super().__init__(clock)
        self.navigation_calls = 0

    def discover_navigation(self, domain: str):
        self.navigation_calls += 1
        if self.navigation_calls == 1:
            raise RecoverableAcquisitionError("temporary DNS failure")
        return super().discover_navigation(domain)


class FinalDiscoveryDriftOnceBackend(SlowBackend):
    def __init__(self, clock):
        super().__init__(clock)
        self.workload_ids = []
        self.discovery_calls = []

    def discover(self, url, approved_origins):
        self.discovery_calls.append((url, tuple(approved_origins)))
        result = super().discover(url, approved_origins)
        if len(self.discovery_calls) == 2:
            late_origin = "https://late-origin.example"
            result.observed_origins = sorted([*approved_origins, late_origin])
            result.expandable_origins = sorted([*approved_origins, late_origin])
            result.exclusions = [
                {
                    "url": f"{late_origin}/asset.js",
                    "reason": "origin not approved",
                }
            ]
        return result

    def prepare(self, workload_id, url, approved_origins, output_root, *, origin_ip_pins=None):
        self.workload_ids.append(workload_id)
        if len(self.workload_ids) == 1:
            raise RecoverablePreparationError(
                "complete coverage final browser discovery observed new HTTPS GET origins "
                "after convergence: https://late-origin.example"
            )
        return super().prepare(
            workload_id,
            url,
            approved_origins,
            output_root,
            origin_ip_pins=origin_ip_pins,
        )


def test_preparation_error_taxonomy_retries_only_explicit_transient_failures():
    assert issubclass(RecoverablePreparationError, PreparationError)
    assert issubclass(RecoverablePreparationError, RecoverableAcquisitionError)
    assert not issubclass(PreparationError, RecoverableAcquisitionError)


def test_all_rejected_candidates_fail_quota_and_completion_publication_detects_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    (tmp_path / "stability").mkdir()

    class ProbePolicyBatchBackend(BatchBackend):
        def discover(self, url, approved_origins):
            raise TerminalProbePolicyError(f"probe policy rejected {url}")

    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    post_baseline_backend = ProbePolicyBatchBackend(
        baseline + timedelta(seconds=25),
        runner=runner,
        navigation_barrier=Barrier(2),
    )
    common = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
    }
    run_due_acquisition(runner, backend=post_baseline_backend, now=baseline, **common)
    run_due_acquisition(runner, backend=post_baseline_backend, now=baseline, **common)
    for _batch in range((CANDIDATE_COUNT - 2) // 2):
        status = run_due_acquisition(
            runner,
            backend=RejectingBackend(),
            max_candidates=MAX_CANDIDATES_PER_ACTION,
            **common,
        )
    assert status["selection"]["quota_unmet_strata"] == [
        stratum.id for stratum in TRANCO_RANK_STRATA
    ]
    assert {
        key: value
        for key, value in status.items()
        if key not in {"selection", "selection_blocked_candidate_ids"}
    } == {
        "candidate_count": CANDIDATE_COUNT,
        "acquisition_schema_version": acquisition_module.SCHEMA_VERSION,
        "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
        "maximum_candidates_per_action": 2,
        "global_live_page_cap": 5,
        "active_batch": None,
        "terminal_count": CANDIDATE_COUNT,
        "pending_count": 0,
        "probing_count": 0,
        "due_now_count": 0,
        "finalisable_count": 0,
        "missed_window_count": 0,
        "recovery_required_count": 0,
        "pending_start_blocked": False,
        "work_due_now": False,
        "complete": False,
        "next_due": None,
    }
    with pytest.raises(ValueError, match="resolved deterministic prefix"):
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)
    # Below, isolate immutable publication/ledger-tamper mechanics from the
    # scientifically impossible all-rejected quota.  The real quota rejection
    # is asserted above; separate full-catalogue tests cover accepted prefixes.
    original_selection = acquisition_module._derive_checkpoint_selection

    def publication_fixture_selection(*args):
        selection, blocked = original_selection(*args)
        return {**selection, "complete": True}, blocked

    monkeypatch.setattr(
        acquisition_module, "_derive_checkpoint_selection", publication_fixture_selection
    )
    original_create = acquisition_module.durable_create
    completion_path = runner / "completion.json"
    prelink = runner / (f".{completion_path.name}{acquisition_module.ATOMIC_TEMP_MARKER}prelink")

    def interrupted_completion_create(path: Path, value: bytes) -> None:
        if path == completion_path:
            prelink.write_bytes(value[:16])
            raise KeyboardInterrupt
        original_create(path, value)

    monkeypatch.setattr(
        acquisition_module,
        "durable_create",
        interrupted_completion_create,
    )
    with pytest.raises(KeyboardInterrupt):
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)
    assert prelink.is_file()
    assert not completion_path.exists()
    monkeypatch.setattr(acquisition_module, "durable_create", original_create)
    completion_path = write_acquisition_completion(runner, candidate_catalogue_path=catalogue)
    assert not prelink.exists()
    completion = load_json(completion_path)
    assert completion["receipt_type"] == COMPLETION_TYPE
    assert completion["payload"]["completion_schema_version"] == (COMPLETION_SCHEMA_VERSION)
    assert completion["payload"]["checkpoint_schema_version"] == (CHECKPOINT_SCHEMA_VERSION)
    assert len(completion["payload"]["baseline_batches"]) == 1
    assert completion["payload"]["baseline_batches_sha256"] == evidence_sha256(
        completion["payload"]["baseline_batches"]
    )
    candidate_id = completion["payload"]["baseline_batches"][0]["candidate_ids"][0]
    candidate_state = load_json(runner / "checkpoint.json")["payload"]["candidates"][candidate_id]
    terminal = load_json(runner / candidate_state["terminal"]["path"])["payload"]
    assert terminal["candidate_id"] == candidate_id
    assert terminal["terminal_schema_version"] == TERMINAL_SCHEMA_VERSION
    assert terminal["checkpoint_schema_version"] == CHECKPOINT_SCHEMA_VERSION
    assert terminal["baseline_batch"] == completion["payload"]["baseline_batches"][0]
    validate_acquisition_completion(
        completion, candidate_catalogue_path=catalogue, runner_root=runner
    )
    completion_bytes = completion_path.read_bytes()
    postlink = runner / (f".{completion_path.name}{acquisition_module.ATOMIC_TEMP_MARKER}postlink")
    acquisition_module.os.link(completion_path, postlink)
    assert (
        write_acquisition_completion(
            runner,
            candidate_catalogue_path=catalogue,
        )
        == completion_path
    )
    assert not postlink.exists()
    assert completion_path.read_bytes() == completion_bytes
    completion_path.write_bytes(b"different completion")
    with pytest.raises(FileExistsError, match="completion already differs"):
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)
    completion_path.write_bytes(completion_bytes)
    completion_path.unlink()
    completion_path.symlink_to(runner / "checkpoint.json")
    with pytest.raises(FileExistsError, match="completion already differs"):
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)
    completion_path.unlink()
    completion_path.mkdir()
    with pytest.raises(FileExistsError, match="completion already differs"):
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)
    completion_path.rmdir()
    completion_path.write_bytes(completion_bytes)

    changed = copy.deepcopy(completion)
    changed["payload"]["terminal_receipts"].pop(next(iter(changed["payload"]["terminal_receipts"])))
    with pytest.raises(ValueError):
        validate_acquisition_completion(
            changed, candidate_catalogue_path=catalogue, runner_root=runner
        )

    wrong_study = bind_receipt(
        {**completion["payload"], "study_id": "wrong-study"},
        receipt_type=COMPLETION_TYPE,
    )
    with pytest.raises(ValueError, match="another catalogue"):
        validate_acquisition_completion(
            wrong_study,
            candidate_catalogue_path=catalogue,
            runner_root=runner,
        )

    for mutation in ("ledger", "ledger-hash"):
        changed_payload = copy.deepcopy(completion["payload"])
        if mutation == "ledger":
            changed_payload["baseline_batches"] = []
            changed_payload["baseline_batches_sha256"] = evidence_sha256([])
        else:
            changed_payload["baseline_batches_sha256"] = "0" * 64
        changed = bind_receipt(changed_payload, receipt_type=COMPLETION_TYPE)
        with pytest.raises(ValueError, match="baseline-batch ledger"):
            validate_acquisition_completion(
                changed,
                candidate_catalogue_path=catalogue,
                runner_root=runner,
            )

    changed_checkpoint = copy.deepcopy(load_json(runner / "checkpoint.json")["payload"])
    changed_state = changed_checkpoint["candidates"][candidate_id]
    changed_terminal_path = runner / changed_state["terminal"]["path"]
    changed_terminal = copy.deepcopy(load_json(changed_terminal_path)["payload"])
    changed_terminal["baseline_batch"] = None
    _replace_receipt_payload(changed_terminal_path, changed_terminal)
    changed_state["terminal"]["sha256"] = hashlib.sha256(
        changed_terminal_path.read_bytes()
    ).hexdigest()
    _replace_receipt_payload(runner / "checkpoint.json", changed_checkpoint)
    with pytest.raises(ValueError, match="baseline-batch binding"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_initial_status_is_resumable_and_incomplete(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    assert acquisition_status(runner, candidate_catalogue_path=catalogue)["terminal_count"] == 0
    with pytest.raises(ValueError, match="resolved deterministic prefix"):
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)


@pytest.mark.parametrize("legacy_schema", (1, 2, 3))
def test_historical_schemas_are_readable_but_cannot_be_mutated(
    tmp_path: Path, legacy_schema: int
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    provenance_path = runner / "provenance.json"
    provenance_payload = copy.deepcopy(load_json(provenance_path)["payload"])
    provenance_payload["acquisition_schema_version"] = legacy_schema
    if legacy_schema < 3:
        provenance_payload.pop("acquisition_action_timing_contract")
        provenance_payload.pop("baseline_scheduling_contract")
        provenance_payload.pop("passive_render_hard_cap_after_load_ms")
    _replace_receipt_payload(provenance_path, provenance_payload)

    checkpoint_path = runner / "checkpoint.json"
    checkpoint_payload = copy.deepcopy(load_json(checkpoint_path)["payload"])
    checkpoint_payload.pop("checkpoint_schema_version")
    checkpoint_payload.pop("baseline_batches")
    checkpoint_payload.pop("active_batch")
    _strip_schema_five_policy_evidence(checkpoint_payload)
    checkpoint_payload["provenance_sha256"] = hashlib.sha256(
        provenance_path.read_bytes()
    ).hexdigest()
    _replace_receipt_payload(checkpoint_path, checkpoint_payload)

    checkpoint_before = checkpoint_path.read_bytes()
    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert status["pending_count"] == CANDIDATE_COUNT
    with pytest.raises(ValueError, match="historical acquisition runners"):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=RejectingBackend(),
        )
    with pytest.raises(ValueError, match="historical acquisition runners"):
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)
    assert checkpoint_path.read_bytes() == checkpoint_before


@pytest.mark.parametrize("legacy_schema", (4, 5))
def test_historical_modern_schemas_keep_their_exact_read_only_checkpoint_shape(
    tmp_path: Path,
    legacy_schema: int,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="ignored",
    )
    provenance_path = runner / "provenance.json"
    provenance = copy.deepcopy(load_json(provenance_path)["payload"])
    provenance["acquisition_schema_version"] = legacy_schema
    _replace_receipt_payload(provenance_path, provenance)
    checkpoint_path = runner / "checkpoint.json"
    checkpoint = copy.deepcopy(load_json(checkpoint_path)["payload"])
    checkpoint["checkpoint_schema_version"] = (
        acquisition_module.SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION
    )
    checkpoint["provenance_sha256"] = acquisition_module.sha256_file(provenance_path)
    if legacy_schema == 4:
        _strip_schema_five_policy_evidence(checkpoint)
    _replace_receipt_payload(checkpoint_path, checkpoint)
    before = checkpoint_path.read_bytes()

    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert status["acquisition_schema_version"] == legacy_schema
    assert status["checkpoint_schema_version"] == (
        acquisition_module.SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION
    )
    assert status["pending_count"] == CANDIDATE_COUNT
    assert "selection" not in status
    with pytest.raises(ValueError, match="historical acquisition runners"):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=NoNetworkBackend(),
        )
    with pytest.raises(ValueError, match="historical acquisition runners"):
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)
    assert checkpoint_path.read_bytes() == before


def test_historical_schema_policy_map_and_render_contract_are_frozen() -> None:
    source_contract = _HISTORICAL_ACQUISITION_CONTRACTS["schema3_4"]
    schema_five_variants = _HISTORICAL_ACQUISITION_CONTRACTS["schema5_source_variants"]
    schema_six_variants = _HISTORICAL_ACQUISITION_CONTRACTS["schema6_receipts"]
    manifest = _prepared_manifest("https://example.com/", ["https://example.com"])
    render_v3 = copy.deepcopy(manifest["preparation"]["render_observation"])
    render_v3.pop("internal_document_lifecycle_summary")
    render_v3["schema_version"] = acquisition_module._SCHEMA_SIX_RENDER_OBSERVATION_SCHEMA_VERSION
    render_v1 = copy.deepcopy(source_contract["render_observation"])

    with pytest.raises(ValueError, match="no instrumentation contract"):
        acquisition_module._instrumentation_policy_for(1)
    with pytest.raises(ValueError, match="no passive-render contract"):
        acquisition_module._passive_render_contract_for(1)
    with pytest.raises(ValueError, match="no document-response contract"):
        acquisition_module._document_response_schema_for(1)

    assert (
        acquisition_module._instrumentation_policy_for(2)
        == source_contract["instrumentation_policy"]
    )
    assert acquisition_module._document_response_schema_for(2) == 1
    with pytest.raises(ValueError, match="no passive-render contract"):
        acquisition_module._passive_render_contract_for(2)

    for schema in (3, 4):
        assert (
            acquisition_module._instrumentation_policy_for(schema)
            == source_contract["instrumentation_policy"]
        )
        assert (
            acquisition_module._passive_render_contract_for(schema)
            == (source_contract["passive_render_contract"])
        )
        assert (
            acquisition_module._passive_render_contract_sha256_for(schema)
            == (source_contract["passive_render_contract_sha256"])
        )
        acquisition_module._validate_versioned_render_observation(
            render_v1,
            acquisition_schema_version=schema,
        )

    with pytest.raises(ValueError, match="ambiguous"):
        acquisition_module._instrumentation_policy_for(5)
    for variant in schema_five_variants:
        policy = variant["instrumentation_policy"]
        assert (
            acquisition_module._instrumentation_policy_for(
                5,
                recorded_policy=policy,
            )
            == policy
        )
        contract = acquisition_module._historical_evidence_contract_for(
            5,
            instrumentation_policy=policy,
        )
        assert contract["fixed_provenance_sha256"] == variant["fixed_provenance_sha256"]
        assert contract["source_lab_commits"] == tuple(variant["source_lab_commits"])
    acquisition_module._validate_versioned_render_observation(
        render_v3,
        acquisition_schema_version=5,
    )

    with pytest.raises(ValueError, match="ambiguous"):
        acquisition_module._instrumentation_policy_for(6)
    for variant in schema_six_variants:
        policy = variant["instrumentation_policy"]
        assert (
            acquisition_module._instrumentation_policy_for(
                6,
                recorded_policy=policy,
            )
            == policy
        )
        contract = acquisition_module._historical_evidence_contract_for(
            6,
            instrumentation_policy=policy,
        )
        assert contract["fixed_provenance_sha256"] == variant["fixed_provenance_sha256"]
        assert contract["source_lab_commits"] == (variant["source_lab_commit"],)
    acquisition_module._validate_versioned_render_observation(
        render_v3,
        acquisition_schema_version=6,
    )

    for schema in (3, 4):
        with pytest.raises(ValueError, match="historical render observation fields"):
            acquisition_module._validate_versioned_render_observation(
                render_v3,
                acquisition_schema_version=schema,
            )
    for schema in (5, 6):
        with pytest.raises(ValueError, match="historical render observation fields"):
            acquisition_module._validate_versioned_render_observation(
                render_v1,
                acquisition_schema_version=schema,
            )
    with pytest.raises(ValueError, match="does not match its schema"):
        acquisition_module._historical_evidence_contract_for(
            5,
            instrumentation_policy=source_contract["instrumentation_policy"],
        )
    with pytest.raises(ValueError, match="does not match its schema"):
        acquisition_module._historical_evidence_contract_for(
            5,
            instrumentation_policy=(
                "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v11"
            ),
        )


def test_source_era_schema_five_fixed_projection_is_a_golden_contract() -> None:
    variants = _HISTORICAL_ACQUISITION_CONTRACTS["schema5_source_variants"]
    assert [variant["instrumentation_policy"].rsplit("-", 1)[-1] for variant in variants] == [
        "v10",
        "v12",
        "v13",
        "v14",
    ]
    for index, variant in enumerate(variants):
        projection = _schema_five_fixed_projection(variant)
        assert (
            hashlib.sha256(canonical_json_bytes(projection)).hexdigest()
            == variant["fixed_provenance_sha256"]
        )
        contract = acquisition_module._historical_evidence_contract_for(
            5,
            instrumentation_policy=variant["instrumentation_policy"],
        )
        assert contract["fixed_provenance_sha256"] == variant["fixed_provenance_sha256"]
        assert contract["source_lab_commits"] == tuple(variant["source_lab_commits"])
        for source_lab_commit in variant["source_lab_commits"]:
            provenance = _synthetic_historical_provenance(
                5,
                fixed_projection=projection,
                source_lab_commit=source_lab_commit,
            )
            assert acquisition_module._validate_current_provenance_contract(provenance) == (
                provenance
            )

        mismatched_source = variants[(index + 1) % len(variants)]["source_lab_commits"][0]
        mismatched = _synthetic_historical_provenance(
            5,
            fixed_projection=projection,
            source_lab_commit=mismatched_source,
        )
        with pytest.raises(ValueError, match="provenance policy"):
            acquisition_module._validate_current_provenance_contract(mismatched)


def test_schema_six_frozen_projections_are_self_contained_golden_contracts() -> None:
    variants = _HISTORICAL_ACQUISITION_CONTRACTS["schema6_receipts"]
    for index, variant in enumerate(variants):
        projection = _schema_six_fixed_projection(variant)
        assert (
            hashlib.sha256(canonical_json_bytes(projection)).hexdigest()
            == variant["fixed_provenance_sha256"]
        )
        provenance = _synthetic_historical_provenance(
            6,
            fixed_projection=projection,
            source_lab_commit=variant["source_lab_commit"],
        )
        assert acquisition_module._validate_current_provenance_contract(provenance) == provenance

        mismatched = copy.deepcopy(provenance)
        mismatched["source"]["lab_commit"] = variants[(index + 1) % len(variants)][
            "source_lab_commit"
        ]
        with pytest.raises(ValueError, match="provenance policy"):
            acquisition_module._validate_current_provenance_contract(mismatched)


@pytest.mark.parametrize(
    ("variant_index", "relative_root", "durable_failure"),
    (
        (
            0,
            "artifacts/class-study-retired-acquisitions/cohort-v91-c60641b7ead8/acquisition",
            "tranco-0000697, tranco-0000984",
        ),
        (
            1,
            "artifacts/class-study-retired-acquisitions/cohort-v95-b93507604671/acquisition",
            "tranco-0000697",
        ),
        (
            2,
            "artifacts/class-study-retired-acquisitions/cohort-v96-bab80c20096b/acquisition",
            "tranco-0000697",
        ),
    ),
)
def test_immutable_schema_six_acquisitions_reach_their_durable_state_verifier(
    variant_index: int,
    relative_root: str,
    durable_failure: str,
) -> None:
    repository = Path(__file__).resolve().parents[1]
    artifact_roots = (
        "artifacts/class-study-retired-acquisitions/cohort-v91-c60641b7ead8/acquisition",
        "artifacts/class-study-retired-acquisitions/cohort-v95-b93507604671/acquisition",
        "artifacts/class-study-retired-acquisitions/cohort-v96-bab80c20096b/acquisition",
    )
    assert relative_root == artifact_roots[variant_index]
    runner = repository / relative_root
    if not runner.is_dir():
        pytest.skip("immutable acquisition artifact is not present in this checkout")
    variant = _HISTORICAL_ACQUISITION_CONTRACTS["schema6_receipts"][variant_index]
    provenance_path = runner / "provenance.json"
    provenance = load_json(provenance_path)
    assert (
        hashlib.sha256(provenance_path.read_bytes()).hexdigest()
        == variant["provenance_file_sha256"]
    )
    assert provenance["payload_sha256"] == variant["provenance_payload_sha256"]
    payload = acquisition_module.validate_hash_bound_receipt(
        provenance,
        expected_type=acquisition_module.PROVENANCE_TYPE,
    )
    assert payload["source"]["lab_commit"] == variant["source_lab_commit"]
    assert acquisition_module._validate_current_provenance_contract(payload) == payload

    checkpoint_path = runner / "checkpoint.json"
    before = checkpoint_path.read_bytes()
    catalogue = repository / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"
    with pytest.raises(InternalAcquisitionError, match=durable_failure):
        acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert checkpoint_path.read_bytes() == before

    mismatched = copy.deepcopy(payload)
    other = _HISTORICAL_ACQUISITION_CONTRACTS["schema6_receipts"][(variant_index + 1) % 3]
    mismatched["cdp_target_instrumentation_policy"] = other["instrumentation_policy"]
    with pytest.raises(ValueError, match="provenance policy"):
        acquisition_module._validate_current_provenance_contract(mismatched)

    other_provenance_path = repository / artifact_roots[(variant_index + 1) % 3] / "provenance.json"
    if other_provenance_path.is_file():
        other_payload = acquisition_module.validate_hash_bound_receipt(
            load_json(other_provenance_path),
            expected_type=acquisition_module.PROVENANCE_TYPE,
        )
        coherent_other_contract_with_wrong_source = copy.deepcopy(other_payload)
        coherent_other_contract_with_wrong_source["source"] = copy.deepcopy(payload["source"])
        with pytest.raises(ValueError, match="provenance policy"):
            acquisition_module._validate_current_provenance_contract(
                coherent_other_contract_with_wrong_source
            )


def test_immutable_schema_seven_v100_acquisition_reaches_its_durable_state_verifier() -> None:
    repository = Path(__file__).resolve().parents[1]
    runner = (
        repository
        / "artifacts/class-study-retired-acquisitions/cohort-v100-eb2631f0a7de/acquisition"
    )
    if not runner.is_dir():
        pytest.skip("immutable v100 acquisition artifact is not present in this checkout")
    variants = _HISTORICAL_ACQUISITION_CONTRACTS["schema7_archived_receipts"]
    assert len(variants) == 1
    variant = variants[0]
    assert variant["cohort"] == "v100"

    strict_path = runner.parent / "strict-verification.json"
    assert strict_path.stat().st_mode & 0o777 == 0o600
    assert (
        hashlib.sha256(strict_path.read_bytes()).hexdigest()
        == variant["strict_verification_file_sha256"]
    )
    strict = load_json(strict_path)
    assert (
        strict["payload_sha256"]
        == variant["strict_verification_payload_sha256"]
    )
    strict_payload = acquisition_module.validate_hash_bound_receipt(
        strict,
        expected_type="qcsd-class-study-retired-acquisition-strict-verification",
    )
    assert strict_payload["evidentiary_status"] == "non-scientific-maintenance-only"
    assert strict_payload["promotion_authority"] is False
    assert strict_payload["strict_checks"] == {
        "archive_inode_tree_matches_pre_move_receipt": True,
        "authority_mode_octal": "0600",
        "candidate_catalogue_mode_octal": "0600",
        "docker_boot_id_matches_maintenance_receipt": True,
        "docker_containers_with_owner_label": 0,
        "docker_daemon_id_matches_maintenance_receipt": True,
        "docker_networks_with_owner_label": 0,
        "docker_volume_response_has_volumes_key": True,
        "docker_volumes_with_owner_label": 0,
        "docker_warnings": None,
        "intent_receipt_delta": ["completed_utc", "status"],
        "source_path_absent": True,
    }

    authority_path = repository / "artifacts/class-study-acquisition-authority-v100.json"
    assert (
        hashlib.sha256(authority_path.read_bytes()).hexdigest()
        == variant["authority_file_sha256"]
    )
    authority = load_json(authority_path)
    assert authority["payload_sha256"] == variant["authority_payload_sha256"]
    authority_payload = acquisition_module.validate_hash_bound_receipt(
        authority,
        expected_type="qcsd-class-study-acquisition-authority",
    )
    assert authority_payload["cohort_version"] == 100
    assert authority_payload["promotion_authority"] is False

    provenance_path = runner / "provenance.json"
    assert (
        hashlib.sha256(provenance_path.read_bytes()).hexdigest()
        == variant["provenance_file_sha256"]
    )
    provenance = load_json(provenance_path)
    assert provenance["payload_sha256"] == variant["provenance_payload_sha256"]
    provenance_payload = acquisition_module.validate_hash_bound_receipt(
        provenance,
        expected_type=acquisition_module.PROVENANCE_TYPE,
    )
    assert provenance_payload["acquisition_schema_version"] == 7
    assert provenance_payload["source"]["lab_commit"] == variant["source_lab_commit"]
    assert provenance_payload["acquisition_authority"]["sha256"] == variant[
        "authority_file_sha256"
    ]
    assert (
        acquisition_module._validate_current_provenance_contract(provenance_payload)
        == provenance_payload
    )

    checkpoint_path = runner / "checkpoint.json"
    before = checkpoint_path.read_bytes()
    assert hashlib.sha256(before).hexdigest() == variant["checkpoint_file_sha256"]
    checkpoint = load_json(checkpoint_path)
    assert checkpoint["payload_sha256"] == variant["checkpoint_payload_sha256"]
    checkpoint_payload = acquisition_module.validate_hash_bound_receipt(
        checkpoint,
        expected_type=acquisition_module.CHECKPOINT_TYPE,
    )
    assert checkpoint_payload["checkpoint_schema_version"] == 3
    assert checkpoint_payload["provenance_sha256"] == variant["provenance_file_sha256"]
    catalogue = repository / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"
    with pytest.raises(InternalAcquisitionError, match="tranco-0000697"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert checkpoint_path.read_bytes() == before


def test_historical_orphan_terminals_are_verify_only(tmp_path: Path) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=RejectingBackend(),
    )

    provenance_path = runner / "provenance.json"
    provenance_payload = copy.deepcopy(load_json(provenance_path)["payload"])
    provenance_payload["acquisition_schema_version"] = 3
    _replace_receipt_payload(provenance_path, provenance_payload)
    provenance_sha256 = hashlib.sha256(provenance_path.read_bytes()).hexdigest()

    checkpoint_path = runner / "checkpoint.json"
    checkpoint_payload = copy.deepcopy(load_json(checkpoint_path)["payload"])
    checkpoint_payload.pop("checkpoint_schema_version")
    checkpoint_payload.pop("baseline_batches")
    checkpoint_payload.pop("active_batch")
    _strip_schema_five_policy_evidence(checkpoint_payload)
    checkpoint_payload["provenance_sha256"] = provenance_sha256
    orphan_count = 0
    for state in checkpoint_payload["candidates"].values():
        binding = state["terminal"]
        if binding is None:
            continue
        terminal_path = runner / binding["path"]
        terminal_payload = copy.deepcopy(load_json(terminal_path)["payload"])
        terminal_payload["terminal_schema_version"] = 2
        terminal_payload["provenance_sha256"] = provenance_sha256
        terminal_payload.pop("checkpoint_schema_version")
        terminal_payload.pop("baseline_batch")
        terminal_payload["checkpoint_state_sha256"] = (
            acquisition_module._normalised_terminal_state_sha256(
                state,
                kind=terminal_payload["kind"],
            )
        )
        _replace_receipt_payload(terminal_path, terminal_payload)
        state["state"] = "pending"
        state["terminal"] = None
        orphan_count += 1
    _replace_receipt_payload(checkpoint_path, checkpoint_payload)
    checkpoint_before = checkpoint_path.read_bytes()

    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert orphan_count == MAX_CANDIDATES_PER_ACTION
    assert status["recovery_required_count"] == orphan_count
    assert checkpoint_path.read_bytes() == checkpoint_before
    with pytest.raises(ValueError, match="historical acquisition runners"):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=RejectingBackend(),
        )
    assert checkpoint_path.read_bytes() == checkpoint_before


@pytest.mark.parametrize("legacy_schema", (1, 2, 3))
def test_completion_validation_accepts_each_legacy_schema_shape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    legacy_schema: int,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    catalogue_value, candidates = acquisition_module.load_candidate_catalogue_receipt(catalogue)
    monkeypatch.setattr(
        acquisition_module,
        "load_candidate_catalogue_receipt",
        lambda _path: (catalogue_value, candidates[:1]),
    )
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=RejectingBackend(),
    )
    current_completion = load_json(
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)
    )["payload"]

    provenance_path = runner / "provenance.json"
    provenance_payload = copy.deepcopy(load_json(provenance_path)["payload"])
    provenance_payload["acquisition_schema_version"] = legacy_schema
    _replace_receipt_payload(provenance_path, provenance_payload)
    provenance_sha256 = hashlib.sha256(provenance_path.read_bytes()).hexdigest()

    checkpoint_path = runner / "checkpoint.json"
    checkpoint_payload = copy.deepcopy(load_json(checkpoint_path)["payload"])
    checkpoint_payload.pop("checkpoint_schema_version")
    checkpoint_payload.pop("baseline_batches")
    checkpoint_payload.pop("active_batch")
    _strip_schema_five_policy_evidence(checkpoint_payload)
    checkpoint_payload["provenance_sha256"] = provenance_sha256
    candidate_id, state = next(iter(checkpoint_payload["candidates"].items()))
    terminal_path = runner / state["terminal"]["path"]
    terminal_payload = copy.deepcopy(load_json(terminal_path)["payload"])
    terminal_payload["provenance_sha256"] = provenance_sha256
    terminal_payload.pop("checkpoint_schema_version")
    terminal_payload.pop("baseline_batch")
    terminal_payload["checkpoint_state_sha256"] = (
        acquisition_module._normalised_terminal_state_sha256(
            state,
            kind=terminal_payload["kind"],
        )
    )
    if legacy_schema == 1:
        terminal_payload.pop("terminal_schema_version")
        terminal_payload.pop("terminalised_at")
        terminal_payload.pop("checkpoint_state_sha256")
    else:
        terminal_payload["terminal_schema_version"] = 2
    _replace_receipt_payload(terminal_path, terminal_payload)
    state["terminal"]["sha256"] = hashlib.sha256(terminal_path.read_bytes()).hexdigest()
    _replace_receipt_payload(checkpoint_path, checkpoint_payload)
    checkpoint = load_json(checkpoint_path)

    legacy_completion_payload = {
        key: copy.deepcopy(value)
        for key, value in current_completion.items()
        if key
        not in {
            "completion_schema_version",
            "checkpoint_schema_version",
            "baseline_batches",
            "baseline_batches_sha256",
            "selection",
        }
    }
    legacy_completion_payload.update(
        {
            "acquisition_schema_version": legacy_schema,
            "provenance_sha256": provenance_sha256,
            "checkpoint_payload_sha256": checkpoint["payload_sha256"],
            "terminal_receipts": {candidate_id: state["terminal"]},
        }
    )
    legacy_completion = bind_receipt(
        legacy_completion_payload,
        receipt_type=COMPLETION_TYPE,
    )
    checkpoint_before = checkpoint_path.read_bytes()
    assert (
        validate_acquisition_completion(
            legacy_completion,
            candidate_catalogue_path=catalogue,
            runner_root=runner,
        )["acquisition_schema_version"]
        == legacy_schema
    )
    assert checkpoint_path.read_bytes() == checkpoint_before


def test_schema_one_observed_eligible_completion_uses_its_original_evidence_shape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    catalogue_value, candidates = acquisition_module.load_candidate_catalogue_receipt(catalogue)
    monkeypatch.setattr(
        acquisition_module,
        "load_candidate_catalogue_receipt",
        lambda _path: (catalogue_value, candidates[:1]),
    )
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    candidate_id, _state = _complete_one_probing_candidate(
        runner,
        catalogue=catalogue,
        stability=stability,
        workloads=tmp_path / "workloads",
        backend=SlowBackend(clock),
        clock=clock,
    )
    current_completion = load_json(
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)
    )["payload"]

    provenance_path = runner / "provenance.json"
    provenance_payload = copy.deepcopy(load_json(provenance_path)["payload"])
    provenance_payload["acquisition_schema_version"] = 1
    _replace_receipt_payload(provenance_path, provenance_payload)
    provenance_sha256 = hashlib.sha256(provenance_path.read_bytes()).hexdigest()

    checkpoint_path = runner / "checkpoint.json"
    checkpoint_payload = copy.deepcopy(load_json(checkpoint_path)["payload"])
    checkpoint_payload.pop("checkpoint_schema_version")
    checkpoint_payload.pop("baseline_batches")
    checkpoint_payload.pop("active_batch")
    _strip_schema_five_policy_evidence(checkpoint_payload)
    checkpoint_payload["provenance_sha256"] = provenance_sha256
    state = checkpoint_payload["candidates"][candidate_id]
    for page in state["pages"]:
        for index, observation in enumerate(page["observations"]):
            schema_one_observation = {
                key: copy.deepcopy(value)
                for key, value in observation.items()
                if key in acquisition_module.SCHEMA_ONE_OBSERVATION_FIELDS
            }
            schema_one_observation["runner_provenance_sha256"] = provenance_sha256
            assert set(schema_one_observation) == (acquisition_module.SCHEMA_ONE_OBSERVATION_FIELDS)
            assert "discovery_instrumentation_policy" not in schema_one_observation
            page["observations"][index] = schema_one_observation

    terminal_path = runner / state["terminal"]["path"]
    terminal_payload = copy.deepcopy(load_json(terminal_path)["payload"])
    terminal_payload["provenance_sha256"] = provenance_sha256
    for field in (
        "terminal_schema_version",
        "terminalised_at",
        "checkpoint_state_sha256",
        "checkpoint_schema_version",
        "baseline_batch",
    ):
        terminal_payload.pop(field)
    _replace_receipt_payload(terminal_path, terminal_payload)
    state["terminal"]["sha256"] = hashlib.sha256(terminal_path.read_bytes()).hexdigest()
    _replace_receipt_payload(checkpoint_path, checkpoint_payload)
    checkpoint = load_json(checkpoint_path)

    legacy_completion_payload = {
        key: copy.deepcopy(value)
        for key, value in current_completion.items()
        if key
        not in {
            "completion_schema_version",
            "checkpoint_schema_version",
            "baseline_batches",
            "baseline_batches_sha256",
            "selection",
        }
    }
    legacy_completion_payload.update(
        {
            "acquisition_schema_version": 1,
            "provenance_sha256": provenance_sha256,
            "checkpoint_payload_sha256": checkpoint["payload_sha256"],
            "terminal_receipts": {candidate_id: state["terminal"]},
        }
    )
    legacy_completion = bind_receipt(
        legacy_completion_payload,
        receipt_type=COMPLETION_TYPE,
    )
    checkpoint_before = checkpoint_path.read_bytes()
    assert (
        validate_acquisition_completion(
            legacy_completion,
            candidate_catalogue_path=catalogue,
            runner_root=runner,
        )["observed_toolchain"]
        == current_completion["observed_toolchain"]
    )
    assert checkpoint_path.read_bytes() == checkpoint_before

    rebound_checkpoint_payload = copy.deepcopy(checkpoint["payload"])
    rebound_checkpoint_payload["candidates"][candidate_id]["pages"][0]["observations"][0][
        "unpublished_optional_evidence"
    ] = "not-a-schema-one-field"
    _replace_receipt_payload(checkpoint_path, rebound_checkpoint_payload)
    rebound_checkpoint = load_json(checkpoint_path)
    rebound_completion_payload = copy.deepcopy(legacy_completion_payload)
    rebound_completion_payload["checkpoint_payload_sha256"] = rebound_checkpoint["payload_sha256"]
    rebound_completion = bind_receipt(
        rebound_completion_payload,
        receipt_type=COMPLETION_TYPE,
    )
    with pytest.raises(ValueError, match="schema-one checkpoint observation fields"):
        validate_acquisition_completion(
            rebound_completion,
            candidate_catalogue_path=catalogue,
            runner_root=runner,
        )


def test_schema_three_observed_eligible_completion_rebinds_transitive_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    catalogue_value, candidates = acquisition_module.load_candidate_catalogue_receipt(catalogue)
    monkeypatch.setattr(
        acquisition_module,
        "load_candidate_catalogue_receipt",
        lambda _path: (catalogue_value, candidates[:1]),
    )
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    candidate_id, _state = _complete_one_probing_candidate(
        runner,
        catalogue=catalogue,
        stability=stability,
        workloads=tmp_path / "workloads",
        backend=SlowBackend(clock),
        clock=clock,
    )
    current_completion = load_json(
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)
    )["payload"]

    provenance_path = runner / "provenance.json"
    provenance_payload = copy.deepcopy(load_json(provenance_path)["payload"])
    provenance_payload["acquisition_schema_version"] = 3
    _replace_receipt_payload(provenance_path, provenance_payload)
    provenance_sha256 = hashlib.sha256(provenance_path.read_bytes()).hexdigest()

    checkpoint_path = runner / "checkpoint.json"
    checkpoint_payload = copy.deepcopy(load_json(checkpoint_path)["payload"])
    checkpoint_payload.pop("checkpoint_schema_version")
    checkpoint_payload.pop("baseline_batches")
    checkpoint_payload.pop("active_batch")
    _strip_schema_five_policy_evidence(checkpoint_payload)
    checkpoint_payload["provenance_sha256"] = provenance_sha256
    state = checkpoint_payload["candidates"][candidate_id]
    for page in state["pages"]:
        for observation in page["observations"]:
            assert set(observation) == acquisition_module.CURRENT_OBSERVATION_FIELDS
            _downgrade_observation_to_historical_contract(
                runner,
                observation,
                provenance_sha256=provenance_sha256,
                acquisition_schema_version=3,
            )

    terminal_path = runner / state["terminal"]["path"]
    terminal_payload = copy.deepcopy(load_json(terminal_path)["payload"])
    stability_path = Path(terminal_payload["stability_receipt"]["path"])
    stability_payload = copy.deepcopy(load_json(stability_path)["payload"])
    selected_page = next(
        page
        for page in state["pages"]
        if page["page"]["ordinal"] == int(stability_path.stem.removeprefix("page-"))
    )
    observations = tuple(
        acquisition_module.StabilityObservation(
            **{
                key: observation.get(key)
                for key in acquisition_module.StabilityObservation.__dataclass_fields__
            }
        )
        for observation in selected_page["observations"]
    )
    page = PageCandidate(**selected_page["page"])
    stability_payload["observations"] = [observation.as_dict() for observation in observations]
    stability_payload["decision"] = acquisition_module.derive_stability_decision(
        page,
        baseline_started_at=state["baseline_started_at"],
        observations=observations,
    ).as_dict()
    _replace_receipt_payload(stability_path, stability_payload)
    admitted_path = Path(terminal_payload["admitted_workload"]["path"])
    selected_prepared_path = Path(selected_page["observations"][0]["prepared_path"])
    admitted_path.write_bytes(selected_prepared_path.read_bytes())

    terminal_payload["terminal_schema_version"] = 2
    terminal_payload["provenance_sha256"] = provenance_sha256
    terminal_payload["stability_receipt"]["sha256"] = hashlib.sha256(
        stability_path.read_bytes()
    ).hexdigest()
    terminal_payload["admitted_workload"]["sha256"] = hashlib.sha256(
        admitted_path.read_bytes()
    ).hexdigest()
    terminal_payload["checkpoint_state_sha256"] = (
        acquisition_module._normalised_terminal_state_sha256(
            state,
            kind=terminal_payload["kind"],
        )
    )
    terminal_payload.pop("checkpoint_schema_version")
    terminal_payload.pop("baseline_batch")
    _replace_receipt_payload(terminal_path, terminal_payload)
    state["terminal"]["sha256"] = hashlib.sha256(terminal_path.read_bytes()).hexdigest()
    _replace_receipt_payload(checkpoint_path, checkpoint_payload)
    checkpoint = load_json(checkpoint_path)

    legacy_completion_payload = {
        key: copy.deepcopy(value)
        for key, value in current_completion.items()
        if key
        not in {
            "completion_schema_version",
            "checkpoint_schema_version",
            "baseline_batches",
            "baseline_batches_sha256",
            "selection",
        }
    }
    legacy_completion_payload.update(
        {
            "acquisition_schema_version": 3,
            "provenance_sha256": provenance_sha256,
            "checkpoint_payload_sha256": checkpoint["payload_sha256"],
            "terminal_receipts": {candidate_id: state["terminal"]},
        }
    )
    legacy_completion = bind_receipt(
        legacy_completion_payload,
        receipt_type=COMPLETION_TYPE,
    )
    checkpoint_before = checkpoint_path.read_bytes()
    assert (
        validate_acquisition_completion(
            legacy_completion,
            candidate_catalogue_path=catalogue,
            runner_root=runner,
        )["observed_toolchain"]
        == current_completion["observed_toolchain"]
    )
    assert checkpoint_path.read_bytes() == checkpoint_before


def test_runner_creates_and_strictly_validates_document_response_namespace(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    receipts = runner / "document-response-receipts"
    prepared = runner / "prepared-probes"
    assert receipts.is_dir() and not receipts.is_symlink()
    assert prepared.is_dir() and not prepared.is_symlink()
    (receipts / "uncheckpointed.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected acquisition document-response"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)

    (receipts / "uncheckpointed.json").unlink()
    (prepared / "uncheckpointed.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected acquisition prepared-probe"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_transient_navigation_failure_retries_and_preserves_each_attempt(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = TransientNavigationBackend(clock)

    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=backend,
        clock=clock,
    )

    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "baseline-ready"
    )
    # Two candidates launch in the first navigation round; the transient
    # failure is retried while its compatible partner remains completed.
    assert backend.navigation_calls == 3
    assert [item["outcome"] for item in active["navigation_attempts"]] == [
        "recoverable-failure",
        "completed",
    ]
    assert [item["attempt"] for item in active["navigation_attempts"]] == [1, 2]


def test_unexpected_navigation_fault_is_durably_checkpointed_and_blocks_resume(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )

    class BrokenBackend(RejectingBackend):
        def discover_navigation(self, domain: str):
            raise AssertionError(f"broken navigation adapter for {domain}")

    with pytest.raises(InternalAcquisitionError, match="durable internal navigation"):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=BrokenBackend(),
        )

    checkpoint = load_json(runner / "checkpoint.json")
    failed = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if "internal_acquisition_error" in state
    )
    assert failed["terminal"] is None
    assert failed["navigation_attempts"][-1]["outcome"] == "internal-acquisition-error"
    assert failed["internal_acquisition_error"] == {
        "schema_version": 1,
        "stage": "navigation",
        "attempt": 1,
        "page_ordinal": None,
        "probe_id": None,
        "exception_type": "AssertionError",
        "message": next(
            item["reason"].removeprefix("AssertionError: ")
            for item in failed["navigation_attempts"]
            if item["outcome"] == "internal-acquisition-error"
        ),
        "recorded_at": failed["navigation_attempts"][-1]["completed_at"],
    }
    with pytest.raises(InternalAcquisitionError, match="checkpoint contains durable"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_terminal_navigation_policy_failure_does_not_retry(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )

    class PolicyBackend(RejectingBackend):
        calls = 0

        def discover_navigation(self, domain: str):
            self.calls += 1
            raise TerminalProbePolicyError("origin cap exceeded")

    backend = PolicyBackend()
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=backend,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    terminal = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "terminal"
    )
    assert backend.calls == MAX_CANDIDATES_PER_ACTION
    assert [item["outcome"] for item in terminal["navigation_attempts"]] == [
        "terminal-policy-rejection"
    ]


def test_later_probe_rejects_a_different_prepare_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "1" * 64)
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "2" * 64)
    with pytest.raises(ValueError, match="frozen source/prepare image"):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=RejectingBackend(),
        )


def test_baseline_action_prearms_short_probe_and_records_start_not_slow_completion(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = SlowBackend(clock)
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=tmp_path / "workloads",
        backend=backend,
        clock=clock,
        max_candidates=1,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    first_id = next(
        candidate_id
        for candidate_id, state in checkpoint["payload"]["candidates"].items()
        if state["state"] == "baseline-ready"
    )
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=tmp_path / "workloads",
        backend=backend,
        clock=clock,
        max_candidates=1,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    states = checkpoint["payload"]["candidates"]
    observation = states[first_id]["pages"][0]["observations"][0]
    assert states[first_id]["baseline_started_at"] == "2026-08-28T00:00:10Z"
    assert observation["observed_at"] == "2026-08-28T00:00:35Z"
    assert observation["probe_completed_at"] == "2026-08-28T00:00:55Z"
    assert sum(state["state"] == "probing" for state in states.values()) == 1


def test_current_navigation_success_duration_has_an_exact_soft_limit(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=SlowBackend(clock),
        clock=clock,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    payload = copy.deepcopy(checkpoint["payload"])
    state = next(
        item for item in payload["candidates"].values() if item["state"] == "baseline-ready"
    )
    attempt = state["navigation_attempts"][0]
    started = datetime.fromisoformat(attempt["started_at"].replace("Z", "+00:00"))
    attempt["completed_at"] = acquisition_module._format_time(started + timedelta(seconds=1_800))
    _replace_receipt_payload(runner / "checkpoint.json", payload)
    acquisition_status(runner, candidate_catalogue_path=catalogue)

    payload = copy.deepcopy(load_json(runner / "checkpoint.json")["payload"])
    state = next(
        item for item in payload["candidates"].values() if item["state"] == "baseline-ready"
    )
    state["navigation_attempts"][0]["completed_at"] = acquisition_module._format_time(
        started + timedelta(seconds=1_800, microseconds=1)
    )
    _replace_receipt_payload(runner / "checkpoint.json", payload)
    with pytest.raises(ValueError, match="navigation-attempt ledger"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_interrupted_navigation_duration_is_not_fabricated_as_success(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    checkpoint = load_json(runner / "checkpoint.json")
    payload = copy.deepcopy(checkpoint["payload"])
    state = next(iter(payload["candidates"].values()))
    state["navigation_attempts"] = [
        {
            "attempt": 1,
            "started_at": "2026-08-28T00:00:00Z",
            "completed_at": "2026-08-28T02:00:00Z",
            "outcome": "interrupted",
            "reason": "externally bounded action ended before an outcome",
            "policy_evidence": None,
        }
    ]
    _replace_receipt_payload(runner / "checkpoint.json", payload)
    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert status["terminal_count"] == 0
    persisted = load_json(runner / "checkpoint.json")["payload"]["candidates"]
    assert next(iter(persisted.values()))["navigation_attempts"][0]["outcome"] == ("interrupted")


def test_clock_rollback_keeps_pending_start_and_recovery_records_interruption(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))

    class RegressingClockBackend:
        def discover_navigation(self, domain: str):
            clock.value -= timedelta(seconds=1)
            return _homepage_navigation(domain)

    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "clock": clock,
    }
    with pytest.raises(ValueError, match="clock moved backwards"):
        run_due_acquisition(
            runner,
            backend=RegressingClockBackend(),
            **arguments,
        )
    checkpoint = load_json(runner / "checkpoint.json")
    state = next(
        item
        for item in checkpoint["payload"]["candidates"].values()
        if item.get("pending_navigation") is not None
    )
    assert state["navigation_attempts"] == []
    assert state["pending_navigation"]["attempt"] == 1

    clock.value = datetime(2026, 8, 28, 0, 0, 1, tzinfo=UTC)
    run_due_acquisition(
        runner,
        backend=RejectingBackend(),
        **arguments,
    )
    run_due_acquisition(
        runner,
        backend=RejectingBackend(),
        **arguments,
    )
    _candidate_id, state = _first_terminal_state(runner)
    assert [item["outcome"] for item in state["navigation_attempts"]] == [
        "interrupted",
        "terminal-policy-rejection",
    ]
    assert not any(item["outcome"] == "completed" for item in state["navigation_attempts"])


def test_current_probe_success_duration_has_an_exact_soft_limit(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": SlowBackend(clock),
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    payload = copy.deepcopy(checkpoint["payload"])
    state = next(item for item in payload["candidates"].values() if item["state"] == "probing")
    attempt = state["pages"][0]["probe_attempts"][0]
    observed = datetime.fromisoformat(attempt["observed_at"].replace("Z", "+00:00"))
    attempt["completed_at"] = acquisition_module._format_time(observed + timedelta(seconds=1_800))
    _replace_receipt_payload(runner / "checkpoint.json", payload)
    acquisition_status(runner, candidate_catalogue_path=catalogue)

    payload = copy.deepcopy(load_json(runner / "checkpoint.json")["payload"])
    state = next(item for item in payload["candidates"].values() if item["state"] == "probing")
    state["pages"][0]["probe_attempts"][0]["completed_at"] = acquisition_module._format_time(
        observed + timedelta(seconds=1_800, microseconds=1)
    )
    _replace_receipt_payload(runner / "checkpoint.json", payload)
    with pytest.raises(ValueError, match="probe-attempt ledger"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_serial_spacing_refuses_a_second_baseline_batch_but_allows_navigation(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": SlowBackend(clock),
        "clock": clock,
        "max_candidates": MAX_CANDIDATES_PER_ACTION,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    status = run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    probing = [
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    ]
    assert len(probing) == 2
    assert all(len(state["pages"][0]["observations"]) == 1 for state in probing)
    assert (
        sum(
            "baseline_started_at" in state for state in checkpoint["payload"]["candidates"].values()
        )
        == 2
    )
    assert (
        sum(
            state["state"] == "baseline-ready"
            for state in checkpoint["payload"]["candidates"].values()
        )
        == 2
    )
    assert status["pending_count"] == 118
    assert status["pending_start_blocked"] is False
    assert status["work_due_now"] is True
    assert status["next_due"] == "2026-08-28T00:40:20Z"


def test_current_checkpoint_rejects_a_cross_offset_baseline_collision(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": SlowBackend(clock),
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    payload = copy.deepcopy(checkpoint["payload"])
    first = next(state for state in payload["candidates"].values() if state["state"] == "probing")
    second = next(
        state for state in payload["candidates"].values() if state["state"] == "baseline-ready"
    )
    first_baseline = datetime.fromisoformat(first["baseline_started_at"].replace("Z", "+00:00"))
    # Two baselines are far apart directly, but this second baseline's t+24h
    # action would collide exactly with the first baseline's t+72h action.
    second["state"] = "probing"
    second["baseline_started_at"] = acquisition_module._format_time(
        first_baseline + timedelta(hours=48)
    )
    second_id = next(
        candidate_id for candidate_id, state in payload["candidates"].items() if state is second
    )
    baseline_body = {
        "baseline_started_at": second["baseline_started_at"],
        "candidate_ids": [second_id],
        "live_page_count": len(second["pages"]),
    }
    payload["baseline_batches"].append(
        {
            "batch_id": acquisition_module._batch_identifier("baseline", baseline_body),
            **baseline_body,
        }
    )
    _replace_receipt_payload(runner / "checkpoint.json", payload)
    with pytest.raises(ValueError, match="serial scheduling contract"):
        acquisition_status(
            runner,
            candidate_catalogue_path=catalogue,
            now=first_baseline,
        )


def test_due_probe_at_latest_edge_outranks_an_already_missed_candidate(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = SlowBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
        "max_candidates": 1,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    payload = copy.deepcopy(checkpoint["payload"])
    first = next(state for state in payload["candidates"].values() if state["state"] == "probing")
    second = next(
        state for state in payload["candidates"].values() if state["state"] == "baseline-ready"
    )
    first_baseline = datetime.fromisoformat(first["baseline_started_at"].replace("Z", "+00:00"))
    second_baseline = first_baseline + timedelta(hours=24, minutes=25)
    second["state"] = "probing"
    second["baseline_started_at"] = acquisition_module._format_time(second_baseline)
    second_id = next(
        candidate_id for candidate_id, state in payload["candidates"].items() if state is second
    )
    baseline_body = {
        "baseline_started_at": second["baseline_started_at"],
        "candidate_ids": [second_id],
        "live_page_count": len(second["pages"]),
    }
    payload["baseline_batches"].append(
        {
            "batch_id": acquisition_module._batch_identifier("baseline", baseline_body),
            **baseline_body,
        }
    )
    _replace_receipt_payload(runner / "checkpoint.json", payload)

    # Candidate one has already missed t+24h. Candidate two still owns the
    # exact inclusive t+30s latest edge; spending the sole action on stale
    # cleanup would destroy that otherwise valid observation.
    clock.value = second_baseline + timedelta(seconds=35)
    status = acquisition_status(
        runner,
        candidate_catalogue_path=catalogue,
        now=clock.value,
    )
    assert status["due_now_count"] == 1
    assert status["missed_window_count"] == 1
    run_due_acquisition(runner, **arguments)

    states = load_json(runner / "checkpoint.json")["payload"]["candidates"]
    first_state = next(
        state
        for state in states.values()
        if state.get("baseline_started_at") == acquisition_module._format_time(first_baseline)
    )
    second_state = next(
        state
        for state in states.values()
        if state.get("baseline_started_at") == acquisition_module._format_time(second_baseline)
    )
    assert first_state["terminal"] is None
    assert len(first_state["pages"][0]["observations"]) == 1
    assert second_state["terminal"] is None
    assert second_state["pages"][0]["observations"][0]["observed_at"] == (
        acquisition_module._format_time(second_baseline + timedelta(seconds=35))
    )


def test_missed_window_is_retained_but_blocks_new_selection_work(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = SlowBackend(clock)
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=tmp_path / "workloads",
        backend=backend,
        clock=clock,
        max_candidates=1,
    )
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=stability,
            workload_root=tmp_path / "workloads",
            backend=backend,
            clock=clock,
            max_candidates=1,
            sleeper=lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt),
        )
    interrupted_wait = load_json(runner / "checkpoint.json")["payload"]
    assert interrupted_wait["active_batch"] is None
    assert len(interrupted_wait["baseline_batches"]) == 1
    armed_id = interrupted_wait["baseline_batches"][0]["candidate_ids"][0]
    assert interrupted_wait["candidates"][armed_id]["state"] == "probing"
    assert all(
        page["probe_attempts"] == [] and "pending_probe" not in page
        for page in interrupted_wait["candidates"][armed_id]["pages"]
    )
    clock.value = datetime(2026, 8, 28, 0, 1, tzinfo=UTC)
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=tmp_path / "workloads",
        backend=backend,
        clock=clock,
        max_candidates=1,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    missed = [state for state in checkpoint["payload"]["candidates"].values() if state["terminal"]]
    assert len(missed) == 1
    terminal = load_json(runner / missed[0]["terminal"]["path"])
    assert terminal["payload"]["kind"] == "probe-window-missed"
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=tmp_path / "workloads",
        backend=backend,
        clock=clock,
        max_candidates=1,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    assert (
        sum(
            state["state"] == "baseline-ready"
            for state in checkpoint["payload"]["candidates"].values()
        )
        == 0
    )
    status = acquisition_status(runner, candidate_catalogue_path=catalogue, now=clock.value)
    assert status["selection_blocked_candidate_ids"] == [armed_id]
    assert armed_id in status["selection"]["admission_ids"]
    assert status["complete"] is False and status["work_due_now"] is False


def test_orphan_terminal_is_validated_and_recovered_after_checkpoint_interruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    original_save = acquisition_module._save_acquisition_checkpoint

    def interrupted_save(*args, **kwargs):
        if tuple((runner / "terminals").glob("*.json")):
            raise KeyboardInterrupt
        return original_save(*args, **kwargs)

    monkeypatch.setattr(acquisition_module, "_save_acquisition_checkpoint", interrupted_save)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=RejectingBackend(),
        )
    checkpoint = load_json(runner / "checkpoint.json")
    assert all(state["terminal"] is None for state in checkpoint["payload"]["candidates"].values())
    assert len(tuple((runner / "terminals").glob("*.json"))) == 2

    monkeypatch.setattr(acquisition_module, "_save_acquisition_checkpoint", original_save)
    checkpoint_before = (runner / "checkpoint.json").read_bytes()
    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert status["terminal_count"] == 0
    assert status["recovery_required_count"] == 2
    assert status["work_due_now"] is True
    assert (runner / "checkpoint.json").read_bytes() == checkpoint_before
    with pytest.raises(ValueError, match="recovery exceeds the candidate action bound"):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=RejectingBackend(),
            max_candidates=1,
        )
    assert (runner / "checkpoint.json").read_bytes() == checkpoint_before
    recovered_status = run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=NoNetworkBackend(),
        max_candidates=2,
    )
    assert recovered_status["terminal_count"] == 2
    checkpoint = load_json(runner / "checkpoint.json")
    terminal_states = [
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["terminal"] is not None
    ]
    assert len(terminal_states) == 2
    assert all(state["state"] == "terminal" for state in terminal_states)
    assert all(
        "navigation_attempts" not in state
        for state in checkpoint["payload"]["candidates"].values()
        if state["terminal"] is None
    )


def test_orphan_terminal_recovery_rejects_a_changed_preterminal_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    original_save = acquisition_module._save_acquisition_checkpoint

    def interrupted_save(*args, **kwargs):
        if tuple((runner / "terminals").glob("*.json")):
            raise KeyboardInterrupt
        return original_save(*args, **kwargs)

    monkeypatch.setattr(acquisition_module, "_save_acquisition_checkpoint", interrupted_save)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=RejectingBackend(),
        )
    monkeypatch.setattr(acquisition_module, "_save_acquisition_checkpoint", original_save)

    terminal_path = next((runner / "terminals").glob("*.json"))
    candidate_id = terminal_path.stem
    checkpoint = load_json(runner / "checkpoint.json")
    checkpoint_payload = copy.deepcopy(checkpoint["payload"])
    state = checkpoint_payload["candidates"][candidate_id]
    assert state["terminal"] is None
    state["navigation_attempts"][-1]["reason"] = "forged terminal-policy reason"
    _replace_receipt_payload(runner / "checkpoint.json", checkpoint_payload)

    with pytest.raises(ValueError, match="does not bind the checkpoint state"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_terminal_publication_temp_namespace_and_crash_cleanup(tmp_path: Path) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    [(candidate_id, _domain)] = _catalogue_candidate_identities(catalogue, 1)
    terminal = runner / "terminals" / f"{candidate_id}.json"
    prelink = terminal.parent / (f".{terminal.name}{acquisition_module.ATOMIC_TEMP_MARKER}prelink")
    prelink.write_bytes(b"partial terminal")
    acquisition_status(runner, candidate_catalogue_path=catalogue)
    checkpoint_before = (runner / "checkpoint.json").read_bytes()
    _checkpoint, recoveries = acquisition_module._load_checkpoint(
        runner / "checkpoint.json",
        runner / "provenance.json",
        catalogue,
    )
    assert recoveries == 0
    assert not prelink.exists()
    assert (runner / "checkpoint.json").read_bytes() == checkpoint_before

    junk = terminal.parent / f".not-a-terminal.json{acquisition_module.ATOMIC_TEMP_MARKER}junk"
    junk.write_bytes(b"junk")
    with pytest.raises(ValueError, match="unexpected acquisition terminal path"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)
    junk.unlink()

    unsafe = terminal.parent / (f".{terminal.name}{acquisition_module.ATOMIC_TEMP_MARKER}unsafe")
    unsafe.symlink_to(runner / "checkpoint.json")
    with pytest.raises(ValueError, match="terminal temporary path is unsafe"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)
    unsafe.unlink()

    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=RejectingBackend(),
        max_candidates=1,
    )
    assert terminal.is_file()
    terminal_bytes = terminal.read_bytes()
    postlink = terminal.parent / (
        f".{terminal.name}{acquisition_module.ATOMIC_TEMP_MARKER}postlink"
    )
    acquisition_module.os.link(terminal, postlink)
    _checkpoint, recoveries = acquisition_module._load_checkpoint(
        runner / "checkpoint.json",
        runner / "provenance.json",
        catalogue,
    )
    assert recoveries == 0
    assert not postlink.exists()
    assert terminal.read_bytes() == terminal_bytes


def test_current_runner_rejects_a_legacy_terminal_shape(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=RejectingBackend(),
    )

    def make_legacy(_state, terminal_payload):
        terminal_payload.pop("terminal_schema_version")
        terminal_payload.pop("terminalised_at")
        terminal_payload.pop("checkpoint_state_sha256")

    _rewrite_terminal_and_checkpoint(runner, mutate=make_legacy)
    with pytest.raises(ValueError, match="terminal evidence fields"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_three_interrupted_navigation_starts_form_a_valid_preprobe_terminal(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )

    class InterruptingNavigationBackend:
        def discover_navigation(self, _domain):
            raise KeyboardInterrupt

    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": InterruptingNavigationBackend(),
    }
    for _attempt in range(3):
        with pytest.raises(KeyboardInterrupt):
            run_due_acquisition(runner, **arguments)
        run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    _candidate_id, state = _first_terminal_state(runner)
    terminal = load_json(runner / state["terminal"]["path"])["payload"]
    assert terminal["kind"] == "pre-probe-rejection"
    assert [item["outcome"] for item in state["navigation_attempts"]] == [
        "interrupted",
        "interrupted",
        "interrupted",
    ]


def test_probe_window_terminal_requires_a_proven_missed_instant(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": SlowBackend(clock),
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(
            runner,
            **arguments,
            sleeper=lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt),
        )
    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    clock.value = datetime.fromisoformat(
        active["baseline_started_at"].replace("Z", "+00:00")
    ) + timedelta(minutes=1)
    run_due_acquisition(runner, **arguments)

    def move_inside_window(state, terminal_payload):
        baseline = datetime.fromisoformat(state["baseline_started_at"].replace("Z", "+00:00"))
        terminal_payload["terminalised_at"] = (
            (baseline + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
        )

    _rewrite_terminal_and_checkpoint(runner, mutate=move_inside_window)
    with pytest.raises(ValueError, match="still admissible"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_stable_page_unavailable_recomputes_the_checkpoint_partition(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": ProbeRejectingBackend(clock),
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    _candidate_id, terminal_state = _first_terminal_state(runner)
    terminal = load_json(runner / terminal_state["terminal"]["path"])["payload"]
    assert terminal["terminal_schema_version"] == TERMINAL_SCHEMA_VERSION
    assert terminal["kind"] == "stable-page-unavailable"

    def remove_rejection(state, _terminal_payload):
        state["pages"][0].pop("rejection")

    _rewrite_terminal_and_checkpoint(runner, mutate=remove_rejection)
    with pytest.raises(ValueError, match="retains an incomplete page"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_slow_backend_can_reach_eligible_terminal_across_outer_windows(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = SlowBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    for instant in (
        datetime(2026, 8, 28, 0, 0, 40, tzinfo=UTC),
        datetime(2026, 8, 29, 0, 0, 10, tzinfo=UTC),
        datetime(2026, 8, 31, 0, 0, 10, tzinfo=UTC),
    ):
        clock.value = instant
        run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    terminal_state = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["terminal"] is not None
    )
    terminal = load_json(runner / terminal_state["terminal"]["path"])
    assert terminal["payload"]["kind"] == "eligible"


def test_eligible_terminal_observations_must_exactly_match_the_checkpoint(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    _complete_one_probing_candidate(
        runner,
        catalogue=catalogue,
        stability=stability,
        workloads=tmp_path / "workloads",
        backend=SlowBackend(clock),
        clock=clock,
    )

    def change_stable_observations(state, _terminal_payload):
        for observation in state["pages"][0]["observations"]:
            observation["body_bytes"] += 1

    _rewrite_terminal_and_checkpoint(runner, mutate=change_stable_observations)
    with pytest.raises(ValueError, match="exact checkpoint selection"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_eligible_terminal_must_select_the_first_eligible_checkpoint_page(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    workloads = tmp_path / "workloads"
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    candidate_id, _state = _complete_one_probing_candidate(
        runner,
        catalogue=catalogue,
        stability=stability,
        workloads=workloads,
        backend=TwoPageBackend(clock),
        clock=clock,
    )

    def select_second_page(state, terminal_payload):
        second = state["pages"][1]
        stability_path = stability / candidate_id / "page-01.json"
        prepared_path = Path(second["observations"][0]["prepared_path"])
        admitted_path = Path(terminal_payload["admitted_workload"]["path"])
        admitted_path.write_bytes(prepared_path.read_bytes())
        terminal_payload["stability_receipt"] = {
            "path": str(stability_path.resolve()),
            "sha256": hashlib.sha256(stability_path.read_bytes()).hexdigest(),
        }
        terminal_payload["admitted_workload"] = {
            "path": str(admitted_path.resolve()),
            "sha256": hashlib.sha256(admitted_path.read_bytes()).hexdigest(),
        }

    _rewrite_terminal_and_checkpoint(runner, mutate=select_second_page)
    with pytest.raises(ValueError, match="exact checkpoint selection"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_probe_start_checkpoint_recovers_after_hard_interruption(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = InterruptOnceBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
        "max_candidates": 1,
    }
    run_due_acquisition(runner, **arguments)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    pending = active["pages"][0]["pending_probe"]
    assert pending["observed_at"] == "2026-08-28T00:00:35Z"
    assert pending["attempt"] == 1
    assert pending["workload_id"].endswith("-a001")
    clock.value = datetime(2026, 8, 28, 0, 0, 37, tzinfo=UTC)
    run_due_acquisition(runner, **arguments)
    recovered = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in recovered["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    assert active["pages"][0]["observations"] == []
    assert active["pages"][0]["probe_attempts"][-1]["outcome"] == "interrupted"
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    assert active["pages"][0]["observations"][0]["observed_at"] == ("2026-08-28T00:00:37Z")
    assert backend.workload_ids[0].endswith("-a001")
    assert backend.workload_ids[1].endswith("-a002")


def test_final_preparation_origin_drift_reconverges_inside_the_same_window(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = FinalDiscoveryDriftOnceBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
        "max_candidates": 1,
    }
    run_due_acquisition(runner, **arguments)
    clock.value = datetime(2026, 8, 28, 0, 0, 40, tzinfo=UTC)

    run_due_acquisition(runner, **arguments)

    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    page = active["pages"][0]
    assert [item["outcome"] for item in page["probe_attempts"]] == [
        "recoverable-failure",
        "completed",
    ]
    assert [item["attempt"] for item in page["probe_attempts"]] == [1, 2]
    assert backend.workload_ids[0].endswith("-a001")
    assert backend.workload_ids[1].endswith("-a002")
    assert len(backend.discovery_calls) == 3
    assert backend.discovery_calls[0] == backend.discovery_calls[1]
    assert backend.discovery_calls[2][1] == (
        "https://late-origin.example",
        backend.discovery_calls[0][1][0],
    )
    assert len(page["observations"]) == 1


def test_unexpected_probe_fault_is_durably_checkpointed_and_blocks_resume(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))

    class BrokenProbeBackend(SlowBackend):
        def discover(self, url, approved_origins):
            raise PreparationError(f"Neqo HTTP/3 probe failed (101) after a Rust panic for {url}")

    backend = BrokenProbeBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    with pytest.raises(InternalAcquisitionError, match="durable internal probe"):
        run_due_acquisition(runner, **arguments)

    checkpoint = load_json(runner / "checkpoint.json")
    failed = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if "internal_acquisition_error" in state
    )
    error = failed["internal_acquisition_error"]
    assert error["stage"] == "probe"
    assert error["page_ordinal"] == 0
    assert error["probe_id"] == "t+30s"
    assert error["exception_type"] == "PreparationError"
    assert failed["pages"][0]["probe_attempts"][-1]["outcome"] == ("internal-acquisition-error")
    with pytest.raises(InternalAcquisitionError, match="checkpoint contains durable"):
        run_due_acquisition(runner, **arguments)


def test_probe_attempt_ledger_rejects_gaps_post_success_work_and_missing_success():
    candidate_id = "class-ledger"

    def record(attempt: int, outcome: str) -> dict[str, object]:
        return {
            "probe_id": "t+30s",
            "workload_id": _probe_attempt_workload_id(candidate_id, 0, "t+30s", attempt),
            "attempt": attempt,
            "observed_at": "2026-08-28T00:00:30Z",
            "completed_at": "2026-08-28T00:00:31Z",
            "outcome": outcome,
            "reason": None if outcome == "completed" else "transient",
            "policy_evidence": None,
        }

    with pytest.raises(ValueError, match="ledger"):
        _validate_probe_attempts(
            {
                "page": {"ordinal": 0},
                "observations": [],
                "probe_attempts": [record(2, "recoverable-failure")],
            },
            candidate_id=candidate_id,
        )
    with pytest.raises(ValueError, match="ledger"):
        _validate_probe_attempts(
            {
                "page": {"ordinal": 0},
                "observations": [{"probe_id": "t+30s"}],
                "probe_attempts": [
                    record(1, "completed"),
                    record(2, "recoverable-failure"),
                ],
            },
            candidate_id=candidate_id,
        )
    with pytest.raises(ValueError, match="success ledger"):
        _validate_probe_attempts(
            {
                "page": {"ordinal": 0},
                "observations": [{"probe_id": "t+30s"}],
                "probe_attempts": [],
            },
            candidate_id=candidate_id,
        )


@pytest.mark.parametrize("historical_schema", (1, 2, 3, 4))
def test_probe_attempt_policy_evidence_field_is_exactly_schema_versioned(
    historical_schema: int,
) -> None:
    candidate_id = "class-schema-attempt"
    historical_attempt = {
        "probe_id": "t+30s",
        "workload_id": _probe_attempt_workload_id(candidate_id, 0, "t+30s", 1),
        "attempt": 1,
        "observed_at": "2026-08-28T00:00:30Z",
        "completed_at": "2026-08-28T00:00:31Z",
        "outcome": "interrupted",
        "reason": "fixture interruption",
    }

    _validate_probe_attempts(
        {"page": {"ordinal": 0}, "observations": [], "probe_attempts": [historical_attempt]},
        candidate_id=candidate_id,
        acquisition_schema_version=historical_schema,
    )
    with pytest.raises(ValueError, match="probe-attempt ledger"):
        _validate_probe_attempts(
            {
                "page": {"ordinal": 0},
                "observations": [],
                "probe_attempts": [{**historical_attempt, "policy_evidence": None}],
            },
            candidate_id=candidate_id,
            acquisition_schema_version=historical_schema,
        )

    with pytest.raises(ValueError, match="probe-attempt ledger"):
        _validate_probe_attempts(
            {"page": {"ordinal": 0}, "observations": [], "probe_attempts": [historical_attempt]},
            candidate_id=candidate_id,
            acquisition_schema_version=acquisition_module.SCHEMA_VERSION,
        )
    current_attempt = {**historical_attempt, "policy_evidence": None}
    _validate_probe_attempts(
        {"page": {"ordinal": 0}, "observations": [], "probe_attempts": [current_attempt]},
        candidate_id=candidate_id,
        acquisition_schema_version=acquisition_module.SCHEMA_VERSION,
    )


def test_manifest_written_before_kill_is_never_relabelled_on_resume(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = InterruptAfterManifestBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
        "max_candidates": 1,
    }
    run_due_acquisition(runner, **arguments)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(runner, **arguments)

    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    pending = active["pages"][0]["pending_probe"]
    assert pending["attempt"] == 1
    stale_path = runner / "prepared-probes" / f"{pending['workload_id']}.json"
    assert stale_path.read_bytes() == b"orphaned first-attempt manifest"

    clock.value = datetime(2026, 8, 28, 0, 0, 37, tzinfo=UTC)
    run_due_acquisition(runner, **arguments)
    recovered = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in recovered["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    assert active["pages"][0]["observations"] == []
    assert active["pages"][0]["probe_attempts"][-1]["outcome"] == "interrupted"
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    observation = active["pages"][0]["observations"][0]
    first_id, second_id = backend.workload_ids
    assert first_id.endswith("-a001")
    assert second_id.endswith("-a002")
    assert first_id != second_id
    assert observation["observed_at"] == "2026-08-28T00:00:37Z"
    assert observation["prepared_path"] == str(
        (runner / "prepared-probes" / f"{second_id}.json").resolve()
    )
    resumed_manifest = runner / "prepared-probes" / f"{second_id}.json"
    assert (
        observation["prepared_workload_sha256"]
        == hashlib.sha256(resumed_manifest.read_bytes()).hexdigest()
    )
    assert resumed_manifest.read_bytes() != b"orphaned first-attempt manifest"
    assert (
        observation["prepared_workload_sha256"]
        != hashlib.sha256(stale_path.read_bytes()).hexdigest()
    )
    rebound = copy.deepcopy(checkpoint["payload"])
    candidate_id = next(
        candidate_id
        for candidate_id, state in rebound["candidates"].items()
        if state is not None and state["state"] == "probing"
    )
    rebound_observation = rebound["candidates"][candidate_id]["pages"][0]["observations"][0]
    rebound_observation["prepared_path"] = str(stale_path.resolve())
    rebound_observation["document_response_receipt_path"] = (
        f"document-response-receipts/{first_id}.json"
    )
    _replace_receipt_payload(runner / "checkpoint.json", rebound)
    with pytest.raises(ValueError, match="observation differs from its completed attempt"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_pending_probe_cannot_restart_network_work_after_its_window(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = InterruptOnceBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    clock.value = datetime(2026, 8, 28, 0, 0, 40, tzinfo=UTC)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(runner, **arguments)

    clock.value = datetime(2026, 8, 28, 1, 0, tzinfo=UTC)
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    terminal_state = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["terminal"] is not None
    )
    terminal = load_json(runner / terminal_state["terminal"]["path"])
    assert terminal["payload"]["kind"] == "probe-window-missed"
    page = terminal_state["pages"][0]
    assert "pending_probe" not in page
    assert len(page["probe_attempts"]) == 1
    assert page["probe_attempts"][0] == {
        "probe_id": "t+30s",
        "workload_id": page["probe_attempts"][0]["workload_id"],
        "attempt": 1,
        "observed_at": "2026-08-28T00:01:05Z",
        "completed_at": "2026-08-28T01:00:00Z",
        "outcome": "interrupted",
        "reason": "prior invocation ended before recording an outcome",
        "policy_evidence": None,
    }
    assert page["probe_attempts"][0]["workload_id"].endswith("-t30s-a001")


def test_navigation_boundary_allows_https_www_but_rejects_lookalikes_and_http():
    assert _navigation_request_allowed("GET", "https://www.example.com/", "example.com")
    assert _navigation_request_allowed("GET", "https://cdn.www.example.com/a", "example.com")
    assert not _navigation_request_allowed("GET", "https://example.com.evil.test/", "example.com")
    assert not _navigation_request_allowed("GET", "http://www.example.com/", "example.com")
    assert not _navigation_request_allowed("POST", "https://www.example.com/", "example.com")
    assert unsafe_catalogue_domain_reason("animalsexporn.net") == (
        "domain-safety-policy-rejected:porn"
    )
    assert unsafe_catalogue_domain_reason("escortsandbabes.com.au") == (
        "domain-safety-policy-rejected:escort"
    )
    assert unsafe_catalogue_domain_reason("watchhentai.net") == (
        "domain-safety-policy-rejected:hentai"
    )
    assert unsafe_catalogue_domain_reason("topcasinolucky.com") == (
        "domain-safety-policy-rejected:casino"
    )
    assert unsafe_catalogue_domain_reason("xnxx.com") == (
        "domain-safety-policy-rejected:exact-domain"
    )
    assert unsafe_catalogue_domain_reason("ordinary-example.com") is None


def test_navigation_redirect_convergence_pins_arbitrary_in_boundary_subdomain_once(
    monkeypatch: pytest.MonkeyPatch,
):
    class FakePlaywrightError(Exception):
        pass

    sync_api = ModuleType("playwright.sync_api")
    sync_api.Error = FakePlaywrightError  # type: ignore[attr-defined]
    sync_api.sync_playwright = lambda: None  # type: ignore[attr-defined]
    playwright = ModuleType("playwright")
    playwright.sync_api = sync_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    base = "https://example.com"
    redirected = "https://news.example.com"
    resolution_calls = []

    def resolve(origins):
        resolution_calls.append(tuple(origins))
        return {value: "1.1.1.1" if value == base else "8.8.8.8" for value in origins}

    passes = []

    def navigation_pass(domain, **kwargs):
        assert domain == "example.com"
        pins = dict(kwargs["navigation_pins"])
        passes.append(pins)
        if redirected not in pins:
            raise acquisition_module._NavigationPinExpansion({redirected})
        return NavigationDiscovery(
            "example.com",
            (),
            (base, redirected),
            (),
            ((f"{base}/", (base, redirected)),),
        )

    monkeypatch.setattr(acquisition_module, "public_origin_ip_pins", resolve)
    monkeypatch.setattr(
        acquisition_module,
        "_catalogue_boundary_navigation_pass",
        navigation_pass,
    )

    result = catalogue_boundary_navigation("example.com")

    assert result.observed_origins == (base, redirected)
    assert resolution_calls == [(base,), (redirected,)]
    assert passes == [
        {base: "1.1.1.1"},
        {base: "1.1.1.1", redirected: "8.8.8.8"},
    ]


def test_navigation_redirect_convergence_rejects_private_subdomain_answer(
    monkeypatch: pytest.MonkeyPatch,
):
    class FakePlaywrightError(Exception):
        pass

    sync_api = ModuleType("playwright.sync_api")
    sync_api.Error = FakePlaywrightError  # type: ignore[attr-defined]
    sync_api.sync_playwright = lambda: None  # type: ignore[attr-defined]
    playwright = ModuleType("playwright")
    playwright.sync_api = sync_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    redirected = "https://private.example.com"

    def resolve(origins):
        if redirected in origins:
            raise TerminalProbePolicyError("public-origin policy rejected DNS answers")
        return {"https://example.com": "1.1.1.1"}

    monkeypatch.setattr(acquisition_module, "public_origin_ip_pins", resolve)
    monkeypatch.setattr(
        acquisition_module,
        "_catalogue_boundary_navigation_pass",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            acquisition_module._NavigationPinExpansion({redirected})
        ),
    )

    with pytest.raises(TerminalProbePolicyError, match="rejected DNS"):
        catalogue_boundary_navigation("example.com")


def _run_navigation_pass_with_primary_redirect(
    target_url: str,
    monkeypatch: pytest.MonkeyPatch,
    *,
    retained_router_failure: Exception | None = None,
):
    holder: dict[str, object] = {}

    class FakePlaywrightError(Exception):
        pass

    class FakeRoute:
        def __init__(self, request):
            self.request = request

        def abort(self):
            return None

        def continue_(self):
            return None

    class FakeRequest:
        method = "GET"

        def __init__(self, url: str, frame: object):
            self.url = url
            self.frame = frame

        def is_navigation_request(self):
            return True

    class FakePage:
        def __init__(self, context):
            self.context = context
            self.main_frame = object()
            self.url = "https://example.com/"

        def goto(self, *_args, **_kwargs):
            router = holder["router"]
            source = SimpleNamespace(target_type="page", generation=0)
            for index, url in enumerate(("https://example.com/", target_url)):
                router.on_event(
                    source,
                    "Fetch.requestPaused",
                    {
                        "requestId": f"fetch-{index}",
                        "request": {"method": "GET", "url": url},
                        "frameId": "root-frame",
                        "resourceType": "Document",
                    },
                )
            raise FakePlaywrightError("request-stage redirect abort")

    class FakeContext:
        service_workers = []

        def __init__(self):
            self.handlers = {}

        def add_init_script(self, *, script):
            assert script

        def route(self, _pattern, handler):
            self.route_handler = handler

        def route_web_socket(self, pattern, handler):
            assert pattern == "**"
            self.websocket_handler = handler

        def on(self, event, handler):
            self.handlers[event] = handler

        def new_page(self):
            return FakePage(self)

        def new_cdp_session(self, _page):
            return SimpleNamespace(
                send=lambda command, _parameters=None: (
                    {"frameTree": {"frame": {"id": "root-frame"}}}
                    if command == "Page.getFrameTree"
                    else {}
                )
            )

        def close(self):
            return None

    class FakeBrowser:
        def new_context(self, **_kwargs):
            return FakeContext()

        def new_browser_cdp_session(self):
            return object()

        def close(self):
            return None

    class FakePlaywright:
        def __enter__(self):
            def launch(**kwargs):
                assert kwargs["env"] == acquisition_module.chromium_child_environment()
                assert kwargs["executable_path"] == str(
                    playwright_driver.DEFAULT_CONFIGURED_EXECUTABLE
                )
                return FakeBrowser()

            chromium = SimpleNamespace(launch=launch)
            return SimpleNamespace(chromium=chromium)

        def __exit__(self, *_args):
            return None

    class FakeRouter:
        shutdown_ready = True
        active_request_identities = ()

        def __init__(self, _session, *, on_event, **_kwargs):
            self.on_event = on_event
            self.aborting = False
            holder["router"] = self

        def start(self):
            return None

        def send(self, *_args, **_kwargs):
            return None

        def raise_if_failed(self):
            if self.aborting and retained_router_failure is not None:
                raise retained_router_failure
            return None

        def begin_abort(self):
            self.aborting = True
            return None

        def finish_abort(self):
            return None

    class FakeBrowserGuard:
        def __init__(self, _session, _router):
            pass

        def start(self):
            return None

        def begin_abort(self):
            return None

        def finish_abort(self):
            return None

    monkeypatch.setattr(
        acquisition_module,
        "validate_default_playwright_driver_once",
        lambda: {"test_fixture": True},
    )
    monkeypatch.setattr(
        acquisition_module,
        "launch_production_browser",
        lambda _playwright, **_kwargs: (
            FakeBrowser(),
            {"launch_profile": "production-fail-closed"},
        ),
    )
    monkeypatch.setattr(acquisition_module, "RecursiveCdpTargetRouter", FakeRouter)
    monkeypatch.setattr(acquisition_module, "BrowserSharedWorkerGuard", FakeBrowserGuard)
    return acquisition_module._catalogue_boundary_navigation_pass(
        "example.com",
        deadline=acquisition_module.time.monotonic() + 1,
        navigation_pins={"https://example.com": "1.1.1.1"},
        sync_playwright=FakePlaywright,
        playwright_error=FakePlaywrightError,
    )


def test_navigation_pass_aborts_then_requests_a_pin_for_primary_subdomain_redirect(
    monkeypatch: pytest.MonkeyPatch,
):
    with pytest.raises(acquisition_module._NavigationPinExpansion) as captured:
        _run_navigation_pass_with_primary_redirect(
            "https://news.example.com/article",
            monkeypatch,
        )

    assert captured.value.origins == ("https://news.example.com",)


def test_navigation_pass_retains_out_of_boundary_redirect_as_explicit_policy_rejection(
    monkeypatch: pytest.MonkeyPatch,
):
    with pytest.raises(
        TerminalProbePolicyError,
        match="document navigation left the allowed HTTPS candidate-domain boundary",
    ):
        _run_navigation_pass_with_primary_redirect("https://example.net/", monkeypatch)


def test_navigation_pass_retained_router_failure_outranks_retryable_pin_expansion(
    monkeypatch: pytest.MonkeyPatch,
):
    retained = CdpTargetIntegrityError("synthetic retained router failure")
    with pytest.raises(CdpTargetIntegrityError, match="synthetic retained router failure"):
        _run_navigation_pass_with_primary_redirect(
            "https://news.example.com/article",
            monkeypatch,
            retained_router_failure=retained,
        )


def test_navigation_completion_discards_resolved_root_continue_race() -> None:
    with pytest.raises(
        RecoverableAcquisitionError,
        match="discarded after 1 correlated root Fetch continuation race",
    ):
        acquisition_module._require_unexceptional_navigation_completion(
            {
                "total": 1,
                "resolved": 1,
                "pending": 0,
                "aborted": 0,
                "terminal_outcomes": {"Network.loadingFinished": 1},
            }
        )


@pytest.mark.parametrize(
    "summary",
    (
        {
            "total": 1,
            "resolved": 0,
            "pending": 1,
            "aborted": 0,
            "terminal_outcomes": {"Network.loadingFinished": 0},
        },
        {
            "total": 1,
            "resolved": 0,
            "pending": 0,
            "aborted": 1,
            "terminal_outcomes": {"Network.loadingFinished": 0},
        },
    ),
)
def test_navigation_completion_rejects_nonterminal_root_continue_summary(summary) -> None:
    with pytest.raises(CdpTargetIntegrityError, match="summary is non-terminal"):
        acquisition_module._require_unexceptional_navigation_completion(summary)


def test_navigation_completion_accepts_no_root_continue_race() -> None:
    acquisition_module._require_unexceptional_navigation_completion(
        {
            "total": 0,
            "resolved": 0,
            "pending": 0,
            "aborted": 0,
            "terminal_outcomes": {"Network.loadingFinished": 0},
        }
    )


def test_content_type_probe_validates_then_uses_central_browser_launch(
    monkeypatch: pytest.MonkeyPatch,
):
    class FakePlaywrightError(Exception):
        pass

    class FakeLocator:
        def inner_text(self, **_kwargs):
            return "ordinary page"

        def count(self):
            return 0

    class FakePage:
        url = "https://example.com/article"

        def __init__(self, context, session):
            self.context = context
            self.session = session
            self.main_frame = object()

        def goto(self, *_args, **_kwargs):
            request = SimpleNamespace(
                method="GET",
                url=self.url,
                frame=self.main_frame,
                is_navigation_request=lambda: True,
            )
            route = SimpleNamespace(
                request=request,
                abort=lambda *_args: pytest.fail("root document route was aborted"),
                continue_=lambda: None,
            )
            self.context.route_handler(route)
            self.session.handlers["Fetch.requestPaused"](
                {
                    "requestId": "root-document",
                    "request": {"method": "GET", "url": self.url},
                    "resourceType": "Document",
                    "frameId": "root-frame",
                }
            )
            return SimpleNamespace(
                status=200,
                headers={"content-type": "text/html; charset=utf-8"},
            )

        def title(self):
            return "Example"

        def locator(self, _selector):
            return FakeLocator()

        def close(self):
            return None

    class FakeContext:
        def __init__(self):
            self.session = SimpleNamespace(handlers={}, commands=[])

            def on(event, handler):
                self.session.handlers[event] = handler

            def send(command, parameters=None):
                self.session.commands.append((command, parameters))
                if command == "Page.getFrameTree":
                    return {"frameTree": {"frame": {"id": "root-frame"}}}
                return {}

            self.session.on = on
            self.session.send = send

        def route(self, _pattern, _handler):
            self.route_handler = _handler

        def new_page(self):
            return FakePage(self, self.session)

        def new_cdp_session(self, _page):
            return self.session

        def close(self):
            return None

    class FakeBrowser:
        version = "143.0.7499.4"

        def new_context(self, **options):
            observed.append(("context-options", options))
            return FakeContext()

        def close(self):
            return None

    observed = []

    class FakeManager:
        def __enter__(self):
            observed.append(
                ("driver-enter", os.environ.get(playwright_driver.OWNERSHIP_MARKER_NAME))
            )

            def launch(**kwargs):
                observed.append(("browser-env", kwargs["env"]))
                observed.append(("browser-executable", kwargs["executable_path"]))
                observed.append(("browser-args", kwargs["args"]))
                return FakeBrowser()

            return SimpleNamespace(chromium=SimpleNamespace(launch=launch))

        def __exit__(self, *_args):
            return None

    sync_api = ModuleType("playwright.sync_api")
    sync_api.Error = FakePlaywrightError  # type: ignore[attr-defined]
    sync_api.sync_playwright = FakeManager  # type: ignore[attr-defined]
    playwright = ModuleType("playwright")
    playwright.sync_api = sync_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setattr(
        acquisition_module,
        "validate_default_playwright_driver_once",
        lambda: observed.append(("validated", True)),
    )

    def launch_production(_playwright, *, approved_origins, origin_ip_pins):
        observed.append(
            (
                "browser-launch",
                tuple(approved_origins),
                dict(origin_ip_pins),
            )
        )
        return FakeBrowser(), {"launch_profile": "production-fail-closed"}

    monkeypatch.setattr(
        acquisition_module,
        "launch_production_browser",
        launch_production,
    )
    monkeypatch.setenv(playwright_driver.OWNERSHIP_MARKER_NAME, "1")

    response = acquisition_module.browser_document_content_type(
        "https://example.com/article",
        ("https://example.com",),
        1_000,
        {"https://example.com": "1.1.1.1"},
    )

    assert response.status == 200
    assert response.content_type == "text/html"
    assert observed == [
        ("validated", True),
        ("driver-enter", None),
        (
            "browser-launch",
            ("https://example.com",),
            {"https://example.com": "1.1.1.1"},
        ),
        (
            "context-options",
            {
                "ignore_https_errors": False,
                "java_script_enabled": False,
                "service_workers": "block",
            },
        ),
    ]
    assert os.environ[playwright_driver.OWNERSHIP_MARKER_NAME] == "1"


def test_content_type_probe_rejects_executable_override_before_driver_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sync_api = ModuleType("playwright.sync_api")
    sync_api.Error = RuntimeError  # type: ignore[attr-defined]

    def must_not_start():
        raise AssertionError("substituted executable reached the Playwright driver")

    sync_api.sync_playwright = must_not_start  # type: ignore[attr-defined]
    playwright = ModuleType("playwright")
    playwright.sync_api = sync_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setattr(
        acquisition_module,
        "validate_default_playwright_driver_once",
        lambda: {"test_fixture": True},
    )
    monkeypatch.setenv(
        playwright_driver.CHROMIUM_EXECUTABLE_ENVIRONMENT_VARIABLE,
        "/tmp/substituted-chromium",
    )

    with pytest.raises(ValueError, match="PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"):
        acquisition_module.browser_document_content_type(
            "https://example.com/article",
            ("https://example.com",),
            1_000,
            {"https://example.com": "1.1.1.1"},
        )


def test_public_origin_policy_pins_public_dns_and_rejects_private_answers(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        acquisition_module.socket,
        "getaddrinfo",
        lambda *_a, **_k: [(acquisition_module.socket.AF_INET, 1, 6, "", ("1.1.1.1", 443))],
    )
    assert public_origin_ip_pins(("https://example.com",)) == {"https://example.com": "1.1.1.1"}
    monkeypatch.setattr(
        acquisition_module.socket,
        "getaddrinfo",
        lambda *_a, **_k: [(acquisition_module.socket.AF_INET, 1, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(ValueError, match="rejected DNS"):
        public_origin_ip_pins(("https://example.com",))
    monkeypatch.setattr(
        acquisition_module.socket,
        "getaddrinfo",
        lambda *_a, **_k: [
            (acquisition_module.socket.AF_INET, 1, 6, "", ("1.1.1.1", 443)),
            (acquisition_module.socket.AF_INET, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(ValueError, match="rejected DNS"):
        public_origin_ip_pins(("https://example.com",))
    monkeypatch.setattr(
        acquisition_module.socket,
        "getaddrinfo",
        lambda *_a, **_k: [
            (
                acquisition_module.socket.AF_INET6,
                1,
                6,
                "",
                ("64:ff9b::c000:201", 443, 0, 0),
            )
        ],
    )
    with pytest.raises(ValueError, match="rejected DNS"):
        public_origin_ip_pins(("https://example.com",))
    with pytest.raises(ValueError, match="IP-literal"):
        public_origin_ip_pins(("https://127.0.0.1",))
    monkeypatch.setattr(
        acquisition_module.socket,
        "getaddrinfo",
        lambda *_a, **_k: (_ for _ in ()).throw(acquisition_module.socket.gaierror("DNS down")),
    )
    with pytest.raises(RecoverableAcquisitionError, match="DNS lookup failed"):
        public_origin_ip_pins(("https://example.com",))


def test_public_origin_policy_resolves_one_pin_per_chromium_hostname(
    monkeypatch: pytest.MonkeyPatch,
):
    calls = []

    def resolve(hostname, port, **_kwargs):
        calls.append((hostname, port))
        address = "1.1.1.1" if len(calls) == 1 else "8.8.8.8"
        return [(acquisition_module.socket.AF_INET, 1, 6, "", (address, port))]

    monkeypatch.setattr(acquisition_module.socket, "getaddrinfo", resolve)
    assert public_origin_ip_pins(("https://example.com", "https://example.com:8443")) == {
        "https://example.com": "1.1.1.1",
        "https://example.com:8443": "1.1.1.1",
    }
    assert calls == [("example.com", 443)]

    with pytest.raises(TerminalProbePolicyError, match="conflict for a shared hostname"):
        acquisition_module._validated_frozen_origin_ip_pins(
            ("https://example.com", "https://example.com:8443"),
            {
                "https://example.com": "1.1.1.1",
                "https://example.com:8443": "8.8.8.8",
            },
        )


def test_public_address_policy_matches_neqo_shared_golden_vectors() -> None:
    vectors = load_json(
        Path(__file__).resolve().parents[1]
        / "neqo-qcsd/neqo-bin/src/qcsd/public-address-policy-v1.json"
    )
    assert vectors["schema_version"] == 1
    assert vectors["policy"] == "qcsd-public-network-address-v1"
    assert all(_is_public_network_address(value) for value in vectors["accepted"])
    assert all(not _is_public_network_address(value) for value in vectors["rejected"])
    assert not _is_public_network_address("not-an-ip-address")


def test_navigation_verification_preserves_candidate_identity_and_rejects_redirects():
    candidate = PageCandidate(
        candidate_domain="example.com",
        registrable_domain="example.com",
        url="https://www.example.com/about",
        source="same-registrable-domain-link",
        ordinal=1,
        discovery_content_type="text/html",
    )
    assert (
        _verified_navigation_link(
            candidate,
            final_url=candidate.url,
            content_type="text/html; charset=utf-8",
            boundary="example.com",
        ).url
        == candidate.url
    )
    assert (
        _verified_navigation_link(
            candidate,
            final_url="https://evil.test/about",
            content_type="text/html",
            boundary="example.com",
        )
        is None
    )
    assert (
        _verified_navigation_link(
            candidate,
            final_url="https://www.example.com/about",
            content_type="application/pdf",
            boundary="example.com",
        )
        is None
    )
    redirected = _verified_navigation_link(
        candidate,
        final_url="https://shop.example.com/about",
        content_type="text/html",
        boundary="example.com",
    )
    assert redirected.url == candidate.url
    acquisition_module._validate_navigation_rejections(
        [
            {
                "url": candidate.url,
                "kind": "playwright-navigation-failure",
                "reason": "net::ERR_ABORTED",
            },
            {
                "url": candidate.url,
                "kind": "non-html-primary-response",
                "reason": "application/pdf",
            },
        ],
        boundary="example.com",
    )
    with pytest.raises(ValueError, match="violates its policy"):
        acquisition_module._validate_navigation_rejections(
            [
                {
                    "url": "https://example.com.evil.test/",
                    "kind": "playwright-navigation-failure",
                    "reason": "failure",
                }
            ],
            boundary="example.com",
        )


def test_transitive_bound_file_rejects_admitted_workload_tamper(tmp_path: Path):
    import hashlib

    workload = tmp_path / "class.json"
    workload.write_bytes(b"frozen workload")
    binding = {
        "path": str(workload),
        "sha256": hashlib.sha256(workload.read_bytes()).hexdigest(),
    }
    assert _verified_bound_file(binding, label="workload") == workload
    workload.write_bytes(b"substituted workload")
    with pytest.raises(ValueError, match="does not verify"):
        _verified_bound_file(binding, label="workload")


def test_admitted_workload_publish_rejects_missing_complete_coverage_before_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "prepared.json"
    source.write_text('{"fixture": true}\n', encoding="utf-8")
    destination = tmp_path / "published/class-001.json"
    checked = []

    def reject_missing_coverage(manifest, *, workload_id):
        checked.append((manifest, workload_id))
        raise ValueError("requires a complete-coverage admission")

    monkeypatch.setattr(
        acquisition_module,
        "validate_class_study_preparation",
        reject_missing_coverage,
    )

    with pytest.raises(ValueError, match="complete-coverage"):
        acquisition_module._publish_admitted_workload(
            source,
            destination,
            hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    assert checked == [({"fixture": True}, "class-001")]
    assert not destination.exists()


def test_admitted_workload_publication_recovers_only_exact_owned_temps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "prepared.json"
    source.write_text('{"fixture": true}\n', encoding="utf-8")
    destination = tmp_path / "published/class-001.json"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    monkeypatch.setattr(
        acquisition_module,
        "validate_class_study_preparation",
        lambda _manifest, *, workload_id: None,
    )
    original_create = acquisition_module.durable_create
    stale = destination.parent / (
        f".{destination.name}{acquisition_module.ATOMIC_TEMP_MARKER}interrupted"
    )

    def interrupted_create(path: Path, value: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        stale.write_bytes(value[:4])
        raise KeyboardInterrupt

    monkeypatch.setattr(acquisition_module, "durable_create", interrupted_create)
    with pytest.raises(KeyboardInterrupt):
        acquisition_module._publish_admitted_workload(source, destination, digest)
    assert stale.is_file()
    assert not destination.exists()

    monkeypatch.setattr(acquisition_module, "durable_create", original_create)
    acquisition_module._publish_admitted_workload(source, destination, digest)
    assert not stale.exists()
    assert destination.read_bytes() == source.read_bytes()

    postlink = destination.parent / (
        f".{destination.name}{acquisition_module.ATOMIC_TEMP_MARKER}postlink"
    )
    acquisition_module.os.link(destination, postlink)
    acquisition_module._publish_admitted_workload(source, destination, digest)
    assert not postlink.exists()
    assert destination.read_bytes() == source.read_bytes()

    unsafe = destination.parent / (
        f".{destination.name}{acquisition_module.ATOMIC_TEMP_MARKER}unsafe"
    )
    unsafe.symlink_to(source)
    with pytest.raises(ValueError, match="temporary path is unsafe"):
        acquisition_module._publish_admitted_workload(source, destination, digest)
    assert unsafe.is_symlink()

    stability_destination = tmp_path / "stability/class-001/page-00.json"
    stability_destination.parent.mkdir(parents=True)
    unsafe_stability_temp = stability_destination.parent / ".page-00.json.unsafe.qcsd-tmp"
    unsafe_stability_temp.mkdir()
    with pytest.raises(ValueError, match="temporary path is unsafe"):
        acquisition_module._discard_owned_publication_temps(
            stability_destination,
            style="create-only-json",
        )


def test_existing_backend_reads_list_shaped_primary_response_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    manifest = tmp_path / "probe.json"
    value = {
        "preparation": {
            "final_url": "https://example.com/",
            "chromium_version": "Chromium 1",
            "prepare_image_digest": acquisition_module.os.environ["QCSD_LAB_IMAGE_DIGEST"],
            "lab_source": acquisition_module.source_metadata(),
            "origin_ip_pins": {"https://example.com": "1.1.1.1"},
            "expected_responses": [
                {
                    "resource_id": 0,
                    "status": 200,
                    "bytes": 123,
                    "body_sha256": "a" * 64,
                }
            ],
            "neqo_version": "1",
            "neqo_base_commit": "2",
            "published_qcsd_commit": "3",
            "migration_commit": "4",
            "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
            "render_observation": {},
            "render_observation_sha256": "c" * 64,
            "discovery_event_audit_sha256": "d" * 64,
        }
    }
    manifest.write_text(__import__("json").dumps(value), encoding="utf-8")
    prepared = PreparedWorkload(manifest, hashlib.sha256(manifest.read_bytes()).hexdigest(), 1, 1)
    prepare_arguments = {}

    def fake_prepare(*_args, **kwargs):
        prepare_arguments.update(kwargs)
        return prepared

    monkeypatch.setattr(acquisition_module, "prepare_workload", fake_prepare)
    monkeypatch.setattr(
        acquisition_module, "validate_class_study_preparation", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        acquisition_module,
        "_prepared_replay_identity_sha256",
        lambda _manifest: "b" * 64,
    )
    monkeypatch.setattr(
        acquisition_module,
        "_prepared_primary_response",
        lambda candidate: candidate["preparation"]["expected_responses"][0],
    )
    monkeypatch.setattr(
        acquisition_module,
        "public_origin_ip_pins",
        lambda _origins: {"https://example.com": "1.1.1.1"},
    )
    probe = ExistingAcquisitionBackend(
        content_type_probe=lambda _url, _origins, _timeout, _pins: "text/html"
    ).prepare("workload", "https://example.com/", ["https://example.com"], tmp_path)
    assert (probe.status, probe.body_bytes, probe.body_sha256) == (200, 123, "a" * 64)
    assert prepare_arguments["stability_runs"] == 3


def _root_redirect_manifest() -> dict:
    start = "https://example.com/start"
    final = "https://example.com/final"
    value = _prepared_manifest(start, ["https://example.com"])
    preparation = value["preparation"]
    preparation["final_url"] = final
    preparation["expected_responses"][0].update(
        status=301,
        bytes=1,
        body_sha256="a" * 64,
    )
    root_source = preparation["discovery_event_audit"]["events"][0]["source"]
    initial_occurrence = "request-00000000"
    preparation["discovery_event_audit"]["events"] = preparation["discovery_event_audit"]["events"][
        :2
    ]
    value["resources"].append(
        {
            "id": 1,
            "url": final,
            "type": "Document",
            "depends_on": [0],
            "headers": [],
        }
    )
    preparation["expected_responses"].append(
        {
            "resource_id": 1,
            "status": 200,
            "bytes": 456,
            "body_sha256": "b" * 64,
        }
    )
    preparation["discovery_event_audit"]["events"].extend(
        [
            {
                "sequence": 3,
                "monotonic_ms": 0,
                "kind": "network-request",
                "source": root_source,
                "network_id": "network-0",
                "occurrence_id": "request-00000001",
                "occurrence_index": 1,
                "method": "GET",
                "url": final,
                "frame_id": None,
                "resource_type": "Document",
                "safe_request_headers": [],
                "interception_required": True,
                "redirected": True,
                "redirect_from_occurrence_id": initial_occurrence,
                "mapping": {"kind": "resource", "resource_id": 1},
                "dependency_evidence": [
                    {
                        "kind": "redirect",
                        "value": initial_occurrence,
                        "resolved_resource_id": 0,
                    }
                ],
                "resolved_dependency_resource_ids": [0],
            },
            {
                "sequence": 4,
                "monotonic_ms": 0,
                "kind": "fetch-request",
                "source": root_source,
                "fetch_id": "fetch-1",
                "network_id": "network-0",
                "redirected_fetch_id": "fetch-0",
                "network_occurrence_id": "request-00000001",
                "method": "GET",
                "url": final,
                "frame_id": None,
                "policy_decision": "continue",
                "policy_reason": None,
                "relationship": "primary",
            },
            {
                "sequence": 5,
                "monotonic_ms": 0,
                "kind": "network-terminal",
                "source": root_source,
                "network_id": "network-0",
                "outcome": "finished",
                "network_occurrence_ids": [
                    initial_occurrence,
                    "request-00000001",
                ],
            },
        ]
    )
    return value


def test_prepared_primary_response_follows_exact_root_redirect_chain():
    manifest = _root_redirect_manifest()
    assert acquisition_module._prepared_primary_response(manifest) == {
        "resource_id": 1,
        "status": 200,
        "bytes": 456,
        "body_sha256": "b" * 64,
    }

    # A same-URL subframe Document is not the primary merely because its URL
    # and media type resemble the final top-level response.
    manifest["resources"].append(
        {
            "id": 2,
            "url": "https://example.com/final",
            "type": "Document",
            "depends_on": [1],
            "headers": [],
        }
    )
    subframe = copy.deepcopy(manifest["preparation"]["discovery_event_audit"]["events"][2])
    subframe["source"] = {
        "session_path": ["iframe-session"],
        "target_id": "iframe-target",
        "target_type": "iframe",
        "generation": 0,
        "parent_session_path": [],
        "parent_frame_id": "frame-1",
    }
    subframe["network_id"] = "subframe-network"
    subframe["occurrence_id"] = "request-00000002"
    subframe["occurrence_index"] = 0
    subframe["redirected"] = False
    subframe["redirect_from_occurrence_id"] = None
    subframe["mapping"] = {"kind": "resource", "resource_id": 2}
    manifest["preparation"]["discovery_event_audit"]["events"].append(subframe)
    manifest["preparation"]["expected_responses"].append(
        {
            "resource_id": 2,
            "status": 418,
            "bytes": 999,
            "body_sha256": "c" * 64,
        }
    )
    assert acquisition_module._prepared_primary_response(manifest)["resource_id"] == 1


def test_prepared_primary_response_rejects_a_forked_root_redirect_chain():
    manifest = _root_redirect_manifest()
    fork = copy.deepcopy(manifest["preparation"]["discovery_event_audit"]["events"][2])
    fork["occurrence_id"] = "request-00000002"
    fork["mapping"] = {"kind": "resource", "resource_id": 2}
    manifest["resources"].append(
        {
            "id": 2,
            "url": "https://example.com/other",
            "type": "Document",
            "depends_on": [0],
            "headers": [],
        }
    )
    manifest["preparation"]["discovery_event_audit"]["events"].append(fork)
    with pytest.raises(TerminalProbePolicyError, match="redirect chain is ambiguous"):
        acquisition_module._prepared_primary_response(manifest)


def test_existing_backend_never_recovers_a_fixed_id_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    (tmp_path / "workload.json").write_text("{}\n", encoding="utf-8")
    called = False

    def create_only_prepare(*_args, **_kwargs):
        nonlocal called
        called = True
        raise FileExistsError("create-only preparer rejected the stale ID")

    monkeypatch.setattr(acquisition_module, "prepare_workload", create_only_prepare)
    monkeypatch.setattr(
        acquisition_module,
        "public_origin_ip_pins",
        lambda _origins: {"https://example.com": "1.1.1.1"},
    )
    with pytest.raises(FileExistsError, match="create-only preparer rejected"):
        ExistingAcquisitionBackend().prepare(
            "workload", "https://example.com/", ["https://example.com"], tmp_path
        )
    assert called


def test_origin_convergence_can_start_from_verified_navigation_redirect_origins():
    class RedirectBackend:
        def discover(self, url, approved_origins):
            if "https://www.example.com" not in approved_origins:
                raise ValueError("redirect origin was not pre-approved")
            return DiscoveryResult(
                source_url=url,
                final_url="https://www.example.com/",
                chromium_version="test",
                settle_ms=0,
                observed_request_count=2,
                observed_origins=list(approved_origins),
                approved_origins=list(approved_origins),
                exclusions=[],
                resources=[{"id": 0}],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=list(approved_origins),
            )

    approved, result = _converge_origins(
        RedirectBackend(),
        "https://example.com/",
        seed_origins=("https://www.example.com",),
    )
    assert approved == ["https://example.com", "https://www.example.com"]
    assert result.final_url == "https://www.example.com/"


def _two_navigation_pages() -> tuple[PageCandidate, PageCandidate]:
    return (
        PageCandidate(
            candidate_domain="example.com",
            registrable_domain="example.com",
            url="https://example.com/",
            source="canonical-homepage",
            ordinal=0,
            discovery_content_type=None,
        ),
        PageCandidate(
            candidate_domain="example.com",
            registrable_domain="example.com",
            url="https://example.com/about",
            source="same-registrable-domain-link",
            ordinal=1,
            discovery_content_type="text/html",
        ),
    )


@pytest.mark.parametrize(
    ("page_ledger", "message"),
    [
        ((), "is required"),
        (
            (("https://example.com/", ("https://example.com",)),),
            "is incomplete",
        ),
    ],
)
def test_navigation_origin_ledger_rejects_absence_or_incomplete_page_evidence(
    page_ledger, message: str
) -> None:
    navigation = NavigationDiscovery(
        registrable_domain="example.com",
        links=(),
        observed_origins=("https://about.example", "https://example.com"),
        page_observed_origins=page_ledger,
    )

    with pytest.raises(ValueError, match=message):
        acquisition_module._navigation_origins_by_page(
            navigation,
            _two_navigation_pages(),
        )


def test_navigation_origin_ledger_rejects_unbound_page_origin_leakage() -> None:
    navigation = NavigationDiscovery(
        registrable_domain="example.com",
        links=(),
        observed_origins=("https://example.com",),
        page_observed_origins=(
            (
                "https://example.com/",
                ("https://example.com", "https://leaked.example"),
            ),
            ("https://example.com/about", ("https://example.com",)),
        ),
    )

    with pytest.raises(ValueError, match="exceed the global ledger"):
        acquisition_module._navigation_origins_by_page(
            navigation,
            _two_navigation_pages(),
        )


def test_each_page_uses_only_its_own_navigation_origin_seeds(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    baseline = datetime(2026, 8, 28, tzinfo=UTC)

    class PageSpecificBackend:
        def __init__(self):
            self.first_approved: dict[str, tuple[str, ...]] = {}
            self.domain = ""

        def discover_navigation(self, domain):
            self.domain = domain
            homepage = f"https://{domain}/"
            about = f"https://{domain}/about"
            news = f"https://{domain}/news"
            page_origins = {
                homepage: (f"https://home-assets.{domain}",),
                about: (f"https://about-assets.{domain}",),
                news: (f"https://news-assets.{domain}",),
            }
            return NavigationDiscovery(
                registrable_domain=domain,
                links=(
                    acquisition_module.DiscoveredLink(about, "text/html"),
                    acquisition_module.DiscoveredLink(news, "text/html"),
                ),
                observed_origins=tuple(
                    sorted(origin for values in page_origins.values() for origin in values)
                ),
                page_observed_origins=tuple(sorted(page_origins.items())),
            )

        def discover(self, url, approved_origins):
            self.first_approved.setdefault(url, tuple(sorted(approved_origins)))
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(approved_origins),
                observed_origins=list(approved_origins),
                approved_origins=list(approved_origins),
                exclusions=[],
                resources=[{"id": 0, "url": url}],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=list(approved_origins),
            )

        def prepare(self, workload_id, url, approved_origins, output_root, *, origin_ip_pins=None):
            output_root.mkdir(parents=True, exist_ok=True)
            path = output_root / f"{workload_id}.json"
            manifest = _prepared_manifest(url, approved_origins)
            path.write_bytes(canonical_json_bytes(manifest))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            return PreparedProbe(
                observed_at="2026-08-28T00:00:55Z",
                final_url=url,
                status=200,
                content_type="text/html",
                body_bytes=100,
                body_sha256=f"{1:064x}",
                resource_graph_sha256=_prepared_replay_identity_sha256(manifest),
                prepared=PreparedWorkload(path, digest, 1, 1),
                chromium_version="test-chromium",
                neqo_provenance={
                    "neqo_version": "test-neqo",
                    "neqo_base_commit": "4" * 40,
                    "published_qcsd_commit": "5" * 40,
                    "migration_commit": "6" * 40,
                },
                passive_render_contract_sha256=(
                    manifest["preparation"]["passive_render_contract_sha256"]
                ),
                render_observation=manifest["preparation"]["render_observation"],
                render_observation_sha256=(manifest["preparation"]["render_observation_sha256"]),
                discovery_event_audit_sha256=(
                    manifest["preparation"]["discovery_event_audit_sha256"]
                ),
                preparation_origin_ip_pins=dict(origin_ip_pins or {}),
                document_response_chromium_version="test-chromium",
            )

    backend = PageSpecificBackend()
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "max_candidates": 1,
    }
    run_due_acquisition(runner, now=baseline, **arguments)
    run_due_acquisition(runner, now=baseline + timedelta(seconds=30), **arguments)

    root_origin = f"https://{backend.domain}"
    assert backend.first_approved == {
        f"{root_origin}/": tuple(sorted((root_origin, f"https://home-assets.{backend.domain}"))),
        f"{root_origin}/about": tuple(
            sorted((root_origin, f"https://about-assets.{backend.domain}"))
        ),
        f"{root_origin}/news": tuple(
            sorted((root_origin, f"https://news-assets.{backend.domain}"))
        ),
    }


def test_origin_convergence_admits_discovered_cross_origin_resources():
    calls: list[tuple[str, ...]] = []

    class MultiOriginBackend:
        def discover(self, url, approved_origins):
            approved = tuple(sorted(approved_origins))
            calls.append(approved)
            observed = {"https://page.example"}
            if "https://cdn.example" not in approved:
                observed.add("https://cdn.example")
            elif "https://fonts.example" not in approved:
                observed.update(("https://cdn.example", "https://fonts.example"))
            else:
                observed.update(("https://cdn.example", "https://fonts.example"))
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(observed),
                observed_origins=sorted(observed),
                approved_origins=list(approved),
                exclusions=[],
                resources=[
                    {"id": index, "url": f"{value}/resource-{index}"}
                    for index, value in enumerate(sorted(observed))
                    if value in approved
                ],
                origin_ip_pins={value: "1.1.1.1" for value in approved},
                expandable_origins=sorted(observed),
            )

    approved, result = _converge_origins(
        MultiOriginBackend(),
        "https://page.example/",
    )

    assert calls == [
        ("https://page.example",),
        ("https://cdn.example", "https://page.example"),
        (
            "https://cdn.example",
            "https://fonts.example",
            "https://page.example",
        ),
    ]
    assert approved == [
        "https://cdn.example",
        "https://fonts.example",
        "https://page.example",
    ]
    assert {resource["url"].split("/resource-")[0] for resource in result.resources} == set(
        approved
    )


def test_origin_convergence_does_not_promote_a_post_only_origin():
    class PostObservingBackend:
        def discover(self, url, approved_origins):
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=2,
                observed_origins=[
                    "https://page.example",
                    "https://telemetry.example",
                ],
                approved_origins=list(approved_origins),
                exclusions=[
                    {
                        "url": "https://telemetry.example/report",
                        "reason": "unsafe method: POST",
                    }
                ],
                resources=[{"id": 0, "url": "https://page.example/"}],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=["https://page.example"],
            )

    approved, result = _converge_origins(
        PostObservingBackend(),
        "https://page.example/",
    )
    assert approved == ["https://page.example"]
    assert result.observed_origins == [
        "https://page.example",
        "https://telemetry.example",
    ]


def test_origin_convergence_rejects_absent_get_ledger_without_promoting_post_origin():
    class MissingExpansionLedgerBackend:
        def discover(self, url, approved_origins):
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=2,
                observed_origins=[
                    "https://page.example",
                    "https://telemetry.example",
                ],
                approved_origins=list(approved_origins),
                exclusions=[
                    {
                        "url": "https://telemetry.example/report",
                        "reason": "unsafe method: POST",
                    }
                ],
                resources=[{"id": 0, "url": "https://page.example/"}],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=None,
            )

    with pytest.raises(ValueError, match="omitted its HTTPS-GET-only"):
        _converge_origins(
            MissingExpansionLedgerBackend(),
            "https://page.example/",
        )


def test_origin_convergence_typed_rejects_33_get_origins_instead_of_truncating():
    class OverCapBackend:
        def discover(self, url, approved_origins):
            observed = ["https://page.example"] + [
                f"https://cdn-{index:02d}.example" for index in range(32)
            ]
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(observed),
                observed_origins=observed,
                approved_origins=list(approved_origins),
                exclusions=[],
                resources=[
                    {"id": 0, "url": "https://page.example/"},
                ],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=sorted(observed),
            )

    with pytest.raises(TerminalProbePolicyError, match="exceeded its finite origin cap"):
        _converge_origins(OverCapBackend(), "https://page.example/")


def test_origin_convergence_typed_rejects_513_non_get_audit_origins() -> None:
    class AuditCapBackend:
        def discover(self, url, approved_origins):
            observed = ["https://page.example"] + [
                f"https://telemetry-{index:03d}.example" for index in range(512)
            ]
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(observed),
                observed_origins=sorted(observed),
                approved_origins=list(approved_origins),
                exclusions=[
                    {
                        "url": f"{value}/report",
                        "reason": "unsafe method: POST",
                    }
                    for value in observed[1:]
                ],
                resources=[{"id": 0, "url": "https://page.example/"}],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=["https://page.example"],
            )

    with pytest.raises(TerminalProbePolicyError, match="observed-origin audit cap"):
        _converge_origins(AuditCapBackend(), "https://page.example/")


def test_origin_convergence_accepts_exactly_the_finite_origin_cap():
    expected_origins = ["https://page.example"] + [
        f"https://cdn-{index:02d}.example" for index in range(MAX_APPROVED_ORIGINS - 1)
    ]
    calls: list[tuple[str, ...]] = []

    class ExactCapBackend:
        def discover(self, url, approved_origins):
            approved = tuple(sorted(approved_origins))
            calls.append(approved)
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(expected_origins),
                observed_origins=sorted(expected_origins),
                approved_origins=list(approved),
                exclusions=[],
                resources=[
                    {"id": index, "url": f"{value}/resource-{index}"}
                    for index, value in enumerate(approved)
                ],
                origin_ip_pins={value: "1.1.1.1" for value in approved},
                expandable_origins=sorted(expected_origins),
            )

    approved, result = _converge_origins(
        ExactCapBackend(),
        "https://page.example/",
    )

    assert len(approved) == MAX_APPROVED_ORIGINS
    assert approved == sorted(expected_origins)
    assert len(calls) == 2
    assert {resource["url"].split("/resource-")[0] for resource in result.resources} == set(
        approved
    )


def test_origin_convergence_accepts_a_graph_settling_on_the_eighth_pass():
    calls: list[tuple[str, ...]] = []

    class EighthPassBackend:
        def discover(self, url, approved_origins):
            approved = tuple(sorted(approved_origins))
            calls.append(approved)
            observed = set(approved)
            if len(calls) < MAX_ORIGIN_PASSES:
                observed.add(f"https://cdn-{len(calls):02d}.example")
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(observed),
                observed_origins=sorted(observed),
                approved_origins=list(approved),
                exclusions=[],
                resources=[
                    {"id": index, "url": f"{value}/resource-{index}"}
                    for index, value in enumerate(approved)
                ],
                origin_ip_pins={value: "1.1.1.1" for value in approved},
                expandable_origins=sorted(observed),
            )

    approved, result = _converge_origins(
        EighthPassBackend(),
        "https://page.example/",
    )

    assert len(calls) == MAX_ORIGIN_PASSES
    assert len(approved) == MAX_ORIGIN_PASSES
    assert tuple(result.approved_origins) == calls[-1]
    assert result.expandable_origins == approved


def test_origin_convergence_rejects_instead_of_sealing_an_unsettled_graph():
    class NeverSettlesBackend:
        def discover(self, url, approved_origins):
            observed = [*approved_origins, f"https://cdn-{len(approved_origins):02d}.example"]
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(observed),
                observed_origins=observed,
                approved_origins=list(approved_origins),
                exclusions=[],
                resources=[
                    {"id": 0, "url": "https://page.example/"},
                ],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=sorted(observed),
            )

    with pytest.raises(TerminalProbePolicyError, match="did not converge within its pass cap"):
        _converge_origins(NeverSettlesBackend(), "https://page.example/")


def test_completion_provenance_retains_each_probe_origin_set():
    def declared_schema_two_observation(
        *,
        approved_origins: list[str],
        discovered_origins: list[str],
        pin: str,
        observed_at: str,
        completed_at: str,
    ) -> dict[str, object]:
        return {
            "runner_provenance_sha256": "b" * 64,
            "approved_origins": approved_origins,
            "discovery_observed_origins": discovered_origins,
            "discovery_expandable_origins": approved_origins,
            "discovery_origin_ip_pins": {approved_origins[0]: pin},
            "discovery_instrumentation_policy": (
                acquisition_module._SCHEMA_THREE_FOUR_CDP_TARGET_INSTRUMENTATION_POLICY
            ),
            "chromium_version": "Chromium 1",
            "neqo_provenance": {"neqo_version": "1"},
            "observed_at": observed_at,
            "probe_completed_at": completed_at,
        }

    states = {
        "class-000": {
            "terminal": {"path": "terminals/class-000.json", "sha256": "a" * 64},
            "pages": [
                {
                    "approved_origins": ["https://second.example"],
                    "observations": [
                        declared_schema_two_observation(
                            approved_origins=["https://first.example"],
                            discovered_origins=[
                                "https://first.example",
                                "https://telemetry.example",
                            ],
                            pin="1.1.1.1",
                            observed_at="2026-08-28T00:00:30Z",
                            completed_at="2026-08-28T00:00:31Z",
                        ),
                        declared_schema_two_observation(
                            approved_origins=["https://second.example"],
                            discovered_origins=["https://second.example"],
                            pin="8.8.8.8",
                            observed_at="2026-08-29T00:00:30Z",
                            completed_at="2026-08-29T00:00:31Z",
                        ),
                    ],
                }
            ],
        }
    }
    assert set(states["class-000"]["pages"][0]["observations"][0]) != (
        acquisition_module.CURRENT_OBSERVATION_FIELDS
    )
    assert acquisition_module._validate_observation_provenance(
        states,
        provenance_sha256="b" * 64,
        runner_provenance={
            "acquisition_schema_version": 2,
            "image_digest": "sha256:test",
            "source": {"commit": "1"},
        },
    ) == {
        "chromium_version": "Chromium 1",
        "neqo_provenance": {"neqo_version": "1"},
        "image_digest": "sha256:test",
        "source": {"commit": "1"},
    }
    translation_checkpoint = copy.deepcopy(states)
    translation_checkpoint["class-000"]["pages"][0]["observations"][0]["discovery_origin_ip_pins"][
        "https://first.example"
    ] = "64:ff9b::c000:201"
    with pytest.raises(ValueError, match="checkpoint observation provenance"):
        acquisition_module._validate_observation_provenance(
            translation_checkpoint,
            provenance_sha256="b" * 64,
            runner_provenance={
                "acquisition_schema_version": 2,
                "image_digest": "sha256:test",
                "source": {"commit": "1"},
            },
        )
    instrumentation_checkpoint = copy.deepcopy(states)
    instrumentation_checkpoint["class-000"]["pages"][0]["observations"][0][
        "discovery_instrumentation_policy"
    ] = "unreceipted-root-only-cdp"
    with pytest.raises(ValueError, match="checkpoint observation provenance"):
        acquisition_module._validate_observation_provenance(
            instrumentation_checkpoint,
            provenance_sha256="b" * 64,
            runner_provenance={
                "acquisition_schema_version": 2,
                "image_digest": "sha256:test",
                "source": {"commit": "1"},
            },
        )
    missing_instrumentation_checkpoint = copy.deepcopy(states)
    missing_instrumentation_checkpoint["class-000"]["pages"][0]["observations"][0].pop(
        "discovery_instrumentation_policy"
    )
    with pytest.raises(ValueError, match="checkpoint observation"):
        acquisition_module._validate_observation_provenance(
            missing_instrumentation_checkpoint,
            provenance_sha256="b" * 64,
            runner_provenance={
                "acquisition_schema_version": 2,
                "image_digest": "sha256:test",
                "source": {"commit": "1"},
            },
        )


def test_current_observation_provenance_is_reconstructed_from_preparation_and_response(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = SlowBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
        "max_candidates": 1,
    }
    run_due_acquisition(runner, **arguments)
    clock.value = datetime(2026, 8, 28, 0, 0, 40, tzinfo=UTC)
    run_due_acquisition(runner, **arguments)

    checkpoint = load_json(runner / "checkpoint.json")
    states = checkpoint["payload"]["candidates"]
    candidate_id = next(
        candidate_id
        for candidate_id, state in states.items()
        if state["state"] == "probing" and state["pages"][0]["observations"]
    )
    states[candidate_id]["terminal"] = {"test-only": True}
    provenance_path = runner / "provenance.json"
    provenance = acquisition_module.validate_hash_bound_receipt(
        load_json(provenance_path), expected_type=acquisition_module.PROVENANCE_TYPE
    )

    def validate(candidate_states):
        return acquisition_module._validate_observation_provenance(
            candidate_states,
            provenance_sha256=acquisition_module.sha256_file(provenance_path),
            runner_provenance=provenance,
            runner_root=runner,
        )

    assert validate(states)["chromium_version"] == "test-chromium"

    def observation(candidate_states):
        return candidate_states[candidate_id]["pages"][0]["observations"][0]

    mutations = {
        "final-url": lambda item: item.__setitem__("final_url", "https://forged.example/"),
        "status": lambda item: item.__setitem__("status", 201),
        "body-bytes": lambda item: item.__setitem__("body_bytes", 101),
        "body-sha": lambda item: item.__setitem__("body_sha256", "f" * 64),
        "resource-graph": lambda item: item.__setitem__("resource_graph_sha256", "e" * 64),
        "approved-origins": lambda item: item.__setitem__(
            "approved_origins", ["https://forged.example"]
        ),
        "preparation-pins": lambda item: item.__setitem__(
            "preparation_origin_ip_pins",
            {item["approved_origins"][0]: "8.8.8.8"},
        ),
        "chromium": lambda item: item.__setitem__("chromium_version", "forged"),
        "neqo": lambda item: item["neqo_provenance"].__setitem__("neqo_version", "forged"),
        "content-type": lambda item: item.__setitem__("content_type", "application/xhtml+xml"),
        "response-receipt": lambda item: item.__setitem__(
            "document_response_receipt_sha256", "0" * 64
        ),
        "unknown-field": lambda item: item.__setitem__(
            "forged_metadata", {"payload_leak": "unbound"}
        ),
        "noncanonical-prepared-path": lambda item: item.__setitem__(
            "prepared_path",
            str(
                Path(item["prepared_path"]).parent
                / ".."
                / "prepared-probes"
                / Path(item["prepared_path"]).name
            ),
        ),
    }
    for label, mutate in mutations.items():
        forged = copy.deepcopy(states)
        mutate(observation(forged))
        with pytest.raises(ValueError, match="checkpoint"):
            validate(forged)

    forged = copy.deepcopy(states)
    forged_observation = observation(forged)
    prepared_path = Path(forged_observation["prepared_path"])
    response_path = runner / forged_observation["document_response_receipt_path"]
    original_prepared = prepared_path.read_bytes()
    original_response = response_path.read_bytes()
    try:
        prepared_manifest = load_json(prepared_path)
        prepared_manifest["preparation"]["lab_source"]["lab_commit"] = "7" * 40
        prepared_path.write_bytes(canonical_json_bytes(prepared_manifest))
        forged_observation["prepared_workload_sha256"] = hashlib.sha256(
            prepared_path.read_bytes()
        ).hexdigest()
        response_payload = load_json(response_path)["payload"]
        response_payload["prepared_workload_sha256"] = forged_observation[
            "prepared_workload_sha256"
        ]
        response_path.write_bytes(
            canonical_json_bytes(
                bind_receipt(
                    response_payload,
                    receipt_type=acquisition_module.DOCUMENT_RESPONSE_RECEIPT_TYPE,
                )
            )
        )
        forged_observation["document_response_receipt_sha256"] = hashlib.sha256(
            response_path.read_bytes()
        ).hexdigest()
        with pytest.raises(ValueError, match="prepared discovery evidence"):
            validate(forged)
    finally:
        prepared_path.write_bytes(original_prepared)
        response_path.write_bytes(original_response)

    prepared_root = runner / "prepared-probes"
    escaped_root = runner / "escaped-prepared-probes"
    prepared_root.rename(escaped_root)
    prepared_root.symlink_to(escaped_root, target_is_directory=True)
    with pytest.raises(ValueError, match="prepared-probe root"):
        validate(states)


def test_existing_backend_applies_the_bounded_timeout_to_navigation(
    monkeypatch: pytest.MonkeyPatch,
):
    observed = {}

    def fake_navigation(domain: str, *, timeout_ms: int):
        observed.update(domain=domain, timeout_ms=timeout_ms)
        return _homepage_navigation(domain)

    monkeypatch.setattr(acquisition_module, "catalogue_boundary_navigation", fake_navigation)
    result = ExistingAcquisitionBackend(timeout_ms=12_345).discover_navigation("example.com")
    assert result.registrable_domain == "example.com"
    assert observed == {"domain": "example.com", "timeout_ms": 12_345}


def test_replay_identity_excludes_per_run_preparation_evidence(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        acquisition_module,
        "runtime_manifest",
        lambda _manifest: {"resources": [{"id": 0, "url": "https://example.com/"}]},
    )
    preparation = {
        "source_url": "https://example.com/",
        "final_url": "https://www.example.com/",
        "approved_origins": ["https://example.com"],
        "origin_ip_pins": {"https://example.com": "1.1.1.1"},
        "browser_request_headers": [{"resource_id": 0, "headers": []}],
        "request_header_transformation": ("browser-safe-input-to-neqo-stability-frozen-runtime-v1"),
        "expected_responses": [
            {
                "resource_id": 0,
                "status": 200,
                "bytes": 123,
                "body_sha256": "a" * 64,
            }
        ],
        "udp_payload_qualification": {"runs": [{"packets_sha256": "1" * 64}]},
    }
    first = {"preparation": preparation, "resources": []}
    expected_identity = {
        "schema_version": 3,
        "source_url": preparation["source_url"],
        "final_url": preparation["final_url"],
        "approved_origins": preparation["approved_origins"],
        "origin_ip_pins": preparation["origin_ip_pins"],
        "browser_request_headers": preparation["browser_request_headers"],
        "request_header_transformation": preparation["request_header_transformation"],
        "expected_responses": preparation["expected_responses"],
        "passive_render_contract_sha256": None,
        "runtime_manifest": {"resources": [{"id": 0, "url": "https://example.com/"}]},
    }
    assert (
        _prepared_replay_identity_sha256(first)
        == hashlib.sha256(canonical_json_bytes(expected_identity)).hexdigest()
    )
    second = copy.deepcopy(first)
    second["preparation"]["udp_payload_qualification"]["runs"][0]["packets_sha256"] = "2" * 64
    assert _prepared_replay_identity_sha256(first) == _prepared_replay_identity_sha256(second)
    second["preparation"]["expected_responses"][0]["body_sha256"] = "b" * 64
    assert _prepared_replay_identity_sha256(first) != _prepared_replay_identity_sha256(second)
    for field, replacement in (
        ("origin_ip_pins", {"https://example.com": "8.8.8.8"}),
        (
            "browser_request_headers",
            [{"resource_id": 0, "headers": [["accept", "text/html"]]}],
        ),
        ("request_header_transformation", "forged-transformation"),
    ):
        changed = copy.deepcopy(first)
        changed["preparation"][field] = replacement
        assert _prepared_replay_identity_sha256(first) != _prepared_replay_identity_sha256(changed)


def _prefix_selection_runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Full catalogue/selection/closure fixture; terminal science is a separate unit."""
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="ignored",
    )
    checkpoint = load_json(runner / "checkpoint.json")["payload"]
    selection = acquisition_status(runner, candidate_catalogue_path=catalogue)["selection"]
    for candidate_id in selection["admission_ids"]:
        terminal_path = runner / "terminals" / f"{candidate_id}.json"
        terminal_path.write_bytes(
            canonical_json_bytes(
                bind_receipt(
                    {
                        "candidate_id": candidate_id,
                        "kind": "eligible",
                        "terminalised_at": "2026-08-31T00:00:00Z",
                    },
                    receipt_type=acquisition_module.TERMINAL_TYPE,
                )
            )
        )
        checkpoint["candidates"][candidate_id] = {
            "state": "terminal",
            "pages": [],
            "terminal": {
                "path": f"terminals/{candidate_id}.json",
                "sha256": acquisition_module.sha256_file(terminal_path),
            },
        }
    _replace_receipt_payload(runner / "checkpoint.json", checkpoint)

    def admitted_terminal_binding(path, *, candidate, **_kwargs):
        # The fixture supplies already-admitted eligibility; leave receipt
        # hashes, catalogue inventory, policy, chronology and closure real.
        payload = acquisition_module.validate_hash_bound_receipt(
            load_json(path),
            expected_type=acquisition_module.TERMINAL_TYPE,
        )
        assert payload["candidate_id"] == candidate.candidate_id
        return {
            "path": f"terminals/{candidate.candidate_id}.json",
            "sha256": acquisition_module.sha256_file(path),
        }

    monkeypatch.setattr(
        acquisition_module, "_validated_terminal_binding", admitted_terminal_binding
    )
    return runner, catalogue


def test_schema_seven_completion_preserves_unassessed_tail_and_seals_exact_prefix(
    tmp_path, monkeypatch
):
    runner, catalogue = _prefix_selection_runner(tmp_path, monkeypatch)
    checkpoint_before = (runner / "checkpoint.json").read_bytes()
    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert status["complete"] is True
    assert status["terminal_count"] == 120
    assert status["pending_count"] == 0 and status["work_due_now"] is False
    assert len(status["selection"]["candidate_ids"]) == 600
    assert len(status["selection"]["unassessed_ids"]) == 480
    completion = load_json(write_acquisition_completion(runner, candidate_catalogue_path=catalogue))
    payload = validate_acquisition_completion(
        completion, candidate_catalogue_path=catalogue, runner_root=runner
    )
    assert payload["completion_schema_version"] == acquisition_module.COMPLETION_SCHEMA_VERSION
    selection = acquisition_module.validate_hash_bound_receipt(
        payload["selection"],
        expected_type=acquisition_module.SELECTION_TYPE,
    )
    assert selection == status["selection"]
    assert set(payload["terminal_receipts"]) == set(selection["terminal_ids"])
    assert not set(payload["terminal_receipts"]).intersection(selection["unassessed_ids"])
    assert (runner / "checkpoint.json").read_bytes() == checkpoint_before
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=NoNetworkBackend(),
    )
    assert (runner / "checkpoint.json").read_bytes() == checkpoint_before
    for key in ("pilot_ids", "unassessed_ids", "prefix_ids"):
        changed = copy.deepcopy(payload)
        inventory = changed["selection"]["payload"]
        inventory[key] = inventory[key][1:]
        changed["selection"] = bind_receipt(
            inventory, receipt_type=acquisition_module.SELECTION_TYPE
        )
        with pytest.raises(ValueError, match="selection prefix"):
            validate_acquisition_completion(
                bind_receipt(changed, receipt_type=COMPLETION_TYPE),
                candidate_catalogue_path=catalogue,
                runner_root=runner,
            )


def test_schema_seven_completion_blocks_earlier_unresolved(tmp_path, monkeypatch):
    runner, catalogue = _prefix_selection_runner(tmp_path, monkeypatch)
    checkpoint = load_json(runner / "checkpoint.json")["payload"]
    selected_id = acquisition_status(runner, candidate_catalogue_path=catalogue)["selection"][
        "pilot_ids"
    ][0]
    checkpoint["candidates"][selected_id] = {"state": "pending", "pages": [], "terminal": None}
    (runner / "terminals" / f"{selected_id}.json").unlink()
    _replace_receipt_payload(runner / "checkpoint.json", checkpoint)
    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert status["complete"] is False
    assert selected_id in status["selection"]["needed_ids"]
    assert status["selection"]["pilot_ids"] == []
    with pytest.raises(ValueError, match="resolved deterministic prefix"):
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)


def test_schema_seven_started_tail_must_drain_before_completion(tmp_path, monkeypatch):
    runner, catalogue = _prefix_selection_runner(tmp_path, monkeypatch)
    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    tail_id = status["selection"]["unassessed_ids"][0]
    checkpoint = load_json(runner / "checkpoint.json")["payload"]
    checkpoint["candidates"][tail_id]["navigation_attempts"] = [
        {
            "attempt": 1,
            "started_at": "2026-08-31T00:00:00Z",
            "completed_at": "2026-08-31T00:00:01Z",
            "outcome": "interrupted",
            "reason": "fixture interruption",
            "policy_evidence": None,
        }
    ]
    _replace_receipt_payload(runner / "checkpoint.json", checkpoint)
    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert status["selection"]["complete"] is True and status["complete"] is False
    assert status["pending_count"] == 1 and status["work_due_now"] is True
    with pytest.raises(ValueError, match="resolved deterministic prefix"):
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)


def test_schema_seven_missed_terminal_blocks_without_advancing_frontier(tmp_path, monkeypatch):
    runner, catalogue = _prefix_selection_runner(tmp_path, monkeypatch)
    initial = acquisition_status(runner, candidate_catalogue_path=catalogue)
    candidate_id = initial["selection"]["pilot_ids"][0]
    checkpoint = load_json(runner / "checkpoint.json")["payload"]
    binding = checkpoint["candidates"][candidate_id]["terminal"]
    terminal_path = runner / binding["path"]
    terminal = load_json(terminal_path)["payload"]
    terminal["kind"] = "probe-window-missed"
    _replace_receipt_payload(terminal_path, terminal)
    binding["sha256"] = acquisition_module.sha256_file(terminal_path)
    _replace_receipt_payload(runner / "checkpoint.json", checkpoint)
    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert status["complete"] is False
    assert status["selection_blocked_candidate_ids"] == [candidate_id]
    assert candidate_id in status["selection"]["admission_ids"]
    assert status["pending_count"] == 0 and status["work_due_now"] is False
    assert status["selection"]["pilot_ids"] == []
    with pytest.raises(ValueError, match="resolved deterministic prefix"):
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)


def test_batch_reservation_releases_only_after_all_scientific_terminals():
    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    batches = [
        {
            "baseline_started_at": acquisition_module._format_time(baseline),
            "candidate_ids": ["a", "b"],
        }
    ]
    states = {"a": {"pages": []}, "b": {"pages": []}}
    terminals = {
        "a": {"kind": "stable-page-unavailable", "terminalised_at": "2026-08-28T00:00:30Z"}
    }
    assert (
        acquisition_module._baseline_batch_reservations(batches, states, terminals)[0].released_at
        is None
    )
    terminals["b"] = {"kind": "eligible", "terminalised_at": "2026-08-28T00:00:40Z"}
    reservation = acquisition_module._baseline_batch_reservations(batches, states, terminals)[0]
    assert reservation.released_at == baseline + timedelta(minutes=40, seconds=40)
    terminals["b"]["kind"] = "probe-window-missed"
    assert (
        acquisition_module._baseline_batch_reservations(batches, states, terminals)[0].released_at
        is None
    )


@pytest.mark.parametrize(
    "kind,state,expected",
    [
        ("eligible", {"pages": []}, True),
        ("stable-page-unavailable", {"pages": []}, False),
        (
            "pre-probe-rejection",
            {"navigation_attempts": [{"outcome": "terminal-policy-rejection"}]},
            False,
        ),
        (
            "pre-probe-rejection",
            {"navigation_attempts": [{"outcome": "recoverable-failure"}]},
            None,
        ),
        ("probe-window-missed", {"pages": []}, None),
        (
            "stable-page-unavailable",
            {"pages": [{"rejection": {"kind": "probe-retry-exhausted"}}]},
            None,
        ),
        ("eligible", {"pages": [{"rejection": {"kind": "probe-retry-exhausted"}}]}, None),
    ],
)
def test_only_scientific_terminal_outcomes_release_selection_slots(kind, state, expected):
    assert acquisition_module._scientific_terminal_eligibility({"kind": kind}, state) is expected


def test_acquisition_authority_is_explicit_mutually_exclusive_and_prepare_validated(
    tmp_path, monkeypatch
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    authority = tmp_path / "authority.json"
    authority.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                {"fixture": True},
                receipt_type=class_attestation.ACQUISITION_AUTHORITY_RECEIPT_TYPE,
            )
        )
    )
    calls = []

    def validate(path, *, runtime_role):
        calls.append((path, runtime_role))
        return {"path": str(path), "sha256": acquisition_module.sha256_file(path)}

    monkeypatch.setattr(class_attestation, "validate_class_acquisition_authority", validate)
    common = {
        "candidate_catalogue_path": catalogue,
        "started_at": "2026-08-28T00:00:00Z",
        "browser_tool": "ignored",
    }
    with pytest.raises(ValueError, match="exactly one"):
        initialise_runner(tmp_path / "missing", **common)
    with pytest.raises(ValueError, match="exactly one"):
        initialise_runner(
            tmp_path / "both",
            acquisition_authority=authority,
            foundation_attestation=authority,
            **common,
        )
    runner = initialise_runner(tmp_path / "runner", acquisition_authority=authority, **common)
    provenance = load_json(runner / "provenance.json")["payload"]
    assert "foundation_attestation" not in provenance
    assert provenance["acquisition_authority"]["path"] == str(authority)
    acquisition_module._validate_runner_runtime(provenance)
    assert calls == [(authority, "prepare"), (authority, "prepare")]


def test_schema_five_fixed_contract_and_policy_ledgers_remain_verification_only(tmp_path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="ignored",
    )
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=RejectingBackend(),
    )
    provenance_path = runner / "provenance.json"
    provenance = load_json(provenance_path)["payload"]
    provenance["acquisition_schema_version"] = 5
    _replace_receipt_payload(provenance_path, provenance)
    provenance = load_json(provenance_path)["payload"]
    checkpoint = load_json(runner / "checkpoint.json")["payload"]
    checkpoint["checkpoint_schema_version"] = (
        acquisition_module.SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION
    )
    checkpoint["provenance_sha256"] = acquisition_module.sha256_file(provenance_path)
    for state in checkpoint["candidates"].values():
        if state["terminal"] is None:
            continue
        terminal_path = runner / state["terminal"]["path"]
        terminal = load_json(terminal_path)["payload"]
        terminal["terminal_schema_version"] = acquisition_module.SCHEMA_SIX_TERMINAL_SCHEMA_VERSION
        terminal["checkpoint_schema_version"] = (
            acquisition_module.SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION
        )
        terminal["provenance_sha256"] = checkpoint["provenance_sha256"]
        _replace_receipt_payload(terminal_path, terminal)
        state["terminal"]["sha256"] = acquisition_module.sha256_file(terminal_path)
    _replace_receipt_payload(runner / "checkpoint.json", checkpoint)
    before = (runner / "checkpoint.json").read_bytes()
    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert status["acquisition_schema_version"] == 5 and "selection" not in status
    assert status["terminal_count"] == 2 and status["pending_count"] == 598
    assert set(provenance) == acquisition_module.SCHEMA_FIVE_PROVENANCE_FIELDS
    with pytest.raises(ValueError, match="provenance policy"):
        acquisition_module._validate_current_provenance_contract(
            {
                **provenance,
                "baseline_scheduling_contract": (
                    acquisition_module.TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT
                ),
            }
        )
    with pytest.raises(ValueError, match="historical acquisition runners"):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=NoNetworkBackend(),
        )
    assert (runner / "checkpoint.json").read_bytes() == before
    changed = copy.deepcopy(checkpoint)
    first = next(state for state in changed["candidates"].values() if state["terminal"] is not None)
    first["navigation_attempts"][0].pop("policy_evidence")
    _replace_receipt_payload(runner / "checkpoint.json", changed)
    with pytest.raises(ValueError, match="navigation-attempt ledger"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_schema_six_exact_contract_is_readable_but_cannot_resume_or_publish(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="ignored",
    )
    provenance_path = runner / "provenance.json"
    provenance = copy.deepcopy(load_json(provenance_path)["payload"])
    provenance["acquisition_schema_version"] = 6
    _replace_receipt_payload(provenance_path, provenance)
    provenance = load_json(provenance_path)["payload"]
    assert acquisition_module._validate_current_provenance_contract(provenance) == provenance
    assert (
        provenance["cdp_target_instrumentation_policy"]
        == acquisition_module._SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY
    )
    assert (
        provenance["passive_render_contract_sha256"]
        == acquisition_module._SCHEMA_SIX_PASSIVE_RENDER_CONTRACT_SHA256
    )

    checkpoint_path = runner / "checkpoint.json"
    checkpoint = copy.deepcopy(load_json(checkpoint_path)["payload"])
    checkpoint["checkpoint_schema_version"] = (
        acquisition_module.SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION
    )
    checkpoint["provenance_sha256"] = acquisition_module.sha256_file(provenance_path)
    _replace_receipt_payload(checkpoint_path, checkpoint)
    before = checkpoint_path.read_bytes()

    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert status["acquisition_schema_version"] == 6
    assert status["checkpoint_schema_version"] == (
        acquisition_module.SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION
    )
    assert "selection" in status
    assert status["pending_count"] == len(status["selection"]["admission_ids"])
    with pytest.raises(ValueError, match="historical acquisition runners"):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=NoNetworkBackend(),
        )
    with pytest.raises(ValueError, match="historical acquisition runners"):
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)
    assert checkpoint_path.read_bytes() == before


def test_schema_six_and_seven_contract_discriminators_cannot_collide(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="ignored",
    )
    provenance_path = runner / "provenance.json"
    provenance = copy.deepcopy(load_json(provenance_path)["payload"])
    provenance["acquisition_schema_version"] = 6
    _replace_receipt_payload(provenance_path, provenance)
    provenance = load_json(provenance_path)["payload"]
    tampered = copy.deepcopy(provenance)
    tampered["cdp_target_instrumentation_policy"] = CDP_TARGET_INSTRUMENTATION_POLICY
    with pytest.raises(ValueError, match="provenance policy"):
        acquisition_module._validate_current_provenance_contract(tampered)

    checkpoint_path = runner / "checkpoint.json"
    checkpoint = copy.deepcopy(load_json(checkpoint_path)["payload"])
    checkpoint["provenance_sha256"] = acquisition_module.sha256_file(provenance_path)
    # A schema-seven checkpoint discriminator cannot be relabelled as schema six.
    _replace_receipt_payload(checkpoint_path, checkpoint)
    with pytest.raises(ValueError, match="modern acquisition checkpoint shape"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)

    checkpoint["checkpoint_schema_version"] = (
        acquisition_module.SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION
    )
    _replace_receipt_payload(checkpoint_path, checkpoint)
    assert (
        acquisition_status(runner, candidate_catalogue_path=catalogue)["acquisition_schema_version"]
        == 6
    )


def test_schema_six_completion_receipt_tuple_remains_exactly_verifiable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    catalogue_value, candidates = acquisition_module.load_candidate_catalogue_receipt(catalogue)
    monkeypatch.setattr(
        acquisition_module,
        "load_candidate_catalogue_receipt",
        lambda _path: (catalogue_value, candidates[:1]),
    )
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="ignored",
    )
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=RejectingBackend(),
    )
    completion = copy.deepcopy(
        load_json(write_acquisition_completion(runner, candidate_catalogue_path=catalogue))[
            "payload"
        ]
    )

    provenance_path = runner / "provenance.json"
    provenance = copy.deepcopy(load_json(provenance_path)["payload"])
    provenance["acquisition_schema_version"] = 6
    _replace_receipt_payload(provenance_path, provenance)
    provenance_sha256 = acquisition_module.sha256_file(provenance_path)
    checkpoint_path = runner / "checkpoint.json"
    checkpoint = copy.deepcopy(load_json(checkpoint_path)["payload"])
    checkpoint["checkpoint_schema_version"] = (
        acquisition_module.SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION
    )
    checkpoint["provenance_sha256"] = provenance_sha256
    terminal_receipts = {}
    for candidate_id, state in checkpoint["candidates"].items():
        terminal_path = runner / state["terminal"]["path"]
        terminal = copy.deepcopy(load_json(terminal_path)["payload"])
        terminal["terminal_schema_version"] = acquisition_module.SCHEMA_SIX_TERMINAL_SCHEMA_VERSION
        terminal["checkpoint_schema_version"] = (
            acquisition_module.SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION
        )
        terminal["provenance_sha256"] = provenance_sha256
        _replace_receipt_payload(terminal_path, terminal)
        state["terminal"]["sha256"] = acquisition_module.sha256_file(terminal_path)
        terminal_receipts[candidate_id] = copy.deepcopy(state["terminal"])
    _replace_receipt_payload(checkpoint_path, checkpoint)
    sealed_checkpoint = load_json(checkpoint_path)
    completion.update(
        acquisition_schema_version=6,
        completion_schema_version=(acquisition_module.SCHEMA_SIX_COMPLETION_SCHEMA_VERSION),
        checkpoint_schema_version=(acquisition_module.SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION),
        provenance_sha256=provenance_sha256,
        checkpoint_payload_sha256=sealed_checkpoint["payload_sha256"],
        terminal_receipts=terminal_receipts,
    )
    schema_six_completion = bind_receipt(completion, receipt_type=COMPLETION_TYPE)
    assert (
        validate_acquisition_completion(
            schema_six_completion,
            candidate_catalogue_path=catalogue,
            runner_root=runner,
        )["acquisition_schema_version"]
        == 6
    )

    colliding = copy.deepcopy(completion)
    colliding["completion_schema_version"] = COMPLETION_SCHEMA_VERSION
    with pytest.raises(ValueError, match="acquisition completion schema"):
        validate_acquisition_completion(
            bind_receipt(colliding, receipt_type=COMPLETION_TYPE),
            candidate_catalogue_path=catalogue,
            runner_root=runner,
        )
