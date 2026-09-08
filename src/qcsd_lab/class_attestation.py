"""Fail-closed promotion receipts for ``classifier-multiorigin100-v1``.

The class-study coordinator deliberately keeps capture orchestration separate
from scientific authority.  This module is that authority boundary.  It emits
create-only, hash-bound foundation, readiness, historical, comparison, and
final-validation receipts:

* a *foundation* receipt after fresh source/build/reference/code/regression/
  controlled, pinned-CDP, and packet-observed browser-egress gates reverify,
  before any class acquisition or pilot fitting;
* a *readiness* receipt after the final cohort, authoritative fit, full live
  qualification, and the 900-cell first-launch certification all reverify;
* a final validation attestation after all ten canaries and formal blocks, the
  closed handoff, correctness/performance/classifier evaluation, comparison
  review, and before/after historical-corpus guard all reverify.

Paths are never accepted as proof.  Receipt validation reconstructs the same
value from the referenced immutable inputs and compares it byte-for-byte.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import class_evaluation
from .browser_egress_fixture import (
    QUALIFICATION_ID as BROWSER_EGRESS_QUALIFICATION_ID,
)
from .browser_egress_fixture import VECTOR_COUNT as BROWSER_EGRESS_VECTOR_COUNT
from .browser_egress_fixture import (
    expanded_vectors_sha256 as browser_egress_vectors_sha256,
)
from .browser_egress_qualification import (
    verify_qualification as verify_browser_egress_qualification,
)
from .buflo_evaluation import historical_anchor_metric_inventory, original_study_comparison_rows
from .buflo_study import (
    _one_build_execution_identity,
    _validate_result_environment,
    validate_build_execution_receipt,
    validate_code_gate_receipt,
    validate_historical_corpus_guard,
    validate_qualification_receipt,
    validate_reference_gate_receipt,
    validate_regression_results,
)
from .class_acquisition import (
    CHECKPOINT_SCHEMA_VERSION as ACQUISITION_CHECKPOINT_SCHEMA_VERSION,
    COMPLETION_SCHEMA_VERSION as ACQUISITION_COMPLETION_SCHEMA_VERSION,
    COMPLETION_TYPE,
    SCHEMA_VERSION as ACQUISITION_SCHEMA_VERSION,
    validate_acquisition_completion,
)
from .class_acquisition import PROVENANCE_TYPE as ACQUISITION_PROVENANCE_TYPE
from .class_fitting import (
    AUTHORITATIVE_STAGE,
    NUMERIC_PROVENANCE_FILE,
    PILOT_STAGE,
    PROVENANCE_FILE,
    QualificationContext,
    verify_class_fitting_bundle,
    verify_numeric_fitting_bundle,
)
from .class_handoff import (
    CLASS_STUDY_HISTORICAL_POST_INPUT,
    CLASS_STUDY_LAUNCH_INPUT,
    CLASS_STUDY_LAUNCHES_PATH,
    verify_class_handoff,
)
from .class_study import (
    COMPATIBILITY_MODES,
    FINAL_CLASS_COUNT,
    FORMAL_BLOCK_COUNT,
    FORMAL_MODES,
    FORMAL_VISITS_PER_BLOCK,
    STUDY_ID,
    bind_receipt,
    canonical_json_bytes,
    canonical_json_sha256,
    is_class_study_id,
    is_successor_study_id,
    validate_hash_bound_receipt,
    write_create_only_json,
)
from .pinned_cdp import PROBE_SCHEMA_VERSION as PINNED_CDP_PROBE_SCHEMA_VERSION
from .pinned_cdp import validate_pinned_cdp_receipt
from .playwright_driver import EXPECTED_CHROMIUM_VERSION
from .util import LAB_ROOT, load_json, require_disjoint_path, sha256_file, source_metadata
from .verification import verify_result

SCHEMA_VERSION = 1
FOUNDATION_SCHEMA_VERSION = 4
HISTORICAL_FOUNDATION_SCHEMA_VERSION = 3
READINESS_SCHEMA_VERSION = 3
HISTORICAL_READINESS_SCHEMA_VERSION = 2
QUALIFICATION_AUTHORITY_SCHEMA_VERSION = 2
HISTORICAL_QUALIFICATION_AUTHORITY_SCHEMA_VERSION = 1
FOUNDATION_RECEIPT_TYPE = "qcsd-class-study-foundation-attestation"
READINESS_RECEIPT_TYPE = "qcsd-class-study-readiness-attestation"
READINESS_IMPLEMENTATION_STATUS = "candidate-ready-for-pre-formal-snapshot"
VALIDATION_RECEIPT_TYPE = "qcsd-class-study-validation-attestation"
HISTORICAL_SNAPSHOT_RECEIPT_TYPE = "qcsd-class-study-historical-snapshot"
COMPARISON_REVIEW_RECEIPT_TYPE = "qcsd-class-study-comparison-review"
QUALIFICATION_AUTHORITY_TYPE = "qcsd-class-study-qualification-authority"
_CLASS_STUDY_FOUNDATION_INPUT = "inputs/class-study-foundation.json"
_CLASS_STUDY_READINESS_INPUT = "inputs/class-study-readiness.json"
_CLASS_STUDY_HISTORICAL_PRE_INPUT = "inputs/class-study-historical-pre-snapshot.json"

READINESS_SAMPLE_COUNT = 900
FORMAL_SAMPLE_COUNT = 16_000
CANARY_SAMPLE_COUNT = 1_000
FINAL_QUALIFICATION_EXECUTIONS = 600
REGRESSION_SAMPLE_COUNT = 18
CONTROLLED_SAMPLE_COUNT = 160
_BROWSER_EGRESS_GATE = (
    "browser-egress-packet-qualification-"
    f"{BROWSER_EGRESS_VECTOR_COUNT}-of-{BROWSER_EGRESS_VECTOR_COUNT}"
)

IMPLEMENTATION_SCOPE = "client_only_quic"
VALIDATED_DESCRIPTION = "validated client-only QCSD adaptation"
VALIDATED_STATUS = "seven validated research defenses / nine total modes"

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_PARAMETER_MODES = frozenset(
    {
        "traffic-morphing",
        "wtf-pad",
        "walkie-talkie",
        "buflo",
        "cs-buflo",
    }
)
_RUNTIME_KIND_BY_MODE = {
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

_READINESS_GATES = (
    "current-clean-source-and-no-cache-build",
    "independent-reference-conformance",
    "complete-code-gate",
    "nine-mode-regression-18-of-18",
    "controlled-qualification-160-of-160",
    _BROWSER_EGRESS_GATE,
    "pilot-derived-final-selection-and-cohort-assembly",
    "authoritative-fitting-2000-of-2000",
    "full-live-final-qualification-600-of-600",
    "first-launch-certification-900-of-900",
)
_FOUNDATION_GATES = (
    "current-clean-source-and-no-cache-build",
    "independent-reference-conformance",
    "complete-code-gate",
    "nine-mode-regression-18-of-18",
    "controlled-qualification-160-of-160",
    "pinned-cdp-integration-probe",
    _BROWSER_EGRESS_GATE,
)

_FINAL_GATES = (
    "class-readiness-attestation",
    "pre-block-canaries-1000-of-1000",
    "formal-capture-16000-of-16000",
    "closed-deep-verified-handoff",
    "client-correctness",
    "performance-and-overhead-reporting",
    "candidate-algorithm-and-transport-reporting",
    "dlsvm-capacity-preflight",
    "classifier-security-evaluation",
    "original-study-comparison-review",
    "historical-corpus-before-after-identity",
    "current-source-and-no-waiver-promotion",
)


def create_class_foundation_attestation(destination: Path, **inputs: Any) -> Path:
    """Create the immutable authority required before class acquisition."""

    destination = require_disjoint_path(
        destination,
        _protected_foundation_inputs(inputs),
        label="class foundation attestation destination",
    )
    payload = _foundation_value(
        **inputs,
        recorded_at=None,
        deep_code_gate=True,
        evidence_source=None,
        pinned_runtime_role="collection",
    )
    output = write_create_only_json(
        destination,
        bind_receipt(payload, receipt_type=FOUNDATION_RECEIPT_TYPE),
    )
    validate_class_foundation_attestation(output, deep_code_gate=False)
    return output


def validate_class_foundation_attestation(
    path: Path,
    *,
    deep_code_gate: bool = True,
    runtime_role: str = "collection",
    allow_historical: bool = False,
) -> dict[str, Any]:
    """Reconstruct the seven prerequisite gates from immutable evidence."""

    receipt_path, value, payload = _load_bound_receipt(path, expected_type=FOUNDATION_RECEIPT_TYPE)
    _validate_foundation_envelope(payload, allow_historical=allow_historical)
    historical = (
        allow_historical
        and payload["attestation_schema_version"]
        == HISTORICAL_FOUNDATION_SCHEMA_VERSION
    )
    evidence = payload.get("evidence")
    if not isinstance(evidence, Mapping):
        raise TypeError("class foundation typed evidence is missing")
    expected = _foundation_value(
        cohort_version=payload.get("cohort_version"),
        build_execution_receipt=_path_from_binding(
            evidence.get("build_execution"), label="build execution"
        ),
        reference_receipt=_path_from_binding(evidence.get("reference"), label="reference"),
        code_gate_receipt=_path_from_binding(evidence.get("code_gate"), label="code gate"),
        controlled_qualification_receipt=_path_from_binding(
            evidence.get("controlled_qualification"),
            label="controlled qualification",
        ),
        pinned_cdp_receipt=_pinned_cdp_path_from_binding(
            evidence.get("pinned_cdp_probe"),
            allow_historical=historical,
        ),
        browser_egress_qualification_root=_browser_egress_root_from_binding(
            evidence.get("browser_egress_qualification")
        ),
        regression_result_roots=_roots_from_bindings(evidence.get("regression_results")),
        controlled_result_roots=_roots_from_bindings(evidence.get("controlled_results")),
        recorded_at=payload.get("recorded_at"),
        deep_code_gate=deep_code_gate,
        evidence_source=payload.get("source"),
        pinned_runtime_role=runtime_role,
        attestation_schema_version=payload["attestation_schema_version"],
        allow_historical=historical,
    )
    if payload != expected:
        raise ValueError("class foundation attestation differs from reconstructed evidence")
    _validate_foundation_runtime(
        payload,
        runtime_role=runtime_role,
        build_execution_receipt=_path_from_binding(
            evidence.get("build_execution"), label="build execution"
        ),
        allow_historical=historical,
    )
    return {
        "path": str(receipt_path),
        "sha256": sha256_file(receipt_path),
        "payload_sha256": value["payload_sha256"],
        **expected,
    }


def class_qualification_authority(
    foundation_attestation: Path,
    *,
    deep_code_gate: bool = True,
    runtime_role: str = "collection",
    allow_historical: bool = False,
) -> dict[str, Any]:
    """Derive the one build/source identity authorised for live qualification.

    The foundation is reconstructed first, including its requested runtime-role
    check.  The prepare source is then derived from the same no-cache build
    receipt rather than from an ambient image name or caller-supplied digest.
    """

    foundation = validate_class_foundation_attestation(
        foundation_attestation,
        deep_code_gate=deep_code_gate,
        runtime_role=runtime_role,
        allow_historical=allow_historical,
    )
    historical = (
        allow_historical
        and foundation.get("attestation_schema_version")
        == HISTORICAL_FOUNDATION_SCHEMA_VERSION
    )
    evidence = foundation.get("evidence")
    if not isinstance(evidence, Mapping):  # pragma: no cover - foundation validation guards this
        raise TypeError("class foundation typed evidence is missing")
    build_path = _path_from_binding(evidence.get("build_execution"), label="build execution")
    collection_source = foundation.get("source")
    if not isinstance(collection_source, Mapping):  # pragma: no cover - guarded above
        raise TypeError("class foundation has no bound source")
    build = validate_build_execution_receipt(
        build_path,
        expected_collection_image=str(collection_source.get("image_digest")),
        expected_cohort_version=foundation.get("cohort_version"),
        allow_historical=historical,
    )
    if build.get("source") != collection_source:
        raise ValueError("class qualification build differs from foundation source")
    prepare_image = build["images"]["prepare"]["id"]
    authority = {
        "schema_version": (
            HISTORICAL_QUALIFICATION_AUTHORITY_SCHEMA_VERSION
            if historical
            else QUALIFICATION_AUTHORITY_SCHEMA_VERSION
        ),
        "artifact_type": QUALIFICATION_AUTHORITY_TYPE,
        "foundation_attestation": {
            "path": foundation["path"],
            "sha256": foundation["sha256"],
            "payload_sha256": foundation["payload_sha256"],
        },
        "build_execution": {"path": build["path"], "sha256": build["sha256"]},
        "build_execution_identity": dict(foundation["build_execution_identity"]),
        "collection_source": dict(collection_source),
        "prepare_source": {**dict(collection_source), "image_digest": prepare_image},
        "prepare_image_digest": prepare_image,
    }
    return validate_class_qualification_authority(
        authority, allow_historical=allow_historical
    )


def validate_class_qualification_authority(
    value: object, *, allow_historical: bool = False
) -> dict[str, Any]:
    """Validate the portable authority embedded in qualification/fitting evidence."""

    keys = {
        "schema_version",
        "artifact_type",
        "foundation_attestation",
        "build_execution",
        "build_execution_identity",
        "collection_source",
        "prepare_source",
        "prepare_image_digest",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError("class qualification authority has an invalid exact schema")
    foundation = value.get("foundation_attestation")
    build = value.get("build_execution")
    identity = value.get("build_execution_identity")
    collection = value.get("collection_source")
    prepare = value.get("prepare_source")
    prepare_image = value.get("prepare_image_digest")
    schema_version = value.get("schema_version")
    current_identity_keys = {
        "cohort_version",
        "sha256",
        "completion_path",
        "completion_sha256",
        "collection_image",
        "started_at",
        "finished_at",
    }
    historical_identity_keys = current_identity_keys - {
        "completion_path",
        "completion_sha256",
    }
    if (
        type(schema_version) is not int
        or schema_version
        not in {
            HISTORICAL_QUALIFICATION_AUTHORITY_SCHEMA_VERSION,
            QUALIFICATION_AUTHORITY_SCHEMA_VERSION,
        }
        or (
            schema_version == HISTORICAL_QUALIFICATION_AUTHORITY_SCHEMA_VERSION
            and not allow_historical
        )
        or value.get("artifact_type") != QUALIFICATION_AUTHORITY_TYPE
        or not isinstance(foundation, Mapping)
        or set(foundation) != {"path", "sha256", "payload_sha256"}
        or not isinstance(foundation.get("path"), str)
        or _DIGEST.fullmatch(str(foundation.get("sha256"))) is None
        or _DIGEST.fullmatch(str(foundation.get("payload_sha256"))) is None
        or not isinstance(build, Mapping)
        or set(build) != {"path", "sha256"}
        or not isinstance(build.get("path"), str)
        or _DIGEST.fullmatch(str(build.get("sha256"))) is None
        or not isinstance(identity, Mapping)
        or set(identity)
        != (
            historical_identity_keys
            if schema_version == HISTORICAL_QUALIFICATION_AUTHORITY_SCHEMA_VERSION
            else current_identity_keys
        )
        or type(identity.get("cohort_version")) is not int
        or identity["cohort_version"] < 1
        or identity.get("sha256") != build.get("sha256")
        or (
            schema_version == QUALIFICATION_AUTHORITY_SCHEMA_VERSION
            and (
                identity.get("completion_path")
                != (
                    "/lab/artifacts/buflo-study/"
                    f"build-completion-v{identity['cohort_version']}.json"
                )
                or _DIGEST.fullmatch(str(identity.get("completion_sha256"))) is None
            )
        )
        or _IMAGE_DIGEST.fullmatch(str(identity.get("collection_image"))) is None
        or _IMAGE_DIGEST.fullmatch(str(prepare_image)) is None
    ):
        raise ValueError("class qualification authority binding is invalid")
    _validate_immutable_source(collection, label="qualification collection source")
    _validate_immutable_source(prepare, label="qualification prepare source")
    expected_prepare = {**dict(collection), "image_digest": prepare_image}
    if (
        identity.get("collection_image") != collection.get("image_digest")
        or prepare != expected_prepare
    ):
        raise ValueError("class qualification prepare source differs from its build")
    return json.loads(canonical_json_bytes(value))


def create_class_readiness_attestation(destination: Path, **inputs: Any) -> Path:
    """Create readiness authority only after every pre-formal gate re-runs."""

    destination = require_disjoint_path(
        destination,
        _protected_readiness_inputs(inputs),
        label="class-readiness attestation destination",
    )
    payload = _readiness_value(**inputs, deep_code_gate=True)
    output = write_create_only_json(
        destination,
        bind_receipt(payload, receipt_type=READINESS_RECEIPT_TYPE),
    )
    validate_class_readiness_attestation(output, deep_code_gate=False)
    return output


def validate_class_readiness_attestation(
    path: Path,
    *,
    deep_code_gate: bool = True,
    allow_historical: bool = False,
) -> dict[str, Any]:
    """Independently reconstruct one readiness receipt from its evidence."""

    receipt_path, value, payload = _load_bound_receipt(path, expected_type=READINESS_RECEIPT_TYPE)
    if is_successor_study_id(payload.get("study_id")):
        from .class_successor import validate_successor_readiness

        return validate_successor_readiness(
            receipt_path,
            deep_code_gate=deep_code_gate,
        )
    _validate_readiness_envelope(payload, allow_historical=allow_historical)
    expected = _readiness_value(
        **_readiness_kwargs(payload),
        deep_code_gate=deep_code_gate,
        attestation_schema_version=payload["attestation_schema_version"],
        allow_historical=allow_historical,
    )
    if payload != expected:
        raise ValueError("class-readiness attestation differs from reconstructed evidence")
    return {
        "path": str(receipt_path),
        "sha256": sha256_file(receipt_path),
        "payload_sha256": value["payload_sha256"],
        **expected,
    }


def create_class_historical_snapshot(
    destination: Path,
    *,
    phase: str,
    readiness_attestation: Path,
    formal_result_roots: Sequence[Path] = (),
    pre_snapshot: Path | None = None,
) -> Path:
    """Freeze a deep historical-corpus identity before or after formal capture."""

    protected = [
        LAB_ROOT / "handoffs/classifier-multiorigin5-v2",
        readiness_attestation,
        *formal_result_roots,
    ]
    if pre_snapshot is not None:
        protected.append(pre_snapshot)
    destination = require_disjoint_path(
        destination,
        tuple(Path(item) for item in protected),
        label=f"class historical {phase} snapshot destination",
    )
    payload = _historical_snapshot_value(
        phase=phase,
        readiness_attestation=readiness_attestation,
        formal_result_roots=formal_result_roots,
        pre_snapshot=pre_snapshot,
        recorded_at=None,
    )
    output = write_create_only_json(
        destination,
        bind_receipt(payload, receipt_type=HISTORICAL_SNAPSHOT_RECEIPT_TYPE),
    )
    validate_class_historical_snapshot(output)
    return output


def validate_class_historical_snapshot(
    path: Path,
    *,
    expected_phase: str | None = None,
) -> dict[str, Any]:
    """Deeply re-run the historical guard and rebuild a class snapshot."""

    receipt_path, value, payload = _load_bound_receipt(
        path, expected_type=HISTORICAL_SNAPSHOT_RECEIPT_TYPE
    )
    phase = payload.get("phase")
    if phase not in {"pre-formal", "post-formal"}:
        raise ValueError("class historical snapshot phase is invalid")
    if expected_phase is not None and phase != expected_phase:
        raise ValueError("class historical snapshot has the wrong phase")
    readiness = _path_from_binding(payload.get("readiness"), label="readiness")
    formal_roots = _roots_from_bindings(payload.get("formal_results"), allow_empty=True)
    pre = payload.get("pre_formal_snapshot")
    pre_path = None if pre is None else _path_from_binding(pre, label="pre snapshot")
    expected = _historical_snapshot_value(
        phase=phase,
        readiness_attestation=readiness,
        formal_result_roots=formal_roots,
        pre_snapshot=pre_path,
        recorded_at=payload.get("recorded_at"),
    )
    if payload != expected:
        raise ValueError("class historical snapshot differs from reconstructed evidence")
    return {
        "path": str(receipt_path),
        "sha256": sha256_file(receipt_path),
        "payload_sha256": value["payload_sha256"],
        **expected,
    }


def create_class_comparison_review(
    destination: Path,
    *,
    handoff: Path,
    evaluation_receipt: Path,
    reviewer: str,
    reviewed_at: str,
    reviews: Sequence[Mapping[str, Any]],
    _post_write_validate: bool = True,
) -> Path:
    """Publish a human review covering every published anchor metric.

    The function validates the handoff and evaluation before accepting review
    text.  It does not manufacture explanations: a reviewer must supply one
    substantive disposition for every checked-in historical metric.
    """

    if type(_post_write_validate) is not bool:
        raise ValueError("class comparison post-write validation flag must be a boolean")
    destination = require_disjoint_path(
        destination,
        (handoff, evaluation_receipt),
        label="class comparison review destination",
    )
    payload = _comparison_review_value(
        handoff=handoff,
        evaluation_receipt=evaluation_receipt,
        reviewer=reviewer,
        reviewed_at=reviewed_at,
        reviews=reviews,
    )
    output = write_create_only_json(
        destination,
        bind_receipt(payload, receipt_type=COMPARISON_REVIEW_RECEIPT_TYPE),
    )
    if _post_write_validate:
        validate_class_comparison_review(output)
    return output


def build_class_comparison_review_template(
    *,
    handoff: Path,
    evaluation_receipt: Path,
) -> dict[str, Any]:
    """Return the exact published/QCSD pairs a human review must acknowledge."""

    handoff_root = verify_class_handoff(handoff, deep=True)
    evaluation = class_evaluation.verify_class_evaluation_receipt(
        evaluation_receipt,
        handoff_root=handoff_root,
        deep_verify_handoff=True,
        replay_attacks=False,
    )
    _require_evaluation_completion(evaluation, require_full_replay=False)
    historical_rows = list(original_study_comparison_rows())
    inventory = list(historical_anchor_metric_inventory(historical_rows))
    pairs = _comparison_pairs(historical_rows, inventory, evaluation)
    return {
        "template_schema_version": 1,
        "artifact_type": "qcsd-class-study-comparison-review-template",
        "study_id": evaluation.get("study_id", STUDY_ID),
        "handoff": _handoff_binding(handoff_root),
        "evaluation": _file_binding(evaluation_receipt),
        "comparison_rows_sha256": canonical_json_sha256(pairs),
        "comparison_rows": pairs,
        "reviews": [
            {
                "defense": pair["defense"],
                "anchor_id": pair["anchor_id"],
                "metric": pair["metric"],
                "pair_sha256": pair["pair_sha256"],
                "disposition": None,
                "explanation": "",
                "context_differences": pair["context_differences"],
            }
            for pair in pairs
        ],
    }


def validate_class_comparison_review(
    path: Path,
    *,
    handoff: Path | None = None,
    evaluation_receipt: Path | None = None,
) -> dict[str, Any]:
    """Reconstruct an exhaustive original-study comparison review."""

    receipt_path, value, payload = _load_bound_receipt(
        path, expected_type=COMPARISON_REVIEW_RECEIPT_TYPE
    )
    bound_handoff = payload.get("handoff")
    if not isinstance(bound_handoff, Mapping) or not isinstance(bound_handoff.get("root"), str):
        raise TypeError("class comparison review has no handoff binding")
    handoff_path = Path(bound_handoff["root"]) if handoff is None else Path(handoff)
    evaluation_path = (
        _path_from_binding(payload.get("evaluation"), label="evaluation")
        if evaluation_receipt is None
        else Path(evaluation_receipt)
    )
    expected = _comparison_review_value(
        handoff=handoff_path,
        evaluation_receipt=evaluation_path,
        reviewer=payload.get("reviewer"),
        reviewed_at=payload.get("reviewed_at"),
        reviews=payload.get("reviews"),
    )
    if payload != expected:
        raise ValueError("class comparison review differs from reconstructed evidence")
    return {
        "path": str(receipt_path),
        "sha256": sha256_file(receipt_path),
        "payload_sha256": value["payload_sha256"],
        **expected,
    }


def create_class_validation_attestation(
    destination: Path,
    *,
    _post_write_validate: bool = True,
    **inputs: Any,
) -> Path:
    """Create the sole promotion authority after every final gate re-runs."""

    if type(_post_write_validate) is not bool:
        raise ValueError("class validation post-write validation flag must be a boolean")
    destination = require_disjoint_path(
        destination,
        _protected_final_inputs(inputs),
        label="class validation attestation destination",
    )
    payload = _validation_value(**inputs, deep_code_gate=True)
    output = write_create_only_json(
        destination,
        bind_receipt(payload, receipt_type=VALIDATION_RECEIPT_TYPE),
    )
    if _post_write_validate:
        validate_class_validation_attestation(output, deep_code_gate=False)
    return output


def validate_class_validation_attestation(
    path: Path,
    *,
    deep_code_gate: bool = True,
) -> dict[str, Any]:
    """Reconstruct the all-pass class-study promotion attestation."""

    receipt_path, value, payload = _load_bound_receipt(path, expected_type=VALIDATION_RECEIPT_TYPE)
    _validate_validation_envelope(payload)
    expected = _validation_value(
        **_validation_kwargs(payload),
        deep_code_gate=deep_code_gate,
    )
    if payload != expected:
        raise ValueError("class validation attestation differs from reconstructed evidence")
    return {
        "path": str(receipt_path),
        "sha256": sha256_file(receipt_path),
        "payload_sha256": value["payload_sha256"],
        **expected,
    }


def _foundation_value(
    *,
    cohort_version: int,
    build_execution_receipt: Path,
    reference_receipt: Path,
    code_gate_receipt: Path,
    controlled_qualification_receipt: Path,
    pinned_cdp_receipt: Path,
    browser_egress_qualification_root: Path,
    regression_result_roots: Sequence[Path],
    controlled_result_roots: Sequence[Path],
    recorded_at: object,
    deep_code_gate: bool,
    evidence_source: object,
    pinned_runtime_role: str,
    attestation_schema_version: int = FOUNDATION_SCHEMA_VERSION,
    allow_historical: bool = False,
) -> dict[str, Any]:
    if type(cohort_version) is not int or cohort_version < 1:
        raise ValueError("class foundation cohort version must be a positive integer")
    if type(deep_code_gate) is not bool:
        raise ValueError("class foundation deep-code flag must be a boolean")
    historical = (
        attestation_schema_version == HISTORICAL_FOUNDATION_SCHEMA_VERSION
        and allow_historical
    )
    if attestation_schema_version != FOUNDATION_SCHEMA_VERSION and not historical:
        raise ValueError("class foundation schema is not admitted")
    current_source = source_metadata() if evidence_source is None else evidence_source
    _validate_immutable_source(current_source, label="current class-study source")
    if not isinstance(current_source, Mapping):
        raise TypeError("class foundation source is not an object")
    current_source = dict(current_source)
    build = validate_build_execution_receipt(
        build_execution_receipt,
        expected_collection_image=current_source["image_digest"],
        expected_cohort_version=cohort_version,
        allow_historical=historical,
    )
    if build["source"] != current_source:
        raise ValueError("class foundation build differs from current source")
    build_identity = _build_identity(build, include_completion=not historical)
    browser_egress = _validate_browser_egress_qualification(
        browser_egress_qualification_root,
        cohort_version=cohort_version,
        build=build,
        allow_historical=historical,
    )
    pinned_cdp = validate_pinned_cdp_receipt(
        pinned_cdp_receipt,
        build_execution_receipt=build_execution_receipt,
        expected_cohort_version=cohort_version,
        runtime_role=pinned_runtime_role,
        allow_historical=historical,
    )
    reference = validate_reference_gate_receipt(
        reference_receipt,
        expected_cohort_version=cohort_version,
        allow_historical=historical,
    )
    regression = validate_regression_results(
        regression_result_roots,
        _expected_collection_source=current_source,
    )
    if regression.get("samples") != REGRESSION_SAMPLE_COUNT:
        raise ValueError("class foundation regression is not exactly 18/18")
    code = validate_code_gate_receipt(
        code_gate_receipt,
        regression_result_roots=regression_result_roots,
        expected_cohort_version=cohort_version,
        deep=deep_code_gate,
        _expected_collection_source=current_source,
        allow_historical=historical,
    )
    controlled = validate_qualification_receipt(
        controlled_qualification_receipt,
        controlled_result_roots=controlled_result_roots,
        expected_cohort_version=cohort_version,
        _expected_collection_source=current_source,
        allow_historical=historical,
    )
    controlled_results = controlled.get("controlled_results")
    build_binding = {"path": build["path"], "sha256": build["sha256"]}
    if (
        reference.get("build_execution") != build_identity
        or code.get("source") != current_source
        or regression.get("source") != current_source
        or controlled.get("source") != current_source
        or code.get("build_execution_receipt") != build_binding
        or controlled.get("build_execution") != build_binding
        or not isinstance(controlled_results, Mapping)
        or controlled_results.get("samples") != CONTROLLED_SAMPLE_COUNT
        or _one_class_build_execution_identity(
            [record["environment"] for record in regression["results"]],
            include_completion=not historical,
        )
        != build_identity
        or _one_class_build_execution_identity(
            [record["environment"] for record in controlled_results["results"]],
            include_completion=not historical,
        )
        != build_identity
    ):
        raise ValueError("class foundation gates do not share one source/build")
    if recorded_at is None:
        recorded_at = datetime.now(UTC).isoformat()
    timestamp = _aware_timestamp(recorded_at, label="foundation attestation")
    probe_timestamp = _aware_timestamp(
        pinned_cdp.get("recorded_at"), label="pinned CDP probe"
    )
    build_finished = _aware_timestamp(
        build.get("finished_at"), label="no-cache build finish"
    )
    if not build_finished <= probe_timestamp <= timestamp:
        raise ValueError(
            "class foundation requires build finish <= pinned CDP probe <= foundation"
        )
    qualification_started = _aware_timestamp(
        browser_egress.get("qualification_started_at"),
        label="browser-egress qualification start",
    )
    qualification_finished = _aware_timestamp(
        browser_egress.get("qualification_finished_at"),
        label="browser-egress qualification finish",
    )
    qualification_recorded = _aware_timestamp(
        browser_egress.get("recorded_at"),
        label="browser-egress qualification final receipt",
    )
    if not (
        build_finished
        <= qualification_started
        <= qualification_finished
        <= qualification_recorded
        <= timestamp
    ):
        raise ValueError(
            "class foundation requires build finish <= browser-egress start <= "
            "finish <= final receipt <= foundation"
        )
    evidence = {
        "build_execution": _file_binding(build_execution_receipt),
        "pinned_cdp_probe": _pinned_cdp_binding(pinned_cdp),
        "browser_egress_qualification": _browser_egress_binding(
            browser_egress, browser_egress_qualification_root
        ),
        "reference": _file_binding(reference_receipt),
        "code_gate": _file_binding(code_gate_receipt),
        "controlled_qualification": _file_binding(controlled_qualification_receipt),
        "regression_results": [_result_binding(path) for path in regression_result_roots],
        "controlled_results": [_result_binding(path) for path in controlled_result_roots],
    }
    gate_evidence = {
        "current-clean-source-and-no-cache-build": [
            build["sha256"],
            *([] if historical else [build["completion_sha256"]]),
        ],
        "independent-reference-conformance": [reference["sha256"]],
        "complete-code-gate": [code["sha256"]],
        "nine-mode-regression-18-of-18": [
            item["evidence_sha256"] for item in evidence["regression_results"]
        ],
        "controlled-qualification-160-of-160": [
            controlled["sha256"],
            *(item["evidence_sha256"] for item in evidence["controlled_results"]),
        ],
        "pinned-cdp-integration-probe": [
            pinned_cdp["sha256"],
            pinned_cdp["payload_sha256"],
            pinned_cdp["build_execution"]["sha256"],
            pinned_cdp["build_execution"]["payload_sha256"],
            *(
                []
                if historical
                else [pinned_cdp["build_execution_identity"]["completion_sha256"]]
            ),
            pinned_cdp["probe_contract_sha256"],
        ],
        _BROWSER_EGRESS_GATE: [
            browser_egress["sha256"],
            browser_egress["payload_sha256"],
            browser_egress["expanded_vectors_sha256"],
        ],
    }
    return {
        "attestation_schema_version": attestation_schema_version,
        "artifact_type": FOUNDATION_RECEIPT_TYPE,
        "study_id": STUDY_ID,
        "cohort_version": cohort_version,
        "recorded_at": timestamp.isoformat(),
        "implementation_status": "foundation-ready-for-class-acquisition",
        "promotion_authority": False,
        "implementation_scope": IMPLEMENTATION_SCOPE,
        "paper_equivalent": False,
        "no_waivers": True,
        "source": current_source,
        "build_execution_identity": build_identity,
        "evidence": evidence,
        "summary": {
            "reference_profiles": reference["profiles_checked"],
            "regression_samples": REGRESSION_SAMPLE_COUNT,
            "controlled_samples": CONTROLLED_SAMPLE_COUNT,
            "pinned_cdp_probe": "pass",
            "browser_egress_packet_qualification": "pass",
            "browser_egress_vectors": BROWSER_EGRESS_VECTOR_COUNT,
        },
        "hard_gates": _hard_gate_records(_FOUNDATION_GATES, gate_evidence),
        "all_foundation_gates_passed": True,
    }


def _validated_runtime_inputs(
    value: Any,
    *,
    expected_modes: Sequence[str],
    label: str,
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != set(expected_modes):
        raise ValueError(f"{label} does not bind every expected runtime input")
    result: dict[str, dict[str, Any]] = {}
    for mode in expected_modes:
        raw = value.get(mode)
        if not isinstance(raw, Mapping):
            raise ValueError(f"{label} {mode} runtime input is malformed")
        identity = dict(raw)
        if identity.get("runtime_kind") != _RUNTIME_KIND_BY_MODE[mode]:
            raise ValueError(f"{label} {mode} runtime kind is invalid")
        identity_type = identity.get("identity_type")
        if mode in _PARAMETER_MODES:
            if (
                set(identity)
                != {
                    "identity_type",
                    "runtime_kind",
                    "parameters_sha256",
                    "provenance_sha256",
                    "input_policy",
                }
                or identity_type != "hash-bound-parameter-artifact"
                or _DIGEST.fullmatch(str(identity.get("parameters_sha256"))) is None
                or _DIGEST.fullmatch(str(identity.get("provenance_sha256"))) is None
                or not isinstance(identity.get("input_policy"), str)
                or not identity["input_policy"]
            ):
                raise ValueError(f"{label} {mode} parameter identity is malformed")
        elif mode == "static":
            if (
                set(identity)
                != {
                    "identity_type",
                    "runtime_kind",
                    "schedule_sha256",
                    "mode",
                }
                or identity_type != "hash-bound-static-schedule"
                or _DIGEST.fullmatch(str(identity.get("schedule_sha256"))) is None
                or identity.get("mode") not in {"chaff-only", "chaff-and-shape"}
            ):
                raise ValueError(f"{label} static schedule identity is malformed")
        else:
            expected_type = (
                "source-bound-no-defense" if mode == "undefended" else "source-bound-built-in"
            )
            if set(identity) != {"identity_type", "runtime_kind"} or identity_type != expected_type:
                raise ValueError(f"{label} {mode} built-in identity is malformed")
        result[mode] = identity
    return result


def _readiness_value(
    *,
    foundation_attestation: Path,
    cohort_version: int,
    build_execution_receipt: Path,
    reference_receipt: Path,
    code_gate_receipt: Path,
    controlled_qualification_receipt: Path,
    regression_result_roots: Sequence[Path],
    controlled_result_roots: Sequence[Path],
    candidate_catalogue: Path,
    stability_root: Path,
    workload_root: Path,
    acquisition_completion: Path,
    pilot_cohort_receipt: Path,
    pilot_cohort_assembly: Path,
    pilot_fitting_result_root: Path,
    pilot_numeric_bundle_root: Path,
    pilot_compatibility_result_root: Path,
    final_selection_receipt: Path,
    final_cohort_receipt: Path,
    final_cohort_assembly: Path,
    authoritative_fitting_result_root: Path,
    authoritative_fitting_bundle_root: Path,
    qualification_workload_root: Path,
    qualification_sidecar_root: Path,
    qualification_prefix_root: Path,
    certification_result_root: Path,
    deep_code_gate: bool,
    attestation_schema_version: int = READINESS_SCHEMA_VERSION,
    allow_historical: bool = False,
) -> dict[str, Any]:
    if type(cohort_version) is not int or cohort_version < 1:
        raise ValueError("class readiness cohort version must be a positive integer")
    if type(deep_code_gate) is not bool:
        raise ValueError("class readiness deep-code flag must be a boolean")
    historical = (
        attestation_schema_version == HISTORICAL_READINESS_SCHEMA_VERSION
        and allow_historical
    )
    if attestation_schema_version != READINESS_SCHEMA_VERSION and not historical:
        raise ValueError("class readiness schema is not admitted")

    foundation = validate_class_foundation_attestation(
        foundation_attestation,
        deep_code_gate=deep_code_gate,
        allow_historical=historical,
    )
    qualification_authority = class_qualification_authority(
        foundation_attestation,
        deep_code_gate=deep_code_gate,
        runtime_role="collection",
        allow_historical=historical,
    )
    if foundation.get("cohort_version") != cohort_version:
        raise ValueError("class readiness and foundation cohort versions differ")
    current_source = source_metadata()
    _validate_immutable_source(current_source, label="current class-study source")
    build = validate_build_execution_receipt(
        build_execution_receipt,
        expected_collection_image=current_source["image_digest"],
        expected_cohort_version=cohort_version,
        allow_historical=historical,
    )
    if build["source"] != current_source:
        raise ValueError("class readiness build differs from the current source")
    build_identity = _build_identity(build, include_completion=not historical)

    reference = validate_reference_gate_receipt(
        reference_receipt,
        expected_cohort_version=cohort_version,
        allow_historical=historical,
    )
    if reference.get("build_execution") != build_identity:
        raise ValueError("class readiness reference gate uses a different build")
    regression = validate_regression_results(regression_result_roots)
    if regression.get("samples") != REGRESSION_SAMPLE_COUNT:
        raise ValueError("class readiness regression is not exactly 18/18")
    code = validate_code_gate_receipt(
        code_gate_receipt,
        regression_result_roots=regression_result_roots,
        expected_cohort_version=cohort_version,
        deep=deep_code_gate,
        allow_historical=historical,
    )
    controlled = validate_qualification_receipt(
        controlled_qualification_receipt,
        controlled_result_roots=controlled_result_roots,
        expected_cohort_version=cohort_version,
        allow_historical=historical,
    )
    controlled_results = controlled.get("controlled_results")
    if (
        not isinstance(controlled_results, Mapping)
        or controlled_results.get("samples") != CONTROLLED_SAMPLE_COUNT
    ):
        raise ValueError("class readiness controlled qualification is not 160/160")
    build_binding = {"path": build["path"], "sha256": build["sha256"]}
    if (
        code.get("source") != current_source
        or regression.get("source") != current_source
        or controlled.get("source") != current_source
        or code.get("build_execution_receipt") != build_binding
        or controlled.get("build_execution") != build_binding
    ):
        raise ValueError("class readiness prerequisite gates do not share one source/build")
    if (
        _one_class_build_execution_identity(
            [record["environment"] for record in regression["results"]],
            include_completion=not historical,
        )
        != build_identity
        or _one_class_build_execution_identity(
            [record["environment"] for record in controlled_results["results"]],
            include_completion=not historical,
        )
        != build_identity
    ):
        raise ValueError("class readiness live prerequisite gates use a different build")
    foundation_evidence = foundation.get("evidence")
    if not isinstance(foundation_evidence, Mapping):
        raise TypeError("class readiness foundation typed evidence is missing")
    pinned_cdp_path = _pinned_cdp_path_from_binding(
        foundation_evidence.get("pinned_cdp_probe"),
        allow_historical=historical,
    )
    pinned_cdp = validate_pinned_cdp_receipt(
        pinned_cdp_path,
        build_execution_receipt=build_execution_receipt,
        expected_cohort_version=cohort_version,
        runtime_role="collection",
        allow_historical=historical,
    )
    browser_egress_root = _browser_egress_root_from_binding(
        foundation_evidence.get("browser_egress_qualification")
    )
    browser_egress = _validate_browser_egress_qualification(
        browser_egress_root,
        cohort_version=cohort_version,
        build=build,
        allow_historical=historical,
    )
    browser_egress_binding = _browser_egress_binding(
        browser_egress, browser_egress_root
    )
    expected_foundation_evidence = {
        "build_execution": _file_binding(build_execution_receipt),
        "pinned_cdp_probe": _pinned_cdp_binding(pinned_cdp),
        "browser_egress_qualification": browser_egress_binding,
        "reference": _file_binding(reference_receipt),
        "code_gate": _file_binding(code_gate_receipt),
        "controlled_qualification": _file_binding(controlled_qualification_receipt),
        "regression_results": [_result_binding(path) for path in regression_result_roots],
        "controlled_results": [_result_binding(path) for path in controlled_result_roots],
    }
    if (
        foundation.get("source") != current_source
        or foundation.get("build_execution_identity") != build_identity
        or foundation_evidence != expected_foundation_evidence
    ):
        raise ValueError("class readiness prerequisite gates differ from foundation")

    completion_path, completion_value, _completion_payload = _load_bound_receipt(
        acquisition_completion,
        expected_type=COMPLETION_TYPE,
    )
    completion = validate_acquisition_completion(
        completion_value,
        candidate_catalogue_path=_regular_file(candidate_catalogue, "candidate catalogue"),
        runner_root=completion_path.parent,
    )
    _require_current_acquisition_completion(completion)
    observed_toolchain = _require_acquisition_toolchain(
        completion.get("observed_toolchain"),
        source=current_source,
        build_receipt=build,
    )
    provenance_path, provenance_value, provenance = _load_bound_receipt(
        completion_path.parent / "provenance.json",
        expected_type=ACQUISITION_PROVENANCE_TYPE,
    )
    foundation_binding = _file_binding(foundation_attestation)
    if (
        provenance.get("foundation_attestation") != foundation_binding
        or completion.get("provenance_sha256") != sha256_file(provenance_path)
        or provenance_value.get("payload_sha256") is None
    ):
        raise ValueError("class acquisition provenance is not foundation-bound")
    if _aware_timestamp(
        foundation.get("recorded_at"), label="foundation attestation"
    ) > _aware_timestamp(provenance.get("started_at"), label="acquisition start"):
        raise ValueError("class acquisition predates its foundation attestation")

    from .class_pipeline import (
        build_final_selection_input,
        validate_final_selection_input,
        verify_class_study_result,
        verify_cohort_admission,
    )

    pilot_admission = verify_cohort_admission(
        pilot_cohort_receipt,
        pilot_cohort_assembly,
        candidate_catalogue_path=candidate_catalogue,
        stability_root=stability_root,
        workload_root=workload_root,
        acquisition_completion_path=acquisition_completion,
    )
    if pilot_admission.selection.feasible_pairs is not None:
        raise ValueError("class readiness pilot admission unexpectedly has a pair graph")
    pilot_fit = verify_class_study_result(
        pilot_fitting_result_root,
        admission=pilot_admission,
        expected_role="pilot-fitting",
    )
    pilot_numeric = verify_numeric_fitting_bundle(
        pilot_numeric_bundle_root,
        source_result_root=pilot_fitting_result_root,
    )
    if pilot_numeric.stage != PILOT_STAGE:
        raise ValueError("class readiness pilot numeric bundle has the wrong stage")
    pilot_compatibility = verify_class_study_result(
        pilot_compatibility_result_root,
        admission=pilot_admission,
        expected_role="pilot-compatibility",
    )
    _selection_path, selection_value, selection_payload = _load_bound_receipt(
        final_selection_receipt,
        expected_type="qcsd-class-study-final-selection-input",
    )
    selection_compatibility = selection_payload.get("pilot_compatibility")
    selection_bundle = (
        selection_compatibility.get("finalized_bundle")
        if isinstance(selection_compatibility, Mapping)
        else None
    )
    qualification_authority_sha256 = canonical_json_sha256(qualification_authority)
    if (
        not isinstance(selection_bundle, Mapping)
        or selection_bundle.get("qualification_authority") != qualification_authority
        or selection_bundle.get("qualification_authority_sha256")
        != qualification_authority_sha256
    ):
        raise ValueError("class readiness final selection uses another qualification authority")
    validate_final_selection_input(
        selection_value,
        pilot_admission=pilot_admission,
        pilot_fitting_result_root=pilot_fitting_result_root,
        pilot_numeric_bundle_root=pilot_numeric_bundle_root,
        pilot_compatibility_result_root=pilot_compatibility_result_root,
        qualification_authority=qualification_authority,
    )
    if selection_value != build_final_selection_input(
        pilot_admission,
        pilot_fitting_result_root=pilot_fitting_result_root,
        pilot_numeric_bundle_root=pilot_numeric_bundle_root,
        pilot_compatibility_result_root=pilot_compatibility_result_root,
        qualification_authority=qualification_authority,
    ):
        raise ValueError("class readiness final selection was not independently reproduced")

    final_admission = verify_cohort_admission(
        final_cohort_receipt,
        final_cohort_assembly,
        candidate_catalogue_path=candidate_catalogue,
        stability_root=stability_root,
        workload_root=workload_root,
        acquisition_completion_path=acquisition_completion,
        final_selection_receipt_path=final_selection_receipt,
    )
    selection = final_admission.selection
    if (
        selection.feasible_pairs is None
        or len(selection.final) != FINAL_CLASS_COUNT
        or len(selection.reserves) != 20
        or final_admission.final_selection_sha256
        != sha256_file(_regular_file(final_selection_receipt, "final selection"))
    ):
        raise ValueError("class readiness final selection/cohort is incomplete")

    fitting_result = verify_class_study_result(
        authoritative_fitting_result_root,
        admission=final_admission,
        expected_role="authoritative-fitting",
    )
    if fitting_result.get("samples") != 2_000:
        raise ValueError("class readiness authoritative fitting is not 2,000/2,000")
    qualification_context = QualificationContext(
        workload_root=_regular_directory(
            qualification_workload_root, "qualification workload root"
        ),
        sidecar_root=_regular_directory(qualification_sidecar_root, "qualification sidecar root"),
        prefix_spec_root=_regular_directory(qualification_prefix_root, "qualification prefix root"),
        qualification_authority=qualification_authority,
    )
    fitting = verify_class_fitting_bundle(
        authoritative_fitting_bundle_root,
        qualification_context=qualification_context,
        source_result_root=authoritative_fitting_result_root,
    )
    if (
        fitting.stage != AUTHORITATIVE_STAGE
        or fitting.provenance.get("runtime_authorized") is not True
        or fitting.provenance["cohort"].get("receipt_sha256") != final_admission.cohort_sha256
        or fitting.provenance["cohort"].get("assembly_receipt_sha256")
        != final_admission.assembly_sha256
        or len(fitting.provenance["qualification_inputs"]["qualification_bindings"])
        != FINAL_CLASS_COUNT
    ):
        raise ValueError("class readiness authoritative fitting/final qualification is invalid")

    certification = verify_class_study_result(
        certification_result_root,
        admission=final_admission,
        expected_role="certification",
    )
    if (
        certification.get("samples") != READINESS_SAMPLE_COUNT
        or certification.get("accepted") != READINESS_SAMPLE_COUNT
        or certification.get("first_launch_unique_class_mode_pairs") != READINESS_SAMPLE_COUNT
    ):
        raise ValueError("class readiness certification is not 900/900 first-launch evidence")
    expected_fitted_parameters = {
        "traffic-morphing": fitting.artifact_hashes["traffic_morphing"],
        "wtf-pad": fitting.artifact_hashes["wtf_pad"],
        "walkie-talkie": fitting.artifact_hashes["walkie_talkie"],
    }
    certification_parameters = certification.get("defense_parameter_sha256")
    if (
        not isinstance(certification_parameters, Mapping)
        or set(certification_parameters) != _PARAMETER_MODES
        or any(
            not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None
            for digest in certification_parameters.values()
        )
        or any(
            certification_parameters.get(mode) != digest
            for mode, digest in expected_fitted_parameters.items()
        )
    ):
        raise ValueError("class readiness certification used different fitted parameters")
    certification_runtime_inputs = _validated_runtime_inputs(
        certification.get("defense_runtime_inputs"),
        expected_modes=COMPATIBILITY_MODES,
        label="class readiness certification",
    )
    if any(
        certification_runtime_inputs[mode]["parameters_sha256"] != certification_parameters[mode]
        for mode in _PARAMETER_MODES
    ):
        raise ValueError("class readiness certification parameter and runtime-input maps differ")
    final_qualification_manifest_sha256 = fitting.provenance["qualification_inputs"].get(
        "qualification_manifest_sha256"
    )
    if (
        not isinstance(final_qualification_manifest_sha256, str)
        or _DIGEST.fullmatch(final_qualification_manifest_sha256) is None
        or certification.get("chaff_qualification_set_manifest_sha256")
        != final_qualification_manifest_sha256
    ):
        raise ValueError("class readiness certification used a different qualification manifest")

    prerequisite_result_records = (
        pilot_fit,
        pilot_compatibility,
        fitting_result,
        certification,
    )
    if any(
        record.get("class_study_foundation_sha256") != foundation_binding["sha256"]
        for record in prerequisite_result_records
    ):
        raise ValueError("class readiness results do not share the exact foundation")

    result_roots = (
        pilot_fitting_result_root,
        pilot_compatibility_result_root,
        authoritative_fitting_result_root,
        certification_result_root,
    )
    verified_results = tuple(verify_result(Path(root)) for root in result_roots)
    environments = []
    for verified in verified_results:
        if verified.experiment.get("source") != current_source:
            raise ValueError("class readiness result uses a different immutable source")
        environments.append(_validate_result_environment(verified, current_source))
    if (
        _one_class_build_execution_identity(
            environments, include_completion=not historical
        )
        != build_identity
    ):
        raise ValueError("class readiness results do not share the no-cache build")

    fitting_source = fitting.provenance["source_result"].get("source_fingerprints")
    if fitting_source != current_source:
        raise ValueError("class readiness fitted bundle has different source fingerprints")

    evidence = {
        "foundation": foundation_binding,
        "build_execution": _file_binding(build_execution_receipt),
        "browser_egress_qualification": browser_egress_binding,
        "reference": _file_binding(reference_receipt),
        "code_gate": _file_binding(code_gate_receipt),
        "controlled_qualification": _file_binding(controlled_qualification_receipt),
        "regression_results": [_result_binding(path) for path in regression_result_roots],
        "controlled_results": [_result_binding(path) for path in controlled_result_roots],
        "candidate_catalogue": _file_binding(candidate_catalogue),
        "stability_root": _directory_binding(stability_root),
        "workload_root": _directory_binding(workload_root),
        "acquisition_completion": _file_binding(acquisition_completion),
        "pilot_cohort": _file_binding(pilot_cohort_receipt),
        "pilot_cohort_assembly": _file_binding(pilot_cohort_assembly),
        "pilot_fitting_result": _class_result_binding(pilot_fitting_result_root),
        "pilot_numeric_bundle": _fitting_bundle_binding(
            pilot_numeric.root,
            provenance_name=NUMERIC_PROVENANCE_FILE,
            artifact_hashes=pilot_numeric.artifact_hashes,
        ),
        "pilot_compatibility_result": _class_result_binding(pilot_compatibility_result_root),
        "final_selection": _file_binding(final_selection_receipt),
        "final_cohort": _file_binding(final_cohort_receipt),
        "final_cohort_assembly": _file_binding(final_cohort_assembly),
        "authoritative_fitting_result": _class_result_binding(authoritative_fitting_result_root),
        "authoritative_fitting_bundle": _fitting_bundle_binding(
            fitting.root,
            provenance_name=PROVENANCE_FILE,
            artifact_hashes=fitting.artifact_hashes,
        ),
        "qualification_context": {
            "workload_root": _directory_binding(qualification_context.workload_root),
            "sidecar_root": _directory_binding(qualification_context.sidecar_root),
            "prefix_spec_root": _directory_binding(qualification_context.prefix_spec_root),
            "qualification_authority": qualification_authority,
            "qualification_authority_sha256": qualification_authority_sha256,
        },
        "certification_result": _class_result_binding(certification_result_root),
    }
    gate_evidence = {
        "current-clean-source-and-no-cache-build": [
            foundation_binding["sha256"],
            build["sha256"],
            *([] if historical else [build["completion_sha256"]]),
        ],
        "independent-reference-conformance": [
            foundation_binding["sha256"],
            reference["sha256"],
        ],
        "complete-code-gate": [foundation_binding["sha256"], code["sha256"]],
        "nine-mode-regression-18-of-18": [
            foundation_binding["sha256"],
            *(item["evidence_sha256"] for item in evidence["regression_results"]),
        ],
        "controlled-qualification-160-of-160": [
            foundation_binding["sha256"],
            controlled["sha256"],
            *(item["evidence_sha256"] for item in evidence["controlled_results"]),
        ],
        _BROWSER_EGRESS_GATE: [
            foundation_binding["sha256"],
            browser_egress["sha256"],
            browser_egress["payload_sha256"],
            browser_egress["expanded_vectors_sha256"],
        ],
        "pilot-derived-final-selection-and-cohort-assembly": [
            evidence["acquisition_completion"]["sha256"],
            canonical_json_sha256(observed_toolchain),
            evidence["final_selection"]["sha256"],
            evidence["final_cohort"]["sha256"],
            evidence["final_cohort_assembly"]["sha256"],
            evidence["pilot_numeric_bundle"]["provenance_sha256"],
            evidence["pilot_compatibility_result"]["evidence_sha256"],
            qualification_authority_sha256,
        ],
        "authoritative-fitting-2000-of-2000": [
            evidence["authoritative_fitting_result"]["evidence_sha256"],
            evidence["authoritative_fitting_bundle"]["provenance_sha256"],
        ],
        "full-live-final-qualification-600-of-600": [
            fitting.provenance["qualification_inputs"]["qualification_manifest_sha256"],
            fitting.provenance["qualification_inputs"]["qualification_bindings_sha256"],
        ],
        "first-launch-certification-900-of-900": [
            evidence["certification_result"]["evidence_sha256"]
        ],
    }
    return {
        "attestation_schema_version": attestation_schema_version,
        "artifact_type": READINESS_RECEIPT_TYPE,
        "study_id": STUDY_ID,
        "cohort_version": cohort_version,
        "implementation_status": READINESS_IMPLEMENTATION_STATUS,
        "promotion_authority": False,
        "implementation_scope": IMPLEMENTATION_SCOPE,
        "paper_equivalent": False,
        "no_waivers": True,
        "source": current_source,
        "build_execution_identity": build_identity,
        "evidence": evidence,
        "summary": {
            "reference_profiles": reference["profiles_checked"],
            "regression_samples": REGRESSION_SAMPLE_COUNT,
            "controlled_samples": CONTROLLED_SAMPLE_COUNT,
            "browser_egress_packet_qualification": "pass",
            "browser_egress_vectors": BROWSER_EGRESS_VECTOR_COUNT,
            "pilot_fitting_samples": pilot_fit["samples"],
            "pilot_compatibility_samples": pilot_compatibility["samples"],
            "acquisition_observed_toolchain_sha256": canonical_json_sha256(observed_toolchain),
            "final_classes": len(selection.final),
            "reserve_classes": len(selection.reserves),
            "authoritative_fitting_samples": fitting_result["samples"],
            "final_qualification_executions": FINAL_QUALIFICATION_EXECUTIONS,
            "certification_samples": certification["samples"],
            "certification_unique_first_launch_pairs": certification[
                "first_launch_unique_class_mode_pairs"
            ],
            "fitted_parameter_sha256": expected_fitted_parameters,
            "certification_defense_parameter_sha256": dict(certification_parameters),
            "certification_defense_runtime_inputs": certification_runtime_inputs,
            "final_qualification_set_manifest_sha256": (final_qualification_manifest_sha256),
            "qualification_authority_sha256": qualification_authority_sha256,
        },
        "hard_gates": _hard_gate_records(_READINESS_GATES, gate_evidence),
        "all_readiness_gates_passed": True,
    }


def _validation_value(
    *,
    readiness_attestation: Path,
    canary_result_roots: Sequence[Path],
    formal_result_roots: Sequence[Path],
    historical_pre_snapshot: Path,
    historical_post_snapshot: Path,
    handoff: Path,
    evaluation_receipt: Path,
    comparison_review: Path,
    deep_code_gate: bool,
) -> dict[str, Any]:
    if type(deep_code_gate) is not bool:
        raise ValueError("class validation deep-code flag must be a boolean")
    readiness = validate_class_readiness_attestation(
        readiness_attestation, deep_code_gate=deep_code_gate
    )
    current_source = source_metadata()
    _validate_immutable_source(current_source, label="current final-attestation source")
    if readiness["source"] != current_source:
        raise ValueError("class validation source differs from class readiness")
    admission = _admission_from_readiness(readiness)

    if (
        len(canary_result_roots) != FORMAL_BLOCK_COUNT
        or len({Path(path).resolve() for path in canary_result_roots}) != FORMAL_BLOCK_COUNT
    ):
        raise ValueError("class validation requires ten unique canary result roots")
    if (
        len(formal_result_roots) != FORMAL_BLOCK_COUNT
        or len({Path(path).resolve() for path in formal_result_roots}) != FORMAL_BLOCK_COUNT
    ):
        raise ValueError("class validation requires ten unique formal result roots")

    from .class_pipeline import verify_class_study_result

    canary_records = []
    formal_records = []
    verified_results = []
    readiness_sha256 = sha256_file(
        _regular_file(readiness_attestation, "class readiness attestation")
    )
    historical_pre_sha256 = sha256_file(
        _regular_file(historical_pre_snapshot, "historical pre snapshot")
    )
    readiness_evidence = readiness.get("evidence")
    readiness_foundation = (
        readiness_evidence.get("foundation") if isinstance(readiness_evidence, Mapping) else None
    )
    foundation_sha256 = (
        readiness_foundation.get("sha256") if isinstance(readiness_foundation, Mapping) else None
    )
    if not isinstance(foundation_sha256, str) or _DIGEST.fullmatch(foundation_sha256) is None:
        raise ValueError("class validation readiness has no exact foundation identity")
    readiness_successor = (
        readiness_evidence.get("successor_restart")
        if isinstance(readiness_evidence, Mapping)
        else None
    )
    successor_sha256 = (
        readiness_successor.get("sha256") if isinstance(readiness_successor, Mapping) else None
    )
    successor_study = is_successor_study_id(readiness.get("study_id"))
    if successor_study != (
        isinstance(successor_sha256, str) and _DIGEST.fullmatch(successor_sha256) is not None
    ):
        raise ValueError("class validation readiness successor identity is incomplete")
    certification_runtime_inputs = _validated_runtime_inputs(
        readiness["summary"].get("certification_defense_runtime_inputs"),
        expected_modes=COMPATIBILITY_MODES,
        label="class readiness certification",
    )
    final_qualification_manifest_sha256 = readiness["summary"].get(
        "final_qualification_set_manifest_sha256"
    )
    if (
        not isinstance(final_qualification_manifest_sha256, str)
        or _DIGEST.fullmatch(final_qualification_manifest_sha256) is None
    ):
        raise ValueError("class validation readiness has no final qualification manifest identity")
    for block, (canary_root, formal_root) in enumerate(
        zip(canary_result_roots, formal_result_roots, strict=True), start=1
    ):
        canary = verify_class_study_result(
            canary_root,
            admission=admission,
            expected_role="canary",
            expected_block=block,
        )
        formal = verify_class_study_result(
            formal_root,
            admission=admission,
            expected_role="formal",
            expected_block=block,
        )
        if canary.get("samples") != FINAL_CLASS_COUNT or formal.get("samples") != 1_600:
            raise ValueError("class validation block sample cardinality is invalid")
        _require_formal_authority_bindings(
            canary,
            formal,
            foundation_sha256=foundation_sha256,
            readiness_sha256=readiness_sha256,
            historical_pre_sha256=historical_pre_sha256,
        )
        if any(
            record.get("class_study_id") != readiness["study_id"]
            or record.get("class_study_successor_sha256") != successor_sha256
            for record in (canary, formal)
        ):
            raise ValueError("class validation block is bound to another study/successor authority")
        certification_parameters = readiness["summary"].get(
            "certification_defense_parameter_sha256"
        )
        expected_formal_parameters = (
            {
                mode: certification_parameters[mode]
                for mode in FORMAL_MODES
                if mode in _PARAMETER_MODES
            }
            if isinstance(certification_parameters, Mapping)
            and set(certification_parameters) == _PARAMETER_MODES
            else None
        )
        if formal.get("defense_parameter_sha256") != expected_formal_parameters:
            raise ValueError("class validation formal block used a different parameter map")
        _require_final_runtime_bindings(
            canary,
            formal,
            block=block,
            certification_runtime_inputs=certification_runtime_inputs,
            final_qualification_manifest_sha256=(final_qualification_manifest_sha256),
        )
        canary_verified = verify_result(Path(canary_root))
        formal_verified = verify_result(Path(formal_root))
        if (
            canary_verified.experiment.get("source") != current_source
            or formal_verified.experiment.get("source") != current_source
        ):
            raise ValueError("class validation block uses a different source")
        _require_canary_before_formal(canary_verified.experiment, formal_verified.experiment)
        canary_records.append(canary)
        formal_records.append(formal)
        verified_results.extend((canary_verified, formal_verified))

    environments = [
        _validate_result_environment(verified, current_source) for verified in verified_results
    ]
    if _one_build_execution_identity(environments) != readiness["build_execution_identity"]:
        raise ValueError("class validation blocks use a different no-cache build")
    if sum(record["samples"] for record in canary_records) != CANARY_SAMPLE_COUNT:
        raise ValueError("class validation canaries are not 1,000/1,000")
    if sum(record["samples"] for record in formal_records) != FORMAL_SAMPLE_COUNT:
        raise ValueError("class validation formal capture is not 16,000/16,000")

    pre = validate_class_historical_snapshot(historical_pre_snapshot, expected_phase="pre-formal")
    post = validate_class_historical_snapshot(
        historical_post_snapshot, expected_phase="post-formal"
    )
    if (
        pre["source"] != current_source
        or post["source"] != current_source
        or pre.get("study_id") != readiness["study_id"]
        or post.get("study_id") != readiness["study_id"]
        or pre["readiness"] != _file_binding(readiness_attestation)
        or post["readiness"] != _file_binding(readiness_attestation)
        or post["pre_formal_snapshot"] != _file_binding(historical_pre_snapshot)
        or post["formal_results"] != [_class_result_binding(path) for path in formal_result_roots]
        or pre["historical_corpus_guard_sha256"] != post["historical_corpus_guard_sha256"]
    ):
        raise ValueError("class validation historical before/after evidence differs")
    pre_time = _aware_timestamp(pre.get("recorded_at"), label="pre-formal snapshot")
    post_time = _aware_timestamp(post.get("recorded_at"), label="post-formal snapshot")
    certification_root = _root_from_result_binding(
        readiness["evidence"]["certification_result"], label="certification result"
    )
    certification_time = _aware_timestamp(
        verify_result(certification_root).experiment.get("completed_at"),
        label="certification completion",
    )
    first_capture_time = min(
        _aware_timestamp(verified.experiment.get("started_at"), label="block start")
        for verified in verified_results
    )
    last_capture_time = max(
        _aware_timestamp(verified.experiment.get("completed_at"), label="block completion")
        for verified in verified_results
    )
    if not certification_time <= pre_time <= first_capture_time or post_time < last_capture_time:
        raise ValueError("class historical snapshots do not bracket formal acquisition")

    handoff_root = verify_class_handoff(handoff, deep=True)
    dataset = _load_regular_json(handoff_root / "dataset.json", "class handoff dataset")
    blocks = dataset.get("blocks")
    embedded_post = dataset.get("historical_post_snapshot")
    if (
        dataset.get("study_id") != readiness["study_id"]
        or dataset.get("sample_count") != FORMAL_SAMPLE_COUNT
        or dataset.get("class_count") != FINAL_CLASS_COUNT
        or dataset.get("modes") != list(FORMAL_MODES)
        or not isinstance(blocks, list)
        or len(blocks) != FORMAL_BLOCK_COUNT
        or [block.get("result_root") for block in blocks]
        != [str(Path(path).resolve()) for path in formal_result_roots]
        or [block.get("result_evidence_sha256") for block in blocks]
        != [record["evidence_sha256"] for record in formal_records]
        or dataset.get("execution_source", {}).get("value") != current_source
        or dataset.get("exporter_source") != current_source
        or embedded_post
        != {
            "path": CLASS_STUDY_HISTORICAL_POST_INPUT,
            "sha256": sha256_file(
                _regular_file(
                    historical_post_snapshot,
                    "historical post snapshot",
                )
            ),
            "payload_sha256": post.get("payload_sha256"),
        }
        or sha256_file(
            _regular_file(
                handoff_root / CLASS_STUDY_HISTORICAL_POST_INPUT,
                "embedded historical post snapshot",
            )
        )
        != embedded_post.get("sha256")
    ):
        raise ValueError("class validation handoff differs from formal source evidence")

    evaluation = class_evaluation.verify_class_evaluation_receipt(
        evaluation_receipt,
        handoff_root=handoff_root,
        deep_verify_handoff=True,
        replay_attacks=True,
    )
    evaluation_completion = _require_evaluation_completion(evaluation, require_full_replay=True)
    if evaluation.get("study_id") != readiness["study_id"]:
        raise ValueError("class evaluation uses another study identity")
    expected_launch_blocks = [
        {
            "block": block,
            "path": f"{CLASS_STUDY_LAUNCHES_PATH}/block-{block:02d}.json",
            "sha256": evidence["class_study_launch_sha256"],
        }
        for block, evidence in enumerate(
            [_class_result_binding(path) for path in formal_result_roots],
            start=1,
        )
    ]
    expected_launches = {
        "source_path": CLASS_STUDY_LAUNCH_INPUT,
        "blocks": expected_launch_blocks,
        "bindings_sha256": canonical_json_sha256(expected_launch_blocks),
    }
    evaluation_handoff = evaluation.get("handoff")
    if (
        evaluation.get("class_study_launches") != expected_launches
        or not isinstance(evaluation_handoff, Mapping)
        or evaluation_handoff.get("class_study_launches_sha256")
        != canonical_json_sha256(expected_launches)
    ):
        raise ValueError("class evaluation first-launch lineage differs from formal results")
    comparison = validate_class_comparison_review(
        comparison_review,
        handoff=handoff_root,
        evaluation_receipt=evaluation_receipt,
    )
    if comparison.get("study_id") != readiness["study_id"]:
        raise ValueError("class comparison review uses another study identity")

    evidence = {
        "readiness": _file_binding(readiness_attestation),
        "canary_results": [_class_result_binding(path) for path in canary_result_roots],
        "formal_results": [_class_result_binding(path) for path in formal_result_roots],
        "historical_pre_snapshot": _file_binding(historical_pre_snapshot),
        "historical_post_snapshot": _file_binding(historical_post_snapshot),
        "handoff": _handoff_binding(handoff_root),
        "evaluation": _file_binding(evaluation_receipt),
        "comparison_review": _file_binding(comparison_review),
    }
    if successor_study:
        evidence["successor_restart"] = dict(readiness_successor)
    gate_evidence = {
        "class-readiness-attestation": [evidence["readiness"]["sha256"]],
        "pre-block-canaries-1000-of-1000": [
            item["evidence_sha256"] for item in evidence["canary_results"]
        ],
        "formal-capture-16000-of-16000": [
            item["evidence_sha256"] for item in evidence["formal_results"]
        ],
        "closed-deep-verified-handoff": [evidence["handoff"]["sha256sums_sha256"]],
        "client-correctness": [evaluation_completion["correctness_sha256"]],
        "performance-and-overhead-reporting": [evaluation_completion["performance_sha256"]],
        "candidate-algorithm-and-transport-reporting": [
            evaluation_completion["candidate_algorithm_sha256"]
        ],
        "dlsvm-capacity-preflight": [
            evaluation_completion["dlsvm_preflight_sha256"],
            evaluation_completion["dlsvm_execution_model_sha256"],
        ],
        "classifier-security-evaluation": [evidence["evaluation"]["sha256"]],
        "original-study-comparison-review": [evidence["comparison_review"]["sha256"]],
        "historical-corpus-before-after-identity": [
            evidence["historical_pre_snapshot"]["sha256"],
            evidence["historical_post_snapshot"]["sha256"],
            post["historical_corpus_guard_sha256"],
        ],
        "current-source-and-no-waiver-promotion": [
            canonical_json_sha256(current_source),
            evidence["readiness"]["sha256"],
            *([evidence["successor_restart"]["sha256"]] if successor_study else []),
        ],
    }
    return {
        "attestation_schema_version": SCHEMA_VERSION,
        "artifact_type": VALIDATION_RECEIPT_TYPE,
        "study_id": readiness["study_id"],
        "cohort_version": readiness["cohort_version"],
        "implementation_status": VALIDATED_STATUS,
        "implementation_status_description": VALIDATED_DESCRIPTION,
        "promotion_authority": True,
        "implementation_scope": IMPLEMENTATION_SCOPE,
        "paper_equivalent": False,
        "no_waivers": True,
        "source": current_source,
        "evidence": evidence,
        "summary": {
            "classes": FINAL_CLASS_COUNT,
            "modes": len(FORMAL_MODES),
            "canary_samples": CANARY_SAMPLE_COUNT,
            "formal_samples": FORMAL_SAMPLE_COUNT,
            "formal_blocks": FORMAL_BLOCK_COUNT,
            "client_correctness": evaluation_completion["correctness"],
            "performance": evaluation_completion["performance"],
            "candidate_algorithm": {
                "sample_count": evaluation_completion["candidate_algorithm"]["sample_count"],
                "sha256": evaluation_completion["candidate_algorithm_sha256"],
            },
            "dlsvm_capacity_preflight": evaluation_completion["dlsvm_preflight"],
            "classifier_result_count": evaluation["result_count"],
            "comparison_reviewed_metrics": comparison["reviewed_metric_count"],
            "historical_corpus_guard_sha256": post["historical_corpus_guard_sha256"],
            "certification_defense_runtime_inputs": certification_runtime_inputs,
            "final_qualification_set_manifest_sha256": (final_qualification_manifest_sha256),
        },
        "hard_gates": _hard_gate_records(_FINAL_GATES, gate_evidence),
        "all_validation_gates_passed": True,
    }


def _historical_snapshot_value(
    *,
    phase: str,
    readiness_attestation: Path,
    formal_result_roots: Sequence[Path],
    pre_snapshot: Path | None,
    recorded_at: object,
) -> dict[str, Any]:
    if phase not in {"pre-formal", "post-formal"}:
        raise ValueError("class historical snapshot phase must be pre-formal or post-formal")
    readiness = validate_class_readiness_attestation(readiness_attestation)
    current_source = source_metadata()
    if current_source != readiness["source"]:
        raise ValueError("class historical snapshot source differs from readiness")
    if recorded_at is None:
        recorded_at = datetime.now(UTC).isoformat()
    timestamp = _aware_timestamp(recorded_at, label=f"historical {phase} snapshot")
    if phase == "pre-formal":
        if formal_result_roots or pre_snapshot is not None:
            raise ValueError("pre-formal class snapshot cannot bind formal results")
        results: list[dict[str, str]] = []
        pre_binding = None
    else:
        if len(formal_result_roots) != FORMAL_BLOCK_COUNT or pre_snapshot is None:
            raise ValueError("post-formal class snapshot requires pre snapshot and ten roots")
        pre = validate_class_historical_snapshot(pre_snapshot, expected_phase="pre-formal")
        if pre["source"] != current_source or pre["readiness"] != _file_binding(
            readiness_attestation
        ):
            raise ValueError("class historical snapshots have different source/readiness")
        results = _validate_post_snapshot_formal_results(
            readiness=readiness,
            readiness_attestation=readiness_attestation,
            pre=pre,
            pre_snapshot=pre_snapshot,
            formal_result_roots=formal_result_roots,
            recorded_at=timestamp,
        )
        pre_binding = _file_binding(pre_snapshot)
    guard = validate_historical_corpus_guard(deep=True)
    return {
        "snapshot_schema_version": SCHEMA_VERSION,
        "artifact_type": HISTORICAL_SNAPSHOT_RECEIPT_TYPE,
        "study_id": readiness["study_id"],
        "phase": phase,
        "recorded_at": timestamp.isoformat(),
        "source": current_source,
        "readiness": _file_binding(readiness_attestation),
        "historical_corpus_guard": guard,
        "historical_corpus_guard_sha256": canonical_json_sha256(guard),
        "pre_formal_snapshot": pre_binding,
        "formal_results": results,
    }


def _validate_post_snapshot_formal_results(
    *,
    readiness: Mapping[str, Any],
    readiness_attestation: Path,
    pre: Mapping[str, Any],
    pre_snapshot: Path,
    formal_result_roots: Sequence[Path],
    recorded_at: datetime,
) -> list[dict[str, str]]:
    """Reconstruct the exact ten formal blocks before publishing post-history.

    A generic sealed class result is not post-formal authority.  This boundary
    repeats the role/block, source, promotion-authority, fitted-input, build,
    and chronology checks so an independently valid pilot/certification result
    cannot advance the handoff gate.
    """

    from .class_pipeline import verify_class_study_result

    admission = _admission_from_readiness(readiness)
    readiness_sha256 = sha256_file(
        _regular_file(readiness_attestation, "class readiness attestation")
    )
    pre_sha256 = sha256_file(_regular_file(pre_snapshot, "historical pre snapshot"))
    evidence = readiness.get("evidence")
    foundation = evidence.get("foundation") if isinstance(evidence, Mapping) else None
    foundation_sha256 = foundation.get("sha256") if isinstance(foundation, Mapping) else None
    if not isinstance(foundation_sha256, str) or _DIGEST.fullmatch(foundation_sha256) is None:
        raise ValueError("post-formal snapshot readiness has no foundation identity")
    certification = evidence.get("certification_result") if isinstance(evidence, Mapping) else None
    certification_root = _root_from_result_binding(certification, label="certification result")
    certification_time = _aware_timestamp(
        verify_result(certification_root).experiment.get("completed_at"),
        label="certification completion",
    )
    pre_time = _aware_timestamp(pre.get("recorded_at"), label="pre-formal snapshot")
    runtime_inputs = _validated_runtime_inputs(
        readiness.get("summary", {}).get("certification_defense_runtime_inputs"),
        expected_modes=COMPATIBILITY_MODES,
        label="post-formal readiness certification",
    )
    qualification_sha256 = readiness.get("summary", {}).get(
        "final_qualification_set_manifest_sha256"
    )
    parameters = readiness.get("summary", {}).get("certification_defense_parameter_sha256")
    if (
        not isinstance(qualification_sha256, str)
        or _DIGEST.fullmatch(qualification_sha256) is None
        or not isinstance(parameters, Mapping)
        or set(parameters) != _PARAMETER_MODES
    ):
        raise ValueError("post-formal snapshot readiness runtime identity is incomplete")
    expected_parameters = {
        mode: parameters[mode] for mode in FORMAL_MODES if mode in _PARAMETER_MODES
    }
    readiness_successor = (
        evidence.get("successor_restart") if isinstance(evidence, Mapping) else None
    )
    successor_sha256 = (
        readiness_successor.get("sha256") if isinstance(readiness_successor, Mapping) else None
    )
    successor_study = is_successor_study_id(readiness.get("study_id"))
    if successor_study != (
        isinstance(successor_sha256, str) and _DIGEST.fullmatch(successor_sha256) is not None
    ):
        raise ValueError("post-formal snapshot successor identity is incomplete")

    bindings: list[dict[str, str]] = []
    verified_results = []
    starts: list[datetime] = []
    completions: list[datetime] = []
    for block, root in enumerate(formal_result_roots, start=1):
        record = verify_class_study_result(
            root,
            admission=admission,
            expected_role="formal",
            expected_block=block,
        )
        expected_authority = {
            "class_study_foundation_sha256": foundation_sha256,
            "class_study_readiness_sha256": readiness_sha256,
            "class_study_historical_pre_snapshot_sha256": pre_sha256,
        }
        if any(record.get(key) != digest for key, digest in expected_authority.items()):
            raise ValueError(
                "post-formal block uses different foundation/readiness/pre-formal authority"
            )
        if (
            record.get("class_study_id") != readiness.get("study_id")
            or record.get("class_study_successor_sha256") != successor_sha256
            or _validated_runtime_inputs(
                record.get("defense_runtime_inputs"),
                expected_modes=FORMAL_MODES,
                label=f"post-formal block {block:02d}",
            )
            != {mode: runtime_inputs[mode] for mode in FORMAL_MODES}
            or record.get("defense_parameter_sha256") != expected_parameters
            or record.get("chaff_qualification_set_manifest_sha256") != qualification_sha256
        ):
            raise ValueError("post-formal block differs from readiness runtime identity")
        verified = verify_result(Path(root))
        if verified.experiment.get("source") != readiness.get("source"):
            raise ValueError("post-formal block uses a different immutable source")
        starts.append(
            _aware_timestamp(
                verified.experiment.get("started_at"),
                label=f"formal block {block:02d} start",
            )
        )
        completions.append(
            _aware_timestamp(
                verified.experiment.get("completed_at"),
                label=f"formal block {block:02d} completion",
            )
        )
        verified_results.append(verified)
        bindings.append(_class_result_binding(Path(root)))

    environments = [
        _validate_result_environment(verified, readiness["source"]) for verified in verified_results
    ]
    if _one_build_execution_identity(environments) != readiness.get("build_execution_identity"):
        raise ValueError("post-formal blocks use a different no-cache build")
    if not certification_time <= pre_time <= min(starts):
        raise ValueError("pre-formal snapshot does not precede the exact formal blocks")
    if recorded_at < max(completions):
        raise ValueError("post-formal snapshot predates formal block completion")
    return bindings


def _comparison_review_value(
    *,
    handoff: Path,
    evaluation_receipt: Path,
    reviewer: object,
    reviewed_at: object,
    reviews: object,
) -> dict[str, Any]:
    if not isinstance(reviewer, str) or not reviewer.strip():
        raise ValueError("class comparison reviewer is required")
    if not isinstance(reviewed_at, str):
        raise TypeError("class comparison review timestamp is required")
    try:
        timestamp = datetime.fromisoformat(reviewed_at)
    except ValueError as error:
        raise ValueError("class comparison review timestamp is invalid") from error
    if timestamp.tzinfo is None:
        raise ValueError("class comparison review timestamp must include a timezone")
    handoff_root = verify_class_handoff(handoff, deep=True)
    evaluation = class_evaluation.verify_class_evaluation_receipt(
        evaluation_receipt,
        handoff_root=handoff_root,
        deep_verify_handoff=True,
        replay_attacks=False,
    )
    _require_evaluation_completion(evaluation, require_full_replay=False)

    historical_rows = list(original_study_comparison_rows())
    inventory = list(historical_anchor_metric_inventory(historical_rows))
    pairs = _comparison_pairs(historical_rows, inventory, evaluation)
    expected = {(pair["defense"], pair["anchor_id"], pair["metric"]): pair for pair in pairs}
    if not isinstance(reviews, Sequence) or isinstance(reviews, (str, bytes)):
        raise TypeError("class comparison reviews must be a sequence")
    normalised: list[dict[str, Any]] = []
    comparison_rows: list[dict[str, Any]] = []
    observed: set[tuple[str, str, str]] = set()
    for raw in reviews:
        if not isinstance(raw, Mapping) or set(raw) != {
            "defense",
            "anchor_id",
            "metric",
            "pair_sha256",
            "disposition",
            "explanation",
            "context_differences",
        }:
            raise ValueError("class comparison review entry schema is invalid")
        record = dict(raw)
        identity = (record["defense"], record["anchor_id"], record["metric"])
        pair = expected.get(identity)
        explanation = record["explanation"]
        explanation_lower = explanation.casefold() if isinstance(explanation, str) else ""
        defense_names = {
            str(record["defense"]).casefold(),
            str(record["defense"]).replace("-", " ").casefold(),
        }
        context_differences = record.get("context_differences")
        qcsd_value = pair.get("qcsd_value") if pair is not None else None
        allowed_dispositions = (
            {"not-comparable"}
            if pair is not None and qcsd_value is None
            else {"expected", "explained", "resolved"}
        )
        required_tokens = (
            str(record["anchor_id"]).casefold(),
            str(record["metric"]).casefold(),
            "published",
            "qcsd",
        )
        if (
            pair is None
            or identity in observed
            or record.get("pair_sha256") != pair["pair_sha256"]
            or record["disposition"] not in allowed_dispositions
            or not isinstance(explanation, str)
            or len(explanation.split()) < 20
            or not any(name in explanation_lower for name in defense_names)
            or any(token not in explanation_lower for token in required_tokens)
            or not isinstance(context_differences, list)
            or context_differences != pair["context_differences"]
            or (qcsd_value is None and "unavailable" not in explanation_lower)
            or (
                qcsd_value is not None
                and (
                    _comparison_number_token(pair["published_value"]) not in explanation_lower
                    or _comparison_number_token(qcsd_value) not in explanation_lower
                )
            )
        ):
            raise ValueError("class comparison review entry is incomplete or unexplained")
        observed.add(identity)
        normalised.append(record)
        comparison_rows.append(
            {
                **pair,
                "review": {
                    "disposition": record["disposition"],
                    "explanation": explanation,
                    "context_differences": context_differences,
                },
            }
        )
    if observed != set(expected):
        raise ValueError("class comparison review omits published anchor metrics")
    normalised.sort(key=lambda row: (row["defense"], row["anchor_id"], row["metric"]))
    comparison_rows.sort(key=lambda row: (row["defense"], row["anchor_id"], row["metric"]))
    discrepancy_count = sum(
        row["absolute_discrepancy"] not in {None, 0.0} for row in comparison_rows
    )
    unavailable_count = sum(row["qcsd_value"] is None for row in comparison_rows)
    return {
        "review_schema_version": SCHEMA_VERSION,
        "artifact_type": COMPARISON_REVIEW_RECEIPT_TYPE,
        "study_id": evaluation.get("study_id", STUDY_ID),
        "implementation_scope": IMPLEMENTATION_SCOPE,
        "paper_equivalent": False,
        "reviewer": reviewer.strip(),
        "reviewed_at": reviewed_at,
        "handoff": _handoff_binding(handoff_root),
        "evaluation": _file_binding(evaluation_receipt),
        "historical_rows_sha256": canonical_json_sha256(historical_rows),
        "historical_anchor_inventory_sha256": canonical_json_sha256(inventory),
        "reviewed_metric_count": len(normalised),
        "reviews": normalised,
        "comparison_rows": comparison_rows,
        "comparison_rows_sha256": canonical_json_sha256(comparison_rows),
        "numeric_discrepancy_count": discrepancy_count,
        "qcsd_metric_unavailable_count": unavailable_count,
        "unexplained_discrepancies": 0,
        "passed": True,
    }


_COMPARISON_CONTEXT_FIELDS = (
    "transport",
    "endpoint_cooperation",
    "dataset_size",
    "visits",
    "observation_layer",
    "header_accounting",
    "padding_variant",
    "early_termination_semantics",
    "overhead_formula",
    "latency_definition",
    "classifier_protocol",
)


def _comparison_pairs(
    historical_rows: Sequence[Mapping[str, Any]],
    inventory: Sequence[Mapping[str, Any]],
    evaluation: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Pair every published scalar with one explicit QCSD metric or unavailability."""

    by_anchor = {str(row["anchor_id"]): row for row in historical_rows}
    pairs: list[dict[str, Any]] = []
    for item in inventory:
        anchor_id = str(item["anchor_id"])
        historical = by_anchor.get(anchor_id)
        if historical is None:
            raise ValueError("class comparison historical inventory is inconsistent")
        defense = "buflo" if anchor_id.startswith("buflo-") else "cs-buflo"
        for metric in item["metric_paths"]:
            published = _nested_metric(historical.get("metrics"), str(metric))
            if type(published) not in {int, float} or not math.isfinite(float(published)):
                raise ValueError("class comparison published metric is not finite")
            qcsd = _qcsd_comparison_metric(
                evaluation,
                defense=defense,
                metric=str(metric),
            )
            qcsd_value = qcsd["value"]
            difference = None if qcsd_value is None else float(qcsd_value) - float(published)
            absolute = None if difference is None else abs(difference)
            relative = (
                None
                if absolute is None or float(published) == 0
                else 100.0 * absolute / abs(float(published))
            )
            published_context = {field: historical[field] for field in _COMPARISON_CONTEXT_FIELDS}
            qcsd_context = _qcsd_comparison_context(
                defense,
                study_id=str(evaluation.get("study_id", STUDY_ID)),
            )
            context_differences = sorted(
                field
                for field in _COMPARISON_CONTEXT_FIELDS
                if published_context[field] != qcsd_context[field]
            )
            if len(context_differences) < 3:
                raise ValueError(
                    "class comparison context lacks the required transport/study contrast"
                )
            pair = {
                "defense": defense,
                "anchor_id": anchor_id,
                "metric": str(metric),
                "published_value": published,
                "qcsd_value": qcsd_value,
                "unit": _comparison_metric_unit(str(metric)),
                "published_formula": _published_metric_formula(historical, str(metric)),
                "qcsd_formula": qcsd["formula"],
                "qcsd_metric_source": qcsd["source"],
                "qcsd_unavailable_reason": qcsd["unavailable_reason"],
                "signed_discrepancy": difference,
                "absolute_discrepancy": absolute,
                "relative_discrepancy_percent": relative,
                "context": {
                    "published": published_context,
                    "qcsd": qcsd_context,
                },
                "context_differences": context_differences,
            }
            pair["pair_sha256"] = canonical_json_sha256(pair)
            pairs.append(pair)
    pairs.sort(key=lambda row: (row["defense"], row["anchor_id"], row["metric"]))
    return pairs


def _nested_metric(value: object, dotted: str) -> object:
    cursor = value
    for component in dotted.split("."):
        if not isinstance(cursor, Mapping) or component not in cursor:
            raise ValueError(f"class comparison metric path is absent: {dotted}")
        cursor = cursor[component]
    return cursor


def _qcsd_comparison_metric(
    evaluation: Mapping[str, Any], *, defense: str, metric: str
) -> dict[str, Any]:
    performance = evaluation.get("performance")
    paired = performance.get("paired_by_mode") if isinstance(performance, Mapping) else None
    mode = paired.get(defense) if isinstance(paired, Mapping) else None
    if not isinstance(mode, Mapping):
        raise ValueError(f"class comparison lacks {defense} performance metrics")
    performance_paths = {
        "bandwidth_ratio": (
            "wire_ratio_of_sums",
            "sum(defended observer-frame bytes)/sum(paired undefended observer-frame bytes)",
        ),
        "extra_bandwidth_percent": (
            "additional_wire_percent",
            (
                "100*(sum(defended observer-frame bytes)/"
                "sum(paired undefended observer-frame bytes)-1)"
            ),
        ),
        "latency_ratio": (
            "duration_ratio_of_sums",
            (
                "sum(defended application completion seconds)/"
                "sum(paired undefended completion seconds)"
            ),
        ),
    }
    if metric in performance_paths:
        key, formula = performance_paths[metric]
        value = mode.get(key)
        return _available_qcsd_metric(
            value,
            formula=formula,
            source=f"performance.paired_by_mode.{defense}.{key}",
        )
    if metric == "latency_seconds":
        quantiles = mode.get("added_seconds_pair_quantiles")
        value = quantiles.get("p50") if isinstance(quantiles, Mapping) else None
        return _available_qcsd_metric(
            value,
            formula="median(defended completion seconds - paired undefended completion seconds)",
            source=f"performance.paired_by_mode.{defense}.added_seconds_pair_quantiles.p50",
        )

    attack = None
    if metric in {"panchenko_percent", "accuracy.panchenko.mean_percent"}:
        attack = "panchenko"
    elif metric in {"vng_plus_plus_percent", "accuracy.vng_plus_plus.mean_percent"}:
        attack = "vngpp"
    elif metric == "dlsvm_percent":
        attack = "dlsvm"
    elif metric in {
        "accuracy.panchenko.plus_minus_percent",
        "accuracy.vng_plus_plus.plus_minus_percent",
    }:
        attack = "panchenko" if "panchenko" in metric else "vngpp"
    if attack is not None:
        result = _primary_adaptive_attack_result(evaluation, defense=defense, attack=attack)
        if metric.endswith("plus_minus_percent"):
            bootstrap = result.get("block_workload_bootstrap_95")
            intervals = bootstrap.get("bootstrap_95") if isinstance(bootstrap, Mapping) else None
            accuracy = intervals.get("accuracy") if isinstance(intervals, Mapping) else None
            low = accuracy.get("low") if isinstance(accuracy, Mapping) else None
            high = accuracy.get("high") if isinstance(accuracy, Mapping) else None
            point = result.get("accuracy")
            if not all(type(value) in {int, float} for value in (low, high, point)):
                raise ValueError("class comparison classifier interval is incomplete")
            value = 100.0 * max(float(point) - float(low), float(high) - float(point))
            return _available_qcsd_metric(
                value,
                formula=(
                    "maximum half-width of the 95% acquisition-block/workload "
                    "bootstrap accuracy interval"
                ),
                source=(
                    f"results[{attack},{defense},temporal-heldout-test-adaptive]."
                    "block_workload_bootstrap_95.bootstrap_95.accuracy"
                ),
            )
        return _available_qcsd_metric(
            100.0 * float(result["accuracy"]),
            formula="100*held-out block-10 adaptive-attacker accuracy",
            source=f"results[{attack},{defense},temporal-heldout-test-adaptive].accuracy",
        )

    return {
        "value": None,
        "formula": "not evaluated by the registered QCSD attack inventory",
        "source": None,
        "unavailable_reason": (
            "the final QCSD matrix contains Panchenko, VNG++, and DLSVM only; "
            f"there is no registered QCSD counterpart for {metric}"
        ),
    }


def _available_qcsd_metric(value: object, *, formula: str, source: str) -> dict[str, Any]:
    if type(value) not in {int, float} or not math.isfinite(float(value)):
        raise ValueError(f"class comparison QCSD metric is unavailable: {source}")
    return {
        "value": value,
        "formula": formula,
        "source": source,
        "unavailable_reason": None,
    }


def _primary_adaptive_attack_result(
    evaluation: Mapping[str, Any], *, defense: str, attack: str
) -> Mapping[str, Any]:
    results = evaluation.get("results")
    if not isinstance(results, list):
        raise ValueError("class comparison evaluation has no classifier results")
    matches = [
        result
        for result in results
        if isinstance(result, Mapping)
        and result.get("attack") == attack
        and result.get("training_defense") == defense
        and result.get("testing_defense") == defense
        and result.get("protocol") == "temporal-heldout-test-adaptive"
    ]
    if len(matches) != 1:
        raise ValueError(
            f"class comparison requires one {attack}/{defense} primary adaptive result"
        )
    return matches[0]


def _comparison_metric_unit(metric: str) -> str:
    if metric in {"bandwidth_ratio", "latency_ratio"}:
        return "multiplicative-ratio"
    if metric == "latency_seconds":
        return "seconds"
    return "percentage-points"


def _published_metric_formula(historical: Mapping[str, Any], metric: str) -> str:
    if metric in {"bandwidth_ratio", "extra_bandwidth_percent"}:
        return str(historical["overhead_formula"])
    if metric in {"latency_ratio", "latency_seconds"}:
        return str(historical["latency_definition"])
    return str(historical["classifier_protocol"])


def _qcsd_comparison_context(defense: str, *, study_id: str = STUDY_ID) -> dict[str, str]:
    return {
        "transport": "client-only QUIC/HTTP/3 QCSD adaptation over UDP",
        "endpoint_cooperation": (
            "ordinary unmodified HTTP/3 servers; client-only shaping and standard QUIC chaff/credit"
        ),
        "dataset_size": (f"closed-world 100-class {study_id} formal corpus with 16,000 samples"),
        "visits": "two paired visits per class and mode in each of ten acquisition blocks",
        "observation_layer": (
            "capture-interface Ethernet observer-frame timestamp, direction, and length"
        ),
        "header_accounting": (
            "captured observer-frame wire bytes; separate UDP-payload accounting is reported"
        ),
        "padding_variant": (
            "canonical live BuFLO rho=20ms,tau=10s,1200-byte UDP-payload adaptation"
            if defense == "buflo"
            else "canonical CTSP CS-BuFLO 600-byte UDP-payload client-only adaptation"
        ),
        "early_termination_semantics": (
            "inclusive client-local BuFLO minimum duration and terminal drain"
            if defense == "buflo"
            else "client-local quiet/power-of-two stop and drain; no server padding-complete signal"
        ),
        "overhead_formula": (
            "ratio of sums over paired defended and undefended observer-frame bytes; "
            "additional percent is 100*(ratio-1)"
        ),
        "latency_definition": (
            "paired application completion-time ratio and added seconds; the "
            "comparison row uses the declared metric source"
        ),
        "classifier_protocol": (
            "primary adaptive attacker trained on blocks 1-8, validated on block 9, "
            "and tested once on held-out block 10"
        ),
    }


def _comparison_number_token(value: int | float) -> str:
    return format(float(value), ".12g").casefold()


def _require_candidate_algorithm_completion(
    value: Any,
    *,
    classes: Sequence[str],
    classes_sha256: str,
) -> dict[str, Any]:
    """Require complete candidate diagnostics over every formal class stratum."""

    candidate_modes = ("buflo", "cs-buflo")
    expected_blocks = tuple(range(1, FORMAL_BLOCK_COUNT + 1))
    expected_directions = ("outgoing", "incoming")
    coverage = value.get("coverage") if isinstance(value, Mapping) else None
    checks = value.get("checks") if isinstance(value, Mapping) else None
    breakdowns = value.get("breakdowns") if isinstance(value, Mapping) else None
    if (
        not isinstance(value, Mapping)
        or value.get("schema_version") != 1
        or value.get("passed") is not True
        or value.get("sample_count") != 4_000
        or not isinstance(coverage, Mapping)
        or coverage.get("class_count") != FINAL_CLASS_COUNT
        or coverage.get("classes_sha256") != classes_sha256
        or coverage.get("modes") != list(candidate_modes)
        or coverage.get("acquisition_blocks") != list(expected_blocks)
        or coverage.get("visits_per_class_mode_block") != FORMAL_VISITS_PER_BLOCK
        or coverage.get("directions") != list(expected_directions)
        or coverage.get("diagnostic_schema_versions") != [4]
        or checks
        != {
            "run_schedule_events_packets_rederived": True,
            "classifier_input": False,
            "current_schema_required": True,
        }
        or not isinstance(breakdowns, Mapping)
        or breakdowns.get("available") is not True
        or breakdowns.get("classifier_input") is not False
        or breakdowns.get("schema_version") != 3
    ):
        raise ValueError("class evaluation lacks complete candidate algorithm/transport evidence")

    strata = breakdowns.get("strata")
    expected_strata = {
        (mode, class_label, block, direction)
        for mode in candidate_modes
        for class_label in classes
        for block in expected_blocks
        for direction in expected_directions
    }
    required_directional = {
        "target_size_histogram",
        "desired_udp_bytes",
        "observed_udp_bytes",
        "target_realization_ratio",
        "satisfaction_counts",
        "congestion_reason_counts",
        "traffic_composition_bytes",
        "inter_target_delta_us",
        "estimated_jitter_us",
        "scheduling_lateness_us",
        "receive_credit_advertisement",
        "receive_credit_consumption",
        "inferred_rate_transition_count",
        "inferred_rate_transition_histogram",
        "cs_buflo",
    }
    if not isinstance(strata, list) or len(strata) != len(expected_strata):
        raise ValueError("class evaluation candidate directional coverage is incomplete")
    actual_strata: set[tuple[Any, ...]] = set()
    for row in strata:
        if (
            not isinstance(row, Mapping)
            or row.get("samples") != FORMAL_VISITS_PER_BLOCK
            or not required_directional <= set(row)
            or not isinstance(row.get("target_size_histogram"), Mapping)
            or not isinstance(row.get("satisfaction_counts"), Mapping)
            or not isinstance(row.get("congestion_reason_counts"), Mapping)
            or not isinstance(row.get("traffic_composition_bytes"), Mapping)
            or not isinstance(row.get("receive_credit_advertisement"), Mapping)
            or not isinstance(row.get("receive_credit_consumption"), Mapping)
        ):
            raise ValueError("class evaluation candidate directional row is invalid")
        identity = (
            row.get("defense"),
            row.get("workload_id"),
            row.get("acquisition_block_index"),
            row.get("direction"),
        )
        actual_strata.add(identity)
        if (row.get("defense") == "cs-buflo" and not isinstance(row.get("cs_buflo"), Mapping)) or (
            row.get("defense") == "buflo" and row.get("cs_buflo") is not None
        ):
            raise ValueError("class evaluation CS-BuFLO diagnostic coverage is invalid")
    if actual_strata != expected_strata:
        raise ValueError("class evaluation candidate directional identities are incomplete")

    grouped_expectations = (
        ("buflo_terminal_tail_strata", "buflo"),
        ("buflo_schedule_stop_strata", "buflo"),
        ("cs_buflo_local_termination_strata", "cs-buflo"),
    )
    for field, mode in grouped_expectations:
        rows = breakdowns.get(field)
        expected = {
            (mode, class_label, block) for class_label in classes for block in expected_blocks
        }
        if (
            not isinstance(rows, list)
            or len(rows) != len(expected)
            or {
                (
                    row.get("defense"),
                    row.get("workload_id"),
                    row.get("acquisition_block_index"),
                )
                for row in rows
                if isinstance(row, Mapping) and row.get("samples") == FORMAL_VISITS_PER_BLOCK
            }
            != expected
        ):
            raise ValueError(f"class evaluation {field} coverage is incomplete")
    return dict(value)


def _require_evaluation_completion(
    value: Mapping[str, Any], *, require_full_replay: bool
) -> dict[str, Any]:
    """Require immutable correctness/performance plus complete classifier replay."""

    if not isinstance(value, Mapping):
        raise TypeError("class evaluation verification did not return an object")
    correctness = value.get("correctness")
    performance = value.get("performance")
    classes = value.get("classes")
    if (
        not isinstance(classes, list)
        or len(classes) != FINAL_CLASS_COUNT
        or len(set(classes)) != FINAL_CLASS_COUNT
        or any(not isinstance(item, str) or not item for item in classes)
    ):
        raise ValueError("class evaluation class inventory is incomplete")
    correctness_coverage = correctness.get("coverage") if isinstance(correctness, Mapping) else None
    correctness_checks = correctness.get("checks") if isinstance(correctness, Mapping) else None
    expected_blocks = list(range(1, FORMAL_BLOCK_COUNT + 1))
    if (
        not isinstance(correctness, Mapping)
        or correctness.get("schema_version") != 1
        or correctness.get("passed") is not True
        or correctness.get("sample_count") != FORMAL_SAMPLE_COUNT
        or correctness.get("passed_samples") != FORMAL_SAMPLE_COUNT
        or not isinstance(correctness_coverage, Mapping)
        or correctness_coverage.get("class_count") != FINAL_CLASS_COUNT
        or _DIGEST.fullmatch(str(correctness_coverage.get("classes_sha256"))) is None
        or correctness_coverage.get("modes") != list(FORMAL_MODES)
        or correctness_coverage.get("acquisition_blocks") != expected_blocks
        or correctness_coverage.get("visits_per_class_mode_block") != 2
        or correctness_checks
        != {
            "prepared_response_identity": "exact",
            "defense_fidelity": "independently-recomputed-eligible",
            "exact_receipt_match": True,
        }
    ):
        raise ValueError("class evaluation lacks complete client-correctness evidence")
    expected_metrics = [
        "ratio-of-sums wire and UDP-payload overhead",
        "packet-count overhead",
        "paired completion ratio and added seconds",
        "paired goodput",
        "client CPU, wall time, RSS, context switches, and timer wakeups",
        "transport retransmissions",
        "nullable RAPL energy",
        "direction/workload/acquisition-block breakdowns",
    ]
    performance_coverage = performance.get("coverage") if isinstance(performance, Mapping) else None
    bootstrap = performance.get("bootstrap") if isinstance(performance, Mapping) else None
    rapl = performance.get("rapl") if isinstance(performance, Mapping) else None
    paired = performance.get("paired_by_mode") if isinstance(performance, Mapping) else None
    breakdowns = performance.get("breakdowns") if isinstance(performance, Mapping) else None
    defended_modes = set(FORMAL_MODES) - {"undefended"}
    rapl_available = rapl.get("available_samples") if isinstance(rapl, Mapping) else None
    rapl_unavailable = rapl.get("unavailable_samples") if isinstance(rapl, Mapping) else None
    if (
        not isinstance(performance, Mapping)
        or performance.get("schema_version") != 1
        or performance.get("passed") is not True
        or performance.get("sample_count") != FORMAL_SAMPLE_COUNT
        or performance.get("complete_samples") != FORMAL_SAMPLE_COUNT
        or not isinstance(performance_coverage, Mapping)
        or performance_coverage.get("class_count") != FINAL_CLASS_COUNT
        or performance_coverage.get("modes") != list(FORMAL_MODES)
        or performance_coverage.get("acquisition_blocks") != expected_blocks
        or performance_coverage.get("paired_visits") != 2_000
        or performance_coverage.get("defended_baseline_pairs") != 14_000
        or bootstrap
        != {
            "draws": 10_000,
            "seed": class_evaluation.FORMAL_BOOTSTRAP_SEED,
            "cluster": "acquisition_block+workload_id",
            "resampling": "joint-cluster-with-replacement",
        }
        or performance.get("metric_inventory") != expected_metrics
        or not isinstance(rapl, Mapping)
        or rapl.get("nullable") is not True
        or type(rapl_available) is not int
        or type(rapl_unavailable) is not int
        or rapl_available + rapl_unavailable != FORMAL_SAMPLE_COUNT
        or not isinstance(rapl.get("unavailable_reasons"), list)
        or not isinstance(paired, Mapping)
        or set(paired) != defended_modes
        or any(
            not isinstance(record, Mapping)
            or record.get("performance_evidence_available") is not True
            for record in paired.values()
        )
        or not isinstance(breakdowns, Mapping)
        or not isinstance(breakdowns.get("directional"), Mapping)
        or not breakdowns["directional"]
        or not isinstance(breakdowns.get("client"), Mapping)
        or not breakdowns["client"]
    ):
        raise ValueError("class evaluation lacks complete performance/overhead evidence")
    candidate_algorithm = _require_candidate_algorithm_completion(
        value.get("candidate_algorithm"),
        classes=classes,
        classes_sha256=str(correctness_coverage["classes_sha256"]),
    )
    preflight = value.get("dlsvm_capacity_preflight")
    if (
        not isinstance(preflight, Mapping)
        or set(preflight)
        != {
            "schema_version",
            "artifact_type",
            "path",
            "sha256",
            "workload_sha256",
            "projection_sha256",
            "execution_model",
            "execution_model_sha256",
            "admission",
        }
        or preflight.get("schema_version") != 2
        or preflight.get("artifact_type") != "qcsd-dlsvm-native-capacity-preflight"
        or not isinstance(preflight.get("path"), str)
        or _DIGEST.fullmatch(str(preflight.get("sha256"))) is None
        or _DIGEST.fullmatch(str(preflight.get("workload_sha256"))) is None
        or _DIGEST.fullmatch(str(preflight.get("projection_sha256"))) is None
        or preflight.get("execution_model") != class_evaluation.CLASS_DLSVM_EXECUTION_MODEL
        or preflight.get("execution_model_sha256")
        != class_evaluation.CLASS_DLSVM_EXECUTION_MODEL_SHA256
        or preflight.get("admission")
        != {
            "wall_time_available": True,
            "memory_available": True,
            "cache_storage_available": True,
        }
    ):
        raise ValueError("class evaluation lacks an admitted DLSVM capacity preflight")
    if (
        value.get("sample_count") != FORMAL_SAMPLE_COUNT
        or value.get("class_count") != FINAL_CLASS_COUNT
        or value.get("modes") != list(FORMAL_MODES)
        or not isinstance(value.get("result_count"), int)
        or value["result_count"] <= 0
    ):
        raise ValueError("class evaluation classifier evidence is incomplete")
    strength = value.get("verification_strength")
    if require_full_replay and (
        not isinstance(strength, Mapping)
        or strength.get("level") != "full-replay"
        or strength.get("deep_handoff") is not True
        or strength.get("classic_pcap_regenerated") is not True
        or strength.get("correctness_recomputed") is not True
        or strength.get("performance_summary_recomputed") is not True
        or strength.get("performance_raw_evidence_recomputed") is not True
        or strength.get("dlsvm_all_matrix_cells_recomputed") is not True
        or strength.get("dlsvm_capacity_preflight_revalidated") is not True
        or strength.get("dlsvm_current_capacity_admitted") is not True
        or strength.get("dlsvm_execution_model_sha256")
        != class_evaluation.CLASS_DLSVM_EXECUTION_MODEL_SHA256
        or strength.get("candidate_algorithm_diagnostics_rederived") is not True
        or strength.get("classifier_attacks_replayed") is not True
        or strength.get("limitations") != []
        or strength.get("authorizes_final_attestation") is not False
    ):
        raise ValueError("class evaluation was not fully and deeply replayed")
    return {
        "correctness": dict(correctness),
        "performance": dict(performance),
        "candidate_algorithm": candidate_algorithm,
        "dlsvm_preflight": dict(preflight),
        "correctness_sha256": canonical_json_sha256(correctness),
        "performance_sha256": canonical_json_sha256(performance),
        "candidate_algorithm_sha256": canonical_json_sha256(candidate_algorithm),
        "dlsvm_preflight_sha256": str(preflight["sha256"]),
        "dlsvm_execution_model_sha256": str(preflight["execution_model_sha256"]),
    }


def _readiness_kwargs(payload: Mapping[str, Any]) -> dict[str, Any]:
    evidence = payload.get("evidence")
    if not isinstance(evidence, Mapping):
        raise TypeError("class-readiness typed evidence is missing")
    qualification = evidence.get("qualification_context")
    if not isinstance(qualification, Mapping):
        raise TypeError("class-readiness qualification context is missing")
    return {
        "foundation_attestation": _path_from_binding(
            evidence.get("foundation"), label="foundation"
        ),
        "cohort_version": payload.get("cohort_version"),
        "build_execution_receipt": _path_from_binding(
            evidence.get("build_execution"), label="build execution"
        ),
        "reference_receipt": _path_from_binding(evidence.get("reference"), label="reference"),
        "code_gate_receipt": _path_from_binding(evidence.get("code_gate"), label="code gate"),
        "controlled_qualification_receipt": _path_from_binding(
            evidence.get("controlled_qualification"), label="controlled qualification"
        ),
        "regression_result_roots": _roots_from_bindings(evidence.get("regression_results")),
        "controlled_result_roots": _roots_from_bindings(evidence.get("controlled_results")),
        "candidate_catalogue": _path_from_binding(
            evidence.get("candidate_catalogue"), label="candidate catalogue"
        ),
        "stability_root": _root_from_directory_binding(
            evidence.get("stability_root"), label="stability root"
        ),
        "workload_root": _root_from_directory_binding(
            evidence.get("workload_root"), label="workload root"
        ),
        "acquisition_completion": _path_from_binding(
            evidence.get("acquisition_completion"), label="acquisition completion"
        ),
        "pilot_cohort_receipt": _path_from_binding(
            evidence.get("pilot_cohort"), label="pilot cohort"
        ),
        "pilot_cohort_assembly": _path_from_binding(
            evidence.get("pilot_cohort_assembly"), label="pilot cohort assembly"
        ),
        "pilot_fitting_result_root": _root_from_result_binding(
            evidence.get("pilot_fitting_result"), label="pilot fitting result"
        ),
        "pilot_numeric_bundle_root": _root_from_bundle_binding(
            evidence.get("pilot_numeric_bundle"), label="pilot numeric bundle"
        ),
        "pilot_compatibility_result_root": _root_from_result_binding(
            evidence.get("pilot_compatibility_result"), label="pilot compatibility result"
        ),
        "final_selection_receipt": _path_from_binding(
            evidence.get("final_selection"), label="final selection"
        ),
        "final_cohort_receipt": _path_from_binding(
            evidence.get("final_cohort"), label="final cohort"
        ),
        "final_cohort_assembly": _path_from_binding(
            evidence.get("final_cohort_assembly"), label="final cohort assembly"
        ),
        "authoritative_fitting_result_root": _root_from_result_binding(
            evidence.get("authoritative_fitting_result"),
            label="authoritative fitting result",
        ),
        "authoritative_fitting_bundle_root": _root_from_bundle_binding(
            evidence.get("authoritative_fitting_bundle"),
            label="authoritative fitting bundle",
        ),
        "qualification_workload_root": _root_from_directory_binding(
            qualification.get("workload_root"), label="qualification workload root"
        ),
        "qualification_sidecar_root": _root_from_directory_binding(
            qualification.get("sidecar_root"), label="qualification sidecar root"
        ),
        "qualification_prefix_root": _root_from_directory_binding(
            qualification.get("prefix_spec_root"), label="qualification prefix root"
        ),
        "certification_result_root": _root_from_result_binding(
            evidence.get("certification_result"), label="certification result"
        ),
    }


def _validation_kwargs(payload: Mapping[str, Any]) -> dict[str, Any]:
    evidence = payload.get("evidence")
    if not isinstance(evidence, Mapping):
        raise TypeError("class validation typed evidence is missing")
    handoff = evidence.get("handoff")
    if not isinstance(handoff, Mapping) or not isinstance(handoff.get("root"), str):
        raise TypeError("class validation handoff root is missing")
    return {
        "readiness_attestation": _path_from_binding(evidence.get("readiness"), label="readiness"),
        "canary_result_roots": _roots_from_bindings(evidence.get("canary_results")),
        "formal_result_roots": _roots_from_bindings(evidence.get("formal_results")),
        "historical_pre_snapshot": _path_from_binding(
            evidence.get("historical_pre_snapshot"), label="historical pre snapshot"
        ),
        "historical_post_snapshot": _path_from_binding(
            evidence.get("historical_post_snapshot"), label="historical post snapshot"
        ),
        "handoff": Path(handoff["root"]),
        "evaluation_receipt": _path_from_binding(evidence.get("evaluation"), label="evaluation"),
        "comparison_review": _path_from_binding(
            evidence.get("comparison_review"), label="comparison review"
        ),
    }


def _admission_from_readiness(readiness: Mapping[str, Any]) -> Any:
    from .class_pipeline import (
        verify_cohort_admission,
        verify_successor_cohort_admission,
    )

    study_id = readiness.get("study_id")
    if is_successor_study_id(study_id):
        evidence = readiness.get("evidence")
        restart = evidence.get("successor_restart") if isinstance(evidence, Mapping) else None
        return verify_successor_cohort_admission(
            _path_from_binding(restart, label="successor restart")
        )

    kwargs = _readiness_kwargs(readiness)
    return verify_cohort_admission(
        kwargs["final_cohort_receipt"],
        kwargs["final_cohort_assembly"],
        candidate_catalogue_path=kwargs["candidate_catalogue"],
        stability_root=kwargs["stability_root"],
        workload_root=kwargs["workload_root"],
        acquisition_completion_path=kwargs["acquisition_completion"],
        final_selection_receipt_path=kwargs["final_selection_receipt"],
    )


def _validate_readiness_envelope(
    payload: Mapping[str, Any], *, allow_historical: bool = False
) -> None:
    schema_version = payload.get("attestation_schema_version")
    if (
        schema_version
        not in {HISTORICAL_READINESS_SCHEMA_VERSION, READINESS_SCHEMA_VERSION}
        or (
            schema_version == HISTORICAL_READINESS_SCHEMA_VERSION
            and not allow_historical
        )
        or payload.get("artifact_type") != READINESS_RECEIPT_TYPE
        or payload.get("study_id") != STUDY_ID
        or payload.get("implementation_status") != READINESS_IMPLEMENTATION_STATUS
        or payload.get("promotion_authority") is not False
        or payload.get("implementation_scope") != IMPLEMENTATION_SCOPE
        or payload.get("paper_equivalent") is not False
        or payload.get("no_waivers") is not True
        or payload.get("all_readiness_gates_passed") is not True
    ):
        raise ValueError("class-readiness promotion envelope is invalid")
    _validate_hard_gates(payload.get("hard_gates"), _READINESS_GATES)


def _validate_foundation_envelope(
    payload: Mapping[str, Any], *, allow_historical: bool = False
) -> None:
    schema_version = payload.get("attestation_schema_version")
    if (
        schema_version
        not in {HISTORICAL_FOUNDATION_SCHEMA_VERSION, FOUNDATION_SCHEMA_VERSION}
        or (
            schema_version == HISTORICAL_FOUNDATION_SCHEMA_VERSION
            and not allow_historical
        )
        or payload.get("artifact_type") != FOUNDATION_RECEIPT_TYPE
        or payload.get("study_id") != STUDY_ID
        or payload.get("implementation_status") != "foundation-ready-for-class-acquisition"
        or payload.get("promotion_authority") is not False
        or payload.get("implementation_scope") != IMPLEMENTATION_SCOPE
        or payload.get("paper_equivalent") is not False
        or payload.get("no_waivers") is not True
        or payload.get("all_foundation_gates_passed") is not True
    ):
        raise ValueError("class foundation promotion envelope is invalid")
    _aware_timestamp(payload.get("recorded_at"), label="foundation attestation")
    _validate_hard_gates(payload.get("hard_gates"), _FOUNDATION_GATES)


def _validate_validation_envelope(payload: Mapping[str, Any]) -> None:
    study_id = payload.get("study_id")
    if (
        payload.get("attestation_schema_version") != SCHEMA_VERSION
        or payload.get("artifact_type") != VALIDATION_RECEIPT_TYPE
        or not is_class_study_id(study_id)
        or payload.get("implementation_status") != VALIDATED_STATUS
        or payload.get("implementation_status_description") != VALIDATED_DESCRIPTION
        or payload.get("promotion_authority") is not True
        or payload.get("implementation_scope") != IMPLEMENTATION_SCOPE
        or payload.get("paper_equivalent") is not False
        or payload.get("no_waivers") is not True
        or payload.get("all_validation_gates_passed") is not True
    ):
        raise ValueError("class validation promotion envelope is invalid")
    _validate_hard_gates(payload.get("hard_gates"), _FINAL_GATES)


def _hard_gate_records(
    identities: Sequence[str], evidence: Mapping[str, Sequence[str]]
) -> list[dict[str, Any]]:
    records = []
    for ordinal, identity in enumerate(identities, start=1):
        digests = sorted(set(evidence.get(identity, ())))
        if not digests or any(_DIGEST.fullmatch(digest) is None for digest in digests):
            raise ValueError(f"hard gate has no valid evidence: {identity}")
        records.append(
            {
                "ordinal": ordinal,
                "gate": identity,
                "gate_identity_sha256": canonical_json_sha256(
                    {"ordinal": ordinal, "gate": identity}
                ),
                "result": "pass",
                "evidence_sha256s": digests,
            }
        )
    return records


def _validate_hard_gates(value: object, identities: Sequence[str]) -> None:
    if not isinstance(value, list) or len(value) != len(identities):
        raise ValueError("class attestation hard-gate inventory is incomplete")
    required = {
        "ordinal",
        "gate",
        "gate_identity_sha256",
        "result",
        "evidence_sha256s",
    }
    for ordinal, (record, identity) in enumerate(zip(value, identities, strict=True), start=1):
        evidence = record.get("evidence_sha256s") if isinstance(record, Mapping) else None
        if (
            not isinstance(record, Mapping)
            or set(record) != required
            or record.get("ordinal") != ordinal
            or record.get("gate") != identity
            or record.get("gate_identity_sha256")
            != canonical_json_sha256({"ordinal": ordinal, "gate": identity})
            or record.get("result") != "pass"
            or not isinstance(evidence, list)
            or not evidence
            or evidence != sorted(set(evidence))
            or any(
                not isinstance(item, str) or _DIGEST.fullmatch(item) is None for item in evidence
            )
        ):
            raise ValueError(f"class attestation hard gate is invalid: {ordinal}")


def _validate_immutable_source(value: object, *, label: str) -> None:
    expected = {
        "image_digest",
        "lab_commit",
        "lab_dirty",
        "lab_patch_sha256",
        "neqo_commit",
        "neqo_pinned_commit",
        "neqo_dirty",
        "neqo_patch_sha256",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != expected
        or _IMAGE_DIGEST.fullmatch(str(value.get("image_digest"))) is None
        or _COMMIT.fullmatch(str(value.get("lab_commit"))) is None
        or _COMMIT.fullmatch(str(value.get("neqo_commit"))) is None
        or value.get("neqo_commit") != value.get("neqo_pinned_commit")
        or value.get("lab_dirty") is not False
        or value.get("neqo_dirty") is not False
        or value.get("lab_patch_sha256") != _EMPTY_SHA256
        or value.get("neqo_patch_sha256") != _EMPTY_SHA256
    ):
        raise ValueError(f"{label} is not one clean immutable collection image")


def _validate_foundation_runtime(
    payload: Mapping[str, Any],
    *,
    runtime_role: str,
    build_execution_receipt: Path,
    allow_historical: bool = False,
) -> None:
    if runtime_role not in {"collection", "prepare"}:
        raise ValueError("class foundation runtime role is invalid")
    bound_source = payload.get("source")
    if not isinstance(bound_source, Mapping):
        raise TypeError("class foundation has no bound source")
    build = validate_build_execution_receipt(
        build_execution_receipt,
        expected_collection_image=str(bound_source.get("image_digest")),
        expected_cohort_version=payload.get("cohort_version"),
        allow_historical=allow_historical,
    )
    runtime_source = source_metadata()
    expected = dict(bound_source)
    if runtime_role == "prepare":
        expected["image_digest"] = build["images"]["prepare"]["id"]
    if runtime_source != expected:
        raise ValueError(f"class foundation {runtime_role} runtime differs from its no-cache build")


def _require_acquisition_toolchain(
    value: object,
    *,
    source: Mapping[str, Any],
    build_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Require acquisition observations from the attested image/Neqo source."""

    if not isinstance(value, Mapping) or set(value) != {
        "chromium_version",
        "neqo_provenance",
        "image_digest",
        "source",
    }:
        raise ValueError("class acquisition observed toolchain is incomplete")
    neqo = value.get("neqo_provenance")
    images = build_receipt.get("images")
    prepare = images.get("prepare") if isinstance(images, Mapping) else None
    prepare_image = prepare.get("id") if isinstance(prepare, Mapping) else None
    acquisition_source = {**source, "image_digest": prepare_image}
    if (
        not isinstance(value.get("chromium_version"), str)
        or value["chromium_version"] != EXPECTED_CHROMIUM_VERSION
        or _IMAGE_DIGEST.fullmatch(str(prepare_image)) is None
        or value.get("image_digest") != prepare_image
        or value.get("source") != acquisition_source
        or not isinstance(neqo, Mapping)
        or set(neqo)
        != {
            "neqo_version",
            "neqo_base_commit",
            "published_qcsd_commit",
            "migration_commit",
        }
        or not isinstance(neqo.get("neqo_version"), str)
        or not str(neqo["neqo_version"]).strip()
        or any(
            not isinstance(neqo.get(key), str) or _COMMIT.fullmatch(str(neqo[key])) is None
            for key in (
                "neqo_base_commit",
                "published_qcsd_commit",
                "migration_commit",
            )
        )
        or neqo.get("migration_commit") != source.get("neqo_commit")
        or source.get("neqo_commit") != source.get("neqo_pinned_commit")
    ):
        raise ValueError("class acquisition observed toolchain differs from current source/build")
    return dict(value)


def _require_current_acquisition_completion(value: object) -> dict[str, Any]:
    """Keep historical acquisition evidence verify-only at the readiness boundary."""

    if (
        not isinstance(value, Mapping)
        or type(value.get("acquisition_schema_version")) is not int
        or value["acquisition_schema_version"] != ACQUISITION_SCHEMA_VERSION
        or type(value.get("completion_schema_version")) is not int
        or value["completion_schema_version"] != ACQUISITION_COMPLETION_SCHEMA_VERSION
        or type(value.get("checkpoint_schema_version")) is not int
        or value["checkpoint_schema_version"] != ACQUISITION_CHECKPOINT_SCHEMA_VERSION
    ):
        raise ValueError(
            "class readiness requires current acquisition schema, completion, and checkpoint evidence"
        )
    return dict(value)


def _build_identity(
    build: Mapping[str, Any], *, include_completion: bool = True
) -> dict[str, Any]:
    cohort_version = build["cohort_version"]
    identity = {
        "cohort_version": cohort_version,
        "sha256": build["sha256"],
        "collection_image": build["collection_image"],
        "started_at": build["started_at"],
        "finished_at": build["finished_at"],
    }
    if not include_completion:
        return identity
    completion_path = build.get("completion_path")
    completion_sha256 = build.get("completion_sha256")
    build_path = build.get("path")
    if (
        not isinstance(build_path, str)
        or not isinstance(completion_path, str)
        or not Path(completion_path).is_absolute()
        or Path(completion_path).resolve()
        != Path(build_path).resolve().with_name(
            f"build-completion-v{cohort_version}.json"
        )
        or not isinstance(completion_sha256, str)
        or _DIGEST.fullmatch(completion_sha256) is None
    ):
        raise ValueError("class attestation requires a completed schema-5 build identity")
    return {
        **identity,
        "completion_path": (
            f"/lab/artifacts/buflo-study/build-completion-v{cohort_version}.json"
        ),
        "completion_sha256": completion_sha256,
    }


def _one_class_build_execution_identity(
    environments: Sequence[Mapping[str, Any]], *, include_completion: bool
) -> dict[str, Any]:
    if include_completion:
        return _one_build_execution_identity(environments)
    identities = []
    for environment in environments:
        build = environment.get("build_execution")
        if not isinstance(build, Mapping):
            raise ValueError("historical class evidence has no build identity")
        identities.append(_build_identity(build, include_completion=False))
    if not identities or any(identity != identities[0] for identity in identities[1:]):
        raise ValueError("historical class evidence does not share one build identity")
    return identities[0]


def _require_formal_authority_bindings(
    canary: Mapping[str, Any],
    formal: Mapping[str, Any],
    *,
    foundation_sha256: str,
    readiness_sha256: str,
    historical_pre_sha256: str,
) -> None:
    expected = {
        "class_study_foundation_sha256": foundation_sha256,
        "class_study_readiness_sha256": readiness_sha256,
        "class_study_historical_pre_snapshot_sha256": historical_pre_sha256,
    }
    if any(
        record.get(key) != digest for record in (canary, formal) for key, digest in expected.items()
    ):
        raise ValueError(
            "class validation block is bound to different foundation/readiness/pre-formal authority"
        )


def _require_final_runtime_bindings(
    canary: Mapping[str, Any],
    formal: Mapping[str, Any],
    *,
    block: int,
    certification_runtime_inputs: Mapping[str, Mapping[str, Any]],
    final_qualification_manifest_sha256: str,
) -> None:
    """Require final blocks to reproduce certified inputs and final named set."""

    canary_runtime_inputs = _validated_runtime_inputs(
        canary.get("defense_runtime_inputs"),
        expected_modes=("undefended",),
        label=f"class canary block {block:02d}",
    )
    formal_runtime_inputs = _validated_runtime_inputs(
        formal.get("defense_runtime_inputs"),
        expected_modes=FORMAL_MODES,
        label=f"class formal block {block:02d}",
    )
    if canary_runtime_inputs != {
        "undefended": certification_runtime_inputs["undefended"]
    } or formal_runtime_inputs != {
        mode: certification_runtime_inputs[mode] for mode in FORMAL_MODES
    }:
        raise ValueError("class validation block used different runtime inputs")
    if (
        canary.get("chaff_qualification_set_manifest_sha256") is not None
        or formal.get("chaff_qualification_set_manifest_sha256")
        != final_qualification_manifest_sha256
    ):
        raise ValueError("class validation block used a different qualification manifest")


def _require_canary_before_formal(canary: Mapping[str, Any], formal: Mapping[str, Any]) -> None:
    try:
        canary_end = datetime.fromisoformat(str(canary["completed_at"]))
        formal_start = datetime.fromisoformat(str(formal["started_at"]))
    except (KeyError, ValueError) as error:
        raise ValueError("class canary/formal timestamps are invalid") from error
    if canary_end.tzinfo is None or formal_start.tzinfo is None or canary_end >= formal_start:
        raise ValueError("class formal block did not follow its completed canary")


def _aware_timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"class {label} timestamp is missing")
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"class {label} timestamp is invalid") from error
    if timestamp.tzinfo is None:
        raise ValueError(f"class {label} timestamp has no timezone")
    return timestamp


def _load_bound_receipt(
    path: Path, *, expected_type: str
) -> tuple[Path, Mapping[str, Any], dict[str, Any]]:
    receipt_path = _regular_file(path, expected_type)
    try:
        value = load_json(receipt_path)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{expected_type} is invalid JSON") from error
    if not isinstance(value, Mapping):
        raise TypeError(f"{expected_type} is not an object")
    if receipt_path.read_bytes() != canonical_json_bytes(value):
        raise ValueError(f"{expected_type} is not canonically encoded")
    payload = validate_hash_bound_receipt(value, expected_type=expected_type)
    return receipt_path, value, payload


def _load_regular_json(path: Path, label: str) -> dict[str, Any]:
    source = _regular_file(path, label)
    try:
        value = load_json(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise TypeError(f"{label} is not an object")
    return value


def _regular_file(path: Path, label: str) -> Path:
    unresolved = Path(path).absolute()
    if unresolved.is_symlink():
        raise ValueError(f"{label} cannot be a symlink")
    resolved = unresolved.resolve()
    if not resolved.is_file():
        raise ValueError(f"{label} is not a regular file: {resolved}")
    return resolved


def _regular_directory(path: Path, label: str) -> Path:
    unresolved = Path(path).absolute()
    if unresolved.is_symlink():
        raise ValueError(f"{label} cannot be a symlink")
    resolved = unresolved.resolve()
    if not resolved.is_dir():
        raise ValueError(f"{label} is not a regular directory: {resolved}")
    return resolved


def _file_binding(path: Path) -> dict[str, str]:
    resolved = _regular_file(path, "evidence file")
    return {"path": str(resolved), "sha256": sha256_file(resolved)}


def _pinned_cdp_binding(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Project the exact receipt/build/contract authority into foundation evidence."""

    build = receipt.get("build_execution")
    if not isinstance(build, Mapping):
        raise TypeError("pinned CDP probe has no build binding")
    projection = {
        "path": str(receipt["path"]),
        "sha256": str(receipt["sha256"]),
        "payload_sha256": str(receipt["payload_sha256"]),
        "build_execution": dict(build),
        "probe_contract_sha256": str(receipt["probe_contract_sha256"]),
    }
    if receipt.get("probe_schema_version") == PINNED_CDP_PROBE_SCHEMA_VERSION:
        identity = receipt.get("build_execution_identity")
        if not isinstance(identity, Mapping):
            raise TypeError("current pinned CDP probe has no build identity")
        projection["build_execution_identity"] = dict(identity)
    return projection


def _validate_browser_egress_qualification(
    root: Path,
    *,
    cohort_version: int,
    build: Mapping[str, Any],
    allow_historical: bool = False,
) -> dict[str, Any]:
    qualification_root = _regular_directory(root, "browser-egress qualification root")
    receipt = verify_browser_egress_qualification(
        qualification_root,
        lab_root=LAB_ROOT,
        expected_cohort_version=cohort_version,
        allow_historical=allow_historical,
    )
    required = {
        "path",
        "sha256",
        "payload_sha256",
        "qualification_id",
        "cohort_version",
        "qualification_started_at",
        "qualification_finished_at",
        "recorded_at",
        "prepare_image_id",
        "build_execution",
        "expanded_vectors_sha256",
        "passed_vector_count",
        "passed",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != required:
        raise ValueError("browser-egress qualification result has an invalid exact schema")
    qualification_build = receipt.get("build_execution")
    expected_build_fields = {
        "path",
        "sha256",
        "payload_sha256",
        "cohort_version",
        "collection_image_id",
        "prepare_image_id",
        "reference_image_id",
    }
    if not allow_historical:
        expected_build_fields.update({"completion_path", "completion_sha256"})
    images = build.get("images")
    if not isinstance(images, Mapping) or set(images) != {"collection", "prepare", "reference"}:
        raise ValueError("browser-egress qualification build image roles are incomplete")
    if (
        not isinstance(qualification_build, Mapping)
        or set(qualification_build) != expected_build_fields
    ):
        raise ValueError("browser-egress qualification build binding is invalid")
    qualification_build_path = Path(str(qualification_build.get("path")))
    if not qualification_build_path.is_absolute():
        qualification_build_path = LAB_ROOT / qualification_build_path
    build_payload_sha256 = build.get("payload_sha256")
    if build_payload_sha256 is None:
        build_payload_sha256 = _load_regular_json(
            Path(str(build.get("path"))), "no-cache build execution"
        ).get("payload_sha256")
    if (
        receipt.get("qualification_id") != BROWSER_EGRESS_QUALIFICATION_ID
        or receipt.get("cohort_version") != cohort_version
        or receipt.get("passed_vector_count") != BROWSER_EGRESS_VECTOR_COUNT
        or receipt.get("expanded_vectors_sha256") != browser_egress_vectors_sha256()
        or receipt.get("passed") is not True
        or receipt.get("prepare_image_id") != images["prepare"].get("id")
        or qualification_build_path.absolute() != Path(str(build.get("path"))).absolute()
        or qualification_build.get("sha256") != build.get("sha256")
        or qualification_build.get("payload_sha256") != build_payload_sha256
        or qualification_build.get("cohort_version") != cohort_version
        or (
            not allow_historical
            and (
                qualification_build.get("completion_path")
                != f"/lab/artifacts/buflo-study/build-completion-v{cohort_version}.json"
                or qualification_build.get("completion_sha256")
                != build.get("completion_sha256")
            )
        )
        or qualification_build.get("collection_image_id") != images["collection"].get("id")
        or qualification_build.get("prepare_image_id") != images["prepare"].get("id")
        or qualification_build.get("reference_image_id") != images["reference"].get("id")
    ):
        raise ValueError("browser-egress qualification uses a different source/build/image")
    for key in ("sha256", "payload_sha256", "expanded_vectors_sha256"):
        if _DIGEST.fullmatch(str(receipt.get(key))) is None:
            raise ValueError("browser-egress qualification digest is invalid")
    expected_final = qualification_root / "final.json"
    if Path(str(receipt.get("path"))).absolute() != expected_final.absolute():
        raise ValueError("browser-egress qualification final receipt path is not canonical")
    return dict(receipt)


def _browser_egress_binding(
    receipt: Mapping[str, Any], root: Path
) -> dict[str, Any]:
    return {
        "root": str(_regular_directory(root, "browser-egress qualification root")),
        **dict(receipt),
    }


def _result_binding(path: Path) -> dict[str, str]:
    root = _regular_directory(path, "evidence result")
    evidence = _regular_file(root / "evidence.sha256", "result evidence seal")
    return {"root": str(root), "evidence_sha256": sha256_file(evidence)}


def _class_result_binding(path: Path) -> dict[str, str]:
    """Bind a class result to its seal, launch, and promotion authorities."""

    root = _regular_directory(path, "class-study evidence result")
    verified = verify_result(root)
    configuration = verified.experiment.get("configuration")
    if not isinstance(configuration, Mapping):
        raise TypeError("class-study evidence result has no frozen configuration")
    role = configuration.get("evidence_role")
    if role not in {
        "pilot-fitting",
        "pilot-compatibility",
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    }:
        raise ValueError("class-study evidence result has no recognised role")
    launch = _regular_file(
        root / CLASS_STUDY_LAUNCH_INPUT,
        "class-study first-launch claim",
    )
    relative = launch.relative_to(root).as_posix()
    launch_sha256 = sha256_file(launch)
    if (
        verified.checksums.get(relative) != launch_sha256
        or configuration.get("class_study_launch_sha256") != launch_sha256
    ):
        raise ValueError("class-study result first-launch claim is not seal/configuration bound")
    binding = {
        **_result_binding(root),
        "class_study_launch_sha256": launch_sha256,
    }
    required = {
        _CLASS_STUDY_FOUNDATION_INPUT: "class_study_foundation_sha256",
    }
    if role in {"canary", "formal"}:
        required.update(
            {
                _CLASS_STUDY_READINESS_INPUT: "class_study_readiness_sha256",
                _CLASS_STUDY_HISTORICAL_PRE_INPUT: ("class_study_historical_pre_snapshot_sha256"),
            }
        )
    all_authorities = {
        _CLASS_STUDY_FOUNDATION_INPUT: "class_study_foundation_sha256",
        _CLASS_STUDY_READINESS_INPUT: "class_study_readiness_sha256",
        _CLASS_STUDY_HISTORICAL_PRE_INPUT: ("class_study_historical_pre_snapshot_sha256"),
    }
    for relative, configuration_key in all_authorities.items():
        if relative not in required:
            authority = root / relative
            if configuration_key in configuration or authority.exists() or authority.is_symlink():
                raise ValueError(f"class-study {role} result has unexpected {configuration_key}")
            continue
        configured = configuration.get(configuration_key)
        if not isinstance(configured, str) or _DIGEST.fullmatch(configured) is None:
            raise ValueError(f"class-study result lacks required {configuration_key}")
        authority = _regular_file(root / relative, f"class-study {configuration_key}")
        digest = sha256_file(authority)
        if verified.checksums.get(relative) != digest or configured != digest:
            raise ValueError(
                f"class-study result {configuration_key} is not seal/configuration bound"
            )
        binding[configuration_key] = digest
    successor_key = "class_study_successor_sha256"
    successor_relative = "inputs/class-study-successor.json"
    successor_digest = configuration.get(successor_key)
    study_id = configuration.get("class_study_id", STUDY_ID)
    successor_input = root / successor_relative
    if successor_digest is None:
        if study_id != STUDY_ID or successor_input.exists() or successor_input.is_symlink():
            raise ValueError("class-study result has an unbound successor identity")
    else:
        if (
            not is_successor_study_id(study_id)
            or not isinstance(successor_digest, str)
            or _DIGEST.fullmatch(successor_digest) is None
        ):
            raise ValueError("class-study result successor identity is invalid")
        successor_file = _regular_file(successor_input, "class-study successor restart")
        digest = sha256_file(successor_file)
        if verified.checksums.get(successor_relative) != digest or digest != successor_digest:
            raise ValueError("class-study result successor restart is not seal/configuration bound")
        binding["class_study_id"] = study_id
        binding[successor_key] = digest
    return binding


def _directory_binding(path: Path) -> dict[str, str]:
    return {"root": str(_regular_directory(path, "evidence directory"))}


def _fitting_bundle_binding(
    root: Path, *, provenance_name: str, artifact_hashes: Mapping[str, str]
) -> dict[str, Any]:
    directory = _regular_directory(root, "fitting bundle")
    provenance = _regular_file(directory / provenance_name, "fitting provenance")
    return {
        "root": str(directory),
        "provenance": provenance_name,
        "provenance_sha256": sha256_file(provenance),
        "artifacts": dict(artifact_hashes),
    }


def _handoff_binding(root: Path) -> dict[str, str]:
    directory = _regular_directory(root, "class handoff")
    return {
        "root": str(directory),
        "sha256sums_sha256": sha256_file(
            _regular_file(directory / "SHA256SUMS", "handoff SHA256SUMS")
        ),
        "dataset_sha256": sha256_file(_regular_file(directory / "dataset.json", "handoff dataset")),
        "samples_sha256": sha256_file(
            _regular_file(directory / "samples.jsonl", "handoff samples")
        ),
    }


def _path_from_binding(value: object, *, label: str) -> Path:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"path", "sha256"}
        or not isinstance(value.get("path"), str)
        or not isinstance(value.get("sha256"), str)
    ):
        raise ValueError(f"class attestation {label} binding is invalid")
    path = _regular_file(Path(value["path"]), label)
    if sha256_file(path) != value["sha256"]:
        raise ValueError(f"class attestation {label} digest changed")
    return path


def _pinned_cdp_path_from_binding(
    value: object, *, allow_historical: bool = False
) -> Path:
    expected_fields = {
        "path",
        "sha256",
        "payload_sha256",
        "build_execution",
        "probe_contract_sha256",
    }
    if not allow_historical:
        expected_fields.add("build_execution_identity")
    if (
        not isinstance(value, Mapping)
        or set(value) != expected_fields
        or not isinstance(value.get("path"), str)
        or _DIGEST.fullmatch(str(value.get("sha256"))) is None
        or _DIGEST.fullmatch(str(value.get("payload_sha256"))) is None
        or _DIGEST.fullmatch(str(value.get("probe_contract_sha256"))) is None
        or not isinstance(value.get("build_execution"), Mapping)
        or (
            not allow_historical
            and not isinstance(value.get("build_execution_identity"), Mapping)
        )
    ):
        raise ValueError("class attestation pinned CDP probe binding is invalid")
    path = _regular_file(Path(value["path"]), "pinned CDP probe")
    if sha256_file(path) != value["sha256"]:
        raise ValueError("class attestation pinned CDP probe digest changed")
    return path


def _browser_egress_root_from_binding(value: object) -> Path:
    if not isinstance(value, Mapping) or "root" not in value:
        raise ValueError("class attestation browser-egress qualification binding is invalid")
    root = _regular_directory(
        Path(str(value["root"])), "browser-egress qualification root"
    )
    receipt = {key: item for key, item in value.items() if key != "root"}
    if _browser_egress_binding(receipt, root) != dict(value):
        raise ValueError("class attestation browser-egress qualification binding is invalid")
    return root


def _root_from_result_binding(value: object, *, label: str) -> Path:
    if (
        not isinstance(value, Mapping)
        or not {"root", "evidence_sha256"}.issubset(value)
        or not isinstance(value.get("root"), str)
        or not isinstance(value.get("evidence_sha256"), str)
    ):
        raise ValueError(f"class attestation {label} result binding is invalid")
    root = _regular_directory(Path(value["root"]), label)
    if sha256_file(_regular_file(root / "evidence.sha256", label)) != value["evidence_sha256"]:
        raise ValueError(f"class attestation {label} evidence digest changed")
    if set(value) != {"root", "evidence_sha256"}:
        expected = _class_result_binding(root)
        if expected != dict(value):
            raise ValueError(f"class attestation {label} authority binding changed")
    return root


def _root_from_directory_binding(value: object, *, label: str) -> Path:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"root"}
        or not isinstance(value.get("root"), str)
    ):
        raise ValueError(f"class attestation {label} directory binding is invalid")
    return _regular_directory(Path(value["root"]), label)


def _root_from_bundle_binding(value: object, *, label: str) -> Path:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"root", "provenance", "provenance_sha256", "artifacts"}
        or not isinstance(value.get("root"), str)
        or not isinstance(value.get("provenance"), str)
        or Path(value["provenance"]).name != value["provenance"]
        or not isinstance(value.get("artifacts"), Mapping)
    ):
        raise ValueError(f"class attestation {label} bundle binding is invalid")
    root = _regular_directory(Path(value["root"]), label)
    provenance = _regular_file(root / value["provenance"], label)
    if sha256_file(provenance) != value.get("provenance_sha256"):
        raise ValueError(f"class attestation {label} provenance changed")
    return root


def _roots_from_bindings(value: object, *, allow_empty: bool = False) -> tuple[Path, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ValueError("class attestation result binding inventory is invalid")
    return tuple(_root_from_result_binding(item, label="result evidence") for item in value)


def _protected_readiness_inputs(inputs: Mapping[str, Any]) -> tuple[Path, ...]:
    protected: list[Path] = [LAB_ROOT / "handoffs/classifier-multiorigin5-v2"]
    for key in (
        "regression_result_roots",
        "controlled_result_roots",
    ):
        protected.extend(Path(path) for path in inputs.get(key, ()))
    for key in (
        "foundation_attestation",
        "build_execution_receipt",
        "reference_receipt",
        "code_gate_receipt",
        "controlled_qualification_receipt",
        "candidate_catalogue",
        "stability_root",
        "workload_root",
        "acquisition_completion",
        "pilot_cohort_receipt",
        "pilot_cohort_assembly",
        "pilot_fitting_result_root",
        "pilot_numeric_bundle_root",
        "pilot_compatibility_result_root",
        "final_selection_receipt",
        "final_cohort_receipt",
        "final_cohort_assembly",
        "authoritative_fitting_result_root",
        "authoritative_fitting_bundle_root",
        "qualification_workload_root",
        "qualification_sidecar_root",
        "qualification_prefix_root",
        "certification_result_root",
    ):
        value = inputs.get(key)
        if value is not None:
            protected.append(Path(value))
    return tuple(protected)


def _protected_foundation_inputs(inputs: Mapping[str, Any]) -> tuple[Path, ...]:
    protected: list[Path] = []
    for key in ("regression_result_roots", "controlled_result_roots"):
        protected.extend(Path(path) for path in inputs.get(key, ()))
    for key in (
        "build_execution_receipt",
        "pinned_cdp_receipt",
        "browser_egress_qualification_root",
        "reference_receipt",
        "code_gate_receipt",
        "controlled_qualification_receipt",
    ):
        value = inputs.get(key)
        if value is not None:
            protected.append(Path(value))
    return tuple(protected)


def _protected_final_inputs(inputs: Mapping[str, Any]) -> tuple[Path, ...]:
    protected: list[Path] = [LAB_ROOT / "handoffs/classifier-multiorigin5-v2"]
    for key in ("canary_result_roots", "formal_result_roots"):
        protected.extend(Path(path) for path in inputs.get(key, ()))
    for key in (
        "readiness_attestation",
        "historical_pre_snapshot",
        "historical_post_snapshot",
        "handoff",
        "evaluation_receipt",
        "comparison_review",
    ):
        value = inputs.get(key)
        if value is not None:
            protected.append(Path(value))
    return tuple(protected)
