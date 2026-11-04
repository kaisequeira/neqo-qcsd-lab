"""Prospective, source-bound contracts for the curated/Tranco rapid study.

The supplied URL catalogue is a list of *hints*.  Its URLs are neither a
captured resource graph nor evidence that any domain works over HTTP/3.  This
module fixes candidate order, five no-fitting conditions, and independent
sample targets.  The frozen Tranco catalogue supplies a second-stage fallback
population.  A cohort receipt can be assembled only through a caller's
independent verifier for each ordered decision receipt; it is not capture
authority.  A bounded root screen may defer browser work, but only a full live
site-terminal receipt may admit a class.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .class_acquisition import DOMAIN_SAFETY_POLICY, unsafe_catalogue_domain_reason
from .class_catalogue import canonical_query_free_html_url, validate_candidate_catalogue_receipt
from .class_curated_source import validate_curated_source_receipt
from .manifest import validate_manifest
from .util import durable_create

PROFILE_RECEIPT_TYPE = "qcsd-curated-tranco-rapid-profile-v4"
COHORT_RECEIPT_TYPE = "qcsd-curated-tranco-rapid-cohort-selection-v4"
SCHEMA_VERSION = 4
STUDY_FAMILY = "classifier-curated-tranco-rapid-v4"
V5_PROFILE_RECEIPT_TYPE = "qcsd-curated-tranco-rapid-profile-v5"
V5_COHORT_RECEIPT_TYPE = "qcsd-curated-tranco-rapid-cohort-selection-v5"
V5_SCHEMA_VERSION = 5
V5_STUDY_FAMILY = "classifier-curated-tranco-rapid-v5"
HISTORICAL_V2_PROFILE_RECEIPT_TYPE = "qcsd-curated-tranco-rapid-profile-v2"
HISTORICAL_V2_STUDY_FAMILY = "classifier-curated-tranco-rapid-v2"
HISTORICAL_V2_SELECTION_POLICY = "first-N-deep-verified-admitted-in-precommitted-order-v1"
HISTORICAL_V2_ADMISSION_POLICY = "live-browser-complete-resource-graph-http3-and-cross-origin-v1"
HISTORICAL_V3_PROFILE_RECEIPT_TYPE = "qcsd-curated-tranco-rapid-profile-v3"
HISTORICAL_V3_STUDY_FAMILY = "classifier-curated-tranco-rapid-v3"
HISTORICAL_V3_SELECTION_POLICY = "first-N-admitted-with-verified-ordered-screen-decisions-v2"
SOURCE_SHA256 = "548e4718cbc20e70e391e36206cb0285327da4c78434039ffb616d83b98d068b"
SOURCE_CANDIDATE_COUNT = 73
FALLBACK_CATALOGUE_SHA256 = (
    "9d2ec1d755648292526ff623700b07a9bab3988a67444c262aea9f4a855e5146"
)
FALLBACK_CANDIDATE_COUNT = 600
FROZEN_V4_PROFILE_SHA256 = "ac40a338bf72c9062b4ece0d1f16de6476763c522295f668e2f5fe931f8c6a92"
FROZEN_V5_PROFILE_SHA256 = "f7eb0228a06429cc2ae91d0f9d52577399e15b68f4915d41cb60291445542b60"
ORDER_POLICY = (
    "curated-v1-sha256-order-then-frozen-tranco-catalogue-order-dedup-domain-v2"
)
SELECTION_POLICY = "first-N-admitted-with-first-screen-and-safety-decisions-v3"
ADMISSION_POLICY = (
    "root-screened-human-reviewed-live-graph-http3-and-cross-origin-v3"
)
SITE_SAFETY_REVIEW_POLICY = {
    "policy": "human-public-page-safety-review-v1",
    "admission_decision": "approved-public-page",
    "exclusion_decision": "excluded-public-page",
    "manual_exclusion_reasons": ["adult-explicit-content", "gambling-content"],
    "receipt_requirement": (
        "independently-verified-human-review-bound-to-candidate-source-"
        "reviewed-url-reviewer-decision-and-reason"
    ),
    "review_order": "after-first-known-valid-root-probe-before-browser-preparation",
}
# An ambiguous probe can also mean a local operational error.  Only these
# exact, independently verified observation classes permit cheap deferral.
ROOT_SCREEN_DEFERRED_DETAILS = {
    "response-known-invalid": "ambiguous",
    "peer-close-336": "ambiguous",
    "public-origin-policy-nonpublic-dns": "ambiguous",
    "timeout": "timeout",
    "idle-timeout": "idle-timeout",
    "peer-close-296": "peer-tls-handshake-failure",
}
SAFETY_POLICY_SHA256 = hashlib.sha256(
    (json.dumps(DOMAIN_SAFETY_POLICY, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
).hexdigest()
TRIAGE_POLICY = {
    "policy": "automatic-safety-then-first-controlled-root-then-human-safety-v2",
    "root_screen_policy": "first-controlled-neqo-h3-root-probe-v1",
    "root_url_template": "https://{domain}/",
    "candidate_probe_timeout_seconds": 12,
    "candidate_probe_count": 1,
    "control_url": "https://cloudflare-quic.com/",
    "control_batch_size": 10,
    "control_rule": "known-valid-before-and-after-complete-batch",
    "deferred_root_details": ROOT_SCREEN_DEFERRED_DETAILS,
    "safety_policy_sha256": SAFETY_POLICY_SHA256,
}
V5_ROOT_SCREEN_DEFERRED_DETAILS = {
    **ROOT_SCREEN_DEFERRED_DETAILS,
    "dns-name-not-found": "ambiguous",
}
V5_SELECTED_PAGE_H3_POLICY = "controlled-exact-selected-page-neqo-h3-v1"
V5_TRIAGE_POLICY = {
    **TRIAGE_POLICY,
    "policy": "automatic-safety-then-controlled-root-and-selected-page-h3-v3",
    "root_screen_policy": "first-controlled-neqo-h3-root-probe-v2",
    "deferred_root_details": V5_ROOT_SCREEN_DEFERRED_DETAILS,
    "selected_page_h3_policy": V5_SELECTED_PAGE_H3_POLICY,
    "selected_page_scope": "canonical-query-free-html-url-at-frozen-domain-or-subdomain",
    "selected_page_proof": "independently-controlled-exact-url-known-valid",
    "dns_name_not_found": "exact-gaierror-minus-two-is-operational-deferral-not-site-rejection",
}
V5_SITE_SAFETY_REVIEW_POLICY = {
    **SITE_SAFETY_REVIEW_POLICY,
    "review_order": "after-first-controlled-root-before-selected-page-browser-preparation",
}
V5_SELECTION_POLICY = "first-N-admitted-with-root-selected-page-and-safety-decisions-v4"
V5_ADMISSION_POLICY = (
    "human-reviewed-exact-page-h3-complete-live-graph-and-cross-origin-v4"
)
HISTORICAL_V3_TRIAGE_POLICY = {
    "policy": "automatic-and-human-safety-then-first-controlled-neqo-h3-root-probe-v1",
    "root_url_template": "https://{domain}/",
    "candidate_probe_timeout_seconds": 12,
    "candidate_probe_count": 1,
    "control_url": "https://cloudflare-quic.com/",
    "control_batch_size": 10,
    "control_rule": "known-valid-before-and-after-complete-batch",
    "deferred_root_details": ROOT_SCREEN_DEFERRED_DETAILS,
    "safety_policy_sha256": SAFETY_POLICY_SHA256,
}
HISTORICAL_V3_SITE_SAFETY_REVIEW_POLICY = {
    "policy": "human-public-page-safety-review-v1",
    "admission_decision": "approved-public-page",
    "manual_exclusion_reasons": ["adult-explicit-content", "gambling-content"],
    "receipt_requirement": (
        "independently-verified-human-review-bound-to-candidate-source-"
        "reviewed-url-reviewer-decision-and-reason"
    ),
}
FORMAL_MODES = ("undefended", "front", "tamaraw", "buflo", "cs-buflo")
RESEARCH_PROFILE_SHA256 = "3fa993dc1bfe7334f6d87ee8b9ddc749705d2d8a59a09cc150aced95b7035902"
BUFLO_PARAMETERS_SHA256 = "8ba1b822d512e87382b25d83460e0cfe1ecf1f47aa66c17ee9dabb28999596e2"
CS_BUFLO_PARAMETERS_SHA256 = "12bb24ff049cb2517b3a1e12eb9917efc9a220c10e6ba4fc6b7a57ee4540da7b"

# Launch-10 is a 50-visit, zero-credit shakedown.  Final-50 alone is the
# registered 16,000-trace formal corpus.  Neither can be relabelled or pooled.
COHORT_CONTRACTS = {
    "launch-10": {
        "study_id": "classifier-curated10-rapid-v4",
        "role": "shakedown",
        "class_count": 10,
        "visits_per_class_mode": 1,
        "planned_visit_count": 50,
        "formal_sample_target": 0,
    },
    "final-50": {
        "study_id": "classifier-curated50-rapid-v4",
        "role": "final",
        "class_count": 50,
        "visits_per_class_mode": 64,
        "planned_visit_count": 16_000,
        "formal_sample_target": 16_000,
    },
}
V5_COHORT_CONTRACTS = {
    generation: {
        **contract,
        "study_id": contract["study_id"].removesuffix("-v4") + "-v5",
    }
    for generation, contract in COHORT_CONTRACTS.items()
}

_DOMAIN_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _bind(
    payload: Mapping[str, Any], receipt_type: str, *, schema_version: int = SCHEMA_VERSION
) -> dict[str, Any]:
    detached = json.loads(_canonical_json(payload))
    return {
        "schema_version": schema_version,
        "receipt_type": receipt_type,
        "payload_sha256": _sha(_canonical_json(detached)),
        "payload": detached,
    }


def _unpack(
    value: Mapping[str, Any], receipt_type: str, *, schema_version: int = SCHEMA_VERSION
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version", "receipt_type", "payload_sha256", "payload"
    }:
        raise ValueError("rapid-study receipt envelope is invalid")
    if type(value["schema_version"]) is not int or value["schema_version"] != schema_version:
        raise ValueError("rapid-study receipt schema is unsupported")
    if value["receipt_type"] != receipt_type or not isinstance(value["payload"], Mapping):
        raise ValueError("rapid-study receipt type or payload is invalid")
    payload = json.loads(_canonical_json(value["payload"]))
    if value["payload_sha256"] != _sha(_canonical_json(payload)):
        raise ValueError("rapid-study receipt payload hash does not verify")
    return payload


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate curated-source JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite curated-source JSON value: {value}")


def _domain(value: object) -> str:
    if not isinstance(value, str) or _DOMAIN_RE.fullmatch(value) is None:
        raise ValueError("curated-source domain is not canonical lower-case DNS")
    return value


def _source_candidates(source_bytes: bytes) -> list[dict[str, Any]]:
    if not isinstance(source_bytes, bytes) or _sha(source_bytes) != SOURCE_SHA256:
        raise ValueError("curated-source bytes differ from the registered SHA-256")
    try:
        source = json.loads(
            source_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("curated source is not valid UTF-8 JSON") from exc
    if not isinstance(source, list) or len(source) != SOURCE_CANDIDATE_COUNT:
        raise ValueError("curated source must contain exactly 73 candidate domains")

    candidates: list[dict[str, Any]] = []
    seen_domains: set[str] = set()
    for source_position, raw in enumerate(source, start=1):
        if not isinstance(raw, dict) or set(raw) != {"crUX_domain", "resources"}:
            raise ValueError("curated-source candidate fields are invalid")
        domain = _domain(raw["crUX_domain"])
        if domain in seen_domains:
            raise ValueError("curated-source candidate domain occurs twice")
        seen_domains.add(domain)
        groups = raw["resources"]
        if not isinstance(groups, list):
            raise ValueError("curated-source resource groups must be a list")
        seen_resource_domains: set[str] = set()
        seen_urls: set[str] = set()
        url_count = 0
        for group in groups:
            if not isinstance(group, dict) or set(group) != {"resource_domain", "resource_urls"}:
                raise ValueError("curated-source resource-group fields are invalid")
            resource_domain = _domain(group["resource_domain"])
            if resource_domain in seen_resource_domains:
                raise ValueError("curated-source resource domain occurs twice")
            seen_resource_domains.add(resource_domain)
            urls = group["resource_urls"]
            if not isinstance(urls, list) or not urls:
                raise ValueError("curated-source resource group has no URLs")
            for url in urls:
                if not isinstance(url, str) or url in seen_urls:
                    raise ValueError("curated-source resource URL is missing or duplicated")
                seen_urls.add(url)
                try:
                    parsed = urlsplit(url)
                    valid = (
                        parsed.scheme == "https"
                        and parsed.netloc == resource_domain
                        and bool(parsed.path)
                        and not parsed.fragment
                        and parsed.username is None
                        and parsed.password is None
                    )
                except ValueError:
                    valid = False
                if not valid:
                    raise ValueError(
                        "curated-source resource URL is not canonical HTTPS "
                        "for its declared domain"
                    )
                url_count += 1
        candidate_id = f"curated-{_sha(domain.encode('ascii'))[:20]}"
        candidates.append({
            # Match class_curated_source._candidate_id exactly so the imported
            # source receipt and this hash-ordered profile share identity.
            "candidate_id": candidate_id,
            "source_candidate_id": candidate_id,
            "source_kind": "curated",
            "source_sha256": SOURCE_SHA256,
            "domain": domain,
            "source_position": source_position,
            "listed_resource_group_count": len(groups),
            "listed_resource_url_count": url_count,
            "resource_hints_sha256": _sha(_canonical_json(groups)),
            "tranco_rank": None,
            "tranco_stratum": None,
        })

    if len({candidate["candidate_id"] for candidate in candidates}) != len(candidates):
        raise ValueError("curated-source candidate IDs collide")
    candidates.sort(
        key=lambda candidate: (
            _sha(
                f"{SOURCE_SHA256}\0classifier-curated-rapid-v1\0{candidate['domain']}".encode(
                    "ascii"
                )
            ),
            candidate["domain"],
        )
    )
    for candidate_order, candidate in enumerate(candidates, start=1):
        candidate["candidate_order"] = candidate_order
    return candidates


def _fallback_catalogue(catalogue_bytes: bytes) -> tuple[dict[str, Any], tuple[Any, ...]]:
    """Validate the exact frozen 600-domain receipt and its original order."""

    if not isinstance(catalogue_bytes, bytes) or _sha(catalogue_bytes) != FALLBACK_CATALOGUE_SHA256:
        raise ValueError("fallback Tranco catalogue bytes differ from registered SHA-256")
    try:
        receipt = json.loads(
            catalogue_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("fallback Tranco catalogue is not strict UTF-8 JSON") from exc
    if not isinstance(receipt, dict):
        raise ValueError("fallback Tranco catalogue receipt must be an object")
    ordered = validate_candidate_catalogue_receipt(receipt)
    if len(ordered) != FALLBACK_CANDIDATE_COUNT:
        raise ValueError("fallback Tranco catalogue is not the registered 600 candidates")
    return receipt, ordered


def _merge_candidates(
    curated: Sequence[dict[str, Any]], tranco_ordered: Sequence[Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Append original Tranco order after curated hash order, recording overlaps."""

    candidates = [dict(candidate) for candidate in curated]
    curated_by_domain = {candidate["domain"]: candidate for candidate in curated}
    seen_domains = set(curated_by_domain)
    seen_ids = {candidate["candidate_id"] for candidate in curated}
    overlaps: list[dict[str, Any]] = []
    for source_position, candidate in enumerate(tranco_ordered, start=1):
        if candidate.domain in curated_by_domain:
            overlaps.append({
                "domain": candidate.domain,
                "tranco_candidate_id": candidate.candidate_id,
                "tranco_source_position": source_position,
                "tranco_rank": candidate.rank,
                "tranco_stratum": candidate.stratum.id,
                "kept_curated_candidate_id": curated_by_domain[candidate.domain]["candidate_id"],
            })
            continue
        if candidate.domain in seen_domains or candidate.candidate_id in seen_ids:
            raise ValueError("fallback catalogue repeats a candidate domain or ID")
        seen_domains.add(candidate.domain)
        seen_ids.add(candidate.candidate_id)
        candidates.append({
            "candidate_id": candidate.candidate_id,
            "source_candidate_id": candidate.candidate_id,
            "source_kind": "tranco-fallback",
            "source_sha256": FALLBACK_CATALOGUE_SHA256,
            "domain": candidate.domain,
            "source_position": source_position,
            "listed_resource_group_count": None,
            "listed_resource_url_count": None,
            "resource_hints_sha256": None,
            "tranco_rank": candidate.rank,
            "tranco_stratum": candidate.stratum.id,
        })
    for candidate_order, candidate in enumerate(candidates, start=1):
        candidate["candidate_order"] = candidate_order
    return candidates, overlaps


def _profile_payload(source_bytes: bytes, catalogue_bytes: bytes) -> dict[str, Any]:
    curated = _source_candidates(source_bytes)
    catalogue_receipt, tranco_ordered = _fallback_catalogue(catalogue_bytes)
    candidates, overlaps = _merge_candidates(curated, tranco_ordered)
    contracts = [
        {"generation": generation, **contract}
        for generation, contract in COHORT_CONTRACTS.items()
    ]
    for contract in contracts:
        if contract["planned_visit_count"] != (
            contract["class_count"] * len(FORMAL_MODES) * contract["visits_per_class_mode"]
        ):
            raise AssertionError("rapid-study sample arithmetic is inconsistent")
        expected_formal = (
            contract["planned_visit_count"] if contract["role"] == "final" else 0
        )
        if contract["formal_sample_target"] != expected_formal:
            raise AssertionError("rapid-study formal credit differs from cohort role")
    return {
        "study_family": STUDY_FAMILY,
        "source_sha256": SOURCE_SHA256,
        "source_candidate_count": SOURCE_CANDIDATE_COUNT,
        "fallback_catalogue_sha256": FALLBACK_CATALOGUE_SHA256,
        "fallback_catalogue_payload_sha256": catalogue_receipt["payload_sha256"],
        "fallback_catalogue_candidate_count": FALLBACK_CANDIDATE_COUNT,
        "fallback_appended_count": len(candidates) - len(curated),
        "fallback_overlaps": overlaps,
        "candidate_count": len(candidates),
        "source_data_role": "resource-discovery-hints-only-no-admission-credit",
        "candidate_order_policy": ORDER_POLICY,
        "curated_order_namespace": "classifier-curated-rapid-v1",
        "curated_order_key_delimiter": "NUL-byte",
        "fallback_order_namespace": "frozen-Tranco-catalogue-receipt-order",
        "candidates": candidates,
        "admission_policy": ADMISSION_POLICY,
        "admission_minimum_cross_origin_resources": 1,
        "site_safety_review_policy": SITE_SAFETY_REVIEW_POLICY,
        "selection_policy": SELECTION_POLICY,
        "triage_policy": TRIAGE_POLICY,
        "formal_modes": list(FORMAL_MODES),
        "fitting_policy": "no-live-fitting-or-pairing",
        "runtime_profile": {
            "name": "research-1200",
            "path": "neqo-qcsd/neqo-csdef/profiles/research-1200.toml",
            "sha256": RESEARCH_PROFILE_SHA256,
        },
        "fixed_parameter_files": [
            {
                "mode": "buflo",
                "path": "config/defense-params/buflo-live.json",
                "sha256": BUFLO_PARAMETERS_SHA256,
            },
            {
                "mode": "cs-buflo",
                "path": "config/defense-params/cs-buflo-ctsp-live.json",
                "sha256": CS_BUFLO_PARAMETERS_SHA256,
            },
        ],
        "cohort_contracts": contracts,
        "corpus_relationship": "separate-generations-no-shakedown-promotion-or-sample-pooling",
        "capture_authority": "none-profile-and-cohort-selection-are-not-capture-gates",
    }


def build_profile_receipt(
    source_bytes: bytes, catalogue_bytes: bytes
) -> dict[str, Any]:
    """Bind both exact sources without asserting site eligibility."""

    return _bind(_profile_payload(source_bytes, catalogue_bytes), PROFILE_RECEIPT_TYPE)


def validate_profile_receipt(
    value: Mapping[str, Any], source_bytes: bytes, catalogue_bytes: bytes
) -> tuple[dict[str, Any], ...]:
    """Re-derive candidate order and provenance from both registered sources."""

    payload = _unpack(value, PROFILE_RECEIPT_TYPE)
    expected = _profile_payload(source_bytes, catalogue_bytes)
    if payload != expected:
        raise ValueError("rapid-study profile differs from its registered source and contract")
    return tuple(expected["candidates"])


def _v5_profile_payload(source_bytes: bytes, catalogue_bytes: bytes) -> dict[str, Any]:
    """Keep the 50 x 5 x 64 grid while changing only prospective site selection."""

    payload = _profile_payload(source_bytes, catalogue_bytes)
    payload.update({
        "study_family": V5_STUDY_FAMILY,
        "admission_policy": V5_ADMISSION_POLICY,
        "site_safety_review_policy": V5_SITE_SAFETY_REVIEW_POLICY,
        "selection_policy": V5_SELECTION_POLICY,
        "triage_policy": V5_TRIAGE_POLICY,
        "cohort_contracts": [
            {"generation": generation, **contract}
            for generation, contract in V5_COHORT_CONTRACTS.items()
        ],
    })
    return payload


def build_v5_profile_receipt(
    source_bytes: bytes, catalogue_bytes: bytes
) -> dict[str, Any]:
    """Bind a fresh exact-page H3 admission policy without promoting v4 results."""

    return _bind(
        _v5_profile_payload(source_bytes, catalogue_bytes),
        V5_PROFILE_RECEIPT_TYPE, schema_version=V5_SCHEMA_VERSION,
    )


def validate_v5_profile_receipt(
    value: Mapping[str, Any], source_bytes: bytes, catalogue_bytes: bytes
) -> tuple[dict[str, Any], ...]:
    """Re-derive every v5 candidate and rule from both frozen sources."""

    payload = _unpack(value, V5_PROFILE_RECEIPT_TYPE, schema_version=V5_SCHEMA_VERSION)
    expected = _v5_profile_payload(source_bytes, catalogue_bytes)
    if payload != expected:
        raise ValueError("v5 rapid-study profile differs from its registered contract")
    return tuple(expected["candidates"])


def validate_historical_v2_profile_receipt(
    value: Mapping[str, Any], source_bytes: bytes, catalogue_bytes: bytes
) -> tuple[dict[str, Any], ...]:
    """Verify the published v2 profile without giving it v3 selection authority."""

    payload = _unpack(
        value, HISTORICAL_V2_PROFILE_RECEIPT_TYPE, schema_version=2
    )
    expected = _profile_payload(source_bytes, catalogue_bytes)
    expected["study_family"] = HISTORICAL_V2_STUDY_FAMILY
    expected["selection_policy"] = HISTORICAL_V2_SELECTION_POLICY
    expected["admission_policy"] = HISTORICAL_V2_ADMISSION_POLICY
    del expected["triage_policy"]
    del expected["site_safety_review_policy"]
    for contract in expected["cohort_contracts"]:
        contract["study_id"] = contract["study_id"].removesuffix("-v4") + "-v2"
    if payload != expected:
        raise ValueError("historical v2 rapid profile differs from its registered contract")
    return tuple(expected["candidates"])


def validate_historical_v3_profile_receipt(
    value: Mapping[str, Any], source_bytes: bytes, catalogue_bytes: bytes
) -> tuple[dict[str, Any], ...]:
    """Verify the published v3 profile without giving it v4 selection authority."""

    payload = _unpack(
        value, HISTORICAL_V3_PROFILE_RECEIPT_TYPE, schema_version=3
    )
    expected = _profile_payload(source_bytes, catalogue_bytes)
    expected["study_family"] = HISTORICAL_V3_STUDY_FAMILY
    expected["selection_policy"] = HISTORICAL_V3_SELECTION_POLICY
    expected["admission_policy"] = HISTORICAL_V2_ADMISSION_POLICY
    expected["triage_policy"] = HISTORICAL_V3_TRIAGE_POLICY
    expected["site_safety_review_policy"] = HISTORICAL_V3_SITE_SAFETY_REVIEW_POLICY
    for contract in expected["cohort_contracts"]:
        contract["study_id"] = contract["study_id"].removesuffix("-v4") + "-v3"
    if payload != expected:
        raise ValueError("historical v3 rapid profile differs from its registered contract")
    return tuple(expected["candidates"])


def validate_fixed_parameter_files(root: Path) -> None:
    """Fail if any no-fitting mode's preregistered parameter bytes changed."""

    expected = (
        ("neqo-qcsd/neqo-csdef/profiles/research-1200.toml", RESEARCH_PROFILE_SHA256),
        ("config/defense-params/buflo-live.json", BUFLO_PARAMETERS_SHA256),
        ("config/defense-params/cs-buflo-ctsp-live.json", CS_BUFLO_PARAMETERS_SHA256),
    )
    for relative, digest in expected:
        path = root / relative
        if not path.is_file() or path.is_symlink() or _sha(path.read_bytes()) != digest:
            raise ValueError(f"rapid-study fixed parameter bytes changed: {relative}")


def _execution_binding(value: Mapping[str, Any]) -> dict[str, str]:
    """Bind admission to one verified source manifest and container image."""

    if not isinstance(value, Mapping) or set(value) != {
        "source_manifest_sha256", "admission_image_digest"
    }:
        raise ValueError("rapid-study source/image execution binding is invalid")
    manifest = value["source_manifest_sha256"]
    image = value["admission_image_digest"]
    if not isinstance(manifest, str) or _SHA_RE.fullmatch(manifest) is None:
        raise ValueError("rapid-study source manifest digest is invalid")
    if not isinstance(image, str) or _IMAGE_DIGEST_RE.fullmatch(image) is None:
        raise ValueError("rapid-study admission image digest is invalid")
    return {"source_manifest_sha256": manifest, "admission_image_digest": image}


def _survey_probe_class(detail: Any, url: str) -> tuple[str, str]:
    """Reclassify retained Neqo output, without trusting a JSONL outcome label."""

    if not isinstance(detail, Mapping) or set(detail) != {
        "url", "started_at", "completed_at", "resolver_addresses", "resolver_error",
        "exit_code", "stdout_sha256", "stdout_excerpt", "output_sha256",
        "output_text", "known_valid", "outcome"
    } or detail["url"] != url or detail["resolver_error"] is not None:
        raise ValueError("curated H3 survey probe facts are incomplete")
    if detail["exit_code"] == 0:
        output = detail["output_text"]
        if (
            not isinstance(output, str)
            or not isinstance(detail["output_sha256"], str)
            or _sha(output.encode("utf-8")) != detail["output_sha256"]
            or detail["stdout_excerpt"] != ""
            or detail["stdout_sha256"] != _sha(b"")
            or type(detail["known_valid"]) is not bool
        ):
            raise ValueError("curated H3 survey completed probe output is invalid")
        try:
            manifest = json.loads(
                output, object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            )
            validate_manifest(manifest)
            resources = manifest["resources"]
        except (ValueError, TypeError, KeyError) as error:
            raise ValueError("curated H3 survey output manifest is invalid") from error
        if (
            not isinstance(resources, list) or len(resources) != 1
            or resources[0].get("url") != url
            or resources[0].get("known_valid") is not detail["known_valid"]
        ):
            raise ValueError("curated H3 survey output is not the exact root probe")
        result = (
            ("known-valid", "known-valid") if detail["known_valid"]
            else ("ambiguous", "response-known-invalid")
        )
    elif detail["exit_code"] == 1:
        stdout = detail["stdout_excerpt"]
        if (
            not isinstance(stdout, str) or len(stdout) > 4096
            or _sha(stdout.encode("utf-8")) != detail["stdout_sha256"]
            or detail["output_text"] is not None
            or detail["output_sha256"] is not None
            or detail["known_valid"] is not None
        ):
            raise ValueError("curated H3 survey error probe output is invalid")
        errors = {
            "Error: Timeout(12)\n": ("timeout", "timeout"),
            "Error: Transport(IdleTimeout)\n": ("idle-timeout", "idle-timeout"),
            ('Error: RunAborted("HTTP/3 endpoint 0 closed before accepted run '
             'completion: Transport(IdleTimeout)")\n'): ("idle-timeout", "idle-timeout"),
            ('Error: RunAborted("HTTP/3 endpoint 0 closed before accepted run '
             'completion: Transport(Peer(296))")\n'):
                ("peer-tls-handshake-failure", "peer-close-296"),
            ('Error: RunAborted("HTTP/3 endpoint 0 closed before accepted run '
             'completion: Transport(Peer(336))")\n'):
                ("ambiguous", "peer-close-336"),
        }
        host = urlsplit(url).hostname
        dns_error = (
            'Error: Argument("public-origin policy rejected a non-public DNS '
            f'answer for {host}:443")\n'
        )
        if stdout == dns_error:
            result = ("ambiguous", "public-origin-policy-nonpublic-dns")
        elif stdout in errors:
            result = errors[stdout]
        else:
            raise ValueError("curated H3 survey has an unclassified operational error")
    else:
        raise ValueError("curated H3 survey has no completed Neqo probe")
    if detail["outcome"] != result[0]:
        raise ValueError("curated H3 survey probe outcome differs from retained output")
    return result


def _survey_probe_class_v5(detail: Any, url: str) -> tuple[str, str]:
    """Classify only the exact observed DNS miss as an operational deferral."""

    if isinstance(detail, Mapping) and detail.get("resolver_error") is not None:
        if (
            set(detail) != {
                "url", "started_at", "completed_at", "resolver_addresses", "resolver_error",
                "exit_code", "stdout_sha256", "stdout_excerpt", "output_sha256",
                "output_text", "known_valid", "outcome",
            }
            or detail["url"] != url
            or detail["resolver_error"] != "gaierror: [Errno -2] Name or service not known"
            or detail["resolver_addresses"] != []
            or detail["exit_code"] is not None
            or detail["stdout_sha256"] != _sha(b"")
            or detail["stdout_excerpt"] != ""
            or detail["output_sha256"] is not None
            or detail["output_text"] is not None
            or detail["known_valid"] is not None
            or detail["outcome"] != "ambiguous"
        ):
            raise ValueError("v5 root survey has an unclassified resolver failure")
        try:
            started = datetime.fromisoformat(detail["started_at"].replace("Z", "+00:00"))
            completed = datetime.fromisoformat(detail["completed_at"].replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError("v5 root survey DNS timestamps are invalid") from error
        if started.tzinfo is None or completed.tzinfo is None or completed < started:
            raise ValueError("v5 root survey DNS timestamps are unordered")
        return "ambiguous", "dns-name-not-found"
    return _survey_probe_class(detail, url)


def _survey_row(rows: Sequence[Any], index: int, stage: str, batch: int | None) -> dict[str, Any]:
    if index >= len(rows) or not isinstance(rows[index], dict):
        raise ValueError("curated H3 survey ended inside a batch")
    row = rows[index]
    if row.get("stage") != stage or (batch is not None and row.get("batch_index") != batch):
        raise ValueError("curated H3 survey batch order is invalid")
    return row


def verify_curated_h3_survey_log(
    path: Path, source_bytes: bytes, source_receipt_bytes: bytes, *,
    execution_binding: Mapping[str, Any],
    expected_runtime_source: Mapping[str, Any],
    expected_mounted_module_hashes: Mapping[str, str],
    not_before_utc: datetime,
    _profile_version: int = 4,
) -> tuple[dict[str, Any], ...]:
    """Reopen one complete create-only curated root-screen slice.

    ``not_before_utc`` must come from the separately published profile
    freeze.  The caller must obtain runtime and module hashes from independent
    image/source evidence, not copy them from this log.  The result is a cheap
    screen fact for each source-order candidate, never site admission.
    """

    if _profile_version not in {4, 5}:
        raise ValueError("curated H3 survey profile version is unsupported")
    v5 = _profile_version == 5
    policy = V5_TRIAGE_POLICY if v5 else TRIAGE_POLICY
    classify_probe = _survey_probe_class_v5 if v5 else _survey_probe_class
    validate_screen = _validated_v5_root_screen if v5 else _validated_root_screen
    binding = _execution_binding(execution_binding)
    module_keys = {"tools.h3_curated_survey", "qcsd_lab.h3_prebaseline"}
    if v5:
        module_keys.add("qcsd_lab.rapid_study_profile")
    if not isinstance(not_before_utc, datetime) or (
        not_before_utc.tzinfo is None or not_before_utc.utcoffset()
    ) is None:
        raise ValueError("curated H3 survey requires a timezone-aware profile freeze")
    if not isinstance(source_receipt_bytes, bytes):
        raise ValueError("curated H3 source receipt bytes are invalid")
    receipt = json.loads(
        source_receipt_bytes, object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )
    validate_curated_source_receipt(receipt, source_bytes=source_bytes)
    ordered = sorted(_source_candidates(source_bytes), key=lambda row: row["source_position"])
    if (
        not isinstance(expected_runtime_source, Mapping)
        or set(expected_runtime_source) != {
            "image_digest", "lab_commit", "lab_dirty", "lab_patch_sha256",
            "neqo_commit", "neqo_dirty", "neqo_patch_sha256", "neqo_pinned_commit"
        }
        or expected_runtime_source.get("image_digest") != binding["admission_image_digest"]
        or not isinstance(expected_runtime_source.get("lab_commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", expected_runtime_source["lab_commit"]) is None
        or not isinstance(expected_runtime_source.get("neqo_commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", expected_runtime_source["neqo_commit"]) is None
        or expected_runtime_source.get("neqo_pinned_commit") != expected_runtime_source.get("neqo_commit")
        or expected_runtime_source.get("lab_dirty") is not False
        or expected_runtime_source.get("neqo_dirty") is not False
        or expected_runtime_source.get("lab_patch_sha256") != _sha(b"")
        or expected_runtime_source.get("neqo_patch_sha256") != _sha(b"")
        or not isinstance(expected_mounted_module_hashes, Mapping)
        or set(expected_mounted_module_hashes) != module_keys
        or any(
            not isinstance(digest, str) or _SHA_RE.fullmatch(digest) is None
            for digest in expected_mounted_module_hashes.values()
        )
    ):
        raise ValueError("curated H3 survey expected runtime binding is invalid")
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("curated H3 survey log is missing or linked")
    raw = path.read_bytes()
    if not raw or len(raw) > 4_000_000 or not raw.endswith(b"\n"):
        raise ValueError("curated H3 survey log is incomplete or oversized")
    try:
        rows = [
            json.loads(line, object_pairs_hook=_reject_duplicate_keys,
                       parse_constant=_reject_constant)
            for line in raw.decode("utf-8").splitlines()
        ]
    except (UnicodeError, ValueError) as error:
        raise ValueError("curated H3 survey log is not strict JSONL") from error
    if not 2 <= len(rows) <= 200 or any(
        not isinstance(row, dict)
        or row.get("record_type") != (
            "qcsd-non-evidentiary-h3-rapid-v5-curated-root-survey" if v5 else
            "qcsd-non-evidentiary-h3-curated-root-survey"
        )
        or row.get("schema_version") != 1
        or row.get("scientific_credit") is not False
        for row in rows
    ):
        raise ValueError("curated H3 survey log record contract is invalid")
    start = _survey_row(rows, 0, "start", None)
    complete = _survey_row(rows, len(rows) - 1, "complete", None)
    try:
        started_at = datetime.fromisoformat(start["at"])
    except (TypeError, ValueError, KeyError) as error:
        raise ValueError("curated H3 survey start time is invalid") from error
    if started_at.tzinfo is None or started_at < not_before_utc:
        raise ValueError("curated H3 survey predates the profile freeze")
    start_index, count = start.get("start_index"), start.get("count")
    if (
        type(start_index) is not int or type(count) is not int
        or start_index < 0 or not 1 <= count <= 40
        or start_index + count > len(ordered)
        or start.get("source_sha256") != SOURCE_SHA256
        or (v5 and (
            start.get("study_version") != 5
            or start.get("profile_sha256") != FROZEN_V5_PROFILE_SHA256
        ))
        or start.get("receipt_sha256") != _sha(source_receipt_bytes)
        or start.get("candidate_count") != len(ordered)
        or start.get("selected_targets") != count
        or start.get("image_digest") != binding["admission_image_digest"]
        or start.get("runtime_source") != dict(expected_runtime_source)
        or start.get("mounted_module_hashes") != dict(expected_mounted_module_hashes)
        or start.get("control_url") != policy["control_url"]
        or start.get("batch_size") != policy["control_batch_size"]
        or type(start.get("timeout_seconds")) is not int
        or not 1 <= start["timeout_seconds"] <= 900
    ):
        raise ValueError("curated H3 survey source, image or protocol binding differs")
    screen_digest = _sha(raw)
    decisions: list[dict[str, Any]] = []
    outcomes: Counter[str] = Counter()
    attempted = skipped = 0
    index = 1
    for batch, offset in enumerate(range(0, count, policy["control_batch_size"])):
        before = _survey_row(rows, index, "control-before", batch)
        if (
            before.get("outcome") != "known-valid"
            or classify_probe(before.get("detail"), policy["control_url"])[0]
            != "known-valid"
        ):
            raise ValueError("curated H3 survey control before candidate batch failed")
        index += 1
        batch_attempted = 0
        for candidate in ordered[start_index + offset:start_index + min(offset + 10, count)]:
            safety = unsafe_catalogue_domain_reason(candidate["domain"])
            row = _survey_row(
                rows, index, "candidate-skipped" if safety else "candidate", batch
            )
            if any(row.get(key) != expected for key, expected in {
                "source_index": candidate["source_position"],
                "candidate_id": candidate["candidate_id"],
                "domain": candidate["domain"],
                "observed_resource_url_count": candidate["listed_resource_url_count"],
                "origin_hint_count": candidate["listed_resource_group_count"],
                "pre_browser_safety_reason": safety,
            }.items()):
                raise ValueError("curated H3 survey candidate identity or order differs")
            screen = None
            if safety:
                if row.get("reason") != safety:
                    raise ValueError("curated H3 survey safety skip differs from policy")
                skipped += 1
            else:
                url = f"https://{candidate['domain']}/"
                outcome, detail = classify_probe(row.get("detail"), url)
                if row.get("outcome") != outcome:
                    raise ValueError("curated H3 survey candidate outcome differs")
                screen = {
                    "policy": policy["root_screen_policy"],
                    "url": url,
                    "outcome": outcome,
                    "detail": detail,
                    "receipt_sha256": screen_digest,
                    "controls_passed": True,
                }
                validate_screen(screen, candidate)
                outcomes[outcome] += 1
                attempted += 1
                batch_attempted += 1
            decisions.append({
                "candidate_id": candidate["candidate_id"],
                "domain": candidate["domain"],
                "source_position": candidate["source_position"],
                "root_screen": screen,
                "automatic_safety_reason": safety,
            })
            index += 1
        after = _survey_row(rows, index, "control-after", batch)
        if (
            after.get("outcome") != "known-valid"
            or classify_probe(after.get("detail"), policy["control_url"])[0]
            != "known-valid"
        ):
            raise ValueError("curated H3 survey control after candidate batch failed")
        index += 1
        batch_end = _survey_row(rows, index, "batch-complete", batch)
        if batch_end.get("controls_pass") is not True or batch_end.get("attempted_targets") != batch_attempted:
            raise ValueError("curated H3 survey batch count or controls differ")
        index += 1
    if index != len(rows) - 1 or any(complete.get(key) != expected for key, expected in {
        "status": "complete",
        "selected_targets": count,
        "attempted_targets": attempted,
        "skipped_unsafe_targets": skipped,
        "completed_batches": (count + 9) // 10,
        "outcomes": dict(outcomes),
    }.items()):
        raise ValueError("curated H3 survey complete inventory differs from its batches")
    return tuple(decisions)


def verify_curated_h3_survey_logs(
    paths: Sequence[Path], source_bytes: bytes, source_receipt_bytes: bytes, *,
    execution_binding: Mapping[str, Any],
    expected_runtime_source: Mapping[str, Any],
    expected_mounted_module_hashes: Mapping[str, str],
    not_before_utc: datetime,
) -> tuple[dict[str, Any], ...]:
    """Require one verified first-screen decision for each of the 73 source sites."""

    if not isinstance(paths, Sequence) or isinstance(paths, (str, bytes)) or not paths:
        raise ValueError("curated H3 survey needs one or more complete slice logs")
    combined = [
        item
        for path in paths
        for item in verify_curated_h3_survey_log(
            path, source_bytes, source_receipt_bytes,
            execution_binding=execution_binding,
            expected_runtime_source=expected_runtime_source,
            expected_mounted_module_hashes=expected_mounted_module_hashes,
            not_before_utc=not_before_utc,
        )
    ]
    ordered = sorted(_source_candidates(source_bytes), key=lambda row: row["source_position"])
    combined.sort(key=lambda row: row["source_position"])
    if (
        len(combined) != len(ordered)
        or [row["source_position"] for row in combined] != list(range(1, len(ordered) + 1))
        or any(
            item["candidate_id"] != candidate["candidate_id"]
            for item, candidate in zip(combined, ordered, strict=True)
        )
    ):
        raise ValueError("curated H3 survey logs leave gaps or duplicate candidates")
    return tuple(combined)


def verify_v5_curated_h3_survey_logs(
    paths: Sequence[Path], profile_bytes: bytes, source_bytes: bytes,
    source_receipt_bytes: bytes, catalogue_bytes: bytes, *,
    execution_binding: Mapping[str, Any],
    expected_runtime_source: Mapping[str, Any],
    expected_mounted_module_hashes: Mapping[str, str],
    not_before_utc: datetime,
) -> tuple[dict[str, Any], ...]:
    """Verify fresh curated first screens under the frozen v5 identity."""

    if not isinstance(profile_bytes, bytes) or _sha(profile_bytes) != FROZEN_V5_PROFILE_SHA256:
        raise ValueError("curated v5 screen profile differs from frozen bytes")
    try:
        profile = json.loads(
            profile_bytes, object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, TypeError) as error:
        raise ValueError("curated v5 screen profile is not strict JSON") from error
    validate_v5_profile_receipt(profile, source_bytes, catalogue_bytes)
    if not isinstance(paths, Sequence) or isinstance(paths, (str, bytes)) or not paths:
        raise ValueError("curated v5 screen needs complete slice logs")
    combined = [
        item
        for path in paths
        for item in verify_curated_h3_survey_log(
            path, source_bytes, source_receipt_bytes,
            execution_binding=execution_binding,
            expected_runtime_source=expected_runtime_source,
            expected_mounted_module_hashes=expected_mounted_module_hashes,
            not_before_utc=not_before_utc,
            _profile_version=5,
        )
    ]
    ordered = sorted(_source_candidates(source_bytes), key=lambda row: row["source_position"])
    combined.sort(key=lambda row: row["source_position"])
    if (
        len(combined) != len(ordered)
        or [row["source_position"] for row in combined] != list(range(1, len(ordered) + 1))
        or any(
            item["candidate_id"] != candidate["candidate_id"]
            for item, candidate in zip(combined, ordered, strict=True)
        )
    ):
        raise ValueError("curated v5 screen logs leave gaps or repeat candidates")
    return tuple(combined)


def verify_fallback_h3_survey_log(
    path: Path, profile_bytes: bytes, source_bytes: bytes, catalogue_bytes: bytes, *,
    execution_binding: Mapping[str, Any],
    expected_runtime_source: Mapping[str, Any],
    expected_mounted_module_hashes: Mapping[str, str],
    not_before_utc: datetime,
    _profile_version: int = 4,
) -> tuple[dict[str, Any], ...]:
    """Reopen a complete version-bound fallback root survey as screen facts.

    Inputs and runtime hashes must come from independent source/image evidence.
    A valid root result is still only a first-screen decision; page safety,
    complete resource graphs, and multi-origin admission remain separate.
    """

    if _profile_version not in {4, 5}:
        raise ValueError("fallback H3 survey profile version is unsupported")
    v5 = _profile_version == 5
    profile_sha = FROZEN_V5_PROFILE_SHA256 if v5 else FROZEN_V4_PROFILE_SHA256
    validate_profile = validate_v5_profile_receipt if v5 else validate_profile_receipt
    policy = V5_TRIAGE_POLICY if v5 else TRIAGE_POLICY
    classify_probe = _survey_probe_class_v5 if v5 else _survey_probe_class
    validate_screen = _validated_v5_root_screen if v5 else _validated_root_screen
    record_type = (
        "qcsd-non-evidentiary-h3-rapid-v5-fallback-root-survey" if v5 else
        "qcsd-non-evidentiary-h3-rapid-v4-fallback-root-survey"
    )
    binding = _execution_binding(execution_binding)
    if not isinstance(not_before_utc, datetime) or (
        not_before_utc.tzinfo is None or not_before_utc.utcoffset()
    ) is None:
        raise ValueError("fallback H3 survey requires a timezone-aware profile freeze")
    if (
        not isinstance(profile_bytes, bytes)
        or _sha(profile_bytes) != profile_sha
    ):
        raise ValueError(
            "fallback H3 survey profile differs from frozen "
            + ("v5" if v5 else "v4") + " bytes"
        )
    try:
        profile = json.loads(
            profile_bytes, object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, TypeError) as error:
        raise ValueError("fallback H3 survey profile is not strict JSON") from error
    ordered = validate_profile(profile, source_bytes, catalogue_bytes)
    fallback = tuple(
        candidate for candidate in ordered if candidate["source_kind"] == "tranco-fallback"
    )
    if len(fallback) != FALLBACK_CANDIDATE_COUNT:
        raise ValueError("fallback H3 survey population is incomplete")
    module_keys = {
        "tools.h3_rapid_fallback_survey", "qcsd_lab.h3_prebaseline",
        "qcsd_lab.rapid_study_profile",
    }
    if (
        not isinstance(expected_runtime_source, Mapping)
        or set(expected_runtime_source) != {
            "image_digest", "lab_commit", "lab_dirty", "lab_patch_sha256",
            "neqo_commit", "neqo_dirty", "neqo_patch_sha256", "neqo_pinned_commit",
        }
        or expected_runtime_source.get("image_digest") != binding["admission_image_digest"]
        or not isinstance(expected_runtime_source.get("lab_commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", expected_runtime_source["lab_commit"]) is None
        or not isinstance(expected_runtime_source.get("neqo_commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", expected_runtime_source["neqo_commit"]) is None
        or expected_runtime_source.get("neqo_pinned_commit") != expected_runtime_source.get("neqo_commit")
        or expected_runtime_source.get("lab_dirty") is not False
        or expected_runtime_source.get("neqo_dirty") is not False
        or expected_runtime_source.get("lab_patch_sha256") != _sha(b"")
        or expected_runtime_source.get("neqo_patch_sha256") != _sha(b"")
        or not isinstance(expected_mounted_module_hashes, Mapping)
        or set(expected_mounted_module_hashes) != module_keys
        or any(
            not isinstance(digest, str) or _SHA_RE.fullmatch(digest) is None
            for digest in expected_mounted_module_hashes.values()
        )
    ):
        raise ValueError("fallback H3 survey expected runtime binding is invalid")
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("fallback H3 survey log is missing or linked")
    raw = path.read_bytes()
    if not raw or len(raw) > 4_000_000 or not raw.endswith(b"\n"):
        raise ValueError("fallback H3 survey log is incomplete or oversized")
    try:
        rows = [
            json.loads(line, object_pairs_hook=_reject_duplicate_keys,
                       parse_constant=_reject_constant)
            for line in raw.decode("utf-8").splitlines()
        ]
    except (UnicodeError, ValueError) as error:
        raise ValueError("fallback H3 survey log is not strict JSONL") from error
    if not 2 <= len(rows) <= 200 or any(
        not isinstance(row, dict)
        or row.get("record_type") != record_type
        or row.get("schema_version") != 1
        or row.get("scientific_credit") is not False
        for row in rows
    ):
        raise ValueError("fallback H3 survey log record contract is invalid")

    def row_at(index: int, stage: str, batch: int | None = None) -> dict[str, Any]:
        if index >= len(rows) or rows[index].get("stage") != stage or (
            batch is not None and rows[index].get("batch_index") != batch
        ):
            raise ValueError("fallback H3 survey stage or batch order is invalid")
        return rows[index]

    start = row_at(0, "start")
    complete = row_at(len(rows) - 1, "complete")
    try:
        started_at = datetime.fromisoformat(start["at"])
    except (TypeError, ValueError, KeyError) as error:
        raise ValueError("fallback H3 survey start time is invalid") from error
    if started_at.tzinfo is None or started_at < not_before_utc:
        raise ValueError("fallback H3 survey predates the profile freeze")
    start_index, count = start.get("start_index"), start.get("count")
    if (
        type(start_index) is not int or type(count) is not int
        or start_index < 0 or not 1 <= count <= 40
        or start_index + count > len(fallback)
        or start.get("profile_sha256") != profile_sha
        or start.get("source_sha256") != SOURCE_SHA256
        or start.get("catalogue_sha256") != FALLBACK_CATALOGUE_SHA256
        or start.get("profile_candidate_count") != len(ordered)
        or start.get("fallback_candidate_count") != len(fallback)
        or start.get("selected_targets") != count
        or start.get("image_digest") != binding["admission_image_digest"]
        or start.get("runtime_source") != dict(expected_runtime_source)
        or start.get("mounted_module_hashes") != dict(expected_mounted_module_hashes)
        or start.get("control_url") != policy["control_url"]
        or start.get("batch_size") != policy["control_batch_size"]
        or type(start.get("timeout_seconds")) is not int
        or not 1 <= start["timeout_seconds"] <= 900
    ):
        raise ValueError("fallback H3 survey profile, source or runtime binding differs")
    screen_digest = _sha(raw)
    decisions: list[dict[str, Any]] = []
    outcomes: Counter[str] = Counter()
    attempted = skipped = 0
    index = 1
    for batch, offset in enumerate(range(0, count, policy["control_batch_size"])):
        before = row_at(index, "control-before", batch)
        if (
            before.get("outcome") != "known-valid"
            or classify_probe(before.get("detail"), policy["control_url"])[0]
            != "known-valid"
        ):
            raise ValueError("fallback H3 survey control before candidate batch failed")
        index += 1
        batch_attempted = 0
        for fallback_index in range(
            start_index + offset,
            start_index + min(offset + policy["control_batch_size"], count),
        ):
            candidate = fallback[fallback_index]
            safety = unsafe_catalogue_domain_reason(candidate["domain"])
            row = row_at(index, "candidate-skipped" if safety else "candidate", batch)
            if any(row.get(key) != expected for key, expected in {
                "fallback_index": fallback_index,
                "candidate_order": candidate["candidate_order"],
                "source_position": candidate["source_position"],
                "candidate_id": candidate["candidate_id"],
                "domain": candidate["domain"],
                "tranco_rank": candidate["tranco_rank"],
                "tranco_stratum": candidate["tranco_stratum"],
                "pre_browser_safety_reason": safety,
            }.items()):
                raise ValueError("fallback H3 survey candidate identity or order differs")
            screen = None
            if safety:
                if row.get("reason") != safety:
                    raise ValueError("fallback H3 survey safety skip differs from policy")
                skipped += 1
            else:
                url = f"https://{candidate['domain']}/"
                outcome, detail = classify_probe(row.get("detail"), url)
                if row.get("outcome") != outcome:
                    raise ValueError("fallback H3 survey candidate outcome differs")
                screen = {
                    "policy": policy["root_screen_policy"],
                    "url": url,
                    "outcome": outcome,
                    "detail": detail,
                    "receipt_sha256": screen_digest,
                    "controls_passed": True,
                }
                validate_screen(screen, candidate)
                outcomes[outcome] += 1
                attempted += 1
                batch_attempted += 1
            decisions.append({
                "fallback_index": fallback_index,
                "candidate_order": candidate["candidate_order"],
                "candidate_id": candidate["candidate_id"],
                "domain": candidate["domain"],
                "source_kind": candidate["source_kind"],
                "source_position": candidate["source_position"],
                "root_screen": screen,
                "automatic_safety_reason": safety,
            })
            index += 1
        after = row_at(index, "control-after", batch)
        if (
            after.get("outcome") != "known-valid"
            or classify_probe(after.get("detail"), policy["control_url"])[0]
            != "known-valid"
        ):
            raise ValueError("fallback H3 survey control after candidate batch failed")
        index += 1
        batch_end = row_at(index, "batch-complete", batch)
        if (
            batch_end.get("controls_pass") is not True
            or batch_end.get("attempted_targets") != batch_attempted
        ):
            raise ValueError("fallback H3 survey batch inventory or controls differ")
        index += 1
    if index != len(rows) - 1 or any(complete.get(key) != expected for key, expected in {
        "status": "complete",
        "selected_targets": count,
        "attempted_targets": attempted,
        "skipped_unsafe_targets": skipped,
        "completed_batches": (count + policy["control_batch_size"] - 1)
        // policy["control_batch_size"],
        "outcomes": dict(outcomes),
    }.items()):
        raise ValueError("fallback H3 survey complete inventory differs from its batches")
    return tuple(decisions)


def verify_fallback_h3_survey_logs(
    paths: Sequence[Path], profile_bytes: bytes, source_bytes: bytes,
    catalogue_bytes: bytes, *,
    execution_binding: Mapping[str, Any],
    expected_runtime_source: Mapping[str, Any],
    expected_mounted_module_hashes: Mapping[str, str],
    not_before_utc: datetime,
) -> tuple[dict[str, Any], ...]:
    """Require one first controlled result for a gap-free v4 fallback prefix.

    The caller must inventory every earlier run. Repeats cannot replace a
    previously verified first result; incomplete logs grant no screen facts.
    """

    if not isinstance(paths, Sequence) or isinstance(paths, (str, bytes)) or not paths:
        raise ValueError("fallback H3 survey needs one or more complete slice logs")
    combined = [
        decision
        for path in paths
        for decision in verify_fallback_h3_survey_log(
            path, profile_bytes, source_bytes, catalogue_bytes,
            execution_binding=execution_binding,
            expected_runtime_source=expected_runtime_source,
            expected_mounted_module_hashes=expected_mounted_module_hashes,
            not_before_utc=not_before_utc,
        )
    ]
    if [decision["fallback_index"] for decision in combined] != list(range(len(combined))):
        raise ValueError("fallback H3 survey logs leave gaps, reorder or repeat first results")
    return tuple(combined)


def verify_v5_fallback_h3_survey_logs(
    paths: Sequence[Path], profile_bytes: bytes, source_bytes: bytes,
    catalogue_bytes: bytes, *,
    execution_binding: Mapping[str, Any],
    expected_runtime_source: Mapping[str, Any],
    expected_mounted_module_hashes: Mapping[str, str],
    not_before_utc: datetime,
) -> tuple[dict[str, Any], ...]:
    """Accept only complete post-freeze v5 slices with exact DNS classification."""

    if not isinstance(paths, Sequence) or isinstance(paths, (str, bytes)) or not paths:
        raise ValueError("v5 fallback H3 survey needs complete slice logs")
    combined = [
        decision
        for path in paths
        for decision in verify_fallback_h3_survey_log(
            path, profile_bytes, source_bytes, catalogue_bytes,
            execution_binding=execution_binding,
            expected_runtime_source=expected_runtime_source,
            expected_mounted_module_hashes=expected_mounted_module_hashes,
            not_before_utc=not_before_utc,
            _profile_version=5,
        )
    ]
    if [decision["fallback_index"] for decision in combined] != list(range(len(combined))):
        raise ValueError("v5 fallback H3 survey logs leave gaps or repeat first results")
    return tuple(combined)


def _validated_root_screen(value: Any, candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Check independently verified facts from the first controlled root probe."""

    if not isinstance(value, Mapping) or set(value) != {
        "policy", "url", "outcome", "detail", "receipt_sha256", "controls_passed"
    }:
        raise ValueError("rapid-study root screen facts are invalid")
    detail = value["detail"]
    expected_outcome = (
        "known-valid" if detail == "known-valid"
        else ROOT_SCREEN_DEFERRED_DETAILS.get(detail) if isinstance(detail, str)
        else None
    )
    digest = value["receipt_sha256"]
    if (
        value["policy"] != TRIAGE_POLICY["root_screen_policy"]
        or value["url"] != f"https://{candidate['domain']}/"
        or expected_outcome is None
        or value["outcome"] != expected_outcome
        or not isinstance(digest, str)
        or _SHA_RE.fullmatch(digest) is None
        or value["controls_passed"] is not True
    ):
        raise ValueError("rapid-study root screen lacks a controlled first probe")
    return dict(value)


def _validated_v5_root_screen(value: Any, candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Retain the first v5 root result, including an exact operational DNS miss."""

    if not isinstance(value, Mapping) or set(value) != {
        "policy", "url", "outcome", "detail", "receipt_sha256", "controls_passed"
    }:
        raise ValueError("v5 rapid-study root screen facts are invalid")
    detail = value["detail"]
    expected_outcome = (
        "known-valid" if detail == "known-valid"
        else V5_ROOT_SCREEN_DEFERRED_DETAILS.get(detail) if isinstance(detail, str)
        else None
    )
    digest = value["receipt_sha256"]
    if (
        value["policy"] != V5_TRIAGE_POLICY["root_screen_policy"]
        or value["url"] != f"https://{candidate['domain']}/"
        or expected_outcome is None
        or value["outcome"] != expected_outcome
        or not isinstance(digest, str)
        or _SHA_RE.fullmatch(digest) is None
        or value["controls_passed"] is not True
    ):
        raise ValueError("v5 rapid-study root screen lacks a controlled first probe")
    return dict(value)


def _validated_v5_selected_page_h3_proof(
    value: Any, candidate: Mapping[str, Any]
) -> dict[str, Any]:
    """Require exact controlled H3 proof for the eventual replayed page URL."""

    if not isinstance(value, Mapping) or set(value) != {
        "policy", "url", "selected_page_ordinal", "navigation_receipt_sha256",
        "outcome", "receipt_sha256", "controls_passed",
    }:
        raise ValueError("v5 selected-page H3 proof facts are invalid")
    url = value["url"]
    try:
        canonical = canonical_query_free_html_url(
            url, registrable_domain=candidate["domain"]
        )
    except (TypeError, ValueError) as error:
        raise ValueError("v5 selected-page H3 URL is outside the frozen page boundary") from error
    ordinal = value["selected_page_ordinal"]
    if (
        url != canonical
        or type(ordinal) is not int or not 0 <= ordinal <= 4
        or (ordinal == 0) != (url == f"https://{candidate['domain']}/")
        or value["policy"] != V5_SELECTED_PAGE_H3_POLICY
        or value["outcome"] != "known-valid"
        or value["controls_passed"] is not True
        or any(
            not isinstance(value[key], str) or _SHA_RE.fullmatch(value[key]) is None
            for key in ("navigation_receipt_sha256", "receipt_sha256")
        )
    ):
        raise ValueError("v5 selected-page H3 proof is not an exact controlled page pass")
    return dict(value)


def _validated_site_safety_review(value: Any) -> dict[str, Any]:
    """Check the facts from an independently verified human review receipt."""

    if not isinstance(value, Mapping) or set(value) != {
        "policy", "decision", "reason", "receipt_sha256"
    }:
        raise ValueError("rapid-study human safety review facts are invalid")
    digest = value["receipt_sha256"]
    if (
        value["policy"] != SITE_SAFETY_REVIEW_POLICY["policy"]
        or not isinstance(digest, str)
        or _SHA_RE.fullmatch(digest) is None
    ):
        raise ValueError("rapid-study human safety review receipt is invalid")
    if value["decision"] == SITE_SAFETY_REVIEW_POLICY["admission_decision"]:
        if value["reason"] is not None:
            raise ValueError("approved human safety review cannot give an exclusion reason")
    elif value["decision"] == SITE_SAFETY_REVIEW_POLICY["exclusion_decision"]:
        if value["reason"] not in SITE_SAFETY_REVIEW_POLICY["manual_exclusion_reasons"]:
            raise ValueError("human safety exclusion reason is unregistered")
    else:
        raise ValueError("human safety review decision is unregistered")
    return dict(value)


def _validated_triage(
    value: Any, candidate: Mapping[str, Any],
    screen: Mapping[str, Any] | None, review: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Account for a cheap prefix decision without claiming full-page ineligibility."""

    if not isinstance(value, Mapping) or set(value) != {
        "policy", "reason", "safety_reason"
    } or value["policy"] != TRIAGE_POLICY["policy"]:
        raise ValueError("rapid-study triage facts or protocol are invalid")
    automatic_reason = unsafe_catalogue_domain_reason(candidate["domain"])
    if value["reason"] == "automatic-safety-exclusion":
        if (
            automatic_reason is None or value["safety_reason"] != automatic_reason
            or screen is not None or review is not None
        ):
            raise ValueError("rapid-study safety exclusion is not policy-derived")
    elif value["reason"] == "bounded-root-h3-no-known-valid":
        if (
            automatic_reason is not None or value["safety_reason"] is not None
            or screen is None or screen["outcome"] == "known-valid" or review is not None
        ):
            raise ValueError("rapid-study root screen cannot defer this candidate")
    elif value["reason"] == "manual-safety-exclusion":
        if (
            automatic_reason is not None
            or screen is None or screen["outcome"] != "known-valid"
            or review is None
            or review["decision"] != SITE_SAFETY_REVIEW_POLICY["exclusion_decision"]
            or value["safety_reason"] != review["reason"]
        ):
            raise ValueError("rapid-study manual safety exclusion lacks verified review")
    else:
        raise ValueError("rapid-study triage reason is unregistered")
    return dict(value)


def _validated_v5_triage(
    value: Any, candidate: Mapping[str, Any],
    screen: Mapping[str, Any] | None, review: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Distinguish operational DNS deferral from scientific ineligibility."""

    if not isinstance(value, Mapping) or set(value) != {
        "policy", "reason", "safety_reason"
    } or value["policy"] != V5_TRIAGE_POLICY["policy"]:
        raise ValueError("v5 rapid-study triage facts or protocol are invalid")
    automatic_reason = unsafe_catalogue_domain_reason(candidate["domain"])
    reason = value["reason"]
    if reason == "automatic-safety-exclusion":
        valid = (
            automatic_reason is not None and value["safety_reason"] == automatic_reason
            and screen is None and review is None
        )
    elif reason == "operational-dns-name-not-found":
        valid = (
            automatic_reason is None and value["safety_reason"] is None
            and screen is not None and screen["detail"] == "dns-name-not-found"
            and review is None
        )
    elif reason == "bounded-root-h3-no-known-valid":
        valid = (
            automatic_reason is None and value["safety_reason"] is None
            and screen is not None and screen["outcome"] != "known-valid"
            and screen["detail"] != "dns-name-not-found" and review is None
        )
    elif reason == "manual-safety-exclusion":
        valid = (
            automatic_reason is None and screen is not None and review is not None
            and review["decision"] == SITE_SAFETY_REVIEW_POLICY["exclusion_decision"]
            and value["safety_reason"] == review["reason"]
        )
    else:
        raise ValueError("v5 rapid-study triage reason is unregistered")
    if not valid:
        raise ValueError("v5 rapid-study triage lacks its exact screen or safety evidence")
    return dict(value)


def _selection_payload(
    profile_receipt: Mapping[str, Any],
    source_bytes: bytes,
    catalogue_bytes: bytes,
    generation: str,
    terminal_sha256s: Sequence[str],
    execution_binding: Mapping[str, Any],
    deep_verify_terminal: Callable[[str], Mapping[str, Any]],
) -> dict[str, Any]:
    candidates = validate_profile_receipt(profile_receipt, source_bytes, catalogue_bytes)
    binding = _execution_binding(execution_binding)
    if not isinstance(generation, str) or generation not in COHORT_CONTRACTS:
        raise ValueError("rapid-study cohort generation is unregistered")
    if not isinstance(terminal_sha256s, Sequence) or isinstance(terminal_sha256s, (str, bytes)):
        raise ValueError("rapid-study terminal SHA-256s must be an ordered sequence")
    if not callable(deep_verify_terminal):
        raise ValueError("rapid-study requires an independent decision receipt verifier")
    contract = COHORT_CONTRACTS[generation]
    terminals: list[dict[str, Any]] = []
    selected: list[str] = []
    if len(terminal_sha256s) > len(candidates):
        raise ValueError("rapid-study terminal prefix exceeds the candidate list")
    seen_terminal_digests: set[str] = set()
    for candidate, digest in zip(candidates, terminal_sha256s, strict=False):
        if not isinstance(digest, str) or _SHA_RE.fullmatch(digest) is None:
            raise ValueError("rapid-study terminal receipt SHA-256 is invalid")
        if digest in seen_terminal_digests:
            raise ValueError("rapid-study terminal receipt SHA-256 repeats")
        seen_terminal_digests.add(digest)
        facts = deep_verify_terminal(digest)
        common_fields = {
            "candidate_id", "domain", "source_kind", "outcome",
            "admission", "execution_binding", "root_screen", "site_safety_review"
        }
        if not isinstance(facts, Mapping) or set(facts) not in (
            common_fields, common_fields | {"triage"}
        ):
            raise ValueError("decision receipt verifier returned invalid facts")
        if _execution_binding(facts["execution_binding"]) != binding:
            raise ValueError("deep terminal belongs to a different source or image")
        if any(facts[key] != candidate[key] for key in ("candidate_id", "domain", "source_kind")):
            raise ValueError("deep terminal outcome or provenance does not match candidate order")
        outcome = facts["outcome"]
        admission = facts["admission"]
        triage = facts.get("triage")
        screen = (
            _validated_root_screen(facts["root_screen"], candidate)
            if facts["root_screen"] is not None else None
        )
        review = (
            _validated_site_safety_review(facts["site_safety_review"])
            if facts["site_safety_review"] is not None else None
        )
        if outcome == "admitted":
            if "triage" in facts:
                raise ValueError("admitted site cannot use a cheap screen decision")
            if not isinstance(admission, Mapping) or set(admission) != {
                "cross_origin_resource_count", "full_resource_graph_sha256",
                "h3_proof_sha256"
            }:
                raise ValueError("admitted site lacks full graph and HTTP/3 proof")
            if unsafe_catalogue_domain_reason(candidate["domain"]) is not None:
                raise ValueError("automatically unsafe site cannot be admitted")
            if screen is None or screen["outcome"] != "known-valid":
                raise ValueError("admitted site lacks its first controlled root screen")
            if (
                review is None
                or review["decision"] != SITE_SAFETY_REVIEW_POLICY["admission_decision"]
            ):
                raise ValueError("admitted site lacks an approved human safety review")
            count = admission["cross_origin_resource_count"]
            if type(count) is not int or count < 1:
                raise ValueError("admitted site lacks a live observed cross-origin resource")
            for key in ("full_resource_graph_sha256", "h3_proof_sha256"):
                if not isinstance(admission[key], str) or _SHA_RE.fullmatch(admission[key]) is None:
                    raise ValueError("admitted site proof digest is invalid")
            selected.append(candidate["candidate_id"])
        elif outcome == "ineligible":
            if admission is not None or "triage" in facts:
                raise ValueError("ineligible site cannot carry an admission proof")
            if (
                screen is None or screen["outcome"] != "known-valid"
                or review is None
                or review["decision"] != SITE_SAFETY_REVIEW_POLICY["admission_decision"]
            ):
                raise ValueError("ineligible site lacks a screened and reviewed page decision")
        elif outcome == "screen-deferred":
            if admission is not None or "triage" not in facts:
                raise ValueError("screen-deferred site cannot carry admission proof")
            triage = _validated_triage(triage, candidate, screen, review)
        else:
            raise ValueError("operational errors are not scientific site terminals")
        terminals.append({
            "candidate_id": candidate["candidate_id"],
            "domain": candidate["domain"],
            "source_kind": candidate["source_kind"],
            "terminal_receipt_sha256": digest,
            "outcome": outcome,
            "admission": dict(admission) if admission is not None else None,
            "root_screen": screen,
            "site_safety_review": review,
            **({"triage": triage} if outcome == "screen-deferred" else {}),
        })
        if len(selected) == contract["class_count"] and len(terminals) != len(terminal_sha256s):
            raise ValueError("terminal prefix continues after the first N admitted sites")
    if len(selected) != contract["class_count"]:
        raise ValueError("cohort is incomplete: not enough deep-verified admitted sites")
    return {
        "study_id": contract["study_id"],
        "generation": generation,
        "cohort_role": contract["role"],
        "profile_receipt_sha256": _sha(_canonical_json(profile_receipt)),
        "source_sha256": SOURCE_SHA256,
        "fallback_catalogue_sha256": FALLBACK_CATALOGUE_SHA256,
        "execution_binding": binding,
        "selection_policy": SELECTION_POLICY,
        "terminal_decisions": terminals,
        "selected_candidate_ids": selected,
        "selected_candidates": [
            {
                "candidate_id": candidate["candidate_id"],
                "domain": candidate["domain"],
                "source_kind": candidate["source_kind"],
                "source_candidate_id": candidate["source_candidate_id"],
                "source_sha256": candidate["source_sha256"],
                "source_position": candidate["source_position"],
                "tranco_rank": candidate["tranco_rank"],
                "tranco_stratum": candidate["tranco_stratum"],
            }
            for candidate in candidates if candidate["candidate_id"] in selected
        ],
        "formal_modes": list(FORMAL_MODES),
        "visits_per_class_mode": contract["visits_per_class_mode"],
        "planned_visit_count": contract["planned_visit_count"],
        "formal_sample_target": contract["formal_sample_target"],
        "sample_credit_policy": (
            "zero-credit-diagnostic" if contract["role"] == "shakedown"
            else "formal-only-after-separate-readiness-and-deep-verification"
        ),
        "capture_authority": "none-requires-separate-live-capture-readiness",
    }


def _v5_selection_payload(
    profile_receipt: Mapping[str, Any],
    source_bytes: bytes,
    catalogue_bytes: bytes,
    generation: str,
    terminal_sha256s: Sequence[str],
    execution_binding: Mapping[str, Any],
    deep_verify_terminal: Callable[[str], Mapping[str, Any]],
) -> dict[str, Any]:
    """Select first-N sites only after exact-page H3 and complete-graph proof."""

    candidates = validate_v5_profile_receipt(
        profile_receipt, source_bytes, catalogue_bytes
    )
    binding = _execution_binding(execution_binding)
    if not isinstance(generation, str) or generation not in V5_COHORT_CONTRACTS:
        raise ValueError("v5 rapid-study cohort generation is unregistered")
    if not isinstance(terminal_sha256s, Sequence) or isinstance(
        terminal_sha256s, (str, bytes)
    ):
        raise ValueError("v5 rapid-study terminal SHA-256s must be ordered")
    if not callable(deep_verify_terminal):
        raise ValueError("v5 rapid-study requires independent terminal verification")
    contract = V5_COHORT_CONTRACTS[generation]
    if len(terminal_sha256s) > len(candidates):
        raise ValueError("v5 rapid-study terminal prefix exceeds candidate list")
    decisions: list[dict[str, Any]] = []
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate, digest in zip(candidates, terminal_sha256s, strict=False):
        if not isinstance(digest, str) or _SHA_RE.fullmatch(digest) is None or digest in seen:
            raise ValueError("v5 rapid-study terminal digest is invalid or repeated")
        seen.add(digest)
        facts = deep_verify_terminal(digest)
        fields = {
            "candidate_id", "domain", "source_kind", "outcome", "admission",
            "execution_binding", "root_screen", "site_safety_review",
            "selected_page_h3_proof",
        }
        if not isinstance(facts, Mapping) or set(facts) not in (fields, fields | {"triage"}):
            raise ValueError("v5 terminal verifier returned invalid facts")
        if _execution_binding(facts["execution_binding"]) != binding:
            raise ValueError("v5 terminal belongs to another source or image")
        if any(
            facts[key] != candidate[key] for key in ("candidate_id", "domain", "source_kind")
        ):
            raise ValueError("v5 terminal differs from frozen candidate order")
        screen = (
            _validated_v5_root_screen(facts["root_screen"], candidate)
            if facts["root_screen"] is not None else None
        )
        review = (
            _validated_site_safety_review(facts["site_safety_review"])
            if facts["site_safety_review"] is not None else None
        )
        page_proof = (
            _validated_v5_selected_page_h3_proof(
                facts["selected_page_h3_proof"], candidate
            )
            if facts["selected_page_h3_proof"] is not None else None
        )
        outcome, admission = facts["outcome"], facts["admission"]
        triage = facts.get("triage")
        if outcome == "admitted":
            if "triage" in facts or not isinstance(admission, Mapping) or set(admission) != {
                "selected_page_url", "prepared_workload_sha256",
                "cross_origin_resource_count", "full_resource_graph_sha256",
                "h3_proof_sha256",
            }:
                raise ValueError("v5 admitted site lacks exact page and complete graph proof")
            if unsafe_catalogue_domain_reason(candidate["domain"]) is not None:
                raise ValueError("v5 automatically unsafe site cannot be admitted")
            if screen is None or page_proof is None:
                raise ValueError("v5 admitted site lacks controlled root and selected-page screens")
            if page_proof["receipt_sha256"] == screen["receipt_sha256"]:
                raise ValueError("v5 selected-page H3 proof must be separately controlled")
            if (
                review is None
                or review["decision"] != SITE_SAFETY_REVIEW_POLICY["admission_decision"]
            ):
                raise ValueError("v5 admitted site lacks approved human safety review")
            if (
                admission["selected_page_url"] != page_proof["url"]
                or admission["h3_proof_sha256"] != page_proof["receipt_sha256"]
                or type(admission["cross_origin_resource_count"]) is not int
                or admission["cross_origin_resource_count"] < 1
                or any(
                    not isinstance(admission[key], str)
                    or _SHA_RE.fullmatch(admission[key]) is None
                    for key in ("prepared_workload_sha256", "full_resource_graph_sha256")
                )
            ):
                raise ValueError("v5 admission differs from selected-page or multi-origin proof")
            selected.append(candidate)
        elif outcome == "ineligible":
            if (
                admission is not None or "triage" in facts or screen is None
                or page_proof is None or review is None
                or review["decision"] != SITE_SAFETY_REVIEW_POLICY["admission_decision"]
            ):
                raise ValueError("v5 ineligible site lacks full screened page decision")
        elif outcome == "screen-deferred":
            if admission is not None or page_proof is not None or "triage" not in facts:
                raise ValueError("v5 screen-deferred site cannot carry admission proof")
            triage = _validated_v5_triage(triage, candidate, screen, review)
        else:
            raise ValueError("v5 operational errors are not scientific site terminals")
        decisions.append({
            "candidate_id": candidate["candidate_id"],
            "domain": candidate["domain"],
            "source_kind": candidate["source_kind"],
            "terminal_receipt_sha256": digest,
            "outcome": outcome,
            "admission": dict(admission) if admission is not None else None,
            "root_screen": screen,
            "site_safety_review": review,
            "selected_page_h3_proof": page_proof,
            **({"triage": triage} if outcome == "screen-deferred" else {}),
        })
        if len(selected) == contract["class_count"] and len(decisions) != len(terminal_sha256s):
            raise ValueError("v5 terminal prefix continues past the first N admitted sites")
    if len(selected) != contract["class_count"]:
        raise ValueError("v5 cohort is incomplete: not enough deep-verified sites")
    return {
        "study_id": contract["study_id"],
        "generation": generation,
        "cohort_role": contract["role"],
        "profile_receipt_sha256": _sha(_canonical_json(profile_receipt)),
        "source_sha256": SOURCE_SHA256,
        "fallback_catalogue_sha256": FALLBACK_CATALOGUE_SHA256,
        "execution_binding": binding,
        "selection_policy": V5_SELECTION_POLICY,
        "terminal_decisions": decisions,
        "selected_candidate_ids": [candidate["candidate_id"] for candidate in selected],
        "selected_candidates": [
            {
                key: candidate[key] for key in (
                    "candidate_id", "domain", "source_kind", "source_candidate_id",
                    "source_sha256", "source_position", "tranco_rank", "tranco_stratum",
                )
            }
            for candidate in selected
        ],
        "formal_modes": list(FORMAL_MODES),
        "visits_per_class_mode": contract["visits_per_class_mode"],
        "planned_visit_count": contract["planned_visit_count"],
        "formal_sample_target": contract["formal_sample_target"],
        "sample_credit_policy": (
            "zero-credit-diagnostic" if contract["role"] == "shakedown"
            else "formal-only-after-separate-readiness-and-deep-verification"
        ),
        "capture_authority": "none-requires-separate-live-capture-readiness",
    }


def build_v5_cohort_receipt(
    profile_receipt: Mapping[str, Any], source_bytes: bytes, catalogue_bytes: bytes, *,
    generation: str, terminal_sha256s: Sequence[str],
    execution_binding: Mapping[str, Any],
    deep_verify_terminal: Callable[[str], Mapping[str, Any]],
) -> dict[str, Any]:
    payload = _v5_selection_payload(
        profile_receipt, source_bytes, catalogue_bytes, generation, terminal_sha256s,
        execution_binding, deep_verify_terminal,
    )
    return _bind(payload, V5_COHORT_RECEIPT_TYPE, schema_version=V5_SCHEMA_VERSION)


def validate_v5_cohort_receipt(
    value: Mapping[str, Any], profile_receipt: Mapping[str, Any],
    source_bytes: bytes, catalogue_bytes: bytes, *,
    execution_binding: Mapping[str, Any],
    deep_verify_terminal: Callable[[str], Mapping[str, Any]],
) -> tuple[str, ...]:
    payload = _unpack(value, V5_COHORT_RECEIPT_TYPE, schema_version=V5_SCHEMA_VERSION)
    terminals = payload.get("terminal_decisions")
    if not isinstance(terminals, list):
        raise ValueError("v5 cohort terminal decisions are invalid")
    digests = [
        item.get("terminal_receipt_sha256") if isinstance(item, Mapping) else None
        for item in terminals
    ]
    expected = _v5_selection_payload(
        profile_receipt, source_bytes, catalogue_bytes, payload.get("generation"), digests,
        execution_binding, deep_verify_terminal,
    )
    if payload != expected:
        raise ValueError("v5 rapid-study cohort differs from deep-verified selection")
    return tuple(expected["selected_candidate_ids"])


def build_cohort_receipt(
    profile_receipt: Mapping[str, Any],
    source_bytes: bytes,
    catalogue_bytes: bytes,
    *,
    generation: str,
    terminal_sha256s: Sequence[str],
    execution_binding: Mapping[str, Any],
    deep_verify_terminal: Callable[[str], Mapping[str, Any]],
) -> dict[str, Any]:
    """Select the first N admitted sites with a verified decision for every prior site."""

    payload = _selection_payload(
        profile_receipt, source_bytes, catalogue_bytes, generation, terminal_sha256s,
        execution_binding, deep_verify_terminal,
    )
    return _bind(payload, COHORT_RECEIPT_TYPE)


def validate_cohort_receipt(
    value: Mapping[str, Any],
    profile_receipt: Mapping[str, Any],
    source_bytes: bytes,
    catalogue_bytes: bytes,
    *,
    execution_binding: Mapping[str, Any],
    deep_verify_terminal: Callable[[str], Mapping[str, Any]],
) -> tuple[str, ...]:
    """Reopen every ordered decision using the independent verifier.

    For admission, the callback must verify the referenced receipt's actual
    bytes, current terminal schema, approved human site-safety review, full
    live browser resource graph and HTTP/3 evidence.  For manual safety
    exclusion it must verify the human review receipt and its narrow reason.
    For screen deferral it must verify the complete original controlled survey
    batch and first candidate probe; a non-clear homepage remains unassessed
    for full-page eligibility.  A hint URL, digest string, or this receipt
    alone cannot authorize capture.
    """

    payload = _unpack(value, COHORT_RECEIPT_TYPE)
    terminals = payload.get("terminal_decisions")
    if not isinstance(terminals, list):
        raise ValueError("rapid-study cohort terminal decisions are invalid")
    digests = [
        entry.get("terminal_receipt_sha256") if isinstance(entry, dict) else None
        for entry in terminals
    ]
    expected = _selection_payload(
        profile_receipt, source_bytes, catalogue_bytes, payload.get("generation"), digests,
        execution_binding, deep_verify_terminal,
    )
    if payload != expected:
        raise ValueError("rapid-study cohort differs from deep-verified ordered selection")
    return tuple(expected["selected_candidate_ids"])


def write_receipt_create_only(path: Path, receipt: Mapping[str, Any]) -> Path:
    """Publish a complete rapid-study receipt once, preserving collisions."""

    if not isinstance(receipt, Mapping) or receipt.get("receipt_type") not in {
        PROFILE_RECEIPT_TYPE, COHORT_RECEIPT_TYPE,
        V5_PROFILE_RECEIPT_TYPE, V5_COHORT_RECEIPT_TYPE,
    }:
        raise ValueError("only rapid-study profile and cohort receipts may be published")
    schema_version = (
        V5_SCHEMA_VERSION if receipt["receipt_type"] in {
            V5_PROFILE_RECEIPT_TYPE, V5_COHORT_RECEIPT_TYPE,
        } else SCHEMA_VERSION
    )
    _unpack(receipt, receipt["receipt_type"], schema_version=schema_version)
    durable_create(path, _canonical_json(receipt))
    return path
