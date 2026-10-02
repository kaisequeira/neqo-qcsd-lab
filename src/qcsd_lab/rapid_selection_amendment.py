"""Prospective selection amendments beside the unchanged frozen v5 study.

V1 records fresh typed browser-navigation deferrals. V2 adds an explicit
automatic URL/domain screen and narrow typed navigation/preparation deferrals.
Deferrals give no admission or trace credit and make no whole-domain claim.
Complete admitted graphs, controlled page H3 proof and the 16,000-visit grid
remain required; the original v1 declaration stays independently verifiable.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import rapid_study_profile as profile
from .util import durable_create

SELECTION_AMENDMENT_RECEIPT_TYPE = "qcsd-rapid-v5-selection-amendment"
AMENDED_COHORT_RECEIPT_TYPE = "qcsd-rapid-v5-amended-class-cohort"
AMENDED_SELECTION_POLICY = "first-N-admitted-with-prospective-browser-policy-screen-deferrals-v1"
AMENDED_V2_SELECTION_POLICY = "first-N-automatic-public-url-screened-with-typed-page-policy-deferrals-v2"
AMENDED_V2_ADMISSION_POLICY = "root-and-exact-page-h3-automatic-public-url-screen-complete-live-graph-and-cross-origin-v2"
BROWSER_POLICY_DEFERRAL_POLICY = "prospective-nonreplayable-browser-navigation-deferral-v1"
BROWSER_POLICY_DEFERRAL_REASON = "browser-navigation-policy-deferred"
PAGE_POLICY_DEFERRAL_POLICY = "prospective-typed-page-policy-screen-deferral-v2"
PAGE_POLICY_DEFERRAL_REASON = "page-policy-screen-deferred"
PARENT_PROFILE_PUBLICATION_UTC = "2026-10-02T12:58:17Z"
FROZEN_V1_AMENDMENT_PUBLICATION_UTC = "2026-10-02T14:30:27.785695Z"
FROZEN_V1_AMENDMENT_SHA256 = "ffc91c4a4fafe39ae9ec3875c982d8a5537fcaae6a253ee58e33c7f492bc8486"
AUTOMATED_SITE_SCREEN_POLICY = "frozen-public-url-and-domain-screen-v1"
AUTOMATED_SITE_SCREEN_DECISION = "automatic-policy-pass"


def automated_screen_policy_payload() -> dict[str, Any]:
    """Declare the narrow URL/domain rules; this is no content classifier."""
    return {
        "policy": AUTOMATED_SITE_SCREEN_POLICY,
        "decision": AUTOMATED_SITE_SCREEN_DECISION,
        "domain_safety_policy": deepcopy(profile.DOMAIN_SAFETY_POLICY),
        "selected_page_url_policy": "canonical-query-free-html-https-default-port-exact-candidate-or-subdomain-v1",
        "selected_page_choice": "independently-rederived-navigation-ordinal-zero-through-four",
        "selected_page_h3": "separate-passing-control-known-valid-exact-url-receipt",
        "named_human_review": "not-required",
        "content_classification_claimed": False,
        "scientific_credit": False,
    }


def automated_screen_policy_bytes() -> bytes:
    return profile._canonical_json(automated_screen_policy_payload())


def automated_screen_policy_sha256() -> str:
    return profile._sha(automated_screen_policy_bytes())


def _utc(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("selection amendment publication must be a UTC timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("selection amendment publication must be a UTC timestamp") from error
    if result.tzinfo is None or result.utcoffset() != UTC.utcoffset(result):
        raise ValueError("selection amendment publication must use UTC")
    if value != result.isoformat().replace("+00:00", "Z"):
        raise ValueError("selection amendment publication must use canonical UTC")
    return result


def _amendment_payload(
    published_at_utc: str, parent_profile_sha256: str, *, revision: int = 1,
) -> dict[str, Any]:
    if type(revision) is not int or revision not in (1, 2):
        raise ValueError("selection amendment revision is unregistered")
    published = _utc(published_at_utc)
    if published < _utc(PARENT_PROFILE_PUBLICATION_UTC) or published > datetime.now(UTC):
        raise ValueError("selection amendment publication is before its parent or in the future")
    if parent_profile_sha256 != profile.FROZEN_V5_PROFILE_SHA256:
        raise ValueError("selection amendment parent is not the frozen v5 profile")
    result = {
        "amendment_id": "crux73-tranco600-rapid-v5-selection-v1",
        "parent_profile_sha256": parent_profile_sha256,
        "parent_selection_policy": profile.V5_SELECTION_POLICY,
        "published_at_utc": published_at_utc,
        "selection_policy": AMENDED_SELECTION_POLICY,
        "browser_policy_deferral": {
            "policy": BROWSER_POLICY_DEFERRAL_POLICY,
            "triage_reason": BROWSER_POLICY_DEFERRAL_REASON,
            "exception_type": "NonReplayableEgressPolicyError",
            "action_kind": "catalogue-boundary-navigation",
            "action_scope": "catalogue-root-and-optional-link-navigation",
            "failure_page_attribution": "unavailable",
            "required_root_screen": "known-valid-with-passing-controls",
            "human_review": "none-at-this-navigation-screen-branch",
            "outcome": "screen-deferred",
            "scientific_credit": False,
            "scope": "candidate-navigation-screen-only-not-whole-domain-ineligibility",
            "required_proof": "independently-reopened-exact-candidate-image-source-module-and-raw-guard-evidence",
        },
        "freshness_policy": {
            "parent_profile_not_before_utc": PARENT_PROFILE_PUBLICATION_UTC,
            "supporting_root_observations": "may-reopen-unchanged-parent-v5-profile-source-image-and-module-bound-observations",
            "new_typed_browser_policy_failure": "started-at-or-after-published-at-utc",
            "old_failed_attempts": "preserved-zero-credit-no-promotion-relabel-or-retroactive-terminal-authority",
        },
        "candidate_order_policy": profile.ORDER_POLICY,
        "admission_policy": profile.V5_ADMISSION_POLICY,
        "admitted_resource_graph": "unchanged-complete-live-resource-graph-with-cross-origin-proof",
        "non_replayable_egress_guard": "unchanged-fail-closed-no-api-suppression-or-transport-waiver",
        "formal_modes": list(profile.FORMAL_MODES),
        "cohort_contracts": [
            {"generation": generation, **contract}
            for generation, contract in profile.V5_COHORT_CONTRACTS.items()
        ],
        "capture_authority": "none-requires-separate-live-capture-readiness",
    }
    if revision == 2:
        if published < _utc(FROZEN_V1_AMENDMENT_PUBLICATION_UTC):
            raise ValueError("selection amendment v2 publication is before its v1 parent")
        # Reconstruct the frozen v1 envelope independently. A change to its
        # declaration cannot silently become a differently interpreted parent.
        parent = profile._bind(
            _amendment_payload(FROZEN_V1_AMENDMENT_PUBLICATION_UTC, parent_profile_sha256),
            SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5,
        )
        parent_sha = profile._sha(profile._canonical_json(parent))
        if parent_sha != FROZEN_V1_AMENDMENT_SHA256:
            raise ValueError("frozen v1 selection amendment declaration no longer verifies")
        result.update({
            "amendment_id": "crux73-tranco600-rapid-v5-selection-v2",
            "revision": 2,
            "parent_selection_amendment_sha256": parent_sha,
            "selection_policy": AMENDED_V2_SELECTION_POLICY,
            "parent_admission_policy": profile.V5_ADMISSION_POLICY,
            "admission_policy": AMENDED_V2_ADMISSION_POLICY,
            "automated_site_screen_policy": automated_screen_policy_payload(),
            "automated_screen_policy_sha256": automated_screen_policy_sha256(),
            "page_policy_deferral": {
                "policy": PAGE_POLICY_DEFERRAL_POLICY,
                "triage_reason": PAGE_POLICY_DEFERRAL_REASON,
                "outcome": PAGE_POLICY_DEFERRAL_REASON,
                "scientific_credit": False,
                "scope": "candidate-action-screen-only-not-whole-domain-ineligibility",
                "required_root_screen": "known-valid-with-passing-controls",
                "navigation_action": {
                    "kind": "catalogue-boundary-navigation",
                    "scope": "catalogue-root-and-optional-link-navigation",
                    "failure_page_attribution": "unavailable",
                    "exception_types": ["PassiveRenderPolicyError"],
                    "selected_page_h3_and_automated_screen": "absent-before-page-selection",
                },
                "preparation_action": {
                    "kind": "complete-graph-preparation",
                    "exception_types": [
                        "PassiveRenderPolicyError", "FullGraphH3PolicyError",
                        "ResponseStabilityPolicyError",
                    ],
                    "required_proof": "exact-navigation-selected-page-h3-and-automated-screen",
                },
                "required_failure_proof": "independently-reopened-exact-candidate-image-source-modules-and-raw-typed-stage-evidence",
                "new_failure_freshness": "started-at-or-after-published-at-utc",
                "other_errors": "operational-no-policy-screen-terminal-authority",
            },
        })
        result["freshness_policy"] = {
            **result["freshness_policy"],
            "supporting_navigation_and_exact_page_h3": "may-reopen-unchanged-parent-v5-profile-source-image-and-independent-module-bound-observations",
            "new_automated_screen_and_page_policy_failure": "at-or-after-published-at-utc",
            "v1_browser_failure_receipts": "retain-v1-only-authority-no-v2-relabel-or-promotion",
        }
    return result


def build_selection_amendment(
    *, published_at_utc: str,
    parent_profile_sha256: str = profile.FROZEN_V5_PROFILE_SHA256,
    revision: int = 1,
) -> dict[str, Any]:
    return profile._bind(
        _amendment_payload(published_at_utc, parent_profile_sha256, revision=revision),
        SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5,
    )


def validate_selection_amendment(
    value: Mapping[str, Any], *,
    parent_profile_sha256: str = profile.FROZEN_V5_PROFILE_SHA256,
) -> dict[str, Any]:
    payload = profile._unpack(value, SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5)
    ids = {
        "crux73-tranco600-rapid-v5-selection-v1": 1,
        "crux73-tranco600-rapid-v5-selection-v2": 2,
    }
    amendment_id = payload.get("amendment_id")
    revision = ids.get(amendment_id) if isinstance(amendment_id, str) else None
    expected = _amendment_payload(
        payload.get("published_at_utc"), parent_profile_sha256, revision=revision,
    )
    if payload != expected:
        raise ValueError("selection amendment differs from its prospective fixed contract")
    return payload


def selection_amendment_revision(value: Mapping[str, Any]) -> int:
    return validate_selection_amendment(value).get("revision", 1)


def selection_amendment_not_before_utc(value: Mapping[str, Any]) -> datetime:
    return _utc(validate_selection_amendment(value)["published_at_utc"])


def selection_amendment_sha256(value: Mapping[str, Any]) -> str:
    validate_selection_amendment(value)
    return profile._sha(profile._canonical_json(value))


def write_receipt_create_only(path: Path, receipt: Mapping[str, Any]) -> Path:
    """Publish a new amendment/cohort envelope once without widening v5."""
    if not isinstance(receipt, Mapping) or receipt.get("receipt_type") not in {
        SELECTION_AMENDMENT_RECEIPT_TYPE, AMENDED_COHORT_RECEIPT_TYPE,
    }:
        raise ValueError("only selection amendment and amended cohort receipts may be published")
    profile._unpack(receipt, receipt["receipt_type"], schema_version=5)
    if receipt["receipt_type"] == SELECTION_AMENDMENT_RECEIPT_TYPE:
        validate_selection_amendment(receipt)
    durable_create(path, profile._canonical_json(receipt))
    return path


def _browser_deferral(
    facts: Mapping[str, Any], candidate: Mapping[str, Any], binding: Mapping[str, str],
    selection_amendment: Mapping[str, Any], screen: Mapping[str, Any] | None,
    review: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if (
        facts["outcome"] != "screen-deferred" or facts["admission"] is not None
        or facts["selected_page_h3_proof"] is not None or screen is None
        or screen["outcome"] != "known-valid"
        or profile.unsafe_catalogue_domain_reason(candidate["domain"]) is not None
        or review is not None
        or facts["triage"] != {
            "policy": BROWSER_POLICY_DEFERRAL_POLICY,
            "reason": BROWSER_POLICY_DEFERRAL_REASON, "safety_reason": None,
        }
    ):
        raise ValueError("browser-policy deferral cannot admit or scientifically reject a site")
    from .rapid_browser_policy_evidence import validate_browser_policy_failure_facts

    failure = validate_browser_policy_failure_facts(
        facts["browser_policy_failure"], candidate=candidate,
        execution_binding=binding,
        policy_amendment_sha256=selection_amendment_sha256(selection_amendment),
        not_before_utc=selection_amendment_not_before_utc(selection_amendment),
    )
    return dict(failure)


def _automated_screen(
    value: Any, candidate: Mapping[str, Any], page_proof: Mapping[str, Any] | None,
    binding: Mapping[str, str], selection_amendment: Mapping[str, Any],
) -> dict[str, Any] | None:
    if value is None:
        return None
    if page_proof is None:
        raise ValueError("automated site screen lacks its exact selected-page H3 proof")
    from .rapid_site_admission import validate_automated_site_screen_facts

    screen = validate_automated_site_screen_facts(
        value, candidate=candidate, selected_page_url=page_proof["url"],
        execution_binding=binding,
        selection_amendment_sha256=selection_amendment_sha256(selection_amendment),
        not_before_utc=selection_amendment_not_before_utc(selection_amendment),
    )
    if (
        screen["policy"] != AUTOMATED_SITE_SCREEN_POLICY
        or screen["decision"] != AUTOMATED_SITE_SCREEN_DECISION
        or screen["policy_sha256"] != automated_screen_policy_sha256()
        or screen["selected_page_url"] != page_proof["url"]
        or screen["selected_page_ordinal"] != page_proof["selected_page_ordinal"]
        or screen["navigation_receipt_sha256"] != page_proof["navigation_receipt_sha256"]
        or screen["selected_page_h3_receipt_sha256"] != page_proof["receipt_sha256"]
    ):
        raise ValueError("automated site screen differs from its declared rules or exact page proof")
    return dict(screen)


def _page_policy_deferral(
    facts: Mapping[str, Any], candidate: Mapping[str, Any], binding: Mapping[str, str],
    selection_amendment: Mapping[str, Any], root: Mapping[str, Any] | None,
    page_proof: Mapping[str, Any] | None, automated_screen: Mapping[str, Any] | None,
    review: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if (
        facts["outcome"] != PAGE_POLICY_DEFERRAL_REASON or facts["admission"] is not None
        or root is None or root["outcome"] != "known-valid" or review is not None
        or profile.unsafe_catalogue_domain_reason(candidate["domain"]) is not None
        or facts["triage"] != {
            "policy": PAGE_POLICY_DEFERRAL_POLICY,
            "reason": PAGE_POLICY_DEFERRAL_REASON, "safety_reason": None,
        }
    ):
        raise ValueError("typed page-policy deferral lacks its controlled screening context")
    from .rapid_site_admission import validate_page_policy_failure_facts

    failure = validate_page_policy_failure_facts(
        facts["page_policy_failure"], candidate=candidate, execution_binding=binding,
        selection_amendment_sha256=selection_amendment_sha256(selection_amendment),
        not_before_utc=selection_amendment_not_before_utc(selection_amendment),
        selected_page_h3_proof=page_proof, automated_site_screen=automated_screen,
    )
    action = failure["action"]["kind"]
    if action == "catalogue-boundary-navigation":
        if page_proof is not None or automated_screen is not None:
            raise ValueError("navigation policy deferral cannot carry later preparation proofs")
    elif action == "complete-graph-preparation":
        if page_proof is None or automated_screen is None:
            raise ValueError("preparation policy deferral lacks exact page and automated screen proofs")
    else:
        raise ValueError("page-policy deferral action is unregistered")
    return dict(failure)


def build_amended_cohort_receipt(
    profile_receipt: Mapping[str, Any], source_bytes: bytes, catalogue_bytes: bytes, *,
    selection_amendment: Mapping[str, Any], generation: str,
    terminal_sha256s: Sequence[str], execution_binding: Mapping[str, Any],
    deep_verify_terminal: Callable[[str], Mapping[str, Any]],
) -> dict[str, Any]:
    payload = _selection_payload(
        profile_receipt, source_bytes, catalogue_bytes, generation, terminal_sha256s,
        execution_binding, deep_verify_terminal, selection_amendment,
    )
    return profile._bind(payload, AMENDED_COHORT_RECEIPT_TYPE, schema_version=5)


def validate_amended_cohort_receipt(
    value: Mapping[str, Any], profile_receipt: Mapping[str, Any],
    source_bytes: bytes, catalogue_bytes: bytes, *,
    selection_amendment: Mapping[str, Any], execution_binding: Mapping[str, Any],
    deep_verify_terminal: Callable[[str], Mapping[str, Any]],
) -> tuple[str, ...]:
    payload = profile._unpack(value, AMENDED_COHORT_RECEIPT_TYPE, schema_version=5)
    terminals = payload.get("terminal_decisions")
    if not isinstance(terminals, list):
        raise ValueError("amended cohort terminal decisions are invalid")
    digests = [
        item.get("terminal_receipt_sha256") if isinstance(item, Mapping) else None
        for item in terminals
    ]
    expected = _selection_payload(
        profile_receipt, source_bytes, catalogue_bytes, payload.get("generation"), digests,
        execution_binding, deep_verify_terminal, selection_amendment,
    )
    if payload != expected:
        raise ValueError("amended cohort differs from deep-verified ordered selection")
    return tuple(expected["selected_candidate_ids"])



def _selection_payload(
    profile_receipt: Mapping[str, Any],
    source_bytes: bytes,
    catalogue_bytes: bytes,
    generation: str,
    terminal_sha256s: Sequence[str],
    execution_binding: Mapping[str, Any],
    deep_verify_terminal: Callable[[str], Mapping[str, Any]],
    selection_amendment: Mapping[str, Any],
) -> dict[str, Any]:
    """Select first-N sites only after exact-page H3 and complete-graph proof."""

    candidates = profile.validate_v5_profile_receipt(
        profile_receipt, source_bytes, catalogue_bytes
    )
    amendment_payload = validate_selection_amendment(
        selection_amendment,
        parent_profile_sha256=profile._sha(profile._canonical_json(profile_receipt)),
    )
    revision = amendment_payload.get("revision", 1)
    binding = profile._execution_binding(execution_binding)
    if not isinstance(generation, str) or generation not in profile.V5_COHORT_CONTRACTS:
        raise ValueError("v5 rapid-study cohort generation is unregistered")
    if not isinstance(terminal_sha256s, Sequence) or isinstance(
        terminal_sha256s, (str, bytes)
    ):
        raise ValueError("v5 rapid-study terminal SHA-256s must be ordered")
    if not callable(deep_verify_terminal):
        raise ValueError("v5 rapid-study requires independent terminal verification")
    contract = profile.V5_COHORT_CONTRACTS[generation]
    if len(terminal_sha256s) > len(candidates):
        raise ValueError("v5 rapid-study terminal prefix exceeds candidate list")
    decisions: list[dict[str, Any]] = []
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate, digest in zip(candidates, terminal_sha256s, strict=False):
        if not isinstance(digest, str) or profile._SHA_RE.fullmatch(digest) is None or digest in seen:
            raise ValueError("v5 rapid-study terminal digest is invalid or repeated")
        seen.add(digest)
        facts = deep_verify_terminal(digest)
        fields = {
            "candidate_id", "domain", "source_kind", "outcome", "admission",
            "execution_binding", "root_screen", "site_safety_review",
            "selected_page_h3_proof",
        }
        if revision == 2:
            fields |= {"automated_site_screen"}
        allowed_fields = (
            fields, fields | {"triage"}, fields | {"triage", "browser_policy_failure"},
        )
        if revision == 2:
            allowed_fields += (fields | {"triage", "page_policy_failure"},)
        if not isinstance(facts, Mapping) or set(facts) not in allowed_fields:
            raise ValueError("v5 terminal verifier returned invalid facts")
        if profile._execution_binding(facts["execution_binding"]) != binding:
            raise ValueError("v5 terminal belongs to another source or image")
        if any(
            facts[key] != candidate[key] for key in ("candidate_id", "domain", "source_kind")
        ):
            raise ValueError("v5 terminal differs from frozen candidate order")
        screen = (
            profile._validated_v5_root_screen(facts["root_screen"], candidate)
            if facts["root_screen"] is not None else None
        )
        review = (
            profile._validated_site_safety_review(facts["site_safety_review"])
            if facts["site_safety_review"] is not None else None
        )
        page_proof = (
            profile._validated_v5_selected_page_h3_proof(
                facts["selected_page_h3_proof"], candidate
            )
            if facts["selected_page_h3_proof"] is not None else None
        )
        outcome, admission = facts["outcome"], facts["admission"]
        triage = facts.get("triage")
        browser_failure = None
        page_failure = None
        automatic_screen = (
            _automated_screen(
                facts["automated_site_screen"], candidate, page_proof, binding,
                selection_amendment,
            ) if revision == 2 else None
        )
        if "browser_policy_failure" in facts:
            if automatic_screen is not None:
                raise ValueError("browser navigation deferral cannot carry a later automated page screen")
            browser_failure = _browser_deferral(
                facts, candidate, binding, selection_amendment, screen, review,
            )
        elif revision == 2 and "page_policy_failure" in facts:
            page_failure = _page_policy_deferral(
                facts, candidate, binding, selection_amendment, screen, page_proof,
                automatic_screen, review,
            )
        elif outcome == "admitted":
            if "triage" in facts or not isinstance(admission, Mapping) or set(admission) != {
                "selected_page_url", "prepared_workload_sha256",
                "cross_origin_resource_count", "full_resource_graph_sha256",
                "h3_proof_sha256",
            }:
                raise ValueError("v5 admitted site lacks exact page and complete graph proof")
            if profile.unsafe_catalogue_domain_reason(candidate["domain"]) is not None:
                raise ValueError("v5 automatically unsafe site cannot be admitted")
            if screen is None or page_proof is None:
                raise ValueError("v5 admitted site lacks controlled root and selected-page screens")
            if page_proof["receipt_sha256"] == screen["receipt_sha256"]:
                raise ValueError("v5 selected-page H3 proof must be separately controlled")
            if revision == 1 and (
                review is None or review["decision"] != profile.SITE_SAFETY_REVIEW_POLICY["admission_decision"]
            ):
                raise ValueError("v5 admitted site lacks approved human safety review")
            if revision == 2 and (
                automatic_screen is None
                or (review is not None and review["decision"] != profile.SITE_SAFETY_REVIEW_POLICY["admission_decision"])
            ):
                raise ValueError("v2 admitted site lacks its independent automatic public URL screen")
            if (
                admission["selected_page_url"] != page_proof["url"]
                or admission["h3_proof_sha256"] != page_proof["receipt_sha256"]
                or type(admission["cross_origin_resource_count"]) is not int
                or admission["cross_origin_resource_count"] < 1
                or any(
                    not isinstance(admission[key], str)
                    or profile._SHA_RE.fullmatch(admission[key]) is None
                    for key in ("prepared_workload_sha256", "full_resource_graph_sha256")
                )
            ):
                raise ValueError("v5 admission differs from selected-page or multi-origin proof")
            selected.append(candidate)
        elif outcome == "ineligible":
            if (
                admission is not None or "triage" in facts or screen is None
                or page_proof is None
                or (revision == 1 and (
                    review is None or review["decision"] != profile.SITE_SAFETY_REVIEW_POLICY["admission_decision"]
                ))
                or (revision == 2 and (
                    automatic_screen is None
                    or (review is not None and review["decision"] != profile.SITE_SAFETY_REVIEW_POLICY["admission_decision"])
                ))
            ):
                raise ValueError("v5 ineligible site lacks full screened page decision")
        elif outcome == "screen-deferred":
            if admission is not None or page_proof is not None or "triage" not in facts:
                raise ValueError("v5 screen-deferred site cannot carry admission proof")
            triage = profile._validated_v5_triage(triage, candidate, screen, review)
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
            **({"triage": triage} if outcome in {"screen-deferred", PAGE_POLICY_DEFERRAL_REASON} else {}),
            **({"browser_policy_failure": browser_failure} if browser_failure is not None else {}),
            **({"automated_site_screen": automatic_screen} if revision == 2 else {}),
            **({"page_policy_failure": page_failure} if page_failure is not None else {}),
        })
        if len(selected) == contract["class_count"] and len(decisions) != len(terminal_sha256s):
            raise ValueError("v5 terminal prefix continues past the first N admitted sites")
    if len(selected) != contract["class_count"]:
        raise ValueError("v5 cohort is incomplete: not enough deep-verified sites")
    return {
        "study_id": contract["study_id"],
        "generation": generation,
        "cohort_role": contract["role"],
        "profile_receipt_sha256": profile._sha(profile._canonical_json(profile_receipt)),
        "source_sha256": profile.SOURCE_SHA256,
        "fallback_catalogue_sha256": profile.FALLBACK_CATALOGUE_SHA256,
        "execution_binding": binding,
        "selection_policy": amendment_payload["selection_policy"],
        "selection_amendment_sha256": selection_amendment_sha256(selection_amendment),
        **({"automated_screen_policy_sha256": automated_screen_policy_sha256()} if revision == 2 else {}),
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
        "formal_modes": list(profile.FORMAL_MODES),
        "visits_per_class_mode": contract["visits_per_class_mode"],
        "planned_visit_count": contract["planned_visit_count"],
        "formal_sample_target": contract["formal_sample_target"],
        "sample_credit_policy": (
            "zero-credit-diagnostic" if contract["role"] == "shakedown"
            else "formal-only-after-separate-readiness-and-deep-verification"
        ),
        "capture_authority": "none-requires-separate-live-capture-readiness",
    }
