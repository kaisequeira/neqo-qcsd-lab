"""Retain prospective browser policy failures without navigation success credit.

The existing navigation operation starts at the exact catalogue HTTPS root and
may inspect optional pages. Its guard evidence does not attribute the failure
to a particular document, so these receipts make that limit explicit.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import (
    acquisition_errors, browser_egress, class_acquisition, class_catalogue,
    rapid_page_evidence as page, rapid_study_profile, util,
)
from .acquisition_errors import NonReplayableEgressPolicyError
from .class_acquisition import ExistingAcquisitionBackend

BROWSER_POLICY_FAILURE_RECEIPT_TYPE = "qcsd-rapid-v5-root-browser-policy-failure-v1"
BROWSER_POLICY_FAILURE_POLICY = "exact-frozen-candidate-browser-navigation-typed-policy-failure-v1"
ACTION_SCOPE = "catalogue-root-and-optional-link-navigation"
_PAYLOAD_KEYS = {
    "policy", "profile_sha256", "policy_amendment_sha256", "candidate",
    "execution_binding", "runtime", "implementation_hashes", "started_at",
    "completed_at", "action", "failure_page_attribution", "raw_failure",
    "scientific_credit",
}


def implementation_sources() -> dict[str, Path]:
    """Return producer and independent verifier bytes to freeze prospectively."""
    return {
        "qcsd_lab.rapid_browser_policy_evidence": Path(__file__),
        "qcsd_lab.rapid_page_evidence": Path(page.__file__),
        "qcsd_lab.browser_egress": Path(browser_egress.__file__),
        "qcsd_lab.acquisition_errors": Path(acquisition_errors.__file__),
        "qcsd_lab.class_acquisition": Path(class_acquisition.__file__),
        "qcsd_lab.class_catalogue": Path(class_catalogue.__file__),
        "qcsd_lab.rapid_study_profile": Path(rapid_study_profile.__file__),
        "qcsd_lab.util": Path(util.__file__),
    }


def implementation_hashes() -> dict[str, str]:
    return {name: page._sha(page._regular(path).read_bytes())
            for name, path in implementation_sources().items()}


def _hashes(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != set(implementation_sources()) or any(
        not isinstance(digest, str) or page._SHA.fullmatch(digest) is None
        for digest in value.values()
    ):
        raise ValueError("browser policy implementation hashes are invalid")
    return dict(value)


def _amendment(value: Any) -> str:
    if not isinstance(value, str) or page._SHA.fullmatch(value) is None:
        raise ValueError("browser policy amendment digest is invalid")
    return value


def _action(domain: str) -> dict[str, Any]:
    return {
        "kind": "catalogue-boundary-navigation", "url": f"https://{domain}/",
        "scope": ACTION_SCOPE, "selected_page_ordinal": None,
    }


def _failure(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "exception_type", "message", "evidence"
    } or value["exception_type"] != "NonReplayableEgressPolicyError" or (
        not isinstance(value["message"], str) or not value["message"]
        or len(value["message"]) > 65_536
    ):
        raise ValueError("browser policy failure is not the exact retained typed failure")
    return {
        "exception_type": value["exception_type"], "message": value["message"],
        "evidence": browser_egress.validate_non_replayable_egress_failure_evidence(
            value["evidence"]
        ),
    }


def produce_navigation_policy_observation(
    *, output: Path, profile: Path, source: Path, catalogue: Path, candidate_id: str,
    execution_binding: Mapping[str, Any], policy_amendment_sha256: str,
    expected_implementation_hashes: Mapping[str, str], not_before_utc: datetime,
    backend: ExistingAcquisitionBackend | None = None,
) -> dict[str, Any]:
    """Perform one new navigation; retain success or only the exact typed failure.

    All other errors propagate as operational failures. The ordinary navigation
    producer and receipt remain unchanged, including their deterministic pages.
    """
    profile_receipt, source_bytes, catalogue_bytes = page._inputs(profile, source, catalogue)
    candidate = page._candidate(profile_receipt, source_bytes, catalogue_bytes, candidate_id)
    binding = page._binding(execution_binding)
    amendment = _amendment(policy_amendment_sha256)
    runtime = page._runtime_payload(binding)
    hashes = implementation_hashes()
    if hashes != _hashes(expected_implementation_hashes):
        raise ValueError("browser policy implementation changed after its prospective freeze")
    output = Path(output).absolute()
    if any(part.is_symlink() for part in (output, *output.parents)):
        raise ValueError("browser policy destination must not contain symlinks")
    if output.exists():
        raise FileExistsError(output)
    started = datetime.now(UTC).isoformat()
    page._freshness(started, started, not_before_utc)
    try:
        return page.produce_navigation_receipt(
            output=output, profile=profile, source=source, catalogue=catalogue,
            candidate_id=candidate_id, execution_binding=binding,
            backend=backend if backend is not None else ExistingAcquisitionBackend(),
        )
    except NonReplayableEgressPolicyError as error:
        if type(error) is not NonReplayableEgressPolicyError:
            raise
        raw_failure = _failure({
            "exception_type": type(error).__name__, "message": str(error),
            "evidence": error.evidence,
        })
    completed = datetime.now(UTC).isoformat()
    page._freshness(started, completed, not_before_utc)
    if page._runtime_payload(binding) != runtime or implementation_hashes() != hashes:
        raise ValueError("browser policy source/image/implementation changed during navigation")
    return page._create(output, {
        "policy": BROWSER_POLICY_FAILURE_POLICY,
        "profile_sha256": rapid_study_profile.FROZEN_V5_PROFILE_SHA256,
        "policy_amendment_sha256": amendment, "candidate": candidate,
        "execution_binding": binding, "runtime": runtime, "implementation_hashes": hashes,
        "started_at": started, "completed_at": completed, "action": _action(candidate["domain"]),
        "failure_page_attribution": "unavailable", "raw_failure": raw_failure,
        "scientific_credit": False,
    }, BROWSER_POLICY_FAILURE_RECEIPT_TYPE)


def verify_browser_policy_failure(
    path: Path, *, profile_receipt: Mapping[str, Any], source_bytes: bytes,
    catalogue_bytes: bytes, candidate_id: str, execution_binding: Mapping[str, Any],
    policy_amendment_sha256: str, expected_implementation_hashes: Mapping[str, str],
    not_before_utc: datetime,
) -> dict[str, Any]:
    """Reopen the typed guard payload under independently supplied frozen bindings."""
    payload, digest = page._open(path, BROWSER_POLICY_FAILURE_RECEIPT_TYPE)
    candidate = page._candidate(profile_receipt, source_bytes, catalogue_bytes, candidate_id)
    binding = page._binding(execution_binding)
    amendment = _amendment(policy_amendment_sha256)
    if set(payload) != _PAYLOAD_KEYS or payload["policy"] != BROWSER_POLICY_FAILURE_POLICY or (
        payload["profile_sha256"] != rapid_study_profile.FROZEN_V5_PROFILE_SHA256
        or payload["policy_amendment_sha256"] != amendment
        or page._json(payload["candidate"]) != page._json(candidate)
        or payload["execution_binding"] != binding or payload["action"] != _action(candidate["domain"])
        or payload["failure_page_attribution"] != "unavailable"
        or payload["scientific_credit"] is not False
        or _hashes(payload["implementation_hashes"]) != _hashes(expected_implementation_hashes)
    ):
        raise ValueError("browser policy source/profile/amendment/action binding differs")
    runtime = page._validate_runtime(payload["runtime"], binding)
    page._freshness(payload["started_at"], payload["completed_at"], not_before_utc)
    raw_failure = _failure(payload["raw_failure"])
    return {
        "browser_policy_failure_receipt_sha256": digest, "policy": payload["policy"],
        "profile_sha256": payload["profile_sha256"], "policy_amendment_sha256": amendment,
        "candidate": candidate, "execution_binding": binding, "runtime_source": runtime,
        "implementation_hashes": _hashes(payload["implementation_hashes"]),
        "started_at": payload["started_at"], "completed_at": payload["completed_at"],
        "action": _action(candidate["domain"]), "failure_page_attribution": "unavailable",
        "raw_failure": raw_failure, "scientific_credit": False,
    }


verify_navigation_policy_failure = verify_browser_policy_failure


def validate_browser_policy_failure_facts(
    value: Any, *, candidate: Mapping[str, Any], execution_binding: Mapping[str, Any],
    policy_amendment_sha256: str, not_before_utc: datetime,
) -> dict[str, Any]:
    """Validate facts returned by an independent receipt-reopening callback.

    This structural check does not replace reopening the receipt with externally
    supplied implementation hashes and the retained raw source-manifest bytes.
    """
    keys = (_PAYLOAD_KEYS - {"runtime"}) | {
        "runtime_source", "browser_policy_failure_receipt_sha256"
    }
    binding = page._binding(execution_binding)
    amendment = _amendment(policy_amendment_sha256)
    if not isinstance(value, Mapping) or set(value) != keys or (
        value["policy"] != BROWSER_POLICY_FAILURE_POLICY
        or value["profile_sha256"] != rapid_study_profile.FROZEN_V5_PROFILE_SHA256
        or value["policy_amendment_sha256"] != amendment
        or page._json(value["candidate"]) != page._json(dict(candidate))
        or value["execution_binding"] != binding or value["action"] != _action(candidate["domain"])
        or value["failure_page_attribution"] != "unavailable" or value["scientific_credit"] is not False
        or not isinstance(value["browser_policy_failure_receipt_sha256"], str)
        or page._SHA.fullmatch(value["browser_policy_failure_receipt_sha256"]) is None
    ):
        raise ValueError("browser policy failure facts differ from independent bindings")
    _hashes(value["implementation_hashes"])
    source = value["runtime_source"]
    if not isinstance(source, Mapping) or set(source) != util.SOURCE_METADATA_KEYS or (
        source["image_digest"] != binding["admission_image_digest"]
        or source["lab_dirty"] is not False or source["neqo_dirty"] is not False
        or source["lab_patch_sha256"] != page._EMPTY_SHA or source["neqo_patch_sha256"] != page._EMPTY_SHA
        or any(not isinstance(source[key], str) or page._COMMIT.fullmatch(source[key]) is None
               for key in ("lab_commit", "neqo_commit", "neqo_pinned_commit"))
        or source["neqo_pinned_commit"] != source["neqo_commit"]
    ):
        raise ValueError("browser policy failure facts source is not clean and pinned")
    page._freshness(value["started_at"], value["completed_at"], not_before_utc)
    _failure(value["raw_failure"])
    return page._loads(page._json(value))
