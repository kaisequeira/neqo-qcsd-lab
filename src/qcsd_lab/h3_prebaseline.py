"""Prospective HTTP/3 reachability screen before an acquisition baseline.

This is a narrow site-availability check, not a page replay or a substitute for
the later full, multi-origin stability observations. A timeout is site evidence
only when the same Neqo client reaches a known-good HTTP/3 control on both
sides of the candidate attempts.
"""

from __future__ import annotations

import json
import os
import re
import socket
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .class_catalogue import DiscoveredLink, select_page_candidates
from .class_study import bind_receipt, validate_hash_bound_receipt
from .manifest import validate_manifest
from .process_scheduler import capture_scheduler_launch_prefix
from .util import ProcessTimeoutError, neqo_host_timeout, run, sha256_bytes, source_metadata

PREBASELINE_H3_SCREEN_CONTRACT: dict[str, Any] = {
    "schema_version": 1,
    "policy": "prebaseline-primary-origin-neqo-h3-reachability-v1",
    "control_url": "https://cloudflare-quic.com/",
    "timeout_seconds": 12,
    "control_probe_order": "before-and-after-candidate-origin-attempts",
    "control_success": "both-known_valid-true",
    "candidate_attempts_per_distinct_primary_origin": 2,
    "site_rejection": (
        "any-selected-page-request-origin-fails-both-attempts-with-classified-"
        "http3-connectivity-timeout-or-idle-timeout"
    ),
    "uncertain_outcome": "mixed-ambiguous-or-control-failure-blocks",
    "resolver_addresses": "diagnostic-only-no-neqo-pin-claim",
}
PREBASELINE_H3_SCREEN_V2_CONTRACT: dict[str, Any] = {
    "schema_version": 2,
    "policy": "prebaseline-exact-selected-page-neqo-h3-reachability-v2",
    "control_url": PREBASELINE_H3_SCREEN_CONTRACT["control_url"],
    "timeout_seconds": PREBASELINE_H3_SCREEN_CONTRACT["timeout_seconds"],
    "control_probe_order": "before-and-after-selected-page-attempts",
    "control_success": "both-known_valid-true",
    "candidate_attempts_per_selected_page": 2,
    "maximum_selected_pages": 5,
    "pass": "at-least-one-exact-selected-page-known_valid-on-both-attempts",
    "site_rejection": (
        "all-exact-selected-pages-fail-both-attempts-with-classified-"
        "http3-connectivity-timeout-or-idle-timeout"
    ),
    "uncertain_outcome": "mixed-ambiguous-or-control-failure-blocks",
    "resolver_addresses": "diagnostic-only-no-neqo-pin-claim",
}

H3_SCREEN_RECEIPT_TYPE = "qcsd-class-study-prebaseline-h3-screen"
H3_SITE_REASON = "prebaseline HTTP/3 unavailable on a selected page request origin"
H3_SITE_V2_REASON = "prebaseline HTTP/3 unavailable at all selected page URLs"
H3_BLOCK_REASON = "prebaseline HTTP/3 reachability screen inconclusive"
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CLASSIFIED_ERRORS = {
    "Error: Timeout(12)": "timeout",
    "Error: Transport(IdleTimeout)": "idle-timeout",
    (
        'Error: RunAborted("HTTP/3 endpoint 0 closed before accepted run completion: '
        'Transport(IdleTimeout)")'
    ): "idle-timeout",
}
_MAX_STDOUT_CHARS = 4096
_MAX_OUTPUT_CHARS = 65536


class H3SiteUnavailable(RuntimeError):
    def __init__(self, receipt: Mapping[str, Any]) -> None:
        payload = receipt.get("payload")
        reason = (
            H3_SITE_V2_REASON
            if isinstance(payload, Mapping) and payload.get("screen_schema_version") == 2
            else H3_SITE_REASON
        )
        super().__init__(reason)
        self.receipt = dict(receipt)


class H3ScreenBlocked(RuntimeError):
    def __init__(self, receipt: Mapping[str, Any]) -> None:
        super().__init__(H3_BLOCK_REASON)
        self.receipt = dict(receipt)


def _decision(before: str, origin_attempts: Sequence[Mapping[str, Any]], after: str | None) -> str:
    if before != "known-valid" or after != "known-valid" or not origin_attempts:
        return "blocked"
    outcomes = [
        (
            "pass" if all(attempt.get("outcome") == "known-valid" for attempt in item["attempts"])
            else "failed" if all(
                attempt.get("outcome") in {"timeout", "idle-timeout"}
                for attempt in item["attempts"]
            )
            else "ambiguous"
        )
        for item in origin_attempts
    ]
    if "ambiguous" in outcomes:
        return "blocked"
    return "site-rejection" if "failed" in outcomes else "pass"


def _decision_v2(before: str, page_attempts: Sequence[Mapping[str, Any]], after: str | None) -> str:
    if before != "known-valid" or after != "known-valid" or not page_attempts:
        return "blocked"
    page_outcomes = [
        tuple(attempt.get("outcome") for attempt in item["attempts"])
        for item in page_attempts
    ]
    if any(outcomes == ("known-valid", "known-valid") for outcomes in page_outcomes):
        return "pass"
    if all(
        all(outcome in {"timeout", "idle-timeout"} for outcome in outcomes)
        for outcomes in page_outcomes
    ):
        return "site-rejection"
    return "blocked"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _canonical_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.astimezone(UTC).isoformat().replace(
        "+00:00", "Z"
    ) == value


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _origin(value: str) -> str:
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or parts.username is not None
        or parts.password is not None
        or not parts.hostname
        or parts.port not in {None, 443}
    ):
        raise ValueError("H3 screen requires an ordinary HTTPS primary origin")
    host = parts.hostname.lower().rstrip(".")
    return f"https://{host}"


def _resolver_addresses(url: str) -> tuple[list[str], str | None]:
    host = urlsplit(url).hostname
    if not host:
        return [], "missing-host"
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    except OSError as error:
        return [], f"{type(error).__name__}: {error}"
    addresses = sorted({str(item[4][0]) for item in answers})
    return addresses, None if addresses else "empty-resolution"


def _run_one(url: str) -> dict[str, Any]:
    """Run one bounded positional Neqo probe and retain bounded raw diagnostics."""

    started_at = _utc_now()
    addresses, resolver_error = _resolver_addresses(url)
    result_code: int | None = None
    stdout = ""
    output_sha256: str | None = None
    output_text: str | None = None
    known_valid: bool | None = None
    outcome = "ambiguous"
    if resolver_error is None:
        with tempfile.TemporaryDirectory(prefix="qcsd-h3-screen-") as directory:
            output = Path(directory) / "probe.json"
            command = [
                *capture_scheduler_launch_prefix(),
                os.environ.get("QCSD_NEQO_CLIENT", "/usr/local/bin/neqo-qcsd-client"),
                "probe",
                url,
                "--output",
                str(output),
                "--max-bytes",
                "1048576",
                "--timeout-seconds",
                str(PREBASELINE_H3_SCREEN_CONTRACT["timeout_seconds"]),
            ]
            try:
                result = run(
                    command,
                    check=False,
                    timeout=neqo_host_timeout(PREBASELINE_H3_SCREEN_CONTRACT["timeout_seconds"]),
                )
            except ProcessTimeoutError as error:
                stdout = error.result.stdout or ""
            except OSError as error:
                stdout = f"{type(error).__name__}: {error}"
            else:
                result_code = result.returncode
                stdout = result.stdout or ""
                if result_code == 0 and output.is_file() and not output.is_symlink():
                    raw = output.read_bytes()
                    output_sha256 = sha256_bytes(raw)
                    try:
                        output_text = raw.decode("utf-8") if len(raw) <= _MAX_OUTPUT_CHARS else None
                        manifest = json.loads(raw)
                        validate_manifest(manifest)
                        resources = manifest["resources"]
                        if (
                            isinstance(resources, list)
                            and len(resources) == 1
                            and resources[0].get("url") == url
                            and type(resources[0].get("known_valid")) is bool
                        ):
                            known_valid = (
                                resources[0]["known_valid"] if output_text is not None else None
                            )
                            if known_valid is True:
                                outcome = "known-valid"
                    except (TypeError, ValueError, KeyError, AttributeError):
                        pass
                elif result_code == 1:
                    outcome = _CLASSIFIED_ERRORS.get(stdout.strip(), "ambiguous")
    return {
        "url": url,
        "started_at": started_at,
        "completed_at": _utc_now(),
        "resolver_addresses": addresses,
        "resolver_error": resolver_error,
        "exit_code": result_code,
        "stdout_sha256": sha256_bytes(stdout.encode("utf-8")),
        "stdout_excerpt": stdout[:_MAX_STDOUT_CHARS],
        "output_sha256": output_sha256,
        "output_text": output_text,
        "known_valid": known_valid,
        "outcome": outcome,
    }


def build_h3_screen_receipt(
    *,
    candidate_id: str,
    domain: str,
    selected_pages: Sequence[Mapping[str, str]],
    navigation_links: Sequence[Mapping[str, str]],
    control_before: Mapping[str, Any],
    origin_attempts: Sequence[Mapping[str, Any]],
    control_after: Mapping[str, Any] | None,
    image_digest: str,
    source: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind one complete diagnostic. This constructor is also used by test fakes."""

    payload = {
        "screen_schema_version": 1,
        "contract": PREBASELINE_H3_SCREEN_CONTRACT,
        "candidate_id": candidate_id,
        "domain": domain,
        "selected_pages": [dict(item) for item in selected_pages],
        "navigation_links": [dict(item) for item in navigation_links],
        "control_before": dict(control_before),
        "origin_attempts": [dict(item) for item in origin_attempts],
        "control_after": dict(control_after) if control_after is not None else None,
        "image_digest": image_digest,
        "source": dict(source),
    }
    before_pass = control_before.get("outcome") == "known-valid"
    after_pass = control_after is not None and control_after.get("outcome") == "known-valid"
    payload["decision"] = _decision(
        "known-valid" if before_pass else "ambiguous",
        origin_attempts,
        "known-valid" if after_pass else "ambiguous",
    )
    receipt = bind_receipt(payload, receipt_type=H3_SCREEN_RECEIPT_TYPE)
    validate_h3_screen_receipt(receipt)
    return receipt


def build_h3_screen_receipt_v2(
    *,
    candidate_id: str,
    domain: str,
    selected_pages: Sequence[Mapping[str, str]],
    navigation_links: Sequence[Mapping[str, str]],
    control_before: Mapping[str, Any],
    page_attempts: Sequence[Mapping[str, Any]],
    control_after: Mapping[str, Any] | None,
    image_digest: str,
    source: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind a complete exact-page diagnostic without creating scientific credit."""

    payload = {
        "screen_schema_version": 2,
        "contract": PREBASELINE_H3_SCREEN_V2_CONTRACT,
        "candidate_id": candidate_id,
        "domain": domain,
        "selected_pages": [dict(item) for item in selected_pages],
        "navigation_links": [dict(item) for item in navigation_links],
        "control_before": dict(control_before),
        "page_attempts": [dict(item) for item in page_attempts],
        "control_after": dict(control_after) if control_after is not None else None,
        "image_digest": image_digest,
        "source": dict(source),
    }
    payload["decision"] = _decision_v2(
        control_before.get("outcome", "ambiguous"),
        page_attempts,
        control_after.get("outcome", "ambiguous") if control_after is not None else None,
    )
    receipt = bind_receipt(payload, receipt_type=H3_SCREEN_RECEIPT_TYPE)
    validate_h3_screen_receipt(receipt)
    return receipt


def validate_h3_screen_receipt(
    value: object,
    *,
    candidate_id: str | None = None,
    domain: str | None = None,
    image_digest: str | None = None,
    source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload = validate_hash_bound_receipt(value, expected_type=H3_SCREEN_RECEIPT_TYPE)
    if isinstance(payload, Mapping) and payload.get("screen_schema_version") == 2:
        return _validate_h3_screen_receipt_v2(
            payload,
            candidate_id=candidate_id,
            domain=domain,
            image_digest=image_digest,
            source=source,
        )
    expected_fields = {
        "screen_schema_version", "contract", "candidate_id", "domain", "selected_pages",
        "navigation_links", "control_before", "origin_attempts", "control_after",
        "image_digest", "source", "decision",
    }
    if not isinstance(payload, Mapping) or set(payload) != expected_fields:
        raise ValueError("H3 screen receipt fields differ from the contract")
    if (
        payload["screen_schema_version"] != 1
        or payload["contract"] != PREBASELINE_H3_SCREEN_CONTRACT
        or not isinstance(payload["candidate_id"], str)
        or not payload["candidate_id"]
        or not isinstance(payload["domain"], str)
        or not payload["domain"]
        or candidate_id is not None and payload["candidate_id"] != candidate_id
        or domain is not None and payload["domain"] != domain
        or image_digest is not None and payload["image_digest"] != image_digest
        or source is not None and payload["source"] != dict(source)
    ):
        raise ValueError("H3 screen receipt identity differs")
    pages = payload["selected_pages"]
    if not isinstance(pages, list) or not 1 <= len(pages) <= 5:
        raise ValueError("H3 screen selected page ledger is invalid")
    selected_origins: set[str] = set()
    page_urls: set[str] = set()
    for page in pages:
        if not isinstance(page, Mapping) or set(page) != {"url", "request_origin"}:
            raise ValueError("H3 screen selected page ledger is invalid")
        if (
            not isinstance(page["url"], str)
            or not isinstance(page["request_origin"], str)
            or _origin(page["url"]) != page["request_origin"]
            or page["url"] in page_urls
        ):
            raise ValueError("H3 screen selected page origin differs")
        page_urls.add(page["url"])
        selected_origins.add(page["request_origin"])
    links = payload["navigation_links"]
    if not isinstance(links, list) or any(
        not isinstance(link, Mapping) or set(link) != {"url", "content_type"}
        or not isinstance(link["url"], str) or not isinstance(link["content_type"], str)
        for link in links
    ):
        raise ValueError("H3 screen navigation link ledger is invalid")
    expected_pages = select_page_candidates(
        payload["domain"],
        registrable_domain=payload["domain"],
        discovered_links=tuple(
            DiscoveredLink(link["url"], link["content_type"]) for link in links
        ),
    )
    if [page["url"] for page in pages] != [page.url for page in expected_pages]:
        raise ValueError("H3 screen selected pages differ from retained navigation links")
    attempts = payload["origin_attempts"]
    if not isinstance(attempts, list):
        raise ValueError("H3 screen origin attempt set differs from selected pages")
    expected_origins = sorted(selected_origins)
    actual_origins = [item.get("origin") for item in attempts if isinstance(item, Mapping)]
    if len(actual_origins) != len(attempts) or actual_origins not in (expected_origins, []):
        raise ValueError("H3 screen origin attempt set differs from selected pages")

    def check_attempt(attempt: object, expected_url: str) -> str:
        fields = {
            "url", "started_at", "completed_at", "resolver_addresses", "resolver_error",
            "exit_code", "stdout_sha256", "stdout_excerpt", "output_sha256",
            "output_text",
            "known_valid", "outcome",
        }
        if not isinstance(attempt, Mapping) or set(attempt) != fields:
            raise ValueError("H3 screen probe attempt is malformed")
        if (
            attempt["url"] != expected_url
            or not _canonical_timestamp(attempt["started_at"])
            or not _canonical_timestamp(attempt["completed_at"])
            or _parse_timestamp(attempt["completed_at"])
            < _parse_timestamp(attempt["started_at"])
            or not isinstance(attempt["resolver_addresses"], list)
            or attempt["resolver_addresses"] != sorted(set(attempt["resolver_addresses"]))
            or any(
                not isinstance(addr, str) or not addr
                for addr in attempt["resolver_addresses"]
            )
            or (
                attempt["resolver_error"] is not None
                and not isinstance(attempt["resolver_error"], str)
            )
            or attempt["exit_code"] is not None and type(attempt["exit_code"]) is not int
            or not isinstance(attempt["stdout_excerpt"], str)
            or len(attempt["stdout_excerpt"]) > _MAX_STDOUT_CHARS
            or not isinstance(attempt["stdout_sha256"], str)
            or _HEX_SHA256.fullmatch(attempt["stdout_sha256"]) is None
            or attempt["output_sha256"] is not None
            and (not isinstance(attempt["output_sha256"], str)
                 or _HEX_SHA256.fullmatch(attempt["output_sha256"]) is None)
            or attempt["output_text"] is not None and (
                not isinstance(attempt["output_text"], str)
                or len(attempt["output_text"]) > _MAX_OUTPUT_CHARS
            )
            or attempt["known_valid"] is not None and type(attempt["known_valid"]) is not bool
            or attempt["outcome"] not in {"known-valid", "timeout", "idle-timeout", "ambiguous"}
        ):
            raise ValueError("H3 screen probe attempt is invalid")
        if attempt["output_text"] is not None:
            try:
                manifest = json.loads(attempt["output_text"])
                validate_manifest(manifest)
                resources = manifest["resources"]
            except (TypeError, ValueError, KeyError, AttributeError) as error:
                raise ValueError("H3 screen output manifest is invalid") from error
            if (
                sha256_bytes(attempt["output_text"].encode("utf-8"))
                != attempt["output_sha256"]
                or len(resources) != 1
                or resources[0]["url"] != expected_url
                or resources[0]["known_valid"] != attempt["known_valid"]
            ):
                raise ValueError("H3 screen output proof differs from recorded result")
        if attempt["outcome"] == "known-valid" and (
            attempt["exit_code"] != 0 or attempt["known_valid"] is not True
            or attempt["output_text"] is None
        ):
            raise ValueError("H3 screen known-valid proof is inconsistent")
        if attempt["outcome"] in {"timeout", "idle-timeout"} and attempt["output_text"] is not None:
            raise ValueError("H3 screen timeout cannot have a completed output manifest")
        if attempt["outcome"] in {"timeout", "idle-timeout"} and (
            attempt["exit_code"] != 1 or attempt["known_valid"] is not None
            or attempt["resolver_error"] is not None
            or attempt["stdout_excerpt"].strip() not in _CLASSIFIED_ERRORS
            or _CLASSIFIED_ERRORS[attempt["stdout_excerpt"].strip()] != attempt["outcome"]
            or attempt["stdout_sha256"] != sha256_bytes(
                attempt["stdout_excerpt"].encode("utf-8")
            )
        ):
            raise ValueError("H3 screen timeout classification is inconsistent")
        return attempt["outcome"]

    before = check_attempt(
        payload["control_before"], PREBASELINE_H3_SCREEN_CONTRACT["control_url"]
    )
    after_raw = payload["control_after"]
    after = (
        check_attempt(after_raw, PREBASELINE_H3_SCREEN_CONTRACT["control_url"])
        if after_raw is not None
        else None
    )
    if before == "known-valid" and actual_origins != expected_origins:
        raise ValueError("H3 screen omitted a selected primary origin")
    for item in attempts:
        if not isinstance(item, Mapping) or set(item) != {"origin", "attempts"}:
            raise ValueError("H3 screen origin attempt is malformed")
        origin_attempts = item["attempts"]
        if not isinstance(origin_attempts, list) or len(origin_attempts) != 2:
            raise ValueError("H3 screen requires two attempts per selected origin")
        for attempt in origin_attempts:
            check_attempt(attempt, item["origin"] + "/")
    sequence = [payload["control_before"]]
    sequence.extend(attempt for item in attempts for attempt in item["attempts"])
    if after_raw is not None:
        sequence.append(after_raw)
    if any(
        _parse_timestamp(first["completed_at"]) > _parse_timestamp(second["started_at"])
        for first, second in zip(sequence, sequence[1:])
    ):
        raise ValueError("H3 screen control and candidate probes are out of order")
    if before != "known-valid" and (attempts or after is not None):
        raise ValueError("H3 screen ran candidate probes after failed first control")
    expected_decision = _decision(before, attempts, after)
    if payload["decision"] != expected_decision:
        raise ValueError("H3 screen decision differs from its exact probe evidence")
    return dict(payload)


def _check_v2_probe_attempt(attempt: object, expected_url: str) -> str:
    fields = {
        "url", "started_at", "completed_at", "resolver_addresses", "resolver_error",
        "exit_code", "stdout_sha256", "stdout_excerpt", "output_sha256",
        "output_text", "known_valid", "outcome",
    }
    if not isinstance(attempt, Mapping) or set(attempt) != fields:
        raise ValueError("H3 screen probe attempt is malformed")
    if (
        attempt["url"] != expected_url
        or not _canonical_timestamp(attempt["started_at"])
        or not _canonical_timestamp(attempt["completed_at"])
        or _parse_timestamp(attempt["completed_at"])
        < _parse_timestamp(attempt["started_at"])
        or not isinstance(attempt["resolver_addresses"], list)
        or any(not isinstance(addr, str) or not addr for addr in attempt["resolver_addresses"])
        or attempt["resolver_addresses"] != sorted(set(attempt["resolver_addresses"]))
        or (attempt["resolver_error"] is not None and not isinstance(attempt["resolver_error"], str))
        or attempt["exit_code"] is not None and type(attempt["exit_code"]) is not int
        or not isinstance(attempt["stdout_excerpt"], str)
        or len(attempt["stdout_excerpt"]) > _MAX_STDOUT_CHARS
        or not isinstance(attempt["stdout_sha256"], str)
        or _HEX_SHA256.fullmatch(attempt["stdout_sha256"]) is None
        or attempt["output_sha256"] is not None
        and (not isinstance(attempt["output_sha256"], str)
             or _HEX_SHA256.fullmatch(attempt["output_sha256"]) is None)
        or attempt["output_text"] is not None and (
            not isinstance(attempt["output_text"], str)
            or len(attempt["output_text"]) > _MAX_OUTPUT_CHARS
        )
        or attempt["known_valid"] is not None and type(attempt["known_valid"]) is not bool
        or attempt["outcome"] not in {"known-valid", "timeout", "idle-timeout", "ambiguous"}
    ):
        raise ValueError("H3 screen probe attempt is invalid")
    if attempt["output_text"] is not None:
        try:
            manifest = json.loads(attempt["output_text"])
            validate_manifest(manifest)
            resources = manifest["resources"]
        except (TypeError, ValueError, KeyError, AttributeError) as error:
            raise ValueError("H3 screen output manifest is invalid") from error
        if (
            sha256_bytes(attempt["output_text"].encode("utf-8")) != attempt["output_sha256"]
            or len(resources) != 1
            or resources[0]["url"] != expected_url
            or resources[0]["known_valid"] != attempt["known_valid"]
        ):
            raise ValueError("H3 screen output proof differs from recorded result")
    if attempt["outcome"] == "known-valid" and (
        attempt["exit_code"] != 0
        or attempt["known_valid"] is not True
        or attempt["output_text"] is None
    ):
        raise ValueError("H3 screen known-valid proof is inconsistent")
    if attempt["outcome"] in {"timeout", "idle-timeout"} and attempt["output_text"] is not None:
        raise ValueError("H3 screen timeout cannot have a completed output manifest")
    if attempt["outcome"] in {"timeout", "idle-timeout"} and (
        attempt["exit_code"] != 1
        or attempt["known_valid"] is not None
        or attempt["resolver_error"] is not None
        or attempt["stdout_excerpt"].strip() not in _CLASSIFIED_ERRORS
        or _CLASSIFIED_ERRORS[attempt["stdout_excerpt"].strip()] != attempt["outcome"]
        or attempt["stdout_sha256"] != sha256_bytes(attempt["stdout_excerpt"].encode("utf-8"))
    ):
        raise ValueError("H3 screen timeout classification is inconsistent")
    return attempt["outcome"]


def _validate_h3_screen_receipt_v2(
    payload: Mapping[str, Any],
    *,
    candidate_id: str | None,
    domain: str | None,
    image_digest: str | None,
    source: Mapping[str, Any] | None,
) -> dict[str, Any]:
    expected_fields = {
        "screen_schema_version", "contract", "candidate_id", "domain", "selected_pages",
        "navigation_links", "control_before", "page_attempts", "control_after",
        "image_digest", "source", "decision",
    }
    if set(payload) != expected_fields:
        raise ValueError("H3 screen receipt fields differ from the v2 contract")
    if (
        type(payload["screen_schema_version"]) is not int
        or payload["screen_schema_version"] != 2
        or payload["contract"] != PREBASELINE_H3_SCREEN_V2_CONTRACT
        or not isinstance(payload["candidate_id"], str)
        or not payload["candidate_id"]
        or not isinstance(payload["domain"], str)
        or not payload["domain"]
        or candidate_id is not None and payload["candidate_id"] != candidate_id
        or domain is not None and payload["domain"] != domain
        or image_digest is not None and payload["image_digest"] != image_digest
        or source is not None and payload["source"] != dict(source)
    ):
        raise ValueError("H3 screen receipt identity differs")
    pages = payload["selected_pages"]
    if not isinstance(pages, list) or not 1 <= len(pages) <= 5:
        raise ValueError("H3 screen selected page ledger is invalid")
    page_urls: set[str] = set()
    for page in pages:
        if not isinstance(page, Mapping) or set(page) != {"url", "request_origin"}:
            raise ValueError("H3 screen selected page ledger is invalid")
        if (
            not isinstance(page["url"], str)
            or not isinstance(page["request_origin"], str)
            or _origin(page["url"]) != page["request_origin"]
            or page["url"] in page_urls
        ):
            raise ValueError("H3 screen selected page origin differs")
        page_urls.add(page["url"])
    links = payload["navigation_links"]
    if not isinstance(links, list) or any(
        not isinstance(link, Mapping) or set(link) != {"url", "content_type"}
        or not isinstance(link["url"], str) or not isinstance(link["content_type"], str)
        for link in links
    ):
        raise ValueError("H3 screen navigation link ledger is invalid")
    expected_pages = select_page_candidates(
        payload["domain"],
        registrable_domain=payload["domain"],
        discovered_links=tuple(
            DiscoveredLink(link["url"], link["content_type"]) for link in links
        ),
    )
    if [page["url"] for page in pages] != [page.url for page in expected_pages]:
        raise ValueError("H3 screen selected pages differ from retained navigation links")

    before = _check_v2_probe_attempt(
        payload["control_before"], PREBASELINE_H3_SCREEN_V2_CONTRACT["control_url"]
    )
    after_raw = payload["control_after"]
    after = (
        _check_v2_probe_attempt(after_raw, PREBASELINE_H3_SCREEN_V2_CONTRACT["control_url"])
        if after_raw is not None
        else None
    )
    attempts = payload["page_attempts"]
    if not isinstance(attempts, list):
        raise ValueError("H3 screen page attempt set differs from selected pages")
    if before == "known-valid":
        if len(attempts) != len(pages):
            raise ValueError("H3 screen omitted a selected page")
    elif attempts or after_raw is not None:
        raise ValueError("H3 screen ran page probes after failed first control")
    for page, item in zip(pages, attempts):
        if not isinstance(item, Mapping) or set(item) != {"url", "attempts"}:
            raise ValueError("H3 screen page attempt is malformed")
        if item["url"] != page["url"]:
            raise ValueError("H3 screen page attempt order differs from selected pages")
        pair = item["attempts"]
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError("H3 screen requires two attempts per selected page")
        for attempt in pair:
            _check_v2_probe_attempt(attempt, page["url"])
    sequence = [payload["control_before"]]
    sequence.extend(attempt for item in attempts for attempt in item["attempts"])
    if after_raw is not None:
        sequence.append(after_raw)
    if any(
        _parse_timestamp(first["completed_at"]) > _parse_timestamp(second["started_at"])
        for first, second in zip(sequence, sequence[1:])
    ):
        raise ValueError("H3 screen control and candidate probes are out of order")
    expected_decision = _decision_v2(before, attempts, after)
    if payload["decision"] != expected_decision:
        raise ValueError("H3 screen decision differs from its exact probe evidence")
    return dict(payload)


def screen_prebaseline_h3(
    *,
    candidate_id: str,
    domain: str,
    selected_pages: Sequence[Mapping[str, str]],
    navigation_links: Sequence[Mapping[str, str]],
) -> dict[str, Any]:
    """Run the control/candidate/control sequence before the baseline is armed."""

    if not 1 <= len(selected_pages) <= PREBASELINE_H3_SCREEN_V2_CONTRACT["maximum_selected_pages"]:
        raise ValueError("H3 screen selected page ledger is invalid")
    if any(
        not isinstance(page, Mapping)
        or set(page) != {"url", "request_origin"}
        or not isinstance(page["url"], str)
        or not isinstance(page["request_origin"], str)
        or _origin(page["url"]) != page["request_origin"]
        for page in selected_pages
    ):
        raise ValueError("H3 screen selected page ledger is invalid")
    if any(
        not isinstance(link, Mapping)
        or set(link) != {"url", "content_type"}
        or not isinstance(link["url"], str)
        or not isinstance(link["content_type"], str)
        for link in navigation_links
    ):
        raise ValueError("H3 screen navigation link ledger is invalid")
    canonical_pages = select_page_candidates(
        domain,
        registrable_domain=domain,
        discovered_links=tuple(
            DiscoveredLink(link["url"], link["content_type"]) for link in navigation_links
        ),
    )
    page_urls = [page["url"] for page in selected_pages]
    if page_urls != [page.url for page in canonical_pages]:
        raise ValueError("H3 screen selected pages differ from retained navigation links")

    image_digest = os.environ.get("QCSD_LAB_IMAGE_DIGEST", "native")
    source = dict(source_metadata())
    if image_digest == "native" and source.get("image_digest") is None:
        source["image_digest"] = "native"
    before = _run_one(PREBASELINE_H3_SCREEN_V2_CONTRACT["control_url"])
    page_attempts: list[dict[str, Any]] = []
    after: dict[str, Any] | None = None
    if before["outcome"] == "known-valid":
        for url in page_urls:
            page_attempts.append(
                {"url": url, "attempts": [_run_one(url) for _ in range(2)]}
            )
        after = _run_one(PREBASELINE_H3_SCREEN_V2_CONTRACT["control_url"])
    receipt = build_h3_screen_receipt_v2(
        candidate_id=candidate_id,
        domain=domain,
        selected_pages=selected_pages,
        navigation_links=navigation_links,
        control_before=before,
        page_attempts=page_attempts,
        control_after=after,
        image_digest=image_digest,
        source=source,
    )
    decision = receipt["payload"]["decision"]
    if decision == "site-rejection":
        raise H3SiteUnavailable(receipt)
    if decision == "blocked":
        raise H3ScreenBlocked(receipt)
    return receipt
