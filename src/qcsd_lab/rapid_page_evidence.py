"""Create and independently reopen prospective rapid-v5 page evidence.

These receipts prove deterministic navigation and a controlled exact-page H3
observation. They do not admit sites or prove a complete replay resource graph.
The admission verifier must combine them with safety and preparation evidence.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import class_acquisition, class_catalogue, h3_prebaseline, rapid_study_profile, util
from .class_acquisition import ExistingAcquisitionBackend, NavigationDiscovery, NavigationRejection
from .class_catalogue import DiscoveredLink, select_page_candidates

NAVIGATION_RECEIPT_TYPE = "qcsd-rapid-v5-catalogue-boundary-navigation-v1"
PAGE_H3_RECEIPT_TYPE = "qcsd-rapid-v5-controlled-selected-page-h3-v1"
NAVIGATION_POLICY = "exact-frozen-domain-browser-navigation-and-deterministic-pages-v1"
SCHEMA_VERSION = 1
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_EMPTY_SHA = hashlib.sha256(b"").hexdigest()
_MAX_RECEIPT_BYTES = 2_000_000


def _json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate receipt JSON key")
        result[key] = value
    return result


def _no_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _loads(raw: bytes | str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_unique, parse_constant=_no_constant)
    except (UnicodeError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("page evidence is not strict UTF-8 JSON") from error


def _regular(path: Path) -> Path:
    value = Path(os.path.abspath(path))
    if any(part.is_symlink() for part in (value, *value.parents)) or not value.is_file():
        raise ValueError("page evidence input must be a regular nonlinked file")
    return value


def _read(path: Path) -> bytes:
    raw = _regular(path).read_bytes()
    if not raw or len(raw) > _MAX_RECEIPT_BYTES:
        raise ValueError("page evidence input is empty or oversized")
    return raw


def _binding(value: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {
        "source_manifest_sha256", "admission_image_digest"
    } or not isinstance(value["source_manifest_sha256"], str) or not isinstance(
        value["admission_image_digest"], str
    ) or _SHA.fullmatch(value["source_manifest_sha256"]) is None or _IMAGE.fullmatch(
        value["admission_image_digest"]
    ) is None:
        raise ValueError("page evidence execution binding is invalid")
    return dict(value)


def _runtime_payload(binding: Mapping[str, Any]) -> dict[str, Any]:
    manifest_path = Path(os.environ.get("QCSD_LAB_SOURCE_METADATA", util.DEFAULT_SOURCE_METADATA))
    raw = _read(manifest_path)
    if _sha(raw) != binding["source_manifest_sha256"]:
        raise ValueError("page evidence runtime source manifest differs from binding")
    if os.environ.get("QCSD_LAB_IMAGE_DIGEST") != binding["admission_image_digest"]:
        raise ValueError("page evidence runtime image differs from binding")
    result = {"source_manifest_text": raw.decode("utf-8")}
    _validate_runtime(result, binding)
    return result


def _validate_runtime(value: Any, binding: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"source_manifest_text"}:
        raise ValueError("page evidence runtime facts are invalid")
    text = value["source_manifest_text"]
    if not isinstance(text, str) or _sha(text.encode()) != binding["source_manifest_sha256"]:
        raise ValueError("page evidence retained source manifest does not verify")
    source = _loads(text)
    if not isinstance(source, dict) or set(source) != util.SOURCE_METADATA_KEYS or (
        source["image_digest"] not in (None, binding["admission_image_digest"])
        or source["lab_dirty"] is not False or source["neqo_dirty"] is not False
        or source["lab_patch_sha256"] != _EMPTY_SHA or source["neqo_patch_sha256"] != _EMPTY_SHA
        or not isinstance(source["lab_commit"], str) or _COMMIT.fullmatch(source["lab_commit"]) is None
        or not isinstance(source["neqo_commit"], str) or _COMMIT.fullmatch(source["neqo_commit"]) is None
        or source["neqo_pinned_commit"] != source["neqo_commit"]
    ):
        raise ValueError("page evidence source manifest is not clean and pinned")
    return {**source, "image_digest": binding["admission_image_digest"]}


def implementation_hashes(kind: str = "navigation") -> dict[str, str]:
    """Return exact implementation bytes to freeze before prospective evidence."""
    if kind not in {"navigation", "page-h3"}:
        raise ValueError("unregistered page evidence implementation kind")
    modules = {
        "qcsd_lab.rapid_page_evidence": Path(__file__),
        "qcsd_lab.class_acquisition": Path(class_acquisition.__file__),
        "qcsd_lab.class_catalogue": Path(class_catalogue.__file__),
        "qcsd_lab.rapid_study_profile": Path(rapid_study_profile.__file__),
        "qcsd_lab.util": Path(util.__file__),
    }
    if kind == "page-h3":
        modules["qcsd_lab.h3_prebaseline"] = Path(h3_prebaseline.__file__)
        modules["neqo-qcsd-client"] = Path(os.environ.get(
            "QCSD_NEQO_CLIENT", "/usr/local/bin/neqo-qcsd-client"
        ))
    return {key: _sha(_regular(path).read_bytes()) for key, path in modules.items()}


def _hashes(value: Any, kind: str) -> dict[str, str]:
    keys = {
        "qcsd_lab.rapid_page_evidence", "qcsd_lab.class_acquisition",
        "qcsd_lab.class_catalogue", "qcsd_lab.rapid_study_profile", "qcsd_lab.util",
    }
    if kind == "page-h3":
        keys |= {"qcsd_lab.h3_prebaseline", "neqo-qcsd-client"}
    if not isinstance(value, Mapping) or set(value) != keys or any(
        not isinstance(item, str) or _SHA.fullmatch(item) is None for item in value.values()
    ):
        raise ValueError("page evidence implementation hashes are invalid")
    return dict(value)


def _candidate(
    profile_receipt: Mapping[str, Any], source_bytes: bytes, catalogue_bytes: bytes,
    candidate_id: str,
) -> dict[str, Any]:
    if _sha(_json(profile_receipt)) != rapid_study_profile.FROZEN_V5_PROFILE_SHA256:
        raise ValueError("page evidence profile is not the frozen prospective v5 profile")
    candidates = rapid_study_profile.validate_v5_profile_receipt(
        profile_receipt, source_bytes, catalogue_bytes
    )
    matches = [candidate for candidate in candidates if candidate["candidate_id"] == candidate_id]
    if len(matches) != 1:
        raise ValueError("page evidence candidate is outside the frozen profile")
    candidate = matches[0]
    if class_acquisition.unsafe_catalogue_domain_reason(candidate["domain"]) is not None:
        raise ValueError("page evidence candidate is automatically unsafe")
    return candidate


def _inputs(profile: Path, source: Path, catalogue: Path) -> tuple[dict[str, Any], bytes, bytes]:
    profile_bytes = _read(profile)
    if _sha(profile_bytes) != rapid_study_profile.FROZEN_V5_PROFILE_SHA256:
        raise ValueError("page evidence profile bytes differ from frozen v5")
    return _loads(profile_bytes), _read(source), _read(catalogue)


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("page evidence timestamp is invalid")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("page evidence timestamp is invalid") from error
    if result.tzinfo is None or result.utcoffset() != UTC.utcoffset(result):
        raise ValueError("page evidence timestamp must use UTC")
    return result


def _freshness(started: Any, completed: Any, not_before_utc: datetime) -> tuple[datetime, datetime]:
    if not isinstance(not_before_utc, datetime) or not_before_utc.tzinfo is None:
        raise ValueError("page evidence freshness barrier must be an aware datetime")
    start, end = _time(started), _time(completed)
    if start < not_before_utc or end < start or end > datetime.now(UTC):
        raise ValueError("page evidence timestamps are stale or unordered")
    return start, end


def _navigation_dict(value: NavigationDiscovery) -> dict[str, Any]:
    if not isinstance(value, NavigationDiscovery):
        raise ValueError("navigation backend returned an invalid discovery")
    return {
        "registrable_domain": value.registrable_domain,
        "links": [{"url": link.url, "content_type": link.content_type} for link in value.links],
        "observed_origins": list(value.observed_origins),
        "rejections": [rejection.as_dict() for rejection in value.rejections],
        "page_observed_origins": [
            {"url": url, "origins": list(origins)} for url, origins in value.page_observed_origins
        ],
    }


def _navigation(value: Any, domain: str) -> NavigationDiscovery:
    if not isinstance(value, Mapping) or set(value) != {
        "registrable_domain", "links", "observed_origins", "rejections", "page_observed_origins"
    } or value["registrable_domain"] != domain:
        raise ValueError("retained navigation differs from the exact frozen domain")
    for key in ("links", "observed_origins", "rejections", "page_observed_origins"):
        if not isinstance(value[key], list) or len(value[key]) > 1000:
            raise ValueError("retained navigation arrays are invalid")
    links = []
    for row in value["links"]:
        if not isinstance(row, Mapping) or set(row) != {"url", "content_type"} or any(
            not isinstance(row[key], str) or not row[key] or len(row[key]) > 4096 for key in row
        ):
            raise ValueError("retained navigation link is invalid")
        links.append(DiscoveredLink(**row))
    def origins(values: Any) -> tuple[str, ...]:
        if not isinstance(values, list) or any(not isinstance(item, str) for item in values) or (
            values != sorted(set(values))
        ):
            raise ValueError("retained navigation origins are not unique and ordered")
        for origin in values:
            if not isinstance(origin, str):
                raise ValueError("retained navigation origin is invalid")
            canonical = class_catalogue.canonical_query_free_html_url(
                origin + "/", registrable_domain=domain
            )
            if canonical != origin + "/":
                raise ValueError("retained navigation origin left the frozen boundary")
        return tuple(values)
    observed = origins(value["observed_origins"])
    rejections = []
    for row in value["rejections"]:
        if not isinstance(row, Mapping) or set(row) != {"url", "kind", "reason"} or any(
            not isinstance(item, str) or not item or len(item) > 65536 for item in row.values()
        ):
            raise ValueError("retained navigation rejection is invalid")
        rejections.append(NavigationRejection(**row))
    page_origins = []
    for row in value["page_observed_origins"]:
        if not isinstance(row, Mapping) or set(row) != {"url", "origins"} or (
            class_catalogue.canonical_query_free_html_url(row["url"], registrable_domain=domain)
            != row["url"]
        ):
            raise ValueError("retained navigation page is invalid")
        selected_origins = origins(row["origins"])
        if not set(selected_origins) <= set(observed):
            raise ValueError("retained page origins were not observed by navigation")
        page_origins.append((row["url"], selected_origins))
    if len({url for url, _ in page_origins}) != len(page_origins):
        raise ValueError("retained navigation repeats a page origin record")
    return NavigationDiscovery(domain, tuple(links), observed, tuple(rejections), tuple(page_origins))


def _envelope(payload: Mapping[str, Any], receipt_type: str) -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "receipt_type": receipt_type,
            "payload_sha256": _sha(_json(payload)), "payload": dict(payload)}


def _create(path: Path, payload: Mapping[str, Any], receipt_type: str) -> dict[str, Any]:
    target = Path(os.path.abspath(path))
    if any(part.is_symlink() for part in (target, *target.parents)):
        raise ValueError("page evidence destination must not contain symlinks")
    receipt = _envelope(payload, receipt_type)
    util.durable_create(target, _json(receipt))
    return receipt


def _open(path: Path, receipt_type: str) -> tuple[dict[str, Any], str]:
    raw = _read(path)
    value = _loads(raw)
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "receipt_type", "payload_sha256", "payload"
    } or type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION or (
        value["receipt_type"] != receipt_type or not isinstance(value["payload"], dict)
        or value["payload_sha256"] != _sha(_json(value["payload"]))
    ):
        raise ValueError("page evidence receipt envelope does not verify")
    return value["payload"], _sha(raw)


def produce_navigation_receipt(
    *, output: Path, profile: Path, source: Path, catalogue: Path, candidate_id: str,
    execution_binding: Mapping[str, Any], backend: ExistingAcquisitionBackend | None = None,
) -> dict[str, Any]:
    """Discover pages through the existing exact-boundary backend, once."""
    profile_receipt, source_bytes, catalogue_bytes = _inputs(profile, source, catalogue)
    candidate = _candidate(profile_receipt, source_bytes, catalogue_bytes, candidate_id)
    binding = _binding(execution_binding)
    runtime = _runtime_payload(binding)
    hashes = implementation_hashes("navigation")
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    started = datetime.now(UTC).isoformat()
    raw_navigation = _navigation_dict((backend or ExistingAcquisitionBackend()).discover_navigation(
        candidate["domain"]
    ))
    navigation = _navigation(raw_navigation, candidate["domain"])
    pages = select_page_candidates(candidate["domain"], registrable_domain=candidate["domain"],
                                   discovered_links=navigation.links)
    return _create(output, {
        "policy": NAVIGATION_POLICY, "candidate": candidate,
        "profile_sha256": rapid_study_profile.FROZEN_V5_PROFILE_SHA256,
        "execution_binding": binding, "runtime": runtime, "implementation_hashes": hashes,
        "started_at": started, "completed_at": datetime.now(UTC).isoformat(),
        "raw_navigation": raw_navigation, "selected_pages": [page.as_dict() for page in pages],
        "scientific_credit": False,
    }, NAVIGATION_RECEIPT_TYPE)


def verify_navigation_receipt(
    path: Path, *, profile_receipt: Mapping[str, Any], source_bytes: bytes,
    catalogue_bytes: bytes, candidate_id: str, execution_binding: Mapping[str, Any],
    expected_implementation_hashes: Mapping[str, str], not_before_utc: datetime,
) -> dict[str, Any]:
    """Reopen raw navigation and derive exact deterministic ordinal 0..4 pages."""
    payload, digest = _open(path, NAVIGATION_RECEIPT_TYPE)
    candidate = _candidate(profile_receipt, source_bytes, catalogue_bytes, candidate_id)
    binding = _binding(execution_binding)
    if set(payload) != {
        "policy", "candidate", "profile_sha256", "execution_binding", "runtime",
        "implementation_hashes", "started_at", "completed_at", "raw_navigation",
        "selected_pages", "scientific_credit"
    } or payload["policy"] != NAVIGATION_POLICY or payload["candidate"] != candidate or (
        payload["profile_sha256"] != rapid_study_profile.FROZEN_V5_PROFILE_SHA256
        or payload["execution_binding"] != binding or payload["scientific_credit"] is not False
        or _hashes(payload["implementation_hashes"], "navigation")
        != _hashes(expected_implementation_hashes, "navigation")
    ):
        raise ValueError("navigation receipt source/profile/implementation binding differs")
    runtime = _validate_runtime(payload["runtime"], binding)
    _freshness(payload["started_at"], payload["completed_at"], not_before_utc)
    navigation = _navigation(payload["raw_navigation"], candidate["domain"])
    pages = select_page_candidates(candidate["domain"], registrable_domain=candidate["domain"],
                                   discovered_links=navigation.links)
    if payload["selected_pages"] != [page.as_dict() for page in pages]:
        raise ValueError("navigation selected pages differ from retained deterministic derivation")
    return {"navigation_receipt_sha256": digest, "navigation": navigation, "pages": pages,
            "candidate": candidate, "execution_binding": binding, "runtime_source": runtime,
            "started_at": payload["started_at"], "completed_at": payload["completed_at"]}


def _probe_class(raw: Any, url: str, start: datetime, end: datetime) -> tuple[str, str]:
    if not isinstance(raw, Mapping):
        raise ValueError("page H3 raw probe is invalid")
    _, observed_end = _freshness(raw.get("started_at"), raw.get("completed_at"), start)
    if observed_end > end:
        raise ValueError("page H3 raw probe lies outside receipt timestamps")
    addresses = raw.get("resolver_addresses")
    if not isinstance(addresses, list) or any(not isinstance(item, str) for item in addresses) or (
        addresses != sorted(set(addresses))
    ):
        raise ValueError("page H3 resolver addresses are invalid")
    try:
        parsed_addresses = [ipaddress.ip_address(item) for item in addresses]
    except ValueError as error:
        raise ValueError("page H3 resolver address is invalid") from error
    outcome = rapid_study_profile._survey_probe_class_v5(raw, url)
    if raw["exit_code"] is not None and type(raw["exit_code"]) is not int:
        raise ValueError("page H3 exit code has an invalid type")
    if outcome[0] == "known-valid" and (
        not parsed_addresses or any(not address.is_global for address in parsed_addresses)
    ):
        raise ValueError("known-valid page H3 did not resolve exclusively to public addresses")
    return outcome


def produce_selected_page_h3_receipt(
    *, output: Path, navigation_receipt: Path, selected_page_ordinal: int,
    profile: Path, source: Path, catalogue: Path, candidate_id: str,
    execution_binding: Mapping[str, Any],
    expected_navigation_implementation_hashes: Mapping[str, str], not_before_utc: datetime,
    probe: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Retain a new before/exact-page/after controlled observation, once."""
    profile_receipt, source_bytes, catalogue_bytes = _inputs(profile, source, catalogue)
    navigation = verify_navigation_receipt(
        navigation_receipt, profile_receipt=profile_receipt, source_bytes=source_bytes,
        catalogue_bytes=catalogue_bytes, candidate_id=candidate_id,
        execution_binding=execution_binding,
        expected_implementation_hashes=expected_navigation_implementation_hashes,
        not_before_utc=not_before_utc,
    )
    if type(selected_page_ordinal) is not int or not 0 <= selected_page_ordinal < len(navigation["pages"]):
        raise ValueError("selected page ordinal is outside deterministic navigation")
    binding = _binding(execution_binding)
    runtime = _runtime_payload(binding)
    hashes = implementation_hashes("page-h3")
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    if probe is None:
        if os.environ.get("QCSD_PUBLIC_ORIGIN_ONLY") != "1":
            raise ValueError("live selected-page H3 probe requires public-origin-only policy")
        probe = h3_prebaseline._run_one
    selected_page = navigation["pages"][selected_page_ordinal]
    control = rapid_study_profile.V5_TRIAGE_POLICY["control_url"]
    started = datetime.now(UTC).isoformat()
    before = probe(control)
    page = probe(selected_page.url)
    after = probe(control)
    return _create(output, {
        "policy": rapid_study_profile.V5_SELECTED_PAGE_H3_POLICY,
        "candidate": navigation["candidate"],
        "profile_sha256": rapid_study_profile.FROZEN_V5_PROFILE_SHA256,
        "execution_binding": binding, "runtime": runtime, "implementation_hashes": hashes,
        "navigation_receipt_sha256": navigation["navigation_receipt_sha256"],
        "selected_page": selected_page.as_dict(), "control_url": control,
        "started_at": started, "completed_at": datetime.now(UTC).isoformat(),
        "control_before": before, "exact_page_probe": page, "control_after": after,
        "scientific_credit": False,
    }, PAGE_H3_RECEIPT_TYPE)


def verify_selected_page_h3_receipt(
    path: Path, *, navigation_receipt: Path, profile_receipt: Mapping[str, Any],
    source_bytes: bytes, catalogue_bytes: bytes, candidate_id: str,
    execution_binding: Mapping[str, Any],
    expected_navigation_implementation_hashes: Mapping[str, str],
    expected_implementation_hashes: Mapping[str, str], not_before_utc: datetime,
) -> dict[str, Any]:
    """Classify retained raw probes and return the exact v5 page proof facts.

    A completed failed observation remains readable, but does not return a
    selected-page admission proof: either control or page failure raises.
    """
    payload, digest = _open(path, PAGE_H3_RECEIPT_TYPE)
    navigation = verify_navigation_receipt(
        navigation_receipt, profile_receipt=profile_receipt, source_bytes=source_bytes,
        catalogue_bytes=catalogue_bytes, candidate_id=candidate_id,
        execution_binding=execution_binding,
        expected_implementation_hashes=expected_navigation_implementation_hashes,
        not_before_utc=not_before_utc,
    )
    binding = _binding(execution_binding)
    if set(payload) != {
        "policy", "candidate", "profile_sha256", "execution_binding", "runtime",
        "implementation_hashes", "navigation_receipt_sha256", "selected_page", "control_url",
        "started_at", "completed_at", "control_before", "exact_page_probe", "control_after",
        "scientific_credit"
    } or payload["policy"] != rapid_study_profile.V5_SELECTED_PAGE_H3_POLICY or (
        payload["candidate"] != navigation["candidate"]
        or payload["profile_sha256"] != rapid_study_profile.FROZEN_V5_PROFILE_SHA256
        or payload["execution_binding"] != binding or payload["scientific_credit"] is not False
        or payload["navigation_receipt_sha256"] != navigation["navigation_receipt_sha256"]
        or payload["control_url"] != rapid_study_profile.V5_TRIAGE_POLICY["control_url"]
        or _hashes(payload["implementation_hashes"], "page-h3")
        != _hashes(expected_implementation_hashes, "page-h3")
    ):
        raise ValueError("page H3 receipt source/profile/implementation binding differs")
    _validate_runtime(payload["runtime"], binding)
    start, end = _freshness(payload["started_at"], payload["completed_at"], not_before_utc)
    if start < _time(navigation["completed_at"]):
        raise ValueError("page H3 probe predates its retained navigation")
    page_dict = payload["selected_page"]
    if not isinstance(page_dict, Mapping) or type(page_dict.get("ordinal")) is not int or not (
        0 <= page_dict["ordinal"] < len(navigation["pages"])
    ):
        raise ValueError("page H3 selected ordinal is invalid")
    page = navigation["pages"][page_dict["ordinal"]]
    if page_dict != page.as_dict():
        raise ValueError("page H3 exact URL differs from deterministic navigation")
    before = _probe_class(payload["control_before"], payload["control_url"], start, end)
    selected = _probe_class(payload["exact_page_probe"], page.url, start, end)
    after = _probe_class(payload["control_after"], payload["control_url"], start, end)
    if _time(payload["control_before"]["completed_at"]) > _time(payload["exact_page_probe"]["started_at"]) or (
        _time(payload["exact_page_probe"]["completed_at"]) > _time(payload["control_after"]["started_at"])
    ):
        raise ValueError("page H3 controlled raw probe order is invalid")
    if before[0] != "known-valid" or after[0] != "known-valid":
        raise ValueError("selected-page H3 controls did not pass")
    if selected[0] != "known-valid":
        raise ValueError("selected exact page did not prove known-valid H3")
    return {"policy": rapid_study_profile.V5_SELECTED_PAGE_H3_POLICY, "url": page.url,
            "selected_page_ordinal": page.ordinal,
            "navigation_receipt_sha256": navigation["navigation_receipt_sha256"],
            "outcome": "known-valid", "receipt_sha256": digest, "controls_passed": True}
