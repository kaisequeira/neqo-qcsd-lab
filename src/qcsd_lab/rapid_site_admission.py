"""Durable, independently reopened site evidence for the prospective v5 study.

This module grants no capture credit. A site is admitted after its prospective
safety policy, controlled exact-page H3 proof and complete-coverage preparer
agree on the same page, source and image. Only explicitly amended, independently
proved typed policy failures may be recorded as zero-credit search deferrals.
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib
import json
import re
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from functools import cached_property
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any, Iterator

from . import rapid_study_profile as profile
from .class_acquisition import (
    ExistingAcquisitionBackend, _converge_origins,
    _prepared_primary_response, unsafe_catalogue_domain_reason, validate_class_study_preparation,
)
from .discover import origin
from .manifest import validate_manifest
from .util import SOURCE_METADATA_KEYS, durable_create, source_metadata

TERMINAL_TYPE = "qcsd-rapid-v5-site-terminal"
REVIEW_TYPE = "qcsd-rapid-v5-human-site-review"
PREPARATION_TYPE = "qcsd-rapid-v5-site-preparation"
AUTOMATED_SCREEN_TYPE = "qcsd-rapid-v5-automated-public-page-screen-v1"
PAGE_POLICY_FAILURE_TYPE = "qcsd-rapid-v5-typed-page-policy-failure-v2"
COLLECTOR_FAILURE_TYPE = "qcsd-rapid-v5-bound-operational-collector-failure-v3"
ATTEMPT_FAILURE_TYPE = "qcsd-rapid-v5-bound-unsuccessful-live-attempt-v4"
PROVENANCE_TYPE = "qcsd-rapid-v5-acquisition-provenance"
CHECKPOINT_TYPE = "qcsd-rapid-v5-acquisition-checkpoint"
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
IMPLEMENTATION_GROUPS = {"curated", "fallback", "navigation", "page", "preparation"}
BROWSER_POLICY_GROUP = "browser_policy"
COLLECTOR_GROUP = "collector"
ATTEMPT_GROUP = "attempt"
PREPARATION_MODULES = (
    "qcsd_lab.rapid_site_admission", "qcsd_lab.class_acquisition", "qcsd_lab.prepare",
    "qcsd_lab.manifest", "qcsd_lab.discover", "qcsd_lab.discovery_evidence", "qcsd_lab.util",
)
APPLICATION_RESPONSE_POLICY_MODULE = "qcsd_lab.application_response_policy"


def preparation_implementation_sources(*, application_response_policy: bool = False) -> dict[str, Path]:
    """Identify producer/verifier bytes independently of the reused image source."""
    if type(application_response_policy) is not bool:
        raise ValueError("preparation policy source inventory opt-in must be boolean")
    names = (*PREPARATION_MODULES, *((APPLICATION_RESPONSE_POLICY_MODULE,) if application_response_policy else ()))
    return {name: Path(importlib.import_module(name).__file__) for name in names}


def preparation_implementation_hashes(*, application_response_policy: bool = False) -> dict[str, str]:
    return {name: _sha(_read(path)) for name, path in
            preparation_implementation_sources(application_response_policy=application_response_policy).items()}


def _json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON constant: {value}")


def _read(path: Path) -> bytes:
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
        raise ValueError(f"evidence is not a regular file: {path}")
    return path.read_bytes()


def _load(raw: bytes) -> Any:
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)


def _bind(kind: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    return {"schema_version": 1, "receipt_type": kind, "payload": dict(payload),
            "payload_sha256": _sha(_json(payload))}


def _unpack(raw: bytes, kind: str) -> dict[str, Any]:
    value = _load(raw)
    if (not isinstance(value, dict) or set(value) != {
        "schema_version", "receipt_type", "payload", "payload_sha256"
    } or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["receipt_type"] != kind or not isinstance(value["payload"], dict)
        or value["payload_sha256"] != _sha(_json(value["payload"]))):
        raise ValueError(f"invalid {kind} receipt")
    return value["payload"]


def _utc(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("evidence time must include its timezone")
    return result


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _selection_amendment_payload(raw: bytes) -> dict[str, Any]:
    from .rapid_selection_amendment import validate_selection_amendment
    value = _load(raw)
    if _json(value) != raw:
        raise ValueError("selection amendment receipt must use canonical immutable bytes")
    return validate_selection_amendment(value)


def _child(root: Path, reference: Mapping[str, Any]) -> Path:
    if not isinstance(reference, Mapping) or set(reference) != {"path", "sha256"}:
        raise ValueError("evidence reference is malformed")
    name, digest = reference["path"], reference["sha256"]
    if (not isinstance(name, str) or not name or "\\" in name
        or PurePosixPath(name).is_absolute() or any(p in {"", ".", ".."} for p in name.split("/"))
        or not isinstance(digest, str) or SHA_RE.fullmatch(digest) is None):
        raise ValueError("evidence reference is unsafe")
    root = Path(root).resolve()
    path = root.joinpath(*name.split("/"))
    current = path
    while current != root:
        if current.is_symlink():
            raise ValueError("evidence path contains a symlink")
        current = current.parent
    if not path.resolve().is_relative_to(root) or _sha(_read(path)) != digest:
        raise ValueError("evidence reference bytes changed")
    return path


def evidence_reference(root: Path, path: Path) -> dict[str, str]:
    root, path = Path(root).resolve(), Path(path).absolute()
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise ValueError("evidence must be inside its acquisition root") from error
    result = {"path": relative, "sha256": _sha(_read(path))}
    _child(root, result)
    return result


def import_evidence(root: Path, path: Path) -> dict[str, str]:
    """Retain bytes in a content addressed input store, without replacing them."""
    raw = _read(path)
    target = Path(root) / "inputs" / f"{_sha(raw)}.evidence"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if _read(target) != raw:
            raise ValueError("retained input digest collision")
    else:
        durable_create(target, raw)
    return evidence_reference(root, target)


@dataclass(frozen=True)
class AdmissionContext:
    root: Path
    provenance_sha256: str
    profile_bytes: bytes
    source_bytes: bytes
    source_receipt_bytes: bytes
    catalogue_bytes: bytes
    execution_binding: Mapping[str, str]
    expected_runtime_source: Mapping[str, Any]
    mounted_module_hashes: Mapping[str, Mapping[str, str]]
    not_before_utc: datetime
    selection_amendment_bytes: bytes | None = None

    @property
    def selection_amendment_sha256(self) -> str | None:
        return _sha(self.selection_amendment_bytes) if self.selection_amendment_bytes is not None else None

    @property
    def browser_policy_not_before_utc(self) -> datetime:
        if self.selection_amendment_bytes is None:
            raise ValueError("browser policy deferral requires a prospective selection amendment")
        amendment = _selection_amendment_payload(self.selection_amendment_bytes)
        return max(self.not_before_utc, _utc(amendment["published_at_utc"]))

    @property
    def selection_amendment_revision(self) -> int | None:
        if self.selection_amendment_bytes is None:
            return None
        from .rapid_selection_amendment import selection_amendment_revision
        return selection_amendment_revision(_load(self.selection_amendment_bytes))

    @property
    def application_response_policy(self) -> str | None:
        if self.selection_amendment_revision not in {5, 6}:
            return None
        return _selection_amendment_payload(self.selection_amendment_bytes)["application_response_policy"]

    @property
    def primary_document_identity_policy(self) -> str | None:
        if self.selection_amendment_revision != 6:
            return None
        return _selection_amendment_payload(self.selection_amendment_bytes)["primary_document_identity_policy"]

    @property
    def page_policy_not_before_utc(self) -> datetime:
        if self.selection_amendment_revision not in {2, 3, 4, 5, 6}:
            raise ValueError("automated screen and typed page-policy deferral require selection amendment revision 2")
        return self.browser_policy_not_before_utc

    @property
    def collector_not_before_utc(self) -> datetime:
        if self.selection_amendment_revision not in {3, 4, 5, 6}:
            raise ValueError("operational collector deferral requires selection amendment revision 3")
        return self.browser_policy_not_before_utc

    @property
    def attempt_not_before_utc(self) -> datetime:
        if self.selection_amendment_revision not in {4, 5, 6}:
            raise ValueError("unsuccessful live attempt deferral requires selection amendment revision 4")
        return self.browser_policy_not_before_utc

    @cached_property
    def proof_cache(self) -> dict[str, dict[Any, Any]]:
        # Only semantic results are cached. Every referenced file is reopened
        # and hashed before a lookup, and the key includes independent runtime
        # and implementation expectations. A changed byte never gains reuse.
        return {"root": {}, "page": {}, "prepared": {}, "browser_policy": {},
                "automated_screen": {}, "page_policy": {}}

    @cached_property
    def candidates(self) -> tuple[dict[str, Any], ...]:
        if _sha(self.profile_bytes) != profile.FROZEN_V5_PROFILE_SHA256:
            raise ValueError("admission profile differs from the frozen v5 bytes")
        return profile.validate_v5_profile_receipt(
            _load(self.profile_bytes), self.source_bytes, self.catalogue_bytes
        )

    def candidate(self, candidate_id: str) -> dict[str, Any]:
        for candidate in self.candidates:
            if candidate["candidate_id"] == candidate_id:
                return candidate
        raise ValueError("candidate is outside the frozen v5 profile")


def initialize_acquisition(
    root: Path, *, profile_path: Path, source: Path, source_receipt: Path,
    catalogue: Path, source_manifest: Path, admission_image_digest: str,
    not_before_utc: datetime, module_sources: Mapping[str, Mapping[str, Path]],
    selection_amendment: Path | None = None,
) -> AdmissionContext:
    """Freeze independently supplied image metadata and verifier source snapshots."""
    root = Path(root)
    if root.exists() or root.is_symlink():
        raise FileExistsError("rapid acquisition destination is create-only")
    if (not isinstance(not_before_utc, datetime) or not_before_utc.tzinfo is None
        or not_before_utc.utcoffset() is None):
        raise ValueError("profile freeze must include its timezone")
    required_groups = IMPLEMENTATION_GROUPS | ({BROWSER_POLICY_GROUP} if selection_amendment is not None else set())
    if selection_amendment is not None:
        from .rapid_selection_amendment import selection_amendment_revision
        revision = selection_amendment_revision(_load(_read(selection_amendment)))
        if revision >= 3:
            required_groups |= {COLLECTOR_GROUP}
        if revision >= 4:
            required_groups |= {ATTEMPT_GROUP}
    if set(module_sources) != required_groups:
        raise ValueError("all independent implementation snapshots are required")
    profile_raw, source_raw, catalogue_raw = _read(profile_path), _read(source), _read(catalogue)
    if _sha(profile_raw) != profile.FROZEN_V5_PROFILE_SHA256:
        raise ValueError("acquisition needs the frozen v5 profile")
    profile.validate_v5_profile_receipt(_load(profile_raw), source_raw, catalogue_raw)
    if selection_amendment is not None:
        _selection_amendment_payload(_read(selection_amendment))
    source_raw_manifest = _read(source_manifest)
    binding = profile._execution_binding({
        "source_manifest_sha256": _sha(source_raw_manifest),
        "admission_image_digest": admission_image_digest,
    })
    runtime = _runtime_source(source_raw_manifest, binding)
    root.mkdir(parents=True)
    input_paths = {
            "profile": profile_path, "source": source, "source_receipt": source_receipt,
            "catalogue": catalogue, "source_manifest": source_manifest,
    }
    if selection_amendment is not None:
        input_paths["selection_amendment"] = selection_amendment
    inputs = {key: import_evidence(root, value) for key, value in input_paths.items()}
    modules = {
        group: {name: import_evidence(root, path) for name, path in sources.items()}
        for group, sources in module_sources.items()
    }
    durable_create(root / "provenance.json", _json(_bind(PROVENANCE_TYPE, {
        "profile_version": 5, "inputs": inputs, "module_sources": modules,
        "execution_binding": binding, "runtime_source": runtime,
        "not_before_utc": not_before_utc.isoformat(), "created_at": _now(),
        "scientific_credit": False,
    })))
    context = load_admission_context(root)
    write_checkpoint(context)
    return context


def _runtime_source(raw: bytes, binding: Mapping[str, str]) -> dict[str, Any]:
    value = _load(raw)
    empty = _sha(b"")
    if (not isinstance(value, dict) or set(value) != SOURCE_METADATA_KEYS
        or value["image_digest"] not in {None, binding["admission_image_digest"]}
        or any(not isinstance(value[k], str) or re.fullmatch(r"[0-9a-f]{40}", value[k]) is None
               for k in ("lab_commit", "neqo_commit", "neqo_pinned_commit"))
        or value["neqo_commit"] != value["neqo_pinned_commit"]
        or value["lab_dirty"] is not False or value["neqo_dirty"] is not False
        or value["lab_patch_sha256"] != empty or value["neqo_patch_sha256"] != empty
        or _sha(raw) != binding["source_manifest_sha256"]):
        raise ValueError("admission requires independently bound clean image source metadata")
    return {**value, "image_digest": binding["admission_image_digest"]}


def load_admission_context(root: Path) -> AdmissionContext:
    root = Path(root).resolve()
    raw = _read(root / "provenance.json")
    value = _unpack(raw, PROVENANCE_TYPE)
    if set(value) != {"profile_version", "inputs", "module_sources", "execution_binding",
                      "runtime_source", "not_before_utc", "created_at", "scientific_credit"}:
        raise ValueError("acquisition provenance fields changed")
    if value["profile_version"] != 5 or value["scientific_credit"] is not False:
        raise ValueError("acquisition provenance grants unsupported authority")
    base_inputs = {"profile", "source", "source_receipt", "catalogue", "source_manifest"}
    if not isinstance(value["inputs"], Mapping) or set(value["inputs"]) not in (base_inputs, base_inputs | {"selection_amendment"}):
        raise ValueError("acquisition input inventory changed")
    inputs = {key: _read(_child(root, ref)) for key, ref in value["inputs"].items()}
    binding = profile._execution_binding(value["execution_binding"])
    runtime = _runtime_source(inputs["source_manifest"], binding)
    if value["runtime_source"] != runtime:
        raise ValueError("runtime source differs from independent image metadata")
    groups = value["module_sources"]
    required_groups = IMPLEMENTATION_GROUPS | ({BROWSER_POLICY_GROUP} if "selection_amendment" in inputs else set())
    if "selection_amendment" in inputs:
        from .rapid_selection_amendment import selection_amendment_revision
        revision = selection_amendment_revision(_load(inputs["selection_amendment"]))
        if revision >= 3:
            required_groups |= {COLLECTOR_GROUP}
        if revision >= 4:
            required_groups |= {ATTEMPT_GROUP}
    if not isinstance(groups, Mapping) or set(groups) != required_groups:
        raise ValueError("acquisition implementation inventory changed")
    hashes = {}
    for group, modules in groups.items():
        if not isinstance(modules, Mapping) or not modules:
            raise ValueError("implementation group has no retained source")
        hashes[group] = {name: _sha(_read(_child(root, ref))) for name, ref in modules.items()}
    context = AdmissionContext(
        root, _sha(raw), inputs["profile"], inputs["source"], inputs["source_receipt"],
        inputs["catalogue"], binding, runtime, hashes, _utc(value["not_before_utc"]),
        inputs.get("selection_amendment"),
    )
    context.candidates
    if context.selection_amendment_bytes is not None:
        from .rapid_browser_policy_evidence import implementation_sources
        _selection_amendment_payload(context.selection_amendment_bytes)
        if set(context.mounted_module_hashes[BROWSER_POLICY_GROUP]) != set(implementation_sources()):
            raise ValueError("browser policy implementation inventory changed")
    if context.selection_amendment_revision in {3, 4, 5, 6}:
        from .rapid_collector_failure_evidence import implementation_sources
        if set(context.mounted_module_hashes[COLLECTOR_GROUP]) != set(implementation_sources()):
            raise ValueError("collector implementation inventory changed")
    if context.selection_amendment_revision in {4, 5, 6}:
        from .rapid_attempt_failure_evidence import implementation_sources
        if set(context.mounted_module_hashes[ATTEMPT_GROUP]) != set(implementation_sources(
            application_response_policy=context.application_response_policy is not None,
        )):
            raise ValueError("unsuccessful attempt implementation inventory changed")
    if set(context.mounted_module_hashes["preparation"]) != set(preparation_implementation_sources(
        application_response_policy=context.application_response_policy is not None,
    )):
        raise ValueError("preparation implementation inventory changed")
    return context


def verify_root_screen(
    context: AdmissionContext, candidate_id: str, references: Sequence[Mapping[str, str]],
) -> dict[str, Any]:
    """Reopen full controlled survey logs; ignore supplied outcome summaries."""
    candidate = context.candidate(candidate_id)
    paths = [_child(context.root, ref) for ref in references]
    group = "curated" if candidate["source_kind"] == "curated" else "fallback"
    cache_key = (
        tuple(ref["sha256"] for ref in references),
        _sha(_json(context.mounted_module_hashes[group])),
        _sha(_json(context.expected_runtime_source)), context.not_before_utc.isoformat(),
    )
    cached = context.proof_cache["root"].get(cache_key)
    if cached is not None:
        decisions = cached
    else:
        decisions = None
    kwargs = dict(execution_binding=context.execution_binding,
                  expected_runtime_source=context.expected_runtime_source,
                  not_before_utc=context.not_before_utc)
    if decisions is None and candidate["source_kind"] == "curated":
        decisions = profile.verify_v5_curated_h3_survey_logs(
            paths, context.profile_bytes, context.source_bytes, context.source_receipt_bytes,
            context.catalogue_bytes,
            expected_mounted_module_hashes=context.mounted_module_hashes["curated"], **kwargs,
        )
    elif decisions is None:
        decisions = profile.verify_v5_fallback_h3_survey_logs(
            paths, context.profile_bytes, context.source_bytes, context.catalogue_bytes,
            expected_mounted_module_hashes=context.mounted_module_hashes["fallback"], **kwargs,
        )
    context.proof_cache["root"][cache_key] = decisions
    found = [row for row in decisions if row["candidate_id"] == candidate_id]
    if len(found) != 1 or found[0]["domain"] != candidate["domain"]:
        raise ValueError("root survey has no unique first decision for this candidate")
    return deepcopy(found[0])


def produce_human_review(
    output: Path, context: AdmissionContext, *, candidate_id: str, reviewed_url: str,
    reviewer: str, decision: str, reason: str | None, human_confirmed: bool,
) -> dict[str, Any]:
    """Record an explicit operator review; no inferred or automatic approvals."""
    candidate = context.candidate(candidate_id)
    if human_confirmed is not True or not isinstance(reviewer, str) or not reviewer.strip():
        raise ValueError("a named human must explicitly confirm the review")
    canonical = profile.canonical_query_free_html_url(reviewed_url, registrable_domain=candidate["domain"])
    if canonical != reviewed_url:
        raise ValueError("human review URL is not the exact canonical page")
    profile._validated_site_safety_review({
        "policy": profile.SITE_SAFETY_REVIEW_POLICY["policy"], "decision": decision,
        "reason": reason, "receipt_sha256": "0" * 64,
    })
    receipt = _bind(REVIEW_TYPE, {
        "profile_sha256": _sha(context.profile_bytes), "candidate_id": candidate_id,
        "domain": candidate["domain"], "source_sha256": candidate["source_sha256"],
        "reviewed_url": reviewed_url, "reviewer": reviewer.strip(),
        "decision": decision, "reason": reason, "human_confirmed": True,
        "policy": profile.SITE_SAFETY_REVIEW_POLICY["policy"], "reviewed_at": _now(),
        "scientific_credit": False,
    })
    durable_create(Path(output), _json(receipt))
    verify_human_review(output, context, candidate_id=candidate_id, reviewed_url=reviewed_url)
    return receipt


def verify_human_review(
    path: Path, context: AdmissionContext, *, candidate_id: str, reviewed_url: str,
) -> dict[str, Any]:
    raw = _read(path)
    value = _unpack(raw, REVIEW_TYPE)
    candidate = context.candidate(candidate_id)
    if set(value) != {"profile_sha256", "candidate_id", "domain", "source_sha256", "reviewed_url",
                      "reviewer", "decision", "reason", "human_confirmed", "policy", "reviewed_at",
                      "scientific_credit"}:
        raise ValueError("human review fields changed")
    if (value["profile_sha256"] != _sha(context.profile_bytes)
        or value["candidate_id"] != candidate_id or value["domain"] != candidate["domain"]
        or value["source_sha256"] != candidate["source_sha256"]
        or value["reviewed_url"] != reviewed_url or value["human_confirmed"] is not True
        or not isinstance(value["reviewer"], str) or not value["reviewer"].strip()
        or _utc(value["reviewed_at"]) < context.not_before_utc
        or value["scientific_credit"] is not False
        or profile.canonical_query_free_html_url(reviewed_url, registrable_domain=candidate["domain"]) != reviewed_url):
        raise ValueError("human review does not bind the current candidate and exact page")
    return profile._validated_site_safety_review({
        "policy": value["policy"], "decision": value["decision"],
        "reason": value["reason"], "receipt_sha256": _sha(raw),
    })


def _page_facts(
    context: AdmissionContext, candidate_id: str, navigation: Path, page_h3: Path,
) -> dict[str, Any]:
    from .rapid_page_evidence import verify_navigation_receipt, verify_selected_page_h3_receipt
    cache_key = (
        candidate_id, _sha(_read(navigation)), _sha(_read(page_h3)),
        _sha(_json(context.mounted_module_hashes["navigation"])),
        _sha(_json(context.mounted_module_hashes["page"])),
        _sha(_json(context.execution_binding)), context.not_before_utc.isoformat(),
    )
    if cache_key in context.proof_cache["page"]:
        return deepcopy(context.proof_cache["page"][cache_key])
    kwargs = dict(profile_receipt=_load(context.profile_bytes), source_bytes=context.source_bytes,
                  catalogue_bytes=context.catalogue_bytes, candidate_id=candidate_id,
                  execution_binding=context.execution_binding, not_before_utc=context.not_before_utc)
    verify_navigation_receipt(
        navigation, expected_implementation_hashes=context.mounted_module_hashes["navigation"], **kwargs
    )
    facts = verify_selected_page_h3_receipt(
        page_h3, navigation_receipt=navigation,
        expected_navigation_implementation_hashes=context.mounted_module_hashes["navigation"],
        expected_implementation_hashes=context.mounted_module_hashes["page"], **kwargs,
    )
    context.proof_cache["page"][cache_key] = facts
    return deepcopy(facts)


def validate_automated_site_screen_facts(
    value: Any, *, candidate: Mapping[str, Any], selected_page_url: str,
    execution_binding: Mapping[str, Any], selection_amendment_sha256: str,
    not_before_utc: datetime,
) -> dict[str, Any]:
    """Validate declared URL/domain screening facts after independent reopening."""
    from .rapid_page_evidence import _freshness
    from .rapid_selection_amendment import (
        AUTOMATED_SITE_SCREEN_DECISION, AUTOMATED_SITE_SCREEN_POLICY, automated_screen_policy_sha256,
    )
    fields = {"policy", "policy_sha256", "decision", "selected_page_url", "selected_page_ordinal",
              "navigation_receipt_sha256", "selected_page_h3_receipt_sha256", "receipt_sha256",
              "execution_binding", "selection_amendment_sha256", "screened_at", "scientific_credit"}
    if (not isinstance(value, Mapping) or set(value) != fields
        or value["policy"] != AUTOMATED_SITE_SCREEN_POLICY
        or value["policy_sha256"] != automated_screen_policy_sha256()
        or value["decision"] != AUTOMATED_SITE_SCREEN_DECISION
        or value["selected_page_url"] != selected_page_url
        or profile.canonical_query_free_html_url(selected_page_url, registrable_domain=candidate["domain"]) != selected_page_url
        or unsafe_catalogue_domain_reason(candidate["domain"]) is not None
        or type(value["selected_page_ordinal"]) is not int or not 0 <= value["selected_page_ordinal"] <= 4
        or _json(value["execution_binding"]) != _json(execution_binding)
        or value["selection_amendment_sha256"] != selection_amendment_sha256
        or value["scientific_credit"] is not False
        or any(not isinstance(value[key], str) or SHA_RE.fullmatch(value[key]) is None for key in (
            "policy_sha256", "navigation_receipt_sha256", "selected_page_h3_receipt_sha256",
            "receipt_sha256", "selection_amendment_sha256"))):
        raise ValueError("automated public URL/domain screen facts are invalid")
    _freshness(value["screened_at"], value["screened_at"], not_before_utc)
    return deepcopy(dict(value))


def produce_automated_site_screen(
    output: Path, context: AdmissionContext, *, candidate_id: str,
    navigation: Path, page_h3: Path, selected_page_ordinal: int,
) -> dict[str, Any]:
    """Record the frozen URL/domain rules; this does not classify page content."""
    from .rapid_selection_amendment import automated_screen_policy_payload
    context.page_policy_not_before_utc
    page = _page_facts(context, candidate_id, navigation, page_h3)
    if type(selected_page_ordinal) is not int or selected_page_ordinal != page["selected_page_ordinal"]:
        raise ValueError("automated screen ordinal differs from the independently selected page")
    if preparation_implementation_hashes(application_response_policy=context.application_response_policy is not None) != context.mounted_module_hashes["preparation"]:
        raise ValueError("automated screen implementation changed since the prospective source freeze")
    candidate = context.candidate(candidate_id)
    if unsafe_catalogue_domain_reason(candidate["domain"]) is not None:
        raise ValueError("automatic domain policy excludes this candidate before page work")
    receipt = _bind(AUTOMATED_SCREEN_TYPE, {
        "profile_sha256": _sha(context.profile_bytes), "candidate": candidate,
        "provenance_sha256": context.provenance_sha256,
        "selection_amendment_sha256": context.selection_amendment_sha256,
        "execution_binding": dict(context.execution_binding),
        "implementation_hashes": dict(context.mounted_module_hashes["preparation"]),
        "inputs": {"navigation": import_evidence(context.root, navigation),
                   "page_h3": import_evidence(context.root, page_h3)},
        "selected_page_url": page["url"], "selected_page_ordinal": selected_page_ordinal,
        "screen_policy": automated_screen_policy_payload(), "screened_at": _now(),
        "scientific_credit": False,
    })
    durable_create(Path(output), _json(receipt))
    verify_automated_site_screen(output, context, candidate_id=candidate_id)
    return receipt


def verify_automated_site_screen(path: Path, context: AdmissionContext, *, candidate_id: str) -> dict[str, Any]:
    from .rapid_selection_amendment import (
        AUTOMATED_SITE_SCREEN_DECISION, AUTOMATED_SITE_SCREEN_POLICY,
        automated_screen_policy_payload, automated_screen_policy_sha256,
    )
    barrier = context.page_policy_not_before_utc
    raw = _read(path)
    value = _unpack(raw, AUTOMATED_SCREEN_TYPE)
    fields = {"profile_sha256", "candidate", "provenance_sha256", "selection_amendment_sha256",
              "execution_binding", "implementation_hashes", "inputs", "selected_page_url",
              "selected_page_ordinal", "screen_policy", "screened_at", "scientific_credit"}
    candidate = context.candidate(candidate_id)
    if (set(value) != fields or value["profile_sha256"] != _sha(context.profile_bytes)
        or _json(value["candidate"]) != _json(candidate)
        or value["provenance_sha256"] != context.provenance_sha256
        or value["selection_amendment_sha256"] != context.selection_amendment_sha256
        or _json(value["execution_binding"]) != _json(context.execution_binding)
        or value["implementation_hashes"] != context.mounted_module_hashes["preparation"]
        or value["screen_policy"] != automated_screen_policy_payload()
        or value["scientific_credit"] is not False
        or not isinstance(value["inputs"], Mapping) or set(value["inputs"]) != {"navigation", "page_h3"}):
        raise ValueError("automated screen receipt differs from its prospective context")
    page = _page_facts(context, candidate_id, *(
        _child(context.root, value["inputs"][key]) for key in ("navigation", "page_h3")
    ))
    if value["selected_page_url"] != page["url"] or value["selected_page_ordinal"] != page["selected_page_ordinal"]:
        raise ValueError("automated screen differs from exact navigation and H3 page proofs")
    return validate_automated_site_screen_facts({
        "policy": AUTOMATED_SITE_SCREEN_POLICY, "policy_sha256": automated_screen_policy_sha256(),
        "decision": AUTOMATED_SITE_SCREEN_DECISION, "selected_page_url": value["selected_page_url"],
        "selected_page_ordinal": value["selected_page_ordinal"],
        "navigation_receipt_sha256": page["navigation_receipt_sha256"],
        "selected_page_h3_receipt_sha256": page["receipt_sha256"], "receipt_sha256": _sha(raw),
        "execution_binding": dict(context.execution_binding),
        "selection_amendment_sha256": context.selection_amendment_sha256,
        "screened_at": value["screened_at"], "scientific_credit": False,
    }, candidate=candidate, selected_page_url=page["url"], execution_binding=context.execution_binding,
       selection_amendment_sha256=context.selection_amendment_sha256, not_before_utc=barrier)


def _page_policy_implementation(context: AdmissionContext) -> dict[str, dict[str, str]]:
    return {key: dict(context.mounted_module_hashes[key]) for key in ("preparation", BROWSER_POLICY_GROUP)}


def begin_page_policy_action(context: AdmissionContext) -> dict[str, Any]:
    """Capture actual bound runtime and recheck both source groups before work."""
    from .rapid_browser_policy_evidence import implementation_hashes
    from .rapid_page_evidence import _runtime_payload, _validate_runtime
    context.page_policy_not_before_utc
    if (preparation_implementation_hashes(application_response_policy=context.application_response_policy is not None) != context.mounted_module_hashes["preparation"]
        or implementation_hashes() != context.mounted_module_hashes[BROWSER_POLICY_GROUP]):
        raise ValueError("typed page-policy action implementation changed since prospective freeze")
    runtime = _runtime_payload(context.execution_binding)
    if _validate_runtime(runtime, context.execution_binding) != dict(context.expected_runtime_source):
        raise ValueError("typed page-policy action runtime differs from independent clean source")
    return runtime


def is_page_policy_failure(error: Exception, *, action_kind: str) -> bool:
    from .acquisition_errors import PassiveRenderPolicyError, FullGraphH3PolicyError, ResponseStabilityPolicyError
    allowed = (PassiveRenderPolicyError,) if action_kind == "catalogue-boundary-navigation" else (
        PassiveRenderPolicyError, FullGraphH3PolicyError, ResponseStabilityPolicyError,
    )
    return type(error) in allowed


def validate_page_policy_failure_facts(
    value: Any, *, candidate: Mapping[str, Any], execution_binding: Mapping[str, Any],
    selection_amendment_sha256: str, not_before_utc: datetime,
    selected_page_h3_proof: Mapping[str, Any] | None = None,
    automated_site_screen: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Revalidate raw typed stage proof and its declared candidate/action bounds."""
    from .rapid_page_evidence import _freshness
    from .prepare import validate_passive_render_policy_failure_evidence, validate_preparation_policy_failure_evidence
    from .rapid_selection_amendment import PAGE_POLICY_DEFERRAL_POLICY
    fields = {"page_policy_failure_receipt_sha256", "policy", "profile_sha256", "selection_amendment_sha256",
              "candidate", "execution_binding", "runtime_source", "implementation_hashes", "started_at",
              "completed_at", "action", "failure_page_attribution", "raw_failure",
              "navigation_receipt_sha256", "selected_page_h3_receipt_sha256",
              "automated_site_screen_receipt_sha256", "scientific_credit"}
    if (not isinstance(value, Mapping) or set(value) != fields or value["policy"] != PAGE_POLICY_DEFERRAL_POLICY
        or value["profile_sha256"] != profile.FROZEN_V5_PROFILE_SHA256
        or value["selection_amendment_sha256"] != selection_amendment_sha256
        or _json(value["candidate"]) != _json(candidate)
        or _json(value["execution_binding"]) != _json(execution_binding)
        or unsafe_catalogue_domain_reason(candidate["domain"]) is not None
        or value["scientific_credit"] is not False
        or not isinstance(value["page_policy_failure_receipt_sha256"], str)
        or SHA_RE.fullmatch(value["page_policy_failure_receipt_sha256"]) is None):
        raise ValueError("typed page-policy failure facts are invalid")
    _freshness(value["started_at"], value["completed_at"], not_before_utc)
    action = value["action"]
    if not isinstance(action, Mapping) or set(action) != {"kind", "url", "scope", "selected_page_ordinal"}:
        raise ValueError("typed page-policy failure action fields are invalid")
    proof_keys = ("navigation_receipt_sha256", "selected_page_h3_receipt_sha256", "automated_site_screen_receipt_sha256")
    if action["kind"] == "catalogue-boundary-navigation":
        if (action != {"kind": "catalogue-boundary-navigation", "url": f"https://{candidate['domain']}/",
                       "scope": "catalogue-root-and-optional-link-navigation", "selected_page_ordinal": None}
            or value["failure_page_attribution"] != "unavailable"
            or selected_page_h3_proof is not None or automated_site_screen is not None
            or any(value[key] is not None for key in proof_keys)):
            raise ValueError("navigation policy failure claimed unavailable page attribution")
        allowed = {"PassiveRenderPolicyError"}
    elif action["kind"] == "complete-graph-preparation":
        if selected_page_h3_proof is None or automated_site_screen is None:
            raise ValueError("preparation policy failure lacks independently reopened page and automated screen")
        page = selected_page_h3_proof
        if (action != {"kind": "complete-graph-preparation", "url": page["url"],
                       "scope": "exact-selected-page-complete-resource-graph-preparation",
                       "selected_page_ordinal": page["selected_page_ordinal"]}
            or value["failure_page_attribution"] != "exact-selected-page"
            or value["navigation_receipt_sha256"] != page["navigation_receipt_sha256"]
            or value["selected_page_h3_receipt_sha256"] != page["receipt_sha256"]
            or value["automated_site_screen_receipt_sha256"] != automated_site_screen["receipt_sha256"]):
            raise ValueError("preparation policy failure changed its exact page proof binding")
        allowed = {"PassiveRenderPolicyError", "FullGraphH3PolicyError", "ResponseStabilityPolicyError"}
    else:
        raise ValueError("unregistered typed page-policy failure action")
    raw = value["raw_failure"]
    if (not isinstance(raw, Mapping) or set(raw) != {"exception_type", "message", "evidence", "capture_source",
                                                  "capture_started_at", "capture_completed_at"}
        or raw["exception_type"] not in allowed or not isinstance(raw["message"], str)):
        raise ValueError("page-policy deferral lacks its exact typed raw failure")
    if raw["exception_type"] == "PassiveRenderPolicyError":
        validate_passive_render_policy_failure_evidence(raw["evidence"])
    else:
        stage = "full-graph-h3" if raw["exception_type"] == "FullGraphH3PolicyError" else "response-stability"
        evidence = validate_preparation_policy_failure_evidence(raw["evidence"], source_url=action["url"])
        if evidence["stage"] != stage:
            raise ValueError("typed preparation exception differs from its retained raw stage")
    captures = [raw[key] for key in ("capture_source", "capture_started_at", "capture_completed_at")]
    if any(item is not None for item in captures):
        if (any(item is None for item in captures) or _json(raw["capture_source"]) != _json(value["runtime_source"])):
            raise ValueError("typed preparation inner runtime source differs from outer observation")
        _freshness(raw["capture_started_at"], raw["capture_completed_at"], not_before_utc)
        if not _utc(value["started_at"]) <= _utc(raw["capture_started_at"]) <= _utc(raw["capture_completed_at"]) <= _utc(value["completed_at"]):
            raise ValueError("typed preparation inner timestamps lie outside the actual outer action")
    elif raw["exception_type"] != "PassiveRenderPolicyError":
        raise ValueError("typed graph/stability failure lacks actual preparer source and timestamps")
    hashes = value["implementation_hashes"]
    if (not isinstance(hashes, Mapping) or set(hashes) != {"preparation", BROWSER_POLICY_GROUP}
        or set(hashes["preparation"]) not in (set(PREPARATION_MODULES), set(PREPARATION_MODULES) | {APPLICATION_RESPONSE_POLICY_MODULE})):
        raise ValueError("typed page-policy proof implementation source groups are invalid")
    from .rapid_browser_policy_evidence import implementation_sources
    if set(hashes[BROWSER_POLICY_GROUP]) != set(implementation_sources()) or any(
        not isinstance(digest, str) or SHA_RE.fullmatch(digest) is None
        for group in hashes.values() for digest in group.values()
    ):
        raise ValueError("typed page-policy proof implementation hashes are invalid")
    source = value["runtime_source"]
    if (not isinstance(source, Mapping) or set(source) != SOURCE_METADATA_KEYS
        or source["image_digest"] != execution_binding["admission_image_digest"]
        or source["lab_dirty"] is not False or source["neqo_dirty"] is not False
        or source["neqo_commit"] != source["neqo_pinned_commit"]
        or source["lab_patch_sha256"] != _sha(b"") or source["neqo_patch_sha256"] != _sha(b"")):
        raise ValueError("typed page-policy proof runtime is not clean and pinned")
    return deepcopy(dict(value))


def retain_page_policy_failure(
    output: Path, context: AdmissionContext, *, candidate_id: str, error: Exception,
    action_kind: str, started_at: str, runtime: Mapping[str, Any],
    navigation: Path | None = None, page_h3: Path | None = None, automated_screen: Path | None = None,
) -> Path:
    """Retain an exact typed failure; explicit sealing still grants zero credit."""
    if not is_page_policy_failure(error, action_kind=action_kind):
        raise ValueError("exception type is not an amended page-policy deferral")
    raw_failure = {"exception_type": type(error).__name__, "message": str(error),
                   "evidence": deepcopy(getattr(error, "evidence", None)),
                   **{key: deepcopy(getattr(error, key, None)) for key in (
                       "capture_source", "capture_started_at", "capture_completed_at")}}
    # Raw observations survive a refused source binding or raw proof validation.
    durable_create(Path(output).with_name("raw-typed-policy-error.json"), _json(raw_failure))
    if begin_page_policy_action(context) != runtime:
        raise ValueError("typed page-policy runtime changed during the actual action")
    candidate = context.candidate(candidate_id)
    refs = {key: import_evidence(context.root, path) for key, path in {
        "navigation": navigation, "page_h3": page_h3, "automated_screen": automated_screen,
    }.items() if path is not None}
    page = _page_facts(context, candidate_id, navigation, page_h3) if navigation is not None and page_h3 is not None else None
    from .rapid_selection_amendment import PAGE_POLICY_DEFERRAL_POLICY
    payload = {
        "policy": PAGE_POLICY_DEFERRAL_POLICY, "profile_sha256": _sha(context.profile_bytes),
        "candidate": candidate, "provenance_sha256": context.provenance_sha256,
        "selection_amendment_sha256": context.selection_amendment_sha256,
        "execution_binding": dict(context.execution_binding), "runtime": dict(runtime),
        "implementation_hashes": _page_policy_implementation(context), "started_at": started_at,
        "completed_at": _now(), "inputs": refs, "raw_failure": raw_failure,
        "action": {"kind": action_kind, "url": page["url"] if page else f"https://{candidate['domain']}/",
                   "scope": "exact-selected-page-complete-resource-graph-preparation" if page else "catalogue-root-and-optional-link-navigation",
                   "selected_page_ordinal": page["selected_page_ordinal"] if page else None},
        "failure_page_attribution": "exact-selected-page" if page else "unavailable", "scientific_credit": False,
    }
    receipt = _bind(PAGE_POLICY_FAILURE_TYPE, payload)
    # Validate before publishing a ready proof. A rejected raw observation stays retryable.
    _page_policy_payload_facts(payload, context, candidate_id, receipt_sha256=_sha(_json(receipt)))
    durable_create(Path(output), _json(receipt))
    page_policy_failure_facts(output, context, candidate_id)
    return Path(output)


def _page_policy_payload_facts(value: Mapping[str, Any], context: AdmissionContext, candidate_id: str, *, receipt_sha256: str) -> dict[str, Any]:
    from .rapid_page_evidence import _validate_runtime
    fields = {"policy", "profile_sha256", "candidate", "provenance_sha256", "selection_amendment_sha256",
              "execution_binding", "runtime", "implementation_hashes", "started_at", "completed_at", "inputs",
              "raw_failure", "action", "failure_page_attribution", "scientific_credit"}
    if (set(value) != fields or value["provenance_sha256"] != context.provenance_sha256
        or value["implementation_hashes"] != _page_policy_implementation(context)):
        raise ValueError("typed page-policy receipt changed its independent context/source binding")
    source = _validate_runtime(value["runtime"], context.execution_binding)
    if source != dict(context.expected_runtime_source):
        raise ValueError("typed page-policy source differs from independent admission source")
    refs = value["inputs"]
    if not isinstance(refs, Mapping):
        raise ValueError("typed page-policy receipt inputs are invalid")
    page = screen = None
    if value["action"]["kind"] == "catalogue-boundary-navigation":
        if refs:
            raise ValueError("navigation failure cannot claim later page proofs")
    else:
        if set(refs) != {"navigation", "page_h3", "automated_screen"}:
            raise ValueError("preparation failure lacks exact retained page and screen inputs")
        page = _page_facts(context, candidate_id, *(_child(context.root, refs[key]) for key in ("navigation", "page_h3")))
        screen = verify_automated_site_screen(_child(context.root, refs["automated_screen"]), context, candidate_id=candidate_id)
    facts = {key: deepcopy(value[key]) for key in fields - {"runtime", "inputs", "provenance_sha256"}}
    facts.update({"runtime_source": source, "page_policy_failure_receipt_sha256": receipt_sha256,
                  "navigation_receipt_sha256": page["navigation_receipt_sha256"] if page else None,
                  "selected_page_h3_receipt_sha256": page["receipt_sha256"] if page else None,
                  "automated_site_screen_receipt_sha256": screen["receipt_sha256"] if screen else None})
    return validate_page_policy_failure_facts(
        facts, candidate=context.candidate(candidate_id), execution_binding=context.execution_binding,
        selection_amendment_sha256=context.selection_amendment_sha256, not_before_utc=context.page_policy_not_before_utc,
        selected_page_h3_proof=page, automated_site_screen=screen,
    )


def page_policy_failure_facts(path: Path, context: AdmissionContext, candidate_id: str) -> dict[str, Any]:
    raw = _read(path)
    return _page_policy_payload_facts(_unpack(raw, PAGE_POLICY_FAILURE_TYPE), context, candidate_id, receipt_sha256=_sha(raw))


def begin_operational_collector_action(context: AdmissionContext) -> dict[str, Any]:
    """Bind the actual collector runtime before a prospectively allowed action."""
    from .rapid_collector_failure_evidence import begin_collector_action
    from .rapid_page_evidence import _validate_runtime
    runtime = begin_collector_action(
        context.execution_binding, context.mounted_module_hashes[COLLECTOR_GROUP],
        context.collector_not_before_utc,
    )
    if _validate_runtime(runtime, context.execution_binding) != dict(context.expected_runtime_source):
        raise ValueError("collector runtime differs from independent clean admission source")
    return runtime


def _collector_action(candidate: Mapping[str, Any], page: Mapping[str, Any] | None) -> dict[str, Any]:
    if page is None:
        return {"kind": "catalogue-boundary-navigation", "url": f"https://{candidate['domain']}/",
                "scope": "catalogue-root-and-optional-link-navigation", "selected_page_ordinal": None}
    return {"kind": "complete-graph-preparation", "url": page["url"],
            "scope": "exact-selected-page-complete-resource-graph-preparation",
            "selected_page_ordinal": page["selected_page_ordinal"]}


def validate_operational_collector_failure_facts(
    value: Any, *, candidate: Mapping[str, Any], execution_binding: Mapping[str, Any],
    selection_amendment_sha256: str, not_before_utc: datetime,
    selected_page_h3_proof: Mapping[str, Any] | None = None,
    automated_site_screen: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Revalidate an operational observation and its exact page support bindings."""
    from .rapid_collector_failure_evidence import validate_collector_failure_facts
    support_keys = {"navigation_receipt_sha256", "selected_page_h3_receipt_sha256",
                    "automated_site_screen_receipt_sha256"}
    if not isinstance(value, Mapping) or not support_keys.issubset(value):
        raise ValueError("operational collector facts lack their explicit support bindings")
    page, screen = selected_page_h3_proof, automated_site_screen
    if (page is None) != (screen is None):
        raise ValueError("collector preparation requires both exact page H3 and automatic screen")
    raw_facts = {key: deepcopy(item) for key, item in value.items() if key not in support_keys}
    validate_collector_failure_facts(
        raw_facts, candidate=candidate, execution_binding=execution_binding,
        selection_amendment_sha256=selection_amendment_sha256, not_before_utc=not_before_utc,
        expected_action=_collector_action(candidate, page),
    )
    if unsafe_catalogue_domain_reason(candidate["domain"]) is not None:
        raise ValueError("automatic domain exclusion must precede collector work")
    expected = {
        "navigation_receipt_sha256": page["navigation_receipt_sha256"] if page else None,
        "selected_page_h3_receipt_sha256": page["receipt_sha256"] if page else None,
        "automated_site_screen_receipt_sha256": screen["receipt_sha256"] if screen else None,
    }
    if any(value[key] != digest for key, digest in expected.items()):
        raise ValueError("collector observation changed its exact page support bindings")
    if page is not None and (screen["selected_page_h3_receipt_sha256"] != page["receipt_sha256"]
                            or screen["navigation_receipt_sha256"] != page["navigation_receipt_sha256"]
                            or screen["selected_page_url"] != page["url"]
                            or screen["selected_page_ordinal"] != page["selected_page_ordinal"]):
        raise ValueError("collector preparation screen differs from its exact selected page")
    return deepcopy(dict(value))


def _collector_supports(context: AdmissionContext, candidate_id: str, refs: Any) -> tuple[Any, Any]:
    if not isinstance(refs, Mapping):
        raise ValueError("collector input inventory is invalid")
    if not refs:
        return None, None
    if set(refs) != {"navigation", "page_h3", "automated_screen"}:
        raise ValueError("collector preparation lacks exact navigation, page and screen inputs")
    page = _page_facts(context, candidate_id, *(_child(context.root, refs[key]) for key in ("navigation", "page_h3")))
    screen = verify_automated_site_screen(_child(context.root, refs["automated_screen"]), context, candidate_id=candidate_id)
    return page, screen


def retain_operational_collector_failure(
    output: Path, context: AdmissionContext, *, candidate_id: str, error: Exception,
    action_kind: str, started_at: str, runtime: Mapping[str, Any],
    navigation: Path | None = None, page_h3: Path | None = None, automated_screen: Path | None = None,
) -> Path:
    """Retain one actual collector limitation; only an explicit seal advances search."""
    from .rapid_collector_failure_evidence import is_collector_failure, retain_collector_failure
    context.collector_not_before_utc
    if not is_collector_failure(error):
        raise ValueError("exception is not the prospectively allowed exact collector failure")
    inputs = {key: import_evidence(context.root, path) for key, path in {
        "navigation": navigation, "page_h3": page_h3, "automated_screen": automated_screen,
    }.items() if path is not None}
    page, _screen = _collector_supports(context, candidate_id, inputs)
    action = _collector_action(context.candidate(candidate_id), page)
    if action["kind"] != action_kind:
        raise ValueError("collector failure action differs from its retained proof inputs")
    output = Path(output)
    durable_create(output.with_name("collector-inputs.json"), _json({
        "candidate_id": candidate_id, "provenance_sha256": context.provenance_sha256,
        "action": action, "inputs": inputs,
    }))
    observation = output.with_name("collector-observation.json")
    retain_collector_failure(
        observation, error=error, profile_receipt=_load(context.profile_bytes),
        source_bytes=context.source_bytes, catalogue_bytes=context.catalogue_bytes,
        candidate_id=candidate_id, execution_binding=context.execution_binding,
        selection_amendment_sha256=context.selection_amendment_sha256,
        expected_implementation_hashes=context.mounted_module_hashes[COLLECTOR_GROUP],
        not_before_utc=context.collector_not_before_utc, started_at=started_at, runtime=runtime,
        action=action, attempt_root=output.parent,
    )
    durable_create(output, _json(_bind(COLLECTOR_FAILURE_TYPE, {
        "candidate_id": candidate_id, "provenance_sha256": context.provenance_sha256,
        "inputs": inputs, "collector_observation": evidence_reference(context.root, observation),
        "completed_at": _now(), "scientific_credit": False,
    })))
    operational_collector_failure_facts(output, context, candidate_id)
    return output


def operational_collector_failure_facts(path: Path, context: AdmissionContext, candidate_id: str) -> dict[str, Any]:
    """Reopen all actual raw/source files and supporting exact page evidence."""
    from .rapid_collector_failure_evidence import verify_collector_failure
    barrier = context.collector_not_before_utc
    value = _unpack(_read(path), COLLECTOR_FAILURE_TYPE)
    if (set(value) != {"candidate_id", "provenance_sha256", "inputs", "collector_observation",
                       "completed_at", "scientific_credit"}
        or value["candidate_id"] != candidate_id or value["provenance_sha256"] != context.provenance_sha256
        or value["scientific_credit"] is not False):
        raise ValueError("collector wrapper changed its independent acquisition binding")
    candidate = context.candidate(candidate_id)
    page, screen = _collector_supports(context, candidate_id, value["inputs"])
    facts = verify_collector_failure(
        _child(context.root, value["collector_observation"]), profile_receipt=_load(context.profile_bytes),
        source_bytes=context.source_bytes, catalogue_bytes=context.catalogue_bytes,
        candidate_id=candidate_id, execution_binding=context.execution_binding,
        selection_amendment_sha256=context.selection_amendment_sha256,
        expected_implementation_hashes=context.mounted_module_hashes[COLLECTOR_GROUP],
        not_before_utc=barrier, expected_action=_collector_action(candidate, page),
    )
    if (_json(facts["runtime_source"]) != _json(context.expected_runtime_source)
        or not _utc(facts["completed_at"]) <= _utc(value["completed_at"]) <= datetime.now(UTC)):
        raise ValueError("collector wrapper changed its actual source or completion time")
    facts.update({"navigation_receipt_sha256": page["navigation_receipt_sha256"] if page else None,
                  "selected_page_h3_receipt_sha256": page["receipt_sha256"] if page else None,
                  "automated_site_screen_receipt_sha256": screen["receipt_sha256"] if screen else None})
    return validate_operational_collector_failure_facts(
        facts, candidate=candidate, execution_binding=context.execution_binding,
        selection_amendment_sha256=context.selection_amendment_sha256, not_before_utc=barrier,
        selected_page_h3_proof=page, automated_site_screen=screen,
    )


class ObservedUnsuccessfulLiveAttempt(Exception):
    """An actual backend failure was retained; no policy meaning is inferred."""

    def __init__(self, proof: Path) -> None:
        super().__init__("source-bound live backend operation did not succeed")
        self.proof = proof


class UnsuccessfulControlledPageProbe(Exception):
    """Both controls passed but the retained exact page probe did not."""


_BLOCKING_BACKEND_TYPES = {
    "ValueError", "TypeError", "KeyError", "AssertionError", "ImportError", "ModuleNotFoundError",
    "FileExistsError", "FileNotFoundError", "PermissionError", "PreparationError",
}
_BLOCKING_BACKEND_MESSAGES = {
    "prepared-probe output root is not an owned regular directory",
    "prepared workload source/image differs from acquisition runtime",
    "prepared primary response identity is invalid",
    "preparation runtime source changed during its policy observation",
}


def _blocking_backend_node(kind: str, message: str, functions: Sequence[str]) -> bool:
    return (kind in _BLOCKING_BACKEND_TYPES or message in _BLOCKING_BACKEND_MESSAGES
            or any(name.startswith(("validate_", "_validate")) or name in {
                "source_metadata", "_regular_directory", "_new_directory", "_runtime_payload",
                "_prepared_primary_response", "_failure_capture_source", "_stamp_policy_failure",
            } for name in functions))


def blocking_backend_failure(error: Exception) -> bool:
    """Validation/configuration exceptions cannot become candidate deferrals."""
    seen = set()
    def check(value: BaseException | None) -> bool:
        if value is None or id(value) in seen:
            return False
        seen.add(id(value))
        functions = []
        trace = value.__traceback__
        while trace is not None:
            functions.append(trace.tb_frame.f_code.co_name)
            trace = trace.tb_next
        return (_blocking_backend_node(type(value).__name__, str(value), functions)
                or check(value.__cause__) or check(value.__context__))
    return check(error)


def _attempt_action(candidate: Mapping[str, Any], page: Mapping[str, Any] | None = None,
                    *, probe_page: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if probe_page is not None:
        return {"kind": "selected-page-h3-probe", "url": probe_page["url"],
                "scope": "exact-selected-page-controlled-h3-probe",
                "selected_page_ordinal": probe_page["selected_page_ordinal"]}
    return _collector_action(candidate, page)


def _attempt_supports(context: AdmissionContext, candidate_id: str, refs: Mapping[str, Any],
                      action: Mapping[str, Any]) -> tuple[Any, Any, Any]:
    if action["kind"] == "catalogue-boundary-navigation":
        if refs:
            raise ValueError("unsuccessful navigation cannot claim later page inputs")
        return None, None, None
    if action["kind"] == "complete-graph-preparation":
        page, screen = _collector_supports(context, candidate_id, refs)
        if page is None or _attempt_action(context.candidate(candidate_id), page) != action:
            raise ValueError("unsuccessful preparation changed its exact selected page")
        return page, screen, None
    if action["kind"] != "selected-page-h3-probe" or set(refs) != {"navigation", "controlled_probe"}:
        raise ValueError("unsuccessful attempt support scope is unregistered")
    from .rapid_page_evidence import verify_navigation_receipt, _probe_class
    navigation = verify_navigation_receipt(
        _child(context.root, refs["navigation"]), profile_receipt=_load(context.profile_bytes),
        source_bytes=context.source_bytes, catalogue_bytes=context.catalogue_bytes,
        candidate_id=candidate_id, execution_binding=context.execution_binding,
        expected_implementation_hashes=context.mounted_module_hashes["navigation"],
        not_before_utc=context.not_before_utc,
    )
    ordinal = action["selected_page_ordinal"]
    if type(ordinal) is not int or not 0 <= ordinal < len(navigation["pages"]):
        raise ValueError("unsuccessful exact page probe ordinal is invalid")
    selected = navigation["pages"][ordinal]
    if _attempt_action(context.candidate(candidate_id), probe_page={
        "url": selected.url, "selected_page_ordinal": ordinal}) != action:
        raise ValueError("unsuccessful exact page differs from deterministic navigation")
    raw = _load(_read(_child(context.root, refs["controlled_probe"])))
    if set(raw) != {"started_at", "completed_at", "control_before", "exact_page_probe", "control_after"}:
        raise ValueError("unsuccessful exact page lacks its raw controlled observation")
    from .rapid_page_evidence import _freshness
    start, end = _freshness(raw["started_at"], raw["completed_at"], context.attempt_not_before_utc)
    _validate_controlled_unsuccessful_probe(raw, action["url"], start, end)
    proof = {"receipt_sha256": refs["controlled_probe"]["sha256"],
             "navigation_receipt_sha256": navigation["navigation_receipt_sha256"],
             "selected_page_url": selected.url, "selected_page_ordinal": ordinal, "raw_probe": raw}
    return None, None, proof


def _validate_controlled_unsuccessful_probe(raw: Mapping[str, Any], url: str,
                                           start: datetime, end: datetime) -> None:
    from .rapid_page_evidence import _probe_class
    control = profile.V5_TRIAGE_POLICY["control_url"]
    before = _probe_class(raw["control_before"], control, start, end)
    after = _probe_class(raw["control_after"], control, start, end)
    selected = _probe_class(raw["exact_page_probe"], url, start, end) if raw["exact_page_probe"] is not None else None
    if before[0] != "known-valid" or after[0] != "known-valid":
        raise ValueError("unsuccessful exact page controls did not pass")
    if selected is not None and selected[0] == "known-valid":
        raise ValueError("unsuccessful exact page proof actually passed")
    if raw["exact_page_probe"] is None:
        ordered = _utc(raw["control_before"]["completed_at"]) <= _utc(raw["control_after"]["started_at"])
    else:
        ordered = (_utc(raw["control_before"]["completed_at"]) <= _utc(raw["exact_page_probe"]["started_at"])
                   <= _utc(raw["exact_page_probe"]["completed_at"]) <= _utc(raw["control_after"]["started_at"]))
    if not ordered:
        raise ValueError("unsuccessful page probe raw control order differs")


def validate_unsuccessful_attempt_failure_facts(
    value: Any, *, candidate: Mapping[str, Any], execution_binding: Mapping[str, Any],
    selection_amendment_sha256: str, not_before_utc: datetime,
    selected_page_h3_proof: Mapping[str, Any] | None = None,
    automated_site_screen: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    from .rapid_attempt_failure_evidence import validate_attempt_failure_facts
    extras = {"profile_sha256", "selection_amendment_sha256", "candidate", "navigation_receipt_sha256",
              "selected_page_h3_receipt_sha256", "automated_site_screen_receipt_sha256", "controlled_page_probe"}
    if (not isinstance(value, Mapping) or not extras.issubset(value)
        or value["profile_sha256"] != profile.FROZEN_V5_PROFILE_SHA256
        or value["selection_amendment_sha256"] != selection_amendment_sha256
        or _json(value["candidate"]) != _json(candidate)
        or unsafe_catalogue_domain_reason(candidate["domain"]) is not None):
        raise ValueError("unsuccessful attempt changed its candidate or prospective policy")
    raw = {key: deepcopy(item) for key, item in value.items() if key not in extras}
    action, page, screen = raw["action"], selected_page_h3_proof, automated_site_screen
    controlled = value["controlled_page_probe"]
    if action["kind"] == "selected-page-h3-probe":
        if (page is not None or screen is not None or not isinstance(controlled, Mapping)
            or set(controlled) != {"receipt_sha256", "navigation_receipt_sha256", "selected_page_url",
                                   "selected_page_ordinal", "raw_probe"}
            or action != _attempt_action(candidate, probe_page={"url": controlled["selected_page_url"],
                "selected_page_ordinal": controlled["selected_page_ordinal"]})
            or profile.canonical_query_free_html_url(action["url"], registrable_domain=candidate["domain"]) != action["url"]):
            raise ValueError("unsuccessful page probe lacks its exact raw controlled input")
        probe = controlled["raw_probe"]
        if (controlled["receipt_sha256"] != _sha(_json(probe))
            or not isinstance(controlled["navigation_receipt_sha256"], str)
            or SHA_RE.fullmatch(controlled["navigation_receipt_sha256"]) is None):
            raise ValueError("unsuccessful page raw probe/navigation bytes differ from their bindings")
        from .rapid_page_evidence import _freshness
        start, end = _freshness(probe["started_at"], probe["completed_at"], not_before_utc)
        _validate_controlled_unsuccessful_probe(probe, action["url"], start, end)
        expected = (controlled["navigation_receipt_sha256"], None, None)
    else:
        if controlled is not None or (page is None) != (screen is None) or action != _attempt_action(candidate, page):
            raise ValueError("unsuccessful attempt action differs from its exact page support")
        expected = (page["navigation_receipt_sha256"] if page else None,
                    page["receipt_sha256"] if page else None, screen["receipt_sha256"] if screen else None)
        if page is not None and (screen["selected_page_h3_receipt_sha256"] != page["receipt_sha256"]
            or screen["navigation_receipt_sha256"] != page["navigation_receipt_sha256"]
            or screen["selected_page_url"] != page["url"]
            or screen["selected_page_ordinal"] != page["selected_page_ordinal"]):
            raise ValueError("unsuccessful preparation automatic screen differs from its exact page")
    if tuple(value[key] for key in ("navigation_receipt_sha256", "selected_page_h3_receipt_sha256",
                                    "automated_site_screen_receipt_sha256")) != expected:
        raise ValueError("unsuccessful attempt changed its navigation/page/screen bindings")
    validate_attempt_failure_facts(raw, execution_binding=execution_binding,
                                  not_before_utc=not_before_utc, expected_action=action)
    def blocked(node: Mapping[str, Any] | None) -> bool:
        return node is not None and (
            _blocking_backend_node(node["exception_type"], node["message"],
                                   [frame["function"] for frame in node["frames"]])
            or blocked(node["cause"]) or blocked(node["context"]))
    if blocked(raw["raw_failure"]["exception"]):
        raise ValueError("retained validation/configuration error has no attempt deferral authority")
    return deepcopy(dict(value))


def retain_unsuccessful_attempt_failure(
    output: Path, context: AdmissionContext, *, candidate_id: str, error: Exception,
    action: Mapping[str, Any], started_at: str, runtime: Mapping[str, Any],
    inputs: Mapping[str, Path] | None = None,
) -> Path:
    from .rapid_attempt_failure_evidence import retain_attempt_failure
    context.attempt_not_before_utc
    if blocking_backend_failure(error):
        raise ValueError("validation/configuration errors cannot become unsuccessful attempt deferrals")
    refs = {key: import_evidence(context.root, path) for key, path in (inputs or {}).items()}
    _attempt_supports(context, candidate_id, refs, action)
    output = Path(output)
    durable_create(output.with_name("attempt-inputs.json"), _json({
        "candidate_id": candidate_id, "provenance_sha256": context.provenance_sha256,
        "action": action, "inputs": refs,
    }))
    observation = output.with_name("attempt-observation.json")
    retain_attempt_failure(observation, error=error, action=action, started_at=started_at,
        runtime=runtime, execution_binding=context.execution_binding,
        expected_implementation_hashes=context.mounted_module_hashes[ATTEMPT_GROUP],
        not_before_utc=context.attempt_not_before_utc, attempt_root=output.parent)
    durable_create(output, _json(_bind(ATTEMPT_FAILURE_TYPE, {
        "candidate_id": candidate_id, "provenance_sha256": context.provenance_sha256,
        "selection_amendment_sha256": context.selection_amendment_sha256,
        "action": action, "inputs": refs, "attempt_observation": evidence_reference(context.root, observation),
        "completed_at": _now(), "scientific_credit": False,
    })))
    unsuccessful_attempt_failure_facts(output, context, candidate_id)
    return output


def unsuccessful_attempt_failure_facts(path: Path, context: AdmissionContext, candidate_id: str) -> dict[str, Any]:
    from .rapid_attempt_failure_evidence import verify_attempt_failure
    value = _unpack(_read(path), ATTEMPT_FAILURE_TYPE)
    if (set(value) != {"candidate_id", "provenance_sha256", "selection_amendment_sha256", "action", "inputs",
                       "attempt_observation", "completed_at", "scientific_credit"}
        or value["candidate_id"] != candidate_id or value["provenance_sha256"] != context.provenance_sha256
        or value["selection_amendment_sha256"] != context.selection_amendment_sha256
        or value["scientific_credit"] is not False):
        raise ValueError("unsuccessful attempt wrapper changed its independent context")
    page, screen, probe = _attempt_supports(context, candidate_id, value["inputs"], value["action"])
    observation = _child(context.root, value["attempt_observation"])
    facts = verify_attempt_failure(observation,
        execution_binding=context.execution_binding,
        expected_implementation_hashes=context.mounted_module_hashes[ATTEMPT_GROUP],
        not_before_utc=context.attempt_not_before_utc, expected_action=value["action"])
    retained_inputs = _load(_read(observation.with_name("attempt-inputs.json")))
    if _json(retained_inputs) != _json({
        "candidate_id": candidate_id, "provenance_sha256": context.provenance_sha256,
        "action": value["action"], "inputs": value["inputs"],
    }):
        raise ValueError("unsuccessful attempt wrapper inputs differ from the actual retained operation")
    if (_json(facts["runtime_source"]) != _json(context.expected_runtime_source)
        or not _utc(facts["completed_at"]) <= _utc(value["completed_at"]) <= datetime.now(UTC)):
        raise ValueError("unsuccessful attempt wrapper changed runtime or actual completion")
    facts.update({"profile_sha256": profile.FROZEN_V5_PROFILE_SHA256,
        "selection_amendment_sha256": context.selection_amendment_sha256,
        "candidate": context.candidate(candidate_id),
        "navigation_receipt_sha256": page["navigation_receipt_sha256"] if page else (
            probe["navigation_receipt_sha256"] if probe else None),
        "selected_page_h3_receipt_sha256": page["receipt_sha256"] if page else None,
        "automated_site_screen_receipt_sha256": screen["receipt_sha256"] if screen else None,
        "controlled_page_probe": probe})
    return validate_unsuccessful_attempt_failure_facts(facts, candidate=context.candidate(candidate_id),
        execution_binding=context.execution_binding, selection_amendment_sha256=context.selection_amendment_sha256,
        not_before_utc=context.attempt_not_before_utc, selected_page_h3_proof=page, automated_site_screen=screen)


class InsufficientPaddingCapacityError(RuntimeError):
    """A complete prepared graph cannot supply the registered padding capacity."""


def _has_response_padding_capacity(manifest: Mapping[str, Any]) -> bool:
    preparation = manifest["preparation"]
    primary = origin(preparation["final_url"])
    expected = {row["resource_id"]: row for row in preparation["expected_responses"]}
    return any(
        resource["id"] != 0
        and resource["known_valid"] is True
        and origin(resource["url"]) == primary
        and 200 <= expected[resource["id"]]["status"] < 300
        and expected[resource["id"]]["bytes"] >= 1200
        for resource in manifest["resources"]
    )


_PADDING_CAPACITY_FAILURE = "revision 6 has no stable same-origin auxiliary response of at least 1200 bytes for potential padding capacity"


class ObservedLiveBackend:
    """Observe live operations; source, input and proof errors remain blocking."""

    def __init__(self, backend: Any, context: AdmissionContext, candidate_id: str, attempt: Path,
                 action: Mapping[str, Any], inputs: Mapping[str, Path] | None = None) -> None:
        self.backend, self.context, self.candidate_id = backend, context, candidate_id
        self.attempt, self.action, self.inputs = attempt, action, inputs

    def _call(self, callback: Any, *args: Any, **kwargs: Any) -> Any:
        from .rapid_attempt_failure_evidence import begin_attempt_action
        runtime = begin_attempt_action(self.context.execution_binding,
            self.context.mounted_module_hashes[ATTEMPT_GROUP], self.context.attempt_not_before_utc)
        from .rapid_page_evidence import _validate_runtime
        if _json(_validate_runtime(runtime, self.context.execution_binding)) != _json(self.context.expected_runtime_source):
            raise ValueError("live backend runtime differs from independent context")
        started = _now()
        try:
            result = callback(*args, **kwargs)
        except Exception as error:
            if blocking_backend_failure(error):
                raise
            proof = retain_unsuccessful_attempt_failure(self.attempt / "attempt-failure.json", self.context,
                candidate_id=self.candidate_id, error=error, action=self.action,
                started_at=started, runtime=runtime, inputs=self.inputs)
            raise ObservedUnsuccessfulLiveAttempt(proof) from error
        if begin_attempt_action(self.context.execution_binding,
            self.context.mounted_module_hashes[ATTEMPT_GROUP], self.context.attempt_not_before_utc) != runtime:
            raise ValueError("live backend runtime changed after successful operation")
        return result

    def discover_navigation(self, domain: str) -> Any:
        return self._call(self.backend.discover_navigation, domain)

    def discover(self, url: str, approved: Sequence[str]) -> Any:
        return self._call(self.backend.discover, url, approved)

    def prepare(self, workload_id: str, url: str, approved: Sequence[str], output_root: Path,
                *, origin_ip_pins: Mapping[str, str], application_response_policy: str | None = None,
                primary_document_identity_policy: str | None = None) -> Any:
        from .class_acquisition import _validated_frozen_origin_ip_pins, _regular_directory
        _regular_directory(output_root.parent)
        if output_root.exists() or output_root.is_symlink():
            _regular_directory(output_root)
        _validated_frozen_origin_ip_pins(approved, origin_ip_pins)
        if application_response_policy is not None:
            from .application_response_policy import validate_application_response_policy
            validate_application_response_policy(application_response_policy)
        if application_response_policy != self.context.application_response_policy:
            raise ValueError("backend application response policy differs from prospective context")
        if primary_document_identity_policy is not None:
            from .application_response_policy import validate_primary_document_identity_policy
            validate_primary_document_identity_policy(primary_document_identity_policy)
        if primary_document_identity_policy != self.context.primary_document_identity_policy:
            raise ValueError("backend primary document identity policy differs from prospective context")
        policy_kwargs = ({"application_response_policy": application_response_policy}
                         if application_response_policy is not None else {})
        if primary_document_identity_policy is not None:
            policy_kwargs["primary_document_identity_policy"] = primary_document_identity_policy
        producer = (self._prepare_with_padding_capacity
                    if self.context.selection_amendment_revision == 6 else self.backend.prepare)
        return self._call(producer, workload_id, url, approved, output_root,
                          origin_ip_pins=origin_ip_pins, **policy_kwargs)

    def _prepare_with_padding_capacity(self, workload_id: str, url: str, approved: Sequence[str],
                                      output_root: Path, **kwargs: Any) -> Any:
        result = self.backend.prepare(workload_id, url, approved, output_root, **kwargs)
        manifest_path = Path(result.prepared.path)
        manifest = _load(_read(manifest_path))
        validate_manifest(manifest)
        validate_class_study_preparation(manifest, workload_id=workload_id,
            application_response_policy=self.context.application_response_policy,
            primary_document_identity_policy=self.context.primary_document_identity_policy)
        preparation = manifest["preparation"]
        if (preparation["source_url"] != url
            or preparation["lab_source"] != dict(self.context.expected_runtime_source)
            or preparation["prepare_image_digest"] != self.context.execution_binding["admission_image_digest"]):
            raise ValueError("prepared workload/page/source differs before its capacity screen")
        _application_response_evidence(manifest_path, manifest, self.context)
        if not _has_response_padding_capacity(manifest):
            raise InsufficientPaddingCapacityError(_PADDING_CAPACITY_FAILURE)
        return result


def _full_graph(manifest: Mapping[str, Any]) -> dict[str, Any]:
    preparation = manifest["preparation"]
    return {
        "schema_version": 1, "source_url": preparation["source_url"],
        "final_url": preparation["final_url"], "resources": manifest["resources"],
        "browser_request_headers": preparation["browser_request_headers"],
        "discovery_event_audit": preparation["discovery_event_audit"],
        "discovery_event_audit_sha256": preparation["discovery_event_audit_sha256"],
        "coverage_admission": preparation["coverage_admission"],
    }


def _application_response_evidence(
    path: Path, manifest: Mapping[str, Any], context: AdmissionContext,
) -> str | None:
    """Reopen the opt-in JSON ledgers; compact status/hash claims alone do not admit."""
    from .application_response_policy import (
        validate_application_response_policy_evidence, validate_application_responses,
        validate_primary_document_identity_evidence, primary_document_identity_policy,
        build_primary_document_identity_evidence,
    )
    from .rapid_page_evidence import _freshness
    from .prepare import (
        _failure_child_execution, _terminal_http_error_policy_evidence,
        _terminal_http_error_probe_records,
    )
    proof = validate_application_response_policy_evidence(manifest)
    variable_primary = context.primary_document_identity_policy is not None
    primary_proof = validate_primary_document_identity_evidence(manifest) if variable_primary else None
    if variable_primary and (primary_proof is None or primary_document_identity_policy(manifest) != context.primary_document_identity_policy):
        raise ValueError("primary document identity evidence differs from its prospective authority")
    if proof is None and not variable_primary:
        return None
    path = Path(path)
    root = path.parent / f"{path.stem}-application-response-evidence"
    raw_inventory = _read(root / "inventory.json")
    inventory = _load(raw_inventory)
    fields = {"schema_version", "artifact_type", "workload_id", "original_directory",
              "capture_source_before", "capture_source_after", "started_at", "completed_at",
              "policy_evidence", "files", "scientific_credit"}
    if variable_primary:
        fields |= {"primary_document_identity_policy", "primary_document_identity_evidence"}
    if (not isinstance(inventory, Mapping) or set(inventory) != fields
        or type(inventory["schema_version"]) is not int or inventory["schema_version"] != (2 if variable_primary else 1)
        or inventory["artifact_type"] != "qcsd-application-response-preparation-evidence"
        or inventory["workload_id"] != path.stem or inventory["scientific_credit"] is not False
        or _json(inventory["policy_evidence"]) != _json(proof)
        or any(_json(inventory[key]) != _json(context.expected_runtime_source)
               for key in ("capture_source_before", "capture_source_after"))
        or not isinstance(inventory["original_directory"], str)):
        raise ValueError("application response retained evidence changed its workload, policy or runtime")
    if variable_primary and (inventory["primary_document_identity_policy"] != context.primary_document_identity_policy
        or _json(inventory["primary_document_identity_evidence"]) != _json(primary_proof)):
        raise ValueError("primary document retained evidence changed its declared policy or witnesses")
    original = Path(inventory["original_directory"])
    if (not original.is_absolute() or ".." in original.parts
        or not original.name.startswith(f".{path.stem}-prepare-")):
        raise ValueError("application response child directory differs from its actual preparation identity")
    start, end = _freshness(inventory["started_at"], inventory["completed_at"], context.page_policy_not_before_utc)
    preparation = manifest["preparation"]
    count = preparation["stability_runs"]
    names = {"probe-input.json", "probe-output.json", "probe.log.execution.json",
             "probe-output.probe-head/run.json", "stability-input.json",
             *[name for index in range(count) for name in (
                 f"stability-{index}/run.json", f"stability-{index}.log.execution.json") ]}
    get_name = "probe-output.probe-get/run.json"
    if not variable_primary or proof is not None or isinstance(inventory["files"], Mapping) and get_name in inventory["files"]:
        names.add(get_name)
    if not isinstance(inventory["files"], Mapping) or set(inventory["files"]) != names:
        raise ValueError("application response retained evidence omits an actual probe or stability file")
    observed = set()
    for child in root.rglob("*"):
        if child.is_symlink():
            raise ValueError("application response retained inventory contains a symlink")
        if child.is_file():
            observed.add(child.relative_to(root).as_posix())
    if observed != {"inventory.json", *[f"artifacts/{name}" for name in names]}:
        raise ValueError("application response closed inventory changed its retained files")
    artifacts = {}
    for name in sorted(names):
        raw = _read(root / "artifacts" / name)
        record = inventory["files"][name]
        if (not isinstance(record, Mapping) or set(record) != {"sha256", "size"}
            or type(record["size"]) is not int or record != {"sha256": _sha(raw), "size": len(raw)}):
            raise ValueError("application response retained raw file bytes changed")
        artifacts[name] = raw
    discovered, resolved = (_load(artifacts[name]) for name in ("probe-input.json", "probe-output.json"))
    validate_manifest(discovered)
    validate_manifest(resolved)
    resources = manifest["resources"]
    identity = lambda rows: [{key: row[key] for key in ("id", "url", "type", "depends_on")} for row in rows]
    stability_input = _load(artifacts["stability-input.json"])
    validate_manifest(stability_input)
    if (identity(discovered["resources"]) != identity(resources)
        or identity(resolved["resources"]) != identity(resources)
        or identity(stability_input["resources"]) != identity(resources)
        or [{"resource_id": row["id"], "headers": row["headers"]} for row in discovered["resources"]]
        != preparation["browser_request_headers"]):
        raise ValueError("application response probe changed the complete discovered graph")
    if proof is not None:
        negatives = _terminal_http_error_probe_records(
            SimpleNamespace(resources=discovered["resources"]), resolved, root / "artifacts",
            execution_directory=original,
        )
        if sorted(negatives) != [row["resource_id"] for row in proof["get_responses"]]:
            raise ValueError("application response raw GET proof changed its exact negative leaves")
    probe_execution = _failure_child_execution(artifacts, "probe.log.execution.json", "probe", returncode=0)
    if not start <= _utc(probe_execution["started_at"]) <= _utc(probe_execution["completed_at"]) <= end:
        raise ValueError("application response probe lies outside its actual preparation")
    previous = _utc(probe_execution["completed_at"])
    runs = []
    for index in range(count):
        execution = _failure_child_execution(artifacts, f"stability-{index}.log.execution.json", "run", returncode=0)
        command = execution["command"]
        expected_tail = ["run", "--application-response-policy", context.application_response_policy,
                         "--workload", str(original / "stability-input.json"), "--profile", "live",
                         "--defense", "none", "--seed", "0", "--output-dir", str(original / f"stability-{index}"),
                         "--max-response-bytes", str(preparation["max_response_bytes"]),
                         "--timeout-seconds", str(preparation["timeout_seconds"])]
        if (command[command.index("run"):] != expected_tail
            or execution["configured_timeout_seconds"] != preparation["timeout_seconds"]):
            raise ValueError("application response stability child changed the prospective runtime arguments")
        child_start, child_end = _utc(execution["started_at"]), _utc(execution["completed_at"])
        if not previous <= child_start <= child_end <= end:
            raise ValueError("application response stability executions are not fresh and ordered")
        previous = child_end
        run = _load(artifacts[f"stability-{index}/run.json"])
        validate_application_responses(manifest, run)
        run_start, run_end = run.get("started_unix_ns"), run.get("ended_unix_ns")
        if (type(run_start) is not int or type(run_end) is not int
            or run.get("time_anchor_unix_ns") != run_start
            or not child_start.timestamp() * 1e9 - 1_000 <= run_start <= run_end <= child_end.timestamp() * 1e9 + 1_000):
            raise ValueError("application response stability run timestamps differ from actual child execution")
        if (run.get("workload_hash_sha256") != _sha(artifacts["stability-input.json"])
            or any(run.get(key) != preparation[key] for key in (
                "neqo_version", "neqo_base_commit", "published_qcsd_commit", "migration_commit"))):
            raise ValueError("application response stability changed its actual input or client provenance")
        runs.append(run)
    if proof is not None and _json(_terminal_http_error_policy_evidence(root / "artifacts", resources, runs)) != _json(proof):
        raise ValueError("application response compact proof differs from independently reopened raw ledgers")
    if variable_primary:
        rederived = build_primary_document_identity_evidence(
            manifest, runs, stability_run_sha256s=[_sha(artifacts[f"stability-{index}/run.json"]) for index in range(count)],
        )
        if _json(rederived) != _json(primary_proof):
            raise ValueError("primary document compact proof differs from independently reopened raw ledgers")
    return _sha(raw_inventory)


def verify_prepared_workload(
    path: Path, graph: Path, context: AdmissionContext, *, selected_page_url: str,
) -> dict[str, Any]:
    raw, graph_raw = _read(path), _read(graph)
    manifest = _load(raw)
    policy_evidence_sha = (_application_response_evidence(path, manifest, context)
                           if context.application_response_policy is not None else None)
    cache_key = (_sha(raw), _sha(graph_raw), selected_page_url, _sha(_json(context.expected_runtime_source)),
                 context.application_response_policy, context.primary_document_identity_policy, policy_evidence_sha)
    if cache_key in context.proof_cache["prepared"]:
        return deepcopy(context.proof_cache["prepared"][cache_key])
    validate_manifest(manifest)
    validate_class_study_preparation(manifest, workload_id=Path(path).stem,
                                     application_response_policy=context.application_response_policy,
                                     primary_document_identity_policy=context.primary_document_identity_policy)
    preparation = manifest["preparation"]
    if (preparation["source_url"] != selected_page_url
        or preparation["lab_source"] != dict(context.expected_runtime_source)
        or preparation["prepare_image_digest"] != context.execution_binding["admission_image_digest"]
        or _load(graph_raw) != _full_graph(manifest)):
        raise ValueError("prepared workload/page/source or its complete resource graph differs")
    resources = manifest["resources"]
    primary = origin(preparation["final_url"])
    if context.selection_amendment_revision == 6:
        # Variable primary HTML cannot supply an exact-identity padding body.
        # This screens potential capacity; sustained chaff qualification remains separate.
        if not _has_response_padding_capacity(manifest):
            raise ValueError(_PADDING_CAPACITY_FAILURE)
    count = sum(origin(resource["url"]) != primary for resource in resources)
    facts = {
        "selected_page_url": selected_page_url, "prepared_workload_sha256": _sha(raw),
        "cross_origin_resource_count": count, "full_resource_graph_sha256": _sha(graph_raw),
    }
    if context.application_response_policy is not None:
        from .application_response_policy import validate_application_response_graph
        policy_facts = validate_application_response_graph(manifest)
        facts.update(application_response_policy=policy_facts["policy"],
                     terminal_http_error_resource_ids=policy_facts["terminal_http_error_resource_ids"],
                     application_response_evidence_sha256=policy_evidence_sha)
    if context.primary_document_identity_policy is not None:
        facts["primary_document_identity_policy"] = context.primary_document_identity_policy
    context.proof_cache["prepared"][cache_key] = facts
    return deepcopy(facts)


def _new_attempt(context: AdmissionContext, candidate_id: str, action: str) -> Path:
    context.candidate(candidate_id)
    base = context.root / "attempts" / candidate_id
    base.mkdir(parents=True, exist_ok=True)
    numbers = []
    for path in base.iterdir():
        if path.is_symlink() or not path.is_dir() or re.fullmatch(r"attempt-[0-9]{6}", path.name) is None:
            raise ValueError("attempt inventory contains an unexpected path")
        numbers.append(int(path.name.removeprefix("attempt-")))
    next_number = max(numbers, default=0) + 1
    output = base / f"attempt-{next_number:06d}"
    output.mkdir()
    durable_create(output / "intent.json", _json({
        "candidate_id": candidate_id, "action": action, "started_at": _now(),
        "provenance_sha256": context.provenance_sha256, "scientific_credit": False,
    }))
    return output


def prepare_site(
    context: AdmissionContext, *, candidate_id: str, navigation: Path,
    page_h3: Path, human_review: Path | None = None,
    automated_screen: Path | None = None, backend: Any = None,
) -> Path:
    """Run the existing live full-graph preparer in one retained, retryable attempt."""
    page = _page_facts(context, candidate_id, navigation, page_h3)
    if context.selection_amendment_revision in {2, 3, 4, 5, 6}:
        if human_review is not None or automated_screen is None:
            raise ValueError("revision 2 preparation requires its distinct automated screen")
        screen = verify_automated_site_screen(automated_screen, context, candidate_id=candidate_id)
        if screen["selected_page_h3_receipt_sha256"] != page["receipt_sha256"]:
            raise ValueError("preparation automated screen differs from exact selected page")
        safety_path, safety_key = automated_screen, "automated_screen"
    else:
        if automated_screen is not None or human_review is None:
            raise ValueError("legacy preparation requires an explicit approved human page review")
        review = verify_human_review(human_review, context, candidate_id=candidate_id, reviewed_url=page["url"])
        if review["decision"] != profile.SITE_SAFETY_REVIEW_POLICY["admission_decision"]:
            raise ValueError("preparation requires an explicit approved human page review")
        safety_path, safety_key = human_review, "human_review"
    # The default production adapter must run inside the independently frozen image.
    if backend is None and dict(source_metadata()) != dict(context.expected_runtime_source):
        raise ValueError("preparation runtime is outside the frozen clean admission image")
    implementation_hashes = preparation_implementation_hashes(
        application_response_policy=context.application_response_policy is not None)
    if implementation_hashes != context.mounted_module_hashes["preparation"]:
        raise ValueError("preparation implementation changed since the prospective source freeze")
    attempt = _new_attempt(context, candidate_id, "prepare")
    references = {
        key: import_evidence(context.root, value)
        for key, value in {"navigation": navigation, "page_h3": page_h3, safety_key: safety_path}.items()
    }
    durable_create(attempt / "inputs.json", _json(references))
    backend = backend or ExistingAcquisitionBackend()
    if context.selection_amendment_revision in {4, 5, 6}:
        backend = ObservedLiveBackend(backend, context, candidate_id, attempt,
            _attempt_action(context.candidate(candidate_id), page),
            {"navigation": navigation, "page_h3": page_h3, "automated_screen": automated_screen})
    action_started_at = _now()
    action_runtime = None
    collector_runtime = None
    try:
        if context.selection_amendment_revision in {2, 3, 4, 5, 6}:
            action_runtime = begin_page_policy_action(context)
        if context.selection_amendment_revision == 3:
            collector_runtime = begin_operational_collector_action(context)
        approved, discovery = _converge_origins(backend, page["url"])
        durable_create(attempt / "origin-convergence.json", _json(asdict(discovery)))
        workload_id = f"rapid-v5-{candidate_id}-{attempt.name}"
        policy_kwargs = ({"application_response_policy": context.application_response_policy}
                         if context.application_response_policy is not None else {})
        if context.primary_document_identity_policy is not None:
            policy_kwargs["primary_document_identity_policy"] = context.primary_document_identity_policy
        probe = backend.prepare(workload_id, page["url"], approved, attempt / "workloads",
                                origin_ip_pins=discovery.origin_ip_pins, **policy_kwargs)
        manifest_path = Path(probe.prepared.path)
        manifest = _load(_read(manifest_path))
        validate_manifest(manifest)
        validate_class_study_preparation(manifest, workload_id=workload_id,
                                         application_response_policy=context.application_response_policy,
                                         primary_document_identity_policy=context.primary_document_identity_policy)
        graph_path = attempt / "full-resource-graph.json"
        durable_create(graph_path, _json(_full_graph(manifest)))
        facts = verify_prepared_workload(manifest_path, graph_path, context, selected_page_url=page["url"])
        if action_runtime is not None and begin_page_policy_action(context) != action_runtime:
            raise ValueError("preparation runtime changed during complete graph preparation")
        receipt = _bind(PREPARATION_TYPE, {
            "candidate_id": candidate_id, "provenance_sha256": context.provenance_sha256,
            "inputs": references, "prepared_workload": evidence_reference(context.root, manifest_path),
            "full_resource_graph": evidence_reference(context.root, graph_path),
            "origin_convergence": evidence_reference(context.root, attempt / "origin-convergence.json"),
            "implementation_hashes": implementation_hashes,
            "document_response": {
                "final_url": probe.final_url, "status": probe.status, "content_type": probe.content_type,
                "body_bytes": probe.body_bytes, "body_sha256": probe.body_sha256,
                "chromium_version": probe.chromium_version,
            },
            "completed_at": _now(), "facts": facts, "scientific_credit": False,
            **({"started_at": action_started_at} if context.application_response_policy is not None else {}),
        })
        durable_create(attempt / "preparation.json", _json(receipt))
    except Exception as error:
        if isinstance(error, ObservedUnsuccessfulLiveAttempt):
            write_checkpoint(context)
            return error.proof
        if collector_runtime is not None:
            from .rapid_collector_failure_evidence import is_collector_failure
            if is_collector_failure(error):
                try:
                    output = retain_operational_collector_failure(
                        attempt / "collector-failure.json", context, candidate_id=candidate_id, error=error,
                        action_kind="complete-graph-preparation", started_at=action_started_at, runtime=collector_runtime,
                        navigation=navigation, page_h3=page_h3, automated_screen=automated_screen,
                    )
                except Exception as validation_error:
                    durable_create(attempt / "operational-error.json", _json({
                        "candidate_id": candidate_id, "stage": "prepare-collector-proof-validation",
                        "exception_type": type(validation_error).__name__, "message": str(validation_error),
                        "completed_at": _now(), "retryable": True, "scientific_credit": False,
                        "provenance_sha256": context.provenance_sha256,
                    }))
                    write_checkpoint(context)
                    raise
                write_checkpoint(context)
                return output
        if (context.selection_amendment_revision in {2, 3} and action_runtime is not None
            and is_page_policy_failure(error, action_kind="complete-graph-preparation")):
            try:
                output = retain_page_policy_failure(
                    attempt / "page-policy-failure.json", context, candidate_id=candidate_id, error=error,
                    action_kind="complete-graph-preparation", started_at=action_started_at, runtime=action_runtime,
                    navigation=navigation, page_h3=page_h3, automated_screen=automated_screen,
                )
            except Exception as validation_error:
                durable_create(attempt / "operational-error.json", _json({
                    "candidate_id": candidate_id, "stage": "prepare-policy-proof-validation",
                    "exception_type": type(validation_error).__name__, "message": str(validation_error),
                    "completed_at": _now(), "retryable": True, "scientific_credit": False,
                    "provenance_sha256": context.provenance_sha256,
                }))
                write_checkpoint(context)
                raise
            write_checkpoint(context)
            return output
        durable_create(attempt / "operational-error.json", _json({
            "candidate_id": candidate_id, "stage": "prepare", "exception_type": type(error).__name__,
            "message": str(error), "completed_at": _now(), "retryable": True,
            "scientific_credit": False, "provenance_sha256": context.provenance_sha256,
        }))
        write_checkpoint(context)
        raise
    write_checkpoint(context)
    return attempt / "preparation.json"


def _preparation_facts(path: Path, context: AdmissionContext, candidate_id: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    value = _unpack(_read(path), PREPARATION_TYPE)
    fields = {"candidate_id", "provenance_sha256", "inputs", "prepared_workload",
                      "full_resource_graph", "origin_convergence", "implementation_hashes", "document_response",
                      "completed_at", "facts", "scientific_credit"}
    if context.application_response_policy is not None:
        fields |= {"started_at"}
    if set(value) != fields:
        raise ValueError("preparation receipt fields changed")
    safety_key = "automated_screen" if context.selection_amendment_revision in {2, 3, 4, 5, 6} else "human_review"
    if (value["candidate_id"] != candidate_id or value["provenance_sha256"] != context.provenance_sha256
        or value["scientific_credit"] is not False or _utc(value["completed_at"]) < context.not_before_utc
        or value["implementation_hashes"] != context.mounted_module_hashes["preparation"]
        or not isinstance(value["inputs"], Mapping)
        or set(value["inputs"]) != {"navigation", "page_h3", safety_key}):
        raise ValueError("preparation receipt belongs to another candidate or source")
    if context.application_response_policy is not None:
        from .rapid_page_evidence import _freshness
        _freshness(value["started_at"], value["completed_at"], context.page_policy_not_before_utc)
    navigation, page_h3, review_path = (
        _child(context.root, value["inputs"][key]) for key in ("navigation", "page_h3", safety_key)
    )
    page = _page_facts(context, candidate_id, navigation, page_h3)
    if context.selection_amendment_revision in {2, 3, 4, 5, 6}:
        review = verify_automated_site_screen(review_path, context, candidate_id=candidate_id)
        if review["selected_page_h3_receipt_sha256"] != page["receipt_sha256"]:
            raise ValueError("prepared page automated screen differs from exact page")
        if not _utc(review["screened_at"]) <= _utc(value["completed_at"]) <= datetime.now(UTC):
            raise ValueError("preparation predates its automated screen or lies in the future")
    else:
        review = verify_human_review(review_path, context, candidate_id=candidate_id, reviewed_url=page["url"])
        if review["decision"] != profile.SITE_SAFETY_REVIEW_POLICY["admission_decision"]:
            raise ValueError("prepared page lacks an approved human review")
    convergence = _load(_read(_child(context.root, value["origin_convergence"])))
    if not isinstance(convergence, Mapping) or convergence.get("source_url") != page["url"]:
        raise ValueError("origin convergence belongs to another selected page")
    workload = _child(context.root, value["prepared_workload"])
    facts = verify_prepared_workload(
        workload, _child(context.root, value["full_resource_graph"]), context, selected_page_url=page["url"]
    )
    manifest = _load(_read(workload))
    candidate = context.candidate(candidate_id)
    final_url = manifest["preparation"]["final_url"]
    if profile.canonical_query_free_html_url(final_url, registrable_domain=candidate["domain"]) != final_url:
        raise ValueError("prepared final document left the frozen canonical candidate page boundary")
    expected_response = _prepared_primary_response(manifest)
    document_response = value["document_response"]
    if (not isinstance(document_response, Mapping) or set(document_response) != {
        "final_url", "status", "content_type", "body_bytes", "body_sha256", "chromium_version"
    } or document_response["final_url"] != manifest["preparation"]["final_url"]
        or document_response["content_type"] not in {"text/html", "application/xhtml+xml"}
        or type(document_response["status"]) is not int or document_response["status"] != expected_response["status"]
        or type(document_response["body_bytes"]) is not int or document_response["body_bytes"] < 1
        or document_response["body_bytes"] != expected_response["bytes"]
        or document_response["body_sha256"] != expected_response["body_sha256"]
        or document_response["chromium_version"] != manifest["preparation"]["chromium_version"]):
        raise ValueError("browser primary document differs from the complete prepared page identity")
    if (convergence.get("origin_ip_pins") != manifest["preparation"]["origin_ip_pins"]
        or convergence.get("expandable_origins") != manifest["preparation"]["approved_origins"]):
        raise ValueError("preparation changed the converged full origin boundary or pins")
    if value["facts"] != facts:
        raise ValueError("preparation summary differs from independently reopened workload")
    return facts, page, review


def browser_policy_failure_facts(path: Path, context: AdmissionContext, candidate_id: str) -> dict[str, Any]:
    """Reopen only the prospectively authorized typed navigation policy proof."""
    if context.selection_amendment_bytes is None:
        raise ValueError("browser policy deferral requires a prospective selection amendment")
    from .rapid_browser_policy_evidence import verify_browser_policy_failure
    barrier = context.browser_policy_not_before_utc
    raw = _read(path)
    cache_key = (
        _sha(raw), candidate_id, context.selection_amendment_sha256,
        _sha(_json(context.mounted_module_hashes[BROWSER_POLICY_GROUP])),
        _sha(_json(context.execution_binding)), _sha(_json(context.expected_runtime_source)), barrier.isoformat(),
    )
    cached = context.proof_cache["browser_policy"].get(cache_key)
    if cached is None:
        cached = verify_browser_policy_failure(
            path, profile_receipt=_load(context.profile_bytes), source_bytes=context.source_bytes,
            catalogue_bytes=context.catalogue_bytes, candidate_id=candidate_id,
            execution_binding=context.execution_binding,
            policy_amendment_sha256=context.selection_amendment_sha256,
            expected_implementation_hashes=context.mounted_module_hashes[BROWSER_POLICY_GROUP],
            not_before_utc=barrier,
        )
        context.proof_cache["browser_policy"][cache_key] = cached
    if cached["runtime_source"] != dict(context.expected_runtime_source):
        raise ValueError("browser policy runtime differs from independent admission source")
    return deepcopy(cached)


def _root_allows_policy_progression(context: AdmissionContext, screen: Mapping[str, Any]) -> bool:
    if context.selection_amendment_revision not in {3, 4, 5, 6}:
        return screen["outcome"] == "known-valid"
    from .rapid_selection_amendment import root_screen_allows_browser_progression
    return root_screen_allows_browser_progression(screen, revision=context.selection_amendment_revision)


def _terminal_facts(value: Mapping[str, Any], context: AdmissionContext) -> dict[str, Any]:
    fields = {"candidate_id", "provenance_sha256", "root_surveys", "human_review",
              "reviewed_url", "preparation", "defer_root", "facts", "completed_at", "scientific_credit"}
    revision_two = context.selection_amendment_revision in {2, 3, 4, 5, 6}
    revision_three = context.selection_amendment_revision in {3, 4, 5, 6}
    revision_four = context.selection_amendment_revision in {4, 5, 6}
    if revision_two:
        fields |= {"automated_screen"}
    valid_fields = (fields, fields | {"browser_policy_failure"}, fields | {"page_policy_failure"}) if revision_two else (
        fields, fields | {"browser_policy_failure"},
    )
    if revision_three:
        valid_fields += (fields | {"collector_failure"},)
    if revision_four:
        valid_fields += (fields | {"attempt_failure"},)
    if set(value) not in valid_fields:
        raise ValueError("site terminal fields changed")
    candidate = context.candidate(value["candidate_id"])
    if (value["provenance_sha256"] != context.provenance_sha256 or value["scientific_credit"] is not False
        or _utc(value["completed_at"]) < context.not_before_utc or type(value["defer_root"]) is not bool):
        raise ValueError("site terminal belongs to another prospective acquisition")
    automatic = unsafe_catalogue_domain_reason(candidate["domain"])
    screen = review = page = admission = automatic_screen = page_failure = collector_failure = None
    triage = None
    browser_failure = None
    browser_reference = value.get("browser_policy_failure")
    page_failure_reference = value.get("page_policy_failure")
    collector_reference = value.get("collector_failure")
    attempt_reference = value.get("attempt_failure")
    attempt_failure = None
    auto_reference = value.get("automated_screen")
    if revision_two and (value["human_review"] is not None or value["reviewed_url"] is not None):
        raise ValueError("revision 2 terminal must retain automated screen separately from human review")
    if "page_policy_failure" in value and page_failure_reference is None:
        raise ValueError("typed page policy terminal lacks its exact failure proof")
    if "browser_policy_failure" in value and browser_reference is None:
        raise ValueError("browser policy terminal lacks its exact retained failure proof")
    if "collector_failure" in value and collector_reference is None:
        raise ValueError("collector terminal lacks its exact fresh operational proof")
    if "attempt_failure" in value and attempt_reference is None:
        raise ValueError("unsuccessful attempt terminal lacks its fresh observation")
    if browser_reference is not None and context.selection_amendment_bytes is None:
        raise ValueError("browser policy deferral requires a prospective selection amendment")
    if automatic is not None:
        if (browser_reference is not None or page_failure_reference is not None or collector_reference is not None
            or attempt_reference is not None
            or auto_reference is not None
            or value["root_surveys"] or any(value[key] is not None for key in ("human_review", "reviewed_url", "preparation"))):
            raise ValueError("automatic safety exclusion must precede live page work")
        outcome = "screen-deferred"
        triage = {"policy": profile.V5_TRIAGE_POLICY["policy"], "reason": "automatic-safety-exclusion",
                  "safety_reason": automatic}
    else:
        decision = verify_root_screen(context, candidate["candidate_id"], value["root_surveys"])
        screen = decision["root_screen"]
        if screen is None:
            raise ValueError("safe candidate lacks a controlled root decision")
        if value["human_review"] is not None:
            review = verify_human_review(_child(context.root, value["human_review"]), context,
                                         candidate_id=candidate["candidate_id"], reviewed_url=value["reviewed_url"])
        elif value["reviewed_url"] is not None:
            raise ValueError("review URL lacks its explicit human receipt")
        if attempt_reference is not None:
            if (not revision_four or not _root_allows_policy_progression(context, screen)
                or value["preparation"] is not None or review is not None or value["defer_root"]):
                raise ValueError("unsuccessful attempt lacks its independently controlled search context")
            failure_path = _child(context.root, attempt_reference)
            attempt_failure = unsuccessful_attempt_failure_facts(failure_path, context, candidate["candidate_id"])
            wrapper = _unpack(_read(failure_path), ATTEMPT_FAILURE_TYPE)
            if attempt_failure["action"]["kind"] == "complete-graph-preparation":
                if auto_reference is None:
                    raise ValueError("unsuccessful preparation terminal lacks its separate automatic screen")
                automatic_screen = verify_automated_site_screen(_child(context.root, auto_reference), context,
                    candidate_id=candidate["candidate_id"])
                page = _page_facts(context, candidate["candidate_id"], *(
                    _child(context.root, wrapper["inputs"][key]) for key in ("navigation", "page_h3")))
                if automatic_screen["receipt_sha256"] != attempt_failure["automated_site_screen_receipt_sha256"]:
                    raise ValueError("unsuccessful preparation terminal changed its automatic screen")
            elif auto_reference is not None:
                raise ValueError("unsuccessful navigation/page probe cannot claim a later safety screen")
            if not _utc(attempt_failure["completed_at"]) <= _utc(value["completed_at"]) <= datetime.now(UTC):
                raise ValueError("unsuccessful attempt terminal predates its actual observation")
            from .rapid_selection_amendment import ATTEMPT_FAILURE_DEFERRAL_POLICY, ATTEMPT_FAILURE_DEFERRAL_REASON
            outcome = ATTEMPT_FAILURE_DEFERRAL_REASON
            triage = {"policy": ATTEMPT_FAILURE_DEFERRAL_POLICY,
                      "reason": ATTEMPT_FAILURE_DEFERRAL_REASON, "safety_reason": None}
        elif browser_reference is not None:
            if (not _root_allows_policy_progression(context, screen) or value["preparation"] is not None
                or review is not None or value["defer_root"] or auto_reference is not None):
                raise ValueError("browser policy deferral must retain its controlled root and separate failure proof")
            from .rapid_selection_amendment import BROWSER_POLICY_DEFERRAL_POLICY
            browser_failure = browser_policy_failure_facts(
                _child(context.root, browser_reference), context, candidate["candidate_id"]
            )
            if not _utc(browser_failure["completed_at"]) <= _utc(value["completed_at"]) <= datetime.now(UTC):
                raise ValueError("browser policy terminal predates its proof or lies in the future")
            outcome = "screen-deferred"
            triage = {"policy": BROWSER_POLICY_DEFERRAL_POLICY,
                      "reason": "browser-navigation-policy-deferred", "safety_reason": None}
        elif collector_reference is not None:
            if (not revision_three or not _root_allows_policy_progression(context, screen) or value["preparation"] is not None
                or review is not None or value["defer_root"]):
                raise ValueError("collector deferral lacks its controlled root and separate fresh proof")
            from .rapid_selection_amendment import OPERATIONAL_COLLECTOR_DEFERRAL_POLICY, OPERATIONAL_COLLECTOR_DEFERRAL_REASON
            failure_path = _child(context.root, collector_reference)
            collector_failure = operational_collector_failure_facts(failure_path, context, candidate["candidate_id"])
            wrapper = _unpack(_read(failure_path), COLLECTOR_FAILURE_TYPE)
            if collector_failure["action"]["kind"] == "complete-graph-preparation":
                if auto_reference is None:
                    raise ValueError("collector preparation terminal lacks its separate automatic screen")
                automatic_screen = verify_automated_site_screen(
                    _child(context.root, auto_reference), context, candidate_id=candidate["candidate_id"])
                page = _page_facts(context, candidate["candidate_id"], *(
                    _child(context.root, wrapper["inputs"][key]) for key in ("navigation", "page_h3")))
                if automatic_screen["receipt_sha256"] != collector_failure["automated_site_screen_receipt_sha256"]:
                    raise ValueError("collector terminal screen differs from its actual failure inputs")
            elif auto_reference is not None:
                raise ValueError("collector navigation failure cannot claim a later page screen")
            if not _utc(collector_failure["completed_at"]) <= _utc(value["completed_at"]) <= datetime.now(UTC):
                raise ValueError("collector terminal predates its actual proof or lies in the future")
            outcome = OPERATIONAL_COLLECTOR_DEFERRAL_REASON
            triage = {"policy": OPERATIONAL_COLLECTOR_DEFERRAL_POLICY,
                      "reason": OPERATIONAL_COLLECTOR_DEFERRAL_REASON, "safety_reason": None}
        elif page_failure_reference is not None:
            if (not revision_two or not _root_allows_policy_progression(context, screen) or value["preparation"] is not None
                or review is not None or value["defer_root"]):
                raise ValueError("typed page-policy terminal lacks its controlled root and separate failure proof")
            from .rapid_selection_amendment import PAGE_POLICY_DEFERRAL_POLICY, PAGE_POLICY_DEFERRAL_REASON
            failure_path = _child(context.root, page_failure_reference)
            page_failure = page_policy_failure_facts(failure_path, context, candidate["candidate_id"])
            failure_value = _unpack(_read(failure_path), PAGE_POLICY_FAILURE_TYPE)
            if page_failure["action"]["kind"] == "complete-graph-preparation":
                if auto_reference is None:
                    raise ValueError("typed preparation terminal lacks its distinct automated screen")
                automatic_screen = verify_automated_site_screen(
                    _child(context.root, auto_reference), context, candidate_id=candidate["candidate_id"])
                refs = failure_value["inputs"]
                page = _page_facts(context, candidate["candidate_id"], *(
                    _child(context.root, refs[key]) for key in ("navigation", "page_h3")))
                if automatic_screen["receipt_sha256"] != page_failure["automated_site_screen_receipt_sha256"]:
                    raise ValueError("typed preparation terminal screen differs from failure proof")
            elif auto_reference is not None:
                raise ValueError("navigation policy terminal cannot claim a later automated page screen")
            if not _utc(page_failure["completed_at"]) <= _utc(value["completed_at"]) <= datetime.now(UTC):
                raise ValueError("typed page-policy terminal predates its proof or lies in the future")
            outcome = PAGE_POLICY_DEFERRAL_REASON
            triage = {"policy": PAGE_POLICY_DEFERRAL_POLICY, "reason": PAGE_POLICY_DEFERRAL_REASON, "safety_reason": None}
        elif review is not None and review["decision"] == profile.SITE_SAFETY_REVIEW_POLICY["exclusion_decision"]:
            if value["preparation"] is not None:
                raise ValueError("manually excluded page cannot carry preparation")
            outcome = "screen-deferred"
            triage = {"policy": profile.V5_TRIAGE_POLICY["policy"], "reason": "manual-safety-exclusion",
                      "safety_reason": review["reason"]}
        elif value["defer_root"]:
            if (value["preparation"] is not None or review is not None
                or screen["outcome"] == "known-valid" or auto_reference is not None):
                raise ValueError("root operational failure remains retryable, or this root cannot be deferred")
            outcome = "screen-deferred"
            triage = {"policy": profile.V5_TRIAGE_POLICY["policy"], "reason": (
                "operational-dns-name-not-found" if screen["detail"] == "dns-name-not-found"
                else "bounded-root-h3-no-known-valid"),
                      "safety_reason": None}
        else:
            if value["preparation"] is None or (auto_reference is None if revision_two else review is None):
                raise ValueError("candidate is pending exact-page preparation and its prospective safety screen")
            admission, page, prepared_review = _preparation_facts(
                _child(context.root, value["preparation"]), context, candidate["candidate_id"]
            )
            if revision_two:
                automatic_screen = verify_automated_site_screen(
                    _child(context.root, auto_reference), context, candidate_id=candidate["candidate_id"])
                if automatic_screen != prepared_review:
                    raise ValueError("terminal automated screen differs from prepared page")
                if not _utc(automatic_screen["screened_at"]) <= _utc(value["completed_at"]) <= datetime.now(UTC):
                    raise ValueError("terminal predates its automated screen or lies in the future")
            elif review != prepared_review or value["reviewed_url"] != page["url"]:
                raise ValueError("terminal human review differs from prepared page")
            admission = {**admission, "h3_proof_sha256": page["receipt_sha256"]}
            outcome = "admitted" if admission["cross_origin_resource_count"] >= 1 else "ineligible"
            if outcome == "ineligible":
                admission = None
    facts = {
        "candidate_id": candidate["candidate_id"], "domain": candidate["domain"],
        "source_kind": candidate["source_kind"], "outcome": outcome, "admission": admission,
        "execution_binding": dict(context.execution_binding), "root_screen": screen,
        "site_safety_review": review, "selected_page_h3_proof": page,
        **({"triage": triage} if triage is not None else {}),
        **({"browser_policy_failure": browser_failure} if browser_failure is not None else {}),
        **({"automated_site_screen": automatic_screen} if revision_two else {}),
        **({"page_policy_failure": page_failure} if page_failure is not None else {}),
        **({"operational_collector_failure": collector_failure} if collector_failure is not None else {}),
        **({"unsuccessful_attempt_failure": attempt_failure} if attempt_failure is not None else {}),
    }
    if triage is not None and browser_failure is None and page_failure is None and collector_failure is None and attempt_failure is None:
        profile._validated_v5_triage(triage, candidate, screen, review)
    if page is not None:
        profile._validated_v5_selected_page_h3_proof(page, candidate)
    return facts


def produce_site_terminal(
    context: AdmissionContext, *, candidate_id: str, root_surveys: Sequence[Path] = (),
    human_review: Path | None = None, reviewed_url: str | None = None,
    preparation: Path | None = None, defer_root: bool = False,
    browser_policy_failure: Path | None = None,
    automated_screen: Path | None = None, page_policy_failure: Path | None = None,
    collector_failure: Path | None = None,
    attempt_failure: Path | None = None,
) -> Path:
    if browser_policy_failure is not None and context.selection_amendment_bytes is None:
        raise ValueError("browser policy deferral requires a prospective selection amendment")
    if (automated_screen is not None or page_policy_failure is not None) and context.selection_amendment_revision not in {2, 3, 4, 5, 6}:
        raise ValueError("automated screen and typed page-policy deferral require selection amendment revision 2")
    if collector_failure is not None and context.selection_amendment_revision not in {3, 4, 5, 6}:
        raise ValueError("collector deferral requires selection amendment revision 3")
    if attempt_failure is not None and context.selection_amendment_revision not in {4, 5, 6}:
        raise ValueError("unsuccessful attempt deferral requires selection amendment revision 4")
    if sum(path is not None for path in (browser_policy_failure, page_policy_failure, collector_failure, attempt_failure)) > 1:
        raise ValueError("terminal cannot combine separate browser, page-policy and collector failures")
    attempt = _new_attempt(context, candidate_id, "seal-terminal")
    value = {
        "candidate_id": candidate_id, "provenance_sha256": context.provenance_sha256,
        "root_surveys": [import_evidence(context.root, path) for path in root_surveys],
        "human_review": import_evidence(context.root, human_review) if human_review else None,
        "reviewed_url": reviewed_url,
        "preparation": import_evidence(context.root, preparation) if preparation else None,
        "defer_root": defer_root, "facts": None, "completed_at": _now(), "scientific_credit": False,
    }
    if browser_policy_failure is not None:
        value["browser_policy_failure"] = import_evidence(context.root, browser_policy_failure)
    if context.selection_amendment_revision in {2, 3, 4, 5, 6}:
        value["automated_screen"] = import_evidence(context.root, automated_screen) if automated_screen else None
    if page_policy_failure is not None:
        value["page_policy_failure"] = import_evidence(context.root, page_policy_failure)
    if collector_failure is not None:
        value["collector_failure"] = import_evidence(context.root, collector_failure)
    if attempt_failure is not None:
        value["attempt_failure"] = import_evidence(context.root, attempt_failure)
    try:
        value["facts"] = _terminal_facts(value, context)
        output = attempt / "terminal.json"
        durable_create(output, _json(_bind(TERMINAL_TYPE, value)))
        verify_site_terminal(output, context)
    except Exception as error:
        durable_create(attempt / "operational-error.json", _json({
            "stage": "seal-terminal", "exception_type": type(error).__name__, "message": str(error),
            "retryable": True, "scientific_credit": False, "completed_at": _now(),
        }))
        write_checkpoint(context)
        raise
    write_checkpoint(context)
    return output


def verify_site_terminal(path: Path, context: AdmissionContext) -> dict[str, Any]:
    value = _unpack(_read(path), TERMINAL_TYPE)
    expected = _terminal_facts(value, context)
    if value["facts"] != expected:
        raise ValueError("terminal summary differs from reopened scientific evidence")
    return expected


def acquisition_status(context: AdmissionContext) -> dict[str, Any]:
    """Re-derive the ordered terminal prefix and disclose every retained attempt."""
    candidates = context.candidates
    known = {candidate["candidate_id"] for candidate in candidates}
    base = context.root / "attempts"
    records: dict[str, list[dict[str, Any]]] = {}
    terminals: dict[str, dict[str, Any]] = {}
    if base.exists():
        for directory in sorted(base.iterdir()):
            if directory.is_symlink() or not directory.is_dir() or directory.name not in known:
                raise ValueError("acquisition attempt inventory contains an unknown candidate")
            for attempt in sorted(directory.iterdir()):
                if attempt.is_symlink() or not attempt.is_dir() or re.fullmatch(r"attempt-[0-9]{6}", attempt.name) is None:
                    raise ValueError("acquisition attempt inventory is malformed")
                intent = _load(_read(attempt / "intent.json"))
                if intent.get("candidate_id") != directory.name or intent.get("provenance_sha256") != context.provenance_sha256:
                    raise ValueError("attempt intent differs from frozen provenance")
                terminal = attempt / "terminal.json"
                preparation = attempt / "preparation.json"
                error = attempt / "operational-error.json"
                navigation_path = attempt / "navigation.json"
                observation_path = attempt / "navigation-observation.json"
                page_path = attempt / "page-h3.json"
                human_review = attempt / "human-review.json"
                automated_screen = attempt / "automated-screen.json"
                policy_failure = attempt / "page-policy-failure.json"
                collector_failure = attempt / "collector-failure.json"
                attempt_failure = attempt / "attempt-failure.json"
                state = "interrupted-or-pending"
                if terminal.exists():
                    facts = verify_site_terminal(terminal, context)
                    if directory.name in terminals:
                        raise ValueError("candidate has repeated scientific terminal receipts")
                    terminals[directory.name] = {"reference": evidence_reference(context.root, terminal), "facts": facts}
                    state = facts["outcome"]
                    if facts.get("triage", {}).get("reason") == "operational-dns-name-not-found":
                        state = "zero-credit-operational-dns-screen-deferred"
                    elif facts.get("triage", {}).get("reason") == "browser-navigation-policy-deferred":
                        state = "zero-credit-browser-policy-screen-deferred"
                    elif facts.get("triage", {}).get("reason") == "page-policy-screen-deferred":
                        state = "zero-credit-page-policy-screen-deferred"
                    elif facts.get("triage", {}).get("reason") == "operational-collector-screen-deferred":
                        state = "zero-credit-retryable-operational-collector-screen-deferred"
                    elif facts.get("triage", {}).get("reason") == "unsuccessful-live-attempt-screen-deferred":
                        state = "zero-credit-retryable-unsuccessful-live-attempt-screen-deferred"
                elif preparation.exists():
                    _preparation_facts(preparation, context, directory.name)
                    state = "prepared-needs-terminal"
                elif error.exists():
                    error_value = _load(_read(error))
                    if error_value.get("retryable") is not True or error_value.get("scientific_credit") is not False:
                        raise ValueError("operational error has gained scientific credit")
                    state = "retryable-operational-error"
                elif attempt_failure.exists():
                    unsuccessful_attempt_failure_facts(attempt_failure, context, directory.name)
                    state = "failed-attempt-needs-explicit-terminal"
                elif collector_failure.exists():
                    operational_collector_failure_facts(collector_failure, context, directory.name)
                    state = "collector-failure-needs-explicit-terminal"
                elif policy_failure.exists():
                    page_policy_failure_facts(policy_failure, context, directory.name)
                    state = "page-policy-failure-needs-explicit-terminal"
                elif observation_path.exists():
                    from .rapid_page_evidence import NAVIGATION_RECEIPT_TYPE, verify_navigation_receipt
                    observation_type = _load(_read(observation_path)).get("receipt_type")
                    if observation_type == NAVIGATION_RECEIPT_TYPE:
                        verify_navigation_receipt(
                            observation_path, profile_receipt=_load(context.profile_bytes),
                            source_bytes=context.source_bytes, catalogue_bytes=context.catalogue_bytes,
                            candidate_id=directory.name, execution_binding=context.execution_binding,
                            expected_implementation_hashes=context.mounted_module_hashes["navigation"],
                            not_before_utc=context.not_before_utc,
                        )
                        state = "navigation-ready"
                    else:
                        browser_policy_failure_facts(observation_path, context, directory.name)
                        state = "browser-policy-failure-needs-explicit-terminal"
                elif navigation_path.exists():
                    from .rapid_page_evidence import verify_navigation_receipt
                    verify_navigation_receipt(
                        navigation_path, profile_receipt=_load(context.profile_bytes),
                        source_bytes=context.source_bytes, catalogue_bytes=context.catalogue_bytes,
                        candidate_id=directory.name, execution_binding=context.execution_binding,
                        expected_implementation_hashes=context.mounted_module_hashes["navigation"],
                        not_before_utc=context.not_before_utc,
                    )
                    state = "navigation-ready"
                elif page_path.exists():
                    inputs = _load(_read(attempt / "inputs.json"))
                    _page_facts(context, directory.name, _child(context.root, inputs["navigation"]), page_path)
                    state = "exact-page-h3-ready"
                elif human_review.exists():
                    review_payload = _unpack(_read(human_review), REVIEW_TYPE)
                    review = verify_human_review(human_review, context, candidate_id=directory.name,
                                                reviewed_url=review_payload["reviewed_url"])
                    state = "human-review-approved" if review["decision"] == "approved-public-page" else "human-review-excluded"
                elif automated_screen.exists():
                    verify_automated_site_screen(automated_screen, context, candidate_id=directory.name)
                    state = "automated-url-domain-screen-passed"
                inventory = []
                for path in sorted(attempt.rglob("*")):
                    if path.is_symlink():
                        raise ValueError("attempt inventory contains linked evidence")
                    if path.is_file():
                        inventory.append(evidence_reference(context.root, path))
                records.setdefault(directory.name, []).append({
                    "attempt": attempt.name, "state": state,
                    "intent": evidence_reference(context.root, attempt / "intent.json"),
                    "inventory": inventory,
                    **({"error": evidence_reference(context.root, error)} if error.exists() else {}),
                    **({"preparation": evidence_reference(context.root, preparation)} if preparation.exists() else {}),
                    **({"terminal": evidence_reference(context.root, terminal)} if terminal.exists() else {}),
                    **({"navigation": evidence_reference(context.root, navigation_path)} if navigation_path.exists() else {}),
                    **({"navigation_observation": evidence_reference(context.root, observation_path)} if observation_path.exists() else {}),
                    **({"page_h3": evidence_reference(context.root, page_path)} if page_path.exists() else {}),
                    **({"human_review": evidence_reference(context.root, human_review)} if human_review.exists() else {}),
                    **({"automated_screen": evidence_reference(context.root, automated_screen)} if automated_screen.exists() else {}),
                    **({"page_policy_failure": evidence_reference(context.root, policy_failure)} if policy_failure.exists() else {}),
                    **({"collector_failure": evidence_reference(context.root, collector_failure)} if collector_failure.exists() else {}),
                    **({"attempt_failure": evidence_reference(context.root, attempt_failure)} if attempt_failure.exists() else {}),
                })
    prefix = []
    for candidate in candidates:
        if candidate["candidate_id"] not in terminals:
            break
        prefix.append(terminals[candidate["candidate_id"]]["reference"])
    admitted = sum(terminal["facts"]["outcome"] == "admitted" for terminal in terminals.values())
    next_candidate = candidates[len(prefix)] if len(prefix) < len(candidates) else None
    return {
        "provenance_sha256": context.provenance_sha256, "terminal_prefix": prefix,
        "terminal_count": len(terminals), "admitted_site_count": admitted,
        "next_candidate": next_candidate, "attempts": records,
        "pending_requirement": (("root-survey-or-navigation-exact-page-h3-automated-url-domain-screen-and-full-graph-preparation"
                                  if context.selection_amendment_revision in {2, 3, 4, 5, 6} else
                                  "root-survey-or-human-review-navigation-exact-page-h3-and-full-graph-preparation") if next_candidate else None),
        "formal_accepted_trace_count": 0, "formal_trace_target": 16_000,
        "capture_authority": "none-site-acquisition-only",
        **({"selection_amendment_sha256": context.selection_amendment_sha256} if context.selection_amendment_bytes is not None else {}),
    }


def write_checkpoint(context: AdmissionContext) -> Path:
    status = acquisition_status(context)
    directory = context.root / "checkpoints"
    directory.mkdir(exist_ok=True)
    paths = sorted(directory.glob("checkpoint-*.json"))
    previous = None
    checked_references: dict[str, str] = {}
    for number, path in enumerate(paths, start=1):
        if path.name != f"checkpoint-{number:06d}.json":
            raise ValueError("checkpoint chain has gaps")
        raw = _read(path)
        value = _unpack(raw, CHECKPOINT_TYPE)
        if (value.get("sequence") != number or value.get("previous_sha256") != previous
            or value.get("status", {}).get("provenance_sha256") != context.provenance_sha256):
            raise ValueError("checkpoint chain changed")
        for records in value["status"].get("attempts", {}).values():
            for record in records:
                for reference in record.get("inventory", []):
                    # Repeated snapshots must agree, while every unique file is
                    # reopened and hashed anew during this invocation.
                    if (isinstance(reference, Mapping) and set(reference) == {"path", "sha256"}
                        and isinstance(reference["path"], str) and isinstance(reference["sha256"], str)
                        and reference["path"] in checked_references):
                        if checked_references[reference["path"]] != reference["sha256"]:
                            raise ValueError("checkpoint inventories declare conflicting evidence hashes")
                        continue
                    _child(context.root, reference)
                    checked_references[reference["path"]] = reference["sha256"]
        previous = _sha(raw)
    output = directory / f"checkpoint-{len(paths) + 1:06d}.json"
    durable_create(output, _json(_bind(CHECKPOINT_TYPE, {
        "sequence": len(paths) + 1, "previous_sha256": previous, "recorded_at": _now(), "status": status,
    })))
    return output


@contextmanager
def acquisition_lock(root: Path) -> Iterator[None]:
    """Serialize mutations of one acquisition root; locks grant no evidence."""
    path = Path(root) / ".acquisition.lock"
    if path.is_symlink():
        raise ValueError("acquisition lock is linked")
    with path.open("a") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def build_acquisition_cohort(context: AdmissionContext, generation: str) -> Path:
    """Publish first ten or fifty verified admissions with every earlier decision."""
    status = acquisition_status(context)
    if any(record["state"] == "interrupted-or-pending" for records in status["attempts"].values() for record in records):
        raise ValueError("cohort cannot hide interrupted or pending acquisition attempts")
    target = profile.V5_COHORT_CONTRACTS[generation]["class_count"]
    terminal_paths = [_child(context.root, ref) for ref in status["terminal_prefix"]]
    selected_paths, admitted = [], 0
    for path in terminal_paths:
        selected_paths.append(path)
        admitted += verify_site_terminal(path, context)["outcome"] == "admitted"
        if admitted == target:
            break
    lookup = {_sha(_read(path)): path for path in selected_paths}
    verifier = lambda digest: verify_site_terminal(lookup[digest], context)
    kwargs = dict(
        generation=generation, terminal_sha256s=[_sha(_read(path)) for path in selected_paths],
        execution_binding=context.execution_binding, deep_verify_terminal=verifier,
    )
    if context.selection_amendment_bytes is not None:
        from .rapid_selection_amendment import build_amended_cohort_receipt
        receipt = build_amended_cohort_receipt(
            _load(context.profile_bytes), context.source_bytes, context.catalogue_bytes,
            selection_amendment=_load(context.selection_amendment_bytes), **kwargs,
        )
    else:
        receipt = profile.build_v5_cohort_receipt(
            _load(context.profile_bytes), context.source_bytes, context.catalogue_bytes, **kwargs,
        )
    validate_acquisition_cohort(context, receipt, verifier)
    destination = context.root / "cohorts"
    destination.mkdir(exist_ok=True)
    output = destination / f"{generation}.json"
    if context.selection_amendment_bytes is not None:
        from .rapid_selection_amendment import write_receipt_create_only
        write_receipt_create_only(output, receipt)
    else:
        profile.write_receipt_create_only(output, receipt)
    write_checkpoint(context)
    return output


def validate_acquisition_cohort(context: AdmissionContext, receipt: Mapping[str, Any], deep_verify_terminal: Any) -> tuple[str, ...]:
    """Use exactly the selection contract independently bound by this context."""
    kwargs = dict(execution_binding=context.execution_binding, deep_verify_terminal=deep_verify_terminal)
    if context.selection_amendment_bytes is not None:
        from .rapid_selection_amendment import validate_amended_cohort_receipt
        return validate_amended_cohort_receipt(
            receipt, _load(context.profile_bytes), context.source_bytes, context.catalogue_bytes,
            selection_amendment=_load(context.selection_amendment_bytes), **kwargs,
        )
    return profile.validate_v5_cohort_receipt(
        receipt,
        _load(context.profile_bytes), context.source_bytes, context.catalogue_bytes,
        **kwargs,
    )


def qualified_capture_sites(
    context: AdmissionContext, cohort: Path, *, workload_root: Path,
    qualification_sets: Sequence[Mapping[str, Any]],
) -> tuple[Any, ...]:
    """Translate the verified cohort only after reopening each five-site qualifier."""
    from .chaff_qualification import RESPONSE_ONLY_QUALIFICATION_SCOPE, validate_named_qualification_set_manifest
    from .rapid_capture_plan import Site
    status = acquisition_status(context)
    lookup = {ref["sha256"]: _child(context.root, ref) for ref in status["terminal_prefix"]}
    receipt = _load(_read(cohort))
    selected = validate_acquisition_cohort(
        context, receipt, lambda digest: verify_site_terminal(lookup[digest], context)
    )
    by_id = {}
    for path in lookup.values():
        facts = verify_site_terminal(path, context)
        if facts["outcome"] == "admitted":
            terminal = _unpack(_read(path), TERMINAL_TYPE)
            prepared = _unpack(_read(_child(context.root, terminal["preparation"])), PREPARATION_TYPE)
            workload = _child(context.root, prepared["prepared_workload"])
            by_id[facts["candidate_id"]] = (facts, workload)
    if len(qualification_sets) * 5 != len(selected):
        raise ValueError("capture preparation needs one exact five-site qualification set per shard")
    sites = []
    for offset, qualification in enumerate(qualification_sets):
        if set(qualification) != {"qualification_set", "manifest", "sidecar_root", "prefix_spec_root"}:
            raise ValueError("qualification shard binding is malformed")
        ids = selected[offset * 5:(offset + 1) * 5]
        workload_ids = [by_id[candidate_id][1].stem for candidate_id in ids]
        for candidate_id in ids:
            _, path = by_id[candidate_id]
            destination = Path(workload_root) / f"{path.stem}.json"
            if _read(destination) != _read(path):
                raise ValueError("materialized workload differs from admitted immutable bytes")
        manifest_path = Path(qualification["manifest"])
        manifest_raw = _read(manifest_path)
        validate_named_qualification_set_manifest(
            _load(manifest_raw), workload_root=Path(workload_root),
            sidecar_root=Path(qualification["sidecar_root"]),
            prefix_spec_root=Path(qualification["prefix_spec_root"]) if qualification["prefix_spec_root"] else None,
            expected_qualification_set=qualification["qualification_set"], expected_workload_ids=workload_ids,
            expected_qualification_scope=RESPONSE_ONLY_QUALIFICATION_SCOPE,
        )
        for candidate_id, workload_id in zip(ids, workload_ids, strict=True):
            facts, path = by_id[candidate_id]
            manifest = _load(_read(path))
            sites.append(Site(candidate_id, workload_id, facts["admission"]["prepared_workload_sha256"],
                              origin(manifest["preparation"]["final_url"]), qualification["qualification_set"],
                              _sha(manifest_raw)))
    return tuple(sites)
