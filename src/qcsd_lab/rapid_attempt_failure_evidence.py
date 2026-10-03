"""Retained evidence of an unsuccessful source-bound live operation.

Observe actual backend calls and the three explicit convergence limits on
approved origins, observed origins and discovery passes after real discovery.
Save complete observed discovery passes before retaining those budget failures.
Preflight, source/schema validation and later proof verification stay outside
the failure-retention boundary. This receipt proves the caught exception and
available attempt bytes, grants no site verdict, and does not reconstruct
missing browser, DOM, CDP or transport details.
"""

from __future__ import annotations

import importlib
import os
import re
import traceback
from collections.abc import Mapping
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import rapid_page_evidence as page, rapid_study_profile as profile, util

ATTEMPT_FAILURE_RECEIPT_TYPE = "qcsd-rapid-v5-unsuccessful-backend-attempt-v1"
ATTEMPT_FAILURE_POLICY = "prospective-source-bound-unsuccessful-backend-attempt-v1"
_FLAGS = {
    "failure_scope": "unsuccessful-live-backend-attempt",
    "evidence_scope": "actual-exception-and-retained-attempt-files-only",
    "retryable": True, "whole_domain_ineligible": False, "scientific_credit": False,
    "formal_accepted_trace_count": 0, "site_credit": 0, "actual_attempt_count": 1,
}
_MODULE_NAMES = {
    "qcsd_lab.rapid_attempt_failure_evidence", "qcsd_lab.rapid_site_admission",
    "qcsd_lab.class_acquisition", "qcsd_lab.class_catalogue", "qcsd_lab.prepare",
    "qcsd_lab.manifest", "qcsd_lab.discover", "qcsd_lab.discovery_evidence",
    "qcsd_lab.acquisition_errors", "qcsd_lab.browser_egress", "qcsd_lab.cdp_targets",
    "qcsd_lab.h3_prebaseline", "qcsd_lab.rapid_page_evidence",
    "qcsd_lab.rapid_study_profile", "qcsd_lab.rapid_selection_amendment", "qcsd_lab.util",
}
_KEYS = _MODULE_NAMES | {"neqo-qcsd-client", "tools.rapid_acquire"}
APPLICATION_RESPONSE_POLICY_MODULE = "qcsd_lab.application_response_policy"
_LATER_WRAPPER = "attempt-failure.json"
_EXCEPTION_KEYS = {"exception_type", "exception_module", "message", "frames", "cause", "context", "suppress_context"}
_PAYLOAD_KEYS = {"policy", "execution_binding", "runtime", "implementation_hashes", "started_at",
                 "completed_at", "action", "artifacts", "attempt_inventory", *_FLAGS}
_FACT_KEYS = (_PAYLOAD_KEYS - {"runtime", "artifacts"}) | {
    "attempt_failure_receipt_sha256", "runtime_source", "raw_failure",
}


def implementation_sources(*, application_response_policy: bool = False) -> dict[str, Path]:
    if type(application_response_policy) is not bool:
        raise ValueError("attempt policy source inventory opt-in must be boolean")
    names = _MODULE_NAMES | ({APPLICATION_RESPONSE_POLICY_MODULE} if application_response_policy else set())
    return {**{name: Path(importlib.import_module(name).__file__) for name in sorted(names)},
            "tools.rapid_acquire": Path(__file__).parents[2] / "tools" / "rapid_acquire.py",
            "neqo-qcsd-client": Path(os.environ.get("QCSD_NEQO_CLIENT", "/usr/local/bin/neqo-qcsd-client"))}


def implementation_hashes(*, application_response_policy: bool = False) -> dict[str, str]:
    return {name: page._sha(page._regular(path).read_bytes()) for name, path in
            implementation_sources(application_response_policy=application_response_policy).items()}


def _hashes(value: Any) -> dict[str, str]:
    if (not isinstance(value, Mapping) or set(value) not in (_KEYS, _KEYS | {APPLICATION_RESPONSE_POLICY_MODULE})
        or any(not isinstance(item, str) or page._SHA.fullmatch(item) is None for item in value.values())):
        raise ValueError("attempt observer implementation/client bindings are invalid")
    return dict(value)


def _flags(value: Mapping[str, Any]) -> None:
    if any(page._json(value.get(key)) != page._json(expected) for key, expected in _FLAGS.items()):
        raise ValueError("unsuccessful attempt cannot claim scientific credit or a whole-domain verdict")


def _action(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"kind", "url", "scope", "selected_page_ordinal"}:
        raise ValueError("attempt action fields are invalid")
    from urllib.parse import urlsplit
    if not isinstance(value["url"], str):
        raise ValueError("attempt action URL is invalid")
    host = urlsplit(value["url"]).hostname
    if not host or profile.canonical_query_free_html_url(value["url"], registrable_domain=host) != value["url"]:
        raise ValueError("attempt action URL is not canonical HTTPS")
    kinds = {
        "catalogue-boundary-navigation": "catalogue-root-and-optional-link-navigation",
        "selected-page-h3-probe": "exact-selected-page-controlled-h3-probe",
        "complete-graph-preparation": "exact-selected-page-complete-resource-graph-preparation",
    }
    if value["kind"] not in kinds or value["scope"] != kinds[value["kind"]]:
        raise ValueError("attempt action is not an independently bound live backend operation")
    ordinal = value["selected_page_ordinal"]
    if value["kind"] == "catalogue-boundary-navigation":
        if ordinal is not None or value["url"] != f"https://{host}/":
            raise ValueError("navigation attempt must bind the exact catalogue root")
    elif type(ordinal) is not int or not 0 <= ordinal <= 4:
        raise ValueError("page attempt needs its exact selected-page ordinal")
    return dict(value)


def begin_attempt_action(execution_binding: Mapping[str, Any], expected_implementation_hashes: Mapping[str, str],
                         not_before_utc: datetime) -> dict[str, Any]:
    """Validate the frozen runtime before the source-bound live operation."""
    now = datetime.now(UTC).isoformat()
    page._freshness(now, now, not_before_utc)
    hashes = _hashes(expected_implementation_hashes)
    if implementation_hashes(application_response_policy=APPLICATION_RESPONSE_POLICY_MODULE in hashes) != hashes:
        raise ValueError("attempt observer source/client changed after prospective freeze")
    return page._runtime_payload(page._binding(execution_binding))


def _exception(error: BaseException, hashes: Mapping[str, str], sources: Mapping[str, Path],
               seen: set[int] | None = None) -> dict[str, Any]:
    seen = set() if seen is None else set(seen)
    if id(error) in seen or len(seen) >= 32 or error.__traceback__ is None:
        raise ValueError("attempt needs an actual raised exception with a bounded, acyclic chain")
    seen.add(id(error))
    frames = []
    current = error.__traceback__
    while current is not None:
        frame = current.tb_frame
        module = frame.f_globals.get("__name__", "<unknown>")
        digest = hashes.get(module)
        if digest is not None and Path(frame.f_code.co_filename).absolute() != sources[module].absolute():
            raise ValueError("attempt traceback uses another implementation file")
        frames.append({"module": module, "filename": frame.f_code.co_filename, "function": frame.f_code.co_name,
                       "line_number": current.tb_lineno, "source_sha256": digest})
        current = current.tb_next
    return {"exception_type": type(error).__name__, "exception_module": type(error).__module__, "message": str(error),
            "frames": frames, "suppress_context": error.__suppress_context__,
            "cause": _exception(error.__cause__, hashes, sources, seen) if error.__cause__ is not None else None,
            "context": _exception(error.__context__, hashes, sources, seen) if error.__context__ is not None else None}


def _validate_exception(value: Any, hashes: Mapping[str, str], trace: str, depth: int = 0) -> None:
    if (not isinstance(value, Mapping) or set(value) != _EXCEPTION_KEYS or depth >= 32
        or any(not isinstance(value[key], str) or not value[key] for key in ("exception_type", "exception_module"))
        or not isinstance(value["message"], str) or type(value["suppress_context"]) is not bool
        or not isinstance(value["frames"], list) or not value["frames"]):
        raise ValueError("attempt retained exception/class/chain is invalid")
    prefix = "" if value["exception_module"] in {"builtins", "__main__"} else re.escape(value["exception_module"]) + r"\."
    label = prefix + r"(?:[^\n: ]+\.)*" + re.escape(value["exception_type"])
    label += re.escape(": " + value["message"]) if value["message"] else ""
    if re.search(r"(?m)^" + label + r"(?:\n|$)", trace) is None:
        raise ValueError("attempt exception contradicts the retained actual traceback")
    for frame in value["frames"]:
        if (not isinstance(frame, Mapping) or set(frame) != {"module", "filename", "function", "line_number", "source_sha256"}
            or any(not isinstance(frame[key], str) or not frame[key] for key in ("module", "filename", "function"))
            or type(frame["line_number"]) is not int or frame["line_number"] < 1
            or frame["source_sha256"] != hashes.get(frame["module"])
            or f"File \"{frame['filename']}\", line {frame['line_number']}, in {frame['function']}" not in trace):
            raise ValueError("attempt retained traceback frame/source differs")
    for key in ("cause", "context"):
        if value[key] is not None:
            _validate_exception(value[key], hashes, trace, depth + 1)


def _raw_facts(error: Mapping[str, Any], trace: bytes, hashes: Mapping[str, str]) -> dict[str, Any]:
    text = trace.decode("utf-8")
    _validate_exception(error, hashes, text)
    return {"exception_type": error["exception_type"], "exception_module": error["exception_module"],
            "message": error["message"], "exception": deepcopy(dict(error)),
            "traceback_text": text, "traceback_sha256": page._sha(trace)}


def _directory(path: Path) -> Path:
    path = Path(path).absolute()
    if not path.is_dir() or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("attempt evidence requires an existing directory without symlinks")
    return path


def _inventory(root: Path, excluded: set[str]) -> dict[str, Any]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("attempt evidence inventory contains a symlink")
        if path.is_dir():
            continue
        name = path.relative_to(root).as_posix()
        if name in excluded:
            continue
        raw = page._regular(path).read_bytes()
        result[name] = {"sha256": page._sha(raw), "size": len(raw)}
    return result


def _reference(root: Path, path: Path) -> dict[str, str]:
    return {"path": path.relative_to(root).as_posix(), "sha256": page._sha(page._regular(path).read_bytes())}


def _artifact(root: Path, reference: Any) -> bytes:
    if (not isinstance(reference, Mapping) or set(reference) != {"path", "sha256"}
        or not isinstance(reference["path"], str) or not reference["path"] or "\\" in reference["path"]
        or Path(reference["path"]).is_absolute() or any(p in {".", ".."} for p in reference["path"].split("/"))
        or Path(reference["path"]).as_posix() != reference["path"]):
        raise ValueError("attempt artifact reference is invalid")
    raw = page._regular(root / reference["path"]).read_bytes()
    if page._sha(raw) != reference["sha256"]:
        raise ValueError("attempt retained raw/source/client artifact changed")
    return raw


def retain_attempt_failure(
    output: Path, *, error: Exception, action: Mapping[str, Any], started_at: str, runtime: Mapping[str, Any],
    execution_binding: Mapping[str, Any], expected_implementation_hashes: Mapping[str, str],
    not_before_utc: datetime, attempt_root: Path,
) -> Path:
    """Seal available bytes after a caught live operation error; never read an old log."""
    root, output = _directory(attempt_root), Path(output).absolute()
    if (output.parent != root or output.name == _LATER_WRAPPER or output.exists() or output.is_symlink()
        or (root / _LATER_WRAPPER).exists()):
        raise ValueError("attempt observation needs a new create-only destination")
    if not isinstance(error, Exception):
        raise ValueError("attempt observer requires an actual caught backend exception")
    binding, hashes, action = page._binding(execution_binding), _hashes(expected_implementation_hashes), _action(action)
    if begin_attempt_action(binding, hashes, not_before_utc) != dict(runtime):
        raise ValueError("attempt runtime source/image changed during backend execution")
    sources = implementation_sources(application_response_policy=APPLICATION_RESPONSE_POLICY_MODULE in hashes)
    raw_error = _exception(error, hashes, sources)
    parts, seen = [], set()
    def retain_trace(current):
        if current is None or id(current) in seen:
            return
        seen.add(id(current))
        parts.extend(traceback.TracebackException.from_exception(current, capture_locals=False).format(chain=False))
        retain_trace(current.__cause__)
        retain_trace(current.__context__)
    retain_trace(error)
    trace = "".join(parts).encode("utf-8")
    _raw_facts(raw_error, trace, hashes)
    evidence = root / "attempt-evidence"
    evidence.mkdir()
    util.durable_create(evidence / "exception.json", page._json(raw_error))
    util.durable_create(evidence / "traceback.txt", trace)
    source_dir = evidence / "sources"
    source_dir.mkdir()
    refs = {}
    for name, path in sources.items():
        raw = page._regular(path).read_bytes()
        if page._sha(raw) != hashes[name]:
            raise ValueError("attempt implementation/client changed while retaining evidence")
        target = source_dir / hashes[name]
        if not target.exists():
            util.durable_create(target, raw)
        elif target.read_bytes() != raw:
            raise ValueError("attempt retained source object collision")
        refs[name] = _reference(root, target)
    completed = datetime.now(UTC).isoformat()
    page._freshness(started_at, completed, not_before_utc)
    if begin_attempt_action(binding, hashes, not_before_utc) != dict(runtime):
        raise ValueError("attempt runtime source/image changed during evidence retention")
    page._create(output, {
        "policy": ATTEMPT_FAILURE_POLICY, "execution_binding": binding, "runtime": dict(runtime),
        "implementation_hashes": hashes, "started_at": started_at, "completed_at": completed, "action": action,
        "artifacts": {"exception": _reference(root, evidence / "exception.json"),
                      "traceback": _reference(root, evidence / "traceback.txt"), "sources": refs},
        "attempt_inventory": _inventory(root, {output.name, _LATER_WRAPPER}), **_FLAGS,
    }, ATTEMPT_FAILURE_RECEIPT_TYPE)
    return output


def verify_attempt_failure(
    path: Path, *, execution_binding: Mapping[str, Any], expected_implementation_hashes: Mapping[str, str],
    not_before_utc: datetime, expected_action: Mapping[str, Any],
) -> dict[str, Any]:
    """Reopen the actual exception, all saved source/client and existing files."""
    payload, digest = page._open(path, ATTEMPT_FAILURE_RECEIPT_TYPE)
    binding, hashes = page._binding(execution_binding), _hashes(expected_implementation_hashes)
    if (set(payload) != _PAYLOAD_KEYS or payload["policy"] != ATTEMPT_FAILURE_POLICY
        or payload["execution_binding"] != binding or payload["implementation_hashes"] != hashes
        or payload["action"] != _action(expected_action)):
        raise ValueError("attempt observation differs from independent frozen execution/action bindings")
    _flags(payload)
    page._freshness(payload["started_at"], payload["completed_at"], not_before_utc)
    source = page._validate_runtime(payload["runtime"], binding)
    root = _directory(path.parent)
    if page._json(_inventory(root, {path.name, _LATER_WRAPPER})) != page._json(payload["attempt_inventory"]):
        raise ValueError("attempt closed inventory changed or gained unregistered files")
    artifacts = payload["artifacts"]
    if (not isinstance(artifacts, Mapping) or set(artifacts) != {"exception", "traceback", "sources"}
        or not isinstance(artifacts["sources"], Mapping) or set(artifacts["sources"]) != set(hashes)):
        raise ValueError("attempt source/client artifact inventory is incomplete")
    if {name: page._sha(_artifact(root, ref)) for name, ref in artifacts["sources"].items()} != hashes:
        raise ValueError("attempt retained implementations/client differ from independent hashes")
    raw = _raw_facts(page._loads(_artifact(root, artifacts["exception"])), _artifact(root, artifacts["traceback"]), hashes)
    facts = {key: deepcopy(payload[key]) for key in _PAYLOAD_KEYS - {"runtime", "artifacts"}}
    facts.update(attempt_failure_receipt_sha256=digest, runtime_source=source, raw_failure=raw)
    return validate_attempt_failure_facts(facts, execution_binding=binding, not_before_utc=not_before_utc,
                                         expected_action=expected_action)


def validate_attempt_failure_facts(
    value: Any, *, execution_binding: Mapping[str, Any], not_before_utc: datetime,
    expected_action: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Check compact facts after the independent receipt-reopening callback."""
    binding = page._binding(execution_binding)
    if (not isinstance(value, Mapping) or set(value) != _FACT_KEYS or value["policy"] != ATTEMPT_FAILURE_POLICY
        or value["execution_binding"] != binding or not isinstance(value["attempt_failure_receipt_sha256"], str)
        or page._SHA.fullmatch(value["attempt_failure_receipt_sha256"]) is None):
        raise ValueError("attempt facts changed their independently verified execution binding")
    _flags(value)
    hashes, action = _hashes(value["implementation_hashes"]), _action(value["action"])
    if expected_action is not None and action != _action(expected_action):
        raise ValueError("attempt facts changed the independently verified backend action")
    page._freshness(value["started_at"], value["completed_at"], not_before_utc)
    source = value["runtime_source"]
    if (not isinstance(source, Mapping) or set(source) != util.SOURCE_METADATA_KEYS
        or source["image_digest"] != binding["admission_image_digest"]
        or source["lab_dirty"] is not False or source["neqo_dirty"] is not False
        or source["lab_patch_sha256"] != page._EMPTY_SHA or source["neqo_patch_sha256"] != page._EMPTY_SHA
        or any(not isinstance(source[key], str) or page._COMMIT.fullmatch(source[key]) is None
               for key in ("lab_commit", "neqo_commit", "neqo_pinned_commit"))
        or source["neqo_commit"] != source["neqo_pinned_commit"]):
        raise ValueError("attempt runtime is not its clean matched pinned image")
    raw = value["raw_failure"]
    if (not isinstance(raw, Mapping) or set(raw) != {"exception_type", "exception_module", "message", "exception",
                                                  "traceback_text", "traceback_sha256"}
        or not isinstance(raw["traceback_text"], str)
        or page._sha(raw["traceback_text"].encode()) != raw["traceback_sha256"]):
        raise ValueError("attempt facts lack independently reopened exception/traceback bytes")
    _validate_exception(raw["exception"], hashes, raw["traceback_text"])
    if any(raw[key] != raw["exception"][key] for key in ("exception_type", "exception_module", "message")):
        raise ValueError("attempt raw facts changed the exact actual exception identity")
    if not isinstance(value["attempt_inventory"], Mapping) or not value["attempt_inventory"]:
        raise ValueError("attempt facts lack their closed available-file inventory")
    for name, item in value["attempt_inventory"].items():
        if (not isinstance(name, str) or not name or Path(name).is_absolute() or ".." in Path(name).parts
            or not isinstance(item, Mapping) or set(item) != {"sha256", "size"}
            or type(item["size"]) is not int or item["size"] < 0 or not isinstance(item["sha256"], str)
            or page._SHA.fullmatch(item["sha256"]) is None):
            raise ValueError("attempt available-file inventory facts are invalid")
    return page._loads(page._json(value))
