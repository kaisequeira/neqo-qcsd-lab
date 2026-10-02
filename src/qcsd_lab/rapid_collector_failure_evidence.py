"""Fresh, zero-credit observations of a narrowly identified CDP collector failure.

The observer retains the actual exception, all exception-chain tracebacks and
closed attempt bytes. It cannot reconstruct CDP parameters which the collector
did not save, and cannot establish that a whole domain is unsuitable.
"""

from __future__ import annotations

import ast
import os
import traceback
from collections.abc import Mapping
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import (
    acquisition_errors, browser_egress, cdp_targets, class_acquisition,
    class_catalogue, discover, discovery_evidence, prepare,
    rapid_page_evidence as page, rapid_study_profile, util,
)

COLLECTOR_FAILURE_RECEIPT_TYPE = "qcsd-rapid-v5-operational-collector-failure-v1"
COLLECTOR_FAILURE_POLICY = "prospective-exact-cdp-event-collector-limitation-v1"
_FLAGS = {"failure_scope": "collector-limitation", "event_parameters": "unavailable-not-reconstructed",
          "retryable": True, "whole_domain_ineligible": False, "scientific_credit": False,
          "formal_accepted_trace_count": 0, "site_credit": 0, "actual_attempt_count": 1}
_MODULES = {
    "qcsd_lab.cdp_targets": cdp_targets, "qcsd_lab.discover": discover,
    "qcsd_lab.discovery_evidence": discovery_evidence, "qcsd_lab.class_acquisition": class_acquisition,
    "qcsd_lab.class_catalogue": class_catalogue, "qcsd_lab.prepare": prepare,
    "qcsd_lab.acquisition_errors": acquisition_errors, "qcsd_lab.browser_egress": browser_egress,
    "qcsd_lab.rapid_page_evidence": page, "qcsd_lab.rapid_study_profile": rapid_study_profile,
    "qcsd_lab.util": util,
}
_KEYS = {"qcsd_lab.rapid_collector_failure_evidence", "neqo-qcsd-client", *_MODULES}
_LATER_WRAPPER = "collector-failure.json"
_EXCEPTION_KEYS = {"exception_type", "exception_module", "message", "attributes", "frames",
                   "cause", "context", "suppress_context"}
_PAYLOAD_KEYS = {"policy", "profile_sha256", "selection_amendment_sha256", "candidate", "execution_binding",
                 "runtime", "implementation_hashes", "started_at", "completed_at", "action", "artifacts",
                 "attempt_inventory", *_FLAGS}


def implementation_sources() -> dict[str, Path]:
    return {"qcsd_lab.rapid_collector_failure_evidence": Path(__file__),
            **{name: Path(module.__file__) for name, module in _MODULES.items()},
            "neqo-qcsd-client": Path(os.environ.get("QCSD_NEQO_CLIENT", "/usr/local/bin/neqo-qcsd-client"))}


def implementation_hashes() -> dict[str, str]:
    return {name: page._sha(page._regular(path).read_bytes()) for name, path in implementation_sources().items()}


def _hashes(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _KEYS or any(
        not isinstance(digest, str) or page._SHA.fullmatch(digest) is None for digest in value.values()
    ):
        raise ValueError("collector implementation/class/client hashes are invalid")
    return dict(value)


def _digest(value: Any) -> str:
    if not isinstance(value, str) or page._SHA.fullmatch(value) is None:
        raise ValueError("collector amendment or artifact digest is invalid")
    return value


def _flags(value: Mapping[str, Any]) -> None:
    if any(page._json(value.get(key)) != page._json(expected) for key, expected in _FLAGS.items()):
        raise ValueError("collector observation has nonzero credit or changes its operational scope")


def _action(value: Any, candidate: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"kind", "url", "scope", "selected_page_ordinal"}:
        raise ValueError("collector action fields are invalid")
    if value["kind"] == "catalogue-boundary-navigation":
        expected = {"kind": value["kind"], "url": f"https://{candidate['domain']}/",
                    "scope": "catalogue-root-and-optional-link-navigation", "selected_page_ordinal": None}
        if dict(value) != expected:
            raise ValueError("collector navigation changed the exact catalogue root action")
    elif value["kind"] == "complete-graph-preparation":
        if (value["scope"] != "exact-selected-page-complete-resource-graph-preparation"
            or type(value["selected_page_ordinal"]) is not int or not 0 <= value["selected_page_ordinal"] <= 4
            or rapid_study_profile.canonical_query_free_html_url(value["url"], registrable_domain=candidate["domain"]) != value["url"]):
            raise ValueError("collector preparation lacks its exact canonical selected page")
    else:
        raise ValueError("collector action is not a registered navigation/preparation")
    return dict(value)


def begin_collector_action(execution_binding: Mapping[str, Any], expected_implementation_hashes: Mapping[str, str],
                           not_before_utc: datetime) -> dict[str, Any]:
    """Check the fresh bound runtime and collector before the actual operation."""
    now = datetime.now(UTC).isoformat()
    page._freshness(now, now, not_before_utc)
    if implementation_hashes() != _hashes(expected_implementation_hashes):
        raise ValueError("collector implementation or client changed after prospective freeze")
    return page._runtime_payload(page._binding(execution_binding))


def _frame_list(error: BaseException, hashes: Mapping[str, str]) -> list[dict[str, Any]]:
    result = []
    current = error.__traceback__
    while current is not None:
        frame = current.tb_frame
        module = frame.f_globals.get("__name__", "")
        source_hash = hashes.get(module)
        if source_hash is not None and Path(frame.f_code.co_filename).absolute() != implementation_sources()[module].absolute():
            raise ValueError("collector traceback uses another module source file")
        result.append({"module": module, "filename": frame.f_code.co_filename, "function": frame.f_code.co_name,
                       "line_number": current.tb_lineno, "source_sha256": source_hash})
        current = current.tb_next
    return result


def _exception(error: BaseException, hashes: Mapping[str, str], seen: set[int] | None = None) -> dict[str, Any]:
    seen = set() if seen is None else set(seen)
    if id(error) in seen or len(seen) >= 8:
        raise ValueError("collector exception chain is cyclic or exceeds its bound")
    seen.add(id(error))
    if type(error) not in {cdp_targets.CdpTargetIntegrityError, acquisition_errors.PassiveRenderPolicyError}:
        raise ValueError("collector exception chain contains another operational/global error")
    attributes = deepcopy(error.__dict__)
    page._json(attributes)
    if type(error) is acquisition_errors.PassiveRenderPolicyError:
        prepare.validate_passive_render_policy_failure_evidence(attributes.get("evidence"))
    return {"exception_type": type(error).__name__, "exception_module": type(error).__module__, "message": str(error),
            "attributes": attributes, "frames": _frame_list(error, hashes), "suppress_context": error.__suppress_context__,
            "cause": _exception(error.__cause__, hashes, seen) if error.__cause__ is not None else None,
            "context": _exception(error.__context__, hashes, seen) if error.__context__ is not None else None}


def _direct_raise(frame: Mapping[str, Any], source: bytes, message: str | None = None) -> None:
    if (frame["module"] != "qcsd_lab.cdp_targets" or not frame["function"].startswith("_handle_")
        or frame["source_sha256"] != page._sha(source)):
        raise ValueError("collector error did not originate at a frozen CDP event handler")
    tree = ast.parse(source)
    methods = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
               and node.name == frame["function"] and node.lineno <= frame["line_number"] <= node.end_lineno]
    raises = [node for method in methods for node in ast.walk(method) if isinstance(node, ast.Raise)
              and node.lineno <= frame["line_number"] <= node.end_lineno
              and isinstance(node.exc, ast.Call) and isinstance(node.exc.func, ast.Name)
              and node.exc.func.id == "CdpTargetIntegrityError"]
    if not raises:
        raise ValueError("collector traceback is not a direct exact typed CDP event raise")
    if message is not None and all(
        node.exc.args and isinstance(node.exc.args[0], ast.Constant) and isinstance(node.exc.args[0].value, str)
        and node.exc.args[0].value != message for node in raises
    ):
        raise ValueError("collector exception message contradicts its exact frozen literal raise")


def is_collector_failure(error: Exception) -> bool:
    """Exclude invented errors, subclasses, wrapped generic errors and setup failures."""
    if type(error) is not cdp_targets.CdpTargetIntegrityError or error.__traceback__ is None:
        return False
    try:
        sources = implementation_sources()
        hashes = {name: page._sha(page._regular(path).read_bytes()) for name, path in sources.items() if name != "neqo-qcsd-client"}
        raw = _exception(error, hashes)
        _direct_raise(raw["frames"][-1], page._regular(sources["qcsd_lab.cdp_targets"]).read_bytes(), raw["message"])
        return True
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return False


def _validate_exception(value: Any, hashes: Mapping[str, str], depth: int = 0) -> None:
    if (not isinstance(value, Mapping) or set(value) != _EXCEPTION_KEYS or depth >= 8
        or not isinstance(value["message"], str) or not value["message"]
        or not isinstance(value["attributes"], Mapping) or type(value["suppress_context"]) is not bool
        or (value["exception_module"], value["exception_type"]) not in {
            ("qcsd_lab.cdp_targets", "CdpTargetIntegrityError"),
            ("qcsd_lab.acquisition_errors", "PassiveRenderPolicyError")}
        or not isinstance(value["frames"], list) or not value["frames"]):
        raise ValueError("collector raw exception/class/traceback is invalid")
    for frame in value["frames"]:
        if (not isinstance(frame, Mapping) or set(frame) != {"module", "filename", "function", "line_number", "source_sha256"}
            or any(not isinstance(frame[key], str) or not frame[key] for key in ("module", "filename", "function"))
            or type(frame["line_number"]) is not int or frame["line_number"] <= 0
            or frame["source_sha256"] != hashes.get(frame["module"])):
            raise ValueError("collector traceback frame/source binding is invalid")
    if value["exception_type"] == "PassiveRenderPolicyError":
        prepare.validate_passive_render_policy_failure_evidence(value["attributes"].get("evidence"))
    for key in ("cause", "context"):
        if value[key] is not None:
            _validate_exception(value[key], hashes, depth + 1)


def _raw_facts(error: Mapping[str, Any], trace: bytes, hashes: Mapping[str, str], sources: Mapping[str, bytes]) -> dict[str, Any]:
    _validate_exception(error, hashes)
    if (error["exception_type"] != "CdpTargetIntegrityError" or error["exception_module"] != "qcsd_lab.cdp_targets"
        or not trace or b"CdpTargetIntegrityError" not in trace):
        raise ValueError("collector observation is not an actual exact CDP failure")
    leaf = error["frames"][-1]
    _direct_raise(leaf, sources["qcsd_lab.cdp_targets"], error["message"])
    text = trace.decode()
    def correlate(current):
        if f"{current['exception_module']}.{current['exception_type']}: {current['message']}" not in text:
            raise ValueError("collector exception contradicts its retained actual traceback")
        for frame in current["frames"]:
            if f"File \"{frame['filename']}\", line {frame['line_number']}, in {frame['function']}" not in text:
                raise ValueError("collector structured frames contradict the retained traceback")
        for key in ("cause", "context"):
            if current[key] is not None:
                correlate(current[key])
    correlate(error)
    return {"exception_type": error["exception_type"], "exception_module": error["exception_module"], "message": error["message"],
            "exception": deepcopy(dict(error)), "traceback_text": text, "traceback_sha256": page._sha(trace),
            "raise_site": {key: leaf[key] for key in ("module", "function", "line_number", "source_sha256")},
            "source_hashes": dict(hashes)}


def _directory(path: Path) -> Path:
    path = Path(path).absolute()
    if not path.is_dir() or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("collector attempt must be an existing directory without symlinks")
    return path


def _child(root: Path, relative: Any) -> Path:
    if (not isinstance(relative, str) or not relative or "\\" in relative or Path(relative).is_absolute()
        or any(part in {".", ".."} for part in relative.split("/")) or Path(relative).as_posix() != relative):
        raise ValueError("collector attempt artifact path is not canonical")
    return page._regular(root / relative)


def _inventory(root: Path, excluded: set[str]) -> dict[str, dict[str, Any]]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("collector attempt inventory contains a symlink")
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        raw = page._regular(path).read_bytes()
        result[relative] = {"sha256": page._sha(raw), "size": len(raw)}
    return result


def _reference(root: Path, path: Path) -> dict[str, str]:
    return {"path": path.relative_to(root).as_posix(), "sha256": page._sha(page._regular(path).read_bytes())}


def _artifact(root: Path, reference: Any) -> bytes:
    if not isinstance(reference, Mapping) or set(reference) != {"path", "sha256"}:
        raise ValueError("collector retained artifact reference is invalid")
    raw = _child(root, reference["path"]).read_bytes()
    if page._sha(raw) != _digest(reference["sha256"]):
        raise ValueError("collector retained raw/source artifact changed")
    return raw


def retain_collector_failure(
    output: Path, *, error: Exception, profile_receipt: Mapping[str, Any], source_bytes: bytes,
    catalogue_bytes: bytes, candidate_id: str, execution_binding: Mapping[str, Any],
    selection_amendment_sha256: str, expected_implementation_hashes: Mapping[str, str],
    not_before_utc: datetime, started_at: str, runtime: Mapping[str, Any], action: Mapping[str, Any],
    attempt_root: Path,
) -> Path:
    """Retain one newly caught exact typed exception; never import an old log."""
    root = _directory(attempt_root)
    output = Path(output).absolute()
    if output.parent != root or output.exists() or output.is_symlink() or (root / _LATER_WRAPPER).exists():
        raise ValueError("collector observation needs a new create-only attempt destination")
    candidate = page._candidate(profile_receipt, source_bytes, catalogue_bytes, candidate_id)
    binding = page._binding(execution_binding)
    hashes = _hashes(expected_implementation_hashes)
    if not is_collector_failure(error):
        raise ValueError("exception is not a direct exact typed collector event failure")
    raw_error = _exception(error, hashes)
    # Save each chain member's traceback even if Python suppressed its display.
    trace_parts = []
    seen = set()
    def retain_trace(current):
        if current is None or id(current) in seen:
            return
        seen.add(id(current))
        trace_parts.extend(traceback.TracebackException.from_exception(current, capture_locals=False).format(chain=False))
        retain_trace(current.__cause__)
        retain_trace(current.__context__)
    retain_trace(error)
    trace = "".join(trace_parts).encode()
    evidence_dir = root / "collector-evidence"
    evidence_dir.mkdir()
    util.durable_create(evidence_dir / "exception.json", page._json(raw_error))
    util.durable_create(evidence_dir / "traceback.txt", trace)
    completed = datetime.now(UTC).isoformat()
    page._freshness(started_at, completed, not_before_utc)
    if begin_collector_action(binding, hashes, not_before_utc) != dict(runtime):
        raise ValueError("collector runtime source/image changed during the actual action")
    source_dir = evidence_dir / "sources"
    source_dir.mkdir()
    source_refs = {}
    source_raws = {}
    for name, path in implementation_sources().items():
        raw = page._regular(path).read_bytes()
        if page._sha(raw) != hashes[name]:
            raise ValueError("collector source or client changed during evidence retention")
        target = source_dir / hashes[name]
        if target.exists():
            if target.read_bytes() != raw:
                raise ValueError("collector source object collision")
        else:
            util.durable_create(target, raw)
        source_refs[name] = _reference(root, target)
        source_raws[name] = raw
    _raw_facts(raw_error, trace, hashes, source_raws)
    payload = {"policy": COLLECTOR_FAILURE_POLICY, "profile_sha256": rapid_study_profile.FROZEN_V5_PROFILE_SHA256,
               "selection_amendment_sha256": _digest(selection_amendment_sha256), "candidate": candidate,
               "execution_binding": binding, "runtime": dict(runtime), "implementation_hashes": hashes,
               "started_at": started_at, "completed_at": completed, "action": _action(action, candidate),
               "artifacts": {"exception": _reference(root, evidence_dir / "exception.json"),
                             "traceback": _reference(root, evidence_dir / "traceback.txt"), "sources": source_refs},
               "attempt_inventory": _inventory(root, {output.name, _LATER_WRAPPER}), **_FLAGS}
    page._create(output, payload, COLLECTOR_FAILURE_RECEIPT_TYPE)
    return output


def verify_collector_failure(
    path: Path, *, profile_receipt: Mapping[str, Any], source_bytes: bytes, catalogue_bytes: bytes,
    candidate_id: str, execution_binding: Mapping[str, Any], selection_amendment_sha256: str,
    expected_implementation_hashes: Mapping[str, str], not_before_utc: datetime, expected_action: Mapping[str, Any],
) -> dict[str, Any]:
    """Reopen all retained exception, class/client/source and closed attempt bytes."""
    payload, digest = page._open(path, COLLECTOR_FAILURE_RECEIPT_TYPE)
    candidate = page._candidate(profile_receipt, source_bytes, catalogue_bytes, candidate_id)
    binding = page._binding(execution_binding)
    hashes = _hashes(expected_implementation_hashes)
    if (set(payload) != _PAYLOAD_KEYS or payload["policy"] != COLLECTOR_FAILURE_POLICY
        or payload["profile_sha256"] != rapid_study_profile.FROZEN_V5_PROFILE_SHA256
        or payload["selection_amendment_sha256"] != _digest(selection_amendment_sha256)
        or page._json(payload["candidate"]) != page._json(candidate) or payload["execution_binding"] != binding
        or payload["implementation_hashes"] != hashes or payload["action"] != _action(expected_action, candidate)):
        raise ValueError("collector receipt differs from independent frozen candidate/action/source bindings")
    _flags(payload)
    page._freshness(payload["started_at"], payload["completed_at"], not_before_utc)
    runtime = page._validate_runtime(payload["runtime"], binding)
    root = _directory(path.parent)
    if page._json(_inventory(root, {path.name, _LATER_WRAPPER})) != page._json(payload["attempt_inventory"]):
        raise ValueError("collector closed attempt inventory changed or gained unregistered files")
    artifacts = payload["artifacts"]
    if set(artifacts) != {"exception", "traceback", "sources"} or set(artifacts["sources"]) != _KEYS:
        raise ValueError("collector raw/source/client artifact inventory is incomplete")
    sources = {name: _artifact(root, ref) for name, ref in artifacts["sources"].items()}
    if {name: page._sha(raw) for name, raw in sources.items()} != hashes:
        raise ValueError("collector retained module/class/client source differs from prospective hashes")
    raw = _raw_facts(page._loads(_artifact(root, artifacts["exception"])), _artifact(root, artifacts["traceback"]), hashes, sources)
    facts = {key: deepcopy(payload[key]) for key in _PAYLOAD_KEYS - {"runtime", "artifacts"}}
    facts.update(collector_failure_receipt_sha256=digest, runtime_source=runtime, raw_failure=raw)
    return validate_collector_failure_facts(facts, candidate=candidate, execution_binding=binding,
                                          selection_amendment_sha256=selection_amendment_sha256,
                                          not_before_utc=not_before_utc, expected_action=expected_action)


def validate_collector_failure_facts(
    value: Any, *, candidate: Mapping[str, Any], execution_binding: Mapping[str, Any],
    selection_amendment_sha256: str, not_before_utc: datetime, expected_action: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Check compact facts only after an independent receipt-reopening callback."""
    keys = (_PAYLOAD_KEYS - {"runtime", "artifacts"}) | {"collector_failure_receipt_sha256", "runtime_source", "raw_failure"}
    if (not isinstance(value, Mapping) or set(value) != keys or value["policy"] != COLLECTOR_FAILURE_POLICY
        or value["profile_sha256"] != rapid_study_profile.FROZEN_V5_PROFILE_SHA256
        or value["selection_amendment_sha256"] != _digest(selection_amendment_sha256)
        or page._json(value["candidate"]) != page._json(candidate)
        or value["execution_binding"] != page._binding(execution_binding)):
        raise ValueError("collector failure facts differ from independently supplied context")
    _flags(value)
    _digest(value["collector_failure_receipt_sha256"])
    hashes = _hashes(value["implementation_hashes"])
    action = _action(value["action"], candidate)
    if expected_action is not None and action != _action(expected_action, candidate):
        raise ValueError("collector failure facts changed the independently reopened action")
    page._freshness(value["started_at"], value["completed_at"], not_before_utc)
    source = value["runtime_source"]
    if (not isinstance(source, Mapping) or set(source) != util.SOURCE_METADATA_KEYS
        or source["image_digest"] != execution_binding["admission_image_digest"]
        or source["lab_dirty"] is not False or source["neqo_dirty"] is not False
        or source["lab_patch_sha256"] != page._EMPTY_SHA or source["neqo_patch_sha256"] != page._EMPTY_SHA
        or any(not isinstance(source[key], str) or page._COMMIT.fullmatch(source[key]) is None
               for key in ("lab_commit", "neqo_commit", "neqo_pinned_commit"))
        or source["neqo_commit"] != source["neqo_pinned_commit"]):
        raise ValueError("collector failure runtime is not the independently bound clean pinned image")
    raw = value["raw_failure"]
    if (not isinstance(raw, Mapping) or set(raw) != {"exception_type", "exception_module", "message", "exception", "traceback_text",
                                                   "traceback_sha256", "raise_site", "source_hashes"}
        or raw["exception_type"] != "CdpTargetIntegrityError" or raw["exception_module"] != "qcsd_lab.cdp_targets"
        or raw["source_hashes"] != hashes or not isinstance(raw["traceback_text"], str)
        or page._sha(raw["traceback_text"].encode()) != raw["traceback_sha256"]):
        raise ValueError("collector facts lack their independently reopened raw typed failure")
    _validate_exception(raw["exception"], hashes)
    leaf = raw["exception"]["frames"][-1]
    if (raw["exception"]["exception_type"] != raw["exception_type"] or raw["exception"]["exception_module"] != raw["exception_module"]
        or raw["exception"]["message"] != raw["message"] or leaf["module"] != "qcsd_lab.cdp_targets"
        or not leaf["function"].startswith("_handle_")
        or raw["raise_site"] != {key: leaf[key] for key in ("module", "function", "line_number", "source_sha256")}):
        raise ValueError("collector facts changed their exact direct CDP handler failure")
    if not isinstance(value["attempt_inventory"], Mapping) or not value["attempt_inventory"]:
        raise ValueError("collector facts lack a closed actual attempt inventory")
    for name, item in value["attempt_inventory"].items():
        if (not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts
            or not isinstance(item, Mapping) or set(item) != {"sha256", "size"}
            or type(item["size"]) is not int or item["size"] < 0):
            raise ValueError("collector attempt inventory facts are invalid")
        _digest(item["sha256"])
    return page._loads(page._json(value))
