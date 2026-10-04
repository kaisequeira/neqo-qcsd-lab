"""Prospectively change only FRONT's declared padding-omission acceptance.

Enrollment and admission remain original evidence. A fresh capture manifest
differs by one quoted policy literal; its complete application evidence is
copied unchanged. This declaration provides no qualification or trace credit.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Mapping

from . import rapid_lane_evidence as lanes
from . import rapid_site_admission as admission

RECEIPT_TYPE = "qcsd-rapid-v6-front-capture-policy-amendment-v1"
CONTRACT = "front-only-literal-replacement-with-unchanged-enrolled-application-v1"
ORIGINAL_POLICY = "rapid-v5-front-bounded-outgoing-congestion-omission-1pct-v1"
CAPTURE_POLICY = "rapid-v5-front-bounded-outgoing-padding-omission-1pct-v2"
WINDOW_CAPTURE_POLICY = "rapid-v5-front-bounded-outgoing-padding-omission-10pct-window-10000us-v3"
WINDOW_RECEIPT_TYPE = "qcsd-rapid-v6-front-capture-policy-amendment-v2"
WINDOW_CONTRACT = "front-only-10000us-padding-window-10pct-literal-replacement-with-unchanged-enrolled-application-v2"
FIELD = "front_capture_policy"
FIELDS = {"contract", "mode", "preparation_field", "original_policy", "capture_policy",
          "enrollment", "admission_provenance", "runtime_source_manifest", "client_binary",
          "collection_image_digest", "workloads", "published_at",
          "formal_accepted_trace_count", "scientific_credit"}
WORKLOAD_FIELDS = {"candidate_id", "workload_id", "original_manifest", "capture_manifest",
                   "resource_records_sha256", "application_evidence_files"}
EXACT = {"contract": CONTRACT, "mode": "front", "preparation_field": FIELD,
         "original_policy": ORIGINAL_POLICY, "capture_policy": CAPTURE_POLICY,
         "formal_accepted_trace_count": 0, "scientific_credit": False}


def _contract(capture_policy: str) -> tuple[str, dict[str, Any]]:
    if capture_policy == CAPTURE_POLICY:
        return RECEIPT_TYPE, EXACT
    if capture_policy == WINDOW_CAPTURE_POLICY:
        return WINDOW_RECEIPT_TYPE, {**EXACT, "contract": WINDOW_CONTRACT,
                                     "capture_policy": WINDOW_CAPTURE_POLICY}
    raise ValueError("FRONT amendment requires an explicit supported capture policy")


def _directory(manifest: Path) -> Path:
    return manifest.with_name(manifest.stem + "-application-response-evidence")


def _inventory(directory: Path) -> dict[str, dict[str, Any]]:
    lanes._regular_directory(directory)
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("FRONT amendment application evidence contains a symlink")
        if path.is_dir():
            continue
        raw = lanes._read(path)
        result[str(path.relative_to(directory))] = {
            "sha256": lanes._sha(raw), "executable": bool(path.stat().st_mode & 0o111)}
    if not result:
        raise ValueError("FRONT amendment needs the complete original application evidence")
    return result


def _derived(raw: bytes, capture_policy: str = CAPTURE_POLICY) -> tuple[bytes, str]:
    _contract(capture_policy)
    original = lanes._load(raw)
    if (not isinstance(original, dict) or not isinstance(original.get("preparation"), dict)
        or original["preparation"].get(FIELD) != ORIGINAL_POLICY
        or not isinstance(original.get("resources"), list) or not original["resources"]):
        raise ValueError("FRONT amendment requires an original V1 complete resource graph")
    token = ('"' + ORIGINAL_POLICY + '"').encode()
    if raw.count(token) != 1:
        raise ValueError("FRONT amendment requires one unique quoted original policy literal")
    changed = raw.replace(token, ('"' + capture_policy + '"').encode(), 1)
    derived = lanes._load(changed)
    derived["preparation"][FIELD] = ORIGINAL_POLICY
    if derived != original:
        raise ValueError("FRONT amendment changed application or other preparation fields")
    return changed, lanes._sha(lanes._json(original["resources"]))


def _rows(classes: list[dict[str, Any]], workload_root: Path,
          capture_policy: str = CAPTURE_POLICY) -> list[dict[str, Any]]:
    from . import rapid_rolling_capture as rolling
    rows = []
    for row in classes:
        context = admission.load_admission_context(Path(row["admission_root"]))
        terminal = rolling._open_ref(row["terminal"])
        facts = admission.verify_site_terminal(terminal, context)
        original, _ = rolling._prepared_workload(context, terminal)
        raw = lanes._read(original)
        derived, graph_sha = _derived(raw, capture_policy)
        target = workload_root / original.name
        if (facts["candidate_id"] != row["candidate_id"]
            or facts["admission"]["prepared_workload_sha256"] != lanes._sha(raw)
            or target == original or _directory(target) == _directory(original)):
            raise ValueError("FRONT amendment changed original admission or reused its workload location")
        rows.append({"candidate_id": row["candidate_id"], "workload_id": original.stem,
                     "original_manifest": rolling._ref(original),
                     "capture_manifest": {"path": str(target), "sha256": lanes._sha(derived)},
                     "resource_records_sha256": graph_sha,
                     "application_evidence_files": _inventory(_directory(original))})
    return rows


def _validate_for_enrollment(path: Path, enrollment: Path, runtime: Mapping[str, str],
                             batch: Mapping[str, Any], classes: list[dict[str, Any]]) -> dict[str, Any]:
    """Consume only facts freshly reopened by this operation's enrollment verifier."""
    from . import rapid_rolling_capture as rolling
    path = Path(path).absolute()
    policy_root = rolling._open_ref(batch["policy"]).parent
    if not path.is_relative_to(policy_root) or ".." in path.parts:
        raise ValueError("FRONT amendment must remain inside its original study evidence root")
    raw = lanes._read(path)
    wrapper = lanes._load(raw)
    receipt_type = wrapper.get("receipt_type") if isinstance(wrapper, Mapping) else None
    capture_policy = WINDOW_CAPTURE_POLICY if receipt_type == WINDOW_RECEIPT_TYPE else CAPTURE_POLICY
    expected_type, exact = _contract(capture_policy)
    value = admission._unpack(raw, expected_type)
    rolling._keys(value, FIELDS, "FRONT amendment")
    if any(type(value[key]) is not type(expected) or value[key] != expected for key, expected in exact.items()):
        raise ValueError("FRONT amendment changes its closed prospective contract")
    original_policy = admission._unpack(lanes._read(policy_root / "policy.json"), rolling.POLICY_TYPE)
    if runtime["data_root"] != original_policy["runtime"]["data_root"]:
        raise ValueError("FRONT amendment changed its original study data root")
    references = {"enrollment": enrollment, "admission_provenance": Path(batch["admission_root"]) / "provenance.json",
                  "runtime_source_manifest": Path(runtime["source_manifest"]), "client_binary": Path(runtime["client_binary"])}
    for key, expected in references.items():
        if value[key] != rolling._ref(expected):
            raise ValueError("FRONT amendment changed enrollment, original admission or capture runtime")
        rolling._open_ref(value[key])
    if value["collection_image_digest"] != runtime["collection_image_digest"]:
        raise ValueError("FRONT amendment changed its actual capture image")
    if not admission._utc(batch["declared_at"]) <= admission._utc(value["published_at"]) <= admission._utc(admission._now()):
        raise ValueError("FRONT amendment publication is outside its prospective enrollment")
    selected = classes[-len(batch["selected_candidate_ids"]):]
    expected_rows = _rows(selected, Path(runtime["workload_root"]), capture_policy)
    if not isinstance(value["workloads"], list) or len(value["workloads"]) != len(expected_rows):
        raise ValueError("FRONT amendment omitted or added an enrolled workload")
    for row, expected in zip(value["workloads"], expected_rows, strict=True):
        rolling._keys(row, WORKLOAD_FIELDS, "FRONT amendment workload")
        if not isinstance(row["application_evidence_files"], dict):
            raise ValueError("FRONT amendment application inventory is invalid")
        for item in row["application_evidence_files"].values():
            rolling._keys(item, {"sha256", "executable"}, "FRONT application evidence file")
            if type(item["executable"]) is not bool:
                raise ValueError("FRONT amendment executable metadata requires a Boolean")
        if row != expected:
            raise ValueError("FRONT amendment changed its original graph, evidence or manifest bindings")
        original = rolling._open_ref(row["original_manifest"])
        target = rolling._open_ref(row["capture_manifest"])
        if lanes._read(target) != _derived(lanes._read(original), capture_policy)[0]:
            raise ValueError("FRONT amendment permits only its exact quoted original-to-capture policy replacement")
        if _inventory(_directory(target)) != expected["application_evidence_files"]:
            raise ValueError("FRONT amendment changed copied application evidence bytes or executable bits")
    return value


def validate_amendment(path: Path, *, enrollment: Path, runtime: Mapping[str, str]) -> dict[str, Any]:
    from . import rapid_rolling_capture as rolling
    runtime = rolling._runtime(dict(runtime))
    batch, classes, _ = rolling._verify_enrollment(enrollment)
    return _validate_for_enrollment(path, enrollment, runtime, batch, classes)


def publish_amendment(enrollment: Path, runtime: Mapping[str, str], output: Path, *,
                      capture_policy: str = CAPTURE_POLICY) -> Path:
    """Create fresh capture inputs and declare them before qualification/capture."""
    from . import rapid_rolling_capture as rolling
    receipt_type, exact = _contract(capture_policy)
    runtime = rolling._runtime(dict(runtime))
    batch, classes, policy = rolling._verify_enrollment(enrollment)
    output = Path(output).absolute()
    policy_root = rolling._open_ref(batch["policy"]).parent
    if (runtime["data_root"] != policy["runtime"]["data_root"]
        or not output.is_relative_to(policy_root) or ".." in output.parts or output.exists() or output.is_symlink()):
        raise ValueError("FRONT amendment requires a fresh declaration in the original study root")
    selected = classes[-len(batch["selected_candidate_ids"]):]
    rows = _rows(selected, Path(runtime["workload_root"]), capture_policy)
    # Validate every destination and original byte before creating any input.
    copies = []
    for row in rows:
        original = rolling._open_ref(row["original_manifest"])
        target = Path(row["capture_manifest"]["path"])
        if any(p.exists() or p.is_symlink() for p in (target, _directory(target))):
            raise ValueError("FRONT amendment never overwrites an earlier capture workload")
        raw = _derived(lanes._read(original), capture_policy)[0]
        files = [(relative, lanes._read(_directory(original) / relative),
                  stat.S_IMODE((_directory(original) / relative).stat().st_mode))
                 for relative in row["application_evidence_files"]]
        copies.append((target, raw, files))
    for target, raw, files in copies:
        admission.durable_create(target, raw)
        _directory(target).mkdir()
        for relative, file_raw, permissions in files:
            copied = _directory(target) / relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            admission.durable_create(copied, file_raw)
            os.chmod(copied, permissions)
    payload = {**exact, "enrollment": rolling._ref(enrollment),
               "admission_provenance": rolling._ref(Path(batch["admission_root"]) / "provenance.json"),
               "runtime_source_manifest": rolling._ref(Path(runtime["source_manifest"])),
               "client_binary": rolling._ref(Path(runtime["client_binary"])),
               "collection_image_digest": runtime["collection_image_digest"],
               "workloads": rows, "published_at": admission._now()}
    rolling._write(output, receipt_type, payload)
    _validate_for_enrollment(output, enrollment, runtime, batch, classes)
    return output


def require_canary(reference: Mapping[str, Any], facts: Mapping[str, Any], amendment_reference: Mapping[str, Any],
                   amendment: Mapping[str, Any]) -> None:
    """Bind already fully reopened current FRONT evidence to this declaration."""
    from . import rapid_rolling_capture as rolling
    canary = lanes._load(lanes._read(rolling._open_ref(reference["plan"])))
    matching = next((row for row in amendment["workloads"]
                     if row["capture_manifest"]["sha256"] == facts.get("workload_sha256")), None)
    if (canary.get("front_capture_amendment") != amendment_reference or matching is None
        or facts.get("full_graph", {}).get("resource_records_sha256") != matching["resource_records_sha256"]):
        raise ValueError("FRONT canary changed its amendment, derived manifest or complete graph")
    start = lanes._load(lanes._read(rolling._open_ref(reference["capture"]["started"])))
    if admission._utc(start["started_at"]) < admission._utc(amendment["published_at"]):
        raise ValueError("FRONT canary was captured before its prospective amendment")
