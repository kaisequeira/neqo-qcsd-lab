"""Prospective prepared-budget response qualification; historical producers stay exact.

This separate role retains all 120 complete-response/header/clock/UDP checks.
It binds only the declared per-resource byte ceiling to a validated preparation.
No retained partial response or old sidecar gains qualification authority.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import Any, Mapping, Sequence

from . import chaff_qualification as legacy
from .chaff_qualification import (
    BASE_MANIFEST_KEYS,
    CANDIDATE_ATTEMPT_KEYS,
    IDENTITY_REQUEST_HEADER_MODE,
    LAB_ROOT,
    METHOD,
    PACKET_OBSERVATION_KEYS,
    PREPARED_CANDIDATE_RESPONSE_KEYS,
    PreparationError,
    QUALIFICATION_RUNS,
    QualifiedChaffInput,
    QualifiedChaffOutput,
    RESPONSE_ARTIFACT_TYPE,
    RESPONSE_ONLY_APPROVED_ORIGINS_SELECTION_POLICY,
    RESPONSE_ONLY_COMPLETIONS_PER_CANDIDATE,
    RESPONSE_ONLY_EPOCH_SPACING_SECONDS,
    RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
    RESPONSE_ONLY_QUALIFICATION_SCOPE,
    RESPONSE_ONLY_REQUESTS_PER_EPOCH,
    RESPONSE_ONLY_V2_POLICY_KEYS,
    RESPONSE_ONLY_V2_SELECTION_POLICY,
    RESPONSE_ONLY_WAVES_PER_EPOCH,
    RESPONSE_ONLY_WAVE_SPACING_MILLISECONDS,
    RESPONSE_QUALIFICATION_V2_RECEIPT_SCHEMA_VERSION,
    RESPONSE_V2_DIRECTIONAL_RECEIPT_SCHEMA_VERSION,
    RESPONSE_V2_RECEIPT_KEYS,
    RESPONSE_V2_REQUEST_KEYS,
    RESPONSE_V2_RUN_KEYS,
    UDP_PAYLOAD_CEILING,
    _bound_neqo_client,
    _digest,
    _exact_mapping,
    _https_origin,
    _normalize_content_encoding,
    _prepared_candidate_response,
    _qualification_execution_context,
    _receipt_neqo_provenance,
    _receipt_udp_policy,
    _recheck_bound_neqo_client,
    _regular_directory_without_symlinks,
    _rename_noreplace,
    _response_v2_run_record,
    _run_neqo,
    _source_execution_identity,
    _stable_neqo_provenance,
    _validate_expected_response,
    _validate_implementation_receipt,
    _validate_neqo_provenance,
    _validate_receipt_neqo_provenance,
    _validate_response_only_request_header_primitive,
    _validate_response_only_v2_resource_receipt,
    _validate_source,
    _validate_udp_statistics,
    canonical_bytes,
    derive_response_only_chaff_manifest_v2,
    load_json,
    project_identity_chaff_headers,
    qualification_digest,
    response_only_candidate_resources,
    response_only_request_header_primitive,
    response_only_selection_policy,
    selected_navigation_root,
    sha256_bytes,
    sha256_file,
    source_metadata,
    validate_qualification_set,
    validate_research_preparation,
)

SIDECAR_SCHEMA_VERSION = 3
RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION = SIDECAR_SCHEMA_VERSION
RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE = "qcsd-prepared-budget-response-qualification-v1"
NAMED_ARTIFACT_TYPE = "qcsd-prepared-budget-response-qualification-set-v1"
RESPONSE_ONLY_V2_SIDECAR_KEYS = legacy.RESPONSE_ONLY_V2_SIDECAR_KEYS | {"response_budget_source"}
RESPONSE_ONLY_PREPARED_RESPONSE_BUDGET_POLICY = "prepared-resource-response-budget-v1"
RESPONSE_ONLY_PREPARED_RESPONSE_BUDGETS = frozenset({16_777_216, 67_108_864})


def _budget_source() -> dict[str, str]:
    return {"module_sha256": sha256_file(Path(__file__)),
            "legacy_module_sha256": sha256_file(Path(legacy.__file__))}


def _budget_execution_context():
    context = legacy._qualification_execution_context()
    if sha256_file(LAB_ROOT / "src/qcsd_lab/response_budget_qualification.py") != _budget_source()["module_sha256"]:
        raise ValueError("response budget qualifier differs from its executed Source")
    return context


def is_budget_sidecar(value: object) -> bool:
    return isinstance(value, Mapping) and value.get("artifact_type") == RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE


def validate_response_only_sidecar(value: object, **kwargs):
    if not is_budget_sidecar(value):
        return legacy.validate_response_only_sidecar(value, **kwargs)
    version = kwargs.pop("expected_sidecar_schema_version", None)
    if version is not None and (type(version) is not int or version != SIDECAR_SCHEMA_VERSION):
        raise ValueError("response budget sidecar schema differs from the declared role")
    return _validate_response_only_sidecar_v2(value, **kwargs)


def sidecar_schema(path: Path, historical_schema: int) -> int:
    """Select a typed reader; the reader still reopens and proves every field."""
    return SIDECAR_SCHEMA_VERSION if is_budget_sidecar(load_json(path)) else historical_schema


def load_response_qualified_chaff(sidecar_path: Path, *, workload_id: str,
    base_manifest_path: Path, expected_sidecar_schema_version: int | None,
    require_current_implementation: bool = True) -> QualifiedChaffInput:
    path = legacy._named_regular_file(Path(sidecar_path).parent, Path(sidecar_path).name, "response sidecar")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not is_budget_sidecar(value):
        return legacy.load_response_qualified_chaff(path, workload_id=workload_id,
            base_manifest_path=base_manifest_path, expected_sidecar_schema_version=expected_sidecar_schema_version,
            require_current_implementation=require_current_implementation)
    result = validate_response_only_sidecar(value, workload_id=workload_id,
        base_manifest_path=base_manifest_path, expected_sidecar_schema_version=expected_sidecar_schema_version,
        require_current_implementation=require_current_implementation)
    return QualifiedChaffInput(sidecar_path=path.resolve(), sidecar_sha256=sha256_bytes(raw),
        manifest=result.manifest, manifest_sha256=result.manifest_sha256,
        application_manifest_sha256=result.application_manifest_sha256,
        application_resource_id=result.application_resource_id,
        selected_chaff_resource_id=result.selected_chaff_resource_id,
        qualified_parallel_chaff_streams=result.qualified_parallel_chaff_streams,
        walkie_talkie_required_chaff_streams=None)


def _named_manifest(workload_ids: Sequence[str], *, qualification_set: str,
    workload_root: Path, sidecar_root: Path, require_current_implementation: bool) -> dict[str, Any]:
    cohort = legacy._named_workload_ids(workload_ids)
    name = legacy.validate_qualification_set(qualification_set)
    workloads = legacy._regular_directory_without_symlinks(workload_root, "workload root")
    sidecars = legacy._regular_directory_without_symlinks(sidecar_root, "sidecar root")
    entries = []
    for index, identifier in enumerate(cohort):
        workload = legacy._named_regular_file(workloads, identifier + ".json", "workload")
        sidecar = legacy._named_regular_file(sidecars, identifier + ".json", "sidecar")
        qualified = load_response_qualified_chaff(sidecar, workload_id=identifier,
            base_manifest_path=workload, expected_sidecar_schema_version=SIDECAR_SCHEMA_VERSION,
            require_current_implementation=require_current_implementation)
        entries.append({"index": index, "workload_id": identifier,
            "workload_manifest": {"path": workload.name, "sha256": sha256_file(workload)},
            "qualification_sidecar": {"path": sidecar.name, "sha256": qualified.sidecar_sha256},
            "runtime_manifest_sha256": qualified.manifest_sha256, "prefix_pack_spec": None})
    manifest = {"schema_version": 1, "artifact_type": NAMED_ARTIFACT_TYPE,
        "qualification_set": name, "qualification_scope": RESPONSE_ONLY_QUALIFICATION_SCOPE,
        "qualification_sidecar_schema_version": SIDECAR_SCHEMA_VERSION,
        "workload_count": len(cohort), "workload_ids": list(cohort), "workloads": entries}
    manifest["bindings_sha256"] = legacy._named_qualification_bindings_sha256(manifest)
    return manifest


def validate_named_qualification_set_manifest(value: object, *, workload_root: Path,
    sidecar_root: Path, prefix_spec_root: Path | None = None,
    expected_qualification_set: str | None = None, expected_qualification_scope: str | None = None,
    expected_workload_ids: Sequence[str] | None = None, require_current_implementation: bool = True,
    expected_qualification_authority: Mapping[str, Any] | None = None) -> dict[str, Any]:
    kwargs = dict(workload_root=workload_root, sidecar_root=sidecar_root, prefix_spec_root=prefix_spec_root,
        expected_qualification_set=expected_qualification_set, expected_qualification_scope=expected_qualification_scope,
        expected_workload_ids=expected_workload_ids, require_current_implementation=require_current_implementation,
        expected_qualification_authority=expected_qualification_authority)
    if not isinstance(value, Mapping) or value.get("artifact_type") != NAMED_ARTIFACT_TYPE:
        return legacy.validate_named_qualification_set_manifest(value, **kwargs)
    manifest = legacy._exact_mapping(value, legacy.NAMED_QUALIFICATION_SET_KEYS, "prepared-budget named set")
    if (type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
        or type(manifest["qualification_sidecar_schema_version"]) is not int
        or manifest["qualification_sidecar_schema_version"] != SIDECAR_SCHEMA_VERSION
        or type(manifest["workload_count"]) is not int
        or prefix_spec_root is not None or expected_qualification_authority is not None
        or manifest["qualification_scope"] != RESPONSE_ONLY_QUALIFICATION_SCOPE
        or (expected_qualification_scope is not None and expected_qualification_scope != RESPONSE_ONLY_QUALIFICATION_SCOPE)
        or (expected_qualification_set is not None and manifest["qualification_set"] != expected_qualification_set)
        or (expected_workload_ids is not None and tuple(manifest["workload_ids"]) != tuple(expected_workload_ids))):
        raise ValueError("prepared-budget named qualification contract differs")
    if (not legacy._digest(manifest["bindings_sha256"])
        or manifest["bindings_sha256"] != legacy._named_qualification_bindings_sha256(manifest)):
        raise ValueError("prepared-budget named qualification digest differs")
    expected = _named_manifest(manifest["workload_ids"], qualification_set=manifest["qualification_set"],
        workload_root=workload_root, sidecar_root=sidecar_root,
        require_current_implementation=require_current_implementation)
    if dict(manifest) != expected:
        raise ValueError("prepared-budget named qualification bindings differ")
    return dict(manifest)


def load_named_qualification_set(manifest_path: Path, *, workload_root: Path,
    sidecar_root: Path | None = None, **kwargs):
    path = Path(os.path.abspath(manifest_path))
    legacy._named_regular_file(path.parent, path.name, "named manifest")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, Mapping) or value.get("artifact_type") != NAMED_ARTIFACT_TYPE:
        return legacy.load_named_qualification_set(path, workload_root=workload_root,
            sidecar_root=sidecar_root, **kwargs)
    manifest = validate_named_qualification_set_manifest(value, workload_root=workload_root,
        sidecar_root=sidecar_root or path.parent, **kwargs)
    return legacy.NamedQualificationSetOutput(path=path.parent.resolve(), manifest_path=path.resolve(),
        manifest_sha256=sha256_bytes(raw), qualification_set=manifest["qualification_set"],
        qualification_scope=manifest["qualification_scope"], workload_ids=tuple(manifest["workload_ids"]))


def publish_named_qualification_set(workload_ids: Sequence[str], *, qualification_set: str,
    qualification_scope: str, workload_root: Path, sidecar_root: Path, publication_root: Path,
    qualification_sidecar_schema_version: int | None = None, **kwargs):
    if qualification_scope != RESPONSE_ONLY_QUALIFICATION_SCOPE or qualification_sidecar_schema_version != SIDECAR_SCHEMA_VERSION:
        return legacy.publish_named_qualification_set(workload_ids, qualification_set=qualification_set,
            qualification_scope=qualification_scope, workload_root=workload_root, sidecar_root=sidecar_root,
            publication_root=publication_root, qualification_sidecar_schema_version=qualification_sidecar_schema_version, **kwargs)
    require_current = kwargs.pop("require_current_implementation", True)
    if kwargs.get("prefix_spec_root") is not None or kwargs.get("qualification_authority") is not None:
        raise ValueError("prepared-budget response qualification cannot carry a full-chaff authority")
    if set(kwargs) - {"prefix_spec_root", "qualification_authority"}:
        raise TypeError("unexpected prepared-budget qualification publication argument")
    parent = legacy._regular_directory_without_symlinks(publication_root, "publication root")
    name = legacy.validate_qualification_set(qualification_set)
    destination = parent / name
    if destination.exists() or destination.is_symlink() or list(parent.glob(f".{name}.qcsd-set-*")):
        raise FileExistsError("prepared-budget named qualification destination is already claimed")
    manifest = _named_manifest(workload_ids, qualification_set=name, workload_root=workload_root,
        sidecar_root=sidecar_root, require_current_implementation=require_current)
    candidate = Path(tempfile.mkdtemp(prefix=f".{name}.qcsd-set-", dir=parent))
    for entry in manifest["workloads"]:
        reference = entry["qualification_sidecar"]
        source = legacy._named_regular_file(sidecar_root, reference["path"], "sidecar")
        with source.open("rb") as input_file, (candidate / reference["path"]).open("xb") as output:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
    manifest_path = candidate / legacy.NAMED_QUALIFICATION_SET_MANIFEST
    with manifest_path.open("xb") as output:
        output.write(canonical_bytes(manifest)); output.flush(); os.fsync(output.fileno())
    validate_named_qualification_set_manifest(load_json(manifest_path), workload_root=workload_root,
        sidecar_root=candidate, expected_qualification_set=name, expected_workload_ids=workload_ids,
        require_current_implementation=require_current)
    if _named_manifest(workload_ids, qualification_set=name, workload_root=workload_root,
        sidecar_root=sidecar_root, require_current_implementation=require_current) != manifest:
        raise ValueError("prepared-budget qualification inputs changed before publication")
    legacy._fsync_named_directory(candidate)
    legacy._rename_noreplace(candidate, destination)
    legacy._fsync_named_directory(parent)
    return legacy.NamedQualificationSetOutput(path=destination,
        manifest_path=destination / legacy.NAMED_QUALIFICATION_SET_MANIFEST,
        manifest_sha256=sha256_file(destination / legacy.NAMED_QUALIFICATION_SET_MANIFEST),
        qualification_set=name, qualification_scope=qualification_scope, workload_ids=tuple(workload_ids))


def _validate_response_only_sidecar_v2(
    value: object,
    *,
    workload_id: str,
    base_manifest_path: Path,
    require_current_implementation: bool = True,
) -> QualifiedChaffInput:
    """Validate the sustained identity-response sidecar and schema-four manifest."""

    sidecar = _exact_mapping(
        value,
        RESPONSE_ONLY_V2_SIDECAR_KEYS,
        "response-only v2 chaff qualification sidecar",
    )
    if (
        type(sidecar["schema_version"]) is not int
        or sidecar["schema_version"] != RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION
        or sidecar["artifact_type"] != RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE
        or sidecar["qualification_scope"] != RESPONSE_ONLY_QUALIFICATION_SCOPE
        or sidecar["workload_id"] != workload_id
        or sidecar["selection_policy"] not in {
            RESPONSE_ONLY_V2_SELECTION_POLICY, RESPONSE_ONLY_APPROVED_ORIGINS_SELECTION_POLICY,
        }
        or type(sidecar["application_resource_id"]) is not int
        or sidecar["application_resource_id"] != 0
        or type(sidecar["selected_chaff_resource_id"]) is not int
        or type(sidecar["qualified_parallel_chaff_streams"]) is not int
        or sidecar["qualified_parallel_chaff_streams"] != RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        or sidecar["method"] != METHOD
    ):
        raise ValueError("response-only v2 chaff qualification policy binding is invalid")
    if sidecar["response_budget_source"] != _budget_source():
        raise ValueError("response budget qualification producer Source differs")
    if "response_budget_policy" not in sidecar["qualification_policy"]:
        raise ValueError("response budget qualification policy marker is absent")
    _validate_response_only_request_header_primitive(sidecar["request_header_primitive"])

    base_receipt = _exact_mapping(sidecar["base_manifest"], BASE_MANIFEST_KEYS, "base manifest")
    if Path(str(base_receipt["path"])).name != base_manifest_path.name or base_receipt[
        "sha256"
    ] != sha256_file(base_manifest_path):
        raise ValueError("response-only v2 chaff qualification base manifest mismatch")
    base = load_json(base_manifest_path)
    max_response_bytes = _validate_response_only_v2_policy(
        sidecar["qualification_policy"],
        prepared_max_response_bytes=base["preparation"].get("max_response_bytes"),
    )
    validate_research_preparation(base, workload_id=workload_id)
    application = selected_navigation_root(base, workload_id)
    candidates = response_only_candidate_resources(base, workload_id)
    if sidecar["selection_policy"] != response_only_selection_policy(base):
        raise ValueError("response-only chaff origin selection policy differs from prepared workload")

    _validate_source(sidecar["qualification_source"], sidecar["qualification_image_digest"])
    _validate_implementation_receipt(
        sidecar["implementation_receipt"], require_current=require_current_implementation
    )
    if _source_execution_identity(sidecar["implementation_receipt"]["source"]) != (
        _source_execution_identity(sidecar["qualification_source"])
    ):
        raise ValueError("implementation receipt source differs from qualification source")
    if require_current_implementation:
        current_source = source_metadata()
        if current_source.get("neqo_commit") != sidecar["qualification_source"].get(
            "neqo_commit"
        ) or current_source.get("neqo_pinned_commit") != current_source.get("neqo_commit"):
            raise ValueError("Neqo source has changed since response-only chaff qualification")
    _validate_neqo_provenance(
        sidecar["neqo_provenance"], qualification_source=sidecar["qualification_source"]
    )

    attempts = sidecar["candidate_attempts"]
    if not isinstance(attempts, list) or not attempts or len(attempts) > len(candidates):
        raise ValueError("response-only v2 candidate attempts must be a non-empty prefix")
    validated_attempts: list[dict[str, Any]] = []
    for candidate_index, value_attempt in enumerate(attempts):
        candidate, prepared = candidates[candidate_index]
        attempt = _validate_response_only_candidate_attempt(
            value_attempt,
            candidate_index=candidate_index,
            base_resource=candidate,
            prepared_response=prepared,
            application_manifest_sha256=base_receipt["sha256"],
            application_resource_id=application["id"],
            neqo_provenance=sidecar["neqo_provenance"],
            max_response_bytes=max_response_bytes,
        )
        expected_outcome = "qualified" if candidate_index == len(attempts) - 1 else "rejected"
        if attempt["outcome"] != expected_outcome:
            raise ValueError("response-only v2 candidate prefix outcome is invalid")
        validated_attempts.append(attempt)
    selected_attempt = validated_attempts[-1]
    selected_resource, _prepared = candidates[len(attempts) - 1]
    if (
        selected_attempt["failure_class"] is not None
        or sidecar["selected_chaff_resource_id"] != selected_resource["id"]
    ):
        raise ValueError("response-only v2 selected candidate binding is invalid")
    resource = _validate_response_only_v2_resource_receipt(
        sidecar["resource"],
        selected_resource,
        selected_attempt=selected_attempt,
    )
    manifest = derive_response_only_chaff_manifest_v2(sidecar, selected_resource, resource)
    return QualifiedChaffInput(
        sidecar_path=Path(),
        sidecar_sha256=sha256_bytes(canonical_bytes(dict(sidecar))),
        manifest=manifest,
        manifest_sha256=sha256_bytes(canonical_bytes(manifest)),
        application_manifest_sha256=sha256_file(base_manifest_path),
        application_resource_id=application["id"],
        selected_chaff_resource_id=selected_resource["id"],
        qualified_parallel_chaff_streams=RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
        walkie_talkie_required_chaff_streams=None,
    )


def qualify_response_chaff_v2(
    workload_id: str,
    *,
    qualification_root: Path,
    workload_root: Path | None = None,
    timeout_seconds: int = 30,
    interval_seconds: int = RESPONSE_ONLY_EPOCH_SPACING_SECONDS,
    max_response_bytes: int | None = None,
    _execution_context: tuple[dict[str, Any], dict[str, Any], str] | None = None,
) -> QualifiedChaffOutput:
    """Create one v2 sidecar from a sustained deterministic candidate prefix."""

    if max_response_bytes is None:
        return legacy.qualify_response_chaff_v2(workload_id, qualification_root=qualification_root,
            workload_root=workload_root, timeout_seconds=timeout_seconds, interval_seconds=interval_seconds,
            _execution_context=_execution_context)
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", workload_id):
        raise ValueError("workload ID must contain lowercase letters, digits, and single hyphens")
    if type(interval_seconds) is not int or interval_seconds != RESPONSE_ONLY_EPOCH_SPACING_SECONDS:
        raise ValueError(
            "response-only v2 qualification requires the fixed 30-second epoch spacing"
        )
    destination_root = _regular_directory_without_symlinks(
        qualification_root, "response qualification destination"
    )
    destination = destination_root / f"{workload_id}.json"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(
            f"{destination} already exists; response qualification is create-only"
        )
    workloads = _regular_directory_without_symlinks(
        workload_root or LAB_ROOT / "config/workloads", "workload root"
    )
    base_path = workloads / f"{workload_id}.json"
    if not base_path.is_file() or base_path.is_symlink():
        raise ValueError(f"workload manifest is not a regular file: {base_path}")
    executed_implementation, source, qualification_image = (
        _execution_context or _budget_execution_context()
    )
    neqo_client, neqo_client_sha256 = _bound_neqo_client(executed_implementation)
    base = load_json(base_path)
    validate_research_preparation(base, workload_id=workload_id)
    qualification_policy = response_only_v2_qualification_policy(max_response_bytes)
    response_limit = _validate_response_only_v2_policy(
        qualification_policy,
        prepared_max_response_bytes=base["preparation"].get("max_response_bytes"),
    )
    application = selected_navigation_root(base, workload_id)
    candidates = response_only_candidate_resources(base, workload_id)
    base_sha = sha256_file(base_path)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{workload_id}-response-v2-qualification-evidence-",
            dir=destination_root,
        )
    )
    completed = False
    attempts: list[dict[str, Any]] = []
    all_receipts: list[dict[str, Any]] = []
    selected: dict[str, Any] | None = None
    selected_response: dict[str, Any] | None = None
    selected_request_stream_bytes: int | None = None
    try:
        for candidate_index, (candidate, prepared_response) in enumerate(candidates):
            candidate_directory = temporary / (
                f"candidate-{candidate_index:03d}-resource-{candidate['id']}"
            )
            candidate_directory.mkdir()
            epochs = _run_response_qualifications_v2(
                base_path,
                candidate_directory,
                selected_chaff_resource_id=candidate["id"],
                application_manifest_sha256=base_sha,
                application_resource_id=application["id"],
                url=candidate["url"],
                headers=project_identity_chaff_headers(candidate),
                neqo_client=neqo_client,
                neqo_client_sha256=neqo_client_sha256,
                timeout_seconds=timeout_seconds,
                interval_seconds=interval_seconds,
                max_response_bytes=response_limit,
            )
            all_receipts.extend(receipt for _exit_code, receipt in epochs)
            attempt, expected_response, request_stream_bytes = _candidate_attempt_record_v2(
                candidate_index=candidate_index,
                base_resource=candidate,
                prepared_response=prepared_response,
                epochs=epochs,
                application_manifest_sha256=base_sha,
                application_resource_id=application["id"],
                max_response_bytes=response_limit,
            )
            attempts.append(attempt)
            if attempt["outcome"] == "qualified":
                selected = candidate
                selected_response = expected_response
                selected_request_stream_bytes = request_stream_bytes
                break
        if selected is None or selected_response is None or selected_request_stream_bytes is None:
            raise PreparationError(
                "no frozen response-only candidate passed sustained identity qualification"
            )
        response_digest = attempts[-1]["response_qualification_sha256"]
        sidecar = {
            "schema_version": RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION,
            "artifact_type": RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE,
            "qualification_scope": RESPONSE_ONLY_QUALIFICATION_SCOPE,
            "workload_id": workload_id,
            "base_manifest": {"path": base_path.name, "sha256": base_sha},
            "selection_policy": response_only_selection_policy(base),
            "application_resource_id": application["id"],
            "selected_chaff_resource_id": selected["id"],
            "qualified_parallel_chaff_streams": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
            "request_header_primitive": response_only_request_header_primitive(),
            "method": METHOD,
            "qualification_policy": qualification_policy,
            "response_budget_source": _budget_source(),
            "qualification_source": source,
            "qualification_image_digest": qualification_image,
            "neqo_provenance": _stable_neqo_provenance(all_receipts),
            "implementation_receipt": executed_implementation,
            "candidate_attempts": attempts,
            "resource": {
                "resource_id": selected["id"],
                "url": selected["url"],
                "headers": project_identity_chaff_headers(selected),
                "request_stream_bytes": selected_request_stream_bytes,
                "expected_response": selected_response,
                "response_qualification_sha256": response_digest,
            },
        }
        validated = validate_response_only_sidecar(
            sidecar,
            workload_id=workload_id,
            base_manifest_path=base_path,
            expected_sidecar_schema_version=RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION,
        )
        try:
            with destination.open("xb") as output:
                output.write(canonical_bytes(sidecar))
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            raise FileExistsError(
                f"{destination} already exists; response qualification is create-only"
            ) from None
        completed = True
    finally:
        if completed:
            shutil.rmtree(temporary)
    return QualifiedChaffOutput(
        destination,
        sha256_file(destination),
        validated.manifest_sha256,
    )


def qualify_all_response_chaff(
    workload_ids: Sequence[str],
    *,
    workload_root: Path | None = None,
    qualification_store: Path | None = None,
    qualification_set: str | None = None,
    timeout_seconds: int = 30,
    interval_seconds: int = 30,
    max_response_bytes: int | None = None,
) -> tuple[QualifiedChaffOutput, ...]:
    """Qualify and atomically publish one explicit five-workload response cohort."""

    if max_response_bytes is None:
        return legacy.qualify_all_response_chaff(workload_ids, workload_root=workload_root,
            qualification_store=qualification_store, qualification_set=qualification_set,
            timeout_seconds=timeout_seconds, interval_seconds=interval_seconds)
    cohort = tuple(workload_ids)
    if (
        len(cohort) != 5
        or len(set(cohort)) != 5
        or any(
            not isinstance(workload_id, str)
            or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", workload_id) is None
            for workload_id in cohort
        )
    ):
        raise ValueError("response qualification requires exactly five unique workload IDs")
    store_input = qualification_store or LAB_ROOT / "config/chaff-response-qualification-store"
    store = _regular_directory_without_symlinks(store_input, "response qualification store")
    if qualification_set is None:
        publication_root = store
        destination_name = "v2"
    else:
        destination_name = validate_qualification_set(qualification_set)
        publication_root = _regular_directory_without_symlinks(
            store / "sets", "response qualification sets root"
        )
    destination = publication_root / destination_name
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(
            f"{destination} already exists; batch response qualification is create-only"
        )
    stale = sorted(publication_root.glob(f".{destination_name}.qcsd-batch-*"))
    if stale:
        raise ValueError("response qualification store contains a stale unpublished batch")
    workloads = _regular_directory_without_symlinks(
        workload_root or LAB_ROOT / "config/workloads", "workload root"
    )
    input_hashes: dict[Path, str] = {}
    primary_origins: set[tuple[str, str, int]] = set()
    for workload_id in cohort:
        workload = workloads / f"{workload_id}.json"
        if workload.is_symlink() or not workload.is_file():
            raise ValueError(f"workload manifest is not a regular file: {workload}")
        manifest = load_json(workload)
        validate_research_preparation(manifest, workload_id=workload_id)
        _validate_response_only_v2_policy(
            response_only_v2_qualification_policy(max_response_bytes),
            prepared_max_response_bytes=manifest["preparation"].get("max_response_bytes"),
        )
        application = selected_navigation_root(manifest, workload_id)
        primary_origin = _https_origin(application["url"])
        if primary_origin is None:
            raise ValueError(
                f"response qualification workload has no primary HTTPS origin: {workload_id}"
            )
        primary_origins.add(primary_origin)
        response_only_candidate_resources(manifest, workload_id)
        input_hashes[workload] = sha256_file(workload)
    if len(primary_origins) != 5:
        raise ValueError("response qualification requires five distinct primary HTTPS origins")
    execution_context = _budget_execution_context()
    candidate = Path(
        tempfile.mkdtemp(prefix=f".{destination_name}.qcsd-batch-", dir=publication_root)
    )
    try:
        outputs = [
            qualify_response_chaff_v2(
                workload_id,
                workload_root=workloads,
                qualification_root=candidate,
                timeout_seconds=timeout_seconds,
                interval_seconds=interval_seconds,
                _execution_context=execution_context,
                max_response_bytes=max_response_bytes,
            )
            for workload_id in cohort
        ]
        entries = sorted(candidate.iterdir(), key=lambda path: path.name)
        expected_names = sorted(f"{workload_id}.json" for workload_id in cohort)
        if (
            [path.name for path in entries] != expected_names
            or any(path.is_symlink() or not path.is_file() for path in entries)
            or any(
                sha256_file(output.path) != output.sha256
                for output in outputs
                if output.path.parent == candidate
            )
        ):
            raise ValueError(
                "batch response qualification did not produce the exact five-workload cohort"
            )
        if _regular_directory_without_symlinks(workloads, "workload root") != workloads:
            raise ValueError("batch response qualification input root changed before publication")
        for path, expected_sha256 in input_hashes.items():
            if path.is_symlink() or not path.is_file() or sha256_file(path) != expected_sha256:
                raise ValueError("batch response qualification input changed before publication")
        _bound_neqo_client(execution_context[0])
        directory_fd = os.open(candidate, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        _rename_noreplace(candidate, destination)
        store_fd = os.open(publication_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(store_fd)
        finally:
            os.close(store_fd)
    except Exception:
        # Retain one unpublished same-filesystem candidate for diagnosis.
        raise
    return tuple(
        QualifiedChaffOutput(
            destination / output.path.name,
            sha256_file(destination / output.path.name),
            output.manifest_sha256,
        )
        for output in outputs
    )


def _run_response_qualifications_v2(
    application_path: Path,
    directory: Path,
    *,
    selected_chaff_resource_id: int,
    application_manifest_sha256: str,
    application_resource_id: int,
    url: str,
    headers: list[list[str]],
    neqo_client: Path,
    neqo_client_sha256: str,
    timeout_seconds: int,
    interval_seconds: int,
    max_response_bytes: int = 1_048_576,
) -> list[tuple[int, dict[str, Any]]]:
    """Run three fresh sustained connection epochs for one candidate.

    Representation identity and response-capacity failures are complete
    measurements, so all three epochs are retained before the candidate is
    rejected.  Every network, name-resolution, timeout, or protocol failure is
    an environmental/transport failure and aborts the whole transaction.
    """

    runs: list[tuple[int, dict[str, Any]]] = []
    for index in range(QUALIFICATION_RUNS):
        if index:
            time.sleep(interval_seconds)
        _recheck_bound_neqo_client(neqo_client, neqo_client_sha256)
        output = directory / f"response-{index}"
        result = _run_neqo(
            [
                str(neqo_client),
                "qualify-chaff-response",
                "--workload",
                str(application_path),
                "--application-resource-id",
                "0",
                "--selected-chaff-resource-id",
                str(selected_chaff_resource_id),
                "--output-dir",
                str(output),
                "--timeout-seconds",
                str(timeout_seconds),
                "--max-response-bytes",
                str(max_response_bytes),
                "--packet-size",
                str(UDP_PAYLOAD_CEILING),
                "--parallel-requests",
                str(RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS),
                "--total-requests",
                str(RESPONSE_ONLY_REQUESTS_PER_EPOCH),
                "--request-header-mode",
                IDENTITY_REQUEST_HEADER_MODE,
            ],
            log=directory / f"response-{index}.log",
            configured_timeout_seconds=timeout_seconds,
            label=f"sustained chaff response qualification {index + 1}",
        )
        receipt_path = output / "qualification.json"
        try:
            receipt = load_json(receipt_path)
        except (OSError, TypeError, ValueError) as error:
            raise PreparationError(
                f"sustained chaff response qualification {index + 1} lacks a valid receipt"
            ) from error
        if not isinstance(receipt, Mapping):
            raise PreparationError(
                f"sustained chaff response qualification {index + 1} receipt is not an object"
            )
        failure_class = receipt.get("failure_class")
        if result.returncode == 0:
            if receipt.get("passed") is not True or failure_class is not None:
                raise PreparationError(
                    "successful sustained response qualifier returned an inconsistent receipt"
                )
        elif failure_class not in {"identity", "capacity"}:
            rendered = failure_class if isinstance(failure_class, str) else "unclassified"
            raise PreparationError(
                "sustained response qualification aborted on "
                f"{rendered} failure in epoch {index + 1}"
            )
        try:
            _validate_response_receipt_v2(
                receipt,
                application_manifest_sha256=application_manifest_sha256,
                application_resource_id=application_resource_id,
                selected_chaff_resource_id=selected_chaff_resource_id,
                url=url,
                headers=headers,
                max_response_bytes=max_response_bytes,
            )
        except ValueError as error:
            raise PreparationError(
                f"sustained response qualification epoch {index + 1} is malformed: {error}"
            ) from error
        runs.append((result.returncode, dict(receipt)))
    return runs


def _validate_response_receipt_v2(
    value: object,
    *,
    application_manifest_sha256: str,
    application_resource_id: int,
    selected_chaff_resource_id: int,
    url: str,
    headers: list[list[str]],
    max_response_bytes: int = 1_048_576,
) -> tuple[list[tuple[int, str, int, str]], int, int, int, str, str | None]:
    """Validate one sustained 8x5 response epoch without hiding a rejection."""

    receipt, incoming_limit = _receipt_udp_policy(
        value,
        legacy_keys=RESPONSE_V2_RECEIPT_KEYS,
        legacy_schema=RESPONSE_QUALIFICATION_V2_RECEIPT_SCHEMA_VERSION,
        directional_schema=RESPONSE_V2_DIRECTIONAL_RECEIPT_SCHEMA_VERSION,
        outgoing_ceiling=UDP_PAYLOAD_CEILING,
        label="sustained response qualification receipt",
    )
    started = receipt["started_unix_ns"]
    ended = receipt["ended_unix_ns"]
    invocation_id = receipt["invocation_id"]
    failure_class = receipt["failure_class"]
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"]
        not in {
            RESPONSE_QUALIFICATION_V2_RECEIPT_SCHEMA_VERSION,
            RESPONSE_V2_DIRECTIONAL_RECEIPT_SCHEMA_VERSION,
        }
        or receipt["artifact_type"] != RESPONSE_ARTIFACT_TYPE
        or receipt["application_workload_sha256"] != application_manifest_sha256
        or type(receipt["application_resource_id"]) is not int
        or receipt["application_resource_id"] != application_resource_id
        or type(receipt["selected_chaff_resource_id"]) is not int
        or receipt["selected_chaff_resource_id"] != selected_chaff_resource_id
        or type(receipt["qualified_parallel_chaff_streams"]) is not int
        or receipt["qualified_parallel_chaff_streams"] != RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        or receipt["method"] != METHOD
        or receipt["url"] != url
        or receipt["request_headers"] != headers
        or receipt["request_header_mode"] != IDENTITY_REQUEST_HEADER_MODE
        or type(receipt["parallel_requests"]) is not int
        or receipt["parallel_requests"] != RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        or type(receipt["total_requests"]) is not int
        or receipt["total_requests"] != RESPONSE_ONLY_REQUESTS_PER_EPOCH
        or type(receipt["request_waves"]) is not int
        or receipt["request_waves"] != RESPONSE_ONLY_WAVES_PER_EPOCH
        or type(receipt["max_concurrent_requests"]) is not int
        or receipt["max_concurrent_requests"] != RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        or type(receipt["connection_count"]) is not int
        or receipt["connection_count"] != 1
        or type(receipt["requests_opened_before_first_network_output"]) is not int
        or receipt["requests_opened_before_first_network_output"]
        != RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        or type(receipt["request_stream_bytes"]) is not int
        or receipt["request_stream_bytes"] <= 0
        or type(receipt["max_response_bytes"]) is not int
        or type(max_response_bytes) is not int
        or max_response_bytes not in {1_048_576, *RESPONSE_ONLY_PREPARED_RESPONSE_BUDGETS}
        or receipt["max_response_bytes"] != max_response_bytes
        or type(receipt["udp_payload_ceiling"]) is not int
        or receipt["udp_payload_ceiling"] != UDP_PAYLOAD_CEILING
        or type(started) is not int
        or type(ended) is not int
        or started < 0
        or ended <= started
        or not isinstance(invocation_id, str)
        or not invocation_id.strip()
        or invocation_id != invocation_id.strip()
        or receipt["completion_status"] != "complete"
        or failure_class not in {None, "identity", "capacity"}
    ):
        raise ValueError("sustained response qualification receipt binding is invalid")
    if receipt["passed"] is True:
        if failure_class is not None or receipt["error"] is not None:
            raise ValueError("passing sustained response receipt reports a failure")
    elif receipt["passed"] is False:
        if (
            failure_class not in {"identity", "capacity"}
            or not isinstance(receipt["error"], str)
            or not receipt["error"].strip()
            or receipt["error"] != receipt["error"].strip()
        ):
            raise ValueError("rejected sustained response receipt lacks an exact failure class")
    else:
        raise ValueError("sustained response qualification passed flag is invalid")

    _validate_receipt_neqo_provenance(receipt, label="sustained response qualification")
    requests = receipt["requests"]
    if not isinstance(requests, list) or len(requests) != RESPONSE_ONLY_REQUESTS_PER_EPOCH:
        raise ValueError("sustained response qualification request count is invalid")
    identities: list[tuple[int, str, int, str]] = []
    sizes: list[int] = []
    stream_ids: set[int] = set()
    for index, value_request in enumerate(requests):
        request = _exact_mapping(
            value_request, RESPONSE_V2_REQUEST_KEYS, "sustained response qualification request"
        )
        status = request["status"]
        encoding = request["content_encoding"]
        body_bytes = request["body_bytes"]
        body_sha256 = request["body_sha256"]
        size = request["request_stream_bytes"]
        stream_id = request["stream_id"]
        if (
            type(request["request_index"]) is not int
            or request["request_index"] != index
            or type(request["wave_index"]) is not int
            or request["wave_index"] != index // RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
            or type(stream_id) is not int
            or stream_id != index * 4
            or stream_id in stream_ids
            or type(size) is not int
            or size <= 0
            or type(status) is not int
            or not 100 <= status <= 599
            or not isinstance(encoding, str)
            or encoding != _normalize_content_encoding(encoding)
            or type(body_bytes) is not int
            or body_bytes < 0
            or body_bytes > receipt["max_response_bytes"]
            or not _digest(body_sha256)
            or request["complete"] is not True
            or request["outcome"] != "complete"
        ):
            raise ValueError("sustained response qualification request is invalid")
        stream_ids.add(stream_id)
        identities.append((status, encoding, body_bytes, body_sha256))
        sizes.append(size)
    if len(set(sizes)) != 1 or receipt["request_stream_bytes"] != sizes[0]:
        raise ValueError("sustained response qualification request primitive changed")
    capacity_failure = any(identity[2] < UDP_PAYLOAD_CEILING for identity in identities)
    identity_failure = len(set(identities)) != 1 or any(
        not 200 <= identity[0] <= 299 or identity[1] != "identity" for identity in identities
    )
    derived_failure = "capacity" if capacity_failure else "identity" if identity_failure else None
    if failure_class != derived_failure or receipt["passed"] is (derived_failure is not None):
        raise ValueError("sustained response qualification failure class is inconsistent")

    observations = receipt["packet_observations"]
    if not isinstance(observations, list) or not observations:
        raise ValueError("sustained response qualification packet transcript is missing")
    normalized: list[dict[str, Any]] = []
    qualification_directions: set[str] = set()
    for sequence, value_observation in enumerate(observations):
        observation = _exact_mapping(
            value_observation, PACKET_OBSERVATION_KEYS, "response packet observation"
        )
        if (
            type(observation["sequence"]) is not int
            or observation["sequence"] != sequence
            or observation["phase"] not in {"handshake", "qualification"}
            or observation["direction"] not in {"incoming", "outgoing"}
            or type(observation["udp_payload_bytes"]) is not int
            or not 1 <= observation["udp_payload_bytes"] <= (
                incoming_limit
                if observation["direction"] == "incoming"
                else UDP_PAYLOAD_CEILING
            )
        ):
            raise ValueError("sustained response qualification packet transcript is invalid")
        if observation["phase"] == "qualification":
            qualification_directions.add(observation["direction"])
        normalized.append(observation)
    rust_ordered = [
        {
            "sequence": item["sequence"],
            "phase": item["phase"],
            "direction": item["direction"],
            "udp_payload_bytes": item["udp_payload_bytes"],
        }
        for item in normalized
    ]
    packet_log = json.dumps(rust_ordered, separators=(",", ":")).encode()
    if receipt["packet_log_sha256"] != sha256_bytes(packet_log) or qualification_directions != {
        "incoming",
        "outgoing",
    }:
        raise ValueError("sustained response qualification packet transcript hash is invalid")
    _validate_udp_statistics(
        receipt["packets"], observations=rust_ordered, incoming_limit=incoming_limit
    )
    return identities, sizes[0], started, ended, invocation_id, failure_class


def _candidate_attempt_record_v2(
    *,
    candidate_index: int,
    base_resource: Mapping[str, Any],
    prepared_response: Mapping[str, Any],
    epochs: Sequence[tuple[int, Mapping[str, Any]]],
    application_manifest_sha256: str,
    application_resource_id: int,
    neqo_provenance: Mapping[str, Any] | None = None,
    max_response_bytes: int = 1_048_576,
) -> tuple[dict[str, Any], dict[str, Any] | None, int]:
    """Validate and bind all 120 completions for one deterministic candidate."""

    if len(epochs) != QUALIFICATION_RUNS:
        raise PreparationError("each response-only v2 candidate requires exactly three epochs")
    headers = project_identity_chaff_headers(base_resource)
    identities: list[tuple[int, str, int, str]] = []
    sizes: list[int] = []
    invocation_ids: set[str] = set()
    provenances: list[dict[str, Any]] = []
    prior_end = -1
    records: list[dict[str, Any]] = []
    explicit_failures: set[str] = set()
    for epoch_index, (exit_code, raw_receipt) in enumerate(epochs):
        if type(exit_code) is not int or exit_code < 0:
            raise PreparationError("sustained response qualifier exit code is invalid")
        try:
            epoch_identities, size, started, ended, invocation_id, failure_class = (
                _validate_response_receipt_v2(
                    raw_receipt,
                    application_manifest_sha256=application_manifest_sha256,
                    application_resource_id=application_resource_id,
                    selected_chaff_resource_id=base_resource["id"],
                    url=base_resource["url"],
                    headers=headers,
                    max_response_bytes=max_response_bytes,
                )
            )
        except ValueError as error:
            raise PreparationError(str(error)) from error
        if (exit_code == 0) is (failure_class is not None):
            raise PreparationError("sustained response qualifier exit status is inconsistent")
        if invocation_id in invocation_ids or started <= prior_end:
            raise PreparationError("sustained response epochs are not independent invocations")
        if prior_end >= 0 and started - prior_end < RESPONSE_ONLY_EPOCH_SPACING_SECONDS * 10**9:
            raise PreparationError("sustained response epochs lack the fixed 30-second spacing")
        invocation_ids.add(invocation_id)
        prior_end = ended
        identities.extend(epoch_identities)
        sizes.append(size)
        provenance = _receipt_neqo_provenance(raw_receipt)
        provenances.append(provenance)
        if neqo_provenance is not None and provenance != dict(neqo_provenance):
            raise PreparationError("sustained response epoch Neqo provenance changed")
        if failure_class is not None:
            explicit_failures.add(failure_class)
        records.append(_response_v2_run_record(epoch_index, exit_code, raw_receipt))
    if len({json.dumps(value, sort_keys=True) for value in provenances}) != 1:
        raise PreparationError("sustained response epoch Neqo provenance changed")
    if len(set(sizes)) != 1:
        raise PreparationError("identity chaff request-stream bytes changed across epochs")
    capacity_failure = "capacity" in explicit_failures or any(
        identity[2] < UDP_PAYLOAD_CEILING for identity in identities
    )
    identity_failure = (
        "identity" in explicit_failures
        or len(set(identities)) != 1
        or any(
            not 200 <= identity[0] <= 299 or identity[1] != "identity" for identity in identities
        )
    )
    failure_class = "capacity" if capacity_failure else "identity" if identity_failure else None
    outcome = "qualified" if failure_class is None else "rejected"
    response_digest = qualification_digest(
        "qcsd-chaff-sustained-response-qualification-v3", records
    )
    expected_response: dict[str, Any] | None = None
    if failure_class is None:
        status, encoding, body_bytes, body_sha256 = identities[0]
        expected_response = {
            "status": status,
            "content_encoding": encoding,
            "body_bytes": body_bytes,
            "body_sha256": body_sha256,
        }
        _validate_expected_response(expected_response)
    attempt = {
        "candidate_index": candidate_index,
        "resource_id": base_resource["id"],
        "url": base_resource["url"],
        "prepared_response": _prepared_candidate_response(prepared_response),
        "headers": headers,
        "outcome": outcome,
        "failure_class": failure_class,
        "connection_epochs": records,
        "response_qualification_sha256": response_digest,
    }
    return attempt, expected_response, sizes[0]


def _validate_response_only_candidate_attempt(
    value: object,
    *,
    candidate_index: int,
    base_resource: Mapping[str, Any],
    prepared_response: Mapping[str, Any],
    application_manifest_sha256: str,
    application_resource_id: int,
    neqo_provenance: Mapping[str, Any],
    max_response_bytes: int = 1_048_576,
) -> dict[str, Any]:
    attempt = _exact_mapping(value, CANDIDATE_ATTEMPT_KEYS, "response-only v2 candidate attempt")
    prepared = _exact_mapping(
        attempt["prepared_response"],
        PREPARED_CANDIDATE_RESPONSE_KEYS,
        "response-only v2 prepared candidate response",
    )
    if (
        type(attempt["candidate_index"]) is not int
        or attempt["candidate_index"] != candidate_index
        or type(attempt["resource_id"]) is not int
        or attempt["resource_id"] != base_resource.get("id")
        or attempt["url"] != base_resource.get("url")
        or attempt["headers"] != project_identity_chaff_headers(base_resource)
        or attempt["outcome"] not in {"qualified", "rejected"}
        or attempt["failure_class"] not in {None, "identity", "capacity"}
        or type(prepared["status"]) is not int
        or type(prepared["body_bytes"]) is not int
        or not _digest(prepared["body_sha256"])
    ):
        raise ValueError("response-only v2 candidate attempt binding is invalid")
    epochs_value = attempt["connection_epochs"]
    if not isinstance(epochs_value, list) or len(epochs_value) != QUALIFICATION_RUNS:
        raise ValueError("response-only v2 candidate requires exactly three epochs")
    epochs: list[tuple[int, Mapping[str, Any]]] = []
    for epoch_index, value_epoch in enumerate(epochs_value):
        epoch = _exact_mapping(value_epoch, RESPONSE_V2_RUN_KEYS, "sustained response epoch")
        receipt = epoch["receipt"]
        if not isinstance(receipt, Mapping):
            raise ValueError("sustained response epoch receipt must be an object")
        expected_sha256 = qualification_digest(
            "qcsd-chaff-sustained-response-receipt-object-v3", [receipt]
        )
        if (
            type(epoch["epoch_index"]) is not int
            or epoch["epoch_index"] != epoch_index
            or type(epoch["process_exit_code"]) is not int
            or epoch["process_exit_code"] < 0
            or epoch["receipt_object_sha256"] != expected_sha256
        ):
            raise ValueError("sustained response epoch binding is invalid")
        epochs.append((epoch["process_exit_code"], receipt))
    try:
        expected, _identity, _request_size = _candidate_attempt_record_v2(
            candidate_index=candidate_index,
            base_resource=base_resource,
            prepared_response=prepared_response,
            epochs=epochs,
            application_manifest_sha256=application_manifest_sha256,
            application_resource_id=application_resource_id,
            neqo_provenance=neqo_provenance,
            max_response_bytes=max_response_bytes,
        )
    except PreparationError as error:
        raise ValueError(str(error)) from error
    if dict(attempt) != expected:
        raise ValueError("response-only v2 candidate attempt derivation is inconsistent")
    return dict(attempt)


def response_only_v2_qualification_policy(
    max_response_bytes: int | None = None,
) -> dict[str, Any]:
    """Keep the historical default or declare a prepared-resource byte budget."""

    if max_response_bytes is not None and (
        type(max_response_bytes) is not int
        or max_response_bytes not in RESPONSE_ONLY_PREPARED_RESPONSE_BUDGETS
    ):
        raise ValueError("response qualification requires a declared 16 MiB or 64 MiB budget")
    policy = {
        "qualification_scope": RESPONSE_ONLY_QUALIFICATION_SCOPE,
        "connection_epochs_per_candidate": QUALIFICATION_RUNS,
        "waves_per_connection_epoch": RESPONSE_ONLY_WAVES_PER_EPOCH,
        "parallel_requests_per_wave": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
        "total_requests_per_connection_epoch": RESPONSE_ONLY_REQUESTS_PER_EPOCH,
        "total_completions_per_candidate": RESPONSE_ONLY_COMPLETIONS_PER_CANDIDATE,
        "connection_epoch_spacing_seconds": RESPONSE_ONLY_EPOCH_SPACING_SECONDS,
        "inter_wave_spacing_milliseconds": RESPONSE_ONLY_WAVE_SPACING_MILLISECONDS,
        "qualified_parallel_chaff_streams": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
        "profile": "research-1200",
        "response_defense": "none",
        "seed": 0,
        "udp_payload_ceiling": UDP_PAYLOAD_CEILING,
        "max_response_bytes": 1_048_576,
        "separate_chaff_namespace": True,
    }
    if max_response_bytes is not None:
        policy["max_response_bytes"] = max_response_bytes
        policy["response_budget_policy"] = RESPONSE_ONLY_PREPARED_RESPONSE_BUDGET_POLICY
    return policy


def _validate_response_only_v2_policy(
    value: object,
    *,
    prepared_max_response_bytes: object = None,
) -> int:
    explicit_budget = isinstance(value, Mapping) and "response_budget_policy" in value
    policy = _exact_mapping(
        value,
        RESPONSE_ONLY_V2_POLICY_KEYS | ({"response_budget_policy"} if explicit_budget else set()),
        "response-only v2 chaff qualification policy",
    )
    integer_fields = RESPONSE_ONLY_V2_POLICY_KEYS - {
        "qualification_scope",
        "profile",
        "response_defense",
        "separate_chaff_namespace",
    }
    if (
        any(type(policy[field]) is not int for field in integer_fields)
        or policy["separate_chaff_namespace"] is not True
        or (explicit_budget and (
            type(prepared_max_response_bytes) is not int
            or policy["max_response_bytes"] != prepared_max_response_bytes
        ))
        or dict(policy) != response_only_v2_qualification_policy(
            policy["max_response_bytes"] if explicit_budget else None
        )
    ):
        raise ValueError("response-only v2 qualification policy is not the exact sustained policy")
    return policy["max_response_bytes"]
