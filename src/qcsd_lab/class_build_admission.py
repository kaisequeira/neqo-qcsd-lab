"""Host-only build admission for class-study launcher actions.

The public launcher calls this module before it asks Docker to reconcile stale
state.  It deliberately does *not* duplicate the scientific validators in the
collection image.  Its narrower job is to follow the immutable class-study
authority chain far enough to identify the one no-cache build, then require a
current schema-5 execution receipt and schema-1 completion receipt.

Only the Python standard library and the checkout's exact ``build_storage.py``
are loaded.  This keeps the boundary usable with ``python3 -I`` on the host.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_MAX_AUTHORITY_BYTES = 16 * 1024 * 1024
_MAX_EXPERIMENT_BYTES = 512 * 1024 * 1024
_MAX_FROZEN_INPUT_BYTES = 512 * 1024 * 1024
_MAX_FROZEN_INPUT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
_MAX_FROZEN_INPUT_ENTRIES = 4_096
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_SOURCE_METADATA_KEYS = frozenset(
    {
        "image_digest",
        "lab_commit",
        "lab_dirty",
        "lab_patch_sha256",
        "neqo_commit",
        "neqo_pinned_commit",
        "neqo_dirty",
        "neqo_patch_sha256",
    }
)

_FOUNDATION = "qcsd-class-study-foundation-attestation"
_READINESS = "qcsd-class-study-readiness-attestation"
_HISTORICAL = "qcsd-class-study-historical-snapshot"
_COMPARISON = "qcsd-class-study-comparison-review"
_VALIDATION = "qcsd-class-study-validation-attestation"
_EVALUATION = "qcsd-class-study-evaluation"
_ACQUISITION = "qcsd-class-study-acquisition-provenance"
_ACQUISITION_AUTHORITY = "qcsd-class-study-acquisition-authority"
_ACQUISITION_COMPLETION = "qcsd-class-study-acquisition-completion"
_SUCCESSOR_POLICY = "qcsd-class-study-successor-policy"
_SUCCESSOR_DECISION = "qcsd-class-study-successor-decision"
_SUCCESSOR_RESTART = "qcsd-class-study-successor-restart"
_PINNED_CDP = "qcsd-class-study-pinned-cdp-probe"
_BROWSER_EGRESS = "qcsd-browser-egress-qualification-foundation"
_REFERENCE = "qcsd-buflo-csbuflo-reference-execution"
_CODE_GATE = "qcsd-buflo-study-code-gate"
_CONTROLLED_QUALIFICATION = "qcsd-buflo-study-qualification"
_QUALIFICATION_AUTHORITY = "qcsd-class-study-qualification-authority"
_COHORT = "qcsd-class-study-cohort"
_COHORT_ASSEMBLY = "qcsd-class-study-cohort-assembly"
_CLASS_ROLES = frozenset(
    {
        "pilot-fitting",
        "pilot-compatibility",
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    }
)
_CLASS_FITTED_ROLES = frozenset({"pilot-compatibility", "certification", "formal"})
_PROMOTED_ROLES = frozenset({"canary", "formal"})
_PILOT_QUALIFICATION_SET = "classifier-multiorigin100-v1-pilot120-full-v1"
_AUTHORITATIVE_QUALIFICATION_SET = "classifier-multiorigin100-v1-final100-full-v1"
_COMPATIBILITY_MODES = (
    "undefended",
    "static",
    "front",
    "tamaraw",
    "traffic-morphing",
    "wtf-pad",
    "walkie-talkie",
    "buflo",
    "cs-buflo",
)
_FORMAL_MODES = tuple(name for name in _COMPATIBILITY_MODES if name != "static")
_MODE_KINDS = {
    "undefended": "none",
    "static": "static",
    "front": "front",
    "tamaraw": "tamaraw",
    "traffic-morphing": "traffic_morphing",
    "wtf-pad": "wtf_pad",
    "walkie-talkie": "walkie_talkie",
    "buflo": "buflo",
    "cs-buflo": "cs_buflo",
}
_WORKLOAD_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")

_FOUNDATION_SCHEMA = 4
_READINESS_SCHEMA = 3
_ACQUISITION_SCHEMA = 6
_EVALUATION_SCHEMA = 2
_SUCCESSOR_DECISION_SCHEMA = 3
_SUCCESSOR_RESTART_SCHEMA = 2
_PINNED_CDP_SCHEMA = 14
_HISTORICAL_PINNED_CDP_SCHEMAS = frozenset({8, 9, 11, 12, 13})
# Mirrored from browser_egress_qualification and checked against its producer
# in tests. Importing the package here would break the stdlib-only host gate.
_BROWSER_EGRESS_FOUNDATION_SCHEMA = 6
_HISTORICAL_BROWSER_EGRESS_FOUNDATION_SCHEMAS = frozenset({2, 3, 4, 5})
_BROWSER_EGRESS_FINAL_SCHEMA = 1
_HANDOFF_HISTORICAL_POST = "inputs/class-study-historical-post-snapshot.json"
_BASE_STUDY_ID = "classifier-multiorigin100-v1"
_SUCCESSOR_STUDY_ID = re.compile(
    r"classifier-multiorigin100-v2-g(?:0[1-9]|[1-9][0-9])-[0-9a-f]{12}\Z"
)
_SUCCESSOR_RESTART_KEYS = frozenset(
    {
        "restart_schema_version",
        "artifact_type",
        "study_id",
        "predecessor_study_id",
        "replacement_generation",
        "cumulative_failed_class_ids",
        "successor_identity_sha256",
        "successor_decision",
        "source_sha256",
        "build_execution_identity_sha256",
        "predecessor_foundation_sha256",
        "selection_sha256",
        "namespace",
        "immutable_plan_artifacts",
        "required_restart_gates",
        "downstream_restart",
        "readiness",
        "predecessor_downstream_artifact_reuse_permitted",
    }
)
_QUALIFICATION_AUTHORITY_KEYS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "foundation_attestation",
        "build_execution",
        "build_execution_identity",
        "collection_source",
        "prepare_source",
        "prepare_image_digest",
    }
)
_CURRENT_BUILD_IDENTITY_KEYS = frozenset(
    {
        "cohort_version",
        "sha256",
        "completion_path",
        "completion_sha256",
        "collection_image",
        "started_at",
        "finished_at",
    }
)
_NAMED_QUALIFICATION_SET_KEYS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "qualification_set",
        "qualification_scope",
        "qualification_sidecar_schema_version",
        "workload_count",
        "workload_ids",
        "workloads",
        "bindings_sha256",
        "qualification_authority",
        "qualification_authority_sha256",
    }
)
_NAMED_QUALIFICATION_ENTRY_KEYS = frozenset(
    {
        "index",
        "workload_id",
        "workload_manifest",
        "qualification_sidecar",
        "runtime_manifest_sha256",
        "prefix_pack_spec",
    }
)
_CLASS_STUDY_SIDECAR_KEYS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "workload_id",
        "base_manifest",
        "selection_policy",
        "application_resource_id",
        "selected_chaff_resource_id",
        "qualified_parallel_chaff_streams",
        "walkie_talkie_required_chaff_streams",
        "header_projection",
        "method",
        "qualification_policy",
        "qualification_source",
        "qualification_image_digest",
        "neqo_provenance",
        "implementation_receipt",
        "fitting_source",
        "schema_five_diagnostic",
        "schema_six_capacity_falsification_diagnostic",
        "schema_six_runtime_falsification_diagnostic",
        "schema_two_sender_framing_falsification_diagnostic",
        "prefix_pack_spec",
        "resource",
        "qualification_authority",
        "qualification_authority_sha256",
    }
)
_COHORT_ASSEMBLY_KEYS = frozenset(
    {
        "study_id",
        "assembly_schema_version",
        "eligibility_policy",
        "candidate_catalogue",
        "acquisition_completion",
        "final_selection",
        "stability_root",
        "workload_root",
        "candidates",
        "eligible_count",
        "selected_evidence_count",
        "cohort",
    }
)
_FINAL_FITTING_FILES = frozenset(
    {"traffic-morphing.json", "wtf-pad.json", "walkie-talkie.json", "provenance.json"}
)
_FINAL_PROVENANCE_KEYS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "status",
        "runtime_authorized",
        "stage",
        "bundle_name",
        "qcsd_profile",
        "udp_payload_ceiling",
        "parameter_input_policy",
        "source_result",
        "cohort",
        "fitting_contract",
        "sample_contributions",
        "qualification_inputs",
        "algorithms",
        "artifacts",
    }
)
_FINAL_QUALIFICATION_INPUT_KEYS = frozenset(
    {
        "role",
        "qualification_bytes_excluded",
        "prefix_specification_bytes_excluded",
        "qualification_set",
        "qualification_manifest_sha256",
        "qualification_manifest",
        "qualification_authority",
        "qualification_bindings_sha256",
        "qualification_bindings",
    }
)
_FITTING_COHORT_KEYS = frozenset(
    {
        "role",
        "receipt_sha256",
        "receipt",
        "assembly_receipt_sha256",
        "assembly_receipt",
    }
)
_SUCCESSOR_RUNTIME_ACTIONS = frozenset(
    {
        "status",
        "fit-numeric",
        "prefix-specs",
        "qualify-prefix",
        "finalize-fitting",
        "capture",
        "resume",
        "readiness",
        "historical-snapshot",
        "export",
        "evaluate",
        "comparison-review",
        "attest",
        "verify",
    }
)


class _HistoricalAuthority(ValueError):
    """An intact but pre-current authority, permitted only for inspection."""


@dataclass(frozen=True)
class BuildAdmission:
    """The exact current build pair and all three immutable image IDs."""

    receipt_path: Path
    receipt_sha256: str
    cohort_version: int
    collection_image: str
    prepare_image: str
    reference_image: str
    completion_path: Path
    completion_sha256: str
    completion_payload_sha256: str
    source: Mapping[str, Any]
    identity: Mapping[str, Any]

    def output_fields(self) -> tuple[str, ...]:
        return (
            "required",
            str(self.receipt_path),
            self.receipt_sha256,
            str(self.cohort_version),
            self.collection_image,
            self.prepare_image,
            self.reference_image,
            str(self.completion_path),
            self.completion_sha256,
            self.completion_payload_sha256,
        )


def _canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _under_root(root: Path, raw: str | os.PathLike[str], *, label: str) -> Path:
    text = os.fspath(raw)
    candidate = root / text.removeprefix("/lab/") if text.startswith("/lab/") else Path(text)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{label} is outside the Lab root") from error
    cursor = root
    for component in relative.parts:
        cursor /= component
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"{label} traverses a symbolic link: {cursor}")
    return candidate


def _regular_file(
    root: Path,
    raw: str | os.PathLike[str],
    *,
    label: str,
    max_bytes: int | None = _MAX_AUTHORITY_BYTES,
) -> Path:
    path = _under_root(root, raw, label=label)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ValueError(f"{label} is not a regular file") from error
    if not stat.S_ISREG(metadata.st_mode) or (
        max_bytes is not None and metadata.st_size > max_bytes
    ):
        raise ValueError(f"{label} is not a bounded regular file")
    return path


def _regular_directory(root: Path, raw: str | os.PathLike[str], *, label: str) -> Path:
    path = _under_root(root, raw, label=label)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ValueError(f"{label} is not a regular directory") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} is not a regular directory")
    return path


def _load_json_file(
    root: Path,
    raw: str | os.PathLike[str],
    *,
    label: str,
    max_bytes: int | None = _MAX_AUTHORITY_BYTES,
) -> tuple[Path, Any]:
    path = _regular_file(root, raw, label=label, max_bytes=max_bytes)
    try:
        value = json.loads(
            path.read_bytes(),
            parse_constant=lambda item: (_ for _ in ()).throw(
                ValueError(f"{label} contains non-finite JSON: {item}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is invalid JSON") from error
    return path, value


def _envelope(
    root: Path,
    raw: str | os.PathLike[str],
    *,
    label: str,
    expected_type: str | None = None,
) -> tuple[Path, Mapping[str, Any], Mapping[str, Any]]:
    path, value = _load_json_file(root, raw, label=label)
    if (
        not isinstance(value, Mapping)
        or set(value) != {"schema_version", "receipt_type", "payload_sha256", "payload"}
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or not isinstance(value.get("receipt_type"), str)
        or (expected_type is not None and value.get("receipt_type") != expected_type)
        or not isinstance(value.get("payload"), Mapping)
        or not isinstance(value.get("payload_sha256"), str)
        or value.get("payload_sha256")
        != hashlib.sha256(_canonical_json_bytes(value["payload"])).hexdigest()
    ):
        raise ValueError(f"{label} hash envelope is invalid")
    return path, value, value["payload"]


def _class_campaign_identity(name: object, role: object) -> tuple[str, bool]:
    """Return the exact study identity encoded by one generated campaign name."""

    if not isinstance(name, str) or role not in _CLASS_ROLES:
        raise ValueError("class frozen campaign identity is invalid")
    if name.startswith(f"{_BASE_STUDY_ID}-"):
        study_id = _BASE_STUDY_ID
        successor = False
    else:
        match = re.fullmatch(
            r"(?P<study>classifier-multiorigin100-v2-"
            r"g(?:0[1-9]|[1-9][0-9])-[0-9a-f]{12})-(?P<suffix>.+)",
            name,
        )
        if match is None:
            raise ValueError("class frozen campaign name is not canonical")
        study_id = match.group("study")
        successor = True
    expected_suffix = {
        "pilot-fitting": "pilot-fitting-1200",
        "pilot-compatibility": "pilot-compatibility-1080-1200",
        "authoritative-fitting": (
            "authoritative-fitting-2000-1200" if successor else "authoritative-fitting-1200"
        ),
        "certification": "certification-900-1200",
    }.get(role)
    suffix = name.removeprefix(f"{study_id}-")
    if role in _PROMOTED_ROLES:
        if re.fullmatch(rf"{role}-(?:0[1-9]|10)-1200", suffix) is None:
            raise ValueError("class frozen campaign name is not canonical")
    elif suffix != expected_suffix:
        raise ValueError("class frozen campaign name is not canonical")
    if successor and role not in {
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    }:
        raise ValueError("class frozen successor campaign role is invalid")
    return study_id, successor


def _class_launch_key(
    *,
    study_id: str,
    campaign_name: str,
    evidence_role: str,
    cohort_sha256: str,
    assembly_sha256: str,
) -> str:
    identity = {
        "study_id": study_id,
        "campaign_name": campaign_name,
        "evidence_role": evidence_role,
        "class_study_cohort_sha256": cohort_sha256,
        "class_study_cohort_assembly_sha256": assembly_sha256,
        "uniqueness_policy": "canonical-role-block-and-cohort-assembly-v1",
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _named_qualification_bindings_sha256(value: Mapping[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "bindings_sha256"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(
        f"qcsd-named-chaff-qualification-set-v{value.get('schema_version')}\0".encode() + encoded
    ).hexdigest()


def _bound_file(
    root: Path,
    value: object,
    *,
    label: str,
) -> Path:
    if (
        not isinstance(value, Mapping)
        or not isinstance(value.get("path"), str)
        or not isinstance(value.get("sha256"), str)
        or _DIGEST.fullmatch(value["sha256"]) is None
    ):
        raise ValueError(f"{label} binding is invalid")
    path = _regular_file(root, value["path"], label=label)
    if _sha256(path) != value["sha256"]:
        raise ValueError(f"{label} binding changed")
    return path


def _bound_directory(root: Path, value: object, *, label: str) -> Path:
    if not isinstance(value, Mapping) or not isinstance(value.get("root"), str):
        raise TypeError(f"{label} binding is invalid")
    return _regular_directory(root, value["root"], label=label)


def _load_build_storage(root: Path) -> Any:
    source = _regular_file(
        root,
        root / "src/qcsd_lab/build_storage.py",
        label="build evidence validator",
    )
    specification = importlib.util.spec_from_file_location(
        "_qcsd_class_build_admission_storage", source
    )
    if specification is None or specification.loader is None:
        raise ValueError("cannot load the exact build evidence validator")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _current_build(
    root: Path,
    path: Path,
    *,
    expected_cohort: int | None = None,
    storage: Any | None = None,
) -> BuildAdmission:
    validator = storage if storage is not None else _load_build_storage(root)
    probe = _regular_file(
        root,
        root / "tools/windows_docker_storage_probe.ps1",
        label="Docker storage probe",
    )
    resolved, raw, value, validated, completion = validator.load_validated_build_execution(
        path,
        expected_cohort_version=expected_cohort,
        expected_probe_sha256=_sha256(probe),
        checkout_root=root,
        expected_build_root=root,
        require_current=True,
    )
    if validated.get("schema_version") != 5 or completion is None:
        raise ValueError("class-study current build requires schema 5 and completion schema 1")
    cohort = validated.get("cohort_version")
    images = validated.get("image_ids")
    if (
        type(cohort) is not int
        or cohort < 1
        or not isinstance(images, Mapping)
        or set(images) != {"collection", "prepare", "reference"}
        or any(_IMAGE.fullmatch(str(images.get(name))) is None for name in images)
        or completion.get("schema_version") != 1
    ):
        raise ValueError("class-study current build identity is invalid")
    started_at = value.get("started_at") if isinstance(value, Mapping) else None
    finished_at = value.get("finished_at") if isinstance(value, Mapping) else None
    if not isinstance(started_at, str) or not isinstance(finished_at, str):
        raise ValueError("class-study current build timestamps are invalid")
    completion_path = validator.build_completion_path(resolved, cohort)
    rebound, completion_raw, completion_value = validator.load_stable_build_completion(
        completion_path
    )
    if rebound != completion_path or completion_value != completion:
        raise ValueError("class-study build completion changed after admission")
    receipt_sha256 = hashlib.sha256(raw).hexdigest()
    completion_sha256 = hashlib.sha256(completion_raw).hexdigest()
    identity = {
        "cohort_version": cohort,
        "sha256": receipt_sha256,
        "completion_path": f"/lab/artifacts/buflo-study/build-completion-v{cohort}.json",
        "completion_sha256": completion_sha256,
        "collection_image": images["collection"],
        "started_at": started_at,
        "finished_at": finished_at,
    }
    return BuildAdmission(
        receipt_path=resolved,
        receipt_sha256=receipt_sha256,
        cohort_version=cohort,
        collection_image=images["collection"],
        prepare_image=images["prepare"],
        reference_image=images["reference"],
        completion_path=completion_path,
        completion_sha256=completion_sha256,
        completion_payload_sha256=completion["payload_sha256"],
        source=validated["source"],
        identity=identity,
    )


class _Resolver:
    def __init__(self, root: Path, *, build_loader: Callable[..., BuildAdmission] | None = None):
        self.root = root
        self._storage = None
        self._build_loader = build_loader
        self._seen: dict[tuple[str, Path], BuildAdmission] = {}
        self._successor_restarts: dict[Path, BuildAdmission] = {}
        self._active_successor_restarts: set[Path] = set()
        self._source_constraints: list[tuple[dict[str, Any], str]] = []
        self._qualification_authorities: dict[tuple[str, Path | None], BuildAdmission] = {}

    def build(self, path: Path, *, expected_cohort: int | None = None) -> BuildAdmission:
        key = ("build", path)
        if key not in self._seen:
            if self._build_loader is not None:
                value = self._build_loader(path, expected_cohort=expected_cohort)
            else:
                if self._storage is None:
                    self._storage = _load_build_storage(self.root)
                value = _current_build(
                    self.root,
                    path,
                    expected_cohort=expected_cohort,
                    storage=self._storage,
                )
            self._seen[key] = value
        value = self._seen[key]
        if expected_cohort is not None and value.cohort_version != expected_cohort:
            raise ValueError("class-study build cohort differs from the requested cohort")
        return value

    def foundation(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        path, _value, payload = _envelope(
            self.root, raw, label="class foundation", expected_type=_FOUNDATION
        )
        evidence = payload.get("evidence")
        identity = payload.get("build_execution_identity")
        schema = payload.get("attestation_schema_version")
        if type(schema) is int and schema < _FOUNDATION_SCHEMA:
            raise _HistoricalAuthority(
                "class foundation is historical, not current build authority"
            )
        if (
            payload.get("artifact_type") != _FOUNDATION
            or schema != _FOUNDATION_SCHEMA
            or not isinstance(evidence, Mapping)
            or not isinstance(identity, Mapping)
        ):
            raise ValueError("class foundation is not current build authority")
        build_path = _bound_file(
            self.root, evidence.get("build_execution"), label="foundation build execution"
        )
        cohort = payload.get("cohort_version")
        if type(cohort) is not int or cohort < 1:
            raise ValueError("class foundation cohort is invalid")
        build = self.build(build_path, expected_cohort=cohort)
        if (
            dict(identity) != dict(build.identity)
            or payload.get("source") != build.source
            or _sha256(path) != hashlib.sha256(_canonical_json_bytes(_value)).hexdigest()
        ):
            raise ValueError("class foundation build identity differs from its current build")
        linked = [build]
        for name, route, label in (
            ("pinned_cdp_probe", self.pinned_cdp, "foundation pinned CDP probe"),
            (
                "browser_egress_qualification",
                self.browser_egress,
                "foundation browser-egress qualification",
            ),
            ("reference", self.reference, "foundation reference receipt"),
            ("code_gate", self.code_gate, "foundation code-gate receipt"),
            (
                "controlled_qualification",
                self.controlled_qualification,
                "foundation controlled-qualification receipt",
            ),
        ):
            binding = evidence.get(name)
            if binding is None:
                continue
            authority = (
                _bound_directory(self.root, binding, label=label)
                if name == "browser_egress_qualification"
                else _bound_file(self.root, binding, label=label)
            )
            linked.append(route(authority))
        for name in ("regression_results", "controlled_results"):
            linked.extend(self.result_bindings(evidence.get(name), label=f"foundation {name}"))
        return _require_same_build(linked)

    def readiness(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        _path, _value, payload = _envelope(
            self.root, raw, label="class readiness", expected_type=_READINESS
        )
        evidence = payload.get("evidence")
        schema = payload.get("attestation_schema_version")
        if type(schema) is int and schema < _READINESS_SCHEMA:
            raise _HistoricalAuthority("class readiness is historical")
        if (
            payload.get("artifact_type") != _READINESS
            or schema != _READINESS_SCHEMA
            or not isinstance(evidence, Mapping)
        ):
            raise ValueError("class readiness is not current build authority")
        foundation_path = _bound_file(
            self.root, evidence.get("foundation"), label="readiness foundation"
        )
        build = self.foundation(foundation_path)
        if (
            payload.get("source") != build.source
            or payload.get("build_execution_identity") != build.identity
            or payload.get("cohort_version") != build.cohort_version
        ):
            raise ValueError("class readiness build identity differs from its foundation")
        linked = [build]
        direct = evidence.get("build_execution")
        if direct is not None:
            direct_path = _bound_file(self.root, direct, label="readiness build execution")
            linked.append(self.build(direct_path))
        for name, route, label in (
            (
                "browser_egress_qualification",
                self.browser_egress,
                "readiness browser-egress qualification",
            ),
            ("reference", self.reference, "readiness reference receipt"),
            ("code_gate", self.code_gate, "readiness code-gate receipt"),
            (
                "controlled_qualification",
                self.controlled_qualification,
                "readiness controlled-qualification receipt",
            ),
        ):
            binding = evidence.get(name)
            if binding is None:
                continue
            authority = (
                _bound_directory(self.root, binding, label=label)
                if name == "browser_egress_qualification"
                else _bound_file(self.root, binding, label=label)
            )
            linked.append(route(authority))
        for name in ("regression_results", "controlled_results"):
            linked.extend(self.result_bindings(evidence.get(name), label=f"readiness {name}"))
        for name in (
            "pilot_fitting_result",
            "pilot_compatibility_result",
            "authoritative_fitting_result",
            "certification_result",
        ):
            binding = evidence.get(name)
            if binding is not None:
                linked.append(
                    self.frozen_environment(
                        _bound_directory(self.root, binding, label=f"readiness {name}")
                    )
                )
        completion = evidence.get("acquisition_completion")
        if completion is not None:
            linked.append(
                self.acquisition_completion(
                    _bound_file(
                        self.root,
                        completion,
                        label="readiness acquisition completion",
                    )
                )
            )
        qualification = evidence.get("qualification_context")
        if qualification is not None:
            if not isinstance(qualification, Mapping):
                raise TypeError("readiness qualification context is invalid")
            linked.append(
                self.qualification_authority(
                    qualification.get("qualification_authority"),
                    label="readiness qualification context",
                )
            )
        for name in ("final_selection", "final_cohort_assembly", "pilot_cohort_assembly"):
            binding = evidence.get(name)
            if binding is not None:
                linked.extend(
                    self.carrier_file(
                        _bound_file(self.root, binding, label=f"readiness {name}"),
                        label=f"readiness {name}",
                    )
                )
        for name in ("pilot_numeric_bundle", "authoritative_fitting_bundle"):
            binding = evidence.get(name)
            if binding is not None:
                linked.extend(self.fitting_bundle_binding(binding, label=f"readiness {name}"))
        restart = evidence.get("successor_restart")
        study_id = payload.get("study_id")
        successor_study = isinstance(study_id, str) and _SUCCESSOR_STUDY_ID.fullmatch(study_id)
        if study_id != _BASE_STUDY_ID and not successor_study:
            raise ValueError("class readiness has an invalid study identity")
        if bool(successor_study) != (restart is not None):
            raise ValueError("class readiness successor authority is incomplete")
        if restart is not None:
            linked.append(
                self.successor_restart(
                    _bound_file(self.root, restart, label="readiness successor restart")
                )
            )
        return _require_same_build(linked)

    def historical(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        _path, _value, payload = _envelope(
            self.root, raw, label="class historical snapshot", expected_type=_HISTORICAL
        )
        if (
            payload.get("artifact_type") != _HISTORICAL
            or payload.get("snapshot_schema_version") != 1
        ):
            raise ValueError("class historical snapshot schema is invalid")
        readiness_path = _bound_file(
            self.root, payload.get("readiness"), label="historical snapshot readiness"
        )
        build = self.readiness(readiness_path)
        if payload.get("source") != build.source:
            raise ValueError("class historical snapshot source differs from readiness")
        linked = [build]
        pre = payload.get("pre_formal_snapshot")
        if pre is not None:
            linked.append(
                self.historical(_bound_file(self.root, pre, label="historical pre-formal snapshot"))
            )
        linked.extend(
            self.result_bindings(payload.get("formal_results"), label="historical formal results")
        )
        return _require_same_build(linked)

    def handoff(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        root = _regular_directory(self.root, raw, label="class handoff")
        return self.historical(root / _HANDOFF_HISTORICAL_POST)

    def acquisition_authority(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        """Resolve acquisition-only proof without accepting it as a foundation."""

        _path, _value, payload = _envelope(
            self.root,
            raw,
            label="class acquisition authority",
            expected_type=_ACQUISITION_AUTHORITY,
        )
        evidence = payload.get("evidence")
        cohort = payload.get("cohort_version")
        if (
            payload.get("artifact_type") != _ACQUISITION_AUTHORITY
            or type(payload.get("attestation_schema_version")) is not int
            or payload.get("attestation_schema_version") != 1
            or payload.get("authority_scope") != "public-page-acquisition-only"
            or payload.get("promotion_authority") is not False
            or payload.get("no_waivers") is not True
            or type(cohort) is not int
            or cohort < 1
            or not isinstance(evidence, Mapping)
        ):
            raise ValueError("class acquisition authority is not current acquisition-only proof")
        build = self.build(
            _bound_file(self.root, evidence.get("build_execution"), label="acquisition build"),
            expected_cohort=cohort,
        )
        if (
            payload.get("source") != build.source
            or payload.get("prepare_source")
            != {**dict(build.source), "image_digest": build.prepare_image}
            or payload.get("build_execution_identity") != build.identity
        ):
            raise ValueError("class acquisition authority differs from its current build")
        study = _bound_file(
            self.root, payload.get("study_contract"), label="acquisition study contract"
        )
        if study != self.root / "config/class-study/v1/study.json":
            raise ValueError("class acquisition authority binds another study contract")
        correctness = payload.get("acquisition_correctness")
        if (
            not isinstance(correctness, Mapping)
            or correctness.get("source") != build.source
            or correctness.get("build_execution_identity") != build.identity
            or correctness.get("study_contract") != payload.get("study_contract")
        ):
            raise ValueError("acquisition correctness proof differs from its current build")
        # The image validator reconstructs the complete correctness command/log
        # and 110-vector packet evidence; this host boundary resolves their build.
        return _require_same_build(
            (
                build,
                self.pinned_cdp(
                    _bound_file(
                        self.root,
                        evidence.get("pinned_cdp_probe"),
                        label="acquisition pinned CDP probe",
                    )
                ),
                self.browser_egress(
                    _bound_directory(
                        self.root,
                        evidence.get("browser_egress_qualification"),
                        label="acquisition browser-egress qualification",
                    )
                ),
            )
        )

    def acquisition_authority_or_foundation(
        self, raw: str | os.PathLike[str]
    ) -> BuildAdmission:
        _path, value = _load_json_file(self.root, raw, label="acquisition authority")
        receipt_type = value.get("receipt_type") if isinstance(value, Mapping) else None
        if receipt_type == _ACQUISITION_AUTHORITY:
            return self.acquisition_authority(raw)
        if receipt_type == _FOUNDATION:
            return self.foundation(raw)
        raise ValueError("acquisition authority must be acquisition-only or full foundation")

    def acquisition(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        runner = _regular_directory(self.root, raw, label="class acquisition root")
        _path, _value, payload = _envelope(
            self.root,
            runner / "provenance.json",
            label="class acquisition provenance",
            expected_type=_ACQUISITION,
        )
        schema = payload.get("acquisition_schema_version")
        if type(schema) is int and schema < _ACQUISITION_SCHEMA:
            raise _HistoricalAuthority("class acquisition provenance is historical")
        if type(schema) is not int or schema != _ACQUISITION_SCHEMA:
            raise ValueError("class acquisition provenance schema is invalid")
        if "foundation_attestation" in payload:
            raise ValueError("current acquisition provenance contains a legacy foundation binding")
        authority_path = _bound_file(
            self.root,
            payload.get("acquisition_authority"),
            label="acquisition authority",
        )
        build = self.acquisition_authority_or_foundation(authority_path)
        expected_source = {**dict(build.source), "image_digest": build.prepare_image}
        if (
            payload.get("image_digest") != build.prepare_image
            or payload.get("source") != expected_source
        ):
            raise ValueError("class acquisition source differs from the authority build")
        return build

    def comparison(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        _path, _value, payload = _envelope(
            self.root, raw, label="class comparison review", expected_type=_COMPARISON
        )
        if payload.get("artifact_type") != _COMPARISON:
            raise ValueError("class comparison review schema is invalid")
        linked = [
            self.handoff(
                _bound_directory(self.root, payload.get("handoff"), label="review handoff")
            )
        ]
        linked.append(
            self.evaluation(
                _bound_file(
                    self.root,
                    payload.get("evaluation"),
                    label="review evaluation receipt",
                )
            )
        )
        return _require_same_build(linked)

    def evaluation(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        _path, _value, payload = _envelope(
            self.root, raw, label="class evaluation", expected_type=_EVALUATION
        )
        schema = payload.get("schema_version")
        if schema == 1:
            raise _HistoricalAuthority("class evaluation is historical")
        if payload.get("artifact_type") != _EVALUATION or schema != _EVALUATION_SCHEMA:
            raise ValueError("class evaluation schema is invalid")
        return self.handoff(
            _bound_directory(self.root, payload.get("handoff"), label="evaluation handoff")
        )

    def validation(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        _path, _value, payload = _envelope(
            self.root, raw, label="class validation attestation", expected_type=_VALIDATION
        )
        evidence = payload.get("evidence")
        if (
            payload.get("artifact_type") != _VALIDATION
            or payload.get("attestation_schema_version") != 1
            or not isinstance(evidence, Mapping)
        ):
            raise ValueError("class validation attestation schema is invalid")
        readiness_path = _bound_file(
            self.root, evidence.get("readiness"), label="validation readiness"
        )
        build = self.readiness(readiness_path)
        _readiness_path, _readiness_value, readiness_payload = _envelope(
            self.root,
            readiness_path,
            label="validation readiness",
            expected_type=_READINESS,
        )
        readiness_evidence = readiness_payload.get("evidence")
        if not isinstance(readiness_evidence, Mapping):
            raise TypeError("validation readiness evidence is invalid")
        if payload.get("source") != build.source:
            raise ValueError("class validation source differs from readiness")
        linked = [build]
        if evidence.get("evaluation") is None:
            raise ValueError("class validation attestation omits its mandatory evaluation")
        expected_restart = readiness_evidence.get("successor_restart")
        observed_restart = evidence.get("successor_restart")
        if (expected_restart is None) != (observed_restart is None) or (
            expected_restart is not None and expected_restart != observed_restart
        ):
            raise ValueError("class validation successor restart differs from readiness")
        for name, route, label in (
            ("historical_pre_snapshot", self.historical, "validation historical pre"),
            ("historical_post_snapshot", self.historical, "validation historical post"),
            ("handoff", self.handoff, "validation handoff"),
            ("comparison_review", self.comparison, "validation comparison review"),
            ("evaluation", self.evaluation, "validation evaluation"),
            ("successor_restart", self.successor_restart, "validation successor restart"),
        ):
            binding = evidence.get(name)
            if binding is None:
                continue
            authority = (
                _bound_directory(self.root, binding, label=label)
                if name == "handoff"
                else _bound_file(self.root, binding, label=label)
            )
            linked.append(route(authority))
        for name in ("canary_results", "formal_results"):
            linked.extend(self.result_bindings(evidence.get(name), label=f"validation {name}"))
        return _require_same_build(linked)

    def pinned_cdp(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        _path, _value, payload = _envelope(
            self.root, raw, label="pinned CDP receipt", expected_type=_PINNED_CDP
        )
        schema = payload.get("probe_schema_version")
        if type(schema) is int and schema in _HISTORICAL_PINNED_CDP_SCHEMAS:
            raise _HistoricalAuthority("pinned CDP receipt is historical")
        binding = payload.get("build_execution")
        cohort = payload.get("cohort_version")
        if (
            type(schema) is not int
            or schema != _PINNED_CDP_SCHEMA
            or payload.get("artifact_type") != _PINNED_CDP
            or type(cohort) is not int
            or cohort < 1
            or not isinstance(binding, Mapping)
        ):
            raise ValueError("pinned CDP receipt is not current build authority")
        build = self.build(
            _bound_file(self.root, binding, label="pinned CDP build execution"),
            expected_cohort=cohort,
        )
        if (
            payload.get("build_execution_identity") != build.identity
            or payload.get("collection_source") != build.source
            or payload.get("prepare_image_digest") != build.prepare_image
            or payload.get("prepare_source")
            != {**dict(build.source), "image_digest": build.prepare_image}
        ):
            raise ValueError("pinned CDP receipt differs from its current build")
        return build

    def browser_egress(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        root = _regular_directory(self.root, raw, label="browser-egress qualification")
        foundation_path, foundation_value, payload = _envelope(
            self.root,
            root / "foundation.json",
            label="browser-egress foundation",
            expected_type=_BROWSER_EGRESS,
        )
        schema = payload.get("schema_version")
        if type(schema) is int and schema in _HISTORICAL_BROWSER_EGRESS_FOUNDATION_SCHEMAS:
            raise _HistoricalAuthority("browser-egress qualification is historical")
        binding = payload.get("build_execution")
        cohort = payload.get("cohort_version")
        if (
            type(schema) is not int
            or schema != _BROWSER_EGRESS_FOUNDATION_SCHEMA
            or type(cohort) is not int
            or cohort < 1
            or not isinstance(binding, Mapping)
        ):
            raise ValueError("browser-egress qualification has no current build authority")
        _final_path, _final_value, final_payload = _envelope(
            self.root,
            root / "final.json",
            label="browser-egress final receipt",
            expected_type="qcsd-browser-egress-qualification-final",
        )
        expected_foundation = {
            "path": "foundation.json",
            "sha256": _sha256(foundation_path),
            "payload_sha256": foundation_value["payload_sha256"],
        }
        if (
            type(final_payload.get("schema_version")) is not int
            or final_payload.get("schema_version") != _BROWSER_EGRESS_FINAL_SCHEMA
            or type(final_payload.get("cohort_version")) is not int
            or final_payload.get("cohort_version") != cohort
            or final_payload.get("verdict") != "passed"
            or final_payload.get("foundation") != expected_foundation
        ):
            raise ValueError("browser-egress final receipt differs from its foundation")
        build = self.build(
            _bound_file(self.root, binding, label="browser-egress build execution"),
            expected_cohort=cohort,
        )
        if (
            binding.get("completion_path")
            != f"/lab/artifacts/buflo-study/build-completion-v{cohort}.json"
            or binding.get("completion_sha256") != build.completion_sha256
            or binding.get("collection_image_id") != build.collection_image
            or binding.get("prepare_image_id") != build.prepare_image
            or binding.get("reference_image_id") != build.reference_image
            or payload.get("source") != {**dict(build.source), "image_digest": build.prepare_image}
        ):
            raise ValueError("browser-egress qualification differs from its current build")
        return build

    def reference(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        _path, value = _load_json_file(self.root, raw, label="reference execution receipt")
        schema = value.get("schema_version") if isinstance(value, Mapping) else None
        if schema == 1:
            raise _HistoricalAuthority("reference execution receipt is historical")
        execution = value.get("build_execution") if isinstance(value, Mapping) else None
        receipt = execution.get("receipt") if isinstance(execution, Mapping) else None
        cohort = receipt.get("cohort_version") if isinstance(receipt, Mapping) else None
        if (
            schema != 2
            or value.get("artifact_type") != _REFERENCE
            or type(cohort) is not int
            or cohort < 1
            or not isinstance(execution, Mapping)
        ):
            raise ValueError("reference execution receipt has no current build authority")
        build = self.build(
            self.root / f"artifacts/buflo-study/build-execution-v{cohort}.json",
            expected_cohort=cohort,
        )
        image = value.get("reference_image")
        if (
            receipt != json.loads(build.receipt_path.read_bytes())
            or execution.get("sha256") != build.receipt_sha256
            or execution.get("completion_path")
            != f"/lab/artifacts/buflo-study/build-completion-v{cohort}.json"
            or execution.get("completion_sha256") != build.completion_sha256
            or execution.get("completion_payload_sha256") != build.completion_payload_sha256
            or execution.get("completion") != json.loads(build.completion_path.read_bytes())
            or not isinstance(image, Mapping)
            or image.get("id") != build.reference_image
        ):
            raise ValueError("reference execution receipt differs from its current build")
        return build

    def _plain_gate(
        self,
        raw: str | os.PathLike[str],
        *,
        label: str,
        artifact_type: str,
        build_key: str,
    ) -> BuildAdmission:
        _path, value = _load_json_file(self.root, raw, label=label)
        schema = value.get("schema_version") if isinstance(value, Mapping) else None
        if schema == 1:
            raise _HistoricalAuthority(f"{label} is historical")
        binding = value.get(build_key) if isinstance(value, Mapping) else None
        cohort = value.get("cohort_version") if isinstance(value, Mapping) else None
        if (
            schema != 2
            or value.get("artifact_type") != artifact_type
            or type(cohort) is not int
            or cohort < 1
            or not isinstance(binding, Mapping)
        ):
            raise ValueError(f"{label} has no current build authority")
        build = self.build(
            _bound_file(self.root, binding, label=f"{label} build execution"),
            expected_cohort=cohort,
        )
        if value.get("source") != build.source:
            raise ValueError(f"{label} source differs from its current build")
        return build

    def code_gate(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        return self._plain_gate(
            raw,
            label="code-gate receipt",
            artifact_type=_CODE_GATE,
            build_key="build_execution_receipt",
        )

    def controlled_qualification(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        return self._plain_gate(
            raw,
            label="controlled-qualification receipt",
            artifact_type=_CONTROLLED_QUALIFICATION,
            build_key="build_execution",
        )

    def result_bindings(self, value: object, *, label: str) -> list[BuildAdmission]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise TypeError(f"{label} bindings are invalid")
        result: list[BuildAdmission] = []
        for ordinal, binding in enumerate(value, start=1):
            result.append(
                self.frozen_environment(
                    _bound_directory(self.root, binding, label=f"{label} binding {ordinal}")
                )
            )
        return result

    def fitting_bundle_binding(self, value: object, *, label: str) -> list[BuildAdmission]:
        if (
            not isinstance(value, Mapping)
            or not isinstance(value.get("root"), str)
            or not isinstance(value.get("provenance"), str)
            or not isinstance(value.get("provenance_sha256"), str)
            or _DIGEST.fullmatch(value["provenance_sha256"]) is None
        ):
            raise TypeError(f"{label} fitting-bundle binding is invalid")
        root = _regular_directory(self.root, value["root"], label=label)
        provenance = _regular_file(
            self.root,
            root / value["provenance"],
            label=f"{label} provenance",
        )
        if _sha256(provenance) != value["provenance_sha256"]:
            raise ValueError(f"{label} provenance binding changed")
        return self.carrier_file(provenance, label=f"{label} provenance")

    def qualification_authority(
        self,
        value: object,
        *,
        label: str,
        frozen_foundation: Path | None = None,
    ) -> BuildAdmission:
        if not isinstance(value, Mapping) or set(value) != _QUALIFICATION_AUTHORITY_KEYS:
            raise TypeError(f"{label} qualification authority is invalid")
        frozen_key = (
            _under_root(
                self.root,
                frozen_foundation,
                label=f"{label} frozen foundation",
            )
            if frozen_foundation is not None
            else None
        )
        cache_key = (
            hashlib.sha256(_canonical_json_bytes(value)).hexdigest(),
            frozen_key,
        )
        cached = self._qualification_authorities.get(cache_key)
        if cached is not None:
            return cached
        schema = value.get("schema_version")
        if schema == 1:
            raise _HistoricalAuthority(f"{label} qualification authority is historical")
        foundation = value.get("foundation_attestation")
        direct = value.get("build_execution")
        identity = value.get("build_execution_identity")
        if (
            schema != 2
            or value.get("artifact_type") != _QUALIFICATION_AUTHORITY
            or not isinstance(foundation, Mapping)
            or set(foundation) != {"path", "sha256", "payload_sha256"}
            or not isinstance(foundation.get("path"), str)
            or _DIGEST.fullmatch(str(foundation.get("sha256"))) is None
            or _DIGEST.fullmatch(str(foundation.get("payload_sha256"))) is None
            or not isinstance(direct, Mapping)
            or set(direct) != {"path", "sha256"}
            or not isinstance(direct.get("path"), str)
            or _DIGEST.fullmatch(str(direct.get("sha256"))) is None
            or not isinstance(identity, Mapping)
            or set(identity) != _CURRENT_BUILD_IDENTITY_KEYS
        ):
            raise ValueError(f"{label} qualification authority is not current")
        foundation_path = (
            _regular_file(
                self.root,
                frozen_foundation,
                label=f"{label} frozen foundation",
            )
            if frozen_foundation is not None
            else _bound_file(self.root, foundation, label=f"{label} foundation")
        )
        _foundation_path, foundation_envelope, foundation_payload = _envelope(
            self.root,
            foundation_path,
            label=f"{label} foundation",
            expected_type=_FOUNDATION,
        )
        foundation_build = self.foundation(foundation_path)
        foundation_evidence = foundation_payload.get("evidence")
        direct_build = self.build(_bound_file(self.root, direct, label=f"{label} build execution"))
        build = _require_same_build((foundation_build, direct_build))
        if (
            foundation.get("sha256") != _sha256(foundation_path)
            or foundation.get("payload_sha256") != foundation_envelope["payload_sha256"]
            or not isinstance(foundation_evidence, Mapping)
            or direct != foundation_evidence.get("build_execution")
            or dict(identity) != dict(build.identity)
            or value.get("collection_source") != build.source
            or value.get("prepare_source")
            != {**dict(build.source), "image_digest": build.prepare_image}
            or value.get("prepare_image_digest") != build.prepare_image
        ):
            raise ValueError(f"{label} qualification authority differs from its build")
        self._qualification_authorities[cache_key] = build
        return build

    def carrier_value(
        self,
        value: object,
        *,
        label: str,
        frozen_foundation: Path | None = None,
    ) -> list[BuildAdmission]:
        """Find typed qualification authorities in one bounded JSON carrier."""

        found: list[BuildAdmission] = []
        pending: list[tuple[object, int]] = [(value, 0)]
        visited_containers = 0
        while pending:
            current, depth = pending.pop()
            if depth > 32:
                raise ValueError(f"{label} authority carrier is too deeply nested")
            if isinstance(current, Mapping):
                visited_containers += 1
                if visited_containers > 4_000_000:
                    raise ValueError(f"{label} authority carrier is too large")
                if current.get("artifact_type") == _QUALIFICATION_AUTHORITY:
                    found.append(
                        self.qualification_authority(
                            current,
                            label=label,
                            frozen_foundation=frozen_foundation,
                        )
                    )
                    continue
                pending.extend((item, depth + 1) for item in current.values())
            elif isinstance(current, list):
                visited_containers += 1
                if visited_containers > 4_000_000:
                    raise ValueError(f"{label} authority carrier is too large")
                pending.extend((item, depth + 1) for item in current)
        return found

    def frozen_json_carriers(
        self,
        inputs: Path,
        experiment: object,
        *,
        frozen_foundation: Path,
    ) -> list[BuildAdmission]:
        """Close typed build edges in every bounded frozen JSON carrier."""

        files: list[Path] = []
        pending: list[tuple[Path, int]] = [(inputs, 0)]
        observed_entries = 0
        while pending:
            directory, depth = pending.pop()
            try:
                with os.scandir(directory) as iterator:
                    entries: list[tuple[str, Path, os.stat_result]] = []
                    for entry in iterator:
                        observed_entries += 1
                        if observed_entries > _MAX_FROZEN_INPUT_ENTRIES:
                            raise ValueError(
                                "class frozen inputs contain too many filesystem entries"
                            )
                        entries.append(
                            (
                                entry.name,
                                Path(entry.path),
                                entry.stat(follow_symlinks=False),
                            )
                        )
            except OSError as error:
                raise ValueError("class frozen input inventory is not readable") from error
            for _name, path, metadata in sorted(entries, reverse=True):
                if stat.S_ISDIR(metadata.st_mode):
                    if depth >= 32:
                        raise ValueError("class frozen input inventory is too deeply nested")
                    pending.append((path, depth + 1))
                elif stat.S_ISREG(metadata.st_mode):
                    if path.suffix == ".json":
                        files.append(path)
                else:
                    raise ValueError(
                        f"class frozen input inventory contains an unsafe entry: {path}"
                    )
        files.sort()
        if len(files) > 2_048:
            raise ValueError("class frozen inputs contain too many JSON carriers")
        total_bytes = 0
        linked = self.carrier_value(
            experiment,
            label="class frozen experiment",
            frozen_foundation=frozen_foundation,
        )
        for path in files:
            bounded = _regular_file(
                self.root,
                path,
                label=f"class frozen input {path.relative_to(inputs)}",
                max_bytes=_MAX_FROZEN_INPUT_BYTES,
            )
            total_bytes += bounded.stat().st_size
            if total_bytes > _MAX_FROZEN_INPUT_TOTAL_BYTES:
                raise ValueError("class frozen JSON inputs exceed the aggregate size limit")
            _path, value = _load_json_file(
                self.root,
                bounded,
                label=f"class frozen input {path.relative_to(inputs)}",
                max_bytes=_MAX_FROZEN_INPUT_BYTES,
            )
            linked.extend(
                self.carrier_value(
                    value,
                    label=f"class frozen input {path.relative_to(inputs)}",
                    frozen_foundation=frozen_foundation,
                )
            )
        return linked

    def frozen_defense_inventory(
        self,
        result: Path,
        configuration: Mapping[str, Any],
        *,
        role: str,
    ) -> None:
        """Bind the exact role mode order and every frozen external input."""

        expected_modes = (
            ("undefended",)
            if role in {"pilot-fitting", "authoritative-fitting", "canary"}
            else _FORMAL_MODES
            if role == "formal"
            else _COMPATIBILITY_MODES
        )
        records = configuration.get("defenses")
        if not isinstance(records, list) or len(records) != len(expected_modes):
            raise ValueError(f"class frozen {role} defense inventory is invalid")
        common_parameters = {
            "traffic-morphing": "traffic-morphing.json",
            "wtf-pad": "wtf-pad.json",
            "walkie-talkie": "walkie-talkie.json",
        }
        for name, record in zip(expected_modes, records, strict=True):
            if not isinstance(record, Mapping):
                raise TypeError(f"class frozen {role} defense inventory is invalid")
            base = {"name", "kind", "baseline"}
            if (
                record.get("name") != name
                or record.get("kind") != _MODE_KINDS[name]
                or record.get("baseline") is not (name == "undefended")
            ):
                raise ValueError(f"class frozen {role} defense inventory is invalid")
            if name == "static":
                expected_keys = base | {"schedule", "schedule_sha256", "mode"}
                expected_path = "inputs/defense-parameters/static/schedule.csv"
                if (
                    set(record) != expected_keys
                    or record.get("schedule") != expected_path
                    or record.get("mode") != "chaff-only"
                ):
                    raise ValueError("class frozen static defense binding is invalid")
                schedule = _regular_file(
                    self.root,
                    result / expected_path,
                    label="class frozen static schedule",
                    max_bytes=_MAX_FROZEN_INPUT_BYTES,
                )
                if record.get("schedule_sha256") != _sha256(schedule):
                    raise ValueError("class frozen static schedule hash changed")
                continue
            parameter_filename = common_parameters.get(name)
            if parameter_filename is not None:
                parameter_path = f"inputs/defense-parameters/class-study/{parameter_filename}"
                provenance_path = "inputs/defense-parameters/class-study/provenance.json"
                input_policy = (
                    "sealed-class-study-pilot-fitting-v1"
                    if role == "pilot-compatibility"
                    else "sealed-class-study-fitting-v1"
                )
            elif name in {"buflo", "cs-buflo"}:
                parameter_path = f"inputs/defense-parameters/{name}/parameters.json"
                provenance_path = f"inputs/defense-parameters/{name}/provenance.json"
                input_policy = "reviewed-buflo-study-candidate-v1"
            else:
                if set(record) != base:
                    raise ValueError(f"class frozen {name} defense binding is invalid")
                continue
            expected_keys = base | {
                "parameters",
                "parameters_sha256",
                "provenance",
                "provenance_sha256",
                "input_policy",
            }
            if (
                set(record) != expected_keys
                or record.get("parameters") != parameter_path
                or record.get("provenance") != provenance_path
                or record.get("input_policy") != input_policy
            ):
                raise ValueError(f"class frozen {name} defense binding is invalid")
            parameter = _regular_file(
                self.root,
                result / parameter_path,
                label=f"class frozen {name} parameters",
                max_bytes=_MAX_FROZEN_INPUT_BYTES,
            )
            provenance = _regular_file(
                self.root,
                result / provenance_path,
                label=f"class frozen {name} provenance",
                max_bytes=_MAX_FROZEN_INPUT_BYTES,
            )
            if record.get("parameters_sha256") != _sha256(parameter) or record.get(
                "provenance_sha256"
            ) != _sha256(provenance):
                raise ValueError(f"class frozen {name} defense input hash changed")

    def frozen_workload_inventory(
        self,
        result: Path,
        configuration: Mapping[str, Any],
        *,
        role: str,
        workload_ids: Sequence[str],
    ) -> None:
        """Bind every role-specific workload input and exact directory inventory."""

        records = configuration.get("workloads")
        if not isinstance(records, list) or len(records) != len(workload_ids):
            raise ValueError(f"class frozen {role} workload inventory is invalid")
        fitted = role in _CLASS_FITTED_ROLES
        base_keys = {"id", "visits", "manifest", "sha256", "resource_count", "origin_count"}
        fitted_keys = base_keys | {
            "chaff_qualification",
            "chaff_qualification_sha256",
            "chaff_manifest",
            "chaff_manifest_sha256",
            "runtime_manifest",
            "runtime_manifest_sha256",
            "chaff_prefix_spec",
            "chaff_prefix_spec_sha256",
        }
        expected_visits = {
            "pilot-fitting": 2,
            "pilot-compatibility": 1,
            "authoritative-fitting": 10,
            "certification": 1,
            "canary": 1,
            "formal": 2,
        }[role]
        inventory: dict[str, set[str]] = {
            "workloads": set(),
            "runtime-workloads": set(),
            "chaff-qualifications": set(),
            "chaff-manifests": set(),
            "chaff-prefix-specs": set(),
        }
        for workload_id, record in zip(workload_ids, records, strict=True):
            if (
                not isinstance(record, Mapping)
                or set(record) != (fitted_keys if fitted else base_keys)
                or record.get("id") != workload_id
                or record.get("visits") != expected_visits
            ):
                raise ValueError(f"class frozen {role} workload record is invalid")
            expected_paths = {
                "manifest": f"inputs/workloads/{workload_id}.json",
            }
            if fitted:
                expected_paths.update(
                    chaff_qualification=(f"inputs/chaff-qualifications/{workload_id}.json"),
                    chaff_manifest=f"inputs/chaff-manifests/{workload_id}.json",
                    runtime_manifest=f"inputs/runtime-workloads/{workload_id}.json",
                    chaff_prefix_spec=f"inputs/chaff-prefix-specs/{workload_id}.json",
                )
            for field, relative in expected_paths.items():
                if record.get(field) != relative:
                    raise ValueError(f"class frozen {workload_id} {field} path is invalid")
                path = _regular_file(
                    self.root,
                    result / relative,
                    label=f"class frozen {workload_id} {field}",
                    max_bytes=_MAX_FROZEN_INPUT_BYTES,
                )
                if record.get(f"{field}_sha256" if field != "manifest" else "sha256") != _sha256(
                    path
                ):
                    raise ValueError(f"class frozen {workload_id} {field} hash changed")
                inventory[Path(relative).parent.name].add(path.name)
        expected_files = {f"{workload_id}.json" for workload_id in workload_ids}
        for dirname, observed in inventory.items():
            path = result / "inputs" / dirname
            if dirname != "workloads" and not fitted:
                if path.exists() or path.is_symlink():
                    raise ValueError(f"class frozen {role} has unexpected {dirname}")
                continue
            directory = _regular_directory(
                self.root,
                path,
                label=f"class frozen {dirname}",
            )
            expected_directory_files = (
                expected_files | {"_qualification-set.json"}
                if dirname == "chaff-qualifications"
                else expected_files
            )
            if (
                observed != expected_files
                or {entry.name for entry in directory.iterdir()} != expected_directory_files
            ):
                raise ValueError(f"class frozen {dirname} inventory is invalid")

        parameters = _regular_directory(
            self.root,
            result / "inputs/defense-parameters",
            label="class frozen defense-parameter root",
        )
        expected_parameter_dirs = (
            {"class-study", "buflo", "cs-buflo", "static"}
            if fitted and role != "formal"
            else {"class-study", "buflo", "cs-buflo"}
            if fitted
            else set()
        )
        if {entry.name for entry in parameters.iterdir()} != expected_parameter_dirs:
            raise ValueError("class frozen defense-parameter inventory is invalid")
        if fitted:
            for name in ("buflo", "cs-buflo"):
                directory = _regular_directory(
                    self.root,
                    parameters / name,
                    label=f"class frozen {name} parameter directory",
                )
                if {entry.name for entry in directory.iterdir()} != {
                    "parameters.json",
                    "provenance.json",
                }:
                    raise ValueError(f"class frozen {name} parameter inventory is invalid")
            if role != "formal":
                static = _regular_directory(
                    self.root,
                    parameters / "static",
                    label="class frozen static parameter directory",
                )
                if {entry.name for entry in static.iterdir()} != {"schedule.csv"}:
                    raise ValueError("class frozen static parameter inventory is invalid")

    def _record_fitting_source(self, value: object, *, label: str) -> None:
        """Record the exact source projection carried by fitting provenance.

        Numeric provenance deliberately has no embedded build receipt.  Its
        source-result fingerprints therefore constrain a separately resolved
        completed build; they never create build authority by themselves.
        """

        if not isinstance(value, Mapping) or "source_result" not in value:
            return
        source_result = value.get("source_result")
        source = (
            source_result.get("source_fingerprints") if isinstance(source_result, Mapping) else None
        )
        if (
            not isinstance(source, Mapping)
            or set(source) != _SOURCE_METADATA_KEYS
            or _IMAGE.fullmatch(str(source.get("image_digest"))) is None
            or _COMMIT.fullmatch(str(source.get("lab_commit"))) is None
            or _COMMIT.fullmatch(str(source.get("neqo_commit"))) is None
            or _COMMIT.fullmatch(str(source.get("neqo_pinned_commit"))) is None
            or source.get("neqo_commit") != source.get("neqo_pinned_commit")
            or source.get("lab_dirty") is not False
            or source.get("neqo_dirty") is not False
            or source.get("lab_patch_sha256") != _EMPTY_SHA256
            or source.get("neqo_patch_sha256") != _EMPTY_SHA256
        ):
            raise ValueError(f"{label} source fingerprints are invalid")
        self._source_constraints.append((dict(source), label))

    def require_source_constraints(self, build: BuildAdmission) -> None:
        for source, label in self._source_constraints:
            if source != build.source:
                raise ValueError(f"{label} source fingerprints differ from the resolved build")

    def carrier_file(self, raw: str | os.PathLike[str], *, label: str) -> list[BuildAdmission]:
        _path, value = _load_json_file(self.root, raw, label=label)
        self._record_fitting_source(value, label=label)
        return self.carrier_value(value, label=label)

    def carrier_directory(
        self,
        raw: str | os.PathLike[str],
        *,
        label: str,
        filenames: Sequence[str] | None = None,
    ) -> list[BuildAdmission]:
        root = _regular_directory(self.root, raw, label=label)
        if filenames is None:
            files = sorted(root.glob("*.json"))
            if len(files) > 512:
                raise ValueError(f"{label} contains too many authority carriers")
        else:
            files = [root / name for name in filenames if (root / name).is_file()]
        found: list[BuildAdmission] = []
        for path in files:
            found.extend(self.carrier_file(path, label=f"{label} {path.name}"))
        return found

    def acquisition_completion(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        path = _regular_file(self.root, raw, label="class acquisition completion")
        _path, _value, completion = _envelope(
            self.root,
            path,
            label="class acquisition completion",
            expected_type=_ACQUISITION_COMPLETION,
        )
        acquisition_schema = completion.get("acquisition_schema_version")
        if type(acquisition_schema) is int and acquisition_schema < _ACQUISITION_SCHEMA:
            raise _HistoricalAuthority("class acquisition completion is historical")
        provenance_sha256 = completion.get("provenance_sha256")
        if (
            type(acquisition_schema) is not int
            or acquisition_schema != _ACQUISITION_SCHEMA
            or type(completion.get("completion_schema_version")) is not int
            or completion.get("completion_schema_version") != 3
            or not isinstance(provenance_sha256, str)
            or _DIGEST.fullmatch(provenance_sha256) is None
        ):
            raise ValueError("class acquisition completion is not current build authority")
        provenance = _regular_file(
            self.root,
            path.parent / "provenance.json",
            label="class acquisition provenance",
        )
        if _sha256(provenance) != provenance_sha256:
            raise ValueError("class acquisition completion binds another provenance")
        return self.acquisition(path.parent)

    def successor_decision(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        _path, _value, payload = _envelope(
            self.root, raw, label="successor decision", expected_type=_SUCCESSOR_DECISION
        )
        evidence = payload.get("evidence")
        if payload.get("decision_schema_version") != _SUCCESSOR_DECISION_SCHEMA or not isinstance(
            evidence, Mapping
        ):
            raise ValueError("successor decision schema is invalid")
        foundation_path = _bound_file(
            self.root,
            evidence.get("predecessor_foundation"),
            label="successor predecessor foundation",
        )
        foundation_build = self.foundation(foundation_path)
        predecessor = payload.get("predecessor")
        if predecessor is not None:
            if not isinstance(predecessor, Mapping):
                raise TypeError("successor predecessor identity is invalid")
            if (
                predecessor.get("source") != foundation_build.source
                or predecessor.get("source_sha256")
                != hashlib.sha256(_canonical_json_bytes(foundation_build.source)).hexdigest()
                or predecessor.get("build_execution_identity") != foundation_build.identity
                or predecessor.get("build_execution_identity_sha256")
                != hashlib.sha256(_canonical_json_bytes(foundation_build.identity)).hexdigest()
            ):
                raise ValueError("successor predecessor identity differs from its foundation")
        linked = [foundation_build]
        certification = evidence.get("certification_result")
        if certification is not None:
            linked.append(
                self.frozen_environment(
                    _bound_directory(
                        self.root,
                        certification,
                        label="successor certification result",
                    )
                )
            )
        for name in ("predecessor_final_selection", "predecessor_cohort_assembly"):
            binding = evidence.get(name)
            if binding is not None:
                linked.extend(
                    self.carrier_file(
                        _bound_file(
                            self.root,
                            binding,
                            label=f"successor {name.replace('_', ' ')}",
                        ),
                        label=f"successor {name.replace('_', ' ')}",
                    )
                )
        predecessor_restart = evidence.get("predecessor_successor_restart")
        if predecessor_restart is not None:
            linked.append(
                self.successor_restart(
                    _bound_file(
                        self.root,
                        predecessor_restart,
                        label="successor predecessor restart",
                    )
                )
            )
        return _require_same_build(linked)

    def successor_restart(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        path = _regular_file(self.root, raw, label="successor restart")
        cached = self._successor_restarts.get(path)
        if cached is not None:
            return cached
        if path in self._active_successor_restarts:
            raise ValueError("successor restart authority chain is cyclic")
        self._active_successor_restarts.add(path)
        try:
            _path, _value, payload = _envelope(
                self.root, path, label="successor restart", expected_type=_SUCCESSOR_RESTART
            )
            if (
                set(payload) != _SUCCESSOR_RESTART_KEYS
                or payload.get("restart_schema_version") != _SUCCESSOR_RESTART_SCHEMA
            ):
                raise ValueError("successor restart schema is invalid")
            hidden = self.carrier_value(payload, label="successor restart")
            if hidden:
                raise ValueError("successor restart contains an unexpected build authority")
            decision_binding = payload.get("successor_decision")
            decision_path = _bound_file(self.root, decision_binding, label="successor decision")
            _decision_path, decision_value, _decision_payload = _envelope(
                self.root,
                decision_path,
                label="successor decision",
                expected_type=_SUCCESSOR_DECISION,
            )
            if (
                not isinstance(decision_binding, Mapping)
                or set(decision_binding) != {"path", "sha256", "payload_sha256"}
                or decision_binding.get("payload_sha256") != decision_value.get("payload_sha256")
            ):
                raise ValueError("successor decision binding is incomplete")
            build = self.successor_decision(decision_path)
            if (
                payload.get("predecessor_foundation_sha256")
                != self._decision_foundation_sha256(decision_path)
                or payload.get("source_sha256")
                != hashlib.sha256(_canonical_json_bytes(build.source)).hexdigest()
                or payload.get("build_execution_identity_sha256")
                != hashlib.sha256(_canonical_json_bytes(build.identity)).hexdigest()
            ):
                raise ValueError("successor restart build authority differs from its decision")
            plan = self._successor_plan(path, payload)

            # Cache the already-resolved restart before following campaign
            # references back to it.  A predecessor cycle is still rejected
            # above because it re-enters while the cache is absent.
            self._successor_restarts[path] = build
            linked = [build]
            for name, artifact in sorted(plan.items()):
                if artifact.suffix == ".json":
                    linked.extend(
                        self.carrier_file(
                            artifact,
                            label=f"successor restart {name}",
                        )
                    )
                    continue
                try:
                    campaign_document = _CampaignSubsetParser(
                        artifact.read_text(encoding="utf-8")
                    ).parse()
                except (OSError, UnicodeError) as error:
                    raise ValueError(f"successor restart {name} is not readable UTF-8") from error
                linked.extend(
                    self.carrier_value(
                        campaign_document,
                        label=f"successor restart {name}",
                    )
                )
                _role, campaign = _campaign_authorities(
                    self,
                    artifact,
                    allow_prospective=True,
                    follow_runtime=False,
                )
                linked.extend(campaign)
            resolved = _require_same_build(linked)
            self._successor_restarts[path] = resolved
            return resolved
        except Exception:
            self._successor_restarts.pop(path, None)
            raise
        finally:
            self._active_successor_restarts.remove(path)

    def _successor_plan(
        self,
        restart_path: Path,
        payload: Mapping[str, Any],
    ) -> dict[str, Path]:
        """Validate the exact immutable restart inventory and every file hash."""

        study_id = payload.get("study_id")
        identity_sha256 = payload.get("successor_identity_sha256")
        if (
            not isinstance(study_id, str)
            or _SUCCESSOR_STUDY_ID.fullmatch(study_id) is None
            or not isinstance(identity_sha256, str)
            or _DIGEST.fullmatch(identity_sha256) is None
            or study_id.rsplit("-", 1)[-1] != identity_sha256[:12]
        ):
            raise ValueError("successor restart identity is invalid")
        restart_root = restart_path.parent.parent
        if (
            restart_path.name != "successor-restart.json"
            or restart_path.parent.name != "plan"
            or restart_root.name != study_id
        ):
            raise ValueError("successor restart path differs from its hash-derived identity")
        namespace = payload.get("namespace")
        expected_namespace = {
            "restart_root_name": study_id,
            "launch_namespace": f".{study_id}-launches",
            "results_root": "results",
            "authoritative_numeric_root": (
                f"artifacts/{_BASE_STUDY_ID}-authoritative-fitting-numeric"
            ),
            "authoritative_prefix_root": (
                f"artifacts/{_BASE_STUDY_ID}-authoritative-fitting-prefix-specs"
            ),
            "authoritative_final_root": (f"artifacts/{_BASE_STUDY_ID}-authoritative-fitting"),
            "final_qualification_root": f"qualification/{study_id}-final-full",
        }
        if namespace != expected_namespace:
            raise ValueError("successor restart namespace is invalid")

        expected = {
            "successor-cohort.json",
            "successor-compatible-cohort.json",
            "successor-compatible-cohort-assembly.json",
            "successor-final-selection.json",
            "final-qualification-plan.json",
            f"campaigns/{study_id}-authoritative-fitting-2000-1200.yml",
            f"campaigns/{study_id}-certification-900-1200.yml",
        }
        for block in range(1, 11):
            expected.add(f"campaigns/{study_id}-canary-{block:02d}-1200.yml")
            expected.add(f"campaigns/{study_id}-formal-{block:02d}-1200.yml")
        bindings = payload.get("immutable_plan_artifacts")
        if not isinstance(bindings, Mapping) or set(bindings) != expected:
            raise ValueError("successor restart immutable plan inventory is invalid")

        plan_root = _regular_directory(
            self.root,
            restart_path.parent,
            label="successor restart plan",
        )
        expected_top = {
            "successor-restart.json",
            "successor-cohort.json",
            "successor-compatible-cohort.json",
            "successor-compatible-cohort-assembly.json",
            "successor-final-selection.json",
            "final-qualification-plan.json",
            "campaigns",
        }
        if {entry.name for entry in plan_root.iterdir()} != expected_top:
            raise ValueError("successor restart plan contains unexpected or missing entries")
        campaigns = _regular_directory(
            self.root,
            plan_root / "campaigns",
            label="successor restart campaigns",
        )
        expected_campaigns = {Path(item).name for item in expected if item.startswith("campaigns/")}
        if {entry.name for entry in campaigns.iterdir()} != expected_campaigns:
            raise ValueError("successor restart campaigns contain unexpected or missing entries")

        resolved: dict[str, Path] = {}
        for relative in sorted(expected):
            binding = bindings[relative]
            if (
                not isinstance(binding, Mapping)
                or set(binding) != {"path", "sha256"}
                or binding.get("path") != relative
                or not isinstance(binding.get("sha256"), str)
                or _DIGEST.fullmatch(binding["sha256"]) is None
            ):
                raise ValueError(f"successor restart {relative} binding is invalid")
            artifact = _regular_file(
                self.root,
                plan_root / relative,
                label=f"successor restart {relative}",
            )
            if _sha256(artifact) != binding["sha256"]:
                raise ValueError(f"successor restart artifact changed: {relative}")
            resolved[relative] = artifact
        return resolved

    def successor_runtime_paths(
        self,
        raw: str | os.PathLike[str],
    ) -> dict[str, Path]:
        """Return the runtime paths derived by ``_successor_action_context``."""

        path = _regular_file(self.root, raw, label="successor restart")
        self.successor_restart(path)
        _path, _value, payload = _envelope(
            self.root, path, label="successor restart", expected_type=_SUCCESSOR_RESTART
        )
        study_id = payload["study_id"]
        root = path.parent.parent
        artifacts = root / "artifacts"
        qualification = root / "qualification"
        final_set = qualification / f"{study_id}-final-full"
        return {
            "root": root,
            "numeric_bundle": artifacts / f"{_BASE_STUDY_ID}-authoritative-fitting-numeric",
            "prefix_spec_root": (
                artifacts / f"{_BASE_STUDY_ID}-authoritative-fitting-prefix-specs"
            ),
            "qualification_checkpoint": qualification / "checkpoint.json",
            "qualification_work_root": qualification / "work",
            "qualification_set_root": final_set,
            "qualification_manifest": final_set / "_qualification-set.json",
            "final_bundle": artifacts / f"{_BASE_STUDY_ID}-authoritative-fitting",
        }

    def _decision_foundation_sha256(self, path: Path) -> str:
        _path, _value, payload = _envelope(
            self.root, path, label="successor decision", expected_type=_SUCCESSOR_DECISION
        )
        evidence = payload.get("evidence")
        if not isinstance(evidence, Mapping):
            raise TypeError("successor decision has no evidence")
        foundation = evidence.get("predecessor_foundation")
        if not isinstance(foundation, Mapping) or not isinstance(foundation.get("sha256"), str):
            raise TypeError("successor decision has no predecessor foundation")
        return foundation["sha256"]

    def frozen_environment(self, raw: str | os.PathLike[str]) -> BuildAdmission:
        result = _regular_directory(self.root, raw, label="class capture result")
        _path, environment = _load_json_file(
            self.root,
            result / "inputs/study-environment.json",
            label="class frozen study environment",
        )
        execution = environment.get("build_execution") if isinstance(environment, Mapping) else None
        receipt = execution.get("receipt") if isinstance(execution, Mapping) else None
        cohort = receipt.get("cohort_version") if isinstance(receipt, Mapping) else None
        schema = environment.get("schema_version") if isinstance(environment, Mapping) else None
        if schema in {1, 2}:
            raise _HistoricalAuthority("class frozen study environment is historical")
        environment_keys = {
            "schema_version",
            "artifact_type",
            "docker",
            "collection_image",
            "build_inputs",
            "build_execution",
            "clock_status",
            "capture_scheduler",
        }
        docker = environment.get("docker") if isinstance(environment, Mapping) else None
        collection_image = (
            environment.get("collection_image") if isinstance(environment, Mapping) else None
        )
        build_inputs = environment.get("build_inputs") if isinstance(environment, Mapping) else None
        clock_status = environment.get("clock_status") if isinstance(environment, Mapping) else None
        if (
            not isinstance(environment, Mapping)
            or set(environment) != environment_keys
            or schema != 3
            or environment.get("artifact_type") != "qcsd-buflo-study-environment"
            or not isinstance(docker, Mapping)
            or set(docker)
            != {
                "client_version",
                "server_version",
                "server_os",
                "server_arch",
                "ncpu",
                "mem_total_bytes",
                "storage_driver",
            }
            or not isinstance(collection_image, Mapping)
            or set(collection_image) != {"id", "repo_digests"}
            or not isinstance(collection_image.get("repo_digests"), list)
            or not isinstance(build_inputs, Mapping)
            or set(build_inputs)
            != {
                "schema_version",
                "artifact_type",
                "rust_base_image",
                "debian_base_image",
                "uv_lock_sha256",
                "cargo_lock_sha256",
            }
            or not isinstance(execution, Mapping)
            or set(execution)
            != {
                "receipt",
                "sha256",
                "completion_path",
                "completion_sha256",
                "completion_payload_sha256",
                "completion",
            }
            or not isinstance(clock_status, Mapping)
            or set(clock_status) != {"relationship", "host", "container"}
            or not isinstance(environment.get("capture_scheduler"), Mapping)
            or type(cohort) is not int
            or cohort < 1
        ):
            raise ValueError("class frozen environment has no current completed build")
        build_path = self.root / f"artifacts/buflo-study/build-execution-v{cohort}.json"
        build = self.build(build_path, expected_cohort=cohort)
        completion = execution.get("completion")
        if (
            receipt != json.loads(build.receipt_path.read_bytes())
            or execution.get("sha256") != build.receipt_sha256
            or execution.get("completion_path")
            != f"/lab/artifacts/buflo-study/build-completion-v{cohort}.json"
            or execution.get("completion_sha256") != build.completion_sha256
            or execution.get("completion_payload_sha256") != build.completion_payload_sha256
            or completion != json.loads(build.completion_path.read_bytes())
            or not isinstance(collection_image, Mapping)
            or collection_image.get("id") != build.collection_image
        ):
            raise ValueError("class frozen environment build pair changed")
        return build

    def frozen_resume_authority(
        self,
        raw: str | os.PathLike[str],
        *,
        canonical_successor: str | os.PathLike[str] | None = None,
        canonical_foundation: str | os.PathLike[str] | None = None,
        canonical_readiness: str | os.PathLike[str] | None = None,
        canonical_historical_pre: str | os.PathLike[str] | None = None,
    ) -> tuple[str, BuildAdmission]:
        """Close every frozen current-result build edge before Docker resume."""

        result = _regular_directory(self.root, raw, label="class capture result")
        _experiment_path, experiment = _load_json_file(
            self.root,
            result / "experiment.json",
            label="class frozen experiment",
            max_bytes=_MAX_EXPERIMENT_BYTES,
        )
        configuration = experiment.get("configuration") if isinstance(experiment, Mapping) else None
        role = configuration.get("evidence_role") if isinstance(configuration, Mapping) else None
        campaign_name = experiment.get("name") if isinstance(experiment, Mapping) else None
        if role not in _CLASS_ROLES or not isinstance(configuration, Mapping):
            raise ValueError("class frozen experiment has an invalid evidence role")
        study_id, successor_campaign = _class_campaign_identity(campaign_name, role)
        expected_configuration_keys = {
            "campaign_sha256",
            "profile",
            "request_policies",
            "workloads",
            "defenses",
            "limits",
            "evidence_role",
            "class_study_cohort_sha256",
            "class_study_cohort_assembly_sha256",
            "class_study_id",
            "class_study_launch_sha256",
            "class_study_foundation_sha256",
            "public_origin_policy",
            "sample_order",
            "study_environment_sha256",
        }
        if role not in {"pilot-fitting", "authoritative-fitting"}:
            expected_configuration_keys.add("defense_order")
        if role in _CLASS_FITTED_ROLES:
            expected_configuration_keys.update(
                {
                    "chaff_qualification_set",
                    "chaff_qualification_set_manifest_sha256",
                }
            )
        if successor_campaign:
            expected_configuration_keys.add("class_study_successor_sha256")
        if role in _PROMOTED_ROLES:
            expected_configuration_keys.update(
                {
                    "class_study_readiness_sha256",
                    "class_study_historical_pre_snapshot_sha256",
                }
            )
        if set(configuration) != expected_configuration_keys:
            raise ValueError("class frozen configuration schema is invalid")
        expected_purpose = {
            "pilot-fitting": "fitting",
            "pilot-compatibility": "smoke",
            "authoritative-fitting": "fitting",
            "certification": "smoke",
            "canary": "smoke",
            "formal": "evaluation",
        }[str(role)]
        expected_policies = (
            ["as-defined", "half-duplex"]
            if role in {"pilot-fitting", "authoritative-fitting"}
            else ["as-defined"]
        )
        expected_limits = {
            "timeout_seconds": 120,
            "max_response_bytes": 1_048_576,
            "capture_seconds": 180,
            "capture_megabytes": 64,
            "max_attempts": 1 if role == "certification" else 3,
            "per_origin_cooldown_seconds": 30,
            "settle_seconds": 1,
        }
        expected_public_origin_policy = {
            "environment": "QCSD_PUBLIC_ORIGIN_ONLY",
            "required_value": "1",
            "resolution": "resolve-once-reject-any-non-public-connect-exact-address",
        }
        if role in {"pilot-fitting", "authoritative-fitting"}:
            expected_defense_order = None
        elif role in {"pilot-compatibility", "certification"}:
            expected_defense_order = {"scheme": "cyclic-latin-square", "block": 0}
        else:
            assert isinstance(campaign_name, str)
            block = int(campaign_name.rsplit("-", 2)[-2]) - 1
            expected_defense_order = {
                "scheme": "cyclic-latin-square",
                "block": block,
            }
        if (
            experiment.get("purpose") != expected_purpose
            or configuration.get("profile") != "research-1200"
            or configuration.get("request_policies") != expected_policies
            or configuration.get("limits") != expected_limits
            or configuration.get("sample_order")
            != {"scheme": "origin-aware-windowed", "window_size": 16}
            or configuration.get("public_origin_policy") != expected_public_origin_policy
            or configuration.get("defense_order") != expected_defense_order
            or (expected_defense_order is None and "defense_order" in configuration)
        ):
            raise ValueError("class frozen role execution contract is invalid")
        inputs = _regular_directory(self.root, result / "inputs", label="class frozen inputs")
        environment_path = _regular_file(
            self.root,
            inputs / "study-environment.json",
            label="class frozen study environment",
        )
        build = self.frozen_environment(result)
        if configuration.get("study_environment_sha256") != _sha256(environment_path):
            raise ValueError("class frozen study environment differs from configuration")
        linked = [build]

        _source_path, frozen_source = _load_json_file(
            self.root, inputs / "source.json", label="class frozen source"
        )
        if frozen_source != build.source or experiment.get("source") != build.source:
            raise ValueError("class frozen source differs from its completed build")

        campaign_path = _regular_file(
            self.root, inputs / "campaign.yml", label="class frozen campaign"
        )
        try:
            campaign_text = campaign_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ValueError("class frozen campaign is not readable UTF-8") from error
        campaign_document = _CampaignSubsetParser(campaign_text).parse()
        campaign_scalars = _campaign_carrier_scalars(campaign_text)
        campaign_workloads = campaign_document.get("workloads")
        configured_workloads = configuration.get("workloads")
        expected_workload_count = 120 if role in {"pilot-fitting", "pilot-compatibility"} else 100
        campaign_workload_ids = (
            list(campaign_workloads) if isinstance(campaign_workloads, Mapping) else None
        )
        configured_workload_ids = (
            [
                record.get("id") if isinstance(record, Mapping) else None
                for record in configured_workloads
            ]
            if isinstance(configured_workloads, list)
            else None
        )
        if (
            campaign_document.get("name") != campaign_name
            or campaign_document.get("evidence_role") != role
            or configuration.get("campaign_sha256") != _sha256(campaign_path)
            or configuration.get("class_study_id") != study_id
            or not isinstance(campaign_document.get("class_study_cohort"), str)
            or len(campaign_scalars["class_study_cohort_assembly"]) != 1
            or campaign_workload_ids is None
            or len(campaign_workload_ids) != expected_workload_count
            or len(set(campaign_workload_ids)) != expected_workload_count
            or configured_workload_ids != campaign_workload_ids
        ):
            raise ValueError("class frozen campaign identity or hash differs from experiment")
        assert campaign_workload_ids is not None
        self.frozen_workload_inventory(
            result,
            configuration,
            role=str(role),
            workload_ids=campaign_workload_ids,
        )

        foundation_path, foundation_envelope, _foundation_payload = _envelope(
            self.root,
            inputs / "class-study-foundation.json",
            label="class frozen foundation",
            expected_type=_FOUNDATION,
        )
        if configuration.get("class_study_foundation_sha256") != _sha256(foundation_path):
            raise ValueError("class frozen foundation differs from experiment configuration")
        if canonical_foundation is None:
            raise ValueError("class resume has no external foundation authority")
        external_foundation = _regular_file(
            self.root,
            canonical_foundation,
            label="class resume external foundation",
        )
        if external_foundation.read_bytes() != foundation_path.read_bytes():
            raise ValueError("class frozen foundation differs from external resume authority")
        linked.append(self.foundation(foundation_path))
        linked.extend(
            self.carrier_value(
                campaign_document,
                label="class frozen campaign",
                frozen_foundation=foundation_path,
            )
        )

        cohort_path, cohort_envelope, cohort_payload = _envelope(
            self.root,
            inputs / "class-study-cohort.json",
            label="class frozen cohort",
            expected_type=_COHORT,
        )
        assembly_path, assembly_envelope, assembly = _envelope(
            self.root,
            inputs / "class-study-cohort-assembly.json",
            label="class frozen cohort assembly",
            expected_type=_COHORT_ASSEMBLY,
        )
        cohort_sha256 = _sha256(cohort_path)
        assembly_sha256 = _sha256(assembly_path)
        expected_cohort_binding = {
            "receipt_type": cohort_envelope["receipt_type"],
            "payload_sha256": cohort_envelope["payload_sha256"],
            "canonical_file_sha256": hashlib.sha256(
                _canonical_json_bytes(cohort_envelope)
            ).hexdigest(),
        }
        pilot_role = role in {"pilot-fitting", "pilot-compatibility"}
        cohort_inventories = cohort_payload.get("inventories")
        cohort_workload_ids = (
            cohort_inventories.get("pilot" if pilot_role else "final")
            if isinstance(cohort_inventories, Mapping)
            else None
        )
        if (
            cohort_payload.get("study_id") != _BASE_STUDY_ID
            or cohort_workload_ids != campaign_workload_ids
            or set(assembly) != _COHORT_ASSEMBLY_KEYS
            or assembly.get("study_id") != _BASE_STUDY_ID
            or assembly.get("assembly_schema_version") != 3
            or assembly.get("cohort") != expected_cohort_binding
            or (assembly.get("final_selection") is None) is not pilot_role
            or configuration.get("class_study_cohort_sha256") != cohort_sha256
            or configuration.get("class_study_cohort_assembly_sha256") != assembly_sha256
        ):
            raise ValueError("class frozen cohort and assembly binding is invalid")
        assembly_authorities = self.carrier_value(
            assembly,
            label="class frozen cohort assembly",
            frozen_foundation=foundation_path,
        )
        if pilot_role and assembly_authorities:
            raise ValueError("class frozen pilot assembly unexpectedly has build authority")
        if not pilot_role and not assembly_authorities:
            raise ValueError("class frozen final assembly has no build authority")
        linked.extend(assembly_authorities)

        promotion_paths: dict[str, tuple[Path, Mapping[str, Any]]] = {}
        promotion_specs = (
            (
                "class-study-readiness.json",
                "class_study_readiness_sha256",
                _READINESS,
                self.readiness,
                canonical_readiness,
            ),
            (
                "class-study-historical-pre-snapshot.json",
                "class_study_historical_pre_snapshot_sha256",
                _HISTORICAL,
                self.historical,
                canonical_historical_pre,
            ),
        )
        for filename, key, receipt_type, route, external_raw in promotion_specs:
            candidate = inputs / filename
            exists = candidate.exists() or candidate.is_symlink()
            if role not in _PROMOTED_ROLES:
                if exists or key in configuration or external_raw is not None:
                    raise ValueError(f"{role} result has unexpected authority {filename}")
                continue
            if external_raw is None:
                raise ValueError(f"class resume has no external authority for {filename}")
            authority_path, _authority_envelope, authority_payload = _envelope(
                self.root,
                candidate,
                label=f"class frozen {filename}",
                expected_type=receipt_type,
            )
            if configuration.get(key) != _sha256(authority_path):
                raise ValueError(f"class frozen {filename} differs from configuration")
            external_path = _regular_file(
                self.root,
                external_raw,
                label=f"class resume external {filename}",
            )
            if external_path.read_bytes() != authority_path.read_bytes():
                raise ValueError(f"class frozen {filename} differs from external resume authority")
            linked.append(route(authority_path))
            promotion_paths[filename] = (authority_path, authority_payload)
        if role in _PROMOTED_ROLES:
            readiness_path, readiness_payload = promotion_paths["class-study-readiness.json"]
            _historical_path, historical_payload = promotion_paths[
                "class-study-historical-pre-snapshot.json"
            ]
            readiness_evidence = readiness_payload.get("evidence")
            readiness_foundation = (
                readiness_evidence.get("foundation")
                if isinstance(readiness_evidence, Mapping)
                else None
            )
            readiness_cohort = (
                readiness_evidence.get("final_cohort")
                if isinstance(readiness_evidence, Mapping)
                else None
            )
            readiness_assembly = (
                readiness_evidence.get("final_cohort_assembly")
                if isinstance(readiness_evidence, Mapping)
                else None
            )
            historical_readiness = historical_payload.get("readiness")
            if (
                readiness_payload.get("source") != build.source
                or historical_payload.get("source") != build.source
                or not isinstance(readiness_foundation, Mapping)
                or readiness_foundation.get("sha256") != _sha256(foundation_path)
                or not isinstance(historical_readiness, Mapping)
                or historical_readiness.get("sha256") != _sha256(readiness_path)
                or not isinstance(readiness_cohort, Mapping)
                or readiness_cohort.get("sha256") != cohort_sha256
                or not isinstance(readiness_assembly, Mapping)
                or readiness_assembly.get("sha256") != assembly_sha256
                or readiness_payload.get("study_id") != study_id
                or historical_payload.get("study_id") != study_id
                or historical_payload.get("phase") != "pre-formal"
            ):
                raise ValueError("class frozen promotion authority differs from campaign inputs")

        successor_path = inputs / "class-study-successor.json"
        successor_exists = successor_path.exists() or successor_path.is_symlink()
        successor_sha256 = configuration.get("class_study_successor_sha256")
        successor_values = campaign_scalars["class_study_successor"]
        if not successor_campaign:
            if (
                successor_exists
                or "class_study_successor_sha256" in configuration
                or canonical_successor is not None
                or successor_values
            ):
                raise ValueError("class frozen base result has unexpected successor authority")
        else:
            if (
                len(successor_values) != 1
                or not isinstance(successor_sha256, str)
                or _DIGEST.fullmatch(successor_sha256) is None
                or canonical_successor is None
            ):
                raise ValueError("class frozen successor result lacks canonical restart authority")
            successor_file = _regular_file(
                self.root, successor_path, label="class frozen successor"
            )
            canonical_path = _regular_file(
                self.root, canonical_successor, label="class canonical successor"
            )
            plan_root = canonical_path.parent
            plan_campaign = _regular_file(
                self.root,
                plan_root / "campaigns" / f"{campaign_name}.yml",
                label="class canonical successor campaign",
            )
            plan_cohort = _regular_file(
                self.root,
                plan_root / "successor-compatible-cohort.json",
                label="class canonical successor cohort",
            )
            plan_assembly = _regular_file(
                self.root,
                plan_root / "successor-compatible-cohort-assembly.json",
                label="class canonical successor cohort assembly",
            )
            _successor_path, _successor_envelope, successor_payload = _envelope(
                self.root,
                successor_file,
                label="class frozen successor",
                expected_type=_SUCCESSOR_RESTART,
            )
            if (
                successor_payload.get("restart_schema_version") != _SUCCESSOR_RESTART_SCHEMA
                or successor_payload.get("study_id") != study_id
                or _sha256(successor_file) != successor_sha256
                or _sha256(canonical_path) != successor_sha256
                or successor_file.read_bytes() != canonical_path.read_bytes()
                or campaign_path.read_bytes() != plan_campaign.read_bytes()
                or cohort_path.read_bytes() != plan_cohort.read_bytes()
                or assembly_path.read_bytes() != plan_assembly.read_bytes()
            ):
                raise ValueError(
                    "class frozen successor inputs differ from their canonical restart plan"
                )
            linked.append(self.successor_restart(canonical_path))
            if role in _PROMOTED_ROLES:
                readiness_payload = promotion_paths["class-study-readiness.json"][1]
                readiness_evidence = readiness_payload.get("evidence")
                readiness_successor = (
                    readiness_evidence.get("successor_restart")
                    if isinstance(readiness_evidence, Mapping)
                    else None
                )
                if (
                    not isinstance(readiness_successor, Mapping)
                    or readiness_successor.get("sha256") != successor_sha256
                ):
                    raise ValueError("class frozen readiness uses another successor restart")

        launch_path, launch = _load_json_file(
            self.root,
            inputs / "class-study-launch.json",
            label="class frozen first-launch claim",
        )
        launch_payload = launch.get("payload") if isinstance(launch, Mapping) else None
        launch_keys = {
            "study_id",
            "launch_key",
            "campaign_name",
            "campaign_sha256",
            "evidence_role",
            "class_study_cohort_sha256",
            "class_study_cohort_assembly_sha256",
            "result_root",
            "created_at",
            "source",
            "policy",
        }
        if successor_campaign:
            launch_keys.update({"class_study_successor_sha256", "launch_namespace"})
        launch_digest = (
            hashlib.sha256(
                json.dumps(launch_payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if isinstance(launch_payload, Mapping)
            else None
        )
        expected_launch_key = _class_launch_key(
            study_id=study_id,
            campaign_name=str(campaign_name),
            evidence_role=str(role),
            cohort_sha256=cohort_sha256,
            assembly_sha256=assembly_sha256,
        )
        container_result_root = f"/lab/{result.relative_to(self.root).as_posix()}"
        if (
            not isinstance(launch, Mapping)
            or set(launch) != {"schema_version", "artifact_type", "payload_sha256", "payload"}
            or launch.get("schema_version") != 1
            or launch.get("artifact_type") != "qcsd-class-study-first-launch-claim"
            or not isinstance(launch_payload, Mapping)
            or set(launch_payload) != launch_keys
            or launch.get("payload_sha256") != launch_digest
            or launch_payload.get("source") != build.source
            or launch_payload.get("study_id") != study_id
            or launch_payload.get("campaign_name") != campaign_name
            or launch_payload.get("campaign_sha256") != _sha256(campaign_path)
            or launch_payload.get("evidence_role") != role
            or launch_payload.get("class_study_cohort_sha256") != cohort_sha256
            or launch_payload.get("class_study_cohort_assembly_sha256") != assembly_sha256
            or launch_payload.get("result_root") != container_result_root
            or not isinstance(launch_payload.get("created_at"), str)
            or not launch_payload.get("created_at")
            or launch_payload.get("policy") != "one-result-root-per-campaign-and-cohort-assembly"
            or launch_payload.get("launch_key") != expected_launch_key
            or configuration.get("class_study_launch_sha256") != _sha256(launch_path)
            or (
                successor_campaign
                and (
                    launch_payload.get("class_study_successor_sha256") != successor_sha256
                    or launch_payload.get("launch_namespace") != f".{study_id}-launches"
                )
            )
        ):
            raise ValueError("class frozen first-launch claim differs from its campaign")
        if result.parent.name != campaign_name or result.parent.parent.name != "results":
            raise ValueError("class frozen first-launch result path is not canonical")
        registry = _regular_directory(
            self.root,
            result.parent.parent / f".{study_id}-launches",
            label="class first-launch registry",
        )
        marker = _regular_file(
            self.root,
            registry / f"{expected_launch_key}.json",
            label="class first-launch registry marker",
        )
        if marker.read_bytes() != launch_path.read_bytes():
            raise ValueError("class frozen first-launch claim differs from its registry marker")
        self.frozen_defense_inventory(result, configuration, role=str(role))
        linked.extend(
            self.frozen_json_carriers(
                inputs,
                {
                    "source": experiment.get("source"),
                    "configuration": configuration,
                },
                frozen_foundation=foundation_path,
            )
        )

        expected_qualification = None
        if role == "pilot-compatibility":
            expected_qualification = _PILOT_QUALIFICATION_SET
        elif role in {"certification", "formal"}:
            expected_qualification = (
                f"{study_id}-final-full" if successor_campaign else _AUTHORITATIVE_QUALIFICATION_SET
            )
        qualification_values = campaign_scalars["chaff_qualification_set"]
        if qualification_values != ([expected_qualification] if expected_qualification else []):
            raise ValueError("class frozen campaign qualification identity is invalid")
        if (expected_qualification is None and "chaff_qualification_set" in configuration) or (
            expected_qualification is not None
            and configuration.get("chaff_qualification_set") != expected_qualification
        ):
            raise ValueError("class frozen configuration qualification identity is invalid")

        bundle_root_path = inputs / "defense-parameters/class-study"
        qualification_root_path = inputs / "chaff-qualifications"
        if role not in _CLASS_FITTED_ROLES:
            if (
                bundle_root_path.exists()
                or bundle_root_path.is_symlink()
                or qualification_root_path.exists()
                or qualification_root_path.is_symlink()
                or "chaff_qualification_set_manifest_sha256" in configuration
            ):
                raise ValueError(f"{role} result has unexpected fitted qualification inputs")
            return role, _require_same_build(linked)

        bundle_root = _regular_directory(
            self.root, bundle_root_path, label="class frozen final fitting bundle"
        )
        if {entry.name for entry in bundle_root.iterdir()} != _FINAL_FITTING_FILES:
            raise ValueError("class frozen final fitting bundle has an invalid inventory")
        bundle_files = {
            name: _regular_file(
                self.root,
                bundle_root / name,
                label=f"class frozen fitting {name}",
                max_bytes=_MAX_FROZEN_INPUT_BYTES,
            )
            for name in _FINAL_FITTING_FILES
        }
        provenance_path, provenance = _load_json_file(
            self.root,
            bundle_files["provenance.json"],
            label="class frozen final fitting provenance",
            max_bytes=_MAX_FROZEN_INPUT_BYTES,
        )
        expected_stage = "pilot" if role == "pilot-compatibility" else "authoritative"
        expected_status = (
            "pilot-test-only" if expected_stage == "pilot" else "authoritative-fitted-artifact"
        )
        source_result = provenance.get("source_result") if isinstance(provenance, Mapping) else None
        source_keys = {
            "campaign",
            "evidence_sha256",
            "experiment_sha256",
            "input_digest",
            "campaign_sha256",
            "source_fingerprints",
        }
        if successor_campaign:
            source_keys.update({"study_id", "class_study_successor_sha256"})
        expected_fitting_campaign = (
            f"{_BASE_STUDY_ID}-pilot-fitting-1200"
            if expected_stage == "pilot"
            else (
                f"{study_id}-authoritative-fitting-2000-1200"
                if successor_campaign
                else f"{_BASE_STUDY_ID}-authoritative-fitting-1200"
            )
        )
        if (
            not isinstance(provenance, Mapping)
            or set(provenance) != _FINAL_PROVENANCE_KEYS
            or provenance.get("schema_version") != 2
            or provenance.get("artifact_type") != "qcsd-class-study-research-defense-bundle"
            or provenance.get("stage") != expected_stage
            or provenance.get("status") != expected_status
            or provenance.get("runtime_authorized") is not (expected_stage == "authoritative")
            or not isinstance(source_result, Mapping)
            or set(source_result) != source_keys
            or source_result.get("campaign") != expected_fitting_campaign
            or source_result.get("source_fingerprints") != build.source
            or any(
                _DIGEST.fullmatch(str(source_result.get(key))) is None
                for key in (
                    "evidence_sha256",
                    "experiment_sha256",
                    "input_digest",
                    "campaign_sha256",
                )
            )
            or (
                successor_campaign
                and (
                    source_result.get("study_id") != study_id
                    or source_result.get("class_study_successor_sha256") != successor_sha256
                )
            )
        ):
            raise ValueError("class frozen final fitting provenance identity is invalid")
        provenance_cohort = provenance.get("cohort")
        if (
            not isinstance(provenance_cohort, Mapping)
            or set(provenance_cohort) != _FITTING_COHORT_KEYS
            or provenance_cohort.get("role") != expected_stage
            or provenance_cohort.get("receipt") != cohort_envelope
            or provenance_cohort.get("assembly_receipt") != assembly_envelope
            or provenance_cohort.get("receipt_sha256")
            != hashlib.sha256(_canonical_json_bytes(cohort_envelope)).hexdigest()
            or provenance_cohort.get("assembly_receipt_sha256")
            != hashlib.sha256(_canonical_json_bytes(assembly_envelope)).hexdigest()
        ):
            raise ValueError("class frozen fitting provenance uses another cohort")
        qualification_inputs = provenance.get("qualification_inputs")
        if (
            not isinstance(qualification_inputs, Mapping)
            or set(qualification_inputs) != _FINAL_QUALIFICATION_INPUT_KEYS
        ):
            raise ValueError("class frozen fitting qualification receipt is invalid")
        linked.append(
            self.qualification_authority(
                qualification_inputs.get("qualification_authority"),
                label="class frozen final fitting provenance",
                frozen_foundation=foundation_path,
            )
        )

        defense_records = configuration.get("defenses")
        if not isinstance(defense_records, list):
            raise TypeError("class frozen defense configuration is invalid")
        expected_parameters = {
            "traffic-morphing": "traffic-morphing.json",
            "wtf-pad": "wtf-pad.json",
            "walkie-talkie": "walkie-talkie.json",
        }
        fitted_records = {
            record.get("name"): record
            for record in defense_records
            if isinstance(record, Mapping)
            and record.get("provenance") == "inputs/defense-parameters/class-study/provenance.json"
        }
        if set(fitted_records) != set(expected_parameters):
            raise ValueError("class frozen fitting defenses are incomplete")
        for name, filename in expected_parameters.items():
            record = fitted_records[name]
            if (
                record.get("parameters") != f"inputs/defense-parameters/class-study/{filename}"
                or record.get("parameters_sha256") != _sha256(bundle_files[filename])
                or record.get("provenance_sha256") != _sha256(provenance_path)
            ):
                raise ValueError("class frozen fitting parameters differ from configuration")

        qualification_root = _regular_directory(
            self.root,
            qualification_root_path,
            label="class frozen qualification sidecars",
        )
        manifest_path, manifest = _load_json_file(
            self.root,
            qualification_root / "_qualification-set.json",
            label="class frozen qualification manifest",
            max_bytes=_MAX_FROZEN_INPUT_BYTES,
        )
        expected_count = 120 if expected_stage == "pilot" else 100
        workload_ids = manifest.get("workload_ids") if isinstance(manifest, Mapping) else None
        entries = manifest.get("workloads") if isinstance(manifest, Mapping) else None
        manifest_authority = (
            manifest.get("qualification_authority") if isinstance(manifest, Mapping) else None
        )
        if (
            not isinstance(manifest, Mapping)
            or set(manifest) != _NAMED_QUALIFICATION_SET_KEYS
            or manifest.get("schema_version") != 3
            or manifest.get("artifact_type") != "qcsd-named-chaff-qualification-set"
            or manifest.get("qualification_set") != expected_qualification
            or manifest.get("qualification_scope") != "full"
            or manifest.get("qualification_sidecar_schema_version") != 3
            or manifest.get("workload_count") != expected_count
            or not isinstance(workload_ids, list)
            or len(workload_ids) != expected_count
            or len(set(workload_ids)) != expected_count
            or any(
                not isinstance(workload_id, str) or _WORKLOAD_ID.fullmatch(workload_id) is None
                for workload_id in workload_ids
            )
            or workload_ids != campaign_workload_ids
            or not isinstance(entries, list)
            or len(entries) != expected_count
            or manifest.get("bindings_sha256") != _named_qualification_bindings_sha256(manifest)
            or manifest.get("qualification_authority_sha256")
            != hashlib.sha256(_canonical_json_bytes(manifest_authority)).hexdigest()
        ):
            raise ValueError("class frozen qualification manifest is invalid")
        manifest_build = self.qualification_authority(
            manifest_authority,
            label="class frozen qualification manifest",
            frozen_foundation=foundation_path,
        )
        linked.append(manifest_build)
        assert isinstance(manifest_authority, Mapping)
        if (
            manifest_authority["foundation_attestation"].get("sha256") != _sha256(foundation_path)
            or manifest_authority["foundation_attestation"].get("payload_sha256")
            != foundation_envelope["payload_sha256"]
            or configuration.get("chaff_qualification_set_manifest_sha256")
            != _sha256(manifest_path)
        ):
            raise ValueError("class frozen qualification authority differs from its foundation")
        expected_inventory = {"_qualification-set.json", *(f"{item}.json" for item in workload_ids)}
        if {entry.name for entry in qualification_root.iterdir()} != expected_inventory:
            raise ValueError("class frozen qualification sidecar inventory is incomplete")
        for index, (workload_id, entry) in enumerate(zip(workload_ids, entries, strict=True)):
            if not isinstance(entry, Mapping) or set(entry) != _NAMED_QUALIFICATION_ENTRY_KEYS:
                raise ValueError("class frozen qualification entry has an invalid schema")
            sidecar_binding = entry.get("qualification_sidecar")
            if (
                entry.get("index") != index
                or entry.get("workload_id") != workload_id
                or not isinstance(sidecar_binding, Mapping)
                or set(sidecar_binding) != {"path", "sha256"}
                or sidecar_binding.get("path") != f"{workload_id}.json"
            ):
                raise ValueError("class frozen qualification workload order is invalid")
            sidecar_path, sidecar = _load_json_file(
                self.root,
                qualification_root / f"{workload_id}.json",
                label=f"class frozen qualification {workload_id}",
                max_bytes=_MAX_FROZEN_INPUT_BYTES,
            )
            if (
                sidecar_binding.get("sha256") != _sha256(sidecar_path)
                or not isinstance(sidecar, Mapping)
                or set(sidecar) != _CLASS_STUDY_SIDECAR_KEYS
                or sidecar.get("schema_version") != 3
                or sidecar.get("artifact_type") != "qcsd-chaff-qualification"
                or sidecar.get("workload_id") != workload_id
                or sidecar.get("qualification_authority") != manifest_authority
                or sidecar.get("qualification_authority_sha256")
                != manifest.get("qualification_authority_sha256")
                or sidecar.get("qualification_source") != manifest_authority.get("prepare_source")
                or sidecar.get("qualification_image_digest")
                != manifest_authority.get("prepare_image_digest")
            ):
                raise ValueError("class frozen qualification sidecar authority is invalid")
        if (
            qualification_inputs.get("qualification_set") != expected_qualification
            or qualification_inputs.get("qualification_manifest_sha256") != _sha256(manifest_path)
            or qualification_inputs.get("qualification_manifest") != manifest
            or qualification_inputs.get("qualification_authority") != manifest_authority
            or not isinstance(provenance.get("fitting_contract"), Mapping)
            or provenance["fitting_contract"].get("workload_order") != workload_ids
        ):
            raise ValueError("class frozen fitting provenance differs from qualification set")

        return role, _require_same_build(linked)

    def inspection_is_historical(self, raw: str | os.PathLike[str], receipt_type: str) -> bool:
        """Classify only an explicit top-level inspection artefact as historical."""

        _path, _value, payload = _envelope(
            self.root,
            raw,
            label="class inspection target",
            expected_type=receipt_type,
        )
        if receipt_type in {_FOUNDATION, _READINESS}:
            schema = payload.get("attestation_schema_version")
            current = _FOUNDATION_SCHEMA if receipt_type == _FOUNDATION else _READINESS_SCHEMA
            return type(schema) is int and schema < current
        if receipt_type == _EVALUATION:
            schema = payload.get("schema_version")
            return type(schema) is int and schema < _EVALUATION_SCHEMA
        if receipt_type == _HISTORICAL:
            readiness = _bound_file(
                self.root,
                payload.get("readiness"),
                label="historical inspection readiness",
            )
            return self.inspection_is_historical(readiness, _READINESS)
        # Comparison and validation receipts have no historical outer schema.
        # They must therefore be traversed: a current wrapper cannot make a
        # historical nested authority silently inspectable.
        if receipt_type in {_VALIDATION, _COMPARISON}:
            return False
        return False

    def handoff_is_historical(self, raw: str | os.PathLike[str]) -> bool:
        root = _regular_directory(self.root, raw, label="class handoff")
        return self.inspection_is_historical(
            root / _HANDOFF_HISTORICAL_POST,
            _HISTORICAL,
        )

    def target(
        self,
        raw: str | os.PathLike[str],
        *,
        foundation: str | None,
        handoff: str | None,
        capture_result: str | None,
        qualification_manifest: str | None,
        prefix_spec_root: str | None,
    ) -> BuildAdmission | None:
        path = _under_root(self.root, raw, label="class verification target")
        if path.is_dir():
            if (path / "experiment.json").is_file():
                try:
                    return self.frozen_environment(path)
                except _HistoricalAuthority:
                    return None
            if (path / "dataset.json").is_file():
                if self.handoff_is_historical(path):
                    return None
                return self.handoff(path)
            manifest = path / "_qualification-set.json"
            if manifest.is_file():
                _manifest_path, value = _load_json_file(
                    self.root, manifest, label="class qualification manifest"
                )
                schema = value.get("schema_version") if isinstance(value, Mapping) else None
                if type(schema) is int and schema < 3:
                    return None
                linked = self.carrier_value(value, label="class qualification manifest")
                if foundation:
                    linked.append(self.foundation(foundation))
                return _require_same_build(linked) if linked else None
            linked: list[BuildAdmission] = []
            for filename in ("numeric-provenance.json", "provenance.json"):
                provenance = path / filename
                if provenance.is_file():
                    linked.extend(
                        self.carrier_file(
                            provenance,
                            label=f"class fitting {filename}",
                        )
                    )
            if qualification_manifest and prefix_spec_root:
                linked.extend(
                    self.carrier_file(
                        qualification_manifest,
                        label="class fitting qualification manifest",
                    )
                )
                if foundation:
                    linked.append(self.foundation(foundation))
            if not capture_result:
                raise ValueError("fitting verification requires --capture-result before Docker")
            linked.append(self.frozen_environment(capture_result))
            return _require_same_build(linked) if linked else None
        _path, value = _load_json_file(self.root, path, label="class verification target")
        receipt_type = value.get("receipt_type") if isinstance(value, Mapping) else None
        routes: dict[str, Callable[[str | os.PathLike[str]], BuildAdmission]] = {
            _ACQUISITION_AUTHORITY: self.acquisition_authority,
            _FOUNDATION: self.foundation,
            _READINESS: self.readiness,
            _HISTORICAL: self.historical,
            _COMPARISON: self.comparison,
            _VALIDATION: self.validation,
            _SUCCESSOR_DECISION: self.successor_decision,
            _SUCCESSOR_RESTART: self.successor_restart,
        }
        if receipt_type in routes:
            if self.inspection_is_historical(path, receipt_type):
                return None
            return routes[receipt_type](path)
        if receipt_type == _SUCCESSOR_POLICY:
            return None
        if receipt_type == _EVALUATION:
            if self.inspection_is_historical(path, _EVALUATION):
                return None
            if not handoff:
                raise ValueError("evaluation verification requires --handoff")
            if self.handoff_is_historical(handoff):
                return None
            return _require_same_build((self.evaluation(path), self.handoff(handoff)))
        return None


def _require_same_build(values: Sequence[BuildAdmission]) -> BuildAdmission:
    if not values:
        raise ValueError("no class-study build authority was resolved")
    first = values[0]
    identity = first.output_fields()[1:]
    for value in values[1:]:
        if value.output_fields()[1:] != identity:
            raise ValueError("class-study inputs resolve to different completed builds")
    return first


def _single(options: Mapping[str, object], name: str) -> str:
    value = options.get(name, "")
    if value is None or value == "":
        return ""
    if isinstance(value, (str, os.PathLike)):
        return os.fspath(value)
    raise TypeError(f"class-study --{name.replace('_', '-')} value is invalid")


def _many(options: Mapping[str, object], name: str) -> tuple[str, ...]:
    value = options.get(name, ())
    if value is None or value == "":
        return ()
    if isinstance(value, (str, os.PathLike)):
        return (os.fspath(value),)
    if not isinstance(value, Sequence):
        raise TypeError(f"class-study --{name.replace('_', '-')} values are invalid")
    result: list[str] = []
    for item in value:
        if not isinstance(item, (str, os.PathLike)):
            raise TypeError(f"class-study --{name.replace('_', '-')} value is invalid")
        result.append(os.fspath(item))
    return tuple(result)


def _required(options: Mapping[str, object], name: str, message: str) -> str:
    value = _single(options, name)
    if not value:
        raise ValueError(message)
    return value


_CAMPAIGN_CARRIER_KEYS = frozenset(
    {
        "evidence_role",
        "parameters",
        "chaff_qualification_set",
        "class_study_successor",
        "class_study_cohort_assembly",
    }
)
_YAML_IMPLICIT_NON_STRING = re.compile(
    r"(?:null|true|false|yes|no|on|off|~|"
    r"[-+]?[.](?:inf|nan)|"
    r"[-+]?0(?:x[0-9a-f]+|o[0-7]+|b[01]+)|"
    r"[-+]?[0-9]+(?::[0-9]+)+|"
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[Tt ].*)?|"
    r"[-+]?(?:(?:[0-9]+(?:[.][0-9]*)?|[.][0-9]+)(?:[eE][-+]?[0-9]+)?))\Z",
    re.IGNORECASE,
)


def _quoted_yaml_scalar(line: str, start: int) -> tuple[str, int]:
    quote = line[start]
    cursor = start + 1
    if quote == "'":
        value: list[str] = []
        while cursor < len(line):
            if line[cursor] == "'":
                if cursor + 1 < len(line) and line[cursor + 1] == "'":
                    value.append("'")
                    cursor += 2
                    continue
                return "".join(value), cursor + 1
            value.append(line[cursor])
            cursor += 1
        raise ValueError("class campaign has an unterminated quoted scalar")
    escaped = False
    while cursor < len(line):
        character = line[cursor]
        if character == '"' and not escaped:
            token = line[start : cursor + 1]
            try:
                value = json.loads(token)
            except json.JSONDecodeError as error:
                raise ValueError("class campaign has a non-JSON double-quoted scalar") from error
            if not isinstance(value, str):
                raise ValueError("class campaign quoted scalar is not a string")
            return value, cursor + 1
        if character == "\\" and not escaped:
            escaped = True
        else:
            escaped = False
        cursor += 1
    raise ValueError("class campaign has an unterminated quoted scalar")


def _campaign_masked_line(line: str) -> str:
    masked = list(line)
    cursor = 0
    while cursor < len(line):
        if line[cursor] in "'\"":
            _value, end = _quoted_yaml_scalar(line, cursor)
            for index in range(cursor, end):
                masked[index] = " "
            cursor = end
            continue
        if line[cursor] == "#":
            if cursor != 0 and line[cursor - 1] != " ":
                raise ValueError("class campaign has an unsafe unquoted hash scalar")
            for index in range(cursor, len(line)):
                masked[index] = " "
            break
        cursor += 1
    return "".join(masked)


class _CampaignFlowParser:
    def __init__(self, text: str, bump: Callable[[], None]):
        self.text = text
        self.cursor = 0
        self._bump = bump

    def _spaces(self) -> None:
        while self.cursor < len(self.text) and self.text[self.cursor] == " ":
            self.cursor += 1

    def _scalar(self, *, key: bool = False) -> object:
        self._spaces()
        if self.cursor >= len(self.text):
            raise ValueError("class campaign flow value is missing")
        if self.text[self.cursor] in "'\"":
            value, self.cursor = _quoted_yaml_scalar(self.text, self.cursor)
            return value
        start = self.cursor
        stops = ":" if key else ",]}"
        while self.cursor < len(self.text) and self.text[self.cursor] not in stops:
            self.cursor += 1
        value = self.text[start : self.cursor].strip(" ")
        if not value:
            raise ValueError("class campaign flow scalar is empty")
        if not key and re.search(r":(?:\s|$)", value):
            # YAML treats this spelling inside a flow sequence as an implicit
            # mapping.  The campaign schema never emits that shorthand, so
            # rejecting it avoids silently interpreting an authority key as a
            # harmless scalar.
            raise ValueError("class campaign flow sequence has an implicit mapping")
        if _YAML_IMPLICIT_NON_STRING.fullmatch(value) is not None:
            return None
        return value

    def value(self) -> object:
        self._spaces()
        if self.cursor >= len(self.text):
            raise ValueError("class campaign flow value is missing")
        self._bump()
        if self.text[self.cursor] == "{":
            return self.mapping()
        if self.text[self.cursor] == "[":
            return self.sequence()
        return self._scalar()

    def mapping(self) -> dict[str, object]:
        self.cursor += 1
        result: dict[str, object] = {}
        self._spaces()
        if self.cursor < len(self.text) and self.text[self.cursor] == "}":
            self.cursor += 1
            return result
        while True:
            key = self._scalar(key=True)
            if not isinstance(key, str) or not key or key in result:
                raise ValueError("class campaign flow mapping has an invalid duplicate key")
            self._spaces()
            if self.cursor >= len(self.text) or self.text[self.cursor] != ":":
                raise ValueError("class campaign flow mapping key has no colon")
            self.cursor += 1
            result[key] = self.value()
            self._spaces()
            if self.cursor >= len(self.text):
                raise ValueError("class campaign flow mapping is unterminated")
            delimiter = self.text[self.cursor]
            self.cursor += 1
            if delimiter == "}":
                return result
            if delimiter != ",":
                raise ValueError("class campaign flow mapping is malformed")

    def sequence(self) -> list[object]:
        self.cursor += 1
        result: list[object] = []
        self._spaces()
        if self.cursor < len(self.text) and self.text[self.cursor] == "]":
            self.cursor += 1
            return result
        while True:
            result.append(self.value())
            self._spaces()
            if self.cursor >= len(self.text):
                raise ValueError("class campaign flow sequence is unterminated")
            delimiter = self.text[self.cursor]
            self.cursor += 1
            if delimiter == "]":
                return result
            if delimiter != ",":
                raise ValueError("class campaign flow sequence is malformed")


class _CampaignSubsetParser:
    def __init__(self, text: str):
        if any(
            character == "\t" or (ord(character) < 32 and character not in "\r\n")
            for character in text
        ):
            raise ValueError("class campaign contains tabs or control characters")
        self.lines: list[tuple[int, str]] = []
        self.index = 0
        self.nodes = 0
        for original in text.splitlines():
            masked = _campaign_masked_line(original)
            stripped_masked = masked.lstrip(" ")
            if (
                stripped_masked.startswith("%")
                or re.match(r"(?:---|[.][.][.])(?:\s|$)", stripped_masked)
                or re.search(r"(?:^|[\s\[{,])[?](?:\s|$)", masked)
                or re.search(r"(?:^|[\s,{])<<\s*:", masked)
                or re.search(r"(?:^|[\s\[{:,-])[&*!][^\s,}\]]+", masked)
                or re.search(r":\s*[|>]", masked)
            ):
                raise ValueError("class campaign uses unsupported YAML syntax")
            comment = self._comment_index(original)
            line = original[:comment].rstrip(" \r")
            if not line.strip(" "):
                continue
            indent = len(line) - len(line.lstrip(" "))
            self.lines.append((indent, line[indent:]))

    @staticmethod
    def _comment_index(line: str) -> int:
        cursor = 0
        while cursor < len(line):
            if line[cursor] in "'\"":
                _value, cursor = _quoted_yaml_scalar(line, cursor)
                continue
            if line[cursor] == "#":
                if cursor != 0 and line[cursor - 1] != " ":
                    raise ValueError("class campaign has an unsafe unquoted hash scalar")
                return cursor
            cursor += 1
        return len(line)

    def _bump(self) -> None:
        self.nodes += 1
        if self.nodes > 100_000:
            raise ValueError("class campaign contains too many YAML nodes")

    @staticmethod
    def _mapping_entry(text: str) -> tuple[str, str]:
        cursor = 0
        while cursor < len(text):
            if text[cursor] in "'\"":
                _value, cursor = _quoted_yaml_scalar(text, cursor)
                continue
            if text[cursor] == ":" and (cursor + 1 == len(text) or text[cursor + 1] == " "):
                return text[:cursor], text[cursor + 1 :]
            cursor += 1
        raise ValueError("class campaign block mapping entry has no colon")

    @staticmethod
    def _key(text: str) -> str:
        value = text.strip(" ")
        if not value:
            raise ValueError("class campaign mapping key is empty")
        if value[0] in "'\"":
            decoded, end = _quoted_yaml_scalar(value, 0)
            if end != len(value):
                raise ValueError("class campaign quoted mapping key is malformed")
            return decoded
        if _YAML_IMPLICIT_NON_STRING.fullmatch(value) is not None:
            raise ValueError("class campaign mapping key is not a string")
        return value

    def _inline(self, text: str) -> object:
        value = text.strip(" ")
        if not value:
            raise ValueError("class campaign inline value is empty")
        if value[0] in "{[":
            parser = _CampaignFlowParser(value, self._bump)
            output = parser.value()
            parser._spaces()
            if parser.cursor != len(value):
                raise ValueError("class campaign flow value has trailing syntax")
            return output
        self._bump()
        if value[0] in "'\"":
            decoded, end = _quoted_yaml_scalar(value, 0)
            if end != len(value):
                raise ValueError("class campaign quoted scalar has trailing syntax")
            return decoded
        if _YAML_IMPLICIT_NON_STRING.fullmatch(value) is not None:
            return None
        return value

    def parse(self) -> Mapping[str, object]:
        if not self.lines or self.lines[0][0] != 0:
            raise ValueError("class campaign root mapping is missing")
        output = self._block(0, 0)
        if self.index != len(self.lines) or not isinstance(output, Mapping):
            raise ValueError("class campaign root is not one mapping")
        return output

    def _block(self, indent: int, depth: int) -> object:
        if depth > 32 or self.index >= len(self.lines):
            raise ValueError("class campaign block nesting is invalid")
        content = self.lines[self.index][1]
        if content == "-" or content.startswith("- "):
            return self._sequence(indent, depth)
        return self._mapping(indent, depth)

    def _nested_or_null(self, indent: int, depth: int) -> object:
        if self.index >= len(self.lines):
            return None
        child_indent, child = self.lines[self.index]
        if child_indent > indent or (
            child_indent == indent and (child == "-" or child.startswith("- "))
        ):
            return self._block(child_indent, depth + 1)
        return None

    def _mapping(self, indent: int, depth: int) -> dict[str, object]:
        result: dict[str, object] = {}
        while self.index < len(self.lines):
            current_indent, content = self.lines[self.index]
            if current_indent < indent or (
                current_indent == indent and (content == "-" or content.startswith("- "))
            ):
                break
            if current_indent != indent:
                raise ValueError("class campaign mapping indentation is invalid")
            key_text, value_text = self._mapping_entry(content)
            key = self._key(key_text)
            if key in result:
                raise ValueError("class campaign mapping has a duplicate decoded key")
            self._bump()
            self.index += 1
            result[key] = (
                self._inline(value_text)
                if value_text.strip(" ")
                else self._nested_or_null(indent, depth)
            )
        return result

    def _sequence_mapping(self, indent: int, depth: int, content: str) -> dict[str, object]:
        key_text, value_text = self._mapping_entry(content)
        key = self._key(key_text)
        self._bump()
        result = {
            key: (
                self._inline(value_text)
                if value_text.strip(" ")
                else self._nested_or_null(indent + 2, depth)
            )
        }
        continuation_indent = indent + 2
        if self.index < len(self.lines) and self.lines[self.index][0] == continuation_indent:
            continuation = self._mapping(continuation_indent, depth + 1)
            if set(result).intersection(continuation):
                raise ValueError("class campaign sequence mapping has a duplicate decoded key")
            result.update(continuation)
        return result

    def _sequence(self, indent: int, depth: int) -> list[object]:
        result: list[object] = []
        while self.index < len(self.lines):
            current_indent, content = self.lines[self.index]
            if current_indent != indent or not (content == "-" or content.startswith("- ")):
                break
            self._bump()
            self.index += 1
            remainder = content[1:].lstrip(" ")
            if not remainder:
                value = self._nested_or_null(indent, depth)
            elif remainder == "-" or remainder.startswith("- "):
                # Generated campaigns never use compact block list nesting.
                # Reject it instead of decoding the leading dash as a mapping
                # key and potentially hiding an authority-bearing scalar.
                raise ValueError("class campaign uses unsupported compact nested sequences")
            elif remainder[0] in "[{":
                value = self._inline(remainder)
            else:
                try:
                    self._mapping_entry(remainder)
                except ValueError:
                    value = self._inline(remainder)
                else:
                    value = self._sequence_mapping(indent, depth + 1, remainder)
            result.append(value)
        return result


def _campaign_carrier_scalars(text: str) -> dict[str, list[str]]:
    """Parse the restricted safe-dump subset and extract all authority scalars."""

    document = _CampaignSubsetParser(text).parse()
    role = document.get("evidence_role")
    if not isinstance(role, str) or not role:
        raise ValueError("class campaign has no root string evidence role")
    selected = {name: [] for name in _CAMPAIGN_CARRIER_KEYS}
    selected["evidence_role"].append(role)
    pending: list[tuple[object, bool, int]] = [(document, True, 0)]
    visited = 0
    while pending:
        value, root, depth = pending.pop()
        visited += 1
        if visited > 100_000 or depth > 32:
            raise ValueError("class campaign parsed structure is too deeply nested")
        if isinstance(value, Mapping):
            children: list[tuple[object, bool, int]] = []
            for key, item in value.items():
                if key == "evidence_role" and not root:
                    raise ValueError("class campaign evidence role must appear only at the root")
                if key in selected and key != "evidence_role":
                    if not isinstance(item, str) or not item:
                        raise ValueError(f"class campaign {key} is not a string scalar")
                    selected[key].append(item)
                children.append((item, False, depth + 1))
            pending.extend(reversed(children))
        elif isinstance(value, list):
            pending.extend((item, False, depth + 1) for item in reversed(value))
    for name in (
        "chaff_qualification_set",
        "class_study_successor",
        "class_study_cohort_assembly",
    ):
        if len(selected[name]) > 1:
            raise ValueError(f"class campaign has ambiguous {name.replace('_', ' ')}")
    return selected


def _campaign_authorities(
    resolver: _Resolver,
    raw: str | os.PathLike[str],
    *,
    allow_prospective: bool = False,
    follow_runtime: bool = True,
) -> tuple[str, list[BuildAdmission]]:
    path = _regular_file(resolver.root, raw, label="class campaign")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError("class campaign is not readable UTF-8") from error
    selected = _campaign_carrier_scalars(text)
    role = selected["evidence_role"][0]
    if re.fullmatch(r"[a-z-]+", role) is None:
        raise ValueError("class campaign has an invalid evidence role")
    authorities: list[BuildAdmission] = []
    parameters = selected["parameters"]
    fitted_roots = {
        _under_root(
            resolver.root,
            path.parent / Path(item).parent,
            label="class campaign fitted bundle",
        )
        for item in parameters
        if any(
            item.endswith(f"/{name}")
            for name in ("traffic-morphing.json", "wtf-pad.json", "walkie-talkie.json")
        )
    }
    if follow_runtime:
        for bundle in sorted(fitted_roots):
            if allow_prospective and not (bundle.exists() or bundle.is_symlink()):
                continue
            authorities.extend(
                resolver.carrier_directory(
                    bundle,
                    label="class campaign fitted bundle",
                    filenames=("provenance.json",),
                )
            )
    qualifications = selected["chaff_qualification_set"]
    if len(qualifications) > 1:
        raise ValueError("class campaign has ambiguous qualification authority")
    if qualifications and follow_runtime:
        if path.parent.name == "campaigns" and path.parent.parent.name == "plan":
            manifest = (
                path.parent.parent.parent
                / "qualification"
                / qualifications[0]
                / "_qualification-set.json"
            )
        else:
            manifest = (
                resolver.root
                / "config/chaff-qualification-store/sets"
                / qualifications[0]
                / "_qualification-set.json"
            )
        if allow_prospective and not (manifest.exists() or manifest.is_symlink()):
            manifest = None
        if manifest is not None:
            authorities.extend(
                resolver.carrier_file(manifest, label="class campaign qualification manifest")
            )
    successors = selected["class_study_successor"]
    if len(successors) > 1:
        raise ValueError("class campaign has ambiguous successor authority")
    if successors:
        authorities.append(
            resolver.successor_restart(
                _under_root(
                    resolver.root,
                    path.parent / successors[0],
                    label="class campaign successor restart",
                )
            )
        )
    assemblies = selected["class_study_cohort_assembly"]
    if len(assemblies) > 1:
        raise ValueError("class campaign has ambiguous cohort assembly")
    if assemblies:
        authorities.extend(
            resolver.carrier_file(
                _under_root(
                    resolver.root,
                    path.parent / assemblies[0],
                    label="class campaign cohort assembly",
                ),
                label="class campaign cohort assembly",
            )
        )
    return role, authorities


def resolve_action_admission(
    root: Path,
    *,
    action: str,
    stage: str = "",
    execute: bool = False,
    cohort_version: int | None = None,
    options: Mapping[str, object] | None = None,
    build_loader: Callable[..., BuildAdmission] | None = None,
) -> BuildAdmission | None:
    """Resolve the build consumed by one class-study action, if any."""

    values = dict(options or {})
    resolver = _Resolver(Path(root).resolve(), build_loader=build_loader)
    admissions: list[BuildAdmission] = []

    def add_foundation(required: bool = True) -> None:
        raw = _single(values, "foundation")
        if raw:
            admissions.append(resolver.foundation(raw))
        elif required:
            raise ValueError("class-study action requires --foundation-attestation before Docker")

    def add_single(name: str, route: Callable[[str], BuildAdmission]) -> None:
        raw = _single(values, name)
        if raw:
            admissions.append(route(raw))

    def add_results(*names: str) -> None:
        for name in names:
            admissions.extend(resolver.frozen_environment(raw) for raw in _many(values, name))

    def add_carrier_files(*names: str) -> None:
        for name in names:
            for raw in _many(values, name):
                admissions.extend(
                    resolver.carrier_file(raw, label=f"class {name.replace('_', ' ')}")
                )

    def add_carrier_directories(*names: str, filenames: Sequence[str] | None = None) -> None:
        for name in names:
            for raw in _many(values, name):
                admissions.extend(
                    resolver.carrier_directory(
                        raw,
                        label=f"class {name.replace('_', ' ')}",
                        filenames=filenames,
                    )
                )

    def add_existing_carrier_files(*names: str) -> None:
        for name in names:
            for raw in _many(values, name):
                path = _under_root(
                    resolver.root,
                    raw,
                    label=f"class {name.replace('_', ' ')}",
                )
                if path.exists() or path.is_symlink():
                    admissions.extend(
                        resolver.carrier_file(
                            path,
                            label=f"class {name.replace('_', ' ')}",
                        )
                    )

    def add_qualification_publications(*names: str) -> None:
        for name in names:
            for raw in _many(values, name):
                publication = _regular_directory(
                    resolver.root,
                    raw,
                    label=f"class {name.replace('_', ' ')}",
                )
                if successor:
                    manifest = successor_paths["qualification_manifest"]
                elif stage == "pilot":
                    manifest = publication / _PILOT_QUALIFICATION_SET / "_qualification-set.json"
                elif stage == "authoritative":
                    manifest = (
                        publication / _AUTHORITATIVE_QUALIFICATION_SET / "_qualification-set.json"
                    )
                else:
                    raise ValueError(
                        "class qualification publication requires stage pilot or authoritative"
                    )
                if manifest.exists() or manifest.is_symlink():
                    admissions.extend(
                        resolver.carrier_file(
                            manifest,
                            label="class published qualification manifest",
                        )
                    )

    def add_existing_file(path: Path, *, label: str) -> None:
        if path.exists() or path.is_symlink():
            admissions.extend(resolver.carrier_file(path, label=label))

    def add_existing_directory(
        path: Path,
        *,
        label: str,
        filenames: Sequence[str] | None = None,
    ) -> None:
        if path.exists() or path.is_symlink():
            admissions.extend(resolver.carrier_directory(path, label=label, filenames=filenames))

    def finish() -> BuildAdmission | None:
        if not admissions:
            return None
        admitted = _require_same_build(admissions)
        resolver.require_source_constraints(admitted)
        return admitted

    successor = _single(values, "successor_restart")
    if successor:
        if action not in _SUCCESSOR_RUNTIME_ACTIONS:
            raise ValueError(f"class-study {action} does not accept --successor-restart")
        admissions.append(resolver.successor_restart(successor))
        successor_paths = resolver.successor_runtime_paths(successor)
        sidecar_path = (
            successor_paths["qualification_set_root"]
            if action in {"readiness", "finalize-fitting", "verify"}
            else successor_paths["qualification_work_root"]
        )
        expected_options: tuple[tuple[str, Path], ...] = (
            ("numeric_bundle", successor_paths["numeric_bundle"]),
            ("prefix_spec_root", successor_paths["prefix_spec_root"]),
            ("qualification_checkpoint", successor_paths["qualification_checkpoint"]),
            ("qualification_sidecar_root", sidecar_path),
            (
                "qualification_publication_root",
                successor_paths["qualification_set_root"].parent,
            ),
            ("qualification_manifest", successor_paths["qualification_manifest"]),
            ("final_bundle", successor_paths["final_bundle"]),
        )
        for name, expected in expected_options:
            supplied = _many(values, name)
            for raw in supplied:
                observed = _under_root(
                    resolver.root,
                    raw,
                    label=f"successor {name.replace('_', ' ')}",
                )
                if observed != expected:
                    raise ValueError(f"successor {name.replace('_', ' ')} must use {expected}")
        campaign = _single(values, "campaign")
        if campaign:
            campaign_path = _under_root(
                resolver.root,
                campaign,
                label="successor campaign",
            )
            if campaign_path.parent != successor_paths["root"] / "plan/campaigns":
                raise ValueError("successor campaign must come from its immutable plan")

        # Mirror only the derived paths consumed by this action.  Prospective
        # outputs and unrelated later-stage evidence must not select or
        # conflict with the image for an earlier action.
        if action in {"prefix-specs", "qualify-prefix", "finalize-fitting"}:
            add_existing_directory(
                successor_paths["numeric_bundle"],
                label="successor numeric bundle",
                filenames=("numeric-provenance.json",),
            )
        if action in {"qualify-prefix", "finalize-fitting", "readiness"}:
            add_existing_directory(
                successor_paths["prefix_spec_root"],
                label="successor prefix-spec root",
            )
        if action == "qualify-prefix":
            add_existing_file(
                successor_paths["qualification_checkpoint"],
                label="successor qualification checkpoint",
            )
            add_existing_directory(
                successor_paths["qualification_work_root"],
                label="successor qualification work",
            )
            add_existing_file(
                successor_paths["qualification_manifest"],
                label="successor published qualification manifest",
            )
        if action in {"finalize-fitting", "readiness"}:
            add_existing_directory(
                successor_paths["qualification_set_root"],
                label="successor published qualification set",
            )
            add_existing_directory(
                successor_paths["qualification_set_root"] / "_prefix-specs",
                label="successor published qualification prefix specs",
            )
        if action == "readiness":
            add_existing_directory(
                successor_paths["final_bundle"],
                label="successor final fitting bundle",
                filenames=("provenance.json",),
            )

    # Production routes promotion receipts before constructing cohort/fitting
    # admissions.  Match that ordering so unrelated optional inputs cannot
    # block inspection of an already closed promotion object.
    if action == "verify":
        raw_target = _required(values, "target", "class-study verify requires --target")
        target_path = _under_root(
            resolver.root,
            raw_target,
            label="class verification target",
        )
        if target_path.is_file():
            _path, target_value = _load_json_file(
                resolver.root,
                target_path,
                label="class verification target",
            )
            receipt_type = (
                target_value.get("receipt_type") if isinstance(target_value, Mapping) else None
            )
            if receipt_type in {
                _ACQUISITION_AUTHORITY,
                _FOUNDATION,
                _READINESS,
                _HISTORICAL,
                _COMPARISON,
                _VALIDATION,
            }:
                promotion = resolver.target(
                    raw_target,
                    foundation=None,
                    handoff=None,
                    capture_result=None,
                    qualification_manifest=None,
                    prefix_spec_root=None,
                )
                if promotion is not None:
                    admissions.append(promotion)
                return finish()

    if not successor and action in {
        "readiness",
        "cohort",
        "campaigns",
        "fit-numeric",
        "prefix-specs",
        "qualify-prefix",
        "finalize-fitting",
        "capture",
        "resume",
        "export",
    }:
        if action in {"cohort", "campaigns"}:
            acquisition_completion = _required(
                values,
                "acquisition_completion",
                f"class-study {action} requires --acquisition-completion before Docker",
            )
            admissions.append(resolver.acquisition_completion(acquisition_completion))
        else:
            add_single("acquisition_completion", resolver.acquisition_completion)

    if not successor and action in {
        "campaigns",
        "fit-numeric",
        "prefix-specs",
        "qualify-prefix",
        "finalize-fitting",
        "capture",
        "resume",
        "export",
    }:
        add_carrier_files("final_selection", "final_cohort_assembly")

    if action in {"comparison-review", "attest", "status"}:
        raw_evaluation = _single(values, "evaluation")
        if raw_evaluation:
            if action == "status" and resolver.inspection_is_historical(
                raw_evaluation, _EVALUATION
            ):
                pass
            else:
                admissions.append(resolver.evaluation(raw_evaluation))

    if not successor and (
        action in {"prefix-specs", "qualify-prefix", "finalize-fitting", "readiness", "status"}
        or (action in {"cohort", "campaigns"} and stage == "authoritative")
    ):
        add_carrier_directories("numeric_bundle", filenames=("numeric-provenance.json",))

    if not successor and action in {
        "qualify-prefix",
        "finalize-fitting",
        "readiness",
        "status",
    }:
        add_carrier_directories("prefix_spec_root")

    if action == "acquisition-authority":
        build = _required(
            values,
            "build",
            "class-study acquisition-authority requires --build-execution-receipt before Docker",
        )
        admissions.append(
            resolver.build(
                _regular_file(resolver.root, build, label="acquisition authority build"),
                expected_cohort=cohort_version,
            )
        )
        for name, route in (
            ("pinned_cdp", resolver.pinned_cdp),
            ("browser_egress", resolver.browser_egress),
        ):
            raw = _required(
                values, name, f"class-study acquisition-authority requires {name} before Docker"
            )
            admissions.append(route(raw))
    elif action == "foundation":
        build = _required(
            values,
            "build",
            "class-study foundation requires --build-execution-receipt before Docker",
        )
        admissions.append(
            resolver.build(
                _regular_file(resolver.root, build, label="foundation build execution"),
                expected_cohort=cohort_version,
            )
        )
        add_single("pinned_cdp", resolver.pinned_cdp)
        add_single("browser_egress", resolver.browser_egress)
        add_single("reference", resolver.reference)
        add_single("code_gate", resolver.code_gate)
        add_single("controlled_qualification", resolver.controlled_qualification)
        add_results("regression_results", "controlled_results")
    elif action == "readiness":
        add_foundation()
        if successor:
            add_results("authoritative_fitting_result", "certification_result")
        else:
            build = _required(
                values,
                "build",
                "class-study readiness requires --build-execution-receipt before Docker",
            )
            admissions.append(
                resolver.build(
                    _regular_file(resolver.root, build, label="readiness build execution"),
                    expected_cohort=cohort_version,
                )
            )
            add_single("reference", resolver.reference)
            add_single("code_gate", resolver.code_gate)
            add_single("controlled_qualification", resolver.controlled_qualification)
            add_results("regression_results", "controlled_results")
            add_results(
                "pilot_fitting_result",
                "pilot_compatibility_result",
                "authoritative_fitting_result",
                "certification_result",
            )
            add_carrier_files("final_selection")
            add_carrier_directories("final_bundle", filenames=("provenance.json",))
            add_carrier_directories("qualification_sidecar_root")
            add_carrier_files("final_cohort_assembly", "pilot_cohort_assembly")
    elif action == "successor-decision":
        add_foundation()
        add_results("certification_result")
        add_carrier_files("final_selection", "final_cohort_assembly")
    elif action == "successor-restart":
        decision = _required(
            values,
            "successor_decision",
            "class-study successor-restart requires --successor-decision before Docker",
        )
        admissions.append(resolver.successor_decision(decision))
    elif action == "successor-verify":
        target = _required(values, "target", "class-study successor-verify requires --target")
        admission = resolver.target(
            target,
            foundation=None,
            handoff=None,
            capture_result=None,
            qualification_manifest=None,
            prefix_spec_root=None,
        )
        if admission is not None:
            admissions.append(admission)
    elif action == "fit-numeric":
        _required(
            values,
            "capture_result",
            "class-study fit-numeric requires --capture-result before Docker",
        )
        add_results("capture_result", "results")
    elif action == "prefix-specs":
        _required(
            values,
            "capture_result",
            "class-study prefix-specs requires --capture-result before Docker",
        )
        add_results("capture_result")
    elif action == "acquisition-init":
        authority = _single(values, "acquisition_authority")
        if authority and _single(values, "foundation"):
            raise ValueError(
                "acquisition-init accepts exactly one acquisition authority or foundation"
            )
        if authority:
            admissions.append(resolver.acquisition_authority(authority))
        else:
            add_foundation()
    elif action in {"acquisition-run", "acquisition-status", "acquisition-complete"}:
        acquisition = _required(
            values,
            "acquisition_root",
            f"class-study {action} requires --acquisition-root before Docker",
        )
        admissions.append(resolver.acquisition(acquisition))
    elif action in {"cohort", "campaigns"} and stage != "authoritative":
        pass
    elif (action in {"cohort", "campaigns"} and stage == "authoritative") or action in {
        "qualify-prefix",
        "finalize-fitting",
    }:
        add_foundation()
        if action in {"cohort", "campaigns", "finalize-fitting"}:
            add_results("results")
        if action == "qualify-prefix":
            add_results("capture_result")
            add_existing_carrier_files("qualification_checkpoint")
            add_carrier_directories("qualification_sidecar_root")
            add_qualification_publications("qualification_publication_root")
        if action == "finalize-fitting":
            add_carrier_files("qualification_manifest")
    elif action == "capture":
        add_foundation()
        add_single("readiness", resolver.readiness)
        add_single("historical_pre", resolver.historical)
        add_results("results")
        role, campaign_admissions = _campaign_authorities(
            resolver,
            _required(values, "campaign", "class-study capture requires --campaign before Docker"),
        )
        admissions.extend(campaign_admissions)
        if role in {"canary", "formal"} and (
            not _single(values, "readiness") or not _single(values, "historical_pre")
        ):
            raise ValueError(
                "class-study formal capture requires readiness and historical-pre before Docker"
            )
        if execute:
            build = _required(
                values,
                "build",
                "class-study capture --execute requires --build-execution-receipt before Docker",
            )
            admissions.append(
                resolver.build(_regular_file(resolver.root, build, label="capture build execution"))
            )
    elif action == "resume":
        add_foundation()
        add_single("readiness", resolver.readiness)
        add_single("historical_pre", resolver.historical)
        add_results("results")
        capture_result = _required(
            values,
            "capture_result",
            "class-study resume requires --capture-result before Docker",
        )
        role, frozen_admission = resolver.frozen_resume_authority(
            capture_result,
            canonical_successor=successor or None,
            canonical_foundation=_single(values, "foundation") or None,
            canonical_readiness=_single(values, "readiness") or None,
            canonical_historical_pre=_single(values, "historical_pre") or None,
        )
        admissions.append(frozen_admission)
        if role in {"canary", "formal"} and (
            not _single(values, "readiness") or not _single(values, "historical_pre")
        ):
            raise ValueError(
                "class-study formal resume requires readiness and historical-pre before Docker"
            )
    elif action == "historical-snapshot":
        readiness = _required(
            values,
            "readiness",
            "class-study historical-snapshot requires --readiness-attestation before Docker",
        )
        admissions.append(resolver.readiness(readiness))
        if _single(values, "historical_pre"):
            admissions.append(resolver.historical(_single(values, "historical_pre")))
        add_results("formal_results")
    elif action == "export":
        snapshot = _required(
            values,
            "historical_post",
            "class-study export requires --historical-post-snapshot before Docker",
        )
        admissions.append(resolver.historical(snapshot))
        add_results("results")
    elif action in {"evaluate", "comparison-review"}:
        handoff = _required(
            values, "handoff", f"class-study {action} requires --handoff before Docker"
        )
        admissions.append(resolver.handoff(handoff))
        if action == "comparison-review" and not _single(values, "evaluation"):
            raise ValueError(
                "class-study comparison-review requires --evaluation-receipt before Docker"
            )
    elif action == "attest":
        readiness = _required(
            values,
            "readiness",
            "class-study attest requires --readiness-attestation before Docker",
        )
        admissions.append(resolver.readiness(readiness))
        for name, route in (
            ("historical_pre", resolver.historical),
            ("historical_post", resolver.historical),
            ("handoff", resolver.handoff),
            ("comparison", resolver.comparison),
        ):
            add_single(name, route)
        if not _single(values, "evaluation"):
            raise ValueError("class-study attest requires --evaluation-receipt before Docker")
        add_results("canary_results", "formal_results")
    elif action == "status":
        add_single("acquisition_authority", resolver.acquisition_authority)
        for name, route, receipt_type in (
            (
                "foundation",
                resolver.foundation,
                _FOUNDATION,
            ),
            (
                "readiness",
                resolver.readiness,
                _READINESS,
            ),
        ):
            raw = _single(values, name)
            if not raw:
                continue
            if resolver.inspection_is_historical(raw, receipt_type):
                continue
            admissions.append(route(raw))
        for name, route, receipt_type in (
            ("historical_pre", resolver.historical, _HISTORICAL),
            ("historical_post", resolver.historical, _HISTORICAL),
            ("comparison", resolver.comparison, _COMPARISON),
            ("validation", resolver.validation, _VALIDATION),
        ):
            raw = _single(values, name)
            if raw and not resolver.inspection_is_historical(raw, receipt_type):
                admissions.append(route(raw))
        raw_handoff = _single(values, "handoff")
        if raw_handoff and not resolver.handoff_is_historical(raw_handoff):
            admissions.append(resolver.handoff(raw_handoff))
        for raw in _many(values, "results"):
            try:
                admissions.append(resolver.frozen_environment(raw))
            except _HistoricalAuthority:
                pass
        for name, route in (
            ("acquisition_root", resolver.acquisition),
            ("acquisition_completion", resolver.acquisition_completion),
        ):
            raw = _single(values, name)
            if raw:
                provenance_root = (
                    _regular_directory(resolver.root, raw, label="class acquisition root")
                    if name == "acquisition_root"
                    else _regular_file(
                        resolver.root, raw, label="class acquisition completion"
                    ).parent
                )
                _path, _value, payload = _envelope(
                    resolver.root,
                    provenance_root / "provenance.json",
                    label="class acquisition provenance",
                    expected_type=_ACQUISITION,
                )
                schema = payload.get("acquisition_schema_version")
                if type(schema) is int and schema < _ACQUISITION_SCHEMA:
                    continue
                admissions.append(route(raw))
        for raw in _many(values, "qualification_manifest"):
            _path, manifest = _load_json_file(
                resolver.root, raw, label="class qualification manifest"
            )
            schema = manifest.get("schema_version") if isinstance(manifest, Mapping) else None
            if type(schema) is int and schema < 3:
                continue
            admissions.extend(
                resolver.carrier_value(manifest, label="class qualification manifest")
            )
        for raw in _many(values, "final_bundle"):
            bundle = _regular_directory(resolver.root, raw, label="class final bundle")
            _path, provenance = _load_json_file(
                resolver.root,
                bundle / "provenance.json",
                label="class final-bundle provenance",
            )
            schema = provenance.get("schema_version") if isinstance(provenance, Mapping) else None
            if schema == 1:
                continue
            admissions.extend(
                resolver.carrier_file(
                    bundle / "provenance.json",
                    label="class final-bundle provenance",
                )
            )
        raw_selection = _single(values, "final_selection")
        if raw_selection:
            _path, _value, selection = _envelope(
                resolver.root,
                raw_selection,
                label="class final selection",
                expected_type="qcsd-class-study-final-selection-input",
            )
            schema = selection.get("selection_schema_version")
            if schema != 1:
                admissions.extend(resolver.carrier_value(selection, label="class final selection"))
        raw_assembly = _single(values, "final_cohort_assembly")
        if raw_assembly:
            _path, _value, assembly = _envelope(
                resolver.root,
                raw_assembly,
                label="class final cohort assembly",
                expected_type="qcsd-class-study-cohort-assembly",
            )
            schema = assembly.get("assembly_schema_version")
            if type(schema) is not int or schema >= 3:
                admissions.extend(
                    resolver.carrier_value(assembly, label="class final cohort assembly")
                )
    elif action == "verify":
        target = _required(values, "target", "class-study verify requires --target")
        if not successor:
            add_single("acquisition_completion", resolver.acquisition_completion)
            add_carrier_files("final_selection", "final_cohort_assembly")
        admission = resolver.target(
            target,
            foundation=_single(values, "foundation") or None,
            handoff=_single(values, "handoff") or None,
            capture_result=_single(values, "capture_result") or None,
            qualification_manifest=(
                _many(values, "qualification_manifest")[0]
                if _many(values, "qualification_manifest")
                else None
            ),
            prefix_spec_root=(
                _many(values, "prefix_spec_root")[0] if _many(values, "prefix_spec_root") else None
            ),
        )
        if admission is not None:
            admissions.append(admission)

    # Successor-mode fit/prefix and every other allowed successor action have
    # already admitted the restart at the top of this function.  The remaining
    # v1 actions intentionally carry no current build authority.
    return finish()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-root", type=Path, required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--stage", default="")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--cohort-version", type=int)
    for name in (
        "build",
        "foundation",
        "acquisition-authority",
        "readiness",
        "historical-pre",
        "historical-post",
        "handoff",
        "evaluation",
        "comparison",
        "validation",
        "acquisition-root",
        "capture-result",
        "successor-decision",
        "successor-restart",
        "target",
        "final-selection",
        "pinned-cdp",
        "browser-egress",
        "reference",
        "code-gate",
        "controlled-qualification",
        "pilot-fitting-result",
        "pilot-compatibility-result",
        "authoritative-fitting-result",
        "certification-result",
        "acquisition-completion",
        "qualification-checkpoint",
        "qualification-sidecar-root",
        "final-cohort-assembly",
        "pilot-cohort-assembly",
        "campaign",
        "campaign-root",
        "qualification-publication-root",
    ):
        parser.add_argument(f"--{name}", default="")
    for name in (
        "result",
        "regression-result",
        "controlled-result",
        "canary-result",
        "formal-result",
        "numeric-bundle",
        "prefix-spec-root",
        "qualification-manifest",
        "final-bundle",
    ):
        parser.add_argument(f"--{name}", action="append", default=[])
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parser = _parser()
    parsed = parser.parse_args(arguments)
    if parsed.cohort_version is not None and parsed.cohort_version < 1:
        parser.error("--cohort-version must be positive")
    options = {
        name: getattr(parsed, name)
        for name in (
            "build",
            "foundation",
            "acquisition_authority",
            "readiness",
            "historical_pre",
            "historical_post",
            "handoff",
            "evaluation",
            "comparison",
            "validation",
            "acquisition_root",
            "capture_result",
            "successor_decision",
            "successor_restart",
            "target",
            "final_selection",
            "pinned_cdp",
            "browser_egress",
            "reference",
            "code_gate",
            "controlled_qualification",
            "pilot_fitting_result",
            "pilot_compatibility_result",
            "authoritative_fitting_result",
            "certification_result",
            "acquisition_completion",
            "qualification_checkpoint",
            "qualification_sidecar_root",
            "final_cohort_assembly",
            "pilot_cohort_assembly",
            "campaign",
            "campaign_root",
            "qualification_publication_root",
            "result",
            "regression_result",
            "controlled_result",
            "canary_result",
            "formal_result",
            "numeric_bundle",
            "prefix_spec_root",
            "qualification_manifest",
            "final_bundle",
        )
    }
    options.update(
        {
            "results": options.pop("result"),
            "regression_results": options.pop("regression_result"),
            "controlled_results": options.pop("controlled_result"),
            "canary_results": options.pop("canary_result"),
            "formal_results": options.pop("formal_result"),
        }
    )
    try:
        admission = resolve_action_admission(
            parsed.lab_root,
            action=parsed.action,
            stage=parsed.stage,
            execute=parsed.execute,
            cohort_version=parsed.cohort_version,
            options=options,
        )
    except (OSError, RecursionError, TypeError, ValueError, json.JSONDecodeError) as error:
        parser.exit(1, f"class-study build admission failed: {error}\n")
    fields = ("not-required",) if admission is None else admission.output_fields()
    for field in fields:
        print(field)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
