"""Sealed fitting-result validation and create-only research artifact bundles."""

from __future__ import annotations

import json
import itertools
import math
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

from . import fitting_morphing, fitting_walkie_talkie, fitting_wtfpad
from .experiment import resolved_sample_directory
from .fitting_morphing import fit_traffic_morphing
from .fitting_trace import FittingTrace, load_fitting_trace
from .fitting_walkie_talkie import fit_walkie_talkie
from .fitting_wtfpad import fit_wtf_pad
from .util import (
    LAB_ROOT,
    SOURCE_METADATA_KEYS,
    atomic_json,
    load_json,
    run,
    sha256_bytes,
    sha256_file,
)
from .verification import VerifiedResult, verify_result


BUNDLE_SCHEMA_VERSION = 2
BUNDLE_DIRECTORY = "research-1200"
BUNDLE_FILES = {
    "traffic_morphing": "traffic-morphing.json",
    "wtf_pad": "wtf-pad.json",
    "walkie_talkie": "walkie-talkie.json",
}
PROVENANCE_FILE = "provenance.json"
EXACT_BUNDLE_FILES = frozenset((*BUNDLE_FILES.values(), PROVENANCE_FILE))
RESEARCH_PARAMETER_INPUT_POLICY = "sealed-fitting-result-v1"
RESEARCH_ARTIFACT_STATUS = "fitted-research-artifact"
FITTER_VERSION = "qcsd_lab.fitting 2.1.0"
LEGACY_FITTER_VERSION = "qcsd_lab.fitting 2.0.2"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ALGORITHM_GENERATORS = {
    "traffic_morphing": "qcsd_lab.fitting_morphing 2.0.0",
    "wtf_pad": "qcsd_lab.fitting_wtfpad 2.0.0",
    "walkie_talkie": "qcsd_lab.fitting_walkie_talkie 2.1.0",
}
LEGACY_ALGORITHM_GENERATORS = {
    **ALGORITHM_GENERATORS,
    "walkie_talkie": "qcsd_lab.fitting_walkie_talkie 2.0.1",
}


@dataclass(frozen=True)
class FittingInputs:
    verified: VerifiedResult
    workload_ids: tuple[str, ...]
    as_defined: Mapping[str, tuple[FittingTrace, ...]]
    half_duplex: Mapping[str, tuple[FittingTrace, ...]]


@dataclass(frozen=True)
class VerifiedArtifactBundle:
    root: Path
    provenance: dict[str, Any]
    artifact_hashes: dict[str, str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": True,
            "root": str(self.root),
            "qcsd_profile": "research-1200",
            "provenance_sha256": sha256_file(self.root / PROVENANCE_FILE),
            "artifacts": self.artifact_hashes,
        }


def is_artifact_bundle_candidate(path: Path) -> bool:
    """Recognize complete, partial, and colliding fixed artifact directories."""

    if path.name == BUNDLE_DIRECTORY:
        return True
    if not path.is_dir():
        return False
    names = {entry.name for entry in path.iterdir()}
    return bool(names & EXACT_BUNDLE_FILES)


def fit_result(
    result_root: Path,
    *,
    artifacts_root: Path | None = None,
) -> Path:
    """Fit all three artifacts and atomically create the fixed four-file bundle."""

    _require_scipy_version()
    fitting = validate_fitting_result(result_root)
    experiment = fitting.verified.experiment
    source_result = {
        "campaign": experiment["name"],
        "evidence_sha256": sha256_file(fitting.verified.root / "evidence.sha256"),
        "experiment_sha256": fitting.verified.checksums["experiment.json"],
        "input_digest": experiment["input_digest"],
        "campaign_sha256": experiment["configuration"]["campaign_sha256"],
        "source_fingerprints": dict(experiment["source"]),
    }
    traffic, traffic_diagnostics = fit_traffic_morphing(fitting.as_defined)
    wtf, wtf_diagnostics = fit_wtf_pad(
        tuple(trace for name in fitting.workload_ids for trace in fitting.as_defined[name]),
        fitted_from=_consumed_corpus_digest(fitting.as_defined, fitting.workload_ids),
    )
    walkie, walkie_diagnostics = fit_walkie_talkie(fitting.half_duplex)
    artifacts = {
        "traffic_morphing": traffic,
        "wtf_pad": wtf,
        "walkie_talkie": walkie,
    }
    algorithm_receipts = {
        "traffic_morphing": traffic_diagnostics,
        "wtf_pad": wtf_diagnostics,
        "walkie_talkie": walkie_diagnostics,
    }
    for kind, parameter in artifacts.items():
        parameter["generated_by"] = (
            f"{ALGORITHM_GENERATORS[kind]}; algorithm_receipt_sha256="
            f"{_algorithm_receipt_digest(algorithm_receipts[kind])}"
        )

    parent = (
        artifacts_root.resolve()
        if artifacts_root is not None
        else (LAB_ROOT / "artifacts").resolve()
    )
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / BUNDLE_DIRECTORY
    temporary = Path(tempfile.mkdtemp(prefix=f".{BUNDLE_DIRECTORY}.qcsd-tmp-", dir=parent))
    try:
        for kind, filename in BUNDLE_FILES.items():
            atomic_json(temporary / filename, artifacts[kind])
        artifact_hashes = {
            kind: sha256_file(temporary / filename) for kind, filename in BUNDLE_FILES.items()
        }
        provenance = {
            "schema_version": BUNDLE_SCHEMA_VERSION,
            "artifact_type": "qcsd-research-defense-bundle",
            "status": RESEARCH_ARTIFACT_STATUS,
            "production_ready": True,
            "qcsd_profile": "research-1200",
            "udp_payload_ceiling": 1_200,
            "source_result": source_result,
            "fitting_contract": _fitting_contract(fitting.workload_ids),
            "sample_contributions": _sample_contributions(fitting),
            "algorithms": algorithm_receipts,
            "artifacts": {
                kind: {"path": BUNDLE_FILES[kind], "sha256": artifact_hashes[kind]}
                for kind in sorted(BUNDLE_FILES)
            },
        }
        atomic_json(temporary / PROVENANCE_FILE, provenance)
        verify_artifact_bundle(temporary)

        if destination.exists() or destination.is_symlink():
            existing = verify_artifact_bundle(destination)
            if _bundle_bytes(destination) != _bundle_bytes(temporary):
                raise FileExistsError(
                    f"research artifact bundle already exists with different content: {destination}"
                )
            return existing.root
        temporary.rename(destination)
        return verify_artifact_bundle(destination).root
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def validate_fitting_result(root: Path) -> FittingInputs:
    """Require the exact sealed 6×10×2 undefended research fitting corpus."""

    verified = verify_result(root)
    experiment = verified.experiment
    configuration = experiment["configuration"]
    if (
        experiment["purpose"] != "fitting"
        or experiment["status"] != "complete"
        or experiment["summary"].get("passed") is not True
    ):
        raise ValueError("fitting requires a complete, fully eligible fitting result")
    if configuration.get("profile") != "research-1200":
        raise ValueError("fitting requires the research-1200 QCSD profile")
    _validate_clean_source(experiment.get("source"))
    if configuration.get("request_policies") != ["as-defined", "half-duplex"]:
        raise ValueError("fitting requires request policies in exact as-defined/half-duplex order")

    workload_records = configuration.get("workloads")
    if not isinstance(workload_records, list) or len(workload_records) != 6:
        raise ValueError("fitting requires exactly six workloads")
    workload_ids: list[str] = []
    for record in workload_records:
        if (
            not isinstance(record, Mapping)
            or not isinstance(record.get("id"), str)
            or not record["id"]
            or record.get("visits") != 10
        ):
            raise ValueError("every fitting workload must declare exactly ten visits")
        workload_ids.append(str(record["id"]))
    if len(workload_ids) != len(set(workload_ids)):
        raise ValueError("fitting workload IDs must be unique")
    for record in workload_records:
        manifest_path = verified.root / str(record["manifest"])
        manifest = load_json(manifest_path)
        if not isinstance(manifest, dict):
            raise ValueError("every research fitting workload requires a preparation receipt")
        from .manifest import validate_research_preparation

        validate_research_preparation(manifest, workload_id=str(record["id"]))

    defenses = configuration.get("defenses")
    if defenses != [{"name": "undefended", "kind": "none", "baseline": True}]:
        raise ValueError("fitting requires exactly one undefended baseline")
    samples = experiment["samples"]
    if len(samples) != 120:
        raise ValueError("fitting requires exactly 120 accepted samples")
    expected = {
        (workload, policy, visit)
        for workload in workload_ids
        for policy in ("as-defined", "half-duplex")
        for visit in range(10)
    }
    observed: set[tuple[str, str, int]] = set()
    by_policy: dict[str, dict[str, list[FittingTrace]]] = {
        "as-defined": {workload: [] for workload in workload_ids},
        "half-duplex": {workload: [] for workload in workload_ids},
    }
    for sample in samples:
        identity = (sample["workload_id"], sample["request_policy"], sample["visit"])
        if identity not in expected or identity in observed:
            raise ValueError(
                "fitting samples do not form the exact workload/policy/visit cross product"
            )
        if (
            sample["state"] != "accepted"
            or sample["eligible"] is not True
            or sample["defense"] != "undefended"
            or sample["runtime_kind"] != "none"
            or sample["baseline"] is not True
        ):
            raise ValueError("every fitting sample must be an eligible undefended baseline")
        observed.add(identity)
        sample_root = resolved_sample_directory(verified.root, sample, require_directory=True)
        trace = load_fitting_trace(
            sample_root,
            sample_id=sample["sample_id"],
            workload_id=sample["workload_id"],
            request_policy=sample["request_policy"],
            visit=sample["visit"],
            require_observations=sample["request_policy"] == "half-duplex",
            accepted_artifacts=sample["artifacts"],
        )
        by_policy[sample["request_policy"]][sample["workload_id"]].append(trace)
    if observed != expected:
        raise ValueError("fitting result is missing required workload/policy/visit samples")
    frozen = {
        policy: {
            workload: tuple(sorted(values, key=lambda trace: (trace.visit, trace.sample_id)))
            for workload, values in workloads.items()
        }
        for policy, workloads in by_policy.items()
    }
    return FittingInputs(
        verified=verified,
        workload_ids=tuple(workload_ids),
        as_defined=frozen["as-defined"],
        half_duplex=frozen["half-duplex"],
    )


def verify_artifact_bundle(root: Path) -> VerifiedArtifactBundle:
    """Verify the exact four-file bundle, common receipt, and runtime schemas."""

    if root.is_symlink():
        raise ValueError(f"artifact bundle must not be a symbolic link: {root}")
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"artifact bundle is not a regular directory: {root}")
    entries = {path.name for path in root.iterdir()}
    if entries != EXACT_BUNDLE_FILES:
        missing = sorted(EXACT_BUNDLE_FILES - entries)
        extra = sorted(entries - EXACT_BUNDLE_FILES)
        raise ValueError(
            "artifact bundle file set mismatch"
            + (f"; missing {', '.join(missing)}" if missing else "")
            + (f"; extra {', '.join(extra)}" if extra else "")
        )
    if any(path.is_symlink() or not path.is_file() for path in root.iterdir()):
        raise ValueError("artifact bundle may contain only regular files")
    provenance = load_json(root / PROVENANCE_FILE)
    contract_version = _validate_provenance(provenance)
    artifact_hashes: dict[str, str] = {}
    for kind, filename in BUNDLE_FILES.items():
        record = provenance["artifacts"][kind]
        if record != {"path": filename, "sha256": sha256_file(root / filename)}:
            raise ValueError(f"artifact provenance hash mismatch: {filename}")
        artifact_hashes[kind] = record["sha256"]
        parameter = load_json(root / filename)
        _validate_runtime_parameter(parameter, kind, contract_version=contract_version)
        assert isinstance(parameter, Mapping)
        _validate_algorithm_artifact_binding(
            provenance, kind, parameter, contract_version=contract_version
        )
    expected_workloads = {record["workload_id"] for record in provenance["sample_contributions"]}
    _validate_artifact_coverage(root, expected_workloads)
    if contract_version == 3:
        _run_rust_parameter_validator(
            "bundle", root, tuple(provenance["fitting_contract"]["workload_order"])
        )
    return VerifiedArtifactBundle(root, dict(provenance), artifact_hashes)


def research_parameter_record(
    parameter_path: Path,
    provenance_path: Path,
    *,
    expected_kind: str,
    expected_workloads: Sequence[str] | Mapping[str, object] | None,
    parameter_name: str | None = None,
    allow_historical: bool = False,
) -> tuple[str, str, str]:
    """Validate one runtime file against a shared fitted-bundle receipt."""

    if parameter_path.is_symlink() or provenance_path.is_symlink():
        raise ValueError("research parameter files must not be symbolic links")
    if not parameter_path.is_file() or not provenance_path.is_file():
        raise ValueError("research parameter and provenance must be regular files")
    parameter_path = parameter_path.resolve()
    provenance_path = provenance_path.resolve()
    provenance = load_json(provenance_path)
    contract_version = _validate_provenance(provenance)
    if contract_version == 2 and not allow_historical:
        raise ValueError(
            "legacy research parameter bundles are accepted only as frozen historical evidence"
        )
    if expected_kind not in BUNDLE_FILES:
        raise ValueError(f"unsupported research parameter kind: {expected_kind}")
    record = provenance["artifacts"][expected_kind]
    expected_name = parameter_name or parameter_path.name
    if record["path"] != expected_name or record["sha256"] != sha256_file(parameter_path):
        raise ValueError("research parameter file does not match its shared provenance receipt")
    parameter = load_json(parameter_path)
    _validate_runtime_parameter(parameter, expected_kind, contract_version=contract_version)
    assert isinstance(parameter, Mapping)
    _validate_algorithm_artifact_binding(
        provenance, expected_kind, parameter, contract_version=contract_version
    )
    sealed_order = tuple(provenance["fitting_contract"]["workload_order"])
    sealed_workloads = set(sealed_order)
    expected = set(expected_workloads or ())
    unknown = sorted(expected - sealed_workloads)
    if unknown:
        raise ValueError(
            "research parameter campaign workloads are absent from the sealed fitting "
            f"cohort: {', '.join(unknown)}"
        )
    if expected_kind != "wtf_pad":
        _validate_exact_parameter_coverage(parameter, expected_kind, sealed_workloads)
    if contract_version == 3:
        _run_rust_parameter_validator(expected_kind, parameter_path, sealed_order)
    return record["sha256"], sha256_file(provenance_path), RESEARCH_PARAMETER_INPUT_POLICY


def _sample_contributions(fitting: FittingInputs) -> list[dict[str, object]]:
    result = []
    for workload in fitting.workload_ids:
        policies: dict[str, object] = {}
        for policy, mapping in (
            ("as-defined", fitting.as_defined),
            ("half-duplex", fitting.half_duplex),
        ):
            policies[policy] = [
                {
                    "consumed_evidence": dict(trace.consumed_evidence),
                    "sample_id": trace.sample_id,
                    "visit": trace.visit,
                    "training_input_sha256": trace.training_input_sha256,
                }
                for trace in mapping[workload]
            ]
        result.append({"workload_id": workload, "policies": policies})
    return result


def _consumed_corpus_digest(
    traces: Mapping[str, Sequence[FittingTrace]], workload_order: Sequence[str]
) -> str:
    identity = [
        {
            "workload_id": workload,
            "samples": [trace.training_input_sha256 for trace in traces[workload]],
        }
        for workload in workload_order
    ]
    return sha256_bytes(
        b"qcsd-consumed-fitting-corpus-v1\0"
        + json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )


def _training_input_digest(
    *,
    sample_id: str,
    workload_id: str,
    request_policy: str,
    visit: int,
    consumed_evidence: Mapping[str, object],
) -> str:
    identity = {
        "consumed_evidence": dict(consumed_evidence),
        "request_policy": request_policy,
        "sample_id": sample_id,
        "visit": visit,
        "workload_id": workload_id,
    }
    return sha256_bytes(
        b"qcsd-fitting-trace-v1\0"
        + json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )


def _validate_provenance(value: object) -> int:
    expected = {
        "schema_version",
        "artifact_type",
        "status",
        "production_ready",
        "qcsd_profile",
        "udp_payload_ceiling",
        "source_result",
        "fitting_contract",
        "sample_contributions",
        "algorithms",
        "artifacts",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValueError("research artifact provenance has an invalid schema")
    if (
        value["schema_version"] != BUNDLE_SCHEMA_VERSION
        or value["artifact_type"] != "qcsd-research-defense-bundle"
        or value["status"] != RESEARCH_ARTIFACT_STATUS
        or value["production_ready"] is not True
        or value["qcsd_profile"] != "research-1200"
        or value["udp_payload_ceiling"] != 1_200
    ):
        raise ValueError("research artifact provenance has an invalid research binding")
    source = value["source_result"]
    if not isinstance(source, Mapping) or set(source) != {
        "campaign",
        "campaign_sha256",
        "evidence_sha256",
        "experiment_sha256",
        "input_digest",
        "source_fingerprints",
    }:
        raise ValueError("research artifact source-result receipt is invalid")
    for key in ("campaign_sha256", "evidence_sha256", "experiment_sha256", "input_digest"):
        if not _digest(source.get(key)):
            raise ValueError(f"research artifact source-result {key} is invalid")
    if not isinstance(source.get("campaign"), str) or not source["campaign"]:
        raise ValueError("research artifact source campaign is invalid")
    _validate_clean_source(source.get("source_fingerprints"))
    if _contains_absolute_path(source["source_fingerprints"]):
        raise ValueError("research artifact provenance must not contain absolute paths")
    contract = value["fitting_contract"]
    if not isinstance(contract, Mapping):
        raise ValueError("research fitting contract receipt is invalid")
    contract_version = contract.get("contract_version")
    if contract_version == 2:
        contract_keys = {
            "contract_version",
            "fitter_version",
            "parameter_schema_version",
            "profile",
            "request_policies",
            "visits_per_policy",
            "workload_order",
            "constants",
        }
        expected_fitter = LEGACY_FITTER_VERSION
        expected_schema: object = 2
        observed_schema = contract.get("parameter_schema_version")
    elif contract_version == 3:
        contract_keys = {
            "contract_version",
            "fitter_version",
            "parameter_schema_versions",
            "profile",
            "request_policies",
            "visits_per_policy",
            "workload_order",
            "constants",
        }
        expected_fitter = FITTER_VERSION
        expected_schema = {"traffic_morphing": 2, "walkie_talkie": 3, "wtf_pad": 2}
        observed_schema = contract.get("parameter_schema_versions")
    else:
        raise ValueError("research fitting contract receipt is invalid")
    if set(contract) != contract_keys:
        raise ValueError("research fitting contract receipt is invalid")
    if (
        type(contract_version) is not int
        or contract["fitter_version"] != expected_fitter
        or observed_schema != expected_schema
        or contract["profile"] != "research-1200"
        or contract["request_policies"] != ["as-defined", "half-duplex"]
        or contract["visits_per_policy"] != 10
        or not isinstance(contract["workload_order"], list)
        or len(contract["workload_order"]) != 6
        or len(set(contract["workload_order"])) != 6
        or not isinstance(contract["constants"], Mapping)
    ):
        raise ValueError("research fitting contract values are invalid")
    expected_contract = (
        _legacy_fitting_contract(contract["workload_order"])
        if contract_version == 2
        else _fitting_contract(contract["workload_order"])
    )
    if dict(contract) != expected_contract:
        raise ValueError("research fitting contract constants are invalid")
    _require_scipy_version()
    contributions = value["sample_contributions"]
    if not isinstance(contributions, list) or len(contributions) != 6:
        raise ValueError("research provenance requires six workload contributions")
    workload_ids: list[str] = []
    sample_ids: set[str] = set()
    training_inputs: set[str] = set()
    sample_identities: set[tuple[str, str, int]] = set()
    for contribution in contributions:
        if not isinstance(contribution, Mapping) or set(contribution) != {
            "workload_id",
            "policies",
        }:
            raise ValueError("research workload contribution is malformed")
        workload = contribution["workload_id"]
        policies = contribution["policies"]
        if not isinstance(workload, str) or not workload or not isinstance(policies, Mapping):
            raise ValueError("research workload contribution identity is invalid")
        workload_ids.append(workload)
        if set(policies) != {"as-defined", "half-duplex"}:
            raise ValueError("research workload contribution policies are invalid")
        for policy, samples in policies.items():
            if not isinstance(samples, list) or len(samples) != 10:
                raise ValueError("research workload policy requires ten contributions")
            visits = []
            for sample in samples:
                if not isinstance(sample, Mapping) or set(sample) != {
                    "consumed_evidence",
                    "sample_id",
                    "visit",
                    "training_input_sha256",
                }:
                    raise ValueError("research sample contribution is malformed")
                if not isinstance(sample["sample_id"], str) or not sample["sample_id"]:
                    raise ValueError("research sample contribution ID is invalid")
                if not _digest(sample["training_input_sha256"]):
                    raise ValueError("research sample contribution digest is invalid")
                if type(sample["visit"]) is not int:
                    raise ValueError("research sample contribution visit is invalid")
                consumed = sample["consumed_evidence"]
                if (
                    not isinstance(consumed, Mapping)
                    or set(consumed)
                    != {
                        "neqo/events.csv",
                        "neqo/run.json",
                    }
                    or any(not _digest(digest) for digest in consumed.values())
                ):
                    raise ValueError("research sample consumed-evidence binding is invalid")
                expected_training_input = _training_input_digest(
                    sample_id=sample["sample_id"],
                    workload_id=workload,
                    request_policy=str(policy),
                    visit=sample["visit"],
                    consumed_evidence=consumed,
                )
                if sample["training_input_sha256"] != expected_training_input:
                    raise ValueError(
                        "research sample training-input digest does not match its identity"
                    )
                visits.append(sample["visit"])
                sample_id = sample["sample_id"]
                training_input = sample["training_input_sha256"]
                visit = sample["visit"]
                identity = (workload, str(policy), visit)
                if sample_id in sample_ids or identity in sample_identities:
                    raise ValueError("research sample contributions must be globally unique")
                if training_input in training_inputs:
                    raise ValueError("research training-input bindings must be globally unique")
                sample_ids.add(sample_id)
                training_inputs.add(training_input)
                sample_identities.add(identity)
            if visits != list(range(10)):
                raise ValueError(
                    "research sample contributions must preserve visit order 0 through 9"
                )
    if workload_ids != contract["workload_order"]:
        raise ValueError("research workload contributions do not preserve frozen campaign order")
    if len(sample_ids) != 120 or len(sample_identities) != 120:
        raise ValueError("research provenance requires 120 distinct sample contributions")
    if not isinstance(value["algorithms"], Mapping) or set(value["algorithms"]) != set(
        BUNDLE_FILES
    ):
        raise ValueError("research artifact algorithm receipt is invalid")
    _validate_algorithm_receipts(
        value["algorithms"],
        contract["workload_order"],
        contract_version=contract_version,
    )
    artifacts = value["artifacts"]
    if not isinstance(artifacts, Mapping) or set(artifacts) != set(BUNDLE_FILES):
        raise ValueError("research artifact hash receipt is invalid")
    for kind, filename in BUNDLE_FILES.items():
        record = artifacts[kind]
        if (
            not isinstance(record, Mapping)
            or set(record) != {"path", "sha256"}
            or record["path"] != filename
            or not _digest(record["sha256"])
        ):
            raise ValueError(f"research artifact receipt is invalid for {kind}")
    return contract_version


def _validate_algorithm_receipts(
    algorithms: Mapping[str, object],
    workload_order: Sequence[str],
    *,
    contract_version: int,
) -> None:
    _validate_traffic_morphing_receipt(algorithms["traffic_morphing"], workload_order)
    _validate_wtf_pad_receipt(algorithms["wtf_pad"])
    _validate_walkie_talkie_receipt(
        algorithms["walkie_talkie"],
        workload_order,
        contract_version=contract_version,
    )


def _validate_traffic_morphing_receipt(value: object, workload_order: Sequence[str]) -> None:
    receipt = _exact_mapping(
        value,
        {
            "algorithm",
            "candidate_costs",
            "corpus_bucket_counts",
            "selected_mapping",
        },
        "Traffic Morphing algorithm receipt",
    )
    if receipt["algorithm"] != "all-directed-padding-only-lp-then-minimum-cost-derangement":
        raise ValueError("Traffic Morphing algorithm receipt is invalid")
    expected_edges = [
        (source, target)
        for source in workload_order
        for target in workload_order
        if source != target
    ]
    corpus = receipt["corpus_bucket_counts"]
    if not isinstance(corpus, list) or len(corpus) != len(workload_order):
        raise ValueError("Traffic Morphing corpus bucket counts are invalid")
    for workload, value in zip(workload_order, corpus, strict=True):
        record = _exact_mapping(
            value,
            {"workload_id", "outgoing", "incoming"},
            "Traffic Morphing corpus bucket counts",
        )
        if record["workload_id"] != workload:
            raise ValueError("Traffic Morphing corpus workload order is invalid")
        for direction in ("outgoing", "incoming"):
            counts = record[direction]
            if (
                not isinstance(counts, list)
                or len(counts) != len(fitting_morphing.DEFAULT_BUCKETS)
                or any(type(count) is not int or count < 0 for count in counts)
                or sum(counts) <= 0
            ):
                raise ValueError("Traffic Morphing corpus bucket counts are invalid")
    candidates = _cost_records(
        receipt["candidate_costs"],
        identity_fields=("source", "target"),
        cost_fields=("l1_cost", "estimated_added_bytes"),
        label="Traffic Morphing candidate costs",
    )
    if [(item["source"], item["target"]) for item in candidates] != expected_edges:
        raise ValueError("Traffic Morphing candidate costs do not cover every directed edge")
    selected = _cost_records(
        receipt["selected_mapping"],
        identity_fields=("source", "target"),
        cost_fields=("l1_cost", "estimated_added_bytes"),
        label="Traffic Morphing selected mapping",
    )
    if [item["source"] for item in selected] != list(workload_order):
        raise ValueError("Traffic Morphing selected sources do not preserve workload order")
    targets = [item["target"] for item in selected]
    if sorted(targets) != sorted(workload_order) or any(
        item["source"] == item["target"] for item in selected
    ):
        raise ValueError("Traffic Morphing selected mapping is not a derangement")
    candidate_by_edge = {(item["source"], item["target"]): item for item in candidates}
    if any(item != candidate_by_edge.get((item["source"], item["target"])) for item in selected):
        raise ValueError("Traffic Morphing selected costs disagree with candidate costs")
    optimum: tuple[tuple[float, float, tuple[str, ...]], tuple[str, ...]] | None = None
    for target_vector in itertools.permutations(workload_order):
        if any(
            source == target for source, target in zip(workload_order, target_vector, strict=True)
        ):
            continue
        edges = [
            candidate_by_edge[(source, target)]
            for source, target in zip(workload_order, target_vector, strict=True)
        ]
        key = (
            math.fsum(float(edge["l1_cost"]) for edge in edges),
            math.fsum(float(edge["estimated_added_bytes"]) for edge in edges),
            tuple(target_vector),
        )
        if optimum is None or key < optimum[0]:
            optimum = (key, tuple(target_vector))
    if optimum is None or tuple(targets) != optimum[1]:
        raise ValueError("Traffic Morphing selected mapping is not the recorded optimum")


def _validate_wtf_pad_receipt(value: object) -> None:
    receipt = _exact_mapping(
        value,
        {
            "algorithm",
            "global_bandwidth_threshold_bytes_per_second",
            "populations",
            "training_samples",
        },
        "WTF-PAD algorithm receipt",
    )
    if receipt["algorithm"] != "corpus-mean-bandwidth-mle-ks-histograms" or not _positive_number(
        receipt["global_bandwidth_threshold_bytes_per_second"]
    ):
        raise ValueError("WTF-PAD algorithm receipt is invalid")
    populations = _exact_mapping(
        receipt["populations"], {"outgoing", "incoming"}, "WTF-PAD populations"
    )
    training_samples = receipt["training_samples"]
    if not isinstance(training_samples, list) or len(training_samples) != 60:
        raise ValueError("WTF-PAD receipt requires exactly 60 training samples")
    observed_hashes: set[str] = set()
    aggregate: dict[str, dict[str, list[int]]] = {
        direction: {"intra": [], "between": [], "lengths": []}
        for direction in ("outgoing", "incoming")
    }
    total_bytes = 0
    total_duration_ns = 0
    for sample in training_samples:
        record = _exact_mapping(
            sample,
            {
                "training_input_sha256",
                "total_bytes",
                "active_duration_ns",
                "directions",
            },
            "WTF-PAD training sample",
        )
        training_hash = record["training_input_sha256"]
        if not _digest(training_hash) or training_hash in observed_hashes:
            raise ValueError("WTF-PAD training sample hashes are invalid")
        observed_hashes.add(training_hash)
        if (
            type(record["total_bytes"]) is not int
            or record["total_bytes"] <= 0
            or type(record["active_duration_ns"]) is not int
            or record["active_duration_ns"] <= 0
        ):
            raise ValueError("WTF-PAD training bandwidth sample is invalid")
        total_bytes += record["total_bytes"]
        total_duration_ns += record["active_duration_ns"]
        directions = _exact_mapping(
            record["directions"], {"outgoing", "incoming"}, "WTF-PAD directions"
        )
        for direction in ("outgoing", "incoming"):
            values = _exact_mapping(
                directions[direction],
                {
                    "intra_burst_delays_us",
                    "between_burst_delays_us",
                    "burst_lengths_packets",
                },
                f"WTF-PAD {direction} training population",
            )
            intra = _positive_integer_list(values["intra_burst_delays_us"])
            between = _positive_integer_list(values["between_burst_delays_us"])
            lengths = _positive_integer_list(values["burst_lengths_packets"])
            if len(lengths) != len(between) + 1 or sum(lengths) != len(intra) + len(between) + 1:
                raise ValueError(f"WTF-PAD {direction} per-sample burst population is inconsistent")
            aggregate[direction]["intra"].extend(intra)
            aggregate[direction]["between"].extend(between)
            aggregate[direction]["lengths"].extend(lengths)
    expected_threshold = fitting_wtfpad._float(total_bytes * 1_000_000_000.0 / total_duration_ns)
    if receipt["global_bandwidth_threshold_bytes_per_second"] != expected_threshold:
        raise ValueError("WTF-PAD global bandwidth threshold is inconsistent")
    for direction in ("outgoing", "incoming"):
        population = _exact_mapping(
            populations[direction],
            {"between_burst_delays", "intra_burst_delays", "bursts"},
            f"WTF-PAD {direction} population",
        )
        if (
            any(
                type(population[field]) is not int or population[field] <= 0
                for field in ("between_burst_delays", "intra_burst_delays", "bursts")
            )
            or population["between_burst_delays"] != len(aggregate[direction]["between"])
            or population["intra_burst_delays"] != len(aggregate[direction]["intra"])
            or population["bursts"] != len(aggregate[direction]["lengths"])
            or population["bursts"] != population["between_burst_delays"] + 60
        ):
            raise ValueError(f"WTF-PAD {direction} population receipt is invalid")


def _validate_walkie_talkie_receipt(
    value: object,
    workload_order: Sequence[str],
    *,
    contract_version: int = 3,
) -> None:
    if contract_version == 2:
        _validate_legacy_walkie_talkie_receipt(value, workload_order)
        return
    if contract_version != 3:
        raise ValueError("unsupported research fitting contract version")
    _validate_current_walkie_talkie_receipt(value, workload_order)


def _validate_legacy_walkie_talkie_receipt(value: object, workload_order: Sequence[str]) -> None:
    receipt = _exact_mapping(
        value,
        {"algorithm", "candidate_pair_costs", "selected_pairs", "training_visits"},
        "Walkie-Talkie algorithm receipt",
    )
    if receipt["algorithm"] != "full-cohort-minimum-weight-perfect-matching":
        raise ValueError("Walkie-Talkie algorithm receipt is invalid")
    lexical = tuple(sorted(workload_order))
    expected_pairs = [
        (left, right) for index, left in enumerate(lexical) for right in lexical[index + 1 :]
    ]
    training_visits = receipt["training_visits"]
    if not isinstance(training_visits, list) or len(training_visits) != len(workload_order):
        raise ValueError("Walkie-Talkie training visits are invalid")
    observed_training_hashes: set[str] = set()
    for workload, workload_value in zip(workload_order, training_visits, strict=True):
        record = _exact_mapping(
            workload_value,
            {"workload_id", "visits"},
            "Walkie-Talkie workload training visits",
        )
        if record["workload_id"] != workload or not isinstance(record["visits"], list):
            raise ValueError("Walkie-Talkie training workload order is invalid")
        if len(record["visits"]) != 10:
            raise ValueError("Walkie-Talkie requires ten training visits per workload")
        for visit, visit_value in enumerate(record["visits"]):
            visit_record = _exact_mapping(
                visit_value,
                {"visit", "training_input_sha256", "bursts", "batch_ends"},
                "Walkie-Talkie training visit",
            )
            training_hash = visit_record["training_input_sha256"]
            if (
                visit_record["visit"] != visit
                or not _digest(training_hash)
                or training_hash in observed_training_hashes
            ):
                raise ValueError("Walkie-Talkie training visit identity is invalid")
            observed_training_hashes.add(training_hash)
            _parse_burst_sequence(
                visit_record["bursts"],
                visit_record["batch_ends"],
                "Walkie-Talkie training visit",
            )
    candidates = _cost_records(
        receipt["candidate_pair_costs"],
        identity_fields=("left", "right"),
        cost_fields=("matching_cost_packets",),
        label="Walkie-Talkie candidate pair costs",
        integer_costs=True,
    )
    if [(item["left"], item["right"]) for item in candidates] != expected_pairs:
        raise ValueError("Walkie-Talkie candidate costs do not cover every lexical pair")
    selected = _cost_records(
        receipt["selected_pairs"],
        identity_fields=("real", "decoy"),
        cost_fields=("matching_cost_packets",),
        label="Walkie-Talkie selected pairs",
        integer_costs=True,
    )
    selected_pairs = [(item["real"], item["decoy"]) for item in selected]
    if (
        len(selected_pairs) != len(lexical) // 2
        or selected_pairs != sorted(selected_pairs)
        or any(left >= right for left, right in selected_pairs)
        or sorted(identity for pair in selected_pairs for identity in pair) != list(lexical)
    ):
        raise ValueError("Walkie-Talkie selected pairs are not a lexical perfect matching")
    candidate_by_pair = {
        (item["left"], item["right"]): item["matching_cost_packets"] for item in candidates
    }
    if any(
        item["matching_cost_packets"] != candidate_by_pair.get((item["real"], item["decoy"]))
        for item in selected
    ):
        raise ValueError("Walkie-Talkie selected costs disagree with candidate costs")

    def choose(remaining: tuple[str, ...]) -> tuple[int, tuple[tuple[str, str], ...]]:
        if not remaining:
            return 0, ()
        left = remaining[0]
        optimum: tuple[int, tuple[tuple[str, str], ...]] | None = None
        for index in range(1, len(remaining)):
            right = remaining[index]
            rest_cost, rest_pairs = choose(remaining[1:index] + remaining[index + 1 :])
            candidate = (
                candidate_by_pair[(left, right)] + rest_cost,
                tuple(sorted(((left, right), *rest_pairs))),
            )
            if optimum is None or candidate < optimum:
                optimum = candidate
        assert optimum is not None
        return optimum

    _cost, optimum_pairs = choose(lexical)
    if tuple(selected_pairs) != optimum_pairs:
        raise ValueError("Walkie-Talkie selected pairs are not the recorded optimum")


def _validate_current_walkie_talkie_receipt(value: object, workload_order: Sequence[str]) -> None:
    receipt = _exact_mapping(
        value,
        {
            "algorithm",
            "pairing_objective",
            "receiver_continuation",
            "candidate_pair_costs",
            "selected_pairs",
            "training_visits",
        },
        "Walkie-Talkie algorithm receipt",
    )
    if (
        receipt["algorithm"] != "full-cohort-minimum-weight-perfect-matching"
        or receipt["pairing_objective"] != "minimum-base-symmetric-mold-padding-cost"
    ):
        raise ValueError("Walkie-Talkie algorithm receipt is invalid")
    if receipt["receiver_continuation"] != fitting_walkie_talkie.receiver_continuation_contract():
        raise ValueError("Walkie-Talkie receiver-continuation receipt is invalid")
    lexical = tuple(sorted(workload_order))
    expected_pairs = [
        (left, right) for index, left in enumerate(lexical) for right in lexical[index + 1 :]
    ]
    training_visits = receipt["training_visits"]
    if not isinstance(training_visits, list) or len(training_visits) != len(workload_order):
        raise ValueError("Walkie-Talkie training visits are invalid")
    observed_training_hashes: set[str] = set()
    envelopes: dict[str, fitting_walkie_talkie.ProfileEnvelope] = {}
    for workload, value in zip(workload_order, training_visits, strict=True):
        record = _exact_mapping(
            value,
            {"workload_id", "visits"},
            "Walkie-Talkie workload training visits",
        )
        if record["workload_id"] != workload or not isinstance(record["visits"], list):
            raise ValueError("Walkie-Talkie training workload order is invalid")
        if len(record["visits"]) != 10:
            raise ValueError("Walkie-Talkie requires ten training visits per workload")
        sequences: list[tuple[fitting_walkie_talkie.BurstPair, ...]] = []
        for visit, visit_value in enumerate(record["visits"]):
            visit_record = _exact_mapping(
                visit_value,
                {"visit", "training_input_sha256", "bursts", "batch_ends"},
                "Walkie-Talkie training visit",
            )
            training_hash = visit_record["training_input_sha256"]
            if (
                visit_record["visit"] != visit
                or not _digest(training_hash)
                or training_hash in observed_training_hashes
            ):
                raise ValueError("Walkie-Talkie training visit identity is invalid")
            observed_training_hashes.add(training_hash)
            sequences.append(
                _parse_burst_sequence(
                    visit_record["bursts"],
                    visit_record["batch_ends"],
                    "Walkie-Talkie training visit",
                )
            )
        envelopes[workload] = fitting_walkie_talkie.componentwise_envelope(sequences)
    candidates = _cost_records(
        receipt["candidate_pair_costs"],
        identity_fields=("left", "right"),
        cost_fields=("base_matching_cost_packets", "matching_cost_packets"),
        label="Walkie-Talkie candidate pair costs",
        integer_costs=True,
    )
    if [(item["left"], item["right"]) for item in candidates] != expected_pairs:
        raise ValueError("Walkie-Talkie candidate costs do not cover every lexical pair")
    expected_candidates = [
        {
            "left": left,
            "right": right,
            "base_matching_cost_packets": fitting_walkie_talkie.symmetric_mold_padding_cost(
                envelopes[left].bursts, envelopes[right].bursts
            ),
            "matching_cost_packets": fitting_walkie_talkie.mold_padding_cost(
                envelopes[left].bursts, envelopes[right].bursts
            ),
        }
        for left, right in expected_pairs
    ]
    if candidates != expected_candidates:
        raise ValueError("Walkie-Talkie candidate costs disagree with training envelopes")
    selected = _cost_records(
        receipt["selected_pairs"],
        identity_fields=("real", "decoy"),
        cost_fields=("base_matching_cost_packets", "matching_cost_packets"),
        label="Walkie-Talkie selected pairs",
        integer_costs=True,
    )
    selected_pairs = [(item["real"], item["decoy"]) for item in selected]
    if (
        len(selected_pairs) != len(lexical) // 2
        or selected_pairs != sorted(selected_pairs)
        or any(left >= right for left, right in selected_pairs)
        or sorted(identity for pair in selected_pairs for identity in pair) != list(lexical)
    ):
        raise ValueError("Walkie-Talkie selected pairs are not a lexical perfect matching")
    candidate_by_pair = {(item["left"], item["right"]): item for item in candidates}
    if any(
        candidate_by_pair.get((item["real"], item["decoy"])) is None
        or any(
            item[field] != candidate_by_pair[(item["real"], item["decoy"])][field]
            for field in ("base_matching_cost_packets", "matching_cost_packets")
        )
        for item in selected
    ):
        raise ValueError("Walkie-Talkie selected costs disagree with candidate costs")

    def choose(remaining: tuple[str, ...]) -> tuple[int, tuple[tuple[str, str], ...]]:
        if not remaining:
            return 0, ()
        left = remaining[0]
        optimum: tuple[int, tuple[tuple[str, str], ...]] | None = None
        for index in range(1, len(remaining)):
            right = remaining[index]
            rest_cost, rest_pairs = choose(remaining[1:index] + remaining[index + 1 :])
            candidate = (
                candidate_by_pair[(left, right)]["base_matching_cost_packets"] + rest_cost,
                tuple(sorted(((left, right), *rest_pairs))),
            )
            if optimum is None or candidate < optimum:
                optimum = candidate
        assert optimum is not None
        return optimum

    _cost, optimum_pairs = choose(lexical)
    if tuple(selected_pairs) != optimum_pairs:
        raise ValueError("Walkie-Talkie selected pairs are not the recorded optimum")


def _validate_algorithm_artifact_binding(
    provenance: Mapping[str, object],
    kind: str,
    parameter: Mapping[str, Any],
    *,
    contract_version: int,
) -> None:
    algorithms = provenance["algorithms"]
    assert isinstance(algorithms, Mapping)
    receipt = algorithms[kind]
    generators = LEGACY_ALGORITHM_GENERATORS if contract_version == 2 else ALGORITHM_GENERATORS
    expected_generator = (
        f"{generators[kind]}; algorithm_receipt_sha256={_algorithm_receipt_digest(receipt)}"
    )
    if parameter.get("generated_by") != expected_generator:
        raise ValueError(f"{kind} artifact does not bind its algorithm receipt")
    if kind == "traffic_morphing":
        _validate_traffic_morphing_artifact(provenance, parameter)
        return
    if kind == "wtf_pad":
        _validate_wtf_pad_artifact(provenance, parameter)
        return
    if kind == "walkie_talkie":
        _validate_walkie_talkie_artifact(provenance, parameter, contract_version=contract_version)
        return
    raise ValueError(f"unsupported research parameter kind: {kind}")


def _validate_traffic_morphing_artifact(
    provenance: Mapping[str, object], parameter: Mapping[str, Any]
) -> None:
    _require_exact_keys(
        parameter,
        {
            "adaptation",
            "buckets",
            "generated_by",
            "paper_equivalent",
            "profiles",
            "schema_version",
            "udp_payload_ceiling",
        },
        "Traffic Morphing artifact",
    )
    constants = provenance["fitting_contract"]["constants"]["traffic_morphing"]
    algorithm = provenance["algorithms"]["traffic_morphing"]
    assert isinstance(constants, Mapping) and isinstance(algorithm, Mapping)
    buckets = constants["buckets"]
    if (
        parameter["adaptation"] != "qcsd-client-only"
        or parameter["paper_equivalent"] is not False
        or parameter["schema_version"] != 2
        or parameter["udp_payload_ceiling"] != 1_200
        or parameter["buckets"] != buckets
        or not isinstance(buckets, list)
    ):
        raise ValueError("Traffic Morphing artifact constants are invalid")
    corpus: dict[str, dict[str, tuple[list[float], int, list[int]]]] = {}
    for record in algorithm["corpus_bucket_counts"]:
        workload = record["workload_id"]
        corpus[workload] = {}
        for direction in ("outgoing", "incoming"):
            counts = record[direction]
            total = sum(counts)
            distribution = [fitting_morphing._canonical_float(count / total) for count in counts]
            corpus[workload][direction] = (distribution, total, counts)
    recomputed_edges: dict[tuple[str, str], fitting_morphing.DirectedFit] = {}
    workload_order = tuple(corpus)
    for source in workload_order:
        for target in workload_order:
            if source == target:
                continue
            outgoing = fitting_morphing.morphing_matrix(
                np.asarray(corpus[source]["outgoing"][2], dtype=float)
                / corpus[source]["outgoing"][1],
                np.asarray(corpus[target]["outgoing"][2], dtype=float)
                / corpus[target]["outgoing"][1],
                buckets,
            )
            incoming = fitting_morphing.morphing_matrix(
                np.asarray(corpus[source]["incoming"][2], dtype=float)
                / corpus[source]["incoming"][1],
                np.asarray(corpus[target]["incoming"][2], dtype=float)
                / corpus[target]["incoming"][1],
                buckets,
            )
            recomputed_edges[(source, target)] = fitting_morphing.DirectedFit(
                source=source,
                target=target,
                outgoing=outgoing,
                incoming=incoming,
                source_outgoing_packets=corpus[source]["outgoing"][1],
                source_incoming_packets=corpus[source]["incoming"][1],
            )
    expected_candidates = [
        {
            "source": source,
            "target": target,
            "l1_cost": recomputed_edges[(source, target)].fidelity_cost,
            "estimated_added_bytes": recomputed_edges[(source, target)].byte_cost,
        }
        for source in workload_order
        for target in workload_order
        if source != target
    ]
    recomputed_selection = fitting_morphing.minimum_cost_derangement(
        workload_order, recomputed_edges
    )
    expected_selected = [
        {
            "source": source,
            "target": target,
            "l1_cost": recomputed_edges[(source, target)].fidelity_cost,
            "estimated_added_bytes": recomputed_edges[(source, target)].byte_cost,
        }
        for source, target in recomputed_selection
    ]
    if (
        algorithm["candidate_costs"] != expected_candidates
        or algorithm["selected_mapping"] != expected_selected
    ):
        raise ValueError("Traffic Morphing candidate costs or optimum are inconsistent")
    profiles = parameter["profiles"]
    selected = algorithm["selected_mapping"]
    if not isinstance(profiles, list) or len(profiles) != len(selected):
        raise ValueError("Traffic Morphing profile count is invalid")
    for profile, selection in zip(profiles, selected, strict=True):
        profile_record = _exact_mapping(
            profile,
            {"incoming", "outgoing", "source", "target"},
            "Traffic Morphing profile",
        )
        source = profile_record["source"]
        target = profile_record["target"]
        if (source, target) != (selection["source"], selection["target"]):
            raise ValueError("Traffic Morphing profile selection is inconsistent")
        direction_values: dict[str, tuple[float, float]] = {}
        for direction in ("outgoing", "incoming"):
            source_distribution = corpus[source][direction][0]
            target_distribution = corpus[target][direction][0]
            direction_values[direction] = _validate_morphing_direction_derivations(
                profile_record[direction],
                buckets,
                source_distribution,
                target_distribution,
                f"Traffic Morphing {source}->{target} {direction}",
            )
        expected_l1 = direction_values["outgoing"][0] + direction_values["incoming"][0]
        expected_bytes = (
            corpus[source]["outgoing"][1] * direction_values["outgoing"][1]
            + corpus[source]["incoming"][1] * direction_values["incoming"][1]
        )
        if (
            selection["l1_cost"] != expected_l1
            or selection["estimated_added_bytes"] != expected_bytes
        ):
            raise ValueError("Traffic Morphing selected aggregate costs are inconsistent")
    expected_profiles = [
        fitting_morphing._profile_json(recomputed_edges[(source, target)])
        for source, target in recomputed_selection
    ]
    if profiles != expected_profiles:
        raise ValueError("Traffic Morphing profiles do not match canonical LP solutions")


def _validate_morphing_direction_derivations(
    value: object,
    buckets: Sequence[int],
    expected_source: list[float],
    expected_target: list[float],
    label: str,
) -> tuple[float, float]:
    direction = _exact_mapping(
        value,
        {
            "expected_added_bytes",
            "l1_distance",
            "realized_distribution",
            "rows",
            "source_distribution",
            "target_distribution",
        },
        label,
    )
    width = len(buckets)
    source = _finite_probability_vector(direction["source_distribution"], width, label)
    target = _finite_probability_vector(direction["target_distribution"], width, label)
    if source != expected_source or target != expected_target:
        raise ValueError(f"{label} source/target distributions do not match the corpus")
    rows_value = direction["rows"]
    if not isinstance(rows_value, list) or len(rows_value) != width:
        raise ValueError(f"{label} matrix has an invalid shape")
    rows: list[list[float]] = []
    for row_index, row_value in enumerate(rows_value):
        row = _finite_probability_vector(row_value, width, label)
        if any(weight != 0.0 for weight in row[:row_index]):
            raise ValueError(f"{label} matrix permits downward morphing")
        if source[row_index] == 0.0 and row != [
            1.0 if column == row_index else 0.0 for column in range(width)
        ]:
            raise ValueError(f"{label} unsupported source row must be identity")
        rows.append(row)
    realized = [
        fitting_morphing._canonical_float(
            math.fsum(source[row] * rows[row][column] for row in range(width))
        )
        for column in range(width)
    ]
    claimed_realized = _finite_probability_vector(direction["realized_distribution"], width, label)
    if claimed_realized != realized:
        raise ValueError(f"{label} realized distribution is inconsistent")
    l1 = fitting_morphing._canonical_float(
        math.fsum(abs(actual - expected) for actual, expected in zip(realized, target, strict=True))
    )
    added = fitting_morphing._canonical_float(
        math.fsum(
            source[row] * rows[row][column] * (buckets[column] - buckets[row])
            for row in range(width)
            for column in range(row, width)
        )
    )
    if direction["l1_distance"] != l1 or direction["expected_added_bytes"] != added:
        raise ValueError(f"{label} derived costs are inconsistent")
    return l1, added


def _validate_wtf_pad_artifact(
    provenance: Mapping[str, object], parameter: Mapping[str, Any]
) -> None:
    _require_scipy_version()
    _require_exact_keys(
        parameter,
        {
            "schema_version",
            "adaptation",
            "paper_equivalent",
            "fitted_from",
            "generated_by",
            "fitting",
            "outgoing",
            "incoming",
        },
        "WTF-PAD artifact",
    )
    constants = provenance["fitting_contract"]["constants"]["wtf_pad"]
    algorithm = provenance["algorithms"]["wtf_pad"]
    assert isinstance(constants, Mapping) and isinstance(algorithm, Mapping)
    expected_fitting = {
        "instantaneous_bandwidth_window_packets": constants["bandwidth_window_packets"],
        "burst_threshold_method": constants["burst_threshold_method"],
        "bandwidth_threshold_bytes_per_second": algorithm[
            "global_bandwidth_threshold_bytes_per_second"
        ],
        "candidate_models": constants["candidate_models"],
        "tuning_percentile": constants["tuning_percentile"],
        "tuning_applies_to": constants["tuning_applies_to"],
        "tuning_transformation": constants["tuning_transformation"],
        "finite_domain_percentile": constants["finite_domain_percentile"],
        "histogram_bin_count": constants["histogram_bin_count"],
        "histogram_scale": constants["histogram_scale"],
        "finite_token_budget": constants["finite_token_budget"],
        "fake_burst_probability": constants["fake_burst_probability"],
        "infinity_token_formulas": constants["infinity_token_formulas"],
    }
    if (
        parameter["schema_version"] != 2
        or parameter["adaptation"] != "qcsd-client-only"
        or parameter["paper_equivalent"] is not False
        or parameter["fitting"] != expected_fitting
        or parameter["fitted_from"] != _provenance_corpus_digest(provenance, "as-defined")
    ):
        raise ValueError("WTF-PAD artifact constants or fitted_from binding are invalid")
    expected_hashes = _provenance_training_hashes(provenance, "as-defined")
    training_samples = algorithm["training_samples"]
    if [sample["training_input_sha256"] for sample in training_samples] != expected_hashes:
        raise ValueError("WTF-PAD training samples do not match as-defined contributions")
    for direction in ("outgoing", "incoming"):
        intra: list[int] = []
        between: list[int] = []
        lengths: list[int] = []
        for sample in training_samples:
            values = sample["directions"][direction]
            intra.extend(values["intra_burst_delays_us"])
            between.extend(values["between_burst_delays_us"])
            lengths.extend(values["burst_lengths_packets"])
        mean_length = fitting_wtfpad._float(float(np.mean(np.asarray(lengths, dtype=np.int64))))
        if mean_length <= 1.0:
            raise ValueError(f"WTF-PAD {direction} mean burst length is invalid")
        burst_infinity = fitting_wtfpad._rounded_positive_tokens(
            ((1.0 - constants["fake_burst_probability"]) / constants["fake_burst_probability"])
            * constants["finite_token_budget"],
            f"{direction} H_B",
        )
        gap_infinity = fitting_wtfpad._rounded_positive_tokens(
            (constants["finite_token_budget"] - mean_length + 1.0) / (mean_length - 1.0),
            f"{direction} H_G",
        )
        expected_burst_histogram, expected_burst_fit = fitting_wtfpad._fit_population(
            np.asarray(between, dtype=np.int64),
            infinity_tokens=burst_infinity,
            label=f"{direction} between-burst verification",
            tuning_percentile=constants["tuning_percentile"],
        )
        expected_gap_histogram, expected_gap_fit = fitting_wtfpad._fit_population(
            np.asarray(intra, dtype=np.int64),
            infinity_tokens=gap_infinity,
            label=f"{direction} intra-burst verification",
            tuning_percentile=None,
        )
        direction_value = _validate_wtf_direction_schema(parameter[direction], direction)
        expected_direction = {
            "burst": expected_burst_histogram,
            "gap": expected_gap_histogram,
            "fit": {
                "mean_burst_length_packets": mean_length,
                "burst": expected_burst_fit,
                "gap": expected_gap_fit,
            },
        }
        if direction_value != expected_direction:
            raise ValueError(f"WTF-PAD {direction} histogram derivations are inconsistent")
        if (
            sum(direction_value["burst"]["tokens"]) != constants["finite_token_budget"]
            or sum(direction_value["gap"]["tokens"]) != constants["finite_token_budget"]
        ):
            raise ValueError(f"WTF-PAD {direction} finite token total is inconsistent")


def _validate_wtf_direction_schema(value: object, direction: str) -> Mapping[str, Any]:
    record = _exact_mapping(value, {"burst", "gap", "fit"}, f"WTF-PAD {direction}")
    for state in ("burst", "gap"):
        histogram = _exact_mapping(
            record[state], {"edges_us", "tokens", "infinity_tokens"}, f"WTF-PAD {state}"
        )
        edges = _positive_integer_list(histogram["edges_us"])
        tokens = histogram["tokens"]
        if (
            len(edges) != fitting_wtfpad.FINITE_BINS
            or not isinstance(tokens, list)
            or len(tokens) != len(edges)
            or any(type(token) is not int or token < 0 for token in tokens)
            or type(histogram["infinity_tokens"]) is not int
            or histogram["infinity_tokens"] <= 0
        ):
            raise ValueError(f"WTF-PAD {direction} {state} histogram schema is invalid")
    fit = _exact_mapping(
        record["fit"],
        {"mean_burst_length_packets", "burst", "gap"},
        f"WTF-PAD {direction} fit",
    )
    if not _positive_number(fit["mean_burst_length_packets"]):
        raise ValueError(f"WTF-PAD {direction} mean burst length is invalid")
    for state in ("burst", "gap"):
        population = _exact_mapping(
            fit[state],
            {
                "sample_count",
                "selected_model",
                "histogram_max_us",
                "runtime_parameters",
                "parameter_transformation",
                "candidates",
            },
            f"WTF-PAD {direction} {state} fit",
        )
        if (
            type(population["sample_count"]) is not int
            or population["sample_count"] <= 0
            or type(population["histogram_max_us"]) is not int
            or population["histogram_max_us"] <= 0
            or not isinstance(population["selected_model"], str)
            or not isinstance(population["parameter_transformation"], str)
            or not _finite_number_list(population["runtime_parameters"])
            or not isinstance(population["candidates"], list)
            or len(population["candidates"]) != 2
        ):
            raise ValueError(f"WTF-PAD {direction} {state} fit schema is invalid")
        for candidate in population["candidates"]:
            candidate_record = _exact_mapping(
                candidate,
                {"name", "parameters", "ks_statistic"},
                f"WTF-PAD {direction} {state} candidate",
            )
            if (
                not isinstance(candidate_record["name"], str)
                or not _finite_number_list(candidate_record["parameters"])
                or not _nonnegative_number(candidate_record["ks_statistic"])
                or candidate_record["ks_statistic"] > 1
            ):
                raise ValueError(f"WTF-PAD {direction} {state} candidate is invalid")
    return record


def _validate_walkie_talkie_artifact(
    provenance: Mapping[str, object],
    parameter: Mapping[str, Any],
    *,
    contract_version: int,
) -> None:
    if contract_version == 2:
        _validate_legacy_walkie_talkie_artifact(provenance, parameter)
        return
    if contract_version != 3:
        raise ValueError("unsupported research fitting contract version")
    _validate_current_walkie_talkie_artifact(provenance, parameter)


def _validate_legacy_walkie_talkie_artifact(
    provenance: Mapping[str, object], parameter: Mapping[str, Any]
) -> None:
    _require_exact_keys(
        parameter,
        {
            "adaptation",
            "burst_definition",
            "cell_byte_domain",
            "schema_version",
            "generated_by",
            "matching_algorithm",
            "paper_equivalent",
            "packet_size",
            "profiles",
        },
        "Walkie-Talkie artifact",
    )
    constants = provenance["fitting_contract"]["constants"]["walkie_talkie"]
    algorithm = provenance["algorithms"]["walkie_talkie"]
    assert isinstance(constants, Mapping) and isinstance(algorithm, Mapping)
    if (
        parameter["adaptation"] != "qcsd-client-only"
        or parameter["burst_definition"] != constants["burst_definition"]
        or parameter["cell_byte_domain"] != constants["cell_byte_domain"]
        or parameter["schema_version"] != 2
        or parameter["matching_algorithm"] != constants["runtime_matching_algorithm"]
        or parameter["paper_equivalent"] is not False
        or parameter["packet_size"] != constants["packet_size"]
    ):
        raise ValueError("Walkie-Talkie artifact constants are invalid")
    expected_hashes = _provenance_training_hashes(provenance, "half-duplex")
    training_visits = algorithm["training_visits"]
    flattened_receipt_hashes = [
        visit["training_input_sha256"]
        for workload in training_visits
        for visit in workload["visits"]
    ]
    if flattened_receipt_hashes != expected_hashes:
        raise ValueError("Walkie-Talkie training visits do not match half-duplex contributions")
    envelopes: dict[str, fitting_walkie_talkie.ProfileEnvelope] = {}
    training_by_workload: dict[str, list[str]] = {}
    for workload in training_visits:
        sequences = [
            _parse_burst_sequence(
                visit["bursts"], visit["batch_ends"], "Walkie-Talkie training visit"
            )
            for visit in workload["visits"]
        ]
        identity = workload["workload_id"]
        envelopes[identity] = fitting_walkie_talkie.componentwise_envelope(sequences)
        training_by_workload[identity] = [
            visit["training_input_sha256"] for visit in workload["visits"]
        ]
    lexical = tuple(sorted(envelopes))
    expected_candidates = [
        {
            "left": left,
            "right": right,
            "matching_cost_packets": fitting_walkie_talkie.symmetric_mold_padding_cost(
                envelopes[left].bursts, envelopes[right].bursts
            ),
        }
        for index, left in enumerate(lexical)
        for right in lexical[index + 1 :]
    ]
    pairs = fitting_walkie_talkie.minimum_weight_perfect_matching(envelopes)
    expected_selected = [
        {"real": real, "decoy": decoy, "matching_cost_packets": cost} for real, decoy, cost in pairs
    ]
    if (
        algorithm["candidate_pair_costs"] != expected_candidates
        or algorithm["selected_pairs"] != expected_selected
    ):
        raise ValueError("Walkie-Talkie matching receipt is inconsistent with its envelopes")
    expected_profiles: list[dict[str, object]] = []
    for real, decoy, cost in pairs:
        real_envelope = envelopes[real]
        decoy_envelope = envelopes[decoy]
        molded = tuple(
            fitting_walkie_talkie.symmetric_mold(real_envelope.bursts, decoy_envelope.bursts)
        )
        expected_profiles.append(
            {
                "real": real,
                "decoy": decoy,
                "matching_cost_packets": cost,
                "training_inputs": {
                    "real": training_by_workload[real],
                    "decoy": training_by_workload[decoy],
                },
                "variation": {
                    "real": fitting_walkie_talkie._variation_json(real_envelope),
                    "decoy": fitting_walkie_talkie._variation_json(decoy_envelope),
                },
                "source_envelopes": {
                    "real": fitting_walkie_talkie._bursts_json(real_envelope.bursts),
                    "decoy": fitting_walkie_talkie._bursts_json(decoy_envelope.bursts),
                },
                "batch_ends": {
                    "real": fitting_walkie_talkie._batch_ends(real_envelope.bursts),
                    "decoy": fitting_walkie_talkie._batch_ends(decoy_envelope.bursts),
                },
                "molded_batch_ends": fitting_walkie_talkie._batch_ends(molded),
                "total_scheduled_bytes": fitting_walkie_talkie._total_packets(molded)
                * constants["packet_size"],
                "bursts": fitting_walkie_talkie._bursts_json(molded),
            }
        )
    profiles = parameter["profiles"]
    if not isinstance(profiles, list) or len(profiles) != len(expected_profiles):
        raise ValueError("Walkie-Talkie artifact profile count is invalid")
    for profile in profiles:
        _validate_walkie_profile_schema(profile)
    if profiles != expected_profiles:
        raise ValueError("Walkie-Talkie artifact profiles are not derived from training visits")


def _validate_current_walkie_talkie_artifact(
    provenance: Mapping[str, object], parameter: Mapping[str, Any]
) -> None:
    _require_exact_keys(
        parameter,
        {
            "adaptation",
            "burst_definition",
            "cell_byte_domain",
            "schema_version",
            "generated_by",
            "matching_algorithm",
            "paper_equivalent",
            "packet_size",
            "receiver_continuation",
            "profiles",
        },
        "Walkie-Talkie artifact",
    )
    constants = provenance["fitting_contract"]["constants"]["walkie_talkie"]
    algorithm = provenance["algorithms"]["walkie_talkie"]
    assert isinstance(constants, Mapping) and isinstance(algorithm, Mapping)
    if (
        parameter["adaptation"] != "qcsd-client-only"
        or parameter["burst_definition"] != constants["burst_definition"]
        or parameter["cell_byte_domain"] != constants["cell_byte_domain"]
        or parameter["schema_version"] != 3
        or parameter["matching_algorithm"] != constants["pairing_algorithm"]
        or parameter["paper_equivalent"] is not False
        or parameter["packet_size"] != constants["packet_size"]
        or parameter["receiver_continuation"] != constants["receiver_continuation"]
        or parameter["receiver_continuation"] != algorithm["receiver_continuation"]
    ):
        raise ValueError("Walkie-Talkie artifact constants are invalid")
    expected_hashes = _provenance_training_hashes(provenance, "half-duplex")
    training_visits = algorithm["training_visits"]
    flattened_receipt_hashes = [
        visit["training_input_sha256"]
        for workload in training_visits
        for visit in workload["visits"]
    ]
    if flattened_receipt_hashes != expected_hashes:
        raise ValueError("Walkie-Talkie training visits do not match half-duplex contributions")
    envelopes: dict[str, fitting_walkie_talkie.ProfileEnvelope] = {}
    training_by_workload: dict[str, list[str]] = {}
    for workload in training_visits:
        sequences = [
            _parse_burst_sequence(
                visit["bursts"], visit["batch_ends"], "Walkie-Talkie training visit"
            )
            for visit in workload["visits"]
        ]
        identity = workload["workload_id"]
        envelopes[identity] = fitting_walkie_talkie.componentwise_envelope(sequences)
        training_by_workload[identity] = [
            visit["training_input_sha256"] for visit in workload["visits"]
        ]
    lexical = tuple(sorted(envelopes))
    expected_candidates = [
        {
            "left": left,
            "right": right,
            "base_matching_cost_packets": (
                fitting_walkie_talkie.symmetric_mold_padding_cost(
                    envelopes[left].bursts, envelopes[right].bursts
                )
            ),
            "matching_cost_packets": fitting_walkie_talkie.mold_padding_cost(
                envelopes[left].bursts, envelopes[right].bursts
            ),
        }
        for index, left in enumerate(lexical)
        for right in lexical[index + 1 :]
    ]
    pairs = fitting_walkie_talkie.minimum_weight_perfect_matching(envelopes)
    expected_selected = []
    for real, decoy, base_cost in pairs:
        expected_selected.append(
            {
                "real": real,
                "decoy": decoy,
                "base_matching_cost_packets": base_cost,
                "matching_cost_packets": fitting_walkie_talkie.mold_padding_cost(
                    envelopes[real].bursts, envelopes[decoy].bursts
                ),
            }
        )
    if (
        algorithm["candidate_pair_costs"] != expected_candidates
        or algorithm["selected_pairs"] != expected_selected
    ):
        raise ValueError("Walkie-Talkie matching receipt is inconsistent with its envelopes")
    expected_profiles: list[dict[str, object]] = []
    for real, decoy, _base_cost in pairs:
        real_envelope = envelopes[real]
        decoy_envelope = envelopes[decoy]
        molded = tuple(fitting_walkie_talkie.mold(real_envelope.bursts, decoy_envelope.bursts))
        expected_profiles.append(
            {
                "real": real,
                "decoy": decoy,
                "matching_cost_packets": fitting_walkie_talkie.mold_padding_cost(
                    real_envelope.bursts, decoy_envelope.bursts
                ),
                "training_inputs": {
                    "real": training_by_workload[real],
                    "decoy": training_by_workload[decoy],
                },
                "variation": {
                    "real": fitting_walkie_talkie._variation_json(real_envelope),
                    "decoy": fitting_walkie_talkie._variation_json(decoy_envelope),
                },
                "source_envelopes": {
                    "real": fitting_walkie_talkie._bursts_json(real_envelope.bursts),
                    "decoy": fitting_walkie_talkie._bursts_json(decoy_envelope.bursts),
                },
                "batch_ends": {
                    "real": fitting_walkie_talkie._batch_ends(real_envelope.bursts),
                    "decoy": fitting_walkie_talkie._batch_ends(decoy_envelope.bursts),
                },
                "molded_batch_ends": fitting_walkie_talkie._batch_ends(molded),
                "total_scheduled_bytes": fitting_walkie_talkie._total_packets(molded)
                * constants["packet_size"],
                "bursts": fitting_walkie_talkie._bursts_json(molded),
            }
        )
    profiles = parameter["profiles"]
    if not isinstance(profiles, list) or len(profiles) != len(expected_profiles):
        raise ValueError("Walkie-Talkie artifact profile count is invalid")
    for profile in profiles:
        _validate_walkie_profile_schema(profile)
    if profiles != expected_profiles:
        raise ValueError("Walkie-Talkie artifact profiles are not derived from training visits")


def _validate_walkie_profile_schema(value: object) -> None:
    profile = _exact_mapping(
        value,
        {
            "real",
            "decoy",
            "matching_cost_packets",
            "training_inputs",
            "variation",
            "source_envelopes",
            "batch_ends",
            "molded_batch_ends",
            "total_scheduled_bytes",
            "bursts",
        },
        "Walkie-Talkie profile",
    )
    if (
        not isinstance(profile["real"], str)
        or not profile["real"]
        or not isinstance(profile["decoy"], str)
        or not profile["decoy"]
        or type(profile["matching_cost_packets"]) is not int
        or profile["matching_cost_packets"] < 0
        or type(profile["total_scheduled_bytes"]) is not int
        or profile["total_scheduled_bytes"] <= 0
    ):
        raise ValueError("Walkie-Talkie profile scalar fields are invalid")
    training = _exact_mapping(
        profile["training_inputs"], {"real", "decoy"}, "Walkie-Talkie training inputs"
    )
    variation = _exact_mapping(profile["variation"], {"real", "decoy"}, "Walkie-Talkie variation")
    envelopes = _exact_mapping(
        profile["source_envelopes"], {"real", "decoy"}, "Walkie-Talkie envelopes"
    )
    batch_ends = _exact_mapping(
        profile["batch_ends"], {"real", "decoy"}, "Walkie-Talkie batch ends"
    )
    for side in ("real", "decoy"):
        if not isinstance(training[side], list) or any(
            not _digest(value) for value in training[side]
        ):
            raise ValueError("Walkie-Talkie training hashes are invalid")
        stats = _exact_mapping(
            variation[side],
            {"visit_count", "varying_components", "maximum_component_spread"},
            "Walkie-Talkie variation statistics",
        )
        if any(type(stats[field]) is not int or stats[field] < 0 for field in stats):
            raise ValueError("Walkie-Talkie variation statistics are invalid")
        _parse_burst_sequence(envelopes[side], batch_ends[side], "Walkie-Talkie source envelope")
    _parse_burst_sequence(profile["bursts"], profile["molded_batch_ends"], "Walkie-Talkie mold")


def _parse_burst_sequence(
    bursts_value: object, batch_ends_value: object, label: str
) -> tuple[fitting_walkie_talkie.BurstPair, ...]:
    if not isinstance(bursts_value, list) or not bursts_value:
        raise ValueError(f"{label} bursts are invalid")
    if (
        not isinstance(batch_ends_value, list)
        or not batch_ends_value
        or any(type(index) is not int or index < 0 for index in batch_ends_value)
        or batch_ends_value != sorted(set(batch_ends_value))
        or batch_ends_value[-1] != len(bursts_value) - 1
    ):
        raise ValueError(f"{label} batch ends are invalid")
    ends = set(batch_ends_value)
    result: list[fitting_walkie_talkie.BurstPair] = []
    for index, value in enumerate(bursts_value):
        record = _exact_mapping(value, {"outgoing", "incoming"}, f"{label} burst")
        outgoing = record["outgoing"]
        incoming = record["incoming"]
        if (
            type(outgoing) is not int
            or type(incoming) is not int
            or not 0 <= outgoing <= fitting_walkie_talkie.MAX_U32
            or not 0 <= incoming <= fitting_walkie_talkie.MAX_U32
            or outgoing + incoming == 0
        ):
            raise ValueError(f"{label} burst counts are invalid")
        result.append(fitting_walkie_talkie.BurstPair(outgoing, incoming, index in ends))
    return tuple(result)


def _provenance_training_hashes(provenance: Mapping[str, object], policy: str) -> list[str]:
    contributions = provenance["sample_contributions"]
    return [
        sample["training_input_sha256"]
        for workload in contributions
        for sample in workload["policies"][policy]
    ]


def _provenance_corpus_digest(provenance: Mapping[str, object], policy: str) -> str:
    identity = [
        {
            "workload_id": workload["workload_id"],
            "samples": [sample["training_input_sha256"] for sample in workload["policies"][policy]],
        }
        for workload in provenance["sample_contributions"]
    ]
    return sha256_bytes(
        b"qcsd-consumed-fitting-corpus-v1\0"
        + json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )


def _finite_probability_vector(value: object, width: int, label: str) -> list[float]:
    if not isinstance(value, list) or len(value) != width or not _finite_number_list(value):
        raise ValueError(f"{label} probability vector is invalid")
    result = [float(item) for item in value]
    if any(item < 0.0 or item > 1.0 for item in result) or not math.isclose(
        math.fsum(result), 1.0, abs_tol=1e-12
    ):
        raise ValueError(f"{label} probability vector is invalid")
    return result


def _finite_number_list(value: object) -> bool:
    return isinstance(value, list) and all(
        not isinstance(item, bool) and isinstance(item, (int, float)) and math.isfinite(float(item))
        for item in value
    )


def _positive_integer_list(value: object) -> list[int]:
    if not isinstance(value, list) or any(type(item) is not int or item <= 0 for item in value):
        raise ValueError("fitting population must contain positive integers")
    return value


def _require_exact_keys(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise ValueError(f"{label} has an invalid schema")


def _require_scipy_version() -> None:
    import scipy

    if scipy.__version__ != "1.17.1" or np.__version__ != "2.2.6":
        raise ValueError("research fitting requires NumPy 2.2.6 and SciPy 1.17.1")


def _cost_records(
    value: object,
    *,
    identity_fields: tuple[str, str],
    cost_fields: tuple[str, ...],
    label: str,
    integer_costs: bool = False,
) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    expected = {*identity_fields, *cost_fields}
    result: list[Mapping[str, object]] = []
    for item in value:
        record = _exact_mapping(item, expected, label)
        if any(
            not isinstance(record[field], str) or not record[field] for field in identity_fields
        ):
            raise ValueError(f"{label} contains an invalid identity")
        for field in cost_fields:
            cost = record[field]
            valid = type(cost) is int and cost >= 0 if integer_costs else _nonnegative_number(cost)
            if not valid:
                raise ValueError(f"{label} contains an invalid cost")
        result.append(record)
    return result


def _exact_mapping(value: object, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(f"{label} has an invalid schema")
    return value


def _nonnegative_number(value: object) -> bool:
    import math

    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) >= 0
    )


def _positive_number(value: object) -> bool:
    return _nonnegative_number(value) and float(value) > 0


def _algorithm_receipt_digest(value: object) -> str:
    return sha256_bytes(
        b"qcsd-algorithm-receipt-v1\0"
        + json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    )


def _validate_runtime_parameter(value: object, kind: str, *, contract_version: int) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{kind} parameter artifact must be a JSON object")
    if contract_version not in {2, 3}:
        raise ValueError("unsupported research fitting contract version")
    expected_schema_version = 3 if kind == "walkie_talkie" and contract_version == 3 else 2
    if (
        value.get("schema_version") != expected_schema_version
        or value.get("adaptation") != "qcsd-client-only"
        or value.get("paper_equivalent") is not False
    ):
        raise ValueError(f"{kind} parameter artifact has an invalid runtime contract")
    if kind == "traffic_morphing":
        if value.get("udp_payload_ceiling") != 1_200 or value.get("buckets", [None])[-1] != 1_200:
            raise ValueError("Traffic Morphing artifact has the wrong 1200-byte domain")
    elif kind == "wtf_pad":
        fitting = value.get("fitting")
        if (
            not isinstance(fitting, Mapping)
            or fitting.get("burst_threshold_method") != "corpus-mean-bandwidth"
        ):
            raise ValueError("WTF-PAD artifact lacks the global corpus threshold contract")
    elif kind == "walkie_talkie":
        if value.get("packet_size") != 1_200:
            raise ValueError("Walkie-Talkie artifact has the wrong cell size")
    else:
        raise ValueError(f"unsupported research parameter kind: {kind}")
    from .parameters import _validate_runtime_shape

    _validate_runtime_shape(
        value,
        kind,
        1_200,
        Path(BUNDLE_FILES[kind]),
        expected_schema_version=expected_schema_version,
    )


def _fitting_contract(workload_order: Sequence[str]) -> dict[str, object]:
    return {
        "contract_version": 3,
        "fitter_version": FITTER_VERSION,
        "parameter_schema_versions": {
            "traffic_morphing": 2,
            "walkie_talkie": 3,
            "wtf_pad": 2,
        },
        "profile": "research-1200",
        "request_policies": ["as-defined", "half-duplex"],
        "visits_per_policy": 10,
        "workload_order": list(workload_order),
        "constants": {
            "dependencies": {
                "numpy": "2.2.6",
                "scipy": "1.17.1",
            },
            "extractor": {
                "authoritative_files": ["neqo/events.csv", "neqo/run.json"],
                "events_columns": [
                    "monotonic_us",
                    "connection",
                    "event",
                    "outcome",
                    "details",
                ],
                "typed_record_filter": {
                    "event": "observation",
                    "outcome": "recorded",
                },
                "production_sequence": "unique-contiguous-zero-based-set",
                "production_event_order": "nondecreasing-(nanoseconds,sequence)-file-order",
                "csv_time_binding": "monotonic_us=floor(production_monotonic_ns/1000)",
                "traffic_window": {
                    "start_field": "defense_start_monotonic_ns",
                    "end_field": "application_completion_monotonic_ns",
                    "inclusive": True,
                },
                "typed_lifecycle_closure": {
                    "applies_to": "half-duplex",
                    "event": "application_complete",
                    "full_trace_cardinality": 1,
                    "production_relation": "marker-nanoseconds>=end-field",
                    "retention": "numeric-window-plus-unique-causal-closure-marker",
                    "post_end_observations_before_marker": "forbidden",
                },
                "datagram_event": "classified_datagram",
                "validated_datagram_classes": ["natural", "defense_cover"],
                "consumed_datagram_class": "natural",
                "directions": ["outgoing", "incoming"],
                "udp_payload_range_inclusive": [1, 1_200],
                "cross_visit_state": "forbidden",
                "training_input_domain_separator": "qcsd-fitting-trace-v1\\0",
                "consumed_corpus_domain_separator": "qcsd-consumed-fitting-corpus-v1\\0",
            },
            "traffic_morphing": {
                "buckets": [64, 150, 300, 500, 700, 900, 1_100, 1_200],
                "bucket_assignment": "smallest-bucket-greater-than-or-equal-searchsorted-left",
                "distribution_aggregation": "pooled-packet-counts-per-workload-direction",
                "solver": {
                    "implementation": "scipy.optimize.linprog",
                    "scipy_version": "1.17.1",
                    "method": "highs",
                    "options": {
                        "dual_feasibility_tolerance": 1e-9,
                        "ipm_optimality_tolerance": 1e-10,
                        "presolve": True,
                        "primal_feasibility_tolerance": 1e-9,
                    },
                },
                "matrix_constraints": {
                    "row_sum": "sum_j(M[i,j])=1",
                    "padding_only": "M[i,j]=0 when j<i",
                    "unsupported_source_row": "identity",
                    "bounds": "0<=M[i,j]<=1",
                },
                "realized_distribution_formula": "r[j]=fsum_i(p_source[i]*M[i,j])",
                "l1_formula": "fsum_j(abs(r[j]-p_target[j]))",
                "expected_added_bytes_formula": "fsum_i,j(p_source[i]*M[i,j]*(bucket[j]-bucket[i]))",
                "lp_stages": [
                    "minimize-l1-slack",
                    "fix-l1-optimum-then-minimize-expected-added-bytes",
                    "fix-l1-and-byte-optima-then-minimize-each-row-major-cell",
                ],
                "canonicalization": {
                    "cell_order": "row-major",
                    "cell_objective": "minimum",
                    "fixed_cell_constraint": "equality",
                    "matrix_zero_threshold": 1e-8,
                    "solver_snap_threshold": 1e-10,
                    "serialized_decimal_places": 15,
                    "row_renormalization": True,
                },
                "conditional_flow_tie_break": "lexicographically-minimum-row-major",
                "edge_cost": {
                    "primary": "l1_outgoing+l1_incoming",
                    "secondary": "n_outgoing*Eadd_outgoing+n_incoming*Eadd_incoming",
                    "summation": "math.fsum-no-rounding",
                },
                "assignment": {
                    "constraint": "one-to-one-directed-derangement",
                    "source_order": "frozen-campaign-order",
                    "self_edges": "excluded",
                },
                "assignment_tie_break": "lexical-target-vector",
                "mapping_constraint": "padding-only-upward-buckets",
            },
            "wtf_pad": {
                "bandwidth_window_packets": 2,
                "burst_threshold_method": "corpus-mean-bandwidth",
                "global_bandwidth_formula": "1e9*sum(trace_bytes)/sum(trace_last_ns-trace_first_ns)",
                "instantaneous_bandwidth_formula": "1e9*(left_bytes+right_bytes)/delta_ns",
                "burst_comparison": "instantaneous_bandwidth>=global_threshold",
                "interarrival_conversion": "ceil(delta_ns/1000)-microseconds",
                "cross_visit_interarrivals": "forbidden",
                "candidate_models": ["normal", "lognormal"],
                "maximum_likelihood": {
                    "normal": "scipy.stats.norm.fit",
                    "lognormal": "scipy.stats.lognorm.fit(floc=0)",
                },
                "ks_test": "scipy.stats.kstest-full-precision",
                "model_selection": "minimum-KS-normal-first-exact-tie",
                "minimum_distinct_delays": 2,
                "fake_burst_probability": 0.9,
                "finite_bins": 19,
                "infinity_bins": 1,
                "finite_domain_percentile": 99.5,
                "finite_token_budget": 10_000,
                "histogram_bin_count": 20,
                "histogram_scale": "exponential",
                "infinity_token_rounding": "ceil",
                "infinity_token_formulas": {
                    "burst": "k_inf = (1 - p_fake) / p_fake * K",
                    "gap": "k_inf = (K - mean_burst_length + 1) / (mean_burst_length - 1)",
                },
                "minimum_state_population": 20,
                "token_allocation": "largest-remainder-leftmost-tie",
                "finite_edge_formula": "ceil(max_us*(2^(i+1)-1)/(2^19-1))-strictly-increasing-clamp",
                "finite_probability_formula": "max(0,CDF(edge_i)-CDF(edge_(i-1)))",
                "finite_probability_lower_origin_us": 0,
                "gap_transformation": "identity",
                "tuning_percentile": 0.5,
                "tuning_applies_to": "burst-histogram-only",
                "tuning_transformation": "paper-gaussian-percentile-shift-v1",
                "tuning_formula": {
                    "z": "scipy.stats.norm.ppf(tuning_percentile)",
                    "scale_multiplier": "exp(z^2/2)",
                    "normal": "location'=location+scale*z;scale'=scale*multiplier",
                    "lognormal": "shape'=shape*multiplier;loc'=0;scale'=scale*exp(shape*z)",
                },
                "finite_cutoff": "ceil(selected-runtime-model-ppf(0.995))",
            },
            "walkie_talkie": {
                "burst_definition": "global-application-batch-direction-transitions",
                "cell_byte_domain": "http3-request-stream-offset.bytes",
                "included_stream_role": "application",
                "excluded_stream_roles": ["chaff", "control"],
                "outgoing_retransmission_rule": "union-stream-offset-ranges-per-batch",
                "incoming_rule": "sum-positive-raw-BytesRead-per-batch",
                "zero_bytes_read": "validated-unsigned-no-op-excluded-from-direction-segmentation",
                "direction_segmentation": "coalesce-adjacent-equal-directions",
                "batch_direction_rule": "outgoing-first-and-at-least-one-incoming",
                "cell_count_formula": "ceil(unique_or_read_bytes/packet_size)",
                "cross_visit_state": "forbidden",
                "visit_stability": {
                    "batch_count": "exactly-equal",
                    "per_batch_direction_structure": "exactly-equal",
                    "visit_order": "0-through-9",
                },
                "envelope": "componentwise-max-corresponding-structure",
                "symmetric_mold": "batch-aware-componentwise-max-with-zero-for-missing-pair",
                "receiver_continuation": (fitting_walkie_talkie.receiver_continuation_contract()),
                "prepared_receiver_continuation_invariant": {
                    "adapted_target_formula": (
                        "sealed_symmetric_envelope_cells*packet_size+packet_size"
                    ),
                    "application_stream_bound": (
                        "raw-request-stream-bytes<="
                        "projected-stable-body-bytes+max_stream_data_excess"
                    ),
                    "chaff_capacity_requirement": (
                        "eligible-chaff-projected-stable-body-bytes>=packet_size"
                    ),
                    "failure_policy": "source-envelope-overflow-is-fidelity-ineligible",
                    "live_component_bound": (
                        "source_raw_bytes<=sealed_symmetric_envelope_cells*packet_size"
                    ),
                    "parser_bootstrap_requirement": (
                        "pristine-chaff-header-bytes<=parser_allowance_ceiling_bytes<packet_size"
                    ),
                    "post_all_applications_residual_lower_bound_formula": (
                        "adapted_target_bytes-source_raw_bytes>=packet_size"
                    ),
                    "residual_reallocation": (
                        "cumulative-application-FIN-residuals-requeue-within-same-incoming-turn"
                    ),
                    "residual_coalescence": (
                        "stable-app-first-FIN-return-fragments-coalesce-on-first-eligible-"
                        "chaff-stream"
                    ),
                    "scope": "prepared-research-cohort-under-listed-assumptions",
                },
                "runtime_mold": ("receiver-continuation-adaptation(symmetric-mold(real,decoy))"),
                "matching_cost_formula": (
                    "2*total_packets(runtime_mold)-total_packets(real)-total_packets(decoy)"
                ),
                "matching_tie_break": "lexical-pair-vector",
                "packet_size": 1_200,
                "pairing": "full-cohort-minimum-weight-perfect-matching",
                "pairing_objective": "minimum-base-symmetric-mold-padding-cost",
                "base_matching_cost_formula": (
                    "2*total_packets(symmetric_mold)-total_packets(real)-total_packets(decoy)"
                ),
                "pair_orientation": "lexical",
                "pairing_algorithm": ("minimum-base-symmetric-mold-padding-cost-one-to-one"),
                "total_scheduled_bytes_formula": "total_packets(runtime_mold)*packet_size",
                "training_hash_order": "visit-order",
            },
        },
    }


def _legacy_fitting_contract(workload_order: Sequence[str]) -> dict[str, object]:
    """Reconstruct the exact contract-2 oracle used by preserved results."""

    current = _fitting_contract(workload_order)
    constants = dict(current["constants"])
    constants["walkie_talkie"] = {
        "burst_definition": "global-application-batch-direction-transitions",
        "cell_byte_domain": "http3-request-stream-offset.bytes",
        "included_stream_role": "application",
        "excluded_stream_roles": ["chaff", "control"],
        "outgoing_retransmission_rule": "union-stream-offset-ranges-per-batch",
        "incoming_rule": "sum-positive-raw-BytesRead-per-batch",
        "zero_bytes_read": "validated-unsigned-no-op-excluded-from-direction-segmentation",
        "direction_segmentation": "coalesce-adjacent-equal-directions",
        "batch_direction_rule": "outgoing-first-and-at-least-one-incoming",
        "cell_count_formula": "ceil(unique_or_read_bytes/packet_size)",
        "cross_visit_state": "forbidden",
        "visit_stability": {
            "batch_count": "exactly-equal",
            "per_batch_direction_structure": "exactly-equal",
            "visit_order": "0-through-9",
        },
        "envelope": "componentwise-max-corresponding-structure",
        "mold": "batch-aware-componentwise-max-with-zero-for-missing-pair",
        "matching_cost_formula": ("2*total_packets(mold)-total_packets(real)-total_packets(decoy)"),
        "matching_tie_break": "lexical-pair-vector",
        "packet_size": 1_200,
        "pairing": "full-cohort-minimum-weight-perfect-matching",
        "pair_orientation": "lexical",
        "runtime_matching_algorithm": "minimum-cost-one-to-one",
        "total_scheduled_bytes_formula": "total_packets(mold)*packet_size",
        "training_hash_order": "visit-order",
    }
    return {
        "contract_version": 2,
        "fitter_version": LEGACY_FITTER_VERSION,
        "parameter_schema_version": 2,
        "profile": "research-1200",
        "request_policies": ["as-defined", "half-duplex"],
        "visits_per_policy": 10,
        "workload_order": list(workload_order),
        "constants": constants,
    }


def _validate_clean_source(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != SOURCE_METADATA_KEYS:
        raise ValueError("research fitting requires complete source/image provenance")
    image = value.get("image_digest")
    if (
        not isinstance(image, str)
        or not image.startswith("sha256:")
        or not _digest(image.removeprefix("sha256:"))
    ):
        raise ValueError("research fitting requires a concrete image SHA-256 digest")
    if value.get("lab_dirty") is not False or value.get("neqo_dirty") is not False:
        raise ValueError("research fitting requires clean lab and Neqo sources")
    if (
        value.get("lab_patch_sha256") != EMPTY_SHA256
        or value.get("neqo_patch_sha256") != EMPTY_SHA256
    ):
        raise ValueError("research fitting requires empty source patch hashes")
    for key in ("lab_commit", "neqo_commit", "neqo_pinned_commit"):
        commit = value.get(key)
        if (
            not isinstance(commit, str)
            or len(commit) != 40
            or any(character not in "0123456789abcdef" for character in commit)
        ):
            raise ValueError(f"research fitting source {key} is invalid")
    if value["neqo_commit"] != value["neqo_pinned_commit"]:
        raise ValueError("research fitting Neqo commit does not match the pinned submodule")


def _validate_artifact_coverage(root: Path, expected: set[str]) -> None:
    for kind, filename in BUNDLE_FILES.items():
        parameter = load_json(root / filename)
        if kind != "wtf_pad":
            if not isinstance(parameter, Mapping):
                raise ValueError(f"{kind} artifact must be a JSON object")
            _validate_exact_parameter_coverage(parameter, kind, expected)


def _validate_exact_parameter_coverage(
    parameter: Mapping[str, Any], kind: str, expected: set[str]
) -> None:
    profiles = parameter.get("profiles")
    if not isinstance(profiles, list):
        raise ValueError(f"{kind} artifact profiles are invalid")
    if kind == "traffic_morphing":
        sources = [profile.get("source") for profile in profiles if isinstance(profile, Mapping)]
        targets = [profile.get("target") for profile in profiles if isinstance(profile, Mapping)]
        if (
            len(sources) != len(expected)
            or len(targets) != len(expected)
            or set(sources) != expected
            or set(targets) != expected
            or len(set(sources)) != len(sources)
            or len(set(targets)) != len(targets)
            or any(source == target for source, target in zip(sources, targets, strict=True))
        ):
            raise ValueError("Traffic Morphing source/target profiles must be an exact derangement")
        return
    if kind == "walkie_talkie":
        identities = [
            profile.get(field)
            for profile in profiles
            if isinstance(profile, Mapping)
            for field in ("real", "decoy")
        ]
        if len(identities) != len(expected) or set(identities) != expected:
            raise ValueError(
                "Walkie-Talkie profile union does not exactly match campaign workloads"
            )
        return
    raise ValueError(f"unsupported exact coverage kind: {kind}")


def _parameter_workloads(value: Mapping[str, Any], kind: str) -> set[str]:
    if kind == "wtf_pad":
        return set()
    profiles = value.get("profiles")
    if not isinstance(profiles, list):
        raise ValueError(f"{kind} parameter profiles are invalid")
    if kind == "traffic_morphing":
        return {profile["source"] for profile in profiles if isinstance(profile, Mapping)}
    return {
        identity
        for profile in profiles
        if isinstance(profile, Mapping)
        for identity in (profile.get("real"), profile.get("decoy"))
        if isinstance(identity, str)
    }


def _bundle_bytes(root: Path) -> tuple[bytes, ...]:
    return tuple((root / filename).read_bytes() for filename in sorted(EXACT_BUNDLE_FILES))


def _run_rust_parameter_validator(kind: str, path: Path, workloads: Sequence[str]) -> None:
    command = _rust_parameter_validator_command()
    result = run(
        [*command, kind, str(path), *workloads],
        cwd=LAB_ROOT / "neqo-qcsd",
        check=False,
    )
    if result.returncode:
        detail = result.stdout.strip() or "no validator output"
        raise ValueError(f"production Rust parameter parser rejected {kind}: {detail}")


def _rust_parameter_validator_command() -> list[str]:
    configured = os.environ.get("QCSD_PARAMETER_VALIDATOR")
    if configured:
        candidate = Path(configured)
        if not candidate.is_file():
            raise ValueError(f"configured parameter validator does not exist: {candidate}")
        return [str(candidate)]
    installed = shutil.which("qcsd-validate-parameters")
    if installed:
        return [installed]
    neqo = LAB_ROOT / "neqo-qcsd"
    for candidate in (
        neqo / "target/release/qcsd-validate-parameters",
        neqo / "target/debug/qcsd-validate-parameters",
    ):
        if candidate.is_file():
            return [str(candidate)]
    if shutil.which("cargo") and (neqo / "Cargo.lock").is_file():
        return [
            "cargo",
            "run",
            "--locked",
            "--offline",
            "--quiet",
            "-p",
            "neqo-csdef",
            "--bin",
            "qcsd-validate-parameters",
            "--",
        ]
    raise ValueError("the offline qcsd-validate-parameters production parser is unavailable")


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _contains_absolute_path(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(_contains_absolute_path(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_absolute_path(item) for item in value)
    if isinstance(value, str):
        return Path(value).is_absolute()
    return False
