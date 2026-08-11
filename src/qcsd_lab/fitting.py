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


BUNDLE_SCHEMA_VERSION = 1
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
FITTER_VERSION = "qcsd_lab.fitting 1.0.0"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ALGORITHM_GENERATORS = {
    "traffic_morphing": "qcsd_lab.fitting_morphing 1.0.0",
    "wtf_pad": "qcsd_lab.fitting_wtfpad 1.0.0",
    "walkie_talkie": "qcsd_lab.fitting_walkie_talkie 1.0.0",
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
    _validate_provenance(provenance)
    artifact_hashes: dict[str, str] = {}
    for kind, filename in BUNDLE_FILES.items():
        record = provenance["artifacts"][kind]
        if record != {"path": filename, "sha256": sha256_file(root / filename)}:
            raise ValueError(f"artifact provenance hash mismatch: {filename}")
        artifact_hashes[kind] = record["sha256"]
        parameter = load_json(root / filename)
        _validate_runtime_parameter(parameter, kind)
        assert isinstance(parameter, Mapping)
        _validate_algorithm_artifact_binding(provenance, kind, parameter)
    expected_workloads = {record["workload_id"] for record in provenance["sample_contributions"]}
    _validate_artifact_coverage(root, expected_workloads)
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
) -> tuple[str, str, str]:
    """Validate one runtime file against a shared fitted-bundle receipt."""

    if parameter_path.is_symlink() or provenance_path.is_symlink():
        raise ValueError("research parameter files must not be symbolic links")
    if not parameter_path.is_file() or not provenance_path.is_file():
        raise ValueError("research parameter and provenance must be regular files")
    parameter_path = parameter_path.resolve()
    provenance_path = provenance_path.resolve()
    provenance = load_json(provenance_path)
    _validate_provenance(provenance)
    if expected_kind not in BUNDLE_FILES:
        raise ValueError(f"unsupported research parameter kind: {expected_kind}")
    record = provenance["artifacts"][expected_kind]
    expected_name = parameter_name or parameter_path.name
    if record["path"] != expected_name or record["sha256"] != sha256_file(parameter_path):
        raise ValueError("research parameter file does not match its shared provenance receipt")
    parameter = load_json(parameter_path)
    _validate_runtime_parameter(parameter, expected_kind)
    assert isinstance(parameter, Mapping)
    _validate_algorithm_artifact_binding(provenance, expected_kind, parameter)
    expected = set(expected_workloads or ())
    if expected and expected_kind != "wtf_pad":
        _validate_exact_parameter_coverage(parameter, expected_kind, expected)
    _run_rust_parameter_validator(expected_kind, parameter_path, tuple(sorted(expected)))
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


def _validate_provenance(value: object) -> None:
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
    if not isinstance(contract, Mapping) or set(contract) != {
        "contract_version",
        "fitter_version",
        "parameter_schema_version",
        "profile",
        "request_policies",
        "visits_per_policy",
        "workload_order",
        "constants",
    }:
        raise ValueError("research fitting contract receipt is invalid")
    if (
        contract["contract_version"] != 1
        or contract["fitter_version"] != FITTER_VERSION
        or contract["parameter_schema_version"] != 2
        or contract["profile"] != "research-1200"
        or contract["request_policies"] != ["as-defined", "half-duplex"]
        or contract["visits_per_policy"] != 10
        or not isinstance(contract["workload_order"], list)
        or len(contract["workload_order"]) != 6
        or len(set(contract["workload_order"])) != 6
        or not isinstance(contract["constants"], Mapping)
    ):
        raise ValueError("research fitting contract values are invalid")
    if dict(contract) != _fitting_contract(contract["workload_order"]):
        raise ValueError("research fitting contract constants are invalid")
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
    _validate_algorithm_receipts(value["algorithms"], contract["workload_order"])
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


def _validate_algorithm_receipts(
    algorithms: Mapping[str, object], workload_order: Sequence[str]
) -> None:
    _validate_traffic_morphing_receipt(algorithms["traffic_morphing"], workload_order)
    _validate_wtf_pad_receipt(algorithms["wtf_pad"])
    _validate_walkie_talkie_receipt(algorithms["walkie_talkie"], workload_order)


def _validate_traffic_morphing_receipt(value: object, workload_order: Sequence[str]) -> None:
    receipt = _exact_mapping(
        value,
        {"algorithm", "candidate_costs", "selected_mapping"},
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
        {"algorithm", "global_bandwidth_threshold_bytes_per_second", "populations"},
        "WTF-PAD algorithm receipt",
    )
    if receipt["algorithm"] != "corpus-mean-bandwidth-mle-ks-histograms" or not _positive_number(
        receipt["global_bandwidth_threshold_bytes_per_second"]
    ):
        raise ValueError("WTF-PAD algorithm receipt is invalid")
    populations = _exact_mapping(
        receipt["populations"], {"outgoing", "incoming"}, "WTF-PAD populations"
    )
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
            or population["bursts"] != population["between_burst_delays"] + 60
        ):
            raise ValueError(f"WTF-PAD {direction} population receipt is invalid")


def _validate_walkie_talkie_receipt(value: object, workload_order: Sequence[str]) -> None:
    receipt = _exact_mapping(
        value,
        {"algorithm", "candidate_pair_costs", "selected_pairs"},
        "Walkie-Talkie algorithm receipt",
    )
    if receipt["algorithm"] != "full-cohort-minimum-weight-perfect-matching":
        raise ValueError("Walkie-Talkie algorithm receipt is invalid")
    lexical = tuple(sorted(workload_order))
    expected_pairs = [
        (left, right) for index, left in enumerate(lexical) for right in lexical[index + 1 :]
    ]
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


def _validate_algorithm_artifact_binding(
    provenance: Mapping[str, object], kind: str, parameter: Mapping[str, Any]
) -> None:
    algorithms = provenance["algorithms"]
    contract = provenance["fitting_contract"]
    assert isinstance(algorithms, Mapping) and isinstance(contract, Mapping)
    receipt = algorithms[kind]
    expected_generator = (
        f"{ALGORITHM_GENERATORS[kind]}; algorithm_receipt_sha256="
        f"{_algorithm_receipt_digest(receipt)}"
    )
    if parameter.get("generated_by") != expected_generator:
        raise ValueError(f"{kind} artifact does not bind its algorithm receipt")
    constants = contract["constants"]
    assert isinstance(constants, Mapping)
    if kind == "traffic_morphing":
        algorithm = _exact_mapping(
            receipt,
            {"algorithm", "candidate_costs", "selected_mapping"},
            "Traffic Morphing algorithm receipt",
        )
        profiles = parameter.get("profiles")
        selected = algorithm["selected_mapping"]
        if not isinstance(profiles, list) or not isinstance(selected, list):
            raise ValueError("Traffic Morphing artifact/receipt binding is invalid")
        identities = [
            (profile.get("source"), profile.get("target"))
            for profile in profiles
            if isinstance(profile, Mapping)
        ]
        selected_identities = [
            (item.get("source"), item.get("target"))
            for item in selected
            if isinstance(item, Mapping)
        ]
        if (
            identities != selected_identities
            or parameter.get("buckets") != constants["traffic_morphing"]["buckets"]
        ):
            raise ValueError("Traffic Morphing artifact disagrees with its algorithm receipt")
        for profile, item in zip(profiles, selected, strict=True):
            assert isinstance(profile, Mapping) and isinstance(item, Mapping)
            outgoing = profile.get("outgoing")
            incoming = profile.get("incoming")
            if (
                not isinstance(outgoing, Mapping)
                or not isinstance(incoming, Mapping)
                or item["l1_cost"]
                != outgoing.get("l1_distance", -1) + incoming.get("l1_distance", -1)
            ):
                raise ValueError("Traffic Morphing selected fidelity cost is inconsistent")
            for direction in (outgoing, incoming):
                rows = direction.get("rows")
                if not isinstance(rows, list) or any(
                    any(float(weight) != 0.0 for weight in row[:index])
                    for index, row in enumerate(rows)
                    if isinstance(row, list)
                ):
                    raise ValueError("Traffic Morphing artifact permits downward morphing")
        return
    if kind == "wtf_pad":
        algorithm = _exact_mapping(
            receipt,
            {"algorithm", "global_bandwidth_threshold_bytes_per_second", "populations"},
            "WTF-PAD algorithm receipt",
        )
        fitting = parameter.get("fitting")
        if not isinstance(fitting, Mapping):
            raise ValueError("WTF-PAD fitting metadata is invalid")
        wtf_constants = constants["wtf_pad"]
        assert isinstance(wtf_constants, Mapping)
        expected_constants = {
            "instantaneous_bandwidth_window_packets": wtf_constants["bandwidth_window_packets"],
            "burst_threshold_method": wtf_constants["burst_threshold_method"],
            "candidate_models": wtf_constants["candidate_models"],
            "tuning_percentile": wtf_constants["tuning_percentile"],
            "tuning_applies_to": wtf_constants["tuning_applies_to"],
            "finite_domain_percentile": wtf_constants["finite_domain_percentile"],
            "histogram_bin_count": wtf_constants["histogram_bin_count"],
            "histogram_scale": wtf_constants["histogram_scale"],
            "finite_token_budget": wtf_constants["finite_token_budget"],
            "fake_burst_probability": wtf_constants["fake_burst_probability"],
            "infinity_token_formulas": wtf_constants["infinity_token_formulas"],
            "tuning_transformation": wtf_constants["tuning_transformation"],
        }
        if any(fitting.get(key) != expected for key, expected in expected_constants.items()) or (
            fitting.get("bandwidth_threshold_bytes_per_second")
            != algorithm["global_bandwidth_threshold_bytes_per_second"]
        ):
            raise ValueError("WTF-PAD artifact disagrees with its algorithm receipt")
        populations = algorithm["populations"]
        assert isinstance(populations, Mapping)
        for direction in ("outgoing", "incoming"):
            direction_fit = parameter.get(direction)
            population = populations[direction]
            if not isinstance(direction_fit, Mapping) or not isinstance(population, Mapping):
                raise ValueError("WTF-PAD population binding is invalid")
            fit = direction_fit.get("fit")
            if not isinstance(fit, Mapping):
                raise ValueError("WTF-PAD direction fit is invalid")
            burst = fit.get("burst")
            gap = fit.get("gap")
            if (
                not isinstance(burst, Mapping)
                or not isinstance(gap, Mapping)
                or burst.get("sample_count") != population["between_burst_delays"]
                or gap.get("sample_count") != population["intra_burst_delays"]
                or burst.get("parameter_transformation") != wtf_constants["tuning_transformation"]
                or gap.get("parameter_transformation") != wtf_constants["gap_transformation"]
            ):
                raise ValueError("WTF-PAD population counts disagree with its artifact")
            for state in ("burst", "gap"):
                histogram = direction_fit.get(state)
                if (
                    not isinstance(histogram, Mapping)
                    or len(histogram.get("edges_us", [])) != wtf_constants["finite_bins"]
                ):
                    raise ValueError("WTF-PAD finite histogram domain is inconsistent")
        return
    if kind == "walkie_talkie":
        algorithm = _exact_mapping(
            receipt,
            {"algorithm", "candidate_pair_costs", "selected_pairs"},
            "Walkie-Talkie algorithm receipt",
        )
        profiles = parameter.get("profiles")
        selected = algorithm["selected_pairs"]
        wt_constants = constants["walkie_talkie"]
        assert isinstance(wt_constants, Mapping)
        if (
            not isinstance(profiles, list)
            or not isinstance(selected, list)
            or parameter.get("packet_size") != wt_constants["packet_size"]
            or parameter.get("cell_byte_domain") != wt_constants["cell_byte_domain"]
        ):
            raise ValueError("Walkie-Talkie artifact/receipt binding is invalid")
        artifact_selection = [
            {
                "real": profile.get("real"),
                "decoy": profile.get("decoy"),
                "matching_cost_packets": profile.get("matching_cost_packets"),
            }
            for profile in profiles
            if isinstance(profile, Mapping)
        ]
        if artifact_selection != selected:
            raise ValueError("Walkie-Talkie artifact disagrees with its selected-pair receipt")
        return
    raise ValueError(f"unsupported research parameter kind: {kind}")


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


def _validate_runtime_parameter(value: object, kind: str) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{kind} parameter artifact must be a JSON object")
    if (
        value.get("schema_version") != 2
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

    _validate_runtime_shape(value, kind, 1_200, Path(BUNDLE_FILES[kind]))


def _fitting_contract(workload_order: Sequence[str]) -> dict[str, object]:
    return {
        "contract_version": 1,
        "fitter_version": FITTER_VERSION,
        "parameter_schema_version": 2,
        "profile": "research-1200",
        "request_policies": ["as-defined", "half-duplex"],
        "visits_per_policy": 10,
        "workload_order": list(workload_order),
        "constants": {
            "traffic_morphing": {
                "buckets": [64, 150, 300, 500, 700, 900, 1_100, 1_200],
                "solver": {
                    "implementation": "scipy.optimize.linprog",
                    "method": "highs",
                    "options": {
                        "dual_feasibility_tolerance": 1e-9,
                        "ipm_optimality_tolerance": 1e-10,
                        "presolve": True,
                        "primal_feasibility_tolerance": 1e-9,
                    },
                },
                "objectives": ["l1", "expected-added-bytes", "row-major-lexicographic-minimum"],
                "conditional_flow_tie_break": "lexicographically-minimum-row-major",
                "assignment_tie_break": "lexical-target-vector",
                "mapping_constraint": "padding-only-upward-buckets",
            },
            "wtf_pad": {
                "bandwidth_window_packets": 2,
                "burst_threshold_method": "corpus-mean-bandwidth",
                "candidate_models": ["normal", "lognormal"],
                "fake_burst_probability": 0.9,
                "finite_bins": 19,
                "infinity_bins": 1,
                "finite_domain_percentile": 99.5,
                "finite_token_budget": 10_000,
                "histogram_bin_count": 20,
                "histogram_scale": "exponential",
                "infinity_token_rounding": "ceil",
                "infinity_token_formulas": {
                    "burst": "k_inf = p_inf / (1 - p_inf) * K",
                    "gap": "k_inf = (K - mean_burst_length + 1) / (mean_burst_length - 1)",
                },
                "minimum_state_population": 20,
                "token_allocation": "largest-remainder-leftmost-tie",
                "gap_transformation": "identity",
                "tuning_percentile": 0.5,
                "tuning_applies_to": "burst-histogram-only",
                "tuning_transformation": "paper-gaussian-percentile-shift-v1",
            },
            "walkie_talkie": {
                "cell_byte_domain": "http3-request-stream-offset.bytes",
                "envelope": "componentwise-max-corresponding-structure",
                "matching_tie_break": "lexical-pair-vector",
                "packet_size": 1_200,
                "pairing": "full-cohort-minimum-weight-perfect-matching",
                "pair_orientation": "lexical",
            },
        },
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
