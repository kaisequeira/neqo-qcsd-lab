"""Runtime parameter-bundle validation for parameterized QCSD defences.

The lab does not fit defence parameters.  It accepts an already prepared JSON
bundle, verifies the adjacent provenance receipt, copies both files into the
sample, and checks that the Neqo runner used the copied hash.  Keeping this
module generic prevents offline Traffic Morphing, WTF-PAD, and Walkie-Talkie
analysis code from becoming a second lab workflow.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .profiles import udp_payload_ceiling
from .seal import verify_checksum_seal
from .util import LAB_ROOT, load_json, sha256_file

PROVENANCE_SCHEMA_VERSION = 1
SEALED_INPUT_KIND = "sealed-completed-campaign"
SEALED_PARAMETER_INPUT_POLICY = "sealed-completed-campaigns"
REVIEWED_PARAMETER_INPUT_POLICY = "reviewed-engineering-fixture"
PARAMETER_ARTIFACT_NAME = "defense-parameters.json"
PARAMETER_PROVENANCE_ARTIFACT_NAME = "defense-parameters.provenance.json"
RUNNER_PACKET_HEADER = (
    "direction,monotonic_us,connection,observed_udp_length,scheduled_target,satisfaction,slot_id"
)
GENERATOR_BY_KIND = {
    "traffic_morphing": "morphing",
    "wtf_pad": "wtfpad",
    "walkie_talkie": "walkie-talkie",
}


@dataclass(frozen=True)
class ParameterArtifact:
    """One validated runtime parameter file and its provenance sidecar."""

    path: Path
    sha256: str
    provenance_path: Path
    provenance_sha256: str
    input_policy: str


def parameter_provenance_path(parameter: Path) -> Path:
    return parameter.with_suffix(parameter.suffix + ".provenance.json")


def validate_parameter_artifact(
    parameter_path: Path,
    *,
    provenance_path: Path | None = None,
    expected_parameter_name: str | None = None,
    expected_kind: str | None = None,
    allow_reviewed_fixture: bool = False,
    expected_input_policy: str | None = None,
    expected_qcsd_profile: str | None = None,
    expected_udp_payload_ceiling: int | None = None,
    expected_split_seed: int | None = None,
    expected_workloads: Mapping[str, tuple[str, str, int]] | None = None,
) -> ParameterArtifact:
    """Validate the immutable files needed to launch a parameterized defence."""

    parameter_path = parameter_path.resolve()
    provenance_path = (
        provenance_path.resolve()
        if provenance_path is not None
        else parameter_provenance_path(parameter_path)
    )
    if not parameter_path.is_file():
        raise ValueError(f"reactive defense parameter file does not exist: {parameter_path}")
    if not provenance_path.is_file():
        raise ValueError(
            "reactive defense parameter file requires an adjacent provenance sidecar: "
            f"{provenance_path}"
        )

    parameter_sha256 = sha256_file(parameter_path)
    parameter = _mapping(load_json(parameter_path), "reactive defense parameters")
    provenance = _mapping(load_json(provenance_path), "parameter provenance")
    if provenance.get("schema_version") != PROVENANCE_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported parameter provenance schema_version in {provenance_path}; "
            f"expected {PROVENANCE_SCHEMA_VERSION}"
        )
    recorded_file = _mapping(
        provenance.get("parameter_file"),
        "parameter provenance parameter_file metadata",
    )
    expected_name = expected_parameter_name or parameter_path.name
    if recorded_file.get("path") != expected_name:
        raise ValueError(
            f"parameter provenance filename does not match its parameter file: {provenance_path}"
        )
    if recorded_file.get("sha256") != parameter_sha256:
        raise ValueError(
            f"parameter provenance SHA-256 does not match its parameter file: {provenance_path}"
        )

    input_policy = provenance.get("input_policy")
    engineering_opt_in = provenance.get("unsealed_engineering_opt_in")
    generator = provenance.get("generator")
    if not isinstance(generator, str) or not generator:
        raise ValueError(f"parameter provenance has no generator identity: {provenance_path}")
    if input_policy == REVIEWED_PARAMETER_INPUT_POLICY:
        _validate_reviewed_fixture(
            parameter_path,
            provenance_path,
            allow_reviewed_fixture=allow_reviewed_fixture,
            copied_bundle=(
                expected_input_policy == REVIEWED_PARAMETER_INPUT_POLICY
                and expected_parameter_name is not None
                and parameter_path.name == PARAMETER_ARTIFACT_NAME
                and provenance_path.name == PARAMETER_PROVENANCE_ARTIFACT_NAME
            ),
        )
        if engineering_opt_in is not True:
            raise ValueError(
                "reviewed engineering parameter provenance must record its engineering opt-in"
            )
    elif input_policy == SEALED_PARAMETER_INPUT_POLICY:
        if allow_reviewed_fixture:
            raise ValueError(
                "allow_reviewed_fixture must not be set for sealed production parameters"
            )
        if engineering_opt_in is not False:
            raise ValueError(
                "sealed production parameter provenance must disable the engineering opt-in"
            )
        _validate_sealed_inputs(
            provenance.get("inputs"),
            provenance_path,
            expected_kind=expected_kind,
            expected_qcsd_profile=expected_qcsd_profile,
            expected_udp_payload_ceiling=expected_udp_payload_ceiling,
            expected_split_seed=expected_split_seed,
        )
        expected_generator = GENERATOR_BY_KIND.get(expected_kind or "")
        if expected_generator is not None and generator != expected_generator:
            raise ValueError(
                f"sealed parameter generator does not match {expected_kind}: {provenance_path}"
            )
        if not isinstance(provenance.get("analysis"), Mapping):
            raise ValueError(
                f"sealed parameter provenance lacks analysis metadata: {provenance_path}"
            )
    else:
        raise ValueError(
            "reactive campaign parameters require sealed production provenance or an "
            f"explicitly reviewed acceptance fixture; unsupported input_policy "
            f"{input_policy!r} in {provenance_path}"
        )
    if expected_input_policy is not None and input_policy != expected_input_policy:
        raise ValueError(f"parameter provenance input policy mismatch: {provenance_path}")

    _validate_runtime_shape(parameter, expected_kind, provenance_path)
    _validate_profile_binding(
        parameter,
        expected_qcsd_profile=expected_qcsd_profile,
        expected_udp_payload_ceiling=expected_udp_payload_ceiling,
        provenance_path=provenance_path,
    )
    _validate_workload_coverage(
        parameter,
        provenance,
        expected_kind=expected_kind,
        expected_workloads=expected_workloads,
        provenance_path=provenance_path,
    )
    return ParameterArtifact(
        path=parameter_path,
        sha256=parameter_sha256,
        provenance_path=provenance_path,
        provenance_sha256=sha256_file(provenance_path),
        input_policy=str(input_policy),
    )


def validate_sample_parameter_artifacts(
    sample: Path,
    defense: Mapping[str, Any],
    *,
    checksum_paths: set[str] | None = None,
    checksum_root: Path | None = None,
    expected_runtime_path: Path | None = None,
    expected_workload_id: str | None = None,
    expected_qcsd_profile: str | None = None,
    expected_udp_payload_ceiling: int | None = None,
    expected_split_seed: int | None = None,
    expected_workloads: Mapping[str, tuple[str, str, int]] | None = None,
) -> ParameterArtifact:
    """Validate a copied bundle and the runner receipt for one sample."""

    parameter_path = sample / "neqo" / PARAMETER_ARTIFACT_NAME
    provenance_path = sample / "neqo" / PARAMETER_PROVENANCE_ARTIFACT_NAME
    policy = defense.get("parameters_input_policy")
    artifact = validate_parameter_artifact(
        parameter_path,
        provenance_path=provenance_path,
        expected_parameter_name=Path(str(defense.get("parameters", ""))).name,
        expected_kind=str(defense.get("kind", "")),
        allow_reviewed_fixture=policy == REVIEWED_PARAMETER_INPUT_POLICY,
        expected_input_policy=str(policy) if isinstance(policy, str) else None,
        expected_qcsd_profile=expected_qcsd_profile,
        expected_udp_payload_ceiling=expected_udp_payload_ceiling,
        expected_split_seed=expected_split_seed,
        expected_workloads=expected_workloads,
    )
    if artifact.sha256 != defense.get("parameters_sha256"):
        raise ValueError(f"sample defense parameter hash mismatch: {sample}")
    if artifact.provenance_sha256 != defense.get("parameters_provenance_sha256"):
        raise ValueError(f"sample defense parameter provenance hash mismatch: {sample}")
    if checksum_paths is not None:
        if checksum_root is None:
            raise ValueError("checksum_root is required with checksum_paths")
        for path in (artifact.path, artifact.provenance_path):
            relative = path.relative_to(checksum_root).as_posix()
            if relative not in checksum_paths:
                raise ValueError(
                    f"sample defense parameter artifact is not checksum-sealed: {relative}"
                )

    try:
        run_data = _mapping(load_json(sample / "neqo/run.json"), "runner metadata")
    except (OSError, ValueError) as error:
        raise ValueError(f"sample defense parameter run binding is unreadable: {sample}") from error
    validate_run_parameter_binding(
        run_data,
        kind=str(defense.get("kind")),
        sha256=artifact.sha256,
        expected_path=expected_runtime_path,
        expected_workload_id=expected_workload_id,
    )
    return artifact


def validate_run_parameter_binding(
    run_data: Mapping[str, Any],
    *,
    kind: str,
    sha256: str | None,
    expected_path: Path | None = None,
    expected_workload_id: str | None = None,
) -> None:
    """Validate the runner's immutable parameter kind/hash/path receipt."""

    parameter = run_data.get("defense_parameters")
    if (
        not isinstance(parameter, Mapping)
        or parameter.get("kind") != kind
        or parameter.get("sha256") != sha256
        or (expected_path is not None and parameter.get("path") != str(expected_path))
    ):
        raise ValueError("sample defense parameter run binding mismatch")
    if expected_workload_id is not None:
        resolved = run_data.get("resolved_configuration")
        resolved_defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
        if (
            not isinstance(resolved_defense, Mapping)
            or resolved_defense.get("workload_id") != expected_workload_id
        ):
            raise ValueError("sample defense workload run binding mismatch")


def _validate_reviewed_fixture(
    parameter_path: Path,
    provenance_path: Path,
    *,
    allow_reviewed_fixture: bool,
    copied_bundle: bool,
) -> None:
    if not allow_reviewed_fixture:
        raise ValueError(
            "reviewed engineering parameter fixtures require allow_reviewed_fixture: true"
        )
    fixture_root = (LAB_ROOT / "config/defense-params").resolve()
    if not copied_bundle and (
        not parameter_path.is_relative_to(fixture_root)
        or not provenance_path.is_relative_to(fixture_root)
    ):
        raise ValueError(
            f"reviewed engineering parameter fixtures must be checked in under {fixture_root}"
        )


def _validate_sealed_inputs(
    raw_inputs: Any,
    provenance_path: Path,
    *,
    expected_kind: str | None,
    expected_qcsd_profile: str | None,
    expected_udp_payload_ceiling: int | None,
    expected_split_seed: int | None,
) -> None:
    if not isinstance(raw_inputs, Mapping) or not raw_inputs:
        raise ValueError(
            f"sealed parameter provenance must contain input evidence: {provenance_path}"
        )
    if any(not isinstance(group, list) or not group for group in raw_inputs.values()):
        raise ValueError(f"sealed parameter provenance inputs are malformed: {provenance_path}")
    evidence = [item for group in raw_inputs.values() for item in group]
    if any(not isinstance(item, Mapping) for item in evidence):
        raise ValueError(f"sealed parameter provenance inputs are malformed: {provenance_path}")
    _validate_defense_input_policy(raw_inputs, expected_kind, provenance_path)
    identities = [
        (
            str(item.get("campaign_root")),
            str(item.get("workload_id")),
            str(item.get("visit_id")),
        )
        for item in evidence
    ]
    paths = [str(item.get("path")) for item in evidence]
    if len(identities) != len(set(identities)) or len(paths) != len(set(paths)):
        raise ValueError(
            f"sealed parameter provenance contains duplicate inputs: {provenance_path}"
        )
    contracts = {
        (item.get("split_seed"), item.get("qcsd_profile"), item.get("udp_payload_ceiling"))
        for item in evidence
    }
    if len(contracts) != 1:
        raise ValueError(f"sealed parameter provenance mixes capture contracts: {provenance_path}")

    campaigns: dict[Path, tuple[dict[str, str], dict[str, Any], list[dict[str, Any]]]] = {}
    selected_populations: dict[tuple[Path, str], set[str]] = {}
    for item in evidence:
        _validate_evidence_domain(
            item,
            provenance_path,
            expected_qcsd_profile=expected_qcsd_profile,
            expected_udp_payload_ceiling=expected_udp_payload_ceiling,
            expected_split_seed=expected_split_seed,
        )
        root = Path(str(item["campaign_root"])).resolve()
        campaign_data = campaigns.get(root)
        if campaign_data is None:
            campaign_data = _load_sealed_campaign(root, item, provenance_path)
            campaigns[root] = campaign_data
        checksums, campaign, samples = campaign_data
        if sha256_file(root / "campaign.json") != item.get("campaign_sha256") or sha256_file(
            root / "SHA256SUMS"
        ) != item.get("seal_sha256"):
            raise ValueError(
                f"sealed parameter provenance campaign digest is inconsistent: {provenance_path}"
            )
        _validate_evidence_file(item, root, checksums, provenance_path)
        sample = _sample_for_evidence(item, root, samples, provenance_path)
        _validate_evidence_sample(item, sample, campaign, provenance_path)
        workload_id = str(item["workload_id"])
        selected_populations.setdefault((root, workload_id), set()).add(str(item["visit_id"]))

    for (root, workload_id), observed in selected_populations.items():
        _checksums, _campaign, samples = campaigns[root]
        expected = {
            str(sample.get("visit_id"))
            for sample in samples
            if sample.get("workload_id") == workload_id
            and sample.get("state") == "captured"
            and sample.get("eligible", sample.get("classifier_eligible")) is True
            and sample.get("fidelity_eligible") is True
            and sample.get("split") == "train"
            and _is_undefended(sample)
        }
        declared = {
            str(visit)
            for item in evidence
            if Path(str(item["campaign_root"])).resolve() == root
            and item.get("workload_id") == workload_id
            for visit in item.get("eligible_train_visit_ids", [])
        }
        if not expected or observed != expected or declared != expected:
            raise ValueError(
                "sealed parameter provenance does not contain the complete eligible train "
                f"population for {workload_id!r}: {provenance_path}"
            )


def _validate_defense_input_policy(
    raw_inputs: Mapping[str, Any],
    expected_kind: str | None,
    provenance_path: Path,
) -> None:
    expected_groups = {
        "traffic_morphing": {"source", "target"},
        "wtf_pad": {"traces"},
        "walkie_talkie": {"real", "decoy"},
    }.get(expected_kind or "")
    if expected_groups is None:
        return
    if set(raw_inputs) != expected_groups:
        raise ValueError(
            f"sealed {expected_kind} provenance has the wrong input groups: {provenance_path}"
        )

    def group(name: str) -> list[Mapping[str, Any]]:
        return [item for item in raw_inputs[name] if isinstance(item, Mapping)]

    if expected_kind == "traffic_morphing":
        source = group("source")
        target = group("target")
        if any(item.get("role") != "monitored" for item in source) or any(
            item.get("role") != "unmonitored" for item in target
        ):
            raise ValueError(
                f"sealed Traffic Morphing source/target roles are invalid: {provenance_path}"
            )
        if {item.get("source_manifest_sha256") for item in source} & {
            item.get("source_manifest_sha256") for item in target
        }:
            raise ValueError(
                f"sealed Traffic Morphing source and target evidence overlap: {provenance_path}"
            )
    elif expected_kind == "wtf_pad":
        visits_by_class: dict[str, set[str]] = {}
        for item in group("traces"):
            class_label = item.get("class_label")
            sample_id = item.get("sample_id")
            if isinstance(class_label, str) and isinstance(sample_id, str):
                visits_by_class.setdefault(class_label, set()).add(sample_id)
        if len(visits_by_class) < 2 or any(len(visits) < 2 for visits in visits_by_class.values()):
            raise ValueError(
                f"sealed WTF-PAD evidence requires two classes and two visits each: "
                f"{provenance_path}"
            )
    else:
        real = group("real")
        decoy = group("decoy")
        if any(
            item.get("role") != "monitored" or item.get("request_policy") != "half-duplex"
            for item in real
        ) or any(
            item.get("role") != "unmonitored" or item.get("request_policy") != "half-duplex"
            for item in decoy
        ):
            raise ValueError(
                f"sealed Walkie-Talkie roles/request policy are invalid: {provenance_path}"
            )
        if {item.get("source_manifest_sha256") for item in real} & {
            item.get("source_manifest_sha256") for item in decoy
        }:
            raise ValueError(
                f"sealed Walkie-Talkie real and decoy evidence overlap: {provenance_path}"
            )
        for item in (*real, *decoy):
            if (
                not isinstance(item.get("events_path"), str)
                or not _is_digest(item.get("events_sha256"))
                or item.get("fitting_trace_format") != "walkie-talkie-causal-application-batches-v2"
                or item.get("fitting_length_basis") != "http3-request-stream-offset.bytes"
            ):
                raise ValueError(
                    f"sealed Walkie-Talkie causal event evidence is incomplete: {provenance_path}"
                )


def _validate_evidence_domain(
    item: Mapping[str, Any],
    provenance_path: Path,
    *,
    expected_qcsd_profile: str | None,
    expected_udp_payload_ceiling: int | None,
    expected_split_seed: int | None,
) -> None:
    required = {
        "kind",
        "path",
        "sha256",
        "campaign_root",
        "campaign_name",
        "campaign_sha256",
        "seal_sha256",
        "campaign_stage",
        "study_id",
        "visit_id",
        "split_group_id",
        "sample_id",
        "sample_path",
        "workload_id",
        "source_manifest_sha256",
        "repetition",
        "class_label",
        "role",
        "split",
        "request_policy",
        "qcsd_profile",
        "udp_payload_ceiling",
        "split_seed",
        "eligible_train_visit_ids",
        "defense",
        "runtime_kind",
        "view",
        "trace_format",
        "length_basis",
        "run_path",
        "run_sha256",
        "application_window_us",
    }
    if required - set(item):
        raise ValueError(f"sealed parameter provenance input is incomplete: {provenance_path}")
    if (
        item.get("kind") != SEALED_INPUT_KIND
        or item.get("campaign_stage") != "parameter-fitting"
        or item.get("split") != "train"
        or item.get("role") not in {"monitored", "unmonitored"}
        or not _is_undefended(item)
        or item.get("view") != "runner"
        or item.get("trace_format") != "runner-udp-payload"
        or item.get("length_basis") != "udp.payload"
        or item.get("request_policy") not in {"as-defined", "half-duplex"}
        or item.get("qcsd_profile") not in {"live", "published"}
        or item.get("udp_payload_ceiling") != udp_payload_ceiling(item.get("qcsd_profile"))
    ):
        raise ValueError(
            f"sealed parameter provenance input has the wrong evidence domain: {provenance_path}"
        )
    for key in (
        "sha256",
        "campaign_sha256",
        "seal_sha256",
        "study_id",
        "visit_id",
        "split_group_id",
        "sample_id",
        "source_manifest_sha256",
        "run_sha256",
    ):
        if not _is_digest(item.get(key)):
            raise ValueError(
                f"sealed parameter provenance input has an invalid {key}: {provenance_path}"
            )
    if type(item.get("split_seed")) is not int or item["split_seed"] < 0:
        raise ValueError(f"sealed parameter provenance split seed is invalid: {provenance_path}")
    if type(item.get("repetition")) is not int or item["repetition"] < 0:
        raise ValueError(f"sealed parameter provenance repetition is invalid: {provenance_path}")
    population = item.get("eligible_train_visit_ids")
    if (
        not isinstance(population, list)
        or not population
        or population != sorted(set(population))
        or any(not _is_digest(visit) for visit in population)
        or item.get("visit_id") not in population
    ):
        raise ValueError(
            f"sealed parameter provenance train population is invalid: {provenance_path}"
        )
    window = item.get("application_window_us")
    if (
        not isinstance(window, list)
        or len(window) != 2
        or any(type(value) is not int or value < 0 for value in window)
        or window[1] < window[0]
    ):
        raise ValueError(
            f"sealed parameter provenance application window is invalid: {provenance_path}"
        )
    if expected_qcsd_profile is not None and item.get("qcsd_profile") != expected_qcsd_profile:
        raise ValueError(
            f"parameter evidence QCSD profile does not match campaign: {provenance_path}"
        )
    if (
        expected_udp_payload_ceiling is not None
        and item.get("udp_payload_ceiling") != expected_udp_payload_ceiling
    ):
        raise ValueError(
            f"parameter evidence UDP ceiling does not match campaign: {provenance_path}"
        )
    if expected_split_seed is not None and item.get("split_seed") != expected_split_seed:
        raise ValueError(
            f"parameter evidence split seed does not match campaign: {provenance_path}"
        )


def _load_sealed_campaign(
    root: Path,
    item: Mapping[str, Any],
    provenance_path: Path,
) -> tuple[dict[str, str], dict[str, Any], list[dict[str, Any]]]:
    try:
        checksums = verify_checksum_seal(root)
        campaign = _mapping(load_json(root / "campaign.json"), "sealed campaign receipt")
        samples = [
            value
            for value in (
                json.loads(line)
                for line in (root / "samples.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            )
            if isinstance(value, dict)
        ]
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ValueError(
            f"sealed parameter provenance input campaign cannot be verified: {provenance_path}"
        ) from error
    state = campaign.get("campaign")
    summary = campaign.get("summary")
    configuration = campaign.get("configuration")
    if (
        not isinstance(state, Mapping)
        or state.get("status") != "complete"
        or state.get("stage") != "parameter-fitting"
        or not isinstance(summary, Mapping)
        or summary.get("passed") is not True
        or not isinstance(configuration, Mapping)
        or sha256_file(root / "campaign.json") != item.get("campaign_sha256")
        or sha256_file(root / "SHA256SUMS") != item.get("seal_sha256")
    ):
        raise ValueError(
            f"sealed parameter provenance input campaign is not complete: {provenance_path}"
        )
    if not samples:
        raise ValueError(f"sealed parameter provenance campaign has no samples: {provenance_path}")
    return checksums, campaign, samples


def _validate_evidence_file(
    item: Mapping[str, Any],
    root: Path,
    checksums: Mapping[str, str],
    provenance_path: Path,
) -> None:
    trace = Path(str(item["path"])).resolve()
    if not trace.is_relative_to(root):
        raise ValueError(f"sealed parameter trace escapes its campaign: {provenance_path}")
    relative = trace.relative_to(root).as_posix()
    if trace.name != "packets.csv" or trace.parent.name != "neqo":
        raise ValueError(f"sealed parameter input is not a runner packet trace: {provenance_path}")
    if checksums.get(relative) != item.get("sha256"):
        raise ValueError(f"sealed parameter trace is not checksum-bound: {provenance_path}")
    try:
        header = trace.open(encoding="utf-8").readline().rstrip("\r\n")
    except OSError as error:
        raise ValueError(f"sealed parameter trace cannot be read: {provenance_path}") from error
    if header != RUNNER_PACKET_HEADER:
        raise ValueError(f"sealed parameter input has the wrong packet domain: {provenance_path}")
    run_path = item.get("run_path")
    run_sha256 = item.get("run_sha256")
    if (
        not isinstance(run_path, str)
        or not _is_digest(run_sha256)
        or checksums.get(run_path) != run_sha256
    ):
        raise ValueError(
            f"sealed parameter runner receipt is not checksum-bound: {provenance_path}"
        )
    expected_run = trace.parent / "run.json"
    if (root / run_path).resolve() != expected_run.resolve():
        raise ValueError(f"sealed parameter runner receipt path is invalid: {provenance_path}")
    run = _mapping(load_json(root / run_path), "sealed parameter runner receipt")
    start_ns = run.get("defense_start_monotonic_ns")
    completion_ns = run.get("application_completion_monotonic_ns")
    resolved = run.get("resolved_configuration")
    resolved_defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    if (
        type(start_ns) is not int
        or type(completion_ns) is not int
        or completion_ns < start_ns
        or run.get("completion_status") != "complete"
        or run.get("request_policy") != item.get("request_policy")
        or not isinstance(resolved_defense, Mapping)
        or resolved_defense.get("kind") != "none"
        or item.get("application_window_us") != [start_ns // 1_000, completion_ns // 1_000]
    ):
        raise ValueError(f"sealed parameter application window is not run-bound: {provenance_path}")
    events_path = item.get("events_path")
    events_sha256 = item.get("events_sha256")
    if events_path is not None or events_sha256 is not None:
        events = Path(str(events_path)).resolve()
        if (
            events != (trace.parent / "events.csv").resolve()
            or not _is_digest(events_sha256)
            or not events.is_relative_to(root)
            or checksums.get(events.relative_to(root).as_posix()) != events_sha256
        ):
            raise ValueError(
                f"sealed parameter event evidence is not checksum-bound: {provenance_path}"
            )


def _sample_for_evidence(
    item: Mapping[str, Any],
    root: Path,
    samples: list[dict[str, Any]],
    provenance_path: Path,
) -> dict[str, Any]:
    sample_path = item.get("sample_path")
    if not isinstance(sample_path, str):
        raise ValueError(f"sealed parameter input lacks a sample path: {provenance_path}")
    candidate = Path(sample_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"sealed parameter sample path is unsafe: {provenance_path}")
    trace = Path(str(item["path"])).resolve()
    if trace != (root / candidate / "neqo/packets.csv").resolve():
        raise ValueError(f"sealed parameter trace/sample binding is invalid: {provenance_path}")
    matches = [sample for sample in samples if sample.get("path") == sample_path]
    if len(matches) != 1:
        raise ValueError(f"sealed parameter input is not uniquely indexed: {provenance_path}")
    return matches[0]


def _validate_evidence_sample(
    item: Mapping[str, Any],
    sample: Mapping[str, Any],
    campaign: Mapping[str, Any],
    provenance_path: Path,
) -> None:
    configuration = campaign.get("configuration")
    state = campaign.get("campaign")
    workloads = configuration.get("workloads") if isinstance(configuration, Mapping) else None
    capture = configuration.get("capture") if isinstance(configuration, Mapping) else None
    expected = {
        "campaign_name": state.get("name") if isinstance(state, Mapping) else None,
        "study_id": configuration.get("study_id") if isinstance(configuration, Mapping) else None,
        "visit_id": sample.get("visit_id"),
        "split_group_id": sample.get("split_group_id"),
        "sample_id": sample.get("sample_id"),
        "workload_id": sample.get("workload_id"),
        "source_manifest_sha256": sample.get("source_manifest_sha256"),
        "repetition": sample.get("repetition"),
        "class_label": sample.get("class_label"),
        "role": sample.get("role"),
        "split": sample.get("split"),
        "request_policy": (
            workloads.get("request_policy") if isinstance(workloads, Mapping) else None
        ),
        "defense": sample.get("defense"),
        "runtime_kind": sample.get("runtime_kind"),
        "split_seed": configuration.get("seed") if isinstance(configuration, Mapping) else None,
        "qcsd_profile": (
            configuration.get("qcsd_profile") if isinstance(configuration, Mapping) else None
        ),
        "udp_payload_ceiling": (
            capture.get("udp_payload_ceiling") if isinstance(capture, Mapping) else None
        ),
    }
    if any(item.get(key) != value for key, value in expected.items()) or (
        sample.get("state") != "captured"
        or sample.get("eligible", sample.get("classifier_eligible")) is not True
        or sample.get("fidelity_eligible") is not True
    ):
        raise ValueError(
            f"sealed parameter input no longer matches its campaign index: {provenance_path}"
        )


def _validate_runtime_shape(
    parameter: Mapping[str, Any],
    expected_kind: str | None,
    provenance_path: Path,
) -> None:
    if expected_kind is None:
        return
    required = {
        "traffic_morphing": {"buckets", "udp_payload_ceiling", "profiles"},
        "wtf_pad": {"outgoing", "incoming", "fitting"},
        "walkie_talkie": {"packet_size", "matching_algorithm", "profiles"},
    }.get(expected_kind)
    # Campaign loading rejects parameter files for every other kind.  Dataset
    # validation still accepts old synthetic fixtures that exercised only the
    # copied-file/checksum contract with a placeholder runtime kind.
    if required is None:
        return
    if parameter.get("schema_version") != 2 or required - set(parameter):
        raise ValueError(
            f"{expected_kind} parameter file has the wrong runtime schema: {provenance_path}"
        )
    if (
        parameter.get("adaptation") != "qcsd-client-only"
        or parameter.get("paper_equivalent") is not False
    ):
        raise ValueError(
            f"{expected_kind} parameter file lacks the client-only adaptation declaration: "
            f"{provenance_path}"
        )


def _validate_profile_binding(
    parameter: Mapping[str, Any],
    *,
    expected_qcsd_profile: str | None,
    expected_udp_payload_ceiling: int | None,
    provenance_path: Path,
) -> None:
    if expected_qcsd_profile is not None:
        expected_for_profile = udp_payload_ceiling(expected_qcsd_profile)
        if expected_for_profile is None:
            raise ValueError(f"unsupported expected QCSD profile: {expected_qcsd_profile}")
        if (
            expected_udp_payload_ceiling is not None
            and expected_udp_payload_ceiling != expected_for_profile
        ):
            raise ValueError("expected QCSD profile and UDP ceiling disagree")
    if expected_udp_payload_ceiling is None:
        return
    if (
        "udp_payload_ceiling" in parameter
        and parameter.get("udp_payload_ceiling") != expected_udp_payload_ceiling
    ):
        raise ValueError(f"Traffic Morphing UDP ceiling does not match campaign: {provenance_path}")
    if "packet_size" in parameter and parameter.get("packet_size") != expected_udp_payload_ceiling:
        raise ValueError(f"Walkie-Talkie packet size does not match campaign: {provenance_path}")


def _validate_workload_coverage(
    parameter: Mapping[str, Any],
    provenance: Mapping[str, Any],
    *,
    expected_kind: str | None,
    expected_workloads: Mapping[str, tuple[str, str, int]] | None,
    provenance_path: Path,
) -> None:
    if expected_workloads is None or expected_kind == "wtf_pad":
        return
    profiles = parameter.get("profiles")
    if not isinstance(profiles, list) or any(not isinstance(item, Mapping) for item in profiles):
        raise ValueError(f"runtime workload profiles are malformed: {provenance_path}")
    if expected_kind == "traffic_morphing":
        observed = [item.get("source") for item in profiles]
        expected = set(expected_workloads)
    elif expected_kind == "walkie_talkie":
        real = [item.get("real") for item in profiles]
        decoy = [item.get("decoy") for item in profiles]
        observed = [*real, *decoy]
        expected = set(expected_workloads)
        expected_real = {
            workload
            for workload, (_digest, role, _visits) in expected_workloads.items()
            if role == "monitored"
        }
        expected_decoy = {
            workload
            for workload, (_digest, role, _visits) in expected_workloads.items()
            if role == "unmonitored"
        }
        if set(real) != expected_real or set(decoy) != expected_decoy:
            raise ValueError(
                "Walkie-Talkie profiles do not match the research workload roles: "
                f"{provenance_path}"
            )
    else:
        return
    if (
        any(not isinstance(value, str) or not value for value in observed)
        or len(observed) != len(set(observed))
        or set(observed) != expected
    ):
        raise ValueError(
            f"runtime parameter profiles must cover every research workload once: {provenance_path}"
        )

    inputs = provenance.get("inputs")
    if not isinstance(inputs, Mapping):
        raise ValueError(f"parameter provenance inputs are malformed: {provenance_path}")
    for workload, (digest, role, _visits) in expected_workloads.items():
        if expected_kind == "traffic_morphing":
            group = inputs.get("source")
        else:
            group = inputs.get("real" if role == "monitored" else "decoy")
        evidence = (
            [item for item in group if isinstance(item, Mapping)] if isinstance(group, list) else []
        )
        if not any(
            item.get("workload_id") == workload
            and item.get("source_manifest_sha256") == digest
            and item.get("role") == role
            for item in evidence
        ):
            raise ValueError(
                f"parameter evidence does not bind research workload {workload!r}: "
                f"{provenance_path}"
            )


def _is_undefended(value: Mapping[str, Any]) -> bool:
    return value.get("runtime_kind") == "none" or (
        value.get("runtime_kind") is None and value.get("defense") in {"none", "undefended"}
    )


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value
