from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .capture import (
    extract_trace,
    offload_evidence_is_valid,
    read_normalized_trace,
    udp_ceiling_evidence,
)
from .defenses import DEFENSE_ORDER, is_canonical_defense_suite
from .fidelity import validate_fidelity_record
from .parameters import validate_sample_parameter_artifacts
from .profiles import UDP_PAYLOAD_CEILING_BY_PROFILE
from .seal import verify_checksum_seal
from .util import (
    atomic_json,
    atomic_text,
    load_json,
    padding_event_guard_triggered,
    response_signature,
    run,
    sha256_file,
)

REQUIRED_ROOT_FILES = {
    "SHA256SUMS",
    "campaign.json",
    "classifier.json",
    "classifier-samples.jsonl",
    "dataset.json",
    "samples.jsonl",
    "splits.json",
    "metrics.csv",
    "projection.json",
    "report.html",
}
DIRECT_VIEW_ID = "direct-quic"
DIRECT_CAPTURE_PATH = "captures/direct-quic.pcapng"
DIRECT_TRACE_PATH = "traces/direct-quic.csv"
DIRECT_VIEW_CONTRACT = {
    "id": DIRECT_VIEW_ID,
    "kind": DIRECT_VIEW_ID,
    "interface": "eth0",
    "link_type": "Ethernet",
    "length_basis": "frame.len",
    "primary": True,
}
CLASSIC_FIGURE_FILES = {
    "trace-comparison.pdf",
    "trace-comparison.svg",
    "trace-comparison-2.pdf",
    "trace-comparison-2.svg",
}
CLASSIFIER_RECORD_KEYS = {
    "sample_id",
    "visit_id",
    "split_group_id",
    "workload_id",
    "class_label",
    "role",
    "split",
    "defense",
    "eligibility",
    "sequence",
}
CLASSIFIER_FEATURE_CONTRACT = {
    "sequence": ["delta_time_ns", "direction", "frame_len"],
    "direction": {"client_egress": 1, "client_ingress": -1},
    "first_delta_time_ns": 0,
    "variable_length": True,
    "normalization": "none",
    "batch_padding": "mask-required",
    "defense_tail": "retained",
    "model_features": ["sequence"],
    "forbidden_model_features": [
        "artifact paths",
        "defense",
        "endpoint tuples",
        "schedule",
        "seed",
        "application completion",
        "diagnostics",
        "normalized trace duration",
    ],
}
CLASSIFIER_SPLIT_CONTRACT = {
    "unit": "split_group_id",
    "ratios": {"train": 0.70, "validation": 0.15, "test": 0.15},
    "grouping": (
        "all aliases, scopes, request policies, defenses, retries, and derivatives of one "
        "source-manifest/repetition group share one split"
    ),
}
CLASSIFIER_ELIGIBILITY_CONTRACT = {
    "sample": "valid direct trace, response equality, and valid defense termination",
    "fidelity": "sample-eligible and all declared realization gates pass",
    "seven_way_pair": (
        "all seven canonical defenses are sample- and fidelity-eligible for the visit"
    ),
    "research": "research-stage fidelity-eligible sample in a complete seven-way pair",
    "headline_population": "intersection of complete seven-way pairs",
}


class DatasetValidationError(RuntimeError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"dataset validation failed with {len(errors)} error(s)")


def load_sample_index(root: Path) -> list[dict[str, Any]]:
    records = []
    with (root / "samples.jsonl").open(encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid samples.jsonl line {number}: {error}") from error
            if not isinstance(record, dict):
                raise ValueError(f"samples.jsonl line {number} is not an object")
            records.append(record)
    return records


def load_classifier_sample_index(root: Path) -> list[dict[str, Any]]:
    records = []
    with (root / "classifier-samples.jsonl").open(encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"classifier-samples.jsonl line {number} is invalid: {error}"
                ) from error
            if not isinstance(record, dict):
                raise ValueError(f"classifier-samples.jsonl line {number} is not an object")
            records.append(record)
    return records


def _classifier_contract(
    stage: str,
    configured_defense_entries: list[dict[str, Any]],
    *,
    record_count: int,
    complete_pair_count: int,
) -> dict[str, Any]:
    defenses = [
        str(item["name"])
        for item in configured_defense_entries
        if isinstance(item.get("name"), str)
    ]
    return {
        "schema_version": 2,
        "task": "website-fingerprinting",
        "training_unit": "one independent workload classifier per defense",
        "physical_layout": "workload/paired-visit/defense",
        "stage": stage,
        "feature_contract": CLASSIFIER_FEATURE_CONTRACT,
        "splits": CLASSIFIER_SPLIT_CONTRACT,
        "eligibility": CLASSIFIER_ELIGIBILITY_CONTRACT,
        "defenses": defenses,
        "defense_runtime_kinds": {
            str(item["name"]): item.get("kind")
            for item in configured_defense_entries
            if isinstance(item.get("name"), str)
        },
        "baseline_defense": next(
            (
                item.get("name")
                for item in configured_defense_entries
                if item.get("baseline") is True
            ),
            None,
        ),
        "canonical_seven_defense_suite": is_canonical_defense_suite(configured_defense_entries),
        "record_count": record_count,
        "complete_pair_count": complete_pair_count,
        "acceptance_only": stage != "research",
        "samples": "classifier-samples.jsonl",
    }


def write_classifier_indexes(root: Path) -> tuple[Path, Path]:
    """Write leakage-safe index views over canonical direct sequences.

    Selection metadata remains in the index so a trainer can choose one
    defence and split.  The declared model feature surface is only the inline
    variable-length ``(delta_time_ns, direction, frame_len)`` sequence.
    """

    root = root.resolve()
    campaign = load_json(root / "campaign.json")
    samples = load_sample_index(root)
    configured_defense_entries = [
        item
        for item in campaign.get("configuration", {}).get("defenses", [])
        if isinstance(item, dict)
    ]
    defenses = [
        item.get("name") for item in configured_defense_entries if isinstance(item.get("name"), str)
    ]
    canonical_suite = is_canonical_defense_suite(configured_defense_entries)
    by_visit: dict[str, list[dict[str, Any]]] = {}
    for sample in samples:
        by_visit.setdefault(str(sample.get("visit_id")), []).append(sample)
    pair_eligible = {
        visit_id: canonical_suite
        and len(members) == len(DEFENSE_ORDER)
        and {member.get("defense") for member in members} == set(defenses)
        and all(_eligible(member) and member.get("fidelity_eligible") is True for member in members)
        for visit_id, members in by_visit.items()
    }
    stage = campaign.get("campaign", {}).get("stage", "acceptance")
    records: list[dict[str, Any]] = []
    for sample in samples:
        trace = root / str(sample.get("path", "")) / DIRECT_TRACE_PATH
        sequence = _classifier_sequence(trace) if trace.is_file() else []
        visit_id = str(sample.get("visit_id"))
        sample_eligible = bool(_eligible(sample) and sequence)
        fidelity_eligible = bool(sample_eligible and sample.get("fidelity_eligible") is True)
        complete_pair = bool(pair_eligible.get(visit_id))
        records.append(
            {
                "sample_id": sample.get("sample_id"),
                "visit_id": visit_id,
                "split_group_id": sample.get("split_group_id"),
                "workload_id": sample.get("workload_id"),
                "class_label": sample.get("class_label"),
                "role": sample.get("role"),
                "split": sample.get("split"),
                "defense": sample.get("defense"),
                "eligibility": {
                    "sample": sample_eligible,
                    "fidelity": fidelity_eligible,
                    "seven_way_pair": complete_pair,
                    "research": bool(stage == "research" and fidelity_eligible and complete_pair),
                },
                "sequence": sequence,
            }
        )
    records.sort(
        key=lambda item: (
            str(item["workload_id"]),
            str(item["visit_id"]),
            defenses.index(item["defense"]) if item["defense"] in defenses else len(defenses),
        )
    )
    samples_path = root / "classifier-samples.jsonl"
    atomic_text(
        samples_path,
        "".join(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n" for record in records
        ),
    )
    pair_count = sum(pair_eligible.values())
    contract = _classifier_contract(
        stage,
        configured_defense_entries,
        record_count=len(records),
        complete_pair_count=pair_count,
    )
    contract_path = root / "classifier.json"
    atomic_json(contract_path, contract)
    return contract_path, samples_path


def _classifier_sequence(path: Path) -> list[list[int]]:
    rows = read_normalized_trace(path)
    sequence: list[list[int]] = []
    previous_time = 0
    for index, row in enumerate(rows):
        relative_time = int(row["relative_time_ns"])
        if relative_time < previous_time:
            raise ValueError(f"classifier trace timestamps are not monotonic: {path}")
        direction = 1 if row["direction"] == "outgoing" else -1
        frame_len = int(row["length_bytes"])
        sequence.append(
            [
                0 if index == 0 else relative_time - previous_time,
                direction,
                frame_len,
            ]
        )
        previous_time = relative_time
    return sequence


def _validate_classifier_indexes(
    root: Path,
    contract: Any,
    records: list[dict[str, Any]],
    samples: list[dict[str, Any]],
    configured_defense_entries: list[dict[str, Any]],
    campaign_stage: str,
    errors: list[str],
) -> None:
    if not isinstance(contract, dict) or contract.get("schema_version") != 2:
        errors.append("classifier.json has an unsupported schema")
        return

    by_id = {str(sample.get("sample_id")): sample for sample in samples}
    record_ids = [str(record.get("sample_id")) for record in records]
    if len(record_ids) != len(set(record_ids)) or set(record_ids) != set(by_id):
        errors.append("classifier sample IDs do not exactly match samples.jsonl")
        return

    configured_defenses = [
        str(item["name"])
        for item in configured_defense_entries
        if isinstance(item.get("name"), str)
    ]
    canonical_suite = is_canonical_defense_suite(configured_defense_entries)
    if campaign_stage == "research" and not canonical_suite:
        errors.append("research classifier data requires the canonical seven-defense suite")

    members_by_visit: dict[str, list[dict[str, Any]]] = {}
    for sample in samples:
        members_by_visit.setdefault(str(sample.get("visit_id")), []).append(sample)
    pair_eligible = {
        visit_id: canonical_suite
        and len(members) == len(DEFENSE_ORDER)
        and {member.get("defense") for member in members} == set(configured_defenses)
        and all(_eligible(member) and member.get("fidelity_eligible") is True for member in members)
        for visit_id, members in members_by_visit.items()
    }
    expected_contract = _classifier_contract(
        campaign_stage,
        configured_defense_entries,
        record_count=len(records),
        complete_pair_count=sum(pair_eligible.values()),
    )
    if contract != expected_contract:
        errors.append("classifier.json does not exactly match the generated classifier contract")

    for record in records:
        sample_id = str(record.get("sample_id"))
        sample = by_id[sample_id]
        if set(record) != CLASSIFIER_RECORD_KEYS:
            errors.append(f"classifier record schema is not exact: {sample_id}")
        expected_metadata = {
            "visit_id": sample.get("visit_id"),
            "split_group_id": sample.get("split_group_id"),
            "workload_id": sample.get("workload_id"),
            "class_label": sample.get("class_label"),
            "role": sample.get("role"),
            "split": sample.get("split"),
            "defense": sample.get("defense"),
        }
        if any(record.get(key) != value for key, value in expected_metadata.items()):
            errors.append(f"classifier record metadata mismatch: {sample_id}")
        trace = root / str(sample.get("path", "")) / DIRECT_TRACE_PATH
        try:
            expected_sequence = _classifier_sequence(trace) if trace.is_file() else []
        except (OSError, ValueError) as error:
            errors.append(f"classifier sequence cannot be reproduced: {error}")
            continue
        if record.get("sequence") != expected_sequence:
            errors.append(f"classifier sequence mismatch: {sample_id}")
        sequence = record.get("sequence")
        sample_eligible = bool(_eligible(sample) and expected_sequence)
        fidelity = bool(sample_eligible and sample.get("fidelity_eligible") is True)
        complete_pair = bool(pair_eligible.get(str(sample.get("visit_id"))))
        expected_eligibility = {
            "sample": sample_eligible,
            "fidelity": fidelity,
            "seven_way_pair": complete_pair,
            "research": bool(campaign_stage == "research" and fidelity and complete_pair),
        }
        if record.get("eligibility") != expected_eligibility:
            errors.append(f"classifier eligibility is incorrect: {sample_id}")
        malformed_sequence = not isinstance(sequence, list) or any(
            not isinstance(item, list)
            or len(item) != 3
            or not isinstance(item[0], int)
            or isinstance(item[0], bool)
            or item[0] < 0
            or type(item[1]) is not int
            or item[1] not in {-1, 1}
            or not isinstance(item[2], int)
            or isinstance(item[2], bool)
            or item[2] <= 0
            for item in sequence
        )
        if malformed_sequence or (sequence and sequence[0][0] != 0):
            errors.append(f"classifier sequence has invalid values: {sample_id}")


def _validate_split_index(
    plans: Any,
    configuration: Any,
    splits: Any,
    errors: list[str],
) -> None:
    if (
        not isinstance(plans, list)
        or not all(isinstance(plan, dict) for plan in plans)
        or not isinstance(configuration, dict)
        or type(configuration.get("seed")) is not int
        or not isinstance(splits, dict)
    ):
        errors.append("split index cannot be reproduced from campaign provenance")
        return
    # Imported lazily to avoid coupling dataset module initialization to the
    # collector.  This is the same stable split function used before capture.
    from .campaign import create_splits

    expected = create_splits(plans, configuration["seed"])
    if splits != expected:
        errors.append("split index does not exactly reproduce from campaign seed and visits")


def _reproduce_visit_plan(
    recorded: Any,
    configuration: Any,
    errors: list[str],
) -> list[dict[str, Any]]:
    """Reproduce immutable study and visit identities from workload provenance."""

    if not isinstance(recorded, list) or not all(isinstance(item, dict) for item in recorded):
        errors.append("campaign visit plan is malformed")
        return []
    if not isinstance(configuration, dict):
        errors.append("campaign visit plan cannot be reproduced from configuration")
        return []
    workloads = configuration.get("workloads")
    if not isinstance(workloads, dict):
        errors.append("campaign visit plan cannot be reproduced from workload provenance")
        return []
    entries = workloads.get("entries")
    if (
        not isinstance(entries, list)
        or not all(isinstance(item, dict) for item in entries)
        or type(configuration.get("seed")) is not int
        or not isinstance(workloads.get("request_policy"), str)
        or not isinstance(workloads.get("scope"), str)
        or not isinstance(workloads.get("root"), str)
    ):
        errors.append("campaign visit plan cannot be reproduced from workload provenance")
        return []

    from .campaign import visit_plan_for_workloads

    try:
        study_id, expected = visit_plan_for_workloads(
            campaign_seed=configuration["seed"],
            request_policy=workloads["request_policy"],
            workload_scope=workloads["scope"],
            workload_root=workloads["root"],
            workloads=entries,
        )
    except (KeyError, TypeError, ValueError) as error:
        errors.append(f"campaign visit plan cannot be reproduced: {error}")
        return []
    if configuration.get("study_id") != study_id:
        errors.append("campaign study ID does not reproduce from workload provenance")
    if recorded != expected:
        errors.append("campaign visits do not exactly reproduce from workload provenance")
    return expected


def _reproduce_sample_plan(
    plans: Any,
    configuration: Any,
    splits: Any,
    errors: list[str],
) -> dict[str, dict[str, Any]]:
    if (
        not isinstance(plans, list)
        or not all(isinstance(plan, dict) for plan in plans)
        or not isinstance(configuration, dict)
        or not isinstance(splits, dict)
    ):
        errors.append("sample plan cannot be reproduced from campaign provenance")
        return {}
    workloads = configuration.get("workloads")
    capture = configuration.get("capture")
    defenses = configuration.get("defenses")
    assignments = splits.get("assignments")
    if (
        not isinstance(workloads, dict)
        or not isinstance(workloads.get("scope"), str)
        or not isinstance(capture, dict)
        or not isinstance(capture.get("network_condition"), str)
        or not isinstance(defenses, list)
        or not defenses
        or not all(
            isinstance(defense, dict)
            and isinstance(defense.get("name"), str)
            and isinstance(defense.get("kind"), str)
            and type(defense.get("baseline")) is bool
            for defense in defenses
        )
        or not isinstance(assignments, dict)
    ):
        errors.append("sample plan cannot be reproduced from campaign provenance")
        return {}

    from .campaign import stable_digest

    expected: dict[str, dict[str, Any]] = {}
    required_visit_fields = {
        "visit_id",
        "split_group_id",
        "workload_id",
        "source_manifest_sha256",
        "class_label",
        "role",
        "repetition",
        "seed",
        "path",
    }
    for visit in plans:
        if (
            not required_visit_fields <= set(visit)
            or not isinstance(visit.get("visit_id"), str)
            or not isinstance(visit.get("split_group_id"), str)
            or not isinstance(visit.get("path"), str)
            or visit.get("split_group_id") not in assignments
        ):
            errors.append("sample plan contains an invalid visit declaration")
            return {}
        for defense in defenses:
            name = defense["name"]
            sample_id = stable_digest(
                "sample",
                visit["visit_id"],
                workloads["scope"],
                "direct",
                capture["network_condition"],
                name,
            )
            if sample_id in expected:
                errors.append("sample plan reproduces duplicate sample IDs")
                return {}
            expected[sample_id] = {
                "sample_id": sample_id,
                "visit_id": visit["visit_id"],
                "split_group_id": visit["split_group_id"],
                "workload_id": visit["workload_id"],
                "source_manifest_sha256": visit["source_manifest_sha256"],
                "class_label": visit["class_label"],
                "role": visit["role"],
                "repetition": visit["repetition"],
                "defense": name,
                "runtime_kind": defense["kind"],
                "seed": visit["seed"],
                "path": f"{visit['path']}/{name}",
                "split": assignments[visit["split_group_id"]],
            }
    return expected


def _validate_sample_plan(
    samples: list[dict[str, Any]],
    expected: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    if not expected:
        return
    indexed = {
        str(sample.get("sample_id")): sample for sample in samples if isinstance(sample, dict)
    }
    if set(indexed) != set(expected):
        errors.append("sample index does not exactly match the reproduced campaign plan")
    for sample_id in sorted(set(indexed) & set(expected)):
        sample = indexed[sample_id]
        for key, value in expected[sample_id].items():
            if sample.get(key) != value:
                errors.append(f"sample plan {key} mismatch: {sample_id}")


def _validate_campaign_summary(
    summary: Any,
    plans: list[dict[str, Any]],
    samples: list[dict[str, Any]],
    expected_samples: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    """Recompute campaign completion from exact planned sample membership."""

    actual_by_visit: dict[str, list[dict[str, Any]]] = {}
    for sample in samples:
        actual_by_visit.setdefault(str(sample.get("visit_id")), []).append(sample)
    expected_ids_by_visit: dict[str, set[str]] = {}
    for sample_id, sample in expected_samples.items():
        expected_ids_by_visit.setdefault(str(sample.get("visit_id")), set()).add(sample_id)

    operationally_eligible_visits = 0
    fidelity_eligible_visits = 0
    for plan in plans:
        visit_id = str(plan.get("visit_id"))
        members = actual_by_visit.get(visit_id, [])
        actual_ids = {str(member.get("sample_id")) for member in members}
        exact_membership = (
            bool(expected_ids_by_visit.get(visit_id))
            and actual_ids == (expected_ids_by_visit[visit_id])
        )
        operationally_eligible = exact_membership and all(
            member.get("state") == "captured" and _eligible(member) for member in members
        )
        fidelity_eligible = operationally_eligible and all(
            member.get("fidelity_eligible") is True for member in members
        )
        operationally_eligible_visits += int(operationally_eligible)
        fidelity_eligible_visits += int(fidelity_eligible)

    expected_summary = {
        "eligible_visits": fidelity_eligible_visits,
        "operationally_eligible_visits": operationally_eligible_visits,
        "fidelity_eligible_visits": fidelity_eligible_visits,
        "required_visits": len(plans),
        "logical_samples": len(expected_samples),
        "passed": fidelity_eligible_visits == len(plans),
    }
    if summary != expected_summary:
        errors.append("campaign summary does not exactly match validated sample eligibility")
    if (
        isinstance(summary, dict)
        and summary.get("passed") is True
        and not expected_summary["passed"]
    ):
        errors.append("passed campaign contains incomplete or ineligible planned visits")


def validate_dataset(root: Path, *, raise_on_error: bool = True) -> dict[str, Any]:
    """Validate one canonical direct-capture visit dataset."""

    root = root.resolve()
    errors: list[str] = []
    warnings: list[str] = []
    missing = sorted(name for name in REQUIRED_ROOT_FILES if not (root / name).is_file())
    if missing:
        errors.extend(f"missing required root artifact: {name}" for name in missing)
        return _validation_result(errors, warnings, [], {}, raise_on_error)

    dataset = load_json(root / "dataset.json")
    campaign = load_json(root / "campaign.json")
    splits = load_json(root / "splits.json")
    samples = load_sample_index(root)
    classifier = load_json(root / "classifier.json")
    classifier_samples = load_classifier_sample_index(root)
    try:
        checksum_paths: set[str] | None = set(verify_checksum_seal(root))
    except (OSError, ValueError) as error:
        errors.append(str(error))
        checksum_paths = set()
    configuration = campaign.get("configuration", {})
    recorded_plans = campaign.get("visits", [])
    reproduced_plans = _reproduce_visit_plan(recorded_plans, configuration, errors)
    plans = reproduced_plans or (
        recorded_plans
        if isinstance(recorded_plans, list)
        and all(isinstance(item, dict) for item in recorded_plans)
        else []
    )
    plan_ids = {plan.get("visit_id") for plan in plans}
    plan_split_group_ids = {plan.get("split_group_id") for plan in plans}
    plans_by_id = {plan.get("visit_id"): plan for plan in plans}
    assignments = splits.get("assignments", {})
    if plan_split_group_ids != set(assignments):
        errors.append("split assignments do not exactly match planned split groups")
    sample_ids = [sample.get("sample_id") for sample in samples]
    if None in sample_ids or len(sample_ids) != len(set(sample_ids)):
        errors.append("sample IDs are missing or duplicated")
    configured_defense_entries = (
        [item for item in configuration.get("defenses", []) if isinstance(item, dict)]
        if isinstance(configuration, dict)
        else []
    )
    canonical_suite = is_canonical_defense_suite(configured_defense_entries)
    campaign_state = campaign.get("campaign", {})
    campaign_summary = campaign.get("summary", {})
    campaign_stage = (
        str(campaign_state.get("stage", "acceptance"))
        if isinstance(campaign_state, dict)
        else "acceptance"
    )
    campaign_purpose = campaign_state.get("purpose") if isinstance(campaign_state, dict) else None
    if not isinstance(configuration, dict) or configuration.get("stage") != campaign_stage:
        errors.append("campaign stage declarations do not agree")
    if dataset.get("stage") != campaign_stage:
        errors.append("dataset stage does not match the campaign")
    if (
        not isinstance(campaign_state, dict)
        or campaign_state.get("status") != "complete"
        or not isinstance(campaign_summary, dict)
        or campaign_summary.get("passed") is not True
        or dataset.get("status") != "complete"
    ):
        errors.append("dataset is not a complete successful campaign")
    _validate_split_index(plans, configuration, splits, errors)
    expected_samples = _reproduce_sample_plan(plans, configuration, splits, errors)
    _validate_sample_plan(samples, expected_samples, errors)
    _validate_classifier_indexes(
        root,
        classifier,
        classifier_samples,
        samples,
        configured_defense_entries,
        campaign_stage,
        errors,
    )

    capture_configuration = (
        configuration.get("capture", {}) if isinstance(configuration, dict) else {}
    )
    configured_views = (
        capture_configuration.get("views", []) if isinstance(capture_configuration, dict) else []
    )
    configured_udp_payload_ceiling = (
        capture_configuration.get("udp_payload_ceiling")
        if isinstance(capture_configuration, dict)
        else None
    )
    expected_profile_ceiling = UDP_PAYLOAD_CEILING_BY_PROFILE.get(
        configuration.get("qcsd_profile") if isinstance(configuration, dict) else None
    )
    if (
        expected_profile_ceiling is None
        or configured_udp_payload_ceiling != expected_profile_ceiling
    ):
        errors.append("campaign UDP-payload ceiling does not match its QCSD profile")
    raw_definitions = dataset.get("observer_definitions", [])
    definition_items = raw_definitions if isinstance(raw_definitions, list) else []
    definitions = {
        item["id"]: item
        for item in definition_items
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    primary = [item for item in definitions.values() if item.get("primary")]
    purpose = str(dataset.get("purpose", ""))
    raw_dataset_defenses = dataset.get("defenses", [])
    dataset_defense_entries = (
        [item for item in raw_dataset_defenses if isinstance(item, dict)]
        if isinstance(raw_dataset_defenses, list)
        else []
    )
    defenses = {
        item["name"] for item in dataset_defense_entries if isinstance(item.get("name"), str)
    }
    baselines = {
        item["name"]
        for item in dataset_defense_entries
        if isinstance(item.get("name"), str) and item.get("baseline")
    }
    configured_defenses = {
        item.get("name"): item
        for item in campaign.get("configuration", {}).get("defenses", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    expected_dataset_defenses = [
        {"name": item.get("name"), "baseline": item.get("baseline")}
        for item in configured_defense_entries
    ]
    if dataset.get("defenses") != expected_dataset_defenses:
        errors.append("dataset defense declarations do not match the campaign")
    by_visit: dict[str, list[dict[str, Any]]] = {}
    metadata_by_id: dict[str, dict[str, Any]] = {}
    for sample in samples:
        visit_id = sample.get("visit_id")
        split_group_id = sample.get("split_group_id")
        by_visit.setdefault(str(visit_id), []).append(sample)
        if visit_id not in plan_ids:
            errors.append(f"sample {sample.get('sample_id')} references an unknown visit")
        if sample.get("split") != assignments.get(split_group_id):
            errors.append(f"sample {sample.get('sample_id')} has the wrong split")
        sample_path = root / str(sample.get("path", ""))
        if not sample_path.resolve().is_relative_to(root):
            errors.append(f"sample path escapes result root: {sample.get('path')}")
            continue
        metadata_path = sample_path / "sample.json"
        if not metadata_path.is_file():
            errors.append(f"sample metadata is missing: {sample.get('path')}")
            continue
        metadata = load_json(metadata_path)
        metadata_by_id[str(sample.get("sample_id"))] = metadata
        if metadata.get("sample_id") != sample.get("sample_id"):
            errors.append(f"sample metadata ID mismatch: {sample.get('path')}")
        expected_sample = expected_samples.get(str(sample.get("sample_id")))
        if expected_sample is not None:
            for key in (
                "visit_id",
                "split_group_id",
                "workload_id",
                "class_label",
                "role",
                "repetition",
                "defense",
                "runtime_kind",
                "seed",
                "split",
            ):
                if metadata.get(key) != expected_sample[key]:
                    errors.append(f"sample metadata {key} mismatch: {sample.get('path')}")
        _validate_fidelity_record(
            sample_path,
            sample,
            metadata,
            checksum_paths,
            errors,
        )
        if sample.get("state") != "captured":
            continue
        defense_configuration = configured_defenses.get(sample.get("defense"))
        expected_runtime_kind = (
            defense_configuration.get("kind") if isinstance(defense_configuration, dict) else None
        )
        if isinstance(expected_runtime_kind, str):
            if sample.get("runtime_kind") != expected_runtime_kind:
                errors.append(f"sample indexed runtime kind mismatch: {sample.get('path')}")
            if metadata.get("runtime_kind") != expected_runtime_kind:
                errors.append(f"sample metadata runtime kind mismatch: {sample.get('path')}")
        configured_workloads = configuration.get("workloads")
        expected_request_policy = (
            configured_workloads.get("request_policy")
            if isinstance(configured_workloads, dict)
            else None
        )
        if (
            metadata.get("stage") != campaign_stage
            or metadata.get("purpose") != campaign_purpose
            or metadata.get("request_policy") != expected_request_policy
        ):
            errors.append(f"sample campaign binding mismatch: {sample.get('path')}")
        run_path = sample_path / "neqo" / "run.json"
        try:
            run_data = load_json(run_path)
        except (OSError, ValueError) as error:
            errors.append(f"sample runner metadata is unreadable: {sample.get('path')}: {error}")
            run_data = {}
        if isinstance(defense_configuration, dict) and isinstance(run_data, dict):
            from .campaign import validate_sample_run_binding

            try:
                validate_sample_run_binding(
                    sample_path,
                    run_data,
                    sample,
                    metadata,
                    defense_name=str(defense_configuration.get("name")),
                    defense_kind=str(defense_configuration.get("kind")),
                    expected_udp_payload_ceiling=configured_udp_payload_ceiling,
                )
            except ValueError as error:
                errors.append(str(error))
        else:
            errors.append(f"sample run binding cannot be validated: {sample.get('path')}")
        if (
            isinstance(defense_configuration, dict)
            and defense_configuration.get("parameters_sha256") is not None
        ):
            _validate_parameter_artifacts(
                root,
                sample_path,
                defense_configuration,
                (
                    str(sample["workload_id"])
                    if defense_configuration.get("kind") in {"traffic_morphing", "walkie_talkie"}
                    and "workload_id" in sample
                    else None
                ),
                checksum_paths,
                errors,
                expected_qcsd_profile=(
                    str(configuration.get("qcsd_profile"))
                    if isinstance(configuration.get("qcsd_profile"), str)
                    else None
                ),
                expected_udp_payload_ceiling=(
                    configured_udp_payload_ceiling
                    if isinstance(configured_udp_payload_ceiling, int)
                    else None
                ),
                expected_split_seed=(
                    configuration.get("seed") if campaign_stage == "research" else None
                ),
                expected_workloads=(
                    _configured_parameter_workloads(configuration)
                    if campaign_stage == "research"
                    else None
                ),
            )
        if plans_by_id.get(visit_id, {}).get("workload_model") is not None:
            plan = plans_by_id.get(visit_id, {})
            for key in (
                "workload_scope",
                "workload_model",
                "source_manifest_sha256",
                "resolved_manifest_sha256",
                "resource_count",
                "origin_count",
                "expected_endpoint_count",
            ):
                if metadata.get(key) != plan.get(key):
                    errors.append(f"sample {key} mismatch: {sample.get('path')}")
            actual_endpoints = len(run_data.get("endpoints", []))
            if actual_endpoints != plan.get("expected_endpoint_count"):
                errors.append(f"sample endpoint count mismatch: {sample.get('path')}")
        if metadata.get("resolved_defense") is None:
            errors.append(f"captured sample lacks resolved defense: {sample.get('path')}")
        if metadata.get("udp_payload_ceiling") != configured_udp_payload_ceiling:
            errors.append(f"sample UDP-payload ceiling mismatch: {sample.get('path')}")
        _validate_direct_artifact_cardinality(sample_path, sample, errors)
        views = _views(metadata)
        if len(views) != 1:
            errors.append(f"sample must declare exactly one direct view: {sample.get('path')}")
        recorded = {view.get("id") for view in views}
        if recorded != set(definitions):
            errors.append(f"sample view plan disagrees with dataset: {sample.get('path')}")
        valid = {view["id"] for view in views if view.get("valid")}
        for view in views:
            _validate_view(
                root,
                sample_path,
                view,
                definitions,
                configured_udp_payload_ceiling,
                metadata.get("capture_offloads"),
                errors,
            )
        if primary and _eligible(sample) and primary[0]["id"] not in valid:
            errors.append(f"eligible sample lacks its primary view: {sample.get('path')}")
        indexed_views = sample.get("views")
        expected = {identifier: identifier in valid for identifier in definitions}
        if indexed_views != expected:
            errors.append(f"indexed view validity is incorrect: {sample.get('path')}")

    for visit_id, members in by_visit.items():
        if {sample.get("defense") for sample in members} != defenses:
            errors.append(f"paired visit {visit_id} does not contain every defense")
        baseline = next((sample for sample in members if sample.get("defense") in baselines), None)
        reference = response_signature(root / baseline["path"]) if baseline else None
        for sample in members:
            if sample.get("state") != "captured":
                continue
            metadata = metadata_by_id.get(str(sample.get("sample_id")), {})
            signature = response_signature(root / sample["path"])
            drift = reference is not None and signature is not None and signature != reference
            matches = reference is not None and signature is not None and not drift
            if metadata.get("content_drift") != drift or sample.get("content_drift") != drift:
                errors.append(f"content drift state is incorrect: {sample.get('path')}")
            recorded_match = metadata.get("response_match", sample.get("response_match"))
            if recorded_match is not None and recorded_match != matches:
                errors.append(f"response match state is incorrect: {sample.get('path')}")
            primary_valid = bool(
                primary
                and any(
                    view.get("id") == primary[0]["id"] and view.get("valid")
                    for view in _views(metadata)
                )
            )
            run_data = load_json(root / sample["path"] / "neqo" / "run.json")
            operationally_valid = not padding_event_guard_triggered(run_data)
            recorded_operational = metadata.get(
                "operationally_valid",
                sample.get("operationally_valid"),
            )
            if recorded_operational is not None and recorded_operational != operationally_valid:
                errors.append(f"operational validity is incorrect: {sample.get('path')}")
            if _eligible(sample) != bool(matches and primary_valid and operationally_valid):
                errors.append(f"sample eligibility is incorrect: {sample.get('path')}")

    _validate_campaign_summary(
        campaign_summary,
        plans,
        samples,
        expected_samples,
        errors,
    )

    allowed_purposes = {"classification", "parameter-fitting"}
    if (
        not isinstance(campaign_state, dict)
        or campaign_state.get("purpose") not in allowed_purposes
        or campaign_state.get("purpose") != purpose
        or not isinstance(capture_configuration, dict)
        or capture_configuration.get("mode") != "direct"
        or capture_configuration.get("purpose") != purpose
    ):
        errors.append(
            "campaign must declare one supported direct-capture purpose "
            "(classification or parameter-fitting)"
        )
    if (
        not isinstance(configured_views, list)
        or len(configured_views) != 1
        or not isinstance(configured_views[0], dict)
        or not _is_canonical_direct_view(configured_views[0])
        or capture_configuration.get("primary_view") != DIRECT_VIEW_ID
    ):
        errors.append("campaign must configure exactly one canonical direct QUIC view")
    if not isinstance(raw_definitions, list) or len(raw_definitions) != 1 or len(definitions) != 1:
        errors.append("dataset must declare exactly one observer definition")
    if len(primary) != 1:
        errors.append("dataset must declare exactly one primary view")
    elif (
        not _is_canonical_direct_view(primary[0])
        or dataset.get("primary_observer") != DIRECT_VIEW_ID
    ):
        errors.append("dataset must use the canonical direct QUIC view")
    if purpose not in allowed_purposes:
        errors.append("dataset purpose must be classification or parameter-fitting")
    if dataset.get("data_license") != "not-for-release":
        errors.append("dataset data license must be not-for-release")
    else:
        warnings.append("dataset is marked not-for-release")
    for entry in campaign.get("configuration", {}).get("workloads", {}).get("entries", []):
        if "resolved_manifest_sha256" not in entry:
            continue
        resolved = root / "resolved-workloads" / f"{entry.get('workload_id')}.json"
        if not resolved.is_file():
            errors.append(f"resolved workload is missing: {resolved.name}")
        elif sha256_file(resolved) != entry.get("resolved_manifest_sha256"):
            errors.append(f"resolved workload hash mismatch: {resolved.name}")
    if canonical_suite:
        _validate_classic_figure_surface(
            root,
            plans,
            checksum_paths,
            errors,
        )
    return _validation_result(errors, warnings, samples, by_visit, raise_on_error, purpose)


def _validation_result(
    errors: list[str],
    warnings: list[str],
    samples: list[dict[str, Any]],
    visits: dict[str, Any],
    raise_on_error: bool,
    purpose: str | None = None,
) -> dict[str, Any]:
    if errors and raise_on_error:
        raise DatasetValidationError(errors)
    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "logical_samples": len(samples),
        "paired_visits": len(visits),
        "purpose": purpose,
        "eligible_samples": sum(_eligible(sample) for sample in samples),
    }


def _views(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    views = metadata.get("views", [])
    return views if isinstance(views, list) else []


def _eligible(sample: dict[str, Any]) -> bool:
    return sample.get("eligible") is True


def _validate_fidelity_record(
    sample_path: Path,
    sample: dict[str, Any],
    metadata: dict[str, Any],
    checksum_paths: set[str] | None,
    errors: list[str],
) -> None:
    label = str(sample.get("path"))
    path = sample_path / "fidelity.yml"
    if checksum_paths is not None:
        relative = path.relative_to(sample_path.parents[2]).as_posix()
        if relative not in checksum_paths:
            errors.append(f"sample fidelity record is not checksum-sealed: {label}")
    try:
        validate_fidelity_record(sample_path, sample, metadata)
    except (OSError, ValueError) as error:
        errors.append(f"{error}: {label}")


def _validate_parameter_artifacts(
    root: Path,
    sample: Path,
    defense: dict[str, Any],
    expected_workload_id: str | None,
    checksum_paths: set[str] | None,
    errors: list[str],
    *,
    expected_qcsd_profile: str | None,
    expected_udp_payload_ceiling: int | None,
    expected_split_seed: int | None,
    expected_workloads: dict[str, tuple[str, str, int]] | None,
) -> None:
    label = str(sample)
    try:
        validate_sample_parameter_artifacts(
            sample,
            defense,
            checksum_paths=checksum_paths,
            checksum_root=root,
            expected_workload_id=expected_workload_id,
            expected_qcsd_profile=expected_qcsd_profile,
            expected_udp_payload_ceiling=expected_udp_payload_ceiling,
            expected_split_seed=expected_split_seed,
            expected_workloads=expected_workloads,
        )
    except (OSError, ValueError) as error:
        errors.append(f"{error}: {label}")


def _configured_parameter_workloads(
    configuration: Mapping[str, Any],
) -> dict[str, tuple[str, str, int]]:
    workloads = configuration.get("workloads")
    entries = workloads.get("entries") if isinstance(workloads, Mapping) else None
    if not isinstance(entries, list):
        return {}
    if not all(isinstance(workload, dict) for workload in entries):
        return {}
    from .campaign import parameter_workload_contract

    try:
        return parameter_workload_contract(entries)
    except ValueError:
        return {}


def _validate_direct_artifact_cardinality(
    sample_path: Path,
    sample: dict[str, Any],
    errors: list[str],
) -> None:
    label = str(sample.get("path"))
    expected = {
        "captures": {"direct-quic.pcapng"},
        "traces": {"direct-quic.csv"},
    }
    for directory_name, expected_files in expected.items():
        directory = sample_path / directory_name
        actual = (
            {
                path.relative_to(directory).as_posix()
                for path in directory.rglob("*")
                if path.is_file()
            }
            if directory.is_dir()
            else set()
        )
        if actual != expected_files:
            errors.append(
                f"sample {directory_name} artifacts must be exactly "
                f"{sorted(expected_files)}: {label}"
            )


def _validate_classic_figure_surface(
    root: Path,
    plans: list[dict[str, Any]],
    checksum_paths: set[str] | None,
    errors: list[str],
) -> None:
    try:
        report = (root / "report.html").read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"classic figure report cannot be read: {error}")
        return
    for plan in plans:
        relative_group = Path(str(plan.get("path", "")))
        group = (root / relative_group).resolve()
        label = relative_group.as_posix()
        if (
            relative_group.is_absolute()
            or ".." in relative_group.parts
            or not group.is_relative_to(root)
            or not group.is_dir()
        ):
            errors.append(f"classic figure group path is invalid: {label}")
            continue
        actual = {
            path.name
            for path in group.iterdir()
            if path.is_file()
            and path.name.startswith("trace-comparison")
            and path.suffix in {".pdf", ".svg"}
        }
        if actual != CLASSIC_FIGURE_FILES:
            errors.append(
                f"classic figure artifacts must be the exact two-page PDF/SVG surface: {label}"
            )
        for name in sorted(CLASSIC_FIGURE_FILES & actual):
            path = group / name
            relative = path.relative_to(root).as_posix()
            data = path.read_bytes()
            if (
                not data
                or (path.suffix == ".pdf" and not data.startswith(b"%PDF"))
                or (path.suffix == ".svg" and b"<svg" not in data[:1024])
            ):
                errors.append(f"classic figure format is invalid: {relative}")
            if checksum_paths is not None and relative not in checksum_paths:
                errors.append(f"classic figure is not checksum-sealed: {relative}")
            attribute = "href" if path.suffix == ".pdf" else "src"
            if f'{attribute}="{relative}"' not in report:
                errors.append(f"classic figure is not linked from report.html: {relative}")


def _validate_view(
    root: Path,
    sample: Path,
    view: dict[str, Any],
    declarations: dict[str, dict[str, Any]],
    expected_udp_payload_ceiling: Any,
    sample_offloads: Any,
    errors: list[str],
) -> None:
    identifier = view.get("id")
    declaration = declarations.get(identifier)
    label = f"{sample.relative_to(root)}:{identifier}"
    if declaration is None:
        errors.append(f"undeclared view in {label}")
        return
    for key in ("kind", "interface", "length_basis", "link_type", "primary"):
        if view.get(key) != declaration.get(key):
            errors.append(f"view {key} mismatch in {label}")
    if (
        view.get("capture_path") != DIRECT_CAPTURE_PATH
        or view.get("trace_path") != DIRECT_TRACE_PATH
    ):
        errors.append(f"view must use fixed direct artifact paths in {label}")
    capture = _contained_artifact(sample, view.get("capture_path"), label, "capture", errors)
    trace_path = _contained_artifact(sample, view.get("trace_path"), label, "trace", errors)
    if capture is None or trace_path is None:
        return
    if not capture.is_file() or not trace_path.is_file():
        errors.append(f"view artifact missing in {label}")
        return
    info = run(["capinfos", "-E", str(capture)], check=False)
    if capture.read_bytes()[:4] != b"\x0a\x0d\x0d\x0a":
        errors.append(f"capture is not PCAPNG in {label}")
    if info.returncode or str(view.get("link_type", "")).lower() not in info.stdout.lower():
        errors.append(f"capture link type mismatch in {label}")
    if view.get("truncated") is not False:
        errors.append(f"capture is truncated in {label}")
    if view.get("capture_active_through_settle") is not True:
        errors.append(f"capture did not remain active through the defense tail in {label}")
    if sha256_file(capture) != view.get("capture_sha256"):
        errors.append(f"capture hash mismatch in {label}")
    if sha256_file(trace_path) != view.get("trace_sha256"):
        errors.append(f"trace hash mismatch in {label}")
    try:
        rows = read_normalized_trace(trace_path)
        run_data = load_json(sample / "neqo" / "run.json")
        endpoints = run_data.get("endpoints", [])
        derived = extract_trace(
            capture,
            endpoints,
        )
    except (KeyError, OSError, RuntimeError, ValueError) as error:
        errors.append(f"trace cannot be reproduced in {label}: {error}")
        return
    expected = [
        {
            "relative_time_ns": str(packet.relative_time_ns),
            "direction": packet.direction,
            "length_bytes": str(packet.length_bytes),
            "signed_length_bytes": str(packet.signed_length_bytes),
        }
        for packet in derived
    ]
    if rows != expected:
        errors.append(f"normalized trace disagrees with PCAPNG in {label}")
    if len(rows) != view.get("packet_count"):
        errors.append(f"packet count mismatch in {label}")
    if not isinstance(expected_udp_payload_ceiling, int):
        errors.append(f"campaign UDP-payload ceiling is invalid in {label}")
    else:
        resolved_configuration = run_data.get("resolved_configuration")
        resolved_ceiling = (
            resolved_configuration.get("max_udp_payload_size")
            if isinstance(resolved_configuration, dict)
            else None
        )
        expected_ceiling_evidence = udp_ceiling_evidence(
            derived,
            expected_udp_payload_ceiling,
        )
        runner_binding_valid = resolved_ceiling == expected_udp_payload_ceiling
        expected_ceiling_evidence.update(
            {
                "runner_resolved_udp_payload_ceiling": resolved_ceiling,
                "runner_binding_valid": runner_binding_valid,
                "valid": bool(expected_ceiling_evidence["valid"] and runner_binding_valid),
            }
        )
        if view.get("udp_payload_ceiling_evidence") != expected_ceiling_evidence:
            errors.append(f"UDP-payload ceiling evidence mismatch in {label}")
        if expected_ceiling_evidence["valid"] is not True:
            errors.append(f"UDP-payload ceiling is not satisfied in {label}")
    offload = view.get("capture_offload_evidence")
    if not offload_evidence_is_valid(
        offload,
        interface=str(view.get("interface", "")),
    ):
        errors.append(f"capture offload evidence is invalid in {label}")
    if sample_offloads != [offload]:
        errors.append(f"sample capture offload evidence mismatch in {label}")
    for row in rows:
        length = int(row["length_bytes"])
        signed = int(row["signed_length_bytes"])
        expected_sign = length if row["direction"] == "outgoing" else -length
        if length <= 0 or signed != expected_sign:
            errors.append(f"invalid direction/length semantics in {label}")
            break


def _is_canonical_direct_view(view: dict[str, Any]) -> bool:
    return all(view.get(key) == value for key, value in DIRECT_VIEW_CONTRACT.items())


def _contained_artifact(
    sample: Path,
    relative: Any,
    label: str,
    artifact: str,
    errors: list[str],
) -> Path | None:
    if not isinstance(relative, str) or not relative:
        errors.append(f"view {artifact} path is invalid in {label}")
        return None
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        errors.append(f"view {artifact} path escapes sample directory in {label}")
        return None
    resolved = (sample / relative_path).resolve()
    if not resolved.is_relative_to(sample.resolve()):
        errors.append(f"view {artifact} path escapes sample directory in {label}")
        return None
    return resolved


def write_projection(root: Path, *, reference_visits_per_defense: int = 20_000) -> Path:
    samples = load_sample_index(root)
    captured = [sample for sample in samples if sample.get("state") == "captured"]
    campaign = load_json(root / "campaign.json")
    started = _parse_time(campaign.get("campaign", {}).get("started_at"))
    completed = _parse_time(campaign.get("campaign", {}).get("completed_at"))
    wall = (completed - started).total_seconds() if started and completed else None
    storage = _storage(root, captured)
    internal = sum(
        path.stat().st_size
        for sample in captured
        for name in ("neqo", "attempts")
        for path in (root / sample["path"] / name).rglob("*")
        if path.is_file()
    )
    requests = delivered = 0
    for sample in captured:
        run_json = root / sample["path"] / "neqo" / "run.json"
        if not run_json.is_file():
            continue
        for response in load_json(run_json).get("responses", []):
            requests += 1
            delivered += int(response.get("bytes", 0))
    defenses = sorted({str(sample.get("defense")) for sample in samples})
    per_defense = {}
    for defense in defenses:
        members = [sample for sample in captured if sample.get("defense") == defense]
        factor = reference_visits_per_defense / max(len(members), 1)
        measured = _storage(root, members)
        per_defense[defense] = {
            "measured_samples": len(members),
            "views": {
                name: {
                    **values,
                    "projected_pcapng_bytes": round(values["pcapng_bytes"] * factor),
                    "projected_trace_bytes": round(values["trace_bytes"] * factor),
                }
                for name, values in measured.items()
            },
        }
    scale = reference_visits_per_defense * len(defenses) / max(len(captured), 1)
    projection = {
        "measured": {
            "wall_seconds": wall,
            "logical_samples": len(samples),
            "captured_samples": len(captured),
            "attempts": sum(int(sample.get("attempts", 0)) for sample in samples),
            "failure_rate": sum(sample.get("state") != "captured" for sample in samples)
            / max(len(samples), 1),
            "drift_rate": sum(sample.get("content_drift") is True for sample in samples)
            / max(len(samples), 1),
            "views": storage,
            "internal_bytes": internal,
            "requests": requests,
            "delivered_response_bytes": delivered,
            "throughput_samples_per_hour": len(captured) * 3600 / wall if wall else None,
        },
        "qcsd_scale_reference": {
            "visits_per_defense": reference_visits_per_defense,
            "defense_count": len(defenses),
            "per_defense": per_defense,
            "projected_wall_seconds": round(wall * scale) if wall else None,
            "projected_internal_bytes": round(internal * scale),
            "retention_decision": "requires explicit authorization",
        },
    }
    destination = root / "projection.json"
    atomic_json(destination, projection)
    return destination


def _storage(root: Path, samples: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    totals: dict[str, dict[str, int]] = {}
    for sample in samples:
        path = root / sample["path"]
        metadata = load_json(path / "sample.json")
        for view in _views(metadata):
            if not view.get("valid"):
                continue
            values = totals.setdefault(
                view["id"], {"valid_samples": 0, "pcapng_bytes": 0, "trace_bytes": 0}
            )
            values["valid_samples"] += 1
            values["pcapng_bytes"] += (path / view["capture_path"]).stat().st_size
            values["trace_bytes"] += (path / view["trace_path"]).stat().st_size
    return totals


def _parse_time(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None
