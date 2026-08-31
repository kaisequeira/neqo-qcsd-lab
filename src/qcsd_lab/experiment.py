from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Sequence

from .util import atomic_json, load_json, sha256_file


SCHEMA_VERSION = 1
EXPERIMENT_FILE = "experiment.json"
EVIDENCE_FILE = "evidence.sha256"
RESULT_DIRECTORIES = ("inputs", "samples", "failures", "derived")
PURPOSES = {"smoke", "fitting", "evaluation"}
EXPERIMENT_STATES = {"running", "complete", "incomplete"}
SAMPLE_STATES = {"planned", "running", "accepted", "failed", "interrupted"}
ACCEPTED_ARTIFACTS = {
    "capture.pcapng",
    "neqo/run.json",
    "neqo/packets.csv",
    "neqo/events.csv",
    "neqo/schedule.csv",
}
STRICT_DEFENSE_FIDELITY_FAILURE = "StrictDefenseFidelityFailure"
STRICT_CLIENT_DEFENSE_EXECUTION_FAILURE = "StrictClientDefenseExecutionFailure"
TERMINAL_DEFENSE_FAILURE_TYPES = frozenset(
    {
        STRICT_DEFENSE_FIDELITY_FAILURE,
        STRICT_CLIENT_DEFENSE_EXECUTION_FAILURE,
    }
)

_DIGEST = re.compile(r"[0-9a-f]{64}")
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_QUALIFICATION_SET = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_CLASS_STUDY_ID = re.compile(
    r"classifier-multiorigin100-v(?:1|2-[0-9a-f]{12})"
)
_CLASS_STUDY_ROLES = frozenset(
    {
        "pilot-fitting",
        "pilot-compatibility",
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    }
)
_CLASS_STUDY_COMMON_CONFIGURATION_KEYS = frozenset(
    {
        "evidence_role",
        "class_study_cohort_sha256",
        "class_study_cohort_assembly_sha256",
        "class_study_id",
        "class_study_launch_sha256",
        "class_study_foundation_sha256",
        "public_origin_policy",
    }
)
_CLASS_STUDY_OPTIONAL_CONFIGURATION_KEYS = frozenset(
    {
        "class_study_successor_sha256",
        "class_study_readiness_sha256",
        "class_study_historical_pre_snapshot_sha256",
    }
)
_CLASS_STUDY_DIGEST_CONFIGURATION_KEYS = frozenset(
    {
        "class_study_cohort_sha256",
        "class_study_cohort_assembly_sha256",
        "class_study_launch_sha256",
        "class_study_foundation_sha256",
        "class_study_successor_sha256",
        "class_study_readiness_sha256",
        "class_study_historical_pre_snapshot_sha256",
    }
)
_CLASS_STUDY_PUBLIC_ORIGIN_POLICY = {
    "environment": "QCSD_PUBLIC_ORIGIN_ONLY",
    "required_value": "1",
    "resolution": "resolve-once-reject-any-non-public-connect-exact-address",
}
_EXPERIMENT_KEYS = {
    "schema_version",
    "name",
    "purpose",
    "status",
    "started_at",
    "completed_at",
    "input_digest",
    "source",
    "configuration",
    "execution_order",
    "samples",
    "summary",
}
_CONFIGURATION_KEYS = {
    "campaign_sha256",
    "profile",
    "request_policies",
    "workloads",
    "defenses",
    "limits",
}
_OPTIONAL_CONFIGURATION_KEYS = {
    "chaff_qualification_set",
    "defense_order",
    "study_environment_sha256",
    "capture_admission_sha256",
    "formal_cohort_sha256",
    "evidence_role",
    "sample_order",
    "chaff_qualification_set_manifest_sha256",
    "class_study_cohort_sha256",
    "class_study_cohort_assembly_sha256",
    "class_study_id",
    "class_study_successor_sha256",
    "class_study_launch_sha256",
    "class_study_foundation_sha256",
    "class_study_readiness_sha256",
    "class_study_historical_pre_snapshot_sha256",
    "public_origin_policy",
}
_SAMPLE_KEYS = {
    "sample_id",
    "workload_id",
    "request_policy",
    "visit",
    "defense",
    "runtime_kind",
    "baseline",
    "seed",
    "path",
    "state",
    "attempts",
    "eligible",
    "failure",
    "diagnostics",
    "artifacts",
}
_SUMMARY_KEYS = {"planned", "accepted", "failed", "eligible", "passed"}
_SAMPLE_IDENTITY_KEYS = (
    "sample_id",
    "workload_id",
    "request_policy",
    "visit",
    "defense",
    "runtime_kind",
    "baseline",
    "seed",
    "path",
)
_UNSET = object()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def result_path(results_root: Path, campaign_name: str, run_id: str) -> Path:
    """Return the canonical ``results/<campaign>/<run-id>`` path safely."""

    _validate_component(campaign_name, "campaign name")
    _validate_component(run_id, "run ID")
    root = results_root.resolve()
    result = (root / campaign_name / run_id).resolve()
    if not result.is_relative_to(root):
        raise ValueError("result path escapes results root")
    return result


def initialize_experiment(
    root: Path,
    *,
    name: str,
    purpose: str,
    run_id: str,
    source: Mapping[str, Any],
    configuration: Mapping[str, Any],
    samples: Sequence[Mapping[str, Any]],
    started_at: str | None = None,
) -> dict[str, Any]:
    """Create the canonical directories and first atomic experiment checkpoint.

    Frozen input files should be placed under ``inputs/`` before this call. Their
    hashes then become part of ``input_digest`` and cannot change on resume.
    """

    _validate_component(name, "campaign name")
    _validate_component(run_id, "run ID")
    if purpose not in PURPOSES:
        raise ValueError(f"invalid experiment purpose: {purpose!r}")
    root = root.resolve()
    if root.exists() and any(root.iterdir()):
        allowed_staged = root / "inputs"
        unexpected = [path for path in root.iterdir() if path != allowed_staged]
        if unexpected:
            raise FileExistsError(f"result directory is not empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    for directory in RESULT_DIRECTORIES:
        (root / directory).mkdir(parents=True, exist_ok=True)
    source_path = root / "inputs/source.json"
    if source_path.exists() and load_json(source_path) != dict(source):
        raise ValueError("staged inputs/source.json does not match running source")
    atomic_json(source_path, source)

    planned = [_initial_sample(item) for item in samples]
    order = [sample["sample_id"] for sample in planned]
    if len(order) != len(set(order)):
        raise ValueError("sample IDs must be unique")
    experiment: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "name": name,
        "purpose": purpose,
        "status": "running",
        "started_at": started_at or utc_now(),
        "completed_at": None,
        "input_digest": input_digest(
            root,
            source=source,
            configuration=configuration,
            samples=planned,
        ),
        "source": dict(source),
        "configuration": dict(configuration),
        "execution_order": order,
        "samples": planned,
        "summary": _summary(planned, passed=False),
    }
    checkpoint_experiment(root, experiment)
    return experiment


def load_experiment(root: Path) -> dict[str, Any]:
    value = load_json(root / EXPERIMENT_FILE)
    validate_experiment(value)
    return value


def checkpoint_experiment(root: Path, experiment: Mapping[str, Any]) -> None:
    """Atomically replace the sole mutable campaign-state checkpoint."""

    root = root.resolve()
    if (root / EVIDENCE_FILE).exists():
        raise ValueError("sealed result is immutable; retire its seal before checkpointing")
    validate_experiment(experiment)
    atomic_json(root / EXPERIMENT_FILE, experiment)


def sample_record(experiment: MutableMapping[str, Any], sample_id: str) -> dict[str, Any]:
    matches = [sample for sample in experiment["samples"] if sample["sample_id"] == sample_id]
    if len(matches) != 1:
        raise ValueError(f"unknown or duplicate sample ID: {sample_id}")
    return matches[0]


def transition_sample(
    experiment: MutableMapping[str, Any],
    sample_id: str,
    state: str,
    *,
    increment_attempt: bool = False,
    eligible: bool | None = None,
    failure: Mapping[str, Any] | None | object = _UNSET,
    diagnostics: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply one valid lifecycle transition in memory.

    Callers explicitly checkpoint after any associated filesystem promotion has
    completed, keeping state transitions atomic from the reader's perspective.
    """

    if state not in SAMPLE_STATES:
        raise ValueError(f"invalid sample state: {state!r}")
    sample = sample_record(experiment, sample_id)
    previous = sample["state"]
    allowed = {
        "planned": {"running"},
        "running": {"accepted", "failed", "interrupted"},
        "failed": {"running"},
        # Resume may classify a prospectively budgeted physical launch as a
        # durable failed attempt before deciding whether another launch fits
        # within the campaign cap.
        "interrupted": {"running", "failed"},
        "accepted": set(),
    }
    if state != previous and state not in allowed[previous]:
        raise ValueError(f"invalid sample transition: {previous} -> {state}")
    if increment_attempt:
        if state != "running" or previous not in {"planned", "failed", "interrupted"}:
            raise ValueError("attempts can only increment when starting an attempt")
        sample["attempts"] += 1
    if eligible is not None:
        sample["eligible"] = eligible
    if failure is not _UNSET:
        sample["failure"] = dict(failure) if isinstance(failure, Mapping) else failure
    elif state in {"running", "accepted"}:
        sample["failure"] = None
    if diagnostics is not None:
        sample["diagnostics"] = dict(diagnostics)
    sample["state"] = state
    experiment["summary"] = _summary(experiment["samples"], passed=False)
    return sample


def accept_sample(
    root: Path,
    experiment: MutableMapping[str, Any],
    sample_id: str,
    *,
    diagnostics: Mapping[str, Any] | None = None,
    eligible: bool = False,
) -> dict[str, Any]:
    """Bind the promoted sample directory byte-for-byte and mark it accepted."""

    sample = sample_record(experiment, sample_id)
    if sample["state"] != "running":
        raise ValueError("only a running sample can be accepted")
    artifacts = accepted_sample_hashes(root, sample)
    sample["artifacts"] = artifacts
    return transition_sample(
        experiment,
        sample_id,
        "accepted",
        eligible=eligible,
        failure=None,
        diagnostics=diagnostics,
    )


def set_sample_eligibility(
    experiment: MutableMapping[str, Any], sample_id: str, eligible: bool
) -> dict[str, Any]:
    sample = sample_record(experiment, sample_id)
    if sample["state"] != "accepted":
        raise ValueError("only an accepted sample can be eligible")
    sample["eligible"] = eligible
    experiment["summary"] = _summary(experiment["samples"], passed=False)
    return sample


def interrupt_running_samples(experiment: MutableMapping[str, Any]) -> list[str]:
    """Convert stale running checkpoints to resumable interrupted states."""

    interrupted: list[str] = []
    for sample in experiment["samples"]:
        if sample["state"] == "running":
            sample["state"] = "interrupted"
            sample["failure"] = {
                "stage": "interruption",
                "message": "stale running checkpoint",
            }
            interrupted.append(sample["sample_id"])
    experiment["summary"] = _summary(experiment["samples"], passed=False)
    return interrupted


def finalize_experiment(
    root: Path,
    experiment: MutableMapping[str, Any],
    *,
    status: str,
    completed_at: str | None = None,
) -> dict[str, Any]:
    """Write the terminal checkpoint; sealing is a separate explicit operation."""

    if status not in {"complete", "incomplete"}:
        raise ValueError("terminal experiment status must be complete or incomplete")
    samples = experiment["samples"]
    passed = bool(samples) and all(
        sample["state"] == "accepted" and sample["eligible"] is True for sample in samples
    )
    if status == "complete" and not passed:
        raise ValueError("a complete experiment requires every planned sample to be eligible")
    experiment["status"] = status
    experiment["completed_at"] = completed_at or utc_now()
    experiment["summary"] = _summary(samples, passed=status == "complete" and passed)
    checkpoint_experiment(root, experiment)
    return dict(experiment["summary"])


def accepted_sample_hashes(root: Path, sample: Mapping[str, Any]) -> dict[str, str]:
    """Hash the exact accepted artifact set for one sample."""

    root = root.resolve()
    sample_root = _sample_root(root, sample)
    relative_files = _regular_files(sample_root, relative_to=sample_root)
    actual = set(relative_files)
    missing = sorted(ACCEPTED_ARTIFACTS - actual)
    extra = sorted(actual - ACCEPTED_ARTIFACTS)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"extra {', '.join(extra)}")
        raise ValueError(
            f"accepted sample {sample['sample_id']} artifact set mismatch: " + "; ".join(details)
        )
    return {
        path.relative_to(root).as_posix(): sha256_file(path)
        for _, path in sorted(relative_files.items())
    }


def validate_accepted_samples(
    root: Path,
    experiment: Mapping[str, Any] | None = None,
    *,
    allow_running_artifacts: bool = False,
) -> dict[str, dict[str, str]]:
    """Validate every accepted sample's exact, independently recorded hash set.

    The strict default rejects every file below ``samples/`` that is not bound
    to an accepted sample.  Resume may temporarily permit files below the exact
    canonical path of a sample whose durable checkpoint is still ``running``:
    a process can stop after moving an attempt into place but before recording
    its accepted hashes.  No other unbound path is permitted.
    """

    root = root.resolve()
    value = dict(experiment) if experiment is not None else load_experiment(root)
    validated: dict[str, dict[str, str]] = {}
    recorded_paths: set[str] = set()
    for sample in value["samples"]:
        if sample["state"] != "accepted":
            if sample["artifacts"]:
                raise ValueError(f"non-accepted sample records artifacts: {sample['sample_id']}")
            continue
        actual = accepted_sample_hashes(root, sample)
        expected = sample["artifacts"]
        if actual != expected:
            missing = sorted(set(expected) - set(actual))
            extra = sorted(set(actual) - set(expected))
            changed = sorted(
                path for path in set(actual) & set(expected) if actual[path] != expected[path]
            )
            details = []
            if missing:
                details.append(f"missing {', '.join(missing)}")
            if extra:
                details.append(f"extra {', '.join(extra)}")
            if changed:
                details.append(f"modified {', '.join(changed)}")
            raise ValueError(
                f"accepted sample hash mismatch for {sample['sample_id']}: " + "; ".join(details)
            )
        validated[sample["sample_id"]] = actual
        recorded_paths.update(actual)
    samples_root = root / "samples"
    if not samples_root.is_dir() or samples_root.is_symlink():
        raise ValueError(f"result has no regular samples directory: {root}")
    all_sample_files = set(_regular_files(samples_root, relative_to=root))
    unbound = sorted(all_sample_files - recorded_paths)
    if allow_running_artifacts and unbound:
        running_prefixes = tuple(
            f"{sample['path']}/" for sample in value["samples"] if sample["state"] == "running"
        )
        unbound = [
            path
            for path in unbound
            if not any(path.startswith(prefix) for prefix in running_prefixes)
        ]
    if unbound:
        raise ValueError(f"unbound files in authoritative samples directory: {', '.join(unbound)}")
    return validated


def input_artifact_hashes(root: Path) -> dict[str, str]:
    root = root.resolve()
    inputs = root / "inputs"
    if not inputs.is_dir() or inputs.is_symlink():
        raise ValueError(f"result has no inputs directory: {root}")
    files = _regular_files(inputs, relative_to=root)
    return {relative: sha256_file(path) for relative, path in sorted(files.items())}


def input_digest(
    root: Path,
    *,
    source: Mapping[str, Any],
    configuration: Mapping[str, Any],
    samples: Sequence[Mapping[str, Any]],
) -> str:
    """Fingerprint frozen inputs and the immutable, ordered sample plan."""

    payload = {
        "configuration": configuration,
        "inputs": input_artifact_hashes(root),
        "sample_plan": sample_plan_identity(samples),
        "source": source,
    }
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"qcsd-experiment-input-v2\0" + data).hexdigest()


def sample_plan_identity(samples: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return the immutable identities in their exact planned execution order."""

    return [{key: sample[key] for key in _SAMPLE_IDENTITY_KEYS} for sample in samples]


def validate_planned_sample_identity(
    experiment: Mapping[str, Any], expected_samples: Sequence[Mapping[str, Any]]
) -> None:
    """Match a mutable checkpoint to the plan derived from its frozen inputs."""

    expected = sample_plan_identity(expected_samples)
    actual = sample_plan_identity(experiment["samples"])
    expected_order = [sample["sample_id"] for sample in expected]
    if actual != expected or experiment["execution_order"] != expected_order:
        raise ValueError("experiment planned sample identity/order mismatch")


def validate_resume_fingerprints(
    root: Path,
    expected_source: Mapping[str, Any] | None = None,
    *,
    experiment: Mapping[str, Any] | None = None,
    expected_configuration: Mapping[str, Any] | None = None,
    expected_input_digest: str | None = None,
) -> str:
    """Recompute frozen-input identity and optionally match the current runner."""

    root = root.resolve()
    value = dict(experiment) if experiment is not None else load_experiment(root)
    actual = input_digest(
        root,
        source=value["source"],
        configuration=value["configuration"],
        samples=value["samples"],
    )
    if actual != value["input_digest"]:
        raise ValueError("result input fingerprint mismatch")
    if expected_source is not None and dict(expected_source) != value["source"]:
        raise ValueError("resume source fingerprint mismatch")
    if (
        expected_configuration is not None
        and dict(expected_configuration) != value["configuration"]
    ):
        raise ValueError("resume configuration fingerprint mismatch")
    if expected_input_digest is not None and expected_input_digest != actual:
        raise ValueError("resume input fingerprint mismatch")
    return actual


def validate_experiment(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != _EXPERIMENT_KEYS:
        raise ValueError("experiment.json has an invalid top-level schema")
    if value["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported experiment schema: {value['schema_version']!r}")
    _validate_component(value["name"], "experiment name")
    if value["purpose"] not in PURPOSES:
        raise ValueError("experiment purpose is invalid")
    if value["status"] not in EXPERIMENT_STATES:
        raise ValueError("experiment status is invalid")
    if not isinstance(value["started_at"], str) or not value["started_at"]:
        raise ValueError("experiment started_at is invalid")
    if value["status"] == "running":
        if value["completed_at"] is not None:
            raise ValueError("running experiment cannot have completed_at")
    elif not isinstance(value["completed_at"], str) or not value["completed_at"]:
        raise ValueError("terminal experiment requires completed_at")
    if not _is_digest(value["input_digest"]):
        raise ValueError("experiment input_digest is invalid")
    if not isinstance(value["source"], Mapping):
        raise ValueError("experiment source is invalid")
    _validate_configuration(value["configuration"])

    samples = value["samples"]
    if not isinstance(samples, list) or not samples:
        raise ValueError("experiment requires at least one sample")
    for sample in samples:
        _validate_sample(sample)
    sample_ids = [sample["sample_id"] for sample in samples]
    if len(sample_ids) != len(set(sample_ids)):
        raise ValueError("experiment sample IDs are not unique")
    if value["execution_order"] != sample_ids:
        raise ValueError("execution_order must exactly match sample order")

    expected_summary = _summary(samples, passed=value["status"] == "complete")
    if value["summary"] != expected_summary:
        raise ValueError("experiment summary does not match sample state")
    if value["status"] == "complete" and not expected_summary["passed"]:
        raise ValueError("complete experiment is not fully eligible")
    if value["status"] != "complete" and value["summary"]["passed"] is not False:
        raise ValueError("non-complete experiment cannot pass")


def _initial_sample(value: Mapping[str, Any]) -> dict[str, Any]:
    identity = {
        key: value[key]
        for key in (
            "sample_id",
            "workload_id",
            "request_policy",
            "visit",
            "defense",
            "runtime_kind",
            "baseline",
            "seed",
            "path",
        )
    }
    sample = {
        **identity,
        "state": "planned",
        "attempts": 0,
        "eligible": False,
        "failure": None,
        "diagnostics": {},
        "artifacts": {},
    }
    _validate_sample(sample)
    return sample


def _validate_configuration(value: object) -> None:
    if not isinstance(value, Mapping):
        raise ValueError("experiment configuration schema is invalid")
    keys = set(value)
    if not _CONFIGURATION_KEYS <= keys or not (
        keys - _CONFIGURATION_KEYS <= _OPTIONAL_CONFIGURATION_KEYS
    ):
        raise ValueError("experiment configuration schema is invalid")
    if not _is_digest(value["campaign_sha256"]):
        raise ValueError("configuration campaign_sha256 is invalid")
    if not isinstance(value["profile"], str) or not value["profile"]:
        raise ValueError("configuration profile is invalid")
    if not isinstance(value["request_policies"], list) or not all(
        isinstance(item, str) and item for item in value["request_policies"]
    ):
        raise ValueError("configuration request_policies are invalid")
    if not isinstance(value["workloads"], list) or not value["workloads"]:
        raise ValueError("configuration workloads are invalid")
    if not isinstance(value["defenses"], list) or not value["defenses"]:
        raise ValueError("configuration defenses are invalid")
    if not isinstance(value["limits"], Mapping):
        raise ValueError("configuration limits are invalid")
    if "chaff_qualification_set" in value and (
        not isinstance(value["chaff_qualification_set"], str)
        or _QUALIFICATION_SET.fullmatch(value["chaff_qualification_set"]) is None
    ):
        raise ValueError("configuration chaff_qualification_set is invalid")
    if "defense_order" in value:
        defense_order = value["defense_order"]
        if (
            not isinstance(defense_order, Mapping)
            or set(defense_order) != {"scheme", "block"}
            or defense_order["scheme"] != "cyclic-latin-square"
            or type(defense_order["block"]) is not int
            or defense_order["block"] < 0
        ):
            raise ValueError("configuration defense_order is invalid")
    if "study_environment_sha256" in value and not _is_digest(
        value["study_environment_sha256"]
    ):
        raise ValueError("configuration study_environment_sha256 is invalid")
    _validate_class_study_configuration(value)


def _validate_class_study_configuration(value: Mapping[str, Any]) -> None:
    class_keys = (
        _CLASS_STUDY_COMMON_CONFIGURATION_KEYS
        | _CLASS_STUDY_OPTIONAL_CONFIGURATION_KEYS
    )
    present = set(value) & class_keys
    if not present:
        return
    if not _CLASS_STUDY_COMMON_CONFIGURATION_KEYS <= set(value):
        raise ValueError("configuration class-study binding is incomplete")

    role = value["evidence_role"]
    if not isinstance(role, str) or role not in _CLASS_STUDY_ROLES:
        raise ValueError("configuration class-study evidence_role is invalid")
    study_id = value["class_study_id"]
    if not isinstance(study_id, str) or _CLASS_STUDY_ID.fullmatch(study_id) is None:
        raise ValueError("configuration class_study_id is invalid")

    for key in _CLASS_STUDY_DIGEST_CONFIGURATION_KEYS & set(value):
        if not _is_digest(value[key]):
            raise ValueError(f"configuration {key} is invalid")

    policy = value["public_origin_policy"]
    if not isinstance(policy, Mapping) or dict(policy) != _CLASS_STUDY_PUBLIC_ORIGIN_POLICY:
        raise ValueError("configuration public_origin_policy is invalid")

    successor_present = "class_study_successor_sha256" in value
    if (study_id == "classifier-multiorigin100-v1" and successor_present) or (
        study_id != "classifier-multiorigin100-v1" and not successor_present
    ):
        raise ValueError("configuration class-study successor binding is inconsistent")

    final_authority_keys = {
        "class_study_readiness_sha256",
        "class_study_historical_pre_snapshot_sha256",
    }
    observed_final_authority = final_authority_keys & set(value)
    expected_final_authority = final_authority_keys if role in {"canary", "formal"} else set()
    if observed_final_authority != expected_final_authority:
        raise ValueError("configuration class-study role authority is inconsistent")


def _validate_sample(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != _SAMPLE_KEYS:
        raise ValueError("experiment sample schema is invalid")
    _validate_component(value["sample_id"], "sample ID")
    for key in ("workload_id", "request_policy", "defense"):
        _validate_component(value[key], f"sample {key}")
    if not isinstance(value["runtime_kind"], str) or not value["runtime_kind"]:
        raise ValueError("sample runtime_kind is invalid")
    if (
        not isinstance(value["visit"], int)
        or isinstance(value["visit"], bool)
        or value["visit"] < 0
    ):
        raise ValueError("sample visit is invalid")
    if not isinstance(value["seed"], int) or isinstance(value["seed"], bool):
        raise ValueError("sample seed is invalid")
    if not isinstance(value["baseline"], bool):
        raise ValueError("sample baseline is invalid")
    expected_path = (
        f"samples/{value['workload_id']}/{value['request_policy']}/"
        f"visit-{value['visit']:03d}/{value['defense']}"
    )
    if value["path"] != expected_path:
        raise ValueError(f"sample path is not canonical: {value['path']!r}")
    if value["state"] not in SAMPLE_STATES:
        raise ValueError("sample state is invalid")
    if (
        not isinstance(value["attempts"], int)
        or isinstance(value["attempts"], bool)
        or value["attempts"] < 0
    ):
        raise ValueError("sample attempts is invalid")
    if not isinstance(value["eligible"], bool):
        raise ValueError("sample eligible is invalid")
    if value["failure"] is not None and not isinstance(value["failure"], Mapping):
        raise ValueError("sample failure is invalid")
    if not isinstance(value["diagnostics"], Mapping):
        raise ValueError("sample diagnostics are invalid")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, Mapping):
        raise ValueError("sample artifacts are invalid")
    prefix = value["path"] + "/"
    if any(
        not isinstance(path, str)
        or not path.startswith(prefix)
        or not _safe_relative(path)
        or not _is_digest(digest)
        for path, digest in artifacts.items()
    ):
        raise ValueError("sample artifact binding is invalid")
    if value["state"] == "accepted":
        if not artifacts or value["failure"] is not None:
            raise ValueError("accepted sample lacks clean artifact bindings")
    elif artifacts:
        raise ValueError("non-accepted sample cannot bind artifacts")
    if value["eligible"] and value["state"] != "accepted":
        raise ValueError("only accepted samples can be eligible")


def _summary(samples: Sequence[Mapping[str, Any]], *, passed: bool) -> dict[str, Any]:
    accepted = sum(sample["state"] == "accepted" for sample in samples)
    failed = sum(sample["state"] == "failed" for sample in samples)
    eligible = sum(sample["eligible"] is True for sample in samples)
    fully_eligible = bool(samples) and accepted == eligible == len(samples)
    return {
        "planned": len(samples),
        "accepted": accepted,
        "failed": failed,
        "eligible": eligible,
        "passed": bool(passed and fully_eligible),
    }


def resolved_sample_directory(
    root: Path,
    sample: Mapping[str, Any],
    *,
    require_directory: bool = False,
) -> Path:
    """Resolve a canonical sample path inside the authoritative samples tree."""

    relative = str(sample["path"])
    path = _resolved_authoritative_path(root, relative, scope="samples", label="sample")
    if require_directory and not path.is_dir():
        raise ValueError(f"accepted sample directory is missing or unsafe: {relative}")
    return path


def resolved_attempt_directory(root: Path, sample: Mapping[str, Any]) -> Path:
    """Resolve the current attempt path inside failures without trusting sample JSON."""

    _validate_component(sample.get("sample_id"), "sample ID")
    attempts = sample.get("attempts")
    if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 1:
        raise ValueError("sample attempt number is invalid")
    relative = f"failures/{sample['sample_id']}/attempt-{attempts:03d}"
    return _resolved_authoritative_path(root, relative, scope="failures", label="attempt")


def validate_durable_attempt_evidence(
    root: Path,
    experiment: Mapping[str, Any],
) -> None:
    """Reconcile durable launch counts with their exact terminal evidence.

    Legacy campaigns retain their established per-invocation retry semantics.
    BuFLO-study and schema-two class-study campaigns instead count physical
    launches across resumes, so their sealed failure tree must prove every
    consumed attempt without gaps, aliases, or unrecorded extra launches.
    """

    if not _requires_durable_attempt_evidence(experiment):
        return
    root = root.resolve()
    failures_root = root / "failures"
    if failures_root.is_symlink() or not failures_root.is_dir():
        raise ValueError(f"result has no regular failures directory: {root}")
    configuration = experiment.get("configuration")
    limits = configuration.get("limits") if isinstance(configuration, Mapping) else None
    max_attempts = limits.get("max_attempts") if isinstance(limits, Mapping) else None
    if type(max_attempts) is not int or max_attempts < 1:
        raise ValueError("durable attempt evidence has no valid configured attempt cap")
    samples = experiment.get("samples")
    if not isinstance(samples, Sequence) or isinstance(samples, (str, bytes)):
        raise TypeError("durable attempt evidence has no sample inventory")

    experiment_status = experiment.get("status")
    expected_sample_directories: set[str] = set()
    for sample in samples:
        if not isinstance(sample, Mapping):
            raise TypeError("durable attempt evidence contains a malformed sample")
        sample_id = sample.get("sample_id")
        _validate_component(sample_id, "sample ID")
        state = sample.get("state")
        attempts = sample.get("attempts")
        if state == "planned":
            if (
                experiment_status != "incomplete"
                or type(attempts) is not int
                or attempts != 0
                or sample.get("failure") is not None
            ):
                raise ValueError(
                    "sealed durable attempt evidence contains an invalid unlaunched sample"
                )
            sample_failures = failures_root / sample_id
            if sample_failures.exists() or sample_failures.is_symlink():
                raise ValueError(
                    f"unlaunched sample {sample_id} has unexpected failed-attempt evidence"
                )
            continue
        if state not in {"accepted", "failed"}:
            raise ValueError("sealed durable attempt evidence contains a nonterminal sample")
        if (
            type(attempts) is not int
            or attempts < 1
            or attempts > max_attempts
        ):
            raise ValueError("sample exceeds the durable physical-attempt budget")
        expected_attempt_count = attempts - 1 if state == "accepted" else attempts
        expected_attempts = {
            f"attempt-{attempt:03d}" for attempt in range(1, expected_attempt_count + 1)
        }
        sample_failures = failures_root / sample_id
        if expected_attempts:
            expected_sample_directories.add(sample_id)
            if sample_failures.is_symlink() or not sample_failures.is_dir():
                raise ValueError(
                    f"sample {sample_id} lacks its durable failed-attempt directory"
                )
            actual_attempts = _regular_child_directory_names(
                sample_failures,
                label=f"sample {sample_id} failed-attempt inventory",
            )
        else:
            if sample_failures.exists() or sample_failures.is_symlink():
                raise ValueError(
                    f"sample {sample_id} has unexpected durable failed-attempt evidence"
                )
            actual_attempts = set()
        if actual_attempts != expected_attempts:
            raise ValueError(
                f"sample {sample_id} durable failed-attempt inventory is not exact and contiguous"
            )
        current_failure: Mapping[str, Any] | None = None
        terminal_defense_failure_attempt: int | None = None
        for attempt_name in sorted(expected_attempts):
            attempt = sample_failures / attempt_name
            failure = _terminal_attempt_failure(attempt, sample_id=sample_id)
            attempt_number = int(attempt_name.removeprefix("attempt-"))
            if failure.get("type") in TERMINAL_DEFENSE_FAILURE_TYPES:
                terminal_defense_failure_attempt = attempt_number
            if attempt_name == f"attempt-{attempts:03d}":
                current_failure = failure
        if terminal_defense_failure_attempt is not None and (
            state != "failed" or terminal_defense_failure_attempt != attempts
        ):
            raise ValueError(
                f"sample {sample_id} retried after a terminal client defence/QCSD failure"
            )
        if state == "failed":
            recorded_failure = sample.get("failure")
            if (
                not isinstance(recorded_failure, Mapping)
                or not recorded_failure
                or current_failure != recorded_failure
            ):
                raise ValueError(
                    f"sample {sample_id} terminal failure differs from its attempt receipt"
                )

    actual_sample_directories = _regular_child_directory_names(
        failures_root,
        label="durable failed-sample inventory",
    )
    if actual_sample_directories != expected_sample_directories:
        raise ValueError("durable failed-sample inventory differs from experiment.json")


def _requires_durable_attempt_evidence(experiment: Mapping[str, Any]) -> bool:
    name = experiment.get("name")
    if isinstance(name, str) and name.startswith("buflo-study-v1-"):
        return True
    configuration = experiment.get("configuration")
    if not isinstance(configuration, Mapping):
        return False
    study_id = configuration.get("class_study_id")
    return isinstance(study_id, str) and _CLASS_STUDY_ID.fullmatch(study_id) is not None


def _regular_child_directory_names(directory: Path, *, label: str) -> set[str]:
    names: set[str] = set()
    for child in directory.iterdir():
        if child.is_symlink() or not child.is_dir():
            raise ValueError(f"{label} contains a non-directory entry: {child.name}")
        names.add(child.name)
    return names


def _terminal_attempt_failure(attempt: Path, *, sample_id: str) -> Mapping[str, Any]:
    attempt_receipt = attempt / "attempt.json"
    exception_receipt = attempt / "failure.json"
    for receipt in (attempt_receipt, exception_receipt):
        if receipt.is_symlink() or (receipt.exists() and not receipt.is_file()):
            raise ValueError(
                f"sample {sample_id} durable attempt has an unsafe terminal receipt"
            )
    receipts = [receipt for receipt in (attempt_receipt, exception_receipt) if receipt.is_file()]
    if len(receipts) != 1:
        raise ValueError(
            f"sample {sample_id} durable attempt must have exactly one terminal receipt"
        )
    receipt = receipts[0]
    value = load_json(receipt)
    if receipt == attempt_receipt:
        if not isinstance(value, Mapping) or value.get("success") is not False:
            raise ValueError(
                f"sample {sample_id} retained attempt.json is not a terminal failure"
            )
        failure = value.get("failure")
    else:
        failure = value
    if not isinstance(failure, Mapping) or not failure:
        raise ValueError(f"sample {sample_id} terminal failure receipt is invalid")
    return failure


def _sample_root(root: Path, sample: Mapping[str, Any]) -> Path:
    return resolved_sample_directory(root, sample, require_directory=True)


def _resolved_authoritative_path(root: Path, relative: str, *, scope: str, label: str) -> Path:
    root = root.resolve()
    candidate_relative = Path(relative)
    if (
        not _safe_relative(relative)
        or not candidate_relative.parts
        or candidate_relative.parts[0] != scope
    ):
        raise ValueError(f"unsafe {label} path: {relative}")
    scope_root = root / scope
    if scope_root.is_symlink() or not scope_root.is_dir():
        raise ValueError(f"result has no regular {scope} directory: {root}")
    current = root
    for part in candidate_relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"unsafe {label} path: {relative}")
    resolved = (root / candidate_relative).resolve()
    if not resolved.is_relative_to(scope_root.resolve()):
        raise ValueError(f"unsafe {label} path: {relative}")
    return resolved


def _regular_files(directory: Path, *, relative_to: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"authoritative evidence cannot contain symlinks: {path}")
        if path.is_file():
            files[path.relative_to(relative_to).as_posix()] = path
    return files


def _safe_relative(value: str) -> bool:
    path = Path(value)
    return (
        bool(value)
        and not path.is_absolute()
        and ".." not in path.parts
        and path.as_posix() == value
    )


def _validate_component(value: object, label: str) -> None:
    if not isinstance(value, str) or _PATH_COMPONENT.fullmatch(value) is None:
        raise ValueError(f"invalid {label}: {value!r}")


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None
