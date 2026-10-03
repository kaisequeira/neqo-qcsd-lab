from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .application_response_policy import (
    LEGACY_APPLICATION_RESPONSE_POLICY,
    application_response_policy,
    validate_application_responses,
)
from .experiment import (
    EVIDENCE_FILE,
    EXPERIMENT_FILE,
    RESULT_DIRECTORIES,
    checkpoint_experiment,
    interrupt_running_samples,
    load_experiment,
    resolved_sample_directory,
    validate_accepted_samples,
    validate_durable_attempt_evidence,
    validate_resume_fingerprints,
)
from .util import atomic_text, load_json, run, sha256_file


AUTHORITATIVE_DIRECTORIES = ("inputs", "samples", "failures")
OPTIONAL_AUTHORITATIVE_DIRECTORIES = ("kernel-tx-evidence",)
_ALLOWED_ROOT_ENTRIES = {
    EXPERIMENT_FILE,
    EVIDENCE_FILE,
    *RESULT_DIRECTORIES,
    *OPTIONAL_AUTHORITATIVE_DIRECTORIES,
}
_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class VerifiedResult:
    root: Path
    experiment: dict[str, Any]
    checksums: dict[str, str]
    accepted_samples: dict[str, dict[str, str]]

    def as_dict(self) -> dict[str, Any]:
        """Return a concise, JSON-serializable CLI verification receipt."""

        return {
            "valid": True,
            "root": str(self.root),
            "name": self.experiment["name"],
            "purpose": self.experiment["purpose"],
            "status": self.experiment["status"],
            "authoritative_files": len(self.checksums),
            "accepted_samples": len(self.accepted_samples),
        }


def authoritative_files(root: Path) -> dict[str, Path]:
    """Return the exact files governed by ``evidence.sha256``."""

    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"result directory does not exist: {root}")
    unknown = sorted(path.name for path in root.iterdir() if path.name not in _ALLOWED_ROOT_ENTRIES)
    if unknown:
        raise ValueError(f"unknown top-level result entries: {', '.join(unknown)}")
    experiment = root / EXPERIMENT_FILE
    if not experiment.is_file() or experiment.is_symlink():
        raise ValueError(f"result has no regular {EXPERIMENT_FILE}: {root}")
    result = {EXPERIMENT_FILE: experiment}
    for name in AUTHORITATIVE_DIRECTORIES:
        directory = root / name
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError(f"result has no regular {name}/ directory: {root}")
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise ValueError(f"authoritative evidence cannot contain symlinks: {path}")
            if path.is_file():
                result[path.relative_to(root).as_posix()] = path
    for name in OPTIONAL_AUTHORITATIVE_DIRECTORIES:
        directory = root / name
        if not directory.exists():
            continue
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError(f"optional evidence path is not a regular directory: {directory}")
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise ValueError(f"authoritative evidence cannot contain symlinks: {path}")
            if path.is_file():
                result[path.relative_to(root).as_posix()] = path
    derived = root / "derived"
    if derived.exists() and (not derived.is_dir() or derived.is_symlink()):
        raise ValueError("derived must be a regular directory when present")
    return dict(sorted(result.items()))


def seal_result(root: Path) -> dict[str, str]:
    """Create the deterministic final evidence index for a terminal result."""

    root = root.resolve()
    if (root / EVIDENCE_FILE).exists():
        return verify_result(root).checksums
    experiment = load_experiment(root)
    if experiment["status"] not in {"complete", "incomplete"}:
        raise ValueError("only a terminal experiment can be sealed")
    validate_resume_fingerprints(root, experiment=experiment)
    _validate_frozen_contract(root, experiment, allow_historical_research_bundle=False)
    validate_accepted_samples(root, experiment)
    validate_durable_attempt_evidence(root, experiment)
    checksums = {
        relative: sha256_file(path) for relative, path in authoritative_files(root).items()
    }
    atomic_text(root / EVIDENCE_FILE, _format_checksums(checksums))
    return checksums


def reseal_result(root: Path) -> dict[str, str]:
    """Seal an incomplete result after a successful resume reaches a terminal state."""

    if (root / EVIDENCE_FILE).exists():
        raise ValueError("result is already sealed")
    return seal_result(root)


def verify_result(root: Path) -> VerifiedResult:
    """Verify exact authoritative coverage, hashes, schema, and sample bindings."""

    root = root.resolve()
    seal = root / EVIDENCE_FILE
    checksums = _read_checksums(root, seal)
    actual_files = authoritative_files(root)
    listed = set(checksums)
    actual = set(actual_files)
    if listed != actual:
        missing = sorted(listed - actual)
        extra = sorted(actual - listed)
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"extra {', '.join(extra)}")
        raise ValueError(
            "evidence index does not exactly cover authoritative files: " + "; ".join(details)
        )
    for relative, expected in checksums.items():
        if sha256_file(actual_files[relative]) != expected:
            raise ValueError(f"modified authoritative evidence: {relative}")

    experiment = load_experiment(root)
    if experiment["status"] not in {"complete", "incomplete"}:
        raise ValueError("sealed experiment is not terminal")
    validate_resume_fingerprints(root, experiment=experiment)
    _validate_frozen_contract(root, experiment, allow_historical_research_bundle=True)
    accepted = validate_accepted_samples(root, experiment)
    validate_durable_attempt_evidence(root, experiment)
    _validate_endpoint_capture_replay(root, experiment)
    return VerifiedResult(root, experiment, checksums, accepted)


def prepare_resume(
    root: Path,
    *,
    expected_source: Mapping[str, Any] | None = None,
    expected_configuration: Mapping[str, Any] | None = None,
    expected_input_digest: str | None = None,
) -> dict[str, Any]:
    """Validate a result for resume and retire a verified incomplete seal if present."""

    root = root.resolve()
    seal = root / EVIDENCE_FILE
    if seal.exists():
        verified = verify_result(root)
        experiment = verified.experiment
        if experiment["status"] == "complete":
            raise ValueError("completed result cannot be resumed")
        validate_resume_fingerprints(
            root,
            experiment=experiment,
            expected_source=expected_source,
            expected_configuration=expected_configuration,
            expected_input_digest=expected_input_digest,
        )
        _validate_frozen_contract(
            root,
            experiment,
            allow_historical_research_bundle=False,
        )
        # The seal is retired only after every read-only preflight succeeds.
        seal.unlink()
        experiment["status"] = "running"
        experiment["completed_at"] = None
        experiment["summary"]["passed"] = False
    else:
        experiment = load_experiment(root)
        if experiment["status"] != "running":
            raise ValueError("unsealed terminal result cannot be resumed")
        validate_resume_fingerprints(
            root,
            experiment=experiment,
            expected_source=expected_source,
            expected_configuration=expected_configuration,
            expected_input_digest=expected_input_digest,
        )
        _validate_frozen_contract(
            root,
            experiment,
            allow_historical_research_bundle=False,
        )
        # First validate every accepted binding and reject unbound files
        # anywhere except the canonical path of the one in-progress sample.
        # Promotion precedes the accepted checkpoint, so that exact directory
        # can legitimately contain a partial or complete-but-unbound move after
        # interruption.  Only after the read-only validation succeeds may it be
        # discarded as part of the interrupted attempt.
        validate_accepted_samples(root, experiment, allow_running_artifacts=True)
        _discard_running_sample_artifacts(root, experiment)
        validate_accepted_samples(root, experiment)
    interrupt_running_samples(experiment)
    checkpoint_experiment(root, experiment)
    return experiment


def _discard_running_sample_artifacts(root: Path, experiment: Mapping[str, Any]) -> None:
    samples_root = (root / "samples").resolve()
    running = [sample for sample in experiment["samples"] if sample["state"] == "running"]
    if len(running) > 1:
        raise ValueError("sequential experiment has multiple running samples")
    for sample in running:
        sample_root = resolved_sample_directory(root, sample)
        if sample_root.exists() or sample_root.is_symlink():
            if (
                sample_root.is_symlink()
                or not sample_root.is_relative_to(samples_root)
                or not sample_root.is_dir()
            ):
                raise ValueError(f"interrupted sample path is unsafe: {sample['path']}")
            shutil.rmtree(sample_root)
        sample_id = sample.get("sample_id")
        if isinstance(sample_id, str):
            sidecar = root / "kernel-tx-evidence" / sample_id
            if sidecar.exists() or sidecar.is_symlink():
                if sidecar.is_symlink() or not sidecar.is_dir():
                    raise ValueError("interrupted kernel-TX sidecar path is unsafe")
                shutil.rmtree(sidecar)
    evidence_root = root / "kernel-tx-evidence"
    if evidence_root.is_dir() and not evidence_root.is_symlink():
        try:
            evidence_root.rmdir()
        except OSError:
            pass


def retire_seal_for_resume(
    root: Path,
    *,
    expected_source: Mapping[str, Any] | None = None,
    expected_configuration: Mapping[str, Any] | None = None,
    expected_input_digest: str | None = None,
) -> dict[str, Any]:
    """Explicit name retained for callers that distinguish resume preflight."""

    if not (root / EVIDENCE_FILE).is_file():
        raise ValueError("result is not sealed")
    return prepare_resume(
        root,
        expected_source=expected_source,
        expected_configuration=expected_configuration,
        expected_input_digest=expected_input_digest,
    )


def _read_checksums(root: Path, seal: Path) -> dict[str, str]:
    try:
        lines = seal.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as error:
        raise ValueError(f"result is not sealed: {root}") from error
    checksums: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
        try:
            digest, relative = line.split("  ", 1)
        except ValueError as error:
            raise ValueError(f"invalid evidence index line {line_number}") from error
        path = Path(relative)
        if (
            _DIGEST.fullmatch(digest) is None
            or not relative
            or path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != relative
            or relative == EVIDENCE_FILE
            or relative == "derived"
            or relative.startswith("derived/")
        ):
            raise ValueError(f"invalid evidence index line {line_number}")
        resolved = (root / path).resolve()
        if not resolved.is_relative_to(root):
            raise ValueError(f"evidence path escapes result: {relative}")
        if relative in checksums:
            raise ValueError(f"duplicate evidence index entry: {relative}")
        checksums[relative] = digest
    if not checksums:
        raise ValueError(f"empty evidence index: {root}")
    return checksums


def _format_checksums(checksums: Mapping[str, str]) -> str:
    return "".join(f"{checksums[path]}  {path}\n" for path in sorted(checksums))


_ENDPOINT_REPLAY_SCRIPT = """import json,sys
from pathlib import Path
source = Path(sys.argv[2])
sys.path.insert(0, str(source))
from qcsd_lab import verification
root = Path(sys.argv[1])
image = sys.argv[3]
verifier = source / 'qcsd_lab/verification.py'
if Path(verification.__file__).resolve() != verifier.resolve():
    raise ValueError('endpoint replay did not import the explicitly mounted verifier')
if verification.sha256_file(verifier) != sys.argv[4]:
    raise ValueError('endpoint replay verifier source bytes changed')
experiment = verification.load_experiment(root)
if experiment.get('source', {}).get('image_digest') != image:
    raise ValueError('endpoint replay tool image differs from sealed runtime source')
checked = verification._replay_endpoint_captures_locally(root, experiment)
print(json.dumps({'schema_version': 1, 'valid': True, 'tool_image_digest': image,
                  'root': str(root), 'verifier_source': str(verifier),
                  'verifier_sha256': sys.argv[4], 'sample_ids': checked},
                 sort_keys=True, allow_nan=False))
"""


def _endpoint_capture_replay_marker(run: Any, sample: Mapping[str, Any]) -> bool:
    endpoints = run.get("endpoints") if isinstance(run, Mapping) else None
    native_marker = isinstance(endpoints, list) and any(
        isinstance(endpoint, Mapping) and "receive_lifecycle" in endpoint
        for endpoint in endpoints
    )
    diagnostics = sample.get("diagnostics")
    capture = diagnostics.get("capture") if isinstance(diagnostics, Mapping) else None
    recorded = capture.get("direct_runner_reconciliation") if isinstance(capture, Mapping) else None
    return native_marker or isinstance(recorded, Mapping) and "direct_tail_policy" in recorded


def _validate_endpoint_capture_replay(root: Path, experiment: Mapping[str, Any]) -> None:
    """Replay locally or once per result in its immutable offline tool image.

    The mounted current verifier supplies all replay logic. The image supplies
    its installed Python dependencies and TShark, without gaining authority
    for that new source. Host evidence seals and frozen-source policy checks
    have already succeeded before this transport is considered.
    """
    sample_ids = [sample["sample_id"] for sample in experiment["samples"]
                  if sample["state"] == "accepted" and _endpoint_capture_replay_marker(
                      load_json(resolved_sample_directory(root, sample) / "neqo/run.json"), sample)]
    if not sample_ids:
        return
    if shutil.which("tshark") is not None:
        _replay_endpoint_captures_locally(root, experiment)
        return
    source = experiment.get("source")
    image = source.get("image_digest") if isinstance(source, Mapping) else None
    if not isinstance(image, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
        raise ValueError("endpoint replay without host TShark requires its immutable source image digest")
    root = root.resolve()
    verifier = Path(__file__).resolve()
    module_source = verifier.parent.parent
    verifier_hash = sha256_file(verifier)
    command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
               "--tmpfs", "/tmp:rw,nosuid,nodev,noexec",
               "--volume", f"{root}:{root}:ro", "--volume", f"{module_source}:{module_source}:ro",
               "--entrypoint", "/opt/qcsd-venv/bin/python3", image, "-I", "-B", "-c",
               _ENDPOINT_REPLAY_SCRIPT, str(root), str(module_source), image, verifier_hash]
    execution = run(command, cwd=root)
    expected = {"schema_version": 1, "valid": True, "tool_image_digest": image, "root": str(root),
                "verifier_source": str(verifier), "verifier_sha256": verifier_hash, "sample_ids": sample_ids}
    try:
        recorded = json.loads(execution.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("endpoint replay tool transport returned no checked JSON status") from error
    if (execution.returncode != 0
        or json.dumps(recorded, sort_keys=True, separators=(",", ":"), allow_nan=False)
        != json.dumps(expected, sort_keys=True, separators=(",", ":"), allow_nan=False)):
        raise ValueError("endpoint replay tool transport status differs from its immutable request")


def _replay_endpoint_captures_locally(root: Path, experiment: Mapping[str, Any]) -> list[str]:
    """Reopen prospective endpoint receipts from immutable PCAP/Native bytes.

    The accepted sample has no standalone observer CSV. Recreate that exact
    six-column sequence outside the evidence tree, using the sealed Native
    tuple inventory and actual PCAP timestamps. Either prospective marker
    requires replay, so removing one cannot turn new evidence into a legacy
    four-column receipt. Historical samples with neither marker are unchanged.
    """
    from .capture import extract_trace, write_normalized_trace
    from .fidelity import (
        reconcile_direct_runner_artifacts,
        validate_primary_capture_clock_integrity,
    )

    checked: list[str] = []
    for sample in experiment["samples"]:
        if sample["state"] != "accepted":
            continue
        directory = resolved_sample_directory(root, sample)
        run_path, packets_path = directory / "neqo/run.json", directory / "neqo/packets.csv"
        run = load_json(run_path)
        endpoints = run.get("endpoints") if isinstance(run, Mapping) else None
        diagnostics = sample.get("diagnostics")
        capture = diagnostics.get("capture") if isinstance(diagnostics, Mapping) else None
        recorded = capture.get("direct_runner_reconciliation") if isinstance(capture, Mapping) else None
        if not _endpoint_capture_replay_marker(run, sample):
            continue
        if (not isinstance(capture, Mapping) or not isinstance(recorded, Mapping)
            or capture.get("capture_path") != "capture.pcapng"
            or capture.get("primary") is not True or capture.get("valid") is not True):
            raise ValueError("endpoint capture replay requires its accepted primary diagnostics")
        pcap = directory / "capture.pcapng"
        if capture.get("capture_sha256") != sha256_file(pcap):
            raise ValueError("endpoint capture replay PCAP hash differs from diagnostics")
        if not isinstance(endpoints, list) or not endpoints:
            raise ValueError("endpoint capture replay requires Native endpoint tuples")
        validate_primary_capture_clock_integrity(
            capture, require_pairing_uncertainty=True, require_timestamp_type=True,
            label="endpoint capture replay",
        )
        trace = extract_trace(pcap, endpoints)
        if (not trace or type(capture.get("packet_count")) is not int
            or capture["packet_count"] != len(trace)
            or any(type(packet.connection) is not int or packet.connection < 0
                   or type(packet.timestamp_unix_ns) is not int or packet.timestamp_unix_ns <= 0
                   for packet in trace)):
            raise ValueError("endpoint capture replay lacks exact six-column PCAP attribution")
        with tempfile.TemporaryDirectory(prefix="qcsd-endpoint-replay-") as temporary:
            trace_path = Path(temporary) / "direct.csv"
            write_normalized_trace(trace_path, trace)
            reconciliation = reconcile_direct_runner_artifacts(
                run_path, packets_path, trace_path,
                timestamp_tolerance_ns=recorded["direct_timestamp_tolerance_ns"],
                clock_anchors=capture["capture_clock_anchors"],
            )
        expected = {
            **reconciliation.metrics,
            "evidence_eligible": reconciliation.evidence_eligible,
            "limitations": list(reconciliation.limitations),
        }
        if (reconciliation.evidence_eligible is not True
            or json.dumps(recorded, sort_keys=True, separators=(",", ":"), allow_nan=False)
            != json.dumps(expected, sort_keys=True, separators=(",", ":"), allow_nan=False)):
            raise ValueError("endpoint capture replay differs from recorded reconciliation metrics")
        checked.append(sample["sample_id"])
    return checked


def _validate_frozen_contract(
    root: Path,
    experiment: dict[str, Any],
    *,
    allow_historical_research_bundle: bool,
) -> None:
    # Kept as a lazy import because the orchestrator deliberately imports
    # verification only at command boundaries.
    from .orchestrator import validate_frozen_experiment_contract

    validate_frozen_experiment_contract(
        root,
        experiment,
        allow_historical_research_bundle=allow_historical_research_bundle,
    )
    _validate_policy_application_responses(root, experiment)


def _validate_policy_application_responses(root: Path, experiment: Mapping[str, Any]) -> None:
    """Reopen prepared-source policies for accepted samples, including baseline."""

    from .capture_acceptance_policy import validate_buflo_source_binding, validate_tamaraw_source_binding, validate_front_source_binding, validate_terminal_primary_source_binding

    prepared_by_id: dict[str, dict[str, Any]] = {}
    for workload in experiment["configuration"]["workloads"]:
        relative = workload.get("manifest")
        if relative is None:
            continue
        path = root / relative
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("prepared application policy input escapes result")
        prepared = load_json(path)
        if (application_response_policy(prepared) != LEGACY_APPLICATION_RESPONSE_POLICY
            and sha256_file(path) != workload.get("sha256")):
            raise ValueError("prepared application policy input hash differs from configuration")
        prepared_by_id[workload["id"]] = prepared
    if not prepared_by_id:
        return
    for sample in experiment["samples"]:
        if sample["state"] != "accepted" or sample["workload_id"] not in prepared_by_id:
            continue
        run_path = resolved_sample_directory(root, sample) / "neqo/run.json"
        if run_path.is_symlink() or not run_path.is_file():
            raise ValueError("accepted policy sample lacks a regular runner receipt")
        prepared = prepared_by_id[sample["workload_id"]]
        run = load_json(run_path)
        validate_buflo_source_binding(prepared, run, runner_directory=run_path.parent)
        validate_tamaraw_source_binding(prepared, run)
        validate_front_source_binding(prepared, run)
        validate_terminal_primary_source_binding(prepared, run, runner_directory=run_path.parent)
        if application_response_policy(prepared) != LEGACY_APPLICATION_RESPONSE_POLICY:
            validate_application_responses(prepared, run, require_identity=True)
