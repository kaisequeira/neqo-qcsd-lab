#!/usr/bin/env python3
"""Supervise the canonical class-study acquisition without owning its state.

This host-side process deliberately has no third-party or ``qcsd_lab`` import.
The acquisition checkpoint remains the only resume authority: this process
validates it, asks the existing coordinator for status, invokes bounded due
work, and otherwise sleeps only as far as the next five-second heartbeat.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

STUDY_ID = "classifier-multiorigin100-v1"
CANDIDATE_COUNT = 600
SCHEMA_VERSION = 1
CATALOGUE_TYPE = "qcsd-class-study-candidate-catalogue"
PROVENANCE_TYPE = "qcsd-class-study-acquisition-provenance"
CHECKPOINT_TYPE = "qcsd-class-study-acquisition-checkpoint"
FOUNDATION_TYPE = "qcsd-class-study-foundation-attestation"
ACTION_RESULT_TYPE = "qcsd-class-study-coordinator-result"
PREPARE_IMAGE_ENV = "QCSD_LAB_PREPARE_IMAGE"
CONTAINER_ACQUISITION_ROOT = f"/lab/artifacts/{STUDY_ID}-acquisition"
MAX_CANDIDATES = CANDIDATE_COUNT
ACQUISITION_TIMEOUT_MS = 60_000
MAX_PROBE_ATTEMPTS = 3
PENDING_BASELINE_GUARD_MS = MAX_PROBE_ATTEMPTS * ACQUISITION_TIMEOUT_MS + 10_000
DEFAULT_HEARTBEAT_SECONDS = 5.0
SOURCE_RECHECK_SECONDS = 60.0
LOCK_ENV = "QCSD_CLASS_ACQUISITION_LOCK_FD"
CONTAINER_NAME = "qcsd-classifier-multiorigin100-v1-acquisition-run"
CONTAINER_LABELS = {
    "org.qcsd.study": STUDY_ID,
    "org.qcsd.role": "acquisition-run",
    "org.qcsd.acquisition-root": CONTAINER_ACQUISITION_ROOT,
}
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_HOST_ENV_KEYS = {
    "DOCKER_CERT_PATH",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "DOCKER_HOST",
    "DOCKER_TLS_VERIFY",
    "HOME",
    "LANG",
    "LOGNAME",
    "PATH",
    "SSH_AUTH_SOCK",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TMPDIR",
    "TZ",
    "USER",
    "XDG_RUNTIME_DIR",
}
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CANDIDATE_ID_RE = re.compile(r"tranco-[0-9]{7}\Z")

_RECEIPT_KEYS = {"schema_version", "receipt_type", "payload_sha256", "payload"}
_CATALOGUE_PAYLOAD_KEYS = {
    "study_id",
    "catalogue_schema_version",
    "tranco",
    "selection",
    "candidates",
}
_PROVENANCE_PAYLOAD_KEYS = {
    "study_id",
    "acquisition_schema_version",
    "candidate_catalogue_sha256",
    "candidate_catalogue_payload_sha256",
    "candidate_count",
    "foundation_attestation",
    "started_at",
    "image_digest",
    "source",
    "browser_tool",
    "navigation_implementation",
    "registrable_domain_policy",
    "domain_safety_policy",
    "domain_safety_policy_sha256",
    "origin_policy",
    "eligibility_inputs",
    "prohibited_inputs",
}
_SOURCE_KEYS = {
    "image_digest",
    "lab_commit",
    "lab_dirty",
    "lab_patch_sha256",
    "neqo_commit",
    "neqo_pinned_commit",
    "neqo_dirty",
    "neqo_patch_sha256",
}
_ORIGIN_POLICY = {
    "max_passes": 8,
    "max_origins": 32,
    "max_observed_audit_origins": 512,
    "max_navigation_attempts": MAX_PROBE_ATTEMPTS,
    "max_probe_attempts_per_window": MAX_PROBE_ATTEMPTS,
    "pending_baseline_guard_ms": PENDING_BASELINE_GUARD_MS,
    "navigation_seed_scope": "page-specific-document-navigation-origins-only",
    "resource_graph_scope": "iteratively-converged-public-https-get-origins",
    "dns": "all-answers-global-and-browser-host-resolver-pinned",
    "neqo": "QCSD_PUBLIC_ORIGIN_ONLY-resolve-once-connect-exact-address",
}
_CHECKPOINT_PAYLOAD_KEYS = {
    "provenance_sha256",
    "candidate_catalogue_sha256",
    "candidates",
}
_STATUS_KEYS = {
    "candidate_count",
    "terminal_count",
    "pending_count",
    "probing_count",
    "due_now_count",
    "missed_window_count",
    "recovery_required_count",
    "pending_start_blocked",
    "work_due_now",
    "complete",
    "next_due",
}
_STATUS_DETAIL_KEYS = _STATUS_KEYS | {"valid", "runner_root", "gate"}
_RUN_DETAIL_KEYS = _STATUS_KEYS | {
    "valid",
    "runner_root",
    "bounded_candidates",
    "runner_slept",
}
_ACTION_KEYS = {
    "schema_version",
    "artifact_type",
    "action",
    "status",
    "details",
    "blockers",
}
_EXPECTED_WINDOWS = [
    {"probe_id": "t+30s", "target_ms": 30_000, "earliest_ms": 25_000, "latest_ms": 35_000},
    {
        "probe_id": "t+24h",
        "target_ms": 86_400_000,
        "earliest_ms": 85_500_000,
        "latest_ms": 87_300_000,
    },
    {
        "probe_id": "t+72h",
        "target_ms": 259_200_000,
        "earliest_ms": 258_300_000,
        "latest_ms": 260_100_000,
    },
]


class WatchError(RuntimeError):
    """The supervisor cannot safely continue from the current evidence."""


class CommandRunner(Protocol):
    def __call__(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        lock_fd: int,
    ) -> subprocess.CompletedProcess[str]: ...


@dataclass(frozen=True)
class WatchPaths:
    """The one fresh v1 acquisition layout accepted by the supervisor."""

    lab_root: Path
    launcher: Path
    candidate_catalogue: Path
    acquisition_root: Path
    stability_root: Path
    workload_root: Path

    @classmethod
    def from_lab_root(cls, root: Path) -> WatchPaths:
        lab_root = Path(os.path.abspath(root))
        return cls(
            lab_root=lab_root,
            launcher=lab_root / "qcsd-lab",
            candidate_catalogue=(
                lab_root
                / "config/class-study/v1"
                / f"{STUDY_ID}-candidates.json"
            ),
            acquisition_root=lab_root / "artifacts" / f"{STUDY_ID}-acquisition",
            stability_root=lab_root / "artifacts" / f"{STUDY_ID}-stability",
            workload_root=lab_root / "config/workloads",
        )

    @classmethod
    def from_script(cls) -> WatchPaths:
        return cls.from_lab_root(Path(__file__).resolve(strict=True).parents[1])

    @property
    def provenance(self) -> Path:
        return self.acquisition_root / "provenance.json"

    @property
    def checkpoint(self) -> Path:
        return self.acquisition_root / "checkpoint.json"

    @property
    def mutation_lock(self) -> Path:
        return self.acquisition_root / ".class-study-acquisition.lock"


@dataclass(frozen=True)
class AcquisitionBinding:
    prepare_image: str
    catalogue_sha256: str
    provenance_sha256: str
    candidate_ids: frozenset[str]
    source: Mapping[str, Any]


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise WatchError("evidence contains a non-canonical JSON value") from error


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise WatchError(f"cannot hash evidence file: {path}") from error
    return digest.hexdigest()


def _safe_host_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    values = os.environ if source is None else source
    return {
        key: value
        for key, value in values.items()
        if key in _HOST_ENV_KEYS or key.startswith("LC_")
    }


def _require_regular_path(path: Path, *, root: Path, directory: bool, label: str) -> Path:
    root = Path(os.path.abspath(root))
    candidate = Path(os.path.abspath(path))
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise WatchError(f"{label} escapes the canonical Lab root") from error
    current = root
    if root.is_symlink() or not root.is_dir():
        raise WatchError("canonical Lab root is not a regular directory")
    for component in relative.parts:
        current /= component
        if current.is_symlink():
            raise WatchError(f"{label} path contains a symlink: {current}")
    if directory:
        if not candidate.is_dir():
            raise WatchError(f"{label} is not an existing directory: {candidate}")
    elif not candidate.is_file():
        raise WatchError(f"{label} is not an existing regular file: {candidate}")
    return candidate


def _load_canonical_receipt(path: Path, *, receipt_type: str, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise WatchError(f"{label} is not valid UTF-8 JSON: {path}") from error
    if not isinstance(value, dict) or set(value) != _RECEIPT_KEYS:
        raise WatchError(f"{label} receipt envelope differs from the contract")
    if raw != _canonical_json_bytes(value):
        raise WatchError(f"{label} is not canonically encoded")
    if value["schema_version"] != SCHEMA_VERSION or value["receipt_type"] != receipt_type:
        raise WatchError(f"{label} identifies another schema or receipt type")
    payload = value["payload"]
    if not isinstance(payload, dict):
        raise WatchError(f"{label} payload is not an object")
    claimed = value["payload_sha256"]
    if not isinstance(claimed, str) or claimed != _sha256_bytes(_canonical_json_bytes(payload)):
        raise WatchError(f"{label} payload SHA-256 does not verify")
    return value


def _container_binding_path(value: str, *, paths: WatchPaths, label: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/lab/"):
        raise WatchError(f"{label} is not a canonical /lab binding")
    relative = Path(value.removeprefix("/lab/"))
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or str(relative) != value.removeprefix("/lab/")
    ):
        raise WatchError(f"{label} is not a normalised /lab binding")
    return _require_regular_path(
        paths.lab_root / relative,
        root=paths.lab_root,
        directory=False,
        label=label,
    )


def _validate_catalogue(paths: WatchPaths) -> tuple[dict[str, Any], frozenset[str], str]:
    catalogue = _load_canonical_receipt(
        paths.candidate_catalogue,
        receipt_type=CATALOGUE_TYPE,
        label="candidate catalogue",
    )
    payload = catalogue["payload"]
    if set(payload) != _CATALOGUE_PAYLOAD_KEYS:
        raise WatchError("candidate catalogue payload fields differ from the v1 contract")
    if payload["study_id"] != STUDY_ID or payload["catalogue_schema_version"] != 1:
        raise WatchError("candidate catalogue identifies another study")
    candidates = payload["candidates"]
    if not isinstance(candidates, list) or len(candidates) != CANDIDATE_COUNT:
        raise WatchError(
            f"candidate catalogue does not contain exactly {CANDIDATE_COUNT} candidates"
        )
    candidate_ids: list[str] = []
    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) != {
            "candidate_id",
            "domain",
            "rank",
            "stratum",
            "eligible",
        }:
            raise WatchError("candidate catalogue contains a malformed candidate")
        candidate_id = candidate["candidate_id"]
        if not isinstance(candidate_id, str) or _CANDIDATE_ID_RE.fullmatch(candidate_id) is None:
            raise WatchError("candidate catalogue contains an invalid candidate identity")
        if candidate["eligible"] is not False:
            raise WatchError("candidate catalogue contains a post-acquisition outcome")
        candidate_ids.append(candidate_id)
    if len(set(candidate_ids)) != CANDIDATE_COUNT:
        raise WatchError("candidate catalogue candidate identities are not unique")
    return catalogue, frozenset(candidate_ids), _sha256_file(paths.candidate_catalogue)


def _validate_foundation(binding: Any, *, paths: WatchPaths) -> None:
    if not isinstance(binding, dict) or set(binding) != {"path", "sha256"}:
        raise WatchError("acquisition foundation binding is malformed")
    claimed = binding["sha256"]
    if not isinstance(claimed, str) or _SHA256_RE.fullmatch(claimed) is None:
        raise WatchError("acquisition foundation SHA-256 is malformed")
    foundation_path = _container_binding_path(
        binding["path"], paths=paths, label="acquisition foundation"
    )
    if _sha256_file(foundation_path) != claimed:
        raise WatchError("acquisition foundation binding does not verify")
    _load_canonical_receipt(
        foundation_path,
        receipt_type=FOUNDATION_TYPE,
        label="acquisition foundation",
    )


def _validate_immutable_binding(paths: WatchPaths) -> AcquisitionBinding:
    _require_regular_path(paths.launcher, root=paths.lab_root, directory=False, label="launcher")
    if not os.access(paths.launcher, os.X_OK):
        raise WatchError(f"launcher is not executable: {paths.launcher}")
    _require_regular_path(
        paths.candidate_catalogue,
        root=paths.lab_root,
        directory=False,
        label="candidate catalogue",
    )
    _require_regular_path(
        paths.acquisition_root,
        root=paths.lab_root,
        directory=True,
        label="acquisition root",
    )
    _require_regular_path(
        paths.stability_root,
        root=paths.lab_root,
        directory=True,
        label="stability root",
    )
    _require_regular_path(
        paths.workload_root,
        root=paths.lab_root,
        directory=True,
        label="workload root",
    )
    _require_regular_path(
        paths.provenance,
        root=paths.lab_root,
        directory=False,
        label="acquisition provenance",
    )
    catalogue, candidate_ids, catalogue_sha256 = _validate_catalogue(paths)
    provenance = _load_canonical_receipt(
        paths.provenance,
        receipt_type=PROVENANCE_TYPE,
        label="acquisition provenance",
    )
    payload = provenance["payload"]
    if set(payload) != _PROVENANCE_PAYLOAD_KEYS:
        raise WatchError("acquisition provenance payload fields differ from the v1 contract")
    if (
        payload["study_id"] != STUDY_ID
        or payload["acquisition_schema_version"] != SCHEMA_VERSION
        or payload["candidate_count"] != CANDIDATE_COUNT
        or payload["candidate_catalogue_sha256"] != catalogue_sha256
        or payload["candidate_catalogue_payload_sha256"] != catalogue["payload_sha256"]
        or payload["origin_policy"] != _ORIGIN_POLICY
    ):
        raise WatchError("acquisition provenance is bound to another study or catalogue")
    image = payload["image_digest"]
    if not isinstance(image, str) or _IMAGE_RE.fullmatch(image) is None:
        raise WatchError("acquisition provenance does not bind an exact prepare image SHA-256")
    source = payload["source"]
    if (
        not isinstance(source, dict)
        or set(source) != _SOURCE_KEYS
        or source.get("image_digest") != image
        or not isinstance(source.get("lab_commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", source["lab_commit"]) is None
        or source.get("lab_dirty") is not False
        or source.get("lab_patch_sha256") != EMPTY_SHA256
        or not isinstance(source.get("neqo_commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", source["neqo_commit"]) is None
        or source.get("neqo_pinned_commit") != source.get("neqo_commit")
        or source.get("neqo_dirty") is not False
        or source.get("neqo_patch_sha256") != EMPTY_SHA256
    ):
        raise WatchError("acquisition provenance does not bind an exact clean source checkout")
    _validate_foundation(payload["foundation_attestation"], paths=paths)
    provenance_sha256 = _sha256_file(paths.provenance)
    binding = AcquisitionBinding(
        prepare_image=image,
        catalogue_sha256=catalogue_sha256,
        provenance_sha256=provenance_sha256,
        candidate_ids=candidate_ids,
        source=dict(source),
    )
    return binding


def _validate_acquisition_binding(paths: WatchPaths) -> AcquisitionBinding:
    binding = _validate_immutable_binding(paths)
    _validate_checkpoint(paths, binding)
    return binding


def _validate_checkpoint(paths: WatchPaths, binding: AcquisitionBinding) -> str:
    _require_regular_path(
        paths.checkpoint,
        root=paths.lab_root,
        directory=False,
        label="acquisition checkpoint",
    )
    checkpoint = _load_canonical_receipt(
        paths.checkpoint,
        receipt_type=CHECKPOINT_TYPE,
        label="acquisition checkpoint",
    )
    payload = checkpoint["payload"]
    if set(payload) != _CHECKPOINT_PAYLOAD_KEYS:
        raise WatchError("acquisition checkpoint payload fields differ from the v1 contract")
    if (
        payload["provenance_sha256"] != binding.provenance_sha256
        or payload["candidate_catalogue_sha256"] != binding.catalogue_sha256
    ):
        raise WatchError("acquisition checkpoint evidence bindings do not verify")
    states = payload["candidates"]
    if not isinstance(states, dict) or set(states) != binding.candidate_ids:
        raise WatchError("acquisition checkpoint candidate set differs from the catalogue")
    if any(not isinstance(state, dict) for state in states.values()):
        raise WatchError("acquisition checkpoint contains a non-object candidate state")
    return _sha256_file(paths.checkpoint)


def _git_text(paths: WatchPaths, *arguments: str, cwd: Path | None = None) -> str:
    try:
        completed = subprocess.run(
            ("git", "-C", str(cwd or paths.lab_root), *arguments),
            cwd=paths.lab_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
            env=_safe_host_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WatchError(f"cannot verify host source checkout: {error}") from error
    if completed.returncode != 0:
        raise WatchError(
            "cannot verify host source checkout: "
            + (completed.stderr.strip() or f"git exited {completed.returncode}")
        )
    return completed.stdout.strip()


def _validate_host_source(paths: WatchPaths, binding: AcquisitionBinding) -> None:
    """Fail closed if either host checkout drifts from frozen provenance."""

    source = binding.source
    lab_head = _git_text(paths, "rev-parse", "HEAD")
    neqo_head = _git_text(paths, "rev-parse", "HEAD", cwd=paths.lab_root / "neqo-qcsd")
    lab_status = _git_text(paths, "status", "--porcelain", "--untracked-files=all")
    neqo_status = _git_text(
        paths,
        "status",
        "--porcelain",
        "--untracked-files=all",
        cwd=paths.lab_root / "neqo-qcsd",
    )
    gitlink_line = _git_text(paths, "ls-files", "--stage", "--", "neqo-qcsd")
    fields = gitlink_line.split()
    gitlink = fields[1] if len(fields) >= 2 and fields[0] == "160000" else None
    if (
        lab_head != source["lab_commit"]
        or neqo_head != source["neqo_commit"]
        or gitlink != source["neqo_pinned_commit"]
        or lab_status
        or neqo_status
    ):
        raise WatchError(
            "host Lab/Neqo checkout drifted from the clean source bound by acquisition provenance"
        )


def _docker_command(paths: WatchPaths, *arguments: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ("docker", *arguments),
            cwd=paths.lab_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=20,
            env=_safe_host_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WatchError(f"cannot inspect acquisition container: {error}") from error


def _inspect_acquisition_container(
    paths: WatchPaths, binding: AcquisitionBinding
) -> dict[str, Any] | None:
    completed = _docker_command(paths, "container", "inspect", CONTAINER_NAME)
    if completed.returncode != 0:
        listed = _docker_command(
            paths,
            "container",
            "ls",
            "--all",
            "--filter",
            f"name=^/{CONTAINER_NAME}$",
            "--format",
            "{{.Names}}",
        )
        if listed.returncode == 0 and CONTAINER_NAME not in listed.stdout.splitlines():
            return None
        raise WatchError(
            "cannot inspect acquisition container: "
            + (completed.stderr.strip() or f"docker exited {completed.returncode}")
        )
    try:
        values = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise WatchError("Docker returned malformed acquisition-container metadata") from error
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise WatchError("Docker returned ambiguous acquisition-container metadata")
    value = values[0]
    config = value.get("Config")
    mounts = value.get("Mounts")
    labels = config.get("Labels") if isinstance(config, dict) else None
    expected_labels = {**CONTAINER_LABELS, "org.qcsd.image-id": binding.prepare_image}
    expected_mounts = {
        str(paths.acquisition_root): CONTAINER_ACQUISITION_ROOT,
        str(paths.stability_root): f"/lab/artifacts/{STUDY_ID}-stability",
        str(paths.workload_root): "/lab/config/workloads",
    }
    observed_mounts: dict[str, tuple[str, bool]] = {}
    if isinstance(mounts, list):
        for mount in mounts:
            if isinstance(mount, dict) and isinstance(mount.get("Source"), str):
                observed_mounts[mount["Source"]] = (
                    mount.get("Destination"),
                    mount.get("RW"),
                )
    if (
        not isinstance(value.get("Id"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["Id"]) is None
        or value.get("Name") != f"/{CONTAINER_NAME}"
        or value.get("Image") != binding.prepare_image
        or not isinstance(labels, dict)
        or any(labels.get(key) != expected for key, expected in expected_labels.items())
        or any(
            observed_mounts.get(source) != (destination, True)
            for source, destination in expected_mounts.items()
        )
    ):
        raise WatchError(
            "refusing to manage acquisition container whose immutable identity differs"
        )
    return value


def _cleanup_orphan_container(paths: WatchPaths, binding: AcquisitionBinding) -> None:
    """Stop/remove only the exact labelled container bound to this acquisition."""

    inspected = _inspect_acquisition_container(paths, binding)
    if inspected is None:
        return
    container_id = inspected["Id"]
    stopped = _docker_command(paths, "container", "stop", "--time", "10", container_id)
    if stopped.returncode != 0 and _inspect_acquisition_container(paths, binding) is not None:
        raise WatchError(
            "cannot stop acquisition container: "
            + (stopped.stderr.strip() or f"docker exited {stopped.returncode}")
        )
    inspected = _inspect_acquisition_container(paths, binding)
    if inspected is None:
        return
    if inspected["Id"] != container_id:
        raise WatchError("acquisition container identity changed during cleanup")
    removed = _docker_command(paths, "container", "rm", "--force", container_id)
    if removed.returncode != 0 and _inspect_acquisition_container(paths, binding) is not None:
        raise WatchError(
            "cannot remove acquisition container: "
            + (removed.stderr.strip() or f"docker exited {removed.returncode}")
        )
    if _inspect_acquisition_container(paths, binding) is not None:
        raise WatchError("acquisition container still exists after bounded cleanup")


def _status_command(paths: WatchPaths) -> tuple[str, ...]:
    return (
        str(paths.launcher),
        "class-study",
        "acquisition-status",
        "--candidate-catalogue",
        str(paths.candidate_catalogue),
        "--acquisition-root",
        str(paths.acquisition_root),
    )


def _run_command(paths: WatchPaths) -> tuple[str, ...]:
    return (
        str(paths.launcher),
        "class-study",
        "acquisition-run",
        "--candidate-catalogue",
        str(paths.candidate_catalogue),
        "--acquisition-root",
        str(paths.acquisition_root),
        "--stability-root",
        str(paths.stability_root),
        "--workload-root",
        str(paths.workload_root),
        "--acquisition-max-candidates",
        str(MAX_CANDIDATES),
        "--acquisition-timeout-ms",
        str(ACQUISITION_TIMEOUT_MS),
    )


def _subprocess_runner(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    lock_fd: int,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        tuple(command),
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        pass_fds=(lock_fd,),
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate()
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
        raise
    return subprocess.CompletedProcess(tuple(command), process.returncode, stdout, stderr)


def _run_action(
    action: str,
    *,
    paths: WatchPaths,
    runner: CommandRunner,
    environment: Mapping[str, str],
    lock_fd: int,
) -> dict[str, Any]:
    command = _status_command(paths) if action == "acquisition-status" else _run_command(paths)
    try:
        completed = runner(
            command,
            cwd=paths.lab_root,
            env=environment,
            lock_fd=lock_fd,
        )
    except OSError as error:
        raise WatchError(f"cannot execute {action}: {error}") from error
    if completed.returncode != 0:
        diagnostic = (completed.stderr or completed.stdout or "").strip()
        suffix = f": {diagnostic}" if diagnostic else ""
        raise WatchError(f"{action} child failed with exit {completed.returncode}{suffix}")
    try:
        result = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise WatchError(f"{action} child output is not exactly one JSON result") from error
    return _validate_action_result(result, action=action)


def _validate_action_result(value: Any, *, action: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ACTION_KEYS:
        raise WatchError(f"{action} result envelope differs from the coordinator contract")
    if (
        value["schema_version"] != SCHEMA_VERSION
        or value["artifact_type"] != ACTION_RESULT_TYPE
        or value["action"] != action
    ):
        raise WatchError(f"{action} result identity is mismatched")
    blockers = value["blockers"]
    if not isinstance(blockers, list) or any(not isinstance(item, str) for item in blockers):
        raise WatchError(f"{action} result blockers are malformed")
    details = value["details"]
    expected_keys = _STATUS_DETAIL_KEYS if action == "acquisition-status" else _RUN_DETAIL_KEYS
    if not isinstance(details, dict) or set(details) != expected_keys:
        raise WatchError(f"{action} result details differ from the coordinator contract")
    if details["valid"] is not True or details["runner_root"] != CONTAINER_ACQUISITION_ROOT:
        raise WatchError(f"{action} result names another acquisition root")
    _validate_status_details(details, action=action)
    if action == "acquisition-status":
        gate = details["gate"]
        if gate != {
            "required_windows": _EXPECTED_WINDOWS,
            "labels": ["t+30s", "t+24h", "t+72h"],
            "all_three_required_per_page_receipt": True,
            "acquisition_owner": "resumable-qcsd-class-study-production-runner",
            "runner_sleeps_between_windows": False,
        }:
            raise WatchError("acquisition-status result carries another stability gate")
        if value["status"] != "complete" or blockers:
            raise WatchError("acquisition-status result has invalid action status or blockers")
    else:
        if details["bounded_candidates"] != MAX_CANDIDATES or details["runner_slept"] is not False:
            raise WatchError("acquisition-run result differs from the bounded no-sleep contract")
        expected_status = "ready" if details["complete"] else "pending"
        if value["status"] != expected_status or bool(blockers) == details["complete"]:
            raise WatchError("acquisition-run result status/blockers are inconsistent")
    return value


def _validate_status_details(details: Mapping[str, Any], *, action: str) -> None:
    count_names = (
        "candidate_count",
        "terminal_count",
        "pending_count",
        "probing_count",
        "due_now_count",
        "missed_window_count",
        "recovery_required_count",
    )
    for name in count_names:
        if type(details[name]) is not int or details[name] < 0:
            raise WatchError(f"{action} result has an invalid {name}")
    for name in ("pending_start_blocked", "work_due_now", "complete"):
        if type(details[name]) is not bool:
            raise WatchError(f"{action} result has an invalid {name}")
    if (
        details["candidate_count"] != CANDIDATE_COUNT
        or details["terminal_count"] + details["pending_count"] + details["probing_count"]
        != CANDIDATE_COUNT
        or details["due_now_count"] > details["probing_count"]
        or details["missed_window_count"] > details["probing_count"]
        or details["due_now_count"] + details["missed_window_count"]
        > details["probing_count"]
        or details["recovery_required_count"]
        > details["pending_count"] + details["probing_count"]
        or (details["pending_start_blocked"] and not details["pending_count"])
    ):
        raise WatchError(f"{action} result counts are inconsistent")
    expected_due = bool(
        details["due_now_count"]
        or details["missed_window_count"]
        or details["recovery_required_count"]
        or (details["pending_count"] and not details["pending_start_blocked"])
    )
    if details["work_due_now"] != expected_due:
        raise WatchError(f"{action} result due-work flag is inconsistent")
    expected_complete = (
        details["terminal_count"] == CANDIDATE_COUNT
        and details["recovery_required_count"] == 0
    )
    if details["complete"] != expected_complete:
        raise WatchError(f"{action} result completion flag is inconsistent")
    if details["complete"] and (
        details["pending_count"] or details["probing_count"] or details["next_due"] is not None
    ):
        raise WatchError(f"{action} complete result retains unfinished work")
    next_due = details["next_due"]
    if next_due is not None:
        _parse_timestamp(next_due, label=f"{action} next_due")


def _parse_timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise WatchError(f"{label} is not a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise WatchError(f"{label} is not a valid timestamp") from error
    if parsed.tzinfo is None:
        raise WatchError(f"{label} is not timezone-aware")
    return parsed.astimezone(UTC)


def _utc_now(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise WatchError("supervisor clock did not return a timezone-aware datetime")
    return value.astimezone(UTC)


def _acquire_mutation_lock(path: Path) -> int:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise WatchError(f"cannot open acquisition mutation lock: {path}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise WatchError("acquisition mutation lock is not a single regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor)
        raise WatchError(
            "another class-study acquisition process holds the runner lock"
        ) from error
    except (OSError, WatchError):
        os.close(descriptor)
        raise
    return descriptor


def watch_acquisition(
    *,
    paths: WatchPaths | None = None,
    runner: CommandRunner | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    sleeper: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    source_validator: Callable[[WatchPaths, AcquisitionBinding], None] | None = None,
    environment: Mapping[str, str] | None = None,
    heartbeat_seconds: float = DEFAULT_HEARTBEAT_SECONDS,
) -> dict[str, Any]:
    """Run until the existing checkpoint reports every candidate terminal."""

    if isinstance(heartbeat_seconds, bool) or not isinstance(heartbeat_seconds, (int, float)):
        raise WatchError("heartbeat must be a finite number in [1, 5]")
    heartbeat = float(heartbeat_seconds)
    if not math.isfinite(heartbeat) or not 1 <= heartbeat <= DEFAULT_HEARTBEAT_SECONDS:
        raise WatchError("heartbeat must be a finite number in [1, 5]")
    active_paths = paths or WatchPaths.from_script()
    _require_regular_path(
        active_paths.acquisition_root,
        root=active_paths.lab_root,
        directory=True,
        label="acquisition root",
    )
    descriptor = _acquire_mutation_lock(active_paths.mutation_lock)
    real_runner = runner is None
    active_runner = _subprocess_runner if runner is None else runner
    validate_source = source_validator or _validate_host_source
    binding: AcquisitionBinding | None = None
    container_management_started = False
    try:
        # Validate only immutable identity before orphan handling.  A detached
        # acquisition container can still be writing checkpoint.json after its
        # host wrapper dies, so reading that mutable file before stopping the
        # exact labelled orphan would race the writer.
        binding = _validate_immutable_binding(active_paths)
        if real_runner:
            container_management_started = True
            _cleanup_orphan_container(active_paths, binding)
        _validate_checkpoint(active_paths, binding)
        validate_source(active_paths, binding)
        child_environment = _safe_host_environment(environment)
        child_environment[PREPARE_IMAGE_ENV] = binding.prepare_image
        child_environment[LOCK_ENV] = str(descriptor)
        last_source_check = monotonic()
        while True:
            status_result = _run_action(
                "acquisition-status",
                paths=active_paths,
                runner=active_runner,
                environment=child_environment,
                lock_fd=descriptor,
            )
            details = status_result["details"]
            if details["complete"]:
                _validate_checkpoint(active_paths, binding)
                return status_result
            if details["work_due_now"]:
                validate_source(active_paths, binding)
                before = _validate_checkpoint(active_paths, binding)
                _run_action(
                    "acquisition-run",
                    paths=active_paths,
                    runner=active_runner,
                    environment=child_environment,
                    lock_fd=descriptor,
                )
                after = _validate_checkpoint(active_paths, binding)
                if after == before:
                    raise WatchError("due acquisition run did not advance the checkpoint")
                continue
            next_due = details["next_due"]
            if next_due is None:
                raise WatchError("incomplete acquisition has no due work and no next_due")
            target = _parse_timestamp(next_due, label="acquisition-status next_due")
            remaining = (target - _utc_now(clock)).total_seconds()
            while remaining > 0:
                sleeper(min(remaining, heartbeat))
                monotonic_now = monotonic()
                if monotonic_now - last_source_check >= SOURCE_RECHECK_SECONDS:
                    current_binding = _validate_acquisition_binding(active_paths)
                    if current_binding != binding:
                        raise WatchError("acquisition evidence binding changed while waiting")
                    validate_source(active_paths, binding)
                    last_source_check = monotonic_now
                remaining = (target - _utc_now(clock)).total_seconds()
            # The checkpoint cannot be mutated by a conforming peer while this
            # process holds the shared mutation lock.  At the recorded earliest
            # boundary, invoke due work directly instead of spending window
            # slack on a redundant status container.
            validate_source(active_paths, binding)
            before = _validate_checkpoint(active_paths, binding)
            _run_action(
                "acquisition-run",
                paths=active_paths,
                runner=active_runner,
                environment=child_environment,
                lock_fd=descriptor,
            )
            after = _validate_checkpoint(active_paths, binding)
            if after == before:
                raise WatchError("scheduled acquisition run did not advance the checkpoint")
    finally:
        if real_runner and binding is not None and container_management_started:
            _cleanup_orphan_container(active_paths, binding)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _raise_keyboard_interrupt(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Supervise the canonical classifier-multiorigin100-v1 acquisition "
            "from its immutable checkpoint."
        )
    )
    parser.add_argument(
        "--heartbeat-seconds",
        type=float,
        default=DEFAULT_HEARTBEAT_SECONDS,
        help="host heartbeat while waiting (finite, 1 to 5 seconds; default: 5)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    previous_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
    try:
        result = watch_acquisition(heartbeat_seconds=arguments.heartbeat_seconds)
    except KeyboardInterrupt:
        print("class acquisition watch interrupted; resume from checkpoint", file=sys.stderr)
        return 130
    except WatchError as error:
        print(f"class acquisition watch failed: {error}", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_term)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
