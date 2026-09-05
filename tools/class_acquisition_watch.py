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
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path
from typing import Any, Protocol

STUDY_ID = "classifier-multiorigin100-v1"
CANDIDATE_COUNT = 600
SCHEMA_VERSION = 1
ACQUISITION_SCHEMA_VERSION = 4
CHECKPOINT_SCHEMA_VERSION = 2
CATALOGUE_TYPE = "qcsd-class-study-candidate-catalogue"
PROVENANCE_TYPE = "qcsd-class-study-acquisition-provenance"
CHECKPOINT_TYPE = "qcsd-class-study-acquisition-checkpoint"
FOUNDATION_TYPE = "qcsd-class-study-foundation-attestation"
ACTION_RESULT_TYPE = "qcsd-class-study-coordinator-result"
DOCKER_ADMISSION_TYPE = "qcsd-class-study-docker-admission"
SCOPE_SUPERVISION_TYPE = "qcsd-class-watch-scope-supervision"
SCOPE_RECOVERY_TYPE = "qcsd-class-watch-scope-recovery"
SCOPE_NAMESPACE_TYPE = "qcsd-class-watch-state-namespace"
PREPARE_IMAGE_ENV = "QCSD_LAB_PREPARE_IMAGE"
PINNED_CONTEXT_ENV = "QCSD_DOCKER_PINNED_CONTEXT"
PINNED_HOST_ENV = "QCSD_DOCKER_PINNED_HOST"
PINNED_SERVER_ID_ENV = "QCSD_DOCKER_PINNED_SERVER_ID"
CONTAINER_ACQUISITION_ROOT = f"/lab/artifacts/{STUDY_ID}-acquisition"
# One coordinator action may advance a compatible pair, while every page-level
# worker shares this immutable process-wide concurrency budget. The core
# coordinator publishes its transactional batch before starting either worker.
MAX_CANDIDATES = 2
GLOBAL_LIVE_PAGE_CAP = 5
BROWSER_NAVIGATION_TIMEOUT_MS = 60_000
PASSIVE_RENDER_HARD_CAP_MS = 30_000
# Retained as the public coordinator-CLI timeout name. This is the browser
# navigation component timeout, not a discovery, probe, or action deadline.
ACQUISITION_TIMEOUT_MS = BROWSER_NAVIGATION_TIMEOUT_MS
MAX_PROBE_ATTEMPTS = 3
DEFAULT_HEARTBEAT_SECONDS = 5.0
SOURCE_RECHECK_SECONDS = 60.0
DOCKER_SUPERVISOR_SIGNAL_ENVELOPE_SECONDS = 120
ADMISSION_RUNTIME_SECONDS = 600
STATUS_RUNTIME_SECONDS = 300
STATUS_CLEANUP_SECONDS = 10
ACQUISITION_ACTION_TIMEOUT_SECONDS = 1_800
ACQUISITION_ACTION_CLEANUP_SECONDS = 120
# The user-systemd scope is the outer backup for the in-container hard action
# timeout.  At expiry it sends INT, then permits the same cleanup envelope
# before systemd escalates to KILL.
RUN_RUNTIME_SECONDS = (
    ACQUISITION_ACTION_TIMEOUT_SECONDS + ACQUISITION_ACTION_CLEANUP_SECONDS
)
ACQUISITION_OUTER_HARD_SECONDS = (
    RUN_RUNTIME_SECONDS + ACQUISITION_ACTION_CLEANUP_SECONDS
)
# Reserve enough separation for the complete configured acquisition hard
# envelope, one worst-case status scope, and an explicit 50-second scheduling
# margin.  This also exceeds the 30-minute width of either long probe window.
SERIAL_SCHEDULER_MARGIN_SECONDS = 50
MINIMUM_BASELINE_SPACING_SECONDS = (
    ACQUISITION_OUTER_HARD_SECONDS
    + STATUS_RUNTIME_SECONDS
    + STATUS_CLEANUP_SECONDS
    + SERIAL_SCHEDULER_MARGIN_SECONDS
)
PENDING_BASELINE_GUARD_MS = MINIMUM_BASELINE_SPACING_SECONDS * 1_000
SCOPE_CLIENT_GRACE_SECONDS = 15
SCOPE_QUERY_TIMEOUT_SECONDS = 2
SCOPE_SETTLE_SECONDS = 0.05
SCOPE_EMPTY_OBSERVATIONS = 2
LOCK_ENV = "QCSD_CLASS_ACQUISITION_LOCK_FD"
SCOPE_ROOT_ENV = "QCSD_CLASS_WATCH_SCOPE_ROOT"
SCOPE_STATE_ROOT_ENV = "QCSD_CLASS_WATCH_STATE_ROOT"
SCOPE_AUTHORITY_ENV = "QCSD_CLASS_WATCH_REQUEST_AUTHORITY"
SCOPE_ACTION_ENV = "QCSD_CLASS_WATCH_ACTION_SHA256"
SCOPE_SOURCE_ENV = "QCSD_CLASS_WATCH_SOURCE_BINDING_SHA256"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CANDIDATE_ID_RE = re.compile(r"tranco-[0-9]{7}\Z")
_BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_SCOPE_UNIT_RE = re.compile(r"qcsd-class-watch-[0-9a-f]{32}[.]scope\Z")
_SCOPE_ROOT_RE = re.compile(r"scope(?:[.]next)?[.][0-9a-f]{32}\Z")
_STATE_NAMESPACE_RE = re.compile(r"[0-9a-f]{64}\Z")
_SCOPE_ROOT_FILES = {
    "BIRTH.lock",
    "stdout",
    "stderr",
    "status",
    "status.next",
    "SUPERVISION",
    "SUPERVISION.next",
    "RECOVERY",
    "RECOVERY.next",
    "REQUEST",
    "REQUEST.next",
    "GO",
    "GO.next",
}

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
    "cdp_target_instrumentation_policy",
    "passive_render_contract",
    "passive_render_contract_sha256",
    "browser_navigation_timeout_ms",
    "passive_render_hard_cap_after_load_ms",
    "acquisition_action_timing_contract",
    "baseline_scheduling_contract",
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
_CDP_TARGET_INSTRUMENTATION_POLICY = (
    "playwright-1.52-public-cdp-recursive-non-flat-paused-debugger-targets-v3"
)
_PASSIVE_RENDER_CONTRACT = {
    "schema_version": 1,
    "policy": "bounded-passive-render-quiescence-v1",
    "viewport": {"width": 1365, "height": 768, "deviceScaleFactor": 1},
    "cache": "disabled",
    "service_workers": "bypassed-and-registration-blocked",
    "interaction": "none",
    "minimum_after_load_ms": 10_000,
    "quiet_window_ms": 3_000,
    "quiet_window_begins": "after-minimum-or-last-relevant-event-whichever-is-later",
    "hard_cap_after_load_ms": PASSIVE_RENDER_HARD_CAP_MS,
    "poll_interval_ms": 100,
    "active_request_scope": "all-network-request-occurrences",
    "relevant_events": [
        "network-request",
        "fetch-request",
        "network-terminal",
        "target-attached",
        "target-detached",
        "target-destroyed",
        "target-info-changed",
    ],
    "hard_cap_policy": "typed-candidate-rejection",
}
_PASSIVE_RENDER_CONTRACT_SHA256 = hashlib.sha256(
    (
        json.dumps(_PASSIVE_RENDER_CONTRACT, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
).hexdigest()
_ORIGIN_POLICY = {
    "max_passes": 8,
    "max_navigation_redirect_passes": 8,
    "max_origins": 32,
    "max_observed_audit_origins": 512,
    "max_navigation_attempts": MAX_PROBE_ATTEMPTS,
    "max_probe_attempts_per_window": MAX_PROBE_ATTEMPTS,
    "navigation_seed_scope": "page-specific-document-navigation-origins-only",
    "resource_graph_scope": "iteratively-converged-public-https-get-request-instances",
    "request_instance_identity": (
        "observation-order-resource-id-with-preceding-initiator-and-redirect-edges"
    ),
    "dns": "all-answers-global-and-browser-host-resolver-pinned",
    "neqo": "QCSD_PUBLIC_ORIGIN_ONLY-resolve-once-connect-exact-address",
}
_ACQUISITION_ACTION_TIMING_CONTRACT = {
    "schema_version": 2,
    "policy": "bounded-compatible-candidate-batch-whole-action-deadline-v2",
    "bounded_candidates": MAX_CANDIDATES,
    "global_live_page_cap": GLOBAL_LIVE_PAGE_CAP,
    "batch_selection": (
        "same-priority-same-stage-immutable-catalogue-order-compatible-pair-"
        "otherwise-singleton"
    ),
    "transactional_publication": (
        "active-batch-and-pending-attempts-published-before-parallel-work"
    ),
    "coordinator_merge": (
        "deterministic-immutable-catalogue-order-after-all-workers-return"
    ),
    "browser_navigation_timeout_ms": BROWSER_NAVIGATION_TIMEOUT_MS,
    "browser_navigation_timeout_scope": "navigation-component-only",
    "passive_render_hard_cap_after_load_ms": PASSIVE_RENDER_HARD_CAP_MS,
    "passive_render_timeout_scope": "post-load-component-only",
    "inner_timeout": {
        "scope": "in-container-coordinator-process-group",
        "soft_deadline_ms": ACQUISITION_ACTION_TIMEOUT_SECONDS * 1_000,
        "soft_signal": "SIGINT",
        "cleanup_grace_ms": ACQUISITION_ACTION_CLEANUP_SECONDS * 1_000,
        "hard_signal": "SIGKILL",
        "hard_deadline_ms": RUN_RUNTIME_SECONDS * 1_000,
    },
    "outer_timeout": {
        "scope": "canonical-host-acquisition-watch-user-systemd-scope",
        "runtime_max_ms": RUN_RUNTIME_SECONDS * 1_000,
        "runtime_signal": "SIGINT",
        "cleanup_grace_ms": ACQUISITION_ACTION_CLEANUP_SECONDS * 1_000,
        "final_signal": "SIGKILL",
        "hard_deadline_ms": ACQUISITION_OUTER_HARD_SECONDS * 1_000,
    },
    "direct_public_acquisition_run": (
        "forbidden-without-validated-watcher-scope-authority"
    ),
    "successful_ledger_attempt_duration_limit_ms": (
        ACQUISITION_ACTION_TIMEOUT_SECONDS * 1_000
    ),
    "whole_action_duration_evidence": (
        "externally-enforced-process-status-no-per-action-duration-receipt"
    ),
    "interruption_recovery": (
        "published-active-batch-attempts-become-interrupted-never-completed"
    ),
}
_BASELINE_SCHEDULING_CONTRACT = {
    "schema_version": 2,
    "policy": "serial-nonoverlapping-stability-window-batch-reservations-v2",
    "maximum_candidates_per_batch": MAX_CANDIDATES,
    "global_live_page_cap": GLOBAL_LIVE_PAGE_CAP,
    "minimum_baseline_spacing_ms": PENDING_BASELINE_GUARD_MS,
    "window_start_reservation_ms": PENDING_BASELINE_GUARD_MS,
    "longest_probe_window_width_ms": 1_800_000,
    "acquisition_outer_configured_hard_cutoff_ms": (
        ACQUISITION_OUTER_HARD_SECONDS * 1_000
    ),
    "status_configured_hard_cutoff_ms": (
        STATUS_RUNTIME_SECONDS + STATUS_CLEANUP_SECONDS
    )
    * 1_000,
    "scheduler_margin_ms": SERIAL_SCHEDULER_MARGIN_SECONDS * 1_000,
    "navigation_phase": "separate-bounded-action-before-baseline",
    "short_probe": "same-action-wait-until-t+30s-earliest",
    "outer_probes": "watcher-launches-acquisition-run-at-window-earliest",
    "within_batch_baseline": "one-equal-baseline-per-recorded-baseline-batch",
    "schedule_validation_unit": "baseline-batches-not-raw-candidate-timestamps",
    "unpaired_candidate_policy": "singleton-when-no-compatible-partner",
    "serial_action_start_offsets_ms": [0, 85_500_000, 258_300_000],
    "stability_window_earliest_offsets_ms": [25_000, 85_500_000, 258_300_000],
    "collision_scope": (
        "baseline-arming-and-t+24h-t+72h-action-starts-across-batches"
    ),
    "strict_serial_zero_duration_projection": {
        "candidate_count": CANDIDATE_COUNT,
        "maximum_candidates_per_batch": MAX_CANDIDATES,
        "batch_count": 300,
        "algorithm": "greedy-earliest-safe-baseline-batches",
        "pairing_assumption": (
            "all-candidates-form-300-compatible-two-candidate-batches"
        ),
        "last_baseline_offset_ms": 2_784_000_000,
        "last_t+72h_earliest_offset_ms": 3_042_300_000,
    },
}
_RUN_WAIT_POLICY = {
    "navigation_phase": "separate-bounded-action-before-baseline",
    "t+30s": "same-action-interruptible-wait-to-earliest-then-probe",
    "t+24h-and-t+72h": "host-watcher-launch-at-earliest-no-container-wait",
}
_CHECKPOINT_PAYLOAD_KEYS = {
    "checkpoint_schema_version",
    "provenance_sha256",
    "candidate_catalogue_sha256",
    "baseline_batches",
    "active_batch",
    "candidates",
}
_STATUS_KEYS = {
    "acquisition_schema_version",
    "checkpoint_schema_version",
    "maximum_candidates_per_action",
    "global_live_page_cap",
    "active_batch",
    "candidate_count",
    "terminal_count",
    "pending_count",
    "probing_count",
    "due_now_count",
    "finalisable_count",
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
    "runner_wait_policy",
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
        authority_fd: int,
        state_root: Path,
        source_binding_sha256: str,
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
    state_base: Path

    @classmethod
    def from_lab_root(
        cls,
        root: Path,
        *,
        state_base: Path | None = None,
    ) -> WatchPaths:
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
            state_base=Path(
                os.path.abspath(
                    state_base
                    or Path("/var/tmp")
                    / f"qcsd-class-watch-lifecycle-{os.getuid()}"
                )
            ),
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
        return self.state_root / "WATCH.lock"

    @property
    def action_lock(self) -> Path:
        return self.acquisition_root / ".class-study-acquisition.lock"

    @property
    def namespace_sha256(self) -> str:
        return _sha256_bytes(_canonical_json_bytes(_state_namespace_identity(self)))

    @property
    def state_root(self) -> Path:
        return self.state_base / self.namespace_sha256


@dataclass(frozen=True)
class AcquisitionBinding:
    prepare_image: str
    catalogue_sha256: str
    provenance_sha256: str
    candidate_ids: frozenset[str]
    candidate_order: tuple[str, ...]
    source: Mapping[str, Any]


@dataclass(frozen=True)
class ReceiptSnapshot:
    value: Mapping[str, Any]
    sha256: str


@dataclass(frozen=True)
class DockerAdmission:
    context: str
    host: str
    server_id: str
    host_boot_id: str


@dataclass(frozen=True)
class ScopeState:
    load_state: str
    active_state: str
    sub_state: str
    control_group: str | None
    processes: tuple[int, ...]


@dataclass(frozen=True)
class ScopeRecoveryPlan:
    root: Path
    record: Mapping[str, Any] | None
    recovery: bool
    unit: str
    state: ScopeState
    request: Mapping[str, Any] | None
    birth_lock_fd: int | None
    birth_lock_busy: bool
    birth_missing_after_recovery: bool = False


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise WatchError("evidence contains a non-canonical JSON value") from error


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _state_namespace_identity(paths: WatchPaths) -> dict[str, Any]:
    return {
        "acquisition_root": str(paths.acquisition_root),
        "artifact_type": SCOPE_NAMESPACE_TYPE,
        "lab_root": str(paths.lab_root),
        "schema_version": SCHEMA_VERSION,
        "study_id": STUDY_ID,
    }


def _source_binding_sha256(binding: AcquisitionBinding) -> str:
    return _sha256_bytes(
        _canonical_json_bytes(
            {
                "candidate_catalogue_sha256": binding.catalogue_sha256,
                "prepare_image": binding.prepare_image,
                "provenance_sha256": binding.provenance_sha256,
                "source": dict(binding.source),
            }
        )
    )


def _parse_exact_json_object(value: str, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, content in pairs:
            if key in result:
                raise WatchError(f"{label} contains a duplicate JSON key")
            result[key] = content
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=reject_duplicates)
    except (TypeError, json.JSONDecodeError) as error:
        raise WatchError(f"{label} is not exactly one JSON result") from error
    if not isinstance(parsed, dict):
        raise WatchError(f"{label} is not a JSON object")
    return parsed


def _safe_host_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the fixed host execution environment.

    The caller environment is intentionally ignored.  Docker configuration,
    shell hooks, Python import paths and executable search paths must not be
    selectable by the account that starts a multi-day acquisition watch.
    """

    del source
    uid = os.getuid()

    def fixed(path: Path, *, owner: int, mode: int, kind: int) -> os.stat_result:
        try:
            lexical = path.absolute()
            canonical = path.resolve(strict=True)
            value = path.stat(follow_symlinks=False)
        except OSError as error:
            raise WatchError("user-systemd runtime path is unavailable") from error
        if (
            lexical != canonical
            or path.is_symlink()
            or stat.S_IFMT(value.st_mode) != kind
            or value.st_uid != owner
            or stat.S_IMODE(value.st_mode) != mode
        ):
            raise WatchError("user-systemd runtime path is not safely owned")
        return value

    fixed(Path("/run"), owner=0, mode=0o755, kind=stat.S_IFDIR)
    fixed(Path("/run/user"), owner=0, mode=0o755, kind=stat.S_IFDIR)
    runtime = Path(f"/run/user/{uid}")
    fixed(runtime, owner=uid, mode=0o700, kind=stat.S_IFDIR)
    bus = runtime / "bus"
    fixed(bus, owner=uid, mode=0o666, kind=stat.S_IFSOCK)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONNOUSERSITE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "DOCKER_CONTEXT": "default",
        "XDG_RUNTIME_DIR": str(runtime),
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
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


def _read_stable_file(path: Path, *, root: Path, label: str) -> tuple[bytes, str]:
    """Read and hash one immutable pathname identity exactly once."""

    _require_regular_path(path, root=root, directory=False, label=label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    root = Path(os.path.abspath(root))
    path = Path(os.path.abspath(path))
    relative = path.relative_to(root)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    directory_fd: int | None = None
    try:
        directory_fd = os.open(root, directory_flags)
        for component in relative.parts[:-1]:
            child_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
        descriptor = os.open(relative.parts[-1], flags, dir_fd=directory_fd)
    except OSError as error:
        raise WatchError(f"cannot open {label}: {path}") from error
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise WatchError(f"{label} is not a single regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        try:
            current = os.stat(path, follow_symlinks=False)
        except OSError as error:
            raise WatchError(f"{label} pathname changed while it was read") from error
    finally:
        os.close(descriptor)
    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_uid,
            value.st_gid,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    if identity(before) != identity(after) or identity(after) != identity(current):
        raise WatchError(f"{label} changed while it was read")
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        raise WatchError(f"{label} size changed while it was read")
    return raw, _sha256_bytes(raw)


def _load_canonical_receipt(
    path: Path,
    *,
    root: Path,
    receipt_type: str,
    label: str,
) -> ReceiptSnapshot:
    try:
        raw, sha256 = _read_stable_file(path, root=root, label=label)
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
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
    return ReceiptSnapshot(value=value, sha256=sha256)


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


def _validate_catalogue(paths: WatchPaths) -> tuple[Mapping[str, Any], tuple[str, ...], str]:
    snapshot = _load_canonical_receipt(
        paths.candidate_catalogue,
        root=paths.lab_root,
        receipt_type=CATALOGUE_TYPE,
        label="candidate catalogue",
    )
    catalogue = snapshot.value
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
    return catalogue, tuple(candidate_ids), snapshot.sha256


def _validate_foundation(binding: Any, *, paths: WatchPaths) -> None:
    if not isinstance(binding, dict) or set(binding) != {"path", "sha256"}:
        raise WatchError("acquisition foundation binding is malformed")
    claimed = binding["sha256"]
    if not isinstance(claimed, str) or _SHA256_RE.fullmatch(claimed) is None:
        raise WatchError("acquisition foundation SHA-256 is malformed")
    foundation_path = _container_binding_path(
        binding["path"], paths=paths, label="acquisition foundation"
    )
    snapshot = _load_canonical_receipt(
        foundation_path,
        root=paths.lab_root,
        receipt_type=FOUNDATION_TYPE,
        label="acquisition foundation",
    )
    if snapshot.sha256 != claimed:
        raise WatchError("acquisition foundation binding does not verify")


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
    catalogue, candidate_order, catalogue_sha256 = _validate_catalogue(paths)
    candidate_ids = frozenset(candidate_order)
    provenance_snapshot = _load_canonical_receipt(
        paths.provenance,
        root=paths.lab_root,
        receipt_type=PROVENANCE_TYPE,
        label="acquisition provenance",
    )
    provenance = provenance_snapshot.value
    payload = provenance["payload"]
    if set(payload) != _PROVENANCE_PAYLOAD_KEYS:
        raise WatchError("acquisition provenance payload fields differ from the v4 contract")
    if (
        payload["study_id"] != STUDY_ID
        or payload["acquisition_schema_version"] != ACQUISITION_SCHEMA_VERSION
        or payload["candidate_count"] != CANDIDATE_COUNT
        or payload["candidate_catalogue_sha256"] != catalogue_sha256
        or payload["candidate_catalogue_payload_sha256"] != catalogue["payload_sha256"]
        or payload["navigation_implementation"]
        != "playwright-cdp-catalogue-domain-boundary-redirect-pin-convergence-v3"
        or payload["cdp_target_instrumentation_policy"]
        != _CDP_TARGET_INSTRUMENTATION_POLICY
        or payload["passive_render_contract"] != _PASSIVE_RENDER_CONTRACT
        or payload["passive_render_contract_sha256"]
        != _PASSIVE_RENDER_CONTRACT_SHA256
        or payload["browser_navigation_timeout_ms"]
        != BROWSER_NAVIGATION_TIMEOUT_MS
        or payload["passive_render_hard_cap_after_load_ms"]
        != PASSIVE_RENDER_HARD_CAP_MS
        or payload["acquisition_action_timing_contract"]
        != _ACQUISITION_ACTION_TIMING_CONTRACT
        or payload["baseline_scheduling_contract"]
        != _BASELINE_SCHEDULING_CONTRACT
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
    binding = AcquisitionBinding(
        prepare_image=image,
        catalogue_sha256=catalogue_sha256,
        provenance_sha256=provenance_snapshot.sha256,
        candidate_ids=candidate_ids,
        candidate_order=candidate_order,
        source=dict(source),
    )
    return binding


def _validate_acquisition_binding(paths: WatchPaths) -> AcquisitionBinding:
    binding = _validate_immutable_binding(paths)
    _validate_checkpoint(paths, binding)
    return binding


def _validate_checkpoint(paths: WatchPaths, binding: AcquisitionBinding) -> ReceiptSnapshot:
    _require_regular_path(
        paths.checkpoint,
        root=paths.lab_root,
        directory=False,
        label="acquisition checkpoint",
    )
    snapshot = _load_canonical_receipt(
        paths.checkpoint,
        root=paths.lab_root,
        receipt_type=CHECKPOINT_TYPE,
        label="acquisition checkpoint",
    )
    checkpoint = snapshot.value
    payload = checkpoint["payload"]
    if set(payload) != _CHECKPOINT_PAYLOAD_KEYS:
        raise WatchError("acquisition checkpoint payload fields differ from the v2 contract")
    if (
        payload["checkpoint_schema_version"] != CHECKPOINT_SCHEMA_VERSION
        or isinstance(payload["checkpoint_schema_version"], bool)
        or payload["provenance_sha256"] != binding.provenance_sha256
        or payload["candidate_catalogue_sha256"] != binding.catalogue_sha256
    ):
        raise WatchError("acquisition checkpoint evidence bindings do not verify")
    states = payload["candidates"]
    if not isinstance(states, dict) or set(states) != binding.candidate_ids:
        raise WatchError("acquisition checkpoint candidate set differs from the catalogue")
    if any(not isinstance(state, dict) for state in states.values()):
        raise WatchError("acquisition checkpoint contains a non-object candidate state")
    baseline_by_candidate = _validate_baseline_batches(
        payload["baseline_batches"],
        binding=binding,
        states=states,
    )
    _validate_active_batch(
        payload["active_batch"],
        binding=binding,
        states=states,
        baseline_by_candidate=baseline_by_candidate,
    )
    return snapshot


def _candidate_id_list(
    value: Any,
    *,
    binding: AcquisitionBinding,
    label: str,
) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= MAX_CANDIDATES
        or any(not isinstance(item, str) for item in value)
        or len(set(value)) != len(value)
        or not set(value).issubset(binding.candidate_ids)
        or [binding.candidate_order.index(item) for item in value]
        != sorted(binding.candidate_order.index(item) for item in value)
    ):
        raise WatchError(f"{label} candidate identities are invalid")
    return value


def _validate_live_page_count(value: Any, *, label: str) -> int:
    if type(value) is not int or not 0 <= value <= GLOBAL_LIVE_PAGE_CAP:
        raise WatchError(f"{label} live-page count exceeds the global cap")
    return value


def _content_addressed_batch_id(prefix: str, value: Mapping[str, Any]) -> str:
    body = {name: item for name, item in value.items() if name != "batch_id"}
    return f"{prefix}-{_sha256_bytes(_canonical_json_bytes(body))}"


def _validate_baseline_batches(
    value: Any,
    *,
    binding: AcquisitionBinding,
    states: Mapping[str, Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    if not isinstance(value, list):
        raise WatchError("acquisition checkpoint baseline batch ledger is malformed")
    batch_ids: set[str] = set()
    batch_by_candidate: dict[str, Mapping[str, Any]] = {}
    previous_baseline: datetime | None = None
    action_starts: list[tuple[datetime, str]] = []
    for batch in value:
        if not isinstance(batch, dict) or set(batch) != {
            "batch_id",
            "baseline_started_at",
            "candidate_ids",
            "live_page_count",
        }:
            raise WatchError("acquisition checkpoint baseline batch is malformed")
        batch_id = batch["batch_id"]
        if (
            not isinstance(batch_id, str)
            or batch_id != _content_addressed_batch_id("baseline", batch)
            or batch_id in batch_ids
        ):
            raise WatchError("acquisition checkpoint baseline batch identity is invalid")
        batch_ids.add(batch_id)
        baseline = _parse_timestamp(
            batch["baseline_started_at"],
            label="acquisition checkpoint baseline batch time",
        )
        if previous_baseline is not None and baseline <= previous_baseline:
            raise WatchError(
                "acquisition checkpoint baseline batches are not append-ordered"
            )
        previous_baseline = baseline
        action_starts.extend(
            (
                baseline + timedelta(milliseconds=offset),
                batch_id,
            )
            for offset in _BASELINE_SCHEDULING_CONTRACT[
                "serial_action_start_offsets_ms"
            ]
        )
        candidate_ids = _candidate_id_list(
            batch["candidate_ids"],
            binding=binding,
            label="acquisition checkpoint baseline batch",
        )
        if set(batch_by_candidate).intersection(candidate_ids):
            raise WatchError(
                "acquisition checkpoint schedules a candidate in two baseline batches"
            )
        live_pages = _validate_live_page_count(
            batch["live_page_count"],
            label="acquisition checkpoint baseline batch",
        )
        observed_live_pages = 0
        for candidate_id in candidate_ids:
            state = states[candidate_id]
            pages = state.get("pages")
            if (
                state.get("baseline_started_at") != batch["baseline_started_at"]
                or not isinstance(pages, list)
                or not pages
            ):
                raise WatchError(
                    "acquisition checkpoint baseline batch differs from candidate state"
                )
            observed_live_pages += len(pages)
            batch_by_candidate[candidate_id] = batch
        if live_pages != observed_live_pages:
            raise WatchError(
                "acquisition checkpoint baseline batch live-page count is false"
            )
    ordered_starts = sorted(action_starts)
    for (left, left_batch), (right, right_batch) in pairwise(ordered_starts):
        if (
            left_batch != right_batch
            and right - left < timedelta(milliseconds=PENDING_BASELINE_GUARD_MS)
        ):
            raise WatchError(
                "acquisition checkpoint baseline batches violate the serial schedule"
            )
    state_candidates = {
        candidate_id
        for candidate_id, state in states.items()
        if "baseline_started_at" in state
    }
    if set(batch_by_candidate) != state_candidates:
        raise WatchError(
            "acquisition checkpoint baseline batches do not exactly cover candidate state"
        )
    return batch_by_candidate


def _validate_active_batch(
    value: Any,
    *,
    binding: AcquisitionBinding,
    states: Mapping[str, Mapping[str, Any]] | None = None,
    baseline_by_candidate: Mapping[str, Mapping[str, Any]] | None = None,
) -> Mapping[str, Any] | None:
    if value is None:
        if states is not None and _pending_attempts(states):
            raise WatchError(
                "acquisition checkpoint has pending attempts without an active batch"
            )
        return None
    if not isinstance(value, dict) or set(value) != {
        "active_batch_schema_version",
        "batch_id",
        "stage",
        "published_at",
        "candidate_ids",
        "live_page_count",
        "attempts",
    }:
        raise WatchError("acquisition checkpoint active batch is malformed")
    if value["active_batch_schema_version"] != 1 or isinstance(
        value["active_batch_schema_version"], bool
    ):
        raise WatchError("acquisition checkpoint active batch schema is invalid")
    if (
        not isinstance(value["batch_id"], str)
        or value["batch_id"] != _content_addressed_batch_id("active", value)
    ):
        raise WatchError("acquisition checkpoint active batch identity is invalid")
    if value["stage"] not in {"navigation", "probe"}:
        raise WatchError("acquisition checkpoint active batch stage is invalid")
    _parse_timestamp(
        value["published_at"],
        label="acquisition checkpoint active batch publication time",
    )
    candidate_ids = _candidate_id_list(
        value["candidate_ids"],
        binding=binding,
        label="acquisition checkpoint active batch",
    )
    live_pages = _validate_live_page_count(
        value["live_page_count"],
        label="acquisition checkpoint active batch",
    )
    attempts = value["attempts"]
    if not isinstance(attempts, list):
        raise WatchError("acquisition checkpoint active batch attempts are malformed")
    attempt_identities: set[tuple[Any, ...]] = set()
    for attempt in attempts:
        if not isinstance(attempt, dict) or set(attempt) != {
            "candidate_id",
            "page_ordinal",
            "probe_id",
            "workload_id",
            "attempt",
            "started_at",
        }:
            raise WatchError("acquisition checkpoint active batch attempt is malformed")
        if attempt["candidate_id"] not in candidate_ids:
            raise WatchError("acquisition checkpoint active batch attempt names another candidate")
        if (
            type(attempt["attempt"]) is not int
            or not 1 <= attempt["attempt"] <= MAX_PROBE_ATTEMPTS
        ):
            raise WatchError("acquisition checkpoint active batch attempt count is invalid")
        if value["stage"] == "navigation":
            if any(
                attempt[name] is not None
                for name in ("page_ordinal", "probe_id", "workload_id")
            ):
                raise WatchError(
                    "acquisition checkpoint active navigation attempt has page identity"
                )
        elif (
            type(attempt["page_ordinal"]) is not int
            or attempt["page_ordinal"] < 0
            or attempt["probe_id"] not in {item["probe_id"] for item in _EXPECTED_WINDOWS}
            or not isinstance(attempt["workload_id"], str)
            or not attempt["workload_id"]
        ):
            raise WatchError("acquisition checkpoint active probe identity is invalid")
        _parse_timestamp(
            attempt["started_at"],
            label="acquisition checkpoint active batch attempt start",
        )
        if attempt["started_at"] != value["published_at"]:
            raise WatchError(
                "acquisition checkpoint active batch attempts have unequal start times"
            )
        identity = tuple(attempt[name] for name in (
            "candidate_id",
            "page_ordinal",
            "probe_id",
            "workload_id",
            "attempt",
        ))
        if identity in attempt_identities:
            raise WatchError("acquisition checkpoint active batch attempt is duplicated")
        attempt_identities.add(identity)
    if not attempts or len(attempts) != live_pages:
        raise WatchError(
            "acquisition checkpoint active batch attempts differ from its live-page count"
        )
    observed_candidate_ids = list(
        dict.fromkeys(attempt["candidate_id"] for attempt in attempts)
    )
    if observed_candidate_ids != candidate_ids:
        raise WatchError(
            "acquisition checkpoint active candidate ordering is invalid"
        )
    if value["stage"] == "navigation" and len(attempts) != len(candidate_ids):
        raise WatchError(
            "acquisition checkpoint active navigation cardinality is invalid"
        )
    if value["stage"] == "probe":
        probe_identities = [
            (attempt["candidate_id"], attempt["page_ordinal"])
            for attempt in attempts
        ]
        if (
            len(probe_identities) != len(set(probe_identities))
            or len({attempt["probe_id"] for attempt in attempts}) != 1
        ):
            raise WatchError(
                "acquisition checkpoint active probe batch mixes identities or windows"
            )
        expected_order = sorted(
            attempts,
            key=lambda attempt: (
                binding.candidate_order.index(attempt["candidate_id"]),
                attempt["page_ordinal"],
            ),
        )
        if attempts != expected_order:
            raise WatchError(
                "acquisition checkpoint active probe attempts are not deterministically ordered"
            )
    if states is not None:
        _reconcile_active_attempts(
            value,
            candidate_ids=candidate_ids,
            binding=binding,
            states=states,
            baseline_by_candidate=baseline_by_candidate or {},
        )
    return value


def _pending_attempts(
    states: Mapping[str, Mapping[str, Any]],
) -> list[tuple[str, str, Mapping[str, Any], Mapping[str, Any] | None]]:
    pending: list[tuple[str, str, Mapping[str, Any], Mapping[str, Any] | None]] = []
    for candidate_id, state in states.items():
        navigation = state.get("pending_navigation")
        if "pending_navigation" in state:
            if not isinstance(navigation, Mapping):
                raise WatchError(
                    "acquisition checkpoint pending navigation is malformed"
                )
            pending.append((candidate_id, "navigation", navigation, None))
        pages = state.get("pages")
        if "pages" in state and not isinstance(pages, list):
            raise WatchError("acquisition checkpoint candidate page ledger is malformed")
        if not isinstance(pages, list):
            continue
        for page in pages:
            if not isinstance(page, Mapping):
                raise WatchError("acquisition checkpoint candidate page is malformed")
            probe = page.get("pending_probe")
            if "pending_probe" in page:
                if not isinstance(probe, Mapping):
                    raise WatchError("acquisition checkpoint pending probe is malformed")
                pending.append((candidate_id, "probe", probe, page))
    return pending


def _reconcile_active_attempts(
    active: Mapping[str, Any],
    *,
    candidate_ids: list[str],
    binding: AcquisitionBinding,
    states: Mapping[str, Mapping[str, Any]],
    baseline_by_candidate: Mapping[str, Mapping[str, Any]],
) -> None:
    stage = active["stage"]
    expected_pending = _pending_attempts(states)
    if any(pending_stage != stage for _, pending_stage, _, _ in expected_pending):
        raise WatchError("acquisition checkpoint mixes active attempt stages")
    expected_attempts: list[dict[str, Any]] = []
    pending_by_candidate: dict[
        str, list[tuple[str, Mapping[str, Any], Mapping[str, Any] | None]]
    ] = {}
    for candidate_id, pending_stage, pending, page in expected_pending:
        pending_by_candidate.setdefault(candidate_id, []).append(
            (pending_stage, pending, page)
        )
    for candidate_id in binding.candidate_order:
        for pending_stage, pending, page in pending_by_candidate.get(candidate_id, []):
            state = states[candidate_id]
            if candidate_id not in candidate_ids or pending_stage != stage:
                raise WatchError(
                    "acquisition checkpoint pending attempt falls outside its active batch"
                )
            if stage == "navigation":
                if state.get("state") != "pending" or set(pending) != {
                    "attempt",
                    "started_at",
                }:
                    raise WatchError(
                        "acquisition checkpoint active navigation state is malformed"
                    )
                expected_attempts.append(
                    {
                        "candidate_id": candidate_id,
                        "page_ordinal": None,
                        "probe_id": None,
                        "workload_id": None,
                        "attempt": pending["attempt"],
                        "started_at": pending["started_at"],
                    }
                )
                continue
            if (
                state.get("state") != "probing"
                or candidate_id not in baseline_by_candidate
            ):
                raise WatchError("acquisition checkpoint active probe state is malformed")
            page_value = page.get("page") if isinstance(page, Mapping) else None
            ordinal = (
                page_value.get("ordinal") if isinstance(page_value, Mapping) else None
            )
            if (
                type(ordinal) is not int
                or ordinal < 0
                or set(pending)
                != {"probe_id", "workload_id", "attempt", "observed_at"}
            ):
                raise WatchError("acquisition checkpoint active probe state is malformed")
            expected_attempts.append(
                {
                    "candidate_id": candidate_id,
                    "page_ordinal": ordinal,
                    "probe_id": pending["probe_id"],
                    "workload_id": pending["workload_id"],
                    "attempt": pending["attempt"],
                    "started_at": pending["observed_at"],
                }
            )
    if active["attempts"] != expected_attempts:
        raise WatchError(
            "acquisition checkpoint active attempts differ from pending candidate state"
        )
    expected_candidate_ids = list(dict.fromkeys(
        attempt["candidate_id"] for attempt in expected_attempts
    ))
    if candidate_ids != expected_candidate_ids:
        raise WatchError(
            "acquisition checkpoint active candidates differ from pending candidate state"
        )


def _active_batch_summary(value: Any, *, binding: AcquisitionBinding) -> dict[str, Any] | None:
    active = _validate_active_batch(value, binding=binding)
    if active is None:
        return None
    return {
        "batch_id": active["batch_id"],
        "stage": active["stage"],
        "published_at": active["published_at"],
        "candidate_ids": active["candidate_ids"],
        "live_page_count": active["live_page_count"],
        "attempt_count": len(active["attempts"]),
    }


def _git_text(paths: WatchPaths, *arguments: str, cwd: Path | None = None) -> str:
    try:
        completed = subprocess.run(
            (
                "/usr/bin/git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.excludesFile=/dev/null",
                "-C",
                str(cwd or paths.lab_root),
                *arguments,
            ),
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


def _verify_git_checkout_binding(
    paths: WatchPaths, checkout: Path, expected_git_dir: Path
) -> None:
    tree = Path(_git_text(paths, "rev-parse", "--show-toplevel", cwd=checkout))
    git_dir = Path(_git_text(paths, "rev-parse", "--absolute-git-dir", cwd=checkout))
    if tree.resolve(strict=True) != checkout.resolve(strict=True) or git_dir.resolve(
        strict=True
    ) != expected_git_dir.resolve(strict=True):
        raise WatchError("host source checkout has a redirected worktree or gitdir")
    for metadata in (
        expected_git_dir / "info/exclude",
        expected_git_dir / "info/attributes",
        expected_git_dir / "info/grafts",
    ):
        if metadata.is_symlink() or (metadata.exists() and not metadata.is_file()):
            raise WatchError("host source Git metadata has an unsafe type")
        if not metadata.exists():
            continue
        content = metadata.read_text(encoding="utf-8")
        if metadata.name == "grafts":
            unsafe = bool(content)
        else:
            unsafe = any(
                line.strip() and not line.lstrip().startswith("#")
                for line in content.splitlines()
            )
        if unsafe:
            raise WatchError("host source Git metadata can hide checkout bytes")


def _verify_git_index_bytes(paths: WatchPaths, checkout: Path) -> None:
    object_format = _git_text(paths, "rev-parse", "--show-object-format", cwd=checkout)
    if object_format not in {"sha1", "sha256"}:
        raise WatchError("host source Git object format is unsupported")
    command = (
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
        "-C",
        str(checkout),
        "ls-files",
        "--stage",
        "-z",
    )
    try:
        completed = subprocess.run(
            command,
            cwd=paths.lab_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            env=_safe_host_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WatchError("cannot inventory host source index") from error
    if completed.returncode != 0:
        raise WatchError("cannot inventory host source index")
    root_fd = os.open(checkout, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for record in completed.stdout.split(b"\0"):
            if not record:
                continue
            header, separator, relative = record.partition(b"\t")
            fields = header.split(b" ")
            if not separator or len(fields) != 3 or fields[2] != b"0":
                raise WatchError("host source index contains an invalid stage")
            mode, expected = fields[0], fields[1].decode("ascii")
            parts = relative.split(b"/")
            if relative.startswith(b"/") or b".." in parts or any(not p for p in parts):
                raise WatchError("host source index path is unsafe")
            if mode == b"160000":
                continue
            parent_fd = os.dup(root_fd)
            try:
                for component in parts[:-1]:
                    child_fd = os.open(
                        component,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=parent_fd,
                    )
                    os.close(parent_fd)
                    parent_fd = child_fd
                name = parts[-1]
                value = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if mode == b"120000":
                    if not stat.S_ISLNK(value.st_mode):
                        raise WatchError("host source symlink mode changed")
                    payload = os.fsencode(os.readlink(name, dir_fd=parent_fd))
                elif mode in {b"100644", b"100755"}:
                    descriptor = os.open(
                        name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd
                    )
                    try:
                        opened = os.fstat(descriptor)
                        if (
                            not stat.S_ISREG(opened.st_mode)
                            or opened.st_nlink != 1
                            or (opened.st_dev, opened.st_ino)
                            != (value.st_dev, value.st_ino)
                            or bool(opened.st_mode & 0o111) != (mode == b"100755")
                        ):
                            raise WatchError("host source file identity changed")
                        chunks: list[bytes] = []
                        while chunk := os.read(descriptor, 1024 * 1024):
                            chunks.append(chunk)
                        payload = b"".join(chunks)
                    finally:
                        os.close(descriptor)
                else:
                    raise WatchError("host source index mode is unsupported")
            except OSError as error:
                raise WatchError("host source path is unavailable or redirected") from error
            finally:
                os.close(parent_fd)
            digest = hashlib.new(object_format)
            digest.update(b"blob " + str(len(payload)).encode("ascii") + b"\0")
            digest.update(payload)
            if digest.hexdigest() != expected:
                raise WatchError("host source raw bytes differ from the Git index")
    finally:
        os.close(root_fd)


def _host_source_snapshot(paths: WatchPaths) -> tuple[str, str, str | None, str, str]:
    _verify_git_checkout_binding(paths, paths.lab_root, paths.lab_root / ".git")
    _verify_git_checkout_binding(
        paths,
        paths.lab_root / "neqo-qcsd",
        paths.lab_root / ".git/modules/third_party/neqo-qcsd",
    )
    _verify_git_index_bytes(paths, paths.lab_root)
    _verify_git_index_bytes(paths, paths.lab_root / "neqo-qcsd")
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
    return lab_head, neqo_head, gitlink, lab_status, neqo_status


def _validate_host_source(paths: WatchPaths, binding: AcquisitionBinding) -> None:
    """Fail closed if either host checkout drifts or races provenance checks."""

    source = binding.source
    first = _host_source_snapshot(paths)
    second = _host_source_snapshot(paths)
    if first != second:
        raise WatchError("host Lab/Neqo checkout changed while source was verified")
    lab_head, neqo_head, gitlink, lab_status, neqo_status = first
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


def _admission_command(paths: WatchPaths) -> tuple[str, ...]:
    return (
        "/usr/bin/bash",
        str(paths.launcher),
        "class-study",
        "acquisition-admission",
    )


def _scope_command_runtime(command: Sequence[str]) -> int:
    if "acquisition-admission" in command:
        return ADMISSION_RUNTIME_SECONDS
    if "acquisition-status" in command:
        return STATUS_RUNTIME_SECONDS
    if "acquisition-run" in command:
        return RUN_RUNTIME_SECONDS
    raise WatchError("refusing to scope an unrecognised acquisition command")


def _systemctl(
    unit: str,
    *arguments: str,
    environment: Mapping[str, str],
) -> subprocess.CompletedProcess[str]:
    if _SCOPE_UNIT_RE.fullmatch(unit) is None:
        raise WatchError("acquisition scope unit identity is malformed")
    try:
        return subprocess.run(
            ("/usr/bin/systemctl", "--user", *arguments, "--", unit),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=SCOPE_QUERY_TIMEOUT_SECONDS,
            env=dict(environment),
            start_new_session=True,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WatchError(f"cannot inspect acquisition cgroup {unit}: {error}") from error


def _scope_state(unit: str, environment: Mapping[str, str]) -> ScopeState:
    completed = _systemctl(
        unit,
        "show",
        "--no-pager",
        "--property=LoadState",
        "--property=ActiveState",
        "--property=SubState",
        "--property=ControlGroup",
        environment=environment,
    )
    if completed.returncode != 0:
        raise WatchError(f"cannot query acquisition cgroup {unit}")
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "=" not in line:
            raise WatchError(f"acquisition cgroup {unit} returned malformed state")
        key, value = line.split("=", 1)
        if key in values or key not in {
            "LoadState",
            "ActiveState",
            "SubState",
            "ControlGroup",
        }:
            raise WatchError(f"acquisition cgroup {unit} returned ambiguous state")
        values[key] = value
    if set(values) != {"LoadState", "ActiveState", "SubState", "ControlGroup"}:
        raise WatchError(f"acquisition cgroup {unit} returned incomplete state")
    load = values["LoadState"]
    active = values["ActiveState"]
    sub = values["SubState"]
    control_group = values["ControlGroup"] or None
    if load == "not-found" and active == "inactive" and sub == "dead":
        if control_group is not None:
            raise WatchError(f"absent acquisition cgroup {unit} retained a path")
        return ScopeState(load, active, sub, None, ())
    if load != "loaded" or active not in {
        "active",
        "activating",
        "deactivating",
        "inactive",
        "failed",
    }:
        raise WatchError(f"acquisition cgroup {unit} has an unrecognised state")
    if control_group is None:
        if active not in {"inactive", "failed"}:
            raise WatchError(f"active acquisition cgroup {unit} has no kernel path")
        return ScopeState(load, active, sub, None, ())
    if (
        not control_group.startswith("/")
        or "//" in control_group
        or "/../" in control_group
        or control_group.endswith("/..")
        or "/./" in control_group
        or control_group.endswith("/.")
        or not control_group.endswith(f"/{unit}")
        or re.fullmatch(r"/[A-Za-z0-9_.@:/-]+", control_group) is None
    ):
        raise WatchError(f"acquisition cgroup {unit} returned an unsafe kernel path")
    cgroup_root = Path("/sys/fs/cgroup") / control_group.removeprefix("/")
    events_path = cgroup_root / "cgroup.events"
    procs_path = cgroup_root / "cgroup.procs"
    try:
        if cgroup_root.is_symlink() or not cgroup_root.is_dir():
            raise WatchError(f"acquisition cgroup {unit} kernel path is unavailable")
        if events_path.is_symlink() or procs_path.is_symlink():
            raise WatchError(f"acquisition cgroup {unit} kernel files are unsafe")
        events = events_path.read_text(encoding="ascii").splitlines()
        members = procs_path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise WatchError(f"cannot read the complete acquisition cgroup {unit}") from error
    populated: list[str] = []
    for row in events:
        fields = row.split()
        if len(fields) != 2:
            raise WatchError(f"acquisition cgroup {unit} events are malformed")
        if fields[0] == "populated":
            populated.append(fields[1])
    if len(populated) != 1 or populated[0] not in {"0", "1"}:
        raise WatchError(f"acquisition cgroup {unit} has no exact populated state")
    processes: list[int] = []
    for member in members:
        if re.fullmatch(r"[1-9][0-9]*", member) is None:
            raise WatchError(f"acquisition cgroup {unit} process inventory is malformed")
        processes.append(int(member))
    if populated[0] == "0" and processes:
        raise WatchError(f"acquisition cgroup {unit} state contradicts its process inventory")
    if populated[0] == "1" and not processes:
        # Nested cgroups may be populated while the directly bound cgroup is
        # empty.  Represent that as a non-empty sentinel without guessing a PID.
        processes.append(-1)
    return ScopeState(load, active, sub, control_group, tuple(processes))


def _scope_signal(
    unit: str,
    requested: str,
    environment: Mapping[str, str],
) -> bool:
    if requested not in {"SIGINT", "SIGKILL"}:
        raise WatchError("acquisition cgroup signal is invalid")
    completed = _systemctl(
        unit,
        "kill",
        "--kill-whom=all",
        f"--signal={requested}",
        environment=environment,
    )
    return completed.returncode == 0


def _scope_stop(unit: str, environment: Mapping[str, str]) -> bool:
    return _systemctl(unit, "stop", environment=environment).returncode == 0


def _scope_reset(unit: str, environment: Mapping[str, str]) -> bool:
    return _systemctl(unit, "reset-failed", environment=environment).returncode == 0


def _wait_scope_empty(
    unit: str,
    environment: Mapping[str, str],
    *,
    deadline: float,
) -> bool:
    observations = 0
    bound_group: str | None = None
    while time.monotonic() < deadline:
        try:
            state = _scope_state(unit, environment)
        except WatchError:
            observations = 0
            time.sleep(SCOPE_SETTLE_SECONDS)
            continue
        if bound_group is not None and state.control_group not in {None, bound_group}:
            return False
        if state.control_group is not None:
            bound_group = state.control_group
        empty = state.load_state == "not-found" or not state.processes
        if empty:
            observations += 1
            if observations >= SCOPE_EMPTY_OBSERVATIONS:
                if state.active_state in {"active", "activating", "deactivating"}:
                    if not _scope_stop(unit, environment):
                        return False
                    observations = 0
                    bound_group = None
                elif state.active_state == "failed":
                    if not _scope_reset(unit, environment):
                        return False
                    observations = 0
                    bound_group = None
                else:
                    return True
        else:
            observations = 0
        time.sleep(SCOPE_SETTLE_SECONDS)
    return False


def _host_boot_id() -> str:
    try:
        first = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii")
        second = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise WatchError("cannot bind the host boot identity") from error
    first = first.strip()
    if first != second.strip() or _BOOT_ID_RE.fullmatch(first) is None:
        raise WatchError("host boot identity is unstable or malformed")
    return first


def _process_identity(pid: int) -> tuple[int, int, int] | None:
    if type(pid) is not int or pid <= 0:
        raise WatchError("scope supervisor PID is malformed")
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError) as error:
        raise WatchError("cannot authenticate scope supervisor process identity") from error
    close = raw.rfind(")")
    if close <= 1 or close + 2 >= len(raw):
        raise WatchError("scope supervisor process identity is malformed")
    fields = raw[close + 2 :].split()
    if len(fields) < 20 or fields[0] == "Z":
        return None
    try:
        process_group = int(fields[2])
        session = int(fields[3])
        start_time = int(fields[19])
    except ValueError as error:
        raise WatchError("scope supervisor process identity is malformed") from error
    if min(start_time, session, process_group) <= 0:
        raise WatchError("scope supervisor process identity is malformed")
    return start_time, session, process_group


def _current_control_group() -> str:
    """Return the current process's single unified-cgroup pathname."""

    path = Path("/proc/self/cgroup")
    try:
        first = path.read_text(encoding="ascii")
        second = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise WatchError("cannot authenticate the current acquisition cgroup") from error
    if first != second:
        raise WatchError("current acquisition cgroup identity changed while read")
    rows = first.splitlines()
    if len(rows) != 1 or not rows[0].startswith("0::"):
        raise WatchError("current acquisition cgroup identity is malformed")
    control_group = rows[0][3:]
    if (
        not control_group.startswith("/")
        or "//" in control_group
        or "/../" in control_group
        or control_group.endswith("/..")
        or "/./" in control_group
        or control_group.endswith("/.")
        or re.fullmatch(r"/[A-Za-z0-9_.@:/-]+", control_group) is None
    ):
        raise WatchError("current acquisition cgroup identity is unsafe")
    return control_group


def _atomic_scope_record(path: Path, value: Mapping[str, Any]) -> None:
    staged = path.with_name(path.name + ".next")
    raw = _canonical_json_bytes(value)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(staged, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                if count <= 0:
                    raise WatchError("durable acquisition scope record write stalled")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(staged, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except (OSError, WatchError) as error:
        try:
            staged.unlink(missing_ok=True)
        except OSError:
            pass
        if isinstance(error, WatchError):
            raise
        raise WatchError(f"cannot publish durable acquisition scope record: {path}") from error


def _validate_private_state_directory(path: Path, *, label: str) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise WatchError(f"cannot inspect {label}: {path}") from error
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise WatchError(f"{label} is not a private owner-only directory: {path}")


def _create_private_state_directory(path: Path, *, label: str) -> None:
    parent = path.parent
    try:
        parent_state = parent.stat(follow_symlinks=False)
    except OSError as error:
        raise WatchError(f"cannot inspect {label} parent: {parent}") from error
    parent_is_var_tmp = parent == Path("/var/tmp")
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_state.st_mode)
        or (
            not parent_is_var_tmp
            and (
                parent_state.st_uid != os.getuid()
                or stat.S_IMODE(parent_state.st_mode) & 0o022
            )
        )
        or (
            parent_is_var_tmp
            and (
                parent_state.st_uid != 0
                or stat.S_IMODE(parent_state.st_mode) & stat.S_ISVTX == 0
            )
        )
    ):
        raise WatchError(f"{label} parent is not a trusted directory: {parent}")
    try:
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError:
        pass
    except OSError as error:
        raise WatchError(f"cannot create {label}: {path}") from error
    _validate_private_state_directory(path, label=label)


def _ensure_state_namespace(paths: WatchPaths) -> Path:
    _create_private_state_directory(paths.state_base, label="acquisition watch state base")
    root = paths.state_root
    _create_private_state_directory(root, label="acquisition watch state namespace")
    expected = dict(_state_namespace_identity(paths))
    expected["namespace_sha256"] = paths.namespace_sha256
    namespace_path = root / "NAMESPACE.json"
    namespace_staged = root / "NAMESPACE.json.next"
    try:
        namespace_state: os.stat_result | None = namespace_path.stat(
            follow_symlinks=False
        )
    except FileNotFoundError:
        namespace_state = None
    except OSError as error:
        raise WatchError("cannot inspect acquisition watch state namespace receipt") from error
    if namespace_state is None:
        try:
            staged_state: os.stat_result | None = namespace_staged.stat(
                follow_symlinks=False
            )
        except FileNotFoundError:
            staged_state = None
        except OSError as error:
            raise WatchError(
                "cannot inspect staged acquisition watch state namespace receipt"
            ) from error
        if staged_state is not None:
            if (
                not stat.S_ISREG(staged_state.st_mode)
                or staged_state.st_uid != os.getuid()
                or staged_state.st_nlink != 1
                or stat.S_IMODE(staged_state.st_mode) != 0o600
            ):
                raise WatchError(
                    "staged acquisition watch state namespace receipt is unsafe"
                )
            staged_raw, _ = _read_stable_file(
                namespace_staged,
                root=root,
                label="staged acquisition watch state namespace receipt",
            )
            try:
                staged_value = json.loads(staged_raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as error:
                raise WatchError(
                    "staged acquisition watch state namespace receipt is malformed"
                ) from error
            if staged_raw != _canonical_json_bytes(staged_value) or staged_value != expected:
                raise WatchError(
                    "staged acquisition watch state namespace receipt does not verify"
                )
            try:
                os.replace(namespace_staged, namespace_path)
                directory_fd = os.open(
                    root,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                )
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError as error:
                raise WatchError(
                    "cannot finish acquisition watch state namespace publication"
                ) from error
        else:
            _atomic_scope_record(namespace_path, expected)
    try:
        namespace_state = namespace_path.stat(follow_symlinks=False)
    except OSError as error:
        raise WatchError("cannot inspect acquisition watch state namespace receipt") from error
    if (
        not stat.S_ISREG(namespace_state.st_mode)
        or namespace_state.st_uid != os.getuid()
        or namespace_state.st_nlink != 1
        or stat.S_IMODE(namespace_state.st_mode) != 0o600
    ):
        raise WatchError(
            "acquisition watch state namespace receipt is not a private single regular file"
        )
    raw, _ = _read_stable_file(
        namespace_path,
        root=root,
        label="acquisition watch state namespace receipt",
    )
    try:
        observed = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise WatchError("acquisition watch state namespace receipt is malformed") from error
    if raw != _canonical_json_bytes(observed) or observed != expected:
        raise WatchError("acquisition watch state namespace receipt does not verify")
    try:
        staged_state = namespace_staged.stat(follow_symlinks=False)
    except FileNotFoundError:
        staged_state = None
    except OSError as error:
        raise WatchError(
            "cannot inspect stale acquisition watch namespace publication"
        ) from error
    if staged_state is not None:
        if (
            not stat.S_ISREG(staged_state.st_mode)
            or staged_state.st_uid != os.getuid()
            or staged_state.st_nlink != 1
            or stat.S_IMODE(staged_state.st_mode) != 0o600
        ):
            raise WatchError("stale acquisition watch namespace publication is unsafe")
        try:
            namespace_staged.unlink()
            directory_fd = os.open(
                root,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as error:
            raise WatchError(
                "cannot remove stale acquisition watch namespace publication"
            ) from error
    lock_path = root / "WATCH.lock"
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except FileExistsError:
        descriptor = -1
    except OSError as error:
        raise WatchError("cannot create acquisition watch lock") from error
    if descriptor >= 0:
        try:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    try:
        lock_state = lock_path.stat(follow_symlinks=False)
    except OSError as error:
        raise WatchError("cannot inspect acquisition watch lock") from error
    if (
        lock_path.is_symlink()
        or not stat.S_ISREG(lock_state.st_mode)
        or lock_state.st_uid != os.getuid()
        or lock_state.st_nlink != 1
        or stat.S_IMODE(lock_state.st_mode) != 0o600
    ):
        raise WatchError("acquisition watch lock is not a private single regular file")
    return root


def _scope_supervision_record(
    *,
    state_root: Path,
    unit: str,
    command: Sequence[str],
    authority_fd: int,
    birth_lock_fd: int,
    source_binding_sha256: str,
    request_nonce: str,
) -> dict[str, Any]:
    identity = _process_identity(os.getpid())
    if identity is None:
        raise WatchError("cannot bind the live acquisition scope supervisor")
    start_time, session, process_group = identity
    lock_state = os.fstat(authority_fd)
    birth_lock_state = os.fstat(birth_lock_fd)
    token = unit.removeprefix("qcsd-class-watch-").removesuffix(".scope")
    action_sha256 = _sha256_bytes(_canonical_json_bytes(list(command)))
    authority = _scope_request_authority(
        action_sha256=action_sha256,
        request_nonce=request_nonce,
        scope_token=token,
        scope_unit=unit,
        source_binding_sha256=source_binding_sha256,
        state_namespace_sha256=state_root.name,
    )
    return {
        "action_sha256": action_sha256,
        "artifact_type": SCOPE_SUPERVISION_TYPE,
        "birth_lock_device": birth_lock_state.st_dev,
        "birth_lock_inode": birth_lock_state.st_ino,
        "host_boot_id": _host_boot_id(),
        "lock_device": lock_state.st_dev,
        "lock_inode": lock_state.st_ino,
        "phase": "declared-before-request",
        "request_authority_sha256": authority,
        "request_nonce": request_nonce,
        "schema_version": SCHEMA_VERSION,
        "scope_token": token,
        "scope_unit": unit,
        "source_binding_sha256": source_binding_sha256,
        "state_namespace_sha256": state_root.name,
        "supervisor_pid": os.getpid(),
        "supervisor_process_group": process_group,
        "supervisor_session": session,
        "supervisor_start_time": start_time,
        "wrapper_pid": 0,
        "wrapper_process_group": 0,
        "wrapper_session": 0,
        "wrapper_start_time": 0,
    }


def _scope_request_authority(
    *,
    action_sha256: str,
    request_nonce: str,
    scope_token: str,
    scope_unit: str,
    source_binding_sha256: str,
    state_namespace_sha256: str,
) -> str:
    return _sha256_bytes(
        _canonical_json_bytes(
            {
                "action_sha256": action_sha256,
                "request_nonce": request_nonce,
                "scope_token": scope_token,
                "scope_unit": scope_unit,
                "source_binding_sha256": source_binding_sha256,
                "state_namespace_sha256": state_namespace_sha256,
            }
        )
    )


def _scope_token(root: Path) -> str:
    match = _SCOPE_ROOT_RE.fullmatch(root.name)
    if match is None:
        raise WatchError(f"acquisition scope root name is malformed: {root}")
    return root.name.rsplit(".", 1)[1]


def _validate_scope_record(
    value: Any,
    *,
    recovery: bool,
    root: Path,
    state_root: Path,
) -> dict[str, Any]:
    common = {
        "action_sha256",
        "artifact_type",
        "birth_lock_device",
        "birth_lock_inode",
        "host_boot_id",
        "lock_device",
        "lock_inode",
        "phase",
        "request_authority_sha256",
        "request_nonce",
        "schema_version",
        "scope_token",
        "scope_unit",
        "source_binding_sha256",
        "state_namespace_sha256",
        "supervisor_pid",
        "supervisor_process_group",
        "supervisor_session",
        "supervisor_start_time",
        "wrapper_pid",
        "wrapper_process_group",
        "wrapper_session",
        "wrapper_start_time",
    }
    expected = common | (
        {"empty_observations", "outcome", "recovered_from_phase"}
        if recovery
        else set()
    )
    if not isinstance(value, dict) or set(value) != expected:
        raise WatchError("acquisition scope record differs from the exact contract")
    positive_numeric = (
        "birth_lock_device",
        "birth_lock_inode",
        "lock_device",
        "lock_inode",
        "supervisor_pid",
        "supervisor_process_group",
        "supervisor_session",
        "supervisor_start_time",
    )
    wrapper_numeric = (
        "wrapper_pid",
        "wrapper_process_group",
        "wrapper_session",
        "wrapper_start_time",
    )
    launch_phase = value.get("recovered_from_phase") if recovery else value["phase"]
    if (
        value["schema_version"] != SCHEMA_VERSION
        or value["artifact_type"]
        != (SCOPE_RECOVERY_TYPE if recovery else SCOPE_SUPERVISION_TYPE)
        or value["phase"]
        not in (
            {"empty-proven"}
            if recovery
            else {
                "declared-before-request",
                "request-authorised",
                "armed-for-exec",
            }
        )
        or launch_phase
        not in {
            "declared-before-request",
            "request-authorised",
            "armed-for-exec",
        }
        or not isinstance(value["action_sha256"], str)
        or _SHA256_RE.fullmatch(value["action_sha256"]) is None
        or not isinstance(value["host_boot_id"], str)
        or _BOOT_ID_RE.fullmatch(value["host_boot_id"]) is None
        or not isinstance(value["scope_unit"], str)
        or _SCOPE_UNIT_RE.fullmatch(value["scope_unit"]) is None
        or not isinstance(value["scope_token"], str)
        or re.fullmatch(r"[0-9a-f]{32}", value["scope_token"]) is None
        or value["scope_token"] != _scope_token(root)
        or value["scope_unit"] != f"qcsd-class-watch-{value['scope_token']}.scope"
        or not isinstance(value["source_binding_sha256"], str)
        or _SHA256_RE.fullmatch(value["source_binding_sha256"]) is None
        or value["state_namespace_sha256"] != state_root.name
        or _STATE_NAMESPACE_RE.fullmatch(value["state_namespace_sha256"]) is None
        or not isinstance(value["request_nonce"], str)
        or _SHA256_RE.fullmatch(value["request_nonce"]) is None
        or not isinstance(value["request_authority_sha256"], str)
        or value["request_authority_sha256"]
        != _scope_request_authority(
            action_sha256=value["action_sha256"],
            request_nonce=value["request_nonce"],
            scope_token=value["scope_token"],
            scope_unit=value["scope_unit"],
            source_binding_sha256=value["source_binding_sha256"],
            state_namespace_sha256=value["state_namespace_sha256"],
        )
        or any(
            type(value[name]) is not int or value[name] <= 0
            for name in positive_numeric
        )
        or any(
            type(value[name]) is not int or value[name] < 0
            for name in wrapper_numeric
        )
    ):
        raise WatchError("acquisition scope record contains malformed identity")
    wrapper_values = tuple(value[name] for name in wrapper_numeric)
    if launch_phase == "declared-before-request":
        if any(wrapper_values):
            raise WatchError("declared acquisition scope unexpectedly binds a wrapper")
    elif any(item <= 0 for item in wrapper_values):
        raise WatchError("authorised acquisition scope has no exact wrapper identity")
    if recovery and (
        value["empty_observations"] != SCOPE_EMPTY_OBSERVATIONS
        or value["outcome"] != "scope-empty-and-inactive"
    ):
        raise WatchError("acquisition scope recovery proof is malformed")
    return dict(value)


def _read_scope_record(
    root: Path,
    *,
    state_root: Path,
) -> tuple[dict[str, Any], Path, bool]:
    candidates = [root / "SUPERVISION", root / "RECOVERY"]
    present = [path for path in candidates if path.exists()]
    if len(present) != 1:
        raise WatchError(f"acquisition scope root has ambiguous durable state: {root}")
    path = present[0]
    raw, _ = _read_stable_file(path, root=root, label="scope lifecycle record")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise WatchError("acquisition scope lifecycle record is malformed") from error
    if raw != _canonical_json_bytes(value):
        raise WatchError("acquisition scope lifecycle record is not canonical")
    recovery = (
        value.get("artifact_type") == SCOPE_RECOVERY_TYPE
        if isinstance(value, dict)
        else False
    )
    # During the atomic SUPERVISION -> RECOVERY pathname transition a recovery
    # envelope is deliberately valid at either of the two names.
    return (
        _validate_scope_record(
            value,
            recovery=recovery,
            root=root,
            state_root=state_root,
        ),
        path,
        recovery,
    )


def _replace_scope_phase(
    root: Path,
    supervision: Mapping[str, Any],
    *,
    phase: str,
    wrapper_identity: tuple[int, int, int, int],
    state_root: Path,
) -> dict[str, Any]:
    if phase not in {"request-authorised", "armed-for-exec"}:
        raise WatchError("acquisition scope phase transition is invalid")
    wrapper_pid, start_time, session, process_group = wrapper_identity
    updated = dict(supervision)
    updated.update(
        {
            "artifact_type": SCOPE_SUPERVISION_TYPE,
            "phase": phase,
            "wrapper_pid": wrapper_pid,
            "wrapper_process_group": process_group,
            "wrapper_session": session,
            "wrapper_start_time": start_time,
        }
    )
    _validate_scope_record(
        updated,
        recovery=False,
        root=root,
        state_root=state_root,
    )
    _atomic_scope_record(root / "SUPERVISION", updated)
    return updated


def _publish_scope_go(root: Path, *, authority: str) -> None:
    if _SHA256_RE.fullmatch(authority) is None:
        raise WatchError("acquisition scope execution authority is malformed")
    path = root / "GO"
    staged = root / "GO.next"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if path.exists():
        raise WatchError("acquisition scope execution was already released")
    try:
        descriptor = os.open(staged, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            raw = (authority + "\n").encode("ascii")
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                if count <= 0:
                    raise WatchError("acquisition scope execution release write stalled")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(staged, path)
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except (OSError, WatchError) as error:
        try:
            staged.unlink(missing_ok=True)
        except OSError:
            pass
        if isinstance(error, WatchError):
            raise
        raise WatchError("cannot publish acquisition scope execution release") from error


def _publish_scope_recovery(
    root: Path,
    supervision: Mapping[str, Any],
    *,
    state_root: Path,
) -> dict[str, Any]:
    recovery = dict(supervision)
    recovered_from_phase = recovery["phase"]
    recovery.update(
        {
            "artifact_type": SCOPE_RECOVERY_TYPE,
            "empty_observations": SCOPE_EMPTY_OBSERVATIONS,
            "outcome": "scope-empty-and-inactive",
            "phase": "empty-proven",
            "recovered_from_phase": recovered_from_phase,
        }
    )
    _validate_scope_record(
        recovery,
        recovery=True,
        root=root,
        state_root=state_root,
    )
    transition = root / "SUPERVISION"
    _atomic_scope_record(transition, recovery)
    try:
        os.replace(transition, root / "RECOVERY")
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        raise WatchError("cannot finish durable acquisition scope recovery") from error
    return recovery


def _validate_state_namespace_root(state_root: Path) -> None:
    _validate_private_state_directory(
        state_root,
        label="acquisition watch state namespace",
    )
    if _STATE_NAMESPACE_RE.fullmatch(state_root.name) is None:
        raise WatchError("acquisition watch state namespace name is malformed")
    namespace_path = state_root / "NAMESPACE.json"
    try:
        namespace_state = namespace_path.stat(follow_symlinks=False)
    except OSError as error:
        raise WatchError("cannot inspect acquisition watch state namespace receipt") from error
    if (
        namespace_path.is_symlink()
        or not stat.S_ISREG(namespace_state.st_mode)
        or namespace_state.st_uid != os.getuid()
        or namespace_state.st_nlink != 1
        or stat.S_IMODE(namespace_state.st_mode) != 0o600
    ):
        raise WatchError(
            "acquisition watch state namespace receipt is not a private single regular file"
        )
    raw, _ = _read_stable_file(
        namespace_path,
        root=state_root,
        label="acquisition watch state namespace receipt",
    )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise WatchError("acquisition watch state namespace receipt is malformed") from error
    expected_keys = {
        "acquisition_root",
        "artifact_type",
        "lab_root",
        "namespace_sha256",
        "schema_version",
        "study_id",
    }
    if (
        raw != _canonical_json_bytes(value)
        or not isinstance(value, dict)
        or set(value) != expected_keys
        or value["artifact_type"] != SCOPE_NAMESPACE_TYPE
        or value["schema_version"] != SCHEMA_VERSION
        or value["study_id"] != STUDY_ID
        or value["namespace_sha256"] != state_root.name
        or not isinstance(value["lab_root"], str)
        or not os.path.isabs(value["lab_root"])
        or not isinstance(value["acquisition_root"], str)
        or not os.path.isabs(value["acquisition_root"])
    ):
        raise WatchError("acquisition watch state namespace receipt does not verify")
    identity = dict(value)
    del identity["namespace_sha256"]
    if _sha256_bytes(_canonical_json_bytes(identity)) != state_root.name:
        raise WatchError("acquisition watch state namespace digest does not verify")


def _paths_from_state_namespace(state_root: Path) -> WatchPaths:
    _validate_state_namespace_root(state_root)
    raw, _ = _read_stable_file(
        state_root / "NAMESPACE.json", root=state_root,
        label="acquisition watch state namespace receipt",
    )
    value = json.loads(raw.decode("utf-8"))
    paths = WatchPaths.from_lab_root(Path(value["lab_root"]), state_base=state_root.parent)
    if paths.state_root != state_root or str(paths.acquisition_root) != value["acquisition_root"]:
        raise WatchError("acquisition watch namespace does not derive canonical paths")
    return paths


def _assert_watch_lock_held(state_root: Path) -> tuple[int, int]:
    path = state_root / "WATCH.lock"
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise WatchError("cannot authenticate the acquisition watch lock") from error
    acquired = False
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise WatchError("acquisition watch lock identity is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except BlockingIOError:
            return metadata.st_dev, metadata.st_ino
        raise WatchError("acquisition watch state is not owned by a live supervisor lock")
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _assert_recorded_watch_lock_holder(state_root: Path, record: Mapping[str, Any]) -> None:
    expected = (record["supervisor_start_time"], record["supervisor_session"], record["supervisor_process_group"])
    if _process_identity(record["supervisor_pid"]) != expected:
        raise WatchError("recorded acquisition supervisor identity is not live")
    metadata = os.stat(state_root / "WATCH.lock", follow_symlinks=False)
    if (metadata.st_dev, metadata.st_ino) != (record["lock_device"], record["lock_inode"]):
        raise WatchError("recorded acquisition supervisor lock identity changed")
    needle = (os.major(metadata.st_dev), os.minor(metadata.st_dev), metadata.st_ino)
    try:
        lines = Path("/proc/locks").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise WatchError("cannot prove the recorded acquisition supervisor lock holder") from error
    owners = []
    for line in lines:
        fields = line.split()
        if len(fields) < 8 or fields[1:4] != ["FLOCK", "ADVISORY", "WRITE"]:
            continue
        try:
            major, minor, inode = fields[5].split(":")
            identity = (int(major, 16), int(minor, 16), int(inode))
            owner = int(fields[4])
        except (ValueError, IndexError):
            continue
        if identity == needle:
            owners.append(owner)
    if owners != [record["supervisor_pid"]]:
        raise WatchError("recorded acquisition supervisor does not hold the exact watch lock")
    if _process_identity(record["supervisor_pid"]) != expected:
        raise WatchError("recorded acquisition supervisor changed during lock proof")


def _state_scope_roots(state_root: Path) -> tuple[list[Path], list[Path]]:
    try:
        children = sorted(state_root.iterdir())
    except OSError as error:
        raise WatchError("cannot enumerate acquisition watch state") from error
    roots: list[Path] = []
    unexpected: list[Path] = []
    for child in children:
        if _SCOPE_ROOT_RE.fullmatch(child.name) is not None:
            roots.append(child)
        elif child.name not in {"NAMESPACE.json", "WATCH.lock"}:
            unexpected.append(child)
    return roots, unexpected


def _validate_scope_children(root: Path) -> set[str]:
    try:
        children = list(root.iterdir())
    except OSError as error:
        raise WatchError(f"cannot inspect private acquisition scope root: {root}") from error
    names: set[str] = set()
    for child in children:
        if child.name in names or child.name not in _SCOPE_ROOT_FILES:
            raise WatchError(f"private acquisition scope root has an unexpected entry: {root}")
        names.add(child.name)
        try:
            metadata = child.stat(follow_symlinks=False)
        except OSError as error:
            raise WatchError(f"cannot inspect private acquisition scope file: {child}") from error
        if (
            child.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise WatchError(f"private acquisition scope file is unsafe: {child}")
    return names


def _open_scope_birth_lock(
    root: Path,
    *,
    record: Mapping[str, Any] | None,
) -> tuple[int | None, bool]:
    """Authenticate and probe the launch lock without disturbing its owner."""

    path = root / "BIRTH.lock"
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if record is None:
            return None, False
        raise WatchError("acquisition scope birth lock is absent") from None
    except OSError as error:
        raise WatchError("cannot open acquisition scope birth lock") from error
    try:
        metadata = os.fstat(descriptor)
        try:
            pathname = os.stat(path, follow_symlinks=False)
        except OSError as error:
            raise WatchError("acquisition scope birth lock pathname changed") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not stat.S_ISREG(pathname.st_mode)
            or metadata.st_uid != os.getuid()
            or pathname.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or pathname.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or stat.S_IMODE(pathname.st_mode) != 0o600
            or (metadata.st_dev, metadata.st_ino)
            != (pathname.st_dev, pathname.st_ino)
            or (
                record is not None
                and (metadata.st_dev, metadata.st_ino)
                != (record["birth_lock_device"], record["birth_lock_inode"])
            )
        ):
            raise WatchError("acquisition scope birth lock identity does not verify")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(descriptor)
            return None, True
        return descriptor, False
    except BaseException:
        os.close(descriptor)
        raise


def _wait_scope_birth_lock(
    root: Path,
    *,
    record: Mapping[str, Any] | None,
    deadline: float,
) -> int | None:
    """Hold the exact birth lock before accepting absence or deleting its root."""

    while time.monotonic() < deadline:
        descriptor, busy = _open_scope_birth_lock(root, record=record)
        if descriptor is not None or not busy:
            return descriptor
        time.sleep(SCOPE_SETTLE_SECONDS)
    raise WatchError("acquisition scope launcher birth remains possible")


def _validate_held_scope_birth_lock(
    root: Path,
    *,
    record: Mapping[str, Any],
    descriptor: int,
) -> None:
    path = root / "BIRTH.lock"
    try:
        held = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise WatchError("held acquisition scope birth lock is unavailable") from error
    if (
        not stat.S_ISREG(held.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or held.st_uid != os.getuid()
        or current.st_uid != os.getuid()
        or held.st_nlink != 1
        or current.st_nlink != 1
        or stat.S_IMODE(held.st_mode) != 0o600
        or stat.S_IMODE(current.st_mode) != 0o600
        or (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino)
        or (held.st_dev, held.st_ino)
        != (record["birth_lock_device"], record["birth_lock_inode"])
    ):
        raise WatchError("held acquisition scope birth lock identity does not verify")


def _read_scope_request(
    root: Path,
    *,
    record: Mapping[str, Any],
    required: bool,
) -> dict[str, Any] | None:
    path = root / "REQUEST"
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        if required:
            raise WatchError("acquisition scope request binding is absent")
        return None
    except OSError as error:
        raise WatchError("cannot inspect acquisition scope request binding") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise WatchError("acquisition scope request binding is unsafe")
    raw, _ = _read_stable_file(path, root=root, label="acquisition scope request binding")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise WatchError("acquisition scope request binding is malformed") from error
    expected = {
        "action_sha256",
        "artifact_type",
        "request_authority_sha256",
        "request_nonce",
        "schema_version",
        "scope_token",
        "scope_unit",
        "source_binding_sha256",
        "state_namespace_sha256",
        "wrapper_pid",
    }
    if (
        raw != _canonical_json_bytes(value)
        or not isinstance(value, dict)
        or set(value) != expected
        or value["artifact_type"] != "qcsd-class-watch-scope-request"
        or value["schema_version"] != SCHEMA_VERSION
        or type(value["wrapper_pid"]) is not int
        or value["wrapper_pid"] <= 0
        or any(
            value[name] != record[name]
            for name in expected - {"artifact_type", "schema_version", "wrapper_pid"}
        )
    ):
        raise WatchError("acquisition scope request binding does not verify")
    return value


def _read_scope_go(root: Path, *, authority: str, required: bool) -> bool:
    path = root / "GO"
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        if required:
            raise WatchError("acquisition scope execution release is absent")
        return False
    except OSError as error:
        raise WatchError("cannot inspect acquisition scope execution release") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise WatchError("acquisition scope execution release is unsafe")
    raw, _ = _read_stable_file(path, root=root, label="acquisition scope execution release")
    if raw != (authority + "\n").encode("ascii"):
        raise WatchError("acquisition scope execution release does not authenticate")
    return True


def _validate_current_scope(
    root: Path,
    *,
    record: Mapping[str, Any],
    recovery: bool,
    request: Mapping[str, Any] | None,
    state: ScopeState,
    current_authority: str | None,
    expected_action_sha256: str | None,
    expected_source_binding_sha256: str | None,
) -> None:
    _assert_recorded_watch_lock_holder(root.parent, record)
    expected_supervisor = (
        record["supervisor_start_time"],
        record["supervisor_session"],
        record["supervisor_process_group"],
    )
    expected_wrapper = (
        record["wrapper_start_time"],
        record["wrapper_session"],
        record["wrapper_process_group"],
    )
    if (
        recovery
        or record["phase"] != "armed-for-exec"
        or current_authority is None
        or current_authority != record["request_authority_sha256"]
        or expected_action_sha256 is None
        or expected_action_sha256 != record["action_sha256"]
        or expected_source_binding_sha256 is None
        or expected_source_binding_sha256 != record["source_binding_sha256"]
        or record["host_boot_id"] != _host_boot_id()
        or _process_identity(record["supervisor_pid"]) != expected_supervisor
        or request is None
        or _process_identity(record["wrapper_pid"]) != expected_wrapper
        or record["wrapper_pid"] not in state.processes
        or os.getpid() not in state.processes
        or state.control_group is None
        or _current_control_group() != state.control_group
        or not _read_scope_go(root, authority=current_authority, required=True)
    ):
        raise WatchError("current acquisition scope request authority does not verify")


def _validate_stale_scope_state(
    root: Path,
    *,
    record: Mapping[str, Any],
    recovery: bool,
    request: Mapping[str, Any] | None,
    state: ScopeState,
    birth_lock_busy: bool,
) -> None:
    phase = record["recovered_from_phase"] if recovery else record["phase"]
    go_present = _read_scope_go(
        root,
        authority=record["request_authority_sha256"],
        required=False,
    )
    if recovery:
        if state.processes or state.active_state in {"active", "activating", "deactivating"}:
            raise WatchError("recovered acquisition scope unit was reused")
        return
    if phase == "declared-before-request":
        if go_present:
            raise WatchError("declared acquisition scope has an execution release")
        if request is None:
            if state.processes and not birth_lock_busy:
                raise WatchError("unrequested acquisition scope has a populated unit")
            return
        if state.processes and request["wrapper_pid"] not in state.processes:
            raise WatchError("unconfirmed acquisition scope request has another process")
        return
    if request is None:
        raise WatchError("authorised acquisition scope has no request binding")
    if phase == "request-authorised" and go_present:
        raise WatchError("unarmed acquisition scope has an execution release")


def _wait_scope_absent(unit: str, environment: Mapping[str, str]) -> bool:
    for observation in range(SCOPE_EMPTY_OBSERVATIONS):
        if _scope_state(unit, environment).load_state != "not-found":
            return False
        if observation + 1 < SCOPE_EMPTY_OBSERVATIONS:
            time.sleep(SCOPE_SETTLE_SECONDS)
    return True


def _discard_staged_scope_files(root: Path, *, state_root: Path) -> None:
    """Remove only authenticated, now-inert atomic-write remnants.

    A process can die after creating ``SUPERVISION.next`` but before replacing
    the durable record.  Once the associated cgroup has been proved empty, the
    staged file has no remaining authority and must not make every subsequent
    recovery attempt fail at ``O_EXCL``.  Validate each inode before unlinking
    and fsync the containing directory so recovery can safely be retried.
    """

    _validate_scope_root(root, state_root=state_root)
    changed = False
    for name in (
        "SUPERVISION.next",
        "RECOVERY.next",
        "REQUEST.next",
        "GO.next",
        "status.next",
    ):
        path = root / name
        try:
            metadata = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise WatchError(f"cannot inspect staged acquisition scope file: {path}") from error
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise WatchError(f"staged acquisition scope file is unsafe: {path}")
        try:
            path.unlink()
        except OSError as error:
            raise WatchError(f"cannot remove staged acquisition scope file: {path}") from error
        changed = True
    if changed:
        try:
            directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as error:
            raise WatchError("cannot persist staged acquisition scope cleanup") from error


def _recover_stale_scope_roots(
    *,
    state_root: Path,
    current_root: Path | None = None,
    current_authority: str | None = None,
    expected_action_sha256: str | None = None,
    expected_source_binding_sha256: str | None = None,
) -> int:
    environment = _safe_host_environment()
    _validate_state_namespace_root(state_root)
    lock_identity = _assert_watch_lock_held(state_root)
    roots, unexpected = _state_scope_roots(state_root)
    if unexpected:
        raise WatchError(
            f"acquisition watch state contains an unexpected entry: {unexpected[0]}"
        )
    seen_tokens: set[str] = set()
    plans: list[ScopeRecoveryPlan] = []
    held_birth_fds: set[int] = set()
    try:
        for root in roots:
            _validate_scope_root(root, state_root=state_root)
            child_names = _validate_scope_children(root)
            token = _scope_token(root)
            if token in seen_tokens:
                raise WatchError("acquisition watch state contains a duplicate scope token")
            seen_tokens.add(token)
            unit = f"qcsd-class-watch-{token}.scope"
            if not child_names & {"SUPERVISION", "RECOVERY"}:
                if (
                    (not root.name.startswith("scope.next.") and bool(child_names))
                    or child_names - {"BIRTH.lock", "SUPERVISION.next"}
                ):
                    raise WatchError("acquisition scope root has no durable lifecycle record")
                birth_fd, birth_busy = _open_scope_birth_lock(root, record=None)
                if birth_fd is not None:
                    held_birth_fds.add(birth_fd)
                state = _scope_state(unit, environment)
                if state.load_state != "not-found":
                    raise WatchError("unpublished acquisition scope root has a live unit")
                plans.append(
                    ScopeRecoveryPlan(
                        root,
                        None,
                        False,
                        unit,
                        state,
                        None,
                        birth_fd,
                        birth_busy,
                        False,
                    )
                )
                continue
            record, _, recovery = _read_scope_record(root, state_root=state_root)
            if (record["lock_device"], record["lock_inode"]) != lock_identity:
                raise WatchError("acquisition scope record names another supervisor lock")
            if record["scope_unit"] != unit:
                raise WatchError("acquisition scope root and unit identities differ")
            birth_missing_after_recovery = recovery and "BIRTH.lock" not in child_names
            if birth_missing_after_recovery:
                if child_names != {"RECOVERY"}:
                    raise WatchError(
                        "birth-free acquisition recovery is not an exact teardown state"
                    )
                birth_fd, birth_busy = None, False
            else:
                birth_fd, birth_busy = _open_scope_birth_lock(root, record=record)
            if birth_fd is not None:
                held_birth_fds.add(birth_fd)
            request = _read_scope_request(root, record=record, required=False)
            state = _scope_state(unit, environment)
            if birth_missing_after_recovery and state.load_state != "not-found":
                raise WatchError("birth-free acquisition recovery retained a unit")
            if current_root is not None and root == current_root:
                if not birth_busy:
                    raise WatchError("current acquisition scope has no live launcher")
                _validate_current_scope(
                    root,
                    record=record,
                    recovery=recovery,
                    request=request,
                    state=state,
                    current_authority=current_authority,
                    expected_action_sha256=expected_action_sha256,
                    expected_source_binding_sha256=expected_source_binding_sha256,
                )
                plans.append(
                    ScopeRecoveryPlan(
                        root,
                        record,
                        recovery,
                        unit,
                        state,
                        request,
                        birth_fd,
                        birth_busy,
                    )
                )
                continue
            if not recovery and record["host_boot_id"] == _host_boot_id():
                observed = _process_identity(record["supervisor_pid"])
                expected = (
                    record["supervisor_start_time"],
                    record["supervisor_session"],
                    record["supervisor_process_group"],
                )
                if observed == expected:
                    raise WatchError(f"another live acquisition scope owns {root}")
            if record["host_boot_id"] != _host_boot_id():
                if state.load_state != "not-found":
                    raise WatchError("pre-boot acquisition scope unit identity was reused")
            else:
                _validate_stale_scope_state(
                    root,
                    record=record,
                    recovery=recovery,
                    request=request,
                    state=state,
                    birth_lock_busy=birth_busy,
                )
            plans.append(
                ScopeRecoveryPlan(
                    root,
                    record,
                    recovery,
                    unit,
                    state,
                    request,
                    birth_fd,
                    birth_busy,
                    birth_missing_after_recovery,
                )
            )

        if current_root is not None and all(plan.root != current_root for plan in plans):
            raise WatchError("current acquisition scope is absent from durable state")

        # No process, unit or pathname is mutated until every reserved root has
        # passed the complete structural, process and cgroup admission above.
        recovered = 0
        for plan in plans:
            if current_root is not None and plan.root == current_root:
                continue
            birth_fd = plan.birth_lock_fd
            if plan.record is None:
                if birth_fd is None:
                    birth_fd = _wait_scope_birth_lock(
                        plan.root,
                        record=None,
                        deadline=time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS * 2,
                    )
                    if birth_fd is not None:
                        held_birth_fds.add(birth_fd)
                if not _wait_scope_absent(plan.unit, environment):
                    raise WatchError("unpublished acquisition scope unit appeared during recovery")
            else:
                launch_phase = (
                    plan.record["recovered_from_phase"]
                    if plan.recovery
                    else plan.record["phase"]
                )
                authorised = (
                    launch_phase != "declared-before-request" or plan.request is not None
                )
                if plan.record["host_boot_id"] == _host_boot_id() and authorised:
                    state = _scope_state(plan.unit, environment)
                    if state.processes and not _scope_signal(
                        plan.unit, "SIGKILL", environment
                    ):
                        raise WatchError(
                            f"cannot terminate stale acquisition scope {plan.unit}"
                        )
                birth_missing_after_recovery = plan.birth_missing_after_recovery
                if birth_fd is None and not birth_missing_after_recovery:
                    birth_fd = _wait_scope_birth_lock(
                        plan.root,
                        record=plan.record,
                        deadline=time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS * 2,
                    )
                    if birth_fd is not None:
                        held_birth_fds.add(birth_fd)
                if birth_missing_after_recovery:
                    if not _wait_scope_absent(plan.unit, environment):
                        raise WatchError(
                            "birth-free acquisition recovery unit reappeared"
                        )
                elif plan.record["host_boot_id"] != _host_boot_id():
                    if not _wait_scope_absent(plan.unit, environment):
                        raise WatchError("pre-boot acquisition scope unit was reused")
                elif not authorised:
                    if not _wait_scope_empty(
                        plan.unit,
                        environment,
                        deadline=time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS,
                    ):
                        raise WatchError(
                            "unauthorised acquisition scope is populated or unprovable"
                        )
                else:
                    state = _scope_state(plan.unit, environment)
                    if state.processes and not _scope_signal(
                        plan.unit, "SIGKILL", environment
                    ):
                        raise WatchError(
                            f"cannot terminate stale acquisition scope {plan.unit}"
                        )
                    if not _wait_scope_empty(
                        plan.unit,
                        environment,
                        deadline=time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS,
                    ):
                        raise WatchError(
                            f"stale acquisition scope remains non-empty: {plan.unit}"
                        )
                if not birth_missing_after_recovery:
                    _discard_staged_scope_files(plan.root, state_root=state_root)
                if not plan.recovery:
                    recovery_record = _publish_scope_recovery(
                        plan.root,
                        plan.record,
                        state_root=state_root,
                    )
                else:
                    recovery_record = plan.record
                _finish_scope_teardown(
                    plan.root,
                    state_root=state_root,
                    recovery=recovery_record,
                    birth_lock_fd=birth_fd,
                )
            if plan.record is None:
                _finish_unpublished_scope_teardown(
                    plan.root,
                    state_root=state_root,
                    birth_lock_fd=birth_fd,
                )
            recovered += 1
        return recovered
    finally:
        for descriptor in held_birth_fds:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _validate_scope_root(root: Path, *, state_root: Path) -> None:
    try:
        metadata = root.stat(follow_symlinks=False)
    except OSError as error:
        raise WatchError(f"cannot inspect private acquisition scope root: {root}") from error
    if (
        root.parent != state_root
        or _SCOPE_ROOT_RE.fullmatch(root.name) is None
        or root.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise WatchError(f"unsafe acquisition scope root blocks recovery: {root}")


def _fsync_scope_directory(path: Path, *, label: str) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise WatchError(f"cannot persist {label}") from error


def _unlink_scope_file(path: Path, *, label: str) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise WatchError(f"cannot inspect {label}: {path}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise WatchError(f"unsafe {label}: {path}")
    try:
        path.unlink()
    except OSError as error:
        raise WatchError(f"cannot remove {label}: {path}") from error


def _finish_scope_teardown(
    root: Path,
    *,
    state_root: Path,
    recovery: Mapping[str, Any],
    birth_lock_fd: int | None,
) -> None:
    """Remove an empty recovered scope in a SIGKILL-resumable order."""

    _validate_scope_root(root, state_root=state_root)
    children = _validate_scope_children(root)
    if "SUPERVISION" in children or any(name.endswith(".next") for name in children):
        raise WatchError("recovered acquisition scope retains staged authority")
    if "RECOVERY" not in children:
        raise WatchError("acquisition scope teardown has no recovery authority")
    observed, _, is_recovery = _read_scope_record(root, state_root=state_root)
    if not is_recovery or observed != recovery:
        raise WatchError("acquisition scope recovery changed before teardown")
    ordinary = children - {"BIRTH.lock", "RECOVERY"}
    if "BIRTH.lock" not in children and ordinary:
        raise WatchError("birth-free acquisition teardown retains ordinary output")
    for name in sorted(ordinary):
        _unlink_scope_file(root / name, label="private acquisition scope output")
    if ordinary:
        _fsync_scope_directory(root, label="acquisition scope output removal")
    if "BIRTH.lock" in children:
        if birth_lock_fd is None:
            raise WatchError("acquisition scope birth lock is not held for teardown")
        metadata = os.fstat(birth_lock_fd)
        if (metadata.st_dev, metadata.st_ino) != (
            recovery["birth_lock_device"],
            recovery["birth_lock_inode"],
        ):
            raise WatchError("held acquisition scope birth lock changed before teardown")
        _unlink_scope_file(root / "BIRTH.lock", label="acquisition scope birth lock")
        _fsync_scope_directory(root, label="acquisition scope birth-lock removal")
    _unlink_scope_file(root / "RECOVERY", label="acquisition scope recovery record")
    _fsync_scope_directory(root, label="acquisition scope recovery-record removal")
    try:
        root.rmdir()
    except OSError as error:
        raise WatchError(f"cannot remove private acquisition scope root: {root}") from error
    _fsync_scope_directory(state_root, label="acquisition scope root removal")


def _finish_unpublished_scope_teardown(
    root: Path,
    *,
    state_root: Path,
    birth_lock_fd: int | None,
) -> None:
    """Remove a root that never acquired durable launch authority."""

    _validate_scope_root(root, state_root=state_root)
    children = _validate_scope_children(root)
    if children - {"BIRTH.lock", "SUPERVISION.next"}:
        raise WatchError("unpublished acquisition scope gained unexpected authority")
    if "BIRTH.lock" in children and birth_lock_fd is None:
        raise WatchError("unpublished acquisition scope birth lock is not held")
    if "SUPERVISION.next" in children:
        _unlink_scope_file(
            root / "SUPERVISION.next",
            label="staged acquisition scope supervision",
        )
        _fsync_scope_directory(root, label="staged acquisition supervision removal")
    if "BIRTH.lock" in children:
        _unlink_scope_file(root / "BIRTH.lock", label="acquisition scope birth lock")
        _fsync_scope_directory(root, label="acquisition scope birth-lock removal")
    try:
        root.rmdir()
    except OSError as error:
        raise WatchError(f"cannot remove unpublished acquisition scope root: {root}") from error
    _fsync_scope_directory(state_root, label="unpublished acquisition scope root removal")


def _cleanup_scope_root(root: Path, *, state_root: Path) -> None:
    """Compatibility entry point for authenticated, already-inert test/recovery roots."""
    children = _validate_scope_children(root)
    record: Mapping[str, Any] | None = None
    if children & {"SUPERVISION", "RECOVERY"}:
        record, _, recovered = _read_scope_record(root, state_root=state_root)
        held = _wait_scope_birth_lock(
            root, record=record,
            deadline=time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS * 2,
        )
        if held is None:
            raise WatchError("cannot authenticate acquisition scope birth before cleanup")
        try:
            if not _wait_scope_absent(record["scope_unit"], _safe_host_environment()):
                raise WatchError("acquisition scope unit is not absent during cleanup")
            _discard_staged_scope_files(root, state_root=state_root)
            recovery = record if recovered else _publish_scope_recovery(root, record, state_root=state_root)
            _finish_scope_teardown(root, state_root=state_root, recovery=recovery, birth_lock_fd=held)
        finally:
            os.close(held)
    else:
        held, busy = _open_scope_birth_lock(root, record=None)
        if busy:
            raise WatchError("unpublished acquisition scope birth remains live")
        try:
            _finish_unpublished_scope_teardown(root, state_root=state_root, birth_lock_fd=held)
        finally:
            if held is not None:
                os.close(held)


def _terminate_and_reap_launcher(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as error:
            raise WatchError("cannot reap acquisition scope host launcher") from error
    if process.returncode is None:
        raise WatchError("acquisition scope host launcher was not reaped")


def _finalize_scope_root(
    root: Path, *, state_root: Path, supervision: Mapping[str, Any], unit: str,
    environment: Mapping[str, str], process: subprocess.Popen[str] | None,
    birth_lock_fd: int,
) -> None:
    _terminate_and_reap_launcher(process)
    held = birth_lock_fd
    acquired = False
    if held < 0:
        value = _wait_scope_birth_lock(
            root, record=supervision,
            deadline=time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS * 2,
        )
        if value is None:
            raise WatchError("acquisition scope birth lock disappeared before teardown")
        held, acquired = value, True
    try:
        _validate_held_scope_birth_lock(root, record=supervision, descriptor=held)
        current, _, recovered = _read_scope_record(root, state_root=state_root)
        for name in ("scope_unit", "scope_token", "action_sha256", "source_binding_sha256", "request_authority_sha256", "birth_lock_device", "birth_lock_inode"):
            if current[name] != supervision[name]:
                raise WatchError("acquisition scope authority changed before teardown")
        state = _scope_state(unit, environment)
        if state.processes:
            _scope_signal(unit, "SIGKILL", environment)
        if not _wait_scope_empty(unit, environment, deadline=time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS):
            raise WatchError("acquisition scope remains populated before teardown")
        _discard_staged_scope_files(root, state_root=state_root)
        recovery = current if recovered else _publish_scope_recovery(root, current, state_root=state_root)
        _finish_scope_teardown(root, state_root=state_root, recovery=recovery, birth_lock_fd=held)
    finally:
        if acquired:
            os.close(held)


_HOST_SCOPE_LAUNCHER = r'''
set -u
birth_fd=$1
root=$2
shift 2
for fd_path in /proc/${BASHPID}/fd/*; do
  fd=${fd_path##*/}
  case "${fd}" in
    0|1|2|"${birth_fd}") continue ;;
    *[!0-9]*|"") exit 125 ;;
  esac
  eval "exec ${fd}>&-" || exit 125
done
"$@" &
launcher_pid=$!
request_seen=0
for _attempt in {1..300}; do
  if [[ -f "${root}/REQUEST" && ! -L "${root}/REQUEST" ]]; then
    request_seen=1
    break
  fi
  if ! kill -0 "${launcher_pid}" 2>/dev/null; then
    wait "${launcher_pid}"
    status=$?
    eval "exec ${birth_fd}>&-" || exit 125
    exit "${status}"
  fi
  sleep 0.05
done
if (( request_seen == 0 )); then
  kill -KILL "${launcher_pid}" 2>/dev/null || true
  wait "${launcher_pid}" 2>/dev/null || true
  eval "exec ${birth_fd}>&-" || exit 125
  exit 124
fi
wait "${launcher_pid}"
status=$?
eval "exec ${birth_fd}>&-" || exit 125
exit "${status}"
'''


_SCOPE_WRAPPER = r'''
set -u
umask 077
root=$1
request_nonce=$2
scope_unit=$3
action_sha256=$4
request_authority=$5
scope_token=$6
source_binding=$7
state_namespace=$8
status_path=$9
shift 9
stdout_path=$1
stderr_path=$2
shift 2
for fd_path in /proc/${BASHPID}/fd/*; do
  fd=${fd_path##*/}
  case "${fd}" in
    0|1|2) continue ;;
    *[!0-9]*|"") exit 125 ;;
  esac
  eval "exec ${fd}>&-" || exit 125
done
request_staged=${root}/REQUEST.next
request_path=${root}/REQUEST
wrapper_pid=${BASHPID}
(
  set -C
  {
    printf '{\n'
    printf '  "action_sha256": "%s",\n' "${action_sha256}"
    printf '  "artifact_type": "qcsd-class-watch-scope-request",\n'
    printf '  "request_authority_sha256": "%s",\n' "${request_authority}"
    printf '  "request_nonce": "%s",\n' "${request_nonce}"
    printf '  "schema_version": 1,\n'
    printf '  "scope_token": "%s",\n' "${scope_token}"
    printf '  "scope_unit": "%s",\n' "${scope_unit}"
    printf '  "source_binding_sha256": "%s",\n' "${source_binding}"
    printf '  "state_namespace_sha256": "%s",\n' "${state_namespace}"
    printf '  "wrapper_pid": %s\n' "${wrapper_pid}"
    printf '}\n'
  } >"${request_staged}"
) || exit 125
chmod 600 -- "${request_staged}" || exit 125
sync -f "${request_staged}" || exit 125
mv -T --no-clobber -- "${request_staged}" "${request_path}" || exit 125
[[ ! -e "${request_staged}" ]] || exit 125
sync -f "${root}" || exit 125
released=0
for _attempt in {1..300}; do
  if [[ -f "${root}/GO" && ! -L "${root}/GO" &&
        "$(stat -Lc '%F:%u:%a:%h:%s' -- "${root}/GO")" == \
        "regular file:$(id -u):600:1:65" ]]; then
    IFS= read -r release_value <"${root}/GO" || exit 125
    if [[ "${release_value}" == "${request_authority}" ]]; then
      released=1
      break
    fi
    exit 125
  fi
  sleep 0.05
done
(( released == 1 )) || exit 125
"$@" </dev/null >"${stdout_path}" 2>"${stderr_path}"
status=$?
case "${status}" in ""|*[!0-9]*) exit 125 ;; esac
(( status <= 255 )) || exit 125
staged=${status_path}.next
printf '%s\n' "${status}" >"${staged}" || exit 125
chmod 600 -- "${staged}" || exit 125
sync -f "${staged}" || exit 125
mv -f -- "${staged}" "${status_path}" || exit 125
sync -f "${status_path%/*}" || exit 125
exit "${status}"
'''


class _SignalLatch:
    watched = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)

    def __init__(self) -> None:
        self.first: int | None = None
        self.event = threading.Event()
        self.previous_handlers: dict[signal.Signals, Any] = {}
        self.previous_mask: set[signal.Signals] | None = None

    def _handle(self, signum: int, _frame: Any) -> None:
        if self.first is None:
            self.first = signum
        self.event.set()

    def __enter__(self) -> _SignalLatch:
        self.previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, self.watched)
        self.previous_handlers = {
            watched: signal.getsignal(watched) for watched in self.watched
        }
        for watched in self.watched:
            signal.signal(watched, self._handle)
        signal.pthread_sigmask(
            signal.SIG_SETMASK,
            self.previous_mask.difference(self.watched),
        )
        return self

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        assert self.previous_mask is not None
        signal.pthread_sigmask(signal.SIG_BLOCK, self.watched)
        # Sample the latch only after blocking all watched signals.  This closes
        # the final-success window between the caller's last ``raise_if_set``
        # and handler restoration while still allowing the surrounding
        # ``finally`` blocks to finish lock and scope cleanup first.
        latched = self.first
        try:
            for watched, previous in self.previous_handlers.items():
                signal.signal(watched, previous)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, self.previous_mask)
        if _kind is None and latched is not None:
            raise WatchSignalInterrupt(latched)

    def raise_if_set(self) -> None:
        if self.first is not None:
            raise WatchSignalInterrupt(self.first)


_active_signal_latch: _SignalLatch | None = None


def _create_scope_root(
    *,
    state_root: Path,
    unit: str,
    command: Sequence[str],
    authority_fd: int,
    source_binding_sha256: str,
) -> tuple[Path, dict[str, Any], int]:
    _validate_lock_identity(state_root / "WATCH.lock", authority_fd)
    if (
        _SHA256_RE.fullmatch(source_binding_sha256) is None
        or not command
        or any(type(argument) is not str or "\0" in argument for argument in command)
    ):
        raise WatchError("acquisition scope action binding is malformed")
    token = unit.removeprefix("qcsd-class-watch-").removesuffix(".scope")
    if _SCOPE_UNIT_RE.fullmatch(unit) is None or re.fullmatch(r"[0-9a-f]{32}", token) is None:
        raise WatchError("cannot derive a private acquisition scope root identity")
    _validate_state_namespace_root(state_root)
    request_nonce = secrets.token_hex(32)
    staged_root = state_root / f"scope.next.{token}"
    try:
        staged_root.mkdir(mode=0o700)
    except OSError as error:
        raise WatchError("cannot reserve a private acquisition scope root") from error
    root: Path | None = None
    birth_lock_fd: int | None = None
    try:
        staged_root.chmod(0o700)
        birth_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        birth_lock_fd = os.open(staged_root / "BIRTH.lock", birth_flags, 0o600)
        os.fchmod(birth_lock_fd, 0o600)
        fcntl.flock(birth_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fsync(birth_lock_fd)
        supervision = _scope_supervision_record(
            state_root=state_root,
            unit=unit,
            command=command,
            authority_fd=authority_fd,
            birth_lock_fd=birth_lock_fd,
            source_binding_sha256=source_binding_sha256,
            request_nonce=request_nonce,
        )
        _validate_scope_record(
            supervision,
            recovery=False,
            root=staged_root,
            state_root=state_root,
        )
        _atomic_scope_record(staged_root / "SUPERVISION", supervision)
        root = state_root / staged_root.name.replace("scope.next.", "scope.", 1)
        os.replace(staged_root, root)
        state_fd = os.open(state_root, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(state_fd)
        finally:
            os.close(state_fd)
        return root, supervision, birth_lock_fd
    except (OSError, WatchError) as error:
        if birth_lock_fd is not None:
            os.close(birth_lock_fd)
        for candidate in (root, staged_root):
            if candidate is not None and candidate.exists():
                try:
                    _cleanup_scope_root(candidate, state_root=state_root)
                except WatchError:
                    pass
        if isinstance(error, WatchError):
            raise
        raise WatchError("cannot publish durable acquisition scope root") from error


def _scope_completed(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    authority_fd: int,
    state_root: Path,
    source_binding_sha256: str,
    latch: _SignalLatch,
) -> subprocess.CompletedProcess[str]:
    runtime = _scope_command_runtime(command)
    _validate_lock_identity(state_root / "WATCH.lock", authority_fd)
    token = secrets.token_hex(16)
    unit = f"qcsd-class-watch-{token}.scope"
    environment = _safe_host_environment(env)
    for key in (
        PREPARE_IMAGE_ENV,
        PINNED_CONTEXT_ENV,
        PINNED_HOST_ENV,
        PINNED_SERVER_ID_ENV,
    ):
        if key in env:
            environment[key] = env[key]
    if _scope_state(unit, environment).load_state != "not-found":
        raise WatchError("cannot reserve a unique acquisition cgroup")
    root, supervision, birth_lock_fd = _create_scope_root(
        state_root=state_root,
        unit=unit,
        command=command,
        authority_fd=authority_fd,
        source_binding_sha256=source_binding_sha256,
    )
    # Every public acquisition action must prove that it is the exact command
    # launched by this watcher, in this live systemd scope, while this process
    # still holds the canonical WATCH lock.  Admission, status, and run all use
    # the same verifier; direct launcher invocations receive none of these
    # create-only values and fail before Docker can be inspected or mutated.
    environment[SCOPE_ROOT_ENV] = str(root)
    environment[SCOPE_STATE_ROOT_ENV] = str(state_root)
    environment[SCOPE_AUTHORITY_ENV] = supervision["request_authority_sha256"]
    environment[SCOPE_ACTION_ENV] = supervision["action_sha256"]
    environment[SCOPE_SOURCE_ENV] = supervision["source_binding_sha256"]
    stdout_path = root / "stdout"
    stderr_path = root / "stderr"
    status_path = root / "status"
    graceful_run = "acquisition-run" in command
    kill_signal = "SIGINT" if graceful_run else "SIGKILL"
    stop_seconds = (
        ACQUISITION_ACTION_CLEANUP_SECONDS if graceful_run else STATUS_CLEANUP_SECONDS
    )
    systemd_command = (
        "/usr/bin/systemd-run",
        "--user",
        "--scope",
        "--collect",
        "--quiet",
        "--expand-environment=no",
        f"--unit={unit}",
        "--property=KillMode=control-group",
        f"--property=KillSignal={kill_signal}",
        f"--property=TimeoutStopSec={stop_seconds}s",
        f"--property=RuntimeMaxSec={runtime}s",
        "--",
        "/usr/bin/bash",
        "--noprofile",
        "--norc",
        "-c",
        _SCOPE_WRAPPER,
        "qcsd-class-watch-wrapper",
        str(root),
        supervision["request_nonce"],
        unit,
        supervision["action_sha256"],
        supervision["request_authority_sha256"],
        supervision["scope_token"],
        supervision["source_binding_sha256"],
        supervision["state_namespace_sha256"],
        str(status_path),
        str(stdout_path),
        str(stderr_path),
        *command,
    )
    process: subprocess.Popen[str] | None = None
    launcher_stdout = ""
    launcher_stderr = ""
    timed_out = False
    interrupted = False
    leak_detected = False
    scope_proven_empty = False
    failure: BaseException | None = None
    deadline = time.monotonic() + runtime + SCOPE_CLIENT_GRACE_SECONDS
    try:
        process = subprocess.Popen(
            (
                "/usr/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                _HOST_SCOPE_LAUNCHER,
                "qcsd-class-watch-host-launcher",
                str(birth_lock_fd),
                str(root),
                *systemd_command,
            ),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=True,
            pass_fds=(birth_lock_fd,),
            start_new_session=True,
        )
        os.close(birth_lock_fd)
        birth_lock_fd = -1
        handshake_deadline = min(deadline, time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS)
        request: Mapping[str, Any] | None = None
        while time.monotonic() < handshake_deadline:
            if latch.event.is_set():
                interrupted = True
                break
            if process.poll() is not None:
                break
            try:
                request = _read_scope_request(root, record=supervision, required=False)
            except WatchError:
                raise
            if request is not None:
                _validate_lock_identity(state_root / "WATCH.lock", authority_fd)
                state = _scope_state(unit, environment)
                wrapper_pid = request["wrapper_pid"]
                wrapper_process = _process_identity(wrapper_pid)
                if wrapper_process is None or wrapper_pid not in state.processes:
                    raise WatchError("acquisition scope wrapper is outside its exact cgroup")
                decision_mask = signal.pthread_sigmask(
                    signal.SIG_BLOCK,
                    latch.watched,
                )
                try:
                    pending = signal.sigpending()
                    if latch.first is None:
                        for watched in latch.watched:
                            if watched in pending:
                                latch.first = int(watched)
                                latch.event.set()
                                break
                    if latch.first is not None:
                        interrupted = True
                    else:
                        # This pending-signal sample is the admission decision
                        # point.  Later terminal signals remain blocked until
                        # GO is durable, then take the ordinary interruption
                        # path without creating a pre-authority race window.
                        _validate_lock_identity(
                            state_root / "WATCH.lock",
                            authority_fd,
                        )
                        state = _scope_state(unit, environment)
                        if (
                            wrapper_pid not in state.processes
                            or _process_identity(wrapper_pid) != wrapper_process
                        ):
                            raise WatchError(
                                "acquisition scope wrapper changed before authorisation"
                            )
                        start_time, session, process_group = wrapper_process
                        wrapper_identity = (
                            wrapper_pid,
                            start_time,
                            session,
                            process_group,
                        )
                        supervision = _replace_scope_phase(
                            root,
                            supervision,
                            phase="request-authorised",
                            wrapper_identity=wrapper_identity,
                            state_root=state_root,
                        )
                        state = _scope_state(unit, environment)
                        if (
                            wrapper_pid not in state.processes
                            or _process_identity(wrapper_pid) != wrapper_process
                        ):
                            raise WatchError(
                                "acquisition scope wrapper changed before arming"
                            )
                        supervision = _replace_scope_phase(
                            root,
                            supervision,
                            phase="armed-for-exec",
                            wrapper_identity=wrapper_identity,
                            state_root=state_root,
                        )
                        _validate_lock_identity(
                            state_root / "WATCH.lock",
                            authority_fd,
                        )
                        state = _scope_state(unit, environment)
                        if (
                            wrapper_pid not in state.processes
                            or _process_identity(wrapper_pid) != wrapper_process
                        ):
                            raise WatchError(
                                "acquisition scope wrapper changed before execution release"
                            )
                        _publish_scope_go(
                            root,
                            authority=supervision["request_authority_sha256"],
                        )
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, decision_mask)
                break
            time.sleep(SCOPE_SETTLE_SECONDS)
        if not interrupted and request is None:
            raise WatchError("acquisition scope request handshake did not complete")
        while True:
            if latch.event.is_set():
                interrupted = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                launcher_stdout, launcher_stderr = process.communicate(
                    timeout=min(0.2, remaining)
                )
                break
            except subprocess.TimeoutExpired:
                continue
        if interrupted or timed_out:
            _scope_signal(unit, "SIGINT", environment)
            graceful_deadline = time.monotonic() + DOCKER_SUPERVISOR_SIGNAL_ENVELOPE_SECONDS
            if not _wait_scope_empty(unit, environment, deadline=graceful_deadline):
                _scope_signal(unit, "SIGKILL", environment)
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                launcher_stdout, launcher_stderr = process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
        try:
            initial_state = _scope_state(unit, environment)
            leak_detected = bool(initial_state.processes)
        except WatchError:
            leak_detected = True
        if leak_detected:
            _scope_signal(unit, "SIGKILL", environment)
        scope_proven_empty = _wait_scope_empty(
            unit,
            environment,
            deadline=time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS,
        )
        if not scope_proven_empty:
            _scope_signal(unit, "SIGKILL", environment)
            scope_proven_empty = _wait_scope_empty(
                unit,
                environment,
                deadline=time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS,
            )
        if not scope_proven_empty:
            raise WatchError(
                f"acquisition cgroup remains populated or unprovable: {unit}; evidence root {root}"
            )
        _validate_lock_identity(state_root / "WATCH.lock", authority_fd)
        if interrupted:
            latch.raise_if_set()
        if timed_out:
            raise WatchError(f"acquisition action exceeded its whole-tree runtime: {command}")
        if leak_detected:
            raise WatchError("acquisition action left a surviving cgroup descendant")
        if process.returncode is None:
            raise WatchError("acquisition scope launcher did not terminate")
        if not status_path.exists():
            diagnostic = launcher_stderr.strip() or launcher_stdout.strip()
            raise WatchError(
                "acquisition scope did not publish an authenticated status"
                + (f": {diagnostic}" if diagnostic else "")
            )
        status_raw, _ = _read_stable_file(status_path, root=root, label="scope status")
        try:
            status_text = status_raw.decode("ascii")
        except UnicodeError as error:
            raise WatchError("acquisition scope status is not ASCII") from error
        if re.fullmatch(r"(?:0|[1-9][0-9]{0,2})\n", status_text) is None:
            raise WatchError("acquisition scope status is malformed")
        status = int(status_text)
        if status > 255 or process.returncode != status:
            raise WatchError("acquisition scope launcher status is unauthenticated")
        stdout_raw, _ = _read_stable_file(stdout_path, root=root, label="scope stdout")
        stderr_raw, _ = _read_stable_file(stderr_path, root=root, label="scope stderr")
        try:
            stdout = stdout_raw.decode("utf-8")
            stderr = stderr_raw.decode("utf-8")
        except UnicodeError as error:
            raise WatchError("acquisition action output is not UTF-8") from error
        return subprocess.CompletedProcess(tuple(command), status, stdout, stderr)
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            _finalize_scope_root(
                root, state_root=state_root, supervision=supervision, unit=unit,
                environment=environment, process=process, birth_lock_fd=birth_lock_fd,
            )
            birth_lock_fd = -1
        except WatchError:
            if failure is None:
                raise
        finally:
            if birth_lock_fd >= 0:
                os.close(birth_lock_fd)


def _validate_docker_admission(value: Any) -> DockerAdmission:
    expected = {
        "schema_version",
        "artifact_type",
        "docker_context",
        "docker_host",
        "docker_server_id",
        "host_boot_id",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise WatchError("Docker admission result differs from the exact contract")
    context = value["docker_context"]
    host = value["docker_host"]
    server_id = value["docker_server_id"]
    host_boot_id = value["host_boot_id"]
    if (
        value["schema_version"] != SCHEMA_VERSION
        or value["artifact_type"] != DOCKER_ADMISSION_TYPE
        or context != "default"
        or host not in {
            "unix:///var/run/docker.sock",
            "npipe:////./pipe/dockerDesktopLinuxEngine",
        }
        or not isinstance(server_id, str)
        or re.fullmatch(r"[A-Za-z0-9_.:-]+", server_id) is None
        or server_id == "unavailable"
        or not isinstance(host_boot_id, str)
        or _BOOT_ID_RE.fullmatch(host_boot_id) is None
        or host_boot_id != _host_boot_id()
    ):
        raise WatchError("Docker admission result contains an unsafe binding")
    return DockerAdmission(context, host, server_id, host_boot_id)


def _run_docker_admission(
    *,
    paths: WatchPaths,
    runner: CommandRunner,
    environment: Mapping[str, str],
    authority_fd: int,
    state_root: Path,
    source_binding_sha256: str,
) -> DockerAdmission:
    try:
        completed = runner(
            _admission_command(paths),
            cwd=paths.lab_root,
            env=environment,
            authority_fd=authority_fd,
            state_root=state_root,
            source_binding_sha256=source_binding_sha256,
        )
    except OSError as error:
        raise WatchError(f"cannot execute Docker admission: {error}") from error
    if completed.returncode != 0:
        diagnostic = (completed.stderr or completed.stdout or "").strip()
        raise WatchError(
            "Docker admission/recovery failed"
            + (f": {diagnostic}" if diagnostic else "")
        )
    value = _parse_exact_json_object(completed.stdout, label="Docker admission output")
    return _validate_docker_admission(value)


def _docker_environment(
    admission: DockerAdmission,
    binding: AcquisitionBinding,
) -> dict[str, str]:
    environment = _safe_host_environment()
    environment["DOCKER_CONTEXT"] = admission.context
    environment[PINNED_CONTEXT_ENV] = admission.context
    environment[PINNED_HOST_ENV] = admission.host
    environment[PINNED_SERVER_ID_ENV] = admission.server_id
    environment[PREPARE_IMAGE_ENV] = binding.prepare_image
    return environment


def _status_command(paths: WatchPaths) -> tuple[str, ...]:
    return (
        "/usr/bin/bash",
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
        "/usr/bin/bash",
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
    authority_fd: int,
    state_root: Path,
    source_binding_sha256: str,
) -> subprocess.CompletedProcess[str]:
    global _active_signal_latch
    if _active_signal_latch is not None:
        return _scope_completed(
            command,
            cwd=cwd,
            env=env,
            authority_fd=authority_fd,
            state_root=state_root,
            source_binding_sha256=source_binding_sha256,
            latch=_active_signal_latch,
        )
    with _SignalLatch() as latch:
        _active_signal_latch = latch
        try:
            completed = _scope_completed(
                command,
                cwd=cwd,
                env=env,
                authority_fd=authority_fd,
                state_root=state_root,
                source_binding_sha256=source_binding_sha256,
                latch=latch,
            )
            latch.raise_if_set()
            return completed
        finally:
            _active_signal_latch = None


def _run_action(
    action: str,
    *,
    paths: WatchPaths,
    runner: CommandRunner,
    environment: Mapping[str, str],
    authority_fd: int,
    state_root: Path,
    source_binding_sha256: str,
) -> dict[str, Any]:
    command = _status_command(paths) if action == "acquisition-status" else _run_command(paths)
    try:
        completed = runner(
            command,
            cwd=paths.lab_root,
            env=environment,
            authority_fd=authority_fd,
            state_root=state_root,
            source_binding_sha256=source_binding_sha256,
        )
    except OSError as error:
        raise WatchError(f"cannot execute {action}: {error}") from error
    if completed.returncode != 0:
        diagnostic = (completed.stderr or completed.stdout or "").strip()
        suffix = f": {diagnostic}" if diagnostic else ""
        raise WatchError(f"{action} child failed with exit {completed.returncode}{suffix}")
    result = _parse_exact_json_object(
        completed.stdout,
        label=f"{action} child output",
    )
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
            "batching": {
                "maximum_candidates_per_action": MAX_CANDIDATES,
                "global_live_page_cap": GLOBAL_LIVE_PAGE_CAP,
            },
            "runner_wait_policy": _RUN_WAIT_POLICY,
        }:
            raise WatchError("acquisition-status result carries another stability gate")
        if value["status"] != "complete" or blockers:
            raise WatchError("acquisition-status result has invalid action status or blockers")
    else:
        if (
            details["bounded_candidates"] != MAX_CANDIDATES
            or details["runner_wait_policy"] != _RUN_WAIT_POLICY
        ):
            raise WatchError("acquisition-run result differs from the bounded wait contract")
        expected_status = "ready" if details["complete"] else "pending"
        if value["status"] != expected_status or bool(blockers) == details["complete"]:
            raise WatchError("acquisition-run result status/blockers are inconsistent")
    return value


def _validate_status_details(details: Mapping[str, Any], *, action: str) -> None:
    if (
        details["acquisition_schema_version"] != ACQUISITION_SCHEMA_VERSION
        or isinstance(details["acquisition_schema_version"], bool)
        or details["checkpoint_schema_version"] != CHECKPOINT_SCHEMA_VERSION
        or isinstance(details["checkpoint_schema_version"], bool)
        or details["maximum_candidates_per_action"] != MAX_CANDIDATES
        or isinstance(details["maximum_candidates_per_action"], bool)
        or details["global_live_page_cap"] != GLOBAL_LIVE_PAGE_CAP
        or isinstance(details["global_live_page_cap"], bool)
    ):
        raise WatchError(f"{action} result carries another acquisition schema or batch cap")
    active_batch = details["active_batch"]
    if active_batch is not None:
        if not isinstance(active_batch, dict) or set(active_batch) != {
            "batch_id",
            "stage",
            "published_at",
            "candidate_ids",
            "live_page_count",
            "attempt_count",
        }:
            raise WatchError(f"{action} result active batch summary is malformed")
        if (
            not isinstance(active_batch["batch_id"], str)
            or not active_batch["batch_id"]
            or active_batch["stage"] not in {"navigation", "probe"}
        ):
            raise WatchError(f"{action} result active batch identity is invalid")
        _parse_timestamp(
            active_batch["published_at"],
            label=f"{action} active batch publication time",
        )
        candidate_ids = active_batch["candidate_ids"]
        if (
            not isinstance(candidate_ids, list)
            or not 1 <= len(candidate_ids) <= MAX_CANDIDATES
            or any(not isinstance(item, str) for item in candidate_ids)
            or len(set(candidate_ids)) != len(candidate_ids)
        ):
            raise WatchError(f"{action} result active batch candidates are invalid")
        live_page_count = _validate_live_page_count(
            active_batch["live_page_count"],
            label=f"{action} active batch",
        )
        if (
            type(active_batch["attempt_count"]) is not int
            or live_page_count == 0
            or active_batch["attempt_count"] != live_page_count
        ):
            raise WatchError(f"{action} result active batch attempt count is invalid")
    count_names = (
        "candidate_count",
        "terminal_count",
        "pending_count",
        "probing_count",
        "due_now_count",
        "finalisable_count",
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
        or details["due_now_count"]
        + details["finalisable_count"]
        + details["missed_window_count"]
        > details["probing_count"]
        or details["recovery_required_count"]
        > details["pending_count"]
        + details["probing_count"]
        + (active_batch["attempt_count"] if active_batch is not None else 0)
        or (
            active_batch is not None
            and details["recovery_required_count"]
            < active_batch["attempt_count"]
        )
        or (details["pending_start_blocked"] and not details["pending_count"])
    ):
        raise WatchError(f"{action} result counts are inconsistent")
    expected_due = bool(
        details["due_now_count"]
        or details["finalisable_count"]
        or details["missed_window_count"]
        or details["recovery_required_count"]
        or (details["pending_count"] and not details["pending_start_blocked"])
    )
    if details["work_due_now"] != expected_due:
        raise WatchError(f"{action} result due-work flag is inconsistent")
    expected_complete = (
        details["terminal_count"] == CANDIDATE_COUNT
        and details["recovery_required_count"] == 0
        and details["finalisable_count"] == 0
        and active_batch is None
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
    canonical = parsed.astimezone(UTC)
    if canonical.isoformat().replace("+00:00", "Z") != value:
        raise WatchError(f"{label} is not a canonical UTC timestamp")
    return canonical


def _utc_now(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise WatchError("supervisor clock did not return a timezone-aware datetime")
    return value.astimezone(UTC)


def _acquire_mutation_lock(path: Path) -> int:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    directory_fd: int | None = None
    try:
        directory_fd = os.open(path.parent, directory_flags)
        descriptor = os.open(path.name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise WatchError(f"cannot open acquisition mutation lock: {path}") from error
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise WatchError("acquisition mutation lock is not a single regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _validate_lock_identity(path, descriptor)
    except BlockingIOError as error:
        os.close(descriptor)
        raise WatchError(
            "another class-study acquisition process holds the runner lock"
        ) from error
    except (OSError, WatchError):
        os.close(descriptor)
        raise
    return descriptor


def _validate_lock_identity(path: Path, descriptor: int) -> None:
    try:
        descriptor_state = os.fstat(descriptor)
        pathname_state = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise WatchError("acquisition mutation lock pathname is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(descriptor_state.st_mode)
        or not stat.S_ISREG(pathname_state.st_mode)
        or descriptor_state.st_nlink != 1
        or pathname_state.st_nlink != 1
        or descriptor_state.st_uid != os.getuid()
        or pathname_state.st_uid != os.getuid()
        or stat.S_IMODE(descriptor_state.st_mode) != 0o600
        or stat.S_IMODE(pathname_state.st_mode) != 0o600
        or (descriptor_state.st_dev, descriptor_state.st_ino)
        != (pathname_state.st_dev, pathname_state.st_ino)
    ):
        raise WatchError("acquisition mutation lock pathname identity changed")


def _revalidate_immutable_and_source(
    paths: WatchPaths,
    binding: AcquisitionBinding,
    source_validator: Callable[[WatchPaths, AcquisitionBinding], None],
) -> None:
    current = _validate_immutable_binding(paths)
    if current != binding:
        raise WatchError("acquisition immutable evidence binding changed")
    source_validator(paths, binding)


def _run_verified_action(
    action: str,
    *,
    paths: WatchPaths,
    binding: AcquisitionBinding,
    runner: CommandRunner,
    environment: Mapping[str, str],
    authority_fd: int,
    state_root: Path,
    source_binding_sha256: str,
    source_validator: Callable[[WatchPaths, AcquisitionBinding], None],
) -> tuple[dict[str, Any], ReceiptSnapshot, ReceiptSnapshot]:
    _validate_lock_identity(paths.mutation_lock, authority_fd)
    _revalidate_immutable_and_source(paths, binding, source_validator)
    before = _validate_checkpoint(paths, binding)
    result = _run_action(
        action,
        paths=paths,
        runner=runner,
        environment=environment,
        authority_fd=authority_fd,
        state_root=state_root,
        source_binding_sha256=source_binding_sha256,
    )
    _validate_lock_identity(paths.mutation_lock, authority_fd)
    _revalidate_immutable_and_source(paths, binding, source_validator)
    after = _validate_checkpoint(paths, binding)
    observed_active_batch = _active_batch_summary(
        after.value["payload"]["active_batch"],
        binding=binding,
    )
    if result["details"]["active_batch"] != observed_active_batch:
        raise WatchError(f"{action} result active batch differs from the checkpoint")
    if action == "acquisition-status" and after.sha256 != before.sha256:
        raise WatchError("acquisition-status mutated or raced the checkpoint")
    if action == "acquisition-run" and after.sha256 == before.sha256:
        details = result["details"]
        # A status snapshot can be just outside a reservation boundary, while
        # the separately scoped run reaches the coordinator just inside it.
        # The coordinator must then refuse the baseline without mutation.  It
        # is safe to re-status and wait only when the returned state itself is
        # blocked, has no due/recovery work, and names the next safe instant.
        benign_launch_drift = (
            details["complete"] is False
            and details["work_due_now"] is False
            and details["due_now_count"] == 0
            and details["finalisable_count"] == 0
            and details["missed_window_count"] == 0
            and details["recovery_required_count"] == 0
            and details["pending_start_blocked"] is True
            and details["next_due"] is not None
        )
        if not benign_launch_drift:
            raise WatchError("acquisition-run did not advance the checkpoint")
    return result, before, after


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

    global _active_signal_latch
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
    active_runner = _subprocess_runner if runner is None else runner
    validate_source = source_validator or _validate_host_source
    if _active_signal_latch is not None:
        raise WatchError("nested acquisition signal supervision is not allowed")
    descriptor: int | None = None
    with _SignalLatch() as latch:
        _active_signal_latch = latch
        try:
            # Signal handlers are installed while their signals are masked.
            # Validate immutable evidence/source before creating any durable
            # lifecycle state or admitting a Docker mutation.
            latch.raise_if_set()
            binding = _validate_immutable_binding(active_paths)
            validate_source(active_paths, binding)
            state_root = _ensure_state_namespace(active_paths)
            descriptor = _acquire_mutation_lock(active_paths.mutation_lock)
            latch.raise_if_set()
            _revalidate_immutable_and_source(active_paths, binding, validate_source)
            source_binding_sha256 = _source_binding_sha256(binding)

            # The admission action owns both watcher-scope and Docker stale-root
            # recovery.  checkpoint.json is not read until that recovery ends.
            _validate_lock_identity(active_paths.mutation_lock, descriptor)
            admission_environment = _safe_host_environment(environment)
            admission = _run_docker_admission(
                paths=active_paths,
                runner=active_runner,
                environment=admission_environment,
                authority_fd=descriptor,
                state_root=state_root,
                source_binding_sha256=source_binding_sha256,
            )
            _validate_lock_identity(active_paths.mutation_lock, descriptor)
            _revalidate_immutable_and_source(active_paths, binding, validate_source)
            _validate_checkpoint(active_paths, binding)
            child_environment = _docker_environment(admission, binding)
            last_source_check = monotonic()

            while True:
                latch.raise_if_set()
                status_result, _, _ = _run_verified_action(
                    "acquisition-status",
                    paths=active_paths,
                    binding=binding,
                    runner=active_runner,
                    environment=child_environment,
                    authority_fd=descriptor,
                    state_root=state_root,
                    source_binding_sha256=source_binding_sha256,
                    source_validator=validate_source,
                )
                details = status_result["details"]
                if details["complete"]:
                    _validate_lock_identity(active_paths.mutation_lock, descriptor)
                    _revalidate_immutable_and_source(
                        active_paths, binding, validate_source
                    )
                    _validate_checkpoint(active_paths, binding)
                    latch.raise_if_set()
                    return status_result
                if details["work_due_now"]:
                    _run_verified_action(
                        "acquisition-run",
                        paths=active_paths,
                        binding=binding,
                        runner=active_runner,
                        environment=child_environment,
                        authority_fd=descriptor,
                        state_root=state_root,
                        source_binding_sha256=source_binding_sha256,
                        source_validator=validate_source,
                    )
                    continue
                next_due = details["next_due"]
                if next_due is None:
                    raise WatchError("incomplete acquisition has no due work and no next_due")
                target = _parse_timestamp(next_due, label="acquisition-status next_due")
                remaining = (target - _utc_now(clock)).total_seconds()
                while remaining > 0:
                    duration = min(remaining, heartbeat)
                    if sleeper is time.sleep:
                        latch.event.wait(duration)
                    else:
                        sleeper(duration)
                    latch.raise_if_set()
                    _validate_lock_identity(active_paths.mutation_lock, descriptor)
                    monotonic_now = monotonic()
                    if monotonic_now - last_source_check >= SOURCE_RECHECK_SECONDS:
                        _revalidate_immutable_and_source(
                            active_paths, binding, validate_source
                        )
                        _validate_checkpoint(active_paths, binding)
                        last_source_check = monotonic_now
                    remaining = (target - _utc_now(clock)).total_seconds()
                _run_verified_action(
                    "acquisition-run",
                    paths=active_paths,
                    binding=binding,
                    runner=active_runner,
                    environment=child_environment,
                    authority_fd=descriptor,
                    state_root=state_root,
                    source_binding_sha256=source_binding_sha256,
                    source_validator=validate_source,
                )
        finally:
            # Every production action has already proved its scope empty, so
            # closing this descriptor releases the lock immediately.  Recheck
            # the pathname first; replacing it can never silently transfer
            # authority to another inode.
            lock_error: WatchError | None = None
            if descriptor is not None:
                try:
                    _validate_lock_identity(active_paths.mutation_lock, descriptor)
                except WatchError as error:
                    lock_error = error
                os.close(descriptor)
            _active_signal_latch = None
            if lock_error is not None and sys.exception() is None:
                raise lock_error


class WatchSignalInterrupt(KeyboardInterrupt):
    """Carry the first host signal through orderly checkpoint cleanup."""

    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


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
    parser.add_argument(
        "--recover-stale-scopes-internal",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--state-root-internal",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--current-scope-root-internal",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--current-authority-internal",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--expected-action-sha256-internal",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--expected-source-binding-sha256-internal",
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.recover_stale_scopes_internal:
        try:
            state_root = arguments.state_root_internal
            current_root = arguments.current_scope_root_internal
            current_authority = arguments.current_authority_internal
            expected_action_sha256 = arguments.expected_action_sha256_internal
            expected_source_binding_sha256 = (
                arguments.expected_source_binding_sha256_internal
            )
            if (
                state_root is None
                or current_root is None
                or current_authority is None
                or _SHA256_RE.fullmatch(current_authority) is None
                or expected_action_sha256 is None
                or _SHA256_RE.fullmatch(expected_action_sha256) is None
                or expected_source_binding_sha256 is None
                or _SHA256_RE.fullmatch(expected_source_binding_sha256) is None
            ):
                raise WatchError("internal scope recovery requires exact action authority")
            state_root = Path(os.path.abspath(state_root))
            current_root = Path(os.path.abspath(current_root))
            paths = _paths_from_state_namespace(state_root)
            binding = _validate_immutable_binding(paths)
            _validate_host_source(paths, binding)
            canonical_actions = {
                _sha256_bytes(_canonical_json_bytes(list(command)))
                for command in (
                    _admission_command(paths),
                    _status_command(paths),
                    _run_command(paths),
                )
            }
            canonical_source = _source_binding_sha256(binding)
            if (
                expected_action_sha256 not in canonical_actions
                or expected_source_binding_sha256 != canonical_source
            ):
                raise WatchError("internal scope recovery is not bound to current canonical source")
            _validate_scope_root(current_root, state_root=state_root)
            recovered = _recover_stale_scope_roots(
                state_root=state_root,
                current_root=current_root,
                current_authority=current_authority,
                expected_action_sha256=expected_action_sha256,
                expected_source_binding_sha256=expected_source_binding_sha256,
            )
        except WatchError as error:
            print(f"class acquisition scope recovery failed: {error}", file=sys.stderr)
            return 1
        print(json.dumps({"recovered_scope_roots": recovered}, sort_keys=True))
        return 0
    if any(
        value is not None
        for value in (
            arguments.state_root_internal,
            arguments.current_scope_root_internal,
            arguments.current_authority_internal,
            arguments.expected_action_sha256_internal,
            arguments.expected_source_binding_sha256_internal,
        )
    ):
        print(
            "class acquisition watch failed: current scope root is internal-only",
            file=sys.stderr,
        )
        return 2
    try:
        result = watch_acquisition(heartbeat_seconds=arguments.heartbeat_seconds)
    except WatchSignalInterrupt as interrupt:
        print("class acquisition watch interrupted; resume from checkpoint", file=sys.stderr)
        return 128 + interrupt.signum
    except KeyboardInterrupt:
        print("class acquisition watch interrupted; resume from checkpoint", file=sys.stderr)
        return 130
    except WatchError as error:
        print(f"class acquisition watch failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
