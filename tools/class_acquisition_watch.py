#!/usr/bin/env python3
"""Supervise the canonical class-study acquisition without owning its state.

This host-side process deliberately has no third-party or ``qcsd_lab`` import.
The acquisition checkpoint remains the only resume authority: this process
validates the immutable foundation, deeply replays its browser-egress gate at
admission, asks the existing coordinator for status, invokes bounded due work,
and otherwise sleeps only as far as the next five-second heartbeat.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import hashlib
import json
import math
import os
import posixpath
import re
import secrets
import select
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
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

STUDY_ID = "classifier-multiorigin100-v1"
CANDIDATE_COUNT = 600
SCHEMA_VERSION = 1
SOURCE_BINDING_PREIMAGE_SCHEMA_VERSION = 2
ACQUISITION_SCHEMA_VERSION = 5
HISTORICAL_ACQUISITION_SCHEMA_VERSIONS = frozenset({1, 2, 3, 4})
CHECKPOINT_SCHEMA_VERSION = 2
FOUNDATION_SCHEMA_VERSION = 4
HISTORICAL_FOUNDATION_SCHEMA_VERSION = 3
CATALOGUE_TYPE = "qcsd-class-study-candidate-catalogue"
PROVENANCE_TYPE = "qcsd-class-study-acquisition-provenance"
CHECKPOINT_TYPE = "qcsd-class-study-acquisition-checkpoint"
FOUNDATION_TYPE = "qcsd-class-study-foundation-attestation"
PINNED_CDP_TYPE = "qcsd-class-study-pinned-cdp-probe"
BUILD_EXECUTION_TYPE = "qcsd-buflo-study-no-cache-build-execution"
BUILD_EXECUTION_MAX_BYTES = 16 * 1024 * 1024
BUILD_COMPLETION_TYPE = "qcsd-buflo-study-build-completion"
BUILD_COMPLETION_MAX_BYTES = 64 * 1024
BROWSER_EGRESS_FINAL_TYPE = "qcsd-browser-egress-qualification-final"
BROWSER_EGRESS_QUALIFICATION_ID = "browser-egress-qualification-v1"
BROWSER_EGRESS_VECTOR_COUNT = 110
BROWSER_EGRESS_EXPANDED_VECTORS_SHA256 = (
    "d9038cf12d733f914ad8e71365d98b8ac9eeb98aa9f02aa4ad43b992d3bd21ba"
)
BROWSER_EGRESS_MANIFEST_RELATIVE_PATH = "config/class-study/v1/browser-egress-qualification-v2.json"
BROWSER_EGRESS_MANIFEST_SHA256 = "5690dc4faca03b4d55d8f4e77ecd6ce55cc75bdb9a1b2f4903ac79a5ed1015ea"
BROWSER_EGRESS_ARGV_RELATIVE_PATH = "config/class-study/v1/browser-egress-chromium-argv-v1.json"
BROWSER_EGRESS_ARGV_SHA256 = "458f51042d64433c089e5c43ab1167bbfa337ed4b6bda5e9d0d4efc0edf99c36"
_BROWSER_EGRESS_VECTOR_IDS = tuple(
    [
        f"constructor--{context}--{surface}"
        for context in (
            "page",
            "same-origin-frame",
            "cross-origin-frame",
            "dedicated-worker",
            "shared-worker",
        )
        for surface in (
            "websocket",
            "websocket-stream",
            "webtransport",
            "rtc-stun-udp",
            "rtc-stun-tcp",
            "rtc-turn-udp",
            "rtc-turn-tcp",
            "tcp-client",
            "tcp-server",
            "udp-socket",
        )
    ]
    + [
        f"urlloader--{context}--{surface}"
        for surface, contexts in (
            (
                "fetch",
                (
                    "page",
                    "same-origin-frame",
                    "cross-origin-frame",
                    "dedicated-worker",
                    "shared-worker",
                ),
            ),
            (
                "xhr",
                (
                    "page",
                    "same-origin-frame",
                    "cross-origin-frame",
                    "dedicated-worker",
                    "shared-worker",
                ),
            ),
            ("beacon", ("page", "same-origin-frame", "cross-origin-frame")),
            (
                "trusted-anchor-ping",
                ("page", "same-origin-frame", "cross-origin-frame"),
            ),
            (
                "legacy-csp-report",
                ("page", "same-origin-frame", "cross-origin-frame"),
            ),
        )
        for context in contexts
    ]
    + [f"service-worker--page--{surface}" for surface in ("registration", "import", "fetch")]
    + [
        f"popup--page--{surface}"
        for surface in (
            "window-open-omitted-target",
            "window-open-empty-target",
            "window-open-blank-target",
            "window-open-attacker-name",
            "window-open-existing-named-frame",
            "attached-anchor",
            "detached-anchor",
            "button-formtarget",
            "input-formtarget",
            "request-submit-submitter",
        )
    ]
    + [
        f"browser-service--browser--{surface}"
        for surface in (
            "dns-prefetch",
            "preconnect",
            "speculation-prefetch",
            "speculation-prerender",
            "reporting-nel-live",
            "reporting-nel-close-flush",
            "fedcm",
            "protected-audience",
            "attribution",
            "shared-storage",
            "proxy",
            "pac",
            "idle-launch-close",
        )
    ]
    + [
        f"browser-service-control--{context}--{surface}"
        for context, surface in (
            ("off-the-record", "speculation-prefetch-disabled"),
            ("off-the-record", "speculation-prefetch-enabled"),
            ("default-profile", "dns-prefetch-disabled"),
            ("default-profile", "dns-prefetch-enabled"),
            ("default-profile", "preconnect-disabled"),
            ("default-profile", "preconnect-enabled"),
            ("default-profile", "speculation-prerender-disabled"),
            ("default-profile", "speculation-prerender-enabled"),
            ("default-profile", "reporting-disabled"),
            ("default-profile", "reporting-enabled"),
            ("default-profile", "network-error-logging-disabled"),
            ("default-profile", "network-error-logging-enabled"),
        )
    ]
    + [f"positive-control--fixture--{surface}" for surface in ("tcp", "udp", "dns")]
)
if len(_BROWSER_EGRESS_VECTOR_IDS) != BROWSER_EGRESS_VECTOR_COUNT:  # pragma: no cover
    raise RuntimeError("browser-egress watcher vector inventory is inconsistent")
BUILD_WSL_HOST_MIN_AVAILABLE_BYTES = 64 * 1024**3
BUILD_HOST_STORAGE_POLICY = "docker-data-vhdx-backing-volume-minimum-v1"
BUILD_HOST_STORAGE_PROBE = "powershell-get-volume-docker-data-vhdx-v1"
BUILD_HOST_STORAGE_BOUNDARIES = (
    "before-collection",
    "before-prepare",
    "before-reference",
    "after-reference",
)
BUILD_HOST_STORAGE_LOCATION_SOURCES = {
    "wsl-lxss-docker-desktop-data",
    "docker-settings-store",
    "docker-legacy-settings",
}
BUILD_RUST_BASE_IMAGE = (
    "docker.io/library/rust:1.90-bookworm@"
    "sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f"
)
BUILD_DEBIAN_BASE_IMAGE = (
    "docker.io/library/debian:bookworm-slim@"
    "sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818"
)
BUILD_IMAGE_TAGS = {
    "collection": "neqo-qcsd-lab-collection:local",
    "prepare": "neqo-qcsd-lab-prepare:local",
    "reference": "neqo-qcsd-lab-reference:local",
}
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
BROWSER_EGRESS_VERIFY_RUNTIME_SECONDS = 600
STATUS_RUNTIME_SECONDS = 300
STATUS_CLEANUP_SECONDS = 10
ACQUISITION_ACTION_TIMEOUT_SECONDS = 1_800
ACQUISITION_ACTION_CLEANUP_SECONDS = 120
# The user-systemd scope is the outer backup for the in-container hard action
# timeout.  At expiry it sends INT, then permits the same cleanup envelope
# before systemd escalates to KILL.
RUN_RUNTIME_SECONDS = ACQUISITION_ACTION_TIMEOUT_SECONDS + ACQUISITION_ACTION_CLEANUP_SECONDS
ACQUISITION_OUTER_HARD_SECONDS = RUN_RUNTIME_SECONDS + ACQUISITION_ACTION_CLEANUP_SECONDS
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
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REPO_DIGEST_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
_VOLUME_ID_RE = re.compile(
    r"\\\\\?\\Volume\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}\\\Z"
)
_WINDOWS_VHD_RE = re.compile(r"[A-Za-z]:\\[^\r\n]+[.]vhdx\Z", re.IGNORECASE)
_CANDIDATE_ID_RE = re.compile(r"tranco-[0-9]{7}\Z")
_BOOT_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
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
    "non_replayable_egress_contract",
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
_BUILD_EXECUTION_KEYS = {
    "schema_version",
    "artifact_type",
    "cohort_version",
    "started_at",
    "finished_at",
    "duration_seconds",
    "docker",
    "commands",
    "images",
    "source",
    "build_inputs",
    "dockerfile_sha256",
    "cache_policy",
    "payload_sha256",
    "host_storage_preflight",
    "role_provenance",
    "buildx",
}
_BUILD_EXECUTION_SCHEMA5_KEYS = _BUILD_EXECUTION_KEYS | {
    "cohort_allocation",
    "cohort_claim",
    "cohort_claim_chain",
    "cohort_authority_reproofs",
}
_COHORT_ALLOCATION_KEYS = {
    "schema_version",
    "artifact_type",
    "policy",
    "ledger_path",
    "ledger_sha256",
    "ledger_payload_base64",
    "git_object_format",
    "ledger_git_blob_oid",
    "lab_commit",
    "neqo_commit",
    "neqo_gitlink",
    "lab_commit_ledger_proof",
    "last_consumed_version",
    "allocated_version",
}
_COHORT_ALLOCATION_TYPE = "qcsd-buflo-study-cohort-allocation"
_COHORT_ALLOCATION_POLICY = "dense-prefix-durable-publications-consume-v1"
_COHORT_LEDGER_PATH = "config/buflo-study/v1/consumed-cohorts.json"
_COHORT_LEDGER_TYPE = "qcsd-buflo-study-consumed-cohorts"
_COHORT_LEDGER_MAX_BYTES = 16 * 1024
_COHORT_GIT_PROOF_KEYS = {
    "schema_version",
    "artifact_type",
    "commit_payload_base64",
    "tree_payloads_base64",
}
_COHORT_GIT_PROOF_TYPE = "qcsd-buflo-study-cohort-ledger-git-proof"
_COHORT_GIT_PROOF_COMMIT_MAX_BYTES = 256 * 1024
_COHORT_GIT_PROOF_TREE_MAX_BYTES = 1024 * 1024
_COHORT_GIT_PROOF_TREE_COUNT = 4
_COHORT_CLAIM_MAX_BYTES = 4 * 1024 * 1024
_COHORT_CLAIM_REGISTRY_PATH = "artifacts/buflo-study/cohort-claims-v1"
_COHORT_CLAIM_TYPE = "qcsd-buflo-study-cohort-claim"
_COHORT_CLAIM_SNAPSHOT_TYPE = "qcsd-buflo-study-cohort-claim-publication"
_COHORT_AUTHORITY_TYPE = "qcsd-buflo-study-cohort-allocation-authority"
_COHORT_CLAIM_SNAPSHOT_KEYS = {
    "schema_version",
    "artifact_type",
    "policy",
    "cohort_version",
    "registry",
    "claim",
    "registry_head_at_publication",
    "payload_sha256",
}
_COHORT_CLAIM_KEYS = {"schema_version", "artifact_type", "payload", "payload_sha256"}
_COHORT_CLAIM_PAYLOAD_KEYS = {
    "policy",
    "registry_path",
    "cohort_version",
    "authority",
    "authority_sha256",
    "source",
    "ledger",
    "predecessor",
}
_COHORT_AUTHORITY_KEYS = {"schema_version", "artifact_type", "git", "filesystem", "receipt"}
_COHORT_AUTHORITY_GIT_KEYS = {
    "object_format",
    "lab_head",
    "head_blob_oid",
    "index_blob_oid",
    "worktree_blob_oid",
    "neqo_head",
    "head_gitlink",
    "index_gitlink",
}
_COHORT_AUTHORITY_FILESYSTEM_KEYS = {"directories", "ledger", "git_index"}
_COHORT_AUTHORITY_DIRECTORY_NAMES = {
    "repository-root",
    "config",
    "buflo-study",
    "v1",
    "git",
}
_COHORT_CLAIM_SOURCE_KEYS = {"lab_commit", "neqo_commit", "neqo_gitlink"}
_COHORT_CLAIM_LEDGER_KEYS = {
    "path",
    "sha256",
    "git_object_format",
    "git_blob_oid",
    "payload_base64",
    "last_consumed_version",
}
_COHORT_CLAIM_PREDECESSOR_KEYS = {"kind", "cohort_version", "sha256"}
_COHORT_CLAIM_CHAIN_TYPE = "qcsd-buflo-study-cohort-claim-chain"
_COHORT_CLAIM_CHAIN_KEYS = {
    "schema_version",
    "artifact_type",
    "policy",
    "genesis",
    "claims",
    "head",
    "payload_sha256",
}
_COHORT_CLAIM_CHAIN_GENESIS_KEYS = {
    "ledger_path",
    "ledger_sha256",
    "last_consumed_version",
}
_COHORT_CLAIM_CHAIN_ENTRY_KEYS = {"cohort_version", "sha256", "payload_base64"}
_COHORT_CLAIM_CHAIN_HEAD_KEYS = {"cohort_version", "sha256"}
_COHORT_CLAIM_CHAIN_MAX_ENTRIES = 4096
_COHORT_CLAIM_CHAIN_MAX_DECODED_BYTES = 8 * 1024 * 1024
_COHORT_SNAPSHOT_REGISTRY_KEYS = {"path", "stat"}
_COHORT_SNAPSHOT_CLAIM_KEYS = {"path", "sha256", "payload_base64", "stat"}
_COHORT_FILE_STAT_KEYS = {
    "dev",
    "inode",
    "uid",
    "gid",
    "mode",
    "nlink",
    "size",
    "mtime_ns",
    "ctime_ns",
}
_COHORT_DIRECTORY_STAT_KEYS = {"dev", "inode", "uid", "gid", "mode", "nlink"}
_COHORT_REPROOF_KEYS = {
    "boundary",
    "observed_at",
    "authority_sha256",
    "claim_snapshot_sha256",
    "claim_file_sha256",
}
_COHORT_REPROOF_BOUNDARIES = (
    "after-cohort-claim-before-docker-recovery",
    "immediately-before-docker-recovery",
    "after-evidence-build-lock",
    "immediately-before-build-transaction",
    "immediately-after-build-transaction",
    "immediately-before-collection-build",
    "immediately-before-prepare-build",
    "immediately-before-reference-build",
    "after-reference-build-before-receipt",
)
_COHORT_FINAL_REPROOF_MAX_AGE_SECONDS = 2.0
_BUILD_COMPLETION_KEYS = {
    "schema_version",
    "artifact_type",
    "cohort_version",
    "completed_at",
    "receipt",
    "source",
    "cohort_authority",
    "transaction",
    "final_reproof",
    "payload_sha256",
}
_BUILD_COMPLETION_RECEIPT_KEYS = {
    "path",
    "schema_version",
    "cohort_version",
    "payload_sha256",
    "sha256",
    "stat",
}
_BUILD_COMPLETION_SOURCE_KEYS = {"lab_commit", "neqo_commit", "neqo_gitlink"}
_BUILD_COMPLETION_AUTHORITY_KEYS = {
    "allocation_sha256",
    "claim_snapshot_sha256",
    "claim_file_sha256",
    "claim_chain_sha256",
    "claim_chain_payload_sha256",
}
_BUILD_COMPLETION_REPROOF_KEYS = {
    "boundary",
    "observed_at",
    "authority_sha256",
    "claim_snapshot_sha256",
    "claim_file_sha256",
    "claim_chain_sha256",
}
_BUILD_COMPLETION_REPROOF_BOUNDARY = (
    "after-build-transaction-completion-before-completion-publication"
)
_BUILD_COMPLETION_MAX_DELAY_SECONDS = 2.0
_BUILD_TRANSACTION_RETIREMENT_TYPE = "qcsd-buflo-study-build-transaction-retirement"
_BUILD_COMPLETION_TRANSACTION_KEYS = {
    "schema_version",
    "artifact_type",
    "root",
    "record",
    "guardian",
    "lifecycle_lock",
    "cohort_lock",
    "operation_lock",
}
_BUILD_TRANSACTION_ROOT_KEYS = {"path", "stat"}
_BUILD_TRANSACTION_RECORD_KEYS = {"path", "sha256", "payload_base64", "stat"}
_BUILD_COMPLETION_GUARDIAN_KEYS = {
    "pid",
    "start_time",
    "qcsd_pid",
    "qcsd_start_time",
}
_BUILD_COMPLETION_LIFECYCLE_KEYS = {
    "path",
    "device",
    "inode",
    "parent_device",
    "parent_inode",
    "lease_nonce",
}
_BUILD_COMPLETION_COHORT_LOCK_KEYS = {
    "path",
    "device",
    "inode",
    "parent_device",
    "parent_inode",
    "guardian_fd",
}
_BUILD_COMPLETION_OPERATION_LOCK_KEYS = {
    "path",
    "device",
    "inode",
    "parent_device",
    "parent_inode",
}
_BUILD_TRANSACTION_RECORD_FIELDS = (
    "object",
    "lifecycle_schema",
    "lifecycle_state",
    "lifecycle_root",
    "lifecycle_token",
    "supervisor_source_path",
    "supervisor_source_sha256",
    "supervisor_source_device",
    "supervisor_source_inode",
    "docker_context",
    "docker_host",
    "docker_server_id",
    "docker_request_revalidation",
    "docker_daemon_id",
    "host_boot_id",
    "working_directory",
    "cohort_version",
    "receipt_path",
    "transaction_state",
)
_BUILDX_KEYS = {"schema_version", "policy", "identity", "observations", "passed"}
_BUILDX_IDENTITY_KEYS = {
    "selection_source",
    "plugin_name",
    "plugin_vendor",
    "metadata_schema_version",
    "short_description",
    "reported_plugin_version",
    "reported_plugin_path",
    "plugin",
    "resolved",
    "version_output",
    "version",
    "commit",
}
_BUILDX_STAT_KEYS = {
    "dev",
    "inode",
    "uid",
    "gid",
    "mode",
    "nlink",
    "size",
    "mtime_ns",
    "ctime_ns",
}
_BUILDX_PLUGIN_KEYS = {"path", "symlink_target"} | _BUILDX_STAT_KEYS
_BUILDX_RESOLVED_KEYS = {"path", "sha256"} | _BUILDX_STAT_KEYS
_BUILDX_PLUGIN_DIRECTORIES = frozenset(
    PurePosixPath(path)
    for path in (
        "/usr/local/lib/docker/cli-plugins",
        "/usr/local/libexec/docker/cli-plugins",
        "/usr/lib/docker/cli-plugins",
        "/usr/libexec/docker/cli-plugins",
    )
)
_BUILDX_BOUNDARIES = (
    "before-collection",
    "after-collection",
    "after-prepare",
    "after-reference",
)
_BUILDX_SELECTION_SOURCE = "docker-info-client-plugin-metadata-v1"
_BUILDX_POLICY = "docker-selected-buildx-binary-stability-v1"
_BUILDX_VERSION_OUTPUT_RE = re.compile(
    r"github[.]com/docker/buildx "
    r"(?P<version>v(?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)[.]"
    r"(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
    r"(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?) "
    r"(?P<commit>[0-9a-f]{40})"
)
_BUILD_INPUT_KEYS = {
    "schema_version",
    "artifact_type",
    "rust_base_image",
    "debian_base_image",
    "uv_lock_sha256",
    "cargo_lock_sha256",
}
_BUILD_STORAGE_OBSERVATION_KEYS = {
    "schema_version",
    "probe",
    "probe_sha256",
    "boundary",
    "observed_at",
    "location_source",
    "data_vhd_path",
    "data_vhd_file_length_bytes",
    "backing_volume_unique_id",
    "drive_letter",
    "file_system",
    "health_status",
    "operational_status",
    "total_bytes",
    "available_bytes",
}
_BUILD_STORAGE_PREFLIGHT_KEYS = {
    "schema_version",
    "applicable",
    "platform",
    "platform_detection",
    "policy",
    "required_available_bytes",
    "observations",
    "minimum_available_bytes",
    "passed",
}
_CDP_TARGET_INSTRUMENTATION_POLICY = (
    "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v14"
)
_PLAYWRIGHT_VERSION = "1.57.0"
_CHROMIUM_VERSION = "143.0.7499.4"
_CHROMIUM_EXECUTABLE = "/usr/local/bin/qcsd-chromium"
_PINNED_CDP_SCHEMA_VERSION = 13
_HISTORICAL_PINNED_CDP_SCHEMA_VERSION = 8
_HISTORICAL_PINNED_CDP_SCHEMA_VERSIONS = frozenset({8, 9, 11, 12})
_PINNED_CDP_CONTRACT_SCHEMA_VERSION = 12
_HISTORICAL_PINNED_CDP_CONTRACT_SCHEMA_VERSION = 8
_HISTORICAL_PINNED_CDP_CONTRACT_V12_SCHEMA_VERSION = 11
_BOOTSTRAP_PREARM_SUMMARY_SCHEMA_VERSION = 1
_EGRESS_PREARM_SUMMARY_SCHEMA_VERSION = 2
_PINNED_CDP_TARGET_ACTIVITY_SCHEMA_VERSION = 1
_PINNED_CDP_WORKER_WEBTRANSPORT_PROBE_SCHEMA_VERSION = 1
_NON_REPLAYABLE_EGRESS_POLICY = "blocked-non-urlloader-egress-v1"
_NON_REPLAYABLE_EGRESS_SCHEMA_VERSION = 2
_BROWSER_EGRESS_COMMAND_LINE_SCHEMA_VERSION = 4
_BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE = "production-fail-closed"
_BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES = [
    "--disable-background-networking",
    "--disable-client-side-phishing-detection",
    "--disable-component-update",
    "--disable-crashpad-for-testing",
    "--disable-default-apps",
    "--disable-domain-reliability",
    "--disable-extensions",
    "--disable-quic",
    "--disable-sync",
    "--no-first-run",
    "--no-pings",
    "--no-proxy-server",
    "--no-sandbox",
    "--no-service-autorun",
    "--no-zygote",
]
_BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES = [
    "--disable-extensions-except",
    "--enable-background-networking",
    "--enable-client-side-phishing-detection",
    "--enable-component-update",
    "--enable-default-apps",
    "--enable-domain-reliability",
    "--enable-extensions",
    "--enable-pings",
    "--enable-quic",
    "--enable-service-autorun",
    "--enable-sync",
    "--first-run",
    "--force-first-run",
    "--force-first-run-ui",
    "--host-rules",
    "--load-extension",
    "--proxy-auto-detect",
    "--proxy-pac-url",
    "--proxy-server",
    "--service-autorun",
    "--single-process",
]
_BROWSER_EGRESS_REQUIRED_DISABLED_FEATURE_TOKENS = sorted(
    [
        "AcceptCHFrame",
        "AutoDeElevate",
        "AvoidUnnecessaryBeforeUnloadCheckSync",
        "DestroyProfileOnBrowserClose",
        "DialMediaRouteProvider",
        "FedCm",
        "GlobalMediaControls",
        "HttpsUpgrades",
        "LensOverlay",
        "MediaRouter",
        "NetworkErrorLogging",
        "OptimizationHints",
        "PaintHolding",
        "RenderDocument",
        "Reporting",
        "ThirdPartyStoragePartitioning",
        "Translate",
    ]
)
_BROWSER_EGRESS_REQUIRED_DISABLED_BLINK_FEATURE_TOKENS = sorted(
    ["AdInterestGroupAPI", "AttributionReporting", "Fledge", "SharedStorageAPI"]
)
_BROWSER_EGRESS_REQUIRED_ENABLED_FEATURE_ARGUMENTS = [["CDPScreenshotNewSurface"]]
_BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT = (
    "--browser-subprocess-path=/usr/local/libexec/qcsd-chromium-child"
)
_PINNED_CDP_RESOLVER_PROJECTION = {
    "schema_version": 1,
    "mode": "approved-map-or-exclude-then-not-found",
    "rule_count": 3,
    "mapped_host_count": 2,
    "excluded_host_count": 0,
    "catch_all_not_found": True,
    "canonical_rules_sha256": ("7fc67c9e271c3f1ed88a3a57b60dda5ab9d63a484a929cc010fb7ca635b98907"),
}
_PAGE_TARGET_EGRESS_APIS = (
    "WebSocketStream",
    "WebTransport",
    "RTCPeerConnection",
    "webkitRTCPeerConnection",
    "TCPSocket",
    "TCPServerSocket",
    "UDPSocket",
)
_WORKER_TARGET_EGRESS_APIS = ("WebSocket", *_PAGE_TARGET_EGRESS_APIS)
_TARGET_EGRESS_APIS = sorted(set(_WORKER_TARGET_EGRESS_APIS))
_PLAYWRIGHT_BROWSERS_JSON_SHA256 = (
    "b509d013de89d621a142818e0937de356fbb0169096922c08581a4f83e463b8e"
)
_CHROMIUM_EXECUTABLE_SHA256 = "6f72e258e11d85ec413b1671422c83d65af9f9ddcbc811657a43700b324ce928"
_LEGACY_PLAYWRIGHT_DRIVER_CONTENT_SHA256 = (
    "f2f774b92c6074dcab28bc5a0afa13b43c70e372057558b7246d4ba168602d51"
)
_LEGACY_PLAYWRIGHT_DRIVER_PAYLOAD_SHA256 = (
    "926b894666e6b5d6dcdb31dc28d581a9cb22eba1f6dc924be74b49402c44e3c3"
)
_LEGACY_PLAYWRIGHT_DRIVER_RECEIPT_SHA256 = (
    "7194034787b5c1c34ffd88d62cf9969b1510fca7955a0ed7b7c3168f23a8bfb2"
)
_LEGACY_PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY = {
    "name": "qcsd-conditional-exclusive-recursive-cdp-target-ownership-v6",
    "activation_environment_variable": "QCSD_EXCLUSIVE_CDP_TARGET_OWNERSHIP",
    "activation_value": "1",
    "inactive_semantics": "native-playwright-unfiltered-auto-attach",
    "driver_start_environment_lock": "held-only-through-sync-playwright-enter",
    "forbidden_driver_environment_variables": [
        "NODE_OPTIONS",
        "NODE_PATH",
        "PLAYWRIGHT_NODEJS_PATH",
        "PLAYWRIGHT_NODEJS_PORT",
        "PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK",
        "PLAYWRIGHT_DISABLE_SERVICE_WORKER_CONSOLE",
        "PLAYWRIGHT_DISABLE_SERVICE_WORKER_NETWORK",
        "PLAYWRIGHT_HOST_PLATFORM_OVERRIDE",
        "PLAYWRIGHT_LEGACY_SCREENSHOT",
        "PLAYWRIGHT_SKIP_NAVIGATION_CHECK",
        "PWDEBUG",
        "PW_CHROMIUM_ATTACH_TO_OTHER",
        "SELENIUM_REMOTE_CAPABILITIES",
        "SELENIUM_REMOTE_HEADERS",
        "SELENIUM_REMOTE_URL",
    ],
    "chromium_child_environment": {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    },
    "shared_worker_pause_fix": {
        "chromium_commit": "0606a60db66fc14d6fd76c8d532392b26504b308",
        "chromium_position": 1_529_406,
        "required_semantics": "wait-for-debugger-on-start-holds-new-shared-worker",
    },
    "browser_service_containment": {
        "dns_over_https_policy": {"DnsOverHttpsMode": "off"},
        "network_prediction_policy": {"NetworkPredictionOptions": 2},
        "same_approved_origin_speculation_prefetch_required": True,
        "ordinary_playwright_launch": True,
    },
}
_LEGACY_EXPECTED_PLAYWRIGHT_DRIVER_BINDING = {
    "receipt_sha256": _LEGACY_PLAYWRIGHT_DRIVER_RECEIPT_SHA256,
    "payload_sha256": _LEGACY_PLAYWRIGHT_DRIVER_PAYLOAD_SHA256,
    "content_sha256": _LEGACY_PLAYWRIGHT_DRIVER_CONTENT_SHA256,
    "policy": _LEGACY_PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY,
    "browsers_json_sha256": _PLAYWRIGHT_BROWSERS_JSON_SHA256,
    "chromium_executable_sha256": _CHROMIUM_EXECUTABLE_SHA256,
}
_PREVIOUS_PLAYWRIGHT_DRIVER_CONTENT_SHA256 = (
    "4d8f576c788db015ecfd977fb3868a437c55ba45b39da7943990f3938ee7798f"
)
_PREVIOUS_PLAYWRIGHT_DRIVER_PAYLOAD_SHA256 = (
    "91982e3a741cc7bc58c4b3abe85358cd63946ed6db11e15dd754b0e7cf51409f"
)
_PREVIOUS_PLAYWRIGHT_DRIVER_RECEIPT_SHA256 = (
    "709f81c4f07b3b06eb6bd4c29f4b6eb69a5e8157f8378638b75a453226ed0caa"
)
_PREVIOUS_PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY = {
    **_LEGACY_PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY,
    "name": "qcsd-conditional-exclusive-recursive-cdp-target-ownership-v7",
    "exclusive_context_route": {
        "playwright_fetch_resource_types": ["Document"],
        "request_stage": "Request",
        "purpose": "pre-io-popup-and-document-navigation-policy",
        "subresource_admission_owner": "qcsd-recursive-cdp-fetch",
        "http_credentials": "rejected-before-network-manager-state-mutation",
    },
}
_PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING = {
    "receipt_sha256": _PREVIOUS_PLAYWRIGHT_DRIVER_RECEIPT_SHA256,
    "payload_sha256": _PREVIOUS_PLAYWRIGHT_DRIVER_PAYLOAD_SHA256,
    "content_sha256": _PREVIOUS_PLAYWRIGHT_DRIVER_CONTENT_SHA256,
    "policy": _PREVIOUS_PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY,
    "browsers_json_sha256": _PLAYWRIGHT_BROWSERS_JSON_SHA256,
    "chromium_executable_sha256": _CHROMIUM_EXECUTABLE_SHA256,
}
_PLAYWRIGHT_DRIVER_CONTENT_SHA256 = (
    "3f8b25f097d439ccbfa4404efc887357d441d437ccefaca5852a93e3dfe28186"
)
_PLAYWRIGHT_DRIVER_PAYLOAD_SHA256 = (
    "3e14582e31c0f2bf9fb7f5c6222643dd351403e44a02a8096dc8441f91e820e0"
)
_PLAYWRIGHT_DRIVER_RECEIPT_SHA256 = (
    "a5aada06e4fd315d08b2235701480a13f0852188749e489d6bc9386b3a34632f"
)
_PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY = {
    **_PREVIOUS_PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY,
    "name": "qcsd-conditional-exclusive-recursive-cdp-target-ownership-v8",
    "exclusive_context_route": {
        "playwright_fetch_resource_types": ["Document"],
        "request_stage": "Request",
        "purpose": "pre-io-popup-and-document-navigation-policy",
        "subresource_admission_owner": "qcsd-recursive-cdp-fetch",
        "http_credentials": (
            "rejected-at-awaited-pre-context-and-runtime-mutation-boundaries"
        ),
        "http_credentials_rejection": {
            "client_certificate_proxy_override": "allowed-when-unauthenticated",
            "context_reuse": "new-context-guarded-and-reset-cannot-introduce-credentials",
            "ephemeral_context": "browser-new-context-before-validation-or-target-creation",
            "persistent_context": "browser-type-launch-persistent-context-before-browser-launch",
            "runtime_update": "browser-context-set-http-credentials-before-mutation",
            "scope": "exclusive-chromium-only",
        },
    },
}
_EXPECTED_PLAYWRIGHT_DRIVER_BINDING = {
    "receipt_sha256": _PLAYWRIGHT_DRIVER_RECEIPT_SHA256,
    "payload_sha256": _PLAYWRIGHT_DRIVER_PAYLOAD_SHA256,
    "content_sha256": _PLAYWRIGHT_DRIVER_CONTENT_SHA256,
    "policy": _PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY,
    "browsers_json_sha256": _PLAYWRIGHT_BROWSERS_JSON_SHA256,
    "chromium_executable_sha256": _CHROMIUM_EXECUTABLE_SHA256,
}
_EXPECTED_BROWSER_TOOL_IDENTITY = {
    "schema_version": 1,
    "name": "playwright-chromium",
    "playwright_version": _PLAYWRIGHT_VERSION,
    "chromium_revision": "1200",
    "chromium_version": _CHROMIUM_VERSION,
    "configured_executable_path": _CHROMIUM_EXECUTABLE,
    "playwright_driver": _EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
}
_HISTORICAL_PINNED_CDP_CONTRACT_V11 = {
    # Probe schema 11 binds both the paused-OOPIF pre-author instrumentation
    # semantics and Document-only Playwright routing under exclusive QCSD
    # ownership. The independently versioned browser/probe behaviour contract
    # advances with those semantic boundaries.
    "schema_version": 10,
    "policy": "pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v10",
    "instrumentation_policy": (
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v12"
    ),
    "playwright_version": _PLAYWRIGHT_VERSION,
    "chromium_executable": _CHROMIUM_EXECUTABLE,
    "chromium_version": _CHROMIUM_VERSION,
    "playwright_driver_ownership_policy": _PREVIOUS_PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY,
    "playwright_driver_binding": _PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
    "playwright_browsers_json_sha256": _PLAYWRIGHT_BROWSERS_JSON_SHA256,
    "chromium_executable_sha256": _CHROMIUM_EXECUTABLE_SHA256,
    "network_scope": "docker-network-none-loopback-only",
    "observation_timeout_ms": 10_000,
    "required_quiet_interval_ms": 250,
    "target_activity_schema_version": _PINNED_CDP_TARGET_ACTIVITY_SCHEMA_VERSION,
    "required_target_types": ["iframe", "shared_worker", "worker"],
    "required_observations": [
        "cross-site-iframe-network-request",
        "dedicated-and-shared-worker-network-requests",
        "dedicated-worker-fetch-paused-on-owning-page-session",
        "shared-worker-fetch-paused-on-guarded-shared-worker-session",
        "shared-worker-bootstrap-held-through-secondary-fetch-prearm",
        "target-lifecycle-activity-resets-quiescence",
        "duplicate-url-occurrences-remain-distinct",
        "all-deterministic-http-responses-finished-successfully",
        "router-ledger-extra-info-and-server-shutdown-complete",
        "all-runnable-targets-prearmed-against-non-urlloader-egress",
        "context-websocket-route-installed-before-first-page",
        "zero-service-worker-and-non-replayable-egress-attempts",
        "required-effective-chromium-egress-switches",
        "unprivileged-zero-capability-runtime",
        "paused-runnable-target-first-script-prearmed-before-execution",
        "dedicated-and-shared-worker-response-bodies-consumed",
        "document-only-playwright-route-with-recursive-cdp-subresource-ownership",
        "shared-worker-guardian-real-detach-ordered-before-final-proof",
    ],
    "non_replayable_egress_policy": _NON_REPLAYABLE_EGRESS_POLICY,
    "packet_level_egress_completeness_claimed": False,
}
_HISTORICAL_PINNED_CDP_CONTRACT_V12 = {
    **_HISTORICAL_PINNED_CDP_CONTRACT_V11,
    "schema_version": _HISTORICAL_PINNED_CDP_CONTRACT_V12_SCHEMA_VERSION,
    "policy": "pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v11",
    "instrumentation_policy": (
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v13"
    ),
    "required_observations": [
        item
        for item in _HISTORICAL_PINNED_CDP_CONTRACT_V11["required_observations"]
        if item
        not in {
            "zero-service-worker-and-non-replayable-egress-attempts",
            "paused-runnable-target-first-script-prearmed-before-execution",
            "dedicated-and-shared-worker-response-bodies-consumed",
            "document-only-playwright-route-with-recursive-cdp-subresource-ownership",
            "shared-worker-guardian-real-detach-ordered-before-final-proof",
        }
    ]
    + [
        "zero-unsanctioned-service-worker-and-non-replayable-egress-attempts",
        "paused-runnable-target-first-script-prearmed-before-execution",
        "dedicated-and-shared-worker-response-bodies-consumed",
        "document-only-playwright-route-with-recursive-cdp-subresource-ownership",
        "shared-worker-guardian-real-detach-ordered-before-final-proof",
        "potentially-trustworthy-loopback-worker-origin",
        "dedicated-and-shared-worker-webtransport-blocked-after-prearm-with-exact-telemetry",
    ],
    "worker_webtransport_probe_schema_version": (
        _PINNED_CDP_WORKER_WEBTRANSPORT_PROBE_SCHEMA_VERSION
    ),
}
_PINNED_CDP_CONTRACT = {
    **_HISTORICAL_PINNED_CDP_CONTRACT_V12,
    "schema_version": _PINNED_CDP_CONTRACT_SCHEMA_VERSION,
    "policy": "pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v12",
    "instrumentation_policy": _CDP_TARGET_INSTRUMENTATION_POLICY,
    "playwright_driver_ownership_policy": _PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY,
    "playwright_driver_binding": _EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
}
_HISTORICAL_PINNED_CDP_CONTRACT = {
    "schema_version": _HISTORICAL_PINNED_CDP_CONTRACT_SCHEMA_VERSION,
    "policy": "pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v8",
    "instrumentation_policy": (
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v10"
    ),
    "playwright_version": _PLAYWRIGHT_VERSION,
    "chromium_executable": _CHROMIUM_EXECUTABLE,
    "chromium_version": _CHROMIUM_VERSION,
    "playwright_driver_ownership_policy": _LEGACY_PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY,
    "playwright_driver_binding": _LEGACY_EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
    "playwright_browsers_json_sha256": _PLAYWRIGHT_BROWSERS_JSON_SHA256,
    "chromium_executable_sha256": _CHROMIUM_EXECUTABLE_SHA256,
    "network_scope": "docker-network-none-loopback-only",
    "observation_timeout_ms": 10_000,
    "required_quiet_interval_ms": 250,
    "target_activity_schema_version": _PINNED_CDP_TARGET_ACTIVITY_SCHEMA_VERSION,
    "required_target_types": ["iframe", "shared_worker", "worker"],
    "required_observations": [
        "cross-site-iframe-network-request",
        "dedicated-and-shared-worker-network-requests",
        "dedicated-worker-fetch-paused-on-owning-page-session",
        "shared-worker-fetch-paused-on-guarded-shared-worker-session",
        "shared-worker-bootstrap-held-through-secondary-fetch-prearm",
        "target-lifecycle-activity-resets-quiescence",
        "duplicate-url-occurrences-remain-distinct",
        "all-deterministic-http-responses-finished-successfully",
        "router-ledger-extra-info-and-server-shutdown-complete",
        "all-runnable-targets-prearmed-against-non-urlloader-egress",
        "context-websocket-route-installed-before-first-page",
        "zero-service-worker-and-non-replayable-egress-attempts",
        "required-effective-chromium-egress-switches",
        "unprivileged-zero-capability-runtime",
    ],
    "non_replayable_egress_policy": _NON_REPLAYABLE_EGRESS_POLICY,
    "packet_level_egress_completeness_claimed": False,
}
_PINNED_CDP_TARGET_ACTIVITY_EVENTS = (
    "target-attached",
    "target-info-changed",
    "target-detached",
    "target-destroyed",
)
_PINNED_CDP_TARGET_ACTIVITY_TYPES = ("iframe", "page", "shared_worker", "worker")
_PINNED_CDP_EVENT_METHODS = (
    "Fetch.requestPaused",
    "Network.loadingFailed",
    "Network.loadingFinished",
    "Network.requestServedFromCache",
    "Network.requestWillBeSent",
    "Network.requestWillBeSentExtraInfo",
    "Network.responseReceived",
)
_PINNED_CDP_HTTP_STATUS_COUNTS = {
    "/": {"200": 1},
    "/dedicated-data": {"200": 1},
    "/dedicated-worker.js": {"200": 1},
    "/duplicate": {"200": 2},
    "/frame": {"200": 1},
    "/frame-data": {"200": 1},
    "/redirect": {"302": 1},
    "/redirected": {"200": 1},
    "/shared-data": {"200": 1},
    "/shared-worker.js": {"200": 1},
}
_PINNED_CDP_SERVER_REQUEST_COUNTS = {
    path: sum(statuses.values()) for path, statuses in _PINNED_CDP_HTTP_STATUS_COUNTS.items()
}
_PINNED_CDP_WORKER_RESPONSE_CONSUMPTION = {
    "dedicated_worker": "qcsd-dedicated-response-consumed",
    "shared_worker": "qcsd-shared-response-consumed",
}
_PINNED_CDP_WORKER_WEBTRANSPORT_MEASUREMENT = {
    "resolved_type": "function",
    "own_descriptor": "data",
    "action_issued": True,
    "action_succeeded": False,
    "exception_name": "TypeError",
}
_PINNED_CDP_WORKER_WEBTRANSPORT_PROBE = {
    "schema_version": _PINNED_CDP_WORKER_WEBTRANSPORT_PROBE_SCHEMA_VERSION,
    "by_target_type": {
        target_type: {
            "measurement": dict(_PINNED_CDP_WORKER_WEBTRANSPORT_MEASUREMENT),
            "guard_telemetry": {
                "notification_count": 1,
                "api": "WebTransport",
                "mechanism": "paused-target-runtime-shim",
                "url": None,
            },
        }
        for target_type in ("shared_worker", "worker")
    },
}
_PINNED_CDP_BOOTSTRAP_PREARM_SUMMARY = {
    "schema_version": _BOOTSTRAP_PREARM_SUMMARY_SCHEMA_VERSION,
    "held_total": 1,
    "released_total": 1,
    "pending_total": 0,
    "release_before_setup_envelopes_total": 0,
    "by_worker_type": {
        "worker": {
            "held": 0,
            "released": 0,
            "pending": 0,
            "released_after_setup_envelopes": 0,
            "owner_target_types": {
                "page": 0,
                "iframe": 0,
                "worker": 0,
                "shared_worker": 0,
            },
        },
        "shared_worker": {
            "held": 1,
            "released": 1,
            "pending": 0,
            "released_after_setup_envelopes": 1,
            "owner_target_types": {
                "page": 1,
                "iframe": 0,
                "worker": 0,
                "shared_worker": 0,
            },
        },
    },
}
_NON_REPLAYABLE_EGRESS_CONTRACT = {
    "schema_version": 2,
    "policy": _NON_REPLAYABLE_EGRESS_POLICY,
    "target_shim_schema_version": 1,
    "target_shim_sha256": {
        "iframe": "c3e6347e810fbc1b1c1517a0d6888d1743578cebbcb6641df763ef1a11cf9fdf",
        "page": "c3e6347e810fbc1b1c1517a0d6888d1743578cebbcb6641df763ef1a11cf9fdf",
        "shared_worker": "41e85a575dac0d0cc1bd67a904ae28666a15f9ab878825170901b58ad736ad7e",
        "worker": "41e85a575dac0d0cc1bd67a904ae28666a15f9ab878825170901b58ad736ad7e",
    },
    "popup_navigation_guard_sha256": (
        "69b182afbcd0c9bb0b8ecb2c3224a4bc3e6443c1572b939f074eb02e367f2dfe"
    ),
    "context_page_init_sha256": (
        "dbfe0d8953c31631129dfe030d090cf5f7b9936c9b042336d456101e59ed33aa"
    ),
    "context_init_target_type": "page",
    "chromium_popup_blocking": "default-enabled",
    "popup_urlloader_boundary": (
        "playwright-browser-context-navigation-route-before-first-page-bound-to-root-page"
    ),
    "browser_popup_tab_tripwire_is_pre_io": False,
    "required_chromium_switches": list(_BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES),
    "no_pings_is_admission_boundary": False,
    "fresh_image_kernel_counter_qualification_required": True,
    "page_frame_websocket_boundary": "playwright-browser-context-route-before-first-page",
    "worker_websocket_boundary": "paused-target-runtime-shim",
    "service_worker_policy": "browser-context-block-plus-browser-target-tripwire",
    "cdp_tripwires_are_pre_io": False,
    "packet_level_completeness_claimed": False,
}
_FOUNDATION_GATES = (
    "current-clean-source-and-no-cache-build",
    "independent-reference-conformance",
    "complete-code-gate",
    "nine-mode-regression-18-of-18",
    "controlled-qualification-160-of-160",
    "pinned-cdp-integration-probe",
    "browser-egress-packet-qualification-110-of-110",
)
_PASSIVE_RENDER_CONTRACT = {
    "schema_version": 3,
    "policy": "bounded-passive-render-quiescence-v3",
    "viewport": {"width": 1365, "height": 768, "deviceScaleFactor": 1},
    "cache": "disabled",
    "service_workers": "bypassed-and-registration-blocked",
    "interaction": "none",
    "minimum_after_load_ms": 10_000,
    "quiet_window_ms": 3_000,
    "quiet_window_begins": "after-minimum-or-last-relevant-event-whichever-is-later",
    "hard_cap_after_load_ms": PASSIVE_RENDER_HARD_CAP_MS,
    "poll_interval_ms": 100,
    "active_request_scope": "all-instrumented-urlloader-request-occurrences",
    "quiescence_requires": [
        "no-active-network-request-occurrences",
        "recursive-target-router-shutdown-ready",
        "no-pending-shared-worker-bootstrap-prearm",
        "all-observed-target-egress-shims-prearmed",
        "zero-non-replayable-egress-attempts",
        "zero-browser-context-service-workers",
    ],
    "relevant_events": [
        "network-request",
        "fetch-request",
        "network-terminal",
        "target-attached",
        "target-detached",
        "target-destroyed",
        "target-info-changed",
        "non-replayable-egress-attempt",
    ],
    "non_replayable_egress_policy": _NON_REPLAYABLE_EGRESS_POLICY,
    "non_replayable_egress_boundary": {
        "page_frame_websocket": "playwright-route-before-page",
        "paused_target_constructor_shim": True,
        "cdp_network_events": "post-construction-tripwire-only",
        "packet_level_completeness_claimed": False,
    },
    "hard_cap_policy": "typed-candidate-rejection",
}
_PASSIVE_RENDER_CONTRACT_SHA256 = hashlib.sha256(
    (json.dumps(_PASSIVE_RENDER_CONTRACT, sort_keys=True, separators=(",", ":")) + "\n").encode()
).hexdigest()
_ORIGIN_POLICY = {
    "max_passes": 8,
    "max_navigation_redirect_passes": 8,
    "max_origins": 32,
    "max_observed_audit_origins": 512,
    "max_navigation_attempts": MAX_PROBE_ATTEMPTS,
    "max_probe_attempts_per_window": MAX_PROBE_ATTEMPTS,
    "navigation_seed_scope": "page-specific-in-boundary-https-get-origins",
    "resource_graph_scope": "iteratively-converged-public-https-get-request-instances",
    "request_instance_identity": (
        "observation-order-resource-id-with-preceding-initiator-and-redirect-edges"
    ),
    "dns": "all-answers-global-and-browser-host-resolver-pinned",
    "neqo": "QCSD_PUBLIC_ORIGIN_ONLY-resolve-once-connect-exact-address",
}
_NAVIGATION_IMPLEMENTATION = "playwright-public-cdp-recursive-catalogue-boundary-egress-guard-v4"
_REGISTRABLE_DOMAIN_POLICY = "exact-frozen-tranco-candidate-domain"
_DOMAIN_SAFETY_POLICY = {
    "policy": "frozen-domain-safety-deny-v2",
    "denied_substrings": [
        "adult",
        "bet",
        "casino",
        "escort",
        "gambl",
        "hentai",
        "malware",
        "phishing",
        "porn",
        "sex",
        "xxx",
    ],
    "denied_exact_domains": [
        "deep-nudes.com",
        "ebonyfacial.net",
        "greenxh.live",
        "hanime.tv",
        "joyclub.de",
        "mygirls.me",
        "xvideos.tube",
        "xnxx.com",
    ],
}
_DOMAIN_SAFETY_POLICY_SHA256 = hashlib.sha256(
    (json.dumps(_DOMAIN_SAFETY_POLICY, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
).hexdigest()
_ELIGIBILITY_INPUTS = ["page-safety", "three-window-technical-stability"]
_PROHIBITED_INPUTS = ["classifier", "defence", "latency", "bandwidth", "privacy"]
_ACQUISITION_ACTION_TIMING_CONTRACT = {
    "schema_version": 2,
    "policy": "bounded-compatible-candidate-batch-whole-action-deadline-v2",
    "bounded_candidates": MAX_CANDIDATES,
    "global_live_page_cap": GLOBAL_LIVE_PAGE_CAP,
    "batch_selection": (
        "same-priority-same-stage-immutable-catalogue-order-compatible-pair-otherwise-singleton"
    ),
    "transactional_publication": (
        "active-batch-and-pending-attempts-published-before-parallel-work"
    ),
    "coordinator_merge": ("deterministic-immutable-catalogue-order-after-all-workers-return"),
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
    "direct_public_acquisition_run": ("forbidden-without-validated-watcher-scope-authority"),
    "successful_ledger_attempt_duration_limit_ms": (ACQUISITION_ACTION_TIMEOUT_SECONDS * 1_000),
    "whole_action_duration_evidence": (
        "externally-enforced-process-status-no-per-action-duration-receipt"
    ),
    "interruption_recovery": ("published-active-batch-attempts-become-interrupted-never-completed"),
}
_BASELINE_SCHEDULING_CONTRACT = {
    "schema_version": 2,
    "policy": "serial-nonoverlapping-stability-window-batch-reservations-v2",
    "maximum_candidates_per_batch": MAX_CANDIDATES,
    "global_live_page_cap": GLOBAL_LIVE_PAGE_CAP,
    "minimum_baseline_spacing_ms": PENDING_BASELINE_GUARD_MS,
    "window_start_reservation_ms": PENDING_BASELINE_GUARD_MS,
    "longest_probe_window_width_ms": 1_800_000,
    "acquisition_outer_configured_hard_cutoff_ms": (ACQUISITION_OUTER_HARD_SECONDS * 1_000),
    "status_configured_hard_cutoff_ms": (STATUS_RUNTIME_SECONDS + STATUS_CLEANUP_SECONDS) * 1_000,
    "scheduler_margin_ms": SERIAL_SCHEDULER_MARGIN_SECONDS * 1_000,
    "navigation_phase": "separate-bounded-action-before-baseline",
    "short_probe": "same-action-wait-until-t+30s-earliest",
    "outer_probes": "watcher-launches-acquisition-run-at-window-earliest",
    "within_batch_baseline": "one-equal-baseline-per-recorded-baseline-batch",
    "schedule_validation_unit": "baseline-batches-not-raw-candidate-timestamps",
    "unpaired_candidate_policy": "singleton-when-no-compatible-partner",
    "serial_action_start_offsets_ms": [0, 85_500_000, 258_300_000],
    "stability_window_earliest_offsets_ms": [25_000, 85_500_000, 258_300_000],
    "collision_scope": ("baseline-arming-and-t+24h-t+72h-action-starts-across-batches"),
    "strict_serial_zero_duration_projection": {
        "candidate_count": CANDIDATE_COUNT,
        "maximum_candidates_per_batch": MAX_CANDIDATES,
        "batch_count": 300,
        "algorithm": "greedy-earliest-safe-baseline-batches",
        "pairing_assumption": ("all-candidates-form-300-compatible-two-candidate-batches"),
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
_STATUS_DETAIL_KEYS = _STATUS_KEYS | {
    "valid",
    "runner_root",
    "gate",
    "authoritative",
    "gate_verification",
}
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
                lab_root / "config/class-study/v1" / f"{STUDY_ID}-candidates.json"
            ),
            acquisition_root=lab_root / "artifacts" / f"{STUDY_ID}-acquisition",
            stability_root=lab_root / "artifacts" / f"{STUDY_ID}-stability",
            workload_root=lab_root / "config/workloads",
            state_base=Path(
                os.path.abspath(
                    state_base or Path("/var/tmp") / f"qcsd-class-watch-lifecycle-{os.getuid()}"
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
    cohort_version: int
    catalogue_sha256: str
    provenance_sha256: str
    foundation_sha256: str
    pinned_cdp_sha256: str
    pinned_cdp_payload_sha256: str
    pinned_cdp_contract_sha256: str
    build_execution_sha256: str
    build_completion_path: str
    build_completion_sha256: str
    browser_egress_qualification: Mapping[str, Any]
    browser_egress_tree_sha256: str
    candidate_ids: frozenset[str]
    candidate_order: tuple[str, ...]
    source: Mapping[str, Any]


@dataclass(frozen=True)
class ReceiptSnapshot:
    value: Mapping[str, Any]
    sha256: str


@dataclass(frozen=True)
class BuildExecutionSnapshot:
    value: Mapping[str, Any]
    sha256: str
    size_bytes: int
    completion_sha256: str | None


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
        return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError) as error:
        raise WatchError("evidence contains a non-canonical JSON value") from error


def _matches_json_contract(value: Any, expected: Any) -> bool:
    """Compare JSON values without Python's ``bool``/``int`` equality alias."""

    try:
        return _canonical_json_bytes(value) == _canonical_json_bytes(expected)
    except WatchError:
        return False


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
                "browser_egress_qualification": dict(binding.browser_egress_qualification),
                "browser_egress_tree_sha256": binding.browser_egress_tree_sha256,
                "candidate_catalogue_sha256": binding.catalogue_sha256,
                "build_completion_path": binding.build_completion_path,
                "build_completion_sha256": binding.build_completion_sha256,
                "build_execution_sha256": binding.build_execution_sha256,
                "cohort_version": binding.cohort_version,
                "foundation_sha256": binding.foundation_sha256,
                "pinned_cdp_contract_sha256": binding.pinned_cdp_contract_sha256,
                "pinned_cdp_payload_sha256": binding.pinned_cdp_payload_sha256,
                "pinned_cdp_sha256": binding.pinned_cdp_sha256,
                "prepare_image": binding.prepare_image,
                "provenance_sha256": binding.provenance_sha256,
                "source": dict(binding.source),
                "source_binding_preimage_schema_version": (SOURCE_BINDING_PREIMAGE_SCHEMA_VERSION),
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


def _read_stable_file(
    path: Path,
    *,
    root: Path,
    label: str,
    maximum_bytes: int | None = None,
) -> tuple[bytes, str]:
    """Read and hash one immutable pathname identity exactly once."""

    if maximum_bytes is not None and (type(maximum_bytes) is not int or maximum_bytes < 0):
        raise WatchError(f"{label} maximum byte count is invalid")
    _require_regular_path(path, root=root, directory=False, label=label)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    root = Path(os.path.abspath(root))
    path = Path(os.path.abspath(path))
    relative = path.relative_to(root)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )

    def file_identity(value: os.stat_result) -> tuple[int, ...]:
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

    def same_directory_entry(left: os.stat_result, right: os.stat_result) -> bool:
        return (
            stat.S_ISDIR(left.st_mode)
            and stat.S_ISDIR(right.st_mode)
            and left.st_dev == right.st_dev
            and left.st_ino == right.st_ino
            and left.st_uid == right.st_uid
            and left.st_gid == right.st_gid
            and stat.S_IMODE(left.st_mode) == stat.S_IMODE(right.st_mode)
        )

    directory_descriptors: list[int] = []
    directory_links: list[tuple[int, str, int]] = []
    descriptor: int | None = None
    try:
        root_descriptor = os.open(root, directory_flags)
        directory_descriptors.append(root_descriptor)
        for component in relative.parts[:-1]:
            parent_descriptor = directory_descriptors[-1]
            child_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            child_stat = os.fstat(child_descriptor)
            if not stat.S_ISDIR(child_stat.st_mode):
                os.close(child_descriptor)
                raise WatchError(f"{label} path contains a non-directory component")
            directory_descriptors.append(child_descriptor)
            directory_links.append((parent_descriptor, component, child_descriptor))
        directory_descriptor = directory_descriptors[-1]
        filename = relative.parts[-1]
        descriptor = os.open(filename, flags, dir_fd=directory_descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise WatchError(f"{label} is not a single regular file")
        if maximum_bytes is not None and before.st_size > maximum_bytes:
            raise WatchError(f"{label} exceeds its maximum byte count")
        chunks: list[bytes] = []
        total = 0
        while True:
            read_size = 1024 * 1024
            if maximum_bytes is not None:
                read_size = min(read_size, maximum_bytes - total + 1)
            chunk = os.read(descriptor, read_size)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if maximum_bytes is not None and total > maximum_bytes:
                raise WatchError(f"{label} exceeds its maximum byte count")
        after = os.fstat(descriptor)
        current = os.stat(
            filename,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        root_after = os.fstat(root_descriptor)
        root_path_after = os.stat(root, follow_symlinks=False)
        directory_path_stable = same_directory_entry(root_after, root_path_after) and all(
            same_directory_entry(
                os.fstat(child_descriptor),
                os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                ),
            )
            for parent_descriptor, component, child_descriptor in directory_links
        )
    except OSError as error:
        raise WatchError(f"cannot safely read {label}: {path}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory_descriptor in reversed(directory_descriptors):
            os.close(directory_descriptor)

    if (
        not directory_path_stable
        or file_identity(before) != file_identity(after)
        or file_identity(after) != file_identity(current)
    ):
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
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != SCHEMA_VERSION
        or value["receipt_type"] != receipt_type
    ):
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


def _container_binding_directory(value: str, *, paths: WatchPaths, label: str) -> Path:
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
        directory=True,
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


def _validate_clean_source(value: Any, *, image: str, label: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != _SOURCE_KEYS
        or value.get("image_digest") != image
        or _IMAGE_RE.fullmatch(str(image)) is None
        or not isinstance(value.get("lab_commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", value["lab_commit"]) is None
        or value.get("lab_dirty") is not False
        or value.get("lab_patch_sha256") != EMPTY_SHA256
        or not isinstance(value.get("neqo_commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", value["neqo_commit"]) is None
        or value.get("neqo_pinned_commit") != value.get("neqo_commit")
        or value.get("neqo_dirty") is not False
        or value.get("neqo_patch_sha256") != EMPTY_SHA256
    ):
        raise WatchError(f"{label} does not bind one exact clean image source")


def _evidence_timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise WatchError(f"{label} timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise WatchError(f"{label} timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise WatchError(f"{label} timestamp is not timezone-aware")
    return parsed.astimezone(UTC)


def _validate_build_inputs(value: Any, *, label: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != _BUILD_INPUT_KEYS
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("artifact_type") != "qcsd-study-build-inputs"
        or value.get("rust_base_image") != BUILD_RUST_BASE_IMAGE
        or value.get("debian_base_image") != BUILD_DEBIAN_BASE_IMAGE
        or not isinstance(value.get("uv_lock_sha256"), str)
        or _SHA256_RE.fullmatch(value["uv_lock_sha256"]) is None
        or not isinstance(value.get("cargo_lock_sha256"), str)
        or _SHA256_RE.fullmatch(value["cargo_lock_sha256"]) is None
    ):
        raise WatchError(f"{label} are invalid")
    return dict(value)


def _validate_build_role_provenance(
    value: Any,
    *,
    image_ids: Mapping[str, str],
    source: Mapping[str, Any],
    build_inputs: Mapping[str, Any],
) -> None:
    targets = ("collection", "prepare", "reference")
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "sources", "build_inputs"}
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or not isinstance(value.get("sources"), dict)
        or set(value["sources"]) != set(targets)
        or not isinstance(value.get("build_inputs"), dict)
        or set(value["build_inputs"]) != set(targets)
    ):
        raise WatchError("foundation no-cache build role provenance is invalid")
    sources = value["sources"]
    for target in targets:
        _validate_clean_source(
            sources[target],
            image=image_ids[target],
            label=f"foundation no-cache build {target} role provenance",
        )
    source_identities = []
    for target in targets:
        identity = dict(sources[target])
        identity.pop("image_digest")
        source_identities.append(identity)
    if any(identity != source_identities[0] for identity in source_identities[1:]) or sources[
        "collection"
    ] != dict(source):
        raise WatchError("foundation no-cache build image roles used different source snapshots")
    collection_inputs = _validate_build_inputs(
        value["build_inputs"]["collection"],
        label="foundation no-cache build collection role inputs",
    )
    prepare_inputs = _validate_build_inputs(
        value["build_inputs"]["prepare"],
        label="foundation no-cache build prepare role inputs",
    )
    if (
        value["build_inputs"]["reference"] is not None
        or collection_inputs != prepare_inputs
        or collection_inputs != dict(build_inputs)
    ):
        raise WatchError("foundation no-cache build image roles used different inputs")


def _validate_build_storage_observation(
    value: Any,
    *,
    boundary: str,
    probe_sha256: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _BUILD_STORAGE_OBSERVATION_KEYS:
        raise WatchError("foundation no-cache build storage observation schema is invalid")
    data_vhd_path = value["data_vhd_path"]
    path_parts = data_vhd_path.split("\\") if isinstance(data_vhd_path, str) else []
    total_bytes = value["total_bytes"]
    available_bytes = value["available_bytes"]
    file_length = value["data_vhd_file_length_bytes"]
    integers = (total_bytes, available_bytes, file_length)
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["probe"] != BUILD_HOST_STORAGE_PROBE
        or not isinstance(value["probe_sha256"], str)
        or _SHA256_RE.fullmatch(value["probe_sha256"]) is None
        or value["probe_sha256"] != probe_sha256
        or value["boundary"] != boundary
        or value["location_source"] not in BUILD_HOST_STORAGE_LOCATION_SOURCES
        or not isinstance(data_vhd_path, str)
        or _WINDOWS_VHD_RE.fullmatch(data_vhd_path) is None
        or any(part in {"", ".", ".."} for part in path_parts[1:])
        or not isinstance(value["backing_volume_unique_id"], str)
        or _VOLUME_ID_RE.fullmatch(value["backing_volume_unique_id"]) is None
        or (
            value["drive_letter"] is not None
            and (
                not isinstance(value["drive_letter"], str)
                or re.fullmatch(r"[A-Z]", value["drive_letter"]) is None
                or value["drive_letter"] != data_vhd_path[0].upper()
            )
        )
        or not isinstance(value["file_system"], str)
        or not value["file_system"]
        or value["health_status"] != "Healthy"
        or value["operational_status"] != ["OK"]
        or any(not isinstance(item, int) or isinstance(item, bool) for item in integers)
        or file_length <= 0
        or total_bytes <= 0
        or not 0 <= available_bytes <= total_bytes
    ):
        raise WatchError("foundation no-cache build storage observation is invalid")
    _evidence_timestamp(value["observed_at"], label="foundation no-cache build storage observation")
    if available_bytes < BUILD_WSL_HOST_MIN_AVAILABLE_BYTES:
        raise WatchError(
            "foundation no-cache build storage observation falls below the 64 GiB minimum"
        )
    return dict(value)


def _validate_build_storage_preflight(value: Any, *, probe_sha256: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != _BUILD_STORAGE_PREFLIGHT_KEYS
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or not isinstance(value.get("applicable"), bool)
        or value.get("policy") != BUILD_HOST_STORAGE_POLICY
        or value.get("required_available_bytes") != BUILD_WSL_HOST_MIN_AVAILABLE_BYTES
        or value.get("passed") is not True
    ):
        raise WatchError("foundation no-cache build storage preflight schema is invalid")
    detection = value["platform_detection"]
    detection_keys = {
        "schema_version",
        "probe",
        "kernel_release",
        "proc_version",
        "wsl_interop_env_present",
        "wsl_distro_name_env_present",
        "run_wsl_directory_present",
    }
    if (
        not isinstance(detection, dict)
        or set(detection) != detection_keys
        or type(detection.get("schema_version")) is not int
        or detection["schema_version"] != 1
        or detection.get("probe") != "wsl-multi-signal-v1"
        or not isinstance(detection.get("kernel_release"), str)
        or not detection["kernel_release"].strip()
        or not isinstance(detection.get("proc_version"), str)
        or not detection["proc_version"].strip()
        or any(
            not isinstance(detection.get(key), bool)
            for key in (
                "wsl_interop_env_present",
                "wsl_distro_name_env_present",
                "run_wsl_directory_present",
            )
        )
    ):
        raise WatchError("foundation no-cache build platform detection is invalid")
    detected_wsl = any(
        (
            "microsoft" in detection["kernel_release"].lower(),
            "microsoft" in detection["proc_version"].lower(),
            detection["wsl_interop_env_present"],
            detection["wsl_distro_name_env_present"],
            detection["run_wsl_directory_present"],
        )
    )
    if not value["applicable"]:
        if (
            detected_wsl
            or value["platform"] != "other-host"
            or value["observations"] != []
            or value["minimum_available_bytes"] is not None
        ):
            raise WatchError("foundation no-cache build non-WSL preflight is invalid")
        return dict(value)
    if (
        not detected_wsl
        or value["platform"] != "windows-wsl2"
        or not isinstance(value["observations"], list)
        or len(value["observations"]) != len(BUILD_HOST_STORAGE_BOUNDARIES)
    ):
        raise WatchError("foundation no-cache build WSL preflight is invalid")
    observations = [
        _validate_build_storage_observation(
            observation,
            boundary=boundary,
            probe_sha256=probe_sha256,
        )
        for observation, boundary in zip(
            value["observations"], BUILD_HOST_STORAGE_BOUNDARIES, strict=True
        )
    ]
    stable_identities = {
        (
            observation["probe_sha256"],
            observation["location_source"],
            observation["data_vhd_path"],
            observation["backing_volume_unique_id"],
            observation["drive_letter"],
            observation["file_system"],
        )
        for observation in observations
    }
    observed_times = [
        _evidence_timestamp(
            observation["observed_at"],
            label="foundation no-cache build storage observation",
        )
        for observation in observations
    ]
    minimum_available_bytes = min(observation["available_bytes"] for observation in observations)
    if (
        len(stable_identities) != 1
        or observed_times != sorted(observed_times)
        or any(left >= right for left, right in pairwise(observed_times))
        or type(value["minimum_available_bytes"]) is not int
        or value["minimum_available_bytes"] != minimum_available_bytes
    ):
        raise WatchError("foundation no-cache build WSL preflight is inconsistent")
    return dict(value)


def _nonempty_buildx_string(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and all(ord(character) >= 0x20 and ord(character) != 0x7F for character in value)
    )


def _canonical_buildx_path(value: Any, *, label: str) -> PurePosixPath:
    if not _nonempty_buildx_string(value) or "\0" in value or value.startswith("//"):
        raise WatchError(f"{label} is not an absolute canonical path")
    path = PurePosixPath(value)
    if not path.is_absolute() or path.parent == path or str(path) != value or ".." in path.parts:
        raise WatchError(f"{label} is not an absolute canonical path")
    return path


def _validate_buildx_stat(value: Mapping[str, Any], *, label: str) -> dict[str, int]:
    if set(value) != _BUILDX_STAT_KEYS or any(type(value.get(key)) is not int for key in value):
        raise WatchError(f"{label} stat identity is invalid")
    record = {key: value[key] for key in _BUILDX_STAT_KEYS}
    if (
        record["dev"] < 0
        or record["inode"] <= 0
        or record["uid"] < 0
        or record["gid"] < 0
        or record["mode"] <= 0
        or record["mode"] > 0o177777
        or record["nlink"] <= 0
        or record["size"] < 0
        or record["mtime_ns"] < 0
        or record["ctime_ns"] < 0
    ):
        raise WatchError(f"{label} stat identity is invalid")
    return record


def _validate_buildx_identity(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _BUILDX_IDENTITY_KEYS:
        raise WatchError("foundation no-cache build buildx identity schema is invalid")
    if (
        value.get("selection_source") != _BUILDX_SELECTION_SOURCE
        or value.get("plugin_name") != "buildx"
        or not _nonempty_buildx_string(value.get("plugin_vendor"))
        or not _nonempty_buildx_string(value.get("metadata_schema_version"))
        or not _nonempty_buildx_string(value.get("short_description"))
        or not _nonempty_buildx_string(value.get("reported_plugin_version"))
    ):
        raise WatchError("foundation no-cache build Docker buildx metadata is invalid")
    reported_path = _canonical_buildx_path(
        value.get("reported_plugin_path"),
        label="foundation Docker-reported buildx plugin path",
    )
    if (
        reported_path.name != "docker-buildx"
        or reported_path.parent not in _BUILDX_PLUGIN_DIRECTORIES
    ):
        raise WatchError(
            "foundation Docker-reported buildx plugin path is outside fixed system directories"
        )
    plugin = value.get("plugin")
    resolved = value.get("resolved")
    if not isinstance(plugin, Mapping) or set(plugin) != _BUILDX_PLUGIN_KEYS:
        raise WatchError("foundation no-cache build buildx plugin identity is invalid")
    if not isinstance(resolved, Mapping) or set(resolved) != _BUILDX_RESOLVED_KEYS:
        raise WatchError("foundation no-cache build resolved buildx identity is invalid")
    plugin_path = _canonical_buildx_path(
        plugin.get("path"), label="foundation buildx plugin lexical path"
    )
    resolved_path = _canonical_buildx_path(
        resolved.get("path"), label="foundation resolved buildx target path"
    )
    if plugin_path != reported_path:
        raise WatchError("foundation no-cache build buildx path binding is invalid")
    plugin_stat = _validate_buildx_stat(
        {key: plugin[key] for key in _BUILDX_STAT_KEYS},
        label="foundation buildx plugin",
    )
    resolved_stat = _validate_buildx_stat(
        {key: resolved[key] for key in _BUILDX_STAT_KEYS},
        label="foundation resolved buildx target",
    )
    symlink_target = plugin.get("symlink_target")
    if symlink_target is None:
        if (
            not stat.S_ISREG(plugin_stat["mode"])
            or plugin_path != resolved_path
            or plugin_stat != resolved_stat
        ):
            raise WatchError(
                "foundation direct buildx plugin identity does not bind its resolved target"
            )
    else:
        if (
            not _nonempty_buildx_string(symlink_target)
            or "\0" in symlink_target
            or symlink_target.startswith("//")
            or not stat.S_ISLNK(plugin_stat["mode"])
        ):
            raise WatchError("foundation buildx plugin symlink identity is invalid")
        target_path = PurePosixPath(symlink_target)
        if str(target_path) != symlink_target:
            raise WatchError("foundation buildx plugin symlink target is not canonical")
        target_from_parent = (
            target_path if target_path.is_absolute() else plugin_path.parent / target_path
        )
        normalized_target = PurePosixPath(posixpath.normpath(str(target_from_parent)))
        if normalized_target != resolved_path or plugin_stat["size"] != len(
            os.fsencode(symlink_target)
        ):
            raise WatchError(
                "foundation buildx plugin symlink target differs from the resolved target"
            )
    if (
        plugin_stat["uid"] != 0
        or plugin_stat["gid"] != 0
        or plugin_stat["nlink"] != 1
        or not stat.S_ISREG(resolved_stat["mode"])
        or resolved_stat["uid"] != 0
        or resolved_stat["gid"] != 0
        or resolved_stat["nlink"] != 1
        or resolved_stat["size"] <= 0
        or not resolved_stat["mode"] & 0o111
        or resolved_stat["mode"] & (stat.S_ISUID | stat.S_ISGID | stat.S_IWGRP | stat.S_IWOTH)
        or not isinstance(resolved.get("sha256"), str)
        or _SHA256_RE.fullmatch(resolved["sha256"]) is None
    ):
        raise WatchError("foundation resolved buildx target is not a safe root-owned executable")
    version_output = value.get("version_output")
    match = (
        _BUILDX_VERSION_OUTPUT_RE.fullmatch(version_output)
        if isinstance(version_output, str)
        else None
    )
    if (
        match is None
        or value.get("version") != match.group("version")
        or value.get("commit") != match.group("commit")
        or value.get("reported_plugin_version") != match.group("version")
    ):
        raise WatchError("foundation no-cache build buildx version binding is invalid")
    return {
        "selection_source": value["selection_source"],
        "plugin_name": value["plugin_name"],
        "plugin_vendor": value["plugin_vendor"],
        "metadata_schema_version": value["metadata_schema_version"],
        "short_description": value["short_description"],
        "reported_plugin_version": value["reported_plugin_version"],
        "reported_plugin_path": value["reported_plugin_path"],
        "plugin": dict(plugin),
        "resolved": dict(resolved),
        "version_output": version_output,
        "version": value["version"],
        "commit": value["commit"],
    }


def _validate_buildx_provenance(
    value: Any,
    *,
    started: datetime,
    finished: datetime,
) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value) != _BUILDX_KEYS
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("policy") != _BUILDX_POLICY
        or value.get("passed") is not True
    ):
        raise WatchError("foundation no-cache build buildx provenance schema is invalid")
    identity = _validate_buildx_identity(value.get("identity"))
    identity_sha256 = _sha256_bytes(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )
    observations = value.get("observations")
    if not isinstance(observations, list) or len(observations) != len(_BUILDX_BOUNDARIES):
        raise WatchError("foundation no-cache build buildx observation inventory is invalid")
    observed_times: list[datetime] = []
    for observation, boundary in zip(observations, _BUILDX_BOUNDARIES, strict=True):
        if (
            not isinstance(observation, Mapping)
            or set(observation) != {"boundary", "observed_at", "identity_sha256"}
            or observation.get("boundary") != boundary
            or not isinstance(observation.get("observed_at"), str)
            or not isinstance(observation.get("identity_sha256"), str)
            or _SHA256_RE.fullmatch(observation["identity_sha256"]) is None
            or observation["identity_sha256"] != identity_sha256
        ):
            raise WatchError("foundation no-cache build buildx observation is invalid")
        observed_times.append(
            _evidence_timestamp(
                observation["observed_at"],
                label="foundation no-cache build buildx observation",
            )
        )
    first, second, third, fourth = observed_times
    if not started <= first < second < third < fourth <= finished:
        raise WatchError("foundation no-cache build buildx observations fall outside the build")


def _canonical_compact_json_bytes(value: Any, *, newline: bool = False) -> bytes:
    try:
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise WatchError("foundation no-cache build contains non-finite JSON") from error
    return raw + (b"\n" if newline else b"")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise WatchError("foundation no-cache build contains a duplicate JSON key")
        value[key] = item
    return value


def _invalid_json_constant(value: str) -> Any:
    raise WatchError(f"foundation no-cache build contains invalid JSON constant: {value}")


def _decode_canonical_base64(value: Any, *, label: str, maximum_bytes: int) -> bytes:
    if not isinstance(value, str):
        raise WatchError(f"{label} encoding is invalid")
    try:
        encoded = value.encode("ascii")
        raw = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise WatchError(f"{label} encoding is invalid") from error
    if not raw or len(raw) > maximum_bytes or base64.b64encode(raw) != encoded:
        raise WatchError(f"{label} encoding is invalid")
    return raw


def _git_object_oid(object_type: bytes, payload: bytes) -> str:
    digest = hashlib.sha1()
    digest.update(object_type + b" " + str(len(payload)).encode("ascii") + b"\0")
    digest.update(payload)
    return digest.hexdigest()


def _parse_git_tree(payload: bytes) -> dict[bytes, tuple[bytes, str]]:
    entries: dict[bytes, tuple[bytes, str]] = {}
    previous_sort_key: bytes | None = None
    offset = 0
    allowed_modes = {b"40000", b"100644", b"100755", b"120000", b"160000"}
    while offset < len(payload):
        space = payload.find(b" ", offset)
        nul = payload.find(b"\0", space + 1) if space >= 0 else -1
        oid_start = nul + 1
        oid_end = oid_start + 20
        if space <= offset or nul <= space + 1 or oid_end > len(payload):
            raise WatchError("foundation no-cache build cohort Git tree is malformed")
        mode = payload[offset:space]
        name = payload[space + 1 : nul]
        if (
            mode not in allowed_modes
            or name in {b"", b".", b".."}
            or b"/" in name
            or name in entries
        ):
            raise WatchError("foundation no-cache build cohort Git tree is malformed")
        sort_key = name + (b"/" if mode == b"40000" else b"")
        if previous_sort_key is not None and sort_key <= previous_sort_key:
            raise WatchError("foundation no-cache build cohort Git tree is malformed")
        previous_sort_key = sort_key
        entries[name] = (mode, payload[oid_start:oid_end].hex())
        offset = oid_end
    if not entries:
        raise WatchError("foundation no-cache build cohort Git tree is malformed")
    return entries


def _validate_cohort_git_proof(
    value: Any,
    *,
    lab_commit: str,
    ledger_blob_oid: str,
    neqo_gitlink: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _COHORT_GIT_PROOF_KEYS
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != _COHORT_GIT_PROOF_TYPE
    ):
        raise WatchError("foundation no-cache build cohort Git proof schema is invalid")
    commit_payload = _decode_canonical_base64(
        value["commit_payload_base64"],
        label="foundation no-cache build cohort Git commit",
        maximum_bytes=_COHORT_GIT_PROOF_COMMIT_MAX_BYTES,
    )
    encoded_trees = value["tree_payloads_base64"]
    if not isinstance(encoded_trees, list) or len(encoded_trees) != _COHORT_GIT_PROOF_TREE_COUNT:
        raise WatchError("foundation no-cache build cohort Git tree inventory is invalid")
    tree_payloads = [
        _decode_canonical_base64(
            encoded,
            label="foundation no-cache build cohort Git tree",
            maximum_bytes=_COHORT_GIT_PROOF_TREE_MAX_BYTES,
        )
        for encoded in encoded_trees
    ]
    if _git_object_oid(b"commit", commit_payload) != lab_commit:
        raise WatchError("foundation no-cache build cohort Git commit binding is invalid")
    first_line, separator, _ = commit_payload.partition(b"\n")
    root_match = re.fullmatch(rb"tree ([0-9a-f]{40})", first_line)
    if not separator or root_match is None:
        raise WatchError("foundation no-cache build cohort Git commit is malformed")
    expected_tree_oid = root_match.group(1).decode("ascii")
    components = tuple(component.encode("ascii") for component in _COHORT_LEDGER_PATH.split("/"))
    for index, (component, tree_payload) in enumerate(zip(components, tree_payloads, strict=True)):
        if _git_object_oid(b"tree", tree_payload) != expected_tree_oid:
            raise WatchError("foundation no-cache build cohort Git tree binding is invalid")
        entries = _parse_git_tree(tree_payload)
        if index == 0 and entries.get(b"neqo-qcsd") != (b"160000", neqo_gitlink):
            raise WatchError("foundation no-cache build cohort Git gitlink binding is invalid")
        entry = entries.get(component)
        expected_mode = b"100644" if index == len(components) - 1 else b"40000"
        if entry is None or entry[0] != expected_mode:
            raise WatchError("foundation no-cache build cohort Git path binding is invalid")
        expected_tree_oid = entry[1]
    if expected_tree_oid != ledger_blob_oid:
        raise WatchError("foundation no-cache build cohort Git ledger binding is invalid")
    return {
        "schema_version": 1,
        "artifact_type": _COHORT_GIT_PROOF_TYPE,
        "commit_payload_base64": value["commit_payload_base64"],
        "tree_payloads_base64": list(encoded_trees),
    }


def _validate_cohort_stat(
    value: Any,
    *,
    keys: set[str],
    label: str,
    required_mode: int | None = None,
    required_nlink: int | None = None,
    required_size: int | None = None,
) -> dict[str, int]:
    if (
        not isinstance(value, Mapping)
        or set(value) != keys
        or any(type(value[key]) is not int for key in keys)
        or value["dev"] <= 0
        or value["inode"] <= 0
        or value["uid"] < 0
        or value["gid"] < 0
        or not 0 <= value["mode"] <= 0o7777
        or value["nlink"] < 1
        or ("size" in keys and value["size"] < 0)
        or ("mtime_ns" in keys and value["mtime_ns"] < 0)
        or ("ctime_ns" in keys and value["ctime_ns"] < 0)
        or (required_mode is not None and value["mode"] != required_mode)
        or (required_nlink is not None and value["nlink"] != required_nlink)
        or (required_size is not None and value.get("size") != required_size)
    ):
        raise WatchError(f"{label} stat binding is invalid")
    return {key: value[key] for key in keys}


def _validate_cohort_allocation(
    value: Any,
    *,
    cohort_version: int,
    source: Mapping[str, Any],
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _COHORT_ALLOCATION_KEYS
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != _COHORT_ALLOCATION_TYPE
        or value.get("policy") != _COHORT_ALLOCATION_POLICY
        or value.get("ledger_path") != _COHORT_LEDGER_PATH
    ):
        raise WatchError("foundation no-cache build cohort allocation schema is invalid")
    ledger_raw = _decode_canonical_base64(
        value["ledger_payload_base64"],
        label="foundation no-cache build cohort ledger",
        maximum_bytes=_COHORT_LEDGER_MAX_BYTES,
    )
    if (
        not isinstance(value.get("ledger_sha256"), str)
        or _SHA256_RE.fullmatch(value["ledger_sha256"]) is None
        or _sha256_bytes(ledger_raw) != value["ledger_sha256"]
    ):
        raise WatchError("foundation no-cache build cohort ledger SHA-256 is invalid")
    if value.get("git_object_format") != "sha1":
        raise WatchError("foundation no-cache build cohort Git object format is invalid")
    if (
        not isinstance(value.get("ledger_git_blob_oid"), str)
        or _COMMIT_RE.fullmatch(value["ledger_git_blob_oid"]) is None
        or _git_object_oid(b"blob", ledger_raw) != value["ledger_git_blob_oid"]
    ):
        raise WatchError("foundation no-cache build cohort Git blob binding is invalid")
    try:
        ledger = json.loads(
            ledger_raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_invalid_json_constant,
        )
    except (UnicodeError, ValueError) as error:
        raise WatchError("foundation no-cache build cohort ledger is invalid JSON") from error
    if (
        not isinstance(ledger, Mapping)
        or set(ledger) != {"schema_version", "artifact_type", "policy", "consumed_versions"}
        or type(ledger.get("schema_version")) is not int
        or ledger.get("schema_version") != 1
        or ledger.get("artifact_type") != _COHORT_LEDGER_TYPE
        or ledger.get("policy") != _COHORT_ALLOCATION_POLICY
    ):
        raise WatchError("foundation no-cache build cohort ledger schema is invalid")
    versions = ledger["consumed_versions"]
    if (
        not isinstance(versions, list)
        or not versions
        or any(type(version) is not int for version in versions)
        or versions != list(range(1, len(versions) + 1))
    ):
        raise WatchError("foundation no-cache build cohort ledger is not a dense prefix")
    if (
        type(value.get("last_consumed_version")) is not int
        or value["last_consumed_version"] != versions[-1]
        or type(value.get("allocated_version")) is not int
        or value["allocated_version"] <= value["last_consumed_version"]
        or value["allocated_version"] != cohort_version
    ):
        raise WatchError("foundation no-cache build cohort allocation version binding is invalid")
    commits = (value.get("lab_commit"), value.get("neqo_commit"), value.get("neqo_gitlink"))
    if (
        any(
            not isinstance(commit, str) or _COMMIT_RE.fullmatch(commit) is None
            for commit in commits
        )
        or value["lab_commit"] != source.get("lab_commit")
        or value["neqo_commit"] != source.get("neqo_commit")
        or value["neqo_gitlink"] != source.get("neqo_commit")
    ):
        raise WatchError("foundation no-cache build cohort allocation source binding is invalid")
    proof = _validate_cohort_git_proof(
        value["lab_commit_ledger_proof"],
        lab_commit=value["lab_commit"],
        ledger_blob_oid=value["ledger_git_blob_oid"],
        neqo_gitlink=value["neqo_gitlink"],
    )
    projected = dict(value)
    projected["lab_commit_ledger_proof"] = proof
    return projected


def _validate_embedded_cohort_authority(
    value: Any,
    *,
    allocation: Mapping[str, Any],
    ledger_size: int,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _COHORT_AUTHORITY_KEYS
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != _COHORT_AUTHORITY_TYPE
        or not isinstance(value.get("receipt"), Mapping)
        or dict(value["receipt"]) != dict(allocation)
    ):
        raise WatchError("foundation no-cache build cohort claim authority is invalid")
    expected_git = {
        "object_format": allocation["git_object_format"],
        "lab_head": allocation["lab_commit"],
        "head_blob_oid": allocation["ledger_git_blob_oid"],
        "index_blob_oid": allocation["ledger_git_blob_oid"],
        "worktree_blob_oid": allocation["ledger_git_blob_oid"],
        "neqo_head": allocation["neqo_commit"],
        "head_gitlink": allocation["neqo_gitlink"],
        "index_gitlink": allocation["neqo_gitlink"],
    }
    git = value.get("git")
    if (
        not isinstance(git, Mapping)
        or set(git) != _COHORT_AUTHORITY_GIT_KEYS
        or dict(git) != expected_git
    ):
        raise WatchError("foundation no-cache build cohort claim Git authority is invalid")
    filesystem = value.get("filesystem")
    if (
        not isinstance(filesystem, Mapping)
        or set(filesystem) != _COHORT_AUTHORITY_FILESYSTEM_KEYS
        or not isinstance(filesystem.get("directories"), Mapping)
        or set(filesystem["directories"]) != _COHORT_AUTHORITY_DIRECTORY_NAMES
    ):
        raise WatchError("foundation no-cache build cohort filesystem authority is invalid")
    for identity in filesystem["directories"].values():
        validated = _validate_cohort_stat(
            identity,
            keys=_COHORT_FILE_STAT_KEYS,
            label="foundation no-cache build cohort authority directory",
        )
        if validated["mode"] & 0o022:
            raise WatchError("foundation no-cache build cohort filesystem authority is invalid")
    ledger_stat = _validate_cohort_stat(
        filesystem.get("ledger"),
        keys=_COHORT_FILE_STAT_KEYS,
        label="foundation no-cache build cohort authority ledger",
        required_nlink=1,
        required_size=ledger_size,
    )
    index_stat = _validate_cohort_stat(
        filesystem.get("git_index"),
        keys=_COHORT_FILE_STAT_KEYS,
        label="foundation no-cache build cohort authority Git index",
        required_nlink=1,
    )
    if ledger_stat["mode"] & 0o133 or index_stat["mode"] & 0o022 or index_stat["size"] < 1:
        raise WatchError("foundation no-cache build cohort filesystem authority is invalid")
    return json.loads(_canonical_compact_json_bytes(value))


def _validate_embedded_cohort_claim(
    raw: bytes,
    *,
    expected_version: int,
    genesis_allocation: Mapping[str, Any],
    expected_predecessor: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    try:
        claim = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_invalid_json_constant,
        )
    except (UnicodeError, ValueError) as error:
        raise WatchError("foundation no-cache build cohort claim is invalid JSON") from error
    if raw != _canonical_compact_json_bytes(claim, newline=True):
        raise WatchError("foundation no-cache build cohort claim bytes are not canonical")
    if (
        not isinstance(claim, Mapping)
        or set(claim) != _COHORT_CLAIM_KEYS
        or type(claim.get("schema_version")) is not int
        or claim.get("schema_version") != 1
        or claim.get("artifact_type") != _COHORT_CLAIM_TYPE
        or not isinstance(claim.get("payload"), Mapping)
    ):
        raise WatchError("foundation no-cache build cohort claim schema is invalid")
    payload = claim["payload"]
    if (
        set(payload) != _COHORT_CLAIM_PAYLOAD_KEYS
        or not isinstance(claim.get("payload_sha256"), str)
        or _SHA256_RE.fullmatch(claim["payload_sha256"]) is None
        or claim["payload_sha256"] != _sha256_bytes(_canonical_compact_json_bytes(payload))
        or payload.get("policy") != _COHORT_ALLOCATION_POLICY
        or payload.get("registry_path") != _COHORT_CLAIM_REGISTRY_PATH
        or type(payload.get("cohort_version")) is not int
        or payload.get("cohort_version") != expected_version
    ):
        raise WatchError("foundation no-cache build cohort claim payload is invalid")
    source = payload.get("source")
    authority = payload.get("authority")
    allocation_value = authority.get("receipt") if isinstance(authority, Mapping) else None
    if not isinstance(source, Mapping) or set(source) != _COHORT_CLAIM_SOURCE_KEYS:
        raise WatchError("foundation no-cache build cohort claim source binding is invalid")
    allocation = _validate_cohort_allocation(
        allocation_value,
        cohort_version=expected_version,
        source=source,
    )
    genesis_fields = (
        "policy",
        "ledger_path",
        "ledger_sha256",
        "ledger_payload_base64",
        "git_object_format",
        "ledger_git_blob_oid",
        "last_consumed_version",
    )
    if any(allocation[field] != genesis_allocation[field] for field in genesis_fields):
        raise WatchError("foundation no-cache build cohort claim genesis binding is invalid")
    ledger_raw = base64.b64decode(allocation["ledger_payload_base64"], validate=True)
    validated_authority = _validate_embedded_cohort_authority(
        authority,
        allocation=allocation,
        ledger_size=len(ledger_raw),
    )
    authority_sha256 = _sha256_bytes(_canonical_compact_json_bytes(validated_authority))
    if payload.get("authority_sha256") != authority_sha256:
        raise WatchError("foundation no-cache build cohort claim authority digest is invalid")
    if dict(source) != {
        "lab_commit": allocation["lab_commit"],
        "neqo_commit": allocation["neqo_commit"],
        "neqo_gitlink": allocation["neqo_gitlink"],
    }:
        raise WatchError("foundation no-cache build cohort claim source binding is invalid")
    expected_ledger = {
        "path": allocation["ledger_path"],
        "sha256": allocation["ledger_sha256"],
        "git_object_format": allocation["git_object_format"],
        "git_blob_oid": allocation["ledger_git_blob_oid"],
        "payload_base64": allocation["ledger_payload_base64"],
        "last_consumed_version": allocation["last_consumed_version"],
    }
    if (
        not isinstance(payload.get("ledger"), Mapping)
        or set(payload["ledger"]) != _COHORT_CLAIM_LEDGER_KEYS
        or dict(payload["ledger"]) != expected_ledger
    ):
        raise WatchError("foundation no-cache build cohort claim ledger binding is invalid")
    predecessor = payload.get("predecessor")
    if not isinstance(predecessor, Mapping) or set(predecessor) != _COHORT_CLAIM_PREDECESSOR_KEYS:
        raise WatchError("foundation no-cache build cohort claim predecessor is invalid")
    if expected_predecessor is not None:
        if dict(predecessor) != dict(expected_predecessor):
            raise WatchError("foundation no-cache build cohort claim predecessor is invalid")
    else:
        last_consumed = allocation["last_consumed_version"]
        if expected_version == last_consumed + 1:
            expected = {
                "kind": "genesis-ledger",
                "cohort_version": last_consumed,
                "sha256": allocation["ledger_sha256"],
            }
            if dict(predecessor) != expected:
                raise WatchError("foundation no-cache build cohort claim predecessor is invalid")
        elif (
            predecessor.get("kind") != "cohort-claim"
            or type(predecessor.get("cohort_version")) is not int
            or predecessor.get("cohort_version") != expected_version - 1
            or not isinstance(predecessor.get("sha256"), str)
            or _SHA256_RE.fullmatch(predecessor["sha256"]) is None
        ):
            raise WatchError("foundation no-cache build cohort claim predecessor is invalid")
    return json.loads(_canonical_compact_json_bytes(claim)), allocation, authority_sha256


def _validate_cohort_claim_snapshot(
    value: Any,
    *,
    allocation: Mapping[str, Any],
    cohort_version: int,
) -> tuple[dict[str, Any], str, str, str]:
    if not isinstance(value, Mapping) or set(value) != _COHORT_CLAIM_SNAPSHOT_KEYS:
        raise WatchError("foundation no-cache build cohort claim snapshot schema is invalid")
    digest_payload = dict(value)
    claimed_digest = digest_payload.pop("payload_sha256")
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != _COHORT_CLAIM_SNAPSHOT_TYPE
        or value.get("policy") != _COHORT_ALLOCATION_POLICY
        or type(value.get("cohort_version")) is not int
        or value.get("cohort_version") != cohort_version
        or not isinstance(claimed_digest, str)
        or _SHA256_RE.fullmatch(claimed_digest) is None
        or claimed_digest != _sha256_bytes(_canonical_compact_json_bytes(digest_payload))
    ):
        raise WatchError("foundation no-cache build cohort claim snapshot digest is invalid")
    registry = value["registry"]
    claim_binding = value["claim"]
    head = value["registry_head_at_publication"]
    expected_path = f"{_COHORT_CLAIM_REGISTRY_PATH}/claim-v{cohort_version}.json"
    if (
        not isinstance(registry, Mapping)
        or set(registry) != _COHORT_SNAPSHOT_REGISTRY_KEYS
        or registry.get("path") != _COHORT_CLAIM_REGISTRY_PATH
        or not isinstance(claim_binding, Mapping)
        or set(claim_binding) != _COHORT_SNAPSHOT_CLAIM_KEYS
        or claim_binding.get("path") != expected_path
        or not isinstance(head, Mapping)
        or set(head) != _COHORT_CLAIM_CHAIN_HEAD_KEYS
        or type(head.get("cohort_version")) is not int
        or head.get("cohort_version") != cohort_version
        or head.get("sha256") != claim_binding.get("sha256")
    ):
        raise WatchError("foundation no-cache build cohort claim snapshot binding is invalid")
    _validate_cohort_stat(
        registry.get("stat"),
        keys=_COHORT_DIRECTORY_STAT_KEYS,
        label="foundation no-cache build cohort claim registry",
        required_mode=0o700,
    )
    claim_raw = _decode_canonical_base64(
        claim_binding["payload_base64"],
        label="foundation no-cache build cohort snapshot claim",
        maximum_bytes=_COHORT_CLAIM_MAX_BYTES,
    )
    claim_file_sha256 = claim_binding["sha256"]
    if (
        not isinstance(claim_file_sha256, str)
        or _SHA256_RE.fullmatch(claim_file_sha256) is None
        or _sha256_bytes(claim_raw) != claim_file_sha256
    ):
        raise WatchError("foundation no-cache build cohort claim file SHA-256 is invalid")
    _validate_cohort_stat(
        claim_binding.get("stat"),
        keys=_COHORT_FILE_STAT_KEYS,
        label="foundation no-cache build cohort claim file",
        required_mode=0o600,
        required_nlink=1,
        required_size=len(claim_raw),
    )
    _claim, embedded_allocation, authority_sha256 = _validate_embedded_cohort_claim(
        claim_raw,
        expected_version=cohort_version,
        genesis_allocation=allocation,
        expected_predecessor=None,
    )
    if dict(embedded_allocation) != dict(allocation):
        raise WatchError("foundation no-cache build cohort snapshot allocation is invalid")
    projected = json.loads(_canonical_compact_json_bytes(value))
    snapshot_sha256 = _sha256_bytes(_canonical_compact_json_bytes(projected))
    return projected, authority_sha256, snapshot_sha256, claim_file_sha256


def _validate_cohort_claim_chain(
    value: Any,
    *,
    allocation: Mapping[str, Any],
    cohort_version: int,
    current_snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _COHORT_CLAIM_CHAIN_KEYS:
        raise WatchError("foundation no-cache build cohort claim-chain schema is invalid")
    digest_payload = dict(value)
    claimed_digest = digest_payload.pop("payload_sha256")
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != _COHORT_CLAIM_CHAIN_TYPE
        or value.get("policy") != _COHORT_ALLOCATION_POLICY
        or not isinstance(claimed_digest, str)
        or _SHA256_RE.fullmatch(claimed_digest) is None
        or claimed_digest != _sha256_bytes(_canonical_compact_json_bytes(digest_payload))
    ):
        raise WatchError("foundation no-cache build cohort claim-chain digest is invalid")
    expected_genesis = {
        "ledger_path": allocation["ledger_path"],
        "ledger_sha256": allocation["ledger_sha256"],
        "last_consumed_version": allocation["last_consumed_version"],
    }
    genesis = value.get("genesis")
    if (
        not isinstance(genesis, Mapping)
        or set(genesis) != _COHORT_CLAIM_CHAIN_GENESIS_KEYS
        or dict(genesis) != expected_genesis
    ):
        raise WatchError("foundation no-cache build cohort claim-chain genesis is invalid")
    claims = value.get("claims")
    expected_count = cohort_version - allocation["last_consumed_version"]
    if (
        not isinstance(claims, list)
        or not claims
        or expected_count > _COHORT_CLAIM_CHAIN_MAX_ENTRIES
        or len(claims) != expected_count
    ):
        raise WatchError("foundation no-cache build cohort claim-chain inventory is invalid")
    predecessor = {
        "kind": "genesis-ledger",
        "cohort_version": allocation["last_consumed_version"],
        "sha256": allocation["ledger_sha256"],
    }
    total_decoded = 0
    projected_claims: list[dict[str, Any]] = []
    versions = range(allocation["last_consumed_version"] + 1, cohort_version + 1)
    for entry, expected_version in zip(claims, versions, strict=True):
        if (
            not isinstance(entry, Mapping)
            or set(entry) != _COHORT_CLAIM_CHAIN_ENTRY_KEYS
            or type(entry.get("cohort_version")) is not int
            or entry.get("cohort_version") != expected_version
            or not isinstance(entry.get("sha256"), str)
            or _SHA256_RE.fullmatch(entry["sha256"]) is None
        ):
            raise WatchError("foundation no-cache build cohort claim-chain entry is invalid")
        raw = _decode_canonical_base64(
            entry["payload_base64"],
            label="foundation no-cache build cohort claim-chain entry",
            maximum_bytes=_COHORT_CLAIM_MAX_BYTES,
        )
        total_decoded += len(raw)
        if (
            total_decoded > _COHORT_CLAIM_CHAIN_MAX_DECODED_BYTES
            or _sha256_bytes(raw) != entry["sha256"]
        ):
            raise WatchError("foundation no-cache build cohort claim-chain entry digest is invalid")
        _claim, embedded_allocation, _authority = _validate_embedded_cohort_claim(
            raw,
            expected_version=expected_version,
            genesis_allocation=allocation,
            expected_predecessor=predecessor,
        )
        if expected_version == cohort_version and dict(embedded_allocation) != dict(allocation):
            raise WatchError(
                "foundation no-cache build cohort claim-chain tail allocation is invalid"
            )
        projected_claims.append(dict(entry))
        predecessor = {
            "kind": "cohort-claim",
            "cohort_version": expected_version,
            "sha256": entry["sha256"],
        }
    expected_head = {"cohort_version": cohort_version, "sha256": projected_claims[-1]["sha256"]}
    head = value.get("head")
    snapshot_claim = current_snapshot.get("claim")
    if (
        not isinstance(head, Mapping)
        or set(head) != _COHORT_CLAIM_CHAIN_HEAD_KEYS
        or dict(head) != expected_head
        or not isinstance(snapshot_claim, Mapping)
        or snapshot_claim.get("sha256") != expected_head["sha256"]
        or snapshot_claim.get("payload_base64") != projected_claims[-1]["payload_base64"]
    ):
        raise WatchError("foundation no-cache build cohort claim-chain head binding is invalid")
    return {
        "schema_version": 1,
        "artifact_type": _COHORT_CLAIM_CHAIN_TYPE,
        "policy": _COHORT_ALLOCATION_POLICY,
        "genesis": dict(genesis),
        "claims": projected_claims,
        "head": dict(head),
        "payload_sha256": claimed_digest,
    }


def _validate_cohort_reproofs(
    value: Any,
    *,
    started: datetime,
    finished: datetime,
    authority_sha256: str,
    claim_snapshot_sha256: str,
    claim_file_sha256: str,
    buildx: Mapping[str, Any],
    host_storage_preflight: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(_COHORT_REPROOF_BOUNDARIES):
        raise WatchError("foundation no-cache build cohort reproof inventory is invalid")
    projected: list[dict[str, Any]] = []
    times: list[datetime] = []
    for row, boundary in zip(value, _COHORT_REPROOF_BOUNDARIES, strict=True):
        if (
            not isinstance(row, Mapping)
            or set(row) != _COHORT_REPROOF_KEYS
            or row.get("boundary") != boundary
            or not isinstance(row.get("observed_at"), str)
            or row.get("authority_sha256") != authority_sha256
            or row.get("claim_snapshot_sha256") != claim_snapshot_sha256
            or row.get("claim_file_sha256") != claim_file_sha256
        ):
            raise WatchError("foundation no-cache build cohort reproof is invalid")
        observed = _evidence_timestamp(row["observed_at"], label="cohort-authority reproof")
        if not started <= observed <= finished:
            raise WatchError("foundation no-cache build cohort reproof timing is invalid")
        times.append(observed)
        projected.append(dict(row))
    if any(left >= right for left, right in zip(times, times[1:])):
        raise WatchError("foundation no-cache build cohort reproof timing is invalid")
    buildx_times = [
        _evidence_timestamp(row["observed_at"], label="buildx observation")
        for row in buildx["observations"]
    ]
    if not (
        times[4]
        < buildx_times[0]
        < times[5]
        < buildx_times[1]
        < times[6]
        < buildx_times[2]
        < times[7]
        < buildx_times[3]
        < times[8]
    ):
        raise WatchError("foundation no-cache build cohort stage timeline is invalid")
    if host_storage_preflight["applicable"]:
        storage_times = [
            _evidence_timestamp(row["observed_at"], label="host-storage observation")
            for row in host_storage_preflight["observations"]
        ]
        if not (
            times[1] < storage_times[0] < times[2]
            and buildx_times[1] < storage_times[1] < times[6]
            and buildx_times[2] < storage_times[2] < times[7]
            and buildx_times[3] < storage_times[3] < times[8]
        ):
            raise WatchError("foundation no-cache build cohort storage timeline is invalid")
    if (finished - times[-1]).total_seconds() > _COHORT_FINAL_REPROOF_MAX_AGE_SECONDS:
        raise WatchError("foundation no-cache build final cohort reproof is not immediate")
    return projected


def _validate_build_execution_schema4_or_5(value: Any, *, paths: WatchPaths) -> dict[str, Any]:
    schema_version = value.get("schema_version") if isinstance(value, Mapping) else None
    expected_keys = _BUILD_EXECUTION_SCHEMA5_KEYS if schema_version == 5 else _BUILD_EXECUTION_KEYS
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or type(value.get("schema_version")) is not int
        or value["schema_version"] not in {4, 5}
        or value.get("artifact_type") != BUILD_EXECUTION_TYPE
        or type(value.get("cohort_version")) is not int
        or value["cohort_version"] <= 0
    ):
        raise WatchError("foundation no-cache build execution schema is invalid")
    payload = dict(value)
    claimed = payload.pop("payload_sha256")
    if (
        not isinstance(claimed, str)
        or _SHA256_RE.fullmatch(claimed) is None
        or claimed
        != _sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    ):
        raise WatchError("foundation no-cache build execution payload hash is invalid")
    started = _evidence_timestamp(value["started_at"], label="no-cache build start")
    finished = _evidence_timestamp(value["finished_at"], label="no-cache build finish")
    duration = value["duration_seconds"]
    if (
        finished < started
        or not isinstance(duration, (int, float))
        or isinstance(duration, bool)
        or not math.isfinite(duration)
        or duration <= 0
        or abs(float(duration) - (finished - started).total_seconds()) > 2.0
    ):
        raise WatchError("foundation no-cache build duration is invalid")

    docker = value["docker"]
    docker_keys = {
        "client_version",
        "server_version",
        "context",
        "endpoint",
        "server_name",
        "server_operating_system",
        "server_os_type",
        "server_architecture",
        "server_id",
    }
    if (
        not isinstance(docker, dict)
        or set(docker) != docker_keys
        or any(not isinstance(docker[key], str) or not docker[key] for key in docker)
    ):
        raise WatchError("foundation no-cache build Docker identity is invalid")
    if (
        docker["context"] not in {"default", "desktop-linux"}
        or docker["endpoint"]
        not in {
            "unix:///var/run/docker.sock",
            "npipe:////./pipe/dockerDesktopLinuxEngine",
        }
        or docker["server_os_type"] != "linux"
    ):
        raise WatchError("foundation no-cache build Docker endpoint is unsupported")
    _validate_buildx_provenance(
        value["buildx"],
        started=started,
        finished=finished,
    )

    targets = ("collection", "prepare", "reference")
    images = value["images"]
    if not isinstance(images, dict) or set(images) != set(targets):
        raise WatchError("foundation no-cache build image inventory is invalid")
    image_ids: dict[str, str] = {}
    for target in targets:
        record = images[target]
        if (
            not isinstance(record, dict)
            or set(record) != {"tag", "id", "repo_digests"}
            or record.get("tag") != BUILD_IMAGE_TAGS[target]
            or not isinstance(record.get("id"), str)
            or _IMAGE_RE.fullmatch(record["id"]) is None
            or not isinstance(record.get("repo_digests"), list)
            or any(
                not isinstance(digest, str) or _REPO_DIGEST_RE.fullmatch(digest) is None
                for digest in record["repo_digests"]
            )
        ):
            raise WatchError(f"foundation no-cache build {target} image binding is invalid")
        image_ids[target] = record["id"]
    if len(set(image_ids.values())) != len(image_ids):
        raise WatchError("foundation no-cache build image roles lack distinct immutable IDs")

    commands = value["commands"]
    if not isinstance(commands, list) or len(commands) != len(targets):
        raise WatchError("foundation no-cache build command inventory is incomplete")
    recorded_build_root: PurePosixPath | None = None
    for target, command in zip(targets, commands, strict=True):
        prefix = [
            "docker",
            "--host",
            docker["endpoint"],
            "build",
            "--pull",
            "--no-cache",
        ]
        argv = command.get("argv") if isinstance(command, dict) else None
        iidfile_value: str | None = None
        iidfile: PurePosixPath | None = None
        if isinstance(argv, list) and len(argv) >= len(prefix) + 2:
            iidfile_value = argv[len(prefix) + 1] if argv[len(prefix)] == "--iidfile" else None
            if isinstance(iidfile_value, str):
                iidfile = PurePosixPath(iidfile_value)
                prefix.extend(["--iidfile", iidfile_value])
        prefix.extend(["--target", target, "--tag", images[target]["tag"], "--file"])
        paths_valid = (
            isinstance(argv, list)
            and len(argv) == len(prefix) + 2
            and all(isinstance(argument, str) for argument in argv)
        )
        dockerfile = PurePosixPath(argv[-2]) if paths_valid else None
        build_root = PurePosixPath(argv[-1]) if paths_valid else None
        if (
            not isinstance(command, dict)
            or set(command) != {"target", "argv", "exit_code", "image_id"}
            or command.get("target") != target
            or not isinstance(argv, list)
            or argv[:-2] != prefix
            or dockerfile is None
            or build_root is None
            or not dockerfile.is_absolute()
            or not build_root.is_absolute()
            or argv[-2].startswith("//")
            or argv[-1].startswith("//")
            or str(dockerfile) != argv[-2]
            or str(build_root) != argv[-1]
            or ".." in dockerfile.parts
            or ".." in build_root.parts
            or dockerfile.name != "Dockerfile"
            or dockerfile.parent != build_root
            or build_root.parent == build_root
            or iidfile is None
            or not iidfile.is_absolute()
            or str(iidfile) != iidfile_value
            or str(iidfile).startswith("//")
            or ".." in iidfile.parts
            or iidfile.name != f"{target}.iid"
            or iidfile.parent.parent != build_root / "artifacts" / "buflo-study"
            or re.fullmatch(
                rf"[.]build-iids-v{value['cohort_version']}[.][A-Za-z0-9]{{6}}",
                iidfile.parent.name,
            )
            is None
            or (recorded_build_root is not None and build_root != recorded_build_root)
            or type(command.get("exit_code")) is not int
            or command["exit_code"] != 0
            or command.get("image_id") != image_ids[target]
        ):
            raise WatchError(
                "foundation no-cache build commands do not prove --pull --no-cache execution"
            )
        recorded_build_root = build_root
    expected_build_root = PurePosixPath(str(paths.lab_root.resolve()))
    if recorded_build_root != expected_build_root:
        raise WatchError(
            "foundation no-cache build command root differs from the canonical Lab checkout"
        )

    if value["cache_policy"] != {
        "pull": True,
        "no_cache": True,
        "scope": "Docker-layer-cache-disabled;declared-BuildKit-dependency-cache-mounts-only",
    }:
        raise WatchError("foundation no-cache build cache policy is invalid")
    source = value["source"]
    _validate_clean_source(
        source,
        image=image_ids["collection"],
        label="foundation no-cache build source",
    )
    build_inputs = _validate_build_inputs(
        value["build_inputs"], label="foundation no-cache build inputs"
    )
    checkout_files = {
        "dockerfile_sha256": (paths.lab_root / "Dockerfile", "Dockerfile"),
        "uv_lock_sha256": (paths.lab_root / "uv.lock", "uv.lock"),
        "cargo_lock_sha256": (
            paths.lab_root / "neqo-qcsd/Cargo.lock",
            "Neqo Cargo.lock",
        ),
    }
    checkout_sha256s: dict[str, str] = {}
    for key, (checkout_path, label) in checkout_files.items():
        _, checkout_sha256s[key] = _read_stable_file(
            checkout_path,
            root=paths.lab_root,
            label=f"foundation no-cache build {label}",
        )
    if (
        not isinstance(value["dockerfile_sha256"], str)
        or _SHA256_RE.fullmatch(value["dockerfile_sha256"]) is None
        or value["dockerfile_sha256"] != checkout_sha256s["dockerfile_sha256"]
        or build_inputs["uv_lock_sha256"] != checkout_sha256s["uv_lock_sha256"]
        or build_inputs["cargo_lock_sha256"] != checkout_sha256s["cargo_lock_sha256"]
    ):
        raise WatchError("foundation no-cache build checkout binding is stale")
    _validate_build_role_provenance(
        value["role_provenance"],
        image_ids=image_ids,
        source=source,
        build_inputs=build_inputs,
    )
    _, probe_sha256 = _read_stable_file(
        paths.lab_root / "tools/windows_docker_storage_probe.ps1",
        root=paths.lab_root,
        label="foundation no-cache build storage probe",
    )
    preflight = _validate_build_storage_preflight(
        value["host_storage_preflight"], probe_sha256=probe_sha256
    )
    if preflight["applicable"]:
        observation_times = [
            _evidence_timestamp(
                observation["observed_at"],
                label="foundation no-cache build storage observation",
            )
            for observation in preflight["observations"]
        ]
        if schema_version == 5:
            timing_is_valid = (
                started
                <= observation_times[0]
                < observation_times[1]
                < observation_times[2]
                < observation_times[3]
                <= finished
            )
        else:
            timing_is_valid = (
                observation_times[0]
                <= started
                < observation_times[1]
                < observation_times[2]
                < observation_times[3]
                <= finished
            )
        if not timing_is_valid:
            raise WatchError("foundation no-cache build storage timing is invalid")
        if "docker desktop" not in docker["server_operating_system"].lower():
            raise WatchError("foundation no-cache WSL build did not use Docker Desktop")

    validated: dict[str, Any] = {
        "schema_version": schema_version,
        "started_at": started,
        "finished_at": finished,
    }
    if schema_version == 5:
        allocation = _validate_cohort_allocation(
            value["cohort_allocation"],
            cohort_version=value["cohort_version"],
            source=source,
        )
        claim, authority_sha256, claim_snapshot_sha256, claim_file_sha256 = (
            _validate_cohort_claim_snapshot(
                value["cohort_claim"],
                allocation=allocation,
                cohort_version=value["cohort_version"],
            )
        )
        chain = _validate_cohort_claim_chain(
            value["cohort_claim_chain"],
            allocation=allocation,
            cohort_version=value["cohort_version"],
            current_snapshot=claim,
        )
        _validate_cohort_reproofs(
            value["cohort_authority_reproofs"],
            started=started,
            finished=finished,
            authority_sha256=authority_sha256,
            claim_snapshot_sha256=claim_snapshot_sha256,
            claim_file_sha256=claim_file_sha256,
            buildx=value["buildx"],
            host_storage_preflight=preflight,
        )
        validated.update(
            {
                "allocation_sha256": _sha256_bytes(_canonical_compact_json_bytes(allocation)),
                "authority_sha256": authority_sha256,
                "claim_snapshot_sha256": claim_snapshot_sha256,
                "claim_file_sha256": claim_file_sha256,
                "claim_chain_sha256": _sha256_bytes(_canonical_compact_json_bytes(chain)),
                "claim_chain_payload_sha256": chain["payload_sha256"],
            }
        )
    return validated


def _filesystem_stat_record(value: os.stat_result) -> dict[str, int]:
    return {
        "dev": value.st_dev,
        "inode": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": stat.S_IMODE(value.st_mode),
        "nlink": value.st_nlink,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _filesystem_stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _load_build_completion(
    path: Path,
    *,
    paths: WatchPaths,
) -> tuple[Mapping[str, Any], bytes, str, tuple[int, ...]]:
    try:
        before = os.stat(path, follow_symlinks=False)
        raw, sha256 = _read_stable_file(
            path,
            root=paths.lab_root,
            label="foundation no-cache build completion",
            maximum_bytes=BUILD_COMPLETION_MAX_BYTES,
        )
        after = os.stat(path, follow_symlinks=False)
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_invalid_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, OSError) as error:
        raise WatchError("foundation no-cache build completion is not valid JSON") from error
    if (
        _filesystem_stat_identity(before) != _filesystem_stat_identity(after)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise WatchError("foundation no-cache build completion identity is invalid")
    if not isinstance(value, Mapping) or raw != _canonical_compact_json_bytes(value, newline=True):
        raise WatchError("foundation no-cache build completion is not canonical")
    return value, raw, sha256, _filesystem_stat_identity(before)


def _parse_build_transaction_record(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("ascii")
    except UnicodeError as error:
        raise WatchError(
            "foundation no-cache build completion transaction record is not ASCII"
        ) from error
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        raise WatchError(
            "foundation no-cache build completion transaction record framing is invalid"
        )
    fields: dict[str, str] = {}
    order: list[str] = []
    for line in text[:-1].split("\n"):
        if not line or "=" not in line:
            raise WatchError(
                "foundation no-cache build completion transaction record framing is invalid"
            )
        key, item = line.split("=", 1)
        if key in fields:
            raise WatchError(
                "foundation no-cache build completion transaction record has duplicate fields"
            )
        fields[key] = item
        order.append(key)
    if tuple(order) != _BUILD_TRANSACTION_RECORD_FIELDS:
        raise WatchError(
            "foundation no-cache build completion transaction record inventory is invalid"
        )
    return fields


def _validate_build_completion_transaction(
    value: Any,
    *,
    receipt: Mapping[str, Any],
    cohort_version: int,
) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value) != _BUILD_COMPLETION_TRANSACTION_KEYS
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != _BUILD_TRANSACTION_RETIREMENT_TYPE
    ):
        raise WatchError("foundation no-cache build completion transaction is invalid")
    root = value.get("root")
    record = value.get("record")
    guardian = value.get("guardian")
    lifecycle = value.get("lifecycle_lock")
    cohort_lock = value.get("cohort_lock")
    operation_lock = value.get("operation_lock")
    if (
        not isinstance(root, Mapping)
        or set(root) != _BUILD_TRANSACTION_ROOT_KEYS
        or not isinstance(record, Mapping)
        or set(record) != _BUILD_TRANSACTION_RECORD_KEYS
        or not isinstance(guardian, Mapping)
        or set(guardian) != _BUILD_COMPLETION_GUARDIAN_KEYS
        or any(type(guardian[key]) is not int or guardian[key] <= 0 for key in guardian)
        or guardian["pid"] == guardian["qcsd_pid"]
        or not isinstance(lifecycle, Mapping)
        or set(lifecycle) != _BUILD_COMPLETION_LIFECYCLE_KEYS
        or not isinstance(cohort_lock, Mapping)
        or set(cohort_lock) != _BUILD_COMPLETION_COHORT_LOCK_KEYS
        or not isinstance(operation_lock, Mapping)
        or set(operation_lock) != _BUILD_COMPLETION_OPERATION_LOCK_KEYS
    ):
        raise WatchError("foundation no-cache build completion transaction authority is invalid")
    if (
        any(
            type(lifecycle.get(key)) is not int or lifecycle[key] <= 0
            for key in ("device", "inode", "parent_device", "parent_inode")
        )
        or not isinstance(lifecycle.get("lease_nonce"), str)
        or _SHA256_RE.fullmatch(lifecycle["lease_nonce"]) is None
        or any(
            type(cohort_lock.get(key)) is not int or cohort_lock[key] <= 0
            for key in (
                "device",
                "inode",
                "parent_device",
                "parent_inode",
                "guardian_fd",
            )
        )
        or any(
            type(operation_lock.get(key)) is not int or operation_lock[key] <= 0
            for key in ("device", "inode", "parent_device", "parent_inode")
        )
    ):
        raise WatchError(
            "foundation no-cache build completion transaction lock identity is invalid"
        )
    lock_paths: list[Path] = []
    for binding in (lifecycle, cohort_lock, operation_lock):
        raw_path = binding.get("path")
        if not isinstance(raw_path, str):
            raise WatchError(
                "foundation no-cache build completion transaction lock path is invalid"
            )
        candidate = Path(raw_path)
        if not candidate.is_absolute() or Path(os.path.normpath(candidate)) != candidate:
            raise WatchError(
                "foundation no-cache build completion transaction lock path is invalid"
            )
        lock_paths.append(candidate)
    lifecycle_path, cohort_path, operation_path = lock_paths
    if (
        not lifecycle_path.name.endswith(".lock")
        or cohort_path.name != ".allocation.lock"
        or operation_path.name != ".allocation-operation.lock"
        or cohort_path.parent != operation_path.parent
        or cohort_lock["parent_device"] != operation_lock["parent_device"]
        or cohort_lock["parent_inode"] != operation_lock["parent_inode"]
        or len(
            {
                (lifecycle["device"], lifecycle["inode"]),
                (cohort_lock["device"], cohort_lock["inode"]),
                (operation_lock["device"], operation_lock["inode"]),
            }
        )
        != 3
    ):
        raise WatchError(
            "foundation no-cache build completion transaction lock relationship is invalid"
        )

    commands = receipt.get("commands")
    if (
        not isinstance(commands, list)
        or not commands
        or not isinstance(commands[0], Mapping)
        or not isinstance(commands[0].get("argv"), list)
        or not commands[0]["argv"]
    ):
        raise WatchError(
            "foundation no-cache build completion transaction receipt commands are invalid"
        )
    build_root = Path(str(commands[0]["argv"][-1]))
    if not build_root.is_absolute() or Path(os.path.normpath(build_root)) != build_root:
        raise WatchError(
            "foundation no-cache build completion transaction checkout path is invalid"
        )
    transaction_base = Path(str(lifecycle_path)[: -len(".lock")])
    transaction_root = Path(str(root.get("path", "")))
    expected_receipt = build_root / f"artifacts/buflo-study/build-execution-v{cohort_version}.json"
    if (
        not transaction_root.is_absolute()
        or Path(os.path.normpath(transaction_root)) != transaction_root
        or transaction_root.name != f"transaction.{lifecycle['lease_nonce'][:32]}"
        or transaction_root.parent != transaction_base
        or record.get("path") != str(transaction_root / "SUPERVISION")
    ):
        raise WatchError("foundation no-cache build completion transaction path binding is invalid")
    _validate_cohort_stat(
        root["stat"],
        keys=_COHORT_DIRECTORY_STAT_KEYS,
        label="foundation no-cache build completion transaction root",
        required_mode=0o700,
    )
    record_raw = _decode_canonical_base64(
        record.get("payload_base64"),
        label="foundation no-cache build completion transaction record",
        maximum_bytes=64 * 1024,
    )
    if (
        not isinstance(record.get("sha256"), str)
        or _SHA256_RE.fullmatch(record["sha256"]) is None
        or _sha256_bytes(record_raw) != record["sha256"]
    ):
        raise WatchError(
            "foundation no-cache build completion transaction record binding is invalid"
        )
    _validate_cohort_stat(
        record["stat"],
        keys=_COHORT_FILE_STAT_KEYS,
        label="foundation no-cache build completion transaction record",
        required_mode=0o600,
        required_nlink=1,
        required_size=len(record_raw),
    )
    fields = _parse_build_transaction_record(record_raw)
    if (
        fields["object"] != "docker-build-transaction"
        or fields["lifecycle_schema"] != "1"
        or fields["lifecycle_state"] != "request-authorised"
        or fields["lifecycle_root"] != str(transaction_root)
        or fields["lifecycle_token"] != lifecycle["lease_nonce"][:32]
        or not Path(fields["supervisor_source_path"]).is_absolute()
        or _SHA256_RE.fullmatch(fields["supervisor_source_sha256"]) is None
        or not fields["supervisor_source_device"].isdigit()
        or int(fields["supervisor_source_device"]) <= 0
        or not fields["supervisor_source_inode"].isdigit()
        or int(fields["supervisor_source_inode"]) <= 0
        or re.fullmatch(r"[A-Za-z0-9_.-]+", fields["docker_context"]) is None
        or fields["docker_host"]
        not in {
            "unix:///var/run/docker.sock",
            "npipe:////./pipe/dockerDesktopLinuxEngine",
        }
        or re.fullmatch(r"[A-Za-z0-9_.:-]+", fields["docker_server_id"]) is None
        or fields["docker_server_id"] != fields["docker_daemon_id"]
        or fields["docker_request_revalidation"] != "in-scope-immediately-before-mutation"
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            fields["host_boot_id"],
        )
        is None
        or fields["working_directory"] != str(build_root)
        or fields["cohort_version"] != str(cohort_version)
        or fields["receipt_path"] != str(expected_receipt)
        or fields["transaction_state"] != "uncommitted-static-tag-mutation"
    ):
        raise WatchError(
            "foundation no-cache build completion transaction record authority is invalid"
        )


def _validate_build_completion(
    value: Any,
    *,
    completion_path: Path,
    receipt_path: Path,
    receipt_raw: bytes,
    receipt_stat: Mapping[str, int],
    receipt: Mapping[str, Any],
    build_validation: Mapping[str, Any],
    paths: WatchPaths,
) -> None:
    cohort_version = receipt["cohort_version"]
    expected_completion_path = (
        paths.lab_root / f"artifacts/buflo-study/build-completion-v{cohort_version}.json"
    )
    expected_receipt_path = f"artifacts/buflo-study/build-execution-v{cohort_version}.json"
    if (
        completion_path != expected_completion_path
        or receipt_path != paths.lab_root / expected_receipt_path
    ):
        raise WatchError("foundation no-cache build completion path is not canonical")
    if not isinstance(value, Mapping) or set(value) != _BUILD_COMPLETION_KEYS:
        raise WatchError("foundation no-cache build completion schema is invalid")
    payload = dict(value)
    claimed_payload_sha256 = payload.pop("payload_sha256")
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != BUILD_COMPLETION_TYPE
        or type(value.get("cohort_version")) is not int
        or value.get("cohort_version") != cohort_version
        or not isinstance(claimed_payload_sha256, str)
        or _SHA256_RE.fullmatch(claimed_payload_sha256) is None
        or claimed_payload_sha256 != _sha256_bytes(_canonical_compact_json_bytes(payload))
    ):
        raise WatchError("foundation no-cache build completion payload is invalid")

    receipt_binding = value["receipt"]
    if (
        not isinstance(receipt_binding, Mapping)
        or set(receipt_binding) != _BUILD_COMPLETION_RECEIPT_KEYS
        or receipt_binding.get("path") != expected_receipt_path
        or type(receipt_binding.get("schema_version")) is not int
        or receipt_binding.get("schema_version") != 5
        or type(receipt_binding.get("cohort_version")) is not int
        or receipt_binding.get("cohort_version") != cohort_version
        or receipt_binding.get("payload_sha256") != receipt.get("payload_sha256")
        or receipt_binding.get("sha256") != _sha256_bytes(receipt_raw)
        or not isinstance(receipt_binding.get("stat"), Mapping)
        or dict(receipt_binding["stat"]) != dict(receipt_stat)
    ):
        raise WatchError("foundation no-cache build completion receipt binding is invalid")
    _validate_cohort_stat(
        receipt_binding["stat"],
        keys=_COHORT_FILE_STAT_KEYS,
        label="foundation no-cache build completion receipt",
        required_mode=0o600,
        required_nlink=1,
        required_size=len(receipt_raw),
    )

    source = value["source"]
    expected_source = {
        "lab_commit": receipt["source"]["lab_commit"],
        "neqo_commit": receipt["source"]["neqo_commit"],
        "neqo_gitlink": receipt["cohort_allocation"]["neqo_gitlink"],
    }
    if (
        not isinstance(source, Mapping)
        or set(source) != _BUILD_COMPLETION_SOURCE_KEYS
        or dict(source) != expected_source
    ):
        raise WatchError("foundation no-cache build completion source binding is invalid")

    expected_authority = {key: build_validation[key] for key in _BUILD_COMPLETION_AUTHORITY_KEYS}
    authority = value["cohort_authority"]
    if (
        not isinstance(authority, Mapping)
        or set(authority) != _BUILD_COMPLETION_AUTHORITY_KEYS
        or dict(authority) != expected_authority
    ):
        raise WatchError("foundation no-cache build completion cohort authority is invalid")

    _validate_build_completion_transaction(
        value["transaction"],
        receipt=receipt,
        cohort_version=cohort_version,
    )

    final_reproof = value["final_reproof"]
    expected_reproof = {
        "boundary": _BUILD_COMPLETION_REPROOF_BOUNDARY,
        "authority_sha256": build_validation["authority_sha256"],
        "claim_snapshot_sha256": build_validation["claim_snapshot_sha256"],
        "claim_file_sha256": build_validation["claim_file_sha256"],
        "claim_chain_sha256": build_validation["claim_chain_sha256"],
    }
    if (
        not isinstance(final_reproof, Mapping)
        or set(final_reproof) != _BUILD_COMPLETION_REPROOF_KEYS
        or any(final_reproof.get(key) != expected for key, expected in expected_reproof.items())
        or not isinstance(final_reproof.get("observed_at"), str)
    ):
        raise WatchError("foundation no-cache build completion final reproof is invalid")
    reproof_time = _evidence_timestamp(
        final_reproof["observed_at"],
        label="foundation no-cache build completion final reproof",
    )
    completed_at = _evidence_timestamp(
        value["completed_at"],
        label="foundation no-cache build completion",
    )
    if (
        reproof_time < build_validation["finished_at"]
        or completed_at < reproof_time
        or (completed_at - reproof_time).total_seconds() > _BUILD_COMPLETION_MAX_DELAY_SECONDS
    ):
        raise WatchError("foundation no-cache build completion timing is invalid")


def _load_build_execution(
    path: Path,
    *,
    paths: WatchPaths,
    require_current: bool = False,
) -> BuildExecutionSnapshot:
    try:
        before = os.stat(path, follow_symlinks=False)
        raw, sha256 = _read_stable_file(
            path,
            root=paths.lab_root,
            label="foundation no-cache build execution",
            maximum_bytes=BUILD_EXECUTION_MAX_BYTES,
        )
        after = os.stat(path, follow_symlinks=False)
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, OSError) as error:
        raise WatchError("foundation no-cache build execution is not valid JSON") from error
    if (
        _filesystem_stat_identity(before) != _filesystem_stat_identity(after)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
    ):
        raise WatchError("foundation no-cache build execution identity is invalid")
    if not isinstance(value, dict) or raw != _canonical_json_bytes(value):
        raise WatchError("foundation no-cache build execution is not canonical")
    validation = _validate_build_execution_schema4_or_5(value, paths=paths)
    completion_sha256: str | None = None
    if require_current:
        if value["schema_version"] != 5:
            raise WatchError(
                "foundation no-cache build execution is historical; "
                "current admission requires schema 5"
            )
        if stat.S_IMODE(before.st_mode) != 0o600:
            raise WatchError("foundation no-cache build execution mode is invalid")
        completion_path = path.with_name(f"build-completion-v{value['cohort_version']}.json")
        completion, completion_raw, completion_sha256, completion_identity = _load_build_completion(
            completion_path,
            paths=paths,
        )
        _validate_build_completion(
            completion,
            completion_path=completion_path,
            receipt_path=path,
            receipt_raw=raw,
            receipt_stat=_filesystem_stat_record(before),
            receipt=value,
            build_validation=validation,
            paths=paths,
        )
        current = os.stat(path, follow_symlinks=False)
        if _filesystem_stat_identity(before) != _filesystem_stat_identity(current):
            raise WatchError("foundation no-cache build execution changed during completion proof")
        (
            completion_after,
            completion_raw_after,
            completion_sha256_after,
            completion_identity_after,
        ) = _load_build_completion(completion_path, paths=paths)
        if (
            completion_after != completion
            or completion_raw_after != completion_raw
            or completion_sha256_after != completion_sha256
            or completion_identity_after != completion_identity
        ):
            raise WatchError("foundation no-cache build completion changed during proof")
    return BuildExecutionSnapshot(
        value=value,
        sha256=sha256,
        size_bytes=len(raw),
        completion_sha256=completion_sha256,
    )


def _validate_bootstrap_prearm_summary(value: Any, *, require_terminal: bool) -> None:
    fields = {
        "schema_version",
        "held_total",
        "released_total",
        "pending_total",
        "release_before_setup_envelopes_total",
        "by_worker_type",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WatchError("pinned CDP bootstrap-prearm summary fields are invalid")
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != _BOOTSTRAP_PREARM_SUMMARY_SCHEMA_VERSION
    ):
        raise WatchError("pinned CDP bootstrap-prearm summary schema is invalid")
    total_fields = (
        "held_total",
        "released_total",
        "pending_total",
        "release_before_setup_envelopes_total",
    )
    if any(type(value.get(field)) is not int or value[field] < 0 for field in total_fields):
        raise WatchError("pinned CDP bootstrap-prearm totals are invalid")

    worker_types = ("worker", "shared_worker")
    owner_target_types = ("page", "iframe", "worker", "shared_worker")
    by_worker_type = value.get("by_worker_type")
    if not isinstance(by_worker_type, Mapping) or set(by_worker_type) != set(worker_types):
        raise WatchError("pinned CDP bootstrap-prearm worker inventory is invalid")

    held_total = 0
    released_total = 0
    pending_total = 0
    released_after_total = 0
    for worker_type in worker_types:
        summary = by_worker_type.get(worker_type)
        count_fields = (
            "held",
            "released",
            "pending",
            "released_after_setup_envelopes",
        )
        if not isinstance(summary, Mapping) or set(summary) != {
            *count_fields,
            "owner_target_types",
        }:
            raise WatchError("pinned CDP bootstrap-prearm per-type fields are invalid")
        if any(type(summary.get(field)) is not int or summary[field] < 0 for field in count_fields):
            raise WatchError("pinned CDP bootstrap-prearm per-type counts are invalid")
        owner_counts = summary.get("owner_target_types")
        if (
            not isinstance(owner_counts, Mapping)
            or set(owner_counts) != set(owner_target_types)
            or any(
                type(owner_counts.get(target_type)) is not int or owner_counts[target_type] < 0
                for target_type in owner_target_types
            )
        ):
            raise WatchError("pinned CDP bootstrap-prearm owner counts are invalid")
        held = summary["held"]
        released = summary["released"]
        pending = summary["pending"]
        released_after = summary["released_after_setup_envelopes"]
        if (
            released > held
            or pending != held - released
            or released_after > released
            or sum(owner_counts.values()) != held
        ):
            raise WatchError("pinned CDP bootstrap-prearm counts are inconsistent")
        if worker_type == "worker" and any(
            (held, released, pending, released_after, *owner_counts.values())
        ):
            raise WatchError("dedicated workers cannot use the shared-worker prearm")
        if require_terminal and (pending or released_after != released):
            raise WatchError("pinned CDP bootstrap-prearm is not terminal")
        held_total += held
        released_total += released
        pending_total += pending
        released_after_total += released_after

    if (
        value["held_total"] != held_total
        or value["released_total"] != released_total
        or value["pending_total"] != pending_total
        or value["release_before_setup_envelopes_total"] != 0
        or (require_terminal and released_after_total != released_total)
    ):
        raise WatchError("pinned CDP bootstrap-prearm aggregate is inconsistent")


def _validate_pinned_target_activity(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "generation",
        "by_target_type",
    }:
        raise WatchError("pinned CDP target-activity fields are invalid")
    generation = value.get("generation")
    by_target_type = value.get("by_target_type")
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != _PINNED_CDP_TARGET_ACTIVITY_SCHEMA_VERSION
        or type(generation) is not int
        or generation < 0
        or not isinstance(by_target_type, dict)
        or set(by_target_type) != set(_PINNED_CDP_TARGET_ACTIVITY_TYPES)
    ):
        raise WatchError("pinned CDP target-activity aggregate is invalid")
    observed_total = 0
    for target_type in _PINNED_CDP_TARGET_ACTIVITY_TYPES:
        entry = by_target_type[target_type]
        if not isinstance(entry, dict) or set(entry) != {
            "total",
            "max_source_generation",
            "event_counts",
        }:
            raise WatchError("pinned CDP target-activity entry is invalid")
        total = entry.get("total")
        maximum = entry.get("max_source_generation")
        event_counts = entry.get("event_counts")
        if (
            type(total) is not int
            or total < 0
            or not isinstance(event_counts, dict)
            or set(event_counts) != set(_PINNED_CDP_TARGET_ACTIVITY_EVENTS)
            or any(
                type(event_counts.get(event)) is not int or event_counts[event] < 0
                for event in _PINNED_CDP_TARGET_ACTIVITY_EVENTS
            )
            or sum(event_counts.values()) != total
            or (total == 0 and maximum is not None)
            or (total > 0 and (type(maximum) is not int or maximum < 0))
        ):
            raise WatchError("pinned CDP target-activity aggregate is invalid")
        observed_total += total
    if observed_total != generation:
        raise WatchError("pinned CDP target-activity generation is inconsistent")
    if by_target_type["page"]["event_counts"]["target-attached"] != 0 or any(
        by_target_type[target_type]["event_counts"]["target-attached"] < 1
        for target_type in ("iframe", "shared_worker", "worker")
    ):
        raise WatchError("pinned CDP target-activity observation did not pass")


def _target_egress_api_count(target_type: str) -> int:
    return len(
        _PAGE_TARGET_EGRESS_APIS
        if target_type in {"page", "iframe"}
        else _WORKER_TARGET_EGRESS_APIS
    )


def _validate_egress_prearm_summary(value: Any) -> Mapping[str, Any]:
    fields = {
        "schema_version",
        "policy",
        "target_total",
        "installed_total",
        "pending_total",
        "popup_guard_required_total",
        "popup_guard_installed_total",
        "by_target_type",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WatchError("pinned CDP target egress-prearm fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != _EGRESS_PREARM_SUMMARY_SCHEMA_VERSION
        or value["policy"] != _NON_REPLAYABLE_EGRESS_POLICY
    ):
        raise WatchError("pinned CDP target egress-prearm identity is invalid")
    total_fields = (
        "target_total",
        "installed_total",
        "pending_total",
        "popup_guard_required_total",
        "popup_guard_installed_total",
    )
    if any(type(value[field]) is not int or value[field] < 0 for field in total_fields):
        raise WatchError("pinned CDP target egress-prearm totals are invalid")
    by_target_type = value["by_target_type"]
    target_types = {"page", "iframe", "worker", "shared_worker"}
    if not isinstance(by_target_type, Mapping) or set(by_target_type) != target_types:
        raise WatchError("pinned CDP target egress-prearm type inventory is invalid")
    target_total = installed_total = pending_total = 0
    for target_type in sorted(target_types):
        item = by_target_type[target_type]
        item_fields = {
            "target_count",
            "installed_count",
            "pending_count",
            "protected_api_observations",
            "unavailable_api_observations",
            "popup_guard_required_count",
            "popup_guard_installed_count",
        }
        if not isinstance(item, Mapping) or set(item) != item_fields:
            raise WatchError("pinned CDP target egress-prearm per-type fields are invalid")
        if any(type(item[field]) is not int or item[field] < 0 for field in item_fields):
            raise WatchError("pinned CDP target egress-prearm per-type counts are invalid")
        if (
            item["installed_count"] > item["target_count"]
            or item["pending_count"] != item["target_count"] - item["installed_count"]
            or item["protected_api_observations"] + item["unavailable_api_observations"]
            != item["installed_count"] * _target_egress_api_count(target_type)
            or item["popup_guard_required_count"]
            != (item["target_count"] if target_type in {"page", "iframe"} else 0)
            or item["popup_guard_installed_count"] > item["popup_guard_required_count"]
        ):
            raise WatchError("pinned CDP target egress-prearm per-type counts are inconsistent")
        target_total += item["target_count"]
        installed_total += item["installed_count"]
        pending_total += item["pending_count"]
    if (
        value["target_total"] != target_total
        or value["installed_total"] != installed_total
        or value["pending_total"] != pending_total
        or value["popup_guard_required_total"]
        != sum(by_target_type[item]["popup_guard_required_count"] for item in target_types)
        or value["popup_guard_installed_total"]
        != sum(by_target_type[item]["popup_guard_installed_count"] for item in target_types)
    ):
        raise WatchError("pinned CDP target egress-prearm aggregate is inconsistent")
    if (
        pending_total
        or installed_total != target_total
        or value["popup_guard_installed_total"] != value["popup_guard_required_total"]
    ):
        raise WatchError("pinned CDP target egress-prearm is not terminal")
    return value


def _validate_non_replayable_egress_summary(value: Any) -> None:
    fields = {
        "schema_version",
        "policy",
        "attempt_count",
        "protected_apis",
        "context_init_script_installed",
        "context_navigation_route_installed",
        "root_page_bound",
        "context_websocket_route_installed",
        "context_service_worker_listener_installed",
        "cdp_tripwires_are_pre_io",
        "packet_level_completeness_claimed",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WatchError("pinned CDP non-replayable egress fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != _NON_REPLAYABLE_EGRESS_SCHEMA_VERSION
        or value["policy"] != _NON_REPLAYABLE_EGRESS_POLICY
        or type(value["attempt_count"]) is not int
        or value["attempt_count"] != 0
        or value["context_init_script_installed"] is not True
        or value["context_navigation_route_installed"] is not True
        or value["root_page_bound"] is not True
        or value["context_websocket_route_installed"] is not True
        or value["context_service_worker_listener_installed"] is not True
        or value["cdp_tripwires_are_pre_io"] is not False
        or value["packet_level_completeness_claimed"] is not False
        or value["protected_apis"] != _TARGET_EGRESS_APIS
    ):
        raise WatchError("pinned CDP non-replayable egress identity is invalid")


def _validate_worker_webtransport_probe(value: Any) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"schema_version", "by_target_type"}
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != _PINNED_CDP_WORKER_WEBTRANSPORT_PROBE_SCHEMA_VERSION
    ):
        raise WatchError("pinned CDP worker WebTransport probe fields are invalid")
    by_target_type = value.get("by_target_type")
    if not isinstance(by_target_type, Mapping) or set(by_target_type) != {
        "shared_worker",
        "worker",
    }:
        raise WatchError("pinned CDP worker WebTransport target inventory is invalid")
    for target_type in ("shared_worker", "worker"):
        item = by_target_type.get(target_type)
        if not isinstance(item, Mapping) or set(item) != {"measurement", "guard_telemetry"}:
            raise WatchError("pinned CDP worker WebTransport target fields are invalid")
        measurement = item.get("measurement")
        guard = item.get("guard_telemetry")
        if (
            not isinstance(measurement, Mapping)
            or type(measurement.get("action_issued")) is not bool
            or type(measurement.get("action_succeeded")) is not bool
            or dict(measurement) != _PINNED_CDP_WORKER_WEBTRANSPORT_MEASUREMENT
            or not isinstance(guard, Mapping)
            or type(guard.get("notification_count")) is not int
            or dict(guard)
            != _PINNED_CDP_WORKER_WEBTRANSPORT_PROBE["by_target_type"][target_type][
                "guard_telemetry"
            ]
        ):
            raise WatchError("pinned CDP worker WebTransport action or telemetry did not pass")


def _validate_browser_egress_command_line(value: Any) -> None:
    fields = {
        "schema_version",
        "launch_profile",
        "required_switches",
        "observed_required_switches",
        "antagonistic_switches",
        "observed_antagonistic_switches",
        "required_disabled_feature_tokens",
        "observed_disabled_feature_tokens",
        "required_disabled_blink_feature_tokens",
        "observed_disabled_blink_feature_tokens",
        "required_enabled_feature_arguments",
        "observed_enabled_feature_arguments",
        "feature_switch_argument_counts",
        "complete_feature_policy_is_last",
        "subprocess_wrapper_argument",
        "required_switches_are_bare_and_unique",
        "host_resolver_switch_is_unique",
        "host_resolver_is_fail_closed",
        "host_resolver_policy",
        "no_pings_is_admission_boundary",
        "packet_level_completeness_claimed",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WatchError("pinned CDP browser egress command-line fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != _BROWSER_EGRESS_COMMAND_LINE_SCHEMA_VERSION
        or value["launch_profile"] != _BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE
        or value["required_switches"] != _BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES
        or value["observed_required_switches"] != _BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES
        or value["antagonistic_switches"] != _BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES
        or value["observed_antagonistic_switches"] != []
        or value["required_disabled_feature_tokens"]
        != _BROWSER_EGRESS_REQUIRED_DISABLED_FEATURE_TOKENS
        or value["observed_disabled_feature_tokens"]
        != _BROWSER_EGRESS_REQUIRED_DISABLED_FEATURE_TOKENS
        or value["required_disabled_blink_feature_tokens"]
        != _BROWSER_EGRESS_REQUIRED_DISABLED_BLINK_FEATURE_TOKENS
        or value["observed_disabled_blink_feature_tokens"]
        != _BROWSER_EGRESS_REQUIRED_DISABLED_BLINK_FEATURE_TOKENS
        or value["required_enabled_feature_arguments"]
        != _BROWSER_EGRESS_REQUIRED_ENABLED_FEATURE_ARGUMENTS
        or value["observed_enabled_feature_arguments"]
        != _BROWSER_EGRESS_REQUIRED_ENABLED_FEATURE_ARGUMENTS
        or value["feature_switch_argument_counts"]
        != {
            "disable_features": 2,
            "disable_blink_features": 1,
            "enable_features": 1,
            "enable_blink_features": 0,
        }
        or value["complete_feature_policy_is_last"] is not True
        or value["subprocess_wrapper_argument"] != _BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT
        or value["required_switches_are_bare_and_unique"] is not True
        or value["host_resolver_switch_is_unique"] is not True
        or value["host_resolver_is_fail_closed"] is not True
        or value["host_resolver_policy"] != _PINNED_CDP_RESOLVER_PROJECTION
        or value["no_pings_is_admission_boundary"] is not False
        or value["packet_level_completeness_claimed"] is not False
    ):
        raise WatchError("pinned CDP browser egress command-line projection is invalid")


def _validate_pinned_cdp_observation(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "playwright_version",
        "chromium_version",
        "chromium_executable",
        "playwright_driver",
        "isolation",
        "topology",
    }:
        raise WatchError("pinned CDP observation fields are invalid")
    if (
        value.get("playwright_version") != _PLAYWRIGHT_VERSION
        or value.get("chromium_version") != _CHROMIUM_VERSION
        or value.get("chromium_executable") != _CHROMIUM_EXECUTABLE
    ):
        raise WatchError("pinned CDP browser observation is invalid")
    driver = value.get("playwright_driver")
    if driver != _EXPECTED_PLAYWRIGHT_DRIVER_BINDING:
        raise WatchError("pinned CDP Playwright driver observation is invalid")
    isolation = value.get("isolation")
    credential_fields = (
        "real_uid",
        "effective_uid",
        "saved_uid",
        "filesystem_uid",
        "real_gid",
        "effective_gid",
        "saved_gid",
        "filesystem_gid",
        "expected_uid",
        "expected_gid",
    )
    capability_fields = (
        "inheritable_capabilities",
        "permitted_capabilities",
        "effective_capabilities",
        "bounding_capabilities",
        "ambient_capabilities",
    )
    if (
        not isinstance(isolation, dict)
        or set(isolation)
        != {
            *credential_fields,
            "supplementary_groups",
            *capability_fields,
            "no_new_privileges",
            "observed_interfaces",
        }
        or any(
            type(isolation.get(field)) is not int or isolation[field] < 1
            for field in credential_fields
        )
        or any(
            isolation[field] != isolation["expected_uid"]
            for field in ("real_uid", "effective_uid", "saved_uid", "filesystem_uid")
        )
        or any(
            isolation[field] != isolation["expected_gid"]
            for field in ("real_gid", "effective_gid", "saved_gid", "filesystem_gid")
        )
        or not isinstance(isolation.get("supplementary_groups"), list)
        or any(
            type(group) is not int or group < 1
            for group in isolation.get("supplementary_groups", [])
        )
        or isolation.get("supplementary_groups")
        != sorted(set(isolation.get("supplementary_groups", [])))
        or any(isolation.get(field) != "0000000000000000" for field in capability_fields)
        or isolation.get("no_new_privileges") is not True
        or isolation.get("observed_interfaces") != ["lo"]
    ):
        raise WatchError("pinned CDP isolation observation is invalid")
    topology = value.get("topology")
    topology_booleans = (
        "cross_site_iframe_request",
        "redirect_target_request",
        "dedicated_worker_network_request",
        "shared_worker_network_request",
        "dedicated_worker_fetch_paused_on_page",
        "shared_worker_fetch_paused_on_shared_worker",
        "router_closed",
        "browser_guard_closed",
        "ledger_closed",
        "extra_info_closed",
        "browser_closed",
        "server_thread_stopped",
    )
    if not isinstance(topology, dict) or set(topology) != {
        "observed_target_types",
        "event_count",
        "event_method_counts",
        "cross_site_iframe_request",
        "duplicate_request_occurrences",
        "redirect_target_request",
        "worker_network_target_types",
        "dedicated_worker_network_request",
        "shared_worker_network_request",
        "dedicated_worker_fetch_paused_on_page",
        "shared_worker_fetch_paused_on_shared_worker",
        "worker_response_consumption",
        "worker_webtransport_probe",
        "http_status_counts",
        "server_request_counts",
        "bootstrap_prearm_summary",
        "egress_prearm_summary",
        "non_replayable_egress_summary",
        "browser_egress_command_line",
        "browser_context_service_worker_count",
        "quiescent_target_activity",
        "router_closed",
        "browser_guard_closed",
        "ledger_closed",
        "extra_info_closed",
        "browser_closed",
        "server_thread_stopped",
    }:
        raise WatchError("pinned CDP topology fields are invalid")
    method_counts = topology.get("event_method_counts")
    if (
        not isinstance(method_counts, Mapping)
        or set(method_counts) != set(_PINNED_CDP_EVENT_METHODS)
        or any(
            type(method_counts.get(method)) is not int or method_counts[method] < 0
            for method in _PINNED_CDP_EVENT_METHODS
        )
        or sum(method_counts.values()) != topology.get("event_count")
        or method_counts["Network.loadingFailed"] != 0
        or method_counts["Network.requestServedFromCache"] != 0
    ):
        raise WatchError("pinned CDP event-method aggregate is invalid")
    prearm = topology.get("bootstrap_prearm_summary")
    _validate_bootstrap_prearm_summary(prearm, require_terminal=True)
    egress_prearm = _validate_egress_prearm_summary(topology.get("egress_prearm_summary"))
    _validate_non_replayable_egress_summary(topology.get("non_replayable_egress_summary"))
    _validate_worker_webtransport_probe(topology.get("worker_webtransport_probe"))
    _validate_browser_egress_command_line(topology.get("browser_egress_command_line"))
    _validate_pinned_target_activity(topology.get("quiescent_target_activity"))
    http_status_counts = topology.get("http_status_counts")
    server_request_counts = topology.get("server_request_counts")
    if (
        not isinstance(http_status_counts, Mapping)
        or any(
            not isinstance(statuses, Mapping)
            or any(type(count) is not int for count in statuses.values())
            for statuses in http_status_counts.values()
        )
        or not isinstance(server_request_counts, Mapping)
        or any(type(count) is not int for count in server_request_counts.values())
    ):
        raise WatchError("pinned CDP topology observation did not pass")
    if (
        topology.get("observed_target_types") != ["iframe", "page", "shared_worker", "worker"]
        or type(topology.get("event_count")) is not int
        or topology["event_count"] < sum(_PINNED_CDP_SERVER_REQUEST_COUNTS.values())
        or topology.get("duplicate_request_occurrences") != 2
        or topology.get("worker_network_target_types") != ["shared_worker", "worker"]
        or topology.get("worker_response_consumption") != _PINNED_CDP_WORKER_RESPONSE_CONSUMPTION
        or http_status_counts != _PINNED_CDP_HTTP_STATUS_COUNTS
        or server_request_counts != _PINNED_CDP_SERVER_REQUEST_COUNTS
        or prearm != _PINNED_CDP_BOOTSTRAP_PREARM_SUMMARY
        or egress_prearm["target_total"] < 4
        or egress_prearm["installed_total"] != egress_prearm["target_total"]
        or egress_prearm["by_target_type"]["page"]["installed_count"] != 1
        or any(
            egress_prearm["by_target_type"][target_type]["installed_count"] < 1
            for target_type in ("iframe", "shared_worker", "worker")
        )
        or type(topology.get("browser_context_service_worker_count")) is not int
        or topology["browser_context_service_worker_count"] != 0
        or any(topology.get(field) is not True for field in topology_booleans)
    ):
        raise WatchError("pinned CDP topology observation did not pass")


def _validate_browser_egress_qualification_binding(
    value: Any,
    *,
    paths: WatchPaths,
    cohort: int,
    build: Mapping[str, Any],
    build_binding: Mapping[str, Any],
    build_size_bytes: int,
    build_completion_sha256: str,
    prepare_image: str,
    foundation_recorded: datetime,
) -> dict[str, Any]:
    fields = {
        "root",
        "path",
        "sha256",
        "payload_sha256",
        "qualification_id",
        "cohort_version",
        "qualification_started_at",
        "qualification_finished_at",
        "recorded_at",
        "prepare_image_id",
        "build_execution",
        "expanded_vectors_sha256",
        "passed_vector_count",
        "passed",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WatchError("acquisition foundation browser-egress binding is invalid")
    expected_root = f"/lab/artifacts/buflo-study/browser-egress-qualification-v{cohort}"
    expected_final = f"{expected_root}/final.json"
    if value.get("root") != expected_root or value.get("path") != expected_final:
        raise WatchError("acquisition foundation browser-egress path is not canonical")
    qualification_root = _container_binding_directory(
        value["root"], paths=paths, label="browser-egress qualification root"
    )
    final_path = _container_binding_path(
        value["path"], paths=paths, label="browser-egress qualification final"
    )
    if final_path != qualification_root / "final.json":
        raise WatchError("acquisition foundation browser-egress final is outside its root")
    snapshot = _load_canonical_receipt(
        final_path,
        root=paths.lab_root,
        receipt_type=BROWSER_EGRESS_FINAL_TYPE,
        label="browser-egress qualification final",
    )
    qualification_build = value.get("build_execution")
    expected_build_fields = {
        "path",
        "sha256",
        "size_bytes",
        "payload_sha256",
        "cohort_version",
        "completion_path",
        "completion_sha256",
        "collection_image_id",
        "prepare_image_id",
        "reference_image_id",
    }
    images = build.get("images")
    if not isinstance(images, Mapping) or set(images) != {
        "collection",
        "prepare",
        "reference",
    }:
        raise WatchError("browser-egress qualification build image roles are incomplete")
    expected_build = {
        # The browser-egress foundation deliberately uses a Lab-root-relative
        # file binding.  The class foundation's build binding is the canonical
        # /lab path; accepting either spelling here would weaken the exact
        # cross-artifact projection.
        "path": f"artifacts/buflo-study/build-execution-v{cohort}.json",
        "sha256": build_binding["sha256"],
        "size_bytes": build_size_bytes,
        "payload_sha256": build.get("payload_sha256"),
        "cohort_version": cohort,
        "completion_path": f"/lab/artifacts/buflo-study/build-completion-v{cohort}.json",
        "completion_sha256": build_completion_sha256,
        "collection_image_id": images["collection"].get("id"),
        "prepare_image_id": images["prepare"].get("id"),
        "reference_image_id": images["reference"].get("id"),
    }
    if (
        snapshot.sha256 != value.get("sha256")
        or snapshot.value["payload_sha256"] != value.get("payload_sha256")
        or value.get("qualification_id") != BROWSER_EGRESS_QUALIFICATION_ID
        or type(value.get("cohort_version")) is not int
        or value["cohort_version"] != cohort
        or value.get("prepare_image_id") != prepare_image
        or not isinstance(qualification_build, Mapping)
        or set(qualification_build) != expected_build_fields
        or not _matches_json_contract(qualification_build, expected_build)
        or value.get("expanded_vectors_sha256") != BROWSER_EGRESS_EXPANDED_VECTORS_SHA256
        or type(value.get("passed_vector_count")) is not int
        or value["passed_vector_count"] != BROWSER_EGRESS_VECTOR_COUNT
        or value.get("passed") is not True
    ):
        raise WatchError(
            "acquisition foundation browser-egress source/build/result binding differs"
        )

    final = snapshot.value["payload"]
    final_fields = {
        "schema_version",
        "qualification_id",
        "study_id",
        "cohort_version",
        "qualification_started_at",
        "qualification_finished_at",
        "recorded_at",
        "foundation",
        "checkpoint",
        "expanded_vectors_sha256",
        "passed_results",
        "attempt_count",
        "passed_vector_count",
        "operational_failure_count",
        "semantic_failure_count",
        "packet_level_egress_qualification",
        "consumer_contract",
        "verdict",
    }
    passed_results = final.get("passed_results") if isinstance(final, Mapping) else None
    final_foundation = final.get("foundation") if isinstance(final, Mapping) else None
    final_checkpoint = final.get("checkpoint") if isinstance(final, Mapping) else None
    if (
        not isinstance(final, Mapping)
        or set(final) != final_fields
        or type(final.get("schema_version")) is not int
        or final["schema_version"] != 1
        or final.get("qualification_id") != BROWSER_EGRESS_QUALIFICATION_ID
        or final.get("study_id") != STUDY_ID
        or type(final.get("cohort_version")) is not int
        or final["cohort_version"] != cohort
        or final.get("qualification_started_at") != value.get("qualification_started_at")
        or final.get("qualification_finished_at") != value.get("qualification_finished_at")
        or final.get("recorded_at") != value.get("recorded_at")
        or final.get("expanded_vectors_sha256") != BROWSER_EGRESS_EXPANDED_VECTORS_SHA256
        or final.get("expanded_vectors_sha256") != value.get("expanded_vectors_sha256")
        or type(final.get("passed_vector_count")) is not int
        or final["passed_vector_count"] != BROWSER_EGRESS_VECTOR_COUNT
        or type(final.get("attempt_count")) is not int
        or not BROWSER_EGRESS_VECTOR_COUNT
        <= final["attempt_count"]
        <= BROWSER_EGRESS_VECTOR_COUNT * 3
        or type(final.get("operational_failure_count")) is not int
        or not 0 <= final["operational_failure_count"] <= BROWSER_EGRESS_VECTOR_COUNT * 2
        or final["attempt_count"]
        != final["passed_vector_count"] + final["operational_failure_count"]
        or type(final.get("semantic_failure_count")) is not int
        or final["semantic_failure_count"] != 0
        or final.get("packet_level_egress_qualification") != "passed"
        or not isinstance(final.get("consumer_contract"), Mapping)
        or not isinstance(final_foundation, Mapping)
        or set(final_foundation) != {"path", "sha256", "payload_sha256"}
        or final_foundation.get("path") != "foundation.json"
        or _SHA256_RE.fullmatch(str(final_foundation.get("sha256"))) is None
        or _SHA256_RE.fullmatch(str(final_foundation.get("payload_sha256"))) is None
        or not isinstance(final_checkpoint, Mapping)
        or set(final_checkpoint) != {"path", "sha256"}
        or final_checkpoint.get("path") != "experiment.json"
        or _SHA256_RE.fullmatch(str(final_checkpoint.get("sha256"))) is None
        or final.get("verdict") != "passed"
        or not isinstance(passed_results, list)
        or len(passed_results) != BROWSER_EGRESS_VECTOR_COUNT
    ):
        raise WatchError("browser-egress qualification final payload is invalid")
    result_paths: list[str] = []
    result_ids: list[str] = []
    for ordinal, result in enumerate(passed_results, 1):
        if not isinstance(result, Mapping) or set(result) != {
            "vector_ordinal",
            "vector_id",
            "attempt_number",
            "path",
            "sha256",
            "payload_sha256",
        }:
            raise WatchError("browser-egress qualification result inventory is invalid")
        result_path = result.get("path")
        vector_id = result.get("vector_id")
        if (
            type(result.get("vector_ordinal")) is not int
            or result["vector_ordinal"] != ordinal
            or not isinstance(vector_id, str)
            or not vector_id
            or type(result.get("attempt_number")) is not int
            or not 1 <= result["attempt_number"] <= 3
            or not isinstance(result_path, str)
            or re.fullmatch(r"attempts/result-[0-9]{4}\.json", result_path) is None
            or _SHA256_RE.fullmatch(str(result.get("sha256"))) is None
            or _SHA256_RE.fullmatch(str(result.get("payload_sha256"))) is None
        ):
            raise WatchError("browser-egress qualification result inventory is invalid")
        result_paths.append(result_path)
        result_ids.append(vector_id)
    if len(set(result_paths)) != len(result_paths) or result_ids != list(
        _BROWSER_EGRESS_VECTOR_IDS
    ):
        raise WatchError("browser-egress qualification result inventory is not canonical")

    build_finished = _evidence_timestamp(build.get("finished_at"), label="no-cache build finish")
    qualification_started = _evidence_timestamp(
        value.get("qualification_started_at"),
        label="browser-egress qualification start",
    )
    qualification_finished = _evidence_timestamp(
        value.get("qualification_finished_at"),
        label="browser-egress qualification finish",
    )
    qualification_recorded = _evidence_timestamp(
        value.get("recorded_at"), label="browser-egress qualification final receipt"
    )
    if not (
        build_finished
        <= qualification_started
        <= qualification_finished
        <= qualification_recorded
        <= foundation_recorded
    ):
        raise WatchError("acquisition foundation/browser-egress chronology is invalid")
    return json.loads(_canonical_json_bytes(value))


def _browser_egress_tree_inventory(
    root: Path,
    *,
    paths: WatchPaths,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Enumerate one closed, non-linked qualification tree without following links."""

    qualification_root = _require_regular_path(
        root,
        root=paths.lab_root,
        directory=True,
        label="browser-egress qualification root",
    )
    directories: list[str] = []
    files: list[str] = []
    pending = [qualification_root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as error:
            raise WatchError("cannot enumerate browser-egress sealed evidence") from error
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(qualification_root).as_posix()
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise WatchError("cannot inspect browser-egress sealed evidence") from error
            if stat.S_ISLNK(metadata.st_mode):
                raise WatchError(f"browser-egress sealed evidence contains a symlink: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                directories.append(relative)
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                files.append(relative)
            else:
                raise WatchError(
                    f"browser-egress sealed evidence contains an unsafe entry: {relative}"
                )
    return tuple(sorted(directories)), tuple(sorted(files))


def _browser_egress_tree_sha256(qualification: Mapping[str, Any], *, paths: WatchPaths) -> str:
    """Bind every pathname and byte in the tree accepted by the deep verifier."""

    root = _container_binding_directory(
        qualification.get("root"),
        paths=paths,
        label="browser-egress qualification root",
    )
    directories, files = _browser_egress_tree_inventory(root, paths=paths)
    bindings: list[dict[str, Any]] = []
    for relative in files:
        raw, digest = _read_stable_file(
            root / PurePosixPath(relative),
            root=paths.lab_root,
            label=f"browser-egress sealed evidence {relative}",
        )
        bindings.append(
            {
                "path": relative,
                "sha256": digest,
                "size_bytes": len(raw),
            }
        )
    after_directories, after_files = _browser_egress_tree_inventory(root, paths=paths)
    if (after_directories, after_files) != (directories, files):
        raise WatchError("browser-egress sealed evidence inventory changed while it was read")
    return _sha256_bytes(
        _canonical_json_bytes(
            {
                "schema_version": SCHEMA_VERSION,
                "directories": list(directories),
                "files": bindings,
            }
        )
    )


def _validate_foundation(
    binding: Any,
    *,
    paths: WatchPaths,
    prepare_source: Mapping[str, Any],
    prepare_image: str,
    acquisition_started_at: Any,
) -> dict[str, Any]:
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
    payload = snapshot.value["payload"]
    expected_foundation_keys = {
        "attestation_schema_version",
        "artifact_type",
        "study_id",
        "cohort_version",
        "recorded_at",
        "implementation_status",
        "promotion_authority",
        "implementation_scope",
        "paper_equivalent",
        "no_waivers",
        "source",
        "build_execution_identity",
        "evidence",
        "summary",
        "hard_gates",
        "all_foundation_gates_passed",
    }
    cohort = payload.get("cohort_version")
    if (
        set(payload) != expected_foundation_keys
        or payload.get("attestation_schema_version") != FOUNDATION_SCHEMA_VERSION
        or payload.get("artifact_type") != FOUNDATION_TYPE
        or payload.get("study_id") != STUDY_ID
        or type(cohort) is not int
        or cohort < 1
        or payload.get("implementation_status") != "foundation-ready-for-class-acquisition"
        or payload.get("promotion_authority") is not False
        or payload.get("implementation_scope") != "client_only_quic"
        or payload.get("paper_equivalent") is not False
        or payload.get("no_waivers") is not True
        or payload.get("all_foundation_gates_passed") is not True
        or binding["path"] != f"/lab/artifacts/class-study-foundation-v{cohort}.json"
    ):
        raise WatchError("acquisition foundation authority envelope is invalid")
    collection_source = payload.get("source")
    if not isinstance(collection_source, dict):
        raise WatchError("acquisition foundation collection source is missing")
    collection_image = collection_source.get("image_digest")
    _validate_clean_source(
        collection_source,
        image=str(collection_image),
        label="acquisition foundation collection source",
    )
    evidence = payload.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != {
        "build_execution",
        "pinned_cdp_probe",
        "browser_egress_qualification",
        "reference",
        "code_gate",
        "controlled_qualification",
        "regression_results",
        "controlled_results",
    }:
        raise WatchError("acquisition foundation evidence inventory is incomplete")
    build_binding = evidence.get("build_execution")
    if (
        not isinstance(build_binding, dict)
        or set(build_binding) != {"path", "sha256"}
        or build_binding.get("path") != f"/lab/artifacts/buflo-study/build-execution-v{cohort}.json"
        or _SHA256_RE.fullmatch(str(build_binding.get("sha256"))) is None
    ):
        raise WatchError("acquisition foundation build binding is invalid")
    build_path = _container_binding_path(
        build_binding["path"], paths=paths, label="foundation no-cache build execution"
    )
    build_snapshot = _load_build_execution(
        build_path,
        paths=paths,
        require_current=True,
    )
    build = build_snapshot.value
    images = build.get("images")
    collection_role = images.get("collection") if isinstance(images, dict) else None
    prepare_role = images.get("prepare") if isinstance(images, dict) else None
    if (
        build_snapshot.sha256 != build_binding["sha256"]
        or build.get("cohort_version") != cohort
        or build.get("source") != collection_source
        or not isinstance(collection_role, dict)
        or collection_role.get("id") != collection_image
        or not isinstance(prepare_role, dict)
        or prepare_role.get("id") != prepare_image
    ):
        raise WatchError("acquisition foundation build/source/image binding differs")
    build_completion_sha256 = build_snapshot.completion_sha256
    if build_completion_sha256 is None:  # pragma: no cover - require_current guards this
        raise WatchError("acquisition foundation has no completed no-cache build")
    expected_identity = {
        "cohort_version": cohort,
        "sha256": build_snapshot.sha256,
        "completion_path": (f"/lab/artifacts/buflo-study/build-completion-v{cohort}.json"),
        "completion_sha256": build_completion_sha256,
        "collection_image": collection_image,
        "started_at": build.get("started_at"),
        "finished_at": build.get("finished_at"),
    }
    if payload.get("build_execution_identity") != expected_identity:
        raise WatchError("acquisition foundation build identity is invalid")

    foundation_recorded = _evidence_timestamp(payload.get("recorded_at"), label="class foundation")
    browser_egress = _validate_browser_egress_qualification_binding(
        evidence.get("browser_egress_qualification"),
        paths=paths,
        cohort=cohort,
        build=build,
        build_binding={
            "path": build_binding["path"],
            "sha256": build_snapshot.sha256,
        },
        build_size_bytes=build_snapshot.size_bytes,
        build_completion_sha256=build_completion_sha256,
        prepare_image=prepare_image,
        foundation_recorded=foundation_recorded,
    )

    pinned_binding = evidence.get("pinned_cdp_probe")
    if not isinstance(pinned_binding, dict) or set(pinned_binding) != {
        "path",
        "sha256",
        "payload_sha256",
        "build_execution",
        "build_execution_identity",
        "probe_contract_sha256",
    }:
        raise WatchError("acquisition foundation pinned CDP binding is missing")
    for key in ("sha256", "payload_sha256", "probe_contract_sha256"):
        if _SHA256_RE.fullmatch(str(pinned_binding.get(key))) is None:
            raise WatchError("acquisition foundation pinned CDP digest is invalid")
    expected_pinned_path = f"/lab/artifacts/buflo-study/pinned-cdp-execution-v{cohort}.json"
    if pinned_binding.get("path") != expected_pinned_path:
        raise WatchError("acquisition foundation pinned CDP path is not canonical")
    pinned_path = _container_binding_path(
        pinned_binding["path"], paths=paths, label="foundation pinned CDP probe"
    )
    pinned_snapshot = _load_canonical_receipt(
        pinned_path,
        root=paths.lab_root,
        receipt_type=PINNED_CDP_TYPE,
        label="foundation pinned CDP probe",
    )
    pinned = pinned_snapshot.value["payload"]
    if set(pinned) != {
        "probe_schema_version",
        "artifact_type",
        "study_id",
        "cohort_version",
        "recorded_at",
        "result",
        "build_execution",
        "build_execution_identity",
        "collection_source",
        "prepare_source",
        "prepare_image_digest",
        "probe_contract",
        "probe_contract_sha256",
        "observation",
    }:
        raise WatchError("foundation pinned CDP payload fields differ from the contract")
    contract_sha256 = _sha256_bytes(_canonical_json_bytes(_PINNED_CDP_CONTRACT))
    pinned_build = pinned.get("build_execution")
    expected_pinned_build = {
        "path": build_binding["path"],
        "sha256": build_snapshot.sha256,
        "payload_sha256": build.get("payload_sha256"),
    }
    expected_prepare_source = {**collection_source, "image_digest": prepare_image}
    if (
        pinned_snapshot.sha256 != pinned_binding["sha256"]
        or pinned_snapshot.value["payload_sha256"] != pinned_binding["payload_sha256"]
        or type(pinned.get("probe_schema_version")) is not int
        or pinned.get("probe_schema_version") != _PINNED_CDP_SCHEMA_VERSION
        or pinned.get("artifact_type") != PINNED_CDP_TYPE
        or pinned.get("study_id") != STUDY_ID
        or pinned.get("cohort_version") != cohort
        or pinned.get("result") != "pass"
        or pinned_build != expected_pinned_build
        or pinned_binding.get("build_execution") != expected_pinned_build
        or pinned.get("build_execution_identity") != expected_identity
        or pinned_binding.get("build_execution_identity") != expected_identity
        or pinned.get("collection_source") != collection_source
        or pinned.get("prepare_source") != expected_prepare_source
        or dict(prepare_source) != expected_prepare_source
        or pinned.get("prepare_image_digest") != prepare_image
        or pinned.get("probe_contract") != _PINNED_CDP_CONTRACT
        or pinned.get("probe_contract_sha256") != contract_sha256
        or pinned_binding.get("probe_contract_sha256") != contract_sha256
    ):
        raise WatchError("foundation pinned CDP source/build/contract binding differs")
    _validate_pinned_cdp_observation(pinned.get("observation"))
    build_finished = _evidence_timestamp(build.get("finished_at"), label="no-cache build finish")
    probe_recorded = _evidence_timestamp(pinned.get("recorded_at"), label="pinned CDP probe")
    acquisition_started = _evidence_timestamp(
        acquisition_started_at, label="class acquisition start"
    )
    if not build_finished <= probe_recorded <= foundation_recorded <= acquisition_started:
        raise WatchError("acquisition foundation/pinned CDP chronology is invalid")

    summary = payload.get("summary")
    if (
        not isinstance(summary, dict)
        or set(summary)
        != {
            "reference_profiles",
            "regression_samples",
            "controlled_samples",
            "pinned_cdp_probe",
            "browser_egress_packet_qualification",
            "browser_egress_vectors",
        }
        or type(summary.get("reference_profiles")) is not int
        or summary["reference_profiles"] != 8
        or type(summary.get("regression_samples")) is not int
        or summary["regression_samples"] != 18
        or type(summary.get("controlled_samples")) is not int
        or summary["controlled_samples"] != 160
        or summary.get("pinned_cdp_probe") != "pass"
        or summary.get("browser_egress_packet_qualification") != "pass"
        or type(summary.get("browser_egress_vectors")) is not int
        or summary["browser_egress_vectors"] != BROWSER_EGRESS_VECTOR_COUNT
    ):
        raise WatchError("acquisition foundation gate summary is invalid")
    gates = payload.get("hard_gates")
    if not isinstance(gates, list) or len(gates) != len(_FOUNDATION_GATES):
        raise WatchError("acquisition foundation hard-gate inventory is incomplete")
    for ordinal, (gate, identity) in enumerate(zip(gates, _FOUNDATION_GATES, strict=True), 1):
        evidence_sha256s = gate.get("evidence_sha256s") if isinstance(gate, dict) else None
        if (
            not isinstance(gate, dict)
            or set(gate)
            != {
                "ordinal",
                "gate",
                "gate_identity_sha256",
                "result",
                "evidence_sha256s",
            }
            or gate.get("ordinal") != ordinal
            or gate.get("gate") != identity
            or gate.get("gate_identity_sha256")
            != _sha256_bytes(_canonical_json_bytes({"ordinal": ordinal, "gate": identity}))
            or gate.get("result") != "pass"
            or not isinstance(evidence_sha256s, list)
            or not evidence_sha256s
            or evidence_sha256s != sorted(set(evidence_sha256s))
            or any(_SHA256_RE.fullmatch(str(item)) is None for item in evidence_sha256s)
        ):
            raise WatchError("acquisition foundation hard-gate evidence is invalid")
    expected_probe_gate = sorted(
        {
            pinned_snapshot.sha256,
            pinned_snapshot.value["payload_sha256"],
            build_snapshot.sha256,
            build_completion_sha256,
            str(build.get("payload_sha256")),
            contract_sha256,
        }
    )
    if gates[-2]["evidence_sha256s"] != expected_probe_gate:
        raise WatchError("acquisition foundation pinned CDP hard gate is not exact")
    expected_browser_egress_gate = sorted(
        {
            browser_egress["sha256"],
            browser_egress["payload_sha256"],
            browser_egress["expanded_vectors_sha256"],
        }
    )
    if gates[-1]["evidence_sha256s"] != expected_browser_egress_gate:
        raise WatchError("acquisition foundation browser-egress hard gate is not exact")
    return {
        "foundation_sha256": snapshot.sha256,
        "pinned_cdp_sha256": pinned_snapshot.sha256,
        "pinned_cdp_payload_sha256": pinned_snapshot.value["payload_sha256"],
        "pinned_cdp_contract_sha256": contract_sha256,
        "build_execution_sha256": build_snapshot.sha256,
        "build_completion_path": expected_identity["completion_path"],
        "build_completion_sha256": build_completion_sha256,
        "cohort_version": cohort,
        "browser_egress_qualification": browser_egress,
    }


def _validate_immutable_binding(paths: WatchPaths) -> AcquisitionBinding:
    for relative, expected_sha256, label in (
        (
            BROWSER_EGRESS_MANIFEST_RELATIVE_PATH,
            BROWSER_EGRESS_MANIFEST_SHA256,
            "browser-egress manifest contract",
        ),
        (
            BROWSER_EGRESS_ARGV_RELATIVE_PATH,
            BROWSER_EGRESS_ARGV_SHA256,
            "browser-egress Chromium argv contract",
        ),
    ):
        _raw, observed_sha256 = _read_stable_file(
            paths.lab_root / relative,
            root=paths.lab_root,
            label=label,
        )
        if observed_sha256 != expected_sha256:
            raise WatchError(f"{label} differs from the frozen watcher contract")
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
    acquisition_schema_version = payload.get("acquisition_schema_version")
    if type(acquisition_schema_version) is not int:
        raise WatchError("acquisition provenance schema version is not an exact integer")
    if acquisition_schema_version in HISTORICAL_ACQUISITION_SCHEMA_VERSIONS:
        raise WatchError("historical acquisition provenance is verify-only and cannot be resumed")
    if acquisition_schema_version != ACQUISITION_SCHEMA_VERSION:
        raise WatchError("acquisition provenance uses an unsupported schema")
    if set(payload) != _PROVENANCE_PAYLOAD_KEYS:
        raise WatchError("acquisition provenance payload fields differ from the v5 contract")
    fixed_contract = {
        "browser_tool": _EXPECTED_BROWSER_TOOL_IDENTITY,
        "navigation_implementation": _NAVIGATION_IMPLEMENTATION,
        "cdp_target_instrumentation_policy": _CDP_TARGET_INSTRUMENTATION_POLICY,
        "non_replayable_egress_contract": _NON_REPLAYABLE_EGRESS_CONTRACT,
        "passive_render_contract": _PASSIVE_RENDER_CONTRACT,
        "passive_render_contract_sha256": _PASSIVE_RENDER_CONTRACT_SHA256,
        "browser_navigation_timeout_ms": BROWSER_NAVIGATION_TIMEOUT_MS,
        "passive_render_hard_cap_after_load_ms": PASSIVE_RENDER_HARD_CAP_MS,
        "acquisition_action_timing_contract": _ACQUISITION_ACTION_TIMING_CONTRACT,
        "baseline_scheduling_contract": _BASELINE_SCHEDULING_CONTRACT,
        "registrable_domain_policy": _REGISTRABLE_DOMAIN_POLICY,
        "domain_safety_policy": _DOMAIN_SAFETY_POLICY,
        "domain_safety_policy_sha256": _DOMAIN_SAFETY_POLICY_SHA256,
        "origin_policy": _ORIGIN_POLICY,
        "eligibility_inputs": _ELIGIBILITY_INPUTS,
        "prohibited_inputs": _PROHIBITED_INPUTS,
    }
    if (
        payload["study_id"] != STUDY_ID
        or payload["acquisition_schema_version"] != ACQUISITION_SCHEMA_VERSION
        or type(payload["candidate_count"]) is not int
        or payload["candidate_count"] != CANDIDATE_COUNT
        or payload["candidate_catalogue_sha256"] != catalogue_sha256
        or payload["candidate_catalogue_payload_sha256"] != catalogue["payload_sha256"]
        or payload["browser_tool"] != _EXPECTED_BROWSER_TOOL_IDENTITY
        or not isinstance(payload["browser_tool"], dict)
        or type(payload["browser_tool"].get("schema_version")) is not int
        or payload["browser_tool"]["schema_version"] != 1
        or any(
            not _matches_json_contract(payload.get(field), expected)
            for field, expected in fixed_contract.items()
        )
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
    foundation_authority = _validate_foundation(
        payload["foundation_attestation"],
        paths=paths,
        prepare_source=source,
        prepare_image=image,
        acquisition_started_at=payload["started_at"],
    )
    binding = AcquisitionBinding(
        prepare_image=image,
        cohort_version=foundation_authority["cohort_version"],
        catalogue_sha256=catalogue_sha256,
        provenance_sha256=provenance_snapshot.sha256,
        foundation_sha256=foundation_authority["foundation_sha256"],
        pinned_cdp_sha256=foundation_authority["pinned_cdp_sha256"],
        pinned_cdp_payload_sha256=foundation_authority["pinned_cdp_payload_sha256"],
        pinned_cdp_contract_sha256=foundation_authority["pinned_cdp_contract_sha256"],
        build_execution_sha256=foundation_authority["build_execution_sha256"],
        build_completion_path=foundation_authority["build_completion_path"],
        build_completion_sha256=foundation_authority["build_completion_sha256"],
        browser_egress_qualification=foundation_authority["browser_egress_qualification"],
        browser_egress_tree_sha256=_browser_egress_tree_sha256(
            foundation_authority["browser_egress_qualification"],
            paths=paths,
        ),
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
        type(payload["checkpoint_schema_version"]) is not int
        or payload["checkpoint_schema_version"] != CHECKPOINT_SCHEMA_VERSION
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
            raise WatchError("acquisition checkpoint baseline batches are not append-ordered")
        previous_baseline = baseline
        action_starts.extend(
            (
                baseline + timedelta(milliseconds=offset),
                batch_id,
            )
            for offset in _BASELINE_SCHEDULING_CONTRACT["serial_action_start_offsets_ms"]
        )
        candidate_ids = _candidate_id_list(
            batch["candidate_ids"],
            binding=binding,
            label="acquisition checkpoint baseline batch",
        )
        if set(batch_by_candidate).intersection(candidate_ids):
            raise WatchError("acquisition checkpoint schedules a candidate in two baseline batches")
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
            raise WatchError("acquisition checkpoint baseline batch live-page count is false")
    ordered_starts = sorted(action_starts)
    for (left, left_batch), (right, right_batch) in pairwise(ordered_starts):
        if left_batch != right_batch and right - left < timedelta(
            milliseconds=PENDING_BASELINE_GUARD_MS
        ):
            raise WatchError("acquisition checkpoint baseline batches violate the serial schedule")
    state_candidates = {
        candidate_id for candidate_id, state in states.items() if "baseline_started_at" in state
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
            raise WatchError("acquisition checkpoint has pending attempts without an active batch")
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
    if not isinstance(value["batch_id"], str) or value["batch_id"] != _content_addressed_batch_id(
        "active", value
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
        if type(attempt["attempt"]) is not int or not 1 <= attempt["attempt"] <= MAX_PROBE_ATTEMPTS:
            raise WatchError("acquisition checkpoint active batch attempt count is invalid")
        if value["stage"] == "navigation":
            if any(
                attempt[name] is not None for name in ("page_ordinal", "probe_id", "workload_id")
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
        identity = tuple(
            attempt[name]
            for name in (
                "candidate_id",
                "page_ordinal",
                "probe_id",
                "workload_id",
                "attempt",
            )
        )
        if identity in attempt_identities:
            raise WatchError("acquisition checkpoint active batch attempt is duplicated")
        attempt_identities.add(identity)
    if not attempts or len(attempts) != live_pages:
        raise WatchError(
            "acquisition checkpoint active batch attempts differ from its live-page count"
        )
    observed_candidate_ids = list(dict.fromkeys(attempt["candidate_id"] for attempt in attempts))
    if observed_candidate_ids != candidate_ids:
        raise WatchError("acquisition checkpoint active candidate ordering is invalid")
    if value["stage"] == "navigation" and len(attempts) != len(candidate_ids):
        raise WatchError("acquisition checkpoint active navigation cardinality is invalid")
    if value["stage"] == "probe":
        probe_identities = [
            (attempt["candidate_id"], attempt["page_ordinal"]) for attempt in attempts
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
                raise WatchError("acquisition checkpoint pending navigation is malformed")
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
        pending_by_candidate.setdefault(candidate_id, []).append((pending_stage, pending, page))
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
                    raise WatchError("acquisition checkpoint active navigation state is malformed")
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
            if state.get("state") != "probing" or candidate_id not in baseline_by_candidate:
                raise WatchError("acquisition checkpoint active probe state is malformed")
            page_value = page.get("page") if isinstance(page, Mapping) else None
            ordinal = page_value.get("ordinal") if isinstance(page_value, Mapping) else None
            if (
                type(ordinal) is not int
                or ordinal < 0
                or set(pending) != {"probe_id", "workload_id", "attempt", "observed_at"}
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
    expected_candidate_ids = list(
        dict.fromkeys(attempt["candidate_id"] for attempt in expected_attempts)
    )
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


def _verify_git_checkout_binding(paths: WatchPaths, checkout: Path, expected_git_dir: Path) -> None:
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
                line.strip() and not line.lstrip().startswith("#") for line in content.splitlines()
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
                    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
                    try:
                        opened = os.fstat(descriptor)
                        if (
                            not stat.S_ISREG(opened.st_mode)
                            or opened.st_nlink != 1
                            or (opened.st_dev, opened.st_ino) != (value.st_dev, value.st_ino)
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


def _validate_bound_build_evidence(
    paths: WatchPaths,
    binding: AcquisitionBinding,
) -> None:
    cohort = binding.cohort_version
    build_path = paths.lab_root / f"artifacts/buflo-study/build-execution-v{cohort}.json"
    expected_completion_path = f"/lab/artifacts/buflo-study/build-completion-v{cohort}.json"
    if binding.build_completion_path != expected_completion_path:
        raise WatchError("bound build completion path is not canonical")
    snapshot = _load_build_execution(
        build_path,
        paths=paths,
        require_current=True,
    )
    if (
        snapshot.sha256 != binding.build_execution_sha256
        or snapshot.completion_sha256 != binding.build_completion_sha256
    ):
        raise WatchError("bound build receipt or completion changed after admission")


def _validate_host_source(paths: WatchPaths, binding: AcquisitionBinding) -> None:
    """Fail closed if either host checkout drifts or races provenance checks."""

    source = binding.source
    first = _host_source_snapshot(paths)
    _validate_bound_build_evidence(paths, binding)
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
        str(paths.launcher),
        "class-study",
        "acquisition-admission",
    )


def _browser_egress_verify_command(
    paths: WatchPaths, binding: AcquisitionBinding
) -> tuple[str, ...]:
    cohort = binding.cohort_version
    build_path = paths.lab_root / f"artifacts/buflo-study/build-execution-v{cohort}.json"
    result_root = paths.lab_root / f"artifacts/buflo-study/browser-egress-qualification-v{cohort}"
    return (
        str(paths.launcher),
        "test",
        "browser-egress",
        "verify",
        "--cohort-version",
        str(cohort),
        "--build-execution-receipt",
        str(build_path),
        "--result-root",
        str(result_root),
    )


def _is_canonical_browser_egress_verify_command(command: Sequence[str]) -> bool:
    if len(command) != 10:
        return False
    launcher = Path(command[0])
    if not launcher.is_absolute() or launcher.name != "qcsd-lab":
        return False
    cohort_text = command[5]
    try:
        cohort = int(cohort_text)
    except ValueError:
        return False
    if cohort < 1 or str(cohort) != cohort_text:
        return False
    root = launcher.parent
    expected = (
        str(root / "qcsd-lab"),
        "test",
        "browser-egress",
        "verify",
        "--cohort-version",
        cohort_text,
        "--build-execution-receipt",
        str(root / f"artifacts/buflo-study/build-execution-v{cohort}.json"),
        "--result-root",
        str(root / f"artifacts/buflo-study/browser-egress-qualification-v{cohort}"),
    )
    return tuple(command) == expected


def _scope_command_runtime(command: Sequence[str]) -> int:
    if "acquisition-admission" in command:
        return ADMISSION_RUNTIME_SECONDS
    if _is_canonical_browser_egress_verify_command(command):
        return BROWSER_EGRESS_VERIFY_RUNTIME_SECONDS
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
            and (parent_state.st_uid != os.getuid() or stat.S_IMODE(parent_state.st_mode) & 0o022)
        )
        or (
            parent_is_var_tmp
            and (parent_state.st_uid != 0 or stat.S_IMODE(parent_state.st_mode) & stat.S_ISVTX == 0)
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
        namespace_state: os.stat_result | None = namespace_path.stat(follow_symlinks=False)
    except FileNotFoundError:
        namespace_state = None
    except OSError as error:
        raise WatchError("cannot inspect acquisition watch state namespace receipt") from error
    if namespace_state is None:
        try:
            staged_state: os.stat_result | None = namespace_staged.stat(follow_symlinks=False)
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
                raise WatchError("staged acquisition watch state namespace receipt is unsafe")
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
                raise WatchError("staged acquisition watch state namespace receipt does not verify")
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
        raise WatchError("cannot inspect stale acquisition watch namespace publication") from error
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
        {"empty_observations", "outcome", "recovered_from_phase"} if recovery else set()
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
        type(value["schema_version"]) is not int
        or value["schema_version"] != SCHEMA_VERSION
        or value["artifact_type"] != (SCOPE_RECOVERY_TYPE if recovery else SCOPE_SUPERVISION_TYPE)
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
        or any(type(value[name]) is not int or value[name] <= 0 for name in positive_numeric)
        or any(type(value[name]) is not int or value[name] < 0 for name in wrapper_numeric)
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
        value.get("artifact_type") == SCOPE_RECOVERY_TYPE if isinstance(value, dict) else False
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
        or type(value["schema_version"]) is not int
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
        state_root / "NAMESPACE.json",
        root=state_root,
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


def _assert_live_pidfd(pidfd: int) -> None:
    poller = select.poll()
    try:
        poller.register(
            pidfd,
            select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
        )
        events = poller.poll(0)
    except OSError as error:
        raise WatchError("cannot poll the recorded acquisition supervisor") from error
    for observed_fd, flags in events:
        if observed_fd != pidfd or flags & select.POLLNVAL:
            raise WatchError("recorded acquisition supervisor pidfd became invalid")
        if flags & select.POLLIN:
            raise WatchError("recorded acquisition supervisor identity is not live")
        if flags:
            raise WatchError("recorded acquisition supervisor pidfd is indeterminate")


def _assert_recorded_watch_lock_holder(state_root: Path, record: Mapping[str, Any]) -> None:
    supervisor_pid = record["supervisor_pid"]
    opener = getattr(os, "pidfd_open", None)
    if opener is None:
        raise WatchError("recorded acquisition supervisor proof requires pidfd support")
    try:
        pidfd = opener(supervisor_pid, 0)
    except ProcessLookupError as error:
        raise WatchError("recorded acquisition supervisor identity is not live") from error
    except OSError as error:
        raise WatchError("cannot bind the recorded acquisition supervisor") from error
    try:
        _assert_live_pidfd(pidfd)
        _assert_recorded_watch_lock_holder_bound(state_root, record)
        _assert_live_pidfd(pidfd)
    finally:
        os.close(pidfd)


def _assert_recorded_watch_lock_holder_bound(state_root: Path, record: Mapping[str, Any]) -> None:
    supervisor_pid = record["supervisor_pid"]
    expected = (
        record["supervisor_start_time"],
        record["supervisor_session"],
        record["supervisor_process_group"],
    )
    if _process_identity(supervisor_pid) != expected:
        raise WatchError("recorded acquisition supervisor identity is not live")
    metadata = os.stat(state_root / "WATCH.lock", follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (metadata.st_dev, metadata.st_ino) != (record["lock_device"], record["lock_inode"])
    ):
        raise WatchError("recorded acquisition supervisor lock identity changed")
    lock_key = f"{os.major(metadata.st_dev):02x}:{os.minor(metadata.st_dev):02x}:{metadata.st_ino}"
    descriptor_root = Path(f"/proc/{supervisor_pid}/fd")
    try:
        descriptor_names = tuple(descriptor_root.iterdir())
    except (OSError, UnicodeError) as error:
        raise WatchError("cannot prove the recorded acquisition supervisor lock holder") from error
    if len(descriptor_names) > 4_096:
        raise WatchError("recorded acquisition supervisor descriptor census is excessive")
    holders: list[int] = []
    for descriptor_path in descriptor_names:
        if re.fullmatch(r"[0-9]+", descriptor_path.name) is None:
            raise WatchError("recorded acquisition supervisor descriptor is malformed")
        try:
            descriptor_state = descriptor_path.stat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise WatchError(
                "cannot prove the recorded acquisition supervisor lock holder"
            ) from error
        if (descriptor_state.st_dev, descriptor_state.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            continue
        descriptor = int(descriptor_path.name)
        try:
            lines = (
                Path(f"/proc/{supervisor_pid}/fdinfo/{descriptor}")
                .read_text(encoding="ascii")
                .splitlines()
            )
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError) as error:
            raise WatchError(
                "cannot prove the recorded acquisition supervisor lock holder"
            ) from error
        rows = []
        for line in lines:
            key, separator, value = line.partition(":")
            if key == "lock" and separator:
                rows.append(value.split())
        if not rows:
            continue
        if len(rows) != 1 or (
            len(rows[0]) != 8
            or re.fullmatch(r"[1-9][0-9]*:", rows[0][0]) is None
            or rows[0][1:4] != ["FLOCK", "ADVISORY", "WRITE"]
            or rows[0][4] != str(supervisor_pid)
            or rows[0][5:] != [lock_key, "0", "EOF"]
        ):
            raise WatchError("recorded acquisition supervisor lock descriptor is invalid")
        holders.append(descriptor)
    if not holders:
        raise WatchError("recorded acquisition supervisor does not hold the exact watch lock")
    try:
        final_metadata = os.stat(state_root / "WATCH.lock", follow_symlinks=False)
    except OSError as error:
        raise WatchError("recorded acquisition supervisor lock identity changed") from error
    if (
        final_metadata.st_dev,
        final_metadata.st_ino,
        final_metadata.st_uid,
        final_metadata.st_mode,
        final_metadata.st_nlink,
    ) != (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_mode,
        metadata.st_nlink,
    ):
        raise WatchError("recorded acquisition supervisor lock identity changed")
    if _process_identity(supervisor_pid) != expected:
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
            or (metadata.st_dev, metadata.st_ino) != (pathname.st_dev, pathname.st_ino)
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
        or (held.st_dev, held.st_ino) != (record["birth_lock_device"], record["birth_lock_inode"])
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
        or type(value["schema_version"]) is not int
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
        raise WatchError(f"acquisition watch state contains an unexpected entry: {unexpected[0]}")
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
                    not root.name.startswith("scope.next.") and bool(child_names)
                ) or child_names - {"BIRTH.lock", "SUPERVISION.next"}:
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
                    plan.record["recovered_from_phase"] if plan.recovery else plan.record["phase"]
                )
                authorised = launch_phase != "declared-before-request" or plan.request is not None
                if plan.record["host_boot_id"] == _host_boot_id() and authorised:
                    state = _scope_state(plan.unit, environment)
                    if state.processes and not _scope_signal(plan.unit, "SIGKILL", environment):
                        raise WatchError(f"cannot terminate stale acquisition scope {plan.unit}")
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
                        raise WatchError("birth-free acquisition recovery unit reappeared")
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
                    if state.processes and not _scope_signal(plan.unit, "SIGKILL", environment):
                        raise WatchError(f"cannot terminate stale acquisition scope {plan.unit}")
                    if not _wait_scope_empty(
                        plan.unit,
                        environment,
                        deadline=time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS,
                    ):
                        raise WatchError(f"stale acquisition scope remains non-empty: {plan.unit}")
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
            root,
            record=record,
            deadline=time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS * 2,
        )
        if held is None:
            raise WatchError("cannot authenticate acquisition scope birth before cleanup")
        try:
            if not _wait_scope_absent(record["scope_unit"], _safe_host_environment()):
                raise WatchError("acquisition scope unit is not absent during cleanup")
            _discard_staged_scope_files(root, state_root=state_root)
            recovery = (
                record
                if recovered
                else _publish_scope_recovery(root, record, state_root=state_root)
            )
            _finish_scope_teardown(
                root, state_root=state_root, recovery=recovery, birth_lock_fd=held
            )
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
    root: Path,
    *,
    state_root: Path,
    supervision: Mapping[str, Any],
    unit: str,
    environment: Mapping[str, str],
    process: subprocess.Popen[str] | None,
    birth_lock_fd: int,
) -> None:
    _terminate_and_reap_launcher(process)
    held = birth_lock_fd
    acquired = False
    if held < 0:
        value = _wait_scope_birth_lock(
            root,
            record=supervision,
            deadline=time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS * 2,
        )
        if value is None:
            raise WatchError("acquisition scope birth lock disappeared before teardown")
        held, acquired = value, True
    try:
        _validate_held_scope_birth_lock(root, record=supervision, descriptor=held)
        current, _, recovered = _read_scope_record(root, state_root=state_root)
        for name in (
            "scope_unit",
            "scope_token",
            "action_sha256",
            "source_binding_sha256",
            "request_authority_sha256",
            "birth_lock_device",
            "birth_lock_inode",
        ):
            if current[name] != supervision[name]:
                raise WatchError("acquisition scope authority changed before teardown")
        state = _scope_state(unit, environment)
        if state.processes:
            _scope_signal(unit, "SIGKILL", environment)
        if not _wait_scope_empty(
            unit, environment, deadline=time.monotonic() + SCOPE_CLIENT_GRACE_SECONDS
        ):
            raise WatchError("acquisition scope remains populated before teardown")
        _discard_staged_scope_files(root, state_root=state_root)
        recovery = (
            current if recovered else _publish_scope_recovery(root, current, state_root=state_root)
        )
        _finish_scope_teardown(root, state_root=state_root, recovery=recovery, birth_lock_fd=held)
    finally:
        if acquired:
            os.close(held)


_HOST_SCOPE_LAUNCHER = r"""
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
"""


_SCOPE_WRAPPER = r"""
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
"""


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
        self.previous_handlers = {watched: signal.getsignal(watched) for watched in self.watched}
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
    stop_seconds = ACQUISITION_ACTION_CLEANUP_SECONDS if graceful_run else STATUS_CLEANUP_SECONDS
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
                            raise WatchError("acquisition scope wrapper changed before arming")
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
                launcher_stdout, launcher_stderr = process.communicate(timeout=min(0.2, remaining))
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
                root,
                state_root=state_root,
                supervision=supervision,
                unit=unit,
                environment=environment,
                process=process,
                birth_lock_fd=birth_lock_fd,
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
        type(value["schema_version"]) is not int
        or value["schema_version"] != SCHEMA_VERSION
        or value["artifact_type"] != DOCKER_ADMISSION_TYPE
        or context != "default"
        or host
        not in {
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
            "Docker admission/recovery failed" + (f": {diagnostic}" if diagnostic else "")
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


def _run_browser_egress_verification(
    *,
    paths: WatchPaths,
    binding: AcquisitionBinding,
    runner: CommandRunner,
    environment: Mapping[str, str],
    authority_fd: int,
    state_root: Path,
    source_binding_sha256: str,
) -> dict[str, Any]:
    command = _browser_egress_verify_command(paths, binding)
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
        raise WatchError(f"cannot execute browser-egress deep verification: {error}") from error
    if completed.returncode != 0:
        diagnostic = (completed.stderr or completed.stdout or "").strip()
        raise WatchError(
            "browser-egress deep verification failed with exit "
            f"{completed.returncode}" + (f": {diagnostic}" if diagnostic else "")
        )
    result = _parse_exact_json_object(
        completed.stdout,
        label="browser-egress deep-verification output",
    )
    try:
        encoded = completed.stdout.encode("utf-8")
    except UnicodeError as error:  # pragma: no cover - CompletedProcess[str] contract
        raise WatchError("browser-egress deep-verification output is not UTF-8") from error
    if encoded != _canonical_json_bytes(result):
        raise WatchError("browser-egress deep-verification output is not canonical JSON")
    expected = {
        key: value for key, value in binding.browser_egress_qualification.items() if key != "root"
    }
    if not _matches_json_contract(result, expected):
        raise WatchError("browser-egress deep verification differs from the foundation binding")
    return result


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
        type(value["schema_version"]) is not int
        or value["schema_version"] != SCHEMA_VERSION
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
        gate_verification = details["gate_verification"]
        expected_gate = {
            "required_windows": _EXPECTED_WINDOWS,
            "labels": ["t+30s", "t+24h", "t+72h"],
            "all_three_required_per_page_receipt": True,
            "acquisition_owner": "resumable-qcsd-class-study-production-runner",
            "batching": {
                "maximum_candidates_per_action": MAX_CANDIDATES,
                "global_live_page_cap": GLOBAL_LIVE_PAGE_CAP,
            },
            "runner_wait_policy": _RUN_WAIT_POLICY,
        }
        if not _matches_json_contract(gate, expected_gate):
            raise WatchError("acquisition-status result carries another stability gate")
        if (
            details["authoritative"] is not False
            or not isinstance(gate_verification, dict)
            or set(gate_verification)
            != {"foundation_path", "foundation_sha256", "informational_only"}
            or not isinstance(gate_verification["foundation_path"], str)
            or re.fullmatch(
                r"/lab/artifacts/class-study-foundation-v[1-9][0-9]*\.json",
                gate_verification["foundation_path"],
            )
            is None
            or not isinstance(gate_verification["foundation_sha256"], str)
            or _SHA256_RE.fullmatch(gate_verification["foundation_sha256"]) is None
            or gate_verification["informational_only"] is not True
        ):
            raise WatchError("acquisition-status foundation verification is not informational")
        if value["status"] != "complete" or blockers:
            raise WatchError("acquisition-status result has invalid action status or blockers")
    else:
        if (
            type(details["bounded_candidates"]) is not int
            or details["bounded_candidates"] != MAX_CANDIDATES
            or not _matches_json_contract(details["runner_wait_policy"], _RUN_WAIT_POLICY)
        ):
            raise WatchError("acquisition-run result differs from the bounded wait contract")
        expected_status = "ready" if details["complete"] else "pending"
        if value["status"] != expected_status or bool(blockers) == details["complete"]:
            raise WatchError("acquisition-run result status/blockers are inconsistent")
    return value


def _validate_status_details(details: Mapping[str, Any], *, action: str) -> None:
    if (
        type(details["acquisition_schema_version"]) is not int
        or details["acquisition_schema_version"] != ACQUISITION_SCHEMA_VERSION
        or type(details["checkpoint_schema_version"]) is not int
        or details["checkpoint_schema_version"] != CHECKPOINT_SCHEMA_VERSION
        or type(details["maximum_candidates_per_action"]) is not int
        or details["maximum_candidates_per_action"] != MAX_CANDIDATES
        or type(details["global_live_page_cap"]) is not int
        or details["global_live_page_cap"] != GLOBAL_LIVE_PAGE_CAP
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
        or details["due_now_count"] + details["finalisable_count"] + details["missed_window_count"]
        > details["probing_count"]
        or details["recovery_required_count"]
        > details["pending_count"]
        + details["probing_count"]
        + (active_batch["attempt_count"] if active_batch is not None else 0)
        or (
            active_batch is not None
            and details["recovery_required_count"] < active_batch["attempt_count"]
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
        raise WatchError("another class-study acquisition process holds the runner lock") from error
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
    if action == "acquisition-status":
        expected_gate_verification = {
            "foundation_path": (
                f"/lab/artifacts/class-study-foundation-v{binding.cohort_version}.json"
            ),
            "foundation_sha256": binding.foundation_sha256,
            "informational_only": True,
        }
        if not _matches_json_contract(
            result["details"]["gate_verification"],
            expected_gate_verification,
        ):
            raise WatchError("acquisition-status uses another foundation binding")
        if after.sha256 != before.sha256:
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
            child_environment = _docker_environment(admission, binding)
            _run_browser_egress_verification(
                paths=active_paths,
                binding=binding,
                runner=active_runner,
                environment=child_environment,
                authority_fd=descriptor,
                state_root=state_root,
                source_binding_sha256=source_binding_sha256,
            )
            _validate_lock_identity(active_paths.mutation_lock, descriptor)
            _revalidate_immutable_and_source(active_paths, binding, validate_source)
            _validate_checkpoint(active_paths, binding)
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
                    _revalidate_immutable_and_source(active_paths, binding, validate_source)
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
                        _revalidate_immutable_and_source(active_paths, binding, validate_source)
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
            expected_source_binding_sha256 = arguments.expected_source_binding_sha256_internal
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
                    _browser_egress_verify_command(paths, binding),
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
