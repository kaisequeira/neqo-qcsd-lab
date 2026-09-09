"""Immutable receipts for the evidence-grade browser-egress gate.

This is the orchestration-independent half of the gate.  It freezes the test
matrix and Chromium contract, validates source/build/image/cohort provenance,
publishes attempt receipts append-only, derives the resumable checkpoint, and
deep-verifies every referenced artifact before producing a final receipt.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any

from .browser_egress import (
    BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES,
    BROWSER_EGRESS_COMMAND_LINE_SCHEMA_VERSION,
    BROWSER_EGRESS_EXPLICIT_CHROMIUM_ARGS,
    BROWSER_EGRESS_NETWORK_PREDICTION_DISABLED_CONTROL_PROFILE,
    BROWSER_EGRESS_NETWORK_PREDICTION_ENABLED_CONTROL_PROFILE,
    BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE,
    BROWSER_EGRESS_QUALIFICATION_CONTROL_PROFILES,
    BROWSER_EGRESS_REPORTING_DISABLED_CONTROL_PROFILE,
    BROWSER_EGRESS_REPORTING_ENABLED_CONTROL_PROFILE,
    BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES,
    _validate_qualification_dns_control_resolver_argument,
    browser_egress_chromium_args,
    browser_egress_qualification_control_chromium_args,
    validate_browser_egress_command_line_projection,
    validate_fail_closed_host_resolver_argument,
)
from .browser_egress_fixture import (
    BROWSER_SERVICE_CONTROL_SPECS,
    BROWSER_SERVICE_SURFACES,
    CLOSE_GRACE_MS,
    CONSTRUCTOR_CONTEXTS,
    CONSTRUCTOR_SURFACES,
    CONTROL_SURFACES,
    DOCUMENT_CONTEXTS,
    FIXTURE_CERTIFICATE,
    FIXTURE_PRIVATE_KEY,
    FIXTURE_TOPOLOGY,
    POPUP_SURFACES,
    PROXY_ENVIRONMENT_KEYS,
    QUALIFICATION_ID,
    SERVICE_WORKER_SURFACES,
    VECTOR_COUNT,
    expanded_vectors_sha256,
    expected_browser_launch_contract,
    expected_vectors,
    fixture_contract_sha256,
    inventory_json,
    validate_fixture_observation,
    validate_semantic_observation,
    validate_sink_receipt,
    validate_vector,
    vector_by_id,
)
from .browser_egress_observer import (
    reconcile_sink_and_packet_evidence,
    safe_relative_artifact,
    validate_capture_receipt,
)
from .class_study import (
    STUDY_ID,
    bind_receipt,
    canonical_json_bytes,
    canonical_json_sha256,
    validate_hash_bound_receipt,
)
from .playwright_driver import (
    CHROMIUM_ARCHIVE_SHA256,
    CHROMIUM_ARCHIVE_URL,
    CHROMIUM_CHILD_ENVIRONMENT,
    CHROMIUM_DNS_OVER_HTTPS_MODE,
    CHROMIUM_MANAGED_POLICY_MODE,
    CHROMIUM_SUBPROCESS_WRAPPER_MODE,
    DEFAULT_CHROMIUM_MANAGED_POLICY,
    DEFAULT_CHROMIUM_SUBPROCESS_WRAPPER,
    DEFAULT_CONFIGURED_EXECUTABLE,
    DEFAULT_RESOLVED_EXECUTABLE,
    EXPECTED_BROWSERS_JSON_SHA256,
    EXPECTED_CHROMIUM_REVISION,
    EXPECTED_CHROMIUM_SHA256,
    EXPECTED_CHROMIUM_MANAGED_POLICY_SHA256,
    EXPECTED_CHROMIUM_CONTROL_POLICY_SHA256,
    EXPECTED_CHROMIUM_SUBPROCESS_WRAPPER_SHA256,
    EXPECTED_CHROMIUM_VERSION,
    EXPECTED_PLAYWRIGHT_DRIVER_CONTENT_SHA256,
    EXPECTED_PLAYWRIGHT_DRIVER_PAYLOAD_SHA256,
    EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256,
    FORBIDDEN_DRIVER_ENVIRONMENT_VARIABLES,
    PLAYWRIGHT_VERSION,
)
from .util import SOURCE_METADATA_KEYS, load_json, sha256_file

MANIFEST_SCHEMA_VERSION = 1
ARGV_SCHEMA_VERSION = 1
FOUNDATION_SCHEMA_VERSION = 3
HISTORICAL_FOUNDATION_SCHEMA_VERSION = 2
ATTEMPT_INTENT_SCHEMA_VERSION = 1
RESULT_SCHEMA_VERSION = 1
CHECKPOINT_SCHEMA_VERSION = 1
FINAL_SCHEMA_VERSION = 1

MANIFEST_RELATIVE_PATH = "config/class-study/v1/browser-egress-qualification-v1.json"
ARGV_RELATIVE_PATH = "config/class-study/v1/browser-egress-chromium-argv-v1.json"
FOUNDATION_FILENAME = "foundation.json"
CHECKPOINT_FILENAME = "experiment.json"
FINAL_FILENAME = "final.json"
ATTEMPT_DIRECTORY = "attempts"
ATTEMPT_INTENT_DIRECTORY = "attempt-intents"
EVIDENCE_DIRECTORY = "evidence"
ZERO_DIGEST = "0" * 64
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
MAX_OPERATIONAL_ATTEMPTS = 3

FOUNDATION_RECEIPT_TYPE = "qcsd-browser-egress-qualification-foundation"
ATTEMPT_INTENT_RECEIPT_TYPE = "qcsd-browser-egress-qualification-attempt-intent"
RESULT_RECEIPT_TYPE = "qcsd-browser-egress-qualification-vector-result"
FINAL_RECEIPT_TYPE = "qcsd-browser-egress-qualification-final"

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_CODE = re.compile(r"[a-z0-9][a-z0-9-]{0,127}\Z")
_CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
_UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")
_TOPOLOGY_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600

# Tests replace this with a process-terminating callback to exercise actual
# power-loss boundaries.  It is deliberately not controlled by an environment
# variable: production callers cannot enable durability fault injection.
_DURABILITY_FAULT_INJECTOR: Callable[[str], None] | None = None

BUILD_DOCKER_DAEMON_FIELDS = frozenset(
    {
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
)
LIVE_DOCKER_DAEMON_FIELDS = BUILD_DOCKER_DAEMON_FIELDS | {
    "ncpu",
    "mem_total_bytes",
    "storage_driver",
    "docker_root_dir",
}

REQUIRED_SOURCE_BINDING_PATHS = (
    "Dockerfile",
    "pyproject.toml",
    "uv.lock",
    "config/class-study/v1/chromium-managed-policy-v1.json",
    "config/class-study/v1/chromium-network-prediction-positive-control-v1.json",
    "config/class-study/v1/browser-egress-fixture-cert-v1.pem",
    "config/class-study/v1/browser-egress-fixture-key-v1.pem",
    "src/qcsd_lab/__init__.py",
    "src/qcsd_lab/acquisition_errors.py",
    "src/qcsd_lab/buflo_study.py",
    "src/qcsd_lab/build_storage.py",
    "src/qcsd_lab/browser_egress.py",
    "src/qcsd_lab/browser_egress_fixture.py",
    "src/qcsd_lab/browser_egress_observer.py",
    "src/qcsd_lab/browser_egress_qualification.py",
    "src/qcsd_lab/capture.py",
    "src/qcsd_lab/class_acquisition.py",
    "src/qcsd_lab/class_run_binding.py",
    "src/qcsd_lab/cdp_targets.py",
    "src/qcsd_lab/class_study.py",
    "src/qcsd_lab/defenses.py",
    "src/qcsd_lab/discover.py",
    "src/qcsd_lab/discovery_evidence.py",
    "src/qcsd_lab/fidelity.py",
    "src/qcsd_lab/fitting_trace.py",
    "src/qcsd_lab/fitting_walkie_talkie.py",
    "src/qcsd_lab/kernel_tx.py",
    "src/qcsd_lab/manifest.py",
    "src/qcsd_lab/parameters.py",
    "src/qcsd_lab/pinned_cdp.py",
    "src/qcsd_lab/playwright_driver.py",
    "src/qcsd_lab/profiles.py",
    "src/qcsd_lab/cli.py",
    "src/qcsd_lab/util.py",
    "tools/browser_egress_qualification.py",
    "tools/docker_lifecycle_lock_guardian.py",
    "tools/docker_lifecycle_native.py",
    "tools/docker_signal_supervisor.sh",
    "tools/qcsd_chromium_child_wrapper.sh",
    "tools/windows_docker_storage_probe.ps1",
    "qcsd-lab",
)

EFFECTIVE_ARGV_BINDING_SCHEMA_VERSION = 2
DOCKER_INSPECT_PROJECTION_SCHEMA_VERSION = 2
POLICY_VOLUME_PROJECTION_SCHEMA_VERSION = 1
POLICY_VOLUME_ROLE = "policy_volume"
POLICY_SEED_ROLE = "policy_seed"
POLICY_VOLUME_SUFFIX = "policy0"
POLICY_VOLUME_MANAGED_DIRECTORY = "/etc/chromium/policies/managed"
POLICY_VOLUME_POLICY_FILENAME = "qcsd-network-prediction.json"
POLICY_VOLUME_POLICY_PATH = (
    f"{POLICY_VOLUME_MANAGED_DIRECTORY}/{POLICY_VOLUME_POLICY_FILENAME}"
)
POLICY_VOLUME_SEED_SOURCE = (
    "/usr/share/qcsd-lab/browser-egress-controls/network-prediction-options-0.json"
)
FIXTURE_RUNTIME_CERTIFICATE = f"/opt/qcsd-lab/{FIXTURE_CERTIFICATE['path']}"
FIXTURE_RUNTIME_PRIVATE_KEY = f"/opt/qcsd-lab/{FIXTURE_PRIVATE_KEY['path']}"
FIXTURE_TLS_MASK_DIRECTORY = "/opt/qcsd-lab/config/class-study/v1"
ROLE_TMPFS_OPTIONS = "rw,nosuid,nodev,mode=1777"
FIXTURE_TLS_MASK_TMPFS_OPTIONS = "ro,nosuid,nodev,noexec,mode=000"


class FoundationVerificationMode(str, Enum):
    """Select live execution admission or later portable evidence replay."""

    EXECUTION = "execution-in-prepare-image"
    PORTABLE_REPLAY = "portable-attestation-replay"

EXECUTION_CONTRACT: dict[str, Any] = {
    "schema_version": 3,
    "topology": "fresh-prepare-image-isolated-internal-bridge-v3",
    "direct_network_members": [
        "browser",
        "fixture",
        "forbidden_sink",
        "dns_sink",
    ],
    "observer_independent_network_attachments": 0,
    "one_vector_per_fresh_subject_container": True,
    "negative_vector_subject": "fresh-chromium-browser",
    "positive_control_subject": "fresh-idle-chromium-plus-independent-control-emitter",
    "browser_service_control_subject": (
        "fresh-chromium-with-vector-bound-policy-context-and-resolver-profile"
    ),
    "browser": {
        "image_role": "prepare",
        "chromium_distribution": "full-chromium-revision-1200",
        "managed_network_prediction_policy": "NetworkPredictionOptions=2",
        "managed_dns_over_https_policy": {"DnsOverHttpsMode": "off"},
        "quic": {
            "enabled": False,
            "disable_switch": "--disable-quic",
            "disable_switch_bare_and_unique": True,
            "rationale": "prevent-preferred-address-migration-bypassing-resolver-pins",
        },
        "user": "host-supplied-numeric-nonroot-uid-gid",
        "privileged": False,
        "cap_drop": ["ALL"],
        "read_only_root": True,
    },
    "fixture_tls": {
        "certificate_source_path": FIXTURE_CERTIFICATE["path"],
        "certificate_runtime_path": FIXTURE_RUNTIME_CERTIFICATE,
        "certificate_sha256": FIXTURE_CERTIFICATE["sha256"],
        "certificate_spki_sha256_base64": FIXTURE_CERTIFICATE[
            "spki_sha256_base64"
        ],
        "certificate_runtime_uid": 0,
        "certificate_runtime_gid": 0,
        "certificate_runtime_mode": "0o444",
        "private_key_source_path": FIXTURE_PRIVATE_KEY["path"],
        "private_key_runtime_path": FIXTURE_RUNTIME_PRIVATE_KEY,
        "private_key_sha256": FIXTURE_PRIVATE_KEY["sha256"],
        "private_key_runtime_uid": 0,
        "private_key_runtime_gid": 0,
        "private_key_runtime_mode": "0o400",
        "runtime_visibility": ["fixture"],
        "other_roles_masked": True,
        "mask_directory": FIXTURE_TLS_MASK_DIRECTORY,
        "mask_tmpfs_options": FIXTURE_TLS_MASK_TMPFS_OPTIONS,
        "masked_roles": [
            "browser",
            "observer",
            "forbidden_sink",
            "dns_sink",
            "policy_seed",
        ],
    },
    "network_prediction_enabled_control_policy": {
        "source_path": (
            "config/class-study/v1/"
            "chromium-network-prediction-positive-control-v1.json"
        ),
        "seed_image_path": POLICY_VOLUME_SEED_SOURCE,
        "runtime_path": POLICY_VOLUME_POLICY_PATH,
        "sha256": EXPECTED_CHROMIUM_CONTROL_POLICY_SHA256,
        "dns_over_https_mode": CHROMIUM_DNS_OVER_HTTPS_MODE,
        "mode": "0o444",
        "uid": 0,
        "gid": 0,
        "sole_managed_policy": True,
        "volume_driver": "local",
        "volume_scope": "local",
        "volume_options": {},
        "volume_name_pattern": "qcsd-be-<attempt-topology-token>-policy0",
        "browser_mount_read_only": True,
        "seeder_network": "none",
        "seeder_user": "0:0",
        "seeder_cap_drop": ["ALL"],
        "seeder_read_only_root": True,
        "seeder_tls_directory_masked": True,
    },
    "observer": {
        "separate_container": True,
        "user": "0:0",
        "user_rationale": "root-uid-required-for-dumpcap-with-single-effective-capability",
        "network_mode": "container:browser",
        "privileged": False,
        "cap_drop": ["ALL"],
        "cap_add": ["CAP_NET_RAW"],
        "interface": "any",
        "capture_filter": None,
        "starts_before_browser": True,
        "stops_after_browser_exit_and_grace": True,
        "pcap_storage": "container-tmpfs",
        "pcap_extraction": "docker-exec-stream-after-dumpcap-stop-before-observer-exit",
    },
    "sink": {
        "separate_container": True,
        "ordinary_http_hit_is_sufficient_evidence": False,
        "tcp_udp_dns_counters_required": True,
    },
    "reporting_close_grace_ms": CLOSE_GRACE_MS,
    "capture_exit_code": 0,
    "capture_drop_counter_contract": (
        "one-detailed-dumpcap-pcap-dumpcap-flushed-ps_ifdrop-record"
    ),
    "capture_kernel_drops": 0,
    "capture_interface_drops": 0,
    "operational_retry_limit": MAX_OPERATIONAL_ATTEMPTS,
    "semantic_failure_is_terminal": True,
}

CONSUMER_CONTRACT: dict[str, Any] = {
    "schema_version": 1,
    "required_before": ["class-foundation", "class-readiness", "class-acquisition"],
    "authorization_scope": "exact-source-image-browser-argv-environment-and-fixture-only",
    "per_run_packet_guarantee_claimed": False,
    "per_run_guarantee_requires": "per-run-capture-or-equivalent-os-or-proxy-mediation",
    "http_hit_only_proof_forbidden": True,
}

FAILURE_CODES = frozenset(
    {
        "browser-start-failed",
        "capture-dropped-packets",
        "capture-process-failed",
        "docker-start-failed",
        "infrastructure-timeout",
        "interrupted",
        "observer-start-failed",
        "packet-policy-failed",
        "runtime-binding-failed",
        "semantic-observation-failed",
        "fixture-observation-failed",
        "sink-reconciliation-failed",
    }
)


def expected_manifest_config() -> dict[str, Any]:
    """Return the only accepted v1 matrix recipe and expanded inventory hash."""

    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "artifact_type": "qcsd-browser-egress-qualification-manifest",
        "qualification_id": QUALIFICATION_ID,
        "study_id": STUDY_ID,
        "vector_count": VECTOR_COUNT,
        "group_counts": {
            "constructor_transport": 50,
            "urlloader": 19,
            "service_worker": 3,
            "popup_navigation": 10,
            "browser_service": 13,
            "browser_service_control": 12,
            "positive_control": 3,
        },
        "ordering": [
            "constructor-transport-context-major",
            "urlloader-surface-major",
            "service-worker",
            "popup-navigation",
            "browser-service",
            "browser-service-control-paired-order",
            "positive-control",
        ],
        "axes": {
            "constructor_contexts": list(CONSTRUCTOR_CONTEXTS),
            "constructor_surfaces": list(CONSTRUCTOR_SURFACES),
            "document_contexts": list(DOCUMENT_CONTEXTS),
            "service_worker_surfaces": list(SERVICE_WORKER_SURFACES),
            "popup_surfaces": list(POPUP_SURFACES),
            "browser_service_surfaces": list(BROWSER_SERVICE_SURFACES),
            "browser_service_control_pairs": [
                {
                    "context": context,
                    "surface": surface,
                    "semantic_kind": semantic_kind,
                    "semantic_mechanism": semantic_mechanism,
                    "packet_policy": packet_policy,
                }
                for (
                    context,
                    surface,
                    semantic_kind,
                    semantic_mechanism,
                    packet_policy,
                ) in BROWSER_SERVICE_CONTROL_SPECS
            ],
            "positive_control_surfaces": list(CONTROL_SURFACES),
        },
        "expanded_vectors_sha256": expanded_vectors_sha256(),
        "fixture_topology": FIXTURE_TOPOLOGY,
        "execution_contract": EXECUTION_CONTRACT,
        "acceptance": {
            "negative_vectors": (
                "exact-semantic-outcome-zero-approved-mechanism-sentinels-and-"
                "zero-forbidden-syn-accept-tcp-payload-udp-dns"
            ),
            "browser_service_controls": (
                "each-disabled-enabled-pair-requires-exact-static-document-"
                "fixture-and-packet-endpoint-evidence"
            ),
            "positive_controls": "exact-tcp-udp-and-deterministic-udp-plus-tcp-dns-evidence",
            "capture": (
                "exit-zero-and-explicit-zero-pcap-dumpcap-flushed-ps_ifdrop"
            ),
            "all_vectors_required": True,
        },
    }


def validate_manifest_config(value: object) -> dict[str, Any]:
    expected = expected_manifest_config()
    if canonical_json_bytes(value) != canonical_json_bytes(expected):
        raise ValueError("browser-egress qualification manifest differs from frozen v1")
    return json.loads(canonical_json_bytes(value))


def expected_argv_config() -> dict[str, Any]:
    ordinary_contract = expected_browser_launch_contract(expected_vectors()[0])
    qualification_launch = browser_egress_chromium_args(
        approved_origins=ordinary_contract["resolver_approved_origins"],
        origin_ip_pins=ordinary_contract["resolver_origin_ip_pins"],
        approved_ip_exclusions=ordinary_contract["resolver_approved_ip_exclusions"],
    )
    if tuple(qualification_launch[:-1]) != BROWSER_EGRESS_EXPLICIT_CHROMIUM_ARGS:
        raise ValueError("browser-egress qualification launch arguments are inconsistent")
    control_contracts = [
        expected_browser_launch_contract(vector)
        for vector in expected_vectors()
        if vector.family == "browser-service-control"
    ]
    control_profiles = []
    for profile in BROWSER_EGRESS_QUALIFICATION_CONTROL_PROFILES:
        members = [
            contract
            for contract in control_contracts
            if contract["launch_profile"] == profile
        ]
        if not members:
            raise ValueError("browser-egress qualification control profile is unused")
        managed_policies = {
            canonical_json_sha256(contract["managed_policy"]): contract["managed_policy"]
            for contract in members
        }
        if len(managed_policies) != 1:
            raise ValueError("browser-egress launch profile selects conflicting policies")
        control_profiles.append(
            {
                "launch_profile": profile,
                "managed_policy": next(iter(managed_policies.values())),
                "context_kinds": sorted({contract["context_kind"] for contract in members}),
                "resolver_profiles": sorted(
                    {contract["resolver_profile"] for contract in members}
                ),
                "vector_ids": [contract["vector_id"] for contract in members],
            }
        )
    return {
        "schema_version": ARGV_SCHEMA_VERSION,
        "artifact_type": "qcsd-browser-egress-chromium-argv-contract",
        "qualification_id": QUALIFICATION_ID,
        "playwright_version": PLAYWRIGHT_VERSION,
        "chromium_revision": EXPECTED_CHROMIUM_REVISION,
        "chromium_version": EXPECTED_CHROMIUM_VERSION,
        "chromium_executable": str(DEFAULT_CONFIGURED_EXECUTABLE),
        "chromium_executable_sha256": EXPECTED_CHROMIUM_SHA256,
        "chromium_archive_url": CHROMIUM_ARCHIVE_URL,
        "chromium_archive_sha256": CHROMIUM_ARCHIVE_SHA256,
        "chromium_subprocess_wrapper": {
            "path": str(DEFAULT_CHROMIUM_SUBPROCESS_WRAPPER),
            "sha256": EXPECTED_CHROMIUM_SUBPROCESS_WRAPPER_SHA256,
            "mode": f"0o{CHROMIUM_SUBPROCESS_WRAPPER_MODE:o}",
        },
        "chromium_managed_policy": {
            "path": str(DEFAULT_CHROMIUM_MANAGED_POLICY),
            "sha256": EXPECTED_CHROMIUM_MANAGED_POLICY_SHA256,
            "mode": f"0o{CHROMIUM_MANAGED_POLICY_MODE:o}",
            "managed_directory_file_count": 1,
            "sole_managed_policy": True,
            "value": {
                "DnsOverHttpsMode": CHROMIUM_DNS_OVER_HTTPS_MODE,
                "NetworkPredictionOptions": 2,
            },
        },
        "chromium_network_prediction_control_policy": {
            "source_path": (
                "config/class-study/v1/"
                "chromium-network-prediction-positive-control-v1.json"
            ),
            "seed_image_path": POLICY_VOLUME_SEED_SOURCE,
            "runtime_path": POLICY_VOLUME_POLICY_PATH,
            "sha256": EXPECTED_CHROMIUM_CONTROL_POLICY_SHA256,
            "mode": "0o444",
            "managed_directory_file_count": 1,
            "sole_managed_policy": True,
            "value": {
                "DnsOverHttpsMode": CHROMIUM_DNS_OVER_HTTPS_MODE,
                "NetworkPredictionOptions": 0,
            },
        },
        "fixture_certificate": {
            "source_path": FIXTURE_CERTIFICATE["path"],
            "runtime_path": FIXTURE_RUNTIME_CERTIFICATE,
            "sha256": FIXTURE_CERTIFICATE["sha256"],
            "spki_sha256_base64": FIXTURE_CERTIFICATE[
                "spki_sha256_base64"
            ],
            "mode": "0o444",
        },
        "fixture_private_key": {
            "source_path": FIXTURE_PRIVATE_KEY["path"],
            "runtime_path": FIXTURE_RUNTIME_PRIVATE_KEY,
            "sha256": FIXTURE_PRIVATE_KEY["sha256"],
            "mode": "0o400",
            "visible_to_browser": False,
        },
        "policy_root_inventory": [
            {
                "path": "/etc/chromium/policies/managed",
                "state": "sole-managed-policy",
                "file_count": 1,
            },
            {
                "path": "/etc/chromium/policies/recommended",
                "state": "empty-directory",
                "file_count": 0,
            },
            {
                "path": "/etc/opt/chrome/policies",
                "state": "absent",
                "file_count": 0,
            },
            {
                "path": "/etc/chromium-browser/policies",
                "state": "absent",
                "file_count": 0,
            },
        ],
        "qualification_control_profiles": control_profiles,
        "qualification_control_contracts_sha256": canonical_json_sha256(
            control_contracts
        ),
        "playwright_browsers_json_sha256": EXPECTED_BROWSERS_JSON_SHA256,
        "explicit_launch_arguments": list(BROWSER_EGRESS_EXPLICIT_CHROMIUM_ARGS),
        "qualification_launch_arguments": [qualification_launch[-1]],
        "required_effective_switches": list(BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES),
        "antagonistic_effective_switches": list(
            BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES
        ),
        "command_line_projection_schema_version": BROWSER_EGRESS_COMMAND_LINE_SCHEMA_VERSION,
        "accepted_executable_argv0": [
            str(DEFAULT_CONFIGURED_EXECUTABLE),
            str(DEFAULT_RESOLVED_EXECUTABLE),
        ],
        "effective_argv_source": "Browser.getBrowserCommandLine",
        "child_environment": dict(CHROMIUM_CHILD_ENVIRONMENT),
        "forbidden_driver_environment_variables": list(
            FORBIDDEN_DRIVER_ENVIRONMENT_VARIABLES
        ),
        "packet_level_admission_boundary": False,
    }


def validate_argv_config(value: object) -> dict[str, Any]:
    expected = expected_argv_config()
    if canonical_json_bytes(value) != canonical_json_bytes(expected):
        raise ValueError("browser-egress Chromium argv contract differs from frozen v1")
    return json.loads(canonical_json_bytes(value))


def _integer(value: object, *, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _canonical_build_completion_path(cohort_version: int) -> str:
    return f"/lab/artifacts/buflo-study/build-completion-v{cohort_version}.json"


def _current_build_completion_identity(
    build: Mapping[str, Any],
    *,
    lab_root: Path,
    cohort_version: int,
) -> tuple[str, str]:
    """Require and normalize the paired completion identity for current evidence."""

    completion_path = build.get("completion_path")
    expected = (
        Path(lab_root).resolve()
        / f"artifacts/buflo-study/build-completion-v{cohort_version}.json"
    )
    if (
        not isinstance(completion_path, str)
        or not Path(completion_path).is_absolute()
        or Path(completion_path).resolve() != expected
    ):
        raise ValueError("browser-egress build completion path differs from its cohort")
    return (
        _canonical_build_completion_path(cohort_version),
        _sha256(build.get("completion_sha256"), label="build completion SHA-256"),
    )


def _image_id(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _IMAGE.fullmatch(value) is None:
        raise ValueError(f"{label} must be an immutable Docker image ID")
    return value


def _timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        raise ValueError(f"{label} is not canonical UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError(f"{label} is not UTC")
    return parsed


def _canonical_relative(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"{label} path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{label} path is not canonical and relative")
    return value


def _safe_directory(path: Path, *, label: str, private: bool = False) -> Path:
    candidate = Path(os.path.abspath(path))
    cursor = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        cursor /= part
        try:
            component = cursor.lstat()
        except OSError as error:
            raise ValueError(f"{label} is unavailable") from error
        if cursor.is_symlink() or not stat.S_ISDIR(component.st_mode):
            raise ValueError(f"{label} has a non-directory or symlink component")
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise ValueError(f"{label} is unavailable") from error
    if candidate.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} is not a regular directory")
    if private and (
        metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE
    ):
        raise ValueError(f"{label} must be owned by the current user with mode 0700")
    return candidate


def _private_regular_file(
    path: Path, *, label: str, allowed_links: frozenset[int] = frozenset({1})
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE
        or metadata.st_nlink not in allowed_links
    ):
        links = "/".join(str(item) for item in sorted(allowed_links))
        raise ValueError(
            f"{label} must be a current-user mode-0600 regular file with {links} link(s)"
        )
    return metadata


def _durability_boundary(name: str) -> None:
    injector = _DURABILITY_FAULT_INJECTOR
    if injector is not None:
        injector(name)


def _new_temp_file(parent: Path, *, prefix: str, suffix: str) -> tuple[Path, int]:
    for _attempt in range(128):
        candidate = parent / f"{prefix}{secrets.token_hex(4)}{suffix}"
        try:
            descriptor = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                PRIVATE_FILE_MODE,
            )
        except FileExistsError:
            continue
        return candidate, descriptor
    raise FileExistsError("unable to allocate a unique browser-egress temporary path")


def write_create_only_json(path: Path, value: Any) -> Path:
    """Publish private canonical JSON create-only with recoverable boundaries."""

    destination = Path(os.path.abspath(path))
    parent = _safe_directory(destination.parent, label="create-only JSON parent", private=True)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"create-only JSON already exists: {destination}")
    encoded = canonical_json_bytes(value)
    temporary, descriptor = _new_temp_file(
        parent, prefix=f".{destination.name}.", suffix=".qcsd-tmp"
    )
    published = False
    try:
        try:
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _durability_boundary(f"create-only:{destination.name}:pre-link")
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError as error:
            raise FileExistsError(f"create-only JSON already exists: {destination}") from error
        published = True
        _fsync_directory(parent)
        _durability_boundary(f"create-only:{destination.name}:post-link")
        temporary.unlink()
        _fsync_directory(parent)
        _private_regular_file(destination, label="published create-only JSON")
        return destination
    except BaseException:
        # Normal exceptions leave no private scratch behind.  Process death at
        # either injected boundary deliberately bypasses this block and is
        # reconciled on resume.
        if temporary.exists() and not published:
            temporary.unlink()
            _fsync_directory(parent)
        elif temporary.exists() and published:
            # Preserve a post-link pair: deleting it here could hide ambiguity
            # if publication itself was interrupted by an unexpected error.
            pass
        raise


def atomic_json(path: Path, value: Any) -> None:
    """Durably replace one private checkpoint with recoverable scratch."""

    destination = Path(os.path.abspath(path))
    parent = _safe_directory(destination.parent, label="atomic JSON parent", private=True)
    encoded = canonical_json_bytes(value)
    temporary, descriptor = _new_temp_file(
        parent, prefix=f".{destination.name}.qcsd-tmp-", suffix=""
    )
    replaced = False
    try:
        try:
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _durability_boundary(f"atomic:{destination.name}:pre-replace")
        os.replace(temporary, destination)
        replaced = True
        _fsync_directory(parent)
        _durability_boundary(f"atomic:{destination.name}:post-replace")
        _private_regular_file(destination, label="published atomic JSON")
    finally:
        if not replaced and temporary.exists():
            temporary.unlink()
            _fsync_directory(parent)


def _rename_no_replace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for fail-closed publication")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(f"browser-egress qualification root exists: {destination}")
        raise OSError(error, os.strerror(error), destination)


def _file_binding(root: Path, relative: str) -> dict[str, Any]:
    path = safe_relative_artifact(root, relative, label="browser-egress bound file")
    return {
        "path": relative,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def validate_file_binding(
    value: object,
    *,
    expected_path: str | None = None,
    root: Path | None = None,
    deep: bool = False,
    label: str = "browser-egress file",
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"path", "sha256", "size_bytes"}:
        raise ValueError(f"{label} binding fields are invalid")
    path = _canonical_relative(value["path"], label=label)
    if expected_path is not None and path != expected_path:
        raise ValueError(f"{label} path differs from the contract")
    _sha256(value["sha256"], label=f"{label} SHA-256")
    _integer(value["size_bytes"], label=f"{label} size", minimum=1)
    if deep:
        if root is None:
            raise ValueError(f"deep {label} validation requires a root")
        actual = safe_relative_artifact(root, path, label=label)
        if actual.stat().st_size != value["size_bytes"] or sha256_file(actual) != value["sha256"]:
            raise ValueError(f"{label} binding does not verify")
    return json.loads(canonical_json_bytes(value))


def validate_source_binding(value: object, *, prepare_image_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != SOURCE_METADATA_KEYS:
        raise ValueError("browser-egress source binding fields are invalid")
    if value["image_digest"] != prepare_image_id:
        raise ValueError("browser-egress source metadata does not bind the prepare image")
    for key in ("lab_commit", "neqo_commit", "neqo_pinned_commit"):
        if not isinstance(value[key], str) or _COMMIT.fullmatch(value[key]) is None:
            raise ValueError(f"browser-egress source commit is invalid: {key}")
    if value["neqo_commit"] != value["neqo_pinned_commit"]:
        raise ValueError("browser-egress Rust checkout differs from its pinned commit")
    if value["lab_dirty"] is not False or value["neqo_dirty"] is not False:
        raise ValueError("browser-egress qualification requires clean source")
    if value["lab_patch_sha256"] != EMPTY_SHA256 or value["neqo_patch_sha256"] != EMPTY_SHA256:
        raise ValueError("browser-egress clean source has a non-empty patch hash")
    return json.loads(canonical_json_bytes(value))


def _browser_binding() -> dict[str, Any]:
    return {
        "playwright_version": PLAYWRIGHT_VERSION,
        "chromium_revision": EXPECTED_CHROMIUM_REVISION,
        "chromium_version": EXPECTED_CHROMIUM_VERSION,
        "chromium_executable": str(DEFAULT_CONFIGURED_EXECUTABLE),
        "chromium_executable_sha256": EXPECTED_CHROMIUM_SHA256,
        "playwright_browsers_json_sha256": EXPECTED_BROWSERS_JSON_SHA256,
        "playwright_driver_receipt_sha256": EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256,
        "playwright_driver_payload_sha256": EXPECTED_PLAYWRIGHT_DRIVER_PAYLOAD_SHA256,
        "playwright_driver_content_sha256": EXPECTED_PLAYWRIGHT_DRIVER_CONTENT_SHA256,
    }


def validate_build_docker_daemon_binding(value: object) -> dict[str, str]:
    """Validate the exact historical daemon projection in the build receipt."""

    if not isinstance(value, Mapping) or set(value) != BUILD_DOCKER_DAEMON_FIELDS:
        raise ValueError("browser-egress Docker daemon binding fields are invalid")
    if any(
        not isinstance(value[key], str) or not value[key]
        for key in BUILD_DOCKER_DAEMON_FIELDS
    ):
        raise ValueError("browser-egress Docker daemon binding is invalid")
    return json.loads(canonical_json_bytes(value))


def validate_docker_daemon_binding(value: object) -> dict[str, Any]:
    """Validate the full live daemon admission and capacity projection."""

    if not isinstance(value, Mapping) or set(value) != LIVE_DOCKER_DAEMON_FIELDS:
        raise ValueError("browser-egress live Docker daemon binding fields are invalid")
    string_fields = LIVE_DOCKER_DAEMON_FIELDS - {"ncpu", "mem_total_bytes"}
    if any(not isinstance(value[key], str) or not value[key] for key in string_fields):
        raise ValueError("browser-egress live Docker daemon binding is invalid")
    for key in ("ncpu", "mem_total_bytes"):
        if type(value[key]) is not int or value[key] <= 0:
            raise ValueError(f"browser-egress live Docker capacity is invalid: {key}")
    root = PurePosixPath(value["docker_root_dir"])
    if not root.is_absolute() or root.as_posix() != value["docker_root_dir"]:
        raise ValueError("browser-egress Docker root directory is not canonical")
    return json.loads(canonical_json_bytes(value))


def build_docker_daemon_projection(value: object) -> dict[str, str]:
    """Project a validated live daemon onto fields recorded by the build."""

    live = validate_docker_daemon_binding(value)
    return {key: live[key] for key in sorted(BUILD_DOCKER_DAEMON_FIELDS)}


def require_live_docker_daemon(
    value: object, *, expected: Mapping[str, Any]
) -> dict[str, Any]:
    """Fail closed unless a fresh live projection exactly matches a receipt."""

    live = validate_docker_daemon_binding(value)
    recorded = validate_docker_daemon_binding(expected)
    if live != recorded:
        raise ValueError("browser-egress live Docker daemon differs from its foundation")
    return live


def build_live_docker_daemon_binding(
    *,
    docker_version: object,
    docker_info: object,
    context: str,
    endpoint: str,
    pinned_server_id: str,
) -> dict[str, Any]:
    """Extract one strict live binding from Docker's version and info responses."""

    if not isinstance(docker_version, Mapping) or not isinstance(docker_info, Mapping):
        raise ValueError("browser-egress Docker version/info response is invalid")
    client = docker_version.get("Client")
    server = docker_version.get("Server")
    if not isinstance(client, Mapping) or not isinstance(server, Mapping):
        raise ValueError("browser-egress Docker version response is incomplete")
    if (
        not isinstance(context, str)
        or not context
        or not isinstance(endpoint, str)
        or not endpoint
        or not isinstance(pinned_server_id, str)
        or not pinned_server_id
        or client.get("Context") != context
        or docker_info.get("ID") != pinned_server_id
        or server.get("Version") != docker_info.get("ServerVersion")
        or server.get("Os") != docker_info.get("OSType")
    ):
        raise ValueError("browser-egress Docker response differs from its pinned endpoint")
    return validate_docker_daemon_binding(
        {
            "client_version": client.get("Version"),
            "server_version": server.get("Version"),
            "context": context,
            "endpoint": endpoint,
            "server_name": docker_info.get("Name"),
            "server_operating_system": docker_info.get("OperatingSystem"),
            "server_os_type": docker_info.get("OSType"),
            "server_architecture": docker_info.get("Architecture"),
            "server_id": docker_info.get("ID"),
            "ncpu": docker_info.get("NCPU"),
            "mem_total_bytes": docker_info.get("MemTotal"),
            "storage_driver": docker_info.get("Driver"),
            "docker_root_dir": docker_info.get("DockerRootDir"),
        }
    )


def build_foundation_payload(
    *,
    lab_root: Path,
    cohort_version: int,
    build_execution: Mapping[str, Any],
    prepare_repo_digests: Sequence[str],
    runtime_source: Mapping[str, Any],
    live_docker_daemon: Mapping[str, Any],
) -> dict[str, Any]:
    """Construct, but do not publish, one exact source/image/cohort foundation."""

    _integer(cohort_version, label="browser-egress cohort version", minimum=1)
    if not isinstance(build_execution, Mapping) or build_execution.get("passed") is not True:
        raise ValueError("validated no-cache build execution is required")
    if build_execution.get("cohort_version") != cohort_version:
        raise ValueError("browser-egress cohort version differs from its build")
    images = build_execution.get("images")
    if not isinstance(images, Mapping) or set(images) != {"collection", "prepare", "reference"}:
        raise ValueError("browser-egress build image roles are incomplete")
    prepare_id = _image_id(images["prepare"].get("id"), label="prepare image")
    build_path = Path(str(build_execution.get("path", "")))
    try:
        build_relative = build_path.resolve().relative_to(Path(lab_root).resolve()).as_posix()
    except (OSError, ValueError) as error:
        raise ValueError("browser-egress build receipt is outside the Lab root") from error
    source = validate_source_binding(runtime_source, prepare_image_id=prepare_id)
    root = _safe_directory(lab_root, label="Lab root")
    build_file_value = load_json(root / build_relative)
    if not isinstance(build_file_value, Mapping):
        raise ValueError("browser-egress build receipt is not a JSON object")
    build_payload_sha256 = _sha256(
        build_file_value.get("payload_sha256"), label="build execution payload SHA-256"
    )
    build_docker_daemon = validate_build_docker_daemon_binding(
        build_file_value.get("docker")
    )
    docker_daemon = validate_docker_daemon_binding(live_docker_daemon)
    if build_docker_daemon_projection(docker_daemon) != build_docker_daemon:
        raise ValueError(
            "browser-egress live Docker daemon differs from the no-cache build daemon"
        )
    completion_path, completion_sha256 = _current_build_completion_identity(
        build_execution,
        lab_root=root,
        cohort_version=cohort_version,
    )
    payload = {
        "schema_version": FOUNDATION_SCHEMA_VERSION,
        "qualification_id": QUALIFICATION_ID,
        "study_id": STUDY_ID,
        "cohort_version": cohort_version,
        "build_execution": {
            **_file_binding(root, build_relative),
            "payload_sha256": build_payload_sha256,
            "cohort_version": cohort_version,
            "completion_path": completion_path,
            "completion_sha256": completion_sha256,
            "collection_image_id": images["collection"]["id"],
            "prepare_image_id": prepare_id,
            "reference_image_id": images["reference"]["id"],
        },
        "prepare_image": {"id": prepare_id, "repo_digests": list(prepare_repo_digests)},
        "docker_daemon": docker_daemon,
        "source": source,
        "browser": _browser_binding(),
        "contracts": {
            "manifest": _file_binding(root, MANIFEST_RELATIVE_PATH),
            "argv": _file_binding(root, ARGV_RELATIVE_PATH),
            "expanded_vectors_sha256": expanded_vectors_sha256(),
            "fixture_contract_sha256": fixture_contract_sha256(),
        },
        "source_files": [
            _file_binding(root, relative) for relative in REQUIRED_SOURCE_BINDING_PATHS
        ],
        "execution_contract": EXECUTION_CONTRACT,
        "consumer_contract": CONSUMER_CONTRACT,
    }
    return validate_foundation_payload(payload)


def validate_foundation_payload(
    value: object, *, allow_historical: bool = False
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "qualification_id",
        "study_id",
        "cohort_version",
        "build_execution",
        "prepare_image",
        "docker_daemon",
        "source",
        "browser",
        "contracts",
        "source_files",
        "execution_contract",
        "consumer_contract",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("browser-egress foundation fields are invalid")
    cohort_version = _integer(
        value["cohort_version"], label="browser-egress cohort version", minimum=1
    )
    schema_version = value["schema_version"]
    if (
        type(schema_version) is not int
        or schema_version
        not in {HISTORICAL_FOUNDATION_SCHEMA_VERSION, FOUNDATION_SCHEMA_VERSION}
        or (
            schema_version == HISTORICAL_FOUNDATION_SCHEMA_VERSION
            and not allow_historical
        )
        or value["qualification_id"] != QUALIFICATION_ID
        or value["study_id"] != STUDY_ID
    ):
        raise ValueError("browser-egress foundation identity is invalid")
    build = value["build_execution"]
    build_fields = {
        "path",
        "sha256",
        "size_bytes",
        "payload_sha256",
        "cohort_version",
        "collection_image_id",
        "prepare_image_id",
        "reference_image_id",
    }
    if schema_version == FOUNDATION_SCHEMA_VERSION:
        build_fields.update({"completion_path", "completion_sha256"})
    if not isinstance(build, Mapping) or set(build) != build_fields:
        raise ValueError("browser-egress build binding fields are invalid")
    validate_file_binding(
        {key: build[key] for key in ("path", "sha256", "size_bytes")},
        label="browser-egress build receipt",
    )
    _sha256(build["payload_sha256"], label="build execution payload SHA-256")
    if build["cohort_version"] != cohort_version:
        raise ValueError("browser-egress build cohort version is invalid")
    if schema_version == FOUNDATION_SCHEMA_VERSION:
        _sha256(build["completion_sha256"], label="build completion SHA-256")
        if build["completion_path"] != _canonical_build_completion_path(cohort_version):
            raise ValueError("browser-egress build completion path is invalid")
    for key in ("collection_image_id", "prepare_image_id", "reference_image_id"):
        _image_id(build[key], label=key)
    if len({build[key] for key in ("collection_image_id", "prepare_image_id", "reference_image_id")}) != 3:
        raise ValueError("browser-egress build image roles are not distinct")
    image = value["prepare_image"]
    if not isinstance(image, Mapping) or set(image) != {"id", "repo_digests"}:
        raise ValueError("browser-egress prepare image fields are invalid")
    if _image_id(image["id"], label="prepare image") != build["prepare_image_id"]:
        raise ValueError("browser-egress prepare image binding is inconsistent")
    repo_digests = image["repo_digests"]
    if not isinstance(repo_digests, list) or any(
        not isinstance(item, str) or re.search(r"@sha256:[0-9a-f]{64}\Z", item) is None
        for item in repo_digests
    ):
        raise ValueError("browser-egress prepare image repo digests are invalid")
    validate_source_binding(value["source"], prepare_image_id=image["id"])
    validate_docker_daemon_binding(value["docker_daemon"])
    if value["browser"] != _browser_binding():
        raise ValueError("browser-egress pinned browser binding is invalid")
    contracts = value["contracts"]
    if not isinstance(contracts, Mapping) or set(contracts) != {
        "manifest",
        "argv",
        "expanded_vectors_sha256",
        "fixture_contract_sha256",
    }:
        raise ValueError("browser-egress contract binding fields are invalid")
    validate_file_binding(
        contracts["manifest"],
        expected_path=MANIFEST_RELATIVE_PATH,
        label="browser-egress manifest",
    )
    validate_file_binding(
        contracts["argv"], expected_path=ARGV_RELATIVE_PATH, label="browser-egress argv"
    )
    if (
        contracts["expanded_vectors_sha256"] != expanded_vectors_sha256()
        or contracts["fixture_contract_sha256"] != fixture_contract_sha256()
    ):
        raise ValueError("browser-egress generated contract digest is invalid")
    source_files = value["source_files"]
    if not isinstance(source_files, list) or len(source_files) != len(REQUIRED_SOURCE_BINDING_PATHS):
        raise ValueError("browser-egress source file inventory is incomplete")
    for binding, expected_path in zip(source_files, REQUIRED_SOURCE_BINDING_PATHS, strict=True):
        validate_file_binding(binding, expected_path=expected_path, label="browser-egress source")
    if canonical_json_bytes(value["execution_contract"]) != canonical_json_bytes(EXECUTION_CONTRACT):
        raise ValueError("browser-egress execution contract is invalid")
    if canonical_json_bytes(value["consumer_contract"]) != canonical_json_bytes(CONSUMER_CONTRACT):
        raise ValueError("browser-egress consumer contract is invalid")
    return json.loads(canonical_json_bytes(value))


def deep_validate_foundation(
    value: object,
    *,
    lab_root: Path,
    build_validator: Callable[..., Mapping[str, Any]] | None = None,
    mode: FoundationVerificationMode = FoundationVerificationMode.PORTABLE_REPLAY,
    allow_historical: bool = False,
) -> dict[str, Any]:
    """Re-hash immutable inputs, optionally admitting live prepare execution.

    Portable replay deliberately does not compare the current collection
    process to the prepare-image runtime.  Execution admission must run inside
    the exact prepare image and additionally measures live source metadata and
    the immutable Playwright/Chromium installation.
    """

    if not isinstance(mode, FoundationVerificationMode):
        raise ValueError("browser-egress foundation verification mode is invalid")

    payload = validate_foundation_payload(value, allow_historical=allow_historical)
    historical = payload["schema_version"] == HISTORICAL_FOUNDATION_SCHEMA_VERSION
    root = _safe_directory(lab_root, label="Lab root")
    contracts = payload["contracts"]
    validate_file_binding(
        contracts["manifest"],
        expected_path=MANIFEST_RELATIVE_PATH,
        root=root,
        deep=True,
        label="browser-egress manifest",
    )
    validate_file_binding(
        contracts["argv"],
        expected_path=ARGV_RELATIVE_PATH,
        root=root,
        deep=True,
        label="browser-egress argv",
    )
    validate_manifest_config(load_json(root / MANIFEST_RELATIVE_PATH))
    validate_argv_config(load_json(root / ARGV_RELATIVE_PATH))
    for binding, expected_path in zip(
        payload["source_files"], REQUIRED_SOURCE_BINDING_PATHS, strict=True
    ):
        validate_file_binding(
            binding,
            expected_path=expected_path,
            root=root,
            deep=True,
            label="browser-egress source",
        )
    build = payload["build_execution"]
    validate_file_binding(
        {key: build[key] for key in ("path", "sha256", "size_bytes")},
        root=root,
        deep=True,
        label="browser-egress build receipt",
    )
    build_file_value = load_json(root / build["path"])
    if (
        not isinstance(build_file_value, Mapping)
        or build_file_value.get("payload_sha256") != build["payload_sha256"]
        or validate_build_docker_daemon_binding(build_file_value.get("docker"))
        != build_docker_daemon_projection(payload["docker_daemon"])
    ):
        raise ValueError("browser-egress build payload binding does not verify")
    if build_validator is None:
        from .buflo_study import validate_build_execution_receipt

        build_validator = validate_build_execution_receipt
    validated_build = build_validator(
        root / build["path"],
        expected_cohort_version=payload["cohort_version"],
        allow_historical=historical,
    )
    expected_completion = (
        None
        if historical
        else _current_build_completion_identity(
            validated_build,
            lab_root=root,
            cohort_version=payload["cohort_version"],
        )
    )
    if (
        validated_build.get("sha256") != build["sha256"]
        or validated_build.get("cohort_version") != payload["cohort_version"]
        or (
            expected_completion is not None
            and (
                build["completion_path"] != expected_completion[0]
                or build["completion_sha256"] != expected_completion[1]
            )
        )
        or validated_build.get("images", {}).get("collection", {}).get("id")
        != build["collection_image_id"]
        or validated_build.get("images", {}).get("prepare", {}).get("id")
        != build["prepare_image_id"]
        or validated_build.get("images", {}).get("reference", {}).get("id")
        != build["reference_image_id"]
    ):
        raise ValueError("browser-egress build execution does not reproduce its binding")
    build_source = validated_build.get("source")
    if not isinstance(build_source, Mapping):
        raise ValueError("browser-egress build source binding is absent")
    source = payload["source"]
    for key in SOURCE_METADATA_KEYS - {"image_digest"}:
        if build_source.get(key) != source[key]:
            raise ValueError("browser-egress runtime source differs from its no-cache build")
    if mode is FoundationVerificationMode.EXECUTION:
        from .util import source_metadata

        if source_metadata() != source:
            raise ValueError("browser-egress live source metadata differs from its foundation")
        from .playwright_driver import (
            expected_playwright_driver_receipt,
            validate_default_playwright_driver_once,
        )

        validated_driver = validate_default_playwright_driver_once()
        if canonical_json_bytes(validated_driver) != canonical_json_bytes(
            expected_playwright_driver_receipt()
        ):
            raise ValueError("browser-egress pinned Playwright driver did not validate")
    return payload


def _policy_volume_required(vector_id: str) -> bool:
    contract = expected_browser_launch_contract(vector_by_id(vector_id))
    return contract["managed_policy"]["NetworkPredictionOptions"] == 0


def policy_volume_name(*, vector_id: str, attempt_topology: Mapping[str, Any]) -> str | None:
    """Return the only named policy volume authorised by a durable intent."""

    _topology_labels(vector_id=vector_id, topology=attempt_topology)
    if not _policy_volume_required(vector_id):
        return None
    return f"qcsd-be-{attempt_topology['topology_token']}-{POLICY_VOLUME_SUFFIX}"


def _expected_resolver_projection(contract: Mapping[str, Any]) -> dict[str, Any]:
    profile = contract["launch_profile"]
    keyword = {
        "approved_origins": contract["resolver_approved_origins"],
        "origin_ip_pins": contract["resolver_origin_ip_pins"],
        "approved_ip_exclusions": contract["resolver_approved_ip_exclusions"],
    }
    if profile == BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE:
        arguments = browser_egress_chromium_args(**keyword)
    else:
        arguments = browser_egress_qualification_control_chromium_args(
            launch_profile=profile,
            dns_exception_hostname=contract["dns_exception_hostname"],
            **keyword,
        )
    resolver = arguments[-1]
    if contract["dns_exception_hostname"] is None:
        return validate_fail_closed_host_resolver_argument(resolver)
    # Reuse the resolver producer's exact projection and compact hashing
    # domain.  Receipt JSON uses a separate indented canonical form, so
    # rebuilding this digest with ``canonical_json_bytes`` is not equivalent.
    return _validate_qualification_dns_control_resolver_argument(
        resolver,
        approved_origins=contract["resolver_approved_origins"],
        origin_ip_pins=contract["resolver_origin_ip_pins"],
        approved_ip_exclusions=contract["resolver_approved_ip_exclusions"],
        dns_exception_hostname=contract["dns_exception_hostname"],
    )


def _validate_effective_argv(
    value: object, *, vector_id: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "projection_sha256",
        "command_line_projection",
    }:
        raise ValueError("browser-egress effective argv binding fields are invalid")
    if value["schema_version"] != EFFECTIVE_ARGV_BINDING_SCHEMA_VERSION:
        raise ValueError("browser-egress effective argv binding schema is invalid")
    digest = _sha256(
        value["projection_sha256"],
        label="browser-egress effective argv projection",
    )
    projection = validate_browser_egress_command_line_projection(
        value["command_line_projection"]
    )
    contract = expected_browser_launch_contract(vector_by_id(vector_id))
    if (
        value["command_line_projection"] != projection
        or digest != canonical_json_sha256(projection)
        or projection["launch_profile"] != contract["launch_profile"]
        or projection["host_resolver_policy"]
        != _expected_resolver_projection(contract)
    ):
        raise ValueError("browser-egress effective argv projection is invalid")
    return json.loads(canonical_json_bytes(value))


def _validate_driver_runtime(value: object, *, vector_id: str) -> dict[str, Any]:
    fields = {
        "schema_version",
        "artifact_type",
        "production_receipt_sha256",
        "production_receipt_payload_sha256",
        "active_managed_policy",
        "dns_over_https_mode",
        "network_prediction_options",
        "semantics",
        "policy_directory_inventory",
        "qualification_only_policy_substitution",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("browser-egress driver runtime fields are invalid")
    contract = expected_browser_launch_contract(vector_by_id(vector_id))
    option = contract["managed_policy"]["NetworkPredictionOptions"]
    policy = (
        expected_argv_config()["chromium_network_prediction_control_policy"]
        if option == 0
        else expected_argv_config()["chromium_managed_policy"]
    )
    expected_active = {
        "path": POLICY_VOLUME_POLICY_PATH,
        "sha256": policy["sha256"],
        "mode": policy["mode"],
        "managed_directory_file_count": 1,
        "sole_managed_policy": True,
    }
    if (
        value["schema_version"] != 1
        or value["artifact_type"] != "qcsd-playwright-qualification-runtime"
        or value["production_receipt_sha256"]
        != EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256
        or value["production_receipt_payload_sha256"]
        != EXPECTED_PLAYWRIGHT_DRIVER_PAYLOAD_SHA256
        or value["active_managed_policy"] != expected_active
        or value["dns_over_https_mode"] != CHROMIUM_DNS_OVER_HTTPS_MODE
        or value["network_prediction_options"] != option
        or value["semantics"]
        != (
            "predict-on-any-connection-qualification-control"
            if option == 0
            else "never-predict"
        )
        or value["policy_directory_inventory"]
        != expected_argv_config()["policy_root_inventory"]
        or value["qualification_only_policy_substitution"] != (option == 0)
    ):
        raise ValueError("browser-egress driver runtime differs from its vector")
    return json.loads(canonical_json_bytes(value))


def _validate_policy_file_inventory(value: object) -> list[dict[str, Any]]:
    expected = [
        {
            "path": POLICY_VOLUME_POLICY_PATH,
            "name": POLICY_VOLUME_POLICY_FILENAME,
            "type": "regular",
            "uid": 0,
            "gid": 0,
            "mode": "0o444",
            "nlink": 1,
            "size_bytes": 56,
            "sha256": EXPECTED_CHROMIUM_CONTROL_POLICY_SHA256,
        }
    ]
    if value != expected:
        raise ValueError("browser-egress policy-volume file inventory is invalid")
    return json.loads(canonical_json_bytes(value))


def _validate_fixture_tls_runtime(
    value: object, *, foundation: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "certificate",
        "private_key",
    } or value["schema_version"] != 1:
        raise ValueError("browser-egress fixture TLS runtime fields are invalid")
    source_bindings = {
        binding["path"]: binding for binding in foundation["source_files"]
    }
    for field, source, runtime_path, mode in (
        (
            "certificate",
            FIXTURE_CERTIFICATE,
            FIXTURE_RUNTIME_CERTIFICATE,
            "0o444",
        ),
        (
            "private_key",
            FIXTURE_PRIVATE_KEY,
            FIXTURE_RUNTIME_PRIVATE_KEY,
            "0o400",
        ),
    ):
        record = value[field]
        binding = source_bindings.get(source["path"])
        if (
            not isinstance(record, Mapping)
            or set(record)
            != {"path", "sha256", "size_bytes", "uid", "gid", "mode", "nlink"}
            or binding is None
            or record["path"] != runtime_path
            or record["sha256"] != source["sha256"]
            or record["sha256"] != binding["sha256"]
            or record["size_bytes"] != binding["size_bytes"]
            or record["uid"] != 0
            or record["gid"] != 0
            or record["mode"] != mode
            or record["nlink"] != 1
        ):
            raise ValueError("browser-egress fixture TLS runtime is invalid")
    return json.loads(canonical_json_bytes(value))


def validate_docker_inspect_projection(
    value: object,
    *,
    vector_id: str,
    prepare_image_id: str,
    browser_uid: int,
    browser_gid: int,
    attempt_topology: Mapping[str, Any],
    docker_root_dir: str,
) -> dict[str, Any]:
    """Validate the content-minimised post-cleanup Docker/network inspection."""

    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "network",
        "containers",
        "policy_volume",
    }:
        raise ValueError("browser-egress Docker inspection fields are invalid")
    if value["schema_version"] != DOCKER_INSPECT_PROJECTION_SCHEMA_VERSION:
        raise ValueError("browser-egress Docker inspection schema is invalid")
    daemon_root = PurePosixPath(docker_root_dir)
    if not daemon_root.is_absolute() or daemon_root.as_posix() != docker_root_dir:
        raise ValueError("browser-egress Docker root directory is invalid")
    network = value["network"]
    expected_network_fields = {
        "id",
        "name",
        "driver",
        "internal",
        "attachable",
        "enable_ipv6",
        "ipam_config",
        "labels",
        "members",
    }
    if not isinstance(network, Mapping) or set(network) != expected_network_fields:
        raise ValueError("browser-egress network inspection fields are invalid")
    if (
        not isinstance(network["id"], str)
        or _CONTAINER.fullmatch(network["id"]) is None
        or network["name"] != FIXTURE_TOPOLOGY["network"]["name"]
        or network["driver"] != "bridge"
        or network["internal"] is not True
        or network["attachable"] is not False
        or network["enable_ipv6"] is not True
        or network["ipam_config"]
        != [
            {"subnet": FIXTURE_TOPOLOGY["network"]["ipv4_subnet"]},
            {"subnet": FIXTURE_TOPOLOGY["network"]["ipv6_subnet"]},
        ]
        or network["labels"]
        != _topology_labels(vector_id=vector_id, topology=attempt_topology)
    ):
        raise ValueError("browser-egress isolated network inspection is invalid")
    containers = value["containers"]
    roles = ("browser", "observer", "fixture", "forbidden_sink", "dns_sink")
    direct_roles = ("browser", "fixture", "forbidden_sink", "dns_sink")
    if not isinstance(containers, Mapping) or set(containers) != set(roles):
        raise ValueError("browser-egress Docker role inspection is incomplete")
    members = network["members"]
    if not isinstance(members, Mapping) or set(members) != set(direct_roles):
        raise ValueError("browser-egress network membership is incomplete")
    expected_addresses = {
        "browser": (
            FIXTURE_TOPOLOGY["browser_addresses"][0],
            FIXTURE_TOPOLOGY["browser_addresses"][1],
        ),
        "observer": (None, None),
        "fixture": (
            FIXTURE_TOPOLOGY["fixture_addresses"][0],
            FIXTURE_TOPOLOGY["fixture_addresses"][1],
        ),
        "forbidden_sink": (
            FIXTURE_TOPOLOGY["forbidden_sink_addresses"][0],
            FIXTURE_TOPOLOGY["forbidden_sink_addresses"][1],
        ),
        "dns_sink": (
            FIXTURE_TOPOLOGY["dns_sink_addresses"][0],
            FIXTURE_TOPOLOGY["dns_sink_addresses"][1],
        ),
    }
    ids: list[str] = []
    endpoint_ids: dict[str, str] = {}
    browser_record = containers.get("browser")
    browser_id = (
        browser_record.get("id") if isinstance(browser_record, Mapping) else None
    )
    for role in roles:
        record = containers[role]
        fields = {
            "id",
            "image_id",
            "user",
            "privileged",
            "read_only_root",
            "cap_add",
            "cap_drop",
            "security_options",
            "network_mode",
            "network_attachments",
            "ipv4_address",
            "ipv6_address",
            "labels",
            "mounts",
            "tmpfs",
            "dns_servers",
            "running",
            "exit_code",
        }
        if not isinstance(record, Mapping) or set(record) != fields:
            raise ValueError(f"browser-egress {role} inspect fields are invalid")
        identifier = record["id"]
        if not isinstance(identifier, str) or _CONTAINER.fullmatch(identifier) is None:
            raise ValueError(f"browser-egress {role} container ID is invalid")
        ids.append(identifier)
        expected_user = f"{browser_uid}:{browser_gid}" if role == "browser" else "0:0"
        expected_mode = (
            f"container:{browser_id}"
            if role == "observer"
            else FIXTURE_TOPOLOGY["network"]["name"]
        )
        expected_mounts: list[dict[str, Any]] = []
        if role == "browser" and _policy_volume_required(vector_id):
            expected_mounts.append(
                {
                    "type": "volume",
                    "name": policy_volume_name(
                        vector_id=vector_id, attempt_topology=attempt_topology
                    ),
                    "destination": POLICY_VOLUME_MANAGED_DIRECTORY,
                    "rw": False,
                }
            )
        expected_tmpfs = [
            {
                "destination": "/tmp",
                "options": ROLE_TMPFS_OPTIONS,
            }
        ]
        if role != "fixture":
            expected_tmpfs.append(
                {
                    "destination": FIXTURE_TLS_MASK_DIRECTORY,
                    "options": FIXTURE_TLS_MASK_TMPFS_OPTIONS,
                }
            )
        expected_tmpfs.sort(key=lambda item: item["destination"])
        attachments = record["network_attachments"]
        if not isinstance(attachments, list):
            raise ValueError(f"browser-egress {role} network attachments are invalid")
        if role == "observer":
            if attachments:
                raise ValueError(
                    "browser-egress observer must use only the browser network namespace"
                )
        else:
            attachment_fields = {
                "name",
                "network_id",
                "endpoint_id",
                "ipv4_address",
                "ipv6_address",
            }
            if (
                len(attachments) != 1
                or not isinstance(attachments[0], Mapping)
                or set(attachments[0]) != attachment_fields
            ):
                raise ValueError(
                    f"browser-egress {role} must have one exact network attachment"
                )
            attachment = attachments[0]
            endpoint_id = attachment["endpoint_id"]
            if (
                attachment["name"] != FIXTURE_TOPOLOGY["network"]["name"]
                or attachment["network_id"] != network["id"]
                or not isinstance(endpoint_id, str)
                or _CONTAINER.fullmatch(endpoint_id) is None
                or (attachment["ipv4_address"], attachment["ipv6_address"])
                != expected_addresses[role]
            ):
                raise ValueError(
                    f"browser-egress {role} network attachment differs from the isolated network"
                )
            endpoint_ids[role] = endpoint_id
        if (
            record["image_id"] != prepare_image_id
            or record["user"] != expected_user
            or record["privileged"] is not False
            or record["read_only_root"] is not True
            or record["cap_add"] != (["CAP_NET_RAW"] if role == "observer" else [])
            or record["cap_drop"] != ["ALL"]
            or record["security_options"] != ["no-new-privileges:true"]
            or record["network_mode"] != expected_mode
            or (record["ipv4_address"], record["ipv6_address"])
            != expected_addresses[role]
            or record["labels"]
            != _topology_labels(
                vector_id=vector_id,
                topology=attempt_topology,
                include_role=role,
            )
            or record["mounts"] != sorted(
                expected_mounts, key=lambda mount: mount["destination"]
            )
            or record["tmpfs"] != expected_tmpfs
            or record["dns_servers"]
            != (FIXTURE_TOPOLOGY["browser_dns_servers"] if role == "browser" else [])
            or record["running"] is not False
            or type(record["exit_code"]) is not int
            or record["exit_code"] != 0
        ):
            raise ValueError(f"browser-egress {role} runtime isolation is invalid")
    if len(set(ids)) != len(roles):
        raise ValueError("browser-egress Docker roles did not use distinct containers")
    if len(set(endpoint_ids.values())) != len(direct_roles):
        raise ValueError("browser-egress direct Docker endpoints are not distinct")
    ipv4_prefix = FIXTURE_TOPOLOGY["network"]["ipv4_subnet"].rsplit("/", 1)[1]
    ipv6_prefix = FIXTURE_TOPOLOGY["network"]["ipv6_subnet"].rsplit("/", 1)[1]
    for role in direct_roles:
        member = members[role]
        if not isinstance(member, Mapping) or set(member) != {
            "container_id",
            "endpoint_id",
            "ipv4_address",
            "ipv6_address",
        }:
            raise ValueError(f"browser-egress {role} network member fields are invalid")
        ipv4_address, ipv6_address = expected_addresses[role]
        if (
            member["container_id"] != containers[role]["id"]
            or member["endpoint_id"] != endpoint_ids[role]
            or member["ipv4_address"] != f"{ipv4_address}/{ipv4_prefix}"
            or member["ipv6_address"] != f"{ipv6_address}/{ipv6_prefix}"
        ):
            raise ValueError(
                f"browser-egress {role} network membership differs from its endpoint"
            )
    expected_volume_name = policy_volume_name(
        vector_id=vector_id, attempt_topology=attempt_topology
    )
    volume = value["policy_volume"]
    if expected_volume_name is None:
        if volume is not None:
            raise ValueError("browser-egress vector has an unauthorised policy volume")
    else:
        volume_fields = {
            "schema_version",
            "name",
            "driver",
            "scope",
            "labels",
            "options",
            "mountpoint_is_canonical",
            "mountpoint_sha256",
            "file_inventory",
        }
        expected_mountpoint = (
            PurePosixPath(docker_root_dir)
            / "volumes"
            / expected_volume_name
            / "_data"
        ).as_posix()
        if (
            not isinstance(volume, Mapping)
            or set(volume) != volume_fields
            or volume["schema_version"] != POLICY_VOLUME_PROJECTION_SCHEMA_VERSION
            or volume["name"] != expected_volume_name
            or volume["driver"] != "local"
            or volume["scope"] != "local"
            or volume["labels"]
            != _topology_labels(
                vector_id=vector_id,
                topology=attempt_topology,
                include_role=POLICY_VOLUME_ROLE,
            )
            or volume["options"] != {}
            or volume["mountpoint_is_canonical"] is not True
            or volume["mountpoint_sha256"]
            != hashlib.sha256(expected_mountpoint.encode("utf-8")).hexdigest()
        ):
            raise ValueError("browser-egress policy volume inspection is invalid")
        _validate_policy_file_inventory(volume["file_inventory"])
    return json.loads(canonical_json_bytes(value))


def validate_runtime_binding(
    value: object,
    *,
    foundation: Mapping[str, Any],
    vector_id: str,
    global_ordinal: int,
    attempt_number: int,
    started_at: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "prepare_image_id",
        "docker_daemon",
        "source",
        "browser",
        "effective_argv",
        "driver_runtime",
        "fixture_tls_runtime",
        "child_environment",
        "browser_identity",
        "attempt_topology",
        "subject_kind",
        "docker_inspect",
        "fixture_contract_sha256",
    }:
        raise ValueError("browser-egress runtime binding fields are invalid")
    if (
        value["prepare_image_id"] != foundation["prepare_image"]["id"]
        or value["docker_daemon"] != foundation["docker_daemon"]
        or value["source"] != foundation["source"]
        or value["browser"] != foundation["browser"]
        or value["child_environment"] != expected_argv_config()["child_environment"]
        or value["fixture_contract_sha256"] != fixture_contract_sha256()
    ):
        raise ValueError("browser-egress runtime differs from its foundation")
    vector = vector_by_id(vector_id)
    expected_topology = build_attempt_topology_binding(
        foundation=foundation,
        global_ordinal=global_ordinal,
        attempt_number=attempt_number,
        vector_id=vector.vector_id,
        started_at=started_at,
    )
    if value["attempt_topology"] != expected_topology:
        raise ValueError("browser-egress runtime attempt topology is invalid")
    expected_subject = (
        "idle-chromium-plus-independent-control-emitter"
        if vector.family == "positive-control"
        else "chromium-browser"
    )
    if value["subject_kind"] != expected_subject:
        raise ValueError("browser-egress subject kind differs from its vector")
    _validate_effective_argv(value["effective_argv"], vector_id=vector.vector_id)
    _validate_driver_runtime(value["driver_runtime"], vector_id=vector.vector_id)
    _validate_fixture_tls_runtime(value["fixture_tls_runtime"], foundation=foundation)
    identity = value["browser_identity"]
    if not isinstance(identity, Mapping) or set(identity) != {"uid", "gid"}:
        raise ValueError("browser-egress browser identity fields are invalid")
    if (
        type(identity["uid"]) is not int
        or type(identity["gid"]) is not int
        or identity["uid"] <= 0
        or identity["gid"] <= 0
    ):
        raise ValueError("browser-egress browser identity must be numeric and non-root")
    validate_docker_inspect_projection(
        value["docker_inspect"],
        vector_id=vector_id,
        prepare_image_id=foundation["prepare_image"]["id"],
        browser_uid=identity["uid"],
        browser_gid=identity["gid"],
        attempt_topology=expected_topology,
        docker_root_dir=foundation["docker_daemon"]["docker_root_dir"],
    )
    return json.loads(canonical_json_bytes(value))


def _validate_failure_evidence(
    value: object, *, evidence_root: Path | None, deep: bool
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"diagnostic_code", "artifacts"}:
        raise ValueError("browser-egress failure evidence fields are invalid")
    if not isinstance(value["diagnostic_code"], str) or _CODE.fullmatch(value["diagnostic_code"]) is None:
        raise ValueError("browser-egress failure diagnostic code is invalid")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list):
        raise ValueError("browser-egress failure artifact inventory is invalid")
    paths: list[str] = []
    for binding in artifacts:
        validated = validate_file_binding(
            binding,
            root=evidence_root,
            deep=deep,
            label="browser-egress failure artifact",
        )
        paths.append(validated["path"])
    if paths != sorted(set(paths)):
        raise ValueError("browser-egress failure artifacts are unordered or duplicated")
    return json.loads(canonical_json_bytes(value))


def validate_result_payload(
    value: object,
    *,
    foundation: Mapping[str, Any],
    evidence_root: Path | None = None,
    deep: bool = False,
    tshark: Path = Path("/usr/bin/tshark"),
    dumpcap: Path = Path("/usr/bin/dumpcap"),
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "qualification_id",
        "foundation_payload_sha256",
        "global_ordinal",
        "attempt_number",
        "previous_result_sha256",
        "vector",
        "started_at",
        "finished_at",
        "verdict",
        "failure_code",
        "runtime",
        "semantic",
        "fixture",
        "sink",
        "capture",
        "failure_evidence",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("browser-egress vector-result fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != RESULT_SCHEMA_VERSION
        or value["qualification_id"] != QUALIFICATION_ID
        or value["foundation_payload_sha256"] != canonical_json_sha256(foundation)
    ):
        raise ValueError("browser-egress vector-result identity is invalid")
    _integer(value["global_ordinal"], label="browser-egress result ordinal", minimum=1)
    _integer(value["attempt_number"], label="browser-egress attempt number", minimum=1)
    if value["attempt_number"] > MAX_OPERATIONAL_ATTEMPTS:
        raise ValueError("browser-egress attempt exceeds the frozen retry limit")
    _sha256(value["previous_result_sha256"], label="previous browser-egress result")
    vector = validate_vector(value["vector"])
    started = _timestamp(value["started_at"], label="browser-egress attempt start")
    finished = _timestamp(value["finished_at"], label="browser-egress attempt finish")
    if finished < started:
        raise ValueError("browser-egress result finishes before it starts")
    verdict = value["verdict"]
    if verdict not in {"passed", "operational-failure", "semantic-failure"}:
        raise ValueError("browser-egress result verdict is invalid")
    if verdict == "passed":
        if value["failure_code"] is not None or value["failure_evidence"] is not None:
            raise ValueError("passed browser-egress vector carries failure evidence")
        runtime = validate_runtime_binding(
            value["runtime"],
            foundation=foundation,
            vector_id=vector.vector_id,
            global_ordinal=value["global_ordinal"],
            attempt_number=value["attempt_number"],
            started_at=value["started_at"],
        )
        semantic = validate_semantic_observation(value["semantic"], vector=vector)
        configuration = semantic["measurement"]["configuration_observation"]
        if vector.surface in {"proxy", "pac"}:
            proxy_environment = sorted(
                key
                for key in runtime["child_environment"]
                if key in PROXY_ENVIRONMENT_KEYS
            )
            if configuration != {
                "surface": vector.surface,
                "effective_argv_projection_sha256": runtime["effective_argv"][
                    "projection_sha256"
                ],
                "child_environment_sha256": canonical_json_sha256(
                    runtime["child_environment"]
                ),
                "no_proxy_server_argument_count": 1,
                "antagonistic_proxy_switches_present": [],
                "proxy_environment_keys_present": proxy_environment,
            } or (
                configuration["no_proxy_server_argument_count"] != 1
                or configuration["antagonistic_proxy_switches_present"] != []
                or configuration["proxy_environment_keys_present"] != []
            ):
                raise ValueError(
                    "browser-egress proxy/PAC observation differs from measured runtime"
                )
        fixture = validate_fixture_observation(value["fixture"], vector=vector)
        sink = validate_sink_receipt(value["sink"], vector=vector)
        capture = validate_capture_receipt(
            value["capture"],
            vector=vector,
            evidence_root=evidence_root,
            deep=deep,
            tshark=tshark,
            dumpcap=dumpcap,
        )
        expected_pcap = (
            f"{EVIDENCE_DIRECTORY}/{vector.ordinal:03d}--{vector.vector_id}/"
            f"attempt-{value['attempt_number']}/capture.pcapng"
        )
        if capture["pcap"]["path"] != expected_pcap:
            raise ValueError("browser-egress PCAP path differs from the vector/attempt inventory")
        reconcile_sink_and_packet_evidence(vector=vector, analysis=capture["analysis"], sink=sink)
        semantic_times = {
            entry["event"]: entry["monotonic_ns"] for entry in semantic["chronology"]
        }
        capture_times = capture["chronology"]
        if (
            semantic_times["observer-ready"] != capture_times["observer_ready_ns"]
            or capture_times["subject_started_ns"]
            > semantic_times["browser-started"]
            or semantic_times["browser-exited"]
            > capture_times["subject_exited_ns"]
            or semantic_times["reporting-grace-finished"]
            != capture_times["reporting_grace_finished_ns"]
            or semantic_times["observer-stopped"] != capture_times["observer_stopped_ns"]
        ):
            raise ValueError("browser-egress semantic and packet chronologies disagree")
        fixture_times = fixture["chronology"]
        sink_times = sink["chronology"]
        if not (
            fixture_times["ready_ns"] <= semantic_times["sinks-ready"]
            and capture_times["reporting_grace_finished_ns"]
            <= fixture_times["stopped_ns"]
            <= capture_times["observer_stopped_ns"]
            and max(
                sink_times["forbidden_ready_ns"], sink_times["dns_ready_ns"]
            )
            == semantic_times["sinks-ready"]
            and capture_times["reporting_grace_finished_ns"]
            <= sink_times["forbidden_stopped_ns"]
            <= capture_times["observer_stopped_ns"]
            and capture_times["reporting_grace_finished_ns"]
            <= sink_times["dns_stopped_ns"]
            <= capture_times["observer_stopped_ns"]
        ):
            raise ValueError("browser-egress fixture/sinks did not span the measured lifetime")
        if (
            runtime != value["runtime"]
            or semantic != value["semantic"]
            or fixture != value["fixture"]
        ):
            raise ValueError("browser-egress result evidence is not canonical")
    else:
        failure_code = value["failure_code"]
        if failure_code not in FAILURE_CODES:
            raise ValueError("browser-egress result failure code is invalid")
        if verdict == "operational-failure" and failure_code not in {
            "browser-start-failed",
            "capture-process-failed",
            "docker-start-failed",
            "infrastructure-timeout",
            "interrupted",
            "observer-start-failed",
        }:
            raise ValueError("semantic failure was misclassified as operational")
        if verdict == "semantic-failure" and failure_code in {
            "browser-start-failed",
            "docker-start-failed",
            "infrastructure-timeout",
            "interrupted",
            "observer-start-failed",
        }:
            raise ValueError("operational failure was misclassified as semantic")
        _validate_failure_evidence(
            value["failure_evidence"], evidence_root=evidence_root, deep=deep
        )
        expected_prefix = (
            f"{EVIDENCE_DIRECTORY}/{vector.ordinal:03d}--{vector.vector_id}/"
            f"attempt-{value['attempt_number']}/"
        )
        if any(
            not binding["path"].startswith(expected_prefix)
            for binding in value["failure_evidence"]["artifacts"]
        ):
            raise ValueError("browser-egress failure artifact path differs from its attempt")
        # Failure receipts retain raw files through explicit bindings.  They do
        # not promote partial observations into passing evidence.
        for key in ("runtime", "semantic", "fixture", "sink", "capture"):
            if value[key] is not None:
                raise ValueError("failed browser-egress result contains unvalidated inline evidence")
    return json.loads(canonical_json_bytes(value))


def build_passed_result_receipt(
    *,
    foundation: Mapping[str, Any],
    global_ordinal: int,
    attempt_number: int,
    previous_result_sha256: str,
    vector_id: str,
    started_at: str,
    finished_at: str,
    runtime: Mapping[str, Any],
    semantic: Mapping[str, Any],
    fixture: Mapping[str, Any],
    sink: Mapping[str, Any],
    capture: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a validated hash-bound passing result from live role outputs."""

    validated_foundation = validate_foundation_payload(foundation)
    payload = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "qualification_id": QUALIFICATION_ID,
        "foundation_payload_sha256": canonical_json_sha256(validated_foundation),
        "global_ordinal": global_ordinal,
        "attempt_number": attempt_number,
        "previous_result_sha256": previous_result_sha256,
        "vector": vector_by_id(vector_id).as_dict(),
        "started_at": started_at,
        "finished_at": finished_at,
        "verdict": "passed",
        "failure_code": None,
        "runtime": dict(runtime),
        "semantic": dict(semantic),
        "fixture": dict(fixture),
        "sink": dict(sink),
        "capture": dict(capture),
        "failure_evidence": None,
    }
    validated = validate_result_payload(payload, foundation=validated_foundation)
    return bind_receipt(validated, receipt_type=RESULT_RECEIPT_TYPE)


def build_failure_result_receipt(
    *,
    foundation: Mapping[str, Any],
    global_ordinal: int,
    attempt_number: int,
    previous_result_sha256: str,
    vector_id: str,
    started_at: str,
    finished_at: str,
    verdict: str,
    failure_code: str,
    failure_artifacts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build a validated failure receipt without promoting partial evidence."""

    validated_foundation = validate_foundation_payload(foundation)
    payload = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "qualification_id": QUALIFICATION_ID,
        "foundation_payload_sha256": canonical_json_sha256(validated_foundation),
        "global_ordinal": global_ordinal,
        "attempt_number": attempt_number,
        "previous_result_sha256": previous_result_sha256,
        "vector": vector_by_id(vector_id).as_dict(),
        "started_at": started_at,
        "finished_at": finished_at,
        "verdict": verdict,
        "failure_code": failure_code,
        "runtime": None,
        "semantic": None,
        "fixture": None,
        "sink": None,
        "capture": None,
        "failure_evidence": {
            "diagnostic_code": failure_code,
            "artifacts": [dict(binding) for binding in failure_artifacts],
        },
    }
    validated = validate_result_payload(payload, foundation=validated_foundation)
    return bind_receipt(validated, receipt_type=RESULT_RECEIPT_TYPE)


def _initial_checkpoint(*, foundation_file_sha256: str, foundation_payload_sha256: str) -> dict[str, Any]:
    return {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "artifact_type": "qcsd-browser-egress-qualification-checkpoint",
        "qualification_id": QUALIFICATION_ID,
        "foundation": {
            "path": FOUNDATION_FILENAME,
            "sha256": foundation_file_sha256,
            "payload_sha256": foundation_payload_sha256,
        },
        "expanded_vectors_sha256": expanded_vectors_sha256(),
        "attempts": [],
        "passed_vector_ids": [],
        "next_vector_ordinal": 1,
        "chain_head_sha256": ZERO_DIGEST,
        "status": "running",
        "terminal_failure": None,
    }


def _advance_checkpoint(
    checkpoint: Mapping[str, Any], *, result: Mapping[str, Any], receipt_binding: Mapping[str, Any]
) -> dict[str, Any]:
    if checkpoint["status"] != "running":
        raise ValueError("browser-egress checkpoint is already terminal")
    vectors = inventory_json()
    next_ordinal = checkpoint["next_vector_ordinal"]
    if next_ordinal < 1 or next_ordinal > VECTOR_COUNT:
        raise ValueError("browser-egress checkpoint has no valid next vector")
    expected_vector = vectors[next_ordinal - 1]
    previous_attempts = [
        item for item in checkpoint["attempts"] if item["vector_id"] == expected_vector["vector_id"]
    ]
    expected_attempt = len(previous_attempts) + 1
    expected_global = len(checkpoint["attempts"]) + 1
    if (
        result["vector"] != expected_vector
        or result["attempt_number"] != expected_attempt
        or result["global_ordinal"] != expected_global
        or result["previous_result_sha256"] != checkpoint["chain_head_sha256"]
    ):
        raise ValueError("browser-egress result is out of order or breaks its chain")
    entry = {
        "global_ordinal": expected_global,
        "vector_ordinal": next_ordinal,
        "vector_id": expected_vector["vector_id"],
        "attempt_number": expected_attempt,
        "verdict": result["verdict"],
        "started_at": result["started_at"],
        "finished_at": result["finished_at"],
        "path": receipt_binding["path"],
        "sha256": receipt_binding["sha256"],
        "payload_sha256": receipt_binding["payload_sha256"],
    }
    updated = json.loads(canonical_json_bytes(checkpoint))
    if updated["attempts"]:
        previous_finished = _timestamp(
            updated["attempts"][-1]["finished_at"], label="previous browser-egress finish"
        )
        if _timestamp(result["started_at"], label="browser-egress result start") < previous_finished:
            raise ValueError("browser-egress attempts overlap or regress in wall-clock time")
    updated["attempts"].append(entry)
    updated["chain_head_sha256"] = receipt_binding["sha256"]
    verdict = result["verdict"]
    if verdict == "passed":
        updated["passed_vector_ids"].append(expected_vector["vector_id"])
        if next_ordinal == VECTOR_COUNT:
            updated["next_vector_ordinal"] = None
            updated["status"] = "complete"
        else:
            updated["next_vector_ordinal"] = next_ordinal + 1
    elif verdict == "semantic-failure" or expected_attempt == MAX_OPERATIONAL_ATTEMPTS:
        updated["status"] = "failed"
        updated["terminal_failure"] = {
            "vector_id": expected_vector["vector_id"],
            "attempt_number": expected_attempt,
            "verdict": verdict,
            "failure_code": result["failure_code"],
        }
    return updated


def validate_checkpoint(value: object, *, foundation_binding: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "schema_version",
        "artifact_type",
        "qualification_id",
        "foundation",
        "expanded_vectors_sha256",
        "attempts",
        "passed_vector_ids",
        "next_vector_ordinal",
        "chain_head_sha256",
        "status",
        "terminal_failure",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("browser-egress checkpoint fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != CHECKPOINT_SCHEMA_VERSION
        or value["artifact_type"] != "qcsd-browser-egress-qualification-checkpoint"
        or value["qualification_id"] != QUALIFICATION_ID
        or value["foundation"] != foundation_binding
        or value["expanded_vectors_sha256"] != expanded_vectors_sha256()
        or value["status"] not in {"running", "failed", "complete"}
    ):
        raise ValueError("browser-egress checkpoint identity is invalid")
    _sha256(value["chain_head_sha256"], label="browser-egress checkpoint chain head")
    if not isinstance(value["attempts"], list) or not isinstance(value["passed_vector_ids"], list):
        raise ValueError("browser-egress checkpoint inventories are invalid")
    if value["next_vector_ordinal"] is not None:
        _integer(value["next_vector_ordinal"], label="next browser-egress vector", minimum=1)
    expected_ids = [row["vector_id"] for row in inventory_json()]
    passed: list[str] = []
    per_vector_attempts: dict[str, int] = {}
    for global_ordinal, entry in enumerate(value["attempts"], 1):
        if not isinstance(entry, Mapping) or set(entry) != {
            "global_ordinal",
            "vector_ordinal",
            "vector_id",
            "attempt_number",
            "verdict",
            "started_at",
            "finished_at",
            "path",
            "sha256",
            "payload_sha256",
        }:
            raise ValueError("browser-egress checkpoint attempt fields are invalid")
        vector_ordinal = _integer(
            entry["vector_ordinal"], label="checkpoint vector ordinal", minimum=1
        )
        if (
            type(entry["global_ordinal"]) is not int
            or entry["global_ordinal"] != global_ordinal
            or vector_ordinal > VECTOR_COUNT
            or entry["vector_id"] != expected_ids[vector_ordinal - 1]
            or entry["path"] != f"{ATTEMPT_DIRECTORY}/result-{global_ordinal:04d}.json"
            or entry["verdict"] not in {"passed", "operational-failure", "semantic-failure"}
        ):
            raise ValueError("browser-egress checkpoint attempt identity is invalid")
        expected_attempt = per_vector_attempts.get(entry["vector_id"], 0) + 1
        if type(entry["attempt_number"]) is not int or entry["attempt_number"] != expected_attempt:
            raise ValueError("browser-egress checkpoint attempt number is invalid")
        per_vector_attempts[entry["vector_id"]] = expected_attempt
        if expected_attempt > MAX_OPERATIONAL_ATTEMPTS:
            raise ValueError("browser-egress checkpoint exceeds its retry limit")
        if _timestamp(entry["finished_at"], label="checkpoint finish") < _timestamp(
            entry["started_at"], label="checkpoint start"
        ):
            raise ValueError("browser-egress checkpoint attempt chronology is invalid")
        _sha256(entry["sha256"], label="checkpoint result")
        _sha256(entry["payload_sha256"], label="checkpoint result payload")
        if entry["verdict"] == "passed":
            passed.append(entry["vector_id"])
    if value["passed_vector_ids"] != passed or passed != expected_ids[: len(passed)]:
        raise ValueError("browser-egress checkpoint passed vectors are not a manifest prefix")
    expected_head = ZERO_DIGEST if not value["attempts"] else value["attempts"][-1]["sha256"]
    if value["chain_head_sha256"] != expected_head:
        raise ValueError("browser-egress checkpoint chain head is invalid")
    if value["status"] == "complete":
        if len(passed) != VECTOR_COUNT or value["next_vector_ordinal"] is not None or value[
            "terminal_failure"
        ] is not None:
            raise ValueError("completed browser-egress checkpoint is inconsistent")
    elif value["status"] == "running":
        if value["next_vector_ordinal"] != len(passed) + 1 or value["terminal_failure"] is not None:
            raise ValueError("running browser-egress checkpoint is inconsistent")
    else:
        terminal = value["terminal_failure"]
        if not isinstance(terminal, Mapping) or set(terminal) != {
            "vector_id",
            "attempt_number",
            "verdict",
            "failure_code",
        } or not value["attempts"]:
            raise ValueError("failed browser-egress checkpoint has no terminal evidence")
        last = value["attempts"][-1]
        if (
            terminal["vector_id"] != last["vector_id"]
            or terminal["attempt_number"] != last["attempt_number"]
            or terminal["verdict"] != last["verdict"]
            or value["next_vector_ordinal"] != len(passed) + 1
        ):
            raise ValueError("failed browser-egress checkpoint terminal evidence is inconsistent")
    return json.loads(canonical_json_bytes(value))


def _initialisation_staging_pattern(destination: Path) -> re.Pattern[str]:
    return re.compile(
        rf"[.]{re.escape(destination.name)}[.]([0-9a-f]{{8}})[.]qcsd-tmp\Z"
    )


def _remove_valid_initialisation_staging(
    staging: Path,
    *,
    foundation: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
) -> None:
    """Remove only a provably private, incomplete initialisation tree."""

    _safe_directory(staging, label="browser-egress initialisation staging", private=True)
    expected_directories = {
        ATTEMPT_DIRECTORY,
        ATTEMPT_INTENT_DIRECTORY,
        EVIDENCE_DIRECTORY,
    }
    expected_bytes = {
        FOUNDATION_FILENAME: canonical_json_bytes(foundation),
        CHECKPOINT_FILENAME: canonical_json_bytes(checkpoint),
    }
    create_temp = re.compile(
        rf"[.]{re.escape(FOUNDATION_FILENAME)}[.]([0-9a-f]{{8}})[.]qcsd-tmp\Z"
    )
    atomic_temp = re.compile(
        rf"[.]{re.escape(CHECKPOINT_FILENAME)}[.]qcsd-tmp-([0-9a-f]{{8}})\Z"
    )
    files: list[Path] = []
    inode_names: dict[tuple[int, int], list[str]] = {}
    for entry in sorted(staging.iterdir(), key=lambda item: item.name):
        if entry.name in expected_directories:
            directory = _safe_directory(
                entry, label="browser-egress staged ledger directory", private=True
            )
            if any(directory.iterdir()):
                raise ValueError("browser-egress initialisation staging directory is not empty")
            continue
        if entry.name == FOUNDATION_FILENAME or create_temp.fullmatch(entry.name):
            expected = expected_bytes[FOUNDATION_FILENAME]
        elif entry.name == CHECKPOINT_FILENAME or atomic_temp.fullmatch(entry.name):
            expected = expected_bytes[CHECKPOINT_FILENAME]
        else:
            raise ValueError("browser-egress initialisation staging contains an unknown entry")
        metadata = _private_regular_file(
            entry,
            label="browser-egress staged ledger file",
            allowed_links=frozenset({1, 2}),
        )
        if entry.read_bytes() != expected:
            raise ValueError("browser-egress initialisation staging content is invalid")
        files.append(entry)
        inode_names.setdefault((metadata.st_dev, metadata.st_ino), []).append(entry.name)
    for entry in files:
        metadata = entry.lstat()
        if metadata.st_nlink != len(inode_names[(metadata.st_dev, metadata.st_ino)]):
            raise ValueError("browser-egress initialisation staging has an external hard link")
    for entry in files:
        entry.unlink()
    for name in sorted(expected_directories):
        directory = staging / name
        if directory.exists():
            directory.rmdir()
    staging.rmdir()
    _fsync_directory(staging.parent)


def _reconcile_initialisation_staging(
    destination: Path,
    *,
    foundation: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
) -> None:
    parent = destination.parent
    pattern = _initialisation_staging_pattern(destination)
    prefix = f".{destination.name}."
    candidates: list[Path] = []
    for entry in parent.iterdir():
        if pattern.fullmatch(entry.name):
            candidates.append(entry)
        elif entry.name.startswith(prefix) and "qcsd-tmp" in entry.name:
            raise ValueError("browser-egress initialisation has an unrecognised residue")
    if len(candidates) > 1:
        raise ValueError("multiple browser-egress initialisation residues exist")
    if candidates:
        _remove_valid_initialisation_staging(
            candidates[0], foundation=foundation, checkpoint=checkpoint
        )


def _new_initialisation_staging(destination: Path) -> Path:
    for _attempt in range(128):
        staging = destination.parent / (
            f".{destination.name}.{secrets.token_hex(4)}.qcsd-tmp"
        )
        try:
            staging.mkdir(mode=PRIVATE_DIRECTORY_MODE)
        except FileExistsError:
            continue
        _fsync_directory(destination.parent)
        return staging
    raise FileExistsError("unable to allocate browser-egress initialisation staging")


def create_qualification(
    root: Path,
    foundation_payload: Mapping[str, Any],
    *,
    lab_root: Path,
    build_validator: Callable[..., Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Admit the live prepare environment, then create a fresh evidence root."""

    payload = deep_validate_foundation(
        foundation_payload,
        lab_root=lab_root,
        build_validator=build_validator,
        mode=FoundationVerificationMode.EXECUTION,
    )
    foundation = bind_receipt(payload, receipt_type=FOUNDATION_RECEIPT_TYPE)
    foundation_sha256 = canonical_json_sha256(foundation)
    foundation_binding = {
        "path": FOUNDATION_FILENAME,
        "sha256": foundation_sha256,
        "payload_sha256": foundation["payload_sha256"],
    }
    checkpoint = _initial_checkpoint(
        foundation_file_sha256=foundation_binding["sha256"],
        foundation_payload_sha256=foundation_binding["payload_sha256"],
    )
    destination = Path(os.path.abspath(root))
    parent = _safe_directory(destination.parent, label="browser-egress result parent")
    parent_metadata = parent.lstat()
    if (
        parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise ValueError(
            "browser-egress result parent must be current-user owned and not group/world writable"
        )
    if os.path.lexists(destination):
        raise FileExistsError(f"browser-egress qualification root already exists: {destination}")
    _reconcile_initialisation_staging(
        destination, foundation=foundation, checkpoint=checkpoint
    )
    staging = _new_initialisation_staging(destination)
    published = False
    try:
        _durability_boundary("initial-create:staging-created")
        for name in (
            ATTEMPT_DIRECTORY,
            ATTEMPT_INTENT_DIRECTORY,
            EVIDENCE_DIRECTORY,
        ):
            (staging / name).mkdir(mode=PRIVATE_DIRECTORY_MODE)
        _fsync_directory(staging)
        _durability_boundary("initial-create:directories-created")
        foundation_path = write_create_only_json(staging / FOUNDATION_FILENAME, foundation)
        if sha256_file(foundation_path) != foundation_sha256:
            raise ValueError("staged browser-egress foundation hash changed unexpectedly")
        _durability_boundary("initial-create:foundation-published")
        atomic_json(staging / CHECKPOINT_FILENAME, checkpoint)
        _fsync_directory(staging)
        _durability_boundary("initial-create:pre-publish")
        _rename_no_replace(staging, destination)
        published = True
        _fsync_directory(parent)
        _durability_boundary("initial-create:post-publish")
    except BaseException:
        if not published and staging.exists():
            _remove_valid_initialisation_staging(
                staging, foundation=foundation, checkpoint=checkpoint
            )
        raise
    return checkpoint


def _load_foundation(
    root: Path,
    *,
    recovery_link: Path | None = None,
    allow_historical: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    foundation_path = root / FOUNDATION_FILENAME
    if recovery_link != foundation_path:
        foundation_path = safe_relative_artifact(
            root, FOUNDATION_FILENAME, label="foundation"
        )
    _private_regular_file(
        foundation_path,
        label="browser-egress foundation",
        allowed_links=(
            frozenset({1, 2})
            if recovery_link == foundation_path
            else frozenset({1})
        ),
    )
    envelope = load_json(foundation_path)
    payload = validate_hash_bound_receipt(envelope, expected_type=FOUNDATION_RECEIPT_TYPE)
    validated = validate_foundation_payload(
        payload, allow_historical=allow_historical
    )
    binding = {
        "path": FOUNDATION_FILENAME,
        "sha256": sha256_file(foundation_path),
        "payload_sha256": envelope["payload_sha256"],
    }
    return validated, binding


def attempt_topology_token(
    *,
    foundation_payload_sha256: str,
    global_ordinal: int,
    attempt_number: int,
    vector_id: str,
    started_at: str,
) -> str:
    """Derive the durable, receipt-bound identity for one Docker topology."""

    _sha256(foundation_payload_sha256, label="topology foundation payload")
    _integer(global_ordinal, label="topology global ordinal", minimum=1)
    _integer(attempt_number, label="topology attempt number", minimum=1)
    if attempt_number > MAX_OPERATIONAL_ATTEMPTS:
        raise ValueError("topology attempt exceeds the frozen retry limit")
    vector = vector_by_id(vector_id)
    _timestamp(started_at, label="topology attempt start")
    identity = {
        "qualification_id": QUALIFICATION_ID,
        "foundation_payload_sha256": foundation_payload_sha256,
        "global_ordinal": global_ordinal,
        "attempt_number": attempt_number,
        "vector_id": vector.vector_id,
        "started_at": started_at,
    }
    return hashlib.sha256(canonical_json_bytes(identity)).hexdigest()[:32]


def build_attempt_topology_binding(
    *,
    foundation: Mapping[str, Any],
    global_ordinal: int,
    attempt_number: int,
    vector_id: str,
    started_at: str,
) -> dict[str, Any]:
    """Build the exact Docker label identity carried by an attempt intent."""

    validated_foundation = validate_foundation_payload(foundation)
    foundation_sha256 = canonical_json_sha256(validated_foundation)
    return {
        "cohort_version": validated_foundation["cohort_version"],
        "foundation_payload_sha256": foundation_sha256,
        "global_ordinal": global_ordinal,
        "attempt_number": attempt_number,
        "topology_token": attempt_topology_token(
            foundation_payload_sha256=foundation_sha256,
            global_ordinal=global_ordinal,
            attempt_number=attempt_number,
            vector_id=vector_id,
            started_at=started_at,
        ),
    }


def _topology_labels(
    *, vector_id: str, topology: Mapping[str, Any], include_role: str | None = None
) -> dict[str, str]:
    fields = {
        "cohort_version",
        "foundation_payload_sha256",
        "global_ordinal",
        "attempt_number",
        "topology_token",
    }
    if not isinstance(topology, Mapping) or set(topology) != fields:
        raise ValueError("browser-egress attempt topology fields are invalid")
    cohort_version = _integer(
        topology["cohort_version"], label="topology cohort version", minimum=1
    )
    global_ordinal = _integer(
        topology["global_ordinal"], label="topology global ordinal", minimum=1
    )
    attempt_number = _integer(
        topology["attempt_number"], label="topology attempt number", minimum=1
    )
    if attempt_number > MAX_OPERATIONAL_ATTEMPTS:
        raise ValueError("topology attempt exceeds the frozen retry limit")
    foundation_sha256 = _sha256(
        topology["foundation_payload_sha256"], label="topology foundation payload"
    )
    token = topology["topology_token"]
    if not isinstance(token, str) or _TOPOLOGY_TOKEN.fullmatch(token) is None:
        raise ValueError("browser-egress topology token is invalid")
    labels = {
        "org.qcsd.owner": "qcsd-lab",
        "org.qcsd.study": STUDY_ID,
        "org.qcsd.qualification": QUALIFICATION_ID,
        "org.qcsd.vector": vector_by_id(vector_id).vector_id,
        "org.qcsd.cohort-version": str(cohort_version),
        "org.qcsd.foundation": foundation_sha256,
        "org.qcsd.global-ordinal": str(global_ordinal),
        "org.qcsd.attempt-number": str(attempt_number),
        "org.qcsd.topology-token": token,
    }
    if include_role is not None:
        labels["org.qcsd.role"] = include_role
    return labels


def validate_attempt_intent_payload(
    value: object, *, foundation: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate one durable pre-execution attempt declaration."""

    fields = {
        "schema_version",
        "qualification_id",
        "foundation_payload_sha256",
        "global_ordinal",
        "attempt_number",
        "previous_result_sha256",
        "vector",
        "started_at",
        "evidence_directory",
        "topology_token",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("browser-egress attempt-intent fields are invalid")
    validated_foundation = validate_foundation_payload(foundation)
    global_ordinal = _integer(
        value["global_ordinal"], label="attempt-intent global ordinal", minimum=1
    )
    attempt_number = _integer(
        value["attempt_number"], label="attempt-intent attempt number", minimum=1
    )
    if (
        value["schema_version"] != ATTEMPT_INTENT_SCHEMA_VERSION
        or value["qualification_id"] != QUALIFICATION_ID
        or value["foundation_payload_sha256"]
        != canonical_json_sha256(validated_foundation)
        or attempt_number > MAX_OPERATIONAL_ATTEMPTS
    ):
        raise ValueError("browser-egress attempt-intent identity is invalid")
    _sha256(
        value["previous_result_sha256"],
        label="attempt-intent previous result SHA-256",
    )
    vector = validate_vector(value["vector"])
    _timestamp(value["started_at"], label="attempt-intent start")
    expected_directory = (
        f"{EVIDENCE_DIRECTORY}/{vector.ordinal:03d}--{vector.vector_id}/"
        f"attempt-{attempt_number}"
    )
    if value["evidence_directory"] != expected_directory:
        raise ValueError("browser-egress attempt-intent evidence directory is invalid")
    expected_token = attempt_topology_token(
        foundation_payload_sha256=value["foundation_payload_sha256"],
        global_ordinal=global_ordinal,
        attempt_number=attempt_number,
        vector_id=vector.vector_id,
        started_at=value["started_at"],
    )
    if (
        not isinstance(value["topology_token"], str)
        or _TOPOLOGY_TOKEN.fullmatch(value["topology_token"]) is None
        or value["topology_token"] != expected_token
    ):
        raise ValueError("browser-egress attempt-intent topology token is invalid")
    if global_ordinal < attempt_number:
        raise ValueError("browser-egress attempt-intent ordinal is impossible")
    return json.loads(canonical_json_bytes(value))


def _load_attempt_intents(
    root: Path,
    *,
    foundation: Mapping[str, Any],
    recovery_link: Path | None = None,
) -> list[dict[str, Any]]:
    intent_root = _safe_directory(
        root / ATTEMPT_INTENT_DIRECTORY,
        label="browser-egress attempt intents",
        private=True,
    )
    entries = sorted(
        (
            path
            for path in intent_root.iterdir()
            if re.fullmatch(r"intent-[0-9]{4}[.]json", path.name)
        ),
        key=lambda path: path.name,
    )
    expected_names = [
        f"intent-{index:04d}.json" for index in range(1, len(entries) + 1)
    ]
    if [path.name for path in entries] != expected_names:
        raise ValueError("browser-egress attempt-intent files are incomplete or noncanonical")
    records: list[dict[str, Any]] = []
    for index, path in enumerate(entries, 1):
        _private_regular_file(
            path,
            label="browser-egress attempt intent",
            allowed_links=(
                frozenset({1, 2}) if recovery_link == path else frozenset({1})
            ),
        )
        envelope = load_json(path)
        if path.read_bytes() != canonical_json_bytes(envelope):
            raise ValueError("browser-egress attempt intent is not canonical JSON")
        payload = validate_hash_bound_receipt(
            envelope, expected_type=ATTEMPT_INTENT_RECEIPT_TYPE
        )
        validated = validate_attempt_intent_payload(payload, foundation=foundation)
        if validated["global_ordinal"] != index:
            raise ValueError("browser-egress attempt-intent sequence is invalid")
        records.append(
            {
                "payload": validated,
                "binding": {
                    "path": f"{ATTEMPT_INTENT_DIRECTORY}/{path.name}",
                    "sha256": sha256_file(path),
                    "payload_sha256": envelope["payload_sha256"],
                },
            }
        )
    return records


def _next_attempt_plan(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    if checkpoint["status"] == "complete":
        return {"schema_version": 1, "complete": True}
    if checkpoint["status"] != "running":
        raise ValueError("browser-egress qualification is not resumable")
    ordinal = checkpoint["next_vector_ordinal"]
    vector = inventory_json()[ordinal - 1]
    prior = [
        item for item in checkpoint["attempts"] if item["vector_id"] == vector["vector_id"]
    ]
    return {
        "schema_version": 1,
        "complete": False,
        "vector": vector,
        "global_ordinal": len(checkpoint["attempts"]) + 1,
        "attempt_number": len(prior) + 1,
        "previous_result_sha256": checkpoint["chain_head_sha256"],
    }


def _validate_attempt_intent_sequence(
    records: Sequence[Mapping[str, Any]], *, checkpoint: Mapping[str, Any]
) -> None:
    attempts = checkpoint["attempts"]
    if len(records) not in {len(attempts), len(attempts) + 1}:
        raise ValueError("browser-egress attempt-intent/result cardinality is invalid")
    previous_sha256 = ZERO_DIGEST
    for index, entry in enumerate(attempts):
        intent = records[index]["payload"]
        if (
            intent["global_ordinal"] != entry["global_ordinal"]
            or intent["attempt_number"] != entry["attempt_number"]
            or intent["previous_result_sha256"] != previous_sha256
            or intent["vector"] != inventory_json()[entry["vector_ordinal"] - 1]
            or intent["started_at"] != entry["started_at"]
        ):
            raise ValueError("browser-egress result differs from its attempt intent")
        previous_sha256 = entry["sha256"]
    if len(records) == len(attempts):
        return
    if checkpoint["status"] != "running":
        raise ValueError("terminal browser-egress checkpoint has an outstanding intent")
    plan = _next_attempt_plan(checkpoint)
    outstanding = records[-1]["payload"]
    for key in (
        "global_ordinal",
        "attempt_number",
        "previous_result_sha256",
        "vector",
    ):
        if outstanding[key] != plan[key]:
            raise ValueError("outstanding browser-egress attempt intent is out of order")


def _validate_result_against_attempt_intent(
    result: Mapping[str, Any], intent: Mapping[str, Any]
) -> None:
    for key in (
        "foundation_payload_sha256",
        "global_ordinal",
        "attempt_number",
        "previous_result_sha256",
        "vector",
        "started_at",
    ):
        if result[key] != intent[key]:
            raise ValueError("browser-egress result differs from its attempt intent")


def begin_attempt(
    root: Path,
    *,
    next_plan: Mapping[str, Any],
    vector_id: str,
    started_at: str,
) -> dict[str, Any]:
    """Durably publish an intent before any live role or evidence path exists."""

    reconcile_qualification_filesystem(root)
    evidence_root = _safe_directory(
        root, label="browser-egress qualification root", private=True
    )
    foundation, _foundation_binding = _load_foundation(evidence_root)
    checkpoint = _load_checkpoint_without_reconciliation(evidence_root)
    records = _load_attempt_intents(evidence_root, foundation=foundation)
    _validate_attempt_intent_sequence(records, checkpoint=checkpoint)
    if len(records) != len(checkpoint["attempts"]):
        raise ValueError("browser-egress outstanding attempt must be recovered before execution")
    expected_plan = _next_attempt_plan(checkpoint)
    if expected_plan.get("complete") is True:
        raise ValueError("completed browser-egress qualification cannot begin an attempt")
    if dict(next_plan) != expected_plan or expected_plan["vector"]["vector_id"] != vector_id:
        raise ValueError("browser-egress attempt intent differs from its next-vector plan")
    intent = {
        "schema_version": ATTEMPT_INTENT_SCHEMA_VERSION,
        "qualification_id": QUALIFICATION_ID,
        "foundation_payload_sha256": canonical_json_sha256(foundation),
        "global_ordinal": expected_plan["global_ordinal"],
        "attempt_number": expected_plan["attempt_number"],
        "previous_result_sha256": expected_plan["previous_result_sha256"],
        "vector": expected_plan["vector"],
        "started_at": started_at,
        "evidence_directory": (
            f"{EVIDENCE_DIRECTORY}/{expected_plan['vector']['ordinal']:03d}--"
            f"{vector_id}/attempt-{expected_plan['attempt_number']}"
        ),
    }
    intent["topology_token"] = attempt_topology_token(
        foundation_payload_sha256=intent["foundation_payload_sha256"],
        global_ordinal=intent["global_ordinal"],
        attempt_number=intent["attempt_number"],
        vector_id=intent["vector"]["vector_id"],
        started_at=intent["started_at"],
    )
    payload = validate_attempt_intent_payload(intent, foundation=foundation)
    if checkpoint["attempts"] and _timestamp(
        payload["started_at"], label="attempt-intent start"
    ) < _timestamp(
        checkpoint["attempts"][-1]["finished_at"],
        label="previous browser-egress finish",
    ):
        raise ValueError("browser-egress attempt intent regresses ledger chronology")
    receipt = bind_receipt(payload, receipt_type=ATTEMPT_INTENT_RECEIPT_TYPE)
    relative = (
        f"{ATTEMPT_INTENT_DIRECTORY}/"
        f"intent-{expected_plan['global_ordinal']:04d}.json"
    )
    path = write_create_only_json(evidence_root / relative, receipt)
    return {
        "path": relative,
        "sha256": sha256_file(path),
        "payload_sha256": receipt["payload_sha256"],
        "topology_token": payload["topology_token"],
        "foundation_payload_sha256": payload["foundation_payload_sha256"],
        "global_ordinal": payload["global_ordinal"],
        "attempt_number": payload["attempt_number"],
        "evidence_directory": payload["evidence_directory"],
    }


def append_result(
    root: Path,
    receipt: Mapping[str, Any],
    *,
    tshark: Path = Path("/usr/bin/tshark"),
    dumpcap: Path = Path("/usr/bin/dumpcap"),
) -> dict[str, Any]:
    """Publish one result create-only and replace only the derived checkpoint."""

    reconcile_qualification_filesystem(root, tshark=tshark, dumpcap=dumpcap)
    evidence_root = _safe_directory(
        root, label="browser-egress qualification root", private=True
    )
    foundation, foundation_binding = _load_foundation(evidence_root)
    checkpoint = _load_checkpoint_without_reconciliation(evidence_root)
    if checkpoint["status"] != "running":
        raise ValueError("browser-egress checkpoint is already terminal")
    payload = validate_hash_bound_receipt(receipt, expected_type=RESULT_RECEIPT_TYPE)
    result = validate_result_payload(
        payload,
        foundation=foundation,
        evidence_root=evidence_root,
        deep=True,
        tshark=tshark,
        dumpcap=dumpcap,
    )
    expected_plan = _next_attempt_plan(checkpoint)
    if expected_plan.get("complete") is True or any(
        result[key] != expected_plan[key]
        for key in (
            "global_ordinal",
            "attempt_number",
            "previous_result_sha256",
            "vector",
        )
    ):
        raise ValueError("browser-egress result is out of order or breaks its chain")
    intent_records = _load_attempt_intents(evidence_root, foundation=foundation)
    _validate_attempt_intent_sequence(intent_records, checkpoint=checkpoint)
    if len(intent_records) != len(checkpoint["attempts"]) + 1:
        raise ValueError("browser-egress result has no outstanding attempt intent")
    _validate_result_against_attempt_intent(result, intent_records[-1]["payload"])
    expected_global = expected_plan["global_ordinal"]
    if result["global_ordinal"] != expected_global:
        raise ValueError("browser-egress result global ordinal is invalid")
    if result["verdict"] == "passed":
        current_docker = result["runtime"]["docker_inspect"]
        current_containers = {
            record["id"] for record in current_docker["containers"].values()
        }
        current_network = current_docker["network"]["id"]
        for entry in checkpoint["attempts"]:
            if entry["verdict"] != "passed":
                continue
            prior_path = safe_relative_artifact(
                evidence_root, entry["path"], label="prior browser-egress result"
            )
            prior_envelope = load_json(prior_path)
            prior_payload = validate_hash_bound_receipt(
                prior_envelope, expected_type=RESULT_RECEIPT_TYPE
            )
            prior = validate_result_payload(prior_payload, foundation=foundation)
            prior_docker = prior["runtime"]["docker_inspect"]
            prior_containers = {
                record["id"] for record in prior_docker["containers"].values()
            }
            if (
                current_containers.intersection(prior_containers)
                or current_network == prior_docker["network"]["id"]
            ):
                raise ValueError("browser-egress vector reused a Docker container or network")
    relative = f"{ATTEMPT_DIRECTORY}/result-{expected_global:04d}.json"
    binding = {
        "path": relative,
        "sha256": canonical_json_sha256(receipt),
        "payload_sha256": receipt["payload_sha256"],
    }
    updated = _advance_checkpoint(checkpoint, result=result, receipt_binding=binding)
    path = write_create_only_json(evidence_root / relative, receipt)
    if sha256_file(path) != binding["sha256"]:  # pragma: no cover - create helper invariant
        raise ValueError("published browser-egress result hash changed unexpectedly")
    _durability_boundary(f"append-result:{path.name}:post-publish")
    validate_checkpoint(updated, foundation_binding=foundation_binding)
    atomic_json(evidence_root / CHECKPOINT_FILENAME, updated)
    return updated


def _replay_checkpoint(
    root: Path,
    *,
    foundation: Mapping[str, Any],
    foundation_binding: Mapping[str, Any],
    deep: bool,
    tshark: Path,
    dumpcap: Path,
    maximum_results: int | None = None,
    recovery_link: Path | None = None,
) -> dict[str, Any]:
    checkpoint = _initial_checkpoint(
        foundation_file_sha256=foundation_binding["sha256"],
        foundation_payload_sha256=foundation_binding["payload_sha256"],
    )
    intent_records = _load_attempt_intents(
        root, foundation=foundation, recovery_link=recovery_link
    )
    attempts_root = _safe_directory(
        root / ATTEMPT_DIRECTORY, label="browser-egress attempts", private=True
    )
    all_entries = sorted(
        (
            path
            for path in attempts_root.iterdir()
            if re.fullmatch(r"result-[0-9]{4}[.]json", path.name)
        ),
        key=lambda path: path.name,
    )
    expected_names = [
        f"result-{index:04d}.json" for index in range(1, len(all_entries) + 1)
    ]
    if [path.name for path in all_entries] != expected_names:
        raise ValueError("browser-egress attempt files are incomplete or noncanonical")
    if maximum_results is not None:
        _integer(maximum_results, label="maximum replayed browser-egress results", minimum=0)
        if maximum_results > len(all_entries):
            raise ValueError("browser-egress replay limit exceeds its result inventory")
        entries = all_entries[:maximum_results]
    else:
        entries = all_entries
    seen_container_ids: set[str] = set()
    seen_network_ids: set[str] = set()
    for index, path in enumerate(entries, 1):
        _private_regular_file(
            path,
            label="browser-egress attempt receipt",
            allowed_links=(
                frozenset({1, 2}) if recovery_link == path else frozenset({1})
            ),
        )
        envelope = load_json(path)
        payload = validate_hash_bound_receipt(envelope, expected_type=RESULT_RECEIPT_TYPE)
        result = validate_result_payload(
            payload,
            foundation=foundation,
            evidence_root=root,
            deep=deep,
            tshark=tshark,
            dumpcap=dumpcap,
        )
        if index > len(intent_records):
            raise ValueError("browser-egress result has no attempt intent")
        _validate_result_against_attempt_intent(
            result, intent_records[index - 1]["payload"]
        )
        if result["verdict"] == "passed":
            docker = result["runtime"]["docker_inspect"]
            container_ids = {
                record["id"] for record in docker["containers"].values()
            }
            network_id = docker["network"]["id"]
            if seen_container_ids.intersection(container_ids) or network_id in seen_network_ids:
                raise ValueError("browser-egress vector reused a Docker container or network")
            seen_container_ids.update(container_ids)
            seen_network_ids.add(network_id)
        relative = f"{ATTEMPT_DIRECTORY}/{path.name}"
        binding = {
            "path": relative,
            "sha256": sha256_file(path),
            "payload_sha256": envelope["payload_sha256"],
        }
        checkpoint = _advance_checkpoint(checkpoint, result=result, receipt_binding=binding)
        if checkpoint["status"] != "running" and index != len(entries):
            raise ValueError("browser-egress results continue after a terminal attempt")
    _validate_attempt_intent_sequence(intent_records, checkpoint=checkpoint)
    return checkpoint


_RECOVERABLE_ATTEMPT_ARTIFACTS = frozenset(
    {
        "browser.log",
        "browser-inspect.txt",
        "observer.log",
        "observer-inspect.txt",
        "fixture.log",
        "fixture-inspect.txt",
        "forbidden.log",
        "forbidden-inspect.txt",
        "dns.log",
        "dns-inspect.txt",
        "network-inspect.txt",
        "causal-actor.json",
        "causal-capture.json",
        "causal-dns.json",
        "causal-fixture.json",
        "causal-forbidden.json",
        "causal-runtime.json",
        "capture.pcapng",
        "failure.json",
        "resume-recovery.json",
    }
)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


_CREATE_ONLY_RESIDUE = re.compile(
    r"[.](foundation[.]json|final[.]json|intent-[0-9]{4}[.]json|"
    r"result-[0-9]{4}[.]json)[.]([0-9a-f]{8})[.]qcsd-tmp\Z"
)
_CHECKPOINT_RESIDUE = re.compile(
    r"[.]experiment[.]json[.]qcsd-tmp-([0-9a-f]{8})\Z"
)
_RECOVERY_DIAGNOSTIC_RESIDUE = re.compile(
    r"[.]resume-recovery[.]json[.]([0-9a-f]{8})[.]qcsd-tmp\Z"
)


def _read_canonical_json_file(path: Path, *, label: str) -> Any:
    value = load_json(path)
    if path.read_bytes() != canonical_json_bytes(value):
        raise ValueError(f"{label} is not canonical JSON")
    return value


def _checkpoint_pair(
    root: Path,
    *,
    foundation: Mapping[str, Any],
    binding: Mapping[str, Any],
    deep: bool,
    tshark: Path,
    dumpcap: Path,
    recovery_link: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    rebuilt = _replay_checkpoint(
        root,
        foundation=foundation,
        foundation_binding=binding,
        deep=deep,
        tshark=tshark,
        dumpcap=dumpcap,
        recovery_link=recovery_link,
    )
    checkpoint_path = root / CHECKPOINT_FILENAME
    _private_regular_file(checkpoint_path, label="browser-egress checkpoint")
    stored = validate_checkpoint(
        _read_canonical_json_file(checkpoint_path, label="browser-egress checkpoint"),
        foundation_binding=binding,
    )
    return stored, rebuilt


def _require_checkpoint_current_or_predecessor(
    root: Path,
    *,
    foundation: Mapping[str, Any],
    binding: Mapping[str, Any],
    stored: Mapping[str, Any],
    rebuilt: Mapping[str, Any],
    tshark: Path,
    dumpcap: Path,
    recovery_link: Path | None = None,
) -> None:
    if stored == rebuilt:
        return
    if len(stored["attempts"]) + 1 != len(rebuilt["attempts"]):
        raise ValueError("browser-egress checkpoint divergence is not recoverable")
    predecessor = _replay_checkpoint(
        root,
        foundation=foundation,
        foundation_binding=binding,
        deep=True,
        tshark=tshark,
        dumpcap=dumpcap,
        maximum_results=len(stored["attempts"]),
        recovery_link=recovery_link,
    )
    if stored != predecessor:
        raise ValueError("browser-egress checkpoint divergence is not an exact publish lag")


def _validate_create_only_residue(
    root: Path,
    *,
    temporary: Path,
    logical_name: str,
    tshark: Path,
    dumpcap: Path,
) -> Path:
    """Validate one scratch receipt and return its canonical target."""

    if logical_name == FOUNDATION_FILENAME:
        target = root / FOUNDATION_FILENAME
    elif logical_name == FINAL_FILENAME:
        target = root / FINAL_FILENAME
    elif logical_name.startswith("intent-"):
        target = root / ATTEMPT_INTENT_DIRECTORY / logical_name
    elif logical_name.startswith("result-"):
        target = root / ATTEMPT_DIRECTORY / logical_name
    else:
        raise ValueError("unrecognised browser-egress create-only residue")
    recovery_link = target if target.exists() else None
    envelope = _read_canonical_json_file(
        temporary, label="browser-egress create-only residue"
    )
    if logical_name == FOUNDATION_FILENAME:
        payload = validate_hash_bound_receipt(
            envelope, expected_type=FOUNDATION_RECEIPT_TYPE
        )
        validate_foundation_payload(payload)
        if not target.exists():
            raise ValueError("canonical-root foundation residue cannot be pre-publication")
        if target.read_bytes() != temporary.read_bytes():
            raise ValueError("foundation residue differs from the canonical foundation")
        return target
    foundation, binding = _load_foundation(root)
    stored, rebuilt = _checkpoint_pair(
        root,
        foundation=foundation,
        binding=binding,
        deep=True,
        tshark=tshark,
        dumpcap=dumpcap,
        recovery_link=recovery_link,
    )
    _require_checkpoint_current_or_predecessor(
        root,
        foundation=foundation,
        binding=binding,
        stored=stored,
        rebuilt=rebuilt,
        tshark=tshark,
        dumpcap=dumpcap,
        recovery_link=recovery_link,
    )
    if logical_name.startswith("intent-"):
        index = int(logical_name[7:11])
        payload = validate_hash_bound_receipt(
            envelope, expected_type=ATTEMPT_INTENT_RECEIPT_TYPE
        )
        intent = validate_attempt_intent_payload(payload, foundation=foundation)
        records = _load_attempt_intents(
            root, foundation=foundation, recovery_link=recovery_link
        )
        if target.exists():
            if target.read_bytes() != temporary.read_bytes():
                raise ValueError("attempt-intent residue differs from its target")
        else:
            if index != len(records) + 1 or rebuilt["status"] != "running":
                raise ValueError("attempt-intent residue is out of sequence")
            plan = _next_attempt_plan(rebuilt)
            for key in (
                "global_ordinal",
                "attempt_number",
                "previous_result_sha256",
                "vector",
            ):
                if intent[key] != plan[key]:
                    raise ValueError("attempt-intent residue differs from the next plan")
            if rebuilt["attempts"] and _timestamp(
                intent["started_at"], label="attempt-intent residue start"
            ) < _timestamp(
                rebuilt["attempts"][-1]["finished_at"],
                label="previous browser-egress finish",
            ):
                raise ValueError("attempt-intent residue regresses ledger chronology")
        return target
    if logical_name.startswith("result-"):
        index = int(logical_name[7:11])
        payload = validate_hash_bound_receipt(envelope, expected_type=RESULT_RECEIPT_TYPE)
        result = validate_result_payload(
            payload,
            foundation=foundation,
            evidence_root=root,
            deep=True,
            tshark=tshark,
            dumpcap=dumpcap,
        )
        records = _load_attempt_intents(root, foundation=foundation)
        if target.exists():
            if target.read_bytes() != temporary.read_bytes():
                raise ValueError("result residue differs from its target")
        else:
            if index != len(rebuilt["attempts"]) + 1 or len(records) != index:
                raise ValueError("result residue is out of sequence")
            plan = _next_attempt_plan(rebuilt)
            for key in (
                "global_ordinal",
                "attempt_number",
                "previous_result_sha256",
                "vector",
            ):
                if result[key] != plan[key]:
                    raise ValueError("result residue differs from the next plan")
            _validate_result_against_attempt_intent(result, records[-1]["payload"])
            if result["verdict"] == "passed":
                current_docker = result["runtime"]["docker_inspect"]
                current_containers = {
                    record["id"] for record in current_docker["containers"].values()
                }
                current_network = current_docker["network"]["id"]
                for entry in rebuilt["attempts"]:
                    if entry["verdict"] != "passed":
                        continue
                    prior_path = root / entry["path"]
                    prior_envelope = _read_canonical_json_file(
                        prior_path, label="prior browser-egress result"
                    )
                    prior_payload = validate_hash_bound_receipt(
                        prior_envelope, expected_type=RESULT_RECEIPT_TYPE
                    )
                    prior = validate_result_payload(
                        prior_payload, foundation=foundation
                    )
                    prior_docker = prior["runtime"]["docker_inspect"]
                    prior_containers = {
                        record["id"]
                        for record in prior_docker["containers"].values()
                    }
                    if (
                        current_containers.intersection(prior_containers)
                        or current_network == prior_docker["network"]["id"]
                    ):
                        raise ValueError(
                            "browser-egress residue reused a Docker container or network"
                        )
        return target
    if logical_name == FINAL_FILENAME:
        payload = validate_hash_bound_receipt(envelope, expected_type=FINAL_RECEIPT_TYPE)
        preliminary = validate_final_payload(payload)
        expected = _build_final_payload_without_reconciliation(
            root,
            recorded_at=preliminary["recorded_at"],
            tshark=tshark,
            dumpcap=dumpcap,
        )
        validate_final_payload(preliminary, expected=expected)
        if target.exists() and target.read_bytes() != temporary.read_bytes():
            raise ValueError("final receipt residue differs from its target")
        return target
    raise ValueError("unrecognised browser-egress create-only residue")


def _publish_or_clean_create_only_residue(
    temporary: Path, *, target: Path
) -> None:
    temporary_metadata = _private_regular_file(
        temporary,
        label="browser-egress create-only residue",
        allowed_links=frozenset({1, 2}),
    )
    if target.exists() or target.is_symlink():
        target_metadata = _private_regular_file(
            target,
            label="browser-egress recovered target",
            allowed_links=frozenset({2}),
        )
        if (
            temporary_metadata.st_nlink != 2
            or (temporary_metadata.st_dev, temporary_metadata.st_ino)
            != (target_metadata.st_dev, target_metadata.st_ino)
        ):
            raise ValueError("browser-egress residue is not the target's sole hard link")
    else:
        if temporary_metadata.st_nlink != 1:
            raise ValueError("browser-egress pre-publication residue has a foreign hard link")
        os.link(temporary, target, follow_symlinks=False)
        _fsync_directory(target.parent)
        _durability_boundary(f"reconcile:{target.name}:post-link")
    current = temporary.lstat()
    if current.st_nlink != 2:
        raise ValueError("browser-egress recovered publication link count is invalid")
    temporary.unlink()
    _fsync_directory(temporary.parent)
    _private_regular_file(target, label="browser-egress recovered target")


def _reconcile_checkpoint_residue(
    root: Path, *, temporary: Path, tshark: Path, dumpcap: Path
) -> None:
    _private_regular_file(temporary, label="browser-egress checkpoint residue")
    foundation, binding = _load_foundation(root)
    stored, rebuilt = _checkpoint_pair(
        root,
        foundation=foundation,
        binding=binding,
        deep=True,
        tshark=tshark,
        dumpcap=dumpcap,
    )
    _require_checkpoint_current_or_predecessor(
        root,
        foundation=foundation,
        binding=binding,
        stored=stored,
        rebuilt=rebuilt,
        tshark=tshark,
        dumpcap=dumpcap,
    )
    candidate = validate_checkpoint(
        _read_canonical_json_file(
            temporary, label="browser-egress checkpoint residue"
        ),
        foundation_binding=binding,
    )
    if candidate != rebuilt:
        raise ValueError("browser-egress checkpoint residue does not reproduce the ledger")
    os.replace(temporary, root / CHECKPOINT_FILENAME)
    _fsync_directory(root)
    _private_regular_file(root / CHECKPOINT_FILENAME, label="browser-egress checkpoint")


def _repair_checkpoint_publish_lag(
    root: Path, *, tshark: Path, dumpcap: Path
) -> None:
    foundation, binding = _load_foundation(root)
    stored, rebuilt = _checkpoint_pair(
        root,
        foundation=foundation,
        binding=binding,
        deep=True,
        tshark=tshark,
        dumpcap=dumpcap,
    )
    _require_checkpoint_current_or_predecessor(
        root,
        foundation=foundation,
        binding=binding,
        stored=stored,
        rebuilt=rebuilt,
        tshark=tshark,
        dumpcap=dumpcap,
    )
    if stored != rebuilt:
        atomic_json(root / CHECKPOINT_FILENAME, rebuilt)


def _validate_recovery_diagnostic(
    value: object, *, intent: Mapping[str, Any]
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {
            "schema_version",
            "vector_id",
            "attempt_number",
            "failure_code",
            "stage",
            "finished_at",
        }
        or value["schema_version"] != 1
        or value["vector_id"] != intent["vector"]["vector_id"]
        or value["attempt_number"] != intent["attempt_number"]
        or value["failure_code"] != "interrupted"
        or value["stage"] != "resume-recovery"
        or _timestamp(
            value["finished_at"], label="browser-egress recovery finish"
        )
        < _timestamp(intent["started_at"], label="browser-egress interrupted attempt start")
    ):
        raise ValueError("browser-egress recovery diagnostic is invalid")
    return json.loads(canonical_json_bytes(value))


def _validate_recovery_diagnostic_residue(
    root: Path,
    *,
    temporary: Path,
    tshark: Path,
    dumpcap: Path,
) -> Path:
    foundation, binding = _load_foundation(root)
    stored, rebuilt = _checkpoint_pair(
        root,
        foundation=foundation,
        binding=binding,
        deep=True,
        tshark=tshark,
        dumpcap=dumpcap,
    )
    _require_checkpoint_current_or_predecessor(
        root,
        foundation=foundation,
        binding=binding,
        stored=stored,
        rebuilt=rebuilt,
        tshark=tshark,
        dumpcap=dumpcap,
    )
    intents = _load_attempt_intents(root, foundation=foundation)
    _validate_attempt_intent_sequence(intents, checkpoint=rebuilt)
    if len(intents) != len(rebuilt["attempts"]) + 1:
        raise ValueError(
            "browser-egress recovery residue has no exact outstanding attempt"
        )
    intent = intents[-1]["payload"]
    expected_parent = root / intent["evidence_directory"]
    if temporary.parent != expected_parent:
        raise ValueError("browser-egress recovery residue is not intent-bound")
    _safe_directory(
        expected_parent,
        label="browser-egress recovery residue attempt directory",
        private=True,
    )
    _validate_recovery_diagnostic(
        _read_canonical_json_file(
            temporary, label="browser-egress recovery diagnostic residue"
        ),
        intent=intent,
    )
    target = expected_parent / "resume-recovery.json"
    if target.exists() and target.read_bytes() != temporary.read_bytes():
        raise ValueError("browser-egress recovery residue differs from its target")
    return target


def reconcile_qualification_filesystem(
    root: Path,
    *,
    tshark: Path = Path("/usr/bin/tshark"),
    dumpcap: Path = Path("/usr/bin/dumpcap"),
    allow_historical: bool = False,
) -> dict[str, Any]:
    """Exactly reconcile one proven crash residue; reject every ambiguity."""

    evidence_root = _safe_directory(
        root, label="browser-egress qualification root", private=True
    )
    for name in (ATTEMPT_DIRECTORY, ATTEMPT_INTENT_DIRECTORY, EVIDENCE_DIRECTORY):
        _safe_directory(
            evidence_root / name,
            label=f"browser-egress {name} directory",
            private=True,
        )
    locations = (
        evidence_root,
        evidence_root / ATTEMPT_DIRECTORY,
        evidence_root / ATTEMPT_INTENT_DIRECTORY,
    )
    residues: list[tuple[Path, str]] = []
    checkpoint_residues: list[Path] = []
    recovery_residues: list[Path] = []
    for directory in locations:
        for entry in directory.iterdir():
            match = _CREATE_ONLY_RESIDUE.fullmatch(entry.name)
            if match is not None:
                logical = match.group(1)
                if (
                    (logical.startswith("intent-") and directory.name != ATTEMPT_INTENT_DIRECTORY)
                    or (logical.startswith("result-") and directory.name != ATTEMPT_DIRECTORY)
                    or (
                        logical in {FOUNDATION_FILENAME, FINAL_FILENAME}
                        and directory != evidence_root
                    )
                ):
                    raise ValueError("browser-egress residue is in the wrong directory")
                residues.append((entry, logical))
            elif directory == evidence_root and _CHECKPOINT_RESIDUE.fullmatch(entry.name):
                checkpoint_residues.append(entry)
            elif "qcsd-tmp" in entry.name:
                raise ValueError("browser-egress ledger contains an unrecognised residue")
    evidence_directory = evidence_root / EVIDENCE_DIRECTORY
    for entry in evidence_directory.rglob("*"):
        if "qcsd-tmp" not in entry.name:
            continue
        if _RECOVERY_DIAGNOSTIC_RESIDUE.fullmatch(entry.name) is None:
            raise ValueError(
                "browser-egress evidence contains an unrecognised residue"
            )
        recovery_residues.append(entry)
    if len(residues) + len(checkpoint_residues) + len(recovery_residues) > 1:
        raise ValueError("multiple browser-egress ledger residues exist")
    allowed_residue = (
        checkpoint_residues[0]
        if checkpoint_residues
        else (
            residues[0][0]
            if residues
            else (recovery_residues[0] if recovery_residues else None)
        )
    )
    validate_open_evidence_inventory(
        evidence_root,
        allow_final=True,
        allowed_residue=allowed_residue,
        allow_historical=allow_historical,
    )
    if checkpoint_residues:
        _reconcile_checkpoint_residue(
            evidence_root,
            temporary=checkpoint_residues[0],
            tshark=tshark,
            dumpcap=dumpcap,
        )
    elif residues:
        temporary, logical = residues[0]
        target = _validate_create_only_residue(
            evidence_root,
            temporary=temporary,
            logical_name=logical,
            tshark=tshark,
            dumpcap=dumpcap,
        )
        _publish_or_clean_create_only_residue(temporary, target=target)
        if logical.startswith("result-"):
            _repair_checkpoint_publish_lag(
                evidence_root, tshark=tshark, dumpcap=dumpcap
            )
    elif recovery_residues:
        temporary = recovery_residues[0]
        target = _validate_recovery_diagnostic_residue(
            evidence_root,
            temporary=temporary,
            tshark=tshark,
            dumpcap=dumpcap,
        )
        _publish_or_clean_create_only_residue(temporary, target=target)
    if residues or checkpoint_residues or recovery_residues:
        validate_open_evidence_inventory(
            evidence_root,
            allow_final=True,
            allow_historical=allow_historical,
        )
    return {
        "schema_version": 1,
        "qualification_id": QUALIFICATION_ID,
        "reconciled": bool(residues or checkpoint_residues or recovery_residues),
    }


def validate_open_evidence_inventory(
    root: Path,
    *,
    allow_final: bool,
    allowed_residue: Path | None = None,
    allow_historical: bool = False,
) -> None:
    """Validate the exact mutable-ledger inventory at an operation boundary."""

    evidence_root = _safe_directory(
        root, label="browser-egress qualification root", private=True
    )
    recovery_link: Path | None = None
    if allowed_residue is not None and allowed_residue.exists():
        residue_metadata = _private_regular_file(
            allowed_residue,
            label="browser-egress allowed residue",
            allowed_links=frozenset({1, 2}),
        )
        if residue_metadata.st_nlink == 2:
            linked = [
                path
                for path in evidence_root.rglob("*")
                if path != allowed_residue
                and not path.is_symlink()
                and path.is_file()
                and (path.lstat().st_dev, path.lstat().st_ino)
                == (residue_metadata.st_dev, residue_metadata.st_ino)
            ]
            if len(linked) != 1:
                raise ValueError("browser-egress residue hard-link peer is ambiguous")
            recovery_link = linked[0]
    foundation, binding = _load_foundation(
        evidence_root,
        recovery_link=recovery_link,
        allow_historical=allow_historical,
    )
    rebuilt = _replay_checkpoint(
        evidence_root,
        foundation=foundation,
        foundation_binding=binding,
        deep=False,
        tshark=Path("/usr/bin/tshark"),
        dumpcap=Path("/usr/bin/dumpcap"),
        recovery_link=recovery_link,
    )
    intents = _load_attempt_intents(
        evidence_root, foundation=foundation, recovery_link=recovery_link
    )
    expected_files = {FOUNDATION_FILENAME, CHECKPOINT_FILENAME}
    expected_files.update(record["binding"]["path"] for record in intents)
    expected_directories = {
        ATTEMPT_DIRECTORY,
        ATTEMPT_INTENT_DIRECTORY,
        EVIDENCE_DIRECTORY,
    }
    attempts_root = _safe_directory(
        evidence_root / ATTEMPT_DIRECTORY,
        label="browser-egress attempts",
        private=True,
    )
    for path in sorted(attempts_root.iterdir(), key=lambda item: item.name):
        if re.fullmatch(r"result-[0-9]{4}[.]json", path.name) is None:
            continue
        relative = f"{ATTEMPT_DIRECTORY}/{path.name}"
        expected_files.add(relative)
        _private_regular_file(
            path,
            label="browser-egress result receipt",
            allowed_links=(
                frozenset({1, 2}) if recovery_link == path else frozenset({1})
            ),
        )
        envelope = _read_canonical_json_file(path, label="browser-egress result receipt")
        payload = validate_hash_bound_receipt(envelope, expected_type=RESULT_RECEIPT_TYPE)
        result = validate_result_payload(payload, foundation=foundation)
        if result["verdict"] == "passed":
            expected_files.add(result["capture"]["pcap"]["path"])
        else:
            expected_files.update(
                artifact["path"] for artifact in result["failure_evidence"]["artifacts"]
            )
    outstanding = len(intents) == len(rebuilt["attempts"]) + 1
    if outstanding:
        relative = PurePosixPath(intents[-1]["payload"]["evidence_directory"])
        vector_relative = PurePosixPath(*relative.parts[:2]).as_posix()
        vector_path = evidence_root / vector_relative
        if vector_path.exists() or vector_path.is_symlink():
            _safe_directory(
                vector_path,
                label="browser-egress outstanding vector evidence",
                private=True,
            )
            expected_directories.add(vector_relative)
        attempt_path = evidence_root / relative
        if attempt_path.exists() or attempt_path.is_symlink():
            _safe_directory(
                attempt_path,
                label="browser-egress outstanding attempt evidence",
                private=True,
            )
            expected_directories.add(relative.as_posix())
            for artifact in attempt_path.iterdir():
                if artifact == allowed_residue:
                    continue
                if artifact.name not in _RECOVERABLE_ATTEMPT_ARTIFACTS:
                    raise ValueError(
                        "interrupted browser-egress attempt contains an unknown artifact"
                    )
                expected_files.add((relative / artifact.name).as_posix())
    final_path = evidence_root / FINAL_FILENAME
    if final_path.exists() or final_path.is_symlink():
        if not allow_final:
            raise ValueError("browser-egress final receipt is not allowed while the ledger is open")
        expected_files.add(FINAL_FILENAME)
    if allowed_residue is not None:
        residue = Path(os.path.abspath(allowed_residue))
        try:
            relative_residue = residue.relative_to(evidence_root).as_posix()
        except ValueError as error:
            raise ValueError("browser-egress allowed residue is outside the evidence root") from error
        expected_files.add(relative_residue)
    for relative in tuple(expected_files):
        parent = PurePosixPath(relative).parent
        while str(parent) != ".":
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    inode_paths: dict[tuple[int, int], list[str]] = {}
    for path in evidence_root.rglob("*"):
        relative = path.relative_to(evidence_root).as_posix()
        metadata = path.lstat()
        if path.is_symlink():
            raise ValueError(f"browser-egress open inventory contains a symlink: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE
            ):
                raise ValueError(
                    f"browser-egress open directory has unsafe ownership/mode: {relative}"
                )
            actual_directories.add(relative)
        elif stat.S_ISREG(metadata.st_mode):
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE
                or metadata.st_nlink not in {1, 2}
            ):
                raise ValueError(
                    f"browser-egress open file has unsafe ownership/mode/links: {relative}"
                )
            actual_files.add(relative)
            inode_paths.setdefault((metadata.st_dev, metadata.st_ino), []).append(relative)
        else:
            raise ValueError(f"browser-egress open inventory contains an unsafe entry: {relative}")
    for paths in inode_paths.values():
        metadata = (evidence_root / paths[0]).lstat()
        if metadata.st_nlink != len(paths):
            raise ValueError("browser-egress open inventory contains an external hard link")
        if len(paths) == 2:
            if allowed_residue is None:
                raise ValueError("browser-egress open inventory contains an unexpected hard link")
            residue_relative = allowed_residue.relative_to(evidence_root).as_posix()
            if residue_relative not in paths:
                raise ValueError("browser-egress hard link is not the allowed crash residue")
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ValueError("browser-egress open evidence inventory is not exact")


def _recovery_attempt_directory(root: Path, *, intent: Mapping[str, Any]) -> Path:
    evidence = _safe_directory(
        root / EVIDENCE_DIRECTORY, label="browser-egress evidence", private=True
    )
    relative = PurePosixPath(intent["evidence_directory"])
    vector = evidence / relative.parts[1]
    attempt = vector / relative.parts[2]
    for path, parent, label in (
        (vector, evidence, "vector evidence"),
        (attempt, vector, "attempt evidence"),
    ):
        if path.is_symlink():
            raise ValueError(f"browser-egress {label} is a symlink")
        if not path.exists():
            path.mkdir(mode=PRIVATE_DIRECTORY_MODE)
            _fsync_directory(parent)
        else:
            _safe_directory(path, label=f"browser-egress {label}", private=True)
    return _safe_directory(
        attempt,
        label="browser-egress interrupted attempt evidence",
        private=True,
    )


def _validate_recovery_artifacts(path: Path, *, intent: Mapping[str, Any]) -> None:
    for artifact in path.iterdir():
        if artifact.name not in _RECOVERABLE_ATTEMPT_ARTIFACTS:
            raise ValueError("interrupted browser-egress attempt contains an unknown artifact")
        _private_regular_file(
            artifact, label="interrupted browser-egress artifact"
        )
    diagnostic = path / "failure.json"
    if diagnostic.exists():
        value = load_json(diagnostic)
        if (
            not isinstance(value, Mapping)
            or set(value) != {
                "schema_version",
                "vector_id",
                "attempt_number",
                "failure_code",
                "stage",
            }
            or value["schema_version"] != 1
            or value["vector_id"] != intent["vector"]["vector_id"]
            or value["attempt_number"] != intent["attempt_number"]
            or value["failure_code"] not in FAILURE_CODES
            or not isinstance(value["stage"], str)
            or _CODE.fullmatch(value["stage"]) is None
            or diagnostic.read_bytes() != canonical_json_bytes(value)
        ):
            raise ValueError("interrupted browser-egress failure diagnostic is invalid")


def resume_admission_plan(
    root: Path,
    *,
    tshark: Path = Path("/usr/bin/tshark"),
    dumpcap: Path = Path("/usr/bin/dumpcap"),
) -> dict[str, Any]:
    """Reconcile an exact crash residue, then bind the sole stale topology."""

    reconcile_qualification_filesystem(root, tshark=tshark, dumpcap=dumpcap)
    evidence_root = _safe_directory(
        root, label="browser-egress qualification root", private=True
    )
    foundation, binding = _load_foundation(evidence_root)
    rebuilt = _replay_checkpoint(
        evidence_root,
        foundation=foundation,
        foundation_binding=binding,
        deep=True,
        tshark=tshark,
        dumpcap=dumpcap,
    )
    checkpoint_path = safe_relative_artifact(
        evidence_root, CHECKPOINT_FILENAME, label="checkpoint"
    )
    stored = validate_checkpoint(load_json(checkpoint_path), foundation_binding=binding)
    publish_lag = stored != rebuilt
    if publish_lag:
        if len(stored["attempts"]) + 1 != len(rebuilt["attempts"]):
            raise ValueError("browser-egress checkpoint divergence is not recoverable")
        predecessor = _replay_checkpoint(
            evidence_root,
            foundation=foundation,
            foundation_binding=binding,
            deep=True,
            tshark=tshark,
            dumpcap=dumpcap,
            maximum_results=len(stored["attempts"]),
        )
        if stored != predecessor:
            raise ValueError("browser-egress checkpoint divergence is not an exact publish lag")
    records = _load_attempt_intents(evidence_root, foundation=foundation)
    _validate_attempt_intent_sequence(records, checkpoint=rebuilt)
    final_path = evidence_root / FINAL_FILENAME
    if final_path.exists() or final_path.is_symlink():
        _validate_existing_final_receipt(
            evidence_root, tshark=tshark, dumpcap=dumpcap
        )
    last_intent = records[-1]["payload"] if records else None
    return {
        "schema_version": 1,
        "checkpoint_publish_lag": publish_lag,
        "checkpoint_status": rebuilt["status"],
        "prepare_image_id": foundation["prepare_image"]["id"],
        "docker_root_dir": foundation["docker_daemon"]["docker_root_dir"],
        "cleanup": (
            None
            if last_intent is None
            else {
                "vector_id": last_intent["vector"]["vector_id"],
                "global_ordinal": last_intent["global_ordinal"],
                "attempt_number": last_intent["attempt_number"],
                "evidence_directory": last_intent["evidence_directory"],
                "topology_token": last_intent["topology_token"],
                "cohort_version": foundation["cohort_version"],
                "foundation_payload_sha256": canonical_json_sha256(foundation),
                "outstanding": len(records) == len(rebuilt["attempts"]) + 1,
            }
        ),
    }


def recover_interrupted_attempt(
    root: Path,
    *,
    finished_at: str,
    tshark: Path = Path("/usr/bin/tshark"),
    dumpcap: Path = Path("/usr/bin/dumpcap"),
) -> dict[str, Any]:
    """Repair one exact publish lag or seal one durable outstanding intent."""

    reconcile_qualification_filesystem(root, tshark=tshark, dumpcap=dumpcap)
    evidence_root = _safe_directory(
        root, label="browser-egress qualification root", private=True
    )
    foundation, binding = _load_foundation(evidence_root)
    rebuilt = _replay_checkpoint(
        evidence_root,
        foundation=foundation,
        foundation_binding=binding,
        deep=True,
        tshark=tshark,
        dumpcap=dumpcap,
    )
    checkpoint_path = safe_relative_artifact(
        evidence_root, CHECKPOINT_FILENAME, label="checkpoint"
    )
    stored = validate_checkpoint(load_json(checkpoint_path), foundation_binding=binding)
    if stored != rebuilt:
        if len(stored["attempts"]) + 1 != len(rebuilt["attempts"]):
            raise ValueError("browser-egress checkpoint divergence is not recoverable")
        predecessor = _replay_checkpoint(
            evidence_root,
            foundation=foundation,
            foundation_binding=binding,
            deep=True,
            tshark=tshark,
            dumpcap=dumpcap,
            maximum_results=len(stored["attempts"]),
        )
        if stored != predecessor:
            raise ValueError("browser-egress checkpoint divergence is not an exact publish lag")
        atomic_json(checkpoint_path, rebuilt)
        stored = rebuilt

    records = _load_attempt_intents(evidence_root, foundation=foundation)
    _validate_attempt_intent_sequence(records, checkpoint=stored)
    if len(records) == len(stored["attempts"]):
        return stored
    intent = records[-1]["payload"]
    attempt_directory = _recovery_attempt_directory(evidence_root, intent=intent)
    _validate_recovery_artifacts(attempt_directory, intent=intent)
    recovery_path = attempt_directory / "resume-recovery.json"
    if recovery_path.exists():
        recovery = _validate_recovery_diagnostic(
            _read_canonical_json_file(
                recovery_path, label="browser-egress recovery diagnostic"
            ),
            intent=intent,
        )
        recovery_finished_at = recovery["finished_at"]
    else:
        recovery_finished_at = finished_at
        recovery = {
            "schema_version": 1,
            "vector_id": intent["vector"]["vector_id"],
            "attempt_number": intent["attempt_number"],
            "failure_code": "interrupted",
            "stage": "resume-recovery",
            "finished_at": recovery_finished_at,
        }
        write_create_only_json(recovery_path, recovery)
    _validate_recovery_artifacts(attempt_directory, intent=intent)
    artifacts = [
        {
            "path": artifact.relative_to(evidence_root).as_posix(),
            "sha256": sha256_file(artifact),
            "size_bytes": artifact.stat().st_size,
        }
        for artifact in sorted(attempt_directory.iterdir(), key=lambda item: item.name)
    ]
    receipt = build_failure_result_receipt(
        foundation=foundation,
        global_ordinal=intent["global_ordinal"],
        attempt_number=intent["attempt_number"],
        previous_result_sha256=intent["previous_result_sha256"],
        vector_id=intent["vector"]["vector_id"],
        started_at=intent["started_at"],
        finished_at=recovery_finished_at,
        verdict="operational-failure",
        failure_code="interrupted",
        failure_artifacts=artifacts,
    )
    return append_result(evidence_root, receipt, tshark=tshark, dumpcap=dumpcap)


def _load_checkpoint_without_reconciliation(
    root: Path,
    *,
    deep: bool = False,
    tshark: Path = Path("/usr/bin/tshark"),
    dumpcap: Path = Path("/usr/bin/dumpcap"),
    allow_historical: bool = False,
) -> dict[str, Any]:
    evidence_root = _safe_directory(
        root, label="browser-egress qualification root", private=True
    )
    foundation, binding = _load_foundation(
        evidence_root, allow_historical=allow_historical
    )
    rebuilt = _replay_checkpoint(
        evidence_root,
        foundation=foundation,
        foundation_binding=binding,
        deep=deep,
        tshark=tshark,
        dumpcap=dumpcap,
    )
    stored_path = safe_relative_artifact(evidence_root, CHECKPOINT_FILENAME, label="checkpoint")
    stored = validate_checkpoint(load_json(stored_path), foundation_binding=binding)
    if stored != rebuilt:
        raise ValueError("browser-egress checkpoint does not reproduce from append-only results")
    return rebuilt


def load_checkpoint(
    root: Path,
    *,
    deep: bool = False,
    tshark: Path = Path("/usr/bin/tshark"),
    dumpcap: Path = Path("/usr/bin/dumpcap"),
) -> dict[str, Any]:
    """Rebuild the append-only ledger and compare the mutable resume checkpoint."""

    reconcile_qualification_filesystem(root, tshark=tshark, dumpcap=dumpcap)
    return _load_checkpoint_without_reconciliation(
        root, deep=deep, tshark=tshark, dumpcap=dumpcap
    )


def _build_final_payload_without_reconciliation(
    root: Path,
    *,
    recorded_at: str,
    tshark: Path = Path("/usr/bin/tshark"),
    dumpcap: Path = Path("/usr/bin/dumpcap"),
    allow_historical: bool = False,
) -> dict[str, Any]:
    evidence_root = _safe_directory(
        root, label="browser-egress qualification root", private=True
    )
    foundation, foundation_binding = _load_foundation(
        evidence_root, allow_historical=allow_historical
    )
    stored, checkpoint = _checkpoint_pair(
        evidence_root,
        foundation=foundation,
        binding=foundation_binding,
        deep=True,
        tshark=tshark,
        dumpcap=dumpcap,
    )
    if stored != checkpoint:
        raise ValueError("browser-egress checkpoint must be current before finalisation")
    if checkpoint["status"] != "complete" or len(checkpoint["passed_vector_ids"]) != VECTOR_COUNT:
        raise ValueError("browser-egress qualification is not complete")
    passed: list[dict[str, Any]] = []
    for entry in checkpoint["attempts"]:
        if entry["verdict"] == "passed":
            passed.append(
                {
                    "vector_ordinal": entry["vector_ordinal"],
                    "vector_id": entry["vector_id"],
                    "attempt_number": entry["attempt_number"],
                    "path": entry["path"],
                    "sha256": entry["sha256"],
                    "payload_sha256": entry["payload_sha256"],
                }
            )
    checkpoint_path = evidence_root / CHECKPOINT_FILENAME
    qualification_started_at = checkpoint["attempts"][0]["started_at"]
    qualification_finished_at = checkpoint["attempts"][-1]["finished_at"]
    if _timestamp(recorded_at, label="browser-egress final recorded_at") < _timestamp(
        qualification_finished_at, label="browser-egress qualification finish"
    ):
        raise ValueError("browser-egress final receipt predates qualification completion")
    return {
        "schema_version": FINAL_SCHEMA_VERSION,
        "qualification_id": QUALIFICATION_ID,
        "study_id": STUDY_ID,
        "cohort_version": foundation["cohort_version"],
        "qualification_started_at": qualification_started_at,
        "qualification_finished_at": qualification_finished_at,
        "recorded_at": recorded_at,
        "foundation": foundation_binding,
        "checkpoint": {
            "path": CHECKPOINT_FILENAME,
            "sha256": sha256_file(checkpoint_path),
        },
        "expanded_vectors_sha256": expanded_vectors_sha256(),
        "passed_results": passed,
        "attempt_count": len(checkpoint["attempts"]),
        "passed_vector_count": len(passed),
        "operational_failure_count": sum(
            entry["verdict"] == "operational-failure" for entry in checkpoint["attempts"]
        ),
        "semantic_failure_count": 0,
        "packet_level_egress_qualification": "passed",
        "consumer_contract": CONSUMER_CONTRACT,
        "verdict": "passed",
    }


def build_final_payload(
    root: Path,
    *,
    recorded_at: str,
    tshark: Path = Path("/usr/bin/tshark"),
    dumpcap: Path = Path("/usr/bin/dumpcap"),
) -> dict[str, Any]:
    evidence_root = _safe_directory(
        root, label="browser-egress qualification root", private=True
    )
    reconcile_qualification_filesystem(
        evidence_root, tshark=tshark, dumpcap=dumpcap
    )
    return _build_final_payload_without_reconciliation(
        evidence_root,
        recorded_at=recorded_at,
        tshark=tshark,
        dumpcap=dumpcap,
    )


def _validate_existing_final_receipt(
    root: Path, *, tshark: Path, dumpcap: Path
) -> Path:
    final_path = root / FINAL_FILENAME
    _private_regular_file(final_path, label="browser-egress final receipt")
    envelope = _read_canonical_json_file(
        final_path, label="browser-egress final receipt"
    )
    payload = validate_hash_bound_receipt(envelope, expected_type=FINAL_RECEIPT_TYPE)
    preliminary = validate_final_payload(payload)
    expected = _build_final_payload_without_reconciliation(
        root,
        recorded_at=preliminary["recorded_at"],
        tshark=tshark,
        dumpcap=dumpcap,
    )
    validate_final_payload(preliminary, expected=expected)
    return final_path


def validate_final_payload(
    value: object, *, expected: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    fields = {
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
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("browser-egress final receipt fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != FINAL_SCHEMA_VERSION
        or value["qualification_id"] != QUALIFICATION_ID
        or value["study_id"] != STUDY_ID
        or type(value["cohort_version"]) is not int
        or value["cohort_version"] < 1
        or value["expanded_vectors_sha256"] != expanded_vectors_sha256()
        or value["passed_vector_count"] != VECTOR_COUNT
        or value["semantic_failure_count"] != 0
        or value["packet_level_egress_qualification"] != "passed"
        or canonical_json_bytes(value["consumer_contract"])
        != canonical_json_bytes(CONSUMER_CONTRACT)
        or value["verdict"] != "passed"
    ):
        raise ValueError("browser-egress final receipt is not a passing v1 qualification")
    for key in ("attempt_count", "passed_vector_count", "operational_failure_count"):
        _integer(value[key], label=f"browser-egress final {key}")
    started = _timestamp(value["qualification_started_at"], label="browser-egress qualification start")
    finished = _timestamp(value["qualification_finished_at"], label="browser-egress qualification finish")
    recorded = _timestamp(value["recorded_at"], label="browser-egress final recorded_at")
    if not started <= finished <= recorded:
        raise ValueError("browser-egress final chronology is invalid")
    if value["attempt_count"] != value["passed_vector_count"] + value["operational_failure_count"]:
        raise ValueError("browser-egress final attempt counts do not reconcile")
    foundation = value["foundation"]
    if not isinstance(foundation, Mapping) or set(foundation) != {
        "path",
        "sha256",
        "payload_sha256",
    } or foundation["path"] != FOUNDATION_FILENAME:
        raise ValueError("browser-egress final foundation binding is invalid")
    _sha256(foundation["sha256"], label="final foundation file")
    _sha256(foundation["payload_sha256"], label="final foundation payload")
    checkpoint = value["checkpoint"]
    if not isinstance(checkpoint, Mapping) or set(checkpoint) != {"path", "sha256"} or checkpoint[
        "path"
    ] != CHECKPOINT_FILENAME:
        raise ValueError("browser-egress final checkpoint binding is invalid")
    _sha256(checkpoint["sha256"], label="final checkpoint")
    results = value["passed_results"]
    if not isinstance(results, list) or len(results) != VECTOR_COUNT:
        raise ValueError("browser-egress final passed-result inventory is incomplete")
    expected_ids = [row["vector_id"] for row in inventory_json()]
    if [row.get("vector_id") if isinstance(row, Mapping) else None for row in results] != expected_ids:
        raise ValueError("browser-egress final result order differs from the manifest")
    for ordinal, row in enumerate(results, 1):
        if not isinstance(row, Mapping) or set(row) != {
            "vector_ordinal",
            "vector_id",
            "attempt_number",
            "path",
            "sha256",
            "payload_sha256",
        }:
            raise ValueError("browser-egress final result binding fields are invalid")
        if (
            type(row["vector_ordinal"]) is not int
            or row["vector_ordinal"] != ordinal
            or type(row["attempt_number"]) is not int
            or not 1 <= row["attempt_number"] <= MAX_OPERATIONAL_ATTEMPTS
            or not isinstance(row["path"], str)
            or re.fullmatch(r"attempts/result-[0-9]{4}[.]json", row["path"]) is None
        ):
            # Exact global paths (including preceding operational failures)
            # are independently reproduced through ``expected`` in deep verify.
            raise ValueError("browser-egress final result binding is invalid")
        _sha256(row["sha256"], label="final vector result")
        _sha256(row["payload_sha256"], label="final vector payload")
    if len({row["path"] for row in results}) != VECTOR_COUNT:
        raise ValueError("browser-egress final result paths are duplicated")
    if expected is not None and value != expected:
        raise ValueError("browser-egress final receipt does not reproduce from its checkpoint")
    return json.loads(canonical_json_bytes(value))


def create_final_receipt(
    root: Path,
    *,
    recorded_at: str,
    tshark: Path = Path("/usr/bin/tshark"),
    dumpcap: Path = Path("/usr/bin/dumpcap"),
) -> Path:
    """Publish once, or verify and return the exact already-published receipt."""

    evidence_root = _safe_directory(
        root, label="browser-egress qualification root", private=True
    )
    reconcile_qualification_filesystem(
        evidence_root, tshark=tshark, dumpcap=dumpcap
    )
    final_path = evidence_root / FINAL_FILENAME
    if final_path.exists() or final_path.is_symlink():
        return _validate_existing_final_receipt(
            evidence_root, tshark=tshark, dumpcap=dumpcap
        )
    payload = _build_final_payload_without_reconciliation(
        evidence_root, recorded_at=recorded_at, tshark=tshark, dumpcap=dumpcap
    )
    receipt = bind_receipt(payload, receipt_type=FINAL_RECEIPT_TYPE)
    published = write_create_only_json(final_path, receipt)
    _durability_boundary("final:post-publish")
    validate_open_evidence_inventory(evidence_root, allow_final=True)
    return published


def validate_closed_evidence_inventory(
    root: Path, *, allow_historical: bool = False
) -> None:
    """Reject every unbound/missing file, directory, hard link, or symlink."""

    evidence_root = _safe_directory(
        root, label="browser-egress qualification root", private=True
    )
    validate_open_evidence_inventory(
        evidence_root,
        allow_final=True,
        allow_historical=allow_historical,
    )
    expected_files = {
        FOUNDATION_FILENAME,
        CHECKPOINT_FILENAME,
        FINAL_FILENAME,
    }
    attempts = _safe_directory(
        evidence_root / ATTEMPT_DIRECTORY,
        label="browser-egress attempts",
        private=True,
    )
    foundation, _binding = _load_foundation(
        evidence_root, allow_historical=allow_historical
    )
    intent_records = _load_attempt_intents(evidence_root, foundation=foundation)
    expected_files.update(record["binding"]["path"] for record in intent_records)
    for path in sorted(attempts.iterdir(), key=lambda item: item.name):
        relative = f"{ATTEMPT_DIRECTORY}/{path.name}"
        expected_files.add(relative)
        envelope = load_json(path)
        payload = validate_hash_bound_receipt(envelope, expected_type=RESULT_RECEIPT_TYPE)
        result = validate_result_payload(payload, foundation=foundation, evidence_root=evidence_root)
        if result["verdict"] == "passed":
            expected_files.add(result["capture"]["pcap"]["path"])
        else:
            expected_files.update(
                binding["path"] for binding in result["failure_evidence"]["artifacts"]
            )
    expected_directories = {
        ATTEMPT_DIRECTORY,
        ATTEMPT_INTENT_DIRECTORY,
        EVIDENCE_DIRECTORY,
    }
    for relative in expected_files:
        parent = PurePosixPath(relative).parent
        while str(parent) != ".":
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for path in evidence_root.rglob("*"):
        relative = path.relative_to(evidence_root).as_posix()
        metadata = path.lstat()
        if path.is_symlink():
            raise ValueError(f"browser-egress sealed inventory contains a symlink: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE
            ):
                raise ValueError(
                    f"browser-egress sealed inventory has unsafe directory mode: {relative}"
                )
            actual_directories.add(relative)
        elif (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == PRIVATE_FILE_MODE
        ):
            actual_files.add(relative)
        else:
            raise ValueError(f"browser-egress sealed inventory contains an unsafe entry: {relative}")
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ValueError("browser-egress sealed evidence inventory is not closed")


def verify_qualification(
    root: Path,
    *,
    lab_root: Path,
    expected_cohort_version: int | None = None,
    build_validator: Callable[..., Mapping[str, Any]] | None = None,
    verification_mode: FoundationVerificationMode = FoundationVerificationMode.PORTABLE_REPLAY,
    allow_historical: bool = False,
    tshark: Path = Path("/usr/bin/tshark"),
    dumpcap: Path = Path("/usr/bin/dumpcap"),
) -> dict[str, Any]:
    """Deep-verify foundation, PCAPs, sink reconciliation, chain, and final seal."""

    reconcile_qualification_filesystem(
        root,
        tshark=tshark,
        dumpcap=dumpcap,
        allow_historical=allow_historical,
    )
    evidence_root = _safe_directory(
        root, label="browser-egress qualification root", private=True
    )
    foundation, _binding = _load_foundation(
        evidence_root, allow_historical=allow_historical
    )
    deep_validate_foundation(
        foundation,
        lab_root=lab_root,
        build_validator=build_validator,
        mode=verification_mode,
        allow_historical=allow_historical,
    )
    if expected_cohort_version is not None and foundation["cohort_version"] != expected_cohort_version:
        raise ValueError("browser-egress qualification cohort version differs from expectation")
    _load_checkpoint_without_reconciliation(
        evidence_root,
        deep=True,
        tshark=tshark,
        dumpcap=dumpcap,
        allow_historical=allow_historical,
    )
    final_path = safe_relative_artifact(evidence_root, FINAL_FILENAME, label="final receipt")
    _private_regular_file(final_path, label="browser-egress final receipt")
    envelope = load_json(final_path)
    payload = validate_hash_bound_receipt(envelope, expected_type=FINAL_RECEIPT_TYPE)
    expected = _build_final_payload_without_reconciliation(
        evidence_root,
        recorded_at=payload["recorded_at"],
        tshark=tshark,
        dumpcap=dumpcap,
        allow_historical=allow_historical,
    )
    validated = validate_final_payload(payload, expected=expected)
    validate_closed_evidence_inventory(
        evidence_root, allow_historical=allow_historical
    )
    return {
        "path": str(final_path),
        "sha256": sha256_file(final_path),
        "payload_sha256": envelope["payload_sha256"],
        "qualification_id": QUALIFICATION_ID,
        "cohort_version": validated["cohort_version"],
        "qualification_started_at": validated["qualification_started_at"],
        "qualification_finished_at": validated["qualification_finished_at"],
        "recorded_at": validated["recorded_at"],
        "prepare_image_id": foundation["prepare_image"]["id"],
        "build_execution": dict(foundation["build_execution"]),
        "expanded_vectors_sha256": expanded_vectors_sha256(),
        "passed_vector_count": VECTOR_COUNT,
        "passed": True,
    }
