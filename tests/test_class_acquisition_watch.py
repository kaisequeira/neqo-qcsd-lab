from __future__ import annotations

import base64
import copy
import fcntl
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tools import class_acquisition_watch as watch

_REAL_VALIDATE_HOST_SOURCE = watch._validate_host_source


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def _target_activity() -> dict[str, Any]:
    by_target_type: dict[str, Any] = {}
    for target_type in watch._PINNED_CDP_TARGET_ACTIVITY_TYPES:
        attached = 0 if target_type == "page" else 1
        by_target_type[target_type] = {
            "total": attached,
            "max_source_generation": 0 if attached else None,
            "event_counts": {
                event: attached if event == "target-attached" else 0
                for event in watch._PINNED_CDP_TARGET_ACTIVITY_EVENTS
            },
        }
    return {
        "schema_version": watch._PINNED_CDP_TARGET_ACTIVITY_SCHEMA_VERSION,
        "generation": 3,
        "by_target_type": by_target_type,
    }


def _srcdoc_pseudo_document_summary(
    *,
    terminal_method: str = "Network.loadingFailed",
) -> dict[str, Any]:
    loader_digest = hashlib.sha256(b"fixture-srcdoc-loader").hexdigest()
    summary: dict[str, Any] = {
        "schema_version": watch._PINNED_CDP_SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
        "policy": watch._PINNED_CDP_SRCDOC_PSEUDO_DOCUMENT_POLICY,
        "enabled": True,
        "total": 1,
        "resolved": 1,
        "pending": 0,
        "aborted": 0,
        "open_candidates": 0,
        "network_history_saturated": False,
        "fetch_history_saturated": False,
        "candidate_limit_saturated": False,
        "terminal_outcome_counts": {
            "Network.loadingFailed": 1,
            "Network.loadingFinished": 0,
        },
        "diagnostics": [
            {
                "schema_version": 3,
                "source_role": "root-page",
                "frame_id_sha256": hashlib.sha256(b"fixture-srcdoc-frame").hexdigest(),
                "loader_id_sha256": loader_digest,
                "request_id_sha256": loader_digest,
                "requested_event_ordinal": 1,
                "started_navigating_event_ordinal": 2,
                "started_event_ordinal": 3,
                "terminal_event_ordinal": 4,
                "stopped_event_ordinal": 5,
                "navigation_reason": "initialFrameNavigation",
                "navigation_type": "differentDocument",
                "disposition": "currentTab",
                "url_kind": "about:srcdoc",
                "loader_binding": "Page.frameStartedNavigating.loaderId",
                "request_id_matches_loader": True,
                "terminal_variant": "loading-failed-document-abort",
                "terminal_method": "Network.loadingFailed",
                "terminal_fields": [
                    "canceled",
                    "errorText",
                    "requestId",
                    "timestamp",
                    "type",
                ],
                "resource_type": "Document",
                "error_text": "net::ERR_ABORTED",
                "canceled": True,
                "encoded_data_length": None,
                "network_request_seen": False,
                "fetch_pause_seen": False,
                "frame_stopped_after_terminal": True,
            }
        ],
    }
    if terminal_method == "Network.loadingFinished":
        summary["terminal_outcome_counts"] = {
            "Network.loadingFailed": 0,
            "Network.loadingFinished": 1,
        }
        summary["diagnostics"][0].update(
            {
                "terminal_variant": "loading-finished",
                "terminal_method": "Network.loadingFinished",
                "terminal_fields": ["encodedDataLength", "requestId", "timestamp"],
                "resource_type": None,
                "error_text": None,
                "canceled": None,
                "encoded_data_length": 33,
            }
        )
    elif terminal_method != "Network.loadingFailed":
        raise AssertionError(f"unsupported terminal method: {terminal_method}")
    return summary


def _egress_prearm_summary() -> dict[str, Any]:
    by_target_type = {}
    for target_type in ("page", "iframe", "worker", "shared_worker"):
        popup_required = 1 if target_type in {"page", "iframe"} else 0
        by_target_type[target_type] = {
            "target_count": 1,
            "installed_count": 1,
            "pending_count": 0,
            "protected_api_observations": watch._target_egress_api_count(target_type),
            "unavailable_api_observations": 0,
            "popup_guard_required_count": popup_required,
            "popup_guard_installed_count": popup_required,
        }
    return {
        "schema_version": watch._EGRESS_PREARM_SUMMARY_SCHEMA_VERSION,
        "policy": watch._NON_REPLAYABLE_EGRESS_POLICY,
        "target_total": 4,
        "installed_total": 4,
        "pending_total": 0,
        "popup_guard_required_total": 2,
        "popup_guard_installed_total": 2,
        "by_target_type": by_target_type,
    }


def _non_replayable_egress_summary() -> dict[str, Any]:
    return {
        "schema_version": watch._NON_REPLAYABLE_EGRESS_SCHEMA_VERSION,
        "policy": watch._NON_REPLAYABLE_EGRESS_POLICY,
        "attempt_count": 0,
        "protected_apis": copy.deepcopy(watch._TARGET_EGRESS_APIS),
        "context_init_script_installed": True,
        "context_navigation_route_installed": True,
        "root_page_bound": True,
        "context_websocket_route_installed": True,
        "context_service_worker_listener_installed": True,
        "cdp_tripwires_are_pre_io": False,
        "packet_level_completeness_claimed": False,
    }


def _browser_egress_command_line() -> dict[str, Any]:
    switches = copy.deepcopy(watch._BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES)
    return {
        "schema_version": watch._BROWSER_EGRESS_COMMAND_LINE_SCHEMA_VERSION,
        "launch_profile": watch._BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE,
        "required_switches": switches,
        "observed_required_switches": copy.deepcopy(switches),
        "antagonistic_switches": copy.deepcopy(
            watch._BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES
        ),
        "observed_antagonistic_switches": [],
        "required_disabled_feature_tokens": copy.deepcopy(
            watch._BROWSER_EGRESS_REQUIRED_DISABLED_FEATURE_TOKENS
        ),
        "observed_disabled_feature_tokens": copy.deepcopy(
            watch._BROWSER_EGRESS_REQUIRED_DISABLED_FEATURE_TOKENS
        ),
        "required_disabled_blink_feature_tokens": copy.deepcopy(
            watch._BROWSER_EGRESS_REQUIRED_DISABLED_BLINK_FEATURE_TOKENS
        ),
        "observed_disabled_blink_feature_tokens": copy.deepcopy(
            watch._BROWSER_EGRESS_REQUIRED_DISABLED_BLINK_FEATURE_TOKENS
        ),
        "required_enabled_feature_arguments": copy.deepcopy(
            watch._BROWSER_EGRESS_REQUIRED_ENABLED_FEATURE_ARGUMENTS
        ),
        "observed_enabled_feature_arguments": copy.deepcopy(
            watch._BROWSER_EGRESS_REQUIRED_ENABLED_FEATURE_ARGUMENTS
        ),
        "feature_switch_argument_counts": {
            "disable_features": 2,
            "disable_blink_features": 1,
            "enable_features": 1,
            "enable_blink_features": 0,
        },
        "complete_feature_policy_is_last": True,
        "subprocess_wrapper_argument": watch._BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT,
        "required_switches_are_bare_and_unique": True,
        "host_resolver_switch_is_unique": True,
        "host_resolver_is_fail_closed": True,
        "host_resolver_policy": copy.deepcopy(watch._PINNED_CDP_RESOLVER_PROJECTION),
        "no_pings_is_admission_boundary": False,
        "packet_level_completeness_claimed": False,
    }


def _receipt(receipt_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "receipt_type": receipt_type,
        "payload_sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
        "payload": copy.deepcopy(payload),
    }


def _write_receipt(path: Path, receipt_type: str, payload: dict[str, Any]) -> None:
    path.write_bytes(_canonical(_receipt(receipt_type, payload)))


@pytest.mark.parametrize("historical_schema", (1, 2, 3, 4, 5, 6))
def test_receipt_loader_accepts_legitimate_historical_payload_schemas(
    tmp_path: Path,
    historical_schema: int,
) -> None:
    path = tmp_path / "historical.json"
    payload = {"acquisition_schema_version": historical_schema}
    _write_receipt(path, "historical-acquisition", payload)

    snapshot = watch._load_canonical_receipt(
        path,
        root=tmp_path,
        receipt_type="historical-acquisition",
        label="historical acquisition",
    )

    assert snapshot.value["payload"] == payload


@pytest.mark.parametrize("schema_alias", (True, 1.0, "1"))
def test_receipt_loader_requires_an_exact_integer_envelope_schema(
    tmp_path: Path,
    schema_alias: object,
) -> None:
    path = tmp_path / "receipt.json"
    receipt = _receipt("test-receipt", {"historical_schema": 1})
    receipt["schema_version"] = schema_alias
    path.write_bytes(_canonical(receipt))

    with pytest.raises(watch.WatchError, match="another schema or receipt type"):
        watch._load_canonical_receipt(
            path,
            root=tmp_path,
            receipt_type="test-receipt",
            label="test receipt",
        )


def _write_build_execution(path: Path, payload: dict[str, Any]) -> None:
    value = copy.deepcopy(payload)
    value["payload_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    path.write_bytes(_canonical(value))
    path.chmod(0o600)


def _buildx_provenance() -> dict[str, Any]:
    reported_path = "/usr/local/lib/docker/cli-plugins/docker-buildx"
    symlink_target = (
        "/mnt/wsl/docker-desktop/cli-tools/usr/local/lib/docker/cli-plugins/docker-buildx"
    )
    version = "v0.29.1-desktop.1"
    commit = "28f6246ff24e2c05095e8741e48c48dcb2d3b4bc"
    identity = {
        "selection_source": "docker-info-client-plugin-metadata-v1",
        "plugin_name": "buildx",
        "plugin_vendor": "Docker Inc.",
        "metadata_schema_version": "0.1.0",
        "short_description": "Docker Buildx",
        "reported_plugin_version": version,
        "reported_plugin_path": reported_path,
        "plugin": {
            "path": reported_path,
            "symlink_target": symlink_target,
            "dev": 2096,
            "inode": 280747,
            "uid": 0,
            "gid": 0,
            "mode": stat.S_IFLNK | 0o777,
            "nlink": 1,
            "size": len(symlink_target.encode()),
            "mtime_ns": 1_788_582_497_670_041_680,
            "ctime_ns": 1_788_582_497_670_041_680,
        },
        "resolved": {
            "path": symlink_target,
            "dev": 1792,
            "inode": 2122,
            "uid": 0,
            "gid": 0,
            "mode": stat.S_IFREG | 0o755,
            "nlink": 1,
            "size": 65_994_936,
            "mtime_ns": 1_763_156_518_000_000_000,
            "ctime_ns": 1_763_166_552_000_000_000,
            "sha256": "9" * 64,
        },
        "version_output": f"github.com/docker/buildx {version} {commit}",
        "version": version,
        "commit": commit,
    }
    identity_sha256 = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": 1,
        "policy": "docker-selected-buildx-binary-stability-v1",
        "identity": identity,
        "observations": [
            {
                "boundary": boundary,
                "observed_at": observed_at,
                "identity_sha256": identity_sha256,
            }
            for boundary, observed_at in (
                ("before-collection", "2026-08-28T00:00:01+00:00"),
                ("after-collection", "2026-08-28T00:15:00+00:00"),
                ("after-prepare", "2026-08-28T00:30:00+00:00"),
                ("after-reference", "2026-08-28T00:59:59+00:00"),
            )
        ],
        "passed": True,
    }


def _compact_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


def _git_object_oid(object_type: bytes, payload: bytes) -> str:
    digest = hashlib.sha1()
    digest.update(object_type + b" " + str(len(payload)).encode("ascii") + b"\0")
    digest.update(payload)
    return digest.hexdigest()


def _git_tree_payload(entries: list[tuple[bytes, bytes, str]]) -> bytes:
    ordered = sorted(
        entries,
        key=lambda entry: entry[1] + (b"/" if entry[0] == b"40000" else b""),
    )
    return b"".join(mode + b" " + name + b"\0" + bytes.fromhex(oid) for mode, name, oid in ordered)


def _cohort_allocation(
    *,
    cohort_version: int,
    neqo_commit: str,
) -> dict[str, Any]:
    ledger = {
        "schema_version": 1,
        "artifact_type": watch._COHORT_LEDGER_TYPE,
        "policy": watch._COHORT_ALLOCATION_POLICY,
        "consumed_versions": list(range(1, cohort_version)),
    }
    ledger_raw = json.dumps(ledger, sort_keys=True, separators=(",", ":")).encode("ascii")
    ledger_blob_oid = _git_object_oid(b"blob", ledger_raw)
    v1_tree = _git_tree_payload([(b"100644", b"consumed-cohorts.json", ledger_blob_oid)])
    study_tree = _git_tree_payload([(b"40000", b"v1", _git_object_oid(b"tree", v1_tree))])
    config_tree = _git_tree_payload(
        [(b"40000", b"buflo-study", _git_object_oid(b"tree", study_tree))]
    )
    root_tree = _git_tree_payload(
        [
            (b"40000", b"config", _git_object_oid(b"tree", config_tree)),
            (b"160000", b"neqo-qcsd", neqo_commit),
        ]
    )
    commit_payload = (
        f"tree {_git_object_oid(b'tree', root_tree)}\n"
        "author QCSD Test <qcsd@example.invalid> 0 +0000\n"
        "committer QCSD Test <qcsd@example.invalid> 0 +0000\n"
        "\n"
        "watcher cohort proof\n"
    ).encode("ascii")
    lab_commit = _git_object_oid(b"commit", commit_payload)
    return {
        "schema_version": 1,
        "artifact_type": watch._COHORT_ALLOCATION_TYPE,
        "policy": watch._COHORT_ALLOCATION_POLICY,
        "ledger_path": watch._COHORT_LEDGER_PATH,
        "ledger_sha256": hashlib.sha256(ledger_raw).hexdigest(),
        "ledger_payload_base64": base64.b64encode(ledger_raw).decode("ascii"),
        "git_object_format": "sha1",
        "ledger_git_blob_oid": ledger_blob_oid,
        "lab_commit": lab_commit,
        "neqo_commit": neqo_commit,
        "neqo_gitlink": neqo_commit,
        "lab_commit_ledger_proof": {
            "schema_version": 1,
            "artifact_type": watch._COHORT_GIT_PROOF_TYPE,
            "commit_payload_base64": base64.b64encode(commit_payload).decode("ascii"),
            "tree_payloads_base64": [
                base64.b64encode(payload).decode("ascii")
                for payload in (root_tree, config_tree, study_tree, v1_tree)
            ],
        },
        "last_consumed_version": cohort_version - 1,
        "allocated_version": cohort_version,
    }


def _cohort_file_stat(*, inode: int, mode: int, size: int) -> dict[str, int]:
    return {
        "dev": 1,
        "inode": inode,
        "uid": 1000,
        "gid": 1000,
        "mode": mode,
        "nlink": 1,
        "size": size,
        "mtime_ns": 1_000_000_000 + inode,
        "ctime_ns": 2_000_000_000 + inode,
    }


def _cohort_authority(allocation: dict[str, Any]) -> dict[str, Any]:
    ledger_size = len(base64.b64decode(allocation["ledger_payload_base64"]))
    directories = {
        name: {
            **_cohort_file_stat(inode=100 + index, mode=0o755, size=4096),
            "nlink": 2,
        }
        for index, name in enumerate(("repository-root", "config", "buflo-study", "v1", "git"))
    }
    return {
        "schema_version": 1,
        "artifact_type": watch._COHORT_AUTHORITY_TYPE,
        "git": {
            "object_format": "sha1",
            "lab_head": allocation["lab_commit"],
            "head_blob_oid": allocation["ledger_git_blob_oid"],
            "index_blob_oid": allocation["ledger_git_blob_oid"],
            "worktree_blob_oid": allocation["ledger_git_blob_oid"],
            "neqo_head": allocation["neqo_commit"],
            "head_gitlink": allocation["neqo_gitlink"],
            "index_gitlink": allocation["neqo_gitlink"],
        },
        "filesystem": {
            "directories": directories,
            "ledger": _cohort_file_stat(inode=200, mode=0o644, size=ledger_size),
            "git_index": _cohort_file_stat(inode=201, mode=0o644, size=4096),
        },
        "receipt": copy.deepcopy(allocation),
    }


def _cohort_evidence(
    allocation: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    version = allocation["allocated_version"]
    authority = _cohort_authority(allocation)
    authority_sha256 = _compact_digest(authority)
    claim_payload = {
        "policy": watch._COHORT_ALLOCATION_POLICY,
        "registry_path": watch._COHORT_CLAIM_REGISTRY_PATH,
        "cohort_version": version,
        "authority": authority,
        "authority_sha256": authority_sha256,
        "source": {
            "lab_commit": allocation["lab_commit"],
            "neqo_commit": allocation["neqo_commit"],
            "neqo_gitlink": allocation["neqo_gitlink"],
        },
        "ledger": {
            "path": allocation["ledger_path"],
            "sha256": allocation["ledger_sha256"],
            "git_object_format": allocation["git_object_format"],
            "git_blob_oid": allocation["ledger_git_blob_oid"],
            "payload_base64": allocation["ledger_payload_base64"],
            "last_consumed_version": allocation["last_consumed_version"],
        },
        "predecessor": {
            "kind": "genesis-ledger",
            "cohort_version": allocation["last_consumed_version"],
            "sha256": allocation["ledger_sha256"],
        },
    }
    claim = {
        "schema_version": 1,
        "artifact_type": watch._COHORT_CLAIM_TYPE,
        "payload": claim_payload,
        "payload_sha256": _compact_digest(claim_payload),
    }
    claim_raw = (
        json.dumps(claim, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("ascii")
    claim_sha256 = hashlib.sha256(claim_raw).hexdigest()
    encoded_claim = base64.b64encode(claim_raw).decode("ascii")
    snapshot = {
        "schema_version": 1,
        "artifact_type": watch._COHORT_CLAIM_SNAPSHOT_TYPE,
        "policy": watch._COHORT_ALLOCATION_POLICY,
        "cohort_version": version,
        "registry": {
            "path": watch._COHORT_CLAIM_REGISTRY_PATH,
            "stat": {
                "dev": 1,
                "inode": 300,
                "uid": 1000,
                "gid": 1000,
                "mode": 0o700,
                "nlink": 2,
            },
        },
        "claim": {
            "path": f"{watch._COHORT_CLAIM_REGISTRY_PATH}/claim-v{version}.json",
            "sha256": claim_sha256,
            "payload_base64": encoded_claim,
            "stat": _cohort_file_stat(inode=301, mode=0o600, size=len(claim_raw)),
        },
        "registry_head_at_publication": {
            "cohort_version": version,
            "sha256": claim_sha256,
        },
    }
    snapshot["payload_sha256"] = _compact_digest(snapshot)
    chain = {
        "schema_version": 1,
        "artifact_type": watch._COHORT_CLAIM_CHAIN_TYPE,
        "policy": watch._COHORT_ALLOCATION_POLICY,
        "genesis": {
            "ledger_path": allocation["ledger_path"],
            "ledger_sha256": allocation["ledger_sha256"],
            "last_consumed_version": allocation["last_consumed_version"],
        },
        "claims": [
            {
                "cohort_version": version,
                "sha256": claim_sha256,
                "payload_base64": encoded_claim,
            }
        ],
        "head": {"cohort_version": version, "sha256": claim_sha256},
    }
    chain["payload_sha256"] = _compact_digest(chain)
    reproof_times = (
        "2026-08-28T00:00:00.100000+00:00",
        "2026-08-28T00:00:00.200000+00:00",
        "2026-08-28T00:00:00.300000+00:00",
        "2026-08-28T00:00:00.400000+00:00",
        "2026-08-28T00:00:00.500000+00:00",
        "2026-08-28T00:00:02+00:00",
        "2026-08-28T00:16:00+00:00",
        "2026-08-28T00:31:00+00:00",
        "2026-08-28T00:59:59.500000+00:00",
    )
    snapshot_sha256 = _compact_digest(snapshot)
    reproofs = [
        {
            "boundary": boundary,
            "observed_at": observed_at,
            "authority_sha256": authority_sha256,
            "claim_snapshot_sha256": snapshot_sha256,
            "claim_file_sha256": claim_sha256,
        }
        for boundary, observed_at in zip(
            watch._COHORT_REPROOF_BOUNDARIES,
            reproof_times,
            strict=True,
        )
    ]
    return snapshot, chain, reproofs


def _write_build_completion(
    path: Path,
    *,
    build_path: Path,
    build: dict[str, Any],
) -> None:
    build_raw = build_path.read_bytes()
    metadata = build_path.stat(follow_symlinks=False)
    allocation = build["cohort_allocation"]
    claim = build["cohort_claim"]
    chain = build["cohort_claim_chain"]
    claim_raw = base64.b64decode(claim["claim"]["payload_base64"], validate=True)
    claim_value = json.loads(claim_raw)
    authority_sha256 = _compact_digest(claim_value["payload"]["authority"])
    chain_raw = json.dumps(chain, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "ascii"
    )
    build_root = Path(build["commands"][0]["argv"][-1])
    lease_nonce = "d" * 64
    lifecycle_base = build_root / ".qcsd-test-lifecycle"
    lifecycle_lock_path = Path(f"{lifecycle_base}.lock")
    transaction_root = lifecycle_base / f"transaction.{lease_nonce[:32]}"
    cohort_registry = build_root / "artifacts/buflo-study/cohort-claims-v1"
    transaction_fields = {
        "object": "docker-build-transaction",
        "lifecycle_schema": "1",
        "lifecycle_state": "request-authorised",
        "lifecycle_root": str(transaction_root),
        "lifecycle_token": lease_nonce[:32],
        "supervisor_source_path": str(build_root / "tools/docker_signal_supervisor.sh"),
        "supervisor_source_sha256": "e" * 64,
        "supervisor_source_device": "10",
        "supervisor_source_inode": "401",
        "docker_context": build["docker"]["context"],
        "docker_host": build["docker"]["endpoint"],
        "docker_server_id": build["docker"]["server_id"],
        "docker_request_revalidation": "in-scope-immediately-before-mutation",
        "docker_daemon_id": build["docker"]["server_id"],
        "host_boot_id": "00000000-0000-0000-0000-000000000001",
        "working_directory": str(build_root),
        "cohort_version": str(build["cohort_version"]),
        "receipt_path": str(build_path),
        "transaction_state": "uncommitted-static-tag-mutation",
    }
    transaction_raw = "".join(
        f"{field}={transaction_fields[field]}\n" for field in watch._BUILD_TRANSACTION_RECORD_FIELDS
    ).encode("ascii")
    transaction = {
        "schema_version": 1,
        "artifact_type": watch._BUILD_TRANSACTION_RETIREMENT_TYPE,
        "root": {
            "path": str(transaction_root),
            "stat": {
                "dev": 10,
                "inode": 402,
                "uid": 1000,
                "gid": 1000,
                "mode": 0o700,
                "nlink": 2,
            },
        },
        "record": {
            "path": str(transaction_root / "SUPERVISION"),
            "sha256": hashlib.sha256(transaction_raw).hexdigest(),
            "payload_base64": base64.b64encode(transaction_raw).decode("ascii"),
            "stat": _cohort_file_stat(
                inode=403,
                mode=0o600,
                size=len(transaction_raw),
            ),
        },
        "guardian": {
            "pid": 410,
            "start_time": 411,
            "qcsd_pid": 412,
            "qcsd_start_time": 413,
        },
        "lifecycle_lock": {
            "path": str(lifecycle_lock_path),
            "device": 10,
            "inode": 414,
            "parent_device": 10,
            "parent_inode": 415,
            "lease_nonce": lease_nonce,
        },
        "cohort_lock": {
            "path": str(cohort_registry / ".allocation.lock"),
            "device": 10,
            "inode": 416,
            "parent_device": 10,
            "parent_inode": 417,
            "guardian_fd": 7,
        },
        "operation_lock": {
            "path": str(cohort_registry / ".allocation-operation.lock"),
            "device": 10,
            "inode": 418,
            "parent_device": 10,
            "parent_inode": 417,
        },
    }
    payload = {
        "schema_version": 1,
        "artifact_type": watch.BUILD_COMPLETION_TYPE,
        "cohort_version": build["cohort_version"],
        "completed_at": "2026-08-28T01:00:00.200000+00:00",
        "receipt": {
            "path": f"artifacts/buflo-study/{build_path.name}",
            "schema_version": 5,
            "cohort_version": build["cohort_version"],
            "payload_sha256": build["payload_sha256"],
            "sha256": hashlib.sha256(build_raw).hexdigest(),
            "stat": {
                "dev": metadata.st_dev,
                "inode": metadata.st_ino,
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "mode": stat.S_IMODE(metadata.st_mode),
                "nlink": metadata.st_nlink,
                "size": metadata.st_size,
                "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
            },
        },
        "source": {
            "lab_commit": build["source"]["lab_commit"],
            "neqo_commit": build["source"]["neqo_commit"],
            "neqo_gitlink": allocation["neqo_gitlink"],
        },
        "cohort_authority": {
            "allocation_sha256": _compact_digest(allocation),
            "claim_snapshot_sha256": _compact_digest(claim),
            "claim_file_sha256": hashlib.sha256(claim_raw).hexdigest(),
            "claim_chain_sha256": hashlib.sha256(chain_raw).hexdigest(),
            "claim_chain_payload_sha256": chain["payload_sha256"],
        },
        "transaction": transaction,
        "final_reproof": {
            "boundary": watch._BUILD_COMPLETION_REPROOF_BOUNDARY,
            "observed_at": "2026-08-28T01:00:00.100000+00:00",
            "authority_sha256": authority_sha256,
            "claim_snapshot_sha256": _compact_digest(claim),
            "claim_file_sha256": hashlib.sha256(claim_raw).hexdigest(),
            "claim_chain_sha256": hashlib.sha256(chain_raw).hexdigest(),
        },
    }
    payload["payload_sha256"] = _compact_digest(payload)
    path.write_bytes(
        (json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode(
            "ascii"
        )
    )
    path.chmod(0o600)


def _batch(prefix: str, body: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(body)
    value["batch_id"] = f"{prefix}-{hashlib.sha256(_canonical(body)).hexdigest()}"
    return value


def _checkpoint_payload(acquisition: Fixture) -> dict[str, Any]:
    return copy.deepcopy(
        json.loads(acquisition.paths.checkpoint.read_text(encoding="utf-8"))["payload"]
    )


def _replace_checkpoint(acquisition: Fixture, payload: dict[str, Any]) -> None:
    _write_receipt(acquisition.paths.checkpoint, watch.CHECKPOINT_TYPE, payload)


@dataclass
class Fixture:
    paths: watch.WatchPaths
    image: str
    candidate_ids: list[str]
    foundation_path: Path
    pinned_cdp_path: Path
    build_execution_path: Path
    build_completion_path: Path
    browser_egress_root: Path
    browser_egress_final_path: Path

    def advance_checkpoint(self) -> None:
        value = json.loads(self.paths.checkpoint.read_text(encoding="utf-8"))
        payload = copy.deepcopy(value["payload"])
        first = payload["candidates"][self.candidate_ids[0]]
        first["watch_test_revision"] = first.get("watch_test_revision", 0) + 1
        _write_receipt(self.paths.checkpoint, watch.CHECKPOINT_TYPE, payload)
        _materialise_selection(self, _selection_fixture(watch.CANDIDATE_COUNT))


@pytest.fixture
def acquisition(tmp_path: Path) -> Fixture:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path,
        state_base=tmp_path / "host-watch-state",
    )
    paths.candidate_catalogue.parent.mkdir(parents=True)
    source_root = Path(__file__).resolve().parents[1]
    for relative in (
        watch.BROWSER_EGRESS_MANIFEST_RELATIVE_PATH,
        watch.BROWSER_EGRESS_ARGV_RELATIVE_PATH,
    ):
        target = paths.lab_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source_root / relative).read_bytes())
    paths.acquisition_root.mkdir(parents=True)
    paths.action_lock.write_bytes(b"")
    paths.stability_root.mkdir(parents=True)
    paths.workload_root.mkdir(parents=True)
    paths.launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    paths.launcher.chmod(0o755)
    (paths.lab_root / "tools").mkdir()
    (paths.lab_root / "tools/windows_docker_storage_probe.ps1").write_text(
        "# exact fixture storage probe\n", encoding="utf-8"
    )
    (paths.lab_root / "neqo-qcsd").mkdir()
    (paths.lab_root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (paths.lab_root / "uv.lock").write_text("fixture uv lock\n", encoding="utf-8")
    (paths.lab_root / "neqo-qcsd/Cargo.lock").write_text("fixture Cargo lock\n", encoding="utf-8")

    candidate_ids = [f"tranco-{rank:07d}" for rank in range(1, watch.CANDIDATE_COUNT + 1)]
    catalogue_payload = {
        "study_id": watch.STUDY_ID,
        "catalogue_schema_version": 1,
        "tranco": {"list_sha256": "a" * 64},
        "selection": {},
        "candidates": [
            {
                "candidate_id": candidate_id,
                "domain": f"site-{rank}.example",
                "rank": rank,
                "stratum": "test",
                "eligible": False,
            }
            for rank, candidate_id in enumerate(candidate_ids, 1)
        ],
    }
    _write_receipt(paths.candidate_catalogue, watch.CATALOGUE_TYPE, catalogue_payload)
    catalogue = json.loads(paths.candidate_catalogue.read_text(encoding="utf-8"))
    catalogue_sha256 = hashlib.sha256(paths.candidate_catalogue.read_bytes()).hexdigest()

    image = "sha256:" + "a" * 64
    collection_image = "sha256:" + "e" * 64
    cohort_allocation = _cohort_allocation(cohort_version=23, neqo_commit="c" * 40)
    cohort_claim, cohort_chain, cohort_reproofs = _cohort_evidence(cohort_allocation)
    collection_source = {
        "image_digest": collection_image,
        "lab_commit": cohort_allocation["lab_commit"],
        "lab_dirty": False,
        "lab_patch_sha256": watch.EMPTY_SHA256,
        "neqo_commit": "c" * 40,
        "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": watch.EMPTY_SHA256,
    }
    prepare_source = {**collection_source, "image_digest": image}
    build_execution_path = paths.lab_root / "artifacts/buflo-study/build-execution-v23.json"
    build_execution_path.parent.mkdir(parents=True)
    reference_image = "sha256:" + "f" * 64
    build_images = {
        "collection": {
            "tag": watch.BUILD_IMAGE_TAGS["collection"],
            "id": collection_image,
            "repo_digests": [],
        },
        "prepare": {
            "tag": watch.BUILD_IMAGE_TAGS["prepare"],
            "id": image,
            "repo_digests": [],
        },
        "reference": {
            "tag": watch.BUILD_IMAGE_TAGS["reference"],
            "id": reference_image,
            "repo_digests": [],
        },
    }
    build_root = str(paths.lab_root.resolve())
    build_commands = []
    for target in ("collection", "prepare", "reference"):
        build_commands.append(
            {
                "target": target,
                "argv": [
                    "docker",
                    "--host",
                    "unix:///var/run/docker.sock",
                    "build",
                    "--pull",
                    "--no-cache",
                    "--iidfile",
                    (f"{build_root}/artifacts/buflo-study/.build-iids-v23.ABC123/{target}.iid"),
                    "--target",
                    target,
                    "--tag",
                    build_images[target]["tag"],
                    "--file",
                    f"{build_root}/Dockerfile",
                    build_root,
                ],
                "exit_code": 0,
                "image_id": build_images[target]["id"],
            }
        )
    build_inputs = {
        "schema_version": 1,
        "artifact_type": "qcsd-study-build-inputs",
        "rust_base_image": watch.BUILD_RUST_BASE_IMAGE,
        "debian_base_image": watch.BUILD_DEBIAN_BASE_IMAGE,
        "uv_lock_sha256": hashlib.sha256((paths.lab_root / "uv.lock").read_bytes()).hexdigest(),
        "cargo_lock_sha256": hashlib.sha256(
            (paths.lab_root / "neqo-qcsd/Cargo.lock").read_bytes()
        ).hexdigest(),
    }
    _write_build_execution(
        build_execution_path,
        {
            "schema_version": 5,
            "artifact_type": watch.BUILD_EXECUTION_TYPE,
            "cohort_version": 23,
            "started_at": "2026-08-28T00:00:00+00:00",
            "finished_at": "2026-08-28T01:00:00+00:00",
            "duration_seconds": 3600.0,
            "docker": {
                "client_version": "29.0.1",
                "server_version": "29.0.1",
                "context": "default",
                "endpoint": "unix:///var/run/docker.sock",
                "server_name": "fixture-docker",
                "server_operating_system": "Ubuntu 24.04",
                "server_os_type": "linux",
                "server_architecture": "x86_64",
                "server_id": "fixture-server-id",
            },
            "commands": build_commands,
            "source": collection_source,
            "images": build_images,
            "build_inputs": build_inputs,
            "dockerfile_sha256": hashlib.sha256(
                (paths.lab_root / "Dockerfile").read_bytes()
            ).hexdigest(),
            "cache_policy": {
                "pull": True,
                "no_cache": True,
                "scope": (
                    "Docker-layer-cache-disabled;declared-BuildKit-dependency-cache-mounts-only"
                ),
            },
            "host_storage_preflight": {
                "schema_version": 1,
                "applicable": False,
                "platform": "other-host",
                "platform_detection": {
                    "schema_version": 1,
                    "probe": "wsl-multi-signal-v1",
                    "kernel_release": "6.8.0-fixture",
                    "proc_version": "Linux version 6.8.0-fixture",
                    "wsl_interop_env_present": False,
                    "wsl_distro_name_env_present": False,
                    "run_wsl_directory_present": False,
                },
                "policy": watch.BUILD_HOST_STORAGE_POLICY,
                "required_available_bytes": watch.BUILD_WSL_HOST_MIN_AVAILABLE_BYTES,
                "observations": [],
                "minimum_available_bytes": None,
                "passed": True,
            },
            "role_provenance": {
                "schema_version": 1,
                "sources": {
                    target: {
                        **collection_source,
                        "image_digest": build_images[target]["id"],
                    }
                    for target in ("collection", "prepare", "reference")
                },
                "build_inputs": {
                    "collection": copy.deepcopy(build_inputs),
                    "prepare": copy.deepcopy(build_inputs),
                    "reference": None,
                },
            },
            "buildx": _buildx_provenance(),
            "cohort_allocation": cohort_allocation,
            "cohort_claim": cohort_claim,
            "cohort_claim_chain": cohort_chain,
            "cohort_authority_reproofs": cohort_reproofs,
        },
    )
    build = json.loads(build_execution_path.read_text(encoding="utf-8"))
    build_completion_path = build_execution_path.with_name("build-completion-v23.json")
    _write_build_completion(
        build_completion_path,
        build_path=build_execution_path,
        build=build,
    )
    build_sha256 = hashlib.sha256(build_execution_path.read_bytes()).hexdigest()
    build_completion_sha256 = hashlib.sha256(build_completion_path.read_bytes()).hexdigest()
    build_binding = {
        "path": "/lab/artifacts/buflo-study/build-execution-v23.json",
        "sha256": build_sha256,
        "payload_sha256": build["payload_sha256"],
    }
    build_identity = {
        "cohort_version": 23,
        "sha256": build_sha256,
        "completion_path": "/lab/artifacts/buflo-study/build-completion-v23.json",
        "completion_sha256": build_completion_sha256,
        "collection_image": collection_image,
        "started_at": build["started_at"],
        "finished_at": build["finished_at"],
    }
    pinned_cdp_path = paths.lab_root / "artifacts/buflo-study/pinned-cdp-execution-v23.json"
    contract_sha256 = hashlib.sha256(_canonical(watch._PINNED_CDP_CONTRACT)).hexdigest()
    pinned_payload = {
        "probe_schema_version": watch._PINNED_CDP_SCHEMA_VERSION,
        "artifact_type": watch.PINNED_CDP_TYPE,
        "study_id": watch.STUDY_ID,
        "cohort_version": 23,
        "recorded_at": "2026-08-28T02:00:00+00:00",
        "result": "pass",
        "build_execution": build_binding,
        "build_execution_identity": build_identity,
        "collection_source": collection_source,
        "prepare_source": prepare_source,
        "prepare_image_digest": image,
        "probe_contract": copy.deepcopy(watch._PINNED_CDP_CONTRACT),
        "probe_contract_sha256": contract_sha256,
        "observation": {
            "playwright_version": "1.57.0",
            "chromium_version": "143.0.7499.4",
            "chromium_executable": "/usr/local/bin/qcsd-chromium",
            "playwright_driver": copy.deepcopy(watch._EXPECTED_PLAYWRIGHT_DRIVER_BINDING),
            "isolation": {
                "real_uid": 1000,
                "effective_uid": 1000,
                "saved_uid": 1000,
                "filesystem_uid": 1000,
                "real_gid": 1000,
                "effective_gid": 1000,
                "saved_gid": 1000,
                "filesystem_gid": 1000,
                "expected_uid": 1000,
                "expected_gid": 1000,
                "supplementary_groups": [1000],
                "inheritable_capabilities": "0000000000000000",
                "permitted_capabilities": "0000000000000000",
                "effective_capabilities": "0000000000000000",
                "bounding_capabilities": "0000000000000000",
                "ambient_capabilities": "0000000000000000",
                "no_new_privileges": True,
                "observed_interfaces": ["lo"],
            },
            "topology": {
                "observed_target_types": ["iframe", "page", "shared_worker", "worker"],
                "event_count": 42,
                "event_method_counts": {
                    "Fetch.requestPaused": 2,
                    "Network.loadingFailed": 0,
                    "Network.loadingFinished": 11,
                    "Network.requestServedFromCache": 0,
                    "Network.requestWillBeSent": 11,
                    "Network.requestWillBeSentExtraInfo": 7,
                    "Network.responseReceived": 11,
                },
                "cross_site_iframe_request": True,
                "duplicate_request_occurrences": 2,
                "redirect_target_request": True,
                "worker_network_target_types": ["shared_worker", "worker"],
                "dedicated_worker_network_request": True,
                "shared_worker_network_request": True,
                "dedicated_worker_fetch_paused_on_page": True,
                "shared_worker_fetch_paused_on_shared_worker": True,
                "worker_response_consumption": copy.deepcopy(
                    watch._PINNED_CDP_WORKER_RESPONSE_CONSUMPTION
                ),
                "worker_webtransport_probe": copy.deepcopy(
                    watch._PINNED_CDP_WORKER_WEBTRANSPORT_PROBE
                ),
                "http_status_counts": copy.deepcopy(watch._PINNED_CDP_HTTP_STATUS_COUNTS),
                "server_request_counts": copy.deepcopy(watch._PINNED_CDP_SERVER_REQUEST_COUNTS),
                "bootstrap_prearm_summary": copy.deepcopy(
                    watch._PINNED_CDP_BOOTSTRAP_PREARM_SUMMARY
                ),
                "egress_prearm_summary": _egress_prearm_summary(),
                "srcdoc_pseudo_document_summary": _srcdoc_pseudo_document_summary(),
                "non_replayable_egress_summary": _non_replayable_egress_summary(),
                "browser_egress_command_line": _browser_egress_command_line(),
                "browser_context_service_worker_count": 0,
                "quiescent_target_activity": _target_activity(),
                "router_closed": True,
                "browser_guard_closed": True,
                "ledger_closed": True,
                "extra_info_closed": True,
                "browser_closed": True,
                "server_thread_stopped": True,
            },
        },
    }
    _write_receipt(pinned_cdp_path, watch.PINNED_CDP_TYPE, pinned_payload)
    pinned = json.loads(pinned_cdp_path.read_text(encoding="utf-8"))
    pinned_sha256 = hashlib.sha256(pinned_cdp_path.read_bytes()).hexdigest()
    pinned_binding = {
        "path": "/lab/artifacts/buflo-study/pinned-cdp-execution-v23.json",
        "sha256": pinned_sha256,
        "payload_sha256": pinned["payload_sha256"],
        "build_execution": build_binding,
        "build_execution_identity": copy.deepcopy(build_identity),
        "probe_contract_sha256": contract_sha256,
    }
    browser_egress_root = paths.lab_root / "artifacts/buflo-study/browser-egress-qualification-v23"
    browser_egress_root.mkdir()
    browser_egress_final_path = browser_egress_root / "final.json"
    expanded_vectors_sha256 = watch.BROWSER_EGRESS_EXPANDED_VECTORS_SHA256
    browser_egress_vector_ids = list(watch._BROWSER_EGRESS_VECTOR_IDS)
    browser_egress_final_payload = {
        "schema_version": 1,
        "qualification_id": watch.BROWSER_EGRESS_QUALIFICATION_ID,
        "study_id": watch.STUDY_ID,
        "cohort_version": 23,
        "qualification_started_at": "2026-08-28T01:15:00+00:00",
        "qualification_finished_at": "2026-08-28T01:30:00+00:00",
        "recorded_at": "2026-08-28T01:45:00+00:00",
        "foundation": {
            "path": "foundation.json",
            "sha256": "1" * 64,
            "payload_sha256": "2" * 64,
        },
        "checkpoint": {"path": "experiment.json", "sha256": "3" * 64},
        "expanded_vectors_sha256": expanded_vectors_sha256,
        "passed_results": [
            {
                "vector_ordinal": ordinal,
                "vector_id": browser_egress_vector_ids[ordinal - 1],
                "attempt_number": 1,
                "path": f"attempts/result-{ordinal:04d}.json",
                "sha256": hashlib.sha256(f"result-{ordinal}".encode()).hexdigest(),
                "payload_sha256": hashlib.sha256(f"payload-{ordinal}".encode()).hexdigest(),
            }
            for ordinal in range(1, watch.BROWSER_EGRESS_VECTOR_COUNT + 1)
        ],
        "attempt_count": watch.BROWSER_EGRESS_VECTOR_COUNT,
        "passed_vector_count": watch.BROWSER_EGRESS_VECTOR_COUNT,
        "operational_failure_count": 0,
        "semantic_failure_count": 0,
        "packet_level_egress_qualification": "passed",
        "consumer_contract": {"policy": "fixture-closed-egress-v1"},
        "verdict": "passed",
    }
    _write_receipt(
        browser_egress_final_path,
        watch.BROWSER_EGRESS_FINAL_TYPE,
        browser_egress_final_payload,
    )
    browser_egress_final = json.loads(browser_egress_final_path.read_text(encoding="utf-8"))
    browser_egress_binding = {
        "root": ("/lab/artifacts/buflo-study/browser-egress-qualification-v23"),
        "path": ("/lab/artifacts/buflo-study/browser-egress-qualification-v23/final.json"),
        "sha256": hashlib.sha256(browser_egress_final_path.read_bytes()).hexdigest(),
        "payload_sha256": browser_egress_final["payload_sha256"],
        "qualification_id": watch.BROWSER_EGRESS_QUALIFICATION_ID,
        "cohort_version": 23,
        "qualification_started_at": browser_egress_final_payload["qualification_started_at"],
        "qualification_finished_at": browser_egress_final_payload["qualification_finished_at"],
        "recorded_at": browser_egress_final_payload["recorded_at"],
        "prepare_image_id": image,
        "build_execution": {
            "path": "artifacts/buflo-study/build-execution-v23.json",
            "sha256": build_binding["sha256"],
            "size_bytes": build_execution_path.stat().st_size,
            "payload_sha256": build_binding["payload_sha256"],
            "cohort_version": 23,
            "completion_path": build_identity["completion_path"],
            "completion_sha256": build_identity["completion_sha256"],
            "collection_image_id": collection_image,
            "prepare_image_id": image,
            "reference_image_id": reference_image,
        },
        "expanded_vectors_sha256": expanded_vectors_sha256,
        "passed_vector_count": watch.BROWSER_EGRESS_VECTOR_COUNT,
        "passed": True,
    }
    foundation_path = paths.lab_root / "artifacts/class-study-foundation-v23.json"
    hard_gates = []
    for ordinal, gate in enumerate(watch._FOUNDATION_GATES, 1):
        evidence_sha256s = [str(ordinal) * 64]
        if gate == "pinned-cdp-integration-probe":
            evidence_sha256s = sorted(
                {
                    pinned_sha256,
                    pinned["payload_sha256"],
                    build_sha256,
                    build_completion_sha256,
                    build["payload_sha256"],
                    contract_sha256,
                }
            )
        elif gate == "browser-egress-packet-qualification-110-of-110":
            evidence_sha256s = sorted(
                {
                    browser_egress_binding["sha256"],
                    browser_egress_binding["payload_sha256"],
                    browser_egress_binding["expanded_vectors_sha256"],
                }
            )
        hard_gates.append(
            {
                "ordinal": ordinal,
                "gate": gate,
                "gate_identity_sha256": hashlib.sha256(
                    _canonical({"ordinal": ordinal, "gate": gate})
                ).hexdigest(),
                "result": "pass",
                "evidence_sha256s": evidence_sha256s,
            }
        )
    _write_receipt(
        foundation_path,
        watch.FOUNDATION_TYPE,
        {
            "attestation_schema_version": watch.FOUNDATION_SCHEMA_VERSION,
            "artifact_type": watch.FOUNDATION_TYPE,
            "study_id": watch.STUDY_ID,
            "cohort_version": 23,
            "recorded_at": "2026-08-28T03:00:00+00:00",
            "implementation_status": "foundation-ready-for-class-acquisition",
            "promotion_authority": False,
            "implementation_scope": "client_only_quic",
            "paper_equivalent": False,
            "no_waivers": True,
            "source": collection_source,
            "build_execution_identity": build_identity,
            "evidence": {
                "build_execution": {
                    "path": build_binding["path"],
                    "sha256": build_binding["sha256"],
                },
                "pinned_cdp_probe": pinned_binding,
                "browser_egress_qualification": browser_egress_binding,
                "reference": {},
                "code_gate": {},
                "controlled_qualification": {},
                "regression_results": [],
                "controlled_results": [],
            },
            "summary": {
                "reference_profiles": 8,
                "regression_samples": 18,
                "controlled_samples": 160,
                "pinned_cdp_probe": "pass",
                "browser_egress_packet_qualification": "pass",
                "browser_egress_vectors": watch.BROWSER_EGRESS_VECTOR_COUNT,
            },
            "hard_gates": hard_gates,
            "all_foundation_gates_passed": True,
        },
    )
    provenance_payload = {
        "study_id": watch.STUDY_ID,
        "acquisition_schema_version": watch.ACQUISITION_SCHEMA_VERSION,
        "candidate_catalogue_sha256": catalogue_sha256,
        "candidate_catalogue_payload_sha256": catalogue["payload_sha256"],
        "candidate_count": watch.CANDIDATE_COUNT,
        "acquisition_authority": {
            "path": "/lab/artifacts/class-study-foundation-v23.json",
            "sha256": hashlib.sha256(foundation_path.read_bytes()).hexdigest(),
        },
        "acquisition_selection_policy": watch.ACQUISITION_SELECTION_POLICY,
        "started_at": "2026-08-29T00:00:00Z",
        "image_digest": image,
        "source": prepare_source,
        "browser_tool": copy.deepcopy(watch._EXPECTED_BROWSER_TOOL_IDENTITY),
        "navigation_implementation": watch._NAVIGATION_IMPLEMENTATION,
        "cdp_target_instrumentation_policy": watch._CDP_TARGET_INSTRUMENTATION_POLICY,
        "non_replayable_egress_contract": copy.deepcopy(watch._NON_REPLAYABLE_EGRESS_CONTRACT),
        "passive_render_contract": copy.deepcopy(watch._PASSIVE_RENDER_CONTRACT),
        "passive_render_contract_sha256": watch._PASSIVE_RENDER_CONTRACT_SHA256,
        "browser_navigation_timeout_ms": watch.BROWSER_NAVIGATION_TIMEOUT_MS,
        "passive_render_hard_cap_after_load_ms": watch.PASSIVE_RENDER_HARD_CAP_MS,
        "acquisition_action_timing_contract": copy.deepcopy(
            watch._ACQUISITION_ACTION_TIMING_CONTRACT
        ),
        "baseline_scheduling_contract": copy.deepcopy(watch._TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT),
        "registrable_domain_policy": watch._REGISTRABLE_DOMAIN_POLICY,
        "domain_safety_policy": copy.deepcopy(watch._DOMAIN_SAFETY_POLICY),
        "domain_safety_policy_sha256": watch._DOMAIN_SAFETY_POLICY_SHA256,
        "origin_policy": copy.deepcopy(watch._ORIGIN_POLICY),
        "eligibility_inputs": copy.deepcopy(watch._ELIGIBILITY_INPUTS),
        "prohibited_inputs": copy.deepcopy(watch._PROHIBITED_INPUTS),
    }
    _write_receipt(paths.provenance, watch.PROVENANCE_TYPE, provenance_payload)
    provenance_sha256 = hashlib.sha256(paths.provenance.read_bytes()).hexdigest()
    checkpoint_payload = {
        "checkpoint_schema_version": watch.CHECKPOINT_SCHEMA_VERSION,
        "provenance_sha256": provenance_sha256,
        "candidate_catalogue_sha256": catalogue_sha256,
        "baseline_batches": [],
        "active_batch": None,
        "candidates": {
            candidate_id: {"state": "pending", "pages": [], "terminal": None}
            for candidate_id in candidate_ids
        },
    }
    _write_receipt(paths.checkpoint, watch.CHECKPOINT_TYPE, checkpoint_payload)
    watch._ensure_state_namespace(paths)
    return Fixture(
        paths,
        image,
        candidate_ids,
        foundation_path,
        pinned_cdp_path,
        build_execution_path,
        build_completion_path,
        browser_egress_root,
        browser_egress_final_path,
    )


@pytest.fixture(autouse=True)
def _accept_fixture_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(watch, "_validate_host_source", lambda _paths, _binding: None)


def _selection_fixture(
    terminal: int = 0, *, terminal_ids: list[str] | None = None, first24: bool = False
) -> dict[str, Any]:
    candidates = [f"tranco-{rank:07d}" for rank in range(1, 601)]
    terminals = set(candidates[:terminal] if terminal_ids is None else terminal_ids)
    strata = []
    for index, name in enumerate(("1-1000", "1001-10000", "10001-100000", "100001-500000", "500001-1000000")):
        members = candidates[index * 120:(index + 1) * 120]
        potential = members[:24] if first24 else [*members[:23], members[-1]]
        eligible = [item for item in potential if item in terminals]
        complete = len(eligible) == 24
        cutoff = members.index(eligible[-1]) + 1 if complete else len(members)
        prefix = members[:cutoff]
        needed = [item for item in prefix if item not in terminals]
        strata.append({
            "id": name, "complete": complete and not needed, "quota_unmet": not complete and not needed,
            "cutoff_id": eligible[-1] if complete else None,
            "prefix_ids": prefix, "eligible_ids": eligible, "needed_ids": needed,
            "admission_ids": [item for item in members if item not in terminals or item in eligible][:24],
            "unassessed_ids": [item for item in members[cutoff:] if item not in terminals],
        })
    complete = all(row["complete"] for row in strata)
    return {
        "schema_version": 1, "policy": watch.ACQUISITION_SELECTION_POLICY,
        "tranco_list_sha256": "a" * 64, "complete": complete,
        "quota_unmet_strata": [row["id"] for row in strata if row["quota_unmet"]],
        "candidate_ids": candidates, "terminal_ids": [item for item in candidates if item in terminals],
        "prefix_ids": [item for row in strata for item in row["prefix_ids"]],
        "needed_ids": [item for row in strata for item in row["needed_ids"]],
        "admission_ids": [item for row in strata for item in row["admission_ids"]],
        "remaining_ids": [item for item in candidates if item not in terminals],
        "unassessed_ids": [item for row in strata for item in row["unassessed_ids"]],
        "pilot_ids": [item for row in strata for item in row["eligible_ids"]] if complete else [],
        "strata": strata,
    }


def _materialise_selection(
    acquisition: Fixture, selection: dict[str, Any], *, blocked_ids: tuple[str, ...] = (),
) -> None:
    """Give fake-runner outcomes real receipt/state bindings, not live-page proof."""

    from qcsd_lab.acquisition_timing import greedy_baseline_schedule

    checkpoint = _checkpoint_payload(acquisition)
    eligible = [item for row in selection["strata"] for item in row["eligible_ids"]]
    terminal_ids = set(selection["terminal_ids"]) | set(blocked_ids)
    batches = []
    by_candidate = {}
    starts = greedy_baseline_schedule(datetime(2026, 8, 29, tzinfo=UTC), (len(eligible) + 1) // 2)
    for index, start in enumerate(starts):
        members = eligible[index * 2:(index + 1) * 2]
        batch = _batch("baseline", {
            "baseline_started_at": start.isoformat().replace("+00:00", "Z"), "candidate_ids": members,
            "live_page_count": len(members),
        })
        batches.append(batch)
        by_candidate.update(dict.fromkeys(members, batch))
    for candidate_id in selection["candidate_ids"]:
        if candidate_id not in terminal_ids:
            continue
        batch = by_candidate.get(candidate_id)
        state = {**checkpoint["candidates"][candidate_id], "terminal": None}
        if batch is None:
            kind = "pre-probe-rejection"
            state.update(state="pending", pages=[], navigation_attempts=[{
                "outcome": "recoverable-error" if candidate_id in blocked_ids else "terminal-policy-rejection",
            }])
            state.pop("baseline_started_at", None)
            terminalised = "2026-08-29T00:00:00Z"
        else:
            kind = "eligible"
            state.update(state="probing", pages=[{}], baseline_started_at=batch["baseline_started_at"])
            terminalised = (datetime.fromisoformat(batch["baseline_started_at"]) + timedelta(hours=73)).isoformat().replace("+00:00", "Z")
        terminal = {
            "terminal_schema_version": watch.TERMINAL_SCHEMA_VERSION,
            "checkpoint_schema_version": watch.CHECKPOINT_SCHEMA_VERSION,
            "candidate_id": candidate_id, "kind": kind, "reason": "fixture outcome",
            "terminalised_at": terminalised,
            "checkpoint_state_sha256": hashlib.sha256(_canonical(state)).hexdigest(),
            "provenance_sha256": checkpoint["provenance_sha256"], "baseline_batch": batch,
            "stability_receipt": None, "admitted_workload": None,
        }
        relative = f"terminals/{candidate_id}.json"
        path = acquisition.paths.acquisition_root / relative
        path.parent.mkdir(exist_ok=True)
        _write_receipt(path, "qcsd-class-study-acquisition-terminal", terminal)
        state.update(state="terminal", terminal={
            "path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
        checkpoint["candidates"][candidate_id] = state
    checkpoint["baseline_batches"] = batches
    checkpoint["active_batch"] = None
    _replace_checkpoint(acquisition, checkpoint)


def _acquisition_only_authority(acquisition: Fixture) -> Path:
    root = acquisition.paths.lab_root
    foundation = json.loads(acquisition.foundation_path.read_bytes())["payload"]
    provenance = json.loads(acquisition.paths.provenance.read_bytes())["payload"]
    study_path = root / "config/class-study/v1/study.json"
    study_path.write_bytes(b"{}\n")
    inputs = {}
    for relative in (*watch._ACQUISITION_CORRECTNESS_TESTS, "pyproject.toml", "uv.lock"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(f"fixture {relative}\n".encode())
        inputs[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    study = {"path": "/lab/config/class-study/v1/study.json", "sha256": hashlib.sha256(study_path.read_bytes()).hexdigest()}
    correctness = {
        "schema_version": 1, "gate": "acquisition-focused-correctness",
        "argv": ["/opt/qcsd-venv/bin/python", "-m", "pytest", "-p", "no:cacheprovider", *watch._ACQUISITION_CORRECTNESS_TESTS],
        "cwd": "/lab", "input_sha256": inputs, "source": foundation["source"],
        "build_execution_identity": foundation["build_execution_identity"], "study_contract": study,
        "started_at": "2026-08-28T02:15:00+00:00", "finished_at": "2026-08-28T02:30:00+00:00",
        "exit_code": 0, "stdout": "1 passed\n", "stdout_bytes": 9,
        "stdout_sha256": hashlib.sha256(b"1 passed\n").hexdigest(),
    }
    evidence = {key: foundation["evidence"][key] for key in ("build_execution", "pinned_cdp_probe", "browser_egress_qualification")}
    identity = foundation["build_execution_identity"]
    browser = evidence["browser_egress_qualification"]
    gate_evidence = {
        "current-clean-source-and-no-cache-build": [identity["sha256"], identity["completion_sha256"]],
        "acquisition-focused-correctness": [hashlib.sha256(_canonical(correctness)).hexdigest()],
        "pinned-cdp-integration-probe": [evidence["pinned_cdp_probe"]["sha256"]],
        "browser-egress-packet-qualification-110-of-110": [browser["sha256"], browser["payload_sha256"], browser["expanded_vectors_sha256"]],
    }
    payload = {
        **{key: foundation[key] for key in ("study_id", "cohort_version", "recorded_at", "promotion_authority", "implementation_scope", "paper_equivalent", "no_waivers", "source", "build_execution_identity")},
        "attestation_schema_version": 1, "artifact_type": watch.ACQUISITION_AUTHORITY_TYPE,
        "implementation_status": "acquisition-ready", "authority_scope": "public-page-acquisition-only",
        "prepare_source": provenance["source"], "study_contract": study, "evidence": evidence,
        "acquisition_correctness": correctness, "all_acquisition_gates_passed": True,
        "hard_gates": [
            {"ordinal": ordinal, "gate": gate, "gate_identity_sha256": hashlib.sha256(_canonical({"ordinal": ordinal, "gate": gate})).hexdigest(),
             "result": "pass", "evidence_sha256s": sorted(set(hashes))}
            for ordinal, (gate, hashes) in enumerate(gate_evidence.items(), 1)
        ],
    }
    path = root / "artifacts/class-study-acquisition-authority-v23.json"
    _write_receipt(path, watch.ACQUISITION_AUTHORITY_TYPE, payload)
    provenance["acquisition_authority"] = {"path": "/lab/artifacts/class-study-acquisition-authority-v23.json", "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    _write_receipt(acquisition.paths.provenance, watch.PROVENANCE_TYPE, provenance)
    checkpoint = _checkpoint_payload(acquisition)
    checkpoint["provenance_sha256"] = hashlib.sha256(acquisition.paths.provenance.read_bytes()).hexdigest()
    _replace_checkpoint(acquisition, checkpoint)
    return path


def test_acquisition_only_authority_verifies_without_execution_or_full_foundation(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _acquisition_only_authority(acquisition)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("verification must not execute tests or enter full foundation")
    monkeypatch.setattr(watch.subprocess, "run", forbidden)
    monkeypatch.setattr(watch, "_validate_foundation", forbidden)
    binding = watch._validate_immutable_binding(acquisition.paths)
    assert binding.acquisition_authority_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert binding.foundation_sha256 is None


@pytest.mark.parametrize("mutation", ("argv", "cwd", "exit", "stdout", "length", "input", "study", "gates", "scope", "prepare_source", "chronology"))
def test_acquisition_only_authority_rejects_resealed_gate_drift(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    path = _acquisition_only_authority(acquisition)
    payload = json.loads(path.read_bytes())["payload"]
    correctness = payload["acquisition_correctness"]
    if mutation == "argv":
        correctness["argv"][-1] = "tests/test_buflo_study.py"
    elif mutation == "cwd":
        correctness["cwd"] = "/tmp"
    elif mutation == "exit":
        correctness["exit_code"] = False
    elif mutation == "stdout":
        correctness["stdout"] = "0 passed\n"
    elif mutation == "length":
        correctness["stdout_bytes"] += 1
    elif mutation == "input":
        correctness["input_sha256"]["uv.lock"] = "0" * 64
    elif mutation == "study":
        payload["study_contract"]["sha256"] = "0" * 64
    elif mutation == "gates":
        payload["hard_gates"].reverse()
    elif mutation == "scope":
        payload["authority_scope"] = "formal-capture"
    elif mutation == "prepare_source":
        payload["prepare_source"]["image_digest"] = "sha256:" + "0" * 64
    elif mutation == "chronology":
        correctness["started_at"] = "2026-08-28T00:00:00+00:00"
    _write_receipt(path, watch.ACQUISITION_AUTHORITY_TYPE, payload)
    provenance = json.loads(acquisition.paths.provenance.read_bytes())["payload"]
    provenance["acquisition_authority"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    _write_receipt(acquisition.paths.provenance, watch.PROVENANCE_TYPE, provenance)
    monkeypatch.setattr(watch.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("verification executed a command"))
    with pytest.raises(watch.WatchError):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_acquisition_contracts_match_runtime() -> None:
    from qcsd_lab.acquisition_timing import TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT
    from qcsd_lab.class_attestation import ACQUISITION_CORRECTNESS_TESTS
    assert watch._TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT == TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT
    assert watch._ACQUISITION_CORRECTNESS_TESTS == ACQUISITION_CORRECTNESS_TESTS


def test_watcher_accepts_complete_120_member_terminal_prefix_with_480_unassessed() -> None:
    terminal_ids = [f"tranco-{index * 120 + rank:07d}" for index in range(5) for rank in range(1, 25)]
    details = _details(terminal=120)
    details.update(selection=_selection_fixture(terminal_ids=terminal_ids, first24=True),
                   pending_count=0, work_due_now=False, complete=True)
    watch._validate_status_details(details, action="acquisition-status")
    assert len(details["selection"]["pilot_ids"]) == 120
    assert len(details["selection"]["unassessed_ids"]) == 480
    assert details["selection"]["remaining_ids"] == details["selection"]["unassessed_ids"]


def _complete_prefix_details() -> dict[str, Any]:
    terminal_ids = [f"tranco-{index * 120 + rank:07d}" for index in range(5) for rank in range(1, 25)]
    details = _details(terminal=120)
    details.update(selection=_selection_fixture(terminal_ids=terminal_ids, first24=True),
                   pending_count=0, work_due_now=False, complete=True)
    return details


def test_watcher_rejects_complete_prefix_invented_from_all_pending_checkpoint(
    acquisition: Fixture,
) -> None:
    details = _complete_prefix_details()
    before = acquisition.paths.checkpoint.read_bytes()
    runner = FakeRunner([_completed(_result("acquisition-status", details))])
    with pytest.raises(watch.WatchError, match="authenticated checkpoint terminals"):
        watch.watch_acquisition(paths=acquisition.paths, runner=runner)
    assert acquisition.paths.checkpoint.read_bytes() == before
    assert not (acquisition.paths.acquisition_root / "completion.json").exists()


@pytest.mark.parametrize("mutation", ("hidden-blocker", "false-eligible", "hidden-started"))
def test_watcher_joins_status_outcomes_to_checkpoint(
    acquisition: Fixture, mutation: str,
) -> None:
    details = _complete_prefix_details()
    actual = copy.deepcopy(details["selection"])
    blocked = ()
    if mutation == "hidden-blocker":
        blocked = (acquisition.candidate_ids[24],)
    elif mutation == "false-eligible":
        # Keep the reported scientific terminal inventory, but its first
        # member's authenticated outcome is rejection rather than eligible.
        actual["strata"][0]["eligible_ids"].pop(0)
    _materialise_selection(acquisition, actual, blocked_ids=blocked)
    if mutation == "hidden-started":
        checkpoint = _checkpoint_payload(acquisition)
        checkpoint["candidates"][acquisition.candidate_ids[24]]["navigation_attempts"] = [
            {"outcome": "recoverable-error"}
        ]
        _replace_checkpoint(acquisition, checkpoint)
    runner = FakeRunner([_completed(_result("acquisition-status", details))])
    with pytest.raises(watch.WatchError, match="authenticated|hides started"):
        watch.watch_acquisition(paths=acquisition.paths, runner=runner)


@pytest.mark.parametrize("mutation", (
    "raw-hash", "state-hash", "provenance", "candidate", "batch", "kind", "schema",
    "missing-binding", "pending-with-binding", "path", "prebaseline",
))
def test_watcher_rejects_terminal_receipt_or_state_drift(
    acquisition: Fixture, mutation: str,
) -> None:
    details = _complete_prefix_details()
    _materialise_selection(acquisition, details["selection"])
    checkpoint = _checkpoint_payload(acquisition)
    state = checkpoint["candidates"][acquisition.candidate_ids[0]]
    path = acquisition.paths.acquisition_root / state["terminal"]["path"]
    terminal = json.loads(path.read_bytes())["payload"]
    if mutation == "raw-hash":
        state["terminal"]["sha256"] = "0" * 64
    elif mutation == "state-hash":
        state["pages"][0]["rejection"] = {"kind": "probe-retry-exhausted"}
    elif mutation == "missing-binding":
        state["terminal"] = None
    elif mutation == "pending-with-binding":
        state["state"] = "pending"
    elif mutation == "path":
        state["terminal"]["path"] = "terminals/another-candidate.json"
    else:
        if mutation == "provenance":
            terminal["provenance_sha256"] = "0" * 64
        elif mutation == "candidate":
            terminal["candidate_id"] = acquisition.candidate_ids[1]
        elif mutation == "batch":
            terminal["baseline_batch"] = None
        elif mutation == "kind":
            terminal["kind"] = "invented"
        elif mutation == "schema":
            terminal["terminal_schema_version"] = True
        elif mutation == "prebaseline":
            terminal["terminalised_at"] = "2026-08-28T00:00:00Z"
        _write_receipt(path, "qcsd-class-study-acquisition-terminal", terminal)
        state["terminal"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    _replace_checkpoint(acquisition, checkpoint)
    runner = FakeRunner([_completed(_result("acquisition-status", details))])
    with pytest.raises(watch.WatchError, match="terminal"):
        watch.watch_acquisition(paths=acquisition.paths, runner=runner)


@pytest.mark.parametrize(("kind", "state", "expected"), (
    ("eligible", {"pages": [{}]}, True),
    ("stable-page-unavailable", {"pages": [{}]}, False),
    ("probe-window-missed", {"pages": [{}]}, None),
    ("eligible", {"pages": [{"rejection": {"kind": "probe-retry-exhausted"}}]}, None),
    ("stable-page-unavailable", {"pages": [{"rejection": {"kind": "probe-retry-exhausted"}}]}, None),
    ("pre-probe-rejection", {"pages": [], "navigation_attempts": [{"outcome": "terminal-policy-rejection"}]}, False),
    ("pre-probe-rejection", {"pages": [], "navigation_attempts": [{"outcome": "recoverable-error"}]}, None),
    ("pre-probe-rejection", {"pages": [], "navigation_attempts": []}, None),
))
def test_watcher_terminal_outcome_projection_matches_runtime(kind, state, expected) -> None:
    from qcsd_lab.class_acquisition import _scientific_terminal_eligibility

    terminal = {"kind": kind}
    assert watch._scientific_terminal_eligibility(terminal, state) is expected
    assert _scientific_terminal_eligibility(terminal, state) is expected


def test_watcher_accepts_runtime_produced_selection_from_bound_terminal_outcomes(
    acquisition: Fixture,
) -> None:
    from qcsd_lab.class_acquisition import (
        _checkpoint_terminal_payloads,
        _derive_checkpoint_selection,
    )
    from qcsd_lab.class_study import (
        TRANCO_RANK_STRATA,
        ClassCandidate,
        deterministic_candidate_order,
    )

    candidates = deterministic_candidate_order([
        ClassCandidate(
            acquisition.candidate_ids[index * 120 + offset],
            f"site-{index}-{offset}.example", stratum.minimum_rank + offset, False,
        )
        for index, stratum in enumerate(TRANCO_RANK_STRATA) for offset in range(120)
    ], tranco_list_sha256="a" * 64)
    catalogue = json.loads(acquisition.paths.candidate_catalogue.read_bytes())
    catalogue["payload"]["candidates"] = [candidate.as_dict() for candidate in candidates]
    _write_receipt(acquisition.paths.candidate_catalogue, watch.CATALOGUE_TYPE, catalogue["payload"])
    catalogue = json.loads(acquisition.paths.candidate_catalogue.read_bytes())
    catalogue_sha256 = hashlib.sha256(acquisition.paths.candidate_catalogue.read_bytes()).hexdigest()
    provenance = json.loads(acquisition.paths.provenance.read_bytes())["payload"]
    provenance.update(candidate_catalogue_sha256=catalogue_sha256,
                      candidate_catalogue_payload_sha256=catalogue["payload_sha256"])
    _write_receipt(acquisition.paths.provenance, watch.PROVENANCE_TYPE, provenance)
    checkpoint = _checkpoint_payload(acquisition)
    checkpoint.update(candidate_catalogue_sha256=catalogue_sha256,
                      provenance_sha256=hashlib.sha256(acquisition.paths.provenance.read_bytes()).hexdigest())
    _replace_checkpoint(acquisition, checkpoint)
    acquisition.candidate_ids = [candidate.candidate_id for candidate in candidates]
    initial, _ = _derive_checkpoint_selection(candidates, catalogue, checkpoint["candidates"], {})
    # This exercises real runtime projection, not live three-window page proof.
    terminal_ids = initial["admission_ids"]
    prospective_terminals = {candidate_id: {"kind": "eligible"} for candidate_id in terminal_ids}
    selection, _ = _derive_checkpoint_selection(
        candidates, catalogue, checkpoint["candidates"], prospective_terminals,
    )
    _materialise_selection(acquisition, selection)
    checkpoint = _checkpoint_payload(acquisition)
    terminals = _checkpoint_terminal_payloads(acquisition.paths.acquisition_root, checkpoint["candidates"])
    selection, blocked = _derive_checkpoint_selection(candidates, catalogue, checkpoint["candidates"], terminals)
    details = _details(terminal=len(terminals))
    details.update(selection=selection, selection_blocked_candidate_ids=blocked,
                   pending_count=0, work_due_now=False, complete=True)
    before = acquisition.paths.checkpoint.read_bytes()
    result = watch.watch_acquisition(
        paths=acquisition.paths,
        runner=FakeRunner([_completed(_result("acquisition-status", details))]),
    )
    assert result["details"]["complete"] is True
    assert len(selection["unassessed_ids"]) == 480
    assert acquisition.paths.checkpoint.read_bytes() == before
    assert not (acquisition.paths.acquisition_root / "completion.json").exists()


def test_watcher_infrastructure_terminal_blocks_completion_without_site_ineligibility() -> None:
    terminal_ids = [
        f"tranco-{index * 120 + rank:07d}" for index in range(5) for rank in range(1, 25)
    ]
    details = _details(terminal=121)
    details.update(
        selection=_selection_fixture(terminal_ids=terminal_ids, first24=True),
        selection_blocked_candidate_ids=["tranco-0000025"],
        pending_count=0,
        work_due_now=False,
        complete=False,
    )
    watch._validate_status_details(details, action="acquisition-status")
    assert "tranco-0000025" not in details["selection"]["terminal_ids"]
    assert "tranco-0000025" in details["selection"]["remaining_ids"]
    details["complete"] = True
    with pytest.raises(watch.WatchError, match="completion flag"):
        watch._validate_status_details(details, action="acquisition-status")


@pytest.mark.parametrize("mutation", ("unknown-as-rejected", "pilot-order", "needed", "admission", "quota", "blocked"))
def test_watcher_rejects_selection_inventory_or_completion_drift(mutation: str) -> None:
    details = _details(terminal=600)
    selection = details["selection"]
    if mutation == "unknown-as-rejected":
        selection["terminal_ids"].pop(0)
    elif mutation == "pilot-order":
        selection["pilot_ids"].reverse()
    elif mutation == "needed":
        selection["needed_ids"] = [selection["candidate_ids"][0]]
    elif mutation == "admission":
        selection["admission_ids"].pop()
    elif mutation == "quota":
        selection["strata"][0]["eligible_ids"].pop()
    elif mutation == "blocked":
        details["selection_blocked_candidate_ids"] = [selection["candidate_ids"][0]]
    with pytest.raises(watch.WatchError):
        watch._validate_status_details(details, action="acquisition-status")


@pytest.mark.parametrize("mutation", (None, "late", "missed", "retry", "hash"))
def test_watcher_replays_causal_scientific_terminal_release(
    acquisition: Fixture, mutation: str | None,
) -> None:
    payload = _checkpoint_payload(acquisition)
    first, second = acquisition.candidate_ids[:2]
    starts = ("2026-08-29T01:00:00Z", "2026-08-31T01:00:00Z")
    batches = []
    for candidate_id, started in zip((first, second), starts, strict=True):
        payload["candidates"][candidate_id] = {
            "state": "probing", "pages": [{"page": {"ordinal": 0}}],
            "terminal": None, "baseline_started_at": started,
        }
        batches.append(_batch("baseline", {
            "baseline_started_at": started, "candidate_ids": [candidate_id], "live_page_count": 1,
        }))
    payload["baseline_batches"] = batches
    state = payload["candidates"][first]
    if mutation == "retry":
        state["pages"][0]["rejection"] = {"kind": "probe-retry-exhausted"}
    terminal = {
        "terminal_schema_version": watch.TERMINAL_SCHEMA_VERSION,
        "checkpoint_schema_version": watch.CHECKPOINT_SCHEMA_VERSION,
        "candidate_id": first, "kind": "probe-window-missed" if mutation == "missed" else "stable-page-unavailable",
        "terminalised_at": "2026-08-31T00:21:00Z" if mutation == "late" else "2026-08-29T01:01:00Z",
        "provenance_sha256": payload["provenance_sha256"], "baseline_batch": batches[0],
        "checkpoint_state_sha256": hashlib.sha256(_canonical(state)).hexdigest(),
        "reason": "fixture scientific rejection", "stability_receipt": None,
        "admitted_workload": None,
    }
    relative = f"terminals/{first}.json"
    path = acquisition.paths.acquisition_root / relative
    path.parent.mkdir(exist_ok=True)
    _write_receipt(path, "qcsd-class-study-acquisition-terminal", terminal)
    state["state"] = "terminal"
    state["terminal"] = {"path": relative, "sha256": "0" * 64 if mutation == "hash" else hashlib.sha256(path.read_bytes()).hexdigest()}
    _replace_checkpoint(acquisition, payload)
    binding = watch._validate_immutable_binding(acquisition.paths)
    if mutation is None:
        watch._validate_checkpoint(acquisition.paths, binding)
    else:
        with pytest.raises(watch.WatchError):
            watch._validate_checkpoint(acquisition.paths, binding)


def _details(
    *,
    terminal: int = 0,
    probing: int = 0,
    due: int = 0,
    finalisable: int = 0,
    missed: int = 0,
    recovery: int = 0,
    blocked: bool = False,
    next_due: str | None = None,
    active_batch: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pending = watch.CANDIDATE_COUNT - terminal - probing
    complete = (
        terminal == watch.CANDIDATE_COUNT
        and finalisable == 0
        and recovery == 0
        and active_batch is None
    )
    work_due = bool(recovery or due or finalisable or missed or (pending and not blocked))
    return {
        "acquisition_schema_version": watch.ACQUISITION_SCHEMA_VERSION,
        "checkpoint_schema_version": watch.CHECKPOINT_SCHEMA_VERSION,
        "maximum_candidates_per_action": watch.MAX_CANDIDATES,
        "global_live_page_cap": watch.GLOBAL_LIVE_PAGE_CAP,
        "active_batch": copy.deepcopy(active_batch),
        "candidate_count": watch.CANDIDATE_COUNT,
        "terminal_count": terminal,
        "pending_count": pending,
        "probing_count": probing,
        "due_now_count": due,
        "finalisable_count": finalisable,
        "missed_window_count": missed,
        "recovery_required_count": recovery,
        "pending_start_blocked": blocked,
        "work_due_now": work_due,
        "complete": complete,
        "next_due": next_due,
        "selection": _selection_fixture(terminal),
        "selection_blocked_candidate_ids": [],
    }


def _result(
    action: str,
    details: dict[str, Any],
    *,
    runner_root: str | None = None,
    foundation_sha256: str = "0" * 64,
) -> dict:
    payload = copy.deepcopy(details)
    payload.update(
        {
            "valid": True,
            "runner_root": runner_root or watch.CONTAINER_ACQUISITION_ROOT,
        }
    )
    if action == "acquisition-status":
        payload["gate"] = {
            "required_windows": copy.deepcopy(watch._EXPECTED_WINDOWS),
            "labels": ["t+30s", "t+24h", "t+72h"],
            "all_three_required_per_page_receipt": True,
            "acquisition_owner": "resumable-qcsd-class-study-production-runner",
            "batching": {
                "maximum_candidates_per_action": watch.MAX_CANDIDATES,
                "global_live_page_cap": watch.GLOBAL_LIVE_PAGE_CAP,
            },
            "runner_wait_policy": copy.deepcopy(watch._RUN_WAIT_POLICY),
        }
        payload["authoritative"] = False
        payload["gate_verification"] = {
            "acquisition_authority_path": "/lab/artifacts/class-study-foundation-v23.json",
            "acquisition_authority_sha256": foundation_sha256,
            "informational_only": True,
        }
        status = "complete"
        blockers: list[str] = []
    else:
        payload["bounded_candidates"] = watch.MAX_CANDIDATES
        payload["runner_wait_policy"] = copy.deepcopy(watch._RUN_WAIT_POLICY)
        status = "ready" if payload["complete"] else "pending"
        blockers = [] if payload["complete"] else ["rerun from coordinator state"]
    return {
        "schema_version": 1,
        "artifact_type": watch.ACTION_RESULT_TYPE,
        "action": action,
        "status": status,
        "details": payload,
        "blockers": blockers,
    }


def _completed(value: Any, *, returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    stdout = value if isinstance(value, str) else json.dumps(value)
    return subprocess.CompletedProcess((), returncode, stdout, stderr)


def _completed_canonical(
    value: Any, *, returncode: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess((), returncode, _canonical(value).decode("utf-8"), stderr)


def _browser_egress_result(paths: watch.WatchPaths) -> dict[str, Any]:
    foundation = json.loads(
        (paths.lab_root / "artifacts/class-study-foundation-v23.json").read_text(encoding="utf-8")
    )
    binding = foundation["payload"]["evidence"]["browser_egress_qualification"]
    return {key: copy.deepcopy(value) for key, value in binding.items() if key != "root"}


def _admission() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": watch.DOCKER_ADMISSION_TYPE,
        "docker_context": "default",
        "docker_host": "unix:///var/run/docker.sock",
        "docker_server_id": "test-daemon-01",
        "host_boot_id": watch._host_boot_id(),
    }


_DEFAULT_BROWSER_EGRESS_RESPONSE = object()


class FakeRunner:
    def __init__(
        self,
        responses: list[Any],
        *,
        browser_egress_response: Any = _DEFAULT_BROWSER_EGRESS_RESPONSE,
    ) -> None:
        self.responses = list(responses)
        self.browser_egress_response = browser_egress_response
        self.calls: list[tuple[tuple[str, ...], Path, dict[str, str]]] = []

    def __call__(
        self,
        command,
        *,
        cwd,
        env,
        authority_fd,
        state_root,
        source_binding_sha256,
    ):
        assert watch.LOCK_ENV not in env
        assert state_root.name == self._paths(command).namespace_sha256
        assert re.fullmatch(r"[0-9a-f]{64}", source_binding_sha256)
        self.calls.append((tuple(command), cwd, dict(env)))
        if tuple(command) == watch._admission_command(self._paths(command)):
            return _completed(_admission())
        if watch._is_canonical_browser_egress_verify_command(command):
            response = self.browser_egress_response
            if response is _DEFAULT_BROWSER_EGRESS_RESPONSE:
                return _completed_canonical(_browser_egress_result(self._paths(command)))
            if callable(response):
                response = response(tuple(command), cwd, dict(env))
            return response
        if not self.responses:
            raise AssertionError("unexpected coordinator call")
        response = self.responses.pop(0)
        if callable(response):
            response = response(tuple(command), cwd, dict(env))
        if (
            isinstance(response, subprocess.CompletedProcess)
            and command[2] == "acquisition-status"
            and response.returncode == 0
        ):
            try:
                value = json.loads(response.stdout)
            except (TypeError, json.JSONDecodeError):
                pass
            else:
                verification = value.get("details", {}).get("gate_verification")
                if (
                    isinstance(verification, dict)
                    and verification.get("acquisition_authority_sha256") == "0" * 64
                ):
                    binding = watch._validate_immutable_binding(self._paths(command))
                    verification["acquisition_authority_sha256"] = binding.acquisition_authority_sha256
                    response = _completed(value)
        return response

    @staticmethod
    def _paths(command: tuple[str, ...] | list[str]) -> watch.WatchPaths:
        launcher = Path(command[0])
        return watch.WatchPaths.from_lab_root(launcher.parent)


class FakeClock:
    def __init__(self, value: datetime) -> None:
        self.value = value
        self.sleeps: list[float] = []

    def __call__(self) -> datetime:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += timedelta(seconds=seconds)


class FakeMonotonic:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


def test_due_work_uses_exact_command_environment_and_paths(acquisition: Fixture) -> None:
    assert watch.ACQUISITION_SCHEMA_VERSION == 7
    assert watch.CHECKPOINT_SCHEMA_VERSION == 3
    assert watch.TERMINAL_SCHEMA_VERSION == 4
    assert watch.COMPLETION_SCHEMA_VERSION == 4
    assert watch.SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION == 2
    assert watch.SCHEMA_SIX_TERMINAL_SCHEMA_VERSION == 3
    assert watch.SCHEMA_SIX_COMPLETION_SCHEMA_VERSION == 3
    assert watch.ACQUISITION_TIMEOUT_MS == 60_000
    assert watch.PENDING_BASELINE_GUARD_MS == 2_400_000
    assert watch.MAX_CANDIDATES == 2
    assert watch.GLOBAL_LIVE_PAGE_CAP == 5
    assert watch.ACQUISITION_ACTION_TIMEOUT_SECONDS == 1_800
    assert watch.ACQUISITION_ACTION_CLEANUP_SECONDS == 120
    assert watch.RUN_RUNTIME_SECONDS == 1_920
    expected_run_command = (
        str(acquisition.paths.launcher),
        "class-study",
        "acquisition-run",
        "--candidate-catalogue",
        str(acquisition.paths.candidate_catalogue),
        "--acquisition-root",
        str(acquisition.paths.acquisition_root),
        "--stability-root",
        str(acquisition.paths.stability_root),
        "--workload-root",
        str(acquisition.paths.workload_root),
        "--acquisition-max-candidates",
        str(watch.MAX_CANDIDATES),
        "--acquisition-timeout-ms",
        str(watch.ACQUISITION_TIMEOUT_MS),
    )
    assert watch._run_command(acquisition.paths) == expected_run_command
    assert watch._run_command(acquisition.paths).count("acquisition-run") == 1
    assert watch._admission_command(acquisition.paths) == (
        str(acquisition.paths.launcher),
        "class-study",
        "acquisition-admission",
    )
    assert watch._status_command(acquisition.paths) == (
        str(acquisition.paths.launcher),
        "class-study",
        "acquisition-status",
        "--candidate-catalogue",
        str(acquisition.paths.candidate_catalogue),
        "--acquisition-root",
        str(acquisition.paths.acquisition_root),
    )
    due = _details(probing=1, due=1, blocked=True)
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def run_response(command, _cwd, _env):
        assert command[2] == "acquisition-run"
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", due)),
            run_response,
            _completed(_result("acquisition-status", complete)),
        ]
    )
    result = watch.watch_acquisition(
        paths=acquisition.paths,
        runner=runner,
        environment={
            "PATH": "/usr/bin:/bin",
            "BASH_ENV": "/tmp/untrusted-shell-hook",
            "PYTHONPATH": "/tmp/untrusted-python",
            "PRESERVED": "no",
            watch.PREPARE_IMAGE_ENV: "wrong",
        },
    )

    assert result["details"]["complete"] is True
    assert [call[0] for call in runner.calls] == [
        watch._admission_command(acquisition.paths),
        watch._browser_egress_verify_command(
            acquisition.paths, watch._validate_immutable_binding(acquisition.paths)
        ),
        watch._status_command(acquisition.paths),
        watch._run_command(acquisition.paths),
        watch._status_command(acquisition.paths),
    ]
    assert all(call[1] == acquisition.paths.lab_root for call in runner.calls)
    assert all(call[2]["PATH"] == "/usr/bin:/bin" for call in runner.calls)
    assert all("PRESERVED" not in call[2] for call in runner.calls)
    assert all("BASH_ENV" not in call[2] for call in runner.calls)
    assert all("PYTHONPATH" not in call[2] for call in runner.calls)
    assert all(watch.SCOPE_ROOT_ENV not in call[2] for call in runner.calls)
    coordinator_calls = [
        call for call in runner.calls if call[0] != watch._admission_command(acquisition.paths)
    ]
    assert all(call[2][watch.PREPARE_IMAGE_ENV] == acquisition.image for call in coordinator_calls)
    assert all(watch.LOCK_ENV not in call[2] for call in runner.calls)


def test_browser_egress_verify_command_has_one_exact_supervised_scope(
    acquisition: Fixture,
) -> None:
    binding = watch._validate_immutable_binding(acquisition.paths)
    command = watch._browser_egress_verify_command(acquisition.paths, binding)
    assert command == (
        str(acquisition.paths.launcher),
        "test",
        "browser-egress",
        "verify",
        "--cohort-version",
        "23",
        "--build-execution-receipt",
        str(acquisition.build_execution_path),
        "--result-root",
        str(acquisition.browser_egress_root),
    )
    assert watch._scope_command_runtime(command) == 600

    for index, replacement in (
        (3, "run"),
        (5, "023"),
        (7, str(acquisition.build_execution_path.with_name("other.json"))),
        (9, str(acquisition.browser_egress_root.with_name("other"))),
    ):
        forged = list(command)
        forged[index] = replacement
        with pytest.raises(watch.WatchError, match="unrecognised acquisition command"):
            watch._scope_command_runtime(forged)


def test_action_status_validates_transactional_active_batch_summary() -> None:
    active = {
        "batch_id": "active-" + "a" * 64,
        "stage": "navigation",
        "published_at": "2026-08-29T01:00:00Z",
        "candidate_ids": ["tranco-0000001", "tranco-0000002"],
        "live_page_count": 2,
        "attempt_count": 2,
    }
    details = _details(recovery=2, active_batch=active)
    watch._validate_action_result(
        _result("acquisition-status", details), action="acquisition-status"
    )

    probe_active = copy.deepcopy(active)
    probe_active.update({"stage": "probe", "live_page_count": 5, "attempt_count": 5})
    watch._validate_action_result(
        _result(
            "acquisition-status",
            _details(
                terminal=watch.CANDIDATE_COUNT - 2,
                probing=2,
                recovery=5,
                active_batch=probe_active,
            ),
        ),
        action="acquisition-status",
    )

    for field, value in (("stage", "baseline"), ("attempt_count", 1)):
        invalid = copy.deepcopy(details)
        invalid["active_batch"][field] = value
        with pytest.raises(watch.WatchError, match="active batch"):
            watch._validate_action_result(
                _result("acquisition-status", invalid),
                action="acquisition-status",
            )


@pytest.mark.parametrize("schema_alias", (True, 1.0))
def test_action_result_requires_an_exact_integer_schema(schema_alias: object) -> None:
    result = _result("acquisition-status", _details())
    result["schema_version"] = schema_alias

    with pytest.raises(watch.WatchError, match="identity is mismatched"):
        watch._validate_action_result(result, action="acquisition-status")


@pytest.mark.parametrize(
    "field",
    (
        "acquisition_schema_version",
        "checkpoint_schema_version",
        "maximum_candidates_per_action",
        "global_live_page_cap",
    ),
)
@pytest.mark.parametrize("alias_kind", ("bool", "float"))
def test_action_status_requires_exact_integer_schema_and_cap_fields(
    field: str,
    alias_kind: str,
) -> None:
    details = _details()
    details[field] = True if alias_kind == "bool" else float(details[field])

    with pytest.raises(watch.WatchError, match="schema or batch cap"):
        watch._validate_action_result(
            _result("acquisition-status", details),
            action="acquisition-status",
        )


@pytest.mark.parametrize("alias_kind", ("bool", "float"))
def test_action_status_gate_requires_exact_integer_nested_caps(alias_kind: str) -> None:
    result = _result("acquisition-status", _details())
    cap = result["details"]["gate"]["batching"]["maximum_candidates_per_action"]
    result["details"]["gate"]["batching"]["maximum_candidates_per_action"] = (
        True if alias_kind == "bool" else float(cap)
    )

    with pytest.raises(watch.WatchError, match="another stability gate"):
        watch._validate_action_result(result, action="acquisition-status")


@pytest.mark.parametrize("alias_kind", ("bool", "float"))
def test_action_run_requires_an_exact_integer_candidate_cap(alias_kind: str) -> None:
    result = _result("acquisition-run", _details())
    result["details"]["bounded_candidates"] = (
        True if alias_kind == "bool" else float(watch.MAX_CANDIDATES)
    )

    with pytest.raises(watch.WatchError, match="bounded wait contract"):
        watch._validate_action_result(result, action="acquisition-run")


@pytest.mark.parametrize("schema_alias", (True, 1.0))
def test_docker_admission_requires_an_exact_integer_schema(schema_alias: object) -> None:
    value = {
        "schema_version": schema_alias,
        "artifact_type": watch.DOCKER_ADMISSION_TYPE,
        "docker_context": "default",
        "docker_host": "unix:///var/run/docker.sock",
        "docker_server_id": "fixture-server",
        "host_boot_id": watch._host_boot_id(),
    }

    with pytest.raises(watch.WatchError, match="unsafe binding"):
        watch._validate_docker_admission(value)


def test_action_status_validates_finalisable_work_as_disjoint_and_due() -> None:
    finalisable = _details(
        terminal=watch.CANDIDATE_COUNT - 1,
        probing=1,
        finalisable=1,
    )
    watch._validate_action_result(
        _result("acquisition-status", finalisable),
        action="acquisition-status",
    )

    overlapping = _details(
        terminal=watch.CANDIDATE_COUNT - 1,
        probing=1,
        due=1,
        finalisable=1,
    )
    with pytest.raises(watch.WatchError, match="counts are inconsistent"):
        watch._validate_action_result(
            _result("acquisition-status", overlapping),
            action="acquisition-status",
        )

    false_due_flag = copy.deepcopy(finalisable)
    false_due_flag["work_due_now"] = False
    with pytest.raises(watch.WatchError, match="due-work flag"):
        watch._validate_action_result(
            _result("acquisition-status", false_due_flag),
            action="acquisition-status",
        )


def test_complete_exits_without_creating_completion_receipt(acquisition: Fixture) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    _materialise_selection(acquisition, complete["selection"])
    runner = FakeRunner([_completed(_result("acquisition-status", complete))])

    watch.watch_acquisition(paths=acquisition.paths, runner=runner)

    assert not (acquisition.paths.acquisition_root / "completion.json").exists()
    assert len(runner.calls) == 3


def test_browser_egress_deep_verify_is_exactly_once_before_status(
    acquisition: Fixture,
) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    _materialise_selection(acquisition, complete["selection"])
    runner = FakeRunner([_completed(_result("acquisition-status", complete))])

    watch.watch_acquisition(paths=acquisition.paths, runner=runner)

    binding = watch._validate_immutable_binding(acquisition.paths)
    assert [call[0] for call in runner.calls] == [
        watch._admission_command(acquisition.paths),
        watch._browser_egress_verify_command(acquisition.paths, binding),
        watch._status_command(acquisition.paths),
    ]
    verification_environment = runner.calls[1][2]
    assert verification_environment[watch.PREPARE_IMAGE_ENV] == acquisition.image
    assert verification_environment[watch.PINNED_CONTEXT_ENV] == "default"
    assert verification_environment[watch.PINNED_HOST_ENV] == ("unix:///var/run/docker.sock")
    assert verification_environment[watch.PINNED_SERVER_ID_ENV] == "test-daemon-01"


@pytest.mark.parametrize(
    ("response", "message"),
    (
        (
            _completed("", returncode=19, stderr="deep replay failed"),
            "deep verification failed with exit 19: deep replay failed",
        ),
        (_completed("not-json"), "not exactly one JSON"),
    ),
)
def test_browser_egress_deep_verify_child_failure_is_fail_closed(
    acquisition: Fixture,
    response: subprocess.CompletedProcess,
    message: str,
) -> None:
    runner = FakeRunner([], browser_egress_response=response)

    with pytest.raises(watch.WatchError, match=message):
        watch.watch_acquisition(paths=acquisition.paths, runner=runner)

    assert len(runner.calls) == 2
    assert watch._is_canonical_browser_egress_verify_command(runner.calls[-1][0])


def test_browser_egress_deep_verify_rejects_noncanonical_stdout(
    acquisition: Fixture,
) -> None:
    response = _completed(_browser_egress_result(acquisition.paths))

    with pytest.raises(watch.WatchError, match="not canonical JSON"):
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=FakeRunner([], browser_egress_response=response),
        )


def test_browser_egress_deep_verify_rejects_mismatched_pass_summary(
    acquisition: Fixture,
) -> None:
    result = _browser_egress_result(acquisition.paths)
    result["passed"] = False

    with pytest.raises(watch.WatchError, match="differs from the foundation binding"):
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=FakeRunner([], browser_egress_response=_completed_canonical(result)),
        )


def test_browser_egress_binding_tamper_after_deep_verify_is_detected_before_status(
    acquisition: Fixture,
) -> None:
    result = _browser_egress_result(acquisition.paths)

    def tamper(_command, _cwd, _env):
        acquisition.browser_egress_final_path.write_bytes(
            acquisition.browser_egress_final_path.read_bytes() + b"\n"
        )
        return _completed_canonical(result)

    runner = FakeRunner([], browser_egress_response=tamper)
    with pytest.raises(watch.WatchError, match="not canonically encoded"):
        watch.watch_acquisition(paths=acquisition.paths, runner=runner)

    assert len(runner.calls) == 2


def test_browser_egress_nested_evidence_tamper_after_deep_verify_is_detected_before_status(
    acquisition: Fixture,
) -> None:
    nested = acquisition.browser_egress_root / "evidence/001--fixture/capture.pcapng"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(b"sealed packet evidence")
    result = _browser_egress_result(acquisition.paths)

    def tamper(_command, _cwd, _env):
        nested.write_bytes(b"tampered packet evidence")
        return _completed_canonical(result)

    runner = FakeRunner([], browser_egress_response=tamper)
    with pytest.raises(watch.WatchError, match="immutable evidence binding changed"):
        watch.watch_acquisition(paths=acquisition.paths, runner=runner)

    assert len(runner.calls) == 2


def test_waits_to_target_with_five_second_heartbeats_and_no_busy_spin(
    acquisition: Fixture,
) -> None:
    start = datetime(2026, 8, 29, tzinfo=UTC)
    target = start + timedelta(seconds=12)
    target_text = target.isoformat().replace("+00:00", "Z")
    waiting = _details(probing=1, blocked=True, next_due=target_text)
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def run_response(_command, _cwd, _env):
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", waiting)),
            run_response,
            _completed(_result("acquisition-status", complete)),
        ]
    )
    clock = FakeClock(start)

    watch.watch_acquisition(
        paths=acquisition.paths,
        runner=runner,
        clock=clock,
        sleeper=clock.sleep,
    )

    assert clock.sleeps == [5.0, 5.0, 2.0]
    assert clock.value == target
    assert [call[0][2] for call in runner.calls[2:]] == [
        "acquisition-status",
        "acquisition-run",
        "acquisition-status",
    ]


def test_wait_revalidates_host_source_without_polling_status_containers(
    acquisition: Fixture,
) -> None:
    start = datetime(2026, 8, 29, tzinfo=UTC)
    target = start + timedelta(seconds=65)
    waiting = _details(
        probing=1,
        blocked=True,
        next_due=target.isoformat().replace("+00:00", "Z"),
    )
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    clock = FakeClock(start)
    monotonic = FakeMonotonic()
    validations: list[float] = []

    def sleep(seconds: float) -> None:
        clock.sleep(seconds)
        monotonic.value += seconds

    def validate(_paths, _binding) -> None:
        validations.append(monotonic.value)

    def run_response(_command, _cwd, _env):
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", waiting)),
            run_response,
            _completed(_result("acquisition-status", complete)),
        ]
    )
    watch.watch_acquisition(
        paths=acquisition.paths,
        runner=runner,
        clock=clock,
        sleeper=sleep,
        monotonic=monotonic,
        source_validator=validate,
    )

    assert validations == [0.0] * 6 + [60.0] + [65.0] * 5
    assert [call[0][2] for call in runner.calls[2:]] == [
        "acquisition-status",
        "acquisition-run",
        "acquisition-status",
    ]


def test_resume_uses_existing_checkpoint_and_releases_lock_on_interrupt(
    acquisition: Fixture,
) -> None:
    start = datetime(2026, 8, 29, tzinfo=UTC)
    future = (start + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    waiting = _details(probing=1, blocked=True, next_due=future)
    interrupted = FakeRunner([_completed(_result("acquisition-status", waiting))])

    with pytest.raises(KeyboardInterrupt):
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=interrupted,
            clock=lambda: start,
            sleeper=lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt),
        )

    due = _details(probing=1, missed=1, blocked=True)
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def run_response(_command, _cwd, _env):
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    resumed = FakeRunner(
        [
            _completed(_result("acquisition-status", due)),
            run_response,
            _completed(_result("acquisition-status", complete)),
        ]
    )
    assert watch.watch_acquisition(paths=acquisition.paths, runner=resumed)["details"]["complete"]


def test_clock_jump_delegates_missed_terminalisation_to_existing_runner(
    acquisition: Fixture,
) -> None:
    start = datetime(2026, 8, 29, tzinfo=UTC)
    target = (start + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    waiting = _details(probing=1, blocked=True, next_due=target)
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    clock = FakeClock(start)

    def jump(_seconds: float) -> None:
        clock.sleeps.append(_seconds)
        clock.value += timedelta(seconds=40)

    def run_response(command, _cwd, _env):
        assert command == watch._run_command(acquisition.paths)
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", waiting)),
            run_response,
            _completed(_result("acquisition-status", complete)),
        ]
    )

    watch.watch_acquisition(
        paths=acquisition.paths,
        runner=runner,
        clock=clock,
        sleeper=jump,
    )

    assert clock.sleeps == [5.0]
    assert sum(call[0][2] == "acquisition-run" for call in runner.calls[1:]) == 1


def test_lock_contention_fails_before_calling_coordinator(acquisition: Fixture) -> None:
    descriptor = os.open(acquisition.paths.mutation_lock, os.O_RDWR)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    runner = FakeRunner([])
    try:
        with pytest.raises(watch.WatchError, match="another class-study acquisition"):
            watch.watch_acquisition(paths=acquisition.paths, runner=runner)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
    assert runner.calls == []


def test_incomplete_status_without_due_or_next_due_fails(acquisition: Fixture) -> None:
    stuck = _details(terminal=watch.CANDIDATE_COUNT - 1, probing=1, blocked=False)
    _materialise_selection(acquisition, stuck["selection"])
    runner = FakeRunner([_completed(_result("acquisition-status", stuck))])

    with pytest.raises(watch.WatchError, match="no due work and no next_due"):
        watch.watch_acquisition(paths=acquisition.paths, runner=runner)


@pytest.mark.parametrize("kind", ("infrastructure", "quota"))
def test_drained_watcher_explains_selection_blocker(acquisition: Fixture, kind: str) -> None:
    if kind == "infrastructure":
        details = _details(terminal=1)
        details.update(
            selection=_selection_fixture(),
            selection_blocked_candidate_ids=[acquisition.candidate_ids[0]],
            pending_count=0,
            work_due_now=False,
        )
        reason = "selection blocked by infrastructure outcomes"
    else:
        details = _details(terminal=600)
        selection = details["selection"]
        selection["strata"][0].update(
            eligible_ids=[], admission_ids=[], cutoff_id=None,
            complete=False, quota_unmet=True,
        )
        selection.update(
            complete=False, pilot_ids=[], quota_unmet_strata=["1-1000"],
            admission_ids=[item for row in selection["strata"] for item in row["admission_ids"]],
        )
        details["complete"] = False
        reason = "scientific quota remains unmet"
    _materialise_selection(acquisition, details["selection"],
                           blocked_ids=tuple(details["selection_blocked_candidate_ids"]))
    runner = FakeRunner([_completed(_result("acquisition-status", details))])
    with pytest.raises(watch.WatchError, match=reason):
        watch.watch_acquisition(paths=acquisition.paths, runner=runner)
    assert not any(call[0][2] == "acquisition-run" for call in runner.calls)


@pytest.mark.parametrize(
    "response,match",
    [
        (_completed("not-json"), "not exactly one JSON"),
        (
            _completed(
                _result(
                    "acquisition-status",
                    _details(terminal=watch.CANDIDATE_COUNT),
                    runner_root="/lab/artifacts/another-acquisition",
                )
            ),
            "another acquisition root",
        ),
        (
            _completed(_result("acquisition-run", _details(terminal=watch.CANDIDATE_COUNT))),
            "identity is mismatched",
        ),
    ],
)
def test_malformed_or_mismatched_result_fails(acquisition: Fixture, response, match) -> None:
    with pytest.raises(watch.WatchError, match=match):
        watch.watch_acquisition(paths=acquisition.paths, runner=FakeRunner([response]))


def test_mismatched_prepare_image_and_child_failure_fail_closed(acquisition: Fixture) -> None:
    provenance = json.loads(acquisition.paths.provenance.read_text(encoding="utf-8"))
    payload = copy.deepcopy(provenance["payload"])
    payload["image_digest"] = "neqo-qcsd-lab-prepare:local"
    payload["source"]["image_digest"] = payload["image_digest"]
    _write_receipt(acquisition.paths.provenance, watch.PROVENANCE_TYPE, payload)
    with pytest.raises(watch.WatchError, match="exact prepare image"):
        watch.watch_acquisition(paths=acquisition.paths, runner=FakeRunner([]))

    # Restore a fully bound fixture, then exercise an actual child failure.
    acquisition = _restore_provenance_binding(acquisition)
    failed = _completed("", returncode=17, stderr="docker unavailable")
    with pytest.raises(watch.WatchError, match="exit 17: docker unavailable"):
        watch.watch_acquisition(paths=acquisition.paths, runner=FakeRunner([failed]))


@pytest.mark.parametrize(
    "field",
    [
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
        "origin_policy",
    ],
)
def test_watcher_rejects_discovery_contract_drift(acquisition: Fixture, field: str) -> None:
    provenance = json.loads(acquisition.paths.provenance.read_text(encoding="utf-8"))
    payload = copy.deepcopy(provenance["payload"])
    if field == "passive_render_contract":
        payload[field]["minimum_after_load_ms"] += 1
    elif field == "acquisition_action_timing_contract":
        payload[field]["inner_timeout"]["soft_deadline_ms"] -= 1
    elif field == "baseline_scheduling_contract":
        payload[field]["minimum_baseline_spacing_ms"] -= 1
    elif field.endswith("_ms"):
        payload[field] -= 1
    else:
        payload[field] = "stale-contract"
    _write_receipt(acquisition.paths.provenance, watch.PROVENANCE_TYPE, payload)

    with pytest.raises(watch.WatchError, match="another study or catalogue"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_reconciles_baseline_batches_with_candidate_state(
    acquisition: Fixture,
) -> None:
    payload = _checkpoint_payload(acquisition)
    candidate_ids = acquisition.candidate_ids[:2]
    baseline_started_at = "2026-08-29T01:00:00Z"
    for index, candidate_id in enumerate(candidate_ids):
        payload["candidates"][candidate_id] = {
            "state": "probing",
            "pages": [{"page": {"ordinal": index}}],
            "terminal": None,
            "baseline_started_at": baseline_started_at,
        }
    payload["baseline_batches"] = [
        _batch(
            "baseline",
            {
                "baseline_started_at": baseline_started_at,
                "candidate_ids": candidate_ids,
                "live_page_count": 2,
            },
        )
    ]
    _replace_checkpoint(acquisition, payload)
    binding = watch._validate_immutable_binding(acquisition.paths)
    watch._validate_checkpoint(acquisition.paths, binding)

    mutations = (
        lambda value: value["baseline_batches"][0].__setitem__("live_page_count", 1),
        lambda value: value["candidates"][candidate_ids[0]].__setitem__(
            "baseline_started_at", "2026-08-29T01:00:01Z"
        ),
        lambda value: value["baseline_batches"].append(copy.deepcopy(value["baseline_batches"][0])),
        lambda value: value["baseline_batches"][0]["candidate_ids"].reverse(),
        lambda value: value["baseline_batches"].clear(),
    )
    for mutate in mutations:
        invalid = copy.deepcopy(payload)
        mutate(invalid)
        # Recompute content addressing only when the mutation is intended to
        # exercise cross-ledger truth rather than the ID check itself.
        if len(invalid["baseline_batches"]) == 1:
            body = {
                name: item
                for name, item in invalid["baseline_batches"][0].items()
                if name != "batch_id"
            }
            invalid["baseline_batches"][0] = _batch("baseline", body)
        _replace_checkpoint(acquisition, invalid)
        with pytest.raises(watch.WatchError, match="baseline batch"):
            watch._validate_checkpoint(acquisition.paths, binding)


def test_watcher_rejects_cross_offset_baseline_batch_collision(
    acquisition: Fixture,
) -> None:
    payload = _checkpoint_payload(acquisition)
    candidate_ids = acquisition.candidate_ids[:2]
    starts = ("2026-08-29T01:00:00Z", "2026-08-31T01:00:00Z")
    batches = []
    for candidate_id, started_at in zip(candidate_ids, starts, strict=True):
        payload["candidates"][candidate_id] = {
            "state": "probing",
            "pages": [{"page": {"ordinal": 0}}],
            "terminal": None,
            "baseline_started_at": started_at,
        }
        batches.append(
            _batch(
                "baseline",
                {
                    "baseline_started_at": started_at,
                    "candidate_ids": [candidate_id],
                    "live_page_count": 1,
                },
            )
        )
    payload["baseline_batches"] = batches
    _replace_checkpoint(acquisition, payload)

    with pytest.raises(watch.WatchError, match="violate the serial schedule"):
        watch._validate_checkpoint(
            acquisition.paths,
            watch._validate_immutable_binding(acquisition.paths),
        )


def test_watcher_reconciles_transactional_navigation_batch(
    acquisition: Fixture,
) -> None:
    payload = _checkpoint_payload(acquisition)
    candidate_ids = acquisition.candidate_ids[:2]
    started_at = "2026-08-29T01:00:00Z"
    attempts = []
    for candidate_id in candidate_ids:
        payload["candidates"][candidate_id]["pending_navigation"] = {
            "attempt": 1,
            "started_at": started_at,
        }
        attempts.append(
            {
                "candidate_id": candidate_id,
                "page_ordinal": None,
                "probe_id": None,
                "workload_id": None,
                "attempt": 1,
                "started_at": started_at,
            }
        )
    payload["active_batch"] = _batch(
        "active",
        {
            "active_batch_schema_version": 1,
            "stage": "navigation",
            "published_at": started_at,
            "candidate_ids": candidate_ids,
            "live_page_count": 2,
            "attempts": attempts,
        },
    )
    _replace_checkpoint(acquisition, payload)
    binding = watch._validate_immutable_binding(acquisition.paths)
    watch._validate_checkpoint(acquisition.paths, binding)

    invalid = copy.deepcopy(payload)
    invalid["active_batch"]["stage"] = "baseline"
    body = {name: item for name, item in invalid["active_batch"].items() if name != "batch_id"}
    invalid["active_batch"] = _batch("active", body)
    _replace_checkpoint(acquisition, invalid)
    with pytest.raises(watch.WatchError, match="active batch stage"):
        watch._validate_checkpoint(acquisition.paths, binding)

    invalid = copy.deepcopy(payload)
    invalid["active_batch"]["published_at"] = "2026-08-29T01:00:00.000000Z"
    for attempt in invalid["active_batch"]["attempts"]:
        attempt["started_at"] = invalid["active_batch"]["published_at"]
        invalid["candidates"][attempt["candidate_id"]]["pending_navigation"]["started_at"] = (
            invalid["active_batch"]["published_at"]
        )
    body = {name: item for name, item in invalid["active_batch"].items() if name != "batch_id"}
    invalid["active_batch"] = _batch("active", body)
    _replace_checkpoint(acquisition, invalid)
    with pytest.raises(watch.WatchError, match="canonical UTC timestamp"):
        watch._validate_checkpoint(acquisition.paths, binding)

    invalid = copy.deepcopy(payload)
    invalid["candidates"][candidate_ids[0]]["pending_navigation"]["attempt"] = 2
    _replace_checkpoint(acquisition, invalid)
    with pytest.raises(watch.WatchError, match="differ from pending candidate state"):
        watch._validate_checkpoint(acquisition.paths, binding)


def test_watcher_reconciles_transactional_probe_batch(
    acquisition: Fixture,
) -> None:
    payload = _checkpoint_payload(acquisition)
    candidate_id = acquisition.candidate_ids[0]
    baseline_started_at = "2026-08-29T00:59:30Z"
    started_at = "2026-08-29T01:00:00Z"
    workload_id = f"{candidate_id}-p00-t30s-a001"
    pending_probe = {
        "probe_id": "t+30s",
        "workload_id": workload_id,
        "attempt": 1,
        "observed_at": started_at,
    }
    payload["candidates"][candidate_id] = {
        "state": "probing",
        "pages": [{"page": {"ordinal": 0}, "pending_probe": pending_probe}],
        "terminal": None,
        "baseline_started_at": baseline_started_at,
    }
    payload["baseline_batches"] = [
        _batch(
            "baseline",
            {
                "baseline_started_at": baseline_started_at,
                "candidate_ids": [candidate_id],
                "live_page_count": 1,
            },
        )
    ]
    payload["active_batch"] = _batch(
        "active",
        {
            "active_batch_schema_version": 1,
            "stage": "probe",
            "published_at": started_at,
            "candidate_ids": [candidate_id],
            "live_page_count": 1,
            "attempts": [
                {
                    "candidate_id": candidate_id,
                    "page_ordinal": 0,
                    "probe_id": "t+30s",
                    "workload_id": workload_id,
                    "attempt": 1,
                    "started_at": started_at,
                }
            ],
        },
    )
    _replace_checkpoint(acquisition, payload)
    binding = watch._validate_immutable_binding(acquisition.paths)
    watch._validate_checkpoint(acquisition.paths, binding)

    invalid = copy.deepcopy(payload)
    invalid["active_batch"]["attempts"][0]["page_ordinal"] = 1
    body = {name: item for name, item in invalid["active_batch"].items() if name != "batch_id"}
    invalid["active_batch"] = _batch("active", body)
    _replace_checkpoint(acquisition, invalid)
    with pytest.raises(watch.WatchError, match="differ from pending candidate state"):
        watch._validate_checkpoint(acquisition.paths, binding)

    invalid = copy.deepcopy(payload)
    second_workload = f"{candidate_id}-p01-t24h-a001"
    invalid["candidates"][candidate_id]["pages"].append(
        {
            "page": {"ordinal": 1},
            "pending_probe": {
                "probe_id": "t+24h",
                "workload_id": second_workload,
                "attempt": 1,
                "observed_at": started_at,
            },
        }
    )
    baseline_body = {
        name: item for name, item in invalid["baseline_batches"][0].items() if name != "batch_id"
    }
    baseline_body["live_page_count"] = 2
    invalid["baseline_batches"][0] = _batch("baseline", baseline_body)
    invalid["active_batch"]["live_page_count"] = 2
    invalid["active_batch"]["attempts"].append(
        {
            "candidate_id": candidate_id,
            "page_ordinal": 1,
            "probe_id": "t+24h",
            "workload_id": second_workload,
            "attempt": 1,
            "started_at": started_at,
        }
    )
    body = {name: item for name, item in invalid["active_batch"].items() if name != "batch_id"}
    invalid["active_batch"] = _batch("active", body)
    _replace_checkpoint(acquisition, invalid)
    with pytest.raises(watch.WatchError, match="mixes identities or windows"):
        watch._validate_checkpoint(acquisition.paths, binding)


def test_watcher_rejects_pending_attempt_without_active_batch(
    acquisition: Fixture,
) -> None:
    payload = _checkpoint_payload(acquisition)
    payload["candidates"][acquisition.candidate_ids[0]]["pending_navigation"] = {
        "attempt": 1,
        "started_at": "2026-08-29T01:00:00Z",
    }
    _replace_checkpoint(acquisition, payload)
    with pytest.raises(watch.WatchError, match="without an active batch"):
        watch._validate_checkpoint(
            acquisition.paths,
            watch._validate_immutable_binding(acquisition.paths),
        )


def _restore_provenance_binding(acquisition: Fixture) -> Fixture:
    provenance = json.loads(acquisition.paths.provenance.read_text(encoding="utf-8"))
    payload = copy.deepcopy(provenance["payload"])
    payload["image_digest"] = acquisition.image
    payload["source"]["image_digest"] = acquisition.image
    _write_receipt(acquisition.paths.provenance, watch.PROVENANCE_TYPE, payload)
    checkpoint = json.loads(acquisition.paths.checkpoint.read_text(encoding="utf-8"))
    checkpoint_payload = copy.deepcopy(checkpoint["payload"])
    checkpoint_payload["provenance_sha256"] = hashlib.sha256(
        acquisition.paths.provenance.read_bytes()
    ).hexdigest()
    _write_receipt(acquisition.paths.checkpoint, watch.CHECKPOINT_TYPE, checkpoint_payload)
    return acquisition


def _replace_foundation_and_rebind_provenance(
    acquisition: Fixture, payload: dict[str, Any]
) -> None:
    _write_receipt(acquisition.foundation_path, watch.FOUNDATION_TYPE, payload)
    provenance = json.loads(acquisition.paths.provenance.read_text(encoding="utf-8"))
    provenance_payload = copy.deepcopy(provenance["payload"])
    provenance_payload["acquisition_authority"]["sha256"] = hashlib.sha256(
        acquisition.foundation_path.read_bytes()
    ).hexdigest()
    _write_receipt(acquisition.paths.provenance, watch.PROVENANCE_TYPE, provenance_payload)


def _replace_pinned_and_rebind_foundation(acquisition: Fixture, payload: dict[str, Any]) -> None:
    _write_receipt(acquisition.pinned_cdp_path, watch.PINNED_CDP_TYPE, payload)
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    foundation = json.loads(acquisition.foundation_path.read_text(encoding="utf-8"))
    foundation_payload = copy.deepcopy(foundation["payload"])
    binding = foundation_payload["evidence"]["pinned_cdp_probe"]
    binding["sha256"] = hashlib.sha256(acquisition.pinned_cdp_path.read_bytes()).hexdigest()
    binding["payload_sha256"] = pinned["payload_sha256"]
    binding["build_execution"] = copy.deepcopy(payload["build_execution"])
    binding["build_execution_identity"] = copy.deepcopy(payload["build_execution_identity"])
    binding["probe_contract_sha256"] = payload["probe_contract_sha256"]
    foundation_payload["hard_gates"][-2]["evidence_sha256s"] = sorted(
        {
            binding["sha256"],
            binding["payload_sha256"],
            binding["build_execution"]["sha256"],
            binding["build_execution"]["payload_sha256"],
            foundation_payload["build_execution_identity"]["completion_sha256"],
            binding["probe_contract_sha256"],
        }
    )
    _replace_foundation_and_rebind_provenance(acquisition, foundation_payload)


def _replace_build_and_rebind_foundation(acquisition: Fixture, payload: dict[str, Any]) -> None:
    """Reseal every outer digest so build semantics are the only rejection."""

    _write_build_execution(acquisition.build_execution_path, payload)
    build = json.loads(acquisition.build_execution_path.read_text(encoding="utf-8"))
    if build["schema_version"] == 5:
        _write_build_completion(
            acquisition.build_completion_path,
            build_path=acquisition.build_execution_path,
            build=build,
        )
        completion_sha256 = hashlib.sha256(
            acquisition.build_completion_path.read_bytes()
        ).hexdigest()
    else:
        acquisition.build_completion_path.unlink(missing_ok=True)
        completion_sha256 = None
    build_sha256 = hashlib.sha256(acquisition.build_execution_path.read_bytes()).hexdigest()
    build_binding = {
        "path": "/lab/artifacts/buflo-study/build-execution-v23.json",
        "sha256": build_sha256,
        "payload_sha256": build["payload_sha256"],
    }

    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    pinned_payload = copy.deepcopy(pinned["payload"])
    pinned_payload["build_execution"] = copy.deepcopy(build_binding)
    pinned_payload["build_execution_identity"]["sha256"] = build_sha256
    if completion_sha256 is not None:
        pinned_payload["build_execution_identity"]["completion_sha256"] = completion_sha256
    _write_receipt(acquisition.pinned_cdp_path, watch.PINNED_CDP_TYPE, pinned_payload)
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    pinned_sha256 = hashlib.sha256(acquisition.pinned_cdp_path.read_bytes()).hexdigest()

    foundation = json.loads(acquisition.foundation_path.read_text(encoding="utf-8"))
    foundation_payload = copy.deepcopy(foundation["payload"])
    foundation_payload["build_execution_identity"]["sha256"] = build_sha256
    if completion_sha256 is not None:
        foundation_payload["build_execution_identity"]["completion_sha256"] = completion_sha256
    foundation_payload["evidence"]["build_execution"]["sha256"] = build_sha256
    browser_build = foundation_payload["evidence"]["browser_egress_qualification"][
        "build_execution"
    ]
    browser_build["sha256"] = build_sha256
    browser_build["size_bytes"] = acquisition.build_execution_path.stat().st_size
    browser_build["payload_sha256"] = build["payload_sha256"]
    if completion_sha256 is not None:
        browser_build["completion_sha256"] = completion_sha256
    pinned_binding = foundation_payload["evidence"]["pinned_cdp_probe"]
    pinned_binding["sha256"] = pinned_sha256
    pinned_binding["payload_sha256"] = pinned["payload_sha256"]
    pinned_binding["build_execution"] = copy.deepcopy(build_binding)
    pinned_binding["build_execution_identity"] = copy.deepcopy(
        pinned_payload["build_execution_identity"]
    )
    foundation_payload["hard_gates"][-2]["evidence_sha256s"] = sorted(
        {
            pinned_sha256,
            pinned["payload_sha256"],
            build_sha256,
            (
                completion_sha256
                if completion_sha256 is not None
                else foundation_payload["build_execution_identity"]["completion_sha256"]
            ),
            build["payload_sha256"],
            pinned_binding["probe_contract_sha256"],
        }
    )
    _replace_foundation_and_rebind_provenance(acquisition, foundation_payload)


def _reseal_build_completion(
    acquisition: Fixture,
    mutate: Any,
) -> None:
    completion = json.loads(acquisition.build_completion_path.read_text(encoding="utf-8"))
    completion.pop("payload_sha256")
    mutate(completion)
    completion["payload_sha256"] = _compact_digest(completion)
    acquisition.build_completion_path.write_bytes(
        (
            json.dumps(
                completion,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
    )
    acquisition.build_completion_path.chmod(0o600)


def _replace_completion_transaction_field(
    completion: dict[str, Any],
    field: str,
    replacement: str,
) -> None:
    record = completion["transaction"]["record"]
    raw = base64.b64decode(record["payload_base64"], validate=True)
    values = dict(line.split("=", 1) for line in raw.decode("ascii").splitlines())
    values[field] = replacement
    replaced = "".join(
        f"{name}={values[name]}\n" for name in watch._BUILD_TRANSACTION_RECORD_FIELDS
    ).encode("ascii")
    record["payload_base64"] = base64.b64encode(replaced).decode("ascii")
    record["sha256"] = hashlib.sha256(replaced).hexdigest()
    record["stat"]["size"] = len(replaced)


def test_current_foundation_watcher_accepts_exact_schema5_build_and_completion(
    acquisition: Fixture,
) -> None:
    snapshot = watch._load_build_execution(
        acquisition.build_execution_path,
        paths=acquisition.paths,
        require_current=True,
    )

    assert snapshot.value["schema_version"] == 5
    assert snapshot.value["buildx"]["passed"] is True
    assert (
        snapshot.completion_sha256
        == hashlib.sha256(acquisition.build_completion_path.read_bytes()).hexdigest()
    )


def test_schema4_build_remains_historically_parseable_but_cannot_found_current_admission(
    acquisition: Fixture,
) -> None:
    build = json.loads(acquisition.build_execution_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(build)
    payload.pop("payload_sha256")
    payload["schema_version"] = 4
    for field in (
        "cohort_allocation",
        "cohort_claim",
        "cohort_claim_chain",
        "cohort_authority_reproofs",
    ):
        payload.pop(field)
    _replace_build_and_rebind_foundation(acquisition, payload)

    historical = watch._load_build_execution(
        acquisition.build_execution_path,
        paths=acquisition.paths,
    )
    assert historical.value["schema_version"] == 4
    assert historical.completion_sha256 is None

    with pytest.raises(watch.WatchError, match="historical.*schema 5"):
        watch._validate_immutable_binding(acquisition.paths)


def test_schema5_build_is_parseable_but_not_current_without_completion(
    acquisition: Fixture,
) -> None:
    acquisition.build_completion_path.unlink()

    provisional = watch._load_build_execution(
        acquisition.build_execution_path,
        paths=acquisition.paths,
    )
    assert provisional.value["schema_version"] == 5
    assert provisional.completion_sha256 is None

    with pytest.raises(watch.WatchError, match="build completion"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_independently_rejects_resealed_schema5_allocation_tampering(
    acquisition: Fixture,
) -> None:
    build = json.loads(acquisition.build_execution_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(build)
    payload.pop("payload_sha256")
    payload["cohort_allocation"]["ledger_sha256"] = "1" * 64
    _replace_build_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="cohort ledger SHA-256"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_independently_rejects_resealed_non_dense_claim_chain(
    acquisition: Fixture,
) -> None:
    build = json.loads(acquisition.build_execution_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(build)
    payload.pop("payload_sha256")
    chain = payload["cohort_claim_chain"]
    chain["claims"] = []
    chain.pop("payload_sha256")
    chain["payload_sha256"] = _compact_digest(chain)
    _replace_build_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="claim-chain inventory"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_independently_rejects_resealed_free_form_chain_predecessor(
    acquisition: Fixture,
) -> None:
    build = json.loads(acquisition.build_execution_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(build)
    payload.pop("payload_sha256")
    chain = payload["cohort_claim_chain"]
    entry = chain["claims"][0]
    claim = json.loads(base64.b64decode(entry["payload_base64"], validate=True))
    claim["payload"]["predecessor"]["sha256"] = "1" * 64
    claim["payload_sha256"] = _compact_digest(claim["payload"])
    claim_raw = (
        json.dumps(claim, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("ascii")
    entry["sha256"] = hashlib.sha256(claim_raw).hexdigest()
    entry["payload_base64"] = base64.b64encode(claim_raw).decode("ascii")
    chain["head"]["sha256"] = entry["sha256"]
    chain.pop("payload_sha256")
    chain["payload_sha256"] = _compact_digest(chain)
    _replace_build_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="claim predecessor"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_independently_rejects_crossed_schema5_build_timeline(
    acquisition: Fixture,
) -> None:
    build = json.loads(acquisition.build_execution_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(build)
    payload.pop("payload_sha256")
    payload["cohort_authority_reproofs"][6]["observed_at"] = "2026-08-28T00:14:00+00:00"
    _replace_build_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="cohort stage timeline"):
        watch._validate_immutable_binding(acquisition.paths)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (
            lambda completion: completion["receipt"]["stat"].__setitem__(
                "inode", completion["receipt"]["stat"]["inode"] + 1
            ),
            "completion receipt binding",
        ),
        (
            lambda completion: completion["cohort_authority"].__setitem__(
                "claim_chain_sha256", "1" * 64
            ),
            "completion cohort authority",
        ),
        (
            lambda completion: completion["transaction"]["guardian"].__setitem__(
                "qcsd_pid", completion["transaction"]["guardian"]["pid"]
            ),
            "completion transaction authority",
        ),
        (
            lambda completion: completion["transaction"]["operation_lock"].__setitem__(
                "inode", completion["transaction"]["cohort_lock"]["inode"]
            ),
            "completion transaction lock relationship",
        ),
        (
            lambda completion: completion["transaction"]["root"].__setitem__(
                "path", "/tmp/transaction.00000000000000000000000000000000"
            ),
            "completion transaction path binding",
        ),
        (
            lambda completion: _replace_completion_transaction_field(
                completion,
                "working_directory",
                "/tmp/replayed-build-root",
            ),
            "completion transaction record authority",
        ),
        (
            lambda completion: completion["final_reproof"].__setitem__(
                "claim_file_sha256", "1" * 64
            ),
            "completion final reproof",
        ),
        (
            lambda completion: completion.__setitem__("completed_at", "2026-08-28T01:00:03+00:00"),
            "completion timing",
        ),
    ),
)
def test_watcher_rejects_resealed_build_completion_tampering(
    acquisition: Fixture,
    mutation: Any,
    message: str,
) -> None:
    _reseal_build_completion(acquisition, mutation)

    with pytest.raises(watch.WatchError, match=message):
        watch._validate_immutable_binding(acquisition.paths)


def test_foundation_identity_must_bind_the_canonical_completion_path(
    acquisition: Fixture,
) -> None:
    foundation = json.loads(acquisition.foundation_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(foundation["payload"])
    payload["build_execution_identity"]["completion_path"] = (
        "/lab/artifacts/buflo-study/build-completion-v24.json"
    )
    _replace_foundation_and_rebind_provenance(acquisition, payload)

    with pytest.raises(watch.WatchError, match="build identity"):
        watch._validate_immutable_binding(acquisition.paths)


def test_current_watcher_rejects_historical_class_foundation_schema(
    acquisition: Fixture,
) -> None:
    foundation = json.loads(acquisition.foundation_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(foundation["payload"])
    payload["attestation_schema_version"] = watch.HISTORICAL_FOUNDATION_SCHEMA_VERSION
    _replace_foundation_and_rebind_provenance(acquisition, payload)

    with pytest.raises(watch.WatchError, match="authority envelope"):
        watch._validate_immutable_binding(acquisition.paths)


def test_later_source_reproof_rejects_a_validly_resealed_completion_replacement(
    acquisition: Fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = watch._validate_immutable_binding(acquisition.paths)
    original_authority = watch._source_binding_sha256(binding)
    _reseal_build_completion(
        acquisition,
        lambda completion: completion.__setitem__(
            "completed_at", "2026-08-28T01:00:00.300000+00:00"
        ),
    )
    replacement_sha256 = hashlib.sha256(acquisition.build_completion_path.read_bytes()).hexdigest()
    assert replacement_sha256 != binding.build_completion_sha256
    monkeypatch.setattr(
        watch,
        "_host_source_snapshot",
        lambda _paths: (
            binding.source["lab_commit"],
            binding.source["neqo_commit"],
            binding.source["neqo_pinned_commit"],
            "",
            "",
        ),
    )

    with pytest.raises(watch.WatchError, match="completion changed after admission"):
        _REAL_VALIDATE_HOST_SOURCE(acquisition.paths, binding)
    assert watch._source_binding_sha256(binding) == original_authority


def test_source_binding_preimage_versions_the_build_completion_identity(
    acquisition: Fixture,
) -> None:
    binding = watch._validate_immutable_binding(acquisition.paths)
    preimage = {
        "browser_egress_qualification": dict(binding.browser_egress_qualification),
        "browser_egress_tree_sha256": binding.browser_egress_tree_sha256,
        "candidate_catalogue_sha256": binding.catalogue_sha256,
        "build_completion_path": binding.build_completion_path,
        "build_completion_sha256": binding.build_completion_sha256,
        "build_execution_sha256": binding.build_execution_sha256,
        "cohort_version": binding.cohort_version,
        "foundation_sha256": binding.foundation_sha256,
        "acquisition_authority_path": binding.acquisition_authority_path,
        "acquisition_authority_sha256": binding.acquisition_authority_sha256,
        "pinned_cdp_contract_sha256": binding.pinned_cdp_contract_sha256,
        "pinned_cdp_payload_sha256": binding.pinned_cdp_payload_sha256,
        "pinned_cdp_sha256": binding.pinned_cdp_sha256,
        "prepare_image": binding.prepare_image,
        "provenance_sha256": binding.provenance_sha256,
        "source": dict(binding.source),
        "source_binding_preimage_schema_version": (watch.SOURCE_BINDING_PREIMAGE_SCHEMA_VERSION),
    }
    assert watch.SOURCE_BINDING_PREIMAGE_SCHEMA_VERSION == 3
    assert watch._source_binding_sha256(binding) == watch._sha256_bytes(
        watch._canonical_json_bytes(preimage)
    )

    legacy_preimage = dict(preimage)
    del legacy_preimage["source_binding_preimage_schema_version"]
    del legacy_preimage["build_completion_path"]
    del legacy_preimage["build_completion_sha256"]
    del legacy_preimage["acquisition_authority_path"]
    del legacy_preimage["acquisition_authority_sha256"]
    assert watch._source_binding_sha256(binding) != watch._sha256_bytes(
        watch._canonical_json_bytes(legacy_preimage)
    )


def test_current_foundation_watcher_bounds_the_build_receipt_before_parsing(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(watch, "BUILD_EXECUTION_MAX_BYTES", 1)

    with pytest.raises(watch.WatchError, match="exceeds its maximum byte count"):
        watch._load_build_execution(
            acquisition.build_execution_path,
            paths=acquisition.paths,
        )


@pytest.mark.parametrize(
    ("field_path", "replacement", "message"),
    (
        (("schema_version",), 3, "execution schema"),
        (("duration_seconds",), 60.0, "build duration"),
        (("commands", 0, "argv", 5), "--cache", "--pull --no-cache"),
        (("cache_policy", "no_cache"), False, "cache policy"),
        (("build_inputs", "uv_lock_sha256"), "1" * 64, "checkout binding"),
        (("buildx", "schema_version"), True, "buildx provenance schema"),
        (("buildx", "identity", "plugin", "mode"), True, "stat identity"),
        (
            ("buildx", "identity", "resolved", "mode"),
            stat.S_IFREG | 0o777,
            "safe root-owned executable",
        ),
        (("buildx", "observations", 2, "identity_sha256"), "1" * 64, "observation"),
        (
            ("role_provenance", "sources", "reference", "lab_commit"),
            "1" * 40,
            "different source snapshots",
        ),
        (("host_storage_preflight", "passed"), False, "storage preflight schema"),
    ),
)
def test_watcher_rejects_fully_resealed_schema4_build_tampering(
    acquisition: Fixture,
    field_path: tuple[str | int, ...],
    replacement: Any,
    message: str,
) -> None:
    build = json.loads(acquisition.build_execution_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(build)
    payload.pop("payload_sha256")
    target: Any = payload
    for component in field_path[:-1]:
        target = target[component]
    target[field_path[-1]] = replacement

    _replace_build_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match=message):
        watch._validate_immutable_binding(acquisition.paths)


def test_current_foundation_watcher_rejects_a_fully_valid_historical_schema3_build(
    acquisition: Fixture,
) -> None:
    build = json.loads(acquisition.build_execution_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(build)
    payload.pop("payload_sha256")
    payload["schema_version"] = 3
    payload.pop("buildx")
    _replace_build_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="execution schema"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_fully_resealed_relocated_build_root(
    acquisition: Fixture,
) -> None:
    build = json.loads(acquisition.build_execution_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(build)
    payload.pop("payload_sha256")
    replacement_root = "/unrelated/neqo-qcsd-lab"
    for command in payload["commands"]:
        target = command["target"]
        iid_index = command["argv"].index("--iidfile") + 1
        command["argv"][iid_index] = (
            f"{replacement_root}/artifacts/buflo-study/.build-iids-v23.ABC123/{target}.iid"
        )
        command["argv"][-2] = f"{replacement_root}/Dockerfile"
        command["argv"][-1] = replacement_root

    _replace_build_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="command root differs"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_resealed_foundation_without_pinned_cdp_gate(
    acquisition: Fixture,
) -> None:
    foundation = json.loads(acquisition.foundation_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(foundation["payload"])
    payload["evidence"].pop("pinned_cdp_probe")

    _replace_foundation_and_rebind_provenance(acquisition, payload)

    with pytest.raises(watch.WatchError, match="evidence inventory"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_resealed_foundation_without_browser_egress_gate(
    acquisition: Fixture,
) -> None:
    foundation = json.loads(acquisition.foundation_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(foundation["payload"])
    payload["evidence"].pop("browser_egress_qualification")

    _replace_foundation_and_rebind_provenance(acquisition, payload)

    with pytest.raises(watch.WatchError, match="evidence inventory"):
        watch._validate_immutable_binding(acquisition.paths)


@pytest.mark.parametrize(
    "relative",
    (
        watch.BROWSER_EGRESS_MANIFEST_RELATIVE_PATH,
        watch.BROWSER_EGRESS_ARGV_RELATIVE_PATH,
    ),
)
def test_watcher_rejects_browser_egress_contract_byte_tamper(
    acquisition: Fixture,
    relative: str,
) -> None:
    contract = acquisition.paths.lab_root / relative
    value = json.loads(contract.read_text(encoding="utf-8"))
    value["schema_version"] = True
    contract.write_bytes(_canonical(value))

    with pytest.raises(watch.WatchError, match="frozen watcher contract"):
        watch._validate_immutable_binding(acquisition.paths)


@pytest.mark.parametrize(
    ("field_path", "replacement", "message"),
    (
        (("root",), "/lab/artifacts/buflo-study/browser-egress-qualification-v24", "path"),
        (("passed",), False, "source/build/result"),
        (("passed_vector_count",), 97, "source/build/result"),
        (("expanded_vectors_sha256",), "e" * 64, "source/build/result"),
        (("build_execution", "prepare_image_id"), "sha256:" + "7" * 64, "source/build/result"),
        (
            ("build_execution", "path"),
            "/lab/artifacts/buflo-study/build-execution-v23.json",
            "source/build/result",
        ),
        (("build_execution", "size_bytes"), 1, "source/build/result"),
        (
            ("build_execution", "completion_path"),
            "/lab/artifacts/buflo-study/build-completion-v24.json",
            "source/build/result",
        ),
        (("build_execution", "completion_sha256"), "f" * 64, "source/build/result"),
    ),
)
def test_watcher_rejects_resealed_browser_egress_binding_tamper(
    acquisition: Fixture,
    field_path: tuple[str, ...],
    replacement: Any,
    message: str,
) -> None:
    foundation = json.loads(acquisition.foundation_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(foundation["payload"])
    target = payload["evidence"]["browser_egress_qualification"]
    for component in field_path[:-1]:
        target = target[component]
    target[field_path[-1]] = replacement
    _replace_foundation_and_rebind_provenance(acquisition, payload)

    with pytest.raises(watch.WatchError, match=message):
        watch._validate_immutable_binding(acquisition.paths)


def test_current_watcher_rejects_historical_browser_egress_build_projection(
    acquisition: Fixture,
) -> None:
    foundation = json.loads(acquisition.foundation_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(foundation["payload"])
    browser_build = payload["evidence"]["browser_egress_qualification"]["build_execution"]
    browser_build.pop("completion_path")
    browser_build.pop("completion_sha256")
    _replace_foundation_and_rebind_provenance(acquisition, payload)

    with pytest.raises(watch.WatchError, match="source/build/result"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_fully_resealed_browser_egress_final_semantic_tamper(
    acquisition: Fixture,
) -> None:
    final = json.loads(acquisition.browser_egress_final_path.read_text(encoding="utf-8"))
    final_payload = copy.deepcopy(final["payload"])
    final_payload["verdict"] = "failed"
    _write_receipt(
        acquisition.browser_egress_final_path,
        watch.BROWSER_EGRESS_FINAL_TYPE,
        final_payload,
    )
    rewritten = json.loads(acquisition.browser_egress_final_path.read_text(encoding="utf-8"))
    foundation = json.loads(acquisition.foundation_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(foundation["payload"])
    binding = payload["evidence"]["browser_egress_qualification"]
    binding["sha256"] = hashlib.sha256(
        acquisition.browser_egress_final_path.read_bytes()
    ).hexdigest()
    binding["payload_sha256"] = rewritten["payload_sha256"]
    payload["hard_gates"][-1]["evidence_sha256s"] = sorted(
        {
            binding["sha256"],
            binding["payload_sha256"],
            binding["expanded_vectors_sha256"],
        }
    )
    _replace_foundation_and_rebind_provenance(acquisition, payload)

    with pytest.raises(watch.WatchError, match="final payload is invalid"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_resealed_same_count_wrong_ordered_vector_id(
    acquisition: Fixture,
) -> None:
    final = json.loads(acquisition.browser_egress_final_path.read_text(encoding="utf-8"))
    final_payload = copy.deepcopy(final["payload"])
    final_payload["passed_results"][0]["vector_id"] = final_payload["passed_results"][1][
        "vector_id"
    ]
    _write_receipt(
        acquisition.browser_egress_final_path,
        watch.BROWSER_EGRESS_FINAL_TYPE,
        final_payload,
    )
    rewritten = json.loads(acquisition.browser_egress_final_path.read_text(encoding="utf-8"))
    foundation = json.loads(acquisition.foundation_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(foundation["payload"])
    binding = payload["evidence"]["browser_egress_qualification"]
    binding["sha256"] = hashlib.sha256(
        acquisition.browser_egress_final_path.read_bytes()
    ).hexdigest()
    binding["payload_sha256"] = rewritten["payload_sha256"]
    payload["hard_gates"][-1]["evidence_sha256s"] = sorted(
        {
            binding["sha256"],
            binding["payload_sha256"],
            binding["expanded_vectors_sha256"],
        }
    )
    _replace_foundation_and_rebind_provenance(acquisition, payload)

    with pytest.raises(watch.WatchError, match="result inventory"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_pinned_cdp_contract_matches_runtime_contract() -> None:
    from qcsd_lab import (
        browser_egress,
        browser_egress_fixture,
        browser_egress_qualification,
        cdp_targets,
        class_acquisition,
        class_attestation,
        discovery_evidence,
        pinned_cdp,
        playwright_driver,
    )

    lab_root = Path(__file__).resolve().parents[1]
    study = json.loads((lab_root / "config/class-study/v1/study.json").read_text(encoding="utf-8"))
    manifest_path = lab_root / watch.BROWSER_EGRESS_MANIFEST_RELATIVE_PATH
    argv_path = lab_root / watch.BROWSER_EGRESS_ARGV_RELATIVE_PATH
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    argv = json.loads(argv_path.read_text(encoding="utf-8"))

    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == (
        watch.BROWSER_EGRESS_MANIFEST_SHA256
    )
    assert hashlib.sha256(argv_path.read_bytes()).hexdigest() == (watch.BROWSER_EGRESS_ARGV_SHA256)
    assert manifest == browser_egress_qualification.expected_manifest_config()
    assert argv == browser_egress_qualification.expected_argv_config()
    assert manifest["vector_count"] == watch.BROWSER_EGRESS_VECTOR_COUNT
    assert manifest["expanded_vectors_sha256"] == (watch.BROWSER_EGRESS_EXPANDED_VECTORS_SHA256)
    assert manifest["execution_contract"]["browser"]["quic"] == {
        "disable_switch": "--disable-quic",
        "disable_switch_bare_and_unique": True,
        "enabled": False,
        "rationale": "prevent-preferred-address-migration-bypassing-resolver-pins",
    }
    assert argv["command_line_projection_schema_version"] == (
        watch._BROWSER_EGRESS_COMMAND_LINE_SCHEMA_VERSION
    )
    assert argv["antagonistic_effective_switches"] == (
        watch._BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES
    )
    assert argv["required_effective_switches"].count("--disable-quic") == 1
    assert "--disable-quic" not in argv["antagonistic_effective_switches"]
    assert "--enable-quic" in argv["antagonistic_effective_switches"]

    assert watch._CDP_TARGET_INSTRUMENTATION_POLICY == (
        cdp_targets.CDP_TARGET_INSTRUMENTATION_POLICY
    )
    assert watch._BOOTSTRAP_PREARM_SUMMARY_SCHEMA_VERSION == (
        cdp_targets.BOOTSTRAP_PREARM_SUMMARY_SCHEMA_VERSION
    )
    assert watch._EGRESS_PREARM_SUMMARY_SCHEMA_VERSION == (
        cdp_targets.EGRESS_PREARM_SUMMARY_SCHEMA_VERSION
    )
    assert watch._PINNED_CDP_SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION == (
        cdp_targets.SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION
    )
    assert watch._PINNED_CDP_SRCDOC_PSEUDO_DOCUMENT_POLICY == (
        cdp_targets.SRCDOC_PSEUDO_DOCUMENT_POLICY
    )
    assert watch._PINNED_CDP_SRCDOC_PSEUDO_DOCUMENT_LIMIT == (
        cdp_targets._SRCDOC_PSEUDO_DOCUMENT_LIMIT
    )
    assert watch._PINNED_CDP_SRCDOC_EVENT_ORDINAL_LIMIT == (
        cdp_targets._SRCDOC_EVENT_ORDINAL_LIMIT
    )
    assert watch._PINNED_CDP_SCHEMA_VERSION == pinned_cdp.PROBE_SCHEMA_VERSION
    assert watch._HISTORICAL_PINNED_CDP_SCHEMA_VERSION == (
        pinned_cdp.HISTORICAL_PROBE_SCHEMA_VERSION
    )
    assert watch._HISTORICAL_PINNED_CDP_SCHEMA_VERSIONS == (
        pinned_cdp.HISTORICAL_PROBE_SCHEMA_VERSIONS
    )
    assert watch._PINNED_CDP_CONTRACT_SCHEMA_VERSION == pinned_cdp.PROBE_CONTRACT["schema_version"]
    assert watch._PINNED_CDP_TARGET_ACTIVITY_SCHEMA_VERSION == (
        pinned_cdp.TARGET_ACTIVITY_SCHEMA_VERSION
    )
    assert watch._PINNED_CDP_TARGET_ACTIVITY_EVENTS == (pinned_cdp._TARGET_ACTIVITY_EVENTS)
    assert watch._PINNED_CDP_TARGET_ACTIVITY_TYPES == (pinned_cdp._TARGET_ACTIVITY_TYPES)
    assert watch._PINNED_CDP_CONTRACT == pinned_cdp.PROBE_CONTRACT
    assert watch._HISTORICAL_PINNED_CDP_CONTRACT == (pinned_cdp._HISTORICAL_PROBE_CONTRACT)
    assert watch._HISTORICAL_PINNED_CDP_CONTRACT_V11 == (pinned_cdp._HISTORICAL_PROBE_CONTRACT_V11)
    assert watch._HISTORICAL_PINNED_CDP_CONTRACT_V12 == (pinned_cdp._HISTORICAL_PROBE_CONTRACT_V12)
    assert watch._HISTORICAL_PINNED_CDP_CONTRACT_V13 == (pinned_cdp._HISTORICAL_PROBE_CONTRACT_V13)
    assert watch._HISTORICAL_PINNED_CDP_CONTRACT_V14 == (pinned_cdp._HISTORICAL_PROBE_CONTRACT_V14)
    assert watch._PINNED_CDP_EVENT_METHODS == pinned_cdp._EVENT_METHODS
    assert watch._PINNED_CDP_HTTP_STATUS_COUNTS == (pinned_cdp._EXPECTED_HTTP_STATUS_COUNTS)
    assert watch._PINNED_CDP_SERVER_REQUEST_COUNTS == (pinned_cdp._EXPECTED_SERVER_REQUEST_COUNTS)
    assert watch._PINNED_CDP_WORKER_RESPONSE_CONSUMPTION == (
        pinned_cdp._EXPECTED_WORKER_RESPONSE_CONSUMPTION
    )
    assert watch._PINNED_CDP_WORKER_WEBTRANSPORT_PROBE_SCHEMA_VERSION == (
        pinned_cdp.WORKER_WEBTRANSPORT_PROBE_SCHEMA_VERSION
    )
    assert watch._PINNED_CDP_WORKER_WEBTRANSPORT_PROBE == (
        pinned_cdp._EXPECTED_WORKER_WEBTRANSPORT_PROBE
    )
    assert watch._PINNED_CDP_BOOTSTRAP_PREARM_SUMMARY == (
        pinned_cdp._EXPECTED_PINNED_BOOTSTRAP_PREARM_SUMMARY
    )
    assert watch._PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY == (playwright_driver.OWNERSHIP_POLICY_RECEIPT)
    assert watch._EXPECTED_PLAYWRIGHT_DRIVER_BINDING == (
        playwright_driver.EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
    assert watch._PREVIOUS_PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY == (
        playwright_driver.PREVIOUS_OWNERSHIP_POLICY_RECEIPT
    )
    assert watch._PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING == (
        playwright_driver.PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
    assert watch._LEGACY_PLAYWRIGHT_DRIVER_OWNERSHIP_POLICY == (
        playwright_driver.LEGACY_OWNERSHIP_POLICY_RECEIPT
    )
    assert watch._LEGACY_EXPECTED_PLAYWRIGHT_DRIVER_BINDING == (
        playwright_driver.LEGACY_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
    assert watch._EXPECTED_BROWSER_TOOL_IDENTITY == (
        playwright_driver.expected_browser_tool_identity()
    )
    assert watch._NON_REPLAYABLE_EGRESS_CONTRACT == (browser_egress.NON_REPLAYABLE_EGRESS_CONTRACT)
    assert watch._BROWSER_EGRESS_COMMAND_LINE_SCHEMA_VERSION == (
        browser_egress.BROWSER_EGRESS_COMMAND_LINE_SCHEMA_VERSION
    )
    assert watch._BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES == list(
        browser_egress.BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES
    )
    assert watch._BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES == list(
        browser_egress.BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES
    )
    assert watch._BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE == (
        browser_egress.BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE
    )
    assert watch._BROWSER_EGRESS_REQUIRED_DISABLED_FEATURE_TOKENS == sorted(
        browser_egress.BROWSER_EGRESS_DISABLED_BASE_FEATURES
    )
    assert watch._BROWSER_EGRESS_REQUIRED_DISABLED_BLINK_FEATURE_TOKENS == sorted(
        browser_egress.BROWSER_EGRESS_DISABLED_BLINK_FEATURES
    )
    assert watch._BROWSER_EGRESS_REQUIRED_ENABLED_FEATURE_ARGUMENTS == [
        list(browser_egress.BROWSER_EGRESS_PLAYWRIGHT_ENABLED_FEATURES)
    ]
    assert watch._BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT == (
        browser_egress.BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT
    )
    assert watch._PINNED_CDP_RESOLVER_PROJECTION == (pinned_cdp._PINNED_CDP_RESOLVER_PROJECTION)
    assert watch.BROWSER_EGRESS_FINAL_TYPE == (browser_egress_qualification.FINAL_RECEIPT_TYPE)
    assert watch.BROWSER_EGRESS_QUALIFICATION_ID == (browser_egress_fixture.QUALIFICATION_ID)
    assert watch.BROWSER_EGRESS_VECTOR_COUNT == (browser_egress_fixture.VECTOR_COUNT)
    assert watch.BROWSER_EGRESS_EXPANDED_VECTORS_SHA256 == (
        browser_egress_fixture.expanded_vectors_sha256()
    )
    assert list(watch._BROWSER_EGRESS_VECTOR_IDS) == [
        vector.vector_id for vector in browser_egress_fixture.expected_vectors()
    ]
    assert watch.FOUNDATION_SCHEMA_VERSION == class_attestation.FOUNDATION_SCHEMA_VERSION
    assert watch.HISTORICAL_FOUNDATION_SCHEMA_VERSION == (
        class_attestation.HISTORICAL_FOUNDATION_SCHEMA_VERSION
    )
    assert browser_egress_qualification.FOUNDATION_SCHEMA_VERSION == 6
    assert browser_egress_qualification.HISTORICAL_FOUNDATION_SCHEMA_VERSION == 2
    assert browser_egress_qualification.HISTORICAL_FOUNDATION_SCHEMA_VERSIONS == frozenset(
        {2, 3, 4, 5}
    )
    assert watch._FOUNDATION_GATES == class_attestation._FOUNDATION_GATES
    assert study["authority_gates"]["foundation"]["reconstructed_gates"] == list(
        watch._FOUNDATION_GATES
    )
    assert watch._PASSIVE_RENDER_CONTRACT == discovery_evidence.PASSIVE_RENDER_CONTRACT
    assert watch._PASSIVE_RENDER_CONTRACT_SHA256 == (
        discovery_evidence.PASSIVE_RENDER_CONTRACT_SHA256
    )
    assert watch.ACQUISITION_SCHEMA_VERSION == class_acquisition.SCHEMA_VERSION
    assert watch.HISTORICAL_ACQUISITION_SCHEMA_VERSIONS == (
        class_acquisition.HISTORICAL_SCHEMA_VERSIONS
    )
    assert watch.CHECKPOINT_SCHEMA_VERSION == class_acquisition.CHECKPOINT_SCHEMA_VERSION
    assert watch.TERMINAL_SCHEMA_VERSION == class_acquisition.TERMINAL_SCHEMA_VERSION
    assert watch.COMPLETION_SCHEMA_VERSION == class_acquisition.COMPLETION_SCHEMA_VERSION
    assert watch.SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION == (
        class_acquisition.SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION
    )
    assert watch.SCHEMA_SIX_TERMINAL_SCHEMA_VERSION == (
        class_acquisition.SCHEMA_SIX_TERMINAL_SCHEMA_VERSION
    )
    assert watch.SCHEMA_SIX_COMPLETION_SCHEMA_VERSION == (
        class_acquisition.SCHEMA_SIX_COMPLETION_SCHEMA_VERSION
    )
    assert watch._PROVENANCE_PAYLOAD_KEYS == class_acquisition.CURRENT_PROVENANCE_FIELDS
    assert watch._NAVIGATION_IMPLEMENTATION == class_acquisition.NAVIGATION_IMPLEMENTATION
    assert watch._REGISTRABLE_DOMAIN_POLICY == class_acquisition.REGISTRABLE_DOMAIN_POLICY
    assert watch._DOMAIN_SAFETY_POLICY == class_acquisition.DOMAIN_SAFETY_POLICY
    assert (
        watch._DOMAIN_SAFETY_POLICY_SHA256
        == hashlib.sha256(
            class_acquisition.canonical_json_bytes(class_acquisition.DOMAIN_SAFETY_POLICY)
        ).hexdigest()
    )
    assert watch._ORIGIN_POLICY == class_acquisition.ORIGIN_POLICY
    assert watch._ELIGIBILITY_INPUTS == class_acquisition.ELIGIBILITY_INPUTS
    assert watch._PROHIBITED_INPUTS == class_acquisition.PROHIBITED_INPUTS
    assert watch._ACQUISITION_ACTION_TIMING_CONTRACT == (class_acquisition.ACTION_TIMING_CONTRACT)
    assert watch._BASELINE_SCHEDULING_CONTRACT == (class_acquisition.BASELINE_SCHEDULING_CONTRACT)


@pytest.mark.parametrize("historical_schema", (1, 2, 3, 4, 5, 6))
def test_watcher_treats_historical_provenance_as_verify_only(
    acquisition: Fixture,
    historical_schema: int,
) -> None:
    provenance = json.loads(acquisition.paths.provenance.read_text(encoding="utf-8"))
    payload = copy.deepcopy(provenance["payload"])
    payload["acquisition_schema_version"] = historical_schema
    _write_receipt(acquisition.paths.provenance, watch.PROVENANCE_TYPE, payload)

    with pytest.raises(watch.WatchError, match="historical.*verify-only"):
        watch._validate_immutable_binding(acquisition.paths)


@pytest.mark.parametrize("schema_alias", (True, 7.0, "7"))
def test_watcher_rejects_non_integer_current_provenance_schema(
    acquisition: Fixture,
    schema_alias: object,
) -> None:
    provenance = json.loads(acquisition.paths.provenance.read_text(encoding="utf-8"))
    payload = copy.deepcopy(provenance["payload"])
    payload["acquisition_schema_version"] = schema_alias
    _write_receipt(acquisition.paths.provenance, watch.PROVENANCE_TYPE, payload)

    with pytest.raises(watch.WatchError, match="not an exact integer"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_accepts_current_runtime_pinned_cdp_observation(
    acquisition: Fixture,
) -> None:
    from qcsd_lab import pinned_cdp

    receipt = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    observation = receipt["payload"]["observation"]

    assert pinned_cdp._validate_observation(copy.deepcopy(observation)) == observation
    watch._validate_pinned_cdp_observation(copy.deepcopy(observation))


def test_watcher_rejects_resealed_pinned_cdp_topology_tamper(
    acquisition: Fixture,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(pinned["payload"])
    payload["observation"]["topology"]["shared_worker_fetch_paused_on_shared_worker"] = False

    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="topology observation"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_accepts_exact_loading_finished_srcdoc_evidence(
    acquisition: Fixture,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(pinned["payload"])
    payload["observation"]["topology"]["srcdoc_pseudo_document_summary"] = (
        _srcdoc_pseudo_document_summary(
            terminal_method="Network.loadingFinished"
        )
    )
    _replace_pinned_and_rebind_foundation(acquisition, payload)

    watch._validate_immutable_binding(acquisition.paths)


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        pytest.param("terminal_variant", "loading-finished-other", id="variant"),
        pytest.param("terminal_method", "Network.loadingFailed", id="method"),
        pytest.param(
            "terminal_fields",
            ["requestId", "encodedDataLength", "timestamp"],
            id="field-order",
        ),
        pytest.param("resource_type", "Document", id="resource-type"),
        pytest.param("error_text", "net::ERR_ABORTED", id="error-text"),
        pytest.param("canceled", False, id="canceled"),
        pytest.param("encoded_data_length", True, id="boolean-length"),
        pytest.param("encoded_data_length", 33.0, id="float-length"),
        pytest.param("encoded_data_length", 0, id="zero-length"),
        pytest.param("encoded_data_length", 34, id="different-length"),
        pytest.param("encoded_data_length", None, id="missing-length"),
    ],
)
def test_watcher_rejects_inexact_loading_finished_srcdoc_evidence(
    field_name: str,
    replacement: Any,
) -> None:
    summary = _srcdoc_pseudo_document_summary(
        terminal_method="Network.loadingFinished"
    )
    summary["diagnostics"][0][field_name] = replacement

    with pytest.raises(watch.WatchError, match="diagnostic is inconsistent"):
        watch._validate_srcdoc_pseudo_document_summary(summary)


@pytest.mark.parametrize(
    ("field_path", "replacement", "message"),
    (
        (("egress_prearm_summary", "schema_version"), True, "egress-prearm identity"),
        (
            ("egress_prearm_summary", "by_target_type", "worker", "pending_count"),
            1,
            "egress-prearm per-type counts",
        ),
        (
            ("non_replayable_egress_summary", "attempt_count"),
            True,
            "non-replayable egress identity",
        ),
        (
            ("non_replayable_egress_summary", "protected_apis"),
            [],
            "non-replayable egress identity",
        ),
        (
            (
                "worker_webtransport_probe",
                "by_target_type",
                "worker",
                "measurement",
                "action_succeeded",
            ),
            True,
            "WebTransport action or telemetry",
        ),
        (
            (
                "worker_webtransport_probe",
                "by_target_type",
                "shared_worker",
                "guard_telemetry",
                "notification_count",
            ),
            2,
            "WebTransport action or telemetry",
        ),
        (
            ("srcdoc_pseudo_document_summary", "schema_version"),
            True,
            "srcdoc loader-bound summary identity",
        ),
        (
            (
                "srcdoc_pseudo_document_summary",
                "terminal_outcome_counts",
                "Network.loadingFailed",
            ),
            True,
            "srcdoc loader-bound terminal outcomes",
        ),
        (
            (
                "srcdoc_pseudo_document_summary",
                "terminal_outcome_counts",
                "Network.loadingFinished",
            ),
            1,
            "srcdoc loader-bound terminal outcomes",
        ),
        (
            (
                "srcdoc_pseudo_document_summary",
                "diagnostics",
                0,
                "frame_id_sha256",
            ),
            "raw-frame-id",
            "srcdoc loader-bound diagnostic hash",
        ),
        (
            (
                "srcdoc_pseudo_document_summary",
                "diagnostics",
                0,
                "stopped_event_ordinal",
            ),
            3,
            "srcdoc loader-bound event ordering",
        ),
        (
            (
                "srcdoc_pseudo_document_summary",
                "diagnostics",
                0,
                "started_navigating_event_ordinal",
            ),
            3,
            "srcdoc loader-bound event ordering",
        ),
        (
            (
                "srcdoc_pseudo_document_summary",
                "diagnostics",
                0,
                "loader_id_sha256",
            ),
            "e" * 64,
            "srcdoc loader-bound diagnostic is inconsistent",
        ),
        (
            (
                "srcdoc_pseudo_document_summary",
                "diagnostics",
                0,
                "navigation_type",
            ),
            "sameDocument",
            "srcdoc loader-bound diagnostic strings are invalid",
        ),
        (
            (
                "srcdoc_pseudo_document_summary",
                "diagnostics",
                0,
                "request_id_matches_loader",
            ),
            False,
            "srcdoc loader-bound diagnostic is inconsistent",
        ),
        (
            ("srcdoc_pseudo_document_summary", "network_history_saturated"),
            True,
            "srcdoc loader-bound topology observation",
        ),
        (
            ("browser_egress_command_line", "schema_version"),
            True,
            "command-line projection",
        ),
        (
            ("browser_egress_command_line", "observed_required_switches"),
            [],
            "command-line projection",
        ),
        (
            ("browser_egress_command_line", "antagonistic_switches"),
            [],
            "command-line projection",
        ),
        (
            ("browser_egress_command_line", "observed_antagonistic_switches"),
            ["--proxy-server"],
            "command-line projection",
        ),
        (
            ("browser_egress_command_line", "required_switches_are_bare_and_unique"),
            False,
            "command-line projection",
        ),
        (("browser_context_service_worker_count",), True, "topology observation"),
    ),
)
def test_watcher_rejects_resealed_pinned_cdp_egress_tamper(
    acquisition: Fixture,
    field_path: tuple[str | int, ...],
    replacement: Any,
    message: str,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(pinned["payload"])
    target: Any = payload["observation"]["topology"]
    for component in field_path[:-1]:
        target = target[component]
    target[field_path[-1]] = replacement
    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match=message):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_identifier_bearing_or_zero_srcdoc_proof(
    acquisition: Fixture,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    for kind in ("raw-identifier", "zero-proof"):
        payload = copy.deepcopy(pinned["payload"])
        summary = payload["observation"]["topology"][
            "srcdoc_pseudo_document_summary"
        ]
        if kind == "raw-identifier":
            summary["diagnostics"][0]["frame_id"] = "raw-frame-id"
            message = "srcdoc loader-bound diagnostic fields"
        else:
            summary.update(
                total=0,
                resolved=0,
                terminal_outcome_counts={
                    "Network.loadingFailed": 0,
                    "Network.loadingFinished": 0,
                },
                diagnostics=[],
            )
            message = "srcdoc loader-bound topology observation"
        _replace_pinned_and_rebind_foundation(acquisition, payload)
        with pytest.raises(watch.WatchError, match=message):
            watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_reused_srcdoc_frame_digest(acquisition: Fixture) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = pinned["payload"]
    summary = payload["observation"]["topology"]["srcdoc_pseudo_document_summary"]
    duplicate = copy.deepcopy(summary["diagnostics"][0])
    second_loader = hashlib.sha256(b"second-srcdoc-loader").hexdigest()
    duplicate["loader_id_sha256"] = second_loader
    duplicate["request_id_sha256"] = second_loader
    duplicate["requested_event_ordinal"] = 6
    duplicate["started_navigating_event_ordinal"] = 7
    duplicate["started_event_ordinal"] = 8
    duplicate["terminal_event_ordinal"] = 9
    duplicate["stopped_event_ordinal"] = 10
    summary.update(
        total=2,
        resolved=2,
        terminal_outcome_counts={
            "Network.loadingFailed": 2,
            "Network.loadingFinished": 0,
        },
        diagnostics=[*summary["diagnostics"], duplicate],
    )
    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="diagnostic is inconsistent"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_reused_srcdoc_event_ordinal(acquisition: Fixture) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = pinned["payload"]
    summary = payload["observation"]["topology"]["srcdoc_pseudo_document_summary"]
    duplicate = copy.deepcopy(summary["diagnostics"][0])
    duplicate["frame_id_sha256"] = hashlib.sha256(b"second-srcdoc-frame").hexdigest()
    second_loader = hashlib.sha256(b"second-srcdoc-loader").hexdigest()
    duplicate["loader_id_sha256"] = second_loader
    duplicate["request_id_sha256"] = second_loader
    duplicate["requested_event_ordinal"] = 5
    duplicate["started_navigating_event_ordinal"] = 7
    duplicate["started_event_ordinal"] = 8
    duplicate["terminal_event_ordinal"] = 9
    duplicate["stopped_event_ordinal"] = 10
    summary.update(
        total=2,
        resolved=2,
        terminal_outcome_counts={
            "Network.loadingFailed": 2,
            "Network.loadingFinished": 0,
        },
        diagnostics=[*summary["diagnostics"], duplicate],
    )
    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="ordinals are not globally unique"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_srcdoc_event_ordinals_above_the_bounded_history() -> None:
    summary = _srcdoc_pseudo_document_summary()
    diagnostic = summary["diagnostics"][0]
    for field_name in (
        "requested_event_ordinal",
        "started_navigating_event_ordinal",
        "started_event_ordinal",
        "terminal_event_ordinal",
        "stopped_event_ordinal",
    ):
        diagnostic[field_name] += watch._PINNED_CDP_SRCDOC_EVENT_ORDINAL_LIMIT

    with pytest.raises(watch.WatchError, match="event ordering is invalid"):
        watch._validate_srcdoc_pseudo_document_summary(summary)


@pytest.mark.parametrize(
    ("field_path", "replacement", "message"),
    (
        (
            ("event_method_counts", "Network.loadingFailed"),
            1,
            "event-method aggregate",
        ),
        (("http_status_counts", "/shared-data", "200"), 2, "topology observation"),
        (("http_status_counts", "/shared-data", "200"), True, "topology observation"),
        (("server_request_counts", "/shared-data"), 2, "topology observation"),
        (("server_request_counts", "/shared-data"), True, "topology observation"),
        (
            ("worker_response_consumption", "shared_worker"),
            "failed",
            "topology observation",
        ),
        (("bootstrap_prearm_summary", "schema_version"), True, "bootstrap-prearm summary schema"),
        (
            ("bootstrap_prearm_summary", "pending_total"),
            1,
            "bootstrap-prearm aggregate",
        ),
        (
            (
                "bootstrap_prearm_summary",
                "by_worker_type",
                "shared_worker",
                "released_after_setup_envelopes",
            ),
            0,
            "bootstrap-prearm is not terminal",
        ),
        (
            ("quiescent_target_activity", "generation"),
            4,
            "target-activity generation",
        ),
        (
            ("quiescent_target_activity", "schema_version"),
            True,
            "target-activity aggregate",
        ),
    ),
)
def test_watcher_rejects_resealed_pinned_cdp_aggregate_tamper(
    acquisition: Fixture,
    field_path: tuple[str, ...],
    replacement: Any,
    message: str,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(pinned["payload"])
    target: Any = payload["observation"]["topology"]
    for component in field_path[:-1]:
        target = target[component]
    target[field_path[-1]] = replacement

    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match=message):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_structurally_valid_wrong_bootstrap_owner(
    acquisition: Fixture,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(pinned["payload"])
    owner_counts = payload["observation"]["topology"]["bootstrap_prearm_summary"]["by_worker_type"][
        "shared_worker"
    ]["owner_target_types"]
    owner_counts["page"] = 0
    owner_counts["iframe"] = 1

    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="topology observation"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_structurally_valid_missing_target_attach(
    acquisition: Fixture,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(pinned["payload"])
    counts = payload["observation"]["topology"]["quiescent_target_activity"]["by_target_type"][
        "iframe"
    ]["event_counts"]
    counts["target-attached"] = 0
    counts["target-info-changed"] = 1

    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="target-activity observation"):
        watch._validate_immutable_binding(acquisition.paths)


@pytest.mark.parametrize(
    ("field_path", "replacement"),
    (
        (("browser_tool", "chromium_revision"), "1201"),
        (("browser_tool", "schema_version"), True),
        (("passive_render_contract", "viewport", "deviceScaleFactor"), True),
        (("non_replayable_egress_contract", "schema_version"), True),
        (
            ("non_replayable_egress_contract", "target_shim_sha256", "worker"),
            "0" * 64,
        ),
        (("cdp_target_instrumentation_policy",), "stale-policy"),
        (("origin_policy", "max_origins"), 31),
        (("eligibility_inputs",), ["classifier"]),
    ),
)
def test_watcher_rejects_resealed_provenance_contract_tamper(
    acquisition: Fixture,
    field_path: tuple[str, ...],
    replacement: Any,
) -> None:
    provenance = json.loads(acquisition.paths.provenance.read_text(encoding="utf-8"))
    payload = copy.deepcopy(provenance["payload"])
    target: Any = payload
    for component in field_path[:-1]:
        target = target[component]
    target[field_path[-1]] = replacement
    _write_receipt(acquisition.paths.provenance, watch.PROVENANCE_TYPE, payload)

    with pytest.raises(watch.WatchError, match="another study or catalogue"):
        watch._validate_immutable_binding(acquisition.paths)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("saved_uid", 1001),
        ("filesystem_gid", 1001),
        ("supplementary_groups", [1000, 1000]),
        ("bounding_capabilities", "0000000000000001"),
    ),
)
def test_watcher_rejects_resealed_pinned_cdp_isolation_tamper(
    acquisition: Fixture,
    field: str,
    replacement: Any,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(pinned["payload"])
    payload["observation"]["isolation"][field] = replacement

    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="isolation observation"):
        watch._validate_immutable_binding(acquisition.paths)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("receipt_sha256", "d" * 64),
        ("payload_sha256", "e" * 64),
        ("content_sha256", "f" * 64),
        ("policy", {"name": "unbound-driver"}),
        ("browsers_json_sha256", "0" * 64),
        ("chromium_executable_sha256", "1" * 64),
    ),
)
def test_watcher_rejects_resealed_pinned_cdp_driver_tamper(
    acquisition: Fixture,
    field: str,
    replacement: Any,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(pinned["payload"])
    payload["observation"]["playwright_driver"][field] = replacement

    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="Playwright driver observation"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_resealed_legacy_pinned_cdp_schema(
    acquisition: Fixture,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(pinned["payload"])
    payload["probe_schema_version"] = 4

    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="source/build/contract"):
        watch._validate_immutable_binding(acquisition.paths)


@pytest.mark.parametrize(
    "historical_schema_version",
    sorted(watch._HISTORICAL_PINNED_CDP_SCHEMA_VERSIONS),
)
def test_current_watcher_rejects_historical_pinned_cdp_schema(
    acquisition: Fixture,
    historical_schema_version: int,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(pinned["payload"])
    payload["probe_schema_version"] = historical_schema_version
    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="source/build/contract"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_resealed_foundation_pinned_completion_projection_tamper(
    acquisition: Fixture,
) -> None:
    foundation = json.loads(acquisition.foundation_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(foundation["payload"])
    payload["evidence"]["pinned_cdp_probe"]["build_execution_identity"]["completion_sha256"] = (
        "f" * 64
    )
    _replace_foundation_and_rebind_provenance(acquisition, payload)

    with pytest.raises(watch.WatchError, match="source/build/contract"):
        watch._validate_immutable_binding(acquisition.paths)


@pytest.mark.parametrize("schema_alias", (True, 7.0, "7"))
def test_watcher_rejects_non_integer_current_pinned_cdp_schema(
    acquisition: Fixture,
    schema_alias: object,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(pinned["payload"])
    payload["probe_schema_version"] = schema_alias
    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="source/build/contract"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_resealed_pinned_cdp_wrong_build(
    acquisition: Fixture,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(pinned["payload"])
    payload["build_execution"]["sha256"] = "f" * 64

    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="source/build/contract"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_rejects_resealed_pinned_cdp_wrong_cohort(
    acquisition: Fixture,
) -> None:
    pinned = json.loads(acquisition.pinned_cdp_path.read_text(encoding="utf-8"))
    payload = copy.deepcopy(pinned["payload"])
    payload["cohort_version"] = 24

    _replace_pinned_and_rebind_foundation(acquisition, payload)

    with pytest.raises(watch.WatchError, match="source/build/contract"):
        watch._validate_immutable_binding(acquisition.paths)


def test_due_run_must_advance_checkpoint(acquisition: Fixture) -> None:
    due = _details(probing=1, due=1, blocked=True)
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", due)),
            _completed(_result("acquisition-run", complete)),
        ]
    )

    with pytest.raises(watch.WatchError, match="did not advance the checkpoint"):
        watch.watch_acquisition(paths=acquisition.paths, runner=runner)


def test_launch_drift_to_a_blocked_boundary_restatuses_without_fabrication(
    acquisition: Fixture,
) -> None:
    start = datetime(2026, 8, 29, tzinfo=UTC)
    target = start + timedelta(seconds=2)
    target_text = target.isoformat().replace("+00:00", "Z")
    due = _details(probing=1, due=1, blocked=True)
    drifted = _details(probing=1, blocked=True, next_due=target_text)
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def final_run(_command, _cwd, _env):
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", due)),
            _completed(_result("acquisition-run", drifted)),
            _completed(_result("acquisition-status", drifted)),
            final_run,
            _completed(_result("acquisition-status", complete)),
        ]
    )
    clock = FakeClock(start)
    watch.watch_acquisition(
        paths=acquisition.paths,
        runner=runner,
        clock=clock,
        sleeper=clock.sleep,
    )

    assert clock.value == target
    assert [call[0][2] for call in runner.calls[2:]] == [
        "acquisition-status",
        "acquisition-run",
        "acquisition-status",
        "acquisition-run",
        "acquisition-status",
    ]


def test_expired_next_due_runs_immediately_without_redundant_status(
    acquisition: Fixture,
) -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    expired = (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    waiting = _details(probing=1, blocked=True, next_due=expired)
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def run_response(_command, _cwd, _env):
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", waiting)),
            run_response,
            _completed(_result("acquisition-status", complete)),
        ]
    )

    watch.watch_acquisition(paths=acquisition.paths, runner=runner, clock=lambda: now)

    assert [call[0][2] for call in runner.calls[2:]] == [
        "acquisition-status",
        "acquisition-run",
        "acquisition-status",
    ]


@pytest.mark.parametrize("heartbeat", (0.5, float("inf"), float("nan")))
def test_heartbeat_rejects_subsecond_and_nonfinite_values(
    acquisition: Fixture, heartbeat: float
) -> None:
    with pytest.raises(watch.WatchError, match=r"finite number in \[1, 5\]"):
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=FakeRunner([]),
            heartbeat_seconds=heartbeat,
        )


def test_trusted_environment_ignores_shell_python_docker_and_home_overrides() -> None:
    environment = watch._safe_host_environment(
        {
            "PATH": "/tmp/attacker",
            "HOME": "/tmp/attacker-home",
            "BASH_ENV": "/tmp/hook",
            "PYTHONPATH": "/tmp/imports",
            "DOCKER_HOST": "tcp://attacker.example:2376",
            "DOCKER_CONTEXT": "attacker",
            "DOCKER_CONFIG": "/tmp/docker",
            "XDG_RUNTIME_DIR": "/tmp/runtime",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/bus",
        }
    )

    assert environment["PATH"] == "/usr/bin:/bin"
    assert environment["HOME"] == "/nonexistent"
    assert environment["DOCKER_CONTEXT"] == "default"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert environment["XDG_RUNTIME_DIR"] == f"/run/user/{os.getuid()}"
    assert environment["DBUS_SESSION_BUS_ADDRESS"] == (f"unix:path=/run/user/{os.getuid()}/bus")
    assert (
        not {
            "BASH_ENV",
            "PYTHONPATH",
            "DOCKER_HOST",
            "DOCKER_CONFIG",
        }
        & environment.keys()
    )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.pop("host_boot_id"),
        lambda value: value.__setitem__("docker_context", "attacker"),
        lambda value: value.__setitem__("docker_host", "tcp://remote:2376"),
        lambda value: value.__setitem__("docker_server_id", "bad server id"),
        lambda value: value.__setitem__("artifact_type", "other"),
    ),
)
def test_docker_admission_requires_exact_local_binding(mutation) -> None:
    value = _admission()
    mutation(value)
    with pytest.raises(watch.WatchError, match="Docker admission"):
        watch._validate_docker_admission(value)


def test_admission_precedes_first_checkpoint_read_and_source_precedes_admission(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    _materialise_selection(acquisition, complete["selection"])
    events: list[str] = []
    real_checkpoint = watch._validate_checkpoint

    def checkpoint(paths, binding):
        events.append("checkpoint")
        return real_checkpoint(paths, binding)

    def source(_paths, _binding):
        events.append("source")

    def runner(
        command,
        *,
        cwd,
        env,
        authority_fd,
        state_root,
        source_binding_sha256,
    ):
        assert cwd == acquisition.paths.lab_root
        assert watch.LOCK_ENV not in env
        assert authority_fd >= 0
        assert state_root == acquisition.paths.state_root
        assert re.fullmatch(r"[0-9a-f]{64}", source_binding_sha256)
        if watch._is_canonical_browser_egress_verify_command(command):
            events.append("browser-egress-verify")
            return _completed_canonical(_browser_egress_result(acquisition.paths))
        action = command[2]
        events.append(action)
        if action == "acquisition-admission":
            return _completed(_admission())
        return _completed(
            _result(
                "acquisition-status",
                complete,
                foundation_sha256=watch._validate_immutable_binding(
                    acquisition.paths
                ).foundation_sha256,
            )
        )

    monkeypatch.setattr(watch, "_validate_checkpoint", checkpoint)
    watch.watch_acquisition(
        paths=acquisition.paths,
        runner=runner,
        source_validator=source,
    )

    assert events.index("source") < events.index("acquisition-admission")
    assert events.index("acquisition-admission") < events.index("browser-egress-verify")
    assert events.index("browser-egress-verify") < events.index("checkpoint")
    assert events.count("browser-egress-verify") == 1
    assert events[-2:] == ["source", "checkpoint"]


def test_status_checkpoint_race_fails_closed_after_action(acquisition: Fixture) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def status_mutation(_command, _cwd, _env):
        acquisition.advance_checkpoint()
        return _completed(
            _result(
                "acquisition-status",
                complete,
                foundation_sha256=watch._validate_immutable_binding(
                    acquisition.paths
                ).foundation_sha256,
            )
        )

    with pytest.raises(watch.WatchError, match="mutated or raced"):
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=FakeRunner([status_mutation]),
        )


def test_status_result_from_another_foundation_fails_closed(
    acquisition: Fixture,
) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    response = _result(
        "acquisition-status",
        complete,
        foundation_sha256="f" * 64,
    )

    with pytest.raises(watch.WatchError, match="another foundation binding"):
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=FakeRunner([_completed(response)]),
        )


def test_source_binding_is_rechecked_after_action(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    calls = 0

    def source(_paths, _binding):
        nonlocal calls
        calls += 1
        if calls == 4:
            raise watch.WatchError("post-action source drift")

    with pytest.raises(watch.WatchError, match="post-action source drift"):
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=FakeRunner([_completed(_result("acquisition-status", complete))]),
            source_validator=source,
        )


def test_lock_path_replacement_during_action_fails_and_new_lock_is_reacquirable(
    acquisition: Fixture,
) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def replace_lock(_command, _cwd, _env):
        staged = acquisition.paths.mutation_lock.with_suffix(".replacement")
        staged.write_bytes(b"")
        os.replace(staged, acquisition.paths.mutation_lock)
        return _completed(
            _result(
                "acquisition-status",
                complete,
                foundation_sha256=watch._validate_immutable_binding(
                    acquisition.paths
                ).foundation_sha256,
            )
        )

    with pytest.raises(watch.WatchError, match="lock pathname identity changed"):
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=FakeRunner([replace_lock]),
        )

    descriptor = os.open(acquisition.paths.mutation_lock, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)


def test_signal_is_latched_before_lock_acquisition_and_lock_is_reacquirable(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_acquire = watch._acquire_mutation_lock

    def acquire(path):
        descriptor = real_acquire(path)
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        handler(signal.SIGTERM, None)
        return descriptor

    monkeypatch.setattr(watch, "_acquire_mutation_lock", acquire)
    with pytest.raises(watch.WatchSignalInterrupt) as interrupted:
        watch.watch_acquisition(paths=acquisition.paths, runner=FakeRunner([]))
    assert interrupted.value.signum == signal.SIGTERM

    descriptor = os.open(acquisition.paths.mutation_lock, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)


def test_signal_latched_after_final_success_check_is_not_swallowed(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    _materialise_selection(acquisition, complete["selection"])
    original_raise = watch._SignalLatch.raise_if_set
    checks = 0

    def latch_immediately_after_fourth_check(latch: watch._SignalLatch) -> None:
        nonlocal checks
        checks += 1
        original_raise(latch)
        if checks == 4:
            handler = signal.getsignal(signal.SIGTERM)
            assert callable(handler)
            handler(signal.SIGTERM, None)

    monkeypatch.setattr(
        watch._SignalLatch,
        "raise_if_set",
        latch_immediately_after_fourth_check,
    )
    with pytest.raises(watch.WatchSignalInterrupt) as interrupted:
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=FakeRunner([_completed(_result("acquisition-status", complete))]),
        )
    assert interrupted.value.signum == signal.SIGTERM
    assert checks == 4
    assert watch._active_signal_latch is None

    descriptor = os.open(acquisition.paths.mutation_lock, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)


def test_signal_latch_unblocks_watched_signal_and_restores_exact_prior_mask() -> None:
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
    entered_mask = set(original_mask) | {signal.SIGTERM}
    try:
        with pytest.raises(watch.WatchSignalInterrupt) as interrupted:
            with watch._SignalLatch() as latch:
                active_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                assert active_mask == entered_mask.difference(latch.watched)
                os.kill(os.getpid(), signal.SIGTERM)
        assert interrupted.value.signum == signal.SIGTERM
        restored_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        assert restored_mask == entered_mask
    finally:
        if signal.SIGTERM in signal.sigpending():
            signal.sigwait({signal.SIGTERM})
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)


@pytest.mark.parametrize(
    ("signum", "status"),
    (
        (signal.SIGHUP, 129),
        (signal.SIGINT, 130),
        (signal.SIGQUIT, 131),
        (signal.SIGTERM, 143),
    ),
)
def test_main_maps_latched_terminal_signals_to_resume_status(
    signum: int,
    status: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        watch,
        "watch_acquisition",
        lambda **_kwargs: (_ for _ in ()).throw(watch.WatchSignalInterrupt(signum)),
    )
    assert watch.main([]) == status
    assert "resume from checkpoint" in capsys.readouterr().err


def test_stable_receipt_read_detects_path_replacement(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_read = watch.os.read
    replaced = False

    def racing_read(descriptor: int, length: int) -> bytes:
        nonlocal replaced
        content = real_read(descriptor, length)
        if content and not replaced:
            replaced = True
            replacement = acquisition.paths.checkpoint.with_suffix(".replacement")
            replacement.write_bytes(acquisition.paths.checkpoint.read_bytes())
            os.replace(replacement, acquisition.paths.checkpoint)
        return content

    monkeypatch.setattr(watch.os, "read", racing_read)
    with pytest.raises(watch.WatchError, match="changed while it was read"):
        watch._read_stable_file(
            acquisition.paths.checkpoint,
            root=acquisition.paths.lab_root,
            label="checkpoint",
        )


@pytest.mark.parametrize("replacement_kind", ("directory", "symlink"))
def test_stable_receipt_read_detects_parent_directory_replacement(
    acquisition: Fixture,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    parent = acquisition.paths.lab_root / "race-evidence"
    parent.mkdir()
    receipt = parent / "receipt.json"
    raw = b"{}"
    receipt.write_bytes(raw)
    detached = acquisition.paths.lab_root / "detached-race-evidence"
    real_read = watch.os.read
    replaced = False

    def racing_read(descriptor: int, length: int) -> bytes:
        nonlocal replaced
        content = real_read(descriptor, length)
        if content and not replaced:
            replaced = True
            parent.rename(detached)
            if replacement_kind == "symlink":
                parent.symlink_to(detached, target_is_directory=True)
            else:
                parent.mkdir()
                (parent / receipt.name).write_bytes(raw)
        return content

    monkeypatch.setattr(watch.os, "read", racing_read)

    with pytest.raises(watch.WatchError, match="changed while it was read"):
        watch._read_stable_file(
            receipt,
            root=acquisition.paths.lab_root,
            label="receipt",
        )


def test_stable_receipt_read_allows_benign_parent_child_churn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "lab"
    parent = root / "evidence"
    parent.mkdir(parents=True)
    receipt = parent / "receipt.json"
    raw = b"{}"
    receipt.write_bytes(raw)
    real_stat = os.stat
    churned = False

    def stat_after_churn(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal churned
        if not churned and path == parent.name and kwargs.get("dir_fd") is not None:
            churned = True
            transient = parent / "unrelated-child"
            transient.mkdir()
            transient.rmdir()
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(watch.os, "stat", stat_after_churn)

    observed, _sha256 = watch._read_stable_file(
        receipt,
        root=root,
        label="receipt",
    )

    assert churned
    assert observed == raw


def test_stable_receipt_read_rejects_parent_mode_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "lab"
    parent = root / "evidence"
    parent.mkdir(parents=True)
    parent.chmod(0o755)
    receipt = parent / "receipt.json"
    receipt.write_bytes(b"{}")
    real_stat = os.stat
    drifted = False

    def stat_after_mode_drift(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal drifted
        if not drifted and path == parent.name and kwargs.get("dir_fd") is not None:
            drifted = True
            os.chmod(parent, 0o700)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(watch.os, "stat", stat_after_mode_drift)

    with pytest.raises(watch.WatchError, match="changed while it was read"):
        watch._read_stable_file(
            receipt,
            root=root,
            label="receipt",
        )
    assert drifted


def test_stable_receipt_read_rejects_same_mode_parent_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "lab"
    parent = root / "evidence"
    parent.mkdir(parents=True)
    parent.chmod(0o755)
    receipt = parent / "receipt.json"
    raw = b"{}"
    receipt.write_bytes(raw)
    detached = root / "detached-evidence"
    real_stat = os.stat
    replaced = False

    def stat_after_replacement(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal replaced
        if not replaced and path == parent.name and kwargs.get("dir_fd") is not None:
            replaced = True
            parent.rename(detached)
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
            (parent / receipt.name).write_bytes(raw)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(watch.os, "stat", stat_after_replacement)

    with pytest.raises(watch.WatchError, match="changed while it was read"):
        watch._read_stable_file(
            receipt,
            root=root,
            label="receipt",
        )
    assert replaced


def test_stable_receipt_read_opens_the_final_component_nonblocking(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = watch.os.open
    final_flags: list[int] = []

    def recording_open(
        path: str | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if not flags & getattr(os, "O_DIRECTORY", 0):
            final_flags.append(flags)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(watch.os, "open", recording_open)

    watch._read_stable_file(
        acquisition.paths.checkpoint,
        root=acquisition.paths.lab_root,
        label="checkpoint",
    )

    assert len(final_flags) == 1
    assert final_flags[0] & os.O_NONBLOCK


@pytest.mark.parametrize("schema_alias", (True, 2.0))
def test_checkpoint_requires_an_exact_integer_schema(
    acquisition: Fixture,
    schema_alias: object,
) -> None:
    binding = watch._validate_immutable_binding(acquisition.paths)
    payload = _checkpoint_payload(acquisition)
    payload["checkpoint_schema_version"] = schema_alias
    _replace_checkpoint(acquisition, payload)

    with pytest.raises(watch.WatchError, match="bindings do not verify"):
        watch._validate_checkpoint(acquisition.paths, binding)


def test_host_source_validator_uses_two_identical_fixed_git_snapshots(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = watch._validate_acquisition_binding(acquisition.paths)
    calls: list[tuple[tuple[str, ...], Path | None]] = []

    def git_text(_paths, *arguments, cwd=None):
        calls.append((arguments, cwd))
        if arguments == ("rev-parse", "HEAD"):
            return (
                binding.source["neqo_commit"]
                if cwd == acquisition.paths.lab_root / "neqo-qcsd"
                else binding.source["lab_commit"]
            )
        if arguments == ("ls-files", "--stage", "--", "neqo-qcsd"):
            return f"160000 {binding.source['neqo_pinned_commit']} 0\tneqo-qcsd"
        if arguments == ("status", "--porcelain", "--untracked-files=all"):
            return ""
        raise AssertionError((arguments, cwd))

    monkeypatch.setattr(watch, "_git_text", git_text)
    monkeypatch.setattr(watch, "_verify_git_checkout_binding", lambda *_args: None)
    monkeypatch.setattr(watch, "_verify_git_index_bytes", lambda *_args: None)
    _REAL_VALIDATE_HOST_SOURCE(acquisition.paths, binding)
    assert len(calls) == 10


def test_host_source_validator_rejects_snapshot_race(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = watch._validate_acquisition_binding(acquisition.paths)
    snapshots = iter(
        (
            ("a", "b", "c", "", ""),
            ("a", "b", "c", " M raced", ""),
        )
    )
    monkeypatch.setattr(watch, "_host_source_snapshot", lambda _paths: next(snapshots))
    with pytest.raises(watch.WatchError, match="changed while source was verified"):
        _REAL_VALIDATE_HOST_SOURCE(acquisition.paths, binding)


def test_watch_git_verifier_rejects_clean_filter_bytes(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(("git", "-C", checkout, "init", "-q"), check=True)
    subprocess.run(("git", "-C", checkout, "config", "user.name", "test"), check=True)
    subprocess.run(
        ("git", "-C", checkout, "config", "user.email", "test@example.invalid"), check=True
    )
    (checkout / "payload").write_bytes(b"clean")
    (checkout / ".gitattributes").write_text("payload filter=hide\n", encoding="ascii")
    subprocess.run(("git", "-C", checkout, "add", "."), check=True)
    subprocess.run(("git", "-C", checkout, "commit", "-qm", "initial"), check=True)
    subprocess.run(
        ("git", "-C", checkout, "config", "filter.hide.clean", "printf clean"),
        check=True,
    )
    (checkout / "payload").write_bytes(b"evil!")
    assert subprocess.check_output(("git", "-C", checkout, "status", "--porcelain")) == b""
    paths = watch.WatchPaths.from_lab_root(checkout, state_base=tmp_path / "state")
    watch._verify_git_checkout_binding(paths, checkout, checkout / ".git")
    with pytest.raises(watch.WatchError, match="raw bytes"):
        watch._verify_git_index_bytes(paths, checkout)


def test_watch_git_binding_rejects_local_exclude_and_worktree_redirect(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "checkout"
    alternate = tmp_path / "alternate"
    checkout.mkdir()
    alternate.mkdir()
    subprocess.run(("git", "-C", checkout, "init", "-q"), check=True)
    paths = watch.WatchPaths.from_lab_root(checkout, state_base=tmp_path / "state")
    (checkout / ".git/info/exclude").write_text("hidden.py\n", encoding="ascii")
    with pytest.raises(watch.WatchError, match="hide checkout bytes"):
        watch._verify_git_checkout_binding(paths, checkout, checkout / ".git")
    (checkout / ".git/info/exclude").write_text("# comments only\n", encoding="ascii")
    subprocess.run(("git", "-C", checkout, "config", "core.worktree", str(alternate)), check=True)
    with pytest.raises(watch.WatchError, match="redirected worktree"):
        watch._verify_git_checkout_binding(paths, checkout, checkout / ".git")


def _scope_inventory(state_root: Path | None = None) -> tuple[set[Path], set[str]]:
    roots = set(state_root.glob("scope.*")) if state_root is not None else set()
    completed = subprocess.run(
        (
            "/usr/bin/systemctl",
            "--user",
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            "qcsd-class-watch-*.scope",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
        env=watch._safe_host_environment(),
    )
    if completed.returncode != 0:
        pytest.skip("user systemd is unavailable")
    units = {line.split()[0] for line in completed.stdout.splitlines() if line.split()}
    return roots, units


def _force_remove_test_scope_root(root: Path, *, state_root: Path) -> None:
    """Remove a test-owned inert fixture, including deliberately corrupt records."""
    assert root.parent == state_root
    token = root.name.rsplit(".", 1)[-1]
    assert re.fullmatch(r"[0-9a-f]{32}", token)
    assert watch._wait_scope_absent(
        f"qcsd-class-watch-{token}.scope", watch._safe_host_environment()
    )
    for child in root.iterdir():
        assert child.is_file() and not child.is_symlink()
        child.unlink()
    root.rmdir()


def _scope_test_state(tmp_path: Path) -> tuple[Path, int]:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path,
        state_base=tmp_path / "watch-state",
    )
    state_root = watch._ensure_state_namespace(paths)
    descriptor = watch._acquire_mutation_lock(paths.mutation_lock)
    return state_root, descriptor


def test_state_namespace_promotes_exact_interrupted_publication(tmp_path: Path) -> None:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path / "lab",
        state_base=tmp_path / "watch-state",
    )
    watch._create_private_state_directory(paths.state_base, label="test state base")
    watch._create_private_state_directory(paths.state_root, label="test state namespace")
    expected = dict(watch._state_namespace_identity(paths))
    expected["namespace_sha256"] = paths.namespace_sha256
    staged = paths.state_root / "NAMESPACE.json.next"
    staged.write_bytes(_canonical(expected))
    staged.chmod(0o600)

    assert watch._ensure_state_namespace(paths) == paths.state_root
    assert (paths.state_root / "NAMESPACE.json").read_bytes() == _canonical(expected)
    assert not staged.exists()


def test_state_namespace_removes_only_safe_stale_publication(tmp_path: Path) -> None:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path / "lab",
        state_base=tmp_path / "watch-state",
    )
    state_root = watch._ensure_state_namespace(paths)
    staged = state_root / "NAMESPACE.json.next"
    staged.write_bytes(b"interrupted publication")
    staged.chmod(0o600)

    assert watch._ensure_state_namespace(paths) == state_root
    assert not staged.exists()


def test_state_namespace_does_not_replace_unsafe_receipt_path(tmp_path: Path) -> None:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path / "lab",
        state_base=tmp_path / "watch-state",
    )
    watch._create_private_state_directory(paths.state_base, label="test state base")
    watch._create_private_state_directory(paths.state_root, label="test state namespace")
    namespace = paths.state_root / "NAMESPACE.json"
    namespace.symlink_to(tmp_path / "missing-target")

    with pytest.raises(watch.WatchError, match="private single regular file"):
        watch._ensure_state_namespace(paths)
    assert namespace.is_symlink()


@pytest.mark.parametrize("schema_alias", (True, 1.0))
def test_state_namespace_requires_an_exact_integer_schema(
    tmp_path: Path,
    schema_alias: object,
) -> None:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path / "lab",
        state_base=tmp_path / "watch-state",
    )
    watch._create_private_state_directory(paths.state_base, label="test state base")
    identity = watch._state_namespace_identity(paths)
    identity["schema_version"] = schema_alias
    namespace_sha256 = watch._sha256_bytes(watch._canonical_json_bytes(identity))
    state_root = paths.state_base / namespace_sha256
    watch._create_private_state_directory(state_root, label="test state namespace")
    receipt = {**identity, "namespace_sha256": namespace_sha256}
    namespace = state_root / "NAMESPACE.json"
    namespace.write_bytes(_canonical(receipt))
    namespace.chmod(0o600)

    with pytest.raises(watch.WatchError, match="does not verify"):
        watch._validate_state_namespace_root(state_root)


def _publish_test_scope_request(
    root: Path,
    supervision: dict[str, Any],
    *,
    wrapper_pid: int,
) -> None:
    request = {
        "action_sha256": supervision["action_sha256"],
        "artifact_type": "qcsd-class-watch-scope-request",
        "request_authority_sha256": supervision["request_authority_sha256"],
        "request_nonce": supervision["request_nonce"],
        "schema_version": 1,
        "scope_token": supervision["scope_token"],
        "scope_unit": supervision["scope_unit"],
        "source_binding_sha256": supervision["source_binding_sha256"],
        "state_namespace_sha256": supervision["state_namespace_sha256"],
        "wrapper_pid": wrapper_pid,
    }
    (root / "REQUEST").write_bytes(_canonical(request))
    (root / "REQUEST").chmod(0o600)


@pytest.mark.parametrize("schema_alias", (True, 1.0))
def test_scope_record_and_request_require_exact_integer_schemas(
    tmp_path: Path,
    schema_alias: object,
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    root, supervision, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "a" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="b" * 64,
    )
    try:
        aliased_supervision = {**supervision, "schema_version": schema_alias}
        with pytest.raises(watch.WatchError, match="malformed identity"):
            watch._validate_scope_record(
                aliased_supervision,
                recovery=False,
                root=root,
                state_root=state_root,
            )

        _publish_test_scope_request(root, supervision, wrapper_pid=os.getpid())
        request_path = root / "REQUEST"
        request = json.loads(request_path.read_text(encoding="utf-8"))
        request["schema_version"] = schema_alias
        request_path.write_bytes(_canonical(request))
        request_path.chmod(0o600)
        with pytest.raises(watch.WatchError, match="does not verify"):
            watch._read_scope_request(root, record=supervision, required=True)
    finally:
        os.close(birth_lock_fd)
        _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)


def _locked_descriptor(path: Path) -> int:
    path.write_bytes(b"")
    descriptor = os.open(path, os.O_RDWR)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return descriptor


def test_real_scope_gates_execution_authenticates_current_scope_and_leaves_no_residue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    marker = tmp_path / "action-started"
    lock_state = os.fstat(descriptor)
    lock_identity = f"{lock_state.st_dev}:{lock_state.st_ino}"
    real_publish = watch._publish_scope_go

    def publish(root: Path, *, authority: str) -> None:
        assert not marker.exists()
        record, _, recovery = watch._read_scope_record(root, state_root=state_root)
        assert recovery is False
        assert record["phase"] == "armed-for-exec"
        real_publish(root, authority=authority)

    monkeypatch.setattr(watch, "_publish_scope_go", publish)
    try:
        completed = watch._subprocess_runner(
            (
                "/usr/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                (
                    f"birth_identity=$(/usr/bin/stat -Lc '%d:%i' "
                    f'"${{{watch.SCOPE_ROOT_ENV}}}/BIRTH.lock") || exit 89; '
                    "for fd_path in /proc/$$/fd/*; do "
                    "observed=$(/usr/bin/stat -Lc '%d:%i' -- \"${fd_path}\") || exit 90; "
                    f'test "${{observed}}" != {lock_identity} || exit 91; '
                    'test "${observed}" != "${birth_identity}" || exit 92; '
                    "done; "
                    f"test ! -e /proc/$$/fd/{descriptor} && "
                    'printf started >"$1"'
                ),
                "acquisition-admission",
                str(marker),
            ),
            cwd=tmp_path,
            env={},
            authority_fd=descriptor,
            state_root=state_root,
            source_binding_sha256="a" * 64,
        )
    finally:
        os.close(descriptor)
    assert completed.returncode == 0
    assert completed.stdout == ""
    assert completed.stderr == ""
    assert marker.read_text(encoding="ascii") == "started"
    assert _scope_inventory(state_root) == before


def test_pending_signal_at_scope_decision_never_publishes_go_or_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    marker = tmp_path / "action-started"
    published = False
    real_publish = watch._publish_scope_go

    def publish(root: Path, *, authority: str) -> None:
        nonlocal published
        published = True
        real_publish(root, authority=authority)

    monkeypatch.setattr(watch, "_publish_scope_go", publish)
    monkeypatch.setattr(watch.signal, "sigpending", lambda: {signal.SIGTERM})
    try:
        with pytest.raises(watch.WatchSignalInterrupt) as interrupted:
            watch._subprocess_runner(
                (
                    "/usr/bin/bash",
                    "--noprofile",
                    "--norc",
                    "-c",
                    'printf started >"$1"',
                    "acquisition-admission",
                    str(marker),
                ),
                cwd=tmp_path,
                env={},
                authority_fd=descriptor,
                state_root=state_root,
                source_binding_sha256="a" * 64,
            )
    finally:
        os.close(descriptor)
    assert interrupted.value.signum == signal.SIGTERM
    assert published is False
    assert not marker.exists()
    assert _scope_inventory(state_root) == before


@pytest.mark.parametrize("mismatch", ("action", "source"))
def test_internal_scope_admission_rejects_expected_binding_mismatch(
    tmp_path: Path,
    mismatch: str,
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    action_value = "b" * 64 if mismatch == "action" else f"${{{watch.SCOPE_ACTION_ENV}}}"
    source_value = "b" * 64 if mismatch == "source" else f"${{{watch.SCOPE_SOURCE_ENV}}}"
    script = (
        'exec /usr/bin/python3 -I "$1" '
        "--recover-stale-scopes-internal "
        f'--state-root-internal "${{{watch.SCOPE_STATE_ROOT_ENV}}}" '
        f'--current-scope-root-internal "${{{watch.SCOPE_ROOT_ENV}}}" '
        f'--current-authority-internal "${{{watch.SCOPE_AUTHORITY_ENV}}}" '
        f'--expected-action-sha256-internal "{action_value}" '
        f'--expected-source-binding-sha256-internal "{source_value}"'
    )
    try:
        completed = watch._subprocess_runner(
            (
                "/usr/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                script,
                "acquisition-admission",
                str(Path(__file__).parents[1] / "tools/class_acquisition_watch.py"),
            ),
            cwd=tmp_path,
            env={},
            authority_fd=descriptor,
            state_root=state_root,
            source_binding_sha256="a" * 64,
        )
    finally:
        os.close(descriptor)
    assert completed.returncode == 1
    assert "scope recovery failed" in completed.stderr
    assert _scope_inventory(state_root) == before


@pytest.mark.parametrize(
    "omitted",
    ("--expected-action-sha256-internal", "--expected-source-binding-sha256-internal"),
)
def test_internal_recovery_cli_requires_both_expected_bindings(
    tmp_path: Path,
    omitted: str,
) -> None:
    arguments = [
        "--recover-stale-scopes-internal",
        "--state-root-internal",
        str(tmp_path / "state"),
        "--current-scope-root-internal",
        str(tmp_path / "scope"),
        "--current-authority-internal",
        "a" * 64,
        "--expected-action-sha256-internal",
        "b" * 64,
        "--expected-source-binding-sha256-internal",
        "c" * 64,
    ]
    index = arguments.index(omitted)
    del arguments[index : index + 2]

    assert watch.main(arguments) == 1


@pytest.mark.parametrize("redirect", (True, False), ids=("closed-stdio", "retained-stdio"))
def test_real_scope_kills_setsid_descendant_fails_and_releases_inherited_lock(
    tmp_path: Path,
    redirect: bool,
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    lock_path = state_root / "WATCH.lock"
    try:
        with pytest.raises(watch.WatchError, match="surviving cgroup descendant"):
            watch._subprocess_runner(
                (
                    "/usr/bin/bash",
                    "--noprofile",
                    "--norc",
                    "-c",
                    (
                        "/usr/bin/setsid /usr/bin/bash --noprofile --norc -c "
                        f"'{('exec >/dev/null 2>&1; ' if redirect else '')}"
                        "/usr/bin/sleep 60' & "
                        "printf 'parent-finished\\n'"
                    ),
                    "acquisition-status",
                ),
                cwd=tmp_path,
                env={},
                authority_fd=descriptor,
                state_root=state_root,
                source_binding_sha256="a" * 64,
            )
    finally:
        os.close(descriptor)

    reacquired = os.open(lock_path, os.O_RDWR)
    try:
        fcntl.flock(reacquired, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(reacquired)
    assert _scope_inventory(state_root) == before


def test_stale_durable_scope_record_is_sigkilled_recovered_and_removed(
    tmp_path: Path,
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    token = "f" * 32
    unit = f"qcsd-class-watch-{token}.scope"
    root, supervision, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit=unit,
        command=("/usr/bin/sleep", "60", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    stale = dict(supervision)
    stale.update(
        {
            "supervisor_pid": 999_999_999,
            "supervisor_start_time": 1,
            "supervisor_session": 1,
            "supervisor_process_group": 1,
        }
    )
    environment = watch._safe_host_environment()
    process = subprocess.Popen(
        (
            "/usr/bin/systemd-run",
            "--user",
            "--scope",
            "--collect",
            "--quiet",
            "--expand-environment=no",
            f"--unit={unit}",
            "--property=KillMode=control-group",
            "--property=KillSignal=SIGKILL",
            "--",
            "/usr/bin/sleep",
            "60",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        start_new_session=True,
    )
    try:
        deadline = watch.time.monotonic() + 5
        while watch.time.monotonic() < deadline:
            state = watch._scope_state(unit, environment)
            if state.processes:
                break
            watch.time.sleep(0.05)
        else:
            pytest.fail("test scope did not become populated")
        wrapper_pid = next(pid for pid in state.processes if pid > 0)
        _publish_test_scope_request(root, stale, wrapper_pid=wrapper_pid)
        wrapper_process = watch._process_identity(wrapper_pid)
        assert wrapper_process is not None
        start_time, session, process_group = wrapper_process
        armed = watch._replace_scope_phase(
            root,
            stale,
            phase="request-authorised",
            wrapper_identity=(wrapper_pid, start_time, session, process_group),
            state_root=state_root,
        )
        watch._replace_scope_phase(
            root,
            armed,
            phase="armed-for-exec",
            wrapper_identity=(wrapper_pid, start_time, session, process_group),
            state_root=state_root,
        )

        assert watch._recover_stale_scope_roots(state_root=state_root) == 1
        process.communicate(timeout=5)
    finally:
        if process.poll() is None:
            subprocess.run(
                (
                    "/usr/bin/systemctl",
                    "--user",
                    "kill",
                    "--kill-whom=all",
                    "--signal=SIGKILL",
                    "--",
                    unit,
                ),
                env=environment,
                check=False,
                timeout=5,
            )
            process.kill()
            process.communicate(timeout=5)
        os.close(descriptor)
    assert not root.exists()
    assert _scope_inventory(state_root) == before


def test_sigkill_supervisor_releases_lock_and_restart_recovers_live_scope(
    tmp_path: Path,
) -> None:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path,
        state_base=tmp_path / "watch-state",
    )
    state_root = watch._ensure_state_namespace(paths)
    before = _scope_inventory(state_root)
    marker = tmp_path / "action-started"
    repository = Path(__file__).parents[1]
    child_program = """
import os
import sys
from pathlib import Path
from tools import class_acquisition_watch as watch

paths = watch.WatchPaths.from_lab_root(Path(sys.argv[1]), state_base=Path(sys.argv[2]))
state_root = watch._ensure_state_namespace(paths)
descriptor = watch._acquire_mutation_lock(paths.mutation_lock)
command = (
    "/usr/bin/bash", "--noprofile", "--norc", "-c",
    f"printf started > {sys.argv[3]}; /usr/bin/sleep 60",
    "acquisition-status",
)
try:
    watch._subprocess_runner(
        command,
        cwd=Path(sys.argv[1]),
        env={},
        authority_fd=descriptor,
        state_root=state_root,
        source_binding_sha256="a" * 64,
    )
finally:
    os.close(descriptor)
"""
    supervisor = subprocess.Popen(
        (
            sys.executable,
            "-c",
            child_program,
            str(tmp_path),
            str(paths.state_base),
            str(marker),
        ),
        cwd=repository,
        env=watch._safe_host_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    recovered_descriptor: int | None = None
    environment = watch._safe_host_environment()
    try:
        deadline = watch.time.monotonic() + 10
        scope_root: Path | None = None
        while watch.time.monotonic() < deadline:
            roots = list(state_root.glob("scope.*"))
            if len(roots) == 1 and marker.exists():
                record, _, recovery = watch._read_scope_record(
                    roots[0],
                    state_root=state_root,
                )
                if not recovery and record["phase"] == "armed-for-exec":
                    scope_root = roots[0]
                    break
            watch.time.sleep(0.05)
        assert scope_root is not None, "supervised action did not become armed"

        supervisor.kill()
        assert supervisor.wait(timeout=5) == -signal.SIGKILL

        # The scoped action never inherited this supervisory lock, so a new
        # watcher can acquire it immediately and recover the still-live unit.
        recovered_descriptor = watch._acquire_mutation_lock(paths.mutation_lock)
        assert watch._recover_stale_scope_roots(state_root=state_root) == 1
        assert not scope_root.exists()
    finally:
        if supervisor.poll() is None:
            supervisor.kill()
            supervisor.wait(timeout=5)
        for scope_root in list(state_root.glob("scope.*")):
            token = scope_root.name.rsplit(".", 1)[1]
            unit = f"qcsd-class-watch-{token}.scope"
            subprocess.run(
                (
                    "/usr/bin/systemctl",
                    "--user",
                    "kill",
                    "--kill-whom=all",
                    "--signal=SIGKILL",
                    "--",
                    unit,
                ),
                env=environment,
                check=False,
                timeout=5,
            )
            watch._wait_scope_empty(
                unit,
                environment,
                deadline=watch.time.monotonic() + 5,
            )
            if scope_root.exists():
                _force_remove_test_scope_root(scope_root, state_root=state_root)
        if recovered_descriptor is not None:
            os.close(recovered_descriptor)
    assert _scope_inventory(state_root) == before


@pytest.mark.parametrize(
    "interruption_phase",
    ("after-popen-before-request", "request-authorised", "armed-for-exec"),
)
def test_sigkill_handshake_restart_closes_delayed_scope_birth(
    tmp_path: Path,
    interruption_phase: str,
) -> None:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path,
        state_base=tmp_path / "watch-state",
    )
    state_root = watch._ensure_state_namespace(paths)
    before = _scope_inventory(state_root)
    marker = tmp_path / "interruption-point"
    repository = Path(__file__).parents[1]
    child_program = r"""
import os
import subprocess
import sys
import time
from pathlib import Path
from tools import class_acquisition_watch as watch

paths = watch.WatchPaths.from_lab_root(Path(sys.argv[1]), state_base=Path(sys.argv[2]))
state_root = watch._ensure_state_namespace(paths)
descriptor = watch._acquire_mutation_lock(paths.mutation_lock)
marker = Path(sys.argv[3])
phase = sys.argv[4]
if phase == "after-popen-before-request":
    watch._SCOPE_WRAPPER = (
        "/usr/bin/sleep 1\n" + watch._SCOPE_WRAPPER.replace("{1..300}", "{1..20}")
    )
    real_popen = subprocess.Popen
    def delayed_popen(command, **kwargs):
        process = real_popen(command, **kwargs)
        if isinstance(command, tuple) and watch._HOST_SCOPE_LAUNCHER in command:
            marker.write_text("after-popen-before-request", encoding="ascii")
        return process
    watch.subprocess.Popen = delayed_popen
else:
    watch._SCOPE_WRAPPER = watch._SCOPE_WRAPPER.replace("{1..300}", "{1..100}")
    real_replace = watch._replace_scope_phase
    def delayed_phase(root, supervision, *, phase: str, wrapper_identity, state_root):
        updated = real_replace(
            root,
            supervision,
            phase=phase,
            wrapper_identity=wrapper_identity,
            state_root=state_root,
        )
        if phase == sys.argv[4]:
            marker.write_text(phase, encoding="ascii")
            time.sleep(60)
        return updated
    watch._replace_scope_phase = delayed_phase
command = (
    "/usr/bin/bash", "--noprofile", "--norc", "-c", "/usr/bin/sleep 60",
    "acquisition-status",
)
try:
    watch._subprocess_runner(
        command,
        cwd=Path(sys.argv[1]),
        env={},
        authority_fd=descriptor,
        state_root=state_root,
        source_binding_sha256="a" * 64,
    )
finally:
    os.close(descriptor)
"""
    supervisor = subprocess.Popen(
        (
            sys.executable,
            "-c",
            child_program,
            str(tmp_path),
            str(paths.state_base),
            str(marker),
            interruption_phase,
        ),
        cwd=repository,
        env=watch._safe_host_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    recovered_descriptor: int | None = None
    environment = watch._safe_host_environment()
    try:
        deadline = watch.time.monotonic() + 10
        scope_root: Path | None = None
        while watch.time.monotonic() < deadline:
            roots = list(state_root.glob("scope.*"))
            if len(roots) == 1 and marker.exists():
                scope_root = roots[0]
                if interruption_phase == "after-popen-before-request":
                    assert not (scope_root / "REQUEST").exists()
                break
            if supervisor.poll() is not None:
                pytest.fail("test supervisor exited before the requested interruption")
            watch.time.sleep(0.05)
        assert scope_root is not None, "supervisor did not reach the interruption point"

        supervisor.kill()
        assert supervisor.wait(timeout=5) == -signal.SIGKILL
        recovered_descriptor = watch._acquire_mutation_lock(paths.mutation_lock)
        assert watch._recover_stale_scope_roots(state_root=state_root) == 1
        watch.time.sleep(0.2)
        assert not scope_root.exists()
    finally:
        if supervisor.poll() is None:
            supervisor.kill()
            supervisor.wait(timeout=5)
        for scope_root in list(state_root.glob("scope.*")):
            token = scope_root.name.rsplit(".", 1)[1]
            unit = f"qcsd-class-watch-{token}.scope"
            subprocess.run(
                (
                    "/usr/bin/systemctl",
                    "--user",
                    "kill",
                    "--kill-whom=all",
                    "--signal=SIGKILL",
                    "--",
                    unit,
                ),
                env=environment,
                check=False,
                timeout=5,
            )
            watch._wait_scope_empty(
                unit,
                environment,
                deadline=watch.time.monotonic() + 5,
            )
            try:
                birth_fd = watch._wait_scope_birth_lock(
                    scope_root,
                    record=None,
                    deadline=watch.time.monotonic() + 5,
                )
            except watch.WatchError:
                birth_fd = None
            if birth_fd is not None:
                os.close(birth_fd)
            if scope_root.exists():
                _force_remove_test_scope_root(scope_root, state_root=state_root)
        if recovered_descriptor is not None:
            os.close(recovered_descriptor)
    assert _scope_inventory(state_root) == before


def test_prelaunch_scope_publication_failure_removes_staged_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    real_replace = watch.os.replace
    calls = 0

    def replace(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected directory publication failure")
        return real_replace(source, destination)

    monkeypatch.setattr(watch.os, "replace", replace)
    try:
        with pytest.raises(watch.WatchError, match="durable acquisition scope root"):
            watch._create_scope_root(
                state_root=state_root,
                unit="qcsd-class-watch-" + "e" * 32 + ".scope",
                command=("ignored", "acquisition-status"),
                authority_fd=descriptor,
                source_binding_sha256="a" * 64,
            )
    finally:
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_unpublished_prelaunch_root_is_recovered_without_a_unit(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    token = "a" * 32
    root = state_root / f"scope.next.{token}"
    root.mkdir(mode=0o700)
    try:
        assert watch._recover_stale_scope_roots(state_root=state_root) == 1
    finally:
        if root.exists():
            _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_staged_prelaunch_record_is_recovered_without_a_unit(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    token = "9" * 32
    root = state_root / f"scope.next.{token}"
    root.mkdir(mode=0o700)
    (root / "SUPERVISION.next").write_bytes(b"interrupted pre-publication write")
    (root / "SUPERVISION.next").chmod(0o600)
    try:
        assert watch._recover_stale_scope_roots(state_root=state_root) == 1
    finally:
        if root.exists():
            _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_final_scope_root_without_durable_record_fails_closed(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    root = state_root / ("scope." + "8" * 32)
    root.mkdir(mode=0o700)
    (root / "SUPERVISION.next").write_bytes(b"interrupted write")
    (root / "SUPERVISION.next").chmod(0o600)
    try:
        with pytest.raises(watch.WatchError, match="no durable lifecycle record"):
            watch._recover_stale_scope_roots(state_root=state_root)
    finally:
        _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_stale_atomic_write_remnant_does_not_block_scope_recovery(
    tmp_path: Path,
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    root, supervision, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "c" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    stale = dict(supervision)
    stale.update(
        {
            "supervisor_pid": 999_999_999,
            "supervisor_start_time": 1,
            "supervisor_session": 1,
            "supervisor_process_group": 1,
        }
    )
    watch._atomic_scope_record(root / "SUPERVISION", stale)
    staged = root / "SUPERVISION.next"
    staged.write_bytes(b"interrupted atomic write")
    staged.chmod(0o600)
    try:
        assert watch._recover_stale_scope_roots(state_root=state_root) == 1
    finally:
        if root.exists():
            _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_recovery_validates_every_root_before_mutating_any_root(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    first, supervision, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "1" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    stale = dict(supervision)
    stale.update(
        {
            "supervisor_pid": 999_999_999,
            "supervisor_start_time": 1,
            "supervisor_session": 1,
            "supervisor_process_group": 1,
        }
    )
    watch._atomic_scope_record(first / "SUPERVISION", stale)
    first_before = (first / "SUPERVISION").read_bytes()
    malformed = state_root / ("scope." + "2" * 32)
    malformed.mkdir(mode=0o700)
    (malformed / "SUPERVISION").write_bytes(b"not canonical JSON\n")
    (malformed / "SUPERVISION").chmod(0o600)
    try:
        with pytest.raises(watch.WatchError, match="malformed"):
            watch._recover_stale_scope_roots(state_root=state_root)
        assert first.exists()
        assert (first / "SUPERVISION").read_bytes() == first_before
        assert not (first / "RECOVERY").exists()
    finally:
        for root in (first, malformed):
            if root.exists():
                _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_scope_record_token_unit_and_root_are_structurally_bound(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    root, _, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "3" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    mismatched = state_root / ("scope." + "4" * 32)
    root.rename(mismatched)
    try:
        with pytest.raises(watch.WatchError, match="malformed identity"):
            watch._recover_stale_scope_roots(state_root=state_root)
    finally:
        _force_remove_test_scope_root(mismatched, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_scope_record_is_bound_to_exact_watch_lock_inode(tmp_path: Path) -> None:
    state_root, original_descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    root, supervision, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "5" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=original_descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    stale = dict(supervision)
    stale.update(
        {
            "supervisor_pid": 999_999_999,
            "supervisor_start_time": 1,
            "supervisor_session": 1,
            "supervisor_process_group": 1,
        }
    )
    watch._atomic_scope_record(root / "SUPERVISION", stale)
    replacement = state_root / "WATCH.lock.replacement"
    replacement.write_bytes(b"")
    replacement.chmod(0o600)
    os.replace(replacement, state_root / "WATCH.lock")
    replacement_descriptor = watch._acquire_mutation_lock(state_root / "WATCH.lock")
    try:
        with pytest.raises(watch.WatchError, match="another supervisor lock"):
            watch._recover_stale_scope_roots(state_root=state_root)
    finally:
        _force_remove_test_scope_root(root, state_root=state_root)
        os.close(replacement_descriptor)
        os.close(original_descriptor)
    assert _scope_inventory(state_root) == before


def test_scope_record_is_bound_to_exact_birth_lock_inode(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    root, supervision, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "6" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    stale = dict(supervision)
    stale.update(
        {
            "supervisor_pid": 999_999_999,
            "supervisor_start_time": 1,
            "supervisor_session": 1,
            "supervisor_process_group": 1,
        }
    )
    watch._atomic_scope_record(root / "SUPERVISION", stale)
    replacement = root / "replacement"
    replacement.write_bytes(b"")
    replacement.chmod(0o600)
    os.replace(replacement, root / "BIRTH.lock")
    try:
        with pytest.raises(watch.WatchError, match="birth lock identity"):
            watch._recover_stale_scope_roots(state_root=state_root)
        assert (root / "SUPERVISION").exists()
        assert not (root / "RECOVERY").exists()
    finally:
        _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_live_scope_supervision_record_blocks_unrelated_recovery(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    root, _, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "b" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    try:
        with pytest.raises(watch.WatchError, match="another live acquisition scope"):
            watch._recover_stale_scope_roots(state_root=state_root)
    finally:
        _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_subprocess_runner_latches_signal_without_async_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor = _locked_descriptor(tmp_path / "lock")

    def scoped(
        command,
        *,
        cwd,
        env,
        authority_fd,
        state_root,
        source_binding_sha256,
        latch,
    ):
        assert authority_fd == descriptor
        assert state_root == tmp_path
        assert source_binding_sha256 == "a" * 64
        handler = signal.getsignal(signal.SIGQUIT)
        assert callable(handler)
        handler(signal.SIGQUIT, None)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(watch, "_scope_completed", scoped)
    try:
        with pytest.raises(watch.WatchSignalInterrupt) as interrupted:
            watch._subprocess_runner(
                ("ignored", "acquisition-status"),
                cwd=tmp_path,
                env={},
                authority_fd=descriptor,
                state_root=tmp_path,
                source_binding_sha256="a" * 64,
            )
    finally:
        os.close(descriptor)
    assert interrupted.value.signum == signal.SIGQUIT


def test_scope_state_fails_closed_when_kernel_cgroup_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit = "qcsd-class-watch-" + "d" * 32 + ".scope"
    monkeypatch.setattr(
        watch,
        "_systemctl",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            (),
            0,
            (
                "LoadState=loaded\n"
                "ActiveState=active\n"
                "SubState=running\n"
                f"ControlGroup=/definitely-missing/{unit}\n"
            ),
            "",
        ),
    )
    with pytest.raises(watch.WatchError, match="kernel path is unavailable"):
        watch._scope_state(unit, watch._safe_host_environment())


def test_qcsd_admission_rejects_extra_arguments_before_docker() -> None:
    root = Path(__file__).parents[1]
    completed = subprocess.run(
        (
            str(root / "qcsd-lab"),
            "class-study",
            "acquisition-admission",
            "unexpected",
        ),
        cwd=root,
        env=watch._safe_host_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 2
    assert "rejects unsupported argument" in completed.stderr


@pytest.mark.parametrize("omitted", ("all", watch.SCOPE_ACTION_ENV, watch.SCOPE_SOURCE_ENV))
def test_qcsd_admission_requires_complete_scope_authority_before_docker(
    tmp_path: Path,
    omitted: str,
) -> None:
    root = Path(__file__).parents[1]
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    marker = tmp_path / "docker-was-called"
    docker.write_text(f"#!/bin/sh\n: > {marker}\nexit 97\n", encoding="utf-8")
    docker.chmod(0o755)
    environment = watch._safe_host_environment()
    environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"
    if omitted != "all":
        environment.update(
            {
                watch.SCOPE_STATE_ROOT_ENV: str(tmp_path / "state"),
                watch.SCOPE_ROOT_ENV: str(tmp_path / "scope"),
                watch.SCOPE_AUTHORITY_ENV: "a" * 64,
                watch.SCOPE_ACTION_ENV: "b" * 64,
                watch.SCOPE_SOURCE_ENV: "c" * 64,
            }
        )
        del environment[omitted]

    completed = subprocess.run(
        (
            str(root / "qcsd-lab"),
            "class-study",
            "acquisition-admission",
        ),
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 1
    assert "requires scoped request authority" in completed.stderr
    assert not marker.exists()


def test_qcsd_rejects_cross_action_scope_digest_before_recovery_or_docker(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parents[1]
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    marker = tmp_path / "docker-was-called"
    docker.write_text(f"#!/bin/sh\n: > {marker}\nexit 97\n", encoding="utf-8")
    docker.chmod(0o755)
    paths = watch.WatchPaths.from_lab_root(root)
    replayed_digest = watch._sha256_bytes(
        watch._canonical_json_bytes(list(watch._status_command(paths)))
    )
    environment = watch._safe_host_environment()
    environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"
    environment.update(
        {
            watch.SCOPE_STATE_ROOT_ENV: str(tmp_path / "state"),
            watch.SCOPE_ROOT_ENV: str(tmp_path / "scope"),
            watch.SCOPE_AUTHORITY_ENV: "a" * 64,
            watch.SCOPE_ACTION_ENV: replayed_digest,
            watch.SCOPE_SOURCE_ENV: "c" * 64,
        }
    )

    completed = subprocess.run(
        (
            str(root / "qcsd-lab"),
            "class-study",
            "acquisition-admission",
        ),
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 1
    assert "scoped request action does not match current argv" in completed.stderr
    assert "could not validate scoped watcher authority" not in completed.stderr
    assert not marker.exists()


@pytest.mark.parametrize(
    ("action", "arguments"),
    (
        (
            "acquisition-run",
            ("--acquisition-max-candidates", "2", "--acquisition-timeout-ms", "60000"),
        ),
        ("acquisition-run", ("--acquisition-max-candidates", "1")),
        ("acquisition-run", ()),
        ("acquisition-status", ()),
    ),
)
def test_direct_qcsd_acquisition_action_has_no_watcher_authority_before_docker(
    tmp_path: Path,
    action: str,
    arguments: tuple[str, ...],
) -> None:
    root = Path(__file__).parents[1]
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    marker = tmp_path / "docker-was-called"
    docker.write_text(f"#!/bin/sh\n: > {marker}\nexit 97\n", encoding="utf-8")
    docker.chmod(0o755)
    environment = watch._safe_host_environment()
    environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"

    completed = subprocess.run(
        (
            str(root / "qcsd-lab"),
            "class-study",
            action,
            *arguments,
        ),
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 1
    assert f"class-study {action} requires scoped request authority" in completed.stderr
    assert not marker.exists()


@pytest.mark.parametrize("value", ("0", "3", "true"))
def test_direct_qcsd_rejects_unbounded_acquisition_batch_before_authority_or_docker(
    tmp_path: Path,
    value: str,
) -> None:
    root = Path(__file__).parents[1]
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "docker-was-called"
    docker = fake_bin / "docker"
    docker.write_text(f"#!/bin/sh\n: > {marker}\nexit 97\n", encoding="utf-8")
    docker.chmod(0o755)
    environment = watch._safe_host_environment()
    environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"

    completed = subprocess.run(
        (
            str(root / "qcsd-lab"),
            "class-study",
            "acquisition-run",
            "--acquisition-max-candidates",
            value,
        ),
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 2
    assert "accepts at most two candidates per action" in completed.stderr
    assert not marker.exists()


def test_watcher_has_no_direct_docker_discovery_or_cleanup() -> None:
    source = (Path(__file__).parents[1] / "tools/class_acquisition_watch.py").read_text(
        encoding="utf-8"
    )
    assert 'subprocess.run(("docker"' not in source
    assert "container inspect" not in source
    assert "container rm" not in source
    assert "_cleanup_orphan_container" not in source
    assert "acquisition-admission" in source


def test_acquisition_run_has_nested_truthful_action_deadlines() -> None:
    from qcsd_lab.acquisition_timing import (
        ACTION_TIMING_CONTRACT,
        BASELINE_SCHEDULING_CONTRACT,
    )

    watcher_source = (Path(__file__).parents[1] / "tools/class_acquisition_watch.py").read_text(
        encoding="utf-8"
    )
    launcher_source = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    assert "MAX_CANDIDATES = 2" in watcher_source
    assert "GLOBAL_LIVE_PAGE_CAP = 5" in watcher_source
    assert 'kill_signal = "SIGINT" if graceful_run else "SIGKILL"' in watcher_source
    assert "ACQUISITION_ACTION_TIMEOUT_SECONDS = 1_800" in watcher_source
    assert "ACQUISITION_ACTION_CLEANUP_SECONDS = 120" in watcher_source
    assert watch.RUN_RUNTIME_SECONDS == 1_920
    assert watch.ACQUISITION_OUTER_HARD_SECONDS == 2_040
    assert watch.MINIMUM_BASELINE_SPACING_SECONDS == 2_400
    assert (
        watch._ACQUISITION_ACTION_TIMING_CONTRACT["direct_public_acquisition_run"]
        == "forbidden-without-validated-watcher-scope-authority"
    )
    assert (
        watch._ACQUISITION_ACTION_TIMING_CONTRACT["successful_ledger_attempt_duration_limit_ms"]
        == 1_800_000
    )
    assert (
        watch._ACQUISITION_ACTION_TIMING_CONTRACT["whole_action_duration_evidence"]
        == "externally-enforced-process-status-no-per-action-duration-receipt"
    )
    assert watch._ACQUISITION_ACTION_TIMING_CONTRACT == ACTION_TIMING_CONTRACT
    assert watch._BASELINE_SCHEDULING_CONTRACT == BASELINE_SCHEDULING_CONTRACT
    assert watch._BASELINE_SCHEDULING_CONTRACT == {
        "schema_version": 2,
        "policy": "serial-nonoverlapping-stability-window-batch-reservations-v2",
        "maximum_candidates_per_batch": 2,
        "global_live_page_cap": 5,
        "minimum_baseline_spacing_ms": 2_400_000,
        "window_start_reservation_ms": 2_400_000,
        "longest_probe_window_width_ms": 1_800_000,
        "acquisition_outer_configured_hard_cutoff_ms": 2_040_000,
        "status_configured_hard_cutoff_ms": 310_000,
        "scheduler_margin_ms": 50_000,
        "navigation_phase": "separate-bounded-action-before-baseline",
        "short_probe": "same-action-wait-until-t+30s-earliest",
        "outer_probes": "watcher-launches-acquisition-run-at-window-earliest",
        "within_batch_baseline": "one-equal-baseline-per-recorded-baseline-batch",
        "schedule_validation_unit": "baseline-batches-not-raw-candidate-timestamps",
        "unpaired_candidate_policy": "singleton-when-no-compatible-partner",
        "serial_action_start_offsets_ms": [0, 85_500_000, 258_300_000],
        "stability_window_earliest_offsets_ms": [
            25_000,
            85_500_000,
            258_300_000,
        ],
        "collision_scope": ("baseline-arming-and-t+24h-t+72h-action-starts-across-batches"),
        "strict_serial_zero_duration_projection": {
            "candidate_count": 600,
            "maximum_candidates_per_batch": 2,
            "batch_count": 300,
            "algorithm": "greedy-earliest-safe-baseline-batches",
            "pairing_assumption": ("all-candidates-form-300-compatible-two-candidate-batches"),
            "last_baseline_offset_ms": 2_784_000_000,
            "last_t+72h_earliest_offset_ms": 3_042_300_000,
        },
    }
    assert "-- /usr/bin/timeout --signal=INT --kill-after=120s 1800s" in launcher_source
    assert "accepts at most two candidates per action" in launcher_source


@pytest.mark.parametrize(
    "fault_label",
    (
        "acquisition scope output removal",
        "acquisition scope birth-lock removal",
        "acquisition scope recovery-record removal",
        "acquisition scope root removal",
    ),
)
def test_scope_teardown_crash_boundaries_are_restart_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault_label: str
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    root, supervision, birth_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "d" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    (root / "stdout").write_text("complete", encoding="ascii")
    (root / "stdout").chmod(0o600)
    recovery = watch._publish_scope_recovery(root, supervision, state_root=state_root)
    real_fsync = watch._fsync_scope_directory
    faulted = False

    def inject(path: Path, *, label: str) -> None:
        nonlocal faulted
        real_fsync(path, label=label)
        if not faulted and label == fault_label:
            faulted = True
            raise watch.WatchError("injected teardown crash")

    monkeypatch.setattr(watch, "_fsync_scope_directory", inject)
    try:
        with pytest.raises(watch.WatchError, match="injected teardown crash"):
            watch._finish_scope_teardown(
                root,
                state_root=state_root,
                recovery=recovery,
                birth_lock_fd=birth_fd,
            )
    finally:
        os.close(birth_fd)
    assert faulted
    monkeypatch.setattr(watch, "_fsync_scope_directory", real_fsync)
    expected_recovered = 1 if root.exists() else 0
    assert watch._recover_stale_scope_roots(state_root=state_root) == expected_recovered
    assert not root.exists()
    os.close(descriptor)


@pytest.mark.parametrize(
    "command_kind",
    ("admission", "browser-egress-verify", "status", "run"),
)
def test_internal_scope_accepts_each_current_canonical_action_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command_kind: str,
) -> None:
    paths = watch.WatchPaths.from_lab_root(tmp_path, state_base=tmp_path / "state")
    binding = watch.AcquisitionBinding(
        prepare_image="image@sha256:" + "1" * 64,
        cohort_version=23,
        catalogue_sha256="2" * 64,
        provenance_sha256="3" * 64,
        foundation_sha256="6" * 64,
        acquisition_authority_path="/lab/artifacts/class-study-foundation-v23.json",
        acquisition_authority_sha256="6" * 64,
        pinned_cdp_sha256="7" * 64,
        pinned_cdp_payload_sha256="8" * 64,
        pinned_cdp_contract_sha256="9" * 64,
        build_execution_sha256="a" * 64,
        build_completion_path="/lab/artifacts/buflo-study/build-completion-v23.json",
        build_completion_sha256="c" * 64,
        browser_egress_qualification={
            "root": "/lab/artifacts/buflo-study/browser-egress-qualification-v23",
            "build_execution": {"path": "/lab/artifacts/buflo-study/build-execution-v23.json"},
        },
        browser_egress_tree_sha256="b" * 64,
        candidate_ids=frozenset(),
        candidate_order=(),
        source={
            "lab_commit": "4" * 40,
            "neqo_commit": "5" * 40,
            "neqo_pinned_commit": "5" * 40,
        },
    )
    commands = {
        "admission": watch._admission_command(paths),
        "browser-egress-verify": watch._browser_egress_verify_command(paths, binding),
        "status": watch._status_command(paths),
        "run": watch._run_command(paths),
    }
    action = watch._sha256_bytes(watch._canonical_json_bytes(list(commands[command_kind])))
    source = watch._source_binding_sha256(binding)
    monkeypatch.setattr(watch, "_paths_from_state_namespace", lambda _root: paths)
    monkeypatch.setattr(watch, "_validate_immutable_binding", lambda _paths: binding)
    monkeypatch.setattr(watch, "_validate_host_source", lambda *_args: None)
    monkeypatch.setattr(watch, "_validate_scope_root", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(watch, "_recover_stale_scope_roots", lambda **_kwargs: 0)
    assert (
        watch.main(
            (
                "--recover-stale-scopes-internal",
                "--state-root-internal",
                str(paths.state_root),
                "--current-scope-root-internal",
                str(paths.state_root / ("scope." + "e" * 32)),
                "--current-authority-internal",
                "6" * 64,
                "--expected-action-sha256-internal",
                action,
                "--expected-source-binding-sha256-internal",
                source,
            )
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {"recovered_scope_roots": 0}


def test_recorded_watch_lock_holder_must_be_exact_supervisor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    root, supervision, birth_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "f" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    other = subprocess.Popen(("/usr/bin/sleep", "10"))
    duplicate = os.dup(descriptor)
    independent = os.open(state_root / "WATCH.lock", os.O_RDWR | os.O_CLOEXEC)
    try:
        original_read_text = Path.read_text

        def reject_global_lock_table(path: Path, *args: Any, **kwargs: Any) -> str:
            if path == Path("/proc/locks"):
                raise AssertionError("global lock-table proof is race-prone")
            return original_read_text(path, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", reject_global_lock_table)
        watch._assert_recorded_watch_lock_holder(state_root, supervision)

        def corrupt_fdinfo_ordinal(path: Path, *args: Any, **kwargs: Any) -> str:
            value = reject_global_lock_table(path, *args, **kwargs)
            if path == Path(f"/proc/{os.getpid()}/fdinfo/{descriptor}"):
                return re.sub(
                    r"^(lock:\s+)[1-9][0-9]*:",
                    r"\g<1>0:",
                    value,
                    count=1,
                    flags=re.MULTILINE,
                )
            return value

        monkeypatch.setattr(Path, "read_text", corrupt_fdinfo_ordinal)
        with pytest.raises(
            watch.WatchError,
            match="lock descriptor is invalid",
        ):
            watch._assert_recorded_watch_lock_holder(state_root, supervision)
        identity = watch._process_identity(other.pid)
        assert identity is not None
        forged = dict(supervision)
        forged.update(
            supervisor_pid=other.pid,
            supervisor_start_time=identity[0],
            supervisor_session=identity[1],
            supervisor_process_group=identity[2],
        )
        with pytest.raises(watch.WatchError, match="does not hold the exact watch lock"):
            watch._assert_recorded_watch_lock_holder(state_root, forged)
    finally:
        os.close(independent)
        os.close(duplicate)
        other.terminate()
        other.wait(timeout=5)
        os.close(birth_fd)
        _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
