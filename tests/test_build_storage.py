from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from qcsd_lab import build_storage, cohort_allocation


GIB = 1024**3
PROBE_SHA256 = "1" * 64
VOLUME_ID = "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\"
DATA_VHD_PATH = "C:\\Users\\qcsd-test-user\\AppData\\Local\\Docker\\wsl\\data\\ext4.vhdx"
BOUNDARY_TIMES = (
    ("before-collection", "2026-09-01T00:00:00+00:00"),
    ("before-prepare", "2026-09-01T00:00:02+00:00"),
    ("before-reference", "2026-09-01T00:00:03+00:00"),
    ("after-reference", "2026-09-01T00:00:04+00:00"),
)


def test_isolated_cohort_allocator_fallback_is_cached_as_one_class_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The isolated CLI must not manufacture two incompatible dataclasses."""

    monkeypatch.setattr(build_storage, "_COHORT_ALLOCATION_MODULE", None)
    monkeypatch.setitem(sys.modules, "qcsd_lab", None)

    first = build_storage._cohort_allocation_module()
    second = build_storage._cohort_allocation_module()
    authority = first.GuardianLockAuthority(
        owner_pid=1,
        owner_start=1,
        guardian_pid=1,
        guardian_start=1,
        guardian_fd=3,
        path="/registry/.allocation.lock",
        device=1,
        inode=1,
        parent_device=1,
        parent_inode=2,
        cohort_version=1,
    )

    assert second is first
    assert isinstance(authority, second.GuardianLockAuthority)


def _run_test_git(root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(root),
            *arguments,
        ],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return completed.stdout


def _canonical_digest(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _rehash(value: dict[str, Any]) -> dict[str, Any]:
    value.pop("payload_sha256", None)
    value["payload_sha256"] = _canonical_digest(value)
    return value


def _rehash_buildx_receipt(value: dict[str, Any]) -> dict[str, Any]:
    identity_sha256 = _canonical_digest(value["buildx"]["identity"])
    for observation in value["buildx"]["observations"]:
        observation["identity_sha256"] = identity_sha256
    return _rehash(value)


def _consumed_cohort_payload(
    *,
    consumed_versions: list[int] | None = None,
) -> bytes:
    value = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-consumed-cohorts",
        "policy": "dense-prefix-durable-publications-consume-v1",
        "consumed_versions": (
            list(range(1, 34)) if consumed_versions is None else consumed_versions
        ),
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _git_blob_oid(payload: bytes, *, object_format: str = "sha1") -> str:
    digest = hashlib.new(object_format)
    digest.update(b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload)
    return digest.hexdigest()


def _git_object_oid(
    object_type: bytes,
    payload: bytes,
    *,
    object_format: str = "sha1",
) -> str:
    digest = hashlib.new(object_format)
    digest.update(object_type + b" " + str(len(payload)).encode("ascii") + b"\0")
    digest.update(payload)
    return digest.hexdigest()


def _git_tree_payload(entries: list[tuple[bytes, bytes, str]]) -> bytes:
    ordered = sorted(
        entries,
        key=lambda entry: entry[1] + (b"/" if entry[0] == b"40000" else b""),
    )
    return b"".join(
        mode + b" " + name + b"\0" + bytes.fromhex(oid)
        for mode, name, oid in ordered
    )


def _cohort_git_proof(
    *,
    ledger_blob_oid: str,
    neqo_gitlink: str,
    ledger_name: bytes = b"consumed-cohorts.json",
    ledger_mode: bytes = b"100644",
    ledger_entry_oid: str | None = None,
    directory_modes: tuple[bytes, bytes, bytes] = (b"40000", b"40000", b"40000"),
    gitlink_mode: bytes = b"160000",
    gitlink_entry_oid: str | None = None,
) -> tuple[str, dict[str, Any]]:
    v1_tree = _git_tree_payload(
        [(ledger_mode, ledger_name, ledger_entry_oid or ledger_blob_oid)]
    )
    study_tree = _git_tree_payload(
        [(directory_modes[2], b"v1", _git_object_oid(b"tree", v1_tree))]
    )
    config_tree = _git_tree_payload(
        [
            (
                directory_modes[1],
                b"buflo-study",
                _git_object_oid(b"tree", study_tree),
            )
        ]
    )
    root_tree = _git_tree_payload(
        [
            (directory_modes[0], b"config", _git_object_oid(b"tree", config_tree)),
            (gitlink_mode, b"neqo-qcsd", gitlink_entry_oid or neqo_gitlink),
        ]
    )
    root_oid = _git_object_oid(b"tree", root_tree)
    commit_payload = (
        f"tree {root_oid}\n"
        "author QCSD Test <qcsd@example.invalid> 0 +0000\n"
        "committer QCSD Test <qcsd@example.invalid> 0 +0000\n"
        "\n"
        "cohort allocation proof\n"
    ).encode("ascii")
    commit_oid = _git_object_oid(b"commit", commit_payload)
    return commit_oid, {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-ledger-git-proof",
        "commit_payload_base64": base64.b64encode(commit_payload).decode("ascii"),
        "tree_payloads_base64": [
            base64.b64encode(payload).decode("ascii")
            for payload in (root_tree, config_tree, study_tree, v1_tree)
        ],
    }


def _cohort_allocation(
    *,
    ledger_payload: bytes | None = None,
    neqo_commit: str = "e" * 40,
    allocated_version: int = 34,
) -> dict[str, Any]:
    payload = _consumed_cohort_payload() if ledger_payload is None else ledger_payload
    ledger_blob_oid = _git_blob_oid(payload)
    lab_commit, proof = _cohort_git_proof(
        ledger_blob_oid=ledger_blob_oid,
        neqo_gitlink=neqo_commit,
    )
    return {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-allocation",
        "policy": "dense-prefix-durable-publications-consume-v1",
        "ledger_path": "config/buflo-study/v1/consumed-cohorts.json",
        "ledger_sha256": hashlib.sha256(payload).hexdigest(),
        "ledger_payload_base64": base64.b64encode(payload).decode("ascii"),
        "git_object_format": "sha1",
        "ledger_git_blob_oid": ledger_blob_oid,
        "lab_commit": lab_commit,
        "neqo_commit": neqo_commit,
        "neqo_gitlink": neqo_commit,
        "lab_commit_ledger_proof": proof,
        "last_consumed_version": 33,
        "allocated_version": allocated_version,
    }


def _file_stat(*, inode: int, mode: int, size: int) -> dict[str, int]:
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


def _cohort_authority(
    allocation: dict[str, Any], *, schema_version: int = 2
) -> dict[str, Any]:
    ledger_size = len(base64.b64decode(allocation["ledger_payload_base64"]))
    directories = {
        name: {
            **_file_stat(inode=100 + index, mode=0o755, size=4096),
            "nlink": 2,
        }
        for index, name in enumerate(
            ("repository-root", "config", "buflo-study", "v1", "git")
        )
    }
    if schema_version == 2:
        git_identity = directories["git"]
        directories["git"] = {
            "type": stat.S_IFDIR,
            "dev": git_identity["dev"],
            "inode": git_identity["inode"],
            "uid": git_identity["uid"],
            "gid": git_identity["gid"],
            "mode": git_identity["mode"],
        }
    return {
        "schema_version": schema_version,
        "artifact_type": "qcsd-buflo-study-cohort-allocation-authority",
        "git": {
            "object_format": allocation["git_object_format"],
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
            "ledger": _file_stat(inode=200, mode=0o644, size=ledger_size),
            "git_index": _file_stat(inode=201, mode=0o644, size=4096),
        },
        "receipt": json.loads(json.dumps(allocation)),
    }


def _cohort_claim_evidence(
    allocation: dict[str, Any],
    *,
    authority_schema_version: int = 2,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    version = allocation["allocated_version"]
    predecessor = {
        "kind": "genesis-ledger",
        "cohort_version": allocation["last_consumed_version"],
        "sha256": allocation["ledger_sha256"],
    }
    entries: list[dict[str, Any]] = []
    claim_raw = b""
    claim_sha256 = ""
    authority_sha256 = ""
    for claim_version in range(allocation["last_consumed_version"] + 1, version + 1):
        claim_allocation = json.loads(json.dumps(allocation))
        claim_allocation["allocated_version"] = claim_version
        authority = _cohort_authority(
            claim_allocation,
            schema_version=(
                authority_schema_version if claim_version == version else 1
            ),
        )
        authority_sha256 = _canonical_digest(authority)
        claim_payload = {
            "policy": "dense-prefix-durable-publications-consume-v1",
            "registry_path": "artifacts/buflo-study/cohort-claims-v1",
            "cohort_version": claim_version,
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
            "predecessor": predecessor,
        }
        claim = {
            "schema_version": 1,
            "artifact_type": "qcsd-buflo-study-cohort-claim",
            "payload": claim_payload,
            "payload_sha256": _canonical_digest(claim_payload),
        }
        claim_raw = (
            json.dumps(claim, sort_keys=True, separators=(",", ":"), allow_nan=False)
            + "\n"
        ).encode("ascii")
        claim_sha256 = hashlib.sha256(claim_raw).hexdigest()
        entries.append(
            {
                "cohort_version": claim_version,
                "sha256": claim_sha256,
                "payload_base64": base64.b64encode(claim_raw).decode("ascii"),
            }
        )
        predecessor = {
            "kind": "cohort-claim",
            "cohort_version": claim_version,
            "sha256": claim_sha256,
        }
    claim_chain = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-claim-chain",
        "policy": "dense-prefix-durable-publications-consume-v1",
        "genesis": {
            "ledger_path": allocation["ledger_path"],
            "ledger_sha256": allocation["ledger_sha256"],
            "last_consumed_version": allocation["last_consumed_version"],
        },
        "claims": entries,
        "head": {"cohort_version": version, "sha256": claim_sha256},
    }
    claim_chain["payload_sha256"] = _canonical_digest(claim_chain)
    snapshot = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-claim-publication",
        "policy": "dense-prefix-durable-publications-consume-v1",
        "cohort_version": version,
        "registry": {
            "path": "artifacts/buflo-study/cohort-claims-v1",
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
            "path": (
                f"artifacts/buflo-study/cohort-claims-v1/claim-v{version}.json"
            ),
            "sha256": claim_sha256,
            "payload_base64": base64.b64encode(claim_raw).decode("ascii"),
            "stat": _file_stat(inode=301, mode=0o600, size=len(claim_raw)),
        },
        "registry_head_at_publication": {
            "cohort_version": version,
            "sha256": claim_sha256,
        },
    }
    snapshot["payload_sha256"] = _canonical_digest(snapshot)
    snapshot_sha256 = _canonical_digest(snapshot)
    observed_times = (
        "2026-09-01T00:00:01.050000+00:00",
        "2026-09-01T00:00:01.100000+00:00",
        "2026-09-01T00:00:01.200000+00:00",
        "2026-09-01T00:00:01.300000+00:00",
        "2026-09-01T00:00:01.400000+00:00",
        "2026-09-01T00:00:01.600000+00:00",
        "2026-09-01T00:00:02.200000+00:00",
        "2026-09-01T00:00:03.200000+00:00",
        "2026-09-01T00:00:04.950000+00:00",
    )
    boundaries = (
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
    reproofs = [
        {
            "boundary": boundary,
            "observed_at": observed_at,
            "authority_sha256": authority_sha256,
            "claim_snapshot_sha256": snapshot_sha256,
            "claim_file_sha256": claim_sha256,
        }
        for boundary, observed_at in zip(boundaries, observed_times, strict=True)
    ]
    return snapshot, claim_chain, reproofs


def _rehash_cohort_snapshot(
    value: dict[str, Any],
    *,
    rebind_reproofs: bool = False,
) -> None:
    snapshot = value["cohort_claim"]
    snapshot.pop("payload_sha256", None)
    snapshot["payload_sha256"] = _canonical_digest(snapshot)
    if rebind_reproofs:
        snapshot_sha256 = _canonical_digest(snapshot)
        for row in value["cohort_authority_reproofs"]:
            row["claim_snapshot_sha256"] = snapshot_sha256
            row["claim_file_sha256"] = snapshot["claim"]["sha256"]
    _rehash(value)


def _rehash_cohort_chain(value: dict[str, Any]) -> None:
    chain = value["cohort_claim_chain"]
    chain.pop("payload_sha256", None)
    chain["payload_sha256"] = _canonical_digest(chain)
    _rehash(value)


def _reseal_claim_chain_from(value: dict[str, Any], start: int) -> None:
    """Reseal a deliberately mutated claim and every dependent successor."""

    chain = value["cohort_claim_chain"]
    claims = chain["claims"]
    predecessor: dict[str, Any] | None = None
    for index in range(start, len(claims)):
        raw = base64.b64decode(claims[index]["payload_base64"], validate=True)
        claim = json.loads(raw)
        if predecessor is not None:
            claim["payload"]["predecessor"] = predecessor
        claim["payload"]["authority_sha256"] = _canonical_digest(
            claim["payload"]["authority"]
        )
        claim["payload_sha256"] = _canonical_digest(claim["payload"])
        raw = (
            json.dumps(claim, sort_keys=True, separators=(",", ":"), allow_nan=False)
            + "\n"
        ).encode("ascii")
        digest = hashlib.sha256(raw).hexdigest()
        claims[index] = {
            "cohort_version": claim["payload"]["cohort_version"],
            "sha256": digest,
            "payload_base64": base64.b64encode(raw).decode("ascii"),
        }
        predecessor = {
            "kind": "cohort-claim",
            "cohort_version": claim["payload"]["cohort_version"],
            "sha256": digest,
        }
    tail_raw = base64.b64decode(claims[-1]["payload_base64"], validate=True)
    tail_claim = json.loads(tail_raw)
    _install_cohort_claim_raw(
        value,
        tail_raw,
        authority_sha256=_canonical_digest(tail_claim["payload"]["authority"]),
    )
    chain["head"] = {
        "cohort_version": claims[-1]["cohort_version"],
        "sha256": claims[-1]["sha256"],
    }
    _rehash_cohort_chain(value)


def _install_cohort_claim_raw(
    value: dict[str, Any],
    raw: bytes,
    *,
    authority_sha256: str | None = None,
) -> None:
    snapshot = value["cohort_claim"]
    claim_sha256 = hashlib.sha256(raw).hexdigest()
    snapshot["claim"]["payload_base64"] = base64.b64encode(raw).decode("ascii")
    snapshot["claim"]["sha256"] = claim_sha256
    snapshot["claim"]["stat"]["size"] = len(raw)
    snapshot["registry_head_at_publication"]["sha256"] = claim_sha256
    _rehash_cohort_snapshot(value, rebind_reproofs=True)
    if authority_sha256 is not None:
        for row in value["cohort_authority_reproofs"]:
            row["authority_sha256"] = authority_sha256
        _rehash(value)


def _install_cohort_claim(
    value: dict[str, Any],
    claim: dict[str, Any],
) -> None:
    authority_sha256 = _canonical_digest(claim["payload"]["authority"])
    raw = (
        json.dumps(claim, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("ascii")
    _install_cohort_claim_raw(
        value,
        raw,
        authority_sha256=authority_sha256,
    )


def _embedded_cohort_claim(value: dict[str, Any]) -> dict[str, Any]:
    raw = base64.b64decode(value["cohort_claim"]["claim"]["payload_base64"])
    return json.loads(raw)


def _bind_schema5_lab_commit(value: dict[str, Any], lab_commit: str) -> None:
    value["source"]["lab_commit"] = lab_commit
    for source in value["role_provenance"]["sources"].values():
        source["lab_commit"] = lab_commit


def _replace_allocation_proof(
    value: dict[str, Any],
    *,
    lab_commit: str,
    proof: dict[str, Any],
) -> None:
    value["cohort_allocation"]["lab_commit"] = lab_commit
    value["cohort_allocation"]["lab_commit_ledger_proof"] = proof
    _bind_schema5_lab_commit(value, lab_commit)
    _rehash(value)


def _replace_allocation_ledger(value: dict[str, Any], payload: bytes) -> None:
    current = value["cohort_allocation"]
    allocation = _cohort_allocation(
        ledger_payload=payload,
        neqo_commit=current["neqo_commit"],
    )
    allocation["last_consumed_version"] = current["last_consumed_version"]
    allocation["allocated_version"] = current["allocated_version"]
    value["cohort_allocation"] = allocation
    _bind_schema5_lab_commit(value, allocation["lab_commit"])
    _rehash(value)


def _observation(
    boundary: str,
    observed_at: str,
    *,
    available_bytes: int = 128 * GIB,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "probe": build_storage.BUILD_HOST_STORAGE_PROBE,
        "probe_sha256": PROBE_SHA256,
        "boundary": boundary,
        "observed_at": observed_at,
        "location_source": "wsl-lxss-docker-desktop-data",
        "data_vhd_path": DATA_VHD_PATH,
        "data_vhd_file_length_bytes": 512 * GIB,
        "backing_volume_unique_id": VOLUME_ID,
        "drive_letter": "C",
        "file_system": "NTFS",
        "health_status": "Healthy",
        "operational_status": ["OK"],
        "total_bytes": 1024 * GIB,
        "available_bytes": available_bytes,
    }


def _wsl_preflight(*, available_bytes: int = 128 * GIB) -> dict[str, Any]:
    observations = [
        _observation(boundary, observed_at, available_bytes=available_bytes)
        for boundary, observed_at in BOUNDARY_TIMES
    ]
    return {
        "schema_version": 1,
        "applicable": True,
        "platform": "windows-wsl2",
        "platform_detection": {
            "schema_version": 1,
            "probe": "wsl-multi-signal-v1",
            "kernel_release": "6.6.87.2-microsoft-standard-WSL2",
            "proc_version": "Linux version 6.6.87.2-microsoft-standard-WSL2",
            "wsl_interop_env_present": True,
            "wsl_distro_name_env_present": True,
            "run_wsl_directory_present": True,
        },
        "policy": build_storage.BUILD_HOST_STORAGE_POLICY,
        "required_available_bytes": build_storage.BUILD_WSL_HOST_MIN_AVAILABLE_BYTES,
        "observations": observations,
        "minimum_available_bytes": available_bytes,
        "passed": True,
    }


def _post_start_wsl_preflight() -> dict[str, Any]:
    value = _wsl_preflight()
    for observation, observed_at in zip(
        value["observations"],
        (
            "2026-09-01T00:00:01.150000+00:00",
            "2026-09-01T00:00:02.100000+00:00",
            "2026-09-01T00:00:03.100000+00:00",
            "2026-09-01T00:00:04.925000+00:00",
        ),
        strict=True,
    ):
        observation["observed_at"] = observed_at
    return value


def _non_wsl_preflight() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "applicable": False,
        "platform": "other-host",
        "platform_detection": {
            "schema_version": 1,
            "probe": "wsl-multi-signal-v1",
            "kernel_release": "6.8.0-79-generic",
            "proc_version": "Linux version 6.8.0-79-generic",
            "wsl_interop_env_present": False,
            "wsl_distro_name_env_present": False,
            "run_wsl_directory_present": False,
        },
        "policy": build_storage.BUILD_HOST_STORAGE_POLICY,
        "required_available_bytes": build_storage.BUILD_WSL_HOST_MIN_AVAILABLE_BYTES,
        "observations": [],
        "minimum_available_bytes": None,
        "passed": True,
    }


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
    identity_sha256 = _canonical_digest(identity)
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
                ("before-collection", "2026-09-01T00:00:01.500000+00:00"),
                ("after-collection", "2026-09-01T00:00:02+00:00"),
                ("after-prepare", "2026-09-01T00:00:03+00:00"),
                ("after-reference", "2026-09-01T00:00:04.900000+00:00"),
            )
        ],
        "passed": True,
    }


def _docker_buildx_metadata(path: str) -> dict[str, str]:
    return {
        "Name": "buildx",
        "Path": path,
        "SchemaVersion": "0.1.0",
        "ShortDescription": "Docker Buildx",
        "Vendor": "Docker Inc.",
        "Version": "v0.29.1-desktop.1",
    }


def _build_receipt(
    *,
    schema_version: int,
    host_storage_preflight: dict[str, Any] | None = None,
    cohort_version: int = 34,
) -> dict[str, Any]:
    image_ids = {
        "collection": "sha256:" + "a" * 64,
        "prepare": "sha256:" + "b" * 64,
        "reference": "sha256:" + "c" * 64,
    }
    docker: dict[str, Any] = {
        "client_version": "29.0.1",
        "server_version": "29.0.1",
    }
    if schema_version in {2, 3, 4, 5}:
        docker.update(
            {
                "context": "default",
                "endpoint": "unix:///var/run/docker.sock",
                "server_id": "0123456789AB",
                "server_name": "docker-desktop",
                "server_operating_system": (
                    "Docker Desktop 4.51.0"
                    if host_storage_preflight and host_storage_preflight["applicable"]
                    else "Ubuntu 24.04"
                ),
                "server_os_type": "linux",
                "server_architecture": "x86_64",
            }
        )
    build_root = "/workspace/neqo-qcsd-lab"
    commands = []
    for target in ("collection", "prepare", "reference"):
        tag = (
            build_storage.BUILD_IMAGE_TAGS[target]
            if schema_version in {2, 3, 4, 5}
            else f"neqo-qcsd-lab-{target}:test"
        )
        argv = ["docker"]
        if schema_version == 2:
            argv.extend(["--context", docker["context"]])
        elif schema_version in {3, 4, 5}:
            argv.extend(["--host", docker["endpoint"]])
        argv.extend(["build", "--pull", "--no-cache"])
        if schema_version in {2, 3, 4, 5}:
            argv.extend(
                [
                    "--iidfile",
                    (
                        f"{build_root}/artifacts/buflo-study/"
                        f".build-iids-v{cohort_version}.ABC123/{target}.iid"
                    ),
                ]
            )
        argv.extend(
            [
                "--target",
                target,
                "--tag",
                tag,
                "--file",
                f"{build_root}/Dockerfile",
                build_root,
            ]
        )
        commands.append(
            {
                "target": target,
                "argv": argv,
                "exit_code": 0,
                "image_id": image_ids[target],
            }
        )
    value: dict[str, Any] = {
        "schema_version": schema_version,
        "artifact_type": build_storage.BUILD_EXECUTION_ARTIFACT_TYPE,
        "cohort_version": cohort_version,
        "started_at": "2026-09-01T00:00:01+00:00",
        "finished_at": "2026-09-01T00:00:05+00:00",
        "duration_seconds": 4.0,
        "docker": docker,
        "commands": commands,
        "images": {
            target: {
                "tag": (
                    build_storage.BUILD_IMAGE_TAGS[target]
                    if schema_version in {2, 3, 4, 5}
                    else f"neqo-qcsd-lab-{target}:test"
                ),
                "id": image_ids[target],
                "repo_digests": [],
            }
            for target in ("collection", "prepare", "reference")
        },
        "source": {
            "image_digest": image_ids["collection"],
            "lab_commit": "d" * 40,
            "lab_dirty": False,
            "lab_patch_sha256": build_storage.BUILD_EMPTY_SHA256,
            "neqo_commit": "e" * 40,
            "neqo_pinned_commit": "e" * 40,
            "neqo_dirty": False,
            "neqo_patch_sha256": build_storage.BUILD_EMPTY_SHA256,
        },
        "build_inputs": {
            "schema_version": 1,
            "artifact_type": "qcsd-study-build-inputs",
            "rust_base_image": build_storage.BUILD_RUST_BASE_IMAGE,
            "debian_base_image": build_storage.BUILD_DEBIAN_BASE_IMAGE,
            "uv_lock_sha256": "f" * 64,
            "cargo_lock_sha256": "0" * 64,
        },
        "dockerfile_sha256": "d" * 64,
        "cache_policy": {
            "pull": True,
            "no_cache": True,
            "scope": ("Docker-layer-cache-disabled;declared-BuildKit-dependency-cache-mounts-only"),
        },
    }
    if schema_version in {2, 3, 4, 5}:
        assert host_storage_preflight is not None
        value["host_storage_preflight"] = host_storage_preflight
        value["role_provenance"] = {
            "schema_version": 1,
            "sources": {
                target: {**value["source"], "image_digest": image_ids[target]}
                for target in ("collection", "prepare", "reference")
            },
            "build_inputs": {
                "collection": dict(value["build_inputs"]),
                "prepare": dict(value["build_inputs"]),
                "reference": None,
            },
        }
    if schema_version in {4, 5}:
        value["buildx"] = _buildx_provenance()
    if schema_version == 5:
        allocation = _cohort_allocation(allocated_version=cohort_version)
        value["cohort_allocation"] = allocation
        _bind_schema5_lab_commit(value, allocation["lab_commit"])
        claim, claim_chain, reproofs = _cohort_claim_evidence(allocation)
        value["cohort_claim"] = claim
        value["cohort_claim_chain"] = claim_chain
        value["cohort_authority_reproofs"] = reproofs
    return _rehash(value)


def _write_current_build_pair(
    root: Path,
    *,
    cohort_version: int = 34,
) -> tuple[Path, Path, dict[str, Any], dict[str, Any]]:
    """Write one structurally valid schema-5 receipt/completion test pair."""

    evidence = root / "artifacts/buflo-study"
    evidence.mkdir(parents=True, exist_ok=True)
    receipt_path = evidence / f"build-execution-v{cohort_version}.json"
    receipt_value = _build_receipt(
        schema_version=5,
        host_storage_preflight=_non_wsl_preflight(),
        cohort_version=cohort_version,
    )
    receipt_raw = (
        json.dumps(receipt_value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    receipt_path.write_bytes(receipt_raw)
    receipt_path.chmod(0o600)
    binding = build_storage.build_execution_receipt_binding(
        receipt_path=receipt_path,
        receipt_raw=receipt_raw,
        receipt_value=receipt_value,
        receipt_stat=receipt_path.stat(),
        cohort_version=cohort_version,
    )
    authority = build_storage._completion_authority_bindings(receipt_value)
    lease_nonce = "9" * 64
    transaction_root = Path(
        f"/tmp/qcsd-docker-lifecycle-1000/transaction.{lease_nonce[:32]}"
    )
    transaction_record_path = transaction_root / "SUPERVISION"
    transaction_fields = {
        "object": "docker-build-transaction",
        "lifecycle_schema": "1",
        "lifecycle_state": "request-authorised",
        "lifecycle_root": str(transaction_root),
        "lifecycle_token": lease_nonce[:32],
        "supervisor_source_path": "/workspace/neqo-qcsd-lab/tools/docker_signal_supervisor.sh",
        "supervisor_source_sha256": "8" * 64,
        "supervisor_source_device": "1",
        "supervisor_source_inode": "2",
        "docker_context": "default",
        "docker_host": "unix:///var/run/docker.sock",
        "docker_server_id": "0123456789AB",
        "docker_request_revalidation": "in-scope-immediately-before-mutation",
        "docker_daemon_id": "0123456789AB",
        "host_boot_id": "12345678-1234-1234-1234-123456789abc",
        "working_directory": "/workspace/neqo-qcsd-lab",
        "cohort_version": str(cohort_version),
        "receipt_path": (
            f"/workspace/neqo-qcsd-lab/artifacts/buflo-study/"
            f"build-execution-v{cohort_version}.json"
        ),
        "transaction_state": "uncommitted-static-tag-mutation",
    }
    transaction_raw = "".join(
        f"{key}={transaction_fields[key]}\n"
        for key in build_storage._BUILD_TRANSACTION_RECORD_FIELDS
    ).encode("ascii")
    lifecycle_lock = {
        "path": "/tmp/qcsd-docker-lifecycle-1000.lock",
        "device": 1,
        "inode": 10,
        "parent_device": 1,
        "parent_inode": 1,
        "lease_nonce": lease_nonce,
    }
    cohort_parent = root / "artifacts/buflo-study/cohort-claims-v1"
    transaction = {
        "schema_version": 1,
        "artifact_type": build_storage._BUILD_TRANSACTION_RETIREMENT_ARTIFACT_TYPE,
        "root": {
            "path": str(transaction_root),
            "stat": {
                "dev": 1,
                "inode": 20,
                "uid": os.geteuid(),
                "gid": os.getegid(),
                "mode": 0o700,
                "nlink": 2,
            },
        },
        "record": {
            "path": str(transaction_record_path),
            "sha256": hashlib.sha256(transaction_raw).hexdigest(),
            "payload_base64": base64.b64encode(transaction_raw).decode("ascii"),
            "stat": _file_stat(
                inode=21,
                mode=0o600,
                size=len(transaction_raw),
            ),
        },
        "guardian": {
            "pid": 100,
            "start_time": 1000,
            "qcsd_pid": 101,
            "qcsd_start_time": 1001,
        },
        "lifecycle_lock": lifecycle_lock,
        "cohort_lock": {
            "path": str(cohort_parent / ".allocation.lock"),
            "device": 1,
            "inode": 30,
            "parent_device": 1,
            "parent_inode": 31,
            "guardian_fd": 9,
        },
        "operation_lock": {
            "path": str(cohort_parent / ".allocation-operation.lock"),
            "device": 1,
            "inode": 32,
            "parent_device": 1,
            "parent_inode": 31,
        },
    }
    completion_value: dict[str, Any] = {
        "schema_version": 1,
        "artifact_type": build_storage.BUILD_COMPLETION_ARTIFACT_TYPE,
        "cohort_version": cohort_version,
        "completed_at": "2026-09-01T00:00:05.200000+00:00",
        "receipt": binding,
        "source": {
            "lab_commit": receipt_value["source"]["lab_commit"],
            "neqo_commit": receipt_value["source"]["neqo_commit"],
            "neqo_gitlink": receipt_value["cohort_allocation"]["neqo_gitlink"],
        },
        "cohort_authority": authority,
        "transaction": transaction,
        "final_reproof": {
            "boundary": build_storage.BUILD_COMPLETION_FINAL_REPROOF_BOUNDARY,
            "observed_at": "2026-09-01T00:00:05.100000+00:00",
            "authority_sha256": receipt_value["cohort_authority_reproofs"][-1][
                "authority_sha256"
            ],
            "claim_snapshot_sha256": authority["claim_snapshot_sha256"],
            "claim_file_sha256": authority["claim_file_sha256"],
            "claim_chain_sha256": authority["claim_chain_sha256"],
        },
    }
    completion_value["payload_sha256"] = _canonical_digest(completion_value)
    completion_path = evidence / f"build-completion-v{cohort_version}.json"
    completion_path.write_bytes(
        build_storage._canonical_finite_json_bytes(
            completion_value, label="test build completion", newline=True
        )
    )
    completion_path.chmod(0o600)
    return receipt_path, completion_path, receipt_value, completion_value


def _validate_observation(value: dict[str, Any]) -> dict[str, Any]:
    return build_storage.validate_build_host_storage_observation(
        value,
        expected_boundary="before-collection",
        expected_probe_sha256=PROBE_SHA256,
    )


def test_exact_schema_1_build_receipt_remains_compatible() -> None:
    value = _build_receipt(schema_version=1)

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_cohort_version=34,
        expected_probe_sha256="f" * 64,
    )

    assert validated == {
        "schema_version": 1,
        "cohort_version": 34,
        "image_ids": {
            "collection": "sha256:" + "a" * 64,
            "prepare": "sha256:" + "b" * 64,
            "reference": "sha256:" + "c" * 64,
        },
        "source": value["source"],
        "role_provenance": None,
        "host_storage_preflight": None,
    }


def test_schema_one_build_command_root_remains_relocatable() -> None:
    value = _build_receipt(schema_version=1)

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_build_root=Path("/a/different/current/checkout"),
    )

    assert validated["schema_version"] == 1


@pytest.mark.parametrize(
    "replacement",
    (
        "neqo-qcsd-lab-collection:local",
        "docker.io/library/neqo-qcsd-lab-prepare:local",
        "neqo-qcsd-lab-prepare:other",
    ),
)
def test_schema_two_rejects_rehashed_noncanonical_image_role_tags(
    replacement: str,
) -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    value["images"]["prepare"]["tag"] = replacement
    tag_index = value["commands"][1]["argv"].index("--tag") + 1
    value["commands"][1]["argv"][tag_index] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match="prepare image role tag"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_two_rejects_rehashed_duplicate_immutable_role_ids() -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    duplicate = value["images"]["collection"]["id"]
    value["images"]["prepare"]["id"] = duplicate
    value["commands"][1]["image_id"] = duplicate
    _rehash(value)

    with pytest.raises(ValueError, match="distinct immutable IDs"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_two_rejects_rehashed_cross_role_source_snapshot() -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    value["role_provenance"]["sources"]["reference"]["lab_commit"] = "1" * 40
    _rehash(value)

    with pytest.raises(ValueError, match="different source snapshots"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_two_rejects_rehashed_cross_role_build_inputs() -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    value["role_provenance"]["build_inputs"]["prepare"]["uv_lock_sha256"] = "1" * 64
    _rehash(value)

    with pytest.raises(ValueError, match="different build inputs"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    "replacement",
    (
        "/tmp/prepare.iid",
        "/workspace/neqo-qcsd-lab/artifacts/buflo-study/../prepare.iid",
        ("/workspace/neqo-qcsd-lab/artifacts/buflo-study/.build-iids-v35.ABC123/prepare.iid"),
        ("/workspace/neqo-qcsd-lab/artifacts/buflo-study/.build-iids-v34.A/prepare.iid"),
    ),
)
def test_schema_two_rejects_rehashed_unbound_iid_paths(replacement: str) -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    iidfile_index = value["commands"][1]["argv"].index("--iidfile") + 1
    value["commands"][1]["argv"][iidfile_index] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match="--pull --no-cache"):
        build_storage.validate_build_execution_envelope(value)


def test_valid_wsl_schema_2_binds_all_storage_and_docker_evidence() -> None:
    preflight = _wsl_preflight()
    value = _build_receipt(schema_version=2, host_storage_preflight=preflight)

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_cohort_version=34,
        expected_probe_sha256=PROBE_SHA256,
    )

    assert validated["schema_version"] == 2
    assert validated["host_storage_preflight"] == preflight
    assert validated["host_storage_preflight"] is not preflight


def test_valid_non_wsl_schema_2_records_exact_non_applicable_evidence() -> None:
    preflight = _non_wsl_preflight()
    value = _build_receipt(schema_version=2, host_storage_preflight=preflight)

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_cohort_version=34,
        expected_probe_sha256=PROBE_SHA256,
    )

    assert validated["host_storage_preflight"] == preflight


def test_valid_schema_3_binds_the_executed_pinned_host_build_argv() -> None:
    preflight = _non_wsl_preflight()
    value = _build_receipt(schema_version=3, host_storage_preflight=preflight)

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_cohort_version=34,
        expected_probe_sha256=PROBE_SHA256,
    )

    assert validated["schema_version"] == 3
    assert all(
        command["argv"][:3] == ["docker", "--host", "unix:///var/run/docker.sock"]
        for command in value["commands"]
    )


def test_valid_schema_4_projects_exact_four_boundary_buildx_provenance() -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_cohort_version=34,
        expected_probe_sha256=PROBE_SHA256,
    )

    assert validated["schema_version"] == 4
    assert validated["buildx"] == value["buildx"]
    assert validated["buildx"] is not value["buildx"]
    assert [row["boundary"] for row in validated["buildx"]["observations"]] == [
        "before-collection",
        "after-collection",
        "after-prepare",
        "after-reference",
    ]


def test_schema_5_claim_contract_tracks_the_allocator_contract() -> None:
    assert build_storage._COHORT_CLAIM_MAX_BYTES == cohort_allocation.MAX_CLAIM_BYTES
    assert (
        build_storage._COHORT_CLAIM_REGISTRY_PATH
        == cohort_allocation.REGISTRY_RELATIVE_PATH
    )
    assert (
        build_storage._COHORT_CLAIM_ARTIFACT_TYPE
        == cohort_allocation.CLAIM_ARTIFACT_TYPE
    )
    assert (
        build_storage._COHORT_CLAIM_SNAPSHOT_ARTIFACT_TYPE
        == cohort_allocation.SNAPSHOT_ARTIFACT_TYPE
    )
    assert (
        build_storage._COHORT_AUTHORITY_ARTIFACT_TYPE
        == cohort_allocation.AUTHORITY_ARTIFACT_TYPE
    )
    assert build_storage._COHORT_CLAIM_SNAPSHOT_KEYS == cohort_allocation._SNAPSHOT_KEYS
    assert build_storage._COHORT_CLAIM_KEYS == cohort_allocation._CLAIM_KEYS
    assert (
        build_storage._COHORT_CLAIM_PAYLOAD_KEYS
        == cohort_allocation._CLAIM_PAYLOAD_KEYS
    )
    assert build_storage._COHORT_AUTHORITY_KEYS == cohort_allocation._AUTHORITY_KEYS
    assert (
        build_storage._COHORT_AUTHORITY_GIT_KEYS
        == cohort_allocation._AUTHORITY_GIT_KEYS
    )
    assert (
        build_storage._COHORT_AUTHORITY_FILESYSTEM_KEYS
        == cohort_allocation._AUTHORITY_FILESYSTEM_KEYS
    )
    assert (
        build_storage._COHORT_AUTHORITY_DIRECTORY_NAMES
        == cohort_allocation._AUTHORITY_DIRECTORY_NAMES
    )
    assert (
        build_storage._COHORT_AUTHORITY_SCHEMA_VERSIONS
        == cohort_allocation._AUTHORITY_SCHEMA_VERSIONS
    )
    assert (
        build_storage._COHORT_AUTHORITY_GIT_DIRECTORY_KEYS
        == cohort_allocation._AUTHORITY_DIRECTORY_IDENTITY_KEYS
    )
    assert build_storage._COHORT_CLAIM_SOURCE_KEYS == cohort_allocation._SOURCE_KEYS
    assert (
        build_storage._COHORT_CLAIM_LEDGER_KEYS
        == cohort_allocation._LEDGER_BINDING_KEYS
    )
    assert (
        build_storage._COHORT_CLAIM_PREDECESSOR_KEYS
        == cohort_allocation._PREDECESSOR_KEYS
    )
    assert (
        build_storage._COHORT_SNAPSHOT_REGISTRY_KEYS
        == cohort_allocation._REGISTRY_SNAPSHOT_KEYS
    )
    assert (
        build_storage._COHORT_SNAPSHOT_CLAIM_KEYS
        == cohort_allocation._CLAIM_SNAPSHOT_KEYS
    )
    assert build_storage._COHORT_FILE_STAT_KEYS == cohort_allocation._FILE_STAT_KEYS
    assert (
        build_storage._COHORT_DIRECTORY_STAT_KEYS
        == cohort_allocation._DIRECTORY_BINDING_KEYS
    )


def test_valid_schema_5_projects_exact_cohort_allocation() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_cohort_version=34,
        expected_probe_sha256=PROBE_SHA256,
    )

    assert validated["schema_version"] == 5
    assert validated["buildx"] == value["buildx"]
    assert validated["cohort_allocation"] == value["cohort_allocation"]
    assert validated["cohort_allocation"] is not value["cohort_allocation"]
    assert (
        validated["cohort_allocation"]["lab_commit_ledger_proof"]
        is not value["cohort_allocation"]["lab_commit_ledger_proof"]
    )
    assert (
        validated["cohort_allocation"]["lab_commit_ledger_proof"][
            "tree_payloads_base64"
        ]
        is not value["cohort_allocation"]["lab_commit_ledger_proof"][
            "tree_payloads_base64"
        ]
    )
    assert validated["cohort_allocation"]["last_consumed_version"] == 33
    assert validated["cohort_allocation"]["allocated_version"] == 34
    assert validated["cohort_claim"] == value["cohort_claim"]
    assert validated["cohort_claim"] is not value["cohort_claim"]
    assert validated["cohort_claim_chain"] == value["cohort_claim_chain"]
    assert validated["cohort_claim_chain"] is not value["cohort_claim_chain"]
    assert validated["cohort_authority_reproofs"] == value[
        "cohort_authority_reproofs"
    ]
    assert validated["cohort_authority_reproofs"] is not value[
        "cohort_authority_reproofs"
    ]


def test_schema_5_build_start_precedes_wsl_storage_observations() -> None:
    value = _build_receipt(
        schema_version=5,
        host_storage_preflight=_post_start_wsl_preflight(),
    )

    validated = build_storage.validate_build_execution_envelope(value)

    assert validated["host_storage_preflight"] == value["host_storage_preflight"]


@pytest.mark.parametrize("schema_version", (2, 3, 4))
def test_pre_schema_5_build_start_cannot_precede_wsl_storage_observations(
    schema_version: int,
) -> None:
    value = _build_receipt(
        schema_version=schema_version,
        host_storage_preflight=_post_start_wsl_preflight(),
    )

    with pytest.raises(ValueError, match="host-storage timing"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_permanent_claim_can_allocate_after_the_genesis_successor() -> None:
    value = _build_receipt(
        schema_version=5,
        host_storage_preflight=_non_wsl_preflight(),
        cohort_version=62,
    )

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_cohort_version=62,
    )

    assert validated["cohort_allocation"]["last_consumed_version"] == 33
    assert validated["cohort_allocation"]["allocated_version"] == 62
    claim = _embedded_cohort_claim(value)
    assert claim["payload"]["predecessor"] == {
        "kind": "cohort-claim",
        "cohort_version": 61,
        "sha256": value["cohort_claim_chain"]["claims"][-2]["sha256"],
    }


def test_schema_5_accepts_snapshot_published_by_cohort_allocator(tmp_path: Path) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    root = tmp_path / "claim-root"
    (root / "artifacts/buflo-study").mkdir(parents=True)
    snapshot = cohort_allocation.publish_cohort_claim(
        root,
        _cohort_authority(value["cohort_allocation"]),
    )
    value["cohort_claim"] = snapshot
    value["cohort_claim_chain"] = cohort_allocation.cohort_claim_chain(
        root,
        snapshot,
    )
    _rehash_cohort_snapshot(value, rebind_reproofs=True)

    validated = build_storage.validate_build_execution_envelope(value)

    assert validated["cohort_claim"] == snapshot


def test_schema_5_accepts_mixed_historical_and_stable_directory_authorities() -> None:
    value = _build_receipt(
        schema_version=5,
        host_storage_preflight=_non_wsl_preflight(),
        cohort_version=35,
    )

    validated = build_storage.validate_build_execution_envelope(value)

    claims = value["cohort_claim_chain"]["claims"]
    first = json.loads(base64.b64decode(claims[0]["payload_base64"], validate=True))
    last = json.loads(base64.b64decode(claims[-1]["payload_base64"], validate=True))
    assert first["payload"]["authority"]["schema_version"] == 1
    assert last["payload"]["authority"]["schema_version"] == 2
    assert set(last["payload"]["authority"]["filesystem"]["directories"]["git"]) == {
        "type",
        "dev",
        "inode",
        "uid",
        "gid",
        "mode",
    }
    assert validated["cohort_claim_chain"] == value["cohort_claim_chain"]


def test_schema_two_authority_rejects_legacy_full_git_directory_identity() -> None:
    allocation = _cohort_allocation()
    authority = _cohort_authority(allocation, schema_version=1)
    authority["schema_version"] = 2

    with pytest.raises(ValueError, match="Git directory binding"):
        build_storage._validate_embedded_cohort_authority(
            authority,
            allocation=allocation,
            ledger_size=len(base64.b64decode(allocation["ledger_payload_base64"])),
        )


def test_schema_5_accepts_proof_from_real_git_commit_and_tree_objects(
    tmp_path: Path,
) -> None:
    root = tmp_path / "proof-repository"
    root.mkdir()
    _run_test_git(root, "init", "--quiet", "--object-format=sha1")
    ledger = root / "config/buflo-study/v1/consumed-cohorts.json"
    ledger.parent.mkdir(parents=True)
    ledger.write_bytes(_consumed_cohort_payload())
    _run_test_git(root, "add", "--", "config/buflo-study/v1/consumed-cohorts.json")
    neqo_gitlink = "e" * 40
    _run_test_git(
        root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{neqo_gitlink},neqo-qcsd",
    )
    _run_test_git(
        root,
        "-c",
        "user.name=QCSD Test",
        "-c",
        "user.email=qcsd@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "cohort proof",
    )
    lab_commit = _run_test_git(root, "rev-parse", "HEAD").decode().strip()
    ledger_blob_oid = _run_test_git(
        root,
        "rev-parse",
        "HEAD:config/buflo-study/v1/consumed-cohorts.json",
    ).decode().strip()
    commit_payload = _run_test_git(root, "cat-file", "commit", lab_commit)
    tree_specs = (
        f"{lab_commit}^{{tree}}",
        f"{lab_commit}:config",
        f"{lab_commit}:config/buflo-study",
        f"{lab_commit}:config/buflo-study/v1",
    )
    tree_payloads = []
    for spec in tree_specs:
        tree_oid = _run_test_git(root, "rev-parse", spec).decode().strip()
        tree_payloads.append(_run_test_git(root, "cat-file", "tree", tree_oid))

    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    allocation = value["cohort_allocation"]
    allocation["ledger_git_blob_oid"] = ledger_blob_oid
    allocation["lab_commit"] = lab_commit
    allocation["lab_commit_ledger_proof"] = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-ledger-git-proof",
        "commit_payload_base64": base64.b64encode(commit_payload).decode("ascii"),
        "tree_payloads_base64": [
            base64.b64encode(payload).decode("ascii") for payload in tree_payloads
        ],
    }
    _bind_schema5_lab_commit(value, lab_commit)
    claim, claim_chain, reproofs = _cohort_claim_evidence(allocation)
    value["cohort_claim"] = claim
    value["cohort_claim_chain"] = claim_chain
    value["cohort_authority_reproofs"] = reproofs
    _rehash(value)

    validated = build_storage.validate_build_execution_envelope(value)

    assert validated["cohort_allocation"] == allocation


@pytest.mark.parametrize(
    "field",
    (
        "cohort_allocation",
        "cohort_claim",
        "cohort_claim_chain",
        "cohort_authority_reproofs",
    ),
)
def test_schema_5_requires_all_cohort_evidence(field: str) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value.pop(field)
    _rehash(value)
    with pytest.raises(ValueError, match="receipt schema"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    "field",
    (
        "cohort_allocation",
        "cohort_claim",
        "cohort_claim_chain",
        "cohort_authority_reproofs",
    ),
)
def test_schema_4_forbids_all_schema_5_cohort_evidence(field: str) -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    schema_five = _build_receipt(
        schema_version=5,
        host_storage_preflight=_non_wsl_preflight(),
    )
    value[field] = schema_five[field]
    _rehash(value)
    with pytest.raises(ValueError, match="receipt schema"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("schema_version", True),
        ("schema_version", 2),
        ("artifact_type", "qcsd-buflo-study-cohort-allocation-v2"),
        ("policy", "dense-prefix-receipts-only-v1"),
        ("ledger_path", "/tmp/consumed-cohorts.json"),
    ),
)
def test_schema_5_rejects_rehashed_invalid_allocation_contract(
    field: str, replacement: Any
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_allocation"][field] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match="allocation schema"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("mutation", ("missing", "extra"))
def test_schema_5_requires_exact_allocation_keys(mutation: str) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    if mutation == "missing":
        value["cohort_allocation"].pop("ledger_path")
    else:
        value["cohort_allocation"]["unexpected"] = None
    _rehash(value)

    with pytest.raises(ValueError, match="allocation schema"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    (
        ("ledger_payload_base64", "%%%%", "ledger encoding"),
        ("ledger_payload_base64", "ZE==", "ledger encoding"),
        ("ledger_sha256", "0" * 64, "ledger SHA-256"),
        ("git_object_format", "sha512", "Git object format"),
        ("git_object_format", [], "Git object format"),
        ("ledger_git_blob_oid", "0" * 40, "Git blob binding"),
    ),
)
def test_schema_5_rejects_rehashed_invalid_allocation_crypto(
    field: str, replacement: Any, message: str
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_allocation"][field] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match=message):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    "payload",
    (
        (
            b'{"schema_version":1,"artifact_type":"qcsd-buflo-study-consumed-cohorts",'
            b'"policy":"dense-prefix-durable-publications-consume-v1",'
            b'"consumed_versions":[1],"consumed_versions":[1]}'
        ),
        (
            b'{"schema_version":1,"artifact_type":"qcsd-buflo-study-consumed-cohorts",'
            b'"policy":"dense-prefix-durable-publications-consume-v1","consumed_versions":[NaN]}'
        ),
        b"\xff",
    ),
)
def test_schema_5_rejects_invalid_embedded_ledger_json(payload: bytes) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    _replace_allocation_ledger(value, payload)

    with pytest.raises(ValueError, match="unique-key UTF-8 JSON"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("mutation", "replacement"),
    (
        ("schema_version", 2),
        ("schema_version", True),
        ("artifact_type", "qcsd-buflo-study-consumed-cohorts-v2"),
        ("policy", "dense-prefix-receipts-only-v1"),
        ("unexpected", None),
    ),
)
def test_schema_5_rejects_invalid_embedded_ledger_schema(
    mutation: str, replacement: Any
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    ledger = json.loads(_consumed_cohort_payload())
    ledger[mutation] = replacement
    payload = json.dumps(ledger, sort_keys=True, separators=(",", ":")).encode()
    _replace_allocation_ledger(value, payload)

    with pytest.raises(ValueError, match="ledger schema"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("consumed_versions", ([], [1, 3], [1, True], [2]))
def test_schema_5_rejects_non_dense_embedded_ledger(
    consumed_versions: list[int],
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    _replace_allocation_ledger(
        value,
        _consumed_cohort_payload(consumed_versions=consumed_versions),
    )

    with pytest.raises(ValueError, match="dense prefix"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("last_consumed_version", 32),
        ("last_consumed_version", True),
        ("allocated_version", 35),
        ("allocated_version", True),
    ),
)
def test_schema_5_rejects_rehashed_allocation_version_mismatch(
    field: str, replacement: Any
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_allocation"][field] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match="version binding"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("lab_commit", "f" * 40),
        ("neqo_commit", "f" * 40),
        ("neqo_gitlink", "f" * 40),
    ),
)
def test_schema_5_rejects_rehashed_allocation_source_mismatch(
    field: str, replacement: str
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_allocation"][field] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match="source binding"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_sha256_git_allocation_at_envelope_level() -> None:
    payload = _consumed_cohort_payload()
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_allocation"].update(
        git_object_format="sha256",
        ledger_git_blob_oid=_git_blob_oid(payload, object_format="sha256"),
    )
    _rehash(value)

    with pytest.raises(ValueError, match="Git object format"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("mutation", "replacement"),
    (
        ("schema_version", True),
        ("schema_version", 2),
        ("artifact_type", "qcsd-buflo-study-cohort-ledger-git-proof-v2"),
        ("unexpected", None),
    ),
)
def test_schema_5_rejects_rehashed_invalid_git_proof_schema(
    mutation: str,
    replacement: Any,
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    proof = value["cohort_allocation"]["lab_commit_ledger_proof"]
    proof[mutation] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match="Git proof schema"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_git_proof_with_missing_key() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_allocation"]["lab_commit_ledger_proof"].pop(
        "commit_payload_base64"
    )
    _rehash(value)

    with pytest.raises(ValueError, match="Git proof schema"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("replacement", ("%%%%", "ZE==", ""))
def test_schema_5_rejects_noncanonical_git_commit_encoding(replacement: str) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_allocation"]["lab_commit_ledger_proof"][
        "commit_payload_base64"
    ] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match="Git proof commit encoding"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_oversized_git_commit_proof() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_allocation"]["lab_commit_ledger_proof"][
        "commit_payload_base64"
    ] = base64.b64encode(
        b"x" * (build_storage._COHORT_GIT_PROOF_COMMIT_MAX_BYTES + 1)
    ).decode("ascii")
    _rehash(value)

    with pytest.raises(ValueError, match="Git proof commit encoding"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("replacement", ([], ["ZA=="] * 3, tuple(["ZA=="] * 4)))
def test_schema_5_requires_exact_git_tree_proof_inventory(replacement: Any) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_allocation"]["lab_commit_ledger_proof"][
        "tree_payloads_base64"
    ] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match="Git proof tree inventory"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("replacement", ("%%%%", "ZE==", ""))
def test_schema_5_rejects_noncanonical_git_tree_encoding(replacement: str) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_allocation"]["lab_commit_ledger_proof"][
        "tree_payloads_base64"
    ][0] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match="Git proof tree encoding"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_oversized_git_tree_proof() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_allocation"]["lab_commit_ledger_proof"][
        "tree_payloads_base64"
    ][0] = base64.b64encode(
        b"x" * (build_storage._COHORT_GIT_PROOF_TREE_MAX_BYTES + 1)
    ).decode("ascii")
    _rehash(value)

    with pytest.raises(ValueError, match="Git proof tree encoding"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_rehashed_git_commit_payload_tampering() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    proof = value["cohort_allocation"]["lab_commit_ledger_proof"]
    commit_payload = base64.b64decode(proof["commit_payload_base64"])
    proof["commit_payload_base64"] = base64.b64encode(commit_payload + b"x").decode(
        "ascii"
    )
    _rehash(value)

    with pytest.raises(ValueError, match="Git proof commit binding"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_authenticated_malformed_git_commit_payload() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    proof = dict(value["cohort_allocation"]["lab_commit_ledger_proof"])
    malformed = b"parent " + b"f" * 40 + b"\n\nmissing tree\n"
    proof["commit_payload_base64"] = base64.b64encode(malformed).decode("ascii")
    lab_commit = _git_object_oid(b"commit", malformed)
    _replace_allocation_proof(value, lab_commit=lab_commit, proof=proof)

    with pytest.raises(ValueError, match="Git proof commit payload"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_rehashed_git_tree_payload_tampering() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    trees = value["cohort_allocation"]["lab_commit_ledger_proof"][
        "tree_payloads_base64"
    ]
    root_tree = base64.b64decode(trees[0])
    trees[0] = base64.b64encode(root_tree[:-1] + bytes([root_tree[-1] ^ 1])).decode(
        "ascii"
    )
    _rehash(value)

    with pytest.raises(ValueError, match="Git proof tree binding"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("proof_options", "message"),
    (
        ({"ledger_name": b"other.json"}, "path binding"),
        ({"ledger_mode": b"100755"}, "path binding"),
        ({"ledger_entry_oid": "f" * 40}, "ledger binding"),
        (
            {"directory_modes": (b"100644", b"40000", b"40000")},
            "path binding",
        ),
        ({"gitlink_mode": b"100644"}, "gitlink binding"),
        ({"gitlink_entry_oid": "f" * 40}, "gitlink binding"),
    ),
)
def test_schema_5_rejects_authenticated_wrong_git_path_or_gitlink(
    proof_options: dict[str, Any],
    message: str,
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    allocation = value["cohort_allocation"]
    lab_commit, proof = _cohort_git_proof(
        ledger_blob_oid=allocation["ledger_git_blob_oid"],
        neqo_gitlink=allocation["neqo_gitlink"],
        **proof_options,
    )
    _replace_allocation_proof(value, lab_commit=lab_commit, proof=proof)

    with pytest.raises(ValueError, match=message):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_rehashed_claim_snapshot_digest() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_claim"]["payload_sha256"] = "0" * 64
    _rehash(value)

    with pytest.raises(ValueError, match="claim snapshot digest"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("mutation", ("missing", "extra"))
def test_schema_5_requires_exact_claim_snapshot_keys(mutation: str) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    if mutation == "missing":
        value["cohort_claim"].pop("registry")
    else:
        value["cohort_claim"]["unexpected"] = None
    _rehash(value)

    with pytest.raises(ValueError, match="claim snapshot schema"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("schema_version", True),
        ("schema_version", 2),
        ("artifact_type", "qcsd-buflo-study-cohort-claim-publication-v2"),
        ("policy", "dense-prefix-receipts-only-v1"),
        ("cohort_version", 35),
    ),
)
def test_schema_5_rejects_invalid_claim_snapshot_contract(
    field: str,
    replacement: Any,
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_claim"][field] = replacement
    _rehash_cohort_snapshot(value)

    with pytest.raises(ValueError, match="claim snapshot digest"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("mutation", "replacement"),
    (
        ("registry-path", "artifacts/buflo-study/other"),
        ("claim-path", "artifacts/buflo-study/cohort-claims-v1/claim-v35.json"),
        ("head-version", 35),
        ("head-sha", "0" * 64),
    ),
)
def test_schema_5_rejects_invalid_claim_snapshot_path_or_head_binding(
    mutation: str,
    replacement: Any,
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    snapshot = value["cohort_claim"]
    if mutation == "registry-path":
        snapshot["registry"]["path"] = replacement
    elif mutation == "claim-path":
        snapshot["claim"]["path"] = replacement
    elif mutation == "head-version":
        snapshot["registry_head_at_publication"]["cohort_version"] = replacement
    else:
        snapshot["registry_head_at_publication"]["sha256"] = replacement
    _rehash_cohort_snapshot(value)

    with pytest.raises(ValueError, match="claim snapshot binding"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("target", "field", "replacement", "message"),
    (
        ("registry", "mode", 0o755, "claim registry stat"),
        ("registry", "dev", True, "claim registry stat"),
        ("claim", "mode", 0o644, "claim file stat"),
        ("claim", "nlink", 2, "claim file stat"),
        ("claim", "size", 1, "claim file stat"),
    ),
)
def test_schema_5_rejects_invalid_claim_snapshot_stat_binding(
    target: str,
    field: str,
    replacement: Any,
    message: str,
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_claim"][target]["stat"][field] = replacement
    _rehash_cohort_snapshot(value)

    with pytest.raises(ValueError, match=message):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("replacement", ("%%%%", "ZE==", ""))
def test_schema_5_rejects_noncanonical_claim_file_encoding(replacement: str) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_claim"]["claim"]["payload_base64"] = replacement
    _rehash_cohort_snapshot(value)

    with pytest.raises(ValueError, match="snapshot claim encoding"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_rehashed_claim_file_digest() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_claim"]["claim"]["sha256"] = "0" * 64
    value["cohort_claim"]["registry_head_at_publication"]["sha256"] = "0" * 64
    _rehash_cohort_snapshot(value)

    with pytest.raises(ValueError, match="claim file SHA-256"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_noncanonical_claim_file_bytes() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    raw = base64.b64decode(value["cohort_claim"]["claim"]["payload_base64"])
    _install_cohort_claim_raw(value, raw.removesuffix(b"\n"))

    with pytest.raises(ValueError, match="claim bytes are not canonical"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_duplicate_keys_in_claim_file() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    _install_cohort_claim_raw(
        value,
        b'{"schema_version":1,"schema_version":1}\n',
    )

    with pytest.raises(ValueError, match="finite unique-key JSON"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("schema_version", True),
        ("schema_version", 2),
        ("artifact_type", "qcsd-buflo-study-cohort-claim-v2"),
    ),
)
def test_schema_5_rejects_invalid_embedded_claim_schema(
    field: str,
    replacement: Any,
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    claim = _embedded_cohort_claim(value)
    claim[field] = replacement
    _install_cohort_claim(value, claim)

    with pytest.raises(ValueError, match="cohort claim schema"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_rehashed_embedded_claim_payload_digest() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    claim = _embedded_cohort_claim(value)
    claim["payload_sha256"] = "0" * 64
    _install_cohort_claim(value, claim)

    with pytest.raises(ValueError, match="cohort claim payload"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("policy", "dense-prefix-receipts-only-v1"),
        ("registry_path", "artifacts/buflo-study/other"),
        ("cohort_version", 35),
    ),
)
def test_schema_5_rejects_invalid_embedded_claim_payload_contract(
    field: str,
    replacement: Any,
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    claim = _embedded_cohort_claim(value)
    claim["payload"][field] = replacement
    claim["payload_sha256"] = _canonical_digest(claim["payload"])
    _install_cohort_claim(value, claim)

    with pytest.raises(ValueError, match="cohort claim payload"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("mutation", ("receipt", "git", "filesystem"))
def test_schema_5_rejects_rehashed_claim_authority_divergence(mutation: str) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    claim = _embedded_cohort_claim(value)
    authority = claim["payload"]["authority"]
    if mutation == "receipt":
        authority["receipt"]["allocated_version"] = 35
    elif mutation == "git":
        authority["git"]["head_blob_oid"] = "f" * 40
    else:
        authority["filesystem"]["ledger"]["size"] += 1
    claim["payload"]["authority_sha256"] = _canonical_digest(authority)
    claim["payload_sha256"] = _canonical_digest(claim["payload"])
    _install_cohort_claim(value, claim)

    with pytest.raises(ValueError, match="cohort claim .*authority|authority ledger stat"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_rehashed_claim_authority_digest() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    claim = _embedded_cohort_claim(value)
    claim["payload"]["authority_sha256"] = "0" * 64
    claim["payload_sha256"] = _canonical_digest(claim["payload"])
    _install_cohort_claim(value, claim)

    with pytest.raises(ValueError, match="claim authority digest"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("binding", ("source", "ledger"))
def test_schema_5_rejects_rehashed_claim_source_or_ledger_binding(binding: str) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    claim = _embedded_cohort_claim(value)
    if binding == "source":
        claim["payload"]["source"]["lab_commit"] = "f" * 40
    else:
        claim["payload"]["ledger"]["sha256"] = "0" * 64
    claim["payload_sha256"] = _canonical_digest(claim["payload"])
    _install_cohort_claim(value, claim)

    with pytest.raises(ValueError, match=f"claim {binding} binding"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    "replacement",
    (
        {
            "kind": "cohort-claim",
            "cohort_version": 33,
            "sha256": "9" * 64,
        },
        {
            "kind": "genesis-ledger",
            "cohort_version": 32,
            "sha256": "9" * 64,
        },
    ),
)
def test_schema_5_rejects_invalid_claim_predecessor(
    replacement: dict[str, Any],
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    claim = _embedded_cohort_claim(value)
    claim["payload"]["predecessor"] = replacement
    claim["payload_sha256"] = _canonical_digest(claim["payload"])
    _install_cohort_claim(value, claim)

    with pytest.raises(ValueError, match="claim predecessor"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_resealed_free_form_predecessor_digest() -> None:
    value = _build_receipt(
        schema_version=5,
        host_storage_preflight=_non_wsl_preflight(),
        cohort_version=62,
    )
    claim = _embedded_cohort_claim(value)
    claim["payload"]["predecessor"]["sha256"] = "8" * 64
    claim["payload_sha256"] = _canonical_digest(claim["payload"])
    raw = (
        json.dumps(claim, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("ascii")
    _install_cohort_claim_raw(value, raw)
    digest = hashlib.sha256(raw).hexdigest()
    chain = value["cohort_claim_chain"]
    chain["claims"][-1] = {
        "cohort_version": 62,
        "sha256": digest,
        "payload_base64": base64.b64encode(raw).decode("ascii"),
    }
    chain["head"]["sha256"] = digest
    _rehash_cohort_chain(value)

    with pytest.raises(ValueError, match="claim predecessor"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("mutation", ("missing", "gap", "reordered"))
def test_schema_5_requires_exact_dense_closed_claim_chain(mutation: str) -> None:
    value = _build_receipt(
        schema_version=5,
        host_storage_preflight=_non_wsl_preflight(),
        cohort_version=37,
    )
    claims = value["cohort_claim_chain"]["claims"]
    if mutation == "missing":
        claims.pop(0)
    elif mutation == "gap":
        claims[1]["cohort_version"] += 1
    else:
        claims[0], claims[1] = claims[1], claims[0]
    _rehash_cohort_chain(value)

    with pytest.raises(ValueError, match="claim-chain (inventory|entry)"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_oversized_claim_span_before_materialising_versions() -> None:
    value = _build_receipt(
        schema_version=5,
        host_storage_preflight=_non_wsl_preflight(),
    )
    allocation = value["cohort_allocation"]
    oversized_version = (
        allocation["last_consumed_version"]
        + build_storage._COHORT_CLAIM_CHAIN_MAX_ENTRIES
        + 1
    )

    with pytest.raises(ValueError, match="claim-chain inventory"):
        build_storage._validate_cohort_claim_chain(
            value["cohort_claim_chain"],
            allocation=allocation,
            cohort_version=oversized_version,
            current_snapshot=value["cohort_claim"],
        )


def test_schema_5_claim_chain_tail_must_equal_publication_snapshot() -> None:
    value = _build_receipt(
        schema_version=5,
        host_storage_preflight=_non_wsl_preflight(),
    )
    value["cohort_claim_chain"]["head"]["sha256"] = "8" * 64
    _rehash_cohort_chain(value)

    with pytest.raises(ValueError, match="claim-chain head binding"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_independently_validates_earlier_claim_authority() -> None:
    value = _build_receipt(
        schema_version=5,
        host_storage_preflight=_non_wsl_preflight(),
        cohort_version=37,
    )
    earlier_entry = value["cohort_claim_chain"]["claims"][1]
    earlier_claim = json.loads(
        base64.b64decode(earlier_entry["payload_base64"], validate=True)
    )
    earlier_claim["payload"]["authority"]["filesystem"]["ledger"]["mode"] = 0o666
    earlier_entry["payload_base64"] = base64.b64encode(
        (
            json.dumps(
                earlier_claim,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
    ).decode("ascii")
    _reseal_claim_chain_from(value, 1)

    with pytest.raises(ValueError, match="claim filesystem authority"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("mutation", ("missing", "extra", "reordered"))
def test_schema_5_requires_exact_ordered_nine_reproofs(mutation: str) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    rows = value["cohort_authority_reproofs"]
    if mutation == "missing":
        rows.pop()
    elif mutation == "extra":
        rows.append(dict(rows[-1]))
    else:
        rows[0], rows[1] = rows[1], rows[0]
    _rehash(value)

    with pytest.raises(ValueError, match="reproof inventory|reproof is invalid"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("boundary", "unknown"),
        ("authority_sha256", "0" * 64),
        ("claim_snapshot_sha256", "0" * 64),
        ("claim_file_sha256", "0" * 64),
    ),
)
def test_schema_5_rejects_rehashed_reproof_binding(
    field: str,
    replacement: str,
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_authority_reproofs"][0][field] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match="reproof is invalid"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("mutation", ("missing", "extra"))
def test_schema_5_requires_exact_reproof_row_keys(mutation: str) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    row = value["cohort_authority_reproofs"][0]
    if mutation == "missing":
        row.pop("claim_file_sha256")
    else:
        row["unexpected"] = None
    _rehash(value)

    with pytest.raises(ValueError, match="reproof is invalid"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    "replacement",
    (
        "not-a-time",
        "2026-09-01T00:00:01.100000",
        "2026-09-01T00:00:00.900000+00:00",
        "2026-09-01T00:00:05.100000+00:00",
        "2026-09-01T00:00:01.200000+00:00",
    ),
)
def test_schema_5_rejects_invalid_or_nonmonotonic_reproof_time(
    replacement: str,
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_authority_reproofs"][0]["observed_at"] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match="reproof|timestamp"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_final_reproof_before_after_reference_observation() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_authority_reproofs"][-1]["observed_at"] = (
        "2026-09-01T00:00:04.800000+00:00"
    )
    _rehash(value)

    with pytest.raises(ValueError, match="stage timeline"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("reproof_index", "observed_at"),
    (
        (4, "2026-09-01T00:00:01.550000+00:00"),
        (5, "2026-09-01T00:00:01.450000+00:00"),
        (5, "2026-09-01T00:00:02.050000+00:00"),
        (6, "2026-09-01T00:00:01.950000+00:00"),
        (6, "2026-09-01T00:00:03.050000+00:00"),
        (7, "2026-09-01T00:00:02.950000+00:00"),
        (7, "2026-09-01T00:00:04.925000+00:00"),
    ),
)
def test_schema_5_rejects_each_crossed_build_stage_boundary(
    reproof_index: int,
    observed_at: str,
) -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["cohort_authority_reproofs"][reproof_index]["observed_at"] = observed_at
    _rehash(value)

    with pytest.raises(ValueError, match="stage timeline"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("storage_index", "observed_at"),
    (
        (0, "2026-09-01T00:00:01.075000+00:00"),
        (0, "2026-09-01T00:00:01.225000+00:00"),
        (1, "2026-09-01T00:00:01.975000+00:00"),
        (1, "2026-09-01T00:00:02.225000+00:00"),
        (2, "2026-09-01T00:00:02.975000+00:00"),
        (2, "2026-09-01T00:00:03.225000+00:00"),
        (3, "2026-09-01T00:00:04.875000+00:00"),
        (3, "2026-09-01T00:00:04.975000+00:00"),
    ),
)
def test_schema_5_rejects_each_crossed_storage_stage_boundary(
    storage_index: int,
    observed_at: str,
) -> None:
    value = _build_receipt(
        schema_version=5,
        host_storage_preflight=_post_start_wsl_preflight(),
    )
    value["host_storage_preflight"]["observations"][storage_index][
        "observed_at"
    ] = observed_at
    _rehash(value)

    with pytest.raises(ValueError, match="storage timeline"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_stale_final_reproof_before_receipt_publication() -> None:
    value = _build_receipt(schema_version=5, host_storage_preflight=_non_wsl_preflight())
    value["finished_at"] = "2026-09-01T00:00:08+00:00"
    value["duration_seconds"] = 7.0
    _rehash(value)

    with pytest.raises(ValueError, match="final cohort-authority reproof is not immediate"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_5_rejects_storage_observation_after_its_stage_reproof() -> None:
    preflight = _post_start_wsl_preflight()
    value = _build_receipt(schema_version=5, host_storage_preflight=preflight)
    value["host_storage_preflight"]["observations"][3]["observed_at"] = (
        "2026-09-01T00:00:04.975000+00:00"
    )
    _rehash(value)

    with pytest.raises(ValueError, match="storage timeline"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("schema_version", (1, 2, 3, 4))
def test_pre_schema_5_build_receipts_remain_allocation_free(
    schema_version: int,
) -> None:
    preflight = None if schema_version == 1 else _non_wsl_preflight()
    value = _build_receipt(
        schema_version=schema_version,
        host_storage_preflight=preflight,
    )

    validated = build_storage.validate_build_execution_envelope(value)

    for field in (
        "cohort_allocation",
        "cohort_claim",
        "cohort_claim_chain",
        "cohort_authority_reproofs",
    ):
        assert field not in value
        assert field not in validated


@pytest.mark.parametrize(
    ("field_path", "replacement", "message"),
    (
        (("buildx", "identity", "plugin", "mode"), True, "stat identity"),
        (("buildx", "identity", "resolved", "sha256"), "A" * 64, "safe root-owned"),
        (("buildx", "identity", "reported_plugin_path"), "docker-buildx", "canonical path"),
        (("buildx", "identity", "reported_plugin_version"), "v0.29.0", "version binding"),
        (("buildx", "observations", 2, "boundary"), "after-reference", "observation"),
        (("buildx", "observations", 1, "observed_at"), True, "observation"),
    ),
)
def test_schema_4_rejects_rehashed_malformed_buildx_data(
    field_path: tuple[str | int, ...], replacement: Any, message: str
) -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    target: Any = value
    for component in field_path[:-1]:
        target = target[component]
    target[field_path[-1]] = replacement
    _rehash_buildx_receipt(value)

    with pytest.raises(ValueError, match=message):
        build_storage.validate_build_execution_envelope(value)


def test_schema_4_rejects_extra_buildx_field_and_boundary_reordering() -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["unexpected"] = None
    _rehash(value)
    with pytest.raises(ValueError, match="provenance schema"):
        build_storage.validate_build_execution_envelope(value)

    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["identity"]["unexpected"] = None
    _rehash_buildx_receipt(value)
    with pytest.raises(ValueError, match="identity schema"):
        build_storage.validate_build_execution_envelope(value)

    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["observations"][1]["observed_at"] = value["buildx"]["observations"][0][
        "observed_at"
    ]
    _rehash(value)
    with pytest.raises(ValueError, match="strictly increasing"):
        build_storage.validate_build_execution_envelope(value)

    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["observations"][2]["identity_sha256"] = "1" * 64
    _rehash(value)
    with pytest.raises(ValueError, match="observation"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_4_accepts_a_direct_regular_system_plugin() -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    identity = value["buildx"]["identity"]
    identity["resolved"]["path"] = identity["reported_plugin_path"]
    identity["plugin"] = {
        "path": identity["reported_plugin_path"],
        "symlink_target": None,
        **{key: identity["resolved"][key] for key in build_storage._BUILDX_STAT_KEYS},
    }
    _rehash_buildx_receipt(value)

    validated = build_storage.validate_build_execution_envelope(value)

    assert validated["buildx"]["identity"]["plugin"]["symlink_target"] is None


def test_build_receipt_schema_selection_is_validation_order_independent() -> None:
    values = (
        _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight()),
        _build_receipt(schema_version=1),
        _build_receipt(schema_version=3, host_storage_preflight=_non_wsl_preflight()),
        _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight()),
    )

    assert [
        build_storage.validate_build_execution_envelope(value)["schema_version"] for value in values
    ] == [4, 1, 3, 4]


def test_build_receipt_schema4_requires_buildx_and_schema3_forbids_it() -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value.pop("buildx")
    _rehash(value)
    with pytest.raises(ValueError, match="receipt schema"):
        build_storage.validate_build_execution_envelope(value)

    value = _build_receipt(schema_version=3, host_storage_preflight=_non_wsl_preflight())
    value["buildx"] = _buildx_provenance()
    _rehash(value)
    with pytest.raises(ValueError, match="receipt schema"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("schema_version", ([], {}))
def test_build_receipt_rejects_unhashable_schema_values_as_invalid(
    schema_version: object,
) -> None:
    value = _build_receipt(schema_version=1)
    value["schema_version"] = schema_version
    _rehash(value)

    with pytest.raises(ValueError, match="receipt schema"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("section", "field", "replacement"),
    (
        ("plugin", "uid", 1),
        ("plugin", "gid", 1),
        ("plugin", "nlink", 2),
        ("resolved", "uid", 1),
        ("resolved", "gid", 1),
        ("resolved", "nlink", 2),
        ("resolved", "mode", stat.S_IFREG | 0o644),
        ("resolved", "mode", stat.S_IFREG | stat.S_ISUID | 0o755),
        ("resolved", "mode", stat.S_IFREG | stat.S_ISGID | 0o755),
        ("resolved", "mode", stat.S_IFREG | 0o775),
        ("resolved", "mode", stat.S_IFREG | 0o757),
    ),
)
def test_schema4_rejects_unsafe_buildx_stat_and_mode_data(
    section: str, field: str, replacement: int
) -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["identity"][section][field] = replacement
    _rehash_buildx_receipt(value)

    with pytest.raises(ValueError, match="safe root-owned executable"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("mutation", ("plugin-path", "symlink-target", "resolved-path"))
def test_schema4_rejects_buildx_lexical_and_resolved_path_mismatch(mutation: str) -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    identity = value["buildx"]["identity"]
    if mutation == "plugin-path":
        identity["plugin"]["path"] = "/usr/lib/docker/cli-plugins/docker-buildx"
        message = "path binding"
    elif mutation == "symlink-target":
        replacement = "/opt/docker/buildx-v0.29.1"
        identity["plugin"]["symlink_target"] = replacement
        identity["plugin"]["size"] = len(replacement.encode())
        message = "symlink target differs"
    else:
        identity["resolved"]["path"] = "/opt/docker/buildx-v0.29.1"
        message = "symlink target differs"
    _rehash_buildx_receipt(value)

    with pytest.raises(ValueError, match=message):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        (
            "version_output",
            "github.com/docker/buildx v0.29.1-desktop.1 28f6246ff24e2c05095e8741e48c48dcb2d3b4bc\r",
        ),
        (
            "version_output",
            "github.com/docker/buildx v0.29.1-desktop.1 "
            "28f6246ff24e2c05095e8741e48c48dcb2d3b4bc\nsecond line",
        ),
        ("version", "v0.29.0"),
        ("commit", "F" * 40),
    ),
)
def test_schema4_rejects_nonexact_or_mismatched_buildx_version(
    field: str, replacement: str
) -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["identity"][field] = replacement
    _rehash_buildx_receipt(value)

    with pytest.raises(ValueError, match="version binding"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("index", "observed_at"),
    (
        (0, "2026-09-01T00:00:00.900000+00:00"),
        (3, "2026-09-01T00:00:05.100000+00:00"),
    ),
)
def test_schema4_rejects_buildx_observation_outside_build(index: int, observed_at: str) -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["observations"][index]["observed_at"] = observed_at
    _rehash(value)

    with pytest.raises(ValueError, match="outside the build"):
        build_storage.validate_build_execution_envelope(value)


def test_buildx_provenance_timing_endpoints_are_both_or_neither() -> None:
    provenance = _buildx_provenance()
    started = datetime.fromisoformat("2026-09-01T00:00:01+00:00")
    finished = datetime.fromisoformat("2026-09-01T00:00:05+00:00")

    assert build_storage.validate_buildx_provenance(provenance) == provenance
    assert (
        build_storage.validate_buildx_provenance(
            provenance,
            started_at=started,
            finished_at=finished,
        )
        == provenance
    )
    with pytest.raises(ValueError, match="both build endpoints"):
        build_storage.validate_buildx_provenance(provenance, started_at=started)
    with pytest.raises(ValueError, match="both build endpoints"):
        build_storage.validate_buildx_provenance(provenance, finished_at=finished)


@pytest.mark.parametrize("mutation", ("missing", "extra", "duplicate", "absent"))
def test_capture_rejects_nonexact_or_nonunique_docker_buildx_metadata(
    mutation: str,
) -> None:
    metadata = _docker_buildx_metadata("/usr/local/lib/docker/cli-plugins/docker-buildx")
    plugins = [metadata]
    if mutation == "missing":
        metadata.pop("Vendor")
        message = "exact healthy schema"
    elif mutation == "extra":
        metadata["Err"] = "plugin failed"
        message = "exact healthy schema"
    elif mutation == "duplicate":
        plugins.append(dict(metadata))
        message = "exactly one buildx"
    else:
        metadata["Name"] = "compose"
        message = "exactly one buildx"

    with pytest.raises(ValueError, match=message):
        build_storage.capture_buildx_observation(
            plugins,
            version_output=(
                "github.com/docker/buildx v0.29.1-desktop.1 "
                "28f6246ff24e2c05095e8741e48c48dcb2d3b4bc"
            ),
        )


@pytest.mark.parametrize(
    "raw",
    (
        b"github.com/docker/buildx v0.29.1 deadbeef\r\n",
        b"github.com/docker/buildx v0.29.1 deadbeef\nsecond line\n",
    ),
)
def test_buildx_version_file_requires_one_lf_terminated_or_unterminated_line(
    raw: bytes,
) -> None:
    with pytest.raises(ValueError, match="exactly one line"):
        build_storage._one_version_output_line(raw)


def test_capture_buildx_observation_records_one_stable_symlink_identity(
    tmp_path: Path,
) -> None:
    plugin_root = tmp_path / "cli-plugins"
    target_root = tmp_path / "docker-desktop"
    plugin_root.mkdir()
    target_root.mkdir()
    target = target_root / "buildx-v0.29.1"
    target.write_bytes(b"fixture buildx\n")
    target.chmod(0o755)
    plugin = plugin_root / "docker-buildx"
    plugin.symlink_to(target)
    version = "v0.29.1-desktop.1"
    commit = "28f6246ff24e2c05095e8741e48c48dcb2d3b4bc"
    metadata = [_docker_buildx_metadata(str(plugin))]

    observation = build_storage.capture_buildx_observation(
        metadata,
        version_output=f"github.com/docker/buildx {version} {commit}",
        allowed_plugin_directories=frozenset({PurePosixPath(str(plugin_root))}),
        required_uid=os.getuid(),
        required_gid=os.getgid(),
    )

    assert observation["identity"]["reported_plugin_path"] == str(plugin)
    assert observation["identity"]["plugin"]["symlink_target"] == str(target)
    assert (
        observation["identity"]["resolved"]["sha256"]
        == hashlib.sha256(target.read_bytes()).hexdigest()
    )
    assert observation["identity_sha256"] == _canonical_digest(observation["identity"])
    assert observation["observed_at"].endswith("+00:00")


def test_buildx_observation_cli_reads_exact_regular_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plugins = tmp_path / "plugins.json"
    version = tmp_path / "version.txt"
    metadata = [_docker_buildx_metadata("/usr/local/lib/docker/cli-plugins/docker-buildx")]
    plugins.write_text(json.dumps(metadata), encoding="utf-8")
    version_output = (
        "github.com/docker/buildx v0.29.1-desktop.1 28f6246ff24e2c05095e8741e48c48dcb2d3b4bc"
    )
    version.write_text(version_output + "\n", encoding="utf-8")
    observed = {
        "observed_at": "2026-09-01T00:00:00+00:00",
        "identity": {},
        "identity_sha256": "1" * 64,
    }

    def capture(value: Any, *, version_output: str) -> dict[str, Any]:
        assert value == metadata
        assert version_output == (
            "github.com/docker/buildx v0.29.1-desktop.1 28f6246ff24e2c05095e8741e48c48dcb2d3b4bc"
        )
        return observed

    monkeypatch.setattr(build_storage, "capture_buildx_observation", capture)

    assert (
        build_storage._main(
            [
                "buildx-observation",
                "--plugins-json",
                str(plugins),
                "--version-output",
                str(version),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == observed


def test_buildx_observation_cli_rejects_duplicate_json_keys(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plugins = tmp_path / "plugins.json"
    version = tmp_path / "version.txt"
    plugins.write_text(
        "["
        '{"Name":"buildx","Name":"buildx",'
        '"Path":"/usr/local/lib/docker/cli-plugins/docker-buildx",'
        '"SchemaVersion":"0.1.0","ShortDescription":"Docker Buildx",'
        '"Vendor":"Docker Inc.","Version":"v0.29.1-desktop.1"}'
        "]",
        encoding="utf-8",
    )
    version.write_text(
        "github.com/docker/buildx v0.29.1-desktop.1 28f6246ff24e2c05095e8741e48c48dcb2d3b4bc\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as error:
        build_storage._main(
            [
                "buildx-observation",
                "--plugins-json",
                str(plugins),
                "--version-output",
                str(version),
            ]
        )

    assert error.value.code == 1
    assert "duplicate key: Name" in capsys.readouterr().err


def test_load_stable_build_execution_returns_the_exact_bytes_it_parsed(
    tmp_path: Path,
) -> None:
    receipt = tmp_path / "build-execution.json"
    raw = b'{\n  "schema_version": 1,\n  "label": "\\u0061"\n}\n'
    receipt.write_bytes(raw)

    resolved, observed_raw, value = build_storage.load_stable_build_execution(receipt)

    assert resolved == receipt.resolve()
    assert observed_raw == raw
    assert hashlib.sha256(observed_raw).hexdigest() == hashlib.sha256(raw).hexdigest()
    assert value == {"schema_version": 1, "label": "a"}


def test_current_build_admission_requires_and_validates_completion(
    tmp_path: Path,
) -> None:
    receipt, completion, _receipt_value, completion_value = _write_current_build_pair(
        tmp_path
    )

    resolved, raw, _value, validated, projected_completion = (
        build_storage.load_validated_build_execution(
            receipt,
            expected_cohort_version=34,
            expected_probe_sha256=PROBE_SHA256,
            expected_build_root=Path("/workspace/neqo-qcsd-lab"),
            require_current=True,
        )
    )

    assert resolved == receipt.resolve()
    assert hashlib.sha256(raw).hexdigest() == completion_value["receipt"]["sha256"]
    assert validated["schema_version"] == 5
    assert projected_completion == completion_value
    assert build_storage.build_completion_path(receipt, 34) == completion


@pytest.mark.parametrize(
    "field",
    ("dev", "inode", "uid", "gid", "mtime_ns", "ctime_ns"),
)
def test_current_build_completion_accepts_volatile_bind_mount_stat_drift(
    tmp_path: Path,
    field: str,
) -> None:
    receipt, completion, receipt_value, completion_value = _write_current_build_pair(
        tmp_path
    )
    receipt_raw = receipt.read_bytes()
    observed_stat = build_storage._completion_file_stat_record(receipt.stat())
    observed_stat[field] += 101

    validated = build_storage.validate_build_completion_authority(
        completion_value,
        completion_path=completion,
        receipt_path=receipt,
        receipt_raw=receipt_raw,
        receipt_value=receipt_value,
        receipt_stat=observed_stat,
        expected_cohort_version=34,
    )

    assert validated["receipt"] == completion_value["receipt"]


def test_completion_publication_policy_rejects_volatile_receipt_stat_drift(
    tmp_path: Path,
) -> None:
    receipt, completion, receipt_value, completion_value = _write_current_build_pair(
        tmp_path
    )
    observed_stat = build_storage._completion_file_stat_record(receipt.stat())
    observed_stat["inode"] += 1

    with pytest.raises(ValueError, match="receipt binding"):
        build_storage.validate_build_completion_authority(
            completion_value,
            completion_path=completion,
            receipt_path=receipt,
            receipt_raw=receipt.read_bytes(),
            receipt_value=receipt_value,
            receipt_stat=observed_stat,
            expected_cohort_version=34,
            require_receipt_stat_identity=True,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (("mode", 0o644), ("nlink", 2), ("size", 1_000_000_000)),
)
def test_current_build_completion_rejects_unsafe_portable_receipt_metadata(
    tmp_path: Path,
    field: str,
    replacement: int,
) -> None:
    receipt, completion, receipt_value, completion_value = _write_current_build_pair(
        tmp_path
    )
    changed = json.loads(json.dumps(completion_value))
    changed["receipt"]["stat"][field] = replacement
    changed.pop("payload_sha256")
    changed["payload_sha256"] = _canonical_digest(changed)

    with pytest.raises(ValueError, match="receipt.*stat binding|receipt binding"):
        build_storage.validate_build_completion_authority(
            changed,
            completion_path=completion,
            receipt_path=receipt,
            receipt_raw=receipt.read_bytes(),
            receipt_value=receipt_value,
            receipt_stat=receipt.stat(),
            expected_cohort_version=34,
        )


def test_current_build_admission_rejects_precompletion_receipt(
    tmp_path: Path,
) -> None:
    receipt, completion, _receipt_value, _completion_value = _write_current_build_pair(
        tmp_path
    )
    completion.unlink()

    with pytest.raises(ValueError, match="build completion path cannot be resolved"):
        build_storage.load_validated_build_execution(
            receipt,
            expected_cohort_version=34,
            expected_probe_sha256=PROBE_SHA256,
            expected_build_root=Path("/workspace/neqo-qcsd-lab"),
            require_current=True,
        )


@pytest.mark.parametrize("schema_version", (1, 2, 3, 4))
def test_historical_build_receipts_require_an_explicit_admission_policy(
    tmp_path: Path,
    schema_version: int,
) -> None:
    receipt = tmp_path / f"build-execution-v34.json"
    preflight = None if schema_version == 1 else _non_wsl_preflight()
    value = _build_receipt(
        schema_version=schema_version,
        host_storage_preflight=preflight,
    )
    receipt.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    historical = build_storage.load_validated_build_execution(
        receipt,
        expected_cohort_version=34,
        expected_probe_sha256=(None if schema_version == 1 else PROBE_SHA256),
        expected_build_root=Path("/workspace/neqo-qcsd-lab"),
        require_current=False,
    )
    assert historical[3]["cohort_version"] == 34
    assert historical[4] is None
    with pytest.raises(ValueError, match="current build admission requires schema 5"):
        build_storage.load_validated_build_execution(
            receipt,
            expected_cohort_version=34,
            expected_probe_sha256=(None if schema_version == 1 else PROBE_SHA256),
            expected_build_root=Path("/workspace/neqo-qcsd-lab"),
            require_current=True,
        )


@pytest.mark.parametrize("target", ("receipt", "completion"))
def test_current_build_pair_rejects_byte_mutation_or_replacement(
    tmp_path: Path,
    target: str,
) -> None:
    receipt, completion, _receipt_value, _completion_value = _write_current_build_pair(
        tmp_path
    )
    selected = receipt if target == "receipt" else completion
    original = selected.read_bytes()
    selected.unlink()
    selected.write_bytes(original + b" ")
    selected.chmod(0o600)

    with pytest.raises(ValueError):
        build_storage.load_validated_build_execution(
            receipt,
            expected_cohort_version=34,
            expected_probe_sha256=PROBE_SHA256,
            expected_build_root=Path("/workspace/neqo-qcsd-lab"),
            require_current=True,
        )


@pytest.mark.parametrize(
    "mutation",
    ("guardian-alias", "lock-alias", "lease-root-mismatch"),
)
def test_current_build_pair_rejects_rehashed_transaction_authority_tamper(
    tmp_path: Path,
    mutation: str,
) -> None:
    receipt, completion, _receipt_value, completion_value = _write_current_build_pair(
        tmp_path
    )
    changed = json.loads(json.dumps(completion_value))
    transaction = changed["transaction"]
    if mutation == "guardian-alias":
        transaction["guardian"]["qcsd_pid"] = transaction["guardian"]["pid"]
    elif mutation == "lock-alias":
        transaction["operation_lock"]["inode"] = transaction["cohort_lock"][
            "inode"
        ]
    else:
        transaction["lifecycle_lock"]["lease_nonce"] = "6" * 64
    changed.pop("payload_sha256")
    changed["payload_sha256"] = _canonical_digest(changed)
    completion.write_bytes(
        build_storage._canonical_finite_json_bytes(
            changed, label="tampered build completion", newline=True
        )
    )
    completion.chmod(0o600)

    with pytest.raises(ValueError, match="transaction"):
        build_storage.load_validated_build_execution(
            receipt,
            expected_cohort_version=34,
            expected_probe_sha256=PROBE_SHA256,
            expected_build_root=Path("/workspace/neqo-qcsd-lab"),
            require_current=True,
        )


def test_completion_publisher_is_create_only_and_crash_residue_is_not_admissible(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "build-completion-v34.json"
    value = {"schema_version": 1, "artifact_type": "test"}
    first = build_storage._publish_private_create_only_json(destination, value)
    assert destination.read_bytes() == first
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert destination.stat().st_nlink == 1
    with pytest.raises(ValueError, match="already exists"):
        build_storage._publish_private_create_only_json(destination, value)

    residue = tmp_path / f".{destination.name}.{'a' * 64}.next"
    residue.write_bytes(first)
    residue.chmod(0o600)
    destination.unlink()
    with pytest.raises(ValueError, match="path cannot be resolved"):
        build_storage.load_stable_build_completion(destination)
    # A pre-link crash residue is not a completion and cannot authorise the
    # otherwise published schema-5 receipt.  A later cohort uses a fresh path.
    assert residue.exists()


def _write_live_build_transaction(
    root: Path, *, cohort_version: int = 34
) -> tuple[Path, Path, Path, str]:
    checkout = root / "checkout"
    receipt = checkout / f"artifacts/buflo-study/build-execution-v{cohort_version}.json"
    receipt.parent.mkdir(parents=True)
    lease_nonce = "7" * 64
    transaction = root / "lifecycle" / f"transaction.{lease_nonce[:32]}"
    transaction.mkdir(parents=True, mode=0o700)
    transaction.chmod(0o700)
    record = transaction / "SUPERVISION"
    fields = {
        "object": "docker-build-transaction",
        "lifecycle_schema": "1",
        "lifecycle_state": "request-authorised",
        "lifecycle_root": str(transaction),
        "lifecycle_token": lease_nonce[:32],
        "supervisor_source_path": str(checkout / "tools/docker_signal_supervisor.sh"),
        "supervisor_source_sha256": "8" * 64,
        "supervisor_source_device": "1",
        "supervisor_source_inode": "2",
        "docker_context": "default",
        "docker_host": "unix:///var/run/docker.sock",
        "docker_server_id": "test-daemon",
        "docker_request_revalidation": "in-scope-immediately-before-mutation",
        "docker_daemon_id": "test-daemon",
        "host_boot_id": "12345678-1234-1234-1234-123456789abc",
        "working_directory": str(checkout),
        "cohort_version": str(cohort_version),
        "receipt_path": str(receipt),
        "transaction_state": "uncommitted-static-tag-mutation",
    }
    record.write_bytes(
        "".join(
            f"{key}={fields[key]}\n"
            for key in build_storage._BUILD_TRANSACTION_RECORD_FIELDS
        ).encode("ascii")
    )
    record.chmod(0o600)
    return checkout, receipt, record, lease_nonce


def test_build_transaction_binding_captures_exact_private_inode_and_bytes(
    tmp_path: Path,
) -> None:
    checkout, receipt, record, lease_nonce = _write_live_build_transaction(tmp_path)

    binding = build_storage.capture_build_transaction_binding(
        record,
        expected_receipt=receipt,
        expected_checkout_root=checkout,
        expected_cohort_version=34,
        expected_lease_nonce=lease_nonce,
    )

    assert binding["root"]["stat"]["mode"] == 0o700
    assert binding["record"]["stat"]["mode"] == 0o600
    assert binding["record"]["stat"]["nlink"] == 1
    assert base64.b64decode(binding["record"]["payload_base64"]) == record.read_bytes()


@pytest.mark.parametrize("mutation", ("record-bytes", "root-replacement"))
def test_build_transaction_binding_rejects_toctou_after_stable_record_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    checkout, receipt, record, lease_nonce = _write_live_build_transaction(tmp_path)
    original = build_storage._read_stable_regular_file_with_stat

    def mutate_after_read(*args: Any, **kwargs: Any) -> tuple[bytes, os.stat_result]:
        raw, status = original(*args, **kwargs)
        if mutation == "record-bytes":
            record.write_bytes(raw + b"tamper=1\n")
            record.chmod(0o600)
        else:
            transaction = record.parent
            displaced = transaction.with_name(transaction.name + ".old")
            transaction.rename(displaced)
            transaction.mkdir(mode=0o700)
            replacement = transaction / "SUPERVISION"
            replacement.write_bytes(raw)
            replacement.chmod(0o600)
        return raw, status

    monkeypatch.setattr(
        build_storage, "_read_stable_regular_file_with_stat", mutate_after_read
    )
    with pytest.raises(ValueError, match="changed while captured"):
        build_storage.capture_build_transaction_binding(
            record,
            expected_receipt=receipt,
            expected_checkout_root=checkout,
            expected_cohort_version=34,
            expected_lease_nonce=lease_nonce,
        )


def test_load_stable_build_execution_rejects_a_final_path_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    receipt = tmp_path / "build-execution.json"
    receipt.symlink_to(target)

    with pytest.raises(ValueError, match="cannot be a symlink"):
        build_storage.load_stable_build_execution(receipt)


def test_load_stable_build_execution_rejects_a_parent_path_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "build-execution.json").write_text("{}", encoding="utf-8")
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="path contains a symlink"):
        build_storage.load_stable_build_execution(alias / "build-execution.json")


def test_load_stable_build_execution_rejects_duplicate_keys_at_any_depth(
    tmp_path: Path,
) -> None:
    receipt = tmp_path / "build-execution.json"
    receipt.write_text(
        '{"schema_version":1,"nested":{"digest":"a","digest":"b"}}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate key: digest"):
        build_storage.load_stable_build_execution(receipt)


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_load_stable_build_execution_rejects_non_json_numeric_constants(
    tmp_path: Path,
    constant: str,
) -> None:
    receipt = tmp_path / "build-execution.json"
    receipt.write_text(f'{{"value":{constant}}}', encoding="utf-8")

    with pytest.raises(ValueError, match="invalid constant"):
        build_storage.load_stable_build_execution(receipt)


def test_load_stable_build_execution_rejects_non_utf8_input(tmp_path: Path) -> None:
    receipt = tmp_path / "build-execution.json"
    receipt.write_bytes(b'{"value":"\xff"}')

    with pytest.raises(ValueError, match="not unique-key UTF-8 JSON"):
        build_storage.load_stable_build_execution(receipt)


def test_load_stable_build_execution_enforces_the_size_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = tmp_path / "build-execution.json"
    receipt.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(build_storage, "BUILD_EXECUTION_MAX_BYTES", 1)

    with pytest.raises(ValueError, match="not a stable single regular file"):
        build_storage.load_stable_build_execution(receipt)


@pytest.mark.parametrize("kind", ("directory", "hard-link"))
def test_load_stable_build_execution_requires_one_regular_link(
    tmp_path: Path,
    kind: str,
) -> None:
    receipt = tmp_path / "build-execution.json"
    if kind == "directory":
        receipt.mkdir()
    else:
        source = tmp_path / "source.json"
        source.write_text("{}", encoding="utf-8")
        os.link(source, receipt)

    with pytest.raises(ValueError, match="not a stable single regular file"):
        build_storage.load_stable_build_execution(receipt)


def test_load_stable_build_execution_rejects_a_change_during_its_single_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = tmp_path / "build-execution.json"
    receipt.write_text('{"schema_version":1}', encoding="utf-8")
    real_read = os.read
    changed = False

    def read_then_change(descriptor: int, count: int) -> bytes:
        nonlocal changed
        chunk = real_read(descriptor, count)
        if not changed:
            changed = True
            with receipt.open("ab") as stream:
                stream.write(b" ")
        return chunk

    monkeypatch.setattr(build_storage.os, "read", read_then_change)

    with pytest.raises(ValueError, match="changed while it was read"):
        build_storage.load_stable_build_execution(receipt)


def test_load_stable_build_execution_rejects_parent_directory_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "evidence"
    parent.mkdir()
    receipt = parent / "build-execution.json"
    raw = b'{"schema_version":1}'
    receipt.write_bytes(raw)
    detached = tmp_path / "detached-evidence"
    real_read = os.read
    replaced = False

    def read_then_replace_parent(descriptor: int, count: int) -> bytes:
        nonlocal replaced
        chunk = real_read(descriptor, count)
        if chunk and not replaced:
            replaced = True
            parent.rename(detached)
            parent.mkdir()
            (parent / receipt.name).write_bytes(raw)
        return chunk

    monkeypatch.setattr(build_storage.os, "read", read_then_replace_parent)

    with pytest.raises(ValueError, match="changed while it was read"):
        build_storage.load_stable_build_execution(receipt)


def test_stable_build_reader_allows_benign_parent_child_churn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "evidence"
    parent.mkdir()
    receipt = parent / "build-execution.json"
    raw = b'{"schema_version":1}'
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

    monkeypatch.setattr(build_storage.os, "stat", stat_after_churn)

    observed, _metadata = build_storage._read_stable_regular_file_with_stat(
        receipt,
        label="build execution",
    )

    assert churned
    assert observed == raw


def test_stable_build_reader_rejects_parent_mode_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "evidence"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    receipt = parent / "build-execution.json"
    receipt.write_text('{"schema_version":1}', encoding="utf-8")
    real_stat = os.stat
    drifted = False

    def stat_after_mode_drift(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal drifted
        if not drifted and path == parent.name and kwargs.get("dir_fd") is not None:
            drifted = True
            os.chmod(parent, 0o700)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(build_storage.os, "stat", stat_after_mode_drift)

    with pytest.raises(ValueError, match="changed while it was read"):
        build_storage._read_stable_regular_file_with_stat(
            receipt,
            label="build execution",
        )
    assert drifted


def test_stable_build_reader_rejects_same_mode_parent_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "evidence"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    receipt = parent / "build-execution.json"
    raw = b'{"schema_version":1}'
    receipt.write_bytes(raw)
    detached = tmp_path / "detached-evidence"
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

    monkeypatch.setattr(build_storage.os, "stat", stat_after_replacement)

    with pytest.raises(ValueError, match="changed while it was read"):
        build_storage._read_stable_regular_file_with_stat(
            receipt,
            label="build execution",
        )
    assert replaced


def test_schema_3_rejects_context_argv_even_when_rehashed() -> None:
    value = _build_receipt(schema_version=3, host_storage_preflight=_non_wsl_preflight())
    for command in value["commands"]:
        command["argv"][1:3] = ["--context", value["docker"]["context"]]
    _rehash(value)

    with pytest.raises(ValueError, match="--pull --no-cache"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_two_host_reader_binds_commands_to_the_exact_checkout(
    tmp_path: Path,
) -> None:
    (tmp_path / "neqo-qcsd").mkdir()
    dockerfile = tmp_path / "Dockerfile"
    uv_lock = tmp_path / "uv.lock"
    cargo_lock = tmp_path / "neqo-qcsd/Cargo.lock"
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")
    uv_lock.write_text("uv\n", encoding="utf-8")
    cargo_lock.write_text("cargo\n", encoding="utf-8")
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    value["dockerfile_sha256"] = hashlib.sha256(dockerfile.read_bytes()).hexdigest()
    value["build_inputs"]["uv_lock_sha256"] = hashlib.sha256(uv_lock.read_bytes()).hexdigest()
    value["build_inputs"]["cargo_lock_sha256"] = hashlib.sha256(cargo_lock.read_bytes()).hexdigest()
    for target in ("collection", "prepare"):
        value["role_provenance"]["build_inputs"][target] = dict(value["build_inputs"])
    for command in value["commands"]:
        iidfile_index = command["argv"].index("--iidfile") + 1
        command["argv"][iidfile_index] = str(
            tmp_path / "artifacts/buflo-study/.build-iids-v34.ABC123" / f"{command['target']}.iid"
        )
        command["argv"][-2] = str(dockerfile)
        command["argv"][-1] = str(tmp_path)
    _rehash(value)

    build_storage.validate_build_execution_envelope(
        value,
        expected_probe_sha256=PROBE_SHA256,
        checkout_root=tmp_path,
        expected_build_root=tmp_path,
    )

    for command in value["commands"]:
        iidfile_index = command["argv"].index("--iidfile") + 1
        command["argv"][iidfile_index] = (
            f"/unrelated/tree/artifacts/buflo-study/.build-iids-v34.ABC123/{command['target']}.iid"
        )
        command["argv"][-2] = "/unrelated/tree/Dockerfile"
        command["argv"][-1] = "/unrelated/tree"
    _rehash(value)
    with pytest.raises(ValueError, match="command root differs"):
        build_storage.validate_build_execution_envelope(
            value,
            expected_probe_sha256=PROBE_SHA256,
            checkout_root=tmp_path,
            expected_build_root=tmp_path,
        )


@pytest.mark.parametrize("mutation", ["missing", "unknown"])
def test_observation_rejects_missing_and_unknown_fields(mutation: str) -> None:
    value = _observation(*BOUNDARY_TIMES[0])
    if mutation == "missing":
        del value["file_system"]
    else:
        value["unexpected"] = None

    with pytest.raises(ValueError, match="observation schema is invalid"):
        _validate_observation(value)


@pytest.mark.parametrize("mutation", ["missing", "unknown"])
def test_preflight_rejects_missing_and_unknown_fields(mutation: str) -> None:
    value = _wsl_preflight()
    if mutation == "missing":
        del value["platform_detection"]
    else:
        value["unexpected"] = None

    with pytest.raises(ValueError, match="preflight schema is invalid"):
        build_storage.validate_build_host_storage_preflight(value)


@pytest.mark.parametrize("mutation", ["missing", "unknown"])
def test_platform_detection_rejects_missing_and_unknown_fields(mutation: str) -> None:
    value = _wsl_preflight()
    if mutation == "missing":
        del value["platform_detection"]["kernel_release"]
    else:
        value["platform_detection"]["unexpected"] = None

    with pytest.raises(ValueError, match="platform detection is invalid"):
        build_storage.validate_build_host_storage_preflight(value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("wsl_interop_env_present", 1),
        ("wsl_distro_name_env_present", 0),
        ("run_wsl_directory_present", "true"),
    ],
)
def test_platform_detection_rejects_non_boolean_signal_values(field: str, value: Any) -> None:
    preflight = _wsl_preflight()
    preflight["platform_detection"][field] = value

    with pytest.raises(ValueError, match="platform detection is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize("field", ["kernel_release", "proc_version"])
@pytest.mark.parametrize("value", [None, True, 1])
def test_platform_detection_rejects_non_string_version_signals(field: str, value: Any) -> None:
    preflight = _wsl_preflight()
    preflight["platform_detection"][field] = value

    with pytest.raises(ValueError, match="platform detection is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize("mutation", ["missing", "unknown"])
def test_build_envelope_rejects_missing_and_unknown_fields(mutation: str) -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    if mutation == "missing":
        del value["commands"]
    else:
        value["unexpected"] = None
    _rehash(value)

    with pytest.raises(ValueError, match="receipt schema is invalid"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("mutation", ["missing", "unknown"])
def test_schema_2_docker_identity_rejects_missing_and_unknown_fields(
    mutation: str,
) -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    if mutation == "missing":
        del value["docker"]["server_id"]
    else:
        value["docker"]["unexpected"] = "value"
    _rehash(value)

    with pytest.raises(ValueError, match="Docker identity is invalid"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    "volume_id",
    [
        "12345678-1234-1234-1234-123456789abc",
        "\\\\?\\Volume{12345678123412341234123456789abc}\\",
        "\\\\.\\Volume{12345678-1234-1234-1234-123456789abc}\\",
        "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}",
        "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\extra",
    ],
)
def test_observation_rejects_malformed_or_noncanonical_volume_guid(
    volume_id: str,
) -> None:
    value = _observation(*BOUNDARY_TIMES[0])
    value["backing_volume_unique_id"] = volume_id

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(value)


def test_available_space_threshold_is_inclusive_and_fail_closed_below_it() -> None:
    threshold = build_storage.BUILD_WSL_HOST_MIN_AVAILABLE_BYTES
    exact = _observation(*BOUNDARY_TIMES[0], available_bytes=threshold)
    assert _validate_observation(exact)["available_bytes"] == threshold

    below = _observation(*BOUNDARY_TIMES[0], available_bytes=threshold - 1)
    with pytest.raises(ValueError, match=rf"requires at least {threshold} available bytes"):
        _validate_observation(below)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", True),
        ("data_vhd_file_length_bytes", True),
        ("total_bytes", True),
        ("available_bytes", True),
    ],
)
def test_observation_rejects_boolean_integer_substitutions(field: str, value: bool) -> None:
    observation = _observation(*BOUNDARY_TIMES[0])
    observation[field] = value

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(observation)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("applicable", 1),
        ("required_available_bytes", True),
        ("passed", 1),
    ],
)
def test_preflight_rejects_boolean_substitutions(field: str, value: Any) -> None:
    preflight = _wsl_preflight()
    preflight[field] = value

    with pytest.raises(ValueError, match="preflight schema is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)


def test_preflight_rejects_boolean_minimum_summary() -> None:
    preflight = _wsl_preflight()
    preflight["minimum_available_bytes"] = True

    with pytest.raises(ValueError):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize(
    "location_source",
    ["", "local-appdata-guess", "wsl-logical-free-space"],
)
def test_observation_rejects_unreceipted_location_sources(
    location_source: str,
) -> None:
    value = _observation(*BOUNDARY_TIMES[0])
    value["location_source"] = location_source

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(value)


def test_build_envelope_rejects_source_collection_image_mismatch() -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    value["source"]["image_digest"] = "sha256:" + "f" * 64
    _rehash(value)

    with pytest.raises(ValueError, match="one concrete clean collection image"):
        build_storage.validate_build_execution_envelope(value)


def test_build_envelope_rejects_rehashed_cache_enabled_schema_2_receipt() -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    value["cache_policy"]["no_cache"] = False
    _rehash(value)

    with pytest.raises(ValueError):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("path", "drive_letter"),
    [
        ("relative\\docker_data.vhdx", "C"),
        ("C:/Docker/wsl/data/docker_data.vhdx", "C"),
        ("C:\\Docker\\..\\data\\docker_data.vhdx", "C"),
        ("C:\\Docker\\data\\docker_data.raw", "C"),
        ("C:\\Docker\\data\\docker_data.vhdx\\child", "C"),
        ("C:\\Docker\\data\\docker_data.vhdx", "D"),
    ],
)
def test_observation_rejects_noncanonical_or_mismatched_vhd_paths(
    path: str, drive_letter: str
) -> None:
    value = _observation(*BOUNDARY_TIMES[0])
    value["data_vhd_path"] = path
    value["drive_letter"] = drive_letter

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(value)


@pytest.mark.parametrize("probe_sha256", ["", "A" * 64, "1" * 63, "g" * 64])
def test_observation_rejects_malformed_probe_hash(probe_sha256: str) -> None:
    value = _observation(*BOUNDARY_TIMES[0])
    value["probe_sha256"] = probe_sha256

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(value)


def test_observation_rejects_probe_hash_different_from_source_file() -> None:
    value = _observation(*BOUNDARY_TIMES[0])

    with pytest.raises(ValueError, match="observation is invalid"):
        build_storage.validate_build_host_storage_observation(
            value,
            expected_boundary="before-collection",
            expected_probe_sha256="2" * 64,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("file_system", ""),
        ("health_status", "Warning"),
        ("operational_status", []),
        ("operational_status", ["OK", "Degraded"]),
        ("operational_status", "OK"),
    ],
)
def test_observation_rejects_unhealthy_or_ambiguous_volume_state(field: str, value: Any) -> None:
    observation = _observation(*BOUNDARY_TIMES[0])
    observation[field] = value

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(observation)


def test_observation_rejects_wrong_boundary() -> None:
    value = _observation(*BOUNDARY_TIMES[0])
    value["boundary"] = "before-prepare"

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("data_vhd_path", "D:\\Docker\\wsl\\data\\ext4.vhdx"),
        (
            "backing_volume_unique_id",
            "\\\\?\\Volume{87654321-4321-4321-4321-cba987654321}\\",
        ),
        ("location_source", "docker-settings-store"),
        ("file_system", "ReFS"),
        ("probe_sha256", "2" * 64),
    ],
)
def test_preflight_rejects_storage_identity_changes_mid_build(field: str, value: Any) -> None:
    preflight = _wsl_preflight()
    preflight["observations"][2][field] = value
    if field == "data_vhd_path":
        preflight["observations"][2]["drive_letter"] = "D"

    with pytest.raises(ValueError):
        build_storage.validate_build_host_storage_preflight(preflight)


def test_preflight_rejects_boundary_reordering() -> None:
    preflight = _wsl_preflight()
    preflight["observations"][1]["boundary"] = "before-reference"

    with pytest.raises(ValueError, match="observation is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)


def test_preflight_rejects_stale_minimum_summary() -> None:
    preflight = _wsl_preflight()
    preflight["minimum_available_bytes"] += 1

    with pytest.raises(ValueError, match="preflight is inconsistent"):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize(
    "mutation",
    ["non_wsl_marked_applicable", "wsl_marked_non_applicable", "observations_present"],
)
def test_preflight_rejects_platform_applicability_contradictions(
    mutation: str,
) -> None:
    preflight = _non_wsl_preflight()
    if mutation == "non_wsl_marked_applicable":
        preflight["applicable"] = True
        preflight["platform"] = "windows-wsl2"
    elif mutation == "wsl_marked_non_applicable":
        preflight["platform_detection"]["kernel_release"] = "6.6.87.2-microsoft-standard-WSL2"
    else:
        preflight["observations"] = [_observation(*BOUNDARY_TIMES[0])]

    with pytest.raises(ValueError):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize(
    ("signal", "value"),
    [
        ("kernel_release", "6.6.87.2-microsoft-standard-WSL2"),
        ("proc_version", "Linux version 6.6.87.2-microsoft-standard-WSL2"),
        ("wsl_interop_env_present", True),
        ("wsl_distro_name_env_present", True),
        ("run_wsl_directory_present", True),
    ],
)
def test_each_individual_wsl_signal_requires_applicable_preflight(signal: str, value: Any) -> None:
    preflight = _non_wsl_preflight()
    preflight["platform_detection"][signal] = value

    with pytest.raises(ValueError, match="non-WSL host-storage preflight is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize(
    ("signal", "value"),
    [
        ("kernel_release", "6.6.87.2-microsoft-standard-WSL2"),
        ("proc_version", "Linux version 6.6.87.2-microsoft-standard-WSL2"),
        ("wsl_interop_env_present", True),
        ("wsl_distro_name_env_present", True),
        ("run_wsl_directory_present", True),
    ],
)
def test_each_individual_wsl_signal_suffices_for_applicable_preflight(
    signal: str, value: Any
) -> None:
    preflight = _wsl_preflight()
    preflight["platform_detection"] = _non_wsl_preflight()["platform_detection"]
    preflight["platform_detection"][signal] = value

    validated = build_storage.validate_build_host_storage_preflight(
        preflight,
        expected_probe_sha256=PROBE_SHA256,
    )

    assert validated["applicable"] is True


@pytest.mark.parametrize(
    "timestamps",
    [
        ("2026-09-01T00:00:00", None),
        ("not-a-timestamp", None),
        ("2026-09-01T00:00:03+00:00", "2026-09-01T00:00:02+00:00"),
        ("2026-09-01T00:00:02+00:00", "2026-09-01T00:00:02+00:00"),
    ],
)
def test_observation_and_preflight_reject_invalid_or_reversed_times(
    timestamps: tuple[str, str | None],
) -> None:
    first, second = timestamps
    if second is None:
        observation = _observation("before-collection", first)
        with pytest.raises(ValueError, match="timestamp"):
            _validate_observation(observation)
        return

    preflight = _wsl_preflight()
    preflight["observations"][1]["observed_at"] = first
    preflight["observations"][2]["observed_at"] = second
    with pytest.raises(ValueError, match="preflight is inconsistent"):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("started_at", "2026-09-01T00:00:02.500000+00:00", "host-storage timing"),
        ("finished_at", "2026-09-01T00:00:03.500000+00:00", "host-storage timing"),
        ("finished_at", "2026-08-31T23:59:59+00:00", "duration is invalid"),
        ("started_at", "2026-09-01T00:00:01", "timestamp is not timezone-aware"),
    ],
)
def test_build_envelope_rejects_invalid_storage_or_receipt_timing(
    field: str, value: str, message: str
) -> None:
    receipt = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    receipt[field] = value
    _rehash(receipt)

    with pytest.raises(ValueError, match=message):
        build_storage.validate_build_execution_envelope(receipt)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("context", "remote-builder"),
        ("endpoint", "tcp://192.0.2.10:2376"),
        ("server_os_type", "windows"),
    ],
)
def test_build_envelope_rejects_nonlocal_or_non_linux_docker_endpoint(
    field: str, value: str
) -> None:
    receipt = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    receipt["docker"][field] = value
    _rehash(receipt)

    with pytest.raises(ValueError, match="endpoint is not local and supported"):
        build_storage.validate_build_execution_envelope(receipt)


@pytest.mark.parametrize("field", ["context", "endpoint", "server_id", "server_name"])
def test_build_envelope_rejects_empty_docker_identity(field: str) -> None:
    receipt = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    receipt["docker"][field] = ""
    _rehash(receipt)

    with pytest.raises(ValueError, match="Docker identity is invalid"):
        build_storage.validate_build_execution_envelope(receipt)


def test_wsl_build_requires_docker_desktop_server_identity() -> None:
    receipt = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    receipt["docker"]["server_operating_system"] = "Ubuntu 24.04"
    _rehash(receipt)

    with pytest.raises(ValueError, match="local Docker Desktop engine"):
        build_storage.validate_build_execution_envelope(receipt)


def test_build_envelope_rejects_boolean_cohort_version() -> None:
    receipt = _build_receipt(schema_version=1)
    receipt["cohort_version"] = True
    _rehash(receipt)

    with pytest.raises(ValueError, match="cohort version is not a positive integer"):
        build_storage.validate_build_execution_envelope(receipt)


def test_all_nested_schema_versions_reject_boolean_alias_for_one() -> None:
    observation = _observation(*BOUNDARY_TIMES[0])
    observation["schema_version"] = True
    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(observation)

    preflight = _wsl_preflight()
    preflight["schema_version"] = True
    with pytest.raises(ValueError, match="preflight schema is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)

    preflight = _wsl_preflight()
    preflight["platform_detection"]["schema_version"] = True
    with pytest.raises(ValueError, match="platform detection is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)

    receipt = _build_receipt(schema_version=1)
    receipt["schema_version"] = True
    _rehash(receipt)
    with pytest.raises(ValueError, match="receipt schema is invalid"):
        build_storage.validate_build_execution_envelope(receipt)

    receipt = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    receipt["role_provenance"]["schema_version"] = True
    _rehash(receipt)
    with pytest.raises(ValueError, match="role provenance is invalid"):
        build_storage.validate_build_execution_envelope(receipt)
