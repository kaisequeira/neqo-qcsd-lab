from __future__ import annotations

import base64
import csv
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import (
    buflo_evaluation,
    buflo_handoff,
    buflo_study,
    build_storage,
    capture_session,
    orchestrator,
)
from qcsd_lab.buflo_study import (
    DEBIAN_BASE_IMAGE,
    PARAMETER_FILES,
    RUST_BASE_IMAGE,
    STUDY_PLAN,
    generated_stage_cells,
    load_study_plan,
    run_study_action,
    validate_campaign_matrix,
    validate_controlled_campaign_receipt,
    validate_established_seven_baseline,
    validate_formal_capture_capacity,
    validate_parameters,
    validate_reference_gate_receipt,
    validate_staged_capture_prerequisites,
    validate_study_environment_receipt,
    validate_validation_attestation,
)
from qcsd_lab.capture_session import (
    _client_resource_usage_valid,
    _merge_runner_wakeup_metrics,
    _parse_client_resource_usage,
    _runner_wakeup_metrics_valid,
)
from qcsd_lab.defenses import (
    DEFENSE_ADAPTATIONS,
    DEFENSE_ORDER,
    DEFENSE_RUNTIME_KINDS,
    DEFENSE_VARIANT_LABELS,
)
from qcsd_lab.fidelity import (
    BUFLO_SCHEDULE_STOP_POLICY,
    BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS,
    BUFLO_SCHEDULE_STOP_V4_KEYS,
    BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS,
    BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT,
    BUFLO_TERMINAL_SUBCELL_POLICY,
    CS_BUFLO_STOP_DRAIN_V4_KEYS,
    CS_BUFLO_TERMINATION_STOP_POLICY,
    RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
    RUNNER_WAKEUP_V7_SEMANTICS,
    RUNNER_WAKEUP_V8_SEMANTICS,
    RUNNER_WAKEUP_V9_FAILURE_COUNTER_BY_OUTCOME,
    RUNNER_WAKEUP_V9_SEMANTICS,
    RUNNER_WAKEUP_V10_SEMANTICS,
    RUNNER_WAKEUP_V11_SEMANTICS,
    RUNNER_WAKEUP_V12_SEMANTICS,
    RUNNER_WAKEUP_V13_SEMANTICS,
    RUNNER_WAKEUP_V14_SEMANTICS,
    RUNNER_WAKEUP_V15_SEMANTICS,
    RUNNER_WAKEUP_V16_SEMANTICS,
    SCHEDULE_PREFIX_FIELDS,
    SCHEDULE_QCSD_FIELDS,
    _cs_buflo_padding_targets_match,
    _cs_buflo_payload_padding_target,
    _runner_wakeup_v9_relative_chronology_available,
    _runner_wakeup_v10_relative_chronology_available,
    _schedule_realization_metrics,
    fidelity_eligible,
    new_defense_terminal_receipts_valid,
)
from qcsd_lab.fidelity import (
    _runner_wakeup_metrics_valid as _fidelity_runner_wakeup_metrics_valid,
)
from qcsd_lab.kernel_tx import (
    KERNEL_TX_PROTECTED_SELECTION_WAIT_SEMANTICS,
    KERNEL_TX_RUNNER_SEMANTICS,
    KERNEL_TX_RUNNER_V2_SEMANTICS,
    KERNEL_TX_RUNNER_V3_SEMANTICS,
    KERNEL_TX_RUNNER_V4_SEMANTICS,
    KERNEL_TX_RUNNER_V5_SEMANTICS,
    KERNEL_TX_RUNNER_V6_SEMANTICS,
)
from qcsd_lab.util import LAB_ROOT


@pytest.fixture(autouse=True)
def _remove_test_checkout_build_taints(tmp_path: Path):
    """Remove only audited supervisor records created for this test checkout."""

    yield
    expected_directory = str(tmp_path.resolve())
    for root in Path("/tmp").glob("qcsd-docker-build-supervisor.*"):
        try:
            root_stat = root.lstat()
        except FileNotFoundError:
            continue
        if (
            root.is_symlink()
            or not root.is_dir()
            or root_stat.st_uid != os.getuid()
            or stat.S_IMODE(root_stat.st_mode) != 0o700
        ):
            continue
        records = [
            candidate
            for name in ("SUPERVISION", "RECOVERY", "SUPERVISION.next", "RECOVERY.next")
            if (candidate := root / name).is_file() and not candidate.is_symlink()
        ]
        if not records or not any(
            f"working_directory={expected_directory}\n" in record.read_text(encoding="utf-8")
            for record in records
        ):
            continue
        for record in records:
            metadata = record.stat()
            assert metadata.st_uid == os.getuid()
            assert stat.S_IMODE(metadata.st_mode) == 0o600
            match = re.search(
                r"^cli_pid=([1-9][0-9]*)$",
                record.read_text(encoding="utf-8"),
                flags=re.MULTILINE,
            )
            assert match is None or not Path(f"/proc/{match.group(1)}").exists()
        assert {item.name for item in root.iterdir()} <= {
            "SUPERVISION",
            "RECOVERY",
            "SUPERVISION.next",
            "RECOVERY.next",
        }
        shutil.rmtree(root)


@pytest.mark.parametrize("failed_gate", [None, 0, 1])
def test_lab_code_gate_executor_runs_ordered_commands_and_records_outputs(
    monkeypatch: pytest.MonkeyPatch, failed_gate: int | None,
) -> None:
    calls: list[list[str]] = []
    outputs = ["full suite: passed ✓\n", "schema suite: passed ✓\n"]

    def run(argv, **kwargs):
        assert kwargs == {
            "cwd": LAB_ROOT,
            "text": True,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "check": False,
        }
        index = len(calls)
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv, 1 if index == failed_gate else 0, stdout=outputs[index]
        )

    monkeypatch.setattr(buflo_study.subprocess, "run", run)
    if failed_gate is not None:
        gate = buflo_study._LAB_CODE_GATE_COMMANDS[failed_gate][0]
        with pytest.raises(RuntimeError, match=f"code gate failed: {gate}"):
            buflo_study._run_lab_code_gate_commands()
        assert len(calls) == failed_gate + 1
    else:
        records = buflo_study._run_lab_code_gate_commands()
        assert len(records) == len(buflo_study._LAB_CODE_GATE_COMMANDS)
        for record, (gate, _), output, argv in zip(
            records, buflo_study._LAB_CODE_GATE_COMMANDS, outputs, calls, strict=True
        ):
            assert record == {
                "gate": gate,
                "argv": argv,
                "cwd": str(LAB_ROOT),
                "exit_code": 0,
                "stdout_bytes": len(output.encode("utf-8")),
                "stdout_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
                "stdout": output,
            }
    assert calls == [
        [str(Path(os.sys.executable)) if item == "python" else item for item in template]
        for _gate, template in buflo_study._LAB_CODE_GATE_COMMANDS[:len(calls)]
    ]


def test_rust_code_gate_sidecar_hash_binds_exact_unsorted_json_bytes(
    tmp_path: Path,
) -> None:
    sidecar = tmp_path / "source.json"
    raw = b'{"z":1,"a":2}\n'
    sidecar.write_bytes(raw)
    expected = {"a": 2, "z": 1}

    buflo_study._validate_embedded_json_receipt(
        sidecar,
        expected=expected,
        claimed_sha256=hashlib.sha256(raw).hexdigest(),
        label="test",
    )

    # A semantically equivalent rewrite is still a different embedded receipt.
    sidecar.write_bytes(b'{"z":1, "a":2}\n')
    with pytest.raises(ValueError, match="sidecar hash is invalid"):
        buflo_study._validate_embedded_json_receipt(
            sidecar,
            expected=expected,
            claimed_sha256=hashlib.sha256(raw).hexdigest(),
            label="test",
        )


def test_rust_code_gate_sidecar_rejects_content_mismatch_and_symlink(
    tmp_path: Path,
) -> None:
    sidecar = tmp_path / "source.json"
    raw = b'{"z":1,"a":2}\n'
    sidecar.write_bytes(raw)
    with pytest.raises(ValueError, match="sidecar content is inconsistent"):
        buflo_study._validate_embedded_json_receipt(
            sidecar,
            expected={"a": 3, "z": 1},
            claimed_sha256=hashlib.sha256(raw).hexdigest(),
            label="test",
        )

    link = tmp_path / "source-link.json"
    link.symlink_to(sidecar)
    with pytest.raises(ValueError, match="sidecar is absent or unsafe"):
        buflo_study._validate_embedded_json_receipt(
            link,
            expected={"a": 2, "z": 1},
            claimed_sha256=hashlib.sha256(raw).hexdigest(),
            label="test",
        )


def _reference_execution_fixture(tmp_path: Path, *, build_schema_version: int = 1) -> Path:
    build_execution = _build_execution_value(schema_version=build_schema_version)
    source = {
        "image_digest": "sha256:" + "e" * 64,
        "lab_commit": "b" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": buflo_study.EMPTY_SHA256,
        "neqo_commit": "c" * 40,
        "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": buflo_study.EMPTY_SHA256,
    }
    isolation = {
        "environment_marker": "QCSD_REFERENCE_ISOLATED=1",
        "docker_network_mode": "none",
        "observed_interfaces": ["lo"],
        "reference_inputs_read_only": True,
        "output_mount_writable": True,
        "output_create_only": True,
        "ordinary_collection_contains_author_code": False,
    }
    value = buflo_study._reference_execution_value(
        source=source,
        build_execution={
            "sha256": hashlib.sha256(
                (json.dumps(build_execution, indent=2, sort_keys=True) + "\n").encode()
            ).hexdigest(),
            "receipt": build_execution,
        },
        isolation=isolation,
        execution_id="d" * 32,
        started_at="2026-08-27T00:00:00+00:00",
        finished_at="2026-08-27T00:00:00+00:00",
        duration_seconds=0.0,
    )
    destination = tmp_path / "reference-execution.json"
    destination.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def _buildx_provenance() -> dict[str, object]:
    reported_path = "/usr/local/lib/docker/cli-plugins/docker-buildx"
    symlink_target = (
        "/mnt/wsl/docker-desktop/cli-tools/usr/local/lib/docker/cli-plugins/docker-buildx"
    )
    version = "v0.29.1-desktop.1"
    commit = "28f6246ff24e2c05095e8741e48c48dcb2d3b4bc"
    identity: dict[str, object] = {
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
    identity_sha256 = buflo_study._canonical_digest(identity)
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
                ("before-collection", "2026-08-27T00:00:00.100000+00:00"),
                ("after-collection", "2026-08-27T00:00:00.300000+00:00"),
                ("after-prepare", "2026-08-27T00:00:00.600000+00:00"),
                ("after-reference", "2026-08-27T00:00:00.900000+00:00"),
            )
        ],
        "passed": True,
    }


def _schema5_git_object_oid(kind: bytes, payload: bytes) -> str:
    return hashlib.sha1(  # noqa: S324 - reproduces the repository object format.
        kind + b" " + str(len(payload)).encode("ascii") + b"\0" + payload
    ).hexdigest()


def _schema5_git_tree(entries: list[tuple[bytes, bytes, str]]) -> tuple[bytes, str]:
    payload = b"".join(
        mode + b" " + name + b"\0" + bytes.fromhex(oid)
        for mode, name, oid in sorted(entries, key=lambda item: item[1])
    )
    return payload, _schema5_git_object_oid(b"tree", payload)


def _schema5_cohort_evidence(
    *, cohort_version: int, ledger_payload: bytes, neqo_commit: str
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    list[dict[str, object]],
]:
    ledger_blob = _schema5_git_object_oid(b"blob", ledger_payload)
    v1_tree, v1_oid = _schema5_git_tree(
        [(b"100644", b"consumed-cohorts.json", ledger_blob)]
    )
    study_tree, study_oid = _schema5_git_tree([(b"40000", b"v1", v1_oid)])
    config_tree, config_oid = _schema5_git_tree(
        [(b"40000", b"buflo-study", study_oid)]
    )
    root_tree, root_oid = _schema5_git_tree(
        [
            (b"40000", b"config", config_oid),
            (b"160000", b"neqo-qcsd", neqo_commit),
        ]
    )
    commit_payload = (
        f"tree {root_oid}\n"
        "author QCSD test <qcsd-test@example.invalid> 0 +0000\n"
        "committer QCSD test <qcsd-test@example.invalid> 0 +0000\n"
        "\nschema-5 fixture\n"
    ).encode("ascii")
    lab_commit = _schema5_git_object_oid(b"commit", commit_payload)
    allocation: dict[str, object] = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-allocation",
        "policy": "dense-prefix-durable-publications-consume-v1",
        "ledger_path": "config/buflo-study/v1/consumed-cohorts.json",
        "ledger_sha256": hashlib.sha256(ledger_payload).hexdigest(),
        "ledger_payload_base64": base64.b64encode(ledger_payload).decode("ascii"),
        "git_object_format": "sha1",
        "ledger_git_blob_oid": ledger_blob,
        "lab_commit": lab_commit,
        "neqo_commit": neqo_commit,
        "neqo_gitlink": neqo_commit,
        "lab_commit_ledger_proof": {
            "schema_version": 1,
            "artifact_type": "qcsd-buflo-study-cohort-ledger-git-proof",
            "commit_payload_base64": base64.b64encode(commit_payload).decode("ascii"),
            "tree_payloads_base64": [
                base64.b64encode(item).decode("ascii")
                for item in (root_tree, config_tree, study_tree, v1_tree)
            ],
        },
        "last_consumed_version": cohort_version - 1,
        "allocated_version": cohort_version,
    }

    def file_identity(
        *, inode: int, mode: int, size: int, nlink: int = 1
    ) -> dict[str, int]:
        return {
            "dev": 1,
            "inode": inode,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "mode": mode,
            "nlink": nlink,
            "size": size,
            "mtime_ns": 1_000_000_000 + inode,
            "ctime_ns": 2_000_000_000 + inode,
        }

    authority: dict[str, object] = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-allocation-authority",
        "git": {
            "object_format": "sha1",
            "lab_head": lab_commit,
            "head_blob_oid": ledger_blob,
            "index_blob_oid": ledger_blob,
            "worktree_blob_oid": ledger_blob,
            "neqo_head": neqo_commit,
            "head_gitlink": neqo_commit,
            "index_gitlink": neqo_commit,
        },
        "filesystem": {
            "directories": {
                name: file_identity(
                    inode=100 + index,
                    mode=0o755,
                    size=4096,
                    nlink=2,
                )
                for index, name in enumerate(
                    ("repository-root", "config", "buflo-study", "v1", "git")
                )
            },
            "ledger": file_identity(
                inode=200,
                mode=0o644,
                size=len(ledger_payload),
            ),
            "git_index": file_identity(inode=201, mode=0o644, size=4096),
        },
        "receipt": json.loads(json.dumps(allocation)),
    }
    authority_sha256 = buflo_study._canonical_digest(authority)
    claim_payload = {
        "policy": "dense-prefix-durable-publications-consume-v1",
        "registry_path": "artifacts/buflo-study/cohort-claims-v1",
        "cohort_version": cohort_version,
        "authority": authority,
        "authority_sha256": authority_sha256,
        "source": {
            "lab_commit": lab_commit,
            "neqo_commit": neqo_commit,
            "neqo_gitlink": neqo_commit,
        },
        "ledger": {
            "path": allocation["ledger_path"],
            "sha256": allocation["ledger_sha256"],
            "git_object_format": "sha1",
            "git_blob_oid": ledger_blob,
            "payload_base64": allocation["ledger_payload_base64"],
            "last_consumed_version": cohort_version - 1,
        },
        "predecessor": {
            "kind": "genesis-ledger",
            "cohort_version": cohort_version - 1,
            "sha256": allocation["ledger_sha256"],
        },
    }
    claim = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-claim",
        "payload": claim_payload,
        "payload_sha256": buflo_study._canonical_digest(claim_payload),
    }
    claim_raw = (
        json.dumps(claim, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("ascii")
    claim_sha256 = hashlib.sha256(claim_raw).hexdigest()
    snapshot: dict[str, object] = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-claim-publication",
        "policy": "dense-prefix-durable-publications-consume-v1",
        "cohort_version": cohort_version,
        "registry": {
            "path": "artifacts/buflo-study/cohort-claims-v1",
            "stat": {
                "dev": 1,
                "inode": 300,
                "uid": os.getuid(),
                "gid": os.getgid(),
                "mode": 0o700,
                "nlink": 2,
            },
        },
        "claim": {
            "path": (
                "artifacts/buflo-study/cohort-claims-v1/"
                f"claim-v{cohort_version}.json"
            ),
            "sha256": claim_sha256,
            "payload_base64": base64.b64encode(claim_raw).decode("ascii"),
            "stat": file_identity(inode=301, mode=0o600, size=len(claim_raw)),
        },
        "registry_head_at_publication": {
            "cohort_version": cohort_version,
            "sha256": claim_sha256,
        },
    }
    snapshot["payload_sha256"] = buflo_study._canonical_digest(snapshot)
    snapshot_sha256 = buflo_study._canonical_digest(snapshot)
    claim_chain: dict[str, object] = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-claim-chain",
        "policy": "dense-prefix-durable-publications-consume-v1",
        "genesis": {
            "ledger_path": allocation["ledger_path"],
            "ledger_sha256": allocation["ledger_sha256"],
            "last_consumed_version": cohort_version - 1,
        },
        "claims": [
            {
                "cohort_version": cohort_version,
                "sha256": claim_sha256,
                "payload_base64": base64.b64encode(claim_raw).decode("ascii"),
            }
        ],
        "head": {
            "cohort_version": cohort_version,
            "sha256": claim_sha256,
        },
    }
    claim_chain["payload_sha256"] = buflo_study._canonical_digest(claim_chain)
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
    observed_times = (
        "2026-08-27T00:00:00.010000+00:00",
        "2026-08-27T00:00:00.020000+00:00",
        "2026-08-27T00:00:00.060000+00:00",
        "2026-08-27T00:00:00.070000+00:00",
        "2026-08-27T00:00:00.080000+00:00",
        "2026-08-27T00:00:00.150000+00:00",
        "2026-08-27T00:00:00.400000+00:00",
        "2026-08-27T00:00:00.700000+00:00",
        "2026-08-27T00:00:00.950000+00:00",
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
    return allocation, snapshot, claim_chain, reproofs


def _build_execution_value(
    image_id: str = "sha256:" + "a" * 64,
    *,
    cohort_version: int = 1,
    schema_version: int = 1,
) -> dict[str, object]:
    source = {
        "image_digest": image_id,
        "lab_commit": "b" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": buflo_study.EMPTY_SHA256,
        "neqo_commit": "c" * 40,
        "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": buflo_study.EMPTY_SHA256,
    }
    images = {
        target: {
            "tag": (
                build_storage.BUILD_IMAGE_TAGS[target]
                if schema_version in {2, 3, 4, 5}
                else f"neqo-qcsd-lab-{target}:test"
            ),
            "id": image_id if target == "collection" else "sha256:" + digest * 64,
            "repo_digests": [],
        }
        for target, digest in (("collection", "a"), ("prepare", "d"), ("reference", "e"))
    }
    commands = [
        {
            "target": target,
            "argv": [
                "docker",
                *(
                    ["--context", "default"]
                    if schema_version == 2
                    else ["--host", "unix:///var/run/docker.sock"]
                    if schema_version in {3, 4, 5}
                    else []
                ),
                "build",
                "--pull",
                "--no-cache",
                *(
                    [
                        "--iidfile",
                        str(
                            LAB_ROOT
                            / (f"artifacts/buflo-study/.build-iids-v{cohort_version}.ABC123")
                            / f"{target}.iid"
                        ),
                    ]
                    if schema_version in {2, 3, 4, 5}
                    else []
                ),
                "--target",
                target,
                "--tag",
                images[target]["tag"],
                "--file",
                str((LAB_ROOT / "Dockerfile").resolve()),
                str(LAB_ROOT.resolve()),
            ],
            "exit_code": 0,
            "image_id": images[target]["id"],
        }
        for target in ("collection", "prepare", "reference")
    ]
    value: dict[str, object] = {
        "schema_version": schema_version,
        "artifact_type": buflo_study.BUILD_EXECUTION_ARTIFACT_TYPE,
        "cohort_version": cohort_version,
        "started_at": "2026-08-27T00:00:00+00:00",
        "finished_at": "2026-08-27T00:00:01+00:00",
        "duration_seconds": 1.0,
        "docker": {"client_version": "29.0.1", "server_version": "29.0.1"},
        "commands": commands,
        "images": images,
        "source": source,
        "build_inputs": {
            "schema_version": 1,
            "artifact_type": "qcsd-study-build-inputs",
            "rust_base_image": RUST_BASE_IMAGE,
            "debian_base_image": DEBIAN_BASE_IMAGE,
            "uv_lock_sha256": buflo_study.sha256_file(LAB_ROOT / "uv.lock"),
            "cargo_lock_sha256": buflo_study.sha256_file(LAB_ROOT / "neqo-qcsd/Cargo.lock"),
        },
        "dockerfile_sha256": buflo_study.sha256_file(LAB_ROOT / "Dockerfile"),
        "cache_policy": {
            "pull": True,
            "no_cache": True,
            "scope": "Docker-layer-cache-disabled;declared-BuildKit-dependency-cache-mounts-only",
        },
    }
    if schema_version in {2, 3, 4, 5}:
        value["docker"] = {
            **value["docker"],
            "context": "default",
            "endpoint": "unix:///var/run/docker.sock",
            "server_name": "docker-desktop",
            "server_operating_system": "Docker Desktop",
            "server_os_type": "linux",
            "server_architecture": "x86_64",
            "server_id": "12345678-1234-1234-1234-123456789abc",
        }
        boundaries = (
            (
                "before-collection",
                "2026-08-27T00:00:00.050000+00:00"
                if schema_version == 5
                else "2026-08-26T23:59:59+00:00",
            ),
            (
                "before-prepare",
                "2026-08-27T00:00:00.350000+00:00"
                if schema_version == 5
                else "2026-08-27T00:00:00.200000+00:00",
            ),
            (
                "before-reference",
                "2026-08-27T00:00:00.650000+00:00"
                if schema_version == 5
                else "2026-08-27T00:00:00.400000+00:00",
            ),
            (
                "after-reference",
                "2026-08-27T00:00:00.925000+00:00"
                if schema_version == 5
                else "2026-08-27T00:00:00.800000+00:00",
            ),
        )
        probe_sha256 = buflo_study.sha256_file(LAB_ROOT / "tools/windows_docker_storage_probe.ps1")
        observations = [
            {
                "schema_version": 1,
                "probe": "powershell-get-volume-docker-data-vhdx-v1",
                "probe_sha256": probe_sha256,
                "boundary": boundary,
                "observed_at": observed_at,
                "location_source": "wsl-lxss-docker-desktop-data",
                "data_vhd_path": "C:\\Docker\\wsl\\data\\ext4.vhdx",
                "data_vhd_file_length_bytes": 512 * 1024**3,
                "backing_volume_unique_id": (
                    r"\\?\Volume{12345678-1234-1234-1234-123456789abc}" + "\\"
                ),
                "drive_letter": "C",
                "file_system": "NTFS",
                "health_status": "Healthy",
                "operational_status": ["OK"],
                "total_bytes": 1024**4,
                "available_bytes": 128 * 1024**3,
            }
            for boundary, observed_at in boundaries
        ]
        value["host_storage_preflight"] = {
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
            "policy": "docker-data-vhdx-backing-volume-minimum-v1",
            "required_available_bytes": (buflo_study.BUILD_WSL_HOST_MIN_AVAILABLE_BYTES),
            "observations": observations,
            "minimum_available_bytes": 128 * 1024**3,
            "passed": True,
        }
        value["role_provenance"] = {
            "schema_version": 1,
            "sources": {
                target: {**source, "image_digest": images[target]["id"]}
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
        if cohort_version <= 1:
            raise ValueError("schema-5 build fixtures require a predecessor cohort")
        ledger = {
            "artifact_type": "qcsd-buflo-study-consumed-cohorts",
            "consumed_versions": list(range(1, cohort_version)),
            "policy": "dense-prefix-durable-publications-consume-v1",
            "schema_version": 1,
        }
        ledger_payload = (json.dumps(ledger, sort_keys=True) + "\n").encode()
        allocation, claim, claim_chain, reproofs = _schema5_cohort_evidence(
            cohort_version=cohort_version,
            ledger_payload=ledger_payload,
            neqo_commit=str(source["neqo_commit"]),
        )
        source["lab_commit"] = allocation["lab_commit"]
        value["source"] = source
        role_sources = value["role_provenance"]["sources"]
        for role_source in role_sources.values():
            role_source["lab_commit"] = allocation["lab_commit"]
        value["cohort_allocation"] = allocation
        value["cohort_claim"] = claim
        value["cohort_claim_chain"] = claim_chain
        value["cohort_authority_reproofs"] = reproofs
    value["payload_sha256"] = buflo_study._canonical_digest(value)
    return value


def _write_schema5_build_pair(
    path: Path,
    *,
    cohort_version: int,
) -> tuple[dict[str, object], Path, dict[str, object]]:
    value = _build_execution_value(cohort_version=cohort_version, schema_version=5)
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(raw)
    path.chmod(0o600)
    binding = build_storage.build_execution_receipt_binding(
        receipt_path=path,
        receipt_raw=raw,
        receipt_value=value,
        receipt_stat=path.stat(),
        cohort_version=cohort_version,
    )
    authority = build_storage._completion_authority_bindings(value)
    lease = "9" * 64
    transaction_root = Path(
        f"/tmp/qcsd-docker-lifecycle-1000/transaction.{lease[:32]}"
    )
    transaction_fields = {
        "object": "docker-build-transaction",
        "lifecycle_schema": "1",
        "lifecycle_state": "request-authorised",
        "lifecycle_root": str(transaction_root),
        "lifecycle_token": lease[:32],
        "supervisor_source_path": str(LAB_ROOT / "tools/docker_signal_supervisor.sh"),
        "supervisor_source_sha256": "8" * 64,
        "supervisor_source_device": "1",
        "supervisor_source_inode": "2",
        "docker_context": "default",
        "docker_host": "unix:///var/run/docker.sock",
        "docker_server_id": "12345678-1234-1234-1234-123456789abc",
        "docker_request_revalidation": "in-scope-immediately-before-mutation",
        "docker_daemon_id": "12345678-1234-1234-1234-123456789abc",
        "host_boot_id": "12345678-1234-1234-1234-123456789abc",
        "working_directory": str(LAB_ROOT),
        "cohort_version": str(cohort_version),
        "receipt_path": str(
            LAB_ROOT
            / f"artifacts/buflo-study/build-execution-v{cohort_version}.json"
        ),
        "transaction_state": "uncommitted-static-tag-mutation",
    }
    transaction_raw = "".join(
        f"{key}={transaction_fields[key]}\n"
        for key in build_storage._BUILD_TRANSACTION_RECORD_FIELDS
    ).encode("ascii")
    cohort_parent = LAB_ROOT / "artifacts/buflo-study/cohort-claims-v1"
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
            "path": str(transaction_root / "SUPERVISION"),
            "sha256": hashlib.sha256(transaction_raw).hexdigest(),
            "payload_base64": base64.b64encode(transaction_raw).decode("ascii"),
            "stat": {
                "dev": 1,
                "inode": 21,
                "uid": os.geteuid(),
                "gid": os.getegid(),
                "mode": 0o600,
                "nlink": 1,
                "size": len(transaction_raw),
                "mtime_ns": 1,
                "ctime_ns": 2,
            },
        },
        "guardian": {
            "pid": 100,
            "start_time": 1000,
            "qcsd_pid": 101,
            "qcsd_start_time": 1001,
        },
        "lifecycle_lock": {
            "path": "/tmp/qcsd-docker-lifecycle-1000.lock",
            "device": 1,
            "inode": 10,
            "parent_device": 1,
            "parent_inode": 1,
            "lease_nonce": lease,
        },
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
    completion: dict[str, object] = {
        "schema_version": 1,
        "artifact_type": build_storage.BUILD_COMPLETION_ARTIFACT_TYPE,
        "cohort_version": cohort_version,
        "completed_at": "2026-08-27T00:00:01.200000+00:00",
        "receipt": binding,
        "source": {
            "lab_commit": value["source"]["lab_commit"],
            "neqo_commit": value["source"]["neqo_commit"],
            "neqo_gitlink": value["cohort_allocation"]["neqo_gitlink"],
        },
        "cohort_authority": authority,
        "transaction": transaction,
        "final_reproof": {
            "boundary": build_storage.BUILD_COMPLETION_FINAL_REPROOF_BOUNDARY,
            "observed_at": "2026-08-27T00:00:01.100000+00:00",
            "authority_sha256": value["cohort_authority_reproofs"][-1][
                "authority_sha256"
            ],
            "claim_snapshot_sha256": authority["claim_snapshot_sha256"],
            "claim_file_sha256": authority["claim_file_sha256"],
            "claim_chain_sha256": authority["claim_chain_sha256"],
        },
    }
    completion["payload_sha256"] = buflo_study._canonical_digest(completion)
    completion_path = path.with_name(f"build-completion-v{cohort_version}.json")
    completion_path.write_bytes(
        build_storage._canonical_finite_json_bytes(
            completion, label="test build completion", newline=True
        )
    )
    completion_path.chmod(0o600)
    return value, completion_path, completion


def _install_fake_wsl_storage_probe(
    root: Path,
    binary_root: Path,
    *,
    synthetic_source_authority: bool,
) -> tuple[Path, Path]:
    tools = root / "tools"
    tools.mkdir(exist_ok=True)
    (tools / "windows_docker_storage_probe.ps1").write_bytes(
        (LAB_ROOT / "tools/windows_docker_storage_probe.ps1").read_bytes()
    )
    package = root / "src/qcsd_lab"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_bytes((LAB_ROOT / "src/qcsd_lab/__init__.py").read_bytes())
    buildx_plugin_root = root / "test-system-docker-cli-plugins"
    buildx_target_root = root / "test-docker-desktop-cli-tools"
    buildx_plugin_root.mkdir()
    buildx_target_root.mkdir()
    buildx_target = buildx_target_root / "buildx-v0.29.1-test.1"
    buildx_target.write_bytes(b"test buildx executable\n")
    buildx_target.chmod(0o755)
    buildx_plugin = buildx_plugin_root / "docker-buildx"
    buildx_plugin.symlink_to(buildx_target)
    build_storage_source = (LAB_ROOT / "src/qcsd_lab/build_storage.py").read_text(encoding="utf-8")
    build_storage_policy_marker = "_BUILDX_REQUIRED_GID = 0\n"
    assert build_storage_source.count(build_storage_policy_marker) == 1
    build_storage_source = build_storage_source.replace(
        build_storage_policy_marker,
        build_storage_policy_marker
        + "# Test-only policy injected into this copied validator.\n"
        + f"_BUILDX_PLUGIN_DIRECTORIES = frozenset({{PurePosixPath({str(buildx_plugin_root)!r})}})\n"
        + f"_BUILDX_REQUIRED_UID = {os.getuid()}\n"
        + f"_BUILDX_REQUIRED_GID = {os.getgid()}\n",
    )
    if synthetic_source_authority:
        # Copied-launcher boundary fixtures deliberately use a synthetic
        # cohort authority and no Git repository.  Override only the copied
        # validator's live source probe; production-allocator fixtures retain
        # the real clean checkout/ledger reproof.
        publication_marker = "def publish_build_completion(\n"
        assert build_storage_source.count(publication_marker) == 1
        build_storage_source = build_storage_source.replace(
            publication_marker,
            "# Test-only copied-validator source authority.\n"
            "def _verify_live_completion_source(checkout_root, receipt_value):\n"
            "    return None\n\n\n"
            + publication_marker,
            1,
        )
    (package / "build_storage.py").write_text(
        build_storage_source,
        encoding="utf-8",
    )
    (package / "cohort_allocation.py").write_bytes(
        (LAB_ROOT / "src/qcsd_lab/cohort_allocation.py").read_bytes()
    )
    uname = binary_root / "uname"
    uname.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        '[ "${1:-}" = "-r" ]\n'
        "printf '%s\\n' '6.6.87.2-microsoft-standard-WSL2'\n",
        encoding="utf-8",
    )
    uname.chmod(0o755)
    wslpath = binary_root / "wslpath"
    wslpath.write_text(
        '#!/bin/sh\nset -eu\nfor argument do last="$argument"; done\nprintf \'%s\\n\' "$last"\n',
        encoding="utf-8",
    )
    wslpath.chmod(0o755)
    powershell = binary_root / "powershell.exe"
    powershell.write_text(
        """#!/usr/bin/env python3
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

if os.environ.get("QCSD_TEST_WSL_PROBE_FAIL") == "1":
    raise SystemExit(9)
if os.environ.get("QCSD_TEST_WSL_MALFORMED") == "1":
    print("not-json")
    raise SystemExit(0)
boundary = sys.argv[sys.argv.index("-Boundary") + 1]
probe_path = Path(sys.argv[sys.argv.index("-File") + 1])
marker = os.environ.get("QCSD_TEST_POWERSHELL_MARKER")
if marker:
    with Path(marker).open("a", encoding="utf-8") as output:
        output.write(boundary + "\\n")
available = int(
    os.environ.get("QCSD_TEST_WSL_AVAILABLE_BYTES", str(128 * 1024**3))
)
if os.environ.get("QCSD_TEST_WSL_LOW_BOUNDARY") == boundary:
    available = 64 * 1024**3 - 1
slash = chr(92)
path = os.environ.get(
    "QCSD_TEST_WSL_DATA_PATH",
    "C:" + slash + slash.join(("Docker", "wsl", "data", "ext4.vhdx")),
)
volume = slash * 2 + "?" + slash + "Volume{12345678-1234-1234-1234-123456789abc}" + slash
if os.environ.get("QCSD_TEST_WSL_IDENTITY_CHANGE_BOUNDARY") == boundary:
    volume = slash * 2 + "?" + slash + "Volume{87654321-4321-4321-4321-cba987654321}" + slash
value = {
    "schema_version": 1,
    "probe": "powershell-get-volume-docker-data-vhdx-v1",
    "probe_sha256": hashlib.sha256(probe_path.read_bytes()).hexdigest(),
    "boundary": boundary,
    "observed_at": datetime.now(timezone.utc).isoformat(),
    "location_source": os.environ.get(
        "QCSD_TEST_WSL_LOCATION_SOURCE", "wsl-lxss-docker-desktop-data"
    ),
    "data_vhd_path": path,
    "data_vhd_file_length_bytes": 512 * 1024**3,
    "backing_volume_unique_id": volume,
    "drive_letter": path[0].upper(),
    "file_system": "NTFS",
    "health_status": "Healthy",
    "operational_status": ["OK"],
    "total_bytes": 1024**4,
    "available_bytes": available,
}
print(json.dumps(value, separators=(",", ":")))
""",
        encoding="utf-8",
    )
    powershell.chmod(0o755)
    return buildx_plugin, buildx_target


def _install_fake_boundary_docker(
    binary_root: Path,
    build_marker: Path,
    *,
    buildx_plugin: Path,
    buildx_target: Path,
) -> None:
    docker = binary_root / "docker"
    inventory_marker = build_marker.with_name(f"{build_marker.name}-inventory")
    buildx_mutation_marker = build_marker.with_name(f"{build_marker.name}-buildx-mutated")
    cohort_lab_commit_marker = build_marker.with_name("cohort-lab-commit")
    buildx_version = "v0.29.1-test.1"
    buildx_commit = "28f6246ff24e2c05095e8741e48c48dcb2d3b4bc"
    buildx_metadata = json.dumps(
        [
            {
                "Name": "buildx",
                "Path": str(buildx_plugin),
                "SchemaVersion": "0.1.0",
                "ShortDescription": "Docker Buildx",
                "Vendor": "Docker Inc.",
                "Version": buildx_version,
            }
        ],
        separators=(",", ":"),
    )
    duplicate_buildx_metadata = json.dumps(
        json.loads(buildx_metadata) * 2,
        separators=(",", ":"),
    )
    extra_buildx_metadata = json.loads(buildx_metadata)
    extra_buildx_metadata[0]["Unexpected"] = True
    extra_buildx_metadata_json = json.dumps(
        extra_buildx_metadata,
        separators=(",", ":"),
    )
    docker.write_text(
        f"""#!/bin/sh
set -eu
if [ "${{1:-}}" = "--context" ] || [ "${{1:-}}" = "--host" ]; then
  shift 2
fi
command="$1"
shift
case "$command" in
  build)
    printf 'build\\n' >> {str(build_marker)!r}
    iidfile=""
    target=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --iidfile) iidfile="$2"; shift 2 ;;
        --target) target="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    case "$target" in
      collection) image_number=1 ;;
      prepare) image_number=2 ;;
      reference) image_number=3 ;;
      *) exit 1 ;;
    esac
    [ -n "$iidfile" ] || exit 1
    if [ "${{QCSD_TEST_IID_TARGET:-}}" = "$target" ]; then
      case "${{QCSD_TEST_IID_MODE:-}}" in
        missing) : ;;
        malformed) printf '%s\\n' 'not-an-image-id' > "$iidfile" ;;
        mismatch) printf 'sha256:%064d\\n' 9 > "$iidfile" ;;
        *) exit 1 ;;
      esac
    else
      printf 'sha256:%064d\\n' "$image_number" > "$iidfile"
    fi
    ;;
  context)
    case "$1" in
      show) printf '%s\\n' "${{QCSD_TEST_DOCKER_CONTEXT:-default}}" ;;
      inspect) printf '%s\\n' "${{QCSD_TEST_DOCKER_ENDPOINT:-unix:///var/run/docker.sock}}" ;;
      *) exit 1 ;;
    esac
    ;;
  info)
    if [ "$#" -eq 0 ]; then exit 0; fi
    build_count=0
    if [ -f {str(build_marker)!r} ]; then
      build_count="$(wc -l < {str(build_marker)!r})"
    fi
    server_name="${{QCSD_TEST_DOCKER_SERVER_NAME:-docker-desktop}}"
    server_id="${{QCSD_TEST_DOCKER_SERVER_ID:-12345678-1234-1234-1234-123456789abc}}"
    if [ -n "${{QCSD_TEST_DOCKER_CHANGE_AFTER_BUILDS:-}}" ] &&
       [ "$build_count" -ge "${{QCSD_TEST_DOCKER_CHANGE_AFTER_BUILDS}}" ]; then
      server_name="${{server_name}}-changed"
    fi
    if [ -n "${{QCSD_TEST_DOCKER_ID_CHANGE_AFTER_BUILDS:-}}" ] &&
       [ "$build_count" -ge "${{QCSD_TEST_DOCKER_ID_CHANGE_AFTER_BUILDS}}" ]; then
      server_id="87654321-4321-4321-4321-cba987654321"
    fi
    if [ -f {str(inventory_marker)!r} ]; then
      server_id="87654321-4321-4321-4321-cba987654321"
    fi
    if [ -n "${{QCSD_TEST_BUILDX_MUTATE_AFTER_BUILDS:-}}" ] &&
       [ "$build_count" -ge "${{QCSD_TEST_BUILDX_MUTATE_AFTER_BUILDS}}" ] &&
       [ ! -e {str(buildx_mutation_marker)!r} ]; then
      printf '%s\\n' 'mutated buildx fixture' > {str(buildx_target)!r}
      chmod 0755 {str(buildx_target)!r}
      : > {str(buildx_mutation_marker)!r}
    fi
    case "$2" in
      '{{{{json .}}}}')
        printf '{{"Name":"%s","OperatingSystem":"%s","OSType":"linux","Architecture":"x86_64","ID":"%s"}}\\n' \
          "$server_name" "${{QCSD_TEST_DOCKER_OPERATING_SYSTEM:-Docker Desktop}}" "$server_id"
        ;;
      '{{{{json .ClientInfo.Plugins}}}}')
        case "${{QCSD_TEST_BUILDX_METADATA_MODE:-valid}}" in
          valid) printf '%s\\n' {buildx_metadata!r} ;;
          missing) printf '%s\\n' '[]' ;;
          duplicate) printf '%s\\n' {duplicate_buildx_metadata!r} ;;
          extra) printf '%s\\n' {extra_buildx_metadata_json!r} ;;
          malformed) printf '%s\\n' '[{{"Name":' ;;
          unsafe-path)
            printf '%s\\n' '[{{"Name":"buildx","Path":"/tmp/docker-buildx","SchemaVersion":"0.1.0","ShortDescription":"Docker Buildx","Vendor":"Docker Inc.","Version":"{buildx_version}"}}]'
            ;;
          *) exit 1 ;;
        esac
        ;;
      '{{{{.Name}}}}') printf '%s\\n' "$server_name" ;;
      '{{{{.OperatingSystem}}}}') printf '%s\\n' "${{QCSD_TEST_DOCKER_OPERATING_SYSTEM:-Docker Desktop}}" ;;
      '{{{{.OSType}}}}') printf '%s\\n' 'linux' ;;
      '{{{{.Architecture}}}}') printf '%s\\n' 'x86_64' ;;
      '{{{{.ID}}}}') printf '%s\\n' "$server_id" ;;
      *) exit 1 ;;
    esac
    ;;
  version)
    if [ "${{QCSD_TEST_DOCKER_ID_CHANGE_AFTER_INVENTORY:-0}}" = "1" ]; then
      : > {str(inventory_marker)!r}
    fi
    printf '%s\\n' '{{"Client":{{"Version":"29.0.1"}},"Server":{{"Version":"29.0.1"}}}}'
    ;;
  buildx)
    [ "${{1:-}}" = "version" ] || exit 1
    case "${{QCSD_TEST_BUILDX_VERSION_MODE:-valid}}" in
      valid)
        printf '%s\\n' 'github.com/docker/buildx {buildx_version} {buildx_commit}'
        ;;
      mismatch)
        printf '%s\\n' 'github.com/docker/buildx v0.29.0 {buildx_commit}'
        ;;
      malformed) printf '%s\\n' 'not-buildx-version-output' ;;
      multiline)
        printf '%s\\n%s\\n' \
          'github.com/docker/buildx {buildx_version} {buildx_commit}' extra
        ;;
      *) exit 1 ;;
    esac
    ;;
  image)
    shift
    format=""
    last=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--format" ]; then format="$2"; shift 2; continue; fi
      last="$1"; shift
    done
    case "$format" in
      '{{{{.Id}}}}')
        case "$last" in
          *collection*) printf 'sha256:%064d\\n' 1 ;;
          *prepare*) printf 'sha256:%064d\\n' 2 ;;
          *reference*) printf 'sha256:%064d\\n' 3 ;;
          *) printf '%s\\n' "$last" ;;
        esac
        ;;
      '{{{{json .RepoDigests}}}}') printf '%s\\n' '[]' ;;
      *) exit 1 ;;
    esac
    ;;
  run)
    cidfile=""
    previous=""
    for argument in "$@"; do
      if [ "$previous" = "--cidfile" ]; then cidfile="$argument"; fi
      previous="$argument"
    done
    [ -n "$cidfile" ] || exit 1
    printf '%s\n' {("a" * 64)!r} > "$cidfile"
    case "$*" in
      */source.json)
        if [ -n "${{QCSD_TEST_SOURCE_CHANGE_IMAGE_ID:-}}" ] &&
           case "$*" in *"${{QCSD_TEST_SOURCE_CHANGE_IMAGE_ID}}"*) true ;; *) false ;; esac; then
          printf '%s\\n' '{{"lab_commit":"ffffffffffffffffffffffffffffffffffffffff","lab_dirty":false,"lab_patch_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","neqo_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","neqo_pinned_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","neqo_dirty":false,"neqo_patch_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}'
        else
          test_lab_commit="${{QCSD_TEST_LAB_COMMIT:-}}"
          if [ -z "$test_lab_commit" ] && [ -f {str(cohort_lab_commit_marker)!r} ]; then
            IFS= read -r test_lab_commit < {str(cohort_lab_commit_marker)!r}
          fi
          printf '{{"lab_commit":"%s","lab_dirty":false,"lab_patch_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","neqo_commit":"%s","neqo_pinned_commit":"%s","neqo_dirty":false,"neqo_patch_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}\\n' \\
            "${{test_lab_commit:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}}" \\
            "${{QCSD_TEST_NEQO_COMMIT:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}}" \\
            "${{QCSD_TEST_NEQO_COMMIT:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}}"
        fi
        ;;
      */study-build-inputs.json)
        if [ "${{QCSD_TEST_INVALID_BUILD_INPUTS:-0}}" = "1" ]; then
          printf '%s\\n' '{{}}'
        else
          printf '%s\\n' '{{"artifact_type":"qcsd-study-build-inputs","cargo_lock_sha256":"d8c9f2728aa278ebcd33ccedf3ad309a866870ad5fb93a03526b4b7655c9e911","debian_base_image":"docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818","rust_base_image":"docker.io/library/rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f","schema_version":1,"uv_lock_sha256":"d8c9f2728aa278ebcd33ccedf3ad309a866870ad5fb93a03526b4b7655c9e911"}}'
        fi
        ;;
      *) exit 1 ;;
    esac
    ;;
  container)
    case "$1" in
      ls) exit 0 ;;
      inspect) exit 1 ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 1 ;;
esac
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)


def _launcher_boundary_fixture(
    tmp_path: Path,
    *,
    production_allocator: bool = False,
    production_cohort_version: int = 62,
    committed_launcher_hooks: tuple[tuple[str, str], ...] = (),
) -> tuple[Path, Path, dict[str, str]]:
    launcher = tmp_path / "qcsd-lab"
    original_launcher_source = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")
    launcher_source = original_launcher_source
    trusted_path = (
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"
        "/mnt/c/Windows/System32/WindowsPowerShell/v1.0"
    )
    trusted_path_assignment = f'readonly PATH="{trusted_path}"'
    assert launcher_source.count(trusted_path_assignment) == 1
    launcher_source = launcher_source.replace(
        trusted_path_assignment,
        f"readonly PATH={shlex.quote(str(tmp_path / 'bin') + ':' + trusted_path)}",
        1,
    )
    if not production_allocator:
        verifier_start = launcher_source.index(
            "_qcsd_verify_clean_build_checkout() {"
        )
        verifier_end = launcher_source.index("\n}\n\nif [[", verifier_start) + 2
        launcher_source = (
            launcher_source[:verifier_start]
            + "_qcsd_verify_clean_build_checkout() {\n  return 0\n}"
            + launcher_source[verifier_end:]
        )
    cohort_marker = "# Parse a build request and enforce its create-only destination"
    assert launcher_source.count(cohort_marker) == 1
    launcher_source = launcher_source.replace(
        cohort_marker,
        "# Test-only cohort allocator: these copied-launcher tests exercise "
        "other build boundaries.\n"
        "_qcsd_validate_consumed_cohort_ledger() {\n"
        "  [[ \"$1\" =~ ^[1-9][0-9]*$ ]] && (( $1 >= 2 )) || return 1\n"
        "  python3 -I - \"$1\" \"${ROOT}/test-markers/cohort-lab-commit\" <<'PY'\n"
        "import base64, hashlib, json, os, stat, sys\n"
        "from pathlib import Path\n"
        "version = int(sys.argv[1])\n"
        "ledger = {\n"
        "    'artifact_type': 'qcsd-buflo-study-consumed-cohorts',\n"
        "    'consumed_versions': list(range(1, version)),\n"
        "    'policy': 'dense-prefix-durable-publications-consume-v1',\n"
        "    'schema_version': 1,\n"
        "}\n"
        "payload = (json.dumps(ledger, sort_keys=True) + '\\n').encode()\n"
        "def git_object(kind, payload):\n"
        "    return hashlib.sha1(kind + b' ' + str(len(payload)).encode() + b'\\0' + payload).hexdigest()\n"
        "def tree(entries):\n"
        "    raw = b''.join(\n"
        "        mode + b' ' + name + b'\\0' + bytes.fromhex(oid)\n"
        "        for mode, name, oid in sorted(entries, key=lambda item: item[1])\n"
        "    )\n"
        "    return raw, git_object(b'tree', raw)\n"
        "blob = git_object(b'blob', payload)\n"
        "v1_tree, v1_oid = tree([(b'100644', b'consumed-cohorts.json', blob)])\n"
        "study_tree, study_oid = tree([(b'40000', b'v1', v1_oid)])\n"
        "config_tree, config_oid = tree([(b'40000', b'buflo-study', study_oid)])\n"
        "root_tree, root_oid = tree([\n"
        "    (b'40000', b'config', config_oid),\n"
        "    (b'160000', b'neqo-qcsd', 'b' * 40),\n"
        "])\n"
        "commit_payload = (\n"
        "    f'tree {root_oid}\\n'\n"
        "    'author QCSD test <qcsd-test@example.invalid> 0 +0000\\n'\n"
        "    'committer QCSD test <qcsd-test@example.invalid> 0 +0000\\n'\n"
        "    '\\nsynthetic cohort authority\\n'\n"
        ").encode()\n"
        "lab_commit = git_object(b'commit', commit_payload)\n"
        "Path(sys.argv[2]).write_text(lab_commit + '\\n', encoding='ascii')\n"
        "identity = {\n"
        "    'dev': 1, 'inode': 1, 'uid': os.geteuid(), 'gid': os.getegid(),\n"
        "    'mode': 0o644, 'nlink': 1, 'size': len(payload),\n"
        "    'mtime_ns': 1, 'ctime_ns': 1,\n"
        "}\n"
        "directory_identity = {**identity, 'mode': 0o755, 'size': 1}\n"
        "stable_git_directory_identity = {\n"
        "    'type': stat.S_IFDIR, 'dev': 1, 'inode': 1,\n"
        "    'uid': os.geteuid(), 'gid': os.getegid(), 'mode': 0o755,\n"
        "}\n"
        "receipt = {\n"
        "    'schema_version': 1,\n"
        "    'artifact_type': 'qcsd-buflo-study-cohort-allocation',\n"
        "    'policy': 'dense-prefix-durable-publications-consume-v1',\n"
        "    'ledger_path': 'config/buflo-study/v1/consumed-cohorts.json',\n"
        "    'ledger_sha256': hashlib.sha256(payload).hexdigest(),\n"
        "    'ledger_payload_base64': base64.b64encode(payload).decode(),\n"
        "    'git_object_format': 'sha1',\n"
        "    'ledger_git_blob_oid': blob,\n"
        "    'lab_commit_ledger_proof': {\n"
        "        'schema_version': 1,\n"
        "        'artifact_type': 'qcsd-buflo-study-cohort-ledger-git-proof',\n"
        "        'commit_payload_base64': base64.b64encode(commit_payload).decode(),\n"
        "        'tree_payloads_base64': [\n"
        "            base64.b64encode(item).decode()\n"
        "            for item in (root_tree, config_tree, study_tree, v1_tree)\n"
        "        ],\n"
        "    },\n"
        "    'lab_commit': lab_commit,\n"
        "    'neqo_commit': 'b' * 40,\n"
        "    'neqo_gitlink': 'b' * 40,\n"
        "    'last_consumed_version': version - 1,\n"
        "    'allocated_version': version,\n"
        "}\n"
        "authority = {\n"
        "    'schema_version': 2,\n"
        "    'artifact_type': 'qcsd-buflo-study-cohort-allocation-authority',\n"
        "    'git': {\n"
        "        'object_format': 'sha1', 'lab_head': lab_commit,\n"
        "        'head_blob_oid': blob, 'index_blob_oid': blob,\n"
        "        'worktree_blob_oid': blob, 'neqo_head': 'b' * 40,\n"
        "        'head_gitlink': 'b' * 40, 'index_gitlink': 'b' * 40,\n"
        "    },\n"
        "    'filesystem': {\n"
        "        'directories': {\n"
        "            **{\n"
        "                name: dict(directory_identity)\n"
        "                for name in ('repository-root', 'config', 'buflo-study', 'v1')\n"
        "            },\n"
        "            'git': dict(stable_git_directory_identity),\n"
        "        },\n"
        "        'ledger': dict(identity),\n"
        "        'git_index': dict(identity),\n"
        "    },\n"
        "    'receipt': receipt,\n"
        "}\n"
        "print(json.dumps(authority, sort_keys=True, separators=(',', ':')))\n"
        "PY\n"
        "}\n\n"
        + cohort_marker,
        1,
    )
    if production_allocator:
        copied_start = launcher_source.index("# Test-only cohort allocator:")
        copied_end = launcher_source.index(cohort_marker, copied_start)
        launcher_source = (
            launcher_source[:copied_start]
            + launcher_source[copied_end:]
        )
    for marker, command in committed_launcher_hooks:
        assert launcher_source.count(marker) == 1
        launcher_source = launcher_source.replace(
            marker,
            command + "\n" + marker,
            1,
        )
    launcher.write_text(launcher_source, encoding="utf-8")
    launcher.chmod(0o755)
    (tmp_path / "tools").mkdir()
    supervisor = tmp_path / "tools/docker_signal_supervisor.sh"
    supervisor_source = (
        (LAB_ROOT / "tools/docker_signal_supervisor.sh").read_bytes()
        + b"""\n# Test-only exact lifecycle namespace; production has no environment override.\n_qcsd_secure_lifecycle_base() {\n  local entry canonical metadata\n  _qcsd_lifecycle_base="${QCSD_TEST_LIFECYCLE_BASE:?}"\n  [[ "${_qcsd_lifecycle_base}" == /* && ! -L "${_qcsd_lifecycle_base}" &&\n      -d "${_qcsd_lifecycle_base}" ]] || return 1\n  canonical="$(readlink -f -- "${_qcsd_lifecycle_base}")" || return 1\n  [[ "${canonical}" == "${_qcsd_lifecycle_base}" ]] || return 1\n  metadata="$(stat -Lc '%u:%a:%F' -- "${_qcsd_lifecycle_base}")" || return 1\n  [[ "${metadata}" == "$(id -u):700:directory" ]] || return 1\n  for entry in "${_qcsd_lifecycle_base}"/*; do\n    [[ -e "${entry}" || -L "${entry}" ]] || continue\n    [[ "${entry##*/}" =~ ^(run|network|build|transaction)[.][0-9a-f]{32}$ &&\n        ! -L "${entry}" && -d "${entry}" ]] || return 1\n    _qcsd_validate_lifecycle_root_contents "${entry}" || return 1\n  done\n}\n_qcsd_lifecycle_lock_path() {\n  printf '%s.lock\\n' "${QCSD_TEST_LIFECYCLE_BASE:?}"\n}\n# This copied fixture keeps fake Docker calls local and fast. The production\n# leased transient-service boundary is covered by the guardian/native suite.\n# Preserve the native identity-service command contract so copied launchers\n# still exercise pinned-daemon equality before every fake Docker operation.\n_qcsd_docker_api_service_with_timeout() {\n  local duration="${1:?}" service="${2:?}" host expected observed\n  shift 2\n  [[ "${duration}" =~ ^[1-9][0-9]*$ ]] || return 125\n  case "${service}" in\n    qcsd-native-docker-id)\n      (( $# == 1 )) || return 125\n      host="$1"\n      _qcsd_valid_pinned_docker_host "${host}" || return 125\n      /usr/bin/timeout --signal=KILL --kill-after=1 "${duration}s" \\\n        docker --host "${host}" info --format '{{.ID}}'\n      ;;\n    qcsd-native-docker-verify)\n      (( $# == 2 )) || return 125\n      host="$1"\n      expected="$2"\n      _qcsd_valid_pinned_docker_host "${host}" || return 125\n      [[ "${expected}" =~ ^[A-Za-z0-9_.:-]+$ ]] || return 125\n      observed="$(/usr/bin/timeout --signal=KILL --kill-after=1 \\\n        "${duration}s" docker --host "${host}" info --format '{{.ID}}')" ||\n        return 125\n      [[ "${observed}" == "${expected}" ]] || return 42\n      ;;\n    qcsd-native-docker-exec)\n      (( $# >= 4 )) || return 125\n      host="$1"\n      expected="$2"\n      [[ "$3" == -- && "${expected}" =~ ^[A-Za-z0-9_.:-]+$ ]] || return 125\n      shift 3\n      _qcsd_valid_pinned_docker_host "${host}" || return 125\n      observed="$(/usr/bin/timeout --signal=KILL --kill-after=1 \\\n        "${duration}s" docker --host "${host}" info --format '{{.ID}}')" ||\n        return 125\n      [[ "${observed}" == "${expected}" ]] || return 125\n      /usr/bin/timeout --signal=KILL --kill-after=1 "${duration}s" \\\n        env -u DOCKER_CONTEXT -u DOCKER_HOST -u DOCKER_TLS_VERIFY \\\n          -u DOCKER_CERT_PATH docker --host "${host}" "$@"\n      ;;\n    *)\n      /usr/bin/timeout --signal=KILL --kill-after=1 "${duration}s" \\\n        "${service}" "$@"\n      ;;\n  esac\n}\n_qcsd_launcher_birth_bound_hook() {\n  local kind="$1" launcher_pid="$2" root="$3"\n  if [[ "${QCSD_TEST_KILL_GUARDIAN_AFTER_BIRTH_KIND:-}" == "$kind" &&\n        ! -e "${QCSD_TEST_HANDOVER_DISABLE:-/nonexistent}" ]]; then\n    printf '%s %s\\n' "$launcher_pid" "$root" >"$QCSD_TEST_HANDOVER_MARKER"\n    kill -KILL "$_QCSD_LIFECYCLE_GUARD_PID"\n    while :; do sleep 1; done\n  fi\n}\n"""
    )
    verify_mismatch = b'      [[ "${observed}" == "${expected}" ]] || return 42\n'
    exec_mismatch = b'      [[ "${observed}" == "${expected}" ]] || return 125\n'
    assert supervisor_source.count(verify_mismatch) == 1
    assert supervisor_source.count(exec_mismatch) == 1
    supervisor_source = supervisor_source.replace(
        verify_mismatch,
        b'      if [[ "${observed}" != "${expected}" ]]; then\n'
        b'        echo "Docker pinned daemon identity changed" >&2\n'
        b'        return 42\n'
        b'      fi\n',
    ).replace(
        exec_mismatch,
        b'      if [[ "${observed}" != "${expected}" ]]; then\n'
        b'        echo "Docker pinned daemon identity changed" >&2\n'
        b'        return 125\n'
        b'      fi\n',
    )
    supervisor.write_bytes(supervisor_source)
    supervisor.chmod(0o755)
    native = tmp_path / "tools/docker_lifecycle_native.py"
    native.write_bytes((LAB_ROOT / "tools/docker_lifecycle_native.py").read_bytes())
    native.chmod(0o644)
    guardian = tmp_path / "tools/docker_lifecycle_lock_guardian.py"
    guardian_source = (LAB_ROOT / "tools/docker_lifecycle_lock_guardian.py").read_text(
        encoding="utf-8"
    )
    guardian_source = guardian_source.replace(
        "            source_descriptor=source_descriptor,\n        )",
        "            source_descriptor=source_descriptor,\n"
        '            lock_parent=Path(os.environ["QCSD_TEST_GUARDIAN_LOCK_PARENT"]),\n'
        "        )",
    )
    guardian_source = guardian_source.replace(
        '\nif __name__ == "__main__":',
        "\n# Test-only fixed roots; this copied guardian is never production code.\n"
        '_SAFE_PATH = os.environ["QCSD_TEST_BINARY_ROOT"] + ":" + _SAFE_PATH\n\n'
        'if __name__ == "__main__":',
    )
    guardian.write_text(guardian_source, encoding="utf-8")
    guardian.chmod(0o644)
    (tmp_path / "neqo-qcsd").mkdir()
    (tmp_path / "neqo-qcsd/Cargo.lock").write_text("lock\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("lock\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    binary_root = tmp_path / "bin"
    binary_root.mkdir()
    buildx_plugin, buildx_target = _install_fake_wsl_storage_probe(
        tmp_path,
        binary_root,
        synthetic_source_authority=not production_allocator,
    )
    marker_root = tmp_path / "test-markers"
    marker_root.mkdir()
    build_marker = marker_root / "docker-builds"
    _install_fake_boundary_docker(
        binary_root,
        build_marker,
        buildx_plugin=buildx_plugin,
        buildx_target=buildx_target,
    )
    environment = dict(os.environ)
    environment["PATH"] = f"{binary_root}:{environment['PATH']}"
    identity = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:32]
    environment["QCSD_TEST_DOCKER_SERVER_ID"] = (
        f"{identity[:8]}-{identity[8:12]}-{identity[12:16]}-{identity[16:20]}-{identity[20:]}"
    )
    guardian_lock_parent = tmp_path / "guardian-locks"
    guardian_lock_parent.mkdir(mode=0o700)
    # Mirror the production invariant that the lifecycle namespace is the
    # canonical lock pathname without its ``.lock`` suffix.  Completion
    # publication proves this exact relationship rather than accepting an
    # unrelated test-only transaction directory.
    lifecycle_base = guardian_lock_parent / f"qcsd-docker-lifecycle-{os.geteuid()}"
    lifecycle_base.mkdir(mode=0o700)
    environment["QCSD_TEST_LIFECYCLE_BASE"] = str(lifecycle_base.resolve())
    environment["QCSD_TEST_GUARDIAN_LOCK_PARENT"] = str(guardian_lock_parent.resolve())
    environment["QCSD_TEST_BINARY_ROOT"] = str(binary_root.resolve())
    if production_allocator:
        assert production_cohort_version >= 2
        (tmp_path / "artifacts/buflo-study").mkdir(parents=True)
        (tmp_path / "results").mkdir()
        (tmp_path / "config/workloads").mkdir(parents=True)

        def run_git(repository: Path, *arguments: str) -> str:
            completed = subprocess.run(
                ["/usr/bin/git", "-C", str(repository), *arguments],
                env={
                    **os.environ,
                    "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_CONFIG_SYSTEM": "/dev/null",
                    "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_NO_REPLACE_OBJECTS": "1",
                },
                check=True,
                capture_output=True,
                text=True,
            )
            return completed.stdout.strip()

        nested = tmp_path / "neqo-qcsd"
        run_git(nested, "init", "--quiet", "--object-format=sha1")
        run_git(nested, "add", "--", "Cargo.lock")
        run_git(
            nested,
            "-c",
            "user.name=QCSD test",
            "-c",
            "user.email=qcsd-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "--message",
            "nested source",
        )
        neqo_commit = run_git(nested, "rev-parse", "--verify", "HEAD^{commit}")

        ledger_path = tmp_path / "config/buflo-study/v1/consumed-cohorts.json"
        ledger_path.parent.mkdir(parents=True)
        ledger_path.write_text(
            json.dumps(
                {
                    "artifact_type": "qcsd-buflo-study-consumed-cohorts",
                    "consumed_versions": list(range(1, production_cohort_version)),
                    "policy": "dense-prefix-durable-publications-consume-v1",
                    "schema_version": 1,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        ledger_path.chmod(0o644)
        run_git(tmp_path, "init", "--quiet", "--object-format=sha1")
        (tmp_path / ".gitmodules").write_text(
            '[submodule "third_party/neqo-qcsd"]\n'
            "\tpath = neqo-qcsd\n"
            "\turl = ../neqo-qcsd\n",
            encoding="utf-8",
        )
        (tmp_path / ".gitignore").write_text(
            "/artifacts/\n"
            "/bin/\n"
            "/docker-lifecycle/\n"
            "/guardian-locks/\n"
            "/powershell-boundaries\n"
            "/results/\n"
            "/test-docker-desktop-cli-tools/\n"
            "/test-markers/\n"
            "/test-system-docker-cli-plugins/\n"
            "__pycache__/\n"
            "*.py[cod]\n",
            encoding="utf-8",
        )
        run_git(
            tmp_path,
            "config",
            "submodule.third_party/neqo-qcsd.url",
            "../neqo-qcsd",
        )
        run_git(
            tmp_path,
            "add",
            "--",
            ".gitignore",
            ".gitmodules",
            "Dockerfile",
            "config/buflo-study/v1/consumed-cohorts.json",
            "neqo-qcsd",
            "qcsd-lab",
            "src",
            "tools",
            "uv.lock",
        )
        run_git(tmp_path, "submodule", "absorbgitdirs", "--", "neqo-qcsd")
        run_git(
            tmp_path,
            "-c",
            "user.name=QCSD test",
            "-c",
            "user.email=qcsd-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "--message",
            "cohort authority",
        )
        lab_commit = run_git(tmp_path, "rev-parse", "--verify", "HEAD^{commit}")
        environment["QCSD_TEST_LAB_COMMIT"] = lab_commit
        environment["QCSD_TEST_NEQO_COMMIT"] = neqo_commit
    return launcher, build_marker, environment


def _marked_build_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines()) if path.exists() else 0


def _insert_copied_launcher_hook(launcher: Path, marker: str, command: str) -> None:
    source = launcher.read_text(encoding="utf-8")
    assert source.count(marker) == 1
    launcher.write_text(source.replace(marker, command + "\n" + marker, 1), encoding="utf-8")


def _empty_git_commit_command(repository: Path, message: str) -> str:
    return (
        "GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null "
        "GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 "
        + shlex.join(
            [
                "/usr/bin/git",
                "-C",
                str(repository),
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "user.name=QCSD test",
                "-c",
                "user.email=qcsd-test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "--allow-empty",
                "--message",
                message,
            ]
        )
    )


def _build_cli_taint(*, working_directory: Path, daemon_id: str) -> str:
    return (
        "object=docker-build-cli\n"
        "cli_pid=unavailable\n"
        "cli_start_time=unavailable\n"
        "cli_session=unavailable\n"
        "cli_process_group=unavailable\n"
        "docker_context=default\n"
        "docker_host=unix:///var/run/docker.sock\n"
        f"docker_server_id={daemon_id}\n"
        f"docker_daemon_id={daemon_id}\n"
        f"working_directory={working_directory.resolve()}\n"
        f"build_argv_sha256={'0' * 64}\n"
        "requested_signal=TERM\n"
        "forwarded_cli_signal=INT\n"
        "daemon_cancellation=unavailable-client-disconnect-only\n"
    )


def _build_scope_launcher_taint(
    *,
    supervisor_root: Path,
    record_name: str,
    working_directory: Path,
    daemon_id: str,
    supervision_state: str = "declared",
    recovery_late_signal: bool = False,
) -> str:
    scope_unit = f"qcsd-docker-build-{'0' * 32}.scope"
    common = [
        ("object", "docker-build-scope-launcher"),
        ("process_identity_role", "local-systemd-run-scope-launcher"),
    ]
    if record_name == "SUPERVISION":
        if supervision_state == "declared":
            launcher_identity = ("unavailable",) * 4
            scope_control_group = "unavailable"
            status_file_state = "declared"
        elif supervision_state == "active":
            launcher_identity = ("4242", "12345", "4242", "4242")
            scope_control_group = f"/user.slice/app.slice/{scope_unit}"
            status_file_state = "awaiting-command-status"
        else:
            raise AssertionError(
                f"unsupported scope-launcher supervision state: {supervision_state}"
            )
        fields = common + [
            ("scope_launcher_pid", launcher_identity[0]),
            ("scope_launcher_start_time", launcher_identity[1]),
            ("scope_launcher_session", launcher_identity[2]),
            ("scope_launcher_process_group", launcher_identity[3]),
            ("docker_context", "default"),
            ("docker_host", "unix:///var/run/docker.sock"),
            ("docker_server_id", daemon_id),
            ("docker_daemon_id", daemon_id),
            ("working_directory", str(working_directory.resolve())),
            ("build_argv_sha256", "0" * 64),
            ("scope_required", "1"),
            ("scope_unit", scope_unit),
            ("scope_control_group", scope_control_group),
            ("scope_state", supervision_state),
            ("host_boot_id", "00000000-0000-0000-0000-000000000001"),
            ("status_file", str(supervisor_root.resolve() / "build.status")),
            ("status_file_state", status_file_state),
            ("requested_signal", "none"),
            ("forwarded_cli_signal", "none"),
            ("daemon_cancellation", "unavailable-client-disconnect-only"),
        ]
    elif record_name == "RECOVERY":
        if recovery_late_signal:
            scope_signal = ("0", "not_attempted")
            cli_signal = ("none", "0", "not_attempted")
        else:
            scope_signal = ("1", "accepted")
            cli_signal = ("INT", "1", "accepted")
        fields = common + [
            ("scope_launcher_pid", "4242"),
            ("scope_launcher_start_time", "12345"),
            ("scope_launcher_session", "4242"),
            ("scope_launcher_process_group", "4242"),
            ("docker_context", "default"),
            ("docker_host", "unix:///var/run/docker.sock"),
            ("docker_server_id", daemon_id),
            ("docker_daemon_id", daemon_id),
            ("working_directory", str(working_directory.resolve())),
            ("build_argv_sha256", "0" * 64),
            ("scope_required", "1"),
            ("scope_unit", scope_unit),
            ("scope_control_group", f"/user.slice/app.slice/{scope_unit}"),
            ("scope_final_state", "inactive"),
            ("scope_signal_attempted", scope_signal[0]),
            ("scope_signal_outcome", scope_signal[1]),
            ("scope_leak_detected", "0"),
            ("scope_kill_attempted", "0"),
            ("scope_kill_outcome", "not_attempted"),
            ("scope_empty_proven", "1"),
            ("host_boot_id", "00000000-0000-0000-0000-000000000001"),
            ("status_file", str(supervisor_root.resolve() / "build.status")),
            ("status_file_state", "valid"),
            ("status_file_matches", "1"),
            ("docker_command_status", "130"),
            ("systemd_run_status", "130"),
            ("requested_signal", "TERM"),
            ("forwarded_cli_signal", cli_signal[0]),
            ("cli_signal_attempted", cli_signal[1]),
            ("cli_signal_outcome", cli_signal[2]),
            ("cli_forced", "0"),
            ("cli_force_attempted", "0"),
            ("cli_force_outcome", "not_attempted"),
            ("daemon_cancellation", "unavailable-client-disconnect-only"),
        ]
    else:
        raise AssertionError(f"unsupported scope-launcher record: {record_name}")
    return "".join(f"{key}={value}\n" for key, value in fields)


def _replace_taint_field(taint: str, key: str, value: str) -> str:
    pattern = rf"^{re.escape(key)}=.*$"
    assert len(re.findall(pattern, taint, flags=re.MULTILINE)) == 1
    return re.sub(pattern, f"{key}={value}", taint, flags=re.MULTILINE)


def _runner_wakeup_receipt() -> dict[str, object]:
    return {
        "schema_version": 1,
        "semantics": (
            "actual_select_return_source; socket_wins_simultaneous_readiness; "
            "controller_subset_is_effective_earliest_deadline; "
            "scheduled_cells_are_not_wakeups"
        ),
        "wait_returns": 12,
        "socket_readiness_wakeups": 7,
        "timer_wakeups": 5,
        "controller_deadline_timer_wakeups": 4,
        "other_timer_wakeups": 1,
    }


def _runner_wakeup_receipt_v2() -> dict[str, object]:
    value = _runner_wakeup_receipt()
    value.update(
        {
            "schema_version": 2,
            "semantics": (
                f"{value['semantics']}; "
                "buflo_exact_release_guard_reserves_candidate_window; "
                "buflo_exact_release_active_wait_tail_us=250; "
                "buflo_exact_release_guards_are_separately_receipted_active_waits; "
                "buflo_active_defense_socket_drains_are_single_batch; "
                "buflo_active_defense_http_drains_are_single_event; "
                "buflo_output_is_interrupted_at_guard"
            ),
            "buflo_exact_release_guard_entries": 0,
            "buflo_exact_release_guard_wait_nanoseconds": 0,
            "buflo_exact_release_active_wait_nanoseconds": 0,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 0,
            "buflo_exact_release_max_guard_exit_lateness_nanoseconds": 0,
        }
    )
    return value


def _runner_wakeup_receipt_v3() -> dict[str, object]:
    value = _runner_wakeup_receipt_v2()
    value.update(
        {
            "schema_version": 3,
            "semantics": str(value["semantics"]).replace(
                "buflo_exact_release_active_wait_tail_us=250",
                "buflo_exact_release_active_wait_tail_us=5000",
            ),
        }
    )
    return value


def _runner_wakeup_receipt_v4() -> dict[str, object]:
    value = _runner_wakeup_receipt_v3()
    value.update(
        {
            "schema_version": 4,
            "semantics": (
                f"{_runner_wakeup_receipt()['semantics']}; "
                "buflo_ordinary_output_admission_is_one_realization_window_before_guard; "
                "buflo_exact_release_guard_reserves_candidate_window; "
                "buflo_exact_release_active_wait_tail_us=5000; "
                "buflo_exact_release_guards_are_separately_receipted_active_waits; "
                "buflo_active_defense_socket_drains_are_single_batch; "
                "buflo_active_defense_http_drains_are_single_event; "
                "buflo_ordinary_output_stops_at_admission; "
                "buflo_exact_release_guard_begins_at_guard; "
                "cs_exact_incoming_retry_phases=1/4,1/2,3/4"
            ),
            "cs_exact_incoming_retry_drives": 0,
            "cs_exact_incoming_retry_resolutions": 0,
            "cs_exact_incoming_retry_max_phase_lateness_nanoseconds": 0,
        }
    )
    return value


def _runner_wakeup_receipt_v5() -> dict[str, object]:
    value = _runner_wakeup_receipt_v4()
    value.update(
        {
            "schema_version": 5,
            "semantics": (
                f"{value['semantics']}; "
                "buflo_exact_incoming_retry_wakeups="
                "transport_callback_or_1/4,1/2,3/4,deadline; "
                "buflo_exact_incoming_retry_drives="
                "count_owner_endpoint_output_drive_invocations_"
                "including_immediate_and_error; "
                "buflo_exact_incoming_retry_resolutions="
                "count_drive_invocations_clearing_at_least_one_captured_identity; "
                "buflo_exact_incoming_retry_max_wake_lateness_"
                "includes_terminal_deadline=true; "
                "buflo_exact_incoming_inventory="
                "all_unrealized_slot_owned_adapter_identities_with_same_tick_refresh; "
                "buflo_exact_incoming_expiry=one_logical_slot_one_deadline_miss"
            ),
            "buflo_exact_incoming_retry_drives": 0,
            "buflo_exact_incoming_retry_resolutions": 0,
            "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds": 0,
        }
    )
    return value


def _runner_wakeup_receipt_v6() -> dict[str, object]:
    value = _runner_wakeup_receipt_v5()
    value.update(
        {
            "schema_version": 6,
            "semantics": (
                f"{_runner_wakeup_receipt()['semantics']}; "
                "buflo_ordinary_output_admission_lead_us=10000; "
                "buflo_exact_release_guard_reserves_candidate_window; "
                "buflo_exact_release_guard_lead_us=10000; "
                "buflo_exact_release_active_wait_tail_us=10000; "
                "buflo_exact_release_guard_coincides_with_output_admission=true; "
                "buflo_exact_release_guards_are_separately_receipted_active_waits; "
                "buflo_active_defense_socket_drains_are_single_batch; "
                "buflo_active_defense_http_drains_are_single_event; "
                "buflo_ordinary_output_stops_at_admission; "
                "buflo_exact_release_guard_begins_at_guard; "
                "cs_exact_incoming_retry_phases=1/4,1/2,3/4; "
                "buflo_exact_incoming_retry_wakeups="
                "transport_callback_or_1/4,1/2,3/4,deadline; "
                "buflo_exact_incoming_retry_drives="
                "count_owner_endpoint_output_drive_invocations_"
                "including_immediate_and_error; "
                "buflo_exact_incoming_retry_resolutions="
                "count_drive_invocations_clearing_at_least_one_captured_identity; "
                "buflo_exact_incoming_retry_max_wake_lateness_"
                "includes_terminal_deadline=true; "
                "buflo_exact_incoming_inventory="
                "all_unrealized_slot_owned_adapter_identities_with_same_tick_refresh; "
                "buflo_exact_incoming_expiry=one_logical_slot_one_deadline_miss"
            ),
        }
    )
    return value


def _runner_wakeup_receipt_v7(
    *,
    guard_entries: int = 0,
    dispatch_lateness_nanoseconds: int = 7,
    release_skew_nanoseconds: int = 0,
) -> dict[str, object]:
    if not 0 <= release_skew_nanoseconds <= 999:
        raise ValueError("release skew must fit the sub-microsecond normalisation")
    if guard_entries == 0:
        dispatch_lateness_nanoseconds = 0
        release_skew_nanoseconds = 0
    deadline_skew_nanoseconds = (
        0 if release_skew_nanoseconds == 0 else 1_000 - release_skew_nanoseconds
    )
    release_nanoseconds = 20_000_000 + release_skew_nanoseconds
    deadline_nanoseconds = 25_000_000 - deadline_skew_nanoseconds
    actual_window_nanoseconds = deadline_nanoseconds - release_nanoseconds
    guard_nanoseconds = release_nanoseconds - 2 * actual_window_nanoseconds
    active_wait_per_guard = 2 * actual_window_nanoseconds + dispatch_lateness_nanoseconds
    active_wait_total = guard_entries * active_wait_per_guard
    dispatch_counts = [0] * 8
    spin_counts = [0] * 8
    if guard_entries:
        dispatch_bucket = sum(
            dispatch_lateness_nanoseconds > upper
            for upper in RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS
        )
        dispatch_counts[dispatch_bucket] = guard_entries
        spin_counts[0] = guard_entries
    value = _runner_wakeup_receipt_v6()
    value.update(
        {
            "schema_version": 7,
            "semantics": RUNNER_WAKEUP_V7_SEMANTICS,
            "buflo_exact_release_guard_entries": guard_entries,
            "buflo_exact_release_guard_wait_nanoseconds": active_wait_total,
            "buflo_exact_release_active_wait_nanoseconds": active_wait_total,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 0,
            "buflo_exact_release_max_guard_exit_lateness_nanoseconds": (
                dispatch_lateness_nanoseconds
            ),
            "buflo_exact_release_max_guard_entry_lateness_nanoseconds": 0,
            "buflo_exact_release_passive_sleep_calls": 0,
            "buflo_exact_release_passive_sleep_requested_nanoseconds": 0,
            "buflo_exact_release_passive_sleep_elapsed_nanoseconds": 0,
            "buflo_exact_release_max_passive_sleep_overrun_nanoseconds": 0,
            "buflo_exact_release_active_wait_iterations": guard_entries,
            "buflo_exact_release_active_spin_interruptions": 0,
            "buflo_exact_release_active_spin_interruption_nanoseconds": 0,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": 0,
            "buflo_exact_release_aux_clock_source": (
                "linux-clock-gettime-monotonic-raw-and-thread-cputime-id-v1"
            ),
            "buflo_exact_release_active_wait_aux_clock_guards": guard_entries,
            "buflo_exact_release_active_wait_aux_clock_unavailable_guards": 0,
            "buflo_exact_release_active_wait_aux_clock_nonmonotonic_guards": 0,
            "buflo_exact_release_active_wait_monotonic_raw_nanoseconds": (active_wait_total),
            "buflo_exact_release_active_wait_thread_cpu_nanoseconds": (active_wait_total),
            "buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds": 0,
            "buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds": 0,
            "buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds": 0,
            "buflo_exact_release_dispatch_at_or_after_deadline_guards": (
                guard_entries if dispatch_lateness_nanoseconds >= actual_window_nanoseconds else 0
            ),
            "buflo_exact_release_dispatch_lateness_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": dispatch_counts,
            },
            "buflo_exact_release_active_spin_gap_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": spin_counts,
            },
            "buflo_exact_release_worst_guard": (
                {
                    "endpoint": 0,
                    "slot": 1,
                    "phase": "committed",
                    "packet_timestamp_us": 20_000,
                    "guard_at_defense_nanoseconds": guard_nanoseconds,
                    "entered_at_defense_nanoseconds": guard_nanoseconds,
                    "active_wait_at_defense_nanoseconds": guard_nanoseconds,
                    "active_wait_started_at_defense_nanoseconds": guard_nanoseconds,
                    "release_at_defense_nanoseconds": release_nanoseconds,
                    "deadline_at_defense_nanoseconds": deadline_nanoseconds,
                    "dispatch_at_defense_nanoseconds": (
                        release_nanoseconds + dispatch_lateness_nanoseconds
                    ),
                    "guard_entry_lateness_nanoseconds": 0,
                    "passive_sleep_calls": 0,
                    "passive_sleep_requested_nanoseconds": 0,
                    "passive_sleep_elapsed_nanoseconds": 0,
                    "max_passive_sleep_overrun_nanoseconds": 0,
                    "active_wait_iterations": 1,
                    "active_wait_monotonic_nanoseconds": active_wait_per_guard,
                    "active_wait_monotonic_raw_nanoseconds": active_wait_per_guard,
                    "active_wait_thread_cpu_nanoseconds": active_wait_per_guard,
                    "active_wait_estimated_off_cpu_nanoseconds": 0,
                    "active_wait_monotonic_raw_divergence_nanoseconds": 0,
                    "active_spin_interruptions": 0,
                    "active_spin_interruption_nanoseconds": 0,
                    "max_active_spin_gap_nanoseconds": 0,
                    "dispatch_lateness_nanoseconds": dispatch_lateness_nanoseconds,
                    "dispatch_at_or_after_deadline": (
                        dispatch_lateness_nanoseconds >= actual_window_nanoseconds
                    ),
                    "dispatch_after_deadline_nanoseconds": max(
                        dispatch_lateness_nanoseconds - actual_window_nanoseconds, 0
                    ),
                }
                if guard_entries
                else None
            ),
        }
    )
    return value


def _runner_wakeup_receipt_v8(
    *,
    guard_entries: int = 0,
    dispatch_lateness_nanoseconds: int = 7,
    release_skew_nanoseconds: int = 0,
) -> dict[str, object]:
    value = _runner_wakeup_receipt_v7(
        guard_entries=guard_entries,
        dispatch_lateness_nanoseconds=dispatch_lateness_nanoseconds,
        release_skew_nanoseconds=release_skew_nanoseconds,
    )
    value.update(
        {
            "schema_version": 8,
            "semantics": RUNNER_WAKEUP_V8_SEMANTICS,
        }
    )
    return value


def _runner_wakeup_receipt_v9(
    *,
    guard_entries: int = 0,
    dispatch_lateness_nanoseconds: int = 7,
    release_skew_nanoseconds: int = 0,
) -> dict[str, object]:
    if not 0 <= release_skew_nanoseconds <= 999:
        raise ValueError("release skew must fit the sub-microsecond normalisation")
    if guard_entries == 0:
        dispatch_lateness_nanoseconds = 0
        release_skew_nanoseconds = 0
    deadline_skew_nanoseconds = (
        0 if release_skew_nanoseconds == 0 else 1_000 - release_skew_nanoseconds
    )
    release_nanoseconds = 20_000_000 + release_skew_nanoseconds
    deadline_nanoseconds = 25_000_000 - deadline_skew_nanoseconds
    actual_window_nanoseconds = deadline_nanoseconds - release_nanoseconds
    guard_nanoseconds = release_nanoseconds - actual_window_nanoseconds
    active_wait_per_guard = actual_window_nanoseconds + dispatch_lateness_nanoseconds
    active_wait_total = guard_entries * active_wait_per_guard
    dispatch_counts = [0] * 8
    spin_counts = [0] * 8
    if guard_entries:
        dispatch_bucket = sum(
            dispatch_lateness_nanoseconds > upper
            for upper in RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS
        )
        dispatch_counts[dispatch_bucket] = guard_entries
        spin_counts[0] = guard_entries
    value = _runner_wakeup_receipt_v6()
    value.update(
        {
            "schema_version": 9,
            "semantics": RUNNER_WAKEUP_V9_SEMANTICS,
            "buflo_exact_release_guard_entries": guard_entries,
            "buflo_exact_release_dispatch_ready_guards": guard_entries,
            "buflo_exact_release_failed_guards": 0,
            "buflo_exact_release_invalid_counter_frequency_guards": 0,
            "buflo_exact_release_counter_unavailable_failure_guards": 0,
            "buflo_exact_release_counter_nonmonotonic_failure_guards": 0,
            "buflo_exact_release_counter_frequency_changed_guards": 0,
            "buflo_exact_release_counter_target_error_guards": 0,
            "buflo_exact_release_guard_wait_nanoseconds": active_wait_total,
            "buflo_exact_release_active_wait_nanoseconds": active_wait_total,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 0,
            "buflo_exact_release_max_guard_exit_lateness_nanoseconds": (
                dispatch_lateness_nanoseconds
            ),
            "buflo_exact_release_max_guard_entry_lateness_nanoseconds": 0,
            "buflo_exact_release_passive_sleep_calls": 0,
            "buflo_exact_release_passive_sleep_requested_nanoseconds": 0,
            "buflo_exact_release_passive_sleep_elapsed_nanoseconds": 0,
            "buflo_exact_release_max_passive_sleep_overrun_nanoseconds": 0,
            "buflo_exact_release_active_wait_iterations": 2 * guard_entries,
            "buflo_exact_release_active_spin_interruptions": 0,
            "buflo_exact_release_active_spin_interruption_nanoseconds": 0,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": (1 if guard_entries else 0),
            "buflo_exact_release_active_wait_poll_source": (
                "linux-aarch64-cntvct-el0-predictive-v1"
            ),
            "buflo_exact_release_active_wait_counter_frequency_hz": (
                1_000_000_000 if guard_entries else None
            ),
            "buflo_exact_release_active_wait_counter_guards": guard_entries,
            "buflo_exact_release_active_wait_counter_unavailable_guards": 0,
            "buflo_exact_release_active_wait_counter_nonmonotonic_guards": 0,
            "buflo_exact_release_active_wait_counter_calibrations": guard_entries,
            "buflo_exact_release_active_wait_instant_confirmations": guard_entries,
            "buflo_exact_release_active_wait_early_confirmation_retries": 0,
            "buflo_exact_release_active_wait_counter_nanoseconds": active_wait_total,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": (
                1 if guard_entries else 0
            ),
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": (
                1 if guard_entries else 0
            ),
            "buflo_exact_release_dispatch_at_or_after_deadline_guards": (
                guard_entries if dispatch_lateness_nanoseconds >= actual_window_nanoseconds else 0
            ),
            "buflo_exact_release_dispatch_lateness_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": dispatch_counts,
            },
            "buflo_exact_release_active_spin_gap_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": spin_counts,
            },
            "buflo_exact_release_worst_guard": (
                {
                    "endpoint": 0,
                    "slot": 1,
                    "phase": "committed",
                    "packet_timestamp_us": 20_000,
                    "guard_at_defense_nanoseconds": guard_nanoseconds,
                    "entered_at_defense_nanoseconds": guard_nanoseconds,
                    "active_wait_at_defense_nanoseconds": guard_nanoseconds,
                    "active_wait_started_at_defense_nanoseconds": guard_nanoseconds,
                    "release_at_defense_nanoseconds": release_nanoseconds,
                    "deadline_at_defense_nanoseconds": deadline_nanoseconds,
                    "dispatch_at_defense_nanoseconds": (
                        release_nanoseconds + dispatch_lateness_nanoseconds
                    ),
                    "guard_entry_lateness_nanoseconds": 0,
                    "passive_sleep_calls": 0,
                    "passive_sleep_requested_nanoseconds": 0,
                    "passive_sleep_elapsed_nanoseconds": 0,
                    "max_passive_sleep_overrun_nanoseconds": 0,
                    "active_wait_iterations": 2,
                    "active_wait_monotonic_nanoseconds": active_wait_per_guard,
                    "active_wait_poll_source": "linux-aarch64-cntvct-el0-predictive-v1",
                    "active_wait_counter_frequency_hz": 1_000_000_000,
                    "active_wait_counter_calibrations": 1,
                    "active_wait_instant_confirmations": 1,
                    "active_wait_early_confirmation_retries": 0,
                    "active_wait_counter_nanoseconds": active_wait_per_guard,
                    "max_active_wait_counter_gap_nanoseconds": 1,
                    "max_counter_calibration_span_nanoseconds": 1,
                    "active_spin_interruptions": 0,
                    "active_spin_interruption_nanoseconds": 0,
                    "max_active_spin_gap_nanoseconds": 1,
                    "dispatch_lateness_nanoseconds": dispatch_lateness_nanoseconds,
                    "dispatch_at_or_after_deadline": (
                        dispatch_lateness_nanoseconds >= actual_window_nanoseconds
                    ),
                    "dispatch_after_deadline_nanoseconds": max(
                        dispatch_lateness_nanoseconds - actual_window_nanoseconds, 0
                    ),
                }
                if guard_entries
                else None
            ),
            "buflo_exact_release_last_failure": None,
        }
    )
    return value


def _runner_wakeup_receipt_v10(
    *,
    guard_entries: int = 0,
    dispatch_lateness_nanoseconds: int = 7,
    release_skew_nanoseconds: int = 0,
) -> dict[str, object]:
    value = json.loads(
        json.dumps(
            _runner_wakeup_receipt_v9(
                guard_entries=guard_entries,
                dispatch_lateness_nanoseconds=dispatch_lateness_nanoseconds,
                release_skew_nanoseconds=release_skew_nanoseconds,
            )
        )
    )
    worst = value["buflo_exact_release_worst_guard"]
    active_wait = worst["active_wait_monotonic_nanoseconds"] if isinstance(worst, dict) else 0
    value.update(
        {
            "schema_version": 10,
            "semantics": RUNNER_WAKEUP_V10_SEMANTICS,
            "buflo_exact_release_active_wait_poll_source": (
                "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
            ),
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": 0,
            "buflo_exact_release_active_wait_authoritative_watchdog_dispatches": 0,
            "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards": (
                guard_entries
            ),
            "buflo_exact_release_max_authoritative_sample_gap_nanoseconds": active_wait,
            "buflo_exact_release_max_authoritative_counter_lag_nanoseconds": 0,
            "buflo_exact_release_max_counter_authoritative_lead_nanoseconds": 0,
        }
    )
    if isinstance(worst, dict):
        worst.update(
            {
                "active_wait_poll_source": (
                    "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
                ),
                "active_wait_authoritative_watchdog_checks": 0,
                "active_wait_authoritative_watchdog_dispatches": 0,
                "max_authoritative_sample_gap_nanoseconds": active_wait,
                "max_authoritative_counter_lag_nanoseconds": 0,
                "max_counter_authoritative_lead_nanoseconds": 0,
            }
        )
    return value


def _runner_wakeup_v9_typed_failure(
    outcome: str,
    *,
    nullable_chronology: bool = False,
) -> dict[str, object]:
    counter_field = {
        "invalid-counter-frequency": "buflo_exact_release_invalid_counter_frequency_guards",
        "counter-unavailable": "buflo_exact_release_counter_unavailable_failure_guards",
        "counter-nonmonotonic": "buflo_exact_release_counter_nonmonotonic_failure_guards",
        "counter-frequency-changed": "buflo_exact_release_counter_frequency_changed_guards",
        "counter-target-error": "buflo_exact_release_counter_target_error_guards",
    }[outcome]
    receipt = _runner_wakeup_receipt_v9(guard_entries=1)
    prior_success = outcome == "counter-frequency-changed"
    failure_elapsed_nanoseconds = 5_000_001 if outcome == "counter-frequency-changed" else 1_000
    receipt["buflo_exact_release_guard_entries"] = 2 if prior_success else 1
    receipt["buflo_exact_release_dispatch_ready_guards"] = int(prior_success)
    receipt["buflo_exact_release_failed_guards"] = 1
    receipt[counter_field] = 1
    if prior_success:
        prior_elapsed = receipt["buflo_exact_release_guard_wait_nanoseconds"]
        receipt["buflo_exact_release_guard_wait_nanoseconds"] = (
            prior_elapsed + failure_elapsed_nanoseconds
        )
        receipt["buflo_exact_release_active_wait_nanoseconds"] = (
            prior_elapsed + failure_elapsed_nanoseconds
        )
        receipt["buflo_exact_release_active_wait_iterations"] = 4
        receipt["buflo_exact_release_active_spin_gap_histogram"]["counts"][0] = 2
        receipt["buflo_exact_release_worst_guard"]["active_wait_counter_frequency_hz"] = 500_000_000
    else:
        receipt.update(
            {
                "buflo_exact_release_guard_wait_nanoseconds": failure_elapsed_nanoseconds,
                "buflo_exact_release_active_wait_nanoseconds": failure_elapsed_nanoseconds,
                "buflo_exact_release_max_guard_exit_lateness_nanoseconds": 0,
                "buflo_exact_release_dispatch_lateness_histogram": {
                    "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                    "counts": [0] * 8,
                },
                "buflo_exact_release_worst_guard": None,
                "buflo_exact_release_dispatch_at_or_after_deadline_guards": 0,
            }
        )
    frequency = None if outcome == "invalid-counter-frequency" else 1_000_000_000
    counter_backed = outcome in {
        "counter-nonmonotonic",
        "counter-frequency-changed",
        "counter-target-error",
    }
    counter_nonmonotonic = outcome == "counter-nonmonotonic"
    calibrations = 0 if outcome in {"invalid-counter-frequency", "counter-nonmonotonic"} else 1
    confirmations = 1 if outcome == "counter-frequency-changed" else 0
    counter_delta = int(frequency is not None and calibrations > 0)
    failure_iterations = {
        "invalid-counter-frequency": 0,
        "counter-unavailable": 3,
        "counter-nonmonotonic": 2,
        "counter-frequency-changed": 2,
        "counter-target-error": 2,
    }[outcome]
    aggregate_calibrations = calibrations + int(prior_success)
    aggregate_confirmations = confirmations + int(prior_success)
    aggregate_counter_guards = int(counter_backed) + int(prior_success)
    aggregate_counter_nanoseconds = counter_delta
    if prior_success:
        aggregate_counter_nanoseconds += int(
            receipt["buflo_exact_release_worst_guard"]["active_wait_counter_nanoseconds"]
        )
    receipt.update(
        {
            "buflo_exact_release_active_wait_iterations": failure_iterations
            + (2 if prior_success else 0),
            "buflo_exact_release_active_wait_counter_frequency_hz": (
                500_000_000 if outcome == "counter-frequency-changed" else frequency
            ),
            "buflo_exact_release_active_wait_counter_guards": aggregate_counter_guards,
            "buflo_exact_release_active_wait_counter_unavailable_guards": int(not counter_backed),
            "buflo_exact_release_active_wait_counter_nonmonotonic_guards": int(
                counter_nonmonotonic
            ),
            "buflo_exact_release_active_wait_counter_calibrations": aggregate_calibrations,
            "buflo_exact_release_active_wait_instant_confirmations": aggregate_confirmations,
            "buflo_exact_release_active_wait_counter_nanoseconds": aggregate_counter_nanoseconds,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": counter_delta,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": counter_delta,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": counter_delta,
        }
    )
    nominal_release_nanoseconds = 40_000_000 if prior_success else 20_000_000
    guard_nanoseconds = nominal_release_nanoseconds - 5_000_000
    times: dict[str, int | None] = {
        "guard_at_defense_nanoseconds": guard_nanoseconds,
        "entered_at_defense_nanoseconds": guard_nanoseconds,
        "active_wait_at_defense_nanoseconds": guard_nanoseconds,
        "active_wait_started_at_defense_nanoseconds": guard_nanoseconds,
        "release_at_defense_nanoseconds": nominal_release_nanoseconds,
        "deadline_at_defense_nanoseconds": nominal_release_nanoseconds + 5_000_000,
        "exited_at_defense_nanoseconds": guard_nanoseconds + failure_elapsed_nanoseconds,
    }
    if nullable_chronology:
        times = dict.fromkeys(times)
    receipt["buflo_exact_release_last_failure"] = {
        "outcome": outcome,
        "endpoint": 0,
        "slot": 2 if prior_success else 1,
        "phase": "committed",
        "packet_timestamp_us": nominal_release_nanoseconds // 1_000,
        **times,
        "dispatch_at_defense_nanoseconds": None,
        "guard_entry_lateness_nanoseconds": 0,
        "exit_before_release_nanoseconds": max(5_000_000 - failure_elapsed_nanoseconds, 0),
        "exit_at_or_after_deadline": False,
        "active_wait_poll_source": "linux-aarch64-cntvct-el0-predictive-v1",
        "counter_frequency_hz": frequency,
        "counter_backed": counter_backed,
        "counter_unavailable": not counter_backed,
        "counter_nonmonotonic": counter_nonmonotonic,
        "counter_calibrations": calibrations,
        "instant_confirmations": confirmations,
        "early_confirmation_retries": 0,
        "counter_nanoseconds": counter_delta if frequency is not None else None,
        "max_counter_gap_nanoseconds": counter_delta if frequency is not None else None,
        "max_counter_calibration_span_nanoseconds": counter_delta
        if frequency is not None
        else None,
    }
    return receipt


def _runner_wakeup_v10_typed_failure(
    outcome: str,
    *,
    nullable_chronology: bool = True,
) -> dict[str, object]:
    receipt = json.loads(
        json.dumps(
            _runner_wakeup_v9_typed_failure(
                outcome,
                nullable_chronology=nullable_chronology,
            )
        )
    )
    receipt.update(
        {
            "schema_version": 10,
            "semantics": RUNNER_WAKEUP_V10_SEMANTICS,
            "buflo_exact_release_active_wait_poll_source": (
                "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
            ),
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": 0,
            "buflo_exact_release_active_wait_authoritative_watchdog_dispatches": 0,
            "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards": (
                receipt["buflo_exact_release_dispatch_ready_guards"]
            ),
            "buflo_exact_release_max_authoritative_sample_gap_nanoseconds": 0,
            "buflo_exact_release_max_authoritative_counter_lag_nanoseconds": 0,
            "buflo_exact_release_max_counter_authoritative_lead_nanoseconds": 0,
        }
    )
    worst = receipt["buflo_exact_release_worst_guard"]
    if isinstance(worst, dict):
        worst.update(
            {
                "active_wait_poll_source": (
                    "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
                ),
                "active_wait_authoritative_watchdog_checks": 0,
                "active_wait_authoritative_watchdog_dispatches": 0,
                "max_authoritative_sample_gap_nanoseconds": 0,
                "max_authoritative_counter_lag_nanoseconds": 0,
                "max_counter_authoritative_lead_nanoseconds": 0,
            }
        )
    failure = receipt["buflo_exact_release_last_failure"]
    retained_worst = receipt["buflo_exact_release_worst_guard"]
    failure.update(
        {
            "active_wait_poll_source": (
                "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
            ),
            "active_wait_iterations": receipt["buflo_exact_release_active_wait_iterations"]
            - (retained_worst["active_wait_iterations"] if retained_worst else 0),
            "active_wait_monotonic_nanoseconds": receipt[
                "buflo_exact_release_active_wait_nanoseconds"
            ]
            - (retained_worst["active_wait_monotonic_nanoseconds"] if retained_worst else 0),
            "active_spin_interruptions": receipt["buflo_exact_release_active_spin_interruptions"]
            - (retained_worst["active_spin_interruptions"] if retained_worst else 0),
            "active_spin_interruption_nanoseconds": receipt[
                "buflo_exact_release_active_spin_interruption_nanoseconds"
            ]
            - (retained_worst["active_spin_interruption_nanoseconds"] if retained_worst else 0),
            "max_active_spin_gap_nanoseconds": (failure.get("max_counter_gap_nanoseconds") or 0),
            "authoritative_watchdog_checks": 0,
            "authoritative_watchdog_dispatches": 0,
            "max_authoritative_sample_gap_nanoseconds": 0,
            "max_authoritative_counter_lag_nanoseconds": 0,
            "max_counter_authoritative_lead_nanoseconds": 0,
        }
    )
    if outcome == "invalid-counter-frequency":
        failure["max_authoritative_sample_gap_nanoseconds"] = failure[
            "active_wait_monotonic_nanoseconds"
        ]
        receipt["buflo_exact_release_max_authoritative_sample_gap_nanoseconds"] = failure[
            "active_wait_monotonic_nanoseconds"
        ]
    return receipt


def _runner_wakeup_v10_mixed_failure(
    outcome: str,
    *,
    successes: int = 1,
) -> dict[str, object]:
    receipt = json.loads(json.dumps(_runner_wakeup_receipt_v10(guard_entries=successes)))
    failure_receipt = _runner_wakeup_v10_typed_failure(
        outcome,
        nullable_chronology=False,
    )
    failure = failure_receipt["buflo_exact_release_last_failure"]
    receipt.update(
        {
            "buflo_exact_release_guard_entries": successes + 1,
            "buflo_exact_release_failed_guards": 1,
            "buflo_exact_release_last_failure": failure,
        }
    )
    for key in RUNNER_WAKEUP_V9_FAILURE_COUNTER_BY_OUTCOME.values():
        receipt[key] = failure_receipt[key]
    for key in (
        "buflo_exact_release_guard_wait_nanoseconds",
        "buflo_exact_release_active_wait_nanoseconds",
        "buflo_exact_release_active_wait_iterations",
        "buflo_exact_release_active_spin_interruptions",
        "buflo_exact_release_active_spin_interruption_nanoseconds",
        "buflo_exact_release_active_wait_counter_guards",
        "buflo_exact_release_active_wait_counter_unavailable_guards",
        "buflo_exact_release_active_wait_counter_nonmonotonic_guards",
        "buflo_exact_release_active_wait_counter_calibrations",
        "buflo_exact_release_active_wait_instant_confirmations",
        "buflo_exact_release_active_wait_early_confirmation_retries",
        "buflo_exact_release_active_wait_authoritative_watchdog_checks",
        "buflo_exact_release_active_wait_authoritative_watchdog_dispatches",
        "buflo_exact_release_active_wait_counter_nanoseconds",
    ):
        receipt[key] += failure_receipt[key]
    for key in (
        "buflo_exact_release_max_passive_wake_lateness_nanoseconds",
        "buflo_exact_release_max_guard_entry_lateness_nanoseconds",
        "buflo_exact_release_max_passive_sleep_overrun_nanoseconds",
        "buflo_exact_release_max_active_spin_gap_nanoseconds",
        "buflo_exact_release_max_active_wait_counter_gap_nanoseconds",
        "buflo_exact_release_max_counter_calibration_span_nanoseconds",
        "buflo_exact_release_max_authoritative_sample_gap_nanoseconds",
        "buflo_exact_release_max_authoritative_counter_lag_nanoseconds",
        "buflo_exact_release_max_counter_authoritative_lead_nanoseconds",
    ):
        receipt[key] = max(receipt[key], failure_receipt[key])
    receipt["buflo_exact_release_active_spin_gap_histogram"]["counts"] = [
        left + right
        for left, right in zip(
            receipt["buflo_exact_release_active_spin_gap_histogram"]["counts"],
            failure_receipt["buflo_exact_release_active_spin_gap_histogram"]["counts"],
            strict=True,
        )
    ]
    return receipt


def test_runner_wakeup_schema_eight_binds_barrier_free_poll_semantics() -> None:
    historical = _runner_wakeup_receipt_v7(guard_entries=1)
    current = _runner_wakeup_receipt_v8(guard_entries=1)

    assert set(current) == set(historical)
    assert current["semantics"] == (
        f"{historical['semantics']}; "
        "buflo_exact_release_active_wait_poll=poll_instant_without_arch_spin_hint"
    )
    assert _runner_wakeup_metrics_valid(historical)
    assert _fidelity_runner_wakeup_metrics_valid(historical)
    assert _runner_wakeup_metrics_valid(current)
    assert _fidelity_runner_wakeup_metrics_valid(current)
    assert not _runner_wakeup_metrics_valid({**historical, "semantics": current["semantics"]})
    assert not _fidelity_runner_wakeup_metrics_valid(
        {**historical, "semantics": current["semantics"]}
    )
    assert not _runner_wakeup_metrics_valid({**current, "semantics": historical["semantics"]})
    assert not _fidelity_runner_wakeup_metrics_valid(
        {**current, "semantics": historical["semantics"]}
    )


def test_runner_wakeup_historical_schema_seven_through_nine_semantics_are_frozen() -> None:
    assert hashlib.sha256(RUNNER_WAKEUP_V7_SEMANTICS.encode()).hexdigest() == (
        "6ecb36fd6f347a31d1a0fecbcede2efd1e040122458d3853817030d4b69e1e66"
    )
    assert hashlib.sha256(RUNNER_WAKEUP_V8_SEMANTICS.encode()).hexdigest() == (
        "97f1dd2e053a8dd774d702eb920d5e46c7eb0d622aabf7a6712bd07b04499958"
    )
    assert hashlib.sha256(RUNNER_WAKEUP_V9_SEMANTICS.encode()).hexdigest() == (
        "6ab6713bde70c803a7f243432277edda4f6b850d732c9246f88413e61f487503"
    )
    for semantics in (RUNNER_WAKEUP_V7_SEMANTICS, RUNNER_WAKEUP_V8_SEMANTICS):
        assert "dispatch_ready_guards" not in semantics
        assert "failed_guards" not in semantics


def test_runner_wakeup_schema_nine_binds_predictive_counter_and_instant_confirmation() -> None:
    historical = _runner_wakeup_receipt_v8(guard_entries=1)
    current = _runner_wakeup_receipt_v9(guard_entries=1)

    assert _runner_wakeup_metrics_valid(historical)
    assert _fidelity_runner_wakeup_metrics_valid(historical)
    assert _runner_wakeup_metrics_valid(current)
    assert _fidelity_runner_wakeup_metrics_valid(current)
    assert current["buflo_exact_release_active_wait_counter_guards"] == 1
    assert current["buflo_exact_release_active_wait_instant_confirmations"] == 1
    assert (
        current["buflo_exact_release_worst_guard"]["release_at_defense_nanoseconds"]
        - current["buflo_exact_release_worst_guard"]["guard_at_defense_nanoseconds"]
        == 5_000_000
    )
    assert "buflo_exact_release_aux_clock_source" not in current

    no_confirmation = json.loads(json.dumps(current))
    no_confirmation["buflo_exact_release_active_wait_instant_confirmations"] = 0
    no_confirmation["buflo_exact_release_worst_guard"]["active_wait_instant_confirmations"] = 0
    assert not _runner_wakeup_metrics_valid(no_confirmation)
    assert not _fidelity_runner_wakeup_metrics_valid(no_confirmation)

    stale_ten_millisecond_guard = json.loads(json.dumps(current))
    stale_ten_millisecond_guard["buflo_exact_release_worst_guard"][
        "guard_at_defense_nanoseconds"
    ] -= 5_000_000
    assert not _runner_wakeup_metrics_valid(stale_ten_millisecond_guard)
    assert not _fidelity_runner_wakeup_metrics_valid(stale_ten_millisecond_guard)


def test_runner_wakeup_schema_ten_semantics_exactly_match_rust_producer() -> None:
    source = (LAB_ROOT / "neqo-qcsd/neqo-bin/src/qcsd/mod.rs").read_text(encoding="utf-8")
    prefix = 'const RUNNER_WAKEUP_METRICS_SEMANTICS: &str = "'
    line = next(line for line in source.splitlines() if line.startswith(prefix))
    assert line.endswith('";')
    assert RUNNER_WAKEUP_V10_SEMANTICS == line[len(prefix) : -2]


def test_runner_wakeup_schema_twelve_semantics_remain_frozen() -> None:
    assert RUNNER_WAKEUP_V12_SEMANTICS == (
        f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
        "runner_schema12_retains_schema10_layout_for_non_kernel_metrics=true; "
        "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
        f"buflo_kernel_tx_raw_semantics={KERNEL_TX_RUNNER_V3_SEMANTICS}; "
        "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
    )


def test_runner_wakeup_schema_thirteen_semantics_remain_frozen() -> None:
    assert RUNNER_WAKEUP_V13_SEMANTICS == (
        f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
        "runner_schema13_retains_schema10_layout_for_non_kernel_metrics=true; "
        "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
        f"buflo_kernel_tx_raw_semantics={KERNEL_TX_RUNNER_V4_SEMANTICS}; "
        "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
    )


def test_runner_wakeup_schema_fourteen_semantics_remain_frozen() -> None:
    assert RUNNER_WAKEUP_V14_SEMANTICS == (
        f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
        "runner_schema14_retains_schema10_layout_for_non_kernel_metrics=true; "
        "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
        f"buflo_kernel_tx_raw_semantics={KERNEL_TX_RUNNER_V5_SEMANTICS}; "
        "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
    )


def test_runner_wakeup_schema_fifteen_semantics_remain_frozen() -> None:
    assert RUNNER_WAKEUP_V15_SEMANTICS == (
        f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
        "runner_schema15_retains_schema10_layout_for_non_kernel_metrics=true; "
        "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
        f"buflo_kernel_tx_raw_semantics={KERNEL_TX_RUNNER_V6_SEMANTICS}; "
        "buflo_kernel_protected_selection_wait_semantics="
        f"{KERNEL_TX_PROTECTED_SELECTION_WAIT_SEMANTICS}; "
        "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
    )


def test_runner_wakeup_schema_sixteen_semantics_exactly_match_rust_producer() -> None:
    source = (LAB_ROOT / "neqo-qcsd/neqo-bin/src/qcsd/mod.rs").read_text(encoding="utf-8")
    kernel_prefix = 'const BUFLO_KERNEL_TX_SEMANTICS: &str = "'
    kernel_line = next(line for line in source.splitlines() if line.startswith(kernel_prefix))
    assert kernel_line.endswith('";')
    assert KERNEL_TX_RUNNER_SEMANTICS == kernel_line[len(kernel_prefix) : -2]
    assert "runner_schema16_retains_schema15_and_schema10_layout_for_non_kernel_metrics=true" in (
        RUNNER_WAKEUP_V16_SEMANTICS
    )
    assert f"buflo_kernel_tx_raw_semantics={KERNEL_TX_RUNNER_SEMANTICS}; " in (
        RUNNER_WAKEUP_V16_SEMANTICS
    )
    assert RUNNER_WAKEUP_V11_SEMANTICS == (
        f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
        "runner_schema10_layout_is_retained_for_non_kernel_metrics; "
        "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
        f"buflo_kernel_tx_raw_semantics={KERNEL_TX_RUNNER_V2_SEMANTICS}; "
        "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
    )
    assert "self.schema_version = BUFLO_KERNEL_RUNNER_WAKEUP_METRICS_SCHEMA_VERSION;" in source
    assert (
        '"{RUNNER_WAKEUP_METRICS_SEMANTICS}; '
        "{BUFLO_KERNEL_RUNNER_WAKEUP_RETENTION_SEMANTICS}; "
        "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
        "buflo_kernel_tx_raw_semantics={BUFLO_KERNEL_TX_SEMANTICS}; "
        "buflo_kernel_protected_selection_wait_semantics="
        "{BUFLO_KERNEL_PROTECTED_SELECTION_WAIT_SEMANTICS}; "
        'post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"'
    ) in source


def test_runner_wakeup_schema_ten_adds_watchdog_to_frozen_schema_nine() -> None:
    historical = _runner_wakeup_receipt_v9(guard_entries=1)
    current = _runner_wakeup_receipt_v10(guard_entries=1)

    assert _runner_wakeup_metrics_valid(historical)
    assert _fidelity_runner_wakeup_metrics_valid(historical)
    assert _runner_wakeup_metrics_valid(current)
    assert _fidelity_runner_wakeup_metrics_valid(current)
    assert _runner_wakeup_v10_relative_chronology_available(current)
    assert set(current) - set(historical) == {
        "buflo_exact_release_active_wait_authoritative_watchdog_checks",
        "buflo_exact_release_active_wait_authoritative_watchdog_dispatches",
        "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards",
        "buflo_exact_release_max_authoritative_sample_gap_nanoseconds",
        "buflo_exact_release_max_authoritative_counter_lag_nanoseconds",
        "buflo_exact_release_max_counter_authoritative_lead_nanoseconds",
    }
    assert set(current["buflo_exact_release_worst_guard"]) - set(
        historical["buflo_exact_release_worst_guard"]
    ) == {
        "active_wait_authoritative_watchdog_checks",
        "active_wait_authoritative_watchdog_dispatches",
        "max_authoritative_sample_gap_nanoseconds",
        "max_authoritative_counter_lag_nanoseconds",
        "max_counter_authoritative_lead_nanoseconds",
    }
    for key in (
        "guard_at_defense_nanoseconds",
        "active_wait_at_defense_nanoseconds",
        "release_at_defense_nanoseconds",
        "deadline_at_defense_nanoseconds",
    ):
        assert (
            current["buflo_exact_release_worst_guard"][key]
            == historical["buflo_exact_release_worst_guard"][key]
        )
    assert (
        current["buflo_exact_release_worst_guard"]["release_at_defense_nanoseconds"]
        - current["buflo_exact_release_worst_guard"]["guard_at_defense_nanoseconds"]
        == 5_000_000
    )


def test_runner_wakeup_schema_ten_validates_sixty_four_read_watchdog() -> None:
    receipt = _runner_wakeup_receipt_v10(guard_entries=1)
    receipt["buflo_exact_release_active_wait_iterations"] = 66
    receipt["buflo_exact_release_active_wait_authoritative_watchdog_checks"] = 1
    receipt["buflo_exact_release_active_wait_authoritative_watchdog_dispatches"] = 1
    worst = receipt["buflo_exact_release_worst_guard"]
    worst["active_wait_iterations"] = 66
    worst["active_wait_authoritative_watchdog_checks"] = 1
    worst["active_wait_authoritative_watchdog_dispatches"] = 1

    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)

    wrong_interval = json.loads(json.dumps(receipt))
    wrong_interval["buflo_exact_release_worst_guard"]["active_wait_iterations"] = 65
    assert not _runner_wakeup_metrics_valid(wrong_interval)
    assert not _fidelity_runner_wakeup_metrics_valid(wrong_interval)

    too_many_dispatches = json.loads(json.dumps(receipt))
    too_many_dispatches["buflo_exact_release_active_wait_authoritative_watchdog_dispatches"] = 2
    assert not _runner_wakeup_metrics_valid(too_many_dispatches)
    assert not _fidelity_runner_wakeup_metrics_valid(too_many_dispatches)


def test_runner_wakeup_schema_ten_closes_v46_aggregate_cadence_ambiguity() -> None:
    receipt = _runner_wakeup_receipt_v10(guard_entries=2)
    receipt.update(
        {
            "buflo_exact_release_active_wait_iterations": 132,
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": 2,
            "buflo_exact_release_active_wait_authoritative_watchdog_dispatches": 2,
        }
    )
    receipt["buflo_exact_release_worst_guard"].update(
        {
            "active_wait_iterations": 66,
            "active_wait_authoritative_watchdog_checks": 1,
            "active_wait_authoritative_watchdog_dispatches": 1,
        }
    )

    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)

    missing_per_guard_proof = json.loads(json.dumps(receipt))
    missing_per_guard_proof[
        "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards"
    ] -= 1
    assert not _runner_wakeup_metrics_valid(missing_per_guard_proof)
    assert not _fidelity_runner_wakeup_metrics_valid(missing_per_guard_proof)

    one_fewer_check = json.loads(json.dumps(receipt))
    one_fewer_check["buflo_exact_release_active_wait_authoritative_watchdog_checks"] -= 1
    assert not _runner_wakeup_metrics_valid(one_fewer_check)
    assert not _fidelity_runner_wakeup_metrics_valid(one_fewer_check)

    one_extra_check = json.loads(json.dumps(receipt))
    one_extra_check["buflo_exact_release_active_wait_authoritative_watchdog_checks"] = 3
    assert not _runner_wakeup_metrics_valid(one_extra_check)
    assert not _fidelity_runner_wakeup_metrics_valid(one_extra_check)


def test_runner_wakeup_schema_ten_rejects_single_success_aggregate_divergence() -> None:
    mutations: list[tuple[str, dict[str, object]]] = []

    hidden_watchdog = _runner_wakeup_receipt_v10(guard_entries=1)
    hidden_watchdog["buflo_exact_release_active_wait_iterations"] = 66
    hidden_watchdog["buflo_exact_release_active_wait_authoritative_watchdog_checks"] = 1
    mutations.append(("iterations and watchdog checks", hidden_watchdog))

    hidden_sample_gap = _runner_wakeup_receipt_v10(guard_entries=1)
    hidden_sample_gap["buflo_exact_release_worst_guard"][
        "max_authoritative_sample_gap_nanoseconds"
    ] = 0
    mutations.append(("authoritative sample gap", hidden_sample_gap))

    for key in (
        "buflo_exact_release_max_authoritative_counter_lag_nanoseconds",
        "buflo_exact_release_max_counter_authoritative_lead_nanoseconds",
    ):
        hidden_drift = _runner_wakeup_receipt_v10(guard_entries=1)
        hidden_drift[key] = 1
        mutations.append((key, hidden_drift))

    for label, receipt in mutations:
        assert not _runner_wakeup_metrics_valid(receipt), label
        assert not _fidelity_runner_wakeup_metrics_valid(receipt), label


def test_runner_wakeup_schema_ten_requires_exact_bounded_watchdog_fields() -> None:
    receipt = _runner_wakeup_receipt_v10(guard_entries=1)
    for missing in (
        "buflo_exact_release_active_wait_authoritative_watchdog_checks",
        "buflo_exact_release_max_authoritative_sample_gap_nanoseconds",
    ):
        invalid = json.loads(json.dumps(receipt))
        invalid.pop(missing)
        assert not _runner_wakeup_metrics_valid(invalid)
        assert not _fidelity_runner_wakeup_metrics_valid(invalid)

    invalid = json.loads(json.dumps(receipt))
    invalid["buflo_exact_release_worst_guard"]["max_authoritative_sample_gap_nanoseconds"] = (
        invalid["buflo_exact_release_worst_guard"]["active_wait_monotonic_nanoseconds"] + 1
    )
    invalid["buflo_exact_release_max_authoritative_sample_gap_nanoseconds"] = invalid[
        "buflo_exact_release_worst_guard"
    ]["max_authoritative_sample_gap_nanoseconds"]
    assert not _runner_wakeup_metrics_valid(invalid)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid)


def test_runner_wakeup_schema_ten_requires_exact_top_level_keys() -> None:
    receipt = _runner_wakeup_receipt_v10(guard_entries=1)
    for missing in tuple(receipt):
        invalid = json.loads(json.dumps(receipt))
        invalid.pop(missing)
        assert not _runner_wakeup_metrics_valid(invalid), missing
        assert not _fidelity_runner_wakeup_metrics_valid(invalid), missing

    extra = json.loads(json.dumps(receipt))
    extra["unknown_schema_ten_field"] = 0
    assert not _runner_wakeup_metrics_valid(extra)
    assert not _fidelity_runner_wakeup_metrics_valid(extra)


def test_runner_wakeup_schema_ten_rejects_unhashable_enum_values() -> None:
    receipt = _runner_wakeup_receipt_v10(guard_entries=2)
    mutations: list[tuple[str, dict[str, object]]] = []

    invalid_top_source = json.loads(json.dumps(receipt))
    invalid_top_source["buflo_exact_release_active_wait_poll_source"] = {}
    mutations.append(("top-level poll source", invalid_top_source))

    invalid_worst_phase = json.loads(json.dumps(receipt))
    invalid_worst_phase["buflo_exact_release_worst_guard"]["phase"] = {}
    mutations.append(("worst-guard phase", invalid_worst_phase))

    invalid_worst_source = json.loads(json.dumps(receipt))
    invalid_worst_source["buflo_exact_release_worst_guard"]["active_wait_poll_source"] = []
    mutations.append(("worst-guard poll source", invalid_worst_source))

    mixed = _runner_wakeup_v10_mixed_failure("counter-unavailable")
    for label, key, malformed in (
        ("failure outcome", "outcome", {}),
        ("failure phase", "phase", []),
        ("failure poll source", "active_wait_poll_source", {}),
    ):
        invalid_failure = json.loads(json.dumps(mixed))
        invalid_failure["buflo_exact_release_last_failure"][key] = malformed
        mutations.append((label, invalid_failure))

    for label, invalid in mutations:
        assert not _runner_wakeup_metrics_valid(invalid), label
        assert not _fidelity_runner_wakeup_metrics_valid(invalid), label


def test_runner_wakeup_schema_ten_fallback_zeroes_watchdog_evidence() -> None:
    receipt = _runner_wakeup_receipt_v10(guard_entries=1)
    receipt.update(
        {
            "buflo_exact_release_active_wait_poll_source": "instant-authoritative-fallback-v1",
            "buflo_exact_release_active_wait_counter_frequency_hz": None,
            "buflo_exact_release_active_wait_counter_guards": 0,
            "buflo_exact_release_active_wait_counter_unavailable_guards": 1,
            "buflo_exact_release_active_wait_counter_calibrations": 0,
            "buflo_exact_release_active_wait_instant_confirmations": 0,
            "buflo_exact_release_active_wait_counter_nanoseconds": 0,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": 0,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": 0,
            **{
                key: 0
                for key in (
                    "buflo_exact_release_active_wait_authoritative_watchdog_checks",
                    "buflo_exact_release_active_wait_authoritative_watchdog_dispatches",
                    "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards",
                    "buflo_exact_release_max_authoritative_sample_gap_nanoseconds",
                    "buflo_exact_release_max_authoritative_counter_lag_nanoseconds",
                    "buflo_exact_release_max_counter_authoritative_lead_nanoseconds",
                )
            },
        }
    )
    worst = receipt["buflo_exact_release_worst_guard"]
    worst.update(
        {
            "active_wait_poll_source": "instant-authoritative-fallback-v1",
            "active_wait_counter_frequency_hz": None,
            "active_wait_counter_calibrations": 0,
            "active_wait_instant_confirmations": 0,
            "active_wait_counter_nanoseconds": None,
            "max_active_wait_counter_gap_nanoseconds": None,
            "max_counter_calibration_span_nanoseconds": None,
            **{
                key: 0
                for key in (
                    "active_wait_authoritative_watchdog_checks",
                    "active_wait_authoritative_watchdog_dispatches",
                    "max_authoritative_sample_gap_nanoseconds",
                    "max_authoritative_counter_lag_nanoseconds",
                    "max_counter_authoritative_lead_nanoseconds",
                )
            },
        }
    )

    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)

    receipt["buflo_exact_release_max_authoritative_sample_gap_nanoseconds"] = 1
    assert not _runner_wakeup_metrics_valid(receipt)
    assert not _fidelity_runner_wakeup_metrics_valid(receipt)


def test_runner_wakeup_schema_ten_bounds_retained_failure_watchdog_dispatch() -> None:
    receipt = _runner_wakeup_v10_typed_failure("counter-frequency-changed")
    receipt["buflo_exact_release_active_wait_iterations"] += 64
    receipt["buflo_exact_release_active_wait_authoritative_watchdog_checks"] = 1
    receipt["buflo_exact_release_active_wait_authoritative_watchdog_dispatches"] = 1
    failure = receipt["buflo_exact_release_last_failure"]
    failure["active_wait_iterations"] += 64
    failure["authoritative_watchdog_checks"] = 1
    failure["authoritative_watchdog_dispatches"] = 1

    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)

    failure["max_authoritative_counter_lag_nanoseconds"] = (
        receipt["buflo_exact_release_active_wait_nanoseconds"] + 1
    )
    receipt["buflo_exact_release_max_authoritative_counter_lag_nanoseconds"] = failure[
        "max_authoritative_counter_lag_nanoseconds"
    ]
    assert not _runner_wakeup_metrics_valid(receipt)
    assert not _fidelity_runner_wakeup_metrics_valid(receipt)


def test_runner_wakeup_schema_ten_accepts_typed_unavailable_after_watchdog_sample() -> None:
    receipt = _runner_wakeup_v10_typed_failure("counter-unavailable")
    receipt.update(
        {
            "buflo_exact_release_active_wait_iterations": 67,
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": 1,
            "buflo_exact_release_max_authoritative_sample_gap_nanoseconds": 1,
            "buflo_exact_release_max_authoritative_counter_lag_nanoseconds": 1,
            "buflo_exact_release_max_counter_authoritative_lead_nanoseconds": 1,
        }
    )
    failure = receipt["buflo_exact_release_last_failure"]
    failure.update(
        {
            "active_wait_iterations": 67,
            "authoritative_watchdog_checks": 1,
            "max_authoritative_sample_gap_nanoseconds": 1,
            "max_authoritative_counter_lag_nanoseconds": 1,
            "max_counter_authoritative_lead_nanoseconds": 1,
        }
    )

    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)

    missing_terminal_read = json.loads(json.dumps(receipt))
    missing_terminal_read["buflo_exact_release_active_wait_iterations"] = 66
    assert not _runner_wakeup_metrics_valid(missing_terminal_read)
    assert not _fidelity_runner_wakeup_metrics_valid(missing_terminal_read)

    nested_to_aggregate = {
        "authoritative_watchdog_checks": (
            "buflo_exact_release_active_wait_authoritative_watchdog_checks"
        ),
        "max_authoritative_sample_gap_nanoseconds": (
            "buflo_exact_release_max_authoritative_sample_gap_nanoseconds"
        ),
        "max_authoritative_counter_lag_nanoseconds": (
            "buflo_exact_release_max_authoritative_counter_lag_nanoseconds"
        ),
        "max_counter_authoritative_lead_nanoseconds": (
            "buflo_exact_release_max_counter_authoritative_lead_nanoseconds"
        ),
    }
    for nested_key, aggregate_key in nested_to_aggregate.items():
        hidden_failure_value = json.loads(json.dumps(receipt))
        assert hidden_failure_value[aggregate_key] == 1
        hidden_failure_value["buflo_exact_release_last_failure"][nested_key] = 0
        assert not _runner_wakeup_metrics_valid(hidden_failure_value), nested_key
        assert not _fidelity_runner_wakeup_metrics_valid(hidden_failure_value), nested_key


def test_runner_wakeup_schema_ten_accepts_unavailable_after_early_confirmation() -> None:
    receipt = _runner_wakeup_v10_typed_failure("counter-unavailable")
    receipt.update(
        {
            "buflo_exact_release_active_wait_iterations": 4,
            "buflo_exact_release_active_wait_instant_confirmations": 1,
            "buflo_exact_release_active_wait_early_confirmation_retries": 1,
            "buflo_exact_release_max_counter_authoritative_lead_nanoseconds": 1,
        }
    )
    receipt["buflo_exact_release_last_failure"].update(
        {
            "active_wait_iterations": 4,
            "instant_confirmations": 1,
            "early_confirmation_retries": 1,
            "max_counter_authoritative_lead_nanoseconds": 1,
        }
    )

    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)


def test_runner_wakeup_schema_ten_binds_first_calibration_target_error_state() -> None:
    first_calibration = _runner_wakeup_v10_typed_failure("counter-target-error")
    first_calibration["buflo_exact_release_max_authoritative_sample_gap_nanoseconds"] = 1
    first_calibration["buflo_exact_release_last_failure"][
        "max_authoritative_sample_gap_nanoseconds"
    ] = 1
    assert _runner_wakeup_metrics_valid(first_calibration)
    assert _fidelity_runner_wakeup_metrics_valid(first_calibration)

    mutations: list[tuple[str, dict[str, object]]] = []
    extra_iteration = json.loads(json.dumps(first_calibration))
    extra_iteration["buflo_exact_release_active_wait_iterations"] = 3
    mutations.append(("extra first-calibration read", extra_iteration))

    hidden_watchdog = json.loads(json.dumps(first_calibration))
    hidden_watchdog["buflo_exact_release_active_wait_iterations"] = 66
    hidden_watchdog["buflo_exact_release_active_wait_authoritative_watchdog_checks"] = 1
    hidden_watchdog["buflo_exact_release_last_failure"]["authoritative_watchdog_checks"] = 1
    mutations.append(("first-calibration watchdog", hidden_watchdog))

    for nested_key, aggregate_key in (
        (
            "max_authoritative_counter_lag_nanoseconds",
            "buflo_exact_release_max_authoritative_counter_lag_nanoseconds",
        ),
        (
            "max_counter_authoritative_lead_nanoseconds",
            "buflo_exact_release_max_counter_authoritative_lead_nanoseconds",
        ),
    ):
        hidden_comparison = json.loads(json.dumps(first_calibration))
        hidden_comparison[aggregate_key] = 1
        hidden_comparison["buflo_exact_release_last_failure"][nested_key] = 1
        mutations.append((nested_key, hidden_comparison))

    for label, invalid in mutations:
        assert not _runner_wakeup_metrics_valid(invalid), label
        assert not _fidelity_runner_wakeup_metrics_valid(invalid), label

    two_successes_and_failure = _runner_wakeup_v10_mixed_failure(
        "counter-unavailable",
        successes=2,
    )
    assert _runner_wakeup_metrics_valid(two_successes_and_failure)
    assert _fidelity_runner_wakeup_metrics_valid(two_successes_and_failure)
    maximum_success_active_wait = (
        5_000_000
        + two_successes_and_failure["buflo_exact_release_max_guard_exit_lateness_nanoseconds"]
    )
    retained_failure_active_wait = two_successes_and_failure["buflo_exact_release_last_failure"][
        "active_wait_monotonic_nanoseconds"
    ]
    mixed_duration_ceiling = 2 * maximum_success_active_wait + retained_failure_active_wait
    inflated_mixed_duration = json.loads(json.dumps(two_successes_and_failure))
    inflated_mixed_duration.update(
        {
            "buflo_exact_release_guard_wait_nanoseconds": mixed_duration_ceiling + 1,
            "buflo_exact_release_active_wait_nanoseconds": mixed_duration_ceiling + 1,
        }
    )
    assert not _runner_wakeup_metrics_valid(inflated_mixed_duration)
    assert not _fidelity_runner_wakeup_metrics_valid(inflated_mixed_duration)
    for key in (
        "buflo_exact_release_max_authoritative_sample_gap_nanoseconds",
        "buflo_exact_release_max_authoritative_counter_lag_nanoseconds",
    ):
        impossible_mixed_maximum = json.loads(json.dumps(two_successes_and_failure))
        impossible_mixed_maximum[key] = maximum_success_active_wait + 1
        assert not _runner_wakeup_metrics_valid(impossible_mixed_maximum), key
        assert not _fidelity_runner_wakeup_metrics_valid(impossible_mixed_maximum), key

    long_failure = json.loads(json.dumps(two_successes_and_failure))
    retained_long_failure = long_failure["buflo_exact_release_last_failure"]
    previous_failure_duration = retained_long_failure["active_wait_monotonic_nanoseconds"]
    retained_long_failure.update(
        {
            "active_wait_monotonic_nanoseconds": 100_000_000,
            "exit_before_release_nanoseconds": 0,
            "exit_at_or_after_deadline": True,
        }
    )
    for key in (
        "guard_at_defense_nanoseconds",
        "entered_at_defense_nanoseconds",
        "active_wait_at_defense_nanoseconds",
        "active_wait_started_at_defense_nanoseconds",
        "release_at_defense_nanoseconds",
        "deadline_at_defense_nanoseconds",
        "exited_at_defense_nanoseconds",
    ):
        retained_long_failure[key] = None
    failure_duration_delta = 100_000_000 - previous_failure_duration
    long_failure["buflo_exact_release_guard_wait_nanoseconds"] += failure_duration_delta
    long_failure["buflo_exact_release_active_wait_nanoseconds"] += failure_duration_delta
    assert _runner_wakeup_metrics_valid(long_failure)
    assert _fidelity_runner_wakeup_metrics_valid(long_failure)
    for key in (
        "buflo_exact_release_max_authoritative_sample_gap_nanoseconds",
        "buflo_exact_release_max_authoritative_counter_lag_nanoseconds",
    ):
        impossible_long_failure_maximum = json.loads(json.dumps(long_failure))
        impossible_long_failure_maximum[key] = 50_000_000
        assert not _runner_wakeup_metrics_valid(impossible_long_failure_maximum), key
        assert not _fidelity_runner_wakeup_metrics_valid(impossible_long_failure_maximum), key

    u64_max = 2**64 - 1
    per_success_capacity = u64_max // 2 + 1
    dispatch_lateness = per_success_capacity - 5_000_000
    saturated_before_hidden_entry_subtraction = _runner_wakeup_receipt_v10(
        guard_entries=3,
        dispatch_lateness_nanoseconds=dispatch_lateness,
    )
    saturated_before_hidden_entry_subtraction.update(
        {
            "buflo_exact_release_guard_wait_nanoseconds": u64_max,
            "buflo_exact_release_active_wait_nanoseconds": u64_max,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": (per_success_capacity - 1),
            "buflo_exact_release_max_guard_entry_lateness_nanoseconds": (per_success_capacity - 1),
            "buflo_exact_release_active_wait_poll_source": ("instant-authoritative-fallback-v1"),
            "buflo_exact_release_active_wait_counter_frequency_hz": None,
            "buflo_exact_release_active_wait_counter_guards": 0,
            "buflo_exact_release_active_wait_counter_unavailable_guards": 3,
            "buflo_exact_release_active_wait_counter_calibrations": 0,
            "buflo_exact_release_active_wait_instant_confirmations": 0,
            "buflo_exact_release_active_wait_counter_nanoseconds": 0,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": 0,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": 0,
            "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards": 0,
            "buflo_exact_release_max_authoritative_sample_gap_nanoseconds": 0,
        }
    )
    saturated_worst = saturated_before_hidden_entry_subtraction["buflo_exact_release_worst_guard"]
    saturated_worst.update(
        {
            "guard_entry_lateness_nanoseconds": per_success_capacity - 2,
            "active_wait_monotonic_nanoseconds": 2,
            "active_wait_poll_source": "instant-authoritative-fallback-v1",
            "active_wait_counter_frequency_hz": None,
            "active_wait_counter_calibrations": 0,
            "active_wait_instant_confirmations": 0,
            "active_wait_counter_nanoseconds": None,
            "max_active_wait_counter_gap_nanoseconds": None,
            "max_counter_calibration_span_nanoseconds": None,
            "max_authoritative_sample_gap_nanoseconds": 0,
            "dispatch_at_or_after_deadline": True,
            "dispatch_after_deadline_nanoseconds": dispatch_lateness - 5_000_000,
        }
    )
    for key in (
        "guard_at_defense_nanoseconds",
        "entered_at_defense_nanoseconds",
        "active_wait_at_defense_nanoseconds",
        "active_wait_started_at_defense_nanoseconds",
        "release_at_defense_nanoseconds",
        "deadline_at_defense_nanoseconds",
        "dispatch_at_defense_nanoseconds",
    ):
        saturated_worst[key] = None
    assert not _runner_wakeup_metrics_valid(saturated_before_hidden_entry_subtraction)
    assert not _fidelity_runner_wakeup_metrics_valid(saturated_before_hidden_entry_subtraction)

    saturated_success_lateness = u64_max - 4_999_000
    saturated_per_success_sum = _runner_wakeup_receipt_v10(
        guard_entries=2,
        dispatch_lateness_nanoseconds=saturated_success_lateness,
    )
    saturated_per_success_sum.update(
        {
            "buflo_exact_release_guard_wait_nanoseconds": 2_000,
            "buflo_exact_release_active_wait_nanoseconds": 2_000,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": u64_max,
            "buflo_exact_release_max_guard_entry_lateness_nanoseconds": u64_max,
            "buflo_exact_release_max_guard_exit_lateness_nanoseconds": (saturated_success_lateness),
            "buflo_exact_release_active_wait_counter_nanoseconds": 2_000,
            "buflo_exact_release_dispatch_at_or_after_deadline_guards": 2,
            "buflo_exact_release_max_authoritative_sample_gap_nanoseconds": 1_000,
            "buflo_exact_release_dispatch_lateness_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": [0, 0, 0, 0, 0, 0, 0, 2],
            },
        }
    )
    saturated_success_worst = saturated_per_success_sum["buflo_exact_release_worst_guard"]
    saturated_success_worst.update(
        {
            "guard_entry_lateness_nanoseconds": u64_max - 1_000,
            "active_wait_monotonic_nanoseconds": 1_000,
            "active_wait_counter_nanoseconds": 1_000,
            "dispatch_lateness_nanoseconds": saturated_success_lateness,
            "dispatch_at_or_after_deadline": True,
            "dispatch_after_deadline_nanoseconds": (saturated_success_lateness - 4_999_000),
            "max_authoritative_sample_gap_nanoseconds": 1_000,
        }
    )
    for key in (
        "guard_at_defense_nanoseconds",
        "entered_at_defense_nanoseconds",
        "active_wait_at_defense_nanoseconds",
        "active_wait_started_at_defense_nanoseconds",
        "release_at_defense_nanoseconds",
        "deadline_at_defense_nanoseconds",
        "dispatch_at_defense_nanoseconds",
    ):
        saturated_success_worst[key] = None
    assert _runner_wakeup_metrics_valid(saturated_per_success_sum)
    assert _fidelity_runner_wakeup_metrics_valid(saturated_per_success_sum)

    later_target_error = _runner_wakeup_v10_typed_failure("counter-target-error")
    later_target_error.update(
        {
            "buflo_exact_release_active_wait_iterations": 5,
            "buflo_exact_release_active_wait_counter_calibrations": 2,
            "buflo_exact_release_active_wait_instant_confirmations": 1,
            "buflo_exact_release_active_wait_early_confirmation_retries": 1,
            "buflo_exact_release_max_authoritative_counter_lag_nanoseconds": 1,
            "buflo_exact_release_max_counter_authoritative_lead_nanoseconds": 1,
        }
    )
    later_target_error["buflo_exact_release_last_failure"].update(
        {
            "active_wait_iterations": 5,
            "counter_calibrations": 2,
            "instant_confirmations": 1,
            "early_confirmation_retries": 1,
            "max_authoritative_counter_lag_nanoseconds": 1,
            "max_counter_authoritative_lead_nanoseconds": 1,
        }
    )
    assert _runner_wakeup_metrics_valid(later_target_error)
    assert _fidelity_runner_wakeup_metrics_valid(later_target_error)


def test_runner_wakeup_schema_ten_binds_mixed_success_failure_aggregates() -> None:
    receipt = _runner_wakeup_v10_typed_failure(
        "counter-frequency-changed",
        nullable_chronology=False,
    )
    worst = receipt["buflo_exact_release_worst_guard"]
    failure = receipt["buflo_exact_release_last_failure"]
    worst.update(
        {
            "active_wait_iterations": 66,
            "active_wait_authoritative_watchdog_checks": 1,
            "active_wait_authoritative_watchdog_dispatches": 1,
        }
    )
    failure.update(
        {
            "active_wait_iterations": 66,
            "authoritative_watchdog_checks": 1,
            "authoritative_watchdog_dispatches": 1,
        }
    )
    receipt.update(
        {
            "buflo_exact_release_active_wait_iterations": 132,
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": 2,
            "buflo_exact_release_active_wait_authoritative_watchdog_dispatches": 2,
        }
    )

    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)

    hidden_additive_values: list[tuple[str, int]] = [
        ("buflo_exact_release_active_wait_authoritative_watchdog_checks", 1),
        ("buflo_exact_release_active_wait_authoritative_watchdog_dispatches", 1),
        (
            "buflo_exact_release_active_wait_counter_nanoseconds",
            max(
                worst["active_wait_counter_nanoseconds"] or 0,
                failure["counter_nanoseconds"] or 0,
            ),
        ),
        (
            "buflo_exact_release_guard_wait_nanoseconds",
            receipt["buflo_exact_release_guard_wait_nanoseconds"] - 1,
        ),
        (
            "buflo_exact_release_active_wait_nanoseconds",
            receipt["buflo_exact_release_active_wait_nanoseconds"] - 1,
        ),
    ]
    for key, hidden_value in hidden_additive_values:
        invalid = json.loads(json.dumps(receipt))
        invalid[key] = hidden_value
        if key in {
            "buflo_exact_release_guard_wait_nanoseconds",
            "buflo_exact_release_active_wait_nanoseconds",
        }:
            invalid["buflo_exact_release_guard_wait_nanoseconds"] = hidden_value
            invalid["buflo_exact_release_active_wait_nanoseconds"] = hidden_value
        assert not _runner_wakeup_metrics_valid(invalid), key
        assert not _fidelity_runner_wakeup_metrics_valid(invalid), key

    hidden_frequency_change_reads = json.loads(json.dumps(receipt))
    hidden_frequency_change_reads["buflo_exact_release_active_wait_iterations"] = 133
    assert not _runner_wakeup_metrics_valid(hidden_frequency_change_reads)
    assert not _fidelity_runner_wakeup_metrics_valid(hidden_frequency_change_reads)


@pytest.mark.parametrize(
    "outcome",
    (
        "invalid-counter-frequency",
        "counter-unavailable",
        "counter-nonmonotonic",
        "counter-target-error",
    ),
)
def test_runner_wakeup_schema_ten_binds_exact_sole_success_failure_pair(outcome: str) -> None:
    receipt = _runner_wakeup_v10_mixed_failure(outcome)
    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)

    mutations: list[tuple[str, dict[str, object]]] = []
    longer_pair = json.loads(json.dumps(receipt))
    longer_pair["buflo_exact_release_guard_wait_nanoseconds"] += 1
    longer_pair["buflo_exact_release_active_wait_nanoseconds"] += 1
    mutations.append(("paired duration", longer_pair))

    extra_counter = json.loads(json.dumps(receipt))
    extra_counter["buflo_exact_release_active_wait_counter_nanoseconds"] += 1
    mutations.append(("paired counter sum", extra_counter))

    for key in (
        "buflo_exact_release_max_authoritative_sample_gap_nanoseconds",
        "buflo_exact_release_max_authoritative_counter_lag_nanoseconds",
        "buflo_exact_release_max_counter_authoritative_lead_nanoseconds",
    ):
        extra_maximum = json.loads(json.dumps(receipt))
        extra_maximum[key] += 1
        mutations.append((key, extra_maximum))

    for label, invalid in mutations:
        assert not _runner_wakeup_metrics_valid(invalid), label
        assert not _fidelity_runner_wakeup_metrics_valid(invalid), label


def test_runner_wakeup_schema_ten_binds_failure_watchdog_cadence_interval() -> None:
    impossible: list[tuple[str, dict[str, object]]] = []

    unavailable_zero_checks = _runner_wakeup_v10_typed_failure("counter-unavailable")
    unavailable_zero_checks["buflo_exact_release_active_wait_iterations"] = 100
    impossible.append(("unavailable K0 I100", unavailable_zero_checks))
    for iterations in range(3, 66):
        unavailable_extra_reads = _runner_wakeup_v10_typed_failure("counter-unavailable")
        unavailable_extra_reads["buflo_exact_release_active_wait_iterations"] = iterations
        unavailable_extra_reads["buflo_exact_release_active_wait_counter_calibrations"] = 0
        unavailable_extra_reads["buflo_exact_release_active_wait_counter_nanoseconds"] = 0
        unavailable_extra_reads["buflo_exact_release_max_active_wait_counter_gap_nanoseconds"] = 0
        unavailable_extra_reads["buflo_exact_release_max_counter_calibration_span_nanoseconds"] = 0
        unavailable_extra_reads["buflo_exact_release_last_failure"]["counter_calibrations"] = 0
        unavailable_extra_reads["buflo_exact_release_last_failure"].update(
            {
                "counter_nanoseconds": 0,
                "max_counter_gap_nanoseconds": 0,
                "max_counter_calibration_span_nanoseconds": 0,
            }
        )
        impossible.append((f"unavailable C0 I{iterations}", unavailable_extra_reads))

    nonmonotonic_zero_checks = _runner_wakeup_v10_typed_failure("counter-nonmonotonic")
    nonmonotonic_zero_checks["buflo_exact_release_active_wait_iterations"] = 100
    impossible.append(("nonmonotonic K0 I100", nonmonotonic_zero_checks))
    for iterations in range(3, 66):
        nonmonotonic_extra_reads = _runner_wakeup_v10_typed_failure("counter-nonmonotonic")
        nonmonotonic_extra_reads["buflo_exact_release_active_wait_iterations"] = iterations
        impossible.append((f"nonmonotonic C0 I{iterations}", nonmonotonic_extra_reads))

    later_target_zero_checks = _runner_wakeup_v10_typed_failure("counter-target-error")
    later_target_zero_checks.update(
        {
            "buflo_exact_release_active_wait_iterations": 100,
            "buflo_exact_release_active_wait_counter_calibrations": 2,
            "buflo_exact_release_active_wait_instant_confirmations": 1,
            "buflo_exact_release_active_wait_early_confirmation_retries": 1,
        }
    )
    later_target_zero_checks["buflo_exact_release_last_failure"].update(
        {
            "active_wait_iterations": 100,
            "counter_calibrations": 2,
            "instant_confirmations": 1,
            "early_confirmation_retries": 1,
        }
    )
    impossible.append(("target K0 I100", later_target_zero_checks))

    unavailable_one_check = _runner_wakeup_v10_typed_failure("counter-unavailable")
    unavailable_one_check["buflo_exact_release_active_wait_iterations"] = 200
    unavailable_one_check["buflo_exact_release_active_wait_authoritative_watchdog_checks"] = 1
    unavailable_one_check["buflo_exact_release_last_failure"]["authoritative_watchdog_checks"] = 1
    impossible.append(("unavailable K1 I200", unavailable_one_check))

    for label, invalid in impossible:
        assert not _runner_wakeup_metrics_valid(invalid), label
        assert not _fidelity_runner_wakeup_metrics_valid(invalid), label


def test_runner_wakeup_schema_ten_binds_nullable_duration_and_buflo_retry_lateness() -> None:
    u64_max = 2**64 - 1
    success = _runner_wakeup_receipt_v10(guard_entries=1)
    assert _runner_wakeup_metrics_valid(success)
    assert _fidelity_runner_wakeup_metrics_valid(success)

    invalid_success = json.loads(json.dumps(success))
    invalid_success["buflo_exact_release_active_wait_nanoseconds"] += 1
    invalid_success["buflo_exact_release_guard_wait_nanoseconds"] += 1
    invalid_success["buflo_exact_release_worst_guard"]["active_wait_monotonic_nanoseconds"] += 1
    assert not _runner_wakeup_metrics_valid(invalid_success)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_success)

    failure = _runner_wakeup_v10_typed_failure("counter-target-error")
    assert _runner_wakeup_metrics_valid(failure)
    assert _fidelity_runner_wakeup_metrics_valid(failure)
    invalid_failure = json.loads(json.dumps(failure))
    invalid_failure["buflo_exact_release_active_wait_nanoseconds"] += 1
    invalid_failure["buflo_exact_release_guard_wait_nanoseconds"] += 1
    invalid_failure["buflo_exact_release_last_failure"]["active_wait_monotonic_nanoseconds"] += 1
    assert not _runner_wakeup_metrics_valid(invalid_failure)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_failure)

    overflow_success = _runner_wakeup_receipt_v10(guard_entries=1)
    overflow_worst = overflow_success["buflo_exact_release_worst_guard"]
    for key in (
        "guard_at_defense_nanoseconds",
        "entered_at_defense_nanoseconds",
        "active_wait_at_defense_nanoseconds",
        "active_wait_started_at_defense_nanoseconds",
        "release_at_defense_nanoseconds",
        "deadline_at_defense_nanoseconds",
        "dispatch_at_defense_nanoseconds",
    ):
        overflow_worst[key] = None
    overflow_worst.update(
        {
            "guard_entry_lateness_nanoseconds": 4_999_000,
            "active_wait_monotonic_nanoseconds": u64_max,
            "dispatch_lateness_nanoseconds": u64_max,
            "dispatch_at_or_after_deadline": True,
            "dispatch_after_deadline_nanoseconds": u64_max - 4_999_000,
            "max_authoritative_sample_gap_nanoseconds": u64_max,
        }
    )
    overflow_success.update(
        {
            "buflo_exact_release_guard_wait_nanoseconds": u64_max,
            "buflo_exact_release_active_wait_nanoseconds": u64_max,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 4_999_000,
            "buflo_exact_release_max_guard_entry_lateness_nanoseconds": 4_999_000,
            "buflo_exact_release_max_guard_exit_lateness_nanoseconds": u64_max,
            "buflo_exact_release_dispatch_at_or_after_deadline_guards": 1,
            "buflo_exact_release_max_authoritative_sample_gap_nanoseconds": u64_max,
        }
    )
    overflow_success["buflo_exact_release_dispatch_lateness_histogram"]["counts"] = [
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
    ]
    assert not _runner_wakeup_metrics_valid(overflow_success)
    assert not _fidelity_runner_wakeup_metrics_valid(overflow_success)

    overflow_failure = _runner_wakeup_v10_typed_failure("invalid-counter-frequency")
    retained_failure = overflow_failure["buflo_exact_release_last_failure"]
    for key in (
        "guard_at_defense_nanoseconds",
        "entered_at_defense_nanoseconds",
        "active_wait_at_defense_nanoseconds",
        "active_wait_started_at_defense_nanoseconds",
        "release_at_defense_nanoseconds",
        "deadline_at_defense_nanoseconds",
        "exited_at_defense_nanoseconds",
    ):
        retained_failure[key] = None
    retained_failure.update(
        {
            "guard_entry_lateness_nanoseconds": u64_max,
            "active_wait_monotonic_nanoseconds": 1,
            "max_authoritative_sample_gap_nanoseconds": 1,
            "exit_before_release_nanoseconds": 0,
            "exit_at_or_after_deadline": True,
        }
    )
    overflow_failure.update(
        {
            "buflo_exact_release_guard_wait_nanoseconds": 1,
            "buflo_exact_release_active_wait_nanoseconds": 1,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": u64_max,
            "buflo_exact_release_max_guard_entry_lateness_nanoseconds": u64_max,
            "buflo_exact_release_max_authoritative_sample_gap_nanoseconds": 1,
        }
    )
    assert not _runner_wakeup_metrics_valid(overflow_failure)
    assert not _fidelity_runner_wakeup_metrics_valid(overflow_failure)

    retry_lateness = _runner_wakeup_receipt_v10(guard_entries=0)
    retry_lateness["buflo_exact_incoming_retry_max_wake_lateness_nanoseconds"] = 1
    assert not _runner_wakeup_metrics_valid(retry_lateness)
    assert not _fidelity_runner_wakeup_metrics_valid(retry_lateness)

    two_successes = _runner_wakeup_receipt_v10(guard_entries=2)
    assert _runner_wakeup_metrics_valid(two_successes)
    assert _fidelity_runner_wakeup_metrics_valid(two_successes)
    erased_remaining_duration = json.loads(json.dumps(two_successes))
    retained_duration = erased_remaining_duration["buflo_exact_release_worst_guard"][
        "active_wait_monotonic_nanoseconds"
    ]
    erased_remaining_duration["buflo_exact_release_active_wait_nanoseconds"] = (
        retained_duration + 1_000
    )
    erased_remaining_duration["buflo_exact_release_guard_wait_nanoseconds"] = (
        retained_duration + 1_000
    )
    assert not _runner_wakeup_metrics_valid(erased_remaining_duration)
    assert not _fidelity_runner_wakeup_metrics_valid(erased_remaining_duration)


def test_runner_wakeup_schema_ten_requires_relaxed_read_per_early_retry() -> None:
    impossible: list[tuple[str, dict[str, object]]] = []

    success = _runner_wakeup_receipt_v10(guard_entries=1)
    success.update(
        {
            "buflo_exact_release_active_wait_iterations": 4,
            "buflo_exact_release_active_wait_counter_calibrations": 2,
            "buflo_exact_release_active_wait_instant_confirmations": 2,
            "buflo_exact_release_active_wait_early_confirmation_retries": 1,
        }
    )
    success["buflo_exact_release_worst_guard"].update(
        {
            "active_wait_iterations": 4,
            "active_wait_counter_calibrations": 2,
            "active_wait_instant_confirmations": 2,
            "active_wait_early_confirmation_retries": 1,
        }
    )
    impossible.append(("success without relaxed retry read", success))

    target = _runner_wakeup_v10_typed_failure("counter-target-error")
    target.update(
        {
            "buflo_exact_release_active_wait_iterations": 4,
            "buflo_exact_release_active_wait_counter_calibrations": 2,
            "buflo_exact_release_active_wait_instant_confirmations": 1,
            "buflo_exact_release_active_wait_early_confirmation_retries": 1,
        }
    )
    target["buflo_exact_release_last_failure"].update(
        {
            "counter_calibrations": 2,
            "instant_confirmations": 1,
            "early_confirmation_retries": 1,
        }
    )
    impossible.append(("target failure without relaxed retry read", target))

    for outcome in ("counter-unavailable", "counter-nonmonotonic"):
        failure = _runner_wakeup_v10_typed_failure(outcome)
        failure.update(
            {
                "buflo_exact_release_active_wait_iterations": 3,
                "buflo_exact_release_active_wait_counter_calibrations": 1,
                "buflo_exact_release_active_wait_instant_confirmations": 1,
                "buflo_exact_release_active_wait_early_confirmation_retries": 1,
            }
        )
        failure["buflo_exact_release_last_failure"].update(
            {
                "counter_calibrations": 1,
                "instant_confirmations": 1,
                "early_confirmation_retries": 1,
            }
        )
        impossible.append((f"{outcome} without relaxed retry read", failure))

    for label, invalid in impossible:
        assert not _runner_wakeup_metrics_valid(invalid), label
        assert not _fidelity_runner_wakeup_metrics_valid(invalid), label


@pytest.mark.parametrize("outcome", ("counter-unavailable", "counter-nonmonotonic"))
def test_runner_wakeup_schema_ten_rejects_comparison_without_authoritative_sample(
    outcome: str,
) -> None:
    receipt = _runner_wakeup_v10_typed_failure(outcome)
    receipt["buflo_exact_release_max_authoritative_counter_lag_nanoseconds"] = 1
    receipt["buflo_exact_release_last_failure"]["max_authoritative_counter_lag_nanoseconds"] = 1
    assert not _runner_wakeup_metrics_valid(receipt)
    assert not _fidelity_runner_wakeup_metrics_valid(receipt)

    if outcome == "counter-unavailable":
        receipt = _runner_wakeup_v10_typed_failure(outcome)
        receipt["buflo_exact_release_max_counter_authoritative_lead_nanoseconds"] = 1
        receipt["buflo_exact_release_last_failure"][
            "max_counter_authoritative_lead_nanoseconds"
        ] = 1
        assert not _runner_wakeup_metrics_valid(receipt)
        assert not _fidelity_runner_wakeup_metrics_valid(receipt)


def test_runner_wakeup_schema_ten_binds_predictive_interruption_reachability() -> None:
    u64_max = 2**64 - 1
    saturated_aggregate = _runner_wakeup_receipt_v10(guard_entries=64)
    saturated_aggregate.update(
        {
            "buflo_exact_release_guard_wait_nanoseconds": u64_max,
            "buflo_exact_release_active_wait_nanoseconds": u64_max,
            "buflo_exact_release_active_wait_iterations": u64_max,
            "buflo_exact_release_active_spin_interruptions": u64_max - 63,
            "buflo_exact_release_active_spin_interruption_nanoseconds": u64_max,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": 50_001,
            "buflo_exact_release_active_wait_counter_calibrations": 64,
            "buflo_exact_release_active_wait_instant_confirmations": 64,
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": (u64_max // 64 - 64),
            "buflo_exact_release_active_wait_counter_nanoseconds": u64_max,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": 50_001,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": 1,
            "buflo_exact_release_active_spin_gap_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": [0, 64, 0, 0, 0, 0, 0, 0],
            },
        }
    )
    saturated_aggregate["buflo_exact_release_worst_guard"].update(
        {
            "active_wait_iterations": 65,
            "active_wait_counter_calibrations": 1,
            "active_wait_instant_confirmations": 1,
            "active_wait_authoritative_watchdog_checks": 0,
            "active_spin_interruptions": 64,
            "active_spin_interruption_nanoseconds": 3_200_064,
            "max_active_spin_gap_nanoseconds": 50_001,
            "active_wait_counter_nanoseconds": 5_000_007,
            "max_active_wait_counter_gap_nanoseconds": 50_001,
            "max_counter_calibration_span_nanoseconds": 1,
        }
    )
    assert not _runner_wakeup_metrics_valid(saturated_aggregate)
    assert not _fidelity_runner_wakeup_metrics_valid(saturated_aggregate)

    forged_hidden_success_capacity = _runner_wakeup_v10_mixed_failure("counter-unavailable")
    forged_hidden_success_capacity.update(
        {
            "buflo_exact_release_guard_entries": 3,
            "buflo_exact_release_dispatch_ready_guards": 2,
            "buflo_exact_release_active_wait_iterations": 70,
            "buflo_exact_release_active_wait_counter_guards": 2,
            "buflo_exact_release_active_wait_counter_unavailable_guards": 1,
            "buflo_exact_release_active_wait_counter_calibrations": 2,
            "buflo_exact_release_active_wait_instant_confirmations": 2,
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": 1,
            "buflo_exact_release_active_wait_authoritative_watchdog_dispatches": 1,
            "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards": 2,
            "buflo_exact_release_active_spin_interruptions": 66,
            "buflo_exact_release_active_spin_interruption_nanoseconds": 4_000_000,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": 100_000,
        }
    )
    forged_hidden_success_capacity["buflo_exact_release_last_failure"].update(
        {
            "counter_calibrations": 0,
            "counter_nanoseconds": 0,
            "max_counter_gap_nanoseconds": 0,
            "max_counter_calibration_span_nanoseconds": 0,
        }
    )
    forged_hidden_success_capacity["buflo_exact_release_dispatch_lateness_histogram"]["counts"][
        0
    ] += 1
    forged_hidden_success_capacity["buflo_exact_release_active_spin_gap_histogram"]["counts"] = [
        0,
        3,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
    assert not _runner_wakeup_metrics_valid(forged_hidden_success_capacity)
    assert not _fidelity_runner_wakeup_metrics_valid(forged_hidden_success_capacity)

    receipt = _runner_wakeup_receipt_v10(guard_entries=1)
    receipt.update(
        {
            "buflo_exact_release_active_spin_interruptions": 1,
            "buflo_exact_release_active_spin_interruption_nanoseconds": 100_000,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": 100_000,
            "buflo_exact_release_active_wait_counter_nanoseconds": 100_000,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": 100_000,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": 100_000,
            "buflo_exact_release_active_spin_gap_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": [0, 1, 0, 0, 0, 0, 0, 0],
            },
        }
    )
    receipt["buflo_exact_release_worst_guard"].update(
        {
            "active_spin_interruptions": 1,
            "active_spin_interruption_nanoseconds": 100_000,
            "max_active_spin_gap_nanoseconds": 100_000,
            "active_wait_counter_nanoseconds": 100_000,
            "max_active_wait_counter_gap_nanoseconds": 100_000,
            "max_counter_calibration_span_nanoseconds": 100_000,
        }
    )
    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)

    too_many_interruptions = json.loads(json.dumps(receipt))
    too_many_interruptions["buflo_exact_release_active_spin_interruptions"] = 2
    too_many_interruptions["buflo_exact_release_active_spin_interruption_nanoseconds"] = 200_000
    too_many_interruptions["buflo_exact_release_worst_guard"]["active_spin_interruptions"] = 2
    too_many_interruptions["buflo_exact_release_worst_guard"][
        "active_spin_interruption_nanoseconds"
    ] = 200_000
    assert not _runner_wakeup_metrics_valid(too_many_interruptions)
    assert not _fidelity_runner_wakeup_metrics_valid(too_many_interruptions)

    counter_shorter_than_interruption = json.loads(json.dumps(receipt))
    counter_shorter_than_interruption[
        "buflo_exact_release_active_spin_interruption_nanoseconds"
    ] = 200_000
    counter_shorter_than_interruption["buflo_exact_release_worst_guard"][
        "active_spin_interruption_nanoseconds"
    ] = 200_000
    assert not _runner_wakeup_metrics_valid(counter_shorter_than_interruption)
    assert not _fidelity_runner_wakeup_metrics_valid(counter_shorter_than_interruption)

    failure = _runner_wakeup_v10_typed_failure("counter-target-error")
    failure.update(
        {
            "buflo_exact_release_guard_wait_nanoseconds": 1_000_000,
            "buflo_exact_release_active_wait_nanoseconds": 1_000_000,
            "buflo_exact_release_active_spin_interruptions": 1,
            "buflo_exact_release_active_spin_interruption_nanoseconds": 100_000,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": 100_000,
            "buflo_exact_release_active_wait_counter_nanoseconds": 100_000,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": 100_000,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": 100_000,
            "buflo_exact_release_active_spin_gap_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": [0, 1, 0, 0, 0, 0, 0, 0],
            },
        }
    )
    failure["buflo_exact_release_last_failure"].update(
        {
            "active_wait_monotonic_nanoseconds": 1_000_000,
            "exit_before_release_nanoseconds": 4_000_000,
            "active_spin_interruptions": 1,
            "active_spin_interruption_nanoseconds": 100_000,
            "max_active_spin_gap_nanoseconds": 100_000,
            "counter_nanoseconds": 100_000,
            "max_counter_gap_nanoseconds": 100_000,
            "max_counter_calibration_span_nanoseconds": 100_000,
        }
    )
    assert _runner_wakeup_metrics_valid(failure)
    assert _fidelity_runner_wakeup_metrics_valid(failure)

    failure_with_two_interruptions = json.loads(json.dumps(failure))
    failure_with_two_interruptions["buflo_exact_release_active_spin_interruptions"] = 2
    failure_with_two_interruptions["buflo_exact_release_active_spin_interruption_nanoseconds"] = (
        200_000
    )
    assert not _runner_wakeup_metrics_valid(failure_with_two_interruptions)
    assert not _fidelity_runner_wakeup_metrics_valid(failure_with_two_interruptions)

    failure_with_long_interruption = json.loads(json.dumps(failure))
    failure_with_long_interruption["buflo_exact_release_active_spin_interruption_nanoseconds"] = (
        200_000
    )
    assert not _runner_wakeup_metrics_valid(failure_with_long_interruption)
    assert not _fidelity_runner_wakeup_metrics_valid(failure_with_long_interruption)

    nonmonotonic = _runner_wakeup_v10_typed_failure("counter-nonmonotonic")
    nonmonotonic.update(
        {
            "buflo_exact_release_guard_wait_nanoseconds": 1_000_000,
            "buflo_exact_release_active_wait_nanoseconds": 1_000_000,
            "buflo_exact_release_active_wait_iterations": 3,
            "buflo_exact_release_active_wait_counter_calibrations": 1,
            "buflo_exact_release_active_spin_interruptions": 1,
            "buflo_exact_release_active_spin_interruption_nanoseconds": 100_000,
            "buflo_exact_release_active_wait_counter_nanoseconds": 100_000,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": 100_000,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": 100_000,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": 100_000,
            "buflo_exact_release_active_spin_gap_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": [0, 1, 0, 0, 0, 0, 0, 0],
            },
        }
    )
    nonmonotonic["buflo_exact_release_last_failure"].update(
        {
            "active_wait_iterations": 3,
            "active_wait_monotonic_nanoseconds": 1_000_000,
            "exit_before_release_nanoseconds": 4_000_000,
            "active_spin_interruptions": 1,
            "active_spin_interruption_nanoseconds": 100_000,
            "max_active_spin_gap_nanoseconds": 100_000,
            "counter_calibrations": 1,
            "counter_nanoseconds": 100_000,
            "max_counter_gap_nanoseconds": 100_000,
            "max_counter_calibration_span_nanoseconds": 100_000,
        }
    )
    assert _runner_wakeup_metrics_valid(nonmonotonic)
    assert _fidelity_runner_wakeup_metrics_valid(nonmonotonic)

    nonmonotonic_terminal_gap = json.loads(json.dumps(nonmonotonic))
    nonmonotonic_terminal_gap["buflo_exact_release_active_spin_interruptions"] = 2
    nonmonotonic_terminal_gap["buflo_exact_release_active_spin_interruption_nanoseconds"] = 200_000
    nonmonotonic_terminal_gap["buflo_exact_release_active_wait_counter_nanoseconds"] = 200_000
    nonmonotonic_terminal_gap["buflo_exact_release_last_failure"]["counter_nanoseconds"] = 200_000
    assert not _runner_wakeup_metrics_valid(nonmonotonic_terminal_gap)
    assert not _fidelity_runner_wakeup_metrics_valid(nonmonotonic_terminal_gap)


def test_runner_wakeup_schema_ten_enforces_rust_u64_domain() -> None:
    u64_max = 2**64 - 1
    accepted_aggregate_boundary = _runner_wakeup_receipt_v10(guard_entries=1)
    accepted_aggregate_boundary.update(
        {
            "wait_returns": u64_max,
            "socket_readiness_wakeups": u64_max,
            "timer_wakeups": 0,
            "controller_deadline_timer_wakeups": 0,
            "other_timer_wakeups": 0,
        }
    )
    assert _runner_wakeup_metrics_valid(accepted_aggregate_boundary)
    assert _fidelity_runner_wakeup_metrics_valid(accepted_aggregate_boundary)

    saturated_wake_totals = _runner_wakeup_receipt_v10(guard_entries=1)
    saturated_wake_totals.update(
        {
            "controller_deadline_timer_wakeups": u64_max,
            "other_timer_wakeups": 1,
            "timer_wakeups": u64_max,
            "socket_readiness_wakeups": 1,
            "wait_returns": u64_max,
        }
    )
    assert _runner_wakeup_metrics_valid(saturated_wake_totals)
    assert _fidelity_runner_wakeup_metrics_valid(saturated_wake_totals)

    for key in ("timer_wakeups", "wait_returns"):
        unsaturated_wake_total = json.loads(json.dumps(saturated_wake_totals))
        unsaturated_wake_total[key] = u64_max - 1
        assert not _runner_wakeup_metrics_valid(unsaturated_wake_total), key
        assert not _fidelity_runner_wakeup_metrics_valid(unsaturated_wake_total), key

    saturated_histograms = _runner_wakeup_receipt_v10(guard_entries=1)
    saturated_histograms.update(
        {
            "buflo_exact_release_guard_entries": u64_max,
            "buflo_exact_release_dispatch_ready_guards": u64_max,
            "buflo_exact_release_active_wait_poll_source": "instant-authoritative-fallback-v1",
            "buflo_exact_release_active_wait_counter_frequency_hz": None,
            "buflo_exact_release_active_wait_counter_guards": 0,
            "buflo_exact_release_active_wait_counter_unavailable_guards": u64_max,
            "buflo_exact_release_active_wait_counter_calibrations": 0,
            "buflo_exact_release_active_wait_instant_confirmations": 0,
            "buflo_exact_release_active_wait_counter_nanoseconds": 0,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": 0,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": 0,
            "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards": 0,
        }
    )
    for histogram_key in (
        "buflo_exact_release_dispatch_lateness_histogram",
        "buflo_exact_release_active_spin_gap_histogram",
    ):
        saturated_histograms[histogram_key]["counts"] = [u64_max, 0, 0, 0, 0, 0, 0, 0]
    for key in (
        "buflo_exact_release_active_wait_authoritative_watchdog_checks",
        "buflo_exact_release_active_wait_authoritative_watchdog_dispatches",
        "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards",
        "buflo_exact_release_max_authoritative_sample_gap_nanoseconds",
        "buflo_exact_release_max_authoritative_counter_lag_nanoseconds",
        "buflo_exact_release_max_counter_authoritative_lead_nanoseconds",
    ):
        if key != "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards":
            saturated_histograms[key] = 0
    saturated_histograms["buflo_exact_release_worst_guard"].update(
        {
            "active_wait_poll_source": "instant-authoritative-fallback-v1",
            "active_wait_counter_frequency_hz": None,
            "active_wait_counter_calibrations": 0,
            "active_wait_instant_confirmations": 0,
            "active_wait_counter_nanoseconds": None,
            "max_active_wait_counter_gap_nanoseconds": None,
            "max_counter_calibration_span_nanoseconds": None,
            "active_wait_authoritative_watchdog_checks": 0,
            "active_wait_authoritative_watchdog_dispatches": 0,
            "max_authoritative_sample_gap_nanoseconds": 0,
            "max_authoritative_counter_lag_nanoseconds": 0,
            "max_counter_authoritative_lead_nanoseconds": 0,
        }
    )
    assert _runner_wakeup_metrics_valid(saturated_histograms)
    assert _fidelity_runner_wakeup_metrics_valid(saturated_histograms)
    short_histogram = json.loads(json.dumps(saturated_histograms))
    short_histogram["buflo_exact_release_dispatch_lateness_histogram"]["counts"] = [
        u64_max - 1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
    assert not _runner_wakeup_metrics_valid(short_histogram)
    assert not _fidelity_runner_wakeup_metrics_valid(short_histogram)

    accepted_worst_boundary = _runner_wakeup_receipt_v10(guard_entries=1)
    accepted_worst_boundary["buflo_exact_release_worst_guard"]["endpoint"] = u64_max
    assert _runner_wakeup_metrics_valid(accepted_worst_boundary)
    assert _fidelity_runner_wakeup_metrics_valid(accepted_worst_boundary)

    accepted_failure_boundary = _runner_wakeup_v10_typed_failure("counter-unavailable")
    accepted_failure_boundary["buflo_exact_release_last_failure"]["endpoint"] = u64_max
    assert _runner_wakeup_metrics_valid(accepted_failure_boundary)
    assert _fidelity_runner_wakeup_metrics_valid(accepted_failure_boundary)

    near_limit_checks = (u64_max - 4) // 64 - 1
    accepted_checked_arithmetic_boundary = _runner_wakeup_receipt_v10(guard_entries=1)
    accepted_checked_arithmetic_boundary.update(
        {
            "buflo_exact_release_active_wait_iterations": 2 + 64 * near_limit_checks,
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": near_limit_checks,
        }
    )
    accepted_checked_arithmetic_boundary["buflo_exact_release_worst_guard"].update(
        {
            "active_wait_iterations": 2 + 64 * near_limit_checks,
            "active_wait_authoritative_watchdog_checks": near_limit_checks,
        }
    )
    assert _runner_wakeup_metrics_valid(accepted_checked_arithmetic_boundary)
    assert _fidelity_runner_wakeup_metrics_valid(accepted_checked_arithmetic_boundary)

    accepted_singleton_failure_boundary = _runner_wakeup_v10_typed_failure("counter-target-error")
    failure_relaxed_reads = u64_max - 4
    failure_checks = failure_relaxed_reads // 64
    accepted_singleton_failure_boundary.update(
        {
            "buflo_exact_release_active_wait_iterations": u64_max,
            "buflo_exact_release_active_wait_counter_calibrations": 2,
            "buflo_exact_release_active_wait_instant_confirmations": 1,
            "buflo_exact_release_active_wait_early_confirmation_retries": 1,
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": failure_checks,
        }
    )
    accepted_singleton_failure_boundary["buflo_exact_release_last_failure"].update(
        {
            "active_wait_iterations": u64_max,
            "counter_calibrations": 2,
            "instant_confirmations": 1,
            "early_confirmation_retries": 1,
            "authoritative_watchdog_checks": failure_checks,
        }
    )
    assert _runner_wakeup_metrics_valid(accepted_singleton_failure_boundary)
    assert _fidelity_runner_wakeup_metrics_valid(accepted_singleton_failure_boundary)

    saturated_failure_interruptions = json.loads(json.dumps(accepted_singleton_failure_boundary))
    saturated_failure_interruptions["buflo_exact_release_active_spin_interruptions"] = u64_max
    saturated_failure_interruptions["buflo_exact_release_active_spin_gap_histogram"]["counts"][
        0
    ] = u64_max
    assert not _runner_wakeup_metrics_valid(saturated_failure_interruptions)
    assert not _fidelity_runner_wakeup_metrics_valid(saturated_failure_interruptions)

    overflowing_checked_arithmetic = _runner_wakeup_receipt_v10(guard_entries=2)
    overflowing_checked_arithmetic.update(
        {
            "buflo_exact_release_active_wait_iterations": u64_max,
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": ((u64_max - 4) // 64),
        }
    )
    assert not _runner_wakeup_metrics_valid(overflowing_checked_arithmetic)
    assert not _fidelity_runner_wakeup_metrics_valid(overflowing_checked_arithmetic)

    overflow = u64_max + 1
    mutations: list[tuple[str, dict[str, object]]] = []
    for key in (
        "wait_returns",
        "buflo_exact_release_active_wait_authoritative_watchdog_checks",
    ):
        invalid = _runner_wakeup_receipt_v10(guard_entries=1)
        invalid[key] = overflow
        mutations.append((key, invalid))

    invalid_histogram = _runner_wakeup_receipt_v10(guard_entries=1)
    invalid_histogram["buflo_exact_release_dispatch_lateness_histogram"]["counts"][0] = overflow
    mutations.append(("histogram count", invalid_histogram))

    for key in (
        "endpoint",
        "release_at_defense_nanoseconds",
        "active_wait_counter_nanoseconds",
        "max_authoritative_sample_gap_nanoseconds",
    ):
        invalid = _runner_wakeup_receipt_v10(guard_entries=1)
        invalid["buflo_exact_release_worst_guard"][key] = overflow
        mutations.append((f"worst {key}", invalid))

    for key in (
        "endpoint",
        "exited_at_defense_nanoseconds",
        "counter_nanoseconds",
        "max_authoritative_sample_gap_nanoseconds",
    ):
        invalid = _runner_wakeup_v10_typed_failure("counter-unavailable")
        invalid["buflo_exact_release_last_failure"][key] = overflow
        mutations.append((f"failure {key}", invalid))

    for label, invalid in mutations:
        assert not _runner_wakeup_metrics_valid(invalid), label
        assert not _fidelity_runner_wakeup_metrics_valid(invalid), label


@pytest.mark.parametrize(
    "outcome",
    ("invalid-counter-frequency", "counter-unavailable", "counter-nonmonotonic"),
)
def test_runner_wakeup_schema_ten_retains_fresh_failure_exit_sample(outcome: str) -> None:
    receipt = _runner_wakeup_v10_typed_failure(outcome)
    receipt["buflo_exact_release_active_wait_nanoseconds"] = max(
        receipt["buflo_exact_release_active_wait_nanoseconds"], 1_000
    )
    receipt["buflo_exact_release_guard_wait_nanoseconds"] = receipt[
        "buflo_exact_release_active_wait_nanoseconds"
    ]
    receipt["buflo_exact_release_max_authoritative_sample_gap_nanoseconds"] = 1_000
    receipt["buflo_exact_release_last_failure"]["max_authoritative_sample_gap_nanoseconds"] = 1_000

    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)

    stale_aggregate = json.loads(json.dumps(receipt))
    stale_aggregate["buflo_exact_release_max_authoritative_sample_gap_nanoseconds"] = 999
    assert not _runner_wakeup_metrics_valid(stale_aggregate)
    assert not _fidelity_runner_wakeup_metrics_valid(stale_aggregate)


def test_runner_wakeup_schema_ten_aggregate_retries_require_relaxed_reads() -> None:
    empty_with_hidden_calibration = _runner_wakeup_receipt_v10(guard_entries=0)
    empty_with_hidden_calibration.update(
        {
            "buflo_exact_release_active_wait_iterations": 2,
            "buflo_exact_release_active_wait_counter_calibrations": 1,
        }
    )
    assert not _runner_wakeup_metrics_valid(empty_with_hidden_calibration)
    assert not _fidelity_runner_wakeup_metrics_valid(empty_with_hidden_calibration)

    receipt = _runner_wakeup_receipt_v10(guard_entries=2)
    receipt.update(
        {
            "buflo_exact_release_active_wait_iterations": 6,
            "buflo_exact_release_active_wait_counter_calibrations": 3,
            "buflo_exact_release_active_wait_instant_confirmations": 3,
            "buflo_exact_release_active_wait_early_confirmation_retries": 1,
        }
    )

    assert not _runner_wakeup_metrics_valid(receipt)
    assert not _fidelity_runner_wakeup_metrics_valid(receipt)

    missing_second_calibration = _runner_wakeup_receipt_v10(guard_entries=2)
    missing_second_calibration["buflo_exact_release_active_wait_iterations"] = 65
    missing_second_calibration["buflo_exact_release_worst_guard"]["active_wait_iterations"] = 65
    assert not _runner_wakeup_metrics_valid(missing_second_calibration)
    assert not _fidelity_runner_wakeup_metrics_valid(missing_second_calibration)

    impossible_watchdog_dispatch_partition = _runner_wakeup_receipt_v10(guard_entries=2)
    impossible_watchdog_dispatch_partition.update(
        {
            "buflo_exact_release_active_wait_iterations": 133,
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": 2,
            "buflo_exact_release_active_wait_authoritative_watchdog_dispatches": 2,
        }
    )
    impossible_watchdog_dispatch_partition["buflo_exact_release_worst_guard"].update(
        {
            "active_wait_iterations": 66,
            "active_wait_authoritative_watchdog_checks": 1,
            "active_wait_authoritative_watchdog_dispatches": 1,
        }
    )
    assert not _runner_wakeup_metrics_valid(impossible_watchdog_dispatch_partition)
    assert not _fidelity_runner_wakeup_metrics_valid(impossible_watchdog_dispatch_partition)

    for outcome in RUNNER_WAKEUP_V9_FAILURE_COUNTER_BY_OUTCOME:
        mixed_missing_success_reads = _runner_wakeup_v10_mixed_failure(outcome)
        failure_iterations = (
            mixed_missing_success_reads["buflo_exact_release_active_wait_iterations"]
            - mixed_missing_success_reads["buflo_exact_release_worst_guard"][
                "active_wait_iterations"
            ]
        )
        mixed_missing_success_reads["buflo_exact_release_guard_entries"] = 3
        mixed_missing_success_reads["buflo_exact_release_dispatch_ready_guards"] = 2
        for key in (
            "buflo_exact_release_active_wait_counter_guards",
            "buflo_exact_release_active_wait_counter_calibrations",
            "buflo_exact_release_active_wait_instant_confirmations",
            "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards",
        ):
            mixed_missing_success_reads[key] += 1
        for key in (
            "buflo_exact_release_dispatch_lateness_histogram",
            "buflo_exact_release_active_spin_gap_histogram",
        ):
            mixed_missing_success_reads[key]["counts"][0] += 1
        mixed_missing_success_reads["buflo_exact_release_active_wait_iterations"] = (
            65 + failure_iterations
        )
        mixed_missing_success_reads["buflo_exact_release_worst_guard"]["active_wait_iterations"] = (
            65
        )
        assert not _runner_wakeup_metrics_valid(mixed_missing_success_reads), outcome
        assert not _fidelity_runner_wakeup_metrics_valid(mixed_missing_success_reads), outcome


def test_runner_wakeup_schema_ten_retries_require_positive_counter_progress() -> None:
    receipt = _runner_wakeup_receipt_v10(guard_entries=1)
    receipt.update(
        {
            "buflo_exact_release_active_wait_iterations": 5,
            "buflo_exact_release_active_wait_counter_calibrations": 2,
            "buflo_exact_release_active_wait_instant_confirmations": 2,
            "buflo_exact_release_active_wait_early_confirmation_retries": 1,
        }
    )
    worst = receipt["buflo_exact_release_worst_guard"]
    worst.update(
        {
            "active_wait_iterations": 5,
            "active_wait_counter_calibrations": 2,
            "active_wait_instant_confirmations": 2,
            "active_wait_early_confirmation_retries": 1,
        }
    )
    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)

    forged = json.loads(json.dumps(receipt))
    forged.update(
        {
            "buflo_exact_release_active_wait_counter_nanoseconds": 0,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": 0,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": 0,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": 0,
        }
    )
    forged["buflo_exact_release_worst_guard"].update(
        {
            "active_wait_counter_nanoseconds": 0,
            "max_active_wait_counter_gap_nanoseconds": 0,
            "max_counter_calibration_span_nanoseconds": 0,
            "max_active_spin_gap_nanoseconds": 0,
        }
    )
    assert not _runner_wakeup_metrics_valid(forged)
    assert not _fidelity_runner_wakeup_metrics_valid(forged)


def test_runner_wakeup_schema_ten_bounds_unretained_entry_lateness() -> None:
    receipt = _runner_wakeup_receipt_v10(guard_entries=2)
    ceiling = 5_000_000 + receipt["buflo_exact_release_max_guard_exit_lateness_nanoseconds"]
    receipt["buflo_exact_release_max_guard_entry_lateness_nanoseconds"] = ceiling + 1
    receipt["buflo_exact_release_max_passive_wake_lateness_nanoseconds"] = ceiling + 1

    assert not _runner_wakeup_metrics_valid(receipt)
    assert not _fidelity_runner_wakeup_metrics_valid(receipt)

    retained_failure = _runner_wakeup_v10_mixed_failure("counter-unavailable")
    failure = retained_failure["buflo_exact_release_last_failure"]
    failure.update(
        {
            "entered_at_defense_nanoseconds": 21_000_000,
            "active_wait_started_at_defense_nanoseconds": 21_000_000,
            "exited_at_defense_nanoseconds": 21_001_000,
            "guard_entry_lateness_nanoseconds": 6_000_000,
            "exit_before_release_nanoseconds": 0,
        }
    )
    retained_failure["buflo_exact_release_max_guard_entry_lateness_nanoseconds"] = 6_000_000
    retained_failure["buflo_exact_release_max_passive_wake_lateness_nanoseconds"] = 6_000_000
    assert _runner_wakeup_metrics_valid(retained_failure)
    assert _fidelity_runner_wakeup_metrics_valid(retained_failure)

    retained_failure["buflo_exact_release_max_guard_entry_lateness_nanoseconds"] += 1
    retained_failure["buflo_exact_release_max_passive_wake_lateness_nanoseconds"] += 1
    assert not _runner_wakeup_metrics_valid(retained_failure)
    assert not _fidelity_runner_wakeup_metrics_valid(retained_failure)


def test_runner_wakeup_schema_ten_bounds_unretained_active_wait_and_maxima() -> None:
    receipt = _runner_wakeup_receipt_v10(guard_entries=2)
    maximum_success_active_wait = (
        5_000_000 + receipt["buflo_exact_release_max_guard_exit_lateness_nanoseconds"]
    )
    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)

    inflated_duration = json.loads(json.dumps(receipt))
    inflated_duration["buflo_exact_release_guard_wait_nanoseconds"] += 1
    inflated_duration["buflo_exact_release_active_wait_nanoseconds"] += 1

    hidden_entry_without_duration_reduction = json.loads(json.dumps(receipt))
    hidden_entry_without_duration_reduction.update(
        {
            "buflo_exact_release_max_guard_entry_lateness_nanoseconds": 1,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 1,
        }
    )

    impossible_deadline_count = json.loads(json.dumps(receipt))
    impossible_deadline_count["buflo_exact_release_dispatch_at_or_after_deadline_guards"] = 1

    mutations = [
        ("aggregate active duration", inflated_duration),
        ("hidden entry without duration reduction", hidden_entry_without_duration_reduction),
        ("outside count below minimum adapter window", impossible_deadline_count),
    ]
    for key in (
        "buflo_exact_release_max_authoritative_sample_gap_nanoseconds",
        "buflo_exact_release_max_authoritative_counter_lag_nanoseconds",
    ):
        impossible_maximum = json.loads(json.dumps(receipt))
        impossible_maximum[key] = maximum_success_active_wait + 1
        mutations.append((key, impossible_maximum))

    impossible_spin_maximum = json.loads(json.dumps(receipt))
    impossible_spin_maximum.update(
        {
            "buflo_exact_release_active_spin_interruptions": 1,
            "buflo_exact_release_active_spin_interruption_nanoseconds": (
                maximum_success_active_wait + 1
            ),
            "buflo_exact_release_max_active_spin_gap_nanoseconds": (
                maximum_success_active_wait + 1
            ),
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": (
                maximum_success_active_wait + 1
            ),
            "buflo_exact_release_active_spin_gap_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": [1, 0, 0, 0, 0, 0, 0, 1],
            },
        }
    )
    mutations.append(("active-derived spin maximum", impossible_spin_maximum))

    for label, invalid in mutations:
        assert not _runner_wakeup_metrics_valid(invalid), label
        assert not _fidelity_runner_wakeup_metrics_valid(invalid), label


def test_runner_wakeup_schema_nine_accepts_authoritative_early_confirmation_retry() -> None:
    receipt = _runner_wakeup_receipt_v9(guard_entries=1)
    receipt["buflo_exact_release_active_wait_counter_calibrations"] = 2
    receipt["buflo_exact_release_active_wait_instant_confirmations"] = 2
    receipt["buflo_exact_release_active_wait_early_confirmation_retries"] = 1
    receipt["buflo_exact_release_active_wait_iterations"] = 4
    worst = receipt["buflo_exact_release_worst_guard"]
    worst["active_wait_counter_calibrations"] = 2
    worst["active_wait_instant_confirmations"] = 2
    worst["active_wait_early_confirmation_retries"] = 1
    worst["active_wait_iterations"] = 4

    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)


def test_runner_wakeup_schema_nine_accepts_portable_instant_fallback() -> None:
    receipt = _runner_wakeup_receipt_v9(guard_entries=1)
    receipt.update(
        {
            "buflo_exact_release_active_wait_poll_source": ("instant-authoritative-fallback-v1"),
            "buflo_exact_release_active_wait_counter_frequency_hz": None,
            "buflo_exact_release_active_wait_counter_guards": 0,
            "buflo_exact_release_active_wait_counter_unavailable_guards": 1,
            "buflo_exact_release_active_wait_counter_calibrations": 0,
            "buflo_exact_release_active_wait_instant_confirmations": 0,
            "buflo_exact_release_active_wait_counter_nanoseconds": 0,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": 0,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": 0,
        }
    )
    worst = receipt["buflo_exact_release_worst_guard"]
    worst.update(
        {
            "active_wait_poll_source": "instant-authoritative-fallback-v1",
            "active_wait_counter_frequency_hz": None,
            "active_wait_counter_calibrations": 0,
            "active_wait_instant_confirmations": 0,
            "active_wait_counter_nanoseconds": None,
            "max_active_wait_counter_gap_nanoseconds": None,
            "max_counter_calibration_span_nanoseconds": None,
        }
    )

    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)


@pytest.mark.parametrize(
    "outcome",
    (
        "invalid-counter-frequency",
        "counter-unavailable",
        "counter-nonmonotonic",
        "counter-frequency-changed",
        "counter-target-error",
    ),
)
def test_runner_wakeup_schema_nine_preserves_typed_failure_evidence(outcome: str) -> None:
    receipt = _runner_wakeup_v9_typed_failure(outcome)

    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)


@pytest.mark.parametrize("outcome", ("counter-unavailable", "counter-nonmonotonic"))
def test_runner_wakeup_schema_nine_preserves_typed_failure_across_frequency_mismatch(
    outcome: str,
) -> None:
    receipt = _runner_wakeup_v9_typed_failure(outcome)
    receipt["buflo_exact_release_last_failure"]["counter_frequency_hz"] = 500_000_000

    assert (
        receipt["buflo_exact_release_active_wait_counter_frequency_hz"]
        != receipt["buflo_exact_release_last_failure"]["counter_frequency_hz"]
    )
    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)


def test_runner_wakeup_schema_nine_accepts_nullable_failure_chronology() -> None:
    receipt = _runner_wakeup_v9_typed_failure("counter-target-error", nullable_chronology=True)

    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)
    assert not _runner_wakeup_v9_relative_chronology_available(receipt)


def test_runner_wakeup_schema_nine_rejects_unreachable_success_aggregates() -> None:
    mutations = (
        ("buflo_exact_release_passive_sleep_calls", 1),
        ("buflo_exact_release_guard_wait_nanoseconds", 5_000_008),
        ("buflo_exact_release_max_passive_wake_lateness_nanoseconds", 1),
        ("buflo_exact_release_active_wait_counter_unavailable_guards", 1),
        ("buflo_exact_release_active_wait_counter_nonmonotonic_guards", 1),
        ("buflo_exact_release_max_active_spin_gap_nanoseconds", 2),
        ("buflo_exact_release_max_counter_calibration_span_nanoseconds", 2),
        ("buflo_exact_release_active_wait_iterations", 1),
    )
    for key, replacement in mutations:
        receipt = _runner_wakeup_receipt_v9(guard_entries=1)
        receipt[key] = replacement
        assert not _runner_wakeup_metrics_valid(receipt), key
        assert not _fidelity_runner_wakeup_metrics_valid(receipt), key

    frequency_mismatch = _runner_wakeup_receipt_v9(guard_entries=1)
    frequency_mismatch["buflo_exact_release_worst_guard"]["active_wait_counter_frequency_hz"] = (
        500_000_000
    )
    assert not _runner_wakeup_metrics_valid(frequency_mismatch)
    assert not _fidelity_runner_wakeup_metrics_valid(frequency_mismatch)


def test_runner_wakeup_schema_nine_rejects_mutated_typed_failure_receipts() -> None:
    mutations = []

    dispatch = _runner_wakeup_v9_typed_failure("counter-unavailable")
    dispatch["buflo_exact_release_last_failure"]["dispatch_at_defense_nanoseconds"] = 1
    mutations.append(("failure dispatch", dispatch))

    partial_time = _runner_wakeup_v9_typed_failure("counter-unavailable")
    partial_time["buflo_exact_release_last_failure"]["entered_at_defense_nanoseconds"] = None
    mutations.append(("partial chronology", partial_time))

    partial_counter = _runner_wakeup_v9_typed_failure("counter-unavailable")
    partial_counter["buflo_exact_release_last_failure"]["counter_nanoseconds"] = None
    mutations.append(("partial counter tuple", partial_counter))

    unavailable_reads = _runner_wakeup_v9_typed_failure("counter-unavailable")
    unavailable_reads["buflo_exact_release_active_wait_iterations"] = 2
    mutations.append(("unavailable counter read", unavailable_reads))

    nonmonotonic_reads = _runner_wakeup_v9_typed_failure("counter-nonmonotonic")
    nonmonotonic_reads["buflo_exact_release_active_wait_iterations"] = 1
    mutations.append(("non-monotonic counter read", nonmonotonic_reads))

    invalid_reads = _runner_wakeup_v9_typed_failure("invalid-counter-frequency")
    invalid_reads["buflo_exact_release_active_wait_iterations"] = 1
    mutations.append(("invalid-frequency counter read", invalid_reads))

    changed_early = _runner_wakeup_v9_typed_failure("counter-frequency-changed")
    failure = changed_early["buflo_exact_release_last_failure"]
    failure["exited_at_defense_nanoseconds"] = failure["release_at_defense_nanoseconds"] - 1
    failure["exit_before_release_nanoseconds"] = 1
    mutations.append(("frequency change before release", changed_early))

    nullable_changed_early = _runner_wakeup_v9_typed_failure(
        "counter-frequency-changed", nullable_chronology=True
    )
    nullable_changed_early["buflo_exact_release_last_failure"][
        "exit_before_release_nanoseconds"
    ] = 1
    mutations.append(("nullable frequency change before release", nullable_changed_early))

    changed_without_success = _runner_wakeup_v9_typed_failure("counter-frequency-changed")
    changed_without_success["buflo_exact_release_dispatch_ready_guards"] = 0
    mutations.append(("frequency change without prior success", changed_without_success))

    changed_same_frequency = _runner_wakeup_v9_typed_failure("counter-frequency-changed")
    changed_same_frequency["buflo_exact_release_last_failure"]["counter_frequency_hz"] = (
        changed_same_frequency["buflo_exact_release_active_wait_counter_frequency_hz"]
    )
    mutations.append(("frequency change with unchanged frequency", changed_same_frequency))

    bad_target = _runner_wakeup_v9_typed_failure("counter-target-error")
    bad_target["buflo_exact_release_active_wait_counter_calibrations"] = 0
    bad_target["buflo_exact_release_active_wait_counter_nanoseconds"] = 0
    bad_target["buflo_exact_release_max_active_spin_gap_nanoseconds"] = 0
    bad_target["buflo_exact_release_max_active_wait_counter_gap_nanoseconds"] = 0
    bad_target["buflo_exact_release_max_counter_calibration_span_nanoseconds"] = 0
    target_failure = bad_target["buflo_exact_release_last_failure"]
    target_failure["counter_calibrations"] = 0
    target_failure["counter_nanoseconds"] = 0
    target_failure["max_counter_gap_nanoseconds"] = 0
    target_failure["max_counter_calibration_span_nanoseconds"] = 0
    mutations.append(("target error without calibration", bad_target))

    bad_nonmonotonic = _runner_wakeup_v9_typed_failure("counter-nonmonotonic")
    bad_nonmonotonic["buflo_exact_release_active_wait_counter_nanoseconds"] = 1
    bad_nonmonotonic["buflo_exact_release_max_active_spin_gap_nanoseconds"] = 1
    bad_nonmonotonic["buflo_exact_release_max_active_wait_counter_gap_nanoseconds"] = 1
    nonmonotonic_failure = bad_nonmonotonic["buflo_exact_release_last_failure"]
    nonmonotonic_failure["counter_nanoseconds"] = 1
    nonmonotonic_failure["max_counter_gap_nanoseconds"] = 1
    mutations.append(("zero-calibration counter delta", bad_nonmonotonic))

    for label, receipt in mutations:
        assert not _runner_wakeup_metrics_valid(receipt), label
        assert not _fidelity_runner_wakeup_metrics_valid(receipt), label


@pytest.mark.parametrize("frequency_hz", (1_000_000, 2**32 - 1))
def test_runner_wakeup_schema_nine_accepts_counter_frequency_boundaries(
    frequency_hz: int,
) -> None:
    receipt = _runner_wakeup_receipt_v9(guard_entries=1)
    receipt["buflo_exact_release_active_wait_counter_frequency_hz"] = frequency_hz
    receipt["buflo_exact_release_worst_guard"]["active_wait_counter_frequency_hz"] = frequency_hz

    assert _runner_wakeup_metrics_valid(receipt)
    assert _fidelity_runner_wakeup_metrics_valid(receipt)


@pytest.mark.parametrize("frequency_hz", (999_999, 2**32))
def test_runner_wakeup_schema_nine_rejects_counter_frequency_outside_rust_bounds(
    frequency_hz: int,
) -> None:
    receipt = _runner_wakeup_receipt_v9(guard_entries=1)
    receipt["buflo_exact_release_active_wait_counter_frequency_hz"] = frequency_hz
    receipt["buflo_exact_release_worst_guard"]["active_wait_counter_frequency_hz"] = frequency_hz

    assert not _runner_wakeup_metrics_valid(receipt)
    assert not _fidelity_runner_wakeup_metrics_valid(receipt)


@pytest.mark.parametrize(
    "missing",
    (
        "active_wait_counter_frequency_hz",
        "active_wait_counter_nanoseconds",
        "max_active_wait_counter_gap_nanoseconds",
        "max_counter_calibration_span_nanoseconds",
    ),
)
def test_runner_wakeup_schema_nine_rejects_partial_worst_counter_tuple(missing: str) -> None:
    receipt = _runner_wakeup_receipt_v9(guard_entries=1)
    receipt["buflo_exact_release_worst_guard"][missing] = None

    assert not _runner_wakeup_metrics_valid(receipt)
    assert not _fidelity_runner_wakeup_metrics_valid(receipt)


def test_runner_wakeup_schema_six_has_exact_semantics_and_v5_metric_keys() -> None:
    historical_v5 = _runner_wakeup_receipt_v5()
    current_v6 = _runner_wakeup_receipt_v6()

    assert set(current_v6) == set(historical_v5)
    assert current_v6["semantics"] == (
        "actual_select_return_source; socket_wins_simultaneous_readiness; "
        "controller_subset_is_effective_earliest_deadline; scheduled_cells_are_not_wakeups; "
        "buflo_ordinary_output_admission_lead_us=10000; "
        "buflo_exact_release_guard_reserves_candidate_window; "
        "buflo_exact_release_guard_lead_us=10000; "
        "buflo_exact_release_active_wait_tail_us=10000; "
        "buflo_exact_release_guard_coincides_with_output_admission=true; "
        "buflo_exact_release_guards_are_separately_receipted_active_waits; "
        "buflo_active_defense_socket_drains_are_single_batch; "
        "buflo_active_defense_http_drains_are_single_event; "
        "buflo_ordinary_output_stops_at_admission; "
        "buflo_exact_release_guard_begins_at_guard; "
        "cs_exact_incoming_retry_phases=1/4,1/2,3/4; "
        "buflo_exact_incoming_retry_wakeups=transport_callback_or_1/4,1/2,3/4,deadline; "
        "buflo_exact_incoming_retry_drives="
        "count_owner_endpoint_output_drive_invocations_including_immediate_and_error; "
        "buflo_exact_incoming_retry_resolutions="
        "count_drive_invocations_clearing_at_least_one_captured_identity; "
        "buflo_exact_incoming_retry_max_wake_lateness_includes_terminal_deadline=true; "
        "buflo_exact_incoming_inventory="
        "all_unrealized_slot_owned_adapter_identities_with_same_tick_refresh; "
        "buflo_exact_incoming_expiry=one_logical_slot_one_deadline_miss"
    )
    assert _runner_wakeup_metrics_valid(historical_v5)
    assert _fidelity_runner_wakeup_metrics_valid(historical_v5)
    assert _runner_wakeup_metrics_valid(current_v6)
    assert _fidelity_runner_wakeup_metrics_valid(current_v6)

    wrong_semantics = {**current_v6, "semantics": historical_v5["semantics"]}
    assert not _runner_wakeup_metrics_valid(wrong_semantics)
    assert not _fidelity_runner_wakeup_metrics_valid(wrong_semantics)
    assert not _runner_wakeup_metrics_valid({**current_v6, "unexpected": 0})
    assert not _fidelity_runner_wakeup_metrics_valid({**current_v6, "unexpected": 0})


def test_runner_wakeup_schema_seven_binds_exact_release_timing_evidence() -> None:
    historical_v6 = _runner_wakeup_receipt_v6()
    current_v7 = _runner_wakeup_receipt_v7(guard_entries=2)

    assert _runner_wakeup_metrics_valid(historical_v6)
    assert _fidelity_runner_wakeup_metrics_valid(historical_v6)
    assert _runner_wakeup_metrics_valid(current_v7)
    assert _fidelity_runner_wakeup_metrics_valid(current_v7)
    assert current_v7["semantics"].endswith(
        "buflo_exact_release_10000us_lead_fields_are_configured_maxima=true"
    )
    assert (
        sum(current_v7["buflo_exact_release_dispatch_lateness_histogram"]["counts"])
        == current_v7["buflo_exact_release_guard_entries"]
    )

    at_deadline = _runner_wakeup_receipt_v7(
        guard_entries=1, dispatch_lateness_nanoseconds=5_000_000
    )
    assert _runner_wakeup_metrics_valid(at_deadline)
    assert _fidelity_runner_wakeup_metrics_valid(at_deadline)
    assert at_deadline["buflo_exact_release_dispatch_at_or_after_deadline_guards"] == 1
    assert at_deadline["buflo_exact_release_worst_guard"]["dispatch_at_or_after_deadline"] is True

    late_inside_window = _runner_wakeup_receipt_v7(
        guard_entries=1, dispatch_lateness_nanoseconds=2_000_000
    )
    late_inside_window.update(
        {
            "buflo_exact_release_guard_wait_nanoseconds": 0,
            "buflo_exact_release_active_wait_nanoseconds": 0,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 12_000_000,
            "buflo_exact_release_max_guard_entry_lateness_nanoseconds": 12_000_000,
            "buflo_exact_release_active_wait_monotonic_raw_nanoseconds": 0,
            "buflo_exact_release_active_wait_thread_cpu_nanoseconds": 0,
        }
    )
    late_worst = late_inside_window["buflo_exact_release_worst_guard"]
    late_worst.update(
        {
            "entered_at_defense_nanoseconds": 22_000_000,
            "active_wait_started_at_defense_nanoseconds": 22_000_000,
            "dispatch_at_defense_nanoseconds": 22_000_000,
            "guard_entry_lateness_nanoseconds": 12_000_000,
            "active_wait_monotonic_nanoseconds": 0,
            "active_wait_monotonic_raw_nanoseconds": 0,
            "active_wait_thread_cpu_nanoseconds": 0,
        }
    )
    assert _runner_wakeup_metrics_valid(late_inside_window)
    assert _fidelity_runner_wakeup_metrics_valid(late_inside_window)

    raw_clock_divergence = _runner_wakeup_receipt_v7(guard_entries=1)
    active_wait = raw_clock_divergence["buflo_exact_release_active_wait_nanoseconds"]
    raw_elapsed = active_wait - 1_000_000
    raw_clock_divergence.update(
        {
            "buflo_exact_release_active_wait_monotonic_raw_nanoseconds": raw_elapsed,
            "buflo_exact_release_active_wait_thread_cpu_nanoseconds": 0,
            "buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds": active_wait,
            "buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds": active_wait,
            "buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds": 1_000_000,
        }
    )
    divergent_worst = raw_clock_divergence["buflo_exact_release_worst_guard"]
    divergent_worst.update(
        {
            "active_wait_monotonic_raw_nanoseconds": raw_elapsed,
            "active_wait_thread_cpu_nanoseconds": 0,
            "active_wait_estimated_off_cpu_nanoseconds": active_wait,
            "active_wait_monotonic_raw_divergence_nanoseconds": 1_000_000,
        }
    )
    assert _runner_wakeup_metrics_valid(raw_clock_divergence)
    assert _fidelity_runner_wakeup_metrics_valid(raw_clock_divergence)

    invalid_histogram = json.loads(json.dumps(current_v7))
    invalid_histogram["buflo_exact_release_dispatch_lateness_histogram"]["counts"][0] -= 1
    assert not _runner_wakeup_metrics_valid(invalid_histogram)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_histogram)

    invalid_spin = json.loads(json.dumps(current_v7))
    invalid_spin["buflo_exact_release_max_active_spin_gap_nanoseconds"] = 50_001
    assert not _runner_wakeup_metrics_valid(invalid_spin)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_spin)


def test_runner_wakeup_schema_seven_accepts_fractional_adapter_window() -> None:
    fractional = _runner_wakeup_receipt_v7(
        guard_entries=1,
        dispatch_lateness_nanoseconds=4_999_000,
        release_skew_nanoseconds=456,
    )
    worst = fractional["buflo_exact_release_worst_guard"]

    assert worst["guard_at_defense_nanoseconds"] == 10_002_456
    assert worst["release_at_defense_nanoseconds"] == 20_000_456
    assert worst["deadline_at_defense_nanoseconds"] == 24_999_456
    assert worst["dispatch_at_or_after_deadline"] is True
    assert worst["dispatch_after_deadline_nanoseconds"] == 0
    assert _runner_wakeup_metrics_valid(fractional)
    assert _fidelity_runner_wakeup_metrics_valid(fractional)

    malformed_ceil_floor = json.loads(json.dumps(fractional))
    malformed_ceil_floor["buflo_exact_release_worst_guard"]["deadline_at_defense_nanoseconds"] += 1
    assert not _runner_wakeup_metrics_valid(malformed_ceil_floor)
    assert not _fidelity_runner_wakeup_metrics_valid(malformed_ceil_floor)


def test_runner_wakeup_schema_seven_accepts_mixed_window_deadline_count() -> None:
    mixed = _runner_wakeup_receipt_v7(guard_entries=2, dispatch_lateness_nanoseconds=4_999_800)
    mixed["buflo_exact_release_dispatch_at_or_after_deadline_guards"] = 1

    assert mixed["buflo_exact_release_worst_guard"]["dispatch_at_or_after_deadline"] is False
    assert _runner_wakeup_metrics_valid(mixed)
    assert _fidelity_runner_wakeup_metrics_valid(mixed)

    impossible_all_outside = json.loads(json.dumps(mixed))
    impossible_all_outside["buflo_exact_release_dispatch_at_or_after_deadline_guards"] = 2
    assert not _runner_wakeup_metrics_valid(impossible_all_outside)
    assert not _fidelity_runner_wakeup_metrics_valid(impossible_all_outside)

    impossible_zero_outside = _runner_wakeup_receipt_v7(
        guard_entries=1,
        dispatch_lateness_nanoseconds=4_999_000,
        release_skew_nanoseconds=456,
    )
    impossible_zero_outside["buflo_exact_release_dispatch_at_or_after_deadline_guards"] = 0
    assert not _runner_wakeup_metrics_valid(impossible_zero_outside)
    assert not _fidelity_runner_wakeup_metrics_valid(impossible_zero_outside)


def test_runner_wakeup_schema_seven_binds_aux_pairs_and_spin_histogram() -> None:
    partial_aux = _runner_wakeup_receipt_v7(guard_entries=1)
    partial_aux.update(
        {
            "buflo_exact_release_active_wait_aux_clock_guards": 0,
            "buflo_exact_release_active_wait_aux_clock_unavailable_guards": 1,
            "buflo_exact_release_active_wait_thread_cpu_nanoseconds": 0,
        }
    )
    partial_worst = partial_aux["buflo_exact_release_worst_guard"]
    partial_worst["active_wait_thread_cpu_nanoseconds"] = None
    partial_worst["active_wait_estimated_off_cpu_nanoseconds"] = None
    assert _runner_wakeup_metrics_valid(partial_aux)
    assert _fidelity_runner_wakeup_metrics_valid(partial_aux)

    invalid_aux_formula = json.loads(json.dumps(partial_aux))
    invalid_aux_formula["buflo_exact_release_worst_guard"][
        "active_wait_monotonic_raw_divergence_nanoseconds"
    ] = 1
    invalid_aux_formula[
        "buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds"
    ] = 1
    assert not _runner_wakeup_metrics_valid(invalid_aux_formula)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_aux_formula)

    interrupted = _runner_wakeup_receipt_v7(guard_entries=1)
    interrupted.update(
        {
            "buflo_exact_release_active_spin_interruptions": 1,
            "buflo_exact_release_active_spin_interruption_nanoseconds": 60_000,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": 60_000,
            "buflo_exact_release_active_spin_gap_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": [0, 1, 0, 0, 0, 0, 0, 0],
            },
        }
    )
    interrupted_worst = interrupted["buflo_exact_release_worst_guard"]
    interrupted_worst.update(
        {
            "active_spin_interruptions": 1,
            "active_spin_interruption_nanoseconds": 60_000,
            "max_active_spin_gap_nanoseconds": 60_000,
        }
    )
    assert _runner_wakeup_metrics_valid(interrupted)
    assert _fidelity_runner_wakeup_metrics_valid(interrupted)

    missing_spin_bucket = json.loads(json.dumps(interrupted))
    missing_spin_bucket["buflo_exact_release_active_spin_gap_histogram"]["counts"] = [
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
    assert not _runner_wakeup_metrics_valid(missing_spin_bucket)
    assert not _fidelity_runner_wakeup_metrics_valid(missing_spin_bucket)

    threshold_is_strict = json.loads(json.dumps(interrupted))
    threshold_is_strict["buflo_exact_release_max_active_spin_gap_nanoseconds"] = 50_000
    threshold_is_strict["buflo_exact_release_active_spin_interruption_nanoseconds"] = 50_000
    threshold_is_strict["buflo_exact_release_active_spin_gap_histogram"]["counts"] = [
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
    threshold_worst = threshold_is_strict["buflo_exact_release_worst_guard"]
    threshold_worst["active_spin_interruption_nanoseconds"] = 50_000
    threshold_worst["max_active_spin_gap_nanoseconds"] = 50_000
    assert not _runner_wakeup_metrics_valid(threshold_is_strict)
    assert not _fidelity_runner_wakeup_metrics_valid(threshold_is_strict)


def test_registry_appends_two_candidate_scientific_identities() -> None:
    assert DEFENSE_ORDER[-2:] == ("buflo", "cs-buflo")
    assert DEFENSE_RUNTIME_KINDS["buflo"] == "buflo"
    assert DEFENSE_RUNTIME_KINDS["cs-buflo"] == "cs_buflo"
    assert DEFENSE_ADAPTATIONS["buflo"].implementation_status == "candidate"
    assert DEFENSE_ADAPTATIONS["cs-buflo"].implementation_status == "candidate"
    assert DEFENSE_VARIANT_LABELS == {
        "cs-buflo-ctsp": "CS-BuFLO (CTSP)",
        "cs-buflo-cpsp": "CS-BuFLO (CPSP)",
    }


def test_study_plan_binds_existing_parameter_paths_and_exact_counts() -> None:
    plan = load_study_plan()
    treatments = {item["name"]: item for item in plan["treatments"]}

    for name, (_kind, expected) in PARAMETER_FILES.items():
        if name in treatments:
            assert (STUDY_PLAN.parent / treatments[name]["parameters"]).resolve() == expected
            assert expected.is_file()
    assert plan["controlled"]["expected_samples"] == 160
    assert plan["implementation_baselines"] == {
        "lab_commit": "8988a48a8e43cc9d47505cae12ee7758bc7fa5ee",
        "neqo_commit": "6aceaac85243d6e0e34354108e010705d3c83088",
    }
    assert plan["established_seven_baseline_oracle"] == {
        "path": "config/buflo-study/v1/established-seven-baseline.json",
        "sha256": buflo_study.ESTABLISHED_SEVEN_BASELINE_SHA256,
    }
    assert plan["historical_corpus_guard"]["historical_exporter"] == {
        "path": "tools/classifier_handoff.py",
        "sha256": "f91964df8b6af3b1d89a8c2ff2de1997a59e9ffe36124fa8e20c694515152a72",
    }
    assert plan["regression"]["expected_samples"] == 18
    assert plan["public_stages"]["smoke"]["expected_samples"] == 20
    assert plan["public_stages"]["rehearsal"]["expected_samples"] == 40
    assert plan["public_stages"]["formal"]["expected_samples"] == 1_500
    assert plan["public_stages"]["formal"]["bootstrap_draws"] == 10_000
    assert (
        plan["public_stages"]["formal"]["bootstrap_contract"]
        == buflo_study.FORMAL_BOOTSTRAP_CONTRACT
    )
    assert plan["public_stages"]["formal"]["treatments"] == [
        "undefended",
        "buflo",
        "cs-buflo",
    ]
    assert "cs-buflo-cpsp" not in plan["public_stages"]["formal"]["treatments"]
    assert plan["capture_admission"] == {
        "staged_prerequisites": {
            "smoke": ["regression"],
            "rehearsal": ["regression", "smoke"],
            "formal": ["regression", "smoke", "rehearsal"],
        },
        "reference_gate": "isolated-create-only-conformance-receipt",
        "formal_code_gate": "validated-create-only-code-gate-receipt",
        "source_lineage": "one-exact-clean-collection-image",
        "formal_minimum_available_hours": 12.5,
        "formal_disk_safety_multiplier": 3,
        "formal_disk_projection_basis": ("verified-smoke-plus-rehearsal-bytes-per-sample"),
    }
    assert buflo_study.formal_evaluation_contract_for_cohort(14) is None
    assert (
        buflo_study.formal_evaluation_contract_for_cohort(15)
        == buflo_study.FORMAL_BOOTSTRAP_CONTRACT
    )
    tampered = json.loads(json.dumps(plan))
    tampered["public_stages"]["formal"]["bootstrap_draws"] = 9_999
    with pytest.raises(ValueError, match="formal stage matrix"):
        buflo_study.validate_study_plan(tampered)


def test_established_seven_baseline_rechecks_config_and_behavior_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = validate_established_seven_baseline()
    assert evidence["defenses"] == list(DEFENSE_ORDER[:7])
    assert evidence["passed"] is True

    monkeypatch.setitem(DEFENSE_RUNTIME_KINDS, "front", "tamaraw")
    with pytest.raises(ValueError, match="identities changed"):
        validate_established_seven_baseline()


def test_cs_buflo_provenance_explicitly_receipts_source_live_estimator_divergence() -> None:
    expected = {
        "source_semantics": (
            "author-oracle-advances-16KiB-boundaries-on-actually-transmitted-"
            "real-plus-junk-bytes-per-endpoint-and-direction"
        ),
        "live_semantics": (
            "qcsd-live-advances-16KiB-boundaries-on-exact-fresh-application-"
            "stream-bytes-outgoing-excludes-retransmission-and-defense-added-"
            "bytes-and-uses-consumed-application-offsets-incoming"
        ),
        "rate_boundary_translation_version": 2,
        "rate_boundary_counter_semantics": (
            "client_only_quic_fresh_application_stream_bytes_outgoing_"
            "retransmission_excluded_and_consumed_application_offsets_incoming"
        ),
        "author_rate_boundary_counter_semantics": (
            "per_direction_actually_transmitted_real_plus_junk_bytes"
        ),
        "translation_classification": "expected-client-only-qcsd-adaptation-difference",
        "early_termination_semantics": (
            "client_only_outgoing_observed_udp_and_incoming_consumed_credit_power_of_two_crossing"
        ),
        "expected_difference": (
            "adaptation-boundary-crossings-and-rate-transition-times-may-differ-"
            "from-the-author-artifact"
        ),
    }
    for treatment in ("cs-buflo-ctsp", "cs-buflo-cpsp"):
        parameter = PARAMETER_FILES[treatment][1]
        provenance = json.loads(
            parameter.with_name(parameter.name + ".provenance.json").read_text(encoding="utf-8")
        )
        assert {key: provenance[key] for key in expected} == expected


def test_buflo_provenance_binds_exact_terminal_summary_contract() -> None:
    parameter = PARAMETER_FILES["buflo"][1]
    provenance = json.loads(
        parameter.with_name(parameter.name + ".provenance.json").read_text(encoding="utf-8")
    )
    assert provenance["terminal_subcell_policy"] == (
        "drain_whole_cells_then_client_local_http3_cancel_unallocatable_reviewed_chaff_tail"
    )
    assert provenance["terminal_subcell_observer_effect"] == (
        "typed_stop_sending_and_reset_stream_defense_control_may_follow_the_last_exact_cell"
    )
    assert provenance["terminal_subcell_policy"] == BUFLO_TERMINAL_SUBCELL_POLICY
    assert provenance["terminal_subcell_observer_effect"] == BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT
    assert provenance["terminal_translation_version"] == 2
    assert provenance["terminal_parser_safety"] == (
        "latch-requires-zero-live-parser-lease-bytes-and-zero-pending-"
        "application-parser-boundaries;pending-reviewed-chaff-parser-"
        "boundaries-are-counted-and-cancelled-with-their-streams"
    )


def _formal_performance_evaluation_fixture() -> dict[str, object]:
    modes = ("undefended", "buflo", "cs-buflo")
    defended = ("buflo", "cs-buflo")
    workloads = buflo_study.WORKLOADS
    directional = [
        {
            "defense": mode,
            "workload_id": workload,
            "acquisition_block_index": block,
            "direction": direction,
            "samples": 10,
        }
        for mode in modes
        for workload in workloads
        for block in range(10)
        for direction in ("outgoing", "incoming")
    ]
    client = [
        {
            "defense": mode,
            "workload_id": workload,
            "acquisition_block_index": block,
            "samples": 10,
        }
        for mode in modes
        for workload in workloads
        for block in range(10)
    ]
    paired_directional = [
        {
            "defense": mode,
            "workload_id": workload,
            "acquisition_block_index": block,
            "direction": direction,
            "pairs": 10,
        }
        for mode in defended
        for workload in workloads
        for block in range(10)
        for direction in ("outgoing", "incoming")
    ]
    paired_client = [
        {
            "defense": mode,
            "workload_id": workload,
            "acquisition_block_index": block,
            "pairs": 10,
        }
        for mode in defended
        for workload in workloads
        for block in range(10)
    ]
    required_costs = (
        "user_cpu_seconds",
        "system_cpu_seconds",
        "wall_time_seconds",
        "maximum_rss_bytes",
        "voluntary_context_switches",
        "involuntary_context_switches",
        "timer_wakeups",
        "transport_retransmissions",
    )
    mode_client = [
        {
            "defense": mode,
            "pairs": 500,
            "paired_client_costs": {metric: {"available": True} for metric in required_costs},
            "completion_ratio_block_workload_bootstrap_95": {},
            "added_seconds_block_workload_bootstrap_95": {},
            "goodput_ratio_block_workload_bootstrap_95": {},
        }
        for mode in defended
    ]
    algorithm_strata = [
        {
            "defense": mode,
            "workload_id": workload,
            "acquisition_block_index": block,
            "direction": direction,
            "samples": 10,
        }
        for mode in modes
        for workload in workloads
        for block in range(10)
        for direction in ("outgoing", "incoming")
    ]
    tail = [
        {
            "defense": "buflo",
            "workload_id": workload,
            "acquisition_block_index": block,
            "samples": 10,
            "samples_with_cancellation": 0,
            "terminal_subcell_policy": [BUFLO_TERMINAL_SUBCELL_POLICY],
            "terminal_subcell_observer_effect": [BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT],
            "control_evidence_semantics": [BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS],
            "stream_cancellations": 0,
            "receipt_cancellations": 0,
            "typed_cancellation_action_events": 0,
            "pending_request_cancellations": 0,
            "open_streams_at_latch": 0,
            "parser_lease_bytes_at_latch": 0,
            "pending_parser_boundaries_at_latch": 0,
            "pending_application_parser_boundaries_at_latch": 0,
            "exact_capacity_bytes_cancelled": {
                "total": 0,
                "minimum": 0,
                "maximum": 0,
                "p50": 0.0,
                "p90": 0.0,
                "p95": 0.0,
            },
            "terminal_latched_at_us": {
                "p50": 10_000_001.0,
                "p90": 10_000_002.0,
                "p95": 10_000_003.0,
            },
            "post_cancellation_unscheduled_defense_control_packets": 0,
            "post_cancellation_unscheduled_defense_control_bytes": 0,
        }
        for workload in workloads
        for block in range(10)
    ]
    schedule_stop = [
        {
            "defense": "buflo",
            "workload_id": workload,
            "acquisition_block_index": block,
            "samples": 10,
            "policy": [BUFLO_SCHEDULE_STOP_POLICY],
            "terminal_time_semantics": [BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS],
            "latched_samples": 10,
            "latched_at_us": {
                "minimum": 10_000_000,
                "maximum": 10_000_003,
                "p50": 10_000_001.0,
                "p90": 10_000_002.0,
                "p95": 10_000_003.0,
            },
            "available_bytes": {
                "total": 0,
                "minimum": 0,
                "maximum": 0,
                "p50": 0.0,
                "p90": 0.0,
                "p95": 0.0,
            },
            "required_bytes": [1_200],
            "samples_with_incoming_drain": 10,
            "directions": {
                "outgoing": {
                    "scheduled_cells_at_stop": 50,
                    "terminal_cells_at_stop": 50,
                    "drained_cells_after_stop": 0,
                    "last_scheduled_target_us": {
                        "minimum": 10_000_000,
                        "maximum": 10_000_000,
                        "p50": 10_000_000.0,
                        "p90": 10_000_000.0,
                        "p95": 10_000_000.0,
                    },
                    "last_terminal_at_us": {
                        "minimum": 9_999_990,
                        "maximum": 9_999_999,
                        "p50": 9_999_995.0,
                        "p90": 9_999_998.0,
                        "p95": 9_999_999.0,
                    },
                    "terminal_cells_strictly_before_stop": 50,
                    "terminal_cells_at_or_before_stop": 50,
                    "terminal_cells_at_stop_timestamp": 0,
                },
                "incoming": {
                    "scheduled_cells_at_stop": 50,
                    "terminal_cells_at_stop": 40,
                    "drained_cells_after_stop": 10,
                    "last_scheduled_target_us": {
                        "minimum": 10_000_000,
                        "maximum": 10_000_000,
                        "p50": 10_000_000.0,
                        "p90": 10_000_000.0,
                        "p95": 10_000_000.0,
                    },
                    "last_terminal_at_us": {
                        "minimum": 10_000_001,
                        "maximum": 10_000_010,
                        "p50": 10_000_005.0,
                        "p90": 10_000_009.0,
                        "p95": 10_000_010.0,
                    },
                    "terminal_cells_strictly_before_stop": 40,
                    "terminal_cells_at_or_before_stop": 40,
                    "terminal_cells_at_stop_timestamp": 0,
                },
            },
        }
        for workload in workloads
        for block in range(10)
    ]
    cs_local_et = [
        {
            "defense": "cs-buflo",
            "workload_id": workload,
            "acquisition_block_index": block,
            "samples": 10,
            "before_application_complete_samples": 0,
            "latched_at_us": {
                "p50": 2_000_001.0,
                "p90": 2_000_002.0,
                "p95": 2_000_003.0,
            },
            "pending_request_cancellations": 0,
            "stream_cancellations": 0,
            "application_receive_streams_handed_off": 0,
            "application_parser_boundaries_handed_off": 0,
            "application_parser_lease_bytes_handed_off": 0,
            "application_send_endpoints_released": 0,
            "post_local_et_natural_outgoing_bytes": 0,
            "post_local_et_natural_incoming_bytes": 0,
        }
        for workload in workloads
        for block in range(10)
    ]
    return {
        "performance_breakdowns": {
            "directional": directional,
            "client": client,
            "paired_directional_by_workload_block": paired_directional,
            "paired_client_by_workload_block": paired_client,
            "paired_mode_direction_block_workload_bootstrap_95": [
                {
                    "defense": mode,
                    "direction": direction,
                    "pairs": 500,
                }
                for mode in defended
                for direction in ("outgoing", "incoming")
            ],
            "paired_mode_client_block_workload_bootstrap_95": mode_client,
        },
        "algorithm_breakdowns": {
            "schema_version": 3,
            "available": True,
            "classifier_input": False,
            "strata": algorithm_strata,
            "buflo_terminal_tail_strata": tail,
            "buflo_schedule_stop_strata": schedule_stop,
            "cs_buflo_local_termination_strata": cs_local_et,
        },
        "paired_per_visit": [{} for _ in range(1_000)],
        "paired_metrics": {
            "buflo": {"pairs": 500},
            "cs-buflo": {"pairs": 500},
        },
    }


def test_formal_performance_gate_requires_exact_axes_and_terminal_tail() -> None:
    value = _formal_performance_evaluation_fixture()
    evidence = buflo_study._validate_formal_performance_evidence(value)
    assert evidence["buflo_terminal_tail_strata"] == 50
    assert evidence["buflo_terminal_tail_samples"] == 500
    assert evidence["buflo_schedule_stop_strata"] == 50
    assert evidence["buflo_schedule_stop_samples"] == 500
    assert evidence["buflo_schedule_stop_incoming_drained_cells"] == 500
    assert evidence["cs_buflo_local_termination_strata"] == 50

    mutations = []
    duplicate_algorithm = json.loads(json.dumps(value))
    duplicate_algorithm["algorithm_breakdowns"]["strata"][0].update(
        duplicate_algorithm["algorithm_breakdowns"]["strata"][1]
    )
    mutations.append(duplicate_algorithm)
    duplicate_performance = json.loads(json.dumps(value))
    duplicate_performance["performance_breakdowns"]["directional"][0].update(
        duplicate_performance["performance_breakdowns"]["directional"][1]
    )
    mutations.append(duplicate_performance)
    nonzero_zero_tail = json.loads(json.dumps(value))
    capacity = nonzero_zero_tail["algorithm_breakdowns"]["buflo_terminal_tail_strata"][0][
        "exact_capacity_bytes_cancelled"
    ]
    capacity.update({"total": 10, "minimum": 1, "maximum": 1, "p50": 1, "p90": 1, "p95": 1})
    mutations.append(nonzero_zero_tail)
    parser_backlog = json.loads(json.dumps(value))
    parser_backlog["algorithm_breakdowns"]["buflo_terminal_tail_strata"][0][
        "parser_lease_bytes_at_latch"
    ] = 1
    mutations.append(parser_backlog)
    wrong_policy = json.loads(json.dumps(value))
    wrong_policy["algorithm_breakdowns"]["buflo_terminal_tail_strata"][0][
        "terminal_subcell_policy"
    ] = ["drifted"]
    mutations.append(wrong_policy)
    mismatched_counters = json.loads(json.dumps(value))
    mismatched_counters["algorithm_breakdowns"]["buflo_terminal_tail_strata"][0][
        "receipt_cancellations"
    ] = 1
    mutations.append(mismatched_counters)
    wrong_stop_policy = json.loads(json.dumps(value))
    wrong_stop_policy["algorithm_breakdowns"]["buflo_schedule_stop_strata"][0]["policy"] = [
        "drifted"
    ]
    mutations.append(wrong_stop_policy)
    wrong_time_semantics = json.loads(json.dumps(value))
    wrong_time_semantics["algorithm_breakdowns"]["buflo_schedule_stop_strata"][0][
        "terminal_time_semantics"
    ] = ["drifted"]
    mutations.append(wrong_time_semantics)
    outgoing_drain = json.loads(json.dumps(value))
    outgoing_drain["algorithm_breakdowns"]["buflo_schedule_stop_strata"][0]["directions"][
        "outgoing"
    ]["drained_cells_after_stop"] = 1
    mutations.append(outgoing_drain)
    missing_schedule_stop = json.loads(json.dumps(value))
    missing_schedule_stop["algorithm_breakdowns"]["buflo_schedule_stop_strata"].pop()
    mutations.append(missing_schedule_stop)
    missing_handoff = json.loads(json.dumps(value))
    missing_handoff["algorithm_breakdowns"]["cs_buflo_local_termination_strata"][0][
        "before_application_complete_samples"
    ] = 1
    mutations.append(missing_handoff)
    post_without_early_et = json.loads(json.dumps(value))
    post_without_early_et["algorithm_breakdowns"]["cs_buflo_local_termination_strata"][0][
        "post_local_et_natural_outgoing_bytes"
    ] = 1
    mutations.append(post_without_early_et)
    zero_latch = json.loads(json.dumps(value))
    zero_latch["algorithm_breakdowns"]["cs_buflo_local_termination_strata"][0]["latched_at_us"][
        "p50"
    ] = 0
    mutations.append(zero_latch)

    for changed in mutations:
        with pytest.raises(ValueError, match="formal"):
            buflo_study._validate_formal_performance_evidence(changed)


@pytest.mark.parametrize(
    ("rank", "observed"),
    (
        (0, [{"kind": "noqueue", "root": True}]),
        (
            1,
            [
                {
                    "kind": "netem",
                    "root": True,
                    "options": {
                        "limit": 1_000,
                        "delay": {"delay": 0.025, "jitter": 0, "correlation": 0},
                    },
                }
            ],
        ),
        (
            2,
            [
                {
                    "kind": "netem",
                    "root": True,
                    "options": {
                        "delay": {"delay": 0.025, "jitter": 0, "correlation": 0},
                        "rate": {
                            "rate": 625_000,
                            "packetoverhead": 0,
                            "cellsize": 0,
                            "celloverhead": 0,
                        },
                        "limit": 100,
                    },
                }
            ],
        ),
        (
            3,
            [
                {
                    "kind": "netem",
                    "root": True,
                    "options": {
                        "limit": 1_000,
                        "delay": {"delay": 0.025, "jitter": 0, "correlation": 0},
                        "loss-random": {"loss": 0.01, "correlation": 0},
                    },
                }
            ],
        ),
    ),
)
def test_historical_controlled_receipt_requires_exact_bilateral_qdisc_evidence(
    rank: int, observed: list[dict[str, object]]
) -> None:
    profile = load_study_plan()["controlled"]["netem_profiles"][rank]
    endpoint = {
        "interface": "eth0",
        "applied_qdisc": profile["client_qdisc"],
        "observed_qdisc": observed,
    }
    receipt = {
        "schema_version": 2,
        "stage": "controlled",
        "netem_profile": profile["id"],
        "netem_rank": rank,
        "client_qdisc": profile["client_qdisc"],
        "server_qdisc": profile["server_qdisc"],
        "workload_aliases": {
            "local-large": "local-large",
            "local-small": "local-small",
        },
        "fixture_scope": "controlled-live-manifests-including-two-origin-local-large",
        "treatment_order": [
            "undefended",
            "buflo",
            "cs-buflo-cpsp",
            "cs-buflo-ctsp",
        ],
        "evidence_class": "controlled-test-only-nonformal",
        "network": {
            "schema_version": 1,
            "artifact_type": "qcsd-buflo-controlled-network-v1",
            "image_digest": "sha256:" + "a" * 64,
            "network": "qcsd-buflo-study-v1",
            "client": {"role": "client", **endpoint},
            "servers": [
                {
                    "role": "server",
                    "alias": alias,
                    **endpoint,
                    "applied_qdisc": profile["server_qdisc"],
                }
                for alias in (
                    "qcsd-buflo-server-one",
                    "qcsd-buflo-server-two",
                )
            ],
            "directional_coverage": {
                "client_to_server": {
                    "shaped_egress": "client:eth0",
                    "opposite_ingress": "servers:eth0",
                },
                "server_to_client": {
                    "shaped_egress": "servers:eth0",
                    "opposite_ingress": "client:eth0",
                },
            },
        },
    }

    assert validate_controlled_campaign_receipt(receipt)["netem_rank"] == rank
    historical = dict(receipt)
    historical.pop("fixture_scope")
    historical["schema_version"] = 1
    assert validate_controlled_campaign_receipt(historical)["netem_rank"] == rank
    stripped = dict(receipt)
    stripped.pop("fixture_scope")
    with pytest.raises(ValueError, match="fields are invalid"):
        validate_controlled_campaign_receipt(stripped)
    changed_scope = json.loads(json.dumps(receipt))
    changed_scope["fixture_scope"] = "same-origin-regression-surrogates"
    with pytest.raises(ValueError, match="matrix binding"):
        validate_controlled_campaign_receipt(changed_scope)
    changed = json.loads(json.dumps(receipt))
    changed["network"]["directional_coverage"]["server_to_client"]["opposite_ingress"] = (
        "unobserved"
    )
    with pytest.raises(ValueError, match="bilateral"):
        validate_controlled_campaign_receipt(changed)


def _shared_router_address(interface: str, ipv4: str | None) -> list[dict[str, object]]:
    addr_info: list[dict[str, object]] = []
    if ipv4 is not None:
        address, prefix = ipv4.split("/")
        addr_info.append({"family": "inet", "local": address, "prefixlen": int(prefix)})
    return [
        {
            "ifname": interface,
            "flags": ["BROADCAST", "UP", "LOWER_UP"],
            "mtu": 1_500,
            "addr_info": addr_info,
        }
    ]


def _shared_router_offloads(interface: str) -> list[dict[str, object]]:
    return [
        {
            "ifname": interface,
            "generic-receive-offload": {"active": False},
            "generic-segmentation-offload": {"active": False},
            "tcp-segmentation-offload": {"active": False},
            "tx-udp-segmentation": {"active": False},
        }
    ]


def _shared_router_netem(profile: str, handle: str) -> dict[str, object]:
    options: dict[str, object] = {
        "limit": 100 if "limit 100" in profile else 1_000,
        "delay": {"delay": 0.025, "jitter": 0, "correlation": 0},
        "ecn": False,
        "gap": 0,
    }
    if "rate 5mbit" in profile:
        options["rate"] = {
            "rate": 625_000,
            "packetoverhead": 0,
            "cellsize": 0,
            "celloverhead": 0,
        }
    if "loss 1%" in profile:
        options["loss-random"] = {"loss": 0.01, "correlation": 0}
    return {"kind": "netem", "handle": handle, "root": True, "options": options}


def _shared_router_routes(
    own_subnet: str,
    own_gateway: str,
    own_ip: str,
    remote_subnet: str,
    remote_router: str,
    interface: str,
) -> list[dict[str, object]]:
    return [
        {"dst": "default", "gateway": own_gateway, "dev": interface, "flags": []},
        {
            "dst": own_subnet,
            "dev": interface,
            "flags": [],
            "protocol": "kernel",
            "scope": "link",
            "prefsrc": own_ip,
        },
        {"dst": remote_subnet, "gateway": remote_router, "dev": interface, "flags": []},
    ]


def _shared_router_receipt(
    monkeypatch: pytest.MonkeyPatch, rank: int, *, handle_suffix: str = ""
) -> dict[str, object]:
    profile = load_study_plan()["controlled"]["netem_profiles"][rank]
    client_name = "qcsd-buflo-study-v15-client"
    server_name = "qcsd-buflo-study-v15-server"
    client_subnet, server_subnet, base = buflo_study._controlled_network_pair(
        client_name, server_name
    )
    client_gateway = str(client_subnet.network_address + 1)
    router_client = str(client_subnet.network_address + 2)
    client_ip = str(client_subnet.network_address + 3)
    server_gateway = str(server_subnet.network_address + 1)
    router_server = str(server_subnet.network_address + 2)
    server_ips = [
        str(server_subnet.network_address + 3),
        str(server_subnet.network_address + 4),
    ]
    noqueue = [{"kind": "noqueue", "root": True, "options": {}}]
    ifb_default = [{"kind": "fq_codel", "root": True, "options": {}}]
    impaired = rank != 0
    router_eth0_qdisc = (
        [
            _shared_router_netem(profile["server_qdisc"], f"20{handle_suffix}:"),
            {"kind": "ingress", "handle": "ffff:", "parent": "ffff:fff1", "options": {}},
        ]
        if impaired
        else noqueue
    )
    router_ifb_qdisc = (
        [_shared_router_netem(profile["client_qdisc"], f"10{handle_suffix}:")]
        if impaired
        else ifb_default
    )
    ingress_filter: list[dict[str, object]] = []
    if impaired:
        ingress_filter = [
            {"protocol": "all", "kind": "u32"},
            {"protocol": "all", "kind": "u32", "options": {"ht_divisor": 1}},
            {
                "protocol": "all",
                "kind": "u32",
                "options": {
                    "match": {"value": "0", "mask": "0", "off": 0},
                    "actions": [
                        {
                            "kind": "mirred",
                            "mirred_action": "redirect",
                            "direction": "egress",
                            "to_dev": "ifb0",
                            "control_action": {"type": "stolen"},
                        }
                    ],
                },
            },
        ]
    router_routes = [
        {"dst": "default", "gateway": client_gateway, "dev": "eth0", "flags": []},
        {
            "dst": str(client_subnet),
            "dev": "eth0",
            "flags": [],
            "protocol": "kernel",
            "scope": "link",
            "prefsrc": router_client,
        },
        {
            "dst": str(server_subnet),
            "dev": "eth1",
            "flags": [],
            "protocol": "kernel",
            "scope": "link",
            "prefsrc": router_server,
        },
    ]
    servers = []
    for suffix, alias, server_ip in zip(
        ("one", "two"),
        ("qcsd-buflo-server-one", "qcsd-buflo-server-two"),
        server_ips,
        strict=True,
    ):
        servers.append(
            {
                "container": f"{base}-server-{suffix}",
                "alias": alias,
                "addresses": {"eth0": _shared_router_address("eth0", f"{server_ip}/24")},
                "qdiscs": {"eth0": noqueue},
                "offloads": {"eth0": _shared_router_offloads("eth0")},
                "routes": _shared_router_routes(
                    str(server_subnet),
                    server_gateway,
                    server_ip,
                    str(client_subnet),
                    router_server,
                    "eth0",
                ),
            }
        )
    raw = {
        "schema_version": 1,
        "client_network": {
            "name": client_name,
            "ipam": [{"Subnet": str(client_subnet), "IPRange": "", "Gateway": client_gateway}],
        },
        "server_network": {
            "name": server_name,
            "ipam": [{"Subnet": str(server_subnet), "IPRange": "", "Gateway": server_gateway}],
        },
        "router": {
            "container": f"{base}-router",
            "addresses": {
                "eth0": _shared_router_address("eth0", f"{router_client}/24"),
                "eth1": _shared_router_address("eth1", f"{router_server}/24"),
                "ifb0": _shared_router_address("ifb0", None),
            },
            "qdiscs": {
                "eth0": router_eth0_qdisc,
                "eth1": noqueue,
                "ifb0": router_ifb_qdisc,
            },
            "offloads": {
                "eth0": _shared_router_offloads("eth0"),
                "eth1": _shared_router_offloads("eth1"),
            },
            "routes": router_routes,
            "client_ingress_filters": ingress_filter,
            "ip_forward": 1,
        },
        "servers": servers,
    }
    client_observation = {
        "addresses": {"eth0": _shared_router_address("eth0", f"{client_ip}/24")},
        "qdiscs": {"eth0": noqueue},
        "offloads": {"eth0": _shared_router_offloads("eth0")},
        "routes": _shared_router_routes(
            str(client_subnet),
            client_gateway,
            client_ip,
            str(server_subnet),
            router_client,
            "eth0",
        ),
        "hosts": {
            "qcsd-buflo-server-one": [server_ips[0]],
            "qcsd-buflo-server-two": [server_ips[1]],
        },
    }
    monkeypatch.setattr(buflo_study, "_observe_client_namespace", lambda: client_observation)
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "a" * 64)
    evidence = base64.b64encode(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    network_receipt = buflo_study._build_shared_router_network_receipt(
        network=client_name,
        controlled_network_evidence_b64=evidence,
        client_qdisc=profile["client_qdisc"],
        server_qdisc=profile["server_qdisc"],
        cohort_version=15,
    )
    return {
        "schema_version": buflo_study.LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
        "stage": "controlled",
        "netem_profile": profile["id"],
        "netem_rank": rank,
        "client_qdisc": profile["client_qdisc"],
        "server_qdisc": profile["server_qdisc"],
        "workload_aliases": {"local-large": "local-large", "local-small": "local-small"},
        "fixture_scope": "controlled-live-manifests-including-two-origin-local-large",
        "cohort_version": 15,
        "treatment_order": ["undefended", "buflo", "cs-buflo-cpsp", "cs-buflo-ctsp"],
        "evidence_class": "controlled-test-only-nonformal",
        "network": network_receipt,
    }


@pytest.mark.parametrize("rank", range(4))
def test_shared_router_receipt_binds_exact_once_per_direction_topology(
    monkeypatch: pytest.MonkeyPatch, rank: int
) -> None:
    receipt = _shared_router_receipt(monkeypatch, rank)
    assert validate_controlled_campaign_receipt(receipt)["netem_rank"] == rank
    assert receipt["network"]["capture_point"]["endpoint_impairment_qdiscs"] == 0
    if rank == 2:
        assert receipt["network"]["rate_aggregation"]["scope"] == (
            "one-shared-qdisc-per-direction-across-both-server-origins"
        )


def test_regression_receipt_binds_the_separate_two_origin_nine_mode_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _shared_router_receipt(monkeypatch, 0)
    receipt.update(
        {
            "stage": "regression",
            "workload_aliases": {"complex": "local-large", "simple": "local-small"},
            "fixture_scope": (
                "single-origin-prefix-regression-plus-bound-two-origin-nine-mode-compatibility"
            ),
            "treatment_order": list(load_study_plan()["regression"]["treatments"]),
        }
    )

    assert validate_controlled_campaign_receipt(receipt)["fixture_scope"].endswith(
        "nine-mode-compatibility"
    )
    historical = {
        **receipt,
        "schema_version": buflo_study.PREVIOUS_LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
        "fixture_scope": "same-origin-regression-surrogates",
    }
    assert validate_controlled_campaign_receipt(historical)["schema_version"] == 3
    invalid_current = {**receipt, "fixture_scope": "same-origin-regression-surrogates"}
    with pytest.raises(ValueError, match="matrix binding"):
        validate_controlled_campaign_receipt(invalid_current)


def test_shared_router_receipt_normalizes_nondeterministic_qdisc_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _shared_router_receipt(monkeypatch, 2, handle_suffix="1")
    second = _shared_router_receipt(monkeypatch, 2, handle_suffix="9")
    assert first == second


@pytest.mark.parametrize(
    ("location", "key"),
    (
        ("top", "distribution"),
        ("delay", "reorder"),
        ("rate", "slot"),
        ("loss-random", "seed"),
    ),
)
def test_shared_router_netem_rejects_unknown_raw_options(location: str, key: str) -> None:
    options = _shared_router_netem("netem delay 25ms rate 5mbit limit 100 loss 1%", "10:")[
        "options"
    ]
    assert isinstance(options, dict)
    if location == "top":
        options[key] = 1
    else:
        nested = options[location]
        assert isinstance(nested, dict)
        nested[key] = 1
    with pytest.raises(ValueError, match="controlled netem"):
        buflo_study._canonical_netem_options(options)


def test_shared_router_route_rejects_unreceipted_packetization_attributes() -> None:
    routes = [
        {
            "dst": "default",
            "gateway": "10.0.0.1",
            "dev": "eth0",
            "flags": [],
            "mtu": 576,
        }
    ]
    with pytest.raises(ValueError, match="controlled route row"):
        buflo_study._canonical_routes(routes)


@pytest.mark.parametrize(
    "tamper",
    (
        "ip-forward",
        "router-interface",
        "client-route",
        "client-hosts",
        "ifb-netem",
        "ingress-filter",
        "client-qdisc",
        "server-qdisc",
        "router-offload",
        "coverage-count",
        "aggregate-scope",
        "cohort-version",
    ),
)
def test_shared_router_receipt_rejects_network_evidence_tampering(
    monkeypatch: pytest.MonkeyPatch, tamper: str
) -> None:
    receipt = _shared_router_receipt(monkeypatch, 2)
    changed = json.loads(json.dumps(receipt))
    network = changed["network"]
    if tamper == "ip-forward":
        network["router"]["ip_forward"] = 0
    elif tamper == "router-interface":
        network["router"]["observed_addresses"]["eth0"]["ipv4"] = network["router"][
            "observed_addresses"
        ]["eth1"]["ipv4"]
    elif tamper == "client-route":
        network["client"]["observed_routes"][0]["gateway"] = "10.0.0.254"
    elif tamper == "client-hosts":
        network["client"]["observed_hosts"]["qcsd-buflo-server-one"] = ["10.0.0.9"]
    elif tamper == "ifb-netem":
        network["router"]["observed_qdiscs"]["ifb0"][0]["netem"]["rate_bytes_per_second"] = (
            1_250_000
        )
    elif tamper == "ingress-filter":
        network["router"]["observed_client_ingress_filter"]["action"]["to_device"] = "eth1"
    elif tamper == "client-qdisc":
        network["client"]["observed_qdiscs"] = network["router"]["observed_qdiscs"]["ifb0"]
    elif tamper == "server-qdisc":
        network["servers"][0]["observed_qdiscs"] = network["router"]["observed_qdiscs"]["eth0"]
    elif tamper == "router-offload":
        network["router"]["observed_offloads"]["eth0"]["gso"] = True
    elif tamper == "coverage-count":
        network["directional_coverage"]["client_to_server"]["impairment_applications"] = 2
    elif tamper == "aggregate-scope":
        network["rate_aggregation"]["scope"] = "per-origin"
    elif tamper == "cohort-version":
        changed["cohort_version"] = 16
    with pytest.raises(ValueError, match="controlled"):
        validate_controlled_campaign_receipt(changed)


def test_validation_attestation_promotion_is_fail_closed(tmp_path: Path) -> None:
    attestation = tmp_path / "validation-attestation.json"
    attestation.write_text(
        json.dumps({"implementation_status": "validated-client-only-qcsd-adaptation"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="typed evidence is missing"):
        validate_validation_attestation(attestation)


def test_public_comparison_validation_threads_wall_override_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = tmp_path / "handoff"
    handoff.mkdir()
    evaluation_receipt = tmp_path / "evaluation.json"
    evaluation_receipt.write_text("{}\n", encoding="utf-8")
    review = tmp_path / "review.json"
    review.write_text("{}\n", encoding="utf-8")
    evaluation = {"validated": True}
    observed: list[dict[str, object]] = []

    monkeypatch.setattr(
        buflo_handoff,
        "validate_study_handoff",
        lambda *_args, **_kwargs: handoff.resolve(),
    )

    def validate_evaluation(*_args: object, **kwargs: object) -> dict[str, object]:
        observed.append(dict(kwargs))
        return evaluation

    monkeypatch.setattr(buflo_evaluation, "validate_evaluation_receipt", validate_evaluation)
    monkeypatch.setattr(
        buflo_study,
        "_validate_comparison_review_value",
        lambda *_args, **kwargs: {
            "evaluation_reused": kwargs["evaluation"] is evaluation,
            "passed": True,
        },
    )

    result = buflo_study.validate_comparison_review(
        review,
        evaluation_receipt=evaluation_receipt,
        handoff=handoff,
        formal=True,
        dlsvm_available_wall_seconds=654.0,
    )

    assert result == {"evaluation_reused": True, "passed": True}
    assert len(observed) == 1
    assert observed[0]["deep"] is True
    assert observed[0]["dlsvm_available_wall_seconds"] == 654.0


def test_attestation_create_publishes_validated_value_without_rederivation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "validation-attestation.json"
    value = {
        "schema_version": 2,
        "artifact_type": buflo_study.ATTESTATION_ARTIFACT_TYPE,
        "all_hard_gates_passed": True,
    }
    derivations: list[dict[str, object]] = []

    def derive(**kwargs: object) -> dict[str, object]:
        derivations.append(dict(kwargs))
        return value

    monkeypatch.setattr(buflo_study, "_validation_attestation_value", derive)
    monkeypatch.setattr(
        buflo_study,
        "validate_validation_attestation",
        lambda *_args, **_kwargs: pytest.fail("create must not rederive the attestation"),
    )

    output = buflo_study.create_validation_attestation(
        destination,
        dlsvm_available_wall_seconds=987.0,
    )

    assert output == destination
    assert buflo_study.load_json(output) == value
    assert output.read_bytes() == (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    assert len(derivations) == 1
    assert derivations[0]["deep_code_gate"] is True
    assert derivations[0]["dlsvm_available_wall_seconds"] == 987.0
    assert buflo_study._created_validation_attestation_result(output) == {
        "path": str(output),
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        **value,
    }


def test_existing_attestation_verification_deep_derives_once_and_threads_wall_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = {
        "reference_receipt": {"path": "reference.json"},
        "code_gate_receipt": {"path": "code.json"},
        "qualification_receipt": {"path": "qualification.json"},
        "regression_results": [{"root": "regression"}],
        "controlled_results": [{"root": "controlled"}],
        "smoke_result": {"root": "smoke"},
        "rehearsal_result": {"root": "rehearsal"},
        "formal_results": [{"root": f"formal-{index}"} for index in range(10)],
        "capture_admission": {"path": "admission.json"},
        "formal_cohort": {"path": "cohort.json"},
        "handoff": {"root": "handoff"},
        "evaluation_receipt": {"path": "evaluation.json"},
        "comparison_review": {"path": "comparison.json"},
        "historical_pre_snapshot": {"path": "pre.json"},
        "historical_post_snapshot": {"path": "post.json"},
    }
    value = {
        "schema_version": 2,
        "artifact_type": buflo_study.ATTESTATION_ARTIFACT_TYPE,
        "study_id": buflo_study.BUFLO_STUDY_ID,
        "cohort_version": 15,
        "implementation_status": buflo_study.VALIDATED_STATUS,
        "implementation_status_description": buflo_study.VALIDATED_STATUS_DESCRIPTION,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
        "no_waivers": True,
        "evidence": evidence,
        "hard_gates": buflo_study._hard_gate_records(["a" * 64], schema_version=2),
        "all_hard_gates_passed": True,
    }
    path = tmp_path / "existing-attestation.json"
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    calls: list[dict[str, object]] = []

    def derive(**kwargs: object) -> dict[str, object]:
        calls.append(dict(kwargs))
        return value

    monkeypatch.setattr(buflo_study, "_validation_attestation_value", derive)

    verified = buflo_study.validate_validation_attestation(
        path,
        expected_cohort_version=15,
        deep_code_gate=True,
        dlsvm_available_wall_seconds=4321.0,
    )

    assert verified["all_hard_gates_passed"] is True
    assert len(calls) == 1
    assert calls[0]["deep_code_gate"] is True
    assert calls[0]["dlsvm_available_wall_seconds"] == 4321.0


def test_new_formal_artifacts_cannot_bypass_v15_contract(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="formal cohort creation requires cohort version 15"):
        buflo_study.create_formal_cohort_manifest(
            tmp_path / "cohort.json",
            cohort_id="legacy-new-formal",
            results_root=tmp_path / "results",
            historical_pre_snapshot=tmp_path / "pre.json",
            cohort_version=14,
        )

    with pytest.raises(ValueError, match="formal capture admission requires cohort version 15"):
        buflo_study.create_capture_admission(
            tmp_path / "admission.json",
            stage="formal",
            reference_receipt=tmp_path / "reference.json",
            qualification_receipt=tmp_path / "qualification.json",
            prerequisite_result_roots=(),
            results_root=tmp_path / "results",
            cohort_version=14,
        )


def test_validation_attestation_rejects_each_hard_gate_identity_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = {
        "reference_receipt": {"path": "reference.json"},
        "code_gate_receipt": {"path": "code-gate.json"},
        "qualification_receipt": {"path": "qualification.json"},
        "regression_results": [{"root": "regression"}],
        "controlled_results": [{"root": "controlled"}],
        "smoke_result": {"root": "smoke"},
        "rehearsal_result": {"root": "rehearsal"},
        "formal_results": [{"root": f"formal-{index}"} for index in range(10)],
        "capture_admission": {"path": "admission.json"},
        "formal_cohort": {"path": "cohort.json"},
        "handoff": {"root": "handoff"},
        "evaluation_receipt": {"path": "evaluation.json"},
        "comparison_review": {"path": "comparison.json"},
        "historical_pre_snapshot": {"path": "pre.json"},
        "historical_post_snapshot": {"path": "post.json"},
    }
    canonical = {
        "schema_version": 2,
        "artifact_type": buflo_study.ATTESTATION_ARTIFACT_TYPE,
        "study_id": buflo_study.BUFLO_STUDY_ID,
        "cohort_version": 15,
        "qualification_set": "buflo-study-public5-v15",
        "study_plan": {"path": "study.json", "sha256": "b" * 64},
        "implementation_status": buflo_study.VALIDATED_STATUS,
        "implementation_status_description": buflo_study.VALIDATED_STATUS_DESCRIPTION,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
        "no_waivers": True,
        "source": {},
        "evidence": evidence,
        "validation_summary": {},
        "hard_gates": buflo_study._hard_gate_records(["a" * 64], schema_version=2),
        "all_hard_gates_passed": True,
    }
    monkeypatch.setattr(
        buflo_study,
        "_validation_attestation_value",
        lambda **_kwargs: canonical,
    )
    valid = tmp_path / "valid-attestation.json"
    valid.write_text(json.dumps(canonical), encoding="utf-8")
    assert validate_validation_attestation(valid, deep_code_gate=False)["cohort_version"] == 15

    for index in range(len(buflo_study.HARD_GATE_IDENTITIES)):
        tampered = json.loads(json.dumps(canonical))
        forged_gate = tampered["hard_gates"][index]["gate"] + "-tampered"
        tampered["hard_gates"][index]["gate"] = forged_gate
        tampered["hard_gates"][index]["gate_identity_sha256"] = (
            buflo_study._hard_gate_identity_sha256(index + 1, forged_gate)
        )
        path = tmp_path / f"tampered-gate-{index + 1:02d}.json"
        path.write_text(json.dumps(tampered), encoding="utf-8")
        with pytest.raises(ValueError, match=f"ordinal {index + 1}"):
            validate_validation_attestation(path, deep_code_gate=False)


def test_study_plan_rejects_each_hard_gate_identity_tamper() -> None:
    plan = load_study_plan()
    for index in range(len(buflo_study.HARD_GATE_IDENTITIES)):
        tampered = json.loads(json.dumps(plan))
        tampered["hard_gates"][index] += "-tampered"
        with pytest.raises(ValueError, match="immutable ordered identities"):
            buflo_study.validate_study_plan(tampered)


def test_local_workload_preparation_freezes_real_probe_receipts_without_synthesis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workload = {
        "resources": [
            buflo_study._local_resource(
                0,
                "https://qcsd-buflo-server-one:4433/1024",
                "Document",
                1_024,
            )
        ]
    }
    response = {
        "resource_id": 0,
        "status": 200,
        "bytes": 1_024,
        "body_sha256": "a" * 64,
        "complete": True,
        "outcome": "succeeded",
        "request_headers": [["accept", "text/html"]],
    }
    runs = [
        {
            "neqo_version": "test-neqo",
            "neqo_base_commit": "1" * 40,
            "published_qcsd_commit": "2" * 40,
            "migration_commit": "3" * 40,
            "responses": [response],
        }
        for _index in range(3)
    ]
    directional_statistics = {
        "packet_count": 1,
        "observed_udp_payload_max": 1_200,
        "oversized_packet_count": 0,
    }
    total_statistics = {**directional_statistics, "packet_count": 2}
    udp = {
        "schema_version": 1,
        "configured_udp_payload_ceiling": 1_200,
        "runs": [
            {
                "run_index": index,
                "packets_sha256": chr(ord("d") + index) * 64,
                "incoming": directional_statistics,
                "outgoing": directional_statistics,
                "total": total_statistics,
            }
            for index in range(3)
        ],
    }

    def probe(
        *_args: object, **_kwargs: object
    ) -> tuple[dict[str, object], list[dict[str, object]], dict[str, object]]:
        return (
            {
                "runs": 3,
                "stable_resource_ids": [0],
                "expected_responses": [
                    {
                        key: response[key]
                        for key in ("resource_id", "status", "bytes", "body_sha256")
                    }
                ],
            },
            runs,
            udp,
        )

    monkeypatch.setattr("qcsd_lab.prepare._probe_response_stability", probe)
    monkeypatch.setattr(
        buflo_study,
        "source_metadata",
        lambda: {
            "image_digest": "sha256:" + "9" * 64,
            "lab_commit": "4" * 40,
            "lab_dirty": True,
            "lab_patch_sha256": "5" * 64,
            "neqo_commit": "3" * 40,
            "neqo_pinned_commit": "3" * 40,
            "neqo_dirty": True,
            "neqo_patch_sha256": "6" * 64,
        },
    )
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "9" * 64)

    buflo_study._prepare_local_workloads(
        tmp_path,
        {"local-probe": workload},
        label="test local workload",
    )

    frozen = json.loads((tmp_path / "local-probe.json").read_text(encoding="utf-8"))
    preparation = frozen["preparation"]
    assert preparation["chromium_version"] == "not-applicable-deterministic-local-server"
    assert preparation["lab_source"]["lab_dirty"] is True
    assert [run["packets_sha256"] for run in preparation["udp_payload_qualification"]["runs"]] == [
        "d" * 64,
        "e" * 64,
        "f" * 64,
    ]
    assert preparation["expected_responses"][0]["body_sha256"] == "a" * 64


def test_controlled_rate_driver_is_separate_bounded_and_live_size_gated() -> None:
    values = {
        workload_id: buflo_study._csbuflo_rate_driver_value(workload_id)
        for workload_id in ("local-small", "local-large")
    }
    assert len(set(values.values())) == 2
    assert all(
        len(value.encode("ascii")) == buflo_study.CSBUFLO_RATE_DRIVER_VALUE_BYTES
        for value in values.values()
    )
    assert buflo_study.CSBUFLO_RATE_DRIVER_VALUE_BYTES < 384 * 1_024
    assert (
        buflo_study.CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES
        == buflo_study.CSBUFLO_RATE_DRIVER_BOUNDARY_BYTES
        + 4 * buflo_study.CSBUFLO_RATE_DRIVER_CELL_BYTES
    )

    driver = buflo_study._controlled_csbuflo_rate_driver(1, "local-small")
    resources = [
        buflo_study._local_resource(
            0,
            "https://qcsd-buflo-server-one:4433/131072",
            "Document",
            131_072,
        ),
        driver,
    ]
    response = {
        "resource_id": 1,
        "complete": True,
        "outcome": "succeeded",
        "request_headers": driver["headers"],
        "request_stream_bytes": buflo_study.CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES,
    }
    proof = buflo_study._validate_controlled_csbuflo_rate_driver(
        "local-small",
        resources,
        runs=[{"responses": [response]} for _index in range(3)],
    )
    assert (
        proof["encoded_request_stream_bytes"]
        == [buflo_study.CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES] * 3
    )
    observation = buflo_study._controlled_csbuflo_rate_driver_observation(
        "local-small", {"responses": [response]}
    )
    assert observation["post_boundary_cells"] == 4

    too_short = {**response, "request_stream_bytes": 16_384}
    with pytest.raises(ValueError, match="did not encode beyond"):
        buflo_study._validate_controlled_csbuflo_rate_driver(
            "local-small", resources, runs=[{"responses": [too_short]}]
        )


def test_controlled_driver_does_not_change_regression_manifests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, dict[str, dict[str, object]], bool]] = []

    def capture(
        _root: Path,
        manifests: dict[str, dict[str, object]],
        *,
        label: str,
        require_csbuflo_rate_driver: bool = False,
    ) -> None:
        calls.append((label, manifests, require_csbuflo_rate_driver))

    monkeypatch.setattr(buflo_study, "_prepare_local_workloads", capture)
    buflo_study._create_local_workloads(tmp_path)
    buflo_study._create_regression_workloads(tmp_path)
    buflo_study._create_regression_multi_origin_workload(tmp_path)

    _controlled_label, controlled, controlled_gate = calls[0]
    _regression_label, regression, regression_gate = calls[1]
    _compatibility_label, compatibility, compatibility_gate = calls[2]
    assert controlled_gate is True
    assert regression_gate is False
    assert compatibility_gate is False
    assert [len(controlled[name]["resources"]) for name in ("local-small", "local-large")] == [
        2,
        5,
    ]
    assert [len(regression[name]["resources"]) for name in ("simple", "complex")] == [1, 4]
    assert {
        resource["url"].split("/", 3)[2] for resource in controlled["local-large"]["resources"]
    } == {"qcsd-buflo-server-one:4433", "qcsd-buflo-server-two:4434"}
    assert {
        resource["url"].split("/", 3)[2] for resource in regression["complex"]["resources"]
    } == {"qcsd-buflo-server-one:4433"}
    assert {
        resource["url"].split("/", 3)[2] for resource in compatibility["complex"]["resources"]
    } == {"qcsd-buflo-server-one:4433", "qcsd-buflo-server-two:4434"}
    for workload_id in ("local-small", "local-large"):
        proof = buflo_study._validate_controlled_csbuflo_rate_driver(
            workload_id, controlled[workload_id]["resources"]
        )
        assert proof["resource_id"] == (1 if workload_id == "local-small" else 4)
    assert all(
        buflo_study.CSBUFLO_RATE_DRIVER_HEADER_NAME
        not in {header[0] for resource in manifest["resources"] for header in resource["headers"]}
        for manifest in regression.values()
    )


def _regression_prefix_manifest(workload_id: str) -> dict[str, object]:
    resources = [
        buflo_study._local_resource(
            0,
            "https://qcsd-buflo-server-one:4433/131072",
            "Document",
            131_072,
        )
    ]
    if workload_id == "complex":
        resources.extend(
            [
                buflo_study._local_resource(
                    1,
                    "https://qcsd-buflo-server-one:4433/1024",
                    "Script",
                    1_024,
                    depends_on=[0],
                ),
                buflo_study._local_resource(
                    2,
                    "https://qcsd-buflo-server-one:4433/4096",
                    "Script",
                    4_096,
                    depends_on=[0],
                ),
                buflo_study._local_resource(
                    3,
                    "https://qcsd-buflo-server-one:4433/2048",
                    "Image",
                    2_048,
                    depends_on=[2],
                ),
            ]
        )
    return {
        "preparation": {
            "source_url": resources[0]["url"],
            "final_url": resources[0]["url"],
            "approved_origins": [
                "https://qcsd-buflo-server-one:4433",
            ],
            "expected_responses": [
                {
                    "resource_id": resource["id"],
                    "status": 200,
                    "bytes": resource["data_length"],
                    "body_sha256": f"{resource['id'] + 1:x}" * 64,
                }
                for resource in resources
            ],
        },
        "resources": resources,
    }


def _regression_multi_origin_identity_manifest() -> dict[str, object]:
    manifest = _regression_prefix_manifest("complex")
    resources = manifest["resources"]
    assert isinstance(resources, list)
    for resource in resources:
        if resource["id"] in {2, 3}:
            resource["url"] = resource["url"].replace(
                "qcsd-buflo-server-one:4433", "qcsd-buflo-server-two:4434"
            )
    preparation = manifest["preparation"]
    assert isinstance(preparation, dict)
    preparation["approved_origins"] = list(buflo_study.MULTI_ORIGIN_COMPATIBILITY_ORIGINS)
    preparation["observed_origins"] = list(buflo_study.MULTI_ORIGIN_COMPATIBILITY_ORIGINS)
    return manifest


def _multi_origin_attempt_ledger_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    Path,
    Path,
    Path,
    tuple[SimpleNamespace, ...],
    dict[str, str],
    list[dict[str, object]],
]:
    root = tmp_path / "compatibility"
    mode_root = root / "attempts/wtf-pad"
    rejected = mode_root / "attempt-01"
    accepted = mode_root / "attempt-02"
    rejected.mkdir(parents=True)
    accepted.mkdir()
    (rejected / "attempt.json").write_text(
        json.dumps(
            {
                "success": False,
                "failure": {
                    "stage": "capture",
                    "reason": "direct/runner reconciliation failed",
                },
            }
        ),
        encoding="utf-8",
    )
    (accepted / "attempt.json").write_text(
        json.dumps({"success": True}),
        encoding="utf-8",
    )

    def evidence(
        attempt: Path,
        _application_path: Path,
        _projected_chaff_path: Path,
        defense: SimpleNamespace,
        *,
        seed: int,
        historical_candidate_source: dict[str, object] | None = None,
    ) -> dict[str, object]:
        assert historical_candidate_source is None
        result = json.loads((attempt / "attempt.json").read_text(encoding="utf-8"))
        if result.get("success") is not True:
            raise ValueError("attempt is rejected")
        return {"attempt": str(attempt), "mode": defense.name, "seed": seed}

    monkeypatch.setattr(
        buflo_study,
        "_regression_multi_origin_attempt_evidence",
        evidence,
    )
    application_path = root / "application.json"
    projected_chaff_path = root / "chaff.json"
    defenses = (SimpleNamespace(name="wtf-pad"),)
    relative = "attempts/wtf-pad/attempt-02"
    files = buflo_study._regression_multi_origin_raw_attempt_inventory(accepted)
    samples: list[dict[str, object]] = [
        {
            "mode": "wtf-pad",
            "attempt": relative,
            "files": files,
            "files_sha256": buflo_study._canonical_digest(files),
        }
    ]
    return (
        root,
        application_path,
        projected_chaff_path,
        defenses,
        {"wtf-pad": relative},
        samples,
    )


def _multi_origin_attempt_ledgers(
    fixture: tuple[
        Path,
        Path,
        Path,
        tuple[SimpleNamespace, ...],
        dict[str, str],
        list[dict[str, object]],
    ],
) -> list[dict[str, object]]:
    return buflo_study._regression_multi_origin_attempt_ledgers(*fixture)


def test_regression_multi_origin_attempt_ledger_binds_rejection_before_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)

    [ledger] = _multi_origin_attempt_ledgers(fixture)

    assert ledger["mode"] == "wtf-pad"
    assert ledger["attempt_count"] == 2
    assert ledger["rejected_attempts"] == 1
    assert ledger["accepted_attempt"] == "attempts/wtf-pad/attempt-02"
    rejected, accepted = ledger["attempts"]
    assert rejected["outcome"] == "rejected"
    assert rejected["failure"] == {
        "source": "attempt.json",
        "details": {
            "stage": "capture",
            "reason": "direct/runner reconciliation failed",
        },
    }
    assert rejected["file_count"] == len(rejected["files"]) == 1
    assert accepted["outcome"] == "accepted"
    assert accepted["failure"] is None


def test_regression_multi_origin_attempt_ledger_rejects_tampered_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    original = _multi_origin_attempt_ledgers(fixture)
    attempt = fixture[0] / "attempts/wtf-pad/attempt-01/attempt.json"
    value = json.loads(attempt.read_text(encoding="utf-8"))
    value["failure"]["reason"] = "changed"
    attempt.write_text(json.dumps(value), encoding="utf-8")

    reconstructed = _multi_origin_attempt_ledgers(fixture)
    with pytest.raises(ValueError, match="attempt ledger changed"):
        buflo_study._validate_regression_multi_origin_attempt_ledger_receipt(
            original,
            reconstructed,
        )


def test_regression_multi_origin_attempt_ledger_rejects_deleted_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    (fixture[0] / "attempts/wtf-pad/attempt-01/attempt.json").unlink()

    with pytest.raises(ValueError, match="no terminal evidence"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_attempt_ledger_rejects_gap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    mode_root = fixture[0] / "attempts/wtf-pad"
    (mode_root / "attempt-01").rename(tmp_path / "detached-attempt")

    with pytest.raises(ValueError, match="not exact and contiguous"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_attempt_ledger_rejects_attempt_after_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    extra = fixture[0] / "attempts/wtf-pad/attempt-03"
    extra.mkdir()
    (extra / "attempt.json").write_text(
        json.dumps(
            {
                "success": False,
                "failure": {"stage": "capture", "reason": "late extra attempt"},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="outcomes are not terminal"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_attempt_ledger_rejects_missing_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    rejected = fixture[0] / "attempts/wtf-pad/attempt-01/attempt.json"
    rejected.write_text(json.dumps({"success": False}), encoding="utf-8")

    with pytest.raises(ValueError, match="lacks its reason"):
        buflo_study._regression_multi_origin_rejection_failure(rejected.parent)
    with pytest.raises(ValueError, match="lacks its reason"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_attempt_ledger_rejects_nonterminal_failure_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    rejected = fixture[0] / "attempts/wtf-pad/attempt-01/attempt.json"
    value = json.loads(rejected.read_text(encoding="utf-8"))
    value["success"] = True
    rejected.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="lacks its reason"):
        buflo_study._regression_multi_origin_rejection_failure(rejected.parent)
    with pytest.raises(ValueError, match="attempt outcomes are not terminal"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_attempt_ledger_rejection_marker_is_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    accepted = fixture[0] / "attempts/wtf-pad/attempt-02"
    reason = {
        "schema_version": 1,
        "artifact_type": buflo_study.MULTI_ORIGIN_COMPATIBILITY_ATTEMPT_ERROR_TYPE,
        "failure": {
            "stage": "multi-origin-compatibility-eligibility",
            "type": "ValueError",
            "message": "persisted terminal rejection",
        },
    }
    (accepted / "multi-origin-compatibility-error.json").write_text(
        json.dumps(reason),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="attempt outcomes are not terminal"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_attempt_ledger_rejects_special_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    special = fixture[0] / "attempts/wtf-pad/attempt-01/unbound-fifo"
    os.mkfifo(special)

    with pytest.raises(ValueError, match="special filesystem entry"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_existing_interrupted_attempt_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt = tmp_path / "attempt-01"
    attempt.mkdir()

    def rejected(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise ValueError("not eligible")

    monkeypatch.setattr(
        buflo_study,
        "_regression_multi_origin_attempt_evidence",
        rejected,
    )
    with pytest.raises(ValueError, match="lacks its reason"):
        buflo_study._regression_multi_origin_existing_attempt_evidence(
            attempt,
            tmp_path / "application.json",
            tmp_path / "chaff.json",
            SimpleNamespace(name="wtf-pad"),
            seed=1,
        )
    assert not (attempt / "multi-origin-compatibility-error.json").exists()


def test_regression_multi_origin_existing_terminal_rejection_is_resume_skipped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt = tmp_path / "attempt-01"
    attempt.mkdir()
    reason = {
        "schema_version": 1,
        "artifact_type": buflo_study.MULTI_ORIGIN_COMPATIBILITY_ATTEMPT_ERROR_TYPE,
        "failure": {
            "stage": "multi-origin-compatibility-collection",
            "type": "RuntimeError",
            "message": "collector failed",
        },
    }
    reason_path = attempt / "multi-origin-compatibility-error.json"
    reason_path.write_text(json.dumps(reason), encoding="utf-8")

    def otherwise_eligible(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {"passed": True}

    monkeypatch.setattr(
        buflo_study,
        "_regression_multi_origin_attempt_evidence",
        otherwise_eligible,
    )
    before = reason_path.read_bytes()
    assert (
        buflo_study._regression_multi_origin_existing_attempt_evidence(
            attempt,
            tmp_path / "application.json",
            tmp_path / "chaff.json",
            SimpleNamespace(name="wtf-pad"),
            seed=1,
        )
        is None
    )
    assert reason_path.read_bytes() == before


def test_v36_historical_candidate_schema_path_requires_exact_sealed_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = (
        tmp_path
        / "buflo-study-regression-v36"
        / "multi-origin-nine-mode-compatibility"
        / "receipt.json"
    )
    receipt.parent.mkdir(parents=True)
    receipt.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        buflo_study,
        "source_metadata",
        lambda: {
            **buflo_study.HISTORICAL_MULTI_ORIGIN_V36_SOURCE,
            "lab_commit": "0" * 40,
        },
    )
    monkeypatch.setattr(
        buflo_study,
        "sha256_file",
        lambda path: (
            buflo_study.HISTORICAL_MULTI_ORIGIN_V36_RECEIPT_SHA256
            if Path(path) == receipt
            else "0" * 64
        ),
    )

    selected = buflo_study._regression_multi_origin_historical_candidate_source(
        receipt,
        buflo_study.HISTORICAL_MULTI_ORIGIN_V36_SOURCE,
    )

    assert selected == buflo_study.HISTORICAL_MULTI_ORIGIN_V36_SOURCE
    with pytest.raises(ValueError, match="explicitly frozen source"):
        buflo_study._regression_multi_origin_historical_candidate_source(
            receipt,
            {
                **buflo_study.HISTORICAL_MULTI_ORIGIN_V36_SOURCE,
                "neqo_commit": "0" * 40,
            },
        )


def test_regression_multi_origin_checkpoint_binding_rejects_tamper_and_wrong_acceptance(
    tmp_path: Path,
) -> None:
    root = tmp_path / "compatibility"
    root.mkdir()
    checkpoint = root / "checkpoint.json"
    accepted = {
        mode: f"attempts/{mode}/attempt-01" for mode in buflo_study.MULTI_ORIGIN_COMPATIBILITY_MODES
    }
    value = {
        "schema_version": 1,
        "artifact_type": buflo_study.MULTI_ORIGIN_COMPATIBILITY_CHECKPOINT_TYPE,
        "accepted_attempts": accepted,
    }
    checkpoint.write_text(json.dumps(value), encoding="utf-8")
    binding = {
        "path": "checkpoint.json",
        "sha256": hashlib.sha256(checkpoint.read_bytes()).hexdigest(),
    }
    assert (
        buflo_study._regression_multi_origin_bound_path(
            root,
            binding,
            label="checkpoint",
        )
        == checkpoint.resolve()
    )
    assert (
        buflo_study._validate_regression_multi_origin_checkpoint(
            value,
            require_complete=True,
        )
        == accepted
    )

    value["accepted_attempts"]["wtf-pad"] = "attempts/front/attempt-01"
    checkpoint.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="checkpoint changed"):
        buflo_study._regression_multi_origin_bound_path(
            root,
            binding,
            label="checkpoint",
        )
    with pytest.raises(ValueError, match="checkpoint path is invalid"):
        buflo_study._validate_regression_multi_origin_checkpoint(
            value,
            require_complete=True,
        )


def test_regression_multi_origin_chaff_projection_changes_only_application_hash() -> None:
    strict = {
        "schema_version": 2,
        "application_workload_sha256": "1" * 64,
        "application_resource_id": 0,
        "selected_chaff_resource_id": 0,
        "resources": [{"id": 0, "url": "https://qcsd-buflo-server-one:4433/131072"}],
        "qualification_identity": {"sha256": "2" * 64},
    }
    original = json.loads(json.dumps(strict))

    projected = buflo_study._project_regression_chaff_manifest(
        strict,
        surrogate_sha256="1" * 64,
        application_sha256="3" * 64,
    )

    assert strict == original
    assert projected == {
        **original,
        "application_workload_sha256": "3" * 64,
    }


def test_regression_multi_origin_identity_retains_both_endpoints_and_all_resources_in_every_mode(
    tmp_path: Path,
) -> None:
    from qcsd_lab.fitting_walkie_talkie import receiver_continuation_contract

    manifest = _regression_multi_origin_identity_manifest()
    resources = manifest["resources"]
    preparation = manifest["preparation"]
    assert isinstance(resources, list) and isinstance(preparation, dict)
    expected = {response["resource_id"]: response for response in preparation["expected_responses"]}
    run = {
        "endpoints": [
            {"id": 0, "origin": "https://qcsd-buflo-server-one:4433"},
            {"id": 1, "origin": "https://qcsd-buflo-server-two:4434"},
        ],
        "responses": [
            {
                "resource_id": resource["id"],
                "url": resource["url"],
                "status": expected[resource["id"]]["status"],
                "bytes": expected[resource["id"]]["bytes"],
                "body_sha256": expected[resource["id"]]["body_sha256"],
                "complete": True,
                "outcome": "succeeded",
            }
            for resource in resources
        ],
    }

    source_value = buflo_study.load_json(LAB_ROOT / "config/defense-params/walkie-talkie-live.json")
    source_value.update(
        {
            "schema_version": 6,
            "generated_by": "qcsd-buflo-study-controlled-regression-v1",
            "receiver_continuation": receiver_continuation_contract(),
            "qualification_bindings": [
                {
                    "workload_id": "complex",
                    "chaff_qualification_sidecar_sha256": "1" * 64,
                    "prefix_pack_spec_sha256": "2" * 64,
                    "qualified_chaff_manifest_sha256": "3" * 64,
                    "application_resource_id": 0,
                    "selected_chaff_resource_id": 0,
                    "qualified_parallel_chaff_streams": 5,
                    "walkie_talkie_required_chaff_streams": 1,
                }
            ],
        }
    )
    source_path = tmp_path / "walkie-talkie-prefix-source.json"
    buflo_study.atomic_json(source_path, source_value)
    parameter_path = tmp_path / "walkie-talkie.json"
    provenance_path = tmp_path / "walkie-talkie.provenance.json"
    buflo_study._write_regression_multi_origin_walkie_talkie(
        source_path,
        parameter_path,
        provenance_path,
        application_sha256="a" * 64,
        projected_manifest_sha256="b" * 64,
    )
    defenses = buflo_study._regression_multi_origin_defenses(
        parameter_path,
        provenance_path,
        application_sha256="a" * 64,
    )
    evidence = [
        buflo_study._regression_multi_origin_run_identity(
            run,
            manifest,
            mode=defense.name,
        )
        for defense in defenses
    ]

    assert [row["mode"] for row in evidence] == list(buflo_study.MULTI_ORIGIN_COMPATIBILITY_MODES)
    assert [defense.kind for defense in defenses] == [
        "none",
        "static",
        "front",
        "tamaraw",
        "traffic_morphing",
        "wtf_pad",
        "walkie_talkie",
        "buflo",
        "cs_buflo",
    ]
    assert all(
        row["endpoint_coverage"]["observed_endpoint_count"] == 2
        and row["resource_ids"] == [0, 1, 2, 3]
        and {resource["origin"] for resource in row["resources"]}
        == set(buflo_study.MULTI_ORIGIN_COMPATIBILITY_ORIGINS)
        for row in evidence
    )

    missing = json.loads(json.dumps(run))
    missing["responses"].pop()
    with pytest.raises(ValueError, match="lost or duplicated"):
        buflo_study._regression_multi_origin_run_identity(
            missing,
            manifest,
            mode="walkie-talkie",
        )


@pytest.mark.parametrize(
    ("workload_id", "horizon", "survivors", "required_streams"),
    (("simple", 1, 2, 2), ("complex", 3, 4, 4)),
)
def test_regression_prefix_spec_uses_current_full_capacity_schema(
    tmp_path: Path,
    workload_id: str,
    horizon: int,
    survivors: int,
    required_streams: int,
) -> None:
    from qcsd_lab.chaff_qualification import validate_prefix_pack_spec

    manifest = _regression_prefix_manifest(workload_id)
    historical = json.loads(
        (LAB_ROOT / "config/defense-params/walkie-talkie-live.json").read_text(encoding="utf-8")
    )
    profile = buflo_study._current_regression_walkie_talkie_profile(
        next(profile for profile in historical["profiles"] if profile["real"] == workload_id),
        historical["packet_size"],
    )
    destination = tmp_path / f"{workload_id}.json"

    buflo_study._write_regression_prefix_spec(
        destination,
        workload_id,
        profile["bursts"],
        application_manifest=manifest,
    )

    value = json.loads(destination.read_text(encoding="utf-8"))
    validated = validate_prefix_pack_spec(
        value,
        workload_id=workload_id,
        application_manifest=manifest,
    )
    assert validated["numeric_profile"]["bursts"] == profile["bursts"]
    assert validated["application_resource_id"] == 0
    assert validated["selected_chaff_resource_id"] == 0
    assert validated["maximum_receiver_continuation_reserve_horizon"] == horizon
    assert validated["required_chaff_survivors"] == survivors
    assert validated["required_chaff_streams"] == required_streams
    assert len(validated["stream_activation_stages"]) == len(profile["bursts"])


def test_regression_prefix_spec_rejects_runtime_mould_drift(tmp_path: Path) -> None:
    manifest = _regression_prefix_manifest("simple")

    with pytest.raises(ValueError, match="differs from runtime mould"):
        buflo_study._write_regression_prefix_spec(
            tmp_path / "simple.json",
            "simple",
            [{"outgoing": 5, "incoming": 129}],
            application_manifest=manifest,
        )


def test_local_regression_prefix_spec_source_policy_is_fail_closed(tmp_path: Path) -> None:
    from qcsd_lab.chaff_qualification import validate_prefix_pack_spec

    manifest = _regression_prefix_manifest("simple")
    historical = json.loads(
        (LAB_ROOT / "config/defense-params/walkie-talkie-live.json").read_text(encoding="utf-8")
    )
    profile = buflo_study._current_regression_walkie_talkie_profile(
        next(profile for profile in historical["profiles"] if profile["real"] == "simple"),
        historical["packet_size"],
    )
    destination = tmp_path / "simple.json"
    buflo_study._write_regression_prefix_spec(
        destination,
        "simple",
        profile["bursts"],
        application_manifest=manifest,
    )
    value = json.loads(destination.read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="binding is invalid"):
        validate_prefix_pack_spec(value, workload_id="simple")

    outside = json.loads(json.dumps(value))
    outside["workload_id"] = "outside-local-regression"
    with pytest.raises(ValueError, match="binding is invalid"):
        validate_prefix_pack_spec(
            outside,
            workload_id="outside-local-regression",
            application_manifest=manifest,
        )

    source_tamper = json.loads(json.dumps(value))
    source_tamper["source_walkie_talkie_artifact_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="binding is invalid"):
        validate_prefix_pack_spec(
            source_tamper,
            workload_id="simple",
            application_manifest=manifest,
        )

    numeric_tamper = json.loads(json.dumps(value))
    numeric_tamper["numeric_profile"]["bursts"][0]["outgoing"] += 1
    with pytest.raises(ValueError, match="numeric derivation is invalid"):
        validate_prefix_pack_spec(
            numeric_tamper,
            workload_id="simple",
            application_manifest=manifest,
        )


def test_controlled_and_regression_generators_are_exact_and_unique() -> None:
    controlled = generated_stage_cells("controlled")
    regression = generated_stage_cells("regression")

    assert len(controlled) == 160
    assert len({json.dumps(cell, sort_keys=True) for cell in controlled}) == 160
    assert len(regression) == 18
    assert len({json.dumps(cell, sort_keys=True) for cell in regression}) == 18
    matrix = Counter(
        (cell["workload"], cell["treatment"], cell["netem_profile"]) for cell in controlled
    )
    assert set(matrix.values()) == {5}
    qdiscs = {
        cell["netem_profile"]: (cell["client_qdisc"], cell["server_qdisc"]) for cell in controlled
    }
    assert qdiscs == {
        "clean": ("none", "none"),
        "symmetric-50ms-rtt": ("netem delay 25ms", "netem delay 25ms"),
        "symmetric-5mbit-50ms-rtt-100-packet-queue": (
            "netem delay 25ms rate 5mbit limit 100",
            "netem delay 25ms rate 5mbit limit 100",
        ),
        "symmetric-1pct-loss-50ms-rtt": (
            "netem delay 25ms loss 1%",
            "netem delay 25ms loss 1%",
        ),
    }


def test_ctsp_cpsp_gate_requires_oracle_and_controlled_aggregate() -> None:
    proof = buflo_study._ctsp_cpsp_oracle_proof()
    assert proof["ctsp_greater_than_or_equal_cpsp"] is True
    assert {tuple((row["natural_bytes"], row["cover_bytes"])) for row in proof["anchors"]} == {
        (1_000, 24),
        (1_000, 1_100),
    }
    costs = {
        (profile, workload, visit): {
            "cs-buflo-ctsp": {"wire_bytes": 4_096, "udp_payload_bytes": 4_000},
            "cs-buflo-cpsp": {"wire_bytes": 3_072, "udp_payload_bytes": 3_000},
        }
        for profile in ("clean", "symmetric-50ms-rtt", "symmetric-rate-delay", "symmetric-loss")
        for workload in ("local-small", "local-large")
        for visit in range(5)
    }
    evidence = [f"{index:064x}" for index in range(4)]
    result = buflo_study._validate_ctsp_cpsp_ordering(
        costs,
        evidence_sha256s=evidence,
        explanation_receipt=None,
    )
    assert result["controlled_ctsp_greater_than_or_equal_cpsp"] is True
    assert result["reviewed_explanation"] is None

    changed = {
        key: {
            "cs-buflo-ctsp": {"wire_bytes": 2_000, "udp_payload_bytes": 2_000},
            "cs-buflo-cpsp": {"wire_bytes": 3_000, "udp_payload_bytes": 3_000},
        }
        for key in costs
    }
    with pytest.raises(ValueError, match="without a reviewed explanation"):
        buflo_study._validate_ctsp_cpsp_ordering(
            changed,
            evidence_sha256s=evidence,
            explanation_receipt=None,
        )

    # Preserve tuple keys while making one pair contrary and another pair large
    # enough that the aggregate alone would still pass.
    masked_costs = {
        key: {mode: dict(metrics) for mode, metrics in value.items()}
        for key, value in costs.items()
    }
    first, second = list(masked_costs)[:2]
    masked_costs[first]["cs-buflo-ctsp"] = {
        "wire_bytes": 2_000,
        "udp_payload_bytes": 2_000,
    }
    masked_costs[second]["cs-buflo-ctsp"] = {
        "wire_bytes": 8_192,
        "udp_payload_bytes": 8_000,
    }
    with pytest.raises(ValueError, match="paired result"):
        buflo_study._validate_ctsp_cpsp_ordering(
            masked_costs,
            evidence_sha256s=evidence,
            explanation_receipt=None,
        )


def test_sustained_capacity_gate_requires_all_clean_cells() -> None:
    values = [
        {
            "treatment": treatment,
            "workload": workload,
            "visit": visit,
            "capacity": {
                "passed": True,
                "cell_size_bytes": 1_200 if treatment == "buflo" else 600,
                "minimum_interval_us": (20_000 if treatment == "buflo" else 4_096),
                "outgoing_opportunities": 10,
                "incoming_opportunities": 10,
                "outgoing_full_cells": 10,
                "incoming_consumed_bytes": (12_000 if treatment == "buflo" else 6_000),
                "incoming_advertised_bytes": (12_000 if treatment == "buflo" else 6_000),
                "incoming_terminal_cells": 10,
                "incoming_consumption_delay_us_max": 1_000,
                "runner_full_extended_schema_validated": True,
                "runner_algorithm_evidence_sha256": "a" * 64,
                "minimum_interval_exercised": True,
                "exact_target_sizes": True,
                "no_unresolved_credit": True,
                **(
                    {
                        "terminal_subcell": {
                            "schema_version": 3,
                            "terminal_subcell_policy": (BUFLO_TERMINAL_SUBCELL_POLICY),
                            "terminal_subcell_observer_effect": (
                                BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT
                            ),
                            "control_evidence_semantics": (
                                "post-cancellation unscheduled packet composition "
                                "proves defense-control bytes but does not expose "
                                "individual QUIC frame identity"
                            ),
                            "terminal_latched": True,
                            "terminal_latched_at_us": 10_000_001,
                            "open_streams_at_latch": 1,
                            "stream_cancellations": 1,
                            "receipt_cancellations": 1,
                            "typed_cancellation_action_events": 1,
                            "pending_request_cancellations": 0,
                            "parser_lease_bytes_at_latch": 0,
                            "pending_parser_boundaries_at_latch": 1,
                            "pending_application_parser_boundaries_at_latch": 0,
                            "exact_capacity_bytes_cancelled": 1_199,
                            "whole_cell_floor_bytes": 1_200,
                            "first_cancellation_monotonic_us": 10_000_010,
                            "last_exact_outgoing_cell_monotonic_us": 9_999_990,
                            "last_scheduled_terminal_monotonic_us": 10_000_000,
                            "schedule_stop": {
                                "policy": BUFLO_SCHEDULE_STOP_POLICY,
                                "terminal_time_semantics": (
                                    BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS
                                ),
                                "latched": True,
                                "latched_at_us": 10_000_000,
                                "available_bytes": 1_199,
                                "required_bytes": 1_200,
                                "directions": {
                                    "outgoing": {
                                        "scheduled_cells_at_stop": 10,
                                        "terminal_cells_at_stop": 10,
                                        "drained_cells_after_stop": 0,
                                        "last_scheduled_target_us": 10_000_000,
                                        "last_terminal_at_us": 9_999_990,
                                        "terminal_cells_strictly_before_stop": 10,
                                        "terminal_cells_at_or_before_stop": 10,
                                        "terminal_cells_at_stop_timestamp": 0,
                                    },
                                    "incoming": {
                                        "scheduled_cells_at_stop": 10,
                                        "terminal_cells_at_stop": 9,
                                        "drained_cells_after_stop": 1,
                                        "last_scheduled_target_us": 10_000_000,
                                        "last_terminal_at_us": 10_000_001,
                                        "terminal_cells_strictly_before_stop": 9,
                                        "terminal_cells_at_or_before_stop": 9,
                                        "terminal_cells_at_stop_timestamp": 0,
                                    },
                                },
                            },
                            "post_cancellation_unscheduled_defense_control_packets": 1,
                            "post_cancellation_unscheduled_defense_control_bytes": 4,
                            "first_post_cancellation_defense_control_monotonic_us": 10_000_020,
                            "last_post_cancellation_defense_control_monotonic_us": 10_000_020,
                            "paper_equivalent": False,
                            "implementation_scope": "client_only_quic",
                        }
                    }
                    if treatment == "buflo"
                    else {}
                ),
                **(
                    {
                        f"{direction}_minimum_interval_{field}": 2
                        for direction in ("outgoing", "incoming")
                        for field in ("opportunities", "terminal", "full")
                    }
                    if treatment != "buflo"
                    else {}
                ),
                **(
                    {
                        "incoming_minimum_interval_local_realized": 2,
                        "incoming_local_realized_cells": 10,
                        "request_rate_driver_resource_id": (1 if workload == "local-small" else 4),
                        "request_rate_driver_request_stream_bytes": (
                            buflo_study.CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES
                        ),
                        "request_rate_driver_boundary_bytes": (
                            buflo_study.CSBUFLO_RATE_DRIVER_BOUNDARY_BYTES
                        ),
                        "request_rate_driver_post_boundary_cells": (
                            buflo_study.CSBUFLO_RATE_DRIVER_POST_BOUNDARY_CELLS
                        ),
                    }
                    if treatment != "buflo"
                    else {}
                ),
            },
        }
        for treatment in ("buflo", "cs-buflo-ctsp", "cs-buflo-cpsp")
        for workload in ("local-small", "local-large")
        for visit in range(5)
    ]
    proof = buflo_study._validate_sustained_cell_capacity(values)
    assert proof["samples"] == 30
    assert proof["profiles"]["buflo"]["cell_size_bytes"] == 1_200
    assert proof["profiles"]["buflo"]["terminal_subcell"]["schema_version"] == 3
    assert (
        proof["profiles"]["buflo"]["terminal_subcell"]["pending_parser_boundaries_at_latch"] == 10
    )
    assert (
        proof["profiles"]["buflo"]["terminal_subcell"][
            "pending_application_parser_boundaries_at_latch"
        ]
        == 0
    )
    assert (
        proof["profiles"]["buflo"]["terminal_subcell"]["exact_capacity_bytes_cancelled"]["maximum"]
        == 1_199
    )
    schedule_stop = proof["profiles"]["buflo"]["terminal_subcell"]["schedule_stop"]
    assert schedule_stop["policy"] == BUFLO_SCHEDULE_STOP_POLICY
    assert schedule_stop["terminal_time_semantics"] == BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS
    assert schedule_stop["latched_samples"] == 10
    assert schedule_stop["samples_with_incoming_drain"] == 10
    assert schedule_stop["directions"]["outgoing"]["drained_cells_after_stop"] == 0
    assert schedule_stop["directions"]["incoming"]["drained_cells_after_stop"] == 10
    assert proof["profiles"]["cs-buflo-ctsp"]["minimum_interval_us"] == 4_096
    for index, key, changed in (
        (0, "passed", False),
        (10, "incoming_minimum_interval_local_realized", 1),
        (20, "incoming_local_realized_cells", 9),
        (10, "incoming_advertised_bytes", 5_999),
        (10, "incoming_terminal_cells", 9),
        (10, "runner_full_extended_schema_validated", False),
        (10, "request_rate_driver_request_stream_bytes", 16_384),
        (10, "request_rate_driver_post_boundary_cells", 3),
    ):
        original = values[index]["capacity"][key]
        values[index]["capacity"][key] = changed
        with pytest.raises(ValueError, match="does not sustain"):
            buflo_study._validate_sustained_cell_capacity(values)
        values[index]["capacity"][key] = original

    tail = values[0]["capacity"]["terminal_subcell"]
    tail["parser_lease_bytes_at_latch"] = 1
    with pytest.raises(ValueError, match="does not sustain"):
        buflo_study._validate_sustained_cell_capacity(values)
    tail["parser_lease_bytes_at_latch"] = 0
    tail["pending_application_parser_boundaries_at_latch"] = 1
    with pytest.raises(ValueError, match="does not sustain"):
        buflo_study._validate_sustained_cell_capacity(values)
    tail["pending_application_parser_boundaries_at_latch"] = 0
    tail["pending_parser_boundaries_at_latch"] = 2
    with pytest.raises(ValueError, match="does not sustain"):
        buflo_study._validate_sustained_cell_capacity(values)
    tail["pending_parser_boundaries_at_latch"] = 1
    tail["schedule_stop"]["directions"]["outgoing"]["drained_cells_after_stop"] = 1
    with pytest.raises(ValueError, match="does not sustain"):
        buflo_study._validate_sustained_cell_capacity(values)
    tail["schedule_stop"]["directions"]["outgoing"]["drained_cells_after_stop"] = 0


def test_controlled_endpoint_gate_names_all_new_mode_two_origin_cells() -> None:
    endpoints = [
        {"id": 0, "origin": "https://qcsd-buflo-server-one:4433/"},
        {"id": 1, "origin": "https://qcsd-buflo-server-two:4434/"},
    ]
    coverage = buflo_study._controlled_endpoint_coverage(
        endpoints,
        workload="local-large",
    )
    assert coverage["observed_endpoint_count"] == 2
    assert coverage["passed"] is True

    values = [
        {
            "treatment": cell["treatment"],
            "workload": cell["workload"],
            "visit": cell["visit"],
            "netem_profile": cell["netem_profile"],
            "endpoint_coverage": coverage,
        }
        for cell in generated_stage_cells("controlled")
        if cell["workload"] == "local-large"
        and cell["treatment"] in {"buflo", "cs-buflo-ctsp", "cs-buflo-cpsp"}
    ]
    proof = buflo_study._validate_controlled_multi_endpoint_coverage(values)
    assert proof["samples"] == 60
    assert proof["treatments"] == {
        "buflo": 20,
        "cs-buflo-ctsp": 20,
        "cs-buflo-cpsp": 20,
    }
    assert proof["passed"] is True

    with pytest.raises(ValueError, match="all 60 cells"):
        buflo_study._validate_controlled_multi_endpoint_coverage(values[:-1])
    with pytest.raises(ValueError, match="exact expected endpoint set"):
        buflo_study._controlled_endpoint_coverage(
            [endpoints[0], {"id": 1, "origin": endpoints[0]["origin"]}],
            workload="local-large",
        )


@pytest.mark.parametrize("stage", ("controlled", "regression"))
def test_standard_campaign_receipt_maps_every_local_stage_cell_exactly(stage: str) -> None:
    plan = load_study_plan()
    treatments = (
        tuple(plan["controlled"]["treatments"])
        if stage == "controlled"
        else tuple(plan["regression"]["treatments"])
    )
    workload_aliases = (
        {"local-large": "local-large", "local-small": "local-small"}
        if stage == "controlled"
        else {"complex": "local-large", "simple": "local-small"}
    )
    actual_ids = tuple(workload_aliases)
    aliases_by_target = {target: source for source, target in workload_aliases.items()}
    cells = generated_stage_cells(stage)
    profile_ranks = (
        {profile["id"]: rank for rank, profile in enumerate(plan["controlled"]["netem_profiles"])}
        if stage == "controlled"
        else {"clean": 0}
    )

    for profile, rank in profile_ranks.items():
        selected = [cell for cell in cells if cell["netem_profile"] == profile]
        campaign = SimpleNamespace(
            workloads=tuple(SimpleNamespace(id=value) for value in actual_ids),
            study_controlled={
                "stage": stage,
                "treatment_order": treatments,
                "workload_aliases": workload_aliases,
                "netem_rank": rank,
                "netem_profile": profile,
                "client_qdisc": selected[0]["client_qdisc"],
                "server_qdisc": selected[0]["server_qdisc"],
            },
        )
        observed = {
            json.dumps(
                orchestrator._controlled_study_cell(
                    campaign,
                    {
                        "workload_id": aliases_by_target[cell["workload"]],
                        "visit": cell["visit"],
                        "defense": cell["treatment"],
                    },
                ),
                sort_keys=True,
            )
            for cell in selected
        }
        expected = {
            json.dumps(
                {key: value for key, value in cell.items() if key != "sample_index"},
                sort_keys=True,
            )
            for cell in selected
        }
        assert observed == expected


def test_public_campaigns_are_exact_and_formal_is_latin_balanced() -> None:
    all_campaigns = validate_campaign_matrix()
    formal = validate_campaign_matrix("formal")

    assert all_campaigns["samples"] == 1_560
    assert formal["samples"] == 1_500
    assert len(formal["campaigns"]) == 10
    assert formal["formal_position_counts"]
    assert all(
        max(counts) - min(counts) <= 1 for counts in formal["formal_position_counts"].values()
    )


def test_cohort_v2_resolves_create_only_campaign_without_mutating_v1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = LAB_ROOT / "config/campaigns/buflo-study-v1-smoke.yml"
    original = source.read_bytes()
    monkeypatch.setattr(buflo_study, "COHORT_INPUT_ROOT", tmp_path / "cohort-inputs")

    resolved = buflo_study.campaign_paths(
        "smoke",
        cohort_version=2,
        create_resolved=True,
    )[0]
    document = buflo_study.yaml.safe_load(resolved.read_text(encoding="utf-8"))

    assert resolved == tmp_path / "cohort-inputs/v2/campaigns" / source.name
    assert document["chaff_qualification_set"] == "buflo-study-public5-v2"
    assert source.read_bytes() == original
    assert resolved.read_bytes() == buflo_study._rendered_campaign_bytes(
        source,
        cohort_version=2,
    )
    resolved.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ValueError, match="deterministic source"):
        buflo_study.campaign_paths("smoke", cohort_version=2)


def test_pre_formal_snapshot_binds_selected_cohort_campaigns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(buflo_study, "COHORT_INPUT_ROOT", tmp_path / "cohort-inputs")
    monkeypatch.setattr(
        buflo_study,
        "source_metadata",
        lambda: {"source": "test", "image_digest": "sha256:" + "a" * 64},
    )
    monkeypatch.setattr(buflo_study, "_validate_clean_source", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        buflo_study,
        "validate_historical_corpus_guard",
        lambda *args, **kwargs: {"passed": True},
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_build_execution_receipt",
        lambda *args, **kwargs: {
            "path": str(tmp_path / "build-execution-v2.json"),
            "sha256": "a" * 64,
            "schema_version": 5,
            "cohort_version": 2,
            "completion_path": str(tmp_path / "build-completion-v2.json"),
            "completion_sha256": "b" * 64,
            "collection_image": "sha256:" + "c" * 64,
            "started_at": "2026-09-01T00:00:00+00:00",
            "finished_at": "2026-09-01T00:01:00+00:00",
        },
    )

    snapshot = buflo_study._historical_snapshot_value(
        phase="pre-formal",
        cohort_version=2,
        create_resolved_campaigns=True,
    )

    assert snapshot["cohort_version"] == 2
    assert snapshot["schema_version"] == 2
    assert snapshot["build_execution"]["completion_sha256"] == "b" * 64
    assert snapshot["qualification_set"] == "buflo-study-public5-v2"
    assert len(snapshot["formal_campaigns"]) == 10
    assert all(
        "/cohort-inputs/v2/campaigns/" in row["path"] for row in snapshot["formal_campaigns"]
    )


def test_live_parameters_bind_scope_modes_sampling_and_guard() -> None:
    assert len(validate_parameters()) == 3
    buflo = json.loads((LAB_ROOT / "config/defense-params/buflo-live.json").read_text())
    ctsp = json.loads((LAB_ROOT / "config/defense-params/cs-buflo-ctsp-live.json").read_text())
    cpsp = json.loads((LAB_ROOT / "config/defense-params/cs-buflo-cpsp-live.json").read_text())
    assert buflo == {
        "schema_version": 1,
        "interval_us": 20_000,
        "minimum_duration_us": 10_000_000,
        "packet_size": 1_200,
        "max_events": 6_000,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
    }
    assert buflo["interval_us"] * buflo["max_events"] == 120_000_000
    common = {
        "incoming_padding_mode": "payload",
        "timing_sample_limit": 1_000,
        "jitter_denominator": 100,
        "jitter_max_numerator": 200,
        "early_termination": "local",
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
    }
    assert {key: ctsp[key] for key in common} == common
    assert {key: cpsp[key] for key in common} == common
    assert ctsp["outgoing_padding_mode"] == "total"
    assert cpsp["outgoing_padding_mode"] == "payload"


def test_reference_action_cannot_bypass_isolated_create_only_gate(tmp_path: Path) -> None:
    result = run_study_action(
        "reference",
        reference_root=tmp_path,
        destination=tmp_path / "receipt.json",
    )

    assert result.status == "blocked"
    assert any("network-isolated reference image" in blocker for blocker in result.blockers)
    assert not (tmp_path / "receipt.json").exists()


def test_executed_reference_receipt_semantically_binds_all_oracles_and_sources(
    tmp_path: Path,
) -> None:
    execution = _reference_execution_fixture(tmp_path)
    with pytest.raises(ValueError, match="schema 2 and build completion"):
        validate_reference_gate_receipt(execution)
    receipt = validate_reference_gate_receipt(execution, allow_historical=True)

    assert receipt["profiles_checked"] == 8
    assert receipt["archive"] == {
        "total_records": 4_000,
        "included_records": 3_824,
        "zero_baseline_records": 176,
        "defended_bytes": 7_592_598_380,
        "baseline_bytes": 3_326_013_453,
        "excluded_defended_bytes": 18_656_832,
    }
    assert receipt["sha256"] == hashlib.sha256(execution.read_bytes()).hexdigest()
    assert "dyer-paper-pdf" in receipt["external_sources"]
    assert "csbuflo-preprint-pdf" in receipt["external_sources"]


def test_reference_gate_accepts_a_fully_validated_schema_two_build(
    tmp_path: Path,
) -> None:
    execution = _reference_execution_fixture(tmp_path, build_schema_version=2)

    receipt = validate_reference_gate_receipt(execution, allow_historical=True)

    assert receipt["build_execution"]["cohort_version"] == 1
    assert receipt["profiles_checked"] == 8


@pytest.mark.parametrize("deep", [None, False, True])
def test_checked_in_v20_reference_and_code_gate_remain_historically_verifiable(
    monkeypatch: pytest.MonkeyPatch, deep: bool | None,
) -> None:
    reference = LAB_ROOT / "artifacts/buflo-study/reference-execution-v20.json"
    code_gate = LAB_ROOT / "artifacts/buflo-study/code-gate-v20.json"

    def unexpected_execution():
        pytest.fail("historical receipt verification must not execute current tests")

    monkeypatch.setattr(buflo_study, "_run_lab_code_gate_commands", unexpected_execution)
    with pytest.raises(ValueError, match="current reference admission requires schema 2"):
        validate_reference_gate_receipt(reference)
    with pytest.raises(ValueError, match="current code-gate admission requires schema 2"):
        buflo_study.validate_code_gate_receipt(code_gate, deep=False)

    historical_reference = validate_reference_gate_receipt(
        reference, allow_historical=True
    )
    historical_code_gate = buflo_study.validate_code_gate_receipt(
        code_gate,
        allow_historical=True,
        **({} if deep is None else {"deep": deep}),
    )

    assert historical_reference["build_execution"]["cohort_version"] == 20
    assert historical_code_gate["cohort_version"] == 20
    assert historical_code_gate["live_regression"]["samples"] == 18


def test_bumped_outer_receipts_require_explicit_historical_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = {
        "image_digest": "sha256:" + "a" * 64,
        "lab_commit": "b" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": buflo_study.EMPTY_SHA256,
        "neqo_commit": "c" * 40,
        "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": buflo_study.EMPTY_SHA256,
    }
    fixtures = {
        "qualification": (
            buflo_study.validate_qualification_receipt,
            buflo_study._qualification_receipt_value,
            {
                "schema_version": 1,
                "cohort_version": 20,
                "source": source,
                "controlled_results": {"results": []},
            },
            "current qualification admission requires schema 2",
            {},
        ),
        "snapshot": (
            buflo_study.validate_historical_guard_snapshot,
            buflo_study._historical_snapshot_value,
            {
                "schema_version": 1,
                "cohort_version": 20,
                "source": source,
                "formal_results": [],
            },
            "current historical-snapshot admission requires schema 2",
            {"phase": "pre-formal"},
        ),
        "cohort": (
            buflo_study.validate_formal_cohort_manifest,
            buflo_study._formal_cohort_value,
            {
                "schema_version": 2,
                "cohort_version": 20,
                "cohort_id": "buflo-study-formal-v20",
                "source": source,
                "results_root": str(tmp_path / "results"),
                "historical_pre_formal_snapshot": {"path": str(tmp_path / "pre.json")},
                "formal_campaigns": [],
            },
            "current formal-cohort admission requires schema 3",
            {},
        ),
        "admission": (
            buflo_study.validate_capture_admission,
            buflo_study._capture_admission_value,
            {
                "schema_version": 3,
                "cohort_version": 20,
                "stage": "formal",
                "reference_gate": {"path": str(tmp_path / "reference.json")},
                "qualification": {"path": str(tmp_path / "qualification.json")},
                "staged_prerequisites": {"regression": {"results": []}, "public": {}},
                "results_root": str(tmp_path / "results"),
                "historical_pre_formal_snapshot": None,
                "formal_cohort": None,
                "code_gate": None,
                "formal_capacity": None,
                "allowed_campaigns": [],
            },
            "current capture admission requires schema 4",
            {},
        ),
    }
    for name, (validator, derivation, value, message, kwargs) in fixtures.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            validator(path, **kwargs)
        monkeypatch.setattr(
            buflo_study,
            derivation.__name__,
            lambda *_args, **_kwargs: value,
        )
        assert validator(path, allow_historical=True, **kwargs)["schema_version"] == value[
            "schema_version"
        ]


def test_executed_reference_receipt_rejects_self_declared_source_substitution(
    tmp_path: Path,
) -> None:
    canonical = (
        LAB_ROOT / "config/reference/buflo-csbuflo/buflo-csbuflo-conformance-v1.receipt.json"
    )
    value = json.loads(canonical.read_text(encoding="utf-8"))
    by_id = {source["source_id"]: source for source in value["external_sources"]}
    assert by_id["csbuflo-clientloop-c"]["sha256"] == (
        "6f0148c8891756e39980edf47f2d5fbc254d2da7b4a8096a678cf3bb7777a36e"
    )
    assert by_id["csbuflo-serverloop-c"]["sha256"] == (
        "abc798cecb918d5c89ccec825224d543862e95a9650334bb0b5d4dd99e17a3a9"
    )
    by_id["csbuflo-clientloop-c"]["sha256"] = "0" * 64
    substituted = tmp_path / "substituted-reference-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="immutable checked-in oracle"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    value = json.loads(canonical.read_text(encoding="utf-8"))
    by_id = {source["source_id"]: source for source in value["external_sources"]}
    by_id["csbuflo-serverloop-c"]["url"] = by_id["csbuflo-serverloop-c"]["url"].replace(
        "serverloop.c", "clientloop.c"
    )
    substituted = tmp_path / "substituted-reference-url-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="immutable checked-in oracle"):
        buflo_study._validate_canonical_reference_receipt(substituted)


def test_executed_reference_receipt_recomputes_slice_aggregate_and_golden_vectors(
    tmp_path: Path,
) -> None:
    canonical = buflo_study.CONFORMANCE_RECEIPT
    value = json.loads(canonical.read_text(encoding="utf-8"))
    slices = value["csbuflo_author_conformance"]["source_extraction"]["segment_sha256"]
    slices["jitter_function"] = "0" * 64
    substituted = tmp_path / "substituted-slice-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="source-slice inventory"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    value = json.loads(canonical.read_text(encoding="utf-8"))
    value["csbuflo_author_conformance"]["source_extraction_input_sha256"] = "0" * 64
    substituted = tmp_path / "substituted-slice-aggregate-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="source-slice aggregate"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    value = json.loads(canonical.read_text(encoding="utf-8"))
    value["csbuflo_author_conformance"]["golden_vectors"]["jitter"]["raw_1"] = 82
    substituted = tmp_path / "substituted-golden-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="author harness"):
        buflo_study._validate_canonical_reference_receipt(substituted)


def test_executed_reference_receipt_binds_rate_quantization_discrepancy(
    tmp_path: Path,
) -> None:
    canonical = buflo_study.CONFORMANCE_RECEIPT
    value = json.loads(canonical.read_text(encoding="utf-8"))
    discrepancy = value["csbuflo_paper_internal_discrepancies"][0]
    discrepancy["paper_prose_rule"] = "round-down-rho-to-a-power-of-two"
    substituted = tmp_path / "substituted-rate-discrepancy-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="paper-internal discrepancy"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    value = json.loads(canonical.read_text(encoding="utf-8"))
    value["csbuflo_estimator_contract"]["rate_quantization_resolution"] = "paper-prose-round-up"
    substituted = tmp_path / "substituted-rate-resolution-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="estimator contract"):
        buflo_study._validate_canonical_reference_receipt(substituted)


def test_executed_reference_receipt_recomputes_archive_ratio_and_byte_hash(
    tmp_path: Path,
) -> None:
    canonical = buflo_study.CONFORMANCE_RECEIPT
    value = json.loads(canonical.read_text(encoding="utf-8"))
    value["csbuflo_archive_conformance"]["bandwidth_ratio"] = 2.28279
    substituted = tmp_path / "substituted-archive-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="archive conformance"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    whitespace_changed = tmp_path / "whitespace-changed-receipt.json"
    whitespace_changed.write_text(canonical.read_text(encoding="utf-8") + " ", encoding="utf-8")
    assert json.loads(whitespace_changed.read_text(encoding="utf-8")) == json.loads(
        canonical.read_text(encoding="utf-8")
    )
    assert hashlib.sha256(whitespace_changed.read_bytes()).hexdigest() != (
        buflo_study.CONFORMANCE_RECEIPT_SHA256
    )
    with pytest.raises(ValueError, match="receipt SHA-256"):
        buflo_study._validate_canonical_reference_receipt(whitespace_changed)


def test_reference_execution_rejects_static_or_copied_canonical_receipt(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="execution receipt identity"):
        validate_reference_gate_receipt(buflo_study.CONFORMANCE_RECEIPT)
    copied = tmp_path / "copied-canonical.json"
    copied.write_bytes(buflo_study.CONFORMANCE_RECEIPT.read_bytes())
    with pytest.raises(ValueError, match="execution receipt identity"):
        validate_reference_gate_receipt(copied)


def test_reference_execution_receipt_rejects_tamper(tmp_path: Path) -> None:
    execution = _reference_execution_fixture(tmp_path)
    value = json.loads(execution.read_text(encoding="utf-8"))
    value["isolation"]["docker_network_mode"] = "bridge"
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)
    execution.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="isolation evidence"):
        validate_reference_gate_receipt(execution, allow_historical=True)


def test_staged_capture_rejects_missing_exact_prior_cohorts() -> None:
    with pytest.raises(ValueError, match="exact prerequisite set"):
        validate_staged_capture_prerequisites("formal", ())


def test_formal_capacity_requires_12_5_hours_and_threefold_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged = {
        "public": {
            "smoke": {
                "samples": 20,
                "authoritative_bytes": 20_000,
                "elapsed_seconds": 600,
            },
            "rehearsal": {
                "samples": 40,
                "authoritative_bytes": 40_000,
                "elapsed_seconds": 1_200,
            },
        }
    }
    monkeypatch.setattr(
        buflo_study.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=4_500_000),
    )

    capacity = validate_formal_capture_capacity(
        staged,
        available_window_hours=12.5,
        results_root=tmp_path,
    )

    assert capacity["minimum_sequential_cooldown_seconds"] == 45_000
    assert capacity["measured_projection_seconds"] == 45_000
    assert capacity["expected_formal_wall_seconds"] == 45_000
    assert capacity["projected_formal_bytes"] == 1_500_000
    assert capacity["required_free_bytes"] == 4_500_000
    with pytest.raises(ValueError, match="at least 12.5"):
        validate_formal_capture_capacity(
            staged,
            available_window_hours=12.49,
            results_root=tmp_path,
        )


def test_first_formal_block_uses_frozen_projected_storage_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = tmp_path / "buflo-study-v1-formal-01.yml"
    campaign.write_text("name: buflo-study-v1-formal-01\n", encoding="utf-8")
    result_root = tmp_path / "results" / "buflo-study-v1-formal-01"
    admission_value = {
        "stage": "formal",
        "results_root": str(tmp_path / "results"),
        "allowed_campaigns": [
            {
                "campaign_path": str(campaign.resolve()),
                "campaign_sha256": buflo_study.sha256_file(campaign),
                "result_root": str(result_root),
            }
        ],
        "formal_capacity": {"projected_formal_bytes": 1_000_000},
    }
    monkeypatch.setattr(
        buflo_study,
        "validate_capture_admission",
        lambda _admission: admission_value,
    )
    disk_probes: list[Path] = []
    monkeypatch.setattr(
        buflo_study.shutil,
        "disk_usage",
        lambda path: (disk_probes.append(Path(path)), SimpleNamespace(free=3_000_000))[1],
    )

    assert (
        buflo_study.admitted_result_root(
            tmp_path / "admission.json", campaign, require_sequence=True
        )
        == result_root
    )
    assert disk_probes == [tmp_path / "results"]


def test_capture_admission_rejects_cohort_mismatch_before_replay(tmp_path: Path) -> None:
    admission = tmp_path / "capture-admission.json"
    admission.write_text(json.dumps({"cohort_version": 2}), encoding="utf-8")

    with pytest.raises(ValueError, match="cohort version does not match"):
        buflo_study.validate_capture_admission(
            admission,
            expected_cohort_version=1,
        )


def test_v15_formal_capture_admission_requires_code_gate_before_freeze_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = {"image_digest": "sha256:" + "a" * 64}
    build = {
        "path": "build.json",
        "sha256": "b" * 64,
        "schema_version": 5,
        "cohort_version": 15,
        "completion_path": "/tmp/build-completion-v15.json",
        "completion_sha256": "c" * 64,
        "collection_image": source["image_digest"],
        "started_at": "2026-08-27T00:00:00+00:00",
        "finished_at": "2026-08-27T00:01:00+00:00",
    }
    identity = {
        "cohort_version": 15,
        "sha256": build["sha256"],
        "completion_path": "/lab/artifacts/buflo-study/build-completion-v15.json",
        "completion_sha256": build["completion_sha256"],
        "collection_image": build["collection_image"],
        "started_at": build["started_at"],
        "finished_at": build["finished_at"],
    }
    scheduler = buflo_study._capture_scheduler_environment_contract()
    environment = {
        "schema_version": 3,
        "capture_scheduler": scheduler,
        "docker": {"ncpu": 12},
    }
    regression = {"results": [{"root": "regression", "environment": environment}]}
    staged = {
        "source": source,
        "regression": regression,
        "public": {
            "smoke": {"root": "smoke", "environment": environment},
            "rehearsal": {"root": "rehearsal", "environment": environment},
        },
    }
    qualification = {
        "source": source,
        "build_execution": {"path": build["path"], "sha256": build["sha256"]},
        "controlled_results": {"results": [{"environment": environment}]},
    }
    monkeypatch.setattr(
        buflo_study,
        "validate_reference_gate_receipt",
        lambda *_args, **_kwargs: {"build_execution": identity},
    )
    monkeypatch.setattr(
        buflo_study, "validate_qualification_receipt", lambda *_args, **_kwargs: qualification
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_staged_capture_prerequisites",
        lambda *_args, **_kwargs: staged,
    )
    monkeypatch.setattr(
        buflo_study, "validate_build_execution_receipt", lambda *_args, **_kwargs: build
    )
    monkeypatch.setattr(
        buflo_study,
        "_one_build_execution_identity",
        lambda _values, **_kwargs: identity,
    )
    results_root = tmp_path / "results"
    results_root.mkdir()

    with pytest.raises(ValueError, match="validated code-gate receipt"):
        buflo_study._capture_admission_value(
            stage="formal",
            reference_receipt=tmp_path / "reference.json",
            qualification_receipt=tmp_path / "qualification.json",
            prerequisite_result_roots=(),
            results_root=results_root,
            formal_cohort_manifest=tmp_path / "cohort.json",
            historical_pre_snapshot=tmp_path / "pre.json",
            cohort_version=15,
        )

    pre = tmp_path / "pre.json"
    cohort_path = tmp_path / "cohort.json"
    code_path = tmp_path / "code-gate.json"
    for path in (pre, cohort_path, code_path):
        path.write_text("{}\n", encoding="utf-8")
    code_gate = {
        **buflo_study._file_binding(code_path),
        "source": source,
        "build_execution_receipt": {"path": build["path"], "sha256": build["sha256"]},
        "live_regression": regression,
    }
    monkeypatch.setattr(
        buflo_study, "validate_code_gate_receipt", lambda *_args, **_kwargs: code_gate
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_historical_guard_snapshot",
        lambda *_args, **_kwargs: {"source": source},
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_formal_cohort_manifest",
        lambda *_args, **_kwargs: {
            "cohort_version": 15,
            "qualification_set": "buflo-study-public5-v15",
            "source": source,
            "historical_pre_formal_snapshot": buflo_study._file_binding(pre),
            "results_root": str(results_root.resolve()),
            "formal_campaigns": [],
            "formal_evaluation": buflo_study.FORMAL_BOOTSTRAP_CONTRACT,
        },
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_formal_capture_capacity",
        lambda *_args, **_kwargs: {"available_window_hours": 12.5},
    )
    admitted = buflo_study._capture_admission_value(
        stage="formal",
        reference_receipt=tmp_path / "reference.json",
        qualification_receipt=tmp_path / "qualification.json",
        prerequisite_result_roots=(),
        results_root=results_root,
        formal_cohort_manifest=cohort_path,
        historical_pre_snapshot=pre,
        code_gate_receipt=code_path,
        formal_window_hours=12.5,
        cohort_version=15,
    )
    assert admitted["schema_version"] == 4
    assert admitted["code_gate"] == code_gate


def test_formal_prelaunch_estimate_is_visible_only_on_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    buflo_study._report_frozen_formal_prelaunch(
        {
            "expected_formal_wall_hours": 12.5,
            "conservative_upper_seconds": 50_400,
            "projected_formal_bytes": 1_500_000,
            "required_free_bytes": 4_500_000,
        }
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "expected=12.500h" in captured.err
    assert "3x_required=4500000 bytes" in captured.err


def test_attestation_destination_cannot_overlap_result_inputs(tmp_path: Path) -> None:
    result_root = tmp_path / "formal-result"
    result_root.mkdir()
    with pytest.raises(ValueError, match="overlaps protected input"):
        buflo_study.create_validation_attestation(
            result_root / "attestation.json",
            formal_result_roots=(result_root,),
        )


def test_qualification_rejects_sidecar_from_non_prepare_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from qcsd_lab import chaff_qualification

    qualification_root = tmp_path / "sets"
    selected = qualification_root / "buflo-study-public5-v2"
    selected.mkdir(parents=True)
    for workload in buflo_study.WORKLOADS:
        (selected / f"{workload}.json").write_text(
            json.dumps({"qualification_image_digest": "sha256:" + "e" * 64}),
            encoding="utf-8",
        )
    monkeypatch.setattr(buflo_study, "QUALIFICATION_SET_ROOT", qualification_root)
    monkeypatch.setattr(
        buflo_study,
        "_qualification_build_binding",
        lambda *_args, **_kwargs: (
            {"path": "build.json", "sha256": "f" * 64},
            "sha256:" + "d" * 64,
        ),
    )
    monkeypatch.setattr(chaff_qualification, "load_response_qualified_chaff", lambda *a, **k: None)

    ready, status = buflo_study.qualification_status(
        require_controlled=False,
        cohort_version=2,
    )
    assert ready is False
    assert "exact no-cache prepare image" in status


def test_launcher_requires_clean_capture_image_and_no_cache_build() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")

    assert 'verify_qualification_checkout "buflo-study capture"' in launcher
    assert 'verify_qualification_checkout "buflo study campaign run"' in launcher
    direct_run_guard = launcher.split('verify_qualification_checkout "buflo-study capture"', 1)[
        1
    ].split('verify_qualification_checkout "buflo-study qualify"', 1)[0]
    assert '"${1:-}" == "run"' in direct_run_guard
    assert "buflo-study-v1-(smoke|rehearsal|formal-[0-9]{2})" in direct_run_guard
    assert '"${1:-}" == "resume"' not in direct_run_guard
    supervised_build = (
        'qcsd_run_docker_build docker --context "${build_docker_context}" build --pull --no-cache'
    )
    assert launcher.count(supervised_build) == 3
    assert not re.search(
        r"^\s*docker --context \"\$\{build_docker_context\}\" build ",
        launcher,
        flags=re.MULTILINE,
    )
    assert "WSL_HOST_BUILD_MIN_AVAILABLE_BYTES=68719476736" in launcher
    assert launcher.count('wsl_host_build_storage_probe "') == 4
    assert "windows_docker_storage_probe.ps1" in launcher
    assert '"schema_version": 5' in launcher
    assert '"cohort_allocation": cohort_allocation_authority["receipt"]' in launcher
    assert '"host_storage_preflight": host_storage' in launcher
    assert '"buildx": buildx' in launcher
    assert launcher.count('capture_buildx_observation "') == 4
    assert launcher.count("buildx-observation") == 1
    for boundary in (
        "before-collection",
        "after-collection",
        "after-prepare",
        "after-reference",
    ):
        assert f'capture_buildx_observation "{boundary}"' in launcher
    build_receipt_invocation = '"${ROOT}/src/qcsd_lab/build_storage.py" receipt'
    assert len(
        re.findall(re.escape(build_receipt_invocation) + r"\s+\\$", launcher, re.MULTILINE)
    ) == 5
    selected_pair = launcher.index(
        'study_build_completion_payload_sha256="${study_build_fields[6]}"'
    )
    first_generic_docker = launcher.index(
        'if [[ "${qcsd_deferred_generic_docker:-0}" == "1" ]]'
    )
    assert selected_pair < first_generic_docker
    generic_branch = launcher.split(
        'elif [[ "${1:-}" != "class-study" && "${1:-}" != "etf-probe" ]]; then',
        1,
    )[1].split("\nfi", 1)[0]
    assert "qcsd_deferred_generic_docker=1" in generic_branch
    assert "require_docker" not in generic_branch
    for admitted_fields in (
        "study_build_fields",
        "pinned_cdp_build_fields",
        "browser_egress_build_fields",
        "class_build_fields",
    ):
        assert re.search(
            rf"mapfile -t {admitted_fields} < <\(\s+python3 -I "
            rf"\"\$\{{ROOT\}}/src/qcsd_lab/build_storage\.py\" receipt",
            launcher,
        )
    assert "validate_build_execution_envelope" in launcher
    assert launcher.count('--iidfile "${') == 3
    assert "acquire_evidence_build_lock" in launcher
    assert "reject_evidence_build_image_overrides" in launcher
    assert "reject_docker_endpoint_overrides" in launcher
    assert launcher.count("validate_local_docker_build_endpoint") == 6
    assert "artifacts/buflo-study/build-execution-v${study_cohort_version}.json" in launcher
    assert '"artifact_type": "qcsd-buflo-study-no-cache-build-execution"' in launcher
    assert '"build_execution": {' in launcher
    assert 'QCSD_STUDY_BUILD_EXECUTION="${study_build_execution}"' not in launcher
    assert 'QCSD_STUDY_BUILD_COMPLETION="${study_build_completion}"' not in launcher
    assert 'QCSD_STUDY_ENVIRONMENT_B64=${study_environment_b64}' not in launcher
    assert launcher.count(
        'QCSD_STUDY_ENVIRONMENT_PATH=${study_environment_container_path}'
    ) == 2
    assert launcher.count(
        '${study_environment_host_path}:${study_environment_container_path}:ro'
    ) == 2


def test_study_environment_file_transport_exceeds_linux_single_string_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = tmp_path / "study-environment.json"
    raw = b'{"padding":"' + (b"x" * 200_000) + b'"}'
    assert len(raw) > 131_072
    receipt.write_bytes(raw)
    receipt.chmod(0o600)
    monkeypatch.setattr(buflo_study, "STUDY_ENVIRONMENT_CONTAINER_PATH", receipt)
    monkeypatch.setenv(buflo_study.STUDY_ENVIRONMENT_PATH_ENV, str(receipt))
    monkeypatch.delenv(buflo_study.STUDY_ENVIRONMENT_LEGACY_B64_ENV, raising=False)

    assert buflo_study._study_environment_transport_bytes() == raw


def test_study_environment_transport_rejects_multiple_sources_and_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = tmp_path / "study-environment.json"
    receipt.write_text("{}", encoding="utf-8")
    receipt.chmod(0o600)
    monkeypatch.setattr(buflo_study, "STUDY_ENVIRONMENT_CONTAINER_PATH", receipt)
    monkeypatch.setenv(buflo_study.STUDY_ENVIRONMENT_PATH_ENV, str(receipt))
    monkeypatch.setenv(
        buflo_study.STUDY_ENVIRONMENT_LEGACY_B64_ENV,
        base64.b64encode(b"{}").decode("ascii"),
    )
    with pytest.raises(ValueError, match="multiple transports"):
        buflo_study._study_environment_transport_bytes()

    link = tmp_path / "study-environment-link.json"
    link.symlink_to(receipt)
    monkeypatch.setattr(buflo_study, "STUDY_ENVIRONMENT_CONTAINER_PATH", link)
    monkeypatch.setenv(buflo_study.STUDY_ENVIRONMENT_PATH_ENV, str(link))
    monkeypatch.delenv(buflo_study.STUDY_ENVIRONMENT_LEGACY_B64_ENV)
    with pytest.raises(ValueError, match="file is unavailable"):
        buflo_study._study_environment_transport_bytes()

    monkeypatch.setattr(buflo_study, "STUDY_ENVIRONMENT_CONTAINER_PATH", receipt)
    monkeypatch.setenv(buflo_study.STUDY_ENVIRONMENT_PATH_ENV, str(receipt))
    receipt.chmod(0o644)
    with pytest.raises(ValueError, match="file is unsafe"):
        buflo_study._study_environment_transport_bytes()

    receipt.chmod(0o600)
    hard_link = tmp_path / "study-environment-hard-link.json"
    hard_link.hardlink_to(receipt)
    with pytest.raises(ValueError, match="file is unsafe"):
        buflo_study._study_environment_transport_bytes()


def test_launcher_removes_exact_study_environment_transport() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")
    cleanup = (
        "remove_study_environment_transport() {"
        + launcher.split("remove_study_environment_transport() {", 1)[1].split(
            "\n}\n\ncleanup_study_environment_transport_on_exit()", 1
        )[0]
        + "\n}\n"
    )
    completed = subprocess.run(
        [
            "bash",
            "-c",
            f"""
set -euo pipefail
{cleanup}
study_environment_transport_dir="$(
  mktemp -d --tmpdir=/tmp qcsd-study-environment.XXXXXXXX
)"
study_environment_host_path="${{study_environment_transport_dir}}/study-environment.json"
: >"${{study_environment_host_path}}"
chmod 600 "${{study_environment_host_path}}"
saved_directory="${{study_environment_transport_dir}}"
remove_study_environment_transport
test ! -e "${{saved_directory}}"
test -z "${{study_environment_transport_dir}}"
test -z "${{study_environment_host_path}}"
""",
        ],
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert completed.returncode == 0, completed.stderr


def test_launcher_applies_least_privilege_rr1_capture_partition() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")
    entrypoint = (LAB_ROOT / "docker/collection-entrypoint").read_text(encoding="utf-8")
    network_probe = launcher.split("buflo_namespace_evidence()", 1)[1].split(
        "buflo_controlled_evidence_base64()", 1
    )[0]

    assert (
        'study_capture_scheduler_contract="qcsd-client-rr1-cpu10-etf-helper-cpu11-v1"' in launcher
    )
    assert 'runtime+=(--cpuset-cpus "10-11" --ulimit "rtprio=1:1")' in launcher
    assert "--cpuset-cpus 10-11" in launcher
    assert "--ulimit rtprio=1:1" in launcher
    assert "_qcsd_docker_api ps --format '{{.ID}}'" in launcher
    assert "docker-inspect-all-running-containers-prelaunch-v1" in launcher
    assert "docker-inspect-all-running-containers-prelaunch-v2" in launcher
    assert "QCSD_CAPTURE_ETF_INTERFACE=eth0" in launcher
    assert "QCSD_KERNEL_TX_POST_VETH_CAPTURE_ENDPOINT" in launcher
    assert "buflo_kernel_tx_observer_binding_base64()" in launcher
    assert "QCSD_KERNEL_TX_CONTROLLED_OBSERVER_BINDING_B64" in launcher
    assert "qcsd-kernel-tx-controlled-observer-binding" in launcher
    assert "router-eth0-ingress-after-client-veth-before-ifb0-ingress-netem" in launcher
    assert "controlled kernel-TX router did not reach the idle end state" in launcher
    assert "kernel-TX post-veth capture root contains stale evidence" in launcher
    assert "container_set_matches_expected = expected_pairs == observed_pairs" in launcher
    assert "refuses a running Docker container without the" in launcher
    assert "QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_B64" in launcher
    assert launcher.count('--label "org.qcsd.owner=qcsd-lab"') >= 5
    # Acceptance server, ordinary controlled server, controlled router, and
    # routed public observer remain outside the isolated client CPU partition.
    assert launcher.count("--cpuset-cpus 0-9") == 4
    assert "SYS_NICE" not in launcher
    assert "--cpu-rt-runtime" not in launcher
    assert "unsupported capture scheduler contract" in entrypoint
    assert "taskset --cpu-list 11 qcsd-lab-internal" in entrypoint
    assert "+sys_nice" not in entrypoint
    assert '_qcsd_docker_api exec "${container_id}" /usr/bin/python3 -c' in network_probe
    assert "/usr/local/bin/python3" not in network_probe


def test_capture_scheduler_rejects_swapped_name_to_exact_id_binding() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")
    scheduler_function = (
        "capture_scheduler_host_partition_b64() {"
        + launcher.split("capture_scheduler_host_partition_b64() {", 1)[1].split(
            "\n}\n\nscheduler_host_partition_b64=", 1
        )[0]
        + "\n}\n"
    )
    first_id = "a" * 64
    second_id = "b" * 64
    inspected = json.dumps(
        [
            {
                "Id": first_id,
                "Name": "/first",
                "Config": {"Labels": {"org.qcsd.owner": "qcsd-lab"}},
                "State": {"Running": True},
                "HostConfig": {"CpusetCpus": "0-9"},
            },
            {
                "Id": second_id,
                "Name": "/second",
                "Config": {"Labels": {"org.qcsd.owner": "qcsd-lab"}},
                "State": {"Running": True},
                "HostConfig": {"CpusetCpus": "0-9"},
            },
        ]
    )
    harness = f"""
set -u
{scheduler_function}
docker() {{
  if [[ "$1" == info ]]; then printf '12\\n'
  elif [[ "$1" == ps ]]; then printf '%s\\n%s\\n' '{first_id}' '{second_id}'
  elif [[ "$1" == container && "$2" == inspect ]]; then printf '%s\\n' "$INSPECTED"
  else return 2
  fi
}}
_qcsd_docker_api() {{ docker "$@"; }}
_QCSD_DOCKER_METADATA_TIMEOUT_SECONDS=10
_qcsd_docker_api_with_timeout() {{
  local duration="$1"
  shift
  [[ "$duration" == "$_QCSD_DOCKER_METADATA_TIMEOUT_SECONDS" ]] || return 125
  docker "$@"
}}
study_capture_scheduler_contract=qcsd-client-rr1-cpu10-etf-helper-cpu11-v1
capture_scheduler_host_partition_b64 "$@"
"""

    correct = subprocess.run(
        ["bash", "-c", harness, "scheduler", "first", first_id, "second", second_id],
        env={**os.environ, "INSPECTED": inspected},
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert correct.returncode == 0, correct.stderr
    receipt = json.loads(base64.b64decode(correct.stdout.strip(), validate=True))
    assert receipt["running_container_set_matches_expected"] is True

    swapped = subprocess.run(
        ["bash", "-c", harness, "scheduler", "first", second_id, "second", first_id],
        env={**os.environ, "INSPECTED": inspected},
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert swapped.returncode != 0
    assert "container_set_matches_expected=False" in swapped.stderr


def test_controlled_topology_cleanup_is_fail_closed_and_state_aware(
    tmp_path: Path,
) -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")
    capture_root_helper = (
        "prepare_kernel_tx_capture_root() {"
        + launcher.split("prepare_kernel_tx_capture_root() {", 1)[1].split(
            "\n}\n\nstart_buflo_controlled_router()", 1
        )[0]
        + "\n}\n"
    )
    controlled_router_launcher = (
        "start_buflo_controlled_router() {"
        + launcher.split("start_buflo_controlled_router() {", 1)[1].split(
            "\n}\n\nconfigure_buflo_router()", 1
        )[0]
    )
    lifetime_signal_helpers = (
        "_QCSD_LIFETIME_SIGNAL_STATUS=0"
        + launcher.split("_QCSD_LIFETIME_SIGNAL_STATUS=0", 1)[1].split(
            "\n\nrequire_submodule()", 1
        )[0]
    )
    cleanup_signal_helpers = (
        "_qcsd_latch_cleanup_signal() {"
        + launcher.split("_qcsd_latch_cleanup_signal() {", 1)[1].split(
            "\ncleanup_kernel_tx_public_topology() {", 1
        )[0]
        + "\n"
    )
    study_environment_cleanup = (
        "remove_study_environment_transport() {"
        + launcher.split("remove_study_environment_transport() {", 1)[1].split(
            "\n}\n\ncleanup_study_environment_transport_on_exit()", 1
        )[0]
        + "\n}\n"
    )
    sidecar_cleanup = (
        "cleanup_sidecars() {"
        + launcher.split("cleanup_sidecars() {", 1)[1].split(
            "\n}\n\nstart_capture_acceptance_server", 1
        )[0]
        + "\n}\n"
    )
    controlled_cleanup = (
        "cleanup_buflo_controlled() {"
        + launcher.split("    cleanup_buflo_controlled() {", 1)[1].split(
            "\n    }\n    trap 'cleanup_buflo_controlled", 1
        )[0]
        + "\n}\n"
    )

    router_id = "a" * 64
    first_server_id = "b" * 64
    second_server_id = "c" * 64
    client_network_id = "d" * 64
    server_network_id = "e" * 64

    def run_cleanup(
        case: str,
        *,
        original_status: int,
        fail_id: str = "",
        cleanup_signal: str = "",
        terminal_signal: str = "",
    ):
        case_root = tmp_path / case
        object_root = case_root / "objects"
        capture_root = case_root / "capture"
        object_root.mkdir(parents=True)
        capture_root.mkdir()
        for kind, identity in (
            ("container", router_id),
            ("container", first_server_id),
            ("container", second_server_id),
            ("network", client_network_id),
            ("network", server_network_id),
        ):
            (object_root / f"{kind}-{identity}").touch()
        script = f"""
set -u
{lifetime_signal_helpers}
study_environment_transport_dir=""
study_environment_host_path=""
{study_environment_cleanup}
{cleanup_signal_helpers}
{sidecar_cleanup}
{controlled_cleanup}
_qcsd_cleanup_terminal_hook() {{
  if [[ -n "${{TERMINAL_SIGNAL:-}}" ]]; then
    kill -"$TERMINAL_SIGNAL" "$$"
  fi
}}
_qcsd_docker_exact_id_presence() {{
  if [[ -f "$OBJECT_ROOT/container-$1" ]]; then printf 'present\\n'; else printf 'absent\\n'; fi
}}
_qcsd_docker_exact_network_presence() {{
  if [[ -f "$OBJECT_ROOT/network-$1" ]]; then printf 'present\\n'; else printf 'absent\\n'; fi
}}
_qcsd_docker_api() {{
  printf '%s\\n' "$*" >>"$CALL_LOG"
  if [[ -n "${{CLEANUP_SIGNAL:-}}" && ! -e "$SIGNAL_SENT" ]]; then
    : >"$SIGNAL_SENT"
    kill -"$CLEANUP_SIGNAL" "$$"
  fi
  local identity="${{@: -1}}"
  if [[ "$1" == "rm" ]]; then
    [[ "$identity" != "$FAIL_ID" ]] || return 41
    /usr/bin/unlink "$OBJECT_ROOT/container-$identity"
  elif [[ "$1" == "network" && "$2" == "rm" ]]; then
    [[ "$identity" != "$FAIL_ID" ]] || return 42
    /usr/bin/unlink "$OBJECT_ROOT/network-$identity"
  fi
}}
qcsd_retire_docker_handoff() {{ :; }}
QCSD_DOCKER_IDS_SIDECARS=({router_id} {first_server_id} {second_server_id})
controlled_router_started=0
controlled_router_id={router_id}
QCSD_DOCKER_IDS_CONTROLLED_CLIENT_NETWORKS=({client_network_id})
QCSD_DOCKER_IDS_CONTROLLED_SERVER_NETWORKS=({server_network_id})
kernel_tx_capture_root="$CAPTURE_ROOT"
cleanup_buflo_controlled {original_status}
"""
        completed = subprocess.run(
            ["bash", "-c", script],
            env={
                **os.environ,
                "OBJECT_ROOT": str(object_root),
                "CAPTURE_ROOT": str(capture_root),
                "CALL_LOG": str(case_root / "calls.log"),
                "FAIL_ID": fail_id,
                "CLEANUP_SIGNAL": cleanup_signal,
                "SIGNAL_SENT": str(case_root / "signal-sent"),
                "TERMINAL_SIGNAL": terminal_signal,
            },
            text=True,
            capture_output=True,
            timeout=5,
        )
        return completed, capture_root, (case_root / "calls.log").read_text()

    clean, clean_capture, clean_calls = run_cleanup("clean", original_status=0)
    assert clean.returncode == 0, clean.stderr
    assert not clean_capture.exists()
    assert clean_calls.splitlines() == [
        f"rm --force {router_id}",
        f"rm --force {first_server_id}",
        f"rm --force {second_server_id}",
        f"network rm {server_network_id}",
        f"network rm {client_network_id}",
    ]

    upgraded, upgraded_capture, _ = run_cleanup(
        "failure-zero", original_status=0, fail_id=router_id
    )
    assert upgraded.returncode == 1
    assert upgraded_capture.exists()
    assert "preserving kernel-TX capture root" in upgraded.stderr

    preserved, preserved_capture, _ = run_cleanup(
        "failure-seven", original_status=7, fail_id=router_id
    )
    assert preserved.returncode == 7
    assert preserved_capture.exists()

    for cleanup_signal, expected_status in (
        ("HUP", 129),
        ("INT", 130),
        ("QUIT", 131),
        ("TERM", 143),
    ):
        interrupted, interrupted_capture, interrupted_calls = run_cleanup(
            f"signal-{cleanup_signal.lower()}",
            original_status=0,
            cleanup_signal=cleanup_signal,
        )
        assert interrupted.returncode == expected_status, interrupted.stderr
        assert not interrupted_capture.exists()
        assert len(interrupted_calls.splitlines()) == 5

        terminal, terminal_capture, terminal_calls = run_cleanup(
            f"terminal-{cleanup_signal.lower()}",
            original_status=0,
            terminal_signal=cleanup_signal,
        )
        assert terminal.returncode == expected_status, terminal.stderr
        assert not terminal_capture.exists()
        assert len(terminal_calls.splitlines()) == 5

    failed_and_interrupted, failed_capture, _ = run_cleanup(
        "failure-seven-signal-term",
        original_status=7,
        fail_id=router_id,
        cleanup_signal="TERM",
    )
    assert failed_and_interrupted.returncode == 7
    assert failed_capture.exists()

    terminal_after_failure, terminal_failure_capture, _ = run_cleanup(
        "failure-seven-terminal-term",
        original_status=7,
        fail_id=router_id,
        terminal_signal="TERM",
    )
    assert terminal_after_failure.returncode == 7
    assert terminal_failure_capture.exists()

    assert 'docker rm -f "${name}"' not in sidecar_cleanup
    assert '_qcsd_docker_exact_id_presence "${cid}"' in sidecar_cleanup
    assert '_qcsd_docker_api rm --force "${cid}"' in sidecar_cleanup
    assert '[[ ! "${cid}" =~ ^[0-9a-f]{64}$ ]]' in sidecar_cleanup
    assert "if ! cleanup_sidecars; then" in controlled_cleanup
    assert 'docker network rm "${controlled_server_network}"' not in controlled_cleanup
    assert 'docker network rm "${controlled_client_network}"' not in controlled_cleanup
    assert "QCSD_DOCKER_IDS_CONTROLLED_SERVER_NETWORKS" in controlled_cleanup
    assert "QCSD_DOCKER_IDS_CONTROLLED_CLIENT_NETWORKS" in controlled_cleanup
    assert "_qcsd_docker_exact_network_presence" in controlled_cleanup
    assert "_qcsd_docker_api network rm" in controlled_cleanup
    assert "_qcsd_begin_latched_cleanup" in controlled_cleanup
    assert "_qcsd_finish_latched_cleanup" in controlled_cleanup
    assert "trap '' HUP INT QUIT TERM" not in controlled_cleanup
    assert "preserving kernel-TX capture root" in controlled_cleanup

    controlled_branch = launcher.split(
        'if [[ "${1:-}" == "buflo-study" && "${2:-}" == "capture" ]]', 1
    )[1].split("# Every remaining ETF launch is a public campaign.", 1)[0]
    assert (
        "qcsd_create_docker_network QCSD_DOCKER_IDS_CONTROLLED_CLIENT_NETWORKS" in controlled_branch
    )
    assert (
        "qcsd_create_docker_network QCSD_DOCKER_IDS_CONTROLLED_SERVER_NETWORKS" in controlled_branch
    )
    assert 'controlled_client_network_id="${QCSD_DOCKER_IDS_CONTROLLED_CLIENT_NETWORKS[-1]}"' in (
        controlled_branch
    )
    assert 'controlled_server_network_id="${QCSD_DOCKER_IDS_CONTROLLED_SERVER_NETWORKS[-1]}"' in (
        controlled_branch
    )
    assert '--volume "${capture_root}:/lab/results/${capture_root##*/}:ro"' in controlled_branch
    assert '--volume "${capture_root}:/kernel-tx:rw"' in launcher
    assert '--group-add "${qcsd_invoking_gid}"' in controlled_router_launcher
    assert "--cap-add DAC_OVERRIDE" not in controlled_router_launcher
    assert controlled_router_launcher.count("--cap-add ") == 2
    assert "dac_override" not in controlled_router_launcher.lower()
    assert "dac_read_search" not in controlled_router_launcher.lower()
    assert "--privileged" not in controlled_router_launcher
    assert launcher.count('--group-add "${qcsd_invoking_gid}"') == 2
    assert 'if ! capture_root_first_entry="$(' in capture_root_helper
    assert "cannot inspect the kernel-TX capture root" in capture_root_helper
    assert 'verify_kernel_tx_router_capture_access "${result_ref}"' in (controlled_router_launcher)
    assert "{{json .HostConfig.GroupAdd}}" in launcher
    assert 'Path("/proc/1/status")' in launcher
    assert 'root = Path("/kernel-tx")' in launcher
    assert "stat.S_IMODE(root_status.st_mode) != 0o2770" in launcher
    assert 'probe = root / ".qcsd-router-access-probe"' in launcher
    assert '"${kernel_tx_capture_root}" initialize' in controlled_branch
    assert '"${kernel_tx_capture_root}" verify' in controlled_branch
    assert "qcsd_run_detached_docker QCSD_DOCKER_IDS_SIDECARS" in launcher
    assert "--entrypoint /opt/qcsd-venv/bin/python3" in controlled_router_launcher
    assert '"${image_id}" -m qcsd_lab.kernel_capture_router' in controlled_router_launcher
    assert "--entrypoint /usr/bin/python3" not in controlled_router_launcher
    assert 'sidecars+=("${first_server}")' not in controlled_branch
    assert 'sidecars+=("${second_server}")' not in controlled_branch

    capture_root = tmp_path / "kernel-tx"
    capture_root.mkdir(mode=0o700)
    access = subprocess.run(
        [
            "bash",
            "-c",
            f"set -euo pipefail\n{capture_root_helper}\n"
            'prepare_kernel_tx_capture_root "$CAPTURE_ROOT" initialize',
        ],
        env={
            **os.environ,
            "CAPTURE_ROOT": str(capture_root),
            "qcsd_invoking_uid": str(os.getuid()),
            "qcsd_invoking_gid": str(os.getgid()),
        },
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert access.returncode == 0, access.stderr
    capture_root_stat = capture_root.stat()
    assert capture_root_stat.st_uid == os.getuid()
    assert capture_root_stat.st_gid == os.getgid()
    assert stat.S_IMODE(capture_root_stat.st_mode) == 0o2770

    symlink = tmp_path / "kernel-tx-link"
    symlink.symlink_to(capture_root, target_is_directory=True)
    rejected = subprocess.run(
        [
            "bash",
            "-c",
            f"set -euo pipefail\n{capture_root_helper}\n"
            'prepare_kernel_tx_capture_root "$CAPTURE_ROOT" verify',
        ],
        env={
            **os.environ,
            "CAPTURE_ROOT": str(symlink),
            "qcsd_invoking_uid": str(os.getuid()),
            "qcsd_invoking_gid": str(os.getgid()),
        },
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert rejected.returncode != 0
    assert "existing non-symbolic-link directory" in rejected.stderr

    capture_root.chmod(0o700)
    wrong_mode = subprocess.run(
        [
            "bash",
            "-c",
            f"set -euo pipefail\n{capture_root_helper}\n"
            'prepare_kernel_tx_capture_root "$CAPTURE_ROOT" verify',
        ],
        env={
            **os.environ,
            "CAPTURE_ROOT": str(capture_root),
            "qcsd_invoking_uid": str(os.getuid()),
            "qcsd_invoking_gid": str(os.getgid()),
        },
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert wrong_mode.returncode != 0
    assert stat.S_IMODE(capture_root.stat().st_mode) == 0o700

    capture_root.chmod(0o2770)
    wrong_gid = subprocess.run(
        [
            "bash",
            "-c",
            f"set -euo pipefail\n{capture_root_helper}\n"
            'prepare_kernel_tx_capture_root "$CAPTURE_ROOT" verify',
        ],
        env={
            **os.environ,
            "CAPTURE_ROOT": str(capture_root),
            "qcsd_invoking_uid": str(os.getuid()),
            "qcsd_invoking_gid": str(os.getgid() + 1),
        },
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert wrong_gid.returncode != 0
    assert capture_root.stat().st_gid == os.getgid()
    assert stat.S_IMODE(capture_root.stat().st_mode) == 0o2770

    invalid_action = subprocess.run(
        [
            "bash",
            "-c",
            f"set -euo pipefail\n{capture_root_helper}\n"
            'prepare_kernel_tx_capture_root "$CAPTURE_ROOT" invalid',
        ],
        env={
            **os.environ,
            "CAPTURE_ROOT": str(capture_root),
            "qcsd_invoking_uid": str(os.getuid()),
            "qcsd_invoking_gid": str(os.getgid()),
        },
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert invalid_action.returncode != 0
    assert "access action is invalid" in invalid_action.stderr

    (capture_root / "stale").write_text("evidence", encoding="utf-8")
    nonempty = subprocess.run(
        [
            "bash",
            "-c",
            f"set -euo pipefail\n{capture_root_helper}\n"
            'prepare_kernel_tx_capture_root "$CAPTURE_ROOT" verify',
        ],
        env={
            **os.environ,
            "CAPTURE_ROOT": str(capture_root),
            "qcsd_invoking_uid": str(os.getuid()),
            "qcsd_invoking_gid": str(os.getgid()),
        },
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert nonempty.returncode != 0
    assert "contains stale evidence" in nonempty.stderr


def test_launcher_routes_every_public_etf_campaign_through_post_veth_observer() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")
    entrypoint = (LAB_ROOT / "docker/collection-entrypoint").read_text(encoding="utf-8")
    public_router_launcher = (
        "start_kernel_tx_public_router() {"
        + launcher.split("start_kernel_tx_public_router() {", 1)[1].split(
            "\n}\n\nreplace_container_option_value()", 1
        )[0]
    )
    public = launcher.split("# Every remaining ETF launch is a public campaign.", 1)[1].split(
        'if [[ "${1:-}" == "test"', 1
    )[0]

    assert "docker network create --driver bridge --internal" in public
    assert "_qcsd_docker_api network connect --gw-priority 1" in launcher
    assert 'bridge "${kernel_tx_public_router_id}"' in launcher
    assert "QCSD_KERNEL_TX_ROUTER_TOPOLOGY_KIND=routed-public-egress" in launcher
    assert "QCSD_KERNEL_TX_ROUTER_REQUIRE_MASQUERADE=1" in launcher
    assert 'iptables -t nat -A POSTROUTING -s "${client_subnet}" -o eth1 -j MASQUERADE' in launcher
    assert 'replace_container_option_value --network "${kernel_tx_public_network_id}"' in public
    assert "capture_scheduler_host_partition_b64" in public
    assert '"${kernel_tx_public_router_name}"' in public
    assert "QCSD_KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_B64" in public
    assert "QCSD_KERNEL_TX_CONTROLLED_OBSERVER_BINDING_B64" in public
    assert "QCSD_KERNEL_TX_POST_VETH_CAPTURE_ROOT=/kernel-tx" in public
    assert '--volume "${kernel_tx_public_capture_root}:/kernel-tx:ro"' in public
    assert '--volume "${capture_root}:/kernel-tx:rw"' in launcher
    assert '--group-add "${qcsd_invoking_gid}"' in public_router_launcher
    assert "--cap-add DAC_OVERRIDE" not in public_router_launcher
    assert public_router_launcher.count("--cap-add ") == 2
    assert "dac_override" not in public_router_launcher.lower()
    assert "dac_read_search" not in public_router_launcher.lower()
    assert "--privileged" not in public_router_launcher
    assert (
        'verify_kernel_tx_router_capture_access "${kernel_tx_public_router_id}"'
        in public_router_launcher
    )
    assert 'prepare_kernel_tx_capture_root "${kernel_tx_public_capture_root}" initialize' in public
    assert public.index("trap 'cleanup_kernel_tx_public_topology") < public.index(
        'prepare_kernel_tx_capture_root "${kernel_tx_public_capture_root}" initialize'
    )
    assert "--entrypoint /opt/qcsd-venv/bin/python3" in public_router_launcher
    assert '"${image_id}" -m qcsd_lab.kernel_capture_router' in public_router_launcher
    assert "--entrypoint /usr/bin/python3" not in public_router_launcher
    assert 'cleanup_kernel_tx_public_topology "$?"' in public
    assert "public kernel-TX router did not reach the idle end state" in launcher
    assert "preserving it and failing closed" in launcher
    assert "ip -4 route flush default" in entrypoint
    assert "public kernel-TX client default route is not exclusive" in entrypoint
    assert r"{64}\\Z" not in launcher
    assert r"{64}\Z" in launcher


def test_controlled_network_receipt_environment_is_canonical_and_restored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = buflo_study.KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_ENV
    monkeypatch.setenv(name, "previous")
    receipt = {"schema_version": 2, "artifact_type": "test-network"}

    def observed() -> str:
        return os.environ[name]

    encoded = buflo_study._with_kernel_tx_network_receipt(receipt, observed)

    assert json.loads(base64.b64decode(encoded, validate=True)) == receipt
    assert os.environ[name] == "previous"


def test_versioned_build_receipts_coexist_and_reject_path_or_request_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = {version: tmp_path / f"build-execution-v{version}.json" for version in (1, 2)}
    monkeypatch.setattr(
        buflo_study,
        "build_execution_receipt_path",
        lambda cohort_version=1: paths[cohort_version],
    )
    for version, path in paths.items():
        path.write_text(
            json.dumps(
                _build_execution_value(cohort_version=version),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    v1_sha256 = buflo_study.sha256_file(paths[1])

    assert (
        buflo_study.validate_build_execution_receipt(
            paths[1], expected_cohort_version=1, allow_historical=True
        )[
            "cohort_version"
        ]
        == 1
    )
    assert (
        buflo_study.validate_build_execution_receipt(
            paths[2], expected_cohort_version=2, allow_historical=True
        )[
            "cohort_version"
        ]
        == 2
    )
    assert buflo_study.sha256_file(paths[1]) == v1_sha256
    with pytest.raises(ValueError, match="cohort version differs from the request"):
        buflo_study.validate_build_execution_receipt(
            paths[1], expected_cohort_version=2, allow_historical=True
        )

    copied = tmp_path / "copied-v1-as-v2.json"
    copied.write_bytes(paths[1].read_bytes())
    with pytest.raises(ValueError, match="path does not match its cohort version"):
        buflo_study.validate_build_execution_receipt(copied, allow_historical=True)


def test_schema_three_build_receipt_validates_through_study_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "build-execution-v47.json"
    monkeypatch.setattr(
        buflo_study,
        "build_execution_receipt_path",
        lambda cohort_version=1: path,
    )
    value = _build_execution_value(cohort_version=47, schema_version=3)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validated = buflo_study.validate_build_execution_receipt(
        path,
        expected_collection_image="sha256:" + "a" * 64,
        expected_cohort_version=47,
        allow_historical=True,
    )

    assert validated["cohort_version"] == 47
    assert validated["collection_image"] == "sha256:" + "a" * 64
    assert validated["images"]["collection"]["tag"] == build_storage.BUILD_IMAGE_TAGS["collection"]


def test_schema_four_buildx_receipt_validates_through_historical_study_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "build-execution-v47.json"
    monkeypatch.setattr(
        buflo_study,
        "build_execution_receipt_path",
        lambda cohort_version=1: path,
    )
    value = _build_execution_value(cohort_version=47, schema_version=4)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validated = buflo_study.validate_build_execution_receipt(
        path,
        expected_collection_image="sha256:" + "a" * 64,
        expected_cohort_version=47,
        allow_historical=True,
    )

    assert validated["schema_version"] == 4
    assert validated["buildx"] == value["buildx"]


def test_schema_five_allocation_receipt_validates_through_study_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "build-execution-v47.json"
    monkeypatch.setattr(
        buflo_study,
        "build_execution_receipt_path",
        lambda cohort_version=1: path,
    )
    value, completion_path, completion = _write_schema5_build_pair(
        path, cohort_version=47
    )

    validated = buflo_study.validate_build_execution_receipt(
        path,
        expected_collection_image="sha256:" + "a" * 64,
        expected_cohort_version=47,
    )

    assert validated["schema_version"] == 5
    assert validated["buildx"] == value["buildx"]
    assert validated["cohort_allocation"] == value["cohort_allocation"]
    assert validated["cohort_claim"] == value["cohort_claim"]
    assert validated["cohort_claim_chain"] == value["cohort_claim_chain"]
    assert validated["cohort_authority_reproofs"] == value[
        "cohort_authority_reproofs"
    ]
    assert validated["completion_path"] == str(completion_path.resolve())
    assert validated["completion_sha256"] == hashlib.sha256(
        completion_path.read_bytes()
    ).hexdigest()
    assert validated["build_completion"] == completion


def test_current_study_reader_rejects_missing_or_tampered_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "build-execution-v47.json"
    monkeypatch.setattr(
        buflo_study,
        "build_execution_receipt_path",
        lambda cohort_version=1: path,
    )
    _value, completion_path, _completion = _write_schema5_build_pair(
        path, cohort_version=47
    )
    completion_raw = completion_path.read_bytes()
    completion_path.unlink()
    with pytest.raises(ValueError, match="build completion path cannot be resolved"):
        buflo_study.validate_build_execution_receipt(path, expected_cohort_version=47)

    completion_path.write_bytes(completion_raw + b" ")
    completion_path.chmod(0o600)
    with pytest.raises(ValueError, match="canonical"):
        buflo_study.validate_build_execution_receipt(path, expected_cohort_version=47)


@pytest.mark.parametrize("schema_version", (1, 2, 3, 4))
def test_current_study_reader_rejects_historical_schema_downgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    schema_version: int,
) -> None:
    path = tmp_path / "build-execution-v47.json"
    monkeypatch.setattr(
        buflo_study,
        "build_execution_receipt_path",
        lambda cohort_version=1: path,
    )
    value = _build_execution_value(cohort_version=47, schema_version=schema_version)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="current study build admission requires schema 5"):
        buflo_study.validate_build_execution_receipt(path, expected_cohort_version=47)
    assert (
        buflo_study.validate_build_execution_receipt(
            path,
            expected_cohort_version=47,
            allow_historical=True,
        )["cohort_version"]
        == 47
    )


def test_study_reader_hashes_the_same_stable_receipt_bytes_it_validates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "build-execution-v47.json"
    value = _build_execution_value(cohort_version=47, schema_version=4)
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    monkeypatch.setattr(
        buflo_study,
        "build_execution_receipt_path",
        lambda cohort_version=1: path,
    )
    monkeypatch.setattr(
        buflo_study,
        "load_stable_build_execution",
        lambda observed_path: (observed_path.resolve(), raw, value),
    )

    validated = buflo_study.validate_build_execution_receipt(
        path,
        expected_collection_image="sha256:" + "a" * 64,
        expected_cohort_version=47,
        allow_historical=True,
    )

    assert validated["path"] == str(path.resolve())
    assert validated["sha256"] == hashlib.sha256(raw).hexdigest()


def test_study_reader_rejects_duplicate_keys_before_receipt_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "build-execution-v47.json"
    path.write_text('{"schema_version":4,"schema_version":4}\n', encoding="utf-8")
    monkeypatch.setattr(
        buflo_study,
        "build_execution_receipt_path",
        lambda cohort_version=1: path,
    )

    with pytest.raises(ValueError, match="duplicate key"):
        buflo_study.validate_build_execution_receipt(
            path,
            expected_cohort_version=47,
            allow_historical=True,
        )


def test_schema_four_study_reader_rejects_resealed_buildx_identity_tampering() -> None:
    value = _build_execution_value(schema_version=4)
    value["buildx"]["identity"]["resolved"]["mode"] = stat.S_IFREG | 0o777
    identity_sha256 = buflo_study._canonical_digest(value["buildx"]["identity"])
    for observation in value["buildx"]["observations"]:
        observation["identity_sha256"] = identity_sha256
    payload = dict(value)
    payload.pop("payload_sha256")
    value["payload_sha256"] = buflo_study._canonical_digest(payload)

    with pytest.raises(ValueError, match="safe root-owned executable"):
        buflo_study._validate_build_execution_value(value)


def test_schema_three_study_reader_rejects_context_argv_even_when_rehashed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "build-execution-v47.json"
    monkeypatch.setattr(
        buflo_study,
        "build_execution_receipt_path",
        lambda cohort_version=1: path,
    )
    value = _build_execution_value(cohort_version=47, schema_version=3)
    for command in value["commands"]:
        command["argv"][1:3] = ["--context", value["docker"]["context"]]
    payload = dict(value)
    payload.pop("payload_sha256")
    value["payload_sha256"] = buflo_study._canonical_digest(payload)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="--pull --no-cache"):
        buflo_study.validate_build_execution_receipt(
            path,
            expected_cohort_version=47,
            allow_historical=True,
        )


def test_all_public_v2_campaign_matrices_render_and_validate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(buflo_study, "COHORT_INPUT_ROOT", tmp_path / "cohort-inputs")

    assert buflo_study.validate_campaign_matrix("smoke", cohort_version=2)["samples"] == 20
    assert buflo_study.validate_campaign_matrix("rehearsal", cohort_version=2)["samples"] == 40
    assert buflo_study.validate_campaign_matrix("formal", cohort_version=2)["samples"] == 1_500


def test_versioned_public5_outputs_are_narrowly_ignored() -> None:
    versioned = "config/chaff-response-qualification-store/sets/buflo-study-public5-v2/receipt.json"
    unrelated = "config/chaff-response-qualification-store/sets/unrelated-public5-v2/receipt.json"
    ignored = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", versioned],
        cwd=LAB_ROOT,
        check=False,
    )
    visible = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", unrelated],
        cwd=LAB_ROOT,
        check=False,
    )
    dockerignore = (LAB_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    dockerfile = (LAB_ROOT / "Dockerfile").read_text(encoding="utf-8")
    collection_packages = (
        dockerfile.split("FROM lab-runtime AS collection", 1)[1]
        .split("RUN uv lock --check", 1)[0]
        .split()
    )

    assert ignored.returncode == 0
    assert visible.returncode == 1
    assert "git" in collection_packages
    assert "config/chaff-response-qualification-store/sets/buflo-study-public5-v*/" in dockerignore
    assert "config/chaff-response-qualification-store/sets/*" not in dockerignore


def test_launcher_selects_exact_versioned_build_images_and_frozen_resume_admission() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")

    assert 'BUILD_COHORT_VERSION="${build_cohort_version}"' in launcher
    assert '"cohort_version": int(os.environ["BUILD_COHORT_VERSION"])' in launcher
    assert 'COLLECTION_IMAGE="${study_build_fields[1]}"' in launcher
    assert 'PREPARE_IMAGE="${study_build_fields[2]}"' in launcher
    assert 'REFERENCE_IMAGE="${study_build_fields[3]}"' in launcher
    assert 'QCSD_LAB_PREPARE_IMAGE="${PREPARE_IMAGE}"' in launcher
    assert (
        'study_capture_admission_host="${study_resume_root}/inputs/capture-admission.json"'
        in launcher
    )
    assert 'read_capture_admission_binding "${study_capture_admission_host}"' in launcher
    assert '--entrypoint /opt/qcsd-venv/bin/python3 "${image_id}" -c' in launcher
    assert "--entrypoint /usr/local/bin/python3" not in launcher
    assert (
        '--volume "${reference_cohort_inputs}:'
        '/lab/artifacts/buflo-study/cohort-inputs:rw"' in launcher
    )


def test_build_emits_schema5_with_stable_buildx_and_cohort_allocation(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "90"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert _marked_build_count(build_marker) == 3
    receipt_path = tmp_path / "artifacts/buflo-study/build-execution-v90.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_status = receipt_path.stat()
    assert stat.S_IMODE(receipt_status.st_mode) == 0o600
    assert receipt_status.st_nlink == 1
    assert receipt["schema_version"] == 5
    buildx = receipt["buildx"]
    assert buildx["schema_version"] == 1
    assert buildx["policy"] == "docker-selected-buildx-binary-stability-v1"
    assert buildx["passed"] is True
    assert [row["boundary"] for row in buildx["observations"]] == [
        "before-collection",
        "after-collection",
        "after-prepare",
        "after-reference",
    ]
    assert len({row["identity_sha256"] for row in buildx["observations"]}) == 1
    identity = buildx["identity"]
    assert identity["plugin_name"] == "buildx"
    assert identity["plugin"]["path"] == identity["reported_plugin_path"]
    resolved = Path(identity["resolved"]["path"])
    assert identity["resolved"]["sha256"] == hashlib.sha256(resolved.read_bytes()).hexdigest()
    allocation = receipt["cohort_allocation"]
    assert allocation["allocated_version"] == 90
    assert allocation["last_consumed_version"] == 89
    assert allocation["lab_commit"] == (
        tmp_path / "test-markers/cohort-lab-commit"
    ).read_text(encoding="ascii").strip()
    assert allocation["neqo_commit"] == "b" * 40
    assert allocation["neqo_gitlink"] == "b" * 40
    claim = receipt["cohort_claim"]
    assert claim["cohort_version"] == 90
    assert claim["claim"]["path"].endswith("/claim-v90.json")
    assert (tmp_path / claim["claim"]["path"]).is_file()
    claim_chain = receipt["cohort_claim_chain"]
    assert claim_chain["genesis"] == {
        "ledger_path": allocation["ledger_path"],
        "ledger_sha256": allocation["ledger_sha256"],
        "last_consumed_version": 89,
    }
    assert [item["cohort_version"] for item in claim_chain["claims"]] == [90]
    assert claim_chain["claims"][-1]["sha256"] == claim["claim"]["sha256"]
    assert claim_chain["head"] == {
        "cohort_version": 90,
        "sha256": claim["claim"]["sha256"],
    }
    assert [row["boundary"] for row in receipt["cohort_authority_reproofs"]] == [
        "after-cohort-claim-before-docker-recovery",
        "immediately-before-docker-recovery",
        "after-evidence-build-lock",
        "immediately-before-build-transaction",
        "immediately-after-build-transaction",
        "immediately-before-collection-build",
        "immediately-before-prepare-build",
        "immediately-before-reference-build",
        "after-reference-build-before-receipt",
    ]
    assert not tuple((tmp_path / "artifacts/buflo-study").glob(".build-iids-v90.*"))
    assert not tuple(
        (tmp_path / "artifacts/buflo-study").glob(
            "build-execution-v90.json.staged-*"
        )
    )
    completion_path = tmp_path / "artifacts/buflo-study/build-completion-v90.json"
    assert completion_path.is_file() and not completion_path.is_symlink()
    assert stat.S_IMODE(completion_path.stat().st_mode) == 0o600
    assert completion_path.stat().st_nlink == 1
    admitted = subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            str(tmp_path / "src/qcsd_lab/build_storage.py"),
            "receipt",
            str(receipt_path),
            "--expected-cohort",
            "90",
            "--probe-path",
            str(tmp_path / "tools/windows_docker_storage_probe.ps1"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert admitted.returncode == 0, admitted.stderr
    assert len(admitted.stdout.splitlines()) == 7


def test_build_rejects_same_uid_staging_path_replacement_before_publication(
    tmp_path: Path,
) -> None:
    boundary = (
        '  _qcsd_verify_saved_build_cohort_authority \\\n'
        '    "immediately-before-receipt-publication" || exit 1'
    )
    launcher, build_marker, environment = _launcher_boundary_fixture(
        tmp_path,
        committed_launcher_hooks=(
            (
                boundary,
                '  /usr/bin/unlink -- "${build_receipt_stage}"\n'
                "  /usr/bin/printf '%s\\n' '{\"attacker\":true}' >"
                '"${build_receipt_stage}"',
            ),
        ),
    )

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "91"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    receipt = tmp_path / "artifacts/buflo-study/build-execution-v91.json"
    stages = tuple(receipt.parent.glob(receipt.name + ".staged-*"))
    assert result.returncode != 0
    assert "staged build receipt bytes are not canonical" in result.stderr
    assert _marked_build_count(build_marker) == 3
    assert not receipt.exists()
    assert len(stages) == 1
    assert stages[0].read_bytes() == b'{"attacker":true}\n'


def test_build_publication_race_never_overwrites_existing_receipt(
    tmp_path: Path,
) -> None:
    publication_marker = (
        "  # Commit the already validated staging inode without an overwrite-capable\n"
        "  # rename; the helper revalidates the bytes and links its open descriptor."
    )
    launcher, build_marker, environment = _launcher_boundary_fixture(
        tmp_path,
        committed_launcher_hooks=(
            (
                publication_marker,
                '  /usr/bin/cp -- "${build_receipt_stage}" "${build_receipt}"',
            ),
        ),
    )

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "92"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    receipt = tmp_path / "artifacts/buflo-study/build-execution-v92.json"
    stages = tuple(receipt.parent.glob(receipt.name + ".staged-*"))
    assert result.returncode != 0
    assert "destination raced before publication" in result.stderr
    assert _marked_build_count(build_marker) == 3
    assert receipt.is_file()
    assert len(stages) == 1
    assert receipt.read_bytes() == stages[0].read_bytes()
    value = json.loads(receipt.read_bytes())
    payload = dict(value)
    claimed_digest = payload.pop("payload_sha256")
    assert claimed_digest == buflo_study._canonical_digest(payload)
    assert value["schema_version"] == 5
    assert value["cohort_version"] == 92
    completion = tmp_path / "artifacts/buflo-study/build-completion-v92.json"
    assert not completion.exists()
    rejected = subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            str(tmp_path / "src/qcsd_lab/build_storage.py"),
            "receipt",
            str(receipt),
            "--expected-cohort",
            "92",
            "--probe-path",
            str(tmp_path / "tools/windows_docker_storage_probe.ps1"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode != 0
    assert "completion" in rejected.stderr


def test_build_rechecks_full_source_authority_after_receipt_staging(
    tmp_path: Path,
) -> None:
    boundary = (
        '  _qcsd_verify_saved_build_cohort_authority \\\n'
        '    "immediately-before-receipt-publication" || exit 1'
    )
    launcher, build_marker, environment = _launcher_boundary_fixture(
        tmp_path,
        production_allocator=True,
        production_cohort_version=62,
        committed_launcher_hooks=(
            (
                boundary,
                "  /usr/bin/printf '%s\\n' '# late source drift' "
                '>>"${ROOT}/Dockerfile"',
            ),
        ),
    )

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "62"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    receipt = tmp_path / "artifacts/buflo-study/build-execution-v62.json"
    assert result.returncode != 0
    assert "immediately-before-receipt-publication" in result.stderr
    assert "consumed-cohort/source authority changed" in result.stderr
    assert _marked_build_count(build_marker) == 3
    assert not receipt.exists()
    assert len(tuple(receipt.parent.glob(receipt.name + ".staged-*"))) == 1
    assert (
        tmp_path / "artifacts/buflo-study/cohort-claims-v1/claim-v62.json"
    ).is_file()


def test_build_reproof_ignores_transient_git_directory_child_churn(
    tmp_path: Path,
) -> None:
    boundary = (
        '  _qcsd_reprove_build_cohort_authority '
        '"immediately-before-prepare-build" || exit 1'
    )
    churn = (
        '  /usr/bin/printf "%s\\n" transient >"${ROOT}/.git/qcsd-test-transient"\n'
        '  /usr/bin/rm -f -- "${ROOT}/.git/qcsd-test-transient"'
    )
    launcher, build_marker, environment = _launcher_boundary_fixture(
        tmp_path,
        production_allocator=True,
        production_cohort_version=62,
        committed_launcher_hooks=((boundary, churn),),
    )

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "62"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert _marked_build_count(build_marker) == 3
    receipt = json.loads(
        (tmp_path / "artifacts/buflo-study/build-execution-v62.json").read_text(
            encoding="utf-8"
        )
    )
    claim = json.loads(
        base64.b64decode(
            receipt["cohort_claim"]["claim"]["payload_base64"],
            validate=True,
        )
    )
    authority = claim["payload"]["authority"]
    assert authority["schema_version"] == 2
    assert set(authority["filesystem"]["directories"]["git"]) == {
        "type",
        "dev",
        "inode",
        "uid",
        "gid",
        "mode",
    }


def test_build_executes_production_allocator_across_guardian_and_transaction(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(
        tmp_path,
        production_allocator=True,
        production_cohort_version=62,
    )
    copied_source = launcher.read_text(encoding="utf-8")
    production_source = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")
    copied_start = copied_source.index("_qcsd_verify_clean_build_checkout() {")
    copied_end = copied_source.index("\n}\n\nif [[", copied_start) + 2
    production_start = production_source.index(
        "_qcsd_verify_clean_build_checkout() {"
    )
    production_end = production_source.index("\n}\n\nif [[", production_start) + 2
    assert copied_source[copied_start:copied_end] == production_source[
        production_start:production_end
    ]

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "62"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert _marked_build_count(build_marker) == 3
    receipt = json.loads(
        (tmp_path / "artifacts/buflo-study/build-execution-v62.json").read_text(
            encoding="utf-8"
        )
    )
    allocation = receipt["cohort_allocation"]
    assert receipt["schema_version"] == 5
    assert allocation["allocated_version"] == 62
    assert allocation["last_consumed_version"] == 61
    assert allocation["lab_commit"] == environment["QCSD_TEST_LAB_COMMIT"]
    assert allocation["neqo_commit"] == environment["QCSD_TEST_NEQO_COMMIT"]
    assert allocation["neqo_gitlink"] == environment["QCSD_TEST_NEQO_COMMIT"]


def test_failed_build_permanently_consumes_cohort_and_next_version_progresses(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(
        tmp_path,
        production_allocator=True,
        production_cohort_version=62,
    )
    failed_environment = {
        **environment,
        "QCSD_TEST_WSL_LOW_BOUNDARY": "before-collection",
    }

    failed = subprocess.run(
        [str(launcher), "build", "--cohort-version", "62"],
        cwd=tmp_path,
        env=failed_environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    claim_path = tmp_path / "artifacts/buflo-study/cohort-claims-v1/claim-v62.json"
    assert failed.returncode == 1, failed.stderr
    assert "requires at least" in failed.stderr
    assert "at before-collection" in failed.stderr
    assert claim_path.is_file()
    claim_bytes = claim_path.read_bytes()
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v62.json").exists()

    duplicate = subprocess.run(
        [str(launcher), "build", "--cohort-version", "62"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert duplicate.returncode == 125
    assert "exact next cohort is v63" in duplicate.stderr
    assert claim_path.read_bytes() == claim_bytes
    assert _marked_build_count(build_marker) == 0

    successor = subprocess.run(
        [str(launcher), "build", "--cohort-version", "63"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert successor.returncode == 0, successor.stderr
    assert claim_path.read_bytes() == claim_bytes
    assert (
        tmp_path / "artifacts/buflo-study/cohort-claims-v1/claim-v63.json"
    ).is_file()
    assert _marked_build_count(build_marker) == 3
    receipt = json.loads(
        (tmp_path / "artifacts/buflo-study/build-execution-v63.json").read_text(
            encoding="utf-8"
        )
    )
    assert receipt["cohort_allocation"]["last_consumed_version"] == 61
    assert receipt["cohort_allocation"]["allocated_version"] == 63
    embedded = json.loads(
        base64.b64decode(receipt["cohort_claim"]["claim"]["payload_base64"], validate=True)
    )
    assert embedded["payload"]["predecessor"] == {
        "kind": "cohort-claim",
        "cohort_version": 62,
        "sha256": hashlib.sha256(claim_bytes).hexdigest(),
    }
    claim_chain = receipt["cohort_claim_chain"]
    assert [item["cohort_version"] for item in claim_chain["claims"]] == [62, 63]
    assert claim_chain["claims"][0]["sha256"] == hashlib.sha256(claim_bytes).hexdigest()
    assert claim_chain["head"] == {
        "cohort_version": 63,
        "sha256": receipt["cohort_claim"]["claim"]["sha256"],
    }


def test_production_clean_verifier_rejects_clean_lab_head_advance(
    tmp_path: Path,
) -> None:
    boundary = (
        '    _qcsd_reprove_build_cohort_authority '
        '"immediately-before-docker-recovery" || exit 1'
    )
    launcher, build_marker, environment = _launcher_boundary_fixture(
        tmp_path,
        production_allocator=True,
        production_cohort_version=62,
        committed_launcher_hooks=(
            (boundary, _empty_git_commit_command(tmp_path, "advanced lab head")),
        ),
    )

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "62"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode != 0
    assert "immediately-before-docker-recovery" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v62.json").exists()
    assert (
        subprocess.run(
            ["/usr/bin/git", "-C", str(tmp_path), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        == ""
    )
    assert (
        subprocess.run(
            ["/usr/bin/git", "-C", str(tmp_path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        != environment["QCSD_TEST_LAB_COMMIT"]
    )


def test_production_clean_verifier_rejects_nested_head_gitlink_drift(
    tmp_path: Path,
) -> None:
    boundary = (
        '    _qcsd_reprove_build_cohort_authority '
        '"immediately-before-docker-recovery" || exit 1'
    )
    nested = tmp_path / "neqo-qcsd"
    launcher, build_marker, environment = _launcher_boundary_fixture(
        tmp_path,
        production_allocator=True,
        production_cohort_version=62,
        committed_launcher_hooks=(
            (boundary, _empty_git_commit_command(nested, "advanced nested head")),
        ),
    )

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "62"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode != 0
    assert "immediately-before-docker-recovery" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v62.json").exists()
    assert (
        subprocess.run(
            ["/usr/bin/git", "-C", str(nested), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        == ""
    )
    assert (
        subprocess.run(
            ["/usr/bin/git", "-C", str(nested), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        != environment["QCSD_TEST_NEQO_COMMIT"]
    )


def test_production_allocator_drift_after_guardian_prevents_docker_recovery(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "config/buflo-study/v1/consumed-cohorts.json"
    mutation = (
        "/usr/bin/python3 -I -c "
        + shlex.quote(
            "from pathlib import Path; import sys; "
            "p=Path(sys.argv[1]); p.write_bytes(p.read_bytes()+b' ')"
        )
        + " "
        + shlex.quote(str(ledger))
    )
    boundary = (
        '    _qcsd_reprove_build_cohort_authority '
        '"immediately-before-docker-recovery" || exit 1'
    )
    launcher, build_marker, environment = _launcher_boundary_fixture(
        tmp_path,
        production_allocator=True,
        production_cohort_version=62,
        committed_launcher_hooks=((boundary, mutation),),
    )

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "62"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode != 0
    assert "immediately-before-docker-recovery" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v62.json").exists()
    lifecycle = Path(environment["QCSD_TEST_LIFECYCLE_BASE"])
    assert not tuple(lifecycle.glob("transaction.*"))


def test_production_allocator_inode_drift_before_transaction_fails_closed(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "config/buflo-study/v1/consumed-cohorts.json"
    replacement = tmp_path / "test-markers/replacement-ledger.json"
    mutation = (
        "/usr/bin/python3 -I -c "
        + shlex.quote("import os,sys; os.replace(sys.argv[1],sys.argv[2])")
        + " "
        + shlex.quote(str(replacement))
        + " "
        + shlex.quote(str(ledger))
    )
    boundary = (
        '  _qcsd_reprove_build_cohort_authority '
        '"immediately-before-build-transaction" || exit 1'
    )
    launcher, build_marker, environment = _launcher_boundary_fixture(
        tmp_path,
        production_allocator=True,
        production_cohort_version=62,
        committed_launcher_hooks=((boundary, mutation),),
    )
    replacement.write_bytes(ledger.read_bytes())
    replacement.chmod(0o644)

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "62"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    # The authority reproof must fail before the build transaction.  A later
    # guardian census can legitimately strengthen that failure to its own
    # fail-closed exit status when cleanup cannot be proved complete.
    assert result.returncode != 0
    assert "immediately-before-build-transaction" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v62.json").exists()
    lifecycle = Path(environment["QCSD_TEST_LIFECYCLE_BASE"])
    assert not tuple(lifecycle.glob("transaction.*"))


def test_production_allocator_drift_after_build_lock_fails_closed(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "config/buflo-study/v1/consumed-cohorts.json"
    mutation = (
        "/usr/bin/python3 -I -c "
        + shlex.quote(
            "from pathlib import Path; import sys; "
            "p=Path(sys.argv[1]); p.write_bytes(p.read_bytes()+b' ')"
        )
        + " "
        + shlex.quote(str(ledger))
    )
    boundary = (
        '  _qcsd_reprove_build_cohort_authority '
        '"after-evidence-build-lock" || exit 1'
    )
    launcher, build_marker, environment = _launcher_boundary_fixture(
        tmp_path,
        production_allocator=True,
        production_cohort_version=62,
        committed_launcher_hooks=((boundary, mutation),),
    )

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "62"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode != 0
    assert "after-evidence-build-lock" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v62.json").exists()
    lifecycle = Path(environment["QCSD_TEST_LIFECYCLE_BASE"])
    assert not tuple(lifecycle.glob("transaction.*"))


@pytest.mark.parametrize(
    ("variable", "value"),
    (
        ("QCSD_TEST_BUILDX_METADATA_MODE", "missing"),
        ("QCSD_TEST_BUILDX_METADATA_MODE", "duplicate"),
        ("QCSD_TEST_BUILDX_METADATA_MODE", "extra"),
        ("QCSD_TEST_BUILDX_METADATA_MODE", "malformed"),
        ("QCSD_TEST_BUILDX_METADATA_MODE", "unsafe-path"),
        ("QCSD_TEST_BUILDX_VERSION_MODE", "mismatch"),
        ("QCSD_TEST_BUILDX_VERSION_MODE", "malformed"),
        ("QCSD_TEST_BUILDX_VERSION_MODE", "multiline"),
    ),
)
def test_buildx_preflight_failure_prevents_any_image_build_or_receipt(
    tmp_path: Path,
    variable: str,
    value: str,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment[variable] = value

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "91"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "cannot validate the Buildx identity at before-collection" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v91.json").exists()


def test_buildx_identity_change_stops_before_the_next_image_and_creates_no_receipt(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment["QCSD_TEST_BUILDX_MUTATE_AFTER_BUILDS"] = "1"

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "92"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Buildx identity changed at after-collection" in result.stderr
    assert _marked_build_count(build_marker) == 1
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v92.json").exists()


@pytest.mark.parametrize(
    ("variable", "value"),
    (
        ("QCSD_TEST_WSL_AVAILABLE_BYTES", str(64 * 1024**3 - 1)),
        ("QCSD_TEST_WSL_MALFORMED", "1"),
        ("QCSD_TEST_WSL_PROBE_FAIL", "1"),
    ),
)
def test_build_preflight_failure_prevents_any_docker_build_or_receipt(
    tmp_path: Path, variable: str, value: str
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment[variable] = value

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "71"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v71.json").exists()


@pytest.mark.parametrize(
    ("variable", "value", "expected_builds", "message"),
    (
        (
            "QCSD_TEST_WSL_IDENTITY_CHANGE_BOUNDARY",
            "before-prepare",
            1,
            "backing-volume identity changed",
        ),
        (
            "QCSD_TEST_WSL_LOW_BOUNDARY",
            "after-reference",
            3,
            "requires at least",
        ),
        (
            "QCSD_TEST_DOCKER_CHANGE_AFTER_BUILDS",
            "1",
            1,
            "daemon identity changed",
        ),
        (
            "QCSD_TEST_DOCKER_ID_CHANGE_AFTER_BUILDS",
            "1",
            1,
            "Docker lifecycle retirement refused because daemon identity "
            "could not be verified",
        ),
    ),
)
def test_build_boundary_failure_stops_at_exact_image_and_creates_no_receipt(
    tmp_path: Path,
    variable: str,
    value: str,
    expected_builds: int,
    message: str,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment[variable] = value

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "72"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert _marked_build_count(build_marker) == expected_builds
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v72.json").exists()


def test_build_final_daemon_recheck_catches_post_inventory_id_change(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment["QCSD_TEST_DOCKER_ID_CHANGE_AFTER_INVENTORY"] = "1"

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "74"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "daemon identity changed" in result.stderr
    assert _marked_build_count(build_marker) == 3
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v74.json").exists()


@pytest.mark.parametrize(
    ("variable", "value", "message"),
    (
        ("DOCKER_HOST", "tcp://example.invalid:2375", "rejects Docker endpoint"),
        (
            "QCSD_TEST_DOCKER_ENDPOINT",
            "tcp://example.invalid:2375",
            "requires one local Docker endpoint",
        ),
        (
            "QCSD_TEST_DOCKER_OPERATING_SYSTEM",
            "Remote Linux",
            "requires the local Docker Desktop Linux engine",
        ),
    ),
)
def test_build_rejects_endpoint_bypass_before_any_image_build(
    tmp_path: Path, variable: str, value: str, message: str
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment[variable] = value

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "73"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v73.json").exists()


@pytest.mark.parametrize(
    "variable",
    (
        "QCSD_LAB_COLLECTION_IMAGE",
        "QCSD_LAB_PREPARE_IMAGE",
        "QCSD_LAB_REFERENCE_IMAGE",
    ),
)
def test_build_rejects_image_role_overrides_before_any_image_build(
    tmp_path: Path, variable: str
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment[variable] = "neqo-qcsd-lab-collection:aliased"

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "75"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "rejects image-role override" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v75.json").exists()


def test_build_global_lock_rejects_concurrent_role_tag_mutation(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    daemon_lock_identity = "\t".join(
        (
            environment["QCSD_TEST_DOCKER_SERVER_ID"],
            "linux",
            "x86_64",
        )
    )
    lock_parent = Path(f"/tmp/qcsd-lab-evidence-build-{os.getuid()}")
    lock_parent.mkdir(mode=0o700, exist_ok=True)
    lock_parent.chmod(0o700)
    lock_path = lock_parent / (f"{hashlib.sha256(daemon_lock_identity.encode()).hexdigest()}.lock")
    with lock_path.open("a+", encoding="utf-8") as held_lock:
        lock_path.chmod(0o600)
        fcntl.flock(held_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        environment["QCSD_TEST_DOCKER_CONTEXT"] = "desktop-linux"
        result = subprocess.run(
            [str(launcher), "build", "--cohort-version", "76"],
            cwd=tmp_path,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    assert result.returncode != 0
    assert "user/WSL instance's Docker-daemon lock" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v76.json").exists()


@pytest.mark.parametrize("record_name", ("SUPERVISION", "RECOVERY"))
def test_build_rejects_prior_supervisor_taint_from_another_caller_directory(
    tmp_path: Path, record_name: str
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    caller = tmp_path / "caller"
    caller.mkdir()
    supervisor_root = Path(tempfile.mkdtemp(prefix="qcsd-docker-build-supervisor.", dir="/tmp"))
    record = supervisor_root / record_name
    record.write_text(
        _build_cli_taint(
            working_directory=tmp_path,
            daemon_id=environment["QCSD_TEST_DOCKER_SERVER_ID"],
        ),
        encoding="utf-8",
    )
    record.chmod(0o600)
    try:
        result = subprocess.run(
            [str(launcher), "build", "--cohort-version", "82"],
            cwd=caller,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        record.unlink(missing_ok=True)
        supervisor_root.rmdir()

    assert result.returncode != 0
    assert "blocked by unresolved prior Docker build state" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v82.json").exists()


def test_build_rejects_prior_supervisor_taint_from_same_daemon_in_another_checkout(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    supervisor_root = Path(tempfile.mkdtemp(prefix="qcsd-docker-build-supervisor.", dir="/tmp"))
    record = supervisor_root / "RECOVERY"
    record.write_text(
        _build_cli_taint(
            working_directory=Path("/another/qcsd/checkout"),
            daemon_id=environment["QCSD_TEST_DOCKER_SERVER_ID"],
        ),
        encoding="utf-8",
    )
    record.chmod(0o600)
    try:
        result = subprocess.run(
            [str(launcher), "build", "--cohort-version", "83"],
            cwd=tmp_path,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        record.unlink(missing_ok=True)
        supervisor_root.rmdir()

    assert result.returncode != 0
    assert "blocked by unresolved prior Docker build state" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v83.json").exists()


@pytest.mark.parametrize(
    ("record_name", "supervision_state", "recovery_late_signal"),
    (
        ("SUPERVISION", "declared", False),
        ("SUPERVISION", "active", False),
        ("RECOVERY", "declared", False),
        ("RECOVERY", "declared", True),
    ),
)
def test_build_rejects_valid_scope_launcher_taint_from_same_daemon(
    tmp_path: Path,
    record_name: str,
    supervision_state: str,
    recovery_late_signal: bool,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    supervisor_root = Path(tempfile.mkdtemp(prefix="qcsd-docker-build-supervisor.", dir="/tmp"))
    record = supervisor_root / record_name
    record.write_text(
        _build_scope_launcher_taint(
            supervisor_root=supervisor_root,
            record_name=record_name,
            working_directory=Path("/another/qcsd/checkout"),
            daemon_id=environment["QCSD_TEST_DOCKER_SERVER_ID"],
            supervision_state=supervision_state,
            recovery_late_signal=recovery_late_signal,
        ),
        encoding="utf-8",
    )
    record.chmod(0o600)
    try:
        result = subprocess.run(
            [str(launcher), "build", "--cohort-version", "84"],
            cwd=tmp_path,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        record.unlink(missing_ok=True)
        supervisor_root.rmdir()

    assert result.returncode != 0
    assert "blocked by unresolved prior Docker build state" in result.stderr
    assert "malformed prior supervisor record" not in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v84.json").exists()


@pytest.mark.parametrize("record_name", ("SUPERVISION", "RECOVERY"))
@pytest.mark.parametrize(
    ("mutation", "key", "value"),
    (
        ("replace", "process_identity_role", "docker-cli"),
        ("replace", "scope_launcher_pid", "0"),
        ("replace", "build_argv_sha256", "0" * 63),
        ("replace", "docker_server_id", "different-daemon"),
        ("replace", "scope_unit", "qcsd-docker-build-invalid.scope"),
        ("replace", "host_boot_id", "unavailable"),
        ("replace", "status_file", "/tmp/unbound-build.status"),
        ("replace", "status_file_state", "unknown"),
        ("missing", "process_identity_role", ""),
        ("duplicate", "process_identity_role", "local-systemd-run-scope-launcher"),
        ("extra", "unexpected_field", "value"),
    ),
)
def test_build_rejects_malformed_scope_launcher_taint(
    tmp_path: Path,
    record_name: str,
    mutation: str,
    key: str,
    value: str,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    supervisor_root = Path(tempfile.mkdtemp(prefix="qcsd-docker-build-supervisor.", dir="/tmp"))
    record = supervisor_root / record_name
    taint = _build_scope_launcher_taint(
        supervisor_root=supervisor_root,
        record_name=record_name,
        working_directory=Path("/another/qcsd/checkout"),
        daemon_id=environment["QCSD_TEST_DOCKER_SERVER_ID"],
    )
    if mutation == "replace":
        taint = _replace_taint_field(taint, key, value)
    elif mutation == "missing":
        taint = re.sub(rf"^{re.escape(key)}=.*\n", "", taint, count=1, flags=re.MULTILINE)
    elif mutation in {"duplicate", "extra"}:
        taint += f"{key}={value}\n"
    else:
        raise AssertionError(f"unsupported mutation: {mutation}")
    record.write_text(taint, encoding="utf-8")
    record.chmod(0o600)
    try:
        result = subprocess.run(
            [str(launcher), "build", "--cohort-version", "85"],
            cwd=tmp_path,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        record.unlink(missing_ok=True)
        supervisor_root.rmdir()

    assert result.returncode != 0
    assert "malformed prior supervisor record" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v85.json").exists()


def test_build_rejects_late_signal_scope_taint_without_terminal_scope(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    supervisor_root = Path(tempfile.mkdtemp(prefix="qcsd-docker-build-supervisor.", dir="/tmp"))
    record = supervisor_root / "RECOVERY"
    taint = _build_scope_launcher_taint(
        supervisor_root=supervisor_root,
        record_name="RECOVERY",
        working_directory=Path("/another/qcsd/checkout"),
        daemon_id=environment["QCSD_TEST_DOCKER_SERVER_ID"],
        recovery_late_signal=True,
    )
    taint = _replace_taint_field(taint, "scope_empty_proven", "0")
    taint = _replace_taint_field(taint, "scope_final_state", "unknown")
    record.write_text(taint, encoding="utf-8")
    record.chmod(0o600)
    try:
        result = subprocess.run(
            [str(launcher), "build", "--cohort-version", "87"],
            cwd=tmp_path,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        record.unlink(missing_ok=True)
        supervisor_root.rmdir()

    assert result.returncode != 0
    assert "malformed prior supervisor record" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v87.json").exists()


@pytest.mark.parametrize("symlink_kind", ("supervisor-root", "record"))
def test_build_rejects_symlinked_prior_supervisor_state(tmp_path: Path, symlink_kind: str) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    reserved_root = Path(tempfile.mkdtemp(prefix="qcsd-docker-build-supervisor.", dir="/tmp"))
    taint = _build_cli_taint(
        working_directory=Path("/another/qcsd/checkout"),
        daemon_id=environment["QCSD_TEST_DOCKER_SERVER_ID"],
    )
    if symlink_kind == "supervisor-root":
        target_root = tmp_path / "real-supervisor-root"
        target_root.mkdir(mode=0o700)
        target_record = target_root / "SUPERVISION"
        target_record.write_text(taint, encoding="utf-8")
        target_record.chmod(0o600)
        reserved_root.rmdir()
        reserved_root.symlink_to(target_root, target_is_directory=True)
        record = target_record
    else:
        target_record = tmp_path / "real-supervisor-record"
        target_record.write_text(taint, encoding="utf-8")
        target_record.chmod(0o600)
        record = reserved_root / "SUPERVISION"
        record.symlink_to(target_record)
    try:
        result = subprocess.run(
            [str(launcher), "build", "--cohort-version", "88"],
            cwd=tmp_path,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        if symlink_kind == "supervisor-root":
            reserved_root.unlink(missing_ok=True)
        else:
            record.unlink(missing_ok=True)
            reserved_root.rmdir()

    assert result.returncode != 0
    assert "unsafe prior supervisor" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v88.json").exists()


def test_build_retains_historical_transaction_taint_support(tmp_path: Path) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    supervisor_root = Path(tempfile.mkdtemp(prefix="qcsd-docker-build-supervisor.", dir="/tmp"))
    record = supervisor_root / "SUPERVISION"
    receipt = tmp_path / "artifacts/buflo-study/build-execution-v86.json"
    record.write_text(
        "object=docker-build-transaction\n"
        "docker_context=default\n"
        "docker_host=unix:///var/run/docker.sock\n"
        f"docker_server_id={environment['QCSD_TEST_DOCKER_SERVER_ID']}\n"
        f"docker_daemon_id={environment['QCSD_TEST_DOCKER_SERVER_ID']}\n"
        f"working_directory={Path('/another/qcsd/checkout')}\n"
        "cohort_version=86\n"
        f"receipt_path={receipt.resolve()}\n"
        "transaction_state=uncommitted-static-tag-mutation\n",
        encoding="utf-8",
    )
    record.chmod(0o600)
    try:
        result = subprocess.run(
            [str(launcher), "build", "--cohort-version", "86"],
            cwd=tmp_path,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        record.unlink(missing_ok=True)
        supervisor_root.rmdir()

    assert result.returncode != 0
    assert "blocked by unresolved prior Docker build state" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not receipt.exists()


def test_build_self_validation_rejects_invalid_inputs_before_receipt_write(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment["QCSD_TEST_INVALID_BUILD_INPUTS"] = "1"

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "77"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "build inputs are invalid" in result.stderr
    assert _marked_build_count(build_marker) == 3
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v77.json").exists()


def test_build_rejects_cross_role_source_snapshot_change(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment["QCSD_TEST_SOURCE_CHANGE_IMAGE_ID"] = "sha256:" + f"{2:064d}"

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "80"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "different source snapshots" in result.stderr
    assert _marked_build_count(build_marker) == 3
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v80.json").exists()


@pytest.mark.parametrize(
    ("mode", "message"),
    (
        ("missing", "did not create a regular IID file"),
        ("malformed", "invalid immutable image ID"),
        ("mismatch", "tag no longer binds its build-produced ID"),
    ),
)
def test_build_rejects_missing_malformed_or_mismatched_iid_evidence(
    tmp_path: Path, mode: str, message: str
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment["QCSD_TEST_IID_TARGET"] = "collection"
    environment["QCSD_TEST_IID_MODE"] = mode

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "81"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert _marked_build_count(build_marker) == 1
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v81.json").exists()


def test_build_validator_cannot_be_shadowed_from_the_caller_directory(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    shadow_root = tmp_path / "caller"
    shadow_package = shadow_root / "qcsd_lab"
    shadow_package.mkdir(parents=True)
    marker = shadow_root / "shadow-imported"
    (shadow_package / "__init__.py").write_text("", encoding="utf-8")
    (shadow_package / "build_storage.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('shadowed')\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "78"],
        cwd=shadow_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert _marked_build_count(build_marker) == 3
    assert not marker.exists()
    assert (tmp_path / "artifacts/buflo-study/build-execution-v78.json").is_file()


def test_build_canonicalises_a_symlinked_launcher_root_before_execution(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    symlink_root = tmp_path / "invocation-root"
    symlink_root.symlink_to(tmp_path, target_is_directory=True)

    result = subprocess.run(
        [str(symlink_root / launcher.name), "build", "--cohort-version", "79"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert _marked_build_count(build_marker) == 3
    receipt = json.loads(
        (tmp_path / "artifacts/buflo-study/build-execution-v79.json").read_text(encoding="utf-8")
    )
    assert {command["argv"][-1] for command in receipt["commands"]} == {str(tmp_path.resolve())}
    assert all(
        "invocation-root" not in item for command in receipt["commands"] for item in command["argv"]
    )


def test_windows_storage_probe_is_valid_windows_powershell_syntax() -> None:
    if shutil.which("powershell.exe") is None:
        pytest.skip("Windows PowerShell interop is unavailable")
    probe = LAB_ROOT / "tools/windows_docker_storage_probe.ps1"
    parser = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "$source=[Console]::In.ReadToEnd(); "
                "$tokens=$null; $errors=$null; "
                "[System.Management.Automation.Language.Parser]::ParseInput("
                "$source,[ref]$tokens,[ref]$errors) > $null; "
                "if ($errors.Count -ne 0) { $errors | Out-String | Write-Error; exit 1 }"
            ),
        ],
        input=probe.read_text(encoding="utf-8"),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert parser.returncode == 0, parser.stderr


def test_windows_storage_probe_rejects_registration_settings_conflict(
    tmp_path: Path,
) -> None:
    if shutil.which("powershell.exe") is None:
        pytest.skip("Windows PowerShell interop is unavailable")
    probe = (LAB_ROOT / "tools/windows_docker_storage_probe.ps1").read_text(encoding="utf-8")
    function = probe.split("function Get-CanonicalDataVhd {", 1)[1].split(
        "\n\n$resolved = Get-CanonicalDataVhd", 1
    )[0]
    harness = tmp_path / "probe-conflict.ps1"
    harness.write_text(
        """
$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0
$env:APPDATA = "C:\\Users\\test\\AppData\\Roaming"
function Test-Path {
    param([string]$LiteralPath, [string]$PathType)
    return (
        $LiteralPath -eq "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss" -or
        $LiteralPath -eq "C:\\Users\\test\\AppData\\Roaming\\Docker\\settings-store.json"
    )
}
function Get-ChildItem {
    param([string]$LiteralPath)
    return [pscustomobject]@{ PSPath = "registry-item" }
}
function Get-ItemProperty {
    param([string]$LiteralPath)
    return [pscustomobject]@{
        DistributionName = "docker-desktop-data"
        BasePath = "C:\\RegisteredDockerData"
        VhdFileName = "ext4.vhdx"
    }
}
function Get-Content {
    param([switch]$Raw, [string]$LiteralPath)
    return '{"diskImageLocation":"C:\\\\ConfiguredDockerData"}'
}
function Get-CanonicalDataVhd {
"""
        + function
        + """
try {
    Get-CanonicalDataVhd | Out-Null
    Write-Error "conflicting authoritative locations were accepted"
    exit 2
}
catch {
    if ($_.Exception.Message -notlike "*registration and settings contain conflicting*") {
        Write-Error $_
        exit 3
    }
}
""",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(harness),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr


def test_windows_storage_probe_smoke_reports_the_actual_backing_volume() -> None:
    if shutil.which("powershell.exe") is None or shutil.which("wslpath") is None:
        pytest.skip("Windows PowerShell interop is unavailable")
    probe = LAB_ROOT / "tools/windows_docker_storage_probe.ps1"
    mapped = subprocess.run(
        ["wslpath", "-w", "--", str(probe)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            mapped,
            "-Boundary",
            "before-collection",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        unavailable = (
            "active data location is not authoritatively configured",
            "expected exactly one Docker data VHDX; found 0",
        )
        if any(reason in result.stderr for reason in unavailable):
            pytest.skip(f"authoritative Docker data VHDX is unavailable: {result.stderr}")
        pytest.fail(f"Windows Docker storage probe failed: {result.stderr}")
    observation = json.loads(result.stdout)
    probe_sha256 = hashlib.sha256(probe.read_bytes()).hexdigest()

    assert observation["probe_sha256"] == probe_sha256
    assert observation["location_source"] in (
        "wsl-lxss-docker-desktop-data",
        "docker-settings-store",
        "docker-legacy-settings",
    )
    assert observation["data_vhd_path"].lower().endswith(".vhdx")
    if observation["available_bytes"] < build_storage.BUILD_WSL_HOST_MIN_AVAILABLE_BYTES:
        with pytest.raises(ValueError, match="requires at least"):
            build_storage.validate_build_host_storage_observation(
                observation,
                expected_boundary="before-collection",
                expected_probe_sha256=probe_sha256,
            )
    else:
        build_storage.validate_build_host_storage_observation(
            observation,
            expected_boundary="before-collection",
            expected_probe_sha256=probe_sha256,
        )


@pytest.mark.parametrize(
    ("signal_name", "signal_status"),
    [("HUP", 129), ("INT", 130), ("QUIT", 131), ("TERM", 143)],
)
def test_build_iid_cleanup_latches_terminal_signals_and_preserves_taint(
    tmp_path: Path,
    signal_name: str,
    signal_status: int,
) -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")
    lifetime_signal_helpers = (
        "_QCSD_LIFETIME_SIGNAL_STATUS=0"
        + launcher.split("_QCSD_LIFETIME_SIGNAL_STATUS=0", 1)[1].split(
            "\n\nrequire_submodule()", 1
        )[0]
    )
    cleanup_functions = (
        "build_iid_cleanup_entry_status=0"
        + launcher.split("build_iid_cleanup_entry_status=0", 1)[1].split(
            "\n  trap 'cleanup_build_iids", 1
        )[0]
    )

    def run_cleanup(case: str, *, original_status: int, signal_phase: str):
        case_root = tmp_path / case
        iid_root = case_root / "iids"
        iid_root.mkdir(parents=True)
        iid_paths = [
            iid_root / name
            for name in (
                "collection.iid",
                "prepare.iid",
                "reference.iid",
                ".buildx-plugins.fixture",
                ".buildx-version.fixture",
            )
        ]
        for iid_path in iid_paths:
            iid_path.write_text("sha256:" + "a" * 64 + "\n", encoding="utf-8")
        transaction_root = case_root / "transaction"
        transaction_root.mkdir()
        transaction_record = transaction_root / "SUPERVISION"
        transaction_record.write_text(
            "object=docker-build-transaction\ntransaction_state=uncommitted-static-tag-mutation\n",
            encoding="utf-8",
        )
        harness = f"""
set -u
{lifetime_signal_helpers}
{cleanup_functions}
_qcsd_build_iid_cleanup_terminal_hook() {{
  if [[ "$SIGNAL_PHASE" == "terminal" ]]; then
    kill -"$SIGNAL_NAME" "$$"
  fi
}}
rm() {{
  if [[ "$SIGNAL_PHASE" == "removal" && "$SIGNAL_SENT" == "0" ]]; then
    SIGNAL_SENT=1
    kill -"$SIGNAL_NAME" "$$"
  fi
  /usr/bin/rm "$@"
}}
collection_iid_path="$IID_ROOT/collection.iid"
prepare_iid_path="$IID_ROOT/prepare.iid"
reference_iid_path="$IID_ROOT/reference.iid"
buildx_plugins_json_path="$IID_ROOT/.buildx-plugins.fixture"
buildx_version_output_path="$IID_ROOT/.buildx-version.fixture"
build_iid_dir="$IID_ROOT"
SIGNAL_SENT=0
trap '_qcsd_latch_build_iid_cleanup_signal 129' HUP
trap '_qcsd_latch_build_iid_cleanup_signal 130' INT
trap '_qcsd_latch_build_iid_cleanup_signal 131' QUIT
trap '_qcsd_latch_build_iid_cleanup_signal 143' TERM
if [[ "$SIGNAL_PHASE" == "precleanup" ]]; then
  trap 'cleanup_build_iids "$?"' EXIT
  kill -"$SIGNAL_NAME" "$$"
  exit 99
fi
cleanup_build_iids "$ORIGINAL_STATUS"
"""
        completed = subprocess.run(
            ["bash", "-c", harness],
            env={
                **os.environ,
                "IID_ROOT": str(iid_root),
                "ORIGINAL_STATUS": str(original_status),
                "SIGNAL_NAME": signal_name,
                "SIGNAL_PHASE": signal_phase,
            },
            text=True,
            capture_output=True,
            timeout=5,
        )
        assert not iid_root.exists()
        assert transaction_record.read_text(encoding="utf-8").startswith(
            "object=docker-build-transaction\n"
        )
        return completed

    before_cleanup = run_cleanup(
        f"{signal_name.lower()}-precleanup", original_status=0, signal_phase="precleanup"
    )
    assert before_cleanup.returncode == signal_status, before_cleanup.stderr

    during_removal = run_cleanup(
        f"{signal_name.lower()}-removal", original_status=0, signal_phase="removal"
    )
    assert during_removal.returncode == signal_status, during_removal.stderr

    final_boundary = run_cleanup(
        f"{signal_name.lower()}-terminal", original_status=0, signal_phase="terminal"
    )
    assert final_boundary.returncode == signal_status, final_boundary.stderr


def test_build_iid_cleanup_preserves_original_failure_over_latched_signal(
    tmp_path: Path,
) -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")
    lifetime_signal_helpers = (
        "_QCSD_LIFETIME_SIGNAL_STATUS=0"
        + launcher.split("_QCSD_LIFETIME_SIGNAL_STATUS=0", 1)[1].split(
            "\n\nrequire_submodule()", 1
        )[0]
    )
    cleanup_functions = (
        "build_iid_cleanup_entry_status=0"
        + launcher.split("build_iid_cleanup_entry_status=0", 1)[1].split(
            "\n  trap 'cleanup_build_iids", 1
        )[0]
    )
    iid_root = tmp_path / "iids"
    iid_root.mkdir()
    for name in (
        "collection.iid",
        "prepare.iid",
        "reference.iid",
        ".buildx-plugins.fixture",
        ".buildx-version.fixture",
    ):
        (iid_root / name).touch()
    transaction_record = tmp_path / "SUPERVISION"
    transaction_record.write_text(
        "object=docker-build-transaction\ntransaction_state=uncommitted-static-tag-mutation\n",
        encoding="utf-8",
    )
    harness = f"""
set -u
{lifetime_signal_helpers}
{cleanup_functions}
_qcsd_build_iid_cleanup_terminal_hook() {{ :; }}
rm() {{
  kill -TERM "$$"
  /usr/bin/rm "$@"
}}
collection_iid_path="$IID_ROOT/collection.iid"
prepare_iid_path="$IID_ROOT/prepare.iid"
reference_iid_path="$IID_ROOT/reference.iid"
buildx_plugins_json_path="$IID_ROOT/.buildx-plugins.fixture"
buildx_version_output_path="$IID_ROOT/.buildx-version.fixture"
build_iid_dir="$IID_ROOT"
trap '_qcsd_latch_build_iid_cleanup_signal 129' HUP
trap '_qcsd_latch_build_iid_cleanup_signal 130' INT
trap '_qcsd_latch_build_iid_cleanup_signal 131' QUIT
trap '_qcsd_latch_build_iid_cleanup_signal 143' TERM
cleanup_build_iids 37
"""
    completed = subprocess.run(
        ["bash", "-c", harness],
        env={**os.environ, "IID_ROOT": str(iid_root)},
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert completed.returncode == 37, completed.stderr
    assert not iid_root.exists()
    assert transaction_record.exists()


def test_launcher_build_v5_is_create_only_and_preserves_prior_cohort(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment["QCSD_TEST_DOCKER_SERVER_ID"] = "12345678-1234-1234-1234-123456789abc"
    environment["QCSD_TEST_WSL_AVAILABLE_BYTES"] = str(64 * 1024**3)
    environment["QCSD_TEST_WSL_DATA_PATH"] = r"D:\DockerData\disk\docker_data.vhdx"
    powershell_marker = tmp_path / "powershell-boundaries"
    environment["QCSD_TEST_POWERSHELL_MARKER"] = str(powershell_marker)
    receipt_parent = tmp_path / "artifacts/buflo-study"
    receipt_parent.mkdir(parents=True)
    prior = receipt_parent / "build-execution-v61.json"
    prior.write_bytes(b"immutable historical receipt\n")
    prior_sha256 = hashlib.sha256(prior.read_bytes()).hexdigest()

    first = subprocess.run(
        [str(launcher), "build", "--cohort-version", "62"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert first.returncode == 0, first.stderr
    current = receipt_parent / "build-execution-v62.json"
    current_value = json.loads(current.read_text(encoding="utf-8"))
    assert current_value["cohort_version"] == 62
    assert current_value["schema_version"] == 5
    assert current_value["cohort_allocation"]["allocated_version"] == 62
    assert current_value["cohort_allocation"]["last_consumed_version"] == 61
    assert [
        observation["boundary"]
        for observation in current_value["buildx"]["observations"]
    ] == [
        "before-collection",
        "after-collection",
        "after-prepare",
        "after-reference",
    ]
    assert current_value["buildx"]["passed"] is True
    assert current_value["docker"]["context"] == "default"
    assert all(
        command["argv"][:3] == ["docker", "--host", "unix:///var/run/docker.sock"]
        for command in current_value["commands"]
    )
    preflight = current_value["host_storage_preflight"]
    assert preflight["required_available_bytes"] == 64 * 1024**3
    assert [item["boundary"] for item in preflight["observations"]] == [
        "before-collection",
        "before-prepare",
        "before-reference",
        "after-reference",
    ]
    assert {item["data_vhd_path"] for item in preflight["observations"]} == {
        r"D:\DockerData\disk\docker_data.vhdx"
    }
    assert {item["drive_letter"] for item in preflight["observations"]} == {"D"}
    assert len(powershell_marker.read_text(encoding="utf-8").splitlines()) == 4
    assert _marked_build_count(build_marker) == 3
    assert hashlib.sha256(prior.read_bytes()).hexdigest() == prior_sha256

    duplicate = subprocess.run(
        [str(launcher), "build", "--cohort-version=62"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert duplicate.returncode == 125
    assert "absent create-only receipt" in duplicate.stderr
    assert len(powershell_marker.read_text(encoding="utf-8").splitlines()) == 4
    assert _marked_build_count(build_marker) == 3


def test_build_execution_receipt_rejects_semantically_rehashed_cache_enabled_command() -> None:
    value = json.loads(json.dumps(_build_execution_value()))
    value["commands"][0]["argv"].remove("--no-cache")
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)

    with pytest.raises(ValueError, match="--pull --no-cache"):
        buflo_study._validate_build_execution_value(value)


def test_build_execution_receipt_accepts_consistent_host_paths_from_container() -> None:
    value = json.loads(json.dumps(_build_execution_value()))
    for command in value["commands"]:
        command["argv"][-2] = "/host-checkout/neqo-qcsd-lab/Dockerfile"
        command["argv"][-1] = "/host-checkout/neqo-qcsd-lab"
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)

    assert buflo_study._validate_build_execution_value(value)["cohort_version"] == 1

    value["commands"][0]["argv"][-1] = "/different-build-context"
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)
    with pytest.raises(ValueError, match="--pull --no-cache"):
        buflo_study._validate_build_execution_value(value)


def test_schema_two_container_reader_preserves_validated_physical_host_paths() -> None:
    value = json.loads(json.dumps(_build_execution_value(schema_version=2)))
    host_root = Path("/physical-host-checkout/neqo-qcsd-lab")
    for command in value["commands"]:
        iidfile_index = command["argv"].index("--iidfile") + 1
        command["argv"][iidfile_index] = str(
            host_root / "artifacts/buflo-study/.build-iids-v1.ABC123" / f"{command['target']}.iid"
        )
        command["argv"][-2] = str(host_root / "Dockerfile")
        command["argv"][-1] = str(host_root)
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)

    assert buflo_study._validate_build_execution_value(value)["cohort_version"] == 1

    value = json.loads(json.dumps(_build_execution_value()))
    value["commands"][1]["argv"][-2] = "/other-host-checkout/Dockerfile"
    value["commands"][1]["argv"][-1] = "/other-host-checkout"
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)
    with pytest.raises(ValueError, match="--pull --no-cache"):
        buflo_study._validate_build_execution_value(value)


@pytest.mark.parametrize(
    ("dockerfile", "build_root"),
    [
        ("/Dockerfile", "/"),
        ("//host/repo/Dockerfile", "//host/repo"),
        ("/host/a/../repo/Dockerfile", "/host/a/../repo"),
        ("relative/repo/Dockerfile", "relative/repo"),
    ],
)
def test_build_execution_receipt_rejects_noncanonical_or_unsafe_build_roots(
    dockerfile: str, build_root: str
) -> None:
    value = json.loads(json.dumps(_build_execution_value()))
    for command in value["commands"]:
        command["argv"][-2] = dockerfile
        command["argv"][-1] = build_root
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)

    with pytest.raises(ValueError, match="--pull --no-cache"):
        buflo_study._validate_build_execution_value(value)


@pytest.mark.parametrize(
    "name",
    [
        "buflo-study-v1-public-smoke-1200",
        "buflo-study-v1-public-rehearsal-1200",
        "buflo-study-v1-formal-01-1200",
        "buflo-study-v1-formal-10-1200",
    ],
)
def test_public_campaign_identity_cannot_bypass_capture_admission(name: str) -> None:
    assert orchestrator._public_buflo_campaign(name)


@pytest.mark.parametrize(
    "name",
    [
        "buflo-study-v1-smoke",
        "buflo-study-v1-formal-01",
        "buflo-study-v1-formal-1-1200",
        "buflo-study-v1-controlled-00-1200",
        "other-buflo-study-v1-public-smoke-1200",
    ],
)
def test_public_campaign_identity_rejects_near_miss_names(name: str) -> None:
    assert not orchestrator._public_buflo_campaign(name)


def test_public_campaign_run_requires_typed_admission_before_creating_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("QCSD_BUFLO_CAPTURE_ADMISSION", raising=False)
    campaign = SimpleNamespace(
        name="buflo-study-v1-public-smoke-1200",
        purpose="smoke",
    )

    with pytest.raises(ValueError, match="typed capture admission"):
        orchestrator._run_loaded_campaign(campaign, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_launcher_qualification_is_restartable_build_then_semantic_verify() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")

    assert "requires controlled roots and exactly one --destination" in launcher
    assert 'if [[ ! -e "${qualification_target}" ]]' in launcher
    assert "existing public5 evidence must be a non-symlink directory" in launcher
    assert '"${ROOT}/qcsd-lab" qualify-response-chaff' in launcher
    assert '--env "QCSD_BUFLO_QUALIFY_CONTROLLED_ONLY=1"' in launcher
    assert "QCSD_BUFLO_QUALIFY_VERIFY_ONLY=1" in launcher
    assert '--env "QCSD_BUFLO_QUALIFY_VERIFY_ONLY=1"' in launcher
    assert 'verify_qualification_checkout "buflo-study qualify"' in launcher
    assert 'qualification_set="buflo-study-public5-v${qualification_cohort_version}"' in launcher
    assert '--volume "${ROOT}/handoffs:/lab/handoffs:ro"' in launcher


def test_launcher_rejects_duplicate_qualification_cohort_version(tmp_path: Path) -> None:
    binary_root = tmp_path / "bin"
    binary_root.mkdir()
    docker = binary_root / "docker"
    docker.write_text(
        """#!/bin/sh
set -eu
if [ "${1:-}" = "--context" ] || [ "${1:-}" = "--host" ]; then shift 2; fi
case "${1:-} ${2:-}" in
  "context show") printf 'default\n' ;;
  "context inspect") printf 'unix:///var/run/docker.sock\n' ;;
  "info --format") printf 'test-daemon\n' ;;
esac
exit 0
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    environment = dict(os.environ)
    environment["PATH"] = f"{binary_root}:{environment['PATH']}"

    completed = subprocess.run(
        [
                str(LAB_ROOT / "qcsd-lab"),
            "buflo-study",
            "qualify",
            "--controlled-result",
            str(tmp_path / "controlled"),
            "--destination",
            str(tmp_path / "receipt.json"),
            "--cohort-version",
            "2",
            "--cohort-version",
            "3",
        ],
        cwd=LAB_ROOT,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 2
    assert "at most one --cohort-version" in completed.stderr


def test_study_environment_receipt_binds_minimized_docker_bases_and_locks() -> None:
    build_execution = _build_execution_value()
    value = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-environment",
        "docker": {
            "client_version": "29.0.1",
            "server_version": "29.0.1",
            "server_os": "linux",
            "server_arch": "arm64",
            "ncpu": 8,
            "mem_total_bytes": 16_000_000_000,
            "storage_driver": "overlayfs",
        },
        "collection_image": {
            "id": "sha256:" + "a" * 64,
            "repo_digests": ["collection@example.invalid@sha256:" + "b" * 64],
        },
        "build_inputs": {
            "schema_version": 1,
            "artifact_type": "qcsd-study-build-inputs",
            "rust_base_image": RUST_BASE_IMAGE,
            "debian_base_image": DEBIAN_BASE_IMAGE,
            "uv_lock_sha256": buflo_study.sha256_file(LAB_ROOT / "uv.lock"),
            "cargo_lock_sha256": buflo_study.sha256_file(LAB_ROOT / "neqo-qcsd/Cargo.lock"),
        },
        "build_execution": {
            "sha256": hashlib.sha256(
                (json.dumps(build_execution, indent=2, sort_keys=True) + "\n").encode()
            ).hexdigest(),
            "receipt": build_execution,
        },
        "clock_status": {
            "relationship": "container-shares-host-kernel-realtime-clock",
            "host": {
                "source": "timedatectl-NTPSynchronized-and-python-clock-gettime",
                "synchronized": True,
                "status_evidence": "NTPSynchronized=yes",
                "unavailable_reason": None,
                "realtime_unix_ns": 1_000_000_000_000,
                "monotonic_ns": 10_000,
            },
            "container": {
                "source": "python-clock-gettime-inside-collection-image",
                "synchronized": None,
                "status_evidence": None,
                "unavailable_reason": (
                    "container shares the host kernel clock and has no independent NTP service"
                ),
                "realtime_unix_ns": 1_000_000_000_001,
                "monotonic_ns": 20_000,
            },
        },
    }

    with pytest.raises(ValueError, match="schema 3 and build completion"):
        validate_study_environment_receipt(
            value, expected_image_digest="sha256:" + "a" * 64
        )
    historical_environment = validate_study_environment_receipt(
        value,
        expected_image_digest="sha256:" + "a" * 64,
        allow_historical=True,
    )
    assert historical_environment["image_id"] == "sha256:" + "a" * 64
    assert buflo_study._one_build_execution_identity(
        [historical_environment], allow_historical=True
    ) == {
        "cohort_version": build_execution["cohort_version"],
        "sha256": value["build_execution"]["sha256"],
        "collection_image": "sha256:" + "a" * 64,
        "started_at": build_execution["started_at"],
        "finished_at": build_execution["finished_at"],
    }
    with pytest.raises(ValueError, match="no typed no-cache build identity"):
        buflo_study._one_build_execution_identity([historical_environment])
    scheduled = json.loads(json.dumps(value))
    scheduled["schema_version"] = 2
    scheduled["docker"]["ncpu"] = 12
    scheduled["capture_scheduler"] = buflo_study._capture_scheduler_environment_contract()
    validated = validate_study_environment_receipt(
        scheduled,
        expected_image_digest="sha256:" + "a" * 64,
        allow_historical=True,
    )
    assert validated["capture_scheduler"]["client_affinity_cpus"] == [10]
    kernel_timed = json.loads(json.dumps(scheduled))
    kernel_timed["capture_scheduler"] = (
        buflo_study._buflo_etf_capture_scheduler_environment_contract()
    )
    kernel_validated = validate_study_environment_receipt(
        kernel_timed,
        expected_image_digest="sha256:" + "a" * 64,
        allow_historical=True,
    )
    assert kernel_validated["capture_scheduler"]["timed_egress_helper_affinity_cpus"] == [11]
    assert kernel_validated["capture_scheduler"]["timed_egress_helper_policy"] == "SCHED_RR"
    wrong_topology = json.loads(json.dumps(scheduled))
    wrong_topology["docker"]["ncpu"] = 16
    with pytest.raises(ValueError, match="exact 12-CPU topology"):
        validate_study_environment_receipt(wrong_topology, allow_historical=True)
    wrong_partition = json.loads(json.dumps(scheduled))
    wrong_partition["capture_scheduler"]["client_affinity_cpus"] = [9]
    with pytest.raises(ValueError, match="scheduler environment"):
        validate_study_environment_receipt(wrong_partition, allow_historical=True)
    changed = json.loads(json.dumps(value))
    changed["build_inputs"]["uv_lock_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="base image or lockfile"):
        validate_study_environment_receipt(changed, allow_historical=True)


def test_current_study_environment_binds_completion_and_projects_full_identity(
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "build-execution-v47.json"
    receipt, completion_path, completion = _write_schema5_build_pair(
        receipt_path, cohort_version=47
    )
    value = {
        "schema_version": 3,
        "artifact_type": "qcsd-buflo-study-environment",
        "docker": {
            "client_version": "29.0.1",
            "server_version": "29.0.1",
            "server_os": "linux",
            "server_arch": "x86_64",
            "ncpu": 12,
            "mem_total_bytes": 16_000_000_000,
            "storage_driver": "overlayfs",
        },
        "collection_image": {"id": "sha256:" + "a" * 64, "repo_digests": []},
        "build_inputs": dict(receipt["build_inputs"]),
        "build_execution": {
            "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            "receipt": receipt,
            "completion_path": "/lab/artifacts/buflo-study/build-completion-v47.json",
            "completion_sha256": hashlib.sha256(completion_path.read_bytes()).hexdigest(),
            "completion_payload_sha256": completion["payload_sha256"],
            "completion": completion,
        },
        "clock_status": {
            "relationship": "container-shares-host-kernel-realtime-clock",
            "host": {
                "source": "test-host-clock",
                "synchronized": True,
                "status_evidence": "NTPSynchronized=yes",
                "unavailable_reason": None,
                "realtime_unix_ns": 1_000_000_000_000,
                "monotonic_ns": 10_000,
            },
            "container": {
                "source": "test-container-clock",
                "synchronized": None,
                "status_evidence": None,
                "unavailable_reason": "shares host clock",
                "realtime_unix_ns": 1_000_000_000_001,
                "monotonic_ns": 20_000,
            },
        },
        "capture_scheduler": buflo_study._buflo_etf_capture_scheduler_environment_contract(),
    }

    validated = validate_study_environment_receipt(
        value, expected_image_digest="sha256:" + "a" * 64
    )
    identity = buflo_study._one_build_execution_identity([validated])

    assert identity == {
        "cohort_version": 47,
        "sha256": value["build_execution"]["sha256"],
        "completion_path": "/lab/artifacts/buflo-study/build-completion-v47.json",
        "completion_sha256": value["build_execution"]["completion_sha256"],
        "collection_image": "sha256:" + "a" * 64,
        "started_at": receipt["started_at"],
        "finished_at": receipt["finished_at"],
    }


def test_current_build_identity_rejects_historical_environment() -> None:
    build = {
        "cohort_version": 1,
        "sha256": "a" * 64,
        "collection_image": "sha256:" + "b" * 64,
        "started_at": "2026-09-01T00:00:00+00:00",
        "finished_at": "2026-09-01T00:00:01+00:00",
    }

    with pytest.raises(ValueError, match="no typed no-cache build identity"):
        buflo_study._one_build_execution_identity([{"build_execution": build}])

    # Immutable pre-completion environments remain inspectable only when the
    # caller explicitly selects the historical verification policy.
    assert buflo_study._one_build_execution_identity(
        [{"build_execution": build}], allow_historical=True
    ) == build


def test_public_study_network_receipt_proves_bridge_has_no_netem(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QCSD_STUDY_NETWORK_CONDITION", "public-docker-bridge-no-netem")
    monkeypatch.setattr(
        capture_session,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout='[{"kind":"noqueue","root":true}]',
        ),
    )
    receipt = capture_session._public_study_network_condition("eth0", {"verified": True})

    assert receipt is not None and receipt["valid"] is True
    diagnostics = {
        "network_condition": receipt,
        "offloads": [{"interface": "eth0", "verified": True}],
    }
    buflo_study._validate_public_network_condition(diagnostics)

    changed = json.loads(json.dumps(receipt))
    changed["observed_qdisc"] = [{"kind": "netem", "root": True}]
    changed["netem_present"] = True
    changed["valid"] = False
    with pytest.raises(ValueError, match="no-netem"):
        buflo_study._validate_public_network_condition(
            {**diagnostics, "network_condition": changed}
        )


def test_redirect_attestation_explicitly_binds_empty_prepared_and_final_sequences(
    tmp_path: Path,
) -> None:
    workload_id = "getbootstrap-home-r4"
    data = json.loads(
        (LAB_ROOT / f"config/workloads/{workload_id}.json").read_text(encoding="utf-8")
    )
    expected = {row["resource_id"]: row for row in data["preparation"]["expected_responses"]}
    responses = []
    for resource in data["resources"]:
        identity = expected[resource["id"]]
        responses.append(
            {
                "resource_id": resource["id"],
                "url": resource["url"],
                "status": identity["status"],
                "complete": True,
                "outcome": "succeeded",
            }
        )
    neqo = tmp_path / "neqo"
    neqo.mkdir()
    (neqo / "run.json").write_text(json.dumps({"responses": responses}), encoding="utf-8")

    receipt = orchestrator._redirect_attestation(
        SimpleNamespace(id=workload_id, data=data),
        tmp_path,
    )

    assert receipt["all_redirect_sequences_empty"] is True
    assert receipt["navigation"]["redirect_sequence"] == []
    assert all(
        row["prepared_redirect_sequence"] == [] and row["final_redirect_sequence"] == []
        for row in receipt["resources"]
    )


def test_client_resource_usage_parser_has_exact_nullable_contract(tmp_path: Path) -> None:
    source = tmp_path / "time.txt"
    source.write_text(
        "user_cpu_seconds=1.25\n"
        "system_cpu_seconds=0.50\n"
        "maximum_rss_kib=42\n"
        "voluntary_context_switches=7\n"
        "involuntary_context_switches=2\n",
        encoding="utf-8",
    )

    usage = _parse_client_resource_usage(source, 2.5)

    assert _client_resource_usage_valid(usage)
    assert usage["maximum_rss_bytes"] == 42 * 1_024
    assert usage["timer_wakeups"] is None
    assert usage["timer_wakeups_unavailable_reason"]
    assert usage["rapl_energy_joules"] is None
    assert usage["rapl_unavailable_reason"]


def test_completed_buflo_resource_receipt_binds_runner_timer_wakeups(tmp_path: Path) -> None:
    source = tmp_path / "time.txt"
    source.write_text(
        "user_cpu_seconds=1.25\n"
        "system_cpu_seconds=0.50\n"
        "maximum_rss_kib=42\n"
        "voluntary_context_switches=7\n"
        "involuntary_context_switches=2\n",
        encoding="utf-8",
    )
    usage = _parse_client_resource_usage(source, 2.5)
    metrics = {
        "schema_version": 1,
        "semantics": (
            "actual_select_return_source; socket_wins_simultaneous_readiness; "
            "controller_subset_is_effective_earliest_deadline; "
            "scheduled_cells_are_not_wakeups"
        ),
        "wait_returns": 31,
        "socket_readiness_wakeups": 11,
        "timer_wakeups": 20,
        "controller_deadline_timer_wakeups": 17,
        "other_timer_wakeups": 3,
    }

    assert _runner_wakeup_metrics_valid(metrics)
    assert _fidelity_runner_wakeup_metrics_valid(metrics)
    measured = _merge_runner_wakeup_metrics(usage, metrics, required=True)
    assert measured["source"] == "gnu-time-python-monotonic-and-runner-select-v1"
    assert measured["timer_wakeups"] == 20
    assert measured["timer_wakeups_unavailable_reason"] is None
    assert _client_resource_usage_valid(measured)

    historical_v2 = dict(metrics)
    historical_v2.update(
        {
            "schema_version": 2,
            "semantics": (
                f"{metrics['semantics']}; "
                "buflo_exact_release_guard_reserves_candidate_window; "
                "buflo_exact_release_active_wait_tail_us=250; "
                "buflo_exact_release_guards_are_separately_receipted_active_waits; "
                "buflo_active_defense_socket_drains_are_single_batch; "
                "buflo_active_defense_http_drains_are_single_event; "
                "buflo_output_is_interrupted_at_guard"
            ),
            "buflo_exact_release_guard_entries": 19,
            "buflo_exact_release_guard_wait_nanoseconds": 190_000_000,
            "buflo_exact_release_active_wait_nanoseconds": 4_750_000,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 73,
            "buflo_exact_release_max_guard_exit_lateness_nanoseconds": 41,
        }
    )
    assert _runner_wakeup_metrics_valid(historical_v2)
    assert _fidelity_runner_wakeup_metrics_valid(historical_v2)
    historical_measured = _merge_runner_wakeup_metrics(usage, historical_v2, required=True)
    assert historical_measured["timer_wakeups"] == 20

    historical_v3 = dict(historical_v2)
    historical_v3.update(
        {
            "schema_version": 3,
            "semantics": str(historical_v2["semantics"]).replace(
                "buflo_exact_release_active_wait_tail_us=250",
                "buflo_exact_release_active_wait_tail_us=5000",
            ),
        }
    )
    assert _runner_wakeup_metrics_valid(historical_v3)
    assert _fidelity_runner_wakeup_metrics_valid(historical_v3)

    historical_v4 = dict(historical_v3)
    v4_fields = _runner_wakeup_receipt_v4()
    for key in (
        "schema_version",
        "semantics",
        "cs_exact_incoming_retry_drives",
        "cs_exact_incoming_retry_resolutions",
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds",
    ):
        historical_v4[key] = v4_fields[key]
    assert _runner_wakeup_metrics_valid(historical_v4)
    assert _fidelity_runner_wakeup_metrics_valid(historical_v4)
    historical_v4_measured = _merge_runner_wakeup_metrics(usage, historical_v4, required=True)
    assert historical_v4_measured["timer_wakeups"] == 20

    historical_v5 = dict(historical_v4)
    v5_fields = _runner_wakeup_receipt_v5()
    for key in (
        "schema_version",
        "semantics",
        "buflo_exact_incoming_retry_drives",
        "buflo_exact_incoming_retry_resolutions",
        "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds",
    ):
        historical_v5[key] = v5_fields[key]
    historical_v5.update(
        {
            "buflo_exact_incoming_retry_drives": 3,
            "buflo_exact_incoming_retry_resolutions": 1,
            "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds": 250,
        }
    )
    assert _runner_wakeup_metrics_valid(historical_v5)
    assert _fidelity_runner_wakeup_metrics_valid(historical_v5)

    current = _runner_wakeup_receipt_v9(guard_entries=19)
    for key in (
        "wait_returns",
        "socket_readiness_wakeups",
        "timer_wakeups",
        "controller_deadline_timer_wakeups",
        "other_timer_wakeups",
        "buflo_exact_incoming_retry_drives",
        "buflo_exact_incoming_retry_resolutions",
        "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds",
        "cs_exact_incoming_retry_drives",
        "cs_exact_incoming_retry_resolutions",
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds",
    ):
        current[key] = historical_v5[key]
    assert _runner_wakeup_metrics_valid(current)
    assert _fidelity_runner_wakeup_metrics_valid(current)
    current_measured = _merge_runner_wakeup_metrics(usage, current, required=True)
    assert current_measured["timer_wakeups"] == 20
    assert not any(key.startswith("buflo_exact_incoming_retry_") for key in current_measured)

    inclusive_guard_boundary = dict(current)
    inclusive_guard_boundary["buflo_exact_release_active_wait_nanoseconds"] = current[
        "buflo_exact_release_guard_wait_nanoseconds"
    ]
    assert _runner_wakeup_metrics_valid(inclusive_guard_boundary)
    assert _fidelity_runner_wakeup_metrics_valid(inclusive_guard_boundary)

    invalid_active = dict(current)
    invalid_active["buflo_exact_release_active_wait_nanoseconds"] = (
        int(current["buflo_exact_release_guard_wait_nanoseconds"]) + 1
    )
    assert not _runner_wakeup_metrics_valid(invalid_active)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_active)

    invalid_empty = dict(current)
    invalid_empty["buflo_exact_release_guard_entries"] = 0
    assert not _runner_wakeup_metrics_valid(invalid_empty)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_empty)

    wrong_semantics = dict(current)
    wrong_semantics["semantics"] = historical_v2["semantics"]
    assert not _runner_wakeup_metrics_valid(wrong_semantics)
    assert not _fidelity_runner_wakeup_metrics_valid(wrong_semantics)

    missing_field = dict(current)
    missing_field.pop("buflo_exact_release_max_guard_exit_lateness_nanoseconds")
    assert not _runner_wakeup_metrics_valid(missing_field)
    assert not _fidelity_runner_wakeup_metrics_valid(missing_field)

    extra_field = {**current, "unexpected": 0}
    assert not _runner_wakeup_metrics_valid(extra_field)
    assert not _fidelity_runner_wakeup_metrics_valid(extra_field)

    for aliased_version in (True, 3.0):
        invalid_version = {**current, "schema_version": aliased_version}
        assert not _runner_wakeup_metrics_valid(invalid_version)
        assert not _fidelity_runner_wakeup_metrics_valid(invalid_version)

    invalid_retry_resolution = {
        **current,
        "cs_exact_incoming_retry_resolutions": 1,
    }
    assert not _runner_wakeup_metrics_valid(invalid_retry_resolution)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_retry_resolution)

    invalid_retry_lateness = {
        **current,
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds": 1,
    }
    assert not _runner_wakeup_metrics_valid(invalid_retry_lateness)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_retry_lateness)

    invalid_buflo_retry_resolution = {
        **current,
        "buflo_exact_incoming_retry_drives": 0,
        "buflo_exact_incoming_retry_resolutions": 1,
        "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds": 0,
    }
    assert not _runner_wakeup_metrics_valid(invalid_buflo_retry_resolution)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_buflo_retry_resolution)

    terminal_deadline_lateness_without_retry_drives = {
        **current,
        "buflo_exact_incoming_retry_drives": 0,
        "buflo_exact_incoming_retry_resolutions": 0,
        "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds": 1,
    }
    assert _runner_wakeup_metrics_valid(terminal_deadline_lateness_without_retry_drives)
    assert _fidelity_runner_wakeup_metrics_valid(terminal_deadline_lateness_without_retry_drives)

    with pytest.raises(ValueError, match="lacks runner wakeup metrics"):
        _merge_runner_wakeup_metrics(usage, None, required=True)

    invalid = dict(metrics)
    invalid["wait_returns"] += 1
    assert not _runner_wakeup_metrics_valid(invalid)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid)
    with pytest.raises(ValueError, match="wake.*invalid"):
        _merge_runner_wakeup_metrics(usage, invalid, required=True)


def test_extended_schedule_reconciles_typed_partial_composition(tmp_path: Path) -> None:
    neqo = tmp_path / "neqo"
    neqo.mkdir()
    path = neqo / "schedule.csv"
    fields = SCHEDULE_PREFIX_FIELDS + SCHEDULE_QCSD_FIELDS
    rows = [
        _typed_schedule_row(0, "outgoing", "full", 600, 600, 3),
        _typed_schedule_row(
            1,
            "outgoing",
            "partial",
            600,
            500,
            9,
            reason="congestion_limited",
        ),
        _typed_schedule_row(
            2,
            "outgoing",
            "suppressed",
            600,
            0,
            4,
            reason="congestion_limited",
        ),
        _typed_schedule_row(3, "incoming", "satisfied", 600, None, None),
    ]
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    metrics = _schedule_realization_metrics(tmp_path)

    assert metrics["typed_congestion_reason_column"] is True
    assert metrics["typed_credit_advertisement_columns"] is True
    assert metrics["typed_credit_consumption_columns"] is True
    assert metrics["typed_controller_terminal_time_column"] is True
    assert len(metrics["terminal_defense_elapsed_us_values"]) == 4
    assert metrics["incoming_credit_advertised_events"] == 1
    assert metrics["incoming_credit_consumed_events"] == 1
    assert metrics["incoming_credit_advertisement_delay_us_max"] == 100
    assert metrics["incoming_credit_consumption_delay_us_max"] == 500
    assert metrics["invalid_typed_outcome_rows"] == 0
    assert metrics["invalid_congestion_reason_events"] == 0
    assert metrics["terminal_slots_unique"] is True
    assert metrics["terminal_desired_outgoing_bytes"] == 1_800
    assert metrics["terminal_observed_outgoing_bytes"] == 1_100
    assert metrics["typed_lateness_us_total"] == 16
    assert metrics["typed_lateness_us_max"] == 9
    assert sum(metrics["typed_composition_bytes"].values()) == 1_100

    rows[-1]["credit_consumed_at_us"] = 50
    rows[-1]["credit_consumption_delay_us"] = 50
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    invalid = _schedule_realization_metrics(tmp_path)
    assert invalid["incoming_credit_consumed_events"] == 0
    assert invalid["invalid_credit_consumption_events"] == 1


def test_buflo_fidelity_requires_every_zero_error_and_typed_terminal_once() -> None:
    diagnostics = {
        **_incoming_credit(501 * 1_200),
        "buflo_paper_equivalent": False,
        "buflo_client_only": True,
        "buflo_scheduled_outgoing_cells": 501,
        "buflo_scheduled_incoming_cells": 501,
        "buflo_full_outgoing_cells": 501,
        "buflo_partial_outgoing_cells": 0,
        "buflo_suppressed_outgoing_cells": 0,
        "buflo_missed_outgoing_cells": 0,
        "buflo_missed_incoming_cells": 0,
        "buflo_outgoing_unresolved_cells": 0,
        "buflo_incoming_unresolved_cells": 0,
        "buflo_catch_up_outgoing_cells": 0,
        "buflo_catch_up_incoming_cells": 0,
        "buflo_egress_backlog_pending": False,
        "buflo_application_complete": True,
        "buflo_minimum_duration_reached": True,
        "buflo_event_guard_triggered": False,
        "buflo_terminal_subcell_pending_request_cancellations": 0,
        "buflo_terminal_subcell_stream_cancellations": 0,
        "buflo_terminal_subcell_exact_capacity_bytes_cancelled": 0,
        "buflo_terminal_subcell_latched": True,
        "buflo_terminal_subcell_latched_at_us": 10_000_001,
        "buflo_terminal_subcell_open_streams_at_latch": 0,
        "buflo_terminal_subcell_parser_lease_bytes_at_latch": 0,
        "buflo_terminal_subcell_pending_parser_boundaries_at_latch": 0,
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch": 0,
        "buflo_schedule_stop_latched": True,
        "buflo_schedule_stop_latched_at_us": 10_000_000,
        "buflo_schedule_stop_available_bytes": 0,
        "buflo_schedule_stop_required_bytes": 1_200,
        "buflo_schedule_stop_scheduled_incoming_cells": 501,
        "buflo_schedule_stop_scheduled_outgoing_cells": 501,
        "buflo_schedule_stop_terminal_incoming_cells": 501,
        "buflo_schedule_stop_terminal_outgoing_cells": 501,
    }
    schedule = _schedule_metrics(outgoing=501, incoming=501)
    canonical_targets = list(range(0, 10_000_001, 20_000))
    schedule.update(
        terminal_satisfactions={"satisfied": 1_002},
        target_times_us_by_direction={
            "outgoing": canonical_targets,
            "incoming": canonical_targets,
        },
        scheduled_sizes_by_direction={
            "outgoing": [1_200] * 501,
            "incoming": [1_200] * 501,
        },
    )

    assert fidelity_eligible(
        "buflo",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    terminally_reordered = {
        **schedule,
        "target_times_us_by_direction": {
            "outgoing": canonical_targets,
            # Incoming rows are emitted at credit consumption.  Preserve the
            # complete cadence while emulating one credit consumed after later
            # targets on another stream or endpoint.
            "incoming": [
                *canonical_targets[:114],
                *canonical_targets[115:155],
                canonical_targets[114],
                *canonical_targets[155:],
            ],
        },
    }
    assert fidelity_eligible(
        "buflo",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=terminally_reordered,
    )
    missing_cadence_target = {
        **terminally_reordered,
        "target_times_us_by_direction": {
            **terminally_reordered["target_times_us_by_direction"],
            "incoming": [
                *terminally_reordered["target_times_us_by_direction"]["incoming"][:-1],
                canonical_targets[-2],
            ],
        },
    }
    assert not fidelity_eligible(
        "buflo",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=missing_cadence_target,
    )
    inside_advertisement_limit = {
        **schedule,
        "incoming_credit_advertisement_delay_us_max": 4_999,
    }
    assert fidelity_eligible(
        "buflo",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=inside_advertisement_limit,
    )
    at_advertisement_limit = {
        **schedule,
        "incoming_credit_advertisement_delay_us_max": 5_000,
    }
    assert not fidelity_eligible(
        "buflo",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=at_advertisement_limit,
    )
    run = {
        "completion_status": "complete",
        "error": None,
        "error_class": None,
        "terminal_evidence_render_errors": [],
        "runner_wakeup_metrics": _runner_wakeup_receipt(),
        "resolved_configuration": {"schema_version": 2, "defense": {"kind": "buflo"}},
        "defense_diagnostics": diagnostics,
        "buflo_summary": {
            "schema_version": 4,
            "kind": "buflo",
            "implementation_scope": "client_only_quic",
            "paper_equivalent": False,
            "incoming_opportunity_semantics": (
                "client_receive_credit_and_response_qualified_chaff_attempt"
            ),
            "unavailable_peer_properties": [
                "scheduled_server_datagram_timing",
                "scheduled_server_datagram_size",
            ],
            "terminal_subcell_policy": (
                "drain_whole_cells_then_client_local_http3_cancel_unallocatable_reviewed_chaff_tail"
            ),
            "terminal_subcell_observer_effect": (
                "typed_stop_sending_and_reset_stream_defense_control_may_follow_the_last_exact_cell"
            ),
            "terminal_schedule_stop_policy": BUFLO_SCHEDULE_STOP_POLICY,
            "diagnostics": diagnostics,
        },
        "chaff_responses": [],
        "cs_buflo_summary": None,
    }
    assert new_defense_terminal_receipts_valid(run, "buflo", require_application_complete=True)
    contradictory_error = json.loads(json.dumps(run))
    contradictory_error["error_class"] = "client-defense-fidelity-v1"
    assert not new_defense_terminal_receipts_valid(
        contradictory_error, "buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        run,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v2_wakeups = json.loads(json.dumps(run))
    historical_v2_wakeups["runner_wakeup_metrics"] = {
        **_runner_wakeup_receipt_v2(),
        "buflo_exact_release_guard_entries": 19,
        "buflo_exact_release_guard_wait_nanoseconds": 190_000_000,
        "buflo_exact_release_active_wait_nanoseconds": 4_750_000,
        "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 73,
        "buflo_exact_release_max_guard_exit_lateness_nanoseconds": 41,
    }
    assert new_defense_terminal_receipts_valid(
        historical_v2_wakeups, "buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v2_wakeups,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v3_wakeups = json.loads(json.dumps(historical_v2_wakeups))
    historical_v3_wakeups["runner_wakeup_metrics"] = {
        **historical_v2_wakeups["runner_wakeup_metrics"],
        "schema_version": 3,
        "semantics": _runner_wakeup_receipt_v3()["semantics"],
    }
    assert new_defense_terminal_receipts_valid(
        historical_v3_wakeups, "buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v3_wakeups,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v4_wakeups = json.loads(json.dumps(historical_v3_wakeups))
    historical_v4_wakeups["runner_wakeup_metrics"].update(
        {
            key: value
            for key, value in _runner_wakeup_receipt_v4().items()
            if key
            in {
                "schema_version",
                "semantics",
                "cs_exact_incoming_retry_drives",
                "cs_exact_incoming_retry_resolutions",
                "cs_exact_incoming_retry_max_phase_lateness_nanoseconds",
            }
        }
    )
    assert new_defense_terminal_receipts_valid(
        historical_v4_wakeups, "buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v4_wakeups,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v5_wakeups = json.loads(json.dumps(historical_v4_wakeups))
    historical_v5_wakeups["runner_wakeup_metrics"].update(
        {
            key: value
            for key, value in _runner_wakeup_receipt_v5().items()
            if key
            in {
                "schema_version",
                "semantics",
                "buflo_exact_incoming_retry_drives",
                "buflo_exact_incoming_retry_resolutions",
                "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds",
            }
        }
    )
    historical_v5_wakeups["runner_wakeup_metrics"].update(
        {
            "buflo_exact_incoming_retry_drives": 3,
            "buflo_exact_incoming_retry_resolutions": 1,
            "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds": 250,
        }
    )
    assert new_defense_terminal_receipts_valid(
        historical_v5_wakeups, "buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v5_wakeups,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    current_wakeups = json.loads(json.dumps(historical_v5_wakeups))
    current_wakeups["runner_wakeup_metrics"] = {
        **_runner_wakeup_receipt_v10(guard_entries=500),
        "buflo_exact_incoming_retry_drives": 3,
        "buflo_exact_incoming_retry_resolutions": 1,
        "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds": 250,
    }
    assert not new_defense_terminal_receipts_valid(
        current_wakeups,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    missing_authoritative_confirmation = json.loads(json.dumps(current_wakeups))
    missing_authoritative_confirmation["runner_wakeup_metrics"][
        "buflo_exact_release_active_wait_instant_confirmations"
    ] -= 1
    assert not new_defense_terminal_receipts_valid(
        missing_authoritative_confirmation,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    extra_success_calibration = json.loads(json.dumps(current_wakeups))
    extra_success_calibration["runner_wakeup_metrics"][
        "buflo_exact_release_active_wait_counter_calibrations"
    ] += 1
    assert not new_defense_terminal_receipts_valid(
        extra_success_calibration,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    invalid_cs_retry_metrics = json.loads(json.dumps(current_wakeups))
    invalid_cs_retry_metrics["runner_wakeup_metrics"]["cs_exact_incoming_retry_drives"] = 1
    assert not new_defense_terminal_receipts_valid(
        invalid_cs_retry_metrics, "buflo", require_application_complete=True
    )
    historical_v3 = json.loads(json.dumps(current_wakeups))
    historical_v3["buflo_summary"]["schema_version"] = 3
    historical_v3["buflo_summary"].pop("terminal_schedule_stop_policy")
    for key in BUFLO_SCHEDULE_STOP_V4_KEYS:
        historical_v3["defense_diagnostics"].pop(key)
        historical_v3["buflo_summary"]["diagnostics"].pop(key)
    assert new_defense_terminal_receipts_valid(
        historical_v3, "buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v3,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    legacy_run = json.loads(json.dumps(historical_v3))
    legacy_run["buflo_summary"]["schema_version"] = 2
    legacy_run["defense_diagnostics"].pop(
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch"
    )
    legacy_run["buflo_summary"]["diagnostics"].pop(
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch"
    )
    assert new_defense_terminal_receipts_valid(
        legacy_run, "buflo", require_application_complete=True
    )
    for missing in BUFLO_SCHEDULE_STOP_V4_KEYS:
        partial = json.loads(json.dumps(current_wakeups))
        partial["defense_diagnostics"].pop(missing)
        partial["buflo_summary"]["diagnostics"].pop(missing)
        assert not new_defense_terminal_receipts_valid(
            partial, "buflo", require_application_complete=True
        )
    for key, changed in (
        ("buflo_schedule_stop_latched", False),
        ("buflo_schedule_stop_latched_at_us", 10_000_002),
        ("buflo_schedule_stop_available_bytes", 1_200),
        ("buflo_schedule_stop_required_bytes", 1_199),
        ("buflo_schedule_stop_scheduled_incoming_cells", 500),
        ("buflo_schedule_stop_scheduled_outgoing_cells", 500),
        ("buflo_schedule_stop_terminal_incoming_cells", 502),
        ("buflo_schedule_stop_terminal_outgoing_cells", 500),
    ):
        invalid = json.loads(json.dumps(current_wakeups))
        invalid["defense_diagnostics"][key] = changed
        invalid["buflo_summary"]["diagnostics"][key] = changed
        assert not new_defense_terminal_receipts_valid(
            invalid, "buflo", require_application_complete=True
        )
    drifted_policy = json.loads(json.dumps(current_wakeups))
    drifted_policy["buflo_summary"]["terminal_schedule_stop_policy"] = "drifted"
    assert not new_defense_terminal_receipts_valid(
        drifted_policy, "buflo", require_application_complete=True
    )
    for key in (
        "buflo_partial_outgoing_cells",
        "buflo_missed_outgoing_cells",
        "buflo_catch_up_incoming_cells",
        "buflo_outgoing_unresolved_cells",
    ):
        changed = dict(diagnostics)
        changed[key] = 1
        assert not fidelity_eligible(
            "buflo",
            changed,
            sample_eligible=True,
            missed_events=0,
            outgoing_size_mismatches=0,
            schedule_metrics=schedule,
        )


def test_current_buflo_terminal_receipt_requires_schema_fifteen_kernel_tx() -> None:
    from tests.test_buflo_handoff import _complete_buflo_run
    from tests.test_kernel_tx import _runner_wakeup_v14, _runner_wakeup_v15

    schema_ten = _complete_buflo_run(
        scheduled_outgoing=1,
        scheduled_incoming=1,
        current_runner=False,
    )
    assert not new_defense_terminal_receipts_valid(
        schema_ten,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )

    historical = json.loads(json.dumps(schema_ten))
    historical["runner_wakeup_metrics"] = _runner_wakeup_v14()
    assert not new_defense_terminal_receipts_valid(
        historical,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )

    current = json.loads(json.dumps(schema_ten))
    current["runner_wakeup_metrics"] = _runner_wakeup_v15()
    assert new_defense_terminal_receipts_valid(
        current,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )

    missing_kernel_receipt = json.loads(json.dumps(current))
    missing_kernel_receipt["runner_wakeup_metrics"]["buflo_kernel_tx"] = None
    assert not new_defense_terminal_receipts_valid(
        missing_kernel_receipt,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )


def test_cs_buflo_fidelity_reconciles_typed_composition_and_rate_state() -> None:
    composition = {
        "application_stream_bytes": 400,
        "retransmission_stream_bytes": 100,
        "chaff_stream_bytes": 200,
        "defense_control_bytes": 2,
        "quic_padding_bytes": 300,
        "other_quic_bytes": 98,
    }
    diagnostics = {
        **_incoming_credit(600),
        "cs_buflo_paper_equivalent": False,
        "cs_buflo_client_only": True,
        "cs_buflo_payload_padding": True,
        "cs_buflo_total_padding": False,
        "cs_buflo_early_termination_semantics": (
            "client_only_outgoing_observed_udp_and_incoming_consumed_credit_power_of_two_crossing"
        ),
        "cs_buflo_scheduled_outgoing_cells": 2,
        "cs_buflo_scheduled_incoming_cells": 1,
        "cs_buflo_full_outgoing_cells": 1,
        "cs_buflo_partial_outgoing_cells": 1,
        "cs_buflo_suppressed_outgoing_cells": 0,
        "cs_buflo_missed_outgoing_cells": 0,
        "cs_buflo_missed_incoming_cells": 0,
        "cs_buflo_desired_udp_bytes": 1_200,
        "cs_buflo_realized_udp_bytes": 1_100,
        **{f"cs_buflo_{key}": value for key, value in composition.items()},
        "cs_buflo_lateness_us_total": 12,
        "cs_buflo_lateness_us_max": 9,
        "cs_buflo_natural_outgoing_bytes": 500,
        "cs_buflo_natural_incoming_bytes": 300,
        "cs_buflo_cover_outgoing_bytes": 100,
        "cs_buflo_cover_incoming_bytes": 212,
        "cs_buflo_real_bearing_outgoing_bytes": 400,
        "cs_buflo_real_bearing_incoming_bytes": 300,
        "cs_buflo_realized_incoming_credit_bytes": 600,
        "cs_buflo_outgoing_padding_basis_natural_bytes": 500,
        "cs_buflo_incoming_padding_basis_natural_bytes": 300,
        "cs_buflo_outgoing_padding_basis_cover_bytes": 100,
        "cs_buflo_incoming_padding_basis_cover_bytes": 212,
        "cs_buflo_outgoing_padding_basis_total_bytes": 600,
        "cs_buflo_incoming_padding_basis_total_bytes": 512,
        "cs_buflo_reference_tcp_write_size_bytes": 548,
        "cs_buflo_reference_nominal_tcp_packet_size_bytes": 600,
        "cs_buflo_runtime_udp_packet_size_bytes": 600,
        "cs_buflo_outgoing_termination_accounted_bytes": 1_100,
        "cs_buflo_incoming_termination_accounted_bytes": 600,
        "cs_buflo_outgoing_last_termination_increment_bytes": 100,
        "cs_buflo_incoming_last_termination_increment_bytes": 600,
        "cs_buflo_outgoing_power_of_two_crossed": True,
        "cs_buflo_incoming_power_of_two_crossed": True,
        "cs_buflo_early_termination_translation_version": 2,
        "cs_buflo_termination_stop_policy": CS_BUFLO_TERMINATION_STOP_POLICY,
        "cs_buflo_outgoing_termination_stop_latched": True,
        "cs_buflo_incoming_termination_stop_latched": True,
        "cs_buflo_outgoing_termination_stop_crossing_total_bytes": 1_100,
        "cs_buflo_incoming_termination_stop_crossing_total_bytes": 0,
        "cs_buflo_outgoing_termination_stop_crossing_increment_bytes": 100,
        "cs_buflo_incoming_termination_stop_crossing_increment_bytes": 0,
        "cs_buflo_outgoing_termination_stop_reason": "power_of_two_crossing",
        "cs_buflo_incoming_termination_stop_reason": "padding_target_reached",
        "cs_buflo_outgoing_termination_stop_phase": "application_complete",
        "cs_buflo_incoming_termination_stop_phase": "application_complete",
        "cs_buflo_outgoing_termination_stop_latched_at_us": 1_900_000,
        "cs_buflo_incoming_termination_stop_latched_at_us": 1_800_000,
        "cs_buflo_outgoing_termination_stop_scheduled_cells_at_stop": 2,
        "cs_buflo_incoming_termination_stop_scheduled_cells_at_stop": 1,
        "cs_buflo_outgoing_termination_stop_terminal_cells_at_stop": 2,
        "cs_buflo_incoming_termination_stop_terminal_cells_at_stop": 1,
        "cs_buflo_outgoing_termination_stop_progress_bytes_at_stop": 600,
        "cs_buflo_incoming_termination_stop_progress_bytes_at_stop": 512,
        "cs_buflo_outgoing_termination_stop_padding_target_bytes_at_stop": 1_024,
        "cs_buflo_incoming_termination_stop_padding_target_bytes_at_stop": 512,
        "cs_buflo_outgoing_termination_stop_provisional_invalidation_count": 0,
        "cs_buflo_incoming_termination_stop_provisional_invalidation_count": 0,
        "cs_buflo_outgoing_padding_target_bytes": 1_024,
        "cs_buflo_incoming_padding_target_bytes": 512,
        "cs_buflo_outgoing_interval_us": 8_192,
        "cs_buflo_incoming_interval_us": 8_192,
        "cs_buflo_outgoing_rate_adaptations": 0,
        "cs_buflo_incoming_rate_adaptations": 0,
        "cs_buflo_rate_boundary_translation_version": 2,
        "cs_buflo_rate_boundary_counter_semantics": (
            "client_only_quic_fresh_application_stream_bytes_outgoing_"
            "retransmission_excluded_and_consumed_application_offsets_incoming"
        ),
        "cs_buflo_author_rate_boundary_counter_semantics": (
            "per_direction_actually_transmitted_real_plus_junk_bytes"
        ),
        "cs_buflo_rate_transitions": [],
        "cs_buflo_next_outgoing_adaptation_boundary_bytes": 16_384,
        "cs_buflo_next_incoming_adaptation_boundary_bytes": 16_384,
        "cs_buflo_outgoing_estimator_samples": 4,
        "cs_buflo_incoming_estimator_samples": 2,
        "cs_buflo_outgoing_minimum_interval_opportunities": 0,
        "cs_buflo_incoming_minimum_interval_opportunities": 0,
        "cs_buflo_incoming_minimum_interval_local_realized": 0,
        "cs_buflo_outgoing_minimum_interval_terminal": 0,
        "cs_buflo_incoming_minimum_interval_terminal": 0,
        "cs_buflo_outgoing_minimum_interval_full": 0,
        "cs_buflo_incoming_minimum_interval_full": 0,
        "cs_buflo_incoming_local_realized_cells": 1,
        "cs_buflo_outgoing_unresolved_cells": 0,
        "cs_buflo_incoming_unresolved_cells": 0,
        "cs_buflo_egress_backlog_pending": False,
        "cs_buflo_application_complete": True,
        "cs_buflo_quiet_time_reached": True,
        "cs_buflo_local_termination_latched": True,
        "cs_buflo_local_et_pending_request_cancellations": 0,
        "cs_buflo_local_et_stream_cancellations": 0,
        "cs_buflo_local_et_latched_at_us": 2_000_000,
        "cs_buflo_local_et_before_application_complete": False,
        "cs_buflo_local_et_application_receive_streams_handed_off": 0,
        "cs_buflo_local_et_application_parser_boundaries_handed_off": 0,
        "cs_buflo_local_et_application_parser_lease_bytes_handed_off": 0,
        "cs_buflo_local_et_application_send_endpoints_released": 0,
        "cs_buflo_post_local_et_natural_outgoing_bytes": 0,
        "cs_buflo_post_local_et_natural_incoming_bytes": 0,
        "cs_buflo_event_guard_triggered": False,
    }
    schedule = _schedule_metrics(outgoing=2, incoming=1)
    schedule.update(
        terminal_satisfactions={"full": 1, "partial": 1, "satisfied": 1},
        terminal_desired_outgoing_bytes=1_200,
        terminal_observed_outgoing_bytes=1_100,
        congestion_reasons={"congestion_limited": 1},
        typed_composition_bytes=composition,
        typed_lateness_us_total=12,
        typed_lateness_us_max=9,
        typed_real_bearing_outgoing_bytes=400,
    )

    assert fidelity_eligible(
        "cs-buflo-cpsp",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    run = {
        "completion_status": "complete",
        "error": None,
        "error_class": None,
        "terminal_evidence_render_errors": [],
        "runner_wakeup_metrics": _runner_wakeup_receipt(),
        "resolved_configuration": {
            "schema_version": 2,
            "defense": {"kind": "cs_buflo"},
        },
        "defense_diagnostics": diagnostics,
        "buflo_summary": None,
        "cs_buflo_summary": {
            "schema_version": 4,
            "kind": "cs_buflo",
            "implementation_scope": "client_only_quic",
            "paper_equivalent": False,
            "incoming_opportunity_semantics": (
                "client_receive_credit_and_response_qualified_chaff_attempt"
            ),
            "unavailable_peer_properties": [
                "scheduled_server_datagram_timing",
                "scheduled_server_datagram_size",
            ],
            "incoming_cadence_boundary": ("complete_local_on_wire_max_stream_data_advertisement"),
            "incoming_terminal_boundary": "eventual_peer_stream_offset_consumption",
            "incoming_boundary_separation": (
                "advertisement_rearms_cadence_but_does_not_claim_peer_datagram_or_consumption"
            ),
            "early_termination_semantics": (
                "client_only_outgoing_observed_udp_and_incoming_consumed_credit_"
                "power_of_two_crossing"
            ),
            "early_termination_translation_version": 2,
            "termination_stop_policy": CS_BUFLO_TERMINATION_STOP_POLICY,
            "diagnostics": diagnostics,
        },
    }
    assert new_defense_terminal_receipts_valid(run, "cs_buflo", require_application_complete=True)
    assert not new_defense_terminal_receipts_valid(
        run,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    invalid_summary_version = json.loads(json.dumps(run))
    invalid_summary_version["cs_buflo_summary"]["early_termination_translation_version"] = 2.0
    assert not new_defense_terminal_receipts_valid(
        invalid_summary_version, "cs_buflo", require_application_complete=True
    )
    invalid_stop = json.loads(json.dumps(run))
    invalid_stop["defense_diagnostics"]["cs_buflo_incoming_termination_stop_latched"] = False
    invalid_stop["cs_buflo_summary"]["diagnostics"][
        "cs_buflo_incoming_termination_stop_latched"
    ] = False
    assert not new_defense_terminal_receipts_valid(
        invalid_stop, "cs_buflo", require_application_complete=True
    )
    invalid_crossing = json.loads(json.dumps(run))
    invalid_crossing["defense_diagnostics"][
        "cs_buflo_incoming_termination_stop_crossing_total_bytes"
    ] = 700
    invalid_crossing["cs_buflo_summary"]["diagnostics"][
        "cs_buflo_incoming_termination_stop_crossing_total_bytes"
    ] = 700
    assert not new_defense_terminal_receipts_valid(
        invalid_crossing, "cs_buflo", require_application_complete=True
    )

    historical_v2_wakeups = json.loads(json.dumps(run))
    historical_v2_wakeups["runner_wakeup_metrics"] = _runner_wakeup_receipt_v2()
    assert new_defense_terminal_receipts_valid(
        historical_v2_wakeups, "cs_buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v2_wakeups,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v3_wakeups = json.loads(json.dumps(run))
    historical_v3_wakeups["runner_wakeup_metrics"] = _runner_wakeup_receipt_v3()
    assert new_defense_terminal_receipts_valid(
        historical_v3_wakeups, "cs_buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v3_wakeups,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v4_wakeups = json.loads(json.dumps(run))
    historical_v4_wakeups["runner_wakeup_metrics"] = {
        **_runner_wakeup_receipt_v4(),
        "cs_exact_incoming_retry_drives": 3,
        "cs_exact_incoming_retry_resolutions": 1,
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds": 250,
    }
    assert new_defense_terminal_receipts_valid(
        historical_v4_wakeups, "cs_buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v4_wakeups,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v5_wakeups = json.loads(json.dumps(historical_v4_wakeups))
    historical_v5_wakeups["runner_wakeup_metrics"] = {
        **_runner_wakeup_receipt_v5(),
        "cs_exact_incoming_retry_drives": 3,
        "cs_exact_incoming_retry_resolutions": 1,
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds": 250,
    }
    assert new_defense_terminal_receipts_valid(
        historical_v5_wakeups, "cs_buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v5_wakeups,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    current_wakeups = json.loads(json.dumps(historical_v5_wakeups))
    current_wakeups["runner_wakeup_metrics"] = {
        **_runner_wakeup_receipt_v10(),
        "cs_exact_incoming_retry_drives": 3,
        "cs_exact_incoming_retry_resolutions": 1,
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds": 250,
    }
    assert new_defense_terminal_receipts_valid(
        current_wakeups,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    invalid_wakeups = json.loads(json.dumps(current_wakeups))
    invalid_wakeups["runner_wakeup_metrics"]["buflo_exact_release_guard_entries"] = 1
    invalid_wakeups["runner_wakeup_metrics"]["buflo_exact_release_guard_wait_nanoseconds"] = 1
    assert not new_defense_terminal_receipts_valid(
        invalid_wakeups, "cs_buflo", require_application_complete=True
    )
    invalid_buflo_retry_wakeups = json.loads(json.dumps(current_wakeups))
    invalid_buflo_retry_wakeups["runner_wakeup_metrics"]["buflo_exact_incoming_retry_drives"] = 1
    assert not new_defense_terminal_receipts_valid(
        invalid_buflo_retry_wakeups, "cs_buflo", require_application_complete=True
    )

    legacy_v3 = json.loads(json.dumps(run))
    legacy_v3["cs_buflo_summary"]["schema_version"] = 3
    legacy_v3["cs_buflo_summary"].pop("early_termination_translation_version")
    legacy_v3["cs_buflo_summary"].pop("termination_stop_policy")
    legacy_v3["defense_diagnostics"]["cs_buflo_early_termination_semantics"] = (
        "udp_client_only_observed_udp_power_of_two_crossing"
    )
    legacy_v3["cs_buflo_summary"]["early_termination_semantics"] = (
        "udp_client_only_observed_udp_power_of_two_crossing"
    )
    legacy_v3["cs_buflo_summary"]["diagnostics"]["cs_buflo_early_termination_semantics"] = (
        "udp_client_only_observed_udp_power_of_two_crossing"
    )
    for key in CS_BUFLO_STOP_DRAIN_V4_KEYS:
        legacy_v3["defense_diagnostics"].pop(key)
        legacy_v3["cs_buflo_summary"]["diagnostics"].pop(key)
    assert new_defense_terminal_receipts_valid(
        legacy_v3, "cs_buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        legacy_v3,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )

    legacy = json.loads(json.dumps(legacy_v3))
    legacy["cs_buflo_summary"]["schema_version"] = 2
    for key in (
        "cs_buflo_local_et_latched_at_us",
        "cs_buflo_local_et_before_application_complete",
        "cs_buflo_local_et_application_receive_streams_handed_off",
        "cs_buflo_local_et_application_parser_boundaries_handed_off",
        "cs_buflo_local_et_application_parser_lease_bytes_handed_off",
        "cs_buflo_local_et_application_send_endpoints_released",
        "cs_buflo_post_local_et_natural_outgoing_bytes",
        "cs_buflo_post_local_et_natural_incoming_bytes",
    ):
        legacy["defense_diagnostics"].pop(key)
        legacy["cs_buflo_summary"]["diagnostics"].pop(key)
    assert new_defense_terminal_receipts_valid(
        legacy, "cs_buflo", require_application_complete=True
    )
    wrong_boundary = json.loads(json.dumps(run))
    wrong_boundary["cs_buflo_summary"]["incoming_terminal_boundary"] = "local-advertisement"
    assert not new_defense_terminal_receipts_valid(
        wrong_boundary, "cs_buflo", require_application_complete=True
    )
    wrong_nested = json.loads(json.dumps(run))
    wrong_nested["cs_buflo_summary"]["diagnostics"]["scheduled_incoming_consumed_bytes"] -= 1
    assert not new_defense_terminal_receipts_valid(
        wrong_nested, "cs_buflo", require_application_complete=True
    )
    quiet_only = json.loads(json.dumps(run))
    quiet_only["defense_diagnostics"]["cs_buflo_application_complete"] = False
    quiet_only["cs_buflo_summary"]["diagnostics"]["cs_buflo_application_complete"] = False
    quiet_only["defense_diagnostics"]["cs_buflo_local_et_before_application_complete"] = True
    quiet_only["cs_buflo_summary"]["diagnostics"][
        "cs_buflo_local_et_before_application_complete"
    ] = True
    quiet_only["defense_diagnostics"]["cs_buflo_local_et_application_send_endpoints_released"] = 1
    quiet_only["cs_buflo_summary"]["diagnostics"][
        "cs_buflo_local_et_application_send_endpoints_released"
    ] = 1
    assert new_defense_terminal_receipts_valid(quiet_only, "cs_buflo")
    assert not new_defense_terminal_receipts_valid(
        quiet_only, "cs_buflo", require_application_complete=True
    )
    pre_onload = dict(diagnostics)
    pre_onload.update(
        cs_buflo_local_et_before_application_complete=True,
        cs_buflo_local_et_application_receive_streams_handed_off=1,
        cs_buflo_post_local_et_natural_outgoing_bytes=50,
        cs_buflo_post_local_et_natural_incoming_bytes=25,
        cs_buflo_natural_outgoing_bytes=550,
        cs_buflo_natural_incoming_bytes=325,
    )
    assert fidelity_eligible(
        "cs-buflo-cpsp",
        pre_onload,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    for key, value in (
        ("cs_buflo_local_et_application_receive_streams_handed_off", 0),
        ("cs_buflo_natural_outgoing_bytes", 549),
        ("cs_buflo_real_bearing_incoming_bytes", 301),
    ):
        invalid_pre_onload = dict(pre_onload)
        invalid_pre_onload[key] = value
        assert not fidelity_eligible(
            "cs-buflo-cpsp",
            invalid_pre_onload,
            sample_eligible=True,
            missed_events=0,
            outgoing_size_mismatches=0,
            schedule_metrics=schedule,
        )
    changed = dict(diagnostics)
    changed["cs_buflo_quic_padding_bytes"] += 1
    assert not fidelity_eligible(
        "cs-buflo",
        changed,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    changed = dict(diagnostics)
    changed["cs_buflo_rate_boundary_counter_semantics"] = "author-counter"
    assert not fidelity_eligible(
        "cs-buflo",
        changed,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    for key, value in (
        ("cs_buflo_incoming_local_realized_cells", 0),
        ("cs_buflo_incoming_minimum_interval_local_realized", 1),
        ("scheduled_incoming_advertised_bytes", 599),
    ):
        changed = dict(diagnostics)
        changed[key] = value
        assert not fidelity_eligible(
            "cs-buflo",
            changed,
            sample_eligible=True,
            missed_events=0,
            outgoing_size_mismatches=0,
            schedule_metrics=schedule,
        )


def test_cs_buflo_rate_transition_vector_is_causally_validated() -> None:
    from qcsd_lab.fidelity import _cs_buflo_rate_transition_vector_valid

    transition = {
        "schema_version": 1,
        "direction": "outgoing",
        "at_us": 50_000,
        "boundary_bytes": 16_384,
        "real_bearing_bytes": 17_000,
        "eligible_samples": 4,
        "median_interval_us": 6_000,
        "previous_interval_us": 8_192,
        "resulting_interval_us": 4_096,
        "retained_current_interval": False,
    }
    assert _cs_buflo_rate_transition_vector_valid([transition])
    for key, value in (
        ("boundary_bytes", 32_768),
        ("real_bearing_bytes", 1_000),
        ("resulting_interval_us", 8_192),
        ("retained_current_interval", True),
    ):
        changed = {**transition, key: value}
        assert not _cs_buflo_rate_transition_vector_valid([changed])


@pytest.mark.parametrize(
    ("natural", "cover", "expected"),
    ((1_000, 24, 1_024), (1_000, 1_100, 3_072)),
)
def test_cs_buflo_cpsp_target_uses_power_of_two_quantum_not_power_of_two_target(
    natural: int, cover: int, expected: int
) -> None:
    assert _cs_buflo_payload_padding_target(natural, cover) == expected


def test_cs_buflo_padding_gate_distinguishes_cpsp_3072_from_ctsp_4096() -> None:
    common = {
        "cs_buflo_natural_outgoing_bytes": 1_000,
        "cs_buflo_natural_incoming_bytes": 1_000,
        "cs_buflo_cover_outgoing_bytes": 1_100,
        "cs_buflo_cover_incoming_bytes": 1_100,
        "cs_buflo_realized_udp_bytes": 4_096,
        "cs_buflo_realized_incoming_credit_bytes": 3_072,
        "cs_buflo_outgoing_padding_basis_natural_bytes": 1_000,
        "cs_buflo_incoming_padding_basis_natural_bytes": 1_000,
        "cs_buflo_outgoing_padding_basis_cover_bytes": 1_100,
        "cs_buflo_incoming_padding_basis_cover_bytes": 1_100,
        "cs_buflo_outgoing_padding_basis_total_bytes": 2_100,
        "cs_buflo_incoming_padding_basis_total_bytes": 2_100,
        "cs_buflo_incoming_termination_accounted_bytes": 3_072,
        "cs_buflo_incoming_last_termination_increment_bytes": 1_100,
        "cs_buflo_incoming_power_of_two_crossed": True,
        "cs_buflo_incoming_padding_target_bytes": 3_072,
    }
    cpsp = {
        **common,
        "cs_buflo_payload_padding": True,
        "cs_buflo_total_padding": False,
        "cs_buflo_outgoing_termination_accounted_bytes": 4_096,
        "cs_buflo_outgoing_last_termination_increment_bytes": 2_100,
        "cs_buflo_outgoing_power_of_two_crossed": True,
        "cs_buflo_outgoing_padding_target_bytes": 3_072,
    }
    ctsp = {
        **common,
        "cs_buflo_payload_padding": False,
        "cs_buflo_total_padding": True,
        "cs_buflo_outgoing_termination_accounted_bytes": 4_096,
        "cs_buflo_outgoing_last_termination_increment_bytes": 0,
        "cs_buflo_outgoing_power_of_two_crossed": False,
        "cs_buflo_outgoing_padding_target_bytes": 4_096,
    }

    assert _cs_buflo_padding_targets_match(cpsp)
    assert _cs_buflo_padding_targets_match(ctsp)
    assert not _cs_buflo_padding_targets_match(
        {**cpsp, "cs_buflo_outgoing_padding_target_bytes": 4_096}
    )
    assert not _cs_buflo_padding_targets_match(
        {**ctsp, "cs_buflo_outgoing_padding_target_bytes": 3_072}
    )


def _incoming_credit(value: int) -> dict[str, int]:
    return {
        "scheduled_incoming_requested_bytes": value,
        "scheduled_incoming_advertised_bytes": value,
        "scheduled_incoming_consumed_bytes": value,
        "scheduled_incoming_retired_bytes": 0,
        "scheduled_incoming_unresolved_bytes": 0,
    }


def _schedule_metrics(*, outgoing: int, incoming: int) -> dict[str, object]:
    return {
        "scheduled_events": outgoing + incoming,
        "scheduled_outgoing_events": outgoing,
        "scheduled_incoming_events": incoming,
        "terminal_slots_unique": True,
        "duplicate_terminal_slots": 0,
        "invalid_terminal_rows": 0,
        "typed_congestion_reason_column": True,
        "typed_credit_advertisement_columns": True,
        "typed_credit_consumption_columns": True,
        "typed_controller_terminal_time_column": True,
        "invalid_congestion_reason_events": 0,
        "invalid_typed_outcome_rows": 0,
        "incoming_credit_advertised_events": incoming,
        "incoming_credit_consumed_events": incoming,
        "incoming_credit_missing_events": 0,
        "incoming_credit_consumption_missing_events": 0,
        "invalid_credit_advertisement_events": 0,
        "invalid_credit_consumption_events": 0,
        "incoming_credit_advertisement_delay_us_total": incoming * 100,
        "incoming_credit_advertisement_delay_us_max": 100 if incoming else 0,
        "incoming_credit_advertisement_delay_us_values": [100] * incoming,
        "incoming_credit_consumption_delay_us_total": incoming * 500,
        "incoming_credit_consumption_delay_us_max": 500 if incoming else 0,
        "incoming_credit_consumption_delay_us_values": [500] * incoming,
        "terminal_defense_elapsed_us_values": [0] * (outgoing + incoming),
        "terminal_satisfactions": {"satisfied": outgoing + incoming},
        "terminal_desired_outgoing_bytes": 0,
        "terminal_observed_outgoing_bytes": 0,
        "typed_composition_bytes": {},
        "typed_lateness_us_total": 0,
        "typed_lateness_us_max": 0,
        "typed_real_bearing_outgoing_bytes": 0,
        "target_times_us_by_direction": {"outgoing": [], "incoming": []},
        "scheduled_sizes_by_direction": {"outgoing": [], "incoming": []},
    }


def _typed_schedule_row(
    slot: int,
    direction: str,
    satisfaction: str,
    desired: int,
    observed: int | None,
    lateness: int | None,
    *,
    reason: str = "",
) -> dict[str, object]:
    row: dict[str, object] = {field: "" for field in SCHEDULE_PREFIX_FIELDS + SCHEDULE_QCSD_FIELDS}
    row.update(
        target_time_us=slot * 1_000,
        direction=direction,
        size=desired,
        connection=0,
        action_time_us=slot * 1_000,
        satisfaction=satisfaction,
        observed_size=("" if observed is None or satisfaction == "suppressed" else observed),
        miss_reason={"congestion_limited": "CongestionLimited"}.get(reason, ""),
        slot_id=slot,
        qcsd_outcome_schema_version=3,
        send_policy=("exact" if satisfaction == "satisfied" else "congestion_sensitive"),
        desired_udp_bytes=desired,
        observed_udp_bytes="" if observed is None else observed,
        congestion_reason=reason,
        terminal_defense_elapsed_us=(
            slot * 1_000 + (500 if direction == "incoming" else (lateness or 0))
        ),
    )
    if satisfaction in {"full", "partial", "suppressed"}:
        assert observed is not None and lateness is not None
        row.update(
            application_stream_bytes=observed,
            retransmission_stream_bytes=0,
            chaff_stream_bytes=0,
            defense_control_bytes=0,
            quic_padding_bytes=0,
            other_quic_bytes=0,
            lateness_us=lateness,
        )
    if direction == "incoming":
        row.update(
            credit_advertised_at_us=slot * 1_000 + 100,
            credit_advertisement_delay_us=100,
            credit_consumed_at_us=slot * 1_000 + 500,
            credit_consumption_delay_us=500,
        )
    return row


def test_comparison_review_cannot_omit_declared_csbuflo_incoming_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = tmp_path / "handoff"
    handoff.mkdir()
    for name in ("SHA256SUMS", "dataset.json", "samples.jsonl"):
        (handoff / name).write_text(name + "\n", encoding="utf-8")
    evaluation_receipt = tmp_path / "evaluation.json"
    evaluation_receipt.write_text("{}\n", encoding="utf-8")

    common = [
        {"difference": "transport-and-observation-layer"},
        {"difference": "endpoint-cooperation-and-peer-datagram-unavailability"},
        {"difference": "closed-world-dataset-and-classifier-protocol"},
    ]
    qcsd_rows = [
        {
            "defense": "buflo",
            "known_expected_differences": [
                *common,
                {"difference": ("buflo-terminal-subcell-client-local-cancellation")},
            ],
        },
        {
            "defense": "cs-buflo",
            "known_expected_differences": [
                *common,
                {
                    "difference": (
                        "csbuflo-author-total-transmitted-vs-live-fresh-"
                        "application-stream-byte-adaptation-counter"
                    )
                },
                {"difference": "csbuflo-incoming-boundary-translation"},
                {
                    "difference": (
                        "csbuflo-paper-source-and-client-only-early-termination-translation"
                    )
                },
            ],
        },
    ]
    historical_rows = [
        {
            "anchor_id": "buflo-tau0-rho40-d1000",
            "metrics": {"extra_bandwidth_percent": 93.5},
        },
        {
            "anchor_id": "csbuflo-sites200-ctsp-et1",
            "metrics": {"bandwidth_ratio": 2.796},
        },
    ]
    anchor_inventory = list(buflo_evaluation.historical_anchor_metric_inventory(historical_rows))
    evaluation = {
        "original_study_comparison": {
            "qcsd_rows": qcsd_rows,
            "historical_rows": historical_rows,
            "anchor_metric_inventory": anchor_inventory,
        }
    }
    monkeypatch.setattr(
        buflo_evaluation,
        "validate_evaluation_receipt",
        lambda *_args, **_kwargs: evaluation,
    )
    monkeypatch.setattr(
        buflo_handoff,
        "validate_study_handoff",
        lambda *_args, **_kwargs: handoff.resolve(),
    )

    required_ids = buflo_study._comparison_required_difference_ids(qcsd_rows)
    assert "csbuflo-incoming-boundary-translation" in required_ids
    required_ids.remove("csbuflo-incoming-boundary-translation")
    review = {
        "schema_version": 2,
        "artifact_type": buflo_study.COMPARISON_REVIEW_ARTIFACT_TYPE,
        "formal": True,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
        "evaluation": buflo_study._file_binding(evaluation_receipt),
        "handoff": {
            "root": str(handoff.resolve()),
            "sha256sums_sha256": hashlib.sha256((handoff / "SHA256SUMS").read_bytes()).hexdigest(),
            "dataset_sha256": hashlib.sha256((handoff / "dataset.json").read_bytes()).hexdigest(),
            "samples_sha256": hashlib.sha256((handoff / "samples.jsonl").read_bytes()).hexdigest(),
        },
        "reviewer": "independent-reviewer",
        "reviewed_at": "2026-08-27T00:00:00+00:00",
        "rows": [
            {
                "defense": ("buflo" if item["anchor_id"].startswith("buflo-") else "cs-buflo"),
                "evaluation_row_sha256": buflo_study._canonical_digest(
                    next(
                        row
                        for row in qcsd_rows
                        if row["defense"]
                        == ("buflo" if item["anchor_id"].startswith("buflo-") else "cs-buflo")
                    )
                ),
                "anchor_id": item["anchor_id"],
                "historical_row_sha256": item["historical_row_sha256"],
                "metric": metric,
                "classification": "expected",
                "explanation": (
                    f"For {item['anchor_id']} metric {metric}, the QCSD client-only QUIC "
                    "transport and Ethernet observation layer differ materially from the "
                    "published TCP experiment, so the numeric value is contextual."
                ),
            }
            for item in anchor_inventory
            for metric in item["metric_paths"]
        ],
        "required_differences": [
            {
                "difference": identifier,
                "classification": "expected",
                "explanation": (
                    f"The {identifier} difference is expected because the QCSD client-only "
                    "QUIC transport, endpoint, dataset, and observation protocol are "
                    "explicitly distinct from the original study context."
                ),
            }
            for identifier in sorted(required_ids)
        ],
        "passed": True,
    }
    review_path = tmp_path / "comparison-review.json"
    review_path.write_text(json.dumps(review, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="required-difference inventory"):
        buflo_study.validate_comparison_review(
            review_path,
            evaluation_receipt=evaluation_receipt,
            handoff=handoff,
            formal=True,
        )

    missing_identifier = "csbuflo-incoming-boundary-translation"
    complete = json.loads(json.dumps(review))
    complete["required_differences"].append(
        {
            "difference": missing_identifier,
            "classification": "expected",
            "explanation": (
                f"The {missing_identifier} difference is expected because QCSD client-only "
                "QUIC uses a local endpoint and observation protocol that cannot reproduce "
                "the modified server boundary from the original study."
            ),
        }
    )
    review_path.write_text(json.dumps(complete, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert (
        buflo_study.validate_comparison_review(
            review_path,
            evaluation_receipt=evaluation_receipt,
            handoff=handoff,
            formal=True,
        )["passed"]
        is True
    )

    generic = json.loads(json.dumps(complete))
    generic["rows"][0]["explanation"] = "reviewed"
    review_path.write_text(json.dumps(generic, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="row inventory or digest"):
        buflo_study.validate_comparison_review(
            review_path,
            evaluation_receipt=evaluation_receipt,
            handoff=handoff,
            formal=True,
        )
