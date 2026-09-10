from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import time
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qcsd_lab.browser_egress import (
    BROWSER_EGRESS_PLAYWRIGHT_ENABLED_FEATURES,
    BROWSER_EGRESS_PLAYWRIGHT_FEATURE_ARGUMENT,
    BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE,
    browser_egress_chromium_args,
    browser_egress_qualification_control_chromium_args,
    build_fail_closed_host_resolver_argument,
    validate_browser_egress_command_line,
    validate_browser_egress_qualification_command_line,
)
from qcsd_lab.browser_egress_fixture import (
    _FIXTURE_RESPONSES,
    FIXTURE_CERTIFICATE,
    FIXTURE_PRIVATE_KEY,
    FIXTURE_RESPONSE_BUNDLE_SHA256,
    FIXTURE_TOPOLOGY,
    QUALIFICATION_ID,
    SEMANTIC_OBSERVATION_SCHEMA_VERSION,
    BrowserFixtureServer,
    IndependentDnsSink,
    IndependentTcpSink,
    IndependentUdpSink,
    assemble_live_semantic_observation,
    browser_action_expression,
    dedicated_worker_action_message,
    dns_query_message,
    expanded_vectors_sha256,
    expected_browser_action_arguments,
    expected_fetch_denial_observations,
    expected_browser_launch_contract,
    expected_fixture_connection_counts,
    expected_fixture_report_type_counts,
    expected_fixture_requests,
    expected_fixture_response_headers,
    expected_semantic_chronology,
    expected_sink_counters,
    expected_vectors,
    inventory_json,
    shared_worker_action_message,
    validate_fixture_observation,
    validate_semantic_observation,
    validate_vector,
    validate_vector_inventory,
    vector_by_id,
)
from qcsd_lab.browser_egress_observer import (
    _tool_version_stdout_first_line,
    analyse_pcap,
    reconcile_sink_and_packet_evidence,
    validate_packet_analysis,
)
from qcsd_lab.browser_egress_qualification import (
    ARGV_RELATIVE_PATH,
    CONSUMER_CONTRACT,
    DOCKER_INSPECT_PROJECTION_SCHEMA_VERSION,
    EFFECTIVE_ARGV_BINDING_SCHEMA_VERSION,
    EMPTY_SHA256,
    FINAL_RECEIPT_TYPE,
    FINAL_SCHEMA_VERSION,
    FIXTURE_RUNTIME_CERTIFICATE,
    FIXTURE_RUNTIME_PRIVATE_KEY,
    FIXTURE_TLS_MASK_DIRECTORY,
    FIXTURE_TLS_MASK_TMPFS_OPTIONS,
    HISTORICAL_FOUNDATION_SCHEMA_VERSION,
    MANIFEST_RELATIVE_PATH,
    POLICY_VOLUME_MANAGED_DIRECTORY,
    POLICY_VOLUME_POLICY_FILENAME,
    POLICY_VOLUME_POLICY_PATH,
    POLICY_VOLUME_PROJECTION_SCHEMA_VERSION,
    REQUIRED_SOURCE_BINDING_PATHS,
    RESULT_RECEIPT_TYPE,
    ROLE_TMPFS_OPTIONS,
    FoundationVerificationMode,
    _validate_effective_argv,
    append_result,
    begin_attempt,
    build_attempt_topology_binding,
    build_docker_daemon_projection,
    build_failure_result_receipt,
    build_final_payload,
    build_foundation_payload,
    build_live_docker_daemon_binding,
    build_passed_result_receipt,
    create_final_receipt,
    create_qualification,
    deep_validate_foundation,
    expected_argv_config,
    expected_manifest_config,
    load_checkpoint,
    policy_volume_name,
    reconcile_qualification_filesystem,
    recover_interrupted_attempt,
    require_live_docker_daemon,
    validate_argv_config,
    validate_closed_evidence_inventory,
    validate_docker_inspect_projection,
    validate_final_payload,
    validate_foundation_payload,
    validate_manifest_config,
    validate_open_evidence_inventory,
    validate_result_payload,
    validate_runtime_binding,
    verify_qualification,
)
from qcsd_lab.class_study import bind_receipt, canonical_json_bytes, canonical_json_sha256
from qcsd_lab.playwright_driver import (
    DEFAULT_CONFIGURED_EXECUTABLE,
    EXPECTED_CHROMIUM_CONTROL_POLICY_SHA256,
    EXPECTED_PLAYWRIGHT_DRIVER_PAYLOAD_SHA256,
    EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256,
    expected_playwright_driver_receipt,
)
from qcsd_lab.util import sha256_file


def test_websocket_action_requires_the_exact_policy_close() -> None:
    expression = browser_action_expression()
    assert "__QCSD_WEBSOCKET_POLICY_CLOSE_" not in expression
    assert "event.code !== 1008" in expression
    assert 'event.reason !== "QCSD non-replayable egress policy"' in expression
    assert "event.wasClean !== true" in expression
    assert "QCSD_WEBSOCKET_POLICY_CLOSE_TIMEOUT" in expression


def _source(image: str) -> dict:
    return {
        "image_digest": image,
        "lab_commit": "1" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": EMPTY_SHA256,
        "neqo_commit": "2" * 40,
        "neqo_pinned_commit": "2" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": EMPTY_SHA256,
    }


def _daemon() -> dict[str, str]:
    return {
        "client_version": "29.0.1",
        "server_version": "29.0.1",
        "context": "desktop-linux",
        "endpoint": "unix:///var/run/docker.sock",
        "server_name": "docker-desktop",
        "server_operating_system": "Docker Desktop",
        "server_os_type": "linux",
        "server_architecture": "aarch64",
        "server_id": "daemon-test-id",
    }


def _live_daemon() -> dict:
    return {
        **_daemon(),
        "ncpu": 12,
        "mem_total_bytes": 16_508_784_640,
        "storage_driver": "overlayfs",
        "docker_root_dir": "/var/lib/docker",
    }


def _lab(tmp_path: Path) -> tuple[Path, dict]:
    root = tmp_path / "lab"
    root.mkdir()
    checkout = Path(__file__).resolve().parents[1]
    for relative in REQUIRED_SOURCE_BINDING_PATHS:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative in {FIXTURE_CERTIFICATE["path"], FIXTURE_PRIVATE_KEY["path"]}:
            path.write_bytes((checkout / relative).read_bytes())
        else:
            path.write_text(f"test binding: {relative}\n", encoding="utf-8")
    manifest = root / MANIFEST_RELATIVE_PATH
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_bytes(canonical_json_bytes(expected_manifest_config()))
    argv = root / ARGV_RELATIVE_PATH
    argv.write_bytes(canonical_json_bytes(expected_argv_config()))
    build_path = root / "artifacts/buflo-study/build-execution-v71.json"
    build_path.parent.mkdir(parents=True)
    build_path.write_bytes(canonical_json_bytes({"payload_sha256": "a" * 64, "docker": _daemon()}))
    collection = "sha256:" + "3" * 64
    prepare = "sha256:" + "4" * 64
    reference = "sha256:" + "5" * 64
    validated_build = {
        "path": str(build_path.resolve()),
        "sha256": "6" * 64,
        "cohort_version": 71,
        "completion_path": str((build_path.parent / "build-completion-v71.json").resolve()),
        "completion_sha256": "8" * 64,
        "images": {
            "collection": {"id": collection},
            "prepare": {"id": prepare},
            "reference": {"id": reference},
        },
        "source": _source(collection),
        "passed": True,
    }
    foundation = build_foundation_payload(
        lab_root=root,
        cohort_version=71,
        build_execution=validated_build,
        prepare_repo_digests=["qcsd/prepare@sha256:" + "7" * 64],
        runtime_source=_source(prepare),
        live_docker_daemon=_live_daemon(),
    )
    return root, foundation


class _BuildValidator:
    def __init__(self, foundation: dict, *, allow_historical: bool = False) -> None:
        self.foundation = foundation
        self.allow_historical = allow_historical

    def __call__(
        self,
        path: Path,
        *,
        expected_cohort_version: int,
        allow_historical: bool,
    ) -> dict:
        build = self.foundation["build_execution"]
        assert path.resolve().as_posix().endswith(build["path"])
        assert expected_cohort_version == self.foundation["cohort_version"]
        assert allow_historical is self.allow_historical
        source = dict(self.foundation["source"])
        source["image_digest"] = build["collection_image_id"]
        result = {
            "path": str(path.resolve()),
            "sha256": build["sha256"],
            "cohort_version": expected_cohort_version,
            "images": {
                "collection": {"id": build["collection_image_id"]},
                "prepare": {"id": build["prepare_image_id"]},
                "reference": {"id": build["reference_image_id"]},
            },
            "source": source,
            "passed": True,
        }
        if not self.allow_historical:
            result.update(
                {
                    "completion_path": str(
                        path.parent / f"build-completion-v{expected_cohort_version}.json"
                    ),
                    "completion_sha256": build["completion_sha256"],
                }
            )
        return result


def _admit_create(
    monkeypatch: pytest.MonkeyPatch,
    *,
    result_root: Path,
    lab_root: Path,
    foundation: dict,
) -> dict:
    import qcsd_lab.playwright_driver as driver_module
    import qcsd_lab.util as util_module

    def exact_source() -> dict:
        return copy.deepcopy(foundation["source"])

    def valid_driver() -> dict:
        return expected_playwright_driver_receipt()

    monkeypatch.setattr(util_module, "source_metadata", exact_source)
    monkeypatch.setattr(driver_module, "validate_default_playwright_driver_once", valid_driver)
    return create_qualification(
        result_root,
        foundation,
        lab_root=lab_root,
        build_validator=_BuildValidator(foundation),
    )


def _failure_payload(foundation: dict, *, vector_id: str, attempt: int = 1) -> dict:
    return {
        "schema_version": 1,
        "qualification_id": "browser-egress-qualification-v1",
        "foundation_payload_sha256": canonical_json_sha256(foundation),
        "global_ordinal": 1,
        "attempt_number": attempt,
        "previous_result_sha256": "0" * 64,
        "vector": vector_by_id(vector_id).as_dict(),
        "started_at": "2026-09-06T00:00:00Z",
        "finished_at": "2026-09-06T00:00:01Z",
        "verdict": "operational-failure",
        "failure_code": "docker-start-failed",
        "runtime": None,
        "semantic": None,
        "fixture": None,
        "sink": None,
        "capture": None,
        "failure_evidence": {"diagnostic_code": "docker-start-failed", "artifacts": []},
    }


def test_frozen_manifest_is_exact_110_and_rejects_mutation_order_and_omission() -> None:
    vectors = inventory_json()
    assert len(vectors) == 110
    assert len({row["vector_id"] for row in vectors}) == 110
    assert expanded_vectors_sha256() == (
        "d9038cf12d733f914ad8e71365d98b8ac9eeb98aa9f02aa4ad43b992d3bd21ba"
    )
    assert [vector.family for vector in expected_vectors()].count("constructor-transport") == 50
    validate_vector_inventory(vectors)
    for forged in (vectors[:-1], [vectors[1], vectors[0], *vectors[2:]]):
        with pytest.raises(ValueError, match="frozen"):
            validate_vector_inventory(forged)
    mutated = copy.deepcopy(vectors)
    mutated[0]["surface"] = "webtransport"
    with pytest.raises(ValueError, match="frozen"):
        validate_vector_inventory(mutated)


def test_checked_in_configs_are_exact_and_bool_alias_is_rejected() -> None:
    root = Path(__file__).resolve().parents[1]
    validate_manifest_config(json.loads((root / MANIFEST_RELATIVE_PATH).read_text()))
    validate_argv_config(json.loads((root / ARGV_RELATIVE_PATH).read_text()))
    forged = copy.deepcopy(expected_manifest_config())
    forged["schema_version"] = True
    with pytest.raises(ValueError):
        validate_manifest_config(forged)


def _semantic(vector_id: str, measurement: dict) -> dict:
    vector = vector_by_id(vector_id)
    events = expected_semantic_chronology(vector)
    event_times = {event: index for index, event in enumerate(events, 1)}
    if vector.family == "browser-service-control":
        terminal = vector.semantic_kind
        minimum_dwell_ns = vector.as_dict()["minimum_live_dwell_ms"] * 1_000_000
        event_times[terminal] = event_times["action-started"] + minimum_dwell_ns
        event_times["browser-exited"] = event_times[terminal] + 1
        event_times["reporting-grace-finished"] = event_times["browser-exited"] + 1
        event_times["observer-stopped"] = event_times["reporting-grace-finished"] + 1
    return {
        "schema_version": SEMANTIC_OBSERVATION_SCHEMA_VERSION,
        "vector_id": vector_id,
        "observed_kind": vector.semantic_kind,
        "mechanism": vector.semantic_mechanism,
        "descriptor_state": vector.descriptor_state,
        "action_invocations": (
            0
            if vector.semantic_kind
            in {"idle-observation", "disabled-unavailable", "configuration-verified"}
            else 1
        ),
        "measurement": measurement,
        "chronology": [
            {"sequence": index, "event": event, "monotonic_ns": event_times[event]}
            for index, event in enumerate(events, 1)
        ],
    }


def test_disabled_unavailable_must_be_derived_from_live_raw_descriptor() -> None:
    vector = vector_by_id("constructor--page--tcp-client")
    measured = {
        "resolved_type": "undefined",
        "own_descriptor": "absent",
        "prearm_verified": True,
        "action_issued": False,
        "action_succeeded": False,
        "policy_event_count": 0,
        "fetch_denial_count": 0,
        "fetch_denials": [],
        "exception_name": None,
        "control_observed": False,
        "configuration_observation": None,
    }
    validate_semantic_observation(_semantic(vector.vector_id, measured), vector=vector)
    forged = copy.deepcopy(measured)
    forged["resolved_type"] = "function"
    with pytest.raises(ValueError, match="cannot be derived|not derived"):
        validate_semantic_observation(_semantic(vector.vector_id, forged), vector=vector)


def test_background_action_and_positive_control_have_honest_distinct_chronology() -> None:
    background = vector_by_id("browser-service--browser--preconnect")
    actor = {
        "started_ns": 5,
        "finished_ns": 6,
        "measurement": {
            "resolved_type": "not-applicable",
            "own_descriptor": "not-applicable",
            "prearm_verified": True,
            "action_issued": True,
            "action_succeeded": True,
            "policy_event_count": 0,
            "fetch_denial_count": 0,
            "fetch_denials": [],
            "exception_name": None,
            "control_observed": False,
            "configuration_observation": None,
        },
    }
    events = expected_semantic_chronology(background)
    observation = assemble_live_semantic_observation(
        vector=background,
        actor_result=actor,
        event_times={event: index for index, event in enumerate(events, 1)},
    )
    assert observation["observed_kind"] == "action-issued"
    control_events = expected_semantic_chronology(vector_by_id("positive-control--fixture--tcp"))
    assert "control-emitter-started" in control_events
    assert "browser-started" in control_events
    assert control_events.index("browser-started") < control_events.index("control-emitter-started")
    assert control_events.index("control-emitter-exited") < control_events.index("browser-exited")


@pytest.mark.parametrize(
    "vector_id",
    [
        "browser-service--browser--preconnect",
        "service-worker--page--registration",
    ],
)
def test_action_contract_rejects_generic_pre_network_exception(vector_id: str) -> None:
    vector = vector_by_id(vector_id)
    descriptor = (
        ("function", "accessor")
        if vector.family == "service-worker"
        else ("not-applicable", "not-applicable")
    )
    measurement = {
        "resolved_type": descriptor[0],
        "own_descriptor": descriptor[1],
        "prearm_verified": True,
        "action_issued": True,
        "action_succeeded": False,
        "policy_event_count": 0,
        "fetch_denial_count": 0,
        "fetch_denials": [],
        "exception_name": "NotAllowedError",
        "control_observed": False,
        "configuration_observation": None,
    }
    with pytest.raises(ValueError, match="per-surface contract"):
        validate_semantic_observation(_semantic(vector_id, measurement), vector=vector)


def test_foundation_rejects_bool_float_and_adversarial_reseal(tmp_path: Path) -> None:
    _root, foundation = _lab(tmp_path)
    validate_foundation_payload(foundation)
    for field, alias in (("cohort_version", True), ("cohort_version", 71.0)):
        forged = copy.deepcopy(foundation)
        forged[field] = alias
        with pytest.raises(ValueError):
            validate_foundation_payload(forged)
    forged = copy.deepcopy(foundation)
    forged["prepare_image"]["id"] = "sha256:" + "9" * 64
    # Even an attacker who recomputes an outer receipt cannot repair the
    # independently repeated image/source/build relationships.
    resealed = bind_receipt(forged, receipt_type="qcsd-browser-egress-qualification-foundation")
    with pytest.raises(ValueError, match="inconsistent|bind"):
        validate_foundation_payload(resealed["payload"])
    missing_completion = copy.deepcopy(foundation)
    missing_completion["build_execution"].pop("completion_path")
    with pytest.raises(ValueError, match="build binding"):
        validate_foundation_payload(missing_completion)
    tampered_completion = copy.deepcopy(foundation)
    tampered_completion["build_execution"]["completion_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="does not reproduce its binding"):
        deep_validate_foundation(
            tampered_completion,
            lab_root=_root,
            build_validator=_BuildValidator(foundation),
            mode=FoundationVerificationMode.PORTABLE_REPLAY,
        )
    historical = copy.deepcopy(foundation)
    historical["schema_version"] = HISTORICAL_FOUNDATION_SCHEMA_VERSION
    historical["build_execution"].pop("completion_path")
    historical["build_execution"].pop("completion_sha256")
    with pytest.raises(ValueError, match="foundation identity"):
        validate_foundation_payload(historical)
    assert validate_foundation_payload(historical, allow_historical=True) == json.loads(
        canonical_json_bytes(historical)
    )
    assert deep_validate_foundation(
        historical,
        lab_root=_root,
        build_validator=_BuildValidator(historical, allow_historical=True),
        mode=FoundationVerificationMode.PORTABLE_REPLAY,
        allow_historical=True,
    ) == json.loads(canonical_json_bytes(historical))


def test_foundation_rejects_cross_daemon_and_resealed_daemon_claim(
    tmp_path: Path,
) -> None:
    lab_root, foundation = _lab(tmp_path)
    assert build_docker_daemon_projection(foundation["docker_daemon"]) == _daemon()

    forged = copy.deepcopy(foundation)
    forged["docker_daemon"]["server_id"] = "different-daemon-id"
    resealed = bind_receipt(forged, receipt_type="qcsd-browser-egress-qualification-foundation")
    with pytest.raises(ValueError, match="build payload binding"):
        deep_validate_foundation(
            resealed["payload"],
            lab_root=lab_root,
            build_validator=_BuildValidator(foundation),
        )

    forged = copy.deepcopy(foundation)
    forged["docker_daemon"]["mem_total_bytes"] += 1
    resealed = bind_receipt(forged, receipt_type="qcsd-browser-egress-qualification-foundation")
    with pytest.raises(ValueError, match="live Docker daemon differs"):
        require_live_docker_daemon(_live_daemon(), expected=resealed["payload"]["docker_daemon"])


def test_real_current_docker_daemon_binding_happy_path() -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable")

    def docker_json(*arguments: str) -> dict:
        try:
            completed = subprocess.run(
                [docker, *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            pytest.skip("Docker daemon did not answer the admission probe")
        if completed.returncode != 0:
            pytest.skip("Docker daemon is unavailable")
        return json.loads(completed.stdout)

    context_run = subprocess.run(
        [docker, "context", "show"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
        timeout=10,
    )
    if context_run.returncode != 0 or not context_run.stdout.strip():
        pytest.skip("Docker context is unavailable")
    context = context_run.stdout.strip()
    context_value = docker_json("context", "inspect", context)[0]
    endpoint = context_value["Endpoints"]["docker"]["Host"]
    version = docker_json("version", "--format", "{{json .}}")
    info = docker_json("info", "--format", "{{json .}}")
    live = build_live_docker_daemon_binding(
        docker_version=version,
        docker_info=info,
        context=context,
        endpoint=endpoint,
        pinned_server_id=info["ID"],
    )
    assert require_live_docker_daemon(live, expected=live) == live
    assert build_docker_daemon_projection(live)["server_id"] == info["ID"]


def test_invalid_append_is_validated_before_create_only_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "qualification"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    out_of_order = _failure_payload(foundation, vector_id="constructor--page--websocket", attempt=2)
    receipt = bind_receipt(out_of_order, receipt_type=RESULT_RECEIPT_TYPE)
    with pytest.raises(ValueError, match="out of order"):
        append_result(result_root, receipt)
    assert list((result_root / "attempts").iterdir()) == []
    assert load_checkpoint(result_root)["attempts"] == []


def test_vector_mutation_with_resealed_envelope_cannot_advance_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "qualification"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    forged = _failure_payload(
        foundation, vector_id="constructor--page--websocket-stream", attempt=1
    )
    receipt = bind_receipt(forged, receipt_type=RESULT_RECEIPT_TYPE)
    with pytest.raises(ValueError, match="out of order"):
        append_result(result_root, receipt)
    assert not (result_root / "attempts/result-0001.json").exists()


def _docker_projection(
    vector_id: str,
    prepare: str,
    *,
    seed: int = 1,
    attempt_topology: dict | None = None,
) -> dict:
    if attempt_topology is None:
        attempt_topology = {
            "cohort_version": 71,
            "foundation_payload_sha256": "a" * 64,
            "global_ordinal": 1,
            "attempt_number": 1,
            "topology_token": "b" * 32,
        }
    topology_labels = {
        "org.qcsd.owner": "qcsd-lab",
        "org.qcsd.study": "classifier-multiorigin100-v1",
        "org.qcsd.qualification": "browser-egress-qualification-v1",
        "org.qcsd.vector": vector_id,
        "org.qcsd.cohort-version": str(attempt_topology["cohort_version"]),
        "org.qcsd.foundation": attempt_topology["foundation_payload_sha256"],
        "org.qcsd.global-ordinal": str(attempt_topology["global_ordinal"]),
        "org.qcsd.attempt-number": str(attempt_topology["attempt_number"]),
        "org.qcsd.topology-token": attempt_topology["topology_token"],
    }
    roles = ("browser", "observer", "fixture", "forbidden_sink", "dns_sink")
    addresses = {
        "browser": ("172.30.98.10", "fd00:71:63:73:64:98:0:10"),
        "observer": (None, None),
        "fixture": ("172.30.98.11", "fd00:71:63:73:64:98:0:11"),
        "forbidden_sink": ("172.30.98.20", "fd00:71:63:73:64:98:0:20"),
        "dns_sink": ("172.30.98.53", "fd00:71:63:73:64:98:0:53"),
    }
    ids = {role: hashlib.sha256(f"container:{seed}:{role}".encode()).hexdigest() for role in roles}
    network_id = hashlib.sha256(f"network:{seed}".encode()).hexdigest()
    endpoint_ids = {
        role: hashlib.sha256(f"endpoint:{seed}:{role}".encode()).hexdigest()
        for role in roles
        if role != "observer"
    }
    containers = {}
    for role in roles:
        containers[role] = {
            "id": ids[role],
            "image_id": prepare,
            "user": "1000:1000" if role == "browser" else "0:0",
            "privileged": False,
            "read_only_root": True,
            "cap_add": ["CAP_NET_RAW"] if role == "observer" else [],
            "cap_drop": ["ALL"],
            "security_options": ["no-new-privileges:true"],
            "network_mode": (
                f"container:{ids['browser']}" if role == "observer" else "qcsd-browser-egress-v1"
            ),
            "network_attachments": (
                []
                if role == "observer"
                else [
                    {
                        "name": "qcsd-browser-egress-v1",
                        "network_id": network_id,
                        "endpoint_id": endpoint_ids[role],
                        "ipv4_address": addresses[role][0],
                        "ipv6_address": addresses[role][1],
                    }
                ]
            ),
            "ipv4_address": addresses[role][0],
            "ipv6_address": addresses[role][1],
            "labels": {**topology_labels, "org.qcsd.role": role},
            "mounts": [],
            "tmpfs": sorted(
                [
                    {"destination": "/tmp", "options": ROLE_TMPFS_OPTIONS},
                    *(
                        [
                            {
                                "destination": FIXTURE_TLS_MASK_DIRECTORY,
                                "options": FIXTURE_TLS_MASK_TMPFS_OPTIONS,
                            }
                        ]
                        if role != "fixture"
                        else []
                    ),
                ],
                key=lambda item: item["destination"],
            ),
            "dns_servers": (
                ["172.30.98.53", "fd00:71:63:73:64:98:0:53"] if role == "browser" else []
            ),
            "running": False,
            "exit_code": 0,
        }
    volume = None
    volume_name = policy_volume_name(vector_id=vector_id, attempt_topology=attempt_topology)
    if volume_name is not None:
        containers["browser"]["mounts"] = [
            {
                "type": "volume",
                "name": volume_name,
                "destination": POLICY_VOLUME_MANAGED_DIRECTORY,
                "rw": False,
            }
        ]
        mountpoint = f"/var/lib/docker/volumes/{volume_name}/_data"
        volume = {
            "schema_version": POLICY_VOLUME_PROJECTION_SCHEMA_VERSION,
            "name": volume_name,
            "driver": "local",
            "scope": "local",
            "labels": {**topology_labels, "org.qcsd.role": "policy_volume"},
            "options": {},
            "mountpoint_is_canonical": True,
            "mountpoint_sha256": hashlib.sha256(mountpoint.encode()).hexdigest(),
            "file_inventory": [
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
            ],
        }
    return {
        "schema_version": DOCKER_INSPECT_PROJECTION_SCHEMA_VERSION,
        "snapshot_model": {
            "schema_version": 1,
            "topology_source": "pre-action-live",
            "terminal_state_source": "post-exit",
            "immutable_container_fields_cross_checked": True,
        },
        "network": {
            "id": network_id,
            "name": "qcsd-browser-egress-v1",
            "driver": "bridge",
            "internal": True,
            "attachable": False,
            "enable_ipv6": True,
            "ipam_config": [
                {"subnet": "172.30.98.0/24"},
                {"subnet": "fd00:71:63:73:64:98::/96"},
            ],
            "labels": topology_labels,
            "members": {
                role: {
                    "container_id": ids[role],
                    "endpoint_id": endpoint_ids[role],
                    "ipv4_address": f"{addresses[role][0]}/24",
                    "ipv6_address": f"{addresses[role][1]}/96",
                }
                for role in roles
                if role != "observer"
            },
        },
        "containers": containers,
        "policy_volume": volume,
    }


def _ipv4_packet(src: str, dst: str, protocol: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        0,
        0,
        64,
        protocol,
        0,
        socket.inet_pton(socket.AF_INET, src),
        socket.inet_pton(socket.AF_INET, dst),
    )
    return header + payload


def _ipv6_packet(src: str, dst: str, protocol: int, payload: bytes) -> bytes:
    header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(payload),
        protocol,
        64,
        socket.inet_pton(socket.AF_INET6, src),
        socket.inet_pton(socket.AF_INET6, dst),
    )
    return header + payload


def _tcp_packet(
    src: str,
    dst: str,
    *,
    src_port: int,
    dst_port: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    segment = struct.pack("!HHIIHHHH", src_port, dst_port, 1, 1, 0x5000 | flags, 65535, 0, 0)
    packet = segment + payload
    return (
        _ipv6_packet(src, dst, socket.IPPROTO_TCP, packet)
        if ":" in src
        else _ipv4_packet(src, dst, socket.IPPROTO_TCP, packet)
    )


def _udp_packet(src: str, dst: str, *, src_port: int, dst_port: int, payload: bytes) -> bytes:
    datagram = struct.pack("!HHHH", src_port, dst_port, len(payload) + 8, 0) + payload
    return (
        _ipv6_packet(src, dst, socket.IPPROTO_UDP, datagram)
        if ":" in src
        else _ipv4_packet(src, dst, socket.IPPROTO_UDP, datagram)
    )


def _pcap_packets(vector_id: str) -> list[bytes]:
    vector = vector_by_id(vector_id)
    browser4, browser6 = ("172.30.98.10", "fd00:71:63:73:64:98:0:10")
    fixture4 = "172.30.98.11"
    sink4, sink6 = ("172.30.98.20", "fd00:71:63:73:64:98:0:20")
    dns4, dns6 = ("172.30.98.53", "fd00:71:63:73:64:98:0:53")
    if vector.packet_policy in {
        "zero-forbidden-egress",
        "approved-speculation-prefetch-zero",
        "approved-speculation-prefetch-positive",
        "approved-dns-prefetch-zero",
        "approved-preconnect-zero",
        "approved-speculation-prerender-zero",
        "approved-speculation-prerender-positive",
        "approved-reporting-zero",
        "approved-reporting-positive",
    }:
        return [
            _tcp_packet(
                browser4,
                fixture4,
                src_port=49152,
                dst_port=14443,
                flags=0x02,
            )
        ]
    if vector.packet_policy == "positive-tcp-control":
        packets: list[bytes] = []
        for index, (browser, sink) in enumerate(((browser4, sink4), (browser6, sink6))):
            source_port = 49152 + index
            packets.extend(
                [
                    _tcp_packet(
                        browser,
                        sink,
                        src_port=source_port,
                        dst_port=18443,
                        flags=0x02,
                    ),
                    _tcp_packet(
                        sink,
                        browser,
                        src_port=18443,
                        dst_port=source_port,
                        flags=0x12,
                    ),
                    _tcp_packet(
                        browser,
                        sink,
                        src_port=source_port,
                        dst_port=18443,
                        flags=0x18,
                        payload=b"QCSD-BROWSER-EGRESS-CONTROL-V1!!",
                    ),
                ]
            )
        return packets
    if vector.packet_policy == "positive-udp-control":
        return [
            _udp_packet(
                browser,
                sink,
                src_port=49152 + index,
                dst_port=18444,
                payload=b"QCSD-BROWSER-EGRESS-CONTROL-V1!!",
            )
            for index, (browser, sink) in enumerate(((browser4, sink4), (browser6, sink6)))
        ]
    if vector.packet_policy == "approved-dns-prefetch-positive":
        name = FIXTURE_TOPOLOGY["browser_service_controls"]["dns_exception_hostname"]
        return [
            _udp_packet(
                browser4,
                dns4,
                src_port=49152 + index,
                dst_port=53,
                payload=dns_query_message(name, identifier=0x5250 + index),
            )
            for index in range(
                FIXTURE_TOPOLOGY["browser_service_controls"]["dns_positive_query_count"]
            )
        ]
    if vector.packet_policy == "approved-preconnect-positive":
        port = FIXTURE_TOPOLOGY["ports"]["fixture_preconnect_https"]
        return [
            _tcp_packet(
                browser4,
                fixture4,
                src_port=49152,
                dst_port=port,
                flags=0x02,
            ),
            _tcp_packet(
                fixture4,
                browser4,
                src_port=port,
                dst_port=49152,
                flags=0x12,
            ),
        ]
    if vector.packet_policy in {
        "approved-network-error-logging-zero",
        "approved-network-error-logging-positive",
    }:
        return [
            _tcp_packet(
                browser4,
                fixture4,
                src_port=49152,
                dst_port=FIXTURE_TOPOLOGY["ports"]["fixture_nel_error_https"],
                flags=0x02,
            )
        ]
    if vector.packet_policy == "positive-dns-control":
        names = [
            "udp4-control.egress.invalid",
            "udp6-control.egress.invalid",
            "tcp4-control.egress.invalid",
            "tcp6-control.egress.invalid",
        ]
        packets = []
        for index, (browser, sink) in enumerate(((browser4, dns4), (browser6, dns6))):
            udp_query = dns_query_message(names[index], identifier=0x5151 + index)
            tcp_query = dns_query_message(names[index + 2], identifier=0x5153 + index)
            packets.extend(
                [
                    _udp_packet(
                        browser,
                        sink,
                        src_port=49152 + index,
                        dst_port=53,
                        payload=udp_query,
                    ),
                    _tcp_packet(
                        browser,
                        sink,
                        src_port=49154 + index,
                        dst_port=53,
                        flags=0x02,
                    ),
                    _tcp_packet(
                        browser,
                        sink,
                        src_port=49154 + index,
                        dst_port=53,
                        flags=0x18,
                        payload=struct.pack("!H", len(tcp_query)) + tcp_query,
                    ),
                ]
            )
        return packets
    raise AssertionError(f"synthetic PCAP has no packet policy: {vector.packet_policy}")


def _write_pcap(path: Path, *, vector_id: str) -> int:
    packets = _pcap_packets(vector_id)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.parent.chmod(0o700)
    path.parent.chmod(0o700)
    contents = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    for index, packet in enumerate(packets, 1):
        contents.extend(struct.pack("<IIII", index, 0, len(packet), len(packet)))
        contents.extend(packet)
    path.write_bytes(contents)
    path.chmod(0o600)
    return len(packets)


@pytest.mark.parametrize("vector", expected_vectors(), ids=lambda item: item.vector_id)
def test_every_vector_synthetic_pcap_matches_packet_and_sink_policy(tmp_path: Path, vector) -> None:
    path = tmp_path / f"{vector.ordinal:03d}.pcap"
    _write_pcap(path, vector_id=vector.vector_id)
    analysis, _decoder = analyse_pcap(path, vector=vector)
    assert validate_packet_analysis(analysis, vector=vector) == analysis
    reconcile_sink_and_packet_evidence(
        vector=vector,
        analysis=analysis,
        sink=expected_sink_counters(vector),
    )


def _wall_time(index: int) -> str:
    value = datetime(2026, 9, 6, tzinfo=UTC) + timedelta(seconds=index)
    return value.isoformat().replace("+00:00", "Z")


def _fork_crash_at(boundary: str, action: Callable[[], object]) -> None:
    import qcsd_lab.browser_egress_qualification as qualification

    child = os.fork()
    if child == 0:  # pragma: no cover - assertions execute in the parent
        qualification._DURABILITY_FAULT_INJECTOR = lambda observed: (
            os._exit(86) if observed == boundary else None
        )
        try:
            action()
        except BaseException:
            os._exit(87)
        os._exit(0)
    _pid, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 86


def _limit_qualification_to_first_vector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import qcsd_lab.browser_egress_qualification as qualification

    first = copy.deepcopy(inventory_json()[:1])
    monkeypatch.setattr(qualification, "VECTOR_COUNT", 1)
    monkeypatch.setattr(qualification, "inventory_json", lambda: copy.deepcopy(first))


def _begin_intent(
    result_root: Path,
    *,
    vector_id: str,
    started_at: str,
    checkpoint: dict | None = None,
) -> dict:
    if checkpoint is None:
        checkpoint = load_checkpoint(result_root)
    vector = vector_by_id(vector_id)
    prior = [item for item in checkpoint["attempts"] if item["vector_id"] == vector_id]
    plan = {
        "schema_version": 1,
        "complete": False,
        "vector": vector.as_dict(),
        "global_ordinal": len(checkpoint["attempts"]) + 1,
        "attempt_number": len(prior) + 1,
        "previous_result_sha256": checkpoint["chain_head_sha256"],
    }
    return begin_attempt(
        result_root,
        next_plan=plan,
        vector_id=vector_id,
        started_at=started_at,
    )


def _effective_arguments(
    vector_id: str = "constructor--page--websocket",
) -> list[str]:
    config = expected_argv_config()
    contract = expected_browser_launch_contract(vector_by_id(vector_id))
    keyword = {
        "approved_origins": contract["resolver_approved_origins"],
        "origin_ip_pins": contract["resolver_origin_ip_pins"],
        "approved_ip_exclusions": contract["resolver_approved_ip_exclusions"],
    }
    if contract["launch_profile"] == BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE:
        explicit = browser_egress_chromium_args(**keyword)
    else:
        explicit = browser_egress_qualification_control_chromium_args(
            launch_profile=contract["launch_profile"],
            dns_exception_hostname=contract["dns_exception_hostname"],
            **keyword,
        )
    return [
        str(DEFAULT_CONFIGURED_EXECUTABLE),
        *(switch for switch in config["required_effective_switches"] if switch not in explicit),
        BROWSER_EGRESS_PLAYWRIGHT_FEATURE_ARGUMENT,
        "--enable-features=" + ",".join(BROWSER_EGRESS_PLAYWRIGHT_ENABLED_FEATURES),
        *explicit,
    ]


def _effective_projection(vector_id: str) -> dict:
    contract = expected_browser_launch_contract(vector_by_id(vector_id))
    return validate_browser_egress_qualification_command_line(
        {"arguments": _effective_arguments(vector_id)},
        launch_profile=contract["launch_profile"],
        approved_origins=contract["resolver_approved_origins"],
        origin_ip_pins=contract["resolver_origin_ip_pins"],
        approved_ip_exclusions=contract["resolver_approved_ip_exclusions"],
        dns_exception_hostname=contract["dns_exception_hostname"],
    )


def _runtime(
    foundation: dict,
    *,
    vector_id: str,
    seed: int,
    global_ordinal: int = 1,
    attempt_number: int = 1,
    started_at: str | None = None,
) -> dict:
    vector = vector_by_id(vector_id)
    if started_at is None:
        started_at = _wall_time(global_ordinal * 2)
    attempt_topology = build_attempt_topology_binding(
        foundation=foundation,
        global_ordinal=global_ordinal,
        attempt_number=attempt_number,
        vector_id=vector_id,
        started_at=started_at,
    )
    projection = _effective_projection(vector_id)
    contract = expected_browser_launch_contract(vector)
    network_prediction_option = contract["managed_policy"]["NetworkPredictionOptions"]
    argv_config = expected_argv_config()
    policy = (
        argv_config["chromium_network_prediction_control_policy"]
        if network_prediction_option == 0
        else argv_config["chromium_managed_policy"]
    )
    source_bindings = {item["path"]: item for item in foundation["source_files"]}
    return {
        "prepare_image_id": foundation["prepare_image"]["id"],
        "docker_daemon": foundation["docker_daemon"],
        "source": foundation["source"],
        "browser": foundation["browser"],
        "effective_argv": {
            "schema_version": EFFECTIVE_ARGV_BINDING_SCHEMA_VERSION,
            "projection_sha256": canonical_json_sha256(projection),
            "command_line_projection": projection,
        },
        "driver_runtime": {
            "schema_version": 1,
            "artifact_type": "qcsd-playwright-qualification-runtime",
            "production_receipt_sha256": EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256,
            "production_receipt_payload_sha256": EXPECTED_PLAYWRIGHT_DRIVER_PAYLOAD_SHA256,
            "active_managed_policy": {
                "path": POLICY_VOLUME_POLICY_PATH,
                "sha256": policy["sha256"],
                "mode": policy["mode"],
                "managed_directory_file_count": 1,
                "sole_managed_policy": True,
            },
            "network_prediction_options": network_prediction_option,
            "dns_over_https_mode": "off",
            "semantics": (
                "predict-on-any-connection-qualification-control"
                if network_prediction_option == 0
                else "never-predict"
            ),
            "policy_directory_inventory": argv_config["policy_root_inventory"],
            "qualification_only_policy_substitution": (network_prediction_option == 0),
        },
        "fixture_tls_runtime": {
            "schema_version": 1,
            "certificate": {
                "path": FIXTURE_RUNTIME_CERTIFICATE,
                "sha256": FIXTURE_CERTIFICATE["sha256"],
                "size_bytes": source_bindings[FIXTURE_CERTIFICATE["path"]]["size_bytes"],
                "uid": 0,
                "gid": 0,
                "mode": "0o444",
                "nlink": 1,
            },
            "private_key": {
                "path": FIXTURE_RUNTIME_PRIVATE_KEY,
                "sha256": FIXTURE_PRIVATE_KEY["sha256"],
                "size_bytes": source_bindings[FIXTURE_PRIVATE_KEY["path"]]["size_bytes"],
                "uid": 0,
                "gid": 0,
                "mode": "0o400",
                "nlink": 1,
            },
        },
        "child_environment": expected_argv_config()["child_environment"],
        "browser_identity": {"uid": 1000, "gid": 1000},
        "attempt_topology": attempt_topology,
        "subject_kind": (
            "idle-chromium-plus-independent-control-emitter"
            if vector.family == "positive-control"
            else "chromium-browser"
        ),
        "docker_inspect": _docker_projection(
            vector_id,
            foundation["prepare_image"]["id"],
            seed=seed,
            attempt_topology=attempt_topology,
        ),
        "fixture_contract_sha256": foundation["contracts"]["fixture_contract_sha256"],
    }


def _measurement(vector_id: str) -> dict:
    vector = vector_by_id(vector_id)
    base = {
        "resolved_type": "function",
        "own_descriptor": "data",
        "prearm_verified": True,
        "action_issued": True,
        "action_succeeded": True,
        "policy_event_count": 0,
        "fetch_denial_count": 0,
        "fetch_denials": [],
        "exception_name": None,
        "control_observed": False,
        "configuration_observation": None,
    }
    if vector.semantic_kind == "typed-policy-rejection":
        base["action_succeeded"] = False
        base["policy_event_count"] = 1
        base["exception_name"] = "TypeError"
    elif vector.semantic_kind == "websocket-route-block":
        base["policy_event_count"] = 1
    elif vector.semantic_kind == "fetch-policy-denial":
        base["fetch_denial_count"] = 1
        base["fetch_denials"] = expected_fetch_denial_observations(vector)
    elif vector.semantic_kind == "disabled-unavailable":
        base.update(
            {
                "resolved_type": "undefined",
                "own_descriptor": "absent",
                "action_issued": False,
                "action_succeeded": False,
            }
        )
    elif vector.semantic_kind == "configuration-verified":
        argv = _effective_arguments()
        base.update(
            {
                "resolved_type": "not-applicable",
                "own_descriptor": "not-applicable",
                "action_issued": False,
                "action_succeeded": False,
                "configuration_observation": {
                    "surface": vector.surface,
                    "effective_argv_projection_sha256": canonical_json_sha256(
                        validate_browser_egress_command_line({"arguments": argv})
                    ),
                    "child_environment_sha256": canonical_json_sha256(
                        expected_argv_config()["child_environment"]
                    ),
                    "no_proxy_server_argument_count": 1,
                    "antagonistic_proxy_switches_present": [],
                    "proxy_environment_keys_present": [],
                },
            }
        )
    elif vector.semantic_kind == "idle-observation":
        base.update(
            {
                "resolved_type": "not-applicable",
                "own_descriptor": "not-applicable",
                "action_issued": False,
                "action_succeeded": False,
            }
        )
    elif vector.family == "browser-service":
        base.update(
            {
                "resolved_type": "not-applicable",
                "own_descriptor": "not-applicable",
            }
        )
    elif vector.family == "browser-service-control":
        base.update(
            {
                "resolved_type": "not-applicable",
                "own_descriptor": "not-applicable",
                "prearm_verified": False,
                "control_observed": vector.semantic_kind == "positive-control-observed",
            }
        )
    elif vector.semantic_kind == "positive-control-observed":
        base.update(
            {
                "resolved_type": "not-applicable",
                "own_descriptor": "not-applicable",
                "prearm_verified": False,
                "control_observed": True,
            }
        )
    return base


def test_fetch_denial_measurements_bind_exact_action_url_and_method() -> None:
    expected_methods = {
        "fetch": "GET",
        "xhr": "GET",
        "beacon": "POST",
        "legacy-csp-report": "POST",
        "window-open-existing-named-frame": "GET",
    }
    denial_vectors = [
        vector for vector in expected_vectors() if vector.semantic_kind == "fetch-policy-denial"
    ]
    assert len(denial_vectors) == 17
    for vector in denial_vectors:
        expected = expected_fetch_denial_observations(vector)
        assert expected == [
            {
                "url": expected_browser_action_arguments(vector)["forbiddenUrl"],
                "method": expected_methods[vector.surface],
            }
        ]
        observation = _semantic(vector.vector_id, _measurement(vector.vector_id))
        assert validate_semantic_observation(observation, vector=vector) == observation
        for key, replacement in (("url", "https://forged.invalid/"), ("method", "PATCH")):
            forged = copy.deepcopy(observation)
            forged["measurement"]["fetch_denials"][0][key] = replacement
            with pytest.raises(ValueError, match="Fetch denial"):
                validate_semantic_observation(forged, vector=vector)


def test_v4_vector_action_and_semantic_denial_schemas_fail_closed() -> None:
    vector = vector_by_id("urlloader--page--legacy-csp-report")
    forged_vector = vector.as_dict()
    forged_vector["schema_version"] = 3
    with pytest.raises(ValueError, match="frozen"):
        validate_vector(forged_vector)

    forged_action = vector_by_id("urlloader--page--trusted-anchor-ping").as_dict()
    forged_action["action_contract"]["schema_version"] = 3
    with pytest.raises(ValueError, match="frozen"):
        validate_vector(forged_action)

    observation = _semantic(vector.vector_id, _measurement(vector.vector_id))
    legacy = copy.deepcopy(observation)
    legacy["schema_version"] = 3
    with pytest.raises(ValueError, match="inconsistent"):
        validate_semantic_observation(legacy, vector=vector)

    missing = copy.deepcopy(observation)
    missing["measurement"].pop("fetch_denials")
    with pytest.raises(ValueError, match="measurement fields"):
        validate_semantic_observation(missing, vector=vector)

    mismatch = copy.deepcopy(observation)
    mismatch["measurement"]["fetch_denials"].append(
        dict(mismatch["measurement"]["fetch_denials"][0])
    )
    with pytest.raises(ValueError, match="inventory"):
        validate_semantic_observation(mismatch, vector=vector)

    duplicate = copy.deepcopy(mismatch)
    duplicate["measurement"]["fetch_denial_count"] = 2
    with pytest.raises(ValueError, match="frozen action request"):
        validate_semantic_observation(duplicate, vector=vector)


def _passed_receipt(
    result_root: Path,
    foundation: dict,
    *,
    vector_id: str,
    global_ordinal: int,
    attempt_number: int,
    previous_result_sha256: str,
    seed: int,
    checkpoint: dict | None = None,
) -> tuple[dict, Path]:
    vector = vector_by_id(vector_id)
    if (result_root / "foundation.json").is_file():
        current = checkpoint if checkpoint is not None else load_checkpoint(result_root)
        assert global_ordinal == len(current["attempts"]) + 1
        assert previous_result_sha256 == current["chain_head_sha256"]
        _begin_intent(
            result_root,
            vector_id=vector_id,
            started_at=_wall_time(global_ordinal * 2),
            checkpoint=current,
        )
    base = seed * 10_000_000_000
    events = expected_semantic_chronology(vector)
    times = {event: base + index for index, event in enumerate(events, 2)}
    if vector.surface == "reporting-nel-live":
        times["reporting-live-dwell-finished"] = times["action-issued"] + 2_000_000_000
        times["browser-exited"] = times["reporting-live-dwell-finished"] + 1
    if vector.family == "browser-service-control":
        terminal = vector.semantic_kind
        minimum_dwell_ns = vector.as_dict()["minimum_live_dwell_ms"] * 1_000_000
        times[terminal] = times["action-started"] + minimum_dwell_ns
        times["browser-exited"] = times[terminal] + 1
    times["reporting-grace-finished"] = times["browser-exited"] + 5_000_000_000
    times["observer-stopped"] = times["reporting-grace-finished"] + 2
    actor = {
        "started_ns": times["action-started"],
        "finished_ns": times[vector.semantic_kind],
        "measurement": _measurement(vector_id),
    }
    semantic = assemble_live_semantic_observation(
        vector=vector, actor_result=actor, event_times=times
    )
    pcap_relative = (
        f"evidence/{vector.ordinal:03d}--{vector.vector_id}/attempt-{attempt_number}/capture.pcapng"
    )
    pcap_path = result_root / pcap_relative
    packet_count = _write_pcap(pcap_path, vector_id=vector_id)
    analysis, decoder = analyse_pcap(pcap_path, vector=vector)
    dumpcap_version = _tool_version_stdout_first_line(Path("/usr/bin/dumpcap"), label="dumpcap")
    capture = {
        "schema_version": 2,
        "artifact_type": "qcsd-browser-egress-packet-capture",
        "vector_id": vector_id,
        "pcap": {
            "path": pcap_relative,
            "sha256": sha256_file(pcap_path),
            "size_bytes": pcap_path.stat().st_size,
        },
        "observer": {
            "network_namespace": "browser",
            "interface": "any",
            "capture_filter": None,
            "privileged": False,
            "cap_drop": ["ALL"],
            "cap_add": ["CAP_NET_RAW"],
            "separate_container": True,
        },
        "capture_process": {
            "exit_code": 0,
            "packets_captured": packet_count,
            "packets_received": packet_count,
            "packets_dropped_by_kernel": 0,
            "packets_dropped_by_interface": 0,
            "capture_path_drop_breakdown": {
                "pcap": 0,
                "dumpcap": 0,
                "flushed": 0,
            },
        },
        "capture_tool": {
            "path": "/usr/bin/dumpcap",
            "sha256": sha256_file(Path("/usr/bin/dumpcap")),
            "version_first_line": dumpcap_version,
            "argv": ["/usr/bin/dumpcap", "-q", "-i", "any", "-w", "<PCAP>"],
        },
        "chronology": {
            "observer_started_ns": base + 1,
            "observer_ready_ns": times["observer-ready"],
            "subject_started_ns": times["browser-started"],
            "subject_exited_ns": times["browser-exited"],
            "reporting_grace_finished_ns": times["reporting-grace-finished"],
            "observer_stopped_ns": times["observer-stopped"],
        },
        "packet_decoder": decoder,
        "analysis": analysis,
    }
    fixture = {
        "schema_version": 2,
        "vector_id": vector_id,
        "response_bundle_sha256": FIXTURE_RESPONSE_BUNDLE_SHA256,
        "response_headers_sha256": canonical_json_sha256(expected_fixture_response_headers(vector)),
        "tls_certificate_sha256": "d" * 64,
        "origins": {
            "primary": "https://172.30.98.11:14443",
            "cross": "https://172.30.98.11:14444",
            "preconnect": "https://172.30.98.11:14445",
            "nel_error": "https://172.30.98.11:14446",
        },
        "request_counts": expected_fixture_requests(vector),
        "connection_counts": expected_fixture_connection_counts(vector),
        "report_type_counts": expected_fixture_report_type_counts(vector),
        "chronology": {
            "started_ns": base,
            "ready_ns": times["observer-ready"],
            "stopped_ns": times["reporting-grace-finished"] + 1,
        },
    }
    validate_fixture_observation(fixture, vector=vector)
    sink = expected_sink_counters(vector)
    sink["chronology"] = {
        "forbidden_ready_ns": times["sinks-ready"] - 1,
        "dns_ready_ns": times["sinks-ready"],
        "forbidden_stopped_ns": times["reporting-grace-finished"] + 1,
        "dns_stopped_ns": times["reporting-grace-finished"] + 1,
    }
    receipt = build_passed_result_receipt(
        foundation=foundation,
        global_ordinal=global_ordinal,
        attempt_number=attempt_number,
        previous_result_sha256=previous_result_sha256,
        vector_id=vector_id,
        started_at=_wall_time(global_ordinal * 2),
        finished_at=_wall_time(global_ordinal * 2 + 1),
        runtime=_runtime(
            foundation,
            vector_id=vector_id,
            seed=seed,
            global_ordinal=global_ordinal,
            attempt_number=attempt_number,
            started_at=_wall_time(global_ordinal * 2),
        ),
        semantic=semantic,
        fixture=fixture,
        sink=sink,
        capture=capture,
    )
    return receipt, pcap_path


def test_docker_projection_binds_five_exact_distinct_roles_and_network() -> None:
    prepare = "sha256:" + "4" * 64
    vector_id = "constructor--page--websocket"
    attempt_topology = {
        "cohort_version": 71,
        "foundation_payload_sha256": "a" * 64,
        "global_ordinal": 1,
        "attempt_number": 1,
        "topology_token": "b" * 32,
    }
    projection = _docker_projection(vector_id, prepare, attempt_topology=attempt_topology)
    validate_docker_inspect_projection(
        projection,
        vector_id=vector_id,
        prepare_image_id=prepare,
        browser_uid=1000,
        browser_gid=1000,
        attempt_topology=attempt_topology,
        docker_root_dir="/var/lib/docker",
    )
    forged = copy.deepcopy(projection)
    forged["containers"]["fixture"]["id"] = forged["containers"]["browser"]["id"]
    with pytest.raises(ValueError, match="distinct"):
        validate_docker_inspect_projection(
            forged,
            vector_id=vector_id,
            prepare_image_id=prepare,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
        )
    second_network = copy.deepcopy(projection)
    second_network["containers"]["browser"]["network_attachments"].append(
        {
            "name": "unreceipted-egress",
            "network_id": "9" * 64,
            "endpoint_id": "8" * 64,
            "ipv4_address": "10.99.0.23",
            "ipv6_address": None,
        }
    )
    with pytest.raises(ValueError, match="one exact network attachment"):
        validate_docker_inspect_projection(
            second_network,
            vector_id=vector_id,
            prepare_image_id=prepare,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
        )
    unbound_member = copy.deepcopy(projection)
    unbound_member["network"]["members"]["browser"]["endpoint_id"] = "7" * 64
    with pytest.raises(ValueError, match="membership differs"):
        validate_docker_inspect_projection(
            unbound_member,
            vector_id=vector_id,
            prepare_image_id=prepare,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
        )
    wrong_snapshot_model = copy.deepcopy(projection)
    wrong_snapshot_model["snapshot_model"]["topology_source"] = "post-exit"
    with pytest.raises(ValueError, match="snapshot model"):
        validate_docker_inspect_projection(
            wrong_snapshot_model,
            vector_id=vector_id,
            prepare_image_id=prepare,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
        )


def test_npo0_policy_volume_projection_is_exact_and_content_minimised() -> None:
    prepare = "sha256:" + "4" * 64
    vector_id = "browser-service-control--off-the-record--speculation-prefetch-enabled"
    attempt_topology = {
        "cohort_version": 71,
        "foundation_payload_sha256": "a" * 64,
        "global_ordinal": 1,
        "attempt_number": 1,
        "topology_token": "b" * 32,
    }
    projection = _docker_projection(vector_id, prepare, attempt_topology=attempt_topology)
    validated = validate_docker_inspect_projection(
        projection,
        vector_id=vector_id,
        prepare_image_id=prepare,
        browser_uid=1000,
        browser_gid=1000,
        attempt_topology=attempt_topology,
        docker_root_dir="/var/lib/docker",
    )
    volume_name = f"qcsd-be-{'b' * 32}-policy0"
    assert validated["containers"]["browser"]["mounts"] == [
        {
            "type": "volume",
            "name": volume_name,
            "destination": POLICY_VOLUME_MANAGED_DIRECTORY,
            "rw": False,
        }
    ]
    assert validated["policy_volume"]["mountpoint_is_canonical"] is True
    assert "/var/lib/docker" not in canonical_json_bytes(validated).decode()

    mutations = (
        ("labels", "policy volume inspection"),
        ("mountpoint_sha256", "policy volume inspection"),
        ("file_inventory", "policy-volume file inventory"),
    )
    for field, message in mutations:
        forged = copy.deepcopy(projection)
        if field == "labels":
            forged["policy_volume"][field]["org.qcsd.topology-token"] = "c" * 32
        elif field == "mountpoint_sha256":
            forged["policy_volume"][field] = "d" * 64
        else:
            forged["policy_volume"][field][0]["mode"] = "0o644"
        with pytest.raises(ValueError, match=message):
            validate_docker_inspect_projection(
                forged,
                vector_id=vector_id,
                prepare_image_id=prepare,
                browser_uid=1000,
                browser_gid=1000,
                attempt_topology=attempt_topology,
                docker_root_dir="/var/lib/docker",
            )

    writable_mount = copy.deepcopy(projection)
    writable_mount["containers"]["browser"]["mounts"][0]["rw"] = True
    with pytest.raises(ValueError, match="runtime isolation"):
        validate_docker_inspect_projection(
            writable_mount,
            vector_id=vector_id,
            prepare_image_id=prepare,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
        )


def test_positive_control_subject_cannot_be_misrepresented_as_browser(tmp_path: Path) -> None:
    _lab_root, foundation = _lab(tmp_path)
    vector_id = "positive-control--fixture--tcp"
    runtime = _runtime(foundation, vector_id=vector_id, seed=90)
    validate_runtime_binding(
        runtime,
        foundation=foundation,
        vector_id=vector_id,
        global_ordinal=1,
        attempt_number=1,
        started_at=_wall_time(2),
    )
    forged = copy.deepcopy(runtime)
    forged["subject_kind"] = "independent-control-emitter"
    with pytest.raises(ValueError, match="subject kind"):
        validate_runtime_binding(
            forged,
            foundation=foundation,
            vector_id=vector_id,
            global_ordinal=1,
            attempt_number=1,
            started_at=_wall_time(2),
        )


def test_proxy_configuration_claim_is_exact_and_hash_bound_to_runtime(
    tmp_path: Path,
) -> None:
    _lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "qualification"
    receipt, _pcap = _passed_receipt(
        result_root,
        foundation,
        vector_id="browser-service--browser--proxy",
        global_ordinal=1,
        attempt_number=1,
        previous_result_sha256="0" * 64,
        seed=91,
    )
    payload = copy.deepcopy(receipt["payload"])
    observation = payload["semantic"]["measurement"]["configuration_observation"]
    assert observation["no_proxy_server_argument_count"] == 1
    forged = copy.deepcopy(payload)
    forged["semantic"]["measurement"]["configuration_observation"][
        "effective_argv_projection_sha256"
    ] = "f" * 64
    with pytest.raises(ValueError, match="measured runtime"):
        validate_result_payload(forged, foundation=foundation)
    forged = copy.deepcopy(payload["semantic"])
    forged["measurement"]["configuration_observation"]["no_proxy_server_argument_count"] = 0
    with pytest.raises(ValueError, match="configuration observation"):
        validate_semantic_observation(
            forged, vector=vector_by_id("browser-service--browser--proxy")
        )


def test_final_result_path_requires_literal_json_suffix() -> None:
    results = [
        {
            "vector_ordinal": ordinal,
            "vector_id": vector.vector_id,
            "attempt_number": 1,
            "path": f"attempts/result-{ordinal:04d}.json",
            "sha256": "a" * 64,
            "payload_sha256": "b" * 64,
        }
        for ordinal, vector in enumerate(expected_vectors(), 1)
    ]
    payload = {
        "schema_version": FINAL_SCHEMA_VERSION,
        "qualification_id": QUALIFICATION_ID,
        "study_id": "classifier-multiorigin100-v1",
        "cohort_version": 1,
        "qualification_started_at": "2026-09-06T00:00:00Z",
        "qualification_finished_at": "2026-09-06T00:01:00Z",
        "recorded_at": "2026-09-06T00:02:00Z",
        "foundation": {
            "path": "foundation.json",
            "sha256": "c" * 64,
            "payload_sha256": "d" * 64,
        },
        "checkpoint": {"path": "experiment.json", "sha256": "e" * 64},
        "expanded_vectors_sha256": expanded_vectors_sha256(),
        "passed_results": results,
        "attempt_count": len(results),
        "passed_vector_count": len(results),
        "operational_failure_count": 0,
        "semantic_failure_count": 0,
        "packet_level_egress_qualification": "passed",
        "consumer_contract": CONSUMER_CONTRACT,
        "verdict": "passed",
    }
    validate_final_payload(payload)
    payload["passed_results"][0]["path"] = "attempts/result-0001Xjson"
    with pytest.raises(ValueError, match="binding"):
        validate_final_payload(payload)


def test_effective_argv_contract_uses_production_projection() -> None:
    arguments = _effective_arguments()
    projection = validate_browser_egress_command_line({"arguments": arguments})
    assert projection["required_switches_are_bare_and_unique"] is True
    assert projection["observed_antagonistic_switches"] == []


def test_every_vector_effective_argv_matches_its_exact_launch_contract() -> None:
    for vector in expected_vectors():
        projection = _effective_projection(vector.vector_id)
        binding = {
            "schema_version": EFFECTIVE_ARGV_BINDING_SCHEMA_VERSION,
            "projection_sha256": canonical_json_sha256(projection),
            "command_line_projection": projection,
        }
        assert _validate_effective_argv(binding, vector_id=vector.vector_id) == binding


def test_runtime_rejects_a_valid_but_different_resolver_allowlist(
    tmp_path: Path,
) -> None:
    _lab_root, foundation = _lab(tmp_path)
    vector_id = "constructor--page--websocket"
    runtime = _runtime(foundation, vector_id=vector_id, seed=18)
    forged_arguments = _effective_arguments()
    forged_arguments[-1] = build_fail_closed_host_resolver_argument(
        approved_ip_exclusions=("172.30.98.12",)
    )
    runtime["effective_argv"] = {
        "schema_version": EFFECTIVE_ARGV_BINDING_SCHEMA_VERSION,
        "projection_sha256": canonical_json_sha256(
            validate_browser_egress_command_line({"arguments": forged_arguments})
        ),
        "command_line_projection": validate_browser_egress_command_line(
            {"arguments": forged_arguments}
        ),
    }
    with pytest.raises(ValueError, match="effective argv projection"):
        validate_runtime_binding(
            runtime,
            foundation=foundation,
            vector_id=vector_id,
            global_ordinal=1,
            attempt_number=1,
            started_at=_wall_time(2),
        )


def test_runtime_requires_doh_off_and_root_owned_fixture_tls(tmp_path: Path) -> None:
    _lab_root, foundation = _lab(tmp_path)
    vector_id = "constructor--page--websocket"
    runtime = _runtime(foundation, vector_id=vector_id, seed=19)
    validate_runtime_binding(
        runtime,
        foundation=foundation,
        vector_id=vector_id,
        global_ordinal=1,
        attempt_number=1,
        started_at=_wall_time(2),
    )

    forged_doh = copy.deepcopy(runtime)
    forged_doh["driver_runtime"]["dns_over_https_mode"] = "automatic"
    with pytest.raises(ValueError, match="driver runtime"):
        validate_runtime_binding(
            forged_doh,
            foundation=foundation,
            vector_id=vector_id,
            global_ordinal=1,
            attempt_number=1,
            started_at=_wall_time(2),
        )

    for field, key, value in (
        ("certificate", "uid", 1000),
        ("private_key", "mode", "0o644"),
    ):
        forged_tls = copy.deepcopy(runtime)
        forged_tls["fixture_tls_runtime"][field][key] = value
        with pytest.raises(ValueError, match="fixture TLS runtime"):
            validate_runtime_binding(
                forged_tls,
                foundation=foundation,
                vector_id=vector_id,
                global_ordinal=1,
                attempt_number=1,
                started_at=_wall_time(2),
            )


def test_independent_tcp_udp_dns_sink_roles_measure_live_socket_input() -> None:
    tcp = IndependentTcpSink("127.0.0.1", 0)
    tcp.start()
    with socket.create_connection(("127.0.0.1", tcp.port), timeout=1) as stream:
        stream.sendall(b"abc")
    time.sleep(0.02)
    assert tcp.stop()["received_payload_bytes"] == 3

    udp = IndependentUdpSink("127.0.0.1", 0)
    udp.start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
        datagram.sendto(b"abcd", ("127.0.0.1", udp.port))
    time.sleep(0.02)
    assert udp.stop()["payload_bytes_received"] == 4

    dns = IndependentDnsSink("127.0.0.1", 0)
    dns.start()
    udp_query = dns_query_message("udp-control.egress.invalid", identifier=1)
    tcp_query = dns_query_message("tcp-control.egress.invalid", identifier=2)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
        datagram.sendto(udp_query, ("127.0.0.1", dns.port))
    with socket.create_connection(("127.0.0.1", dns.port), timeout=1) as stream:
        stream.sendall(struct.pack("!H", len(tcp_query)) + tcp_query)
    time.sleep(0.02)
    dns_result = dns.stop()
    assert dns_result["udp_names"] == ["udp-control.egress.invalid"]
    assert dns_result["tcp_names"] == ["tcp-control.egress.invalid"]


def test_websocket_route_and_unavailable_constructor_are_honest_raw_outcomes() -> None:
    websocket = vector_by_id("constructor--page--websocket")
    websocket_events = expected_semantic_chronology(websocket)
    websocket_actor = {
        "started_ns": 5,
        "finished_ns": 6,
        "measurement": {
            "resolved_type": "function",
            "own_descriptor": "data",
            "prearm_verified": True,
            "action_issued": True,
            "action_succeeded": True,
            "policy_event_count": 1,
            "fetch_denial_count": 0,
            "fetch_denials": [],
            "exception_name": None,
            "control_observed": False,
            "configuration_observation": None,
        },
    }
    observed = assemble_live_semantic_observation(
        vector=websocket,
        actor_result=websocket_actor,
        event_times={event: index for index, event in enumerate(websocket_events, 1)},
    )
    assert observed["observed_kind"] == "websocket-route-block"

    unavailable = vector_by_id("constructor--page--tcp-client")
    unavailable_events = expected_semantic_chronology(unavailable)
    unavailable_actor = {
        "started_ns": 5,
        "finished_ns": 6,
        "measurement": {
            "resolved_type": "undefined",
            "own_descriptor": "absent",
            "prearm_verified": True,
            "action_issued": False,
            "action_succeeded": False,
            "policy_event_count": 0,
            "fetch_denial_count": 0,
            "fetch_denials": [],
            "exception_name": None,
            "control_observed": False,
            "configuration_observation": None,
        },
    }
    assert (
        assemble_live_semantic_observation(
            vector=unavailable,
            actor_result=unavailable_actor,
            event_times={event: index for index, event in enumerate(unavailable_events, 1)},
        )["observed_kind"]
        == "disabled-unavailable"
    )


def test_service_worker_actions_and_shared_worker_protocol_are_distinct() -> None:
    vectors = [
        vector_by_id(f"service-worker--page--{surface}")
        for surface in ("registration", "import", "fetch")
    ]
    arguments = [expected_browser_action_arguments(vector) for vector in vectors]
    selected = [
        arguments[0]["serviceWorkerRegistrationUrl"],
        arguments[1]["serviceWorkerImportUrl"],
        arguments[2]["serviceWorkerFetchUrl"],
    ]
    assert len(set(selected)) == 3
    assert selected[0].endswith("/service-worker-registration.js")
    assert "/service-worker-import.js?target=" in selected[1]
    assert "/service-worker-fetch.js?target=" in selected[2]

    shared = vector_by_id("constructor--shared-worker--webtransport")
    message = shared_worker_action_message(shared)
    assert message["protocol"] == "qcsd-shared-worker-action-v1"
    assert message["argument"]["surface"] == "webtransport"
    assert "async ({family, surface" in message["expression"]


def test_dedicated_worker_action_message_is_exact_and_context_typed() -> None:
    dedicated = vector_by_id("constructor--dedicated-worker--websocket")
    message = dedicated_worker_action_message(dedicated)
    assert message == {
        "protocol": "qcsd-dedicated-worker-action-v1",
        "expression": browser_action_expression(),
        "argument": {
            **expected_browser_action_arguments(dedicated),
            "family": dedicated.family,
            "surface": dedicated.surface,
        },
    }

    for wrong_context in (
        vector_by_id("constructor--page--websocket"),
        vector_by_id("constructor--shared-worker--websocket"),
    ):
        with pytest.raises(ValueError, match="requires a dedicated-worker vector"):
            dedicated_worker_action_message(wrong_context)
    with pytest.raises(ValueError, match="requires a shared-worker vector"):
        shared_worker_action_message(dedicated)


def test_dedicated_worker_fixture_installs_a_strict_ready_action_protocol() -> None:
    content_type, body = _FIXTURE_RESPONSES["/dedicated-worker.js"]
    script = body.decode("ascii")

    assert content_type == "text/javascript; charset=utf-8"
    assert "fields !== 'argument,expression,protocol'" in script
    assert "data.protocol !== 'qcsd-dedicated-worker-action-v1'" in script
    assert "typeof data.expression !== 'string'" in script
    assert "typeof data.argument !== 'object'" in script
    assert "const actor = (0, eval)(`(${data.expression})`);" in script
    assert "const result = await actor(data.argument);" in script
    result = "self.postMessage({protocol:data.protocol,result});"
    ready = "self.postMessage({protocol:'qcsd-dedicated-worker-action-v1',ready:true});"
    assert script.index("self.onmessage = async message => {") < script.index(ready)
    assert script.index("const result = await actor(data.argument);") < script.index(result)
    assert "token:event.data" not in script


def test_reporting_nel_live_dwell_and_close_flush_are_temporally_distinct() -> None:
    live = vector_by_id("browser-service--browser--reporting-nel-live")
    live_events = expected_semantic_chronology(live)
    live_times = {event: index for index, event in enumerate(live_events, 1)}
    live_times["reporting-live-dwell-finished"] = live_times["action-issued"] + 2_000_000_000
    live_times["browser-exited"] = live_times["reporting-live-dwell-finished"] + 1
    live_times["reporting-grace-finished"] = live_times["browser-exited"] + 1
    live_times["observer-stopped"] = live_times["reporting-grace-finished"] + 1
    actor = {
        "started_ns": live_times["action-started"],
        "finished_ns": live_times["action-issued"],
        "measurement": _measurement(live.vector_id),
    }
    assemble_live_semantic_observation(vector=live, actor_result=actor, event_times=live_times)
    too_short = dict(live_times)
    too_short["reporting-live-dwell-finished"] = too_short["action-issued"] + 1
    too_short["browser-exited"] = too_short["reporting-live-dwell-finished"] + 1
    too_short["reporting-grace-finished"] = too_short["browser-exited"] + 1
    too_short["observer-stopped"] = too_short["reporting-grace-finished"] + 1
    with pytest.raises(ValueError, match="dwell"):
        assemble_live_semantic_observation(vector=live, actor_result=actor, event_times=too_short)

    close = vector_by_id("browser-service--browser--reporting-nel-close-flush")
    close_events = expected_semantic_chronology(close)
    close_times = {event: index for index, event in enumerate(close_events, 1)}
    close_actor = {
        "started_ns": close_times["action-started"],
        "finished_ns": close_times["action-issued"],
        "measurement": _measurement(close.vector_id),
    }
    assemble_live_semantic_observation(
        vector=close, actor_result=close_actor, event_times=close_times
    )
    too_slow = dict(close_times)
    too_slow["browser-exited"] = too_slow["action-issued"] + 2_000_000_001
    too_slow["reporting-grace-finished"] = too_slow["browser-exited"] + 1
    too_slow["observer-stopped"] = too_slow["reporting-grace-finished"] + 1
    with pytest.raises(ValueError, match="prompt"):
        assemble_live_semantic_observation(
            vector=close, actor_result=close_actor, event_times=too_slow
        )


def test_negative_vectors_alternate_ipv4_ipv6_and_dns_actions_use_a_hostname() -> None:
    grouped: dict[tuple[str, str], set[str]] = {}
    for vector in expected_vectors():
        if vector.family == "positive-control":
            continue
        host = expected_browser_action_arguments(vector)["udpHost"]
        grouped.setdefault((vector.family, vector.context), set()).add(
            "ipv6" if ":" in host else "ipv4"
        )
        forbidden_url = expected_browser_action_arguments(vector)["forbiddenUrl"]
        if ":" in host:
            assert f"[{host}]" in forbidden_url
    assert all(families == {"ipv4", "ipv6"} for families in grouped.values())
    dns_vector = vector_by_id("browser-service--browser--dns-prefetch")
    dns_arguments = expected_browser_action_arguments(dns_vector)
    dns_url = dns_arguments["dnsPrefetchUrl"]
    assert dns_url == dns_arguments["forbiddenHostnameUrl"]
    assert "forbidden.browser-egress.invalid" in dns_url
    assert "172.30.98." not in dns_url
    contract = expected_browser_launch_contract(dns_vector)
    assert all(
        "forbidden.browser-egress.invalid" not in origin
        for origin in contract["resolver_approved_origins"]
    )
    assert "forbidden.browser-egress.invalid" not in contract["resolver_origin_ip_pins"]
    assert contract["dns_exception_hostname"] is None


def test_reporting_fixture_binds_headers_trigger_and_request_inventory() -> None:
    vector = vector_by_id("browser-service--browser--reporting-nel-close-flush")
    headers = expected_fixture_response_headers(vector)
    assert set(headers["primary:/"]) == {
        "Content-Security-Policy-Report-Only",
        "NEL",
        "Report-To",
        "Reporting-Endpoints",
    }
    assert expected_fixture_requests(vector) == {"primary:/": 1, "primary:/nel-trigger": 1}
    observation = {
        "schema_version": 2,
        "vector_id": vector.vector_id,
        "response_bundle_sha256": FIXTURE_RESPONSE_BUNDLE_SHA256,
        "response_headers_sha256": canonical_json_sha256(headers),
        "tls_certificate_sha256": "a" * 64,
        "origins": {
            "primary": "https://172.30.98.11:14443",
            "cross": "https://172.30.98.11:14444",
            "preconnect": "https://172.30.98.11:14445",
            "nel_error": "https://172.30.98.11:14446",
        },
        "request_counts": expected_fixture_requests(vector),
        "connection_counts": expected_fixture_connection_counts(vector),
        "report_type_counts": expected_fixture_report_type_counts(vector),
        "chronology": {"started_ns": 1, "ready_ns": 2, "stopped_ns": 3},
    }
    validate_fixture_observation(observation, vector=vector)
    observation["request_counts"].pop("primary:/nel-trigger")
    with pytest.raises(ValueError, match="request"):
        validate_fixture_observation(observation, vector=vector)


def test_genuine_dual_origin_https_fixture_serves_and_measures_requests(
    tmp_path: Path,
) -> None:
    certificate = tmp_path / "certificate.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=fixture.test",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, key)
    vector = vector_by_id("browser-service--browser--reporting-nel-live")
    server = BrowserFixtureServer(
        tls_context=server_context,
        tls_certificate_sha256=sha256_file(certificate),
        vector=vector,
        host="127.0.0.1",
    )
    server.start()
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(
            "https://127.0.0.1:14443/", context=client_context, timeout=2
        ) as response:
            assert response.status == 200
            assert response.headers["Reporting-Endpoints"].startswith('qcsd="https://')
        with urllib.request.urlopen(
            "https://127.0.0.1:14443/nel-trigger",
            context=client_context,
            timeout=2,
        ) as response:
            assert response.read() == b"qcsd reporting trigger\n"
    finally:
        observation = server.stop(vector=vector)
    assert observation["request_counts"] == {
        "primary:/": 1,
        "primary:/nel-trigger": 1,
    }


def test_source_binding_closes_known_runner_and_core_dependencies() -> None:
    required = set(REQUIRED_SOURCE_BINDING_PATHS)
    assert {
        "qcsd-lab",
        "tools/docker_lifecycle_lock_guardian.py",
        "tools/docker_lifecycle_native.py",
        "tools/docker_signal_supervisor.sh",
        "tools/browser_egress_qualification.py",
        "src/qcsd_lab/browser_egress_fixture.py",
        "src/qcsd_lab/browser_egress_observer.py",
        "src/qcsd_lab/browser_egress_qualification.py",
        "src/qcsd_lab/class_acquisition.py",
        "src/qcsd_lab/browser_egress.py",
        "src/qcsd_lab/build_storage.py",
        "src/qcsd_lab/capture.py",
        "src/qcsd_lab/class_run_binding.py",
        "src/qcsd_lab/class_study.py",
        "src/qcsd_lab/buflo_study.py",
        "src/qcsd_lab/defenses.py",
        "src/qcsd_lab/discovery_evidence.py",
        "src/qcsd_lab/fidelity.py",
        "src/qcsd_lab/fitting_trace.py",
        "src/qcsd_lab/fitting_walkie_talkie.py",
        "src/qcsd_lab/kernel_tx.py",
        "src/qcsd_lab/manifest.py",
        "src/qcsd_lab/parameters.py",
        "src/qcsd_lab/profiles.py",
        "src/qcsd_lab/util.py",
        "src/qcsd_lab/pinned_cdp.py",
        "src/qcsd_lab/cdp_targets.py",
        "src/qcsd_lab/playwright_driver.py",
        "tools/windows_docker_storage_probe.ps1",
    } <= required
    assert "tools/class_acquisition_watch.py" not in required


def test_browser_qualification_module_scope_import_closure_is_source_bound() -> None:
    root = Path(__file__).resolve().parents[1]
    required = set(REQUIRED_SOURCE_BINDING_PATHS)
    pending = [root / "tools/browser_egress_qualification.py"]
    visited: set[str] = set()
    while pending:
        path = pending.pop().resolve()
        relative = path.relative_to(root).as_posix()
        if relative in visited:
            continue
        visited.add(relative)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        if relative.startswith("src/qcsd_lab/"):
            module = "qcsd_lab." + relative.removeprefix("src/qcsd_lab/").removesuffix(
                ".py"
            ).replace("/", ".")
        else:
            module = None
        statements: list[ast.AST] = list(tree.body)
        while statements:
            statement = statements.pop()
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                continue
            imported: list[str] = []
            if isinstance(statement, ast.ImportFrom):
                if statement.level:
                    if module is None:
                        continue
                    parent = module.split(".")[:-1]
                    parent = parent[: len(parent) - (statement.level - 1)]
                    if statement.module:
                        imported = [".".join(parent + [statement.module])]
                    else:
                        imported = [".".join(parent + [alias.name]) for alias in statement.names]
                elif statement.module is not None:
                    imported = [statement.module]
                    if statement.module == "qcsd_lab":
                        imported.extend(f"qcsd_lab.{alias.name}" for alias in statement.names)
            elif isinstance(statement, ast.Import):
                imported = [alias.name for alias in statement.names]
            else:
                statements.extend(ast.iter_child_nodes(statement))
            for imported_module in imported:
                if imported_module == "qcsd_lab":
                    candidate = root / "src/qcsd_lab/__init__.py"
                elif imported_module.startswith("qcsd_lab."):
                    candidate = (
                        root
                        / "src/qcsd_lab"
                        / (imported_module.removeprefix("qcsd_lab.").replace(".", "/") + ".py")
                    )
                else:
                    continue
                if candidate.is_file():
                    pending.append(candidate)
    assert visited <= required


def test_browser_qualification_runner_host_inputs_are_source_bound() -> None:
    launcher = (Path(__file__).resolve().parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    for relative in (
        "src/qcsd_lab/build_storage.py",
        "tools/windows_docker_storage_probe.ps1",
    ):
        assert f"${{ROOT}}/{relative}" in launcher
        assert relative in REQUIRED_SOURCE_BINDING_PATHS


@pytest.mark.parametrize(
    "relative",
    (
        "src/qcsd_lab/build_storage.py",
        "src/qcsd_lab/capture.py",
        "src/qcsd_lab/class_run_binding.py",
        "src/qcsd_lab/defenses.py",
        "src/qcsd_lab/discovery_evidence.py",
        "src/qcsd_lab/fidelity.py",
        "src/qcsd_lab/fitting_trace.py",
        "src/qcsd_lab/fitting_walkie_talkie.py",
        "src/qcsd_lab/kernel_tx.py",
        "src/qcsd_lab/manifest.py",
        "src/qcsd_lab/parameters.py",
        "src/qcsd_lab/profiles.py",
        "tools/docker_lifecycle_lock_guardian.py",
        "tools/docker_lifecycle_native.py",
        "tools/windows_docker_storage_probe.ps1",
    ),
)
def test_foundation_binds_execution_inputs_against_omission_and_mutation(
    tmp_path: Path, relative: str
) -> None:
    lab_root, foundation = _lab(tmp_path)
    validator = _BuildValidator(foundation)
    deep_validate_foundation(
        foundation,
        lab_root=lab_root,
        build_validator=validator,
        mode=FoundationVerificationMode.PORTABLE_REPLAY,
    )

    omitted = copy.deepcopy(foundation)
    omitted["source_files"] = [
        binding for binding in omitted["source_files"] if binding["path"] != relative
    ]
    with pytest.raises(ValueError, match="source file inventory"):
        validate_foundation_payload(omitted)

    (lab_root / relative).write_text("post-foundation mutation\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source binding does not verify"):
        deep_validate_foundation(
            foundation,
            lab_root=lab_root,
            build_validator=validator,
            mode=FoundationVerificationMode.PORTABLE_REPLAY,
        )


def test_foundation_has_explicit_prepare_execution_and_portable_replay_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_root, foundation = _lab(tmp_path)
    validator = _BuildValidator(foundation)
    deep_validate_foundation(
        foundation,
        lab_root=lab_root,
        build_validator=validator,
        mode=FoundationVerificationMode.PORTABLE_REPLAY,
    )

    import qcsd_lab.util as util_module

    def wrong_source() -> dict:
        value = copy.deepcopy(foundation["source"])
        value["lab_commit"] = "9" * 40
        return value

    monkeypatch.setattr(util_module, "source_metadata", wrong_source)
    with pytest.raises(ValueError, match="live source"):
        deep_validate_foundation(
            foundation,
            lab_root=lab_root,
            build_validator=validator,
            mode=FoundationVerificationMode.EXECUTION,
        )
    with pytest.raises(ValueError, match="mode"):
        deep_validate_foundation(
            foundation,
            lab_root=lab_root,
            build_validator=validator,
            mode="portable-attestation-replay",  # type: ignore[arg-type]
        )


def test_absent_or_tampered_pcap_cannot_publish_or_advance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_root, foundation = _lab(tmp_path)
    for case in ("absent", "tampered"):
        result_root = tmp_path / case
        _admit_create(
            monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation
        )
        receipt, pcap = _passed_receipt(
            result_root,
            foundation,
            vector_id="constructor--page--websocket",
            global_ordinal=1,
            attempt_number=1,
            previous_result_sha256="0" * 64,
            seed=1,
        )
        if case == "absent":
            pcap.unlink()
        else:
            pcap.write_bytes(pcap.read_bytes() + b"tamper")
        with pytest.raises(ValueError, match="PCAP|artifact"):
            append_result(result_root, receipt)
        assert list((result_root / "attempts").iterdir()) == []
        assert load_checkpoint(result_root)["attempts"] == []


def test_attempt_intent_is_durable_and_resume_seals_interruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "interrupted"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    binding = _begin_intent(
        result_root,
        vector_id="constructor--page--websocket",
        started_at=_wall_time(1),
    )
    intent_path = result_root / binding["path"]
    assert intent_path.is_file()
    assert sha256_file(intent_path) == binding["sha256"]
    with pytest.raises(ValueError, match="outstanding attempt"):
        _begin_intent(
            result_root,
            vector_id="constructor--page--websocket",
            started_at=_wall_time(2),
        )

    attempt = result_root / "evidence/001--constructor--page--websocket/attempt-1"
    attempt.parent.mkdir(mode=0o700)
    attempt.mkdir(mode=0o700)
    (attempt / "browser.log").write_text("partial role output\n", encoding="utf-8")
    (attempt / "browser.log").chmod(0o600)
    (attempt / "capture.pcapng").write_bytes(b"partial interrupted capture")
    (attempt / "capture.pcapng").chmod(0o600)
    checkpoint = recover_interrupted_attempt(result_root, finished_at=_wall_time(2))
    assert checkpoint["status"] == "running"
    assert checkpoint["attempts"][-1]["verdict"] == "operational-failure"
    result_path = result_root / "attempts/result-0001.json"
    assert result_path.is_file()
    result = json.loads(result_path.read_text(encoding="utf-8"))["payload"]
    assert result["failure_code"] == "interrupted"
    assert (attempt / "capture.pcapng").read_bytes() == b"partial interrupted capture"
    assert (attempt / "resume-recovery.json").is_file()


def test_resume_rejects_tampered_intent_and_unknown_partial_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "tampered"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    binding = _begin_intent(
        result_root,
        vector_id="constructor--page--websocket",
        started_at=_wall_time(1),
    )
    intent_path = result_root / binding["path"]
    intent_path.write_bytes(intent_path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="JSON|payload|intent"):
        recover_interrupted_attempt(result_root, finished_at=_wall_time(2))
    assert list((result_root / "attempts").iterdir()) == []

    clean_root = tmp_path / "unknown-artifact"
    _admit_create(monkeypatch, result_root=clean_root, lab_root=lab_root, foundation=foundation)
    _begin_intent(
        clean_root,
        vector_id="constructor--page--websocket",
        started_at=_wall_time(1),
    )
    attempt = clean_root / "evidence/001--constructor--page--websocket/attempt-1"
    attempt.parent.mkdir(mode=0o700)
    attempt.mkdir(mode=0o700)
    (attempt / "unbound.bin").write_bytes(b"unbound")
    (attempt / "unbound.bin").chmod(0o600)
    with pytest.raises(ValueError, match="unknown artifact"):
        recover_interrupted_attempt(clean_root, finished_at=_wall_time(2))
    assert list((clean_root / "attempts").iterdir()) == []


def test_resume_binds_exact_partially_promoted_causal_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "causal-artifacts"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    vector_id = "constructor--page--websocket"
    _begin_intent(result_root, vector_id=vector_id, started_at=_wall_time(1))
    attempt = result_root / f"evidence/001--{vector_id}/attempt-1"
    attempt.parent.mkdir(mode=0o700)
    attempt.mkdir(mode=0o700)
    expected = {
        "causal-actor.json",
        "causal-capture.json",
        "causal-runtime.json",
        "capture-closure.json",
    }
    for name in expected:
        path = attempt / name
        path.write_bytes(
            canonical_json_bytes({"schema_version": 1, "vector_id": vector_id, "name": name})
        )
        path.chmod(0o600)

    checkpoint = recover_interrupted_attempt(result_root, finished_at=_wall_time(2))
    assert checkpoint["attempts"][-1]["verdict"] == "operational-failure"
    result = json.loads((result_root / "attempts/result-0001.json").read_text(encoding="utf-8"))[
        "payload"
    ]
    bound = {Path(item["path"]).name for item in result["failure_evidence"]["artifacts"]}
    assert expected <= bound
    assert "resume-recovery.json" in bound


def test_resume_repairs_only_exact_one_result_checkpoint_publish_lag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import qcsd_lab.browser_egress_qualification as qualification

    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "publish-lag"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    _begin_intent(
        result_root,
        vector_id="constructor--page--websocket",
        started_at=_wall_time(1),
    )
    receipt = build_failure_result_receipt(
        foundation=foundation,
        global_ordinal=1,
        attempt_number=1,
        previous_result_sha256="0" * 64,
        vector_id="constructor--page--websocket",
        started_at=_wall_time(1),
        finished_at=_wall_time(2),
        verdict="operational-failure",
        failure_code="docker-start-failed",
        failure_artifacts=[],
    )
    original_atomic_json = qualification.atomic_json

    def interrupted_checkpoint_write(_path: Path, _value: object) -> None:
        raise OSError("simulated interruption after result publication")

    monkeypatch.setattr(qualification, "atomic_json", interrupted_checkpoint_write)
    with pytest.raises(OSError, match="simulated interruption"):
        append_result(result_root, receipt)
    monkeypatch.setattr(qualification, "atomic_json", original_atomic_json)
    checkpoint = recover_interrupted_attempt(result_root, finished_at=_wall_time(3))
    assert len(checkpoint["attempts"]) == 1
    result = json.loads((result_root / "attempts/result-0001.json").read_text(encoding="utf-8"))[
        "payload"
    ]
    assert result["failure_code"] == "docker-start-failed"

    stored = json.loads((result_root / "experiment.json").read_text(encoding="utf-8"))
    stored["chain_head_sha256"] = "f" * 64
    (result_root / "experiment.json").write_bytes(canonical_json_bytes(stored))
    with pytest.raises(ValueError, match="checkpoint"):
        recover_interrupted_attempt(result_root, finished_at=_wall_time(4))


def test_retry_terminal_semantics_and_reused_docker_ids_fail_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "retry"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    _begin_intent(
        result_root,
        vector_id="constructor--page--websocket",
        started_at=_wall_time(1),
    )
    first = build_failure_result_receipt(
        foundation=foundation,
        global_ordinal=1,
        attempt_number=1,
        previous_result_sha256="0" * 64,
        vector_id="constructor--page--websocket",
        started_at=_wall_time(1),
        finished_at=_wall_time(2),
        verdict="operational-failure",
        failure_code="docker-start-failed",
        failure_artifacts=[],
    )
    checkpoint = append_result(result_root, first)
    assert checkpoint["status"] == "running"
    _begin_intent(
        result_root,
        vector_id="constructor--page--websocket",
        started_at=_wall_time(3),
    )
    terminal = build_failure_result_receipt(
        foundation=foundation,
        global_ordinal=2,
        attempt_number=2,
        previous_result_sha256=checkpoint["chain_head_sha256"],
        vector_id="constructor--page--websocket",
        started_at=_wall_time(3),
        finished_at=_wall_time(4),
        verdict="semantic-failure",
        failure_code="semantic-observation-failed",
        failure_artifacts=[],
    )
    checkpoint = append_result(result_root, terminal)
    assert checkpoint["status"] == "failed"
    with pytest.raises(ValueError, match="terminal"):
        append_result(result_root, terminal)
    assert len(list((result_root / "attempts").iterdir())) == 2

    unique_root = tmp_path / "unique"
    _admit_create(monkeypatch, result_root=unique_root, lab_root=lab_root, foundation=foundation)
    first_pass, _ = _passed_receipt(
        unique_root,
        foundation,
        vector_id="constructor--page--websocket",
        global_ordinal=1,
        attempt_number=1,
        previous_result_sha256="0" * 64,
        seed=7,
    )
    checkpoint = append_result(unique_root, first_pass)
    second_pass, _ = _passed_receipt(
        unique_root,
        foundation,
        vector_id="constructor--page--websocket-stream",
        global_ordinal=2,
        attempt_number=1,
        previous_result_sha256=checkpoint["chain_head_sha256"],
        seed=7,
    )
    with pytest.raises(ValueError, match="reused"):
        append_result(unique_root, second_pass)
    assert len(list((unique_root / "attempts").iterdir())) == 1


@pytest.mark.parametrize(
    "boundary,published",
    (
        ("create-only:foundation.json:pre-link", False),
        ("create-only:foundation.json:post-link", False),
        ("atomic:experiment.json:pre-replace", False),
        ("atomic:experiment.json:post-replace", False),
        ("initial-create:staging-created", False),
        ("initial-create:directories-created", False),
        ("initial-create:foundation-published", False),
        ("initial-create:pre-publish", False),
        ("initial-create:post-publish", True),
    ),
)
def test_initial_create_is_transactional_at_every_durability_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    published: bool,
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / f"create-{boundary.replace(':', '-')}"
    unrelated = tmp_path / "unrelated.keep"
    unrelated.write_text("preserve\n", encoding="utf-8")
    _fork_crash_at(
        boundary,
        lambda: _admit_create(
            monkeypatch,
            result_root=result_root,
            lab_root=lab_root,
            foundation=foundation,
        ),
    )
    if published:
        assert result_root.is_dir()
        assert load_checkpoint(result_root)["attempts"] == []
    else:
        assert not result_root.exists()
        _admit_create(
            monkeypatch,
            result_root=result_root,
            lab_root=lab_root,
            foundation=foundation,
        )
        assert not list(tmp_path.glob(f".{result_root.name}.*.qcsd-tmp"))
    assert unrelated.read_text(encoding="utf-8") == "preserve\n"
    assert result_root.stat().st_mode & 0o777 == 0o700
    assert (result_root / "foundation.json").stat().st_mode & 0o777 == 0o600


def test_canonical_foundation_post_link_residue_is_exactly_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "foundation-residue"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    target = result_root / "foundation.json"
    residue = result_root / ".foundation.json.deadbeef.qcsd-tmp"
    os.link(target, residue)
    assert target.stat().st_nlink == 2
    outcome = reconcile_qualification_filesystem(result_root)
    assert outcome["reconciled"] is True
    assert not residue.exists()
    assert target.stat().st_nlink == 1


@pytest.mark.parametrize("attack", ("multiple", "symlink", "rogue"))
def test_initialisation_recovery_rejects_hostile_staging_without_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attack: str
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / f"staging-{attack}"
    first = tmp_path / f".{result_root.name}.deadbeef.qcsd-tmp"
    first.mkdir(mode=0o700)
    if attack == "multiple":
        second = tmp_path / f".{result_root.name}.feedface.qcsd-tmp"
        second.mkdir(mode=0o700)
    elif attack == "symlink":
        first.rmdir()
        first.symlink_to(lab_root, target_is_directory=True)
    else:
        rogue = first / "unbound.bin"
        rogue.write_bytes(b"unbound")
        rogue.chmod(0o600)
    with pytest.raises(ValueError):
        _admit_create(
            monkeypatch,
            result_root=result_root,
            lab_root=lab_root,
            foundation=foundation,
        )
    assert first.exists() or first.is_symlink()
    assert not result_root.exists()


@pytest.mark.parametrize("phase", ("pre-link", "post-link"))
def test_attempt_intent_create_only_residue_is_exactly_recovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / f"intent-{phase}"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    vector_id = "constructor--page--websocket"
    _fork_crash_at(
        f"create-only:intent-0001.json:{phase}",
        lambda: _begin_intent(result_root, vector_id=vector_id, started_at=_wall_time(1)),
    )
    outcome = reconcile_qualification_filesystem(result_root)
    assert outcome["reconciled"] is True
    intent = result_root / "attempt-intents/intent-0001.json"
    assert intent.is_file() and intent.stat().st_nlink == 1
    assert not list(intent.parent.glob(".*.qcsd-tmp"))
    checkpoint = recover_interrupted_attempt(result_root, finished_at=_wall_time(2))
    assert checkpoint["attempts"][-1]["verdict"] == "operational-failure"


@pytest.mark.parametrize("phase", ("pre-link", "post-link"))
def test_resume_recovery_diagnostic_residue_is_exactly_recovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / f"resume-recovery-{phase}"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    _begin_intent(
        result_root,
        vector_id="constructor--page--websocket",
        started_at=_wall_time(1),
    )
    _fork_crash_at(
        f"create-only:resume-recovery.json:{phase}",
        lambda: recover_interrupted_attempt(result_root, finished_at=_wall_time(2)),
    )

    outcome = reconcile_qualification_filesystem(result_root)
    assert outcome["reconciled"] is True
    checkpoint = recover_interrupted_attempt(result_root, finished_at=_wall_time(3))
    assert len(checkpoint["attempts"]) == 1
    assert checkpoint["attempts"][0]["finished_at"] == _wall_time(2)
    assert checkpoint["attempts"][0]["verdict"] == "operational-failure"
    diagnostic = next(result_root.rglob("resume-recovery.json"))
    assert json.loads(diagnostic.read_text())["failure_code"] == "interrupted"
    assert diagnostic.stat().st_nlink == 1
    assert not list(result_root.rglob("*qcsd-tmp*"))


@pytest.mark.parametrize(
    "attack", ("mismatched", "multiple", "symlink", "external-hardlink", "wrong-parent")
)
def test_resume_recovery_rejects_hostile_residue_without_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attack: str
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / f"resume-recovery-hostile-{attack}"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    intent = _begin_intent(
        result_root,
        vector_id="constructor--page--websocket",
        started_at=_wall_time(1),
    )
    attempt = result_root / intent["evidence_directory"]
    attempt.parent.mkdir(mode=0o700)
    attempt.mkdir(mode=0o700)
    if attack == "wrong-parent":
        attempt = attempt.parent / "attempt-2"
        attempt.mkdir(mode=0o700)
    residue = attempt / ".resume-recovery.json.deadbeef.qcsd-tmp"
    diagnostic = {
        "schema_version": 1,
        "vector_id": "constructor--page--websocket",
        "attempt_number": 1,
        "failure_code": "interrupted",
        "stage": "resume-recovery",
        "finished_at": _wall_time(2),
    }
    if attack == "mismatched":
        diagnostic["vector_id"] = "constructor--page--webtransport"
    if attack == "symlink":
        residue.symlink_to(result_root / "foundation.json")
    else:
        residue.write_bytes(canonical_json_bytes(diagnostic))
        residue.chmod(0o600)
    protected = [residue]
    if attack == "multiple":
        duplicate = attempt / ".resume-recovery.json.feedface.qcsd-tmp"
        duplicate.write_bytes(residue.read_bytes())
        duplicate.chmod(0o600)
        protected.append(duplicate)
    elif attack == "external-hardlink":
        external = tmp_path / "external-recovery-link"
        os.link(residue, external)
        protected.append(external)

    with pytest.raises(ValueError):
        reconcile_qualification_filesystem(result_root)
    assert all(path.exists() or path.is_symlink() for path in protected)


def test_reconciliation_is_itself_idempotent_after_recovered_link_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "recursive-recovery"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    _fork_crash_at(
        "create-only:intent-0001.json:pre-link",
        lambda: _begin_intent(
            result_root,
            vector_id="constructor--page--websocket",
            started_at=_wall_time(1),
        ),
    )
    _fork_crash_at(
        "reconcile:intent-0001.json:post-link",
        lambda: reconcile_qualification_filesystem(result_root),
    )
    target = result_root / "attempt-intents/intent-0001.json"
    assert target.stat().st_nlink == 2
    reconcile_qualification_filesystem(result_root)
    assert target.stat().st_nlink == 1
    assert not list(target.parent.glob(".*.qcsd-tmp"))


@pytest.mark.parametrize(
    "boundary",
    (
        "create-only:result-0001.json:pre-link",
        "create-only:result-0001.json:post-link",
        "atomic:experiment.json:pre-replace",
        "atomic:experiment.json:post-replace",
    ),
)
def test_result_and_checkpoint_crash_residues_replay_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / boundary.replace(":", "-")
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    vector_id = "constructor--page--websocket"
    _begin_intent(result_root, vector_id=vector_id, started_at=_wall_time(1))
    receipt = build_failure_result_receipt(
        foundation=foundation,
        global_ordinal=1,
        attempt_number=1,
        previous_result_sha256="0" * 64,
        vector_id=vector_id,
        started_at=_wall_time(1),
        finished_at=_wall_time(2),
        verdict="operational-failure",
        failure_code="docker-start-failed",
        failure_artifacts=[],
    )
    _fork_crash_at(boundary, lambda: append_result(result_root, receipt))
    outcome = reconcile_qualification_filesystem(result_root)
    checkpoint = load_checkpoint(result_root)
    assert outcome["reconciled"] is (":pre-" in boundary or "result-0001" in boundary)
    assert len(checkpoint["attempts"]) == 1
    assert checkpoint["attempts"][0]["verdict"] == "operational-failure"
    assert not list(result_root.rglob("*qcsd-tmp*"))


def test_clean_result_publication_lag_is_repaired_without_a_duplicate_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "result-published-checkpoint-lag"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    vector_id = "constructor--page--websocket"
    _begin_intent(result_root, vector_id=vector_id, started_at=_wall_time(1))
    receipt = build_failure_result_receipt(
        foundation=foundation,
        global_ordinal=1,
        attempt_number=1,
        previous_result_sha256="0" * 64,
        vector_id=vector_id,
        started_at=_wall_time(1),
        finished_at=_wall_time(2),
        verdict="operational-failure",
        failure_code="docker-start-failed",
        failure_artifacts=[],
    )
    _fork_crash_at(
        "append-result:result-0001.json:post-publish",
        lambda: append_result(result_root, receipt),
    )
    assert len(list((result_root / "attempts").glob("result-*.json"))) == 1
    assert json.loads((result_root / "experiment.json").read_text())["attempts"] == []

    checkpoint = recover_interrupted_attempt(result_root, finished_at=_wall_time(3))
    assert len(checkpoint["attempts"]) == 1
    assert checkpoint["attempts"][0]["verdict"] == "operational-failure"
    assert len(list((result_root / "attempts").glob("result-*.json"))) == 1
    assert not list(result_root.rglob("*qcsd-tmp*"))


@pytest.mark.parametrize(
    "boundary",
    (
        "create-only:final.json:pre-link",
        "create-only:final.json:post-link",
        "final:post-publish",
    ),
)
def test_final_publication_recovers_and_is_idempotently_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    _limit_qualification_to_first_vector(monkeypatch)
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / f"final-{boundary.replace(':', '-')}"
    checkpoint = _admit_create(
        monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation
    )
    receipt, _pcap = _passed_receipt(
        result_root,
        foundation,
        vector_id="constructor--page--websocket",
        global_ordinal=1,
        attempt_number=1,
        previous_result_sha256=checkpoint["chain_head_sha256"],
        seed=701,
    )
    append_result(result_root, receipt)
    _fork_crash_at(
        boundary,
        lambda: create_final_receipt(result_root, recorded_at=_wall_time(10)),
    )
    reconcile_qualification_filesystem(result_root)
    first = create_final_receipt(result_root, recorded_at=_wall_time(11))
    first_bytes = first.read_bytes()
    second = create_final_receipt(result_root, recorded_at=_wall_time(12))
    assert second.read_bytes() == first_bytes
    verified = verify_qualification(
        result_root,
        lab_root=lab_root,
        expected_cohort_version=71,
        build_validator=_BuildValidator(foundation),
    )
    assert verified["passed"] is True
    assert not list(result_root.rglob("*qcsd-tmp*"))


def test_final_reconciliation_rejects_a_conflicting_valid_receipt_without_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _limit_qualification_to_first_vector(monkeypatch)
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "conflicting-final"
    checkpoint = _admit_create(
        monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation
    )
    receipt, _pcap = _passed_receipt(
        result_root,
        foundation,
        vector_id="constructor--page--websocket",
        global_ordinal=1,
        attempt_number=1,
        previous_result_sha256=checkpoint["chain_head_sha256"],
        seed=702,
    )
    append_result(result_root, receipt)
    final_path = create_final_receipt(result_root, recorded_at=_wall_time(10))
    conflicting = bind_receipt(
        build_final_payload(result_root, recorded_at=_wall_time(11)),
        receipt_type=FINAL_RECEIPT_TYPE,
    )
    residue = result_root / ".final.json.deadbeef.qcsd-tmp"
    residue.write_bytes(canonical_json_bytes(conflicting))
    residue.chmod(0o600)

    final_bytes = final_path.read_bytes()
    residue_bytes = residue.read_bytes()
    with pytest.raises(ValueError, match="differs from its target"):
        reconcile_qualification_filesystem(result_root)
    assert final_path.read_bytes() == final_bytes
    assert residue.read_bytes() == residue_bytes


@pytest.mark.parametrize(
    "attack",
    ("multiple", "symlink", "wrong-mode", "external-hardlink", "rogue"),
)
def test_reconciliation_rejects_hostile_residues_without_deleting_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attack: str
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / f"hostile-{attack}"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    _fork_crash_at(
        "create-only:intent-0001.json:pre-link",
        lambda: _begin_intent(
            result_root,
            vector_id="constructor--page--websocket",
            started_at=_wall_time(1),
        ),
    )
    temporary = next((result_root / "attempt-intents").glob(".*.qcsd-tmp"))
    protected: list[Path] = [temporary]
    if attack == "multiple":
        duplicate = temporary.with_name(".intent-0001.json.deadbeef.qcsd-tmp")
        duplicate.write_bytes(temporary.read_bytes())
        duplicate.chmod(0o600)
        protected.append(duplicate)
    elif attack == "symlink":
        temporary.unlink()
        temporary.symlink_to(result_root / "foundation.json")
    elif attack == "wrong-mode":
        temporary.chmod(0o644)
    elif attack == "external-hardlink":
        outside = tmp_path / "foreign-link"
        os.link(temporary, outside)
        protected.append(outside)
    else:
        rogue = result_root / "rogue.bin"
        rogue.write_bytes(b"hostile")
        rogue.chmod(0o600)
        protected.append(rogue)
    with pytest.raises(ValueError):
        reconcile_qualification_filesystem(result_root)
    assert all(path.exists() or path.is_symlink() for path in protected)


def test_open_inventory_rejects_rogue_entries_and_unsafe_directory_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "open-hostile"
    _admit_create(monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation)
    rogue = result_root / "evidence/rogue.bin"
    rogue.write_bytes(b"rogue")
    rogue.chmod(0o600)
    with pytest.raises(ValueError, match="not exact"):
        validate_open_evidence_inventory(result_root, allow_final=False)
    rogue.unlink()
    (result_root / "attempts").chmod(0o755)
    with pytest.raises(ValueError, match="0700"):
        reconcile_qualification_filesystem(result_root)


def test_full_vector_chain_final_and_portable_deep_verify_are_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab_root, foundation = _lab(tmp_path)
    result_root = tmp_path / "complete"
    checkpoint = _admit_create(
        monkeypatch, result_root=result_root, lab_root=lab_root, foundation=foundation
    )
    for global_ordinal, vector in enumerate(expected_vectors(), 1):
        receipt, _pcap = _passed_receipt(
            result_root,
            foundation,
            vector_id=vector.vector_id,
            global_ordinal=global_ordinal,
            attempt_number=1,
            previous_result_sha256=checkpoint["chain_head_sha256"],
            seed=global_ordinal,
            checkpoint=checkpoint,
        )
        checkpoint = append_result(result_root, receipt)
    assert checkpoint["status"] == "complete"
    vector_count = len(expected_vectors())
    assert len(checkpoint["passed_vector_ids"]) == vector_count
    final_path = create_final_receipt(result_root, recorded_at=_wall_time(300))
    assert final_path.name == "final.json"
    verified = verify_qualification(
        result_root,
        lab_root=lab_root,
        expected_cohort_version=71,
        build_validator=_BuildValidator(foundation),
        verification_mode=FoundationVerificationMode.PORTABLE_REPLAY,
    )
    assert verified["passed"] is True
    assert verified["passed_vector_count"] == vector_count
    assert verified["qualification_started_at"] == _wall_time(2)
    assert verified["qualification_finished_at"] == _wall_time(vector_count * 2 + 1)
    rogue = result_root / "evidence/unbound.bin"
    rogue.write_bytes(b"unbound")
    rogue.chmod(0o600)
    # The shared open-ledger inventory guard may reject an unexpected file
    # before the sealed-inventory comparison; either diagnostic proves the
    # required fail-closed boundary.
    with pytest.raises(ValueError, match=r"inventory is not (?:exact|closed)"):
        validate_closed_evidence_inventory(result_root)
