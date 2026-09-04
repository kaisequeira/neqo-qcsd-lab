from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
from copy import deepcopy
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

import qcsd_lab.parameters as parameters
import qcsd_lab.chaff_qualification as chaff_qualification
import qcsd_lab.capture_session as capture_session
from qcsd_lab.analysis import analyze_result
from qcsd_lab.capture import extract_trace, split_endpoint
from qcsd_lab.fidelity import _schedule_realization_metrics
from qcsd_lab.fitting_walkie_talkie import (
    BurstPair,
    mold,
    mold_padding_cost,
    receiver_continuation_contract,
)
from qcsd_lab.manifest import (
    canonical_bytes,
    https_origin,
    runtime_manifest,
    validate_manifest,
)
from qcsd_lab.orchestrator import _intrinsic_fidelity_failure, run_campaign
from qcsd_lab.util import atomic_json, load_json, response_signature, sha256_bytes, sha256_file
from qcsd_lab.verification import verify_result


CAPTURE_GATE = os.environ.get("QCSD_RUN_CAPTURE_ACCEPTANCE") == "1"
SEALED_DEFENSES = ("undefended",)
PARAMETER_FILES = {
    "static": Path("/lab/config/defense-params/static-migration.csv"),
    "traffic-morphing": Path("/lab/config/defense-params/traffic-morphing-live.json"),
    "wtf-pad": Path("/lab/config/defense-params/wtfpad-live.json"),
    "walkie-talkie": Path("/lab/config/defense-params/walkie-talkie-live.json"),
}
CANONICAL_SAMPLE_FILES = {
    "capture.pcapng",
    "neqo/events.csv",
    "neqo/packets.csv",
    "neqo/run.json",
    "neqo/schedule.csv",
}
CONTROLLED_AEL_HEADERS = [
    ["accept", "text/html,application/xhtml+xml"],
    ["accept-encoding", "identity"],
    ["accept-language", "en-US,en;q=0.9"],
]
CONTROLLED_TEST_DOMAIN = b"qcsd-controlled-live-test-only-v1\0"


def test_controlled_schema_six_wire_fixture_is_explicit_and_non_authoritative(
    tmp_path: Path,
) -> None:
    """Keep the live wire fixture structurally honest without blessing it as evidence."""

    workload_id = "simple"
    source = tmp_path / "simple-prepared.json"
    prepared = _controlled_prepared_manifest(
        [_resource(0, "https://127.0.0.1:4433/131072", "Document", 131_072)]
    )
    source.write_bytes(canonical_bytes(prepared))
    runtime = tmp_path / "simple-runtime.json"
    runtime.write_bytes(canonical_bytes(runtime_manifest(prepared)))
    receipt = _synthetic_response_observation(source, prepared["resources"][0])
    prefix_spec = tmp_path / "simple-prefix-spec.json"
    historical = load_json(
        Path(__file__).parents[1] / "config/defense-params/walkie-talkie-live.json"
    )
    source_profiles = {profile["real"]: profile for profile in historical["profiles"]}
    controlled_profile = _current_controlled_walkie_talkie_profile(
        source_profiles[workload_id], historical["packet_size"]
    )
    _write_controlled_prefix_spec(prefix_spec, workload_id, controlled_profile["bursts"])
    chaff_manifest = tmp_path / "simple-chaff.json"
    _write_controlled_chaff_manifest(
        chaff_manifest,
        workload_id=workload_id,
        application_source=source,
        response_receipt=receipt,
        prefix_spec=prefix_spec,
    )
    response_only_chaff = tmp_path / "simple-response-only-chaff.json"
    _write_controlled_response_only_chaff_manifest(
        response_only_chaff,
        application_source=source,
        response_receipt=receipt,
    )
    sidecar = tmp_path / "simple-sidecar.json"
    sidecar.write_bytes(
        canonical_bytes(
            {
                "schema_version": 1,
                "artifact_type": "qcsd-controlled-live-test-only-chaff-observation",
                "workload_id": workload_id,
                "response_receipt": receipt,
            }
        )
    )
    walkie_talkie = tmp_path / "walkie-talkie-controlled-v6.json"
    _write_controlled_walkie_talkie(
        walkie_talkie,
        {workload_id: (sidecar, prefix_spec, chaff_manifest)},
    )

    manifest = load_json(chaff_manifest)
    assert manifest["schema_version"] == 2
    assert manifest["artifact_type"] == "qcsd-qualified-chaff-manifest"
    assert manifest["application_workload_sha256"] == sha256_file(source)
    assert manifest["resources"][0]["headers"] == CONTROLLED_AEL_HEADERS
    assert manifest["resources"][0]["chaff_qualification"]["prefix_spec_sha256"] == sha256_file(
        prefix_spec
    )
    assert load_json(runtime) == runtime_manifest(prepared)
    response_only = load_json(response_only_chaff)
    assert response_only["schema_version"] == 4
    assert response_only["qualification_scope"] == "response-only"
    assert response_only["application_workload_sha256"] == sha256_file(source)
    assert response_only["resources"][0]["headers"] == CONTROLLED_AEL_HEADERS
    assert response_only["resources"][0]["chaff_qualification"] == {
        "schema_version": 4,
        "qualification_scope": "response-only",
        "method": "GET",
        "request_header_primitive": chaff_qualification.response_only_request_header_primitive(),
        "request_stream_bytes": 163,
        "qualified_parallel_chaff_streams": 5,
        "qualified_completion_count": 120,
        "expected_response": {
            "status": 200,
            "content_encoding": "identity",
            "body_bytes": 4_096,
            "body_sha256": hashlib.sha256(b"\0" * 4_096).hexdigest(),
        },
        "response_qualification_sha256": chaff_qualification.qualification_digest(
            "qcsd-controlled-live-response-only-observation-v1", [receipt]
        ),
    }

    molded = load_json(walkie_talkie)
    selected = next(
        binding
        for binding in molded["qualification_bindings"]
        if binding["workload_id"] == workload_id
    )
    assert molded["schema_version"] == 6
    assert molded["generated_by"] == "controlled-live-test-only"
    assert molded["receiver_continuation"] == receiver_continuation_contract()
    assert molded["profiles"][0]["bursts"] == [{"outgoing": 4, "incoming": 129}]
    assert molded["profiles"][0]["matching_cost_packets"] == 23
    assert molded["profiles"][0]["total_scheduled_bytes"] == 159_600
    assert selected == {
        "workload_id": workload_id,
        "chaff_qualification_sidecar_sha256": sha256_file(sidecar),
        "prefix_pack_spec_sha256": sha256_file(prefix_spec),
        "qualified_chaff_manifest_sha256": sha256_file(chaff_manifest),
        "application_resource_id": 0,
        "selected_chaff_resource_id": 0,
        "qualified_parallel_chaff_streams": 5,
        "walkie_talkie_required_chaff_streams": 2,
    }

    # These artifacts exist only to exercise the real wire/runtime boundary.
    # Neither public authority gate may mistake them for qualification evidence.
    with pytest.raises(ValueError):
        parameters.validate_parameter_artifact(
            walkie_talkie,
            expected_kind="walkie_talkie",
            allow_reviewed_fixture=True,
            expected_qcsd_profile="live",
            expected_udp_payload_ceiling=1_200,
            expected_workloads={workload_id: sha256_file(source)},
        )
    with pytest.raises(ValueError):
        chaff_qualification.load_qualified_chaff(
            sidecar,
            workload_id=workload_id,
            base_manifest_path=source,
            prefix_spec_path=prefix_spec,
            require_current_implementation=False,
        )


def _controlled_prepared_manifest(resources: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a schema-valid A input whose preparation identity is never a chaff oracle."""

    resources = deepcopy(resources)
    root = next(resource for resource in resources if resource["id"] == 0)
    origins = sorted({https_origin(resource["url"]) for resource in resources})
    assert all(origin is not None for origin in origins)
    empty_patch = hashlib.sha256(b"").hexdigest()
    manifest = {
        "preparation": {
            "source_url": root["url"],
            "final_url": root["url"],
            "chromium_version": "controlled-live-test-only",
            "settle_ms": 0,
            "observed_request_count": len(resources),
            "observed_origins": origins,
            "approved_origins": origins,
            "exclusions": [],
            "max_response_bytes": 1_048_576,
            "timeout_seconds": 120,
            "stability_runs": 2,
            "stability_profile": "live",
            "stability_defense": "none",
            "stability_seed": 0,
            "neqo_version": "controlled-live-test-only",
            "neqo_base_commit": "0" * 40,
            "published_qcsd_commit": "0" * 40,
            "migration_commit": "0" * 40,
            "expected_responses": [
                {
                    "resource_id": resource["id"],
                    "status": 200,
                    "bytes": resource["data_length"],
                    "body_sha256": hashlib.sha256(b"\0" * resource["data_length"]).hexdigest(),
                }
                for resource in resources
            ],
            "lab_source": {
                "image_digest": "sha256:" + "0" * 64,
                "lab_commit": "0" * 40,
                "lab_dirty": False,
                "lab_patch_sha256": empty_patch,
                "neqo_commit": "0" * 40,
                "neqo_pinned_commit": "0" * 40,
                "neqo_dirty": False,
                "neqo_patch_sha256": empty_patch,
            },
            "prepare_image_digest": "sha256:" + "0" * 64,
        },
        "resources": resources,
    }
    validate_manifest(manifest)
    return manifest


def _synthetic_response_observation(
    application_source: Path,
    root: dict[str, Any],
) -> dict[str, Any]:
    """Make an offline receipt used only to unit-test fixture construction."""

    body = b"\0" * 4_096
    observations = [
        {
            "sequence": 0,
            "phase": "handshake",
            "direction": "incoming",
            "udp_payload_bytes": 900,
        },
        {
            "sequence": 1,
            "phase": "qualification",
            "direction": "outgoing",
            "udp_payload_bytes": 1_200,
        },
        {
            "sequence": 2,
            "phase": "qualification",
            "direction": "incoming",
            "udp_payload_bytes": 1_000,
        },
    ]
    packet_log = json.dumps(observations, separators=(",", ":")).encode()
    statistic = {
        "incoming": {
            "packet_count": 2,
            "observed_udp_payload_max": 1_000,
            "oversized_packet_count": 0,
        },
        "outgoing": {
            "packet_count": 1,
            "observed_udp_payload_max": 1_200,
            "oversized_packet_count": 0,
        },
        "total": {
            "packet_count": 3,
            "observed_udp_payload_max": 1_200,
            "oversized_packet_count": 0,
        },
    }
    headers = chaff_qualification.project_compact_headers(root)
    return {
        "schema_version": 2,
        "artifact_type": chaff_qualification.RESPONSE_ARTIFACT_TYPE,
        "invocation_id": "controlled-offline-observation",
        "neqo_version": "controlled-live-test-only",
        "application_workload_sha256": sha256_file(application_source),
        "application_resource_id": root["id"],
        "selected_chaff_resource_id": root["id"],
        "qualified_parallel_chaff_streams": 5,
        "method": "GET",
        "url": root["url"],
        "request_headers": headers,
        "parallel_requests": 5,
        "connection_count": 1,
        "requests_opened_before_first_network_output": 5,
        "request_stream_bytes": 163,
        "max_response_bytes": 1_048_576,
        "udp_payload_ceiling": 1_200,
        "started_unix_ns": 1,
        "ended_unix_ns": 2,
        "completion_status": "complete",
        "error": None,
        "source": {
            "neqo_base_commit": "0" * 40,
            "published_qcsd_commit": "0" * 40,
            "migration_commit": "0" * 40,
        },
        "requests": [
            {
                "request_index": index,
                "stream_id": index * 4,
                "request_stream_bytes": 163,
                "status": 200,
                "content_encoding": "identity",
                "body_bytes": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "complete": True,
                "outcome": "complete",
            }
            for index in range(5)
        ],
        "packet_observations": observations,
        "packet_log_sha256": sha256_bytes(packet_log),
        "packets": statistic,
        "passed": True,
    }


def _write_controlled_prefix_spec(
    path: Path,
    workload_id: str,
    bursts: list[dict[str, int]],
) -> None:
    numeric_profile = {"packet_size": 1_200, "bursts": bursts}
    numeric_encoded = json.dumps(numeric_profile, sort_keys=True, separators=(",", ":")).encode()
    historical = Path(__file__).parents[1] / "config/defense-params/walkie-talkie-live.json"
    value = {
        "schema_version": 1,
        "artifact_type": chaff_qualification.PREFIX_SPEC_ARTIFACT_TYPE,
        "workload_id": workload_id,
        "packet_size": 1_200,
        "max_stream_data_excess": 1_000,
        "maximum_receiver_continuation_reserve_horizon": 1,
        "required_chaff_survivors": 2,
        "numeric_profile_sha256": sha256_bytes(
            b"qcsd-walkie-talkie-numeric-profile-v1\0" + numeric_encoded
        ),
        "source_walkie_talkie_artifact_sha256": sha256_file(historical),
        "numeric_profile": numeric_profile,
    }
    path.write_bytes(canonical_bytes(value))


def _write_controlled_chaff_manifest(
    path: Path,
    *,
    workload_id: str,
    application_source: Path,
    response_receipt: dict[str, Any],
    prefix_spec: Path,
) -> None:
    application = load_json(application_source)
    root = next(resource for resource in application["resources"] if resource["id"] == 0)
    headers = chaff_qualification.project_compact_headers(root)
    identity, request_bytes, *_ = chaff_qualification._validate_response_receipt(
        response_receipt,
        application_manifest_sha256=sha256_file(application_source),
        application_resource_id=root["id"],
        selected_chaff_resource_id=root["id"],
        qualified_parallel_chaff_streams=5,
        url=root["url"],
        headers=headers,
    )
    status, content_encoding, body_bytes, body_sha256 = identity
    response_digest = chaff_qualification.qualification_digest(
        "qcsd-controlled-live-response-observation-v1", [response_receipt]
    )
    prefix_observation_digest = sha256_bytes(
        CONTROLLED_TEST_DOMAIN + b"prefix-observation\0" + prefix_spec.read_bytes()
    )
    value = {
        "schema_version": 2,
        "artifact_type": chaff_qualification.MANIFEST_ARTIFACT_TYPE,
        "application_workload_sha256": sha256_file(application_source),
        "application_resource_id": root["id"],
        "selected_chaff_resource_id": root["id"],
        "qualified_parallel_chaff_streams": 5,
        "walkie_talkie_required_chaff_streams": 2,
        "resources": [
            {
                "id": root["id"],
                "url": root["url"],
                "type": root["type"],
                "content_length": body_bytes,
                "data_length": body_bytes,
                "chaff_priority": root["chaff_priority"],
                "known_valid": True,
                "depends_on": [],
                "headers": headers,
                "chaff_qualification": {
                    "schema_version": 2,
                    "method": "GET",
                    "request_stream_bytes": request_bytes,
                    "qualified_parallel_chaff_streams": 5,
                    "walkie_talkie_required_chaff_streams": 2,
                    "expected_response": {
                        "status": status,
                        "content_encoding": content_encoding,
                        "body_bytes": body_bytes,
                        "body_sha256": body_sha256,
                    },
                    "response_qualification_sha256": response_digest,
                    "prefix_pack_qualification_sha256": prefix_observation_digest,
                    "prefix_spec_sha256": sha256_file(prefix_spec),
                },
            }
        ],
    }
    path.write_bytes(canonical_bytes(value))


def _write_controlled_response_only_chaff_manifest(
    path: Path,
    *,
    application_source: Path,
    response_receipt: dict[str, Any],
) -> None:
    """Project one observed local response into a nonauthoritative schema-four fixture."""

    application = load_json(application_source)
    root = next(resource for resource in application["resources"] if resource["id"] == 0)
    headers = chaff_qualification.project_identity_chaff_headers(root)
    identity, request_bytes, *_ = chaff_qualification._validate_response_receipt(
        response_receipt,
        application_manifest_sha256=sha256_file(application_source),
        application_resource_id=root["id"],
        selected_chaff_resource_id=root["id"],
        qualified_parallel_chaff_streams=5,
        url=root["url"],
        headers=headers,
    )
    status, content_encoding, body_bytes, body_sha256 = identity
    response_digest = chaff_qualification.qualification_digest(
        "qcsd-controlled-live-response-only-observation-v1", [response_receipt]
    )
    manifest = chaff_qualification.derive_response_only_chaff_manifest_v2(
        {
            "base_manifest": {"sha256": sha256_file(application_source)},
            "application_resource_id": root["id"],
            "selected_chaff_resource_id": root["id"],
        },
        root,
        {
            "headers": headers,
            "request_stream_bytes": request_bytes,
            "expected_response": {
                "status": status,
                "content_encoding": content_encoding,
                "body_bytes": body_bytes,
                "body_sha256": body_sha256,
            },
            "response_qualification_sha256": response_digest,
        },
    )
    path.write_bytes(canonical_bytes(manifest))


def _write_controlled_walkie_talkie(
    path: Path,
    inputs: dict[str, tuple[Path, Path, Path]],
) -> None:
    historical = Path(__file__).parents[1] / "config/defense-params/walkie-talkie-live.json"
    value = load_json(historical)
    source_profiles = {profile["real"]: profile for profile in value["profiles"]}
    profiles: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    for index, (workload_id, (sidecar, spec, manifest)) in enumerate(inputs.items()):
        profile = _current_controlled_walkie_talkie_profile(
            source_profiles.get(workload_id, value["profiles"][index % len(value["profiles"])]),
            value["packet_size"],
        )
        decoy = f"acceptance-decoy-local-{workload_id}"
        profile["real"] = workload_id
        profile["decoy"] = decoy
        profiles.append(profile)
        bindings.append(
            {
                "workload_id": workload_id,
                "chaff_qualification_sidecar_sha256": sha256_file(sidecar),
                "prefix_pack_spec_sha256": sha256_file(spec),
                "qualified_chaff_manifest_sha256": sha256_file(manifest),
                "application_resource_id": 0,
                "selected_chaff_resource_id": 0,
                "qualified_parallel_chaff_streams": 5,
                "walkie_talkie_required_chaff_streams": 2,
            }
        )
        for field in (
            "chaff_qualification_sidecar_sha256",
            "prefix_pack_spec_sha256",
            "qualified_chaff_manifest_sha256",
        ):
            bindings.append(
                {
                    "workload_id": decoy,
                    "chaff_qualification_sidecar_sha256": sha256_bytes(
                        CONTROLLED_TEST_DOMAIN + f"{decoy}:{field}:sidecar".encode()
                    ),
                    "prefix_pack_spec_sha256": sha256_bytes(
                        CONTROLLED_TEST_DOMAIN + f"{decoy}:{field}:spec".encode()
                    ),
                    "qualified_chaff_manifest_sha256": sha256_bytes(
                        CONTROLLED_TEST_DOMAIN + f"{decoy}:{field}:manifest".encode()
                    ),
                    "application_resource_id": 0,
                    "selected_chaff_resource_id": 0,
                    "qualified_parallel_chaff_streams": 5,
                    "walkie_talkie_required_chaff_streams": 2,
                }
            )
            break
    value.update(
        {
            "schema_version": 6,
            "generated_by": "controlled-live-test-only",
            "receiver_continuation": receiver_continuation_contract(),
            "profiles": profiles,
            "qualification_bindings": bindings,
        }
    )
    path.write_bytes(canonical_bytes(value))


def _current_controlled_walkie_talkie_profile(
    historical: dict[str, Any], packet_size: int
) -> dict[str, Any]:
    """Derive the current schema-six mold from a historical source envelope."""

    profile = deepcopy(historical)

    def source_envelope(side: str) -> tuple[BurstPair, ...]:
        batch_ends = set(profile["batch_ends"][side])
        return tuple(
            BurstPair(
                outgoing=burst["outgoing"],
                incoming=burst["incoming"],
                batch_end=index in batch_ends,
            )
            for index, burst in enumerate(profile["source_envelopes"][side])
        )

    real = source_envelope("real")
    decoy = source_envelope("decoy")
    molded = tuple(mold(real, decoy))
    profile["bursts"] = [
        {"outgoing": burst.outgoing, "incoming": burst.incoming} for burst in molded
    ]
    profile["molded_batch_ends"] = [index for index, burst in enumerate(molded) if burst.batch_end]
    profile["matching_cost_packets"] = mold_padding_cost(real, decoy)
    profile["total_scheduled_bytes"] = (
        sum(burst.outgoing + burst.incoming for burst in molded) * packet_size
    )
    return profile


def _qualify_controlled_live_inputs(
    directory: Path,
    sources: dict[str, Path],
) -> dict[str, tuple[Path, Path, Path, Path]]:
    """Observe one local five-way compact response run per controlled workload.

    This is intentionally a wire smoke, not the three-by-five research
    qualification policy.  The public sidecar loader remains required to reject
    the resulting test-local record.
    """

    qualification_root = directory / "config/chaff-qualification-store/v2"
    prefix_root = directory / "config/chaff-prefix-specs/v2"
    manifest_root = directory / "controlled-live/chaff-manifests"
    response_root = directory / "controlled-live/response-observations"
    for path in (qualification_root, prefix_root, manifest_root, response_root):
        path.mkdir(parents=True, exist_ok=True)
    historical = load_json(PARAMETER_FILES["walkie-talkie"])
    profiles = {profile["real"]: profile for profile in historical["profiles"]}
    results: dict[str, tuple[Path, Path, Path, Path]] = {}
    neqo_client = capture_session.NEQO_CLIENT
    for workload_id, source in sources.items():
        output = response_root / workload_id
        completed = subprocess.run(
            [
                neqo_client,
                "qualify-chaff-response",
                "--workload",
                str(source),
                "--application-resource-id",
                "0",
                "--selected-chaff-resource-id",
                "0",
                "--output-dir",
                str(output),
                "--parallel-requests",
                "5",
                "--max-response-bytes",
                "1048576",
                "--packet-size",
                "1200",
                "--timeout-seconds",
                "120",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=125,
            check=False,
        )
        if completed.returncode:
            raise RuntimeError(
                f"controlled {workload_id} compact response observation failed "
                f"({completed.returncode}): {completed.stdout}"
            )
        receipt = load_json(output / "qualification.json")
        profile = _current_controlled_walkie_talkie_profile(
            profiles[workload_id], historical["packet_size"]
        )
        spec = prefix_root / f"{workload_id}.json"
        _write_controlled_prefix_spec(spec, workload_id, profile["bursts"])
        manifest = manifest_root / f"{workload_id}.json"
        _write_controlled_chaff_manifest(
            manifest,
            workload_id=workload_id,
            application_source=source,
            response_receipt=receipt,
            prefix_spec=spec,
        )
        sidecar = qualification_root / f"{workload_id}.json"
        atomic_json(
            sidecar,
            {
                "schema_version": 1,
                "artifact_type": "qcsd-controlled-live-test-only-chaff-observation",
                "workload_id": workload_id,
                "qualification_policy": {
                    "response_invocations": 1,
                    "parallel_requests": 5,
                    "authoritative": False,
                },
                "application_workload_sha256": sha256_file(source),
                "prefix_pack_spec_sha256": sha256_file(spec),
                "qualified_chaff_manifest_sha256": sha256_file(manifest),
                "response_receipt": receipt,
            },
        )
        results[workload_id] = (source, sidecar, spec, manifest)
    return results


@pytest.mark.skipif(
    not CAPTURE_GATE,
    reason="direct container-edge capture acceptance is launcher-provisioned",
)
def test_controlled_local_capture_uses_the_canonical_sealed_workflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    address = os.environ["QCSD_CAPTURE_SERVER_ADDRESS"]
    port = int(os.environ["QCSD_CAPTURE_SERVER_PORT"])
    second_address = os.environ["QCSD_CAPTURE_SERVER_TWO_ADDRESS"]
    second_port = int(os.environ["QCSD_CAPTURE_SERVER_TWO_PORT"])
    campaign_path = _configuration(
        tmp_path / "direct",
        address,
        port,
        second_address,
        second_port,
    )

    result = run_campaign(campaign_path, tmp_path / "results")
    verified = verify_result(result)
    experiment = verified.experiment
    assert experiment["status"] == "complete"
    assert experiment["summary"] == {
        "planned": 2 * len(SEALED_DEFENSES),
        "accepted": 2 * len(SEALED_DEFENSES),
        "failed": 0,
        "eligible": 2 * len(SEALED_DEFENSES),
        "passed": True,
    }
    assert len(experiment["samples"]) == 2 * len(SEALED_DEFENSES)
    source = experiment["source"]
    assert source["lab_dirty"] is False
    assert source["neqo_dirty"] is False
    assert source["neqo_commit"] == source["neqo_pinned_commit"]
    assert not list(result.rglob("sample.json"))
    assert not list(result.rglob("fidelity.yml"))
    assert not list(result.rglob("*.jsonl"))
    assert not list(result.rglob("qlog"))

    by_workload: dict[str, dict[str, Path]] = defaultdict(dict)
    response_signatures: dict[str, list[list[tuple[Any, ...]]]] = defaultdict(list)
    expected_servers = {
        "simple": {address},
        "complex": {address, second_address},
    }
    expected_endpoints = {"simple": 1, "complex": 2}
    expected_resource_ids = {"simple": {0}, "complex": {0, 1, 2, 3}}
    for sample in experiment["samples"]:
        sample_path = result / sample["path"]
        workload = sample["workload_id"]
        defense = sample["defense"]
        by_workload[workload][defense] = sample_path
        assert sample["state"] == "accepted"
        assert sample["eligible"] is True
        assert sample["diagnostics"]["response_match"] is True
        assert sample["diagnostics"]["fidelity_eligible"] is True
        assert sample["diagnostics"]["endpoint_count"] == expected_endpoints[workload]
        assert sample["diagnostics"]["endpoint_count_valid"] is True
        assert sample["diagnostics"]["operationally_valid"] is True

        actual_files = {
            path.relative_to(sample_path).as_posix()
            for path in sample_path.rglob("*")
            if path.is_file()
        }
        assert actual_files == CANONICAL_SAMPLE_FILES
        run = load_json(sample_path / "neqo/run.json")
        assert run["completion_status"] == "complete"
        assert run["application_workload_source_hash_sha256"] is None
        assert run["chaff_manifest_hash_sha256"] is None
        assert run["chaff_responses"] == []
        assert run["migration_commit"] == source["neqo_commit"]
        assert len(run["endpoints"]) == expected_endpoints[workload]
        assert len(run["responses"]) == len(expected_resource_ids[workload])
        assert {response["resource_id"] for response in run["responses"]} == (
            expected_resource_ids[workload]
        )
        assert all(
            response["status"] == 200
            and response["complete"] is True
            and response["outcome"] == "succeeded"
            for response in run["responses"]
        )
        trace = extract_trace(sample_path / "capture.pcapng", run["endpoints"])
        assert trace
        _assert_direct_destination_isolation(
            sample_path / "capture.pcapng",
            run,
            *expected_servers[workload],
        )
        _assert_capture_contract(sample, run, trace)
        _assert_parameter_binding(result, experiment, sample, run)
        response_signatures[workload].append(response_signature(sample_path) or [])
        if workload == "complex":
            _assert_two_origins_share_the_same_sample(sample_path, run)

    assert set(by_workload) == {"simple", "complex"}
    assert all(set(variants) == set(SEALED_DEFENSES) for variants in by_workload.values())
    assert all(
        len({tuple(signature) for signature in values}) == 1
        for values in response_signatures.values()
    )

    before_evidence = (result / "evidence.sha256").read_bytes()
    analysis = analyze_result(result)
    assert analysis.result_root == result
    assert (result / "derived/summary.csv").is_file()
    assert (result / "derived/report.html").is_file()
    plots = list((result / "derived/plots").glob("*.svg"))
    assert plots and not list((result / "derived/plots").glob("*.pdf"))
    assert (result / "evidence.sha256").read_bytes() == before_evidence
    verify_result(result)


@pytest.mark.skipif(
    not CAPTURE_GATE,
    reason="direct container-edge capture acceptance is launcher-provisioned",
)
def test_controlled_multi_origin_front_and_tamaraw_use_primary_origin_chaff(
    tmp_path: Path,
) -> None:
    """Exercise both response-only defenses across two application origins."""

    address = os.environ["QCSD_CAPTURE_SERVER_ADDRESS"]
    port = int(os.environ["QCSD_CAPTURE_SERVER_PORT"])
    second_address = os.environ["QCSD_CAPTURE_SERVER_TWO_ADDRESS"]
    second_port = int(os.environ["QCSD_CAPTURE_SERVER_TWO_PORT"])
    prepared = _controlled_complex_manifest(address, port, second_address, second_port)
    source = tmp_path / "complex-prepared.json"
    source.write_bytes(canonical_bytes(prepared))
    runtime = tmp_path / "complex-runtime.json"
    runtime.write_bytes(canonical_bytes(runtime_manifest(prepared)))
    controlled = _qualify_controlled_live_inputs(tmp_path, {"complex": source})
    _, sidecar, _, _ = controlled["complex"]
    chaff_manifest = tmp_path / "controlled-live/chaff-manifests/complex-response-only.json"
    _write_controlled_response_only_chaff_manifest(
        chaff_manifest,
        application_source=source,
        response_receipt=load_json(sidecar)["response_receipt"],
    )

    qualified = load_json(chaff_manifest)
    root = prepared["resources"][0]
    assert qualified["schema_version"] == 4
    assert qualified["qualification_scope"] == "response-only"
    assert qualified["application_workload_sha256"] == sha256_file(source)
    assert qualified["application_resource_id"] == root["id"]
    assert qualified["selected_chaff_resource_id"] == root["id"]
    assert len(qualified["resources"]) == 1
    assert qualified["resources"][0]["url"] == root["url"]
    assert qualified["resources"][0]["headers"] == CONTROLLED_AEL_HEADERS
    qualification = qualified["resources"][0]["chaff_qualification"]
    assert qualification["schema_version"] == 4
    assert qualification["qualification_scope"] == "response-only"
    assert qualification["request_header_primitive"] == (
        chaff_qualification.response_only_request_header_primitive()
    )

    context = SimpleNamespace(
        qcsd_profile="live",
        request_policy="as-defined",
        limits=capture_session.Limits(
            timeout_seconds=120,
            max_response_bytes=2_097_152,
            capture_seconds=180,
            capture_megabytes=64,
            max_attempts=1,
            per_origin_cooldown_seconds=0,
            settle_seconds=1,
        ),
        udp_payload_ceiling=1_200,
    )
    signatures: list[list[tuple[Any, ...]]] = []
    for seed_offset, kind in enumerate(("front", "tamaraw")):
        defense = capture_session.Defense(name=kind, kind=kind, baseline=False)
        attempt = tmp_path / f"attempt-{kind}"
        result = capture_session._collect_attempt(
            attempt,
            runtime,
            chaff_manifest,
            "complex",
            defense,
            20_260_819 + seed_offset,
            context,
            application_workload_source=source,
        )
        assert result["success"] is True
        assert (
            _intrinsic_fidelity_failure(
                {"sample_id": f"complex-{kind}", "defense": kind, "runtime_kind": kind},
                result,
                attempt,
            )
            is None
        )

        run = load_json(attempt / "neqo/run.json")
        assert run["completion_status"] == "complete"
        assert run["workload_hash_sha256"] == sha256_file(runtime)
        assert run["application_workload_source_hash_sha256"] == sha256_file(source)
        assert run["chaff_manifest_hash_sha256"] == sha256_file(chaff_manifest)
        assert run["resolved_configuration"]["defense"]["kind"] == kind
        assert run["defense_parameters"] is None
        assert {https_origin(endpoint["origin"]) for endpoint in run["endpoints"]} == {
            https_origin(resource["url"]) for resource in prepared["resources"]
        }
        assert len(run["endpoints"]) == 2
        assert all(endpoint["negotiated_protocol"] == "h3" for endpoint in run["endpoints"])
        assert all(
            endpoint["tuple"]
            == {
                "protocol": "udp",
                "local": endpoint["local_address"],
                "remote": endpoint["remote_address"],
            }
            for endpoint in run["endpoints"]
        )
        _assert_exact_application_responses(prepared, run)
        _assert_primary_origin_chaff(attempt, prepared, qualified, run)
        _assert_defense_schedule_and_credit(attempt, run)

        capture = result["views"][0]
        capture_path = attempt / capture["capture_path"]
        trace = extract_trace(capture_path, run["endpoints"])
        assert trace
        _assert_live_capture_evidence(capture, run, trace)
        _assert_direct_destination_isolation(
            capture_path,
            run,
            address,
            second_address,
        )
        _assert_direct_tuple_union(capture_path, run)
        _assert_two_origins_share_the_same_sample(attempt, run)
        signature = response_signature(attempt)
        assert signature is not None
        signatures.append(signature)

    assert len({tuple(signature) for signature in signatures}) == 1


@pytest.mark.skipif(
    not CAPTURE_GATE,
    reason="direct container-edge capture acceptance is launcher-provisioned",
)
def test_controlled_schema_six_walkie_talkie_uses_real_a_r_c_wire_path(
    tmp_path: Path,
) -> None:
    address = os.environ["QCSD_CAPTURE_SERVER_ADDRESS"]
    port = int(os.environ["QCSD_CAPTURE_SERVER_PORT"])
    source = tmp_path / "simple-prepared.json"
    prepared = _controlled_prepared_manifest(
        [_resource(0, f"https://{address}:{port}/131072", "Document", 131_072)]
    )
    source.write_bytes(canonical_bytes(prepared))
    runtime = tmp_path / "simple-runtime.json"
    runtime.write_bytes(canonical_bytes(runtime_manifest(prepared)))
    controlled = _qualify_controlled_live_inputs(tmp_path, {"simple": source})
    _, sidecar, spec, chaff_manifest = controlled["simple"]
    walkie_talkie = tmp_path / "walkie-talkie-controlled-v6.json"
    _write_controlled_walkie_talkie(
        walkie_talkie,
        {"simple": (sidecar, spec, chaff_manifest)},
    )
    provenance = tmp_path / "walkie-talkie-controlled-v6.json.provenance.json"
    atomic_json(
        provenance,
        {
            "schema_version": 1,
            "artifact_type": "qcsd-controlled-live-test-only-parameter-provenance",
            "production_ready": False,
        },
    )
    with pytest.raises(ValueError):
        parameters.validate_parameter_artifact(
            walkie_talkie,
            provenance_path=provenance,
            expected_kind="walkie_talkie",
            allow_reviewed_fixture=True,
            expected_qcsd_profile="live",
            expected_udp_payload_ceiling=1_200,
            expected_workloads={"simple": sha256_file(source)},
        )
    with pytest.raises(ValueError):
        chaff_qualification.load_qualified_chaff(
            sidecar,
            workload_id="simple",
            base_manifest_path=source,
            prefix_spec_path=spec,
            require_current_implementation=False,
        )

    defense = capture_session.Defense(
        name="walkie-talkie",
        kind="walkie_talkie",
        baseline=False,
        parameters=str(walkie_talkie),
        parameters_path=walkie_talkie,
        parameters_sha256=sha256_file(walkie_talkie),
        parameters_provenance=str(provenance),
        parameters_provenance_path=provenance,
        parameters_provenance_sha256=sha256_file(provenance),
        parameters_input_policy="controlled-live-test-only",
    )
    context = SimpleNamespace(
        qcsd_profile="live",
        request_policy="as-defined",
        limits=capture_session.Limits(
            timeout_seconds=120,
            max_response_bytes=2_097_152,
            capture_seconds=180,
            capture_megabytes=64,
            max_attempts=1,
            per_origin_cooldown_seconds=0,
            settle_seconds=1,
        ),
        udp_payload_ceiling=1_200,
    )
    attempt = tmp_path / "attempt"
    result = capture_session._collect_attempt(
        attempt,
        runtime,
        chaff_manifest,
        "simple",
        defense,
        20_260_814,
        context,
        application_workload_source=source,
    )
    assert result["success"] is True
    assert (
        _intrinsic_fidelity_failure(
            {"defense": "walkie-talkie", "runtime_kind": "walkie_talkie"},
            result,
            attempt,
        )
        is None
    )
    run = load_json(attempt / "neqo/run.json")
    assert run["completion_status"] == "complete"
    assert run["workload_hash_sha256"] == sha256_file(runtime)
    assert run["application_workload_source_hash_sha256"] == sha256_file(source)
    assert run["chaff_manifest_hash_sha256"] == sha256_file(chaff_manifest)
    chaff_responses = run["chaff_responses"]
    assert [receipt["request_id"] for receipt in chaff_responses] == list(range(2))
    assert all(
        receipt["request_stream_bytes"] == receipt["expected_request_stream_bytes"] > 0
        for receipt in chaff_responses
    )
    # The 129-cell receive budget finishes the 131072-byte application body
    # but cannot finish another body of the same size.  Runtime chaff receipts
    # are therefore deliberately partial when the defense completes.
    assert all(
        receipt["complete"] is False
        and receipt["status"] is None
        and receipt["content_encoding"] is None
        and receipt["body_sha256"] is None
        and receipt["status_match"] is None
        and receipt["content_encoding_match"] is None
        and receipt["body_bytes_match"] is None
        and receipt["body_sha256_match"] is None
        and receipt["identity_verified"] is None
        and receipt["outcome"] == "incomplete"
        for receipt in chaff_responses
    )
    assert any(receipt["bytes"] > 0 for receipt in chaff_responses)
    application_headers = run["responses"][0]["request_headers"]
    assert application_headers == prepared["resources"][0]["headers"]
    assert application_headers != CONTROLLED_AEL_HEADERS
    assert all(receipt["request_headers"] == CONTROLLED_AEL_HEADERS for receipt in chaff_responses)
    diagnostics = run["defense_diagnostics"]
    assert diagnostics["scheduled_incoming_requested_bytes"] > 0
    assert (
        diagnostics["scheduled_incoming_requested_bytes"]
        == diagnostics["scheduled_incoming_advertised_bytes"]
        == diagnostics["scheduled_incoming_consumed_bytes"]
    )
    assert diagnostics["scheduled_incoming_retired_bytes"] == 0
    assert diagnostics["scheduled_incoming_unresolved_bytes"] == 0
    assert diagnostics["walkie_talkie_incoming_chaff_bytes"] > 0
    assert (
        diagnostics["walkie_talkie_target_outgoing_cells"]
        == diagnostics["walkie_talkie_observed_outgoing_cells"]
    )
    assert (
        diagnostics["walkie_talkie_target_incoming_cells"]
        == diagnostics["walkie_talkie_observed_incoming_cells"]
    )
    for field in (
        "walkie_talkie_outgoing_shortfall_cells",
        "walkie_talkie_incoming_shortfall_cells",
        "walkie_talkie_outgoing_overflow_cells",
        "walkie_talkie_incoming_overflow_cells",
        "walkie_talkie_source_envelope_overflow_cells",
        "walkie_talkie_application_batch_overflow",
        "walkie_talkie_batch_lifecycle_errors",
        "walkie_talkie_target_observed_cell_l1",
        "walkie_talkie_target_observed_burst_l1",
    ):
        assert diagnostics[field] == 0


def test_current_buflo_capture_requires_kernel_tx_scheduler_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(capture_session, "_capture_scheduler_contract", lambda: None)
    attempt = tmp_path / "attempt"
    context = SimpleNamespace(
        qcsd_profile="live",
        request_policy="as-defined",
        limits=capture_session.Limits(),
        udp_payload_ceiling=1_200,
    )

    with pytest.raises(ValueError, match="kernel-TX ETF scheduler contract"):
        capture_session._collect_attempt(
            attempt,
            tmp_path / "runtime.json",
            tmp_path / "chaff.json",
            "site",
            capture_session.Defense(name="buflo", kind="buflo", baseline=False),
            7,
            context,
            application_workload_source=tmp_path / "prepared.json",
        )

    assert not attempt.exists()


def _configuration(
    directory: Path,
    address: str,
    port: int,
    second_address: str,
    second_port: int,
) -> Path:
    campaign_dir = directory / "config/campaigns"
    workload_dir = directory / "config/workloads"
    campaign_dir.mkdir(parents=True)
    workload_dir.mkdir()
    simple = _controlled_prepared_manifest(
        [_resource(0, f"https://{address}:{port}/131072", "Document", 131_072)]
    )
    complex_workload = _controlled_complex_manifest(address, port, second_address, second_port)
    atomic_json(workload_dir / "simple.json", simple)
    atomic_json(workload_dir / "complex.json", complex_workload)

    campaign = {
        "schema": 1,
        "name": "direct-capture-acceptance",
        "purpose": "smoke",
        "seed": 20_260_730,
        "profile": "live",
        "workloads": {"simple": 1, "complex": 1},
        "request_policies": ["as-defined"],
        "limits": {
            "timeout_seconds": 120,
            "max_response_bytes": 2_097_152,
            "capture_seconds": 180,
            "capture_megabytes": 64,
            "settle_seconds": 1,
            "max_attempts": 3,
            "per_origin_cooldown_seconds": 0,
        },
        "defenses": ["undefended"],
    }
    path = campaign_dir / "campaign.yml"
    path.write_text(yaml.safe_dump(campaign, sort_keys=False), encoding="utf-8")
    return path


def _controlled_complex_manifest(
    address: str,
    port: int,
    second_address: str,
    second_port: int,
) -> dict[str, Any]:
    first_origin = f"https://{address}:{port}"
    second_origin = f"https://{second_address}:{second_port}"
    return _controlled_prepared_manifest(
        [
            _resource(0, f"{first_origin}/131072", "Document", 131_072),
            _resource(1, f"{first_origin}/1024", "Script", 1_024, depends_on=[0]),
            _resource(2, f"{second_origin}/4096", "Script", 4_096, depends_on=[0]),
            _resource(3, f"{second_origin}/2048", "Image", 2_048, depends_on=[2]),
        ]
    )


def _resource(
    identifier: int,
    url: str,
    resource_type: str,
    size: int,
    *,
    depends_on: list[int] | None = None,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "url": url,
        "type": resource_type,
        "content_length": size,
        "data_length": size,
        "chaff_priority": identifier == 0,
        "known_valid": True,
        "depends_on": depends_on or [],
        "headers": [
            *deepcopy(CONTROLLED_AEL_HEADERS),
            ["user-agent", "qcsd-controlled-live-application"],
        ],
    }


def _capture_addresses(capture: Path) -> set[str]:
    result = subprocess.run(
        [
            "tshark",
            "-r",
            str(capture),
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    return {
        address for line in result.stdout.splitlines() for address in line.split("\t") if address
    }


def _assert_direct_destination_isolation(
    capture: Path, run: dict[str, Any], *server_addresses: str
) -> None:
    local_addresses = {endpoint["local_address"].rsplit(":", 1)[0] for endpoint in run["endpoints"]}
    assert len(local_addresses) == 1
    assert _capture_addresses(capture) == {*local_addresses, *server_addresses}


def _assert_capture_contract(sample: dict[str, Any], run: dict[str, Any], trace: list[Any]) -> None:
    capture = sample["diagnostics"]["capture"]
    _assert_live_capture_evidence(capture, run, trace)
    assert capture["capture_path"] == "capture.pcapng"
    assert "trace_path" not in capture
    assert "trace_sha256" not in capture


def _assert_live_capture_evidence(
    capture: dict[str, Any], run: dict[str, Any], trace: list[Any]
) -> None:
    assert capture["primary"] is True
    assert capture["valid"] is True
    assert capture["capture_active_through_settle"] is True
    assert capture["link_type"] == "Ethernet"
    assert capture["length_basis"] == "frame.len"
    assert capture["timestamp_type"] == "host"
    assert capture["packet_count"] == len(trace)
    ceiling = capture["udp_payload_ceiling_evidence"]
    assert ceiling["configured_udp_payload_ceiling"] == 1_200
    assert ceiling["runner_resolved_udp_payload_ceiling"] == 1_200
    assert ceiling["oversized_udp_payload_packets"] == 0
    assert ceiling["valid"] is True
    assert run["resolved_configuration"]["max_udp_payload_size"] == 1_200
    offload = capture["capture_offload_evidence"]
    assert offload["after_state"] == {
        "gro": "off",
        "gso": "off",
        "tso": "off",
        "uso": "off",
    }
    assert offload["verified"] is True
    reconciliation = capture["direct_runner_reconciliation"]
    assert reconciliation["direct_runner_reconciled"] is True
    assert reconciliation["evidence_eligible"] is True
    assert reconciliation["direct_matched_packets"] == reconciliation["direct_runner_packets"]
    assert reconciliation["direct_clock_model"] == "constant-offset"
    assert reconciliation["direct_clock_segment_count"] == 1
    assert reconciliation["direct_clock_step_count"] == 0
    clock = capture["capture_clock_integrity"]
    assert clock["valid"] is True
    assert clock["capture_timestamp_type"] == "host"
    assert clock["clock_domain"] == "linux-kernel"
    assert clock["clock_model"] == "constant-offset"
    assert clock["pairing_uncertainty_recorded"] is True


def _assert_exact_application_responses(prepared: dict[str, Any], run: dict[str, Any]) -> None:
    resources = {resource["id"]: resource for resource in prepared["resources"]}
    identities = {
        response["resource_id"]: response
        for response in prepared["preparation"]["expected_responses"]
    }
    responses = {response["resource_id"]: response for response in run["responses"]}
    assert set(responses) == set(resources) == set(identities)
    for identifier, response in responses.items():
        assert response["url"] == resources[identifier]["url"]
        assert response["request_headers"] == resources[identifier]["headers"]
        assert response["status"] == identities[identifier]["status"] == 200
        assert response["bytes"] == identities[identifier]["bytes"]
        assert response["body_sha256"] == identities[identifier]["body_sha256"]
        assert response["request_stream_bytes"] > 0
        assert response["complete"] is True
        assert response["outcome"] == "succeeded"


def _assert_primary_origin_chaff(
    attempt: Path,
    prepared: dict[str, Any],
    qualified: dict[str, Any],
    run: dict[str, Any],
) -> None:
    resource = qualified["resources"][0]
    primary_origin = https_origin(prepared["resources"][0]["url"])
    assert primary_origin is not None
    assert https_origin(resource["url"]) == primary_origin
    primary_endpoint = next(
        endpoint
        for endpoint in run["endpoints"]
        if https_origin(endpoint["origin"]) == primary_origin
    )
    receipts = run["chaff_responses"]
    assert receipts
    assert len({receipt["request_id"] for receipt in receipts}) == len(receipts)
    assert any(receipt["bytes"] > 0 for receipt in receipts)
    assert all(
        receipt["resource_id"] == resource["id"]
        and receipt["url"] == resource["url"]
        and receipt["request_headers"] == resource["headers"]
        and receipt["request_stream_bytes"]
        == receipt["expected_request_stream_bytes"]
        == resource["chaff_qualification"]["request_stream_bytes"]
        and receipt["outcome"] in {"succeeded", "incomplete", "reset", "endpoint_closed"}
        for receipt in receipts
    )
    with (attempt / "neqo/events.csv").open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    actions = []
    for row in rows:
        if row["event"] != "action" or row["outcome"] != "applied":
            continue
        details = json.loads(row["details"])
        if details.get("type") == "request_chaff":
            actions.append((row, details))
    assert actions
    assert {int(row["connection"]) for row, _ in actions} == {primary_endpoint["id"]}
    assert {details["endpoint"] for _, details in actions} == {primary_endpoint["id"]}
    assert all(https_origin(details["resource"]["url"]) == primary_origin for _, details in actions)


def _assert_defense_schedule_and_credit(attempt: Path, run: dict[str, Any]) -> None:
    schedule = _schedule_realization_metrics(attempt)
    assert schedule["scheduled_events"] > 0
    assert schedule["scheduled_outgoing_events"] > 0
    assert schedule["scheduled_incoming_events"] > 0
    assert schedule["satisfied_events"] == schedule["scheduled_events"]
    assert schedule["missed_events"] == 0
    assert schedule["missed_event_reasons"] == {}
    assert schedule["outgoing_size_mismatch_events"] == 0
    assert schedule["outgoing_size_absolute_error_bytes"] == 0
    with (attempt / "neqo/schedule.csv").open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    scheduled_connections = {int(row["connection"]) for row in rows if row["connection"]}
    assert scheduled_connections
    assert scheduled_connections <= {endpoint["id"] for endpoint in run["endpoints"]}
    assert all(int(row["size"]) == 1_200 for row in rows)
    diagnostics = run["defense_diagnostics"]
    assert diagnostics["scheduled_incoming_requested_bytes"] > 0
    assert (
        diagnostics["scheduled_incoming_requested_bytes"]
        == diagnostics["scheduled_incoming_advertised_bytes"]
        == diagnostics["scheduled_incoming_consumed_bytes"]
    )
    assert diagnostics["scheduled_incoming_retired_bytes"] == 0
    assert diagnostics["scheduled_incoming_unresolved_bytes"] == 0


def _assert_direct_tuple_union(capture: Path, run: dict[str, Any]) -> None:
    completed = subprocess.run(
        [
            "tshark",
            "-r",
            str(capture),
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ipv6.src",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.dst",
            "-e",
            "udp.srcport",
            "-e",
            "udp.dstport",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    observed: set[tuple[str, int, str, int]] = set()
    for row in csv.reader(completed.stdout.splitlines(), delimiter="\t"):
        if len(row) != 6 or not row[4] or not row[5]:
            continue
        observed.add((row[0] or row[1], int(row[4]), row[2] or row[3], int(row[5])))
    expected: set[tuple[str, int, str, int]] = set()
    for endpoint in run["endpoints"]:
        local_address, local_port = split_endpoint(endpoint["local_address"])
        remote_address, remote_port = split_endpoint(endpoint["remote_address"])
        expected.add((local_address, local_port, remote_address, remote_port))
        expected.add((remote_address, remote_port, local_address, local_port))
    assert observed == expected


def _assert_parameter_binding(
    root: Path,
    experiment: dict[str, Any],
    sample: dict[str, Any],
    run: dict[str, Any],
) -> None:
    expected = PARAMETER_FILES.get(sample["defense"])
    parameter = run["defense_parameters"]
    if expected is None:
        assert parameter is None
        return
    record = next(
        item
        for item in experiment["configuration"]["defenses"]
        if item["name"] == sample["defense"]
    )
    field = "schedule" if sample["defense"] == "static" else "parameters"
    frozen = root / record[field]
    assert parameter == {
        "kind": sample["runtime_kind"],
        "path": str(frozen),
        "sha256": sha256_file(expected),
    }
    assert sha256_file(frozen) == parameter["sha256"]
    if sample["defense"] != "static":
        assert sha256_file(root / record["provenance"]) == record["provenance_sha256"]


def _assert_two_origins_share_the_same_sample(sample: Path, run: dict[str, Any]) -> None:
    assert len(run["endpoints"]) == 2
    assert len({endpoint["remote_address"] for endpoint in run["endpoints"]}) == 2
    with (sample / "neqo/packets.csv").open(newline="", encoding="utf-8") as source:
        connections = {int(row["connection"]) for row in csv.DictReader(source)}
    assert connections == {0, 1}
    with (sample / "neqo/events.csv").open(newline="", encoding="utf-8") as source:
        starts = [
            row
            for row in csv.DictReader(source)
            if row["event"] == "application_request" and row["outcome"] == "started"
        ]
    simultaneous: dict[int, set[int]] = defaultdict(set)
    for row in starts:
        simultaneous[int(row["monotonic_us"])].add(int(row["connection"]))
    assert {0, 1} in simultaneous.values()
