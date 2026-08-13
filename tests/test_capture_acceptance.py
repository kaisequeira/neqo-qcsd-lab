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
from qcsd_lab.capture import extract_trace
from qcsd_lab.fitting_walkie_talkie import receiver_continuation_contract
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
    _write_controlled_prefix_spec(prefix_spec, workload_id, [{"outgoing": 3, "incoming": 129}])
    chaff_manifest = tmp_path / "simple-chaff.json"
    _write_controlled_chaff_manifest(
        chaff_manifest,
        workload_id=workload_id,
        application_source=source,
        response_receipt=receipt,
        prefix_spec=prefix_spec,
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
    assert manifest["schema_version"] == 1
    assert manifest["artifact_type"] == "qcsd-qualified-chaff-manifest"
    assert manifest["application_workload_sha256"] == sha256_file(source)
    assert manifest["resources"][0]["headers"] == CONTROLLED_AEL_HEADERS
    assert manifest["resources"][0]["chaff_qualification"]["prefix_spec_sha256"] == sha256_file(
        prefix_spec
    )
    assert load_json(runtime) == runtime_manifest(prepared)

    molded = load_json(walkie_talkie)
    selected = next(
        binding
        for binding in molded["qualification_bindings"]
        if binding["workload_id"] == workload_id
    )
    assert molded["schema_version"] == 6
    assert molded["generated_by"] == "controlled-live-test-only"
    assert molded["receiver_continuation"] == receiver_continuation_contract()
    assert selected == {
        "workload_id": workload_id,
        "chaff_qualification_sidecar_sha256": sha256_file(sidecar),
        "prefix_pack_spec_sha256": sha256_file(prefix_spec),
        "qualified_chaff_manifest_sha256": sha256_file(chaff_manifest),
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
    ]
    packet_log = json.dumps(observations, separators=(",", ":")).encode()
    statistic = {
        "incoming": {
            "packet_count": 1,
            "observed_udp_payload_max": 900,
            "oversized_packet_count": 0,
        },
        "outgoing": {
            "packet_count": 1,
            "observed_udp_payload_max": 1_200,
            "oversized_packet_count": 0,
        },
        "total": {
            "packet_count": 2,
            "observed_udp_payload_max": 1_200,
            "oversized_packet_count": 0,
        },
    }
    headers = chaff_qualification.project_compact_headers(root)
    return {
        "schema_version": 1,
        "artifact_type": chaff_qualification.RESPONSE_ARTIFACT_TYPE,
        "invocation_id": "controlled-offline-observation",
        "neqo_version": "controlled-live-test-only",
        "application_workload_sha256": sha256_file(application_source),
        "application_resource_id": root["id"],
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
            "neqo_base_commit": "controlled-live-test-only",
            "published_qcsd_commit": "controlled-live-test-only",
            "migration_commit": "controlled-live-test-only",
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
        resource_id=root["id"],
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
        "schema_version": 1,
        "artifact_type": chaff_qualification.MANIFEST_ARTIFACT_TYPE,
        "application_workload_sha256": sha256_file(application_source),
        "application_resource_id": root["id"],
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
                    "schema_version": 1,
                    "method": "GET",
                    "request_stream_bytes": request_bytes,
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


def _write_controlled_walkie_talkie(
    path: Path,
    inputs: dict[str, tuple[Path, Path, Path]],
) -> None:
    historical = Path(__file__).parents[1] / "config/defense-params/walkie-talkie-live.json"
    value = load_json(historical)
    source_profiles = {profile["real"]: profile for profile in value["profiles"]}
    profiles: list[dict[str, Any]] = []
    bindings: list[dict[str, str]] = []
    for index, (workload_id, (sidecar, spec, manifest)) in enumerate(inputs.items()):
        profile = deepcopy(
            source_profiles.get(workload_id, value["profiles"][index % len(value["profiles"])])
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


def _qualify_controlled_live_inputs(
    directory: Path,
    sources: dict[str, Path],
) -> dict[str, tuple[Path, Path, Path, Path]]:
    """Observe one local five-way compact response run per controlled workload.

    This is intentionally a wire smoke, not the three-by-five research
    qualification policy.  The public sidecar loader remains required to reject
    the resulting test-local record.
    """

    qualification_root = directory / "config/chaff-qualification-store/v1"
    prefix_root = directory / "config/chaff-prefix-specs"
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
        profile = profiles[workload_id]
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
    assert [receipt["request_id"] for receipt in chaff_responses] == list(range(5))
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
    first_origin = f"https://{address}:{port}"
    second_origin = f"https://{second_address}:{second_port}"
    simple = _controlled_prepared_manifest(
        [_resource(0, f"{first_origin}/131072", "Document", 131_072)]
    )
    complex_workload = _controlled_prepared_manifest(
        [
            _resource(0, f"{first_origin}/131072", "Document", 131_072),
            _resource(1, f"{first_origin}/1024", "Script", 1_024, depends_on=[0]),
            _resource(2, f"{second_origin}/4096", "Script", 4_096, depends_on=[0]),
            _resource(3, f"{second_origin}/2048", "Image", 2_048, depends_on=[2]),
        ]
    )
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
    assert capture["valid"] is True
    assert capture["capture_active_through_settle"] is True
    assert capture["link_type"] == "Ethernet"
    assert capture["length_basis"] == "frame.len"
    assert capture["packet_count"] == len(trace)
    assert capture["capture_path"] == "capture.pcapng"
    assert "trace_path" not in capture
    assert "trace_sha256" not in capture
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
