from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import qcsd_lab.chaff_qualification as qualification
import qcsd_lab.fitting as fitting
from qcsd_lab.chaff_qualification import (
    HEADER_PROJECTION,
    QualifiedChaffOutput,
    derive_chaff_manifest,
    derive_prefix_pack_specs,
    prefix_pack_spec,
    project_compact_headers,
    qualification_digest,
    selected_navigation_root,
    validate_prefix_pack_spec,
    validate_sidecar,
)
from qcsd_lab.fitting import _validate_prefix_spec_mould_binding
from qcsd_lab.manifest import canonical_bytes, runtime_manifest
from qcsd_lab.util import atomic_json, load_json, sha256_bytes, sha256_file


ROOT = Path(__file__).parents[1]
WORKLOAD = ROOT / "config/workloads/cloudflare-quiche-r3.json"
SCHEMA_FIVE_WALKIE = ROOT / qualification.SCHEMA_FIVE_WALKIE_TALKIE_ARCHIVE


def _response() -> dict[str, object]:
    prepared = load_json(WORKLOAD)["preparation"]["expected_responses"][0]
    return {
        "status": 200,
        "content_encoding": "gzip",
        "body_bytes": 13_390,
        "body_sha256": prepared["body_sha256"],
    }


def _packet_log(observations: list[dict[str, object]]) -> str:
    import json

    return sha256_bytes(json.dumps(observations, separators=(",", ":")).encode())


def _statistics(
    observations: list[dict[str, object]],
) -> dict[str, dict[str, int]]:
    by_direction = {
        direction: [
            int(row["udp_payload_bytes"]) for row in observations if row["direction"] == direction
        ]
        for direction in ("incoming", "outgoing")
    }
    incoming = by_direction["incoming"]
    outgoing = by_direction["outgoing"]
    return {
        "incoming": {
            "packet_count": len(incoming),
            "observed_udp_payload_max": max(incoming),
            "oversized_packet_count": 0,
        },
        "outgoing": {
            "packet_count": len(outgoing),
            "observed_udp_payload_max": max(outgoing),
            "oversized_packet_count": 0,
        },
        "total": {
            "packet_count": len(incoming) + len(outgoing),
            "observed_udp_payload_max": max(*incoming, *outgoing),
            "oversized_packet_count": 0,
        },
    }


def _response_receipt(
    *,
    run_index: int,
    application_sha256: str,
    url: str,
    headers: list[list[str]],
    source: dict[str, str],
) -> dict[str, object]:
    expected = _response()
    observations: list[dict[str, object]] = [
        {
            "sequence": 0,
            "phase": "handshake",
            "direction": "incoming",
            "udp_payload_bytes": 900,
        },
        {
            "sequence": 1,
            "phase": "handshake",
            "direction": "outgoing",
            "udp_payload_bytes": 100,
        },
        {
            "sequence": 2,
            "phase": "qualification",
            "direction": "outgoing",
            "udp_payload_bytes": 1_200,
        },
    ]
    return {
        "schema_version": 2,
        "artifact_type": qualification.RESPONSE_ARTIFACT_TYPE,
        "invocation_id": f"response-{run_index}",
        "neqo_version": "test",
        "application_workload_sha256": application_sha256,
        "application_resource_id": 0,
        "selected_chaff_resource_id": 0,
        "qualified_parallel_chaff_streams": 6,
        "method": "GET",
        "url": url,
        "request_headers": headers,
        "parallel_requests": 6,
        "connection_count": 1,
        "requests_opened_before_first_network_output": 6,
        "request_stream_bytes": 163,
        "max_response_bytes": 1_048_576,
        "udp_payload_ceiling": 1_200,
        "started_unix_ns": run_index * 20,
        "ended_unix_ns": run_index * 20 + 10,
        "completion_status": "complete",
        "error": None,
        "source": source,
        "requests": [
            {
                "request_index": request_index,
                "stream_id": request_index * 4,
                "request_stream_bytes": 163,
                "status": expected["status"],
                "content_encoding": expected["content_encoding"],
                "body_bytes": expected["body_bytes"],
                "body_sha256": expected["body_sha256"],
                "complete": True,
                "outcome": "complete",
            }
            for request_index in range(6)
        ],
        "packet_observations": observations,
        "packet_log_sha256": _packet_log(observations),
        "packets": _statistics(observations),
        "passed": True,
    }


def _prefix_receipt(
    *,
    run_index: int,
    application_sha256: str,
    runtime_sha256: str,
    core_sha256: str,
    spec: dict[str, object],
    spec_sha256: str,
    source: dict[str, str],
) -> dict[str, object]:
    application_bytes = 201
    request_bytes = 163
    required = int(spec["required_chaff_streams"])
    transmissions: list[dict[str, object]] = []
    streams: list[dict[str, object]] = []
    for order in range(required + 1):
        role = "application" if order == 0 else "chaff"
        stream_id = order * 4
        size = application_bytes if order == 0 else request_bytes
        complete = True
        acknowledgements = [{"sequence": order, "offset": 0, "bytes": size, "fin": True}]
        if complete:
            transmissions.append(
                {
                    "sequence": len(transmissions),
                    "stream": stream_id,
                    "role": (
                        "application"
                        if order == 0
                        else {"chaff": {"resource_id": 0, "request_id": order - 1}}
                    ),
                    "offset": 0,
                    "bytes": size,
                    "fin": True,
                    "slot": 1,
                }
            )
        streams.append(
            {
                "request_order": order,
                "opening_stage_index": 0,
                "role": role,
                "resource_id": 0,
                "request_id": None if order == 0 else order - 1,
                "stream_id": stream_id,
                "request_stream_bytes": size,
                "qualified_request_stream_bytes": None if order == 0 else request_bytes,
                "transmitted_unique_ranges": [[0, size]] if complete else [],
                "transmitted_unique_bytes": size if complete else 0,
                "fin_transmitted": complete,
                "acknowledgements": acknowledgements,
                "acknowledged_unique_ranges": ([[0, size]] if acknowledgements else []),
                "acknowledged_unique_bytes": size if acknowledgements else 0,
                "fin_acknowledged": bool(acknowledgements),
            }
        )
    target_count = sum(
        int(stage["exact_target_cells"]) for stage in spec["stream_activation_stages"]
    )
    target_slots = list(range(1, target_count + 1))
    observations: list[dict[str, object]] = [
        {
            "sequence": 0,
            "phase": "warmup",
            "direction": "incoming",
            "udp_payload_bytes": 900,
        },
        {
            "sequence": 1,
            "phase": "warmup",
            "direction": "outgoing",
            "udp_payload_bytes": 100,
        },
        *[
            {
                "sequence": index + 2,
                "phase": "qualification",
                "direction": "outgoing",
                "udp_payload_bytes": 1_200,
            }
            for index in range(target_count)
        ],
        {
            "sequence": target_count + 2,
            "phase": "qualification",
            "direction": "outgoing",
            "udp_payload_bytes": 87,
        },
    ]
    stage_receipts = []
    prior_active = 0
    for stage_index, stage in enumerate(spec["stream_activation_stages"]):
        active = int(stage["required_active_chaff_streams"])
        newly = int(stage["newly_required_chaff_streams"])
        slots = target_slots[
            sum(
                int(value["exact_target_cells"])
                for value in spec["stream_activation_stages"][:stage_index]
            ) : sum(
                int(value["exact_target_cells"])
                for value in spec["stream_activation_stages"][: stage_index + 1]
            )
        ]
        stage_receipts.append(
            {
                "stage_index": stage_index,
                "component_index": stage_index,
                "application_resource_ids": stage["application_resource_ids"],
                "application_request_orders": [0] if stage_index == 0 else [],
                "application_stream_ids": [0] if stage_index == 0 else [],
                "target_slot_ids": slots,
                "exact_target_cells": stage["exact_target_cells"],
                "scheduled_target_bytes": int(stage["exact_target_cells"]) * 1_200,
                "required_active_chaff_streams": active,
                "newly_required_chaff_streams": newly,
                "peer_acknowledged_active_chaff_streams": active,
                "newly_peer_acknowledged_request_orders": list(range(prior_active + 1, active + 1)),
                "newly_peer_acknowledged_stream_ids": [
                    order * 4 for order in range(prior_active + 1, active + 1)
                ],
                "allowed_pending_chaff_request_orders": list(range(active + 1, required + 1)),
                "allowed_pending_chaff_stream_ids": [
                    order * 4 for order in range(active + 1, required + 1)
                ],
                "targetless_stream_bytes_at_gate": 0,
                "pending_required_prefix_stream_send": False,
                "passed": True,
            }
        )
        prior_active = active
    return {
        "schema_version": 2,
        "artifact_type": qualification.PREFIX_ARTIFACT_TYPE,
        "invocation_id": f"prefix-{run_index}",
        "neqo_version": "test",
        "application_workload_source_sha256": application_sha256,
        "runtime_workload_sha256": runtime_sha256,
        "chaff_core_sha256": core_sha256,
        "prefix_pack_spec_sha256": spec_sha256,
        "application_resource_id": 0,
        "selected_chaff_resource_id": 0,
        "selected_chaff_body_bytes": 13_390,
        "required_chaff_streams": required,
        "workload_id": spec["workload_id"],
        "numeric_profile_sha256": spec["numeric_profile_sha256"],
        "source_walkie_talkie_artifact_sha256": spec["source_walkie_talkie_artifact_sha256"],
        "packet_size": spec["packet_size"],
        "max_stream_data_excess": spec["max_stream_data_excess"],
        "maximum_receiver_continuation_reserve_horizon": spec[
            "maximum_receiver_continuation_reserve_horizon"
        ],
        "required_chaff_survivors": spec["required_chaff_survivors"],
        "connection_count": 1,
        "peer_settings_received": True,
        "warmup_stream_output_drained": True,
        "packet_cutoff_sequence": 2,
        "requests_opened": required + 1,
        "scheduled_target_slot_ids": target_slots,
        "satisfied_target_slot_ids": target_slots,
        "activation_stage_receipts": stage_receipts,
        "streams": streams,
        "stream_transmissions": transmissions,
        "packet_observations": observations,
        "packet_log_sha256": _packet_log(observations),
        "packets": _statistics(observations),
        "post_slot_pending_stream_send": False,
        "post_slot_pending_required_prefix_stream_send": False,
        "qpack_decoder_stream_id": 10,
        "qpack_decoder_handler_pending": False,
        "qpack_decoder_transport_pending": False,
        "allowed_pending_late_chaff_request_orders": [],
        "allowed_pending_late_chaff_stream_ids": [],
        "targetless_stream_bytes": 0,
        "completion_status": "complete",
        "error": None,
        "started_unix_ns": 60 + run_index * 20,
        "ended_unix_ns": 70 + run_index * 20,
        "source": source,
        "passed": True,
    }


def _sidecar(prefix_path: Path | None = None) -> dict[str, object]:
    manifest = load_json(WORKLOAD)
    root = selected_navigation_root(manifest, "cloudflare-quiche-r3")
    headers = project_compact_headers(root)
    expected = _response()
    source = {
        "image_digest": "sha256:" + "a" * 64,
        "lab_commit": "b" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": qualification.EMPTY_SHA256,
        "neqo_commit": "c" * 40,
        "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": qualification.EMPTY_SHA256,
    }
    implementation = qualification.implementation_receipt()
    implementation["source"] = {**source, "image_digest": None}
    implementation["sha256"] = qualification._implementation_aggregate(implementation)
    neqo_source = {
        "neqo_base_commit": "d" * 40,
        "published_qcsd_commit": "e" * 40,
        "migration_commit": source["neqo_commit"],
    }
    application_sha256 = sha256_file(WORKLOAD)
    response_runs = [
        qualification._response_run_record(
            run_index,
            _response_receipt(
                run_index=run_index,
                application_sha256=application_sha256,
                url=root["url"],
                headers=headers,
                source=neqo_source,
            ),
        )
        for run_index in range(3)
    ]
    response_digest = qualification_digest("qcsd-chaff-response-qualification-v2", response_runs)
    core = qualification.derive_chaff_core(
        application_manifest_sha256=application_sha256,
        base_resource=root,
        headers=headers,
        request_stream_bytes=163,
        expected_response=expected,
        response_qualification_sha256=response_digest,
        application_resource_id=0,
        selected_chaff_resource_id=0,
        qualified_parallel_chaff_streams=6,
        walkie_talkie_required_chaff_streams=6,
    )
    if prefix_path is None:
        spec = prefix_pack_spec(
            "cloudflare-quiche-r3",
            load_json(SCHEMA_FIVE_WALKIE),
            source_walkie_talkie_artifact_sha256=qualification.SOURCE_WALKIE_TALKIE_SHA256,
        )
        spec_sha256 = "9" * 64
    else:
        spec = load_json(prefix_path)
        spec_sha256 = sha256_file(prefix_path)
    prefix_runs = [
        qualification._prefix_run_record(
            run_index,
            _prefix_receipt(
                run_index=run_index,
                application_sha256=application_sha256,
                runtime_sha256=sha256_bytes(canonical_bytes(runtime_manifest(manifest))),
                core_sha256=sha256_bytes(canonical_bytes(core)),
                spec=spec,
                spec_sha256=spec_sha256,
                source=neqo_source,
            ),
        )
        for run_index in range(3)
    ]
    return {
        "schema_version": 2,
        "artifact_type": qualification.SIDECAR_ARTIFACT_TYPE,
        "workload_id": "cloudflare-quiche-r3",
        "base_manifest": {"path": WORKLOAD.name, "sha256": application_sha256},
        "selection_policy": qualification.SELECTION_POLICY,
        "application_resource_id": 0,
        "selected_chaff_resource_id": 0,
        "qualified_parallel_chaff_streams": 6,
        "walkie_talkie_required_chaff_streams": 6,
        "header_projection": list(HEADER_PROJECTION),
        "method": "GET",
        "qualification_policy": {
            "response_runs": 3,
            "parallel_response_requests": 6,
            "qualified_parallel_chaff_streams": 6,
            "walkie_talkie_required_chaff_streams": 6,
            "prefix_pack_runs": 3,
            "profile": "research-1200",
            "response_defense": "none",
            "seed": 0,
            "udp_payload_ceiling": 1_200,
            "max_stream_data_excess": 1_000,
            "separate_chaff_namespace": True,
        },
        "qualification_source": source,
        "qualification_image_digest": source["image_digest"],
        "neqo_provenance": {"neqo_version": "test", **neqo_source},
        "implementation_receipt": implementation,
        "fitting_source": qualification._fitting_source_receipt(),
        "schema_five_diagnostic": qualification._schema_five_diagnostic_receipt(),
        "schema_six_capacity_falsification_diagnostic": (
            qualification._schema_six_capacity_falsification_diagnostic_receipt()
        ),
        "schema_six_runtime_falsification_diagnostic": (
            qualification._schema_six_runtime_falsification_diagnostic_receipt()
        ),
        "schema_two_sender_framing_falsification_diagnostic": (
            qualification._schema_two_sender_framing_falsification_diagnostic_receipt()
        ),
        "prefix_pack_spec": {
            "path": "cloudflare-quiche-r3.json",
            "sha256": spec_sha256,
        },
        "resource": {
            "resource_id": 0,
            "url": root["url"],
            "headers": headers,
            "request_stream_bytes": 163,
            "expected_response": expected,
            "response_runs": response_runs,
            "response_qualification_sha256": response_digest,
            "prefix_pack_runs": prefix_runs,
            "prefix_pack_qualification_sha256": qualification_digest(
                "qcsd-chaff-prefix-pack-qualification-v2", prefix_runs
            ),
        },
    }


def test_projection_is_exact_existing_ael_in_original_order() -> None:
    manifest = load_json(WORKLOAD)
    root = selected_navigation_root(manifest, "cloudflare-quiche-r3")
    before = copy.deepcopy(root["headers"])

    projected = project_compact_headers(root)

    assert [header[0] for header in projected] == list(HEADER_PROJECTION)
    assert projected == [header for header in before if header[0] in HEADER_PROJECTION]
    assert root["headers"] == before


@pytest.mark.parametrize("mutation", ["missing", "reordered", "synthesized"])
def test_projection_rejects_missing_reordered_or_synthesized_headers(mutation: str) -> None:
    root = selected_navigation_root(load_json(WORKLOAD), "cloudflare-quiche-r3")
    changed = copy.deepcopy(root)
    if mutation == "missing":
        changed["headers"] = [header for header in changed["headers"] if header[0] != "accept"]
    elif mutation == "reordered":
        selected = project_compact_headers(changed)
        remaining = [header for header in changed["headers"] if header not in selected]
        changed["headers"] = [selected[1], selected[0], selected[2], *remaining]
    else:
        for header in changed["headers"]:
            if header[0] == "accept-language":
                header[0] = "x-accept-language"

    with pytest.raises(ValueError, match="exact lowercase accept"):
        project_compact_headers(changed)


def test_prefix_spec_is_an_acyclic_numeric_projection() -> None:
    walkie = load_json(SCHEMA_FIVE_WALKIE)
    original = copy.deepcopy(walkie)

    spec = prefix_pack_spec(
        "cloudflare-quiche-r3",
        walkie,
        source_walkie_talkie_artifact_sha256=sha256_file(SCHEMA_FIVE_WALKIE),
    )

    assert spec["artifact_type"] == qualification.PREFIX_SPEC_ARTIFACT_TYPE
    assert spec["maximum_receiver_continuation_reserve_horizon"] == 3
    assert spec["required_chaff_survivors"] == 4
    assert spec["required_chaff_streams"] == 6
    assert [burst["outgoing"] for burst in spec["numeric_profile"]["bursts"]] == [2, 3, 2]
    assert [
        stage["required_active_chaff_streams"] for stage in spec["stream_activation_stages"]
    ] == [
        4,
        6,
        6,
    ]
    assert "receiver_continuation" not in spec["numeric_profile"]
    assert walkie == original
    assert validate_prefix_pack_spec(spec, workload_id="cloudflare-quiche-r3") == spec

    changed = copy.deepcopy(spec)
    changed["application_resource_id"] = False
    with pytest.raises(ValueError, match="specification binding"):
        validate_prefix_pack_spec(changed, workload_id="cloudflare-quiche-r3")


def test_prefix_spec_numeric_profile_is_bound_to_the_runtime_walkie_talkie_mould() -> None:
    walkie = load_json(SCHEMA_FIVE_WALKIE)
    spec = prefix_pack_spec(
        "cloudflare-quiche-r3",
        walkie,
        source_walkie_talkie_artifact_sha256=sha256_file(SCHEMA_FIVE_WALKIE),
    )

    assert sha256_bytes(canonical_bytes({"profiles": walkie["profiles"]})) == (
        "9f131f80237128c02c53d8dd01253999cc4501621c60c7c9e5d9fb950d35a291"
    )
    _validate_prefix_spec_mould_binding(spec, walkie, "cloudflare-quiche-r3")
    changed = copy.deepcopy(walkie)
    profile = next(
        value
        for value in changed["profiles"]
        if "cloudflare-quiche-r3" in {value["real"], value["decoy"]}
    )
    profile["bursts"][0]["outgoing"] += 1
    with pytest.raises(ValueError, match="differs from Walkie-Talkie mould"):
        _validate_prefix_spec_mould_binding(spec, changed, "cloudflare-quiche-r3")


def test_prefix_spec_accepts_single_adapted_continuation_without_symmetric_base() -> None:
    walkie = {
        "packet_size": 1_200,
        "profiles": [
            {
                "real": "cloudflare-quiche-r3",
                "decoy": "nginx-quic-r3",
                "bursts": [{"outgoing": 1, "incoming": 1}],
            }
        ],
    }

    spec = prefix_pack_spec(
        "cloudflare-quiche-r3",
        walkie,
        source_walkie_talkie_artifact_sha256=qualification.SOURCE_WALKIE_TALKIE_SHA256,
    )

    stage = spec["stream_activation_stages"][0]
    assert stage["exact_target_cells"] == 2
    assert stage["outgoing_cells"] == 2
    assert stage["adapted_incoming_cells"] == 1
    assert stage["symmetric_incoming_cells"] == 0
    assert validate_prefix_pack_spec(spec, workload_id="cloudflare-quiche-r3") == spec
    changed = copy.deepcopy(spec)
    changed["stream_activation_stages"][0]["symmetric_incoming_cells"] = 1
    with pytest.raises(ValueError, match="stage shape"):
        validate_prefix_pack_spec(changed, workload_id="cloudflare-quiche-r3")


def test_prefix_spec_sender_framing_rejects_u32_overflow() -> None:
    walkie = {
        "packet_size": 1_200,
        "profiles": [
            {
                "real": "cloudflare-quiche-r3",
                "decoy": "nginx-quic-r3",
                "bursts": [{"outgoing": 2**32 - 1, "incoming": 1}],
            }
        ],
    }

    with pytest.raises(ValueError, match="sender-framed prefix target exceeds u32"):
        prefix_pack_spec(
            "cloudflare-quiche-r3",
            walkie,
            source_walkie_talkie_artifact_sha256=(qualification.SOURCE_WALKIE_TALKIE_SHA256),
        )


def test_schema_two_capacity_plan_is_exact_for_the_sealed_six_workloads() -> None:
    walkie = load_json(SCHEMA_FIVE_WALKIE)
    sender_framed_targets = {
        "apache-traffic-server-docs-r3": [2, 5, 3],
        "nginx-quic-r3": [2, 5, 3],
        "bootstrap-introduction-r3": [2, 4],
        "getbootstrap-home-r3": [2, 4],
        "cloudflare-quiche-r3": [2, 3, 2],
        "nghttp2-ngtcp2-r3": [2, 3, 2],
    }
    expected = {
        "apache-traffic-server-docs-r3": (
            14,
            184_912,
            4,
            [2_922, 96_657, 512_593],
            [678, 2_943, 2_207],
            [737_770, 733_627, 730_220],
        ),
        "nginx-quic-r3": (
            6,
            26_104,
            20,
            [2_523, 15_794, 90_127],
            [1_077, 83_806, 424_673],
            [102_139, 434_797, 8_924],
        ),
        "bootstrap-introduction-r3": (
            6,
            38_376,
            3,
            [17_109, 120_714],
            [891, 12_486],
            [113_037, 99_351],
        ),
        "getbootstrap-home-r3": (
            7,
            38_376,
            3,
            [17_179, 128_447],
            [821, 4_753],
            [113_107, 107_154],
        ),
        "cloudflare-quiche-r3": (
            0,
            13_390,
            6,
            [13_390, 0, 0],
            [1_010, 55_200, 19_200],
            [51_350, 21_730, 1_330],
        ),
        "nghttp2-ngtcp2-r3": (
            1,
            39_082,
            4,
            [6_324, 54_859, 18_868],
            [8_076, 341, 332],
            [147_052, 145_511, 143_979],
        ),
    }
    for workload_id, (resource_id, body_bytes, required, floors, base, after) in expected.items():
        manifest = load_json(ROOT / "config/workloads" / f"{workload_id}.json")
        spec = prefix_pack_spec(
            workload_id,
            walkie,
            source_walkie_talkie_artifact_sha256=qualification.SOURCE_WALKIE_TALKIE_SHA256,
            application_manifest=manifest,
        )
        stages = spec["stream_activation_stages"]
        assert spec["selected_chaff_resource_id"] == resource_id
        assert spec["selected_chaff_body_bytes"] == body_bytes
        assert spec["required_chaff_streams"] == required
        assert [stage["exact_target_cells"] for stage in stages] == sender_framed_targets[
            workload_id
        ]
        assert [stage["application_body_floor_bytes"] for stage in stages] == floors
        assert [stage["base_chaff_bytes"] for stage in stages] == base
        assert [stage["exact_capacity_after_bytes"] for stage in stages] == after
        assert (
            validate_prefix_pack_spec(spec, workload_id=workload_id, application_manifest=manifest)
            == spec
        )


def test_capacity_never_credits_declared_content_length() -> None:
    manifest = load_json(ROOT / "config/workloads/apache-traffic-server-docs-r3.json")
    assert manifest["resources"][0]["content_length"] == 14_576
    assert manifest["preparation"]["expected_responses"][0]["bytes"] == 2_922
    spec = prefix_pack_spec(
        "apache-traffic-server-docs-r3",
        load_json(SCHEMA_FIVE_WALKIE),
        source_walkie_talkie_artifact_sha256=qualification.SOURCE_WALKIE_TALKIE_SHA256,
        application_manifest=manifest,
    )
    assert spec["stream_activation_stages"][0]["application_body_floor_bytes"] == 2_922


def test_schema_six_file_backed_spec_hash_cannot_rebind_a_different_mould(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workload_root = tmp_path / "workloads"
    sidecar_root = tmp_path / "chaff-qualification-store/v2"
    spec_root = tmp_path / "chaff-prefix-specs/v2"
    workload_root.mkdir()
    sidecar_root.mkdir(parents=True)
    spec_root.parent.mkdir(parents=True)
    specs = derive_prefix_pack_specs(
        source_path=SCHEMA_FIVE_WALKIE,
        destination_root=spec_root,
    )
    records: list[dict[str, object]] = []
    for workload_id in qualification.SEALED_WORKLOAD_IDS:
        application = workload_root / f"{workload_id}.json"
        sidecar = sidecar_root / f"{workload_id}.json"
        shutil.copy2(ROOT / "config/workloads" / application.name, application)
        atomic_json(sidecar, {"workload_id": workload_id})
        spec = spec_root / f"{workload_id}.json"
        records.append(
            {
                "workload_id": workload_id,
                "application_workload_sha256": sha256_file(application),
                "chaff_qualification_sidecar": {
                    "path": f"config/chaff-qualification-store/v2/{workload_id}.json",
                    "sha256": sha256_file(sidecar),
                },
                "prefix_pack_spec": {
                    "path": f"config/chaff-prefix-specs/v2/{workload_id}.json",
                    "sha256": sha256_file(spec),
                },
                "qualified_chaff_manifest_sha256": "d" * 64,
                "application_resource_id": 0,
                "selected_chaff_resource_id": load_json(spec)["selected_chaff_resource_id"],
                "qualified_parallel_chaff_streams": max(
                    5, load_json(spec)["required_chaff_streams"]
                ),
                "walkie_talkie_required_chaff_streams": load_json(spec)["required_chaff_streams"],
            }
        )
    assert len(specs) == 6
    runtime = {
        "role": "runtime-qualification-only-excluded-from-fitting",
        "qualification_bytes_excluded": True,
        "schema_five_diagnostic": qualification._schema_five_diagnostic_receipt(),
        "schema_six_capacity_falsification_diagnostic": (
            qualification._schema_six_capacity_falsification_diagnostic_receipt()
        ),
        "schema_six_runtime_falsification_diagnostic": (
            qualification._schema_six_runtime_falsification_diagnostic_receipt()
        ),
        "schema_two_sender_framing_falsification_diagnostic": (
            qualification._schema_two_sender_framing_falsification_diagnostic_receipt()
        ),
        "workloads": records,
    }
    provenance = {
        "fitting_contract": {"workload_order": list(qualification.SEALED_WORKLOAD_IDS)},
        "runtime_qualification_inputs": runtime,
    }

    def loaded(
        sidecar_path: Path,
        *,
        workload_id: str,
        base_manifest_path: Path,
        **_: object,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            application_manifest_sha256=sha256_file(base_manifest_path),
            sidecar_sha256=sha256_file(sidecar_path),
            manifest_sha256="d" * 64,
            application_resource_id=0,
            selected_chaff_resource_id=load_json(spec_root / f"{workload_id}.json")[
                "selected_chaff_resource_id"
            ],
            qualified_parallel_chaff_streams=max(
                5,
                load_json(spec_root / f"{workload_id}.json")["required_chaff_streams"],
            ),
            walkie_talkie_required_chaff_streams=load_json(spec_root / f"{workload_id}.json")[
                "required_chaff_streams"
            ],
        )

    monkeypatch.setattr(qualification, "load_qualified_chaff", loaded)
    walkie = load_json(SCHEMA_FIVE_WALKIE)
    fitting._validate_schema_six_qualification_evidence(
        provenance,
        walkie_talkie=walkie,
        qualification_inputs_root=tmp_path,
        frozen=False,
    )

    changed_path = spec_root / f"{qualification.SEALED_WORKLOAD_IDS[0]}.json"
    changed = load_json(changed_path)
    changed["numeric_profile"]["bursts"][0]["outgoing"] += 1
    atomic_json(changed_path, changed)
    records[0]["prefix_pack_spec"]["sha256"] = sha256_file(changed_path)
    with pytest.raises(ValueError, match="differs from Walkie-Talkie mould"):
        fitting._validate_schema_six_qualification_evidence(
            provenance,
            walkie_talkie=walkie,
            qualification_inputs_root=tmp_path,
            frozen=False,
        )


def test_prefix_specs_are_create_only_and_cover_exact_sealed_cohort(tmp_path: Path) -> None:
    assert qualification.SCHEMA_FIVE_WALKIE_TALKIE_ARCHIVE == Path(
        "artifacts/research-1200-superseded-schema5-0a141768/walkie-talkie.json"
    )
    assert sha256_file(SCHEMA_FIVE_WALKIE) == qualification.SOURCE_WALKIE_TALKIE_SHA256
    destination = tmp_path / "chaff-prefix-specs"
    paths = derive_prefix_pack_specs(
        destination_root=destination,
    )

    assert [path.stem for path in paths] == [
        "apache-traffic-server-docs-r3",
        "bootstrap-introduction-r3",
        "cloudflare-quiche-r3",
        "getbootstrap-home-r3",
        "nghttp2-ngtcp2-r3",
        "nginx-quic-r3",
    ]
    assert all(
        load_json(path)["source_walkie_talkie_artifact_sha256"]
        == qualification.SOURCE_WALKIE_TALKIE_SHA256
        for path in paths
    )
    with pytest.raises(FileExistsError, match="create-only"):
        derive_prefix_pack_specs(
            destination_root=destination,
        )


def test_prefix_specs_refuse_even_an_empty_destination_directory(tmp_path: Path) -> None:
    destination = tmp_path / "chaff-prefix-specs"
    destination.mkdir()

    with pytest.raises(FileExistsError, match="create-only"):
        derive_prefix_pack_specs(
            source_path=SCHEMA_FIVE_WALKIE,
            destination_root=destination,
        )
    assert list(destination.iterdir()) == []


def test_prefix_specs_never_publish_a_partial_directory_on_promotion_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "chaff-prefix-specs"
    monkeypatch.setattr(
        qualification,
        "_rename_noreplace",
        lambda *_: (_ for _ in ()).throw(RuntimeError("synthetic promotion failure")),
    )

    with pytest.raises(RuntimeError, match="synthetic promotion failure"):
        derive_prefix_pack_specs(
            source_path=SCHEMA_FIVE_WALKIE,
            destination_root=destination,
        )
    assert not destination.exists()
    assert not list(tmp_path.glob(".chaff-prefix-specs.qcsd-prefix-specs-*"))


def test_prefix_specs_parse_the_same_source_bytes_they_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "walkie-talkie.json"
    source.write_bytes((SCHEMA_FIVE_WALKIE).read_bytes())
    destination = tmp_path / "chaff-prefix-specs"
    original_read_bytes = Path.read_bytes
    source_reads = 0

    def replace_after_read(path: Path) -> bytes:
        nonlocal source_reads
        value = original_read_bytes(path)
        if path == source:
            source_reads += 1
            path.write_bytes(b'{"schema_version":0}\n')
        return value

    monkeypatch.setattr(Path, "read_bytes", replace_after_read)
    paths = derive_prefix_pack_specs(source_path=source, destination_root=destination)

    assert source_reads == 1
    assert len(paths) == len(qualification.SEALED_WORKLOAD_IDS)
    assert all(
        load_json(path)["source_walkie_talkie_artifact_sha256"]
        == qualification.SOURCE_WALKIE_TALKIE_SHA256
        for path in paths
    )


@pytest.mark.parametrize("linked", ["source", "destination-parent"])
def test_prefix_specs_reject_symlinked_path_components(tmp_path: Path, linked: str) -> None:
    source = SCHEMA_FIVE_WALKIE
    destination = tmp_path / "config/chaff-prefix-specs"
    destination.parent.mkdir()
    if linked == "source":
        source_link = tmp_path / "walkie-talkie.json"
        source_link.symlink_to(source)
        source = source_link
    else:
        real_parent = tmp_path / "real-config"
        real_parent.mkdir()
        destination.parent.rmdir()
        destination.parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="symbolic link|regular file"):
        derive_prefix_pack_specs(source_path=source, destination_root=destination)
    assert not destination.exists()


def _write_prefix_spec(tmp_path: Path) -> Path:
    walkie = load_json(SCHEMA_FIVE_WALKIE)
    spec = prefix_pack_spec(
        "cloudflare-quiche-r3",
        walkie,
        source_walkie_talkie_artifact_sha256=sha256_file(SCHEMA_FIVE_WALKIE),
    )
    path = tmp_path / "cloudflare-quiche-r3.json"
    atomic_json(path, spec)
    return path


def test_sidecar_derives_one_distinct_root_without_changing_application_headers(
    tmp_path: Path,
) -> None:
    prefix_path = _write_prefix_spec(tmp_path)
    sidecar = _sidecar(prefix_path)
    application = load_json(WORKLOAD)
    before = copy.deepcopy(application)

    validated = validate_sidecar(
        sidecar,
        workload_id="cloudflare-quiche-r3",
        base_manifest_path=WORKLOAD,
        prefix_spec_path=prefix_path,
        require_current_implementation=False,
    )
    chaff = validated.manifest

    assert application == before
    assert chaff["artifact_type"] == qualification.MANIFEST_ARTIFACT_TYPE
    assert chaff["application_workload_sha256"] == sha256_file(WORKLOAD)
    assert chaff["application_resource_id"] == 0
    assert len(chaff["resources"]) == 1
    resource = chaff["resources"][0]
    assert resource["headers"] == project_compact_headers(application["resources"][0])
    assert resource["headers"] != application["resources"][0]["headers"]
    assert resource["content_length"] == resource["data_length"] == 13_390
    assert resource["chaff_qualification"]["request_stream_bytes"] == 163
    assert resource["chaff_qualification"]["prefix_spec_sha256"] == sha256_file(prefix_path)


def test_prefix_receipt_allows_sub_ceiling_ack_or_control_datagram(tmp_path: Path) -> None:
    prefix_path = _write_prefix_spec(tmp_path)
    sidecar = _sidecar(prefix_path)
    receipt = sidecar["resource"]["prefix_pack_runs"][0]["receipt"]
    assert any(
        observation["phase"] == "qualification"
        and observation["direction"] == "outgoing"
        and observation["udp_payload_bytes"] < 1_200
        for observation in receipt["packet_observations"]
    )

    validate_sidecar(
        sidecar,
        workload_id="cloudflare-quiche-r3",
        base_manifest_path=WORKLOAD,
        prefix_spec_path=prefix_path,
        require_current_implementation=False,
    )


def test_sidecar_rejects_base_manifest_hash_mismatch(tmp_path: Path) -> None:
    changed = tmp_path / WORKLOAD.name
    changed.write_bytes(WORKLOAD.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="base manifest SHA-256 mismatch"):
        validate_sidecar(
            _sidecar(_write_prefix_spec(tmp_path)),
            workload_id="cloudflare-quiche-r3",
            base_manifest_path=changed,
            prefix_spec_path=tmp_path / "cloudflare-quiche-r3.json",
            require_current_implementation=False,
        )


def test_sidecar_rejects_boolean_schema_six_capacity_diagnostic_integer(tmp_path: Path) -> None:
    prefix_path = _write_prefix_spec(tmp_path)
    sidecar = _sidecar(prefix_path)
    sidecar["schema_six_capacity_falsification_diagnostic"]["failed"] = True

    with pytest.raises(ValueError, match="schema-six capacity falsification diagnostic"):
        validate_sidecar(
            sidecar,
            workload_id="cloudflare-quiche-r3",
            base_manifest_path=WORKLOAD,
            prefix_spec_path=prefix_path,
            require_current_implementation=False,
        )


def test_sidecar_binds_exact_schema_six_runtime_falsification_archive(tmp_path: Path) -> None:
    prefix_path = _write_prefix_spec(tmp_path)
    sidecar = _sidecar(prefix_path)
    diagnostic = sidecar["schema_six_runtime_falsification_diagnostic"]

    assert diagnostic == qualification._schema_six_runtime_falsification_diagnostic_receipt()
    assert diagnostic["archive_manifest_sha256"] == (
        "4ee68a930a344dc0e5874279e09069f92935a2f4f42bc7bb7e88077153b85aa9"
    )
    assert (
        diagnostic["planned"],
        diagnostic["accepted"],
        diagnostic["eligible"],
        diagnostic["failed"],
    ) == (14, 12, 12, 2)
    assert diagnostic["terminal_failures"] == [
        {
            "workload_id": "cloudflare-quiche-r3",
            "defense": "walkie-talkie",
            "stage": "runner",
            "attempts": 3,
        },
        {
            "workload_id": "bootstrap-introduction-r3",
            "defense": "front",
            "stage": "capture",
            "attempts": 3,
        },
    ]
    assert diagnostic["recovered_retries"] == [
        {
            "workload_id": "bootstrap-introduction-r3",
            "defense": "walkie-talkie",
            "failed_attempts": 2,
            "accepted_attempt": 3,
        },
        {
            "workload_id": "bootstrap-introduction-r3",
            "defense": "traffic-morphing",
            "failed_attempts": 1,
            "accepted_attempt": 2,
        },
    ]

    diagnostic["terminal_failures"][0]["attempts"] = True
    with pytest.raises(ValueError, match="schema-six runtime falsification diagnostic"):
        validate_sidecar(
            sidecar,
            workload_id="cloudflare-quiche-r3",
            base_manifest_path=WORKLOAD,
            prefix_spec_path=prefix_path,
            require_current_implementation=False,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [("failed_run_index", False), ("qualification_bytes_excluded", 1)],
)
def test_sidecar_binds_and_rejects_sender_framing_diagnostic_boolean_tampering(
    tmp_path: Path, field: str, value: object
) -> None:
    prefix_path = _write_prefix_spec(tmp_path)
    sidecar = _sidecar(prefix_path)
    diagnostic = sidecar["schema_two_sender_framing_falsification_diagnostic"]
    assert diagnostic == qualification._schema_two_sender_framing_falsification_diagnostic_receipt()
    assert diagnostic["archive_manifest_sha256"] == (
        "c40d4d9e629d701438ca93b232eb7173814b9e1cec79314e49477e9329076b73"
    )
    assert diagnostic["receipt_sha256"] == (
        "6ee69445b84db197c6602a02f6c91d566d28087aa33f36f1d27df5e7b748d354"
    )
    assert diagnostic["packets_sha256"] == (
        "1b18dd574295061115a55b6c31045fd557aa137d7768f1149e9931e594e093c1"
    )
    assert diagnostic["log_sha256"] == (
        "4de19185892585e194779c35c8125300588f178bc5f80fda02f5749523269b09"
    )
    diagnostic[field] = value

    with pytest.raises(ValueError, match="schema-two sender-framing falsification diagnostic"):
        validate_sidecar(
            sidecar,
            workload_id="cloudflare-quiche-r3",
            base_manifest_path=WORKLOAD,
            prefix_spec_path=prefix_path,
            require_current_implementation=False,
        )


def test_sidecar_rejects_boolean_application_resource_id(tmp_path: Path) -> None:
    prefix_path = _write_prefix_spec(tmp_path)
    sidecar = _sidecar(prefix_path)
    sidecar["application_resource_id"] = False

    with pytest.raises(ValueError, match="sidecar policy binding"):
        validate_sidecar(
            sidecar,
            workload_id="cloudflare-quiche-r3",
            base_manifest_path=WORKLOAD,
            prefix_spec_path=prefix_path,
            require_current_implementation=False,
        )


def test_qualify_chaff_refuses_existing_destination_before_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workloads = tmp_path / "workloads"
    qualifications = tmp_path / "qualifications"
    specs = tmp_path / "specs"
    workloads.mkdir()
    qualifications.mkdir()
    specs.mkdir()
    (workloads / WORKLOAD.name).write_bytes(WORKLOAD.read_bytes())
    atomic_json(specs / WORKLOAD.name, {"not": "consulted"})
    destination = qualifications / WORKLOAD.name
    destination.write_text("existing\n", encoding="utf-8")
    called = False

    def network(*args: object, **kwargs: object) -> list[dict[str, object]]:
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(qualification, "_run_response_qualifications", network)
    with pytest.raises(FileExistsError, match="create-only"):
        qualification.qualify_chaff(
            "cloudflare-quiche-r3",
            workload_root=workloads,
            qualification_root=qualifications,
            prefix_spec_root=specs,
        )
    assert called is False
    assert destination.read_text(encoding="utf-8") == "existing\n"


def test_failed_qualification_retains_raw_receipt_and_log_in_unpublished_workdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workloads = tmp_path / "workloads"
    qualifications = tmp_path / "candidate"
    specs = tmp_path / "specs"
    workloads.mkdir()
    qualifications.mkdir()
    specs.mkdir()
    (workloads / WORKLOAD.name).write_bytes(WORKLOAD.read_bytes())
    prefix = _write_prefix_spec(specs)

    def fail_with_evidence(
        application_path: Path,
        directory: Path,
        **_: object,
    ) -> list[dict[str, object]]:
        assert application_path == workloads / WORKLOAD.name
        output = directory / "response-0"
        output.mkdir()
        atomic_json(output / "qualification.json", {"passed": False})
        (directory / "response-0.log").write_text("response_limit\n", encoding="utf-8")
        raise qualification.PreparationError("synthetic response limit")

    monkeypatch.setattr(qualification, "_run_response_qualifications", fail_with_evidence)
    execution_context = _test_execution_context(tmp_path)
    with pytest.raises(qualification.PreparationError, match="response limit"):
        qualification.qualify_chaff(
            "cloudflare-quiche-r3",
            workload_root=workloads,
            qualification_root=qualifications,
            prefix_spec_root=specs,
            interval_seconds=0,
            _execution_context=execution_context,
        )

    assert prefix.is_file()
    assert not (qualifications / WORKLOAD.name).exists()
    evidence = list(qualifications.glob(".cloudflare-quiche-r3-qualification-evidence-*"))
    assert len(evidence) == 1
    assert load_json(evidence[0] / "response-0/qualification.json") == {"passed": False}
    assert (evidence[0] / "response-0.log").read_text() == "response_limit\n"


def test_derived_manifest_has_no_application_preparation_metadata() -> None:
    sidecar = _sidecar()
    root = selected_navigation_root(load_json(WORKLOAD), "cloudflare-quiche-r3")
    derived = derive_chaff_manifest(sidecar, root)

    assert set(derived) == {
        "schema_version",
        "artifact_type",
        "application_workload_sha256",
        "application_resource_id",
        "selected_chaff_resource_id",
        "qualified_parallel_chaff_streams",
        "walkie_talkie_required_chaff_streams",
        "resources",
    }
    assert "preparation" not in derived


def _batch_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    workloads = tmp_path / "workloads"
    specs = tmp_path / "specs"
    store = tmp_path / "store"
    workloads.mkdir()
    store.mkdir()
    for workload_id in qualification.SEALED_WORKLOAD_IDS:
        source = ROOT / "config/workloads" / f"{workload_id}.json"
        (workloads / source.name).write_bytes(source.read_bytes())
    derive_prefix_pack_specs(
        source_path=SCHEMA_FIVE_WALKIE,
        destination_root=specs,
    )
    return workloads, specs, store


def _test_execution_context(
    tmp_path: Path,
) -> tuple[dict[str, object], dict[str, object], str]:
    client = tmp_path / "neqo-qcsd-client"
    client.write_bytes(b"test-bound-neqo-client\n")
    client.chmod(0o755)
    return (
        {
            "neqo_qcsd_client": {
                "path": str(client.resolve()),
                "sha256": sha256_file(client),
            }
        },
        {},
        "test",
    )


def test_qualification_runners_execute_only_the_bound_image_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    implementation, _, _ = _test_execution_context(tmp_path)
    bound, digest = qualification._bound_neqo_client(implementation)
    unbound = tmp_path / "unbound-client"
    unbound.write_bytes(b"must-not-run\n")
    unbound.chmod(0o755)
    monkeypatch.setenv("QCSD_NEQO_CLIENT", str(unbound))
    commands: list[list[str]] = []

    def run_client(command: list[str], **_: object) -> SimpleNamespace:
        commands.append(command)
        output = Path(command[command.index("--output-dir") + 1])
        output.mkdir()
        atomic_json(output / "qualification.json", {"run": len(commands)})
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(qualification, "_run_neqo", run_client)
    (tmp_path / "response-runs").mkdir()
    response = qualification._run_response_qualifications(
        WORKLOAD,
        tmp_path / "response-runs",
        neqo_client=bound,
        neqo_client_sha256=digest,
        selected_chaff_resource_id=0,
        qualified_parallel_chaff_streams=6,
        timeout_seconds=30,
        interval_seconds=0,
    )
    (tmp_path / "prefix-runs").mkdir()
    prefix = qualification._run_prefix_qualifications(
        WORKLOAD,
        WORKLOAD,
        WORKLOAD,
        WORKLOAD,
        tmp_path / "prefix-runs",
        neqo_client=bound,
        neqo_client_sha256=digest,
        timeout_seconds=30,
        interval_seconds=0,
    )

    assert len(response) == len(prefix) == qualification.QUALIFICATION_RUNS
    assert {command[0] for command in commands} == {str(bound)}
    assert str(unbound) not in {item for command in commands for item in command}


def test_bound_qualification_client_is_rehashed_before_execution(tmp_path: Path) -> None:
    implementation, _, _ = _test_execution_context(tmp_path)
    bound, digest = qualification._bound_neqo_client(implementation)
    bound.write_bytes(b"changed-after-receipt\n")

    with pytest.raises(ValueError, match="changed before execution"):
        qualification._recheck_bound_neqo_client(bound, digest)


def _fake_qualification(
    workload_id: str,
    *,
    qualification_root: Path,
    **_: object,
) -> QualifiedChaffOutput:
    path = qualification_root / f"{workload_id}.json"
    atomic_json(path, {"workload_id": workload_id})
    return QualifiedChaffOutput(path, sha256_file(path), "f" * 64)


def test_batch_qualification_publishes_exact_six_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workloads, specs, store = _batch_inputs(tmp_path)
    monkeypatch.setattr(qualification, "qualify_chaff", _fake_qualification)
    execution_context = _test_execution_context(tmp_path)
    monkeypatch.setattr(
        qualification, "_qualification_execution_context", lambda: execution_context
    )

    outputs = qualification.qualify_all_chaff(
        workload_root=workloads,
        prefix_spec_root=specs,
        qualification_store=store,
        interval_seconds=0,
    )

    expected = sorted(f"{item}.json" for item in qualification.SEALED_WORKLOAD_IDS)
    assert sorted(path.name for path in (store / "v2").iterdir()) == expected
    assert [output.path.parent for output in outputs] == [store / "v2"] * 6
    assert not list(store.glob(".v2.qcsd-batch-*"))


def test_batch_qualification_refuses_existing_v2_before_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = tmp_path / "store"
    (store / "v2").mkdir(parents=True)
    called = False

    def network(*args: object, **kwargs: object) -> QualifiedChaffOutput:
        nonlocal called
        called = True
        raise AssertionError

    monkeypatch.setattr(qualification, "qualify_chaff", network)
    with pytest.raises(FileExistsError, match="create-only"):
        qualification.qualify_all_chaff(qualification_store=store)
    assert called is False


def test_batch_rederives_specs_from_sealed_schema_five_before_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workloads, specs, store = _batch_inputs(tmp_path)
    workload_id = qualification.SEALED_WORKLOAD_IDS[0]
    path = specs / f"{workload_id}.json"
    changed = load_json(path)
    changed["numeric_profile"]["bursts"][0]["outgoing"] += 1
    changed["stream_activation_stages"][0]["exact_target_cells"] += 1
    changed["stream_activation_stages"][0]["outgoing_cells"] += 1
    changed["numeric_profile_sha256"] = sha256_bytes(
        b"qcsd-walkie-talkie-numeric-profile-v1\0"
        + json.dumps(changed["numeric_profile"], sort_keys=True, separators=(",", ":")).encode()
    )
    horizon = qualification._maximum_receiver_continuation_reserve_horizon(
        changed["numeric_profile"]["bursts"]
    )
    changed["maximum_receiver_continuation_reserve_horizon"] = horizon
    changed["required_chaff_survivors"] = horizon + 1
    atomic_json(path, changed)
    validate_prefix_pack_spec(load_json(path), workload_id=workload_id)
    called = False

    def network(*args: object, **kwargs: object) -> QualifiedChaffOutput:
        nonlocal called
        called = True
        raise AssertionError

    monkeypatch.setattr(qualification, "qualify_chaff", network)
    with pytest.raises(ValueError, match="differs from the sealed schema-five numeric oracle"):
        qualification.qualify_all_chaff(
            workload_root=workloads,
            prefix_spec_root=specs,
            qualification_store=store,
        )
    assert called is False
    assert not (store / "v2").exists()


@pytest.mark.parametrize("linked_root", ["workloads", "specs"])
def test_batch_qualification_rejects_symlinked_input_directories_before_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, linked_root: str
) -> None:
    workloads, specs, store = _batch_inputs(tmp_path)
    selected = workloads if linked_root == "workloads" else specs
    external = tmp_path / f"external-{linked_root}"
    selected.rename(external)
    selected.symlink_to(external, target_is_directory=True)
    called = False

    def network(*args: object, **kwargs: object) -> QualifiedChaffOutput:
        nonlocal called
        called = True
        raise AssertionError

    monkeypatch.setattr(qualification, "qualify_chaff", network)
    with pytest.raises(ValueError, match="contains a symbolic link"):
        qualification.qualify_all_chaff(
            workload_root=workloads,
            prefix_spec_root=specs,
            qualification_store=store,
        )
    assert called is False
    assert not (store / "v2").exists()


def test_batch_qualification_failure_never_publishes_partial_v2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workloads, specs, store = _batch_inputs(tmp_path)
    calls = 0
    monkeypatch.setattr(qualification, "_qualification_execution_context", lambda: ({}, {}, "test"))

    def fail_third(
        workload_id: str, *, qualification_root: Path, **kwargs: object
    ) -> QualifiedChaffOutput:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise RuntimeError("synthetic qualification failure")
        return _fake_qualification(workload_id, qualification_root=qualification_root, **kwargs)

    monkeypatch.setattr(qualification, "qualify_chaff", fail_third)
    with pytest.raises(RuntimeError, match="synthetic"):
        qualification.qualify_all_chaff(
            workload_root=workloads,
            prefix_spec_root=specs,
            qualification_store=store,
            interval_seconds=0,
        )
    assert not (store / "v2").exists()
    assert len(list(store.glob(".v2.qcsd-batch-*"))) == 1


def test_batch_qualification_rechecks_all_inputs_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workloads, specs, store = _batch_inputs(tmp_path)
    execution_context = _test_execution_context(tmp_path)
    monkeypatch.setattr(
        qualification, "_qualification_execution_context", lambda: execution_context
    )
    calls = 0

    def mutate_after_preflight(
        workload_id: str, *, qualification_root: Path, **kwargs: object
    ) -> QualifiedChaffOutput:
        nonlocal calls
        calls += 1
        output = _fake_qualification(workload_id, qualification_root=qualification_root, **kwargs)
        if calls == len(qualification.SEALED_WORKLOAD_IDS):
            target = specs / f"{qualification.SEALED_WORKLOAD_IDS[0]}.json"
            target.write_bytes(target.read_bytes() + b" ")
        return output

    monkeypatch.setattr(qualification, "qualify_chaff", mutate_after_preflight)
    with pytest.raises(ValueError, match="input changed before publication"):
        qualification.qualify_all_chaff(
            workload_root=workloads,
            prefix_spec_root=specs,
            qualification_store=store,
            interval_seconds=0,
        )

    assert not (store / "v2").exists()
    assert len(list(store.glob(".v2.qcsd-batch-*"))) == 1


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (
            lambda receipt: receipt["streams"][1].update({"transmitted_unique_ranges": [[0, 162]]}),
            "transmitted STREAM aggregate",
        ),
        (
            lambda receipt: receipt.update({"prefix_pack_spec_sha256": "0" * 64}),
            "receipt binding",
        ),
        (
            lambda receipt: receipt["stream_transmissions"][0].update({"slot": None}),
            "invalid STREAM data",
        ),
        (
            lambda receipt: receipt.update({"selected_chaff_resource_id": 6}),
            "receipt binding",
        ),
    ],
)
def test_sidecar_rederives_prefix_proof_instead_of_trusting_passed(
    tmp_path: Path,
    mutate: object,
    match: str,
) -> None:
    prefix_path = _write_prefix_spec(tmp_path)
    sidecar = _sidecar(prefix_path)
    record = sidecar["resource"]["prefix_pack_runs"][0]
    mutate(record["receipt"])
    record["receipt_object_sha256"] = qualification_digest(
        "qcsd-chaff-prefix-pack-receipt-object-v2", [record["receipt"]]
    )
    runs = sidecar["resource"]["prefix_pack_runs"]
    sidecar["resource"]["prefix_pack_qualification_sha256"] = qualification_digest(
        "qcsd-chaff-prefix-pack-qualification-v2", runs
    )

    with pytest.raises(ValueError, match=match):
        validate_sidecar(
            sidecar,
            workload_id="cloudflare-quiche-r3",
            base_manifest_path=WORKLOAD,
            prefix_spec_path=prefix_path,
            require_current_implementation=False,
        )
