from __future__ import annotations

from collections.abc import Iterator
from collections import Counter
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from qcsd_lab import chaff_qualification
import qcsd_lab.orchestrator as orchestrator
from qcsd_lab.util import atomic_json, load_json, sha256_bytes, sha256_file
from tools import classifier_handoff


ROOT = Path(__file__).parents[1]
SOURCE = {
    "image_digest": "sha256:" + "1" * 64,
    "lab_commit": "2" * 40,
    "lab_dirty": False,
    "lab_patch_sha256": classifier_handoff.EMPTY_SHA256,
    "neqo_commit": "3" * 40,
    "neqo_dirty": False,
    "neqo_patch_sha256": classifier_handoff.EMPTY_SHA256,
    "neqo_pinned_commit": "3" * 40,
}
EXPORTER_SOURCE = {
    "execution_image": dict(SOURCE),
    "companion": {
        "lab_commit": SOURCE["lab_commit"],
        "lab_dirty": False,
    },
}
EXPECTED_POC5_CLASSES = (
    "getbootstrap-home-r3",
    "cloudflare-quiche-r3",
    "hyper-basic-client-r1",
    "serde-home-r1",
    "rfc9114-text-r1",
)
EXPECTED_POC5_CLASS_LABELS = {
    "getbootstrap-home-r3": "getbootstrap.com",
    "cloudflare-quiche-r3": "cloudflare-quic.com",
    "hyper-basic-client-r1": "hyper.rs",
    "serde-home-r1": "serde.rs",
    "rfc9114-text-r1": "www.rfc-editor.org",
}
LEGACY_PILOT_CLASSES = (
    "getbootstrap-home-r3",
    "bootstrap-introduction-r3",
    "apache-traffic-server-docs-r3",
    "nginx-quic-r3",
    "cloudflare-quiche-r3",
    "nghttp2-ngtcp2-r3",
)


def _packet_log(observations: list[dict[str, object]]) -> str:
    encoded = json.dumps(observations, separators=(",", ":")).encode()
    return sha256_bytes(encoded)


def _packet_statistics(
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


def _synthetic_response_v2_receipt(
    *,
    epoch_index: int,
    candidate: dict[str, object],
    application_sha256: str,
    neqo_provenance: dict[str, object],
) -> dict[str, object]:
    """Build one exact schema-three sustained identity receipt without I/O."""

    headers = chaff_qualification.project_identity_chaff_headers(candidate)
    observations: list[dict[str, object]] = [
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
            "udp_payload_bytes": 1_200,
        },
    ]
    request_stream_bytes = 151
    response = (200, "identity", 6_500, "6" * 64)
    spacing_ns = chaff_qualification.RESPONSE_ONLY_EPOCH_SPACING_SECONDS * 10**9
    started = epoch_index * (spacing_ns + 100)
    receipt_source = {
        key: neqo_provenance[key]
        for key in chaff_qualification.NEQO_PROVENANCE_KEYS
        if key != "neqo_version"
    }
    return {
        "schema_version": (chaff_qualification.RESPONSE_QUALIFICATION_V2_RECEIPT_SCHEMA_VERSION),
        "artifact_type": chaff_qualification.RESPONSE_ARTIFACT_TYPE,
        "invocation_id": f"synthetic-response-v2-{candidate['id']}-{epoch_index}",
        "neqo_version": neqo_provenance["neqo_version"],
        "application_workload_sha256": application_sha256,
        "application_resource_id": 0,
        "selected_chaff_resource_id": candidate["id"],
        "qualified_parallel_chaff_streams": (
            chaff_qualification.RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        ),
        "method": "GET",
        "url": candidate["url"],
        "request_headers": headers,
        "request_header_mode": chaff_qualification.IDENTITY_REQUEST_HEADER_MODE,
        "parallel_requests": chaff_qualification.RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
        "total_requests": chaff_qualification.RESPONSE_ONLY_REQUESTS_PER_EPOCH,
        "request_waves": chaff_qualification.RESPONSE_ONLY_WAVES_PER_EPOCH,
        "max_concurrent_requests": (chaff_qualification.RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS),
        "connection_count": 1,
        "requests_opened_before_first_network_output": (
            chaff_qualification.RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        ),
        "request_stream_bytes": request_stream_bytes,
        "max_response_bytes": 1_048_576,
        "udp_payload_ceiling": chaff_qualification.UDP_PAYLOAD_CEILING,
        "started_unix_ns": started,
        "ended_unix_ns": started + 100,
        "completion_status": "complete",
        "error": None,
        "failure_class": None,
        "source": receipt_source,
        "requests": [
            {
                "request_index": request_index,
                "wave_index": (
                    request_index // chaff_qualification.RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
                ),
                "stream_id": request_index * 4,
                "request_stream_bytes": request_stream_bytes,
                "status": response[0],
                "content_encoding": response[1],
                "body_bytes": response[2],
                "body_sha256": response[3],
                "complete": True,
                "outcome": "complete",
            }
            for request_index in range(chaff_qualification.RESPONSE_ONLY_REQUESTS_PER_EPOCH)
        ],
        "packet_observations": observations,
        "packet_log_sha256": _packet_log(observations),
        "packets": _packet_statistics(observations),
        "passed": True,
    }


@lru_cache(maxsize=len(EXPECTED_POC5_CLASSES))
def _synthetic_response_only_v2_sidecar(workload_id: str) -> dict:
    """Build validator-complete v2/schema-four evidence without live sidecars."""

    workload_path = ROOT / f"config/workloads/{workload_id}.json"
    workload = load_json(workload_path)
    candidate, prepared = chaff_qualification.response_only_candidate_resources(
        workload, workload_id
    )[0]
    historical = load_json(
        ROOT / f"config/chaff-response-qualification-store/v1/{workload_id}.json"
    )
    neqo_provenance = deepcopy(historical["neqo_provenance"])
    application_sha256 = sha256_file(workload_path)
    epochs = [
        (
            0,
            _synthetic_response_v2_receipt(
                epoch_index=epoch_index,
                candidate=candidate,
                application_sha256=application_sha256,
                neqo_provenance=neqo_provenance,
            ),
        )
        for epoch_index in range(chaff_qualification.QUALIFICATION_RUNS)
    ]
    attempt, expected_response, request_stream_bytes = (
        chaff_qualification._candidate_attempt_record_v2(
            candidate_index=0,
            base_resource=candidate,
            prepared_response=prepared,
            epochs=epochs,
            application_manifest_sha256=application_sha256,
            application_resource_id=0,
            neqo_provenance=neqo_provenance,
        )
    )
    assert expected_response is not None
    sidecar = {
        "schema_version": chaff_qualification.RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION,
        "artifact_type": chaff_qualification.RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE,
        "qualification_scope": chaff_qualification.RESPONSE_ONLY_QUALIFICATION_SCOPE,
        "workload_id": workload_id,
        "base_manifest": {"path": workload_path.name, "sha256": application_sha256},
        "selection_policy": chaff_qualification.RESPONSE_ONLY_V2_SELECTION_POLICY,
        "application_resource_id": 0,
        "selected_chaff_resource_id": candidate["id"],
        "qualified_parallel_chaff_streams": (
            chaff_qualification.RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        ),
        "request_header_primitive": (chaff_qualification.response_only_request_header_primitive()),
        "method": "GET",
        "qualification_policy": chaff_qualification.response_only_v2_qualification_policy(),
        "qualification_source": deepcopy(historical["qualification_source"]),
        "qualification_image_digest": historical["qualification_image_digest"],
        "neqo_provenance": neqo_provenance,
        "implementation_receipt": deepcopy(historical["implementation_receipt"]),
        "candidate_attempts": [attempt],
        "resource": {
            "resource_id": candidate["id"],
            "url": candidate["url"],
            "headers": chaff_qualification.project_identity_chaff_headers(candidate),
            "request_stream_bytes": request_stream_bytes,
            "expected_response": expected_response,
            "response_qualification_sha256": attempt["response_qualification_sha256"],
        },
    }
    chaff_qualification.validate_response_only_sidecar(
        sidecar,
        workload_id=workload_id,
        base_manifest_path=workload_path,
        require_current_implementation=False,
        expected_sidecar_schema_version=2,
    )
    return sidecar


@pytest.fixture(autouse=True)
def _poc5_qualification_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    lab_root = tmp_path / "poc5-lab"
    campaigns = lab_root / "config/campaigns"
    workloads = lab_root / "config/workloads"
    qualifications = lab_root / "config/chaff-response-qualification-store/v2"
    campaigns.mkdir(parents=True)
    workloads.mkdir()
    qualifications.mkdir(parents=True)
    for campaign_file in (
        *classifier_handoff.POC5_CAMPAIGN_FILES,
        "classifier-poc5-rehearsal.yml",
    ):
        source = ROOT / "config/campaigns" / campaign_file
        (campaigns / campaign_file).write_bytes(source.read_bytes())
    sidecars = []
    for workload_id in classifier_handoff.POC5_CLASSES:
        source = ROOT / "config/workloads" / f"{workload_id}.json"
        (workloads / source.name).write_bytes(source.read_bytes())
        destination = qualifications / f"{workload_id}.json"
        sidecar = deepcopy(_synthetic_response_only_v2_sidecar(workload_id))
        atomic_json(destination, sidecar)
        sidecars.append(sidecar)
    receipt = sidecars[0]["implementation_receipt"]
    assert all(sidecar["implementation_receipt"] == receipt for sidecar in sidecars)
    qualification_source = sidecars[0]["qualification_source"]
    assert all(sidecar["qualification_source"] == qualification_source for sidecar in sidecars)
    monkeypatch.setattr(
        chaff_qualification,
        "implementation_receipt",
        lambda *_args, **_kwargs: receipt,
    )
    monkeypatch.setattr(
        chaff_qualification,
        "_implementation_source_files",
        lambda *_args, **_kwargs: receipt["source_files"],
    )
    monkeypatch.setattr(
        chaff_qualification,
        "source_metadata",
        lambda: deepcopy(qualification_source),
    )
    monkeypatch.setenv("QCSD_HANDOFF_LAB_ROOT", str(lab_root))
    classifier_handoff._cached_poc5_configuration.cache_clear()
    yield
    classifier_handoff._cached_poc5_configuration.cache_clear()


def _poc5_receipts() -> list[SimpleNamespace]:
    receipts: list[SimpleNamespace] = []
    for result_index, (name, campaign_file) in enumerate(
        zip(
            classifier_handoff.POC5_RESULT_NAMES,
            classifier_handoff.POC5_CAMPAIGN_FILES,
            strict=True,
        )
    ):
        baseline_result = result_index % 2 == 0
        acquisition_block = result_index // 2
        day = acquisition_block + 1
        baseline_first = acquisition_block % 2 == 0
        hour = 0 if baseline_result == baseline_first else 1
        campaign_path = classifier_handoff._lab_root() / "config/campaigns" / campaign_file
        campaign, configuration = classifier_handoff._expected_poc5_configuration(campaign_path)
        samples = classifier_handoff.plan_campaign(campaign)
        receipts.append(
            SimpleNamespace(
                experiment={
                    "name": name,
                    "purpose": "evaluation",
                    "started_at": f"2026-08-{day:02d}T{hour:02d}:00:00+00:00",
                    "completed_at": f"2026-08-{day:02d}T{hour:02d}:30:00+00:00",
                    "source": dict(SOURCE),
                    "samples": samples,
                    "execution_order": [sample["sample_id"] for sample in samples],
                    "configuration": deepcopy(configuration),
                }
            )
        )
    return receipts


def _poc5_export_metadata() -> tuple[dict, list[dict]]:
    blocks = []
    rows = []
    for result_index, name in enumerate(classifier_handoff.POC5_RESULT_NAMES):
        acquisition_block = result_index // 2
        temporal_split = classifier_handoff.POC5_TEMPORAL_SPLITS[acquisition_block]
        baseline_result = result_index % 2 == 0
        policy = (
            {"undefended": temporal_split}
            if baseline_result
            else {
                "front": "inference",
                "tamaraw": "inference",
                "undefended": temporal_split,
            }
        )
        block_id = f"block-{result_index + 1:03d}"
        acquisition_block_id = f"acquisition-block-{acquisition_block + 1:03d}"
        day = acquisition_block + 1
        baseline_first = acquisition_block % 2 == 0
        hour = 0 if baseline_result == baseline_first else 1
        blocks.append(
            {
                "result_name": name,
                "split": None,
                "sample_splits": policy,
                "acquisition_block_index": acquisition_block,
                "acquisition_block_id": acquisition_block_id,
                "started_at": f"2026-08-{day:02d}T{hour:02d}:00:00+00:00",
                "completed_at": f"2026-08-{day:02d}T{hour:02d}:30:00+00:00",
                "source": dict(SOURCE),
            }
        )
        defenses = ("undefended",) if baseline_result else classifier_handoff.POC5_DEFENSES
        visits = range(20) if baseline_result else range(10)
        for workload_id in classifier_handoff.POC5_CLASSES:
            for defense in defenses:
                runtime_kind, baseline = classifier_handoff.POC5_RUNTIME[defense]
                for visit in visits:
                    rows.append(
                        {
                            "block_index": result_index,
                            "block_id": block_id,
                            "acquisition_block_index": acquisition_block,
                            "acquisition_block_id": acquisition_block_id,
                            "workload_id": workload_id,
                            "class_label": classifier_handoff.POC5_CLASS_LABELS[workload_id],
                            "defense": defense,
                            "defense_role": "baseline" if baseline else "inference-only",
                            "runtime_kind": runtime_kind,
                            "baseline": baseline,
                            "request_policy": "as-defined",
                            "visit": visit,
                            "split": policy[defense],
                            "paired_visit_id": (
                                f"{block_id}/{workload_id}/as-defined/visit-{visit:03d}"
                            ),
                        }
                    )
    class_counts = Counter(row["class_label"] for row in rows)
    defense_counts = Counter(row["defense"] for row in rows)
    split_counts = Counter(row["split"] for row in rows)
    dataset = {
        "exporter_source": deepcopy(EXPORTER_SOURCE),
        "blocks": blocks,
        "classes": sorted(class_counts),
        "sample_count": len(rows),
        "counts_by_class": dict(sorted(class_counts.items())),
        "counts_by_defense": dict(sorted(defense_counts.items())),
        "counts_by_split": dict(sorted(split_counts.items())),
    }
    return dataset, rows


def _poc5_rehearsal_receipt() -> SimpleNamespace:
    campaign_path = (
        classifier_handoff._lab_root() / "config/campaigns/classifier-poc5-rehearsal.yml"
    )
    campaign, configuration = classifier_handoff._expected_poc5_configuration(campaign_path)
    samples = classifier_handoff.plan_campaign(campaign)
    return SimpleNamespace(
        experiment={
            "name": classifier_handoff.POC5_REHEARSAL_RESULT_NAME,
            "purpose": "evaluation",
            "samples": samples,
            "execution_order": [sample["sample_id"] for sample in samples],
            "configuration": deepcopy(configuration),
            "source": dict(SOURCE),
        }
    )


def _poc5_rehearsal_export_metadata() -> tuple[dict, list[dict]]:
    receipt = _poc5_rehearsal_receipt()
    rows = []
    for sample in receipt.experiment["samples"]:
        workload_id = sample["workload_id"]
        rows.append(
            {
                "block_index": 0,
                "block_id": "block-001",
                "acquisition_block_index": 0,
                "acquisition_block_id": "acquisition-block-001",
                "workload_id": workload_id,
                "class_label": classifier_handoff.POC5_CLASS_LABELS[workload_id],
                "defense": sample["defense"],
                "defense_role": ("baseline" if sample["baseline"] else "inference-only"),
                "runtime_kind": sample["runtime_kind"],
                "baseline": sample["baseline"],
                "request_policy": "as-defined",
                "visit": sample["visit"],
                "split": "interface",
                "paired_visit_id": (
                    f"block-001/{workload_id}/as-defined/visit-{sample['visit']:03d}"
                ),
            }
        )
    class_counts = Counter(row["class_label"] for row in rows)
    defense_counts = Counter(row["defense"] for row in rows)
    return (
        {
            "exporter_source": deepcopy(EXPORTER_SOURCE),
            "blocks": [
                {
                    "result_name": classifier_handoff.POC5_REHEARSAL_RESULT_NAME,
                    "split": "interface",
                    "sample_splits": {
                        defense: "interface" for defense in classifier_handoff.POC5_DEFENSES
                    },
                    "acquisition_block_index": 0,
                    "acquisition_block_id": "acquisition-block-001",
                    "source": dict(SOURCE),
                }
            ],
            "classes": sorted(class_counts),
            "sample_count": len(rows),
            "counts_by_class": dict(sorted(class_counts.items())),
            "counts_by_defense": dict(sorted(defense_counts.items())),
            "counts_by_split": {"interface": len(rows)},
        },
        rows,
    )


def test_poc5_exact_active_cohort_and_domain_labels_preserve_legacy_contract() -> None:
    assert classifier_handoff.POC5_CLASSES == EXPECTED_POC5_CLASSES
    assert classifier_handoff.POC5_CLASS_LABELS == EXPECTED_POC5_CLASS_LABELS
    for workload_id, domain in EXPECTED_POC5_CLASS_LABELS.items():
        workload = load_json(ROOT / f"config/workloads/{workload_id}.json")
        assert urlsplit(workload["preparation"]["final_url"]).hostname == domain
        assert workload["preparation"]["approved_origins"] == [f"https://{domain}"]
    assert classifier_handoff.PILOT_CLASSES == LEGACY_PILOT_CLASSES
    assert classifier_handoff.STABLE3_PILOT_CLASSES == (
        "getbootstrap-home-r3",
        "bootstrap-introduction-r3",
        "cloudflare-quiche-r3",
    )


@pytest.mark.parametrize(
    "wrong_workload_id",
    [
        "apache-traffic-server-docs-r3",
        "nginx-quic-r3",
        "nghttp2-ngtcp2-r3",
        "hyper-basic-client-r1",
    ],
)
def test_poc5_handoff_rejects_old_or_wrong_active_workload_id(
    wrong_workload_id: str,
) -> None:
    dataset, rows = _poc5_export_metadata()
    rows = deepcopy(rows)
    assert rows[0]["workload_id"] == "getbootstrap-home-r3"
    rows[0]["workload_id"] = wrong_workload_id

    with pytest.raises(ValueError, match="2,500-sample protocol"):
        classifier_handoff._validate_poc5_handoff_protocol(dataset, rows)


@pytest.mark.parametrize("workload_id", EXPECTED_POC5_CLASSES)
def test_poc5_handoff_rejects_wrong_domain_for_each_active_workload(
    workload_id: str,
) -> None:
    dataset, rows = _poc5_export_metadata()
    rows = deepcopy(rows)
    row = next(value for value in rows if value["workload_id"] == workload_id)
    other_labels = set(EXPECTED_POC5_CLASS_LABELS.values()) - {
        EXPECTED_POC5_CLASS_LABELS[workload_id]
    }
    row["class_label"] = sorted(other_labels)[0]

    with pytest.raises(ValueError, match="2,500-sample protocol"):
        classifier_handoff._validate_poc5_handoff_protocol(dataset, rows)


def test_poc5_response_only_expected_config_matches_materialized_frozen_reload(
    tmp_path: Path,
) -> None:
    campaign_path = (
        classifier_handoff._lab_root() / "config/campaigns/classifier-poc5-paired-01.yml"
    )
    campaign, expected = classifier_handoff._expected_poc5_configuration(campaign_path)
    result = tmp_path / "response-only-result"

    runtime, materialized = orchestrator._materialize_inputs(result, campaign, {})
    frozen = orchestrator._campaign_from_frozen_inputs(result)
    reloaded = orchestrator._frozen_configuration(result, frozen)

    assert expected == materialized == reloaded
    assert orchestrator.plan_campaign(runtime) == orchestrator.plan_campaign(frozen)
    assert not (result / "inputs/chaff-prefix-specs").exists()
    expected_workload_keys = {
        "id",
        "visits",
        "manifest",
        "sha256",
        "resource_count",
        "origin_count",
        "chaff_qualification",
        "chaff_qualification_sha256",
        "chaff_qualification_scope",
        "chaff_manifest",
        "chaff_manifest_sha256",
        "runtime_manifest",
        "runtime_manifest_sha256",
    }
    assert all(
        set(record) == expected_workload_keys
        and record["chaff_qualification_scope"] == orchestrator.RESPONSE_ONLY_CHAFF_SCOPE
        and "chaff_prefix_spec" not in record
        and "chaff_prefix_spec_sha256" not in record
        for record in expected["workloads"]
    )
    for directory in (
        "chaff-qualifications",
        "chaff-manifests",
        "runtime-workloads",
    ):
        assert len(tuple((result / "inputs" / directory).iterdir())) == len(
            classifier_handoff.POC5_CLASSES
        )
    primitive = chaff_qualification.response_only_request_header_primitive()
    for record in expected["workloads"]:
        sidecar_path = result / record["chaff_qualification"]
        manifest_path = result / record["chaff_manifest"]
        runtime_path = result / record["runtime_manifest"]
        assert sha256_file(sidecar_path) == record["chaff_qualification_sha256"]
        assert sha256_file(manifest_path) == record["chaff_manifest_sha256"]
        assert sha256_file(runtime_path) == record["runtime_manifest_sha256"]

        sidecar = load_json(sidecar_path)
        manifest = load_json(manifest_path)
        assert (
            sidecar["schema_version"] == chaff_qualification.RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION
        )
        assert (
            manifest["schema_version"]
            == chaff_qualification.RESPONSE_ONLY_MANIFEST_V2_SCHEMA_VERSION
        )
        assert sidecar["request_header_primitive"] == primitive
        assert sidecar["candidate_attempts"][-1]["outcome"] == "qualified"
        assert all(
            len(attempt["connection_epochs"]) == chaff_qualification.QUALIFICATION_RUNS
            and all(
                epoch["receipt"]["schema_version"]
                == chaff_qualification.RESPONSE_QUALIFICATION_V2_RECEIPT_SCHEMA_VERSION
                and epoch["receipt"]["request_header_mode"]
                == chaff_qualification.IDENTITY_REQUEST_HEADER_MODE
                for epoch in attempt["connection_epochs"]
            )
            for attempt in sidecar["candidate_attempts"]
        )
        qualification = manifest["resources"][0]["chaff_qualification"]
        assert qualification["request_header_primitive"] == primitive
        assert (
            qualification["response_qualification_sha256"]
            == sidecar["candidate_attempts"][-1]["response_qualification_sha256"]
        )


def test_poc5_frozen_v1_schema_three_response_evidence_still_reloads(
    tmp_path: Path,
) -> None:
    campaign_path = (
        classifier_handoff._lab_root() / "config/campaigns/classifier-poc5-paired-01.yml"
    )
    campaign, _expected = classifier_handoff._expected_poc5_configuration(campaign_path)
    result = tmp_path / "historical-response-only-result"
    orchestrator._materialize_inputs(result, campaign, {})

    for workload_id in classifier_handoff.POC5_CLASSES:
        sidecar = load_json(
            ROOT / f"config/chaff-response-qualification-store/v1/{workload_id}.json"
        )
        workload_path = result / f"inputs/workloads/{workload_id}.json"
        workload = load_json(workload_path)
        selected = next(
            resource
            for resource in workload["resources"]
            if resource["id"] == sidecar["selected_chaff_resource_id"]
        )
        atomic_json(result / f"inputs/chaff-qualifications/{workload_id}.json", sidecar)
        atomic_json(
            result / f"inputs/chaff-manifests/{workload_id}.json",
            chaff_qualification.derive_response_only_chaff_manifest(sidecar, selected),
        )

    frozen = orchestrator._campaign_from_frozen_inputs(result)
    reloaded = orchestrator._frozen_configuration(result, frozen)

    assert all(
        workload.chaff_manifest_data["schema_version"]
        == chaff_qualification.RESPONSE_ONLY_MANIFEST_SCHEMA_VERSION
        for workload in frozen.workloads
    )
    assert all(
        record["chaff_qualification_scope"] == orchestrator.RESPONSE_ONLY_CHAFF_SCOPE
        and "chaff_prefix_spec" not in record
        for record in reloaded["workloads"]
    )


def test_poc5_frozen_reload_rejects_mixed_schema_three_and_four(
    tmp_path: Path,
) -> None:
    campaign_path = (
        classifier_handoff._lab_root() / "config/campaigns/classifier-poc5-paired-01.yml"
    )
    campaign, _expected = classifier_handoff._expected_poc5_configuration(campaign_path)
    result = tmp_path / "mixed-response-only-result"
    orchestrator._materialize_inputs(result, campaign, {})

    workload_id = classifier_handoff.POC5_CLASSES[0]
    sidecar = load_json(ROOT / f"config/chaff-response-qualification-store/v1/{workload_id}.json")
    workload = load_json(result / f"inputs/workloads/{workload_id}.json")
    selected = next(
        resource
        for resource in workload["resources"]
        if resource["id"] == sidecar["selected_chaff_resource_id"]
    )
    atomic_json(
        result / f"inputs/chaff-manifests/{workload_id}.json",
        chaff_qualification.derive_response_only_chaff_manifest(sidecar, selected),
    )

    with pytest.raises(ValueError, match="mixes schema-three and schema-four"):
        orchestrator._campaign_from_frozen_inputs(result)


@pytest.mark.parametrize(
    "mutation",
    ["sidecar-schema", "identity-primitive", "candidate-provenance"],
)
def test_poc5_active_configuration_rejects_response_v2_evidence_mutation(
    mutation: str,
) -> None:
    workload_id = classifier_handoff.POC5_CLASSES[0]
    sidecar_path = (
        classifier_handoff._lab_root()
        / f"config/chaff-response-qualification-store/v2/{workload_id}.json"
    )
    sidecar = load_json(sidecar_path)
    if mutation == "sidecar-schema":
        sidecar["schema_version"] = 1
    elif mutation == "identity-primitive":
        sidecar["request_header_primitive"]["forced"] = [["accept-encoding", "gzip"]]
    elif mutation == "candidate-provenance":
        epoch = sidecar["candidate_attempts"][0]["connection_epochs"][0]
        epoch["receipt"]["source"]["migration_commit"] = "f" * 40
        epoch["receipt_object_sha256"] = chaff_qualification.qualification_digest(
            "qcsd-chaff-sustained-response-receipt-object-v3",
            [epoch["receipt"]],
        )
    else:  # pragma: no cover - parametrization is closed
        raise AssertionError(f"unknown mutation: {mutation}")
    atomic_json(sidecar_path, sidecar)
    classifier_handoff._cached_poc5_configuration.cache_clear()

    campaign_path = (
        classifier_handoff._lab_root() / "config/campaigns/classifier-poc5-paired-01.yml"
    )
    with pytest.raises(ValueError):
        classifier_handoff._expected_poc5_configuration(campaign_path)


def test_poc5_full_v2_expected_config_preserves_prefix_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workload = SimpleNamespace(
        id="qualified-site",
        visits=2,
        sha256="1" * 64,
        resource_count=3,
        origin_count=1,
        chaff_qualification_path=Path("qualification.json"),
        chaff_qualification_sha256="2" * 64,
        chaff_qualification_scope=orchestrator.FULL_CHAFF_SCOPE,
        chaff_prefix_spec_path=Path("prefix.json"),
        chaff_prefix_spec_sha256="3" * 64,
        chaff_manifest_sha256="4" * 64,
        runtime_sha256="5" * 64,
    )
    campaign = SimpleNamespace(
        workloads=(workload,),
        defenses=(),
        profile="research-1200",
        request_policies=("as-defined",),
        limits=SimpleNamespace(as_dict=lambda: {}),
    )
    campaign_path = tmp_path / "full-v2.yml"
    atomic_json(campaign_path, {})
    monkeypatch.setattr(classifier_handoff, "load_campaign", lambda _path: campaign)
    classifier_handoff._cached_poc5_configuration.cache_clear()

    _, expected = classifier_handoff._expected_poc5_configuration(campaign_path)

    assert expected["workloads"] == [
        {
            "id": "qualified-site",
            "visits": 2,
            "manifest": "inputs/workloads/qualified-site.json",
            "sha256": "1" * 64,
            "resource_count": 3,
            "origin_count": 1,
            "chaff_qualification": "inputs/chaff-qualifications/qualified-site.json",
            "chaff_qualification_sha256": "2" * 64,
            "chaff_prefix_spec": "inputs/chaff-prefix-specs/qualified-site.json",
            "chaff_prefix_spec_sha256": "3" * 64,
            "chaff_manifest": "inputs/chaff-manifests/qualified-site.json",
            "chaff_manifest_sha256": "4" * 64,
            "runtime_manifest": "inputs/runtime-workloads/qualified-site.json",
            "runtime_manifest_sha256": "5" * 64,
        }
    ]


def test_poc5_contract_accepts_only_exact_ordered_twenty_result_lineage() -> None:
    plan = classifier_handoff._validate_pilot_collection(_poc5_receipts(), [None] * 20)

    assert isinstance(plan, classifier_handoff.Poc5CollectionPlan)
    assert plan.protocol == "formal"
    assert len(plan.sample_splits) == 20
    assert plan.sample_splits[0] == {"undefended": "train"}
    assert plan.sample_splits[1] == {
        "undefended": "train",
        "front": "inference",
        "tamaraw": "inference",
    }
    assert plan.sample_splits[16]["undefended"] == "validation"
    assert plan.sample_splits[18]["undefended"] == "test"
    assert all(
        policy.get(defense) == "inference"
        for policy in plan.sample_splits
        for defense in ("front", "tamaraw")
        if defense in policy
    )


def test_poc5_contract_rejects_non_alternating_within_block_capture_order() -> None:
    receipts = _poc5_receipts()
    first = receipts[0].experiment
    second = receipts[1].experiment
    first["started_at"], second["started_at"] = second["started_at"], first["started_at"]
    first["completed_at"], second["completed_at"] = (
        second["completed_at"],
        first["completed_at"],
    )

    with pytest.raises(ValueError, match="capture order does not alternate"):
        classifier_handoff._validate_pilot_collection(receipts, [None] * 20)


@pytest.mark.parametrize(
    "wrong_workload_id",
    ["apache-traffic-server-docs-r3", "hyper-basic-client-r1"],
    ids=["retired-id", "wrong-active-id"],
)
def test_poc5_collection_rejects_old_or_wrong_active_workload_id(
    wrong_workload_id: str,
) -> None:
    receipts = _poc5_receipts()
    sample = receipts[0].experiment["samples"][0]
    assert sample["workload_id"] == "getbootstrap-home-r3"
    sample["workload_id"] = wrong_workload_id

    with pytest.raises(ValueError, match="100-sample cohort"):
        classifier_handoff._validate_pilot_collection(receipts, [None] * 20)


@pytest.mark.parametrize("mutation", ["within-block-overlap", "block-order"])
def test_poc5_contract_rejects_overlap_and_non_temporal_blocks(mutation: str) -> None:
    receipts = _poc5_receipts()
    if mutation == "within-block-overlap":
        receipts[1].experiment["started_at"] = "2026-08-01T00:15:00+00:00"
    elif mutation == "block-order":
        receipts[2].experiment.update(
            started_at="2026-08-01T01:15:00+00:00",
            completed_at="2026-08-01T01:45:00+00:00",
        )
        receipts[3].experiment.update(
            started_at="2026-08-01T00:45:00+00:00",
            completed_at="2026-08-01T01:15:00+00:00",
        )
    else:
        raise AssertionError(f"unknown mutation: {mutation}")

    with pytest.raises(ValueError, match="alternate|temporally ordered"):
        classifier_handoff._validate_pilot_collection(receipts, [None] * 20)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("order", "20 ordered"),
        ("split", "assigned automatically"),
        ("cohort", "100-sample cohort"),
        ("campaign", "checked-in campaign"),
        ("source", "identical execution source"),
    ],
)
def test_poc5_contract_rejects_lineage_cohort_and_split_drift(mutation: str, message: str) -> None:
    receipts = _poc5_receipts()
    splits = [None] * 20
    if mutation == "order":
        receipts[0], receipts[1] = receipts[1], receipts[0]
    elif mutation == "split":
        splits[0] = "train"
    elif mutation == "cohort":
        receipts[0].experiment["samples"].pop()
    elif mutation == "campaign":
        receipts[0].experiment["configuration"]["campaign_sha256"] = "0" * 64
    elif mutation == "source":
        receipts[-1].experiment["source"]["image_digest"] = "sha256:" + "4" * 64
    else:
        raise AssertionError(f"unknown mutation: {mutation}")

    with pytest.raises(ValueError, match=message):
        classifier_handoff._validate_pilot_collection(receipts, splits)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("lab_dirty", True),
        ("neqo_dirty", True),
        ("lab_patch_sha256", "4" * 64),
        ("neqo_patch_sha256", "4" * 64),
        ("neqo_pinned_commit", "4" * 40),
    ],
)
def test_poc5_contract_rejects_dirty_or_unpinned_execution_source(
    field: str, value: object
) -> None:
    receipts = _poc5_receipts()
    for receipt in receipts:
        receipt.experiment["source"][field] = value

    with pytest.raises(ValueError, match="clean immutable execution source"):
        classifier_handoff._validate_pilot_collection(receipts, [None] * 20)


def test_poc5_export_requires_same_clean_checkout_and_capture_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipts = _poc5_receipts()
    exporter = {
        "execution_image": dict(SOURCE),
        "companion": {
            "lab_commit": SOURCE["lab_commit"],
            "lab_dirty": False,
        },
    }
    monkeypatch.setattr(
        classifier_handoff,
        "_exporter_source_receipt",
        lambda: deepcopy(exporter),
    )

    classifier_handoff._validate_poc5_export_environment(receipts)

    exporter["companion"]["lab_dirty"] = True
    with pytest.raises(ValueError, match="clean capture checkout"):
        classifier_handoff._validate_poc5_export_environment(receipts)
    exporter["companion"]["lab_dirty"] = False
    exporter["execution_image"]["image_digest"] = "sha256:" + "4" * 64
    with pytest.raises(ValueError, match="collection image"):
        classifier_handoff._validate_poc5_export_environment(receipts)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("baseline-manifest", "campaign/input configuration"),
        ("paired-runtime", "campaign/input configuration"),
        ("paired-chaff", "campaign/input configuration"),
        ("defense", "campaign/input configuration"),
        ("profile", "campaign/input configuration"),
        ("sample-order", "planned sample identity/order"),
    ],
)
def test_poc5_contract_rejects_configuration_and_sample_plan_drift(
    mutation: str, message: str
) -> None:
    receipts = _poc5_receipts()
    if mutation == "baseline-manifest":
        receipts[0].experiment["configuration"]["workloads"][0]["sha256"] = "0" * 64
    elif mutation == "paired-runtime":
        receipts[1].experiment["configuration"]["workloads"][0]["runtime_manifest_sha256"] = (
            "0" * 64
        )
    elif mutation == "paired-chaff":
        receipts[1].experiment["configuration"]["workloads"][0]["chaff_qualification_sha256"] = (
            "0" * 64
        )
    elif mutation == "defense":
        receipts[1].experiment["configuration"]["defenses"].reverse()
    elif mutation == "profile":
        receipts[0].experiment["configuration"]["profile"] = "live"
    elif mutation == "sample-order":
        samples = receipts[0].experiment["samples"]
        samples[0], samples[1] = samples[1], samples[0]
    else:
        raise AssertionError(f"unknown mutation: {mutation}")

    with pytest.raises(ValueError, match=message):
        classifier_handoff._validate_pilot_collection(receipts, [None] * 20)


def test_poc5_rehearsal_is_interface_only_and_cannot_mix_with_formal_export() -> None:
    receipt = _poc5_rehearsal_receipt()

    plan = classifier_handoff._validate_pilot_collection([receipt], ["interface"])
    assert isinstance(plan, classifier_handoff.Poc5CollectionPlan)
    assert plan.protocol == "rehearsal"
    assert plan.sample_splits == (
        {"undefended": "interface", "front": "interface", "tamaraw": "interface"},
    )

    with pytest.raises(ValueError, match="requires the interface split"):
        classifier_handoff._validate_pilot_collection([receipt], [None])
    with pytest.raises(ValueError, match="cannot mix"):
        classifier_handoff._validate_pilot_collection(
            [receipt, _poc5_receipts()[0]], ["interface", None]
        )


def test_poc5_rehearsal_handoff_is_exact_schema_v2_importer_gate() -> None:
    dataset, rows = _poc5_rehearsal_export_metadata()

    classifier_handoff._validate_poc5_rehearsal_handoff_protocol(dataset, rows)

    assert dataset["sample_count"] == 30
    assert dataset["counts_by_split"] == {"interface": 30}
    assert all(row["class_label"] != row["workload_id"] for row in rows)


def test_poc5_export_protocol_has_domain_labels_and_no_defended_training_leakage() -> None:
    dataset, rows = _poc5_export_metadata()

    classifier_handoff._validate_poc5_handoff_protocol(dataset, rows)

    assert dataset["sample_count"] == 2_500
    assert dataset["counts_by_defense"] == {
        "front": 500,
        "tamaraw": 500,
        "undefended": 1_500,
    }
    assert dataset["counts_by_split"] == {
        "inference": 1_000,
        "test": 150,
        "train": 1_200,
        "validation": 150,
    }
    assert all(
        row["split"] == "inference" and row["defense_role"] == "inference-only"
        for row in rows
        if row["defense"] in {"front", "tamaraw"}
    )
    assert dataset["blocks"][0]["acquisition_block_id"] == "acquisition-block-001"
    assert dataset["blocks"][1]["acquisition_block_id"] == "acquisition-block-001"
    assert dataset["blocks"][2]["acquisition_block_id"] == "acquisition-block-002"
    assert all(
        row["class_label"] == classifier_handoff.POC5_CLASS_LABELS[row["workload_id"]]
        for row in rows
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("defended-train", "2,500-sample protocol"),
        ("domain", "2,500-sample protocol"),
        ("pair", "paired-visit"),
        ("acquisition", "2,500-sample protocol"),
        ("result-order", "result lineage"),
        ("count", "2,500-sample protocol"),
    ],
)
def test_poc5_export_protocol_rejects_label_split_pairing_and_count_drift(
    mutation: str, message: str
) -> None:
    dataset, rows = _poc5_export_metadata()
    dataset = deepcopy(dataset)
    rows = deepcopy(rows)
    if mutation == "defended-train":
        next(row for row in rows if row["defense"] == "front")["split"] = "train"
    elif mutation == "domain":
        rows[0]["class_label"] = "wrong.example"
    elif mutation == "pair":
        rows[0]["paired_visit_id"] = "wrong"
    elif mutation == "acquisition":
        rows[0]["acquisition_block_id"] = "acquisition-block-999"
    elif mutation == "result-order":
        dataset["blocks"][0], dataset["blocks"][1] = (
            dataset["blocks"][1],
            dataset["blocks"][0],
        )
    elif mutation == "count":
        rows.pop()
    else:
        raise AssertionError(f"unknown mutation: {mutation}")

    with pytest.raises(ValueError, match=message):
        classifier_handoff._validate_poc5_handoff_protocol(dataset, rows)


def test_schema_v1_rejects_inference_split() -> None:
    with pytest.raises(ValueError, match="block split"):
        classifier_handoff._normalize_splits(["inference"], 1)

    row = {
        "schema_version": classifier_handoff.SCHEMA_VERSION,
        "block_index": 0,
        "visit": 0,
        "seed": 1,
        "attempts": 1,
        "packet_count": 1,
        "defense": "undefended",
        "split": "inference",
    }
    with pytest.raises(ValueError, match="sample split is invalid"):
        classifier_handoff._validate_sample_row(
            row,
            {0: {"*": "inference"}},
            schema_version=classifier_handoff.SCHEMA_VERSION,
        )
