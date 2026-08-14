from __future__ import annotations

import copy
import csv
import io
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import qcsd_lab.fitting as fitting_module
import qcsd_lab.orchestrator as orchestrator
from qcsd_lab.capture_session import Defense
from qcsd_lab.chaff_qualification import (
    _schema_five_diagnostic_receipt,
    _schema_six_capacity_falsification_diagnostic_receipt,
    _schema_six_runtime_falsification_diagnostic_receipt,
    _schema_two_sender_framing_falsification_diagnostic_receipt,
)
from qcsd_lab.experiment import (
    accept_sample,
    checkpoint_experiment,
    finalize_experiment,
    initialize_experiment,
    transition_sample,
)
from qcsd_lab.fitting import (
    EXACT_BUNDLE_FILES,
    _fit_result_structural_for_tests,
    _inspect_structural_artifact_bundle,
    validate_fitting_result,
    verify_artifact_bundle as _strict_verify_artifact_bundle,
)
from qcsd_lab.fitting_trace import _read_observations, load_fitting_trace
from qcsd_lab.parameters import (
    validate_frozen_parameter_artifact,
    validate_parameter_artifact,
)
from qcsd_lab.util import atomic_json, atomic_text, sha256_file
from qcsd_lab.verification import authoritative_files, prepare_resume, seal_result, verify_result


WORKLOADS = ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot")
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
REPOSITORY_ROOT = Path(__file__).parents[1]


def _synthetic_qualification_inputs(
    fitting: fitting_module.FittingInputs,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build structural, non-network schema-six bindings for synthetic fitter tests."""

    experiment = fitting.verified.experiment
    workloads = experiment["configuration"]["workloads"]
    records: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    for index, workload in enumerate(workloads):
        workload_id = workload["id"]
        marker = f"{index + 1:064x}"
        spec = f"{index + 11:064x}"
        manifest = f"{index + 21:064x}"
        records.append(
            {
                "workload_id": workload_id,
                "application_workload_sha256": sha256_file(
                    fitting.verified.root / workload["manifest"]
                ),
                "chaff_qualification_sidecar": {
                    "path": f"config/chaff-qualification-store/v2/{workload_id}.json",
                    "sha256": marker,
                },
                "prefix_pack_spec": {
                    "path": f"config/chaff-prefix-specs/v2/{workload_id}.json",
                    "sha256": spec,
                },
                "qualified_chaff_manifest_sha256": manifest,
                "application_resource_id": 0,
                "selected_chaff_resource_id": index,
                "qualified_parallel_chaff_streams": 5,
                "walkie_talkie_required_chaff_streams": 4,
            }
        )
        bindings.append(
            {
                "workload_id": workload_id,
                "chaff_qualification_sidecar_sha256": marker,
                "prefix_pack_spec_sha256": spec,
                "qualified_chaff_manifest_sha256": manifest,
                "application_resource_id": 0,
                "selected_chaff_resource_id": index,
                "qualified_parallel_chaff_streams": 5,
                "walkie_talkie_required_chaff_streams": 4,
            }
        )
    receipt = {
        "role": "runtime-qualification-only-excluded-from-fitting",
        "qualification_bytes_excluded": True,
        "schema_five_diagnostic": _schema_five_diagnostic_receipt(),
        "schema_six_capacity_falsification_diagnostic": (
            _schema_six_capacity_falsification_diagnostic_receipt()
        ),
        "schema_six_runtime_falsification_diagnostic": (
            _schema_six_runtime_falsification_diagnostic_receipt()
        ),
        "schema_two_sender_framing_falsification_diagnostic": (
            _schema_two_sender_framing_falsification_diagnostic_receipt()
        ),
        "workloads": records,
    }
    return bindings, receipt


def test_runtime_qualification_rejects_boolean_application_resource_id() -> None:
    _bindings, receipt = _synthetic_qualification_inputs(
        SimpleNamespace(
            verified=SimpleNamespace(
                root=Path("."),
                experiment={
                    "configuration": {
                        "workloads": [
                            {"id": workload, "manifest": "pyproject.toml"} for workload in WORKLOADS
                        ]
                    }
                },
            )
        )
    )
    receipt["workloads"][0]["application_resource_id"] = False

    with pytest.raises(ValueError, match="resource/capacity binding"):
        fitting_module._validate_runtime_qualification_inputs(
            receipt,
            list(WORKLOADS),
        )


def _fit_result(result: Path, *, artifacts_root: Path) -> Path:
    fitting = validate_fitting_result(result)
    return _fit_result_structural_for_tests(
        result,
        artifacts_root=artifacts_root,
        qualification_inputs=_synthetic_qualification_inputs(fitting),
    )


def _inspect_test_or_verify_historical_bundle(
    root: Path,
) -> fitting_module.VerifiedArtifactBundle | fitting_module.InspectedStructuralArtifactBundle:
    """Inspect synthetic bundles; retain strict verification for historical ones."""

    provenance = json.loads((root / "provenance.json").read_text(encoding="utf-8"))
    if provenance.get("artifact_type") == fitting_module.STRUCTURAL_ARTIFACT_TYPE:
        return _inspect_structural_artifact_bundle(root)
    return _strict_verify_artifact_bundle(root)


def _leaf_paths(value: object, path: tuple[str | int, ...] = ()):
    """Yield one path for every JSON leaf, including empty containers."""

    if isinstance(value, dict):
        if not value:
            yield path, value
            return
        for key in sorted(value):
            yield from _leaf_paths(value[key], (*path, key))
        return
    if isinstance(value, list):
        if not value:
            yield path, value
            return
        for index, item in enumerate(value):
            yield from _leaf_paths(item, (*path, index))
        return
    yield path, value


def _representative_leaf_paths(value: object) -> list[tuple[tuple[str | int, ...], object]]:
    """Collapse homogeneous array elements while retaining every schema leaf."""

    representatives: dict[tuple[str, ...], tuple[tuple[str | int, ...], object]] = {}
    for path, leaf in _leaf_paths(value):
        normalized = tuple("[]" if isinstance(part, int) else part for part in path)
        representatives.setdefault(normalized, (path, leaf))
    return list(representatives.values())


def _alternate_leaf(value: object) -> object:
    """Return a different, finite, same-domain JSON primitive where possible."""

    if isinstance(value, bool):
        return not value
    if type(value) is int:
        return value - 1 if value == 2**64 - 1 else value + 1
    if isinstance(value, float):
        return value + 0.125
    if isinstance(value, str):
        if value.startswith("sha256:") and len(value) == 71:
            replacement = "b" if value[7] != "b" else "a"
            return f"sha256:{replacement}{value[8:]}"
        if len(value) in {40, 64} and all(character in "0123456789abcdef" for character in value):
            replacement = "b" if value[0] != "b" else "a"
            return replacement + value[1:]
        return value + "-tampered"
    if value == []:
        return ["tampered"]
    if value == {}:
        return {"tampered": True}
    if value is None:
        return "tampered"
    raise AssertionError(f"unsupported JSON leaf in tamper test: {value!r}")


def _replace_leaf(
    value: object,
    path: tuple[str | int, ...],
    replacement: object,
) -> object:
    changed = copy.deepcopy(value)
    if not path:
        return replacement
    cursor: Any = changed
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = replacement
    return changed


def _display_path(path: tuple[str | int, ...]) -> str:
    return ".".join(f"[{part}]" if isinstance(part, int) else part for part in path)


def _source(marker: str) -> dict[str, object]:
    return {
        "image_digest": "sha256:" + marker * 64,
        "lab_commit": marker * 40,
        "lab_dirty": False,
        "lab_patch_sha256": EMPTY_SHA256,
        "neqo_commit": "c" * 40,
        "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": EMPTY_SHA256,
    }


def _make_fitting_result(
    base: Path,
    *,
    workloads: tuple[str, ...] = WORKLOADS,
    source_marker: str = "a",
    conflicting_packets_csv: bool = False,
) -> Path:
    config = base / "config"
    (config / "campaigns").mkdir(parents=True)
    (config / "workloads").mkdir()
    source = _source(source_marker)
    manifest = {
        "preparation": {
            "source_url": "https://site.test/",
            "final_url": "https://site.test/",
            "chromium_version": "synthetic-test",
            "settle_ms": 0,
            "observed_request_count": 1,
            "observed_origins": ["https://site.test"],
            "approved_origins": ["https://site.test"],
            "exclusions": [],
            "max_response_bytes": 1_048_576,
            "timeout_seconds": 5,
            "stability_runs": 3,
            "stability_profile": "live",
            "stability_defense": "none",
            "stability_seed": 0,
            "udp_payload_qualification": {
                "schema_version": 1,
                "configured_udp_payload_ceiling": 1_200,
                "runs": [
                    {
                        "run_index": index,
                        "packets_sha256": str(index + 1) * 64,
                        "total": {
                            "packet_count": 2,
                            "observed_udp_payload_max": 1_200,
                            "oversized_packet_count": 0,
                        },
                        "incoming": {
                            "packet_count": 1,
                            "observed_udp_payload_max": 1_200,
                            "oversized_packet_count": 0,
                        },
                        "outgoing": {
                            "packet_count": 1,
                            "observed_udp_payload_max": 1_200,
                            "oversized_packet_count": 0,
                        },
                    }
                    for index in range(3)
                ],
            },
            "neqo_version": "synthetic",
            "neqo_base_commit": "b" * 40,
            "published_qcsd_commit": "d" * 40,
            "migration_commit": "e" * 40,
            "expected_responses": [
                {"resource_id": 0, "status": 200, "bytes": 1_200, "body_sha256": "f" * 64}
            ],
            "lab_source": source,
            "prepare_image_digest": source["image_digest"],
        },
        "resources": [
            {
                "id": 0,
                "url": "https://site.test/",
                "type": "Document",
                "content_length": 1_200,
                "data_length": 1_200,
                "chaff_priority": True,
                "known_valid": True,
                "depends_on": [],
                "headers": [],
            }
        ],
    }
    for workload in workloads:
        atomic_json(config / f"workloads/{workload}.json", manifest)
    campaign_path = config / "campaigns/fitting.yml"
    atomic_text(
        campaign_path,
        "schema: 1\n"
        "name: research-fitting-1200\n"
        "purpose: fitting\n"
        "seed: 2026081201\n"
        "profile: research-1200\n"
        "workloads:\n"
        + "".join(f"  {workload}: 10\n" for workload in workloads)
        + "request_policies:\n"
        "  - as-defined\n"
        "  - half-duplex\n"
        "defenses:\n"
        "  - undefended\n"
        "limits:\n"
        "  timeout_seconds: 120\n"
        "  max_response_bytes: 1048576\n"
        "  capture_seconds: 180\n"
        "  capture_megabytes: 64\n"
        "  max_attempts: 3\n"
        "  per_origin_cooldown_seconds: 30\n"
        "  settle_seconds: 1\n",
    )
    root = base / "results/research-fitting-1200/run-001"
    campaign = orchestrator.load_campaign(campaign_path)
    runtime, configuration = orchestrator._materialize_inputs(root, campaign, source)
    planned = orchestrator.plan_campaign(runtime)
    experiment = initialize_experiment(
        root,
        name=campaign.name,
        purpose=campaign.purpose,
        run_id="run-001",
        source=source,
        configuration=configuration,
        samples=planned,
        started_at="2026-08-12T00:00:00+00:00",
    )
    workload_index = {name: index for index, name in enumerate(workloads)}
    for sample in planned:
        transition_sample(experiment, sample["sample_id"], "running", increment_attempt=True)
        sample_root = root / sample["path"]
        neqo = sample_root / "neqo"
        atomic_text(sample_root / "capture.pcapng", "controlled fitting capture\n")
        atomic_json(
            neqo / "run.json",
            {
                "completion_status": "complete",
                "defense_start_monotonic_ns": 10_000,
                "application_completion_monotonic_ns": 75_000_000,
            },
        )
        index = workload_index[sample["workload_id"]]
        atomic_text(
            neqo / "packets.csv",
            "packets.csv is sealed but deliberately not a fitter input\n"
            if conflicting_packets_csv
            else _packet_csv(index, sample["visit"]),
        )
        atomic_text(
            neqo / "events.csv",
            _event_csv(
                index,
                sample["visit"],
                half_duplex=sample["request_policy"] == "half-duplex",
            ),
        )
        atomic_text(
            neqo / "schedule.csv",
            "target_time_us,direction,size,connection,action_time_us,satisfaction,"
            "observed_size,miss_reason,slot_id\n",
        )
        accept_sample(root, experiment, sample["sample_id"], eligible=True)
    checkpoint_experiment(root, experiment)
    finalize_experiment(
        root,
        experiment,
        status="complete",
        completed_at="2026-08-12T00:10:00+00:00",
    )
    seal_result(root)
    return root


def _packet_values(workload_index: int, visit: int) -> list[tuple[str, int, int]]:
    shift = workload_index * 7 + visit
    return [
        ("outgoing", 100, 80 + shift),
        ("outgoing", 200, 140 + shift),
        ("incoming", 300, 180 + shift),
        ("outgoing", 400, 280 + shift),
        ("incoming", 450, 320 + shift),
        ("incoming", 650, 460 + shift),
        ("outgoing", 20_400, 680 + shift),
        ("outgoing", 20_550, 880 + shift),
        ("incoming", 25_650, 1_000 + shift),
        ("incoming", 25_800, 1_100 + shift),
        ("outgoing", 60_550, 1_180),
        ("outgoing", 60_750, 300 + shift),
        ("incoming", 70_800, 700 + shift),
        ("incoming", 71_100, 900 + shift),
    ]


def _packet_csv(workload_index: int, visit: int) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "direction",
            "monotonic_us",
            "connection",
            "observed_udp_length",
            "scheduled_target",
            "satisfaction",
            "slot_id",
        ]
    )
    for direction, time, length in sorted(
        _packet_values(workload_index, visit), key=lambda item: item[1]
    ):
        writer.writerow([direction, time, 1, length, "", "natural", ""])
    return output.getvalue()


def _event_csv(workload_index: int, visit: int, *, half_duplex: bool) -> str:
    outgoing = 1_250 + workload_index * 40 + visit * 10
    incoming = 2_050 + workload_index * 30 + visit * 11
    observations: list[tuple[int, str, dict[str, object]]] = [
        (
            5_000,
            "classified_datagram",
            {"endpoint": 1, "direction": "outgoing", "length": 1_199, "class": "natural"},
        ),
    ]
    if half_duplex:
        observations.extend(
            [
                (6_000, "application_batch_started", {}),
                (7_000, "application_batch_completed", {}),
                (10_000, "stream_opened", {"endpoint": 1, "stream": 4, "role": "application"}),
                (20_000, "application_batch_started", {}),
                (
                    30_000,
                    "stream_data_transmitted",
                    {
                        "endpoint": 1,
                        "stream": 4,
                        "role": "application",
                        "offset": 0,
                        "bytes": outgoing,
                    },
                ),
                (21_000_000, "bytes_read", {"endpoint": 1, "stream": 4, "bytes": incoming}),
                (
                    22_000_000,
                    "stream_data_transmitted",
                    {
                        "endpoint": 1,
                        "stream": 4,
                        "role": "application",
                        "offset": outgoing,
                        "bytes": 650 + visit,
                    },
                ),
                (
                    72_000_000,
                    "bytes_read",
                    {"endpoint": 1, "stream": 4, "bytes": 700 + workload_index},
                ),
                (73_000_000, "application_batch_completed", {}),
                (75_000_798, "application_complete", {}),
                (76_000_000, "application_batch_started", {}),
                (77_000_000, "application_batch_completed", {}),
            ]
        )
    for direction, time_us, length in _packet_values(workload_index, visit):
        observations.append(
            (
                time_us * 1_000,
                "classified_datagram",
                {"endpoint": 1, "direction": direction, "length": length, "class": "natural"},
            )
        )
    observations.extend(
        [
            (
                30_000_000,
                "classified_datagram",
                {
                    "endpoint": 1,
                    "direction": "outgoing",
                    "length": 1_200,
                    "class": "defense_cover",
                },
            ),
            (
                80_000_000,
                "classified_datagram",
                {"endpoint": 1, "direction": "incoming", "length": 1_198, "class": "natural"},
            ),
        ]
    )
    observations.sort(key=lambda item: item[0])
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["monotonic_us", "connection", "event", "outcome", "details"])
    for sequence, (production_ns, kind, fields) in enumerate(observations):
        details = {
            "type": kind,
            "production_monotonic_ns": production_ns,
            "production_sequence": sequence,
            **fields,
        }
        connection = 1 if "endpoint" in fields else ""
        writer.writerow(
            [
                production_ns // 1_000,
                connection,
                "observation",
                "recorded",
                json.dumps(details, sort_keys=True, separators=(",", ":")),
            ]
        )
    return output.getvalue()


def test_typed_event_reader_uses_production_time_with_sequence_as_tie_break(
    tmp_path: Path,
) -> None:
    events = tmp_path / "events.csv"
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["monotonic_us", "connection", "event", "outcome", "details"])
    for production_ns, sequence in ((1_000, 0), (2_000, 2), (3_000, 1)):
        writer.writerow(
            [
                production_ns // 1_000,
                0,
                "observation",
                "recorded",
                json.dumps(
                    {
                        "type": "application_complete",
                        "production_monotonic_ns": production_ns,
                        "production_sequence": sequence,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ]
        )
    events.write_text(output.getvalue(), encoding="utf-8")

    observations = _read_observations(events)
    assert [item.production_monotonic_ns for item in observations] == [1_000, 2_000, 3_000]
    assert [item.sequence for item in observations] == [0, 2, 1]


@pytest.mark.parametrize(
    "rows, message",
    [
        (((1_000, 0), (2_000, 2), (3_000, 2)), "unique and contiguous"),
        (((2_000, 0), (1_000, 1)), "causal production order"),
        (((1_000, 1), (1_000, 0)), "causal production order"),
    ],
)
def test_typed_event_reader_rejects_invalid_causal_metadata(
    tmp_path: Path,
    rows: tuple[tuple[int, int], ...],
    message: str,
) -> None:
    events = tmp_path / "events.csv"
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["monotonic_us", "connection", "event", "outcome", "details"])
    for production_ns, sequence in rows:
        writer.writerow(
            [
                production_ns // 1_000,
                0,
                "observation",
                "recorded",
                json.dumps(
                    {
                        "type": "application_complete",
                        "production_monotonic_ns": production_ns,
                        "production_sequence": sequence,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ]
        )
    events.write_text(output.getvalue(), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        _read_observations(events)


def _write_fitting_trace(
    root: Path,
    observations: list[tuple[int, str, dict[str, object]]],
    *,
    completion_ns: int = 200_000,
) -> None:
    neqo = root / "neqo"
    atomic_json(
        neqo / "run.json",
        {
            "completion_status": "complete",
            "defense_start_monotonic_ns": 100_000,
            "application_completion_monotonic_ns": completion_ns,
        },
    )
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["monotonic_us", "connection", "event", "outcome", "details"])
    for sequence, (production_ns, kind, fields) in enumerate(observations):
        details = {
            "type": kind,
            "production_monotonic_ns": production_ns,
            "production_sequence": sequence,
            **fields,
        }
        writer.writerow(
            [
                production_ns // 1_000,
                fields.get("endpoint", ""),
                "observation",
                "recorded",
                json.dumps(details, sort_keys=True, separators=(",", ":")),
            ]
        )
    atomic_text(neqo / "events.csv", output.getvalue())


def test_fitting_trace_retains_unique_causal_closure_but_bounds_packets(tmp_path: Path) -> None:
    sample = tmp_path / "sample"
    _write_fitting_trace(
        sample,
        [
            (110_000, "application_batch_started", {}),
            (
                150_000,
                "classified_datagram",
                {"endpoint": 1, "direction": "outgoing", "length": 100, "class": "natural"},
            ),
            (
                160_000,
                "classified_datagram",
                {"endpoint": 1, "direction": "incoming", "length": 200, "class": "natural"},
            ),
            (190_000, "application_batch_completed", {}),
            (200_798, "application_complete", {}),
            (
                201_000,
                "classified_datagram",
                {"endpoint": 1, "direction": "incoming", "length": 300, "class": "natural"},
            ),
            (202_000, "application_batch_started", {}),
        ],
    )

    trace = load_fitting_trace(
        sample,
        sample_id="sample",
        workload_id="alpha",
        request_policy="half-duplex",
        visit=0,
        require_observations=True,
    )
    assert [packet.length_bytes for packet in trace.packets] == [100, 200]
    assert [observation.kind for observation in trace.observations] == [
        "application_batch_started",
        "classified_datagram",
        "classified_datagram",
        "application_batch_completed",
        "application_complete",
    ]


def test_fitting_trace_excludes_same_timestamp_tail_after_closure(tmp_path: Path) -> None:
    sample = tmp_path / "sample"
    _write_fitting_trace(
        sample,
        [
            (
                150_000,
                "classified_datagram",
                {"endpoint": 1, "direction": "outgoing", "length": 100, "class": "natural"},
            ),
            (
                160_000,
                "classified_datagram",
                {"endpoint": 1, "direction": "incoming", "length": 200, "class": "natural"},
            ),
            (200_000, "application_complete", {}),
            (200_000, "application_batch_started", {}),
        ],
    )

    trace = load_fitting_trace(
        sample,
        sample_id="sample",
        workload_id="alpha",
        request_policy="half-duplex",
        visit=0,
        require_observations=True,
    )
    assert [observation.kind for observation in trace.observations] == [
        "classified_datagram",
        "classified_datagram",
        "application_complete",
    ]


@pytest.mark.parametrize(
    "marker_rows, message",
    [
        ([], "exactly one application_complete"),
        (
            [(200_798, "application_complete", {}), (200_900, "application_complete", {})],
            "exactly one application_complete",
        ),
        ([(199_999, "application_complete", {})], "precedes the numeric completion boundary"),
        (
            [
                (200_100, "bytes_read", {"endpoint": 1, "stream": 4, "bytes": 1}),
                (200_798, "application_complete", {}),
            ],
            "intervenes between completion boundary and marker",
        ),
    ],
)
def test_fitting_trace_rejects_invalid_causal_closure(
    tmp_path: Path,
    marker_rows: list[tuple[int, str, dict[str, object]]],
    message: str,
) -> None:
    sample = tmp_path / "sample"
    _write_fitting_trace(
        sample,
        [
            (
                150_000,
                "classified_datagram",
                {"endpoint": 1, "direction": "outgoing", "length": 100, "class": "natural"},
            ),
            (
                160_000,
                "classified_datagram",
                {"endpoint": 1, "direction": "incoming", "length": 200, "class": "natural"},
            ),
            *marker_rows,
        ],
    )
    with pytest.raises(ValueError, match=message):
        load_fitting_trace(
            sample,
            sample_id="sample",
            workload_id="alpha",
            request_policy="half-duplex",
            visit=0,
            require_observations=True,
        )


@pytest.fixture(scope="module")
def fitted_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build one immutable synthetic bundle for exhaustive read/restore checks."""

    base = tmp_path_factory.mktemp("fitting-leaf-tamper")
    result = _make_fitting_result(base / "source")
    return _fit_result(result, artifacts_root=base / "artifacts")


def _legacy_bundle_from_current(source: Path, destination: Path) -> Path:
    """Re-encode a fitted synthetic cohort using the exact frozen v2 contract."""

    shutil.copytree(source, destination)
    provenance_path = destination / "provenance.json"
    walkie_path = destination / "walkie-talkie.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    walkie = json.loads(walkie_path.read_text(encoding="utf-8"))
    current_algorithm = provenance["algorithms"]["walkie_talkie"]
    legacy_algorithm = {
        "algorithm": current_algorithm["algorithm"],
        "candidate_pair_costs": [
            {
                "left": item["left"],
                "right": item["right"],
                "matching_cost_packets": item["base_matching_cost_packets"],
            }
            for item in current_algorithm["candidate_pair_costs"]
        ],
        "selected_pairs": [
            {
                "real": item["real"],
                "decoy": item["decoy"],
                "matching_cost_packets": item["base_matching_cost_packets"],
            }
            for item in current_algorithm["selected_pairs"]
        ],
        "training_visits": current_algorithm["training_visits"],
    }
    selected_cost = {
        (item["real"], item["decoy"]): item["matching_cost_packets"]
        for item in legacy_algorithm["selected_pairs"]
    }
    for profile in walkie["profiles"]:
        for burst in profile["bursts"]:
            if burst["outgoing"] > 0:
                burst["outgoing"] -= 1
            if burst["incoming"] > 0:
                burst["incoming"] -= 1
        profile["matching_cost_packets"] = selected_cost[(profile["real"], profile["decoy"])]
        profile["total_scheduled_bytes"] = 1_200 * sum(
            burst["outgoing"] + burst["incoming"] for burst in profile["bursts"]
        )
    walkie["schema_version"] = 2
    walkie["matching_algorithm"] = "minimum-cost-one-to-one"
    walkie.pop("receiver_continuation")
    walkie.pop("qualification_bindings")
    walkie["generated_by"] = (
        "qcsd_lab.fitting_walkie_talkie 2.0.1; algorithm_receipt_sha256="
        f"{fitting_module._algorithm_receipt_digest(legacy_algorithm)}"
    )
    atomic_json(walkie_path, walkie)
    provenance["fitting_contract"] = fitting_module._legacy_fitting_contract(WORKLOADS)
    provenance["artifact_type"] = "qcsd-research-defense-bundle"
    provenance["status"] = fitting_module.RESEARCH_ARTIFACT_STATUS
    provenance["production_ready"] = True
    provenance.pop("runtime_qualification_inputs")
    provenance["algorithms"]["walkie_talkie"] = legacy_algorithm
    provenance["artifacts"]["walkie_talkie"]["sha256"] = sha256_file(walkie_path)
    atomic_json(provenance_path, provenance)
    return destination


def test_fit_builds_exact_deterministic_bundle_without_mutating_source(tmp_path: Path) -> None:
    result = _make_fitting_result(tmp_path / "source")
    before_experiment = (result / "experiment.json").read_bytes()
    before_evidence = (result / "evidence.sha256").read_bytes()

    first = _fit_result(result, artifacts_root=tmp_path / "artifacts-one")
    second = _fit_result(result, artifacts_root=tmp_path / "artifacts-two")
    assert {path.name for path in first.iterdir()} == EXACT_BUNDLE_FILES
    assert [(first / filename).read_bytes() for filename in sorted(EXACT_BUNDLE_FILES)] == [
        (second / filename).read_bytes() for filename in sorted(EXACT_BUNDLE_FILES)
    ]
    assert _fit_result(result, artifacts_root=tmp_path / "artifacts-one") == first

    verified = _inspect_test_or_verify_historical_bundle(first)
    assert verified.as_dict()["structurally_valid"] is True
    assert verified.as_dict()["authoritative"] is False
    assert set(verified.artifact_hashes) == {
        "traffic_morphing",
        "wtf_pad",
        "walkie_talkie",
    }
    receipt_text = (first / "provenance.json").read_text(encoding="utf-8")
    receipt = json.loads(receipt_text)
    assert receipt["artifact_type"] == fitting_module.STRUCTURAL_ARTIFACT_TYPE
    assert receipt["status"] == fitting_module.STRUCTURAL_ARTIFACT_STATUS
    assert receipt["production_ready"] is False
    with pytest.raises(ValueError, match="invalid research binding"):
        _strict_verify_artifact_bundle(first)
    with pytest.raises(ValueError, match="wrong fields"):
        validate_parameter_artifact(
            first / "walkie-talkie.json",
            provenance_path=first / "provenance.json",
            expected_kind="walkie_talkie",
            expected_qcsd_profile="research-1200",
            expected_udp_payload_ceiling=1_200,
            expected_workloads=set(WORKLOADS),
        )
    assert receipt["fitting_contract"]["contract_version"] == 6
    assert receipt["fitting_contract"]["workload_order"] == list(WORKLOADS)
    assert receipt["fitting_contract"]["fitter_version"] == "qcsd_lab.fitting 2.4.1"
    assert receipt["fitting_contract"]["parameter_schema_versions"] == {
        "traffic_morphing": 2,
        "walkie_talkie": 6,
        "wtf_pad": 2,
    }
    assert receipt["fitting_contract"]["constants"]["extractor"]["production_sequence"] == (
        "unique-contiguous-zero-based-set"
    )
    assert receipt["fitting_contract"]["constants"]["extractor"]["production_event_order"] == (
        "nondecreasing-(nanoseconds,sequence)-file-order"
    )
    assert receipt["fitting_contract"]["constants"]["extractor"]["typed_lifecycle_closure"] == {
        "applies_to": "half-duplex",
        "event": "application_complete",
        "full_trace_cardinality": 1,
        "post_end_observations_before_marker": "forbidden",
        "production_relation": "marker-nanoseconds>=end-field",
        "retention": "numeric-window-plus-unique-causal-closure-marker",
    }
    assert receipt["fitting_contract"]["constants"]["walkie_talkie"]["zero_bytes_read"] == (
        "validated-unsigned-no-op-excluded-from-direction-segmentation"
    )
    assert receipt["fitting_contract"]["constants"]["walkie_talkie"]["incoming_rule"] == (
        "sum-positive-raw-BytesRead-per-batch"
    )
    walkie = json.loads((first / "walkie-talkie.json").read_text(encoding="utf-8"))
    assert walkie["schema_version"] == 6
    assert walkie["matching_algorithm"] == "minimum-base-symmetric-mold-padding-cost-one-to-one"
    assert (
        walkie["receiver_continuation"]
        == fitting_module.fitting_walkie_talkie.receiver_continuation_contract()
    )
    assert walkie["receiver_continuation"]["formula"] == (
        "symmetric_incoming=adapted_incoming-1-if-adapted_incoming>0-else-0"
    )
    assert walkie["receiver_continuation"]["sender_framing_formula"] == (
        "symmetric_outgoing=adapted_outgoing-1-if-adapted_outgoing>0-else-0"
    )
    assert walkie[
        "qualification_bindings"
    ] == fitting_module._qualification_bindings_from_provenance(receipt)
    """Historical schema-five receiver contract, retained below as a literal audit oracle.
    {
        "allocation_policy": (
            "single-peer-acknowledged-pristine-header-phase-controlled-chaff-stream-whole-cell"
        ),
        "application_order": "after-symmetric-elementwise-mold",
        "batch_end_release_policy": (
            "at-molded-batch-end-after-application-batch-complete-otherwise-no-batch-gate"
        ),
        "base_allocation_policy": (
            "application-streams-before-peer-acknowledged-nonreserved-controlled-chaff-streams;"
            "exact-capacity-before-bounded-framing-claims"
        ),
        "causal_capacity_precondition": (
            "first-molded-component-outgoing>0;max_chaff_streams>=maximum-receiver-continuation-"
            "reserve-horizon+1;required-preprovisioned-chaff-request-stream-frames-through-fin-"
            "fit-within-residual-normal-priority-stream-data-budget-after-higher-priority-due-"
            "application-stream-frames-at-each-positive-outgoing-horizon-start"
        ),
        "cells_per_nonzero_incoming_component": 1,
        "formula": "adapted_incoming=symmetric_incoming+1-if-symmetric_incoming>0-else-0",
        "parser_allowance_ceiling_bytes": 1_000,
        "post_outgoing_loss_liveness_limitation": (
            "insufficient-peer-acknowledged-survivors-after-positive-outgoing-targets-resolve-"
            "hold-base-and-continuation-allocation;no-targetless-chaff-stream-retransmission-or-"
            "generic-loss-liveness-guarantee"
        ),
        "prefix_consumability_precondition": (
            "prepared-selected-pristine-first-prior-requested-plus-raw-headroom-bytes-are-"
            "consumable"
        ),
        "provisioning_policy": (
            "fill-configured-chaff-stream-limit-before-due-molded-outgoing-actions"
        ),
        "raw_headroom_bytes_per_nonzero_incoming_component": 1_200,
        "release_policy": (
            "after-all-base-events-controller-requested-and-request-signals-observed;reserve-"
            "deterministic-peer-acknowledged-pristine-candidates-for-current-zero-outgoing-"
            "continuation-horizon-before-first-base-allocation-and-retain-each-until-"
            "corresponding-continuation-release-or-session-end;recompute-live-unconsumed-base-"
            "each-retry;extend-single-coalesced-positive-outstanding-header-blocked-stream-else-"
            "reserved-peer-acknowledged-stream;outstanding-at-or-below-parser-ceiling"
        ),
        "request_activation_policy": (
            "zero-required-insert-count-nonblocking-qpack-chaff-header-block;positive-final-size-"
            "with-contiguous-unique-request-stream-offsets-[0,final-size)-and-fin-peer-"
            "acknowledged-under-molded-outgoing-cells"
        ),
        "request_prefix_delivery_precondition": (
            "before-each-incoming-component-first-base-allocation-peer-acknowledged-nonblocking-"
            "chaff-request-survivors>=current-receiver-continuation-reserve-horizon+1"
        ),
        "resource_precondition": (
            "initial-chaff-selection-yields-known-valid-dependency-free-same-origin-resource-"
            "with-effective-length>=raw-headroom-bytes-per-nonzero-incoming-component"
        ),
        "reserve_policy": (
            "reserve-deterministic-acknowledged-pristine-candidates-for-current-zero-outgoing-"
            "continuation-horizon-before-first-base-allocation-of-each-nonzero-incoming-component"
        ),
        "reserve_lifecycle_policy": (
            "remove-exactly-first-reserve-once-at-corresponding-continuation-controller-"
            "allocation-even-when-positive-live-debt-releases-on-nonreserved-stream;refresh-only-"
            "for-defense-pending-continuation-or-tagged-continuation-still-queued-for-allocation;"
            "retryable-unadvertised-continuation-allocation-rollback-or-requeue-reconstitutes-"
            "corresponding-horizon-reserve-before-further-base-allocation"
        ),
    }
    """
    continuation_invariant = receipt["fitting_contract"]["constants"]["walkie_talkie"][
        "prepared_receiver_continuation_invariant"
    ]
    assert (
        continuation_invariant
        == fitting_module._fitting_contract(WORKLOADS)["constants"]["walkie_talkie"][
            "prepared_receiver_continuation_invariant"
        ]
    )
    assert continuation_invariant["base_release_condition"] == (
        "issued-base-events-controller-requested-and-request-signals-observed-and-(all-base-"
        "events-issued-or-real-reported-nonreserved-capacity<packet_size)"
    )
    assert continuation_invariant["early_release_capacity_snapshot_policy"] == (
        "incoming-capacity-must-have-real-reported-snapshot;unknown-capacity-never-enables-"
        "early-continuation-release"
    )
    assert continuation_invariant["pending_advertisement_coalescing_policy"] == (
        "retain-oldest-reserve-and-defer-continuation-while-exact-single-pending-candidate-"
        "exists;after-max-stream-data-advertisement-prefer-coalesced-append;fallback-to-oldest-"
        "reserve-only-when-no-pending-candidate"
    )
    """Historical literal retained as non-executing audit text.
    {
        "action_ordering": (
            "provision-to-configured-chaff-stream-limit;encode-zero-required-insert-count-"
            "nonblocking-qpack-chaff-header-blocks;transmit-positive-final-size-contiguous-[0,"
            "final-size)-plus-fin-under-due-molded-outgoing-actions;peer-acknowledge-contiguous-"
            "[0,final-size)-plus-fin;require-current-receiver-continuation-reserve-horizon-plus-"
            "one-survivors-before-first-base-allocation;reserve-current-receiver-continuation-"
            "horizon;release-continuation-after-base-release"
        ),
        "adapted_target_formula": "sealed_symmetric_envelope_cells*packet_size+packet_size",
        "allocation_policy": (
            "one-whole-packet_size-cell-to-one-peer-acknowledged-pristine-header-phase-"
            "controlled-chaff-stream"
        ),
        "base_release_condition": (
            "all-base-events-controller-requested-and-request-signals-observed"
        ),
        "base_capacity_policy": (
            "protected-reserve-exact-capacity-excluded-from-ordinary-base-allocation-and-"
            "capacity-availability"
        ),
        "batch_end_release_condition": (
            "application-batch-complete-at-molded-batch-end;otherwise-no-batch-completion-gate"
        ),
        "chaff_capacity_requirement": (
            "selected-peer-acknowledged-pristine-header-phase-controlled-chaff-exact-available-"
            "bytes>=packet_size"
        ),
        "claim_policy": "provisional-framing-claims-are-ineligible",
        "common_header_phase_candidate_definition": (
            "role=chaff;status=none;receive_state=ReceivingHeaders;consumed_bytes=0;"
            "requested_bytes=advertised_bytes<=parser_allowance_ceiling_bytes;"
            "reservation_available=reservation_capacity;framing_bytes=0;parser_lease_used=0;"
            "last_parser_lease_boundary=none;pending_parser_boundary=none;"
            "qpack_required_insert_count=0;request_final_size>0;"
            "wire_activation=contiguous-[0,final_size)-plus-fin-peer-acknowledged"
        ),
        "exact_capacity_requirement": (
            "known_limit>=packet_size;known_limit-requested_bytes>=packet_size"
        ),
        "failure_policy": (
            "source-envelope-overflow-or-continuation-precondition-failure-is-fidelity-ineligible"
        ),
        "fitting_input_support": "sealed-envelope-and-matching-statistics-only",
        "live_component_bound": ("source_raw_bytes<=sealed_symmetric_envelope_cells*packet_size"),
        "outstanding_release_condition": (
            "live-unconsumed-base-bytes<=parser_allowance_ceiling_bytes"
        ),
        "positive_outstanding_selection": (
            "require-all-live-unconsumed-base-bytes-coalesced-on-one-peer-acknowledged-"
            "nonreserved-pristine-header-phase-chaff-whose-advertised-minus-consumed-exactly-"
            "equals-live"
        ),
        "prefix_consumability_precondition": (
            "selected-stream-first-(prior_requested_bytes+packet_size)-raw-response-bytes-are-"
            "consumable"
        ),
        "retry_ledger_policy": (
            "recompute-live-unconsumed-base-bytes-from-prior-credit-ledger-on-every-retry-"
            "excluding-continuation-slot"
        ),
        "request_retransmission_deduplication": (
            "union-peer-acknowledged-request-stream-offset-ranges;duplicate-acknowledged-offsets-"
            "do-not-advance-activation"
        ),
        "reserve_horizon_capacity_requirement": (
            "maximum_reserve_horizon+1<=configured_chaff_stream_limit"
        ),
        "request_prefix_fit_requirement": (
            "required-preprovisioned-chaff-request-stream-frames-through-fin-fit-within-residual-"
            "normal-priority-stream-data-budget-after-higher-priority-due-application-stream-"
            "frames-at-each-positive-outgoing-horizon-start"
        ),
        "request_activation_policy": (
            "zero-required-insert-count-nonblocking-qpack-chaff-header-block;positive-final-size-"
            "with-contiguous-unique-request-stream-offsets-[0,final-size)-and-fin-peer-"
            "acknowledged-under-molded-outgoing-cells"
        ),
        "causal_capacity_precondition": (
            "first-molded-component-outgoing>0;max_chaff_streams>=maximum-receiver-continuation-"
            "reserve-horizon+1;required-preprovisioned-chaff-request-stream-frames-through-fin-"
            "fit-within-residual-normal-priority-stream-data-budget-after-higher-priority-due-"
            "application-stream-frames-at-each-positive-outgoing-horizon-start"
        ),
        "request_prefix_delivery_precondition": (
            "before-each-incoming-component-first-base-allocation-peer-acknowledged-nonblocking-"
            "chaff-request-survivors>=current-receiver-continuation-reserve-horizon+1"
        ),
        "post_outgoing_loss_liveness_limitation": (
            "insufficient-peer-acknowledged-survivors-after-positive-outgoing-targets-resolve-"
            "hold-base-and-continuation-allocation;no-targetless-chaff-stream-retransmission-or-"
            "generic-loss-liveness-guarantee"
        ),
        "reserve_horizon_count_formula": "count-nonzero-incoming-components-in-reserve-horizon",
        "reserve_horizon_definition": (
            "current-nonzero-incoming-component-plus-consecutive-nonzero-incoming-components-"
            "before-next-positive-outgoing-component"
        ),
        "reserve_lifetime": (
            "exclude-each-reserved-candidate-from-base-allocation-until-corresponding-"
            "continuation-release-or-session-or-endpoint-end"
        ),
        "reserve_discharge_policy": (
            "remove-exactly-first-reserve-once-at-corresponding-continuation-controller-"
            "allocation-even-when-positive-live-debt-releases-on-nonreserved-stream"
        ),
        "reserve_loss_policy": (
            "endpoint-or-stream-loss-before-release-requires-equivalent-acknowledged-pristine-"
            "replacement-before-further-base-allocation-or-fails-closed"
        ),
        "reserve_refresh_policy": (
            "refresh-only-for-defense-pending-continuation-or-tagged-continuation-still-queued-"
            "for-allocation"
        ),
        "reserve_rollback_policy": (
            "retryable-unadvertised-continuation-allocation-rollback-or-requeue-reconstitutes-"
            "corresponding-horizon-reserve-before-further-base-allocation"
        ),
        "runtime_not_fitting_observed": (
            "provisioning-peer-acknowledgement-reservation-and-runtime-created-chaff-prefix"
        ),
        "resource_precondition": (
            "initial-chaff-selection-yields-known-valid-dependency-free-same-origin-resource-"
            "with-effective-length>=raw-headroom-bytes-per-nonzero-incoming-component"
        ),
        "initial_mold_causal_requirement": "first-molded-component-outgoing>0",
        "scope": (
            "prepared-frozen-research-cohort-and-reviewed-live-fixture-under-listed-preconditions"
        ),
        "zero_outstanding_selection": (
            "when-live-unconsumed-base-is-zero-use-corresponding-retained-peer-acknowledged-"
            "reserved-pristine-header-phase-chaff-with-requested_bytes=0"
        ),
    }
    """
    assert "residual_reallocation" not in continuation_invariant
    assert "residual_coalescence" not in continuation_invariant
    assert walkie["generated_by"].startswith(
        "qcsd_lab.fitting_walkie_talkie 2.4.1; algorithm_receipt_sha256="
    )
    assert str(tmp_path) not in receipt_text
    assert "timestamp" not in receipt_text
    bundle_link = tmp_path / "research-bundle-link"
    bundle_link.symlink_to(first, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic link"):
        _inspect_test_or_verify_historical_bundle(bundle_link)

    assert (result / "experiment.json").read_bytes() == before_experiment
    assert (result / "evidence.sha256").read_bytes() == before_evidence
    verify_result(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_type", "qcsd-research-defense-bundle"),
        ("status", fitting_module.RESEARCH_ARTIFACT_STATUS),
        ("production_ready", True),
    ],
)
def test_structural_inspector_rejects_authoritative_discriminator_claims(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    result = _make_fitting_result(tmp_path / "source")
    bundle = _fit_result(result, artifacts_root=tmp_path / "artifacts")
    provenance = json.loads((bundle / "provenance.json").read_text(encoding="utf-8"))
    provenance[field] = value
    atomic_json(bundle / "provenance.json", provenance)

    with pytest.raises(ValueError, match="authoritative production claim"):
        _inspect_structural_artifact_bundle(bundle)


def test_runtime_receipt_rejects_schema_six_capacity_diagnostic_tampering(
    fitted_bundle: Path, tmp_path: Path
) -> None:
    changed = tmp_path / "changed"
    shutil.copytree(fitted_bundle, changed)
    provenance_path = changed / "provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    diagnostic = provenance["runtime_qualification_inputs"][
        "schema_six_capacity_falsification_diagnostic"
    ]
    assert diagnostic == _schema_six_capacity_falsification_diagnostic_receipt()
    diagnostic["attempts"] = 2
    atomic_json(provenance_path, provenance)

    with pytest.raises(ValueError, match="schema-six capacity falsification diagnostic"):
        _inspect_structural_artifact_bundle(changed)


def test_runtime_receipt_rejects_schema_six_runtime_diagnostic_tampering(
    fitted_bundle: Path, tmp_path: Path
) -> None:
    changed = tmp_path / "changed"
    shutil.copytree(fitted_bundle, changed)
    provenance_path = changed / "provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    diagnostic = provenance["runtime_qualification_inputs"][
        "schema_six_runtime_falsification_diagnostic"
    ]

    assert diagnostic == _schema_six_runtime_falsification_diagnostic_receipt()
    diagnostic["recovered_retries"][1]["accepted_attempt"] = False
    atomic_json(provenance_path, provenance)

    with pytest.raises(ValueError, match="schema-six runtime falsification diagnostic"):
        _inspect_structural_artifact_bundle(changed)


def test_runtime_receipt_rejects_sender_framing_diagnostic_tampering(
    fitted_bundle: Path, tmp_path: Path
) -> None:
    changed = tmp_path / "changed"
    shutil.copytree(fitted_bundle, changed)
    provenance_path = changed / "provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    diagnostic = provenance["runtime_qualification_inputs"][
        "schema_two_sender_framing_falsification_diagnostic"
    ]
    assert diagnostic == _schema_two_sender_framing_falsification_diagnostic_receipt()
    diagnostic["packets_sha256"] = "0" * 64
    atomic_json(provenance_path, provenance)

    with pytest.raises(ValueError, match="schema-two sender-framing falsification diagnostic"):
        _inspect_structural_artifact_bundle(changed)


@pytest.mark.parametrize(
    ("field", "value"),
    [("failed_run_index", False), ("qualification_bytes_excluded", 1)],
)
def test_runtime_receipt_rejects_sender_framing_diagnostic_boolean_aliases(
    fitted_bundle: Path, tmp_path: Path, field: str, value: object
) -> None:
    changed = tmp_path / "changed"
    shutil.copytree(fitted_bundle, changed)
    provenance_path = changed / "provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    diagnostic = provenance["runtime_qualification_inputs"][
        "schema_two_sender_framing_falsification_diagnostic"
    ]
    diagnostic[field] = value
    atomic_json(provenance_path, provenance)

    with pytest.raises(ValueError, match="schema-two sender-framing falsification diagnostic"):
        _inspect_structural_artifact_bundle(changed)


def test_legacy_v2_bundle_is_strictly_readable_only_as_historical_evidence(
    tmp_path: Path,
    fitted_bundle: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = _legacy_bundle_from_current(fitted_bundle, tmp_path / "research-1200")

    def unexpected_rust_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the v5 Rust parser must not adjudicate a legacy v2 bundle")

    monkeypatch.setattr(
        fitting_module,
        "_run_rust_parameter_validator",
        unexpected_rust_call,
    )
    verified = _inspect_test_or_verify_historical_bundle(legacy)
    assert verified.provenance["fitting_contract"]["contract_version"] == 2

    walkie_path = legacy / "walkie-talkie.json"
    provenance_path = legacy / "provenance.json"
    with pytest.raises(ValueError, match="frozen read-only evidence"):
        validate_parameter_artifact(
            walkie_path,
            provenance_path=provenance_path,
            expected_kind="walkie_talkie",
            expected_qcsd_profile="research-1200",
            expected_udp_payload_ceiling=1_200,
            expected_workloads=set(WORKLOADS),
        )
    frozen_arguments = {
        "provenance_path": provenance_path,
        "original_parameter_name": "walkie-talkie.json",
        "expected_kind": "walkie_talkie",
        "allow_reviewed_fixture": False,
        "expected_qcsd_profile": "research-1200",
        "expected_udp_payload_ceiling": 1_200,
        "expected_workloads": set(WORKLOADS),
    }
    with pytest.raises(ValueError, match="frozen read-only evidence"):
        validate_frozen_parameter_artifact(walkie_path, **frozen_arguments)
    frozen = validate_frozen_parameter_artifact(
        walkie_path,
        **frozen_arguments,
        allow_historical_research_bundle=True,
    )
    assert frozen.input_policy == "sealed-fitting-result-v1"

    walkie = json.loads(walkie_path.read_text(encoding="utf-8"))
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    walkie["profiles"][0]["total_scheduled_bytes"] += 1_200
    atomic_json(walkie_path, walkie)
    provenance["artifacts"]["walkie_talkie"]["sha256"] = sha256_file(walkie_path)
    atomic_json(provenance_path, provenance)
    with pytest.raises(ValueError, match="not derived from training visits"):
        _inspect_test_or_verify_historical_bundle(legacy)


def test_sealed_contract_five_bundle_and_result_are_historical_read_only() -> None:
    bundle = REPOSITORY_ROOT / "artifacts/research-1200-superseded-schema5-0a141768"
    verified_bundle = _strict_verify_artifact_bundle(bundle)
    assert verified_bundle.provenance["fitting_contract"]["contract_version"] == 5
    assert sha256_file(bundle / "provenance.json") == (
        "0a141768487ed662607ee41fa2d439a491f02315376b68fed2fb5555d0884569"
    )
    assert sha256_file(bundle / "walkie-talkie.json") == (
        "16dc343e233f7531277d96fd914d177202e7a508a50f7becdf2d8c0102b8446c"
    )
    with pytest.raises(ValueError, match="frozen read-only evidence"):
        validate_parameter_artifact(
            bundle / "walkie-talkie.json",
            provenance_path=bundle / "provenance.json",
            expected_kind="walkie_talkie",
            expected_qcsd_profile="research-1200",
            expected_udp_payload_ceiling=1_200,
        )

    result = REPOSITORY_ROOT / "results/research-smoke-1200/20260813T111550.268124Z"
    assert sha256_file(result / "evidence.sha256") == (
        "161de34c5b8a6eda1b4eb82e2925735805cd18bec167e25c0dc2d2a6e79c7214"
    )
    assert sha256_file(result / "experiment.json") == (
        "42e3721522f9c97a920eae17a4cf6945fd93a738367f95b4431b9d2e95e6beb9"
    )
    verified_result = verify_result(result)
    assert verified_result.experiment["status"] == "incomplete"
    assert verified_result.experiment["summary"] == {
        "accepted": 12,
        "eligible": 12,
        "failed": 2,
        "passed": False,
        "planned": 14,
    }


def test_historical_schema_two_walkie_talkie_skips_schema_five_resource_preflight(
    tmp_path: Path,
    fitted_bundle: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = _legacy_bundle_from_current(fitted_bundle, tmp_path / "research-1200")
    parameter = legacy / "walkie-talkie.json"
    provenance = legacy / "provenance.json"

    def unexpected_preflight(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("historical schema two must not acquire schema-five prerequisites")

    monkeypatch.setattr(
        orchestrator,
        "_validate_walkie_talkie_resource_preconditions",
        unexpected_preflight,
    )
    artifact = validate_frozen_parameter_artifact(
        parameter,
        provenance_path=provenance,
        original_parameter_name="walkie-talkie.json",
        expected_kind="walkie_talkie",
        allow_reviewed_fixture=False,
        expected_qcsd_profile="research-1200",
        expected_udp_payload_ceiling=1_200,
        expected_workloads=set(WORKLOADS),
        allow_historical_research_bundle=True,
    )
    defense = Defense(
        "walkie-talkie",
        "walkie_talkie",
        False,
        parameters_path=artifact.path,
    )
    assert not orchestrator._uses_schema_six_walkie_talkie(defense)


def test_sealed_historical_schema_two_result_verifies_but_cannot_resume(
    tmp_path: Path,
    fitted_bundle: Path,
) -> None:
    root = tmp_path / "historical-result"
    inputs = root / "inputs"
    workloads = inputs / "workloads"
    workloads.mkdir(parents=True)
    source_workloads = fitted_bundle.parents[1] / "source/config/workloads"
    for workload in WORKLOADS:
        shutil.copy2(source_workloads / f"{workload}.json", workloads / f"{workload}.json")
    _legacy_bundle_from_current(
        fitted_bundle,
        inputs / "defense-parameters/research-1200",
    )
    atomic_text(
        inputs / "campaign.yml",
        "schema: 1\n"
        "name: historical-evaluation\n"
        "purpose: evaluation\n"
        "seed: 2\n"
        "profile: research-1200\n"
        "workloads:\n"
        + "".join(f"  {workload}: 1\n" for workload in WORKLOADS)
        + "request_policies:\n"
        "  - as-defined\n"
        "defenses:\n"
        "  - name: walkie-talkie\n"
        "    kind: walkie_talkie\n"
        "    parameters: ../../artifacts/research-1200/walkie-talkie.json\n",
    )
    campaign = orchestrator._load_campaign(
        inputs / "campaign.yml",
        frozen_inputs=inputs,
        allow_historical_research_bundle=True,
    )
    source = _source("a")
    configuration = orchestrator._frozen_configuration(root, campaign)
    experiment = initialize_experiment(
        root,
        name=campaign.name,
        purpose=campaign.purpose,
        run_id="historical-result",
        source=source,
        configuration=configuration,
        samples=orchestrator.plan_campaign(campaign),
        started_at="2026-08-12T00:00:00+00:00",
    )
    finalize_experiment(
        root,
        experiment,
        status="incomplete",
        completed_at="2026-08-12T00:01:00+00:00",
    )
    checksums = {
        relative: sha256_file(path) for relative, path in authoritative_files(root).items()
    }
    atomic_text(
        root / "evidence.sha256",
        "".join(f"{checksums[path]}  {path}\n" for path in sorted(checksums)),
    )

    verified = verify_result(root)
    assert verified.experiment["status"] == "incomplete"
    before = (root / "evidence.sha256").read_bytes()
    with pytest.raises(ValueError, match="frozen read-only evidence"):
        prepare_resume(root)
    assert (root / "evidence.sha256").read_bytes() == before


@pytest.mark.parametrize("legacy_contract", [False, True])
def test_bundle_contract_rejects_mixed_walkie_talkie_schema_versions(
    tmp_path: Path,
    fitted_bundle: Path,
    legacy_contract: bool,
) -> None:
    if legacy_contract:
        bundle = _legacy_bundle_from_current(fitted_bundle, tmp_path / "legacy")
        wrong_schema = 4
    else:
        bundle = tmp_path / "current"
        shutil.copytree(fitted_bundle, bundle)
        wrong_schema = 3
    walkie_path = bundle / "walkie-talkie.json"
    provenance_path = bundle / "provenance.json"
    walkie = json.loads(walkie_path.read_text(encoding="utf-8"))
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    walkie["schema_version"] = wrong_schema
    atomic_json(walkie_path, walkie)
    provenance["artifacts"]["walkie_talkie"]["sha256"] = sha256_file(walkie_path)
    atomic_json(provenance_path, provenance)

    with pytest.raises(ValueError, match="invalid runtime contract"):
        _inspect_test_or_verify_historical_bundle(bundle)


@pytest.mark.parametrize("contract_version", [3, 4])
def test_superseded_contract_is_not_historical_evidence(
    tmp_path: Path,
    fitted_bundle: Path,
    contract_version: int,
) -> None:
    bundle = tmp_path / f"superseded-contract-{contract_version}"
    shutil.copytree(fitted_bundle, bundle)
    provenance_path = bundle / "provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    provenance["fitting_contract"]["contract_version"] = contract_version
    atomic_json(provenance_path, provenance)

    with pytest.raises(ValueError, match="fitting contract receipt is invalid"):
        _inspect_test_or_verify_historical_bundle(bundle)


def test_subset_campaign_does_not_permit_partial_bundle_coverage(
    tmp_path: Path, fitted_bundle: Path
) -> None:
    bundle = tmp_path / "research-1200"
    shutil.copytree(fitted_bundle, bundle)
    traffic_path = bundle / "traffic-morphing.json"
    provenance_path = bundle / "provenance.json"
    traffic = json.loads(traffic_path.read_text(encoding="utf-8"))
    traffic["profiles"].pop()
    atomic_json(traffic_path, traffic)
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    provenance["artifacts"]["traffic_morphing"]["sha256"] = sha256_file(traffic_path)
    atomic_json(provenance_path, provenance)

    with pytest.raises(ValueError):
        validate_parameter_artifact(
            traffic_path,
            provenance_path=provenance_path,
            expected_kind="traffic_morphing",
            expected_qcsd_profile="research-1200",
            expected_udp_payload_ceiling=1_200,
            expected_workloads=set(WORKLOADS[:-1]),
        )


def test_every_artifact_schema_leaf_is_bound_by_the_common_receipt(
    fitted_bundle: Path,
) -> None:
    """One representative of every recursive JSON field must break its file hash."""

    for filename in ("traffic-morphing.json", "wtf-pad.json", "walkie-talkie.json"):
        path = fitted_bundle / filename
        original = json.loads(path.read_text(encoding="utf-8"))
        cases = _representative_leaf_paths(original)
        assert cases, filename
        try:
            for leaf_path, leaf in cases:
                atomic_json(path, _replace_leaf(original, leaf_path, _alternate_leaf(leaf)))
                with pytest.raises(ValueError, match="hash mismatch") as rejected:
                    _inspect_test_or_verify_historical_bundle(fitted_bundle)
                assert filename in str(rejected.value), _display_path(leaf_path)
        finally:
            atomic_json(path, original)
    _inspect_test_or_verify_historical_bundle(fitted_bundle)


def test_every_internally_bound_provenance_leaf_rejects_single_field_tampering(
    fitted_bundle: Path,
) -> None:
    """Exercise every receipt field except claims sealed by its external SHA only."""

    provenance_path = fitted_bundle / "provenance.json"
    original = json.loads(provenance_path.read_text(encoding="utf-8"))
    # These identify the source result.  No self-hashing JSON receipt can
    # authenticate them; callers preserve the printed provenance SHA-256 as the
    # external seal.  Relational/fixed source fields remain in the rejection set.
    externally_sealed = {
        ("source_result", "campaign"),
        ("source_result", "campaign_sha256"),
        ("source_result", "evidence_sha256"),
        ("source_result", "experiment_sha256"),
        ("source_result", "input_digest"),
        ("source_result", "source_fingerprints", "image_digest"),
        ("source_result", "source_fingerprints", "lab_commit"),
        ("runtime_qualification_inputs", "workloads", 0, "application_workload_sha256"),
    }
    cases = [
        (leaf_path, leaf)
        for leaf_path, leaf in _representative_leaf_paths(original)
        if leaf_path not in externally_sealed
    ]
    assert cases
    try:
        for leaf_path, leaf in cases:
            atomic_json(
                provenance_path,
                _replace_leaf(original, leaf_path, _alternate_leaf(leaf)),
            )
            with pytest.raises(ValueError):
                _inspect_test_or_verify_historical_bundle(fitted_bundle)
    finally:
        atomic_json(provenance_path, original)
    _inspect_test_or_verify_historical_bundle(fitted_bundle)


def test_external_source_claim_tampering_changes_the_recordable_receipt_hash(
    fitted_bundle: Path,
) -> None:
    provenance_path = fitted_bundle / "provenance.json"
    original_bytes = provenance_path.read_bytes()
    original = json.loads(original_bytes)
    original_sha256 = sha256_file(provenance_path)
    try:
        for leaf_path in (
            ("source_result", "campaign"),
            ("source_result", "campaign_sha256"),
            ("source_result", "evidence_sha256"),
            ("source_result", "experiment_sha256"),
            ("source_result", "input_digest"),
            ("source_result", "source_fingerprints", "image_digest"),
            ("source_result", "source_fingerprints", "lab_commit"),
        ):
            cursor: Any = original
            for part in leaf_path:
                cursor = cursor[part]
            atomic_json(
                provenance_path,
                _replace_leaf(original, leaf_path, _alternate_leaf(cursor)),
            )
            assert sha256_file(provenance_path) != original_sha256
    finally:
        provenance_path.write_bytes(original_bytes)
    assert sha256_file(provenance_path) == original_sha256


@pytest.mark.parametrize(
    ("filename", "leaf_path"),
    [
        (
            "traffic-morphing.json",
            ("profiles", 0, "outgoing", "expected_added_bytes"),
        ),
        ("wtf-pad.json", ("outgoing", "burst", "infinity_tokens")),
        ("wtf-pad.json", ("fitted_from",)),
        ("walkie-talkie.json", ("profiles", 0, "total_scheduled_bytes")),
        (
            "walkie-talkie.json",
            ("profiles", 0, "training_inputs", "real", 0),
        ),
        (
            "walkie-talkie.json",
            ("receiver_continuation", "cells_per_nonzero_incoming_component"),
        ),
    ],
)
def test_python_verification_recomputes_derived_artifact_values_before_rust(
    fitted_bundle: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    leaf_path: tuple[str | int, ...],
) -> None:
    """Coherent file/receipt rehashing must still fail the independent Python oracle."""

    artifact_path = fitted_bundle / filename
    provenance_path = fitted_bundle / "provenance.json"
    original_artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    original_provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    cursor: Any = original_artifact
    for part in leaf_path:
        cursor = cursor[part]
    changed = _replace_leaf(original_artifact, leaf_path, _alternate_leaf(cursor))
    atomic_json(artifact_path, changed)
    provenance = copy.deepcopy(original_provenance)
    kind = {
        "traffic-morphing.json": "traffic_morphing",
        "wtf-pad.json": "wtf_pad",
        "walkie-talkie.json": "walkie_talkie",
    }[filename]
    provenance["artifacts"][kind]["sha256"] = sha256_file(artifact_path)
    atomic_json(provenance_path, provenance)

    def unexpected_rust_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Python accepted a derived-value tamper and delegated it to Rust")

    monkeypatch.setattr(
        fitting_module,
        "_run_rust_parameter_validator",
        unexpected_rust_call,
    )
    try:
        with pytest.raises(ValueError):
            _inspect_test_or_verify_historical_bundle(fitted_bundle)
    finally:
        atomic_json(artifact_path, original_artifact)
        atomic_json(provenance_path, original_provenance)


def test_bundle_tamper_and_extra_file_are_rejected(tmp_path: Path) -> None:
    result = _make_fitting_result(tmp_path / "source")
    bundle = _fit_result(result, artifacts_root=tmp_path / "artifacts")
    traffic = bundle / "traffic-morphing.json"
    traffic.write_bytes(traffic.read_bytes() + b" ")
    with pytest.raises(ValueError, match="hash mismatch"):
        _inspect_test_or_verify_historical_bundle(bundle)

    traffic.write_bytes(traffic.read_bytes()[:-1])
    atomic_text(bundle / "unexpected.txt", "not authoritative\n")
    with pytest.raises(ValueError, match="file set mismatch"):
        _inspect_test_or_verify_historical_bundle(bundle)
    (bundle / "unexpected.txt").unlink()

    provenance_path = bundle / "provenance.json"
    pristine_provenance = provenance_path.read_bytes()
    provenance = json.loads(pristine_provenance)
    selected_edges = {
        (item["source"], item["target"])
        for item in provenance["algorithms"]["traffic_morphing"]["selected_mapping"]
    }
    rejected = next(
        item
        for item in provenance["algorithms"]["traffic_morphing"]["candidate_costs"]
        if (item["source"], item["target"]) not in selected_edges
    )
    rejected["estimated_added_bytes"] += 1
    atomic_json(provenance_path, provenance)
    with pytest.raises(ValueError, match="does not bind its algorithm receipt"):
        _inspect_test_or_verify_historical_bundle(bundle)

    provenance_path.write_bytes(pristine_provenance)
    provenance = json.loads(pristine_provenance)
    provenance["algorithms"]["traffic_morphing"]["selected_mapping"][0]["l1_cost"] += 0.25
    atomic_json(provenance_path, provenance)
    with pytest.raises(ValueError, match="selected costs disagree|fidelity cost"):
        _inspect_test_or_verify_historical_bundle(bundle)

    provenance_path.write_bytes(pristine_provenance)
    provenance = json.loads(pristine_provenance)
    first_workload = provenance["sample_contributions"][0]
    first_workload["policies"]["half-duplex"][0]["sample_id"] = first_workload["policies"][
        "as-defined"
    ][0]["sample_id"]
    atomic_json(provenance_path, provenance)
    with pytest.raises(ValueError, match="training-input digest|globally unique"):
        _inspect_test_or_verify_historical_bundle(bundle)

    provenance_path.write_bytes(pristine_provenance)
    provenance = json.loads(pristine_provenance)
    provenance["source_result"]["source_fingerprints"]["lab_dirty"] = True
    atomic_json(provenance_path, provenance)
    with pytest.raises(ValueError, match="clean lab and Neqo"):
        _inspect_test_or_verify_historical_bundle(bundle)


def test_events_only_extractor_excludes_cover_handshake_tail_and_out_of_window_batches(
    tmp_path: Path,
) -> None:
    result = _make_fitting_result(tmp_path / "source")
    fitting = validate_fitting_result(result)
    trace = fitting.as_defined[WORKLOADS[0]][0]
    assert len(trace.packets) == len(_packet_values(0, 0))
    assert 1_200 not in [packet.length_bytes for packet in trace.packets]
    assert 1_199 not in [packet.length_bytes for packet in trace.packets]
    assert 1_198 not in [packet.length_bytes for packet in trace.packets]
    half_duplex = fitting.half_duplex[WORKLOADS[0]][0]
    kinds = [observation.kind for observation in half_duplex.observations]
    assert kinds.count("application_batch_started") == 1
    assert kinds.count("application_batch_completed") == 1


def test_packets_csv_cannot_influence_fitted_artifact_bytes_but_tampering_still_fails(
    tmp_path: Path,
) -> None:
    ordinary = _make_fitting_result(tmp_path / "ordinary")
    conflicting = _make_fitting_result(tmp_path / "conflicting", conflicting_packets_csv=True)
    ordinary_bundle = _fit_result(ordinary, artifacts_root=tmp_path / "ordinary-artifacts")
    conflicting_bundle = _fit_result(conflicting, artifacts_root=tmp_path / "conflicting-artifacts")
    for filename in ("traffic-morphing.json", "wtf-pad.json", "walkie-talkie.json"):
        assert (ordinary_bundle / filename).read_bytes() == (
            conflicting_bundle / filename
        ).read_bytes()

    packets = ordinary / "samples/alpha/as-defined/visit-000/undefended/neqo/packets.csv"
    packets.write_bytes(packets.read_bytes() + b"tamper")
    with pytest.raises(ValueError, match="modified authoritative evidence"):
        verify_result(ordinary)


def test_existing_different_valid_bundle_is_a_collision(tmp_path: Path) -> None:
    first_result = _make_fitting_result(tmp_path / "one", source_marker="a")
    second_result = _make_fitting_result(tmp_path / "two", source_marker="b")
    artifacts = tmp_path / "artifacts"
    _fit_result(first_result, artifacts_root=artifacts)
    with pytest.raises(FileExistsError, match="different content"):
        _fit_result(second_result, artifacts_root=artifacts)


@pytest.mark.parametrize("linked_component", ["leaf", "ancestor"])
def test_authoritative_fit_artifact_root_rejects_symlinks(
    tmp_path: Path, linked_component: str
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    if linked_component == "leaf":
        supplied = tmp_path / "artifacts"
        supplied.symlink_to(real, target_is_directory=True)
    else:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "artifacts").mkdir()
        linked_parent = tmp_path / "linked-parent"
        linked_parent.symlink_to(outside, target_is_directory=True)
        supplied = linked_parent / "artifacts"

    with pytest.raises(ValueError, match="symbolic link"):
        fitting_module._regular_artifacts_root(supplied)


def _write_candidate_bundle(root: Path, marker: bytes) -> None:
    root.mkdir()
    for filename in EXACT_BUNDLE_FILES:
        (root / filename).write_bytes(marker + filename.encode())


def test_bundle_publication_is_noreplace_and_fsyncs_candidate_and_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "candidate"
    destination = tmp_path / "research-1200"
    _write_candidate_bundle(candidate, b"one:")
    synced: list[Path] = []
    monkeypatch.setattr(fitting_module, "_fsync_directory", synced.append)
    monkeypatch.setattr(
        fitting_module,
        "verify_artifact_bundle",
        lambda root: SimpleNamespace(root=root),
    )

    assert fitting_module._publish_bundle_candidate(candidate, destination) == destination
    assert not candidate.exists()
    assert destination.is_dir()
    assert synced == [candidate, tmp_path]


def test_bundle_publication_recovers_only_byte_identical_existing_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "candidate"
    destination = tmp_path / "research-1200"
    _write_candidate_bundle(candidate, b"same:")
    _write_candidate_bundle(destination, b"same:")
    synced: list[Path] = []
    monkeypatch.setattr(fitting_module, "_fsync_directory", synced.append)
    monkeypatch.setattr(
        fitting_module,
        "verify_artifact_bundle",
        lambda root: SimpleNamespace(root=root),
    )

    assert fitting_module._publish_bundle_candidate(candidate, destination) == destination
    assert candidate.is_dir()
    assert synced == [candidate, tmp_path]

    (candidate / "provenance.json").write_bytes(b"different")
    with pytest.raises(FileExistsError, match="different content"):
        fitting_module._publish_bundle_candidate(candidate, destination)


def test_bundle_publication_never_replaces_empty_raced_destination(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    destination = tmp_path / "research-1200"
    _write_candidate_bundle(candidate, b"candidate:")
    destination.mkdir()

    with pytest.raises(FileExistsError, match="not an exact valid bundle"):
        fitting_module._publish_bundle_candidate(candidate, destination)
    assert candidate.is_dir()
    assert destination.is_dir()
    assert not list(destination.iterdir())


def test_schema_six_scope_excludes_controlled_wire_smoke_from_fitting() -> None:
    current = fitting_module._fitting_contract(WORKLOADS)["constants"]["walkie_talkie"]
    historical = fitting_module._contract_five_fitting_contract(WORKLOADS)["constants"][
        "walkie_talkie"
    ]
    assert current["prepared_receiver_continuation_invariant"]["scope"] == (
        "exact-qualified-frozen-six-workload-research-cohort-with-exact-frozen-request-headers-"
        "selected-resource-response-identities-current-producer-and-current-qualifier-under-"
        "listed-preconditions-not-a-universal-origin-guarantee;"
        "controlled-wire-smoke-is-explicitly-nonauthoritative-and-excluded-from-fitting"
    )
    assert historical["prepared_receiver_continuation_invariant"]["scope"] == (
        "prepared-frozen-research-cohort-and-reviewed-live-fixture-under-listed-preconditions"
    )


def test_fitting_campaign_rejects_the_wrong_workload_cardinality(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="exactly six unique workloads"):
        _make_fitting_result(tmp_path / "source", workloads=WORKLOADS[:-1])
