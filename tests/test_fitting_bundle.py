from __future__ import annotations

import copy
import csv
import io
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

import qcsd_lab.fitting as fitting_module
import qcsd_lab.orchestrator as orchestrator
from qcsd_lab.experiment import (
    accept_sample,
    checkpoint_experiment,
    finalize_experiment,
    initialize_experiment,
    transition_sample,
)
from qcsd_lab.fitting import (
    EXACT_BUNDLE_FILES,
    fit_result,
    validate_fitting_result,
    verify_artifact_bundle,
)
from qcsd_lab.parameters import validate_parameter_artifact
from qcsd_lab.util import atomic_json, atomic_text, sha256_file
from qcsd_lab.verification import seal_result, verify_result


WORKLOADS = ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot")
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


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
                {"resource_id": 0, "status": 200, "bytes": 64, "body_sha256": "f" * 64}
            ],
            "lab_source": source,
            "prepare_image_digest": source["image_digest"],
        },
        "resources": [
            {
                "id": 0,
                "url": "https://site.test/",
                "type": "Document",
                "content_length": 64,
                "data_length": 64,
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
                (74_000_000, "application_complete", {}),
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


@pytest.fixture(scope="module")
def fitted_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build one immutable synthetic bundle for exhaustive read/restore checks."""

    base = tmp_path_factory.mktemp("fitting-leaf-tamper")
    result = _make_fitting_result(base / "source")
    return fit_result(result, artifacts_root=base / "artifacts")


def test_fit_builds_exact_deterministic_bundle_without_mutating_source(tmp_path: Path) -> None:
    result = _make_fitting_result(tmp_path / "source")
    before_experiment = (result / "experiment.json").read_bytes()
    before_evidence = (result / "evidence.sha256").read_bytes()

    first = fit_result(result, artifacts_root=tmp_path / "artifacts-one")
    second = fit_result(result, artifacts_root=tmp_path / "artifacts-two")
    assert {path.name for path in first.iterdir()} == EXACT_BUNDLE_FILES
    assert [(first / filename).read_bytes() for filename in sorted(EXACT_BUNDLE_FILES)] == [
        (second / filename).read_bytes() for filename in sorted(EXACT_BUNDLE_FILES)
    ]
    assert fit_result(result, artifacts_root=tmp_path / "artifacts-one") == first

    verified = verify_artifact_bundle(first)
    assert verified.as_dict()["provenance_sha256"] == sha256_file(first / "provenance.json")
    assert set(verified.artifact_hashes) == {
        "traffic_morphing",
        "wtf_pad",
        "walkie_talkie",
    }
    receipt_text = (first / "provenance.json").read_text(encoding="utf-8")
    receipt = json.loads(receipt_text)
    assert receipt["fitting_contract"]["workload_order"] == list(WORKLOADS)
    assert str(tmp_path) not in receipt_text
    assert "timestamp" not in receipt_text
    for kind, filename in (
        ("traffic_morphing", "traffic-morphing.json"),
        ("wtf_pad", "wtf-pad.json"),
        ("walkie_talkie", "walkie-talkie.json"),
    ):
        artifact = validate_parameter_artifact(
            first / filename,
            provenance_path=first / "provenance.json",
            expected_kind=kind,
            expected_qcsd_profile="research-1200",
            expected_udp_payload_ceiling=1_200,
            expected_workloads=set(WORKLOADS),
        )
        assert artifact.input_policy == "sealed-fitting-result-v1"

    subset = set(WORKLOADS[:-1])
    for kind, filename in (
        ("traffic_morphing", "traffic-morphing.json"),
        ("wtf_pad", "wtf-pad.json"),
        ("walkie_talkie", "walkie-talkie.json"),
    ):
        artifact = validate_parameter_artifact(
            first / filename,
            provenance_path=first / "provenance.json",
            expected_kind=kind,
            expected_qcsd_profile="research-1200",
            expected_udp_payload_ceiling=1_200,
            expected_workloads=subset,
        )
        assert artifact.input_policy == "sealed-fitting-result-v1"

    with pytest.raises(
        ValueError,
        match="campaign workloads are absent from the sealed fitting cohort: unknown-site",
    ):
        validate_parameter_artifact(
            first / "walkie-talkie.json",
            provenance_path=first / "provenance.json",
            expected_kind="walkie_talkie",
            expected_qcsd_profile="research-1200",
            expected_udp_payload_ceiling=1_200,
            expected_workloads={*WORKLOADS, "unknown-site"},
        )

    bundle_link = tmp_path / "research-bundle-link"
    bundle_link.symlink_to(first, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic link"):
        verify_artifact_bundle(bundle_link)

    assert (result / "experiment.json").read_bytes() == before_experiment
    assert (result / "evidence.sha256").read_bytes() == before_evidence
    verify_result(result)


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
                    verify_artifact_bundle(fitted_bundle)
                assert filename in str(rejected.value), _display_path(leaf_path)
        finally:
            atomic_json(path, original)
    verify_artifact_bundle(fitted_bundle)


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
                verify_artifact_bundle(fitted_bundle)
    finally:
        atomic_json(provenance_path, original)
    verify_artifact_bundle(fitted_bundle)


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
            verify_artifact_bundle(fitted_bundle)
    finally:
        atomic_json(artifact_path, original_artifact)
        atomic_json(provenance_path, original_provenance)


def test_bundle_tamper_and_extra_file_are_rejected(tmp_path: Path) -> None:
    result = _make_fitting_result(tmp_path / "source")
    bundle = fit_result(result, artifacts_root=tmp_path / "artifacts")
    traffic = bundle / "traffic-morphing.json"
    traffic.write_bytes(traffic.read_bytes() + b" ")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_artifact_bundle(bundle)

    traffic.write_bytes(traffic.read_bytes()[:-1])
    atomic_text(bundle / "unexpected.txt", "not authoritative\n")
    with pytest.raises(ValueError, match="file set mismatch"):
        verify_artifact_bundle(bundle)
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
        verify_artifact_bundle(bundle)

    provenance_path.write_bytes(pristine_provenance)
    provenance = json.loads(pristine_provenance)
    provenance["algorithms"]["traffic_morphing"]["selected_mapping"][0]["l1_cost"] += 0.25
    atomic_json(provenance_path, provenance)
    with pytest.raises(ValueError, match="selected costs disagree|fidelity cost"):
        verify_artifact_bundle(bundle)

    provenance_path.write_bytes(pristine_provenance)
    provenance = json.loads(pristine_provenance)
    first_workload = provenance["sample_contributions"][0]
    first_workload["policies"]["half-duplex"][0]["sample_id"] = first_workload["policies"][
        "as-defined"
    ][0]["sample_id"]
    atomic_json(provenance_path, provenance)
    with pytest.raises(ValueError, match="training-input digest|globally unique"):
        verify_artifact_bundle(bundle)

    provenance_path.write_bytes(pristine_provenance)
    provenance = json.loads(pristine_provenance)
    provenance["source_result"]["source_fingerprints"]["lab_dirty"] = True
    atomic_json(provenance_path, provenance)
    with pytest.raises(ValueError, match="clean lab and Neqo"):
        verify_artifact_bundle(bundle)


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
    ordinary_bundle = fit_result(ordinary, artifacts_root=tmp_path / "ordinary-artifacts")
    conflicting_bundle = fit_result(conflicting, artifacts_root=tmp_path / "conflicting-artifacts")
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
    fit_result(first_result, artifacts_root=artifacts)
    with pytest.raises(FileExistsError, match="different content"):
        fit_result(second_result, artifacts_root=artifacts)


def test_fitting_campaign_rejects_the_wrong_workload_cardinality(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="exactly six unique workloads"):
        _make_fitting_result(tmp_path / "source", workloads=WORKLOADS[:-1])
