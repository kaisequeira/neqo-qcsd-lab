import json
from hashlib import sha256
from pathlib import Path

import pytest

from qcsd_lab.parameters import validate_parameter_artifact
from qcsd_lab.util import atomic_json, atomic_text, sha256_file, write_checksums


def test_sealed_runtime_bundle_revalidates_source_campaigns(tmp_path):
    evidence = _sealed_campaign(
        tmp_path / "training",
        [("source", "monitored", 0), ("target", "unmonitored", 0)],
    )
    parameter, provenance = _morphing_bundle(
        tmp_path,
        source=[evidence["source"][0]],
        target=[evidence["target"][0]],
    )

    artifact = validate_parameter_artifact(
        parameter,
        provenance_path=provenance,
        expected_kind="traffic_morphing",
        expected_qcsd_profile="live",
        expected_udp_payload_ceiling=1200,
    )
    assert artifact.sha256 == sha256_file(parameter)
    assert artifact.input_policy == "sealed-completed-campaigns"

    trace = Path(evidence["source"][0]["path"])
    trace.write_text(trace.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="campaign cannot be verified"):
        validate_parameter_artifact(
            parameter,
            expected_kind="traffic_morphing",
            expected_qcsd_profile="live",
            expected_udp_payload_ceiling=1200,
        )


def test_sealed_runtime_bundle_rejects_duplicate_and_partial_population(tmp_path):
    evidence = _sealed_campaign(
        tmp_path / "training",
        [
            ("source", "monitored", 0),
            ("source", "monitored", 1),
            ("target", "unmonitored", 0),
        ],
    )
    parameter, provenance = _morphing_bundle(
        tmp_path,
        source=[evidence["source"][0]],
        target=[evidence["target"][0]],
    )
    with pytest.raises(ValueError, match="complete eligible train population"):
        validate_parameter_artifact(parameter, expected_kind="traffic_morphing")

    value = json.loads(provenance.read_text(encoding="utf-8"))
    value["inputs"]["source"] = [evidence["source"][0], evidence["source"][0]]
    atomic_json(provenance, value)
    with pytest.raises(ValueError, match="duplicate inputs"):
        validate_parameter_artifact(parameter, expected_kind="traffic_morphing")


def test_sealed_runtime_bundle_rejects_wrong_domain_and_generator(tmp_path):
    evidence = _sealed_campaign(
        tmp_path / "training",
        [("source", "monitored", 0), ("target", "unmonitored", 0)],
    )
    parameter, provenance = _morphing_bundle(
        tmp_path,
        source=[evidence["source"][0]],
        target=[evidence["target"][0]],
    )
    value = json.loads(provenance.read_text(encoding="utf-8"))
    value["inputs"]["source"][0]["split"] = "test"
    atomic_json(provenance, value)
    with pytest.raises(ValueError, match="wrong evidence domain"):
        validate_parameter_artifact(parameter, expected_kind="traffic_morphing")

    value["inputs"]["source"][0]["split"] = "train"
    value["generator"] = "wtfpad"
    atomic_json(provenance, value)
    with pytest.raises(ValueError, match="generator does not match"):
        validate_parameter_artifact(parameter, expected_kind="traffic_morphing")


def _sealed_campaign(
    root: Path,
    entries: list[tuple[str, str, int]],
) -> dict[str, list[dict[str, object]]]:
    root.mkdir()
    records = []
    rows: list[tuple[dict[str, object], Path, Path]] = []
    population: dict[str, list[str]] = {}
    for workload, role, repetition in entries:
        visit_id = _digest(f"visit:{workload}:{repetition}")
        population.setdefault(workload, []).append(visit_id)
        sample_id = _digest(f"sample:{workload}:{repetition}")
        relative = Path(workload) / f"visit-{repetition:05d}" / "undefended"
        neqo = root / relative / "neqo"
        neqo.mkdir(parents=True)
        trace = neqo / "packets.csv"
        trace.write_text(
            "direction,monotonic_us,connection,observed_udp_length,"
            "scheduled_target,satisfaction,slot_id\n"
            "outgoing,1000,0,1200,,unshaped,\n",
            encoding="utf-8",
        )
        run = neqo / "run.json"
        atomic_json(
            run,
            {
                "completion_status": "complete",
                "request_policy": "as-defined",
                "defense_start_monotonic_ns": 1_000_000,
                "application_completion_monotonic_ns": 2_000_000,
                "resolved_configuration": {"defense": {"kind": "none"}},
            },
        )
        source_digest = _digest(f"manifest:{workload}")
        record = {
            "path": relative.as_posix(),
            "state": "captured",
            "eligible": True,
            "fidelity_eligible": True,
            "visit_id": visit_id,
            "split_group_id": _digest(f"group:{workload}:{repetition}"),
            "sample_id": sample_id,
            "workload_id": workload,
            "source_manifest_sha256": source_digest,
            "repetition": repetition,
            "class_label": workload,
            "role": role,
            "split": "train",
            "defense": "undefended",
            "runtime_kind": "none",
        }
        records.append(record)
        rows.append((record, trace, run))

    atomic_text(
        root / "samples.jsonl",
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
    )
    atomic_json(
        root / "campaign.json",
        {
            "campaign": {
                "name": root.name,
                "stage": "parameter-fitting",
                "status": "complete",
            },
            "configuration": {
                "stage": "parameter-fitting",
                "study_id": _digest("study"),
                "seed": 7,
                "qcsd_profile": "live",
                "capture": {"udp_payload_ceiling": 1200},
                "workloads": {"request_policy": "as-defined"},
            },
            "summary": {"passed": True},
        },
    )
    write_checksums(
        root,
        [path for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS"],
    )

    campaign_sha256 = sha256_file(root / "campaign.json")
    seal_sha256 = sha256_file(root / "SHA256SUMS")
    result: dict[str, list[dict[str, object]]] = {}
    for record, trace, run in rows:
        workload = str(record["workload_id"])
        result.setdefault(workload, []).append(
            {
                "kind": "sealed-completed-campaign",
                "path": str(trace),
                "sha256": sha256_file(trace),
                "campaign_root": str(root),
                "campaign_name": root.name,
                "campaign_sha256": campaign_sha256,
                "seal_sha256": seal_sha256,
                "campaign_stage": "parameter-fitting",
                "study_id": _digest("study"),
                "visit_id": record["visit_id"],
                "split_group_id": record["split_group_id"],
                "sample_id": record["sample_id"],
                "sample_path": record["path"],
                "workload_id": workload,
                "source_manifest_sha256": record["source_manifest_sha256"],
                "repetition": record["repetition"],
                "class_label": workload,
                "role": record["role"],
                "split": "train",
                "request_policy": "as-defined",
                "qcsd_profile": "live",
                "udp_payload_ceiling": 1200,
                "split_seed": 7,
                "eligible_train_visit_ids": sorted(population[workload]),
                "defense": "undefended",
                "runtime_kind": "none",
                "view": "runner",
                "trace_format": "runner-udp-payload",
                "length_basis": "udp.payload",
                "run_path": run.relative_to(root).as_posix(),
                "run_sha256": sha256_file(run),
                "application_window_us": [1000, 2000],
            }
        )
    return result


def _morphing_bundle(
    root: Path,
    *,
    source: list[dict[str, object]],
    target: list[dict[str, object]],
) -> tuple[Path, Path]:
    parameter = root / "traffic-morphing.json"
    atomic_json(
        parameter,
        {
            "schema_version": 2,
            "adaptation": "qcsd-client-only",
            "paper_equivalent": False,
            "buckets": [1200],
            "udp_payload_ceiling": 1200,
            "profiles": [{"source": "source", "target": "target"}],
        },
    )
    provenance = parameter.with_suffix(".json.provenance.json")
    atomic_json(
        provenance,
        {
            "schema_version": 1,
            "generator": "morphing",
            "input_policy": "sealed-completed-campaigns",
            "unsealed_engineering_opt_in": False,
            "parameter_file": {
                "path": parameter.name,
                "sha256": sha256_file(parameter),
            },
            "inputs": {"source": source, "target": target},
            "analysis": {},
        },
    )
    return parameter, provenance


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()
