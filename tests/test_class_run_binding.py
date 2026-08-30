from __future__ import annotations

import json
from pathlib import Path

import pytest

from qcsd_lab.class_run_binding import (
    PARAMETERISED_RUNTIME_KINDS,
    WORKLOAD_SCOPED_RUNTIME_KINDS,
    resolve_class_sample_run_binding,
    validate_class_sample_run_binding,
)
from qcsd_lab.manifest import canonical_bytes, runtime_manifest
from qcsd_lab.util import sha256_file
from tests.test_class_campaign_execution import _complete_two_origin_workload


_MODES = (
    ("undefended", "none", True),
    ("static", "static", False),
    ("front", "front", False),
    ("tamaraw", "tamaraw", False),
    ("traffic-morphing", "traffic_morphing", False),
    ("wtf-pad", "wtf_pad", False),
    ("walkie-talkie", "walkie_talkie", False),
    ("buflo", "buflo", False),
    ("cs-buflo", "cs_buflo", False),
)


def _write(path: Path, value: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return path


def _fixture(tmp_path: Path, mode: str, runtime_kind: str, baseline: bool):
    source_root = tmp_path / "source"
    source_root.mkdir(parents=True)
    source = _complete_two_origin_workload(source_root, visits=1)
    root = tmp_path / "result"
    campaign = _write(root / "inputs/campaign.yml", b"schema: 2\n")
    prepared = _write(
        root / f"inputs/workloads/{source.id}.json",
        source.source_bytes,
    )
    runtime = _write(
        root / f"inputs/runtime-workloads/{source.id}.json",
        canonical_bytes(runtime_manifest(source.data)),
    )
    qualification = _write(
        root / f"inputs/chaff-qualifications/{source.id}.json",
        b'{"qualified":true}\n',
    )
    chaff = _write(
        root / f"inputs/chaff-manifests/{source.id}.json",
        b'{"resources":[]}\n',
    )
    workload = {
        "id": source.id,
        "visits": 1,
        "manifest": prepared.relative_to(root).as_posix(),
        "sha256": sha256_file(prepared),
        "runtime_manifest": runtime.relative_to(root).as_posix(),
        "runtime_manifest_sha256": sha256_file(runtime),
        "chaff_qualification": qualification.relative_to(root).as_posix(),
        "chaff_qualification_sha256": sha256_file(qualification),
        "chaff_manifest": chaff.relative_to(root).as_posix(),
        "chaff_manifest_sha256": sha256_file(chaff),
        "resource_count": 2,
        "origin_count": 2,
    }
    defense = {"name": mode, "kind": runtime_kind, "baseline": baseline}
    if runtime_kind == "static":
        schedule = _write(root / "inputs/static-schedule.json", b'{"events":[]}\n')
        defense.update(
            schedule=schedule.relative_to(root).as_posix(),
            schedule_sha256=sha256_file(schedule),
            mode="chaff-and-shape",
        )
    elif runtime_kind in PARAMETERISED_RUNTIME_KINDS:
        parameter = _write(
            root / f"inputs/defense-parameters/{runtime_kind}.json",
            json.dumps({"kind": runtime_kind}, sort_keys=True).encode() + b"\n",
        )
        provenance = _write(
            root / f"inputs/defense-parameters/{runtime_kind}.provenance.json",
            b'{"provenance":true}\n',
        )
        defense.update(
            parameters=parameter.relative_to(root).as_posix(),
            parameters_sha256=sha256_file(parameter),
            provenance=provenance.relative_to(root).as_posix(),
            provenance_sha256=sha256_file(provenance),
            input_policy="sealed-class-study-fitting-v1",
        )
    configuration = {
        "campaign_sha256": sha256_file(campaign),
        "profile": "research-1200",
        "workloads": [workload],
        "defenses": [defense],
        "limits": {"max_response_bytes": 1_048_576},
    }
    sample = {
        "sample_id": f"{source.id}-{mode}",
        "workload_id": source.id,
        "defense": mode,
        "runtime_kind": runtime_kind,
        "baseline": baseline,
        "seed": 19,
        "request_policy": "as-defined",
    }
    run = {
        "completion_status": "complete",
        "error": None,
        "seed": 19,
        "request_policy": "as-defined",
        "workload_hash_sha256": sha256_file(runtime),
        "max_response_bytes": 1_048_576,
        "resolved_configuration": {
            "max_udp_payload_size": 1_200,
            "defense": {
                "kind": runtime_kind,
                **(
                    {"workload_id": source.id}
                    if runtime_kind in WORKLOAD_SCOPED_RUNTIME_KINDS
                    else {}
                ),
            },
        },
        "application_workload_source_hash_sha256": (None if baseline else sha256_file(prepared)),
        "chaff_manifest_hash_sha256": None if baseline else sha256_file(chaff),
        "chaff_responses": [],
        "defense_parameters": (
            None
            if baseline or runtime_kind in {"front", "tamaraw"}
            else {
                "kind": runtime_kind,
                "sha256": (
                    defense["schedule_sha256"]
                    if runtime_kind == "static"
                    else defense["parameters_sha256"]
                ),
            }
        ),
        "responses": [
            {
                **response,
                "complete": True,
                "outcome": "succeeded",
            }
            for response in source.data["preparation"]["expected_responses"]
        ],
        # Explicit default ports exercise canonical endpoint-origin comparison.
        "endpoints": [
            {"origin": f"https://{source.id}.example:443/"},
            {"origin": f"https://cdn.{source.id}.example:443/"},
        ],
    }
    return root, configuration, sample, run


@pytest.mark.parametrize(("mode", "runtime_kind", "baseline"), _MODES)
def test_all_nine_modes_bind_the_same_complete_two_origin_graph(
    tmp_path: Path,
    mode: str,
    runtime_kind: str,
    baseline: bool,
) -> None:
    root, configuration, sample, run = _fixture(
        tmp_path,
        mode,
        runtime_kind,
        baseline,
    )

    binding = resolve_class_sample_run_binding(root, configuration, sample)
    validate_class_sample_run_binding(run, sample, binding)

    assert binding.expected_origins == (
        "https://cdn.class-000.example",
        "https://class-000.example",
    )
    assert len(binding.expected_responses) == 2


def test_wrong_per_mode_runtime_or_application_graph_hash_is_rejected(tmp_path: Path) -> None:
    root, configuration, sample, run = _fixture(
        tmp_path,
        "front",
        "front",
        False,
    )
    binding = resolve_class_sample_run_binding(root, configuration, sample)

    run["workload_hash_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="accepted sample"):
        validate_class_sample_run_binding(run, sample, binding)
    run["workload_hash_sha256"] = binding.receipt()["runtime_workload_sha256"]
    run["application_workload_source_hash_sha256"] = "1" * 64
    with pytest.raises(ValueError, match="graph binding"):
        validate_class_sample_run_binding(run, sample, binding)

    configuration["workloads"][0]["origin_count"] = 1
    with pytest.raises(ValueError, match="cardinality differs"):
        resolve_class_sample_run_binding(root, configuration, sample)


def test_missing_multi_origin_endpoint_or_resource_response_is_rejected(tmp_path: Path) -> None:
    root, configuration, sample, run = _fixture(
        tmp_path,
        "undefended",
        "none",
        True,
    )
    binding = resolve_class_sample_run_binding(root, configuration, sample)

    run["endpoints"] = run["endpoints"][:1]
    with pytest.raises(ValueError, match="endpoint origins"):
        validate_class_sample_run_binding(run, sample, binding)
    run["endpoints"] = [
        {"origin": "https://class-000.example"},
        {"origin": "https://cdn.class-000.example"},
    ]
    run["responses"] = run["responses"][:1]
    with pytest.raises(ValueError, match="prepared full graph"):
        validate_class_sample_run_binding(run, sample, binding)


def test_only_baseline_fitting_may_derive_an_unfrozen_runtime_copy(tmp_path: Path) -> None:
    root, configuration, sample, run = _fixture(
        tmp_path,
        "undefended",
        "none",
        True,
    )
    workload = configuration["workloads"][0]
    workload.pop("runtime_manifest")
    workload.pop("runtime_manifest_sha256")

    with pytest.raises(ValueError, match="no frozen runtime graph"):
        resolve_class_sample_run_binding(root, configuration, sample)
    binding = resolve_class_sample_run_binding(
        root,
        configuration,
        sample,
        allow_derived_runtime_without_frozen_copy=True,
    )
    validate_class_sample_run_binding(run, sample, binding)
