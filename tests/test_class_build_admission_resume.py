from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from qcsd_lab.class_build_admission import resolve_action_admission
from qcsd_lab.class_study import (
    bind_receipt,
    canonical_json_bytes,
    canonical_json_sha256,
    class_study_launch_identity,
    class_study_launch_key,
)
from qcsd_lab.util import sha256_file
from tests.test_class_build_admission_successor import (
    _rewrite_restart,
    _successor_fixture,
)
from tests.test_class_fitting import _cohort_assembly, _cohort_receipt
from tests.test_cli import (
    _class_build_admission_fixture,
    _second_class_build_admission_fixture,
)

BASE_STUDY = "classifier-multiorigin100-v1"
PILOT_QUALIFICATION = f"{BASE_STUDY}-pilot120-full-v1"
FINAL_QUALIFICATION = f"{BASE_STUDY}-final100-full-v1"
PILOT_ROLES = frozenset({"pilot-fitting", "pilot-compatibility"})
FITTED_ROLES = frozenset({"pilot-compatibility", "certification", "formal"})
PROMOTED_ROLES = frozenset({"canary", "formal"})
BASE_ROLES = (
    "pilot-fitting",
    "pilot-compatibility",
    "authoritative-fitting",
    "certification",
    "canary",
    "formal",
)
SUCCESSOR_ROLES = ("authoritative-fitting", "certification", "canary", "formal")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value))


def _publish(path: Path, receipt_type: str, payload: dict[str, object]) -> Path:
    _write_json(path, bind_receipt(payload, receipt_type=receipt_type))
    return path


def _binding(path: Path, *, payload: bool = False) -> dict[str, str]:
    value = {"path": str(path), "sha256": sha256_file(path)}
    if payload:
        value["payload_sha256"] = json.loads(path.read_bytes())["payload_sha256"]
    return value


def _qualification_authority(fixture: object) -> dict[str, object]:
    return {
        "schema_version": 2,
        "artifact_type": "qcsd-class-study-qualification-authority",
        "foundation_attestation": _binding(fixture.foundation, payload=True),
        "build_execution": _binding(fixture.build),
        "build_execution_identity": fixture.admitted.identity,
        "collection_source": fixture.admitted.source,
        "prepare_source": {
            **dict(fixture.admitted.source),
            "image_digest": fixture.admitted.prepare_image,
        },
        "prepare_image_digest": fixture.admitted.prepare_image,
    }


def _campaign_name(role: str, study_id: str, *, successor: bool) -> str:
    suffix = {
        "pilot-fitting": "pilot-fitting-1200",
        "pilot-compatibility": "pilot-compatibility-1080-1200",
        "authoritative-fitting": (
            "authoritative-fitting-2000-1200" if successor else "authoritative-fitting-1200"
        ),
        "certification": "certification-900-1200",
        "canary": "canary-01-1200",
        "formal": "formal-01-1200",
    }[role]
    return f"{study_id}-{suffix}"


def _campaign_text(
    *,
    campaign_name: str,
    role: str,
    qualification_set: str | None,
    successor: bool,
    workload_ids: list[str],
) -> str:
    purpose = {
        "pilot-fitting": "fitting",
        "pilot-compatibility": "smoke",
        "authoritative-fitting": "fitting",
        "certification": "smoke",
        "canary": "smoke",
        "formal": "evaluation",
    }[role]
    study_id = campaign_name.removesuffix(
        f"-{_campaign_name(role, '', successor=successor).lstrip('-')}"
    )
    pilot = role in PILOT_ROLES
    if successor:
        cohort_reference = "../successor-compatible-cohort.json"
        assembly_reference = "../successor-compatible-cohort-assembly.json"
        bundle = f"../../artifacts/{BASE_STUDY}-authoritative-fitting"
        defense_params = "../../../../../config/defense-params"
    else:
        cohort_reference = (
            f"../class-study/v1/{BASE_STUDY}-pilot-cohort.json"
            if pilot
            else f"../class-study/v1/{BASE_STUDY}-cohort.json"
        )
        assembly_reference = (
            f"../class-study/v1/{BASE_STUDY}-pilot-cohort-assembly.json"
            if pilot
            else f"../class-study/v1/{BASE_STUDY}-cohort-assembly.json"
        )
        bundle = (
            f"../../artifacts/{BASE_STUDY}-pilot-fitting"
            if role == "pilot-compatibility"
            else f"../../artifacts/{BASE_STUDY}-authoritative-fitting"
        )
        defense_params = "../defense-params"

    if role in {"pilot-fitting", "authoritative-fitting", "canary"}:
        defenses: list[object] = ["undefended"]
    else:
        defenses = ["undefended"]
        if role != "formal":
            defenses.append(
                {
                    "name": "static",
                    "kind": "static",
                    "schedule": f"{defense_params}/static-control-1200.csv",
                    "mode": "chaff-only",
                }
            )
        defenses.extend(
            (
                "front",
                "tamaraw",
                {
                    "name": "traffic-morphing",
                    "kind": "traffic_morphing",
                    "parameters": f"{bundle}/traffic-morphing.json",
                },
                {
                    "name": "wtf-pad",
                    "kind": "wtf_pad",
                    "parameters": f"{bundle}/wtf-pad.json",
                },
                {
                    "name": "walkie-talkie",
                    "kind": "walkie_talkie",
                    "parameters": f"{bundle}/walkie-talkie.json",
                },
                {
                    "name": "buflo",
                    "kind": "buflo",
                    "parameters": f"{defense_params}/buflo-live.json",
                },
                {
                    "name": "cs-buflo",
                    "kind": "cs_buflo",
                    "parameters": f"{defense_params}/cs-buflo-ctsp-live.json",
                },
            )
        )
    visits = {
        "pilot-fitting": 2,
        "pilot-compatibility": 1,
        "authoritative-fitting": 10,
        "certification": 1,
        "canary": 1,
        "formal": 2,
    }[role]
    document: dict[str, object] = {
        "schema": 2,
        "name": campaign_name,
        "purpose": purpose,
        "evidence_role": role,
        "seed": int.from_bytes(
            hashlib.sha256(f"{study_id}\0{campaign_name}".encode()).digest()[:4],
            "big",
        ),
        "profile": "research-1200",
        "class_study_cohort": cohort_reference,
        "class_study_cohort_assembly": assembly_reference,
    }
    if successor:
        document["class_study_successor"] = "../successor-restart.json"
    document["sample_order"] = {
        "scheme": "origin-aware-windowed",
        "window_size": 16,
    }
    limits = {
        "timeout_seconds": 120,
        "max_response_bytes": 1_048_576,
        "capture_seconds": 180,
        "capture_megabytes": 64,
        "max_attempts": 1 if role == "certification" else 3,
        "per_origin_cooldown_seconds": 30,
        "settle_seconds": 1,
    }
    # The successor producer emits limits in its common prefix, whereas the
    # base campaign producer emits them after the role-specific collections.
    if successor:
        document["limits"] = limits
    document["workloads"] = {workload_id: visits for workload_id in workload_ids}
    document["request_policies"] = (
        ["as-defined", "half-duplex"]
        if role in {"pilot-fitting", "authoritative-fitting"}
        else ["as-defined"]
    )
    document["defenses"] = defenses
    if not successor:
        document["limits"] = limits
    if qualification_set is not None:
        document["chaff_qualification_set"] = qualification_set
    if role not in {"pilot-fitting", "authoritative-fitting"}:
        document["defense_order"] = {
            "scheme": "cyclic-latin-square",
            "block": 0,
        }
    return yaml.safe_dump(document, sort_keys=False, width=100)


def _final_selection_payload(authority: dict[str, object]) -> dict[str, object]:
    """Return the producer's real authority-bearing final-selection shape."""

    parameter_hashes = {
        "traffic-morphing": "1" * 64,
        "wtf-pad": "2" * 64,
        "walkie-talkie": "3" * 64,
    }
    return {
        "study_id": BASE_STUDY,
        "selection_schema_version": 2,
        "selection_policy": "tranco-bound-order-with-qualified-selected-wt6-pairs",
        "pilot_cohort": {"sha256": "4" * 64, "payload_sha256": "5" * 64},
        "pilot_cohort_assembly": {
            "sha256": "6" * 64,
            "payload_sha256": "7" * 64,
        },
        "pilot_numeric_fitting": {
            "numeric_provenance_sha256": "8" * 64,
            "walkie_talkie_artifact_sha256": "9" * 64,
            "source_result": {},
        },
        "pilot_compatibility": {
            "campaign": f"{BASE_STUDY}-pilot-compatibility-1080-1200",
            "evidence_sha256": "a" * 64,
            "experiment_sha256": "b" * 64,
            "accepted_samples": 1_080,
            "unique_class_mode_pairs": 1_080,
            "fitted_parameter_sha256": parameter_hashes,
            "finalized_bundle": {
                "source": "frozen-pilot-compatibility-inputs",
                "provenance_sha256": "c" * 64,
                "artifact_sha256": parameter_hashes,
                "qualification_authority": authority,
                "qualification_authority_sha256": canonical_json_sha256(authority),
            },
        },
        "feasible_pair_rule": {
            "source": "finalized-selected-wt6-profile-and-both-endpoint-qualification"
        },
        "feasible_pair_evidence": [],
        "feasible_pair_graph": [],
        "selected_final_perfect_matching": [],
    }


def _cohort_and_assembly(
    *, role: str, authority: dict[str, object]
) -> tuple[dict[str, Any], dict[str, Any]]:
    # Supply a genuine 600/120/100/20 cohort and its full 600-record assembly
    # body; update only the schema-three fields absent from the older helper.
    cohort = _cohort_receipt()
    legacy_assembly = _cohort_assembly(cohort)
    payload = dict(legacy_assembly["payload"])
    payload["assembly_schema_version"] = 3
    payload["acquisition_completion"] = {
        "path": "completion.json",
        "sha256": "d" * 64,
        "payload_sha256": "e" * 64,
        "provenance_sha256": "f" * 64,
    }
    if role in PILOT_ROLES:
        payload["final_selection"] = None
    else:
        selection = bind_receipt(
            _final_selection_payload(authority),
            receipt_type="qcsd-class-study-final-selection-input",
        )
        selection_bytes = canonical_json_bytes(selection)
        payload["final_selection"] = {
            "path": "final-selection.json",
            "sha256": hashlib.sha256(selection_bytes).hexdigest(),
            "payload_sha256": selection["payload_sha256"],
            "payload": selection["payload"],
        }
    return cohort, bind_receipt(
        payload,
        receipt_type="qcsd-class-study-cohort-assembly",
    )


def _study_environment(fixture: object) -> dict[str, object]:
    admitted = fixture.admitted
    return {
        "schema_version": 3,
        "artifact_type": "qcsd-buflo-study-environment",
        "docker": {
            "client_version": "29.0.1",
            "server_version": "29.0.1",
            "server_os": "linux",
            "server_arch": "amd64",
            "ncpu": 12,
            "mem_total_bytes": 16_000_000_000,
            "storage_driver": "overlay2",
        },
        "collection_image": {
            "id": admitted.collection_image,
            "repo_digests": [f"qcsd-collection@{admitted.collection_image}"],
        },
        "build_inputs": {
            "schema_version": 1,
            "artifact_type": "qcsd-study-build-inputs",
            "rust_base_image": "rust@sha256:" + "a" * 64,
            "debian_base_image": "debian@sha256:" + "b" * 64,
            "uv_lock_sha256": "c" * 64,
            "cargo_lock_sha256": "d" * 64,
        },
        "build_execution": {
            "receipt": json.loads(fixture.build.read_bytes()),
            "sha256": admitted.receipt_sha256,
            "completion_path": admitted.identity["completion_path"],
            "completion_sha256": admitted.completion_sha256,
            "completion_payload_sha256": admitted.completion_payload_sha256,
            "completion": json.loads(admitted.completion_path.read_bytes()),
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
        "capture_scheduler": {
            "schema_version": 2,
            "contract": "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1",
            "scope": "all_measured_neqo_clients",
            "collection_cpuset_cpus": [10, 11],
            "orchestrator_affinity_cpus": [11],
            "client_affinity_cpus": [10],
            "timed_egress_helper_affinity_cpus": [11],
            "sidecar_affinity_cpus": list(range(10)),
            "policy": "SCHED_RR",
            "priority": 1,
            "timed_egress_helper_policy": "SCHED_RR",
            "timed_egress_helper_priority": 1,
            "rlimit_rtprio": {"soft": 1, "hard": 1},
            "cap_sys_nice": False,
            "docker_cpu_rt_runtime_configured": False,
            "affinity_scope": ("qcsd_container_affinity_partition_not_physical_cpu_isolation"),
        },
    }


def _qualification_sidecar(
    workload_id: str,
    *,
    authority: dict[str, object],
) -> dict[str, object]:
    """Use the exact schema-three producer key inventory at modest size."""

    digest = hashlib.sha256(workload_id.encode()).hexdigest()
    return {
        "schema_version": 3,
        "artifact_type": "qcsd-chaff-qualification",
        "workload_id": workload_id,
        "base_manifest": {"path": f"{workload_id}.json", "sha256": digest},
        "selection_policy": "largest-qualified-response-resource",
        "application_resource_id": 0,
        "selected_chaff_resource_id": 1,
        "qualified_parallel_chaff_streams": 5,
        "walkie_talkie_required_chaff_streams": 1,
        "header_projection": [],
        "method": "live-http3-capacity-and-prefix-pack-qualification",
        "qualification_policy": {},
        "qualification_source": authority["prepare_source"],
        "qualification_image_digest": authority["prepare_image_digest"],
        "neqo_provenance": {},
        "implementation_receipt": {},
        "fitting_source": {},
        "schema_five_diagnostic": {},
        "schema_six_capacity_falsification_diagnostic": {},
        "schema_six_runtime_falsification_diagnostic": {},
        "schema_two_sender_framing_falsification_diagnostic": {},
        "prefix_pack_spec": {"path": f"{workload_id}.json", "sha256": digest},
        "resource": {},
        "qualification_authority": authority,
        "qualification_authority_sha256": canonical_json_sha256(authority),
    }


def _qualification_set(
    root: Path,
    *,
    qualification_set: str,
    workload_ids: list[str],
    authority: dict[str, object],
) -> Path:
    root.mkdir(parents=True)
    entries = []
    for index, workload_id in enumerate(workload_ids):
        sidecar = root / f"{workload_id}.json"
        _write_json(sidecar, _qualification_sidecar(workload_id, authority=authority))
        digest = hashlib.sha256(workload_id.encode()).hexdigest()
        entries.append(
            {
                "index": index,
                "workload_id": workload_id,
                "workload_manifest": {
                    "path": f"{workload_id}.json",
                    "sha256": digest,
                },
                "qualification_sidecar": {
                    "path": sidecar.name,
                    "sha256": sha256_file(sidecar),
                },
                "runtime_manifest_sha256": digest,
                "prefix_pack_spec": {
                    "path": f"{workload_id}.json",
                    "sha256": digest,
                },
            }
        )
    manifest: dict[str, object] = {
        "schema_version": 3,
        "artifact_type": "qcsd-named-chaff-qualification-set",
        "qualification_set": qualification_set,
        "qualification_scope": "full",
        "qualification_sidecar_schema_version": 3,
        "workload_count": len(workload_ids),
        "workload_ids": workload_ids,
        "workloads": entries,
        "qualification_authority": authority,
        "qualification_authority_sha256": canonical_json_sha256(authority),
    }
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["bindings_sha256"] = hashlib.sha256(
        b"qcsd-named-chaff-qualification-set-v3\0" + encoded
    ).hexdigest()
    manifest_path = root / "_qualification-set.json"
    _write_json(manifest_path, manifest)
    return manifest_path


def _materialize_workloads(
    inputs: Path,
    *,
    role: str,
    workload_ids: list[str],
) -> list[dict[str, object]]:
    fitted = role in FITTED_ROLES
    visits = {
        "pilot-fitting": 2,
        "pilot-compatibility": 1,
        "authoritative-fitting": 10,
        "certification": 1,
        "canary": 1,
        "formal": 2,
    }[role]
    roots = {"manifest": inputs / "workloads"}
    if fitted:
        roots.update(
            runtime_manifest=inputs / "runtime-workloads",
            chaff_manifest=inputs / "chaff-manifests",
            chaff_prefix_spec=inputs / "chaff-prefix-specs",
        )
    for root in roots.values():
        root.mkdir()
    records = []
    for workload_id in workload_ids:
        for field, root in roots.items():
            _write_json(
                root / f"{workload_id}.json",
                {
                    "schema_version": 1,
                    "artifact_type": f"qcsd-test-{field.replace('_', '-')}",
                    "workload_id": workload_id,
                },
            )
        manifest_path = roots["manifest"] / f"{workload_id}.json"
        record: dict[str, object] = {
            "id": workload_id,
            "visits": visits,
            "manifest": f"inputs/workloads/{workload_id}.json",
            "sha256": sha256_file(manifest_path),
            "resource_count": 2,
            "origin_count": 1,
        }
        if fitted:
            sidecar = inputs / "chaff-qualifications" / f"{workload_id}.json"
            for field, dirname in (
                ("runtime_manifest", "runtime-workloads"),
                ("chaff_manifest", "chaff-manifests"),
                ("chaff_prefix_spec", "chaff-prefix-specs"),
            ):
                path = inputs / dirname / f"{workload_id}.json"
                record[field] = f"inputs/{dirname}/{workload_id}.json"
                record[f"{field}_sha256"] = sha256_file(path)
            record.update(
                chaff_qualification=(f"inputs/chaff-qualifications/{workload_id}.json"),
                chaff_qualification_sha256=sha256_file(sidecar),
            )
        records.append(record)
    return records


def _materialize_defenses(
    inputs: Path,
    *,
    role: str,
    fitted_records: list[dict[str, object]],
) -> list[dict[str, object]]:
    if role in {"pilot-fitting", "authoritative-fitting", "canary"}:
        return [{"name": "undefended", "kind": "none", "baseline": True}]

    records_by_name = {record["name"]: record for record in fitted_records}
    parameter_root = inputs / "defense-parameters"
    candidate_records: dict[str, dict[str, object]] = {}
    for name, kind in (("buflo", "buflo"), ("cs-buflo", "cs_buflo")):
        root = parameter_root / name
        root.mkdir()
        parameters = root / "parameters.json"
        provenance = root / "provenance.json"
        _write_json(parameters, {"schema_version": 1, "defense": name})
        _write_json(provenance, {"schema_version": 1, "defense": name})
        candidate_records[name] = {
            "name": name,
            "kind": kind,
            "baseline": False,
            "parameters": f"inputs/defense-parameters/{name}/parameters.json",
            "parameters_sha256": sha256_file(parameters),
            "provenance": f"inputs/defense-parameters/{name}/provenance.json",
            "provenance_sha256": sha256_file(provenance),
            "input_policy": "reviewed-buflo-study-candidate-v1",
        }

    static_record = None
    if role != "formal":
        static = parameter_root / "static"
        static.mkdir()
        schedule = static / "schedule.csv"
        schedule.write_bytes(b"time_ms,direction,size\n0,outgoing,1200\n")
        static_record = {
            "name": "static",
            "kind": "static",
            "baseline": False,
            "schedule": "inputs/defense-parameters/static/schedule.csv",
            "schedule_sha256": sha256_file(schedule),
            "mode": "chaff-only",
        }

    base = lambda name, kind: {
        "name": name,
        "kind": kind,
        "baseline": name == "undefended",
    }
    records = [base("undefended", "none")]
    if static_record is not None:
        records.append(static_record)
    records.extend(
        (
            base("front", "front"),
            base("tamaraw", "tamaraw"),
            records_by_name["traffic-morphing"],
            records_by_name["wtf-pad"],
            records_by_name["walkie-talkie"],
            candidate_records["buflo"],
            candidate_records["cs-buflo"],
        )
    )
    return records


def _fitting_bundle(
    inputs: Path,
    *,
    role: str,
    study_id: str,
    successor_sha256: str | None,
    fixture: object,
    cohort: dict[str, Any],
    assembly: dict[str, Any],
    cohort_path: Path,
    assembly_path: Path,
    manifest_path: Path,
    workload_ids: list[str],
    authority: dict[str, object],
) -> tuple[Path, list[dict[str, object]]]:
    root = inputs / "defense-parameters/class-study"
    root.mkdir(parents=True)
    artifact_paths = {
        "traffic_morphing": root / "traffic-morphing.json",
        "wtf_pad": root / "wtf-pad.json",
        "walkie_talkie": root / "walkie-talkie.json",
    }
    for kind, path in artifact_paths.items():
        _write_json(
            path,
            {
                "schema_version": 1,
                "artifact_type": f"qcsd-class-study-{kind.replace('_', '-')}-parameters",
                **({"qualification_bindings": []} if kind == "walkie_talkie" else {}),
            },
        )

    pilot = role == "pilot-compatibility"
    stage = "pilot" if pilot else "authoritative"
    source_result: dict[str, object] = {
        "campaign": (
            f"{BASE_STUDY}-pilot-fitting-1200"
            if pilot
            else (
                f"{study_id}-authoritative-fitting-2000-1200"
                if successor_sha256 is not None
                else f"{BASE_STUDY}-authoritative-fitting-1200"
            )
        ),
        "evidence_sha256": "1" * 64,
        "experiment_sha256": "2" * 64,
        "input_digest": "3" * 64,
        "campaign_sha256": "4" * 64,
        "source_fingerprints": fixture.admitted.source,
    }
    if successor_sha256 is not None:
        source_result.update(
            study_id=study_id,
            class_study_successor_sha256=successor_sha256,
        )
    manifest = json.loads(manifest_path.read_bytes())
    bindings = [
        {
            "workload_id": workload_id,
            "chaff_qualification_sidecar_sha256": sha256_file(
                manifest_path.parent / f"{workload_id}.json"
            ),
            "prefix_pack_spec_sha256": hashlib.sha256(workload_id.encode()).hexdigest(),
            "qualified_chaff_manifest_sha256": hashlib.sha256(workload_id.encode()).hexdigest(),
            "application_resource_id": 0,
            "selected_chaff_resource_id": 1,
            "qualified_parallel_chaff_streams": 5,
            "walkie_talkie_required_chaff_streams": 1,
        }
        for workload_id in workload_ids
    ]
    artifacts = {
        kind: {"path": path.name, "sha256": sha256_file(path)}
        for kind, path in artifact_paths.items()
    }
    provenance = {
        "schema_version": 2,
        "artifact_type": "qcsd-class-study-research-defense-bundle",
        "status": "pilot-test-only" if pilot else "authoritative-fitted-artifact",
        "runtime_authorized": not pilot,
        "stage": stage,
        "bundle_name": (
            f"{BASE_STUDY}-pilot-fitting" if pilot else f"{BASE_STUDY}-authoritative-fitting"
        ),
        "qcsd_profile": "research-1200",
        "udp_payload_ceiling": 1_200,
        "parameter_input_policy": (
            "sealed-class-study-pilot-fitting-v1" if pilot else "sealed-class-study-fitting-v1"
        ),
        "source_result": source_result,
        "cohort": {
            "role": stage,
            "receipt_sha256": sha256_file(cohort_path),
            "receipt": cohort,
            "assembly_receipt_sha256": sha256_file(assembly_path),
            "assembly_receipt": assembly,
        },
        "fitting_contract": {"workload_order": workload_ids},
        "sample_contributions": [],
        "qualification_inputs": {
            "role": "runtime-qualification-only-excluded-from-numeric-fitting",
            "qualification_bytes_excluded": True,
            "prefix_specification_bytes_excluded": True,
            "qualification_set": manifest["qualification_set"],
            "qualification_manifest_sha256": sha256_file(manifest_path),
            "qualification_manifest": manifest,
            "qualification_authority": authority,
            "qualification_bindings_sha256": canonical_json_sha256(bindings),
            "qualification_bindings": bindings,
        },
        "algorithms": {},
        "artifacts": artifacts,
    }
    provenance_path = root / "provenance.json"
    _write_json(provenance_path, provenance)
    records = [
        {
            "name": name,
            "kind": {
                "traffic-morphing": "traffic_morphing",
                "wtf-pad": "wtf_pad",
                "walkie-talkie": "walkie_talkie",
            }[name],
            "baseline": False,
            "parameters": f"inputs/defense-parameters/class-study/{path.name}",
            "parameters_sha256": sha256_file(path),
            "provenance": "inputs/defense-parameters/class-study/provenance.json",
            "provenance_sha256": sha256_file(provenance_path),
            "input_policy": provenance["parameter_input_policy"],
        }
        for name, path in (
            ("traffic-morphing", artifact_paths["traffic_morphing"]),
            ("wtf-pad", artifact_paths["wtf_pad"]),
            ("walkie-talkie", artifact_paths["walkie_talkie"]),
        )
    ]
    return provenance_path, records


def _promotion_receipts(
    inputs: Path,
    *,
    study_id: str,
    fixture: object,
    cohort_path: Path,
    assembly_path: Path,
    successor_path: Path | None,
) -> tuple[Path, Path]:
    evidence: dict[str, object] = {
        "foundation": _binding(fixture.foundation),
        "build_execution": _binding(fixture.build),
        "final_cohort": _binding(cohort_path),
        "final_cohort_assembly": _binding(assembly_path),
    }
    if successor_path is not None:
        evidence["successor_restart"] = _binding(successor_path)
    readiness = _publish(
        inputs / "class-study-readiness.json",
        "qcsd-class-study-readiness-attestation",
        {
            "attestation_schema_version": 3,
            "artifact_type": "qcsd-class-study-readiness-attestation",
            "study_id": study_id,
            "cohort_version": fixture.admitted.cohort_version,
            "source": fixture.admitted.source,
            "build_execution_identity": fixture.admitted.identity,
            "evidence": evidence,
        },
    )
    historical = _publish(
        inputs / "class-study-historical-pre-snapshot.json",
        "qcsd-class-study-historical-snapshot",
        {
            "snapshot_schema_version": 1,
            "artifact_type": "qcsd-class-study-historical-snapshot",
            "study_id": study_id,
            "phase": "pre-formal",
            "source": fixture.admitted.source,
            "readiness": _binding(readiness),
        },
    )
    return readiness, historical


def _launch_receipt(
    *,
    result: Path,
    study_id: str,
    campaign_name: str,
    campaign_path: Path,
    role: str,
    cohort_path: Path,
    assembly_path: Path,
    source: object,
    successor_sha256: str | None,
) -> dict[str, object]:
    launch_key = class_study_launch_key(
        **class_study_launch_identity(
            study_id=study_id,
            campaign_name=campaign_name,
            evidence_role=role,
            cohort_sha256=sha256_file(cohort_path),
            cohort_assembly_sha256=sha256_file(assembly_path),
        )
    )
    payload = {
        "study_id": study_id,
        "launch_key": launch_key,
        "campaign_name": campaign_name,
        "campaign_sha256": sha256_file(campaign_path),
        "evidence_role": role,
        "class_study_cohort_sha256": sha256_file(cohort_path),
        "class_study_cohort_assembly_sha256": sha256_file(assembly_path),
        "result_root": f"/lab/{result.relative_to(result.parents[2]).as_posix()}",
        "created_at": "2026-09-07T00:02:00+00:00",
        "source": source,
        "policy": "one-result-root-per-campaign-and-cohort-assembly",
    }
    if successor_sha256 is not None:
        payload.update(
            class_study_successor_sha256=successor_sha256,
            launch_namespace=f".{study_id}-launches",
        )
    detached = json.loads(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return {
        "schema_version": 1,
        "artifact_type": "qcsd-class-study-first-launch-claim",
        "payload_sha256": hashlib.sha256(
            json.dumps(detached, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "payload": detached,
    }


def _refresh_launch(value: SimpleNamespace) -> None:
    old_launch = json.loads(value.launch.read_bytes()) if value.launch.exists() else None
    if old_launch is not None:
        old_marker = value.registry / f"{old_launch['payload']['launch_key']}.json"
        if old_marker.exists():
            old_marker.unlink()
    launch = _launch_receipt(
        result=value.result,
        study_id=value.study_id,
        campaign_name=value.campaign_name,
        campaign_path=value.campaign,
        role=value.role,
        cohort_path=value.cohort,
        assembly_path=value.assembly,
        source=value.fixture.admitted.source,
        successor_sha256=value.successor_sha256,
    )
    _write_json(value.launch, launch)
    value.registry.mkdir(parents=True, exist_ok=True)
    _write_json(value.registry / f"{launch['payload']['launch_key']}.json", launch)


def _rewrite_experiment(value: SimpleNamespace, mutate) -> None:
    experiment = json.loads(value.experiment.read_bytes())
    mutate(experiment)
    _write_json(value.experiment, experiment)


def _rewrite_provenance(value: SimpleNamespace, provenance: dict[str, object]) -> None:
    _write_json(value.provenance, provenance)
    _rewrite_experiment(
        value,
        lambda experiment: [
            record.update(provenance_sha256=sha256_file(value.provenance))
            for record in experiment["configuration"]["defenses"]
            if record.get("provenance") == "inputs/defense-parameters/class-study/provenance.json"
        ],
    )


def _rewrite_manifest(value: SimpleNamespace, manifest: dict[str, object]) -> None:
    detached = {key: item for key, item in manifest.items() if key != "bindings_sha256"}
    encoded = json.dumps(detached, sort_keys=True, separators=(",", ":")).encode()
    manifest["bindings_sha256"] = hashlib.sha256(
        b"qcsd-named-chaff-qualification-set-v3\0" + encoded
    ).hexdigest()
    _write_json(value.manifest, manifest)
    provenance = json.loads(value.provenance.read_bytes())
    provenance["qualification_inputs"]["qualification_manifest"] = manifest
    provenance["qualification_inputs"]["qualification_manifest_sha256"] = sha256_file(
        value.manifest
    )
    _rewrite_provenance(value, provenance)
    _rewrite_experiment(
        value,
        lambda experiment: experiment["configuration"].update(
            chaff_qualification_set_manifest_sha256=sha256_file(value.manifest)
        ),
    )


def _resume_fixture(
    tmp_path: Path,
    *,
    role: str,
    fixture: object | None = None,
    result: Path | None = None,
    successor: object | None = None,
) -> SimpleNamespace:
    """Build the current result-local contract emitted by the orchestrator.

    This is intentionally reusable by CLI/action-routing tests: unlike the
    generic build fixture it contains every strict pre-Docker resume input.
    """

    fixture = fixture or _class_build_admission_fixture(tmp_path)
    successor_path = successor.restart if successor is not None else None
    successor_sha256 = sha256_file(successor_path) if successor_path is not None else None
    study_id = (
        json.loads(successor_path.read_bytes())["payload"]["study_id"]
        if successor_path is not None
        else BASE_STUDY
    )
    campaign_name = _campaign_name(role, study_id, successor=successor_path is not None)
    result = result or fixture.root / "results" / campaign_name / "run-001"
    inputs = result / "inputs"
    inputs.mkdir(parents=True)
    (inputs / "defense-parameters").mkdir()

    _write_json(inputs / "study-environment.json", _study_environment(fixture))
    (inputs / "class-study-foundation.json").write_bytes(fixture.foundation.read_bytes())
    _write_json(inputs / "source.json", fixture.admitted.source)
    if successor_path is not None:
        (inputs / "class-study-successor.json").write_bytes(successor_path.read_bytes())

    authority = _qualification_authority(fixture)
    if successor is None:
        cohort_value, assembly_value = _cohort_and_assembly(
            role=role,
            authority=authority,
        )
    else:
        cohort_value = json.loads(successor.files["successor-compatible-cohort.json"].read_bytes())
        assembly_value = json.loads(
            successor.files["successor-compatible-cohort-assembly.json"].read_bytes()
        )
    cohort_path = inputs / "class-study-cohort.json"
    assembly_path = inputs / "class-study-cohort-assembly.json"
    _write_json(cohort_path, cohort_value)
    _write_json(assembly_path, assembly_value)
    inventory = "pilot" if role in PILOT_ROLES else "final"
    workload_ids = list(cohort_value["payload"]["inventories"][inventory])

    qualification_set = None
    if role == "pilot-compatibility":
        qualification_set = PILOT_QUALIFICATION
    elif role in {"certification", "formal"}:
        qualification_set = (
            f"{study_id}-final-full" if successor_path is not None else FINAL_QUALIFICATION
        )
    campaign_path = inputs / "campaign.yml"
    if successor is None:
        campaign_path.write_text(
            _campaign_text(
                campaign_name=campaign_name,
                role=role,
                qualification_set=qualification_set,
                successor=False,
                workload_ids=workload_ids,
            ),
            encoding="utf-8",
        )
    else:
        campaign_path.write_bytes(successor.files[f"campaigns/{campaign_name}.yml"].read_bytes())

    purpose = {
        "pilot-fitting": "fitting",
        "pilot-compatibility": "smoke",
        "authoritative-fitting": "fitting",
        "certification": "smoke",
        "canary": "smoke",
        "formal": "evaluation",
    }[role]
    request_policies = (
        ["as-defined", "half-duplex"]
        if role in {"pilot-fitting", "authoritative-fitting"}
        else ["as-defined"]
    )
    limits = {
        "timeout_seconds": 120,
        "max_response_bytes": 1_048_576,
        "capture_seconds": 180,
        "capture_megabytes": 64,
        "max_attempts": 1 if role == "certification" else 3,
        "per_origin_cooldown_seconds": 30,
        "settle_seconds": 1,
    }
    configuration: dict[str, object] = {
        "evidence_role": role,
        "campaign_sha256": sha256_file(campaign_path),
        "profile": "research-1200",
        "request_policies": request_policies,
        "limits": limits,
        "sample_order": {"scheme": "origin-aware-windowed", "window_size": 16},
        "class_study_id": study_id,
        "class_study_foundation_sha256": sha256_file(inputs / "class-study-foundation.json"),
        "class_study_cohort_sha256": sha256_file(cohort_path),
        "class_study_cohort_assembly_sha256": sha256_file(assembly_path),
        "study_environment_sha256": sha256_file(inputs / "study-environment.json"),
        "public_origin_policy": {
            "environment": "QCSD_PUBLIC_ORIGIN_ONLY",
            "required_value": "1",
            "resolution": "resolve-once-reject-any-non-public-connect-exact-address",
        },
    }
    if role not in {"pilot-fitting", "authoritative-fitting"}:
        configuration["defense_order"] = {
            "scheme": "cyclic-latin-square",
            "block": 0,
        }
    if successor_sha256 is not None:
        configuration["class_study_successor_sha256"] = successor_sha256

    manifest_path = None
    provenance_path = None
    sidecar_root = None
    fitted_records: list[dict[str, object]] = []
    if role in FITTED_ROLES:
        sidecar_root = inputs / "chaff-qualifications"
        assert qualification_set is not None
        manifest_path = _qualification_set(
            sidecar_root,
            qualification_set=qualification_set,
            workload_ids=workload_ids,
            authority=authority,
        )
        provenance_path, fitted_records = _fitting_bundle(
            inputs,
            role=role,
            study_id=study_id,
            successor_sha256=successor_sha256,
            fixture=fixture,
            cohort=cohort_value,
            assembly=assembly_value,
            cohort_path=cohort_path,
            assembly_path=assembly_path,
            manifest_path=manifest_path,
            workload_ids=workload_ids,
            authority=authority,
        )
        configuration.update(
            chaff_qualification_set=qualification_set,
            chaff_qualification_set_manifest_sha256=sha256_file(manifest_path),
        )

    configuration["workloads"] = _materialize_workloads(
        inputs,
        role=role,
        workload_ids=workload_ids,
    )
    configuration["defenses"] = _materialize_defenses(
        inputs,
        role=role,
        fitted_records=fitted_records,
    )

    readiness = None
    historical = None
    if role in PROMOTED_ROLES:
        readiness, historical = _promotion_receipts(
            inputs,
            study_id=study_id,
            fixture=fixture,
            cohort_path=cohort_path,
            assembly_path=assembly_path,
            successor_path=successor_path,
        )
        configuration.update(
            class_study_readiness_sha256=sha256_file(readiness),
            class_study_historical_pre_snapshot_sha256=sha256_file(historical),
        )

    launch_path = inputs / "class-study-launch.json"
    registry = result.parent.parent / f".{study_id}-launches"
    value = SimpleNamespace(
        fixture=fixture,
        result=result,
        inputs=inputs,
        role=role,
        study_id=study_id,
        campaign_name=campaign_name,
        campaign=campaign_path,
        cohort=cohort_path,
        assembly=assembly_path,
        launch=launch_path,
        registry=registry,
        successor=successor_path,
        successor_sha256=successor_sha256,
        readiness=readiness,
        historical=historical,
        authority=authority,
        qualification=sidecar_root,
        manifest=manifest_path,
        provenance=provenance_path,
        workload_ids=workload_ids,
    )
    _refresh_launch(value)
    configuration["class_study_launch_sha256"] = sha256_file(launch_path)
    experiment_path = result / "experiment.json"
    _write_json(
        experiment_path,
        {
            "name": campaign_name,
            "purpose": purpose,
            "status": "incomplete",
            "source": fixture.admitted.source,
            "configuration": configuration,
        },
    )
    value.experiment = experiment_path
    return value


def _resolve(value: SimpleNamespace):
    options = {
        "foundation": str(value.fixture.foundation),
        "capture_result": str(value.result),
    }
    if value.successor is not None:
        options["successor_restart"] = str(value.successor)
    if value.role in PROMOTED_ROLES:
        options.update(readiness=str(value.readiness), historical_pre=str(value.historical))
    return resolve_action_admission(
        value.fixture.root,
        action="resume",
        options=options,
        build_loader=value.fixture.load,
    )


def _successor_resume_fixture(tmp_path: Path, role: str) -> tuple[SimpleNamespace, SimpleNamespace]:
    successor = _successor_fixture(tmp_path)
    base = SimpleNamespace(
        root=successor.root,
        admitted=successor.first,
        load=successor.load,
        build=Path(successor.first_authority["build_execution"]["path"]),
        foundation=Path(successor.first_authority["foundation_attestation"]["path"]),
    )
    study_id = json.loads(successor.restart.read_bytes())["payload"]["study_id"]
    authority = _qualification_authority(base)
    cohort, assembly = _cohort_and_assembly(role=role, authority=authority)
    workload_ids = list(cohort["payload"]["inventories"]["final"])
    qualification_set = f"{study_id}-final-full" if role in {"certification", "formal"} else None
    campaign_name = _campaign_name(role, study_id, successor=True)
    campaign_relative = f"campaigns/{campaign_name}.yml"
    _write_json(successor.files["successor-compatible-cohort.json"], cohort)
    _write_json(successor.files["successor-compatible-cohort-assembly.json"], assembly)
    successor.files[campaign_relative].write_text(
        _campaign_text(
            campaign_name=campaign_name,
            role=role,
            qualification_set=qualification_set,
            successor=True,
            workload_ids=workload_ids,
        ),
        encoding="utf-8",
    )
    updated_relatives = (
        "successor-compatible-cohort.json",
        "successor-compatible-cohort-assembly.json",
        campaign_relative,
    )
    _rewrite_restart(
        successor,
        lambda payload: [
            payload["immutable_plan_artifacts"][relative].update(
                sha256=sha256_file(successor.files[relative])
            )
            for relative in updated_relatives
        ],
    )
    return successor, _resume_fixture(
        tmp_path,
        role=role,
        fixture=base,
        successor=successor,
    )


@pytest.mark.parametrize("role", BASE_ROLES)
def test_resume_admits_all_six_base_roles(tmp_path: Path, role: str) -> None:
    value = _resume_fixture(tmp_path, role=role)

    assert _resolve(value) == value.fixture.admitted


@pytest.mark.parametrize("role", SUCCESSOR_ROLES)
def test_resume_admits_all_four_successor_roles(tmp_path: Path, role: str) -> None:
    successor, value = _successor_resume_fixture(tmp_path, role)

    assert (
        value.campaign.read_bytes()
        == successor.files[f"campaigns/{value.campaign_name}.yml"].read_bytes()
    )
    assert (
        value.cohort.read_bytes()
        == successor.files["successor-compatible-cohort.json"].read_bytes()
    )
    assert (
        value.assembly.read_bytes()
        == successor.files["successor-compatible-cohort-assembly.json"].read_bytes()
    )
    assert _resolve(value) == successor.first


@pytest.mark.parametrize("mutated_input", ("campaign", "cohort"))
def test_successor_resume_rejects_rehashed_non_plan_inputs(
    tmp_path: Path,
    mutated_input: str,
) -> None:
    _successor, value = _successor_resume_fixture(tmp_path, "authoritative-fitting")
    if mutated_input == "campaign":
        value.campaign.write_text(
            value.campaign.read_text(encoding="utf-8")
            + "# semantically inert but not the immutable plan bytes\n",
            encoding="utf-8",
        )
    else:
        cohort = json.loads(value.cohort.read_bytes())
        cohort["payload"]["fixture_note"] = "valid but not the immutable plan bytes"
        rebound_cohort = bind_receipt(
            cohort["payload"],
            receipt_type=cohort["receipt_type"],
        )
        _write_json(value.cohort, rebound_cohort)
        assembly = json.loads(value.assembly.read_bytes())
        assembly["payload"]["cohort"] = {
            "receipt_type": rebound_cohort["receipt_type"],
            "payload_sha256": rebound_cohort["payload_sha256"],
            "canonical_file_sha256": sha256_file(value.cohort),
        }
        _write_json(
            value.assembly,
            bind_receipt(
                assembly["payload"],
                receipt_type=assembly["receipt_type"],
            ),
        )
    _refresh_launch(value)
    _rewrite_experiment(
        value,
        lambda experiment: experiment["configuration"].update(
            campaign_sha256=sha256_file(value.campaign),
            class_study_cohort_sha256=sha256_file(value.cohort),
            class_study_cohort_assembly_sha256=sha256_file(value.assembly),
            class_study_launch_sha256=sha256_file(value.launch),
        ),
    )

    with pytest.raises(ValueError, match="canonical restart plan"):
        _resolve(value)


def test_resume_rejects_unknown_role(tmp_path: Path) -> None:
    value = _resume_fixture(tmp_path, role="certification")
    _rewrite_experiment(
        value,
        lambda experiment: experiment["configuration"].update(evidence_role="exploratory"),
    )

    with pytest.raises(ValueError, match="evidence role"):
        _resolve(value)


@pytest.mark.parametrize(
    "relative",
    (
        "study-environment.json",
        "source.json",
        "campaign.yml",
        "class-study-foundation.json",
        "class-study-cohort.json",
        "class-study-cohort-assembly.json",
        "class-study-launch.json",
    ),
)
def test_resume_requires_every_result_local_core_input(tmp_path: Path, relative: str) -> None:
    value = _resume_fixture(tmp_path, role="authoritative-fitting")
    (value.inputs / relative).unlink()

    with pytest.raises(ValueError, match="regular|frozen|resume|required|environment"):
        _resolve(value)


def test_resume_requires_matching_global_first_launch_registry_marker(
    tmp_path: Path,
) -> None:
    value = _resume_fixture(tmp_path, role="authoritative-fitting")
    launch = json.loads(value.launch.read_bytes())
    (value.registry / f"{launch['payload']['launch_key']}.json").unlink()

    with pytest.raises(ValueError, match="registry"):
        _resolve(value)


@pytest.mark.parametrize(
    ("role", "expected_count", "expected_set"),
    (
        ("pilot-compatibility", 120, PILOT_QUALIFICATION),
        ("certification", 100, FINAL_QUALIFICATION),
        ("formal", 100, FINAL_QUALIFICATION),
    ),
)
def test_fitted_resume_uses_exact_stage_qualification_inventory(
    tmp_path: Path,
    role: str,
    expected_count: int,
    expected_set: str,
) -> None:
    value = _resume_fixture(tmp_path, role=role)
    manifest = json.loads(value.manifest.read_bytes())

    assert manifest["qualification_set"] == expected_set
    assert manifest["workload_count"] == expected_count
    assert len(manifest["workload_ids"]) == expected_count
    assert {entry.name for entry in value.qualification.iterdir()} == {
        "_qualification-set.json",
        *(f"{workload_id}.json" for workload_id in manifest["workload_ids"]),
    }
    assert _resolve(value) == value.fixture.admitted


def test_successor_fitted_resume_uses_its_exact_final_qualification_identity(
    tmp_path: Path,
) -> None:
    successor, value = _successor_resume_fixture(tmp_path, "certification")
    manifest = json.loads(value.manifest.read_bytes())

    assert manifest["qualification_set"] == f"{value.study_id}-final-full"
    assert manifest["workload_count"] == 100
    assert _resolve(value) == successor.first


def test_fitted_resume_requires_exact_four_file_parameter_bundle(tmp_path: Path) -> None:
    value = _resume_fixture(tmp_path, role="certification")
    bundle = value.provenance.parent

    assert {entry.name for entry in bundle.iterdir()} == {
        "traffic-morphing.json",
        "wtf-pad.json",
        "walkie-talkie.json",
        "provenance.json",
    }
    _write_json(bundle / "unexpected.json", {})
    with pytest.raises(ValueError, match="inventory"):
        _resolve(value)


def test_fitted_resume_rejects_missing_qualification_sidecar(tmp_path: Path) -> None:
    value = _resume_fixture(tmp_path, role="pilot-compatibility")
    (value.qualification / f"{value.workload_ids[-1]}.json").unlink()

    with pytest.raises(ValueError, match="inventory|incomplete|regular file"):
        _resolve(value)


@pytest.mark.parametrize("role", ("canary", "formal"))
@pytest.mark.parametrize(
    "relative",
    ("class-study-readiness.json", "class-study-historical-pre-snapshot.json"),
)
def test_promoted_resume_requires_both_result_local_promotion_receipts(
    tmp_path: Path, role: str, relative: str
) -> None:
    value = _resume_fixture(tmp_path, role=role)
    (value.inputs / relative).unlink()

    with pytest.raises(ValueError, match="regular|frozen|required"):
        _resolve(value)


def test_unpromoted_resume_rejects_promotion_receipt_presence(tmp_path: Path) -> None:
    value = _resume_fixture(tmp_path, role="certification")
    unexpected = value.inputs / "class-study-readiness.json"
    unexpected.write_bytes(value.fixture.readiness.read_bytes())

    with pytest.raises(ValueError, match="unexpected authority"):
        _resolve(value)


def test_promoted_resume_rejects_post_formal_snapshot_as_pre_formal(
    tmp_path: Path,
) -> None:
    value = _resume_fixture(tmp_path, role="canary")
    historical = json.loads(value.historical.read_bytes())
    historical["payload"]["phase"] = "post-formal"
    _write_json(
        value.historical,
        bind_receipt(
            historical["payload"],
            receipt_type="qcsd-class-study-historical-snapshot",
        ),
    )
    _rewrite_experiment(
        value,
        lambda experiment: experiment["configuration"].update(
            class_study_historical_pre_snapshot_sha256=sha256_file(value.historical)
        ),
    )

    with pytest.raises(ValueError, match="promotion authority|pre-formal"):
        _resolve(value)


def test_resume_rejects_different_external_foundation_copy(tmp_path: Path) -> None:
    value = _resume_fixture(tmp_path, role="certification")
    second = _second_class_build_admission_fixture(value.fixture)

    with pytest.raises(ValueError, match="differs from external resume authority"):
        resolve_action_admission(
            value.fixture.root,
            action="resume",
            options={
                "foundation": str(second.foundation),
                "capture_result": str(value.result),
            },
            build_loader=second.load,
        )


@pytest.mark.parametrize(
    ("attribute", "option"),
    (("readiness", "readiness"), ("historical", "historical_pre")),
)
def test_promoted_resume_rejects_different_external_promotion_copy(
    tmp_path: Path, attribute: str, option: str
) -> None:
    value = _resume_fixture(tmp_path, role="canary")
    original = getattr(value, attribute)
    receipt = json.loads(original.read_bytes())
    receipt["payload"]["fixture_note"] = "different canonical bytes"
    alternate = value.fixture.root / f"artifacts/alternate-{attribute}.json"
    _write_json(
        alternate,
        bind_receipt(receipt["payload"], receipt_type=receipt["receipt_type"]),
    )
    options = {
        "foundation": str(value.fixture.foundation),
        "readiness": str(value.readiness),
        "historical_pre": str(value.historical),
        "capture_result": str(value.result),
    }
    options[option] = str(alternate)

    with pytest.raises(ValueError, match="differs from external resume authority"):
        resolve_action_admission(
            value.fixture.root,
            action="resume",
            options=options,
            build_loader=value.fixture.load,
        )


def test_resume_rejects_duplicate_fitted_defense_record(tmp_path: Path) -> None:
    value = _resume_fixture(tmp_path, role="certification")
    _rewrite_experiment(
        value,
        lambda experiment: experiment["configuration"]["defenses"].append(
            dict(experiment["configuration"]["defenses"][4])
        ),
    )

    with pytest.raises(ValueError, match="defense inventory"):
        _resolve(value)


def test_fitted_resume_does_not_count_scalar_trace_rows_as_authority_containers(
    tmp_path: Path,
) -> None:
    value = _resume_fixture(tmp_path, role="certification")
    provenance = json.loads(value.provenance.read_bytes())
    provenance["sample_contributions"] = ["scalar-trace-row"] * 100_001
    _rewrite_provenance(value, provenance)

    assert _resolve(value) == value.fixture.admitted


def test_resume_rejects_fitting_workload_order_mismatch(tmp_path: Path) -> None:
    value = _resume_fixture(tmp_path, role="certification")
    provenance = json.loads(value.provenance.read_bytes())
    provenance["fitting_contract"]["workload_order"] = list(
        reversed(provenance["fitting_contract"]["workload_order"])
    )
    _rewrite_provenance(value, provenance)

    with pytest.raises(ValueError, match="provenance differs from qualification set"):
        _resolve(value)


def test_resume_rejects_build_authority_nested_in_manifest_entry_binding(
    tmp_path: Path,
) -> None:
    value = _resume_fixture(tmp_path, role="certification")
    second = _second_class_build_admission_fixture(value.fixture)
    second_authority = _qualification_authority(second)
    # Force the nested build edge itself to be evaluated against the frozen
    # build-A foundation before the exact manifest checks run.
    second_authority["foundation_attestation"] = _binding(
        value.inputs / "class-study-foundation.json",
        payload=True,
    )
    manifest = json.loads(value.manifest.read_bytes())
    manifest["workloads"][0]["workload_manifest"]["qualification_authority"] = second_authority
    _rewrite_manifest(value, manifest)

    with pytest.raises(ValueError, match="different completed builds"):
        resolve_action_admission(
            value.fixture.root,
            action="resume",
            options={
                "foundation": str(value.fixture.foundation),
                "capture_result": str(value.result),
            },
            build_loader=second.load,
        )


def test_resume_relocated_authority_uses_frozen_foundation_copy(tmp_path: Path) -> None:
    value = _resume_fixture(tmp_path, role="certification")
    frozen_foundation = value.inputs / "class-study-foundation.json"
    value.fixture.foundation.unlink()

    assert (
        resolve_action_admission(
            value.fixture.root,
            action="resume",
            options={
                "foundation": str(frozen_foundation),
                "capture_result": str(value.result),
            },
            build_loader=value.fixture.load,
        )
        == value.fixture.admitted
    )


def test_resume_rejects_cross_build_authority_at_real_final_selection_path(
    tmp_path: Path,
) -> None:
    value = _resume_fixture(tmp_path, role="authoritative-fitting")
    second = _second_class_build_admission_fixture(value.fixture)
    second_authority = _qualification_authority(second)
    assembly = json.loads(value.assembly.read_bytes())
    finalized = assembly["payload"]["final_selection"]["payload"]["pilot_compatibility"][
        "finalized_bundle"
    ]
    finalized["qualification_authority"] = second_authority
    finalized["qualification_authority_sha256"] = canonical_json_sha256(second_authority)
    _write_json(
        value.assembly,
        bind_receipt(
            assembly["payload"],
            receipt_type="qcsd-class-study-cohort-assembly",
        ),
    )
    _refresh_launch(value)
    _rewrite_experiment(
        value,
        lambda experiment: experiment["configuration"].update(
            class_study_cohort_assembly_sha256=sha256_file(value.assembly),
            class_study_launch_sha256=sha256_file(value.launch),
        ),
    )

    with pytest.raises(ValueError, match="different completed builds"):
        resolve_action_admission(
            value.fixture.root,
            action="resume",
            options={
                "foundation": str(value.fixture.foundation),
                "capture_result": str(value.result),
            },
            build_loader=second.load,
        )


def test_successor_fitted_resume_rejects_wrong_restart_identity_in_provenance(
    tmp_path: Path,
) -> None:
    _successor, value = _successor_resume_fixture(tmp_path, "certification")
    provenance = json.loads(value.provenance.read_bytes())
    provenance["source_result"]["class_study_successor_sha256"] = "0" * 64
    _write_json(value.provenance, provenance)
    _rewrite_experiment(
        value,
        lambda experiment: [
            record.update(provenance_sha256=sha256_file(value.provenance))
            for record in experiment["configuration"]["defenses"]
            if record.get("provenance") == "inputs/defense-parameters/class-study/provenance.json"
        ],
    )

    with pytest.raises(ValueError, match="provenance identity"):
        _resolve(value)


def test_resume_rejects_frozen_source_claim_from_another_build(tmp_path: Path) -> None:
    value = _resume_fixture(tmp_path, role="certification")
    second = _second_class_build_admission_fixture(value.fixture)
    _write_json(value.inputs / "source.json", second.admitted.source)

    with pytest.raises(ValueError, match="source"):
        resolve_action_admission(
            value.fixture.root,
            action="resume",
            options={
                "foundation": str(value.fixture.foundation),
                "capture_result": str(value.result),
            },
            build_loader=second.load,
        )


def test_resume_rejects_symlinked_frozen_authority_file(tmp_path: Path) -> None:
    value = _resume_fixture(tmp_path, role="certification")
    target = value.fixture.root / "artifacts/moved-provenance.json"
    target.write_bytes(value.provenance.read_bytes())
    value.provenance.unlink()
    value.provenance.symlink_to(target)

    with pytest.raises(ValueError, match="symbolic link"):
        _resolve(value)
