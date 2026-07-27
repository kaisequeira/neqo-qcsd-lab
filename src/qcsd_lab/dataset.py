from __future__ import annotations

import json
import shutil
import tarfile
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from .capture import extract_trace, read_normalized_trace
from .util import (
    atomic_json,
    atomic_text,
    load_json,
    response_signature,
    run,
    sha256_file,
    write_checksums,
)

REQUIRED_ROOT_FILES = {
    "campaign.json",
    "dataset.json",
    "samples.jsonl",
    "splits.json",
    "metrics.csv",
    "projection.json",
    "report.html",
}


class DatasetValidationError(RuntimeError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"dataset validation failed with {len(errors)} error(s)")


def load_sample_index(root: Path) -> list[dict[str, Any]]:
    records = []
    with (root / "samples.jsonl").open(encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid samples.jsonl line {number}: {error}") from error
            if not isinstance(record, dict):
                raise ValueError(f"samples.jsonl line {number} is not an object")
            records.append(record)
    return records


def validate_dataset(root: Path, *, raise_on_error: bool = True) -> dict[str, Any]:
    """Validate current visit datasets and existing sealed group-id roots."""

    root = root.resolve()
    errors: list[str] = []
    warnings: list[str] = []
    missing = sorted(name for name in REQUIRED_ROOT_FILES if not (root / name).is_file())
    if missing:
        errors.extend(f"missing required root artifact: {name}" for name in missing)
        return _validation_result(errors, warnings, [], {}, raise_on_error)

    dataset = load_json(root / "dataset.json")
    campaign = load_json(root / "campaign.json")
    splits = load_json(root / "splits.json")
    samples = load_sample_index(root)
    legacy = bool(samples and "visit_id" not in samples[0])
    id_key = "group_id" if legacy else "visit_id"
    plan_key = "groups" if legacy else "visits"
    plans = campaign.get(plan_key, [])
    plan_ids = {plan.get(id_key) for plan in plans}
    plans_by_id = {plan.get(id_key): plan for plan in plans}
    assignments = splits.get("assignments", {})
    if plan_ids != set(assignments):
        errors.append("split assignments do not exactly match planned visits")
    sample_ids = [sample.get("sample_id") for sample in samples]
    if None in sample_ids or len(sample_ids) != len(set(sample_ids)):
        errors.append("sample IDs are missing or duplicated")

    definitions = {
        item["id"]: item for item in dataset.get("observer_definitions", [])
    }
    primary = [item for item in definitions.values() if item.get("primary")]
    purpose = _purpose(dataset, primary)
    defenses = {item["name"] for item in dataset.get("defenses", [])}
    baselines = {
        item["name"] for item in dataset.get("defenses", []) if item.get("baseline")
    }
    by_visit: dict[str, list[dict[str, Any]]] = {}
    metadata_by_id: dict[str, dict[str, Any]] = {}
    for sample in samples:
        visit_id = sample.get(id_key)
        by_visit.setdefault(str(visit_id), []).append(sample)
        if visit_id not in plan_ids:
            errors.append(f"sample {sample.get('sample_id')} references an unknown visit")
        actual_split = sample.get("splits") if legacy else sample.get("split")
        if actual_split != assignments.get(visit_id):
            errors.append(f"sample {sample.get('sample_id')} has the wrong split")
        sample_path = root / str(sample.get("path", ""))
        if not sample_path.resolve().is_relative_to(root):
            errors.append(f"sample path escapes result root: {sample.get('path')}")
            continue
        metadata_path = sample_path / "sample.json"
        if not metadata_path.is_file():
            errors.append(f"sample metadata is missing: {sample.get('path')}")
            continue
        metadata = load_json(metadata_path)
        metadata_by_id[str(sample.get("sample_id"))] = metadata
        if metadata.get("sample_id") != sample.get("sample_id"):
            errors.append(f"sample metadata ID mismatch: {sample.get('path')}")
        if sample.get("state") != "captured":
            continue
        if not legacy and plans_by_id.get(visit_id, {}).get("workload_model") is not None:
            plan = plans_by_id.get(visit_id, {})
            for key in (
                "workload_scope",
                "workload_model",
                "source_manifest_sha256",
                "resolved_manifest_sha256",
                "resource_count",
                "origin_count",
                "expected_endpoint_count",
            ):
                if metadata.get(key) != plan.get(key):
                    errors.append(f"sample {key} mismatch: {sample.get('path')}")
            run_data = load_json(sample_path / "neqo" / "run.json")
            actual_endpoints = len(run_data.get("endpoints", []))
            if actual_endpoints != plan.get("expected_endpoint_count"):
                errors.append(f"sample endpoint count mismatch: {sample.get('path')}")
        if metadata.get("resolved_defense") is None:
            errors.append(f"captured sample lacks resolved defense: {sample.get('path')}")
        views = _views(metadata)
        recorded = {view.get("id") for view in views}
        if recorded != set(definitions):
            errors.append(f"sample view plan disagrees with dataset: {sample.get('path')}")
        valid = {view["id"] for view in views if view.get("valid")}
        for view in views:
            if view.get("valid"):
                _validate_view(root, sample_path, view, definitions, errors)
        if primary and _eligible(sample) and primary[0]["id"] not in valid:
            errors.append(f"eligible sample lacks its primary view: {sample.get('path')}")
        if not legacy:
            indexed_views = sample.get("views")
            expected = {identifier: identifier in valid for identifier in definitions}
            if indexed_views != expected:
                errors.append(f"indexed view validity is incorrect: {sample.get('path')}")

    for visit_id, members in by_visit.items():
        if {sample.get("defense") for sample in members} != defenses:
            errors.append(f"paired visit {visit_id} does not contain every defense")
        baseline = next(
            (sample for sample in members if sample.get("defense") in baselines), None
        )
        reference = response_signature(root / baseline["path"]) if baseline else None
        for sample in members:
            if sample.get("state") != "captured":
                continue
            metadata = metadata_by_id.get(str(sample.get("sample_id")), {})
            signature = response_signature(root / sample["path"])
            drift = reference is not None and signature is not None and signature != reference
            matches = reference is not None and signature is not None and not drift
            if metadata.get("content_drift") != drift or sample.get("content_drift") != drift:
                errors.append(f"content drift state is incorrect: {sample.get('path')}")
            recorded_match = metadata.get("response_match", sample.get("response_match"))
            if recorded_match is not None and recorded_match != matches:
                errors.append(f"response match state is incorrect: {sample.get('path')}")
            primary_valid = bool(
                primary
                and any(
                    view.get("id") == primary[0]["id"] and view.get("valid")
                    for view in _views(metadata)
                )
            )
            if _eligible(sample) != bool(matches and primary_valid):
                errors.append(f"sample eligibility is incorrect: {sample.get('path')}")

    if len(primary) != 1:
        errors.append("dataset must declare exactly one primary view")
    elif purpose == "classification" and primary[0].get("kind") != "wireguard-outer":
        errors.append("classification requires outer WireGuard as primary")
    elif purpose == "diagnostics" and primary[0].get("kind") != "direct-quic":
        errors.append("diagnostics requires direct QUIC as primary")
    if purpose == "diagnostics":
        warnings.append("direct diagnostics cannot support privacy-classification publication")
    if dataset.get("data_license") == "not-for-release":
        warnings.append("dataset is marked not-for-release")
    if not legacy:
        for entry in campaign.get("configuration", {}).get("workloads", {}).get("entries", []):
            if "resolved_manifest_sha256" not in entry:
                continue
            resolved = root / "resolved-workloads" / f"{entry.get('workload_id')}.json"
            if not resolved.is_file():
                errors.append(f"resolved workload is missing: {resolved.name}")
            elif sha256_file(resolved) != entry.get("resolved_manifest_sha256"):
                errors.append(f"resolved workload hash mismatch: {resolved.name}")
    if (root / "SHA256SUMS").is_file():
        _verify_checksums(root, errors)
    else:
        warnings.append("dataset is not sealed with SHA256SUMS")
    return _validation_result(errors, warnings, samples, by_visit, raise_on_error, purpose)


def _validation_result(
    errors: list[str],
    warnings: list[str],
    samples: list[dict[str, Any]],
    visits: dict[str, Any],
    raise_on_error: bool,
    purpose: str | None = None,
) -> dict[str, Any]:
    if errors and raise_on_error:
        raise DatasetValidationError(errors)
    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "logical_samples": len(samples),
        "paired_visits": len(visits),
        "purpose": purpose,
        "eligible_samples": sum(_eligible(sample) for sample in samples),
    }


def _views(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    return metadata.get("views", metadata.get("observers", []))


def _eligible(sample: dict[str, Any]) -> bool:
    return sample.get(
        "eligible", sample.get("primary_eligible", sample.get("classifier_eligible", False))
    ) is True


def _purpose(dataset: dict[str, Any], primary: list[dict[str, Any]]) -> str:
    if dataset.get("purpose") in {"classification", "diagnostics"}:
        return str(dataset["purpose"])
    return "classification" if primary and primary[0].get("kind") == "wireguard-outer" else "diagnostics"


def _validate_view(
    root: Path,
    sample: Path,
    view: dict[str, Any],
    declarations: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    identifier = view.get("id")
    declaration = declarations.get(identifier)
    label = f"{sample.relative_to(root)}:{identifier}"
    if declaration is None:
        errors.append(f"undeclared view in {label}")
        return
    for key in ("kind", "interface", "length_basis", "link_type"):
        if view.get(key) != declaration.get(key):
            errors.append(f"view {key} mismatch in {label}")
    capture = sample / str(view.get("capture_path", ""))
    trace_path = sample / str(view.get("trace_path", ""))
    if not capture.is_file() or not trace_path.is_file():
        errors.append(f"view artifact missing in {label}")
        return
    info = run(["capinfos", "-E", str(capture)], check=False)
    if capture.read_bytes()[:4] != b"\x0a\x0d\x0d\x0a":
        errors.append(f"capture is not PCAPNG in {label}")
    if info.returncode or str(view.get("link_type", "")).lower() not in info.stdout.lower():
        errors.append(f"capture link type mismatch in {label}")
    if view.get("truncated") is not False:
        errors.append(f"capture is truncated in {label}")
    if sha256_file(capture) != view.get("capture_sha256"):
        errors.append(f"capture hash mismatch in {label}")
    if sha256_file(trace_path) != view.get("trace_sha256"):
        errors.append(f"trace hash mismatch in {label}")
    try:
        rows = read_normalized_trace(trace_path)
        endpoints = load_json(sample / "neqo" / "run.json").get("endpoints", [])
        derived = extract_trace(
            capture,
            endpoints,
            kind=view["kind"],
            length_basis=view["length_basis"],
            client_port=view.get("client_port"),
        )
    except (KeyError, OSError, RuntimeError, ValueError) as error:
        errors.append(f"trace cannot be reproduced in {label}: {error}")
        return
    expected = [
        {
            "relative_time_ns": str(packet.relative_time_ns),
            "direction": packet.direction,
            "length_bytes": str(packet.length_bytes),
            "signed_length_bytes": str(packet.signed_length_bytes),
        }
        for packet in derived
    ]
    if rows != expected:
        errors.append(f"normalized trace disagrees with PCAPNG in {label}")
    if len(rows) != view.get("packet_count"):
        errors.append(f"packet count mismatch in {label}")
    for row in rows:
        length = int(row["length_bytes"])
        signed = int(row["signed_length_bytes"])
        expected_sign = length if row["direction"] == "outgoing" else -length
        if length <= 0 or signed != expected_sign:
            errors.append(f"invalid direction/length semantics in {label}")
            break


def _verify_checksums(root: Path, errors: list[str]) -> None:
    for line in (root / "SHA256SUMS").read_text().splitlines():
        try:
            expected, relative = line.split("  ", 1)
        except ValueError:
            errors.append("invalid SHA256SUMS line")
            continue
        path = root / relative
        if not path.is_file() or sha256_file(path) != expected:
            errors.append(f"checksum mismatch: {relative}")


def write_projection(root: Path, *, reference_visits_per_defense: int = 20_000) -> Path:
    samples = load_sample_index(root)
    captured = [sample for sample in samples if sample.get("state") == "captured"]
    campaign = load_json(root / "campaign.json")
    started = _parse_time(campaign.get("campaign", {}).get("started_at"))
    completed = _parse_time(campaign.get("campaign", {}).get("completed_at"))
    wall = (completed - started).total_seconds() if started and completed else None
    storage = _storage(root, captured)
    internal = sum(
        path.stat().st_size
        for sample in captured
        for name in ("neqo", "attempts")
        for path in (root / sample["path"] / name).rglob("*")
        if path.is_file()
    )
    requests = delivered = 0
    origins: Counter[str] = Counter()
    for sample in captured:
        run_json = root / sample["path"] / "neqo" / "run.json"
        if not run_json.is_file():
            continue
        for response in load_json(run_json).get("responses", []):
            requests += 1
            delivered += int(response.get("bytes", 0))
            if response.get("url"):
                origins[str(response["url"]).split("/", 3)[2]] += 1
    defenses = sorted({str(sample.get("defense")) for sample in samples})
    per_defense = {}
    for defense in defenses:
        members = [sample for sample in captured if sample.get("defense") == defense]
        factor = reference_visits_per_defense / max(len(members), 1)
        measured = _storage(root, members)
        per_defense[defense] = {
            "measured_samples": len(members),
            "views": {
                name: {
                    **values,
                    "projected_pcapng_bytes": round(values["pcapng_bytes"] * factor),
                    "projected_trace_bytes": round(values["trace_bytes"] * factor),
                }
                for name, values in measured.items()
            },
        }
    scale = reference_visits_per_defense * len(defenses) / max(len(captured), 1)
    projection = {
        "measured": {
            "wall_seconds": wall,
            "logical_samples": len(samples),
            "captured_samples": len(captured),
            "attempts": sum(int(sample.get("attempts", 0)) for sample in samples),
            "failure_rate": sum(sample.get("state") != "captured" for sample in samples) / max(len(samples), 1),
            "drift_rate": sum(sample.get("content_drift") is True for sample in samples) / max(len(samples), 1),
            "views": storage,
            "internal_bytes": internal,
            "requests": requests,
            "delivered_response_bytes": delivered,
            "requests_by_origin": dict(origins),
            "throughput_samples_per_hour": len(captured) * 3600 / wall if wall else None,
        },
        "qcsd_scale_reference": {
            "visits_per_defense": reference_visits_per_defense,
            "defense_count": len(defenses),
            "per_defense": per_defense,
            "projected_wall_seconds": round(wall * scale) if wall else None,
            "projected_internal_bytes": round(internal * scale),
            "retention_decision": "requires explicit authorization",
            "geographic_gateway_feasibility": "not established locally",
        },
    }
    destination = root / "projection.json"
    atomic_json(destination, projection)
    return destination


def _storage(root: Path, samples: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    totals: dict[str, dict[str, int]] = {}
    for sample in samples:
        path = root / sample["path"]
        metadata = load_json(path / "sample.json")
        for view in _views(metadata):
            if not view.get("valid"):
                continue
            values = totals.setdefault(
                view["id"], {"valid_samples": 0, "pcapng_bytes": 0, "trace_bytes": 0}
            )
            values["valid_samples"] += 1
            values["pcapng_bytes"] += (path / view["capture_path"]).stat().st_size
            values["trace_bytes"] += (path / view["trace_path"]).stat().st_size
    return totals


def package_dataset(
    root: Path,
    *,
    pcaps: str,
    output: Path | None = None,
    data_license: str | None = None,
) -> Path:
    if pcaps not in {"primary", "all", "none"}:
        raise ValueError("pcaps must be primary, all, or none")
    validation = validate_dataset(root)
    dataset = load_json(root / "dataset.json")
    primary = next(
        item for item in dataset["observer_definitions"] if item.get("primary")
    )
    if _purpose(dataset, [primary]) != "classification":
        raise ValueError("publication packaging requires WireGuard classification")
    license_name = data_license or dataset.get("data_license")
    if not license_name or license_name == "not-for-release":
        raise ValueError("publication packaging requires an explicit data license")
    output = output or root.parent / f"{root.name}-dataset-{pcaps}.tar.gz"
    if output.exists():
        raise FileExistsError(f"package already exists: {output}")
    with tempfile.TemporaryDirectory(prefix="qcsd-package-", dir=output.parent) as directory:
        stage = Path(directory) / root.name
        stage.mkdir()
        for name in ("dataset.json", "splits.json", "metrics.csv", "projection.json", "report.html"):
            shutil.copy2(root / name, stage / name)
        for name in ("dataset-summary.pdf", "dataset-summary.svg"):
            if (root / name).is_file():
                shutil.copy2(root / name, stage / name)
        card = load_json(stage / "dataset.json")
        card.update(data_license=license_name, release_status="licensed")
        card["package"] = {"pcaps": pcaps, "validation": validation}
        atomic_json(stage / "dataset.json", card)
        atomic_text(stage / "DATASET.md", _standalone_card(card))
        safe_samples = []
        for sample in load_sample_index(root):
            safe_samples.append(
                {
                    key: sample.get(key)
                    for key in (
                        "sample_id",
                        "visit_id",
                        "workload_id",
                        "class_label",
                        "role",
                        "repetition",
                        "defense",
                        "path",
                        "split",
                        "state",
                        "eligible",
                        "content_drift",
                    )
                    if sample.get(key) is not None
                }
            )
            source = root / sample["path"]
            destination = stage / sample["path"]
            metadata = load_json(source / "sample.json")
            valid = {view["id"] for view in _views(metadata) if view.get("valid")}
            selected = valid if pcaps == "all" else ({primary["id"]} & valid)
            traces = destination / "traces"
            traces.mkdir(parents=True, exist_ok=True)
            for identifier in sorted(selected):
                shutil.copy2(source / "traces" / f"{identifier}.csv", traces)
            if pcaps != "none":
                captures = destination / "captures"
                captures.mkdir(parents=True, exist_ok=True)
                for identifier in sorted(selected):
                    shutil.copy2(source / "captures" / f"{identifier}.pcapng", captures)
        atomic_text(
            stage / "samples.jsonl",
            "".join(json.dumps(sample, sort_keys=True) + "\n" for sample in safe_samples),
        )
        write_checksums(stage, [path for path in stage.rglob("*") if path.is_file() and path.name != "SHA256SUMS"])
        with tarfile.open(output, "w:gz") as archive:
            archive.add(stage, arcname=stage.name)
    return output


def _standalone_card(dataset: dict[str, Any]) -> str:
    return f"""# {dataset['title']}

License: {dataset['data_license']}

This package contains encrypted-datagram timing, direction, and size traces captured at
`{dataset['primary_observer']}`. Each train/test assignment belongs to a paired visit and is
shared by every defense. Classifiers may use only the normalized trace columns; qlogs,
destinations, responses, schedules, plaintext, and keys are excluded.
"""


def _parse_time(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None
