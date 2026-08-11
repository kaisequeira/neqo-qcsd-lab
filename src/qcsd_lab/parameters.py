"""Validation for immutable smoke fixtures and sealed research parameters."""

from __future__ import annotations

import math
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .profiles import UDP_PAYLOAD_CEILING_BY_PROFILE
from .util import LAB_ROOT, load_json, sha256_file

PROVENANCE_SCHEMA_VERSION = 1
REVIEWED_PARAMETER_INPUT_POLICY = "reviewed-engineering-fixture"
REVIEWED_FIXTURE_STATUS = "reviewed-smoke-fixture"
PARAMETER_ARTIFACT_NAME = "defense-parameters.json"
PARAMETER_PROVENANCE_ARTIFACT_NAME = "defense-parameters.provenance.json"

_PROVENANCE_KEYS = {
    "schema_version",
    "artifact_type",
    "status",
    "production_ready",
    "defense_kind",
    "qcsd_profile",
    "udp_payload_ceiling",
    "parameter_file",
}
_PARAMETER_FILE_KEYS = {"path", "sha256"}
_PARAMETERIZED_KINDS = {"traffic_morphing", "wtf_pad", "walkie_talkie"}


@dataclass(frozen=True)
class ParameterArtifact:
    """One validated runtime JSON file and its adjacent receipt."""

    path: Path
    sha256: str
    provenance_path: Path
    provenance_sha256: str
    input_policy: str = REVIEWED_PARAMETER_INPUT_POLICY


def parameter_provenance_path(parameter: Path) -> Path:
    """Return a fitted bundle's common receipt or a smoke fixture's adjacent receipt."""

    common = parameter.parent / "provenance.json"
    if parameter.name in {
        "traffic-morphing.json",
        "wtf-pad.json",
        "walkie-talkie.json",
    } and common.is_file():
        return common
    return parameter.with_suffix(parameter.suffix + ".provenance.json")


def validate_parameter_artifact(
    parameter_path: Path,
    *,
    provenance_path: Path | None = None,
    expected_kind: str | None = None,
    allow_reviewed_fixture: bool = False,
    expected_qcsd_profile: str | None = None,
    expected_udp_payload_ceiling: int | None = None,
    expected_workloads: Mapping[str, object] | Collection[str] | None = None,
) -> ParameterArtifact:
    """Validate one runtime parameter file and its concise smoke receipt.

    ``allow_reviewed_fixture`` is deliberately explicit.  The orchestrator
    enables it only for smoke campaigns, so fitting and evaluation campaigns
    cannot accidentally treat the acceptance fixtures as research artifacts.
    """

    return _validate_parameter_artifact(
        parameter_path,
        provenance_path=provenance_path,
        expected_kind=expected_kind,
        allow_reviewed_fixture=allow_reviewed_fixture,
        expected_qcsd_profile=expected_qcsd_profile,
        expected_udp_payload_ceiling=expected_udp_payload_ceiling,
        expected_workloads=expected_workloads,
        receipt_parameter_name=None,
        require_checked_in_fixture=True,
    )


def validate_frozen_parameter_artifact(
    parameter_path: Path,
    *,
    provenance_path: Path,
    original_parameter_name: str,
    expected_kind: str,
    allow_reviewed_fixture: bool,
    expected_qcsd_profile: str,
    expected_udp_payload_ceiling: int,
    expected_workloads: Mapping[str, object] | Collection[str],
) -> ParameterArtifact:
    """Revalidate a copied artifact using its frozen campaign binding.

    Frozen files deliberately have canonical result names (``parameters.json``
    and ``provenance.json``), while the receipt names the checked-in source
    artifact.  This entry point preserves that filename binding without
    pretending the result copy itself is a checked-in fixture.
    """

    if not original_parameter_name or Path(original_parameter_name).name != original_parameter_name:
        raise ValueError("frozen parameter source name must be a filename")
    return _validate_parameter_artifact(
        parameter_path,
        provenance_path=provenance_path,
        expected_kind=expected_kind,
        allow_reviewed_fixture=allow_reviewed_fixture,
        expected_qcsd_profile=expected_qcsd_profile,
        expected_udp_payload_ceiling=expected_udp_payload_ceiling,
        expected_workloads=expected_workloads,
        receipt_parameter_name=original_parameter_name,
        require_checked_in_fixture=False,
    )


def _validate_parameter_artifact(
    parameter_path: Path,
    *,
    provenance_path: Path | None,
    expected_kind: str | None,
    allow_reviewed_fixture: bool,
    expected_qcsd_profile: str | None,
    expected_udp_payload_ceiling: int | None,
    expected_workloads: Mapping[str, object] | Collection[str] | None,
    receipt_parameter_name: str | None,
    require_checked_in_fixture: bool,
) -> ParameterArtifact:
    receipt_path = (
        provenance_path
        if provenance_path is not None
        else parameter_provenance_path(parameter_path)
    )
    if parameter_path.is_symlink() or receipt_path.is_symlink():
        raise ValueError("defense parameter files must not be symbolic links")
    parameter_path = parameter_path.resolve()
    receipt_path = receipt_path.resolve()
    if not parameter_path.is_file():
        raise ValueError(f"defense parameter file does not exist: {parameter_path}")
    if not receipt_path.is_file():
        raise ValueError(
            f"defense parameter file requires an adjacent provenance receipt: {receipt_path}"
        )

    parameter = _mapping(load_json(parameter_path), "defense parameters")
    receipt = _mapping(load_json(receipt_path), "parameter provenance")
    if receipt.get("artifact_type") == "qcsd-research-defense-bundle":
        from .fitting import BUNDLE_FILES, research_parameter_record

        expected_parameter_name = receipt_parameter_name or parameter_path.name
        inferred = {
            filename: kind for kind, filename in BUNDLE_FILES.items()
        }.get(expected_parameter_name)
        kind = expected_kind or inferred
        if kind not in _PARAMETERIZED_KINDS:
            raise ValueError("research parameter defense kind cannot be inferred")
        if expected_qcsd_profile not in {None, "research-1200"}:
            raise ValueError("research parameter QCSD profile does not match campaign")
        if expected_udp_payload_ceiling not in {None, 1_200}:
            raise ValueError("research parameter UDP ceiling does not match campaign")
        parameter_sha256, provenance_sha256, input_policy = research_parameter_record(
            parameter_path,
            receipt_path,
            expected_kind=kind,
            expected_workloads=expected_workloads,
            parameter_name=expected_parameter_name,
        )
        return ParameterArtifact(
            path=parameter_path,
            sha256=parameter_sha256,
            provenance_path=receipt_path,
            provenance_sha256=provenance_sha256,
            input_policy=input_policy,
        )
    _require_exact_keys(receipt, _PROVENANCE_KEYS, "parameter provenance")
    if receipt.get("schema_version") != PROVENANCE_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported parameter provenance schema_version in {receipt_path}; "
            f"expected {PROVENANCE_SCHEMA_VERSION}"
        )
    if receipt.get("artifact_type") != "qcsd-defense-parameters":
        raise ValueError(f"parameter provenance has the wrong artifact type: {receipt_path}")
    if (
        receipt.get("status") != REVIEWED_FIXTURE_STATUS
        or receipt.get("production_ready") is not False
    ):
        raise ValueError(
            f"parameter provenance must explicitly declare a non-production smoke fixture: "
            f"{receipt_path}"
        )
    if not allow_reviewed_fixture:
        raise ValueError("reviewed smoke parameter fixtures are accepted only by smoke campaigns")
    if require_checked_in_fixture:
        _require_checked_in_fixture(parameter_path, receipt_path)

    parameter_sha256 = sha256_file(parameter_path)
    recorded_file = _mapping(receipt.get("parameter_file"), "parameter_file metadata")
    _require_exact_keys(recorded_file, _PARAMETER_FILE_KEYS, "parameter_file metadata")
    expected_parameter_name = receipt_parameter_name or parameter_path.name
    if recorded_file.get("path") != expected_parameter_name:
        raise ValueError(f"parameter provenance filename mismatch: {receipt_path}")
    if recorded_file.get("sha256") != parameter_sha256:
        raise ValueError(f"parameter provenance SHA-256 mismatch: {receipt_path}")

    kind = receipt.get("defense_kind")
    if kind not in _PARAMETERIZED_KINDS:
        raise ValueError(f"parameter provenance has an unsupported defense kind: {receipt_path}")
    if expected_kind is not None and kind != expected_kind:
        raise ValueError(f"parameter defense kind does not match campaign: {receipt_path}")

    profile = receipt.get("qcsd_profile")
    if profile not in UDP_PAYLOAD_CEILING_BY_PROFILE:
        raise ValueError(f"parameter provenance has an unsupported QCSD profile: {receipt_path}")
    ceiling = receipt.get("udp_payload_ceiling")
    if type(ceiling) is not int or ceiling != UDP_PAYLOAD_CEILING_BY_PROFILE[profile]:
        raise ValueError(f"parameter provenance profile and UDP ceiling disagree: {receipt_path}")
    if expected_qcsd_profile is not None and profile != expected_qcsd_profile:
        raise ValueError(f"parameter QCSD profile does not match campaign: {receipt_path}")
    if expected_udp_payload_ceiling is not None and ceiling != expected_udp_payload_ceiling:
        raise ValueError(f"parameter UDP ceiling does not match campaign: {receipt_path}")
    if (
        expected_qcsd_profile is not None
        and expected_udp_payload_ceiling is not None
        and UDP_PAYLOAD_CEILING_BY_PROFILE.get(expected_qcsd_profile)
        != expected_udp_payload_ceiling
    ):
        raise ValueError("expected QCSD profile and UDP ceiling disagree")

    _validate_runtime_shape(parameter, str(kind), int(ceiling), receipt_path)
    _validate_workload_coverage(parameter, str(kind), expected_workloads, receipt_path)
    return ParameterArtifact(
        path=parameter_path,
        sha256=parameter_sha256,
        provenance_path=receipt_path,
        provenance_sha256=sha256_file(receipt_path),
    )


def validate_run_parameter_binding(
    run_data: Mapping[str, Any],
    *,
    kind: str,
    sha256: str,
    expected_path: Path | None = None,
    expected_workload_id: str | None = None,
) -> None:
    """Check the runner's kind/hash/path receipt for an external parameter."""

    parameter = run_data.get("defense_parameters")
    if (
        not isinstance(parameter, Mapping)
        or parameter.get("kind") != kind
        or parameter.get("sha256") != sha256
        or (expected_path is not None and parameter.get("path") != str(expected_path))
    ):
        raise ValueError("sample defense parameter run binding mismatch")
    if expected_workload_id is None:
        return
    resolved = run_data.get("resolved_configuration")
    defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    if not isinstance(defense, Mapping) or defense.get("workload_id") != expected_workload_id:
        raise ValueError("sample defense workload run binding mismatch")


def _require_checked_in_fixture(parameter_path: Path, receipt_path: Path) -> None:
    fixture_root = (LAB_ROOT / "config/defense-params").resolve()
    if not parameter_path.is_relative_to(fixture_root) or not receipt_path.is_relative_to(
        fixture_root
    ):
        raise ValueError(f"reviewed smoke fixtures must be checked in under {fixture_root}")
    if receipt_path != parameter_provenance_path(parameter_path):
        raise ValueError("parameter provenance receipt must be adjacent to its parameter file")


def _validate_runtime_shape(
    parameter: Mapping[str, Any],
    kind: str,
    ceiling: int,
    receipt_path: Path,
) -> None:
    if (
        parameter.get("schema_version") != 2
        or parameter.get("adaptation") != "qcsd-client-only"
        or parameter.get("paper_equivalent") is not False
    ):
        raise ValueError(
            f"{kind} parameter file lacks the versioned client-only runtime contract: "
            f"{receipt_path}"
        )
    if kind == "traffic_morphing":
        _validate_traffic_morphing(parameter, ceiling, receipt_path)
    elif kind == "wtf_pad":
        _validate_wtf_pad(parameter, receipt_path)
    else:
        _validate_walkie_talkie(parameter, ceiling, receipt_path)


def _validate_traffic_morphing(
    parameter: Mapping[str, Any], ceiling: int, receipt_path: Path
) -> None:
    buckets = parameter.get("buckets")
    profiles = parameter.get("profiles")
    if (
        parameter.get("udp_payload_ceiling") != ceiling
        or not isinstance(buckets, list)
        or not buckets
        or any(type(value) is not int or value <= 0 for value in buckets)
        or buckets != sorted(set(buckets))
        or buckets[-1] > ceiling
        or not isinstance(profiles, list)
        or not profiles
    ):
        raise ValueError(f"traffic_morphing parameter runtime shape is invalid: {receipt_path}")
    sources: list[str] = []
    for profile in profiles:
        if not isinstance(profile, Mapping):
            raise ValueError(f"traffic_morphing profile is malformed: {receipt_path}")
        source = profile.get("source")
        target = profile.get("target")
        if not isinstance(source, str) or not source or not isinstance(target, str) or not target:
            raise ValueError(f"traffic_morphing profile identity is invalid: {receipt_path}")
        sources.append(source)
        for direction in ("outgoing", "incoming"):
            _validate_morphing_direction(profile.get(direction), len(buckets), receipt_path)
    if len(sources) != len(set(sources)):
        raise ValueError(f"traffic_morphing source profiles are duplicated: {receipt_path}")


def _validate_morphing_direction(value: Any, width: int, receipt_path: Path) -> None:
    direction = _mapping(value, "traffic_morphing direction")
    for name in ("source_distribution", "target_distribution", "realized_distribution"):
        distribution = direction.get(name)
        if not _probability_row(distribution, width):
            raise ValueError(f"traffic_morphing {name} is invalid: {receipt_path}")
    rows = direction.get("rows")
    if (
        not isinstance(rows, list)
        or len(rows) != width
        or any(not _probability_row(row, width) for row in rows)
    ):
        raise ValueError(f"traffic_morphing matrix is invalid: {receipt_path}")


def _validate_wtf_pad(parameter: Mapping[str, Any], receipt_path: Path) -> None:
    if not isinstance(parameter.get("fitting"), Mapping):
        raise ValueError(f"wtf_pad fitting metadata is missing: {receipt_path}")
    for direction_name in ("outgoing", "incoming"):
        direction = _mapping(parameter.get(direction_name), f"wtf_pad {direction_name}")
        for state in ("burst", "gap"):
            histogram = _mapping(direction.get(state), f"wtf_pad {direction_name} {state}")
            edges = histogram.get("edges_us")
            tokens = histogram.get("tokens")
            infinity = histogram.get("infinity_tokens")
            if (
                not isinstance(edges, list)
                or not edges
                or any(type(value) is not int or value <= 0 for value in edges)
                or edges != sorted(set(edges))
                or not isinstance(tokens, list)
                or len(tokens) != len(edges)
                or any(type(value) is not int or value < 0 for value in tokens)
                or sum(tokens) < 1
                or type(infinity) is not int
                or infinity < 1
            ):
                raise ValueError(
                    f"wtf_pad {direction_name} {state} histogram is invalid: {receipt_path}"
                )


def _validate_walkie_talkie(parameter: Mapping[str, Any], ceiling: int, receipt_path: Path) -> None:
    profiles = parameter.get("profiles")
    if (
        parameter.get("packet_size") != ceiling
        or parameter.get("matching_algorithm") != "minimum-cost-one-to-one"
        or not isinstance(profiles, list)
        or not profiles
    ):
        raise ValueError(f"walkie_talkie parameter runtime shape is invalid: {receipt_path}")
    real_ids: list[str] = []
    decoy_ids: list[str] = []
    for profile in profiles:
        if not isinstance(profile, Mapping):
            raise ValueError(f"walkie_talkie profile is malformed: {receipt_path}")
        real = profile.get("real")
        decoy = profile.get("decoy")
        bursts = profile.get("bursts")
        if (
            not isinstance(real, str)
            or not real
            or not isinstance(decoy, str)
            or not decoy
            or not isinstance(bursts, list)
            or not bursts
        ):
            raise ValueError(f"walkie_talkie profile identity is invalid: {receipt_path}")
        real_ids.append(real)
        decoy_ids.append(decoy)
        for burst in bursts:
            if not isinstance(burst, Mapping):
                raise ValueError(f"walkie_talkie burst is malformed: {receipt_path}")
            outgoing = burst.get("outgoing")
            incoming = burst.get("incoming")
            if (
                type(outgoing) is not int
                or outgoing < 0
                or type(incoming) is not int
                or incoming < 0
                or outgoing + incoming < 1
            ):
                raise ValueError(f"walkie_talkie burst is invalid: {receipt_path}")
    identities = [*real_ids, *decoy_ids]
    if len(identities) != len(set(identities)):
        raise ValueError(f"walkie_talkie profiles are duplicated: {receipt_path}")


def _validate_workload_coverage(
    parameter: Mapping[str, Any],
    kind: str,
    expected_workloads: Mapping[str, object] | Collection[str] | None,
    receipt_path: Path,
) -> None:
    if expected_workloads is None or kind == "wtf_pad":
        return
    expected = set(expected_workloads)
    if not expected or any(not isinstance(value, str) or not value for value in expected):
        raise ValueError("expected workloads must contain non-empty workload IDs")
    profiles = parameter.get("profiles")
    assert isinstance(profiles, list)  # validated by the kind-specific parser
    if kind == "traffic_morphing":
        observed = {
            str(profile["source"])
            for profile in profiles
            if isinstance(profile, Mapping) and isinstance(profile.get("source"), str)
        }
    else:
        observed = {
            str(profile[identity])
            for profile in profiles
            if isinstance(profile, Mapping)
            for identity in ("real", "decoy")
            if isinstance(profile.get(identity), str)
        }
    if not expected <= observed:
        raise ValueError(
            f"{kind} parameter profiles do not cover all campaign workloads: {receipt_path}"
        )


def _probability_row(value: Any, width: int) -> bool:
    return (
        isinstance(value, list)
        and len(value) == width
        and all(_finite_number(item) and 0 <= float(item) <= 1 for item in value)
        and math.isclose(sum(float(item) for item in value), 1.0, abs_tol=1e-6)
    )


def _finite_number(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = ", ".join(sorted(expected - set(value))) or "none"
        extra = ", ".join(sorted(set(value) - expected)) or "none"
        raise ValueError(f"{label} has the wrong fields (missing: {missing}; extra: {extra})")
