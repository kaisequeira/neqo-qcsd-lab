"""Independent raw-run bindings for the extended class-study campaigns.

The collector checks these identities before accepting an attempt.  This module
reconstructs the same contract from sealed inputs so fitting, promotion,
handoff, and attestation do not have to trust the mutable-looking labels in
``experiment.json``.  In particular, the executed runtime graph is always
derived from the admitted prepared application manifest; it is never inferred
from a defense-specific run receipt.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .manifest import canonical_bytes, https_origin, runtime_manifest
from .util import load_json, sha256_bytes, sha256_file


RUNTIME_KIND_BY_MODE = {
    "undefended": "none",
    "static": "static",
    "front": "front",
    "tamaraw": "tamaraw",
    "traffic-morphing": "traffic_morphing",
    "wtf-pad": "wtf_pad",
    "walkie-talkie": "walkie_talkie",
    "buflo": "buflo",
    "cs-buflo": "cs_buflo",
}
BUILT_IN_DEFENDED_RUNTIME_KINDS = frozenset({"front", "tamaraw"})
PARAMETERISED_RUNTIME_KINDS = frozenset(
    {"traffic_morphing", "wtf_pad", "walkie_talkie", "buflo", "cs_buflo"}
)
WORKLOAD_SCOPED_RUNTIME_KINDS = frozenset({"traffic_morphing", "walkie_talkie"})
INPUT_BINDING_KEYS = frozenset(
    {
        "campaign_sha256",
        "application_workload_sha256",
        "runtime_workload_sha256",
        "chaff_qualification_sha256",
        "chaff_manifest_sha256",
        "defense_parameters_sha256",
        "defense_parameters_provenance_sha256",
        "max_response_bytes",
        "max_udp_payload_size",
    }
)


@dataclass(frozen=True)
class ClassSampleRunBinding:
    """Resolved launch and application-correctness identity for one sample."""

    input_bindings: dict[str, Any]
    workload_id: str
    mode: str
    runtime_kind: str
    baseline: bool
    expected_origins: tuple[str, ...]
    expected_responses: tuple[tuple[Any, ...], ...]

    def receipt(self) -> dict[str, Any]:
        """Return the portable JSON receipt embedded in downstream evidence."""

        return dict(self.input_bindings)


def resolve_class_sample_run_binding(
    result_root: Path,
    configuration: Mapping[str, Any],
    sample: Mapping[str, Any],
    *,
    allow_derived_runtime_without_frozen_copy: bool = False,
) -> ClassSampleRunBinding:
    """Reconstruct one sample's exact launch inputs from sealed configuration."""

    root = Path(result_root).resolve()
    workloads = configuration.get("workloads")
    defenses = configuration.get("defenses")
    limits = configuration.get("limits")
    if (
        not isinstance(workloads, list)
        or not isinstance(defenses, list)
        or not isinstance(limits, Mapping)
    ):
        raise ValueError("class-study source configuration is incomplete")

    workload_id = sample.get("workload_id")
    mode = sample.get("defense")
    runtime_kind = sample.get("runtime_kind")
    baseline = sample.get("baseline")
    if (
        not isinstance(workload_id, str)
        or not isinstance(mode, str)
        or not isinstance(runtime_kind, str)
        or type(baseline) is not bool
        or RUNTIME_KIND_BY_MODE.get(mode) != runtime_kind
        or baseline is not (mode == "undefended")
    ):
        raise ValueError("class-study sample has an invalid defense/workload identity")

    workload_matches = [
        value
        for value in workloads
        if isinstance(value, Mapping) and value.get("id") == workload_id
    ]
    defense_matches = [
        value for value in defenses if isinstance(value, Mapping) and value.get("name") == mode
    ]
    if len(workload_matches) != 1 or len(defense_matches) != 1:
        raise ValueError("class-study sample is absent from its frozen configuration")
    workload = workload_matches[0]
    defense = defense_matches[0]
    if defense.get("kind") != runtime_kind or defense.get("baseline") is not baseline:
        raise ValueError("class-study sample defense differs from its frozen configuration")

    campaign_path = _bound_file(root, "inputs/campaign.yml", label="campaign")
    campaign_sha256 = sha256_file(campaign_path)
    if configuration.get("campaign_sha256") != campaign_sha256:
        raise ValueError("class-study frozen campaign hash is invalid")

    prepared_path = _bound_file(
        root,
        workload.get("manifest"),
        label=f"prepared workload {workload_id}",
    )
    application_sha256 = sha256_file(prepared_path)
    if workload.get("sha256") != application_sha256:
        raise ValueError("class-study prepared application hash is invalid")
    prepared = load_json(prepared_path)
    if not isinstance(prepared, dict):
        raise ValueError("class-study prepared application is not an object")
    runtime = runtime_manifest(prepared)
    runtime_bytes = canonical_bytes(runtime)
    runtime_sha256 = sha256_bytes(runtime_bytes)

    runtime_relative = workload.get("runtime_manifest")
    recorded_runtime_sha256 = workload.get("runtime_manifest_sha256")
    if runtime_relative is None and recorded_runtime_sha256 is None:
        # Undefended fitting campaigns materialise the derived runtime in a
        # temporary file and therefore have no frozen runtime-workload copy.
        if not baseline or not allow_derived_runtime_without_frozen_copy:
            raise ValueError("class-study sample has no frozen runtime graph")
    elif not isinstance(runtime_relative, str) or recorded_runtime_sha256 != runtime_sha256:
        raise ValueError("class-study runtime graph differs from its prepared application")
    else:
        runtime_path = _bound_file(
            root,
            runtime_relative,
            label=f"runtime workload {workload_id}",
        )
        if (
            runtime_path.read_bytes() != runtime_bytes
            or sha256_file(runtime_path) != runtime_sha256
        ):
            raise ValueError("class-study frozen runtime graph is not the prepared projection")

    resources = runtime.get("resources")
    preparation = prepared.get("preparation")
    expected_values = (
        preparation.get("expected_responses") if isinstance(preparation, Mapping) else None
    )
    if not isinstance(resources, list) or not resources or not isinstance(expected_values, list):
        raise ValueError("class-study prepared application graph is incomplete")
    origins = []
    for resource in resources:
        resource_origin = (
            https_origin(str(resource.get("url"))) if isinstance(resource, Mapping) else None
        )
        if resource_origin is None:
            raise ValueError("class-study runtime graph contains an invalid resource origin")
        origins.append(resource_origin)
    unique_origins = tuple(sorted(set(origins)))
    if workload.get("resource_count") != len(resources) or workload.get("origin_count") != len(
        unique_origins
    ):
        raise ValueError("class-study frozen workload cardinality differs from its full graph")
    expected_responses = tuple(
        sorted(
            (
                response.get("resource_id"),
                response.get("status"),
                response.get("bytes"),
                response.get("body_sha256"),
                "succeeded",
            )
            for response in expected_values
            if isinstance(response, Mapping)
        )
    )
    if len(expected_responses) != len(expected_values) or {
        response[0] for response in expected_responses
    } != {resource.get("id") for resource in resources if isinstance(resource, Mapping)}:
        raise ValueError("class-study response identity does not cover its runtime graph")

    chaff_qualification_sha256 = _optional_bound_digest(
        root,
        workload,
        path_key="chaff_qualification",
        sha256_key="chaff_qualification_sha256",
        label=f"chaff qualification {workload_id}",
        required=not baseline,
    )
    chaff_manifest_sha256 = _optional_bound_digest(
        root,
        workload,
        path_key="chaff_manifest",
        sha256_key="chaff_manifest_sha256",
        label=f"chaff manifest {workload_id}",
        required=not baseline,
    )
    parameter_sha256, provenance_sha256 = _defense_input_digests(
        root,
        defense,
        runtime_kind=runtime_kind,
        baseline=baseline,
    )
    max_response_bytes = limits.get("max_response_bytes")
    if (
        configuration.get("profile") != "research-1200"
        or type(max_response_bytes) is not int
        or max_response_bytes <= 0
    ):
        raise ValueError("class-study run limits/profile are invalid")

    input_bindings = {
        "campaign_sha256": campaign_sha256,
        "application_workload_sha256": application_sha256,
        "runtime_workload_sha256": runtime_sha256,
        "chaff_qualification_sha256": (None if baseline else chaff_qualification_sha256),
        "chaff_manifest_sha256": None if baseline else chaff_manifest_sha256,
        "defense_parameters_sha256": parameter_sha256,
        "defense_parameters_provenance_sha256": provenance_sha256,
        "max_response_bytes": max_response_bytes,
        "max_udp_payload_size": 1_200,
    }
    _validate_input_binding_receipt(
        input_bindings,
        baseline=baseline,
        runtime_kind=runtime_kind,
    )
    return ClassSampleRunBinding(
        input_bindings=input_bindings,
        workload_id=workload_id,
        mode=mode,
        runtime_kind=runtime_kind,
        baseline=baseline,
        expected_origins=unique_origins,
        expected_responses=expected_responses,
    )


def validate_class_sample_run_binding(
    run: object,
    sample: Mapping[str, Any],
    binding: ClassSampleRunBinding,
) -> None:
    """Require a sealed ``run.json`` to prove the resolved full-graph launch."""

    if not isinstance(run, Mapping):
        raise ValueError("class-study run receipt is not an object")
    inputs = binding.input_bindings
    _validate_input_binding_receipt(
        inputs,
        baseline=binding.baseline,
        runtime_kind=binding.runtime_kind,
    )
    resolved = run.get("resolved_configuration")
    resolved_defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    if (
        sample.get("workload_id") != binding.workload_id
        or sample.get("defense") != binding.mode
        or sample.get("runtime_kind") != binding.runtime_kind
        or sample.get("baseline") is not binding.baseline
        or run.get("completion_status") != "complete"
        or run.get("error") is not None
        or run.get("seed") != sample.get("seed")
        or run.get("request_policy") != sample.get("request_policy")
        or run.get("workload_hash_sha256") != inputs["runtime_workload_sha256"]
        or run.get("max_response_bytes") != inputs["max_response_bytes"]
        or not isinstance(resolved, Mapping)
        or resolved.get("max_udp_payload_size") != inputs["max_udp_payload_size"]
        or not isinstance(resolved_defense, Mapping)
        or resolved_defense.get("kind") != binding.runtime_kind
    ):
        raise ValueError("class-study run is not bound to its accepted sample")

    parameter = run.get("defense_parameters")
    if binding.baseline:
        if (
            run.get("application_workload_source_hash_sha256") is not None
            or run.get("chaff_manifest_hash_sha256") is not None
            or run.get("chaff_responses", []) != []
            or parameter is not None
        ):
            raise ValueError("class-study baseline run binds unexpected defended inputs")
    else:
        if (
            run.get("application_workload_source_hash_sha256")
            != inputs["application_workload_sha256"]
            or run.get("chaff_manifest_hash_sha256") != inputs["chaff_manifest_sha256"]
        ):
            raise ValueError("class-study defended run graph binding is invalid")
        if binding.runtime_kind in BUILT_IN_DEFENDED_RUNTIME_KINDS:
            if parameter is not None:
                raise ValueError("class-study built-in run binds unexpected parameters")
        elif (
            not isinstance(parameter, Mapping)
            or parameter.get("kind") != binding.runtime_kind
            or parameter.get("sha256") != inputs["defense_parameters_sha256"]
        ):
            raise ValueError("class-study defended run parameter binding is invalid")
        if (
            binding.runtime_kind in WORKLOAD_SCOPED_RUNTIME_KINDS
            and resolved_defense.get("workload_id") != binding.workload_id
        ):
            raise ValueError("class-study defense is bound to another workload profile")

    responses = run.get("responses")
    if not isinstance(responses, list):
        raise ValueError("class-study run has no application response receipts")
    observed_responses = tuple(
        sorted(
            (
                response.get("resource_id"),
                response.get("status"),
                response.get("bytes"),
                response.get("body_sha256"),
                response.get("outcome"),
            )
            for response in responses
            if isinstance(response, Mapping) and response.get("complete") is True
        )
    )
    if (
        len(observed_responses) != len(responses)
        or observed_responses != binding.expected_responses
    ):
        raise ValueError("class-study run responses differ from the prepared full graph")

    endpoints = run.get("endpoints")
    endpoint_origins = (
        [
            https_origin(str(endpoint.get("origin")))
            for endpoint in endpoints
            if isinstance(endpoint, Mapping)
        ]
        if isinstance(endpoints, list)
        else []
    )
    if (
        not isinstance(endpoints, list)
        or len(endpoint_origins) != len(endpoints)
        or len(endpoint_origins) != len(binding.expected_origins)
        or any(origin is None for origin in endpoint_origins)
        or tuple(sorted(str(origin) for origin in endpoint_origins)) != binding.expected_origins
    ):
        raise ValueError("class-study run endpoint origins differ from the full runtime graph")


def _validate_input_binding_receipt(
    value: object,
    *,
    baseline: bool,
    runtime_kind: str,
) -> None:
    if not isinstance(value, Mapping) or set(value) != INPUT_BINDING_KEYS:
        raise ValueError("class-study sample input binding schema is invalid")
    required_digests = (
        "campaign_sha256",
        "application_workload_sha256",
        "runtime_workload_sha256",
    )
    if any(not _digest(value.get(key)) for key in required_digests):
        raise ValueError("class-study sample input digest is invalid")
    optional_digests = (
        "chaff_qualification_sha256",
        "chaff_manifest_sha256",
        "defense_parameters_sha256",
        "defense_parameters_provenance_sha256",
    )
    if any(
        item is not None and not _digest(item)
        for item in (value.get(key) for key in optional_digests)
    ):
        raise ValueError("class-study optional sample input digest is invalid")
    if (
        type(value.get("max_response_bytes")) is not int
        or value["max_response_bytes"] <= 0
        or value.get("max_udp_payload_size") != 1_200
    ):
        raise ValueError("class-study sample limit binding is invalid")
    if baseline:
        if runtime_kind != "none" or any(
            value.get(key) is not None
            for key in (
                "chaff_qualification_sha256",
                "chaff_manifest_sha256",
                "defense_parameters_sha256",
                "defense_parameters_provenance_sha256",
            )
        ):
            raise ValueError("class-study baseline input binding is invalid")
        return
    if runtime_kind in BUILT_IN_DEFENDED_RUNTIME_KINDS:
        if any(
            value.get(key) is not None
            for key in (
                "defense_parameters_sha256",
                "defense_parameters_provenance_sha256",
            )
        ):
            raise ValueError("class-study built-in input binding is invalid")
    elif runtime_kind == "static":
        if (
            value.get("defense_parameters_sha256") is None
            or value.get("defense_parameters_provenance_sha256") is not None
        ):
            raise ValueError("class-study static input binding is invalid")
    elif runtime_kind in PARAMETERISED_RUNTIME_KINDS:
        if (
            value.get("defense_parameters_sha256") is None
            or value.get("defense_parameters_provenance_sha256") is None
        ):
            raise ValueError("class-study parameterised input binding is invalid")
    else:
        raise ValueError("class-study defended runtime kind is invalid")
    if any(
        value.get(key) is None for key in ("chaff_qualification_sha256", "chaff_manifest_sha256")
    ):
        raise ValueError("class-study defended chaff input binding is incomplete")


def _defense_input_digests(
    root: Path,
    defense: Mapping[str, Any],
    *,
    runtime_kind: str,
    baseline: bool,
) -> tuple[str | None, str | None]:
    parameter_fields = {
        "parameters",
        "parameters_sha256",
        "provenance",
        "provenance_sha256",
        "input_policy",
    }
    schedule_fields = {"schedule", "schedule_sha256", "mode"}
    has_parameter = any(key in defense for key in parameter_fields)
    has_schedule = any(key in defense for key in schedule_fields)
    if baseline or runtime_kind in BUILT_IN_DEFENDED_RUNTIME_KINDS:
        if has_parameter or has_schedule:
            raise ValueError("class-study source-bound defense has unexpected external input")
        return None, None
    if runtime_kind == "static":
        if has_parameter or set(defense) & schedule_fields != schedule_fields:
            raise ValueError("class-study static schedule binding is incomplete")
        if defense.get("mode") not in {"chaff-only", "chaff-and-shape"}:
            raise ValueError("class-study static schedule mode is invalid")
        schedule_sha256 = _bound_digest(
            root,
            defense.get("schedule"),
            defense.get("schedule_sha256"),
            label="static defense schedule",
        )
        return schedule_sha256, None
    if runtime_kind not in PARAMETERISED_RUNTIME_KINDS or has_schedule:
        raise ValueError("class-study defense external-input kind is invalid")
    if set(defense) & parameter_fields != parameter_fields:
        raise ValueError("class-study defense parameter binding is incomplete")
    if not isinstance(defense.get("input_policy"), str) or not defense["input_policy"]:
        raise ValueError("class-study defense parameter input policy is invalid")
    parameter_sha256 = _bound_digest(
        root,
        defense.get("parameters"),
        defense.get("parameters_sha256"),
        label=f"{runtime_kind} parameters",
    )
    provenance_sha256 = _bound_digest(
        root,
        defense.get("provenance"),
        defense.get("provenance_sha256"),
        label=f"{runtime_kind} parameter provenance",
    )
    return parameter_sha256, provenance_sha256


def _optional_bound_digest(
    root: Path,
    record: Mapping[str, Any],
    *,
    path_key: str,
    sha256_key: str,
    label: str,
    required: bool,
) -> str | None:
    path_value = record.get(path_key)
    digest_value = record.get(sha256_key)
    if path_value is None and digest_value is None and not required:
        return None
    return _bound_digest(root, path_value, digest_value, label=label)


def _bound_digest(root: Path, relative: object, expected: object, *, label: str) -> str:
    if not _digest(expected):
        raise ValueError(f"class-study {label} hash is invalid")
    path = _bound_file(root, relative, label=label)
    digest = sha256_file(path)
    if digest != expected:
        raise ValueError(f"class-study {label} changed")
    return digest


def _bound_file(root: Path, relative: object, *, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"class-study {label} path is invalid")
    candidate = root / relative
    path = candidate.resolve()
    if not path.is_relative_to(root) or candidate.is_symlink() or not path.is_file():
        raise ValueError(f"class-study {label} is not a safe regular file")
    return path


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
