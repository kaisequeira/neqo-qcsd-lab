from __future__ import annotations

import copy
import hashlib
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import qcsd_lab.class_acquisition as acquisition_module
from qcsd_lab.acquisition_errors import RecoverableAcquisitionError
from qcsd_lab.class_acquisition import (
    COMPLETION_TYPE,
    MAX_ACQUISITION_BACKEND_TIMEOUT_MS,
    MAX_APPROVED_ORIGINS,
    MAX_ORIGIN_PASSES,
    MAX_PASSIVE_RENDER_AFTER_LOAD_MS,
    PENDING_BASELINE_GUARD_MS,
    TERMINAL_SCHEMA_VERSION,
    ExistingAcquisitionBackend,
    InternalAcquisitionError,
    NavigationDiscovery,
    PreparedProbe,
    TerminalProbePolicyError,
    _converge_origins,
    _is_public_network_address,
    _navigation_request_allowed,
    _prepared_replay_identity_sha256,
    _probe_attempt_workload_id,
    _validate_probe_attempts,
    _verified_bound_file,
    _verified_navigation_link,
    acquisition_status,
    catalogue_boundary_navigation,
    initialise_runner,
    public_origin_ip_pins,
    run_due_acquisition,
    unsafe_catalogue_domain_reason,
    validate_acquisition_completion,
    write_acquisition_completion,
)
from qcsd_lab.class_catalogue import (
    CANDIDATE_RECEIPT_TYPE,
    CATALOGUE_SCHEMA_VERSION,
    DiscoveredLink,
    PageCandidate,
)
from qcsd_lab.cdp_targets import CDP_TARGET_INSTRUMENTATION_POLICY
from qcsd_lab.class_study import (
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    STUDY_ID,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    bind_receipt,
    canonical_json_bytes,
    deterministic_candidate_order,
)
from qcsd_lab.discover import DiscoveryResult, origin
from qcsd_lab.discovery_evidence import (
    DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
    PASSIVE_RENDER_CONTRACT_SHA256,
    evidence_sha256,
    passive_render_contract,
)
from qcsd_lab.prepare import PreparationError, PreparedWorkload, RecoverablePreparationError
from qcsd_lab.util import load_json


@pytest.fixture(autouse=True)
def _clean_acquisition_source(monkeypatch: pytest.MonkeyPatch):
    """Model the clean immutable image required by the production runner."""

    empty_sha256 = hashlib.sha256(b"").hexdigest()
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "1" * 64)

    def clean_source():
        return {
            "image_digest": acquisition_module.os.environ[
                "QCSD_LAB_IMAGE_DIGEST"
            ],
            "lab_commit": "2" * 40,
            "lab_dirty": False,
            "lab_patch_sha256": empty_sha256,
            "neqo_commit": "3" * 40,
            "neqo_pinned_commit": "3" * 40,
            "neqo_dirty": False,
            "neqo_patch_sha256": empty_sha256,
        }

    monkeypatch.setattr(acquisition_module, "source_metadata", clean_source)


def _foundation(path: Path) -> Path:
    path.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                {"study_id": STUDY_ID},
                receipt_type="qcsd-class-study-foundation-attestation",
            )
        )
    )
    return path


def _catalogue(path: Path) -> Path:
    candidates = deterministic_candidate_order(
        (
            ClassCandidate(
                f"class-{stratum_index}-{offset:02d}",
                f"site-{stratum_index}-{offset:02d}.example",
                stratum.minimum_rank + offset,
                False,
            )
            for stratum_index, stratum in enumerate(TRANCO_RANK_STRATA)
            for offset in range(CANDIDATES_PER_STRATUM)
        ),
        tranco_list_sha256="a" * 64,
    )
    value = bind_receipt(
        {
            "study_id": STUDY_ID,
            "catalogue_schema_version": CATALOGUE_SCHEMA_VERSION,
            "tranco": {
                "list_id": "TEST1",
                "list_sha256": "a" * 64,
                "source_url": "https://tranco-list.eu/download/TEST1/1000000",
                "retrieved_at": "2026-08-28T00:00:00Z",
                "row_count": 1_000_000,
                "entries_sha256": "b" * 64,
            },
            "selection": {
                "rank_strata": [stratum.as_dict() for stratum in TRANCO_RANK_STRATA],
                "per_stratum": CANDIDATES_PER_STRATUM,
                "ordering": "sha256(list_sha256 || study_id || canonical_domain)",
                "outcome_fields_used": [],
            },
            "candidates": [candidate.as_dict() for candidate in candidates],
        },
        receipt_type=CANDIDATE_RECEIPT_TYPE,
    )
    path.write_bytes(canonical_json_bytes(value))
    return path


def _replace_receipt_payload(path: Path, payload: dict) -> None:
    receipt_type = load_json(path)["receipt_type"]
    path.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=receipt_type))
    )


def _first_terminal_state(runner: Path) -> tuple[str, dict]:
    checkpoint = load_json(runner / "checkpoint.json")
    return next(
        (candidate_id, state)
        for candidate_id, state in checkpoint["payload"]["candidates"].items()
        if state["terminal"] is not None
    )


def _rewrite_terminal_and_checkpoint(
    runner: Path,
    *,
    mutate,
) -> tuple[str, dict, dict]:
    checkpoint = load_json(runner / "checkpoint.json")
    checkpoint_payload = copy.deepcopy(checkpoint["payload"])
    candidate_id, state = next(
        (candidate_id, state)
        for candidate_id, state in checkpoint_payload["candidates"].items()
        if state["terminal"] is not None
    )
    terminal_path = runner / state["terminal"]["path"]
    terminal_payload = copy.deepcopy(load_json(terminal_path)["payload"])
    mutate(state, terminal_payload)
    if terminal_payload.get("terminal_schema_version") == TERMINAL_SCHEMA_VERSION:
        terminal_payload["checkpoint_state_sha256"] = (
            acquisition_module._normalised_terminal_state_sha256(
                state, kind=terminal_payload["kind"]
            )
        )
    _replace_receipt_payload(terminal_path, terminal_payload)
    state["terminal"]["sha256"] = hashlib.sha256(terminal_path.read_bytes()).hexdigest()
    _replace_receipt_payload(runner / "checkpoint.json", checkpoint_payload)
    return candidate_id, state, terminal_payload


def _prepared_manifest(url: str, approved_origins, *, source_override=None) -> dict:
    source_origin = origin(url)
    assert source_origin is not None
    resource_origins = [source_origin, *sorted(set(approved_origins) - {source_origin})]
    resources = [
        {
            "id": index,
            "url": url if index == 0 else f"{resource_origin}/resource-{index}",
            "type": "Document" if index == 0 else "Script",
            "depends_on": [] if index == 0 else [0],
            "headers": [],
        }
        for index, resource_origin in enumerate(resource_origins)
    ]
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    source = source_override or {
        "image_digest": "sha256:" + "1" * 64,
        "lab_commit": "2" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": empty_sha256,
        "neqo_commit": "3" * 40,
        "neqo_pinned_commit": "3" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": empty_sha256,
    }
    target_source = {
        "session_path": [],
        "target_id": "fixture-page",
        "target_type": "page",
        "generation": 0,
        "parent_session_path": None,
        "parent_frame_id": None,
    }
    events = []
    for resource in resources:
        resource_id = resource["id"]
        occurrence_id = f"request-{resource_id:08d}"
        dependency_evidence = (
            []
            if resource_id == 0
            else [
                {
                    "kind": "document-url",
                    "value": url,
                    "resolved_resource_id": 0,
                }
            ]
        )
        events.extend(
            [
                {
                    "sequence": len(events) + 1,
                    "monotonic_ms": 0,
                    "kind": "network-request",
                    "source": target_source,
                    "network_id": f"network-{resource_id}",
                    "occurrence_id": occurrence_id,
                    "occurrence_index": 0,
                    "method": "GET",
                    "url": resource["url"],
                    "frame_id": None,
                    "resource_type": resource["type"],
                    "safe_request_headers": resource["headers"],
                    "interception_required": True,
                    "redirected": False,
                    "redirect_from_occurrence_id": None,
                    "mapping": {"kind": "resource", "resource_id": resource_id},
                    "dependency_evidence": dependency_evidence,
                    "resolved_dependency_resource_ids": resource["depends_on"],
                },
                {
                    "sequence": len(events) + 2,
                    "monotonic_ms": 0,
                    "kind": "fetch-request",
                    "source": target_source,
                    "fetch_id": f"fetch-{resource_id}",
                    "network_id": f"network-{resource_id}",
                    "redirected_fetch_id": None,
                    "network_occurrence_id": occurrence_id,
                    "method": "GET",
                    "url": resource["url"],
                    "frame_id": None,
                    "policy_decision": "continue",
                    "policy_reason": None,
                    "relationship": "primary",
                },
                {
                    "sequence": len(events) + 3,
                    "monotonic_ms": 0,
                    "kind": "network-terminal",
                    "source": target_source,
                    "network_id": f"network-{resource_id}",
                    "outcome": "finished",
                    "network_occurrence_ids": [occurrence_id],
                },
            ]
        )
    render_observation = {
        "schema_version": 1,
        "clock": "monotonic-relative-ms",
        "navigation_started_ms": 0,
        "load_event_ms": 0,
        "last_relevant_event_ms": 0,
        "quiet_started_ms": 10_000,
        "cutoff_ms": 13_000,
        "active_request_ids": [],
        "active_request_count": 0,
        "cutoff_reason": "quiescent",
    }
    render_observation_sha256 = evidence_sha256(render_observation)
    discovery_event_audit = {
        "schema_version": DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
        "instrumentation_policy": CDP_TARGET_INSTRUMENTATION_POLICY,
        "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
        "render_observation_sha256": render_observation_sha256,
        "events": events,
        "summary": {
            "event_count": len(events),
            "target_event_count": 0,
            "network_request_count": len(resources),
            "fetch_request_count": len(resources),
            "fetch_internal_restart_count": 0,
            "terminal_event_count": len(resources),
            "resource_occurrence_count": len(resources),
            "exclusion_occurrence_count": 0,
        },
    }
    discovery_event_audit_sha256 = evidence_sha256(discovery_event_audit)
    return {
        "preparation": {
            "source_url": url,
            "final_url": url,
            "chromium_version": "test-chromium",
            "settle_ms": 10_000,
            "observed_request_count": len(resources),
            "observed_origins": list(approved_origins),
            "approved_origins": list(approved_origins),
            "origin_ip_pins": {
                value: "1.1.1.1" for value in sorted(approved_origins)
            },
            "exclusions": [],
            "browser_request_headers": [
                {"resource_id": resource["id"], "headers": resource["headers"]}
                for resource in resources
            ],
            "request_header_transformation": (
                "browser-safe-input-to-neqo-stability-frozen-runtime-v1"
            ),
            "passive_render_contract": passive_render_contract(),
            "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
            "render_observation": render_observation,
            "render_observation_sha256": render_observation_sha256,
            "discovery_event_audit": discovery_event_audit,
            "discovery_event_audit_sha256": discovery_event_audit_sha256,
            "max_response_bytes": 1_048_576,
            "timeout_seconds": 30,
            "stability_runs": 3,
            "stability_profile": "live",
            "stability_defense": "none",
            "stability_seed": 0,
            "udp_payload_qualification": {
                "schema_version": 1,
                "configured_udp_payload_ceiling": 1_200,
                "runs": [
                    {
                        "run_index": run_index,
                        "packets_sha256": f"{run_index + 1:064x}",
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
                            "observed_udp_payload_max": 1_199,
                            "oversized_packet_count": 0,
                        },
                    }
                    for run_index in range(3)
                ],
            },
            "neqo_version": "test-neqo",
            "neqo_base_commit": "4" * 40,
            "published_qcsd_commit": "5" * 40,
            "migration_commit": "6" * 40,
            "expected_responses": [
                {
                    "resource_id": resource["id"],
                    "status": 200,
                    "bytes": 100 + resource["id"],
                    "body_sha256": f"{resource['id'] + 1:064x}",
                }
                for resource in resources
            ],
            "lab_source": source,
            "prepare_image_digest": source["image_digest"],
            "coverage_admission": {
                "schema_version": 3,
                "policy": "all-approved-origins-and-rendered-resources",
                "required_origins": list(approved_origins),
                "required_resources": [
                    {"id": resource["id"], "url": resource["url"]}
                    for resource in resources
                ],
                "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
                "render_observation_sha256": render_observation_sha256,
                "discovery_event_audit_sha256": discovery_event_audit_sha256,
                "origin_ip_pins_sha256": evidence_sha256(
                    {value: "1.1.1.1" for value in sorted(approved_origins)}
                ),
                "browser_request_headers_sha256": evidence_sha256(
                    [
                        {
                            "resource_id": resource["id"],
                            "headers": resource["headers"],
                        }
                        for resource in resources
                    ]
                ),
                "network_request_count": len(resources),
                "resource_occurrence_count": len(resources),
                "exclusion_occurrence_count": 0,
            },
        },
        "resources": resources,
    }


def _homepage_navigation(domain: str) -> NavigationDiscovery:
    homepage = f"https://{domain}/"
    homepage_origin = f"https://{domain}"
    return NavigationDiscovery(
        registrable_domain=domain,
        links=(),
        observed_origins=(homepage_origin,),
        page_observed_origins=((homepage, (homepage_origin,)),),
    )


def test_runner_distinguishes_component_limits_from_whole_action_cutoffs(
    tmp_path: Path,
) -> None:
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=_catalogue(tmp_path / "catalogue.json"),
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    provenance = load_json(runner / "provenance.json")["payload"]

    assert MAX_ACQUISITION_BACKEND_TIMEOUT_MS == 60_000
    assert MAX_PASSIVE_RENDER_AFTER_LOAD_MS == 30_000
    assert provenance["acquisition_schema_version"] == 3
    assert provenance["browser_navigation_timeout_ms"] == 60_000
    assert provenance["passive_render_hard_cap_after_load_ms"] == 30_000
    assert provenance["acquisition_action_timing_contract"] == (
        acquisition_module.ACTION_TIMING_CONTRACT
    )
    assert provenance["baseline_scheduling_contract"] == (
        acquisition_module.BASELINE_SCHEDULING_CONTRACT
    )
    assert "browser_discovery_attempt_budget_ms" not in provenance
    assert "pending_baseline_guard_ms" not in provenance["origin_policy"]
    assert PENDING_BASELINE_GUARD_MS == 2_400_000


@pytest.mark.parametrize(
    ("offset", "valid"),
    (
        (timedelta(seconds=24, microseconds=999_500), False),
        (timedelta(seconds=25), True),
        (timedelta(seconds=35), True),
        (timedelta(seconds=35, microseconds=500), False),
    ),
)
def test_probe_window_edges_use_exact_elapsed_time_not_rounded_milliseconds(
    offset: timedelta,
    valid: bool,
) -> None:
    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    observed = baseline + offset
    page = {
        "page": {"ordinal": 0},
        "observations": [],
        "probe_attempts": [
            {
                "probe_id": "t+30s",
                "workload_id": _probe_attempt_workload_id(
                    "candidate", 0, "t+30s", 1
                ),
                "attempt": 1,
                "observed_at": acquisition_module._format_time(observed),
                "completed_at": acquisition_module._format_time(observed),
                "outcome": "interrupted",
                "reason": "fixture interruption",
            }
        ],
    }
    def validate() -> None:
        _validate_probe_attempts(
            page,
            candidate_id="candidate",
            baseline_started_at=acquisition_module._format_time(baseline),
            enforce_duration_limit=True,
        )

    if valid:
        validate()
    else:
        with pytest.raises(ValueError, match="probe-attempt ledger"):
            validate()


def test_due_scheduler_uses_the_same_exact_inclusive_window_edges() -> None:
    baseline = datetime(2026, 8, 28, tzinfo=UTC)
    page = {
        "page": {"ordinal": 0},
        "observations": [],
        "probe_attempts": [],
    }
    state = {
        "baseline_started_at": acquisition_module._format_time(baseline),
        "pages": [page],
    }
    assert acquisition_module._due_pages(
        state,
        baseline + timedelta(seconds=24, microseconds=999_500),
        candidate_id="candidate",
    ) == []
    assert acquisition_module._due_pages(
        state,
        baseline + timedelta(seconds=25),
        candidate_id="candidate",
    ) == [page]
    assert acquisition_module._due_pages(
        state,
        baseline + timedelta(seconds=35),
        candidate_id="candidate",
    ) == [page]
    with pytest.raises(acquisition_module.MissedProbeWindow):
        acquisition_module._due_pages(
            state,
            baseline + timedelta(seconds=35, microseconds=500),
            candidate_id="candidate",
        )


class RejectingBackend:
    def discover_navigation(self, domain: str):
        raise TerminalProbePolicyError(f"typed DNS rejection for {domain}")


class SlowBackend:
    def __init__(self, clock):
        self.clock = clock

    def discover_navigation(self, domain: str):
        self.clock.value += timedelta(seconds=10)
        return _homepage_navigation(domain)

    def discover(self, url, approved_origins):
        return DiscoveryResult(
            source_url=url,
            final_url=url,
            chromium_version="test",
            settle_ms=0,
            observed_request_count=1,
            observed_origins=list(approved_origins),
            approved_origins=list(approved_origins),
            exclusions=[],
            resources=[{"id": 0}],
            origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
            expandable_origins=list(approved_origins),
        )

    def prepare(
        self, workload_id, url, approved_origins, output_root, *, origin_ip_pins=None
    ):
        output_root.mkdir(parents=True, exist_ok=True)
        path = output_root / f"{workload_id}.json"
        runtime_image = acquisition_module.os.environ.get(
            "QCSD_LAB_IMAGE_DIGEST", "native"
        )
        runtime_source = dict(acquisition_module.source_metadata())
        if runtime_image == "native" and runtime_source.get("image_digest") is None:
            runtime_source["image_digest"] = "native"
        manifest = _prepared_manifest(
            url, approved_origins, source_override=runtime_source
        )
        path.write_bytes(canonical_json_bytes(manifest))
        self.clock.value += timedelta(seconds=20)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return PreparedProbe(
            observed_at=self.clock.value.isoformat().replace("+00:00", "Z"),
            final_url=url,
            status=200,
            content_type="text/html",
            body_bytes=100,
            body_sha256=f"{1:064x}",
            resource_graph_sha256=_prepared_replay_identity_sha256(manifest),
            prepared=PreparedWorkload(
                path,
                digest,
                len(approved_origins),
                len(approved_origins),
            ),
            chromium_version="test-chromium",
            neqo_provenance={
                "neqo_version": "test-neqo",
                "neqo_base_commit": "4" * 40,
                "published_qcsd_commit": "5" * 40,
                "migration_commit": "6" * 40,
            },
            passive_render_contract_sha256=(
                manifest["preparation"]["passive_render_contract_sha256"]
            ),
            render_observation=manifest["preparation"]["render_observation"],
            render_observation_sha256=(
                manifest["preparation"]["render_observation_sha256"]
            ),
            discovery_event_audit_sha256=(
                manifest["preparation"]["discovery_event_audit_sha256"]
            ),
            preparation_origin_ip_pins=dict(origin_ip_pins or {}),
            document_response_chromium_version="test-chromium",
        )


class ProbeRejectingBackend(SlowBackend):
    def discover(self, url, approved_origins):
        raise TerminalProbePolicyError(f"probe policy rejected {url}")


class TwoPageBackend(SlowBackend):
    def discover_navigation(self, domain: str):
        self.clock.value += timedelta(seconds=10)
        homepage = f"https://{domain}/"
        linked = f"https://{domain}/about"
        candidate_origin = f"https://{domain}"
        return NavigationDiscovery(
            registrable_domain=domain,
            links=(DiscoveredLink(linked, "text/html"),),
            observed_origins=(candidate_origin,),
            page_observed_origins=(
                (homepage, (candidate_origin,)),
                (linked, (candidate_origin,)),
            ),
        )


class FakeClock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += timedelta(seconds=seconds)


def _complete_one_probing_candidate(
    runner: Path,
    *,
    catalogue: Path,
    stability: Path,
    workloads: Path,
    backend: SlowBackend,
    clock: FakeClock,
) -> tuple[str, dict]:
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": workloads,
        "backend": backend,
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    candidate_id, state = next(
        (candidate_id, state)
        for candidate_id, state in checkpoint["payload"]["candidates"].items()
        if state["state"] == "probing"
    )
    baseline = datetime.fromisoformat(
        state["baseline_started_at"].replace("Z", "+00:00")
    )
    for window in acquisition_module.STABILITY_PROBE_WINDOWS[1:]:
        clock.value = baseline + timedelta(milliseconds=window.target_ms)
        run_due_acquisition(runner, **arguments)
    final = load_json(runner / "checkpoint.json")
    return candidate_id, final["payload"]["candidates"][candidate_id]


class InterruptOnceBackend(SlowBackend):
    def __init__(self, clock):
        super().__init__(clock)
        self.interrupted = False
        self.workload_ids = []

    def prepare(
        self, workload_id, url, approved_origins, output_root, *, origin_ip_pins=None
    ):
        self.workload_ids.append(workload_id)
        if not self.interrupted:
            self.interrupted = True
            raise KeyboardInterrupt
        return super().prepare(
            workload_id,
            url,
            approved_origins,
            output_root,
            origin_ip_pins=origin_ip_pins,
        )


class InterruptAfterManifestBackend(SlowBackend):
    def __init__(self, clock):
        super().__init__(clock)
        self.interrupted = False
        self.workload_ids = []

    def prepare(
        self, workload_id, url, approved_origins, output_root, *, origin_ip_pins=None
    ):
        self.workload_ids.append(workload_id)
        if not self.interrupted:
            self.interrupted = True
            output_root.mkdir(parents=True, exist_ok=True)
            (output_root / f"{workload_id}.json").write_bytes(b"orphaned first-attempt manifest")
            raise KeyboardInterrupt
        return super().prepare(
            workload_id,
            url,
            approved_origins,
            output_root,
            origin_ip_pins=origin_ip_pins,
        )


class TransientNavigationBackend(SlowBackend):
    def __init__(self, clock):
        super().__init__(clock)
        self.navigation_calls = 0

    def discover_navigation(self, domain: str):
        self.navigation_calls += 1
        if self.navigation_calls == 1:
            raise RecoverableAcquisitionError("temporary DNS failure")
        return super().discover_navigation(domain)


class FinalDiscoveryDriftOnceBackend(SlowBackend):
    def __init__(self, clock):
        super().__init__(clock)
        self.workload_ids = []
        self.discovery_calls = []

    def discover(self, url, approved_origins):
        self.discovery_calls.append((url, tuple(approved_origins)))
        result = super().discover(url, approved_origins)
        if len(self.discovery_calls) == 2:
            late_origin = "https://late-origin.example"
            result.observed_origins = sorted([*approved_origins, late_origin])
            result.expandable_origins = sorted([*approved_origins, late_origin])
            result.exclusions = [
                {
                    "url": f"{late_origin}/asset.js",
                    "reason": "origin not approved",
                }
            ]
        return result

    def prepare(
        self, workload_id, url, approved_origins, output_root, *, origin_ip_pins=None
    ):
        self.workload_ids.append(workload_id)
        if len(self.workload_ids) == 1:
            raise RecoverablePreparationError(
                "complete coverage final browser discovery observed new HTTPS GET origins "
                "after convergence: https://late-origin.example"
            )
        return super().prepare(
            workload_id,
            url,
            approved_origins,
            output_root,
            origin_ip_pins=origin_ip_pins,
        )


def test_preparation_error_taxonomy_retries_only_explicit_transient_failures():
    assert issubclass(RecoverablePreparationError, PreparationError)
    assert issubclass(RecoverablePreparationError, RecoverableAcquisitionError)
    assert not issubclass(PreparationError, RecoverableAcquisitionError)


def test_all_candidates_require_terminal_evidence_and_completion_detects_tamper(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    (tmp_path / "stability").mkdir()

    status = run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=RejectingBackend(),
        max_candidates=CANDIDATE_COUNT,
    )
    assert status == {
        "candidate_count": CANDIDATE_COUNT,
        "terminal_count": CANDIDATE_COUNT,
        "pending_count": 0,
        "probing_count": 0,
        "due_now_count": 0,
        "missed_window_count": 0,
        "recovery_required_count": 0,
        "pending_start_blocked": False,
        "work_due_now": False,
        "complete": True,
        "next_due": None,
    }
    completion_path = write_acquisition_completion(runner, candidate_catalogue_path=catalogue)
    completion = load_json(completion_path)
    assert completion["receipt_type"] == COMPLETION_TYPE
    validate_acquisition_completion(
        completion, candidate_catalogue_path=catalogue, runner_root=runner
    )

    changed = copy.deepcopy(completion)
    changed["payload"]["terminal_receipts"].pop(next(iter(changed["payload"]["terminal_receipts"])))
    with pytest.raises(ValueError):
        validate_acquisition_completion(
            changed, candidate_catalogue_path=catalogue, runner_root=runner
        )


def test_initial_status_is_resumable_and_incomplete(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    assert acquisition_status(runner, candidate_catalogue_path=catalogue)["terminal_count"] == 0
    with pytest.raises(ValueError, match="terminal evidence for all"):
        write_acquisition_completion(runner, candidate_catalogue_path=catalogue)


def test_historical_schema_two_is_readable_but_cannot_be_mutated(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    provenance_path = runner / "provenance.json"
    provenance_payload = copy.deepcopy(load_json(provenance_path)["payload"])
    provenance_payload["acquisition_schema_version"] = 2
    provenance_payload.pop("acquisition_action_timing_contract")
    provenance_payload.pop("baseline_scheduling_contract")
    provenance_payload.pop("passive_render_hard_cap_after_load_ms")
    _replace_receipt_payload(provenance_path, provenance_payload)

    checkpoint_path = runner / "checkpoint.json"
    checkpoint_payload = copy.deepcopy(load_json(checkpoint_path)["payload"])
    checkpoint_payload["provenance_sha256"] = hashlib.sha256(
        provenance_path.read_bytes()
    ).hexdigest()
    _replace_receipt_payload(checkpoint_path, checkpoint_payload)

    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert status["pending_count"] == CANDIDATE_COUNT
    with pytest.raises(ValueError, match="historical acquisition runners"):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=RejectingBackend(),
        )


def test_runner_creates_and_strictly_validates_document_response_namespace(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    receipts = runner / "document-response-receipts"
    prepared = runner / "prepared-probes"
    assert receipts.is_dir() and not receipts.is_symlink()
    assert prepared.is_dir() and not prepared.is_symlink()
    (receipts / "uncheckpointed.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected acquisition document-response"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)

    (receipts / "uncheckpointed.json").unlink()
    (prepared / "uncheckpointed.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected acquisition prepared-probe"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_transient_navigation_failure_retries_and_preserves_each_attempt(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = TransientNavigationBackend(clock)

    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=backend,
        clock=clock,
    )

    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "baseline-ready"
    )
    assert backend.navigation_calls == 2
    assert [item["outcome"] for item in active["navigation_attempts"]] == [
        "recoverable-failure",
        "completed",
    ]
    assert [item["attempt"] for item in active["navigation_attempts"]] == [1, 2]


def test_unexpected_navigation_fault_is_durably_checkpointed_and_blocks_resume(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )

    class BrokenBackend(RejectingBackend):
        def discover_navigation(self, domain: str):
            raise AssertionError(f"broken navigation adapter for {domain}")

    with pytest.raises(InternalAcquisitionError, match="durable internal navigation"):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=BrokenBackend(),
        )

    checkpoint = load_json(runner / "checkpoint.json")
    failed = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if "internal_acquisition_error" in state
    )
    assert failed["terminal"] is None
    assert failed["navigation_attempts"][-1]["outcome"] == "internal-acquisition-error"
    assert failed["internal_acquisition_error"] == {
        "schema_version": 1,
        "stage": "navigation",
        "attempt": 1,
        "page_ordinal": None,
        "probe_id": None,
        "exception_type": "AssertionError",
        "message": next(
            item["reason"].removeprefix("AssertionError: ")
            for item in failed["navigation_attempts"]
            if item["outcome"] == "internal-acquisition-error"
        ),
        "recorded_at": failed["navigation_attempts"][-1]["completed_at"],
    }
    with pytest.raises(InternalAcquisitionError, match="checkpoint contains durable"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_terminal_navigation_policy_failure_does_not_retry(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )

    class PolicyBackend(RejectingBackend):
        calls = 0

        def discover_navigation(self, domain: str):
            self.calls += 1
            raise TerminalProbePolicyError("origin cap exceeded")

    backend = PolicyBackend()
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=backend,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    terminal = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "terminal"
    )
    assert backend.calls == 1
    assert [item["outcome"] for item in terminal["navigation_attempts"]] == [
        "terminal-policy-rejection"
    ]


def test_later_probe_rejects_a_different_prepare_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "1" * 64)
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "2" * 64)
    with pytest.raises(ValueError, match="frozen source/prepare image"):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=RejectingBackend(),
        )


def test_baseline_action_prearms_short_probe_and_records_start_not_slow_completion(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = SlowBackend(clock)
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=tmp_path / "workloads",
        backend=backend,
        clock=clock,
        max_candidates=1,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    first_id = next(
        candidate_id
        for candidate_id, state in checkpoint["payload"]["candidates"].items()
        if state["state"] == "baseline-ready"
    )
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=tmp_path / "workloads",
        backend=backend,
        clock=clock,
        max_candidates=1,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    states = checkpoint["payload"]["candidates"]
    observation = states[first_id]["pages"][0]["observations"][0]
    assert states[first_id]["baseline_started_at"] == "2026-08-28T00:00:10Z"
    assert observation["observed_at"] == "2026-08-28T00:00:35Z"
    assert observation["probe_completed_at"] == "2026-08-28T00:00:55Z"
    assert sum(state["state"] == "probing" for state in states.values()) == 1


def test_current_navigation_success_duration_has_an_exact_soft_limit(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=SlowBackend(clock),
        clock=clock,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    payload = copy.deepcopy(checkpoint["payload"])
    state = next(
        item
        for item in payload["candidates"].values()
        if item["state"] == "baseline-ready"
    )
    attempt = state["navigation_attempts"][0]
    started = datetime.fromisoformat(attempt["started_at"].replace("Z", "+00:00"))
    attempt["completed_at"] = acquisition_module._format_time(
        started + timedelta(seconds=1_800)
    )
    _replace_receipt_payload(runner / "checkpoint.json", payload)
    acquisition_status(runner, candidate_catalogue_path=catalogue)

    payload = copy.deepcopy(load_json(runner / "checkpoint.json")["payload"])
    state = next(
        item
        for item in payload["candidates"].values()
        if item["state"] == "baseline-ready"
    )
    state["navigation_attempts"][0]["completed_at"] = (
        acquisition_module._format_time(
            started + timedelta(seconds=1_800, microseconds=1)
        )
    )
    _replace_receipt_payload(runner / "checkpoint.json", payload)
    with pytest.raises(ValueError, match="navigation-attempt ledger"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_interrupted_navigation_duration_is_not_fabricated_as_success(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    checkpoint = load_json(runner / "checkpoint.json")
    payload = copy.deepcopy(checkpoint["payload"])
    state = next(iter(payload["candidates"].values()))
    state["navigation_attempts"] = [
        {
            "attempt": 1,
            "started_at": "2026-08-28T00:00:00Z",
            "completed_at": "2026-08-28T02:00:00Z",
            "outcome": "interrupted",
            "reason": "externally bounded action ended before an outcome",
        }
    ]
    _replace_receipt_payload(runner / "checkpoint.json", payload)
    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert status["terminal_count"] == 0
    persisted = load_json(runner / "checkpoint.json")["payload"]["candidates"]
    assert next(iter(persisted.values()))["navigation_attempts"][0]["outcome"] == (
        "interrupted"
    )


def test_clock_rollback_keeps_pending_start_and_recovery_records_interruption(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))

    class RegressingClockBackend:
        def discover_navigation(self, domain: str):
            clock.value -= timedelta(seconds=1)
            return _homepage_navigation(domain)

    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "clock": clock,
    }
    with pytest.raises(ValueError, match="clock moved backwards"):
        run_due_acquisition(
            runner,
            backend=RegressingClockBackend(),
            **arguments,
        )
    checkpoint = load_json(runner / "checkpoint.json")
    state = next(
        item
        for item in checkpoint["payload"]["candidates"].values()
        if item.get("pending_navigation") is not None
    )
    assert state["navigation_attempts"] == []
    assert state["pending_navigation"]["attempt"] == 1

    clock.value = datetime(2026, 8, 28, 0, 0, 1, tzinfo=UTC)
    run_due_acquisition(
        runner,
        backend=RejectingBackend(),
        **arguments,
    )
    _candidate_id, state = _first_terminal_state(runner)
    assert [item["outcome"] for item in state["navigation_attempts"]] == [
        "interrupted",
        "terminal-policy-rejection",
    ]
    assert not any(
        item["outcome"] == "completed" for item in state["navigation_attempts"]
    )


def test_current_probe_success_duration_has_an_exact_soft_limit(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": SlowBackend(clock),
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    payload = copy.deepcopy(checkpoint["payload"])
    state = next(
        item for item in payload["candidates"].values() if item["state"] == "probing"
    )
    attempt = state["pages"][0]["probe_attempts"][0]
    observed = datetime.fromisoformat(attempt["observed_at"].replace("Z", "+00:00"))
    attempt["completed_at"] = acquisition_module._format_time(
        observed + timedelta(seconds=1_800)
    )
    _replace_receipt_payload(runner / "checkpoint.json", payload)
    acquisition_status(runner, candidate_catalogue_path=catalogue)

    payload = copy.deepcopy(load_json(runner / "checkpoint.json")["payload"])
    state = next(
        item for item in payload["candidates"].values() if item["state"] == "probing"
    )
    state["pages"][0]["probe_attempts"][0]["completed_at"] = (
        acquisition_module._format_time(
            observed + timedelta(seconds=1_800, microseconds=1)
        )
    )
    _replace_receipt_payload(runner / "checkpoint.json", payload)
    with pytest.raises(ValueError, match="probe-attempt ledger"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_serial_spacing_refuses_a_second_baseline_but_allows_navigation(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    status = run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=tmp_path / "workloads",
        backend=SlowBackend(clock),
        clock=clock,
        max_candidates=5,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    probing = [
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    ]
    assert len(probing) == 1
    assert len(probing[0]["pages"][0]["observations"]) == 1
    assert sum(
        "baseline_started_at" in state
        for state in checkpoint["payload"]["candidates"].values()
    ) == 1
    assert sum(
        state["state"] == "baseline-ready"
        for state in checkpoint["payload"]["candidates"].values()
    ) == 3
    assert status["pending_count"] == CANDIDATE_COUNT - 1
    assert status["pending_start_blocked"] is False
    assert status["work_due_now"] is True
    assert status["next_due"] == "2026-08-28T00:40:10Z"


def test_current_checkpoint_rejects_a_cross_offset_baseline_collision(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": SlowBackend(clock),
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    payload = copy.deepcopy(checkpoint["payload"])
    first = next(
        state
        for state in payload["candidates"].values()
        if state["state"] == "probing"
    )
    second = next(
        state
        for state in payload["candidates"].values()
        if state["state"] == "baseline-ready"
    )
    first_baseline = datetime.fromisoformat(
        first["baseline_started_at"].replace("Z", "+00:00")
    )
    # Two baselines are far apart directly, but this second baseline's t+24h
    # action would collide exactly with the first baseline's t+72h action.
    second["state"] = "probing"
    second["baseline_started_at"] = acquisition_module._format_time(
        first_baseline + timedelta(hours=48)
    )
    _replace_receipt_payload(runner / "checkpoint.json", payload)
    with pytest.raises(ValueError, match="serial scheduling contract"):
        acquisition_status(
            runner,
            candidate_catalogue_path=catalogue,
            now=first_baseline,
        )


def test_due_probe_at_latest_edge_outranks_an_already_missed_candidate(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = SlowBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    payload = copy.deepcopy(checkpoint["payload"])
    first = next(
        state
        for state in payload["candidates"].values()
        if state["state"] == "probing"
    )
    second = next(
        state
        for state in payload["candidates"].values()
        if state["state"] == "baseline-ready"
    )
    first_baseline = datetime.fromisoformat(
        first["baseline_started_at"].replace("Z", "+00:00")
    )
    second_baseline = first_baseline + timedelta(hours=24, minutes=25)
    second["state"] = "probing"
    second["baseline_started_at"] = acquisition_module._format_time(second_baseline)
    _replace_receipt_payload(runner / "checkpoint.json", payload)

    # Candidate one has already missed t+24h. Candidate two still owns the
    # exact inclusive t+30s latest edge; spending the sole action on stale
    # cleanup would destroy that otherwise valid observation.
    clock.value = second_baseline + timedelta(seconds=35)
    status = acquisition_status(
        runner,
        candidate_catalogue_path=catalogue,
        now=clock.value,
    )
    assert status["due_now_count"] == 1
    assert status["missed_window_count"] == 1
    run_due_acquisition(runner, **arguments)

    states = load_json(runner / "checkpoint.json")["payload"]["candidates"]
    first_state = next(
        state
        for state in states.values()
        if state.get("baseline_started_at")
        == acquisition_module._format_time(first_baseline)
    )
    second_state = next(
        state
        for state in states.values()
        if state.get("baseline_started_at")
        == acquisition_module._format_time(second_baseline)
    )
    assert first_state["terminal"] is None
    assert len(first_state["pages"][0]["observations"]) == 1
    assert second_state["terminal"] is None
    assert second_state["pages"][0]["observations"][0]["observed_at"] == (
        acquisition_module._format_time(second_baseline + timedelta(seconds=35))
    )


def test_missed_window_becomes_terminal_and_does_not_block_remaining_candidates(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = SlowBackend(clock)
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=tmp_path / "workloads",
        backend=backend,
        clock=clock,
    )
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=stability,
            workload_root=tmp_path / "workloads",
            backend=backend,
            clock=clock,
            sleeper=lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt),
        )
    clock.value = datetime(2026, 8, 28, 0, 1, tzinfo=UTC)
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=tmp_path / "workloads",
        backend=backend,
        clock=clock,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    missed = [state for state in checkpoint["payload"]["candidates"].values() if state["terminal"]]
    assert len(missed) == 1
    terminal = load_json(runner / missed[0]["terminal"]["path"])
    assert terminal["payload"]["kind"] == "probe-window-missed"
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=tmp_path / "workloads",
        backend=backend,
        clock=clock,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    assert (
        sum(
            state["state"] == "baseline-ready"
            for state in checkpoint["payload"]["candidates"].values()
        )
        == 1
    )


def test_orphan_terminal_is_validated_and_recovered_after_checkpoint_interruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    original_save = acquisition_module._save_acquisition_checkpoint

    def interrupted_save(*args, **kwargs):
        if tuple((runner / "terminals").glob("*.json")):
            raise KeyboardInterrupt
        return original_save(*args, **kwargs)

    monkeypatch.setattr(acquisition_module, "_save_acquisition_checkpoint", interrupted_save)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=RejectingBackend(),
        )
    checkpoint = load_json(runner / "checkpoint.json")
    assert all(state["terminal"] is None for state in checkpoint["payload"]["candidates"].values())
    assert len(tuple((runner / "terminals").glob("*.json"))) == 1

    monkeypatch.setattr(acquisition_module, "_save_acquisition_checkpoint", original_save)
    checkpoint_before = (runner / "checkpoint.json").read_bytes()
    status = acquisition_status(runner, candidate_catalogue_path=catalogue)
    assert status["terminal_count"] == 0
    assert status["recovery_required_count"] == 1
    assert status["work_due_now"] is True
    assert (runner / "checkpoint.json").read_bytes() == checkpoint_before
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=RejectingBackend(),
        max_candidates=1,
    )
    checkpoint = load_json(runner / "checkpoint.json")
    terminal_state = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["terminal"] is not None
    )
    assert terminal_state["state"] == "terminal"


def test_orphan_terminal_recovery_rejects_a_changed_preterminal_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    original_save = acquisition_module._save_acquisition_checkpoint

    def interrupted_save(*args, **kwargs):
        if tuple((runner / "terminals").glob("*.json")):
            raise KeyboardInterrupt
        return original_save(*args, **kwargs)

    monkeypatch.setattr(acquisition_module, "_save_acquisition_checkpoint", interrupted_save)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(
            runner,
            candidate_catalogue_path=catalogue,
            stability_root=tmp_path / "stability",
            workload_root=tmp_path / "workloads",
            backend=RejectingBackend(),
        )
    monkeypatch.setattr(acquisition_module, "_save_acquisition_checkpoint", original_save)

    terminal_path = next((runner / "terminals").glob("*.json"))
    candidate_id = terminal_path.stem
    checkpoint = load_json(runner / "checkpoint.json")
    checkpoint_payload = copy.deepcopy(checkpoint["payload"])
    state = checkpoint_payload["candidates"][candidate_id]
    assert state["terminal"] is None
    state["navigation_attempts"][-1]["reason"] = "forged terminal-policy reason"
    _replace_receipt_payload(runner / "checkpoint.json", checkpoint_payload)

    with pytest.raises(ValueError, match="does not bind the checkpoint state"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_current_runner_rejects_a_legacy_terminal_shape(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=tmp_path / "stability",
        workload_root=tmp_path / "workloads",
        backend=RejectingBackend(),
    )

    def make_legacy(_state, terminal_payload):
        terminal_payload.pop("terminal_schema_version")
        terminal_payload.pop("terminalised_at")
        terminal_payload.pop("checkpoint_state_sha256")

    _rewrite_terminal_and_checkpoint(runner, mutate=make_legacy)
    with pytest.raises(ValueError, match="terminal evidence fields"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_three_interrupted_navigation_starts_form_a_valid_preprobe_terminal(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )

    class InterruptingNavigationBackend:
        def discover_navigation(self, _domain):
            raise KeyboardInterrupt

    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": InterruptingNavigationBackend(),
    }
    for _attempt in range(3):
        with pytest.raises(KeyboardInterrupt):
            run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    _candidate_id, state = _first_terminal_state(runner)
    terminal = load_json(runner / state["terminal"]["path"])["payload"]
    assert terminal["kind"] == "pre-probe-rejection"
    assert [item["outcome"] for item in state["navigation_attempts"]] == [
        "interrupted",
        "interrupted",
        "interrupted",
    ]


def test_probe_window_terminal_requires_a_proven_missed_instant(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": SlowBackend(clock),
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(
            runner,
            **arguments,
            sleeper=lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt),
        )
    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    clock.value = datetime.fromisoformat(
        active["baseline_started_at"].replace("Z", "+00:00")
    ) + timedelta(minutes=1)
    run_due_acquisition(runner, **arguments)

    def move_inside_window(state, terminal_payload):
        baseline = datetime.fromisoformat(
            state["baseline_started_at"].replace("Z", "+00:00")
        )
        terminal_payload["terminalised_at"] = (
            baseline + timedelta(seconds=30)
        ).isoformat().replace("+00:00", "Z")

    _rewrite_terminal_and_checkpoint(runner, mutate=move_inside_window)
    with pytest.raises(ValueError, match="still admissible"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_stable_page_unavailable_recomputes_the_checkpoint_partition(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": ProbeRejectingBackend(clock),
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    run_due_acquisition(runner, **arguments)
    _candidate_id, terminal_state = _first_terminal_state(runner)
    terminal = load_json(runner / terminal_state["terminal"]["path"])["payload"]
    assert terminal["terminal_schema_version"] == TERMINAL_SCHEMA_VERSION
    assert terminal["kind"] == "stable-page-unavailable"

    def remove_rejection(state, _terminal_payload):
        state["pages"][0].pop("rejection")

    _rewrite_terminal_and_checkpoint(runner, mutate=remove_rejection)
    with pytest.raises(ValueError, match="retains an incomplete page"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_slow_backend_can_reach_eligible_terminal_across_outer_windows(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = SlowBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    for instant in (
        datetime(2026, 8, 28, 0, 0, 40, tzinfo=UTC),
        datetime(2026, 8, 29, 0, 0, 10, tzinfo=UTC),
        datetime(2026, 8, 31, 0, 0, 10, tzinfo=UTC),
    ):
        clock.value = instant
        run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    terminal_state = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["terminal"] is not None
    )
    terminal = load_json(runner / terminal_state["terminal"]["path"])
    assert terminal["payload"]["kind"] == "eligible"


def test_eligible_terminal_observations_must_exactly_match_the_checkpoint(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    _complete_one_probing_candidate(
        runner,
        catalogue=catalogue,
        stability=stability,
        workloads=tmp_path / "workloads",
        backend=SlowBackend(clock),
        clock=clock,
    )

    def change_stable_observations(state, _terminal_payload):
        for observation in state["pages"][0]["observations"]:
            observation["body_bytes"] += 1

    _rewrite_terminal_and_checkpoint(runner, mutate=change_stable_observations)
    with pytest.raises(ValueError, match="exact checkpoint selection"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_eligible_terminal_must_select_the_first_eligible_checkpoint_page(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    workloads = tmp_path / "workloads"
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    candidate_id, _state = _complete_one_probing_candidate(
        runner,
        catalogue=catalogue,
        stability=stability,
        workloads=workloads,
        backend=TwoPageBackend(clock),
        clock=clock,
    )

    def select_second_page(state, terminal_payload):
        second = state["pages"][1]
        stability_path = stability / candidate_id / "page-01.json"
        prepared_path = Path(second["observations"][0]["prepared_path"])
        admitted_path = Path(terminal_payload["admitted_workload"]["path"])
        admitted_path.write_bytes(prepared_path.read_bytes())
        terminal_payload["stability_receipt"] = {
            "path": str(stability_path.resolve()),
            "sha256": hashlib.sha256(stability_path.read_bytes()).hexdigest(),
        }
        terminal_payload["admitted_workload"] = {
            "path": str(admitted_path.resolve()),
            "sha256": hashlib.sha256(admitted_path.read_bytes()).hexdigest(),
        }

    _rewrite_terminal_and_checkpoint(runner, mutate=select_second_page)
    with pytest.raises(ValueError, match="exact checkpoint selection"):
        acquisition_status(runner, candidate_catalogue_path=catalogue)


def test_probe_start_checkpoint_recovers_after_hard_interruption(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = InterruptOnceBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    pending = active["pages"][0]["pending_probe"]
    assert pending["observed_at"] == "2026-08-28T00:00:35Z"
    assert pending["attempt"] == 1
    assert pending["workload_id"].endswith("-a001")
    clock.value = datetime(2026, 8, 28, 0, 0, 37, tzinfo=UTC)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    assert active["pages"][0]["observations"][0]["observed_at"] == (
        "2026-08-28T00:00:37Z"
    )
    assert backend.workload_ids[0].endswith("-a001")
    assert backend.workload_ids[1].endswith("-a002")


def test_final_preparation_origin_drift_reconverges_inside_the_same_window(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = FinalDiscoveryDriftOnceBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    clock.value = datetime(2026, 8, 28, 0, 0, 40, tzinfo=UTC)

    run_due_acquisition(runner, **arguments)

    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    page = active["pages"][0]
    assert [item["outcome"] for item in page["probe_attempts"]] == [
        "recoverable-failure",
        "completed",
    ]
    assert [item["attempt"] for item in page["probe_attempts"]] == [1, 2]
    assert backend.workload_ids[0].endswith("-a001")
    assert backend.workload_ids[1].endswith("-a002")
    assert len(backend.discovery_calls) == 3
    assert backend.discovery_calls[0] == backend.discovery_calls[1]
    assert backend.discovery_calls[2][1] == (
        "https://late-origin.example",
        backend.discovery_calls[0][1][0],
    )
    assert len(page["observations"]) == 1


def test_unexpected_probe_fault_is_durably_checkpointed_and_blocks_resume(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))

    class BrokenProbeBackend(SlowBackend):
        def discover(self, url, approved_origins):
            raise PreparationError(
                f"Neqo HTTP/3 probe failed (101) after a Rust panic for {url}"
            )

    backend = BrokenProbeBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    with pytest.raises(InternalAcquisitionError, match="durable internal probe"):
        run_due_acquisition(runner, **arguments)

    checkpoint = load_json(runner / "checkpoint.json")
    failed = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if "internal_acquisition_error" in state
    )
    error = failed["internal_acquisition_error"]
    assert error["stage"] == "probe"
    assert error["page_ordinal"] == 0
    assert error["probe_id"] == "t+30s"
    assert error["exception_type"] == "PreparationError"
    assert failed["pages"][0]["probe_attempts"][-1]["outcome"] == (
        "internal-acquisition-error"
    )
    with pytest.raises(InternalAcquisitionError, match="checkpoint contains durable"):
        run_due_acquisition(runner, **arguments)


def test_probe_attempt_ledger_rejects_gaps_post_success_work_and_missing_success():
    candidate_id = "class-ledger"

    def record(attempt: int, outcome: str) -> dict[str, object]:
        return {
            "probe_id": "t+30s",
            "workload_id": _probe_attempt_workload_id(
                candidate_id, 0, "t+30s", attempt
            ),
            "attempt": attempt,
            "observed_at": "2026-08-28T00:00:30Z",
            "completed_at": "2026-08-28T00:00:31Z",
            "outcome": outcome,
            "reason": None if outcome == "completed" else "transient",
        }

    with pytest.raises(ValueError, match="ledger"):
        _validate_probe_attempts(
            {
                "page": {"ordinal": 0},
                "observations": [],
                "probe_attempts": [record(2, "recoverable-failure")],
            },
            candidate_id=candidate_id,
        )
    with pytest.raises(ValueError, match="ledger"):
        _validate_probe_attempts(
            {
                "page": {"ordinal": 0},
                "observations": [{"probe_id": "t+30s"}],
                "probe_attempts": [
                    record(1, "completed"),
                    record(2, "recoverable-failure"),
                ],
            },
            candidate_id=candidate_id,
        )
    with pytest.raises(ValueError, match="success ledger"):
        _validate_probe_attempts(
            {
                "page": {"ordinal": 0},
                "observations": [{"probe_id": "t+30s"}],
                "probe_attempts": [],
            },
            candidate_id=candidate_id,
        )


def test_manifest_written_before_kill_is_never_relabelled_on_resume(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = InterruptAfterManifestBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(runner, **arguments)

    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    pending = active["pages"][0]["pending_probe"]
    assert pending["attempt"] == 1
    stale_path = runner / "prepared-probes" / f"{pending['workload_id']}.json"
    assert stale_path.read_bytes() == b"orphaned first-attempt manifest"

    clock.value = datetime(2026, 8, 28, 0, 0, 37, tzinfo=UTC)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    observation = active["pages"][0]["observations"][0]
    first_id, second_id = backend.workload_ids
    assert first_id.endswith("-a001")
    assert second_id.endswith("-a002")
    assert first_id != second_id
    assert observation["observed_at"] == "2026-08-28T00:00:37Z"
    assert observation["prepared_path"] == str(
        (runner / "prepared-probes" / f"{second_id}.json").resolve()
    )
    resumed_manifest = runner / "prepared-probes" / f"{second_id}.json"
    assert observation["prepared_workload_sha256"] == hashlib.sha256(
        resumed_manifest.read_bytes()
    ).hexdigest()
    assert resumed_manifest.read_bytes() != b"orphaned first-attempt manifest"
    assert (
        observation["prepared_workload_sha256"]
        != hashlib.sha256(stale_path.read_bytes()).hexdigest()
    )


def test_pending_probe_cannot_restart_network_work_after_its_window(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = InterruptOnceBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
    }
    run_due_acquisition(runner, **arguments)
    clock.value = datetime(2026, 8, 28, 0, 0, 40, tzinfo=UTC)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(runner, **arguments)

    clock.value = datetime(2026, 8, 28, 1, 0, tzinfo=UTC)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    terminal_state = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["terminal"] is not None
    )
    terminal = load_json(runner / terminal_state["terminal"]["path"])
    assert terminal["payload"]["kind"] == "probe-window-missed"
    page = terminal_state["pages"][0]
    assert "pending_probe" not in page
    assert len(page["probe_attempts"]) == 1
    assert page["probe_attempts"][0] == {
        "probe_id": "t+30s",
        "workload_id": page["probe_attempts"][0]["workload_id"],
        "attempt": 1,
        "observed_at": "2026-08-28T00:01:05Z",
        "completed_at": "2026-08-28T01:00:00Z",
        "outcome": "interrupted",
        "reason": "prior invocation ended before recording an outcome",
    }
    assert page["probe_attempts"][0]["workload_id"].endswith("-t30s-a001")


def test_navigation_boundary_allows_https_www_but_rejects_lookalikes_and_http():
    assert _navigation_request_allowed("GET", "https://www.example.com/", "example.com")
    assert _navigation_request_allowed("GET", "https://cdn.www.example.com/a", "example.com")
    assert not _navigation_request_allowed("GET", "https://example.com.evil.test/", "example.com")
    assert not _navigation_request_allowed("GET", "http://www.example.com/", "example.com")
    assert not _navigation_request_allowed("POST", "https://www.example.com/", "example.com")
    assert unsafe_catalogue_domain_reason("animalsexporn.net") == (
        "domain-safety-policy-rejected:porn"
    )
    assert unsafe_catalogue_domain_reason("escortsandbabes.com.au") == (
        "domain-safety-policy-rejected:escort"
    )
    assert unsafe_catalogue_domain_reason("watchhentai.net") == (
        "domain-safety-policy-rejected:hentai"
    )
    assert unsafe_catalogue_domain_reason("topcasinolucky.com") == (
        "domain-safety-policy-rejected:casino"
    )
    assert unsafe_catalogue_domain_reason("xnxx.com") == (
        "domain-safety-policy-rejected:exact-domain"
    )
    assert unsafe_catalogue_domain_reason("ordinary-example.com") is None


def test_navigation_redirect_convergence_pins_arbitrary_in_boundary_subdomain_once(
    monkeypatch: pytest.MonkeyPatch,
):
    class FakePlaywrightError(Exception):
        pass

    sync_api = ModuleType("playwright.sync_api")
    sync_api.Error = FakePlaywrightError  # type: ignore[attr-defined]
    sync_api.sync_playwright = lambda: None  # type: ignore[attr-defined]
    playwright = ModuleType("playwright")
    playwright.sync_api = sync_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    base = "https://example.com"
    redirected = "https://news.example.com"
    resolution_calls = []

    def resolve(origins):
        resolution_calls.append(tuple(origins))
        return {
            value: "1.1.1.1" if value == base else "8.8.8.8"
            for value in origins
        }

    passes = []

    def navigation_pass(domain, **kwargs):
        assert domain == "example.com"
        pins = dict(kwargs["navigation_pins"])
        passes.append(pins)
        if redirected not in pins:
            raise acquisition_module._NavigationPinExpansion({redirected})
        return NavigationDiscovery(
            "example.com",
            (),
            (base, redirected),
            (),
            ((f"{base}/", (base, redirected)),),
        )

    monkeypatch.setattr(acquisition_module, "public_origin_ip_pins", resolve)
    monkeypatch.setattr(
        acquisition_module,
        "_catalogue_boundary_navigation_pass",
        navigation_pass,
    )

    result = catalogue_boundary_navigation("example.com")

    assert result.observed_origins == (base, redirected)
    assert resolution_calls == [(base,), (redirected,)]
    assert passes == [
        {base: "1.1.1.1"},
        {base: "1.1.1.1", redirected: "8.8.8.8"},
    ]


def test_navigation_redirect_convergence_rejects_private_subdomain_answer(
    monkeypatch: pytest.MonkeyPatch,
):
    class FakePlaywrightError(Exception):
        pass

    sync_api = ModuleType("playwright.sync_api")
    sync_api.Error = FakePlaywrightError  # type: ignore[attr-defined]
    sync_api.sync_playwright = lambda: None  # type: ignore[attr-defined]
    playwright = ModuleType("playwright")
    playwright.sync_api = sync_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    redirected = "https://private.example.com"

    def resolve(origins):
        if redirected in origins:
            raise TerminalProbePolicyError("public-origin policy rejected DNS answers")
        return {"https://example.com": "1.1.1.1"}

    monkeypatch.setattr(acquisition_module, "public_origin_ip_pins", resolve)
    monkeypatch.setattr(
        acquisition_module,
        "_catalogue_boundary_navigation_pass",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            acquisition_module._NavigationPinExpansion({redirected})
        ),
    )

    with pytest.raises(TerminalProbePolicyError, match="rejected DNS"):
        catalogue_boundary_navigation("example.com")


def _run_navigation_pass_with_primary_redirect(target_url: str):
    class FakePlaywrightError(Exception):
        pass

    class FakeRoute:
        def __init__(self, request):
            self.request = request

        def abort(self):
            return None

        def continue_(self):
            return None

    class FakeRequest:
        method = "GET"

        def __init__(self, url: str, frame: object):
            self.url = url
            self.frame = frame

        def is_navigation_request(self):
            return True

    class FakePage:
        def __init__(self, context):
            self.context = context
            self.main_frame = object()

        def goto(self, *_args, **_kwargs):
            for url in ("https://example.com/", target_url):
                self.context.route_handler(FakeRoute(FakeRequest(url, self.main_frame)))
            raise FakePlaywrightError("request-stage redirect abort")

    class FakeContext:
        def route(self, _pattern, handler):
            self.route_handler = handler

        def new_page(self):
            return FakePage(self)

    class FakeBrowser:
        def new_context(self, **_kwargs):
            return FakeContext()

        def close(self):
            return None

    class FakePlaywright:
        def __enter__(self):
            chromium = SimpleNamespace(launch=lambda **_kwargs: FakeBrowser())
            return SimpleNamespace(chromium=chromium)

        def __exit__(self, *_args):
            return None

    return acquisition_module._catalogue_boundary_navigation_pass(
        "example.com",
        deadline=acquisition_module.time.monotonic() + 1,
        navigation_pins={"https://example.com": "1.1.1.1"},
        sync_playwright=FakePlaywright,
        playwright_error=FakePlaywrightError,
    )


def test_navigation_pass_aborts_then_requests_a_pin_for_primary_subdomain_redirect():
    with pytest.raises(acquisition_module._NavigationPinExpansion) as captured:
        _run_navigation_pass_with_primary_redirect("https://news.example.com/article")

    assert captured.value.origins == ("https://news.example.com",)


def test_navigation_pass_retains_out_of_boundary_redirect_as_explicit_policy_rejection():
    with pytest.raises(
        TerminalProbePolicyError,
        match="document navigation left the allowed HTTPS candidate-domain boundary",
    ):
        _run_navigation_pass_with_primary_redirect("https://example.net/")


def test_public_origin_policy_pins_public_dns_and_rejects_private_answers(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        acquisition_module.socket,
        "getaddrinfo",
        lambda *_a, **_k: [(acquisition_module.socket.AF_INET, 1, 6, "", ("1.1.1.1", 443))],
    )
    assert public_origin_ip_pins(("https://example.com",)) == {"https://example.com": "1.1.1.1"}
    monkeypatch.setattr(
        acquisition_module.socket,
        "getaddrinfo",
        lambda *_a, **_k: [(acquisition_module.socket.AF_INET, 1, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(ValueError, match="rejected DNS"):
        public_origin_ip_pins(("https://example.com",))
    monkeypatch.setattr(
        acquisition_module.socket,
        "getaddrinfo",
        lambda *_a, **_k: [
            (acquisition_module.socket.AF_INET, 1, 6, "", ("1.1.1.1", 443)),
            (acquisition_module.socket.AF_INET, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(ValueError, match="rejected DNS"):
        public_origin_ip_pins(("https://example.com",))
    monkeypatch.setattr(
        acquisition_module.socket,
        "getaddrinfo",
        lambda *_a, **_k: [
            (
                acquisition_module.socket.AF_INET6,
                1,
                6,
                "",
                ("64:ff9b::c000:201", 443, 0, 0),
            )
        ],
    )
    with pytest.raises(ValueError, match="rejected DNS"):
        public_origin_ip_pins(("https://example.com",))
    with pytest.raises(ValueError, match="IP-literal"):
        public_origin_ip_pins(("https://127.0.0.1",))
    monkeypatch.setattr(
        acquisition_module.socket,
        "getaddrinfo",
        lambda *_a, **_k: (_ for _ in ()).throw(acquisition_module.socket.gaierror("DNS down")),
    )
    with pytest.raises(RecoverableAcquisitionError, match="DNS lookup failed"):
        public_origin_ip_pins(("https://example.com",))


def test_public_origin_policy_resolves_one_pin_per_chromium_hostname(
    monkeypatch: pytest.MonkeyPatch,
):
    calls = []

    def resolve(hostname, port, **_kwargs):
        calls.append((hostname, port))
        address = "1.1.1.1" if len(calls) == 1 else "8.8.8.8"
        return [(acquisition_module.socket.AF_INET, 1, 6, "", (address, port))]

    monkeypatch.setattr(acquisition_module.socket, "getaddrinfo", resolve)
    assert public_origin_ip_pins(
        ("https://example.com", "https://example.com:8443")
    ) == {
        "https://example.com": "1.1.1.1",
        "https://example.com:8443": "1.1.1.1",
    }
    assert calls == [("example.com", 443)]

    with pytest.raises(TerminalProbePolicyError, match="conflict for a shared hostname"):
        acquisition_module._validated_frozen_origin_ip_pins(
            ("https://example.com", "https://example.com:8443"),
            {
                "https://example.com": "1.1.1.1",
                "https://example.com:8443": "8.8.8.8",
            },
        )


def test_public_address_policy_matches_neqo_shared_golden_vectors() -> None:
    vectors = load_json(
        Path(__file__).resolve().parents[1]
        / "neqo-qcsd/neqo-bin/src/qcsd/public-address-policy-v1.json"
    )
    assert vectors["schema_version"] == 1
    assert vectors["policy"] == "qcsd-public-network-address-v1"
    assert all(_is_public_network_address(value) for value in vectors["accepted"])
    assert all(not _is_public_network_address(value) for value in vectors["rejected"])
    assert not _is_public_network_address("not-an-ip-address")


def test_navigation_verification_preserves_candidate_identity_and_rejects_redirects():
    candidate = PageCandidate(
        candidate_domain="example.com",
        registrable_domain="example.com",
        url="https://www.example.com/about",
        source="same-registrable-domain-link",
        ordinal=1,
        discovery_content_type="text/html",
    )
    assert (
        _verified_navigation_link(
            candidate,
            final_url=candidate.url,
            content_type="text/html; charset=utf-8",
            boundary="example.com",
        ).url
        == candidate.url
    )
    assert (
        _verified_navigation_link(
            candidate,
            final_url="https://evil.test/about",
            content_type="text/html",
            boundary="example.com",
        )
        is None
    )
    assert (
        _verified_navigation_link(
            candidate,
            final_url="https://www.example.com/about",
            content_type="application/pdf",
            boundary="example.com",
        )
        is None
    )
    redirected = _verified_navigation_link(
        candidate,
        final_url="https://shop.example.com/about",
        content_type="text/html",
        boundary="example.com",
    )
    assert redirected.url == candidate.url
    acquisition_module._validate_navigation_rejections(
        [
            {
                "url": candidate.url,
                "kind": "playwright-navigation-failure",
                "reason": "net::ERR_ABORTED",
            },
            {
                "url": candidate.url,
                "kind": "non-html-primary-response",
                "reason": "application/pdf",
            },
        ],
        boundary="example.com",
    )
    with pytest.raises(ValueError, match="violates its policy"):
        acquisition_module._validate_navigation_rejections(
            [
                {
                    "url": "https://example.com.evil.test/",
                    "kind": "playwright-navigation-failure",
                    "reason": "failure",
                }
            ],
            boundary="example.com",
        )


def test_transitive_bound_file_rejects_admitted_workload_tamper(tmp_path: Path):
    import hashlib

    workload = tmp_path / "class.json"
    workload.write_bytes(b"frozen workload")
    binding = {
        "path": str(workload),
        "sha256": hashlib.sha256(workload.read_bytes()).hexdigest(),
    }
    assert _verified_bound_file(binding, label="workload") == workload
    workload.write_bytes(b"substituted workload")
    with pytest.raises(ValueError, match="does not verify"):
        _verified_bound_file(binding, label="workload")


def test_admitted_workload_publish_rejects_missing_complete_coverage_before_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "prepared.json"
    source.write_text('{"fixture": true}\n', encoding="utf-8")
    destination = tmp_path / "published/class-001.json"
    checked = []

    def reject_missing_coverage(manifest, *, workload_id):
        checked.append((manifest, workload_id))
        raise ValueError("requires a complete-coverage admission")

    monkeypatch.setattr(
        acquisition_module,
        "validate_class_study_preparation",
        reject_missing_coverage,
    )

    with pytest.raises(ValueError, match="complete-coverage"):
        acquisition_module._publish_admitted_workload(
            source,
            destination,
            hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    assert checked == [({"fixture": True}, "class-001")]
    assert not destination.exists()


def test_existing_backend_reads_list_shaped_primary_response_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    manifest = tmp_path / "probe.json"
    value = {
        "preparation": {
            "final_url": "https://example.com/",
            "chromium_version": "Chromium 1",
            "prepare_image_digest": acquisition_module.os.environ[
                "QCSD_LAB_IMAGE_DIGEST"
            ],
            "lab_source": acquisition_module.source_metadata(),
            "origin_ip_pins": {"https://example.com": "1.1.1.1"},
            "expected_responses": [
                {
                    "resource_id": 0,
                    "status": 200,
                    "bytes": 123,
                    "body_sha256": "a" * 64,
                }
            ],
            "neqo_version": "1",
            "neqo_base_commit": "2",
            "published_qcsd_commit": "3",
                "migration_commit": "4",
                "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
                "render_observation": {},
                "render_observation_sha256": "c" * 64,
                "discovery_event_audit_sha256": "d" * 64,
            }
    }
    manifest.write_text(__import__("json").dumps(value), encoding="utf-8")
    prepared = PreparedWorkload(manifest, hashlib.sha256(manifest.read_bytes()).hexdigest(), 1, 1)
    prepare_arguments = {}

    def fake_prepare(*_args, **kwargs):
        prepare_arguments.update(kwargs)
        return prepared

    monkeypatch.setattr(acquisition_module, "prepare_workload", fake_prepare)
    monkeypatch.setattr(
        acquisition_module, "validate_class_study_preparation", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        acquisition_module,
        "_prepared_replay_identity_sha256",
        lambda _manifest: "b" * 64,
    )
    monkeypatch.setattr(
        acquisition_module,
        "_prepared_primary_response",
        lambda candidate: candidate["preparation"]["expected_responses"][0],
    )
    monkeypatch.setattr(
        acquisition_module,
        "public_origin_ip_pins",
        lambda _origins: {"https://example.com": "1.1.1.1"},
    )
    probe = ExistingAcquisitionBackend(
        content_type_probe=lambda _url, _origins, _timeout, _pins: "text/html"
    ).prepare("workload", "https://example.com/", ["https://example.com"], tmp_path)
    assert (probe.status, probe.body_bytes, probe.body_sha256) == (200, 123, "a" * 64)
    assert prepare_arguments["stability_runs"] == 3


def _root_redirect_manifest() -> dict:
    start = "https://example.com/start"
    final = "https://example.com/final"
    value = _prepared_manifest(start, ["https://example.com"])
    preparation = value["preparation"]
    preparation["final_url"] = final
    preparation["expected_responses"][0].update(
        status=301,
        bytes=1,
        body_sha256="a" * 64,
    )
    root_source = preparation["discovery_event_audit"]["events"][0]["source"]
    initial_occurrence = "request-00000000"
    preparation["discovery_event_audit"]["events"] = preparation[
        "discovery_event_audit"
    ]["events"][:2]
    value["resources"].append(
        {
            "id": 1,
            "url": final,
            "type": "Document",
            "depends_on": [0],
            "headers": [],
        }
    )
    preparation["expected_responses"].append(
        {
            "resource_id": 1,
            "status": 200,
            "bytes": 456,
            "body_sha256": "b" * 64,
        }
    )
    preparation["discovery_event_audit"]["events"].extend(
        [
            {
                "sequence": 3,
                "monotonic_ms": 0,
                "kind": "network-request",
                "source": root_source,
                "network_id": "network-0",
                "occurrence_id": "request-00000001",
                "occurrence_index": 1,
                "method": "GET",
                "url": final,
                "frame_id": None,
                "resource_type": "Document",
                "safe_request_headers": [],
                "interception_required": True,
                "redirected": True,
                "redirect_from_occurrence_id": initial_occurrence,
                "mapping": {"kind": "resource", "resource_id": 1},
                "dependency_evidence": [
                    {
                        "kind": "redirect",
                        "value": initial_occurrence,
                        "resolved_resource_id": 0,
                    }
                ],
                "resolved_dependency_resource_ids": [0],
            },
            {
                "sequence": 4,
                "monotonic_ms": 0,
                "kind": "fetch-request",
                "source": root_source,
                "fetch_id": "fetch-1",
                "network_id": "network-0",
                "redirected_fetch_id": "fetch-0",
                "network_occurrence_id": "request-00000001",
                "method": "GET",
                "url": final,
                "frame_id": None,
                "policy_decision": "continue",
                "policy_reason": None,
                "relationship": "primary",
            },
            {
                "sequence": 5,
                "monotonic_ms": 0,
                "kind": "network-terminal",
                "source": root_source,
                "network_id": "network-0",
                "outcome": "finished",
                "network_occurrence_ids": [
                    initial_occurrence,
                    "request-00000001",
                ],
            },
        ]
    )
    return value


def test_prepared_primary_response_follows_exact_root_redirect_chain():
    manifest = _root_redirect_manifest()
    assert acquisition_module._prepared_primary_response(manifest) == {
        "resource_id": 1,
        "status": 200,
        "bytes": 456,
        "body_sha256": "b" * 64,
    }

    # A same-URL subframe Document is not the primary merely because its URL
    # and media type resemble the final top-level response.
    manifest["resources"].append(
        {
            "id": 2,
            "url": "https://example.com/final",
            "type": "Document",
            "depends_on": [1],
            "headers": [],
        }
    )
    subframe = copy.deepcopy(
        manifest["preparation"]["discovery_event_audit"]["events"][2]
    )
    subframe["source"] = {
        "session_path": ["iframe-session"],
        "target_id": "iframe-target",
        "target_type": "iframe",
        "generation": 0,
        "parent_session_path": [],
        "parent_frame_id": "frame-1",
    }
    subframe["network_id"] = "subframe-network"
    subframe["occurrence_id"] = "request-00000002"
    subframe["occurrence_index"] = 0
    subframe["redirected"] = False
    subframe["redirect_from_occurrence_id"] = None
    subframe["mapping"] = {"kind": "resource", "resource_id": 2}
    manifest["preparation"]["discovery_event_audit"]["events"].append(subframe)
    manifest["preparation"]["expected_responses"].append(
        {
            "resource_id": 2,
            "status": 418,
            "bytes": 999,
            "body_sha256": "c" * 64,
        }
    )
    assert acquisition_module._prepared_primary_response(manifest)["resource_id"] == 1


def test_prepared_primary_response_rejects_a_forked_root_redirect_chain():
    manifest = _root_redirect_manifest()
    fork = copy.deepcopy(
        manifest["preparation"]["discovery_event_audit"]["events"][2]
    )
    fork["occurrence_id"] = "request-00000002"
    fork["mapping"] = {"kind": "resource", "resource_id": 2}
    manifest["resources"].append(
        {
            "id": 2,
            "url": "https://example.com/other",
            "type": "Document",
            "depends_on": [0],
            "headers": [],
        }
    )
    manifest["preparation"]["discovery_event_audit"]["events"].append(fork)
    with pytest.raises(TerminalProbePolicyError, match="redirect chain is ambiguous"):
        acquisition_module._prepared_primary_response(manifest)


def test_existing_backend_never_recovers_a_fixed_id_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    (tmp_path / "workload.json").write_text("{}\n", encoding="utf-8")
    called = False

    def create_only_prepare(*_args, **_kwargs):
        nonlocal called
        called = True
        raise FileExistsError("create-only preparer rejected the stale ID")

    monkeypatch.setattr(acquisition_module, "prepare_workload", create_only_prepare)
    monkeypatch.setattr(
        acquisition_module,
        "public_origin_ip_pins",
        lambda _origins: {"https://example.com": "1.1.1.1"},
    )
    with pytest.raises(FileExistsError, match="create-only preparer rejected"):
        ExistingAcquisitionBackend().prepare(
            "workload", "https://example.com/", ["https://example.com"], tmp_path
        )
    assert called


def test_origin_convergence_can_start_from_verified_navigation_redirect_origins():
    class RedirectBackend:
        def discover(self, url, approved_origins):
            if "https://www.example.com" not in approved_origins:
                raise ValueError("redirect origin was not pre-approved")
            return DiscoveryResult(
                source_url=url,
                final_url="https://www.example.com/",
                chromium_version="test",
                settle_ms=0,
                observed_request_count=2,
                observed_origins=list(approved_origins),
                approved_origins=list(approved_origins),
                exclusions=[],
                resources=[{"id": 0}],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=list(approved_origins),
            )

    approved, result = _converge_origins(
        RedirectBackend(),
        "https://example.com/",
        seed_origins=("https://www.example.com",),
    )
    assert approved == ["https://example.com", "https://www.example.com"]
    assert result.final_url == "https://www.example.com/"


def _two_navigation_pages() -> tuple[PageCandidate, PageCandidate]:
    return (
        PageCandidate(
            candidate_domain="example.com",
            registrable_domain="example.com",
            url="https://example.com/",
            source="canonical-homepage",
            ordinal=0,
            discovery_content_type=None,
        ),
        PageCandidate(
            candidate_domain="example.com",
            registrable_domain="example.com",
            url="https://example.com/about",
            source="same-registrable-domain-link",
            ordinal=1,
            discovery_content_type="text/html",
        ),
    )


@pytest.mark.parametrize(
    ("page_ledger", "message"),
    [
        ((), "is required"),
        (
            (("https://example.com/", ("https://example.com",)),),
            "is incomplete",
        ),
    ],
)
def test_navigation_origin_ledger_rejects_absence_or_incomplete_page_evidence(
    page_ledger, message: str
) -> None:
    navigation = NavigationDiscovery(
        registrable_domain="example.com",
        links=(),
        observed_origins=("https://about.example", "https://example.com"),
        page_observed_origins=page_ledger,
    )

    with pytest.raises(ValueError, match=message):
        acquisition_module._navigation_origins_by_page(
            navigation,
            _two_navigation_pages(),
        )


def test_navigation_origin_ledger_rejects_unbound_page_origin_leakage() -> None:
    navigation = NavigationDiscovery(
        registrable_domain="example.com",
        links=(),
        observed_origins=("https://example.com",),
        page_observed_origins=(
            (
                "https://example.com/",
                ("https://example.com", "https://leaked.example"),
            ),
            ("https://example.com/about", ("https://example.com",)),
        ),
    )

    with pytest.raises(ValueError, match="exceed the global ledger"):
        acquisition_module._navigation_origins_by_page(
            navigation,
            _two_navigation_pages(),
        )


def test_each_page_uses_only_its_own_navigation_origin_seeds(tmp_path: Path):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    baseline = datetime(2026, 8, 28, tzinfo=UTC)

    class PageSpecificBackend:
        def __init__(self):
            self.first_approved: dict[str, tuple[str, ...]] = {}
            self.domain = ""

        def discover_navigation(self, domain):
            self.domain = domain
            homepage = f"https://{domain}/"
            about = f"https://{domain}/about"
            news = f"https://{domain}/news"
            page_origins = {
                homepage: (f"https://home-assets.{domain}",),
                about: (f"https://about-assets.{domain}",),
                news: (f"https://news-assets.{domain}",),
            }
            return NavigationDiscovery(
                registrable_domain=domain,
                links=(
                    acquisition_module.DiscoveredLink(about, "text/html"),
                    acquisition_module.DiscoveredLink(news, "text/html"),
                ),
                observed_origins=tuple(
                    sorted(origin for values in page_origins.values() for origin in values)
                ),
                page_observed_origins=tuple(sorted(page_origins.items())),
            )

        def discover(self, url, approved_origins):
            self.first_approved.setdefault(url, tuple(sorted(approved_origins)))
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(approved_origins),
                observed_origins=list(approved_origins),
                approved_origins=list(approved_origins),
                exclusions=[],
                resources=[{"id": 0, "url": url}],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=list(approved_origins),
            )

        def prepare(
            self, workload_id, url, approved_origins, output_root, *, origin_ip_pins=None
        ):
            output_root.mkdir(parents=True, exist_ok=True)
            path = output_root / f"{workload_id}.json"
            manifest = _prepared_manifest(url, approved_origins)
            path.write_bytes(canonical_json_bytes(manifest))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            return PreparedProbe(
                    observed_at="2026-08-28T00:00:56Z",
                final_url=url,
                status=200,
                content_type="text/html",
                body_bytes=100,
                body_sha256=f"{1:064x}",
                resource_graph_sha256=_prepared_replay_identity_sha256(manifest),
                prepared=PreparedWorkload(path, digest, 1, 1),
                chromium_version="test-chromium",
                neqo_provenance={
                    "neqo_version": "test-neqo",
                    "neqo_base_commit": "4" * 40,
                    "published_qcsd_commit": "5" * 40,
                    "migration_commit": "6" * 40,
                },
                passive_render_contract_sha256=(
                    manifest["preparation"]["passive_render_contract_sha256"]
                ),
                render_observation=manifest["preparation"]["render_observation"],
                render_observation_sha256=(
                    manifest["preparation"]["render_observation_sha256"]
                ),
                discovery_event_audit_sha256=(
                    manifest["preparation"]["discovery_event_audit_sha256"]
                ),
                preparation_origin_ip_pins=dict(origin_ip_pins or {}),
                document_response_chromium_version="test-chromium",
            )

    backend = PageSpecificBackend()
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "max_candidates": 1,
    }
    run_due_acquisition(runner, now=baseline, **arguments)
    run_due_acquisition(runner, now=baseline + timedelta(seconds=30), **arguments)

    root_origin = f"https://{backend.domain}"
    assert backend.first_approved == {
        f"{root_origin}/": tuple(sorted((root_origin, f"https://home-assets.{backend.domain}"))),
        f"{root_origin}/about": tuple(
            sorted((root_origin, f"https://about-assets.{backend.domain}"))
        ),
        f"{root_origin}/news": tuple(
            sorted((root_origin, f"https://news-assets.{backend.domain}"))
        ),
    }


def test_origin_convergence_admits_discovered_cross_origin_resources():
    calls: list[tuple[str, ...]] = []

    class MultiOriginBackend:
        def discover(self, url, approved_origins):
            approved = tuple(sorted(approved_origins))
            calls.append(approved)
            observed = {"https://page.example"}
            if "https://cdn.example" not in approved:
                observed.add("https://cdn.example")
            elif "https://fonts.example" not in approved:
                observed.update(("https://cdn.example", "https://fonts.example"))
            else:
                observed.update(("https://cdn.example", "https://fonts.example"))
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(observed),
                observed_origins=sorted(observed),
                approved_origins=list(approved),
                exclusions=[],
                resources=[
                    {"id": index, "url": f"{value}/resource-{index}"}
                    for index, value in enumerate(sorted(observed))
                    if value in approved
                ],
                origin_ip_pins={value: "1.1.1.1" for value in approved},
                expandable_origins=sorted(observed),
            )

    approved, result = _converge_origins(
        MultiOriginBackend(),
        "https://page.example/",
    )

    assert calls == [
        ("https://page.example",),
        ("https://cdn.example", "https://page.example"),
        (
            "https://cdn.example",
            "https://fonts.example",
            "https://page.example",
        ),
    ]
    assert approved == [
        "https://cdn.example",
        "https://fonts.example",
        "https://page.example",
    ]
    assert {resource["url"].split("/resource-")[0] for resource in result.resources} == set(
        approved
    )


def test_origin_convergence_does_not_promote_a_post_only_origin():
    class PostObservingBackend:
        def discover(self, url, approved_origins):
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=2,
                observed_origins=[
                    "https://page.example",
                    "https://telemetry.example",
                ],
                approved_origins=list(approved_origins),
                exclusions=[
                    {
                        "url": "https://telemetry.example/report",
                        "reason": "unsafe method: POST",
                    }
                ],
                resources=[{"id": 0, "url": "https://page.example/"}],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=["https://page.example"],
            )

    approved, result = _converge_origins(
        PostObservingBackend(),
        "https://page.example/",
    )
    assert approved == ["https://page.example"]
    assert result.observed_origins == [
        "https://page.example",
        "https://telemetry.example",
    ]


def test_origin_convergence_rejects_absent_get_ledger_without_promoting_post_origin():
    class MissingExpansionLedgerBackend:
        def discover(self, url, approved_origins):
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=2,
                observed_origins=[
                    "https://page.example",
                    "https://telemetry.example",
                ],
                approved_origins=list(approved_origins),
                exclusions=[
                    {
                        "url": "https://telemetry.example/report",
                        "reason": "unsafe method: POST",
                    }
                ],
                resources=[{"id": 0, "url": "https://page.example/"}],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=None,
            )

    with pytest.raises(ValueError, match="omitted its HTTPS-GET-only"):
        _converge_origins(
            MissingExpansionLedgerBackend(),
            "https://page.example/",
        )


def test_origin_convergence_typed_rejects_33_get_origins_instead_of_truncating():
    class OverCapBackend:
        def discover(self, url, approved_origins):
            observed = ["https://page.example"] + [
                f"https://cdn-{index:02d}.example" for index in range(32)
            ]
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(observed),
                observed_origins=observed,
                approved_origins=list(approved_origins),
                exclusions=[],
                resources=[
                    {"id": 0, "url": "https://page.example/"},
                ],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=sorted(observed),
            )

    with pytest.raises(TerminalProbePolicyError, match="exceeded its finite origin cap"):
        _converge_origins(OverCapBackend(), "https://page.example/")


def test_origin_convergence_typed_rejects_513_non_get_audit_origins() -> None:
    class AuditCapBackend:
        def discover(self, url, approved_origins):
            observed = ["https://page.example"] + [
                f"https://telemetry-{index:03d}.example" for index in range(512)
            ]
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(observed),
                observed_origins=sorted(observed),
                approved_origins=list(approved_origins),
                exclusions=[
                    {
                        "url": f"{value}/report",
                        "reason": "unsafe method: POST",
                    }
                    for value in observed[1:]
                ],
                resources=[{"id": 0, "url": "https://page.example/"}],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=["https://page.example"],
            )

    with pytest.raises(TerminalProbePolicyError, match="observed-origin audit cap"):
        _converge_origins(AuditCapBackend(), "https://page.example/")


def test_origin_convergence_accepts_exactly_the_finite_origin_cap():
    expected_origins = ["https://page.example"] + [
        f"https://cdn-{index:02d}.example" for index in range(MAX_APPROVED_ORIGINS - 1)
    ]
    calls: list[tuple[str, ...]] = []

    class ExactCapBackend:
        def discover(self, url, approved_origins):
            approved = tuple(sorted(approved_origins))
            calls.append(approved)
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(expected_origins),
                observed_origins=sorted(expected_origins),
                approved_origins=list(approved),
                exclusions=[],
                resources=[
                    {"id": index, "url": f"{value}/resource-{index}"}
                    for index, value in enumerate(approved)
                ],
                origin_ip_pins={value: "1.1.1.1" for value in approved},
                expandable_origins=sorted(expected_origins),
            )

    approved, result = _converge_origins(
        ExactCapBackend(),
        "https://page.example/",
    )

    assert len(approved) == MAX_APPROVED_ORIGINS
    assert approved == sorted(expected_origins)
    assert len(calls) == 2
    assert {resource["url"].split("/resource-")[0] for resource in result.resources} == set(
        approved
    )


def test_origin_convergence_accepts_a_graph_settling_on_the_eighth_pass():
    calls: list[tuple[str, ...]] = []

    class EighthPassBackend:
        def discover(self, url, approved_origins):
            approved = tuple(sorted(approved_origins))
            calls.append(approved)
            observed = set(approved)
            if len(calls) < MAX_ORIGIN_PASSES:
                observed.add(f"https://cdn-{len(calls):02d}.example")
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(observed),
                observed_origins=sorted(observed),
                approved_origins=list(approved),
                exclusions=[],
                resources=[
                    {"id": index, "url": f"{value}/resource-{index}"}
                    for index, value in enumerate(approved)
                ],
                origin_ip_pins={value: "1.1.1.1" for value in approved},
                expandable_origins=sorted(observed),
            )

    approved, result = _converge_origins(
        EighthPassBackend(),
        "https://page.example/",
    )

    assert len(calls) == MAX_ORIGIN_PASSES
    assert len(approved) == MAX_ORIGIN_PASSES
    assert tuple(result.approved_origins) == calls[-1]
    assert result.expandable_origins == approved


def test_origin_convergence_rejects_instead_of_sealing_an_unsettled_graph():
    class NeverSettlesBackend:
        def discover(self, url, approved_origins):
            observed = [*approved_origins, f"https://cdn-{len(approved_origins):02d}.example"]
            return DiscoveryResult(
                source_url=url,
                final_url=url,
                chromium_version="test",
                settle_ms=0,
                observed_request_count=len(observed),
                observed_origins=observed,
                approved_origins=list(approved_origins),
                exclusions=[],
                resources=[
                    {"id": 0, "url": "https://page.example/"},
                ],
                origin_ip_pins={value: "1.1.1.1" for value in approved_origins},
                expandable_origins=sorted(observed),
            )

    with pytest.raises(TerminalProbePolicyError, match="did not converge within its pass cap"):
        _converge_origins(NeverSettlesBackend(), "https://page.example/")


def test_completion_provenance_retains_each_probe_origin_set():
    states = {
        "class-000": {
            "terminal": {"path": "terminals/class-000.json", "sha256": "a" * 64},
            "pages": [
                {
                    "approved_origins": ["https://second.example"],
                    "observations": [
                        {
                            "runner_provenance_sha256": "b" * 64,
                            "approved_origins": ["https://first.example"],
                            "discovery_observed_origins": [
                                "https://first.example",
                                "https://telemetry.example",
                            ],
                            "discovery_expandable_origins": ["https://first.example"],
                            "discovery_origin_ip_pins": {"https://first.example": "1.1.1.1"},
                            "discovery_instrumentation_policy": (
                                CDP_TARGET_INSTRUMENTATION_POLICY
                            ),
                            "chromium_version": "Chromium 1",
                            "neqo_provenance": {"neqo_version": "1"},
                            "observed_at": "2026-08-28T00:00:30Z",
                            "probe_completed_at": "2026-08-28T00:00:31Z",
                        },
                        {
                            "runner_provenance_sha256": "b" * 64,
                            "approved_origins": ["https://second.example"],
                            "discovery_observed_origins": ["https://second.example"],
                            "discovery_expandable_origins": ["https://second.example"],
                            "discovery_origin_ip_pins": {"https://second.example": "8.8.8.8"},
                            "discovery_instrumentation_policy": (
                                CDP_TARGET_INSTRUMENTATION_POLICY
                            ),
                            "chromium_version": "Chromium 1",
                            "neqo_provenance": {"neqo_version": "1"},
                            "observed_at": "2026-08-29T00:00:30Z",
                            "probe_completed_at": "2026-08-29T00:00:31Z",
                        },
                    ],
                }
            ],
        }
    }
    assert acquisition_module._validate_observation_provenance(
        states,
        provenance_sha256="b" * 64,
        runner_provenance={"image_digest": "sha256:test", "source": {"commit": "1"}},
    ) == {
        "chromium_version": "Chromium 1",
        "neqo_provenance": {"neqo_version": "1"},
        "image_digest": "sha256:test",
        "source": {"commit": "1"},
    }
    translation_checkpoint = copy.deepcopy(states)
    translation_checkpoint["class-000"]["pages"][0]["observations"][0]["discovery_origin_ip_pins"][
        "https://first.example"
    ] = "64:ff9b::c000:201"
    with pytest.raises(ValueError, match="checkpoint observation provenance"):
        acquisition_module._validate_observation_provenance(
            translation_checkpoint,
            provenance_sha256="b" * 64,
            runner_provenance={
                "image_digest": "sha256:test",
                "source": {"commit": "1"},
            },
        )
    instrumentation_checkpoint = copy.deepcopy(states)
    instrumentation_checkpoint["class-000"]["pages"][0]["observations"][0][
        "discovery_instrumentation_policy"
    ] = "unreceipted-root-only-cdp"
    with pytest.raises(ValueError, match="checkpoint observation provenance"):
        acquisition_module._validate_observation_provenance(
            instrumentation_checkpoint,
            provenance_sha256="b" * 64,
            runner_provenance={
                "image_digest": "sha256:test",
                "source": {"commit": "1"},
            },
        )


def test_current_observation_provenance_is_reconstructed_from_preparation_and_response(
    tmp_path: Path,
):
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test-browser@1",
    )
    stability = tmp_path / "stability"
    stability.mkdir()
    clock = FakeClock(datetime(2026, 8, 28, tzinfo=UTC))
    backend = SlowBackend(clock)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": stability,
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "clock": clock,
        "max_candidates": 1,
    }
    run_due_acquisition(runner, **arguments)
    clock.value = datetime(2026, 8, 28, 0, 0, 40, tzinfo=UTC)
    run_due_acquisition(runner, **arguments)

    checkpoint = load_json(runner / "checkpoint.json")
    states = checkpoint["payload"]["candidates"]
    candidate_id = next(
        candidate_id
        for candidate_id, state in states.items()
        if state["state"] == "probing" and state["pages"][0]["observations"]
    )
    states[candidate_id]["terminal"] = {"test-only": True}
    provenance_path = runner / "provenance.json"
    provenance = acquisition_module.validate_hash_bound_receipt(
        load_json(provenance_path), expected_type=acquisition_module.PROVENANCE_TYPE
    )

    def validate(candidate_states):
        return acquisition_module._validate_observation_provenance(
            candidate_states,
            provenance_sha256=acquisition_module.sha256_file(provenance_path),
            runner_provenance=provenance,
            runner_root=runner,
        )

    assert validate(states)["chromium_version"] == "test-chromium"

    def observation(candidate_states):
        return candidate_states[candidate_id]["pages"][0]["observations"][0]

    mutations = {
        "final-url": lambda item: item.__setitem__("final_url", "https://forged.example/"),
        "status": lambda item: item.__setitem__("status", 201),
        "body-bytes": lambda item: item.__setitem__("body_bytes", 101),
        "body-sha": lambda item: item.__setitem__("body_sha256", "f" * 64),
        "resource-graph": lambda item: item.__setitem__(
            "resource_graph_sha256", "e" * 64
        ),
        "approved-origins": lambda item: item.__setitem__(
            "approved_origins", ["https://forged.example"]
        ),
        "preparation-pins": lambda item: item.__setitem__(
            "preparation_origin_ip_pins",
            {item["approved_origins"][0]: "8.8.8.8"},
        ),
        "chromium": lambda item: item.__setitem__("chromium_version", "forged"),
        "neqo": lambda item: item["neqo_provenance"].__setitem__(
            "neqo_version", "forged"
        ),
        "content-type": lambda item: item.__setitem__(
            "content_type", "application/xhtml+xml"
        ),
        "response-receipt": lambda item: item.__setitem__(
            "document_response_receipt_sha256", "0" * 64
        ),
        "unknown-field": lambda item: item.__setitem__(
            "forged_metadata", {"payload_leak": "unbound"}
        ),
        "noncanonical-prepared-path": lambda item: item.__setitem__(
            "prepared_path",
            str(
                Path(item["prepared_path"]).parent
                / ".."
                / "prepared-probes"
                / Path(item["prepared_path"]).name
            ),
        ),
    }
    for label, mutate in mutations.items():
        forged = copy.deepcopy(states)
        mutate(observation(forged))
        with pytest.raises(ValueError, match="checkpoint"):
            validate(forged)

    forged = copy.deepcopy(states)
    forged_observation = observation(forged)
    prepared_path = Path(forged_observation["prepared_path"])
    response_path = runner / forged_observation["document_response_receipt_path"]
    original_prepared = prepared_path.read_bytes()
    original_response = response_path.read_bytes()
    try:
        prepared_manifest = load_json(prepared_path)
        prepared_manifest["preparation"]["lab_source"]["lab_commit"] = "7" * 40
        prepared_path.write_bytes(canonical_json_bytes(prepared_manifest))
        forged_observation["prepared_workload_sha256"] = hashlib.sha256(
            prepared_path.read_bytes()
        ).hexdigest()
        response_payload = load_json(response_path)["payload"]
        response_payload["prepared_workload_sha256"] = forged_observation[
            "prepared_workload_sha256"
        ]
        response_path.write_bytes(
            canonical_json_bytes(
                bind_receipt(
                    response_payload,
                    receipt_type=acquisition_module.DOCUMENT_RESPONSE_RECEIPT_TYPE,
                )
            )
        )
        forged_observation["document_response_receipt_sha256"] = hashlib.sha256(
            response_path.read_bytes()
        ).hexdigest()
        with pytest.raises(ValueError, match="prepared discovery evidence"):
            validate(forged)
    finally:
        prepared_path.write_bytes(original_prepared)
        response_path.write_bytes(original_response)

    prepared_root = runner / "prepared-probes"
    escaped_root = runner / "escaped-prepared-probes"
    prepared_root.rename(escaped_root)
    prepared_root.symlink_to(escaped_root, target_is_directory=True)
    with pytest.raises(ValueError, match="prepared-probe root"):
        validate(states)


def test_existing_backend_applies_the_bounded_timeout_to_navigation(
    monkeypatch: pytest.MonkeyPatch,
):
    observed = {}

    def fake_navigation(domain: str, *, timeout_ms: int):
        observed.update(domain=domain, timeout_ms=timeout_ms)
        return _homepage_navigation(domain)

    monkeypatch.setattr(acquisition_module, "catalogue_boundary_navigation", fake_navigation)
    result = ExistingAcquisitionBackend(timeout_ms=12_345).discover_navigation("example.com")
    assert result.registrable_domain == "example.com"
    assert observed == {"domain": "example.com", "timeout_ms": 12_345}


def test_replay_identity_excludes_per_run_preparation_evidence(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        acquisition_module,
        "runtime_manifest",
        lambda _manifest: {"resources": [{"id": 0, "url": "https://example.com/"}]},
    )
    preparation = {
        "source_url": "https://example.com/",
        "final_url": "https://www.example.com/",
        "approved_origins": ["https://example.com"],
        "origin_ip_pins": {"https://example.com": "1.1.1.1"},
        "browser_request_headers": [{"resource_id": 0, "headers": []}],
        "request_header_transformation": (
            "browser-safe-input-to-neqo-stability-frozen-runtime-v1"
        ),
        "expected_responses": [
            {
                "resource_id": 0,
                "status": 200,
                "bytes": 123,
                "body_sha256": "a" * 64,
            }
        ],
        "udp_payload_qualification": {"runs": [{"packets_sha256": "1" * 64}]},
    }
    first = {"preparation": preparation, "resources": []}
    expected_identity = {
        "schema_version": 3,
        "source_url": preparation["source_url"],
        "final_url": preparation["final_url"],
        "approved_origins": preparation["approved_origins"],
        "origin_ip_pins": preparation["origin_ip_pins"],
        "browser_request_headers": preparation["browser_request_headers"],
        "request_header_transformation": preparation[
            "request_header_transformation"
        ],
        "expected_responses": preparation["expected_responses"],
        "passive_render_contract_sha256": None,
        "runtime_manifest": {
            "resources": [{"id": 0, "url": "https://example.com/"}]
        },
    }
    assert _prepared_replay_identity_sha256(first) == hashlib.sha256(
        canonical_json_bytes(expected_identity)
    ).hexdigest()
    second = copy.deepcopy(first)
    second["preparation"]["udp_payload_qualification"]["runs"][0]["packets_sha256"] = "2" * 64
    assert _prepared_replay_identity_sha256(first) == _prepared_replay_identity_sha256(second)
    second["preparation"]["expected_responses"][0]["body_sha256"] = "b" * 64
    assert _prepared_replay_identity_sha256(first) != _prepared_replay_identity_sha256(second)
    for field, replacement in (
        ("origin_ip_pins", {"https://example.com": "8.8.8.8"}),
        (
            "browser_request_headers",
            [{"resource_id": 0, "headers": [["accept", "text/html"]]}],
        ),
        ("request_header_transformation", "forged-transformation"),
    ):
        changed = copy.deepcopy(first)
        changed["preparation"][field] = replacement
        assert _prepared_replay_identity_sha256(first) != _prepared_replay_identity_sha256(
            changed
        )
