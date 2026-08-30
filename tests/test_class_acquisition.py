from __future__ import annotations

import copy
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import qcsd_lab.class_acquisition as acquisition_module
from qcsd_lab.class_acquisition import (
    COMPLETION_TYPE,
    MAX_APPROVED_ORIGINS,
    MAX_ORIGIN_PASSES,
    ExistingAcquisitionBackend,
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
    PageCandidate,
)
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
from qcsd_lab.prepare import PreparationError, PreparedWorkload
from qcsd_lab.util import load_json


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


def _prepared_manifest(url: str, approved_origins) -> dict:
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
    source = {
        "image_digest": "sha256:" + "1" * 64,
        "lab_commit": "2" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": empty_sha256,
        "neqo_commit": "3" * 40,
        "neqo_pinned_commit": "3" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": empty_sha256,
    }
    return {
        "preparation": {
            "source_url": url,
            "final_url": url,
            "chromium_version": "test-chromium",
            "settle_ms": 3_000,
            "observed_request_count": len(resources),
            "observed_origins": list(approved_origins),
            "approved_origins": list(approved_origins),
            "exclusions": [],
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
                "schema_version": 1,
                "policy": "all-approved-origins-and-rendered-resources",
                "required_origins": list(approved_origins),
                "required_resources": [
                    {"id": resource["id"], "url": resource["url"]}
                    for resource in resources
                ],
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

    def prepare(self, workload_id, url, approved_origins, output_root):
        output_root.mkdir(parents=True, exist_ok=True)
        path = output_root / f"{workload_id}.json"
        path.write_bytes(canonical_json_bytes(_prepared_manifest(url, approved_origins)))
        self.clock.value += timedelta(seconds=20)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return PreparedProbe(
            observed_at=self.clock.value.isoformat().replace("+00:00", "Z"),
            final_url=url,
            status=200,
            content_type="text/html",
            body_bytes=100,
            body_sha256="c" * 64,
            resource_graph_sha256=digest,
            prepared=PreparedWorkload(
                path,
                digest,
                len(approved_origins),
                len(approved_origins),
            ),
            chromium_version="test",
            neqo_provenance={"neqo_version": "test"},
        )


class FakeClock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


class InterruptOnceBackend(SlowBackend):
    def __init__(self, clock):
        super().__init__(clock)
        self.interrupted = False
        self.workload_ids = []

    def prepare(self, workload_id, url, approved_origins, output_root):
        self.workload_ids.append(workload_id)
        if not self.interrupted:
            self.interrupted = True
            raise KeyboardInterrupt
        return super().prepare(workload_id, url, approved_origins, output_root)


class InterruptAfterManifestBackend(SlowBackend):
    def __init__(self, clock):
        super().__init__(clock)
        self.interrupted = False
        self.workload_ids = []

    def prepare(self, workload_id, url, approved_origins, output_root):
        self.workload_ids.append(workload_id)
        if not self.interrupted:
            self.interrupted = True
            output_root.mkdir(parents=True, exist_ok=True)
            (output_root / f"{workload_id}.json").write_bytes(b"orphaned first-attempt manifest")
            raise KeyboardInterrupt
        return super().prepare(workload_id, url, approved_origins, output_root)


class TransientNavigationBackend(SlowBackend):
    def __init__(self, clock):
        super().__init__(clock)
        self.navigation_calls = 0

    def discover_navigation(self, domain: str):
        self.navigation_calls += 1
        if self.navigation_calls == 1:
            raise RuntimeError("temporary DNS failure")
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

    def prepare(self, workload_id, url, approved_origins, output_root):
        self.workload_ids.append(workload_id)
        if len(self.workload_ids) == 1:
            raise PreparationError(
                "complete coverage final browser discovery observed new HTTPS GET origins "
                "after convergence: https://late-origin.example"
            )
        return super().prepare(workload_id, url, approved_origins, output_root)


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
        if state["state"] == "probing"
    )
    assert backend.navigation_calls == 2
    assert [item["outcome"] for item in active["navigation_attempts"]] == [
        "recoverable-failure",
        "completed",
    ]
    assert [item["attempt"] for item in active["navigation_attempts"]] == [1, 2]


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


def test_due_probe_preempts_new_baseline_and_records_start_not_slow_completion(
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
        if state["state"] == "probing"
    )
    clock.value = datetime(2026, 8, 28, 0, 0, 40, tzinfo=UTC)
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
    assert observation["observed_at"] == "2026-08-28T00:00:40Z"
    assert observation["probe_completed_at"] == "2026-08-28T00:01:00Z"
    assert sum(state["state"] == "probing" for state in states.values()) == 1


def test_one_bounded_run_refuses_a_new_baseline_near_probe_window(tmp_path: Path):
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
    assert not probing[0]["pages"][0]["observations"]
    assert status["pending_count"] == CANDIDATE_COUNT - 1
    assert status["pending_start_blocked"] is True
    assert status["work_due_now"] is False
    assert status["next_due"] == "2026-08-28T00:00:35Z"


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
        sum(state["state"] == "probing" for state in checkpoint["payload"]["candidates"].values())
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
    # Navigation advances the fake clock by ten seconds, so this candidate's
    # first stability window is centred on 00:00:40 rather than 00:00:30.
    clock.value = datetime(2026, 8, 28, 0, 0, 40, tzinfo=UTC)
    with pytest.raises(KeyboardInterrupt):
        run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    pending = active["pages"][0]["pending_probe"]
    assert pending["observed_at"] == "2026-08-28T00:00:40Z"
    assert pending["attempt"] == 1
    assert pending["workload_id"].endswith("-a001")
    clock.value = datetime(2026, 8, 28, 0, 0, 42, tzinfo=UTC)
    run_due_acquisition(runner, **arguments)
    checkpoint = load_json(runner / "checkpoint.json")
    active = next(
        state
        for state in checkpoint["payload"]["candidates"].values()
        if state["state"] == "probing"
    )
    assert active["pages"][0]["observations"][0]["observed_at"] == ("2026-08-28T00:00:42Z")
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
    clock.value = datetime(2026, 8, 28, 0, 0, 40, tzinfo=UTC)
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

    clock.value = datetime(2026, 8, 28, 0, 0, 42, tzinfo=UTC)
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
    assert observation["observed_at"] == "2026-08-28T00:00:42Z"
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
        "public_origin_ip_pins",
        lambda _origins: {"https://example.com": "1.1.1.1"},
    )
    probe = ExistingAcquisitionBackend(
        content_type_probe=lambda _url, _origins, _timeout: "text/html"
    ).prepare("workload", "https://example.com/", ["https://example.com"], tmp_path)
    assert (probe.status, probe.body_bytes, probe.body_sha256) == (200, 123, "a" * 64)
    assert prepare_arguments["stability_runs"] == 3


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

        def prepare(self, workload_id, url, approved_origins, output_root):
            output_root.mkdir(parents=True, exist_ok=True)
            path = output_root / f"{workload_id}.json"
            path.write_bytes(url.encode())
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            return PreparedProbe(
                observed_at="2026-08-28T00:00:31Z",
                final_url=url,
                status=200,
                content_type="text/html",
                body_bytes=len(url),
                body_sha256=digest,
                resource_graph_sha256=digest,
                prepared=PreparedWorkload(path, digest, 1, 1),
                chromium_version="test",
                neqo_provenance={"neqo_version": "test"},
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


def test_origin_convergence_rejects_instead_of_truncating_over_cap():
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

    with pytest.raises(ValueError, match="exceeded its finite origin cap"):
        _converge_origins(OverCapBackend(), "https://page.example/")


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

    with pytest.raises(ValueError, match="did not converge within its pass cap"):
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
    second = copy.deepcopy(first)
    second["preparation"]["udp_payload_qualification"]["runs"][0]["packets_sha256"] = "2" * 64
    assert _prepared_replay_identity_sha256(first) == _prepared_replay_identity_sha256(second)
    second["preparation"]["expected_responses"][0]["body_sha256"] = "b" * 64
    assert _prepared_replay_identity_sha256(first) != _prepared_replay_identity_sha256(second)
