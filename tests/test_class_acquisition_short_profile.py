"""Prospective short acquisition evidence and historical receipt compatibility."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab.class_acquisition import (
    _baseline_batch_reservations,
    _pending_baseline_blocked,
    initialise_runner,
    run_due_acquisition,
)
from qcsd_lab.class_catalogue import (
    SHORT_STABILITY_ACQUISITION_EVIDENCE_SCHEMA_VERSION,
    SHORT_STABILITY_PROBE_WINDOWS,
    STABILITY_ACQUISITION_EVIDENCE_SCHEMA_VERSION,
    STABILITY_PROBE_WINDOWS,
    StabilityObservation,
    build_stability_receipt,
    derive_stability_decision,
    load_stability_receipt,
    select_page_candidates,
    validate_stability_receipt,
)
from qcsd_lab.class_study import ClassCandidate, bind_receipt
from qcsd_lab.util import load_json
from tests.test_class_acquisition import (
    BatchBackend,
    _catalogue,
    _catalogue_candidate_identities,
    _clean_acquisition_source,
    _foundation,
    _miniature_ledger_selection_policy,
)
from tools import class_acquisition_watch as watch


BASELINE = datetime(2026, 8, 28, tzinfo=UTC)


def test_short_batch_release_requires_both_scientific_terminals() -> None:
    batch = [{
        "baseline_started_at": BASELINE.isoformat().replace("+00:00", "Z"),
        "candidate_ids": ["first", "second"],
    }]
    states = {"first": {"pages": []}, "second": {"pages": []}}
    terminals = {
        "first": {"kind": "stable-page-unavailable", "terminalised_at": "2026-08-28T00:05:00Z"},
    }
    assert _baseline_batch_reservations(
        batch, states, terminals, short_window=True
    )[0].released_at is None
    terminals["second"] = {"kind": "eligible", "terminalised_at": "2026-08-28T00:05:01Z"}
    assert _baseline_batch_reservations(
        batch, states, terminals, short_window=True
    )[0].released_at == BASELINE + timedelta(minutes=6, seconds=1)
    assert _baseline_batch_reservations(
        batch, states, terminals
    )[0].released_at == BASELINE + timedelta(minutes=45, seconds=1)
    terminals["second"]["kind"] = "probe-window-missed"
    assert _baseline_batch_reservations(
        batch, states, terminals, short_window=True
    )[0].released_at is None


def _candidate_and_page():
    candidate = ClassCandidate("short-test", "site.example", 1, False)
    page = select_page_candidates(
        candidate.domain,
        registrable_domain=candidate.domain,
        discovered_links=(),
    )[0]
    return candidate, page


def _observations(page, *, short_window: bool) -> tuple[StabilityObservation, ...]:
    windows = SHORT_STABILITY_PROBE_WINDOWS if short_window else STABILITY_PROBE_WINDOWS
    return tuple(
        StabilityObservation(
            probe_id=window.probe_id,
            observed_at=(BASELINE + timedelta(milliseconds=window.target_ms))
            .isoformat()
            .replace("+00:00", "Z"),
            elapsed_ms=window.target_ms,
            final_url=page.url,
            status=200,
            content_type="text/html",
            body_bytes=100,
            body_sha256="1" * 64,
            resource_graph_sha256="2" * 64,
            # Run-specific prepared manifests and discovery receipts may differ;
            # their semantic page/body/graph identity must still agree.
            prepared_workload_sha256=f"{index + 3:064x}",
            passive_render_contract_sha256="5" * 64,
            render_observation_sha256=f"{index + 6:064x}",
            discovery_event_audit_sha256=f"{index + 9:064x}",
            document_response_receipt_path=f"/synthetic/document-{index}.json",
            document_response_receipt_sha256=f"{index + 12:064x}",
        )
        for index, window in enumerate(windows)
    )


def _receipt(*, short_window: bool, observations=None):
    candidate, page = _candidate_and_page()
    return build_stability_receipt(
        candidate,
        page,
        tranco_list_id="TEST1",
        tranco_list_sha256="a" * 64,
        baseline_started_at=BASELINE.isoformat().replace("+00:00", "Z"),
        observations=observations or _observations(page, short_window=short_window),
        short_window=short_window,
    )


def test_short_receipt_compares_two_prepared_observations() -> None:
    receipt = _receipt(short_window=True)
    payload = receipt["payload"]

    assert payload["acquisition_evidence_schema_version"] == (
        SHORT_STABILITY_ACQUISITION_EVIDENCE_SCHEMA_VERSION
    )
    assert payload["probe_schedule"] == [
        window.as_dict() for window in SHORT_STABILITY_PROBE_WINDOWS
    ]
    assert len(payload["observations"]) == 2
    assert payload["observations"][0]["prepared_workload_sha256"] != (
        payload["observations"][1]["prepared_workload_sha256"]
    )
    decision = validate_stability_receipt(receipt)
    assert decision.eligible
    assert decision.stable_values["prepared_workload_sha256"] == (
        payload["observations"][0]["prepared_workload_sha256"]
    )


@pytest.mark.parametrize(
    "field,reason",
    [
        ("body_sha256", "body-sha256-drift"),
        ("resource_graph_sha256", "resource-graph-sha256-drift"),
        ("passive_render_contract_sha256", "passive-render-contract-drift"),
    ],
)
def test_short_receipt_rejects_semantic_drift(field: str, reason: str) -> None:
    _, page = _candidate_and_page()
    observations = list(_observations(page, short_window=True))
    observations[1] = replace(observations[1], **{field: "f" * 64})

    decision = derive_stability_decision(
        page,
        baseline_started_at=BASELINE.isoformat().replace("+00:00", "Z"),
        observations=observations,
        short_window=True,
    )
    assert not decision.eligible
    assert reason in decision.reasons
    assert decision.stable_values is None
    assert validate_stability_receipt(
        _receipt(short_window=True, observations=observations)
    ) == decision


def test_short_receipt_requires_both_prepared_replays() -> None:
    _, page = _candidate_and_page()
    with pytest.raises(ValueError, match="exactly 2 observations"):
        _receipt(
            short_window=True,
            observations=_observations(page, short_window=True)[:1],
        )


def test_historical_three_window_receipt_remains_verifiable() -> None:
    receipt = _receipt(short_window=False)
    assert receipt["payload"]["acquisition_evidence_schema_version"] == (
        STABILITY_ACQUISITION_EVIDENCE_SCHEMA_VERSION
    )
    assert receipt["payload"]["probe_schedule"] == [
        window.as_dict() for window in STABILITY_PROBE_WINDOWS
    ]
    assert validate_stability_receipt(receipt).eligible

    payload = copy.deepcopy(receipt["payload"])
    payload["probe_schedule"] = [window.as_dict() for window in SHORT_STABILITY_PROBE_WINDOWS]
    rebound = bind_receipt(payload, receipt_type=receipt["receipt_type"])
    with pytest.raises(ValueError, match="probe schedule"):
        validate_stability_receipt(rebound)


def test_v10_runner_prepares_two_distinct_probe_files_in_one_baseline_action(
    tmp_path: Path,
) -> None:
    catalogue = _catalogue(tmp_path / "catalogue.json")
    runner = initialise_runner(
        tmp_path / "runner",
        candidate_catalogue_path=catalogue,
        foundation_attestation=_foundation(tmp_path / "foundation.json"),
        started_at=BASELINE.isoformat().replace("+00:00", "Z"),
        browser_tool="test-browser@1",
    )
    candidate_id, _domain = _catalogue_candidate_identities(catalogue, 1)[0]
    backend = BatchBackend(BASELINE + timedelta(seconds=25), runner=runner)
    arguments = {
        "candidate_catalogue_path": catalogue,
        "stability_root": tmp_path / "stability",
        "workload_root": tmp_path / "workloads",
        "backend": backend,
        "now": BASELINE,
        "max_candidates": 1,
    }

    run_due_acquisition(runner, **arguments)  # Navigation.
    run_due_acquisition(runner, **arguments)  # One bounded baseline action.

    checkpoint = load_json(runner / "checkpoint.json")["payload"]
    state = checkpoint["candidates"][candidate_id]
    observations = state["pages"][0]["observations"]
    assert len(checkpoint["baseline_batches"]) == 1
    assert [observation["probe_id"] for observation in observations] == [
        window.probe_id for window in SHORT_STABILITY_PROBE_WINDOWS
    ]
    prepared_paths = [Path(observation["prepared_path"]) for observation in observations]
    assert prepared_paths[0] != prepared_paths[1]
    for path, observation in zip(prepared_paths, observations, strict=True):
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == observation[
            "prepared_workload_sha256"
        ]
    assert observations[0]["resource_graph_sha256"] == observations[1][
        "resource_graph_sha256"
    ]
    terminal = load_json(runner / state["terminal"]["path"])["payload"]
    assert terminal["kind"] == "eligible"
    stability_path = Path(terminal["stability_receipt"]["path"])
    stability, decision = load_stability_receipt(stability_path)
    assert decision.eligible
    assert stability["payload"]["acquisition_evidence_schema_version"] == (
        SHORT_STABILITY_ACQUISITION_EVIDENCE_SCHEMA_VERSION
    )
    assert Path(terminal["admitted_workload"]["path"]).read_bytes() == (
        prepared_paths[0].read_bytes()
    )


def test_v10_host_watcher_accepts_37_baselines_across_24_hours() -> None:
    """A legacy t+24h offset would falsely collide with later short-profile work."""

    candidate_order = tuple(f"candidate-{index:02d}" for index in range(74))
    binding = SimpleNamespace(
        candidate_ids=frozenset(candidate_order),
        candidate_order=candidate_order,
    )
    states = {}
    batches = []
    for batch_index in range(37):
        started_at = (BASELINE + timedelta(minutes=40 * batch_index)).isoformat().replace(
            "+00:00", "Z"
        )
        candidate_ids = list(candidate_order[2 * batch_index : 2 * batch_index + 2])
        for candidate_id in candidate_ids:
            states[candidate_id] = {
                "state": "probing",
                "pages": [{"page": {"ordinal": 0}}],
                "terminal": None,
                "baseline_started_at": started_at,
            }
        batch = {
            "baseline_started_at": started_at,
            "candidate_ids": candidate_ids,
            "live_page_count": 2,
        }
        batch["batch_id"] = watch._content_addressed_batch_id("baseline", batch)
        batches.append(batch)

    assert batches[-1]["baseline_started_at"] == (
        BASELINE + timedelta(hours=24)
    ).isoformat().replace("+00:00", "Z")
    assert len(
        watch._validate_baseline_batches(batches, binding=binding, states=states)
    ) == 74

    too_close = copy.deepcopy(batches)
    too_close[-1]["baseline_started_at"] = (
        BASELINE + timedelta(hours=24, seconds=-1)
    ).isoformat().replace("+00:00", "Z")
    too_close[-1]["batch_id"] = watch._content_addressed_batch_id(
        "baseline", too_close[-1]
    )
    for candidate_id in too_close[-1]["candidate_ids"]:
        states[candidate_id]["baseline_started_at"] = too_close[-1]["baseline_started_at"]
    with pytest.raises(watch.WatchError, match="violate the serial schedule"):
        watch._validate_baseline_batches(too_close, binding=binding, states=states)


def test_pending_navigation_respects_short_repeat_probe() -> None:
    """A waiting t+5m replay blocks another navigation action for this profile."""

    states = {
        "probing": {
            "state": "probing",
            "terminal": None,
            "baseline_started_at": BASELINE.isoformat().replace("+00:00", "Z"),
            "pages": [{"rejection": None, "observations": [{"probe_id": "t+30s"}]}],
        },
        "next": {"state": "pending", "terminal": None},
    }
    now = BASELINE + timedelta(seconds=30)

    assert _pending_baseline_blocked(
        states, now, baseline_starts=(), short_window=True
    )
    assert not _pending_baseline_blocked(
        states, now, baseline_starts=(), short_window=False
    )
