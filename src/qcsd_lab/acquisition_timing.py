"""Canonical timing and bounded-batch scheduling contract for class acquisition.

The browser navigation timeout and the passive post-load cap are component
limits.  Neither bounds DNS, browser start-up, origin convergence, Neqo replay,
or teardown.  The public launcher therefore owns a separate nested, configured
whole-action cut-off, while this module owns the immutable provenance values
and the collision-free baseline schedule derived from that cut-off.  The
cut-off is a policy limit; it is not misrepresented as a sum-derived upper
bound for the browser/Neqo call tree.
"""

from __future__ import annotations

from collections.abc import Iterable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

ACQUISITION_ACTION_SOFT_TIMEOUT_MS = 1_800_000
ACQUISITION_ACTION_CLEANUP_GRACE_MS = 120_000
ACQUISITION_ACTION_INNER_HARD_TIMEOUT_MS = 1_920_000
ACQUISITION_ACTION_OUTER_RUNTIME_MS = 1_920_000
ACQUISITION_ACTION_OUTER_HARD_TIMEOUT_MS = 2_040_000
STATUS_RUNTIME_MS = 300_000
STATUS_CLEANUP_GRACE_MS = 10_000
SERIAL_SCHEDULER_MARGIN_MS = 50_000
MAX_CANDIDATES_PER_ACTION = 2
GLOBAL_LIVE_PAGE_CAP = 5

MINIMUM_BASELINE_SPACING_MS = (
    ACQUISITION_ACTION_OUTER_HARD_TIMEOUT_MS
    + STATUS_RUNTIME_MS
    + STATUS_CLEANUP_GRACE_MS
    + SERIAL_SCHEDULER_MARGIN_MS
)
WINDOW_START_RESERVATION_MS = MINIMUM_BASELINE_SPACING_MS

# Earliest admissible starts, rather than nominal targets, define the probe
# windows.  The serial reservation below is larger than the widest
# (30-minute) long-probe window.
STABILITY_WINDOW_EARLIEST_OFFSETS_MS = (25_000, 85_500_000, 258_300_000)
# The t+30s observation is pre-armed and executed inside the action that
# establishes the baseline, so it is not another serial launcher start.  The
# baseline action and the two later watcher-launched probes are the three
# starts that must be reserved against every other baseline batch.
SERIAL_ACTION_START_OFFSETS_MS = (0, 85_500_000, 258_300_000)
LONGEST_STABILITY_WINDOW_WIDTH_MS = 1_800_000

ACTION_TIMING_CONTRACT = {
    "schema_version": 2,
    "policy": "bounded-compatible-candidate-batch-whole-action-deadline-v2",
    "bounded_candidates": MAX_CANDIDATES_PER_ACTION,
    "global_live_page_cap": GLOBAL_LIVE_PAGE_CAP,
    "batch_selection": (
        "same-priority-same-stage-immutable-catalogue-order-compatible-pair-"
        "otherwise-singleton"
    ),
    "transactional_publication": (
        "active-batch-and-pending-attempts-published-before-parallel-work"
    ),
    "coordinator_merge": (
        "deterministic-immutable-catalogue-order-after-all-workers-return"
    ),
    "browser_navigation_timeout_ms": 60_000,
    "browser_navigation_timeout_scope": "navigation-component-only",
    "passive_render_hard_cap_after_load_ms": 30_000,
    "passive_render_timeout_scope": "post-load-component-only",
    "inner_timeout": {
        "scope": "in-container-coordinator-process-group",
        "soft_deadline_ms": ACQUISITION_ACTION_SOFT_TIMEOUT_MS,
        "soft_signal": "SIGINT",
        "cleanup_grace_ms": ACQUISITION_ACTION_CLEANUP_GRACE_MS,
        "hard_signal": "SIGKILL",
        "hard_deadline_ms": ACQUISITION_ACTION_INNER_HARD_TIMEOUT_MS,
    },
    "outer_timeout": {
        "scope": "canonical-host-acquisition-watch-user-systemd-scope",
        "runtime_max_ms": ACQUISITION_ACTION_OUTER_RUNTIME_MS,
        "runtime_signal": "SIGINT",
        "cleanup_grace_ms": ACQUISITION_ACTION_CLEANUP_GRACE_MS,
        "final_signal": "SIGKILL",
        "hard_deadline_ms": ACQUISITION_ACTION_OUTER_HARD_TIMEOUT_MS,
    },
    "direct_public_acquisition_run": (
        "forbidden-without-validated-watcher-scope-authority"
    ),
    "successful_ledger_attempt_duration_limit_ms": (
        ACQUISITION_ACTION_SOFT_TIMEOUT_MS
    ),
    "whole_action_duration_evidence": (
        "externally-enforced-process-status-no-per-action-duration-receipt"
    ),
    "interruption_recovery": (
        "published-active-batch-attempts-become-interrupted-never-completed"
    ),
}

BASELINE_SCHEDULING_CONTRACT = {
    "schema_version": 2,
    "policy": "serial-nonoverlapping-stability-window-batch-reservations-v2",
    "maximum_candidates_per_batch": MAX_CANDIDATES_PER_ACTION,
    "global_live_page_cap": GLOBAL_LIVE_PAGE_CAP,
    "minimum_baseline_spacing_ms": MINIMUM_BASELINE_SPACING_MS,
    "window_start_reservation_ms": WINDOW_START_RESERVATION_MS,
    "longest_probe_window_width_ms": LONGEST_STABILITY_WINDOW_WIDTH_MS,
    "acquisition_outer_configured_hard_cutoff_ms": (
        ACQUISITION_ACTION_OUTER_HARD_TIMEOUT_MS
    ),
    "status_configured_hard_cutoff_ms": (
        STATUS_RUNTIME_MS + STATUS_CLEANUP_GRACE_MS
    ),
    "scheduler_margin_ms": SERIAL_SCHEDULER_MARGIN_MS,
    "navigation_phase": "separate-bounded-action-before-baseline",
    "short_probe": "same-action-wait-until-t+30s-earliest",
    "outer_probes": "watcher-launches-acquisition-run-at-window-earliest",
    "within_batch_baseline": "one-equal-baseline-per-recorded-baseline-batch",
    "schedule_validation_unit": "baseline-batches-not-raw-candidate-timestamps",
    "unpaired_candidate_policy": "singleton-when-no-compatible-partner",
    "serial_action_start_offsets_ms": list(SERIAL_ACTION_START_OFFSETS_MS),
    "stability_window_earliest_offsets_ms": list(
        STABILITY_WINDOW_EARLIEST_OFFSETS_MS
    ),
    "collision_scope": (
        "baseline-arming-and-t+24h-t+72h-action-starts-across-batches"
    ),
    "strict_serial_zero_duration_projection": {
        "candidate_count": 600,
        "maximum_candidates_per_batch": MAX_CANDIDATES_PER_ACTION,
        "batch_count": 300,
        "pairing_assumption": (
            "all-candidates-form-300-compatible-two-candidate-batches"
        ),
        "algorithm": "greedy-earliest-safe-baseline-batches",
        "last_baseline_offset_ms": 2_784_000_000,
        "last_t+72h_earliest_offset_ms": 3_042_300_000,
    },
}

# Prospective runners opt into this contract explicitly.  Keep the v2 value
# and its readers unchanged: later terminal evidence must not retrospectively
# relax the scheduling contract recorded by an older acquisition campaign.
# With all 600 candidates surviving, the 300-batch zero-duration projection
# remains 3,042,300,000 ms (~35.21 days) through the last t+72h earliest start.
# This policy removes unnecessary reservations, not genuine stability waits.
TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT = {
    **deepcopy(BASELINE_SCHEDULING_CONTRACT),
    "schema_version": 3,
    "policy": "serial-terminal-released-stability-window-batch-reservations-v3",
    "reservation_release": (
        "all-batch-members-scientifically-terminal-plus-full-serial-reservation"
    ),
    "reservation_release_evidence": (
        "latest-immutable-hash-bound-batch-member-terminalised-at"
    ),
    "reservation_release_delay_ms": WINDOW_START_RESERVATION_MS,
    "reservation_release_validation": "causal-at-each-recorded-baseline-start",
    "infrastructure_failure_policy": (
        "timeout-interruption-and-missed-window-block-not-site-ineligibility"
    ),
    "action_priority": "due-probes-before-new-baselines-and-navigation",
}

RUN_WAIT_POLICY = {
    "navigation_phase": "separate-bounded-action-before-baseline",
    "t+30s": "same-action-interruptible-wait-to-earliest-then-probe",
    "t+24h-and-t+72h": "host-watcher-launch-at-earliest-no-container-wait",
}


def scheduled_window_starts(baseline: datetime) -> tuple[datetime, ...]:
    """Return the three probe-window earliest starts for one aware baseline."""

    if not isinstance(baseline, datetime) or baseline.tzinfo is None:
        raise ValueError("acquisition baseline must be timezone-aware")
    baseline = baseline.astimezone(UTC)
    return tuple(
        baseline + timedelta(milliseconds=offset)
        for offset in STABILITY_WINDOW_EARLIEST_OFFSETS_MS
    )


def scheduled_action_starts(baseline: datetime) -> tuple[datetime, ...]:
    """Return the serial action starts reserved for one aware baseline."""

    if not isinstance(baseline, datetime) or baseline.tzinfo is None:
        raise ValueError("acquisition baseline must be timezone-aware")
    baseline = baseline.astimezone(UTC)
    return tuple(
        baseline + timedelta(milliseconds=offset)
        for offset in SERIAL_ACTION_START_OFFSETS_MS
    )


def baseline_is_safe(candidate: datetime, existing: Iterable[datetime]) -> bool:
    """Whether a candidate baseline preserves every serial reservation."""

    if not isinstance(candidate, datetime) or candidate.tzinfo is None:
        raise ValueError("acquisition baseline must be timezone-aware")
    candidate = candidate.astimezone(UTC)
    reservation = timedelta(milliseconds=WINDOW_START_RESERVATION_MS)
    candidate_starts = scheduled_action_starts(candidate)
    for baseline in existing:
        if not isinstance(baseline, datetime) or baseline.tzinfo is None:
            raise ValueError("acquisition baseline must be timezone-aware")
        baseline = baseline.astimezone(UTC)
        if any(
            abs(candidate_start - existing_start) < reservation
            for candidate_start in candidate_starts
            for existing_start in scheduled_action_starts(baseline)
        ):
            return False
    return True


def earliest_safe_baseline(
    not_before: datetime,
    existing: Iterable[datetime],
) -> datetime:
    """Find the first instant at or after ``not_before`` outside all bans.

    Each existing baseline induces nine cross-action intervals.  Advancing to
    the greatest upper boundary that currently contains the candidate is exact
    because equality with the
    reservation is admissible; repeating closes overlapping intervals without
    a time-step search.
    """

    if not isinstance(not_before, datetime) or not_before.tzinfo is None:
        raise ValueError("acquisition schedule start must be timezone-aware")
    not_before = not_before.astimezone(UTC)
    baselines = tuple(existing)
    for baseline in baselines:
        if not isinstance(baseline, datetime) or baseline.tzinfo is None:
            raise ValueError("acquisition baseline must be timezone-aware")
    baselines = tuple(baseline.astimezone(UTC) for baseline in baselines)
    reservation = timedelta(milliseconds=WINDOW_START_RESERVATION_MS)
    intervals: list[tuple[datetime, datetime]] = []
    for baseline in baselines:
        for candidate_offset in SERIAL_ACTION_START_OFFSETS_MS:
            offset = timedelta(milliseconds=candidate_offset)
            for existing_start in scheduled_action_starts(baseline):
                centre = existing_start - offset
                intervals.append((centre - reservation, centre + reservation))
    candidate = not_before
    while True:
        containing = tuple(high for low, high in intervals if low < candidate < high)
        if not containing:
            if not baseline_is_safe(candidate, baselines):
                raise AssertionError("baseline interval solver reached an unsafe boundary")
            return candidate
        candidate = max(containing)


def validate_baseline_schedule(baselines: Iterable[datetime]) -> None:
    """Reject batch baselines that could schedule two serial actions together."""

    values = tuple(baselines)
    if any(not isinstance(value, datetime) or value.tzinfo is None for value in values):
        raise ValueError("acquisition baseline must be timezone-aware")
    values = tuple(value.astimezone(UTC) for value in values)
    accepted: list[datetime] = []
    for baseline in sorted(values):
        if not baseline_is_safe(baseline, accepted):
            raise ValueError("acquisition baselines violate the serial scheduling contract")
        accepted.append(baseline)


def greedy_baseline_schedule(start: datetime, count: int) -> tuple[datetime, ...]:
    """Schedule ``count`` serial baseline batches with zero work time."""

    if type(count) is not int or count < 0:
        raise ValueError("acquisition schedule count must be a non-negative integer")
    if not isinstance(start, datetime) or start.tzinfo is None:
        raise ValueError("acquisition schedule start must be timezone-aware")
    selected: list[datetime] = []
    candidate = start.astimezone(UTC)
    spacing = timedelta(milliseconds=MINIMUM_BASELINE_SPACING_MS)
    for _ in range(count):
        candidate = earliest_safe_baseline(candidate, selected)
        selected.append(candidate)
        candidate += spacing
    return tuple(selected)


@dataclass(frozen=True)
class BaselineReservation:
    """One batch's reservation and optional authenticated scientific terminal.

    The caller must authenticate every member's immutable terminal receipt and
    supply their latest ``terminalised_at`` only when all members are resolved
    scientifically.  Timeouts, interruptions, and missed windows are not site
    ineligibility and cannot supply this release.  A full existing reservation
    is retained after the terminal time so worker completion cannot waive the
    configured action, cleanup, and status bounds.
    """

    baseline_started_at: datetime
    terminalised_at: datetime | None = None

    def __post_init__(self) -> None:
        baseline = self.baseline_started_at
        terminal = self.terminalised_at
        if not isinstance(baseline, datetime) or baseline.tzinfo is None:
            raise ValueError("acquisition baseline must be timezone-aware")
        baseline = baseline.astimezone(UTC)
        object.__setattr__(self, "baseline_started_at", baseline)
        if terminal is not None:
            if not isinstance(terminal, datetime) or terminal.tzinfo is None:
                raise ValueError("acquisition terminal time must be timezone-aware")
            terminal = terminal.astimezone(UTC)
            if terminal < baseline:
                raise ValueError("acquisition terminal time predates its baseline")
            object.__setattr__(self, "terminalised_at", terminal)

    @property
    def released_at(self) -> datetime | None:
        if self.terminalised_at is None:
            return None
        return self.terminalised_at + timedelta(milliseconds=WINDOW_START_RESERVATION_MS)


def _validated_reservations(
    reservations: Iterable[BaselineReservation],
) -> tuple[BaselineReservation, ...]:
    values = tuple(reservations)
    if any(not isinstance(value, BaselineReservation) for value in values):
        raise ValueError("acquisition reservations must be BaselineReservation values")
    return values


def baseline_is_safe_with_releases(
    candidate: datetime, reservations: Iterable[BaselineReservation]
) -> bool:
    """Apply v2 bounds, releasing only batches resolved before this baseline."""

    if not isinstance(candidate, datetime) or candidate.tzinfo is None:
        raise ValueError("acquisition baseline must be timezone-aware")
    candidate = candidate.astimezone(UTC)
    values = _validated_reservations(reservations)
    return baseline_is_safe(
        candidate,
        (
            value.baseline_started_at
            for value in values
            if value.released_at is None or candidate < value.released_at
        ),
    )


def earliest_safe_baseline_with_releases(
    not_before: datetime, reservations: Iterable[BaselineReservation]
) -> datetime:
    """Find the exact earliest v3 baseline, including causal release boundaries.

    A v2 collision interval ends at its original boundary or the authenticated
    batch release, whichever comes first.  No measured or mean execution time
    substitutes for the configured reservation.
    """

    if not isinstance(not_before, datetime) or not_before.tzinfo is None:
        raise ValueError("acquisition schedule start must be timezone-aware")
    candidate = not_before.astimezone(UTC)
    values = _validated_reservations(reservations)
    reservation = timedelta(milliseconds=WINDOW_START_RESERVATION_MS)
    intervals: list[tuple[datetime, datetime]] = []
    for value in values:
        release = value.released_at
        for candidate_offset in SERIAL_ACTION_START_OFFSETS_MS:
            offset = timedelta(milliseconds=candidate_offset)
            for existing_start in scheduled_action_starts(value.baseline_started_at):
                centre = existing_start - offset
                high = centre + reservation
                if release is not None:
                    high = min(high, release)
                intervals.append((centre - reservation, high))
    while True:
        containing = tuple(high for low, high in intervals if low < candidate < high)
        if not containing:
            if not baseline_is_safe_with_releases(candidate, values):
                raise AssertionError("baseline release solver reached an unsafe boundary")
            return candidate
        candidate = max(containing)


def validate_baseline_schedule_with_releases(
    reservations: Iterable[BaselineReservation],
) -> None:
    """Replay v3 admission at each baseline, never using later release early."""

    values = sorted(
        _validated_reservations(reservations), key=lambda value: value.baseline_started_at
    )
    accepted: list[BaselineReservation] = []
    for value in values:
        if not baseline_is_safe_with_releases(value.baseline_started_at, accepted):
            raise ValueError("acquisition baselines violate the serial scheduling contract")
        accepted.append(value)
