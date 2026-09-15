from __future__ import annotations

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from qcsd_lab.acquisition_timing import (
    ACTION_TIMING_CONTRACT,
    BASELINE_SCHEDULING_CONTRACT,
    BaselineReservation,
    GLOBAL_LIVE_PAGE_CAP,
    MAX_CANDIDATES_PER_ACTION,
    MINIMUM_BASELINE_SPACING_MS,
    SERIAL_ACTION_START_OFFSETS_MS,
    STABILITY_WINDOW_EARLIEST_OFFSETS_MS,
    TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT,
    baseline_is_safe,
    baseline_is_safe_with_releases,
    earliest_safe_baseline,
    earliest_safe_baseline_with_releases,
    greedy_baseline_schedule,
    scheduled_action_starts,
    scheduled_window_starts,
    validate_baseline_schedule,
    validate_baseline_schedule_with_releases,
)


def test_contract_derivation_is_exact_and_exceeds_long_window_width() -> None:
    assert MINIMUM_BASELINE_SPACING_MS == 2_400_000
    assert MAX_CANDIDATES_PER_ACTION == 2
    assert GLOBAL_LIVE_PAGE_CAP == 5
    assert ACTION_TIMING_CONTRACT["schema_version"] == 2
    assert ACTION_TIMING_CONTRACT["bounded_candidates"] == 2
    assert ACTION_TIMING_CONTRACT["global_live_page_cap"] == 5
    assert ACTION_TIMING_CONTRACT["inner_timeout"] == {
        "scope": "in-container-coordinator-process-group",
        "soft_deadline_ms": 1_800_000,
        "soft_signal": "SIGINT",
        "cleanup_grace_ms": 120_000,
        "hard_signal": "SIGKILL",
        "hard_deadline_ms": 1_920_000,
    }
    assert ACTION_TIMING_CONTRACT["outer_timeout"]["hard_deadline_ms"] == 2_040_000
    assert (
        BASELINE_SCHEDULING_CONTRACT["status_configured_hard_cutoff_ms"]
        == 310_000
    )
    assert BASELINE_SCHEDULING_CONTRACT["scheduler_margin_ms"] == 50_000
    assert (
        MINIMUM_BASELINE_SPACING_MS
        > BASELINE_SCHEDULING_CONTRACT["longest_probe_window_width_ms"]
    )


def test_cross_offset_collision_is_rejected_even_with_direct_spacing() -> None:
    first = datetime(2026, 9, 4, tzinfo=UTC)
    # Direct baselines are 48 hours apart, but the later baseline's t+24h is
    # exactly the earlier baseline's t+72h.
    colliding = first + timedelta(hours=48)
    assert abs(colliding - first).total_seconds() * 1_000 > MINIMUM_BASELINE_SPACING_MS
    assert baseline_is_safe(colliding, (first,)) is False
    with pytest.raises(ValueError, match="serial scheduling contract"):
        validate_baseline_schedule((first, colliding))


def test_baseline_action_cannot_overlap_an_existing_long_probe_action() -> None:
    first = datetime(2026, 9, 4, tzinfo=UTC)
    # This baseline begins 39m50s after the first candidate's t+24h action.
    # Treating the embedded t+30s observation as the only short action start
    # would miss this ten-second overlap at the reservation boundary.
    colliding = first + timedelta(milliseconds=85_500_000) + timedelta(
        minutes=39, seconds=50
    )
    assert baseline_is_safe(colliding, (first,)) is False
    assert min(
        abs((left - right).total_seconds() * 1_000)
        for left in scheduled_action_starts(first)
        for right in scheduled_action_starts(colliding)
    ) == 2_390_000


def test_solver_advances_to_exact_safe_boundary_across_overlapping_bans() -> None:
    first = datetime(2026, 9, 4, tzinfo=UTC)
    requested = first + timedelta(hours=48)
    selected = earliest_safe_baseline(requested, (first,))
    assert selected > requested
    assert baseline_is_safe(selected, (first,))
    starts = scheduled_window_starts(first) + scheduled_window_starts(selected)
    assert min(
        abs((left - right).total_seconds() * 1_000)
        for index, left in enumerate(starts[:3])
        for right in starts[3:]
    ) >= MINIMUM_BASELINE_SPACING_MS


def test_timezone_naive_schedule_values_fail_closed() -> None:
    naive = datetime(2026, 9, 4)
    with pytest.raises(ValueError, match="timezone-aware"):
        scheduled_window_starts(naive)
    with pytest.raises(ValueError, match="timezone-aware"):
        earliest_safe_baseline(naive, ())
    with pytest.raises(ValueError, match="timezone-aware"):
        greedy_baseline_schedule(naive, 0)


def test_same_zone_dst_arithmetic_is_normalised_to_utc() -> None:
    new_york = ZoneInfo("America/New_York")
    before_jump = datetime(2026, 3, 8, 1, 50, tzinfo=new_york)
    after_jump = datetime(2026, 3, 8, 3, 10, tzinfo=new_york)
    # These instants are only twenty elapsed minutes apart. Python's direct
    # subtraction for two datetimes carrying the same ZoneInfo object uses the
    # eighty-minute wall-time difference, so the scheduler must normalise.
    assert after_jump.astimezone(UTC) - before_jump.astimezone(UTC) == timedelta(
        minutes=20
    )
    assert baseline_is_safe(after_jump, (before_jump,)) is False


def test_registered_offsets_match_the_acquisition_windows() -> None:
    assert STABILITY_WINDOW_EARLIEST_OFFSETS_MS == (25_000, 85_500_000, 258_300_000)
    assert SERIAL_ACTION_START_OFFSETS_MS == (0, 85_500_000, 258_300_000)


def test_strict_serial_300_batch_projection_is_receipted_exactly() -> None:
    start = datetime(2026, 9, 4, tzinfo=UTC)
    schedule = greedy_baseline_schedule(start, 300)
    projection = BASELINE_SCHEDULING_CONTRACT[
        "strict_serial_zero_duration_projection"
    ]
    assert (schedule[-1] - start).total_seconds() * 1_000 == projection[
        "last_baseline_offset_ms"
    ]
    assert projection == {
        "candidate_count": 600,
        "maximum_candidates_per_batch": 2,
        "batch_count": 300,
        "pairing_assumption": (
            "all-candidates-form-300-compatible-two-candidate-batches"
        ),
        "algorithm": "greedy-earliest-safe-baseline-batches",
        "last_baseline_offset_ms": 2_784_000_000,
        "last_t+72h_earliest_offset_ms": 3_042_300_000,
    }
    last_t72_earliest = schedule[-1] + timedelta(
        milliseconds=STABILITY_WINDOW_EARLIEST_OFFSETS_MS[-1]
    )
    assert (last_t72_earliest - start).total_seconds() * 1_000 == projection[
        "last_t+72h_earliest_offset_ms"
    ]
    assert projection["last_t+72h_earliest_offset_ms"] == 3_042_300_000


def test_greedy_projection_is_not_misrepresented_as_a_global_lower_bound() -> None:
    start = datetime(2026, 9, 4, tzinfo=UTC)
    greedy = greedy_baseline_schedule(start, 300)
    delayed = [start, start + timedelta(minutes=90)]
    next_candidate = delayed[-1] + timedelta(
        milliseconds=MINIMUM_BASELINE_SPACING_MS
    )
    for _ in range(298):
        next_candidate = earliest_safe_baseline(next_candidate, delayed)
        delayed.append(next_candidate)
        next_candidate += timedelta(milliseconds=MINIMUM_BASELINE_SPACING_MS)
    validate_baseline_schedule(delayed)
    assert delayed[-1] - start == timedelta(days=32, hours=3, minutes=10)
    assert delayed[-1] < greedy[-1]


def test_terminal_release_contract_preserves_historical_bounds_and_projection() -> None:
    current = TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT
    assert BASELINE_SCHEDULING_CONTRACT["schema_version"] == 2
    assert current["schema_version"] == 3
    assert current["maximum_candidates_per_batch"] == 2
    assert current["global_live_page_cap"] == 5
    assert current["reservation_release_delay_ms"] == MINIMUM_BASELINE_SPACING_MS
    assert current["reservation_release_delay_ms"] == 2_400_000
    assert current["action_priority"] == "due-probes-before-new-baselines-and-navigation"
    assert current["infrastructure_failure_policy"] == (
        "timeout-interruption-and-missed-window-block-not-site-ineligibility"
    )
    for key in (
        "minimum_baseline_spacing_ms",
        "window_start_reservation_ms",
        "acquisition_outer_configured_hard_cutoff_ms",
        "status_configured_hard_cutoff_ms",
        "scheduler_margin_ms",
        "serial_action_start_offsets_ms",
        "stability_window_earliest_offsets_ms",
        "strict_serial_zero_duration_projection",
    ):
        assert current[key] == BASELINE_SCHEDULING_CONTRACT[key]
    assert current["strict_serial_zero_duration_projection"] is not (
        BASELINE_SCHEDULING_CONTRACT["strict_serial_zero_duration_projection"]
    )


def test_120_candidate_60_batch_ideal_projection_preserves_all_survivor_schedule() -> None:
    start = datetime(2026, 9, 4, tzinfo=UTC)
    historical = greedy_baseline_schedule(start, 60)
    reservations: list[BaselineReservation] = []
    next_start = start
    for expected in historical:
        selected = earliest_safe_baseline_with_releases(next_start, reservations)
        assert selected == expected
        reservations.append(
            BaselineReservation(
                selected,
                selected + timedelta(milliseconds=SERIAL_ACTION_START_OFFSETS_MS[-1]),
            )
        )
        next_start = selected + timedelta(milliseconds=MINIMUM_BASELINE_SPACING_MS)
    validate_baseline_schedule_with_releases(reservations)
    assert (historical[-1] - start) == timedelta(milliseconds=399_900_000)
    last_probe = historical[-1] + timedelta(
        milliseconds=STABILITY_WINDOW_EARLIEST_OFFSETS_MS[-1]
    )
    assert last_probe - start == timedelta(milliseconds=658_200_000)
    assert last_probe - start == timedelta(days=7, hours=14, minutes=50)


@pytest.mark.parametrize("offset_ms", (0, 2_399_999, 2_400_000, 85_500_000, 172_800_000))
def test_unreleased_batches_retain_exact_historical_admission(offset_ms: int) -> None:
    start = datetime(2026, 9, 4, tzinfo=UTC)
    existing = (start, start + timedelta(hours=1))
    requested = start + timedelta(milliseconds=offset_ms)
    reservations = tuple(BaselineReservation(value) for value in existing)
    assert baseline_is_safe_with_releases(requested, iter(reservations)) == (
        baseline_is_safe(requested, existing)
    )
    assert earliest_safe_baseline_with_releases(requested, iter(reservations)) == (
        earliest_safe_baseline(requested, existing)
    )


def test_terminal_release_removes_only_proven_unnecessary_future_reservations() -> None:
    start = datetime(2026, 9, 4, tzinfo=UTC)
    reservation = BaselineReservation(start, start + timedelta(minutes=1))
    # v2 still reserves this rejected batch's +24h action.  Prospective v3
    # admits a new batch, without moving any real observation window.
    requested = start + timedelta(milliseconds=SERIAL_ACTION_START_OFFSETS_MS[1])
    assert baseline_is_safe(requested, (start,)) is False
    assert baseline_is_safe_with_releases(requested, (reservation,)) is True
    assert earliest_safe_baseline_with_releases(requested, (reservation,)) == requested
    assert scheduled_window_starts(requested) == tuple(
        requested + timedelta(milliseconds=offset)
        for offset in (25_000, 85_500_000, 258_300_000)
    )


def test_terminal_release_cannot_waive_full_cleanup_and_status_reservation() -> None:
    start = datetime(2026, 9, 4, tzinfo=UTC)
    next_probe = start + timedelta(milliseconds=SERIAL_ACTION_START_OFFSETS_MS[1])
    terminal = next_probe - timedelta(minutes=20)
    reservation = BaselineReservation(start, terminal)
    release = terminal + timedelta(minutes=40)
    assert reservation.released_at == release
    assert baseline_is_safe_with_releases(release - timedelta(microseconds=1), (reservation,)) is False
    assert baseline_is_safe_with_releases(release, (reservation,)) is True
    # Release is itself an exact interval boundary, before the old collision
    # interval would otherwise end at next_probe + 40 minutes.
    assert earliest_safe_baseline_with_releases(next_probe, (reservation,)) == release


def test_release_solver_closes_overlapping_live_and_released_batch_bans() -> None:
    start = datetime(2026, 9, 4, tzinfo=UTC)
    requested = start + timedelta(milliseconds=SERIAL_ACTION_START_OFFSETS_MS[1])
    released = BaselineReservation(start, requested - timedelta(minutes=20))
    live = BaselineReservation(start + timedelta(minutes=40))
    selected = earliest_safe_baseline_with_releases(requested, (released, live))
    assert selected == requested + timedelta(minutes=80)
    assert baseline_is_safe_with_releases(selected, (released, live)) is True
    assert baseline_is_safe_with_releases(
        selected - timedelta(microseconds=1), (released, live)
    ) is False


def test_schedule_replay_cannot_use_later_terminal_evidence_retroactively() -> None:
    start = datetime(2026, 9, 4, tzinfo=UTC)
    collision = start + timedelta(milliseconds=SERIAL_ACTION_START_OFFSETS_MS[1])
    late_terminal = BaselineReservation(start, collision + timedelta(minutes=1))
    with pytest.raises(ValueError, match="serial scheduling contract"):
        validate_baseline_schedule_with_releases(
            (late_terminal, BaselineReservation(collision))
        )
    early_terminal = BaselineReservation(start, start + timedelta(minutes=1))
    validate_baseline_schedule_with_releases(
        (BaselineReservation(collision), early_terminal)
    )
    # Historical validation remains strict even for that same timestamp pair.
    with pytest.raises(ValueError, match="serial scheduling contract"):
        validate_baseline_schedule((start, collision))


@pytest.mark.parametrize("field", ("baseline", "terminal"))
def test_terminal_release_rejects_naive_timestamps(field: str) -> None:
    start = datetime(2026, 9, 4, tzinfo=UTC)
    with pytest.raises(ValueError, match="timezone-aware"):
        BaselineReservation(
            start.replace(tzinfo=None) if field == "baseline" else start,
            start.replace(tzinfo=None) if field == "terminal" else None,
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        baseline_is_safe_with_releases(start.replace(tzinfo=None), ())
    with pytest.raises(ValueError, match="timezone-aware"):
        earliest_safe_baseline_with_releases(start.replace(tzinfo=None), ())


def test_terminal_release_rejects_impossible_or_untyped_evidence() -> None:
    start = datetime(2026, 9, 4, tzinfo=UTC)
    with pytest.raises(ValueError, match="predates"):
        BaselineReservation(start, start - timedelta(microseconds=1))
    for operation in (
        baseline_is_safe_with_releases,
        earliest_safe_baseline_with_releases,
    ):
        with pytest.raises(ValueError, match="BaselineReservation"):
            operation(start, (start,))
    with pytest.raises(ValueError, match="BaselineReservation"):
        validate_baseline_schedule_with_releases((start,))
    with pytest.raises(ValueError, match="serial scheduling contract"):
        validate_baseline_schedule_with_releases(
            (BaselineReservation(start), BaselineReservation(start))
        )


def test_terminal_release_uses_elapsed_utc_time_across_dst() -> None:
    new_york = ZoneInfo("America/New_York")
    baseline = datetime(2026, 3, 8, 1, 30, tzinfo=new_york)
    terminal = datetime(2026, 3, 8, 1, 50, tzinfo=new_york)
    reservation = BaselineReservation(baseline, terminal)
    assert reservation.baseline_started_at == baseline.astimezone(UTC)
    assert reservation.terminalised_at == terminal.astimezone(UTC)
    assert reservation.released_at == datetime(2026, 3, 8, 7, 30, tzinfo=UTC)
