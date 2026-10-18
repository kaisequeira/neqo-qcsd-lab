"""Focused current-head controls using the original Linux custody/SQL fixture.

The imported fixture's preparation and raw-proof leaves are explicitly synthetic.
Actual authority, flock ownership, immutable files, SQL fences, reservation and
credit guards run unchanged. These tests confer no study or capture credit.
"""
from copy import deepcopy
import fcntl
import sys

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from tests.test_resource_study_capture_authority import (
    attack_sql, campaign, cohort_campaign, lock_home, scoped,
)
from tests.test_resource_study_runtime_cohorts import HOST, MODE, controlled_pilot


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="real Linux flock/fdinfo custody")


@pytest.fixture
def current_cohort(cohort_campaign):
    c = cohort_campaign
    current = c.fresh()
    c.append(current)
    controlled_pilot(current, HOST, MODE)
    return c, current


def test_current_head_copy_is_detached_and_default_history_stays_complete(current_cohort, lock_home):
    c, current = current_cohort
    with scoped(current) as (auth, _):
        expected = deepcopy(auth.records)
        assert len(expected) > 1 and expected[-1]["record_type"] == cohorts.ADMISSION
        with cohorts.capture_records_scope(c.parent, writer_root=current.root, latest_only=True) as head:
            assert head == expected[-1:]
            head[0]["cells"].clear()
            head[0]["cohorts"][0]["members"].clear()
        assert auth.records == expected
        with cohorts.capture_records_scope(c.parent, writer_root=current.root, latest_only=True) as head:
            assert head == expected[-1:]
        with cohorts.capture_records_scope(c.parent, writer_root=current.root) as full:
            assert full == expected
        assert cohorts.records(c.parent) == expected


@pytest.mark.parametrize("value", [None, 1, "true"])
def test_current_head_selection_is_explicit_boolean(current_cohort, lock_home, value):
    c, current = current_cohort
    with scoped(current):
        with pytest.raises(ValueError, match="explicit boolean"):
            with cohorts.capture_records_scope(c.parent, writer_root=current.root, latest_only=value):
                pytest.fail("an untyped view selection exposed authority")


def records_calls(operation):
    """Observe the original full-reader entry; do not replace any validator."""
    calls = []
    code = epochs._records.__code__
    previous = sys.getprofile()

    def observe(frame, event, argument):
        if event == "call" and frame.f_code is code:
            calls.append(frame.f_code.co_name)

    sys.setprofile(observe)
    try:
        result = operation()
    finally:
        sys.setprofile(previous)
    return result, calls


def test_bound_lineage_check_reuses_actual_authority_head_and_fallback_reads_full(current_cohort, lock_home):
    c, current = current_cohort
    with scoped(current) as (auth, _):
        expected = deepcopy(auth.records)
        result, calls = records_calls(lambda: epochs.stable_lineage_active(current))
        assert result is True
        assert calls == [], "bound sealing lineage must reuse the authenticated current head"
        assert auth.records == expected
    # The historical non-capture API takes no additional flock. A caller may
    # already own the parent lock; opening a second exclusive flock can deadlock.
    with epochs._lock(c.parent.root):
        result, calls = records_calls(lambda: epochs.stable_lineage_active(current))
    assert result is True and calls, "outside capture the complete original reader is still required"
    with cohorts.capture_records_scope(c.parent, writer_root=current.root, latest_only=True) as value:
        assert value is None


def test_current_head_callbacks_keep_live_reservations_counts_and_tuple_guards(current_cohort, lock_home):
    c, current = current_cohort
    with scoped(current):
        assert cohorts.counts_snapshot(current, [(HOST, MODE)], latest_only=True) == {(HOST, MODE): 1}
        attempt = current.allocate_attempt(HOST, MODE, purpose="pilot")
        with pytest.raises(ValueError, match="active reservation"):
            current.allocate_attempt(HOST, MODE, purpose="pilot")
        current.mark_captured(attempt["attempt_id"])
        current.fail_attempt(attempt["attempt_id"], "explicit no-credit current-head fixture")
        c.credit(current, port=31002)
        assert cohorts.counts_snapshot(current, [(HOST, MODE)], latest_only=True) == {(HOST, MODE): 2}
        with pytest.raises(ValueError, match="tuple|duplicate|repeats"):
            c.credit(current, port=31002)
        assert current.status()["accepted_count"] == 1


@pytest.mark.parametrize("change", ["head", "classes", "fence"])
def test_current_head_view_refuses_fresh_sql_authority_changes(current_cohort, lock_home, change):
    c, current = current_cohort
    with pytest.raises((ValueError, OSError)):
        with scoped(current):
            if change == "head":
                attack_sql(c.parent, "UPDATE meta SET value=? WHERE key='epoch_head'", ("{}",))
            elif change == "classes":
                attack_sql(c.parent, "UPDATE classes SET sha256=? WHERE hostname=?", ("0" * 64, "alpha.example"))
            else:
                attack_sql(c.parent, "DROP TRIGGER " + next(iter(lineage.fence_ddl())))
            with pytest.raises((ValueError, OSError)):
                with cohorts.capture_records_scope(c.parent, writer_root=current.root, latest_only=True):
                    pytest.fail("a current-head copy bypassed fresh SQL authority")


@pytest.mark.parametrize("change", ["immutable-bytes", "docker-lock"])
def test_current_head_view_retains_full_bytes_and_real_custody_checks(current_cohort, lock_home, change):
    c, current = current_cohort
    with pytest.raises((ValueError, OSError)):
        with scoped(current) as (_, owner):
            if change == "immutable-bytes":
                path = c.parent.root / "study.json"
                raw = path.read_bytes()
                path.chmod(0o644)
                path.write_bytes(raw + b"\n")
                path.chmod(0o444)
            else:
                fcntl.flock(owner.handle, fcntl.LOCK_UN)
            with pytest.raises((ValueError, OSError)):
                with cohorts.capture_records_scope(c.parent, writer_root=current.root, latest_only=True):
                    pytest.fail("a current-head copy weakened full custody or byte checks")
