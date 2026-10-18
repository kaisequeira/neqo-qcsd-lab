"""Run the original source-boundary control with its disposable real lock.

Only fixture registration changes: the imported original test body, source
checks and actual kernel flock remain unchanged. No live lifecycle lock is used.
"""
import sys
import pytest
from tests.test_resource_study_capture_authority import campaign, lock_home
from tests.test_resource_study_runtime_cohorts import (
    cohort_campaign,
    test_operation_source_profile_hashes_at_boundaries_and_refuses_changed_or_closed_authority,
)

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='genuine Linux fdinfo/flock authority')
