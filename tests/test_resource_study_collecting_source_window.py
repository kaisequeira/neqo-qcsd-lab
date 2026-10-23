"""Disposable constructor Source-window controls; no recording credit.

The connected control uses the existing real cohort/SQLite fixture and actual
kernel Docker flock. The guard-only controls create no capture authority and
copy the complete Source closure before adversarial byte changes. No successful
Source validator, ownership check, or original SQL authority is replaced.
"""
from contextlib import contextmanager
from contextvars import copy_context
from concurrent.futures import ThreadPoolExecutor
import fcntl
import os
from pathlib import Path
import sys
import threading

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_runtime as runtime
from tests.test_resource_study_lineage import campaign
from tests.test_resource_study_runtime_cohorts import cohort_campaign


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="actual Linux Docker flock authority")


@pytest.fixture(autouse=True)
def lock_home(tmp_path, monkeypatch):
    home = tmp_path / "lock-home"
    home.mkdir(mode=0o700)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))


def test_real_constructor_amortizes_only_collecting_source_scans(cohort_campaign):
    """Old production fails the scan-count assertion through its existing API.

    Profiling observes real calls; it does not replace any Source/SQL validator.
    The complete original fixture's synthetic Native/raw leaves grant no credit.
    """
    counts = {"collecting_owner": 0, "collecting_source_scan": 0,
              "noncollecting_source_scan": 0, "window_full_hash": 0}
    owner_code = cohorts._CaptureAuthority._owner.__code__
    stamps_code = cohorts._source_stamps.__code__
    contract_code = cohorts._fresh_verifier_contract.__code__

    def profile(frame, event, argument):
        if event != "call":
            return
        if frame.f_code is owner_code and frame.f_locals["self"].collecting is True:
            counts["collecting_owner"] += 1
        if frame.f_code is stamps_code:
            parent = frame.f_back
            while parent is not None:
                if parent.f_code is owner_code:
                    key = ("collecting_source_scan" if parent.f_locals["self"].collecting is True
                           else "noncollecting_source_scan")
                    counts[key] += 1
                    break
                parent = parent.f_back
        if frame.f_code is contract_code:
            parent = frame.f_back
            while parent is not None:
                if parent.f_code.co_name == "_collecting_source_window":
                    counts["window_full_hash"] += 1
                    break
                parent = parent.f_back

    previous = sys.getprofile()
    sys.setprofile(profile)
    try:
        with runtime.docker_lock() as docker_owner:
            with cohorts.capture_authority_scope(cohort_campaign.old.root, docker_owner) as auth:
                assert auth is not None and auth.collecting is False
                auth._owner()
    finally:
        sys.setprofile(previous)
    assert counts["collecting_owner"] > 0
    assert counts["collecting_source_scan"] == 0, "constructor callbacks must not rescan 178 Source paths each"
    assert counts["window_full_hash"] >= 2, "both private window boundaries hash the complete Source graph"
    assert counts["noncollecting_source_scan"] > 0, "active and finish ownership retain their original Source checks"


@pytest.fixture
def disposable_source(tmp_path, monkeypatch):
    original = Path(cohorts.__file__).parent
    copied = tmp_path / "source"
    copied.mkdir()
    for name in cohorts.RAW_DEPENDENCIES:
        target = copied / name
        target.write_bytes((original / name).read_bytes())
        target.chmod(0o644)
    # Only the location of disposable exact Source copies is redirected.
    # Real _source_stamps/_fresh_verifier_contract bodies remain in use.
    monkeypatch.setattr(cohorts, "__file__", str(copied / "resource_study_cohorts.py"))
    return copied


@contextmanager
def guard_window():
    """Only the real new guard, with no ancestry, Store, reservation or grant."""
    with runtime.docker_lock() as docker_owner:
        auth = object.__new__(cohorts._CaptureAuthority)
        auth.pid, auth.owner_thread = os.getpid(), threading.get_ident()
        auth.docker_owner, auth.active, auth.collecting = docker_owner, True, True
        auth.source_auth = cohorts._SourceAuthorization()
        initial_source = auth.source_auth
        auth._collecting_source_snapshot = None
        auth.implementations = auth._implementations()
        token = cohorts._AUTHORITY_INPUT_COLLECTOR.set(auth)
        try:
            with cohorts.bind_source(auth.source_auth), auth._collecting_source_window():
                yield auth
        finally:
            cohorts._AUTHORITY_INPUT_COLLECTOR.reset(token)
            initial_source.active = False
            auth.source_auth.active = False
            auth.active = False


def test_real_collecting_window_cannot_be_reused_after_finish(disposable_source):
    with guard_window() as auth:
        auth._owner()
        with pytest.raises(ValueError, match="entry"):
            with auth._collecting_source_window():
                pytest.fail("nested collecting window must refuse")
    assert auth._collecting_source_snapshot is None
    with pytest.raises(ValueError, match="closed or foreign"):
        auth._owner()


def test_collecting_source_byte_change_refuses_before_a_window_can_return(disposable_source):
    with pytest.raises(ValueError, match="Source"):
        with guard_window() as auth:
            path = disposable_source / "util.py"
            before = path.stat()
            path.write_bytes(path.read_bytes() + b"\n# disposable adversarial mutation\n")
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            # Interior checks never claim that no Source write occurred. They
            # guard the sealed handle; the mandatory boundary must now refuse.
            auth._owner()
    assert auth._collecting_source_snapshot is None


def test_body_failure_keeps_its_identity_and_records_source_closure_failure(disposable_source):
    original = RuntimeError("deliberate original validator refusal")
    with pytest.raises(RuntimeError) as caught:
        with guard_window():
            path = disposable_source / "util.py"
            path.write_bytes(path.read_bytes() + b"\n# changed disposable Source\n")
            raise original
    assert caught.value is original
    assert any("Collecting Source closure also refused:" in note for note in original.__notes__)


@pytest.mark.parametrize("change", ["source-handle", "profile", "stamps-copy", "stamp-value",
                                   "source-active", "source-pid", "owner-thread", "docker-unlock"])
def test_exact_collecting_handle_and_real_lock_mutations_refuse(disposable_source, change):
    with pytest.raises(ValueError):
        with guard_window() as auth:
            if change == "source-handle":
                auth.source_auth = cohorts._SourceAuthorization()
            elif change == "profile":
                auth.source_auth.profile += b" "
            elif change == "stamps-copy":
                auth.source_auth.stamps = dict(auth.source_auth.stamps)
            elif change == "stamp-value":
                auth.source_auth.stamps["util.py"] = (0,) * 9
            elif change == "source-active":
                auth.source_auth.active = False
            elif change == "source-pid":
                auth.source_auth.pid += 1
            elif change == "owner-thread":
                auth.owner_thread += 1
            else:
                fcntl.flock(auth.docker_owner.handle, fcntl.LOCK_UN)
            auth._owner()


@pytest.mark.parametrize("context", ["collector", "source"])
def test_missing_exact_collector_or_source_context_refuses(disposable_source, context):
    with guard_window() as auth:
        variable = (cohorts._AUTHORITY_INPUT_COLLECTOR if context == "collector"
                    else cohorts._SOURCE_OPERATION)
        token = variable.set(None)
        try:
            with pytest.raises(ValueError, match="window"):
                auth._owner()
        finally:
            variable.reset(token)


def test_collecting_window_rejects_a_copied_context_in_another_thread(disposable_source):
    with guard_window() as auth:
        copied = copy_context()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(copied.run, auth._owner)
            with pytest.raises(ValueError, match="window"):
                future.result()


@pytest.mark.parametrize("change", ["check", "stamps", "contract", "code"])
def test_changed_source_validator_identity_or_code_refuses(disposable_source, monkeypatch, change):
    with guard_window() as auth:
        with monkeypatch.context() as patch:
            if change == "check":
                patch.setattr(cohorts._SourceAuthorization, "check", lambda self: None)
            elif change == "stamps":
                patch.setattr(cohorts, "_source_stamps", lambda: {})
            elif change == "contract":
                patch.setattr(cohorts, "_fresh_verifier_contract", lambda: {})
            else:
                patch.setattr(cohorts._SourceAuthorization.check, "__code__", (lambda self: None).__code__)
            with pytest.raises(ValueError, match="implementation"):
                auth._owner()


def test_noncollecting_owner_still_runs_real_source_metadata_guard(disposable_source):
    with pytest.raises(ValueError, match="Source"):
        with guard_window() as auth:
            auth.collecting = False
            path = disposable_source / "util.py"
            path.write_bytes(path.read_bytes() + b"\n# change after collection\n")
            auth._owner()
