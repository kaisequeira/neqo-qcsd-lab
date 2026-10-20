"""Owned startup/lifecycle components, not Native or scientific evidence.

The original disposable lineage fixture supplies real immutable membership,
SQLite and Source authority; Linux FLOCK/fdinfo checks are not replaced. Only
Docker/DNS/route and historical preparation/raw leaves are explicit fixtures.
No successful capture, pilot, timing proof or credit is claimed.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import threading

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_runtime as runtime
from qcsd_lab.resource_study_inputs import canonical_json, sha256_file
from tests import test_resource_study_lineage as lineage_fixture
from tests.test_resource_study_lineage import campaign
from tests.test_resource_study_capture_authority import lock_home
from tests.test_resource_study_catalog_runtime import CatalogDocker


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="real Linux owned authority and FLOCK")


@pytest.fixture
def owned(campaign, lock_home, monkeypatch):
    """A real admitted member with an explicitly synthetic full-runtime DTO."""
    parent, child, _ = campaign
    original_enrollment = lineage_fixture.enrollment

    def full_enrollment(*args, **kwargs):
        value = original_enrollment(*args, **kwargs)
        value["runtime"].update({"canonical_sha256": "1" * 64,
            "native_commit": value["runtime"]["source"]["neqo_commit"],
            "collection_image_digest": "sha256:" + "2" * 64,
            "prepare_image_digest": "sha256:" + "3" * 64})
        value["preparation_dir"] = "prepared/controlled-enrollment"
        return value

    monkeypatch.setattr(lineage_fixture, "enrollment", full_enrollment)
    store = child("owned-catalog-runtime")
    lineage_fixture.admit(parent, store)
    enrollment = store.enrolled()[0]
    image = enrollment["runtime"]["collection_image_digest"]
    docker = CatalogDocker({image})
    monkeypatch.setattr(runtime, "_docker", docker)
    monkeypatch.setattr(runtime, "_host_routes", lambda: [])
    monkeypatch.setattr(runtime, "public_ipv4", lambda host: {
        "hostname": host, "addresses": ["8.8.8.8"], "selected_ipv4": "8.8.8.8"})
    events = []
    actual_lock = runtime.docker_lock

    @contextmanager
    def observe_lock():
        with actual_lock() as owner:
            events.append(("lock-enter", owner))
            try:
                yield owner
            finally:
                events.append(("lock-exit", owner))

    monkeypatch.setattr(runtime, "docker_lock", observe_lock)
    return store, enrollment, docker, events


def engine(owned, auth):
    store, enrollment, _, _ = owned
    value = enrollment["runtime"]
    key = hashlib.sha256(canonical_json(value)).hexdigest()
    return runtime.CatalogCaptureRuntime({store.root: {
        "plan": store.plan(), "study_sha256": sha256_file(store.root / "study.json")}}, 2,
        cell_roots={enrollment["hostname"]: store.root},
        host_runtimes={enrollment["hostname"]: deepcopy(value)},
        worker_runtime_keys=[key, key], host_modes={enrollment["hostname"]: ["front"]},
        _startup_authority=auth)


def test_busy_docker_refuses_before_original_ancestry_and_releases_owner(lock_home, tmp_path, monkeypatch):
    calls = []

    def busy(*args, **kwargs):
        calls.append(args)
        assert args == ("ps", "-q")
        return "already-running-container"

    def forbidden_ancestry(*args, **kwargs):
        pytest.fail("busy Docker must refuse before expensive ancestry validation")

    monkeypatch.setattr(runtime, "_docker", busy)
    monkeypatch.setattr(cohorts, "capture_authority_scope", forbidden_ancestry)
    with pytest.raises(ValueError, match="no unaccounted running containers"):
        with runtime._catalog_capture_authority([tmp_path]):
            pytest.fail("busy Docker startup cannot yield authority")
    assert calls == [("ps", "-q")]
    with runtime.docker_lock() as owner:
        owner.check()  # the failed startup released its real kernel owner
    assert owner.active is False


def test_real_authority_is_borrowed_through_actual_backend_and_closed_only_outside(owned):
    store, _, docker, events = owned
    with runtime._catalog_capture_authority([store.root]) as auth:
        owner = auth.docker_owner
        with engine(owned, auth) as backend:
            assert backend._docker_owner is owner
            with backend.capture_authority_scope() as borrowed:
                assert borrowed is auth and backend._capture_authority is auth
                assert cohorts._CAPTURE_AUTHORITY.get() == (auth, threading.get_ident(), None)
            assert not hasattr(backend, "_capture_authority")
        assert auth.active is True and owner.active is True
        owner.check()
        assert not docker.containers and not docker.networks
        closed = json.loads((backend.flight / "closed.json").read_bytes())
        assert closed["cleanup_errors"] == [] and closed["scientific_credit"] is False
        assert closed["catalog_flight"] == backend.flight_binding()
        assert [name for name, _ in events] == ["lock-enter"]
    assert auth.active is False and owner.active is False
    assert [name for name, _ in events] == ["lock-enter", "lock-exit"]


def test_startup_body_and_cleanup_failures_preserve_one_outer_owner(owned):
    store, _, docker, events = owned
    with runtime._catalog_capture_authority([store.root]) as auth:
        owner = auth.docker_owner
        # Actual MultiRoot.__enter__ failure invokes original __exit__ once;
        # no topology was born and the outer owner remains held.
        startup = engine(owned, auth)
        startup.contexts[store.root]["study_sha256"] = "0" * 64
        with pytest.raises(ValueError, match="study context changed"):
            startup.__enter__()
        assert startup.closed and not docker.containers and not docker.networks
        assert owner.active and auth.active

        class BodyFailure(Exception):
            pass

        body = engine(owned, auth)
        with pytest.raises(BodyFailure, match="explicit body failure"):
            with body:
                raise BodyFailure("explicit body failure")
        assert body.closed and not docker.containers and not docker.networks
        assert owner.active and auth.active
        # Repeated exit cannot remove objects or release any owner twice.
        calls = len(docker.calls)
        body.__exit__(None, None, None)
        assert len(docker.calls) == calls

        cleanup = engine(owned, auth)
        cleanup.__enter__()
        docker.fail = lambda args: args[0] == "rm"
        with pytest.raises(RuntimeError, match="cleanup needs recovery"):
            cleanup.__exit__(None, None, None)
        assert owner.active and auth.active
        closed = json.loads((cleanup.flight / "closed.json").read_bytes())
        assert closed["cleanup_errors"] and closed["scientific_credit"] is False
        # Fixture-only disposal of mocked objects; no successful cleanup claim.
        docker.fail = None
        docker.containers.clear()
        docker.networks.clear()
    assert not owner.active and not auth.active
    assert [name for name, _ in events] == ["lock-enter", "lock-exit"]


def test_foreign_or_changed_borrow_bindings_refuse_without_second_owner(owned, tmp_path):
    store, _, docker, events = owned
    with runtime._catalog_capture_authority([store.root]) as auth:
        backend = engine(owned, auth)
        original = backend._startup_identity
        baseline = len(docker.calls)
        with pytest.raises(ValueError, match="foreign"):
            runtime._checked_catalog_startup_authority(object(), [store.root])
        with pytest.raises(ValueError, match="different writers"):
            runtime._checked_catalog_startup_authority(auth, [store.root, tmp_path])

        named = [
            ("foreign PID", "pid", auth.pid + 1),
            ("foreign thread", "owner_thread", auth.owner_thread + 1),
            ("changed writer set", "writers", frozenset({str(tmp_path)})),
            ("incomplete collection", "collecting", True),
            ("closed authority", "active", False),
            ("foreign Docker owner", "docker_owner", object()),
            ("foreign Source", "source_auth", object()),
        ]
        for name, field, value in named:
            previous = getattr(auth, field)
            try:
                setattr(auth, field, value)
                with pytest.raises(ValueError) as refusal:
                    runtime._checked_catalog_startup_authority(auth, [store.root], expected=original)
                assert refusal.value, name
            finally:
                setattr(auth, field, previous)

        for name, variable, value in [
            ("unbound coordinator", cohorts._CAPTURE_AUTHORITY, None),
            ("worker binding", cohorts._CAPTURE_AUTHORITY, (auth, threading.get_ident(), str(store.root))),
            ("dropped Source binding", cohorts._SOURCE_OPERATION, None),
        ]:
            token = variable.set(value)
            try:
                with pytest.raises(ValueError, match="not bound") as refusal:
                    runtime._checked_catalog_startup_authority(auth, [store.root], expected=original)
                assert refusal.value, name
            finally:
                variable.reset(token)

        parent_root = auth.parent.root
        try:
            auth.parent.root = tmp_path
            with pytest.raises(ValueError, match="parent, Source or Docker owner changed"):
                runtime._checked_catalog_startup_authority(auth, [store.root], expected=original)
        finally:
            auth.parent.root = parent_root
        backend._startup_authority = None
        with pytest.raises(ValueError, match="cannot be dropped"):
            with backend._docker_lock_scope():
                pytest.fail("dropped private authority cannot take a new owner")
        backend._startup_authority = auth
        assert len(docker.calls) == baseline
        assert [name for name, _ in events] == ["lock-enter"]
    assert [name for name, _ in events] == ["lock-enter", "lock-exit"]
