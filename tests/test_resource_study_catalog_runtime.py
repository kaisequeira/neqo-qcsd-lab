"""Catalog topology/job controls with two mocked immutable images.

These exercise the actual backend, partition validator and class attachments.
Docker, DNS and enrollment retrieval are explicit fixture boundaries; they are
not Native fidelity, own-pilot, timing, receipt-proof or live-runtime evidence.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import threading

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_network as network
from qcsd_lab import resource_study_runtime as runtime
from qcsd_lab.resource_study_inputs import canonical_json, sha256_file
from qcsd_lab.resource_study_store import StudyStore
from tests import test_resource_study_runtime as original


def native(index):
    return {"canonical_sha256": str(index) * 64, "client_sha256": str(index + 2) * 64,
            "native_commit": str(index + 4) * 40, "platform": "linux/arm64",
            "collection_image_digest": "sha256:" + str(index + 6) * 64,
            "prepare_image_digest": "sha256:" + str(index + 7) * 64,
            "source": {"neqo_commit": str(index + 4) * 40}}


def runtime_key(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


class CatalogDocker(original.Docker):
    def __init__(self, images):
        super().__init__(ncpu=6, image_arch="arm64", architecture="aarch64")
        self.images = images
        self.affinities = {image: list(range(6)) for image in images}
        self.capture_barrier = None

    def __call__(self, *arguments, timeout=120):
        args = list(arguments)
        if args[:2] == ["image", "inspect"]:
            self.calls.append(args)
            return json.dumps([{"Id": args[2], "Os": "linux", "Architecture": "arm64"}])
        if args[0] == "run" and "--rm" in args:
            self.calls.append(args)
            image = next(value for value in args if value in self.images)
            return json.dumps(self.affinities[image])
        if args[0] == "exec" and "_capture" in args and self.capture_barrier is not None:
            self.capture_barrier.wait(timeout=5)
        result = super().__call__(*arguments, timeout=timeout)
        if args[0] == "create":
            image = next(value for value in args if value in self.images)
            self.containers[result]["Image"] = image
        return result


@pytest.fixture
def catalog(tmp_path, monkeypatch):
    hosts = ("alpha.example", "beta.example")
    roots = [tmp_path / "first", tmp_path / "second"]
    names = [*hosts, *(f"other-{index}.example" for index in range(48))]
    plan = {"acceptance": network.ACCEPTANCE, "tuple_uniqueness_scope": network.TUPLE_SCOPE,
            "class_network": network.build_network_plan(names)}
    contexts = {}
    for index, root in enumerate(roots):
        root.mkdir()
        (root / "study.json").write_bytes(canonical_json({**plan, "created_at": str(index)}))
        contexts[root] = {"plan": json.loads((root / "study.json").read_bytes()),
                          "study_sha256": sha256_file(root / "study.json")}
    runtimes = {host: native(index + 1) for index, host in enumerate(hosts)}
    cell_roots = dict(zip(hosts, roots))
    enrollments = {host: {"hostname": host, "runtime": deepcopy(runtimes[host]),
                         "mode_readiness": {"front": True, "tamaraw": True},
                         "preparation_dir": "prepared/" + host}
                   for host in hosts}
    owner, events = object(), []
    @contextmanager
    def lock():
        events.append("enter")
        try:
            yield owner
        finally:
            events.append("exit")
    monkeypatch.setattr(runtime, "docker_lock", lock)
    monkeypatch.setattr(runtime.os, "fsync", lambda _fd: None)
    monkeypatch.setattr(runtime, "_host_routes", lambda: [])
    monkeypatch.setattr(runtime, "public_ipv4", lambda host: {
        "hostname": host, "addresses": ["8.8.8.8"], "selected_ipv4": "8.8.8.8"})
    monkeypatch.setattr(StudyStore, "enrolled", lambda store: [deepcopy(enrollments[host])
        for host in hosts if cell_roots[host] == store.root])
    docker = CatalogDocker({value["collection_image_digest"] for value in runtimes.values()})
    monkeypatch.setattr(runtime, "_docker", docker)
    arguments = {"cell_roots": cell_roots, "host_runtimes": runtimes,
                 "worker_runtime_keys": [runtime_key(runtimes[host]) for host in hosts],
                 "host_modes": {"alpha.example": ["front"], "beta.example": ["tamaraw"]}}
    return contexts, arguments, enrollments, docker, events, owner


def engine(catalog):
    contexts, arguments, *_ = catalog
    return runtime.CatalogCaptureRuntime(contexts, 2, **arguments)


def attempt(catalog, host):
    root = catalog[1]["cell_roots"][host]
    value = {"hostname": host, "mode": catalog[1]["host_modes"][host][0],
             "path": "attempts/unit", "attempt_id": "0123456789abcdef" * 2}
    (root / value["path"] / "capture").mkdir(parents=True)
    return value


def test_two_runtime_topology_and_concurrent_jobs_keep_exact_image_and_root(catalog):
    contexts, arguments, enrollments, docker, events, _ = catalog
    with engine(catalog) as flight:
        assert flight.runtime is None
        assert flight.runtime_keys == tuple(arguments["worker_runtime_keys"])
        assert flight.host_runtime_keys == {host: runtime_key(value)
            for host, value in arguments["host_runtimes"].items()}
        assert len(flight.workers) == 2
        for host, value in arguments["host_runtimes"].items():
            router = docker.containers[flight.class_routes[host]["router_id"]]
            assert router["Image"] == value["collection_image_digest"]
        for index, worker in enumerate(flight.workers):
            assert docker.containers[worker["id"]]["Image"] == arguments["host_runtimes"][
                ("alpha.example", "beta.example")[index]]["collection_image_digest"]
        docker.capture_barrier = threading.Barrier(2)
        calls = [(index, attempt(catalog, host), deepcopy(enrollments[host]))
                 for index, host in enumerate(("alpha.example", "beta.example"))]
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(flight.capture, *call) for call in calls]
            for future in futures:
                assert future.result()["success"] is False  # explicit mock scientific negative
        for index, job_attempt, _ in calls:
            host = job_attempt["hostname"]
            root = arguments["cell_roots"][host]
            job = json.loads((root / job_attempt["path"] / "job.json").read_bytes())
            assert set(job) == {"hostname", "mode", "enrollment_dir", "attempt_dir", "seed", "runtime"}
            assert job["runtime"] == arguments["host_runtimes"][host]
            assert job["enrollment_dir"] == str(root / enrollments[host]["preparation_dir"])
            attachment = json.loads((root / job_attempt["path"] / "capture/class-network.json").read_bytes())
            assert attachment["network"]["image_digest"] == job["runtime"]["collection_image_digest"]
            assert attachment["binding"] == network.receipt_binding(contexts[root]["plan"],
                contexts[root]["study_sha256"], host)
            assert attachment["worker_container_id"] == flight.workers[index]["id"]
            flight.release(index)
        for path in flight.flights.values():
            launched = json.loads((path / "launched.json").read_bytes())
            assert launched["record_type"] == "qcsd-resource-domain-runtime-catalog-launch-v1"
            assert "runtime" not in launched and "shared_flight" not in launched
            assert launched["catalog_flight"] == flight.flight_binding()
    assert events == ["enter", "exit"] and not docker.containers and not docker.networks
    for root, path in flight.flights.items():
        closed = json.loads((path / "closed.json").read_bytes())
        assert closed["record_type"] == "qcsd-resource-domain-runtime-catalog-closed-v1"
        assert closed["cleanup_errors"] == [] and closed["scientific_credit"] is False
        assert closed["study_sha256"] == contexts[root]["study_sha256"]
        assert closed["catalog_flight"] == flight.flight_binding()


def test_all_owning_roots_receive_original_authority_scope(catalog, monkeypatch):
    contexts, _, _, _, _, owner = catalog
    seen, authority = [], object()
    @contextmanager
    def original_scope(roots, docker_owner):
        seen.append((roots, docker_owner))
        yield authority
    monkeypatch.setattr(cohorts, "capture_authority_scope", original_scope)
    with engine(catalog) as flight:
        with flight.capture_authority_scope() as actual:
            assert actual is authority and flight._capture_authority is authority
        assert not hasattr(flight, "_capture_authority")
    assert seen == [(sorted(contexts), owner)]


def test_same_hostname_cannot_occupy_two_compatible_lanes(catalog):
    contexts, arguments, _, _, _, _ = catalog
    host = "alpha.example"
    root = arguments["cell_roots"][host]
    key = arguments["worker_runtime_keys"][0]
    with runtime.CatalogCaptureRuntime({root: contexts[root]}, 2,
            cell_roots={host: root}, host_runtimes={host: arguments["host_runtimes"][host]},
            worker_runtime_keys=[key, key], host_modes={host: ["front"]}) as flight:
        flight._activate(0, host)
        with pytest.raises(ValueError, match="already owned"):
            flight._activate(1, host)
        assert flight.class_owners == {host: 0}
        flight.release(0)
        flight._activate(1, host)
        assert flight.class_owners == {host: 1}
        flight.release(1)


def test_wrong_lane_or_changed_job_is_refused_before_network_or_job_birth(catalog):
    _, arguments, enrollments, docker, *_ = catalog
    with engine(catalog) as flight:
        value = attempt(catalog, "alpha.example")
        base = len(docker.calls)
        mutations = [(1, value, enrollments["alpha.example"]),
                     (0, {**value, "mode": "buflo"}, enrollments["alpha.example"]),
                     (0, value, {**enrollments["alpha.example"], "preparation_dir": "other"})]
        for index, changed_attempt, changed_enrollment in mutations:
            with pytest.raises(ValueError, match="catalog"):
                flight.capture(index, changed_attempt, changed_enrollment)
        assert len(docker.calls) == base
        assert not (arguments["cell_roots"]["alpha.example"] / value["path"] / "job.json").exists()
        assert not flight.class_owners


@pytest.mark.parametrize("role", ["worker", "router"])
def test_changed_actual_image_is_refused_before_native_job(catalog, role):
    _, arguments, enrollments, docker, *_ = catalog
    with engine(catalog) as flight:
        value = attempt(catalog, "alpha.example")
        identifier = (flight.workers[0]["id"] if role == "worker"
                      else flight.class_routes["alpha.example"]["router_id"])
        docker.containers[identifier]["Image"] = "sha256:" + "0" * 64
        with pytest.raises(ValueError):
            flight.capture(0, value, enrollments["alpha.example"])
        assert not (arguments["cell_roots"]["alpha.example"] / value["path"] / "job.json").exists()
        assert not any("_capture" in args for args in docker.calls)


def test_incompatible_image_affinity_refuses_before_topology(catalog):
    _, arguments, _, docker, events, _ = catalog
    image = arguments["host_runtimes"]["beta.example"]["collection_image_digest"]
    docker.affinities[image] = [0, 1, 2, 3, 4]
    with pytest.raises(ValueError, match="disagree"):
        with engine(catalog):
            pass
    assert events == ["enter", "exit"] and not docker.containers and not docker.networks
    assert not any(args[0] == "create" for args in docker.calls)


def test_catalog_shape_and_caller_mutation_guards(catalog):
    contexts, arguments, *_ = catalog
    mutations = [({**arguments, "worker_runtime_keys": arguments["worker_runtime_keys"][:1]}, 2),
                 ({**arguments, "worker_runtime_keys": [arguments["worker_runtime_keys"][0]] * 2}, 2),
                 ({**arguments, "host_modes": {**arguments["host_modes"], "alpha.example": []}}, 2),
                 ({**arguments, "host_runtimes": {"alpha.example": native(1)}}, 2),
                 (arguments, True), (arguments, 12)]
    for changed, count in mutations:
        with pytest.raises(ValueError, match="catalog"):
            runtime.CatalogCaptureRuntime(contexts, count, **changed)
    flight = engine(catalog)
    arguments["host_runtimes"]["alpha.example"]["source"]["untrusted"] = True
    assert "untrusted" not in flight.host_runtimes["alpha.example"]["source"]
    flight.host_runtimes["alpha.example"]["source"]["changed"] = True
    with pytest.raises(ValueError, match="immutable catalog"):
        flight.flight_binding()


def test_enrollment_runtime_or_selected_readiness_refusal_still_closes_created_flights(catalog):
    _, _, enrollments, docker, events, _ = catalog
    enrollments["alpha.example"]["mode_readiness"]["front"] = False
    flight = engine(catalog)
    with pytest.raises(ValueError, match="actual enrollment"):
        flight.__enter__()
    assert events == ["enter", "exit"] and not docker.containers and not docker.networks
    assert len(flight.flights) == 2
    assert all(json.loads((path / "closed.json").read_bytes())["cleanup_errors"] == []
               for path in flight.flights.values())
    flight.__exit__(None, None, None)
    assert events == ["enter", "exit"]


def test_partial_launch_failure_cleans_once_and_truthful_cleanup_failure_refuses(catalog):
    _, _, _, docker, events, _ = catalog
    docker.fail = lambda args: args[0] == "create" and "org.qcsd.role=resource-study-worker" in args
    flight = engine(catalog)
    with pytest.raises(RuntimeError, match="offline injected"):
        flight.__enter__()
    assert events == ["enter", "exit"] and not docker.containers and not docker.networks
    assert all(json.loads((path / "closed.json").read_bytes())["cleanup_errors"] == []
               for path in flight.flights.values())
    docker.fail = None
    second = engine(catalog)
    second.__enter__()
    docker.fail = lambda args: args[0] == "rm"
    with pytest.raises(RuntimeError, match="cleanup needs recovery"):
        second.__exit__(None, None, None)
    assert events == ["enter", "exit", "enter", "exit"]
    assert all(json.loads((path / "closed.json").read_bytes())["cleanup_errors"]
               for path in second.flights.values())
