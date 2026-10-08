"""Mock Docker launch controls; none is a physical runtime/capture pass."""
from contextlib import contextmanager
import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import kernel_capture_router as router
from qcsd_lab import kernel_tx_runtime as kernel
from qcsd_lab import process_scheduler as scheduler
from qcsd_lab import resource_study_runtime as runtime
from qcsd_lab.resource_study_inputs import canonical_json, sha256_file
from qcsd_lab.resource_study_store import StudyStore


IMAGE = "sha256:" + "a" * 64
RUNTIME = {"collection_image_digest": IMAGE, "platform": "linux/amd64",
           "native_commit": "b" * 40, "client_sha256": "c" * 64}


def option(args, key):
    return args[args.index(key) + 1]


def options(args, key):
    return [args[i + 1] for i, value in enumerate(args[:-1]) if value == key]


class Docker:
    def __init__(self, ncpu=6, *, fail=None, foreign=False, image_arch="amd64", architecture="x86_64"):
        self.ncpu, self.fail, self.foreign = ncpu, fail, foreign
        self.image_arch, self.architecture = image_arch, architecture
        self.calls, self.containers, self.networks = [], {}, {}
        self.bridge = {"Id": "e" * 64, "Name": "bridge"}
        self.adapter = {"success": False, "result": {"success": True},
                        "resource_error": "offline resource rejection", "mode_policies": {"x": "y"}}
        self.ps_calls = 0

    def __call__(self, *arguments, timeout=120):
        args = list(arguments)
        self.calls.append(args)
        if self.fail and self.fail(args):
            raise RuntimeError("offline injected Docker failure")
        if args[0] == "info":
            return json.dumps({"OSType": "linux", "Architecture": self.architecture, "NCPU": self.ncpu})
        if args[:2] == ["image", "inspect"]:
            return json.dumps([{"Id": IMAGE, "Os": "linux", "Architecture": self.image_arch}])
        if args[:2] == ["ps", "-q"]:
            self.ps_calls += 1
            ids = [cid for cid, value in self.containers.items() if value["State"]["Running"]]
            if self.foreign and self.ps_calls > 1:
                unknown = "f" * 64
                self.containers[unknown] = {"Id": unknown, "Name": "/foreign", "Image": IMAGE,
                    "State": {"Status": "running", "Running": True},
                    "Config": {"Labels": {}}, "HostConfig": {"CpusetCpus": "0"}}
                ids.append(unknown)
            return "\n".join(ids)
        if args[:2] == ["network", "create"]:
            cid = f"{100 + len(self.networks):064x}"
            self.networks[cid] = {"Id": cid, "Name": args[-1],
                "IPAM": {"Config": [{"Subnet": f"172.28.{len(self.networks)}.0/24"}]}}
            return cid
        if args[:2] == ["network", "inspect"]:
            return json.dumps([self.bridge if args[2] == "bridge" else self.networks[args[2]]])
        if args[0] == "run" and "--rm" in args:
            return json.dumps(list(range(self.ncpu)))
        if args[0] in {"run", "create"}:
            cid = f"{200 + len(self.containers):064x}"
            network = self.networks[option(args, "--network")]
            network_index = int(network["IPAM"]["Config"][0]["Subnet"].split(".")[2])
            labels = dict(value.split("=", 1) for value in options(args, "--label"))
            self.containers[cid] = {"Id": cid, "Name": "/" + option(args, "--name"), "Image": IMAGE,
                "Config": {"Labels": labels}, "HostConfig": {"CpusetCpus": option(args, "--cpuset-cpus")},
                "State": {"Status": "running" if args[0] == "run" else "created", "Running": args[0] == "run"},
                "NetworkSettings": {"Networks": {network["Name"]: {
                    "IPAddress": f"172.28.{network_index}.2", "EndpointID": f"{300 + len(self.containers):064x}"}}}}
            return cid
        if args[:2] == ["network", "connect"]:
            self.containers[args[-1]]["NetworkSettings"]["Networks"]["bridge"] = {
                "IPAddress": "172.17.0.2", "EndpointID": f"{400 + len(self.containers):064x}"}
            return ""
        if args[:2] == ["container", "inspect"]:
            return json.dumps([self.containers[cid] for cid in args[2:]])
        if args[0] == "start":
            self.containers[args[1]]["State"] = {"Status": "running", "Running": True}
            return args[1]
        if args[0] == "exec":
            return json.dumps(self.adapter) if "_capture" in args else ""
        if args[0] == "rm":
            self.containers.pop(args[-1], None)
            return ""
        if args[:2] == ["network", "rm"]:
            self.networks.pop(args[-1], None)
            return ""
        raise AssertionError(f"unexpected mock Docker operation: {args[0:2]}")


@pytest.fixture
def backend(tmp_path, monkeypatch):
    @contextmanager
    def lock():
        yield
    monkeypatch.setattr(runtime, "docker_lock", lock)
    monkeypatch.setattr(runtime.os, "fsync", lambda _fd: None)
    monkeypatch.setattr(StudyStore, "enrolled", lambda self: [{"hostname": "assets.example.org"}])
    monkeypatch.setattr(runtime, "public_ipv4", lambda hostname: {
        "hostname": hostname, "addresses": ["8.8.8.8"], "selected_ipv4": "8.8.8.8"})
    (tmp_path / "study.json").write_bytes(b"{}\n")
    return tmp_path


@pytest.mark.parametrize("workers,ncpu", [(2, 6), (4, 9)])
def test_launch_has_actual_disjoint_peer_partitions_and_minimum_privileges(backend, monkeypatch, workers, ncpu):
    docker = Docker(ncpu)
    monkeypatch.setattr(runtime, "_docker", docker)
    with runtime.CaptureRuntime(backend, RUNTIME, workers) as flight:
        assert len(flight.workers) == workers
        declared = []
        for worker in flight.workers:
            receipt = json.loads((worker["lane"] / "partition.json").read_bytes())
            assert scheduler._host_partition_peer_valid(receipt)
            assert receipt["peer_contract"] == scheduler.RESOURCE_STUDY_PEER_HOST_PARTITION_CONTRACT
            assert receipt["available_cpus"] == list(range(ncpu))
            declared = receipt["declared_workers"]
            assert len(declared) == workers
            assert worker["partition_sha256"] == sha256_file(worker["lane"] / "partition.json")
            assert worker["lane"].joinpath("observer").stat().st_mode & 0o7777 == 0o2770
        protected = {cpu for item in declared for cpu in (item["client_cpu"], item["orchestrator_cpu"])}
        assert len(protected) == workers * 2
        residual = set(range(ncpu)) - protected
        for args in docker.calls:
            if args[0] == "run" and "--rm" not in args:
                assert {int(cpu) for cpu in option(args, "--cpuset-cpus").split(",")} == residual
                assert set(options(args, "--cap-add")) == {"NET_ADMIN", "NET_RAW"}
                assert "QCSD_KERNEL_TX_ROUTER_CAPTURE_MAX_SECONDS=740" in options(args, "--env")
                assert "org.qcsd.study=resource-study" in options(args, "--label")
            if args[0] == "create":
                assert option(args, "--ulimit") == "rtprio=1:1"
                assert option(args, "--entrypoint") == "/usr/bin/tini"
                assert "--privileged" not in args and "SYS_NICE" not in options(args, "--cap-add")
                assert set(options(args, "--cap-add")) == {"NET_ADMIN", "NET_RAW", "SETUID", "SETGID", "SETPCAP"}
                assert "org.qcsd.study=resource-study" in options(args, "--label")
                assert any("--pid --cpu-list" in arg and "ORCHESTRATOR_CPU" in arg for arg in args)
                environment = dict(value.split("=", 1) for value in options(args, "--env"))
                assert environment["QCSD_LAB_ROOT"] == "/runtime-src"
                for field in (kernel.KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_ENV,
                              kernel.KERNEL_TX_CONTROLLED_OBSERVER_BINDING_ENV):
                    raw = base64.b64decode(environment[field], validate=True)
                    assert raw == kernel._canonical_json(json.loads(raw))
                assert environment["QCSD_CAPTURE_SCHEDULER_CONTRACT"] == scheduler.PORTABLE_ETF_SCHEDULER_CONTRACT_V4
                assert "assets.example.org:8.8.8.8" in options(args, "--add-host")
    assert not docker.containers and not docker.networks
    closed = json.loads((flight.flight / "closed.json").read_bytes())
    assert closed["cleanup_errors"] == [] and closed["scientific_credit"] is False


@pytest.mark.parametrize("workers,ncpu", [(True, 6), (0, 6), (1, 6), (-1, 6), (2, 4), (4, 8)])
def test_capacity_and_worker_shape_refused_before_any_container_birth(backend, monkeypatch, workers, ncpu):
    docker = Docker(ncpu)
    monkeypatch.setattr(runtime, "_docker", docker)
    with pytest.raises(ValueError):
        with runtime.CaptureRuntime(backend, RUNTIME, workers):
            pass
    assert not any(args[0] == "create" or args[0] == "run" and "--rm" not in args
                   for args in docker.calls)


@pytest.mark.parametrize("failure", ["connect", "worker", "partition", "start"])
def test_failure_after_router_birth_reclaims_exact_created_resources(backend, monkeypatch, failure):
    def fail(args):
        return ((failure == "connect" and args[:2] == ["network", "connect"])
                or (failure == "worker" and args[0] == "create")
                or (failure == "partition" and args[:2] == ["container", "inspect"] and len(args) > 3)
                or (failure == "start" and args[0] == "start"))
    docker = Docker(fail=fail)
    monkeypatch.setattr(runtime, "_docker", docker)
    with pytest.raises(RuntimeError, match="offline injected"):
        with runtime.CaptureRuntime(backend, RUNTIME, 2):
            pass
    assert not docker.containers and not docker.networks
    assert any(args[0] == "rm" for args in docker.calls)


def test_foreign_container_born_during_setup_is_in_final_peer_inventory(backend, monkeypatch):
    docker = Docker(foreign=True)
    monkeypatch.setattr(runtime, "_docker", docker)
    with pytest.raises(ValueError):
        with runtime.CaptureRuntime(backend, RUNTIME, 2):
            pass
    assert docker.ps_calls >= 2
    assert list(docker.containers) == ["f" * 64]
    assert not docker.networks


@pytest.mark.parametrize("architecture,platform,image_arch", [
    ("x86_64", "linux/amd64", "arm64"), ("aarch64", "linux/arm64", "amd64"),
    ("x86_64", "linux/arm64", "amd64")])
def test_daemon_and_actual_image_architecture_must_both_match(monkeypatch, architecture, platform, image_arch):
    monkeypatch.setattr(runtime, "_docker", Docker(architecture=architecture, image_arch=image_arch))
    with pytest.raises(ValueError):
        runtime._runtime_check({**RUNTIME, "platform": platform})


def test_adapter_outer_failure_overrides_inner_success_and_drops_native_privileges(backend, monkeypatch):
    docker = Docker()
    monkeypatch.setattr(runtime, "_docker", docker)
    with runtime.CaptureRuntime(backend, RUNTIME, 2) as flight:
        attempt = {"path": "attempts/example", "hostname": "assets.example.org", "mode": "undefended",
                   "attempt_id": "d" * 64}
        (backend / attempt["path"]).mkdir(parents=True)
        result = flight.capture(0, attempt, {"preparation_dir": "enrollment/prepared"})
        assert result["success"] is False
        assert result["resource_error"] == "offline resource rejection"
        args = next(args for args in docker.calls if "_capture" in args)
        assert option(args, "--reuid") == str(runtime.os.getuid())
        assert option(args, "--regid") == str(runtime.os.getgid())
        assert "--clear-groups" in args and "--no-new-privs" in args
        assert "--bounding-set=-all,+net_raw,+net_admin,+setpcap" in args
        assert "--inh-caps=+net_raw,+net_admin,+setpcap" in args
        assert "--ambient-caps=+net_raw,+net_admin,+setpcap" in args
        assert "--user" not in args  # UID/cap transition occurs via setpriv.
        worker_args = next(call for call in docker.calls if call[0] == "create")
        for key, value in (item.split("=", 1) for item in options(worker_args, "--env")):
            monkeypatch.setenv(key, value)
        monkeypatch.setenv(scheduler.CAPTURE_SCHEDULER_HOST_SHA256_ENV, flight.workers[0]["partition_sha256"])
        helper_cpu = flight.workers[0]["helper"]
        monkeypatch.setattr(scheduler.os, "sched_getaffinity", lambda _pid: {helper_cpu})
        monkeypatch.setattr(scheduler.resource, "getrlimit", lambda _which: (1, 1))
        prefix = scheduler.capture_scheduler_launch_prefix()
        assert "--bounding-set=-all,+net_admin,+setpcap" in prefix
        assert "--inh-caps=-all,+net_admin,+setpcap" in prefix
        assert "--ambient-caps=-all,+net_admin,+setpcap" in prefix
        assert prefix[0:3] == ["/usr/bin/taskset", "--cpu-list", "1"]
        assert prefix[3:6] == ["/usr/bin/chrt", "--rr", "1"]


def state(root, maximum=300):
    return router.CaptureState(root=root, secret="a" * 64, interface="eth0",
        topology_kind="routed-public-egress", uplink_interface="eth1",
        client_subnet="172.28.0.0/24", require_masquerade=True,
        max_duration_seconds=maximum)


def start_request(duration):
    return {"schema_version": 1, "action": "start", "secret": "a" * 64,
            "capture_id": "b" * 64, "duration_seconds": duration, "max_megabytes": 256}


@pytest.mark.parametrize("maximum,duration", [(300, 740), (740, 741), (740, True), (740, 740.0), (740, 0)])
def test_router_duration_contract_refuses_before_dumpcap(maximum, duration, tmp_path, monkeypatch):
    def unexpected(*_args, **_kwargs):
        pytest.fail("invalid bound must not birth dumpcap")
    monkeypatch.setattr(router.subprocess, "Popen", unexpected)
    with pytest.raises(ValueError, match="bounds/state"):
        state(tmp_path, maximum).start(start_request(duration))


@pytest.mark.parametrize("maximum", [True, 300.0, "740", 741, 0, None])
def test_router_maximum_is_explicit_and_typed(tmp_path, maximum):
    with pytest.raises(ValueError, match="maximum duration"):
        state(tmp_path, maximum)


def test_prospective_router_starts_real_command_with_finite740_bound(tmp_path, monkeypatch):
    observed = []
    def birth(argv, **kwargs):
        observed.append(argv)
        Path(option(argv, "-w")).write_bytes(b"offline pcap header")
        kwargs["stdout"].write("Capturing on eth0\n")
        kwargs["stdout"].flush()
        return SimpleNamespace(poll=lambda: None)
    monkeypatch.setattr(router.subprocess, "Popen", birth)
    monkeypatch.setattr(router.time, "sleep", lambda _seconds: None)
    value = state(tmp_path, 740)
    monkeypatch.setattr(value, "_router_state", lambda **kwargs: {"capture_process_state": kwargs["capture_process_state"]})
    value.start(start_request(740))
    assert "duration:740" in observed[0] and "filesize:262144" in observed[0]
    assert value.capture_id == "b" * 64
    value.log_handle.close()


def test_preparation_uses_host_uid_without_capabilities_and_freezes_only_new_files(backend, monkeypatch):
    calls = []
    inspection = Docker()
    def docker(*args, **kwargs):
        calls.append(list(args))
        if args[0] != "run":
            return inspection(*args, **kwargs)
        job = json.loads(Path(option(args, "--job")).read_bytes())
        prepared = Path(job["output"])
        prepared.mkdir()
        manifest = prepared / "resources.json"
        manifest.write_bytes(b'{"resources":[]}\n')
        return json.dumps({"hostname": "assets.example.org", "urls": job["urls"],
            "workload_path": str(manifest), "workload_sha256": sha256_file(manifest),
            "paths": {"manifest": str(manifest), "chaff_manifest": None},
            "files": {"resources.json": sha256_file(manifest)},
            "runtime": RUNTIME, "scientific_credit": False})
    monkeypatch.setattr(runtime, "_docker", docker)
    output = backend / "enrollment-attempts/one"
    result = runtime.PreparationRuntime(backend, RUNTIME).prepare({
        "hostname": "assets.example.org", "urls": [f"https://assets.example.org/{i}" for i in range(20)],
        "source_occurrences": [{"source_index": 1}]}, output)
    args = next(args for args in calls if args[0] == "run")
    assert option(args, "--user") == f"{runtime.os.getuid()}:{runtime.os.getgid()}"
    assert option(args, "--cap-drop") == "ALL" and "--cap-add" not in args
    assert "no-new-privileges" in args and "_prepare" in args
    assert "QCSD_LAB_ROOT=/runtime-src" in options(args, "--env")
    assert "QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json" in options(args, "--env")
    assert result["paths"]["chaff_manifest"] is None
    assert not Path(result["workload_path"]).is_absolute()
    assert result["source_occurrences"] == [{"source_index": 1}]
    assert (backend / result["workload_path"]).stat().st_mode & 0o7777 == 0o444
    assert result["scientific_credit"] is False


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.1.2", "::1"])
def test_origin_pins_refuse_private_or_local_dns_answers(monkeypatch, address):
    monkeypatch.setattr(runtime.socket, "getaddrinfo", lambda *_a, **_k: [
        (2, 2, 17, "", ("8.8.8.8", 443)), (2, 2, 17, "", (address, 443))])
    with pytest.raises(ValueError, match="public"):
        runtime.public_ipv4("assets.example.org")


@pytest.mark.parametrize("setting,expected", [(None, 300), ("300", 300), ("740", 740), ("0740", None), ("741", None)])
def test_router_service_env_selects_explicit_prospective_bound(tmp_path, monkeypatch, setting, expected):
    monkeypatch.setenv("QCSD_KERNEL_TX_ROUTER_CAPTURE_ROOT", str(tmp_path))
    monkeypatch.setenv("QCSD_KERNEL_TX_ROUTER_CAPTURE_SECRET", "a" * 64)
    monkeypatch.setenv("QCSD_KERNEL_TX_ROUTER_TOPOLOGY_KIND", "shared-two-network-router")
    monkeypatch.delenv("QCSD_KERNEL_TX_ROUTER_CLIENT_SUBNET", raising=False)
    monkeypatch.delenv("QCSD_KERNEL_TX_ROUTER_REQUIRE_MASQUERADE", raising=False)
    if setting is None:
        monkeypatch.delenv("QCSD_KERNEL_TX_ROUTER_CAPTURE_MAX_SECONDS", raising=False)
    else:
        monkeypatch.setenv("QCSD_KERNEL_TX_ROUTER_CAPTURE_MAX_SECONDS", setting)
    observed = []
    class Server:
        def __init__(self, address, state):
            observed.append((address, state.max_duration_seconds))
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def serve_forever(self, **kwargs):
            pass
    monkeypatch.setattr(router, "_CaptureServer", Server)
    if expected is None:
        with pytest.raises(SystemExit, match="maximum duration"):
            router.main()
        assert not observed
    else:
        router.main()
        assert observed == [(('0.0.0.0', 19090), expected)]
