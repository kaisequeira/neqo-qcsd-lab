"""Native Linux Docker runtime for resource enrollment and protected capture lanes.

The SDK is installed in the immutable image. Only the new study directory is
writable. Each class has a frozen pre-NAT address and authenticated observer;
CPU workers attach to that class between hostname chunks.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import time
from typing import Any

from .resource_study_inputs import canonical_json, sha256_file
from .resource_study_verify import load
from .resource_study_network import (ATTACHMENT_RECORD, check_collisions, mapping_sha256,
                                     receipt_binding, validate_network_plan)

SCHEDULER = "qcsd-client-rr1-portable-etf-helper-v4"


def _docker(*args: str, timeout=120) -> str:
    try:
        result = subprocess.run(["docker", *map(str, args)], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Docker operation exceeded its bounded runtime") from error
    if result.returncode:
        # Avoid echoing argv/environment; router credentials must stay private.
        raise RuntimeError("Docker operation failed: " + result.stderr[-2000:].strip())
    return result.stdout.strip()


def _put(path: Path, value: Any):
    from .resource_study import create_json
    create_json(path, value)


def _encoded(value):
    return base64.b64encode(canonical_json(value).rstrip(b"\n")).decode("ascii")


def public_ipv4(hostname: str) -> dict:
    answers = socket.getaddrinfo(hostname, 443, type=socket.SOCK_DGRAM)
    addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("resource hostname must resolve only to public addresses")
    selected = next((a for a in addresses if ipaddress.ip_address(a).version == 4), None)
    if selected is None:
        raise ValueError("current routed capture requires a public IPv4 endpoint")
    return {"hostname": hostname, "addresses": addresses, "selected_ipv4": selected,
            "observed_at_unix_ns": time.time_ns(), "capture_position": "client-eth0-before-nat"}


@contextmanager
def docker_lock():
    directory = Path.home() / ".cache/qcsd-resource-study"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (directory / "docker.lock").open("a+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another resource-study Docker lifecycle is active") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _runtime_check(runtime: dict):
    image = runtime["collection_image_digest"]
    info = json.loads(_docker("info", "--format", "{{json .}}"))
    architecture = {"x86_64": "amd64", "aarch64": "arm64", "amd64": "amd64", "arm64": "arm64"}
    if (info.get("OSType") != "linux"
            or "linux/" + architecture.get(info.get("Architecture"), "unknown") != runtime["platform"]):
        raise ValueError("capture requires the selected native Linux Docker architecture")
    observed = json.loads(_docker("image", "inspect", image))[0]
    if (observed["Id"] != image or observed.get("Os") != "linux"
            or "linux/" + observed.get("Architecture", "unknown") != runtime["platform"]):
        raise ValueError("runtime image identity changed")
    return info


def _host_routes():
    completed = subprocess.run(["ip", "-j", "-4", "route", "show", "table", "all"],
                               capture_output=True, text=True, timeout=30)
    if completed.returncode:
        raise RuntimeError("cannot inspect host routes for class subnet collisions")
    routes = json.loads(completed.stdout)
    if not isinstance(routes, list) or any(not isinstance(row, dict) for row in routes):
        raise ValueError("host route collision inventory is malformed")
    return routes


class PreparationRuntime:
    def __init__(self, root: Path, runtime: dict):
        self.root, self.runtime = root.absolute(), runtime

    def prepare(self, candidate: dict, output: Path) -> dict:
        output.mkdir(parents=True, exist_ok=False)
        dns = public_ipv4(candidate["hostname"])
        _put(output / "dns.json", dns)
        job = {"hostname": candidate["hostname"], "urls": candidate["urls"],
               "output": str(output / "prepared"), "runtime": self.runtime}
        _put(output / "job.json", job)
        with docker_lock():
            _runtime_check(self.runtime)
            result = _docker("run", "--rm", "--network", "bridge", "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL",
                "--env", "QCSD_LAB_ROOT=/runtime-src", "--env", "QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json",
                "--security-opt", "no-new-privileges", "--add-host", candidate["hostname"] + ":" + dns["selected_ipv4"],
                "--mount", f"type=bind,src={self.root},dst={self.root}",
                "--entrypoint", "/opt/qcsd-venv/bin/python3", self.runtime["collection_image_digest"],
                "-I", "-B", "-m", "qcsd_lab.resource_study_native", "_prepare", "--job", str(output / "job.json"),
                timeout=max(600, len(candidate["urls"]) * 125 + 600))
        _put(output / "result.json", json.loads(result.splitlines()[-1]))
        enrollment = load(output / "result.json")
        enrollment["workload_path"] = Path(enrollment["workload_path"]).relative_to(self.root).as_posix()
        enrollment["paths"] = {key: Path(value).relative_to(self.root).as_posix() if value else None
                               for key, value in enrollment["paths"].items()}
        enrollment["preparation_dir"] = (output / "prepared").relative_to(self.root).as_posix()
        enrollment["files"] = {(output / "prepared" / relative).relative_to(self.root).as_posix(): digest
                               for relative, digest in enrollment["files"].items()}
        enrollment["files"][(output / "dns.json").relative_to(self.root).as_posix()] = sha256_file(output / "dns.json")
        enrollment["source_occurrences"] = candidate.get("source_occurrences", [])
        for relative in enrollment["files"]:
            (self.root / relative).chmod(0o444)
        return enrollment


def topology_receipts(image, network_name, network, subnet, router_name, router, bridge):
    """Bind inspected IDs and interfaces to the existing observer protocol."""
    client_endpoint = router["NetworkSettings"]["Networks"][network_name]
    uplink = router["NetworkSettings"]["Networks"]["bridge"]
    router_ip = client_endpoint["IPAddress"]
    network_receipt = {"schema_version": 1, "artifact_type": "qcsd-kernel-tx-public-network-v1",
        "image_digest": image, "topology": {"kind": "routed-public-egress",
            "client_network": {"name": network_name, "subnet": subnet}, "uplink_network": {"name": "bridge"},
            "router_interfaces": {"client": "eth0", "uplink": "eth1"}},
        "capture_point": {"client_to_server_position": "before-router-eth0-forwarding-and-masquerade"},
        "client": {"network": network_name, "default_route_via": router_ip},
        "router": {"container": router_name, "client_ipv4": router_ip, "client_interface": "eth0",
                   "uplink_interface": "eth1", "ipv4_forwarding": True, "source_masquerade": True},
        "directional_coverage": {"client_to_server": {"capture_position": "before-forwarding", "nat_position": "after-capture"}},
        "observation_contract": {"client_only": True, "ordinary_public_origins": True}}
    binding = {"schema_version": 1, "artifact_type": "qcsd-kernel-tx-public-observer-binding",
        "topology_kind": "routed-public-egress", "image_digest": router["Image"],
        "observer": {"role": "router-ingress-post-client-veth-pre-netem", "container_name": router_name,
            "container_id": router["Id"], "interface": "eth0", "interface_direction": "ingress", "ipv4": router_ip},
        "client_network": {"name": network_name, "id": network["Id"], "router_endpoint_id": client_endpoint["EndpointID"]},
        "uplink_network": {"name": "bridge", "id": bridge["Id"], "router_endpoint_id": uplink["EndpointID"]},
        "observed_direction": "client-to-public-origin",
        "capture_position": "router-eth0-ingress-after-client-veth-before-forwarding-and-masquerade"}
    return router_ip, network_receipt, binding


class CaptureRuntime:
    def __init__(self, root: Path, runtime: dict, workers: int, *, hostnames=None):
        if type(workers) is not int or workers < 2:
            raise ValueError("resource capture requires at least two declared workers")
        self.root, self.runtime, self.count = root.absolute(), runtime, workers
        self.selected_hostnames = None if hostnames is None else set(hostnames)
        self.containers, self.networks, self.workers = [], [], []
        self.class_routes, self.class_owners = {}, {}
        self.switch_lock = threading.RLock()
        self.closed = False

    def __enter__(self):
        self.lock = docker_lock()
        self.lock.__enter__()
        try:
            self.plan = load(self.root / "study.json")
            assignments = validate_network_plan(self.plan, require=True)
            self.study_sha256 = sha256_file(self.root / "study.json")
            info = _runtime_check(self.runtime)
            ncpu = int(info["NCPU"])
            available = json.loads(_docker("run", "--rm", "--network", "none", "--cap-drop", "ALL",
                "--entrypoint", "/opt/qcsd-venv/bin/python3", self.runtime["collection_image_digest"],
                "-I", "-c", "import json,os;print(json.dumps(sorted(os.sched_getaffinity(0))))"))
            if (not isinstance(available, list) or any(type(cpu) is not int or cpu < 0 for cpu in available)
                    or available != sorted(set(available)) or not available or max(available) >= ncpu):
                raise ValueError("Docker affinity probe did not report the actual CPU set")
            if len(available) < 2 * self.count + 1:
                raise ValueError(f"{self.count} protected workers need {2*self.count+1} available logical CPUs")
            if _docker("ps", "-q"):
                raise ValueError("capacity launch requires no unaccounted running containers")
            existing_ids = _docker("network", "ls", "-q").splitlines()
            existing = json.loads(_docker("network", "inspect", *existing_ids)) if existing_ids else []
            collision = check_collisions(self.plan, existing, _host_routes())
            self.flight = self.root / "flights" / secrets.token_hex(12)
            self.flight.mkdir(parents=True)
            _put(self.flight / "collision-check.json", collision)
            image = self.runtime["collection_image_digest"]
            positive = [cpu for cpu in available if cpu >= 1]
            pairs = [(positive[2*i], positive[2*i+1]) for i in range(self.count)]
            sidecars = sorted(set(available) - {cpu for pair in pairs for cpu in pair})
            sidecar_cpuset = ",".join(map(str, sidecars))
            bridge = json.loads(_docker("network", "inspect", "bridge"))[0]
            from .resource_study_store import StudyStore
            domains = [e["hostname"] for e in StudyStore(self.root).enrolled()
                       if self.selected_hostnames is None or e["hostname"] in self.selected_hostnames]
            if not domains:
                raise ValueError("capture topology requires selected enrolled classes")
            if any(host not in assignments for host in domains):
                raise ValueError("enrolled class has no frozen network identity")
            pins = [public_ipv4(host) for host in domains]
            _put(self.flight / "dns.json", {"hosts": pins})
            declared, sidecar_ids = [], {}
            observers = self.flight / "observers"
            observers.mkdir()
            for index, hostname in enumerate(sorted(domains)):
                assignment = assignments[hostname]
                prefix = "qcsd-resource-" + self.flight.name + "-class-" + str(index)
                class_directory = self.flight / "classes" / hostname
                class_directory.mkdir(parents=True)
                capture_root = observers / hostname
                capture_root.mkdir(mode=0o2770)
                capture_root.chmod(0o2770)
                network_id = _docker("network", "create", "--driver", "bridge",
                    "--subnet", assignment["subnet"], "--gateway", assignment["gateway_ipv4"],
                    "--label", "org.qcsd.owner=qcsd-lab", "--label", "org.qcsd.class=" + hostname, prefix)
                self.networks.append(network_id)
                network = json.loads(_docker("network", "inspect", network_id))[0]
                subnet = network["IPAM"]["Config"][0]["Subnet"]
                if subnet != assignment["subnet"] or network["IPAM"]["Config"][0].get("Gateway") != assignment["gateway_ipv4"]:
                    raise ValueError("Docker changed a frozen class subnet or bridge gateway")
                secret = secrets.token_hex(32)
                router_env = {"QCSD_KERNEL_TX_ROUTER_CAPTURE_ROOT": "/kernel-tx", "QCSD_KERNEL_TX_ROUTER_CAPTURE_SECRET": secret,
                    "QCSD_KERNEL_TX_ROUTER_CAPTURE_INTERFACE": "eth0", "QCSD_KERNEL_TX_ROUTER_CAPTURE_PORT": "19090",
                    "QCSD_KERNEL_TX_ROUTER_CAPTURE_MAX_SECONDS": "740",
                    "QCSD_KERNEL_TX_ROUTER_TOPOLOGY_KIND": "routed-public-egress", "QCSD_KERNEL_TX_ROUTER_UPLINK_INTERFACE": "eth1",
                    "QCSD_KERNEL_TX_ROUTER_CLIENT_SUBNET": subnet, "QCSD_KERNEL_TX_ROUTER_REQUIRE_MASQUERADE": "1"}
                router_args = ["create", "--name", prefix + "-router", "--network", network_id,
                    "--ip", assignment["router_ipv4"], "--cpuset-cpus", sidecar_cpuset,
                    "--group-add", str(os.getgid()), "--label", "org.qcsd.owner=qcsd-lab", "--label", "org.qcsd.role=network-router",
                    "--label", "org.qcsd.study=resource-study",
                    "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--security-opt", "no-new-privileges",
                    "--sysctl", "net.ipv4.ip_forward=1", "--mount", f"type=bind,src={capture_root},dst=/kernel-tx",
                    "--entrypoint", "/opt/qcsd-venv/bin/python3"]
                for key, value in router_env.items():
                    router_args += ["--env", key + "=" + value]
                router_id = _docker(*router_args, image, "-I", "-m", "qcsd_lab.kernel_capture_router")
                self.containers.append(router_id)
                sidecar_ids[prefix + "-router"] = router_id
                _docker("start", router_id)
                _docker("network", "connect", "--gw-priority", "1", "bridge", router_id)
                _docker("exec", router_id, "/bin/sh", "-eu", "-c",
                    'ethtool -K eth0 gro off gso off tso off tx-udp-segmentation off; '
                    'ethtool -K eth1 gro off gso off tso off tx-udp-segmentation off; '
                    'iptables -t nat -A POSTROUTING -s "$1" -o eth1 -j MASQUERADE', "sh", subnet)
                router = json.loads(_docker("container", "inspect", router_id))[0]
                router_ip, net_receipt, binding = topology_receipts(image, prefix, network, subnet, prefix + "-router", router, bridge)
                if router_ip != assignment["router_ipv4"]:
                    raise ValueError("Docker changed the persistent class router address")
                _put(class_directory / "network.json", net_receipt)
                _put(class_directory / "observer.json", binding)
                _put(class_directory / "assignment.json", receipt_binding(self.plan, self.study_sha256, hostname))
                environment = {"QCSD_CONTROLLED_ROUTER_CLIENT_IP": router_ip, "QCSD_KERNEL_TX_PUBLIC_ROUTER_IP": router_ip,
                    "QCSD_KERNEL_TX_PUBLIC_CLIENT_SUBNET": subnet,
                    "QCSD_KERNEL_TX_POST_VETH_CAPTURE_ENDPOINT": router_ip + ":19090",
                    "QCSD_KERNEL_TX_POST_VETH_CAPTURE_SECRET": secret,
                    "QCSD_KERNEL_TX_POST_VETH_CAPTURE_ROOT": "/kernel-tx/" + hostname,
                    "QCSD_KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_B64": _encoded(net_receipt),
                    "QCSD_KERNEL_TX_CONTROLLED_OBSERVER_BINDING_B64": _encoded(binding)}
                self.class_routes[hostname] = {"network_id": network_id, "name": prefix,
                    "router_id": router_id, "assignment": assignment, "environment": environment,
                    "network": net_receipt, "observer": binding}
            for index, (client_cpu, helper_cpu) in enumerate(pairs):
                prefix = "qcsd-resource-" + self.flight.name + "-lane-" + str(index)
                lane = self.flight / str(index)
                lane.mkdir()
                wireshark_config = lane / "wireshark-config"
                wireshark_config.mkdir(mode=0o700)
                env = {"QCSD_CAPTURE_SCHEDULER_CONTRACT": SCHEDULER, "QCSD_CAPTURE_CLIENT_CPU": str(client_cpu),
                    "QCSD_CAPTURE_ORCHESTRATOR_CPU": str(helper_cpu), "QCSD_CAPTURE_ETF_INTERFACE": "eth0",
                    "QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_FILE": str(lane / "partition.json"),
                    "QCSD_LAB_IMAGE_DIGEST": image, "QCSD_LAB_SOURCE_METADATA": "/usr/share/qcsd-lab/source.json",
                    "QCSD_LAB_ROOT": "/runtime-src",
                    "WIRESHARK_CONFIG_DIR": str(wireshark_config),
                    "XDG_CONFIG_HOME": str(wireshark_config)}
                args = ["create", "--name", prefix + "-worker", "--network", "bridge",
                    "--cpuset-cpus", f"{client_cpu},{helper_cpu}", "--ulimit", "rtprio=1:1",
                    "--label", "org.qcsd.owner=qcsd-lab", "--label", "org.qcsd.role=resource-study-worker",
                    "--label", "org.qcsd.study=resource-study",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--group-add", str(os.getgid()),
                    "--mount", f"type=bind,src={self.root},dst={self.root}",
                    "--entrypoint", "/usr/bin/tini"]
                for hostname in sorted(domains):
                    args += ["--mount", f"type=bind,src={observers / hostname},dst=/kernel-tx/{hostname},readonly"]
                for capability in ("NET_ADMIN", "NET_RAW", "SETUID", "SETGID", "SETPCAP"):
                    args += ["--cap-add", capability]
                for key, value in env.items():
                    args += ["--env", key + "=" + value]
                for pin in pins:
                    args += ["--add-host", pin["hostname"] + ":" + pin["selected_ipv4"]]
                args += [image, "--", "/bin/sh", "-eu", "-c",
                    '/usr/bin/taskset --pid --cpu-list "${QCSD_CAPTURE_ORCHESTRATOR_CPU}" 1 >/dev/null; '
                    'exec /usr/bin/taskset --cpu-list "${QCSD_CAPTURE_ORCHESTRATOR_CPU}" /bin/sleep infinity']
                worker_id = _docker(*args)
                self.containers.append(worker_id)
                self.workers.append({"id": worker_id, "helper": helper_cpu, "lane": lane,
                    "initial_bridge": True, "hostname": None, "attachment_number": 0})
                declared.append({"id": worker_id, "name": prefix + "-worker", "image_id": image,
                                 "client_cpu": client_cpu, "orchestrator_cpu": helper_cpu})
            running = _docker("ps", "-q").splitlines()
            inventory_ids = list(dict.fromkeys([*running, *(w["id"] for w in self.workers)]))
            inspected = json.loads(_docker("container", "inspect", *inventory_ids))
            from .process_scheduler import build_peer_host_partition
            for worker in self.workers:
                partition = build_peer_host_partition(inspected, available, declared, sidecar_ids, worker["id"],
                    docker_ncpu=ncpu, resource_study=True)
                _put(worker["lane"] / "partition.json", partition)
                worker["partition_sha256"] = sha256_file(worker["lane"] / "partition.json")
                _docker("start", worker["id"])
            _put(self.flight / "launched.json", {"workers": declared, "sidecars": sidecar_ids,
                "runtime": self.runtime, "available_cpus": available, "study_sha256": self.study_sha256,
                "class_mapping_sha256": mapping_sha256(self.plan), "scientific_credit": False})
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _activate(self, index, hostname):
        with self.switch_lock:
            if sha256_file(self.root / "study.json") != self.study_sha256:
                raise ValueError("immutable class network plan changed before capture")
            if hostname not in self.class_routes:
                raise ValueError("class has no enrolled topology in this flight")
            worker = self.workers[index]
            attached = worker["hostname"] == hostname
            if not attached and (worker["hostname"] is not None or hostname in self.class_owners):
                raise ValueError("a class address or worker is already owned by an active hostname chunk")
            route = self.class_routes[hostname]
            assignment = route["assignment"]
            network = json.loads(_docker("network", "inspect", route["network_id"]))[0]
            router = json.loads(_docker("container", "inspect", route["router_id"]))[0]
            _, net_receipt, observer = topology_receipts(self.runtime["collection_image_digest"], route["name"],
                network, assignment["subnet"], route["network"]["router"]["container"], router,
                json.loads(_docker("network", "inspect", "bridge"))[0])
            if (network.get("Id") != route["network_id"] or network.get("Name") != route["name"]
                    or network["IPAM"]["Config"][0].get("Subnet") != assignment["subnet"]
                    or network["IPAM"]["Config"][0].get("Gateway") != assignment["gateway_ipv4"]
                    or net_receipt != route["network"] or observer != route["observer"]
                    or router.get("Id") != route["router_id"] or not router.get("State", {}).get("Running")):
                raise ValueError("persistent class network/router changed before capture")
            if not attached:
                if worker["initial_bridge"]:
                    _docker("network", "disconnect", "bridge", worker["id"])
                    worker["initial_bridge"] = False
                _docker("network", "connect", "--ip", assignment["client_ipv4"], route["network_id"], worker["id"])
                worker["hostname"] = hostname
                self.class_owners[hostname] = index
            inspected = json.loads(_docker("container", "inspect", worker["id"]))[0]
            networks = inspected["NetworkSettings"]["Networks"]
            endpoint = networks.get(route["name"], {})
            if (set(networks) != {route["name"]} or endpoint.get("IPAddress") != assignment["client_ipv4"]
                    or endpoint.get("Gateway") != assignment["gateway_ipv4"]
                    or endpoint.get("NetworkID") != route["network_id"] or not endpoint.get("EndpointID")):
                raise ValueError("worker has an aliased, foreign or changed class network endpoint")
            if not attached:
                _docker("exec", worker["id"], "/usr/sbin/ip", "-4", "route", "replace", "default",
                        "via", assignment["router_ipv4"], "dev", "eth0")
            addresses = json.loads(_docker("exec", worker["id"], "/usr/sbin/ip", "-j", "-4", "address", "show", "dev", "eth0"))
            defaults = json.loads(_docker("exec", worker["id"], "/usr/sbin/ip", "-j", "-4", "route", "show", "default"))
            from .resource_study_network import validate_client_route
            validate_client_route(assignment, addresses, defaults)
            worker["attachment_number"] += 1
            attachment = {"record_type": ATTACHMENT_RECORD, "hostname": hostname,
                "binding": receipt_binding(self.plan, self.study_sha256, hostname),
                "network": route["network"], "observer": route["observer"],
                "worker_container_id": worker["id"], "worker_endpoint": endpoint,
                "host_partition_sha256": worker["partition_sha256"],
                "interface_addresses": addresses, "default_routes": defaults,
                "collision_check": load(self.flight / "collision-check.json")}
            _put(worker["lane"] / "attachments" / f'{worker["attachment_number"]:06d}.json', attachment)
            worker["attachment"] = attachment
            return attachment

    def release(self, index):
        """Release a hostname only after its entire chunk has stopped."""
        with self.switch_lock:
            worker = self.workers[index]
            hostname = worker["hostname"]
            if hostname is not None:
                _docker("network", "disconnect", self.class_routes[hostname]["network_id"], worker["id"])
                worker["hostname"] = None
                del self.class_owners[hostname]
                worker.pop("attachment", None)

    def capture(self, index: int, attempt: dict, enrollment: dict) -> dict:
        worker = self.workers[index]
        attachment = self._activate(index, attempt["hostname"])
        directory = self.root / attempt["path"]
        job = {"hostname": attempt["hostname"], "mode": attempt["mode"],
               "enrollment_dir": str(self.root / enrollment["preparation_dir"]),
               "attempt_dir": str(directory / "capture"), "seed": int(attempt["attempt_id"][:16], 16),
               "runtime": self.runtime}
        _put(directory / "job.json", job)
        arguments = ["exec", "--env", "QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_SHA256=" + worker["partition_sha256"]]
        for key, value in self.class_routes[attempt["hostname"]]["environment"].items():
            arguments += ["--env", key + "=" + value]
        output = _docker(*arguments, worker["id"], "/usr/bin/taskset", "--cpu-list", str(worker["helper"]),
            "/usr/bin/setpriv", "--reuid", str(os.getuid()), "--regid", str(os.getgid()), "--clear-groups",
            "--bounding-set=-all,+net_raw,+net_admin,+setpcap", "--inh-caps=+net_raw,+net_admin,+setpcap",
            "--ambient-caps=+net_raw,+net_admin,+setpcap", "--no-new-privs",
            "/opt/qcsd-venv/bin/python3", "-I", "-B", "-m", "qcsd_lab.resource_study_native", "_capture",
            "--job", str(directory / "job.json"), timeout=850)
        result = json.loads(output.splitlines()[-1])
        _put(directory / "native-adapter.json", result)
        if (directory / "capture").is_dir():
            _put(directory / "capture/class-network.json", attachment)
        return {**result.get("result", result), "success": result.get("success") is True,
                "mode_policies": result.get("mode_policies", {}), "resource_error": result.get("resource_error")}

    def __exit__(self, *_):
        if self.closed:
            return
        self.closed = True
        failures = []
        for identifier in reversed(self.containers):
            try:
                _docker("rm", "--force", identifier)
            except RuntimeError as error:
                failures.append(str(error))
        for identifier in reversed(self.networks):
            try:
                _docker("network", "rm", identifier)
            except RuntimeError as error:
                failures.append(str(error))
        if hasattr(self, "flight"):
            _put(self.flight / "closed.json", {"containers_removed": self.containers,
                "networks_removed": self.networks, "cleanup_errors": failures, "scientific_credit": False})
        self.lock.__exit__(None, None, None)
        if failures:
            raise RuntimeError("capture topology cleanup needs recovery")
