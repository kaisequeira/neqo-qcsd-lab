"""Native Linux Docker runtime for resource enrollment and protected capture lanes.

The SDK is installed in the immutable image. Only the new study directory is
writable. Each class has a frozen pre-NAT address and authenticated observer;
CPU workers attach to that class between hostname chunks.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Mapping

from .resource_study_inputs import MODES, canonical_json, sha256_file
from .resource_study_verify import load
from .resource_study_network import (ATTACHMENT_RECORD, check_collisions, mapping_sha256,
                                     receipt_binding, validate_network_plan)

SCHEDULER = "qcsd-client-rr1-portable-etf-helper-v4"

# Initial shared-flight scope. A new launcher does not establish new runtime
# eligibility: every owning cell still needs its admitted definition and pilot.
SHARED_NATIVE = {
    "canonical_sha256": "b2d9f614dd6925b3b67a5c15708ff4d216d42e16f148df2bd1328756a633efb1",
    "client_sha256": "93b3440a9662da0cf5037a74080b4e04ec7a03231b9117b093e14ff3c5f57b9d",
    "platform": "linux/arm64",
    "native_commit": "ce1e8ef35283cf21ae72035e5d914cdf16587344",
    "collection_image_digest": "sha256:fee72a905cf2ba1661bc9bd2473443a6744e9a47e47b85f5c4c2d6c58506fe4a",
    "prepare_image_digest": "sha256:b8a6bc760399f43f8b59d5748c689723dcdd204243063dd11f380356e6930217",
}

# Same immutable Native122 capture producer; only the external coordinator
# pools already admitted writers. No new runtime or scientific eligibility.
BF122_SHARED_RUNTIME = {'canonical_sha256': 'd199cfc953317c38e9442b92a3a40ef0a8971ecf6c45bab12cc8a138950ae0da', 'client_sha256': '8c78c43f30053af6427ecf3511a938f6c5c30abe0a5a0043c4e37d9054b471f4', 'collection_image_digest': 'sha256:107c7e65c2f8e7d42396b14956b15739d98893ad0970df5d986263f23f304c6d', 'native_commit': '1e9db5f744b0123051f1fe98e6345e88e8b3a773', 'platform': 'linux/arm64', 'prepare_image_digest': 'sha256:c2bef434df5dbcc73a0b449dfa5e83a20044dc77c70222ef446884be24fbef52', 'source': {'image_digest': None, 'lab_commit': '9d2706f091699ee748aca2f5af7b9ba828ee2d64', 'lab_dirty': False, 'lab_patch_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'neqo_commit': '1e9db5f744b0123051f1fe98e6345e88e8b3a773', 'neqo_dirty': False, 'neqo_patch_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'neqo_pinned_commit': '1e9db5f744b0123051f1fe98e6345e88e8b3a773'}}
BF122_SHARED_ROOTS = tuple(
    "/mnt/lima-neqo-data/neqo-obfuscation/study/"
    "native122-source079-BuFLO-original50-runtime-cohort-" + f"{index:03d}"
    for index in range(1, 6)
)

# Source089 only adds a coordinator role for this already installed producer.
# The original Native122 and Native93 paths below retain their exact guards.
BF126_SHARED_RUNTIME = {'canonical_sha256': 'adb1c6d52a0dda65f301fde16f6d03af46fe7ec8f565412afc0c9026df566291', 'client_sha256': 'f7746e03426bf710c1e0a197ff2136789cc8a7aee32e66b34934f27a535ee058', 'native_commit': 'fc87393e3162bbf0562e64c8fb2f2ebe6b4d7cd9', 'platform': 'linux/arm64', 'collection_image_digest': 'sha256:489d25daf256bde2d82da45a1ec479b54e468858b5a3efc6bc7e53995cf5cc55', 'prepare_image_digest': 'sha256:f18f293c472667ea4cf94ffc297551d4848a4339f4c14fc0e60fa178fb36c48e', 'source': {'image_digest': None, 'lab_commit': 'be488d555b64c0479f180c90317146ca42b9c31a', 'lab_dirty': False, 'lab_patch_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'neqo_commit': 'fc87393e3162bbf0562e64c8fb2f2ebe6b4d7cd9', 'neqo_dirty': False, 'neqo_patch_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'neqo_pinned_commit': 'fc87393e3162bbf0562e64c8fb2f2ebe6b4d7cd9'}}
BF126_SHARED_ROOTS = tuple(
    "/mnt/lima-neqo-data/neqo-obfuscation/study/"
    "native126-source087-BuFLO-original50-runtime-cohort-" + f"{index:03d}"
    for index in range(1, 4)
)


def require_shared_runtime(runtime):
    if (type(runtime) is dict
            and runtime.get("native_commit") == BF126_SHARED_RUNTIME["native_commit"]):
        if runtime != BF126_SHARED_RUNTIME:
            raise ValueError("BuFLO126 pooling requires the exact unchanged full runtime")
        return True
    if (type(runtime) is dict
            and runtime.get("native_commit") == BF122_SHARED_RUNTIME["native_commit"]):
        if runtime != BF122_SHARED_RUNTIME:
            raise ValueError("BuFLO122 pooling requires the exact unchanged full runtime")
        return True
    if (type(runtime) is not dict or any(runtime.get(key) != value for key, value in SHARED_NATIVE.items())
            or type(runtime.get("source")) is not dict
            or runtime["source"].get("neqo_commit") != SHARED_NATIVE["native_commit"]):
        raise ValueError("two-root capture requires the exact Native93 runtime")


def shared_roots(values, *, buflo122=False):
    """Original two CS roots, or the explicit finite admitted BuFLO122 pool."""
    native126 = (buflo122 and type(values) in (list, tuple) and 2 <= len(values) <= 3
                 and all(str(value) in BF126_SHARED_ROOTS for value in values))
    if buflo122 and not native126:
        if (type(values) not in (list, tuple) or not 2 <= len(values) <= 5
                or any(str(value) not in BF122_SHARED_ROOTS for value in values)):
            raise ValueError("BuFLO122 pool requires two to five explicit cohort001 through005 roots")
    elif not buflo122 and (type(values) not in (list, tuple) or len(values) != 2):
        raise ValueError("two-root capture requires exactly two writer roots")
    roots = [Path(value) for value in values]
    if (any(not root.is_absolute() or root.resolve(strict=True) != root
            or any(path.is_symlink() for path in (root, *root.parents)) or not root.is_dir() for root in roots)
            or len(set(roots)) != len(roots) or any(a in b.parents for a in roots for b in roots if a != b)):
        raise ValueError("shared writer roots must be distinct canonical nonnested directories")
    return roots


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


def _coordinator_tasks():
    """The outer Guest process only; collection containers have separate PIDs."""
    return sorted(int(path.name) for path in Path("/proc/self/task").iterdir()
                  if path.name.isascii() and path.name.isdecimal())


def _coordinator_thread(tid):
    """Bind one live Linux task's name and mask to its stable start time."""
    if type(tid) is not int or tid <= 0:
        raise ValueError("coordinator task identity must be a positive native TID")
    path = Path("/proc/self/task") / str(tid) / "stat"

    def identity():
        value = path.read_text()
        left, right = value.find("("), value.rfind(")")
        fields = value[right + 1:].split()
        if left < 1 or right <= left or int(value[:left].strip()) != tid or len(fields) < 20:
            raise ValueError("coordinator task stat identity is malformed")
        start = int(fields[19])
        if start <= 0:
            raise ValueError("coordinator task start time is invalid")
        return value[left + 1:right], start

    before = identity()
    affinity = sorted(os.sched_getaffinity(tid))
    if not affinity or identity() != before:
        raise ValueError("coordinator task identity changed during affinity observation")
    return {"tid": tid, "name": before[0], "start_ticks": before[1], "affinity": affinity}


def _coordinator_thread_snapshot():
    tids = _coordinator_tasks()
    values = [_coordinator_thread(tid) for tid in tids]
    if _coordinator_tasks() != tids:
        raise ValueError("coordinator task census changed during affinity observation")
    return values


def _coordinator_await_owned_kernel_exit(owned, auxiliary):
    """Wait at most five seconds for joined pool tasks' exact Linux births.

    Python's thread sentinel can clear before pthread TLS teardown finishes.
    Only disappearance of a captured owned task permits a fresh census retry;
    foreign task changes and every other observation error still refuse.
    """
    pid = os.getpid()
    if (type(owned) is not frozenset
            or any(type(pair) is not tuple or len(pair) != 2
                or any(type(value) is not int or value <= 0 for value in pair)
                or pair[0] == pid for pair in owned)
            or len({tid for tid, _ in owned}) != len(owned)
            or type(auxiliary) is not tuple or not auxiliary
            or any(type(cpu) is not int or cpu < 0 for cpu in auxiliary)
            or auxiliary != tuple(sorted(set(auxiliary)))):
        raise ValueError("exact owned kernel births and auxiliary CPUs required")
    expected = dict(owned)
    foreign_reuses = set()
    started = time.monotonic()
    deadline = started + 5.0
    polls, retries = 0, 0
    while True:
        if sorted(os.sched_getaffinity(0)) != list(auxiliary):
            raise ValueError("coordinator main affinity changed during owned kernel teardown")
        tids = _coordinator_tasks()
        values, missing = [], set()
        for tid in tids:
            try:
                value = _coordinator_thread(tid)
            except (FileNotFoundError, ProcessLookupError):
                if tid not in expected or tid in foreign_reuses:
                    raise
                missing.add(tid)
                continue
            if tid != pid and not set(value["affinity"]) <= set(auxiliary):
                raise ValueError("coordinator task escaped auxiliary CPUs during kernel teardown")
            if tid in expected and value["start_ticks"] != expected[tid]:
                foreign_reuses.add(tid)
            values.append(value)
        after = _coordinator_tasks()
        removed, added = set(tids) - set(after), set(after) - set(tids)
        observed = {value["tid"]: value for value in values}
        if (added or not removed <= expected.keys()
                or any(tid in observed and observed[tid]["start_ticks"] != expected[tid]
                       for tid in removed)):
            raise ValueError("coordinator foreign task census changed during kernel teardown")
        polls += 1
        now = time.monotonic()
        if now < started:
            raise ValueError("coordinator teardown monotonic clock reversed")
        if missing or tids != after:
            retries += 1
            if now >= deadline:
                raise ValueError("owned kernel teardown census remained unstable for five seconds")
        else:
            remaining = [value for value in values
                         if (value["tid"], value["start_ticks"]) in owned]
            if not remaining or now >= deadline:
                return values, {"maximum_wait_seconds": 5.0,
                    "elapsed_seconds": now - started, "polls": polls,
                    "owned_task_disappearance_retries": retries,
                    "owned_thread_identities": [{"tid": tid, "start_ticks": start}
                                                for tid, start in sorted(owned)],
                    "remaining_owned_threads": remaining, "timed_out": now > deadline or bool(remaining),
                    "complete": not remaining and now <= deadline}
        time.sleep(min(0.01, deadline - now))


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


class _DockerLockOwner:
    """Actual FD, with read-only Linux fdinfo FLOCK ownership verification."""
    def __init__(self, path, handle):
        self.path, self.handle, self.pid, self.active = path, handle, os.getpid(), True
        self.identity = self._identity(os.fstat(handle.fileno()))
        self.check()

    @staticmethod
    def _identity(info):
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Docker lifecycle lock is not one regular file")
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)

    def check(self):
        if not self.active or self.pid != os.getpid() or self.handle.closed:
            raise ValueError("Docker lifecycle ownership is closed or foreign")
        if (self.path.resolve(strict=True) != self.path
                or any(p.is_symlink() for p in (self.path, *self.path.parents))
                or self._identity(self.path.lstat()) != self.identity
                or self._identity(os.fstat(self.handle.fileno())) != self.identity):
            raise ValueError("Docker lifecycle lock FD/path identity changed")
        if sys.platform == "linux":
            rows = Path(f"/proc/self/fdinfo/{self.handle.fileno()}").read_text().splitlines()
            device = f"{os.major(self.identity[0]):02x}:{os.minor(self.identity[0]):02x}:{self.identity[1]}"
            expected = ["FLOCK", "ADVISORY", "WRITE", str(self.pid), device, "0", "EOF"]
            if not any(row.startswith("lock:") and row.split()[2:] == expected for row in rows):
                raise ValueError("Docker lifecycle kernel FLOCK ownership differs")



@contextmanager
def docker_lock():
    directory = Path.home() / ".cache/qcsd-resource-study"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (directory / "docker.lock").open("a+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another resource-study Docker lifecycle is active") from error
        owner = _DockerLockOwner(directory / "docker.lock", handle)
        try:
            yield owner
        finally:
            owner.active = False
            fcntl.flock(handle, fcntl.LOCK_UN)



def _checked_catalog_startup_authority(auth, roots, *, expected=None):
    """Borrow one actually bound authority, never a caller's claimed handle."""
    from . import resource_study_cohorts as cohorts
    if (type(roots) not in (list, tuple) or not roots
            or any(not isinstance(root, Path) for root in roots)
            or len(roots) != len(set(map(str, roots)))):
        raise ValueError("catalog startup requires distinct explicit owning roots")
    writers = frozenset(str(root.absolute()) for root in roots)
    if (type(auth) is not cohorts._CaptureAuthority
            or type(auth.docker_owner) is not _DockerLockOwner
            or type(auth.source_auth) is not cohorts._SourceAuthorization
            or type(auth.parent) is not cohorts.StudyStore
            or auth.records is None or auth.collecting or auth.writers != writers
            or auth.pid != os.getpid() or auth.owner_thread != threading.get_ident()):
        raise ValueError("catalog startup authority is foreign, incomplete or has different writers")
    binding = cohorts._CAPTURE_AUTHORITY.get()
    if (type(binding) is not tuple or len(binding) != 3 or binding[0] is not auth
            or binding[1] != threading.get_ident() or binding[2] is not None
            or cohorts._SOURCE_OPERATION.get() is not auth.source_auth):
        raise ValueError("catalog startup authority is not bound to this coordinator and Source")
    identity = (auth, auth.pid, auth.owner_thread, auth.parent, auth.parent.root,
                auth.source_auth, auth.docker_owner, auth.writers)
    if expected is not None and identity != expected:
        raise ValueError("catalog startup authority parent, Source or Docker owner changed")
    auth._collector()
    auth.check()
    return identity


@contextmanager
def _catalog_capture_authority(roots):
    """One Docker owner spans startup validation, capture and topology closure.

    This is the real public catalog path. The backend only borrows this owner;
    the original cohort scope alone finishes and closes its actual authority.
    """
    with docker_lock() as owner:
        if _docker("ps", "-q"):
            raise ValueError("catalog startup requires no unaccounted running containers")
        from .resource_study_cohorts import capture_authority_scope
        with capture_authority_scope(roots, owner) as auth:
            _checked_catalog_startup_authority(auth, roots)
            yield auth


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

    def prepare(self, candidate: dict, output: Path, *, buflo_chaff_cap_bytes: int | None = None,
                buflo_small_response_aggregate: bool = False,
                buflo_duration_policy: str | None = None,
                cs_buflo_duration_policy: str | None = None,
                frozen_application_manifest: dict | None = None) -> dict:
        from .resource_study_native import _buflo_aggregate_option, buflo_aggregate_native_supported
        aggregate = _buflo_aggregate_option(buflo_small_response_aggregate, buflo_chaff_cap_bytes)
        if aggregate and not buflo_aggregate_native_supported(self.runtime.get("native_commit")):
            raise ValueError("aggregate preparation requires the exact Native128 runtime")
        if buflo_duration_policy is not None:
            from .buflo_duration_budget import preparation_policy
            preparation_policy(buflo_duration_policy)
        if cs_buflo_duration_policy is not None:
            from .resource_study_native import cs_duration_policy, CS180_HOST, CS180_NATIVE
            cs_duration_policy(cs_buflo_duration_policy)
            if candidate["hostname"] != CS180_HOST or self.runtime.get("native_commit") != CS180_NATIVE:
                raise ValueError("CS180 requires exact Ang Native137 preparation")
        frozen_raw = None
        if frozen_application_manifest is not None:
            from .resource_study_selection import read_frozen_application_manifest
            frozen_raw, _ = read_frozen_application_manifest(self.root, candidate["hostname"],
                candidate["urls"], frozen_application_manifest)
        output.mkdir(parents=True, exist_ok=False)
        dns = public_ipv4(candidate["hostname"])
        _put(output / "dns.json", dns)
        job = {"hostname": candidate["hostname"], "urls": candidate["urls"],
               "output": str(output / "prepared"), "runtime": self.runtime}
        native_prepare_options = ()
        if aggregate:
            native_prepare_options = ("--buflo-small-response-aggregate",)
        if buflo_chaff_cap_bytes is not None:
            from .resource_study_native import (
                _buflo_chaff_cap, BUFLO_CAPPED_SELECTION_POLICY, BUFLO_CAPPED_SELECTION_TYPE,
            )
            cap = _buflo_chaff_cap(buflo_chaff_cap_bytes)
            native_prepare_options = ("--buflo-chaff-cap-bytes", str(cap))
        if buflo_duration_policy is not None:
            native_prepare_options += ("--buflo-duration-policy", buflo_duration_policy)
        if cs_buflo_duration_policy is not None:
            native_prepare_options += ("--cs-buflo-duration-policy", cs_buflo_duration_policy)
        if frozen_application_manifest is not None:
            native_prepare_options += ("--frozen-application-manifest",
                str(self.root / frozen_application_manifest["manifest_path"]),
                "--frozen-application-manifest-sha256", frozen_application_manifest["manifest_sha256"])
        _put(output / "job.json", job)
        with docker_lock():
            _runtime_check(self.runtime)
            result = _docker("run", "--rm", "--network", "bridge", "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL",
                "--env", "QCSD_LAB_ROOT=/runtime-src", "--env", "QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json",
                "--security-opt", "no-new-privileges", "--add-host", candidate["hostname"] + ":" + dns["selected_ipv4"],
                "--mount", f"type=bind,src={self.root},dst={self.root}",
                "--entrypoint", "/opt/qcsd-venv/bin/python3", self.runtime["collection_image_digest"],
                "-I", "-B", "-m", "qcsd_lab.resource_study_native", "_prepare", "--job", str(output / "job.json"), *native_prepare_options,
                timeout=max(600, len(candidate["urls"]) * 125 + 600))
        _put(output / "result.json", json.loads(result.splitlines()[-1]))
        enrollment = load(output / "result.json")
        if aggregate:
            from .resource_study_native import buflo_aggregate_selection
            selection = enrollment.get("buflo_small_response_aggregate_selection")
            if (type(selection) is not dict or type(selection.get("schema_version")) is not int
                    or selection != buflo_aggregate_selection() or "buflo_chaff_selection" in enrollment):
                raise ValueError("prepared aggregate declaration differs from the explicit Native CLI option")
        elif "buflo_small_response_aggregate_selection" in enrollment:
            raise ValueError("ordinary preparation cannot claim the aggregate option")
        if (buflo_duration_policy is not None
                and enrollment.get("mode_policies", {}).get("buflo", {}).get("buflo_duration_policy") != buflo_duration_policy):
            raise ValueError("prepared BuFLO duration differs from the explicit Native CLI option")
        from .resource_study_native import CS180_POLICY
        actual_cs = enrollment.get("mode_policies", {}).get("cs-buflo", {}).get("cs_buflo_duration_policy")
        if actual_cs != cs_buflo_duration_policy:
            raise ValueError("prepared CS duration differs from explicit Native CLI option")
        if actual_cs == CS180_POLICY:
            from .resource_study_native import _cs180_scope
            _cs180_scope(candidate["hostname"], self.runtime, enrollment["workload_sha256"])
            if (enrollment["mode_settings"]["cs-buflo"]["timeout_seconds"],
                    enrollment["mode_settings"]["cs-buflo"]["capture_seconds"]) != (180, 240):
                raise ValueError("returned CS180 preparation limits differ")
        if buflo_chaff_cap_bytes is not None:
            selection = enrollment.get("buflo_chaff_selection")
            if (type(selection) is not dict
                    or type(selection.get("schema_version")) is not int
                    or type(selection.get("cap_bytes")) is not int
                    or selection != {"schema_version": 1, "record_type": BUFLO_CAPPED_SELECTION_TYPE,
                                     "selection_policy": BUFLO_CAPPED_SELECTION_POLICY, "cap_bytes": cap}):
                raise ValueError("prepared BuFLO cap declaration differs from the explicit Native CLI option")
        if frozen_application_manifest is not None:
            from .resource_study_selection import frozen_application_manifest_declaration, read_frozen_application_manifest
            if (read_frozen_application_manifest(self.root, candidate["hostname"], candidate["urls"],
                    frozen_application_manifest)[0] != frozen_raw
                    or Path(enrollment["workload_path"]).read_bytes() != frozen_raw
                    or enrollment["workload_sha256"] != frozen_application_manifest["manifest_sha256"]
                    or load(Path(enrollment["paths"]["prepared_workload"]))["preparation"].get("frozen_application_manifest")
                        != frozen_application_manifest_declaration(frozen_application_manifest["manifest_sha256"])):
                raise ValueError("Native preparation changed the explicit frozen application manifest")
            enrollment["frozen_application_manifest"] = dict(frozen_application_manifest)
        enrollment["workload_path"] = Path(enrollment["workload_path"]).relative_to(self.root).as_posix()
        enrollment["paths"] = {key: Path(value).relative_to(self.root).as_posix() if value else None
                               for key, value in enrollment["paths"].items()}
        enrollment["preparation_dir"] = (output / "prepared").relative_to(self.root).as_posix()
        enrollment["files"] = {(output / "prepared" / relative).relative_to(self.root).as_posix(): digest
                               for relative, digest in enrollment["files"].items()}
        enrollment["files"][(output / "dns.json").relative_to(self.root).as_posix()] = sha256_file(output / "dns.json")
        if frozen_application_manifest is not None:
            from .resource_study_cohorts import INPUT_CONTEXT
            enrollment["files"][frozen_application_manifest["manifest_path"]] = frozen_application_manifest["manifest_sha256"]
            enrollment["files"][INPUT_CONTEXT] = frozen_application_manifest["context_sha256"]
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


def _router_capture_seconds(enrollment: Mapping[str, Any]) -> int:
    from . import buflo_duration_budget as budget
    policies = enrollment.get("mode_policies", {}).get("buflo", {})
    if policies.get("buflo_duration_policy") != budget.CADENCE64_1280_POLICY:
        return 740
    settings = enrollment.get("mode_settings", {}).get("buflo", {})
    budget.validate_parameters(settings.get("parameters"))
    limits = budget.capture_limits("buflo", {"timeout_seconds": 120, "capture_seconds": 180},
                                  policy=budget.CADENCE64_1280_POLICY)
    if (settings["parameters"][budget.PARAMETER_FIELD] != budget.CADENCE64_1280_POLICY
            or any(type(settings.get(k)) is not int or settings[k] != v for k, v in limits.items())):
        raise ValueError("router capture bound differs from the explicit enrolled BuFLO duration")
    return limits["capture_seconds"]

def _capture_call_timeout_seconds(mode: str, enrollment: Mapping[str, Any]) -> int:
    """Preserve the outer 110-second allowance beyond the enrolled router bound."""
    if mode != "buflo":
        return 850
    return _router_capture_seconds(enrollment) + 110


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

    @contextmanager
    def coordinator_affinity_scope(self):
        """Keep the outer coordinator and its future pool on residual CPUs.

        Enter only after the full-affinity Docker partition is constructed and
        before creating pool threads. Existing unknown siblings refuse entry;
        new pool threads inherit this mask. The actual executor owns the join;
        foreign threads may remain only on auxiliary CPUs. No client/container
        mask changes.
        """
        pid = os.getpid()
        available, pairs, auxiliary = self.coordinator_partition
        protected = [cpu for pair in pairs for cpu in pair]
        if (threading.current_thread() is not threading.main_thread()
                or _coordinator_tasks() != [pid]
                or not available or tuple(sorted(set(available))) != available
                or any(type(cpu) is not int or cpu < 0 for cpu in available)
                or len(pairs) != self.count or any(len(pair) != 2 for pair in pairs)
                or any(type(cpu) is not int for cpu in protected)
                or len(protected) != len(set(protected))
                or not set(protected) <= set(available)
                or not auxiliary or tuple(sorted(set(available) - set(protected))) != auxiliary):
            raise ValueError("coordinator scope requires one main thread and the actual residual CPU partition")
        original = sorted(os.sched_getaffinity(0))
        if original != list(available):
            raise ValueError("coordinator must enter with the complete measured available CPU set")
        flights = list(self.flights.values()) if hasattr(self, "flights") else [self.flight]
        baseline_threads = _coordinator_thread_snapshot()
        if [value["tid"] for value in baseline_threads] != [pid]:
            raise ValueError("coordinator baseline thread census differs")
        fixed = {"record_type": "qcsd-Source029-outer-coordinator-affinity-v2", "schema_version": 2,
            "pid": pid, "available_cpus": list(available), "worker_cpu_pairs": [list(p) for p in pairs],
            "auxiliary_cpus": list(auxiliary), "affinity_before": original,
            "existing_thread_ids": [pid], "new_pool_threads_inherit_auxiliary_mask": True,
            "baseline_threads": baseline_threads, "pool_ownership_source": "ThreadPoolExecutor._threads",
            "container_and_Native_affinity_changed": False, "scientific_credit": False}
        body_error = None
        pool = None
        owned = []
        ownership_observed = False

        @contextmanager
        def observe_executor(executor):
            nonlocal pool, owned, ownership_observed
            if pool is not None:
                raise ValueError("coordinator scope can own only one executor")
            pool = executor
            executor_error = None
            try:
                yield
            except BaseException as error:
                executor_error = error
                raise
            finally:
                try:
                    threads = list(executor._threads)
                    if any(not isinstance(thread, threading.Thread) for thread in threads):
                        raise ValueError("coordinator executor contains an unknown thread owner")
                    owned = [(thread, {**_coordinator_thread(thread.native_id), "python_name": thread.name})
                             for thread in threads]
                    owned.sort(key=lambda item: item[1]["tid"])
                    tids = [value["tid"] for _, value in owned]
                    if (len(tids) != len(set(tids)) or pid in tids
                            or any(not set(value["affinity"]) <= set(auxiliary) for _, value in owned)):
                        raise ValueError("coordinator owned pool identity or auxiliary affinity differs")
                    ownership_observed = True
                except BaseException as failure:
                    if executor_error is None:
                        raise
                    executor_error.add_note("Coordinator pool ownership observation also refused: " + str(failure))

        try:
            os.sched_setaffinity(0, set(auxiliary))
            during = sorted(os.sched_getaffinity(0))
            if during != list(auxiliary) or _coordinator_tasks() != [pid]:
                raise ValueError("coordinator auxiliary affinity or pre-pool thread identity differs")
            self.coordinator_affinity = {**fixed, "affinity_during": during}
            for flight in flights:
                _put(flight / "coordinator-affinity-started.json", self.coordinator_affinity)
            yield observe_executor
        except BaseException as error:
            body_error = error
            raise
        finally:
            try:
                try:
                    threads_after = [] if pool is None else list(pool._threads)
                    joined = (pool is None or (ownership_observed
                        and len(threads_after) == len(owned)
                        and all(any(thread is old for old, _ in owned) for thread in threads_after)
                        and all(not thread.is_alive() for thread in threads_after)))
                    owned_records = [{**value, "alive_after_join": thread.is_alive()} for thread, value in owned]
                    owned_identities = frozenset((value["tid"], value["start_ticks"]) for _, value in owned)
                    python_joined = joined
                    kernel_wait = None
                    if joined and pool is not None:
                        remaining_before, kernel_wait = _coordinator_await_owned_kernel_exit(owned_identities, auxiliary)
                        joined = joined and kernel_wait["complete"]
                    else:
                        remaining_before = _coordinator_thread_snapshot()
                    joined = joined and not any((value["tid"], value["start_ticks"]) in owned_identities
                                                 for value in remaining_before)
                finally:
                    os.sched_setaffinity(0, set(original))
                restored = sorted(os.sched_getaffinity(0))
                remaining_after = _coordinator_thread_snapshot()
                joined = joined and not any((value["tid"], value["start_ticks"]) in owned_identities
                                             for value in remaining_after)
                foreign = [value for value in remaining_before + remaining_after if value["tid"] != pid
                           and (value["tid"], value["start_ticks"]) not in owned_identities]
                foreign_confined = all(set(value["affinity"]) <= set(auxiliary) for value in foreign)
                main_before = [value for value in remaining_before if value["tid"] == pid]
                main_after = [value for value in remaining_after if value["tid"] == pid]
                main_valid = (len(main_before) == len(main_after) == 1
                    and main_before[0]["start_ticks"] == main_after[0]["start_ticks"] == baseline_threads[0]["start_ticks"]
                    and main_before[0]["affinity"] == list(auxiliary) and main_after[0]["affinity"] == original)
                closed = {**fixed, "affinity_restored": restored,
                    "remaining_thread_ids_before_restoration": [value["tid"] for value in remaining_before],
                    "remaining_thread_ids_after_restoration": [value["tid"] for value in remaining_after],
                    "remaining_threads_before_restoration": remaining_before,
                    "remaining_threads_after_restoration": remaining_after,
                    "executor_registered": pool is not None, "owned_pool_threads": owned_records,
                    "foreign_threads_confined_to_auxiliary": foreign_confined,
                    "main_thread_identity_and_affinity_valid": main_valid,
                    "restored": restored == original, "body_failed": body_error is not None,
                    "python_pool_joined_before_kernel_wait": python_joined,
                    "owned_kernel_thread_teardown": kernel_wait,
                    "pool_joined_before_restoration": joined}
                for flight in flights:
                    _put(flight / "coordinator-affinity-closed.json", closed)
                if restored != original or not main_valid or not joined or not foreign_confined:
                    raise ValueError("coordinator affinity restoration or pool-thread closure differs")
            except BaseException as failure:
                if body_error is None:
                    raise
                body_error.add_note("Coordinator affinity closure also refused: " + str(failure))

    @contextmanager
    def capture_authority_scope(self):
        if type(self) not in (CaptureRuntime, MultiRootCaptureRuntime, CatalogCaptureRuntime):
            yield None
            return
        from .resource_study_cohorts import capture_authority_scope
        roots = (list(self.contexts) if type(self) in (MultiRootCaptureRuntime, CatalogCaptureRuntime)
                 else self.root)
        with capture_authority_scope(roots, self._docker_owner) as auth:
            self._capture_authority = auth
            try:
                yield auth
            finally:
                del self._capture_authority

    def __enter__(self):
        self.lock = docker_lock()
        self._docker_owner = self.lock.__enter__()
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
            self.coordinator_partition = (tuple(available), tuple(pairs), tuple(sidecars))
            sidecar_cpuset = ",".join(map(str, sidecars))
            bridge = json.loads(_docker("network", "inspect", "bridge"))[0]
            from .resource_study_store import StudyStore
            router_enrollments = {e["hostname"]: e for e in StudyStore(self.root).enrolled()
                       if self.selected_hostnames is None or e["hostname"] in self.selected_hostnames}
            domains = list(router_enrollments)
            router_capture_limits = {h: _router_capture_seconds(e) for h, e in router_enrollments.items()}
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
                    "QCSD_KERNEL_TX_ROUTER_CAPTURE_MAX_SECONDS": str(router_capture_limits[hostname]),
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
                "coordinator_auxiliary_cpus": sidecars,
                "coordinator_affinity_policy": "qcsd-Source029-outer-coordinator-affinity-v2",
                "class_mapping_sha256": mapping_sha256(self.plan), "scientific_credit": False})
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _router_runtime(self, hostname):
        return self.runtime

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
            _, net_receipt, observer = topology_receipts(self._router_runtime(hostname)["collection_image_digest"], route["name"],
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
            "--job", str(directory / "job.json"),
            timeout=_capture_call_timeout_seconds(attempt["mode"], enrollment))
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


class MultiRootCaptureRuntime(CaptureRuntime):
    """One original protected lane topology, with two owning artifact roots.

    Router, worker, capability, partition and raw job construction follow the
    original runtime. Only the root mounts, per-attempt root binding and the
    duplicated launch/closure metadata differ. This class grants no ledger or
    pilot authority; the public scheduler authenticates both writer contexts.
    """

    def __init__(self, contexts, runtime, workers, *, cell_roots):
        buflo122 = require_shared_runtime(runtime) is True
        if type(workers) is not int or not 2 <= workers <= 11:
            raise ValueError("shared capture requires between two and eleven workers")
        if type(contexts) is not dict or any(not isinstance(root, Path) for root in contexts):
            raise ValueError("shared capture requires authenticated root contexts")
        roots = shared_roots(list(contexts), buflo122=buflo122)
        if (type(cell_roots) is not dict or not cell_roots or len(cell_roots) > 50
                or set(cell_roots.values()) != set(roots)):
            raise ValueError("shared capture needs an explicit hostname-to-root map")
        self.contexts = {}
        for root in roots:
            context = contexts[root]
            plan = load(root / "study.json")
            if (type(context) is not dict or set(context) != {"plan", "study_sha256"}
                    or context["plan"] != plan or context["study_sha256"] != sha256_file(root / "study.json")):
                raise ValueError("shared capture study context changed")
            validate_network_plan(plan, require=True)
            self.contexts[root] = {"plan": plan, "study_sha256": context["study_sha256"]}
        first = self.contexts[roots[0]]["plan"]
        if any(self.contexts[root]["plan"].get(key) != first.get(key)
               for root in roots for key in ("class_network", "class_selection", "source_sha256", "acceptance", "tuple_uniqueness_scope")):
            raise ValueError("shared capture roots have different frozen class plans")
        assignments = validate_network_plan(first, require=True)
        if any(type(host) is not str or host not in assignments for host in cell_roots):
            raise ValueError("shared capture host has no frozen class assignment")
        self.cell_roots = dict(cell_roots)
        self.flights = {}
        super().__init__(roots[0], runtime, workers, hostnames=sorted(cell_roots))

    def flight_binding(self):
        return {"record_type": "qcsd-resource-domain-shared-flight-v1",
            "anchor_root": str(next(iter(self.contexts))),
            "roots": [{"root": str(root), "study_sha256": context["study_sha256"]}
                      for root, context in self.contexts.items()],
            "cell_roots": {host: str(root) for host, root in sorted(self.cell_roots.items())},
            "workers": self.count, "scientific_credit": False}

    def _capacity(self):
        info = _runtime_check(self.runtime)
        ncpu = int(info["NCPU"])
        available = json.loads(_docker("run", "--rm", "--network", "none", "--cap-drop", "ALL",
            "--entrypoint", "/opt/qcsd-venv/bin/python3", self.runtime["collection_image_digest"],
            "-I", "-c", "import json,os;print(json.dumps(sorted(os.sched_getaffinity(0))))"))
        if (not isinstance(available, list) or any(type(cpu) is not int or cpu < 0 for cpu in available)
                or available != sorted(set(available)) or not available or max(available) >= ncpu):
            raise ValueError("Docker affinity probe did not report the actual CPU set")
        return ncpu, available

    def _lane_runtime(self, index):
        return self.runtime

    def _bind_enrollments(self, enrollments):
        pass

    def _job_runtime(self, index, attempt, enrollment):
        return self.runtime

    def _launch_runtime_fields(self):
        return {"runtime": self.runtime}

    def _flight_fields(self):
        return {"shared_flight": self.flight_binding()}

    def _closure_runtime_fields(self):
        return {}

    def _docker_lock_scope(self):
        return docker_lock()

    def __enter__(self):
        self.lock = self._docker_lock_scope()
        self._docker_owner = self.lock.__enter__()
        try:
            for root, context in self.contexts.items():
                if (sha256_file(root / "study.json") != context["study_sha256"]
                        or load(root / "study.json") != context["plan"]):
                    raise ValueError("shared capture study context changed before launch")
            self.plan = load(self.root / "study.json")
            assignments = validate_network_plan(self.plan, require=True)
            self.study_sha256 = sha256_file(self.root / "study.json")
            ncpu, available = self._capacity()
            if len(available) < 2 * self.count + 1:
                raise ValueError(f"{self.count} protected workers need {2*self.count+1} available logical CPUs")
            if _docker("ps", "-q"):
                raise ValueError("capacity launch requires no unaccounted running containers")
            existing_ids = _docker("network", "ls", "-q").splitlines()
            existing = json.loads(_docker("network", "inspect", *existing_ids)) if existing_ids else []
            collision = check_collisions(self.plan, existing, _host_routes())
            nonce = secrets.token_hex(12)
            for root in self.contexts:
                flight = root / "flights" / nonce
                flight.mkdir(parents=True)
                self.flights[root] = flight
            self.flight = self.flights[self.root]
            _put(self.flight / "collision-check.json", collision)
            positive = [cpu for cpu in available if cpu >= 1]
            pairs = [(positive[2*i], positive[2*i+1]) for i in range(self.count)]
            sidecars = sorted(set(available) - {cpu for pair in pairs for cpu in pair})
            self.coordinator_partition = (tuple(available), tuple(pairs), tuple(sidecars))
            sidecar_cpuset = ",".join(map(str, sidecars))
            bridge = json.loads(_docker("network", "inspect", "bridge"))[0]
            domains = sorted(self.cell_roots)
            from .resource_study_store import StudyStore
            router_enrollments = {e["hostname"]: e for root in self.contexts for e in StudyStore(root).enrolled()
                                  if self.cell_roots.get(e["hostname"]) == root}
            if set(router_enrollments) != set(domains):
                raise ValueError("shared router capture lacks its exact current enrolled class")
            self._bind_enrollments(router_enrollments)
            router_capture_limits = {h: _router_capture_seconds(e) for h, e in router_enrollments.items()}
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
                image = self._router_runtime(hostname)["collection_image_digest"]
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
                    "QCSD_KERNEL_TX_ROUTER_CAPTURE_MAX_SECONDS": str(router_capture_limits[hostname]),
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
                image = self._lane_runtime(index)["collection_image_digest"]
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
                    "--entrypoint", "/usr/bin/tini"]
                for root in self.contexts:
                    args += ["--mount", f"type=bind,src={root},dst={root}"]
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
            for root, flight in self.flights.items():
                _put(flight / "launched.json", {"workers": declared, "sidecars": sidecar_ids,
                    **self._launch_runtime_fields(), "available_cpus": available,
                    "coordinator_auxiliary_cpus": sidecars,
                    "coordinator_affinity_policy": "qcsd-Source029-outer-coordinator-affinity-v2",
                    "study_sha256": self.contexts[root]["study_sha256"],
                    "class_mapping_sha256": mapping_sha256(self.contexts[root]["plan"]),
                    **self._flight_fields(), "scientific_credit": False})
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _activate(self, index, hostname):
        if hostname not in self.cell_roots:
            raise ValueError("hostname is outside this shared flight")
        root = self.cell_roots[hostname]
        with self.switch_lock:
            original = self.root, self.plan, self.study_sha256
            context = self.contexts[root]
            self.root, self.plan, self.study_sha256 = root, context["plan"], context["study_sha256"]
            try:
                return super()._activate(index, hostname)
            finally:
                self.root, self.plan, self.study_sha256 = original

    def capture(self, index: int, attempt: dict, enrollment: dict) -> dict:
        job_runtime = self._job_runtime(index, attempt, enrollment)
        worker = self.workers[index]
        attachment = self._activate(index, attempt["hostname"])
        root = self.cell_roots[attempt["hostname"]]
        directory = root / attempt["path"]
        job = {"hostname": attempt["hostname"], "mode": attempt["mode"],
               "enrollment_dir": str(root / enrollment["preparation_dir"]),
               "attempt_dir": str(directory / "capture"), "seed": int(attempt["attempt_id"][:16], 16),
               "runtime": job_runtime}
        _put(directory / "job.json", job)
        arguments = ["exec", "--env", "QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_SHA256=" + worker["partition_sha256"]]
        for key, value in self.class_routes[attempt["hostname"]]["environment"].items():
            arguments += ["--env", key + "=" + value]
        output = _docker(*arguments, worker["id"], "/usr/bin/taskset", "--cpu-list", str(worker["helper"]),
            "/usr/bin/setpriv", "--reuid", str(os.getuid()), "--regid", str(os.getgid()), "--clear-groups",
            "--bounding-set=-all,+net_raw,+net_admin,+setpcap", "--inh-caps=+net_raw,+net_admin,+setpcap",
            "--ambient-caps=+net_raw,+net_admin,+setpcap", "--no-new-privs",
            "/opt/qcsd-venv/bin/python3", "-I", "-B", "-m", "qcsd_lab.resource_study_native", "_capture",
            "--job", str(directory / "job.json"),
            timeout=_capture_call_timeout_seconds(attempt["mode"], enrollment))
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
        publication_errors = []
        try:
            for root, flight in self.flights.items():
                try:
                    _put(flight / "closed.json", {"containers_removed": self.containers,
                        "networks_removed": self.networks, "cleanup_errors": failures,
                        **self._closure_runtime_fields(),
                        "study_sha256": self.contexts[root]["study_sha256"],
                        **self._flight_fields(), "scientific_credit": False})
                except (OSError, ValueError, RuntimeError) as error:
                    publication_errors.append(str(error))
        finally:
            self.lock.__exit__(None, None, None)
        if publication_errors:
            raise RuntimeError("shared flight closure metadata needs recovery")
        if failures:
            raise RuntimeError("capture topology cleanup needs recovery")


class CatalogCaptureRuntime(MultiRootCaptureRuntime):
    """One owned topology with fixed full-runtime worker lanes.

    The coordinator authenticates current admitted members, own-pilots, shared
    quotas and tuple exclusions under the parent epoch lock. This backend binds
    those exact enrollments to actual images and per-attempt jobs. It does not
    issue admission, pilots, proofs or scientific credit.
    """

    def __init__(self, contexts, workers, *, cell_roots, host_runtimes,
                 worker_runtime_keys, host_modes, _startup_authority=None):
        if type(workers) is not int or not 2 <= workers <= 11:
            raise ValueError("catalog capture requires between two and eleven workers")
        if (type(contexts) is not dict or not 1 <= len(contexts) <= 50
                or any(not isinstance(root, Path) for root in contexts)):
            raise ValueError("catalog capture requires authenticated root contexts")
        roots = sorted(contexts)
        if (any(not root.is_absolute() or root.resolve(strict=True) != root
                or any(path.is_symlink() for path in (root, *root.parents))
                or not root.is_dir() for root in roots)
                or any(a in b.parents for a in roots for b in roots if a != b)):
            raise ValueError("catalog roots must be canonical nonnested directories")
        if (type(cell_roots) is not dict or not 1 <= len(cell_roots) <= 50
                or any(not isinstance(root, Path) for root in cell_roots.values())
                or set(cell_roots.values()) != set(roots)
                or type(host_runtimes) is not dict or set(host_runtimes) != set(cell_roots)
                or type(host_modes) is not dict or set(host_modes) != set(cell_roots)):
            raise ValueError("catalog needs one owning root and full runtime per hostname")
        self.contexts = {}
        for root in roots:
            context = contexts[root]
            plan = load(root / "study.json")
            if (type(context) is not dict or set(context) != {"plan", "study_sha256"}
                    or context["plan"] != plan
                    or context["study_sha256"] != sha256_file(root / "study.json")):
                raise ValueError("catalog capture study context changed")
            validate_network_plan(plan, require=True)
            self.contexts[root] = {"plan": plan, "study_sha256": context["study_sha256"]}
        first = self.contexts[roots[0]]["plan"]
        if any(self.contexts[root]["plan"].get(key) != first.get(key)
               for root in roots for key in ("class_network", "class_selection", "source_sha256",
                                             "acceptance", "tuple_uniqueness_scope")):
            raise ValueError("catalog roots have different frozen class plans")
        assignments = validate_network_plan(first, require=True)
        if any(type(host) is not str or host not in assignments for host in cell_roots):
            raise ValueError("catalog host has no frozen class assignment")
        self.cell_roots = dict(cell_roots)
        self.host_runtimes = json.loads(canonical_json(host_runtimes))
        self.host_modes = json.loads(canonical_json(host_modes))
        self.runtime_catalog, self.host_runtime_keys = {}, {}
        for host, value in self.host_runtimes.items():
            if (type(value) is not dict
                    or set(value) != {"canonical_sha256", "client_sha256", "platform", "native_commit",
                                      "collection_image_digest", "prepare_image_digest", "source"}
                    or value["platform"] not in ("linux/arm64", "linux/amd64")
                    or type(value["source"]) is not dict
                    or value["source"].get("neqo_commit") != value["native_commit"]
                    or any(not self._hex(value.get(name), length)
                           for name, length in (("canonical_sha256", 64), ("client_sha256", 64),
                                                ("native_commit", 40)))
                    or any(type(value.get(name)) is not str or not value[name].startswith("sha256:")
                           or not self._hex(value[name][7:], 64)
                           for name in ("collection_image_digest", "prepare_image_digest"))):
                raise ValueError("catalog entry lacks its exact full immutable runtime")
            modes = self.host_modes[host]
            if (type(modes) is not list or not modes
                    or any(type(mode) is not str or mode not in MODES for mode in modes)
                    or modes != sorted(set(modes))):
                raise ValueError("catalog host needs explicit sorted selected modes")
            key = hashlib.sha256(canonical_json(value)).hexdigest()
            self.runtime_catalog[key] = value
            self.host_runtime_keys[host] = key
        if (type(worker_runtime_keys) not in (list, tuple) or len(worker_runtime_keys) != workers
                or any(type(key) is not str or key not in self.runtime_catalog for key in worker_runtime_keys)
                or set(worker_runtime_keys) != set(self.runtime_catalog)):
            raise ValueError("catalog requires a fixed compatible lane for every full runtime")
        self.runtime_keys = tuple(worker_runtime_keys)
        self.flights = {}
        CaptureRuntime.__init__(self, roots[0], None, workers, hostnames=sorted(cell_roots))
        self._catalog_seal = hashlib.sha256(canonical_json(self._catalog_config())).hexdigest()
        self._enrollment_seal = None
        self._startup_authority = _startup_authority
        self._startup_identity = (None if _startup_authority is None else
            _checked_catalog_startup_authority(_startup_authority, list(self.contexts)))

    @contextmanager
    def _docker_lock_scope(self):
        if self._startup_authority is None:
            if self._startup_identity is not None:
                raise ValueError("catalog startup authority binding cannot be dropped")
            with docker_lock() as owner:
                yield owner
            return
        _checked_catalog_startup_authority(self._startup_authority,
            list(self.contexts), expected=self._startup_identity)
        # The outer startup scope is the only owner. Exiting this borrowed
        # scope does not finish authority or release its Docker lifecycle FD.
        yield self._startup_authority.docker_owner

    @contextmanager
    def capture_authority_scope(self):
        if self._startup_authority is None:
            if self._startup_identity is not None:
                raise ValueError("catalog startup authority binding cannot be dropped")
            with super().capture_authority_scope() as auth:
                yield auth
            return
        _checked_catalog_startup_authority(self._startup_authority,
            list(self.contexts), expected=self._startup_identity)
        if self._docker_owner is not self._startup_authority.docker_owner:
            raise ValueError("catalog backend has a different Docker lifecycle owner")
        self._capture_authority = self._startup_authority
        try:
            yield self._capture_authority
        finally:
            del self._capture_authority

    @staticmethod
    def _hex(value, length):
        return (type(value) is str and len(value) == length
                and all(character in "0123456789abcdef" for character in value))

    def _catalog_config(self):
        return {"roots": [{"root": str(root), **context} for root, context in self.contexts.items()],
                "cell_roots": {host: str(root) for host, root in sorted(self.cell_roots.items())},
                "host_runtimes": self.host_runtimes, "runtime_catalog": self.runtime_catalog,
                "host_modes": self.host_modes, "host_runtime_keys": self.host_runtime_keys,
                "worker_runtime_keys": list(self.runtime_keys), "workers": self.count,
                "selected_hostnames": sorted(self.selected_hostnames), "global_runtime": self.runtime}

    def _catalog_guard(self):
        if hashlib.sha256(canonical_json(self._catalog_config())).hexdigest() != self._catalog_seal:
            raise ValueError("immutable catalog runtime or owning-root binding changed")

    def flight_binding(self):
        self._catalog_guard()
        return {"record_type": "qcsd-resource-domain-runtime-catalog-flight-v1", "schema_version": 1,
                "catalog_sha256": self._catalog_seal,
                "roots": [{"root": str(root), "study_sha256": context["study_sha256"]}
                          for root, context in self.contexts.items()],
                "cell_roots": {host: str(root) for host, root in sorted(self.cell_roots.items())},
                "runtime_catalog": json.loads(canonical_json(self.runtime_catalog)),
                "host_runtime_keys": dict(self.host_runtime_keys),
                "worker_runtime_keys": list(self.runtime_keys),
                "host_modes": json.loads(canonical_json(self.host_modes)),
                "workers": self.count, "scientific_credit": False}

    def _capacity(self):
        self._catalog_guard()
        result = None
        for value in self.runtime_catalog.values():
            info = _runtime_check(value)
            ncpu = int(info["NCPU"])
            available = json.loads(_docker("run", "--rm", "--network", "none", "--cap-drop", "ALL",
                "--entrypoint", "/opt/qcsd-venv/bin/python3", value["collection_image_digest"],
                "-I", "-c", "import json,os;print(json.dumps(sorted(os.sched_getaffinity(0))))"))
            if (type(available) is not list or not available
                    or any(type(cpu) is not int or cpu < 0 for cpu in available)
                    or available != sorted(set(available)) or max(available) >= ncpu):
                raise ValueError("catalog image affinity probe did not report the actual CPU set")
            observed = (ncpu, available)
            if result is not None and observed != result:
                raise ValueError("catalog images disagree on the available host CPU partition")
            result = observed
        return result

    def _router_runtime(self, hostname):
        self._catalog_guard()
        return self.host_runtimes[hostname]

    def _lane_runtime(self, index):
        self._catalog_guard()
        if type(index) is not int or not 0 <= index < self.count:
            raise ValueError("catalog worker index is outside the fixed lane partition")
        return self.runtime_catalog[self.runtime_keys[index]]

    def _bind_enrollments(self, enrollments):
        self._catalog_guard()
        for host, enrollment in enrollments.items():
            if (enrollment.get("hostname") != host
                    or enrollment.get("runtime") != self.host_runtimes[host]
                    or type(enrollment.get("mode_readiness")) is not dict
                    or any(enrollment["mode_readiness"].get(mode) is not True for mode in self.host_modes[host])):
                raise ValueError("catalog selected mode or full runtime differs from its actual enrollment")
        self._catalog_enrollments = json.loads(canonical_json(enrollments))
        self._enrollment_seal = hashlib.sha256(canonical_json(self._catalog_enrollments)).hexdigest()

    def _job_runtime(self, index, attempt, enrollment):
        self._catalog_guard()
        self._lane_runtime(index)
        host = attempt.get("hostname")
        if (host not in self.cell_roots or attempt.get("mode") not in self.host_modes[host]
                or self.runtime_keys[index] != self.host_runtime_keys[host]):
            raise ValueError("catalog attempt is outside its selected host/mode or compatible worker lane")
        if (self._enrollment_seal is None
                or hashlib.sha256(canonical_json(self._catalog_enrollments)).hexdigest() != self._enrollment_seal
                or enrollment != self._catalog_enrollments[host]):
            raise ValueError("catalog job enrollment changed after topology launch")
        return self.host_runtimes[host]

    def _activate(self, index, hostname):
        self._catalog_guard()
        value = self._lane_runtime(index)
        if hostname not in self.cell_roots or self.runtime_keys[index] != self.host_runtime_keys[hostname]:
            raise ValueError("catalog hostname cannot activate on a different runtime lane")
        inspected = json.loads(_docker("container", "inspect", self.workers[index]["id"]))[0]
        if inspected.get("Image") != value["collection_image_digest"]:
            raise ValueError("catalog worker image changed before capture")
        return super()._activate(index, hostname)

    def _launch_runtime_fields(self):
        return {"record_type": "qcsd-resource-domain-runtime-catalog-launch-v1", "schema_version": 1}

    def _flight_fields(self):
        return {"catalog_flight": self.flight_binding()}

    def _closure_runtime_fields(self):
        return {"record_type": "qcsd-resource-domain-runtime-catalog-closed-v1", "schema_version": 1}
