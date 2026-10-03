"""Opt-in two-worker capture rehearsal; every receipt grants zero formal credit.

The authenticated shell owns Docker resources. This module checks the bound
inputs, releases actual inspected workers, and reopens ordinary deep results.
It does not change site admission, Native scheduling, or the formal study plan.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .util import durable_create

AUTHORITY_TYPE = "qcsd-two-worker-diagnostic-authority"
NATIVE_CONTRACT = "qcsd-client-rr1-portable-etf-helper-v4"
RUNTIME_PATH_KEYS = {"runtime_source_root", "module_root", "execution_root",
                     "source_manifest", "client_binary", "base_launcher", "host_launcher"}
RUNTIME_KEYS = RUNTIME_PATH_KEYS | {"collection_image_digest"}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read(path: Path) -> bytes:
    path = Path(path).absolute()
    if (not path.is_file() or any(item.is_symlink() for item in (path, *path.parents))):
        raise ValueError("parallel input must be a regular file without symlinks")
    return path.read_bytes()


def put(path: Path, value: Any) -> str:
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    durable_create(path, raw)
    return sha(raw)


def load(path: Path) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("parallel JSON repeats a key")
            result[key] = value
        return result
    return json.loads(read(path), object_pairs_hook=pairs)


def regular_dir(path: Path) -> Path:
    path = Path(path).absolute()
    if (not path.is_dir() or ".." in path.parts
        or any(c in str(path) for c in ("\n", "\r", "\0", ":"))
        or any(item.is_symlink() for item in (path, *path.parents))):
        raise ValueError("parallel directory must exist without symlinks")
    return path


def authority(path: Path, *, execution_root: Path | None = None) -> dict[str, Any]:
    """Reopen immutable inputs without allocating outputs or using Docker."""
    value = load(path)
    if (not isinstance(value, dict)
        or set(value) != {"schema_version", "artifact_type", "runtime", "campaigns"}
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["artifact_type"] != AUTHORITY_TYPE
        or not isinstance(value["runtime"], dict) or set(value["runtime"]) != RUNTIME_KEYS
        or not isinstance(value["campaigns"], list) or len(value["campaigns"]) != 2):
        raise ValueError("parallel diagnostic authority fields differ")
    runtime = value["runtime"]
    if re.fullmatch(r"sha256:[0-9a-f]{64}", str(runtime["collection_image_digest"])) is None:
        raise ValueError("parallel collection image must be immutable")
    for key in RUNTIME_PATH_KEYS:
        text = runtime[key]
        if (not isinstance(text, str) or not Path(text).is_absolute()
            or str(Path(text).absolute()) != text or ".." in Path(text).parts
            or any(c in text for c in ("\n", "\r", "\0", ":"))):
            raise ValueError("parallel runtime paths must be explicit canonical absolute paths")
        if key.endswith("root"):
            regular_dir(Path(text))
        else:
            read(Path(text))
    root = Path(runtime["execution_root"])
    if execution_root is not None and regular_dir(execution_root) != root:
        raise ValueError("parallel authority names another execution root")
    if (runtime["module_root"] != runtime["runtime_source_root"]
        or Path(runtime["host_launcher"]) != root / "qcsd-lab"
        or read(Path(runtime["base_launcher"])) != read(Path(runtime["runtime_source_root"]) / "qcsd-lab")
        or read(Path(runtime["host_launcher"])) != read(Path(runtime["base_launcher"]))):
        raise ValueError("parallel collection and launcher must use the declared new runtime source")
    source = load(Path(runtime["source_manifest"]))
    if (source.get("lab_dirty") is not False or source.get("neqo_dirty") is not False
        or re.fullmatch(r"[0-9a-f]{40}", str(source.get("lab_commit"))) is None
        or source.get("neqo_commit") != source.get("neqo_pinned_commit")):
        raise ValueError("parallel runtime source is not clean and pinned")
    campaigns = []
    for row in value["campaigns"]:
        if (not isinstance(row, dict) or set(row) != {"path", "sha256"}
            or not isinstance(row["path"], str) or not Path(row["path"]).is_absolute()
            or str(Path(row["path"])) != row["path"] or ".." in Path(row["path"]).parts
            or any(c in row["path"] for c in ("\n", "\r", "\0", ":"))
            or not Path(row["path"]).is_relative_to(root)
            or re.fullmatch(r"[0-9a-f]{64}", str(row["sha256"])) is None
            or sha(read(Path(row["path"]))) != row["sha256"]):
            raise ValueError("parallel campaign binding differs")
        campaigns.append(row["path"])
    if len(set(campaigns)) != 2:
        raise ValueError("parallel rehearsal requires two distinct campaigns")
    return value


def host_source(value: dict[str, Any]) -> None:
    """The host cannot select a different verifier checkout with old metadata."""
    runtime = value["runtime"]
    source = load(Path(runtime["source_manifest"]))
    root = Path(runtime["runtime_source_root"])
    def git(where, *args):
        return subprocess.run(["git", "-C", str(where), *args], check=True,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()
    if (git(root, "rev-parse", "HEAD") != source["lab_commit"]
        or git(root, "status", "--porcelain", "--untracked-files=no")
        or git(root / "neqo-qcsd", "rev-parse", "HEAD") != source["neqo_commit"]
        or git(root / "neqo-qcsd", "status", "--porcelain", "--untracked-files=no")
        or git(root, "ls-tree", "HEAD", "neqo-qcsd").split()[:3]
        != ["160000", "commit", source["neqo_commit"]]):
        raise ValueError("parallel host requires the exact clean collection checkout and Native Gitlink")
    executed_root = Path(__file__).resolve().parent
    declared_root = root / "src/qcsd_lab"
    expected = {item.relative_to(declared_root).as_posix(): sha(read(item))
                for item in declared_root.rglob("*.py")}
    tracked = {item.removeprefix("src/qcsd_lab/") for item in git(root, "ls-files", "src/qcsd_lab").splitlines()
               if item.endswith(".py")}
    if tracked != set(expected):
        raise ValueError("parallel runtime Python inventory contains untracked source")
    observed = {item.relative_to(executed_root).as_posix(): sha(read(item))
                for item in executed_root.rglob("*.py")}
    if observed != expected:
        raise ValueError("parallel host verifier package differs from the clean collection source")


def _campaigns(value: dict[str, Any]):
    from .orchestrator import load_campaign
    campaigns = [load_campaign(Path(row["path"])) for row in value["campaigns"]]
    if {campaign.defenses[0].name for campaign in campaigns if len(campaign.defenses) == 1} != {"buflo", "cs-buflo"}:
        raise ValueError("parallel rehearsal needs one BuFLO and one CS-BuFLO lane")
    for campaign in campaigns:
        if (campaign.schema_version != 1 or campaign.purpose != "smoke"
            or re.fullmatch(r"rapid-curated-tranco50-v2-diagnostic-[a-z0-9]+(?:-[a-z0-9]+)*", campaign.name) is None
            or campaign.profile != "research-1200" or campaign.request_policies != ("as-defined",)
            or len(campaign.defenses) != 1 or not campaign.workloads
            or any(workload.visits != 1 for workload in campaign.workloads)
            or campaign.chaff_qualification_set is None
            or any(workload.qualification_set_manifest_sha256 is None for workload in campaign.workloads)
            or len({workload.qualification_set_manifest_sha256 for workload in campaign.workloads}) != 1):
            raise ValueError("parallel campaign is not a qualified zero-credit smoke lane")
    def inputs(campaign):
        return [(w.id, w.sha256, w.visits, w.qualification_set_manifest_sha256) for w in campaign.workloads]
    if (inputs(campaigns[0]) != inputs(campaigns[1])
        or campaigns[0].chaff_qualification_set != campaigns[1].chaff_qualification_set
        or campaigns[0].limits != campaigns[1].limits):
        raise ValueError("parallel lanes changed the paired workload/qualification/limits")
    return campaigns


def image_preflight(path: Path, expected_sha: str) -> dict[str, Any]:
    """Executed in the actual collection image before either worker exists."""
    from .rapid_lane_evidence import executed_image_runtime_check
    from .runtime_provenance import validate_runtime_receipt
    if sha(read(path)) != expected_sha:
        raise ValueError("parallel authority changed before image preflight")
    value = authority(path)
    proof = executed_image_runtime_check(value["runtime"])
    installed = validate_runtime_receipt(required_schema_version=2)
    source_root = Path(value["runtime"]["runtime_source_root"])
    for relative, digest in installed["source_files"].items():
        if sha(read(source_root / relative)) != digest:
            raise ValueError("parallel full installed runtime differs from its collection source")
    module_path = Path(value["runtime"]["runtime_source_root"]) / "src/qcsd_lab/rapid_parallel_capture.py"
    if read(Path(__file__)) != read(module_path):
        raise ValueError("parallel coordinator installed bytes differ from collection source")
    campaigns = _campaigns(value)
    files = {}
    hosts = set()
    for campaign in campaigns:
        paths = [campaign.path]
        for workload in campaign.workloads:
            origins = workload.data["preparation"]["approved_origins"]
            if not isinstance(origins, list) or not origins:
                raise ValueError("parallel inputs lack their complete approved-origin graph")
            for origin in origins:
                parsed = urlsplit(origin)
                if parsed.scheme != "https" or parsed.hostname is None:
                    raise ValueError("parallel approved origin is invalid")
                hosts.add(parsed.hostname)
            paths.extend(getattr(workload, key) for key in (
                "path", "chaff_qualification_path", "chaff_manifest_path",
                "qualification_set_manifest_path") if getattr(workload, key) is not None)
        for defense in campaign.defenses:
            paths.extend(getattr(defense, key) for key in ("parameters_path", "parameters_provenance_path")
                         if getattr(defense, key) is not None)
        for item in paths:
            files[str(item)] = sha(read(item))
    return {"runtime": proof, "authority_sha256": expected_sha,
            "python_runtime_receipt": installed,
            "parallel_module_sha256": sha(read(module_path)),
            "approved_hostnames": sorted(hosts),
            "input_files": files,
            "campaigns": [{"name": c.name, "mode": c.defenses[0].name,
                           "workloads": {w.id: w.sha256 for w in c.workloads},
                           "qualification_manifest_sha256": c.workloads[0].qualification_set_manifest_sha256}
                          for c in campaigns],
            "formal_accepted_trace_count": 0, "scientific_credit": False}


def reopen_preflight(output: Path, expected_sha: str) -> dict[str, Any]:
    proof = load(output / "image-preflight.json")
    if proof["authority_sha256"] != expected_sha:
        raise ValueError("parallel preflight names another authority")
    for path, digest in proof["input_files"].items():
        if sha(read(Path(path))) != digest:
            raise ValueError("parallel preflight workload/qualification/traffic inputs changed")
    return proof


def select_pairs(available: list[int]) -> dict[str, Any]:
    if (not isinstance(available, list) or len(available) < 5
        or available != sorted(set(available))
        or any(type(cpu) is not int or cpu < 0 for cpu in available)
        or available[-4] < 1):
        raise ValueError("optional two-worker capture needs five available CPU IDs (four protected, one residual)")
    return {"pairs": [available[-4:-2], available[-2:]], "sidecar_cpus": available[:-4]}


def initialize(path: Path, output: Path, expected_sha: str, available: list[int]) -> dict[str, Any]:
    value = authority(path)
    if sha(read(path)) != expected_sha:
        raise ValueError("parallel authority changed before launch")
    output = regular_dir(output)
    preflight = reopen_preflight(output, expected_sha)
    dns = load(output / "dns-pins.json")
    expected_hosts = preflight["approved_hostnames"]
    if (dns.get("schema_version") != 1 or dns.get("campaign") != preflight["campaigns"][0]["name"]
        or [row[0] for row in dns["hosts"]] != expected_hosts
        or any(not isinstance(row, list) or len(row) != 2 or not isinstance(row[1], str)
               or ipaddress.ip_address(row[1]).version != 4 or not ipaddress.ip_address(row[1]).is_global
               or str(ipaddress.ip_address(row[1])) != row[1] for row in dns["hosts"])):
        raise ValueError("parallel DNS pins differ from the complete paired origin graph")
    cpu = select_pairs(available)
    for index in range(2):
        lane = output / f"lane-{index + 1}"
        lane.mkdir()
        for name in ("results", "capture", "gate"):
            (lane / name).mkdir()
    put(output / "batch-intent.json", {"schema_version": 1, "authority_sha256": expected_sha,
        "authority": value, "created_at": now(), "cpu_selection": cpu,
        "image_preflight_sha256": sha(read(output / "image-preflight.json")),
        "dns_pin_sha256": sha(read(output / "dns-pins.json")),
        "preflight": preflight,
        "formal_accepted_trace_count": 0, "scientific_credit": False})
    return cpu


def release(path: Path, output: Path, actual: dict[str, Any]) -> None:
    """Close exact actual Docker identities before making either gate visible."""
    from .process_scheduler import build_peer_host_partition
    value = authority(path)
    intent = load(output / "batch-intent.json")
    if intent["authority_sha256"] != sha(read(path)):
        raise ValueError("parallel authority changed before gate release")
    if sha(read(output / "image-preflight.json")) != intent["image_preflight_sha256"]:
        raise ValueError("parallel preflight receipt changed before gate release")
    reopen_preflight(output, intent["authority_sha256"])
    if sha(read(output / "dns-pins.json")) != intent["dns_pin_sha256"]:
        raise ValueError("parallel DNS pins changed before gate release")
    workers = actual["workers"]
    sidecars = actual["sidecars"]
    if (len(workers) != 2 or len(sidecars) != 2
        or any(row["image_id"] != value["runtime"]["collection_image_digest"] for row in workers)
        or len({row["id"] for row in workers}) != 2
        or [ [w["client_cpu"], w["orchestrator_cpu"]] for w in workers] != intent["cpu_selection"]["pairs"]):
        raise ValueError("parallel actual workers differ from the prospective intent")
    partitions = [build_peer_host_partition(actual["inspected_containers"], actual["available_cpus"],
                  workers, sidecars, w["id"], docker_ncpu=actual["docker_ncpu"]) for w in workers]
    # Both independently derived proofs must pass before either release exists.
    put(output / "batch-launch.json", {"schema_version": 1, "started_at": now(),
        "authority_sha256": intent["authority_sha256"], "actual": actual,
        "host_pid": os.getppid(), "formal_accepted_trace_count": 0, "scientific_credit": False})
    for index, partition in enumerate(partitions):
        gate = output / f"lane-{index + 1}" / "gate"
        digest = put(gate / "host-partition.json", partition)
        put(gate / "release.json", {"authority_sha256": intent["authority_sha256"],
            "host_partition_sha256": digest, "worker_id": workers[index]["id"],
            "campaign": "/lab/" + str(Path(value["campaigns"][index]["path"]).relative_to(value["runtime"]["execution_root"]))})


def gate(path: Path, expected_sha: str, index: int, authority_path: Path) -> None:
    """Trusted installed gate runs before collection-entrypoint, without traffic."""
    directory = regular_dir(path)
    if type(index) is not int or index not in (0, 1):
        raise ValueError("parallel worker index is not one of the two declared lanes")
    deadline = time.monotonic() + 120
    while not (directory / "release.json").exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("parallel launch gate was not released within 120 seconds")
        time.sleep(.1)
    value = load(directory / "release.json")
    inputs = authority(authority_path)
    campaign = "/lab/" + str(Path(inputs["campaigns"][index]["path"]).relative_to(inputs["runtime"]["execution_root"]))
    if (sha(read(authority_path)) != expected_sha
        or value["authority_sha256"] != expected_sha or value["campaign"] != campaign):
        raise ValueError("parallel worker received another authority")
    raw = read(directory / "host-partition.json")
    if sha(raw) != value["host_partition_sha256"]:
        raise ValueError("parallel worker host partition changed")
    proof = json.loads(raw)
    worker = proof["declared_workers"][index]
    if (proof["measured_container_id"] != value["worker_id"]
        or worker["id"] != value["worker_id"]
        or str(worker["client_cpu"]) != os.environ.get("QCSD_CAPTURE_CLIENT_CPU")
        or str(worker["orchestrator_cpu"]) != os.environ.get("QCSD_CAPTURE_ORCHESTRATOR_CPU")):
        raise ValueError("parallel worker host partition names another worker")
    os.environ.pop("QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_B64", None)
    os.environ["QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_FILE"] = str(directory / "host-partition.json")
    os.environ["QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_SHA256"] = value["host_partition_sha256"]
    os.execv("/usr/local/bin/collection-entrypoint", ["collection-entrypoint", "run", value["campaign"]])


def _verify_retirement_actual(output: Path, index: int, actual: dict[str, Any]) -> dict[str, Any]:
    """Validate the producer's observations again without writing evidence."""
    launch = load(output / "batch-launch.json")
    if type(index) is not int or index not in (0, 1):
        raise ValueError("parallel retirement names an undeclared lane")
    worker = launch["actual"]["workers"][index]
    expected = {worker["id"], launch["actual"]["lane_resources"][index]["router_id"],
                launch["actual"]["lane_resources"][index]["network_id"]}
    if (actual["absent_ids"] != sorted(expected)
        or type(actual["worker_exit_code"]) is not int
        or actual["worker_terminal"]["Id"] != worker["id"]
        or actual["worker_terminal"]["State"]["Running"] is not False
        or actual["worker_terminal"]["State"]["ExitCode"] != actual["worker_exit_code"]):
        raise ValueError("parallel lane retirement lacks its exact observed terminal/absence")
    _worker_identity(actual["worker_terminal"], worker)
    peer = launch["actual"]["workers"][1-index]
    if actual.get("peer_retirement_sha256") is not None:
        prior = output / f"lane-{2-index}" / "retirement.json"
        if sha(read(prior)) != actual["peer_retirement_sha256"]:
            raise ValueError("parallel peer retirement binding changed")
        state = load(prior)["actual"]["worker_terminal"]
    else:
        state = actual["peer_state"]
    _worker_identity(state, peer)
    return launch


def retire_lane(output: Path, index: int, actual: dict[str, Any]) -> None:
    """Record actual lane absence; an unaffected running peer is permitted."""
    launch = _verify_retirement_actual(output, index, actual)
    put(output / f"lane-{index+1}" / "retirement.json", {"schema_version": 1,
        "retired_at": now(), "actual": actual, "authority_sha256": launch["authority_sha256"],
        "formal_accepted_trace_count": 0, "scientific_credit": False})


def _worker_identity(observed: dict[str, Any], expected: dict[str, Any]) -> None:
    from .process_scheduler import _cpu_list
    if (observed.get("Id") != expected["id"] or observed.get("Image") != expected["image_id"]
        or observed.get("Name", "").removeprefix("/") != expected["name"]
        or _cpu_list(observed["HostConfig"]["CpusetCpus"])
           != {expected["client_cpu"], expected["orchestrator_cpu"]}
        or observed["Config"]["Labels"].get("org.qcsd.owner") != "qcsd-lab"):
        raise ValueError("parallel retirement changed a declared worker identity or CPU pair")


def verify_results(path: Path, output: Path) -> dict[str, Any]:
    from .verification import verify_result
    value = authority(path)
    verify_operator_closure(path, output, value)
    reopen_launch(path, output, value)
    campaigns = _campaigns(value)
    intent = load(output / "batch-intent.json")
    if (intent["authority_sha256"] != sha(read(path))
        or sha(read(output / "image-preflight.json")) != intent["image_preflight_sha256"]
        or sha(read(output / "dns-pins.json")) != intent["dns_pin_sha256"]):
        raise ValueError("parallel prelaunch bindings changed before verification")
    preflight = reopen_preflight(output, intent["authority_sha256"])
    source = load(Path(value["runtime"]["source_manifest"]))
    results = []
    for index, campaign in enumerate(campaigns):
        retirement = load(output / f"lane-{index+1}" / "retirement.json")
        launch = _verify_retirement_actual(output, index, retirement["actual"])
        if retirement["authority_sha256"] != launch["authority_sha256"]:
            raise ValueError("parallel retirement names another launch authority")
        row = {"campaign": campaign.name, "valid": False, "accepted": 0,
               "actual_exit_code": retirement["actual"]["worker_exit_code"]}
        roots = list((output / f"lane-{index+1}" / "results" / campaign.name).glob("*"))
        try:
            if len(roots) != 1 or not roots[0].is_dir():
                raise ValueError("parallel lane lacks one exact result root")
            result = verify_result(roots[0])
            experiment = result.experiment
            configuration = experiment["configuration"]
            slots = [(s["workload_id"], s["visit"], s["defense"]) for s in experiment["samples"]]
            expected = [(w.id, 0, campaign.defenses[0].name) for w in campaign.workloads]
            partition = load(output / f"lane-{index+1}" / "gate/host-partition.json")
            verify_peer_sample_bindings(experiment, partition)
            if (row["actual_exit_code"] != 0 or experiment["status"] != "complete"
                or experiment["purpose"] != "smoke" or experiment["name"] != campaign.name
                or configuration["campaign_sha256"] != sha(campaign.source_bytes)
                or {w["id"]: w["sha256"] for w in configuration["workloads"]}
                   != preflight["campaigns"][index]["workloads"]
                or configuration["chaff_qualification_set_manifest_sha256"]
                   != preflight["campaigns"][index]["qualification_manifest_sha256"]
                or experiment["source"]["image_digest"] != value["runtime"]["collection_image_digest"]
                or experiment["source"]["lab_commit"] != source["lab_commit"]
                or experiment["source"]["lab_dirty"] is not False
                or sorted(slots) != sorted(expected)
                or any(s["state"] != "accepted" for s in experiment["samples"])
                or experiment["summary"]["passed"] is not True):
                raise ValueError("parallel deep result differs from the exact smoke lane")
            launch = load(output / "batch-launch.json")
            if (datetime.fromisoformat(experiment["started_at"].replace("Z", "+00:00"))
                < datetime.fromisoformat(launch["started_at"].replace("Z", "+00:00"))):
                raise ValueError("parallel result predates the actual two-worker launch")
            row.update(valid=True, accepted=len(expected), result_root=str(roots[0]),
                       result_seal_sha256=sha(read(roots[0] / "evidence.sha256")))
        except (OSError, ValueError, KeyError, TypeError) as error:
            row["error"] = f"{type(error).__name__}: {error}"
        results.append(row)
    host_returncode = load(output / "host-process.json")["returncode"]
    return {"schema_version": 1, "lanes": results,
            "valid": host_returncode == 0 and all(row["valid"] for row in results),
            "host_returncode": host_returncode,
            "formal_accepted_trace_count": 0, "scientific_credit": False}


def reopen_launch(path: Path, output: Path, value: dict[str, Any]) -> None:
    """Bind current gate and Docker observations to the same actual launch."""
    from .process_scheduler import build_peer_host_partition
    intent = load(output / "batch-intent.json")
    launch = load(output / "batch-launch.json")
    actual = load(output / "actual-launch.json")
    digest = sha(read(path))
    if (launch["authority_sha256"] != digest or intent["authority_sha256"] != digest
        or launch["actual"] != actual
        or actual["available_cpus"] != intent["cpu_selection"]["sidecar_cpus"]
           + intent["cpu_selection"]["pairs"][0] + intent["cpu_selection"]["pairs"][1]
        or [[w["client_cpu"], w["orchestrator_cpu"]] for w in actual["workers"]]
           != intent["cpu_selection"]["pairs"]
        or any(w["image_id"] != value["runtime"]["collection_image_digest"] for w in actual["workers"])):
        raise ValueError("parallel actual launch differs from its prospective authority or CPU allocation")
    for index, worker in enumerate(actual["workers"]):
        gate = output / f"lane-{index+1}" / "gate"
        release_value = load(gate / "release.json")
        partition = load(gate / "host-partition.json")
        expected = build_peer_host_partition(actual["inspected_containers"], actual["available_cpus"],
            actual["workers"], actual["sidecars"], worker["id"], docker_ncpu=actual["docker_ncpu"])
        expected["captured_at_unix_ns"] = partition["captured_at_unix_ns"]
        campaign = "/lab/" + str(Path(value["campaigns"][index]["path"]).relative_to(value["runtime"]["execution_root"]))
        if (partition != expected or release_value["authority_sha256"] != digest
            or release_value["worker_id"] != worker["id"] or release_value["campaign"] != campaign
            or release_value["host_partition_sha256"] != sha(read(gate / "host-partition.json"))):
            raise ValueError("parallel lane gate no longer binds this actual worker and Docker observation")


def retire_session(path: Path, output: Path) -> dict[str, Any]:
    """Whole-session loss uses the existing global quiescence observation."""
    from . import rapid_lane_evidence as ordinary
    inputs = authority(path)
    host_source(inputs)
    start = load(output / "host-start.json")
    command = [inputs["runtime"]["host_launcher"], "parallel-diagnostic-run", str(path), str(output)]
    if (start["command"] != command or start["authority_sha256"] != sha(read(path))
        or (output / "deep-verification.json").exists()):
        raise ValueError("parallel session retirement differs from the actual launch")
    with ordinary.capture_lock(Path(inputs["runtime"]["execution_root"])):
        retired = {key: ordinary._retired_identity(start[key]) for key in ("host", "operator")}
        with ordinary.capture_lock(Path(inputs["runtime"]["execution_root"]), lifecycle=True) as fd:
            checks = ordinary._retirement_quiescence(output, fd)
            if retired != {key: ordinary._retired_identity(start[key]) for key in retired}:
                raise ValueError("parallel original host identity changed during retirement")
            result = {"schema_version": 1, "observed_at": now(), "host_start_sha256": sha(read(output / "host-start.json")),
                      "retired_processes": retired, "checks": checks,
                      "formal_accepted_trace_count": 0, "scientific_credit": False}
            put(output / "session-retirement.json", result)
            return result


def verify_peer_sample_bindings(experiment: dict[str, Any], partition: dict[str, Any]) -> None:
    """Additional launch identity binding after the ordinary deep verifier."""
    from .process_scheduler import _host_partition_valid
    if partition.get("schema_version") != 5 or not _host_partition_valid(partition):
        raise ValueError("parallel result needs the actual validated peer partition")
    samples = experiment.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ValueError("parallel result has no accepted sample proof")
    for sample in samples:
        try:
            evidence = sample["diagnostics"]["scheduler_runtime_receipt"]["scheduler_runtime_evidence"]
            if sample["state"] != "accepted" or evidence["schema_version"] != 5 or evidence["host_partition"] != partition:
                raise ValueError("parallel sample does not retain this actual worker partition")
        except (KeyError, TypeError) as error:
            raise ValueError("parallel sample lacks its peer-aware scheduler proof") from error


def verify_operator_closure(path: Path, output: Path, value: dict[str, Any]) -> None:
    """Reopen the actual gated host invocation and its closed raw outputs."""
    from .rapid_lane_evidence import HOST_GATE_SCRIPT
    start = load(output / "host-start.json")
    process = load(output / "host-process.json")
    intent = load(output / "operator-intent.json")
    command = [value["runtime"]["host_launcher"], "parallel-diagnostic-run", str(path), str(output)]
    argv = start["host"]["argv"]
    if (intent["command"] != command or start["command"] != command or process["command"] != command
        or intent["authority_sha256"] != sha(read(path)) or start["authority_sha256"] != sha(read(path))
        or start["gate_script_sha256"] != sha(HOST_GATE_SCRIPT.encode())
        or len(argv) != 5 or argv[1:3] != ["-c", HOST_GATE_SCRIPT]
        or json.loads(argv[3]) != command or not argv[4].isdigit()
        or process["host_start_sha256"] != sha(read(output / "host-start.json"))
        or process["stdout_sha256"] != sha(read(output / "host.stdout"))
        or process["stderr_sha256"] != sha(read(output / "host.stderr"))
        or type(process["returncode"]) is not int or process["started_at"] != start["started_at"]
        or datetime.fromisoformat(process["completed_at"].replace("Z", "+00:00"))
           < datetime.fromisoformat(start["started_at"].replace("Z", "+00:00"))):
        raise ValueError("parallel actual host process or raw outputs differ from the prospective launch")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("select", "initialize", "preflight", "release", "gate", "retire", "verify"))
    parser.add_argument("--authority", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sha256")
    parser.add_argument("--actual", type=Path)
    parser.add_argument("--cpus")
    parser.add_argument("--index", type=int)
    args = parser.parse_args(argv)
    if args.action == "select":
        value = authority(args.authority, execution_root=args.output)
        host_source(value)
        print(value["campaigns"][0]["path"])
    elif args.action == "initialize":
        print(json.dumps(initialize(args.authority, args.output, args.sha256, json.loads(args.cpus))))
    elif args.action == "preflight":
        print(json.dumps(image_preflight(args.authority, args.sha256), sort_keys=True))
    elif args.action == "release":
        release(args.authority, args.output, load(args.actual))
    elif args.action == "gate":
        gate(args.output, args.sha256, args.index, args.authority)
    elif args.action == "retire":
        retire_lane(args.output, args.index, load(args.actual))
    else:
        print(json.dumps(verify_results(args.authority, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
