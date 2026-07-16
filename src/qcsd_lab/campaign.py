from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import random
import shutil
import signal
import subprocess
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml

from .manifest import validate_manifest
from .util import LAB_ROOT, atomic_json, git_commit, load_json, run, sha256_file, write_checksums

NEQO_CLIENT = os.environ.get("NEQO_QCSD_CLIENT", "/usr/local/bin/neqo-qcsd-client")


def _slug(value: str) -> str:
    return "".join(character if character.isalnum() or character in "-_" else "-" for character in value)


def _derived_seed(master_seed: int, workload: str, repetition: int, defense: str) -> int:
    material = f"{master_seed}:{workload}:{repetition}:{defense}".encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def load_campaign(path: Path) -> dict[str, Any]:
    campaign = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(campaign, dict) or campaign.get("schema_version") != 1:
        raise ValueError("campaign must use schema_version 1")
    if not campaign.get("workloads") or not campaign.get("defenses"):
        raise ValueError("campaign requires non-empty workloads and defenses")
    base = path.parent
    for workload in campaign["workloads"]:
        workload["manifest"] = str((base / workload["manifest"]).resolve())
    for defense in campaign["defenses"]:
        if "config" in defense:
            defense["config"] = str((base / defense["config"]).resolve())
        elif "preset" not in defense:
            raise ValueError(f"defense {defense.get('name')} requires config or preset")
    campaign.setdefault("repetitions", 1)
    campaign.setdefault("master_seed", 1)
    campaign.setdefault("timeout_seconds", 120)
    campaign.setdefault("max_response_bytes", 16 * 1024 * 1024)
    campaign.setdefault("capture_duration_seconds", campaign["timeout_seconds"] + 15)
    campaign.setdefault("capture_filesize_mb", 256)
    campaign.setdefault("inter_run_delay_seconds", 2)
    campaign.setdefault("keep_raw", False)
    campaign.setdefault("export_pcap", False)
    return campaign


def collect_campaign(path: Path, results_root: Path, *, force: bool = False) -> Path:
    campaign = load_campaign(path)
    name = _slug(campaign.get("name", path.stem))
    root = results_root / name
    root.mkdir(parents=True, exist_ok=True)
    expansion: dict[str, Any] = {"campaign": campaign, "blocks": []}
    for workload in campaign["workloads"]:
        manifest_path = Path(workload["manifest"])
        manifest = load_json(manifest_path)
        validate_manifest(manifest)
        workload_name = _slug(workload["name"])
        for repetition in range(campaign["repetitions"]):
            block = root / workload_name / f"rep-{repetition:03d}"
            block.mkdir(parents=True, exist_ok=True)
            order = list(campaign["defenses"])
            order_seed = _derived_seed(campaign["master_seed"], workload_name, repetition, "order")
            random.Random(order_seed).shuffle(order)
            block_record = {
                "workload": workload_name,
                "repetition": repetition,
                "order_seed": order_seed,
                "defense_order": [defense["name"] for defense in order],
            }
            expansion["blocks"].append(block_record)
            preflight_ok = _preflight(manifest_path, block / "preflight", campaign)
            if not preflight_ok:
                block_record["preflight"] = "failed"
                continue
            block_record["preflight"] = "passed"
            for position, defense in enumerate(order):
                sample = block / f"{position:02d}-{_slug(defense['name'])}"
                seed = _derived_seed(
                    campaign["master_seed"], workload_name, repetition, defense["name"]
                )
                _collect_sample(
                    sample,
                    manifest_path,
                    defense,
                    seed,
                    campaign,
                    campaign_path=path,
                    force=force,
                )
                if campaign["inter_run_delay_seconds"] and position + 1 < len(order):
                    time.sleep(campaign["inter_run_delay_seconds"])
            _compare_block(block)
    expansion["lab_commit"] = git_commit(LAB_ROOT)
    expansion["neqo_commit"] = git_commit(LAB_ROOT / "third_party/neqo-qcsd")
    expansion["image_digest"] = os.environ.get("QCSD_LAB_IMAGE_DIGEST", "unknown")
    atomic_json(root / "campaign.json", expansion)
    return root


def _preflight(manifest: Path, output: Path, campaign: dict[str, Any]) -> bool:
    if (output / "status.json").exists():
        return load_json(output / "status.json").get("passed", False)
    output.mkdir(parents=True, exist_ok=True)
    resolved = output / "resolved.json"
    command = [
        NEQO_CLIENT,
        "probe",
        "--input-manifest",
        str(manifest),
        "--output",
        str(resolved),
        "--max-bytes",
        str(campaign["max_response_bytes"]),
        "--timeout-seconds",
        str(campaign["timeout_seconds"]),
    ]
    result = run(command, log=output / "probe.log", check=False)
    passed = result.returncode == 0 and resolved.exists()
    if passed:
        resources = load_json(resolved).get("resources", [])
        passed = bool(resources) and all(resource.get("known_valid") for resource in resources)
    atomic_json(output / "status.json", {"passed": passed, "returncode": result.returncode})
    return passed


def _offload_metadata(interface: str) -> dict[str, Any]:
    before = run(["ethtool", "-k", interface], check=False)
    changes = {}
    for feature in ("gro", "gso", "tso"):
        result = run(["ethtool", "-K", interface, feature, "off"], check=False)
        changes[feature] = {"returncode": result.returncode, "output": result.stdout.strip()}
    after = run(["ethtool", "-k", interface], check=False)
    return {"interface": interface, "before": before.stdout, "changes": changes, "after": after.stdout}


def _collect_sample(
    sample: Path,
    manifest: Path,
    defense: dict[str, Any],
    seed: int,
    campaign: dict[str, Any],
    *,
    campaign_path: Path,
    force: bool,
) -> None:
    status_path = sample / "sample.json"
    if status_path.exists() and load_json(status_path).get("state") == "captured" and not force:
        return
    if sample.exists() and force:
        shutil.rmtree(sample)
    sample.mkdir(parents=True, exist_ok=True)
    neqo_output = sample / "neqo"
    raw_capture = sample / "raw.pcapng"
    filtered_capture = sample / "traffic.pcapng"
    interface = campaign.get("interface", "eth0")
    metadata: dict[str, Any] = {
        "schema_version": 1,
        "state": "running",
        "defense": defense["name"],
        "seed": seed,
        "workload": str(manifest),
        "workload_sha256": sha256_file(manifest),
        "campaign": str(campaign_path),
        "image_digest": os.environ.get("QCSD_LAB_IMAGE_DIGEST", "unknown"),
        "lab_commit": git_commit(LAB_ROOT),
        "neqo_commit": git_commit(LAB_ROOT / "third_party/neqo-qcsd"),
        "offloads": _offload_metadata(interface),
    }
    atomic_json(status_path, metadata)
    capture_command = [
        "dumpcap",
        "-q",
        "-i",
        interface,
        "-f",
        "udp",
        "-w",
        str(raw_capture),
        "-a",
        f"duration:{campaign['capture_duration_seconds']}",
        "-a",
        f"filesize:{campaign['capture_filesize_mb'] * 1024}",
    ]
    capture_log = (sample / "dumpcap.log").open("w", encoding="utf-8")
    capture = subprocess.Popen(capture_command, stdout=capture_log, stderr=subprocess.STDOUT, text=True)
    time.sleep(0.5)
    command = [
        NEQO_CLIENT,
        "run",
        "--workload",
        str(manifest),
        "--chaff-manifest",
        str(defense.get("chaff_manifest", manifest)),
        "--seed",
        str(seed),
        "--output-dir",
        str(neqo_output),
        "--max-response-bytes",
        str(campaign["max_response_bytes"]),
        "--timeout-seconds",
        str(campaign["timeout_seconds"]),
    ]
    if "config" in defense:
        command += ["--config", defense["config"]]
    else:
        command += ["--preset", defense["preset"]]
    result = run(command, log=sample / "neqo-client.log", check=False)
    if capture.poll() is None:
        capture.send_signal(signal.SIGINT)
    try:
        capture.wait(timeout=10)
    except subprocess.TimeoutExpired:
        capture.terminate()
        capture.wait(timeout=5)
    capture_log.close()

    metadata["runner_returncode"] = result.returncode
    metadata["capture_returncode"] = capture.returncode
    capture_info = run(["capinfos", "-a", "-e", "-c", "-s", str(raw_capture)], check=False)
    (sample / "capinfos.txt").write_text(capture_info.stdout, encoding="utf-8")
    metadata["capture_valid"] = capture_info.returncode == 0
    run_json = neqo_output / "run.json"
    if run_json.exists() and metadata["capture_valid"]:
        try:
            tuples = load_json(run_json).get("endpoints", [])
            display_filter = _tuple_filter(tuples)
            (sample / "capture-filter.txt").write_text(display_filter + "\n", encoding="utf-8")
            filtered = run(
                ["tshark", "-r", str(raw_capture), "-Y", display_filter, "-w", str(filtered_capture)],
                log=sample / "filter.log",
                check=False,
            )
            metadata["filter_returncode"] = filtered.returncode
            if filtered.returncode == 0:
                _extract_trace(filtered_capture, tuples, sample / "traffic.csv")
                if campaign["export_pcap"]:
                    run(["editcap", "-F", "pcap", str(filtered_capture), str(sample / "traffic.pcap")])
        except (KeyError, ValueError, RuntimeError) as error:
            metadata["filter_error"] = str(error)
            metadata["filter_returncode"] = 1
    trace = sample / "traffic.csv"
    trace_has_packets = trace.exists() and sum(1 for _ in trace.open(encoding="utf-8")) > 1
    success = (
        result.returncode == 0
        and metadata["capture_valid"]
        and filtered_capture.exists()
        and filtered_capture.stat().st_size > 0
        and trace_has_packets
    )
    metadata["state"] = "captured" if success else "failed"
    metadata["comparison_eligible"] = False
    if success and not campaign["keep_raw"]:
        raw_capture.unlink(missing_ok=True)
    atomic_json(status_path, metadata)
    files = [path for path in sample.rglob("*") if path.is_file() and path.name != "SHA256SUMS"]
    write_checksums(sample, files)


def _split_endpoint(value: str) -> tuple[str, int]:
    if value.startswith("["):
        address, port = value.rsplit("]:", 1)
        return address[1:], int(port)
    address, port = value.rsplit(":", 1)
    return address, int(port)


def _tuple_filter(endpoints: list[dict[str, Any]]) -> str:
    clauses = []
    for endpoint in endpoints:
        local_ip, local_port = _split_endpoint(endpoint["local_address"])
        remote_ip, remote_port = _split_endpoint(endpoint["remote_address"])
        field = "ipv6" if ipaddress.ip_address(local_ip).version == 6 else "ip"
        forward = (
            f"({field}.src=={local_ip} && udp.srcport=={local_port} && "
            f"{field}.dst=={remote_ip} && udp.dstport=={remote_port})"
        )
        reverse = (
            f"({field}.src=={remote_ip} && udp.srcport=={remote_port} && "
            f"{field}.dst=={local_ip} && udp.dstport=={local_port})"
        )
        clauses.append(f"({forward} || {reverse})")
    if not clauses:
        raise ValueError("run.json contains no endpoint tuples")
    return " || ".join(clauses)


def _extract_trace(capture: Path, endpoints: list[dict[str, Any]], output: Path) -> None:
    command = [
        "tshark",
        "-r",
        str(capture),
        "-T",
        "fields",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-e",
        "frame.time_epoch",
        "-e",
        "frame.len",
        "-e",
        "ip.src",
        "-e",
        "ipv6.src",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
    ]
    rows = list(csv.reader(run(command).stdout.splitlines()))
    local_ports: dict[int, int] = {}
    for endpoint in endpoints:
        _, port = _split_endpoint(endpoint["local_address"])
        local_ports[port] = int(endpoint["id"])
    first_ns = int(Decimal(rows[0][0]) * 1_000_000_000) if rows else 0
    with output.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.writer(destination)
        writer.writerow(
            ["timestamp_unix_ns", "relative_time_ns", "direction", "frame_len", "signed_frame_len", "connection"]
        )
        for row in rows:
            if len(row) < 6 or not row[0]:
                continue
            timestamp = int(Decimal(row[0]) * 1_000_000_000)
            frame_len = int(row[1])
            source_port = int(row[4])
            destination_port = int(row[5])
            outgoing = source_port in local_ports
            connection = local_ports.get(source_port, local_ports.get(destination_port, -1))
            writer.writerow(
                [
                    timestamp,
                    timestamp - first_ns,
                    "outgoing" if outgoing else "incoming",
                    frame_len,
                    frame_len if outgoing else -frame_len,
                    connection,
                ]
            )


def _compare_block(block: Path) -> None:
    samples = [path for path in sorted(block.iterdir()) if (path / "sample.json").exists()]
    baseline_names = {"none", "baseline", "undefended"}
    baseline = next(
        (
            path
            for path in samples
            if str(load_json(path / "sample.json")["defense"]).lower() in baseline_names
        ),
        None,
    )
    if baseline is None:
        baseline = next((path for path in samples if load_json(path / "sample.json")["state"] == "captured"), None)
    reference = _response_signature(baseline) if baseline else None
    for sample in samples:
        metadata = load_json(sample / "sample.json")
        signature = _response_signature(sample)
        drift = reference is not None and signature is not None and signature != reference
        metadata["content_drift"] = drift
        metadata["comparison_reference"] = str(baseline) if baseline else None
        metadata["comparison_eligible"] = (
            metadata["state"] == "captured"
            and reference is not None
            and signature is not None
            and not drift
        )
        atomic_json(sample / "sample.json", metadata)
        files = [
            path
            for path in sample.rglob("*")
            if path.is_file() and path.name != "SHA256SUMS"
        ]
        write_checksums(sample, files)


def _response_signature(sample: Path | None) -> list[tuple[Any, ...]] | None:
    if sample is None:
        return None
    run_json = sample / "neqo" / "run.json"
    if not run_json.exists():
        return None
    responses = load_json(run_json).get("responses", [])
    return sorted(
        (
            response.get("resource_id"),
            response.get("status"),
            response.get("bytes"),
            response.get("body_sha256"),
            response.get("outcome"),
        )
        for response in responses
    )
