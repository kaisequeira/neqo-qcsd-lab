"""Independent, local verification of a resource-domain session.

The ledger never accepts a collector's success flag as its only proof. This
reader joins the frozen URLs, Native application results, encrypted packets,
normalized trace, clocks and defense realization without historical ancestry.
"""
from __future__ import annotations

import hashlib
import csv
import ipaddress
import json
from pathlib import Path, PurePosixPath
import struct
import re
from typing import Any, Iterator
from urllib.parse import urlsplit

from .capture import read_normalized_trace, split_endpoint, offload_evidence_is_valid
from .resource_study_inputs import MODES, canonical_json, normalize_url, sha256_file

ACCEPTANCE = "resource-domain-20-complete-h3-fresh-connection-pre-nat-v1"
SHA = re.compile(r"[0-9a-f]{64}\Z")
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def _initial(payload: bytes) -> bool:
    if len(payload) < 7 or payload[0] & 0xc0 != 0xc0:
        return False
    version = struct.unpack_from("!I", payload, 1)[0]
    if not ((version == 1 and payload[0] & 0x30 == 0)
            or (version == 0x6b3343cf and payload[0] & 0x30 == 0x10)):
        return False
    offset = 5
    for _ in range(2):
        if offset >= len(payload):
            raise ValueError("truncated QUIC connection ID length")
        size = payload[offset]
        offset += 1
        if size > 20 or offset + size > len(payload):
            raise ValueError("truncated QUIC connection ID")
        offset += size
    def varint(position):
        if position >= len(payload):
            raise ValueError("truncated QUIC variable integer")
        width = 1 << (payload[position] >> 6)
        if position + width > len(payload):
            raise ValueError("truncated QUIC variable integer")
        return (int.from_bytes(payload[position:position + width], "big")
                & ((1 << (8 * width - 2)) - 1)), position + width
    token_size, offset = varint(offset)
    offset += token_size
    length, offset = varint(offset)
    if length < 17 or offset + length > len(payload):
        raise ValueError("truncated QUIC Initial packet")
    return True


def load(path: Path) -> dict[str, Any]:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("JSON repeats a field")
            value[key] = item
        return value
    value = json.loads(path.read_bytes(), object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def within(root: Path, relative: str) -> Path:
    name = PurePosixPath(relative)
    if (not isinstance(relative, str) or name.is_absolute() or ".." in name.parts
            or not name.parts or str(name) != relative):
        raise ValueError("artifact path must be canonical and relative")
    path = root / relative
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
        raise ValueError("artifact is not a regular unlinked file")
    return path


def _options(raw: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset < len(raw):
        if offset + 4 > len(raw):
            raise ValueError("truncated PCAPNG option")
        kind, size = struct.unpack_from(endian + "HH", raw, offset)
        offset += 4
        if kind == 0:
            if size:
                raise ValueError("invalid end option")
            return
        if offset + size > len(raw):
            raise ValueError("truncated PCAPNG option body")
        yield kind, raw[offset:offset + size]
        offset += (size + 3) & ~3


def packets(path: Path, five_tuple: list[Any], *, require_fresh=True) -> list[dict[str, Any]]:
    """Read the declared Ethernet, nonfragmented IP/UDP primary PCAPNG.

    Unsupported link types, truncation and off-tuple packets fail closed. No
    Wireshark installation is required for verification after migration.
    """
    local_ip, local_port, remote_ip, remote_port, protocol = five_tuple
    if protocol != 17:
        raise ValueError("session protocol is not UDP")
    endpoint = (local_ip, local_port, remote_ip, remote_port)
    interfaces: list[tuple[int, int, int]] = []
    endian = None
    observed = []
    with path.open("rb") as handle:
        while True:
            head = handle.read(12)
            if not head:
                break
            if len(head) != 12:
                raise ValueError("truncated PCAPNG block")
            if head[:4] == b"\x0a\x0d\x0d\x0a":
                if head[8:12] == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif head[8:12] == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise ValueError("invalid PCAPNG byte-order magic")
                interfaces = []
            if endian is None:
                raise ValueError("PCAPNG section header is absent")
            kind, size = struct.unpack_from(endian + "II", head)
            if size < 12 or size % 4 or size > 64 * 1024 * 1024:
                raise ValueError("invalid PCAPNG block size")
            remaining = handle.read(size - 12)
            raw = head + remaining
            if len(raw) != size or struct.unpack_from(endian + "I", raw, size - 4)[0] != size:
                raise ValueError("truncated or inconsistent PCAPNG block")
            body = raw[8:-4]
            if kind == 1:
                if len(body) < 8:
                    raise ValueError("truncated interface description")
                link, _, snaplen = struct.unpack_from(endian + "HHI", body)
                divisor, offset = 1_000_000, 0
                for option, value in _options(body[8:], endian):
                    if option == 9:
                        if len(value) != 1:
                            raise ValueError("invalid timestamp resolution")
                        divisor = (2 ** (value[0] & 127) if value[0] & 128 else 10 ** value[0])
                    elif option == 14:
                        if len(value) != 8:
                            raise ValueError("invalid timestamp offset")
                        offset = struct.unpack(endian + "q", value)[0]
                if link != 1:
                    raise ValueError("primary capture must use Ethernet")
                interfaces.append((divisor, offset, snaplen))
            elif kind == 6:
                if len(body) < 20:
                    raise ValueError("truncated enhanced packet block")
                interface, hi, lo, captured, original = struct.unpack_from(endian + "IIIII", body)
                if (interface >= len(interfaces) or captured != original
                        or captured < 42 or captured + 20 > len(body)):
                    raise ValueError("packet is truncated or has no declared interface")
                divisor, clock_offset, snaplen = interfaces[interface]
                if snaplen and captured > snaplen:
                    raise ValueError("packet exceeds capture snap length")
                frame = body[20:20 + captured]
                ethertype = struct.unpack_from("!H", frame, 12)[0]
                if ethertype == 0x0800:
                    if len(frame) < 42 or frame[14] >> 4 != 4:
                        raise ValueError("invalid IPv4 frame")
                    ihl = (frame[14] & 15) * 4
                    total = struct.unpack_from("!H", frame, 16)[0]
                    if (ihl < 20 or frame[23] != 17 or total + 14 > len(frame)
                            or struct.unpack_from("!H", frame, 20)[0] & 0x3fff):
                        raise ValueError("primary capture contains non-UDP or fragmented IPv4")
                    source = str(ipaddress.ip_address(frame[26:30]))
                    destination = str(ipaddress.ip_address(frame[30:34]))
                    start, ip_end = 14 + ihl, 14 + total
                elif ethertype == 0x86dd:
                    if len(frame) < 62 or frame[14] >> 4 != 6 or frame[20] != 17:
                        raise ValueError("IPv6 extensions are outside the capture contract")
                    source = str(ipaddress.ip_address(frame[22:38]))
                    destination = str(ipaddress.ip_address(frame[38:54]))
                    start = 54
                    ip_end = start + struct.unpack_from("!H", frame, 18)[0]
                else:
                    raise ValueError("non-IP frame in primary UDP capture")
                if start + 8 > ip_end or ip_end > len(frame):
                    raise ValueError("invalid UDP boundary")
                source_port, destination_port, udp_length = struct.unpack_from("!HHH", frame, start)
                if udp_length < 8 or start + udp_length != ip_end:
                    raise ValueError("inconsistent UDP length")
                key = (source, source_port, destination, destination_port)
                if key == endpoint:
                    direction = "outgoing"
                elif (destination, destination_port, source, source_port) == endpoint:
                    direction = "incoming"
                else:
                    raise ValueError("primary packet is outside the recorded five-tuple")
                payload = frame[start + 8:ip_end]
                initial = _initial(payload)
                observed.append({"timestamp_unix_ns": (((hi << 32) | lo) * 1_000_000_000) // divisor
                                 + clock_offset * 1_000_000_000,
                                 "direction": direction, "length_bytes": original,
                                 "udp_payload_bytes": udp_length - 8, "initial": initial,
                                 "packet_index": len(observed), "source_address": f"[{source}]:{source_port}" if ":" in source else f"{source}:{source_port}",
                                 "destination_address": f"[{destination}]:{destination_port}" if ":" in destination else f"{destination}:{destination_port}",
                                 "datagram_sha256": hashlib.sha256(payload).hexdigest()})
            elif kind in {2, 3}:
                raise ValueError("unverifiable packet block in primary capture")
    if not observed:
        raise ValueError("empty primary capture")
    if require_fresh and not any(p["initial"] and p["direction"] == "outgoing" for p in observed):
        raise ValueError("capture lacks a fresh outgoing QUIC Initial")
    if require_fresh and not any(p["initial"] and p["direction"] == "incoming" for p in observed):
        raise ValueError("capture lacks a server QUIC Initial")
    observed.sort(key=lambda p: p["timestamp_unix_ns"])
    return observed


def application_stream_overlap(path: Path) -> dict[str, int]:
    opened, active, maximum = set(), set(), 0
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row.get("event") != "observation" or row.get("outcome") != "recorded":
                continue
            detail = json.loads(row["details"])
            kind = detail.get("type")
            identity = (detail.get("endpoint"), detail.get("stream"))
            if kind == "stream_opened" and detail.get("role") == "application":
                if identity in opened:
                    raise ValueError("application stream is recorded twice")
                opened.add(identity)
                active.add(identity)
                maximum = max(maximum, len(active))
            elif kind == "stream_finished":
                active.discard(identity)
    return {"application_streams_opened": len(opened), "maximum_open_application_streams": maximum}


def verify_receipt(root: Path, receipt: dict[str, Any]) -> dict[str, Any]:
    """Return independently derived facts or raise; suitable for StudyStore."""
    from .fidelity import (reconcile_direct_runner_artifacts, validate_primary_capture_clock_integrity,
                           _schedule_realization_metrics_from_path, fidelity_eligible)
    root = Path(root).absolute()
    if (receipt.get("schema_version") != 1 or receipt.get("verified") is not True
            or receipt.get("record_type") != "qcsd-resource-domain-session-verification-v1"
            or receipt.get("acceptance") != ACCEPTANCE or receipt.get("mode") not in MODES):
        raise ValueError("session verification contract differs")
    files = receipt.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("session artifact inventory is absent")
    for relative, digest in files.items():
        if sha256_file(within(root, relative)) != digest:
            raise ValueError("session artifact bytes changed")
    paths = receipt["artifact_paths"]
    required = {"run", "packets", "pcap", "trace", "collector", "workload", "enrollment"}
    if not required.issubset(paths) or any(name not in files for name in paths.values()):
        raise ValueError("required raw artifact is not bound")
    artifact = {key: within(root, relative) for key, relative in paths.items()}
    enrollment = load(artifact["enrollment"])
    urls = enrollment["urls"]
    host = receipt["hostname"]
    if (enrollment["hostname"] != host or len(urls) != 20 or len(set(urls)) != 20
            or any(normalize_url(url) != url or urlsplit(url).hostname != host for url in urls)
            or enrollment["workload_sha256"] != sha256_file(artifact["workload"])
            or receipt["workload_sha256"] != enrollment["workload_sha256"]):
        raise ValueError("session differs from the frozen resource set")
    workload = load(artifact["workload"])
    resources = workload["resources"]
    if (len(resources) != 20 or any(type(resource.get("id")) is not int for resource in resources)
            or [resource["url"] for resource in resources] != urls
            or [resource["id"] for resource in resources] != list(range(20))
            or any(resource.get("known_valid") is not True or resource.get("depends_on") != []
                   or resource.get("chaff_priority") is not False for resource in resources)):
        raise ValueError("Native workload URLs differ")
    run = load(artifact["run"])
    if (run.get("method") != "GET" or run.get("request_policy") != "as-defined"
            or type(run.get("max_response_bytes")) is not int or run["max_response_bytes"] != MAX_RESPONSE_BYTES
            or run.get("completion_status") != "complete" or run.get("error") is not None
            or run.get("error_class") is not None or run.get("terminal_evidence_render_errors") != []
            or run.get("workload_hash_sha256") != enrollment["workload_sha256"]
            or type(run.get("started_unix_ns")) is not int
            or type(run.get("ended_unix_ns")) is not int
            or run["started_unix_ns"] >= run["ended_unix_ns"]):
        raise ValueError("Native run did not complete coherently")
    responses = run.get("responses")
    if not isinstance(responses, list) or len(responses) != 20:
        raise ValueError("exactly twenty complete application responses required")
    if any(type(r.get("resource_id")) is not int for r in responses):
        raise ValueError("application response IDs must be integers")
    by_id = {r.get("resource_id"): r for r in responses}
    if len(by_id) != 20 or set(by_id) != {r["id"] for r in resources}:
        raise ValueError("application response IDs are duplicated or missing")
    for resource in resources:
        response = by_id[resource["id"]]
        headers = response.get("response_headers")
        if (not isinstance(headers, list) or any(not isinstance(pair, list) or len(pair) != 2
                or any(type(value) is not str for value in pair) for pair in headers)):
            raise ValueError("resource response headers are absent or malformed")
        if (response.get("url") != resource["url"] or response.get("complete") is not True
                or response.get("request_headers") != resource.get("headers")
                or response.get("outcome") != "succeeded" or type(response.get("status")) is not int
                or not 200 <= response["status"] < 300 or type(response.get("bytes")) is not int
                or not 0 < response["bytes"] <= MAX_RESPONSE_BYTES
                or not isinstance(response.get("body_sha256"), str)
                or SHA.fullmatch(response["body_sha256"]) is None or response["body_sha256"] == EMPTY_SHA256
                or type(response.get("request_stream_bytes")) is not int or response["request_stream_bytes"] <= 0
                or [value for name, value in headers if name.lower() == ":status"] != [str(response["status"])]):
            raise ValueError("resource GET is incomplete, empty or unsuccessful")
        lengths = [value for name, value in headers if name.lower() == "content-length"]
        length = response.get("content_length")
        if (length is not None and (type(length) is not int or length != response["bytes"])
                or lengths and (len(lengths) != 1 or lengths[0] != str(response["bytes"]) or length != response["bytes"])):
            raise ValueError("resource Content-Length contradicts completed body")
    endpoints = run.get("endpoints")
    if not isinstance(endpoints, list) or len(endpoints) != 1:
        raise ValueError("session requires one single-origin fresh endpoint")
    endpoint = endpoints[0]
    if endpoint.get("origin") != "https://" + host + "/" or endpoint.get("negotiated_protocol") != "h3":
        raise ValueError("endpoint attribution or HTTP/3 negotiation differs")
    local, local_port = split_endpoint(endpoint["local_address"])
    remote, remote_port = split_endpoint(endpoint["remote_address"])
    five_tuple = [local, local_port, remote, remote_port, 17]
    if receipt["five_tuple"] != five_tuple or remote_port != 443:
        raise ValueError("observed five-tuple differs")
    if receipt.get("capture_position") != "client-eth0-before-nat":
        raise ValueError("five-tuple observation position is undeclared")
    observed = packets(artifact["pcap"], five_tuple)
    trace = read_normalized_trace(artifact["trace"])
    if len(trace) != len(observed):
        raise ValueError("PCAP and trace packet counts differ")
    first = observed[0]["timestamp_unix_ns"]
    for row, packet in zip(trace, observed):
        sign = 1 if packet["direction"] == "outgoing" else -1
        expected = {"relative_time_ns": packet["timestamp_unix_ns"] - first,
                    "length_bytes": packet["length_bytes"], "signed_length_bytes": sign * packet["length_bytes"],
                    "connection": endpoint["id"], "timestamp_unix_ns": packet["timestamp_unix_ns"]}
        if row["direction"] != packet["direction"] or any(int(row[k]) != v for k, v in expected.items()):
            raise ValueError("trace is not an exact projection of encrypted packets")
        if packet["direction"] == "outgoing" and packet["udp_payload_bytes"] > 1200:
            raise ValueError("outgoing UDP payload exceeds the prospective ceiling")
    collector = load(artifact["collector"])
    if (collector.get("success") is not True or collector.get("runner_timed_out") is not False
            or collector.get("runner_returncode") != 0 or collector.get("runner_binding_valid") is not True
            or collector.get("operationally_valid") is not True):
        raise ValueError("collector reports a failed attempt")
    views = collector["views"]
    if len(views) != 1 or not offload_evidence_is_valid(views[0]["capture_offload_evidence"], interface="eth0"):
        raise ValueError("capture interface or packet offload evidence differs")
    view = views[0]
    if view.get("truncated") is not False or view.get("capture_active_through_settle") is not True:
        raise ValueError("primary capture did not cover the complete session tail")
    reconciliation = reconcile_direct_runner_artifacts(artifact["run"], artifact["packets"], artifact["trace"],
                                                       clock_anchors=view["capture_clock_anchors"])
    if not reconciliation.evidence_eligible:
        raise ValueError("Native packet log does not reconcile with the primary capture")
    validate_primary_capture_clock_integrity({**view, "direct_runner_reconciliation": {
        **reconciliation.metrics, "evidence_eligible": True}}, require_pairing_uncertainty=True,
        require_timestamp_type=True)
    mode = receipt["mode"]
    configuration = run["resolved_configuration"]
    native_kind = {"undefended": "none", "cs-buflo": "cs_buflo"}.get(mode, mode)
    if configuration["defense"]["kind"] != native_kind:
        raise ValueError("Native defense differs from its cell")
    settings = enrollment.get("mode_settings", {}).get(mode)
    if settings is not None:
        if receipt.get("mode_settings") != settings:
            raise ValueError("session changed the frozen traffic setting")
        if receipt.get("mode_policies") != enrollment.get("mode_policies", {}).get(mode, {}):
            raise ValueError("session changed the frozen scientific acceptance policies")
        if (configuration.get("max_udp_payload_size") != settings["udp_payload_ceiling"]
                or run.get("request_policy") != settings["request_policy"]
                or run.get("max_response_bytes") != settings["max_response_bytes"]
                or run.get("method") != "GET"):
            raise ValueError("Native changed the frozen request settings")
        if "resolved_configuration" in settings and configuration != settings["resolved_configuration"]:
            raise ValueError("Native changed the complete fixed defense configuration")
        if "parameters_sha256" in settings and (not isinstance(run.get("defense_parameters"), dict)
                or run["defense_parameters"].get("sha256") != settings["parameters_sha256"]):
            raise ValueError("Native changed the fixed defense parameters")
    actual_runtime, enrolled_runtime = receipt.get("runtime", {}), enrollment.get("runtime", {})
    if (actual_runtime.get("client_sha256") != enrolled_runtime.get("client_sha256")
            or actual_runtime.get("platform") != enrolled_runtime.get("platform")
            or actual_runtime.get("source", {}).get("neqo_commit")
            != enrolled_runtime.get("source", {}).get("neqo_commit")):
        raise ValueError("session Native client differs from its frozen enrollment")
    if (run.get("migration_commit") != actual_runtime.get("source", {}).get("neqo_commit")
            or type(run.get("seed")) is not int
            or "attempt_id" in receipt and run["seed"] != int(receipt["attempt_id"].replace("-", "")[:16], 16)):
        raise ValueError("Native run source or attempt seed differs from its receipt")
    if mode != "undefended":
        if "schedule" not in artifact:
            raise ValueError("defended session lacks the realized schedule")
        policies = receipt.get("mode_policies", {})
        metrics = _schedule_realization_metrics_from_path(artifact["schedule"],
            tamaraw_configuration_policy=policies.get("tamaraw_configuration_policy"),
            front_incoming_credit_acceptance_policy=policies.get("front_incoming_credit_acceptance_policy"))
        if not fidelity_eligible(mode, run["defense_diagnostics"], sample_eligible=True,
                missed_events=metrics.get("missed_events"),
                outgoing_size_mismatches=metrics.get("outgoing_size_mismatch_events"),
                schedule_metrics=metrics, resolved_configuration=configuration,
                require_defense_activation=True,
                front_incoming_credit_acceptance_policy=policies.get("front_incoming_credit_acceptance_policy")):
            raise ValueError("independent defense schedule verification failed")
        if mode == "buflo" and (collector.get("kernel_tx_evidence_valid") is not True
                                 or "kernel_tx" not in artifact or "post_veth" not in artifact):
            raise ValueError("BuFLO requires its kernel TX and post-veth measurement")
        if mode == "buflo":
            from .kernel_tx import kernel_tx_evidence_success_valid
            evidence = load(artifact["kernel_tx"])
            raw_router = packets(artifact["post_veth"], five_tuple, require_fresh=False)
            router_packets = [{"schema_version": 1, "packet_index": p["packet_index"],
                "frame_number": p["packet_index"] + 1, "capture_realtime_ns": p["timestamp_unix_ns"],
                "source_address": p["source_address"], "destination_address": p["destination_address"],
                "udp_payload_bytes": p["udp_payload_bytes"], "datagram_sha256": p["datagram_sha256"]}
                for p in sorted(raw_router, key=lambda p: p["packet_index"])]
            if not kernel_tx_evidence_success_valid(evidence,
                    runner_receipt=run["runner_wakeup_metrics"]["buflo_kernel_tx"],
                    expected_run_json_sha256=sha256_file(artifact["run"]),
                    expected_router_capture_sha256=sha256_file(artifact["post_veth"]),
                    router_capture_receipt=evidence["post_veth_capture"], router_packets=router_packets):
                raise ValueError("independent kernel TX and post-veth verification failed")
    overlap = application_stream_overlap(artifact["events"]) if "events" in artifact else {}
    if receipt.get("purpose") == "pilot" and (overlap.get("application_streams_opened") != 20
                                               or overlap.get("maximum_open_application_streams", 0) < 2):
        raise ValueError("pilot did not demonstrate twenty multiplexed application streams")
    return {"verified": True, "five_tuple": five_tuple, "responses": 20,
            **overlap,
            "packet_count": len(observed), "acceptance": ACCEPTANCE,
            "retained_bytes": sum(within(root, relative).stat().st_size for relative in files
                if within(root, relative).parent == artifact["pcap"].parent
                or artifact["pcap"].parent in within(root, relative).parents),
            "duration_seconds": (run["ended_unix_ns"] - run["started_unix_ns"]) / 1e9}
