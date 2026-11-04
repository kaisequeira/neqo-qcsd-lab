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
from .resource_study_network import (ACCEPTANCE as NETWORK_ACCEPTANCE, validate_receipt_network,
                                     validate_attachment, validate_capture_join)
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


def _udp_packet_inventory(path: Path, *, exact_timestamps=False):
    """Decode every declared UDP frame in original file order, without flow selection."""
    interfaces: list[tuple[int, int, int]] = []
    endian = None
    packet_index = 0
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
                payload = frame[start + 8:ip_end]
                timestamp_ticks = (hi << 32) | lo
                if exact_timestamps and (timestamp_ticks * 1_000_000_000) % divisor:
                    raise ValueError("router timestamp is not an integral nanosecond")
                packet = {"timestamp_unix_ns": (timestamp_ticks * 1_000_000_000) // divisor
                          + clock_offset * 1_000_000_000,
                          "length_bytes": original, "udp_payload_bytes": udp_length - 8,
                          "packet_index": packet_index,
                          "source_address": f"[{source}]:{source_port}" if ":" in source else f"{source}:{source_port}",
                          "destination_address": f"[{destination}]:{destination_port}" if ":" in destination else f"{destination}:{destination_port}",
                          "datagram_sha256": hashlib.sha256(payload).hexdigest()}
                yield packet, key, payload
                packet_index += 1
            elif kind in {2, 3}:
                raise ValueError("unverifiable packet block in primary capture")


def router_udp_packets(path: Path) -> list[dict[str, Any]]:
    """Read the complete post-veth UDP inventory, including ambient traffic.

    The collector's kernel-TX proof binds original frame indices, file order,
    exact nanosecond timestamps and datagram hashes. No flow is removed or
    reordered, and ambient payload is never interpreted as a QUIC handshake.
    """
    observed = []
    for packet, key, _payload in _udp_packet_inventory(path, exact_timestamps=True):
        if not 1 <= key[1] <= 65535 or not 1 <= key[3] <= 65535:
            raise ValueError("router capture contains an invalid UDP port")
        observed.append({"schema_version": 1, "packet_index": packet["packet_index"],
            "frame_number": packet["packet_index"] + 1,
            "capture_realtime_ns": packet["timestamp_unix_ns"],
            "source_address": packet["source_address"],
            "destination_address": packet["destination_address"],
            "udp_payload_bytes": packet["udp_payload_bytes"],
            "datagram_sha256": packet["datagram_sha256"]})
    if not observed:
        raise ValueError("empty router UDP capture")
    return observed


def packets(path: Path, five_tuple: list[Any], *, require_fresh=True) -> list[dict[str, Any]]:
    """Read the declared Ethernet, nonfragmented IP/UDP primary PCAPNG.

    Unsupported link types, truncation and off-tuple packets fail closed. No
    Wireshark installation is required for verification after migration.
    """
    local_ip, local_port, remote_ip, remote_port, protocol = five_tuple
    if protocol != 17:
        raise ValueError("session protocol is not UDP")
    endpoint = (local_ip, local_port, remote_ip, remote_port)
    observed = []
    for packet, key, payload in _udp_packet_inventory(path):
        if key == endpoint:
            direction = "outgoing"
        elif (key[2], key[3], key[0], key[1]) == endpoint:
            direction = "incoming"
        else:
            raise ValueError("primary packet is outside the recorded five-tuple")
        observed.append({**packet, "direction": direction, "initial": _initial(payload)})
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


def selection_proof_present(enrollment: dict, receipt: dict | None = None) -> bool:
    """Detect optional or partial selection metadata without loading its code."""
    def prefixed(names, prefix):
        return any(isinstance(name, str) and name.startswith(prefix) for name in names)
    return ("resource_selection" in enrollment
        or prefixed(enrollment, "resource_selection_")
        or prefixed(enrollment.get("files", {}), "inputs/resource-selections/")
        or prefixed((receipt or {}).get("artifact_paths", {}), "resource_selection_"))


def _verify_cs_supplemental_receipt(root, enrollment, receipt, paths, files, artifact, run):
    """Replay the complete CS pool proof and join its original session assets.

    This is a scoped additional Raw gate. The caller still requires the exact
    formal20 working GETs, packet/trace/clock and CS defense realization gates.
    """
    from . import cs_supplemental_chaff as cs
    if (receipt.get("mode") != "cs-buflo" or "ft_supplemental_chaff" in receipt
            or any(key.startswith("ft_") for key in paths)):
        raise ValueError("separate CS session cannot claim FRONT/Tamaraw pool authority")
    binding = cs.validate_enrollment(root, enrollment, full_proof=True)
    expected_paths = cs.artifact_paths(enrollment)
    if (receipt.get("cs_supplemental_chaff") != binding
            or any(paths.get(key) != relative or relative not in files
                   or files[relative] != enrollment["files"].get(relative)
                   or artifact.get(key) != within(root, relative)
                   for key, relative in expected_paths.items())
            or run.get("application_workload_source_hash_sha256") != binding["application_workload_sha256"]
            or run.get("chaff_manifest_hash_sha256") != binding["chaff_manifest_sha256"]):
        raise ValueError("independent CS proof lacks its whole original Source/qualification inventory")
    cs.validate_runtime_inputs(artifact["workload"], artifact["cs_formal_prepared_workload"],
        artifact["cs_chaff_manifest"], artifact["cs_pool_source"], run, "cs-buflo")
    from .capture_session import _validate_chaff_response_receipts
    _validate_chaff_response_receipts(run, artifact["cs_chaff_manifest"], "cs_buflo")


def verify_receipt(root: Path, receipt: dict[str, Any]) -> dict[str, Any]:
    """Return independently derived facts or raise; suitable for StudyStore."""
    from .fidelity import (reconcile_direct_runner_artifacts, validate_primary_capture_clock_integrity,
                           _schedule_realization_metrics_from_path, fidelity_eligible)
    root = Path(root).absolute()
    if (receipt.get("schema_version") != 1 or receipt.get("verified") is not True
            or receipt.get("record_type") != "qcsd-resource-domain-session-verification-v1"
            or receipt.get("acceptance") not in {ACCEPTANCE, NETWORK_ACCEPTANCE} or receipt.get("mode") not in MODES):
        raise ValueError("session verification contract differs")
    plan = load(within(root, "study.json")) if (root / "study.json").exists() else {}
    plan_sha256 = sha256_file(root / "study.json") if plan else None
    binding = validate_receipt_network(plan, plan_sha256, receipt)
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
    if binding is not None:
        if (paths.get("study") != "study.json" or files.get("study.json") != plan_sha256
                or "class_network" not in artifact or "scheduler" not in artifact):
            raise ValueError("persistent class session lacks its plan/topology raw join")
        validate_attachment(plan, plan_sha256, receipt, load(artifact["class_network"]))
    enrollment = load(artifact["enrollment"])
    if ("class_selection" in plan or "class_selection" in enrollment
            or {"class_selection", "class_selection_inventory", "class_selection_source"}.intersection(paths)):
        from .resource_study_lineage import validate_receipt_enrollment, MANIFEST, INVENTORY, SOURCE
        validate_receipt_enrollment(root, plan, enrollment, receipt=receipt)
        if ("class_selection" not in plan
                or paths.get("class_selection") != MANIFEST
                or paths.get("class_selection_inventory") != INVENTORY
                or paths.get("class_selection_source") != SOURCE
                or any(files.get(name) != enrollment["files"].get(name) for name in (MANIFEST, INVENTORY, SOURCE))):
            raise ValueError("receipt stable selection context differs from enrollment/plan")
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
    if selection_proof_present(enrollment, receipt):
        from .resource_study_selection import validate_selection_proof
        validate_selection_proof(root, enrollment, receipt)
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
    if binding is not None:
        from .process_scheduler import capture_scheduler_runtime_evidence_valid
        scheduler = load(artifact["scheduler"])
        if not capture_scheduler_runtime_evidence_valid(scheduler):
            raise ValueError("persistent class capture lacks valid raw peer scheduler evidence")
        validate_capture_join(load(artifact["class_network"]), collector, scheduler,
            scheduler_sha256=sha256_file(artifact["scheduler"]),
            kernel_evidence=load(artifact["kernel_tx"]) if "kernel_tx" in artifact else None)
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
    from .resource_study_native import CS160_PRIMARY_POLICY,_primary_cs160_check_raw_binding
    primary_policy=enrollment.get('mode_policies',{}).get('cs-buflo',{}).get('cs_buflo_duration_policy')==CS160_PRIMARY_POLICY
    if primary_policy:
        if mode!='cs-buflo' or 'runtime_cohort_input_context'not in artifact:
            raise ValueError('Primary CS160 raw proof requires exact frozen input context and CS mode')
        from .resource_study_cohorts import _cs160_input_declaration
        primary_context=load(artifact['runtime_cohort_input_context'])
        _primary_cs160_check_raw_binding(enrollment.get('cs160_primary_intent'),
            _cs160_input_declaration(primary_context['predecessor']),enrolled_runtime,receipt,enrollment,run)
    elif 'cs160_primary_intent'in enrollment:
        raise ValueError('Primary CS160 enrollment cannot be relabelled as legacy or another policy')
    if (("cs_supplemental_chaff" in receipt or any(key.startswith("cs_") for key in paths))
            and not (mode == "cs-buflo" and "cs_supplemental_chaff" in enrollment)):
        raise ValueError("legacy or other-mode session cannot claim supplemental CS evidence")
    if mode == "cs-buflo" and "cs_supplemental_chaff" in enrollment:
        _verify_cs_supplemental_receipt(root, enrollment, receipt, paths, files, artifact, run)
    elif mode in ("front", "tamaraw") and "ft_supplemental_chaff" in enrollment:
        from . import ft_supplemental_chaff as ft
        ft_binding = ft.validate_enrollment(root, enrollment, full_proof=True)
        expected_paths = ft.artifact_paths(enrollment)
        if (receipt.get("ft_supplemental_chaff") != ft_binding
                or any(paths.get(key) != relative or files.get(relative) != enrollment["files"].get(relative)
                       for key, relative in expected_paths.items())
                or run.get("application_workload_source_hash_sha256") != ft_binding["application_workload_sha256"]
                or run.get("chaff_manifest_hash_sha256") != ft_binding["chaff_manifest_sha256"]):
            raise ValueError("independent FT proof lacks its whole original Source/qualification inventory")
        ft.validate_runtime_inputs(artifact["workload"], artifact["ft_formal_prepared_workload"],
            artifact["ft_chaff_manifest"], artifact["ft_pool_source"], run, mode)
        from .capture_session import _validate_chaff_response_receipts
        _validate_chaff_response_receipts(run, artifact["ft_chaff_manifest"], mode)
    elif ("ft_supplemental_chaff" in receipt or any(key.startswith("ft_") for key in paths)
          or any(run.get(key) is not None for key in ("supplemental_chaff_policy",
              "supplemental_chaff_pool_source_hash_sha256", "supplemental_chaff_selected_pool_resource_id",
              "supplemental_chaff_qualification_evidence_sha256"))):
        raise ValueError("legacy or other-mode session cannot claim supplemental FT evidence")
    if 'retained_parameter_preparation' in enrollment:
        from .resource_study_native import retained_mode_receipt_binding, retained_mode_assets
        provisional = receipt.get('purpose') == 'readiness'
        retained = retained_mode_assets(root, enrollment, provisional=provisional)
        expected_binding = retained_mode_receipt_binding(root, enrollment, provisional=provisional)
        if (mode != 'buflo' or receipt.get('purpose') not in {'formal', 'pilot', 'readiness'}
                or receipt.get('scientific_credit') is not (receipt.get('purpose') == 'formal')
                or receipt.get('retained_parameter_preparation') != expected_binding
                or receipt.get('runtime') != enrollment['runtime']
                or paths.get('retained_chaff_manifest') != enrollment['paths'][retained['chaff_key']]
                or run.get('chaff_manifest_hash_sha256') != expected_binding['historical_binding']['native_manifest_sha256']
                or run.get('application_workload_source_hash_sha256') != expected_binding['historical_binding']['application_workload_sha256']):
            raise ValueError('retained parameter receipt has foreign purpose/runtime/launch binding')
        from .capture_session import _validate_chaff_response_receipts
        _validate_chaff_response_receipts(run, artifact['retained_chaff_manifest'], 'buflo')
    elif 'retained_parameter_preparation' in receipt:
        raise ValueError('legacy enrollment cannot claim retained-parameter readiness')
    if mode == "buflo" and "buflo_chaff_selection" in enrollment:
        from .resource_study_native import validate_buflo_capped_enrollment
        capped = validate_buflo_capped_enrollment(root, enrollment)
        expected_paths = {"buflo_chaff_sidecar": enrollment["paths"]["buflo_chaff_sidecar"],
            "buflo_chaff_manifest": enrollment["paths"]["buflo_chaff_manifest"],
            "buflo_chaff_prepared_workload": enrollment["paths"]["prepared_workload"]}
        if (capped is None or canonical_json(receipt.get("buflo_chaff_selection")) != canonical_json(capped)
                or any(paths.get(key) != value for key, value in expected_paths.items())
                or run.get("chaff_manifest_hash_sha256") != capped["native_manifest_sha256"]
                or run.get("application_workload_source_hash_sha256") != capped["application_workload_sha256"]):
            raise ValueError("capped BuFLO sidecar, Native manifest or actual run binding differs")
        from .capture_session import _validate_chaff_response_receipts
        _validate_chaff_response_receipts(run, artifact["buflo_chaff_manifest"], "buflo")
    elif "buflo_chaff_selection" in receipt:
        raise ValueError("uncapped or non-BuFLO receipt cannot claim capped selection")
    if mode == "buflo" and "buflo_small_response_aggregate_selection" in enrollment:
        from .resource_study_native import validate_buflo_aggregate_enrollment
        aggregate = validate_buflo_aggregate_enrollment(root, enrollment)
        expected_paths = {"buflo_chaff_sidecar": enrollment["paths"]["buflo_chaff_sidecar"],
            "buflo_chaff_manifest": enrollment["paths"]["buflo_chaff_manifest"],
            "buflo_chaff_prepared_workload": enrollment["paths"]["prepared_workload"]}
        if (aggregate is None
                or canonical_json(receipt.get("buflo_small_response_aggregate_selection")) != canonical_json(aggregate)
                or any(paths.get(key) != value for key, value in expected_paths.items())
                or run.get("chaff_manifest_hash_sha256") != aggregate["native_manifest_sha256"]
                or run.get("application_workload_source_hash_sha256") != aggregate["application_workload_sha256"]):
            raise ValueError("aggregate BuFLO sidecar, Native manifest or actual run binding differs")
        from .capture_session import _validate_chaff_response_receipts
        _validate_chaff_response_receipts(run, artifact["buflo_chaff_manifest"], "buflo")
    elif "buflo_small_response_aggregate_selection" in receipt:
        raise ValueError("ordinary or non-BuFLO receipt cannot claim aggregate selection")
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
            if isinstance(run.get("buflo_summary"), dict) and run["buflo_summary"].get("schema_version") == 5:
                from .fidelity import new_defense_terminal_receipts_valid
                if "events" not in artifact:
                    raise ValueError("independent BuFLO local-abandonment event proof is absent")
                if not new_defense_terminal_receipts_valid(run, "buflo",
                        require_application_complete=True, require_current_schema=True,
                        runner_directory=artifact["run"].parent,
                        terminal_trace_paths={"events": artifact["events"], "packets": artifact["packets"]}):
                    raise ValueError("independent BuFLO local-abandonment proof verification failed")
            from .kernel_tx import kernel_tx_evidence_success_valid
            evidence = load(artifact["kernel_tx"])
            router_packets = router_udp_packets(artifact["post_veth"])
            if not kernel_tx_evidence_success_valid(evidence,
                    runner_receipt=run["runner_wakeup_metrics"]["buflo_kernel_tx"],
                    expected_run_json_sha256=sha256_file(artifact["run"]),
                    expected_router_capture_sha256=sha256_file(artifact["post_veth"]),
                    router_capture_receipt=evidence["post_veth_capture"], router_packets=router_packets):
                raise ValueError("independent kernel TX and post-veth verification failed")
    overlap = application_stream_overlap(artifact["events"]) if "events" in artifact else {}
    if (receipt.get("purpose") == "pilot" or ('retained_parameter_preparation' in enrollment
            and receipt.get('purpose') == 'readiness')) and (overlap.get("application_streams_opened") != 20
                                               or overlap.get("maximum_open_application_streams", 0) < 2):
        raise ValueError("pilot did not demonstrate twenty multiplexed application streams")
    return {"verified": True, "five_tuple": five_tuple, "responses": 20,
            **overlap,
            "packet_count": len(observed), "acceptance": receipt["acceptance"],
            "retained_bytes": sum(within(root, relative).stat().st_size for relative in files
                if within(root, relative).parent == artifact["pcap"].parent
                or artifact["pcap"].parent in within(root, relative).parents),
            "duration_seconds": (run["ended_unix_ns"] - run["started_unix_ns"]) / 1e9}


def verify_retained_mode_readiness(root, enrollment):
    """Replay the distinct full physical readiness and original owned closure."""
    from . import resource_study_native as n
    checked = n.retained_mode_assets(root, enrollment)
    base, study = checked['base'], checked['study_root']
    result = json.loads(n.retained_mode_read(base / 'readiness-result.json',
        checked['binding']['readiness_sha256']))
    expected_flight = {'launched', 'closed', 'affinity_started', 'affinity_closed'}
    if type(result['flight']) is not dict or set(result['flight']) != expected_flight:
        raise ValueError('readiness result lacks the complete original owned flight')
    receipt_path, receipt_sha = n._retained_ref(result['receipt'])
    receipt = json.loads(n.retained_mode_read(receipt_path, receipt_sha))
    expected_id = '%016x' % checked['core']['input']['seed'] + checked['binding']['core_sha256'][:16]
    expected_receipt = study / 'readiness-attempts' / enrollment['hostname'] / expected_id / 'verified-readiness/session.json'
    provisional_path = base / 'readiness-coordinator-enrollment.json'
    if (receipt_path != expected_receipt or receipt.get('purpose') != 'readiness'
            or receipt.get('scientific_credit') is not False or receipt.get('mode') != 'buflo'
            or receipt.get('hostname') != enrollment['hostname'] or receipt.get('attempt_id') != expected_id
            or type(receipt.get('slot')) is not int or receipt['slot'] != 0
            or receipt.get('runtime') != enrollment['runtime']
            or receipt.get('artifact_paths', {}).get('enrollment') != provisional_path.relative_to(study).as_posix()):
        raise ValueError('readiness receipt is not the actual distinct no-credit preparation case')
    provisional_sha = receipt.get('files', {}).get(provisional_path.relative_to(study).as_posix())
    if type(provisional_sha) is not str or SHA.fullmatch(provisional_sha) is None:
        raise ValueError('readiness provisional enrollment lacks its actual receipt digest')
    provisional = json.loads(n.retained_mode_read(provisional_path, provisional_sha))
    old = n.retained_mode_assets(study, provisional, provisional=True)
    if (old['binding']['core_sha256'] != checked['binding']['core_sha256']
            or any(provisional.get(key) != enrollment.get(key) for key in
                   ('hostname', 'urls', 'workload_sha256', 'paths', 'runtime', 'mode_settings', 'mode_policies',
                    'resource_selection', 'class_selection', 'runtime_cohort_input_authority'))):
        raise ValueError('readiness provenance differs from the final frozen enrollment')
    # This calls the unchanged physical/clock/schedule/kernel predicates, with
    # only the explicit retained-parameter current-runtime binding branch.
    run = load(within(study, receipt['artifact_paths']['run']))
    if (type(run.get('started_unix_ns')) is not int
            or run['started_unix_ns'] < (base / 'core.json').stat().st_mtime_ns):
        raise ValueError('readiness Native case predates its immutable input core')
    facts = verify_receipt(study, receipt)
    if facts.get('verified') is not True or facts.get('responses') != 20:
        raise ValueError('fresh readiness failed independent full physical verification')
    records = {}
    parents = set()
    for key, ref in result['flight'].items():
        path, digest = n._retained_ref(ref)
        if path.name != {'launched': 'launched.json', 'closed': 'closed.json',
                         'affinity_started': 'coordinator-affinity-started.json',
                         'affinity_closed': 'coordinator-affinity-closed.json'}[key]:
            raise ValueError('readiness flight role/path changed')
        if path.parent.parent != study / 'flights':
            raise ValueError('readiness flight escaped its owning study')
        parents.add(path.parent)
        records[key] = json.loads(n.retained_mode_read(path, digest))
    if len(parents) != 1:
        raise ValueError('readiness flight roles come from different owned flights')
    launched, closed = records['launched'], records['closed']
    started, affinity = records['affinity_started'], records['affinity_closed']
    attachment = load(within(study, receipt['artifact_paths']['class_network']))
    observer = attachment['observer']
    workers = launched.get('workers')
    sidecars = launched.get('sidecars')
    if (launched.get('runtime') != enrollment['runtime']
            or launched.get('study_sha256') != sha256_file(study / 'study.json')
            or type(workers) is not list or len(workers) != 2
            or type(sidecars) is not dict or len(sidecars) != 1
            or observer['observer']['container_id'] not in sidecars.values()
            or attachment['worker_container_id'] not in [row.get('id') for row in workers]
            or closed.get('cleanup_errors') != [] or closed.get('scientific_credit') is not False
            or set(closed.get('containers_removed', [])) != set(sidecars.values()) | {row['id'] for row in workers}
            or closed.get('networks_removed') != [observer['client_network']['id']]
            or any(affinity.get(key) is not True for key in
                   ('executor_registered', 'foreign_threads_confined_to_auxiliary',
                    'main_thread_identity_and_affinity_valid', 'restored', 'pool_joined_before_restoration'))
            or affinity.get('body_failed') is not False
            or started.get('record_type') != 'qcsd-Source029-outer-coordinator-affinity-v2'
            or affinity.get('python_pool_joined_before_kernel_wait') is not True
            or affinity.get('owned_kernel_thread_teardown', {}).get('complete') is not True
            or affinity.get('affinity_restored') != started.get('affinity_before')
            or any(affinity.get(key) != started.get(key) for key in (
                'record_type', 'schema_version', 'pid', 'available_cpus', 'worker_cpu_pairs',
                'auxiliary_cpus', 'affinity_before', 'existing_thread_ids',
                'new_pool_threads_inherit_auxiliary_mask', 'baseline_threads',
                'pool_ownership_source', 'container_and_Native_affinity_changed', 'scientific_credit'))):
        raise ValueError('readiness flight topology, join, custody or affinity closure failed')
    return facts
