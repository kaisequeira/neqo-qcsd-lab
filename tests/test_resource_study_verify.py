"""Local decoder and early receipt refusals; no capture or scientific proof.

The QUIC ciphertext below is opaque synthetic data. Positive tests establish
packet/header decoding only. Receipt controls deliberately stop before the
real Native/fidelity reconciliation boundary and never assert a proof pass.
"""
import csv
import hashlib
import ipaddress
import struct

import pytest

from qcsd_lab import fidelity
from qcsd_lab import resource_study_inputs as inputs
from qcsd_lab import resource_study_verify as verifier


LOCAL = "10.77.0.2"
REMOTE = "198.51.100.23"
TUPLE = [LOCAL, 43001, REMOTE, 443, 17]
TIME = 1_700_000_000_000_000_123


def option(kind, value, endian):
    return struct.pack(endian + "HH", kind, len(value)) + value + bytes((-len(value)) % 4)


def block(kind, body, endian):
    assert len(body) % 4 == 0
    size = len(body) + 12
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


def section(endian):
    return block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def interface(endian, *, link=1, resolution=9, offset=0, snaplen=65535):
    options = option(2, b"eth0", endian) + option(9, bytes([resolution]), endian)
    if offset:
        options += option(14, struct.pack(endian + "q", offset), endian)
    options += option(0, b"", endian)
    return block(1, struct.pack(endian + "HHI", link, 0, snaplen) + options, endian)


def initial(*, version=1):
    """A complete long-header layout, not an authenticated QUIC handshake."""
    first = 0xC0 if version == 1 else 0xD0
    header = bytes([first]) + struct.pack("!I", version)
    header += b"\x08server01\x08client01\x00"  # IDs then zero-length token.
    opaque_length = 1200 - len(header) - 2
    return header + struct.pack("!H", 0x4000 | opaque_length) + bytes(opaque_length)


def frame(payload, *, incoming=False, source_port=None, fragment=0, udp_length=None):
    source, destination = (REMOTE, LOCAL) if incoming else (LOCAL, REMOTE)
    sport, dport = (443, 43001) if incoming else (43001, 443)
    if source_port is not None:
        sport = source_port
    udp = struct.pack("!HHHH", sport, dport, udp_length or len(payload) + 8, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(udp) + 20, 1, fragment, 64, 17, 0,
                     ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed)
    words = struct.unpack("!10H", ip)
    checksum = sum(words)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    ip = ip[:10] + struct.pack("!H", (~checksum) & 0xFFFF) + ip[12:]
    return bytes.fromhex("0200000000010200000000020800") + ip + udp


def enhanced(packet, timestamp, endian, *, interface_id=0, captured=None, original=None):
    captured = len(packet) if captured is None else captured
    original = len(packet) if original is None else original
    header = struct.pack(endian + "IIIII", interface_id, timestamp >> 32,
                         timestamp & 0xFFFFFFFF, captured, original)
    body = header + packet + bytes((-len(packet)) % 4)
    return block(6, body, endian)


def capture_bytes(*, endian="<", outgoing=None, incoming=None, resolution=9, offset=0,
                  link=1, snaplen=65535, timestamp=TIME):
    outgoing = frame(initial()) if outgoing is None else outgoing
    incoming = frame(initial(), incoming=True) if incoming is None else incoming
    return (section(endian) + interface(endian, link=link, resolution=resolution,
                                       offset=offset, snaplen=snaplen)
            + enhanced(outgoing, timestamp, endian)
            + enhanced(incoming, timestamp + 127, endian))


def decode(tmp_path, raw, five_tuple=None):
    path = tmp_path / "session.pcapng"
    path.write_bytes(raw)
    return verifier.packets(path, TUPLE if five_tuple is None else five_tuple)


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("version", [1, 0x6B3343CF])
def test_ethernet_ipv4_initial_pair_preserves_nanoseconds_and_direction(tmp_path, endian, version):
    out, inc = frame(initial(version=version)), frame(initial(version=version), incoming=True)
    actual = decode(tmp_path, capture_bytes(endian=endian, outgoing=out, incoming=inc))
    assert actual == [
        {"timestamp_unix_ns": TIME, "direction": "outgoing", "length_bytes": len(out),
         "udp_payload_bytes": 1200, "initial": True, "packet_index": 0,
         "source_address": f"{LOCAL}:43001", "destination_address": f"{REMOTE}:443",
         "datagram_sha256": hashlib.sha256(out[42:]).hexdigest()},
        {"timestamp_unix_ns": TIME + 127, "direction": "incoming", "length_bytes": len(inc),
         "udp_payload_bytes": 1200, "initial": True, "packet_index": 1,
         "source_address": f"{REMOTE}:443", "destination_address": f"{LOCAL}:43001",
         "datagram_sha256": hashlib.sha256(inc[42:]).hexdigest()},
    ]


@pytest.mark.parametrize("endian", ["<", ">"])
def test_interface_binary_resolution_and_signed_seconds_offset(tmp_path, endian):
    actual = decode(tmp_path, capture_bytes(endian=endian, resolution=0x8A,
                                          offset=-2, timestamp=2048))
    assert [p["timestamp_unix_ns"] for p in actual] == [0, 127 * 1_000_000_000 // 1024]


def test_section_byte_order_change_redeclares_interface(tmp_path):
    first = capture_bytes(endian="<")
    second = capture_bytes(endian=">", timestamp=TIME + 1000)
    actual = decode(tmp_path, first + second)
    assert len(actual) == 4
    assert [p["timestamp_unix_ns"] for p in actual] == [TIME, TIME + 127, TIME + 1000, TIME + 1127]


@pytest.mark.parametrize("cut", [1, 3, 7, 11])
def test_truncated_capture_cannot_supply_a_complete_packet(tmp_path, cut):
    with pytest.raises(ValueError, match="truncated|inconsistent"):
        decode(tmp_path, capture_bytes()[:-cut])


def test_trailer_must_equal_declared_block_boundary(tmp_path):
    raw = bytearray(capture_bytes())
    struct.pack_into("<I", raw, len(raw) - 4, struct.unpack_from("<I", raw, len(raw) - 4)[0] + 4)
    with pytest.raises(ValueError, match="inconsistent"):
        decode(tmp_path, bytes(raw))


def test_section_and_interface_cannot_be_inferred_from_packet_bytes(tmp_path):
    with pytest.raises(ValueError, match="section header"):
        decode(tmp_path, interface("<") + enhanced(frame(initial()), TIME, "<"))
    with pytest.raises(ValueError, match="declared interface"):
        decode(tmp_path, section("<") + enhanced(frame(initial()), TIME, "<"))


@pytest.mark.parametrize("change", ["capture-truncated", "unknown-interface", "snaplen"])
def test_enhanced_packet_capture_metadata_is_checked(tmp_path, change):
    packet = frame(initial())
    options = {"captured": len(packet) - 1} if change == "capture-truncated" else {}
    if change == "unknown-interface":
        options["interface_id"] = 1
    raw = section("<") + interface("<", snaplen=100 if change == "snaplen" else 65535)
    raw += enhanced(packet, TIME, "<", **options)
    raw += enhanced(frame(initial(), incoming=True), TIME + 127, "<")
    with pytest.raises(ValueError, match="truncated|declared interface|snap length"):
        decode(tmp_path, raw)


@pytest.mark.parametrize("side", ["outgoing", "incoming"])
def test_off_tuple_packets_refuse_even_when_both_initials_are_present(tmp_path, side):
    options = {side: frame(initial(), incoming=side == "incoming", source_port=43002)}
    with pytest.raises(ValueError, match="outside the recorded five-tuple"):
        decode(tmp_path, capture_bytes(**options))


@pytest.mark.parametrize("side", ["outgoing", "incoming"])
def test_each_side_requires_an_initial_not_merely_udp_traffic(tmp_path, side):
    options = {side: frame(b"\x40" + bytes(1199), incoming=side == "incoming")}
    with pytest.raises(ValueError, match="outgoing QUIC Initial|server QUIC Initial"):
        decode(tmp_path, capture_bytes(**options))


@pytest.mark.parametrize("side", ["outgoing", "incoming"])
def test_truncated_quic_long_header_is_not_handshake_evidence(tmp_path, side):
    options = {side: frame(b"\xc0\x00\x00\x00\x01\x08\x00", incoming=side == "incoming")}
    with pytest.raises(ValueError):
        decode(tmp_path, capture_bytes(**options))


@pytest.mark.parametrize("change", ["connection-id", "token", "packet-length"])
def test_initial_internal_lengths_cannot_exceed_the_udp_datagram(tmp_path, change):
    payload = bytearray(initial())
    if change == "connection-id":
        payload[5] = 21  # QUIC connection IDs may not exceed twenty bytes.
    elif change == "token":
        payload[23:25] = struct.pack("!H", 0x4000 | 8192)
    else:
        payload[24:26] = struct.pack("!H", 0x4000 | 4096)
    with pytest.raises(ValueError, match="QUIC"):
        decode(tmp_path, capture_bytes(outgoing=frame(bytes(payload))))


@pytest.mark.parametrize("fragment", [1, 0x2000])
def test_ipv4_fragment_or_more_fragments_cannot_prove_udp_packet_units(tmp_path, fragment):
    with pytest.raises(ValueError, match="fragmented IPv4"):
        decode(tmp_path, capture_bytes(outgoing=frame(initial(), fragment=fragment)))


def test_udp_length_must_end_at_ip_payload_boundary(tmp_path):
    with pytest.raises(ValueError, match="UDP length"):
        decode(tmp_path, capture_bytes(outgoing=frame(initial(), udp_length=1207)))


def test_vlan_and_non_ethernet_link_are_outside_primary_contract(tmp_path):
    original = frame(initial())
    vlan = original[:12] + bytes.fromhex("810000010800") + original[14:]
    with pytest.raises(ValueError, match="non-IP frame"):
        decode(tmp_path, capture_bytes(outgoing=vlan))
    with pytest.raises(ValueError, match="Ethernet"):
        decode(tmp_path, capture_bytes(link=101))


def write_json(path, value):
    path.write_bytes(inputs.canonical_json(value))


@pytest.fixture
def early_receipt(tmp_path, monkeypatch):
    """Valid-shaped raw inventory solely for pre-reconciliation refusal tests."""
    urls = [f"https://cdn.example/resource?id={i}" for i in range(20)]
    workload = inputs.native_manifest("cdn.example", urls, {url: 64 for url in urls})
    write_json(tmp_path / "workload.json", workload)
    workload_sha = inputs.sha256_file(tmp_path / "workload.json")
    runtime = {"fixture_role": "controlled pre-reconciliation boundary, no runtime authority"}
    enrollment = {"hostname": "cdn.example", "urls": urls, "workload_sha256": workload_sha,
                  "runtime": runtime}
    write_json(tmp_path / "enrollment.json", enrollment)
    run = {"completion_status": "complete", "error": None, "error_class": None,
           "method": "GET", "request_policy": "as-defined", "max_response_bytes": 16777216,
           "terminal_evidence_render_errors": [], "workload_hash_sha256": workload_sha,
           "started_unix_ns": TIME - 1, "ended_unix_ns": TIME + 1000,
           "responses": [{"resource_id": i, "url": url, "complete": True,
                          "outcome": "succeeded", "status": 200, "bytes": 64,
                          "request_headers": [], "request_stream_bytes": 16, "content_length": 64,
                          "response_headers": [[":status", "200"], ["content-length", "64"]],
                          "body_sha256": hashlib.sha256(bytes([i]) * 64).hexdigest()}
                         for i, url in enumerate(urls)],
           "endpoints": [{"id": 0, "origin": "https://cdn.example/", "negotiated_protocol": "h3",
                          "local_address": f"{LOCAL}:43001", "remote_address": f"{REMOTE}:443"}]}
    write_json(tmp_path / "run.json", run)
    write_json(tmp_path / "collector.json", {})
    (tmp_path / "packets.csv").write_text("not consumed by these early refusal controls\n")
    (tmp_path / "session.pcapng").write_bytes(capture_bytes())
    with (tmp_path / "trace.csv").open("w", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["relative_time_ns", "direction", "length_bytes", "signed_length_bytes",
                         "connection", "timestamp_unix_ns"])
        writer.writerow([0, "outgoing", 1242, 1242, 0, TIME])
        writer.writerow([127, "incoming", 1242, -1242, 0, TIME + 127])
    paths = {"run": "run.json", "packets": "packets.csv", "pcap": "session.pcapng",
             "trace": "trace.csv", "collector": "collector.json", "workload": "workload.json",
             "enrollment": "enrollment.json"}
    receipt = {"schema_version": 1, "verified": True,
               "record_type": "qcsd-resource-domain-session-verification-v1",
               "acceptance": verifier.ACCEPTANCE, "mode": "undefended", "hostname": "cdn.example",
               "workload_sha256": workload_sha, "five_tuple": list(TUPLE),
               "capture_position": "client-eth0-before-nat", "runtime": runtime,
               "artifact_paths": paths,
               "files": {name: inputs.sha256_file(tmp_path / name) for name in paths.values()}}
    calls = []

    def forbidden_reconciliation(*args, **kwargs):
        calls.append(True)
        raise AssertionError("malformed raw input reached downstream reconciliation")

    monkeypatch.setattr(fidelity, "reconcile_direct_runner_artifacts", forbidden_reconciliation)
    return tmp_path, receipt, calls


def replace_raw(root, receipt, role, value):
    path = root / receipt["artifact_paths"][role]
    write_json(path, value)
    receipt["files"][path.name] = inputs.sha256_file(path)


@pytest.mark.parametrize("change", ["nineteen", "duplicate-url", "other-host"])
def test_malformed_twenty_url_enrollment_refuses_before_native_or_fidelity(early_receipt, change):
    root, receipt, calls = early_receipt
    value = verifier.load(root / "enrollment.json")
    if change == "nineteen":
        value["urls"].pop()
    elif change == "duplicate-url":
        value["urls"][-1] = value["urls"][0]
    else:
        value["urls"][-1] = "https://other.example/resource?id=19"
    replace_raw(root, receipt, "enrollment", value)
    with pytest.raises(ValueError, match="frozen resource set"):
        verifier.verify_receipt(root, receipt)
    assert calls == []


@pytest.mark.parametrize("change", ["missing", "duplicate-id", "incomplete", "http-error", "empty"])
def test_twenty_responses_must_all_be_distinct_complete_successful_gets(early_receipt, change):
    root, receipt, calls = early_receipt
    run = verifier.load(root / "run.json")
    if change == "missing":
        run["responses"].pop()
    elif change == "duplicate-id":
        run["responses"][-1]["resource_id"] = 0
    elif change == "incomplete":
        run["responses"][0]["complete"] = False
    elif change == "http-error":
        run["responses"][0]["status"] = 404
    else:
        run["responses"][0]["bytes"] = 0
    replace_raw(root, receipt, "run", run)
    with pytest.raises(ValueError, match="twenty|IDs|resource GET"):
        verifier.verify_receipt(root, receipt)
    assert calls == []


def test_body_identity_digest_must_be_hexadecimal(early_receipt):
    root, receipt, calls = early_receipt
    run = verifier.load(root / "run.json")
    run["responses"][0]["body_sha256"] = "z" * 64
    replace_raw(root, receipt, "run", run)
    with pytest.raises(ValueError, match="resource GET|body|digest"):
        verifier.verify_receipt(root, receipt)
    assert calls == []


@pytest.mark.parametrize("change", ["duplicate-id", "bool-id", "dependency", "unqualified", "chaff"])
def test_rehashed_native_workload_must_keep_exact_twenty_application_shape(early_receipt, change):
    root, receipt, calls = early_receipt
    workload = verifier.load(root / "workload.json")
    if change == "duplicate-id":
        workload["resources"][-1]["id"] = 0
    elif change == "bool-id":
        workload["resources"][0]["id"] = False
    elif change == "dependency":
        workload["resources"][-1]["depends_on"] = [0]
    elif change == "unqualified":
        workload["resources"][0]["known_valid"] = False
    else:
        workload["resources"][0]["chaff_priority"] = True
    replace_raw(root, receipt, "workload", workload)
    digest = inputs.sha256_file(root / "workload.json")
    enrollment = verifier.load(root / "enrollment.json")
    enrollment["workload_sha256"] = digest
    replace_raw(root, receipt, "enrollment", enrollment)
    run = verifier.load(root / "run.json")
    run["workload_hash_sha256"] = digest
    replace_raw(root, receipt, "run", run)
    receipt["workload_sha256"] = digest
    with pytest.raises(ValueError, match="Native workload|resource.*ID"):
        verifier.verify_receipt(root, receipt)
    assert calls == []


def test_boolean_response_id_cannot_alias_an_integer_resource_id(early_receipt):
    root, receipt, calls = early_receipt
    run = verifier.load(root / "run.json")
    run["responses"][0]["resource_id"] = False
    replace_raw(root, receipt, "run", run)
    with pytest.raises(ValueError, match="response IDs|resource.*ID"):
        verifier.verify_receipt(root, receipt)
    assert calls == []


@pytest.mark.parametrize("change", ["oversize", "empty-hash", "wrong-request", "wrong-status-header",
    "missing-headers", "wrong-length", "duplicate-length", "zero-request-bytes", "wrong-method"])
def test_raw_response_completion_is_rederived_before_credit(early_receipt, change):
    root, receipt, calls = early_receipt
    run = verifier.load(root / "run.json")
    response = run["responses"][0]
    if change == "oversize":
        response["bytes"] = 16777217
    elif change == "empty-hash":
        response["body_sha256"] = hashlib.sha256(b"").hexdigest()
    elif change == "wrong-request":
        response["request_headers"] = [["authorization", "unexpected"]]
    elif change == "wrong-status-header":
        response["response_headers"][0][1] = "404"
    elif change == "missing-headers":
        response.pop("response_headers")
    elif change == "wrong-length":
        response["content_length"] = 63
    elif change == "duplicate-length":
        response["response_headers"].append(["content-length", "64"])
    elif change == "zero-request-bytes":
        response["request_stream_bytes"] = 0
    else:
        run["method"] = "POST"
    replace_raw(root, receipt, "run", run)
    with pytest.raises(ValueError, match="resource GET|response headers|Content-Length|complete coherently"):
        verifier.verify_receipt(root, receipt)
    assert calls == []


@pytest.mark.parametrize("change", ["length", "clock", "direction", "connection", "omitted-packet"])
def test_rehashed_trace_mutations_still_refuse_against_original_packets(early_receipt, change):
    root, receipt, calls = early_receipt
    path = root / "trace.csv"
    rows = list(csv.DictReader(path.open(newline="")))
    if change == "omitted-packet":
        rows.pop()
    else:
        row = rows[0]
        key, value = {"length": ("length_bytes", "1241"),
                      "clock": ("timestamp_unix_ns", str(TIME + 1)),
                      "direction": ("direction", "incoming"),
                      "connection": ("connection", "1")}[change]
        row[key] = value
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    receipt["files"]["trace.csv"] = inputs.sha256_file(path)
    with pytest.raises(ValueError, match="PCAP and trace packet counts|exact projection"):
        verifier.verify_receipt(root, receipt)
    assert calls == []


def test_raw_byte_change_is_not_hidden_by_receipt_verified_flag(early_receipt):
    root, receipt, calls = early_receipt
    (root / "run.json").write_bytes((root / "run.json").read_bytes() + b" ")
    with pytest.raises(ValueError, match="artifact bytes changed"):
        verifier.verify_receipt(root, receipt)
    assert calls == []


@pytest.mark.parametrize("path", ["../run.json", "/run.json", "nested/../run.json", "./run.json"])
def test_bound_artifact_paths_cannot_escape_or_alias_root(early_receipt, path):
    root, receipt, calls = early_receipt
    receipt["files"] = {path: receipt["files"]["run.json"]}
    with pytest.raises(ValueError, match="canonical and relative"):
        verifier.verify_receipt(root, receipt)
    assert calls == []


def test_bound_raw_file_cannot_be_replaced_by_a_symlink(early_receipt):
    root, receipt, calls = early_receipt
    path = root / "run.json"
    saved = root / "saved-run.json"
    path.rename(saved)
    path.symlink_to(saved.name)
    with pytest.raises(ValueError, match="regular unlinked"):
        verifier.verify_receipt(root, receipt)
    assert calls == []
