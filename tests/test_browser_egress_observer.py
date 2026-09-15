from __future__ import annotations

import copy
import hashlib
import signal
from pathlib import Path

import pytest

import qcsd_lab.browser_egress_observer as observer_module
from qcsd_lab.browser_egress_dns import dns_control_nxdomain_response
from qcsd_lab.browser_egress_dns_evidence import dns_wire_record, empty_dns_control_evidence
from qcsd_lab.browser_egress_fixture import (
    FIXTURE_TOPOLOGY,
    combine_sink_receipt,
    dns_query_message,
    expected_sink_counters,
    vector_by_id,
)
from qcsd_lab.browser_egress_observer import (
    LivePacketObserver,
    _tool_version_stdout_first_line,
    analyse_packet_records,
    analyse_pcap,
    parse_dumpcap_statistics,
    reconcile_sink_and_packet_evidence,
    safe_relative_artifact,
    validate_capture_receipt,
    validate_packet_analysis,
    validate_packet_record,
)


def _packet(
    frame: int,
    *,
    src: str,
    dst: str,
    transport: str = "tcp",
    src_port: int = 49152,
    dst_port: int = 18443,
    syn: bool = False,
    ack: bool = False,
    payload: int = 0,
    dns_kind: str = "none",
    dns_name: str | None = None,
) -> dict:
    return {
        "schema_version": 1,
        "frame_number": frame,
        "timestamp_ns": frame * 1_000,
        "interface_id": 0,
        "ip_version": 6 if ":" in src else 4,
        "src": src,
        "dst": dst,
        "transport": transport,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_syn": syn,
        "tcp_ack": ack,
        "payload_bytes": payload,
        "dns_kind": dns_kind,
        "dns_name": dns_name,
    }


def test_ipv4_ipv6_tcp_udp_dns_analysis_and_controls() -> None:
    browser4, browser6 = FIXTURE_TOPOLOGY["browser_addresses"]
    sink4, sink6 = FIXTURE_TOPOLOGY["forbidden_sink_addresses"]
    dns4, dns6 = FIXTURE_TOPOLOGY["dns_sink_addresses"]
    tcp = vector_by_id("positive-control--fixture--tcp")
    records = [
        _packet(1, src=browser4, dst=sink4, syn=True),
        _packet(2, src=sink4, dst=browser4, src_port=18443, dst_port=49152, syn=True, ack=True),
        _packet(3, src=browser4, dst=sink4, ack=True, payload=32),
        _packet(4, src=browser6, dst=sink6, syn=True),
        _packet(5, src=sink6, dst=browser6, src_port=18443, dst_port=49152, syn=True, ack=True),
        _packet(6, src=browser6, dst=sink6, ack=True, payload=32),
    ]
    analysis = analyse_packet_records(records, vector=tcp)
    assert analysis["ipv4_packets"] == 3
    assert analysis["ipv6_packets"] == 3
    assert analysis["forbidden_tcp_initial_syn"] == 2
    assert analysis["forbidden_tcp_syn_ack"] == 2
    assert analysis["forbidden_tcp_payload_bytes"] == 64
    validate_packet_analysis(analysis, vector=tcp)

    missing_ipv6 = analyse_packet_records(records[:3], vector=tcp)
    with pytest.raises(ValueError, match="forbidden_tcp_initial_syn"):
        validate_packet_analysis(missing_ipv6, vector=tcp)

    dns = vector_by_id("positive-control--fixture--dns")
    dns_records = [
        _packet(
            1,
            src=browser4,
            dst=dns4,
            transport="udp",
            dst_port=53,
            payload=48,
            dns_kind="query",
            dns_name="udp4-control.egress.invalid",
        ),
        _packet(
            2,
            src=browser4,
            dst=dns4,
            src_port=49153,
            dst_port=53,
            syn=True,
        ),
        _packet(
            3,
            src=browser4,
            dst=dns4,
            src_port=49153,
            dst_port=53,
            payload=50,
            dns_kind="query",
            dns_name="tcp4-control.egress.invalid",
        ),
        _packet(
            4,
            src=browser6,
            dst=dns6,
            transport="udp",
            dst_port=53,
            payload=48,
            dns_kind="query",
            dns_name="udp6-control.egress.invalid",
        ),
        _packet(
            5,
            src=browser6,
            dst=dns6,
            src_port=49154,
            dst_port=53,
            syn=True,
        ),
        _packet(
            6,
            src=browser6,
            dst=dns6,
            src_port=49154,
            dst_port=53,
            payload=50,
            dns_kind="query",
            dns_name="tcp6-control.egress.invalid",
        ),
    ]
    validate_packet_analysis(analyse_packet_records(dns_records, vector=dns), vector=dns)


def test_negative_vector_rejects_initial_syn_udp_payload_and_unexpected_dns() -> None:
    vector = vector_by_id("constructor--page--websocket")
    browser = FIXTURE_TOPOLOGY["browser_addresses"][0]
    sink = FIXTURE_TOPOLOGY["forbidden_sink_addresses"][0]
    analysis = analyse_packet_records(
        [_packet(1, src=browser, dst=sink, syn=True)], vector=vector
    )
    with pytest.raises(ValueError, match="forbidden_tcp_initial_syn"):
        validate_packet_analysis(analysis, vector=vector)


def test_paired_preconnect_control_requires_approved_endpoint_handshake_only_when_enabled() -> None:
    browser = FIXTURE_TOPOLOGY["browser_addresses"][0]
    fixture = FIXTURE_TOPOLOGY["fixture_addresses"][0]
    port = FIXTURE_TOPOLOGY["ports"]["fixture_preconnect_https"]
    records = [
        _packet(1, src=browser, dst=fixture, dst_port=port, syn=True),
        _packet(
            2,
            src=fixture,
            dst=browser,
            src_port=port,
            dst_port=49152,
            syn=True,
            ack=True,
        ),
    ]
    enabled = vector_by_id(
        "browser-service-control--default-profile--preconnect-enabled"
    )
    validate_packet_analysis(
        analyse_packet_records(records, vector=enabled), vector=enabled
    )
    disabled = vector_by_id(
        "browser-service-control--default-profile--preconnect-disabled"
    )
    with pytest.raises(ValueError, match="approved_preconnect_initial_syn"):
        validate_packet_analysis(
            analyse_packet_records(records, vector=disabled), vector=disabled
        )


@pytest.mark.parametrize("analysis_version", [3, 4])
def test_historical_paired_dns_control_binds_exact_query_name_and_count(analysis_version: int) -> None:
    vector = vector_by_id(
        "browser-service-control--default-profile--dns-prefetch-enabled"
    )
    browser = FIXTURE_TOPOLOGY["browser_addresses"][0]
    dns = FIXTURE_TOPOLOGY["dns_sink_addresses"][0]
    name = FIXTURE_TOPOLOGY["browser_service_controls"]["dns_exception_hostname"]
    records = [
        _packet(
            frame,
            src=browser,
            dst=dns,
            transport="udp",
            src_port=49000 + frame,
            dst_port=53,
            payload=48,
            dns_kind="query",
            dns_name=name,
        )
        for frame in range(1, 4)
    ]
    validate_packet_analysis(
        analyse_packet_records(records, vector=vector, analysis_schema_version=analysis_version),
        vector=vector,
    )
    wrong = copy.deepcopy(records)
    wrong[-1]["dns_name"] = "attacker.test"
    with pytest.raises(ValueError, match="dns_query_names"):
        validate_packet_analysis(
            analyse_packet_records(wrong, vector=vector, analysis_schema_version=analysis_version),
            vector=vector,
        )


def _current_dns_control(count: int, *, ipv6: bool = False) -> tuple[list[dict], dict]:
    vector = vector_by_id(
        "browser-service-control--default-profile--dns-prefetch-"
        + ("enabled" if count else "disabled")
    )
    name = FIXTURE_TOPOLOGY["browser_service_controls"]["dns_exception_hostname"]
    browser = FIXTURE_TOPOLOGY["browser_addresses"][int(ipv6)]
    dns = FIXTURE_TOPOLOGY["dns_sink_addresses"][int(ipv6)]
    control = empty_dns_control_evidence(name)
    records = []
    for index in range(count):
        query = dns_query_message(name, identifier=index + 1)
        response = dns_control_nxdomain_response(query, hostname=name)
        control["queries"].append(dns_wire_record(query, (browser, 49000 + index), transport="udp"))
        control["responses"].append(dns_wire_record(response, (browser, 49000 + index), transport="udp"))
        for src, dst, source_port, dest_port, message, kind in (
            ("127.0.0.1", "127.0.0.11", 48000 + index, 58173, query, "query"),
            (browser, dns, 49000 + index, 53, query, "query"),
            (dns, browser, 53, 49000 + index, response, "response"),
            ("127.0.0.11", "127.0.0.1", 53, 48000 + index, response, "response"),
        ):
            record = _packet(
                len(records) + 1, src=src, dst=dst, transport="udp", src_port=source_port,
                dst_port=dest_port, payload=len(message), dns_kind=kind, dns_name=name,
            )
            record.update({
                "schema_version": 2, "outer_ip_protocol": 17, "quoted_transport": None,
                "icmp_type": None, "icmp_code": None,
                "dns_id": index + 1, "dns_type": 1, "dns_class": 1,
                "dns_rcode": 0 if kind == "query" else 3,
                "dns_payload_sha256": hashlib.sha256(message).hexdigest(),
            })
            records.append(record)
    empty = expected_sink_counters(vector)
    sink = combine_sink_receipt(
        vector=vector, tcp=empty["tcp"], udp=empty["udp"],
        dns={
            "udp_names": [name] * count, "tcp_names": [], "control": control,
            "ip_versions": {
                family: {"udp_names": [name] * count if selected else [], "tcp_names": []}
                for family, selected in (("ipv4", not ipv6), ("ipv6", ipv6))
            },
        },
        forbidden_ready_ns=1, dns_ready_ns=2, forbidden_stopped_ns=3, dns_stopped_ns=4,
    )
    return records, sink


@pytest.mark.parametrize("count", [0, 1, 2, 5])
@pytest.mark.parametrize("ipv6", [False, True])
def test_current_dns_pair_counts_all_legs_but_reconciles_only_sink_arrivals(count: int, ipv6: bool) -> None:
    records, sink = _current_dns_control(count, ipv6=ipv6)
    vector = vector_by_id(sink["vector_id"])
    analysis = analyse_packet_records(records, vector=vector)
    assert analysis["dns_udp_queries"] == analysis["dns_udp_responses"] == 2 * count
    assert len(analysis["dns_control_packets"]) == 4 * count
    assert analysis["dns_udp_datagrams"] == sink["dns"]["udp_queries_received"] == count
    assert analysis["unexpected_browser_egress_packets"] == 0
    before = copy.deepcopy(analysis)
    validate_packet_analysis(analysis, vector=vector)
    reconcile_sink_and_packet_evidence(vector=vector, analysis=analysis, sink=sink)
    assert analysis == before


@pytest.mark.parametrize("key", [
    "dns_udp_queries", "dns_udp_queries_ipv4", "dns_udp_responses",
    "dns_udp_datagrams", "dns_udp_datagrams_ipv4", "decoded_transport_packets",
])
def test_current_dns_packet_counts_cannot_disagree_with_wire_projection(key: str) -> None:
    records, sink = _current_dns_control(1)
    vector = vector_by_id(sink["vector_id"])
    analysis = analyse_packet_records(records, vector=vector)
    analysis[key] = 0
    with pytest.raises(ValueError):
        validate_packet_analysis(analysis, vector=vector)


def test_current_dns_pair_cannot_substitute_a_historical_counter_only_sink() -> None:
    records, sink = _current_dns_control(0)
    vector = vector_by_id(sink["vector_id"])
    analysis = analyse_packet_records(records, vector=vector)
    sink["schema_version"] = 1
    sink["dns"].pop("control")
    with pytest.raises(ValueError, match="schema-2 wire-bound sink"):
        reconcile_sink_and_packet_evidence(vector=vector, analysis=analysis, sink=sink)


@pytest.mark.parametrize("index", [0, 1, 2, 3])
def test_current_dns_pair_rejects_any_missing_query_or_reply_leg(index: int) -> None:
    records, sink = _current_dns_control(1)
    vector = vector_by_id(sink["vector_id"])
    records.pop(index)
    with pytest.raises(observer_module.PacketPolicyError, match="four-leg"):
        validate_packet_analysis(analyse_packet_records(records, vector=vector), vector=vector)


def test_fresh_negative_vectors_reject_unsolicited_dns_responses() -> None:
    records, _ = _current_dns_control(1)
    vector = vector_by_id("browser-service--browser--dns-prefetch")
    analysis = analyse_packet_records([records[2]], vector=vector)
    assert analysis["dns_udp_queries"] == 0
    assert analysis["dns_udp_responses"] == 1
    with pytest.raises(observer_module.PacketPolicyError, match="dns_udp_responses"):
        validate_packet_analysis(analysis, vector=vector)


@pytest.mark.parametrize("suffix", ["disabled", "enabled"])
def test_nel_pair_receipts_the_identical_approved_error_trigger(suffix: str) -> None:
    vector = vector_by_id(
        f"browser-service-control--default-profile--network-error-logging-{suffix}"
    )
    browser = FIXTURE_TOPOLOGY["browser_addresses"][0]
    fixture = FIXTURE_TOPOLOGY["fixture_addresses"][0]
    port = FIXTURE_TOPOLOGY["ports"]["fixture_nel_error_https"]
    analysis = analyse_packet_records(
        [_packet(1, src=browser, dst=fixture, dst_port=port, syn=True)],
        vector=vector,
    )
    assert analysis["approved_nel_error_initial_syn"] == 1
    validate_packet_analysis(analysis, vector=vector)


def test_negative_vector_rejects_embedded_resolver_loopback_query() -> None:
    vector = vector_by_id("browser-service--browser--dns-prefetch")
    analysis = analyse_packet_records(
        [
            _packet(
                1,
                src="127.0.0.1",
                dst="127.0.0.11",
                transport="udp",
                src_port=49000,
                dst_port=53,
                payload=48,
                dns_kind="query",
                dns_name="forbidden.browser-egress.invalid",
            )
        ],
        vector=vector,
    )
    assert analysis["dns_udp_queries"] == 1
    with pytest.raises(ValueError, match="dns_udp_queries"):
        validate_packet_analysis(analysis, vector=vector)


def test_negative_vector_rejects_unknown_source_or_second_interface_flow() -> None:
    vector = vector_by_id("constructor--page--websocket")
    fixture = FIXTURE_TOPOLOGY["fixture_addresses"][0]
    analysis = analyse_packet_records(
        [_packet(1, src="192.0.2.44", dst=fixture, dst_port=14443)],
        vector=vector,
    )
    assert analysis["unexpected_browser_egress_packets"] == 1
    with pytest.raises(ValueError, match="unexpected_browser_egress_packets"):
        validate_packet_analysis(analysis, vector=vector)


@pytest.mark.parametrize(
    ("field", "value"),
    [("frame_number", True), ("timestamp_ns", 1.0), ("payload_bytes", False)],
)
def test_packet_record_rejects_bool_and_float_integer_aliases(field: str, value: object) -> None:
    packet = _packet(
        1,
        src=FIXTURE_TOPOLOGY["browser_addresses"][0],
        dst=FIXTURE_TOPOLOGY["fixture_addresses"][0],
    )
    packet[field] = value
    with pytest.raises(ValueError):
        validate_packet_record(packet)


def test_packet_analysis_records_timestamp_regressions_in_frame_order() -> None:
    vector = vector_by_id("constructor--page--websocket")
    browser = FIXTURE_TOPOLOGY["browser_addresses"][0]
    fixture = FIXTURE_TOPOLOGY["fixture_addresses"][0]
    fixture_port = FIXTURE_TOPOLOGY["ports"]["fixture_https"]
    records = [
        _packet(1, src=browser, dst=fixture, dst_port=fixture_port),
        _packet(2, src=fixture, dst=browser, src_port=fixture_port, dst_port=49152),
        _packet(3, src=browser, dst=fixture, dst_port=fixture_port),
        _packet(4, src=fixture, dst=browser, src_port=fixture_port, dst_port=49152),
    ]
    records[0]["timestamp_ns"] = 10_000
    records[1]["timestamp_ns"] = 9_500
    records[2]["timestamp_ns"] = 11_000
    records[3]["timestamp_ns"] = 9_000
    original = copy.deepcopy(records)

    analysis = analyse_packet_records(records, vector=vector)

    assert records == original
    assert analysis["schema_version"] == 5
    assert analysis["timestamp_regressions"] == 2
    assert analysis["maximum_timestamp_regression_ns"] == 2_000
    assert validate_packet_analysis(analysis, vector=vector) == analysis


@pytest.mark.parametrize("frames", [(1, 1), (2, 1)])
def test_packet_analysis_rejects_nonincreasing_frame_numbers(
    frames: tuple[int, int],
) -> None:
    vector = vector_by_id("constructor--page--websocket")
    browser = FIXTURE_TOPOLOGY["browser_addresses"][0]
    fixture = FIXTURE_TOPOLOGY["fixture_addresses"][0]
    records = [
        _packet(frames[0], src=browser, dst=fixture),
        _packet(frames[1], src=browser, dst=fixture),
    ]
    records[0]["timestamp_ns"] = 2_000
    records[1]["timestamp_ns"] = 3_000

    with pytest.raises(ValueError, match="frame numbers are not strictly increasing"):
        analyse_packet_records(records, vector=vector)


def test_historical_packet_analysis_schema_three_remains_valid() -> None:
    vector = vector_by_id("constructor--page--websocket")
    analysis = analyse_packet_records(
        [], vector=vector, analysis_schema_version=3
    )

    assert analysis["schema_version"] == 3
    assert "timestamp_regressions" not in analysis
    assert "maximum_timestamp_regression_ns" not in analysis
    assert validate_packet_analysis(analysis, vector=vector) == analysis


def test_historical_packet_analysis_schema_three_retains_timestamp_order_rule() -> None:
    vector = vector_by_id("constructor--page--websocket")
    browser = FIXTURE_TOPOLOGY["browser_addresses"][0]
    fixture = FIXTURE_TOPOLOGY["fixture_addresses"][0]
    records = [
        _packet(1, src=browser, dst=fixture),
        _packet(2, src=fixture, dst=browser),
    ]
    records[0]["timestamp_ns"] = 2_000
    records[1]["timestamp_ns"] = 1_000

    with pytest.raises(ValueError, match="not capture ordered"):
        analyse_packet_records(records, vector=vector, analysis_schema_version=3)


def test_pcap_and_independent_sink_disagreement_is_fatal() -> None:
    vector = vector_by_id("positive-control--fixture--tcp")
    browser4, browser6 = FIXTURE_TOPOLOGY["browser_addresses"]
    sink4, sink6 = FIXTURE_TOPOLOGY["forbidden_sink_addresses"]
    analysis = analyse_packet_records(
        [
            _packet(1, src=browser4, dst=sink4, syn=True),
            _packet(
                2,
                src=sink4,
                dst=browser4,
                src_port=18443,
                dst_port=49152,
                syn=True,
                ack=True,
            ),
            _packet(3, src=browser4, dst=sink4, ack=True, payload=32),
            _packet(4, src=browser6, dst=sink6, syn=True),
            _packet(
                5,
                src=sink6,
                dst=browser6,
                src_port=18443,
                dst_port=49153,
                syn=True,
                ack=True,
            ),
            _packet(6, src=browser6, dst=sink6, ack=True, payload=32),
        ],
        vector=vector,
    )
    sink = expected_sink_counters(vector)
    sink["tcp"]["received_payload_bytes"] = 63
    sink["tcp"]["ip_versions"]["ipv4"]["received_payload_bytes"] = 31
    sink["tcp"]["received_payload_sha256"] = hashlib.sha256(b"x" * 63).hexdigest()
    sink["tcp"]["ip_versions"]["ipv4"]["received_payload_sha256"] = hashlib.sha256(
        b"x" * 31
    ).hexdigest()
    with pytest.raises(ValueError, match="sink counters differ|disagree"):
        reconcile_sink_and_packet_evidence(vector=vector, analysis=analysis, sink=sink)


def test_safe_artifact_rejects_traversal_symlink_and_hardlink(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    target = root / "capture.pcapng"
    target.write_bytes(b"pcap")
    assert safe_relative_artifact(root, "capture.pcapng", label="test") == target
    with pytest.raises(ValueError):
        safe_relative_artifact(root, "../capture.pcapng", label="test")
    link = root / "link.pcapng"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        safe_relative_artifact(root, "link.pcapng", label="test")
    hard = root / "hard.pcapng"
    hard.hardlink_to(target)
    with pytest.raises(ValueError, match="hard link"):
        safe_relative_artifact(root, "capture.pcapng", label="test")


def _capture(vector_id: str) -> dict:
    vector = vector_by_id(vector_id)
    analysis = analyse_packet_records([], vector=vector)
    return {
        "schema_version": 2,
        "artifact_type": "qcsd-browser-egress-packet-capture",
        "vector_id": vector_id,
        "pcap": {"path": "evidence/capture.pcapng", "sha256": "a" * 64, "size_bytes": 24},
        "observer": {
            "network_namespace": "browser",
            "interface": "any",
            "capture_filter": None,
            "privileged": False,
            "cap_drop": ["ALL"],
            "cap_add": ["CAP_NET_RAW"],
            "separate_container": True,
        },
        "capture_process": {
            "exit_code": 0,
            "packets_captured": 1,
            "packets_received": 1,
            "packets_dropped_by_kernel": 0,
            "packets_dropped_by_interface": 0,
            "capture_path_drop_breakdown": {
                "pcap": 0,
                "dumpcap": 0,
                "flushed": 0,
            },
        },
        "capture_tool": {
            "path": "/usr/bin/dumpcap",
            "sha256": "b" * 64,
            "version_first_line": "Dumpcap 4.0",
            "argv": ["/usr/bin/dumpcap", "-q", "-i", "any", "-w", "<PCAP>"],
        },
        "chronology": {
            "observer_started_ns": 1,
            "observer_ready_ns": 2,
            "subject_started_ns": 3,
            "subject_exited_ns": 4,
            "reporting_grace_finished_ns": 5_000_000_004,
            "observer_stopped_ns": 5_000_000_005,
        },
        "packet_decoder": {
            "path": "/usr/bin/tshark",
            "sha256": "c" * 64,
            "version_first_line": "TShark 4.0",
            "fields": list(observer_module.TSHARK_FIELDS),
            "argv": observer_module.tshark_command(Path("<PCAP>")),
        },
        "analysis": analysis,
    }


def test_capture_requires_zero_drops_and_no_filter() -> None:
    vector = vector_by_id("constructor--page--websocket")
    receipt = _capture(vector.vector_id)
    validate_capture_receipt(receipt, vector=vector)
    dropped = copy.deepcopy(receipt)
    dropped["capture_process"]["packets_dropped_by_kernel"] = 1
    with pytest.raises(ValueError, match="dropped"):
        validate_capture_receipt(dropped, vector=vector)
    filtered = copy.deepcopy(receipt)
    filtered["capture_tool"]["argv"].extend(["-f", "udp"])
    with pytest.raises(ValueError):
        validate_capture_receipt(filtered, vector=vector)


@pytest.mark.parametrize(
    ("field", "breakdown"),
    [
        ("packets_dropped_by_kernel", {"pcap": 1, "dumpcap": 0, "flushed": 0}),
        ("packets_dropped_by_kernel", {"pcap": 0, "dumpcap": 1, "flushed": 0}),
        ("packets_dropped_by_kernel", {"pcap": 0, "dumpcap": 0, "flushed": 1}),
        ("packets_dropped_by_interface", {"pcap": 0, "dumpcap": 0, "flushed": 0}),
    ],
)
def test_capture_rejects_each_explicit_dumpcap_drop_category(
    field: str, breakdown: dict[str, int]
) -> None:
    vector = vector_by_id("constructor--page--websocket")
    receipt = _capture(vector.vector_id)
    receipt["capture_process"]["capture_path_drop_breakdown"] = breakdown
    receipt["capture_process"][field] = 1
    with pytest.raises(ValueError, match="dropped"):
        validate_capture_receipt(receipt, vector=vector)


def test_dumpcap_statistics_requires_explicit_drop_counter() -> None:
    stderr = (
        "Packets captured: 12\n"
        "Packets received/dropped on interface 'any': "
        "12/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)\n"
    )
    assert parse_dumpcap_statistics(stderr, exit_code=0) == {
        "exit_code": 0,
        "packets_captured": 12,
        "packets_received": 12,
        "packets_dropped_by_kernel": 0,
        "packets_dropped_by_interface": 0,
        "capture_path_drop_breakdown": {
            "pcap": 0,
            "dumpcap": 0,
            "flushed": 0,
        },
    }
    with pytest.raises(ValueError, match="omitted"):
        parse_dumpcap_statistics("Packets captured: 12\n", exit_code=0)
    with pytest.raises(ValueError, match="omitted"):
        parse_dumpcap_statistics(
            "Packets captured: 12\n"
            "Packets received/dropped on interface 'any': 12/0\n",
            exit_code=0,
        )
    with pytest.raises(ValueError, match="omitted"):
        parse_dumpcap_statistics(stderr + stderr.splitlines()[1] + "\n", exit_code=0)
    for breakdown in (
        "12/1 (pcap:1/dumpcap:0/flushed:0/ps_ifdrop:0)",
        "12/1 (pcap:0/dumpcap:1/flushed:0/ps_ifdrop:0)",
        "12/1 (pcap:0/dumpcap:0/flushed:1/ps_ifdrop:0)",
        "12/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:1)",
    ):
        parsed = parse_dumpcap_statistics(
            f"Packets captured: 12\nPackets received/dropped on interface 'any': "
            f"{breakdown} (100.0%)\n",
            exit_code=0,
        )
        assert (
            parsed["packets_dropped_by_kernel"]
            or parsed["packets_dropped_by_interface"]
        )


def test_packet_decoder_version_binding_ignores_stderr_diagnostics(tmp_path: Path) -> None:
    tshark = tmp_path / "tshark"
    tshark.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = --version ]; then\n'
        "  echo 'privilege-dependent diagnostic' >&2\n"
        "  echo 'TShark deterministic-version'\n"
        "fi\n",
        encoding="utf-8",
    )
    tshark.chmod(0o700)
    pcap = tmp_path / "capture.pcapng"
    pcap.write_bytes(b"synthetic input ignored by the test decoder")

    analysis, decoder = analyse_pcap(
        pcap,
        vector=vector_by_id("constructor--page--websocket"),
        tshark=tshark,
    )

    assert analysis["unexpected_browser_egress_packets"] == 0
    assert decoder["version_first_line"] == "TShark deterministic-version"


def test_live_observer_version_binding_ignores_stderr_diagnostics(tmp_path: Path) -> None:
    dumpcap = tmp_path / "dumpcap"
    dumpcap.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, signal, sys, time\n"
        "if sys.argv[1] == '--version':\n"
        "    print('privilege-dependent diagnostic', file=sys.stderr)\n"
        "    print('Dumpcap deterministic-version')\n"
        "    raise SystemExit(0)\n"
        "pathlib.Path(sys.argv[5]).write_bytes(b'pcap')\n"
        "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n"
        "while True:\n"
        "    time.sleep(0.1)\n",
        encoding="utf-8",
    )
    dumpcap.chmod(0o700)
    observer = LivePacketObserver(pcap_path=tmp_path / "capture.pcapng", dumpcap=dumpcap)

    try:
        observer.start()
        assert observer.capture_tool is not None
        assert observer.capture_tool["version_first_line"] == "Dumpcap deterministic-version"
    finally:
        if observer.process is not None and observer.process.poll() is None:
            observer.process.terminate()
            observer.process.communicate(timeout=5)


def _closed_live_observer(tmp_path: Path, *, terminal_stderr: str) -> LivePacketObserver:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"closed-pcap")

    class Process:
        returncode = 0

        def send_signal(self, item: signal.Signals) -> None:
            assert item == signal.SIGINT

        def communicate(self, *, timeout: int) -> tuple[None, str]:
            assert timeout == 15
            return None, terminal_stderr

    observer = LivePacketObserver(pcap_path=capture)
    observer.process = Process()  # type: ignore[assignment]
    observer.capture_tool = {
        "path": "/usr/bin/dumpcap",
        "sha256": "a" * 64,
        "version_first_line": "Dumpcap 4.0",
        "argv": ["/usr/bin/dumpcap", "-q", "-i", "any", "-w", "<PCAP>"],
    }
    observer.times = {
        "observer_started_ns": 1,
        "observer_ready_ns": 2,
        "subject_started_ns": 3,
        "subject_exited_ns": 4,
        "reporting_grace_finished_ns": 5_000_000_004,
    }
    return observer


def test_live_observer_closes_and_binds_pcap_before_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    terminal_stderr = (
        "Packets captured: 1\n"
        "Packets received/dropped on interface 'any': "
        "1/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)\n"
    )
    observer = _closed_live_observer(tmp_path, terminal_stderr=terminal_stderr)
    vector = vector_by_id("constructor--page--websocket")
    monkeypatch.setattr(observer_module.time, "monotonic_ns", lambda: 5_000_000_005)
    decoder = {
        "path": "/usr/bin/tshark",
        "sha256": "b" * 64,
        "version_first_line": "TShark 4.0",
        "fields": list(observer_module.TSHARK_FIELDS),
        "argv": observer_module.tshark_command(Path("<PCAP>")),
    }
    monkeypatch.setattr(
        observer_module,
        "analyse_pcap",
        lambda *_args, **_kwargs: (analyse_packet_records([], vector=vector), decoder),
    )

    closure = observer.close_capture(
        vector=vector,
        pcap_relative_path="evidence/capture.pcapng",
    )

    assert closure["schema_version"] == 1
    assert closure["artifact_type"] == "qcsd-browser-egress-capture-closure"
    assert closure["capture_process_terminal"] == {
        "exit_code": 0,
        "stderr": terminal_stderr,
    }
    assert closure["pcap"] == {
        "path": "evidence/capture.pcapng",
        "sha256": hashlib.sha256(b"closed-pcap").hexdigest(),
        "size_bytes": len(b"closed-pcap"),
    }
    receipt = observer.finish_closed_capture(vector=vector, closure=closure)
    assert set(receipt) == {
        "schema_version",
        "artifact_type",
        "vector_id",
        "pcap",
        "observer",
        "capture_process",
        "capture_tool",
        "chronology",
        "packet_decoder",
        "analysis",
    }
    assert receipt["schema_version"] == 2
    assert receipt["pcap"] == closure["pcap"]
    with pytest.raises(ValueError, match="already closed"):
        observer.close_capture(vector=vector, pcap_relative_path="evidence/capture.pcapng")
    with pytest.raises(ValueError, match="already started"):
        observer.finish_closed_capture(vector=vector, closure=closure)


def test_live_observer_preserves_closure_when_terminal_statistics_are_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observer = _closed_live_observer(tmp_path, terminal_stderr="invalid dumpcap output\n")
    vector = vector_by_id("constructor--page--websocket")
    monkeypatch.setattr(observer_module.time, "monotonic_ns", lambda: 5_000_000_005)

    closure = observer.close_capture(
        vector=vector,
        pcap_relative_path="evidence/capture.pcapng",
    )

    assert closure["pcap"]["sha256"] == hashlib.sha256(b"closed-pcap").hexdigest()
    with pytest.raises(ValueError, match="omitted"):
        observer.finish_closed_capture(vector=vector, closure=closure)


def test_live_observer_rejects_pcap_changed_after_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    terminal_stderr = (
        "Packets captured: 1\n"
        "Packets received/dropped on interface 'any': "
        "1/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)\n"
    )
    observer = _closed_live_observer(tmp_path, terminal_stderr=terminal_stderr)
    vector = vector_by_id("constructor--page--websocket")
    monkeypatch.setattr(observer_module.time, "monotonic_ns", lambda: 5_000_000_005)
    closure = observer.close_capture(
        vector=vector,
        pcap_relative_path="evidence/capture.pcapng",
    )
    observer.pcap_path.write_bytes(b"changed-pcap")

    with pytest.raises(ValueError, match="differs from its closure"):
        observer.finish_closed_capture(vector=vector, closure=closure)


@pytest.mark.parametrize(
    "script",
    [
        "#!/bin/sh\necho 'diagnostic only' >&2\n",
        "#!/bin/sh\necho 'Tool version'\necho 'diagnostic' >&2\nexit 7\n",
        "#!/bin/sh\nprintf '\\nTool version\\n'\n",
        "#!/bin/sh\nprintf '  \\nTool version\\n'\n",
    ],
)
def test_tool_version_binding_rejects_empty_stdout_or_nonzero_exit(
    tmp_path: Path, script: str
) -> None:
    executable = tmp_path / "tool"
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o700)

    with pytest.raises(ValueError, match="version query failed"):
        _tool_version_stdout_first_line(executable, label="test tool")


def test_deep_capture_validation_ignores_version_stderr_diagnostics(
    tmp_path: Path,
) -> None:
    tshark = tmp_path / "tshark"
    tshark.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = --version ]; then\n'
        "  echo 'root-only tshark warning' >&2\n"
        "  echo 'TShark deterministic-version'\n"
        "fi\n",
        encoding="utf-8",
    )
    tshark.chmod(0o700)
    dumpcap = tmp_path / "dumpcap"
    dumpcap.write_text(
        "#!/bin/sh\necho 'root-only dumpcap warning' >&2\necho 'Dumpcap deterministic-version'\n",
        encoding="utf-8",
    )
    dumpcap.chmod(0o700)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    pcap = evidence / "capture.pcapng"
    pcap.write_bytes(b"synthetic input ignored by the test decoder")
    vector = vector_by_id("constructor--page--websocket")
    analysis, decoder = analyse_pcap(pcap, vector=vector, tshark=tshark)
    receipt = _capture(vector.vector_id)
    receipt["pcap"] = {
        "path": "evidence/capture.pcapng",
        "sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
        "size_bytes": pcap.stat().st_size,
    }
    receipt["analysis"] = analysis
    receipt["packet_decoder"] = decoder
    receipt["capture_tool"] = {
        "path": str(dumpcap),
        "sha256": hashlib.sha256(dumpcap.read_bytes()).hexdigest(),
        "version_first_line": "Dumpcap deterministic-version",
        "argv": [str(dumpcap), "-q", "-i", "any", "-w", "<PCAP>"],
    }

    assert (
        validate_capture_receipt(
            receipt,
            vector=vector,
            evidence_root=tmp_path,
            deep=True,
            tshark=tshark,
            dumpcap=dumpcap,
        )
        == receipt
    )

    for version in (3, 4):
        historical = copy.deepcopy(receipt)
        historical["analysis"], historical["packet_decoder"] = analyse_pcap(
            pcap, vector=vector, tshark=tshark, analysis_schema_version=version,
        )
        assert historical["analysis"]["schema_version"] == version
        assert historical["packet_decoder"]["fields"] == list(
            observer_module.HISTORICAL_TSHARK_FIELDS
        )
        assert "occurrence=f" in historical["packet_decoder"]["argv"]
        assert (
            validate_capture_receipt(
                historical,
                vector=vector,
                evidence_root=tmp_path,
                deep=True,
                tshark=tshark,
                dumpcap=dumpcap,
            )
            == historical
        )
        historical["packet_decoder"] = decoder
        with pytest.raises(ValueError, match="packet decoder binding"):
            validate_capture_receipt(historical, vector=vector)

    changed_version = copy.deepcopy(receipt)
    changed_version["capture_tool"]["version_first_line"] = "Dumpcap changed-version"
    with pytest.raises(ValueError, match="version binding"):
        validate_capture_receipt(
            changed_version,
            vector=vector,
            evidence_root=tmp_path,
            deep=True,
            tshark=tshark,
            dumpcap=dumpcap,
        )

    changed_decoder = copy.deepcopy(receipt)
    changed_decoder["packet_decoder"]["version_first_line"] = "TShark changed-version"
    with pytest.raises(ValueError, match="packet decoder binding"):
        validate_capture_receipt(
            changed_decoder,
            vector=vector,
            evidence_root=tmp_path,
            deep=True,
            tshark=tshark,
            dumpcap=dumpcap,
        )
