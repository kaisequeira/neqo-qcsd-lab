from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

from qcsd_lab.browser_egress_fixture import (
    FIXTURE_TOPOLOGY,
    expected_sink_counters,
    vector_by_id,
)
from qcsd_lab.browser_egress_observer import (
    _tool_version_stdout_first_line,
    LivePacketObserver,
    analyse_pcap,
    analyse_packet_records,
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


def test_paired_dns_control_binds_exact_query_name_and_count() -> None:
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
        analyse_packet_records(records, vector=vector), vector=vector
    )
    wrong = copy.deepcopy(records)
    wrong[-1]["dns_name"] = "attacker.test"
    with pytest.raises(ValueError, match="dns_query_names"):
        validate_packet_analysis(
            analyse_packet_records(wrong, vector=vector), vector=vector
        )


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
            "fields": [
                "frame.number", "frame.time_epoch", "frame.interface_id", "ip.src", "ip.dst",
                "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "tcp.flags.syn",
                "tcp.flags.ack", "tcp.len", "udp.srcport", "udp.dstport", "udp.length",
                "dns.flags.response", "dns.qry.name",
            ],
            "argv": ["/usr/bin/tshark"],
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
