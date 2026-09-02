from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

import qcsd_lab.capture_session as capture_session
import qcsd_lab.kernel_capture_router as capture_router
import qcsd_lab.kernel_tx_runtime as runtime


def _noqueue() -> list[dict[str, object]]:
    return [{"kind": "noqueue", "handle": "0:", "root": True}]


def _installed(*, packets: int = 0) -> list[dict[str, object]]:
    return [
        {
            "kind": "prio",
            "handle": "1:",
            "root": True,
            "options": {"bands": 2, "priomap": [1] * 6 + [0] + [1] * 9},
        },
        {
            "kind": "pfifo",
            "handle": "10:",
            "parent": "1:2",
            "options": {"limit": 1_000},
        },
        {
            "kind": "etf",
            "handle": "20:",
            "parent": "1:1",
            "options": {
                "clockid": "TAI",
                "delta": 4_000_000,
                "offload": "off",
                "deadline_mode": "off",
                "skip_sock_check": "off",
            },
            "packets": packets,
            "bytes": packets * 1_200,
            "drops": 0,
            "overlimits": 0,
            "requeues": 0,
            "backlog": 0,
            "qlen": 0,
        },
    ]


def _runner_contract() -> dict[str, object]:
    return {
        "schema_version": 1,
        **runtime.expected_qdisc_contract(),
        "priority_method": "per_datagram_scm_priority",
        "scm_priority_supported": True,
        "exclusive_socket_sender": True,
        "so_priority_before": 0,
        "so_priority_during": 0,
        "so_priority_after": 0,
        "so_priority_reset_valid": True,
        "so_txtime_enabled": True,
        "tx_sched_timestamping_enabled": True,
        "tx_software_timestamping_enabled": True,
        "tx_timestamp_opt_id_enabled": True,
        "txtime_errors_enabled": True,
    }


def _encoded(value: dict[str, object]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(raw).decode("ascii")


def _controlled_network() -> dict[str, object]:
    return {
        "schema_version": 2,
        "artifact_type": "qcsd-buflo-controlled-network-v2",
        "image_digest": "sha256:" + "a" * 64,
        "topology": {
            "kind": "shared-two-network-router",
            "client_network": {"name": "cohort-client"},
            "server_network": {"name": "cohort-server"},
            "router_interfaces": {},
        },
        "capture_point": {
            "client_to_server_position": "before-router-eth0-ingress-ifb0-netem"
        },
        "client": {},
        "router": {"container": "cohort-router", "client_ipv4": "10.1.0.2"},
        "servers": [],
        "directional_coverage": {
            "client_to_server": {
                "shaping_site": "router:eth0-ingress-redirect-ifb0-root",
                "capture_position": "before-impairment",
            }
        },
        "rate_aggregation": {},
        "observation_contract": {},
    }


def _observer_binding() -> dict[str, object]:
    return {
        "schema_version": 1,
        "artifact_type": "qcsd-kernel-tx-controlled-observer-binding",
        "topology_kind": "shared-two-network-router",
        "image_digest": "sha256:" + "a" * 64,
        "observer": {
            "role": "router-ingress-post-client-veth-pre-netem",
            "container_name": "cohort-router",
            "container_id": "b" * 64,
            "interface": "eth0",
            "interface_direction": "ingress",
            "ipv4": "10.1.0.2",
        },
        "client_network": {
            "name": "cohort-client",
            "id": "c" * 64,
            "router_endpoint_id": "d" * 64,
        },
        "server_network": {
            "name": "cohort-server",
            "id": "e" * 64,
            "router_endpoint_id": "f" * 64,
        },
        "observed_direction": "client-to-server",
        "capture_position": (
            "router-eth0-ingress-after-client-veth-before-ifb0-ingress-netem"
        ),
    }


def _public_network() -> dict[str, object]:
    return {
        "schema_version": 1,
        "artifact_type": "qcsd-kernel-tx-public-network-v1",
        "image_digest": "sha256:" + "a" * 64,
        "topology": {
            "kind": "routed-public-egress",
            "client_network": {"name": "public-client", "subnet": "10.222.1.0/24"},
            "uplink_network": {"name": "bridge"},
            "router_interfaces": {"client": "eth0", "uplink": "eth1"},
        },
        "capture_point": {
            "client_to_server_position": "before-router-eth0-forwarding-and-masquerade"
        },
        "client": {"network": "public-client", "default_route_via": "10.222.1.2"},
        "router": {
            "container": "public-router",
            "client_ipv4": "10.222.1.2",
            "client_interface": "eth0",
            "uplink_interface": "eth1",
            "ipv4_forwarding": True,
            "source_masquerade": True,
        },
        "directional_coverage": {
            "client_to_server": {
                "capture_position": "before-forwarding",
                "nat_position": "after-capture",
            }
        },
        "observation_contract": {
            "client_only": True,
            "ordinary_public_origins": True,
        },
    }


def _public_observer_binding() -> dict[str, object]:
    return {
        "schema_version": 1,
        "artifact_type": "qcsd-kernel-tx-public-observer-binding",
        "topology_kind": "routed-public-egress",
        "image_digest": "sha256:" + "a" * 64,
        "observer": {
            "role": "router-ingress-post-client-veth-pre-netem",
            "container_name": "public-router",
            "container_id": "b" * 64,
            "interface": "eth0",
            "interface_direction": "ingress",
            "ipv4": "10.222.1.2",
        },
        "client_network": {
            "name": "public-client",
            "id": "c" * 64,
            "router_endpoint_id": "d" * 64,
        },
        "uplink_network": {
            "name": "bridge",
            "id": "e" * 64,
            "router_endpoint_id": "f" * 64,
        },
        "observed_direction": "client-to-public-origin",
        "capture_position": (
            "router-eth0-ingress-after-client-veth-before-forwarding-and-masquerade"
        ),
    }


def _router_state(*, active: bool) -> dict[str, object]:
    def offloads(interface: str) -> list[dict[str, object]]:
        return [
            {
                "ifname": interface,
                "generic-receive-offload": {"active": False},
                "generic-segmentation-offload": {"active": False},
                "tcp-segmentation-offload": {"active": False},
                "tx-udp-segmentation": {"active": False},
            }
        ]

    return {
        "schema_version": 1,
        "topology_kind": "shared-two-network-router",
        "capture_process_state": "capturing" if active else "idle",
        "capture_process_active": active,
        "client_interface": "eth0",
        "uplink_interface": "eth1",
        "client_subnet": None,
        "ipv4_forwarding": 1,
        "interfaces": {
            "eth0": [{"ifname": "eth0"}],
            "eth1": [{"ifname": "eth1"}],
        },
        "routes": [{"dst": "10.1.0.0/24", "dev": "eth0"}],
        "qdiscs": {
            "eth0": [{"kind": "noqueue", "handle": "0:", "parent": "root"}],
            "eth1": [{"kind": "noqueue", "handle": "0:", "parent": "root"}],
        },
        "offloads": {"eth0": offloads("eth0"), "eth1": offloads("eth1")},
        "nat_rules": ["*nat", "COMMIT"],
        "invariants": {
            "client_interface_present": True,
            "uplink_interface_present": True,
            "ipv4_forwarding_enabled": True,
            "uplink_default_route_present": False,
            "source_masquerade_required": False,
            "source_masquerade_present": False,
        },
    }


def test_qdisc_session_uses_high_priority_etf_and_restores_noqueue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshots = iter([_noqueue(), _installed(), _installed(packets=2), _noqueue()])
    applied: list[list[str]] = []
    deletes: list[list[str]] = []
    monkeypatch.setattr(runtime, "_tc_json", lambda _interface: next(snapshots))
    monkeypatch.setattr(runtime, "_tc_apply", lambda command: applied.append(list(command)))

    def completed(command: list[str], **_options: object) -> subprocess.CompletedProcess[str]:
        deletes.append(command)
        return subprocess.CompletedProcess(command, 0, "")

    monkeypatch.setattr(runtime, "run", completed)
    session = runtime.KernelTxQdiscSession()

    assert session.install()["packets"] == 0
    observation = session.finish_observation()
    evidence = runtime.bind_qdisc_observation(observation, _runner_contract())

    priomap = applied[0][applied[0].index("priomap") + 1 :]
    assert priomap == ["1"] * 6 + ["0"] + ["1"] * 9
    assert ["parent", "1:1"] == applied[2][4:6]
    assert ["parent", "1:2"] == applied[1][4:6]
    assert deletes == [["tc", "qdisc", "delete", "dev", "eth0", "root"]]
    assert evidence["after"]["packets"] == 2
    assert evidence["restored_after_capture"] is True


def test_qdisc_binding_rejects_runner_delta_mismatch() -> None:
    observation = {
        "schema_version": 1,
        "source": "tc-json-v1",
        "installed_before_runner": True,
        "verified_after_runner": True,
        "restored_after_capture": True,
        "before": {},
        "after": {},
    }
    contract = _runner_contract()
    contract["delta_ns"] = 5_000_000

    with pytest.raises(RuntimeError, match="runner and Lab qdisc contracts differ"):
        runtime.bind_qdisc_observation(observation, contract)


def test_qdisc_setup_failure_before_mutation_verifies_untouched_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshots = iter([_noqueue(), _noqueue()])
    delete_calls: list[list[str]] = []
    monkeypatch.setattr(runtime, "_tc_json", lambda _interface: next(snapshots))

    def fail(_command: list[str]) -> None:
        raise RuntimeError("synthetic setup failure")

    monkeypatch.setattr(runtime, "_tc_apply", fail)

    def completed(command: list[str], **_options: object) -> subprocess.CompletedProcess[str]:
        delete_calls.append(command)
        return subprocess.CompletedProcess(command, 0, "")

    monkeypatch.setattr(runtime, "run", completed)

    with pytest.raises(RuntimeError, match="synthetic setup failure"):
        runtime.KernelTxQdiscSession().install()
    assert delete_calls == []


def test_kernel_timed_buflo_rejects_sender_only_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(runtime.KERNEL_TX_POST_VETH_ENDPOINT_ENV, raising=False)
    monkeypatch.delenv(runtime.KERNEL_TX_POST_VETH_SECRET_ENV, raising=False)
    monkeypatch.delenv(runtime.KERNEL_TX_POST_VETH_ROOT_ENV, raising=False)

    with pytest.raises(ValueError, match="controlled router post-veth"):
        runtime.require_post_veth_capture_configuration()


def test_controller_isolation_sets_and_rechecks_nondumpable_before_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int]] = []
    results = iter((1, 0, 0, 0))

    def prctl(option: int, argument: int = 0) -> int:
        calls.append((option, argument))
        return next(results)

    monkeypatch.setattr(capture_session, "_linux_prctl", prctl)
    before = capture_session._activate_controller_nondumpable()
    receipt = capture_session._controller_isolation_receipt(before)

    assert calls == [(3, 0), (4, 0), (3, 0), (3, 0)]
    assert receipt["dumpable_before_set"] == 1
    assert receipt["dumpable_after_set"] == 0
    assert receipt["dumpable_before_client_spawn"] == 0


def test_controller_isolation_fails_closed_on_prctl_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def prctl(_option: int, _argument: int = 0) -> int:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError(1, "not permitted")
        return 1

    monkeypatch.setattr(capture_session, "_linux_prctl", prctl)
    with pytest.raises(RuntimeError, match="non-dumpable prctl failed"):
        capture_session._activate_controller_nondumpable()


def test_controller_isolation_fails_closed_on_wrong_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = iter((1, 0, 1))
    monkeypatch.setattr(
        capture_session,
        "_linux_prctl",
        lambda _option, _argument=0: next(results),
    )
    with pytest.raises(RuntimeError, match="remained dumpable"):
        capture_session._activate_controller_nondumpable()

    monkeypatch.setattr(
        capture_session,
        "_linux_prctl",
        lambda _option, _argument=0: 1,
    )
    with pytest.raises(RuntimeError, match="isolation receipt is invalid"):
        capture_session._controller_isolation_receipt(1)


def test_controlled_observer_binding_binds_docker_objects_and_network_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = _controlled_network()
    binding = _observer_binding()
    monkeypatch.setenv(runtime.KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_ENV, _encoded(network))
    monkeypatch.setenv(runtime.KERNEL_TX_CONTROLLED_OBSERVER_BINDING_ENV, _encoded(binding))
    monkeypatch.setenv("QCSD_CONTROLLED_ROUTER_CLIENT_IP", "10.1.0.2")
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "a" * 64)

    observed_network, observed_binding, digest = runtime.require_controlled_observer_binding()

    assert observed_network == network
    assert observed_binding == binding
    assert digest == hashlib.sha256(
        json.dumps(network, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def test_controlled_observer_binding_rejects_sender_relabelling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = _controlled_network()
    binding = _observer_binding()
    binding["observer"]["container_name"] = "measured-client"  # type: ignore[index]
    monkeypatch.setenv(runtime.KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_ENV, _encoded(network))
    monkeypatch.setenv(runtime.KERNEL_TX_CONTROLLED_OBSERVER_BINDING_ENV, _encoded(binding))
    monkeypatch.setenv("QCSD_CONTROLLED_ROUTER_CLIENT_IP", "10.1.0.2")
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "a" * 64)

    with pytest.raises(ValueError, match="controlled router topology"):
        runtime.require_controlled_observer_binding()


def test_public_observer_binding_requires_routed_nat_and_docker_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = _public_network()
    binding = _public_observer_binding()
    monkeypatch.setenv(runtime.KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_ENV, _encoded(network))
    monkeypatch.setenv(runtime.KERNEL_TX_CONTROLLED_OBSERVER_BINDING_ENV, _encoded(binding))
    monkeypatch.setenv("QCSD_CONTROLLED_ROUTER_CLIENT_IP", "10.222.1.2")
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "a" * 64)
    monkeypatch.setattr(
        runtime,
        "run",
        lambda command, **_options: subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                [{"dst": "default", "gateway": "10.222.1.2", "dev": "eth0"}]
            ),
            "",
        ),
    )

    observed, observed_binding, digest = runtime.require_controlled_observer_binding()

    assert observed == network
    assert observed_binding == binding
    assert digest == hashlib.sha256(
        json.dumps(network, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    binding["uplink_network"]["router_endpoint_id"] = "not-a-docker-id"  # type: ignore[index]
    monkeypatch.setenv(runtime.KERNEL_TX_CONTROLLED_OBSERVER_BINDING_ENV, _encoded(binding))
    with pytest.raises(ValueError, match="public observer identity"):
        runtime.require_controlled_observer_binding()


def test_router_packet_extraction_hashes_encrypted_udp_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "router.pcapng"
    capture.write_bytes(b"pcapng")
    payload = b"encrypted-quic"
    output = "\t".join(
        (
            "1",
            "1000.000000123",
            "10.1.0.3",
            "",
            "49152",
            "10.2.0.3",
            "",
            "4433",
            str(len(payload) + 8),
            payload.hex(),
        )
    )

    def completed(command: list[str], **_options: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, output + "\n")

    monkeypatch.setattr(runtime, "run", completed)

    assert runtime.extract_router_udp_packets(capture) == [
        {
            "schema_version": 1,
            "packet_index": 0,
            "frame_number": 1,
            "capture_realtime_ns": 1_000_000_000_123,
            "source_address": "10.1.0.3:49152",
            "destination_address": "10.2.0.3:4433",
            "udp_payload_bytes": len(payload),
            "datagram_sha256": hashlib.sha256(payload).hexdigest(),
        }
    ]


def test_router_capture_finalisation_binds_hash_and_moves_all_artifacts(
    tmp_path: Path,
) -> None:
    capture_id = "a" * 64
    source = tmp_path / f"{capture_id}.pcapng"
    receipt_source = tmp_path / f"{capture_id}.json"
    log_source = tmp_path / f"{capture_id}.log"
    source.write_bytes(b"pcapng")
    log_source.write_text("capture log\n", encoding="utf-8")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    receipt = {
        "schema_version": 2,
        "artifact_type": "qcsd-kernel-tx-router-capture",
        "capture_id": capture_id,
        "observer_role": "router-ingress-post-client-veth-pre-netem",
        "interface": "eth0",
        "timestamp_clock_id": "CLOCK_REALTIME",
        "timestamp_type": "host",
        "capture_start_realtime_ns": 1,
        "capture_end_realtime_ns": 2,
        "packets_received": 1,
        "packets_dropped": 0,
        "interface_packets_dropped": 0,
        "dumpcap_received_packets": 1,
        "dumpcap_returncode": 0,
        "pcapng_sha256": digest,
        "capture_active_at_stop": True,
        "router_state_start": _router_state(active=True),
        "router_state_end": _router_state(active=False),
        "capture_service_end_state": "idle-no-dumpcap-child",
    }
    receipt_source.write_text(json.dumps(receipt), encoding="utf-8")
    receipt_digest = hashlib.sha256(receipt_source.read_bytes()).hexdigest()
    diagnostics = tmp_path / "diagnostics"
    diagnostics.mkdir()
    client = object.__new__(runtime.RouterCaptureClient)
    client.root = tmp_path
    client.capture_id = capture_id
    consumed: dict[str, str] = {}

    def consume(**hashes: str) -> None:
        consumed.update(hashes)
        for path in (source, receipt_source, log_source):
            path.unlink()

    client.consume = consume  # type: ignore[method-assign]

    destination, validated = capture_session._finalize_router_capture(
        client=client,
        source=source,
        receipt=copy.deepcopy(receipt),
        diagnostics=diagnostics,
    )

    assert destination == diagnostics / "kernel-tx-post-veth-raw.pcapng"
    assert destination.read_bytes() == b"pcapng"
    assert validated == receipt
    assert consumed == {
        "pcapng_sha256": hashlib.sha256(b"pcapng").hexdigest(),
        "receipt_sha256": receipt_digest,
        "log_sha256": hashlib.sha256(b"capture log\n").hexdigest(),
    }
    assert not source.exists()
    assert (diagnostics / "kernel-tx-post-veth-receipt.json").is_file()
    assert (diagnostics / "kernel-tx-post-veth-dumpcap.log").is_file()


def test_router_capture_stop_rejects_dumpcap_that_autostopped(tmp_path: Path) -> None:
    capture_id = "a" * 64

    class ExitedProcess:
        def poll(self) -> int:
            return 0

    state = capture_router.CaptureState(
        root=tmp_path,
        secret="b" * 64,
        interface="eth0",
        topology_kind="shared-two-network-router",
        uplink_interface="eth1",
        client_subnet=None,
        require_masquerade=False,
    )
    state.capture_id = capture_id
    state.process = ExitedProcess()  # type: ignore[assignment]
    state.start_realtime_ns = 1
    state.router_state_start = _router_state(active=True)
    state.log_handle = (tmp_path / f"{capture_id}.log").open("x", encoding="utf-8")

    with pytest.raises(RuntimeError, match="exited before the explicit stop boundary"):
        state.stop(
            {
                "schema_version": 1,
                "action": "stop",
                "secret": "b" * 64,
                "capture_id": capture_id,
            }
        )

    assert state.process is None
    assert not (tmp_path / f"{capture_id}.json").exists()


def test_router_capture_consume_is_hash_bound_and_fail_closed(tmp_path: Path) -> None:
    capture_id = "a" * 64
    state = capture_router.CaptureState(
        root=tmp_path,
        secret="b" * 64,
        interface="eth0",
        topology_kind="shared-two-network-router",
        uplink_interface="eth1",
        client_subnet=None,
        require_masquerade=False,
    )
    capture, log, receipt = state._paths(capture_id)
    capture.write_bytes(b"pcapng")
    log.write_bytes(b"log")
    receipt.write_bytes(b"receipt")
    request = {
        "schema_version": 1,
        "action": "consume",
        "secret": "b" * 64,
        "capture_id": capture_id,
        "pcapng_sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
        "receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
        "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
    }

    mismatched = dict(request, log_sha256="0" * 64)
    with pytest.raises(RuntimeError, match="hashes differ"):
        state.consume(mismatched)
    assert all(path.is_file() for path in (capture, log, receipt))

    state.consume(request)
    assert all(not path.exists() for path in (capture, log, receipt))
    with pytest.raises(ValueError, match="start bounds/state"):
        state.start(
            {
                "schema_version": 1,
                "action": "start",
                "secret": "b" * 64,
                "capture_id": capture_id,
                "duration_seconds": 10,
                "max_megabytes": 1,
            }
        )


def test_router_capture_client_consume_requires_stopped_state_and_sends_hashes() -> None:
    client = object.__new__(runtime.RouterCaptureClient)
    client.capture_id = "a" * 64
    client._started = False
    client._stopped = True
    client._consumed = False
    observed: dict[str, object] = {}

    def request(action: str, **fields: object) -> dict[str, object]:
        observed.update(action=action, **fields)
        return {}

    client._request = request  # type: ignore[method-assign]
    client.consume(
        pcapng_sha256="b" * 64,
        receipt_sha256="c" * 64,
        log_sha256="d" * 64,
    )

    assert observed == {
        "action": "consume",
        "pcapng_sha256": "b" * 64,
        "receipt_sha256": "c" * 64,
        "log_sha256": "d" * 64,
    }
    assert client._stopped is False
    assert client._consumed is True


def test_public_router_state_receipts_interfaces_routes_qdiscs_nat_and_idle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Process:
        active = True

        def poll(self) -> int | None:
            return None if self.active else 0

    process = Process()

    def completed(command: list[str], **_options: object) -> subprocess.CompletedProcess[str]:
        if command[:3] == ["ip", "-j", "address"]:
            interface = command[-1]
            return subprocess.CompletedProcess(
                command, 0, json.dumps([{"ifname": interface}]), ""
            )
        if command[:3] == ["tc", "-details", "-statistics"]:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps([{"kind": "noqueue", "handle": "0:", "parent": "root"}]),
                "",
            )
        if command[:3] == ["ethtool", "--json", "--show-features"]:
            interface = command[-1]
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(
                    [
                        {
                            "ifname": interface,
                            "generic-receive-offload": {"active": False},
                            "generic-segmentation-offload": {"active": False},
                            "tcp-segmentation-offload": {"active": False},
                            "tx-udp-segmentation": {"active": False},
                        }
                    ]
                ),
                "",
            )
        if command[:4] == ["ip", "-j", "-4", "route"]:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps([{"dst": "default", "dev": "eth1", "gateway": "172.17.0.1"}]),
                "",
            )
        if command[:3] == ["iptables-save", "-t", "nat"]:
            return subprocess.CompletedProcess(
                command,
                0,
                "# Generated\n*nat\n"
                "-A POSTROUTING -s 10.222.1.0/24 -o eth1 -j MASQUERADE\n"
                "COMMIT\n# Completed\n",
                "",
            )
        if command[:4] == ["iptables", "-t", "nat", "-C"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(command)

    original_read_text = Path.read_text

    def read_text(path: Path, *args: object, **kwargs: object) -> str:
        if str(path) == "/proc/sys/net/ipv4/ip_forward":
            return "1\n"
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(capture_router.subprocess, "run", completed)
    monkeypatch.setattr(capture_router.Path, "read_text", read_text)
    state = capture_router.CaptureState(
        root=tmp_path,
        secret="a" * 64,
        interface="eth0",
        topology_kind="routed-public-egress",
        uplink_interface="eth1",
        client_subnet="10.222.1.0/24",
        require_masquerade=True,
    )
    state.process = process  # type: ignore[assignment]

    start = state._router_state(capture_process_state="capturing")
    process.active = False
    end = state._router_state(capture_process_state="idle")

    assert start["capture_process_active"] is True
    assert end["capture_process_active"] is False
    assert start["routes"][0]["dev"] == "eth1"
    assert start["qdiscs"]["eth0"][0]["kind"] == "noqueue"
    assert start["offloads"]["eth0"][0]["generic-receive-offload"]["active"] is False
    assert start["invariants"]["source_masquerade_present"] is True
    assert all(not line.startswith("#") for line in start["nat_rules"])
