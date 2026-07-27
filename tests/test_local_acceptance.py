import csv
import json
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest


@pytest.mark.skipif(
    os.environ.get("QCSD_RUN_LOCAL_ACCEPTANCE") != "1",
    reason="set QCSD_RUN_LOCAL_ACCEPTANCE=1 for the two-origin replay gate",
)
def test_unmodified_local_server_all_defenses(tmp_path):
    ports = [_free_port(), _free_port()]
    servers = [
        subprocess.Popen(
            ["neqo-server", f"127.0.0.1:{port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for port in ports
    ]
    try:
        time.sleep(0.5)
        manifest = tmp_path / "workload.json"
        manifest.write_text(json.dumps(_manifest(*ports)), encoding="utf-8")
        defenses = {
            "none": {"kind": "none"},
            "front": {"kind": "front"},
            "tamaraw": {"kind": "tamaraw"},
        }
        hashes = {}
        normalized = {}
        for name, defense in defenses.items():
            output = tmp_path / name
            result = _run_client(manifest, defense, output)
            assert result.returncode == 0, f"{name}: {result.stdout}"
            run_data = json.loads((output / "run.json").read_text())
            assert run_data["completion_status"] == "complete"
            assert [response["resource_id"] for response in run_data["responses"]] == [
                0,
                1,
                2,
                3,
            ]
            assert len(run_data["endpoints"]) == 2
            assert all(response["status"] == 200 for response in run_data["responses"])
            hashes[name] = [response["body_sha256"] for response in run_data["responses"]]
            for artifact in ("packets.csv", "events.csv", "schedule.csv"):
                assert (output / artifact).exists()
            if name != "none":
                _assert_terminal_schedule(output, run_data)
                normalized[name] = _normalized_controller_sequence(output)
                if name in {"static-chaff-and-shape", "tamaraw"}:
                    with (output / "schedule.csv").open(newline="") as source:
                        assert any(
                            row["direction"] == "incoming"
                            and row["satisfaction"] == "credit_advertised"
                            for row in csv.DictReader(source)
                        )
        assert len({tuple(value) for value in hashes.values()}) == 1

        for name, defense in defenses.items():
            if name == "none":
                continue
            repeat = tmp_path / f"repeat-{name}"
            result = _run_client(manifest, defense, repeat)
            assert result.returncode == 0, f"repeat {name}: {result.stdout}"
            repeat_data = json.loads((repeat / "run.json").read_text())
            assert repeat_data["completion_status"] == "complete"
            _assert_terminal_schedule(repeat, repeat_data)
            assert _normalized_controller_sequence(repeat) == normalized[name]
    finally:
        for server in servers:
            server.terminate()
        for server in servers:
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _run_client(manifest, defense, output):
    command = [
        "neqo-qcsd-client",
        "run",
        "--workload",
        str(manifest),
        "--profile",
        "live",
        "--defense",
        defense["kind"],
        "--seed",
        "42",
        "--output-dir",
        str(output),
        "--max-response-bytes",
        "2097152",
        "--timeout-seconds",
        "120",
    ]
    if defense["kind"] != "none":
        command += ["--chaff-manifest", str(manifest)]
    if defense["kind"] == "static":
        command += [
            "--schedule",
            str(defense["schedule"]),
            "--static-mode",
            defense["mode"],
        ]
    return subprocess.run(
        command,
        cwd="/lab",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def _assert_terminal_schedule(output, run_data):
    with (output / "schedule.csv").open(newline="") as source:
        rows = list(csv.DictReader(source))
    with (output / "packets.csv").open(newline="") as source:
        packets = list(csv.DictReader(source))
    assert rows
    slot_ids = [row["slot_id"] for row in rows]
    assert all(slot_ids)
    assert len(slot_ids) == len(set(slot_ids))
    allowed_satisfaction = {"satisfied", "credit_advertised", "missed"}
    allowed_misses = {
        "NoEndpoint",
        "InsufficientIncomingCapacity",
        "CongestionLimited",
        "PacingLimited",
        "KeysUnavailable",
        "PathMtu",
        "MandatoryFrames",
        "EndpointClosed",
        "DeadlineExpired",
    }
    defense_start_us = run_data["defense_start_monotonic_ns"] // 1_000
    interval_us = run_data["resolved_configuration"]["control_interval_us"]
    for row in rows:
        assert row["satisfaction"] in allowed_satisfaction
        if row["satisfaction"] == "missed":
            assert row["miss_reason"] in allowed_misses
            continue
        assert not row["miss_reason"]
        lateness = int(row["action_time_us"]) - defense_start_us - int(row["target_time_us"])
        assert lateness >= 0, row
        if row["direction"] == "outgoing":
            assert lateness < interval_us, row
            assert row["satisfaction"] == "satisfied"
            assert int(row["observed_size"]) == int(row["size"])
            matching = [packet for packet in packets if packet["slot_id"] == row["slot_id"]]
            assert len(matching) == 1
            assert matching[0]["direction"] == "outgoing"
            assert int(matching[0]["observed_udp_length"]) == int(row["size"])
            assert int(matching[0]["scheduled_target"]) == int(row["size"])


def _normalized_controller_sequence(output):
    with (output / "schedule.csv").open(newline="") as source:
        schedule = sorted(
            [
                (
                    row["slot_id"],
                    row["target_time_us"],
                    row["direction"],
                    row["size"],
                )
                for row in csv.DictReader(source)
            ],
            key=lambda row: int(row[0]),
        )
    with (output / "events.csv").open(newline="") as source:
        actions_by_slot = {}
        for row in csv.DictReader(source):
            if row["event"] != "action":
                continue
            details = json.loads(row["details"])
            if details.get("type") not in {
                "send_packet",
                "increase_receive_limit",
                "slot_missed",
            }:
                continue
            slot = details.get("slot")
            if slot is None:
                continue
            actions_by_slot.setdefault(
                int(slot),
                (str(slot), details.get("packet")),
            )
    actions = [actions_by_slot[slot] for slot in sorted(actions_by_slot)]
    assert {row[0] for row in schedule} == {row[0] for row in actions}
    return schedule, actions


def _manifest(port, second_port=None):
    second_port = second_port or port
    return {
        "header_policy": {"mode": "minimal", "overrides": []},
        "resources": [
            {
                "id": 0,
                "url": f"https://127.0.0.1:{port}/131072",
                "type": "Document",
                "content_length": 131072,
                "data_length": 131072,
                "chaff_priority": True,
                "known_valid": True,
                "depends_on": [],
                "headers": [],
            },
            {
                "id": 1,
                "url": f"https://127.0.0.1:{port}/1024",
                "type": "Script",
                "content_length": 1024,
                "data_length": 1024,
                "chaff_priority": False,
                "known_valid": True,
                "depends_on": [0],
                "headers": [],
            },
            {
                "id": 2,
                "url": f"https://127.0.0.1:{second_port}/4096",
                "type": "Script",
                "content_length": 4096,
                "data_length": 4096,
                "chaff_priority": False,
                "known_valid": True,
                "depends_on": [0],
                "headers": [],
            },
            {
                "id": 3,
                "url": f"https://127.0.0.1:{second_port}/2048",
                "type": "Image",
                "content_length": 2048,
                "data_length": 2048,
                "chaff_priority": False,
                "known_valid": True,
                "depends_on": [2],
                "headers": [],
            },
        ],
    }
