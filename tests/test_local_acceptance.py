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
    reason="set QCSD_RUN_LOCAL_ACCEPTANCE=1 for the four-mode local HTTP/3 gate",
)
def test_unmodified_local_server_all_defenses(tmp_path):
    port = _free_port()
    server = subprocess.Popen(
        ["neqo-server", f"127.0.0.1:{port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        time.sleep(0.5)
        manifest = tmp_path / "workload.json"
        manifest.write_text(json.dumps(_manifest(port)), encoding="utf-8")
        root = Path("/lab")
        defenses = {
            "none": root / "campaigns/defenses/none.toml",
            "static": root / "campaigns/defenses/static-short.toml",
            "front": root / "campaigns/defenses/front-conservative.toml",
            "tamaraw": root / "campaigns/defenses/tamaraw-conservative.toml",
        }
        hashes = {}
        for name, config in defenses.items():
            output = tmp_path / name
            result = subprocess.run(
                [
                    "neqo-qcsd-client",
                    "run",
                    "--workload",
                    str(manifest),
                    "--chaff-manifest",
                    str(manifest),
                    "--config",
                    str(config),
                    "--seed",
                    "42",
                    "--output-dir",
                    str(output),
                    "--max-response-bytes",
                    "2097152",
                    "--timeout-seconds",
                    "45",
                ],
                cwd=root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            assert result.returncode == 0, f"{name}: {result.stdout}"
            run_data = json.loads((output / "run.json").read_text())
            assert run_data["completion_status"] == "complete"
            assert [response["resource_id"] for response in run_data["responses"]] == [0, 1]
            assert all(response["status"] == 200 for response in run_data["responses"])
            hashes[name] = [response["body_sha256"] for response in run_data["responses"]]
            for artifact in ("packets.csv", "events.csv", "schedule.csv"):
                assert (output / artifact).exists()
            if name != "none":
                with (output / "schedule.csv").open(newline="") as source:
                    assert len(list(csv.DictReader(source))) > 0
        assert len({tuple(value) for value in hashes.values()}) == 1
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _manifest(port):
    return {
        "schema_version": 2,
        "header_policy": {"mode": "minimal", "overrides": []},
        "resources": [
            {
                "id": 0,
                "url": f"https://127.0.0.1:{port}/1048576",
                "type": "Document",
                "content_length": 1048576,
                "data_length": 1048576,
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
        ],
    }
