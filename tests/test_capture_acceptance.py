import json
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

from qcsd_lab.campaign import _collect_sample, _compare_block
from qcsd_lab.plotting import plot_samples
from qcsd_lab.report import create_report
from qcsd_lab.util import load_json

from tests.test_local_acceptance import _manifest


@pytest.mark.skipif(
    os.environ.get("QCSD_RUN_CAPTURE_ACCEPTANCE") != "1",
    reason="set QCSD_RUN_CAPTURE_ACCEPTANCE=1 for privileged loopback capture gate",
)
def test_four_mode_capture_artifacts(tmp_path):
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
        block = tmp_path / "block"
        block.mkdir()
        root = Path("/lab")
        campaign = {
            "interface": "lo",
            "timeout_seconds": 45,
            "max_response_bytes": 2_097_152,
            "capture_duration_seconds": 50,
            "capture_filesize_mb": 128,
            "keep_raw": False,
            "export_pcap": False,
        }
        configs = {
            "none": root / "campaigns/defenses/none.toml",
            "static": root / "campaigns/defenses/static-short.toml",
            "front": root / "campaigns/defenses/front-conservative.toml",
            "tamaraw": root / "campaigns/defenses/tamaraw-conservative.toml",
        }
        for position, (name, config) in enumerate(configs.items()):
            sample = block / f"{position:02d}-{name}"
            _collect_sample(
                sample,
                manifest,
                {"name": name, "config": str(config)},
                42,
                campaign,
                campaign_path=root / "campaigns/example-live.yml",
                force=False,
            )
            metadata = load_json(sample / "sample.json")
            assert metadata["state"] == "captured", metadata
            for relative in (
                "traffic.pcapng",
                "traffic.csv",
                "neqo/run.json",
                "neqo/packets.csv",
                "neqo/events.csv",
                "neqo/schedule.csv",
                "SHA256SUMS",
            ):
                artifact = sample / relative
                assert artifact.exists() and artifact.stat().st_size > 0
            assert any((sample / "neqo/qlog").iterdir())
        _compare_block(block)
        assert all(
            load_json(sample / "sample.json")["comparison_eligible"]
            for sample in block.iterdir()
        )
        figures = tmp_path / "figures"
        plot_samples(sorted(block.iterdir()), figures)
        for artifact in (
            "figure-2-comparison.png",
            "figure-2-comparison.svg",
            "figure-2-comparison.pdf",
            "figure-2-comparison.html",
            "metrics.csv",
        ):
            assert (figures / artifact).stat().st_size > 0
        for sample in block.iterdir():
            sample_figures = figures / sample.name
            for artifact in (
                "observer-unfiltered.png",
                "observer-unfiltered.svg",
                "observer-unfiltered.pdf",
                "observer-unfiltered.html",
                "metrics.json",
            ):
                assert (sample_figures / artifact).stat().st_size > 0
        report = tmp_path / "report"
        create_report(tmp_path, report)
        for artifact in ("report.csv", "report.md", "report.html"):
            assert (report / artifact).stat().st_size > 0
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
