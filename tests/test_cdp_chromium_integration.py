"""Opt-in live check of the receipt-producing pinned-CDP probe implementation."""

from __future__ import annotations

import os

import pytest

from qcsd_lab.pinned_cdp import run_pinned_cdp_probe

pytestmark = pytest.mark.skipif(
    os.environ.get("QCSD_RUN_PINNED_CDP_PROBE") != "1",
    reason="set QCSD_RUN_PINNED_CDP_PROBE=1 inside the prepare image",
)


def test_pinned_chromium_recursive_topology_and_shutdown() -> None:
    """Exercise the exact implementation used to publish the durable receipt."""

    observation = run_pinned_cdp_probe(
        expected_uid=int(os.environ["QCSD_PINNED_CDP_EXPECTED_UID"]),
        expected_gid=int(os.environ["QCSD_PINNED_CDP_EXPECTED_GID"]),
    )
    topology = observation["topology"]
    assert {"iframe", "worker", "shared_worker"}.issubset(
        topology["observed_target_types"]
    )
    assert topology["worker_network_target_types"] == ["shared_worker", "worker"]
    assert topology["duplicate_request_occurrences"] == 2
    assert topology["worker_fetch_paused_on_page"] is True
    assert topology["router_closed"] is True
    assert topology["ledger_closed"] is True
    assert topology["extra_info_closed"] is True
    assert topology["browser_closed"] is True
    assert topology["server_thread_stopped"] is True
