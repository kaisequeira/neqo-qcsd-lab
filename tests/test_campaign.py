from pathlib import Path

from qcsd_lab.campaign import _derived_seed, _split_endpoint, _tuple_filter, load_campaign


def test_seed_derivation_is_stable_and_separates_defenses():
    assert _derived_seed(42, "site", 0, "front") == _derived_seed(42, "site", 0, "front")
    assert _derived_seed(42, "site", 0, "front") != _derived_seed(42, "site", 0, "tamaraw")


def test_endpoint_parser_and_exact_filter_support_both_ip_versions():
    assert _split_endpoint("172.17.0.2:50000") == ("172.17.0.2", 50000)
    assert _split_endpoint("[2001:db8::1]:443") == ("2001:db8::1", 443)
    display_filter = _tuple_filter(
        [
            {
                "id": 0,
                "local_address": "172.17.0.2:50000",
                "remote_address": "203.0.113.1:443",
            },
            {
                "id": 1,
                "local_address": "[2001:db8::2]:50001",
                "remote_address": "[2001:db8::1]:443",
            },
        ]
    )
    assert "udp.srcport==50000" in display_filter
    assert "ip.src==172.17.0.2" in display_filter
    assert "ipv6.src==2001:db8::2" in display_filter


def test_example_campaign_expands_paths():
    root = Path(__file__).parents[1]
    campaign = load_campaign(root / "campaigns/example-live.yml")
    assert campaign["repetitions"] == 1
    assert Path(campaign["workloads"][0]["manifest"]).is_absolute()
    assert all(Path(defense["config"]).is_absolute() for defense in campaign["defenses"])
