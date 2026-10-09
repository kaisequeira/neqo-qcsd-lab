"""Prospective plan/ledger controls; synthetic metadata is no live capture proof."""
from copy import deepcopy
import hashlib
import ipaddress
import json

import pytest

from qcsd_lab import resource_study_network as network
from qcsd_lab import resource_study as study
from qcsd_lab.resource_study_inputs import canonical_json, MODES
from qcsd_lab.resource_study_store import StudyStore


HOSTS = [f"class-{index:02d}.example" for index in range(50)]


def plan():
    return {"schema_version": 1, "record_type": study.RECORD, "class_count": 50,
            "resources_per_session": 20, "sessions_per_mode": 400, "total_sessions": 100000,
            "modes": list(MODES), "acceptance": network.ACCEPTANCE,
            "class_network": network.build_network_plan(HOSTS), "tuple_uniqueness_scope": network.TUPLE_SCOPE}


def session(value, host=HOSTS[0]):
    digest = hashlib.sha256(canonical_json(value)).hexdigest()
    return {"hostname": host, "acceptance": network.ACCEPTANCE, "study_sha256": digest,
            "tuple_uniqueness_scope": network.TUPLE_SCOPE,
            "class_network": network.receipt_binding(value, digest, host),
            "five_tuple": [value["class_network"]["assignments"][host]["client_ipv4"], 40001, "8.8.8.8", 443, 17]}


def test_fifty_addresses_are_deterministic_disjoint_and_bound_across_modes():
    first = network.build_network_plan(HOSTS)
    assert first == network.build_network_plan(reversed(HOSTS))
    assignments = first["assignments"]
    assert len({row["client_ipv4"] for row in assignments.values()}) == 50
    subnets = [ipaddress.ip_network(row["subnet"]) for row in assignments.values()]
    assert all(not left.overlaps(right) for index, left in enumerate(subnets) for right in subnets[index + 1:])
    assert assignments[HOSTS[0]] == {"subnet": "10.232.0.0/29", "gateway_ipv4": "10.232.0.1",
                                   "router_ipv4": "10.232.0.2", "client_ipv4": "10.232.0.3"}
    for mode in MODES:
        value = plan()
        receipt = {**session(value), "mode": mode}
        assert network.validate_receipt_network(value, receipt["study_sha256"], receipt)["assignment"] == assignments[HOSTS[0]]


@pytest.mark.parametrize("mutation", ["missing-map", "missing-scope", "wrong-scope", "duplicate-ip", "wrong-subnet", "wrong-router", "missing-class", "extra-class", "wrong-protocol"])
def test_partial_aliased_or_changed_mapping_fails_closed(mutation):
    value = plan()
    assignments = value["class_network"]["assignments"]
    if mutation == "missing-map":value.pop("class_network")
    elif mutation == "missing-scope":value.pop("tuple_uniqueness_scope")
    elif mutation == "wrong-scope":value["tuple_uniqueness_scope"] = "per-flight"
    elif mutation == "duplicate-ip":assignments[HOSTS[1]]["client_ipv4"] = assignments[HOSTS[0]]["client_ipv4"]
    elif mutation == "wrong-subnet":assignments[HOSTS[1]]["subnet"] = assignments[HOSTS[0]]["subnet"]
    elif mutation == "wrong-router":assignments[HOSTS[0]]["router_ipv4"] = assignments[HOSTS[0]]["gateway_ipv4"]
    elif mutation == "missing-class":assignments.pop(HOSTS[0])
    elif mutation == "extra-class":assignments["extra.example"] = assignments[HOSTS[0]]
    elif mutation == "wrong-protocol":value["acceptance"] = "unrecorded-protocol"
    with pytest.raises(ValueError):network.validate_network_plan(value)


@pytest.mark.parametrize("pool", ["127.0.0.0/23", "169.254.0.0/23", "8.8.0.0/23", "10.232.0.0/24", "10.232.0.1/23", "::/23"])
def test_pool_is_canonical_rfc1918_and_has_fixed_capacity(pool):
    with pytest.raises(ValueError):network.build_network_plan(HOSTS, pool=pool)


@pytest.mark.parametrize("mutation", ["wrong-ip", "cross-class-ip", "wrong-host", "wrong-plan", "wrong-mapping-hash", "missing-binding", "wrong-scope"])
def test_receipt_cannot_borrow_class_address_or_plan_authority(mutation):
    value = plan();receipt = session(value)
    if mutation == "wrong-ip":receipt["five_tuple"][0] = "172.18.0.3"
    elif mutation == "cross-class-ip":receipt["five_tuple"][0] = value["class_network"]["assignments"][HOSTS[1]]["client_ipv4"]
    elif mutation == "wrong-host":receipt["hostname"] = HOSTS[1]
    elif mutation == "wrong-plan":receipt["study_sha256"] = "f" * 64
    elif mutation == "wrong-mapping-hash":receipt["class_network"]["mapping_sha256"] = "f" * 64
    elif mutation == "missing-binding":receipt.pop("class_network")
    elif mutation == "wrong-scope":receipt["tuple_uniqueness_scope"] = "worker-local"
    with pytest.raises(ValueError):network.validate_receipt_network(value, session(value)["study_sha256"], receipt)


def test_legacy_readers_remain_legacy_and_cannot_gain_new_authority():
    historical = {"schema_version": 1, "acceptance": study.ACCEPTANCE}
    assert network.validate_network_plan(historical) is None
    assert network.validate_receipt_network(historical, "a" * 64, {"acceptance": study.ACCEPTANCE}) is None
    with pytest.raises(ValueError):network.validate_network_plan(historical, require=True)
    with pytest.raises(ValueError):network.validate_receipt_network(historical, "a" * 64, session(plan()))


@pytest.mark.parametrize("location", ["docker", "host", "unused-class"])
def test_collision_guard_checks_docker_host_routes_and_unenrolled_assignments(location):
    value = plan();networks=[];routes=[]
    if location == "docker":networks=[{"Id": "other", "IPAM": {"Config": [{"Subnet": "10.232.0.0/16"}]}}]
    elif location == "host":routes=[{"dst": "10.0.0.0/8"}]
    else:routes=[{"dst": value["class_network"]["assignments"][HOSTS[-1]]["client_ipv4"]}]
    with pytest.raises(ValueError, match="collides"):network.check_collisions(value, networks, routes)
    assert network.check_collisions(value, [], [{"dst": "default"}, {"dst": "192.168.5.0/24"}])["collision_free"]


@pytest.mark.parametrize("key,changed,match", [("tuple_uniqueness_scope", "per-flight", "scope binding"),
    ("class_network_sha256", "f" * 64, "scope binding")])
def test_new_ledger_and_export_bind_scope_mapping_and_start_at_zero(tmp_path, key, changed, match):
    store = StudyStore(tmp_path / "new");value=plan();store.initialize(value)
    assert store.status()["accepted_count"] == 0
    output=store.export_manifest(tmp_path / "export.json")
    assert output["accepted_count"] == 0 and output["class_network"] == value["class_network"]
    assert output["tuple_uniqueness_scope"] == network.TUPLE_SCOPE
    with store._transaction() as connection:
        connection.execute("UPDATE meta SET value=? WHERE key=?", (changed, key))
    with pytest.raises(ValueError, match=match):store.plan()


def test_public_prepare_freezes_reserve_and_refuses_post_hoc_changes(tmp_path, capsys):
    source=tmp_path / "source.json"
    source.write_bytes(canonical_json([{"crUX_domain": "referrer.example", "resources": [
        {"resource_domain": host, "resource_urls": [f"https://{host}/r?i={i}" for i in range(20)]} for host in HOSTS]}]))
    root=tmp_path / "new"
    assert study.main(["prepare", "--root", str(root), "--source", str(source), "--storage-reserve-bytes", str(60*1024**3)]) == 0
    frozen=(root / "study.json").read_bytes()
    assert json.loads(frozen)["storage_reserve_bytes"] == 60*1024**3
    assert study.main(["prepare", "--root", str(root), "--storage-reserve-bytes", str(61*1024**3)]) != 0
    assert (root / "study.json").read_bytes() == frozen


def test_route_requires_exact_eth0_ip_and_class_router():
    assignment=plan()["class_network"]["assignments"][HOSTS[0]]
    addresses=[{"ifname":"eth0","flags":["UP"],"addr_info":[{"family":"inet","local":assignment["client_ipv4"],"prefixlen":29}]}]
    defaults=[{"dst":"default","dev":"eth0","gateway":assignment["router_ipv4"]}]
    network.validate_client_route(assignment, addresses, defaults)
    changed=deepcopy(defaults);changed[0]["gateway"]=assignment["gateway_ipv4"]
    with pytest.raises(ValueError, match="bypasses"):network.validate_client_route(assignment,addresses,changed)
    addresses[0]["addr_info"][0]["local"]="172.18.0.3"
    with pytest.raises(ValueError, match="persistent class address"):network.validate_client_route(assignment,addresses,defaults)
