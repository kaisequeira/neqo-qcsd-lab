"""Frozen per-class IPv4 identities for prospective resource-study ledgers.

Historical ledgers have no network contract. They remain readable without
claiming this contract, and cannot acquire it by adding fields to old receipts.
"""
from __future__ import annotations

import hashlib
import ipaddress
import math

from .resource_study_inputs import CLASS_COUNT, _hostname, canonical_json

NETWORK_RECORD = "qcsd-resource-study-class-network-v1"
ATTACHMENT_RECORD = "qcsd-resource-study-class-network-attachment-v1"
ACCEPTANCE = "resource-domain-20-complete-h3-fresh-connection-fixed-class-ip-v2"
TUPLE_SCOPE = "hostname-mode-study-root"
DEFAULT_POOL = "10.232.0.0/23"


def build_network_plan(hostnames, *, pool=DEFAULT_POOL):
    names = list(hostnames)
    if (len(names) != CLASS_COUNT or len(set(names)) != CLASS_COUNT
            or any(_hostname(host) != host for host in names)):
        raise ValueError("class network requires fifty distinct canonical hostnames")
    network = ipaddress.IPv4Network(pool, strict=True)
    private = [ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if str(network) != pool or network.prefixlen != 23 or not any(network.subnet_of(value) for value in private):
        raise ValueError("class address pool must be a canonical private IPv4 /23")
    subnets = list(network.subnets(new_prefix=29))
    assignments = {}
    for host, subnet in zip(sorted(names), subnets):
        assignments[host] = {"subnet": str(subnet), "gateway_ipv4": str(subnet[1]),
                             "router_ipv4": str(subnet[2]), "client_ipv4": str(subnet[3])}
    return {"record_type": NETWORK_RECORD, "pool": pool, "assignments": assignments}


def _network_plan_cache_bytes(plan):
    """Only exact JSON-native plans can share a canonical validation key."""
    def native(value, parents):
        kind = type(value)
        if kind in (str, int, bool) or value is None:
            return True
        if kind is float:
            return math.isfinite(value)
        if kind not in (dict, list) or id(value) in parents:
            return False
        parents.add(id(value))
        try:
            if kind is dict:
                return all(type(key) is str and native(item, parents) for key, item in value.items())
            return all(native(item, parents) for item in value)
        finally:
            parents.remove(id(value))
    try:
        if type(plan) is dict and native(plan, set()):
            return canonical_json(plan)
    except (TypeError, ValueError, OverflowError, RecursionError):
        pass
    return None


def validate_network_plan(plan, *, require=False):
    """Reuse pure validation only inside the existing one-call records owner."""
    # Store imports this module. Resolve the scope only when validation runs,
    # after module initialization, rather than introducing an import cycle.
    from .resource_study_store import _PLAN_READ_SCOPE
    scope = _PLAN_READ_SCOPE.get()
    if scope is None:
        return _uncached_validate_network_plan(plan, require=require)
    from .resource_study_cohorts import _RecordsRead
    if type(scope) is not _RecordsRead:
        raise ValueError("foreign records network validation scope")
    return scope.network_plan(plan, require=require)


def _uncached_validate_network_plan(plan, *, require=False):
    """Return validated assignments, or None for an unchanged historical plan."""
    present = {key for key in ("class_network", "tuple_uniqueness_scope") if key in plan}
    if "class_selection" in plan and present != {"class_network", "tuple_uniqueness_scope"}:
        raise ValueError("stable selection requires its complete map and tuple scope")
    if not present and not require and plan.get("acceptance") != ACCEPTANCE:
        return None
    if present != {"class_network", "tuple_uniqueness_scope"}:
        raise ValueError("study requires frozen class network mapping and tuple uniqueness scope")
    value = plan["class_network"]
    if isinstance(value, dict) and value.get("record_type") == "qcsd-resource-study-class-network-v3":
        if plan.get("acceptance") != ACCEPTANCE or plan["tuple_uniqueness_scope"] != TUPLE_SCOPE:
            raise ValueError("stable map cannot change physical acceptance or tuple scope")
        from .resource_study_lineage import validate_map
        return validate_map(plan)
    if "class_selection" in plan:
        raise ValueError("historical mapping cannot gain stable class selection authority")
    if (plan.get("acceptance") != ACCEPTANCE or plan["tuple_uniqueness_scope"] != TUPLE_SCOPE
            or not isinstance(value, dict) or set(value) != {"record_type", "pool", "assignments"}
            or value.get("record_type") != NETWORK_RECORD or not isinstance(value.get("assignments"), dict)):
        raise ValueError("persistent class network protocol or tuple scope differs")
    expected = build_network_plan(value["assignments"], pool=value["pool"])
    if value != expected:
        raise ValueError("class subnet/address assignment differs from the frozen deterministic mapping")
    return value["assignments"]


def mapping_sha256(plan):
    validate_network_plan(plan, require=True)
    return hashlib.sha256(canonical_json(plan["class_network"])).hexdigest()


def receipt_binding(plan, study_sha256, hostname):
    assignments = validate_network_plan(plan, require=True)
    if hostname not in assignments:
        raise ValueError("hostname has no frozen class network assignment")
    return {"record_type": plan["class_network"]["record_type"], "hostname": hostname,
            "mapping_sha256": mapping_sha256(plan), "assignment": assignments[hostname],
            "study_sha256": study_sha256, "tuple_uniqueness_scope": TUPLE_SCOPE}


def validate_receipt_network(plan, study_sha256, receipt):
    assignments = validate_network_plan(plan)
    fields = {"class_network", "study_sha256", "tuple_uniqueness_scope"}
    if assignments is None:
        if fields.intersection(receipt) or receipt.get("acceptance") == ACCEPTANCE:
            raise ValueError("historical study cannot gain prospective class network authority")
        return None
    host = receipt.get("hostname")
    expected = receipt_binding(plan, study_sha256, host)
    if (receipt.get("acceptance") != ACCEPTANCE or receipt.get("class_network") != expected
            or receipt.get("study_sha256") != study_sha256
            or receipt.get("tuple_uniqueness_scope") != TUPLE_SCOPE):
        raise ValueError("session persistent class network/plan binding differs")
    observed = receipt.get("five_tuple")
    if not isinstance(observed, list) or len(observed) != 5 or observed[0] != assignments[host]["client_ipv4"]:
        raise ValueError("observed client IP differs from its persistent class assignment")
    return expected


def check_collisions(plan, networks, host_routes):
    """Refuse overlap with existing Docker IPAM or nondefault host routes."""
    assignments = validate_network_plan(plan, require=True)
    planned = [ipaddress.IPv4Network(row["subnet"]) for row in assignments.values()]
    existing = []
    for network in networks:
        for item in network.get("IPAM", {}).get("Config") or []:
            if item.get("Subnet"):
                existing.append(("docker:" + str(network.get("Id")), ipaddress.ip_network(item["Subnet"], strict=False)))
    for route in host_routes:
        destination = route.get("dst")
        if destination and destination not in {"default", "0.0.0.0/0"}:
            existing.append(("host-route", ipaddress.ip_network(destination, strict=False)))
    for kind, network in existing:
        if network.version == 4 and any(subnet.overlaps(network) for subnet in planned):
            raise ValueError("frozen class subnet collides with " + kind + ": " + str(network))
    return {"planned_mapping_sha256": mapping_sha256(plan), "docker_networks": networks,
            "host_routes": host_routes, "collision_free": True}


def validate_client_route(assignment, addresses, defaults):
    if not isinstance(addresses, list) or len(addresses) != 1 or addresses[0].get("ifname") != "eth0":
        raise ValueError("class capture requires one observed client eth0 interface")
    address = addresses[0]
    ipv4 = [item for item in address.get("addr_info", []) if item.get("family") == "inet"]
    if ("UP" not in address.get("flags", []) or len(ipv4) != 1
            or ipv4[0].get("local") != assignment["client_ipv4"] or ipv4[0].get("prefixlen") != 29):
        raise ValueError("client eth0 does not have its exact persistent class address")
    if (not isinstance(defaults, list) or len(defaults) != 1
            or defaults[0].get("dst") != "default" or defaults[0].get("dev") != "eth0"
            or defaults[0].get("gateway") != assignment["router_ipv4"]):
        raise ValueError("class capture bypasses its routed observer")


def validate_attachment(plan, study_sha256, receipt, attachment):
    binding = validate_receipt_network(plan, study_sha256, receipt)
    if binding is None:
        raise ValueError("historical receipts have no prospective class attachment authority")
    from .kernel_tx import _public_topology_valid
    assignment = binding["assignment"]
    if (not isinstance(attachment, dict) or attachment.get("record_type") != ATTACHMENT_RECORD
            or attachment.get("hostname") != receipt["hostname"] or attachment.get("binding") != binding
            or not _public_topology_valid(attachment.get("network", {}), attachment.get("observer", {}))):
        raise ValueError("class routed topology/observer binding differs")
    network, observer = attachment["network"], attachment["observer"]
    endpoint = attachment.get("worker_endpoint", {})
    if (network["image_digest"] != receipt["runtime"]["collection_image_digest"]
            or network["topology"]["client_network"]["subnet"] != assignment["subnet"]
            or network["router"]["client_ipv4"] != assignment["router_ipv4"]
            or endpoint.get("IPAddress") != assignment["client_ipv4"]
            or endpoint.get("NetworkID") != observer["client_network"]["id"]
            or endpoint.get("Gateway") != assignment["gateway_ipv4"]
            or not isinstance(endpoint.get("EndpointID"), str) or len(endpoint["EndpointID"]) != 64
            or not isinstance(attachment.get("worker_container_id"), str) or len(attachment["worker_container_id"]) != 64):
        raise ValueError("observed class worker/router/network identity differs")
    validate_client_route(assignment, attachment.get("interface_addresses"), attachment.get("default_routes"))
    collision = attachment.get("collision_check", {})
    if (collision.get("collision_free") is not True
            or collision.get("planned_mapping_sha256") != mapping_sha256(plan)
            or check_collisions(plan, collision.get("docker_networks", []), collision.get("host_routes", [])) != collision):
        raise ValueError("class subnet collision-check binding differs")
    return binding


def validate_capture_join(attachment, collector, scheduler, *, scheduler_sha256, kernel_evidence=None):
    """Join independently validated raw scheduler/router facts to this attachment.

    The caller validates the complete scheduler evidence and, when required by
    the mode, the kernel measurement. These joins prevent borrowing a valid
    proof from another worker or routed observer.
    """
    partition = scheduler.get("host_partition", {})
    observer = attachment["observer"]["observer"]
    if (collector.get("scheduler_runtime_evidence_valid") is not True
            or collector.get("scheduler_runtime_evidence") != scheduler
            or collector.get("scheduler_runtime_evidence_sha256") != scheduler_sha256
            or partition.get("measured_container_id") != attachment["worker_container_id"]
            or hashlib.sha256(canonical_json(partition)).hexdigest() != attachment.get("host_partition_sha256")
            or partition.get("expected_sidecars", {}).get(observer["container_name"]) != observer["container_id"]):
        raise ValueError("class attachment differs from its measured worker/router scheduler proof")
    if kernel_evidence is not None:
        from .kernel_tx import kernel_tx_receipt_sha256
        if (kernel_evidence.get("controlled_network_receipt") != attachment["network"]
                or kernel_evidence.get("controlled_observer_binding") != attachment["observer"]
                or kernel_evidence.get("controlled_network_receipt_sha256") != kernel_tx_receipt_sha256(attachment["network"])):
            raise ValueError("kernel raw observer/network differs from the class attachment")
