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
ISOLATED_LANE_POLICY = "isolated-class-lanes-v2"
ISOLATED_LANE_NETWORK = "qcsd-kernel-tx-public-network-isolated-lane-v2"
ISOLATED_LANE_OBSERVER = "qcsd-kernel-tx-public-observer-binding-isolated-lane-v2"
ISOLATED_LANE_ATTACHMENT = "qcsd-resource-study-class-network-attachment-isolated-lane-v2"
LANE_TRANSPORT_POOL = "172.30.224.0/19"


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
    if isinstance(attachment, dict) and attachment.get("record_type") == ISOLATED_LANE_ATTACHMENT:
        return validate_isolated_lane_attachment(plan, study_sha256, receipt, attachment)
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


def isolated_lane_plan(plan, host_runtime_keys, runtime_keys, *, pool=LANE_TRANSPORT_POOL):
    """Allocate unique Docker L2 transport; retain the frozen kernel class /29.

    Docker IPAM never pretends that overlapping logical addresses are unique.
    Each compatible (hostname, lane) has its own bridge/router namespace.
    """
    assignments = validate_network_plan(plan, require=True)
    transport_pool = ipaddress.IPv4Network(pool, strict=True)
    if (pool != LANE_TRANSPORT_POOL or str(transport_pool) != pool or transport_pool.prefixlen != 19 or not transport_pool.is_private
            or type(host_runtime_keys) is not dict or not host_runtime_keys
            or set(host_runtime_keys) - set(assignments)
            or type(runtime_keys) not in (list, tuple) or not 2 <= len(runtime_keys) <= 11
            or set(runtime_keys) != set(host_runtime_keys.values())):
        raise ValueError("isolated lanes require explicit compatible lanes and a private /19 transport pool")
    subnets = list(transport_pool.subnets(new_prefix=29))
    rows = []
    for host_index, hostname in enumerate(sorted(assignments)):
        if hostname not in host_runtime_keys:
            continue
        for lane, runtime in enumerate(runtime_keys):
            if runtime != host_runtime_keys[hostname]:
                continue
            subnet = subnets[host_index * 11 + lane]
            logical = assignments[hostname]
            if any(subnet.overlaps(ipaddress.IPv4Network(value["subnet"])) for value in assignments.values()):
                raise ValueError("Docker transport overlaps a frozen logical class subnet")
            rows.append({"hostname": hostname, "lane": lane, "assignment": dict(logical),
                "transport_assignment": {"subnet": str(subnet), "gateway_ipv4": str(subnet[1]),
                    "router_ipv4": str(subnet[2]), "client_ipv4": str(subnet[3])}})
    return rows


def check_lane_collisions(plan, rows, networks, host_routes):
    """Check both actual Docker transport and unchanged logical class space."""
    original = check_collisions(plan, networks, host_routes)
    assignments = validate_network_plan(plan, require=True)
    subnets = list(ipaddress.IPv4Network(LANE_TRANSPORT_POOL).subnets(new_prefix=29))
    if type(rows) is not list or not 1 <= len(rows) <= 550:
        raise ValueError("isolated lane collision census is absent or unbounded")
    keys = set()
    for row in rows:
        if (type(row) is not dict or set(row) != {"hostname", "lane", "assignment", "transport_assignment"}
                or row["hostname"] not in assignments or type(row["lane"]) is not int or not 0 <= row["lane"] < 11
                or row["assignment"] != assignments[row["hostname"]] or (row["hostname"], row["lane"]) in keys):
            raise ValueError("isolated lane collision census changed its explicit class/lane mapping")
        keys.add((row["hostname"], row["lane"]))
        subnet = subnets[sorted(assignments).index(row["hostname"]) * 11 + row["lane"]]
        if row["transport_assignment"] != {"subnet":str(subnet), "gateway_ipv4":str(subnet[1]),
                "router_ipv4":str(subnet[2]), "client_ipv4":str(subnet[3])}:
            raise ValueError("isolated lane changed its deterministic Docker transport assignment")
    transports = [ipaddress.IPv4Network(row["transport_assignment"]["subnet"], strict=True) for row in rows]
    if len(transports) != len(set(transports)):
        raise ValueError("isolated lanes repeat Docker transport space")
    existing = [ipaddress.ip_network(item["Subnet"], strict=False)
        for network in networks for item in network.get("IPAM", {}).get("Config") or [] if item.get("Subnet")]
    existing += [ipaddress.ip_network(row["dst"], strict=False) for row in host_routes
        if row.get("dst") and row["dst"] not in ("default", "0.0.0.0/0")]
    logical = [ipaddress.IPv4Network(row["subnet"]) for row in validate_network_plan(plan, require=True).values()]
    if any(a.overlaps(b) for a in transports for b in [*logical, *existing] if b.version == 4):
        raise ValueError("isolated lane transport collides with a class, Docker network or host route")
    return {"policy": ISOLATED_LANE_POLICY, "rows": rows, "class_collision_check": original,
            "collision_free": True}


def _lane_endpoint(endpoint, assignment, network_id, *, router=False):
    expected = assignment["router_ipv4" if router else "client_ipv4"]
    def digest(value):
        return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    if (not isinstance(endpoint, dict) or endpoint.get("IPAddress") != expected
            or endpoint.get("Gateway") != assignment["gateway_ipv4"]
            or endpoint.get("NetworkID") != network_id or not digest(network_id)
            or not digest(endpoint.get("EndpointID"))):
        raise ValueError("Docker-declared lane endpoint does not match its actual transport assignment")


def isolated_lane_public_view(network, observer):
    """Validate explicit v2 provenance; project only the common routing contract.

    This projection is internal validation, never an emitted or credited v1
    receipt. All raw evidence continues to hash and retain the complete v2.
    """
    from copy import deepcopy
    if (type(network) is not dict or type(observer) is not dict
            or network.get("artifact_type") != ISOLATED_LANE_NETWORK or network.get("schema_version") != 2
            or observer.get("artifact_type") != ISOLATED_LANE_OBSERVER or observer.get("schema_version") != 2
            or "isolation" not in network or observer.get("isolation") != network["isolation"]):
        raise ValueError("isolated-lane topology requires its explicit v2 record types")
    isolation = network["isolation"]
    if (type(isolation) is not dict or set(isolation) != {"policy", "hostname", "lane", "logical_assignment",
            "docker_transport", "router_interface_addresses", "router_routes", "router_namespace"}
            or isolation["policy"] != ISOLATED_LANE_POLICY
            or _hostname(isolation["hostname"]) != isolation["hostname"]
            or type(isolation["lane"]) is not int or not 0 <= isolation["lane"] < 11):
        raise ValueError("isolated-lane identity is malformed")
    logical, transport = isolation["logical_assignment"], isolation["docker_transport"]
    fields = {"subnet", "gateway_ipv4", "router_ipv4", "client_ipv4"}
    if type(logical) is not dict or set(logical) != fields or type(transport) is not dict or set(transport) != {"assignment", "router_endpoint"}:
        raise ValueError("logical and Docker transport assignments must be separately recorded")
    for assignment in (logical, transport["assignment"]):
        if type(assignment) is not dict or set(assignment) != fields:
            raise ValueError("lane address assignment is malformed")
        subnet = ipaddress.IPv4Network(assignment["subnet"], strict=True)
        if (subnet.prefixlen != 29 or not subnet.is_private or assignment != {"subnet":str(subnet),
                "gateway_ipv4":str(subnet[1]), "router_ipv4":str(subnet[2]), "client_ipv4":str(subnet[3])}):
            raise ValueError("lane assignment differs from its exact private /29 positions")
    if ipaddress.IPv4Network(logical["subnet"]).overlaps(ipaddress.IPv4Network(transport["assignment"]["subnet"])):
        raise ValueError("Docker transport and logical class addresses must be distinct")
    _lane_endpoint(transport["router_endpoint"], transport["assignment"], observer.get("client_network", {}).get("id"), router=True)
    addresses = isolation["router_interface_addresses"]
    if type(addresses) is not list or len(addresses) != 1 or addresses[0].get("ifname") != "eth0" or "UP" not in addresses[0].get("flags", []):
        raise ValueError("router kernel eth0 observation is absent")
    ipv4 = [a for a in addresses[0].get("addr_info", []) if a.get("family") == "inet"]
    if len(ipv4) != 1 or ipv4[0].get("local") != logical["router_ipv4"] or ipv4[0].get("prefixlen") != 29:
        raise ValueError("router kernel address differs from the unchanged logical class router")
    routes = isolation["router_routes"]
    if (type(routes) is not list or not any(r.get("dst") == logical["subnet"] and r.get("dev") == "eth0" for r in routes)
            or len([r for r in routes if r.get("dst") == "default"]) != 1
            or not any(r.get("dst") == "default" and r.get("dev") == "eth1" for r in routes)
            or any(r.get("dev") == "eth0" and r.get("dst") != logical["subnet"] for r in routes)
            or type(isolation["router_namespace"]) is not str
            or not isolation["router_namespace"].startswith("/var/run/docker/netns/")
            or len(isolation["router_namespace"].split("/")) != 6):
        raise ValueError("isolated router kernel routes or actual Docker namespace are invalid")
    if (network.get("topology", {}).get("client_network", {}).get("subnet") != logical["subnet"]
            or network.get("router", {}).get("client_ipv4") != logical["router_ipv4"]
            or observer.get("observer", {}).get("ipv4") != logical["router_ipv4"]):
        raise ValueError("logical fixed class address is not the actual recorded routing address")
    view, binding = deepcopy(network), deepcopy(observer)
    del view["isolation"]; del binding["isolation"]
    view.update(schema_version=1, artifact_type="qcsd-kernel-tx-public-network-v1")
    binding.update(schema_version=1, artifact_type="qcsd-kernel-tx-public-observer-binding")
    from .kernel_tx import _public_topology_valid
    if not _public_topology_valid(view, binding):
        raise ValueError("isolated lanes fail the unchanged public routing/observer contract")
    return view, binding


def validate_isolated_lane_attachment(plan, study_sha256, receipt, attachment):
    binding = validate_receipt_network(plan, study_sha256, receipt)
    if (binding is None or attachment.get("record_type") != ISOLATED_LANE_ATTACHMENT
            or attachment.get("hostname") != receipt["hostname"] or attachment.get("binding") != binding):
        raise ValueError("isolated attachment changed the original study/class/tuple contract")
    network, observer = attachment.get("network"), attachment.get("observer")
    isolated_lane_public_view(network, observer)
    isolation = network["isolation"]
    if (isolation["hostname"] != receipt["hostname"] or isolation["logical_assignment"] != binding["assignment"]
            or network["image_digest"] != receipt["runtime"]["collection_image_digest"]
            or attachment.get("lane") != isolation["lane"]
            or type(attachment.get("worker_namespace")) is not str
            or not attachment["worker_namespace"].startswith("/var/run/docker/netns/")
            or len(attachment["worker_namespace"].split("/")) != 6
            or attachment["worker_namespace"] == isolation["router_namespace"]
            or type(attachment.get("worker_container_id")) is not str
            or len(attachment["worker_container_id"]) != 64
            or any(c not in "0123456789abcdef" for c in attachment["worker_container_id"])
            or attachment["worker_container_id"] == observer["observer"]["container_id"]
            or attachment.get("worker_endpoint", {}).get("EndpointID") == observer["client_network"]["router_endpoint_id"]):
        raise ValueError("isolated attachment changed its lane, runtime or real namespace")
    catalog = receipt.get("capture_catalog")
    if catalog is not None and (type(catalog) is not dict or catalog.get("worker") != isolation["lane"]
            or catalog.get("record_type") != "qcsd-resource-domain-existing-member-runtime-catalog-receipt-v2"
            or catalog.get("schema_version") != 2 or catalog.get("topology_policy") != ISOLATED_LANE_POLICY):
        raise ValueError("isolated attachment lane differs from its original catalog receipt")
    _lane_endpoint(attachment.get("worker_endpoint"), isolation["docker_transport"]["assignment"], observer["client_network"]["id"])
    validate_client_route(binding["assignment"], attachment.get("interface_addresses"), attachment.get("default_routes"))
    collision = attachment.get("collision_check", {})
    if (collision.get("collision_free") is not True or collision.get("planned_mapping_sha256") != mapping_sha256(plan)
            or check_collisions(plan, collision.get("docker_networks", []), collision.get("host_routes", [])) != collision):
        raise ValueError("isolated attachment lacks the original class collision guard")
    lane_check = attachment.get("lane_collision_check", {})
    rows = lane_check.get("rows", [])
    expected_row = {"hostname":isolation["hostname"], "lane":isolation["lane"],
        "assignment":binding["assignment"], "transport_assignment":isolation["docker_transport"]["assignment"]}
    if (expected_row not in rows or lane_check.get("class_collision_check") != collision
            or check_lane_collisions(plan, rows, collision["docker_networks"], collision["host_routes"]) != lane_check):
        raise ValueError("isolated attachment lacks its actual transport collision guard")
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
