"""One prospective unused-class replacement; historical maps remain immutable.

This authority changes the selected class set, not any retained class address
or installed Native/collector contract. It deliberately supports only the
reviewed original-map -> Xoilac/MAL transition, not arbitrary map migrations.
The resulting selected50 is global across defenses; per-mode replacement is
not supported, including for future WT/TM protocol extensions.
"""
from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import sqlite3

from .resource_study_inputs import canonical_json, candidate_catalogue, sha256_file

MAP = "qcsd-resource-study-class-network-v3"
SELECTION = "qcsd-resource-study-class-selection-v3"
TRANSITION = "qcsd-resource-study-unused-class-transition-v3"
ADMISSION = "qcsd-resource-domain-cell-epoch-admission-v3"
COMPOSITION = "qcsd-resource-domain-cell-epoch-composition-v3"
EXCLUDED = "static.xoilacxba.tv"
INCLUDED = "cdn.myanimelist.net"
RESERVES = [INCLUDED, "ahrefs.com"]
MANIFEST = "inputs/class-selection/selection.json"
INVENTORY = "inputs/class-selection/reserve-inventory.json"
SOURCE = "inputs/supplied-resources.json"
FENCE = "class-write-fence.json"
FENCE_TYPE = "qcsd-resource-study-class-write-fence-v3"
FENCE_PREFIX = "qcsd_class_v3_"
FENCE_FUNCTION = "qcsd_class_v3_write_allowed"
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def digest(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def present(plan):
    return ("class_selection" in plan
            or isinstance(plan.get("class_network"), dict) and plan["class_network"].get("record_type") == MAP)


def build(predecessor, source_sha256, parent_root, parent_study_sha256,
          parent_admission_sha256, inventory_sha256):
    """Build an explicit new authority; this grants no parent membership."""
    from .resource_study_network import NETWORK_RECORD, build_network_plan
    if (predecessor.get("record_type") != NETWORK_RECORD
            or predecessor != build_network_plan(predecessor["assignments"], pool=predecessor["pool"])
            or EXCLUDED not in predecessor["assignments"] or INCLUDED in predecessor["assignments"]):
        raise ValueError("stable replacement requires the original map and unused Xoilac slot")
    assignments = deepcopy(predecessor["assignments"])
    assignments[INCLUDED] = assignments.pop(EXCLUDED)
    network = {"record_type": MAP, "pool": predecessor["pool"], "assignments": assignments,
               "predecessor": deepcopy(predecessor), "predecessor_sha256": digest(predecessor),
               "excluded_hostname": EXCLUDED, "included_hostname": INCLUDED}
    selection = {"record_type": SELECTION, "source_sha256": source_sha256,
                 "parent_root": str(parent_root), "parent_study_sha256": parent_study_sha256,
                 "parent_admission_sha256": parent_admission_sha256,
                 "predecessor_mapping_sha256": digest(predecessor),
                 "mapping_sha256": digest(network), "excluded_hostname": EXCLUDED,
                 "included_hostname": INCLUDED, "reserve_order": RESERVES[:],
                 "selected_hostnames": sorted(assignments),
                 "reserve_inventory": {"path": INVENTORY, "sha256": inventory_sha256}}
    return network, selection


def validate_map(plan):
    """Pure complete-map validation, including the unchanged49 proof."""
    try:
        return _validate_map(plan)
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("stable map authority has malformed field types") from error


def _validate_map(plan):
    from .resource_study_network import build_network_plan
    value, selection = plan.get("class_network"), plan.get("class_selection")
    map_keys = {"record_type", "pool", "assignments", "predecessor", "predecessor_sha256",
                "excluded_hostname", "included_hostname"}
    selection_keys = {"record_type", "source_sha256", "parent_root", "parent_study_sha256",
                      "parent_admission_sha256", "predecessor_mapping_sha256", "mapping_sha256",
                      "excluded_hostname", "included_hostname", "reserve_order",
                      "selected_hostnames", "reserve_inventory"}
    if (not isinstance(value, dict) or set(value) != map_keys or value["record_type"] != MAP
            or not isinstance(selection, dict) or set(selection) != selection_keys
            or selection["record_type"] != SELECTION):
        raise ValueError("stable class selection/map authority is partial or unversioned")
    predecessor = value["predecessor"]
    if (not isinstance(predecessor, dict)
            or set(predecessor) != {"record_type", "pool", "assignments"}
            or predecessor.get("record_type") != "qcsd-resource-study-class-network-v1"):
        raise ValueError("stable map requires one original deterministic predecessor")
    expected_old = build_network_plan(predecessor["assignments"], pool=predecessor["pool"])
    if predecessor != expected_old or value["pool"] != predecessor["pool"]:
        raise ValueError("stable predecessor mapping differs")
    expected = deepcopy(predecessor["assignments"])
    if EXCLUDED not in expected or INCLUDED in expected:
        raise ValueError("stable predecessor lacks the reviewed unused slot")
    expected[INCLUDED] = expected.pop(EXCLUDED)
    if (value["assignments"] != expected or value["excluded_hostname"] != EXCLUDED
            or value["included_hostname"] != INCLUDED or value["predecessor_sha256"] != digest(predecessor)):
        raise ValueError("stable replacement changes a retained assignment or the named unused slot")
    inventory = selection["reserve_inventory"]
    hashes = [selection.get(k) for k in ("source_sha256", "parent_study_sha256", "parent_admission_sha256",
              "predecessor_mapping_sha256", "mapping_sha256")]
    parent = selection["parent_root"]
    if (any(not isinstance(v, str) or _SHA.fullmatch(v) is None for v in hashes)
            or not isinstance(parent, str) or not Path(parent).is_absolute()
            or str(Path(parent)) != parent or ".." in Path(parent).parts or any(ord(c) < 32 for c in parent)
            or selection["source_sha256"] != plan.get("source_sha256")
            or selection["predecessor_mapping_sha256"] != digest(predecessor)
            or selection["mapping_sha256"] != digest(value)
            or selection["excluded_hostname"] != EXCLUDED or selection["included_hostname"] != INCLUDED
            or selection["reserve_order"] != RESERVES or selection["selected_hostnames"] != sorted(expected)
            or not isinstance(inventory, dict) or set(inventory) != {"path", "sha256"}
            or inventory["path"] != INVENTORY or not isinstance(inventory["sha256"], str)
            or _SHA.fullmatch(inventory["sha256"]) is None):
        raise ValueError("stable map/source/selection/predecessor binding differs")
    return value["assignments"]


def validate_context(store, plan=None):
    """Bind actual frozen source/inventory bytes, not only their claimed hashes."""
    from .resource_study_supplements import load_inventory_candidates
    from .resource_study_store import _load
    plan = plan if plan is not None else store.plan()
    validate_map(plan)
    selection = plan["class_selection"]
    for name, expected in ((MANIFEST, digest(selection)), (SOURCE, selection["source_sha256"]),
                           (INVENTORY, selection["reserve_inventory"]["sha256"])):
        raw, observed = store._file(name, expected)
        if observed["mode"] != "0444":
            raise ValueError("stable selection input is mutable")
        if name == MANIFEST and _load(raw) != selection:
            raise ValueError("stable selection manifest differs from its plan")
    source = candidate_catalogue(store.root / SOURCE)
    original = [r["hostname"] for r in source["candidates"] if r["eligible"]][:50]
    if set(original) != set(plan["class_network"]["predecessor"]["assignments"]):
        raise ValueError("stable original source does not bind predecessor50")
    candidates = load_inventory_candidates([store.root / INVENTORY])["candidates"]
    if (len(candidates) != 1 or candidates[0]["hostname"] != INCLUDED
            or candidates[0]["eligible"] is not True):
        raise ValueError("stable reserve inventory needs twenty literal MAL candidates")
    return selection


def bind_enrollment(store, enrollment, *, plan=None):
    plan = store.plan() if plan is None else plan
    if not present(plan):
        return enrollment
    selection = validate_context(store, plan)
    value = deepcopy(enrollment)
    value["class_selection"] = {"record_type": SELECTION, "selection_sha256": digest(selection),
                                "study_sha256": store._file("study.json")[1]["sha256"]}
    for name in (MANIFEST, SOURCE, INVENTORY):
        value["files"][name] = store._file(name)[1]["sha256"]
    return value


def validate_enrollment(store, enrollment, *, plan=None):
    plan = store.plan() if plan is None else plan
    if not present(plan):
        if "class_selection" in enrollment:
            raise ValueError("historical enrollment cannot gain stable selection authority")
        return
    expected = bind_enrollment(store, {**enrollment, "files": {}}, plan=plan)
    if (enrollment.get("class_selection") != expected["class_selection"]
            or any(enrollment.get("files", {}).get(k) != v for k, v in expected["files"].items())):
        raise ValueError("enrollment lacks its immutable stable selection context")
    if enrollment["hostname"] not in plan["class_network"]["assignments"]:
        raise ValueError("enrollment hostname is outside selected50")
    if enrollment["hostname"] == INCLUDED:
        # Keep the reserve's original literal inventory authority unchanged.
        from .resource_study_supplements import load_inventory_candidates
        candidate = load_inventory_candidates([store.root / INVENTORY])["candidates"][0]
    else:
        # A stable child also carries the authenticated original source. Its
        # retained49 keep their original URL/order/occurrence authority; the
        # MAL reserve catalogue cannot authorize another hostname's resources.
        candidates = candidate_catalogue(store.root / SOURCE)["candidates"]
        candidate = next((row for row in candidates if row["hostname"] == enrollment["hostname"]), None)
        if (enrollment["hostname"] not in plan["class_network"]["predecessor"]["assignments"]
                or candidate is None or candidate["eligible"] is not True):
            raise ValueError("stable retained enrollment is outside the authenticated original49 pool")
    urls = enrollment.get("urls")
    if (not isinstance(urls, list) or len(urls) != 20
            or any(type(url) is not str for url in urls)
            or len(set(urls)) != 20 or any(url not in candidate["urls"] for url in urls)
            or urls != sorted(urls, key=candidate["urls"].index)
            or enrollment.get("source_occurrences") != candidate["source_occurrences"]):
        label = "reserve" if enrollment["hostname"] == INCLUDED else "retained"
        raise ValueError(f"stable {label} enrollment differs from authenticated literal pool/order/provenance")
    # The historical/default path imports no unbound selector module. An
    # explicit or partial selector must replay its complete immutable job and
    # input/workload proof, including on pure receipt-reader workers.
    if (any(name == "resource_selection" or name.startswith("resource_selection_") for name in enrollment)
            or any(name.startswith("inputs/resource-selections/") for name in enrollment.get("files", {}))):
        from .resource_study_selection import validate_selection_proof
        validate_selection_proof(store.root, enrollment)


def validate_receipt_enrollment(root, plan, enrollment):
    """Pure raw-proof reader: no Store, ledger connection, or write-capable API."""
    import stat
    from .resource_study_verify import within
    class Files:
        def __init__(self):
            self.root = Path(root)
        def _file(self, relative, expected=None):
            path = within(self.root, relative)
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("stable receipt context is not one regular file")
            raw = path.read_bytes()
            sha = hashlib.sha256(raw).hexdigest()
            if expected is not None and sha != expected:
                raise ValueError("stable receipt context SHA256 differs")
            return raw, {"sha256": sha, "mode": f"{stat.S_IMODE(info.st_mode):04o}"}
    validate_enrollment(Files(), enrollment, plan=plan)


def unused(parent, records):
    """Check every historical parent member; failed preparation is preserved."""
    from .resource_study_store import StudyStore
    from .resource_study_epochs import _membership
    roots = {str(parent.root)} | {c["root"] for r in records for c in r["cells"]}
    if any(c["hostname"] in {EXCLUDED, INCLUDED} for r in records for c in r["cells"]):
        raise ValueError("replacement requires two previously unselected class names")
    proof = []
    for path in sorted(roots):
        store = StudyStore(path)
        member_parent = _membership(store)
        if member_parent is None or member_parent.root != parent.root:
            raise ValueError("stable transition history includes a foreign member")
        for host in (EXCLUDED, INCLUDED):
            if any((store.root / kind / host).exists() or (store.root / kind / host).is_symlink()
                   for kind in ("classes", "attempts", "corpus", "pilots")):
                raise ValueError("stable replacement class has published or orphan session/enrollment history")
        with store._transaction() as connection:
            if connection.execute("SELECT 1 FROM attempts WHERE state IN ('reserved','captured','unverified')").fetchone():
                raise ValueError("stable transition member is active")
            for table in ("classes", "attempts", "accepted"):
                if connection.execute(f"SELECT 1 FROM {table} WHERE hostname IN (?,?)", (EXCLUDED, INCLUDED)).fetchone():
                    raise ValueError("stable replacement class has enrollment/session/accepted history")
        flights = {}
        for launched in sorted((store.root / "flights").glob("*/launched.json")):
            from .resource_study_store import _load
            closure = launched.with_name("closed.json")
            if not closure.exists():
                raise ValueError("stable transition has an unclosed flight or cleanup error")
            launch_raw, launch_info = store._file(launched.relative_to(store.root).as_posix())
            close_raw, close_info = store._file(closure.relative_to(store.root).as_posix())
            if (launch_info["mode"] != "0444" or close_info["mode"] != "0444"
                    or _load(close_raw).get("cleanup_errors") != []):
                raise ValueError("stable transition flight closure authority differs")
            flights[launched.parent.name] = {"launched_sha256": launch_info["sha256"],
                                             "closed_sha256": close_info["sha256"]}
        proof.append({"root": path, "study_sha256": store._file("study.json")[1]["sha256"],
                      "closed_flights": flights})
    return proof


def initialize(parent_path, root, inventory_path, *, storage_reserve_bytes):
    """Freeze a fresh candidate child, without selecting it in the parent."""
    from .resource_study_store import StudyStore, _create
    from .resource_study_epochs import _lock, _records
    from .resource_study_runtime import docker_lock
    from .resource_study import add_inventories, authenticated_input
    from .resource_study_supplements import load_inventory_candidates
    parent, root = StudyStore(parent_path), Path(root).absolute()
    if (root.exists() or root.is_symlink() or ".." in root.parts
            or any(p.is_symlink() for p in root.parents)):
        raise ValueError("stable-map initialization requires a fresh nonexistent root")
    if type(storage_reserve_bytes) is not int or storage_reserve_bytes < 2 * 1024 ** 3:
        raise ValueError("study storage reserve must be an integer of at least two GiB")
    catalogue = load_inventory_candidates([inventory_path])
    if (len(catalogue["candidates"]) != 1 or catalogue["candidates"][0]["hostname"] != INCLUDED
            or catalogue["candidates"][0]["eligible"] is not True):
        raise ValueError("stable reserve initialization requires only literal MAL candidates")
    inventory_sha = catalogue["inventory_files"][0]["sha256"]
    with docker_lock(), _lock(parent.root):
        old = parent.plan()
        records = _records(parent)
        if not records:
            raise ValueError("stable replacement needs an already admitted parent")
        members = {str(parent.root)} | {c["root"] for r in records for c in r["cells"]}
        if any(root.is_relative_to(Path(path)) for path in members):
            raise ValueError("stable-map child must be independent of historical member directories")
        transition = records[-1].get("class_transition")
        if transition is None:
            unused(parent, records)
            network, selection = build(old["class_network"], old["source_sha256"], parent.root,
                parent._file("study.json")[1]["sha256"], digest(records[-1]), inventory_sha)
        else:
            network, selection = deepcopy(transition["class_network"]), deepcopy(transition["class_selection"])
            if selection["reserve_inventory"]["sha256"] != inventory_sha:
                raise ValueError("committed reserve inventory cannot change")
        raw_source = authenticated_input(parent.root / SOURCE, old["source_sha256"])
        raw_inventory = authenticated_input(Path(inventory_path), inventory_sha)
        root.mkdir(parents=True, exist_ok=False)
        _create(root / SOURCE, raw_source)
        _create(root / INVENTORY, raw_inventory)
        _create(root / MANIFEST, canonical_json(selection))
        _create(root / "inputs/candidates.json", canonical_json(candidate_catalogue(root / SOURCE)))
        plan = {**old, "class_network": network, "class_selection": selection,
                "storage_reserve_bytes": storage_reserve_bytes,
                "created_at": datetime.now(timezone.utc).isoformat()}
        store = StudyStore(root)
        store.initialize(plan)
        add_inventories(root, [root / INVENTORY])
        return store.status()


def validate_transition(parent, previous, value):
    """Replay the immutable one-transition authority from parent admission."""
    from .resource_study_store import StudyStore
    keys = {"record_type", "class_selection", "class_network", "member_proof"}
    if not isinstance(value, dict) or set(value) != keys or value["record_type"] != TRANSITION:
        raise ValueError("stable parent transition authority is partial")
    plan = parent.plan()
    candidate = {**plan, "class_selection": value["class_selection"], "class_network": value["class_network"]}
    validate_map(candidate)
    selection = value["class_selection"]
    roots = {str(parent.root)} | {c["root"] for r in previous for c in r["cells"]}
    proof = value["member_proof"]
    if not isinstance(proof, list) or [p.get("root") for p in proof if isinstance(p, dict)] != sorted(roots):
        raise ValueError("stable transition historical member scope differs")
    validate_member_proof(proof)
    if (selection["parent_root"] != str(parent.root)
            or selection["parent_study_sha256"] != parent._file("study.json")[1]["sha256"]
            or selection["predecessor_mapping_sha256"] != digest(plan["class_network"])
            or not previous or selection["parent_admission_sha256"] != digest(previous[-1])):
        raise ValueError("stable parent transition predecessor/member/source authority differs")


def validate_member_proof(proof):
    from .resource_study_store import StudyStore, _load
    for item in proof:
        if not isinstance(item, dict) or set(item) != {"root", "study_sha256", "closed_flights"}:
            raise ValueError("stable transition member proof fields differ")
        store = StudyStore(item["root"])
        if store._file("study.json")[1]["sha256"] != item["study_sha256"] or not isinstance(item["closed_flights"], dict):
            raise ValueError("stable transition member study differs")
        for name, ref in item["closed_flights"].items():
            if (not isinstance(name, str) or not name or "/" in name or name in {".", ".."}
                    or not isinstance(ref, dict) or set(ref) != {"launched_sha256", "closed_sha256"}):
                raise ValueError("stable transition flight proof fields differ")
            for suffix in ("launched", "closed"):
                raw, observed = store._file(f"flights/{name}/{suffix}.json", ref[suffix + "_sha256"])
                if observed["mode"] != "0444" or suffix == "closed" and _load(raw).get("cleanup_errors") != []:
                    raise ValueError("stable transition bound flight closure differs")


def validate_cells(cells, transition):
    """Each cell retains its own map, and agrees with the selected leaf address."""
    from .resource_study_network import mapping_sha256
    from .resource_study_store import StudyStore
    leaf, selection = transition["class_network"], transition["class_selection"]
    allowed = {digest(leaf), leaf["predecessor_sha256"]}
    plans = {}
    for cell in cells:
        if cell["root"] not in plans:
            plans[cell["root"]] = StudyStore(cell["root"]).plan()
        plan = plans[cell["root"]]
        host, binding = cell["hostname"], cell["definition"].get("network", {})
        if (host not in leaf["assignments"] or mapping_sha256(plan) not in allowed
                or plan["source_sha256"] != selection["source_sha256"]
                or binding.get("mapping_sha256") != mapping_sha256(plan)
                or binding.get("assignment") != leaf["assignments"][host]
                or plan["class_network"]["assignments"].get(host) != leaf["assignments"][host]):
            raise ValueError("cell mapping lacks exact committed stable lineage/address authority")
        if present(plan) and plan["class_selection"] != selection:
            raise ValueError("cell stable selected50 context differs")


def enforce_selected(store, records):
    """Retirement remains enforced even when an original root is addressed."""
    from .resource_study_store import StudyStore
    transition = records[-1].get("class_transition") if records else None
    if transition is None:
        if present(store.plan()):
            raise ValueError("stable-map child has no committed parent transition")
        return
    validate_member_proof(transition["member_proof"])
    validate_fences(records)
    roots = {str(store.root)} | {c["root"] for r in records for c in r["cells"]}
    for path in roots:
        member = StudyStore(path)
        no_retired_history(member)
    validate_cells(records[-1]["cells"], transition)


def no_retired_history(store):
    if any((store.root / kind / EXCLUDED).exists() or (store.root / kind / EXCLUDED).is_symlink()
           for kind in ("classes", "attempts", "corpus", "pilots")):
        raise ValueError("retired unused class acquired forbidden artifacts")
    with store._transaction() as connection:
        for table in ("classes", "attempts", "accepted"):
            if connection.execute(f"SELECT 1 FROM {table} WHERE hostname=?", (EXCLUDED,)).fetchone():
                raise ValueError("retired unused class acquired forbidden history")


def fence_ddl():
    """Closed, versioned DDL. No delete or identity-changing update is allowed."""
    result = {}
    for table in ("classes", "attempts", "accepted", "measurements", "meta"):
        for action in ("INSERT", "UPDATE", "DELETE"):
            name = FENCE_PREFIX + table + "_" + action.lower()
            checks = []
            for row in (("OLD", "NEW") if action == "UPDATE" else ("OLD",) if action == "DELETE" else ("NEW",)):
                key = row + (".key" if table == "meta" else ".hostname")
                mode = row + ".value" if table == "meta" else "''" if table == "classes" else row + ".mode"
                attempt = "''" if table in {"classes", "meta"} else row + ".attempt_id"
                operand = action + ":" + row if table == "meta" else action
                checks.append(f"{FENCE_FUNCTION}('{table}','{operand}',{key},{mode},{attempt}) != 1")
            result[name] = (f"CREATE TRIGGER {name} BEFORE {action} ON {table} "
                f"WHEN {' OR '.join(checks)} BEGIN SELECT RAISE(ABORT,'stable class write fence'); END")
    return result


def _schema(connection):
    return [list(r) for r in connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]


def _rows(connection):
    # Before/after installation must preserve every historical row, not merely counts.
    return {table: [list(r) for r in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")]
            for table in ("classes", "attempts", "accepted", "measurements", "meta")}


def check_fence_connection(store, connection, *, expected_sha=None):
    """Read-only schema validation; never installs or repairs a fence."""
    from .resource_study_store import _load
    raw, info = store._file(FENCE, expected_sha)
    value = _load(raw)
    keys = {"record_type", "root", "study_sha256", "parent_root", "selection_sha256",
            "predecessor_admission_sha256", "ddl", "ddl_sha256", "schema_before",
            "schema_before_sha256", "schema_after_sha256", "historical_rows_sha256"}
    if (not isinstance(value, dict) or set(value) != keys or value["record_type"] != FENCE_TYPE
            or info["mode"] != "0444" or value["root"] != str(store.root)
            or value["study_sha256"] != store._file("study.json")[1]["sha256"]
            or value["ddl"] != fence_ddl() or value["ddl_sha256"] != digest(fence_ddl())
            or value["schema_before_sha256"] != digest(value["schema_before"])
            or any(not isinstance(value[k], str) or _SHA.fullmatch(value[k]) is None
                   for k in ("selection_sha256", "predecessor_admission_sha256", "historical_rows_sha256"))):
        raise ValueError("stable class write fence authority differs")
    schema = _schema(connection)
    triggers = {r[1]: r[3] for r in schema if r[1].startswith(FENCE_PREFIX)}
    base = [r for r in schema if not r[1].startswith(FENCE_PREFIX)]
    if (triggers != fence_ddl() or base != value["schema_before"]
            or digest(schema) != value["schema_after_sha256"]):
        raise ValueError("stable class write fence schema/function contract changed")
    return value


def register_fence_connection(store, connection):
    """Old HOST connections lack this function; new connections deny by default."""
    check_fence_connection(store, connection)
    def allowed(table, action, host, mode, attempt):
        scope = getattr(store._stable_write_local, "scope", None)
        if scope is None or action == "DELETE":
            return 0
        if table == "meta":
            if scope.get("kind") != "head-publication" or host != "epoch_head" or attempt != "":
                return 0
            if action == "UPDATE:OLD":
                return int(mode == scope["old_head"])
            if action in {"INSERT:NEW", "UPDATE:NEW"}:
                return int(mode == scope["new_head"])
            return 0
        if (table, action) not in scope["actions"]:
            return 0
        for index, (h, m, identifier) in enumerate(scope["entries"]):
            if host != h or mode != m:
                continue
            if identifier is None:
                if (table, action) != ("attempts", "INSERT") or not isinstance(attempt, str) or re.fullmatch("[0-9a-f]{32}", attempt) is None:
                    return 0
                # Consume the reservation's one UUID choice; cleanup cannot
                # mutate another attempt, and a second INSERT is denied.
                scope["entries"][index] = (h, m, attempt)
                return 1
            if attempt == identifier:
                return 1
        return 0
    connection.create_function(FENCE_FUNCTION, 5, allowed, deterministic=False)


@contextmanager
def write_scope(store, parent, records, entries, actions):
    """Only guarded epoch hooks call this, while holding the parent lock.

    A scope names exact rows (reservation INSERT may choose its new UUID) and
    table/actions. It grants no generic SQL write permission or delete path.
    """
    if not records or "class_transition" not in records[-1]:
        yield
        return
    if any(table == "meta" for table, _ in actions):
        raise ValueError("row scopes cannot grant meta publication rights")
    selection = records[-1]["class_transition"]["class_selection"]
    ref = records[-1]["write_fences"].get(str(store.root))
    if ref is None:
        raise ValueError("stable writer root has no committed fence")
    with store._transaction() as connection:
        value = check_fence_connection(store, connection, expected_sha=ref)
    if (value["selection_sha256"] != digest(selection) or value["parent_root"] != str(parent.root)
            or any(h not in selection["selected_hostnames"] for h, _, _ in entries)):
        raise ValueError("stable write scope differs from committed selected50")
    previous = getattr(store._stable_write_local, "scope", None)
    if previous is not None:
        raise ValueError("stable write scopes cannot be nested or widened")
    store._stable_write_local.scope = {"entries": list(entries), "actions": frozenset(actions),
                                      "admission_sha256": digest(records[-1])}
    try:
        yield
    finally:
        del store._stable_write_local.scope


@contextmanager
def publication_scope(parent, records, value):
    """Exact prospective head publication, called only under the parent lock.

    Both old and new values are bound; no other meta key/action is permitted.
    The immutable proposed admission and all fence refs must already exist.
    """
    from .resource_study_epochs import _read
    if (not records or value.get("class_transition") is None or value["sequence"] != len(records)
            or value["previous_sha256"] != digest(records[-1])
            or value["parent_study_sha256"] != parent._file("study.json")[1]["sha256"]
            or value["class_transition"]["class_selection"]["parent_root"] != str(parent.root)
            or _read(parent.root / "epoch-admissions" / f"{len(records):06d}.json") != value):
        raise ValueError("stable head publication lacks exact immutable next admission")
    if records[-1].get("class_transition") is None:
        validate_transition(parent, records, value["class_transition"])
    elif value["class_transition"] != records[-1]["class_transition"]:
        raise ValueError("stable publication changes committed selection")
    validate_cells(value["cells"], value["class_transition"])
    validate_fences([*records, value])
    expected = canonical_json({"sequence": len(records) - 1, "sha256": digest(records[-1])}).decode()
    next_value = canonical_json({"sequence": len(records), "sha256": digest(value)}).decode()
    with parent._transaction() as connection:
        row = connection.execute("SELECT value FROM meta WHERE key='epoch_head'").fetchone()
        if row is None or row[0] != expected:
            raise ValueError("stable head changed before publication scope")
    if getattr(parent._stable_write_local, "scope", None) is not None:
        raise ValueError("stable publication scope cannot nest or widen")
    parent._stable_write_local.scope = {"kind": "head-publication", "old_head": expected, "new_head": next_value,
                                       "actions": frozenset(), "entries": []}
    try:
        yield
    finally:
        del parent._stable_write_local.scope


def install_fence(store, parent, selection, head_sha):
    """Explicit admission-only migration, called after all gates under parent lock.

    This is deliberately absent from read paths. A partial multi-ledger install
    fails closed and needs an explicit reviewed recovery; it is not healed.
    """
    from .resource_study_store import _create
    if (store.root / FENCE).exists() or (store.root / FENCE).is_symlink():
        raise ValueError("uncommitted or previously installed stable write fence")
    connection = store._connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        before, rows = _schema(connection), _rows(connection)
        if any(r[1].startswith(FENCE_PREFIX) for r in before):
            raise ValueError("unbound stable write fence trigger")
        for ddl in fence_ddl().values():
            connection.execute(ddl)
        after = _schema(connection)
        if _rows(connection) != rows:
            raise ValueError("fence migration changed historical rows")
        value = {"record_type": FENCE_TYPE, "root": str(store.root),
            "study_sha256": store._file("study.json")[1]["sha256"], "parent_root": str(parent.root),
            "selection_sha256": digest(selection), "predecessor_admission_sha256": head_sha,
            "ddl": fence_ddl(), "ddl_sha256": digest(fence_ddl()), "schema_before": before,
            "schema_before_sha256": digest(before), "schema_after_sha256": digest(after),
            "historical_rows_sha256": digest(rows)}
        _create(store.root / FENCE, canonical_json(value))
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
    return digest(value)


def prepare_fences(parent, records, cells, transition):
    """Preserve old refs; explicitly fence only a newly admitted member ledger."""
    from .resource_study_store import StudyStore
    roots = {str(parent.root)} | {c["root"] for r in records for c in r["cells"]} | {c["root"] for c in cells.values()}
    refs = dict(records[-1].get("write_fences", {}))
    for root in sorted(roots - refs.keys()):
        refs[root] = install_fence(StudyStore(root), parent, transition["class_selection"], digest(records[-1]))
    return refs


def validate_fences(records):
    from .resource_study_store import StudyStore
    previous = {}
    historical = set()
    for index, record in enumerate(records):
        historical.update(c["root"] for c in record["cells"])
        if "class_transition" not in record:
            continue
        selection = record["class_transition"]["class_selection"]
        roots = historical | {selection["parent_root"]}
        refs = record.get("write_fences")
        if (not isinstance(refs, dict) or set(refs) != roots
                or any(refs.get(root) != sha for root, sha in previous.items())
                or any(not isinstance(sha, str) or _SHA.fullmatch(sha) is None for sha in refs.values())):
            raise ValueError("stable admission write fence scope/ancestry differs")
        for root in sorted(roots - previous.keys()):
            store = StudyStore(root)
            with store._transaction() as connection:
                value = check_fence_connection(store, connection, expected_sha=refs[root])
            if (value["parent_root"] != selection["parent_root"]
                    or value["selection_sha256"] != digest(selection)
                    or index == 0 or value["predecessor_admission_sha256"] != digest(records[index - 1])):
                raise ValueError("stable write fence selection/head binding differs")
        previous = refs
    # Always reopen every current schema, including when parent records are cached.
    for root, sha in previous.items():
        store = StudyStore(root)
        with store._transaction() as connection:
            check_fence_connection(store, connection, expected_sha=sha)
