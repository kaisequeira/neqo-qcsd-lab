"""Prospective cell epochs over immutable resource-study ledgers.

An epoch owns a fresh ledger. Parent admissions select exactly one ledger for
each cell; superseded sessions remain history and cannot be credited again.
This module does not change scientific validators or import session counts.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
from pathlib import Path
import stat

from .resource_study_inputs import MODES, canonical_json, sha256_file
from .resource_study_store import StudyStore, DuplicateSession, _create, _load, _tuple, _json, _hostname, _mode, _scientific_runtime
from .resource_study_verify import verify_receipt, within, load
from .resource_study_runtime import docker_lock

TYPE = "qcsd-resource-domain-cell-epoch-admission-v1"
MEMBER = "qcsd-resource-domain-cell-epoch-membership-v1"
CHANGES = {"resources", "mode", "native", "acceptance", "qualification", "add-host"}
LIMIT = 16 * 1024 * 1024


def _sha(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _regular(path, *, directory=False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("epoch path must be absolute and contain no symbolic link")
    info = path.stat()
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("epoch root is not a directory")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("epoch authority must be one regular unlinked file")
    return path


def _read(path):
    path = _regular(path)
    with path.open("rb") as handle:
        raw = handle.read(LIMIT + 1)
    if len(raw) > LIMIT or stat.S_IMODE(path.stat().st_mode) != 0o444:
        raise ValueError("epoch authority exceeds its limit or immutable full mode changed")
    return _load(raw)


def _meta(store, key):
    with store._transaction() as connection:
        row = connection.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return None if row is None else row[0]


def _stamp(path):
    info = _regular(path).stat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, stat.S_IMODE(info.st_mode)


@contextmanager
def _lock(parent):
    parent = _regular(parent, directory=True)
    path = parent / "epoch-admission.lock"
    if path.exists() or path.is_symlink():
        _regular(path)
    with path.open("a+b") as handle:
        _regular(path)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX)
        except BlockingIOError as error:
            raise RuntimeError("another epoch admission or credit operation is active") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _membership(store):
    bound = _meta(store, "epoch_membership_sha256")
    if bound is None:
        if (store.root / "epoch-membership.json").exists() or (store.root / "epoch-membership.json").is_symlink():
            raise ValueError("unbound epoch membership file")
        return None
    cached = getattr(store, "_epoch_membership_cache", None)
    if cached is not None:
        if cached[:2] != (bound, _stamp(store.root / "epoch-membership.json")):
            raise ValueError("immutable epoch membership changed")
        return cached[2]
    value = _read(store.root / "epoch-membership.json")
    if (set(value) != {"record_type", "root", "study_sha256", "parent", "parent_study_sha256"}
            or value["record_type"] != MEMBER or value["root"] != str(store.root)
            or value["study_sha256"] != store._file("study.json")[1]["sha256"]
            or _sha(value) != bound or value["parent"] != _meta(store, "epoch_parent")):
        raise ValueError("immutable epoch membership differs from its ledger binding")
    parent = StudyStore(_regular(value["parent"], directory=True))
    if parent._file("study.json")[1]["sha256"] != value["parent_study_sha256"]:
        raise ValueError("epoch parent study changed")
    store._epoch_membership_cache = (bound, _stamp(store.root / "epoch-membership.json"), parent)
    return parent


def _bind(store, parent):
    value = {"record_type": MEMBER, "root": str(store.root), "study_sha256": store._file("study.json")[1]["sha256"],
             "parent": str(parent.root), "parent_study_sha256": parent._file("study.json")[1]["sha256"]}
    path = store.root / "epoch-membership.json"
    if path.exists():
        if _read(path) != value:
            raise ValueError("epoch root already belongs to another parent")
    else:
        _create(path, canonical_json(value))
    with store._transaction() as connection:
        for key, expected in (("epoch_parent", str(parent.root)), ("epoch_membership_sha256", _sha(value))):
            previous = connection.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            if previous is not None and previous[0] != expected:
                raise ValueError("epoch membership ledger binding cannot change")
            connection.execute("INSERT OR IGNORE INTO meta VALUES(?,?)", (key, expected))


def _plan(store):
    value = store.plan()
    expected = {"class_count": 50, "resources_per_session": 20, "sessions_per_mode": 400,
                "modes": list(MODES), "total_sessions": 100000,
                "capture_position": "client-eth0-before-nat", "design": "controlled-resource-domain-http3-replay"}
    if any(value.get(key) != item for key, item in expected.items()) or type(value.get("acceptance")) is not str:
        raise ValueError("epoch study plan differs from the 50-by-five-by-400 contract")
    return value


def _enrollments(store):
    with store._transaction() as connection:
        rows = connection.execute("SELECT * FROM classes ORDER BY hostname").fetchall()
    result = {}
    for row in rows:
        value = _load(store._file(row["path"], row["sha256"])[0])
        if value.get("hostname") != row["hostname"] or store._file(row["path"])[1]["mode"] != "0444":
            raise ValueError("epoch enrollment identity or immutable mode changed")
        result[row["hostname"]] = (value, row["path"], row["sha256"])
    return result


def _cell(store, host, mode):
    host, mode = _hostname(host), _mode(mode)
    with store._transaction() as connection:
        row = connection.execute("SELECT * FROM classes WHERE hostname=?", (host,)).fetchone()
    if row is None:
        raise ValueError("epoch hostname is not enrolled in its root")
    relative, digest = row["path"], row["sha256"]
    stamp = _stamp(store.root / relative)
    cache = getattr(store, "_epoch_cell_cache", {})
    cached = cache.get((host, mode))
    if cached is not None:
        if cached[:2] != (digest, stamp):
            raise ValueError("immutable epoch enrollment changed")
        return cached[2]
    enrollment = _load(store._file(relative, digest)[0])
    if stamp[-1] != 0o444 or enrollment.get("hostname") != host:
        raise ValueError("epoch enrollment mode or hostname changed")
    if len(enrollment["urls"]) != 20 or len(set(enrollment["urls"])) != 20:
        raise ValueError("epoch enrollment must retain twenty distinct resources")
    settings = enrollment.get("mode_settings", {}).get(mode)
    policies = enrollment.get("mode_policies", {}).get(mode)
    if not isinstance(settings, dict) or not isinstance(policies, dict):
        raise ValueError("epoch cell lacks explicit fixed settings and acceptance policies")
    definition = {"urls": enrollment["urls"], "workload_sha256": enrollment["workload_sha256"],
        "settings": settings, "policies": policies, "native": list(_scientific_runtime(enrollment["runtime"])),
        "acceptance": _plan(store)["acceptance"], "ready": enrollment.get("mode_readiness", {}).get(mode) is True}
    value = {"hostname": host, "mode": mode, "root": str(store.root),
            "study_sha256": store._file("study.json")[1]["sha256"], "enrollment_path": relative,
            "enrollment_sha256": digest, "definition": definition, "definition_sha256": _sha(definition)}
    cache[(host, mode)] = (digest, stamp, value)
    store._epoch_cell_cache = cache
    return value


def _key(cell):
    return cell["hostname"], cell["mode"]


def _records(parent):
    parent.plan()
    head = _meta(parent, "epoch_head")
    if head is None:
        return []
    authority = json.loads(head)
    if set(authority) != {"sequence", "sha256"} or type(authority["sequence"]) is not int or authority["sequence"] < 0:
        raise ValueError("epoch head ledger binding is malformed")
    paths = [parent.root / "epoch-admissions" / f"{sequence:06d}.json" for sequence in range(authority["sequence"] + 1)]
    stamps = [_stamp(path) for path in paths]
    cached = getattr(parent, "_epoch_records_cache", None)
    if cached is not None and cached[0] == head:
        if cached[1] != stamps:
            raise ValueError("immutable epoch admission metadata changed")
        return cached[2]
    records, previous = [], None
    for sequence in range(authority["sequence"] + 1):
        value = _read(parent.root / "epoch-admissions" / f"{sequence:06d}.json")
        if (set(value) != {"record_type", "sequence", "previous_sha256", "parent_study_sha256", "change", "affected", "cells", "exclusions"}
                or value["record_type"] != TYPE or value["sequence"] != sequence
                or value["previous_sha256"] != previous
                or value["parent_study_sha256"] != parent._file("study.json")[1]["sha256"]
                or not isinstance(value["cells"], list) or not isinstance(value["exclusions"], list)
                or value["change"] not in (CHANGES | {"initial"})):
            raise ValueError("epoch admission ancestry or fields changed")
        keys = [_key(cell) for cell in value["cells"]]
        if len(keys) != len(set(keys)) or len({key[0] for key in keys}) > 50:
            raise ValueError("epoch admission repeats cells or exceeds fifty hosts")
        for cell in value["cells"]:
            _hostname(cell["hostname"]); _mode(cell["mode"])
            if _sha(cell["definition"]) != cell["definition_sha256"]:
                raise ValueError("epoch scientific definition changed")
        for ref in value["exclusions"]:
            if set(ref) != {"cell", "path", "sha256"} or not isinstance(ref["cell"], list) or len(ref["cell"]) != 2:
                raise ValueError("epoch ancestry exclusion reference is malformed")
            _hostname(ref["cell"][0]); _mode(ref["cell"][1])
        records.append(value)
        previous = _sha(value)
    if previous != authority["sha256"]:
        raise ValueError("epoch admission head SHA256 changed")
    parent._epoch_records_cache = (head, stamps, records)
    return records


def _publish(parent, records, cells, change, affected, exclusions=None):
    value = {"record_type": TYPE, "sequence": len(records), "previous_sha256": _sha(records[-1]) if records else None,
             "parent_study_sha256": parent._file("study.json")[1]["sha256"], "change": change,
             "affected": [list(key) for key in sorted(affected)], "cells": [cells[key] for key in sorted(cells)],
             "exclusions": exclusions if exclusions is not None else []}
    path = parent.root / "epoch-admissions" / f"{len(records):06d}.json"
    if path.exists():
        if _read(path) != value:
            raise ValueError("a different uncommitted admission already owns this sequence")
    else:
        _create(path, canonical_json(value))
    with parent._transaction() as connection:
        expected = None if not records else canonical_json({"sequence": len(records) - 1, "sha256": _sha(records[-1])}).decode()
        current = connection.execute("SELECT value FROM meta WHERE key='epoch_head'").fetchone()
        if (None if current is None else current[0]) != expected:
            raise ValueError("epoch parent changed during admission")
        connection.execute("INSERT OR REPLACE INTO meta VALUES('epoch_head',?)",
            (canonical_json({"sequence": len(records), "sha256": _sha(value)}).decode(),))
    return value


def _freeze_exclusions(parent, records, cells, affected):
    refs = list(records[-1]["exclusions"])
    for key in sorted(affected):
        if key not in cells:
            continue
        cell = cells[key]
        store = StudyStore(cell["root"])
        with store._transaction() as connection:
            rows = connection.execute("SELECT * FROM accepted WHERE hostname=? AND mode=? ORDER BY slot", key).fetchall()
        receipts = []
        for row in rows:
            raw, observation = store._file(row["receipt_path"], row["receipt_sha256"])
            if observation != _load(row["inventory"])[row["receipt_path"]]:
                raise ValueError("superseded cell receipt authority changed")
            receipt = _load(raw)
            if _json(_tuple(receipt["five_tuple"])).decode() != row["five_tuple"]:
                raise ValueError("superseded cell tuple differs from its immutable receipt")
            receipts.append({"five_tuple": _tuple(receipt["five_tuple"]), "receipt_path": row["receipt_path"],
                             "receipt_sha256": row["receipt_sha256"], "attempt_id": row["attempt_id"]})
        value = {"cell": list(key), "root": cell["root"], "study_sha256": cell["study_sha256"],
                 "enrollment_sha256": cell["enrollment_sha256"], "receipts": receipts, "scientific_credit": False}
        relative = "epoch-ancestry/" + _sha(value) + ".json"
        path = parent.root / relative
        if path.exists():
            if _read(path) != value:
                raise ValueError("epoch ancestry exclusion snapshot changed")
        else:
            _create(path, canonical_json(value))
        ref = {"cell": list(key), "path": relative, "sha256": _sha(value)}
        if ref not in refs:
            refs.append(ref)
    return refs


def _excluded(parent, records, key):
    result = set()
    for ref in records[-1]["exclusions"]:
        if tuple(ref["cell"]) != key:
            continue
        value = _read(within(parent.root, ref["path"]))
        if _sha(value) != ref["sha256"] or value["cell"] != list(key) or value["scientific_credit"] is not False:
            raise ValueError("epoch ancestry exclusion authority changed")
        for row in value["receipts"]:
            result.add(_json(_tuple(row["five_tuple"])).decode())
    return result


def _idle(stores):
    for store in stores:
        with store._transaction() as connection:
            if connection.execute("SELECT 1 FROM attempts WHERE state IN ('reserved','captured','unverified')").fetchone():
                raise ValueError("participating epoch root has an active reservation; stop/recover its workers first")


def _verify_preparation(store, host):
    from .resource_study_native import inspect_completed_run, MAX_RESPONSE_BYTES, ROLE
    enrollment = _enrollments(store)[host][0]
    prepared_path = within(store.root, enrollment["paths"]["prepared_workload"])
    prepared = load(prepared_path)
    preparation = prepared["preparation"]
    base = within(store.root, enrollment["preparation_dir"])
    run_path = within(base, preparation["actual_preparation_run"])
    input_path, completed_path = base / "preparation-get/input.json", base / "preparation-get/completed.json"
    for path in (prepared_path, run_path, input_path, completed_path):
        relative = path.relative_to(store.root).as_posix()
        if store._file(relative, enrollment["files"][relative])[1]["mode"] != "0444":
            raise ValueError("epoch live preparation input is not immutable")
    completed = load(completed_path)
    if (preparation.get("role") != ROLE or completed.get("returncode") != 0
            or completed.get("timed_out") is not False or completed.get("client_unchanged") is not True
            or completed.get("client_sha256") != enrollment["runtime"]["client_sha256"]
            or preparation["actual_preparation_run_sha256"] != sha256_file(run_path)):
        raise ValueError("epoch lacks an actual successful bound Native preparation")
    manifest = load(input_path)
    if [row["url"] for row in manifest["resources"]] != enrollment["urls"]:
        raise ValueError("epoch preparation did not fetch its frozen twenty resources")
    run = load(run_path)
    if (run.get("resolved_configuration", {}).get("defense") != {"kind": "none"}
            or run.get("application_response_policy") != "http-2xx-only-v1"
            or run.get("application_workload_source_hash_sha256") is not None
            or run.get("chaff_manifest_hash_sha256") is not None or run.get("chaff_responses") != []):
        raise ValueError("epoch preparation changed its strict undefended direct GET role")
    if load(within(store.root, enrollment["workload_path"]))["resources"] != prepared["resources"]:
        raise ValueError("epoch prepared source differs from its frozen Native resource manifest")
    responses = inspect_completed_run(run, manifest, manifest_sha256=sha256_file(input_path),
        max_response_bytes=MAX_RESPONSE_BYTES, native_commit=enrollment["runtime"]["source"]["neqo_commit"])
    expected = [{key: row[key] for key in ("resource_id", "status", "bytes", "body_sha256")} for row in responses]
    if expected != preparation["expected_responses"]:
        raise ValueError("epoch preparation expected responses differ from the actual twenty GETs")


def _scope(cells, hostnames, modes, change):
    hosts = {key[0] for key in cells}
    selected_hosts = set(hostnames) if hostnames else hosts
    selected_modes = set(modes) if modes else set(MODES)
    if change == "resources":
        if not hostnames or selected_modes != set(MODES):
            raise ValueError("resource changes affect all five modes of each requested hostname")
    if change == "mode" and (not modes or selected_hosts != hosts):
        raise ValueError("mode parameter changes affect every admitted hostname in that mode")
    if change != "add-host" and not selected_hosts.issubset(hosts):
        raise ValueError("epoch scope includes an unadmitted hostname")
    if not selected_hosts or not selected_modes or not selected_modes.issubset(MODES):
        raise ValueError("epoch scope is empty or has an unregistered mode")
    return {(host, mode) for host in selected_hosts for mode in selected_modes}


def _check_change(before, after, change):
    old, new = before["definition"], after["definition"]
    resources = old["urls"] != new["urls"] or old["workload_sha256"] != new["workload_sha256"]
    native = old["native"] != new["native"]
    configuration = ({key: value for key, value in old["settings"].items() if key != "policies"}
                     != {key: value for key, value in new["settings"].items() if key != "policies"})
    acceptance = old["acceptance"] != new["acceptance"] or old["policies"] != new["policies"]
    changes = {"resources": resources, "native": native, "mode": configuration, "acceptance": acceptance}
    if any(changed for name, changed in changes.items() if name != change):
        raise ValueError("epoch changes scientific inputs outside its declared change")
    if change == "qualification":
        if any(changes.values()) or old["ready"] or not new["ready"]:
            raise ValueError("qualification repair must preserve science and make an unavailable mode ready")
    elif not changes.get(change):
        raise ValueError("declared epoch scientific input did not change")


def create_epoch(parent, epoch_root, *, change, affected_hostnames=(), affected_modes=()):
    """Admit prepared fresh inputs; new epoch pilots precede formal credit.

    New roots must have no session attempts. Preparation and qualification do
    not count sessions. Existing root counts and enrollment are never rewritten.
    """
    if change not in CHANGES:
        raise ValueError("unknown epoch change")
    parent, new = StudyStore(_regular(Path(parent).absolute(), directory=True)), StudyStore(_regular(Path(epoch_root).absolute(), directory=True))
    hostnames, modes = list(affected_hostnames), list(affected_modes)
    if len(hostnames) != len(set(hostnames)) or len(modes) != len(set(modes)):
        raise ValueError("duplicate epoch scope")
    for host in hostnames: _hostname(host)
    for mode in modes: _mode(mode)
    with docker_lock(), _lock(parent.root):
        parent_plan, new_plan = _plan(parent), _plan(new)
        if parent_plan["source_sha256"] != new_plan["source_sha256"]:
            raise ValueError("epoch roots use different frozen candidate sources")
        records = _records(parent)
        if not records:
            enrolled = _enrollments(parent)
            if not enrolled:
                raise ValueError("epoch parent has no admitted live classes")
            _idle([parent, new])
            initial = {(host, mode): _cell(parent, host, mode) for host in enrolled for mode in MODES}
            _bind(parent, parent)
            _publish(parent, [], initial, "initial", initial)
            records = _records(parent)
        cells = {_key(cell): cell for cell in records[-1]["cells"]}
        previous_roots = {cell["root"] for record in records for cell in record["cells"]}
        if str(new.root) in previous_roots and change != "add-host":
            raise ValueError("scientific epoch requires a fresh independent root")
        stores = [StudyStore(path) for path in sorted(previous_roots | {str(new.root)})]
        _idle(stores)
        with new._transaction() as connection:
            if change != "add-host" and connection.execute("SELECT 1 FROM attempts").fetchone():
                raise ValueError("new epoch cannot contain pre-admission session attempts")
        affected = _scope(cells, hostnames, modes, change)
        if change == "add-host":
            if not hostnames or modes and set(modes) != set(MODES) or any(host in {key[0] for key in cells} for host in hostnames):
                raise ValueError("new-host admission must add all five cells of new hostnames")
            if len({key[0] for key in cells} | set(hostnames)) > 50:
                raise ValueError("parent already has fifty distinct classes")
        for host in sorted({key[0] for key in affected}):
            _verify_preparation(new, host)
        updated = dict(cells)
        for host, mode in sorted(affected):
            candidate = _cell(new, host, mode)
            if change == "add-host":
                # Compare mode/runtime defaults, excluding each class resource set.
                profiles = [{key: value for key, value in cell["definition"].items()
                             if key not in {"urls", "workload_sha256", "ready"}} for key, cell in cells.items() if key[1] == mode]
                current = {key: value for key, value in candidate["definition"].items()
                           if key not in {"urls", "workload_sha256", "ready"}}
                if not profiles or any(profile != current for profile in profiles):
                    raise ValueError("late hostname has ambiguous or stale mode/runtime defaults")
            else:
                _check_change(cells[(host, mode)], candidate, change)
            updated[(host, mode)] = candidate
        if change == "mode":
            for mode in {key[1] for key in affected}:
                settings = {canonical_json(updated[key]["definition"]["settings"]) for key in affected if key[1] == mode}
                if len(settings) != 1:
                    raise ValueError("mode parameter epoch must declare one fixed setting for all admitted hosts")
        _idle(stores)
        exclusions = _freeze_exclusions(parent, records, cells, affected)
        _bind(new, parent)
        return _publish(parent, records, updated, change, affected, exclusions)


def _active(store, host, mode, records):
    cells = {_key(cell): cell for cell in records[-1]["cells"]}
    selected = cells.get((host, mode))
    if selected is None or selected["root"] != str(store.root) or selected != _cell(store, host, mode):
        raise ValueError("cell is excluded, superseded, or differs from its active epoch")
    return selected


def active_cell(store, host, mode):
    """Filter scheduler cells; direct Store hooks still enforce this boundary."""
    parent = _membership(store)
    if parent is None:
        return True
    with _lock(parent.root):
        records = _records(parent)
        selected = next((cell for cell in records[-1]["cells"] if _key(cell) == (host, mode)), None)
        if selected is None or selected["root"] != str(store.root):
            return False
        _active(store, host, mode, records)
        return True


def is_parent(root):
    return _meta(StudyStore(root), "epoch_head") is not None


def _pilot(store, cell):
    if not cell["definition"]["ready"]:
        raise ValueError("active epoch mode is not qualified")
    cache = getattr(store, "_epoch_pilot_cache", {})
    key = (cell["hostname"], cell["mode"], cell["enrollment_sha256"], cell["definition_sha256"])
    cached = cache.get(key)
    def stamps(paths):
        return [(str(path), path.stat().st_ino, path.stat().st_size, path.stat().st_mtime_ns,
                 path.stat().st_ctime_ns, stat.S_IMODE(path.stat().st_mode)) for path in paths]
    if cached is not None:
        if stamps(cached[0]) != cached[1]:
            raise ValueError("active epoch pilot evidence changed")
        return
    for path in sorted((store.root / "pilots" / cell["hostname"] / cell["mode"]).glob("*/session.json")):
        receipt = load(path)
        enrollment = receipt.get("artifact_paths", {}).get("enrollment")
        if (receipt.get("purpose") != "pilot" or receipt.get("mode") != cell["mode"]
                or receipt.get("hostname") != cell["hostname"]
                or receipt.get("workload_sha256") != cell["definition"]["workload_sha256"]
                or enrollment != cell["enrollment_path"]
                or receipt.get("files", {}).get(enrollment) != cell["enrollment_sha256"]):
            continue
        if (list(_scientific_runtime(receipt["runtime"])) != cell["definition"]["native"]
                or receipt.get("mode_settings") != cell["definition"]["settings"]
                or receipt.get("mode_policies") != cell["definition"]["policies"]):
            continue
        verify_receipt(store.root, receipt)
        paths = [path, *(within(store.root, relative) for relative in receipt["files"])]
        before = stamps(paths)
        if any(item[-1] != 0o444 for item in before):
            raise ValueError("active epoch pilot has writable evidence")
        cache[key] = (paths, before)
        store._epoch_pilot_cache = cache
        return
    raise ValueError("active epoch needs its own genuine matching mode pilot")


def reserve(store, hostname, mode, operation, *, purpose="formal"):
    """Store allocation hook: authority is checked before the reservation."""
    if purpose not in {"formal", "pilot"}:
        raise ValueError("unregistered reservation purpose")
    parent = _membership(store)
    if parent is None:
        return operation()
    with _lock(parent.root):
        records = _records(parent)
        cell = _active(store, _hostname(hostname), _mode(mode), records)
        if purpose == "formal":
            _pilot(store, cell)
        attempt = operation()
        try:
            _create(store.root / attempt["path"] / "epoch-purpose.json", canonical_json({
                "purpose": purpose, "attempt_id": attempt["attempt_id"], "admission_sha256": _sha(records[-1]),
                "definition_sha256": cell["definition_sha256"]}))
        except BaseException:
            store.fail_attempt(attempt["attempt_id"], "epoch purpose publication failed", kind="filesystem")
            raise
        return attempt


def credit(store, receipt_path, operation):
    """Store first-credit hook: active scope, pilot and ancestry tuple fence."""
    parent = _membership(store)
    if parent is None:
        return operation()
    with _lock(parent.root):
        path = Path(receipt_path)
        relative = path.relative_to(store.root).as_posix() if path.is_absolute() else path.as_posix()
        receipt = _load(store._file(relative)[0])
        with store._transaction() as connection:
            row = connection.execute("SELECT * FROM attempts WHERE attempt_id=?", (receipt["attempt_id"],)).fetchone()
        if row is None:
            raise ValueError("epoch credit has no reserved attempt")
        if row["state"] == "accepted":
            return operation()  # Existing immutable idempotent audit adds no credit.
        records = _records(parent)
        host, mode = _hostname(receipt["hostname"]), _mode(receipt["mode"])
        cell = _active(store, host, mode, records)
        intent = _read(store.root / row["path"] / "epoch-purpose.json")
        if (intent.get("purpose") != "formal" or intent.get("attempt_id") != receipt["attempt_id"]
                or intent.get("admission_sha256") != _sha(records[-1])
                or intent.get("definition_sha256") != cell["definition_sha256"]):
            raise ValueError("epoch credit changes its original formal reservation")
        _pilot(store, cell)
        five_tuple = _json(_tuple(receipt["five_tuple"])).decode()
        if five_tuple in _excluded(parent, records, (host, mode)):
            store.fail_attempt(receipt["attempt_id"], "five-tuple already credited in an ancestor epoch", kind="duplicate")
            raise DuplicateSession("five-tuple already credited in an ancestor epoch")
        return operation()


def status(parent, *, deep=False):
    """Select actual receipt rows; deep mode independently rechecks raw evidence."""
    parent = StudyStore(_regular(Path(parent).absolute(), directory=True))
    with _lock(parent.root):
        records = _records(parent)
        if not records:
            raise ValueError("parent has no committed epoch admissions")
        cells, refs, accepted_count = [], [], 0
        for cell in records[-1]["cells"]:
            store = StudyStore(cell["root"])
            if _membership(store).root != parent.root:
                raise ValueError("selected epoch root belongs to another parent")
            _active(store, cell["hostname"], cell["mode"], records)
            with store._transaction() as connection:
                rows = connection.execute("SELECT * FROM accepted WHERE hostname=? AND mode=? ORDER BY slot",
                                          _key(cell)).fetchall()
            if not deep:
                if len(rows) > 400 or len({row["slot"] for row in rows}) != len(rows) or len({row["five_tuple"] for row in rows}) != len(rows):
                    raise ValueError("selected cell accepted index exceeds its quota or repeats identities")
                accepted_count += len(rows)
                cells.append({"hostname": cell["hostname"], "mode": cell["mode"], "epoch_root": cell["root"],
                              "accepted": len(rows), "target": 400})
                continue
            tuples = set()
            excluded = _excluded(parent, records, _key(cell))
            for row in rows:
                raw, observation = store._file(row["receipt_path"], row["receipt_sha256"])
                expected = _load(row["inventory"])[row["receipt_path"]]
                receipt = _load(raw)
                if observation != expected or row["five_tuple"] in tuples:
                    raise ValueError("selected receipt immutable authority or tuple uniqueness changed")
                if (receipt.get("hostname"), receipt.get("mode"), receipt.get("slot"), receipt.get("attempt_id")) != (
                        row["hostname"], row["mode"], row["slot"], row["attempt_id"]):
                    raise ValueError("selected accepted receipt differs from its ledger cell")
                if row["five_tuple"] in excluded:
                    raise ValueError("selected cell repeats an ancestor epoch tuple")
                tuples.add(row["five_tuple"])
                if deep:
                    facts = verify_receipt(store.root, receipt)
                    if _json(facts["five_tuple"]).decode() != row["five_tuple"]:
                        raise ValueError("deep epoch tuple differs from its accepted index")
                refs.append({"hostname": row["hostname"], "mode": row["mode"], "slot": row["slot"],
                    "attempt_id": row["attempt_id"], "epoch_root": str(store.root),
                    "receipt_path": row["receipt_path"], "receipt_sha256": row["receipt_sha256"]})
            cells.append({"hostname": cell["hostname"], "mode": cell["mode"], "epoch_root": cell["root"],
                          "accepted": len(rows), "target": 400})
            accepted_count += len(rows)
        hosts = {cell["hostname"] for cell in cells}
        complete = (len(hosts) == 50 and len(cells) == 250 and all(cell["accepted"] == 400 for cell in cells)
                    and accepted_count == 100000)
        return {"record_type": "qcsd-resource-domain-cell-epoch-composition-v1", "parent_study_sha256": parent._file("study.json")[1]["sha256"],
                "admission_sha256": _sha(records[-1]), "cells": cells, "accepted": refs, "accepted_count": accepted_count,
                "total_sessions": 100000, "complete": complete, "raw_deep_verified": deep,
                "scientific_credit": deep and complete, "scope": "active-cell-root-only; no mixed scientific epochs",
                "status_authority": "raw-deep-verified" if deep else "selected-ledger-verified-at-commit-index"}


def export_manifest(parent, output):
    value = status(parent, deep=True)
    _create(Path(output).absolute(), canonical_json(value))
    return value


def verify(parent, *, recover=False):
    """Recover selected ledgers through their existing API, then audit raw proof."""
    recovered = {}
    if recover:
        parent_store = StudyStore(_regular(Path(parent).absolute(), directory=True))
        with docker_lock():
            with _lock(parent_store.root):
                records = _records(parent_store)
                roots = sorted({cell["root"] for cell in records[-1]["cells"]})
                for root in roots:
                    if _membership(StudyStore(root)).root != parent_store.root:
                        raise ValueError("selected epoch root belongs to another parent")
            # Store recovery invokes the public credit hook, which acquires the
            # parent lock itself. The runtime lock prevents a concurrent flight.
            for root in roots:
                recovered[root] = StudyStore(root).recover()
    value = status(parent, deep=True)
    value["recovery"] = recovered
    return value


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    for name in ("admit", "status", "verify", "export"):
        child = actions.add_parser(name)
        child.add_argument("--parent", type=Path, required=True)
        if name == "admit":
            child.add_argument("--root", type=Path, required=True)
            child.add_argument("--change", choices=sorted(CHANGES), required=True)
            child.add_argument("--affected-hostname", action="append", default=[])
            child.add_argument("--affected-mode", action="append", choices=MODES, default=[])
        elif name == "export":
            child.add_argument("--output", type=Path, required=True)
        elif name == "verify":
            child.add_argument("--recover", action="store_true", help="only after capture workers have stopped")
    args = parser.parse_args(argv)
    try:
        if args.action == "admit":
            value = create_epoch(args.parent, args.root, change=args.change,
                affected_hostnames=args.affected_hostname, affected_modes=args.affected_mode)
        elif args.action == "export":
            value = export_manifest(args.parent, args.output)
        elif args.action == "verify":
            value = verify(args.parent, recover=args.recover)
        else:
            value = status(args.parent)
        print(json.dumps(value, sort_keys=True, allow_nan=False))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(json.dumps({"status": "refused", "reason": str(error), "scientific_credit": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
