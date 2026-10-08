"""Durable, independent resource-domain cells; no historical capture authority.

Immutable verification receipts are the evidence. SQLite indexes reservations
and receipts using FULL-synchronous transactions; it is not a raw verifier.
First credit always requires a caller-supplied independent validator. Recovery
must be requested only after the operator has stopped the study's workers.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import tempfile
import threading
from urllib.parse import urlsplit
import uuid


MODES = ("undefended", "front", "tamaraw", "buflo", "cs-buflo")
CLASSES = 50
RESOURCES = 20
SESSIONS = 400
TARGET = CLASSES * len(MODES) * SESSIONS
RECORD = "qcsd-resource-domain-session-verification-v1"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ACTIVE = ("reserved", "captured", "unverified")


class DuplicateSession(ValueError):
    """The attempted session remains recorded and receives no credit."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _json(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError("JSON contains duplicate fields")
        result[key] = value
    return result


def _load(raw):
    return json.loads(raw, object_pairs_hook=_pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def _hostname(value):
    if (type(value) is not str or len(value) > 253 or value != value.lower()
        or not all(_HOST.fullmatch(label) for label in value.split("."))):
        raise ValueError("hostname must be a canonical ASCII DNS name")
    return value


def _mode(value):
    if type(value) is not str or value not in MODES:
        raise ValueError("unknown resource-study mode")
    return value


def _digest(value):
    if type(value) is not str or not _SHA.fullmatch(value):
        raise ValueError("invalid SHA256")
    return value


def _unlinked(path, *, directory=False):
    path = Path(path).absolute()
    if ".." in path.parts or any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("study path contains a symlink or parent traversal")
    info = path.stat()
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError("study input is not a regular file/directory")
    if not directory and info.st_nlink != 1:
        raise ValueError("study input has another hard-link authority")
    return path


def _fsync(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create(path, raw):
    """Publish complete immutable bytes without replacing an existing name."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _unlinked(path.parent, directory=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(raw); stream.flush()
            os.fchmod(stream.fileno(), 0o444)
            os.fsync(stream.fileno())
        os.link(temporary, path)
        temporary.unlink(); temporary = None
        _fsync(path.parent)
    finally:
        if temporary is not None:
            temporary.unlink()


def _tuple(value):
    if (not isinstance(value, list) or len(value) != 5
        or any(type(value[index]) is not int or not 1 <= value[index] <= 65535 for index in (1, 3))
        or type(value[4]) is not int or value[4] != 17
        or any(type(value[index]) is not str for index in (0, 2))):
        raise ValueError("verification requires one UDP five-tuple")
    local, remote = ipaddress.ip_address(value[0]), ipaddress.ip_address(value[2])
    if local.version != remote.version or local.is_unspecified or remote.is_unspecified:
        raise ValueError("invalid capture-point endpoint addresses")
    return [str(local), value[1], str(remote), value[3], 17]


def _scientific_runtime(value):
    if (not isinstance(value, dict) or not isinstance(value.get("source"), dict)
        or value.get("platform") not in ("linux/amd64", "linux/arm64")
        or type(value["source"].get("neqo_commit")) is not str
        or not re.fullmatch("[0-9a-f]{40}", value["source"]["neqo_commit"])):
        raise ValueError("runtime lacks its platform and Native scientific identity")
    return (_digest(value.get("client_sha256")), value["platform"], value["source"]["neqo_commit"])


def _wall(value):
    if value is None:
        return None
    if type(value) not in (int, float):
        raise ValueError("attempt wall time must be a finite nonnegative measurement")
    try:
        value = float(value)
    except OverflowError:
        raise ValueError("attempt wall time exceeds its finite measurement range") from None
    if not math.isfinite(value) or value < 0:
        raise ValueError("attempt wall time must be a finite nonnegative measurement")
    return value


class StudyStore:
    def __init__(self, root):
        self.root = Path(root).absolute()
        if ".." in self.root.parts or any(path.is_symlink() for path in (self.root, *self.root.parents)):
            raise ValueError("study root must be an unlinked absolute directory")
        self.database = self.root / "ledger.sqlite3"
        self._enrollment_cache = {}
        self._enrollment_lock = threading.RLock()
        self._measurement_schema_ready = False

    def _relative(self, value):
        if type(value) is not str or not value or "\\" in value:
            raise ValueError("study file reference must be a relative POSIX path")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in (".", "..") for part in value.split("/")) or str(path) != value:
            raise ValueError("study file reference escapes its root")
        return self.root.joinpath(*path.parts)

    def _file(self, relative, digest=None):
        path = _unlinked(self._relative(relative))
        raw = path.read_bytes()
        info = path.stat()
        observed = {"sha256": _sha(raw), "mode": f"{stat.S_IMODE(info.st_mode):04o}"}
        if digest is not None and observed["sha256"] != _digest(digest):
            raise ValueError("study file SHA256 changed: " + relative)
        return raw, observed

    def _files(self, refs):
        if not isinstance(refs, dict) or not refs:
            raise ValueError("receipt requires immutable file references")
        return {name: self._file(name, digest)[1] for name, digest in sorted(refs.items())}

    def _assert_inventory(self, inventory):
        for name, expected in inventory.items():
            if self._file(name, expected["sha256"])[1] != expected:
                raise ValueError("study file full mode changed: " + name)

    def _inventory_stamps(self, inventory):
        result = {}
        for name in inventory:
            path = _unlinked(self._relative(name))
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("enrollment input is no longer a regular unlinked file")
            result[name] = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                info.st_ctime_ns, stat.S_IMODE(info.st_mode), info.st_nlink)
        return result

    def _assert_enrollment_inventory(self, row):
        """Hash immutable preparation once per class/Store, then fence metadata.

        This cache is never used for new raw-session inventories. Workload and
        other shared launch files named by the session receipt are still hashed
        by _receipt and around its independent validation callback.
        """
        inventory = _load(row["inventory"])
        key = (row["sha256"], row["path"], row["inventory"])
        with self._enrollment_lock:
            before = self._inventory_stamps(inventory)
            cached = self._enrollment_cache.get(row["hostname"])
            if cached is None:
                self._assert_inventory(inventory)
                after = self._inventory_stamps(inventory)
                if after != before:
                    raise ValueError("enrollment changed during its complete initial hash check")
                self._enrollment_cache[row["hostname"]] = (key, after)
            elif cached != (key, before):
                raise ValueError("immutable enrollment authority or file metadata changed")

    def _connect(self):
        _unlinked(self.root, directory=True)
        _unlinked(self.database)
        for suffix in ("-wal", "-shm", "-journal"):
            path = Path(str(self.database) + suffix)
            if path.exists() or path.is_symlink():
                try:
                    _unlinked(path)
                except FileNotFoundError:
                    # SQLite removes an idle WAL/SHM when another connection
                    # closes. The stable database remains mandatory above;
                    # linked or nonregular sidecars still fail closed.
                    pass
        connection = sqlite3.connect(self.database, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        # Additive index migration also supports a stopped ledger initialized
        # before measurements existed. It imports no timing or credit claims.
        with self._enrollment_lock:
            if not self._measurement_schema_ready:
                connection.execute("""CREATE TABLE IF NOT EXISTS measurements(
                    attempt_id TEXT PRIMARY KEY REFERENCES attempts(attempt_id),
                    hostname TEXT NOT NULL, mode TEXT NOT NULL, outcome TEXT NOT NULL,
                    wall_seconds REAL, retained_bytes INTEGER)""")
                connection.execute("CREATE INDEX IF NOT EXISTS measurements_mode ON measurements(mode,outcome)")
                self._measurement_schema_ready = True
        return connection

    @contextmanager
    def _transaction(self):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self, plan: dict) -> dict:
        if not isinstance(plan, dict) or type(plan.get("schema_version")) is not int or plan["schema_version"] != 1:
            raise ValueError("resource study requires schema_version 1")
        if plan.get("record_type", "qcsd-resource-domain-study-v1") != "qcsd-resource-domain-study-v1":
            raise ValueError("unknown resource-study record type")
        for field, expected in (("class_count", CLASSES), ("resources_per_class", RESOURCES),
            ("resources_per_session", RESOURCES), ("sessions_per_cell", SESSIONS),
            ("sessions_per_mode", SESSIONS), ("session_target", TARGET), ("total_sessions", TARGET)):
            if field in plan and (type(plan[field]) is not int or plan[field] != expected):
                raise ValueError("resource study target changed: " + field)
        if "modes" in plan and plan["modes"] != list(MODES):
            raise ValueError("resource study requires all five canonical modes")
        if any(plan.get(key, False) not in (False, 0) for key in ("scientific_credit", "accepted_count")):
            raise ValueError("new study cannot import credit")
        raw = _json(plan)
        self.root.mkdir(parents=True, exist_ok=True)
        _unlinked(self.root, directory=True)
        try:
            _create(self.root / "study.json", raw)
        except FileExistsError:
            if self._file("study.json")[0] != raw:
                raise ValueError("study already has different immutable inputs")
        try:
            descriptor = os.open(self.database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.fsync(descriptor); os.close(descriptor); _fsync(self.root)
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS classes(
                    hostname TEXT PRIMARY KEY, path TEXT UNIQUE NOT NULL,
                    sha256 TEXT NOT NULL, inventory TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts(
                    attempt_id TEXT PRIMARY KEY, hostname TEXT NOT NULL REFERENCES classes(hostname),
                    mode TEXT NOT NULL, slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 400),
                    attempt INTEGER NOT NULL, path TEXT UNIQUE NOT NULL,
                    state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    reason TEXT, kind TEXT, receipt_path TEXT, receipt_sha256 TEXT,
                    inventory TEXT, UNIQUE(hostname,mode,attempt));
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_cell ON attempts(hostname,mode)
                    WHERE state IN ('reserved','captured','unverified');
                CREATE TABLE IF NOT EXISTS accepted(
                    hostname TEXT NOT NULL, mode TEXT NOT NULL, slot INTEGER NOT NULL,
                    five_tuple TEXT NOT NULL, attempt_id TEXT UNIQUE NOT NULL REFERENCES attempts(attempt_id),
                    receipt_path TEXT UNIQUE NOT NULL, receipt_sha256 TEXT NOT NULL,
                    inventory TEXT NOT NULL, verified_at TEXT NOT NULL,
                    PRIMARY KEY(hostname,mode,slot), UNIQUE(hostname,mode,five_tuple));
            """)
        finally:
            connection.close()
        with self._transaction() as connection:
            row = connection.execute("SELECT value FROM meta WHERE key='study_sha256'").fetchone()
            if row is not None and row[0] != _sha(raw):
                raise ValueError("ledger is bound to different study bytes")
            connection.execute("INSERT OR IGNORE INTO meta VALUES('study_sha256',?)", (_sha(raw),))
        return self.plan()

    def plan(self) -> dict:
        raw, observation = self._file("study.json")
        with self._transaction() as connection:
            row = connection.execute("SELECT value FROM meta WHERE key='study_sha256'").fetchone()
            if row is None or row[0] != observation["sha256"] or observation["mode"] != "0444":
                raise ValueError("immutable study/ledger binding changed")
        return _load(raw)

    def enroll(self, enrollment: dict) -> dict:
        self.plan()
        if not isinstance(enrollment, dict):
            raise ValueError("enrollment must be an object")
        hostname = _hostname(enrollment.get("hostname"))
        urls = enrollment.get("urls")
        if (not isinstance(urls, list) or len(urls) != RESOURCES
            or any(type(url) is not str for url in urls) or len(set(urls)) != RESOURCES):
            raise ValueError("class needs exactly twenty distinct URLs")
        normalized = set()
        for url in urls:
            if type(url) is not str:
                raise ValueError("class URL must be a string")
            parsed = urlsplit(url)
            if (parsed.scheme != "https" or parsed.hostname != hostname or parsed.port not in (None, 443)
                or parsed.username is not None or parsed.password is not None or parsed.fragment
                or any(character in url for character in ("\n", "\r", "\0"))):
                raise ValueError("class URLs must retain the exact HTTPS hostname")
            normalized.add((hostname, parsed.path or "/", parsed.query))
        if len(normalized) != RESOURCES:
            raise ValueError("URL aliases cannot inflate distinct resource count")
        workload = _digest(enrollment.get("workload_sha256"))
        if not isinstance(enrollment.get("runtime"), dict) or not enrollment["runtime"]:
            raise ValueError("enrollment lacks runtime identity")
        if enrollment.get("scientific_credit", False) is not False or enrollment.get("accepted_count", 0) != 0:
            raise ValueError("enrollment grants no session credit")
        inventory = self._files(enrollment.get("files"))
        if workload not in {value["sha256"] for value in inventory.values()}:
            raise ValueError("workload digest lacks an enrolled file")
        path = f"classes/{hostname}/enrollment.json"
        raw = _json(enrollment)
        with self._transaction() as connection:
            old = connection.execute("SELECT * FROM classes WHERE hostname=?", (hostname,)).fetchone()
            if old is None and connection.execute("SELECT count(*) FROM classes").fetchone()[0] >= CLASSES:
                raise ValueError("study already enrolled fifty classes")
            if old is not None:
                if old["sha256"] != _sha(raw):
                    raise ValueError("class already has different immutable enrollment")
                self._assert_inventory(_load(old["inventory"]))
            try:
                _create(self._relative(path), raw)
            except FileExistsError:
                if self._file(path)[0] != raw:
                    raise ValueError("claimed enrollment path contains different bytes")
            inventory[path] = self._file(path, _sha(raw))[1]
            self._assert_inventory(inventory)
            connection.execute("INSERT OR IGNORE INTO classes VALUES(?,?,?,?)",
                (hostname, path, _sha(raw), _json(inventory).decode()))
        return _load(raw)

    def enrolled(self) -> list[dict]:
        self.plan()
        with self._transaction() as connection:
            rows = connection.execute("SELECT * FROM classes ORDER BY hostname").fetchall()
            result = []
            for row in rows:
                self._assert_enrollment_inventory(row)
                result.append(_load(self._file(row["path"], row["sha256"])[0]))
            return result

    def allocate_attempt(self, hostname, mode, *, purpose="formal") -> dict:
        from .resource_study_epochs import reserve
        return reserve(self, hostname, mode, lambda: self._allocate_attempt(hostname, mode), purpose=purpose)

    def _allocate_attempt(self, hostname, mode) -> dict:
        self.plan(); hostname = _hostname(hostname); mode = _mode(mode)
        with self._transaction() as connection:
            enrollment = connection.execute("SELECT * FROM classes WHERE hostname=?", (hostname,)).fetchone()
            if enrollment is None:
                raise ValueError("class is not enrolled")
            self._assert_enrollment_inventory(enrollment)
            if connection.execute("SELECT 1 FROM attempts WHERE hostname=? AND mode=? AND state IN (?,?,?)",
                (hostname, mode, *_ACTIVE)).fetchone() is not None:
                raise ValueError("class/mode cell already has an active reservation")
            occupied = {row[0] for row in connection.execute("SELECT slot FROM accepted WHERE hostname=? AND mode=?", (hostname, mode))}
            slot = next((value for value in range(1, SESSIONS + 1) if value not in occupied), None)
            if slot is None:
                raise ValueError("class/mode cell already has four hundred sessions")
            number = connection.execute("SELECT coalesce(max(attempt),0)+1 FROM attempts WHERE hostname=? AND mode=?", (hostname, mode)).fetchone()[0]
            path = f"attempts/{hostname}/{mode}/session-{slot:06d}/attempt-{number:06d}"
            identifier = uuid.uuid4().hex
            now = _now()
            connection.execute("INSERT INTO attempts(attempt_id,hostname,mode,slot,attempt,path,state,created_at,updated_at) VALUES(?,?,?,?,?,?,'reserved',?,?)",
                (identifier, hostname, mode, slot, number, path, now, now))
        # The reservation survives a crash before the directory is created.
        # A claimed directory is never reused, even after filesystem failure.
        try:
            parent = self._relative(path).parent
            parent.mkdir(parents=True, exist_ok=True); _unlinked(parent, directory=True)
            self._relative(path).mkdir(mode=0o700, exist_ok=False); _fsync(parent)
        except BaseException:
            self.fail_attempt(identifier, "attempt directory creation failed", kind="filesystem")
            raise
        return {"hostname": hostname, "mode": mode, "slot": slot, "attempt": number,
            "attempt_id": identifier, "path": path}

    def fail_attempt(self, attempt_id, reason, kind="failed", *, wall_seconds=None) -> None:
        if type(reason) is not str or not reason or type(kind) is not str or not kind:
            raise ValueError("failure needs a reason and kind")
        wall_seconds = _wall(wall_seconds)
        with self._transaction() as connection:
            row = connection.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if row is not None and row["state"] == "duplicate" and kind == "duplicate":
                self._measurement(connection, row, "duplicate", wall_seconds)
                return
            if row is None or row["state"] not in _ACTIVE:
                raise ValueError("only an active attempt may be failed")
            connection.execute("UPDATE attempts SET state='failed',reason=?,kind=?,updated_at=? WHERE attempt_id=?",
                (reason, kind, _now(), attempt_id))
            self._measurement(connection, row, "pilot" if kind in {"pilot", "pilot-failed"} else "failed", wall_seconds)

    @staticmethod
    def _measurement(connection, attempt, outcome, wall_seconds, retained_bytes=None):
        connection.execute("""INSERT INTO measurements VALUES(?,?,?,?,?,?)
            ON CONFLICT(attempt_id) DO UPDATE SET
            wall_seconds=coalesce(excluded.wall_seconds,measurements.wall_seconds)""",
            (attempt["attempt_id"], attempt["hostname"], attempt["mode"], outcome,
                wall_seconds, retained_bytes))

    def mark_captured(self, attempt_id) -> None:
        """Record capture completion without granting verification or credit."""
        with self._transaction() as connection:
            changed = connection.execute("UPDATE attempts SET state='captured',updated_at=? WHERE attempt_id=? AND state='reserved'",
                (_now(), attempt_id)).rowcount
            if changed != 1:
                raise ValueError("capture completion needs a reserved attempt")

    def _receipt(self, receipt_path):
        path = _unlinked(Path(receipt_path))
        try:
            relative = path.relative_to(self.root).as_posix()
        except ValueError:
            raise ValueError("verification receipt is outside study root") from None
        raw, observation = self._file(relative)
        value = _load(raw)
        required = {"schema_version", "record_type", "verified", "hostname", "mode", "slot", "attempt_id", "five_tuple", "files"}
        if (not isinstance(value, dict) or not required <= set(value)
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["record_type"] != RECORD or value["verified"] is not True
            or type(value["slot"]) is not int or not 1 <= value["slot"] <= SESSIONS
            or type(value["attempt_id"]) is not str or not re.fullmatch("[0-9a-f]{32}", value["attempt_id"])):
            raise ValueError("verification receipt changes its closed identity")
        _hostname(value["hostname"]); _mode(value["mode"])
        five_tuple = _tuple(value["five_tuple"])
        inventory = self._files(value["files"])
        if relative in inventory:
            raise ValueError("verification receipt cannot hash itself")
        inventory[relative] = observation
        return value, relative, observation["sha256"], inventory, five_tuple

    @staticmethod
    def _corpus_path(attempt):
        return f'corpus/{attempt["hostname"]}/{attempt["mode"]}/session-{attempt["slot"]:06d}'

    def _bound_inputs(self, connection, attempt, value, relative):
        if (attempt["hostname"], attempt["mode"], attempt["slot"], attempt["attempt_id"]) != (value["hostname"], value["mode"], value["slot"], value["attempt_id"]):
            raise ValueError("verification changed its original reservation")
        enrollment = connection.execute("SELECT * FROM classes WHERE hostname=?", (value["hostname"],)).fetchone()
        held = _load(enrollment["inventory"])
        self._assert_enrollment_inventory(enrollment)
        enrolled = _load(self._file(enrollment["path"], enrollment["sha256"])[0])
        attempt_prefix = attempt["path"] + "/"
        corpus_prefix = self._corpus_path(attempt) + "/"
        if relative == corpus_prefix + "session.json":
            prefix = corpus_prefix
        elif relative.startswith(attempt_prefix):
            prefix = attempt_prefix
        else:
            raise ValueError("verification receipt is outside its exact attempt/corpus slot")
        for name, digest in value["files"].items():
            if not name.startswith(prefix) and (name not in held or digest != held[name]["sha256"]):
                raise ValueError("verification borrows unregistered or foreign attempt files")
        if "workload_sha256" in value and value["workload_sha256"] != enrolled["workload_sha256"]:
            raise ValueError("verification changed enrolled workload_sha256")
        if "runtime" in value and _scientific_runtime(value["runtime"]) != _scientific_runtime(enrolled["runtime"]):
            raise ValueError("verification changed Native/client/platform scientific identity")
        if "mode_settings" in value:
            settings = enrolled.get("mode_settings")
            if settings is None:
                settings = _load(self._file("study.json")[0]).get("mode_settings")
            if not isinstance(settings, dict) or value["mode"] not in settings or value["mode_settings"] != settings[value["mode"]]:
                raise ValueError("verification changed its declared mode settings")
        return enrolled

    def commit_verified(self, receipt_path, *, validator=None) -> dict:
        from .resource_study_epochs import credit
        return credit(self, receipt_path, lambda: self._commit_verified(receipt_path, validator=validator))

    def _commit_verified(self, receipt_path, *, validator=None) -> dict:
        self.plan()
        value, relative, digest, inventory, five_tuple = self._receipt(receipt_path)
        identifier = value["attempt_id"]
        wall_seconds = _wall(value.get("attempt_wall_seconds"))
        if value.get("purpose", "formal") != "formal" or value.get("scientific_credit", True) is not True:
            raise ValueError("pilot recordings cannot receive formal credit")
        with self._transaction() as connection:
            prior = connection.execute("SELECT * FROM accepted WHERE attempt_id=?", (identifier,)).fetchone()
            if prior is not None:
                if prior["receipt_path"] != relative or prior["receipt_sha256"] != digest or _load(prior["inventory"]) != inventory:
                    raise ValueError("accepted attempt replay changes its receipt or files")
                return {"accepted": True, "idempotent": True, "hostname": value["hostname"], "mode": value["mode"], "slot": value["slot"]}
            attempt = connection.execute("SELECT * FROM attempts WHERE attempt_id=?", (identifier,)).fetchone()
            if (attempt is None or attempt["state"] not in _ACTIVE
                or (attempt["hostname"], attempt["mode"], attempt["slot"]) != (value["hostname"], value["mode"], value["slot"])):
                raise ValueError("verification lacks its original active reservation")
            self._bound_inputs(connection, attempt, value, relative)
            if attempt["receipt_sha256"] is not None and (attempt["receipt_sha256"] != digest or attempt["receipt_path"] != relative or _load(attempt["inventory"]) != inventory):
                raise ValueError("attempt already bound a different verification receipt")
            connection.execute("UPDATE attempts SET state='unverified',receipt_path=?,receipt_sha256=?,inventory=?,updated_at=? WHERE attempt_id=?",
                (relative, digest, _json(inventory).decode(), _now(), identifier))
        if validator is None or not callable(validator):
            raise ValueError("first credit requires an independent raw validator")
        result = validator(self.root, _load(_json(value)))
        if result is not True and (not isinstance(result, dict) or result.get("verified") is not True):
            raise ValueError("independent raw verification did not pass")
        self._assert_inventory(inventory)
        self.plan()
        # The raw validator runs without holding a write transaction. Reopen
        # the enrollment and reservation before committing its independent result.
        duplicate = None
        with self._transaction() as connection:
            attempt = connection.execute("SELECT * FROM attempts WHERE attempt_id=?", (identifier,)).fetchone()
            if attempt is not None and attempt["state"] == "accepted":
                prior = connection.execute("SELECT * FROM accepted WHERE attempt_id=?", (identifier,)).fetchone()
                if prior is not None and prior["receipt_path"] == relative and prior["receipt_sha256"] == digest and _load(prior["inventory"]) == inventory:
                    return {"accepted": True, "idempotent": True, "hostname": value["hostname"], "mode": value["mode"], "slot": value["slot"]}
            if attempt is None or attempt["state"] not in _ACTIVE:
                raise ValueError("attempt changed while independent verification ran")
            self._bound_inputs(connection, attempt, value, relative)
            if connection.execute("SELECT 1 FROM accepted WHERE hostname=? AND mode=? AND (slot=? OR five_tuple=?)",
                (value["hostname"], value["mode"], value["slot"], _json(five_tuple).decode())).fetchone():
                duplicate = "verified session repeats an accepted tuple or slot"
                connection.execute("UPDATE attempts SET state='duplicate',reason=?,kind='duplicate',updated_at=? WHERE attempt_id=?",
                    (duplicate, _now(), identifier))
                self._measurement(connection, attempt, "duplicate", wall_seconds)
            else:
                connection.execute("INSERT INTO accepted VALUES(?,?,?,?,?,?,?,?,?)", (value["hostname"], value["mode"], value["slot"],
                    _json(five_tuple).decode(), identifier, relative, digest, _json(inventory).decode(), _now()))
                connection.execute("UPDATE attempts SET state='accepted',reason=NULL,kind=NULL,updated_at=? WHERE attempt_id=?", (_now(), identifier))
                prefix = (self._corpus_path(attempt) + "/" if relative.startswith(self._corpus_path(attempt) + "/")
                    else attempt["path"] + "/")
                retained = sum(_unlinked(self._relative(name)).stat().st_size for name in inventory
                    if name.startswith(prefix))
                self._measurement(connection, attempt, "accepted", wall_seconds, retained)
        if duplicate is not None:
            raise DuplicateSession(duplicate)
        return {"accepted": True, "idempotent": False, "hostname": value["hostname"], "mode": value["mode"], "slot": value["slot"]}

    def status(self) -> dict:
        """Indexed verified-at-commit counts; does not reread every raw capture."""
        self.plan()
        with self._transaction() as connection:
            hosts = [row[0] for row in connection.execute("SELECT hostname FROM classes ORDER BY hostname")]
            counts = {(row[0], row[1]): row[2] for row in connection.execute("SELECT hostname,mode,count(*) FROM accepted GROUP BY hostname,mode")}
            states = {row[0]: row[1] for row in connection.execute("SELECT state,count(*) FROM attempts GROUP BY state")}
            observations = [dict(row) for row in connection.execute("""SELECT mode,outcome,
                count(*) AS samples,count(wall_seconds) AS wall_samples,
                coalesce(sum(wall_seconds),0) AS wall_seconds,
                count(retained_bytes) AS byte_samples,coalesce(sum(retained_bytes),0) AS retained_bytes
                FROM measurements GROUP BY mode,outcome""")]
        cells = [{"hostname": host, "mode": mode, "accepted": counts.get((host, mode), 0), "target": SESSIONS}
            for host in hosts for mode in MODES]
        accepted = sum(counts.values())
        return {"session_target": TARGET, "class_target": CLASSES, "enrolled_count": len(hosts),
            "accepted_count": accepted, "accepted_by_mode": {mode: sum(count for (host, selected), count in counts.items() if selected == mode) for mode in MODES},
            "cells": cells, "attempts": states, "reserved": states.get("reserved", 0),
            "captured": states.get("captured", 0), "unverified": states.get("unverified", 0),
            "failed": states.get("failed", 0), "duplicate": states.get("duplicate", 0),
            "measurements_by_mode": self._measurement_summary(observations),
            "complete": len(hosts) == CLASSES and len(cells) == CLASSES * len(MODES) and all(cell["accepted"] == SESSIONS for cell in cells)}

    @staticmethod
    def _measurement_summary(observations):
        result = {}
        for mode in MODES:
            rows = [row for row in observations if row["mode"] == mode]
            formal = [row for row in rows if row["outcome"] != "pilot"]
            accepted = next((row for row in rows if row["outcome"] == "accepted"),
                {"wall_samples": 0, "wall_seconds": 0, "byte_samples": 0, "retained_bytes": 0})
            wall = sum(row["wall_seconds"] for row in formal)
            result[mode] = {
                "accepted_wall_samples": accepted["wall_samples"],
                "accepted_wall_seconds": accepted["wall_seconds"],
                "mean_accepted_wall_seconds": (accepted["wall_seconds"] / accepted["wall_samples"] if accepted["wall_samples"] else None),
                "formal_attempt_wall_samples": sum(row["wall_samples"] for row in formal), "formal_attempt_wall_seconds": wall,
                "failed_wall_samples": sum(row["wall_samples"] for row in formal if row["outcome"] == "failed"),
                "duplicate_wall_samples": sum(row["wall_samples"] for row in formal if row["outcome"] == "duplicate"),
                "pilot_wall_samples": sum(row["wall_samples"] for row in rows if row["outcome"] == "pilot"),
                "accepted_per_attributable_attempt_hour": (3600 * accepted["wall_samples"] / wall if wall > 0 else None),
                "accepted_retained_bytes_samples": accepted["byte_samples"], "accepted_retained_bytes": accepted["retained_bytes"],
                "mean_accepted_retained_bytes": (accepted["retained_bytes"] / accepted["byte_samples"] if accepted["byte_samples"] else None),
                "scope": "measured attempt work; not elapsed flight utilization; retained bound session files including receipt, excluding shared inputs"}
        return result

    def recover(self) -> dict:
        """After worker quiescence, retain captured evidence and fail interruptions."""
        self.plan()
        interrupted, pending = [], []
        with self._transaction() as connection:
            rows = connection.execute("SELECT * FROM attempts WHERE state IN (?,?,?) ORDER BY created_at", _ACTIVE).fetchall()
            for row in rows:
                path = self._relative(row["path"])
                if path.exists() or path.is_symlink():
                    _unlinked(path, directory=True)
                published = self._relative(self._corpus_path(row) + "/session.json")
                if row["receipt_path"] is None and (published.exists() or published.is_symlink()):
                    value, relative, digest, inventory, _ = self._receipt(published)
                    self._bound_inputs(connection, row, value, relative)
                    connection.execute("UPDATE attempts SET state='unverified',receipt_path=?,receipt_sha256=?,inventory=?,updated_at=? WHERE attempt_id=?",
                        (relative, digest, _json(inventory).decode(), _now(), row["attempt_id"]))
                    pending.append({"attempt_id": row["attempt_id"], "receipt_path": relative, "receipt_sha256": digest})
                elif row["receipt_path"] is not None:
                    self._assert_inventory(_load(row["inventory"]))
                    connection.execute("UPDATE attempts SET state='unverified',updated_at=? WHERE attempt_id=?", (_now(), row["attempt_id"]))
                    pending.append({"attempt_id": row["attempt_id"], "receipt_path": row["receipt_path"], "receipt_sha256": row["receipt_sha256"]})
                elif self._relative(self._corpus_path(row)).exists():
                    _unlinked(self._relative(self._corpus_path(row)), directory=True)
                    connection.execute("UPDATE attempts SET state='unverified',reason='corpus publication interrupted',kind='interrupted',updated_at=? WHERE attempt_id=?", (_now(), row["attempt_id"]))
                    pending.append({"attempt_id": row["attempt_id"], "receipt_path": None, "corpus_path": self._corpus_path(row)})
                else:
                    connection.execute("UPDATE attempts SET state='failed',reason='interrupted before verified receipt',kind='interrupted',updated_at=? WHERE attempt_id=?",
                        (_now(), row["attempt_id"]))
                    interrupted.append(row["attempt_id"])
        return {"interrupted": interrupted, "pending_verification": pending, "accepted_count": self.status()["accepted_count"], "files_deleted": 0}

    def export_manifest(self, output: Path) -> dict:
        self.plan()
        with self._transaction() as connection:
            refs = []
            for row in connection.execute("SELECT * FROM accepted ORDER BY hostname,mode,slot"):
                # Raw bytes were verified at commit. Export reopens the small
                # immutable receipt, not the accumulated historical PCAP set.
                expected = _load(row["inventory"])[row["receipt_path"]]
                if self._file(row["receipt_path"], row["receipt_sha256"])[1] != expected:
                    raise ValueError("accepted verification receipt full mode changed")
                refs.append({key: row[key] for key in ("hostname", "mode", "slot", "attempt_id", "receipt_path", "receipt_sha256")})
            hosts = [row[0] for row in connection.execute("SELECT hostname FROM classes")]
        counts = {(host, mode): 0 for host in hosts for mode in MODES}
        for ref in refs:
            counts[(ref["hostname"], ref["mode"])] += 1
        complete = len(hosts) == CLASSES and len(refs) == TARGET and all(count == SESSIONS for count in counts.values())
        value = {"schema_version": 1, "record_type": "qcsd-resource-domain-ledger-export-v1",
            "study_sha256": self._file("study.json")[1]["sha256"], "session_target": TARGET,
            "accepted_count": len(refs), "complete": complete, "scientific_credit": complete,
            "scope": "independently-verified-session-receipts; raw-files-verified-at-commit",
            "accepted": refs, "exported_at": _now()}
        _create(Path(output).absolute(), _json(value))
        return value
