#!/usr/bin/env python3
"""Reviewable MX BuFLO production owner. One process owns one slot and commits only after all gates pass."""

import argparse
import collections
import csv
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
import pathlib
import re
import resource
import secrets
import shutil
import sqlite3
import struct
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = pathlib.Path("/mnt/recapture16k")
PRODUCTION_DIR = ROOT / "diagnostics/mx-buflo-production-owner-001"
PROFILE_INPUTS = PRODUCTION_DIR / "inputs"
OUT = None
HOST = ROOT / "five-defense-recapture-20261123-001/www.flashscore.com.mx"
ORIGINAL_INPUTS = HOST / "buflo-inputs-initial-credit-16k-001"
INPUTS = None
NET_MODULE = HOST / "mx-network-policy-002.py"
NET_MANIFEST = HOST / "mx-network-manifest-001.json"
BINARY = ROOT / "diagnostics/mx-buflo-startup-ack-order-001-release/neqo-qcsd-client"
MODEL = ROOT / "runtime-support-001/model.json"
RUNTIME_IMAGE = "sha256:ee315c35752eac8687148c0b718cfd85bfa0e82d1433a880d5dfeb4d55bec6b6"
CONTAINER = None
NETWORK = {
    "mode": "buflo",
    "name": "qcsd-mx-buflo",
    "id": "114a2e9c2c5d86045b60b2b1447d5baf6a1132af720231cf967eb9a65aa2e9f7",
    "subnet": "172.29.201.0/24",
    "gateway": "172.29.201.1",
}
EXPECTED = {
    "resources.json": "d2a43539aeed35d2c2109c049c042a737e2b2c972a7272e4fe3a18ff00f3b317",
    "prepared-workload.json": "070be1ad471d1a4ae9b8f891036ff0b428a3229e8f8cf06a15d4a58b7efd7e93",
    "chaff-manifest.json": "977f4a1bf5c797cfc54b39624fd3e81b57d1156a0036c4e2a491315c8d44d388",
    "params/qcsd-buflo-receive-credit.toml": "19a7251c1db31b6d90df9e257cf7c22c24a8738fb0ac43d4e90a449d5f70241e",
    "params/buflo.json": "5c35c9a6c0ce9d424b3e9cfc9e05a48713b9260fd1385dfba2d79048f58f283e",
}
SOURCE_EXPECTED = {
    "resources.json": "d2a43539aeed35d2c2109c049c042a737e2b2c972a7272e4fe3a18ff00f3b317",
    "prepared-workload.json": "6d4e1c5d309c9bbd341a73ac38068e23417b35b067d5e6b259f39ca7f3c061cd",
    "chaff-manifest.json": "824f4c544a3a3479a519d953692ae994cba4c3f1dffd0ba76bc64957fca2b84c",
    "params/qcsd-buflo-receive-credit.toml": "fff0779b3c62694b59b07dae0311081c982149c536f01ef33153a01049174224",
    "params/buflo.json": "5c35c9a6c0ce9d424b3e9cfc9e05a48713b9260fd1385dfba2d79048f58f283e",
}
NET_MODULE_SHA = "48a4c902bc0d81924df985d30196425692e6a6e32c686a3312f50e93ccd5e278"
NET_MANIFEST_SHA = "6dc25e75edaf030c7c5bbdb44c783fc75cc3dbc3ab0f9408444f0b201f728b4f"
BINARY_SHA = "3ebebcc6e2601ab07684abd9005db6d685114423d4b4366ed9a6a3ee25f08481"
CONFIG_PATH = PRODUCTION_DIR / "owner-config.json"
CONFIG_SHA_FILE = PRODUCTION_DIR / "owner-config.sha256"
TUPLE_MODULE = ROOT / "runtime-support-001/tuple_isolation_per_endpoint.py"
TUPLE_MODULE_SHA = "cd7873974dd2135c9b26af7c05300df81a0d69c03501804003c75d74efdc58fb"
TUPLE_DB = HOST / "shared-ledger-v2.sqlite3"
JOURNAL = None
STATE = None
RESULT = None
LOCK = None
WTFPAD_HISTORY = HOST / "wtfpad-tuple-history-001.json"
WTFPAD_HISTORY_SHA = "4a00be0e83df7c31ecb85721a6563b3085f954d911112d83909a80f8797f812d"
MODE_OWNER_LOCK = HOST / "modes/buflo/production-owner.lock"
PINNED_LEDGER_TUPLE_SET_SHA = "48c964f2fecba3b9aeb5a1bd345b8d2095becc60cc845996990ea42876bd126e"
PINNED_LEDGER_TUPLE_COUNT = 1313
CURRENT_SLOT = None
ATTEMPT_ID = None
REQUEST_ID = None
CAPTURE_PROFILE_SHA = None
SESSION_SEED = None
LEDGER = None
CLIENT_EXEC_SUBMITTED_GLOBAL = False
CONFIG = None


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_pinned_module(path, expected_sha):
    if pathlib.Path(path).is_symlink() or sha256(pathlib.Path(path)) != expected_sha:
        raise RuntimeError("pinned Python module is missing or changed")
    spec=importlib.util.spec_from_file_location("pinned_"+pathlib.Path(path).stem,path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pinned Python module")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fsync_directory(path):
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(str(temporary), str(path))
    fsync_directory(path.parent)


def journal(event, **data):
    record = {
        "sequence": getattr(journal, "sequence", 0) + 1,
        "utc": utc_now(),
        "monotonic_ns": time.monotonic_ns(),
        "request_id": REQUEST_ID,
        "event": event,
        "data": data,
    }
    journal.sequence = record["sequence"]
    with JOURNAL.open("ab") as stream:
        stream.write((json.dumps(record, sort_keys=True) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())
    atomic_json(STATE, record)


def command_readonly(argv, timeout=15):
    return subprocess.run(
        argv, check=True, text=True, capture_output=True, timeout=timeout
    ).stdout.strip()


def mutation_once(label, argv, wait_limit_s, log_path):
    """Submit one mutation and never kill/reissue it if the response is uncertain."""
    journal(label + "_intent", argv=argv, wait_limit_s=wait_limit_s)
    try:
        log = log_path.open("xb")
    except FileExistsError:
        journal(label + "_refused_existing_log", log_path=str(log_path))
        raise RuntimeError(label + " already has a request log; refusing duplicate mutation")
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except Exception as error:
        journal(label + "_launch_failed", error=repr(error))
        raise
    journal(label + "_process_started", pid=process.pid, log_path=str(log_path))
    deadline = time.monotonic() + wait_limit_s
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.25)
    if process.poll() is None:
        log.flush()
        os.fsync(log.fileno())
        journal(label + "_response_wait_limit_elapsed", pid=process.pid, action="do_not_kill_or_resubmit")
        return None, process.pid
    log.flush()
    os.fsync(log.fileno())
    code = process.returncode
    journal(label + "_completed", pid=process.pid, returncode=code)
    return code, process.pid


def command_line_log(path):
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def load_network_policy():
    if sha256(NET_MODULE) != NET_MODULE_SHA or sha256(NET_MANIFEST) != NET_MANIFEST_SHA:
        raise RuntimeError("pinned MX network policy or manifest hash changed")
    spec = importlib.util.spec_from_file_location("mx_network_policy", NET_MODULE)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load pinned MX network policy")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = json.loads(NET_MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("networks", {}).get("buflo") != NETWORK:
        raise RuntimeError("MX BuFLO network manifest changed")
    return module


def inspect_container(container_id):
    return json.loads(command_readonly(["docker", "inspect", container_id], timeout=15))[0]


def validate_qdisc_readback(text):
    observed = json.loads(text)
    before = observed.get("before")
    after = observed.get("after")
    if not isinstance(before, list) or not isinstance(after, list):
        raise ValueError("qdisc readback must contain before/after arrays")
    if len(after) != 3:
        raise ValueError("expected exactly root prio plus ETF and pfifo child qdiscs")
    roots = [q for q in after if q.get("root") is True]
    etfs = [q for q in after if q.get("kind") == "etf" and q.get("parent") == "1:1"]
    fifos = [q for q in after if q.get("kind") == "pfifo" and q.get("parent") == "1:2"]
    if len(roots) != 1 or len(etfs) != 1 or len(fifos) != 1:
        raise ValueError("qdisc hierarchy differs from the required root/ETF/pfifo topology")
    root = roots[0]
    if root.get("kind") != "prio" or root.get("handle") != "1:":
        raise ValueError("root qdisc kind/handle mismatch")
    ropts = root.get("options") or {}
    expected_priomap = [1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    if ropts.get("bands") != 2 or ropts.get("priomap") != expected_priomap:
        raise ValueError("priority bands/map mismatch")
    etf = etfs[0]
    eopts = etf.get("options") or {}
    if etf.get("handle") != "20:" or eopts.get("clockid") != "TAI" or eopts.get("delta") != 10000000:
        raise ValueError("ETF handle/clock/delta mismatch")
    if eopts.get("deadline_mode") != "off" or eopts.get("skip_sock_check") != "off" or eopts.get("offload") != "off":
        raise ValueError("ETF deadline/skip-check/offload flags mismatch")
    fifo = fifos[0]
    if fifo.get("handle") != "10:" or (fifo.get("options") or {}).get("limit") != 1000:
        raise ValueError("ordinary pfifo handle/limit mismatch")
    return {"valid": True, "before": before, "after": after, "contract": "buflo-eth0-prio-etf-pfifo-v1"}


def matched_event_evidence(run_path, events_path):
    run = json.loads(run_path.read_text(encoding="utf-8"))
    permission = run.get("buflo_retained_parser_fin_permission") or {}
    if not isinstance(permission, dict):
        permission = {}
    accounting = permission.get("accounting") or {}
    if not isinstance(accounting, dict):
        accounting = {}
    release_rows = accounting.get("releases", [])
    if not isinstance(release_rows, list):
        release_rows = []
    releases = [
        item for item in release_rows
        if isinstance(item, dict)
        and item.get("permission_source") == "direct_advertised_exact_credit_suffix"
    ]
    slots = {item.get("slot") for item in releases}
    replacement_streams = {
        (replacement[0], replacement[1])
        for release in releases
        for replacement in release.get("replacements", [])
        if isinstance(replacement, list) and len(replacement) == 5
    }
    evidence = []
    with events_path.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            try:
                details = json.loads(row["details"])
            except (KeyError, json.JSONDecodeError):
                continue
            if not isinstance(details, dict):
                continue
            if details.get("type") in {
                "peer_fin_read", "stream_finished", "bytes_read", "stream_opened",
                "response_headers", "receive_limit_advertised", "slot_satisfied", "slot_missed",
            } and details.get("slot") in slots:
                evidence.append({"monotonic_us": row.get("monotonic_us"), "event": row.get("event"), "details": details})
            elif details.get("type") in {"bytes_read", "stream_opened"} and (
                details.get("endpoint"), details.get("stream")
            ) in replacement_streams:
                evidence.append({"monotonic_us": row.get("monotonic_us"), "event": row.get("event"), "details": details})
            elif details.get("type") in {"peer_fin_read", "stream_finished"} and any(
                release.get("stream") == details.get("stream")
                and release.get("endpoint") == details.get("endpoint")
                for release in releases
            ):
                evidence.append({"monotonic_us": row.get("monotonic_us"), "event": row.get("event"), "details": details})
    return {
        "direct_fin_releases": releases,
        "matching_events": evidence,
        "same_slot_advertisement_observed": any(
            item["details"].get("type") == "receive_limit_advertised"
            and item["details"].get("slot") in slots for item in evidence
        ),
        "same_slot_satisfied_observed": any(
            item["details"].get("type") == "slot_satisfied"
            and item["details"].get("slot") in slots for item in evidence
        ),
        "same_slot_missed_observed": any(
            item["details"].get("type") == "slot_missed"
            and item["details"].get("slot") in slots for item in evidence
        ),
        "replacement_streams": sorted([list(item) for item in replacement_streams]),
        "replacement_bytes_read_observed": any(
            item["details"].get("type") == "bytes_read" for item in evidence
        ),
    }


def verify_inputs():
    intent = json.loads((OUT / "INTENT.json").read_text(encoding="utf-8"))
    if (intent.get("kind") != "mx-buflo-production-capture-intent"
            or intent.get("request_id") != REQUEST_ID
            or intent.get("attempt_id") != ATTEMPT_ID
            or intent.get("slot") != CURRENT_SLOT
            or intent.get("capture_credit") is not True
            or intent.get("drive_upload") is not False):
        raise RuntimeError("production intent identity or credit scope is invalid")
    for rel, expected in SOURCE_EXPECTED.items():
        if sha256(ORIGINAL_INPUTS / rel) != expected:
            raise RuntimeError("pinned owner input changed: " + rel)
    for rel, expected in EXPECTED.items():
        if sha256(INPUTS / rel) != expected:
            raise RuntimeError("pinned diagnostic input changed: " + rel)
    source_resources = json.loads((ORIGINAL_INPUTS / "resources.json").read_text())
    diagnostic_resources = json.loads((INPUTS / "resources.json").read_text())
    source_prepared = json.loads((ORIGINAL_INPUTS / "prepared-workload.json").read_text())
    diagnostic_prepared = json.loads((INPUTS / "prepared-workload.json").read_text())
    source_chaff = json.loads((ORIGINAL_INPUTS / "chaff-manifest.json").read_text())
    diagnostic_chaff = json.loads((INPUTS / "chaff-manifest.json").read_text())
    if source_resources != diagnostic_resources or source_prepared["resources"] != diagnostic_prepared["resources"]:
        raise RuntimeError("diagnostic resource roster differs from the pinned source")
    if source_prepared["preparation"]["expected_responses"] != diagnostic_prepared["preparation"]["expected_responses"]:
        raise RuntimeError("diagnostic expected-response identities differ from pinned source")
    if source_chaff["resources"] != diagnostic_chaff["resources"] or source_chaff["selected_chaff_resource_id"] != diagnostic_chaff["selected_chaff_resource_id"]:
        raise RuntimeError("diagnostic chaff resource differs from pinned source")
    if diagnostic_chaff["application_workload_sha256"] != EXPECTED["prepared-workload.json"]:
        raise RuntimeError("production chaff manifest does not bind the exact production prep source")
    if sha256(BINARY) != BINARY_SHA:
        raise RuntimeError("isolated release binary hash differs")
    wtfpad_history_tuple_keys()
    return intent


def capture_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))


def wait_for_tcpdump(process, log_path, wait_s):
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        if log_path.exists() and b"listening on eth0" in log_path.read_bytes():
            return True
        time.sleep(0.05)
    return False


def stop_tcpdump(process, log_stream):
    if process is None:
        return None
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        deadline=time.monotonic()+15
        while process.poll() is None and time.monotonic()<deadline:
            time.sleep(0.1)
        if process.poll() is None:
            journal("tcpdump_sigint_wait_elapsed",pid=process.pid,
                    action="continue_supervising_exact_collector_until_exit")
            last_notice=time.monotonic()
            while process.poll() is None:
                if time.monotonic()-last_notice>=30:
                    journal("tcpdump_still_running_after_sigint",pid=process.pid,
                            action="keep_handle_and_log_open_until_terminal")
                    last_notice=time.monotonic()
                time.sleep(1)
    code=process.returncode
    if log_stream is not None and not log_stream.closed:
        log_stream.flush(); os.fsync(log_stream.fileno()); log_stream.close()
    return code


def container_client_state(container_id):
    top=subprocess.run(["docker","top",container_id,"-eo","pid,args"],text=True,
                       capture_output=True,timeout=10)
    if top.returncode==0:
        lines=top.stdout.splitlines()
        active=[line for line in lines[1:] if "neqo-qcsd-client" in line
                and re.search(r"(?:^|\s)run(?:\s|$)",line)]
        return {"query":"docker top","container_present":True,"active_client_processes":active,
                "client_absent":len(active)==0,"stdout":top.stdout}
    inspect=subprocess.run(["docker","inspect",container_id],text=True,capture_output=True,timeout=10)
    absent=(inspect.returncode!=0 and ("no such object" in inspect.stderr.lower()
            or "no such container" in inspect.stderr.lower()))
    if absent:
        return {"query":"docker top + docker inspect","container_present":False,
                "active_client_processes":[],"client_absent":True,
                "evidence":"daemon confirms container object is absent after client process exit",
                "top_stderr":top.stderr,"inspect_stderr":inspect.stderr}
    raise RuntimeError("cannot prove whether the client remains alive in its container: "
                       +repr({"top_rc":top.returncode,"top_stderr":top.stderr,
                              "inspect_rc":inspect.returncode,"inspect_stderr":inspect.stderr}))


def wait_for_client_terminal(process, collector, log_stream, container_id, timeout_s=90):
    if process is None:
        return None
    deadline=time.monotonic()+timeout_s
    while process.poll() is None and time.monotonic()<deadline:
        time.sleep(0.25)
    timed_out=process.poll() is None
    if timed_out:
        journal("client_exec_wait_bound_elapsed",pid=process.pid,
                action="continue_supervising_same_client_and_keep_tcpdump_running",
                collector_pid=None if collector is None else collector.pid)
    last_notice=time.monotonic()
    collector_failure_reported=False
    while process.poll() is None:
        if collector is not None and collector.poll() is not None and not collector_failure_reported:
            collector_failure_reported=True
            journal("tcpdump_exited_while_client_active",collector_pid=collector.pid,
                    collector_returncode=collector.returncode,client_pid=process.pid,
                    action="fail_closed_and_continue_supervising_same_client_until_exit")
        if time.monotonic()-last_notice>=30:
            journal("client_exec_still_in_flight",pid=process.pid,
                    collector_pid=None if collector is None else collector.pid,
                    collector_running=collector is not None and collector.poll() is None,
                    action="keep_collector_handle_and_logs_open; do_not_kill_or_resubmit")
            last_notice=time.monotonic()
        time.sleep(1)
    # A terminated local docker CLI can lose its connection while the in-container
    # client remains alive. Keep tcpdump and the exact handles until the daemon proves
    # that no client process remains in this unique container.
    last_container_notice=time.monotonic()
    container_state=None
    while container_state is None:
        try:
            observed=container_client_state(container_id)
            if observed.get("client_absent") is True:
                container_state=observed
                break
            if time.monotonic()-last_container_notice>=30:
                journal("container_client_still_active_after_exec_exit",pid=process.pid,
                        container_id=container_id,active_processes=observed.get("active_client_processes"),
                        action="keep_tcpdump_and_owner_lock_until_daemon_confirms_absence")
                last_container_notice=time.monotonic()
        except Exception as inspect_error:
            if time.monotonic()-last_container_notice>=30:
                journal("container_client_state_uncertain_after_exec_exit",pid=process.pid,
                        container_id=container_id,error=repr(inspect_error),
                        action="fail_closed_keep_tcpdump_and_retry_read_only_process_inspection")
                last_container_notice=time.monotonic()
        time.sleep(1)
    if log_stream is not None and not log_stream.closed:
        log_stream.flush(); os.fsync(log_stream.fileno()); log_stream.close()
    return {"returncode":process.returncode,"wait_bound_elapsed":timed_out,
            "collector_running_at_client_exit":collector is not None and collector.poll() is None,
            "collector_failure_reported":collector_failure_reported,
            "container_client_absent":True,"container_client_state":container_state}



def ledger_readonly_state():
    if TUPLE_DB.is_symlink() or not TUPLE_DB.is_file():
        raise RuntimeError("read-only tuple ledger is missing or unsafe")
    uri = "file:" + str(TUPLE_DB) + "?mode=ro"
    db = sqlite3.connect(uri, uri=True, timeout=10)
    try:
        keys = [row[0] for row in db.execute("SELECT k FROM tuples ORDER BY k")]
        meta = db.execute("SELECT k,v FROM meta ORDER BY k").fetchall()
        sessions = db.execute(
            "SELECT mode,slot,attempt,final_sha,state FROM sessions "
            "WHERE mode='buflo' AND slot=? ORDER BY attempt", (CURRENT_SLOT,)
        ).fetchall()
        slot_tuples = db.execute(
            "SELECT k,mode,attempt,slot,final_sha,state FROM tuples "
            "WHERE mode='buflo' AND slot=? ORDER BY k", (CURRENT_SLOT,)
        ).fetchall()
    finally:
        db.close()
    tuple_hash = hashlib.sha256(("\n".join(keys)+"\n").encode()).hexdigest()
    live_rows = [row for row in slot_tuples if row[5] != "excluded"]
    occupied = bool(sessions or live_rows)
    return {
        "path": str(TUPLE_DB), "read_only": True, "tuple_count": len(keys),
        "tuple_keys": keys, "meta": meta, "tuple_set_sha256": tuple_hash,
        "slot": 1, "slot_sessions": sessions, "slot_tuples": slot_tuples,
        "slot_live_tuples": live_rows, "slot_occupied_or_pending": occupied,
    }


def validate_native_tuple_key(value):
    if not isinstance(value, str):
        raise ValueError("tuple key must be a string")
    parsed=json.loads(value)
    if not isinstance(parsed,list) or len(parsed)!=5 or parsed[0]!="udp":
        raise ValueError("tuple key must be canonical UDP five-tuple JSON")
    ipaddress.ip_address(parsed[1]); ipaddress.ip_address(parsed[3])
    if type(parsed[2]) is not int or type(parsed[4]) is not int or not (1<=parsed[2]<=65535 and 1<=parsed[4]<=65535):
        raise ValueError("tuple key ports must be integer UDP ports")
    canonical=json.dumps(parsed,separators=(",",":"))
    if canonical!=value:
        raise ValueError("tuple key JSON is not canonical")
    return value


def wtfpad_history_tuple_keys():
    if WTFPAD_HISTORY.is_symlink() or not WTFPAD_HISTORY.is_file() or sha256(WTFPAD_HISTORY)!=WTFPAD_HISTORY_SHA:
        raise RuntimeError("pinned WTF-PAD tuple history is missing or changed")
    data=json.loads(WTFPAD_HISTORY.read_text(encoding="utf-8"))
    if data.get("kind")!="flashscore-mx-wtfpad-prior-tuple-history" or data.get("domain")!="www.flashscore.com.mx":
        raise RuntimeError("WTF-PAD tuple history identity mismatch")
    committed=data.get("committed")
    reserved=data.get("reserved_native_tuples")
    if not isinstance(committed,list) or len(committed)!=400 or not isinstance(reserved,list) or len(reserved)!=7:
        raise RuntimeError("WTF-PAD history must contain 400 committed slots and seven reserved tuples")
    slots=[]; attempts=[]; keys=[]
    for item in committed:
        if not isinstance(item,dict) or type(item.get("slot")) is not int or not isinstance(item.get("attempt_id"),str):
            raise RuntimeError("malformed committed WTF-PAD slot history")
        slots.append(item["slot"]); attempts.append(item["attempt_id"])
        native=item.get("native_tuple_keys")
        if not isinstance(native,list) or not native:
            raise RuntimeError("committed WTF-PAD slot lacks native tuple keys")
        keys.extend(validate_native_tuple_key(k) for k in native)
    reserved_keys=[validate_native_tuple_key(k) for k in reserved]
    if sorted(slots)!=list(range(1,401)) or len(set(attempts))!=400:
        raise RuntimeError("WTF-PAD committed slot/attempt history is not a unique 1..400 roster")
    all_keys=keys+reserved_keys
    if len(set(all_keys))!=len(all_keys):
        raise RuntimeError("WTF-PAD committed and reserved tuple exclusions overlap")
    return {"sha256":WTFPAD_HISTORY_SHA,"committed_slots":len(committed),
            "reserved_tuple_count":len(reserved_keys),"tuple_keys":sorted(all_keys),
            "tuple_set_sha256":hashlib.sha256(("\n".join(sorted(all_keys))+"\n").encode()).hexdigest()}


def verify_slot_and_tuple_snapshot(state, history):
    meta=dict(state["meta"])
    if meta.get("config:buflo") != CAPTURE_PROFILE_SHA:
        raise RuntimeError("shared ledger BuFLO profile pin differs from this reviewed production profile")
    if state["slot_occupied_or_pending"]:
        raise RuntimeError("selected BuFLO slot has committed/pending state; no capture request may start")
    if history["sha256"]!=WTFPAD_HISTORY_SHA:
        raise RuntimeError("WTF-PAD tuple history hash differs from reviewed pin")
    return {"tuple_count":state["tuple_count"],"tuple_set_sha256":state["tuple_set_sha256"],
            "slot":CURRENT_SLOT,"slot_sessions":state["slot_sessions"],"slot_tuples":state["slot_tuples"],
            "slot_occupied_or_pending":False,"wtfpad_history_sha256":history["sha256"],
            "wtfpad_tuple_count":len(history["tuple_keys"])}


def verify_existing_buflo_history(db, config):
    """Check all prior MX BuFLO exclusions/successes before choosing a new slot."""
    legacy_path=pathlib.Path(config["legacy_owner_module"])
    if legacy_path.is_symlink() or sha256(legacy_path)!=config["legacy_owner_module_sha256"]:
        raise RuntimeError("pinned legacy partial-exclusion verifier changed")
    legacy=load_pinned_module(legacy_path,config["legacy_owner_module_sha256"])
    legacy.MODE="buflo"; legacy.ROOT=HOST/"modes/buflo"; legacy.HOST="www.flashscore.com.mx"
    legacy.verify_partial_exclusions(db)
    legacy.verify_unsealed_exclusion(db)
    legacy.verify_second_unsealed_exclusion(db)
    legacy.verify_third_unsealed_exclusion(db)
    legacy.verify_fourth_unsealed_exclusion(db)

    attempt_root=HOST/"modes/buflo/attempts/www.flashscore.com.mx"
    if attempt_root.is_symlink() or not attempt_root.is_dir():
        raise RuntimeError("existing BuFLO attempt history directory is missing or unsafe")
    rows=db.execute("SELECT k,attempt,slot,final_sha,state FROM tuples WHERE mode='buflo' ORDER BY attempt,k").fetchall()
    by_attempt={}
    for key,attempt,slot,final_sha,state in rows:
        by_attempt.setdefault(attempt,[]).append((key,slot,final_sha,state))
    seen=set()
    manual_partial_keys={aid:key for aid,_,_,key in legacy.PARTIALS["buflo"]}
    for directory in attempt_root.iterdir():
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError("unsafe object in BuFLO attempt history")
        final_path=directory/"FINAL.json"
        if final_path.is_symlink() or not final_path.is_file():
            raise RuntimeError("unsealed prior BuFLO attempt requires reconciliation")
        final_sha=sha256(final_path)
        final=json.loads(final_path.read_text(encoding="utf-8"))
        attempt=directory.name
        if final.get("attempt_id")!=attempt or final.get("hostname")!="www.flashscore.com.mx" or final.get("defense")!="buflo":
            raise RuntimeError("prior BuFLO FINAL identity mismatch")
        seen.add(attempt)
        session=db.execute("SELECT final_sha,state FROM sessions WHERE mode='buflo' AND slot=? AND attempt=?",
                           (final.get("slot"),attempt)).fetchone()
        linked=by_attempt.get(attempt,[])
        if final.get("status")=="success":
            if session!=(final_sha,"committed"):
                raise RuntimeError("untracked or mismatched prior BuFLO success")
            keys=final.get("native_tuple_keys") or final.get("tuple_keys")
            if not isinstance(keys,list) or not keys or {r[0] for r in linked}!=set(keys) or any(r[2:]!=(final_sha,"committed") for r in linked):
                raise RuntimeError("prior committed BuFLO tuple history differs from FINAL")
        elif final.get("status")=="not_started":
            if session is not None or linked or final.get("client_exec_submitted") is not False or final.get("capture_credit") is not False or final.get("session_ledger_write") is not False:
                raise RuntimeError("prior no-request final has credit or endpoint ledger rows")
        elif final.get("status")=="partial":
            observed=final.get("observed_partial_tuple_keys") or final.get("native_tuple_keys") or []
            if not observed and attempt in manual_partial_keys:
                observed=[manual_partial_keys[attempt]]
            if not isinstance(observed,list):
                raise RuntimeError("prior BuFLO partial lacks a canonical observed tuple list")
            if linked:
                if {r[0] for r in linked}!=set(observed) or any(r[1]!=final.get("slot") or r[2]!=final_sha or r[3]!="excluded" for r in linked):
                    raise RuntimeError("prior BuFLO partial exclusion differs from FINAL")
            elif observed:
                raise RuntimeError("prior partial native tuple is missing from shared ledger")
        else:
            raise RuntimeError("prior BuFLO FINAL has unknown status")
    if set(by_attempt)-seen:
        raise RuntimeError("BuFLO ledger contains tuple rows with no prior FINAL directory")


def pcap_packet_multiset_signature(path):
    magics = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
              b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    record_hashes=[]
    with path.open("rb") as stream:
        header=stream.read(24)
        if len(header)!=24 or header[:4] not in magics:
            raise ValueError("unsupported classic PCAP header")
        endian=magics[header[:4]]
        if struct.unpack(endian+"I",header[20:24])[0]!=1:
            raise ValueError("PCAP link type is not Ethernet")
        while True:
            rh=stream.read(16)
            if not rh: break
            if len(rh)!=16: raise ValueError("truncated PCAP record header")
            sec,frac,caplen,origlen=struct.unpack(endian+"IIII",rh)
            packet=stream.read(caplen)
            if caplen!=origlen or len(packet)!=caplen:
                raise ValueError("truncated PCAP record cannot be compared")
            record_hashes.append(hashlib.sha256(struct.pack(">IIII",sec,frac,caplen,origlen)+packet).digest())
    signature=hashlib.sha256(b"".join(sorted(record_hashes))).hexdigest()
    return {"packet_records":len(record_hashes),"timestamp_packet_multiset_sha256":signature}


def strict_nonnegative_int(value, field):
    if not isinstance(value,str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)",value):
        raise ValueError(field+" is missing or is not a canonical nonnegative integer")
    return int(value)


def strict_startup_and_bytes_read(events_path, run, startup, schedule):
    if not schedule:
        raise ValueError("schedule is empty")
    defense_start_ns=run.get("defense_start_monotonic_ns")
    if type(defense_start_ns) is not int or defense_start_ns<0:
        raise ValueError("missing/invalid defense_start_monotonic_ns")
    defense_start_us=defense_start_ns//1000
    incoming=[row for row in schedule if row.get("direction")=="incoming"]
    if not incoming:
        raise ValueError("no scheduled incoming cells")
    first=min(incoming,key=lambda row:strict_nonnegative_int(row.get("target_time_us"),"incoming target_time_us"))
    target_us=strict_nonnegative_int(first.get("target_time_us"),"first incoming target_time_us")
    action_abs_us=strict_nonnegative_int(first.get("action_time_us"),"first incoming action_time_us")
    if action_abs_us<defense_start_us:
        raise ValueError("incoming action precedes defense_start_monotonic_ns")
    action_elapsed_us=action_abs_us-defense_start_us
    slot_id=strict_nonnegative_int(first.get("slot_id"),"first incoming slot_id")
    if first.get("satisfaction")!="satisfied" or first.get("size")!="1200":
        raise ValueError("first scheduled incoming cell is not a satisfied 1200-byte cell")

    rows=[]; bytes_read=[]; ack_rows=[]; ready_rows=[]; ingress_actions=[]
    required_columns={"monotonic_us","event","outcome","details"}
    with events_path.open(newline="",encoding="utf-8") as stream:
        reader=csv.DictReader(stream)
        if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
            raise ValueError("events.csv is missing required columns")
        for index,row in enumerate(reader,2):
            t=strict_nonnegative_int(row.get("monotonic_us"),f"events.csv row {index} monotonic_us")
            raw=row.get("details")
            if not isinstance(raw,str) or not raw:
                raise ValueError(f"events.csv row {index} has missing details")
            if not isinstance(row.get("event"),str) or not row["event"] or not isinstance(row.get("outcome"),str) or not row["outcome"]:
                raise ValueError(f"events.csv row {index} has missing event/outcome fields")
            try: detail=json.loads(raw)
            except Exception as exc: raise ValueError(f"events.csv row {index} has invalid JSON details: {exc}")
            # The only non-object details in the pinned event schema are the 20 request-start IDs.
            if type(detail) is int:
                if row.get("event")!="application_request" or row.get("outcome")!="started" or not (0<=detail<20):
                    raise ValueError(f"events.csv row {index} has an unrecognized scalar event payload")
            elif not isinstance(detail,dict):
                raise ValueError(f"events.csv row {index} details must be an object")
            event_name=row.get("event")
            if isinstance(detail,dict) and detail.get("type")=="bytes_read":
                endpoint=detail.get("endpoint"); stream_id=detail.get("stream"); amount=detail.get("bytes")
                if type(endpoint) is not int or endpoint<0 or type(stream_id) is not int or stream_id<0:
                    raise ValueError(f"events.csv row {index} has invalid bytes_read endpoint/stream")
                if type(amount) is not int or amount<0:
                    raise ValueError(f"events.csv row {index} has missing, malformed, or negative bytes_read count")
                if event_name!="observation":
                    raise ValueError(f"events.csv row {index} bytes_read is not an observation")
                bytes_read.append((t,amount,endpoint,stream_id))
            if event_name=="buflo_incoming_startup_ack":
                if not isinstance(detail,dict): raise ValueError("startup ACK event payload is not an object")
                ack_rows.append((t,row,detail))
            if event_name=="buflo_incoming_startup_ready":
                if not isinstance(detail,dict): raise ValueError("startup-ready event payload is not an object")
                ready_rows.append((t,row,detail))
            if isinstance(detail,dict) and detail.get("type")=="increase_receive_limit":
                packet=detail.get("packet")
                if isinstance(packet,dict) and packet.get("direction")=="incoming" and packet.get("timestamp_us")==target_us:
                    ingress_actions.append((t,row,detail))
            rows.append((t,row,detail))
    if not rows:
        raise ValueError("events.csv has no event rows")
    if not bytes_read:
        raise ValueError("events.csv has no valid bytes_read events")
    if not ack_rows or not ready_rows:
        raise ValueError("startup ACK/ready event evidence is missing")

    ready_endpoint=startup.get("ready_endpoint"); ready_stream=startup.get("ready_stream")
    ready_resource=startup.get("ready_resource_id"); ready_request=startup.get("ready_request_id")
    ack_us=startup.get("ack_observed_at_us"); arm_target=startup.get("armed_at_us")
    if any(type(x) is not int or x<0 for x in [ready_endpoint,ready_stream,ready_resource,ready_request,ack_us,arm_target]):
        raise ValueError("startup diagnostics have missing/noninteger identity or time fields")
    if arm_target!=target_us:
        raise ValueError("startup cadence boundary does not match first incoming target")
    chaff=json.loads((INPUTS/"chaff-manifest.json").read_text(encoding="utf-8"))
    if chaff.get("selected_chaff_resource_id")!=ready_resource:
        raise ValueError("startup stream is not the selected qualified chaff resource")
    matching_ack=[]
    for t,row,detail in ack_rows:
        obs=detail.get("observation")
        if not isinstance(obs,dict): raise ValueError("startup ACK row lacks nested observation")
        role=obs.get("role")
        chaff_role=role.get("chaff") if isinstance(role,dict) else None
        if (obs.get("endpoint"),obs.get("stream"),chaff_role)==(
            ready_endpoint,ready_stream,{"resource_id":ready_resource,"request_id":ready_request}):
            matching_ack.append((t,row,detail,obs))
    if len(matching_ack)!=1:
        raise ValueError("selected startup request lacks exactly one genuine ACK observation")
    ack_abs,row,ack_detail,obs=matching_ack[0]
    request_final=startup.get("request_stream_final_size")
    if row.get("outcome")!="controller_reduced" or ack_detail.get("source")!="native-controller-defense-elapsed-us-v1":
        raise ValueError("selected startup ACK event outcome/schema mismatch")
    if (type(obs.get("endpoint")) is not int or type(obs.get("stream")) is not int
        or type(obs.get("offset")) is not int or obs.get("type")!="stream_data_acknowledged" or obs.get("offset")!=0
        or type(obs.get("bytes")) is not int or obs.get("bytes")!=request_final or obs.get("fin") is not True
        or ack_detail.get("controller_defense_elapsed_us")!=ack_us):
        raise ValueError("selected ACK is not a full acknowledged request stream with FIN")
    if type(request_final) is not int or request_final<=0:
        raise ValueError("startup request final size is invalid")
    chaff_response=[item for item in (run.get("chaff_responses") or [])
                    if isinstance(item,dict) and item.get("resource_id")==ready_resource and item.get("request_id")==ready_request]
    if len(chaff_response)!=1 or chaff_response[0].get("request_stream_bytes")!=request_final or chaff_response[0].get("expected_request_stream_bytes")!=request_final:
        raise ValueError("ACKed stream does not map to one exact chaff request result")

    matching_ready=[]
    for t,row,detail in ready_rows:
        if (detail.get("ready_endpoint"),detail.get("ready_stream"),detail.get("ready_resource_id"),detail.get("ready_request_id"))==(
            ready_endpoint,ready_stream,ready_resource,ready_request):
            matching_ready.append((t,row,detail))
    if len(matching_ready)!=1:
        raise ValueError("selected startup request lacks exactly one startup-ready arming event")
    ready_abs,ready_row,ready_detail=matching_ready[0]
    ready_elapsed=ready_abs-defense_start_us
    if (ready_detail.get("schema_version")!=1 or ready_detail.get("armed") is not True or ready_detail.get("armed_at_us")!=arm_target
        or ready_detail.get("ack_observed_at_us")!=ack_us or ready_detail.get("ready_at_us")!=ack_us
        or ready_detail.get("policy")!="qualified-chaff-terminal-ack-cadence-start-v1"):
        raise ValueError("startup-ready event does not match pinned qualified-ACK policy")
    if len(ingress_actions)!=1:
        raise ValueError("first incoming schedule lacks exactly one matching increase_receive_limit action")
    ingress_abs,ingress_row,ingress_detail=ingress_actions[0]
    if (ingress_abs!=action_abs_us or ingress_abs<ready_abs or ingress_detail.get("endpoint")!=ready_endpoint
        or ingress_detail.get("stream")!=0 or ingress_detail.get("slot")!=slot_id
        or ingress_detail.get("packet",{}).get("length")!=1200):
        raise ValueError("startup ACK/arming does not precede the first scheduled ingress action")
    if not (ack_us<=ready_elapsed<=action_elapsed_us<=target_us):
        raise ValueError("required ACK <= actual arming <= first ingress action <= cell target ordering failed")
    if startup.get("armed") is not True or startup.get("eligible_exact_capacity_bytes",0)<1200:
        raise ValueError("startup was not armed with enough exact live-stream capacity")

    ack_cutoff_abs_us=defense_start_us+ack_us
    if abs(ack_abs-ack_cutoff_abs_us)>1000:
        raise ValueError("ACK event row and controller defense-elapsed time differ by more than 1ms")
    pre_ack=sum(amount for t,amount,_,_ in bytes_read if t<ack_cutoff_abs_us)
    pre_arm=sum(amount for t,amount,_,_ in bytes_read if t<ready_abs)
    pre_armed_target=sum(amount for t,amount,_,_ in bytes_read if t<defense_start_us+arm_target)
    pre_ingress=sum(amount for t,amount,_,_ in bytes_read if t<ingress_abs)
    if pre_ingress<=0:
        raise ValueError("valid bytes_read events are present but none precede first ingress action")
    return {
        "valid":True,"event_rows":len(rows),"bytes_read_event_count":len(bytes_read),
        "pre_ack_bytes_read":pre_ack,"pre_startup_ready_event_bytes_read":pre_arm,
        "pre_scheduled_arm_target_bytes_read":pre_armed_target,
        "pre_first_ingress_action_bytes_read":pre_ingress,
        "ack_event_monotonic_us":ack_abs,"ack_observed_defense_elapsed_us":ack_us,
        "startup_ready_event_monotonic_us":ready_abs,"startup_ready_defense_elapsed_us":ready_elapsed,
        "first_ingress_action_monotonic_us":ingress_abs,"first_ingress_action_defense_elapsed_us":action_elapsed_us,
        "first_ingress_target_us":target_us,"startup_armed_at_us":arm_target,
        "ordering":"genuine selected full-request ACK <= startup-ready arm event <= first increase_receive_limit action <= scheduled cell target",
    }


def pcap_timestamp_screen(path):
    magics = {b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
              b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000)}
    previous = None; count = 0; sorted_ok = True
    with path.open("rb") as f:
        header = f.read(24)
        if len(header) != 24 or header[:4] not in magics:
            raise ValueError("unsupported classic PCAP header")
        endian, scale = magics[header[:4]]
        if struct.unpack(endian+"I", header[20:24])[0] != 1:
            raise ValueError("PCAP link type is not Ethernet")
        while True:
            record = f.read(16)
            if not record: break
            if len(record) != 16: raise ValueError("truncated PCAP record header")
            sec, frac, caplen, origlen = struct.unpack(endian+"IIII", record)
            if caplen != origlen or caplen > 16*1024*1024: raise ValueError("truncated/oversized PCAP record")
            packet = f.read(caplen)
            if len(packet) != caplen: raise ValueError("truncated PCAP packet")
            stamp = sec + frac/scale
            if previous is not None and stamp < previous: sorted_ok = False
            previous = stamp; count += 1
    return {"packet_records": count, "timestamps_nondecreasing": sorted_ok}


def pcap_outgoing_datagrams(path, run):
    magics = {b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
              b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000)}
    result=[]
    with path.open("rb") as f:
        header=f.read(24)
        if len(header)!=24 or header[:4] not in magics: raise ValueError("unsupported PCAP header")
        endian,scale=magics[header[:4]]
        if struct.unpack(endian+"I",header[20:24])[0]!=1: raise ValueError("PCAP is not Ethernet")
        anchor=int(run["time_anchor_unix_ns"])
        endpoints=run.get("endpoints") or []
        if len(endpoints)!=1: raise ValueError("physical schedule screen requires exactly one endpoint")
        tuple_data=endpoints[0]["tuple"]
        local_host,local_port=tuple_data["local"].rsplit(":",1);remote_host,remote_port=tuple_data["remote"].rsplit(":",1)
        local=(local_host,int(local_port),remote_host,int(remote_port))
        while True:
            rh=f.read(16)
            if not rh: break
            if len(rh)!=16: raise ValueError("truncated PCAP packet record")
            sec,frac,caplen,origlen=struct.unpack(endian+"IIII",rh)
            frame=f.read(caplen)
            if caplen!=origlen or len(frame)!=caplen or len(frame)<14: raise ValueError("truncated PCAP Ethernet frame")
            et=int.from_bytes(frame[12:14],"big");off=14
            while et in (0x8100,0x88a8,0x9100):
                if len(frame)<off+4: raise ValueError("truncated VLAN header")
                et=int.from_bytes(frame[off+2:off+4],"big");off+=4
            if et==0x0800:
                if len(frame)<off+20: raise ValueError("truncated IPv4 packet")
                ihl=(frame[off]&15)*4
                if frame[off+9]!=17 or ihl<20: continue
                src=".".join(map(str,frame[off+12:off+16]));dst=".".join(map(str,frame[off+16:off+20]));uoff=off+ihl
            elif et==0x86dd:
                if len(frame)<off+40: raise ValueError("truncated IPv6 packet")
                if frame[off+6]!=17: continue
                import ipaddress
                src=str(ipaddress.ip_address(frame[off+8:off+24]));dst=str(ipaddress.ip_address(frame[off+24:off+40]));uoff=off+40
            else: continue
            if len(frame)<uoff+8: raise ValueError("truncated UDP header")
            sport,dport,ulen,_=struct.unpack("!HHHH",frame[uoff:uoff+8])
            if ulen<8 or uoff+ulen>len(frame): raise ValueError("invalid UDP length")
            direction="outgoing" if (src,sport,dst,dport)==local else "incoming" if (src,sport,dst,dport)==(local[2],local[3],local[0],local[1]) else "foreign"
            payload=frame[uoff+8:uoff+ulen]
            first=payload[0] if payload else 0
            result.append({"elapsed_us":(sec*1_000_000+frac/(scale/1_000_000)-anchor/1000),
                           "direction":direction,"udp_payload_bytes":len(payload),"quic_long_header":bool(first&0x80),"first_byte":first})
    return result

def screen_pcap_schedule(path, run, schedule_path, tolerance_us=5000):
    datagrams=pcap_outgoing_datagrams(path,run)
    outgoing_cells=sorted(int(r["target_time_us"]) for r in csv.DictReader(schedule_path.open(newline=""))
                          if r.get("direction")=="outgoing" and r.get("satisfaction")=="satisfied")
    start=int(run["defense_start_monotonic_ns"])/1000
    timed=[p for p in datagrams if p["direction"]=="outgoing" and p["udp_payload_bytes"]==1200 and not p["quic_long_header"]]
    delays=[];used=set()
    for target in outgoing_cells:
        expected=start+target
        candidates=[(p["elapsed_us"]-expected,i) for i,p in enumerate(timed)
                    if i not in used and 0<=p["elapsed_us"]-expected<=tolerance_us]
        if not candidates:
            raise ValueError("no physical 1200-byte QUIC short-header packet within the scheduled +5ms window")
        delay,index=min(candidates,key=lambda x:x[0]);used.add(index);delays.append(delay)
    if len(used)!=len(timed): raise ValueError("extra 1200-byte short-header egress is outside the schedule")
    return {"scheduled_outgoing_cells":len(outgoing_cells),"matched_physical_short_header_1200B_packets":len(used),
            "unmatched_physical_packets":len(timed)-len(used),"long_header_outgoing_packets":sum(1 for p in datagrams if p["direction"]=="outgoing" and p["quic_long_header"]),
            "unshaped_or_other_1200B_outgoing_count":sum(1 for p in datagrams if p["direction"]=="outgoing" and p["udp_payload_bytes"]==1200 and p["quic_long_header"]),
            "tolerance_us":tolerance_us,"lateness_min_us":min(delays) if delays else None,"lateness_max_us":max(delays) if delays else None,
            "lateness_p99_us":sorted(delays)[int(.99*(len(delays)-1))] if delays else None,
            "no_early_and_within_window":all(0<=d<=tolerance_us for d in delays)}

def candidate_gates(result):
    checks = {}
    def check(name, passed, evidence=None):
        checks[name] = {"passed": bool(passed), "evidence": evidence}
    run_path = OUT / "native/run.json"
    packets_path = OUT / "native/packets.csv"
    schedule_path = OUT / "native/schedule.csv"
    events_path = OUT / "native/events.csv"
    raw_pcap = OUT / "packets.pcap"
    if not all(p.is_file() for p in [run_path, packets_path, schedule_path, events_path, raw_pcap]):
        check("all_native_and_pcap_artifacts_present", False)
        return {"checks": checks, "passed": False, "acceptance_credit": False}
    run = json.loads(run_path.read_text(encoding="utf-8"))
    roster = json.loads((INPUTS/"resources.json").read_text(encoding="utf-8"))["resources"]
    responses = run.get("responses") or []
    expected = {(x.get("id"), x.get("url")) for x in roster}
    successful = {(x.get("resource_id"), x.get("url")) for x in responses
                  if x.get("complete") is True and x.get("outcome") == "succeeded"
                  and type(x.get("status")) is int and 200 <= x["status"] < 300}
    check("exact_20_resources_complete_2xx", len(roster)==20 and len(responses)==20 and successful==expected,
          {"resources":len(roster),"responses":len(responses),"successful_exact_matches":len(successful)})
    chaff = run.get("chaff_responses") or []
    mismatch_flags=("status_match","content_encoding_match","body_bytes_match","body_sha256_match","identity_verified")
    chaff_manifest=json.loads((INPUTS/"chaff-manifest.json").read_text(encoding="utf-8"))
    chaff_resource=next((x for x in chaff_manifest.get("resources",[])
                         if x.get("id")==chaff_manifest.get("selected_chaff_resource_id")),None)
    qualification=(chaff_resource or {}).get("chaff_qualification",{}).get("expected_response",{})
    def chaff_entry_ok(item):
        if not isinstance(item,dict) or any(item.get(k) is False for k in mismatch_flags): return False
        if item.get("outcome")=="succeeded":
            return item.get("complete") is True and item.get("identity_verified") is True
        if item.get("outcome")=="buflo_terminal_subcell_tail_cancelled":
            headers={k.lower():v for k,v in item.get("response_headers",[]) if isinstance(k,str) and isinstance(v,str)}
            expected_body=qualification.get("body_bytes")
            return (item.get("complete") is False and type(item.get("bytes")) is int
                    and type(expected_body) is int and 0<item["bytes"]<expected_body
                    and headers.get(":status")==str(qualification.get("status"))
                    and headers.get("content-length")==str(expected_body)
                    and headers.get("content-encoding","identity")==qualification.get("content_encoding","identity"))
        return False
    incomplete=[i for i,item in enumerate(chaff) if item.get("outcome")!="succeeded"]
    first_incomplete=incomplete[0] if incomplete else len(chaff)
    terminal_latch=(run.get("defense_diagnostics") or {}).get("buflo_terminal_subcell_latched") is True
    chaff_ok=(bool(chaff) and len(chaff)<=40 and all(chaff_entry_ok(item) for item in chaff)
              and len(incomplete)<=5 and incomplete==list(range(first_incomplete,len(chaff)))
              and (not incomplete or terminal_latch))
    check("qualified_chaff_identity_and_terminal_tail_only",chaff_ok,
          {"entries":len(chaff),"incomplete_indices":incomplete,"terminal_subcell_latched":terminal_latch,
           "selected_resource_id":chaff_manifest.get("selected_chaff_resource_id"),"expected_response":qualification,
           "only_known_terminal_tail_cancellation_allowed":True})
    endpoints = run.get("endpoints") or []
    h3 = (len(endpoints)==1 and isinstance(endpoints[0],dict)
          and endpoints[0].get("origin")=="https://www.flashscore.com.mx/"
          and endpoints[0].get("negotiated_protocol")=="h3")
    check("single_origin_http3_endpoint", h3,
          [{"origin":x.get("origin"),"negotiated_protocol":x.get("negotiated_protocol")} for x in endpoints])
    check("client_complete_exit_zero", result.get("process_exit_code")==0 and run.get("completion_status")=="complete"
          and not run.get("error") and not run.get("error_class"),
          {"exit":result.get("process_exit_code"),"completion":run.get("completion_status"),"error":run.get("error_class")})
    cfg=run.get("resolved_configuration") or {}; params=run.get("defense_parameters") or {}; diag=run.get("defense_diagnostics") or {}
    buflo=run.get("buflo_summary") or {}; d=buflo.get("diagnostics") or {}
    check("pinned_buflo_startup_and_16_byte_credit", cfg.get("defense",{}).get("kind")=="buflo"
          and cfg.get("initial_max_stream_data")==16 and cfg.get("max_stream_data_excess")==1000
          and params.get("kind")=="buflo" and params.get("sha256")==EXPECTED["params/buflo.json"],
          {"initial_max_stream_data":cfg.get("initial_max_stream_data"),"max_stream_data_excess":cfg.get("max_stream_data_excess"),"parameter_sha256":params.get("sha256")})
    check("direct_fin_reassignment_disabled", run.get("buflo_direct_fin_credit_reassignment_policy") is None,
          {"policy_present":run.get("buflo_direct_fin_credit_reassignment_policy") is not None,
           "parser_fin_permission_enabled":cfg.get("buflo_retained_parser_fin_permission") is True})
    startup=d.get("buflo_incoming_startup") or {}
    schedule=list(csv.DictReader(schedule_path.open(newline="")))
    try:
        event_evidence=strict_startup_and_bytes_read(events_path,run,startup,schedule)
        event_evidence_error=None
    except Exception as event_error:
        event_evidence=None
        event_evidence_error=repr(event_error)
    check("genuine_ack_arm_before_first_scheduled_ingress",event_evidence is not None,
          event_evidence if event_evidence is not None else {"error":event_evidence_error})
    result["startup_event_accounting"]=event_evidence
    check("no_unresolved_missed_catchup_or_partial_cells", d.get("buflo_missed_outgoing_cells")==0
          and d.get("buflo_missed_incoming_cells")==0 and d.get("buflo_outgoing_unresolved_cells")==0
          and d.get("buflo_incoming_unresolved_cells")==0 and d.get("buflo_catch_up_outgoing_cells")==0
          and d.get("buflo_catch_up_incoming_cells")==0 and d.get("buflo_partial_outgoing_cells")==0
          and d.get("buflo_full_outgoing_cells")==d.get("buflo_scheduled_outgoing_cells")
          and d.get("buflo_event_guard_triggered") is False and d.get("buflo_application_complete") is True
          and d.get("buflo_minimum_duration_reached") is True,
          {k:d.get(k) for k in ["buflo_scheduled_outgoing_cells","buflo_scheduled_incoming_cells","buflo_full_outgoing_cells","buflo_partial_outgoing_cells","buflo_missed_outgoing_cells","buflo_missed_incoming_cells","buflo_outgoing_unresolved_cells","buflo_incoming_unresolved_cells","buflo_catch_up_outgoing_cells","buflo_catch_up_incoming_cells","buflo_minimum_duration_reached"]})
    check("incoming_credit_exactly_requested_advertised_consumed", d.get("scheduled_incoming_requested_bytes")==d.get("scheduled_incoming_advertised_bytes")==d.get("scheduled_incoming_consumed_bytes")
          and d.get("scheduled_incoming_retired_bytes")==0 and d.get("scheduled_incoming_unresolved_bytes")==0,
          {k:d.get(k) for k in ["scheduled_incoming_requested_bytes","scheduled_incoming_advertised_bytes","scheduled_incoming_consumed_bytes","scheduled_incoming_retired_bytes","scheduled_incoming_unresolved_bytes"]})
    sch=collections.Counter((r.get("direction"),r.get("satisfaction")) for r in schedule)
    outgoing=[r for r in schedule if r.get("direction")=="outgoing"]
    check("every_scheduled_cell_satisfied_and_1200B_egress", bool(schedule) and all(r.get("satisfaction")=="satisfied" for r in schedule)
          and all(r.get("size")=="1200" and r.get("observed_size")=="1200" for r in outgoing)
          and sch.get(("outgoing","satisfied"),0)==d.get("buflo_scheduled_outgoing_cells")
          and sch.get(("incoming","satisfied"),0)==d.get("buflo_scheduled_incoming_cells"),
          {"schedule_rows":len(schedule),"states":{f"{k[0]}:{k[1]}":v for k,v in sch.items()},"outgoing_sizes":dict(collections.Counter(r.get("observed_size") for r in outgoing))})
    packet_rows=list(csv.DictReader(packets_path.open(newline="")))
    unscheduled=[r for r in packet_rows if r.get("direction")=="outgoing" and (not r.get("scheduled_target") or r.get("send_policy")=="unscheduled")]
    fields=["application_stream_bytes","retransmission_stream_bytes","chaff_stream_bytes","defense_control_bytes","quic_padding_bytes","other_quic_bytes"]
    try:
        comps={key:0 for key in fields}
        for index,row in enumerate(unscheduled,1):
            for key in fields:
                raw=row.get(key)
                if not isinstance(raw,str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)",raw):
                    raise ValueError(f"unscheduled packet {index} has missing or malformed {key}")
                comps[key]+=int(raw)
        composition_error=None
    except Exception as composition_exc:
        comps=None
        composition_error=repr(composition_exc)
    check("unscheduled_egress_has_no_application_or_chaff_stream_bytes",comps is not None
          and comps["application_stream_bytes"]==0 and comps["retransmission_stream_bytes"]==0 and comps["chaff_stream_bytes"]==0,
          {"count":len(unscheduled),"composition_bytes":comps,"error":composition_error,
           "numeric_policy":"every byte field must be explicitly present and a canonical nonnegative integer"})
    first_in=None if event_evidence is None else event_evidence["first_ingress_action_monotonic_us"]
    prescheduled=None if event_evidence is None else event_evidence["pre_first_ingress_action_bytes_read"]
    check("valid_nonempty_bytes_read_accounting",event_evidence is not None
          and type(prescheduled) is int and prescheduled>=0
          and type(event_evidence.get("bytes_read_event_count")) is int
          and event_evidence.get("bytes_read_event_count")>0,
          {"pre_ack_bytes_read":None if event_evidence is None else event_evidence["pre_ack_bytes_read"],
           "pre_startup_ready_event_bytes_read":None if event_evidence is None else event_evidence["pre_startup_ready_event_bytes_read"],
           "pre_scheduled_arm_target_bytes_read":None if event_evidence is None else event_evidence["pre_scheduled_arm_target_bytes_read"],
           "pre_first_ingress_action_bytes_read":prescheduled,"first_ingress_action_us":first_in,
           "bytes_read_event_count":None if event_evidence is None else event_evidence["bytes_read_event_count"],
           "fixed_empirical_ceiling":False,
           "scientific_note":"Client-only startup traffic is unshaped and non-paper-equivalent. Require complete valid event accounting and preserve exact per-run byte counts; do not infer zero startup traffic or apply the obsolete 16,567-byte diagnostic ceiling."})
    # Raw PCAP remains immutable. If timestamps are out of order, reorder only a copy before tuple filtering.
    pcap_source=raw_pcap
    timestamp_info=pcap_timestamp_screen(pcap_source)
    pcap_multiset_before=pcap_packet_multiset_signature(raw_pcap)
    if not timestamp_info["timestamps_nondecreasing"]:
        reorder=shutil.which("reordercap")
        if reorder is None:
            check("pcap_timestamp_order",False,{**timestamp_info,"reordercap_available":False})
            check("pcap_reorder_preserves_timestamp_packet_multiset",False,{"reason":"reordercap unavailable"})
        else:
            pcap_source=OUT/"capture-reordered.pcap"
            subprocess.run([reorder,str(raw_pcap),str(pcap_source)],check=True,timeout=60)
            timestamp_info=pcap_timestamp_screen(pcap_source)
            pcap_multiset_after=pcap_packet_multiset_signature(pcap_source)
            preserved=(pcap_multiset_before==pcap_multiset_after)
            check("pcap_timestamp_order",timestamp_info["timestamps_nondecreasing"],{**timestamp_info,"reordered_copy":str(pcap_source)})
            check("pcap_reorder_preserves_timestamp_packet_multiset",preserved,
                  {"original":pcap_multiset_before,"reordered":pcap_multiset_after})
    else:
        check("pcap_timestamp_order",True,timestamp_info)
        check("pcap_reorder_preserves_timestamp_packet_multiset",True,{"not_reordered":True,"original":pcap_multiset_before})
    if sha256(TUPLE_MODULE)!=TUPLE_MODULE_SHA:
        check("exact_endpoint_tuple_isolation",False,{"reason":"pinned tuple module changed"})
    else:
        spec=importlib.util.spec_from_file_location("tuple_isolation_per_endpoint",TUPLE_MODULE)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        tuple_result=module.analyze(pcap_source,run,packets_path,output=OUT/"capture-isolated.pcap",expected_sha256=sha256(pcap_source))
        readback=module.analyze(OUT/"capture-isolated.pcap",run,packets_path,expected_sha256=tuple_result["filtered_classic_sha256"])
        exact=(tuple_result.get("native_direction_length_coverage")=="passed" and readback.get("native_direction_length_coverage")=="passed"
               and tuple_result.get("foreign_packets_removed")==0 and readback.get("foreign_packets_removed")==0
               and tuple_result.get("original_packets")==tuple_result.get("retained_packets")==readback.get("original_packets"))
        check("exact_endpoint_tuple_isolation",exact,{"screen":tuple_result,"readback":readback})
        result["tuple_packet_screen"]=tuple_result
        # Current ledger is read-only and supplies tuple de-duplication only; no reservation or commit.
        snapshot=json.loads((OUT/"tuple-ledger-readonly-snapshot.json").read_text(encoding="utf-8"))
        history=wtfpad_history_tuple_keys()
        ledger_prior=set(snapshot.get("tuple_keys",[])); historical=set(history["tuple_keys"]); new=[]
        for endpoint in run.get("endpoints") or []:
            t=endpoint["tuple"]; local=t["local"].rsplit(":",1); remote=t["remote"].rsplit(":",1)
            key=json.dumps(["udp",local[0],int(local[1]),remote[0],int(remote[1])],separators=(",",":"))
            new.append(key)
        ledger_collisions=sorted(set(new)&ledger_prior)
        history_collisions=sorted(set(new)&historical)
        check("native_tuples_exclude_ledger_and_prior_wtfpad_history",bool(new) and not ledger_collisions and not history_collisions,
              {"candidate_tuples":new,"prior_ledger_tuple_count":len(ledger_prior),
               "prior_wtfpad_committed_slots":history["committed_slots"],
               "prior_wtfpad_reserved_tuple_count":history["reserved_tuple_count"],
               "ledger_collisions":ledger_collisions,"wtfpad_history_collisions":history_collisions,
               "ledger_read_only":True,"wtfpad_history_sha256":history["sha256"]})
        rechecks=result.get("slot_ledger_rechecks") or {}
        pre=rechecks.get("immediately_before_client") or {}; post=rechecks.get("after_client_before_any_import") or {}
        candidate_keys=[]
        for endpoint in run.get("endpoints") or []:
            t=endpoint["tuple"]; local=t["local"].rsplit(":",1); remote=t["remote"].rsplit(":",1)
            candidate_keys.append(json.dumps(["udp",local[0],int(local[1]),remote[0],int(remote[1])],separators=(",",":")))
        post_keys=set(post.get("tuple_keys") or [])
        check("read_only_slot_and_tuple_rechecks_still_clear",
              pre.get("valid") is True and post.get("valid") is True
              and pre.get("slot_occupied_or_pending") is False and post.get("slot_occupied_or_pending") is False
              and bool(candidate_keys) and not (set(candidate_keys)&post_keys),
              {"slot":CURRENT_SLOT,"immediately_before_client":pre,"after_client_before_commit":post,
               "candidate_keys_absent_from_current_tuple_set":bool(candidate_keys) and not (set(candidate_keys)&post_keys)})
        result["tuple_packet_screen"]=tuple_result
        physical=screen_pcap_schedule(pcap_source,run,schedule_path,tolerance_us=5000)
        check("physical_pcap_egress_matches_64ms_1200B_schedule",physical.get("no_early_and_within_window") is True
              and physical.get("scheduled_outgoing_cells")==physical.get("matched_physical_short_header_1200B_packets"),physical)
        result["physical_pcap_schedule_screen"]=physical
        # Record known capture/native row delta. It is not silently treated as application data.
        result["pcap_native_row_delta"] = tuple_result.get("original_packets",0)-tuple_result.get("native_rows",0)
    try:
        tcpdump=(OUT/"tcpdump.log").read_text(encoding="utf-8",errors="replace")
        captured=int(re.search(r"(?m)^(\d+) packets captured$",tcpdump).group(1))
        received=int(re.search(r"(?m)^(\d+) packets received by filter$",tcpdump).group(1))
        dropped=int(re.search(r"(?m)^(\d+) packets dropped by kernel$",tcpdump).group(1))
        pcount=timestamp_info["packet_records"]
        capture_ok=captured==received==pcount and dropped==0
        check("complete_pcap_zero_capture_drops",capture_ok,{"captured":captured,"received":received,"pcap_records":pcount,"dropped":dropped})
    except Exception as e:
        check("complete_pcap_zero_capture_drops",False,{"error":repr(e)})
    check("qdisc_credential_client_terminal_and_cleanup_contract",result.get("qdisc_setup",{}).get("valid") is True
          and result.get("credential_preflight",{}).get("valid") is True
          and result.get("client_wait_supervision",{}).get("container_client_absent") is True
          and result.get("client_wait_supervision",{}).get("collector_running_at_client_exit") is True
          and result.get("client_wait_supervision",{}).get("collector_failure_reported") is False
          and result.get("container_absent_after_cleanup") is True
          and result.get("network_empty_after") is True and result.get("mutating_request_pending") is False,
          {"qdisc_valid":result.get("qdisc_setup",{}).get("valid"),"credential_valid":result.get("credential_preflight",{}).get("valid"),
           "container_client_absent":result.get("client_wait_supervision",{}).get("container_client_absent"),
           "collector_running_at_client_exit":result.get("client_wait_supervision",{}).get("collector_running_at_client_exit"),
           "collector_failure_reported":result.get("client_wait_supervision",{}).get("collector_failure_reported"),
           "container_absent":result.get("container_absent_after_cleanup"),"network_empty":result.get("network_empty_after"),"pending":result.get("mutating_request_pending")})
    # No official final, accepted-session record, shared-ledger update, or Drive upload is ever produced here.
    passed=bool(checks) and all(v.get("passed") for v in checks.values())
    return {"checks":checks,"passed":passed,"candidate_ready_for_independent_review":passed,
            "accepted_session":False,"capture_credit":False,"session_ledger_write":False,"drive_upload":False}


def production_tuple_keys(run):
    keys=[]
    for endpoint in run.get("endpoints") or []:
        t=endpoint["tuple"]
        if t.get("protocol")!="udp": raise ValueError("production endpoint is not UDP")
        local=t["local"].rsplit(":",1); remote=t["remote"].rsplit(":",1)
        key=json.dumps(["udp",local[0],int(local[1]),remote[0],int(remote[1])],separators=(",",":"))
        keys.append(validate_native_tuple_key(key))
    if not keys or len(keys)!=len(set(keys)):
        raise ValueError("production run lacks unique canonical endpoint tuples")
    return keys


def commit_accepted(result, intent):
    """Publish local FINAL then atomically commit this one session and its tuples."""
    if result.get("owner_gate",{}).get("passed") is not True:
        raise RuntimeError("capture did not pass all candidate gates")
    run=json.loads((OUT/"native/run.json").read_text(encoding="utf-8"))
    keys=production_tuple_keys(run)
    history=wtfpad_history_tuple_keys()
    current=ledger_readonly_state()
    verify_slot_and_tuple_snapshot(current,history)
    if set(keys)&set(current["tuple_keys"]):
        raise RuntimeError("fresh transactional-preflight found a native tuple collision")
    if set(keys)&set(history["tuple_keys"]):
        raise RuntimeError("fresh WTF-PAD tuple history collision")
    if (TUPLE_MODULE.is_symlink() or sha256(TUPLE_MODULE)!=TUPLE_MODULE_SHA
            or pathlib.Path(CONFIG["ledger_module"]).is_symlink()
            or sha256(pathlib.Path(CONFIG["ledger_module"]))!=CONFIG["ledger_module_sha256"]):
        raise RuntimeError("pinned ledger or tuple module changed before commit")
    ledger=load_pinned_module(pathlib.Path(CONFIG["ledger_module"]),CONFIG["ledger_module_sha256"])
    db=ledger.open_ledger(TUPLE_DB,mode="buflo",config_sha=CAPTURE_PROFILE_SHA,
                          coverage_sha=CONFIG["coverage_sha256"],history_sha=CONFIG["history_sha256"])
    try:
        ledger.reserve(db,mode="buflo",slot=CURRENT_SLOT,attempt=ATTEMPT_ID,
                       keys=keys,excluded=set(history["tuple_keys"]))
        files={}
        for path in sorted(OUT.rglob("*")):
            if path.is_symlink(): raise RuntimeError("symlink in production capture output")
            if path.is_file() and path.name not in ("FINAL.json",".FINAL.tmp","runner.lock"):
                files[str(path.relative_to(OUT))]={"sha256":sha256(path),"size":path.stat().st_size}
        analysis_hash=sha256(RESULT)
        source_note={
            "policy":"qualified-chaff-terminal-ack-observation-arm-v1",
            "initial_max_stream_data":16,
            "buflo_interval_us":64000,
            "direct_fin_credit_reassignment":False,
            "parser_fin_permission":True,
            "client_only":True,
            "paper_equivalent":False,
            "source_patch_sha256":CONFIG["source_patch_sha256"],
            "controller_sha256":CONFIG["controller_sha256"],
            "pre_ack_and_pre_schedule_bytes_read":result.get("startup_event_accounting"),
        }
        final={
            "schema_version":1,"kind":"qcsd-accepted-session-final","hostname":"www.flashscore.com.mx",
            "mode":"buflo","defense":"buflo","slot":CURRENT_SLOT,"attempt_id":ATTEMPT_ID,
            "status":"success","purpose":"production","accepted_session":True,"capture_credit":True,
            "drive_upload":False,"timestamp_utc":utc_now(),"request_id":REQUEST_ID,
            "session_seed":SESSION_SEED,
            "capture_profile_sha256":CAPTURE_PROFILE_SHA,"owner_script_sha256":sha256(pathlib.Path(__file__)),
            "ownership_sha256":sha256(CONFIG_PATH),"coverage_sha256":CONFIG["coverage_sha256"],
            "history_sha256":CONFIG["history_sha256"],"note_sha256":CONFIG["note_sha256"],
            "driver_sha256":sha256(pathlib.Path(__file__)),
            "native_client_sha256":BINARY_SHA,"runtime_image":RUNTIME_IMAGE,
            "input_sha256":EXPECTED,"source_input_sha256":SOURCE_EXPECTED,
            "resource_roster_sha256":EXPECTED["resources.json"],"resource_count":20,
            "successful_responses":20,"required_responses":20,"negotiated_protocol":"h3",
            "paper_equivalent":False,"capture_policy_provenance":source_note,
            "startup_event_accounting":result.get("startup_event_accounting"),
            "defense_gate_summary":result.get("owner_gate"),
            "tuple_keys":keys,"wtfpad_history_sha256":history["sha256"],
            "native_tuple_keys":keys,"tuple_verifier_sha256":TUPLE_MODULE_SHA,
            "network_id":NETWORK["id"],"network_subnet":NETWORK["subnet"],
            "network_manifest_sha256":NET_MANIFEST_SHA,"network_worker_ip":result.get("worker_ip"),
            "pcap_raw_sha256":sha256(OUT/"packets.pcap"),
            "pcap_clean":"capture-isolated.pcap","pcap_clean_sha256":sha256(OUT/"capture-isolated.pcap"),
            "pcap_record_count":(result.get("tuple_packet_screen") or {}).get("original_packets"),
            "capture_packets_reported":(result.get("owner_gate",{}).get("checks",{}).get("complete_pcap_zero_capture_drops",{}).get("evidence") or {}).get("captured"),
            "capture_filter_received":(result.get("owner_gate",{}).get("checks",{}).get("complete_pcap_zero_capture_drops",{}).get("evidence") or {}).get("received"),
            "capture_kernel_dropped":(result.get("owner_gate",{}).get("checks",{}).get("complete_pcap_zero_capture_drops",{}).get("evidence") or {}).get("dropped"),
            "native_packet_rows":(result.get("tuple_packet_screen") or {}).get("native_rows"),
            "packet_count_screen_passed":True,"tuple_packet_screen":result.get("tuple_packet_screen"),
            "physical_schedule_screen":result.get("physical_pcap_schedule_screen"),
            "ledger_before_commit_tuple_set_sha256":current["tuple_set_sha256"],
            "analysis_file":"CAPTURE-ANALYSIS.json","analysis_sha256":analysis_hash,
            "source_role":"mx-buflo-production-recapture","mode_evidence":"native/run.json",
            "files":files,
        }
        atomic_json(OUT/"FINAL.json",final)
        final_sha=sha256(OUT/"FINAL.json")
        ledger.commit(db,mode="buflo",slot=CURRENT_SLOT,attempt=ATTEMPT_ID,final_sha=final_sha)
        row=db.execute("SELECT final_sha,state FROM sessions WHERE mode='buflo' AND slot=?",(CURRENT_SLOT,)).fetchone()
        tuple_rows=db.execute("SELECT k,final_sha,state FROM tuples WHERE mode='buflo' AND slot=? AND attempt=? ORDER BY k",(CURRENT_SLOT,ATTEMPT_ID)).fetchall()
        if row!=(final_sha,"committed") or {x[0] for x in tuple_rows}!=set(keys) or any(x[1:]!=(final_sha,"committed") for x in tuple_rows):
            raise RuntimeError("ledger post-commit readback differs from FINAL and endpoint tuple set")
    finally:
        db.close()
    return final_sha


def store_not_started_final(result):
    """Seal a pre-request owner failure without awarding slot or tuple credit."""
    if (OUT/"FINAL.json").exists():
        raise RuntimeError("cannot overwrite an existing attempt FINAL")
    files={}
    for path in sorted(OUT.rglob("*")):
        if path.is_symlink(): raise RuntimeError("symlink in unstarted attempt output")
        if path.is_file() and path.name not in ("FINAL.json",".FINAL.tmp","runner.lock"):
            files[str(path.relative_to(OUT))]={"sha256":sha256(path),"size":path.stat().st_size}
    record={"schema_version":1,"kind":"qcsd-unstarted-attempt-final","hostname":"www.flashscore.com.mx",
            "mode":"buflo","defense":"buflo","slot":CURRENT_SLOT,"attempt_id":ATTEMPT_ID,
            "status":"not_started","purpose":"production","accepted_session":False,"capture_credit":False,
            "session_ledger_write":False,"drive_upload":False,"request_id":REQUEST_ID,
            "capture_profile_sha256":CAPTURE_PROFILE_SHA,"paper_equivalent":False,
            "client_exec_submitted":False,"reason":result.get("error"),"files":files}
    atomic_json(OUT/"FINAL.json",record)

def main():
    global ROOT, PRODUCTION_DIR, PROFILE_INPUTS, OUT, HOST, ORIGINAL_INPUTS, INPUTS, BINARY, NET_MODULE, NET_MANIFEST
    global RUNTIME_IMAGE, CONTAINER, EXPECTED, SOURCE_EXPECTED, CONFIG_PATH, CONFIG_SHA_FILE, TUPLE_MODULE
    global TUPLE_DB, JOURNAL, STATE, RESULT, LOCK, MODE_OWNER_LOCK, CURRENT_SLOT, ATTEMPT_ID, REQUEST_ID
    global CAPTURE_PROFILE_SHA, SESSION_SEED, CONFIG, LEDGER, CLIENT_EXEC_SUBMITTED_GLOBAL
    parser = argparse.ArgumentParser(description="single-attempt MX BuFLO production owner; commits only after all gates pass")
    parser.add_argument("--execute-reviewed-attempt", action="store_true")
    args = parser.parse_args()
    if not args.execute_reviewed_attempt:
        print("review-only owner; no network action without --execute-reviewed-attempt", file=sys.stderr)
        return 64
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    config_sha = CONFIG_SHA_FILE.read_text(encoding="ascii").strip()
    if sha256(CONFIG_PATH) != config_sha or config.get("owner_script_sha256") != sha256(pathlib.Path(__file__)):
        raise RuntimeError("owner config/code pin mismatch")
    if config.get("execution_enabled") is not True or config.get("independent_review_state") != "approved":
        print("independent review has not enabled this production profile", file=sys.stderr)
        return 65
    if config.get("kind") != "mx-buflo-production-owner-config" or config.get("mode") != "buflo" or config.get("hostname") != "www.flashscore.com.mx":
        raise RuntimeError("production owner configuration identity mismatch")
    if config.get("drive_upload") is not False or config.get("paper_equivalent") is not False:
        raise RuntimeError("production profile must remain local and accurately marked non-paper-equivalent")
    CONFIG = config
    ROOT = pathlib.Path(config["root"])
    PRODUCTION_DIR = ROOT / "diagnostics/mx-buflo-production-owner-001"
    PROFILE_INPUTS = pathlib.Path(config["profile_inputs"])
    HOST = pathlib.Path(config["host_root"])
    ORIGINAL_INPUTS = pathlib.Path(config["source_inputs"])
    BINARY = pathlib.Path(config["binary"])
    NET_MODULE = pathlib.Path(config["network_module"])
    NET_MANIFEST = pathlib.Path(config["network_manifest"])
    RUNTIME_IMAGE = config["runtime_image"]
    TUPLE_MODULE = pathlib.Path(config["tuple_module"])
    TUPLE_DB = pathlib.Path(config["ledger"])
    MODE_OWNER_LOCK = HOST / "modes/buflo/production-owner.lock"
    EXPECTED = config["input_sha256"]
    SOURCE_EXPECTED = config["source_input_sha256"]
    CAPTURE_PROFILE_SHA = config["capture_profile_sha256"]
    if config.get("network") != NETWORK or config.get("binary_sha256") != BINARY_SHA or config.get("runtime_image") != "sha256:ee315c35752eac8687148c0b718cfd85bfa0e82d1433a880d5dfeb4d55bec6b6":
        raise RuntimeError("production binary, image, or network pin mismatch")
    lane_runner=PRODUCTION_DIR/"run_mx_buflo_lane.sh"
    if lane_runner.is_symlink() or sha256(lane_runner)!=config["lane_runner_sha256"]:
        raise RuntimeError("reusable lane supervisor changed from its reviewed pin")
    if sha256(pathlib.Path(config["capture_profile"])) != CAPTURE_PROFILE_SHA:
        raise RuntimeError("capture profile changed from its pinned hash")
    if sha256(TUPLE_MODULE) != TUPLE_MODULE_SHA:
        raise RuntimeError("pinned tuple-isolation module hash changed")
    if MODE_OWNER_LOCK.is_symlink() or not MODE_OWNER_LOCK.is_file():
        raise RuntimeError("mode-wide production owner lock is missing or unsafe")
    mode_lock_stream = MODE_OWNER_LOCK.open("a+")
    try:
        fcntl.flock(mode_lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("another BuFLO owner holds the mode-wide production lock; refusing duplicate work", file=sys.stderr)
        return 19
    pre_db = sqlite3.connect("file:" + str(TUPLE_DB) + "?mode=ro", uri=True, timeout=10)
    try:
        meta = dict(pre_db.execute("SELECT k,v FROM meta").fetchall())
        if meta.get("config:buflo") != CAPTURE_PROFILE_SHA:
            raise RuntimeError("BuFLO mode config-pin migration is not yet applied")
        pending = pre_db.execute("SELECT slot,attempt FROM sessions WHERE mode='buflo' AND state!='committed'").fetchall()
        if pending:
            raise RuntimeError("BuFLO has pending capture reservations requiring reconciliation")
        verify_existing_buflo_history(pre_db, config)
        existing_slots = {row[0] for row in pre_db.execute("SELECT slot FROM sessions WHERE mode='buflo'")}
    finally:
        pre_db.close()
    CURRENT_SLOT = next((n for n in range(1, 401) if n not in existing_slots), 401)
    if CURRENT_SLOT > 400:
        print(json.dumps({"status":"complete","committed_slots":400}), flush=True)
        return 2
    ATTEMPT_ID = secrets.token_hex(16)
    CLIENT_EXEC_SUBMITTED_GLOBAL = False
    SESSION_SEED = int.from_bytes(hashlib.sha256((CAPTURE_PROFILE_SHA+ATTEMPT_ID).encode()).digest()[:8],"big")
    REQUEST_ID = f"mx-buflo-production-slot{CURRENT_SLOT:03d}-request-{ATTEMPT_ID}"
    CONTAINER = f"mx-buflo-production-slot{CURRENT_SLOT:03d}-container-{ATTEMPT_ID}"
    OUT = HOST / "modes/buflo/attempts/www.flashscore.com.mx" / ATTEMPT_ID
    INPUTS = OUT / "inputs"
    JOURNAL = OUT / "journal.jsonl"
    STATE = OUT / "state.json"
    RESULT = OUT / "CAPTURE-ANALYSIS.json"
    LOCK = OUT / "runner.lock"
    OUT.mkdir(mode=0o700, parents=True, exist_ok=False)
    shutil.copytree(PROFILE_INPUTS, INPUTS)
    os.chmod(OUT, 0o770)
    os.chmod(INPUTS, 0o750)
    os.chmod(INPUTS / "params", 0o750)
    atomic_json(OUT / "INTENT.json", {
        "kind":"mx-buflo-production-capture-intent","attempt_id":ATTEMPT_ID,"slot":CURRENT_SLOT,
        "request_id":REQUEST_ID,"capture_credit":True,"drive_upload":False,
        "capture_profile_sha256":CAPTURE_PROFILE_SHA,"paper_equivalent":False})
    lock_stream = LOCK.open("a+")
    try:
        fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("another runner process owns this request; refusing duplicate work", file=sys.stderr)
        return 20
    if JOURNAL.exists() or RESULT.exists():
        print("journal/result already exists; this request is one-shot and will not be replayed", file=sys.stderr)
        return 21
    journal("mode_wide_owner_lock_acquired", path=str(MODE_OWNER_LOCK), held_until_process_exit=True)

    intent = verify_inputs()
    prior_tuples = ledger_readonly_state()
    history=wtfpad_history_tuple_keys()
    verify_slot_and_tuple_snapshot(prior_tuples,history)
    atomic_json(OUT / "tuple-ledger-readonly-snapshot.json", prior_tuples)
    network_policy = load_network_policy()
    if subprocess.run(["docker", "inspect", CONTAINER], capture_output=True, timeout=10).returncode == 0:
        raise RuntimeError("unique diagnostic container name already exists")
    network_policy.inspect_network("buflo", NETWORK, None)

    journal("request_preflight_complete", input_hashes=EXPECTED, binary_sha256=BINARY_SHA,
            network=NETWORK, active_network_expected_empty=True, container_name=CONTAINER,
            mode_wide_owner_lock=str(MODE_OWNER_LOCK),
            tuple_ledger_read_only_snapshot_sha256=sha256(OUT/"tuple-ledger-readonly-snapshot.json"),
            tuple_set_sha256=prior_tuples["tuple_set_sha256"],
            wtfpad_history_sha256=history["sha256"],
            wtfpad_excluded_tuple_count=len(history["tuple_keys"]),
            slot_occupied_or_pending=prior_tuples["slot_occupied_or_pending"])
    result = {
        "kind": "mx-buflo-production-capture-analysis",
        "request_id": intent["request_id"],
        "capture_credit": False,
        "accepted_session": False,
        "session_ledger_write": False,
        "drive_upload": False,
        "production_binary_replaced": False,
        "owner_runner_used": False,
        "binary_sha256": BINARY_SHA,
        "runtime_image": RUNTIME_IMAGE,
        "network": NETWORK,
        "container_name": CONTAINER,
        "session_seed": SESSION_SEED,
        "completion_status": None,
        "direct_fin_releases": [],
        "error": None,
    }

    container_id = None
    container_started = False
    docker_mutation_pending = False
    qdisc_exec_submitted = False
    qdisc_exec_completed = False
    preflight_exec_submitted = False
    preflight_exec_completed = False
    preflight_process = None
    client_exec_submitted = False
    client_exec_completed = False
    client_process = None
    client_log_stream = None
    capture = None
    capture_log_stream = None
    create_log = OUT / "docker-create.log"
    start_log = OUT / "docker-start.log"
    remove_log = OUT / "docker-remove.log"
    qdisc_setup_log = OUT / "qdisc-setup.log"
    preflight_log = OUT / "credential-preflight.log"
    client_log = OUT / "client.log"
    tcpdump_log = OUT / "tcpdump.log"
    pcap = OUT / "packets.pcap"
    native = OUT / "native"
    native.mkdir(mode=0o770, exist_ok=False)
    os.chmod(native, 0o770)

    try:
        create_argv = [
            "docker", "create", "--name", CONTAINER, "--network", NETWORK["name"],
            "--cpuset-cpus", "4-5", "--memory", "3g", "--group-add", "1000", "--cap-drop", "ALL",
            "--cap-add", "NET_ADMIN", "--cap-add", "SETPCAP",
            "--cap-add", "SETUID", "--cap-add", "SETGID",
            "--security-opt", "no-new-privileges:true", "--ulimit", "rtprio=1:1",
            "--mount", "type=bind,src=" + str(INPUTS) + ",dst=/inputs,readonly",
            "--mount", "type=bind,src=" + str(BINARY) + ",dst=/tmp/neqo-qcsd-client,readonly",
            "--mount", "type=bind,src=" + str(MODEL) + ",dst=/model.json,readonly",
            "--mount", "type=bind,src=" + str(OUT) + ",dst=/diagnostic",
            "--entrypoint", "/bin/sleep", RUNTIME_IMAGE, "infinity",
        ]
        code, pid = mutation_once("docker_create", create_argv, 180, create_log)
        result["docker_create_returncode"] = code
        result["docker_create_pid"] = pid
        if code is None:
            result["error"] = "docker create response uncertain; no start request issued"
            docker_mutation_pending = True
            result["terminal"] = False
            return 22
        if code != 0:
            result["error"] = "docker create returned nonzero; no start request issued"
            result["docker_create_output"] = command_line_log(create_log)
            result["terminal"] = True
            return 23
        match = re.search(r"\b([0-9a-f]{64})\b", command_line_log(create_log))
        if not match:
            result["error"] = "docker create returned success without a parseable container ID; no start request issued"
            result["docker_create_output"] = command_line_log(create_log)
            result["terminal"] = False
            return 24
        container_id = match.group(1)
        result["container_id"] = container_id
        journal("docker_create_id_recorded", container_id=container_id)
        created = inspect_container(container_id)
        if created["State"]["Status"] != "created" or created["State"]["Pid"] != 0:
            result["error"] = "created container is not in the expected unstarted state; no start request issued"
            result["create_state"] = created["State"]
            result["terminal"] = True
            return 25
        network_policy.inspect_network("buflo", NETWORK, None)
        journal("docker_create_state_verified", container_id=container_id, status="created", pid=0,
                network_endpoint_attached=False)

        start_code, start_pid = mutation_once("docker_start", ["docker", "start", container_id], 180, start_log)
        result["docker_start_returncode"] = start_code
        result["docker_start_pid"] = start_pid
        if start_code is None:
            result["error"] = "docker start response uncertain; do not issue another start or client exec"
            docker_mutation_pending = True
            result["terminal"] = False
            return 26
        if start_code != 0:
            result["error"] = "docker start returned nonzero; do not retry start"
            result["docker_start_output"] = command_line_log(start_log)
            result["terminal"] = True
            return 27
        container_started = True
        running = inspect_container(container_id)
        if running["State"]["Status"] != "running" or running["State"]["Pid"] <= 0:
            result["error"] = "docker start returned success but container is not running; no client exec issued"
            result["start_state"] = running["State"]
            result["terminal"] = False
            return 28
        network_policy.inspect_network("buflo", NETWORK, running["Id"])
        worker_ip = network_policy.inspect_container("buflo", NETWORK, container_id)
        result["worker_ip"] = worker_ip
        result["container_pid"] = running["State"]["Pid"]
        journal("docker_start_state_verified", container_id=container_id, status="running",
                pid=running["State"]["Pid"], worker_ip=worker_ip)

        qdisc_shell = (
            "set -eu; "
            "before=$(tc -j -d qdisc show dev eth0); "
            "tc qdisc replace dev eth0 root handle 1: prio bands 2 priomap 1 1 1 1 1 1 0 1 1 1 1 1 1 1 1 1; "
            "tc qdisc replace dev eth0 parent 1:1 handle 20: etf clockid TAI delta 10000000; "
            "tc qdisc replace dev eth0 parent 1:2 handle 10: pfifo limit 1000; "
            "after=$(tc -j -d qdisc show dev eth0); "
            "printf '{\"before\":%s,\"after\":%s}\n' \"$before\" \"$after\""
        )
        qdisc_argv = ["docker", "exec", container_id, "/bin/sh", "-c", qdisc_shell]
        journal("qdisc_setup_requested", argv=qdisc_argv,
                expected_contract="buflo-eth0-prio-etf-pfifo-v1", no_client_request_yet=True)
        qdisc_exec_submitted = True
        qdisc_code, qdisc_pid = mutation_once("qdisc_setup", qdisc_argv, 60, qdisc_setup_log)
        result["qdisc_setup_pid"] = qdisc_pid
        result["qdisc_setup_returncode"] = qdisc_code
        result["qdisc_setup_log"] = str(qdisc_setup_log)
        if qdisc_code is None:
            docker_mutation_pending = True
            result["error"] = "qdisc setup response uncertain; no client request issued"
            result["terminal"] = False
            return 29
        qdisc_exec_completed = True
        if qdisc_code != 0:
            result["error"] = "qdisc setup command failed; no client request issued"
            result["qdisc_setup_output"] = command_line_log(qdisc_setup_log)
            result["terminal"] = True
            return 30
        try:
            qdisc_evidence = validate_qdisc_readback(command_line_log(qdisc_setup_log))
        except Exception as error:
            result["error"] = "qdisc readback did not match the required contract: " + repr(error)
            result["qdisc_setup_output"] = command_line_log(qdisc_setup_log)
            result["terminal"] = True
            return 31
        result["qdisc_setup"] = qdisc_evidence
        result["qdisc_setup_log_sha256"] = sha256(qdisc_setup_log)
        journal("qdisc_setup_verified", log_sha256=result["qdisc_setup_log_sha256"],
                before=qdisc_evidence["before"], after=qdisc_evidence["after"],
                contract=qdisc_evidence["contract"])

        preflight_argv = [
            "docker", "exec",
            "--env", "QCSD_CAPTURE_SCHEDULER_CONTRACT=qcsd-client-rr1-portable-etf-helper-v3",
            "--env", "QCSD_CAPTURE_CLIENT_CPU=4",
            "--env", "QCSD_CAPTURE_ORCHESTRATOR_CPU=5",
            "--env", "QCSD_CAPTURE_ETF_INTERFACE=eth0",
            container_id, "taskset", "-c", "4", "chrt", "-r", "1",
            "setpriv", "--reuid=503", "--regid=1000", "--clear-groups",
            "--inh-caps=+net_admin,+setpcap", "--ambient-caps=+net_admin,+setpcap",
            "/bin/sh", "-c",
            "id; grep -E '^(Uid|Gid|CapEff|NoNewPrivs|Cpus_allowed_list):' /proc/self/status; "
            "cat /sys/fs/cgroup/cpuset.cpus.effective; grep 'Max realtime priority' /proc/self/limits; "
            "chrt -p $$; taskset -pc $$",
        ]
        journal("credential_preflight_intent", argv=preflight_argv,
                network_client_not_started=True, no_external_request_expected=True)
        preflight_exec_submitted = True
        preflight_log_stream = preflight_log.open("xb")
        try:
            preflight_process = subprocess.Popen(
                preflight_argv, stdin=subprocess.DEVNULL, stdout=preflight_log_stream,
                stderr=subprocess.STDOUT, start_new_session=True,
            )
        except Exception as error:
            journal("credential_preflight_launch_failed", error=repr(error))
            raise
        journal("credential_preflight_process_started", pid=preflight_process.pid)
        preflight_deadline = time.monotonic() + 15
        while preflight_process.poll() is None and time.monotonic() < preflight_deadline:
            time.sleep(0.1)
        preflight_log_stream.flush()
        os.fsync(preflight_log_stream.fileno())
        preflight_log_stream.close()
        if preflight_process.poll() is None:
            journal("credential_preflight_wait_bound_elapsed", pid=preflight_process.pid,
                    action="do_not_kill_or_run_client")
            result["error"] = "credential preflight still in flight; no client request issued"
            result["terminal"] = False
            result["credential_preflight_log"] = str(preflight_log)
            return 30
        preflight_exec_completed = True
        preflight_text = command_line_log(preflight_log)
        preflight_valid = (
            preflight_process.returncode == 0
            and re.search(r"uid=503\b", preflight_text)
            and re.search(r"gid=1000\b", preflight_text)
            and re.search(r"CapEff:\s*0000000000001100", preflight_text)
            and re.search(r"NoNewPrivs:\s*1", preflight_text)
            and re.search(r"Cpus_allowed_list:\s*4\s*$", preflight_text, re.MULTILINE)
            and re.search(r"^4-5\s*$", preflight_text, re.MULTILINE)
            and re.search(r"Max realtime priority\s+1\s+1", preflight_text)
            and "SCHED_RR" in preflight_text
            and re.search(r"current scheduling priority:\s*1", preflight_text)
        )
        result["credential_preflight"] = {
            "returncode": preflight_process.returncode,
            "valid": bool(preflight_valid),
            "log": str(preflight_log),
            "log_sha256": sha256(preflight_log),
        }
        journal("credential_preflight_completed", pid=preflight_process.pid,
                returncode=preflight_process.returncode, valid=bool(preflight_valid),
                evidence_sha256=sha256(preflight_log))
        if not preflight_valid:
            result["error"] = "credential/ETF preflight mismatch; no client exec or external request issued"
            result["credential_preflight_output"] = preflight_text
            result["terminal"] = True
            return 31

        capture_log_stream = tcpdump_log.open("xb")
        capture = subprocess.Popen(
            ["sudo", "-n", "nsenter", "-t", str(running["State"]["Pid"]), "-n", "tcpdump",
             "-p", "-B", "16384", "-i", "eth0", "-s", "0", "-U", "-w", str(pcap), "udp port 443"],
            stdin=subprocess.DEVNULL, stdout=capture_log_stream, stderr=subprocess.STDOUT,
            preexec_fn=capture_limit,
        )
        journal("tcpdump_started", pid=capture.pid, pcap=str(pcap))
        if not wait_for_tcpdump(capture, tcpdump_log, 10):
            raise RuntimeError("tcpdump did not report readiness within 10 seconds")
        journal("tcpdump_ready", interface="eth0", filter="udp port 443")

        # The mode-wide owner lock remains held. Fresh read-only slot/tuple/history checks
        # fence this exact capture immediately before any request can be issued.
        current_ledger=ledger_readonly_state()
        current_history=wtfpad_history_tuple_keys()
        verify_slot_and_tuple_snapshot(current_ledger,current_history)
        # Refresh across independent-defense commits that may occur while this
        # owner prepares; a later SQL reservation catches any tuple race.
        atomic_json(OUT/"tuple-ledger-readonly-snapshot.json",current_ledger)
        result["slot_ledger_rechecks"]={"immediately_before_client":{
            "valid":True,"slot_occupied_or_pending":False,
            "slot":CURRENT_SLOT,
            "tuple_set_sha256":current_ledger["tuple_set_sha256"],
            "tuple_keys":current_ledger["tuple_keys"],
            "wtfpad_history_sha256":current_history["sha256"],
            "wtfpad_tuple_count":len(current_history["tuple_keys"]),
            "read_only":True}}
        journal("slot_tuple_wtfpad_recheck_before_client",slot=CURRENT_SLOT,slot_occupied_or_pending=False,
                tuple_set_sha256=current_ledger["tuple_set_sha256"],
                wtfpad_history_sha256=current_history["sha256"],
                ledger_read_only=True,mode_lock_held=True)

        client_argv = [
            "docker", "exec",
            "--env", "QCSD_CAPTURE_SCHEDULER_CONTRACT=qcsd-client-rr1-portable-etf-helper-v3",
            "--env", "QCSD_CAPTURE_CLIENT_CPU=4",
            "--env", "QCSD_CAPTURE_ORCHESTRATOR_CPU=5",
            "--env", "QCSD_CAPTURE_ETF_INTERFACE=eth0",
            container_id, "taskset", "-c", "4", "chrt", "-r", "1",
            "setpriv", "--reuid=503", "--regid=1000", "--clear-groups",
            "--inh-caps=+net_admin,+setpcap", "--ambient-caps=+net_admin,+setpcap",
            "/tmp/neqo-qcsd-client", "run",
            "--workload", "/inputs/resources.json",
            "--application-workload-source", "/inputs/prepared-workload.json",
            "--chaff-manifest", "/inputs/chaff-manifest.json",
            "--config", "/inputs/params/qcsd-buflo-receive-credit.toml",
            "--seed", str(SESSION_SEED), "--output-dir", "/diagnostic/native",
            "--max-response-bytes", "16777216", "--timeout-seconds", "60",
            "--buflo-retained-parser-fin-permission",
        ]
        journal("client_exec_intent", argv=client_argv, bounded_client_timeout_s=60,
                retry_policy="one request only; uncertain completion is read-only polled")
        client_exec_submitted = True
        CLIENT_EXEC_SUBMITTED_GLOBAL = True
        client_log_stream = client_log.open("xb")
        try:
            client_process = subprocess.Popen(
                client_argv, stdin=subprocess.DEVNULL, stdout=client_log_stream,
                stderr=subprocess.STDOUT, start_new_session=True,
            )
        except Exception as error:
            journal("client_exec_launch_failed", error=repr(error))
            raise
        journal("client_exec_process_started", pid=client_process.pid)
        client_wait=wait_for_client_terminal(client_process,capture,client_log_stream,container_id,timeout_s=90)
        client_exec_completed = client_process.poll() is not None
        result["client_wait_supervision"]=client_wait
        result["process_exit_code"] = client_process.returncode
        if client_wait and client_wait.get("wait_bound_elapsed"):
            result["client_wait_bound_elapsed"] = True
            result["error"] = "client exceeded the 90-second observation bound; same process remained supervised with tcpdump active until exit"
        journal("client_exec_completed", pid=client_process.pid, returncode=client_process.returncode,
                observation_bound_elapsed=bool(client_wait and client_wait.get("wait_bound_elapsed")),
                collector_running_at_exit=bool(client_wait and client_wait.get("collector_running_at_client_exit")))
        time.sleep(1)
        run_path = native / "run.json"
        if run_path.is_file():
            run_data = json.loads(run_path.read_text(encoding="utf-8"))
            result["completion_status"] = run_data.get("completion_status")
            result["error_class"] = run_data.get("error_class")
            result["client_reported_direct_policy"] = run_data.get("buflo_direct_fin_credit_reassignment_policy")
            result["permission_accounting"] = run_data.get("buflo_retained_parser_fin_permission")
            result["endpoint_tuples"] = [item.get("tuple") for item in (run_data.get("endpoints") or [])]
            if (native / "events.csv").is_file():
                result["same_slot_event_evidence"] = matched_event_evidence(run_path, native / "events.csv")
                result["direct_fin_releases"] = result["same_slot_event_evidence"]["direct_fin_releases"]
        else:
            result["error"] = "client exec completed without native run.json"
        result["client_log_sha256"] = sha256(client_log)
    except Exception as error:
        result["error"] = repr(error)
        journal("runner_exception", error=repr(error), client_exec_submitted=client_exec_submitted,
                client_exec_completed=client_exec_completed)
    finally:
        if client_process is not None and client_process.poll() is None:
            result["error"] = result.get("error") or "client exec remains active during cleanup; retaining collector until exact process exit"
            result["client_exec_pid"] = client_process.pid
            wait_result=wait_for_client_terminal(client_process,capture,client_log_stream,container_id,timeout_s=0)
            result["client_wait_supervision"]=wait_result
            result["process_exit_code"]=client_process.returncode
            client_exec_completed=client_process.poll() is not None
            journal("client_terminal_observed_during_cleanup",pid=client_process.pid,
                    returncode=client_process.returncode,collector_running=wait_result["collector_running_at_client_exit"])
        elif client_process is not None and not client_exec_completed:
            # Even when the local docker exec Popen is already terminal, verify from
            # the daemon that the in-container client did not outlive a broken CLI.
            wait_result=wait_for_client_terminal(client_process,capture,client_log_stream,container_id,timeout_s=0)
            client_exec_completed=client_process.poll() is not None and wait_result.get("container_client_absent") is True
            result["client_wait_supervision"]=wait_result
            result["process_exit_code"]=client_process.returncode
            journal("client_terminal_observed_during_cleanup",pid=client_process.pid,
                    returncode=client_process.returncode,container_client_absent=wait_result.get("container_client_absent"),
                    collector_running=wait_result["collector_running_at_client_exit"])
        if capture is not None:
            code = stop_tcpdump(capture, capture_log_stream)
            journal("tcpdump_stop_observed", returncode=code)
        if capture_log_stream is not None and not capture_log_stream.closed:
            capture_log_stream.flush()
            os.fsync(capture_log_stream.fileno())
            capture_log_stream.close()
        if client_log_stream is not None and not client_log_stream.closed and client_process is not None and client_process.poll() is not None:
            client_log_stream.flush();os.fsync(client_log_stream.fileno());client_log_stream.close()
        if pcap.exists():
            result["pcap_size_bytes"] = pcap.stat().st_size
            result["pcap_sha256"] = sha256(pcap)
        if tcpdump_log.exists():
            result["tcpdump_log"] = tcpdump_log.read_text(encoding="utf-8", errors="replace")
        if client_log.exists():
            result["client_log_sha256"] = sha256(client_log)
        safe_to_remove = (
            container_id is not None
            and not docker_mutation_pending
            and (not qdisc_exec_submitted or qdisc_exec_completed)
            and (not preflight_exec_submitted or preflight_exec_completed)
            and (not client_exec_submitted or client_exec_completed)
        )
        if safe_to_remove and not RESULT.exists():
            remove_code, remove_pid = mutation_once("docker_remove", ["docker", "rm", "--force", container_id], 180, remove_log)
            result["docker_remove_returncode"] = remove_code
            result["docker_remove_pid"] = remove_pid
            if remove_code is None:
                result["container_removed"] = False
                result["cleanup_terminal"] = False
            else:
                result["container_removed"] = remove_code == 0
                result["cleanup_terminal"] = True
        elif container_id is not None:
            result["container_removed"] = False
            result["cleanup_terminal"] = False
            if qdisc_exec_submitted and not qdisc_exec_completed:
                cleanup_reason = "qdisc setup may still be in flight"
            elif preflight_exec_submitted and not preflight_exec_completed:
                cleanup_reason = "credential preflight may still be in flight"
            elif client_exec_submitted and not client_exec_completed:
                cleanup_reason = "client exec may still be in flight"
            else:
                cleanup_reason = "request state is uncertain"
            journal("container_cleanup_withheld", reason=cleanup_reason)
        try:
            inspect_target = container_id or CONTAINER
            state = inspect_container(inspect_target)
            result["container_absent_after_cleanup"] = False
            result["postrun_container_id"] = state["Id"]
            result["postrun_container_state"] = state["State"]
            result["postrun_networks"] = state["NetworkSettings"]["Networks"]
            journal("postrun_container_observed", inspect_target=inspect_target,
                    status=state["State"]["Status"], pid=state["State"]["Pid"],
                    networks=state["NetworkSettings"]["Networks"])
        except subprocess.CalledProcessError:
            result["container_absent_after_cleanup"] = True
            journal("container_absence_confirmed", inspect_target=container_id or CONTAINER)
        except Exception as error:
            result["container_absent_after_cleanup"] = None
            result["postrun_inspect_error"] = repr(error)
        try:
            network_policy = load_network_policy()
            network_policy.inspect_network("buflo", NETWORK, None)
            result["network_empty_after"] = True
            journal("network_empty_after", network=NETWORK["name"])
        except Exception as error:
            result["network_empty_after"] = False
            result["network_after_error"] = repr(error)
            journal("network_not_empty_after", error=repr(error))
        result["mutating_request_pending"] = docker_mutation_pending or result.get("cleanup_terminal") is False
        result["terminal"] = result.get("terminal", client_exec_completed or result.get("docker_create_returncode") is not None)
        try:
            post_ledger=ledger_readonly_state()
            post_history=wtfpad_history_tuple_keys()
            verify_slot_and_tuple_snapshot(post_ledger,post_history)
            post_valid=(post_ledger["slot_occupied_or_pending"] is False
                        and post_ledger["tuple_count"]>=prior_tuples["tuple_count"])
            result.setdefault("slot_ledger_rechecks",{})["after_client_before_any_import"]={
                "valid":post_valid,"slot_occupied_or_pending":post_ledger["slot_occupied_or_pending"],
                "slot":CURRENT_SLOT,
                "tuple_set_sha256":post_ledger["tuple_set_sha256"],
                "tuple_keys":post_ledger["tuple_keys"],
                "wtfpad_history_sha256":post_history["sha256"],
                "wtfpad_tuple_count":len(post_history["tuple_keys"]),"read_only":True}
            journal("slot_tuple_wtfpad_recheck_after_client_before_commit",valid=post_valid,
                    slot_occupied_or_pending=post_ledger["slot_occupied_or_pending"],
                    tuple_set_sha256=post_ledger["tuple_set_sha256"],
                    wtfpad_history_sha256=post_history["sha256"],ledger_read_only=True,
                    statement="transactional tuple reservation still required before final commit")
        except Exception as slot_error:
            result.setdefault("slot_ledger_rechecks",{})["after_client_before_any_import"]={"valid":False,"error":repr(slot_error)}
            journal("slot_tuple_wtfpad_recheck_after_client_failed_closed",error=repr(slot_error))
        result["journal_path"] = str(JOURNAL)
        result["journal_sha256"] = sha256(JOURNAL) if JOURNAL.exists() else None
        result["finished_utc"] = utc_now()
        try:
            result["owner_gate"] = candidate_gates(result)
            result["candidate_ready_for_independent_review"] = result["owner_gate"].get("candidate_ready_for_independent_review") is True
            journal("owner_gates_completed", passed=result["owner_gate"].get("passed"), gate_names=list(result["owner_gate"].get("checks",{})))
        except Exception as gate_error:
            result["owner_gate"] = {"passed":False,"candidate_ready_for_independent_review":False,"error":repr(gate_error),"accepted_session":False,"capture_credit":False,"session_ledger_write":False,"drive_upload":False}
            result["candidate_ready_for_independent_review"] = False
            journal("owner_gates_failed_closed", error=repr(gate_error))
        result["journal_sha256"] = sha256(JOURNAL) if JOURNAL.exists() else None
        result["accepted_session"] = False
        result["capture_credit"] = False
        result["session_ledger_write"] = False
        result["drive_upload"] = False
        if not RESULT.exists():
            atomic_json(RESULT, result)
            if JOURNAL.exists():
                journal("result_persisted", result_path=str(RESULT), result_sha256=sha256(RESULT))
        if result.get("owner_gate", {}).get("passed") is True:
            final_sha=commit_accepted(result,intent)
            print(json.dumps({"status":"success","slot":CURRENT_SLOT,"attempt_id":ATTEMPT_ID,
                              "final_sha256":final_sha,"accepted_session":True,"capture_credit":True,
                              "drive_upload":False},sort_keys=True),flush=True)
            return 0
        if not client_exec_submitted and not (OUT/"FINAL.json").exists():
            store_not_started_final(result)
        print(json.dumps({"status":"failed_uncredited","slot":CURRENT_SLOT,"attempt_id":ATTEMPT_ID,
                          "accepted_session":False,"capture_credit":False,
                          "gate_passed":False,"analysis":str(RESULT)},sort_keys=True),flush=True)
        return 10



if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except Exception as error:
        try:
            if OUT is not None and (OUT/"FINAL.json").is_file():
                print("exception after FINAL publication; preserve files and inspect ledger transaction: "+repr(error),file=sys.stderr)
            else:
                journal("unhandled_terminal_exception", error=repr(error))
                if RESULT is not None and not RESULT.exists():
                    atomic_json(RESULT, {
                        "kind": "mx-buflo-production-capture-analysis",
                        "request_id": REQUEST_ID,
                        "attempt_id": ATTEMPT_ID,
                        "slot": CURRENT_SLOT,
                        "capture_credit": False,
                        "accepted_session": False,
                        "session_ledger_write": False,
                        "drive_upload": False,
                        "terminal": False,
                        "error": repr(error),
                        "journal_path": str(JOURNAL),
                        "journal_sha256": sha256(JOURNAL),
                        "finished_utc": utc_now(),
                    })
                if OUT is not None and CURRENT_SLOT is not None and not CLIENT_EXEC_SUBMITTED_GLOBAL:
                    store_not_started_final({"error":repr(error)})
        except Exception:
            pass
        raise
