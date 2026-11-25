#!/usr/bin/env python3
"""Verified, checkpointed packet-volume and trace-span extraction.

Every input byte is hashed while the capture is piped to Wireshark capinfos.
The final handoff manifest is authoritative for the expected size and hash.
Only rows with exact byte identity and successful parsing enter metrics.
No downloaded packet capture is stored by this program.
"""
import argparse
import csv
import fcntl
import hashlib
import io
import json
import os
import signal
import shutil
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
from urllib.request import urlopen

CAPINFOS = shutil.which("capinfos") or "capinfos"
TSHARK = shutil.which("tshark") or "tshark"
BASELINE = None

def accumulate_fields(stream, result):
    """Consume tshark output concurrently; never retain the packet-level lines."""
    result.update(frames=0, frame_bytes=0, ipv4_bytes=0, ipv4_count=0, ipv6_bytes=0,
                  ipv6_count=0, truncated=0, non_ip=0, multiple_ip=0, ipv6_zero=0,
                  malformed_ip=0, unverified_link=0, other_ip_bytes=0,
                  no_udp_ports_ip_bytes=0, candidates={}, errors=[])
    for raw in stream:
        try:
            fields=raw.decode("ascii").rstrip("\r\n").split("\t")
            if len(fields)!=13:
                raise ValueError("expected 13 fields, got %d" % len(fields))
            length, caplen = int(fields[0]), int(fields[1])
            ips4 = [int(x) for x in fields[2].split(",") if x]
            ips6 = [int(x) for x in fields[3].split(",") if x]
            ethernet=bool(fields[4])
            vlans=[x for x in fields[5].split(",") if x]
            ip_headers=[int(x) for x in fields[6].split(",") if x]
            result["frames"]+=1
            result["frame_bytes"]+=length
            result["truncated"]+=caplen<length
            result["ipv4_bytes"]+=sum(ips4)
            result["ipv4_count"]+=len(ips4)
            result["ipv6_bytes"]+=sum(40+x for x in ips6)
            result["ipv6_count"]+=len(ips6)
            result["non_ip"]+=not ips4 and not ips6
            result["multiple_ip"]+=len(ips4)+len(ips6)>1
            result["ipv6_zero"]+=any(x==0 for x in ips6)
            # Ethernet II plus each 802.1Q tag; if a capture has another link
            # representation, keep its frame/span metrics but do not infer
            # a trustworthy IP byte total from an unknown header offset.
            if ips4 or ips6:
                result["unverified_link"]+=not ethernet
                if ethernet:
                    available=caplen-14-4*len(vlans)
                    malformed=(any(x>available for x in ips4) or
                               any(40+x>available for x in ips6) or
                               len(ip_headers)!=len(ips4) or
                               any(h<20 or h%4 or n<h for n,h in zip(ips4,ip_headers)))
                    result["malformed_ip"]+=malformed
            if len(ips4)+len(ips6)==1:
                ip_size=ips4[0] if ips4 else 40+ips6[0]
                src,dst=(fields[7],fields[8]) if ips4 else (fields[9],fields[10])
                udp_src,udp_dst=fields[11],fields[12]
                if not udp_src or not udp_dst:
                    result["no_udp_ports_ip_bytes"]+=ip_size
                elif (udp_src=="443") != (udp_dst=="443") and src and dst and not any("," in v for v in (src,dst,udp_src,udp_dst)):
                    server_is_src=udp_src=="443"
                    key=(dst,udp_dst,src,udp_src) if server_is_src else (src,udp_src,dst,udp_dst)
                    # Bound memory in unusual traffic; more than 512 candidate
                    # tuples makes direction ambiguous and is not quantified.
                    if len(result["candidates"])<512 or key in result["candidates"]:
                        cand=result["candidates"].setdefault(key,[0,0,0,0])
                        cand[1 if server_is_src else 0]+=ip_size
                        cand[3 if server_is_src else 2]+=1
                    else:
                        result["other_ip_bytes"]+=ip_size
                        result["candidate_overflow"]=True
                else:
                    result["other_ip_bytes"]+=ip_size
        except Exception as exc:
            if len(result["errors"])<3: result["errors"].append(repr(exc))


def drain_stderr(stream, result):
    result["prefix"]=b""
    result["total"]=0
    while True:
        b=stream.read(4096)
        if not b: break
        result["total"]+=len(b)
        if len(result["prefix"])<2048:
            result["prefix"]+=b[:2048-len(result["prefix"])]


def measure(row, base_url, timeout):
    cmd = [CAPINFOS, "-T", "-r", "-M", "-Q", "-t", "-E", "-c", "-d", "-u", "-a", "-e", "-o", "-S", "/dev/stdin"]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,start_new_session=True)
    q = subprocess.Popen([TSHARK, "-n", "-l", "-r", "-", "--disable-protocol", "quic", "-T", "fields",
                          "-E", "occurrence=a", "-E", "aggregator=,", "-E", "quote=n",
                          "-e", "frame.len", "-e", "frame.cap_len", "-e", "ip.len", "-e", "ipv6.plen",
                          "-e", "eth.type", "-e", "vlan.id", "-e", "ip.hdr_len",
                          "-e", "ip.src", "-e", "ip.dst", "-e", "ipv6.src", "-e", "ipv6.dst",
                          "-e", "udp.srcport", "-e", "udp.dstport"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,start_new_session=True)
    stats={}
    reader=threading.Thread(target=accumulate_fields,args=(q.stdout,stats),daemon=True)
    reader.start()
    errors=[{},{}]
    drainers=[threading.Thread(target=drain_stderr,args=(child.stderr,buf),daemon=True)
              for child,buf in zip((p,q),errors)]
    for thread in drainers:thread.start()
    finished=threading.Event()
    timed_out=threading.Event()
    def watchdog():
        if not finished.wait(timeout):
            timed_out.set()
            for child in (p,q):
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
    monitor=threading.Thread(target=watchdog,daemon=True)
    monitor.start()
    digest = hashlib.sha256()
    count = 0
    local = (Path(BASELINE) / row["defense"] / row["domain"] / row["filename"]) if BASELINE else None
    source = "local" if local and local.is_file() else "drive-http"
    try:
        if source == "local":
            stream = local.open("rb")
        else:
            if not base_url:raise FileNotFoundError("capture is not present in --baseline and no --base-url was supplied")
            path = "/".join(quote(row[x], safe="") for x in ("defense", "domain", "filename"))
            stream = urlopen(base_url.rstrip("/") + "/" + path, timeout=timeout)
        with stream:
            while True:
                data = stream.read(1024 * 1024)
                if not data:
                    break
                digest.update(data)
                count += len(data)
                p.stdin.write(data)
                q.stdin.write(data)
        p.stdin.close()
        q.stdin.close()
        out = p.stdout.read().decode("utf-8", "replace")
        rc = p.wait()
        reader.join()
        qrc = q.wait()
        for thread in drainers:thread.join()
        err=errors[0]["prefix"].decode("utf-8","replace")
        qerr=errors[1]["prefix"].decode("utf-8","replace")
        if timed_out.is_set():raise TimeoutError("capture exceeded wall-clock deadline")
        if rc != 0:
            raise ValueError("capinfos exit %s: %s" % (rc, err[:500]))
        if qrc != 0:
            raise ValueError("tshark exit %s: %s" % (qrc, qerr[:500]))
        observed = digest.hexdigest()
        if count != int(row["size"]) or observed != row["sha256"]:
            raise ValueError("manifest mismatch size=%s hash=%s" % (count, observed))
        parsed = list(csv.reader(io.StringIO(out), delimiter="\t"))
        if len(parsed) != 1 or len(parsed[0]) != 9:
            raise ValueError("unexpected capinfos output: %r %r" % (out[:500], err[:500]))
        _, ctype, encapsulation, packets, data_bytes, duration, start, end, ordered = parsed[0]
        if int(packets) <= 0:
            raise ValueError("zero-packet capture")
        if stats["errors"]:
            raise ValueError("invalid tshark packet fields %r" % stats["errors"])
        if stats["frames"] != int(packets) or stats["frame_bytes"] != int(data_bytes):
            raise ValueError("tshark/capinfos frame statistics differ")
        ipv4_count, ipv6_count = stats["ipv4_count"], stats["ipv6_count"]
        truncated, non_ip, multiple_ip, ipv6_zero = stats["truncated"], stats["non_ip"], stats["multiple_ip"], stats["ipv6_zero"]
        ip_bytes = stats["ipv4_bytes"] + stats["ipv6_bytes"]
        ip_valid = (int(packets) == ipv4_count + ipv6_count + non_ip and not truncated and not non_ip
                    and not multiple_ip and not ipv6_zero and not stats["malformed_ip"] and not stats["unverified_link"])
        candidates=stats["candidates"]
        direction_valid=(ip_valid and len(candidates)==1 and not stats.get("candidate_overflow"))
        one=next(iter(candidates.values())) if len(candidates)==1 else None
        direction_valid=bool(direction_valid and one[2] and one[3])
        up=one[0] if direction_valid else None
        down=one[1] if direction_valid else None
        other=(ip_bytes-up-down) if direction_valid else None
        finished.set()
        return dict(status="ok", defense=row["defense"], domain=row["domain"], session=int(row["session"]),
                    filename=row["filename"], drive_file_id=row["drive_file_id"], capture_bytes=count,
                    sha256=observed, source=source, capture_type=ctype, encapsulation=encapsulation,
                    packet_count=int(packets), packet_bytes=int(data_bytes), span_seconds=float(duration),
                    first_epoch=start, last_epoch=end, strict_order=ordered, ip_bytes=ip_bytes,
                    ipv4_packets=ipv4_count, ipv6_packets=ipv6_count, truncated_packets=truncated,
                    non_ip_packets=non_ip, multiple_ip_packets=multiple_ip,
                    ipv6_zero_payload_packets=ipv6_zero, malformed_ip_packets=stats["malformed_ip"],
                    unverified_link_packets=stats["unverified_link"],ip_valid=ip_valid,
                    udp443_tuple_candidates=len(candidates), udp443_candidate_overflow=bool(stats.get("candidate_overflow")),
                    udp443_direction_valid=direction_valid, udp443_up_ip_bytes=up,
                    udp443_down_ip_bytes=down, other_ip_bytes=other,
                    no_udp_ports_ip_bytes=stats["no_udp_ports_ip_bytes"],error="")
    except Exception as exc:
        finished.set()
        for child in (p, q):
            try:
                child.stdin.close()
            except Exception:
                pass
            child.stdin = None
            if child.poll() is None:
                child.kill()
            child.wait()
        reader.join()
        for thread in drainers:thread.join()
        return dict(status="error", defense=row["defense"], domain=row["domain"], session=int(row["session"]),
                    filename=row["filename"], drive_file_id=row["drive_file_id"],
                    error=("TimeoutError('capture exceeded wall-clock deadline')" if timed_out.is_set() else repr(exc)))


def main():
    global CAPINFOS, TSHARK, BASELINE
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--base-url", help="loopback HTTP URL serving the manifest's defense/domain/filename tree")
    ap.add_argument("--baseline", help="optional local root containing defense/domain/filename tree")
    ap.add_argument("--capinfos", default=CAPINFOS)
    ap.add_argument("--tshark", default=TSHARK)
    ap.add_argument("--allow-other-wireshark", action="store_true", help="record but allow a version other than the study's 4.4.20")
    ap.add_argument("--defense", action="append")
    ap.add_argument("--domain", action="append")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--max-errors", type=int, default=100)
    args = ap.parse_args()
    CAPINFOS, TSHARK, BASELINE = args.capinfos, args.tshark, args.baseline
    if not BASELINE and not args.base_url:ap.error("provide --baseline or --base-url")
    if args.base_url:
        from urllib.parse import urlparse
        endpoint=urlparse(args.base_url)
        if endpoint.scheme!="http" or endpoint.hostname not in ("127.0.0.1","localhost","::1"):
            ap.error("--base-url must be loopback HTTP; keep Drive credentials out of this program")
    versions=[]
    for executable in (CAPINFOS,TSHARK):
        v=subprocess.check_output([executable,"--version"],text=True,stderr=subprocess.STDOUT).splitlines()[0]
        versions.append(v)
        if "4.4.20" not in v and not args.allow_other_wireshark:
            raise RuntimeError("Wireshark 4.4.20 required, found "+v)
    if args.workers < 1 or args.workers > 32:
        ap.error("workers must be 1..32")
    lock=open(args.db+".lock","a+")
    try:fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise RuntimeError("another extractor owns this database")
    db = sqlite3.connect(args.db)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS metrics (defense TEXT NOT NULL, domain TEXT NOT NULL, session INTEGER NOT NULL, drive_file_id TEXT NOT NULL, sha256 TEXT NOT NULL, result_json TEXT NOT NULL, PRIMARY KEY(defense,domain,session))")
    db.execute("CREATE TABLE IF NOT EXISTS errors (defense TEXT NOT NULL, domain TEXT NOT NULL, session INTEGER NOT NULL, error TEXT NOT NULL, updated REAL NOT NULL, PRIMARY KEY(defense,domain,session))")
    digest = hashlib.sha256()
    with open(args.manifest,"rb") as f:
        for chunk in iter(lambda: f.read(1024*1024),b""): digest.update(chunk)
    code_sha=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    for key,value in (("manifest_sha256",digest.hexdigest()),("metrics_schema","2026-11-25-ip-frame-direction-v2"),
                      ("extractor_sha256",code_sha),("capinfos_version",versions[0]),("tshark_version",versions[1])):
        prev=db.execute("SELECT value FROM metadata WHERE key=?",(key,)).fetchone()
        if prev and prev[0]!=value: raise RuntimeError("incompatible existing metrics database: "+key)
        db.execute("INSERT OR IGNORE INTO metadata VALUES(?,?)",(key,value))
    old = {(a,b,c):(d,e) for a,b,c,d,e in db.execute("SELECT defense,domain,session,drive_file_id,sha256 FROM metrics")}
    with open(args.manifest, newline="", encoding="utf-8-sig") as f:
        groups = {}
        for r in csv.DictReader(f):
            if args.defense and r["defense"] not in args.defense: continue
            if args.domain and r["domain"] not in args.domain: continue
            ident = (r["defense"],r["domain"],int(r["session"]))
            if ident in old:
                if old[ident] != (r["drive_file_id"],r["sha256"]):
                    raise RuntimeError("manifest changed for recorded session %r" % (ident,))
                continue
            groups.setdefault((r["domain"],r["defense"]),[]).append(r)
    # Cycle across every domain/condition in small blocks, rather than leaving
    # all but the first defenses unmeasured for hours in a long-running pass.
    cells=sorted(groups)
    rows=[]
    for start_index in range(0,max((len(v) for v in groups.values()),default=0),20):
        for cell in cells:
            rows.extend(groups[cell][start_index:start_index+20])
    if args.limit:
        rows = rows[:args.limit]
    start = time.monotonic(); ok=0; errors=0
    print(json.dumps({"selected":len(rows),"already_verified":len(old),"workers":args.workers}),flush=True)
    def attempt(row):
        for i in range(args.retries+1):
            result=measure(row,args.base_url,args.timeout)
            if result["status"] == "ok":return result
            if i < args.retries:time.sleep(min(8,2**i))
        return result
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        # Limit each batch to avoid retaining 120,000 future objects.
        for off in range(0,len(rows),args.workers * 8):
            batch=rows[off:off+args.workers * 8]
            futures=[pool.submit(attempt,r) for r in batch]
            for f in as_completed(futures):
                x=f.result(); key=(x["defense"],x["domain"],x["session"])
                if x["status"] == "ok":
                    db.execute("INSERT OR REPLACE INTO metrics VALUES(?,?,?,?,?,?)",key+(x["drive_file_id"],x["sha256"],json.dumps(x,sort_keys=True)))
                    db.execute("DELETE FROM errors WHERE defense=? AND domain=? AND session=?",key)
                    ok+=1
                else:
                    db.execute("INSERT OR REPLACE INTO errors VALUES(?,?,?,?,?)",key+(x["error"],time.time()))
                    errors+=1
                if (ok+errors)%100 == 0:
                    db.commit()
                    print(json.dumps({"verified":ok,"errors":errors,"seconds":round(time.monotonic()-start,1),"latest":key}),flush=True)
            db.commit()
            if errors>=args.max_errors:
                print(json.dumps({"aborted":"too many errors","limit":args.max_errors}),flush=True)
                break
    print(json.dumps({"verified":ok,"errors":errors,"seconds":round(time.monotonic()-start,1)}),flush=True)
    return 1 if errors else 0

if __name__ == "__main__":
    sys.exit(main())
