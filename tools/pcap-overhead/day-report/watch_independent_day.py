#!/usr/bin/env python3
"""Wait for the completed census, rerun the day sensitivity and draft once.

This is optional local automation. It never changes packet inputs or the
metrics database, contacts Drive, copies existing result tables, or publishes.
An interrupted/failed start requires inspection, not blind duplication.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

MANIFEST_SHA = 'ef0e87f1138db2675e655813b0667b3860235df5c635f045e18f48fac1d72abf'
AGGREGATE_SHA = '6e6427360998bd4da1f4bfdfea3c619931003448f2dfd0c573f6ad8bafdc32e6'
DAY_SHA = '9ae4b14c64ad24b684c2507c127dd20a074c145539e4d51a65ea7aed54b25ca9'
BUILDER_SHA = '5968f78f92026cd2b5d9ae68e4842e4446ba75e16058c23ade6e143fa6c0b19a'
TABLES = ('utc-day-cluster-by-domain.csv', 'utc-day-cluster-eligible-subset-summary.csv')
LOCAL_TERMINAL = {'started', 'complete', 'failed', 'verification_failed', 'upstream_failed'}
UPSTREAM_FAILURE = {'failed', 'aggregation_failed', 'quality_failed', 'verification_failed', 'upstream_failed', 'review_required'}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def read_state(path):
    try:
        x = json.loads(Path(path).read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {'status': 'not_started'}
    if not isinstance(x, dict) or not isinstance(x.get('status'), str):
        raise ValueError('Invalid watcher state')
    return x


def atomic_state(path, state):
    path = Path(path)
    tmp = path.with_name(path.name + '.tmp.' + str(os.getpid()))
    with tmp.open('w', encoding='utf-8') as f:
        json.dump({**state, 'updated_utc': utc()}, f, indent=2, sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def upstream(agg, day):
    for label, state in (('aggregate', agg), ('day', day)):
        status = state.get('status')
        if status in UPSTREAM_FAILURE:
            raise ValueError(label + ' requires review: ' + str(status))
    if any(state.get('status') != 'complete' for state in (agg, day)):
        return None
    result = []
    for label, state in (('aggregate', agg), ('day', day)):
        raw = state.get('output')
        if not isinstance(raw, str) or not raw or not Path(raw).is_dir():
            raise ValueError('Completed ' + label + ' output unavailable')
        result.append(Path(raw).resolve())
    return tuple(result)


def checked_inputs(args, aggregate_dir, first_day_dir):
    pinned = ((args.manifest, MANIFEST_SHA), (args.aggregate, AGGREGATE_SHA),
              (args.day_code, DAY_SHA), (args.builder, BUILDER_SHA))
    if any(not Path(p).is_file() or sha(p) != expected for p, expected in pinned):
        raise ValueError('Pinned manifest or code hash mismatch')
    qpath = aggregate_dir / 'quality.json'
    proofpath = first_day_dir / 'utc-day-cluster-provenance.json'
    files = [qpath, proofpath, *(first_day_dir / x for x in TABLES)]
    if any(p.is_symlink() or not p.is_file() for p in files):
        raise ValueError('Missing or symlinked upstream input')
    q = json.loads(qpath.read_text(encoding='utf-8'))
    p = json.loads(proofpath.read_text(encoding='utf-8'))
    metric = q.get('metric_rows_content_sha256')
    if (q.get('status') != 'complete' or q.get('manifest_sessions') != 120000
            or q.get('accepted_metric_rows') != 120000 or q.get('extractor_errors') != 0
            or q.get('identity_or_other_flags') != {} or q.get('manifest_sha256') != MANIFEST_SHA
            or q.get('analysis_script_sha256') != AGGREGATE_SHA
            or not isinstance(metric, str) or len(metric) != 64):
        raise ValueError('Aggregate quality is not a complete verified census')
    if (p.get('status') != 'complete' or p.get('metric_rows') != 120000
            or p.get('manifest_sha256') != MANIFEST_SHA or p.get('aggregate_code_sha256') != AGGREGATE_SHA
            or p.get('bootstrap_code_sha256') != DAY_SHA or p.get('metric_rows_content_sha256') != metric
            or type(p.get('bootstrap_replicates')) is not int or p['bootstrap_replicates'] < 100
            or type(p.get('seed')) is not int or not p.get('python_version') or not p.get('numpy_version')):
        raise ValueError('Original day sensitivity does not match verified census')
    hashes = {str(f): sha(f) for f in files}
    return p, hashes


def matching_environment(python, proof):
    proc = subprocess.run([str(python), '-c', 'import json,sys,numpy; print(json.dumps([sys.version.split()[0],numpy.__version__]))'],
                          check=True, capture_output=True, text=True, timeout=30)
    version, numpy = json.loads(proc.stdout)
    if version != proof['python_version'].split()[0] or numpy != proof['numpy_version']:
        raise ValueError('Python or NumPy version differs from original day run')


def run_once(args, aggregate_dir, first_day_dir, state_path, *, runner=subprocess.run):
    previous = read_state(state_path)
    if previous['status'] in LOCAL_TERMINAL:
        return {'started': False, 'reason': 'Previous start or terminal state requires inspection'}
    proof, hashes = checked_inputs(args, aggregate_dir, first_day_dir)
    matching_environment(args.python, proof)
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    root = args.state_dir / ('pcap-day-independent-' + stamp + '-' + str(os.getpid()))
    if root.exists():
        raise ValueError('Refusing to reuse a result directory')
    root.mkdir()
    second = root / 'independent-day-results'
    note = root / 'utc-day-review-draft.md'
    qpath = aggregate_dir / 'quality.json'
    rerun = [str(args.python), str(args.day_code), '--manifest', str(args.manifest),
             '--database', str(args.database), '--quality', str(qpath), '--aggregate', str(args.aggregate),
             '--output', str(second), '--bootstrap', str(proof['bootstrap_replicates']), '--seed', str(proof['seed'])]
    draft = [str(args.python), str(args.builder), '--manifest', str(args.manifest), '--quality', str(qpath),
             '--aggregate', str(args.aggregate), '--day-code', str(args.day_code), '--day-output', str(first_day_dir),
             '--independent-day-output', str(second), '--output', str(note)]
    atomic_state(state_path, {'status': 'started', 'watcher_pid': os.getpid(), 'output': str(root),
                              'started_utc': utc(), 'rerun_command': rerun, 'draft_command': draft,
                              'upstream_sha256': hashes, 'builder_sha256': BUILDER_SHA})
    try:
        run = runner(rerun, check=False, capture_output=True, text=True, timeout=args.timeout)
        if run.returncode:
            raise ValueError('Independent day rerun failed: ' + run.stderr[-1200:])
        if any(sha(path) != h for path, h in hashes.items()):
            raise ValueError('Original inputs changed during the rerun')
        if sha(args.builder) != BUILDER_SHA:
            raise ValueError('Report builder changed during rerun')
        built = runner(draft, check=False, capture_output=True, text=True, timeout=args.timeout)
        if built.returncode:
            raise ValueError('UTC-day draft validation failed: ' + built.stderr[-1200:])
        data = note.read_text(encoding='utf-8')
        if not data.startswith('# Exploratory UTC-day cluster sensitivity') or 'SYNTHETIC FIXTURE' in data:
            raise ValueError('Unexpected or synthetic draft')
        result = {'status': 'complete', 'output': str(root), 'draft': str(note), 'draft_sha256': sha(note),
                  'original_inputs_sha256': hashes, 'builder_sha256': BUILDER_SHA,
                  'independent_csv_sha256': {name: sha(second / name) for name in TABLES},
                  'note': 'Local review draft only; no Drive publication or independent-method validation.'}
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        result = {'status': 'failed', 'output': str(root), 'error': str(exc)}
    atomic_state(state_path, result)
    print(json.dumps({'status': result['status'], 'output': str(root)}), flush=True)
    return {'started': True, **result}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'database', 'aggregate-state', 'day-state', 'aggregate', 'day-code', 'builder', 'python', 'state-dir'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--interval', type=int, default=60)
    p.add_argument('--timeout', type=int, default=1800)
    args = p.parse_args()
    if args.interval < 10 or args.timeout < 30:
        p.error('Use a poll interval >=10 seconds and per-process timeout >=30 seconds')
    args.state_dir.mkdir(parents=True, exist_ok=True)
    state_path = args.state_dir / 'day-report-state.json'
    with (args.state_dir / 'day-report.lock').open('a+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Another watcher holds the lock', flush=True)
            return 0
        if read_state(state_path)['status'] in LOCAL_TERMINAL:
            print('Existing marker requires inspection; no duplicate', flush=True)
            return 0
        try:
            if not args.python.is_file():
                raise ValueError('NumPy-capable Python is unavailable')
            if any(sha(p) != h for p, h in ((args.manifest, MANIFEST_SHA), (args.aggregate, AGGREGATE_SHA),
                                             (args.day_code, DAY_SHA), (args.builder, BUILDER_SHA))):
                raise ValueError('Pinned input or source hash differs')
            while True:
                agg, day = read_state(args.aggregate_state), read_state(args.day_state)
                paths = upstream(agg, day)
                if paths is None:
                    atomic_state(state_path, {'status': 'waiting', 'watcher_pid': os.getpid(),
                                              'aggregate_status': agg.get('status'), 'day_status': day.get('status')})
                    time.sleep(args.interval)
                    continue
                result = run_once(args, *paths, state_path)
                return 0 if result.get('status') == 'complete' else 1
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
            atomic_state(state_path, {'status': 'verification_failed', 'watcher_pid': os.getpid(), 'error': str(exc)})
            print('Watcher stopped for inspection:', str(exc), flush=True)
            return 1


if __name__ == '__main__':
    raise SystemExit(main())
