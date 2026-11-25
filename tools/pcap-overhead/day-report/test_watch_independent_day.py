"""Synthetic tests only. No packet data, credentials or Drive are accessed."""
import contextlib
import fcntl
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import watch_independent_day as watcher


class GateTests(unittest.TestCase):
    def test_waits_for_both_upstream_processes(self):
        self.assertIsNone(watcher.upstream({'status': 'waiting'}, {'status': 'waiting'}))
        self.assertIsNone(watcher.upstream({'status': 'complete'}, {'status': 'waiting'}))

    def test_failure_is_not_hidden_behind_other_waiting_job(self):
        with self.assertRaisesRegex(ValueError, 'day requires review'):
            watcher.upstream({'status': 'waiting'}, {'status': 'failed'})
        with self.assertRaisesRegex(ValueError, 'aggregate requires review'):
            watcher.upstream({'status': 'failed'}, {'status': 'waiting'})

    def test_completed_missing_directory_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unavailable'):
            watcher.upstream({'status': 'complete', 'output': '/nonexistent/synthetic'},
                             {'status': 'complete', 'output': '/nonexistent/synthetic2'})

    def test_waiting_status_and_atomic_state_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'state.json'
            self.assertEqual(watcher.read_state(path)['status'], 'not_started')
            watcher.atomic_state(path, {'status': 'waiting', 'watcher_pid': 123})
            self.assertEqual(watcher.read_state(path)['watcher_pid'], 123)

    def test_environment_mismatch_rejected(self):
        fake = SimpleNamespace(stdout=json.dumps(['3.14.4', '2.3.5']))
        with mock.patch.object(watcher.subprocess, 'run', return_value=fake):
            watcher.matching_environment('python', {'python_version': '3.14.4 (test)', 'numpy_version': '2.3.5'})
            with self.assertRaisesRegex(ValueError, 'version differs'):
                watcher.matching_environment('python', {'python_version': '3.9.0 (test)', 'numpy_version': '2.3.5'})

    def test_exclusive_lock_rejects_duplicate_watcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (root/'day-report.lock').open('a+') as locked:
                fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with (root/'day-report.lock').open('a+') as second:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)


class RunOnceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.agg = self.root/'agg'; self.agg.mkdir()
        self.day = self.root/'day'; self.day.mkdir()
        self.quality = self.agg/'quality.json'; self.quality.write_text('synthetic quality')
        self.first = self.day/watcher.TABLES[0]; self.first.write_text('synthetic original')
        self.builder = self.root/'builder'; self.builder.write_text('synthetic builder')
        self.args = SimpleNamespace(state_dir=self.root, python=Path('python'), builder=self.builder,
            day_code=Path('day'), manifest=Path('manifest'), database=Path('database'),
            aggregate=Path('aggregate'), timeout=30)
        self.state = self.root/'state.json'
        self.proof = {'python_version': '3.14.4 (test)', 'numpy_version': '2.3.5',
                      'bootstrap_replicates': 2000, 'seed': 7}
        self.hashes = {str(self.quality): watcher.sha(self.quality), str(self.first): watcher.sha(self.first)}
        self.check = mock.patch.object(watcher, 'checked_inputs', return_value=(self.proof, self.hashes))
        self.env = mock.patch.object(watcher, 'matching_environment')
        self.pin = mock.patch.object(watcher, 'BUILDER_SHA', watcher.sha(self.builder))
        for patcher in (self.check, self.env, self.pin):
            patcher.start(); self.addCleanup(patcher.stop)

    def successful_runner(self, command, **kwargs):
        output = Path(command[command.index('--output') + 1])
        if '--independent-day-output' in command:
            output.write_text('# Exploratory UTC-day cluster sensitivity — review draft\n')
        else:
            output.mkdir()
            for name in watcher.TABLES:
                (output/name).write_text('synthetic independently generated output')
        return SimpleNamespace(returncode=0, stderr='')

    def run_once(self, runner=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return watcher.run_once(self.args, self.agg, self.day, self.state,
                                    runner=runner or self.successful_runner)

    def test_new_execution_then_draft_then_at_most_once(self):
        calls = []
        def capture(command, **kwargs):
            calls.append(command)
            return self.successful_runner(command, **kwargs)
        result = self.run_once(capture)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1], 'day')
        self.assertEqual(calls[1][1], str(self.builder))
        self.assertEqual(watcher.read_state(self.state)['status'], 'complete')
        self.assertFalse(self.run_once()['started'])

    def test_rerun_failure_does_not_launch_draft(self):
        calls = []
        def fail(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=1, stderr='synthetic error')
        result = self.run_once(fail)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(len(calls), 1)

    def test_input_change_during_rerun_stops_draft(self):
        calls = []
        def changed(command, **kwargs):
            calls.append(command)
            self.quality.write_text('changed')
            return self.successful_runner(command, **kwargs)
        result = self.run_once(changed)
        self.assertEqual(result['status'], 'failed')
        self.assertIn('changed', result['error'])
        self.assertEqual(len(calls), 1)

    def test_timeout_is_failure_and_no_false_completion(self):
        def timeout(command, **kwargs):
            raise subprocess.TimeoutExpired(command, 30)
        result = self.run_once(timeout)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(watcher.read_state(self.state)['status'], 'failed')

    def test_previous_start_is_not_reused(self):
        watcher.atomic_state(self.state, {'status': 'started'})
        self.assertFalse(self.run_once()['started'])


class InputChecksTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.agg_dir = self.root/'agg-results'; self.agg_dir.mkdir()
        self.day_dir = self.root/'day-results'; self.day_dir.mkdir()
        self.manifest = self.root/'manifest'; self.manifest.write_bytes(b'synthetic manifest')
        self.aggregate = self.root/'aggregate'; self.aggregate.write_bytes(b'synthetic aggregate')
        self.day_code = self.root/'day-code'; self.day_code.write_bytes(b'synthetic day code')
        self.builder = self.root/'builder'; self.builder.write_bytes(b'synthetic builder')
        self.args = SimpleNamespace(manifest=self.manifest, aggregate=self.aggregate,
                                    day_code=self.day_code, builder=self.builder)
        self.metric = 'b'*64
        self.m, self.a = watcher.sha(self.manifest), watcher.sha(self.aggregate)
        self.d, self.b = watcher.sha(self.day_code), watcher.sha(self.builder)
        self.quality = {'status': 'complete', 'manifest_sessions': 120000,
                        'accepted_metric_rows': 120000, 'extractor_errors': 0,
                        'identity_or_other_flags': {}, 'manifest_sha256': self.m,
                        'analysis_script_sha256': self.a, 'metric_rows_content_sha256': self.metric}
        self.proof = {'status': 'complete', 'metric_rows': 120000, 'manifest_sha256': self.m,
                      'aggregate_code_sha256': self.a, 'bootstrap_code_sha256': self.d,
                      'metric_rows_content_sha256': self.metric, 'bootstrap_replicates': 2000,
                      'seed': 7, 'numpy_version': 'synthetic', 'python_version': '3.9.1 (synthetic)'}
        (self.agg_dir/'quality.json').write_text(json.dumps(self.quality))
        (self.day_dir/'utc-day-cluster-provenance.json').write_text(json.dumps(self.proof))
        for name in watcher.TABLES:
            (self.day_dir/name).write_text('synthetic,not,study,data\n')
        for name, value in [('MANIFEST_SHA', self.m), ('AGGREGATE_SHA', self.a),
                            ('DAY_SHA', self.d), ('BUILDER_SHA', self.b)]:
            patcher = mock.patch.object(watcher, name, value)
            patcher.start(); self.addCleanup(patcher.stop)

    def check(self):
        return watcher.checked_inputs(self.args, self.agg_dir, self.day_dir)

    def test_complete_pinned_inputs_pass(self):
        proof, hashes = self.check()
        self.assertEqual(proof['seed'], 7)
        self.assertEqual(len(hashes), 4)

    def test_incomplete_quality_stops_rerun(self):
        self.quality['accepted_metric_rows'] = 119999
        (self.agg_dir/'quality.json').write_text(json.dumps(self.quality))
        with self.assertRaisesRegex(ValueError, 'not a complete'):
            self.check()

    def test_wrong_metric_snapshot_stops_rerun(self):
        self.proof['metric_rows_content_sha256'] = 'c'*64
        (self.day_dir/'utc-day-cluster-provenance.json').write_text(json.dumps(self.proof))
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.check()

    def test_modified_builder_stops_rerun(self):
        self.builder.write_text('changed')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.check()

    def test_symlinked_upstream_table_stops_rerun(self):
        name = watcher.TABLES[0]
        (self.day_dir/name).unlink()
        (self.day_dir/name).symlink_to(self.day_dir/watcher.TABLES[1])
        with self.assertRaisesRegex(ValueError, 'symlinked'):
            self.check()


if __name__ == '__main__':
    unittest.main()
