"""Portable HOST controls; original GET/raw/install/deep boundaries controlled.

Real public target policy/plan, dependency selectors, file/tree fences, worker
guards and formal prepare run. No fixture authorizes an image or scientific row.
"""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from qcsd_lab import rapid_target_parallel_schedule as workers
from qcsd_lab import rapid_target_chunks as chunks
from qcsd_lab import rapid_ordinary_parallel_schedule as old_workers
from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab.rapid_operation_facts import OperationFacts, current_context
from tests.test_rapid_target_parallel import pair, _REAL_BIND_CAPTURE
from tests.test_rapid_target_chunks import case
from tests.test_rapid_ordinary_parallel import current


def test_real_pair_reuses_one_serial_proof_and_selector_without_mutable_or_cross_action_facts(pair, monkeypatch):
    case, spec, sites, payload, chosen, reference = pair
    counts = {'serial': 0, 'inputs': 0}
    original_serial, original_inputs = chunks.verify_plan, old_workers.input_dependencies
    def serial(*args, **kwargs):
        counts['serial'] += 1
        return original_serial(*args, **kwargs)
    def inputs(*args, **kwargs):
        counts['inputs'] += 1
        return original_inputs(*args, **kwargs)
    monkeypatch.setattr(chunks, 'verify_plan', serial)
    monkeypatch.setattr(old_workers, 'input_dependencies', inputs)
    context = OperationFacts(); context.begin_action()
    base = workers._spec(payload[workers.BASE_FIELD])
    with context.scope():
        capsule = workers.require_plan(payload)
        capsule['capture_limits']['max_attempts'] = -1
        assert workers.require_plan(payload)['capture_limits'] == payload['capture_limits']
        returned_sites, returned_plan = workers._base(base)
        returned_plan['lanes'].clear()
        assert workers._base(base)[1]['lanes']
        files, trees = workers.input_dependencies(base, sites)
        expected_files, expected_trees = set(files), set(trees)
        files.clear(); trees.clear()
        assert workers.input_dependencies(base, sites) == (expected_files, expected_trees)
        workers.bind_dependencies(workers.require_plan(payload), context)
        for lane in chosen:
            assert len(workers.require_worker(payload, lane, sites, spec)) == 16 * len(sites)
        workers.require_disjoint([(spec, payload, lane, sites) for lane in chosen])
        with pytest.raises(ValueError, match='repeat'):
            workers.require_disjoint([(spec, payload, chosen[0], sites)] * 2)
        with pytest.raises(ValueError, match='registered'):
            workers.require_worker(payload, replace(chosen[0], mode='tamaraw'), sites, spec)
        changed = deepcopy(payload); changed['capture_limits']['max_attempts'] = -1
        with pytest.raises(ValueError, match='serial authority'):
            workers.require_plan(changed)
        assert counts == {'serial': 1, 'inputs': 1}
        assert expected_files <= set(context._files)
        assert expected_trees <= {path for path, _ in context._trees}
        context.check()
        context.begin_action()
        workers.require_plan(payload)
        assert counts == {'serial': 2, 'inputs': 2}
        context.check()


def test_cached_pair_closes_bytes_full_modes_tree_membership_source_and_ref_changes(pair, monkeypatch):
    case, spec, sites, payload, chosen, reference = pair
    # Original enrollment semantics remain controlled; the full production
    # capture binder and Source/raw membership observations run unchanged.
    monkeypatch.setattr(OperationFacts, '_enrollment', lambda self, path: self.watch_file(path))
    monkeypatch.setattr(OperationFacts, 'bind_capture', _REAL_BIND_CAPTURE)
    context = OperationFacts(); context.begin_action()
    with context.scope():
        original = workers.require_plan(payload)
        path = Path(case.inputs_ref['path'])
        raw, mode = path.read_bytes(), path.stat().st_mode & 0o7777
        for change in ('bytes', 'mode'):
            try:
                if change == 'bytes': path.write_bytes(raw + b' ')
                else: path.chmod(mode ^ 0o100)
                assert workers.require_plan(payload)['condition_sha256'] == original['condition_sha256']
                with pytest.raises(ValueError, match='dependency bytes or mode'):
                    context.check()
            finally:
                path.write_bytes(raw); path.chmod(mode)
        tree = case.current.raw_root
        extra = tree / 'unregistered-member.json'
        tree_mode = tree.stat().st_mode & 0o7777
        try:
            extra.write_bytes(b'added after the first validated selector')
            workers.require_plan(payload)
            with pytest.raises(ValueError, match='tree bytes, mode or membership'):
                context.check()
        finally: extra.unlink()
        try:
            tree.chmod(tree_mode ^ 0o020)
            with pytest.raises(ValueError, match='tree bytes, mode or membership'):
                context.check()
        finally: tree.chmod(tree_mode)
        extra_source = case.source / 'src/qcsd_lab/new_unbound_reader.py'
        try:
            extra_source.write_bytes(b'added after the Source inventory observation')
            workers.require_plan(payload)
            with pytest.raises(ValueError, match='tree bytes, mode or membership'):
                context.check()
        finally: extra_source.unlink()
        reader = case.source / 'src/qcsd_lab/rapid_target_parallel_schedule.py'
        raw, mode = reader.read_bytes(), reader.stat().st_mode & 0o7777
        for change in ('bytes', 'mode'):
            try:
                if change == 'bytes': reader.write_bytes(raw + b'\n')
                else: reader.chmod(mode ^ 0o100)
                with pytest.raises(ValueError, match='changed during validation'):
                    workers.require_plan(payload)
            finally:
                reader.write_bytes(raw); reader.chmod(mode)
        changed = deepcopy(payload); changed['scheduling']['sha256'] = '0' * 64
        with pytest.raises(ValueError): workers.require_plan(changed)
        context.check()


@pytest.mark.parametrize('change', ['none', 'spec-bytes', 'spec-mode', 'input-bytes', 'tree-member'])
def test_prepare_reuses_same_path_spec_and_one_image_check_but_fences_before_first_intent(change, pair, monkeypatch):
    case, spec, sites, payload, chosen, reference = pair
    spec_path = case.current.root / 'memo-worker-spec.json'
    rolling._write_spec(spec_path, spec)
    root = case.current.root / 'memo-worker-evidence'; root.mkdir()
    counts = {'loads': 0, 'image_checks': 0, 'intents': 0}
    real_load = lanes.load_capture_spec
    def load(path):
        counts['loads'] += 1
        result = real_load(path)
        if change == 'spec-bytes': path.write_bytes(path.read_bytes() + b' ')
        elif change == 'spec-mode': path.chmod((path.stat().st_mode & 0o7777) ^ 0o100)
        return result
    def image_check(*args, **kwargs):
        counts['image_checks'] += 1
        return {'proof': {'plan_payload': payload, 'cohort_generation': 'rolling-50'}}
    def lineage(*args, **kwargs):
        if change == 'input-bytes':
            path = Path(case.inputs_ref['path']); path.write_bytes(path.read_bytes() + b' ')
        elif change == 'tree-member':
            (case.current.raw_root / 'before-intent-new-member.json').write_bytes(b'new raw member')
        return {'controlled_original_actor_boundary': True}
    class BeforeIntent(Exception): pass
    def intent(*args, **kwargs):
        counts['intents'] += 1
        raise BeforeIntent()
    monkeypatch.setattr(lanes, 'load_capture_spec', load)
    monkeypatch.setattr(lanes, 'check_bound_image', image_check)
    monkeypatch.setattr(lanes, '_validate_image_proof', lambda *args, **kwargs: sites)
    monkeypatch.setattr(lanes, '_lineage_payload', lineage)
    monkeypatch.setattr(lanes, 'prepare_lane_intent', intent)
    context = OperationFacts()
    with context.scope(), pytest.raises(BeforeIntent if change == 'none' else ValueError):
        formal.prepare_batch(spec_path, root, [lane.campaign_name for lane in chosen],
            case.current.root / 'memo-authority.json', _context=context)
    assert counts['loads'] == 1
    assert counts['image_checks'] == (0 if change.startswith('spec-') else 1)
    assert counts['intents'] == (1 if change == 'none' else 0)
    assert not (root / 'lanes').exists()
    assert not (case.current.root / 'memo-authority.json').exists()


def test_distinct_spec_paths_still_load_separately_and_preserve_one_image_check(pair, monkeypatch):
    case, spec, sites, payload, chosen, reference = pair
    first, second = case.current.root / 'first-spec.json', case.current.root / 'second-spec.json'
    rolling._write_spec(first, spec); second.write_bytes(first.read_bytes())
    root = case.current.root / 'different-spec-evidence'; root.mkdir()
    counts = {'loads': 0, 'checks': 0}
    original = lanes.load_capture_spec
    def load(path):
        counts['loads'] += 1
        return original(path)
    def check(*args, **kwargs):
        counts['checks'] += 1
        return {'proof': {'plan_payload': payload, 'cohort_generation': 'rolling-50'}}
    class BeforeIntent(Exception): pass
    monkeypatch.setattr(lanes, 'load_capture_spec', load)
    monkeypatch.setattr(lanes, 'check_bound_image', check)
    monkeypatch.setattr(lanes, '_validate_image_proof', lambda *args, **kwargs: sites)
    monkeypatch.setattr(lanes, '_lineage_payload', lambda *args, **kwargs: {})
    def stop(*args, **kwargs): raise BeforeIntent()
    monkeypatch.setattr(lanes, 'prepare_lane_intent', stop)
    context = OperationFacts()
    with context.scope(), pytest.raises(BeforeIntent):
        formal.prepare_batch(first, root, [lane.campaign_name for lane in chosen],
            case.current.root / 'different-spec-authority.json', second_spec=second, _context=context)
    assert counts == {'loads': 2, 'checks': 1}


@pytest.mark.parametrize('change', ['none', 'input-bytes', 'tree-member', 'source-mode'])
def test_cold_installed_plan_check_shares_initial_layout_action_and_final_fence(change, pair, monkeypatch):
    case, spec, sites, payload, chosen, reference = pair
    contexts, calls = [], []
    original = chunks.verify_plan
    def serial(*args, **kwargs):
        calls.append(current_context())
        return original(*args, **kwargs)
    def runtime_check(value):
        contexts.append(current_context())
        assert contexts[-1] is not None
        if change == 'input-bytes':
            path = Path(case.inputs_ref['path']); path.write_bytes(path.read_bytes() + b' ')
        elif change == 'tree-member':
            (case.current.raw_root / 'installed-check-new-member.json').write_bytes(b'new raw member')
        elif change == 'source-mode':
            path = case.source / 'src/qcsd_lab/rapid_target_parallel_schedule.py'
            path.chmod((path.stat().st_mode & 0o7777) ^ 0o100)
        return {'collection_image_digest': spec.collection_image_digest,
            'runtime_source': deepcopy(case.current.canonical['source']),
            'source_manifest_sha256': lanes._sha(spec.source_manifest.read_bytes()),
            'client_sha256': lanes._sha(spec.client_binary.read_bytes()),
            'base_launcher_sha256': lanes._sha(spec.base_launcher.read_bytes()),
            'host_launcher_sha256': lanes._sha(spec.host_launcher.read_bytes()),
            'qualification_implementation': {'controlled_original_installed_boundary': True},
            'traffic_hashes': {}}
    monkeypatch.setattr(chunks, 'verify_plan', serial)
    monkeypatch.setattr(lanes, 'executed_image_runtime_check', runtime_check)
    if change == 'none':
        result = lanes.executed_image_plan_check(spec.serializable())
        assert result['plan_payload'] == payload
        assert result['plan_payload']['scientific_credit'] is False
        assert len(calls) == 1 and calls[0] is contexts[0]
        # Another public image action does not inherit the previous memo.
        lanes.executed_image_plan_check(spec.serializable())
        assert len(calls) == 2 and calls[1] is contexts[1] and contexts[0] is not contexts[1]
    else:
        with pytest.raises(ValueError): lanes.executed_image_plan_check(spec.serializable())
        assert len(calls) == 1
    assert current_context() is None
