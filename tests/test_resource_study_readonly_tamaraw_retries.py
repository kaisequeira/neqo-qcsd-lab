"""Exact readonly-child seal rejection retries; no Native/scientific evidence.

The connected tests use the existing disposable SQLite coordinator fixture and
its synthetic twenty-response raw validator. They run real allocation, seal
failure retention, retry dispatch and ledger commit; no network is requested.
"""
from copy import deepcopy

import pytest

from qcsd_lab import resource_study as study
from tests.test_resource_study_tamaraw_retries import (
    POLICY, MISSING, EXTRA, ScriptedBackend, accepted_count, attempts, context,
    retry_cell, run, retry_study, controlled_validator,
)


def wrapped(reason):
    return f"readonly proof child refused: ValueError: {reason}\n"


class WrappedSealBackend(ScriptedBackend):
    """Only the existing seal-error fixture's transport string differs."""
    def __init__(self, root, scripts, reason):
        super().__init__(root, scripts)
        self.reason = reason

    def capture(self, worker, attempt, enrollment):
        result = super().capture(worker, attempt, enrollment)
        if attempt['attempt_id'] in self.seal_errors:
            self.seal_errors[attempt['attempt_id']] = wrapped(self.reason)
        return result


@pytest.mark.parametrize('reason', [MISSING, EXTRA])
def test_readonly_child_rejection_allocates_fresh_attempt_never_credits_failure(
        retry_study, monkeypatch, reason):
    root, store = retry_study
    backend = WrappedSealBackend(root, {'alpha.example': ['seal', 'pass']}, reason)
    result = run(root, backend, monkeypatch, budget=2)
    ids = [attempt['attempt_id'] for _, attempt in backend.calls]
    # On the unchanged donor the exact child wrapper pauses after one call.
    assert len(ids) == len(set(ids)) == 2
    assert [attempt['slot'] for _, attempt in backend.calls] == [1, 1]
    assert [(r[1], r[2]) for r in attempts(root)] == [('failed', 'failed'), ('accepted', None)]
    assert accepted_count(store, 'alpha.example', 'tamaraw') == 1
    assert result['paused_cells'] == []
    row = retry_cell(result)
    assert row['actual_retry_count'] == 1
    assert row['rejections'][0] == {
        'rejected_attempt_id': ids[0], 'reason': reason, 'retry_permitted': True,
        'fresh_attempt_id': ids[1], 'scientific_credit': False}
    failed = study.load(root / backend.calls[0][1]['path'] / 'failure.json')
    assert failed['reason'] == wrapped(reason) and failed['scientific_credit'] is False
    retained = root / 'failures/alpha.example/tamaraw' / ids[0]
    assert (retained / 'diagnostics/direct-quic-raw.pcapng').is_file()
    assert not (retained / 'session.json').exists()


@pytest.mark.parametrize('reason', [MISSING, EXTRA])
def test_child_wrapper_keeps_two_retry_cap_and_third_failure_pauses(
        retry_study, monkeypatch, reason):
    root, store = retry_study
    backend = WrappedSealBackend(root, {'alpha.example': ['seal'] * 3 + ['pass']}, reason)
    result = run(root, backend, monkeypatch, budget=8)
    assert len(backend.calls) == 3
    assert len({a['attempt_id'] for _, a in backend.calls}) == 3
    assert accepted_count(store, 'alpha.example', 'tamaraw') == 0
    assert result['paused_cells'] == [('alpha.example', 'tamaraw')]
    history = retry_cell(result)
    assert history['actual_retry_count'] == study.TAMARAW_MAX_RETRIES == 2
    assert [r['retry_permitted'] for r in history['rejections']] == [True, True, False]
    for _, attempt in backend.calls:
        failure = study.load(root / attempt['path'] / 'failure.json')
        assert failure['reason'] == wrapped(reason) and failure['scientific_credit'] is False


def test_child_wrapper_does_not_expand_total_attempt_budget(retry_study, monkeypatch):
    root, store = retry_study
    backend = WrappedSealBackend(root, {'alpha.example': ['seal', 'pass']}, MISSING)
    result = run(root, backend, monkeypatch, budget=1)
    assert len(backend.calls) == 1 and accepted_count(store, 'alpha.example', 'tamaraw') == 0
    assert retry_cell(result)['actual_retry_count'] == 0
    assert retry_cell(result)['retry_pending_without_allocation'] is True
    assert result['tamaraw_strict_rejection_retries']['attempt_budget'] == 1


@pytest.mark.parametrize('reason', [MISSING, EXTRA])
def test_only_seal_transport_is_normalized_and_plain_reasons_remain(reason):
    value = context()
    before = deepcopy(value)
    assert study.tamaraw_retry_reason('tamaraw', value, ValueError(reason),
        origin='seal', policy=POLICY) == reason
    assert study.tamaraw_retry_reason('tamaraw', value, ValueError(wrapped(reason)),
        origin='seal', policy=POLICY) == reason
    assert value == before
    collector = context(rejected=True, reason=wrapped(reason))
    assert study.tamaraw_retry_reason('tamaraw', collector, ValueError('collector rejected session'),
        origin='collector', policy=POLICY) is None


@pytest.mark.parametrize('text', [
    wrapped(MISSING).rstrip('\n'), wrapped(MISSING) + '\n',
    wrapped(MISSING).replace('\n', '\r\n'),
    wrapped(MISSING).replace('ValueError: ', 'RuntimeError: '),
    wrapped(MISSING).replace('readonly proof child refused: ', ''),
    wrapped(MISSING).replace('readonly proof child refused: ', 'readonly proof child refused:  '),
    wrapped(MISSING) + 'another failure\n',
    wrapped(MISSING).replace(MISSING, MISSING + ' '),
    wrapped('unknown proof failure'), 'ValueError: ' + MISSING + '\n',
])
def test_unknown_or_multiline_or_changed_wrapper_is_not_retryable(text):
    assert study.tamaraw_retry_reason('tamaraw', context(), ValueError(text),
        origin='seal', policy=POLICY) is None


@pytest.mark.parametrize('field,value', [
    ('success', False), ('runner_binding_valid', False), ('resource_error', 'changed client'),
    ('runner_returncode', False), ('runner_timed_out', True), ('runner_complete', False),
    ('endpoint_count_valid', False), ('process_scheduler_valid', False),
    ('scheduler_runtime_evidence_valid', False), ('operationally_valid', False),
    ('runner_error', 'another failure'), ('views', []), ('mode_policies', {}),
])
def test_exact_wrapper_never_overrides_existing_result_guards(field, value):
    result = context()
    result[field] = value
    assert study.tamaraw_retry_reason('tamaraw', result, ValueError(wrapped(MISSING)),
        origin='seal', policy=POLICY) is None


def test_wrong_type_mode_or_origin_does_not_gain_retry():
    class DerivedValueError(ValueError):
        pass
    for error in (RuntimeError(wrapped(MISSING)), TypeError(wrapped(MISSING)),
                  DerivedValueError(wrapped(MISSING))):
        assert study.tamaraw_retry_reason('tamaraw', context(), error,
            origin='seal', policy=POLICY) is None
    for mode in ('front', 'buflo', 'cs-buflo', 'undefended'):
        assert study.tamaraw_retry_reason(mode, context(), ValueError(wrapped(MISSING)),
            origin='seal', policy=POLICY) is None
    for origin in ('backend', 'commit', 'allocation', 'storage'):
        assert study.tamaraw_retry_reason('tamaraw', context(), ValueError(wrapped(MISSING)),
            origin=origin, policy=POLICY) is None
