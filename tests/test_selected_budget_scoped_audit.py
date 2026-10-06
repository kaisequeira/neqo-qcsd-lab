"""Scoped audit controls; subprocess receipt fixtures never grant admission.

The HOST authentication control reopens the real reviewed inventory/authority
without replaying a prefix or executing GET. The separate actual q087 check is
recorded outside the source tree after these controls pass.
"""
from copy import deepcopy
from pathlib import Path
import json
import subprocess
import sys

import pytest

from qcsd_lab import rapid_selected_budget_input as selected
from qcsd_lab import rapid_selected_capture_input as plain
from qcsd_lab import rapid_per_class_selected_enrollment as ledger
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab import supplied_static_graph as graph
from .test_selected_budget_v3_dual_reader import AUTH, HOST, CASE, W, q082_v3_audit, write


def test_literal_historical_programs_and_original_core_are_unchanged():
    assert graph.digest(selected._AUDIT_PROGRAM.encode()) == '814951fcdc35ecaff577ff79c7330e4b7a7c6263fda82871c043bf15846bc2ca'
    assert graph.digest(selected._AUDIT_PROGRAM_V3.encode()) == '8b6698a961923ad912288f2b1d7c62d957fe68eb953b5edb917da66a1435a63f'
    assert graph.digest(Path(selected.budget.__file__).read_bytes()) == 'a297fd337517ddffc30fc6e08b5961e2556f9311cbe5f7837baa0209bcf298d1'
    assert selected._AUDIT_PROGRAM_V3_SCOPED != selected._AUDIT_PROGRAM_V3


def scoped_fixture(q082_v3_audit):
    _, audit, _, _, tmp = q082_v3_audit
    value = deepcopy(audit)
    started = json.loads(plain.reopen(value['started']).read_bytes())
    started['command'][4] = selected._AUDIT_PROGRAM_V3_SCOPED
    started['command'].extend([value['source_inventory']['path'], value['source_inventory']['sha256'],
                              value['host_authority']['path'], value['host_authority']['sha256']])
    return value, started, tmp


def close_fixture(value, started, tmp, name):
    start = write(tmp / (name + '-started.json'), started)
    completed = json.loads(plain.reopen(value['completed']).read_bytes())
    completed['started'] = plain.reference(start)
    end = write(tmp / (name + '-completed.json'), completed)
    value.update(program_sha256=graph.digest(selected._AUDIT_PROGRAM_V3_SCOPED.encode()),
                 started=plain.reference(start), completed=plain.reference(end))
    return write(tmp / (name + '.json'), receipts._bind(selected.AUDIT_TYPE, value))


def test_writer_binds_scoped_arguments_and_reader_keeps_old_v3(q082_v3_audit, monkeypatch):
    old_path, audit, _, _, tmp = q082_v3_audit
    assert selected.read_audit(old_path)['program_sha256'] == graph.digest(selected._AUDIT_PROGRAM_V3.encode())
    original_run = subprocess.run
    seen = []

    def boundary(command, **kwargs):
        if command[:4] == [sys.executable, '-I', '-B', '-c']:
            seen.append(command)
            return subprocess.CompletedProcess(command, 0, graph.canonical_bytes(audit['result']), b'')
        return original_run(command, **kwargs)

    monkeypatch.setattr(selected.subprocess, 'run', boundary)
    path = selected.audit_budget(tmp / 'writer-fixture', source_root=HOST,
        source_inventory=audit['source_inventory'], host_authority=audit['host_authority'],
        context=CASE, terminal=Path(audit['result']['terminal']['path']))
    result = selected.read_audit(path)
    assert len(seen) == 1 and len(seen[0]) == 12
    assert seen[0][4] == selected._AUDIT_PROGRAM_V3_SCOPED
    assert seen[0][8:] == [audit['source_inventory']['path'], audit['source_inventory']['sha256'],
                          audit['host_authority']['path'], audit['host_authority']['sha256']]
    assert result['result'] == audit['result'] and result['scientific_credit'] is False


@pytest.mark.parametrize('change', ['omit-authority', 'inventory-path', 'inventory-hash',
                                  'authority-path', 'authority-hash', 'old-program'])
def test_rehashed_scoped_receipt_requires_exact_owned_arguments(q082_v3_audit, change):
    value, started, tmp = scoped_fixture(q082_v3_audit)
    if change == 'omit-authority':
        started['command'] = started['command'][:10]
    elif change == 'old-program':
        started['command'][4] = selected._AUDIT_PROGRAM_V3
    else:
        index = {'inventory-path': 8, 'inventory-hash': 9, 'authority-path': 10, 'authority-hash': 11}[change]
        started['command'][index] = str(tmp / 'unowned.json') if index % 2 == 0 else '0' * 64
    path = close_fixture(value, started, tmp, change)
    with pytest.raises(ValueError, match='command'):
        selected.read_audit(path)


def host_scope_control():
    # This uses the actual authentication/action code from the new program.
    # Only its expensive downstream context body is replaced by scope probes.
    program = selected._AUDIT_PROGRAM_V3_SCOPED
    prefix = program[:program.index('        context=b.load_context')]
    suffix = program[program.index('\n    if set(files)'):]
    return prefix + '''        assert typed._ACTIVE.get() is True
        assert bootstrap._HOST_ACCOUNTING.get() is not None
        assert bootstrap._recognized_producer_sources(dict(bootstrap.RETAINED_PRODUCER_SOURCES))
''' + suffix + '''
assert typed._ACTIVE.get() is False
assert bootstrap._HOST_ACCOUNTING.get() is None
assert observed._ACTIVE.get() is None
print(json.dumps({"authority_entered_and_closed":True,"prefix_replayed":False,"scientific_credit":False}))
'''


@pytest.mark.parametrize('authority', ['exact', 'wrong-hash', 'wrong-file'])
def test_actual_host_authority_scope_authenticates_before_prefix_and_closes(authority):
    inventory = plain.reference(AUTH / 'source-inventory.json')
    ref = plain.reference(AUTH / 'host-accounting-authority.json')
    if authority == 'wrong-hash':
        ref['sha256'] = '0' * 64
    if authority == 'wrong-file':
        ref = inventory
    command = [sys.executable, '-I', '-B', '-c', host_scope_control(), str(HOST), str(CASE),
               str(CASE / 'attempts/candidate-000087/terminal.json'), inventory['path'], inventory['sha256'],
               ref['path'], ref['sha256']]
    result = subprocess.run(command, capture_output=True, check=False)
    if authority == 'exact':
        assert result.returncode == 0, result.stderr.decode()
        assert json.loads(result.stdout) == {'authority_entered_and_closed': True, 'prefix_replayed': False,
                                             'scientific_credit': False}
    else:
        assert result.returncode != 0 and result.stdout == b''
        assert b'load_context' not in result.stderr


def test_v3_policy_and_input_reader_identity_survive_without_promoting_new_program(q082_v3_audit):
    old_path, audit, candidate, _, tmp = q082_v3_audit
    v3_policy = {**ledger._sources(), selected.__name__: selected.V3_SELECTED_SOURCE_SHA256,
                 ledger.__name__: '048c0766e3a68d198547f26f4516d4337665c58163c1b6fc1ee1870b9808dc52'}
    assert ledger._policy_sources(v3_policy) is True
    receipt = selected.publish_input(tmp / 'v3-fixture-input.json', audit=old_path, candidate_id=candidate['candidate_id'])
    payload = receipts._unpack(receipt.read_bytes(), selected.RECEIPT_TYPE)
    source = W / 'rapid-execution-selected-budget-v3-reader-v35-20261007/src/qcsd_lab/rapid_selected_budget_input.py'
    payload['direct_validator_sources'][selected.__name__] = selected.V3_SELECTED_SOURCE_SHA256
    payload['direct_validator_files'][selected.__name__] = plain.reference(source)
    old_input = write(tmp / 'retained-v3-input.json', receipts._bind(selected.RECEIPT_TYPE, payload))
    assert selected.validate_input(old_input)[0]['scientific_credit'] is False
    value, started, _ = scoped_fixture(q082_v3_audit)
    new_audit = close_fixture(value, started, tmp, 'scoped-input-fixture')
    payload['selection_audit'] = plain.reference(new_audit)
    changed = write(tmp / 'old-source-new-program.json', receipts._bind(selected.RECEIPT_TYPE, payload))
    with pytest.raises(ValueError, match='earlier unscoped'):
        selected.validate_input(changed)


@pytest.mark.parametrize('name', ['rapid_selected_budget_input', 'rapid_per_class_selected_enrollment'])
def test_finite_source35_reader_pair_and_unknown_changed_code(name, tmp_path):
    before = W / 'rapid-execution-selected-budget-v3-reader-v35-20261007/src/qcsd_lab' / (name + '.py')
    after = Path(selected.__file__).parent / (name + '.py')
    relative = 'src/qcsd_lab/' + name + '.py'
    assert target._compatible_selected_membership_code(relative, target.reference(before), target.reference(after)) is None
    changed = tmp_path / (name + '.py')
    changed.write_bytes(after.read_bytes() + b'\nUNKNOWN_READER = True\n')
    with pytest.raises(ValueError, match='exact reviewed'):
        target._compatible_selected_membership_code(relative, target.reference(before), target.reference(changed))


def test_original_native_client_guard_and_other_scientific_units_remain_exact():
    before = W / 'rapid-execution-selected-budget-v3-reader-v35-20261007/src/qcsd_lab/rapid_fixed_condition_target.py'
    assert target._reader_code_projection(before.read_bytes(), 'target') == target._reader_code_projection(
        Path(target.__file__).read_bytes(), 'target')
