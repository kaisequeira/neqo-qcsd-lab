"""HOST reader fixtures over genuine retained q080/q082 GET and q083 authority.

The new audit operation's process stdout is a fixture; it grants no admission,
site, or trace credit. Original Native GET and prepared graphs are real files.
"""
from copy import deepcopy
from pathlib import Path
import json
import os
import sys

import pytest

from qcsd_lab import rapid_selected_budget_input as selected
from qcsd_lab import rapid_selected_capture_input as plain
from qcsd_lab import rapid_per_class_selected_enrollment as ledger
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab import supplied_static_graph as graph

W = (Path(os.environ['QCSD_HISTORICAL_EVIDENCE_ROOT'])
     if 'QCSD_HISTORICAL_EVIDENCE_ROOT' in os.environ else
     next((p for p in Path(__file__).resolve().parents if (p / 'diagnostic-rehearsals').is_dir()),
          Path(__file__).resolve().parents[1]))
CASE = W / 'diagnostic-rehearsals/supplied-static87-budget64-context-20261005-001'
HOST = W / 'diagnostic-worktrees/completed-get-preparation-deferral-lab-authoring-20261007-002'
AUTH = W / 'diagnostic-rehearsals/completed-get-preparation-deferral-host-checks-20261007-002'
OLD_INPUT = W / ('diagnostic-rehearsals/per-class-admitted-supplied-tail-q080-q087-root-actual-20261007-001/'
    'inputs/static-3a8968539028ad0c6c3a7f7dd7fefab48512548cd197b3764c68f5460b3d3058.json')
POLICY = W / ('diagnostic-rehearsals/selected-additive-and-per-class-classes017-021-v29-root-actual-20261006-001/'
    'per-class-study-002')
ACTUAL_TARGET34 = W / 'diagnostic-rehearsals/fixed-target-enrollment34-root-actual-20261007-001/target.json'
if not all(path.is_file() for path in (OLD_INPUT, ACTUAL_TARGET34,
        POLICY / 'policy.json', CASE / 'attempts/candidate-000082/terminal.json',
        AUTH / 'host-accounting-authority.json', AUTH / 'source-inventory.json')) or not HOST.is_dir():
    pytest.skip('historical read-only receipt oracle is not installed', allow_module_level=True)


def write(path, value):
    path.write_bytes(graph.canonical_bytes(value))
    return path


@pytest.fixture()
def q082_v3_audit(tmp_path):
    # The q082 complete GET/terminal/manifest are genuine.  The newly authored
    # audit subprocess result is explicitly a fixture, not an actual operation.
    terminal = CASE / 'attempts/candidate-000082/terminal.json'
    t = receipts._unpack(terminal.read_bytes(), selected.budget.TERMINAL_TYPE)
    manifest_path = selected.original.open_reference(t['prepared_workload'])
    manifest = json.loads(manifest_path.read_bytes())
    context = receipts._unpack((CASE / 'provenance.json').read_bytes(), selected.budget.CONTEXT_TYPE)
    active_path = selected.original.open_reference(context['prospective_context'])
    active = receipts._unpack(active_path.read_bytes(), selected.budget.static.PROVENANCE_TYPE)
    candidate = active['candidates'][81]
    assert t['candidate_id'] == candidate['candidate_id']
    row = {'candidate': candidate, 'manifest': selected.original.reference(manifest_path),
        'terminal': selected.original.reference(terminal), 'context': selected.original.reference(CASE / 'provenance.json'),
        'capture_limits': manifest['preparation'][selected.budget.FIELD]['capture_limits'],
        'facts': {'candidate_id': candidate['candidate_id'], 'outcome': 'admitted'}, 'scientific_credit': False}
    authority = plain.reference(AUTH / 'host-accounting-authority.json')
    inventory = plain.reference(AUTH / 'source-inventory.json')
    started = {'schema_version': 1, 'command': [sys.executable, '-I', '-B', '-c', selected._AUDIT_PROGRAM_V3,
        str(HOST), str(CASE), str(terminal)], 'started_at': '2026-10-06T00:00:01+00:00',
        'source_inventory': inventory, 'host_authority': authority,
        'context': plain.reference(CASE / 'provenance.json'), 'terminal': plain.reference(terminal)}
    start = write(tmp_path / 'audit-started.json', started)
    stdout = write(tmp_path / 'audit.stdout.log', row)
    stderr = tmp_path / 'audit.stderr.log'
    stderr.write_bytes(b'')
    completed = {'schema_version': 1, 'returncode': 0, 'elapsed_seconds': 1.0,
        'completed_at': '2026-10-06T00:00:02+00:00', 'started': plain.reference(start),
        'stdout': plain.reference(stdout), 'stderr': plain.reference(stderr)}
    end = write(tmp_path / 'audit-completed.json', completed)
    audit = {'contract': selected.CONTRACT, 'source_root': str(HOST), 'source_inventory': inventory,
        'host_authority': authority, 'program_sha256': graph.digest(selected._AUDIT_PROGRAM_V3.encode()),
        'result': row, 'started': plain.reference(start), 'completed': plain.reference(end),
        'stdout': plain.reference(stdout), 'stderr': plain.reference(stderr),
        'published_at': '2026-10-06T00:00:03+00:00', 'scientific_credit': False}
    path = write(tmp_path / 'selection-audit.json', receipts._bind(selected.AUDIT_TYPE, audit))
    return path, audit, candidate, manifest, tmp_path


def test_historical_q080_receipt_and_policy_survive_exact_dual_reader():
    value, row = selected.input_metadata(plain.reference(OLD_INPUT))
    assert value['candidate_id'] == row['candidate']['candidate_id']
    assert value['direct_validator_sources'][selected.__name__] == selected.LEGACY_SELECTED_SOURCE_SHA256
    policy = ledger.verify_policy(POLICY)
    assert policy['implementation_sources'][selected.__name__] == selected.LEGACY_SELECTED_SOURCE_SHA256
    assert policy['class_target'] == 50 and policy['formal_trace_target'] == 16000


def test_v3_q082_fixture_retains_actual_full_graph_caps_and_zero_credit(q082_v3_audit):
    path, _, candidate, manifest, tmp = q082_v3_audit
    audited = selected.read_audit(path)
    assert audited['host_authority']['sha256'] == selected.V3_HOST_AUTHORITY_SHA256
    receipt = selected.publish_input(tmp / 'new-input.json', audit=path, candidate_id=candidate['candidate_id'])
    value, raw, proof = selected.validate_input(receipt)
    assert raw == manifest and proof['full_list_coverage'] is True
    assert proof['resource_count'] == len(raw['resources'])
    assert value['capture_limits']['max_response_bytes'] == 64 * 1024 * 1024
    assert value['capture_limits']['capture_megabytes'] == 256
    assert value['formal_accepted_trace_count'] == 0 and value['scientific_credit'] is False
    prepared = selected.prepare_input(receipt, tmp / (value['workload_id'] + '.json'))
    assert json.loads(prepared.read_bytes())['resources'] == raw['resources']


@pytest.mark.parametrize('field', ['host_authority', 'program_sha256', 'source_inventory'])
def test_v3_audit_rehashed_authority_program_or_inventory_refuses(q082_v3_audit, field):
    _, audit, _, _, tmp = q082_v3_audit
    changed = deepcopy(audit)
    if field == 'program_sha256':
        changed[field] = graph.digest(selected._AUDIT_PROGRAM.encode())
    else:
        changed[field] = plain.reference(OLD_INPUT)
    path = write(tmp / (field + '-changed.json'), receipts._bind(selected.AUDIT_TYPE, changed))
    with pytest.raises(ValueError):
        selected.read_audit(path)


def test_v3_audit_cannot_claim_historical_direct_verifier(q082_v3_audit):
    path, _, candidate, _, tmp = q082_v3_audit
    receipt = selected.publish_input(tmp / 'new-input.json', audit=path, candidate_id=candidate['candidate_id'])
    payload = receipts._unpack(receipt.read_bytes(), selected.RECEIPT_TYPE)
    payload['direct_validator_sources'][selected.__name__] = selected.LEGACY_SELECTED_SOURCE_SHA256
    changed = write(tmp / 'old-source-claimed.json', receipts._bind(selected.RECEIPT_TYPE, payload))
    with pytest.raises(ValueError):
        selected.validate_input(changed)


def test_actual_target34_reader_sources_accept_exact_dual_selected_code():
    actual = json.loads(ACTUAL_TARGET34.read_bytes())['payload']
    assert len(actual['classes']) == 34
    assert target._compatible_sources(actual['sources']) is True
    assert target._compatible_sources(target._sources()) is True
    old = actual['sources']['target']
    current = target.reference(Path(target.__file__))
    assert target._compatible_code_ref('target', old, current) is True


def test_target34_reader_refuses_scientific_or_selected_source_mutation(tmp_path):
    actual = json.loads(ACTUAL_TARGET34.read_bytes())['payload']
    old = actual['sources']['target']
    changed_target = Path(tmp_path / 'rapid_fixed_condition_target.py')
    changed_target.write_bytes(Path(target.__file__).read_bytes() + b'\nTOTAL = -1\n')
    with pytest.raises(ValueError):
        target._compatible_code_ref('target', old, target.reference(changed_target))
    changed_selected = Path(tmp_path / 'rapid_per_class_selected_enrollment.py')
    changed_selected.write_bytes(Path(ledger.__file__).read_bytes() + b'\n# outside the reviewed source hash\n')
    with pytest.raises(ValueError):
        target._compatible_selected_membership_code(
            'src/qcsd_lab/rapid_per_class_selected_enrollment.py',
            actual['sources']['budgets'], target.reference(changed_selected))
