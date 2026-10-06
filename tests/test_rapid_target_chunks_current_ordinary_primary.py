"""Current ordinary group planning; no packet/deep or credit authority is claimed.

Reuse the target fixture's explicitly controlled admission, installed runtime,
and validated canary boundaries. The actual condition, complete prepared graph
validator, per-site byte bindings, target graph/order checks and public policy
publication run unchanged. These HOST fixtures grant no scientific credit.
"""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from qcsd_lab import application_response_policy as app
from qcsd_lab import rapid_ordinary_canary_carry as carry
from qcsd_lab import rapid_ordinary_group_canary as group
from qcsd_lab import rapid_target_chunks as chunks
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import tamaraw_fixed_configuration as tam
from tests.test_rapid_ordinary_parallel import current
from tests.test_rapid_target_chunks import case
from tests.test_primary_document_identity_policy import variable_workload


@pytest.fixture
def ordinary_group(case, monkeypatch):
    current = case.current
    base = current.payload
    base['application_body_identity_policy'] = app.COMPLETE_APPLICATION_DELIVERY_POLICY
    current.facts.update(application_body_identity_policy=app.COMPLETE_APPLICATION_DELIVERY_POLICY,
        ordinary_successful_group_canary=group.TYPE)
    sites = []
    for index, site in enumerate(current.sites):
        manifest, _ = variable_workload()
        prep = manifest['preparation']
        for resource in manifest['resources']:
            resource['url'] = resource['url'].replace('page.test', f'page{index}.test').replace(
                'cdn.test', f'cdn{index}.test')
        prep.update(source_url=manifest['resources'][0]['url'], final_url=manifest['resources'][0]['url'])
        prep['coverage_admission']['required_resources'] = [
            {'id': resource['id'], 'url': resource['url']} for resource in manifest['resources']]
        path = current.spec.workload_root / (site.workload_id + '.json')
        path.write_bytes(target._json(manifest))
        app.validate_prepared_response_graph(manifest)
        sites.append(replace(site, workload_sha256=lanes._sha(path.read_bytes())))
        case.inputs['inputs']['classes'][index]['original_graph_sha256'] = target.membership.graph_identity(path)
    current.sites = tuple(sites)
    configuration = {'profile': 'research-1200', 'request_policies': ['as-defined'],
        'application_body_identity_policy': app.COMPLETE_APPLICATION_DELIVERY_POLICY,
        'defenses': [{'name': 'undefended', 'kind': 'none', 'baseline': True}]}
    resolved = tam.resolved_configuration()
    resolved.update(initial_max_stream_data=16, defense={'kind': 'none'})
    run = {'resolved_configuration': resolved, 'defense_parameters': None,
        'application_response_policy': app.COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
        'primary_document_identity_policy': app.EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY}
    (case.result / 'accepted/sample/neqo/run.json').write_bytes(target._json(run))
    (case.result / 'experiment.json').write_bytes(target._json({'configuration': configuration,
        'samples': [{'path': 'accepted/sample', 'state': 'accepted', 'defense': 'undefended'}]}))
    condition = target.condition_identity(configuration, run, 'undefended')
    assert target._digest(condition) == '503a3e65d5f6f8a578150fa0dcd2ff7b2ff65bf0d812136b5cc6501dc37404db'
    case.inputs['inputs']['condition'] = {'identity': condition, 'identity_sha256': target._digest(condition)}
    # The inherited fixture's admission/base proof is synthetic. Rebinding its
    # full manifests is explicit; current target controls and graphs stay real.
    monkeypatch.setattr(chunks, '_base', lambda spec: (current.sites, base))
    return case


def test_current_group_policy_keeps_native_exact_condition_and_all_site_graphs(ordinary_group):
    case = ordinary_group
    before = {site.workload_id: (case.current.spec.workload_root / (site.workload_id + '.json')).read_bytes()
              for site in case.current.sites}
    original = deepcopy(case.inputs)
    output = case.current.root / 'current-ordinary-group-policy.json'
    chunks.publish_policy(case.current.spec, case.inputs_ref, case.canonical_ref, output)
    policy, sites, base = chunks.validate_policy(target.reference(output))
    assert policy['condition_sha256'] == '503a3e65d5f6f8a578150fa0dcd2ff7b2ff65bf0d812136b5cc6501dc37404db'
    assert policy['current_canary'] == case.current.canary
    assert policy['classes'] == original['inputs']['classes']
    assert policy['capture_limits'] == original['inputs']['capture_limits']
    assert policy['ranges'] == original['inputs']['ranges']
    assert policy['formal_accepted_trace_count'] == 0 and policy['scientific_credit'] is False
    assert sites == case.current.sites and base is case.current.payload
    reference, condition = chunks._condition(case.current.spec, sites, base, 'undefended')
    assert reference == case.current.canary and condition == original['inputs']['condition']['identity']
    assert condition['primary_document_identity_policy'] == app.EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY
    for site in sites:
        path = case.current.spec.workload_root / (site.workload_id + '.json')
        assert path.read_bytes() == before[site.workload_id]
        manifest = json.loads(path.read_bytes())
        assert len(manifest['resources']) == 2
        assert app.primary_document_identity_policy(manifest) == app.VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY
        assert app.validate_prepared_response_graph(manifest)['resource_ids'] == [0, 1]
    assert case.inputs == original


def _manifest(case, change, *, rebind=False):
    site = case.current.sites[0]
    path = case.current.spec.workload_root / (site.workload_id + '.json')
    manifest = json.loads(path.read_bytes())
    change(manifest)
    path.write_bytes(target._json(manifest))
    if rebind:
        case.current.sites = (replace(site, workload_sha256=lanes._sha(path.read_bytes())),
                              *case.current.sites[1:])


@pytest.mark.parametrize('change', ['schema1', 'wrong-type', 'carried', 'facts-marker', 'source', 'client',
    'native-primary', 'native-response', 'body', 'manifest-response', 'manifest-bytes',
    'response-coverage', 'graph', 'order'])
def test_current_group_exception_refuses_scope_and_measurement_changes_before_create(ordinary_group, change):
    case = ordinary_group
    if change == 'schema1': case.current.canary['schema_version'] = 1
    elif change == 'wrong-type': case.current.canary['artifact_type'] = 'unrecognized-current-group'
    elif change == 'carried': case.current.canary.update(schema_version=6, artifact_type=carry.TYPE)
    elif change == 'facts-marker': case.current.facts.pop('ordinary_successful_group_canary')
    elif change == 'source': case.current.facts['source'] = {**case.current.facts['source'], 'lab_commit': '0' * 40}
    elif change == 'client': case.current.facts['client_sha256'] = '0' * 64
    elif change in ('native-primary', 'native-response'):
        path = case.result / 'accepted/sample/neqo/run.json'
        run = json.loads(path.read_bytes())
        run['primary_document_identity_policy' if change == 'native-primary' else 'application_response_policy'] = (
            app.VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY if change == 'native-primary' else app.HTTP_2XX_ONLY_POLICY)
        path.write_bytes(target._json(run))
    elif change == 'body':
        case.current.facts['application_body_identity_policy'] = app.EXACT_APPLICATION_BODY_IDENTITY_POLICY
    elif change == 'manifest-response':
        _manifest(case, lambda m: m['preparation'].update(application_response_policy=app.HTTP_2XX_ONLY_POLICY), rebind=True)
    elif change == 'manifest-bytes':
        _manifest(case, lambda m: m['preparation'].update(max_response_bytes=2_000_000))
    elif change == 'response-coverage':
        _manifest(case, lambda m: m['preparation']['coverage_admission']['required_resources'].pop(), rebind=True)
    elif change == 'graph':
        _manifest(case, lambda m: m['resources'].pop(), rebind=True)
    else: case.current.sites = tuple(reversed(case.current.sites))
    output = case.current.root / ('refused-current-group-' + change + '.json')
    with pytest.raises(ValueError):
        chunks.publish_policy(case.current.spec, case.inputs_ref, case.canonical_ref, output)
    assert not output.exists()


def test_current_group_policy_cannot_be_used_by_front(ordinary_group):
    case = ordinary_group
    base = deepcopy(case.current.payload)
    for row in base['lanes']: row['mode'] = 'front'
    with pytest.raises(ValueError, match='historical canary or control bridge'):
        chunks._condition(case.current.spec, case.current.sites, base, 'front')
