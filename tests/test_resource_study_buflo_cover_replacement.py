"""Append-only same-runtime cover admission controls; ROOT alone executes.

Real disposable stable50/cohort/SQLite/fence/ownpilot/seal/credit paths and the
original saved capped sidecar validator run. Preparation subprocess receipts,
raw packet proof, fsync and Docker are explicit synthetic leaves. These tests
claim no live qualification, traffic, physical timing or scientific credit.
"""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from qcsd_lab import chaff_qualification as chaff
from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_native as native
from qcsd_lab import resource_study_network as network
from qcsd_lab import resource_study_runtime as runtime
from qcsd_lab.resource_study_inputs import MODES, canonical_json, native_manifest, sha256_file
from qcsd_lab.resource_study_store import StudyStore, DuplicateSession, _create
from tests.test_resource_study import CaptureBackend
from tests.test_resource_study_epochs import controlled_pilot
from tests.test_resource_study_lineage import HOSTS, admit, rewrite
from tests.test_resource_study_buflo_capped_chaff import _response_v2_epochs

HOST = 'alpha.example'
POLICY = 'rapid-v7-fixed-64ms-640s-duration-budget-v1'


def producer():
    return deepcopy(runtime.BF122_SHARED_RUNTIME)


def raw_leaf(root, receipt):
    return {'verified': True, 'five_tuple': receipt.get('five_tuple')}


def prepared(store, host, bound, *, capped=False):
    """No network: exact synthetic original20 plus structural saved receipts."""
    urls = study.candidate_pool(store.root)[host]['urls'][:20]
    sizes = [100000, 8000, *([1100] * 18)]
    application = native_manifest(host, urls, dict(zip(urls, sizes)))
    for row in application['resources']:
        row['headers'] = deepcopy(native.REQUEST_HEADERS)
    application['resources'][0]['type'] = 'Document'
    base = Path('inputs') / host
    manifest = store.root / base / 'resources.json'
    _create(manifest, canonical_json(application))
    expected = [{'resource_id': i, 'status': 200, 'bytes': size,
                 'body_sha256': hashlib.sha256(('body-%d' % i).encode()).hexdigest()}
                for i, size in enumerate(sizes)]
    value = {**application, 'preparation': {
        'qualified_chaff_origin_policy': 'prepared-approved-origins-v1',
        'approved_origins': ['https://' + host], 'expected_responses': expected}}
    prepared_path = store.root / base / 'prepared-workload.json'
    _create(prepared_path, canonical_json(value))
    identity = {'status': 200, 'content_encoding': 'identity',
                'body_bytes': sizes[0], 'body_sha256': expected[0]['body_sha256']}
    legacy_sidecar = {'base_manifest': {'sha256': sha256_file(prepared_path)},
        'application_resource_id': 0, 'selected_chaff_resource_id': 0,
        'resource': {'headers': application['resources'][0]['headers'],
                     'expected_response': identity, 'request_stream_bytes': 151,
                     'response_qualification_sha256': '1' * 64}}
    legacy = chaff.derive_response_only_chaff_manifest(legacy_sidecar, application['resources'][0])
    legacy_path = store.root / base / 'chaff-manifest.json'
    _create(legacy_path, canonical_json(legacy))
    paths = {'manifest': manifest.relative_to(store.root).as_posix(),
             'prepared_workload': prepared_path.relative_to(store.root).as_posix(),
             'chaff_manifest': legacy_path.relative_to(store.root).as_posix()}
    selection = None
    if capped:
        result = native._qualify_buflo_capped(prepared_path, store.root / base / 'qualification',
                                              Path('/synthetic-client-not-executed'), bound, 65536)
        assert result['error'] is None
        for key, name, content in (
            ('buflo_chaff_sidecar', 'sidecar.json', result['sidecar']),
            ('buflo_chaff_manifest', 'capped-manifest.json', result['manifest'])):
            path = store.root / base / name
            _create(path, canonical_json(content))
            paths[key] = path.relative_to(store.root).as_posix()
        selection = {'schema_version': 1, 'record_type': native.BUFLO_CAPPED_SELECTION_TYPE,
                     'selection_policy': native.BUFLO_CAPPED_SELECTION_POLICY, 'cap_bytes': 65536}
    enrollment = {'hostname': host, 'urls': urls, 'runtime': deepcopy(bound),
        'workload_path': paths['manifest'], 'workload_sha256': sha256_file(manifest),
        'paths': paths, 'files': {p: sha256_file(store.root / p) for p in paths.values()},
        'mode_settings': {m: {} for m in MODES},
        'mode_policies': {m: ({'buflo_duration_policy': POLICY} if m == 'buflo' else {}) for m in MODES},
        'mode_readiness': dict.fromkeys(MODES, True), 'scientific_credit': False}
    if selection is not None:
        enrollment.update(buflo_chaff_selection=selection, buflo_chaff_qualification_error=None)
    if host == lineage.INCLUDED:
        enrollment['source_occurrences'] = study.candidate_pool(store.root)[host]['source_occurrences']
    return lineage.bind_enrollment(store, enrollment) if 'class_selection' in store.plan() else enrollment


@pytest.fixture
def campaign(tmp_path, monkeypatch):
    from qcsd_lab import resource_study_store as storage
    monkeypatch.setattr(storage.os, 'fsync', lambda _: None)
    monkeypatch.setattr(storage, '_fsync', lambda _: None)
    monkeypatch.setattr(epochs, 'docker_lock', nullcontext)
    monkeypatch.setattr(epochs, '_verify_preparation', lambda *a, **kw: None)
    for module in (epochs, cohorts, study):
        monkeypatch.setattr(module, 'verify_receipt', raw_leaf)
    def responses(path, output, **kwargs):
        base = json.loads(Path(path).read_bytes())
        candidate = base['resources'][kwargs['selected_chaff_resource_id']]
        row = base['preparation']['expected_responses'][candidate['id']]
        return _response_v2_epochs(candidate=candidate,
            application_sha256=sha256_file(path),
            source={'neqo_base_commit': 'a' * 40, 'published_qcsd_commit': 'b' * 40,
                    'migration_commit': producer()['native_commit']},
            identity=(200, 'identity', row['bytes'], row['body_sha256']))
    monkeypatch.setattr(chaff, '_run_response_qualifications_v2', responses)
    source = tmp_path / 'source.json'
    source.write_bytes(canonical_json([{'crUX_domain': 'official.example', 'resources': [
        {'resource_domain': h, 'resource_urls': [f'https://{h}/r?i={i}' for i in range(20)]}
        for h in HOSTS]}]))
    parent = StudyStore(tmp_path / 'parent')
    study.initialize(source, parent.root, storage_reserve_bytes=2 * 1024 ** 3)
    ancestor = {'client_sha256': 'a' * 64, 'platform': 'linux/arm64', 'source': {'neqo_commit': 'c' * 40}}
    for host in HOSTS[:2]:
        parent.enroll(prepared(parent, host, ancestor))
    cells = {(host, mode): epochs._cell(parent, host, mode) for host in HOSTS[:2] for mode in MODES}
    epochs._bind(parent, parent); epochs._publish(parent, [], cells, 'initial', cells)
    inventory = tmp_path / 'MAL.json'
    _create(inventory, canonical_json({'urls': [{'url': f'https://{lineage.INCLUDED}/r?i={i}'} for i in range(25)]}))
    stable = StudyStore(tmp_path / 'stable')
    lineage.initialize(parent.root, stable.root, inventory, storage_reserve_bytes=2 * 1024 ** 3)
    stable.enroll(prepared(stable, lineage.INCLUDED, ancestor))
    admit(parent, stable)
    old = StudyStore(tmp_path / 'native122-uncapped')
    cohorts.initialize_cohort(parent.root, old.root)
    for host in (HOST, 'beta.example'):
        old.enroll(prepared(old, host, producer()))
    ordinary = cohorts.compatibility_template(parent.root, old.root,
        affected_hostnames=[HOST, 'beta.example'], affected_modes=['buflo'])
    ordinary.update(compatible_treatment=True, rationale='Controlled fixture; no physical proof.')
    ordinary_path = tmp_path / 'ordinary.json'; _create(ordinary_path, canonical_json(ordinary))
    cohorts.create_cohort(parent.root, old.root, ordinary_path, sha256_file(ordinary_path))
    for host in (HOST, 'beta.example'):
        controlled_pilot(old, host, 'buflo')
    return parent, old


def candidate(parent, path, *, mutate=None, hosts=(HOST,)):
    new = StudyStore(path)
    cohorts.initialize_cohort(parent.root, new.root)
    for host in hosts:
        value = prepared(new, host, producer(), capped=True)
        if mutate is not None:
            mutate(value)
        new.enroll(value)
    return new


def declaration(parent, new, path, *, authorize=True, hosts=(HOST,)):
    value = cohorts.cover_template(parent.root, new.root,
        affected_hostnames=list(hosts), affected_modes=['buflo'])
    assert value['cover_change_authorized'] is False
    if authorize:
        value.update(cover_change_authorized=True, rationale='Explicit test cover stratum; no live proof.')
    _create(path, canonical_json(value))
    return value, sha256_file(path)


def formal(store, *, port):
    attempt = store.allocate_attempt(HOST, 'buflo')
    enrolled = epochs._enrollments(store)[HOST][0]
    CaptureBackend(store.root).write_capture(attempt, enrolled, port)
    directory = store.root / attempt['path'] / 'capture'
    run = json.loads((directory / 'neqo/run.json').read_bytes())
    ip = store.plan()['class_network']['assignments'][HOST]['client_ipv4']
    run['endpoints'] = [{'id': 0, 'local_address': f'{ip}:{port}', 'remote_address': '8.8.8.8:443'}]
    rewrite(directory / 'neqo/run.json', run)
    _create(directory / 'class-network.json', canonical_json(network.receipt_binding(
        store.plan(), sha256_file(store.root / 'study.json'), HOST)))
    _create(directory / 'diagnostics/scheduler-runtime-evidence.json', canonical_json(
        {'fixture': 'synthetic scientific proof leaf; no physical scheduling claim'}))
    store.mark_captured(attempt['attempt_id'])
    receipt = study.seal(store.root, attempt, enrolled, producer(),
                         {'success': True, 'mode_policies': enrolled['mode_policies']['buflo']})
    return attempt, receipt


def commit(store, *, port):
    attempt, receipt = formal(store, port=port)
    store.commit_verified(receipt, validator=raw_leaf)
    return attempt, receipt


def test_same_runtime_cap_appends_with_equal_definition_and_preserved_credit(campaign, tmp_path):
    parent, old = campaign
    _, prior_receipt = commit(old, port=31000)
    prior_bytes = prior_receipt.read_bytes()
    prior = epochs._records(parent)
    new = candidate(parent, tmp_path / 'capped')
    with pytest.raises(ValueError, match='changed Native'):
        cohorts.compatibility_template(parent.root, new.root,
            affected_hostnames=[HOST], affected_modes=['buflo'])
    path = tmp_path / 'cap.json'; value, digest = declaration(parent, new, path)
    row = value['affected'][0]
    assert row['previous_definition_sha256'] == row['new_definition_sha256']
    assert row['before_cover']['runtime'] == row['after_cover']['runtime'] == producer()
    assert row['before_cover']['resource']['expected_response']['body_bytes'] == 100000
    assert row['after_cover']['resource']['expected_response']['body_bytes'] == 8000
    result = cohorts.create_cover_replacement(parent.root, new.root, path, digest)
    assert result['change'] == 'buflo-capped-cover'
    old_entry = cohorts._entry(prior[-1]['cohorts'], (HOST, 'buflo'))
    entry = cohorts._entry(result['cohorts'], (HOST, 'buflo'))
    assert entry['science'] == old_entry['science']
    assert len(entry['members']) == len(old_entry['members']) + 1
    assert entry['writer'] != old_entry['writer']
    assert prior_receipt.read_bytes() == prior_bytes
    assert cohorts.accepted_count(new, HOST, 'buflo') == 1
    with pytest.raises(ValueError, match='pilot'):
        new.allocate_attempt(HOST, 'buflo')
    controlled_pilot(new, HOST, 'buflo')
    attempt, receipt = commit(new, port=32000)
    assert attempt['slot'] == 2
    assert study.load(receipt)['buflo_chaff_selection']['cap_bytes'] == 65536
    # A historical admitted root now legitimately has rows. Reading it must
    # authenticate immutable provenance without reasserting live fresh-zero.
    current = cohorts.records(parent)
    assert current[-1] == result and cohorts.accepted_count(new, HOST, 'buflo') == 2
    assert prior_receipt.read_bytes() == prior_bytes
    _, duplicate = formal(new, port=31000)
    with pytest.raises(DuplicateSession):
        new.commit_verified(duplicate, validator=raw_leaf)
    assert cohorts.accepted_count(new, HOST, 'buflo') == 2


@pytest.mark.parametrize('case', ['unready', 'wrong-cap', 'wrong-runtime', 'different-policy', 'different-setting'])
def test_cap_replacement_rejects_changed_or_unqualified_inputs(campaign, tmp_path, case):
    parent, _ = campaign
    def mutate(value):
        if case == 'unready': value['mode_readiness']['buflo'] = False
        elif case == 'wrong-cap': value['buflo_chaff_selection']['cap_bytes'] = 65535
        elif case == 'wrong-runtime': value['runtime']['source']['lab_commit'] = '0' * 40
        elif case == 'different-policy': value['mode_policies']['buflo']['buflo_duration_policy'] = 'unreviewed'
        else: value['mode_settings']['buflo']['unreviewed'] = True
    new = candidate(parent, tmp_path / case, mutate=mutate)
    with pytest.raises(ValueError):
        cohorts.cover_template(parent.root, new.root, affected_hostnames=[HOST], affected_modes=['buflo'])


def test_cap_replacement_explicit_authority_and_fresh_root(campaign, tmp_path):
    parent, old = campaign
    new = candidate(parent, tmp_path / 'capped')
    path = tmp_path / 'not-authorized.json'; _, digest = declaration(parent, new, path, authorize=False)
    with pytest.raises(ValueError, match='authority'):
        cohorts.create_cover_replacement(parent.root, new.root, path, digest)
    path2 = tmp_path / 'authorized.json'; _, digest2 = declaration(parent, new, path2)
    held = old.allocate_attempt(HOST, 'buflo')
    with pytest.raises(ValueError, match='active reservation'):
        cohorts.create_cover_replacement(parent.root, new.root, path2, digest2)
    old.fail_attempt(held['attempt_id'], 'controlled cleanup; no packets')
    result = cohorts.create_cover_replacement(parent.root, new.root, path2, digest2)
    assert result['affected'] == [[HOST, 'buflo']]
    # Repeating an immutable admission does not create another member.
    with pytest.raises(ValueError):
        cohorts.create_cover_replacement(parent.root, new.root, path2, digest2)


def test_changed_auxiliary_and_true_cap_are_not_just_metadata(campaign, tmp_path, monkeypatch):
    parent, _ = campaign
    new = candidate(parent, tmp_path / 'capped')
    prior = cohorts.records(parent)[-1]
    old_entry = cohorts._entry(prior['cohorts'], (HOST, 'buflo'))
    old = cohorts._writer(old_entry)['cell']; after = epochs._cell(new, HOST, 'buflo')
    original = cohorts._cover_binding
    def same_aux(cell, *, capped):
        bound = original(cell, capped=capped)
        if capped: bound['resource']['id'] = 0
        return bound
    # This disclosed return-only perturbation isolates the changed-auxiliary
    # predicate; the unperturbed paths above use the real saved validator.
    with monkeypatch.context() as patch:
        patch.setattr(cohorts, '_cover_binding', same_aux)
        with pytest.raises(ValueError, match='changed auxiliary'):
            cohorts._cover_affected(old, after, old_entry, prior['class_transition'])
    enrollment = epochs._enrollments(new)[HOST][0]
    launch = new.root / enrollment['paths']['buflo_chaff_manifest']
    changed = json.loads(launch.read_bytes()); changed['selected_chaff_resource_id'] = 2
    rewrite(launch, changed)
    with pytest.raises(ValueError):
        cohorts.cover_template(parent.root, new.root, affected_hostnames=[HOST], affected_modes=['buflo'])


def test_cover_historical_record_rejects_unaffected_or_member_rewrite(campaign, tmp_path):
    parent, _ = campaign
    new = candidate(parent, tmp_path / 'capped')
    prior = cohorts.records(parent)
    path = tmp_path / 'cap.json'; _, digest = declaration(parent, new, path)
    result = cohorts.create_cover_replacement(parent.root, new.root, path, digest)
    for case in ('unaffected', 'old-member', 'scope'):
        bad = deepcopy(result)
        if case == 'unaffected':
            entry = next(x for x in bad['cohorts'] if x['mode'] != 'buflo')
            entry['science']['unreviewed'] = True
        elif case == 'old-member':
            cohorts._entry(bad['cohorts'], (HOST, 'buflo'))['members'][0]['cell']['definition']['ready'] = False
        else: bad['affected'].append([HOST, 'front'])
        with pytest.raises(ValueError):
            cohorts._validate_record(parent, prior, bad)


def test_cap_public_commands_are_explicit_and_no_other_mode(campaign, tmp_path, monkeypatch, capsys):
    parent, _ = campaign
    new = candidate(parent, tmp_path / 'capped')
    with pytest.raises(ValueError, match='BuFLO'):
        cohorts.cover_template(parent.root, new.root, affected_hostnames=[HOST], affected_modes=['front'])
    calls = []
    def template(p, n, **scope):
        calls.append((p, n, scope)); return {'scientific_credit': False}
    monkeypatch.setattr(cohorts, 'cover_template', template)
    assert study.main(['cohort-buflo-cover-template', '--root', str(parent.root),
        '--cohort-root', str(new.root), '--affected-hostname', HOST, '--affected-mode', 'buflo']) == 0
    assert calls == [(parent.root, new.root, {'affected_hostnames': [HOST], 'affected_modes': ['buflo']})]
    assert json.loads(capsys.readouterr().out)['scientific_credit'] is False


def test_one_fresh_cover_root_can_append_multiple_selected_ready_classes(campaign, tmp_path):
    parent, _ = campaign
    hosts = (HOST, 'beta.example')
    new = candidate(parent, tmp_path / 'two-capped', hosts=hosts)
    path = tmp_path / 'two-cap.json'
    value, digest = declaration(parent, new, path, hosts=hosts)
    assert [row['hostname'] for row in value['affected']] == sorted(hosts)
    result = cohorts.create_cover_replacement(parent.root, new.root, path, digest)
    assert result['affected'] == [[host, 'buflo'] for host in sorted(hosts)]
    for host in hosts:
        entry = cohorts._entry(result['cohorts'], (host, 'buflo'))
        assert cohorts._writer(entry)['cell']['root'] == str(new.root)
        assert cohorts.accepted_count(new, host, 'buflo') == 0
    assert cohorts.records(parent)[-1] == result
