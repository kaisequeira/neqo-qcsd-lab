"""Prospective URL, full-graph and failure boundaries; no actual acquisition.

All resolutions use explicit fixture DNS/HTTP functions, and browser examples
are stock audit unit fixtures. They grant no qualification or capture credit.
"""
from copy import deepcopy
from dataclasses import asdict
import importlib.util
import json
from pathlib import Path
import signal
import sys
import time

import pytest

from qcsd_lab import discover, discovery_evidence
from test_discovery_evidence import _root_resource_audit, _three_resource_dependency_audit, _render_for, _verify


HERE = Path(__file__).parent.parent / 'tools/whole_graph_discovery_v13'


def module(name):
    spec = importlib.util.spec_from_file_location('_test_v13_' + name, HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


homepage = module('canonical_homepage')
producer = module('graph_input')
CANDIDATE = {'catalogue_position': 1, 'candidate_id': 'unit-example', 'domain': 'example.com',
             'rank': 1, 'stratum': 'unit', 'source_url': 'https://example.com/'}
PUBLIC = '93.184.216.34'


def dns(url, *, addresses=None):
    from urllib.parse import urlsplit
    addresses = addresses or [PUBLIC]
    return {'url': url, 'hostname': urlsplit(url).hostname, 'addresses': addresses,
            'selected_address': addresses[0], 'started_at': homepage.now(), 'completed_at': homepage.now()}


def response(url, dns_value, *, status=200, location=None, media='text/html'):
    from urllib.parse import urlsplit
    headers = [['Content-Type', media]]
    if location is not None:
        headers.append(['Location', location])
    return {'url': url, 'method': 'GET', 'status': status, 'headers': headers,
        'remote_address': dns_value['selected_address'], 'tls_hostname': urlsplit(url).hostname,
        'tls_certificate_verified': True, 'body_read_bytes': 0, 'complete_body_claimed': False,
        'started_at': homepage.now(), 'completed_at': homepage.now()}


def plan_ref(tmp_path):
    return homepage.create(tmp_path / 'unit-plan.json', {'role': 'zero-credit-unit-fixture'})


def completed_resolution(tmp_path):
    declared = plan_ref(tmp_path)
    requested = []
    def request(url, records, timeout):
        requested.append(url)
        if url == CANDIDATE['source_url']:
            return response(url, records, status=301, location='https://www.example.com/')
        return response(url, records)
    ref, value = homepage.resolve(tmp_path / 'resolution', candidate=CANDIDATE, plan=declared,
                                  resolver=dns, requester=request)
    assert requested == ['https://example.com/', 'https://www.example.com/']
    return ref, value


def rewrite(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n'); path.chmod(0o600)


def test_redirect_resolution_is_declared_before_browser_and_keeps_original_candidate(tmp_path, monkeypatch):
    ref, value = completed_resolution(tmp_path)
    monkeypatch.setattr(homepage.socket, 'getaddrinfo', lambda *a, **k: pytest.fail('read-only verification attempted DNS'))
    monkeypatch.setattr(homepage.http.client, 'HTTPSConnection', lambda *a, **k: pytest.fail('read-only verification attempted HTTP'))
    assert homepage.verify(homepage.reopen(ref), candidate=CANDIDATE, plan=value['plan']) == value
    assert value['candidate'] == CANDIDATE and value['initial_url'] == CANDIDATE['source_url']
    assert value['final_url'] == 'https://www.example.com/'
    assert value['native_get_qualification_claimed'] is value['challenge_absence_claimed'] is False
    assert value['scientific_credit'] is False and value['site_credit'] == 0
    assert value['policy']['body_read_bytes'] == 0
    assert homepage.instant(value['declared_at']) >= homepage.instant(
        homepage.load(homepage.reopen(value['hops'][-1]['completed']))['completed_at'])


@pytest.mark.parametrize('location', ['http://www.example.com/', 'https://unrelated.example/',
    'https://user:password@www.example.com/', 'https://www.example.com/?tracking=1',
    'https://www.example.com/#fragment', 'https://www.example.com:444/'])
def test_unsupported_redirect_is_refused_before_following_it(tmp_path, location):
    declared = plan_ref(tmp_path); requested = []
    def request(url, records, timeout):
        requested.append(url); return response(url, records, status=302, location=location)
    begun = homepage.instant(homepage.now())
    with pytest.raises(ValueError):
        homepage.resolve(tmp_path / 'attempt', candidate=CANDIDATE, plan=declared, resolver=dns, requester=request)
    assert requested == [CANDIDATE['source_url']]
    assert not (tmp_path / 'attempt/canonical-homepage.json').exists()
    homepage.verify_partial(tmp_path / 'attempt', candidate=CANDIDATE, plan=declared,
                            not_before=begun, not_after=homepage.instant(homepage.now()))


def test_private_dns_answer_is_retained_and_blocks_http(tmp_path):
    declared = plan_ref(tmp_path); requested = []
    def private(url):
        return dns(url, addresses=['10.0.0.1', PUBLIC])
    begun = homepage.instant(homepage.now())
    with pytest.raises(ValueError, match='nonpublic'):
        homepage.resolve(tmp_path / 'attempt', candidate=CANDIDATE, plan=declared,
            resolver=private, requester=lambda *a: requested.append(a))
    assert requested == []
    assert homepage.load(tmp_path / 'attempt/hop-01-dns.json')['addresses'] == ['10.0.0.1', PUBLIC]
    homepage.verify_partial(tmp_path / 'attempt', candidate=CANDIDATE, plan=declared,
                            not_before=begun, not_after=homepage.instant(homepage.now()))


@pytest.mark.parametrize('kind', ['duplicate-location', 'redirect-cycle', 'non-html', 'http-error', 'tls-claim', 'body-claim'])
def test_resolution_refuses_ambiguous_headers_cycles_and_qualification_claims(tmp_path, kind):
    declared = plan_ref(tmp_path); requested = []
    def request(url, records, timeout):
        requested.append(url); value = response(url, records)
        if kind in ('duplicate-location', 'redirect-cycle'):
            value = response(url, records, status=301, location=CANDIDATE['source_url'])
            if kind == 'duplicate-location':
                value['headers'].append(['Location', 'https://www.example.com/'])
        elif kind == 'non-html':
            value['headers'] = [['Content-Type', 'application/pdf']]
        elif kind == 'http-error':
            value['status'] = 403
        elif kind == 'tls-claim':
            value['tls_certificate_verified'] = False
        else:
            value['body_read_bytes'] = 1
        return value
    with pytest.raises(ValueError):
        homepage.resolve(tmp_path / 'attempt', candidate=CANDIDATE, plan=declared, resolver=dns, requester=request)
    assert requested == [CANDIDATE['source_url']]
    assert (tmp_path / 'attempt/hop-01-response.json').is_file()
    assert not (tmp_path / 'attempt/canonical-homepage.json').exists()


def test_dns_wall_deadline_preserves_an_enclosing_timer(tmp_path):
    declared = plan_ref(tmp_path)
    old_handler = signal.getsignal(signal.SIGALRM); old_timer = signal.getitimer(signal.ITIMER_REAL)
    require_unused = old_timer[0] == 0
    if not require_unused:
        pytest.skip('test process already owns an unrelated timer')
    signal.signal(signal.SIGALRM, lambda *a: None)
    signal.setitimer(signal.ITIMER_REAL, 0.03)
    entered = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match='deadline'):
            homepage.resolve(tmp_path / 'attempt', candidate=CANDIDATE, plan=declared,
                resolver=lambda url: signal.pause(), requester=lambda *a: pytest.fail('DNS timeout nevertheless performed HTTP'))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, old_handler)
    assert time.monotonic() - entered < 1
    assert (tmp_path / 'attempt/hop-01-started.json').is_file()
    assert not (tmp_path / 'attempt/canonical-homepage.json').exists()


@pytest.mark.parametrize('mutation', ['private-dns', 'raw-mode', 'final-url', 'policy-bool-alias', 'late-declaration'])
def test_independent_resolution_reopening_refuses_tampering(tmp_path, mutation):
    ref, value = completed_resolution(tmp_path); path = Path(ref['path'])
    if mutation == 'private-dns':
        records = value['hops'][0]; dns_path = homepage.reopen(records['dns'])
        raw = homepage.load(dns_path); raw['addresses'].append('10.0.0.1'); raw['addresses'].sort()
        rewrite(dns_path, raw); records['dns'] = homepage.reference(dns_path)
        completed = homepage.load(homepage.reopen(records['completed'])); completed['dns'] = records['dns']
        rewrite(Path(records['completed']['path']), completed)
        records['completed'] = homepage.reference(records['completed']['path'])
    elif mutation == 'raw-mode':
        Path(value['hops'][0]['dns']['path']).chmod(0o444)
    elif mutation == 'final-url':
        value['final_url'] = 'https://example.com/'
    elif mutation == 'policy-bool-alias':
        value['policy'] = deepcopy(value['policy']); value['policy']['body_read_bytes'] = False
    else:
        value['declared_at'] = '2099-01-01T00:00:00+00:00'
    rewrite(path, value)
    with pytest.raises(ValueError):
        homepage.verify(path)


def test_headers_request_connects_only_to_retained_public_peer_and_reads_no_body(monkeypatch):
    observed = {}
    class Sock:
        def getpeername(self):
            return PUBLIC, 443
    class Response:
        status = 200
        def getheaders(self):
            return [('Content-Type', 'text/html')]
        def read(self, *a):
            pytest.fail('URL resolution read response body')
    class Connection:
        def __init__(self, host, timeout, context):
            observed['host'] = host; observed['timeout'] = timeout; self.timeout = timeout
        def connect(self):
            self.sock = self._create_connection(('example.com', 443), self.timeout)
        def request(self, method, target, headers):
            observed['method'] = method; observed['target'] = target; observed['headers'] = headers
        def getresponse(self):
            return Response()
        def close(self):
            observed['closed'] = True
    def connect(address, timeout, source_address):
        observed['address'] = address; return Sock()
    monkeypatch.setattr(homepage.http.client, 'HTTPSConnection', Connection)
    monkeypatch.setattr(homepage.socket, 'create_connection', connect)
    value = homepage.request_headers(CANDIDATE['source_url'], dns(CANDIDATE['source_url']), 7)
    assert observed['host'] == 'example.com' and observed['address'] == (PUBLIC, 443)
    assert observed['method'] == 'GET' and observed['target'] == '/' and observed['closed']
    assert value['body_read_bytes'] == 0 and value['complete_body_claimed'] is False


def test_terminal_diagnostic_preserves_actual_absence_and_existing_text():
    absent = discover._terminal_failure_evidence('failed', {'canceled': True})
    assert absent == {'error_text': None, 'error_text_present': False, 'canceled': True,
                      'blocked_reason': None, 'cors_error_status_present': False}
    assert discovery_evidence._terminal_diagnostic_fields(absent)
    present = discover._terminal_failure_evidence('failed', {'errorText': 'net::ERR_ABORTED'})
    assert present['error_text'] == 'net::ERR_ABORTED' and 'error_text_present' not in present
    assert discovery_evidence._terminal_diagnostic_fields(present)
    audit, resources = _root_resource_audit()
    terminal = audit['events'][-1]; terminal['outcome'] = 'failed'; terminal['failure'] = absent
    assert _verify(audit, resources)['terminal_event_count'] == 1


@pytest.mark.parametrize('event', [{'errorText': None}, {'errorText': ''}, {'errorText': 0},
    {'canceled': 'true'}, {'blockedReason': ''}, {'corsErrorStatus': []}])
def test_terminal_diagnostic_refuses_malformed_present_fields(event):
    with pytest.raises(discover.DiscoveryIntegrityError):
        discover._terminal_failure_evidence('failed', event)


def discovery_result(*, three=False):
    audit, resources = _three_resource_dependency_audit() if three else _root_resource_audit()
    for row in resources:
        row.update({'content_length': None, 'data_length': 0, 'chaff_priority': False, 'known_valid': False, 'headers': []})
    render = _render_for(audit); audit['render_observation_sha256'] = discovery_evidence.evidence_sha256(render)
    url = resources[0]['url']
    return discover.DiscoveryResult(source_url=url, final_url=url, chromium_version='unit-fixture', settle_ms=13000,
        observed_request_count=len(resources), observed_origins=['https://page.test'], approved_origins=['https://page.test'],
        exclusions=[], resources=resources, origin_ip_pins={'https://page.test': PUBLIC}, expandable_origins=['https://page.test'],
        passive_render_contract=discovery_evidence.passive_render_contract(),
        passive_render_contract_sha256=discovery_evidence.PASSIVE_RENDER_CONTRACT_SHA256,
        render_observation=render, render_observation_sha256=discovery_evidence.evidence_sha256(render),
        discovery_event_audit=audit, discovery_event_audit_sha256=discovery_evidence.evidence_sha256(audit))


def test_full_graph_validator_retains_duplicate_occurrences_and_dependency_edges():
    value = asdict(discovery_result(three=True)); manifest = producer.validate_discovery(value)
    assert manifest['resources'] == value['resources']
    assert len(manifest['resources']) == 3 and manifest['resources'][0]['url'] == manifest['resources'][1]['url']
    assert manifest['resources'][2]['depends_on'] == [1]
    value['resources'][2]['depends_on'] = [0]
    with pytest.raises(ValueError):
        producer.validate_discovery(value)


def producer_fixture(tmp_path, monkeypatch, *, fail=False):
    authority = tmp_path / 'unit-authority'; authority.mkdir(mode=0o700)
    validation_root = tmp_path / 'unit-host-validation'; validation_root.mkdir(mode=0o700)
    metadata = {'image_digest': None, 'lab_commit': 'a' * 40, 'lab_dirty': False, 'lab_patch_sha256': None,
        'neqo_commit': 'b' * 40, 'neqo_pinned_commit': 'b' * 40, 'neqo_dirty': False, 'neqo_patch_sha256': None}
    metadata_path = authority / 'unit-image-metadata.json'; producer.create(metadata_path, metadata)
    candidate = {**CANDIDATE, 'domain': 'page.test', 'source_url': 'https://page.test/'}
    plan = {'source_metadata': producer.reference(metadata_path), 'browser_image': 'sha256:' + '1' * 64,
        'source': {'root': str(producer.SOURCE_ROOT), 'lab_commit': 'c' * 40, 'gitlinks': {'neqo-qcsd': 'd' * 40}},
        'producer_sources': producer.sources(), 'candidates': [candidate], 'declared_at': producer.now(),
        'original_prefix': {}, **producer.LIMITS}
    plan_path = authority / 'unit-producer-plan.json'; producer.create(plan_path, plan)
    validation_path = validation_root / 'validation.json'; producer.create(validation_path, {'closed_at': producer.now()})
    monkeypatch.setattr(producer, 'check_plan', lambda path: plan)
    monkeypatch.setattr(producer, 'physical_plan', lambda path, validation: plan)
    monkeypatch.setattr(producer, 'verify_host_validation', lambda path, plan_path, value: None)
    monkeypatch.setattr(producer, 'verify_snapshot', lambda source: None)
    monkeypatch.setattr(producer, 'dependency_fence', lambda value: {'files': [], 'trees': {}})
    monkeypatch.setattr(producer, 'verify_fence', lambda value: None)
    monkeypatch.setattr(producer.util, 'DEFAULT_SOURCE_METADATA', metadata_path)
    monkeypatch.setenv('QCSD_LAB_IMAGE_DIGEST', plan['browser_image'])
    monkeypatch.setenv('QCSD_LAB_SOURCE_METADATA', str(metadata_path))
    original = producer.homepage.resolve
    monkeypatch.setattr(producer.homepage, 'resolve', lambda root, **kwargs: original(root, **kwargs, resolver=dns,
        requester=lambda url, records, timeout: response(url, records)))
    monkeypatch.setattr(producer.acquisition, 'public_origin_ip_pins', lambda approved: {origin: PUBLIC for origin in approved})
    def browser_fixture(*args, **kwargs):
        if fail:
            raise ValueError('deliberate zero-credit unit browser failure')
        return discovery_result()
    monkeypatch.setattr(producer.browser, 'discover_page', browser_fixture)
    return plan_path, plan, validation_path


def test_complete_graph_roundtrip_has_no_get_or_admission_credit(tmp_path, monkeypatch):
    plan_path, plan, validation_path = producer_fixture(tmp_path, monkeypatch)
    output = tmp_path / 'actual-unit-attempt'
    assert producer.discover(plan_path, 1, output, validation_path) == 0
    value = producer.load(output / 'whole-graph-input.json')
    monkeypatch.setattr(producer, 'check_plan', lambda *a: pytest.fail('public verification repeated historical APIs'))
    result = producer.verify_input(output / 'whole-graph-input.json')
    assert result['resource_count'] == 1 and result['scientific_credit'] is False
    assert value['candidate'] == plan['candidates'][0] and value['final_source_url'] == 'https://page.test/'
    assert value['http3_get_performed'] is False and value['admission_state'] == 'unqualified-graph-input-only'
    (output / 'unexpected-raw-file').write_bytes(b'unaccounted')
    with pytest.raises(ValueError, match='membership'):
        producer.verify_input(output / 'whole-graph-input.json', _plan=plan)


def test_real_operational_failure_reopens_unchanged_full_partial_graph(tmp_path, monkeypatch):
    plan_path, plan, validation_path = producer_fixture(tmp_path, monkeypatch, fail=True)
    output = tmp_path / 'failed-unit-attempt'
    assert producer.discover(plan_path, 1, output, validation_path) == 1
    path = output / 'failed.json'; before = path.read_bytes()
    monkeypatch.setattr(producer, 'check_plan', lambda *a: pytest.fail('public failure verification repeated historical APIs'))
    result = producer.verify_failure(path)
    assert result['failure_stage'] == 'complete-occurrence-convergence' and result['scientific_credit'] is False
    assert path.read_bytes() == before and (output / 'pass-01-started.json').is_file()
    assert not (output / 'whole-graph-input.json').exists()
    (output / 'whole-graph-input.json').write_bytes(b'{}')
    with pytest.raises(ValueError, match='successful graph'):
        producer.verify_failure(path, _plan=plan)


def test_physical_prebirth_reopens_host_closure_without_repeating_historical_apis(tmp_path, monkeypatch):
    plan = {'role': 'zero-credit-unit-fixture'}; calls = []
    monkeypatch.setattr(producer, 'static_plan', lambda path: (plan, []))
    monkeypatch.setattr(producer, 'verify_host_validation', lambda path, plan_path, value: calls.append((path, plan_path, value)))
    monkeypatch.setattr(producer, 'check_plan', lambda *a: pytest.fail('physical prebirth repeated historical HOST APIs'))
    path, validation = tmp_path / 'plan.json', tmp_path / 'validation.json'
    assert producer.physical_plan(path, validation) == plan
    assert calls == [(validation, path, plan)]


def host_validation_fixture(tmp_path, monkeypatch):
    """Unit operation fixtures exercise bindings, never a real qualification."""
    root = tmp_path / 'host'; root.mkdir(mode=0o700)
    operations = root / 'operations'; operations.mkdir(mode=0o700)
    plan = {'candidates': [CANDIDATE], 'producer_sources': producer.sources(), **producer.ZERO}
    plan_path = root / 'plan.json'; producer.create(plan_path, plan)
    bound_input = root / 'immutable-unit-input.json'; producer.create(bound_input, {'role': 'unit-input-only'})
    fixture_recorder = root / 'unit-recorder.py'; fixture_recorder.write_text('# Not executed; zero-credit unit fixture.\n')
    fixture_recorder.chmod(0o644)
    monkeypatch.setattr(producer, 'RECORDER_SHA', producer.reference(fixture_recorder)['sha256'])
    def fence(value):
        return {'files': [producer.reference(bound_input)], 'trees': {}}
    monkeypatch.setattr(producer, 'dependency_fence', fence)
    prefix = operations / 'host-plan-check'
    summary = {'status': 'closed', 'action': 'check', 'candidate_count': 1, **producer.ZERO}
    stdout, stderr = Path(str(prefix) + '.stdout.log'), Path(str(prefix) + '.stderr.log')
    stdout.write_text(json.dumps(summary) + '\n'); stdout.chmod(0o644)
    stderr.write_bytes(b''); stderr.chmod(0o644)
    started = Path(str(prefix) + '-started.json')
    completed = Path(str(prefix) + '-completed.json')
    command = [sys.executable, '-I', '-B', str(producer.HERE / 'operator.py'), 'check', '--plan', str(plan_path)]
    producer.create(started, {'command': command, 'started_at': producer.now()}); started.chmod(0o644)
    producer.create(completed, {'returncode': 0, 'completed_at': producer.now(),
        'stdout_sha256': producer.reference(stdout)['sha256'], 'stderr_sha256': producer.reference(stderr)['sha256']})
    completed.chmod(0o644)
    refs = {key: producer.reference(value) for key, value in (
        ('started', started), ('completed', completed), ('stdout', stdout), ('stderr', stderr))}
    value = {'schema_version': 1, 'artifact_type': 'qcsd-complete-v13-host-plan-validation-v1',
        'plan': producer.reference(plan_path), 'producer_sources': plan['producer_sources'],
        'recorder': producer.reference(fixture_recorder), 'verify_interpreter': str(Path(sys.executable).absolute()),
        'check_operation': refs, 'dependency_fence': fence(plan), 'closed_at': producer.now(), **producer.ZERO}
    path = operations / 'host-plan-validation.json'; producer.create(path, value)
    return path, plan_path, plan, bound_input


def test_host_closure_reopens_without_any_historical_api_or_network_call(tmp_path, monkeypatch):
    path, plan_path, plan, _ = host_validation_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(producer, 'check_plan', lambda *a: pytest.fail('HOST closure replayed historical APIs'))
    monkeypatch.setattr(producer.homepage.socket, 'getaddrinfo', lambda *a: pytest.fail('HOST closure performed DNS'))
    value = producer.verify_host_validation(path, plan_path, plan)
    assert value['plan'] == producer.reference(plan_path) and value['scientific_credit'] is False


@pytest.mark.parametrize('mutation', ['input-bytes', 'input-mode', 'input-missing', 'fence-missing',
    'fence-sha', 'raw-sha', 'raw-missing', 'operation-returncode', 'check-command', 'plan-substitution'])
def test_host_closure_refuses_missing_changed_inputs_or_raw_operations(tmp_path, monkeypatch, mutation):
    path, plan_path, plan, bound_input = host_validation_fixture(tmp_path, monkeypatch)
    value = producer.load(path)
    if mutation == 'input-bytes':
        bound_input.write_text('{"changed": true}\n')
    elif mutation == 'input-mode':
        bound_input.chmod(0o444)
    elif mutation == 'input-missing':
        bound_input.unlink()
    elif mutation == 'fence-missing':
        value['dependency_fence']['files'] = []
    elif mutation == 'fence-sha':
        value['dependency_fence']['files'][0]['sha256'] = '0' * 64
    elif mutation == 'raw-sha':
        value['check_operation']['stdout']['sha256'] = '0' * 64
    elif mutation == 'raw-missing':
        Path(value['check_operation']['stderr']['path']).unlink()
    elif mutation == 'plan-substitution':
        value['plan']['sha256'] = '0' * 64
    else:
        key = 'completed' if mutation == 'operation-returncode' else 'started'
        raw_path = Path(value['check_operation'][key]['path']); raw = producer.load(raw_path)
        if mutation == 'operation-returncode':
            raw['returncode'] = 1
        else:
            raw['command'][-1] = str(plan_path.with_name('different-plan.json'))
        rewrite(raw_path, raw); raw_path.chmod(0o644)
        value['check_operation'][key] = producer.reference(raw_path)
    rewrite(path, value)
    with pytest.raises((ValueError, OSError)):
        producer.verify_host_validation(path, plan_path, plan)
