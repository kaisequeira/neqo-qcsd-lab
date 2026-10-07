"""Bound a prospective HTTPS starting URL; this is not Native GET qualification."""
from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import signal
import ssl
import stat
import time
from urllib.parse import urljoin, urlsplit

from qcsd_lab import class_acquisition as acquisition
from qcsd_lab.class_catalogue import canonical_query_free_html_url

TYPE = 'qcsd-prospective-canonical-homepage-resolution-v1'
ZERO = {'scientific_credit': False, 'site_credit': 0, 'formal_accepted_trace_count': 0}
POLICY = {
    'policy': 'bounded-public-https-same-candidate-boundary-headers-only-resolution-v1',
    'method': 'GET', 'body_read_bytes': 0, 'complete_get_measurement_claimed': False,
    'max_redirects': 8, 'max_hops': 9, 'hop_timeout_seconds': 7,
    'total_timeout_seconds': 45, 'max_accepted_header_bytes': 65536,
    'redirect_statuses': [301, 302, 303, 307, 308],
    'final_media_types': ['text/html', 'application/xhtml+xml'],
    'url_policy': 'existing-canonical-query-free-html-url-with-original-candidate-boundary-v1',
    'dns_policy': 'all-answers-public-and-connect-to-one-retained-answer-with-valid-tls-v1',
    'starting_url_declared_before_browser': True,
    'earlier_root_redirect_requests_in_formal_graph': False,
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def now():
    return datetime.now(timezone.utc).isoformat()


def instant(value):
    require(isinstance(value, str), 'resolution timestamp must be text')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.utcoffset() is not None and result.utcoffset().total_seconds() == 0,
            'resolution timestamp must be UTC')
    return result


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def reference(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'resolution reference contains a link')
    before = path.stat()
    require(stat.S_ISREG(before.st_mode), 'resolution reference is not a regular file')
    raw = path.read_bytes()
    after = path.stat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    require(all(getattr(before, k) == getattr(after, k) for k in fields), 'resolution authority changed during read')
    return {'path': str(path), 'sha256': digest(raw), 'mode': f'{stat.S_IMODE(before.st_mode):04o}'}


def reopen(ref):
    require(isinstance(ref, dict) and set(ref) == {'path', 'sha256', 'mode'}, 'resolution reference fields changed')
    path = Path(ref['path'])
    require(path.is_absolute() and '..' not in path.parts and reference(path) == ref, 'resolution reference bytes/mode changed')
    return path


def load(path):
    def pairs(items):
        value = {}
        for key, child in items:
            require(key not in value, 'resolution JSON repeats a field')
            value[key] = child
        return value
    def constant(_):
        raise ValueError('resolution JSON contains a nonfinite number')
    return json.loads(Path(path).read_bytes(), object_pairs_hook=pairs, parse_constant=constant)


def create(path, value):
    path = Path(path)
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    return reference(path)


def checked_url(url, candidate):
    require(isinstance(candidate, dict) and candidate.get('source_url') == 'https://' + candidate['domain'] + '/',
            'canonical resolution changed original catalogue homepage identity')
    result = canonical_query_free_html_url(url, registrable_domain=candidate['domain'])
    require(result == url, 'canonical resolution URL spelling changed')
    return result


def location_target(url, response, candidate):
    locations = [value for name, value in response['headers'] if name.lower() == 'location']
    require(len(locations) == 1 and isinstance(locations[0], str) and locations[0],
            'redirect needs exactly one nonempty Location')
    target = urljoin(url, locations[0])
    return checked_url(target, candidate)


def validate_dns(value, url):
    require(isinstance(value, dict) and set(value) == {'url', 'hostname', 'addresses', 'selected_address', 'started_at', 'completed_at'},
            'canonical resolution DNS fields changed')
    require(value['url'] == url and value['hostname'] == urlsplit(url).hostname
            and isinstance(value['addresses'], list) and value['addresses']
            and value['addresses'] == sorted(set(value['addresses']))
            and value['selected_address'] in value['addresses']
            and instant(value['started_at']) <= instant(value['completed_at']), 'canonical DNS identity/chronology changed')
    for address in value['addresses']:
        parsed = ipaddress.ip_address(address)
        require(parsed.compressed == address and acquisition._is_public_network_address(parsed),
                'canonical resolution DNS includes a nonpublic or noncanonical answer')
    return value


def resolve_dns(url):
    started = now(); host = urlsplit(url).hostname
    records = socket.getaddrinfo(host, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    addresses = sorted({ipaddress.ip_address(record[4][0]).compressed for record in records})
    require(addresses, 'canonical resolution DNS returned no address')
    selected = min(addresses, key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item))))
    return {'url': url, 'hostname': host, 'addresses': addresses,
        'selected_address': selected, 'started_at': started, 'completed_at': now()}


def validate_response(value, url, dns, candidate):
    require(isinstance(value, dict) and set(value) == {'url', 'method', 'status', 'headers', 'remote_address',
        'tls_hostname', 'tls_certificate_verified', 'body_read_bytes', 'complete_body_claimed', 'started_at', 'completed_at'},
        'canonical response fields changed')
    checked_url(url, candidate)
    require(value['url'] == url and value['method'] == POLICY['method']
            and type(value['status']) is int and 100 <= value['status'] < 600
            and value['remote_address'] == dns['selected_address'] and value['tls_hostname'] == urlsplit(url).hostname
            and value['tls_certificate_verified'] is True and type(value['body_read_bytes']) is int
            and value['body_read_bytes'] == 0 and value['complete_body_claimed'] is False
            and isinstance(value['headers'], list) and all(isinstance(row, list) and len(row) == 2
                and all(isinstance(item, str) for item in row) for row in value['headers'])
            and sum(len(name.encode()) + len(item.encode()) + 4 for name, item in value['headers']) <= POLICY['max_accepted_header_bytes']
            and instant(dns['completed_at']) <= instant(value['started_at']) <= instant(value['completed_at']),
            'canonical response source, bounds or chronology changed')
    return value


def request_headers(url, dns, timeout):
    host = urlsplit(url).hostname
    connection = http.client.HTTPSConnection(host, timeout=timeout, context=ssl.create_default_context())
    # HTTPSConnection wraps this public pinned socket with certificate validation
    # and SNI for its original hostname, without another hostname DNS lookup.
    connection._create_connection = lambda address, timeout, source_address=None: socket.create_connection(
        (dns['selected_address'], 443), timeout, source_address)
    started = now()
    try:
        connection.connect()
        peer = ipaddress.ip_address(connection.sock.getpeername()[0]).compressed
        require(peer == dns['selected_address'], 'canonical TLS connection changed its pinned public peer')
        connection.request('GET', urlsplit(url).path or '/', headers={
            'Accept': 'text/html,application/xhtml+xml', 'User-Agent': 'qcsd-canonical-homepage-v13',
            'Connection': 'close'})
        response = connection.getresponse()
        # Resolution stops after headers. No response body is consumed or promoted
        # to Native GET evidence, content identity, challenge absence or class credit.
        return {'url': url, 'method': 'GET', 'status': response.status,
            'headers': [[name, value] for name, value in response.getheaders()], 'remote_address': peer,
            'tls_hostname': host, 'tls_certificate_verified': True, 'body_read_bytes': 0,
            'complete_body_claimed': False, 'started_at': started, 'completed_at': now()}
    finally:
        connection.close()


@contextmanager
def deadline(seconds):
    """Bound DNS as well as sockets, preserving an enclosing candidate timer."""
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    entered = time.monotonic()
    effective = min(seconds, previous_timer[0]) if previous_timer[0] else seconds
    def expired(signum, frame):
        raise TimeoutError('canonical URL-resolution deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, effective)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0]:
            remaining = max(0.000001, previous_timer[0] - (time.monotonic() - entered))
            signal.setitimer(signal.ITIMER_REAL, remaining, previous_timer[1])


def resolve(root, *, candidate, plan, resolver=resolve_dns, requester=request_headers):
    with deadline(POLICY['total_timeout_seconds']):
        return _resolve(root, candidate=candidate, plan=plan, resolver=resolver, requester=requester)


def _resolve(root, *, candidate, plan, resolver, requester):
    """Root physical URL resolution. Caller keeps failed partial files unchanged."""
    root = Path(root).absolute()
    require(not root.exists() and not root.is_symlink() and root.parent.is_dir(), 'canonical namespace already claimed')
    require(not any(p.is_symlink() for p in root.parents), 'canonical namespace contains a link')
    root.mkdir(mode=0o700)
    current = checked_url(candidate['source_url'], candidate)
    begun, clock_start = now(), time.monotonic()
    hops, seen = [], set()
    for ordinal in range(1, POLICY['max_hops'] + 1):
        require(current not in seen, 'canonical redirect cycle')
        seen.add(current)
        remaining = POLICY['total_timeout_seconds'] - (time.monotonic() - clock_start)
        require(remaining > 0, 'canonical total URL-resolution deadline exceeded')
        started = create(root / f'hop-{ordinal:02d}-started.json',
            {'ordinal': ordinal, 'url': current, 'candidate': candidate, 'plan': plan, 'started_at': now(), **ZERO})
        dns_value = resolver(current)
        dns = create(root / f'hop-{ordinal:02d}-dns.json', dns_value)
        validate_dns(dns_value, current)
        remaining = POLICY['total_timeout_seconds'] - (time.monotonic() - clock_start)
        require(remaining > 0, 'canonical total deadline exceeded during DNS')
        response_value = requester(current, dns_value, min(POLICY['hop_timeout_seconds'], remaining))
        response = create(root / f'hop-{ordinal:02d}-response.json', response_value)
        validate_response(response_value, current, dns_value, candidate)
        completed = create(root / f'hop-{ordinal:02d}-completed.json',
            {'ordinal': ordinal, 'started': started, 'dns': dns, 'response': response, 'completed_at': now(), **ZERO})
        hops.append({'started': started, 'dns': dns, 'response': response, 'completed': completed})
        require(time.monotonic() - clock_start <= POLICY['total_timeout_seconds'], 'canonical total deadline exceeded')
        status = response_value['status']
        if status in POLICY['redirect_statuses']:
            require(ordinal <= POLICY['max_redirects'], 'canonical redirect count exceeded')
            current = location_target(current, response_value, candidate)
            continue
        media = [v.split(';', 1)[0].strip().lower() for k, v in response_value['headers'] if k.lower() == 'content-type']
        require(200 <= status < 300 and len(media) == 1 and media[0] in POLICY['final_media_types'],
                'canonical final response is not HTTPS2xx HTML-labelled headers')
        value = {'artifact_type': TYPE, 'schema_version': 1, 'candidate': candidate, 'plan': plan,
            'initial_url': candidate['source_url'], 'final_url': current, 'policy': POLICY, 'hops': hops,
            'started_at': begun, 'declared_at': now(), 'resolution_role': 'prospective-starting-url-only',
            'native_get_qualification_claimed': False, 'challenge_absence_claimed': False, **ZERO}
        output = root / 'canonical-homepage.json'; create(output, value)
        verify(output, candidate=candidate, plan=plan)
        return reference(output), value
    raise ValueError('canonical redirect chain ended without a declared final URL')


def verify(path, *, candidate=None, plan=None):
    """Read-only reconstruction; no DNS, HTTP, browser, Native or subprocess."""
    path = Path(path).absolute(); reference(path); value = load(path)
    require(isinstance(value, dict) and set(value) == {'artifact_type', 'schema_version', 'candidate', 'plan',
        'initial_url', 'final_url', 'policy', 'hops', 'started_at', 'declared_at', 'resolution_role',
        'native_get_qualification_claimed', 'challenge_absence_claimed', *ZERO}, 'canonical declaration fields changed')
    require(value['artifact_type'] == TYPE and type(value['schema_version']) is int and value['schema_version'] == 1
            and canonical(value['policy']) == canonical(POLICY) and value['resolution_role'] == 'prospective-starting-url-only'
            and value['native_get_qualification_claimed'] is False and value['challenge_absence_claimed'] is False
            and all(type(value.get(k)) is type(v) and value[k] == v for k, v in ZERO.items())
            and (candidate is None or value['candidate'] == candidate) and (plan is None or value['plan'] == plan),
            'canonical declaration changed policy, candidate or zero-credit role')
    candidate = value['candidate']; current = checked_url(value['initial_url'], candidate)
    require(current == candidate['source_url'] and isinstance(value['hops'], list) and 1 <= len(value['hops']) <= POLICY['max_hops'],
            'canonical chain changed initial URL or finite hop count')
    last_time = instant(value['started_at']); seen = set()
    for ordinal, hop in enumerate(value['hops'], 1):
        require(current not in seen and set(hop) == {'started', 'dns', 'response', 'completed'}, 'canonical chain repeats a URL or role')
        seen.add(current)
        documents = {}
        for key, ref in hop.items():
            raw_path = reopen(ref)
            require(raw_path == path.parent / f'hop-{ordinal:02d}-{key}.json' and ref['mode'] == '0600',
                    'canonical raw hop changed namespace, ordinal or full mode')
            documents[key] = load(raw_path)
        begin, dns, response, end = (documents[k] for k in ('started', 'dns', 'response', 'completed'))
        require(set(begin) == {'ordinal', 'url', 'candidate', 'plan', 'started_at', *ZERO}
                and set(end) == {'ordinal', 'started', 'dns', 'response', 'completed_at', *ZERO}
                and type(begin['ordinal']) is int and type(end['ordinal']) is int
                and begin['ordinal'] == ordinal and end['ordinal'] == ordinal
                and begin['url'] == current and begin['candidate'] == candidate and begin['plan'] == value['plan']
                and all(end[k] == hop[k] for k in ('started', 'dns', 'response'))
                and all(type(doc.get(k)) is type(v) and doc[k] == v for doc in (begin, end) for k, v in ZERO.items()),
                'canonical hop changed original command identity or zero credit')
        validate_dns(dns, current); validate_response(response, current, dns, candidate)
        require(last_time <= instant(begin['started_at']) <= instant(dns['started_at'])
                and instant(response['completed_at']) <= instant(end['completed_at']), 'canonical hop chronology changed')
        last_time = instant(end['completed_at'])
        if ordinal < len(value['hops']):
            require(response['status'] in POLICY['redirect_statuses'], 'canonical chain continued after a final response')
            current = location_target(current, response, candidate)
        else:
            media = [v.split(';', 1)[0].strip().lower() for k, v in response['headers'] if k.lower() == 'content-type']
            require(200 <= response['status'] < 300 and len(media) == 1 and media[0] in POLICY['final_media_types'],
                    'canonical chain lacks final2xx HTML-labelled headers')
    declared = instant(value['declared_at'])
    require(value['final_url'] == current and last_time <= declared <= datetime.now(timezone.utc)
            and (declared - instant(value['started_at'])).total_seconds() <= POLICY['total_timeout_seconds'] + 0.001,
            'canonical final URL or preflight duration changed')
    return value


def verify_partial(root, *, candidate, plan, not_before, not_after):
    """Authenticate an unchanged failed resolution without approving its URL."""
    root = Path(root).absolute()
    if not root.exists():
        return
    require(root.is_dir() and not root.is_symlink(), 'partial resolution namespace changed type')
    files = set(root.iterdir())
    require(not (root / 'canonical-homepage.json').exists(), 'completed resolution cannot be relabelled partial')
    current, last_time, seen = candidate['source_url'], not_before, set()
    for ordinal in range(1, POLICY['max_hops'] + 1):
        names = {key: root / f'hop-{ordinal:02d}-{key}.json' for key in ('started', 'dns', 'response', 'completed')}
        present = {key for key, path in names.items() if path in files}
        if not present:
            break
        require('started' in present and current not in seen, 'partial resolution skipped a start or followed a cycle')
        seen.add(current); checked_url(current, candidate)
        values, refs = {}, {}
        for key in present:
            refs[key] = reference(names[key]); values[key] = load(names[key]); files.remove(names[key])
            require(refs[key]['mode'] == '0600', 'partial raw resolution full mode changed')
        begin = values['started']
        require(set(begin) == {'ordinal', 'url', 'candidate', 'plan', 'started_at', *ZERO}
                and type(begin['ordinal']) is int and begin['ordinal'] == ordinal and begin['url'] == current
                and begin['candidate'] == candidate and begin['plan'] == plan
                and all(type(begin.get(key)) is type(expected) and begin[key] == expected for key, expected in ZERO.items())
                and last_time <= instant(begin['started_at']) <= not_after, 'partial original resolution start changed')
        if 'dns' not in present:
            require(present == {'started'}, 'partial resolution sent HTTP before DNS')
            break
        dns = values['dns']
        require(set(dns) == {'url', 'hostname', 'addresses', 'selected_address', 'started_at', 'completed_at'}
                and dns['url'] == current and dns['hostname'] == urlsplit(current).hostname
                and isinstance(dns['addresses'], list) and dns['addresses'] and dns['addresses'] == sorted(set(dns['addresses']))
                and dns['selected_address'] in dns['addresses']
                and instant(begin['started_at']) <= instant(dns['started_at']) <= instant(dns['completed_at']) <= not_after,
                'partial retained DNS identity or chronology changed')
        for address in dns['addresses']:
            require(ipaddress.ip_address(address).compressed == address, 'partial DNS spelling changed')
        try:
            validate_dns(dns, current)
        except ValueError:
            require(present == {'started', 'dns'}, 'failed public DNS validation nevertheless performed HTTP')
            break
        if 'response' not in present:
            require(present == {'started', 'dns'}, 'partial completion omitted its raw HTTP headers')
            break
        response = values['response']
        require(isinstance(response, dict) and set(response) == {'url', 'method', 'status', 'headers', 'remote_address',
                'tls_hostname', 'tls_certificate_verified', 'body_read_bytes', 'complete_body_claimed', 'started_at', 'completed_at'}
                and response['url'] == current and response['method'] == 'GET'
                and type(response['status']) is int and 100 <= response['status'] < 600
                and response['remote_address'] == dns['selected_address']
                and response['tls_hostname'] == urlsplit(current).hostname and response['tls_certificate_verified'] is True
                and type(response['body_read_bytes']) is int and response['body_read_bytes'] == 0
                and response['complete_body_claimed'] is False and isinstance(response['headers'], list)
                and all(isinstance(row, list) and len(row) == 2 and all(isinstance(part, str) for part in row)
                    for row in response['headers'])
                and instant(dns['completed_at']) <= instant(response['started_at']) <= instant(response['completed_at']) <= not_after,
                'partial raw HTTP identity/type/chronology changed')
        try:
            validate_response(response, current, dns, candidate)
        except ValueError:
            require('completed' not in present, 'malformed raw headers gained a completed hop')
            break
        require(instant(response['completed_at']) <= not_after, 'partial HTTP headers postdate failure')
        if 'completed' not in present:
            require(present == {'started', 'dns', 'response'}, 'partial hop roles changed')
            break
        end = values['completed']
        require(set(end) == {'ordinal', 'started', 'dns', 'response', 'completed_at', *ZERO}
                and type(end['ordinal']) is int and end['ordinal'] == ordinal
                and all(end[key] == refs[key] for key in ('started', 'dns', 'response'))
                and all(type(end.get(key)) is type(expected) and end[key] == expected for key, expected in ZERO.items())
                and instant(response['completed_at']) <= instant(end['completed_at']) <= not_after,
                'partial hop completion changed original refs/chronology')
        last_time = instant(end['completed_at'])
        if not files:
            break
        require(response['status'] in POLICY['redirect_statuses'] and ordinal <= POLICY['max_redirects'],
                'partial chain continued after a nonredirect or exceeded its redirect limit')
        current = location_target(current, response, candidate)
    require(not files, 'failed resolution changed its finite original raw membership')
