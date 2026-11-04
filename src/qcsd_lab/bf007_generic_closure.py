"""Experimental BF007 runtime closure check; not an admission authority.

The caller must obtain both expected hashes from an independent, already
authorized input.  Nothing in this module makes a self-declared digest trusted,
or verifies that the build recorder itself was an authorized producer.
"""
import hashlib
import json
import os
import re
import stat
from pathlib import Path

TYPE = 'qcsd-bf007-source141-original-installed-overlay-runtime-v1'
CLIENT = '80685437b19903e3792d6b49426fd7cb4ff82431b2b4764c074dae12ec86ba05'
COMMIT = '7229b4d9d310e2ac347084cf148c2b29b03eaa78'
PRODUCER_GUEST = '73427e1500cf3afd6bf31acd083588608496862dd12e971792ba1a0b15651405'
PRODUCER_HOST = 'c4f49f7720362cc826709e92a4f785cc8d47088e40dd5ffdc2f3da319a936ab1'
NATIVE_RESULT = 'a5d029683b4b575adcd354c85f7e249e93baca4f10ead036d3ffc43d29650da3'
NATIVE_STDOUT = 'd8f31d983d3269a35621a981dfb15997a5f8432742ac0347e0f065975754915e'
BASES = {'collection': 'sha256:809b99909968d92f3ac533cd9160bc952a76619e3be4e04c4eb78f461f3b5922',
         'prepare': 'sha256:0ddecab685b98c679137389ecbca72f16abd14366db0406297369a92f7807344'}
EMPTY = hashlib.sha256(b'').hexdigest()
FILES = frozenset(('native-result.json', 'native-stdout.log', 'overlay-result.json',
                   'overlay-stdout.log', 'collection-proof.json', 'prepare-proof.json',
                   'source-metadata.json', 'neqo-qcsd-client', 'build-spec.json',
                   'build-producer-guest.py', 'build-producer-host.py'))


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def checked_digest(value):
    need(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value), 'invalid digest')
    return value


def stamp(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_nlink, s.st_mode,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read(path, expected, limit=16 * 1024**2):
    path = Path(path)
    checked_digest(expected)
    need(path.is_absolute() and path.resolve(strict=True) == path
         and not any(p.is_symlink() for p in (path, *path.parents)), 'noncanonical path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in (0o444, 0o555)
             and 0 < before.st_size <= limit, 'file custody differs')
        with os.fdopen(os.dup(fd), 'rb') as handle:
            raw = handle.read(limit + 1)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat())
             and digest(raw) == expected, 'file changed or digest differs')
        return raw
    finally:
        os.close(fd)


def events(result, raw, *, producer=None):
    need(result['returncode'] == 0 and result['scientific_credit'] is False
         and result['files']['stdout.log']['sha256'] == digest(raw)
         and result['files']['stdout.log']['size_bytes'] == len(raw), 'recorded result differs')
    terminal = json.loads(raw.splitlines()[-1])
    need(terminal['event'] == 'terminal' and terminal['returncode'] == 0
         and terminal['reason'] is None, 'operation not closed')
    if producer is not None:
        need(all(terminal.get(k) == v for k, v in producer.items()), 'host producer identity differs')
    return [json.loads(line) for line in terminal['guest_output'].splitlines() if line.startswith('{')]


def verify(path, *, expected_canonical_sha256, expected_source_contract_sha256):
    """Check an explicitly pinned closure; do not infer trust from the closure.

    Both expected hashes must be independent inputs, never values read from the
    canonical being checked. Image digests and lab commit are data, not code.
    """
    checked_digest(expected_source_contract_sha256)
    path = Path(path)
    raw = read(path, expected_canonical_sha256, limit=1024 * 1024)
    value = json.loads(raw)
    need(value['artifact_type'] == TYPE and value['schema_version'] == 1
         and value['platform'] == 'linux/arm64' and value['client_sha256'] == CLIENT
         and value['installed_client_sha256'] == CLIENT
         and value['worker_source_contract_sha256'] == expected_source_contract_sha256
         and value['native_action'] == 'separate-actual-cached-build-and-exact-client-overlay'
         and value['installed_scope'] == 'original-per-role-installed-verifier'
         and value['scientific_credit'] is False and value['formal_accepted_trace_count'] == 0
         and value['source_authorized'] is False and value['admission_authorized'] is False,
         'canonical contract differs')
    source = value['source']
    need(source['image_digest'] is None and source['neqo_commit'] == COMMIT
         and source['neqo_pinned_commit'] == COMMIT and source['lab_dirty'] is False
         and source['neqo_dirty'] is False and source['lab_patch_sha256'] == EMPTY
         and source['neqo_patch_sha256'] == EMPTY
         and isinstance(source['lab_commit'], str)
         and re.fullmatch(r'[0-9a-f]{40}', source['lab_commit']), 'source differs')
    file_hashes = value['files']
    need(set(file_hashes) == FILES and file_hashes['neqo-qcsd-client'] == CLIENT
         and file_hashes['native-result.json'] == NATIVE_RESULT
         and file_hashes['native-stdout.log'] == NATIVE_STDOUT
         and file_hashes['build-producer-guest.py'] == PRODUCER_GUEST
         and file_hashes['build-producer-host.py'] == PRODUCER_HOST, 'file set or producer differs')
    records = {name: read(path.parent / name, file_hashes[name]) for name in FILES}
    need(json.loads(records['source-metadata.json']) == source, 'source metadata differs')
    spec = json.loads(records['build-spec.json'])
    need(spec['producer_guest_sha256'] == PRODUCER_GUEST
         and spec['producer_host_sha256'] == PRODUCER_HOST
         and spec['source_contract_sha256'] == expected_source_contract_sha256
         and spec['source_metadata_sha256'] == file_hashes['source-metadata.json']
         and spec['lab_commit'] == source['lab_commit'], 'producer specification differs')
    native = events(json.loads(records['native-result.json']), records['native-stdout.log'])
    producer = {'producer_guest_sha256': PRODUCER_GUEST, 'producer_host_sha256': PRODUCER_HOST,
                'build_spec_sha256': file_hashes['build-spec.json']}
    overlay = events(json.loads(records['overlay-result.json']), records['overlay-stdout.log'], producer=producer)
    builds = [x for x in native if x.get('event') == 'build_completed']
    images = [x for x in overlay if x.get('event') == 'two_role_images_verified']
    need(len(builds) == len(images) == 1 and builds[0]['candidate_commit'] == COMMIT
         and builds[0]['base_commit'] == 'd0165a6abbc87d3f7e5a697d33f1504d1f41399b'
         and builds[0]['patch_sha256'] == 'f6404e77f23db43b7480534adf04ef853f369bbdbbf60587c7b43b604159f110'
         and builds[0]['candidate_mod_sha256'] == 'bff49e99b268b231a6fb7f76baca14ba2104f2c9f07e1b06e3d6023e1a98ba99'
         and builds[0]['binary']['sha256'] == CLIENT and builds[0]['binary']['bytes'] == 7965376
         and builds[0]['scientific_credit_added'] == 0
         and any(x.get('event') == 'lifecycle_closed' and x.get('locks_released') is True
                 and x.get('completed') is True and x.get('scientific_credit_added') == 0 for x in native)
         and images[0]['source'] == source and images[0]['candidate_client_sha256'] == CLIENT
         and images[0]['source_contract_sha256'] == expected_source_contract_sha256
         and all(images[0].get(k) == v for k, v in producer.items())
         and any(x.get('event') == 'locks_released' for x in overlay), 'build closure differs')
    role_images = []
    for role in ('collection', 'prepare'):
        image = value[role + '_image_digest']
        need(isinstance(image, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'image ID differs')
        role_images.append(image)
        proof = json.loads(records[role + '-proof.json'])
        need(images[0]['roles'][role]['image'] == image and images[0]['roles'][role]['base'] == BASES[role]
             and images[0]['roles'][role]['installed_proof_sha256'] == file_hashes[role + '-proof.json']
             and proof['role'] == role and proof['source'] == source and proof['image_digest'] == image
             and proof['source_inventory_sha256'] == spec['source_inventory_sha256']
             and proof['source_metadata_raw_sha256'] == spec['source_metadata_sha256']
             and proof['client_sha256'] == CLIENT and proof['platform'] == 'linux/arm64'
             and proof['site_credit'] == 0 and proof['formal_accepted_trace_count'] == 0,
             'installed role proof differs')
    need(role_images[0] != role_images[1], 'roles share an image')
    return {'collection_image_digest': role_images[0], 'prepare_image_digest': role_images[1],
            'client_sha256': CLIENT, 'platform': 'linux/arm64', 'native_commit': COMMIT,
            'source': source, 'canonical_sha256': digest(raw)}
