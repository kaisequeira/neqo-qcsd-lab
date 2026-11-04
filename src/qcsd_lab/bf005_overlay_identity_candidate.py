"""Candidate additive runtime identity reader; no Source or admission authority.

Its BF005 branch validates a separate overlay closure. A caller must continue
to use the original reader for every other runtime, and original study/session,
quota, exclusion, withdrawal and Source checks remain unchanged.
"""
import hashlib,json,os,stat
from pathlib import Path

TYPE='qcsd-bf005-original-installed-overlay-runtime-v1'
CANONICAL_PATH=Path('/mnt/lima-neqo-data/neqo-obfuscation/study/cohort-store-002/bf005-overlay-runtime-identity-20261101-001/canonical-runtime.json')
CANONICAL_SHA='4734b0296e4ebf7602da1f8ea5172dec5f8a22478416f9ff8d463a5b009a2d43'
CLIENT='e80da6103a669bef35b782a0c05e774d04367f9298bb083a316f2ef9b0b0eaa5'
COMMIT='80ff16c2ddf1f0c0a446e1d91bfd60c02c47fac3'
LAB='c831f481bab92499d48c6d0c6358876336fd02eb'
EMPTY='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
COLLECTION='sha256:7713bc032702b8caa42613f882075ede11dbc07821c4e2feb28eb582a431e5f3'
PREPARE='sha256:a92a80643b8d8e34bb1c0120abacee40ed19156505b36ab54dc7bc50c3c34304'
SOURCE={'image_digest':None,'lab_commit':LAB,'lab_dirty':False,'lab_patch_sha256':EMPTY,
        'neqo_commit':COMMIT,'neqo_pinned_commit':COMMIT,'neqo_dirty':False,'neqo_patch_sha256':EMPTY}
FILES={'native-result.json':'78b3351e08923cdf12cadd94a96dc7711aa2051b964bc445963ecd7fd9c195d7',
       'native-stdout.log':'f9caae00d06477f5b5d6829718f3db863f7a28a82359307d2803dc7ebeb12ff0',
       'overlay-result.json':'ee1f1b98768c3199eedc015aad80160f19067006a3db58d2d6aff205b6b6b480',
       'overlay-stdout.log':'05d2345b48a1491bedb14d0ce9f33f75307a8895f6c7c40d72abdb84e0d508d8',
       'collection-proof.json':'6ef2697c1f752bd5429fe15eacc82eebdd54638426d3248bc1eccaeb267a516f',
       'prepare-proof.json':'27b7772d58ad57c45459c7efa33dda4cef95321d4554ff4178db5c06fd2c9844',
       'source-metadata.json':'e617b2cbee7daa916d8e75ea9c2fb98192f3d04fb6a640ae127c3675c8b69c95',
       'neqo-qcsd-client':CLIENT}
CANONICAL={'artifact_type':TYPE,'schema_version':1,'source':SOURCE,'platform':'linux/arm64',
           'client_sha256':CLIENT,'installed_client_sha256':CLIENT,'collection_image_digest':COLLECTION,'prepare_image_digest':PREPARE,
           'files':FILES,'native_action':'separate-actual-cached-build-and-exact-client-overlay',
           'installed_scope':'original-per-role-installed-verifier','scientific_credit':False,
           'formal_accepted_trace_count':0,'source_authorized':False,'admission_authorized':False}

def need(v,m):
    if not v:raise ValueError(m)
def digest(b):return hashlib.sha256(b).hexdigest()
def stamp(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_nlink,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,expected=None,limit=16*1024**2):
    path=Path(path)
    need(path.is_absolute() and path.resolve(strict=True)==path and not any(x.is_symlink() for x in (path,*path.parents)),
         'overlay file must have a canonical nonsymlink path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        a=os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_uid==os.getuid() and a.st_nlink==1
             and stat.S_IMODE(a.st_mode) in (0o444,0o555) and 0<a.st_size<=limit,'overlay file custody differs')
        with os.fdopen(os.dup(fd),'rb') as f:raw=f.read(limit+1)
        need(len(raw)==a.st_size and stamp(a)==stamp(os.fstat(fd))==stamp(path.lstat())
             and (expected is None or digest(raw)==expected),'overlay file changed')
        return raw
    finally:os.close(fd)
def _events(result,raw):
    need(result['returncode']==0 and result['scientific_credit'] is False and
         result['files']['stdout.log']['sha256']==digest(raw) and result['files']['stdout.log']['size_bytes']==len(raw),
         'recorded operation/source association differs')
    terminal=json.loads(raw.splitlines()[-1])
    need(terminal['event']=='terminal' and terminal['returncode']==0 and terminal['reason'] is None,'operation did not close normally')
    return [json.loads(line) for line in terminal['guest_output'].splitlines() if line.startswith('{')]
def overlay_identity(path):
    """Verify exactly this BF005 closure and return SDK-compatible identity."""
    path=Path(path);need(path==CANONICAL_PATH,'candidate path differs')
    raw=read(path,CANONICAL_SHA,limit=1024*1024);need(len(raw)==2026,'candidate canonical size differs');value=json.loads(raw)
    need(value==CANONICAL,'unknown or altered BF005 overlay canonical')
    root=path.parent
    records={name:read(root/name,expected) for name,expected in FILES.items()}
    need(json.loads(records['source-metadata.json'])==SOURCE,'candidate source metadata differs')
    native=_events(json.loads(records['native-result.json']),records['native-stdout.log'])
    overlay=_events(json.loads(records['overlay-result.json']),records['overlay-stdout.log'])
    builds=[x for x in native if x.get('event')=='artifacts']
    images=[x for x in overlay if x.get('event')=='two_role_images_verified']
    need(len(builds)==len(images)==1 and builds[0]['candidate_commit']==COMMIT
         and builds[0]['outputs']['neqo-qcsd-client']['sha256']==CLIENT
         and images[0]['source']==SOURCE and images[0]['candidate_client_sha256']==CLIENT
         and any(x.get('event')=='locks_released' for x in overlay),'native build or image closure differs')
    for role,image in (('collection',COLLECTION),('prepare',PREPARE)):
        p=json.loads(records[role+'-proof.json'])
        need(images[0]['roles'][role]['image']==image
             and images[0]['roles'][role]['installed_proof_sha256']==FILES[role+'-proof.json']
             and p['role']==role and p['source']==SOURCE and p['image_digest']==image
             and p['client_sha256']==CLIENT and p['platform']=='linux/arm64'
             and p['site_credit']==p['formal_accepted_trace_count']==0,'actual installed role proof differs')
    return {'collection_image_digest':COLLECTION,'prepare_image_digest':PREPARE,
            'client_sha256':CLIENT,'platform':'linux/arm64','native_commit':COMMIT,
            'source':SOURCE,'canonical_sha256':digest(raw)}

def candidate_or_none(canonical):
    """Dispatch this exact path only, preserving every legacy input unchanged."""
    if Path(canonical)!=CANONICAL_PATH:return None
    return overlay_identity(canonical)

def runtime_identity(canonical, *, original_runtime_identity):
    """Harness for the additive branch with the untouched original callable."""
    candidate=candidate_or_none(canonical)
    if candidate is not None:return candidate
    return original_runtime_identity(canonical)
