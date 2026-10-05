"""Explicit external navigation policy for one owned canceled continuation.

The exact original public-DNS/egress/navigation functions run in a private
namespace. Original modules and the full-graph renderer are never replaced.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
from types import FunctionType

from . import class_acquisition as acquisition
from . import cdp_targets as cdp

POLICY = 'exact-owned-canceled-root-continue-with-complete-observation-v1'
TYPE = 'qcsd-external-owned-canceled-navigation-control-v1'
SOURCE_SHA256 = {
    'class_acquisition.py': '062e0f4b1829f141a010027a1c2bd3f960a06bca305e91e49f20d52b971288de',
    'cdp_targets.py': '78a552a29d8da28e7ed44c3de0472e241417349de318569e6d304f564d8af812',
}
MAX_EVENTS = 16384
MAX_ACCEPTED = 4096
COMMAND_LABEL = 'catalogue-navigation-policy:Fetch.continueRequest'
ZERO = {'scientific_credit': False, 'site_credit': 0, 'formal_accepted_trace_count': 0}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def source_refs():
    refs = {}
    for name,module in [('class_acquisition.py',acquisition),('cdp_targets.py',cdp)]:
        path=Path(module.__file__).absolute()
        if path.name != name or any(p.is_symlink() for p in (path,*path.parents)):
            raise cdp.CdpTargetIntegrityError('navigation imported a different original Source')
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=SOURCE_SHA256[name] or path.stat().st_mode&0o7777 != 0o644:
            raise cdp.CdpTargetIntegrityError('navigation original Source bytes or mode changed')
        refs[name]={'path':str(path),'sha256':SOURCE_SHA256[name],'mode':'0644'}
    return refs


def validate_canceled_continuation(row):
    """Replay the exact owned raw identity/terminal/order; never infer success."""
    keys={'policy','source','root_frame_id','navigation_pins','network','fetch','terminal','command',
          'network_sequence','fetch_sequence','command_sequence','terminal_sequence','error_sequence',
          'transport_fingerprint','disposition','continuation_acknowledged','raw_evidence_sha256'}
    if not isinstance(row,dict) or set(row)!=keys or row['policy']!=POLICY:
        raise cdp.CdpTargetIntegrityError('owned canceled continuation fields or policy changed')
    body={k:v for k,v in row.items() if k!='raw_evidence_sha256'}
    if row['raw_evidence_sha256']!=digest(body):
        raise cdp.CdpTargetIntegrityError('owned canceled continuation raw facts changed')
    source=row['source']
    source_keys={'session_path','target_id','target_type','generation','parent_session_path','parent_frame_id'}
    if (not isinstance(source,dict) or set(source)!=source_keys or source['session_path']!=[]
        or source['target_type']!='page' or type(source['generation']) is not int or source['generation']!=0
        or source['parent_session_path'] is not None or source['parent_frame_id'] is not None
        or not isinstance(source['target_id'],str) or not source['target_id']):
        raise cdp.CdpTargetIntegrityError('owned canceled continuation is not the exact root page')
    n,f,t=row['network'],row['fetch'],row['terminal']
    if not all(isinstance(x,dict) for x in (n,f,t)):
        raise cdp.CdpTargetIntegrityError('owned canceled continuation raw events absent')
    nr,fr=n.get('request'),f.get('request')
    if not isinstance(nr,dict) or not isinstance(fr,dict):
        raise cdp.CdpTargetIntegrityError('owned canceled continuation raw requests absent')
    pins=acquisition._validated_frozen_origin_ip_pins(tuple(sorted(row['navigation_pins'])),row['navigation_pins'])
    frame=row['root_frame_id']
    network_id=n.get('requestId');fetch_id=f.get('requestId');kind=n.get('type')
    if (not isinstance(frame,str) or not frame or kind not in {'Script','Other'}
        or n.get('frameId')!=frame or f.get('frameId')!=frame or f.get('resourceType')!=kind
        or not isinstance(network_id,str) or not network_id or not isinstance(fetch_id,str) or not fetch_id
        or fetch_id==network_id or f.get('networkId')!=network_id or t.get('requestId')!=network_id
        or 'redirectResponse' in n or 'redirectedRequestId' in f
        or any(k in f for k in ('responseStatusCode','responseStatusText','responseHeaders','responseErrorReason'))
        or nr.get('method')!='GET' or fr.get('method')!='GET' or nr.get('url')!=fr.get('url')
        or acquisition.origin(nr.get('url','')) not in pins
        or set(t)!={'requestId','timestamp','type','errorText','canceled'}
        or t.get('type')!=kind or t.get('errorText')!='net::ERR_ABORTED' or t.get('canceled') is not True
        or not cdp._is_finite_protocol_number(t.get('timestamp'))
        or row['command']!={'method':'Fetch.continueRequest','params':{'requestId':fetch_id},'label':COMMAND_LABEL}
        or re.fullmatch(r'exception_sha256=[0-9a-f]{64}',row['transport_fingerprint']) is None
        or row['disposition']!='owned-canceled-request-retained-no-continuation-success'
        or row['continuation_acknowledged'] is not False):
        raise cdp.CdpTargetIntegrityError('owned canceled continuation identity/terminal/pins/command differs')
    seq=[row[k] for k in ('network_sequence','fetch_sequence','command_sequence','terminal_sequence','error_sequence')]
    if any(type(x) is not int or x<=0 for x in seq) or len(set(seq))!=len(seq):
        raise cdp.CdpTargetIntegrityError('owned canceled continuation event order is malformed')
    network,fetch,command,terminal,error=seq
    if not (network<fetch<command<error and network<terminal<error
            and (terminal<fetch or command<terminal)):
        raise cdp.CdpTargetIntegrityError('owned canceled terminal is not before pause or during exact send')
    return row


class OwnedCanceledContinuationRouter(cdp.RecursiveCdpTargetRouter):
    def __init__(self,*args,navigation_pins,collector,**kwargs):
        self._control_pins=acquisition._validated_frozen_origin_ip_pins(tuple(sorted(navigation_pins)),navigation_pins)
        self._control_events=[];self._control_commands=[];self._control_sequence=0
        self._control_accepted=set();self._control_collector=collector
        super().__init__(*args,**kwargs)

    def _next_control_sequence(self):
        self._control_sequence+=1
        return self._control_sequence

    def _handle_root_event(self,method,event):
        if method in {'Network.requestWillBeSent','Fetch.requestPaused','Network.loadingFailed','Network.loadingFinished'}:
            if len(self._control_events)>=MAX_EVENTS:
                raise cdp.CdpTargetIntegrityError('external navigation raw-event bound exceeded')
            self._control_events.append((self._next_control_sequence(),method,deepcopy(dict(event))))
        return super()._handle_root_event(method,event)

    def send(self,source,method,params,*,label):
        if source==self.root_source and method=='Fetch.continueRequest' and label==COMMAND_LABEL:
            self._control_commands.append((self._next_control_sequence(),deepcopy(dict(params))))
        return super().send(source,method,params,label=label)

    def _provision_root_invalid_interception(self,decision,*,fingerprint):
        # Original reducer first proves unique source/frame/GET/occurrence,
        # claimed Fetch, exact genuine cancellation, no active/reused/redirect
        # or saturated identity, and issuance of the exact continue command.
        try:
            return super()._provision_root_invalid_interception(decision,fingerprint=fingerprint)
        except cdp._RootCanceledNetworkInvalidInterception:
            key=(decision.policy_source,decision.network_id)
            terminal=self._root_terminal_requests.get(key)
            if (self._shutting_down or self._aborting or terminal is None
                or terminal.terminal_method!='Network.loadingFailed' or key in self._control_accepted
                or len(self._control_accepted)>=MAX_ACCEPTED):
                raise cdp.CdpTargetIntegrityError('owned canceled continuation cannot be accepted during disposal/reuse')
            networks=[(s,e) for s,m,e in self._control_events if m=='Network.requestWillBeSent' and e.get('requestId')==decision.network_id]
            fetches=[(s,e) for s,m,e in self._control_events if m=='Fetch.requestPaused' and e.get('requestId')==decision.fetch_request_id]
            terminals=[(s,e) for s,m,e in self._control_events if m in {'Network.loadingFinished','Network.loadingFailed'} and e.get('requestId')==decision.network_id]
            commands=[(s,p) for s,p in self._control_commands if p.get('requestId')==decision.fetch_request_id]
            if any(len(rows)!=1 for rows in (networks,fetches,terminals,commands)):
                raise cdp.CdpTargetIntegrityError('owned canceled continuation raw history is missing or reused')
            ns,n=networks[0];fs,f=fetches[0];ts,t=terminals[0];cs,p=commands[0]
            row={'policy':POLICY,'source':json.loads(canonical(asdict(self.root_source))),
                 'root_frame_id':self._root_frame_id,'navigation_pins':dict(self._control_pins),
                 'network':n,'fetch':f,'terminal':t,
                 'command':{'method':'Fetch.continueRequest','params':p,'label':COMMAND_LABEL},
                 'network_sequence':ns,'fetch_sequence':fs,'terminal_sequence':ts,
                 'command_sequence':cs,'error_sequence':self._next_control_sequence(),
                 'transport_fingerprint':fingerprint,
                 'disposition':'owned-canceled-request-retained-no-continuation-success',
                 'continuation_acknowledged':False}
            row['raw_evidence_sha256']=digest(row)
            validate_canceled_continuation(row)
            self._control_accepted.add(key)
            self._control_collector.append(row)
            # Nothing is acknowledged or redispatched. The complete original
            # navigation/egress/target lifecycle checks continue normally.
            return None


def _clone(function,namespace):
    value=FunctionType(function.__code__,namespace,function.__name__,function.__defaults__,function.__closure__)
    value.__kwdefaults__=dict(function.__kwdefaults__) if function.__kwdefaults__ is not None else None
    return value


def collect_navigation(domain,*,timeout_ms):
    sources=source_refs();passes=[]
    def owned_pass(*args,**kwargs):
        pins=kwargs['navigation_pins'];rows=[]
        def router(*ra,**rk):
            return OwnedCanceledContinuationRouter(*ra,navigation_pins=pins,collector=rows,**rk)
        namespace={**acquisition.__dict__,'RecursiveCdpTargetRouter':router}
        outcome='failed'
        try:
            value=_clone(acquisition._catalogue_boundary_navigation_pass,namespace)(*args,**kwargs)
            outcome='completed'
            return value
        except acquisition._NavigationPinExpansion:
            outcome='pin-expansion'
            raise
        finally:
            passes.append({'ordinal':len(passes)+1,'navigation_pins':dict(pins),
                'accepted_canceled_continuations':deepcopy(rows),'outcome':outcome})
    namespace={**acquisition.__dict__,'_catalogue_boundary_navigation_pass':owned_pass}
    try:
        value=_clone(acquisition.catalogue_boundary_navigation,namespace)(domain,timeout_ms=timeout_ms)
    except Exception as error:
        original=deepcopy(getattr(error,'evidence',None))
        if original is not None and not isinstance(original,dict):
            raise cdp.CdpTargetIntegrityError('original exception evidence is malformed') from error
        error.evidence={'original_exception_evidence':original,'external_canceled_navigation_control':{
            'policy':POLICY,'domain':domain,'original_sources':sources,'navigation_passes':deepcopy(passes),**ZERO}}
        raise
    control={'schema_version':1,'artifact_type':TYPE,'policy':POLICY,'domain':domain,'original_sources':sources,
             'navigation_passes':passes,'accepted_canceled_continuation_count':sum(len(p['accepted_canceled_continuations']) for p in passes),
             'continuation_success_claimed':False,**ZERO}
    validate_navigation_control(control,domain=domain)
    return value,control


def validate_navigation_control(value,*,domain):
    keys={'schema_version','artifact_type','policy','domain','original_sources','navigation_passes',
          'accepted_canceled_continuation_count','continuation_success_claimed',*ZERO}
    if (not isinstance(value,dict) or set(value)!=keys or type(value['schema_version']) is not int or value['schema_version']!=1
        or value['artifact_type']!=TYPE or value['policy']!=POLICY or value['domain']!=domain
        or value['original_sources']!=source_refs() or value['continuation_success_claimed'] is not False
        or any(type(value[k]) is not type(v) or value[k]!=v for k,v in ZERO.items())
        or not isinstance(value['navigation_passes'],list) or not 1<=len(value['navigation_passes'])<=acquisition.MAX_ORIGIN_PASSES):
        raise cdp.CdpTargetIntegrityError('explicit navigation control authority differs')
    count=0
    for i,p in enumerate(value['navigation_passes'],1):
        if (not isinstance(p,dict) or set(p)!={'ordinal','navigation_pins','accepted_canceled_continuations','outcome'}
            or type(p['ordinal']) is not int or p['ordinal']!=i or not isinstance(p['accepted_canceled_continuations'],list)
            or p['outcome']!=('completed' if i==len(value['navigation_passes']) else 'pin-expansion')):
            raise cdp.CdpTargetIntegrityError('explicit navigation control pass differs')
        acquisition._validated_frozen_origin_ip_pins(tuple(sorted(p['navigation_pins'])),p['navigation_pins'])
        identities=set()
        for row in p['accepted_canceled_continuations']:
            validate_canceled_continuation(row)
            key=(row['source']['target_id'],row['network']['requestId'])
            if key in identities or row['navigation_pins']!=p['navigation_pins']:
                raise cdp.CdpTargetIntegrityError('explicit canceled navigation reuses ownership or pins')
            identities.add(key);count+=1
    if type(value['accepted_canceled_continuation_count']) is not int or value['accepted_canceled_continuation_count']!=count:
        raise cdp.CdpTargetIntegrityError('explicit canceled navigation count differs')
    return value
