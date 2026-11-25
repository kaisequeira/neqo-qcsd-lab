#!/usr/bin/env python3
"""Isolated MAL roster-v3 BuFLO owner using bounded tmpfs capture staging, bounded to reviewed ACK-gated settings."""
import argparse,csv,fcntl,hashlib,importlib.util,ipaddress,json,os,pathlib,re,resource,secrets,shutil,signal,sqlite3,struct,subprocess,threading,time
os.umask(0o077)
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def stable_read(path,expected=None):
 if path.is_symlink() or not path.is_file():raise ValueError('missing or unsafe file')
 with path.open('rb') as f:
  before=os.fstat(f.fileno());data=f.read();after=os.fstat(f.fileno())
 attrs=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
 if attrs(before)!=attrs(after) or len(data)!=before.st_size:raise ValueError('file changed during read')
 if expected is not None and hashlib.sha256(data).hexdigest()!=expected:raise ValueError('file SHA mismatch')
 return data

def command(args,timeout=60):
 return subprocess.run(args,check=True,text=True,capture_output=True,timeout=timeout).stdout.strip()
def inspect_running_container(cid):
 try:return json.loads(command(['docker','inspect',cid]))[0]
 except subprocess.CalledProcessError as e:
  message=(e.stderr or '').lower()
  if 'no such object' not in message and 'no such container' not in message:raise
  if cid in command(['docker','ps','-q','--no-trunc']).splitlines():raise
  return None
def sync_dir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def cap_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024**2,64*1024**2));os.sched_setaffinity(0,{STORAGE_CONFIG['observer_cpu']})
def socket_address(value):
 h,p=value.rsplit(':',1);return str(ipaddress.ip_address(h.strip('[]'))),int(p)
def tuple_keys(run):
 keys=[]
 for e in run.get('endpoints') or []:
  t=e['tuple']
  if t.get('protocol')!='udp':raise ValueError('non-UDP endpoint')
  lh,lp=socket_address(t['local']);rh,rp=socket_address(t['remote'])
  if not (1<=lp<=65535 and 1<=rp<=65535):raise ValueError('invalid endpoint port')
  keys.append(json.dumps(['udp',lh,lp,rh,rp],separators=(',',':')))
 if not keys or len(keys)!=len(set(keys)):raise ValueError('missing or duplicate native tuple')
 return keys
def h3_valid(run,host):
 endpoints=run.get('endpoints') or []
 return len(endpoints)==1 and isinstance(endpoints[0],dict) and endpoints[0].get('origin')=='https://'+host+'/' and endpoints[0].get('negotiated_protocol')=='h3'
def defended_chaff_clean(chaff,maximum,mode,diag):
 if not isinstance(chaff,list) or type(maximum) is not int or maximum<0 or any(not isinstance(x,dict) for x in chaff):return False
 expected='buflo_terminal_subcell_tail_cancelled' if mode=='buflo' else 'local_early_termination_cancelled'
 latch='buflo_terminal_subcell_latched' if mode=='buflo' else 'cs_buflo_local_termination_latched'
 cancelled=[]
 for n,item in enumerate(chaff):
  if chaff_entry_clean(item):continue
  mismatch=any(item.get(k) is False for k in ('status_match','content_encoding_match','body_bytes_match','body_sha256_match','identity_verified'))
  if mismatch or item.get('outcome')!=expected or item.get('complete') is not False:return False
  cancelled.append(n)
 return len(cancelled)<=maximum and (not cancelled or (diag.get(latch) is True and cancelled==list(range(cancelled[0],len(chaff)))))
def defended_run_clean(run,host,roster,workload_sha,prepared_sha,chaff_sha,mode,param_sha):
 if not isinstance(run,dict) or run.get('request_policy')!='half-duplex':return False
 if mode not in ('buflo','cs-buflo') or not isinstance(run,dict) or not isinstance(roster,list) or len(roster)!=20:return False
 if any(not isinstance(x,dict) or type(x.get('id')) is not int or not isinstance(x.get('url'),str) for x in roster):return False
 expected={(x['id'],x['url']) for x in roster};responses=run.get('responses')
 if len(expected)!=20 or {x[0] for x in expected}!=set(range(20)) or not isinstance(responses,list) or len(responses)!=20:return False
 if any(not isinstance(x,dict) or x.get('complete') is not True or x.get('outcome')!='succeeded' or type(x.get('status')) is not int or not 200<=x['status']<300 for x in responses):return False
 pairs={(x.get('resource_id'),x.get('url')) for x in responses};kind=mode.replace('-','_');cfg=run.get('resolved_configuration') or {};params=run.get('defense_parameters') or {};diag=run.get('defense_diagnostics') or {}
 chaff_ok=defended_chaff_clean(run.get('chaff_responses'),cfg.get('max_chaff_streams',5),mode,diag)
 return (pairs==expected and h3_valid(run,host) and cfg.get('defense',{}).get('kind')==kind and params.get('kind')==kind and params.get('sha256')==param_sha and
         type(run.get('defense_start_monotonic_ns')) is int and run['defense_start_monotonic_ns']>0 and
         run.get('completion_status')=='complete' and not run.get('error') and not run.get('error_class') and
         run.get('workload_hash_sha256')==workload_sha and run.get('application_workload_source_hash_sha256')==prepared_sha and
         run.get('chaff_manifest_hash_sha256')==chaff_sha and chaff_ok and diag.get(kind+'_event_guard_triggered') is False and
         diag.get(kind+'_application_complete') is True and diag.get(kind+'_incoming_unresolved_cells')==0 and diag.get(kind+'_outgoing_unresolved_cells')==0 and
         (diag.get('buflo_minimum_duration_reached') is True if mode=='buflo' else diag.get('cs_buflo_quiet_time_reached') is True))
def chaff_entry_clean(c):
 if type(c) is not dict:return False
 mismatched=any(c.get(k) is False for k in ('status_match','content_encoding_match','body_bytes_match','body_sha256_match','identity_verified'))
 return not mismatched and ((c.get('outcome')=='succeeded' and c.get('complete') is True and c.get('identity_verified') is True) or (c.get('outcome')=='incomplete' and c.get('complete') is False))
def clean_chaff(chaff,max_streams=5):
 if type(chaff) is not list or any(type(c) is not dict for c in chaff):return False,[]
 incomplete=[i for i,c in enumerate(chaff) if c.get('outcome')=='incomplete']
 first=incomplete[0] if incomplete else len(chaff)
 return (len(incomplete)<=max_streams and incomplete==list(range(first,len(chaff))) and all(chaff_entry_clean(c) for c in chaff)),incomplete
def quiet_tail_screen(diag,events):
 shortfall=diag.get('wtf_pad_incoming_shortfall_bytes');retired=diag.get('scheduled_incoming_retired_bytes')
 if type(shortfall) is not int or type(retired) is not int:return False
 if shortfall==0:return not events
 if not 1<=shortfall<=8 or retired!=shortfall or len(events)!=1:return False
 event=events[0]
 return (type(event.get('retired_bytes')) is int and event['retired_bytes']==shortfall and event.get('maximum_bytes')==8 and event.get('minimum_quiet_seconds')==2 and type(event.get('quiet_since_last_defense_observation_us')) is int and event['quiet_since_last_defense_observation_us']>=2000000)

def failure_counts(prior,slot):
 scoped=[r for r in prior if r.get('purpose')=='production' and r.get('capture_storage_policy_sha256')==STORAGE_CONFIG.get('storage_policy_sha256') and
         r.get('native_client_sha256')==CLIENT_SHA and r.get('input_sha256')==INPUT_SHA and
         r.get('dispatch_variation_sha256')==VARIATION_SHA and r.get('receive_window_variation_sha256')==RECEIVE_NOTE_SHA]
 return (sum(r.get('slot')==slot and r.get('status')!='success' and r.get('packet_count_screen_passed') is True for r in scoped),
         sum(r.get('slot')==slot and r.get('status')!='success' and r.get('packet_count_screen_passed') is False for r in scoped))

def pcap_tuple_keys(path,isolation):
 import struct
 found=set();network=ipaddress.ip_network(CONFIG['network']['subnet'])
 with pathlib.Path(path).open('rb') as f:
  hdr=f.read(24)
  if len(hdr)!=24 or hdr[:4] not in isolation.MAGIC:raise ValueError('partial PCAP header unavailable')
  order=isolation.MAGIC[hdr[:4]]
  if struct.unpack(order+'I',hdr[20:24])[0]!=1:raise ValueError('partial PCAP link type unsupported')
  while True:
   ph=f.read(16)
   if not ph:break
   if len(ph)!=16:raise ValueError('truncated partial PCAP record')
   _,_,caplen,origlen=struct.unpack(order+'IIII',ph)
   if caplen!=origlen or caplen>16*1024*1024:raise ValueError('truncated/oversized partial PCAP packet')
   frame=f.read(caplen)
   if len(frame)!=caplen:raise ValueError('truncated partial PCAP frame')
   src,sp,dst,dp,_=isolation.packet(frame)
   if not (sp==443 or dp==443):continue
   if ipaddress.ip_address(src) in network:local,lp,remote,rp=src,sp,dst,dp
   elif ipaddress.ip_address(dst) in network:local,lp,remote,rp=dst,dp,src,sp
   else:raise ValueError('partial UDP/443 packet is outside the worker subnet')
   if rp!=443:raise ValueError('partial remote tuple is not UDP/443')
   found.add(json.dumps(['udp',local,lp,remote,rp],separators=(',',':')))
 return found
def pcap_tuple_keys(path,isolation,expected_sha256=None):
 import io
 found=set();network=ipaddress.ip_network(CONFIG['network']['subnet'])
 data=stable_read(path,expected_sha256)
 with io.BytesIO(data) as f:
  hdr=f.read(24)
  if len(hdr)!=24 or hdr[:4] not in isolation.MAGIC:raise ValueError('partial PCAP header unavailable')
  order=isolation.MAGIC[hdr[:4]]
  if struct.unpack(order+'I',hdr[20:24])[0]!=1:raise ValueError('partial PCAP link type unsupported')
  while True:
   ph=f.read(16)
   if not ph:break
   if len(ph)!=16:raise ValueError('truncated partial PCAP record')
   _,_,caplen,origlen=struct.unpack(order+'IIII',ph)
   if caplen!=origlen or caplen>16*1024*1024:raise ValueError('truncated/oversized partial PCAP packet')
   frame=f.read(caplen)
   if len(frame)!=caplen:raise ValueError('truncated partial PCAP frame')
   src,sp,dst,dp,_=isolation.packet(frame)
   if not (sp==443 or dp==443):continue
   if ipaddress.ip_address(src) in network:local,lp,remote,rp=src,sp,dst,dp
   elif ipaddress.ip_address(dst) in network:local,lp,remote,rp=dst,dp,src,sp
   else:raise ValueError('partial UDP/443 packet outside worker subnet')
   if rp!=443:raise ValueError('partial remote tuple not UDP/443')
   found.add(json.dumps(['udp',local,lp,remote,rp],separators=(',',':')))
 return found
def prior_partial_tuple_exclusions(isolation):
 excluded=set()
 for final_path in (ROOT/'attempts'/HOST).glob('*/FINAL.json'):
  record=json.loads(stable_read(final_path))
  if record.get('status')=='success':continue
  saved_native=record.get('native_tuple_keys') or [];saved_pcap=record.get('pcap_udp_tuple_keys') or []
  for vals in (saved_native,saved_pcap):
   if not isinstance(vals,list) or any(not isinstance(x,str) for x in vals) or len(vals)!=len(set(vals)):
    raise RuntimeError('prior partial has malformed tuple evidence')
  files=record.get('files') or {};run_path=final_path.parent/'native/run.json';pcap_path=final_path.parent/'capture.pcap'
  native=set();captured=set()
  if run_path.exists() or 'native/run.json' in files:
   entry=files.get('native/run.json')
   if not run_path.is_file() or not isinstance(entry,dict) or not isinstance(entry.get('sha256'),str):
    raise RuntimeError('prior partial native run missing/unpinned')
   prior_run=json.loads(stable_read(run_path,entry['sha256']))
   if prior_run.get('endpoints'):native.update(tuple_keys(prior_run))
  if pcap_path.exists() or 'capture.pcap' in files:
   entry=files.get('capture.pcap')
   if not pcap_path.is_file() or not isinstance(entry,dict) or not isinstance(entry.get('sha256'),str):
    raise RuntimeError('prior partial PCAP missing/unpinned')
   captured.update(pcap_tuple_keys(pcap_path,isolation,entry['sha256']))
  if saved_native and native and set(saved_native)!=native:raise RuntimeError('saved native tuples differ from run.json')
  if saved_native and not native and (not captured or not set(saved_native).issubset(captured)):
   raise RuntimeError('saved native tuples lack supporting native/PCAP evidence')
  if saved_pcap and captured and set(saved_pcap)!=captured:raise RuntimeError('saved PCAP tuples differ from raw PCAP')
  all_keys=native|captured|set(saved_native)|set(saved_pcap)
  if 'invocation.json' in files and not all_keys:
   # A valid header-only capture with zero tcpdump counts proves the preflight
   # client exited before any UDP/443 tuple existed; all other gaps fail closed.
   empty_capture=(pcap_path.is_file() and pcap_path.stat().st_size==24 and not captured)
   log_path=final_path.parent/'tcpdump.log';log_entry=files.get('tcpdump.log')
   if not empty_capture or not isinstance(log_entry,dict) or not isinstance(log_entry.get('sha256'),str) or not log_path.is_file():
    raise RuntimeError('prior partial invocation has no native/PCAP tuple evidence')
   tcpdump_text=stable_read(log_path,log_entry['sha256']).decode(errors='strict')
   if not all(re.search(r'(?m)^0 packets '+label+r'$',tcpdump_text) for label in ('captured','received by filter','dropped by kernel')):
    raise RuntimeError('empty PCAP lacks zero-count tcpdump evidence')
  excluded.update(all_keys)
 return excluded

def load_pinned_module(path,want):
 import types
 data=stable_read(path,want)
 value=types.ModuleType(path.stem);value.__file__=str(path);exec(compile(data,str(path),'exec'),value.__dict__);return value


def chmod_capture_with_retry(path):
 last=None
 for n in range(3):
  try:subprocess.run(['sudo','-n','chmod','644',str(path)],check=True,timeout=90);return
  except (subprocess.TimeoutExpired,subprocess.CalledProcessError) as e:last=e
  if n<2:time.sleep(2**n)
 raise RuntimeError('capture permission update failed after bounded retries') from last

VARIATION_SHA='0fc66bd59fe33e4c55c73fa3b4ba1c3a640ebd9ad26096cfc44f50e1f02b8b38'
RECEIVE_NOTE_SHA='340646d6fbd9fed08987104175d7b3e69a3e671791c009777c8a74b5daad97f1'
FAILURE_BUDGET_SHA='234adecbbf9f8191841138f5fe9961806ddf8dc4b5f949b6551feceab4d8f3c8'
SCHEDULING_CONTRACT_SHA='a930916f5dc582859f0feb9bcf1abb4f91c61fbf155f8b733e7149f7de5e6264'
PARTIALS=[]

def priority_wrapper(container,argv):
 client=str(STORAGE_CONFIG['client_cpu']);helper=str(STORAGE_CONFIG['orchestrator_cpu'])
 return ['docker','exec','--env','QCSD_CAPTURE_SCHEDULER_CONTRACT=qcsd-client-rr1-portable-etf-helper-v3',
         '--env','QCSD_CAPTURE_CLIENT_CPU='+client,'--env','QCSD_CAPTURE_ORCHESTRATOR_CPU='+helper,
         '--env','QCSD_CAPTURE_ETF_INTERFACE=eth0',container,'taskset','-c',client,'chrt','-r','1',
         'setpriv','--reuid=503','--regid=1000','--clear-groups',
         '--inh-caps=+net_admin,+setpcap','--ambient-caps=+net_admin,+setpcap',*argv]

def verify_transfer(expected_container=None):
 if MODE!='buflo':raise ValueError('mode scope mismatch')
 if sha(CONFIG_PATH)!=CONFIG_SHA or sha(HISTORY)!=CONFIG['history_sha256']:
  raise RuntimeError('scientific mode config/history changed')
 if sha(pathlib.Path(STORAGE_CONFIG['scientific_owner_path']))!=CONFIG['owner_sha256'] or sha(pathlib.Path(__file__))!=STORAGE_CONFIG['driver_sha256']:
  raise RuntimeError('science owner or tmpfs driver changed')
 if sha(STORAGE_CONFIG_PATH)!=STORAGE_CONFIG_SHA:
  raise RuntimeError('tmpfs runner config changed')
 if sha(pathlib.Path(STORAGE_CONFIG['scheduler_placement_path']))!=STORAGE_CONFIG['scheduler_placement_sha256']:
  raise RuntimeError('scheduler placement manifest changed')
 placement=json.loads(stable_read(pathlib.Path(STORAGE_CONFIG['scheduler_placement_path']),STORAGE_CONFIG['scheduler_placement_sha256']))
 if (placement.get('kind')!='qcsd-capture-scheduler-placement-variation' or placement.get('client_cpu')!=STORAGE_CONFIG.get('client_cpu') or
     placement.get('helper_cpu')!=STORAGE_CONFIG.get('orchestrator_cpu') or placement.get('cpuset')!=STORAGE_CONFIG.get('cpuset') or
     placement.get('observer_cpu')!=STORAGE_CONFIG.get('observer_cpu') or placement.get('science_config_sha256')!=CONFIG_SHA):
  raise ValueError('scheduler placement pin mismatch')
 if STORAGE_CONFIG.get('scientific_config_sha256')!=CONFIG_SHA or STORAGE_CONFIG.get('scientific_owner_sha256')!=CONFIG['owner_sha256']:
  raise RuntimeError('tmpfs runner is bound to another science config')
 if sha(pathlib.Path(STORAGE_CONFIG['storage_policy_path']))!=STORAGE_CONFIG['storage_policy_sha256'] or sha(pathlib.Path(STORAGE_CONFIG['failure_budget_path']))!=STORAGE_CONFIG['failure_budget_sha256']:
  raise RuntimeError('tmpfs storage policy or failure budget changed')
 if sha(NOTE)!=CONFIG['replacement_note_sha256'] or sha(INPUTS/'resources.json')!=RESOURCE_PIN:
  raise ValueError('v3 roster pin changed')
 if sha(pathlib.Path(CONFIG['coverage_receipt']))!=CONFIG['coverage_sha256']:
  raise ValueError('coverage manifest changed')
 if sha(pathlib.Path(CONFIG['network_manifest']))!=CONFIG['network_manifest_sha256']:
  raise ValueError('network manifest changed')
 if sha(pathlib.Path(CONFIG['network_module']))!=CONFIG['network_module_sha256']:
  raise ValueError('network policy changed')
 if sha(pathlib.Path(CONFIG['ledger_module']))!=CONFIG['ledger_module_sha256']:
  raise ValueError('shared ledger module changed')
 if any(sha(INPUTS/name)!=digest for name,digest in INPUT_SHA.items()):
  raise ValueError('mode-specific BufLO inputs changed')
 for name,key in [('dispatch-variation-v3.json','dispatch_variation_sha256'),
                  ('receive-window-variation-v3.json','receive_window_variation_sha256'),
                  ('scheduling-contract-v3.json','scheduling_contract_sha256')]:
  if sha(ROOT/name)!=CONFIG[key]:raise ValueError('BufLO mode note changed: '+name)
 note=json.loads(stable_read(NOTE,CONFIG['replacement_note_sha256']))
 if note.get('kind')!='mal-roster-v3-resource-replacement-note' or note.get('domain')!=HOST or note.get('drive_handoff_changed') is not False or [x.get('resource_id') for x in note.get('changes',[])]!=[18]:
  raise ValueError('v3 replacement note mismatch')
 dispatch=json.loads(stable_read(ROOT/'dispatch-variation-v3.json',CONFIG['dispatch_variation_sha256']))
 if (dispatch.get('kind')!='buflo-documented-dispatch-variation' or dispatch.get('cohort')!='cdn.myanimelist.net-roster-v3-001' or
     dispatch.get('domain')!=HOST or dispatch.get('application_workload_sha256')!=RESOURCE_PIN or
     dispatch.get('prepared_workload_sha256')!=INPUT_SHA['prepared-workload.json'] or dispatch.get('interval_us')!=64000 or
     dispatch.get('duration_budget_us')!=1280000000 or dispatch.get('request_policy')!='half-duplex' or
     dispatch.get('ack_startup_policy')!='qualified-chaff-terminal-ack-cadence-start-v1' or dispatch.get('capture_credit') is not False or
     dispatch.get('drive_upload') is not False):raise ValueError('dispatch variation mismatch')
 receive=json.loads(stable_read(ROOT/'receive-window-variation-v3.json',CONFIG['receive_window_variation_sha256']))
 if (receive.get('kind')!='buflo-receive-window-variation' or receive.get('cohort')!='cdn.myanimelist.net-roster-v3-001' or
     receive.get('domain')!=HOST or receive.get('application_workload_sha256')!=RESOURCE_PIN or
     receive.get('prepared_workload_sha256')!=INPUT_SHA['prepared-workload.json'] or receive.get('initial_max_stream_data')!=1 or
     receive.get('automatic_receive_window')!=1048576 or receive.get('max_chaff_streams')!=1 or receive.get('max_stream_data_excess')!=400 or
     receive.get('ack_startup_policy')!='qualified-chaff-terminal-ack-cadence-start-v1' or
     receive.get('diagnostic_result_sha256')!=CONFIG['buflo_canary_result_sha256'] or receive.get('diagnostic_credit') is not False):
  raise ValueError('receive-window variation mismatch')
 budget=json.loads(stable_read(pathlib.Path(STORAGE_CONFIG['failure_budget_path']),STORAGE_CONFIG['failure_budget_sha256']))
 if (budget.get('kind')!='buflo-failure-budget-scope' or budget.get('cohort')!='cdn.myanimelist.net-roster-v3-001' or
     budget.get('domain')!=HOST or budget.get('defense')!='buflo' or budget.get('limits_per_slot')!={'defense_realization_failures':12,'capture_failures':20} or
     budget.get('prior_attempts_preserved') is not True or budget.get('prior_attempt_count')!=14 or
     budget.get('storage_policy_sha256')!=STORAGE_CONFIG['storage_policy_sha256'] or
     budget.get('scope',{}).get('native_client_sha256')!=CLIENT_SHA or budget.get('scope',{}).get('input_sha256')!=INPUT_SHA or
     budget.get('scope',{}).get('dispatch_variation_sha256')!=CONFIG['dispatch_variation_sha256'] or
     budget.get('scope',{}).get('receive_window_variation_sha256')!=CONFIG['receive_window_variation_sha256'] or
     budget.get('scope',{}).get('capture_storage_policy_sha256')!=STORAGE_CONFIG['storage_policy_sha256']):
  raise ValueError('tmpfs failure budget scope mismatch')
 storage=json.loads(stable_read(pathlib.Path(STORAGE_CONFIG['storage_policy_path']),STORAGE_CONFIG['storage_policy_sha256']))
 if (storage.get('kind')!='buflo-tmpfs-capture-staging-policy' or storage.get('cohort')!='cdn.myanimelist.net-roster-v3-001' or
     storage.get('domain')!=HOST or storage.get('science_config_sha256')!=CONFIG_SHA or
     storage.get('minimum_tmpfs_free_bytes')!=2147483648 or storage.get('minimum_memavailable_bytes')!=3221225472 or
     storage.get('max_attempt_tmpfs_bytes')!=536870912 or storage.get('copy_integrity')!='sha256-size-fsync-readback-before-session-credit-v1' or
     storage.get('pcap_and_native_during_capture')!='host-tmpfs-v1' or
     storage.get('scheduler_placement_sha256')!=STORAGE_CONFIG['scheduler_placement_sha256']):
  raise ValueError('tmpfs staging policy mismatch')
 scheduling=json.loads(stable_read(ROOT/'scheduling-contract-v3.json',CONFIG['scheduling_contract_sha256']))
 if (scheduling.get('kind')!='buflo-capture-scheduling-contract' or scheduling.get('cohort')!='cdn.myanimelist.net-roster-v3-001' or
     scheduling.get('domain')!=HOST or scheduling.get('resource_sha256')!=RESOURCE_PIN or
     scheduling.get('qdisc_contract')!='buflo-eth0-prio-etf-pfifo-v1' or scheduling.get('capture_credit') is not False):
  raise ValueError('scheduling contract mismatch')
 coverage=json.loads(stable_read(pathlib.Path(CONFIG['coverage_receipt']),CONFIG['coverage_sha256']))
 if (coverage.get('kind')!='mal-roster-v3-session-coverage' or coverage.get('domain')!=HOST or coverage.get('cohort')!='cdn.myanimelist.net-roster-v3-001' or
     coverage.get('resource_sha256')!=RESOURCE_PIN or coverage.get('target_sessions_per_mode')!=400 or coverage.get('target_total')!=2400 or
     coverage.get('drive_handoff_changed') is not False):raise ValueError('v3 coverage manifest mismatch')
 history=json.loads(stable_read(HISTORY,CONFIG['history_sha256']))
 if history.get('kind')!='mal-roster-v3-prior-tuple-history' or history.get('domain')!=HOST or history.get('imported_as_v3_sessions') is not False:
  raise ValueError('v3 prior tuple history mismatch')
 network_manifest=json.loads(stable_read(pathlib.Path(CONFIG['network_manifest']),CONFIG['network_manifest_sha256']))
 network=(network_manifest.get('networks') or {}).get(MODE)
 if network!=CONFIG['network'] or network_manifest.get('domain')!=HOST:
  raise ValueError('BufLO network binding mismatch')
 network_policy=load_pinned_module(pathlib.Path(CONFIG['network_module']),CONFIG['network_module_sha256'])
 network_policy.inspect_network(MODE,CONFIG['network'],expected_container)
 network_policy.verify_history_disjoint(history,CONFIG['network']['subnet'])
 reserved=set(history.get('reserved_native_tuples') or [])
 for item in history.get('committed') or []:
  reserved.update(item.get('native_tuple_keys') or [])
 # Diagnostics stay no-credit; their observed connections are reserved globally.
 for evidence in CONFIG['diagnostic_tuple_evidence']:
  result=json.loads(stable_read(pathlib.Path(evidence['result_path']),evidence['result_sha256']))
  if (result.get('capture_credit') is True or result.get('accepted_session') is True or
      result.get('session_ledger_write') is True or result.get('production_slot') is not None):
   raise ValueError('diagnostic unexpectedly claims credit')
  if not (result.get('capture_credit') is False or 'no-credit' in str(result.get('purpose','')).lower() or result.get('kind','').startswith('no-credit-')):
   raise ValueError('diagnostic lacks explicit no-credit provenance')
  run=json.loads(stable_read(pathlib.Path(evidence['run_path']),evidence['run_sha256']))
  if not h3_valid(run,HOST):raise ValueError('diagnostic was not a native H3 run')
  reserved.update(tuple_keys(run))
 for key in reserved:
  value=json.loads(key)
  if not isinstance(value,list) or len(value)!=5 or value[0]!='udp' or json.dumps(value,separators=(',',':'))!=key:
   raise ValueError('noncanonical tuple exclusion')
 return {'entries':[],'reserved_native_tuples':sorted(reserved)}

RESOURCE_PIN='eefdae5a1e95620cb1f75a334ca3531ef64669b0f8e6bed7d6449f2b2ae28c22'

def initialize_ledger(history,cutover_sha):
 if sha(pathlib.Path(CONFIG['ledger_module']))!=CONFIG['ledger_module_sha256']:
  raise ValueError('shared ledger module changed')
 global LEDGER
 LEDGER=load_pinned_module(pathlib.Path(CONFIG['ledger_module']),CONFIG['ledger_module_sha256'])
 db=LEDGER.open_ledger(TUPLE_DB,mode=MODE,config_sha=CONFIG_SHA,coverage_sha=CONFIG['coverage_sha256'],
  history_sha=CONFIG['history_sha256'],resource_sha=RESOURCE_PIN,prepared_sha=INPUT_SHA['prepared-workload.json'],
  replacement_note_sha=CONFIG['replacement_note_sha256'])
 for slot,aid,digest in LEDGER.committed(db,MODE):
  p=ROOT/'attempts'/HOST/aid/'FINAL.json';r=json.loads(stable_read(p,digest))
  if r.get('slot')!=slot or r.get('status')!='success' or r.get('defense')!=MODE:
   raise RuntimeError('v3 ledger FINAL mismatch')
  actual=tuple_keys(json.loads(stable_read(p.parent/'native/run.json',r['files']['native/run.json']['sha256'])))
  recorded=[x[0] for x in db.execute('SELECT k FROM tuples WHERE mode=? AND attempt=? AND slot=? AND final_sha=? AND state=?',(MODE,aid,slot,digest,'committed'))]
  if set(actual)!=set(recorded):raise RuntimeError('v3 ledger tuple history mismatch')
 for p in (ROOT/'attempts'/HOST).glob('*'):
  if p.is_symlink() or not p.is_dir() or not (p/'FINAL.json').is_file():raise RuntimeError('unsealed BufLO attempt requires review')
  r=json.loads(stable_read(p/'FINAL.json'))
  if r.get('attempt_id')!=p.name or r.get('hostname')!=HOST:
   raise RuntimeError('attempt identity mismatch')
  if r.get('status')=='success' and db.execute('SELECT attempt FROM sessions WHERE mode=? AND slot=?',(MODE,r['slot'])).fetchone()!=(p.name,):
   raise RuntimeError('untracked BufLO success')
 return db

def store_final(directory,record):
 tmp=directory/'.FINAL.tmp';target=directory/'FINAL.json'
 if target.exists():raise FileExistsError(target)
 with tmp.open('x') as f:json.dump(record,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
 os.link(tmp,target);sync_dir(directory)
 tmp.unlink();sync_dir(directory)
 return sha(target)
def memavailable_bytes():
 for line in pathlib.Path('/proc/meminfo').read_text().splitlines():
  if line.startswith('MemAvailable:'):
   return int(line.split()[1])*1024
 raise RuntimeError('MemAvailable is unavailable')
def check_tmpfs_headroom():
 mount=pathlib.Path(STORAGE_CONFIG['tmpfs_mount'])
 if mount!=pathlib.Path('/dev/shm') or not mount.is_dir():raise RuntimeError('unexpected tmpfs mount path')
 mounted=False
 for line in pathlib.Path('/proc/mounts').read_text().splitlines():
  fields=line.split()
  if len(fields)>=3 and fields[1]==str(mount) and fields[2]=='tmpfs':mounted=True
 if not mounted:raise RuntimeError('capture stage is not backed by tmpfs')
 free=shutil.disk_usage(mount).free;available=memavailable_bytes()
 if free<STORAGE_CONFIG['minimum_tmpfs_free_bytes'] or available<STORAGE_CONFIG['minimum_memavailable_bytes']:
  raise RuntimeError('tmpfs free-space or MemAvailable floor failed')
 return {'tmpfs_free_bytes':free,'memavailable_bytes':available,'floor_tmpfs_bytes':STORAGE_CONFIG['minimum_tmpfs_free_bytes'],'floor_memavailable_bytes':STORAGE_CONFIG['minimum_memavailable_bytes']}
def tree_manifest(root):
 out={}
 for p in sorted(root.rglob('*')):
  if p.is_symlink() or (not p.is_file() and not p.is_dir()):raise ValueError('unsafe tmpfs staging entry')
  if p.is_file():out[str(p.relative_to(root))]={'sha256':sha(p),'size':p.stat().st_size}
 return out
def copy_checked_file(src,dst):
 before={'sha256':sha(src),'size':src.stat().st_size}
 if dst.exists():raise FileExistsError(dst)
 with src.open('rb') as inp,dst.open('xb') as out:
  shutil.copyfileobj(inp,out,1024*1024);out.flush();os.fsync(out.fileno())
 after={'sha256':sha(dst),'size':dst.stat().st_size}
 if before!=after:raise RuntimeError('durable copy mismatch for '+str(dst))
 return {'source':str(src),'destination':str(dst),'sha256':after['sha256'],'size':after['size']}
def copy_checked_tree(src,dst):
 source=tree_manifest(src)
 if dst.exists():raise FileExistsError(dst)
 shutil.copytree(src,dst)
 for p in dst.rglob('*'):
  if p.is_file():
   with p.open('rb') as f:os.fsync(f.fileno())
 for p in sorted([p for p in dst.rglob('*') if p.is_dir()],key=lambda x:len(x.parts),reverse=True):sync_dir(p)
 sync_dir(dst);sync_dir(dst.parent)
 copied=tree_manifest(dst)
 if source!=copied:raise RuntimeError('durable native tree differs from tmpfs source')
 return {'source':str(src),'destination':str(dst),'files':source}

def write_record(path,value):
 with path.open('x') as f:json.dump(value,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
 sync_dir(path.parent)
def reconcile_creation_journal():
 CREATE_JOURNAL.mkdir(exist_ok=True);sync_dir(ROOT)
 for entry in sorted(CREATE_JOURNAL.iterdir()):
  if not entry.is_dir() or entry.is_symlink():raise RuntimeError('invalid creation journal entry')
  if (entry/'RESOLVED.json').is_file():continue
  result=entry/'RESULT.json'
  if not result.is_file():raise RuntimeError('docker create remains unresolved; retain old-owner hold')
  data=json.loads(result.read_bytes());cid=data.get('container','')
  if data.get('returncode')!=0 or not re.fullmatch(r'[0-9a-f]{64}',cid):
   raise RuntimeError('ambiguous docker create result requires manual recovery')
  fence_container(cid)
  write_record(entry/'RESOLVED.json',{'container':cid,'reconciliation':'fenced after interrupted creation'})
def validate_qdisc_readback(text):
 observed=json.loads(text);before=observed.get('before');after=observed.get('after')
 if not isinstance(before,list) or not isinstance(after,list) or len(after)!=3:raise ValueError('qdisc readback shape mismatch')
 roots=[q for q in after if q.get('root') is True]
 etfs=[q for q in after if q.get('kind')=='etf' and q.get('parent')=='1:1']
 fifos=[q for q in after if q.get('kind')=='pfifo' and q.get('parent')=='1:2']
 if len(roots)!=1 or len(etfs)!=1 or len(fifos)!=1:raise ValueError('qdisc topology mismatch')
 root=roots[0];ropts=root.get('options') or {}
 if root.get('kind')!='prio' or root.get('handle')!='1:' or ropts.get('bands')!=2 or ropts.get('priomap')!=[1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1]:raise ValueError('qdisc root mapping mismatch')
 etf=etfs[0];eopts=etf.get('options') or {}
 if etf.get('handle')!='20:' or eopts.get('clockid')!='TAI' or eopts.get('delta')!=10000000 or eopts.get('deadline_mode')!='off' or eopts.get('skip_sock_check')!='off' or eopts.get('offload')!='off':raise ValueError('ETF configuration mismatch')
 fifo=fifos[0]
 if fifo.get('handle')!='10:' or (fifo.get('options') or {}).get('limit')!=1000:raise ValueError('pfifo configuration mismatch')
 return {'valid':True,'before':before,'after':after,'contract':'buflo-eth0-prio-etf-pfifo-v1'}
def prepare_worker(container,directory):
 qdisc_shell=("set -eu; before=$(tc -j -d qdisc show dev eth0); "
  "tc qdisc replace dev eth0 root handle 1: prio bands 2 priomap 1 1 1 1 1 1 0 1 1 1 1 1 1 1 1 1; "
  "tc qdisc replace dev eth0 parent 1:1 handle 20: etf clockid TAI delta 10000000; "
  "tc qdisc replace dev eth0 parent 1:2 handle 10: pfifo limit 1000; "
  "after=$(tc -j -d qdisc show dev eth0); printf '{\"before\":%s,\"after\":%s}\\n' \"$before\" \"$after\"")
 qdisc=subprocess.run(['docker','exec',container,'/bin/sh','-c',qdisc_shell],check=True,text=True,capture_output=True,timeout=60)
 qdisc_evidence=validate_qdisc_readback(qdisc.stdout.strip())
 write_record(directory/'qdisc-setup.json',qdisc_evidence)
 client=str(STORAGE_CONFIG['client_cpu']);helper=str(STORAGE_CONFIG['orchestrator_cpu']);cpuset=str(STORAGE_CONFIG['cpuset'])
 preflight=['docker','exec','--env','QCSD_CAPTURE_SCHEDULER_CONTRACT=qcsd-client-rr1-portable-etf-helper-v3',
  '--env','QCSD_CAPTURE_CLIENT_CPU='+client,'--env','QCSD_CAPTURE_ORCHESTRATOR_CPU='+helper,'--env','QCSD_CAPTURE_ETF_INTERFACE=eth0',
  container,'taskset','-c',client,'chrt','-r','1','setpriv','--reuid=503','--regid=1000','--clear-groups',
  '--inh-caps=+net_admin,+setpcap','--ambient-caps=+net_admin,+setpcap','/bin/sh','-c',
  "id; grep -E '^(Uid|Gid|CapEff|NoNewPrivs|Cpus_allowed_list):' /proc/self/status; cat /sys/fs/cgroup/cpuset.cpus.effective; grep 'Max realtime priority' /proc/self/limits; chrt -p $$; taskset -pc $$"]
 result=subprocess.run(preflight,text=True,capture_output=True,timeout=30)
 text_out=result.stdout+result.stderr
 valid=(result.returncode==0 and re.search(r'uid=503\b',text_out) and re.search(r'gid=1000\b',text_out) and
  re.search(r'CapEff:\s*0000000000001100',text_out) and re.search(r'NoNewPrivs:\s*1',text_out) and
  re.search(r'Cpus_allowed_list:\s*'+re.escape(client)+r'\s*$',text_out,re.MULTILINE) and
  re.search(r'^'+re.escape(cpuset)+r'\s*$',text_out,re.MULTILINE) and
  re.search(r'Max realtime priority\s+1\s+1',text_out) and 'SCHED_RR' in text_out and re.search(r'current scheduling priority:\s*1',text_out))
 write_record(directory/'scheduler-preflight.json',{'argv':preflight,'returncode':result.returncode,'valid':bool(valid),'stdout':result.stdout,'stderr':result.stderr,
  'client_cpu':int(client),'helper_cpu':int(helper),'cpuset':cpuset})
 if not valid:raise RuntimeError('RR/ETF credential or cpuset preflight failed; no client request issued')
def start_container(stage):
 args=['docker','run','-d','--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','SETPCAP','--cap-add','SETUID','--cap-add','SETGID',
  '--security-opt','no-new-privileges:true','--ulimit','rtprio=1:1','--cpuset-cpus',STORAGE_CONFIG['cpuset'],'--memory','3g','--group-add','1000',
  '--network',CONFIG['network']['id'],'--label','qcsd.owner='+LABEL,
  '--mount',f'type=bind,src={INPUTS},dst=/inputs,readonly','--mount',f'type=bind,src={stage},dst=/worker',
  '--mount',f'type=bind,src={CLIENT},dst=/usr/local/bin/neqo-qcsd-client,readonly',
  '--mount',f'type=bind,src={MODEL},dst=/model.json,readonly','--entrypoint','/bin/sleep',IMAGE,'infinity']
 entry=CREATE_JOURNAL/secrets.token_hex(16);entry.mkdir();sync_dir(ROOT)
 write_record(entry/'INTENT.json',{'args':args,'scope':'single labeled reuse worker with verified ETF/RR preparation'})
 recorder='''import json,os,pathlib,subprocess,sys
p=pathlib.Path(sys.argv[1]);args=json.loads(sys.argv[2]);r=subprocess.run(args,text=True,capture_output=True)
v={'returncode':r.returncode,'container':r.stdout.strip(),'stderr':r.stderr}
with (p/'RESULT.json').open('x') as f:json.dump(v,f,sort_keys=True);f.write('\\n');f.flush();os.fsync(f.fileno())
fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
'''
 proc=subprocess.Popen(['/usr/bin/python3','-c',recorder,str(entry),json.dumps(args)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
 try:proc.wait(timeout=900)
 except subprocess.TimeoutExpired:raise RuntimeError('docker create still unresolved; ownership remains reserved')
 result=entry/'RESULT.json'
 if proc.returncode!=0 or not result.is_file():raise RuntimeError('docker create result recorder failed; old-owner hold remains')
 data=json.loads(result.read_bytes());cid=data.get('container','')
 if data.get('returncode')!=0 or not re.fullmatch(r'[0-9a-f]{64}',cid):raise RuntimeError('ambiguous docker create result; old-owner hold remains')
 try:
  prepare_worker(cid,entry)
 except Exception as e:
  fence_container(cid)
  write_record(entry/'SETUP_FAILED.json',{'container':cid,'error':repr(e),'action':'container fenced; no client request issued'})
  write_record(entry/'RESOLVED.json',{'container':cid,'reconciliation':'fenced after failed preparation'})
  raise
 write_record(entry/'RESOLVED.json',{'container':cid,'reconciliation':'identified and prepared with verified ETF/RR settings'})
 return cid

def fence_container(container,settle_seconds=180):
 """Remove the exact worker and prove it absent before touching output."""
 try:command(['docker','rm','-f',container],timeout=30)
 except Exception:
  # A failed command is not proof of safety; a successful daemon listing is.
  pass
 deadline=time.monotonic()+settle_seconds;last_error=None
 while True:
  try:
   existing=command(['docker','ps','-aq','--no-trunc'],timeout=max(1,min(10,int(deadline-time.monotonic())))).splitlines()
   if container not in existing:return
   last_error=RuntimeError('worker container still exists; attempt remains unsealed')
  except Exception as e:last_error=e
  remaining=deadline-time.monotonic()
  if remaining<=0:raise last_error
  time.sleep(min(2,remaining))
def attempt(container,stage,db,slot,isolation,cutover_sha):
 baseline=verify_transfer(container)
 partial_exclusions=prior_partial_tuple_exclusions(isolation)
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('input identity changed during ownership')
 if any(shutil.disk_usage(path).free<minimum for path,minimum in CONFIG['storage_floors'].items()):raise RuntimeError('storage floor')
 aid=secrets.token_hex(16);directory=ROOT/'attempts'/HOST/aid;directory.mkdir(parents=True,exist_ok=False)
 stage_session=stage/aid;stage_session.mkdir(mode=0o700);os.chmod(stage_session,0o700);raw=directory/'capture.pcap';tmp_raw=stage_session/'capture.pcap';tmpfs_before=check_tmpfs_headroom()
 lock=(directory/'attempt.lock').open('x')
 try:
  observer=None;log=None;code=None;error=None;run={};tuple_result={'pass':False};counts={'captured':None,'received':None,'dropped':None}
  exec_begun=False;retire=False;container_fenced=False;network_policy=None;worker_ip=None;pid=None
  try:
   fcntl.flock(lock,fcntl.LOCK_EX)
   network_policy=load_pinned_module(pathlib.Path(CONFIG['network_module']),CONFIG['network_module_sha256'])
   worker_ip=network_policy.inspect_container(MODE,CONFIG['network'],container)
   # The worker qdisc and RR/ETF contract was configured and verified immediately at container start.
   pid=command(['docker','inspect','--format','{{.State.Pid}}',container])
   log=(directory/'tcpdump.log').open('xb')
   observer=subprocess.Popen(['sudo','nsenter','-t',pid,'-n','tcpdump','-p','-B','16384','-i','eth0','-s','0','-U','-w',str(tmp_raw),'udp port 443'],stdout=log,stderr=log,preexec_fn=cap_limit)
   for _ in range(100):
    if observer.poll() is not None:raise RuntimeError('tcpdump exited before client')
    if 'listening on eth0' in (directory/'tcpdump.log').read_text(errors='replace'):break
    time.sleep(.05)
   else:raise RuntimeError('tcpdump readiness timeout')
   seed=secrets.randbits(64)
   native_timeout=680 if MODE=='buflo' else 120
   argv=['/usr/local/bin/neqo-qcsd-client','run','--workload','/inputs/resources.json','--application-workload-source','/inputs/prepared-workload.json',
    '--chaff-manifest','/inputs/chaff-manifest.json','--config','/inputs/params/custom-receive.toml',
    '--request-policy','half-duplex','--seed',str(seed),'--output-dir',f'/worker/{aid}/native','--max-response-bytes','16777216','--timeout-seconds',str(native_timeout)]
   exec_argv=priority_wrapper(container,argv)
   with (directory/'invocation.json').open('x') as f:json.dump({'argv':argv,'exec_wrapper':exec_argv,'container':container,'seed':seed},f);f.write('\n');f.flush();os.fsync(f.fileno())
   with (directory/'client.log').open('xb') as f:
    exec_begun=True
    code=subprocess.run(exec_argv,stdout=f,stderr=subprocess.STDOUT,timeout=(740 if MODE=='buflo' else 180)).returncode
    exec_begun=False
    write_record(directory/'client-exit.json',{'process_exit_code':code,'source':'completed docker exec return code'})
    f.flush();os.fsync(f.fileno())
   time.sleep(2)
  except Exception as e:
   error=repr(e)
   if exec_begun:retire=True
  finally:
   if exec_begun:retire=True
   if retire:
    fence_container(container)
    container_fenced=True
   try:
    if observer and observer.poll() is None:
     subprocess.run(['sudo','kill','-INT',str(observer.pid)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
     observer.wait(timeout=15)
   except Exception as e:
    error=error or repr(e);retire=True
   if observer and observer.poll() is None:
    retire=True
    if not container_fenced:
     fence_container(container)
     container_fenced=True
    raise RuntimeError('observer remains alive after client exit/container fence; attempt remains unsealed')
   if log:
    log.flush();os.fsync(log.fileno());log.close()
   if tmp_raw.exists():chmod_capture_with_retry(tmp_raw)

  try:
   if not tmp_raw.is_file():raise ValueError('missing tmpfs raw capture')
   src=stage_session/'native';dst=directory/'native'
   if not src.is_dir():raise ValueError('missing tmpfs native output')
   raw_copy=copy_checked_file(tmp_raw,raw)
   chmod_capture_with_retry(raw)
   native_copy=copy_checked_tree(src,dst)
   with raw.open('rb') as f:os.fsync(f.fileno())
   sync_dir(directory)
   tmpfs_after=check_tmpfs_headroom()
   staged_bytes=sum(p.stat().st_size for p in stage_session.rglob('*') if p.is_file())
   if staged_bytes>STORAGE_CONFIG['max_attempt_tmpfs_bytes']:raise RuntimeError('tmpfs attempt exceeded configured byte ceiling')
   audit={'kind':'durable-tmpfs-capture-copy-audit','capture_credit':False,'before_credit_copy_only':True,'tmpfs_before':tmpfs_before,'tmpfs_after':tmpfs_after,'stage_bytes':staged_bytes,'max_attempt_bytes':STORAGE_CONFIG['max_attempt_tmpfs_bytes'],'pcap':raw_copy,'native':native_copy,'copy_integrity':'sha256-size-fsync-readback-before-session-credit-v1'}
   write_record(directory/'tmpfs-copy-audit.json',audit)
   shutil.rmtree(stage_session);sync_dir(stage)
   before=sha(raw);dest=raw
   run=json.loads((dst/'run.json').read_bytes())
   network_policy.validate_run(run,worker_ip)
   result=isolation.analyze(dest,run,dst/'packets.csv',output=directory/'capture-isolated.pcap',expected_sha256=before)
   sync_dir(directory)
   check=isolation.analyze(directory/'capture-isolated.pcap',run,dst/'packets.csv',expected_sha256=result['filtered_classic_sha256'])
   if result.get('native_direction_length_coverage')!='passed' or check.get('native_direction_length_coverage')!='passed' or check['foreign_packets_removed'] or check['original_packets']!=result['retained_packets']:raise ValueError('isolated pcap readback or native coverage mismatch')
   tuple_result={**result,'pass':True,'isolated_readback_sha256':check['source_sha256']}
   text=(directory/'tcpdump.log').read_text(errors='replace')
   for k,label in (('captured','captured'),('received','received by filter'),('dropped','dropped by kernel')):
    m=re.search(r'(?m)^(\d+) packets '+label+'$',text)
    if not m:raise ValueError('missing capture counter')
    counts[k]=int(m.group(1))
  except Exception as e:error=error or repr(e)
  if not retire and network_policy is not None and network_policy.inspect_container(MODE,CONFIG['network'],container)!=worker_ip:raise RuntimeError('worker network changed before finalization')
  if verify_transfer(container)!=baseline:raise RuntimeError('ownership or baseline changed before finalization')
  responses=run.get('responses') or [];passed=[x for x in responses if x.get('complete') is True and x.get('outcome')=='succeeded' and type(x.get('status')) is int and 200<=x['status']<300]
  roster=json.loads(stable_read(INPUTS/'resources.json',INPUT_SHA['resources.json'])).get('resources')
  roster_ok=(type(roster) is list and len(roster)==20 and all(type(x) is dict and type(x.get('id')) is int and type(x.get('url')) is str for x in roster) and {x['id'] for x in roster}==set(range(20)) and {(x.get('resource_id'),x.get('url')) for x in passed}=={(x['id'],x['url']) for x in roster})
  cfg=run.get('resolved_configuration') or {};diag=run.get('defense_diagnostics') or {}
  cap_ok=(tuple_result.get('pass') is True and counts['captured'] is not None and counts['captured']>0 and counts['captured']==counts['received']==tuple_result.get('original_packets') and counts['dropped']==0 and type(tuple_result.get('native_rows')) is int and 0<tuple_result['native_rows']<=counts['captured'])
  expected_cfg={'schema_version':2,'control_interval_us':5000,'initial_max_stream_data':1,'automatic_receive_window':1048576,'max_chaff_streams':1,'low_watermark':1000000,'use_empty_resources':False,'max_stream_data_excess':400,'max_udp_payload_size':1200,'drop_unsatisfied_events':False,'keep_alive_lead_time_us':100000,'tail_wait_us':0,'defense':{'kind':'buflo','parameters':'/inputs/params/buflo.json'}}
  clean=(cfg==expected_cfg and code==0 and not error and cap_ok and defended_run_clean(run,HOST,roster,INPUT_SHA['resources.json'],INPUT_SHA['prepared-workload.json'],INPUT_SHA['chaff-manifest.json'],MODE,INPUT_SHA['params/'+MODE+'.json']))
  keys=[];pcap_keys=[];collision=[]
  if isinstance(run,dict) and isinstance(run.get('endpoints'),list) and run.get('endpoints'):
   try:keys=tuple_keys(run)
   except Exception as e:error=error or 'native tuple extraction failed: '+repr(e);clean=False
  if raw.is_file() and raw.stat().st_size>24:
   try:pcap_keys=sorted(pcap_tuple_keys(raw,isolation,sha(raw)))
   except Exception as e:error=error or 'PCAP tuple extraction failed: '+repr(e);clean=False
  if clean and not EXPERIMENT_NO_CREDIT:
   try:LEDGER.reserve(db,mode=MODE,slot=slot,attempt=aid,keys=keys,excluded=set(baseline['reserved_native_tuples'])|partial_exclusions)
   except ValueError as e:collision=[{'reason':str(e)}];clean=False;error='duplicate slot or native connection tuple'
  files={}
  for p in sorted(directory.rglob('*')):
   if p.is_file() and p.name not in ('FINAL.json','attempt.lock','.FINAL.tmp'):files[str(p.relative_to(directory))]={'sha256':sha(p),'size':p.stat().st_size}
  previous=[]
  for p in (ROOT/'attempts'/HOST).glob('*/FINAL.json'):
   old_bytes=stable_read(p);old=json.loads(old_bytes)
   if old.get('slot')==slot and old.get('status')!='success':previous.append({'attempt_id':old['attempt_id'],'final_sha256':hashlib.sha256(old_bytes).hexdigest()})
  final={'schema_version':1,'hostname':HOST,'attempt_id':aid,'slot':slot,'purpose':'no-credit tmpfs staging experiment' if EXPERIMENT_NO_CREDIT else 'production','defense':MODE,
   'status':('diagnostic_pass' if clean else 'partial') if EXPERIMENT_NO_CREDIT else ('success' if clean else 'partial'),'capture_credit':bool(clean and not EXPERIMENT_NO_CREDIT),'successful_responses':len(passed),'required_responses':20,
   'process_exit_code':code,'tail_warning':run.get('error') or error,'native_client_sha256':CLIENT_SHA,'image_id':IMAGE,
   'input_sha256':INPUT_SHA,'driver_sha256':sha(pathlib.Path(__file__)),'owner_sha256':CONFIG['owner_sha256'],
   'coverage_sha256':CONFIG['coverage_sha256'],'history_sha256':CONFIG['history_sha256'],'note_sha256':CONFIG['note_sha256'],
   'ownership_sha256':CONFIG_SHA,'capture_storage_policy_sha256':STORAGE_CONFIG['storage_policy_sha256'],'tmpfs_copy_audit_sha256':sha(directory/'tmpfs-copy-audit.json') if (directory/'tmpfs-copy-audit.json').is_file() else None,'domain_schedule':'parallel-authorized-20261123','replacement_cohort':'cdn.myanimelist.net-roster-v3-001','dispatch_variation_sha256':VARIATION_SHA,'receive_window_variation_sha256':RECEIVE_NOTE_SHA,'failure_budget_scope_sha256':STORAGE_CONFIG['failure_budget_sha256'],'prior_partial_audit_sha256s':[x[2] for x in PARTIALS],'tuple_verifier_sha256':MODULE_SHA,'network_id':CONFIG['network']['id'],'network_subnet':CONFIG['network']['subnet'],'network_worker_ip':worker_ip,'network_manifest_sha256':CONFIG['network_manifest_sha256'],
   'capture_packets_reported':counts['captured'],'capture_filter_received':counts['received'],'capture_kernel_dropped':counts['dropped'],
   'pcap_packets':tuple_result.get('original_packets'),'native_packet_rows':tuple_result.get('native_rows'),'packet_count_screen_passed':cap_ok,
   'tuple_packet_screen':tuple_result,'clean_pcap':'capture-isolated.pcap' if tuple_result.get('pass') else None,
   'native_tuple_keys':keys,'pcap_udp_tuple_keys':pcap_keys,'tuple_collisions':collision,'prior_partial_tuple_exclusions':sorted(partial_exclusions),'prior_nonclean_attempts':previous,
   'source_role':'mal-roster-v3-buflo-20261124','mode_evidence':'native/run.json','files':files}
  if verify_transfer(container)!=baseline:raise RuntimeError('ownership changed before FINAL publication')
  finalsha=store_final(directory,final)
  if EXPERIMENT_NO_CREDIT and keys:
   LEDGER.exclude(db,mode=MODE,slot=slot,attempt=aid,keys=keys,final_sha=finalsha)
  elif clean:
   LEDGER.commit(db,mode=MODE,slot=slot,attempt=aid,final_sha=finalsha)
  elif keys:
   try:LEDGER.exclude(db,mode=MODE,slot=slot,attempt=aid,keys=keys,final_sha=finalsha)
   except ValueError:
    rows=[db.execute('SELECT 1 FROM tuples WHERE k=?',(key,)).fetchone() for key in keys]
    if not all(rows):raise
  print(json.dumps({'hostname':HOST,'slot':slot,'status':final['status'],'attempt_id':aid,'directory':str(directory)},sort_keys=True),flush=True)
  return final['status'],cap_ok,retire
 finally:
  lock.close()

def next_mode_slot(db,mode):
 existing={x[0] for x in db.execute('SELECT slot FROM sessions WHERE mode=?',(mode,))}
 return next((n for n in range(1,401) if n not in existing),401)

def advance_success(db,mode,slot):
 if db.execute("SELECT state FROM sessions WHERE mode=? AND slot=?",(mode,slot)).fetchone()!=('committed',):raise RuntimeError('success was not durably committed')
 return next_mode_slot(db,mode)

def main():
 global CONFIG_PATH,CONFIG_SHA,CONFIG,HISTORY,ROOT,HOST,INPUTS,CLIENT,MODEL,MODULE,IMAGE,MODEL_SHA,CLIENT_SHA,MODULE_SHA,AUDIT,AUDIT_SHA,INPUT_SHA,STOP_FREE,TUPLE_DB,CREATE_JOURNAL,LABEL,NOTE,LEDGER,MODE,STORAGE_CONFIG_PATH,STORAGE_CONFIG_SHA,STORAGE_CONFIG,EXPERIMENT_NO_CREDIT
 p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--config-sha',required=True);p.add_argument('--storage-config',required=True);p.add_argument('--storage-config-sha',required=True);p.add_argument('--once',action='store_true');p.add_argument('--preflight-only',action='store_true');p.add_argument('--scheduler-preflight-only',action='store_true');p.add_argument('--experiment-no-credit',action='store_true');args=p.parse_args()
 CONFIG_PATH=pathlib.Path(args.config);CONFIG_SHA=args.config_sha;CONFIG=json.loads(stable_read(CONFIG_PATH,CONFIG_SHA))
 STORAGE_CONFIG_PATH=pathlib.Path(args.storage_config);STORAGE_CONFIG_SHA=args.storage_config_sha;STORAGE_CONFIG=json.loads(stable_read(STORAGE_CONFIG_PATH,STORAGE_CONFIG_SHA));EXPERIMENT_NO_CREDIT=args.experiment_no_credit
 if EXPERIMENT_NO_CREDIT and not args.once:raise ValueError('no-credit tmpfs experiment must be bounded with --once')
 MODE=CONFIG['mode'];HOST=CONFIG['hostname'];ROOT=pathlib.Path(CONFIG['root']);INPUTS=pathlib.Path(CONFIG['inputs']);HISTORY=pathlib.Path(CONFIG['history']);NOTE=pathlib.Path(CONFIG['note'])
 CLIENT=pathlib.Path(CONFIG['client']);MODEL=pathlib.Path(CONFIG['model']);MODULE=pathlib.Path(CONFIG['tuple_module'])
 IMAGE=CONFIG['image'];MODEL_SHA=CONFIG['model_sha256'];CLIENT_SHA=CONFIG['client_sha256'];MODULE_SHA=CONFIG['tuple_module_sha256'];INPUT_SHA=CONFIG['input_sha256']
 STOP_FREE=30*1024**3;TUPLE_DB=ROOT.parent.parent/'shared-ledger-v3.sqlite3';CREATE_JOURNAL=ROOT/'creation-journal';LABEL='qcsd-mal-v3-'+MODE+'-'+HOST+'-cpu2-3'
 if not re.fullmatch(r'[a-z0-9.-]+',HOST):raise ValueError('unsafe hostname')
 domain_root=pathlib.Path('/mnt/recapture16k/five-defense-recapture-20261123-001')/(HOST+'-roster-v3-001')
 if HOST!='cdn.myanimelist.net' or MODE!='buflo' or ROOT!=domain_root/'modes'/MODE or INPUTS!=domain_root/'mode-inputs/buflo-singlechaff' or NOTE!=domain_root/'replacement-note.json':raise ValueError('defended mode scope mismatch')
 if CONFIG['exclusive_fence_locks']!=[]:raise ValueError('unexpected fence locks')
 if ROOT.resolve()!=ROOT or INPUTS.resolve()!=INPUTS:raise ValueError('symlink in replacement scope')
 if CONFIG['storage_floors'].get(str(ROOT),0)<8*1024**3:raise ValueError('missing minimum guest storage floor')
 ROOT.mkdir(parents=True,exist_ok=True);(ROOT/'attempts'/HOST).mkdir(parents=True,exist_ok=True)
 locks=[]
 for lockpath in [ROOT/'production-owner.lock',*[pathlib.Path(x) for x in CONFIG['exclusive_fence_locks']]]:
  f=lockpath.open('a+');fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(f)
 baseline=verify_transfer()
 if any(r.get('status')=='success' for r in baseline['entries']):raise RuntimeError('historical success requires separate import')
 if STORAGE_CONFIG.get('kind')!='buflo-tmpfs-runner-config' or STORAGE_CONFIG.get('storage_policy_sha256') is None:raise ValueError('tmpfs runner config mismatch')
 check_tmpfs_headroom()
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('capture input identity changed')
 if command(['docker','image','inspect',IMAGE,'--format','{{.Id}}'])!=IMAGE:raise ValueError('image identity changed')
 reconcile_creation_journal()
 if command(['docker','ps','-aq','--filter','label=qcsd.owner='+LABEL]):raise RuntimeError('existing host worker')
 isolation=load_pinned_module(MODULE,MODULE_SHA);db=initialize_ledger(baseline,CONFIG['history_sha256'])
 prior_partial_tuple_exclusions(isolation)
 if args.preflight_only:
  print(json.dumps({'preflight':'passed','mode':MODE,'config_sha256':CONFIG_SHA,'owner_sha256':CONFIG['owner_sha256'],'driver_sha256':STORAGE_CONFIG['driver_sha256'],'storage_policy_sha256':STORAGE_CONFIG['storage_policy_sha256'],'scheduler_placement_sha256':STORAGE_CONFIG['scheduler_placement_sha256'],'client_cpu':STORAGE_CONFIG['client_cpu'],'helper_cpu':STORAGE_CONFIG['orchestrator_cpu'],'observer_cpu':STORAGE_CONFIG['observer_cpu'],'cpuset':STORAGE_CONFIG['cpuset'],'committed':len(LEDGER.committed(db,MODE)),'network':CONFIG['network']['name'],'tmpfs_headroom':check_tmpfs_headroom()},sort_keys=True),flush=True)
  db.close()
  return
 if args.scheduler_preflight_only:
  stage_parent=pathlib.Path(STORAGE_CONFIG['tmpfs_stage_root']);stage_parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  if stage_parent.is_symlink() or any(stage_parent.iterdir()):raise RuntimeError('stale or unsafe scheduler-preflight tmpfs path')
  stage=stage_parent/('scheduler-preflight-'+secrets.token_hex(8));stage.mkdir(mode=0o700);os.chmod(stage,0o700);sync_dir(stage_parent)
  receipt=ROOT/'scheduler-preflight-cpu2-3-001';receipt.mkdir(mode=0o700,exist_ok=False);container=None
  try:
   container=start_container(stage);prepare_worker(container,receipt)
   write_record(receipt/'RESULT.json',{'kind':'scheduler-placement-preflight-result','capture_credit':False,'client_cpu':STORAGE_CONFIG['client_cpu'],'helper_cpu':STORAGE_CONFIG['orchestrator_cpu'],'observer_cpu':STORAGE_CONFIG['observer_cpu'],'cpuset':STORAGE_CONFIG['cpuset'],'qdisc_valid':json.loads((receipt/'qdisc-setup.json').read_bytes()).get('valid') is True,'scheduler_preflight_valid':json.loads((receipt/'scheduler-preflight.json').read_bytes()).get('valid') is True,'container_label':LABEL,'science_config_sha256':CONFIG_SHA,'scheduler_placement_sha256':STORAGE_CONFIG['scheduler_placement_sha256']})
  finally:
   if container:fence_container(container)
   if stage.exists() and stage.is_dir() and not any(stage.iterdir()):stage.rmdir();sync_dir(stage.parent)
  print(json.dumps({'scheduler_preflight':'passed','receipt':str(receipt/'RESULT.json'),'client_cpu':STORAGE_CONFIG['client_cpu'],'helper_cpu':STORAGE_CONFIG['orchestrator_cpu'],'observer_cpu':STORAGE_CONFIG['observer_cpu'],'cpuset':STORAGE_CONFIG['cpuset']},sort_keys=True),flush=True)
  db.close()
  return
 slot=next_mode_slot(db,MODE)
 prior=[json.loads(stable_read(x)) for x in (ROOT/'attempts'/HOST).glob('*/FINAL.json')]
 failures,capture_failures=failure_counts(prior,slot)
 stage_parent=pathlib.Path(STORAGE_CONFIG['tmpfs_stage_root']);stage_parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 if stage_parent.is_symlink() or any(stage_parent.iterdir()):raise RuntimeError('stale or unsafe tmpfs staging data requires reconciliation')
 stage=stage_parent/('worker-stage-'+secrets.token_hex(8));stage.mkdir(mode=0o700);os.chmod(stage,0o700);sync_dir(stage_parent)
 stopping=threading.Event();signal.signal(signal.SIGTERM,lambda *_:stopping.set());signal.signal(signal.SIGINT,lambda *_:stopping.set());container=None
 try:
  container=start_container(stage)
  while not stopping.is_set() and slot<=400 and failures<12 and capture_failures<20:
   status,screen,retired=attempt(container,stage,db,slot,isolation,CONFIG['history_sha256'])
   if retired:container=None
   if status=='success':slot=advance_success(db,MODE,slot);failures=0;capture_failures=0
   elif not screen:capture_failures+=1
   else:failures+=1
   if args.once or stopping.wait(2):break
   if container is None:container=start_container(stage)
 finally:
  if container:fence_container(container)
  if stage.exists() and stage.is_dir() and not any(stage.iterdir()):
   stage.rmdir();sync_dir(stage.parent)
  db.close()
 print(json.dumps({'hostname':HOST,'next_slot':slot,'failures':failures,'capture_failures':capture_failures}),flush=True)
if __name__=='__main__':main()
