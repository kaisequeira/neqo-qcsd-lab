#!/usr/bin/env python3
"""Isolated MAL roster-v3 BuFLO owner using bounded tmpfs capture staging, bounded to reviewed ACK-gated settings."""
import argparse,csv,fcntl,hashlib,importlib.util,ipaddress,json,os,pathlib,re,resource,secrets,shutil,signal,sqlite3,struct,subprocess,threading,time,sys
os.umask(0o077)

# Permanently disabled draft: require validated canary and reviewed handover.
VARIANT_RECEIPT_PATH=pathlib.Path("/mnt/recapture16k/diagnostics/buflo-outgoing-20ms-variant-001/integration-draft-001/generated-handover-v018/buflo-20ms-transition-v001.json")
VARIANT_RECEIPT_SHA="d74737fd47152ad31f381f6fb1c91fc8a9b2717cc7fac1666f65a175b3c6a499"
VARIANT_CHECKER_PATH=pathlib.Path("/mnt/recapture16k/diagnostics/buflo-outgoing-20ms-variant-001/verify_pcap_cells.py")
VARIANT_CHECKER_SHA="555f0d7afa5bd9d473e17d8c8e356748a3e86d5abcc59a5d0fa6febf98f51da9"
VARIANT_GATES_PATH=pathlib.Path("/mnt/recapture16k/diagnostics/buflo-outgoing-20ms-variant-001/offline_variant_canary_v002.py")
VARIANT_GATES_SHA="88abd9b7ab019775682f1220f83edc7866116d4cd78c78058aa2c6523e08dc0d"
ORIGINAL_CLIENT_SHA="3ebebcc6e2601ab07684abd9005db6d685114423d4b4366ed9a6a3ee25f08481"
BASELINE_ATTEMPTS=set()
# This lock protects the mode-wide pending interval from other worker opens.
FINALIZATION_LOCK=threading.RLock()
# Bound simultaneous durable copy/fsync/readback batches; capture remains parallel.
DURABLE_COPY_SEMAPHORE=threading.BoundedSemaphore(1)
DURABLE_COPY_WAIT_SECONDS=60
class DurableCopyWaitTimeout(RuntimeError):pass
class DurableCopyPermit:
 def __enter__(self):
  if not DURABLE_COPY_SEMAPHORE.acquire(timeout=DURABLE_COPY_WAIT_SECONDS):raise DurableCopyWaitTimeout("durable copy permit timed out; preserve unsealed stage")
 def __exit__(self,*args):DURABLE_COPY_SEMAPHORE.release()

ASYNC_EXECUTION_ENABLED=True
ASYNC_OWNER_VERSION="v4-022-async-refill-001"
ASYNC_DRIVER_SHA256="17d39085909a7e86f4821bd4931d62081ed8d9892bb17281c920a6eda30dece2"
def require_clean_mode_before_finalization(db):
 # Called while FINALIZATION_LOCK is held. An older interrupted reservation
 # is never interpreted as a harmless parallel pending session.
 if db.execute("SELECT 1 FROM sessions WHERE mode=? AND state!='committed' LIMIT 1",(MODE,)).fetchone():
  raise RuntimeError('pending session requires reconciliation before finalization')

def accounted_tuple_keys(db,keys):
 # A prior committed tuple remains committed; it is already unavailable for
 # another session. Excluded tuples also count only with a durable FINAL hash.
 accounted=set()
 for key in sorted(set(keys)):
  row=db.execute('SELECT mode,attempt,slot,final_sha,state FROM tuples WHERE k=?',(key,)).fetchone()
  if row is None:continue
  mode,attempt,slot,final_sha,state=row
  if not isinstance(final_sha,str) or not re.fullmatch(r'[0-9a-f]{64}',final_sha):
   raise RuntimeError('tuple lacks durable FINAL evidence')
  if state=='committed':
   session=db.execute('SELECT attempt,final_sha,state FROM sessions WHERE mode=? AND slot=?',(mode,slot)).fetchone()
   if session!=(attempt,final_sha,'committed'):raise RuntimeError('committed tuple lacks matching committed session')
  elif state!='excluded':raise RuntimeError('tuple is pending or has unknown state')
  accounted.add(key)
 return accounted

def exclude_unseen_partial_tuples(db,mode,slot,attempt,keys,final_sha):
 # One SQLite transaction accounts for both native and raw-PCAP tuple keys.
 # Previously committed/excluded rows are never overwritten or downgraded.
 mode=LEDGER._mode(mode);final_sha=LEDGER._sha(final_sha,'partial FINAL')
 if type(slot) is not int or slot not in LEDGER.SLOTS or not isinstance(attempt,str) or not LEDGER.ATTEMPT.fullmatch(attempt):
  raise ValueError('invalid exclusion identity')
 normalized=LEDGER._keys(sorted(set(keys)))
 db.execute('BEGIN IMMEDIATE')
 try:
  if db.execute('SELECT 1 FROM sessions WHERE mode=? AND slot=?',(mode,slot)).fetchone():raise ValueError('cannot exclude tuples for an occupied v3 slot')
  if db.execute('SELECT 1 FROM sessions WHERE attempt=?',(attempt,)).fetchone():raise ValueError('attempt already has a session row')
  accounted=accounted_tuple_keys(db,normalized)
  missing=[key for key in normalized if key not in accounted]
  if missing:db.executemany('INSERT INTO tuples VALUES(?,?,?,?,?,?)',[(key,mode,attempt,slot,final_sha,'excluded') for key in missing])
  db.commit()
 except BaseException:
  if db.in_transaction:db.rollback()
  raise
 return set(normalized)

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

FAILURE_BUDGET = {}

def failure_tallies(prior,eligible_slots=None):
 excluded=set(FAILURE_BUDGET.get('retry_budget_epoch',{}).get('excluded_prior_attempts',{}))
 tallies={}
 for r in prior:
  if r.get('purpose')!='production':
   if r.get('capture_credit') is True:raise RuntimeError('diagnostic FINAL claims credit')
   continue
  if (r.get('hostname')!=HOST or r.get('defense')!='buflo' or
      r.get('native_client_sha256') not in (ORIGINAL_CLIENT_SHA,CLIENT_SHA) or r.get('input_sha256')!=INPUT_SHA or
      r.get('dispatch_variation_sha256')!=VARIATION_SHA or r.get('receive_window_variation_sha256')!=RECEIVE_NOTE_SHA):
   raise RuntimeError('unknown scientific scope or binary in production FINAL')
  if r.get('native_client_sha256')==CLIENT_SHA and r.get('timing_variant_receipt_sha256')!=VARIANT_RECEIPT_SHA:
   raise RuntimeError('variant FINAL lacks matching transition receipt')
  if r.get('attempt_id') in excluded or r.get('attempt_id') in BASELINE_ATTEMPTS:
   continue
  slot=r.get('slot')
  if type(slot) is not int or not 1<=slot<=400:
   raise RuntimeError('budget input has an invalid slot')
  if eligible_slots is not None and slot not in eligible_slots:
   continue
  if r.get('status')=='success':
   continue
  if r.get('status')!='partial' or r.get('capture_credit') is not False:
   raise RuntimeError('budget input has an unexpected non-success production FINAL')
  screen=r.get('packet_count_screen_passed')
  if type(screen) is not bool:
   raise RuntimeError('budget input has no boolean packet screen')
  counts=tallies.setdefault(slot,[0,0])
  counts[0 if screen else 1]+=1
 return {slot:tuple(counts) for slot,counts in tallies.items()}

def failure_counts(prior,slot):
 return failure_tallies(prior,{slot}).get(slot,(0,0))

def current_deferred_slots(prior,initial,ledger_db):
 committed={r[0] for r in LEDGER.committed(ledger_db,MODE)}
 initial_set=set(initial)
 if initial_set & committed:raise RuntimeError('initial deferred policy intersects committed slots')
 eligible=set(range(1,401))-committed
 limits=FAILURE_BUDGET['limits_per_slot']
 tally=failure_tallies(prior,eligible)
 return initial_set|{slot for slot,(defense,capture) in tally.items()
   if defense>=limits['defense_realization_failures'] or capture>=limits['capture_failures']}

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
FAILURE_BUDGET_SHA='34c908f5e4b2965195afeacccde896bad3acafa24b782fc0b50381aba9a3fe1e'
SCHEDULING_CONTRACT_SHA='a930916f5dc582859f0feb9bcf1abb4f91c61fbf155f8b733e7149f7de5e6264'
PARTIALS=[]
PAIR_CONFIG={}
PAIR_CONFIG_PATH=None
PAIR_CONFIG_SHA=None
ACTIVE_CONTAINERS=set()
CONTAINER_LANES={}
ACTIVE_LOCK=threading.RLock()
PAIR_LEASE_DB_PATH=None
CONTAINER_JOURNAL_PATHS={}

def priority_wrapper(container,argv):
 lane=CONTAINER_LANES[container];client=str(lane['client_cpu']);helper=str(lane['helper_cpu'])
 return ['docker','exec','--env','QCSD_CAPTURE_SCHEDULER_CONTRACT=qcsd-client-rr1-portable-etf-helper-v4',
         '--env','QCSD_CAPTURE_CLIENT_CPU='+client,'--env','QCSD_CAPTURE_ORCHESTRATOR_CPU='+helper,
         '--env','QCSD_CAPTURE_ETF_INTERFACE=eth0',container,'taskset','-c',client,'chrt','-r','1',
         'setpriv','--reuid=503','--regid=1000','--clear-groups',
         '--inh-caps=+net_admin,+setpcap','--ambient-caps=+net_admin,+setpcap',*argv]

def verify_transfer(expected_container=None):
 global FAILURE_BUDGET
 if MODE!='buflo':raise ValueError('mode scope mismatch')
 if sha(VARIANT_RECEIPT_PATH)!=VARIANT_RECEIPT_SHA or sha(VARIANT_CHECKER_PATH)!=VARIANT_CHECKER_SHA or sha(VARIANT_GATES_PATH)!=VARIANT_GATES_SHA:
  raise RuntimeError('variant transition, checker or schedule gate changed')
 pinned_variant=json.loads(stable_read(VARIANT_RECEIPT_PATH,VARIANT_RECEIPT_SHA))
 if sha(pathlib.Path(pinned_variant['baseline_path']))!=pinned_variant['baseline_sha256']:
  raise RuntimeError('mixed baseline changed')
 if sha(CONFIG_PATH)!=CONFIG_SHA or sha(HISTORY)!=CONFIG['history_sha256']:
  raise RuntimeError('scientific mode config/history changed')
 if PAIR_CONFIG_PATH is None or sha(PAIR_CONFIG_PATH)!=PAIR_CONFIG_SHA:
  raise RuntimeError('pair owner manifest changed')
 if sha(pathlib.Path(STORAGE_CONFIG['pair_network_policy_path']))!=STORAGE_CONFIG['pair_network_policy_sha256']:
  raise RuntimeError('pair network policy changed')
 if PAIR_CONFIG.get('resource_sha256')!=RESOURCE_PIN or PAIR_CONFIG.get('prepared_workload_sha256')!=INPUT_SHA.get('prepared-workload.json') or PAIR_CONFIG.get('native_client_sha256')!=CLIENT_SHA:
  raise RuntimeError('pair manifest science/client pins changed')
 if sha(pathlib.Path(STORAGE_CONFIG['scientific_owner_path']))!=CONFIG['owner_sha256'] or sha(pathlib.Path(__file__))!=STORAGE_CONFIG['driver_sha256']:
  raise RuntimeError('science owner or tmpfs driver changed')
 if sha(STORAGE_CONFIG_PATH)!=STORAGE_CONFIG_SHA:
  raise RuntimeError('tmpfs runner config changed')
 if sha(pathlib.Path(STORAGE_CONFIG['lane_placement_path']))!=STORAGE_CONFIG['lane_placement_sha256']:
  raise RuntimeError('async lane placement manifest changed')
 placement=json.loads(stable_read(pathlib.Path(STORAGE_CONFIG['lane_placement_path']),STORAGE_CONFIG['lane_placement_sha256']))
 if (placement.get('kind')!='mal-buflo-v4-async-lane-placement' or placement.get('schema_version')!=1 or placement.get('candidate_version')!=ASYNC_OWNER_VERSION or
     placement.get('execution_enabled') is not ASYNC_EXECUTION_ENABLED or placement.get('capture_credit') is not False or
     placement.get('observer_cpu')!=STORAGE_CONFIG.get('observer_cpu') or
     placement.get('lanes')!=STORAGE_CONFIG.get('pair_lanes') or
     placement.get('science_config_sha256')!=CONFIG_SHA or placement.get('network_id')!=CONFIG['network']['id'] or
     placement.get('network_subnet')!=CONFIG['network']['subnet']):
  raise ValueError('async lane placement pin mismatch')
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
 FAILURE_BUDGET=budget
 epoch=budget.get('retry_budget_epoch')
 if (not isinstance(epoch,dict) or epoch.get('kind')!='buflo-retry-budget-epoch-reset' or
     epoch.get('evidence_attempt_id')!='1b24a92bb371d97fb2d13fc5cfa6c4fd' or
     epoch.get('evidence_capture_credit') is not True or epoch.get('reset_slots')!=[99,100,101] or
     not isinstance(epoch.get('excluded_prior_attempts'),dict) or len(epoch['excluded_prior_attempts'])!=36):
  raise ValueError('retry budget epoch pin mismatch')
 evidence_raw=stable_read(pathlib.Path(epoch['evidence_final_path']),epoch['evidence_final_sha256'])
 evidence=json.loads(evidence_raw)
 if evidence.get('attempt_id')!=epoch['evidence_attempt_id'] or evidence.get('status')!='success' or evidence.get('capture_credit') is not True:
  raise ValueError('retry budget epoch evidence is not a credited success')
 for aid,digest in epoch['excluded_prior_attempts'].items():
  raw=stable_read(ROOT/'attempts'/HOST/aid/'FINAL.json',digest)
  rec=json.loads(raw)
  if (rec.get('attempt_id')!=aid or rec.get('slot') not in epoch['reset_slots'] or
      rec.get('status')!='partial' or rec.get('capture_credit') is not False):
   raise ValueError('retry budget exclusion is not the pinned partial')
 if (budget.get('kind')!='buflo-failure-budget-scope' or budget.get('cohort')!='cdn.myanimelist.net-roster-v3-001' or
     budget.get('domain')!=HOST or budget.get('defense')!='buflo' or budget.get('limits_per_slot')!={'defense_realization_failures':12,'capture_failures':20} or
     budget.get('prior_attempts_preserved') is not True or budget.get('prior_attempt_count')!=PAIR_CONFIG.get('prior_attempt_count') or
     budget.get('storage_policy_sha256')!=STORAGE_CONFIG['storage_policy_sha256'] or
     budget.get('scope',{}).get('native_client_sha256')!=ORIGINAL_CLIENT_SHA or budget.get('scope',{}).get('input_sha256')!=INPUT_SHA or
     budget.get('scope',{}).get('dispatch_variation_sha256')!=CONFIG['dispatch_variation_sha256'] or
     budget.get('scope',{}).get('receive_window_variation_sha256')!=CONFIG['receive_window_variation_sha256'] or
     budget.get('scope',{}).get('capture_storage_policy_sha256')!=STORAGE_CONFIG['storage_policy_sha256']):
  raise ValueError('tmpfs failure budget scope mismatch')
 storage=json.loads(stable_read(pathlib.Path(STORAGE_CONFIG['storage_policy_path']),STORAGE_CONFIG['storage_policy_sha256']))
 if (storage.get('kind')!='buflo-async-tmpfs-capture-staging-policy-v022' or storage.get('cohort')!='cdn.myanimelist.net-roster-v3-001' or
     storage.get('domain')!=HOST or storage.get('science_config_sha256')!=CONFIG_SHA or
     storage.get('minimum_tmpfs_free_bytes')!=STORAGE_CONFIG['minimum_tmpfs_free_bytes'] or storage.get('minimum_memavailable_bytes')!=STORAGE_CONFIG['minimum_memavailable_bytes'] or
     storage.get('max_attempt_tmpfs_bytes')!=STORAGE_CONFIG['max_attempt_tmpfs_bytes'] or storage.get('copy_integrity')!='sha256-size-fsync-readback-before-session-credit-v1' or
     storage.get('pcap_and_native_during_capture')!='host-tmpfs-v1' or
     storage.get('lane_placement_sha256')!=STORAGE_CONFIG['lane_placement_sha256']):
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
 with ACTIVE_LOCK:network_policy.inspect_network(MODE,CONFIG['network'],ACTIVE_CONTAINERS if ACTIVE_CONTAINERS else expected_container)
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
 if etf.get('handle')!='20:' or eopts.get('clockid')!='TAI' or eopts.get('delta')!=25000000 or eopts.get('deadline_mode')!='off' or eopts.get('skip_sock_check')!='off' or eopts.get('offload')!='off':raise ValueError('ETF configuration mismatch')
 fifo=fifos[0]
 if fifo.get('handle')!='10:' or (fifo.get('options') or {}).get('limit')!=1000:raise ValueError('pfifo configuration mismatch')
 return {'valid':True,'before':before,'after':after,'contract':'buflo-eth0-prio-etf-pfifo-v1'}
def prepare_worker(container,directory,lane):
 qdisc_shell=("set -eu; before=$(tc -j -d qdisc show dev eth0); "
  "tc qdisc replace dev eth0 root handle 1: prio bands 2 priomap 1 1 1 1 1 1 0 1 1 1 1 1 1 1 1 1; "
  "tc qdisc replace dev eth0 parent 1:1 handle 20: etf clockid TAI delta 25000000; "
  "tc qdisc replace dev eth0 parent 1:2 handle 10: pfifo limit 1000; "
  "after=$(tc -j -d qdisc show dev eth0); printf '{\"before\":%s,\"after\":%s}\\n' \"$before\" \"$after\"")
 qdisc=subprocess.run(['docker','exec',container,'/bin/sh','-c',qdisc_shell],check=True,text=True,capture_output=True,timeout=60)
 qdisc_evidence=validate_qdisc_readback(qdisc.stdout.strip())
 write_record(directory/'qdisc-setup.json',qdisc_evidence)
 client=str(lane['client_cpu']);helper=str(lane['helper_cpu']);cpuset=str(lane['cpuset'])
 preflight=['docker','exec','--env','QCSD_CAPTURE_SCHEDULER_CONTRACT=qcsd-client-rr1-portable-etf-helper-v4',
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
def start_container(stage,lane):
 args=['docker','run','-d','--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','SETPCAP','--cap-add','SETUID','--cap-add','SETGID',
  '--security-opt','no-new-privileges:true','--ulimit','rtprio=1:1','--cpuset-cpus',lane['cpuset'],'--memory',STORAGE_CONFIG['per_container_memory_limit'],'--memory-swap',STORAGE_CONFIG['per_container_memory_limit'],'--group-add','1000',
  '--network',CONFIG['network']['id'],'--ip',lane['static_ip'],'--label','qcsd.owner='+LABEL,'--label','qcsd.lane='+lane['name'],
  '--mount',f'type=bind,src={INPUTS},dst=/inputs,readonly','--mount',f'type=bind,src={stage},dst=/worker',
  '--mount',f'type=bind,src={CLIENT},dst=/usr/local/bin/neqo-qcsd-client,readonly',
  '--mount',f'type=bind,src={MODEL},dst=/model.json,readonly','--entrypoint','/bin/sleep',IMAGE,'infinity']
 entry=CREATE_JOURNAL/secrets.token_hex(16);entry.mkdir();sync_dir(ROOT)
 write_record(entry/'INTENT.json',{'args':args,'scope':'sparse-v4 three-worker MAL BuFLO cohort with shared helper CPU5 and verified ETF/RR preparation','lane':lane})
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
  with ACTIVE_LOCK:ACTIVE_CONTAINERS.add(cid);CONTAINER_LANES[cid]=lane;CONTAINER_JOURNAL_PATHS[cid]=entry
  prepare_worker(cid,entry,lane)
 except Exception as e:
  fence_pair_container(cid)
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
def fence_pair_container(container):
 with ACTIVE_LOCK:
  fence_container(container)
  ACTIVE_CONTAINERS.discard(container)
  CONTAINER_LANES.pop(container,None)
def attempt(container,stage,db,slot,isolation,cutover_sha,attempt_id=None):
 baseline=verify_transfer(container)
 partial_exclusions=prior_partial_tuple_exclusions(isolation)
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('input identity changed during ownership')
 if any(shutil.disk_usage(path).free<minimum for path,minimum in CONFIG['storage_floors'].items()):raise RuntimeError('storage floor')
 aid=attempt_id or secrets.token_hex(16);directory=ROOT/'attempts'/HOST/aid;directory.mkdir(parents=True,exist_ok=False)
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
    fence_pair_container(container)
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
   with DurableCopyPermit():
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
  except DurableCopyWaitTimeout:raise
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
  variant_screen={'pass':False,'reason':'base gates did not pass'}
  if clean:
   try:
    checker=load_pinned_module(VARIANT_CHECKER_PATH,VARIANT_CHECKER_SHA)
    gates=load_pinned_module(VARIANT_GATES_PATH,VARIANT_GATES_SHA)
    with (directory/'native/schedule.csv').open(newline='') as sf:schedule=list(csv.DictReader(sf))
    cells_ok,schedule_ok=gates.evidence_cell_schedule_gates(diag,run,schedule)
    variant_screen=checker.analyze(run,directory/'capture-isolated.pcap')
    variant_screen['schedule_cells_valid']=cells_ok and schedule_ok
    if variant_screen.get('pass') is not True or not cells_ok or not schedule_ok:raise ValueError('variant packet or schedule screen did not pass')
   except Exception as e:
    variant_screen={'pass':False,'error':repr(e)};error=error or 'variant packet screen failed: '+repr(e);clean=False
  write_record(directory/'timing-variant-cell-screen.json',variant_screen)
  keys=[];pcap_keys=[];collision=[]
  if isinstance(run,dict) and isinstance(run.get('endpoints'),list) and run.get('endpoints'):
   try:keys=tuple_keys(run)
   except Exception as e:error=error or 'native tuple extraction failed: '+repr(e);clean=False
  if raw.is_file() and raw.stat().st_size>24:
   try:pcap_keys=sorted(pcap_tuple_keys(raw,isolation,sha(raw)))
   except Exception as e:error=error or 'PCAP tuple extraction failed: '+repr(e);clean=False
  # Pin the full pending interval, including durable FINAL and credit/exclusion.
  with FINALIZATION_LOCK:
   require_clean_mode_before_finalization(db)
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
    'timing_variant_receipt_sha256':VARIANT_RECEIPT_SHA,'timing_variant':'buflo-outgoing-20ms-prospective-v1',
    'process_exit_code':code,'tail_warning':run.get('error') or error,'native_client_sha256':CLIENT_SHA,'image_id':IMAGE,
    'input_sha256':INPUT_SHA,'driver_sha256':sha(pathlib.Path(__file__)),'owner_sha256':CONFIG['owner_sha256'],
    'coverage_sha256':CONFIG['coverage_sha256'],'history_sha256':CONFIG['history_sha256'],'note_sha256':CONFIG['note_sha256'],
    'ownership_sha256':CONFIG_SHA,'capture_storage_policy_sha256':STORAGE_CONFIG['storage_policy_sha256'],'tmpfs_copy_audit_sha256':sha(directory/'tmpfs-copy-audit.json') if (directory/'tmpfs-copy-audit.json').is_file() else None,'domain_schedule':'parallel-authorized-20261123','replacement_cohort':'cdn.myanimelist.net-roster-v3-001','dispatch_variation_sha256':VARIATION_SHA,'receive_window_variation_sha256':RECEIVE_NOTE_SHA,'failure_budget_scope_sha256':STORAGE_CONFIG['failure_budget_sha256'],'prior_partial_audit_sha256s':[x[2] for x in PARTIALS],'tuple_verifier_sha256':MODULE_SHA,'network_id':CONFIG['network']['id'],'network_subnet':CONFIG['network']['subnet'],'network_worker_ip':worker_ip,'network_manifest_sha256':CONFIG['network_manifest_sha256'],'pair_network_policy_sha256':STORAGE_CONFIG['pair_network_policy_sha256'],'pair_config_sha256':PAIR_CONFIG_SHA,'scheduler_contract':'qcsd-client-rr1-portable-etf-helper-v4','scheduler_lane':CONTAINER_LANES.get(container),'per_container_memory_limit':STORAGE_CONFIG['per_container_memory_limit'],
    'capture_packets_reported':counts['captured'],'capture_filter_received':counts['received'],'capture_kernel_dropped':counts['dropped'],
    'pcap_packets':tuple_result.get('original_packets'),'native_packet_rows':tuple_result.get('native_rows'),'packet_count_screen_passed':cap_ok,
    'tuple_packet_screen':tuple_result,'clean_pcap':'capture-isolated.pcap' if tuple_result.get('pass') else None,
    'native_tuple_keys':keys,'pcap_udp_tuple_keys':pcap_keys,'tuple_collisions':collision,'prior_partial_tuple_exclusions':sorted(partial_exclusions),'prior_nonclean_attempts':previous,
    'source_role':'mal-roster-v3-buflo-20261124','mode_evidence':'native/run.json','files':files}
   if verify_transfer(container)!=baseline:raise RuntimeError('ownership changed before FINAL publication')
   finalsha=store_final(directory,final)
   if EXPERIMENT_NO_CREDIT:
    observed=set(keys)|set(pcap_keys)
    if observed:exclude_unseen_partial_tuples(db,MODE,slot,aid,observed,finalsha)
   elif clean:
    LEDGER.commit(db,mode=MODE,slot=slot,attempt=aid,final_sha=finalsha)
   else:
    observed=set(keys)|set(pcap_keys)
    if observed:exclude_unseen_partial_tuples(db,MODE,slot,aid,observed,finalsha)
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

def open_pair_lease_db():
 global PAIR_LEASE_DB_PATH
 PAIR_LEASE_DB_PATH=pathlib.Path(STORAGE_CONFIG['pair_lease_db_path'])
 if PAIR_LEASE_DB_PATH.is_symlink():raise ValueError('unsafe pair lease database')
 PAIR_LEASE_DB_PATH.parent.mkdir(parents=True,exist_ok=True)
 d=sqlite3.connect(PAIR_LEASE_DB_PATH,timeout=30,isolation_level=None)
 d.execute('PRAGMA synchronous=FULL');d.execute('PRAGMA busy_timeout=30000')
 os.chmod(PAIR_LEASE_DB_PATH,0o600)
 d.execute('CREATE TABLE IF NOT EXISTS pair_meta(k TEXT PRIMARY KEY,v TEXT NOT NULL)')
 d.execute("CREATE TABLE IF NOT EXISTS pair_leases(lane TEXT NOT NULL,slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 400),attempt TEXT UNIQUE NOT NULL,state TEXT NOT NULL CHECK(state IN ('reserved','running','success','partial','cancelled','unsealed')),container_id TEXT,final_sha TEXT,updated_unix_ns INTEGER NOT NULL,PRIMARY KEY(lane,attempt))")
 pins={'schema_version':'1','cohort':PAIR_CONFIG['cohort'],'mode':MODE,'science_config_sha256':CONFIG_SHA,'pair_config_sha256':PAIR_CONFIG_SHA,'storage_config_sha256':STORAGE_CONFIG_SHA,'shared_ledger_path':str(TUPLE_DB),'resource_sha256':RESOURCE_PIN}
 d.execute('BEGIN IMMEDIATE')
 try:
  for k,v in pins.items():
   old=d.execute('SELECT v FROM pair_meta WHERE k=?',(k,)).fetchone()
   if old is None:d.execute('INSERT INTO pair_meta VALUES(?,?)',(k,v))
   elif old[0]!=v:raise ValueError('pair lease pin changed: '+k)
  d.commit()
 except BaseException:
  if d.in_transaction:d.rollback()
  d.close();raise
 return d

def insert_pair_lease(pair_db,lane_name,slot,attempt,state="reserved"):
 pair_db.execute("INSERT INTO pair_leases(lane,slot,attempt,state,container_id,final_sha,updated_unix_ns) VALUES(?,?,?,?,?,?,?)",
  (lane_name,slot,attempt,state,None,None,time.time_ns()))

def preflight_pair_lease_allocator(pair_db):
 expected=["lane","slot","attempt","state","container_id","final_sha","updated_unix_ns"]
 actual=[row[1] for row in pair_db.execute("PRAGMA table_info(pair_leases)")]
 if actual!=expected:raise RuntimeError("pair lease schema mismatch")
 pair_db.execute("SAVEPOINT pair_lease_preflight")
 try:
  attempt="preflight-"+secrets.token_hex(16)
  insert_pair_lease(pair_db,"__preflight__",400,attempt)
  row=pair_db.execute("SELECT lane,slot,attempt,state,container_id,final_sha,updated_unix_ns FROM pair_leases WHERE attempt=?",(attempt,)).fetchone()
  if not row or row[:4]!=("__preflight__",400,attempt,"reserved") or row[4:6]!=(None,None) or not isinstance(row[6],int):raise RuntimeError("pair lease insert preflight row mismatch")
  pair_db.execute("ROLLBACK TO pair_lease_preflight")
  pair_db.execute("RELEASE pair_lease_preflight")
 except BaseException:
  try:pair_db.execute("ROLLBACK TO pair_lease_preflight")
  finally:pair_db.execute("RELEASE pair_lease_preflight")
  raise
 return {"passed":True,"schema_columns":actual,"insert_sql":"same helper used by production reservation","row_rolled_back":True}

def reconcile_pair_leases(pair_db,ledger_db):
 live=command(['docker','ps','-aq','--no-trunc','--filter','label=qcsd.owner='+LABEL]).splitlines()
 if live:raise RuntimeError('stale pair containers remain; preserve and reconcile exact collector/client state before retry')
 rows=pair_db.execute("SELECT lane,slot,attempt,state,container_id,final_sha FROM pair_leases WHERE state IN ('reserved','running','unsealed') ORDER BY updated_unix_ns").fetchall()
 for lane,slot,aid,state,cid,oldsha in rows:
  if cid and cid in command(['docker','ps','-aq','--no-trunc']).splitlines():raise RuntimeError('pair lease container remains after exact fence')
  directory=ROOT/'attempts'/HOST/aid;final_path=directory/'FINAL.json'
  if not final_path.exists():
   if directory.exists():raise RuntimeError('pair lease has attempt artifacts without a sealed FINAL; preserve and reconcile')
   pair_db.execute('UPDATE pair_leases SET state=?,updated_unix_ns=? WHERE lane=? AND attempt=?',('cancelled',time.time_ns(),lane,aid))
   continue
  raw=stable_read(final_path);digest=hashlib.sha256(raw).hexdigest();record=json.loads(raw)
  if record.get('attempt_id')!=aid or record.get('slot')!=slot or record.get('capture_credit') not in (True,False):raise RuntimeError('pair lease FINAL identity mismatch')
  session=ledger_db.execute('SELECT attempt,final_sha,state FROM sessions WHERE mode=? AND slot=?',(MODE,slot)).fetchone()
  if record.get('status')=='success' and record.get('capture_credit') is True:
   if session!=(aid,digest,'committed'):raise RuntimeError('pair success FINAL is not exactly committed in shared ledger')
   newstate='success'
  elif record.get('status')=='partial' and record.get('capture_credit') is False:
   if session is not None:
    if session[0]==aid or session[2]!='committed' or not session[1]:raise RuntimeError('partial pair FINAL conflicts with an unresolved or same-attempt session')
    partial_keys=set(record.get('native_tuple_keys') or [])|set(record.get('pcap_udp_tuple_keys') or [])
    committed_keys={r[0] for r in ledger_db.execute('SELECT k FROM tuples WHERE mode=? AND slot=? AND attempt=? AND state=?',(MODE,slot,session[0],'committed'))}
    if not partial_keys or not committed_keys or partial_keys & committed_keys:raise RuntimeError('older pair partial cannot be proven disjoint from later committed session')
   newstate='partial'
  else:raise RuntimeError('pair lease FINAL status is not safely reconcilable')
  pair_db.execute('UPDATE pair_leases SET state=?,final_sha=?,updated_unix_ns=? WHERE lane=? AND attempt=?',(newstate,digest,time.time_ns(),lane,aid))
 pair_db.commit()


def reserve_pair_leases(pair_db,ledger_db,lanes,deferred_slots):
 deferred=list(deferred_slots)
 if any(type(x) is not int or not 1<=x<=400 for x in deferred):raise ValueError('invalid deferred slot')
 if isinstance(deferred_slots,list) and deferred!=sorted(deferred):raise ValueError('deferred slots must be sorted')
 if len(set(deferred))!=len(deferred):raise ValueError('duplicate deferred slot')
 deferred_set=set(deferred)
 pair_db.execute('BEGIN IMMEDIATE')
 try:
  committed={r[0] for r in LEDGER.committed(ledger_db,MODE)}
  unsealed=pair_db.execute("SELECT lane,slot,attempt FROM pair_leases WHERE state='unsealed'").fetchall()
  if unsealed:raise RuntimeError('unsealed pair leases require reconciliation before reservation')
  active={r[0] for r in pair_db.execute("SELECT DISTINCT slot FROM pair_leases WHERE state IN ('reserved','running')")}
  if deferred_set & committed:raise RuntimeError('deferred policy intersects committed slots')
  if deferred_set & active:raise RuntimeError('deferred policy intersects active pair leases')
  leases=[]
  for lane in lanes:
   slot=next((n for n in range(1,401) if n not in committed and n not in active and n not in deferred_set),None)
   if slot is None:break
   attempt=secrets.token_hex(16)
   insert_pair_lease(pair_db,lane['name'],slot,attempt)
   active.add(slot);leases.append({'lane':lane,'slot':slot,'attempt':attempt})
  pair_db.commit()
  return leases
 except BaseException:
  if pair_db.in_transaction:pair_db.rollback()
  raise

def set_pair_lease(pair_db,lease,state,container=None,final_sha=None):
 if state not in ('running','success','partial','unsealed','cancelled'):raise ValueError('invalid pair lease transition')
 pair_db.execute('UPDATE pair_leases SET state=?,container_id=COALESCE(?,container_id),final_sha=COALESCE(?,final_sha),updated_unix_ns=? WHERE lane=? AND slot=? AND attempt=?',
  (state,container,final_sha,time.time_ns(),lease['lane']['name'],lease['slot'],lease['attempt']))
 if pair_db.execute('SELECT changes()').fetchone()[0]!=1:raise RuntimeError('pair lease state transition missed exact lease')
 pair_db.commit()


def pair_stage_bytes(stage_root):
 total=0
 for p in pathlib.Path(stage_root).rglob('*'):
  if p.is_symlink():raise RuntimeError('symlink in pair tmpfs stage')
  if p.is_file():total+=p.stat().st_size
 return total


def validate_pair_workers(network_policy,containers,lanes):
 if set(containers)!={lane['name'] for lane in lanes}:raise RuntimeError('pair worker lane set mismatch')
 network_policy.inspect_network(MODE,CONFIG['network'],set(containers.values()))
 seen=set()
 expected_memory=STORAGE_CONFIG['per_container_memory_limit_bytes']
 for lane in lanes:
  cid=containers[lane['name']]
  actual=network_policy.inspect_container(MODE,CONFIG['network'],cid)
  if actual!=lane['static_ip'] or actual in seen:raise RuntimeError('pair worker did not receive its unique pinned address')
  inspect=json.loads(command(['docker','inspect',cid]))[0]
  host=inspect.get('HostConfig') or {}
  cpuset=host.get('CpusetCpus')
  memory=host.get('Memory')
  effective_memory=command(['docker','exec',cid,'cat','/sys/fs/cgroup/memory.max'])
  effective_swap=command(['docker','exec',cid,'cat','/sys/fs/cgroup/memory.swap.max'])
  if (cpuset!=lane['cpuset'] or memory!=expected_memory or host.get('MemorySwap')!=expected_memory or
      effective_memory!=str(expected_memory) or effective_swap!='0'):
   raise RuntimeError('live worker CPU/memory/swap bounds differ from pinned placement')
  seen.add(actual)
 return sorted(seen)


def cleanup_pair_workers(containers):
 errors=[]
 for cid in list(containers.values()):
  try:fence_pair_container(cid)
  except Exception as e:errors.append(repr(e))
 if errors:raise RuntimeError('pair container fence failed: '+','.join(errors))


def attempt_with_worker_ledger(container,stage,slot,isolation,cutover_sha,attempt_id):
 # A worker can open only outside another worker's reserve/FINAL/commit window.
 # If an earlier attempt truly left pending state, open_ledger still rejects it.
 with FINALIZATION_LOCK:
  lane_db=LEDGER.open_ledger(TUPLE_DB,mode=MODE,config_sha=CONFIG_SHA,coverage_sha=CONFIG['coverage_sha256'],history_sha=CONFIG['history_sha256'],resource_sha=RESOURCE_PIN,prepared_sha=INPUT_SHA['prepared-workload.json'],replacement_note_sha=CONFIG['replacement_note_sha256'])
 try:return attempt(container,stage,lane_db,slot,isolation,cutover_sha,attempt_id)
 finally:lane_db.close()


def advance_no_progress_rounds(previous, accepted_sessions, maximum):
 if type(previous) is not int or type(accepted_sessions) is not int or type(maximum) is not int or previous < 0 or accepted_sessions < 0 or maximum < 1:
  raise ValueError('invalid zero-success round counters')
 if accepted_sessions:
  return 0, False
 current=previous+1
 return current, current>=maximum


def validate_prior_no_progress_baseline(pair_config):
 maximum=pair_config.get('max_no_progress_rounds')
 prior=pair_config.get('prior_zero_success_rounds')
 if type(maximum) is not int or not 1<=maximum<=4 or type(prior) is not int or not 0<=prior<maximum:
  raise ValueError('zero-success round bound must be 1..2 with a valid prior count')
 if prior==0:
  return 0
 receipt_path=pathlib.Path(pair_config['prior_zero_success_receipt_path'])
 receipt=json.loads(stable_read(receipt_path,pair_config['prior_zero_success_receipt_sha256']))
 if (receipt.get('kind')!='mal-buflo-v4-pair-production-round' or receipt.get('accepted_sessions')!=0 or
     receipt.get('capture_credit') is not False or receipt.get('errors')!=[] or receipt.get('round')!=pair_config.get('prior_zero_success_round_number')):
  raise ValueError('pinned prior round is not a clean zero-success result')
 results=receipt.get('results')
 expected=pair_config.get('prior_zero_success_attempts')
 if (not isinstance(results,list) or len(results) not in (2,3) or not isinstance(expected,list) or len(expected)!=len(results) or
     {x.get('attempt') for x in results}!=set(expected) or any(x.get('status')!='partial' for x in results)):
  raise ValueError('pinned prior zero-success round has unexpected attempts')
 previous_manifest=pathlib.Path(pair_config['previous_pair_manifest_path'])
 stable_read(previous_manifest,pair_config['previous_pair_manifest_sha256'])
 previous_db=pathlib.Path(pair_config['previous_pair_lease_db_path'])
 stable_read(previous_db,pair_config['previous_pair_lease_db_sha256'])
 con=sqlite3.connect('file:'+str(previous_db)+'?mode=ro',uri=True)
 try:
  for item in results:
   attempt=item['attempt'];slot=item['slot'];final_path=ROOT/'attempts'/HOST/attempt/'FINAL.json'
   row=con.execute('SELECT slot,state,final_sha FROM pair_leases WHERE attempt=?',(attempt,)).fetchone()
   raw=stable_read(final_path)
   record=json.loads(raw);digest=hashlib.sha256(raw).hexdigest()
   if (row!=(slot,'partial',digest) or record.get('attempt_id')!=attempt or record.get('slot')!=slot or
       record.get('status')!='partial' or record.get('capture_credit') is not False):
    raise ValueError('prior zero-success attempt is not durably reconciled as uncredited partial')
 finally:
  con.close()
 return prior



def load_async_driver():
 path=pathlib.Path(__file__).with_name('async_pair_driver_v001.py')
 if sha(path)!=ASYNC_DRIVER_SHA256:raise RuntimeError('async driver module pin mismatch')
 spec=importlib.util.spec_from_file_location('mal_buflo_async_pair_driver_v001',path)
 if spec is None or spec.loader is None:raise RuntimeError('cannot load pinned async driver module')
 module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
 return module


def run_async_pair_production(args,lanes,containers,stages,ips,network_policy,pair_db,db,isolation,initial_deferred,max_no_progress_rounds,no_progress_rounds,stopping):
 async_driver=load_async_driver()
 book=async_driver.LeaseBook(pair_db,range(1,401),parallel_width=len(lanes),
   max_no_progress_windows=max_no_progress_rounds,prior_no_progress_windows=no_progress_rounds)
 progress=book.progress()
 if progress[2]:
  return {'kind':'zero_success_round_bound_reached_before_start','no_progress_windows':progress[0],
   'maximum':max_no_progress_rounds,'committed':len(LEDGER.committed(db,MODE))}
 attempt_root=ROOT/'attempts'/HOST
 prior_records=[]
 for final_path in sorted(attempt_root.glob('*/FINAL.json')):
  raw=stable_read(final_path);record=json.loads(raw)
  if not isinstance(record,dict) or not isinstance(record.get('attempt_id'),str):raise RuntimeError('malformed prior FINAL while initializing async scheduler')
  prior_records.append(record)
 lane_by_name={lane['name']:lane for lane in lanes}
 final_by_attempt={}
 event_root=ROOT/'pair-async-events-v001';event_root.mkdir(mode=0o700,exist_ok=True)
 callback_errors=[]
 def ensure_lane_container(lane_name):
  lane=lane_by_name[lane_name]
  cid=containers.get(lane_name)
  if cid is None or cid not in ACTIVE_CONTAINERS:
   containers[lane_name]=start_container(stages[lane_name],lane)
   validate_pair_workers(network_policy,containers,lanes)
  return containers[lane_name]
 def reserve(lane_name):
  if stopping.is_set():return None
  check_tmpfs_headroom()
  deferred=current_deferred_slots(prior_records,initial_deferred,db)
  committed={r[0] for r in LEDGER.committed(db,MODE)}
  ensure_lane_container(lane_name)
  return book.reserve(lane_name,committed,deferred,attempt=secrets.token_hex(16))
 def mark_running(lease):
  book.mark_running(lease,ensure_lane_container(lease.lane))
 def execute(lease):
  cid=ensure_lane_container(lease.lane)
  return attempt_with_worker_ledger(cid,stages[lease.lane],lease.slot,isolation,CONFIG['history_sha256'],lease.attempt)
 def terminalize(lease,outcome):
  status,screen,retired=outcome
  raw=stable_read(attempt_root/lease.attempt/'FINAL.json')
  digest=hashlib.sha256(raw).hexdigest();record=json.loads(raw)
  if record.get('attempt_id')!=lease.attempt or record.get('slot')!=lease.slot:raise RuntimeError('attempt FINAL identity mismatch')
  if status=='success' and screen is not True:raise RuntimeError('success lacks packet screen')
  session=db.execute('SELECT attempt,final_sha,state FROM sessions WHERE mode=? AND slot=?',(MODE,lease.slot)).fetchone()
  keys=set(record.get('native_tuple_keys') or [])|set(record.get('pcap_udp_tuple_keys') or [])
  # The driver's historical argument name means "durably unavailable": a
  # prior committed tuple is just as unavailable as an excluded tuple.
  accounted=accounted_tuple_keys(db,keys) if status=='partial' and keys else set()
  state=book.terminalize(lease,returned_status=status,final=record,final_sha=digest,
    committed_session=session,excluded_tuple_keys=accounted)
  final_by_attempt[lease.attempt]={'record':record,'sha256':digest,'status':status,'screen':screen,'retired':retired}
  prior_records.append(record)
  return state
 def on_terminal(lease,state,outcome):
  result=final_by_attempt[lease.attempt];record=result['record']
  event={'kind':'mal-buflo-v4-async-terminal-event','scheduler_version':'async-refill-v001',
   'attempt':lease.attempt,'slot':lease.slot,'lane':lease.lane,'state':state,
   'reported_status':result['status'],'packet_screen':result['screen'],'retired':result['retired'],
   'final_sha256':result['sha256'],'capture_credit':record.get('capture_credit'),
   'no_progress_state':book.progress(),'committed_sessions':len(LEDGER.committed(db,MODE)),
   'worker_ips':ips,'finished_unix_ns':time.time_ns()}
  write_record(event_root/(lease.attempt+'.json'),event)
 def fail_closed(errors,pending_leases):
  for cid in list(ACTIVE_CONTAINERS):
   try:fence_pair_container(cid)
   except Exception as exc:callback_errors.append({'fence_error':repr(exc)})
  all_leases={x.attempt:x for x,_ in errors if x is not None}
  all_leases.update({x.attempt:x for x in pending_leases if x is not None})
  for lease in all_leases.values():
   row=pair_db.execute('SELECT state FROM pair_leases WHERE lane=? AND slot=? AND attempt=?',
     (lease.lane,lease.slot,lease.attempt)).fetchone()
   if row and row[0] in ('reserved','running'):
    try:book.mark_unsealed(lease)
    except Exception as exc:callback_errors.append({'unsealed_transition_error':lease.attempt,'error':repr(exc)})
  callback_errors.extend({'attempt':lease.attempt if lease else None,'error':repr(exc)} for lease,exc in errors)
 completed_count=0
 def observe(lease,state,outcome):
  nonlocal completed_count
  completed_count+=1
  on_terminal(lease,state,outcome)
 result=async_driver.run_refill([lane['name'] for lane in lanes],reserve=reserve,
   mark_running=mark_running,execute=execute,terminalize=terminalize,fail_closed=fail_closed,
   on_terminal=observe,max_no_progress_windows=max_no_progress_rounds,
   prior_no_progress_windows=progress[0],
   stop_requested=lambda:stopping.is_set() or (args.once and completed_count>=len(lanes)))
 progress_after=book.progress()
 committed_count=len(LEDGER.committed(db,MODE))
 deferred=current_deferred_slots(prior_records,initial_deferred,db)
 if callback_errors or result['errors']:
  reason={'kind':'async_attempt_or_callback_error','errors':callback_errors+
   [{'attempt':lease.attempt if lease else None,'error':repr(exc)} for lease,exc in result['errors']]}
 elif progress_after[2]:
  reason={'kind':'zero_success_round_bound_reached','no_progress_windows':progress_after[0],
   'maximum':max_no_progress_rounds}
 elif stopping.is_set() or (args.once and completed_count>=len(lanes)):
  reason={'kind':'requested_clean_stop'}
 elif committed_count>=400:
  reason=None
 elif deferred:
  reason={'kind':'deferred_slots_pending_repair','deferred_slots':sorted(deferred),'committed':committed_count}
 else:
  reason={'kind':'no_eligible_slots','committed':committed_count}
 return {'kind':'mal-buflo-v4-async-owner-summary','scheduler_version':'async-refill-v001',
  'capture_credit':committed_count>0,'committed':committed_count,'completed_attempts':completed_count,
  'no_progress_state':progress_after,'max_no_progress_rounds':max_no_progress_rounds,
  'deferred_slots':sorted(deferred),'worker_ips':ips,'stop_reason':reason,
  'attempt_events':str(event_root)}


def main():
 global BASELINE_ATTEMPTS
 global CONFIG_PATH,CONFIG_SHA,CONFIG,HISTORY,ROOT,HOST,INPUTS,CLIENT,MODEL,MODULE,IMAGE,MODEL_SHA,CLIENT_SHA,MODULE_SHA,AUDIT,AUDIT_SHA,INPUT_SHA,STOP_FREE,TUPLE_DB,CREATE_JOURNAL,LABEL,NOTE,LEDGER,MODE,STORAGE_CONFIG_PATH,STORAGE_CONFIG_SHA,STORAGE_CONFIG,EXPERIMENT_NO_CREDIT,PAIR_CONFIG,PAIR_CONFIG_PATH,PAIR_CONFIG_SHA,ACTIVE_CONTAINERS,CONTAINER_LANES,PAIR_LEASE_DB_PATH,CONTAINER_JOURNAL_PATHS,FAILURE_BUDGET
 p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--config-sha',required=True);p.add_argument('--storage-config',required=True);p.add_argument('--storage-config-sha',required=True);p.add_argument('--once',action='store_true');p.add_argument('--preflight-only',action='store_true');p.add_argument('--enable-async-execution',action='store_true');args=p.parse_args()
 if not ASYNC_EXECUTION_ENABLED or not args.enable_async_execution:raise SystemExit('async derivative is disabled; no capture can start')
 CONFIG_PATH=pathlib.Path(args.config);CONFIG_SHA=args.config_sha;CONFIG=json.loads(stable_read(CONFIG_PATH,CONFIG_SHA))
 STORAGE_CONFIG_PATH=pathlib.Path(args.storage_config);STORAGE_CONFIG_SHA=args.storage_config_sha;STORAGE_CONFIG=json.loads(stable_read(STORAGE_CONFIG_PATH,STORAGE_CONFIG_SHA))
 PAIR_CONFIG_PATH=pathlib.Path(STORAGE_CONFIG['pair_manifest_path']);PAIR_CONFIG=json.loads(stable_read(PAIR_CONFIG_PATH,STORAGE_CONFIG['pair_manifest_sha256']));PAIR_CONFIG_SHA=STORAGE_CONFIG['pair_manifest_sha256']
 if sha(pathlib.Path(STORAGE_CONFIG['scientific_owner_path']))!=CONFIG['owner_sha256'] or sha(CONFIG_PATH)!=CONFIG_SHA:raise RuntimeError('science config or owner pin mismatch')
 if (sha(pathlib.Path(CONFIG['network_module']))!=CONFIG['network_module_sha256'] or CONFIG['network']!=PAIR_CONFIG.get('network') or
     PAIR_CONFIG.get('science_config_sha256')!=CONFIG_SHA or PAIR_CONFIG.get('mode')!='buflo' or PAIR_CONFIG.get('domain')!=CONFIG['hostname']):raise RuntimeError('base network/config pin mismatch')
 if (STORAGE_CONFIG.get('kind')!='buflo-v4-pair-runner-config' or STORAGE_CONFIG.get('scientific_config_sha256')!=CONFIG_SHA or
     STORAGE_CONFIG.get('pair_manifest_sha256')!=PAIR_CONFIG_SHA or sha(STORAGE_CONFIG_PATH)!=STORAGE_CONFIG_SHA):raise RuntimeError('pair runner config pin mismatch')
 pair_network_path=pathlib.Path(STORAGE_CONFIG['pair_network_policy_path']);pair_network_sha=STORAGE_CONFIG['pair_network_policy_sha256']
 if sha(pair_network_path)!=pair_network_sha or pair_network_sha!=PAIR_CONFIG.get('pair_network_policy_sha256'):raise RuntimeError('pair network policy pin mismatch')
 original_network_path=CONFIG['network_module'];original_network_sha=CONFIG['network_module_sha256']
 if sha(pathlib.Path(original_network_path))!=original_network_sha:raise RuntimeError('base network module changed')
 # Operational bridge membership is versioned separately; domain, network identity, and subnet remain science-config pinned.
 CONFIG['network_module']=str(pair_network_path);CONFIG['network_module_sha256']=pair_network_sha
 EXPERIMENT_NO_CREDIT=False
 MODE=CONFIG['mode'];HOST=CONFIG['hostname'];ROOT=pathlib.Path(CONFIG['root']);INPUTS=pathlib.Path(CONFIG['inputs']);HISTORY=pathlib.Path(CONFIG['history']);NOTE=pathlib.Path(CONFIG['note'])
 CLIENT=pathlib.Path(CONFIG['client']);MODEL=pathlib.Path(CONFIG['model']);MODULE=pathlib.Path(CONFIG['tuple_module'])
 IMAGE=CONFIG['image'];MODEL_SHA=CONFIG['model_sha256'];CLIENT_SHA=CONFIG['client_sha256'];MODULE_SHA=CONFIG['tuple_module_sha256'];INPUT_SHA=CONFIG['input_sha256']
 if CLIENT_SHA!=ORIGINAL_CLIENT_SHA:raise ValueError('unexpected original ledger anchor')
 variant=json.loads(stable_read(VARIANT_RECEIPT_PATH,VARIANT_RECEIPT_SHA))
 if (variant.get('kind')!='buflo-20ms-production-transition-v1' or variant.get('mode')!='buflo' or
     variant.get('original_config_sha256')!=CONFIG_SHA or variant.get('original_client_sha256')!=ORIGINAL_CLIENT_SHA or
     variant.get('cadence_us')!=64000 or variant.get('cell_bytes')!=1200 or variant.get('physical_window_us')!=20000 or
     variant.get('selection_after_release_us')!=19000 or variant.get('etf_horizon_us')!=25000 or
     variant.get('allow_omissions') is not False or variant.get('allow_catch_up') is not False or
     variant.get('canary_passed') is not True or variant.get('canary_capture_credit') is not False):
  raise ValueError('invalid or unproven variant transition')
 CLIENT=pathlib.Path(variant['client_path']);CLIENT_SHA=variant['client_sha256']
 if (not isinstance(CLIENT_SHA,str) or len(CLIENT_SHA)!=64 or
     sha(pathlib.Path(variant['canary_result_path']))!=variant['canary_result_sha256'] or
     sha(VARIANT_CHECKER_PATH)!=VARIANT_CHECKER_SHA or sha(VARIANT_GATES_PATH)!=VARIANT_GATES_SHA):
  raise ValueError('variant evidence pin mismatch')
 canary=json.loads(stable_read(pathlib.Path(variant['canary_result_path']),variant['canary_result_sha256']))
 if canary.get('status')!='diagnostic_pass' or canary.get('capture_credit') is not False or canary.get('accepted_sessions')!=0:
  raise ValueError('canary did not pass without production credit')
 prior=json.loads(stable_read(pathlib.Path(variant['baseline_path']),variant['baseline_sha256']))['prior_partial_final_sha256']
 if not isinstance(prior,dict) or any(not isinstance(k,str) or not isinstance(v,str) or len(v)!=64 for k,v in prior.items()):
  raise ValueError('invalid mixed-epoch baseline')
 for prior_id,digest in prior.items():
  prior_record=json.loads(stable_read(ROOT/'attempts'/HOST/prior_id/'FINAL.json',digest))
  if (prior_record.get('attempt_id')!=prior_id or prior_record.get('purpose')!='production' or
      prior_record.get('status')!='partial' or prior_record.get('capture_credit') not in (False,None) or
      prior_record.get('native_client_sha256')!=ORIGINAL_CLIENT_SHA):
   raise ValueError('mixed baseline entry does not describe an original uncredited partial')
 BASELINE_ATTEMPTS=set(prior)
 STOP_FREE=30*1024**3;TUPLE_DB=ROOT.parent.parent/'shared-ledger-v3.sqlite3';CREATE_JOURNAL=ROOT/'creation-journal';LABEL='qcsd-mal-v3-buflo-'+HOST+'-pair-v4-022-async'
 if HOST!='cdn.myanimelist.net' or MODE!='buflo' or ROOT!=ROOT.parent.parent/'modes'/MODE:raise ValueError('pair mode scope mismatch')
 lanes=PAIR_CONFIG.get('lanes')
 if (PAIR_CONFIG.get('candidate_version')!=ASYNC_OWNER_VERSION or
     PAIR_CONFIG.get('execution_enabled') is not ASYNC_EXECUTION_ENABLED or
     PAIR_CONFIG.get('scheduler_version')!='async-refill-v001' or
     PAIR_CONFIG.get('scheduler_contract')!='qcsd-client-rr1-portable-etf-helper-v4' or
     PAIR_CONFIG.get('per_attempt_tmpfs_limit_bytes')!=512*1024**2 or
     STORAGE_CONFIG.get('max_attempt_tmpfs_bytes')!=512*1024**2 or
     PAIR_CONFIG.get('minimum_memavailable_bytes')!=4*1024**3 or
     PAIR_CONFIG.get('minimum_tmpfs_free_bytes')!=2560*1024**2):
  raise ValueError('async pair scheduler or resource bounds mismatch')
 placement=json.loads(stable_read(pathlib.Path(STORAGE_CONFIG['lane_placement_path']),STORAGE_CONFIG['lane_placement_sha256']))
 async_driver=load_async_driver()
 normalized=async_driver.validate_lane_placement(lanes,subnet=CONFIG['network']['subnet'],
   gateway=CONFIG['network']['gateway'],observer_cpu=STORAGE_CONFIG.get('observer_cpu'))
 if placement.get('lanes')!=normalized or STORAGE_CONFIG.get('pair_lanes')!=normalized:
  raise ValueError('pair, storage and validated placement lanes differ')
 lane_count=len(normalized)
 if lane_count!=4 or PAIR_CONFIG.get('helper_shared') is not True or PAIR_CONFIG.get('shared_helper_cpu')!=5:
  raise ValueError('expected four lanes with explicitly shared helper CPU5')
 expected_mem=lane_count*1024**3
 if (STORAGE_CONFIG.get('observer_cpu')!=0 or STORAGE_CONFIG.get('per_container_memory_limit')!='1g' or
     STORAGE_CONFIG.get('per_container_memory_limit_bytes')!=1024**3 or
     STORAGE_CONFIG.get('aggregate_container_memory_limit_bytes')!=expected_mem or
     STORAGE_CONFIG.get('max_parallel_tmpfs_bytes')!=lane_count*512*1024**2 or
     PAIR_CONFIG.get('aggregate_container_memory_limit_bytes')!=expected_mem or
     PAIR_CONFIG.get('max_parallel_workers')!=lane_count or
     PAIR_CONFIG.get('lane_count')!=lane_count):
  raise ValueError('pair lane count or aggregate resource bounds mismatch')
 if (STORAGE_CONFIG.get('pair_lease_db_path')!=PAIR_CONFIG.get('pair_lease_db_path') or
     PAIR_CONFIG.get('pair_lease_db_path') is None or
     STORAGE_CONFIG.get('driver_path')!=str(pathlib.Path(__file__)) or
     STORAGE_CONFIG.get('execution_enabled') is not ASYNC_EXECUTION_ENABLED or
     pathlib.Path(STORAGE_CONFIG['pair_lease_db_path']).name!='pair-leases-async-v001.sqlite3' or
     pathlib.Path(STORAGE_CONFIG['tmpfs_stage_root']).name!='qcsd-mal-buflo-pair-v022-async' or
     STORAGE_CONFIG.get('pair_lease_db_path')==PAIR_CONFIG.get('previous_pair_lease_db_path') or
     STORAGE_CONFIG.get('tmpfs_stage_root')==PAIR_CONFIG.get('previous_tmpfs_stage_root')):
  raise ValueError('async DB or staging path is reused or not versioned')
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('pinned client/model/input mismatch')
 if command(['docker','image','inspect',IMAGE,'--format','{{.Id}}'])!=IMAGE:raise ValueError('image identity changed')
 if CONFIG['exclusive_fence_locks']!=[] or ROOT.resolve()!=ROOT or INPUTS.resolve()!=INPUTS:raise ValueError('unexpected fence or symlink')
 ROOT.mkdir(parents=True,exist_ok=True);(ROOT/'attempts'/HOST).mkdir(parents=True,exist_ok=True)
 locks=[]
 for lockpath in [ROOT/'production-owner.lock',*[pathlib.Path(x) for x in CONFIG['exclusive_fence_locks']]]:
  f=lockpath.open('a+');fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(f)
 baseline=verify_transfer()
 if sha(PAIR_CONFIG_PATH)!=PAIR_CONFIG_SHA:raise RuntimeError('pair manifest changed after load')
 if sha(pathlib.Path(STORAGE_CONFIG['pair_network_policy_path']))!=STORAGE_CONFIG['pair_network_policy_sha256']:raise RuntimeError('pair network policy changed')
 if command(['docker','ps','-aq','--filter','label=qcsd.owner='+LABEL]):raise RuntimeError('existing pair worker before lease recovery')
 reconcile_creation_journal()
 isolation=load_pinned_module(MODULE,MODULE_SHA)
 db=initialize_ledger(baseline,CONFIG['history_sha256'])
 # Static worker IPs must not occur in any committed/excluded v3 tuple.
 used_ips={json.loads(row[0])[1] for row in db.execute('SELECT k FROM tuples')}
 candidate_ips=sorted(x['static_ip'] for x in lanes)
 if used_ips.intersection(set(candidate_ips)):raise RuntimeError('pair static IP already appears in tuple history')
 audit_path=pathlib.Path(PAIR_CONFIG['static_ip_history_audit_path'])
 audit=json.loads(stable_read(audit_path,PAIR_CONFIG['static_ip_history_audit_sha256']))
 zero_occurrences={ip:0 for ip in candidate_ips}
 if (audit.get('kind')!='buflo-pair-worker-ip-history-audit-v4-022-async' or audit.get('candidate_worker_ips')!=candidate_ips or
     audit.get('candidate_ip_occurrences_in_shared_tuple_ledger')!=zero_occurrences or
     audit.get('candidate_ip_occurrences_in_prior_tuple_history')!=zero_occurrences or
     audit.get('candidate_ip_occurrences_in_prior_final_evidence')!=zero_occurrences or
     audit.get('candidate_ips_absent_from_active_network') is not True or audit.get('network_id')!=CONFIG['network']['id']):
  raise RuntimeError('fresh pair worker IP history audit mismatch')
 network_policy=load_pinned_module(pair_network_path,pair_network_sha)
 pair_db=open_pair_lease_db()
 pair_lease_preflight=preflight_pair_lease_allocator(pair_db)
 reconcile_pair_leases(pair_db,db)
 no_progress_rounds=validate_prior_no_progress_baseline(PAIR_CONFIG)
 max_no_progress_rounds=PAIR_CONFIG['max_no_progress_rounds']
 deferral_policy_path=pathlib.Path(PAIR_CONFIG['slot_deferral_policy_path'])
 deferral_policy=json.loads(stable_read(deferral_policy_path,PAIR_CONFIG['slot_deferral_policy_sha256']))
 if (deferral_policy.get('kind')!='mal-buflo-v4-deferred-slot-policy' or
     deferral_policy.get('cohort')!='cdn.myanimelist.net-roster-v3-001' or
     deferral_policy.get('retry_budget_epoch_sha256')!=STORAGE_CONFIG['failure_budget_sha256']):
  raise RuntimeError('slot deferral policy pin mismatch')
 initial_deferred=deferral_policy.get('initial_deferred_slots')
 if (not isinstance(initial_deferred,list) or any(type(x) is not int or not 1<=x<=400 for x in initial_deferred) or
     len(set(initial_deferred))!=len(initial_deferred)):
  raise RuntimeError('invalid initial deferred-slot policy')
 initial_deferred=set(initial_deferred)
 history=json.loads(stable_read(HISTORY,CONFIG['history_sha256']))
 network_policy.verify_history_disjoint(history,CONFIG['network']['subnet'])
 network_policy.inspect_network(MODE,CONFIG['network'],None)
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA:raise RuntimeError('pinned client/model changed')
 stage_parent=pathlib.Path(STORAGE_CONFIG['tmpfs_stage_root']);stage_parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 if stage_parent.is_symlink() or any(stage_parent.iterdir()):raise RuntimeError('pair tmpfs stage is nonempty; preserve and reconcile')
 stage_parent.chmod(0o700);sync_dir(stage_parent)
 stages={}
 for lane in lanes:
  lane_stage=stage_parent/lane['name'];lane_stage.mkdir(mode=0o700);stages[lane['name']]=lane_stage
 if check_tmpfs_headroom()['tmpfs_free_bytes']<STORAGE_CONFIG['minimum_tmpfs_free_bytes']:raise RuntimeError('pair tmpfs floor not met')
 containers={};stopping=threading.Event();signal.signal(signal.SIGTERM,lambda *_:stopping.set());signal.signal(signal.SIGINT,lambda *_:stopping.set())
 if args.preflight_only:
  preflight_root=ROOT/'pair-v4-022-20ms-async-preflight-v018'
  if preflight_root.exists():raise RuntimeError('pair preflight receipt already exists')
  preflight_root.mkdir(mode=0o700)
  try:
   for lane in lanes:containers[lane['name']]=start_container(stages[lane['name']],lane)
   ips=validate_pair_workers(network_policy,containers,lanes)
   record={'kind':'buflo-v4-pair-production-preflight','status':'passed','capture_credit':False,'accepted_sessions':0,'pair_config_sha256':PAIR_CONFIG_SHA,'storage_config_sha256':STORAGE_CONFIG_SHA,'network_policy_sha256':pair_network_sha,'network':CONFIG['network'],'worker_ips':ips,'lanes':lanes,'scheduler_preflight_receipts':[str(CONTAINER_JOURNAL_PATHS[cid]/'scheduler-preflight.json') for cid in sorted(containers.values())],'tmpfs_headroom':check_tmpfs_headroom(),'pair_lease_allocator':pair_lease_preflight}
   write_record(preflight_root/'RESULT.json',record)
  finally:
   cleanup_pair_workers(containers)
  if any(any(stage.iterdir()) for stage in stages.values()):raise RuntimeError('pair preflight left tmpfs files')
  for stage in stages.values():stage.rmdir()
  stage_parent.rmdir();sync_dir(stage_parent.parent)
  pair_db.close();db.close()
  print(json.dumps({'preflight':'passed','receipt':str(preflight_root/'RESULT.json'),'worker_ips':ips,'capture_credit':False},sort_keys=True),flush=True);return
 # The asynchronous owner is isolated and hard-disabled pending independent review.
 try:
  if command(['docker','ps','-aq','--filter','label=qcsd.owner='+LABEL]):raise RuntimeError('pair workers appeared before startup')
  for lane in lanes:containers[lane['name']]=start_container(stages[lane['name']],lane)
  ips=validate_pair_workers(network_policy,containers,lanes)
  async_summary=run_async_pair_production(args,lanes,containers,stages,ips,network_policy,pair_db,db,isolation,
    initial_deferred,max_no_progress_rounds,no_progress_rounds,stopping)
  print(json.dumps({'hostname':HOST,'mode':MODE,**async_summary},sort_keys=True),flush=True)
 finally:
  try:cleanup_pair_workers(containers)
  finally:
   for stage in stages.values():
    if stage.exists() and stage.is_dir() and not any(stage.iterdir()):stage.rmdir()
   if stage_parent.exists() and stage_parent.is_dir() and not any(stage_parent.iterdir()):stage_parent.rmdir();sync_dir(stage_parent.parent)
   pair_db.close();db.close()
if __name__=='__main__':main()

