#!/usr/bin/env python3
"""Isolated Clarín BuFLO or CS-BuFLO capture owner, gated by verified 20k local coverage."""
import argparse,csv,fcntl,hashlib,importlib.util,ipaddress,json,os,pathlib,re,resource,secrets,shutil,signal,sqlite3,subprocess,threading,time
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
def cap_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024**2,64*1024**2))
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
 current=[r for r in prior if r.get("ownership_sha256")==CONFIG_SHA]
 return (sum(r.get("slot")==slot and r.get("status")!="success" and r.get("packet_count_screen_passed") is True for r in current),
         sum(r.get("slot")==slot and r.get("status")!="success" and r.get("packet_count_screen_passed") is False for r in current))
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

OLD_CONFIG_SHA='a28353bccb81babb88adcb4917a9f1a2b4626bf63dddd31857d79dd31272a5b3'
VARIATION_SHA='e204097bf2c983971c53d8b390134eed68120eae1fcae4c0d121b73416c9df88'
PARTIALS=[('e6a163bed824756f730b842fff9c99f9','534e18a0418a11fbce3d4315b29e9ad422aee5fe3f5ca049ee577e1406570172','d3dbb32acfc20281c09ecd7fb7f8f7b11d95215f3b90b172ccdfd5bbf6e3e673','["udp","172.29.171.2",59257,"104.16.179.112",443]'),('4268ab383f65a99be0bbd4f1aec31420','ffe2392f2153df36aa305c40d85a43263be87b828a722bc441bd2fe260f91fae','94a720c00f26c58e7a4c6b4529ef93ddfb984df9f439ffd1c7ababdbe160556b','["udp","172.29.171.2",57203,"104.16.179.112",443]')]


def validate_successor_config(new,old):
 allowed={'owner_sha256','inputs','input_sha256','ledger_config_sha256'}
 if {k:v for k,v in new.items() if k not in allowed}!={k:v for k,v in old.items() if k not in allowed}:raise ValueError('unrelated settings changed')
 for k in ('resources.json','prepared-workload.json','chaff-manifest.json'):
  if new['input_sha256'].get(k)!=old['input_sha256'].get(k):raise ValueError('fixed workload changed')
 if set(new['input_sha256'])!={'resources.json','prepared-workload.json','chaff-manifest.json','params/buflo.json'} or new['input_sha256']['params/buflo.json']!='5c35c9a6c0ce9d424b3e9cfc9e05a48713b9260fd1385dfba2d79048f58f283e':raise ValueError('unapproved parameters')

def verify_transfer(expected_container=None):
 if MODE!='buflo' or sha(ROOT/'owner-config-001.json')!=OLD_CONFIG_SHA or CONFIG.get('ledger_config_sha256')!=OLD_CONFIG_SHA:raise ValueError('original ledger configuration changed')
 old=json.loads(stable_read(ROOT/'owner-config-001.json',OLD_CONFIG_SHA));extra={'prior_config','prior_config_sha256','leases_module','leases_module_sha256','workers','worker_network_module','worker_network_module_sha256','worker_network_manifest','worker_network_manifest_sha256','recovery_module','recovery_module_sha256'};validate_successor_config({k:v for k,v in CONFIG.items() if k not in extra},old)
 note=json.loads(stable_read(ROOT/'dispatch-variation-001.json',VARIATION_SHA))
 if note.get('kind')!='buflo-documented-dispatch-variation' or note.get('domain')!=HOST or note.get('application_workload_sha256')!=INPUT_SHA['resources.json'] or note.get('application_urls_changed') is not False or note.get('interval_us')!=64000 or note.get('request_policy')!='half-duplex' or note.get('parameter_sha256')!=INPUT_SHA['params/buflo.json']:raise ValueError('timing variation changed')
 for aid,finalsha,auditsha,key in PARTIALS:
  audit=json.loads(stable_read(ROOT/('partial-exclusion-'+aid+'.json'),auditsha))
  if audit.get('capture_credit') is not False or audit.get('attempt_id')!=aid or audit.get('final_sha256')!=finalsha or audit.get('native_tuple_keys')!=[key] or audit.get('raw_pcap_tuple_keys')!=[key] or sha(ROOT/'attempts'/HOST/aid/'FINAL.json')!=finalsha:raise ValueError('partial audit changed')
 if sha(CONFIG_PATH)!=CONFIG_SHA or sha(HISTORY)!=CONFIG['history_sha256']:raise RuntimeError('ownership or history changed')
 if sha(pathlib.Path(__file__))!=CONFIG['owner_sha256']:raise RuntimeError('owner code changed')
 if sha(NOTE)!=CONFIG['note_sha256']:raise RuntimeError('workload note changed')
 note=json.loads(stable_read(NOTE,CONFIG['note_sha256']))
 if note.get('replacement_domain')!=HOST or note.get('old_domain')!='th-eu4.pornone.com' or note.get('kind')!='wtfpad-class-domain-replacement' or note.get('resource_count')!=20 or note.get('original_handoff_unchanged') is not True or note.get('original_roster_sha256')!='f28e48a4c149ced9cab456dacaaf064cb256db4cfbfca62bbed684e21bb20f38' or note.get('defense')!='wtf-pad' or note.get('workload_sha256')!=INPUT_SHA['resources.json']:raise ValueError('fixed workload note changed')
 coverage=json.loads(stable_read(pathlib.Path(CONFIG['coverage_receipt']),CONFIG['coverage_sha256']))
 if coverage.get('kind')!='wtfpad-local-50-domain-coverage' or coverage.get('count')!=20000 or coverage.get('domains')!=50 or coverage.get('sessions_per_domain')!=400 or coverage.get('drive_upload_required') is not False or coverage.get('global_original_roster_sha256')!='f28e48a4c149ced9cab456dacaaf064cb256db4cfbfca62bbed684e21bb20f38':raise ValueError('local 20k coverage proof invalid')
 history=json.loads(stable_read(HISTORY,CONFIG['history_sha256']))
 if CONFIG.get('network_module_sha256')!='1673153f8d6794fe1caa9271b820e2841e9e40fc3cf718d6455e0e8d5b97e686':raise ValueError('network policy pin differs')
 network_policy=load_pinned_module(pathlib.Path(CONFIG['network_module']),CONFIG['network_module_sha256'])
 network_manifest=json.loads(stable_read(pathlib.Path(CONFIG['network_manifest']),CONFIG['network_manifest_sha256']))
 if network_manifest.get('domain')!=HOST or network_manifest.get('history_sha256')!=CONFIG['history_sha256'] or (network_manifest.get('networks') or {}).get(MODE)!=CONFIG['network']:raise ValueError('network manifest differs')
 network_policy.inspect_network(MODE,CONFIG['network'],None);network_policy.verify_history_disjoint(history,CONFIG['network']['subnet'])
 if WORKER_INDEX is not None:WORKER_NETWORKS.verify_worker_network(WORKER_INDEX,expected_container)
 if history.get('kind')!='jsdelivr-wtfpad-prior-tuple-history' or history.get('domain')!=HOST or len(history.get('committed',[]))!=400:raise ValueError('prior tuple history invalid')
 entries=history['committed'];slots=[x.get('slot') for x in entries];keys=[k for x in entries for k in x.get('native_tuple_keys',[])]
 reserved=history.get('reserved_native_tuples')
 if sorted(slots)!=list(range(1,401)) or not isinstance(reserved,list) or not reserved or len(set(keys))!=len(keys) or len(set(reserved))!=len(reserved) or set(keys)&set(reserved):raise ValueError('prior tuple exclusions invalid')
 return {'entries':[], 'reserved_native_tuples':sorted(set(keys)|set(reserved))}

def classify_collision(db,keys,baseline,reservation_failed):
 existing=[(key,db.execute('SELECT mode,attempt,slot,final_sha,state FROM tuples WHERE k=?',(key,)).fetchone()) for key in keys]
 reserved=[(key,row) for key,row in existing if row is not None or key in baseline]
 if reservation_failed and not reserved:raise RuntimeError('slot reservation failed without an identified tuple collision')
 if not reserved:return []
 if len(keys)!=1 or len(reserved)!=1:raise RuntimeError('ambiguous multi-endpoint tuple collision')
 key,row=reserved[0]
 if row is not None and row[4] not in ('committed','excluded'):raise RuntimeError('tuple has nonterminal reservation')
 return [{'key':key,'existing_ledger_row':list(row) if row else None,'previous_wtfpad_history':key in baseline}]

def reserve_observed_partial(db,*,mode,slot,attempt,final_sha,keys,baseline):
 if not keys or len(keys)!=len(set(keys)) or set(keys)&set(baseline):raise ValueError('ambiguous partial endpoints')
 db.execute('BEGIN IMMEDIATE')
 try:
  if db.execute('SELECT 1 FROM sessions WHERE mode=? AND slot=?',(mode,slot)).fetchone():raise ValueError('partial slot already credited')
  for key in keys:
   if db.execute('SELECT 1 FROM tuples WHERE k=?',(key,)).fetchone():raise ValueError('partial tuple collision')
   db.execute('INSERT INTO tuples VALUES(?,?,?,?,?,?)',(key,mode,attempt,slot,final_sha,'excluded'))
  db.commit()
 except BaseException:db.rollback();raise

def check_auto_partial(db,record,finalsha):
 keys=record.get('observed_partial_tuple_keys')
 if not isinstance(keys,list) or not keys:raise ValueError('automatic partial lacks endpoint evidence')
 for key in keys:
  if db.execute('SELECT mode,attempt,slot,final_sha,state FROM tuples WHERE k=?',(key,)).fetchone()!=(MODE,record['attempt_id'],record['slot'],finalsha,'excluded'):raise ValueError('automatic partial exclusion requires reconciliation')

def initialize_ledger(history,cutover_sha):
 if sha(pathlib.Path(CONFIG['ledger_module']))!=CONFIG['ledger_module_sha256']:raise ValueError('shared ledger module changed')
 global LEDGER
 LEDGER=load_pinned_module(pathlib.Path(CONFIG['ledger_module']),CONFIG['ledger_module_sha256'])
 db=LEDGER.open_ledger(TUPLE_DB,mode=MODE,config_sha=OLD_CONFIG_SHA,coverage_sha=CONFIG['coverage_sha256'],history_sha=CONFIG['history_sha256'])
 for aid,finalsha,auditsha,key in PARTIALS:
  if db.execute('SELECT mode,attempt,slot,final_sha,state FROM tuples WHERE k=?',(key,)).fetchone()!=('buflo',aid,1,finalsha,'excluded'):raise ValueError('partial tuple exclusion changed')
 for slot,aid,digest in LEDGER.committed(db,MODE):
  p=ROOT/'attempts'/HOST/aid/'FINAL.json';r=json.loads(stable_read(p,digest))
  if r.get('slot')!=slot or r.get('status')!='success' or r.get('defense')!=MODE:raise RuntimeError('ledger FINAL mismatch')
  actual=tuple_keys(json.loads(stable_read(p.parent/'native/run.json',r['files']['native/run.json']['sha256'])))
  recorded=[x[0] for x in db.execute('SELECT k FROM tuples WHERE mode=? AND attempt=? AND slot=? AND final_sha=? AND state=?',(MODE,aid,slot,digest,'committed'))]
  if set(actual)!=set(recorded):raise RuntimeError('ledger tuple history mismatch')
 for p in (ROOT/'attempts'/HOST).glob('*'):
  if p.is_symlink() or not p.is_dir() or not (p/'FINAL.json').is_file():raise RuntimeError('unsealed attempt requires review')
  r=json.loads(stable_read(p/'FINAL.json'))
  if r.get('attempt_id')!=p.name or r.get('hostname')!=HOST:raise RuntimeError('attempt identity mismatch')
  if r.get('status')=='success' and db.execute('SELECT attempt FROM sessions WHERE mode=? AND slot=?',(MODE,r['slot'])).fetchone()!=(p.name,):raise RuntimeError('untracked success requires review')
  if r.get('automatic_partial_exclusion') is True:check_auto_partial(db,r,sha(p/'FINAL.json'))
 return db
def store_final(directory,record):
 tmp=directory/'.FINAL.tmp';target=directory/'FINAL.json'
 if target.exists():raise FileExistsError(target)
 with tmp.open('x') as f:json.dump(record,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
 os.link(tmp,target);sync_dir(directory)
 tmp.unlink();sync_dir(directory)
 return sha(target)
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
def next_worker_ip():
 spec=WORKER_NETWORKS.worker_spec(WORKER_INDEX);net=ipaddress.ip_network(spec['subnet'])
 if net.prefixlen!=24 or str(net.network_address+1)!=spec['gateway']:raise ValueError('unexpected worker subnet')
 entries=list(CREATE_JOURNAL.iterdir())
 if any(e.is_symlink() or not e.is_dir() for e in entries):raise ValueError('unsafe creation journal')
 return str(net.network_address+3+(len(entries)%251))
def start_container(stage):
 desired_ip=next_worker_ip()
 args=['docker','run','-d','--network',WORKER_NETWORKS.worker_spec(WORKER_INDEX)['id'],'--ip',desired_ip,'--label','qcsd.owner='+LABEL,'--label','qcsd.parallel-scope=five-recapture-buflo-cdn.jsdelivr.net',
  '--mount',f'type=bind,src={INPUTS},dst=/inputs,readonly','--mount',f'type=bind,src={stage},dst=/worker',
  '--mount',f'type=bind,src={CLIENT},dst=/usr/local/bin/neqo-qcsd-client,readonly',
  '--mount',f'type=bind,src={MODEL},dst=/model.json,readonly','--entrypoint','/bin/sleep',IMAGE,'infinity']
 entry=CREATE_JOURNAL/secrets.token_hex(16);entry.mkdir();sync_dir(CREATE_JOURNAL)
 write_record(entry/'INTENT.json',{'args':args,'scope':'single labeled reuse worker'})
 # A separate recorder survives owner timeout and writes a durable result only
 # after the Docker CLI finishes.  No result means creation is still ambiguous.
 recorder='''import json,os,pathlib,subprocess,sys\np=pathlib.Path(sys.argv[1]);args=json.loads(sys.argv[2]);r=subprocess.run(args,text=True,capture_output=True)\nv={'returncode':r.returncode,'container':r.stdout.strip(),'stderr':r.stderr}\nwith (p/'RESULT.json').open('x') as f:json.dump(v,f,sort_keys=True);f.write('\\n');f.flush();os.fsync(f.fileno())\nfd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)\n'''
 proc=subprocess.Popen(['/usr/bin/python3','-c',recorder,str(entry),json.dumps(args)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
 try:proc.wait(timeout=900)
 except subprocess.TimeoutExpired:raise RuntimeError('docker create still unresolved; ownership remains reserved')
 result=entry/'RESULT.json'
 if proc.returncode!=0 or not result.is_file():raise RuntimeError('docker create result recorder failed; old-owner hold remains')
 data=json.loads(result.read_bytes());cid=data.get('container','')
 if data.get('returncode')!=0 or not re.fullmatch(r'[0-9a-f]{64}',cid):raise RuntimeError('ambiguous docker create result; old-owner hold remains')
 write_record(entry/'RESOLVED.json',{'container':cid,'reconciliation':'identified and handed to owner','requested_ip':desired_ip})
 try:
  if WORKER_NETWORKS.inspect_worker_container(WORKER_INDEX,cid)!=desired_ip:raise ValueError('worker address differs from requested address')
 except Exception:
  fence_container(cid)
  raise
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
def fence_uncertain_exec_before_collector(container,directory,observer):
 # An exec timeout does not prove the client stopped. Preserve a durable
 # fence intent and keep tcpdump alive until Docker proves the exact container
 # is absent. Any ambiguity remains unsealed and earns no capture credit.
 try: alive_before=observer is not None and observer.poll() is None
 except Exception: alive_before=False
 intent_error=None
 try:write_record(directory/'uncertain-exec-fence-intent.json',{'container':container,'collector_pid':getattr(observer,'pid',None),'collector_alive_before':alive_before,'capture_credit':False,'state':'fence-pending'})
 except Exception as exc:intent_error=exc
 fence_container(container)
 if intent_error is not None:raise RuntimeError('container fenced but fence intent failed; preserve unsealed evidence') from intent_error
 try:alive_after=observer is not None and observer.poll() is None
 except Exception:alive_after=False
 write_record(directory/'uncertain-exec-fence-result.json',{'container':container,'collector_pid':getattr(observer,'pid',None),'collector_alive_before':alive_before,'collector_alive_after':alive_after,'capture_credit':False,'state':'container-absent'})
 if not alive_before or not alive_after:raise RuntimeError('uncertain exec collector continuity unproven; preserve unsealed evidence')

def attempt(container,stage,db,slot,isolation,cutover_sha,lease_token,aid):
 baseline=verify_transfer(container)
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('input identity changed during ownership')
 if any(shutil.disk_usage(path).free<minimum for path,minimum in CONFIG['storage_floors'].items()):raise RuntimeError('storage floor')
 directory=ROOT/'attempts'/HOST/aid;directory.mkdir(parents=True,exist_ok=False)
 stage_session=stage/aid;stage_session.mkdir();raw=directory/'capture.pcap'
 spool_root=pathlib.Path('/tmp/qcsd-jsdelivr-buflo-parallel-spool-001');spool_root.mkdir(mode=0o700,exist_ok=True)
 if spool_root.is_symlink() or not spool_root.is_dir() or shutil.disk_usage(spool_root).free<5*1024**3:raise RuntimeError('unsafe or insufficient guest capture spool')
 spool_dir=spool_root/aid;spool_dir.mkdir(mode=0o700);spool_raw=spool_dir/'capture.pcap'
 lock=(directory/'attempt.lock').open('x')
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  network_policy=load_pinned_module(pathlib.Path(CONFIG['network_module']),CONFIG['network_module_sha256']);worker_ip=WORKER_NETWORKS.inspect_worker_container(WORKER_INDEX,container)
  pid=command(['docker','inspect','--format','{{.State.Pid}}',container]);log=(directory/'tcpdump.log').open('xb');observer=None
  code=None;error=None;run={};tuple_result={'pass':False};counts={'captured':None,'received':None,'dropped':None};exec_begun=False;retire=False
  try:
   observer=subprocess.Popen(['sudo','nsenter','-t',pid,'-n','tcpdump','-p','-B','16384','-i','eth0','-s','0','-U','-w',str(spool_raw),'udp port 443'],stdout=log,stderr=log,preexec_fn=cap_limit)
   for _ in range(100):
    if observer.poll() is not None:raise RuntimeError('tcpdump exited before client')
    if 'listening on eth0' in (directory/'tcpdump.log').read_text(errors='replace'):break
    time.sleep(.05)
   else:raise RuntimeError('tcpdump readiness timeout')
   seed=secrets.randbits(64)
   param_name='params/'+MODE+'.json';native_timeout=680 if MODE=='buflo' else 120
   argv=['/usr/local/bin/neqo-qcsd-client','run','--workload','/inputs/resources.json','--application-workload-source','/inputs/prepared-workload.json',
    '--chaff-manifest','/inputs/chaff-manifest.json','--profile','research-1200','--defense',MODE,'--'+MODE+'-parameters','/inputs/'+param_name,
    '--request-policy','half-duplex','--seed',str(seed),'--output-dir',f'/worker/{aid}/native','--max-response-bytes','16777216','--timeout-seconds',str(native_timeout)]
   with (directory/'invocation.json').open('x') as f:json.dump({'argv':argv,'container':container,'seed':seed},f);f.write('\n');f.flush();os.fsync(f.fileno())
   with (directory/'client.log').open('xb') as f:
    exec_begun=True
    code=subprocess.run(['docker','exec',container,*argv],stdout=f,stderr=subprocess.STDOUT,timeout=(740 if MODE=='buflo' else 180)).returncode
    exec_begun=False
    write_record(directory/'client-exit.json',{'process_exit_code':code,'source':'completed docker exec return code'})
    f.flush();os.fsync(f.fileno())
   time.sleep(2)
  except Exception as e:
   error=repr(e)
   if exec_begun:retire=True
  finally:
   if exec_begun:
    retire=True
    fence_uncertain_exec_before_collector(container,directory,observer)
   try:
    if observer and observer.poll() is None:
     subprocess.run(['sudo','kill','-INT',str(observer.pid)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
     observer.wait(timeout=15)
   except Exception as e:
    error=error or repr(e);retire=True
   if observer and observer.poll() is None:
    retire=True
   log.flush();os.fsync(log.fileno());log.close()
   if spool_raw.exists():
    chmod_capture_with_retry(spool_raw)
    if observer and observer.poll() is None:raise RuntimeError('observer remains alive; spool preserved')
    shutil.copyfile(spool_raw,raw)
    if sha(raw)!=sha(spool_raw):raise RuntimeError('spool copy mismatch; spool preserved')
  if retire:
   fence_container(container)
   if observer and observer.poll() is None:raise RuntimeError('observer remains alive; attempt remains unsealed')
  try:
   if not raw.is_file():raise ValueError('missing raw capture')
   with raw.open('rb') as f:os.fsync(f.fileno())
   sync_dir(directory);before=sha(raw);dest=raw
   src=stage_session/'native';dst=directory/'native'
   if not src.is_dir():raise ValueError('missing native output')
   for p in src.rglob('*'):
    if p.is_symlink() or (not p.is_dir() and not p.is_file()):raise ValueError('unsafe staged native output')
   shutil.copytree(src,dst)
   for p in dst.rglob('*'):
    if p.is_symlink() or (not p.is_dir() and not p.is_file()):raise ValueError('unsafe native output')
    if p.is_file():
     with p.open('rb') as f:os.fsync(f.fileno())
   for p in sorted([p for p in dst.rglob('*') if p.is_dir()],key=lambda x:len(x.parts),reverse=True):sync_dir(p)
   sync_dir(dst);sync_dir(directory)
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
  if not retire and WORKER_NETWORKS.inspect_worker_container(WORKER_INDEX,container)!=worker_ip:raise RuntimeError('worker network changed before finalization')
  if verify_transfer(container)!=baseline:raise RuntimeError('ownership or baseline changed before finalization')
  responses=run.get('responses') or [];passed=[x for x in responses if x.get('complete') is True and x.get('outcome')=='succeeded' and type(x.get('status')) is int and 200<=x['status']<300]
  roster=json.loads(stable_read(INPUTS/'resources.json',INPUT_SHA['resources.json'])).get('resources')
  roster_ok=(type(roster) is list and len(roster)==20 and all(type(x) is dict and type(x.get('id')) is int and type(x.get('url')) is str for x in roster) and {x['id'] for x in roster}==set(range(20)) and {(x.get('resource_id'),x.get('url')) for x in passed}=={(x['id'],x['url']) for x in roster})
  cfg=run.get('resolved_configuration') or {};diag=run.get('defense_diagnostics') or {}
  cap_ok=(tuple_result.get('pass') is True and counts['captured'] is not None and counts['captured']>0 and counts['captured']==counts['received']==tuple_result.get('original_packets') and counts['dropped']==0 and type(tuple_result.get('native_rows')) is int and 0<tuple_result['native_rows']<=counts['captured'])
  clean=(code==0 and not error and cap_ok and defended_run_clean(run,HOST,roster,INPUT_SHA['resources.json'],INPUT_SHA['prepared-workload.json'],INPUT_SHA['chaff-manifest.json'],MODE,INPUT_SHA['params/'+MODE+'.json']))
  keys=[];collision=[]
  if clean:
   keys=tuple_keys(run)
   try:LEASES.reserve(db,MODE,slot,lease_token,aid,keys,set(baseline['reserved_native_tuples']))
   except ValueError as e:collision=[{'reason':str(e)}];clean=False;error='duplicate slot or native connection tuple'
  partial_keys=[]
  if not clean:
   if not cap_ok or tuple_result.get('foreign_packets_removed')!=0:raise RuntimeError('partial endpoint evidence requires review; preserve unsealed attempt')
   partial_keys=tuple_keys(run)
   if not partial_keys:raise RuntimeError('partial has no endpoint evidence; preserve unsealed attempt')
   collision=classify_collision(db,partial_keys,baseline['reserved_native_tuples'],bool(collision))
  files={}
  for p in sorted(directory.rglob('*')):
   if p.is_file() and p.name not in ('FINAL.json','attempt.lock','.FINAL.tmp'):files[str(p.relative_to(directory))]={'sha256':sha(p),'size':p.stat().st_size}
  previous=[]
  for p in (ROOT/'attempts'/HOST).glob('*/FINAL.json'):
   old_bytes=stable_read(p);old=json.loads(old_bytes)
   if old.get('slot')==slot and old.get('status')!='success':previous.append({'attempt_id':old['attempt_id'],'final_sha256':hashlib.sha256(old_bytes).hexdigest()})
  final={'schema_version':1,'hostname':HOST,'attempt_id':aid,'slot':slot,'purpose':'production','defense':MODE,
   'status':'success' if clean else 'partial','successful_responses':len(passed),'required_responses':20,
   'process_exit_code':code,'tail_warning':run.get('error') or error,'native_client_sha256':CLIENT_SHA,'image_id':IMAGE,
   'input_sha256':INPUT_SHA,'driver_sha256':sha(pathlib.Path(__file__)),'owner_sha256':sha(pathlib.Path(__file__)),
   'coverage_sha256':CONFIG['coverage_sha256'],'history_sha256':CONFIG['history_sha256'],'note_sha256':CONFIG['note_sha256'],
   'guest_spool_path':str(spool_raw),'worker_start_delay_requested_us':32000 if WORKER_INDEX==1 else 0,'ownership_sha256':CONFIG_SHA,'domain_schedule':'parallel-authorized-20261123','dispatch_variation_sha256':VARIATION_SHA,'prior_partial_audit_sha256s':[x[2] for x in PARTIALS],'tuple_verifier_sha256':MODULE_SHA,'network_id':WORKER_NETWORKS.worker_spec(WORKER_INDEX)['id'],'network_subnet':WORKER_NETWORKS.worker_spec(WORKER_INDEX)['subnet'],'network_worker_ip':worker_ip,'network_manifest_sha256':CONFIG['network_manifest_sha256'],'worker_network_manifest_sha256':CONFIG['worker_network_manifest_sha256'],'prior_config_sha256':CONFIG['prior_config_sha256'],
   'capture_packets_reported':counts['captured'],'capture_filter_received':counts['received'],'capture_kernel_dropped':counts['dropped'],
   'pcap_packets':tuple_result.get('original_packets'),'native_packet_rows':tuple_result.get('native_rows'),'packet_count_screen_passed':cap_ok,
   'tuple_packet_screen':tuple_result,'clean_pcap':'capture-isolated.pcap' if tuple_result.get('pass') else None,
   'native_tuple_keys':keys,'automatic_partial_exclusion':bool(not clean and not collision),'observed_partial_tuple_keys':partial_keys,'tuple_collisions':collision,'prior_nonclean_attempts':previous,
   'source_role':'five-defense-recapture-local-20261123','mode_evidence':'native/run.json','files':files}
  if verify_transfer(container)!=baseline:raise RuntimeError('ownership changed before FINAL publication')
  finalsha=store_final(directory,final)
  if clean:
   LEASES.commit(db,MODE,slot,lease_token,aid,finalsha)
  elif not collision:
   reserve_observed_partial(db,mode=MODE,slot=slot,attempt=aid,final_sha=finalsha,keys=partial_keys,baseline=baseline['reserved_native_tuples'])
   check_auto_partial(db,final,finalsha)
  else:
   fence_container(container);retire=True
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

def validate_parallel_scope(host,root,inputs,note):
 domain_root=pathlib.Path('/mnt/recapture16k/five-defense-recapture-20261123-001')/host
 if host!='cdn.jsdelivr.net' or root!=domain_root/'modes/buflo' or inputs!=domain_root/'buflo-half-duplex-inputs-001' or note!=domain_root/'inputs/replacement-note.json':raise ValueError('parallel scope mismatch')

def validate_parallel_config(current,prior):
 allowed={'prior_config','prior_config_sha256','leases_module','leases_module_sha256','workers','worker_network_module','worker_network_module_sha256','worker_network_manifest','worker_network_manifest_sha256','recovery_module','recovery_module_sha256'}
 if set(current)!=set(prior)|allowed:raise ValueError('unexpected parallel config fields')
 for key,value in prior.items():
  if key!='owner_sha256' and current.get(key)!=value:raise ValueError('parallel config changed prior field '+key)

def verify_existing_worker_rows(module,db):
 # The previous generation's immutable owner/config and network manifest are
 # accepted only for exact old-subnet rows; new captures require this config.
 old_owner='89d3e59716fcc7f3d153e0a7a33266abc8d95cc67719846dc73a3ecab1e8b37b'
 old_config='1f5281e6363e977d978f810d0a045a70be64f60b284b65af06e69a65ab135670'
 old_manifest_sha='fefbd4f41f7d143a85f8ddcab8e005fcbf113c63c2bafa3aa17b4a9a04e16e42'
 old_path=pathlib.Path('/mnt/recapture16k/isolated-native-fixes-20261123/jsdelivr-buflo-parallel-plan-001/jsdelivr-worker-network-manifest-001.json')
 old=json.loads(stable_read(old_path,old_manifest_sha))
 specs=[(WORKER_NETWORKS.worker_spec(i),CONFIG['owner_sha256'],CONFIG_SHA,CONFIG['worker_network_manifest_sha256']) for i in range(CONFIG['workers'])]
 for i,subnet in [(0,'172.29.150.0/24'),(1,'172.29.151.0/24')]:
  spec=old['networks'][str(i)]
  if spec.get('index')!=i or spec.get('subnet')!=subnet:raise ValueError('old worker manifest changed')
  specs.append((spec,old_owner,old_config,old_manifest_sha))
 networks=[ipaddress.ip_network(x[0]['subnet']) for x in specs]
 if any(a.overlaps(b) for ix,a in enumerate(networks) for b in networks[ix+1:]):raise ValueError('worker networks overlap')
 other=[]
 for key,mode,aid,slot,digest,state in db.execute('select k,mode,attempt,slot,final_sha,state from tuples').fetchall():
  value=json.loads(key)
  if not isinstance(value,list) or len(value)!=5 or value[0]!='udp':raise ValueError('invalid ledger tuple')
  matches=[i for i,net in enumerate(networks) if ipaddress.ip_address(value[1]) in net]
  if not matches:other.append(key);continue
  if len(matches)!=1 or mode!='buflo' or state not in ('committed','excluded') or not isinstance(digest,str):raise ValueError('unattributed worker-subnet tuple')
  spec,owner,config,manifest=specs[matches[0]]
  record=json.loads(stable_read(ROOT/'attempts'/HOST/aid/'FINAL.json',digest))
  if record.get('attempt_id')!=aid or record.get('slot')!=slot or record.get('defense')!=mode or (record.get('owner_sha256'),record.get('ownership_sha256'))!=(owner,config) or record.get('worker_network_manifest_sha256')!=manifest or record.get('network_id')!=spec['id'] or record.get('network_subnet')!=spec['subnet']:raise ValueError('worker-subnet FINAL attribution changed')
  if state=='committed':
   if record.get('status')!='success' or key not in record.get('native_tuple_keys',[]) or db.execute('select attempt,final_sha,state from sessions where mode=? and slot=?',(mode,slot)).fetchone()!=(aid,digest,'committed'):raise ValueError('worker-subnet committed session changed')
  else:
   keys=record.get('observed_partial_tuple_keys')
   if record.get('status')!='partial' or record.get('automatic_partial_exclusion') is not True or record.get('packet_count_screen_passed') is not True or not isinstance(keys,list) or not keys or key not in keys or db.execute('select 1 from sessions where attempt=?',(aid,)).fetchone():raise ValueError('worker-subnet excluded partial changed')
   actual=[x[0] for x in db.execute('select k from tuples where mode=? and attempt=? and slot=? and final_sha=? and state=?',(mode,aid,slot,digest,'excluded'))]
   if len(keys)!=len(set(keys)) or set(actual)!=set(keys):raise ValueError('excluded partial tuple set changed')
 module.verify_ledger_disjoint(other)

def verify_parallel_journals(root):
 path=root/'parallel-journals'
 if not path.exists():return
 if path.is_symlink() or not path.is_dir():raise RuntimeError('unsafe parallel journal root')
 for worker_dir in path.iterdir():
  if worker_dir.is_symlink() or not worker_dir.is_dir():raise RuntimeError('unsafe parallel worker journal')
  for entry in worker_dir.iterdir():
   if entry.is_symlink() or not entry.is_dir():raise RuntimeError('unsafe parallel create journal')
   for name in ('INTENT.json','RESULT.json','RESOLVED.json'):
    if (entry/name).is_symlink() or not (entry/name).is_file():raise RuntimeError('unresolved parallel creation journal')

def worker(index,once,stopping,events=None,generation=None):
 global LABEL,CREATE_JOURNAL,WORKER_INDEX
 WORKER_INDEX=index
 token=secrets.token_hex(16);LABEL='qcsd-five-recapture-buflo-'+HOST+'-parallel-'+token
 if events is not None:events.put({'event':'started','index':index,'generation':generation,'worker_token':token,'label':LABEL})
 CREATE_JOURNAL=ROOT/'parallel-journals'/token;CREATE_JOURNAL.mkdir(parents=True,exist_ok=False);sync_dir(CREATE_JOURNAL.parent)
 db=sqlite3.connect(TUPLE_DB,timeout=30,isolation_level=None);db.execute('PRAGMA synchronous=FULL');db.execute('PRAGMA busy_timeout=30000')
 stage=ROOT/('worker-stage-parallel-'+token);stage.mkdir();sync_dir(ROOT);container=None
 try:
  container=start_container(stage)
  if index in (1,2):time.sleep(.032*index)  # start stagger only; native defense phase is measured
  while not stopping.is_set():
   aid=secrets.token_hex(16);lease_token=secrets.token_hex(16);slot=LEASES.claim(db,MODE,lease_token,aid)
   if slot is None:
    if events is not None:events.put({'event':'exhausted','index':index,'generation':generation})
    break
   if events is not None:events.put({'event':'claimed','index':index,'generation':generation,'slot':slot,'token':lease_token,'attempt':aid})
   status,screen,retired=attempt(container,stage,db,slot,ISOLATION,CONFIG['history_sha256'],lease_token,aid)
   if retired:container=None
   if events is not None:events.put({'event':status,'index':index,'generation':generation,'slot':slot,'token':lease_token,'attempt':aid})
   if status!='success':
    print(json.dumps({'worker':index,'slot':slot,'status':'partial-lease-retained'}),flush=True);break
   if once:break
   if container is None:container=start_container(stage)
 finally:
  if container:fence_container(container)
  db.close()

def verify_recovery_journals():
 path=ROOT/'internal-worker-recovery-journals'
 if not path.exists():return
 if path.is_symlink() or not path.is_dir():raise RuntimeError('unsafe recovery journal root')
 for entry in path.iterdir():
  if entry.is_symlink() or not entry.is_dir():raise RuntimeError('unsafe recovery journal')
  for name in ('INTENT.json','RESULT.json'):
   if (entry/name).is_symlink() or not (entry/name).is_file():raise RuntimeError('unresolved worker recovery journal')
  intent=json.loads(stable_read(entry/'INTENT.json'));result=json.loads(stable_read(entry/'RESULT.json'));item=intent.get('item') or {};intent_sha=sha(entry/'INTENT.json')
  if intent.get('kind')!='internal-worker-recovery' or intent.get('capture_credit') is not False or result.get('capture_credit') is not False or result.get('intent_sha256')!=intent_sha or result.get('worker')!=intent.get('worker') or result.get('slot')!=item.get('slot') or result.get('attempt_id')!=item.get('attempt_id'):raise RuntimeError('worker recovery receipt mismatch')
  db=sqlite3.connect('file:'+str(TUPLE_DB)+'?mode=ro',uri=True,timeout=30)
  try:row=db.execute('select mode,slot,token,attempt,prior_state,audit_path,audit_sha256 from slot_lease_reconciliations where mode=? and slot=? and token=?',(MODE,item.get('slot'),item.get('token'))).fetchone()
  finally:db.close()
  if row!=(MODE,item.get('slot'),item.get('token'),item.get('attempt_id'),'running',str((entry/'INTENT.json').resolve()),intent_sha):raise RuntimeError('worker recovery ledger receipt mismatch')

def reconcile_one_failed_worker(index,state,recovery):
 token=state.get('worker_token');label=state.get('label');claim=state.get('claim')
 if not isinstance(token,str) or not re.fullmatch(r'[0-9a-f]{32}',token) or label!='qcsd-five-recapture-buflo-'+HOST+'-parallel-'+token or not isinstance(claim,tuple) or len(claim)!=3:raise RuntimeError('worker identity incomplete')
 WORKER_NETWORKS.verify_worker_network(index,None)
 if command(['docker','ps','-aq','--filter','label=qcsd.owner='+label]):raise RuntimeError('failed worker still exists')
 journal=ROOT/'parallel-journals'/token
 if journal.is_symlink() or not journal.is_dir():raise RuntimeError('worker journal missing')
 for entry in journal.iterdir():
  if entry.is_symlink() or not entry.is_dir():raise RuntimeError('unsafe worker journal')
  for name in ('INTENT.json','RESULT.json','RESOLVED.json'):
   if (entry/name).is_symlink() or not (entry/name).is_file():raise RuntimeError('unresolved worker creation')
 slot,lease_token,aid=claim;db=sqlite3.connect(TUPLE_DB,timeout=30,isolation_level=None);db.execute('PRAGMA synchronous=FULL');db.execute('PRAGMA busy_timeout=30000');item=None
 try:
  row=db.execute("select mode,slot,token,attempt,state from slot_leases where mode=? and slot=?",(MODE,slot)).fetchone()
  if row!=(MODE,slot,lease_token,aid,'running'):raise RuntimeError('failed worker lease changed')
  item=recovery.partial_candidate(db,CONFIG,row)
  if item['attempt_id']!=aid or item['slot']!=slot:raise RuntimeError('partial attribution changed')
  directory=ROOT/'attempts'/HOST/aid;final=json.loads(stable_read(directory/'FINAL.json',item['final_sha256']));invocation=json.loads(stable_read(directory/'invocation.json',final['files']['invocation.json']['sha256']));spec=WORKER_NETWORKS.worker_spec(index)
  if final.get('network_id')!=spec['id'] or final.get('network_subnet')!=spec['subnet']:raise RuntimeError('failed partial worker network differs')
  matches=[]
  for entry in journal.iterdir():
   result=json.loads(stable_read(entry/'RESULT.json'));resolved=json.loads(stable_read(entry/'RESOLVED.json'))
   if result.get('container')==invocation.get('container') and resolved.get('container')==invocation.get('container'):matches.append(resolved)
  if len(matches)!=1 or matches[0].get('requested_ip')!=final.get('network_worker_ip'):raise RuntimeError('failed partial container journal differs')
  path=ROOT/'internal-worker-recovery-journals'/secrets.token_hex(16);path.mkdir(parents=True,exist_ok=False);sync_dir(path.parent)
  intent=path/'INTENT.json';recovery.write_new(intent,{'kind':'internal-worker-recovery','worker':index,'worker_token':token,'capture_credit':False,'item':{k:v for k,v in item.items() if k!='_lock'}});intent_sha=recovery.sha_file(intent)
  vals=recovery.apply_release(db,[item],intent.resolve(),intent_sha)
  recovery.write_new(path/'RESULT.json',{'capture_credit':False,'intent_sha256':intent_sha,'worker':index,'slot':slot,'attempt_id':aid,'sessions_before_after':vals[:2],'tuples_before_after':vals[2:]})
  print(json.dumps({'event':'worker-lease-reconciled','worker':index,'slot':slot,'attempt':aid,'receipt':str(path/'RESULT.json')}),flush=True)
 finally:
  if item is not None:item['_lock'].close()
  db.close()

WORKER_RETRY_DELAY_SECONDS=10
MAX_WORKER_RECOVERY_FAILURES=10

def supervise_workers(ctx,stopping,events,once,recovery):
 import queue
 workers={};states={};failures={i:0 for i in range(CONFIG['workers'])};retry_due={};blocked=set();global_block=[False]
 def quarantine(index,reason):
  if index is None:global_block[0]=True;retry_due.clear()
  else:blocked.add(index);retry_due.pop(index,None)
  print(json.dumps({'event':'worker-event-quarantined','worker':index,'reason':reason}),flush=True)
 def spawn(index):
  generation=secrets.token_hex(16);states[index]={'generation':generation};child=ctx.Process(target=worker,args=(index,once,stopping,events,generation));child.start();workers[index]=child
  print(json.dumps({'event':'worker-spawned','worker':index,'pid':child.pid,'generation':generation}),flush=True)
 def accept(message):
  if not isinstance(message,dict) or type(message.get('index')) is not int or message.get('index') not in states:
   quarantine(None,'malformed or unattributed event');return
  index=message['index'];state=states[index]
  if message.get('generation')!=state['generation']:
   quarantine(index,'stale worker generation');return
  if index in blocked:return
  try:
   kind=message.get('event')
   if kind=='started':
    token=message['worker_token'];label=message['label']
    if not isinstance(token,str) or not re.fullmatch(r'[0-9a-f]{32}',token) or label!='qcsd-five-recapture-buflo-'+HOST+'-parallel-'+token or state.get('worker_token') is not None:raise ValueError('invalid started event')
    state.update(worker_token=token,label=label)
   elif kind=='claimed':
    slot,token,attempt=message['slot'],message['token'],message['attempt']
    if state.get('worker_token') is None or type(slot) is not int or not 1<=slot<=400 or not isinstance(token,str) or not re.fullmatch(r'[0-9a-f]{32}',token) or not isinstance(attempt,str) or not re.fullmatch(r'[0-9a-f]{32}',attempt) or (state.get('claim') is not None and state.get('outcome')!='success'):raise ValueError('invalid claim event')
    state.update(claim=(slot,token,attempt),outcome=None)
   elif kind in ('success','partial'):
    if state.get('claim')!=(message['slot'],message['token'],message['attempt']) or state.get('outcome') is not None:raise ValueError('outcome claim mismatch')
    state['outcome']=kind
    if kind=='success':failures[index]=0
   elif kind=='exhausted':
    if state.get('claim') is not None and state.get('outcome')!='success':raise ValueError('exhausted with unresolved claim')
    state['outcome']='exhausted'
   else:raise ValueError('unknown worker event')
  except (KeyError,TypeError,ValueError) as exc:quarantine(index,repr(exc))
 try:
  for i in range(CONFIG['workers']):spawn(i)
  while workers or retry_due:
   try:accept(events.get(timeout=.5))
   except queue.Empty:pass
   except Exception as exc:quarantine(None,'event queue: '+repr(exc));time.sleep(.5)
   for index,child in list(workers.items()):
    if child.is_alive():continue
    child.join();del workers[index]
    while True:
     try:accept(events.get_nowait())
     except queue.Empty:break
     except Exception as exc:quarantine(None,'event queue drain: '+repr(exc));break
    state=states[index]
    if stopping.is_set() or once or global_block[0] or index in blocked:continue
    if child.exitcode!=0 or state.get('outcome') not in ('partial','exhausted'):
     quarantine(index,'unsafe exit or missing claim event');continue
    if state['outcome']=='exhausted':continue
    try:reconcile_one_failed_worker(index,state,recovery)
    except Exception as exc:quarantine(index,'recovery: '+repr(exc));continue
    failures[index]+=1
    if failures[index]>MAX_WORKER_RECOVERY_FAILURES:
     quarantine(index,'recovery failure bound reached');continue
    retry_due[index]=time.monotonic()+WORKER_RETRY_DELAY_SECONDS
   if stopping.is_set() or global_block[0]:retry_due.clear()
   for index,due in list(retry_due.items()):
    if index not in blocked and time.monotonic()>=due:del retry_due[index];spawn(index)
 finally:
  # Never terminate a surviving child on supervisor errors. The parent retains
  # the inherited mode lock until every started child finishes its own fence.
  retry_due.clear()
  for child in workers.values():child.join()
 print(json.dumps({'mode':MODE,'workers':CONFIG['workers'],'status':'workers-exited'}),flush=True)


def main():
 import multiprocessing
 global CONFIG_PATH,CONFIG_SHA,CONFIG,HISTORY,ROOT,HOST,INPUTS,CLIENT,MODEL,MODULE,IMAGE,MODEL_SHA,CLIENT_SHA,MODULE_SHA,AUDIT,AUDIT_SHA,INPUT_SHA,STOP_FREE,TUPLE_DB,CREATE_JOURNAL,LABEL,NOTE,LEDGER,MODE,LEASES,ISOLATION,WORKER_INDEX,WORKER_NETWORKS
 p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--config-sha',required=True);p.add_argument('--once',action='store_true');args=p.parse_args()
 CONFIG_PATH=pathlib.Path(args.config);CONFIG_SHA=args.config_sha;CONFIG=json.loads(stable_read(CONFIG_PATH,CONFIG_SHA))
 MODE=CONFIG['mode'];HOST=CONFIG['hostname'];ROOT=pathlib.Path(CONFIG['root']);INPUTS=pathlib.Path(CONFIG['inputs']);HISTORY=pathlib.Path(CONFIG['history']);NOTE=pathlib.Path(CONFIG['note'])
 CLIENT=pathlib.Path(CONFIG['client']);MODEL=pathlib.Path(CONFIG['model']);MODULE=pathlib.Path(CONFIG['tuple_module']);IMAGE=CONFIG['image'];MODEL_SHA=CONFIG['model_sha256'];CLIENT_SHA=CONFIG['client_sha256'];MODULE_SHA=CONFIG['tuple_module_sha256'];INPUT_SHA=CONFIG['input_sha256']
 STOP_FREE=30*1024**3;TUPLE_DB=ROOT.parent.parent/'shared-ledger-v2.sqlite3';CREATE_JOURNAL=ROOT/'creation-journal';LABEL='qcsd-five-recapture-'+MODE+'-'+HOST
 domain_root=pathlib.Path('/mnt/recapture16k/five-defense-recapture-20261123-001')/HOST
 if MODE!='buflo':raise ValueError('wrong mode')
 validate_parallel_scope(HOST,ROOT,INPUTS,NOTE)
 if CONFIG['exclusive_fence_locks']!=[] or ROOT.resolve()!=ROOT or INPUTS.resolve()!=INPUTS:raise ValueError('unsafe scope')
 if CONFIG['storage_floors'].get(str(ROOT),0)<8*1024**3 or type(CONFIG.get('workers')) is not int or not 1<=CONFIG['workers']<=3:raise ValueError('unsafe limits')
 if sha(pathlib.Path(CONFIG['prior_config']))!=CONFIG['prior_config_sha256'] or CONFIG['prior_config_sha256']!='d083d80f297ec3b13fef4299778fa39e16b7a5ebcd59df4b8bd54aa280631414':raise ValueError('prior owner config changed')
 validate_parallel_config(CONFIG,json.loads(stable_read(pathlib.Path(CONFIG['prior_config']),CONFIG['prior_config_sha256'])))
 lock=(ROOT/'production-owner.lock').open('a+');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 WORKER_INDEX=None
 module=load_pinned_module(pathlib.Path(CONFIG['worker_network_module']),CONFIG['worker_network_module_sha256'])
 manifest=json.loads(stable_read(pathlib.Path(CONFIG['worker_network_manifest']),CONFIG['worker_network_manifest_sha256']))
 WORKER_NETWORKS=module.WorkerNetworks(manifest,CONFIG['history_sha256'])
 history=json.loads(stable_read(HISTORY,CONFIG['history_sha256']))
 for index in range(CONFIG['workers']):
  WORKER_NETWORKS.verify_worker_network(index,None);module.verify_history_disjoint(history,WORKER_NETWORKS.worker_spec(index)['subnet'])
 baseline=verify_transfer()
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('capture input identity changed')
 if command(['docker','image','inspect',IMAGE,'--format','{{.Id}}'])!=IMAGE:raise ValueError('image identity changed')
 reconcile_creation_journal();verify_parallel_journals(ROOT)
 if command(['docker','ps','-aq','--filter','label=qcsd.owner='+LABEL]) or command(['docker','ps','-aq','--filter','label=qcsd.parallel-scope=five-recapture-buflo-cdn.jsdelivr.net']):raise RuntimeError('previous worker still present')
 # A worker of this version always retains the inherited supervisor lock.  A
 # prior non-complete lease or prior parallel journal is deliberately a manual
 # reconciliation condition, never automatically recycled after a crash.
 ISOLATION=load_pinned_module(MODULE,MODULE_SHA);db=initialize_ledger(baseline,CONFIG['history_sha256'])
 verify_existing_worker_rows(module,db)
 LEASES=load_pinned_module(pathlib.Path(CONFIG['leases_module']),CONFIG['leases_module_sha256']);LEASES.initialize(db)
 if db.execute("select 1 from slot_leases where mode=? and state!='complete' limit 1",(MODE,)).fetchone():raise RuntimeError('unfinished parallel lease requires reconciliation')
 db.close();ctx=multiprocessing.get_context('fork');stopping=ctx.Event();events=ctx.Queue()
 recovery=load_pinned_module(pathlib.Path(CONFIG['recovery_module']),CONFIG['recovery_module_sha256'])
 recovery.ROOT=ROOT;recovery.DOMAIN=HOST;recovery.MODE=MODE;recovery.DB=TUPLE_DB;recovery.OWNER=pathlib.Path(__file__).name;recovery.OWNER_CONFIG_SHA=CONFIG_SHA
 verify_recovery_journals()
 signal.signal(signal.SIGTERM,lambda *_:stopping.set());signal.signal(signal.SIGINT,lambda *_:stopping.set())
 supervise_workers(ctx,stopping,events,args.once,recovery)

if __name__=='__main__':main()
