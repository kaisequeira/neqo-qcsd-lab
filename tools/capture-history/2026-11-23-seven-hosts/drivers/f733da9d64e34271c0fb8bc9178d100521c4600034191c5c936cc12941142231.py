#!/usr/bin/env python3
"""Isolated Clarín BuFLO or CS-BuFLO capture owner, gated by verified 20k local coverage."""
import argparse,csv,fcntl,hashlib,importlib.util,ipaddress,json,os,pathlib,re,resource,secrets,shutil,signal,sqlite3,subprocess,threading,time
os.umask(0o077)
OLD_CONFIG_SHA='64ce40ad1975e8cad138033c6f3e8154e0704f22281f1bdcbed6c138b6b5bb2b'
QUAL_SHA='30d6f39c17cfc173bf4443f452001b417fa27a8060512b823e81547c1d757312'
CHAFF_SHA='faffa45eda15f7f1bc61e435d0ce7cdc4268a2feb74dfd69244cfbd18ad57499'
SLOW_PARAM_SHA='c09f9222bd041a34a292d87c446cb58a1f36e97c5d7bca5b457b837456aefd5b'
OLD_PARAM_SHA='e46036e50bcdef0f10b6711e8a730f9a452e56728da3f1f19288fcfb177839a7'
PARTIALS=(('4ec211e1b7975beff95194b135b93a08','839186988373a1299a9cfd058789660ca00df293fca5f82b866cd6d0b9d33cb5','17b13172b95da9fffec97d235a30d32819fb89fb2337f2e643a4d493e5d64269','["udp","172.17.0.5",48939,"104.18.7.141",443]'),('94e7b27bc2a476ad0f52c6a4c47cd105','5d2f243103b4ed3a84ea35f86216bcc5bcdf09169bde7062f8fed8b01908dabc','6abbf78f4f97235fb38ff0435c3bf86cd97d2297d1f0e5d97c546ad4e71754f5','["udp","172.17.0.5",59720,"104.18.7.141",443]'),('f149330397ac6fda346204e5ca2af36c','73f564197b3ca5ac16253cc9ab4ec65254948da120e10abff2952ec03733a705','599709e61f6de34ad51446b922aaad81d4518dd206d87a75752b4b9e3fdf06f7','["udp","172.17.0.4",54619,"104.18.6.141",443]'),('da7d56dc6379123efad3ca47c0b68d01','56787a576d4d3ff0f09cc97844d6e262c6ee8e558d26856adc769e0db5208578','6058b9357907be8980149642f0a28825aaebe403fd96672047a3e535fc90fc89','["udp","172.17.0.2",34427,"104.18.7.141",443]'),('cb4afa4402230a730591d248304229a4','fadcab6fbb331d994e13119ec588090bf5de843baa8d0892aa0d34263a1bf205','e3d3145c1ea21775c55dca81682015b538f8a0441bdcdea6c126cdc81d9f1d38','["udp","172.17.0.6",46488,"104.18.7.141",443]'))
def validate_chaff_change(change,host,workload_sha):
 if (not isinstance(change,dict) or change.get('domain')!=host or change.get('defense')!='cs-buflo' or change.get('old_resource_id')!=19 or
     change.get('new_resource_id')!=2 or change.get('new_chaff_sha256')!=CHAFF_SHA or change.get('qualification_sha256')!=QUAL_SHA or
     change.get('application_workload_sha256')!=workload_sha or change.get('application_workload_unchanged') is not True):raise ValueError('chaff change note invalid')
def validate_schedule_change(original,slower,note,host,workload_sha):
 expected=dict(original);expected.update(initial_interval_us=8192,minimum_interval_us=8192,maximum_interval_us=65536)
 if slower!=expected or note.get('domain')!=host or note.get('defense')!='cs-buflo' or note.get('original_params_sha256')!=OLD_PARAM_SHA or note.get('new_params_sha256')!=SLOW_PARAM_SHA or note.get('application_workload_sha256')!=workload_sha or note.get('application_workload_unchanged') is not True:raise ValueError('invalid CS schedule change')
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
 if mode not in ('buflo','cs-buflo') or not isinstance(run,dict) or run.get('request_policy')!='half-duplex' or not isinstance(roster,list) or len(roster)!=20:return False
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
 return (sum(r.get('slot')==slot and r.get('status')!='success' and r.get('packet_count_screen_passed') is True for r in prior),
         sum(r.get('slot')==slot and r.get('status')!='success' and r.get('packet_count_screen_passed') is False for r in prior))
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

def verify_transfer():
 if sha(CONFIG_PATH)!=CONFIG_SHA or sha(HISTORY)!=CONFIG['history_sha256']:raise RuntimeError('ownership or history changed')
 if sha(pathlib.Path(__file__))!=CONFIG['owner_sha256']:raise RuntimeError('owner code changed')
 if sha(ROOT/'owner-config-001.json')!=OLD_CONFIG_SHA or CONFIG.get('ledger_config_sha256')!=OLD_CONFIG_SHA:raise ValueError('original ledger configuration changed')
 if INPUT_SHA.get('chaff-manifest.json')!=CHAFF_SHA:raise ValueError('new chaff is not the qualified manifest')
 if CONFIG.get('retry_policy')!={'max_slot_failures':50,'spacing_seconds':10,'max_capture_failures':3}:raise ValueError('bounded retry policy changed')
 if CONFIG.get('diagnostic_only') is not False:raise ValueError('production mode expected')
 proof=json.loads(stable_read(pathlib.Path(CONFIG['receive_diagnostic_final']),CONFIG['receive_diagnostic_sha256']))
 if proof.get('attempt_id')!='782697bdac4cc1e5863947477915ed7f' or proof.get('purpose')!='diagnostic-no-credit' or proof.get('capture_credit') is not False or proof.get('diagnostic_pass') is not True or proof.get('successful_responses')!=20 or proof.get('process_exit_code')!=0 or proof.get('receive_window_note_sha256')!=CONFIG['receive_window_note_sha256']:raise ValueError('receive window diagnostic not ready')
 window=json.loads(stable_read(pathlib.Path(CONFIG['receive_window_note']),CONFIG['receive_window_note_sha256']))
 if window.get('initial_max_stream_data')!=8192 or window.get('previous_initial_max_stream_data')!=16 or window.get('cs_live_chaff_header_progress') is not False or window.get('custom_config_sha256')!=INPUT_SHA['params/custom-receive.toml'] or window.get('application_workload_sha256')!=INPUT_SHA['resources.json'] or window.get('application_workload_unchanged') is not True:raise ValueError('receive window note invalid')
 change=json.loads(stable_read(pathlib.Path(CONFIG['chaff_change_note']),CONFIG['chaff_change_note_sha256']))
 validate_chaff_change(change,HOST,INPUT_SHA['resources.json'])
 original=json.loads(stable_read(ROOT.parent.parent/'inputs/params/cs-buflo.json',OLD_PARAM_SHA))
 slower=json.loads(stable_read(INPUTS/'params/cs-buflo.json',SLOW_PARAM_SHA))
 if INPUT_SHA.get('params/cs-buflo.json')!=SLOW_PARAM_SHA:raise ValueError('invalid CS schedule pin')
 schedule=json.loads(stable_read(pathlib.Path(CONFIG['schedule_change_note']),CONFIG['schedule_change_note_sha256']))
 validate_schedule_change(original,slower,schedule,HOST,INPUT_SHA['resources.json'])
 dispatch=json.loads(stable_read(pathlib.Path(CONFIG['dispatch_change_note']),CONFIG['dispatch_change_note_sha256']))
 if CONFIG.get('request_policy')!='half-duplex' or dispatch.get('request_policy')!='half-duplex' or dispatch.get('previous_request_policy')!='as-defined' or dispatch.get('domain')!=HOST or dispatch.get('defense')!=MODE or dispatch.get('application_workload_sha256')!=INPUT_SHA['resources.json'] or dispatch.get('application_workload_unchanged') is not True:raise ValueError('invalid dispatch policy note')
 fit=ROOT.parent.parent/'tamaraw-larger-chaff-fit-001';evidence=json.loads(stable_read(fit/'qualification-evidence.json',QUAL_SHA))
 if evidence.get('status')!='THREE_INDEPENDENT_40_RESPONSE_EPOCHS' or evidence.get('domain')!=HOST or evidence.get('resource_id')!=2 or evidence.get('prepared_sha256')!=INPUT_SHA['prepared-workload.json'] or len(evidence.get('epochs',[]))!=3:raise ValueError('chaff qualification changed')
 for n,epoch in enumerate(evidence['epochs']):
  path=fit/('epoch-'+str(n))/'qualification.json'
  if epoch.get('epoch')!=n or epoch.get('responses')!=40 or epoch.get('qualification_path')!=str(path):raise ValueError('invalid qualification epoch')
  report=json.loads(stable_read(path,epoch['sha256']))
  if report.get('passed') is not True or report.get('completion_status')!='complete' or report.get('total_requests')!=40 or len(report.get('requests',[]))!=40:raise ValueError('chaff qualification failed')
 for aid,finalsha,auditsha,key in PARTIALS:
  audit=json.loads(stable_read(ROOT/('partial-exclusion-'+aid+'.json'),auditsha))
  if audit.get('capture_credit') is not False or audit.get('attempt_id')!=aid or audit.get('final_sha256')!=finalsha or audit.get('native_tuple_keys')!=[key] or audit.get('raw_pcap_tuple_keys')!=[key] or sha(ROOT/'attempts'/HOST/aid/'FINAL.json')!=finalsha:raise ValueError('partial audit changed')
 zeroid='e4214649a90bc944c0e583e26e6a6fc9';zero_sha='d71929a1c67a56811f2bb354a160af597ad2a5708e0eb9c167cc8447777a55b7'
 zero=json.loads(stable_read(ROOT/('zero-traffic-'+zeroid+'-audit-001.json'),zero_sha));d=ROOT/'attempts'/HOST/zeroid
 if zero.get('attempt_id')!=zeroid or zero.get('capture_credit') is not False or zero.get('captured')!=0 or zero.get('received')!=0 or zero.get('dropped')!=0 or zero.get('native_endpoints')!=[] or zero.get('native_responses')!=0 or zero.get('pcap_bytes')!=24:raise ValueError('zero traffic audit invalid')
 for name,digest in zero.get('files_sha256',{}).items():stable_read(d/name,digest)
 if set(zero.get('files_sha256',{}))!={'FINAL.json','capture.pcap','native/run.json','tcpdump.log'}:raise ValueError('zero traffic evidence incomplete')
 if sha(NOTE)!=CONFIG['note_sha256']:raise RuntimeError('workload note changed')
 note=json.loads(stable_read(NOTE,CONFIG['note_sha256']))
 if note.get('domain')!=HOST or note.get('defense')!='wtf-pad' or note.get('workload_sha256')!=INPUT_SHA['resources.json']:raise ValueError('fixed workload note changed')
 coverage=json.loads(stable_read(pathlib.Path(CONFIG['coverage_receipt']),CONFIG['coverage_sha256']))
 if coverage.get('kind')!='wtfpad-local-50-domain-coverage' or coverage.get('count')!=20000 or coverage.get('domains')!=50 or coverage.get('sessions_per_domain')!=400 or coverage.get('drive_upload_required') is not False or coverage.get('global_original_roster_sha256')!='f28e48a4c149ced9cab456dacaaf064cb256db4cfbfca62bbed684e21bb20f38':raise ValueError('local 20k coverage proof invalid')
 history=json.loads(stable_read(HISTORY,CONFIG['history_sha256']))
 if history.get('kind')!='clarin-wtfpad-prior-tuple-history' or history.get('domain')!=HOST or len(history.get('committed',[]))!=400:raise ValueError('prior tuple history invalid')
 entries=history['committed'];slots=[x.get('slot') for x in entries];keys=[k for x in entries for k in x.get('native_tuple_keys',[])]
 reserved=history.get('reserved_native_tuples')
 if sorted(slots)!=list(range(1,401)) or not isinstance(reserved,list) or not reserved or len(set(keys))!=len(keys) or len(set(reserved))!=len(reserved) or set(keys)&set(reserved):raise ValueError('prior tuple exclusions invalid')
 return {'entries':[], 'reserved_native_tuples':sorted(set(keys)|set(reserved))}

def verify_partial_exclusions(db):
 for aid,finalsha,auditsha,key in PARTIALS:
  if db.execute('SELECT mode,attempt,slot,final_sha,state FROM tuples WHERE k=?',(key,)).fetchone()!=('cs-buflo',aid,1,finalsha,'excluded'):raise ValueError('partial tuple exclusion changed')

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
 verify_partial_exclusions(db)
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
def start_container(stage):
 args=['docker','run','-d','--network','bridge','--label','qcsd.owner='+LABEL,
  '--label','qcsd.parallel-scope=five-recapture-cs-buflo-www.clarin.com','--mount',f'type=bind,src={INPUTS},dst=/inputs,readonly','--mount',f'type=bind,src={stage},dst=/worker',
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
 write_record(entry/'RESOLVED.json',{'container':cid,'reconciliation':'identified and handed to owner'})
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
def attempt(container,stage,db,slot,isolation,cutover_sha,lease_token,aid):
 baseline=verify_transfer()
 verify_partial_exclusions(db)
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('input identity changed during ownership')
 if any(shutil.disk_usage(path).free<minimum for path,minimum in CONFIG['storage_floors'].items()):raise RuntimeError('storage floor')
 directory=ROOT/'attempts'/HOST/aid;directory.mkdir(parents=True,exist_ok=False)
 stage_session=stage/aid;stage_session.mkdir();raw=directory/'capture.pcap'
 lock=(directory/'attempt.lock').open('x')
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  pid=command(['docker','inspect','--format','{{.State.Pid}}',container]);log=(directory/'tcpdump.log').open('xb');observer=None
  code=None;error=None;run={};tuple_result={'pass':False};counts={'captured':None,'received':None,'dropped':None};exec_begun=False;retire=False
  try:
   observer=subprocess.Popen(['sudo','nsenter','-t',pid,'-n','tcpdump','-p','-B','16384','-i','eth0','-s','0','-U','-w',str(raw),'udp port 443'],stdout=log,stderr=log,preexec_fn=cap_limit)
   for _ in range(100):
    if observer.poll() is not None:raise RuntimeError('tcpdump exited before client')
    if 'listening on eth0' in (directory/'tcpdump.log').read_text(errors='replace'):break
    time.sleep(.05)
   else:raise RuntimeError('tcpdump readiness timeout')
   seed=secrets.randbits(64)
   param_name='params/'+MODE+'.json';native_timeout=680 if MODE=='buflo' else 120
   argv=['/usr/local/bin/neqo-qcsd-client','run','--workload','/inputs/resources.json','--application-workload-source','/inputs/prepared-workload.json',
    '--chaff-manifest','/inputs/chaff-manifest.json','--config','/inputs/params/custom-receive.toml',
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
   try:
    if observer and observer.poll() is None:
     subprocess.run(['sudo','kill','-INT',str(observer.pid)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
     observer.wait(timeout=15)
   except Exception as e:
    error=error or repr(e);retire=True
   if observer and observer.poll() is None:
    retire=True
   log.flush();os.fsync(log.fileno());log.close()
   if raw.exists():chmod_capture_with_retry(raw)
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
  if verify_transfer()!=baseline:raise RuntimeError('ownership or baseline changed before finalization')
  responses=run.get('responses') or [];passed=[x for x in responses if x.get('complete') is True and x.get('outcome')=='succeeded' and type(x.get('status')) is int and 200<=x['status']<300]
  roster=json.loads(stable_read(INPUTS/'resources.json',INPUT_SHA['resources.json'])).get('resources')
  roster_ok=(type(roster) is list and len(roster)==20 and all(type(x) is dict and type(x.get('id')) is int and type(x.get('url')) is str for x in roster) and {x['id'] for x in roster}==set(range(20)) and {(x.get('resource_id'),x.get('url')) for x in passed}=={(x['id'],x['url']) for x in roster})
  cfg=run.get('resolved_configuration') or {};diag=run.get('defense_diagnostics') or {}
  cap_ok=(tuple_result.get('pass') is True and counts['captured'] is not None and counts['captured']>0 and counts['captured']==counts['received']==tuple_result.get('original_packets') and counts['dropped']==0 and type(tuple_result.get('native_rows')) is int and 0<tuple_result['native_rows']<=counts['captured'])
  clean=(code==0 and not error and cap_ok and defended_run_clean(run,HOST,roster,INPUT_SHA['resources.json'],INPUT_SHA['prepared-workload.json'],INPUT_SHA['chaff-manifest.json'],MODE,INPUT_SHA['params/'+MODE+'.json']))
  expected_cfg={'schema_version':2,'control_interval_us':5000,'initial_max_stream_data':8192,'automatic_receive_window':1048576,'max_chaff_streams':5,'low_watermark':1000000,'use_empty_resources':False,'max_stream_data_excess':1000,'max_udp_payload_size':1200,'drop_unsatisfied_events':False,'keep_alive_lead_time_us':100000,'tail_wait_us':0,'defense':{'kind':'cs_buflo','parameters':'/inputs/params/cs-buflo.json'}}
  actual_cfg=dict(cfg);live=actual_cfg.pop('cs_live_chaff_header_progress',False);clean=clean and live is False and actual_cfg==expected_cfg
  keys=[];collision=[]
  if clean:
   keys=tuple_keys(run)
   try:LEASES.reserve(db,MODE,slot,lease_token,aid,keys,set(baseline['reserved_native_tuples']))
   except ValueError as e:collision=[{'reason':str(e)}];clean=False;error='duplicate slot or native connection tuple'
  partial_keys=[]
  if not clean:
   if not cap_ok or tuple_result.get('foreign_packets_removed')!=0 or collision:raise RuntimeError('partial endpoint evidence requires review; preserve unsealed attempt')
   partial_keys=tuple_keys(run)
   if not partial_keys:raise RuntimeError('partial has no endpoint evidence; preserve unsealed attempt')
  files={}
  for p in sorted(directory.rglob('*')):
   if p.is_file() and p.name not in ('FINAL.json','attempt.lock','.FINAL.tmp'):files[str(p.relative_to(directory))]={'sha256':sha(p),'size':p.stat().st_size}
  previous=[]
  for p in (ROOT/'attempts'/HOST).glob('*/FINAL.json'):
   old_bytes=stable_read(p);old=json.loads(old_bytes)
   if old.get('slot')==slot and old.get('status')!='success':previous.append({'attempt_id':old['attempt_id'],'final_sha256':hashlib.sha256(old_bytes).hexdigest()})
  final={'schema_version':1,'hostname':HOST,'attempt_id':aid,'slot':slot,'purpose':'production','defense':MODE,
   'status':'success' if clean else 'partial','receive_diagnostic_sha256':CONFIG['receive_diagnostic_sha256'],'receive_window_note_sha256':CONFIG['receive_window_note_sha256'],'successful_responses':len(passed),'required_responses':20,
   'process_exit_code':code,'tail_warning':run.get('error') or error,'native_client_sha256':CLIENT_SHA,'image_id':IMAGE,
   'input_sha256':INPUT_SHA,'driver_sha256':sha(pathlib.Path(__file__)),'owner_sha256':sha(pathlib.Path(__file__)),
   'coverage_sha256':CONFIG['coverage_sha256'],'history_sha256':CONFIG['history_sha256'],'note_sha256':CONFIG['note_sha256'],
   'ownership_sha256':CONFIG_SHA,'tuple_verifier_sha256':MODULE_SHA,'chaff_qualification_sha256':QUAL_SHA,'chaff_change_note_sha256':CONFIG['chaff_change_note_sha256'],'schedule_change_note_sha256':CONFIG['schedule_change_note_sha256'],'request_policy':'half-duplex','retry_policy':CONFIG['retry_policy'],'dispatch_change_note_sha256':CONFIG['dispatch_change_note_sha256'],'prior_zero_traffic_audit_sha256':'d71929a1c67a56811f2bb354a160af597ad2a5708e0eb9c167cc8447777a55b7','prior_partial_audit_sha256s':[x[2] for x in PARTIALS],
   'capture_packets_reported':counts['captured'],'capture_filter_received':counts['received'],'capture_kernel_dropped':counts['dropped'],
   'pcap_packets':tuple_result.get('original_packets'),'native_packet_rows':tuple_result.get('native_rows'),'packet_count_screen_passed':cap_ok,
   'tuple_packet_screen':tuple_result,'clean_pcap':'capture-isolated.pcap' if tuple_result.get('pass') else None,
   'native_tuple_keys':keys,'automatic_partial_exclusion':not clean,'observed_partial_tuple_keys':partial_keys,'tuple_collisions':collision,'prior_nonclean_attempts':previous,
   'source_role':'five-defense-recapture-local-20261123','mode_evidence':'native/run.json','files':files}
  if verify_transfer()!=baseline:raise RuntimeError('ownership changed before FINAL publication')
  verify_partial_exclusions(db)
  finalsha=store_final(directory,final)
  if clean:
   LEASES.commit(db,MODE,slot,lease_token,aid,finalsha)
  else:
   reserve_observed_partial(db,mode=MODE,slot=slot,attempt=aid,final_sha=finalsha,keys=partial_keys,baseline=baseline['reserved_native_tuples'])
   check_auto_partial(db,final,finalsha)
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
 if host!='www.clarin.com' or root!=domain_root/'modes/cs-buflo-v3' or inputs!=domain_root/'cs-buflo-receive-window-inputs-001' or note!=domain_root/'inputs/replacement-note.json':raise ValueError('parallel scope mismatch')

def validate_parallel_config(current,prior):
 allowed={'prior_config','prior_config_sha256','leases_module','leases_module_sha256','workers'}
 if set(current)!=set(prior)|allowed:raise ValueError('unexpected parallel config fields')
 for key,value in prior.items():
  if key!='owner_sha256' and current.get(key)!=value:raise ValueError('parallel config changed prior field '+key)

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

def worker(index,once,stopping):
 global LABEL,CREATE_JOURNAL
 token=secrets.token_hex(16);LABEL='qcsd-five-recapture-cs-buflo-'+HOST+'-parallel-'+token
 CREATE_JOURNAL=ROOT/'parallel-journals'/token;CREATE_JOURNAL.mkdir(parents=True,exist_ok=False);sync_dir(CREATE_JOURNAL.parent)
 db=sqlite3.connect(TUPLE_DB,timeout=30,isolation_level=None);db.execute('PRAGMA synchronous=FULL');db.execute('PRAGMA busy_timeout=30000')
 stage=ROOT/('worker-stage-parallel-'+token);stage.mkdir();sync_dir(ROOT);container=None
 try:
  container=start_container(stage)
  while not stopping.is_set():
   aid=secrets.token_hex(16);lease_token=secrets.token_hex(16);slot=LEASES.claim(db,MODE,lease_token,aid)
   if slot is None:break
   status,screen,retired=attempt(container,stage,db,slot,ISOLATION,CONFIG['history_sha256'],lease_token,aid)
   if retired:container=None
   if status!='success':
    print(json.dumps({'worker':index,'slot':slot,'status':'partial-lease-retained'}),flush=True);break
   if once:break
   if container is None:container=start_container(stage)
 finally:
  if container:fence_container(container)
  db.close()

def main():
 import multiprocessing
 global CONFIG_PATH,CONFIG_SHA,CONFIG,HISTORY,ROOT,HOST,INPUTS,CLIENT,MODEL,MODULE,IMAGE,MODEL_SHA,CLIENT_SHA,MODULE_SHA,AUDIT,AUDIT_SHA,INPUT_SHA,STOP_FREE,TUPLE_DB,CREATE_JOURNAL,LABEL,NOTE,LEDGER,MODE,LEASES,ISOLATION
 p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--config-sha',required=True);p.add_argument('--once',action='store_true');args=p.parse_args()
 CONFIG_PATH=pathlib.Path(args.config);CONFIG_SHA=args.config_sha;CONFIG=json.loads(stable_read(CONFIG_PATH,CONFIG_SHA))
 MODE=CONFIG['mode'];HOST=CONFIG['hostname'];ROOT=pathlib.Path(CONFIG['root']);INPUTS=pathlib.Path(CONFIG['inputs']);HISTORY=pathlib.Path(CONFIG['history']);NOTE=pathlib.Path(CONFIG['note'])
 CLIENT=pathlib.Path(CONFIG['client']);MODEL=pathlib.Path(CONFIG['model']);MODULE=pathlib.Path(CONFIG['tuple_module']);IMAGE=CONFIG['image'];MODEL_SHA=CONFIG['model_sha256'];CLIENT_SHA=CONFIG['client_sha256'];MODULE_SHA=CONFIG['tuple_module_sha256'];INPUT_SHA=CONFIG['input_sha256']
 STOP_FREE=30*1024**3;TUPLE_DB=ROOT.parent.parent/'shared-ledger-v2.sqlite3';CREATE_JOURNAL=ROOT/'creation-journal';LABEL='qcsd-five-recapture-'+MODE+'-'+HOST
 domain_root=pathlib.Path('/mnt/recapture16k/five-defense-recapture-20261123-001')/HOST
 if MODE!='cs-buflo':raise ValueError('wrong mode')
 validate_parallel_scope(HOST,ROOT,INPUTS,NOTE)
 if CONFIG['exclusive_fence_locks']!=[] or ROOT.resolve()!=ROOT or INPUTS.resolve()!=INPUTS:raise ValueError('unsafe scope')
 if CONFIG['storage_floors'].get(str(ROOT),0)<8*1024**3 or type(CONFIG.get('workers')) is not int or not 1<=CONFIG['workers']<=4:raise ValueError('unsafe limits')
 if sha(pathlib.Path(CONFIG['prior_config']))!=CONFIG['prior_config_sha256'] or CONFIG['prior_config_sha256']!='0608e83bde66c94be39dda8ae2ff1a43e3b2977a2b324312a96fa9e3111ff580':raise ValueError('prior owner config changed')
 validate_parallel_config(CONFIG,json.loads(stable_read(pathlib.Path(CONFIG['prior_config']),CONFIG['prior_config_sha256'])))
 lock=(ROOT/'production-owner.lock').open('a+');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 baseline=verify_transfer()
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('capture input identity changed')
 if command(['docker','image','inspect',IMAGE,'--format','{{.Id}}'])!=IMAGE:raise ValueError('image identity changed')
 reconcile_creation_journal();verify_parallel_journals(ROOT)
 if command(['docker','ps','-aq','--filter','label=qcsd.owner='+LABEL]) or command(['docker','ps','-aq','--filter','label=qcsd.parallel-scope=five-recapture-cs-buflo-www.clarin.com']):raise RuntimeError('previous worker still present')
 # A worker of this version always retains the inherited supervisor lock.  A
 # prior non-complete lease or prior parallel journal is deliberately a manual
 # reconciliation condition, never automatically recycled after a crash.
 ISOLATION=load_pinned_module(MODULE,MODULE_SHA);db=initialize_ledger(baseline,CONFIG['history_sha256'])
 LEASES=load_pinned_module(pathlib.Path(CONFIG['leases_module']),CONFIG['leases_module_sha256']);LEASES.initialize(db)
 if db.execute("select 1 from slot_leases where mode=? and state!='complete' limit 1",(MODE,)).fetchone():raise RuntimeError('unfinished parallel lease requires reconciliation')
 db.close();workers=[];ctx=multiprocessing.get_context('fork');stopping=ctx.Event()
 signal.signal(signal.SIGTERM,lambda *_:stopping.set());signal.signal(signal.SIGINT,lambda *_:stopping.set())
 for i in range(CONFIG['workers']):
  child=ctx.Process(target=worker,args=(i,args.once,stopping));child.start();workers.append(child)
 for child in workers:child.join()
 if any(child.exitcode!=0 for child in workers):raise RuntimeError('parallel worker failed; preserve unresolved leases')
 print(json.dumps({'mode':MODE,'workers':len(workers),'status':'workers-exited'}),flush=True)
if __name__=='__main__':main()
