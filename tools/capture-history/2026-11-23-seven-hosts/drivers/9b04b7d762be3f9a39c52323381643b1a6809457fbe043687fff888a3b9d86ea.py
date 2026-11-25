#!/usr/bin/env python3
"""Isolated Clarín BuFLO or CS-BuFLO capture owner, gated by verified 20k local coverage."""
import argparse,csv,fcntl,hashlib,importlib.util,ipaddress,json,os,pathlib,re,resource,secrets,shutil,signal,sqlite3,subprocess,threading,time
os.umask(0o077)
UNSEALED='0d3a0dd4e5f229e398945603796e5733'
UNSEALED_AUDIT_SHA='89e4d257bf1ca8ac1b5b4abf5783f4492e3665569a78251b7350c66afe028ec2'
UNSEALED_RECEIPT_SHA='e6f3d2c68d5b001acebb0f8a776092a1f58fb54c62f9596e002d903200094b5b'
UNSEALED_KEYS=('["udp","172.17.0.2",57034,"104.18.7.141",443]','["udp","172.17.0.4",58064,"23.46.179.57",443]')
OLD_CONFIG_SHA='15c7166c1952d951823c956edf395f2b5593966a796199f8c46f3b793e8e46f9'
AUDIT_SHA='246cbaa43ade9480629e89dba790cb67db801f495ad5b1936600cc9f0271b7c4'
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

def verify_unsealed():
 d=ROOT/'attempts'/HOST/UNSEALED;audit=json.loads(stable_read(ROOT/('unsealed-failed-'+UNSEALED+'-audit-001.json'),UNSEALED_AUDIT_SHA));receipt=json.loads(stable_read(ROOT/'unsealed-exclusion-289-complete-001.json',UNSEALED_RECEIPT_SHA))
 if audit.get('kind')!='buflo-unsealed-failed-audit' or audit.get('attempt_id')!=UNSEALED or audit.get('slot')!=289 or audit.get('source_final_exists') is not False or audit.get('capture_credit') is not False or audit.get('native_tuple_keys')!=[UNSEALED_KEYS[0]] or audit.get('foreign_tuple_keys')!=[UNSEALED_KEYS[1]] or (d/'FINAL.json').exists():raise ValueError('unsealed audit changed')
 if receipt.get('kind')!='unsealed-exclusion-complete' or receipt.get('attempt_id')!=UNSEALED or receipt.get('slot')!=289 or receipt.get('audit_sha256')!=UNSEALED_AUDIT_SHA or receipt.get('tuples')!=list(UNSEALED_KEYS) or receipt.get('capture_credit') is not False:raise ValueError('unsealed receipt changed')
 expected=audit.get('files');actual={str(p.relative_to(d)) for p in d.rglob('*') if p.is_file() and p.name!='attempt.lock'}
 if not isinstance(expected,dict) or actual!=set(expected):raise ValueError('unsealed inventory changed')
 for name,meta in expected.items():
  p=d/name
  if p.is_symlink() or p.stat().st_size!=meta.get('size') or sha(p)!=meta.get('sha256'):raise ValueError('unsealed evidence changed')
def verify_unsealed_exclusions(db):
 for key in UNSEALED_KEYS:
  if db.execute('select mode,attempt,slot,final_sha,state from tuples where k=?',(key,)).fetchone()!=('buflo',UNSEALED,289,None,'excluded'):raise ValueError('unsealed tuple exclusion changed')

COLLISION_ATTEMPT='e37fc6eebaae9996171448d629603974'
COLLISION_FINAL='56c611ff8d5c1cfeb7cf0a9e47b6eff8caffbaed1259b4509c0b0edf3c567add'
COLLISION_AUDIT='8707466748514f88000b1f134c3fb59fd291537f43fe35b23c8e70f3afd27249'
COLLISION_KEY='["udp","172.17.0.2",55746,"104.18.6.141",443]'
def verify_historical_collision():
 d=ROOT/'attempts'/HOST/COLLISION_ATTEMPT
 a=json.loads(stable_read(ROOT/('partial-historical-collision-'+COLLISION_ATTEMPT+'-audit-001.json'),COLLISION_AUDIT))
 if a.get('kind')!='buflo-partial-historical-tuple-collision' or a.get('domain')!=HOST or a.get('attempt_id')!=COLLISION_ATTEMPT or a.get('slot')!=289 or a.get('final_sha256')!=COLLISION_FINAL or a.get('tuple')!=COLLISION_KEY or a.get('prior_history_sha256')!=CONFIG['history_sha256'] or a.get('prior_history_slot')!=5 or a.get('prior_history_attempt')!='5fd812d2f99f401637ce54c758c993be' or a.get('capture_credit') is not False:raise ValueError('historical collision audit changed')
 history=json.loads(stable_read(HISTORY,CONFIG['history_sha256']));matches=[x for x in history['committed'] if COLLISION_KEY in x.get('native_tuple_keys',[])]
 if len(matches)!=1 or matches[0].get('slot')!=5 or matches[0].get('attempt_id')!=a['prior_history_attempt']:raise ValueError('historical tuple fence changed')
 v=json.loads(stable_read(d/'FINAL.json',COLLISION_FINAL))
 if v.get('attempt_id')!=COLLISION_ATTEMPT or v.get('slot')!=289 or v.get('status')!='partial' or v.get('automatic_partial_exclusion') is not True or v.get('observed_partial_tuple_keys')!=[COLLISION_KEY]:raise ValueError('historical collision source changed')
 for name,meta in v['files'].items():
  q=d/name
  if q.is_symlink() or q.stat().st_size!=meta['size'] or sha(q)!=meta['sha256']:raise ValueError('historical collision evidence changed')
 if tuple_keys(json.loads(stable_read(d/'native/run.json',v['files']['native/run.json']['sha256'])))!=[COLLISION_KEY]:raise ValueError('historical collision native tuple changed')
 return v
COMMITTED_COLLISION_ATTEMPT='aa8edb7928796c6632dabe0ac47f4570'
COMMITTED_COLLISION_FINAL='f0268062699c9d9503113e04c9a8f70327df82d04e4ccacef5f0d40b162ad051'
COMMITTED_COLLISION_AUDIT='27717825339f971ed19fa32c9ce5b54fdc9c4518a3be39e6deede48b82ea0f3a'
COMMITTED_COLLISION_KEY='["udp","172.17.0.2",57598,"104.18.6.141",443]'
PRIOR_COMMITTED_ATTEMPT='d7aecc53bd973973871d5d5999cf2043'
PRIOR_COMMITTED_FINAL='848f3a1fdac2e0c51a1075c9d4f49180559bd2145f012eb6c230e9b02e6bc31d'
def verify_committed_collision():
 d=ROOT/'attempts'/HOST/COMMITTED_COLLISION_ATTEMPT
 a=json.loads(stable_read(ROOT/('partial-committed-collision-'+COMMITTED_COLLISION_ATTEMPT+'-audit-001.json'),COMMITTED_COLLISION_AUDIT))
 if a.get('kind')!='buflo-partial-committed-tuple-collision' or a.get('domain')!=HOST or a.get('attempt_id')!=COMMITTED_COLLISION_ATTEMPT or a.get('slot')!=300 or a.get('final_sha256')!=COMMITTED_COLLISION_FINAL or a.get('tuple')!=COMMITTED_COLLISION_KEY or a.get('prior_mode')!='tamaraw' or a.get('prior_slot')!=388 or a.get('prior_attempt')!=PRIOR_COMMITTED_ATTEMPT or a.get('prior_final_sha256')!=PRIOR_COMMITTED_FINAL or a.get('capture_credit') is not False:raise ValueError('committed collision audit changed')
 v=json.loads(stable_read(d/'FINAL.json',COMMITTED_COLLISION_FINAL))
 if v.get('attempt_id')!=COMMITTED_COLLISION_ATTEMPT or v.get('slot')!=300 or v.get('status')!='partial' or v.get('automatic_partial_exclusion') is not True or v.get('observed_partial_tuple_keys')!=[COMMITTED_COLLISION_KEY]:raise ValueError('collision partial changed')
 for name,meta in v['files'].items():
  q=d/name
  if q.is_symlink() or q.stat().st_size!=meta['size'] or sha(q)!=meta['sha256']:raise ValueError('collision partial evidence changed')
 if tuple_keys(json.loads(stable_read(d/'native/run.json',v['files']['native/run.json']['sha256'])))!=[COMMITTED_COLLISION_KEY]:raise ValueError('collision native tuple changed')
 prior=ROOT.parent.parent/'modes/tamaraw/attempts'/HOST/PRIOR_COMMITTED_ATTEMPT/'FINAL.json';q=json.loads(stable_read(prior,PRIOR_COMMITTED_FINAL))
 if q.get('attempt_id')!=PRIOR_COMMITTED_ATTEMPT or q.get('slot')!=388 or q.get('defense')!='tamaraw' or q.get('status')!='success' or COMMITTED_COLLISION_KEY not in q.get('native_tuple_keys',[]):raise ValueError('prior committed source changed')
 db=sqlite3.connect('file:'+str(TUPLE_DB)+'?mode=ro',uri=True,timeout=30)
 try:
  if db.execute('select attempt,final_sha,state from sessions where mode=? and slot=?',('tamaraw',388)).fetchone()!=(PRIOR_COMMITTED_ATTEMPT,PRIOR_COMMITTED_FINAL,'committed'):raise ValueError('prior committed session changed')
  if db.execute('select mode,attempt,slot,final_sha,state from tuples where k=?',(COMMITTED_COLLISION_KEY,)).fetchone()!=('tamaraw',PRIOR_COMMITTED_ATTEMPT,388,PRIOR_COMMITTED_FINAL,'committed'):raise ValueError('prior committed tuple changed')
 finally:db.close()
 return v

COLLISION345='9e8d616ab005b833b0e64d289d42b150'
COLLISION345_AUDIT_SHA='ff23d5140e792141fbfbee9ec480f1d66748d88765a4c986aae81496a1f5315e'
COLLISION345_KEY='["udp","172.17.0.2",45344,"104.18.7.141",443]'
COLLISION345_PRIOR='5cddd5866afe4618da5a0799e9a5fb18'
COLLISION345_PRIOR_SHA='6dab9a239ed339b46e0b012ce3b4c48193f4676970bf2431a05953e6c5a1c900'
def verify_collision345():
 d=ROOT/'attempts'/HOST/COLLISION345;a=json.loads(stable_read(ROOT/('unsealed-collision-'+COLLISION345+'-audit-001.json'),COLLISION345_AUDIT_SHA))
 if a.get('kind')!='buflo-unsealed-committed-collision' or a.get('attempt_id')!=COLLISION345 or a.get('slot')!=345 or a.get('source_final_exists') is not False or a.get('capture_credit') is not False or a.get('native_tuple_keys')!=[COLLISION345_KEY] or a.get('prior_attempt')!=COLLISION345_PRIOR or a.get('prior_slot')!=232 or a.get('prior_final_sha256')!=COLLISION345_PRIOR_SHA or (d/'FINAL.json').exists() or (d/'FINAL.json').is_symlink():raise ValueError('unsealed collision audit changed')
 entries=list(d.rglob('*'))
 if any(q.is_symlink() for q in entries):raise ValueError('unsealed source symlink')
 files={str(q.relative_to(d)) for q in entries if q.is_file() and q.name!='attempt.lock'}
 if files!=set(a['files']):raise ValueError('unsealed source inventory changed')
 for name,meta in a['files'].items():
  q=d/name
  if q.stat().st_size!=meta['size'] or sha(q)!=meta['sha256']:raise ValueError('unsealed source changed')
 prior=json.loads(stable_read(ROOT/'attempts'/HOST/COLLISION345_PRIOR/'FINAL.json',COLLISION345_PRIOR_SHA))
 if prior.get('attempt_id')!=COLLISION345_PRIOR or prior.get('slot')!=232 or prior.get('status')!='success' or COLLISION345_KEY not in prior.get('native_tuple_keys',[]):raise ValueError('prior source changed')
def verify_collision345_collision(db):
 if db.execute('select mode,attempt,slot,final_sha,state from tuples where k=?',(COLLISION345_KEY,)).fetchone()!=('buflo',COLLISION345_PRIOR,232,COLLISION345_PRIOR_SHA,'committed') or db.execute('select attempt,final_sha,state from sessions where mode=? and slot=?',('buflo',232)).fetchone()!=(COLLISION345_PRIOR,COLLISION345_PRIOR_SHA,'committed'):raise ValueError('prior committed tuple changed')
def verify_transfer():
 if sha(CONFIG_PATH)!=CONFIG_SHA or sha(HISTORY)!=CONFIG['history_sha256']:raise RuntimeError('ownership or history changed')
 if sha(pathlib.Path(__file__))!=CONFIG['owner_sha256']:raise RuntimeError('owner code changed')
 verify_unsealed()
 verify_historical_collision()
 verify_committed_collision()
 verify_collision345()
 if sha(ROOT/'owner-config-001.json')!=OLD_CONFIG_SHA or CONFIG.get('ledger_config_sha256')!=OLD_CONFIG_SHA:raise ValueError('prior ledger config changed')
 audit=json.loads(stable_read(ROOT/'serial-six-slot280-partial-exclusions-001.json',AUDIT_SHA))
 if audit.get('kind')!='buflo-six-serial-partial-exclusions' or len(audit.get('items',[]))!=6 or any(x.get('slot')!=280 or x.get('capture_credit') is not False for x in audit['items']):raise ValueError('slot280 partial audit changed')
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

def verify_slot280_exclusions(db):
 audit=json.loads(stable_read(ROOT/'serial-six-slot280-partial-exclusions-001.json',AUDIT_SHA))
 for x in audit['items']:
  if db.execute('SELECT mode,attempt,slot,final_sha,state FROM tuples WHERE k=?',(x['tuple'],)).fetchone()!=('buflo',x['attempt_id'],280,x['final_sha256'],'excluded'):raise ValueError('slot280 excluded tuple changed')

def initialize_ledger(history,cutover_sha):
 if sha(pathlib.Path(CONFIG['ledger_module']))!=CONFIG['ledger_module_sha256']:raise ValueError('shared ledger module changed')
 global LEDGER
 LEDGER=load_pinned_module(pathlib.Path(CONFIG['ledger_module']),CONFIG['ledger_module_sha256'])
 db=LEDGER.open_ledger(TUPLE_DB,mode=MODE,config_sha=OLD_CONFIG_SHA,coverage_sha=CONFIG['coverage_sha256'],history_sha=CONFIG['history_sha256'])
 verify_slot280_exclusions(db)
 verify_unsealed_exclusions(db)
 verify_collision345_collision(db)
 for slot,aid,digest in LEDGER.committed(db,MODE):
  p=ROOT/'attempts'/HOST/aid/'FINAL.json';r=json.loads(stable_read(p,digest))
  if r.get('slot')!=slot or r.get('status')!='success' or r.get('defense')!=MODE:raise RuntimeError('ledger FINAL mismatch')
  actual=tuple_keys(json.loads(stable_read(p.parent/'native/run.json',r['files']['native/run.json']['sha256'])))
  recorded=[x[0] for x in db.execute('SELECT k FROM tuples WHERE mode=? AND attempt=? AND slot=? AND final_sha=? AND state=?',(MODE,aid,slot,digest,'committed'))]
  if set(actual)!=set(recorded):raise RuntimeError('ledger tuple history mismatch')
 for p in (ROOT/'attempts'/HOST).glob('*'):
  if p.name==COLLISION345 and p.is_dir() and not p.is_symlink():verify_collision345();continue
  if p.name==UNSEALED and p.is_dir() and not p.is_symlink() and not (p/'FINAL.json').exists():continue
  if p.is_symlink() or not p.is_dir() or not (p/'FINAL.json').is_file():raise RuntimeError('unsealed attempt requires review')
  r=json.loads(stable_read(p/'FINAL.json'))
  if r.get('attempt_id')!=p.name or r.get('hostname')!=HOST:raise RuntimeError('attempt identity mismatch')
  if r.get('status')=='success' and db.execute('SELECT attempt FROM sessions WHERE mode=? AND slot=?',(MODE,r['slot'])).fetchone()!=(p.name,):raise RuntimeError('untracked success requires review')
  if r.get('automatic_partial_exclusion') is True:
   if p.name==COLLISION_ATTEMPT:
    if r!=verify_historical_collision():raise ValueError('historical collision mismatch')
   elif p.name==COMMITTED_COLLISION_ATTEMPT:
    if r!=verify_committed_collision():raise ValueError('committed collision mismatch')
   else:check_auto_partial(db,r,sha(p/'FINAL.json'))
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
def attempt(container,stage,db,slot,isolation,cutover_sha):
 baseline=verify_transfer()
 verify_unsealed_exclusions(db)
 verify_collision345_collision(db)
 verify_slot280_exclusions(db)
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('input identity changed during ownership')
 if any(shutil.disk_usage(path).free<minimum for path,minimum in CONFIG['storage_floors'].items()):raise RuntimeError('storage floor')
 aid=secrets.token_hex(16);directory=ROOT/'attempts'/HOST/aid;directory.mkdir(parents=True,exist_ok=False)
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
    '--chaff-manifest','/inputs/chaff-manifest.json','--profile','research-1200','--defense',MODE,'--'+MODE+'-parameters','/inputs/'+param_name,
    '--seed',str(seed),'--output-dir',f'/worker/{aid}/native','--max-response-bytes','16777216','--timeout-seconds',str(native_timeout)]
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
  keys=[];collision=[]
  if clean:
   keys=tuple_keys(run)
   try:LEDGER.reserve(db,mode=MODE,slot=slot,attempt=aid,keys=keys,excluded=set(baseline['reserved_native_tuples']))
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
   'status':'success' if clean else 'partial','successful_responses':len(passed),'required_responses':20,
   'process_exit_code':code,'tail_warning':run.get('error') or error,'native_client_sha256':CLIENT_SHA,'image_id':IMAGE,
   'input_sha256':INPUT_SHA,'driver_sha256':sha(pathlib.Path(__file__)),'owner_sha256':sha(pathlib.Path(__file__)),
   'coverage_sha256':CONFIG['coverage_sha256'],'history_sha256':CONFIG['history_sha256'],'note_sha256':CONFIG['note_sha256'],
   'ownership_sha256':CONFIG_SHA,'slot280_partial_audit_sha256':AUDIT_SHA,'tuple_verifier_sha256':MODULE_SHA,
   'capture_packets_reported':counts['captured'],'capture_filter_received':counts['received'],'capture_kernel_dropped':counts['dropped'],
   'pcap_packets':tuple_result.get('original_packets'),'native_packet_rows':tuple_result.get('native_rows'),'packet_count_screen_passed':cap_ok,
   'tuple_packet_screen':tuple_result,'clean_pcap':'capture-isolated.pcap' if tuple_result.get('pass') else None,
   'prior_unsealed_collision345':([{'attempt_id':COLLISION345,'slot':345,'source_final_exists':False,'capture_credit':False,'audit_sha256':COLLISION345_AUDIT_SHA,'prior_committed_attempt':COLLISION345_PRIOR}] if slot==345 else []),'prior_committed_collision_audit_sha256':COMMITTED_COLLISION_AUDIT if slot==300 else None,'prior_historical_collision_audit_sha256':COLLISION_AUDIT if slot==289 else None,'prior_unsealed_attempts':([{'attempt_id':UNSEALED,'slot':289,'source_final_exists':False,'audit_sha256':UNSEALED_AUDIT_SHA,'exclusion_receipt_sha256':UNSEALED_RECEIPT_SHA}] if slot==289 else []),'native_tuple_keys':keys,'automatic_partial_exclusion':not clean,'observed_partial_tuple_keys':partial_keys,'tuple_collisions':collision,'prior_nonclean_attempts':previous,
   'source_role':'five-defense-recapture-local-20261123','mode_evidence':'native/run.json','files':files}
  if verify_transfer()!=baseline:raise RuntimeError('ownership changed before FINAL publication')
  verify_slot280_exclusions(db)
  verify_unsealed_exclusions(db)
  verify_collision345_collision(db)
  finalsha=store_final(directory,final)
  if clean:
   LEDGER.commit(db,mode=MODE,slot=slot,attempt=aid,final_sha=finalsha)
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

def main():
 global CONFIG_PATH,CONFIG_SHA,CONFIG,HISTORY,ROOT,HOST,INPUTS,CLIENT,MODEL,MODULE,IMAGE,MODEL_SHA,CLIENT_SHA,MODULE_SHA,AUDIT,AUDIT_SHA,INPUT_SHA,STOP_FREE,TUPLE_DB,CREATE_JOURNAL,LABEL,NOTE,LEDGER,MODE
 p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--config-sha',required=True);p.add_argument('--once',action='store_true');args=p.parse_args()
 CONFIG_PATH=pathlib.Path(args.config);CONFIG_SHA=args.config_sha;CONFIG=json.loads(stable_read(CONFIG_PATH,CONFIG_SHA))
 MODE=CONFIG['mode'];HOST=CONFIG['hostname'];ROOT=pathlib.Path(CONFIG['root']);INPUTS=pathlib.Path(CONFIG['inputs']);HISTORY=pathlib.Path(CONFIG['history']);NOTE=pathlib.Path(CONFIG['note'])
 CLIENT=pathlib.Path(CONFIG['client']);MODEL=pathlib.Path(CONFIG['model']);MODULE=pathlib.Path(CONFIG['tuple_module'])
 IMAGE=CONFIG['image'];MODEL_SHA=CONFIG['model_sha256'];CLIENT_SHA=CONFIG['client_sha256'];MODULE_SHA=CONFIG['tuple_module_sha256'];INPUT_SHA=CONFIG['input_sha256']
 STOP_FREE=30*1024**3;TUPLE_DB=ROOT.parent.parent/'shared-ledger-v2.sqlite3';CREATE_JOURNAL=ROOT/'creation-journal';LABEL='qcsd-five-recapture-'+MODE+'-'+HOST
 if not re.fullmatch(r'[a-z0-9.-]+',HOST):raise ValueError('unsafe hostname')
 domain_root=pathlib.Path('/mnt/recapture16k/five-defense-recapture-20261123-001')/HOST
 if HOST!='www.clarin.com' or MODE!='buflo' or ROOT!=domain_root/'modes'/(MODE+'-v3') or INPUTS!=domain_root/'inputs' or NOTE!=INPUTS/'replacement-note.json':raise ValueError('defended mode scope mismatch')
 if CONFIG['exclusive_fence_locks']!=[]:raise ValueError('unexpected fence locks')
 if ROOT.resolve()!=ROOT or INPUTS.resolve()!=INPUTS:raise ValueError('symlink in replacement scope')
 if CONFIG['storage_floors'].get(str(ROOT),0)<8*1024**3:raise ValueError('missing minimum guest storage floor')
 ROOT.mkdir(parents=True,exist_ok=True);(ROOT/'attempts'/HOST).mkdir(parents=True,exist_ok=True)
 locks=[]
 for lockpath in [ROOT/'production-owner.lock',*[pathlib.Path(x) for x in CONFIG['exclusive_fence_locks']]]:
  f=lockpath.open('a+');fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(f)
 baseline=verify_transfer()
 if any(r.get('status')=='success' for r in baseline['entries']):raise RuntimeError('historical success requires separate import')
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('capture input identity changed')
 if command(['docker','image','inspect',IMAGE,'--format','{{.Id}}'])!=IMAGE:raise ValueError('image identity changed')
 reconcile_creation_journal()
 if command(['docker','ps','-aq','--filter','label=qcsd.owner='+LABEL]):raise RuntimeError('existing host worker')
 isolation=load_pinned_module(MODULE,MODULE_SHA);db=initialize_ledger(baseline,CONFIG['history_sha256'])
 slot=next_mode_slot(db,MODE)
 prior=[json.loads(stable_read(x)) for x in (ROOT/'attempts'/HOST).glob('*/FINAL.json')]
 failures,capture_failures=failure_counts(prior,slot)
 stage=ROOT/('worker-stage-'+secrets.token_hex(8));stage.mkdir();sync_dir(ROOT)
 stopping=threading.Event();signal.signal(signal.SIGTERM,lambda *_:stopping.set());signal.signal(signal.SIGINT,lambda *_:stopping.set());container=None
 try:
  container=start_container(stage)
  while not stopping.is_set() and slot<=400 and failures<25 and capture_failures<3:
   status,screen,retired=attempt(container,stage,db,slot,isolation,CONFIG['history_sha256'])
   if retired:container=None
   if status=='success':slot=advance_success(db,MODE,slot);failures=0;capture_failures=0
   elif not screen:capture_failures+=1
   else:failures+=1
   if args.once or stopping.wait(10):break
   if container is None:container=start_container(stage)
 finally:
  if container:fence_container(container)
  db.close()
 print(json.dumps({'hostname':HOST,'next_slot':slot,'failures':failures,'capture_failures':capture_failures}),flush=True)
if __name__=='__main__':main()
