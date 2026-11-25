#!/usr/bin/env python3
"""Isolated MAL roster-v3 front capture owner with pinned resources and local ledger."""
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
def front_run_clean(run,host,roster,workload_sha,prepared_sha):
 if not isinstance(run,dict) or not isinstance(roster,list) or len(roster)!=20:return False
 if any(not isinstance(x,dict) or type(x.get('id')) is not int or not isinstance(x.get('url'),str) for x in roster):return False
 expected={(x['id'],x['url']) for x in roster}
 responses=run.get('responses')
 if len(expected)!=20 or {x[0] for x in expected}!=set(range(20)) or not isinstance(responses,list) or len(responses)!=20:return False
 if any(not isinstance(x,dict) or x.get('complete') is not True or x.get('outcome')!='succeeded' or type(x.get('status')) is not int or not 200<=x['status']<300 for x in responses):return False
 pairs={(x.get('resource_id'),x.get('url')) for x in responses}
 cfg=run.get('resolved_configuration') or {}
 return (pairs==expected and h3_valid(run,host) and cfg=={'automatic_receive_window': 1048576, 'control_interval_us': 10000, 'defense': {'kind': 'front', 'n_client_packets': 450, 'n_server_packets': 600, 'packet_size': 1200, 'peak_maximum_seconds': 4.0, 'peak_minimum_seconds': 1.0}, 'drop_unsatisfied_events': False, 'initial_max_stream_data': 16, 'keep_alive_lead_time_us': 100000, 'low_watermark': 1000000, 'max_chaff_streams': 5, 'max_stream_data_excess': 1000, 'max_udp_payload_size': 1200, 'schema_version': 2, 'tail_wait_us': 0, 'use_empty_resources': False} and
         run.get('completion_status')=='complete' and not run.get('error') and not run.get('error_class') and
         run.get('workload_hash_sha256')==workload_sha and run.get('application_workload_source_hash_sha256')==prepared_sha and run.get('chaff_manifest_hash_sha256')==INPUT_SHA['chaff-manifest.json'] and clean_chaff(run.get('chaff_responses'),5)[0])
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

def defense_action_count(path):
 if not path.is_file():return 0
 with path.open(newline='') as ev:return sum(1 for row in csv.DictReader(ev) if row.get('event')=='action')

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

MODE='front'
WORKER_INDEX=0
WORKER_POLICY=None
WORKER_SPECS=[]
LEASES=None
BASE_CONFIG_SHA='f044e822c2de1eb78edc625c07180c2ae08b218bef251c4cc6cba020f252c0b1'
def verify_transfer(expected_container=None):
 if sha(CONFIG_PATH)!=CONFIG_SHA or sha(HISTORY)!=CONFIG['history_sha256']:raise RuntimeError('ownership or history changed')
 if sha(pathlib.Path(__file__))!=CONFIG['owner_sha256']:raise RuntimeError('owner code changed')
 if sha(NOTE)!=CONFIG['note_sha256']:raise RuntimeError('replacement note changed')
 note=json.loads(stable_read(NOTE,CONFIG['note_sha256']))
 if note.get('kind')!='mal-roster-v3-resource-replacement-note' or note.get('domain')!=HOST or note.get('cohort')!='cdn.myanimelist.net-roster-v3-001' or note.get('drive_handoff_changed') is not False or note.get('capture_credit') is not False or [x.get('resource_id') for x in note.get('changes',[])]!=[18]:raise ValueError('v3 replacement note invalid')
 coverage=json.loads(stable_read(pathlib.Path(CONFIG['coverage_receipt']),CONFIG['coverage_sha256']))
 if coverage.get('kind')!='mal-roster-v3-session-coverage' or coverage.get('cohort')!='cdn.myanimelist.net-roster-v3-001' or coverage.get('domain')!=HOST or coverage.get('resource_sha256')!=INPUT_SHA['resources.json'] or coverage.get('target_sessions_per_mode')!=400 or coverage.get('target_total')!=2400 or coverage.get('drive_handoff_changed') is not False or coverage.get('paper_equivalent') is not False or MODE not in coverage.get('modes',[]):raise ValueError('v3 cohort coverage manifest invalid')
 history=json.loads(stable_read(HISTORY,CONFIG['history_sha256']))
 if history.get('kind')!='mal-roster-v3-prior-tuple-history' or history.get('cohort')!='cdn.myanimelist.net-roster-v3-001' or history.get('imported_as_v3_sessions') is not False or len(history.get('committed',[]))!=1200:raise ValueError('v3 exclusion history invalid')
 reserved=history.get('reserved_native_tuples')
 if not isinstance(reserved,list) or not reserved or len(set(reserved))!=len(reserved):raise ValueError('v3 reserved tuple history invalid')
 for key in reserved:
  value=json.loads(key)
  if not isinstance(value,list) or len(value)!=5 or value[0]!='udp' or json.dumps(value,separators=(',',':'))!=key:raise ValueError('noncanonical prior tuple')
 if CONFIG.get('base_config_sha256')!=BASE_CONFIG_SHA or sha(pathlib.Path(CONFIG['base_config']))!=BASE_CONFIG_SHA:raise ValueError('base mode config pin mismatch')
 spec=WORKER_SPECS[WORKER_INDEX]
 WORKER_POLICY.read_network(spec,expected_container)
 WORKER_POLICY.disjoint(history,spec)
 roster=json.loads(stable_read(INPUTS/'resources.json',INPUT_SHA['resources.json'])).get('resources')
 if not isinstance(roster,list) or len(roster)!=20 or {x.get('id') for x in roster if isinstance(x,dict)}!=set(range(20)):raise ValueError('v3 resource roster invalid')
 return {'entries':[],'reserved_native_tuples':sorted(reserved)}

def initialize_ledger(history,cutover_sha):
 if sha(pathlib.Path(CONFIG['ledger_module']))!=CONFIG['ledger_module_sha256']:raise ValueError('shared ledger module changed')
 global LEDGER
 LEDGER=load_pinned_module(pathlib.Path(CONFIG['ledger_module']),CONFIG['ledger_module_sha256'])
 db=LEDGER.open_ledger(TUPLE_DB,mode='front',config_sha=CONFIG['base_config_sha256'],coverage_sha=CONFIG['coverage_sha256'],history_sha=CONFIG['history_sha256'],prepared_sha=INPUT_SHA['prepared-workload.json'],resource_sha=INPUT_SHA['resources.json'],replacement_note_sha=CONFIG['note_sha256'])
 for slot,aid,digest in LEDGER.committed(db,'front'):
  p=ROOT/'attempts'/HOST/aid/'FINAL.json';r=json.loads(stable_read(p,digest))
  if r.get('slot')!=slot or r.get('status')!='success' or r.get('defense')!='front':raise RuntimeError('ledger FINAL mismatch')
  actual=tuple_keys(json.loads(stable_read(p.parent/'native/run.json',r['files']['native/run.json']['sha256'])))
  recorded=[x[0] for x in db.execute('SELECT k FROM tuples WHERE mode=? AND attempt=? AND slot=? AND final_sha=? AND state=?',('front',aid,slot,digest,'committed'))]
  if set(actual)!=set(recorded):raise RuntimeError('ledger tuple history mismatch')
 for p in (ROOT/'attempts'/HOST).glob('*'):
  if p.is_symlink() or not p.is_dir() or not (p/'FINAL.json').is_file():raise RuntimeError('unsealed attempt requires review')
  r=json.loads(stable_read(p/'FINAL.json'))
  if r.get('attempt_id')!=p.name or r.get('hostname')!=HOST:raise RuntimeError('attempt identity mismatch')
  if r.get('status')=='success' and db.execute('SELECT attempt FROM sessions WHERE mode=? AND slot=?',('front',r['slot'])).fetchone()!=(p.name,):raise RuntimeError('untracked success requires review')
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
 spec=WORKER_SPECS[WORKER_INDEX];network=ipaddress.ip_network(spec['subnet']);used=set()
 for intent in (ROOT/'parallel-journals').glob('*/*/INTENT.json'):
  record=json.loads(stable_read(intent));args=record.get('args')
  if not isinstance(args,list) or args.count('--ip')!=1:raise RuntimeError('unsafe prior worker IP journal')
  ip=ipaddress.ip_address(args[args.index('--ip')+1])
  if ip in network:used.add(str(ip))
 desired_ip=next((str(network.network_address+n) for n in range(3,255) if str(network.network_address+n) not in used),None)
 if desired_ip is None:raise RuntimeError('worker bridge source IP space exhausted')
 args=['docker','run','-d','--network',spec['id'],'--ip',desired_ip,'--label','qcsd.owner='+LABEL,'--label','qcsd.parallel-scope=mal-v3-front-001',
  '--mount',f'type=bind,src={INPUTS},dst=/inputs,readonly','--mount',f'type=bind,src={stage},dst=/worker',
  '--mount',f'type=bind,src={CLIENT},dst=/usr/local/bin/neqo-qcsd-client,readonly',
  '--mount',f'type=bind,src={MODEL},dst=/model.json,readonly','--entrypoint','/bin/sleep',IMAGE,'infinity']
 entry=CREATE_JOURNAL/secrets.token_hex(16);entry.mkdir();sync_dir(CREATE_JOURNAL)
 write_record(entry/'INTENT.json',{'args':args,'worker_index':WORKER_INDEX,'source_ip':desired_ip,'scope':'single isolated mode worker'})
 recorder="import json,os,pathlib,subprocess,sys\np=pathlib.Path(sys.argv[1]);args=json.loads(sys.argv[2]);r=subprocess.run(args,text=True,capture_output=True)\nv={'returncode':r.returncode,'container':r.stdout.strip(),'stderr':r.stderr}\nwith (p/'RESULT.json').open('x') as f:json.dump(v,f,sort_keys=True);f.write('\\n');f.flush();os.fsync(f.fileno())\nfd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)\n"
 proc=subprocess.Popen(['/usr/bin/python3','-c',recorder,str(entry),json.dumps(args)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
 try:proc.wait(timeout=900)
 except subprocess.TimeoutExpired:raise RuntimeError('Docker create unresolved; preserve lease and journal')
 result=entry/'RESULT.json'
 if proc.returncode!=0 or not result.is_file():raise RuntimeError('Docker create recorder failed')
 data=json.loads(result.read_bytes());cid=data.get('container','')
 if data.get('returncode')!=0 or not re.fullmatch(r'[0-9a-f]{64}',cid):raise RuntimeError('ambiguous Docker create result')
 write_record(entry/'RESOLVED.json',{'container':cid,'source_ip':desired_ip,'reconciliation':'identified and handed to worker'})
 return cid

def worker_ip(container):
 return WORKER_POLICY.inspect_container(WORKER_SPECS[WORKER_INDEX],container)

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
 baseline=verify_transfer(container)
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('input identity changed during ownership')
 if any(shutil.disk_usage(path).free<minimum for path,minimum in CONFIG['storage_floors'].items()):raise RuntimeError('storage floor')
 directory=ROOT/'attempts'/HOST/aid;directory.mkdir(parents=True,exist_ok=False)
 stage_session=stage/aid;stage_session.mkdir();raw=directory/'capture.pcap'
 lock=(directory/'attempt.lock').open('x')
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  worker_ip=worker_ip_for_attempt=WORKER_POLICY.inspect_container(WORKER_SPECS[WORKER_INDEX],container)
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
   argv=['/usr/local/bin/neqo-qcsd-client','run','--workload','/inputs/resources.json','--application-workload-source','/inputs/prepared-workload.json','--chaff-manifest','/inputs/chaff-manifest.json',
    '--config','/inputs/params/front.toml','--seed',str(seed),'--output-dir',f'/worker/{aid}/native','--max-response-bytes','16777216','--timeout-seconds','120']
   with (directory/'invocation.json').open('x') as f:json.dump({'argv':argv,'container':container,'seed':seed},f);f.write('\n');f.flush();os.fsync(f.fileno())
   with (directory/'client.log').open('xb') as f:
    exec_begun=True
    code=subprocess.run(['docker','exec',container,*argv],stdout=f,stderr=subprocess.STDOUT,timeout=150).returncode
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
    fence_container(container)
    if observer is None or observer.poll() is not None:raise RuntimeError('uncertain client collector continuity lost; preserve unsealed evidence')
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
   WORKER_POLICY.validate_run(run,WORKER_SPECS[WORKER_INDEX],worker_ip)
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
  if not retire and WORKER_POLICY.inspect_container(WORKER_SPECS[WORKER_INDEX],container)!=worker_ip:raise RuntimeError('worker network changed before finalization')
  if verify_transfer(container)!=baseline:raise RuntimeError('ownership or baseline changed before finalization')
  responses=run.get('responses') or [];passed=[x for x in responses if x.get('complete') is True and x.get('outcome')=='succeeded' and type(x.get('status')) is int and 200<=x['status']<300]
  roster=json.loads(stable_read(INPUTS/'resources.json',INPUT_SHA['resources.json'])).get('resources')
  roster_ok=(type(roster) is list and len(roster)==20 and all(type(x) is dict and type(x.get('id')) is int and type(x.get('url')) is str for x in roster) and {x['id'] for x in roster}==set(range(20)) and {(x.get('resource_id'),x.get('url')) for x in passed}=={(x['id'],x['url']) for x in roster})
  cfg=run.get('resolved_configuration') or {};diag=run.get('defense_diagnostics') or {}
  cap_ok=(tuple_result.get('pass') is True and counts['captured'] is not None and counts['captured']>0 and counts['captured']==counts['received']==tuple_result.get('original_packets') and counts['dropped']==0 and type(tuple_result.get('native_rows')) is int and 0<tuple_result['native_rows']<=counts['captured'])
  defense_actions=defense_action_count(dst/'events.csv')
  clean=(code==0 and not error and cap_ok and defense_actions>0 and front_run_clean(run,HOST,roster,INPUT_SHA['resources.json'],INPUT_SHA['prepared-workload.json']))
  # Extract every observed native tuple before deciding session credit. If the
  # run lacks complete endpoint evidence, fail closed and leave it unsealed.
  keys=tuple_keys(run);collision=[]
  if clean:
   try:LEASES.reserve(db,slot,lease_token,aid,keys,set(baseline['reserved_native_tuples']))
   except ValueError as e:collision=[{'reason':str(e)}];clean=False;error='duplicate slot or native connection tuple'
  files={}
  for p in sorted(directory.rglob('*')):
   if p.is_file() and p.name not in ('FINAL.json','attempt.lock','.FINAL.tmp'):files[str(p.relative_to(directory))]={'sha256':sha(p),'size':p.stat().st_size}
  previous=[]
  for p in (ROOT/'attempts'/HOST).glob('*/FINAL.json'):
   old_bytes=stable_read(p);old=json.loads(old_bytes)
   if old.get('slot')==slot and old.get('status')!='success':previous.append({'attempt_id':old['attempt_id'],'final_sha256':hashlib.sha256(old_bytes).hexdigest()})
  final={'schema_version':1,'hostname':HOST,'attempt_id':aid,'slot':slot,'purpose':'production','defense':'front',
   'status':'success' if clean else 'partial','successful_responses':len(passed),'required_responses':20,
   'process_exit_code':code,'tail_warning':run.get('error') or error,'native_client_sha256':CLIENT_SHA,'image_id':IMAGE,
   'input_sha256':INPUT_SHA,'driver_sha256':sha(pathlib.Path(__file__)),'owner_sha256':sha(pathlib.Path(__file__)),
   'coverage_sha256':CONFIG['coverage_sha256'],'history_sha256':CONFIG['history_sha256'],'note_sha256':CONFIG['note_sha256'],
   'ownership_sha256':CONFIG['base_config_sha256'],'parallel_owner_config_sha256':CONFIG_SHA,'worker_manifest_sha256':CONFIG['worker_manifest_sha256'],'worker_index':WORKER_INDEX,'worker_network_id':WORKER_SPECS[WORKER_INDEX]['id'],'worker_network_subnet':WORKER_SPECS[WORKER_INDEX]['subnet'],'domain_schedule':'mal-roster-v3-independent-mode-lanes-20261124','replacement_cohort':'mal-roster-v3-001','tuple_verifier_sha256':MODULE_SHA,'network_id':WORKER_SPECS[WORKER_INDEX]['id'],'network_subnet':WORKER_SPECS[WORKER_INDEX]['subnet'],'network_worker_ip':worker_ip,'network_manifest_sha256':CONFIG['network_manifest_sha256'],
   'capture_packets_reported':counts['captured'],'capture_filter_received':counts['received'],'capture_kernel_dropped':counts['dropped'],
   'defense_action_count':defense_actions,
   'pcap_packets':tuple_result.get('original_packets'),'native_packet_rows':tuple_result.get('native_rows'),'packet_count_screen_passed':cap_ok,
   'tuple_packet_screen':tuple_result,'clean_pcap':'capture-isolated.pcap' if tuple_result.get('pass') else None,
   'native_tuple_keys':keys,'tuple_collisions':collision,'prior_nonclean_attempts':previous,
   'source_role':'mal-roster-v3-resource-replacement-20261124','mode_evidence':'native/run.json','files':files}
  if verify_transfer(container)!=baseline:raise RuntimeError('ownership changed before FINAL publication')
  finalsha=store_final(directory,final)
  if clean:
   LEASES.commit(db,slot,lease_token,aid,finalsha)
  elif keys:
   journal=ROOT/'parallel-recovery-journals';journal.mkdir(parents=True,exist_ok=True)
   audit=journal/(aid+'.json');write_record(audit,{'kind':'mal-v3-parallel-partial-lease-release','mode':MODE,'slot':slot,'attempt':aid,'token':lease_token,'final_sha256':finalsha,'keys':keys,'capture_credit':False})
   LEASES.exclude_and_release(db,slot,lease_token,aid,keys,finalsha,str(audit.resolve()),sha(audit),set(baseline['reserved_native_tuples']))
  else:
   raise RuntimeError('partial lacks complete tuple evidence; lease stays open for reconciliation')
  print(json.dumps({'hostname':HOST,'slot':slot,'status':final['status'],'attempt_id':aid,'directory':str(directory)},sort_keys=True),flush=True)
  return final['status'],cap_ok,retire
 finally:
  lock.close()

def verify_parallel_journals():
 path=ROOT/'parallel-journals'
 if not path.exists():return
 for worker_dir in path.iterdir():
  if worker_dir.is_symlink() or not worker_dir.is_dir():raise RuntimeError('unsafe parallel worker journal')
  for entry in worker_dir.iterdir():
   if entry.is_symlink() or not entry.is_dir() or any(not (entry/name).is_file() for name in ('INTENT.json','RESULT.json','RESOLVED.json')):raise RuntimeError('unresolved parallel Docker create')

def worker(index,once,stopping):
 global WORKER_INDEX,LABEL,CREATE_JOURNAL
 WORKER_INDEX=index;token=secrets.token_hex(16);LABEL='qcsd-mal-v3-front-parallel-'+token
 CREATE_JOURNAL=ROOT/'parallel-journals'/token;CREATE_JOURNAL.mkdir(parents=True,exist_ok=False);sync_dir(CREATE_JOURNAL.parent)
 db=sqlite3.connect(TUPLE_DB,timeout=30,isolation_level=None);db.execute('PRAGMA synchronous=FULL');db.execute('PRAGMA busy_timeout=30000');LEASES.validate(db)
 stage=ROOT/('worker-stage-parallel-'+token);stage.mkdir();sync_dir(ROOT);container=None;failures=0
 try:
  while not stopping.is_set() and failures<6:
   aid=secrets.token_hex(16);lease_token=secrets.token_hex(16);slot=LEASES.claim(db,lease_token,aid)
   if slot is None:break
   container=start_container(stage)
   status,screen,retired=attempt(container,stage,db,slot,ISOLATION,CONFIG['history_sha256'],lease_token,aid)
   fence_container(container);container=None
   failures=0 if status=='success' else failures+1
   if once or stopping.wait(2):break
 finally:
  if container:fence_container(container)
  db.close()

def main():
 import multiprocessing
 global CONFIG_PATH,CONFIG_SHA,CONFIG,CONFIG_OWNER_SHA,HISTORY,ROOT,HOST,INPUTS,CLIENT,MODEL,MODULE,IMAGE,MODEL_SHA,CLIENT_SHA,MODULE_SHA,AUDIT,AUDIT_SHA,INPUT_SHA,STOP_FREE,TUPLE_DB,CREATE_JOURNAL,LABEL,NOTE,LEDGER,LEASES,ISOLATION,WORKER_INDEX,WORKER_POLICY,WORKER_SPECS
 p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--config-sha',required=True);p.add_argument('--once',action='store_true');args=p.parse_args()
 CONFIG_PATH=pathlib.Path(args.config);CONFIG_SHA=args.config_sha;CONFIG=json.loads(stable_read(CONFIG_PATH,CONFIG_SHA))
 if sha(pathlib.Path(CONFIG['base_config']))!=CONFIG['base_config_sha256'] or CONFIG['base_config_sha256']!='f044e822c2de1eb78edc625c07180c2ae08b218bef251c4cc6cba020f252c0b1':raise ValueError('original mode config changed')
 MODE_EXPECTED='front'
 if CONFIG.get('mode')!=MODE_EXPECTED or type(CONFIG.get('workers')) is not int or CONFIG['workers']!=2:raise ValueError('parallel owner scope mismatch')
 HOST=CONFIG['hostname'];ROOT=pathlib.Path(CONFIG['root']);INPUTS=pathlib.Path(CONFIG['inputs']);HISTORY=pathlib.Path(CONFIG['history']);NOTE=pathlib.Path(CONFIG['note'])
 CLIENT=pathlib.Path(CONFIG['client']);MODEL=pathlib.Path(CONFIG['model']);MODULE=pathlib.Path(CONFIG['tuple_module'])
 IMAGE=CONFIG['image'];MODEL_SHA=CONFIG['model_sha256'];CLIENT_SHA=CONFIG['client_sha256'];MODULE_SHA=CONFIG['tuple_module_sha256'];INPUT_SHA=CONFIG['input_sha256']
 STOP_FREE=30*1024**3;TUPLE_DB=pathlib.Path(CONFIG['ledger_path']);CREATE_JOURNAL=ROOT/'creation-journal';LABEL='qcsd-mal-v3-'+MODE_EXPECTED+'-parallel-supervisor'
 domain_root=pathlib.Path('/mnt/recapture16k/five-defense-recapture-20261123-001/cdn.myanimelist.net-roster-v3-001')
 if HOST!='cdn.myanimelist.net' or ROOT!=domain_root/'modes'/MODE_EXPECTED or INPUTS!=domain_root/'inputs' or NOTE!=INPUTS/'replacement-note.json' or TUPLE_DB!=domain_root/'shared-ledger-v3.sqlite3':raise ValueError('parallel cohort path mismatch')
 if CONFIG.get('exclusive_fence_locks')!=[] or ROOT.resolve()!=ROOT or INPUTS.resolve()!=INPUTS:raise ValueError('unsafe mode paths')
 if CONFIG['storage_floors'].get(str(ROOT),0)<8*1024**3:raise ValueError('storage floor missing')
 lock=(ROOT/'production-owner.lock').open('a+');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 WORKER_POLICY=load_pinned_module(pathlib.Path(CONFIG['worker_policy']),CONFIG['worker_policy_sha256'])
 manifest=json.loads(stable_read(pathlib.Path(CONFIG['worker_manifest']),CONFIG['worker_manifest_sha256']))
 if manifest.get('mode')!=MODE_EXPECTED or len(manifest.get('networks',[]))!=2 or [x.get('index') for x in manifest['networks']]!=[0,1]:raise ValueError('worker manifest mismatch')
 WORKER_SPECS=manifest['networks'];history=json.loads(stable_read(HISTORY,CONFIG['history_sha256']))
 for spec in WORKER_SPECS:WORKER_POLICY.read_network(spec,None);WORKER_POLICY.disjoint(history,spec)
 WORKER_INDEX=0;baseline=verify_transfer()
 if sha(CLIENT)!=CLIENT_SHA or sha(MODEL)!=MODEL_SHA or sha(MODULE)!=MODULE_SHA or any(sha(INPUTS/n)!=v for n,v in INPUT_SHA.items()):raise ValueError('capture inputs changed')
 if command(['docker','image','inspect',IMAGE,'--format','{{.Id}}'])!=IMAGE:raise ValueError('client image changed')
 reconcile_creation_journal();verify_parallel_journals()
 scope='mal-v3-front-001'
 if command(['docker','ps','-aq','--filter','label=qcsd.parallel-scope='+scope]):raise RuntimeError('parallel worker from same plan still exists')
 if command(['docker','ps','-aq','--filter','label=qcsd.owner=qcsd-mal-v3-front-cdn.myanimelist.net']):raise RuntimeError('serial Front worker remains')
 ISOLATION=load_pinned_module(MODULE,MODULE_SHA);db=initialize_ledger(baseline,CONFIG['history_sha256'])
 LEASES=load_pinned_module(pathlib.Path(CONFIG['lease_module']),CONFIG['lease_module_sha256']);LEASES.initialize(db)
 if db.execute("SELECT 1 FROM sessions WHERE mode=? AND state='pending' LIMIT 1",(MODE_EXPECTED,)).fetchone():raise RuntimeError('pending session needs reconciliation')
 if db.execute("SELECT 1 FROM slot_leases WHERE mode=? AND state IN ('running','reserved') LIMIT 1",(MODE_EXPECTED,)).fetchone():raise RuntimeError('unresolved mode lease needs reconciliation')
 db.close();ctx=multiprocessing.get_context('fork');stopping=ctx.Event();children=[]
 signal.signal(signal.SIGTERM,lambda *_:stopping.set());signal.signal(signal.SIGINT,lambda *_:stopping.set())
 try:
  for i in range(CONFIG['workers']):
   child=ctx.Process(target=worker,args=(i,args.once,stopping));child.start();children.append(child)
  while any(child.is_alive() for child in children):
   for child in children:child.join(timeout=1)
   if any(child.exitcode not in (None,0) for child in children):stopping.set()
 finally:
  stopping.set()
  for child in children:
   if child.is_alive():child.join()
 if any(child.exitcode!=0 for child in children):raise RuntimeError('parallel worker failed; preserve all attempt and lease records')
 print(json.dumps({'mode':MODE_EXPECTED,'workers':len(children),'status':'workers-exited'},flush=True))
if __name__=='__main__':main()
